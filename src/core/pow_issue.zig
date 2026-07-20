// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Zat4 — a social-media client built on the AT Protocol.
// Copyright (C) 2026  Connor Avila
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published
// by the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! B1 classification: CORE (pure). **Server-issued, stateless proof-of-work
//! tickets** — the piece that turns Zat4's PoW from a client-side self-imposed
//! tax into an enforced control. Specced in `CONSTELLATION_GATE_DESIGN.md` §9.7.
//!
//! Today's PoW (`core/pow.zig` + `shell/pow.zig`) is real memory-hard work, but
//! the client derives its own challenge and verifies its own answer, and throws
//! the nonce away — `shell/write.zig` says so in its own comment. A modified
//! client simply skips it. This module supplies the missing half: a challenge
//! the SERVER issues and can later prove it issued.
//!
//! ── Why stateless (the DoS argument) ──
//! The enrollment endpoint is public and UNAUTHENTICATED — it must be, since
//! the user has no account yet. If issuing a challenge allocated server state,
//! an adversary would request millions and exhaust memory for free, without
//! doing any work at all. So a `Ticket` carries its own authenticity: it is the
//! challenge parameters plus a MAC over them under a server key. The server
//! stores NOTHING at issue time and revalidates on redemption by recomputing
//! the MAC. Issuance is O(1) with zero retained state.
//!
//! The one thing that cannot be stateless is replay — see `SpentEntry` and
//! `checkAndSpend` below, and note why that set stays naturally small.
//!
//! ── Note on the license (differs from `core/constellation.zig`) ──
//! The Constellation Gate module is deliberately MIT and import-free so it can
//! be lifted into its own repository. This file is NOT part of that module: it
//! is Zat4's PoW layer, which the Gate merely *reads* as signal 3 (Gate §8). It
//! stays AGPL with the rest of the tree and may import freely.
//!
//! Interface, in full: `Ticket`, `TicketState`, `SpentEntry`, `SpendResult`,
//! `issue`, `checkTicket`, `spentTag`, `checkAndSpend`, `sweepExpired`,
//! `default_ttl_secs`, `default_skew_secs`, `Key`, `key_len`, `mac_len`.

const std = @import("std");
const assert = std.debug.assert;
const pow = @import("pow.zig");

/// The server's ticket-signing key. Held by the shell (a secret is I/O-shaped
/// state, B3) and passed in per call so this module stays a pure function of
/// its inputs.
///
/// ── Rotation (Gate §9.8) ──
/// This key is FREELY rotatable, unlike the Constellation Gate's token salt.
/// Rotating it invalidates only tickets currently in flight — at worst a few
/// enrollments retry. Nothing stored depends on it. The two secrets have
/// opposite rotation properties and must not share a config path.
pub const key_len = 32;
pub const Key = [key_len]u8;

/// MAC width carried on the wire. 128 bits truncated from HMAC-SHA256.
///
/// Truncation is safe here and the reason is worth stating: forging a ticket
/// requires producing a valid MAC without the key, and 128 bits is far beyond
/// brute force. The MAC is not a hash of a secret the attacker can grind
/// offline — every guess must be tested against the server, which rate-limits.
pub const mac_len = 16;

/// How long an issued ticket remains redeemable, in seconds.
///
/// ⚠️ PLACEHOLDER — NOT CALIBRATED. ⚠️ The trade is concrete: it must exceed
/// the solve time on the SLOWEST honest device (or real users hit expiry having
/// done the work), while staying short enough that the spent-set (below) stays
/// small. `core/pow.zig`'s difficulty table is itself uncalibrated, so this
/// number cannot be settled before that one is.
pub const default_ttl_secs: i64 = 180;

/// Tolerance for a ticket whose `issued_at` is ahead of the verifying clock.
///
/// A ticket cannot legitimately come from the future — the same server issued
/// it. But clocks step (NTP corrections, VM migrations), and a hard rejection
/// would turn a routine time adjustment into an enrollment outage. This absorbs
/// that without meaningfully widening the window.
pub const default_skew_secs: i64 = 30;

// ── Data model (A1: plain data, fields only; behavior is free functions) ──

/// An issued challenge, wire-shaped and self-authenticating.
///
/// A7: one per in-flight enrollment, and every redemption walks one. Guarded.
///
/// **`tier` is inside the MAC on purpose.** It selects the difficulty, so if it
/// were unauthenticated a client could downgrade its own work to the cheapest
/// tier and the whole tax would collapse. Everything the server will later act
/// on must be covered by the MAC — that is the invariant this struct exists to
/// hold.
pub const Ticket = struct {
    /// Server-chosen random seed the nonce is appended to. Supplied by the
    /// shell's CSPRNG (B3) — randomness never originates in the core.
    seed: [32]u8,
    /// Server clock at issue, in SECONDS. Also supplied by the shell.
    issued_at: i64,
    /// Truncated HMAC-SHA256 over (seed ‖ issued_at ‖ tier) under the key.
    mac: [mac_len]u8,
    /// Which `pow.Tier`, and therefore which difficulty, this ticket demands.
    tier: pow.Tier,
    /// A6: explicit, named padding. Room for a future flag byte.
    _reserved: [7]u8 = .{0} ** 7,

    comptime {
        // Budget: 32 (seed) + 8 (issued_at) + 16 (mac) + 1 (tier)
        // + 7 (reserved) = 64 bytes, exact; align 8 from the i64.
        // Raising this requires an A7.1 justification recorded HERE.
        assert(@sizeOf(Ticket) == 64);
    }
};

/// The outcome of checking a ticket.
///
/// Deliberately NOT a bool. A refusal is not an absence: "you forged this",
/// "you took too long", and "your clock is wrong" demand different responses —
/// the first is an attack worth logging, the second is an honest user who
/// should simply be re-issued a ticket, and the third is an operational fault
/// on OUR side. Collapsing them into `false` would throw away the distinction
/// at exactly the layer that needs it.
pub const TicketState = enum(u8) {
    /// MAC verified and within the window. Proceed to verify the solution.
    valid = 0,
    /// The MAC did not verify: not issued by this server under this key, or
    /// tampered with in flight. This is the attack case.
    forged = 1,
    /// Authentic, but older than the TTL. An honest slow device lands here;
    /// re-issue rather than refuse.
    expired = 2,
    /// Authentic, but issued further in the future than skew tolerance allows.
    /// Since forging requires the key, this indicates OUR clock, not an attack.
    from_the_future = 3,
};

/// One entry in the replay guard: a spent ticket and when it stops mattering.
///
/// A7: held in quantity — one per solved ticket inside the TTL window. Guarded.
pub const SpentEntry = struct {
    /// `spentTag` of the ticket. Zero means the slot is free.
    tag: u64,
    /// After this time the slot may be reused: the ticket it guarded can no
    /// longer be redeemed anyway, because `checkTicket` would call it expired.
    expires_at: i64,

    comptime {
        // Budget: 8 + 8 = 16 bytes, exact.
        assert(@sizeOf(SpentEntry) == 16);
    }
};

/// The outcome of trying to spend a ticket.
pub const SpendResult = enum(u8) {
    /// First redemption. Recorded; the caller may proceed.
    recorded = 0,
    /// Already spent inside its window. This is the replay attack.
    replay = 1,
    /// No free slot. See `checkAndSpend` for why this fails CLOSED.
    full = 2,
};

// ── Free functions (A1: behavior lives here, not on the records) ──

/// PURE (B2): mint a ticket. `seed` comes from the shell's CSPRNG and
/// `issued_at` from the shell's clock (B3) — this function invents neither, so
/// it is deterministic and directly testable.
pub fn issue(key: Key, seed: [32]u8, issued_at: i64, tier: pow.Tier) Ticket {
    var t: Ticket = .{
        .seed = seed,
        .issued_at = issued_at,
        .mac = undefined,
        .tier = tier,
    };
    t.mac = computeMac(key, seed, issued_at, tier);
    return t;
}

/// PURE (B2): check a ticket's authenticity and freshness.
///
/// Order matters and is deliberate: **authenticity is checked before
/// freshness.** A forged ticket must never be reported as merely "expired",
/// because that would tell an attacker their forgery was structurally accepted
/// and only the timestamp needed adjusting.
pub fn checkTicket(
    key: Key,
    t: Ticket,
    now: i64,
    ttl_secs: i64,
    skew_secs: i64,
) TicketState {
    const expected = computeMac(key, t.seed, t.issued_at, t.tier);
    if (!constantTimeEqual(&expected, &t.mac)) return .forged;

    if (t.issued_at > now +| skew_secs) return .from_the_future;
    if (now -| t.issued_at > ttl_secs) return .expired;
    return .valid;
}

/// PURE (B2): the replay-guard identity of a ticket.
///
/// Derived from the MAC, which already covers every field, so two distinct
/// tickets cannot share a tag without an HMAC collision. Returns a nonzero
/// value because zero marks a free slot in the spent set — the one-in-2^64 case
/// is folded to 1 rather than left to alias an empty slot, which would let one
/// specific ticket be replayed forever.
pub fn spentTag(t: Ticket) u64 {
    const tag = std.mem.readInt(u64, t.mac[0..8], .little);
    return if (tag == 0) 1 else tag;
}

/// PURE (B2): record a ticket as spent, refusing a second redemption.
///
/// ── Why a replay guard is unavoidable ──
/// Statelessness buys DoS resistance at issue time, but a stateless ticket can
/// be solved once and submitted repeatedly. Without this, one unit of work buys
/// unlimited accounts — which would defeat the entire point of the tax.
///
/// ── Why this set stays small (the load-bearing property) ──
/// An entry exists only for a ticket that was actually SOLVED, and only until
/// its TTL elapses. An attacker cannot flood it cheaply: every entry costs them
/// a full memory-hard solve. The set is therefore bounded by honest enrollment
/// rate × TTL, not by request rate. That is precisely the asymmetry that makes
/// a bounded buffer safe here.
///
/// ── Fail CLOSED on exhaustion, deliberately ──
/// A full set returns `.full` and the caller must refuse. Evicting an unexpired
/// entry to make room would reopen the replay window on whichever ticket got
/// evicted — trading a bounded availability problem for an unbounded integrity
/// one. Expired slots ARE reclaimed (lazily, below), so a full set means more
/// solved tickets inside one TTL than the operator provisioned for. That is a
/// capacity signal to act on, not a case to paper over.
///
/// `entries` is caller-owned and caller-sized: no allocation happens here (C1,
/// C2), and the capacity decision stays with the shell that knows the box.
pub fn checkAndSpend(
    entries: []SpentEntry,
    tag: u64,
    now: i64,
    expires_at: i64,
) SpendResult {
    var free_slot: ?usize = null;

    for (entries, 0..) |e, i| {
        if (e.tag == tag and e.expires_at > now) return .replay;
        // Remember the first reusable slot — empty, or holding a dead entry.
        if (free_slot == null and (e.tag == 0 or e.expires_at <= now)) {
            free_slot = i;
        }
    }

    const slot = free_slot orelse return .full;
    entries[slot] = .{ .tag = tag, .expires_at = expires_at };
    return .recorded;
}

/// PURE (B2): clear entries whose window has passed.
///
/// `checkAndSpend` already reclaims dead slots opportunistically, so this is
/// not required for correctness — it exists so a caller can keep the set tidy
/// during idle periods and so the occupancy it reports means something. Returns
/// the number of live entries remaining.
pub fn sweepExpired(entries: []SpentEntry, now: i64) usize {
    var live: usize = 0;
    for (entries) |*e| {
        if (e.tag == 0) continue;
        if (e.expires_at <= now) {
            e.* = .{ .tag = 0, .expires_at = 0 };
        } else {
            live += 1;
        }
    }
    return live;
}

/// PURE: HMAC-SHA256 over the ticket's authenticated fields, truncated.
///
/// The field order is fixed and every field is length-fixed, so there is no
/// ambiguity about where one ends and the next begins — no separator is needed
/// and no two distinct field-sets can produce the same input bytes.
fn computeMac(key: Key, seed: [32]u8, issued_at: i64, tier: pow.Tier) [mac_len]u8 {
    const Hmac = std.crypto.auth.hmac.sha2.HmacSha256;
    var h = Hmac.init(&key);
    h.update(&seed);
    var when: [8]u8 = undefined;
    std.mem.writeInt(i64, &when, issued_at, .little);
    h.update(&when);
    h.update(&[_]u8{@intFromEnum(tier)});
    var full: [Hmac.mac_length]u8 = undefined;
    h.final(&full);
    return full[0..mac_len].*;
}

/// PURE: constant-time comparison of two MACs.
///
/// A byte-by-byte early-exit compare leaks, through timing, HOW MUCH of a
/// guessed MAC was correct — which turns forgery from a 2^128 problem into a
/// per-byte search. This accumulates every difference and branches only once,
/// at the end, so the work is identical for every input.
///
/// Hand-rolled rather than imported, following this codebase's own posture on
/// security invariants (`core/pow.zig`: "pinned HERE, not in trust of std").
/// The `volatile` read keeps an optimizing compiler from reintroducing the
/// early exit it is the entire purpose of this function to avoid.
fn constantTimeEqual(a: *const [mac_len]u8, b: *const [mac_len]u8) bool {
    var diff: u8 = 0;
    for (a, b) |x, y| {
        const acc: *volatile u8 = &diff;
        acc.* |= x ^ y;
    }
    return diff == 0;
}

// ── Tests: the pure core, no Io, no allocator ──

const test_key: Key = [_]u8{0x11} ** key_len;
const test_seed = [_]u8{0xC3} ** 32;
const t0: i64 = 1_767_323_045;

test "a freshly issued ticket verifies" {
    const t = issue(test_key, test_seed, t0, .heavy);
    try std.testing.expectEqual(
        TicketState.valid,
        checkTicket(test_key, t, t0 + 5, default_ttl_secs, default_skew_secs),
    );
}

test "a ticket forged without the key is rejected" {
    var t = issue(test_key, test_seed, t0, .heavy);
    t.mac[0] ^= 0x01; // one bit
    try std.testing.expectEqual(
        TicketState.forged,
        checkTicket(test_key, t, t0, default_ttl_secs, default_skew_secs),
    );

    // A different key cannot mint an acceptable ticket.
    const other = issue([_]u8{0x22} ** key_len, test_seed, t0, .heavy);
    try std.testing.expectEqual(
        TicketState.forged,
        checkTicket(test_key, other, t0, default_ttl_secs, default_skew_secs),
    );
}

test "the tier is authenticated: a client cannot downgrade its own difficulty" {
    // The whole tax collapses if the difficulty selector is unauthenticated.
    var t = issue(test_key, test_seed, t0, .heavy);
    t.tier = .light; // "actually, I'd like the easy one"
    try std.testing.expectEqual(
        TicketState.forged,
        checkTicket(test_key, t, t0, default_ttl_secs, default_skew_secs),
    );
}

test "every authenticated field is covered by the MAC" {
    const base = issue(test_key, test_seed, t0, .heavy);

    var seed_swapped = base;
    seed_swapped.seed[31] ^= 0xFF;
    try std.testing.expectEqual(
        TicketState.forged,
        checkTicket(test_key, seed_swapped, t0, default_ttl_secs, default_skew_secs),
    );

    // Moving issued_at forward would otherwise extend a ticket's life forever.
    var time_swapped = base;
    time_swapped.issued_at = t0 + 10_000;
    try std.testing.expectEqual(
        TicketState.forged,
        checkTicket(test_key, time_swapped, t0 + 10_000, default_ttl_secs, default_skew_secs),
    );
}

test "expiry and clock skew are distinguished from forgery" {
    const t = issue(test_key, test_seed, t0, .heavy);

    // Authentic but stale — an honest slow device, to be re-issued not refused.
    try std.testing.expectEqual(
        TicketState.expired,
        checkTicket(test_key, t, t0 + default_ttl_secs + 1, default_ttl_secs, default_skew_secs),
    );
    // Exactly at the boundary is still good (the window is inclusive).
    try std.testing.expectEqual(
        TicketState.valid,
        checkTicket(test_key, t, t0 + default_ttl_secs, default_ttl_secs, default_skew_secs),
    );

    // Authentic but ahead of our clock — since forging needs the key, this
    // says OUR clock stepped, not that we are under attack.
    try std.testing.expectEqual(
        TicketState.from_the_future,
        checkTicket(test_key, t, t0 - default_skew_secs - 1, default_ttl_secs, default_skew_secs),
    );
    // Inside skew tolerance, a stepped clock does not break enrollment.
    try std.testing.expectEqual(
        TicketState.valid,
        checkTicket(test_key, t, t0 - default_skew_secs, default_ttl_secs, default_skew_secs),
    );
}

test "authenticity is checked BEFORE freshness" {
    // A forged ticket must never come back as merely 'expired' — that would
    // tell an attacker the forgery was structurally accepted and only the
    // timestamp needed work.
    var t = issue(test_key, test_seed, t0, .heavy);
    t.mac[7] ^= 0x80;
    try std.testing.expectEqual(
        TicketState.forged,
        checkTicket(test_key, t, t0 + 10 * default_ttl_secs, default_ttl_secs, default_skew_secs),
    );
}

test "a solved ticket cannot be redeemed twice" {
    var set = [_]SpentEntry{.{ .tag = 0, .expires_at = 0 }} ** 8;
    const t = issue(test_key, test_seed, t0, .heavy);
    const tag = spentTag(t);
    const expires = t0 + default_ttl_secs;

    try std.testing.expectEqual(SpendResult.recorded, checkAndSpend(&set, tag, t0, expires));
    try std.testing.expectEqual(SpendResult.replay, checkAndSpend(&set, tag, t0 + 1, expires));
    try std.testing.expectEqual(SpendResult.replay, checkAndSpend(&set, tag, t0 + 60, expires));

    // Once the window passes the entry stops guarding — but by then the ticket
    // is expired anyway, so nothing is actually redeemable.
    try std.testing.expectEqual(
        SpendResult.recorded,
        checkAndSpend(&set, tag, expires + 1, expires + 1 + default_ttl_secs),
    );
}

test "distinct tickets get distinct tags and do not collide in the set" {
    var set = [_]SpentEntry{.{ .tag = 0, .expires_at = 0 }} ** 8;
    var i: u8 = 0;
    while (i < 8) : (i += 1) {
        var seed = test_seed;
        seed[0] = i;
        const t = issue(test_key, seed, t0, .heavy);
        try std.testing.expectEqual(
            SpendResult.recorded,
            checkAndSpend(&set, spentTag(t), t0, t0 + default_ttl_secs),
        );
    }
    // Nine distinct tickets into eight slots, none expired: fails CLOSED.
    var seed = test_seed;
    seed[0] = 99;
    const overflow = issue(test_key, seed, t0, .heavy);
    try std.testing.expectEqual(
        SpendResult.full,
        checkAndSpend(&set, spentTag(overflow), t0, t0 + default_ttl_secs),
    );
}

test "expired slots are reclaimed, so capacity is per-window not lifetime" {
    var set = [_]SpentEntry{.{ .tag = 0, .expires_at = 0 }} ** 4;
    var i: u8 = 0;
    while (i < 4) : (i += 1) {
        var seed = test_seed;
        seed[0] = i;
        _ = checkAndSpend(&set, spentTag(issue(test_key, seed, t0, .heavy)), t0, t0 + 100);
    }
    try std.testing.expectEqual(@as(usize, 4), sweepExpired(&set, t0));

    // After the window, the same four slots serve the next cohort.
    try std.testing.expectEqual(@as(usize, 0), sweepExpired(&set, t0 + 101));
    var seed = test_seed;
    seed[0] = 200;
    try std.testing.expectEqual(
        SpendResult.recorded,
        checkAndSpend(&set, spentTag(issue(test_key, seed, t0 + 101, .heavy)), t0 + 101, t0 + 201),
    );
}

test "spentTag never returns the free-slot sentinel" {
    // Zero marks an empty slot; a tag of zero would let one ticket replay
    // forever. The fold is one line and this pins it.
    var t = issue(test_key, test_seed, t0, .heavy);
    t.mac = .{0} ** mac_len;
    try std.testing.expect(spentTag(t) != 0);
}

test "issue is deterministic given the shell's seed and clock" {
    // The shell owns randomness and time (B3); this function invents neither,
    // which is what makes it testable at all.
    const a = issue(test_key, test_seed, t0, .heavy);
    const b = issue(test_key, test_seed, t0, .heavy);
    try std.testing.expectEqualSlices(u8, &a.mac, &b.mac);
}

test "constantTimeEqual agrees with a plain comparison" {
    const a = [_]u8{0xAB} ** mac_len;
    var b = a;
    try std.testing.expect(constantTimeEqual(&a, &b));
    b[mac_len - 1] ^= 0x01; // difference in the LAST byte still caught
    try std.testing.expect(!constantTimeEqual(&a, &b));
    b = a;
    b[0] ^= 0x01; // and in the first
    try std.testing.expect(!constantTimeEqual(&a, &b));
}

test "an issued ticket carries a difficulty the solver can actually use" {
    // The tier must round-trip into a real pow.Difficulty, or the ticket
    // describes work nobody can do.
    const t = issue(test_key, test_seed, t0, .heavy);
    const d = pow.difficultyFor(t.tier).?;
    try std.testing.expectEqual({}, try pow.validate(d));
    // And the seed is the one the challenge binds to.
    const c = pow.challengeFor(t.seed, t.tier);
    try std.testing.expectEqualSlices(u8, &t.seed, &c.seed);
}
