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

//! B1 classification: CORE (pure). The **proof-of-work** module's pure
//! half — all plain data (A1) plus the security-relevant target check.
//! Specced in POW_MODULE_DESIGN.md as ANTIBOT Layer 4's *volume tax*: a
//! memory-hard challenge that prices per-action volume, tiered by abuse-
//! proneness. It judges no individual — you either did the work or you
//! did not, so there is nothing to misclassify (zero false positives).
//!
//! Interface, in full: `Tier`, `Difficulty`, `Challenge`, `Solution`,
//! `difficultyFor`, `challengeFor`, `leadingZeroBits`, `meetsTarget`,
//! `validate`, `digest_len`, `Error`. The memory-hard computation that
//! turns a `(Challenge, Solution)` into a digest lives in `shell/pow.zig`
//! — see the reconciliation note below.
//!
//! ── Reconciliation with POW_MODULE_DESIGN.md (recorded per H3) ──
//! The design doc placed `verify` in the pure core. Under Zig 0.16.0,
//! `std.crypto.pwhash.argon2.kdf` now takes a trailing `io: std.Io`
//! (it spawns worker threads for `p > 1`). `Io` is the carrier of
//! clock / randomness / network, and B4 forbids the core from holding
//! that capability. So the line is drawn one notch tighter than the doc:
//!   • the digest *computation* (the kdf call) is the SHELL seam
//!     (`shell/pow.zig`), where the `Io` lives;
//!   • the digest *check* (`leadingZeroBits` / `meetsTarget`) stays pure
//!     CORE here — it is the whole security-relevant comparison and needs
//!     no allocator, no `Io`, no clock. It is trivially unit-testable.
//! This keeps every B-law satisfied; it does not bend the ruleset, it
//! chooses the module-internal split that honors it. (When in doubt,
//! obey the stricter reading — RULESET preamble.)

const std = @import("std");
const assert = std.debug.assert;

/// The Argon2 digest width this module works over (bytes). 32 bytes =
/// 256 bits of output to count leading zeros against.
pub const digest_len = 32;

/// Errors this module can surface for a malformed difficulty. Kept as an
/// explicit set (E3) so a caller cannot forget to handle a weak tier.
/// `define errors out of existence` (E4) is applied elsewhere — e.g.
/// `difficultyFor(.none)` returns an absent optional, not an error.
pub const Error = error{
    /// The difficulty's params fall below what Argon2 (RFC 9106) accepts,
    /// or below this module's own floor. Surfaced by `validate` so the
    /// failure is named here, not as a generic library error downstream.
    WeakDifficulty,
};

/// The smallest memory cost (KiB) this module will let through `validate`.
/// Argon2 itself rejects `m < 8 * p`; we pin the same floor explicitly so
/// the invariant lives in OUR code, not in trust of std (DESIGN §6.2).
/// NOTE: this is a *correctness* floor, not the *security* floor — a real
/// deterrent tier must exceed this by orders of magnitude (see §calibration).
const floor_mem_kib: u32 = 8;

// ── Data model (A1: plain data, fields only; behavior is free functions) ──

/// Which difficulty class an action draws (DESIGN §2.1). ANTIBOT Layer 4
/// tiering: trivial actions get `.none` (no PoW issued at all), ordinary
/// posting `.light`, mass/amplifying actions `.heavy`. Subscribers
/// (Layer 3) bypass — enforced by the *caller*, never seen here: this
/// module only ever prices work, it never knows about a subscription.
///
/// An enum, not a record — the size-guard audit (A7) governs structs; a
/// config enum held in single quantity is cold by nature.
pub const Tier = enum(u8) {
    none = 0, // open app, like — NO challenge issued
    light = 1, // ordinary posting
    heavy = 2, // mass posting, amplification
};

/// The calibrated Argon2 cost for one tier, plus the digest target the
/// solution must beat (DESIGN §2.2). `mem_kib` / `iters` / `lanes` map
/// directly onto `argon2.Params{ .m, .t, .p }`. `leading_zero_bits` is
/// the NIP-13-style PoW target applied to the Argon2 digest.
///
/// A7.2: cold struct — there are exactly `Tier`-count of these, set once
/// from the calibration table, never iterated in a hot loop. Size guard
/// waived. (Token present for the A7 audit gate.)
pub const Difficulty = struct {
    mem_kib: u32, // Argon2 Params.m — the memory-hard knob (the deterrent)
    iters: u32, // Argon2 Params.t — time cost, kept low (DESIGN §6.1)
    lanes: u8, // Argon2 Params.p — parallelism (widened to u24 at the seam)
    leading_zero_bits: u8, // PoW target on the digest
};

/// A single issued challenge (DESIGN §2.3). Held in quantity — one per
/// pending action, potentially many in flight across a verification batch
/// — therefore HOT, therefore a size guard is mandatory (A7).
///
/// `seed` is the bound input the nonce is appended to (e.g. derived by the
/// caller from the action's CID plus an issue nonce). A fixed 32 bytes
/// keeps a pointer/slice out of the hot struct (A4/A6); who *derives* the
/// seed in a decentralized atproto world is the deferred integration
/// question (DESIGN §5), not this struct's concern.
pub const Challenge = struct {
    seed: [32]u8, // bound input the nonce is appended to
    tier: Tier, // which Difficulty applies (u8 enum)
    _reserved: [7]u8, // A6: explicit, named padding; room for a future flag byte

    comptime {
        // Budget: 32 (seed) + 1 (tier) + 7 (reserved) = 40 bytes, exact,
        // align 1, no hidden padding. Raising this requires an A7.1
        // justification recorded in this comment.
        assert(@sizeOf(Challenge) == 40);
    }
};

/// The client's answer (DESIGN §2.4): the nonce that makes the digest of
/// `seed ‖ nonce` meet the target. Held wherever Challenges are → HOT →
/// size guard mandatory (A7). No digest is stored: verification recomputes
/// it (one kdf call), which defines the "stored hash mismatched" case out
/// of existence (E4) and keeps this struct minimal (A6).
pub const Solution = struct {
    nonce: u64, // the found counter

    comptime {
        // Budget: 8 bytes, exact.
        assert(@sizeOf(Solution) == 8);
    }
};

// ── Free functions (A1: behavior lives here, not on the records) ──

/// PURE (B2): map a tier to its difficulty. Returns an absent optional for
/// `.none` — "no work is owed" is an ordinary result, not an error (E4).
/// The caller checks the optional; a `null` means *issue no challenge*.
pub fn difficultyFor(tier: Tier) ?Difficulty {
    return switch (tier) {
        .none => null,
        .light => calibration.light,
        .heavy => calibration.heavy,
    };
}

/// PURE (B2): construct the challenge a caller will hand to the solver.
/// The seed binding is the caller's to compute (DESIGN §5); this only
/// packages it with its tier as plain data.
pub fn challengeFor(seed: [32]u8, tier: Tier) Challenge {
    return .{ .seed = seed, .tier = tier, ._reserved = .{0} ** 7 };
}

/// PURE (B2): derive a challenge seed bound to a specific post — SHA-256
/// over the post text and its creation time. Deterministic, no I/O, no
/// allocator (the hash state is a stack value), so it is core. Binding the
/// seed to the content means the work proves effort *for this post*, not a
/// pre-computed nonce reusable across posts. (In the eventual decentralized
/// flow the issuer supplies the seed — DESIGN §5; this is the client-side
/// prototype derivation until then.)
pub fn seedForPost(text: []const u8, created_at: i64) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(text);
    var when: [8]u8 = undefined;
    std.mem.writeInt(i64, &when, created_at, .little);
    h.update(&when);
    var seed: [32]u8 = undefined;
    h.final(&seed);
    return seed;
}

/// PURE (B2): count leading zero bits of the digest, most-significant
/// first (byte 0's high bit is bit 0). This is the NIP-13 difficulty
/// measure applied to the Argon2 output. Returns `u16` so an (astronomically
/// improbable) all-zero 256-bit digest — 256 zeros — cannot overflow.
pub fn leadingZeroBits(digest: *const [digest_len]u8) u16 {
    var count: u16 = 0;
    for (digest) |byte| {
        if (byte == 0) {
            count += 8;
            continue;
        }
        count += @clz(byte);
        break;
    }
    return count;
}

/// PURE (B2): the whole security-relevant check. Same digest + target ⇒
/// same bool, no I/O, no allocator. This is what the shell seam calls
/// after computing the digest, and what tests exercise in isolation.
pub fn meetsTarget(digest: *const [digest_len]u8, target_bits: u8) bool {
    return leadingZeroBits(digest) >= target_bits;
}

/// PURE (B2): reject a difficulty whose params Argon2 (RFC 9106) would
/// refuse, naming the failure as `WeakDifficulty` (E3) so the shell never
/// surfaces a generic library error for a bad tier. Invariants pinned HERE,
/// not in trust of std (DESIGN §6.2): t ≥ 1, p ≥ 1, m ≥ 8·p, m ≥ floor.
pub fn validate(d: Difficulty) Error!void {
    if (d.iters < 1) return Error.WeakDifficulty;
    if (d.lanes < 1) return Error.WeakDifficulty;
    if (d.mem_kib < floor_mem_kib) return Error.WeakDifficulty;
    // Argon2's own gate is `m / 8 >= p`; pin it explicitly.
    if (d.mem_kib / 8 < d.lanes) return Error.WeakDifficulty;
}

/// The per-tier cost table.
///
/// ⚠️ PLACEHOLDER VALUES — NOT YET CALIBRATED. ⚠️
/// Per G1 ("no path is 'tuned' without a number") and DESIGN §6.1, the
/// real work is empirical, per-device calibration against the *slowest*
/// honest phone. These numbers are valid Argon2 params and give a working
/// roundtrip, but the deterrent strength is unproven and MUST be tuned
/// before this tax ships on the write path. The cost model to calibrate
/// against:
///   expected attempts ≈ 2^leading_zero_bits
///   cost per attempt  ≈ Argon2(mem_kib, iters, lanes)   (memory-hard)
///   total honest cost ≈ 2^leading_zero_bits · per-attempt
/// Memory carries the deterrent (it bites a farm's parallelism without
/// punishing one honest one-at-a-time solve); keep `iters` low (DESIGN §6.1).
///
/// A1/A7 do not apply: this is a namespace of compile-time constants, not a
/// record held in quantity — no instances, no hot loop, nothing to size-guard.
const calibration = struct {
    /// PROTOTYPE STANDARD — a single, deliberately-easy memory-based tax
    /// so the mechanism can be exercised end-to-end without a noticeable
    /// wait. 4 MiB per attempt (genuinely memory-hard — the deterrent is
    /// the buffer, not CPU), 2^4 ≈ 16 expected attempts. Measured at
    /// ~5 ms/hash on a dev box → ~80 ms to solve. The whole prototype
    /// draws THIS difficulty for every post; per-tier fine-tuning against
    /// the slowest honest device is deferred (DESIGN §6.1, G1). NOT a
    /// calibrated production value.
    const light: Difficulty = .{
        .mem_kib = 4 * 1024,
        .iters = 1,
        .lanes = 1,
        .leading_zero_bits = 4,
    };
    /// Mass / amplifying actions. 64 MiB, 2^6 ≈ 64 expected attempts.
    /// Untouched placeholder — the prototype write path does not draw this
    /// yet; it lands when tiering is wired (DESIGN §5).
    const heavy: Difficulty = .{
        .mem_kib = 64 * 1024,
        .iters = 3,
        .lanes = 1,
        .leading_zero_bits = 6,
    };
};

// ── Tests: the pure core, no Io, no allocator ──

test "leadingZeroBits counts MSB-first across bytes" {
    const all_zero = [_]u8{0} ** digest_len;
    try std.testing.expectEqual(@as(u16, 256), leadingZeroBits(&all_zero));

    var one_top = [_]u8{0} ** digest_len;
    one_top[0] = 0b1000_0000; // first bit set → zero leading zeros
    try std.testing.expectEqual(@as(u16, 0), leadingZeroBits(&one_top));

    var byte_and_a_half = [_]u8{0} ** digest_len;
    byte_and_a_half[1] = 0b0001_0000; // 8 (byte 0) + 3 (clz of 0x10) = 11
    try std.testing.expectEqual(@as(u16, 11), leadingZeroBits(&byte_and_a_half));
}

test "meetsTarget is an inclusive threshold" {
    var d = [_]u8{0} ** digest_len;
    d[1] = 0b0000_0001; // 8 + 7 = 15 leading zeros
    try std.testing.expect(meetsTarget(&d, 15)); // exactly meets
    try std.testing.expect(meetsTarget(&d, 14)); // exceeds
    try std.testing.expect(!meetsTarget(&d, 16)); // falls short
}

test "difficultyFor: none owes no work, others are valid params" {
    try std.testing.expect(difficultyFor(.none) == null);
    inline for (.{ Tier.light, Tier.heavy }) |t| {
        const d = difficultyFor(t).?;
        try std.testing.expectEqual({}, try validate(d)); // never WeakDifficulty
    }
}

test "validate rejects sub-floor params with a named error" {
    try std.testing.expectError(Error.WeakDifficulty, validate(.{
        .mem_kib = 4, // below floor and below 8·p
        .iters = 1,
        .lanes = 1,
        .leading_zero_bits = 1,
    }));
    try std.testing.expectError(Error.WeakDifficulty, validate(.{
        .mem_kib = 8,
        .iters = 0, // t must be ≥ 1
        .lanes = 1,
        .leading_zero_bits = 1,
    }));
}

test "challengeFor packages seed and tier as plain data" {
    const seed = [_]u8{0xA5} ** 32;
    const c = challengeFor(seed, .light);
    try std.testing.expectEqual(Tier.light, c.tier);
    try std.testing.expectEqualSlices(u8, &seed, &c.seed);
}

test "seedForPost is deterministic and content-bound" {
    const a = seedForPost("hello world", 1_767_323_045);
    const same = seedForPost("hello world", 1_767_323_045);
    try std.testing.expectEqualSlices(u8, &a, &same); // same input ⇒ same seed

    const diff_text = seedForPost("hello worlx", 1_767_323_045);
    const diff_time = seedForPost("hello world", 1_767_323_046);
    try std.testing.expect(!std.mem.eql(u8, &a, &diff_text)); // text binds
    try std.testing.expect(!std.mem.eql(u8, &a, &diff_time)); // time binds
}
