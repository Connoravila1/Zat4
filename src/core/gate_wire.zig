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

//! B1 classification: CORE (pure). The **Constellation Gate's wire format** —
//! how a PoW ticket crosses the network and how a redemption comes back.
//! Specced in `CONSTELLATION_GATE_DESIGN.md` §9.7.
//!
//! ── Why this is fixed-size hex and not JSON ──
//! The gate's endpoint is public and UNAUTHENTICATED — the user has no account
//! yet — which makes everything it parses the highest-risk code in the product
//! (§9.7). Zig is manual-memory, so an attacker-driven parser is exactly where
//! a memory bug would land. So the format gives an attacker nothing to work
//! with: a ticket is a FIXED 114 hex characters over a FIXED 57-byte canonical
//! layout. Length is checked before anything is read, every field is at a
//! constant offset, and no allocation anywhere depends on attacker input.
//! There is no JSON parser on this path, no length prefix to lie about, and no
//! variable-length field at all.
//!
//! Encoding is explicit field-by-field rather than a struct memcpy: `Ticket`
//! has padding and host byte order, neither of which belongs on a wire.
//!
//! Interface, in full: `ticket_wire_len`, `encodeTicket`, `decodeTicket`,
//! `Refusal`, `refusalCode`, `parseIpV4Mapped`, `nonce_wire_max`,
//! `encodeNonce`, `decodeNonce`.

const std = @import("std");
const assert = std.debug.assert;
const pow = @import("pow.zig");
const pow_issue = @import("pow_issue.zig");

/// The canonical on-wire byte layout of a ticket, before hex:
///   [0..32)  seed
///   [32..40) issued_at, i64 little-endian
///   [40..41) tier
///   [41..57) mac
const wire_bytes = 57;

/// A ticket on the wire: `wire_bytes` hex-encoded. Fixed, always.
pub const ticket_wire_len = wire_bytes * 2;

/// Longest decimal u64, for the solution nonce.
pub const nonce_wire_max = 20;

/// PURE (B2): encode a ticket to its fixed-length hex form.
///
/// Returns an array by value — no allocator (C1/C2) and no caller-supplied
/// buffer to get the size of wrong.
pub fn encodeTicket(t: pow_issue.Ticket) [ticket_wire_len]u8 {
    var raw: [wire_bytes]u8 = undefined;
    @memcpy(raw[0..32], &t.seed);
    std.mem.writeInt(i64, raw[32..40], t.issued_at, .little);
    raw[40] = @intFromEnum(t.tier);
    @memcpy(raw[41..57], &t.mac);

    var out: [ticket_wire_len]u8 = undefined;
    for (raw, 0..) |b, i| {
        out[i * 2] = hexDigit(b >> 4);
        out[i * 2 + 1] = hexDigit(b & 0x0F);
    }
    return out;
}

/// PURE (B2): decode a ticket from its hex form.
///
/// Returns an absent optional for ANY malformed input — wrong length, a
/// non-hex character, an out-of-range tier (E4: a bad request is an ordinary
/// result, not an error). The length check comes first, so a short input is
/// never indexed past its end.
///
/// Decoding does NOT authenticate. A decoded ticket is attacker-controlled
/// bytes in a known shape and nothing more; `pow_issue.checkTicket` is what
/// decides whether the server actually issued it. Keeping those two steps
/// separate is deliberate — a decoder that "validated" would invite callers to
/// skip the MAC check.
pub fn decodeTicket(s: []const u8) ?pow_issue.Ticket {
    if (s.len != ticket_wire_len) return null;

    var raw: [wire_bytes]u8 = undefined;
    for (&raw, 0..) |*b, i| {
        const hi = hexValue(s[i * 2]) orelse return null;
        const lo = hexValue(s[i * 2 + 1]) orelse return null;
        b.* = (hi << 4) | lo;
    }

    // The tier is an enum with three members; anything else is malformed.
    // Checked explicitly rather than via @enumFromInt, which would be illegal
    // behavior on an out-of-range value.
    const tier: pow.Tier = switch (raw[40]) {
        0 => .none,
        1 => .light,
        2 => .heavy,
        else => return null,
    };

    var t: pow_issue.Ticket = .{
        .seed = undefined,
        .issued_at = std.mem.readInt(i64, raw[32..40], .little),
        .mac = undefined,
        .tier = tier,
    };
    @memcpy(&t.seed, raw[0..32]);
    @memcpy(&t.mac, raw[41..57]);
    return t;
}

/// PURE (B2): encode a solution nonce as decimal. Returns the used slice of
/// `buf`, which the caller owns and sizes with `nonce_wire_max`.
pub fn encodeNonce(buf: *[nonce_wire_max]u8, nonce: u64) []const u8 {
    if (nonce == 0) {
        buf[0] = '0';
        return buf[0..1];
    }
    var n = nonce;
    var i: usize = nonce_wire_max;
    while (n > 0) {
        i -= 1;
        buf[i] = '0' + @as(u8, @intCast(n % 10));
        n /= 10;
    }
    return buf[i..];
}

/// PURE (B2): decode a decimal nonce. Absent optional on anything malformed —
/// empty, over-long, non-digit, or overflowing u64 (E4).
///
/// The length gate comes first so an over-long input cannot spin the loop, and
/// the multiply is checked rather than wrapped: a wrapped nonce would decode to
/// a DIFFERENT number than the client sent, whose digest would not meet the
/// target, and the honest user would see an inexplicable refusal.
pub fn decodeNonce(s: []const u8) ?u64 {
    if (s.len == 0 or s.len > nonce_wire_max) return null;
    var n: u64 = 0;
    for (s) |c| {
        if (c < '0' or c > '9') return null;
        n = std.math.mul(u64, n, 10) catch return null;
        n = std.math.add(u64, n, c - '0') catch return null;
    }
    return n;
}

/// Why a redemption was refused.
///
/// Each variant maps to a distinct wire code so the CLIENT can react correctly
/// — re-solve, re-request a ticket, or stop. This is the same reasoning as
/// `pow_issue.TicketState` being four-valued: collapsing refusals into one
/// "no" would leave an honest client unable to tell "your work was wrong" from
/// "your ticket aged out", which are opposite instructions.
///
/// What the codes deliberately do NOT distinguish is anything an attacker could
/// use to probe server state. `.forged` and `.replayed` are both real answers,
/// but neither reveals *which* stored value was consulted.
pub const Refusal = enum(u8) {
    /// The ticket did not decode: wrong length, bad hex, unknown tier.
    malformed = 0,
    /// The MAC did not verify. We did not issue this.
    forged = 1,
    /// Authentic but past its TTL. The client should request a new ticket.
    expired = 2,
    /// Authentic but ahead of our clock beyond tolerance. OUR fault, not the
    /// client's — surfaced separately so it is diagnosable rather than
    /// mistaken for an attack.
    clock_skew = 3,
    /// The nonce does not meet the difficulty target. The work is not done.
    unsolved = 4,
    /// This ticket was already redeemed inside its window.
    replayed = 5,
    /// The replay set is full — more solved tickets in one TTL than the
    /// operator provisioned for. Fails CLOSED (`pow_issue.checkAndSpend`).
    /// This is a capacity signal, and it is the operator's to act on.
    at_capacity = 6,
    /// The ticket's tier carries no difficulty (`.none`), so there is no work
    /// to check. A ticket that demands nothing must never buy anything.
    no_work_required = 7,
};

/// PURE (B2): the short wire code for a refusal. Stable strings — a client may
/// branch on these, so they are part of the interface, not debug text.
pub fn refusalCode(r: Refusal) []const u8 {
    return switch (r) {
        .malformed => "Malformed",
        .forged => "Forged",
        .expired => "Expired",
        .clock_skew => "ClockSkew",
        .unsolved => "Unsolved",
        .replayed => "Replayed",
        .at_capacity => "AtCapacity",
        .no_work_required => "NoWorkRequired",
    };
}

/// PURE (B2): parse a dotted-quad IPv4 address into its IPv6-mapped 16-byte
/// form (`::ffff:a.b.c.d`), which is what `constellation.Observation.ip` wants.
///
/// Absent optional on anything that is not a well-formed dotted quad (E4).
///
/// ── Known limitation, stated rather than hidden ──
/// Literal IPv6 text is NOT parsed here and yields null, so an IPv6 client
/// currently contributes no `ip_shared` token. That is a missing signal, not a
/// wrong one — and a missing signal is the safe failure direction, because
/// `constellation.derive` emits no token for an absent observation rather than
/// a sentinel that would cluster every IPv6 user together. Full IPv6 parsing is
/// a follow-up; doing it badly would be worse than not doing it.
pub fn parseIpV4Mapped(s: []const u8) ?[16]u8 {
    var out: [16]u8 = .{0} ** 16;
    out[10] = 0xFF;
    out[11] = 0xFF;

    var octet: usize = 0;
    var it = std.mem.splitScalar(u8, s, '.');
    while (it.next()) |part| {
        if (octet >= 4) return null; // five or more segments
        if (part.len == 0 or part.len > 3) return null;
        var v: u16 = 0;
        for (part) |c| {
            if (c < '0' or c > '9') return null;
            v = v * 10 + (c - '0');
        }
        if (v > 255) return null;
        out[12 + octet] = @intCast(v);
        octet += 1;
    }
    if (octet != 4) return null;
    return out;
}

fn hexDigit(nibble: u8) u8 {
    assert(nibble < 16);
    return if (nibble < 10) '0' + nibble else 'a' + (nibble - 10);
}

fn hexValue(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10, // accept either case on the way in
        else => null,
    };
}

// ── Tests: the pure core, no Io, no allocator ──

const test_key: pow_issue.Key = [_]u8{0x77} ** pow_issue.key_len;

fn sampleTicket() pow_issue.Ticket {
    return pow_issue.issue(test_key, [_]u8{0x42} ** 32, 1_767_323_045, .heavy);
}

test "a ticket round-trips through the wire form exactly" {
    const t = sampleTicket();
    const wire = encodeTicket(t);
    try std.testing.expectEqual(@as(usize, ticket_wire_len), wire.len);

    const back = decodeTicket(&wire).?;
    try std.testing.expectEqualSlices(u8, &t.seed, &back.seed);
    try std.testing.expectEqual(t.issued_at, back.issued_at);
    try std.testing.expectEqual(t.tier, back.tier);
    try std.testing.expectEqualSlices(u8, &t.mac, &back.mac);

    // And the decoded ticket still authenticates — the wire form is lossless
    // over every field the MAC covers.
    try std.testing.expectEqual(
        pow_issue.TicketState.valid,
        pow_issue.checkTicket(test_key, back, t.issued_at, 180, 30),
    );
}

test "decodeTicket refuses every malformed shape without reading out of bounds" {
    const wire = encodeTicket(sampleTicket());

    try std.testing.expect(decodeTicket("") == null);
    try std.testing.expect(decodeTicket("ab") == null);
    try std.testing.expect(decodeTicket(wire[0 .. ticket_wire_len - 1]) == null); // short
    try std.testing.expect(decodeTicket(wire[0..10]) == null); // very short

    var too_long: [ticket_wire_len + 1]u8 = undefined;
    @memcpy(too_long[0..ticket_wire_len], &wire);
    too_long[ticket_wire_len] = 'a';
    try std.testing.expect(decodeTicket(&too_long) == null);

    var bad_hex = wire;
    bad_hex[5] = 'z';
    try std.testing.expect(decodeTicket(&bad_hex) == null);

    // An out-of-range tier byte is malformed, NOT illegal behavior. Byte 40 of
    // the raw layout is the tier, so hex offsets 80 and 81.
    var bad_tier = wire;
    bad_tier[80] = '0';
    bad_tier[81] = '9'; // tier = 9
    try std.testing.expect(decodeTicket(&bad_tier) == null);
}

test "the wire form is case-insensitive on input and lowercase on output" {
    const wire = encodeTicket(sampleTicket());
    for (wire) |c| try std.testing.expect(c < 'A' or c > 'F'); // emitted lowercase

    var upper: [ticket_wire_len]u8 = undefined;
    for (wire, 0..) |c, i| upper[i] = std.ascii.toUpper(c);
    const a = decodeTicket(&wire).?;
    const b = decodeTicket(&upper).?;
    try std.testing.expectEqualSlices(u8, &a.mac, &b.mac);
}

test "a tampered wire ticket decodes but does NOT authenticate" {
    // Decoding is not validation — the point of keeping them separate.
    var wire = encodeTicket(sampleTicket());
    wire[0] = if (wire[0] == 'a') 'b' else 'a'; // flip a seed nibble
    const tampered = decodeTicket(&wire).?; // still well-formed...
    try std.testing.expectEqual(
        pow_issue.TicketState.forged, // ...but not ours
        pow_issue.checkTicket(test_key, tampered, 1_767_323_045, 180, 30),
    );
}

test "nonce round-trips and refuses malformed input" {
    var buf: [nonce_wire_max]u8 = undefined;
    for ([_]u64{ 0, 1, 9, 10, 12_345, std.math.maxInt(u64) }) |n| {
        try std.testing.expectEqual(n, decodeNonce(encodeNonce(&buf, n)).?);
    }

    try std.testing.expect(decodeNonce("") == null);
    try std.testing.expect(decodeNonce("12a") == null);
    try std.testing.expect(decodeNonce("-1") == null);
    try std.testing.expect(decodeNonce(" 1") == null);
    // Overflows u64: checked, not wrapped. A wrapped nonce would decode to a
    // different number than was sent and refuse an honest client for no
    // visible reason.
    try std.testing.expect(decodeNonce("18446744073709551616") == null);
    try std.testing.expect(decodeNonce("999999999999999999999") == null);
}

test "parseIpV4Mapped produces the v6-mapped form and rejects junk" {
    const ip = parseIpV4Mapped("203.0.113.7").?;
    try std.testing.expectEqual(@as(u8, 0xFF), ip[10]);
    try std.testing.expectEqual(@as(u8, 0xFF), ip[11]);
    try std.testing.expectEqual(@as(u8, 203), ip[12]);
    try std.testing.expectEqual(@as(u8, 7), ip[15]);
    for (ip[0..10]) |b| try std.testing.expectEqual(@as(u8, 0), b);

    try std.testing.expect(parseIpV4Mapped("") == null);
    try std.testing.expect(parseIpV4Mapped("203.0.113") == null); // too few
    try std.testing.expect(parseIpV4Mapped("203.0.113.7.9") == null); // too many
    try std.testing.expect(parseIpV4Mapped("203.0.113.256") == null); // range
    try std.testing.expect(parseIpV4Mapped("203.0.113.") == null); // empty octet
    try std.testing.expect(parseIpV4Mapped("203.0.113.0007") == null); // over-long
    try std.testing.expect(parseIpV4Mapped("a.b.c.d") == null);
    try std.testing.expect(parseIpV4Mapped("::ffff:203.0.113.7") == null); // v6: absent, not wrong
}

test "distinct addresses map to distinct bytes" {
    const a = parseIpV4Mapped("10.0.0.1").?;
    const b = parseIpV4Mapped("10.0.0.2").?;
    try std.testing.expect(!std.mem.eql(u8, &a, &b));
}

test "every refusal has a distinct, stable wire code" {
    const all = [_]Refusal{
        .malformed, .forged, .expired, .clock_skew,
        .unsolved,  .replayed, .at_capacity, .no_work_required,
    };
    for (all, 0..) |r, i| {
        const code = refusalCode(r);
        try std.testing.expect(code.len > 0);
        for (all[i + 1 ..]) |other| {
            try std.testing.expect(!std.mem.eql(u8, code, refusalCode(other)));
        }
    }
}
