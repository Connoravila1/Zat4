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

//! B1 classification: CORE (pure). The **on-disk record** for one observed
//! enrollment — the Constellation Gate's durable format.
//!
//! Separate from `core/gate_wire.zig` on purpose (D1): the wire format is a
//! network protocol and the disk format is a storage decision, and they change
//! for entirely different reasons. Folding them together would couple a
//! protocol bump to a migration.
//!
//! ── What is stored, and what is deliberately NOT ──
//! Derived tokens and a frozen assessment. No IP, no User-Agent, no timestamp
//! of anything but the observation itself, no DID. §2's derive-and-discard
//! doctrine means the raw observation dies with the request that carried it;
//! this record is what outlives it. A breach of this file reveals coordination
//! STRUCTURE and nothing about who anyone is.
//!
//! ── Why the frozen factor lives here (§8A) ──
//! Zat Chat defers the deposit to the Zat4 crossing, so observation and pricing
//! happen at different times. The freeze rule says the assessment is fixed at
//! OBSERVATION time — otherwise a patient user is priced against months of
//! store growth they had no part in. That means the factor must be persisted
//! WITH the tokens, not recomputed later. This field is that rule made durable.
//!
//! ── Fixed-size records, and why the checksum is load-bearing ──
//! Every record is exactly `record_bytes`, so replay is a flat scan and a torn
//! tail (power loss mid-append) is simply a short remainder to drop. The
//! checksum catches the nastier case: a record that is the right LENGTH but
//! garbled. Signals never decay, so match counts only ever grow — a corrupt
//! token replayed once becomes a permanent phantom member of a cluster that
//! nothing will ever remove. Dropping a doubtful record costs one observation;
//! accepting one poisons the store forever.
//!
//! Interface, in full: `record_bytes`, `magic`, `max_tokens`, `Enrollment`,
//! `encode`, `decode`.

const std = @import("std");
const assert = std.debug.assert;
const constellation = @import("constellation.zig");

/// Format tag, version included. A future layout change bumps the last byte and
/// `decode` rejects the old one rather than misreading it — records are fixed
/// size, so a silent misparse would otherwise be perfectly plausible.
pub const magic = [4]u8{ 'Z', 'G', 'S', '1' };

/// Upper bound on tokens per enrollment. Equal to the signal count: one token
/// per signal, and `constellation.derive` cannot emit more.
pub const max_tokens = constellation.signal_count;

/// Exact size of one record on disk.
pub const record_bytes = 128;

// Field offsets in the encoded block. Named so `encode` and `decode` cannot
// drift apart silently.
const off_magic = 0; //  4
const off_subject = 4; //  8
const off_observed = 12; //  8
const off_factor = 20; //  4
const off_len = 24; //  1
// 25..28 reserved
const off_tokens = 28; // 96  (6 × 16)
const off_checksum = 124; //  4

/// One observed enrollment, as it is held in memory.
///
/// A7: held in quantity — one per enrollment, walked on replay. Guarded.
pub const Enrollment = struct {
    /// Links this observation to the enrollment event that produced it. Today
    /// this is the PoW ticket's `spentTag`; when the invite-code pool lands it
    /// becomes the join key that a later DID binding attaches to. Deliberately
    /// NOT a DID: at observation time no account exists yet.
    subject_tag: u64,
    /// Server clock at observation, in SECONDS.
    observed_at: i64,
    /// The FROZEN assessment (§8A) — the deposit multiplier in hundredths, as
    /// computed against the store *at the moment of observation*. Charge time
    /// reads this; it must never re-run `assess`.
    factor_x100: u32,
    /// How many of `tokens` are populated. Fewer than `max_tokens` is normal:
    /// graph shape is always absent at enrollment.
    token_len: u8,
    _reserved: [3]u8 = .{0} ** 3,
    tokens: [max_tokens]constellation.Token,

    comptime {
        // Budget: 8 + 8 + 4 + 1 + 3 (reserved) = 24, then 6 × 16 = 96 of
        // tokens, aligned to 8 by the u64 = 120 bytes in memory. The DISK
        // record is 128 (it also carries magic and checksum); the two sizes
        // are independent on purpose and `encode` is the only bridge.
        assert(@sizeOf(Enrollment) == 120);
    }
};

/// PURE (B2): encode one record. Returns the block by value — no allocator
/// (C1/C2) and no caller buffer whose size could be got wrong.
pub fn encode(e: Enrollment) [record_bytes]u8 {
    var b: [record_bytes]u8 = .{0} ** record_bytes;

    @memcpy(b[off_magic..][0..4], &magic);
    std.mem.writeInt(u64, b[off_subject..][0..8], e.subject_tag, .little);
    std.mem.writeInt(i64, b[off_observed..][0..8], e.observed_at, .little);
    std.mem.writeInt(u32, b[off_factor..][0..4], e.factor_x100, .little);

    // Clamp rather than trust: `token_len` indexes a fixed array on the way
    // back out, and a value past the end would be an out-of-bounds read on
    // every future replay.
    const n = @min(e.token_len, max_tokens);
    b[off_len] = n;

    for (e.tokens[0..n], 0..) |t, i| {
        const at = off_tokens + i * 16;
        std.mem.writeInt(u64, b[at..][0..8], t.value, .little);
        b[at + 8] = @intFromEnum(t.kind);
        // bytes 9..16 stay zero — explicit padding, not incidental
    }

    std.mem.writeInt(u32, b[off_checksum..][0..4], checksum(b[0..off_checksum]), .little);
    return b;
}

/// PURE (B2): decode one record. Absent optional for anything not exactly
/// right — wrong length, bad magic, bad checksum, an over-long `token_len`, or
/// an unknown signal kind (E4: a bad record is an ordinary result).
///
/// Every rejection is a DROP, never a repair. A half-understood record is
/// exactly the thing that must not reach the store.
pub fn decode(b: []const u8) ?Enrollment {
    if (b.len != record_bytes) return null;
    if (!std.mem.eql(u8, b[off_magic..][0..4], &magic)) return null;

    const want = std.mem.readInt(u32, b[off_checksum..][0..4], .little);
    if (checksum(b[0..off_checksum]) != want) return null;

    const n = b[off_len];
    if (n > max_tokens) return null;

    var e: Enrollment = .{
        .subject_tag = std.mem.readInt(u64, b[off_subject..][0..8], .little),
        .observed_at = std.mem.readInt(i64, b[off_observed..][0..8], .little),
        .factor_x100 = std.mem.readInt(u32, b[off_factor..][0..4], .little),
        .token_len = n,
        .tokens = undefined,
    };

    for (0..n) |i| {
        const at = off_tokens + i * 16;
        // The kind is an enum with a fixed member set; anything else is a
        // corrupt record. Checked explicitly — @enumFromInt on an out-of-range
        // value is illegal behavior, not a recoverable error.
        const kind: constellation.SignalKind = switch (b[at + 8]) {
            0 => .timing,
            1 => .graph,
            2 => .pow_class,
            3 => .ip_type,
            4 => .ip_shared,
            5 => .platform,
            else => return null,
        };
        e.tokens[i] = .{
            .value = std.mem.readInt(u64, b[at..][0..8], .little),
            .kind = kind,
        };
    }
    // Slots past `token_len` are never read by callers, but leaving them
    // undefined would make the struct non-deterministic to compare in tests.
    for (n..max_tokens) |i| e.tokens[i] = .{ .value = 0, .kind = .timing };

    return e;
}

/// PURE: CRC-32 (IEEE), the standard choice for exactly this job — catching
/// accidental corruption in a stored block. It is NOT a security control and
/// is not asked to be one: this file is written only by the gate itself, and an
/// attacker who can rewrite it can recompute a checksum trivially. The threat
/// being defended against is a torn write, not a forger.
fn checksum(bytes: []const u8) u32 {
    var c = std.hash.Crc32.init();
    c.update(bytes);
    return c.final();
}

// ── Tests: the pure core, no Io, no allocator ──

fn sample() Enrollment {
    var e: Enrollment = .{
        .subject_tag = 0xDEADBEEFCAFEF00D,
        .observed_at = 1_767_323_045,
        .factor_x100 = 150,
        .token_len = 3,
        .tokens = undefined,
    };
    e.tokens[0] = .{ .value = 0x1111_2222_3333_4444, .kind = .timing };
    e.tokens[1] = .{ .value = 0x5555_6666_7777_8888, .kind = .pow_class };
    e.tokens[2] = .{ .value = 0x9999_AAAA_BBBB_CCCC, .kind = .ip_shared };
    for (3..max_tokens) |i| e.tokens[i] = .{ .value = 0, .kind = .timing };
    return e;
}

test "a record round-trips exactly" {
    const e = sample();
    const b = encode(e);
    try std.testing.expectEqual(@as(usize, record_bytes), b.len);

    const back = decode(&b).?;
    try std.testing.expectEqual(e.subject_tag, back.subject_tag);
    try std.testing.expectEqual(e.observed_at, back.observed_at);
    try std.testing.expectEqual(e.factor_x100, back.factor_x100);
    try std.testing.expectEqual(e.token_len, back.token_len);
    for (0..e.token_len) |i| {
        try std.testing.expectEqual(e.tokens[i].value, back.tokens[i].value);
        try std.testing.expectEqual(e.tokens[i].kind, back.tokens[i].kind);
    }
}

test "the frozen factor survives the round trip" {
    // §8A: charge time reads this value; it must never be recomputed. If it
    // did not persist, deferred pricing would silently fall back to assessing
    // against a store that grew while the user waited.
    var e = sample();
    e.factor_x100 = 400;
    try std.testing.expectEqual(@as(u32, 400), decode(&encode(e)).?.factor_x100);
}

test "a torn or garbled record is DROPPED, never repaired" {
    const b = encode(sample());

    // Short read (a torn tail after power loss).
    try std.testing.expect(decode(b[0 .. record_bytes - 1]) == null);
    try std.testing.expect(decode(b[0..0]) == null);

    // Right length, wrong magic.
    var bad_magic = b;
    bad_magic[0] = 'X';
    try std.testing.expect(decode(&bad_magic) == null);

    // Right length and magic, one flipped bit anywhere in the payload. This is
    // the case the checksum exists for: with no signal decay, a corrupt token
    // accepted once is a permanent phantom cluster member.
    for ([_]usize{ 4, 12, 20, 24, 28, 60, 100, 123 }) |i| {
        var flipped = b;
        flipped[i] ^= 0x01;
        try std.testing.expect(decode(&flipped) == null);
    }
}

test "an over-long token_len is refused rather than read out of bounds" {
    var b = encode(sample());
    b[off_len] = max_tokens + 1;
    // Re-checksum so it is ONLY the length that is wrong — otherwise the
    // checksum would catch it first and this would test nothing.
    std.mem.writeInt(u32, b[off_checksum..][0..4], checksum(b[0..off_checksum]), .little);
    try std.testing.expect(decode(&b) == null);
}

test "an unknown signal kind is refused" {
    var b = encode(sample());
    b[off_tokens + 8] = 99; // kind byte of token 0
    std.mem.writeInt(u32, b[off_checksum..][0..4], checksum(b[0..off_checksum]), .little);
    try std.testing.expect(decode(&b) == null);
}

test "encode clamps an over-long token_len instead of reading past the array" {
    var e = sample();
    e.token_len = 200; // caller bug
    const back = decode(&encode(e)).?;
    try std.testing.expectEqual(@as(u8, max_tokens), back.token_len);
}

test "a zero-token record is valid" {
    // Not expected in practice (timing always fires), but it must round-trip
    // rather than be mistaken for corruption.
    var e = sample();
    e.token_len = 0;
    const back = decode(&encode(e)).?;
    try std.testing.expectEqual(@as(u8, 0), back.token_len);
}
