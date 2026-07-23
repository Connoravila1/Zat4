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

//! B1 classification: CORE (pure). RTP packetization/depacketization (RFC 3550)
//! for Zat Chat calling, plus the Opus payload convention (RFC 7587). This is
//! the media-transport layer the "build it ourselves" ruling unlocks
//! (ZAT_CHAT_CALLING_ROADMAP.md §3 decision #9). It owns only the RTP framing;
//! encryption is `srtp.zig`, key derivation is `media_keys.zig`, and the
//! playout ordering is `jitter.zig`.
//!
//! PURE (B2/B3/B4): no clock, no RNG, no I/O. Sequence numbers, timestamps, and
//! the SSRC are handed in by the shell (which owns the media clock); serialize
//! and parse are pure byte transforms, so the wire format is fully
//! unit-testable headlessly (see the round-trip tests at the foot).
//!
//! v1 is voice-first: we EMIT only V=2, no padding, no extension, no CSRC
//! (CC=0). We PARSE robustly — CSRC lists and a header extension are skipped to
//! locate the payload — so a conformant peer is never mis-framed. Video NAL
//! fragmentation (RFC 6184/7798) is a later slice.

const std = @import("std");
const assert = std.debug.assert;

/// The fixed RTP header length in bytes (RFC 3550 §5.1), before any CSRC list
/// or header extension.
pub const fixed_header_len = 12;

/// RTP version this stack speaks (RFC 3550: always 2).
pub const version: u2 = 2;

/// A suggested dynamic payload type for Opus (RFC 7587 uses a dynamic PT
/// negotiated in SDP; pinned here for v1 until signaling negotiates it).
pub const opus_payload_type: u8 = 111;

/// PLAIN DATA (A1). The parts of an RTP header this stack varies per packet —
/// HOT (one per media packet, produced in a tight loop). The constant fields
/// (version=2, padding=0, extension=0, csrc_count=0 on emit) are not stored
/// (A6): they would be dead weight in the hot record.
pub const RtpHeader = struct {
    timestamp: u32, // media-clock timestamp (shell-supplied)
    ssrc: u32, // synchronization source id
    sequence: u16, // per-packet sequence number
    payload_type: u8, // 7-bit PT (high bit must be 0)
    marker: bool, // frame-boundary / event marker

    comptime {
        // Budget: u32+u32 = 8, then u16+u8+bool = 4. 12 exact, align 4, no tail
        // padding. Raising this requires a recorded justification per A7.1.
        assert(@sizeOf(RtpHeader) == 12);
    }
};

/// The result of parsing a packet: the varying header fields plus the payload,
/// borrowed from the input. A7.2: cold struct, size guard waived — a transient
/// return value, never stored in a collection or scanned in bulk.
pub const Parsed = struct {
    header: RtpHeader,
    payload: []const u8,
};

pub const SerializeError = error{ BufferTooSmall, BadPayloadType };
pub const ParseError = error{ Truncated, BadVersion, BadPayloadType };

/// Serialize `header` + `payload` into `buf` (V=2, no padding/extension/CSRC),
/// returning the total frame length. Pure.
pub fn serialize(header: RtpHeader, payload: []const u8, buf: []u8) SerializeError!usize {
    if (header.payload_type & 0x80 != 0) return error.BadPayloadType; // PT is 7-bit
    const total = fixed_header_len + payload.len;
    if (buf.len < total) return error.BufferTooSmall;

    // Byte 0: V(2)=2, P(1)=0, X(1)=0, CC(4)=0.
    buf[0] = @as(u8, version) << 6;
    // Byte 1: M(1), PT(7).
    buf[1] = (@as(u8, @intFromBool(header.marker)) << 7) | (header.payload_type & 0x7f);
    std.mem.writeInt(u16, buf[2..][0..2], header.sequence, .big);
    std.mem.writeInt(u32, buf[4..][0..4], header.timestamp, .big);
    std.mem.writeInt(u32, buf[8..][0..4], header.ssrc, .big);
    @memcpy(buf[fixed_header_len..][0..payload.len], payload);
    return total;
}

/// Parse an RTP packet. Skips any CSRC list and header extension so the payload
/// slice is located correctly even for traffic we don't emit (E4: robust to
/// conformant variation rather than erroring on it). The payload borrows from
/// `frame`.
pub fn parse(frame: []const u8) ParseError!Parsed {
    if (frame.len < fixed_header_len) return error.Truncated;

    const v: u2 = @intCast(frame[0] >> 6);
    if (v != version) return error.BadVersion;
    const has_extension = (frame[0] & 0x10) != 0;
    const csrc_count: usize = frame[0] & 0x0f;

    const marker = (frame[1] & 0x80) != 0;
    const payload_type: u8 = frame[1] & 0x7f;

    const sequence = std.mem.readInt(u16, frame[2..][0..2], .big);
    const timestamp = std.mem.readInt(u32, frame[4..][0..4], .big);
    const ssrc = std.mem.readInt(u32, frame[8..][0..4], .big);

    // Advance past the CSRC list.
    var off: usize = fixed_header_len + csrc_count * 4;
    if (frame.len < off) return error.Truncated;

    // Advance past a one-word-header extension if present (RFC 3550 §5.3.1):
    // [profile:u16][length:u16 (in 32-bit words)] then length words.
    if (has_extension) {
        if (frame.len < off + 4) return error.Truncated;
        const ext_words = std.mem.readInt(u16, frame[off + 2 ..][0..2], .big);
        off += 4 + @as(usize, ext_words) * 4;
        if (frame.len < off) return error.Truncated;
    }

    return .{
        .header = .{
            .timestamp = timestamp,
            .ssrc = ssrc,
            .sequence = sequence,
            .payload_type = payload_type,
            .marker = marker,
        },
        .payload = frame[off..],
    };
}

// ---------------------------------------------------------------------------
// Tests (B2/C6 — pure, deterministic; no allocator needed)
// ---------------------------------------------------------------------------

const testing = std.testing;

test "header + payload round-trips" {
    const h: RtpHeader = .{
        .timestamp = 0xDEAD_BEEF,
        .ssrc = 0x0102_0304,
        .sequence = 0xABCD,
        .payload_type = opus_payload_type,
        .marker = true,
    };
    const payload = "opus-frame-bytes";

    var buf: [256]u8 = undefined;
    const n = try serialize(h, payload, &buf);
    try testing.expectEqual(@as(usize, fixed_header_len + payload.len), n);

    const got = try parse(buf[0..n]);
    try testing.expectEqual(h.timestamp, got.header.timestamp);
    try testing.expectEqual(h.ssrc, got.header.ssrc);
    try testing.expectEqual(h.sequence, got.header.sequence);
    try testing.expectEqual(h.payload_type, got.header.payload_type);
    try testing.expectEqual(h.marker, got.header.marker);
    try testing.expectEqualSlices(u8, payload, got.payload);
}

test "emitted first byte is exactly V=2, no padding/extension/CSRC" {
    var buf: [32]u8 = undefined;
    const n = try serialize(.{ .timestamp = 0, .ssrc = 0, .sequence = 1, .payload_type = 0, .marker = false }, "x", &buf);
    try testing.expectEqual(@as(u8, 0x80), buf[0]); // 10_000000
    try testing.expectEqual(@as(usize, fixed_header_len + 1), n);
}

test "parse skips a CSRC list to locate the payload" {
    // Hand-build a header with CC=2 and two CSRC words before the payload.
    var frame: [fixed_header_len + 8 + 3]u8 = undefined;
    frame[0] = (@as(u8, version) << 6) | 0x02; // V=2, CC=2
    frame[1] = 96; // PT=96, marker off
    std.mem.writeInt(u16, frame[2..][0..2], 7, .big);
    std.mem.writeInt(u32, frame[4..][0..4], 100, .big);
    std.mem.writeInt(u32, frame[8..][0..4], 0xAABBCCDD, .big);
    @memset(frame[12..20], 0); // two CSRC words
    frame[20] = 'a';
    frame[21] = 'b';
    frame[22] = 'c';

    const got = try parse(&frame);
    try testing.expectEqual(@as(u16, 7), got.header.sequence);
    try testing.expectEqual(@as(u32, 0xAABBCCDD), got.header.ssrc);
    try testing.expectEqualSlices(u8, "abc", got.payload);
}

test "parse rejects truncated and wrong-version frames (E3)" {
    var buf: [64]u8 = undefined;
    const n = try serialize(.{ .timestamp = 1, .ssrc = 2, .sequence = 3, .payload_type = 96, .marker = false }, "hi", &buf);
    try testing.expectError(error.Truncated, parse(buf[0..8]));
    buf[0] = 0x40; // version 1
    try testing.expectError(error.BadVersion, parse(buf[0..n]));
}

test "serialize rejects an 8-bit payload type and a too-small buffer (E3)" {
    var small: [4]u8 = undefined;
    try testing.expectError(error.BufferTooSmall, serialize(.{ .timestamp = 0, .ssrc = 0, .sequence = 0, .payload_type = 96, .marker = false }, "payload", &small));
    var buf: [64]u8 = undefined;
    try testing.expectError(error.BadPayloadType, serialize(.{ .timestamp = 0, .ssrc = 0, .sequence = 0, .payload_type = 0x80, .marker = false }, "x", &buf));
}

test "serialize/parse is deterministic (B2)" {
    const h: RtpHeader = .{ .timestamp = 42, .ssrc = 7, .sequence = 9, .payload_type = 111, .marker = false };
    var a: [64]u8 = undefined;
    var b: [64]u8 = undefined;
    const na = try serialize(h, "frame", &a);
    const nb = try serialize(h, "frame", &b);
    try testing.expectEqualSlices(u8, a[0..na], b[0..nb]);
}
