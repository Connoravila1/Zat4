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

//! B1 classification: CORE (pure). The sealed **WebSocket wire codec**
//! (D1): RFC 6455 client handshake strings and frame encode/decode, as
//! pure functions over byte slices. No socket appears here — the shell
//! pumps bytes; this module only transforms them. Randomness (the client
//! masking key, the handshake nonce) is INJECTED as arguments: the shell
//! rolls the dice (B3), the core just uses the numbers.
//!
//! Policy notes, recorded:
//! - No fragmentation support (FIN must be set). Jetstream delivers each
//!   event as one text frame; a fragmented frame is a protocol error here
//!   and the shell answers it by reconnecting. (Scope v1.)
//! - Frames above `max_frame_len` are rejected rather than buffered — a
//!   16 MiB "event" is not an event.

const std = @import("std");
const assert = std.debug.assert;

/// RFC 6455 §1.3 — the fixed GUID concatenated to the client key.
const handshake_guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

pub const accept_len = 28; // base64 of a 20-byte SHA-1
pub const key_len = 24; // base64 of the 16-byte client nonce
pub const max_header_len = 14; // 2 + 8 (u64 length) + 4 (mask)
pub const max_frame_len = 16 * 1024 * 1024;

pub const Opcode = enum(u4) {
    continuation = 0x0,
    text = 0x1,
    binary = 0x2,
    close = 0x8,
    ping = 0x9,
    pong = 0xa,
    _,
};

/// One decoded frame. `payload` borrows the input buffer (unmasked in
/// place when the frame was masked).
/// A7.2: cold struct, size guard waived — one live at a time, transient.
pub const Frame = struct {
    opcode: Opcode,
    payload: []u8,
};

/// A decode that consumed bytes. `consumed` is how far the caller's
/// buffer cursor advances.
/// A7.2: cold struct, size guard waived — transient return value.
pub const Decoded = struct {
    frame: Frame,
    consumed: usize,
};

pub const DecodeError = error{
    ProtocolViolation, // reserved bits set, or a fragmented frame (FIN=0)
    FrameTooLong,
};

/// Base64 the 16-byte nonce into the Sec-WebSocket-Key form.
pub fn encodeKey(nonce: [16]u8, out: *[key_len]u8) []const u8 {
    return std.base64.standard.Encoder.encode(out, &nonce);
}

/// The Sec-WebSocket-Accept value the server must echo for `key`.
pub fn acceptKeyFor(key: []const u8, out: *[accept_len]u8) []const u8 {
    var sha = std.crypto.hash.Sha1.init(.{});
    sha.update(key);
    sha.update(handshake_guid);
    var digest: [20]u8 = undefined;
    sha.final(&digest);
    return std.base64.standard.Encoder.encode(out, &digest);
}

/// The client's opening handshake request.
pub fn buildHandshake(
    buf: []u8,
    host: []const u8,
    path: []const u8,
    key: []const u8,
) error{NoSpaceLeft}![]const u8 {
    return std.fmt.bufPrint(
        buf,
        "GET {s} HTTP/1.1\r\n" ++
            "Host: {s}\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: {s}\r\n" ++
            "Sec-WebSocket-Version: 13\r\n\r\n",
        .{ path, host, key },
    );
}

/// True once `response` holds a complete, valid 101 upgrade for `key`.
/// An incomplete head returns null; a complete-but-wrong head returns
/// false (E4: both are ordinary values).
pub fn handshakeAccepted(response: []const u8, key: []const u8) ?bool {
    if (std.mem.indexOf(u8, response, "\r\n\r\n") == null) return null;
    if (!std.mem.startsWith(u8, response, "HTTP/1.1 101")) return false;
    var accept_buf: [accept_len]u8 = undefined;
    const expected = acceptKeyFor(key, &accept_buf);
    return std.mem.indexOf(u8, response, expected) != null;
}

/// Decode one frame from the front of `bytes`. Returns null when more
/// bytes are needed (ordinary mid-stream state, E4). Masked payloads are
/// unmasked in place — both ends of a conversation use this one decoder.
pub fn decodeFrame(bytes: []u8) DecodeError!?Decoded {
    if (bytes.len < 2) return null;
    const b0 = bytes[0];
    const b1 = bytes[1];
    if (b0 & 0x70 != 0) return error.ProtocolViolation; // RSV bits
    if (b0 & 0x80 == 0) return error.ProtocolViolation; // fragmentation (policy)
    const opcode: Opcode = @enumFromInt(@as(u4, @truncate(b0)));
    const masked = b1 & 0x80 != 0;
    const len7: u7 = @truncate(b1);

    var header_len: usize = 2;
    var payload_len: u64 = len7;
    if (len7 == 126) {
        if (bytes.len < 4) return null;
        payload_len = std.mem.readInt(u16, bytes[2..4], .big);
        header_len = 4;
    } else if (len7 == 127) {
        if (bytes.len < 10) return null;
        payload_len = std.mem.readInt(u64, bytes[2..10], .big);
        header_len = 10;
    }
    if (payload_len > max_frame_len) return error.FrameTooLong;
    if (masked) header_len += 4;

    const total = header_len + payload_len;
    if (bytes.len < total) return null;

    const payload = bytes[header_len..@intCast(total)];
    if (masked) {
        const mask = bytes[header_len - 4 .. header_len];
        for (payload, 0..) |*b, i| b.* ^= mask[i % 4];
    }
    return .{
        .frame = .{ .opcode = opcode, .payload = payload },
        .consumed = @intCast(total),
    };
}

/// Encode one complete frame (FIN set). A client passes its 4-byte mask
/// (the shell's randomness); a server passes null.
pub fn encodeFrame(
    out: []u8,
    opcode: Opcode,
    payload: []const u8,
    mask: ?[4]u8,
) error{NoSpaceLeft}![]const u8 {
    var header: [max_header_len]u8 = undefined;
    header[0] = 0x80 | @as(u8, @intFromEnum(opcode));
    var header_len: usize = 2;
    if (payload.len < 126) {
        header[1] = @intCast(payload.len);
    } else if (payload.len <= std.math.maxInt(u16)) {
        header[1] = 126;
        std.mem.writeInt(u16, header[2..4], @intCast(payload.len), .big);
        header_len = 4;
    } else {
        header[1] = 127;
        std.mem.writeInt(u64, header[2..10], payload.len, .big);
        header_len = 10;
    }
    if (mask) |m| {
        header[1] |= 0x80;
        @memcpy(header[header_len..][0..4], &m);
        header_len += 4;
    }
    const total = header_len + payload.len;
    if (out.len < total) return error.NoSpaceLeft;
    @memcpy(out[0..header_len], header[0..header_len]);
    const dst = out[header_len..total];
    if (mask) |m| {
        for (payload, dst, 0..) |src, *d, i| d.* = src ^ m[i % 4];
    } else {
        @memcpy(dst, payload);
    }
    return out[0..total];
}

// ---------------------------------------------------------------------------
// Tests (B2, C6) — golden bytes straight from RFC 6455
// ---------------------------------------------------------------------------

const testing = std.testing;

test "handshake: the RFC 6455 accept-key vector" {
    var buf: [accept_len]u8 = undefined;
    try testing.expectEqualStrings(
        "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=",
        acceptKeyFor("dGhlIHNhbXBsZSBub25jZQ==", &buf),
    );
}

test "handshake: request contains the essentials; acceptance is checked" {
    var buf: [256]u8 = undefined;
    const req = try buildHandshake(&buf, "example.test", "/subscribe?x=1", "dGhlIHNhbXBsZSBub25jZQ==");
    try testing.expect(std.mem.indexOf(u8, req, "GET /subscribe?x=1 HTTP/1.1") != null);
    try testing.expect(std.mem.indexOf(u8, req, "Host: example.test") != null);
    try testing.expect(std.mem.indexOf(u8, req, "Upgrade: websocket") != null);

    try testing.expectEqual(@as(?bool, null), handshakeAccepted("HTTP/1.1 101 Sw", "k"));
    try testing.expectEqual(
        @as(?bool, true),
        handshakeAccepted(
            "HTTP/1.1 101 Switching Protocols\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\n",
            "dGhlIHNhbXBsZSBub25jZQ==",
        ),
    );
    try testing.expectEqual(
        @as(?bool, false),
        handshakeAccepted("HTTP/1.1 200 OK\r\n\r\n", "dGhlIHNhbXBsZSBub25jZQ=="),
    );
}

test "frames: RFC §5.7 golden bytes — unmasked and masked Hello" {
    // Unmasked "Hello": 81 05 48 65 6c 6c 6f
    var out: [32]u8 = undefined;
    const unmasked = try encodeFrame(&out, .text, "Hello", null);
    try testing.expectEqualSlices(u8, &.{ 0x81, 0x05, 0x48, 0x65, 0x6c, 0x6c, 0x6f }, unmasked);

    // Masked "Hello" with key 37 fa 21 3d: 81 85 37 fa 21 3d 7f 9f 4d 51 58
    var out2: [32]u8 = undefined;
    const masked = try encodeFrame(&out2, .text, "Hello", .{ 0x37, 0xfa, 0x21, 0x3d });
    try testing.expectEqualSlices(
        u8,
        &.{ 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 },
        masked,
    );

    // And the decoder round-trips both, unmasking in place.
    var copy: [11]u8 = undefined;
    @memcpy(&copy, masked);
    const decoded = (try decodeFrame(&copy)).?;
    try testing.expectEqual(Opcode.text, decoded.frame.opcode);
    try testing.expectEqualStrings("Hello", decoded.frame.payload);
    try testing.expectEqual(@as(usize, 11), decoded.consumed);
}

test "frames: 16-bit length, control frames, incompleteness as a value" {
    var payload: [300]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i);
    var out: [320]u8 = undefined;
    const encoded = try encodeFrame(&out, .binary, &payload, null);
    try testing.expectEqual(@as(u8, 126), encoded[1]);
    var mutable: [320]u8 = undefined;
    @memcpy(mutable[0..encoded.len], encoded);
    const decoded = (try decodeFrame(mutable[0..encoded.len])).?;
    try testing.expectEqual(@as(usize, 300), decoded.frame.payload.len);

    var ping = [_]u8{ 0x89, 0x00 };
    try testing.expectEqual(Opcode.ping, (try decodeFrame(&ping)).?.frame.opcode);

    // Every truncation point of the masked Hello frame is just "not yet".
    var golden = [_]u8{ 0x81, 0x85, 0x37, 0xfa, 0x21, 0x3d, 0x7f, 0x9f, 0x4d, 0x51, 0x58 };
    var cut: usize = 0;
    while (cut < golden.len) : (cut += 1) {
        try testing.expectEqual(@as(?Decoded, null), try decodeFrame(golden[0..cut]));
    }

    var fragmented = [_]u8{ 0x01, 0x00 }; // FIN clear
    try testing.expectError(error.ProtocolViolation, decodeFrame(&fragmented));
}
