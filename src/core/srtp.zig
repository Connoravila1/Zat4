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

//! B1 classification: CORE (pure). SRTP media protection — the AES-GCM AEAD
//! profile (RFC 7714, AES-256-GCM), keyed per-call/per-direction from the MLS
//! exporter (`media_keys.zig`). This is the settled media-security decision
//! (ZAT_CHAT_CALLING_ROADMAP.md §3 #10): there is NO DTLS handshake — MLS
//! already authenticates identity and derives the keys, so DTLS is redundant,
//! and the fork's `std.crypto` provides AES-GCM but not the classic
//! AES-CM/HMAC-SHA1 profile.
//!
//! PURE (B2/B3/B4): no clock, no RNG, no I/O. `protect`/`unprotect` are pure
//! transforms over bytes + key material + the packet index (ROC‖SEQ) the caller
//! supplies. Replay policy (`ReplayWindow`) and rollover-counter estimation
//! (`estimateRoc`) are pure helpers the shell composes; keeping them separate
//! lets `unprotect` stay a pure crypto primitive. The whole path is
//! unit-testable headlessly: round-trip, tamper detection, and replay rejection
//! (see the tests at the foot).
//!
//! Layout (RFC 7714 §3): the RTP header travels in the clear and is
//! AUTHENTICATED as AAD; the payload is encrypted; the 16-byte GCM tag is
//! appended. SRTP packet = [RTP header][encrypted payload][auth tag].

const std = @import("std");
const assert = std.debug.assert;
const rtp = @import("rtp.zig");
const media_keys = @import("media_keys.zig");

const Aead = std.crypto.aead.aes_gcm.Aes256Gcm;
const key_len = Aead.key_length; // 32
const nonce_len = Aead.nonce_length; // 12
const tag_len = Aead.tag_length; // 16

comptime {
    // The profile assumes AES-256-GCM keyed by media_keys' 32-byte key + 12-byte
    // salt. Pin the shapes so a mismatch fails the build, not a call.
    assert(key_len == media_keys.key_len);
    assert(nonce_len == media_keys.salt_len);
}

pub const SrtpError = error{
    BufferTooSmall,
    Truncated,
    BadVersion,
    AuthenticationFailed,
};

/// The 48-bit SRTP packet index (RFC 3711 §3.3.1): `(ROC << 16) | SEQ`.
pub fn packetIndex(roc: u32, seq: u16) u64 {
    return (@as(u64, roc) << 16) | @as(u64, seq);
}

/// Build the 12-byte GCM nonce (RFC 7714 §8.1): the salt XORed with
/// `0x0000 ‖ SSRC ‖ ROC ‖ SEQ`.
fn makeNonce(salt: [nonce_len]u8, ssrc: u32, roc: u32, seq: u16) [nonce_len]u8 {
    var iv: [nonce_len]u8 = undefined;
    iv[0] = 0;
    iv[1] = 0;
    std.mem.writeInt(u32, iv[2..][0..4], ssrc, .big);
    std.mem.writeInt(u32, iv[6..][0..4], roc, .big);
    std.mem.writeInt(u16, iv[10..][0..2], seq, .big);
    var nonce: [nonce_len]u8 = undefined;
    for (0..nonce_len) |i| nonce[i] = iv[i] ^ salt[i];
    return nonce;
}

/// Encrypt a serialized RTP `packet` into `out`, returning the SRTP length.
/// The header is authenticated (AAD) and copied in the clear; the payload is
/// encrypted; the GCM tag is appended. `roc` is the sender's rollover counter
/// for this packet (bump it with `senderRoc` when SEQ wraps).
pub fn protect(packet: []const u8, keys: media_keys.MediaKeys, roc: u32, out: []u8) SrtpError!usize {
    const parsed = rtp.parse(packet) catch |e| return switch (e) {
        error.Truncated => error.Truncated,
        error.BadVersion => error.BadVersion,
        error.BadPayloadType => error.Truncated, // malformed header for our purposes
    };
    const header_len = packet.len - parsed.payload.len;
    const total = header_len + parsed.payload.len + tag_len;
    if (out.len < total) return error.BufferTooSmall;

    @memcpy(out[0..header_len], packet[0..header_len]); // header travels in the clear
    const nonce = makeNonce(keys.salt, parsed.header.ssrc, roc, parsed.header.sequence);
    Aead.encrypt(
        out[header_len..][0..parsed.payload.len], // ciphertext
        out[header_len + parsed.payload.len ..][0..tag_len], // tag
        parsed.payload, // plaintext
        packet[0..header_len], // AAD = RTP header
        nonce,
        keys.key,
    );
    return total;
}

/// Decrypt an SRTP `packet` into `out`, returning the recovered RTP length.
/// `roc` must be the rollover counter the sender used for this packet (recover
/// it with `estimateRoc`). Fails with `AuthenticationFailed` on any tampering,
/// wrong key, or wrong index — the honest E2EE guarantee.
pub fn unprotect(packet: []const u8, keys: media_keys.MediaKeys, roc: u32, out: []u8) SrtpError!usize {
    const parsed = rtp.parse(packet) catch |e| return switch (e) {
        error.Truncated => error.Truncated,
        error.BadVersion => error.BadVersion,
        error.BadPayloadType => error.Truncated,
    };
    const trailer = parsed.payload; // ciphertext ‖ tag
    if (trailer.len < tag_len) return error.Truncated;
    const header_len = packet.len - trailer.len;
    const ct_len = trailer.len - tag_len;
    const rtp_len = header_len + ct_len;
    if (out.len < rtp_len) return error.BufferTooSmall;

    @memcpy(out[0..header_len], packet[0..header_len]);
    const nonce = makeNonce(keys.salt, parsed.header.ssrc, roc, parsed.header.sequence);
    Aead.decrypt(
        out[header_len..][0..ct_len], // plaintext out
        trailer[0..ct_len], // ciphertext in
        trailer[ct_len..][0..tag_len].*, // tag by value
        packet[0..header_len], // AAD = RTP header
        nonce,
        keys.key,
    ) catch return error.AuthenticationFailed;
    return rtp_len;
}

// ---------------------------------------------------------------------------
// Rollover-counter estimation and replay protection (pure helpers, RFC 3711)
// ---------------------------------------------------------------------------

/// A sender's rollover counter update: bump ROC when SEQ wraps 0xFFFF → 0x0000.
pub fn senderRoc(roc: u32, prev_seq: u16, new_seq: u16) u32 {
    return if (new_seq < prev_seq and prev_seq -% new_seq > 0x8000) roc +% 1 else roc;
}

/// A receiver's ROC estimate for `seq` given the highest sequence seen so far
/// (RFC 3711 §3.3.1 index-guessing). Recovers the correct ROC for reordered and
/// wrapped packets without transmitting it. Uses widened arithmetic so the
/// guard comparisons match the RFC exactly (`SEQ - s_l > 2^15` in the low half,
/// `s_l - 2^15 > SEQ` in the high half) rather than wrapping subtraction.
pub fn estimateRoc(roc: u32, highest_seq: u16, seq: u16) u32 {
    const s_l: i32 = highest_seq;
    const s: i32 = seq;
    if (s_l < 0x8000) {
        return if (s - s_l > 0x8000) roc -% 1 else roc;
    } else {
        return if (s_l - 0x8000 > s) roc +% 1 else roc;
    }
}

/// PLAIN DATA (A1). A 64-packet sliding replay window over the 48-bit index
/// (RFC 3711 §3.3.2). Bit `i` set ⇒ index `(highest - i)` has been accepted.
/// One per receiving stream — guarded under the tie-break rule.
pub const ReplayWindow = struct {
    highest: u64 = 0, // highest index accepted so far
    bitmap: u64 = 0, // received-mask relative to `highest`
    initialized: bool = false,
    _pad: [7]u8 = [_]u8{0} ** 7, // A6: explicit pad to the u64 alignment boundary

    comptime {
        // Budget: u64+u64 = 16, then bool+pad[7] = 8. 24 exact, align 8.
        assert(@sizeOf(ReplayWindow) == 24);
    }
};

pub const window_size = 64;

/// Test-and-set an index against the replay window. Returns true and records
/// the index if it is fresh; false if it is a replay or too old to judge.
/// Call this only AFTER `unprotect` authenticates the packet (RFC 3711 order:
/// the window advances on authenticated packets, never on forged ones).
pub fn accept(w: *ReplayWindow, index: u64) bool {
    if (!w.initialized) {
        w.initialized = true;
        w.highest = index;
        w.bitmap = 1;
        return true;
    }
    if (index > w.highest) {
        const shift = index - w.highest;
        w.bitmap = if (shift >= window_size) 0 else w.bitmap << @intCast(shift);
        w.bitmap |= 1; // the new highest occupies bit 0
        w.highest = index;
        return true;
    }
    const diff = w.highest - index;
    if (diff >= window_size) return false; // too old to judge
    const mask = @as(u64, 1) << @intCast(diff);
    if (w.bitmap & mask != 0) return false; // already seen — replay
    w.bitmap |= mask;
    return true;
}

// ---------------------------------------------------------------------------
// Tests (B2/C6 — deterministic; no allocator needed)
// ---------------------------------------------------------------------------

const testing = std.testing;

fn sampleKeys() media_keys.MediaKeys {
    var k: media_keys.MediaKeys = undefined;
    for (&k.key, 0..) |*b, i| b.* = @intCast((i * 3 + 1) & 0xff);
    for (&k.salt, 0..) |*b, i| b.* = @intCast((i * 5 + 2) & 0xff);
    return k;
}

fn buildRtp(seq: u16, payload: []const u8, buf: []u8) usize {
    return rtp.serialize(.{ .timestamp = 1000, .ssrc = 0x0A0B0C0D, .sequence = seq, .payload_type = rtp.opus_payload_type, .marker = false }, payload, buf) catch unreachable;
}

test "protect → unprotect round-trips and recovers the exact RTP packet" {
    const keys = sampleKeys();
    var rtp_buf: [256]u8 = undefined;
    const rtp_len = buildRtp(7, "the-quick-brown-opus", &rtp_buf);

    var srtp_buf: [512]u8 = undefined;
    const srtp_len = try protect(rtp_buf[0..rtp_len], keys, 0, &srtp_buf);
    try testing.expectEqual(rtp_len + tag_len, srtp_len);
    // The header is in the clear; the payload is not.
    try testing.expectEqualSlices(u8, rtp_buf[0..rtp.fixed_header_len], srtp_buf[0..rtp.fixed_header_len]);
    try testing.expect(!std.mem.eql(u8, rtp_buf[rtp.fixed_header_len..rtp_len], srtp_buf[rtp.fixed_header_len..rtp_len]));

    var back: [256]u8 = undefined;
    const back_len = try unprotect(srtp_buf[0..srtp_len], keys, 0, &back);
    try testing.expectEqual(rtp_len, back_len);
    try testing.expectEqualSlices(u8, rtp_buf[0..rtp_len], back[0..back_len]);
}

test "a single flipped byte fails authentication (tamper detection)" {
    const keys = sampleKeys();
    var rtp_buf: [128]u8 = undefined;
    const rtp_len = buildRtp(1, "sensitive", &rtp_buf);
    var srtp_buf: [256]u8 = undefined;
    const srtp_len = try protect(rtp_buf[0..rtp_len], keys, 0, &srtp_buf);

    srtp_buf[rtp.fixed_header_len + 1] ^= 0x01; // flip a ciphertext bit
    var back: [128]u8 = undefined;
    try testing.expectError(error.AuthenticationFailed, unprotect(srtp_buf[0..srtp_len], keys, 0, &back));
}

test "the wrong key fails authentication" {
    const keys = sampleKeys();
    var other = sampleKeys();
    other.key[0] ^= 0xFF;
    var rtp_buf: [128]u8 = undefined;
    const rtp_len = buildRtp(1, "hello", &rtp_buf);
    var srtp_buf: [256]u8 = undefined;
    const srtp_len = try protect(rtp_buf[0..rtp_len], keys, 0, &srtp_buf);
    var back: [128]u8 = undefined;
    try testing.expectError(error.AuthenticationFailed, unprotect(srtp_buf[0..srtp_len], other, 0, &back));
}

test "authenticating with the wrong ROC fails (index is bound into the nonce)" {
    const keys = sampleKeys();
    var rtp_buf: [128]u8 = undefined;
    const rtp_len = buildRtp(3, "abc", &rtp_buf);
    var srtp_buf: [256]u8 = undefined;
    const srtp_len = try protect(rtp_buf[0..rtp_len], keys, 5, &srtp_buf);
    var back: [128]u8 = undefined;
    try testing.expectError(error.AuthenticationFailed, unprotect(srtp_buf[0..srtp_len], keys, 6, &back));
    const ok = try unprotect(srtp_buf[0..srtp_len], keys, 5, &back);
    try testing.expectEqual(rtp_len, ok);
}

test "replay window accepts fresh indexes and rejects replays and stale ones" {
    var w: ReplayWindow = .{};
    try testing.expect(accept(&w, 100));
    try testing.expect(accept(&w, 101));
    try testing.expect(accept(&w, 105)); // jump forward
    try testing.expect(accept(&w, 103)); // fill an in-window gap
    try testing.expect(!accept(&w, 105)); // replay of a seen index
    try testing.expect(!accept(&w, 103)); // replay
    try testing.expect(accept(&w, 200)); // big jump forward
    try testing.expect(!accept(&w, 100)); // now far too old to judge
}

test "ROC estimation and sender rollover handle SEQ wraparound" {
    // Sender: wrapping from 0xFFFF to 0x0000 bumps the ROC.
    try testing.expectEqual(@as(u32, 1), senderRoc(0, 0xFFFF, 0x0000));
    try testing.expectEqual(@as(u32, 0), senderRoc(0, 10, 11));
    // Receiver: a low SEQ seen while the highest is near the top means we wrapped.
    try testing.expectEqual(@as(u32, 6), estimateRoc(5, 0xFFF0, 0x0002));
    // A high SEQ seen while the highest is low is a straggler from the prior ROC.
    try testing.expectEqual(@as(u32, 4), estimateRoc(5, 0x0002, 0xFFF0));
    // No wrap in the normal case.
    try testing.expectEqual(@as(u32, 5), estimateRoc(5, 100, 105));
}

test "a full receive path composes estimate → unprotect → accept across a SEQ wrap" {
    const keys = sampleKeys();
    var w: ReplayWindow = .{};
    // The receiver's baseline is established from the first packet (a real
    // receiver seeds highest_seq/roc from packet #1, not from zero).
    var recv_roc: u32 = 0;
    var highest_seq: u16 = 65533;
    // Sender state, tracked independently.
    var send_roc: u32 = 0;
    var prev_send_seq: u16 = 65533;

    for ([_]u16{ 65534, 65535, 0, 1 }) |seq| {
        send_roc = senderRoc(send_roc, prev_send_seq, seq);
        prev_send_seq = seq;

        var rtp_buf: [64]u8 = undefined;
        const rtp_len = buildRtp(seq, "f", &rtp_buf);
        var srtp_buf: [128]u8 = undefined;
        const srtp_len = try protect(rtp_buf[0..rtp_len], keys, send_roc, &srtp_buf);

        const est = estimateRoc(recv_roc, highest_seq, seq);
        var back: [64]u8 = undefined;
        _ = try unprotect(srtp_buf[0..srtp_len], keys, est, &back);
        try testing.expect(accept(&w, packetIndex(est, seq)));

        recv_roc = est;
        highest_seq = seq;
    }
    try testing.expectEqual(@as(u32, 1), send_roc); // the wrap advanced the ROC
    try testing.expectEqual(@as(u32, 1), recv_roc); // and the receiver recovered it
}
