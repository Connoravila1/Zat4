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

//! B1 classification: CORE (pure). The STUN/ICE protocol codec for Zat Chat
//! calling: STUN message framing (RFC 5389/8489), HMAC-SHA1 MESSAGE-INTEGRITY,
//! XOR-MAPPED-ADDRESS, and ICE candidate serialization + priority (RFC 8445).
//! This is the wire-format half of NAT traversal — pure, so it is fully
//! `zig build test`-provable against published known-answer vectors. The
//! impure half (the UDP socket, candidate gathering, connectivity-check
//! scheduling) is a later SHELL module (`shell/call_ice.zig`) that calls into
//! this codec.
//!
//! PURE (B2/B3/B4): no clock, no RNG, no I/O. Transaction ids and the socket
//! come from the shell; every function here is a byte/crypto transform.
//!
//! Crypto note: ICE connectivity checks require STUN MESSAGE-INTEGRITY, which
//! is HMAC-SHA1 (RFC 5389 §15.4). The fork's `std.crypto` ships SHA-1 but not
//! HMAC-SHA1, so it is built here from SHA-1 (HMAC is a trivial construction)
//! and pinned to the RFC 2202 test vectors. Same posture as the AES-GCM SRTP
//! profile: use the primitives the fork has, own the construction.

const std = @import("std");
const assert = std.debug.assert;
const Sha1 = std.crypto.hash.Sha1;

// ---------------------------------------------------------------------------
// HMAC-SHA1 (RFC 2104), built from the fork's SHA-1
// ---------------------------------------------------------------------------

pub const sha1_len = 20;
const hmac_block_len = 64;

/// HMAC-SHA1 of `msg` under `key` (RFC 2104). Pinned to RFC 2202 vectors below.
pub fn hmacSha1(key: []const u8, msg: []const u8, out: *[sha1_len]u8) void {
    var k0 = [_]u8{0} ** hmac_block_len;
    if (key.len > hmac_block_len) {
        Sha1.hash(key, k0[0..sha1_len], .{});
    } else {
        @memcpy(k0[0..key.len], key);
    }
    var ipad: [hmac_block_len]u8 = undefined;
    var opad: [hmac_block_len]u8 = undefined;
    for (0..hmac_block_len) |i| {
        ipad[i] = k0[i] ^ 0x36;
        opad[i] = k0[i] ^ 0x5c;
    }
    var inner = Sha1.init(.{});
    inner.update(&ipad);
    inner.update(msg);
    var ihash: [sha1_len]u8 = undefined;
    inner.final(&ihash);
    var outer = Sha1.init(.{});
    outer.update(&opad);
    outer.update(&ihash);
    outer.final(out);
}

// ---------------------------------------------------------------------------
// STUN message framing (RFC 5389)
// ---------------------------------------------------------------------------

pub const magic_cookie: u32 = 0x2112_A442;
pub const header_len = 20;
pub const txid_len = 12;

pub const Class = enum(u2) { request = 0, indication = 1, success = 2, err = 3 };
pub const method_binding: u12 = 0x001;

pub const attr_xor_mapped_address: u16 = 0x0020;
pub const attr_username: u16 = 0x0006;
pub const attr_message_integrity: u16 = 0x0008;

/// Encode the 14-bit STUN message type from method + class (RFC 5389 §6): the
/// method and class bits are interleaved around the two class bits.
pub fn encodeType(method: u12, class: Class) u16 {
    const m: u16 = method;
    const c: u16 = @intFromEnum(class);
    return ((m & 0x0f80) << 2) | ((m & 0x0070) << 1) | (m & 0x000f) |
        ((c & 0x2) << 7) | ((c & 0x1) << 4);
}

pub fn decodeClass(t: u16) Class {
    const c: u2 = @intCast(((t >> 4) & 0x1) | ((t >> 7) & 0x2));
    return @enumFromInt(c);
}

pub fn decodeMethod(t: u16) u12 {
    return @intCast((t & 0x000f) | ((t >> 1) & 0x0070) | ((t >> 2) & 0x0f80));
}

/// PLAIN DATA (A1). A parsed STUN header. A7.2: cold struct, size guard waived —
/// a transient parse result, never held in bulk.
pub const Header = struct {
    method: u12,
    class: Class,
    length: u16, // attribute bytes following the header
    txid: [txid_len]u8,
};

pub const Error = error{ Truncated, BadMagic, BadType };

/// Write a STUN header into `buf` with the given type/length/transaction id.
fn writeHeader(buf: []u8, msg_type: u16, length: u16, txid: [txid_len]u8) void {
    std.mem.writeInt(u16, buf[0..2], msg_type, .big);
    std.mem.writeInt(u16, buf[2..4], length, .big);
    std.mem.writeInt(u32, buf[4..8], magic_cookie, .big);
    @memcpy(buf[8..20], &txid);
}

/// Build a Binding request (no attributes) into `buf`, returning its length.
pub fn buildBindingRequest(txid: [txid_len]u8, buf: []u8) error{BufferTooSmall}!usize {
    if (buf.len < header_len) return error.BufferTooSmall;
    writeHeader(buf, encodeType(method_binding, .request), 0, txid);
    return header_len;
}

/// Parse a STUN header. Validates the magic cookie.
pub fn parseHeader(msg: []const u8) Error!Header {
    if (msg.len < header_len) return error.Truncated;
    if (std.mem.readInt(u32, msg[4..8], .big) != magic_cookie) return error.BadMagic;
    const t = std.mem.readInt(u16, msg[0..2], .big);
    const length = std.mem.readInt(u16, msg[2..4], .big);
    if (msg.len < header_len + length) return error.Truncated;
    var txid: [txid_len]u8 = undefined;
    @memcpy(&txid, msg[8..20]);
    return .{ .method = decodeMethod(t), .class = decodeClass(t), .length = length, .txid = txid };
}

/// Find an attribute's value slice by type, scanning the TLV list. Returns null
/// when absent (E4). Attributes are 4-byte-aligned (RFC 5389 §15).
pub fn findAttr(msg: []const u8, want: u16) ?[]const u8 {
    if (msg.len < header_len) return null;
    const length = std.mem.readInt(u16, msg[2..4], .big);
    var off: usize = header_len;
    const end = header_len + @as(usize, length);
    while (off + 4 <= end) {
        const atype = std.mem.readInt(u16, msg[off..][0..2], .big);
        const alen = std.mem.readInt(u16, msg[off + 2 ..][0..2], .big);
        const vstart = off + 4;
        if (vstart + alen > msg.len) return null;
        if (atype == want) return msg[vstart..][0..alen];
        off = vstart + ((@as(usize, alen) + 3) & ~@as(usize, 3)); // pad to 4
    }
    return null;
}

// ---------------------------------------------------------------------------
// XOR-MAPPED-ADDRESS (RFC 5389 §15.2)
// ---------------------------------------------------------------------------

pub const family_ipv4: u8 = 0x01;
pub const family_ipv6: u8 = 0x02;

/// PLAIN DATA (A1). A transport address. A7.2: cold struct, size guard waived —
/// a transient parse result. `addr` holds an IPv4 in its first 4 bytes.
pub const Address = struct {
    port: u16,
    is_ipv6: bool,
    addr: [16]u8,
};

/// Append an IPv4 XOR-MAPPED-ADDRESS attribute at `pos`, returning the new
/// length. `ip` is the address in host order; `port` the port.
pub fn appendXorMappedV4(buf: []u8, pos: usize, ip: u32, port: u16) error{BufferTooSmall}!usize {
    const total = pos + 4 + 8;
    if (buf.len < total) return error.BufferTooSmall;
    std.mem.writeInt(u16, buf[pos..][0..2], attr_xor_mapped_address, .big);
    std.mem.writeInt(u16, buf[pos + 2 ..][0..2], 8, .big);
    buf[pos + 4] = 0; // reserved
    buf[pos + 5] = family_ipv4;
    std.mem.writeInt(u16, buf[pos + 6 ..][0..2], port ^ @as(u16, @intCast(magic_cookie >> 16)), .big);
    std.mem.writeInt(u32, buf[pos + 8 ..][0..4], ip ^ magic_cookie, .big);
    return total;
}

/// Decode a XOR-MAPPED-ADDRESS value (the bytes after the attribute header).
/// `txid` is needed to un-XOR an IPv6 address.
pub fn parseXorMapped(value: []const u8, txid: [txid_len]u8) Error!Address {
    if (value.len < 8) return error.Truncated;
    const family = value[1];
    const x_port = std.mem.readInt(u16, value[2..4], .big);
    const port = x_port ^ @as(u16, @intCast(magic_cookie >> 16));
    var out: Address = .{ .port = port, .is_ipv6 = family == family_ipv6, .addr = [_]u8{0} ** 16 };
    if (family == family_ipv4) {
        const x_addr = std.mem.readInt(u32, value[4..8], .big);
        std.mem.writeInt(u32, out.addr[0..4], x_addr ^ magic_cookie, .big);
    } else if (family == family_ipv6) {
        if (value.len < 20) return error.Truncated;
        var mc: [4]u8 = undefined;
        std.mem.writeInt(u32, &mc, magic_cookie, .big);
        for (0..16) |i| {
            const key = if (i < 4) mc[i] else txid[i - 4];
            out.addr[i] = value[4 + i] ^ key;
        }
    } else return error.BadType;
    return out;
}

// ---------------------------------------------------------------------------
// MESSAGE-INTEGRITY (RFC 5389 §15.4) — HMAC-SHA1 over the message
// ---------------------------------------------------------------------------

/// Append a MESSAGE-INTEGRITY attribute (must be the last attribute). `msg_len`
/// is the current message length; returns the new length. The HMAC covers the
/// message with the header length field already set to include this attribute.
pub fn appendMessageIntegrity(buf: []u8, msg_len: usize, key: []const u8) error{BufferTooSmall}!usize {
    const total = msg_len + 4 + sha1_len;
    if (buf.len < total) return error.BufferTooSmall;
    // Header length must count everything through MESSAGE-INTEGRITY.
    std.mem.writeInt(u16, buf[2..4], @intCast(total - header_len), .big);
    var mac: [sha1_len]u8 = undefined;
    hmacSha1(key, buf[0..msg_len], &mac);
    std.mem.writeInt(u16, buf[msg_len..][0..2], attr_message_integrity, .big);
    std.mem.writeInt(u16, buf[msg_len + 2 ..][0..2], sha1_len, .big);
    @memcpy(buf[msg_len + 4 ..][0..sha1_len], &mac);
    return total;
}

/// Verify the MESSAGE-INTEGRITY of a received message (assumes it is the last
/// attribute, as we always emit it). Constant-time tag comparison.
pub fn verifyMessageIntegrity(msg: []const u8, key: []const u8) bool {
    if (msg.len < header_len + 4 + sha1_len) return false;
    const mi_off = msg.len - (4 + sha1_len);
    if (std.mem.readInt(u16, msg[mi_off..][0..2], .big) != attr_message_integrity) return false;
    var mac: [sha1_len]u8 = undefined;
    hmacSha1(key, msg[0..mi_off], &mac);
    return std.crypto.timing_safe.eql([sha1_len]u8, mac, msg[mi_off + 4 ..][0..sha1_len].*);
}

// ---------------------------------------------------------------------------
// ICE candidates (RFC 8445 §5.1)
// ---------------------------------------------------------------------------

pub const CandidateType = enum { host, srflx, prflx, relay };

/// PLAIN DATA (A1). One ICE candidate. A7.2: cold struct, size guard waived —
/// borrows `foundation`/`ip` from the parsed string; a transient value.
pub const Candidate = struct {
    foundation: []const u8,
    component: u8,
    priority: u32,
    ip: []const u8,
    port: u16,
    typ: CandidateType,
};

/// The RFC 8445 §5.1.2.1 type preferences (higher = preferred).
pub fn typePreference(t: CandidateType) u8 {
    return switch (t) {
        .host => 126,
        .prflx => 110,
        .srflx => 100,
        .relay => 0,
    };
}

/// Candidate priority (RFC 8445 §5.1.2.1):
/// `2^24 * type_pref + 2^8 * local_pref + (256 - component)`.
pub fn computePriority(type_pref: u8, local_pref: u16, component: u8) u32 {
    return (@as(u32, type_pref) << 24) + (@as(u32, local_pref) << 8) + (256 - @as(u32, component));
}

fn typeName(t: CandidateType) []const u8 {
    return switch (t) {
        .host => "host",
        .srflx => "srflx",
        .prflx => "prflx",
        .relay => "relay",
    };
}

/// Serialize a candidate to its SDP a=candidate line body (without the
/// "a=candidate:" prefix — just the value), returning the written slice.
pub fn serializeCandidate(c: Candidate, buf: []u8) error{BufferTooSmall}![]const u8 {
    return std.fmt.bufPrint(buf, "candidate:{s} {d} UDP {d} {s} {d} typ {s}", .{
        c.foundation, c.component, c.priority, c.ip, c.port, typeName(c.typ),
    }) catch error.BufferTooSmall;
}

pub const CandidateParseError = error{ Malformed, UnknownType };

/// Parse a "candidate:..." line body into a `Candidate` borrowing from `s`.
pub fn parseCandidate(s: []const u8) CandidateParseError!Candidate {
    const body = if (std.mem.startsWith(u8, s, "candidate:")) s["candidate:".len..] else s;
    var it = std.mem.tokenizeScalar(u8, body, ' ');
    const foundation = it.next() orelse return error.Malformed;
    const component = std.fmt.parseInt(u8, it.next() orelse return error.Malformed, 10) catch return error.Malformed;
    _ = it.next() orelse return error.Malformed; // transport ("UDP")
    const priority = std.fmt.parseInt(u32, it.next() orelse return error.Malformed, 10) catch return error.Malformed;
    const ip = it.next() orelse return error.Malformed;
    const port = std.fmt.parseInt(u16, it.next() orelse return error.Malformed, 10) catch return error.Malformed;
    const typ_kw = it.next() orelse return error.Malformed; // "typ"
    if (!std.mem.eql(u8, typ_kw, "typ")) return error.Malformed;
    const typ_s = it.next() orelse return error.Malformed;
    const typ: CandidateType =
        if (std.mem.eql(u8, typ_s, "host")) .host else if (std.mem.eql(u8, typ_s, "srflx")) .srflx else if (std.mem.eql(u8, typ_s, "prflx")) .prflx else if (std.mem.eql(u8, typ_s, "relay")) .relay else return error.UnknownType;
    return .{ .foundation = foundation, .component = component, .priority = priority, .ip = ip, .port = port, .typ = typ };
}

// ---------------------------------------------------------------------------
// Tests (B2/C6 — pure, deterministic; published known-answer vectors)
// ---------------------------------------------------------------------------

const testing = std.testing;

fn hex(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "HMAC-SHA1 matches the RFC 2202 test-case-1 vector" {
    const key = [_]u8{0x0b} ** 20;
    var out: [sha1_len]u8 = undefined;
    hmacSha1(&key, "Hi There", &out);
    try testing.expectEqualSlices(u8, &hex("b617318655057264e28bc0b6fb378c8ef146be00"), &out);
}

test "STUN Binding request header is well-formed" {
    const txid = hex("0123456789abcdef01234567");
    var buf: [64]u8 = undefined;
    const n = try buildBindingRequest(txid, &buf);
    try testing.expectEqual(@as(usize, header_len), n);
    try testing.expectEqual(@as(u16, 0x0001), std.mem.readInt(u16, buf[0..2], .big)); // type
    try testing.expectEqual(@as(u16, 0x0000), std.mem.readInt(u16, buf[2..4], .big)); // length
    try testing.expectEqual(magic_cookie, std.mem.readInt(u32, buf[4..8], .big));
    const h = try parseHeader(buf[0..n]);
    try testing.expectEqual(method_binding, h.method);
    try testing.expectEqual(Class.request, h.class);
}

test "message type encode/decode round-trips (Binding success = 0x0101)" {
    try testing.expectEqual(@as(u16, 0x0101), encodeType(method_binding, .success));
    const t = encodeType(method_binding, .success);
    try testing.expectEqual(method_binding, decodeMethod(t));
    try testing.expectEqual(Class.success, decodeClass(t));
}

test "XOR-MAPPED-ADDRESS matches the RFC 5769 IPv4 sample encoding" {
    // RFC 5769 §2.2: 192.0.2.1:32853 → X-Port 0xA147, X-Address 0xE112A643.
    var buf: [64]u8 = undefined;
    const n = try appendXorMappedV4(&buf, header_len, 0xC000_0201, 32853);
    // value starts at header_len + 4 (after the attr TLV header)
    try testing.expectEqual(@as(u16, 0xA147), std.mem.readInt(u16, buf[header_len + 4 + 2 ..][0..2], .big));
    try testing.expectEqual(@as(u32, 0xE112_A643), std.mem.readInt(u32, buf[header_len + 4 + 4 ..][0..4], .big));
    _ = n;
}

test "XOR-MAPPED-ADDRESS round-trips through a full message" {
    const txid = hex("0123456789abcdef01234567");
    var buf: [64]u8 = undefined;
    writeHeader(&buf, encodeType(method_binding, .success), 0, txid);
    const n = try appendXorMappedV4(&buf, header_len, 0xC000_0201, 32853);
    std.mem.writeInt(u16, buf[2..4], @intCast(n - header_len), .big); // set message length
    const val = findAttr(buf[0..n], attr_xor_mapped_address).?;
    const addr = try parseXorMapped(val, txid);
    try testing.expectEqual(@as(u16, 32853), addr.port);
    try testing.expect(!addr.is_ipv6);
    try testing.expectEqual(@as(u32, 0xC000_0201), std.mem.readInt(u32, addr.addr[0..4], .big));
}

test "MESSAGE-INTEGRITY appends and verifies, and a tamper is caught" {
    const txid = hex("0123456789abcdef01234567");
    const key = "short-term-credential";
    var buf: [128]u8 = undefined;
    var n = try buildBindingRequest(txid, &buf);
    n = try appendMessageIntegrity(&buf, n, key);
    try testing.expect(verifyMessageIntegrity(buf[0..n], key));
    // Flip a byte in the header → integrity fails.
    buf[9] ^= 0x01;
    try testing.expect(!verifyMessageIntegrity(buf[0..n], key));
    // Wrong key → fails.
    buf[9] ^= 0x01; // restore
    try testing.expect(!verifyMessageIntegrity(buf[0..n], "different-key"));
}

test "ICE candidate serialize/parse round-trips and priority matches RFC 8445" {
    const prio = computePriority(typePreference(.host), 65535, 1);
    try testing.expectEqual(@as(u32, 0x7EFF_FFFF), prio); // host, max local pref, component 1
    const c: Candidate = .{ .foundation = "1", .component = 1, .priority = prio, .ip = "192.168.1.10", .port = 54321, .typ = .host };
    var buf: [128]u8 = undefined;
    const line = try serializeCandidate(c, &buf);
    const got = try parseCandidate(line);
    try testing.expectEqualSlices(u8, c.foundation, got.foundation);
    try testing.expectEqual(c.component, got.component);
    try testing.expectEqual(c.priority, got.priority);
    try testing.expectEqualSlices(u8, c.ip, got.ip);
    try testing.expectEqual(c.port, got.port);
    try testing.expectEqual(c.typ, got.typ);
}

test "parseCandidate rejects malformed input (E3)" {
    try testing.expectError(error.Malformed, parseCandidate("candidate:1 1 UDP"));
    try testing.expectError(error.UnknownType, parseCandidate("candidate:1 1 UDP 100 10.0.0.1 5000 typ bogus"));
}
