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

//! B1 classification: CORE (pure). SSRF address classification — the decision
//! of which destinations Zat4 must never fetch.
//!
//! The atproto spec names SSRF as a REQUIRED protection (SECURITY_ROADMAP
//! Phase 1): Zat4 resolves DIDs and handles, which means it fetches URLs that
//! *other people control* (a handle's `.well-known`, a `did:web` document, a
//! DID document's `serviceEndpoint`). An attacker can craft one whose host
//! points at `127.0.0.1`, `169.254.169.254` (cloud metadata), or an internal
//! `10.x` address to make the client attack its own machine or network.
//!
//! This module is the security-critical *decision*: given an IP address (an
//! IP-literal host, or the bytes a resolver returns for a name), is it in a
//! private / loopback / link-local / reserved range we must refuse? Getting
//! these ranges exactly right — including IPv4-mapped IPv6 and other embedded
//! forms — is where real SSRF bypasses live, so it is pure and exhaustively
//! tested here. The shell (`shell/http.zig`) does the impure parts — resolve
//! the name, then refuse the connection when this module says block — and an
//! operator-configured endpoint (the loopback AppView tunnel) is a *trusted*
//! caller that does not pass through this gate.

const std = @import("std");

pub const Ipv4 = [4]u8;
pub const Ipv6 = [16]u8;

/// Is this IPv4 address one we must never fetch from? Covers loopback, the
/// RFC 1918 private ranges, link-local, carrier-grade NAT, the unspecified
/// block, multicast/reserved, broadcast, and the documentation/benchmark
/// ranges that should never be a real fetch target.
pub fn isBlockedIpv4(a: Ipv4) bool {
    return switch (a[0]) {
        0 => true, // 0.0.0.0/8 "this host"
        10 => true, // 10.0.0.0/8 private
        127 => true, // 127.0.0.0/8 loopback
        100 => (a[1] & 0xc0) == 0x40, // 100.64.0.0/10 CGNAT
        169 => a[1] == 254, // 169.254.0.0/16 link-local (incl. cloud metadata)
        172 => (a[1] & 0xf0) == 0x10, // 172.16.0.0/12 private
        192 => (a[1] == 168) // 192.168.0.0/16 private
        or (a[1] == 0 and a[2] == 0) // 192.0.0.0/24 IETF protocol
        or (a[1] == 0 and a[2] == 2) // 192.0.2.0/24 TEST-NET-1
        or (a[1] == 88 and a[2] == 99), // 192.88.99.0/24 6to4 relay anycast
        198 => (a[1] & 0xfe) == 18 // 198.18.0.0/15 benchmarking
        or (a[1] == 51 and a[2] == 100), // 198.51.100.0/24 TEST-NET-2
        203 => a[1] == 0 and a[2] == 113, // 203.0.113.0/24 TEST-NET-3
        224...255 => true, // 224.0.0.0/4 multicast + 240.0.0.0/4 reserved + .255 broadcast
        else => false,
    };
}

/// Is this IPv6 address one we must never fetch from? Handles the native IPv6
/// special ranges AND the forms that embed an IPv4 address (mapped, compat,
/// NAT64), classifying the embedded v4 so an internal target can't hide inside
/// an IPv6 literal.
pub fn isBlockedIpv6(a: Ipv6) bool {
    // Embedded-IPv4 forms: classify the trailing 32 bits as IPv4.
    if (isIpv4Mapped(a) or isIpv4Compat(a) or isNat64(a)) {
        return isBlockedIpv4(a[12..16].*);
    }
    if (std.mem.eql(u8, &a, &([_]u8{0} ** 16))) return true; // :: unspecified
    if (isLoopbackV6(a)) return true; // ::1
    if ((a[0] & 0xfe) == 0xfc) return true; // fc00::/7 unique-local
    if (a[0] == 0xfe and (a[1] & 0xc0) == 0x80) return true; // fe80::/10 link-local
    if (a[0] == 0xff) return true; // ff00::/8 multicast
    if (a[0] == 0x01 and a[1] == 0x00 and allZero(a[2..8])) return true; // 100::/64 discard
    if (a[0] == 0x20 and a[1] == 0x01 and a[2] == 0x0d and a[3] == 0xb8) return true; // 2001:db8::/32 docs
    return false;
}

fn isLoopbackV6(a: Ipv6) bool {
    return allZero(a[0..15]) and a[15] == 1;
}

fn isIpv4Mapped(a: Ipv6) bool {
    return allZero(a[0..10]) and a[10] == 0xff and a[11] == 0xff;
}

fn isIpv4Compat(a: Ipv6) bool {
    // ::a.b.c.d, excluding :: and ::1 (handled separately).
    return allZero(a[0..12]) and !(a[12] == 0 and a[13] == 0 and a[14] == 0 and a[15] <= 1);
}

fn isNat64(a: Ipv6) bool {
    // 64:ff9b::/96 well-known NAT64 prefix.
    return a[0] == 0x00 and a[1] == 0x64 and a[2] == 0xff and a[3] == 0x9b and allZero(a[4..12]);
}

fn allZero(s: []const u8) bool {
    for (s) |b| if (b != 0) return false;
    return true;
}

/// The verdict for a URL host (no port): if it is an IP literal, classify it;
/// if it is a name, return null — the shell must resolve it and classify each
/// returned address. A name that LOOKS like a malformed IP is treated as a
/// name (the resolver decides).
pub fn ipLiteralVerdict(host: []const u8) ?bool {
    if (parseIpv4(host)) |v4| return isBlockedIpv4(v4);
    if (parseIpv6Host(host)) |v6| return isBlockedIpv6(v6);
    return null;
}

/// Only `https://` is acceptable for an external (untrusted) fetch — `http://`,
/// `file://`, `gopher://`, etc. are rejected outright (Phase 1).
pub fn isAllowedScheme(url: []const u8) bool {
    return std.ascii.startsWithIgnoreCase(url, "https://");
}

/// Extract the host from a URL: no scheme, no userinfo, no port, no path. An
/// IPv6 literal's brackets are stripped (`[::1]:443` → `::1`). Returns null for
/// a URL with no authority component.
pub fn hostOf(url: []const u8) ?[]const u8 {
    const sep = std.mem.indexOf(u8, url, "://") orelse return null;
    var rest = url[sep + 3 ..];
    // authority ends at the first '/', '?' or '#'.
    const end = std.mem.indexOfAny(u8, rest, "/?#") orelse rest.len;
    rest = rest[0..end];
    // strip userinfo
    if (std.mem.lastIndexOfScalar(u8, rest, '@')) |at| rest = rest[at + 1 ..];
    if (rest.len == 0) return null;
    if (rest[0] == '[') { // IPv6 literal: [host]:port
        const close = std.mem.indexOfScalar(u8, rest, ']') orelse return null;
        return rest[1..close];
    }
    // strip :port (a name/IPv4 host has at most one colon)
    if (std.mem.indexOfScalar(u8, rest, ':')) |c| rest = rest[0..c];
    if (rest.len == 0) return null;
    return rest;
}

/// Parse a strict dotted-decimal IPv4 literal. Rejects leading-zero octets so a
/// would-be-octal form (`0177.0.0.1`) is never silently read as decimal here
/// and then mis-resolved as octal by the OS.
pub fn parseIpv4(s: []const u8) ?Ipv4 {
    var out: Ipv4 = undefined;
    var it = std.mem.splitScalar(u8, s, '.');
    var i: usize = 0;
    while (it.next()) |part| : (i += 1) {
        if (i >= 4) return null;
        if (part.len == 0 or part.len > 3) return null;
        if (part.len > 1 and part[0] == '0') return null; // no leading zeros
        var v: u16 = 0;
        for (part) |c| {
            if (c < '0' or c > '9') return null;
            v = v * 10 + (c - '0');
        }
        if (v > 255) return null;
        out[i] = @intCast(v);
    }
    return if (i == 4) out else null;
}

/// Parse an IPv6 literal host (no brackets), including `::` compression and an
/// optional trailing embedded IPv4 (`::ffff:1.2.3.4`).
pub fn parseIpv6Host(s: []const u8) ?Ipv6 {
    if (s.len == 0) return null;
    var out: Ipv6 = [_]u8{0} ** 16;

    // Split on "::" at most once into a head and tail of hextet groups.
    var head: []const u8 = s;
    var tail: ?[]const u8 = null;
    if (std.mem.indexOf(u8, s, "::")) |dc| {
        head = s[0..dc];
        tail = s[dc + 2 ..];
        if (std.mem.indexOf(u8, tail.?, "::") != null) return null; // only one "::"
    } else if (std.mem.indexOfScalar(u8, s, ':') == null) {
        return null; // not an IPv6 literal at all
    }

    var groups: [8]u16 = undefined;
    var head_n: usize = 0;
    var tail_n: usize = 0;
    var embedded_v4: ?Ipv4 = null;

    // head groups
    if (head.len > 0) {
        head_n = parseGroups(head, groups[0..], &embedded_v4) orelse return null;
    }
    var tail_groups: [8]u16 = undefined;
    if (tail) |t| {
        if (t.len > 0) tail_n = parseGroups(t, tail_groups[0..], &embedded_v4) orelse return null;
    } else if (embedded_v4 == null and head_n != 8) {
        return null; // no "::" and not a full 8 groups
    }

    const v4_groups: usize = if (embedded_v4 != null) 2 else 0;
    const total = head_n + tail_n + v4_groups;
    if (total > 8) return null;
    if (tail == null and total != 8) return null;

    var idx: usize = 0;
    for (0..head_n) |g| {
        writeGroup(&out, idx, groups[g]);
        idx += 1;
    }
    // the gap that "::" fills is zeros (already zeroed); skip to the tail slot
    idx = 8 - tail_n - v4_groups;
    for (0..tail_n) |g| {
        writeGroup(&out, idx, tail_groups[g]);
        idx += 1;
    }
    if (embedded_v4) |v4| @memcpy(out[12..16], &v4);
    return out;
}

/// Parse colon-separated hextets; if the final field is dotted IPv4, capture it
/// via `embedded` and stop. Returns the count of 16-bit groups parsed (not
/// counting the embedded v4).
fn parseGroups(s: []const u8, out: []u16, embedded: *?Ipv4) ?usize {
    var it = std.mem.splitScalar(u8, s, ':');
    var n: usize = 0;
    while (it.next()) |field| {
        if (field.len == 0) return null; // empty field (stray colon)
        if (std.mem.indexOfScalar(u8, field, '.') != null) {
            // trailing embedded IPv4 — must be the last field
            if (it.next() != null) return null;
            embedded.* = parseIpv4(field) orelse return null;
            return n;
        }
        if (field.len > 4) return null;
        if (n >= out.len) return null;
        var v: u16 = 0;
        for (field) |c| {
            const d = std.fmt.charToDigit(c, 16) catch return null;
            v = (v << 4) | d;
        }
        out[n] = v;
        n += 1;
    }
    return n;
}

fn writeGroup(out: *Ipv6, group_index: usize, v: u16) void {
    out[group_index * 2] = @intCast(v >> 8);
    out[group_index * 2 + 1] = @intCast(v & 0xff);
}

// ---------------------------------------------------------------------------
// Tests (C6). The classifier is the security-critical surface, so each blocked
// range gets a representative AND a public counter-example.
// ---------------------------------------------------------------------------

const testing = std.testing;

test "IPv4: blocked ranges" {
    const blocked = [_]Ipv4{
        .{ 0, 0, 0, 0 },        .{ 10, 0, 0, 1 },      .{ 127, 0, 0, 1 },
        .{ 100, 64, 0, 1 },     .{ 100, 127, 255, 1 }, .{ 169, 254, 169, 254 }, // cloud metadata
        .{ 172, 16, 0, 1 },     .{ 172, 31, 255, 1 },  .{ 192, 168, 1, 1 },
        .{ 192, 0, 0, 1 },      .{ 192, 0, 2, 5 },     .{ 198, 18, 0, 1 },
        .{ 198, 51, 100, 7 },   .{ 203, 0, 113, 9 },   .{ 224, 0, 0, 1 },
        .{ 240, 0, 0, 1 },      .{ 255, 255, 255, 255 },
    };
    for (blocked) |a| try testing.expect(isBlockedIpv4(a));
}

test "IPv4: public addresses are allowed" {
    const allowed = [_]Ipv4{
        .{ 8, 8, 8, 8 },     .{ 1, 1, 1, 1 },      .{ 93, 184, 216, 34 },
        .{ 172, 15, 0, 1 },  .{ 172, 32, 0, 1 }, // just outside 172.16/12
        .{ 100, 63, 0, 1 },  .{ 100, 128, 0, 1 }, // just outside 100.64/10
        .{ 192, 167, 0, 1 }, .{ 11, 0, 0, 1 },
    };
    for (allowed) |a| try testing.expect(!isBlockedIpv4(a));
}

test "IPv6: native special ranges blocked, public allowed" {
    const loop = [_]u8{0} ** 15 ++ [_]u8{1};
    try testing.expect(isBlockedIpv6(loop)); // ::1
    try testing.expect(isBlockedIpv6([_]u8{0} ** 16)); // ::
    try testing.expect(isBlockedIpv6([_]u8{ 0xfe, 0x80 } ++ [_]u8{0} ** 14)); // fe80::
    try testing.expect(isBlockedIpv6([_]u8{ 0xfc, 0x00 } ++ [_]u8{0} ** 14)); // fc00::
    try testing.expect(isBlockedIpv6([_]u8{ 0xfd, 0x00 } ++ [_]u8{0} ** 14)); // fd00:: (ULA)
    try testing.expect(isBlockedIpv6([_]u8{0xff} ++ [_]u8{0} ** 15)); // ff00::

    // 2606:4700:4700::1111 (public, Cloudflare) is allowed.
    const public = [_]u8{ 0x26, 0x06, 0x47, 0x00, 0x47, 0x00 } ++ [_]u8{0} ** 8 ++ [_]u8{ 0x11, 0x11 };
    try testing.expect(!isBlockedIpv6(public));
}

test "IPv6: embedded IPv4 forms are classified by the inner v4" {
    // ::ffff:127.0.0.1 (mapped loopback) is blocked.
    const mapped_loop = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff, 127, 0, 0, 1 };
    try testing.expect(isBlockedIpv6(mapped_loop));
    // ::ffff:8.8.8.8 (mapped public) is allowed.
    const mapped_pub = [_]u8{0} ** 10 ++ [_]u8{ 0xff, 0xff, 8, 8, 8, 8 };
    try testing.expect(!isBlockedIpv6(mapped_pub));
    // 64:ff9b::10.0.0.1 (NAT64 of a private v4) is blocked.
    const nat64 = [_]u8{ 0, 0x64, 0xff, 0x9b } ++ [_]u8{0} ** 8 ++ [_]u8{ 10, 0, 0, 1 };
    try testing.expect(isBlockedIpv6(nat64));
}

test "scheme allow-list: only https" {
    try testing.expect(isAllowedScheme("https://example.com/x"));
    try testing.expect(!isAllowedScheme("http://example.com"));
    try testing.expect(!isAllowedScheme("file:///etc/passwd"));
    try testing.expect(!isAllowedScheme("gopher://x"));
}

test "hostOf: extracts the bare host" {
    try testing.expectEqualStrings("example.com", hostOf("https://example.com/.well-known/x").?);
    try testing.expectEqualStrings("example.com", hostOf("https://example.com:8443/x").?);
    try testing.expectEqualStrings("127.0.0.1", hostOf("http://127.0.0.1:2584/xrpc").?);
    try testing.expectEqualStrings("::1", hostOf("https://[::1]:443/x").?);
    try testing.expectEqualStrings("host", hostOf("https://user:pw@host/x").?);
    try testing.expect(hostOf("notaurl") == null);
}

test "ipLiteralVerdict: literals classified, names deferred to the resolver" {
    try testing.expectEqual(@as(?bool, true), ipLiteralVerdict("127.0.0.1"));
    try testing.expectEqual(@as(?bool, true), ipLiteralVerdict("169.254.169.254"));
    try testing.expectEqual(@as(?bool, false), ipLiteralVerdict("8.8.8.8"));
    try testing.expectEqual(@as(?bool, true), ipLiteralVerdict("::1"));
    try testing.expectEqual(@as(?bool, true), ipLiteralVerdict("::ffff:10.0.0.1"));
    try testing.expectEqual(@as(?bool, null), ipLiteralVerdict("example.com")); // a name
    try testing.expectEqual(@as(?bool, null), ipLiteralVerdict("0177.0.0.1")); // not strict-decimal → a name
}

test "parseIpv4: strictness" {
    try testing.expect(parseIpv4("1.2.3.4") != null);
    try testing.expect(parseIpv4("255.255.255.255") != null);
    try testing.expect(parseIpv4("256.0.0.1") == null);
    try testing.expect(parseIpv4("1.2.3") == null);
    try testing.expect(parseIpv4("1.2.3.4.5") == null);
    try testing.expect(parseIpv4("01.2.3.4") == null); // leading zero
    try testing.expect(parseIpv4("1.2.3.x") == null);
}

test "parseIpv6Host: compression and embedded v4 round-trips through the classifier" {
    try testing.expect(parseIpv6Host("::1") != null);
    try testing.expect(parseIpv6Host("fe80::1") != null);
    try testing.expect(parseIpv6Host("2606:4700:4700::1111") != null);
    try testing.expect(parseIpv6Host("::ffff:192.168.0.1") != null);
    try testing.expect(parseIpv6Host("not:::valid") == null);
    try testing.expect(parseIpv6Host("plainname") == null);
}

test "fuzz: URL/IP parsing tolerates arbitrary bytes (no crash)" {
    const fuzzgen = @import("fuzzgen.zig");
    var g = fuzzgen.Gen.init(0x5E7);
    var buf: [256]u8 = undefined;
    const seeds = [_][]const u8{
        "https://example.com:8443/x", "http://[::1]:80/", "169.254.169.254", "::ffff:10.0.0.1",
    };
    var i: usize = 0;
    while (i < 4000) : (i += 1) {
        const input = g.next(&buf, &seeds, "htps:/.[]@:0123456789abcdefz", i);
        _ = isAllowedScheme(input);
        if (hostOf(input)) |h| _ = ipLiteralVerdict(h);
        _ = parseIpv4(input);
        _ = parseIpv6Host(input);
    }
}
