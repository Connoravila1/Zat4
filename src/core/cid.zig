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

//! B1 classification: CORE (pure). Content identifiers — recompute and verify.
//!
//! "Recompute the hash and confirm it matches the claimed CID before trusting
//! 'this CID = this content'" (SECURITY_ROADMAP Phase 2 / A8). A CID is a hash
//! of a block's canonical bytes; a server that hands us bytes that do not hash
//! to the CID it claims is lying or corrupted, and we reject it — by the math,
//! not by trust.
//!
//! Scope: the ONE CID shape atproto records use — **CIDv1, dag-cbor codec
//! (0x71), sha2-256 multihash (0x12, 32 bytes)**, written as a `b`-prefixed
//! base32 (lowercase, RFC 4648, no pad) multibase string. The binary form is
//! the 4-byte prefix `01 71 12 20` followed by the 32-byte digest.
//!
//! Pure (B2/B4): hashing and base32 are deterministic computation, not I/O.
//! `verifyValue` pairs with `core/dagcbor.zig` — encode an IPLD value to its
//! canonical bytes, hash, and compare to the claimed CID. The shell parses the
//! hostile record; the recompute-and-compare lives here.

const std = @import("std");
const dagcbor = @import("dagcbor.zig");
const Sha256 = std.crypto.hash.sha2.Sha256;

/// Multicodec / multihash constants for the accepted shape.
pub const codec_dag_cbor = 0x71;
pub const hash_sha2_256 = 0x12;

/// Binary CIDv1 length: version(1) + codec(1) + hash-code(1) + digest-len(1) +
/// 32-byte digest.
pub const binary_len = 4 + 32;

/// Compute the binary CIDv1 (dag-cbor, sha2-256) of a block's canonical bytes.
pub fn computeV1DagCbor(block: []const u8) [binary_len]u8 {
    var digest: [32]u8 = undefined;
    Sha256.hash(block, &digest, .{});
    var out: [binary_len]u8 = undefined;
    out[0] = 0x01; // CIDv1
    out[1] = codec_dag_cbor;
    out[2] = hash_sha2_256;
    out[3] = 0x20; // digest length, 32
    @memcpy(out[4..], &digest);
    return out;
}

pub const ParseError = error{
    NotBase32Multibase, // missing the 'b' base32 multibase prefix
    BadBase32, // a character outside the base32 alphabet
    BadLength, // decoded bytes aren't a 36-byte CIDv1
};

/// Maximum base32 string length we format/parse: ceil(36*8/5) = 58 symbols,
/// plus the 1-char multibase prefix.
pub const max_string_len = 1 + 58;

/// Recompute the CID of `block` and confirm it equals `claimed`. A claimed CID
/// that doesn't parse, or whose bytes differ from the recomputed CID, is a
/// rejection (false) — never trusted (E4: a mismatch is an ordinary negative).
pub fn verifyBlock(block: []const u8, claimed: []const u8) bool {
    var parsed: [binary_len]u8 = undefined;
    parse(claimed, &parsed) catch return false;
    const computed = computeV1DagCbor(block);
    return std.mem.eql(u8, &parsed, &computed);
}

/// Encode an IPLD value to canonical DAG-CBOR (via `core/dagcbor.zig`), then
/// recompute its CID and compare to `claimed`. The end-to-end integrity check
/// for a decoded record.
pub fn verifyValue(
    gpa: std.mem.Allocator,
    value: dagcbor.Value,
    claimed: []const u8,
) dagcbor.EncodeError!bool {
    const bytes = try dagcbor.encode(gpa, value);
    defer gpa.free(bytes);
    return verifyBlock(bytes, claimed);
}

/// Parse a CIDv1 multibase string (base32, 'b' prefix) into its 36 binary
/// bytes. Only the dag-cbor/sha2-256 length is accepted; the caller compares
/// the full binary, so a wrong codec/hash simply won't match a recomputed CID.
pub fn parse(s: []const u8, out: *[binary_len]u8) ParseError!void {
    if (s.len == 0 or s[0] != 'b') return error.NotBase32Multibase;
    var buf: [binary_len + 4]u8 = undefined;
    const n = base32DecodeLower(s[1..], &buf) catch return error.BadBase32;
    if (n != binary_len) return error.BadLength;
    @memcpy(out, buf[0..binary_len]);
}

/// Format a binary CID as a `b`-prefixed lowercase base32 multibase string into
/// `out` (which must hold at least `max_string_len` bytes); returns the slice.
pub fn format(bin: []const u8, out: []u8) []u8 {
    out[0] = 'b';
    const body = base32EncodeLower(bin, out[1..]);
    return out[0 .. 1 + body.len];
}

// ---------------------------------------------------------------------------
// base32 — RFC 4648 lowercase alphabet, no padding (multibase 'b'). Pure,
// streaming over a caller buffer (C1/C2).
// ---------------------------------------------------------------------------

const base32_alphabet = "abcdefghijklmnopqrstuvwxyz234567";

fn base32EncodeLower(data: []const u8, out: []u8) []u8 {
    var n: usize = 0;
    var acc: u32 = 0;
    var bits: u5 = 0;
    for (data) |b| {
        acc = (acc << 8) | b;
        bits += 8;
        while (bits >= 5) {
            bits -= 5;
            const idx: u5 = @intCast((acc >> bits) & 0x1f);
            out[n] = base32_alphabet[idx];
            n += 1;
        }
        acc &= (@as(u32, 1) << bits) - 1; // drop consumed high bits
    }
    if (bits > 0) {
        const idx: u5 = @intCast((acc << (5 - bits)) & 0x1f);
        out[n] = base32_alphabet[idx];
        n += 1;
    }
    return out[0..n];
}

fn base32DecodeLower(s: []const u8, out: []u8) error{BadBase32}!usize {
    var n: usize = 0;
    var acc: u32 = 0;
    var bits: u5 = 0;
    for (s) |c| {
        const v = base32Digit(c) orelse return error.BadBase32;
        acc = (acc << 5) | v;
        bits += 5;
        if (bits >= 8) {
            bits -= 8;
            out[n] = @intCast((acc >> bits) & 0xff);
            n += 1;
            acc &= (@as(u32, 1) << bits) - 1;
        }
    }
    return n;
}

fn base32Digit(c: u8) ?u5 {
    return switch (c) {
        'a'...'z' => @intCast(c - 'a'),
        '2'...'7' => @intCast(c - '2' + 26),
        else => null,
    };
}

// ---------------------------------------------------------------------------
// Tests (C6). The reference CID and base32 vectors were computed independently
// (Python hashlib + stdlib base32), so a match proves cross-implementation
// correctness, not mere self-consistency.
// ---------------------------------------------------------------------------

const testing = std.testing;

// The canonical CID of the dag-cbor block {"hello":"world"} — the same value
// the atproto interop signature fixtures sign. (bafyrei… is the standard CIDv1
// dag-cbor + sha2-256 prefix, matching real atproto record CIDs.)
const hello_world_cid = "bafyreidykglsfhoixmivffc5uwhcgshx4j465xwqntbmu43nb2dzqwfvae";
const hello_world_dagcbor = [_]u8{ 0xa1, 0x65, 'h', 'e', 'l', 'l', 'o', 0x65, 'w', 'o', 'r', 'l', 'd' };

test "base32: RFC 4648 lowercase no-pad vectors" {
    var buf: [16]u8 = undefined;
    try testing.expectEqualStrings("", base32EncodeLower("", &buf));
    try testing.expectEqualStrings("my", base32EncodeLower("f", &buf));
    try testing.expectEqualStrings("mzxq", base32EncodeLower("fo", &buf));
    try testing.expectEqualStrings("mzxw6", base32EncodeLower("foo", &buf));
    try testing.expectEqualStrings("mzxw6ytboi", base32EncodeLower("foobar", &buf));
}

test "base32: decode round-trips encode" {
    const samples = [_][]const u8{ "f", "fo", "foo", "foobar", &hello_world_dagcbor };
    for (samples) |s| {
        var enc: [128]u8 = undefined;
        const e = base32EncodeLower(s, &enc);
        var dec: [128]u8 = undefined;
        const n = try base32DecodeLower(e, &dec);
        try testing.expectEqualSlices(u8, s, dec[0..n]);
    }
}

test "CID: recompute {\"hello\":\"world\"} matches the independent reference" {
    const bin = computeV1DagCbor(&hello_world_dagcbor);
    var buf: [max_string_len]u8 = undefined;
    try testing.expectEqualStrings(hello_world_cid, format(&bin, &buf));
}

test "CID: verifyBlock accepts the true CID and rejects a tampered block" {
    try testing.expect(verifyBlock(&hello_world_dagcbor, hello_world_cid));

    var tampered = hello_world_dagcbor;
    tampered[tampered.len - 1] ^= 0x01; // "worle" instead of "world"
    try testing.expect(!verifyBlock(&tampered, hello_world_cid));

    // A malformed / wrong-multibase claimed CID is a clean false, not a crash.
    try testing.expect(!verifyBlock(&hello_world_dagcbor, "not-a-cid"));
    try testing.expect(!verifyBlock(&hello_world_dagcbor, ""));
    try testing.expect(!verifyBlock(&hello_world_dagcbor, "bxxxx"));
}

test "CID: verifyValue ties dagcbor.encode -> CID end to end" {
    const entries = [_]dagcbor.Entry{.{ .key = "hello", .value = .{ .string = "world" } }};
    const value = dagcbor.Value{ .map = &entries };
    try testing.expect(try verifyValue(testing.allocator, value, hello_world_cid));

    // A different value must NOT match this CID.
    const other = [_]dagcbor.Entry{.{ .key = "hello", .value = .{ .string = "there" } }};
    try testing.expect(!try verifyValue(testing.allocator, .{ .map = &other }, hello_world_cid));
}

test "parse: errors are explicit and total" {
    var out: [binary_len]u8 = undefined;
    try testing.expectError(error.NotBase32Multibase, parse("", &out));
    try testing.expectError(error.NotBase32Multibase, parse("zfoo", &out));
    try testing.expectError(error.BadBase32, parse("b001", &out)); // '0','1' aren't base32
    try testing.expectError(error.BadLength, parse("bmzxw6", &out)); // valid base32, too short
    try parse(hello_world_cid, &out); // the real one parses cleanly
}

test "fuzz: parse/verify tolerate arbitrary bytes (no crash, no leak)" {
    const fuzzgen = @import("fuzzgen.zig");
    var g = fuzzgen.Gen.init(0xC1D5);
    var buf: [256]u8 = undefined;
    const seeds = [_][]const u8{ hello_world_cid, "bafyreih", "b", "z" };
    var i: usize = 0;
    while (i < 4000) : (i += 1) {
        const input = g.next(&buf, &seeds, "bafyrei234567zxdmqABCDEF", i);
        var out: [binary_len]u8 = undefined;
        _ = parse(input, &out) catch {};
        _ = verifyBlock(&hello_world_dagcbor, input);
    }
}
