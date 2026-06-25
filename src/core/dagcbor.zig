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

//! B1 classification: CORE (pure). Deterministic DAG-CBOR encoding.
//!
//! The codec primitive the rest of the trust boundary is built on
//! (SECURITY_ROADMAP Phases 2 & 3). Two things atproto asks us to compute
//! ourselves rest on it:
//!   - **Signing bytes** — a repo commit is signed over SHA-256 of the
//!     DAG-CBOR of the *unsigned* commit node. To verify a signature
//!     (`core/sigverify.zig`) end-to-end we must reproduce those exact bytes.
//!   - **CIDs** — a content identifier is a hash of a block's DAG-CBOR bytes.
//!     To "recompute the CID and confirm it matches" (don't trust the server's
//!     claimed CID) we re-encode and hash.
//!
//! DAG-CBOR is CBOR restricted to ONE canonical byte sequence per value, so
//! the same data always hashes identically. This encoder enforces that
//! determinism (the rules that matter for atproto records):
//!   - integers, lengths, and tags use the SHORTEST head (no padded ints);
//!   - map keys are strings, sorted **length-first then bytewise** (the
//!     original CBOR canonical order DAG-CBOR keeps), with duplicates rejected;
//!   - no indefinite-length items; floats, when present, are 64-bit and finite;
//!   - a CID link is tag 42 wrapping a byte string with the 0x00 identity
//!     multibase prefix.
//!
//! Pure (B2/B4): a transform from a plain `Value` tree to bytes. It allocates
//! its output and a small key-ordering scratch through the caller's allocator
//! (C1/C2) and touches nothing else. Recursion depth is bounded so adversarial
//! nesting can't blow the stack (Phase 2). The shell parses hostile JSON/CBOR
//! into a `Value`; this module never reads the wire itself.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

/// The IPLD data model, as much of it as atproto records use. A plain,
/// recursive value tree handed in by the shell (B5) — no methods (A1).
pub const Value = union(enum) {
    null,
    bool: bool,
    /// IPLD integers live in the signed 64-bit range.
    int: i64,
    /// IPLD Float is always 64-bit; non-finite values are not encodable.
    float: f64,
    bytes: []const u8,
    /// Must be valid UTF-8 (checked at encode time).
    string: []const u8,
    list: []const Value,
    /// Encoded in canonical key order; the input order does not matter and is
    /// not mutated.
    map: []const Entry,
    /// A CID link (tag 42). `bytes` is the raw binary CID (version + codec +
    /// multihash), without the 0x00 identity-multibase prefix this adds.
    link: []const u8,

    comptime {
        // Budget: tag + the widest payload (a slice: ptr+len = 16 on 64-bit),
        // which sets the union size. Held in quantity while building a record
        // tree, so it carries a guard (A7).
        assert(@sizeOf(Value) == 24);
    }
};

/// One map entry. The key is a CBOR text string.
pub const Entry = struct {
    key: []const u8,
    value: Value,

    comptime {
        // A slice key (16) + a 24-byte Value, no padding needed.
        assert(@sizeOf(Entry) == 40);
    }
};

pub const EncodeError = error{
    TooDeep, // nesting beyond max_depth — reject adversarial input, don't crash
    InvalidUtf8, // a string / map key that isn't valid UTF-8
    NonFiniteFloat, // NaN or ±Inf has no DAG-CBOR encoding
    DuplicateKey, // a map with two equal keys is not canonical
} || Allocator.Error;

/// Maximum nesting depth. Bounds stack use against hostile deeply-nested input
/// (Phase 2). atproto records are shallow; 64 is far above any real record.
pub const max_depth = 64;

/// Encode `value` to its canonical DAG-CBOR bytes. Caller owns the returned
/// slice (C1/C5 — free it with the same allocator).
pub fn encode(gpa: Allocator, value: Value) EncodeError![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(gpa);
    try encodeValue(gpa, &out, value, 0);
    return out.toOwnedSlice(gpa);
}

fn encodeValue(
    gpa: Allocator,
    out: *std.ArrayListUnmanaged(u8),
    value: Value,
    depth: usize,
) EncodeError!void {
    if (depth >= max_depth) return error.TooDeep;
    switch (value) {
        .null => try out.append(gpa, 0xf6),
        .bool => |b| try out.append(gpa, if (b) 0xf5 else 0xf4),
        .int => |n| if (n >= 0)
            try writeHead(gpa, out, 0, @intCast(n))
        else
            // Major type 1 encodes -1 - arg; for i64 min this stays in u64.
            try writeHead(gpa, out, 1, @intCast(-1 - @as(i128, n))),
        .float => |f| {
            if (!std.math.isFinite(f)) return error.NonFiniteFloat;
            try out.append(gpa, (7 << 5) | 27);
            const bits: u64 = @bitCast(f);
            var buf: [8]u8 = undefined;
            std.mem.writeInt(u64, &buf, bits, .big);
            try out.appendSlice(gpa, &buf);
        },
        .bytes => |b| {
            try writeHead(gpa, out, 2, b.len);
            try out.appendSlice(gpa, b);
        },
        .string => |s| {
            if (!std.unicode.utf8ValidateSlice(s)) return error.InvalidUtf8;
            try writeHead(gpa, out, 3, s.len);
            try out.appendSlice(gpa, s);
        },
        .list => |items| {
            try writeHead(gpa, out, 4, items.len);
            for (items) |item| try encodeValue(gpa, out, item, depth + 1);
        },
        .map => |entries| try encodeMap(gpa, out, entries, depth),
        .link => |cid| {
            // Tag 42, then a byte string of 0x00 ++ the binary CID.
            try writeHead(gpa, out, 6, 42);
            try writeHead(gpa, out, 2, cid.len + 1);
            try out.append(gpa, 0x00);
            try out.appendSlice(gpa, cid);
        },
    }
}

fn encodeMap(
    gpa: Allocator,
    out: *std.ArrayListUnmanaged(u8),
    entries: []const Entry,
    depth: usize,
) EncodeError!void {
    // Sort indices into the caller's slice — never mutate the input (C4).
    const order = try gpa.alloc(usize, entries.len);
    defer gpa.free(order);
    for (order, 0..) |*o, i| o.* = i;
    std.sort.pdq(usize, order, entries, lessByKey);

    try writeHead(gpa, out, 5, entries.len);
    var prev: ?[]const u8 = null;
    for (order) |i| {
        const key = entries[i].key;
        if (!std.unicode.utf8ValidateSlice(key)) return error.InvalidUtf8;
        if (prev) |p| {
            if (keyOrder(p, key) == .eq) return error.DuplicateKey;
        }
        prev = key;
        try writeHead(gpa, out, 3, key.len);
        try out.appendSlice(gpa, key);
        try encodeValue(gpa, out, entries[i].value, depth + 1);
    }
}

/// DAG-CBOR canonical key order: shorter keys first, then bytewise.
fn keyOrder(a: []const u8, b: []const u8) std.math.Order {
    if (a.len != b.len) return std.math.order(a.len, b.len);
    return std.mem.order(u8, a, b);
}

fn lessByKey(entries: []const Entry, ai: usize, bi: usize) bool {
    return keyOrder(entries[ai].key, entries[bi].key) == .lt;
}

/// Emit a CBOR head: the major type (0..7) in the top 3 bits, with `arg` in
/// the shortest additional-information form DAG-CBOR mandates.
fn writeHead(
    gpa: Allocator,
    out: *std.ArrayListUnmanaged(u8),
    major: u8,
    arg: u64,
) Allocator.Error!void {
    const mt: u8 = major << 5;
    if (arg < 24) {
        try out.append(gpa, mt | @as(u8, @intCast(arg)));
    } else if (arg <= 0xff) {
        try out.appendSlice(gpa, &.{ mt | 24, @intCast(arg) });
    } else if (arg <= 0xffff) {
        var buf: [3]u8 = undefined;
        buf[0] = mt | 25;
        std.mem.writeInt(u16, buf[1..3], @intCast(arg), .big);
        try out.appendSlice(gpa, &buf);
    } else if (arg <= 0xffffffff) {
        var buf: [5]u8 = undefined;
        buf[0] = mt | 26;
        std.mem.writeInt(u32, buf[1..5], @intCast(arg), .big);
        try out.appendSlice(gpa, &buf);
    } else {
        var buf: [9]u8 = undefined;
        buf[0] = mt | 27;
        std.mem.writeInt(u64, buf[1..9], arg, .big);
        try out.appendSlice(gpa, &buf);
    }
}

// ---------------------------------------------------------------------------
// Tests (C6). Vectors are hand-derived from the DAG-CBOR / CBOR spec; the
// {"hello":"world"} case is the exact byte sequence the atproto interop
// signature fixtures use as their signed message (oWVoZWxsb2V3b3JsZA base64),
// tying this encoder to a real cross-implementation reference.
// ---------------------------------------------------------------------------

const testing = std.testing;

fn expectEncodes(value: Value, expected: []const u8) !void {
    const got = try encode(testing.allocator, value);
    defer testing.allocator.free(got);
    try testing.expectEqualSlices(u8, expected, got);
}

test "atoms: null, bool" {
    try expectEncodes(.null, &.{0xf6});
    try expectEncodes(.{ .bool = false }, &.{0xf4});
    try expectEncodes(.{ .bool = true }, &.{0xf5});
}

test "integers use the shortest head" {
    try expectEncodes(.{ .int = 0 }, &.{0x00});
    try expectEncodes(.{ .int = 23 }, &.{0x17});
    try expectEncodes(.{ .int = 24 }, &.{ 0x18, 0x18 });
    try expectEncodes(.{ .int = 255 }, &.{ 0x18, 0xff });
    try expectEncodes(.{ .int = 256 }, &.{ 0x19, 0x01, 0x00 });
    try expectEncodes(.{ .int = 1000000 }, &.{ 0x1a, 0x00, 0x0f, 0x42, 0x40 });
    try expectEncodes(.{ .int = -1 }, &.{0x20});
    try expectEncodes(.{ .int = -500 }, &.{ 0x39, 0x01, 0xf3 });
}

test "bytes and strings" {
    try expectEncodes(.{ .bytes = &.{ 0x01, 0x02, 0x03 } }, &.{ 0x43, 0x01, 0x02, 0x03 });
    try expectEncodes(.{ .string = "" }, &.{0x60});
    try expectEncodes(.{ .string = "a" }, &.{ 0x61, 0x61 });
}

test "list" {
    const items = [_]Value{ .{ .int = 1 }, .{ .int = 2 }, .{ .int = 3 } };
    try expectEncodes(.{ .list = &items }, &.{ 0x83, 0x01, 0x02, 0x03 });
}

test "map: {\"hello\":\"world\"} matches the atproto interop signed message" {
    const entries = [_]Entry{.{ .key = "hello", .value = .{ .string = "world" } }};
    try expectEncodes(.{ .map = &entries }, &.{
        0xa1, 0x65, 'h', 'e', 'l', 'l', 'o', 0x65, 'w', 'o', 'r', 'l', 'd',
    });
    try expectEncodes(.{ .map = &.{} }, &.{0xa0});
}

test "map: canonical key order is length-first, then bytewise — regardless of input order" {
    // Given out of canonical order, the encoder must emit "b" (len 1) before
    // "aa" (len 2), and "aa" before "ab".
    const entries = [_]Entry{
        .{ .key = "ab", .value = .{ .int = 3 } },
        .{ .key = "b", .value = .{ .int = 1 } },
        .{ .key = "aa", .value = .{ .int = 2 } },
    };
    try expectEncodes(.{ .map = &entries }, &.{
        0xa3,
        0x61, 'b',  0x01, // "b" => 1
        0x62, 'a', 'a', 0x02, // "aa" => 2
        0x62, 'a', 'b', 0x03, // "ab" => 3
    });
}

test "CID link: tag 42 wraps 0x00 ++ binary CID" {
    const cid = [_]u8{ 0x01, 0x71, 0x12, 0x20 }; // a stand-in binary CID prefix
    try expectEncodes(.{ .link = &cid }, &.{
        0xd8, 0x2a, // tag 42
        0x45, 0x00, 0x01, 0x71, 0x12, 0x20, // bytes(5) = 0x00 ++ cid
    });
}

test "strictness: duplicate keys, bad UTF-8, and non-finite floats are rejected" {
    const dup = [_]Entry{
        .{ .key = "k", .value = .{ .int = 1 } },
        .{ .key = "k", .value = .{ .int = 2 } },
    };
    try testing.expectError(error.DuplicateKey, encode(testing.allocator, .{ .map = &dup }));

    try testing.expectError(error.InvalidUtf8, encode(testing.allocator, .{ .string = &.{0xff} }));
    try testing.expectError(error.NonFiniteFloat, encode(testing.allocator, .{ .float = std.math.inf(f64) }));
}

test "depth bound: adversarial nesting is rejected, not a stack overflow" {
    // Each node is a single-element list wrapping the one below it, nested past
    // max_depth; encode must return a clean error rather than recurse forever.
    var nodes: [max_depth + 2][1]Value = undefined;
    nodes[0] = .{.{ .int = 0 }};
    var i: usize = 1;
    while (i < nodes.len) : (i += 1) {
        nodes[i] = .{.{ .list = &nodes[i - 1] }};
    }
    const top = Value{ .list = &nodes[nodes.len - 1] };
    try testing.expectError(error.TooDeep, encode(testing.allocator, top));
}

test "float64: a finite float encodes as an 8-byte head" {
    // 1.5 = 0x3FF8000000000000 big-endian.
    try expectEncodes(.{ .float = 1.5 }, &.{ 0xfb, 0x3f, 0xf8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 });
}
