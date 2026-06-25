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
// Decoding — strict DAG-CBOR. There is exactly ONE valid encoding of a value,
// and this decoder REJECTS every other form: non-minimal ints/lengths,
// indefinite lengths, unsorted or duplicate map keys, non-text keys, tags
// other than 42, non-float64 floats, undefined, and trailing bytes. Strictness
// is the security property — a lenient decoder paired with the canonical
// encoder would let a hostile server present two byte sequences that decode to
// the same value, muddying the CID identity the protocol rests on. Leaf
// bytes / strings / CID payloads borrow from the input; only list and map
// arrays allocate, in `arena`, so the caller frees them wholesale (C3).
// ---------------------------------------------------------------------------

pub const DecodeError = error{
    Truncated, // input ended mid-value
    TooDeep, // nesting beyond max_depth
    NotCanonical, // a non-minimal int/length, a non-text key, or an out-of-order/duplicate key
    Unsupported, // a CBOR feature DAG-CBOR forbids (indefinite, undefined, non-f64 float, tag != 42, out-of-int64 int)
    InvalidUtf8, // a text string / key that isn't valid UTF-8
    BadCidLink, // tag 42 not wrapping a 0x00-prefixed byte string
    TrailingBytes, // bytes remain after the single top-level value
} || Allocator.Error;

/// Decode exactly one canonical DAG-CBOR value from `bytes`; the whole input
/// must be that single value (trailing bytes are an error). `arena` holds the
/// decoded list/map arrays, while byte/text/link payloads borrow from `bytes`,
/// so `bytes` must outlive the returned Value.
pub fn decode(arena: Allocator, bytes: []const u8) DecodeError!Value {
    var d = Decoder{ .bytes = bytes, .pos = 0, .arena = arena };
    const v = try d.value(0);
    if (d.pos != bytes.len) return error.TrailingBytes;
    return v;
}

const Decoder = struct {
    // A7.2: cold struct — a transient parse cursor (one per `decode` call),
    // never held in quantity or processed in a loop; size guard waived.
    bytes: []const u8,
    pos: usize,
    arena: Allocator,

    fn take(d: *Decoder, n: usize) DecodeError![]const u8 {
        if (n > d.bytes.len - d.pos) return error.Truncated;
        const s = d.bytes[d.pos .. d.pos + n];
        d.pos += n;
        return s;
    }

    fn byte(d: *Decoder) DecodeError!u8 {
        return (try d.take(1))[0];
    }

    /// Read a head's argument from its 5-bit additional info, enforcing the
    /// SHORTEST encoding (so a non-minimal int or length is rejected).
    fn argument(d: *Decoder, additional: u5) DecodeError!u64 {
        if (additional < 24) return additional;
        switch (additional) {
            24 => {
                const v = (try d.take(1))[0];
                if (v < 24) return error.NotCanonical;
                return v;
            },
            25 => {
                const v = std.mem.readInt(u16, (try d.take(2))[0..2], .big);
                if (v <= 0xff) return error.NotCanonical;
                return v;
            },
            26 => {
                const v = std.mem.readInt(u32, (try d.take(4))[0..4], .big);
                if (v <= 0xffff) return error.NotCanonical;
                return v;
            },
            27 => {
                const v = std.mem.readInt(u64, (try d.take(8))[0..8], .big);
                if (v <= 0xffffffff) return error.NotCanonical;
                return v;
            },
            else => return error.Unsupported, // 28..31: reserved / indefinite
        }
    }

    fn value(d: *Decoder, depth: usize) DecodeError!Value {
        if (depth >= max_depth) return error.TooDeep;
        const head = try d.byte();
        const major: u3 = @intCast(head >> 5);
        const additional: u5 = @intCast(head & 0x1f);
        switch (major) {
            0 => { // unsigned int (IPLD ints are the int64 range)
                const arg = try d.argument(additional);
                if (arg > std.math.maxInt(i64)) return error.Unsupported;
                return .{ .int = @intCast(arg) };
            },
            1 => { // negative int: -1 - arg
                const arg = try d.argument(additional);
                const n = -1 - @as(i128, arg);
                if (n < std.math.minInt(i64)) return error.Unsupported;
                return .{ .int = @intCast(n) };
            },
            2 => { // byte string
                const len = try d.argument(additional);
                return .{ .bytes = try d.take(@intCast(len)) };
            },
            3 => { // text string
                const len = try d.argument(additional);
                const s = try d.take(@intCast(len));
                if (!std.unicode.utf8ValidateSlice(s)) return error.InvalidUtf8;
                return .{ .string = s };
            },
            4 => { // array
                const len = try d.argument(additional);
                if (len > d.bytes.len - d.pos) return error.Truncated; // each item is >= 1 byte
                const items = try d.arena.alloc(Value, @intCast(len));
                for (items) |*it| it.* = try d.value(depth + 1);
                return .{ .list = items };
            },
            5 => { // map (keys must be text, strictly ascending in canonical order)
                const len = try d.argument(additional);
                if (len > d.bytes.len - d.pos) return error.Truncated;
                const entries = try d.arena.alloc(Entry, @intCast(len));
                var prev: ?[]const u8 = null;
                for (entries) |*e| {
                    const key = try d.textKey();
                    if (prev) |p| if (keyOrder(p, key) != .lt) return error.NotCanonical;
                    prev = key;
                    e.* = .{ .key = key, .value = try d.value(depth + 1) };
                }
                return .{ .map = entries };
            },
            6 => { // tag — DAG-CBOR permits ONLY tag 42, a CID link
                const tag = try d.argument(additional);
                if (tag != 42) return error.Unsupported;
                const inner = try d.value(depth + 1);
                const raw = switch (inner) {
                    .bytes => |b| b,
                    else => return error.BadCidLink,
                };
                if (raw.len == 0 or raw[0] != 0x00) return error.BadCidLink;
                return .{ .link = raw[1..] };
            },
            7 => switch (additional) { // simple values + float64
                20 => return .{ .bool = false },
                21 => return .{ .bool = true },
                22 => return .null,
                27 => {
                    const f: f64 = @bitCast(std.mem.readInt(u64, (try d.take(8))[0..8], .big));
                    if (!std.math.isFinite(f)) return error.Unsupported;
                    return .{ .float = f };
                },
                else => return error.Unsupported, // undefined, 16/32-bit float, reserved
            },
        }
    }

    /// A map key MUST be a text string in DAG-CBOR.
    fn textKey(d: *Decoder) DecodeError![]const u8 {
        const head = try d.byte();
        if (head >> 5 != 3) return error.NotCanonical; // not major type 3 (text)
        const s = try d.take(@intCast(try d.argument(@intCast(head & 0x1f))));
        if (!std.unicode.utf8ValidateSlice(s)) return error.InvalidUtf8;
        return s;
    }
};

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

fn valueEql(a: Value, b: Value) bool {
    if (std.meta.activeTag(a) != std.meta.activeTag(b)) return false;
    return switch (a) {
        .null => true,
        .bool => |x| x == b.bool,
        .int => |x| x == b.int,
        .float => |x| x == b.float,
        .bytes => |x| std.mem.eql(u8, x, b.bytes),
        .string => |x| std.mem.eql(u8, x, b.string),
        .link => |x| std.mem.eql(u8, x, b.link),
        .list => |x| blk: {
            if (x.len != b.list.len) break :blk false;
            for (x, b.list) |ai, bi| if (!valueEql(ai, bi)) break :blk false;
            break :blk true;
        },
        .map => |x| blk: {
            if (x.len != b.map.len) break :blk false;
            for (x, b.map) |ae, be| {
                if (!std.mem.eql(u8, ae.key, be.key) or !valueEql(ae.value, be.value)) break :blk false;
            }
            break :blk true;
        },
    };
}

test "decode: round-trips the encoder across every value kind" {
    const cid_bytes = [_]u8{ 0x01, 0x71, 0x12, 0x20, 0xaa };
    const inner = [_]Entry{
        .{ .key = "n", .value = .{ .int = -7 } },
        .{ .key = "s", .value = .{ .string = "hi" } },
    };
    const items = [_]Value{ .{ .int = 0 }, .{ .int = 1000000 }, .{ .bool = true }, .null };
    // Keys already in canonical order so the decoded tree compares equal.
    const top = [_]Entry{
        .{ .key = "b", .value = .{ .bytes = &.{ 1, 2, 3 } } },
        .{ .key = "f", .value = .{ .float = 1.5 } },
        .{ .key = "k", .value = .{ .link = &cid_bytes } },
        .{ .key = "l", .value = .{ .list = &items } },
        .{ .key = "m", .value = .{ .map = &inner } },
    };
    const v = Value{ .map = &top };

    const bytes = try encode(testing.allocator, v);
    defer testing.allocator.free(bytes);
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const decoded = try decode(arena.allocator(), bytes);

    try testing.expect(valueEql(decoded, v));
    // And re-encoding the decoded value reproduces the exact canonical bytes.
    const bytes2 = try encode(testing.allocator, decoded);
    defer testing.allocator.free(bytes2);
    try testing.expectEqualSlices(u8, bytes, bytes2);
}

test "decode: the {\"hello\":\"world\"} vector" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const bytes = [_]u8{ 0xa1, 0x65, 'h', 'e', 'l', 'l', 'o', 0x65, 'w', 'o', 'r', 'l', 'd' };
    const v = try decode(arena.allocator(), &bytes);
    try testing.expectEqual(@as(usize, 1), v.map.len);
    try testing.expectEqualStrings("hello", v.map[0].key);
    try testing.expectEqualStrings("world", v.map[0].value.string);
}

test "decode: strict — every non-canonical or forbidden form is rejected" {
    var arena = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena.deinit();
    const a = arena.allocator();
    try testing.expectError(error.NotCanonical, decode(a, &.{ 0x18, 0x05 })); // uint 5 in 2 bytes
    try testing.expectError(error.Unsupported, decode(a, &.{ 0x9f, 0xff })); // indefinite array
    try testing.expectError(error.TrailingBytes, decode(a, &.{ 0x00, 0x00 })); // two top-level values
    try testing.expectError(error.Truncated, decode(a, &.{0x18})); // arg byte missing
    try testing.expectError(error.Unsupported, decode(a, &.{ 0xc0, 0x00 })); // tag 0 (only 42 allowed)
    try testing.expectError(error.Unsupported, decode(a, &.{ 0xfb, 0x7f, 0xf0, 0, 0, 0, 0, 0, 0 })); // +Inf
    try testing.expectError(error.Unsupported, decode(a, &.{ 0xfa, 0, 0, 0, 0 })); // 32-bit float
    try testing.expectError(error.NotCanonical, decode(a, &.{ 0xa2, 0x61, 'b', 0x00, 0x61, 'a', 0x00 })); // keys out of order
    try testing.expectError(error.NotCanonical, decode(a, &.{ 0xa2, 0x61, 'a', 0x00, 0x61, 'a', 0x00 })); // duplicate key
    try testing.expectError(error.NotCanonical, decode(a, &.{ 0xa1, 0x00, 0x00 })); // non-text key
    try testing.expectError(error.BadCidLink, decode(a, &.{ 0xd8, 0x2a, 0x42, 0x01, 0x02 })); // tag 42, no 0x00 prefix
}

test "fuzz: decode tolerates arbitrary bytes (no crash, no leak)" {
    const fuzzgen = @import("fuzzgen.zig");
    var g = fuzzgen.Gen.init(0xCB0);
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var buf: [256]u8 = undefined;
    const hw = [_]u8{ 0xa1, 0x65, 'h', 'e', 'l', 'l', 'o', 0x65, 'w', 'o', 'r', 'l', 'd' };
    const seeds = [_][]const u8{ &hw, &.{ 0x83, 0x01, 0x02, 0x03 }, &.{0xa0}, &.{0x00} };
    // A charset of CBOR head bytes reaches deep into the major-type branches.
    const heads = [_]u8{ 0xa0, 0xa1, 0x82, 0x83, 0x65, 0x40, 0x18, 0x19, 0xff, 0x00, 0x01, 0x20, 0xd8, 0x2a, 0xfb, 0xf4, 0xf6 };
    var i: usize = 0;
    while (i < 4000) : (i += 1) {
        const input = g.next(&buf, &seeds, &heads, i);
        _ = arena_state.reset(.retain_capacity);
        _ = decode(arena_state.allocator(), input) catch {};
    }
}
