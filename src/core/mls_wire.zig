//! B1 classification: CORE (pure). The MLS wire codec — RFC 9420's TLS
//! presentation-language encoding (ZAT_CHAT_ROADMAP slice C3, part 1 of 2:
//! the CODEC; the KeyPackage/LeafNode/Welcome/Commit framing structs build
//! on it next).
//!
//! This is the attacker-facing byte boundary of the whole chat system:
//! everything a counterparty (or the relay) hands us parses through here
//! first. So the posture is parse-don't-trust: every read is bounds-checked,
//! every error is explicit in the signature (E3), varints MUST be minimally
//! encoded (the RFC's rule — a non-minimal length is rejected, not
//! normalized), and reading allocates NOTHING (vectors are borrowed slices
//! of the input, so a hostile length can never size an allocation).
//!
//! Encoding (RFC 9420 §2.1.2, the QUIC scheme capped at 4 bytes): the top
//! two bits of the first byte pick the width — 00 = 1 byte (6-bit value),
//! 01 = 2 bytes (14-bit), 10 = 4 bytes (30-bit), 11 = invalid.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

pub const ReadError = error{
    Truncated,
    NonMinimalEncoding,
    InvalidVarintPrefix,
    TrailingBytes,
};

pub const WriteError = error{ OutOfMemory, ValueTooLarge };

/// The largest value (and vector length) the varint can carry.
pub const varint_max: u32 = (1 << 30) - 1;

/// A bounds-checked cursor over untrusted bytes. Reads BORROW from the
/// input — the caller owns the buffer, nothing is copied or allocated.
/// A7.2: cold struct, size guard waived — one transient per parse.
pub const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn init(bytes: []const u8) Reader {
        return .{ .bytes = bytes };
    }

    pub fn remaining(r: *const Reader) usize {
        return r.bytes.len - r.pos;
    }

    /// The parse consumed everything — anything left over is an error, not
    /// slack (a trailing-garbage smuggling channel otherwise).
    pub fn finish(r: *const Reader) ReadError!void {
        if (r.pos != r.bytes.len) return error.TrailingBytes;
    }

    pub fn readBytes(r: *Reader, n: usize) ReadError![]const u8 {
        if (r.remaining() < n) return error.Truncated;
        const out = r.bytes[r.pos..][0..n];
        r.pos += n;
        return out;
    }

    pub fn readU8(r: *Reader) ReadError!u8 {
        const b = try r.readBytes(1);
        return b[0];
    }

    pub fn readU16(r: *Reader) ReadError!u16 {
        const b = try r.readBytes(2);
        return std.mem.readInt(u16, b[0..2], .big);
    }

    pub fn readU32(r: *Reader) ReadError!u32 {
        const b = try r.readBytes(4);
        return std.mem.readInt(u32, b[0..4], .big);
    }

    pub fn readU64(r: *Reader) ReadError!u64 {
        const b = try r.readBytes(8);
        return std.mem.readInt(u64, b[0..8], .big);
    }

    /// RFC 9420 §2.1.2 varint. Non-minimal encodings are REJECTED (the
    /// RFC's MUST — otherwise one value has many encodings and anything
    /// hashed over the wire form stops being canonical).
    pub fn readVarint(r: *Reader) ReadError!u32 {
        const b0 = try r.readU8();
        switch (b0 >> 6) {
            0 => return b0,
            1 => {
                const b1 = try r.readU8();
                const v = (@as(u32, b0 & 0x3f) << 8) | b1;
                if (v < 64) return error.NonMinimalEncoding;
                return v;
            },
            2 => {
                const rest = try r.readBytes(3);
                const v = (@as(u32, b0 & 0x3f) << 24) |
                    (@as(u32, rest[0]) << 16) |
                    (@as(u32, rest[1]) << 8) |
                    rest[2];
                if (v < 16384) return error.NonMinimalEncoding;
                return v;
            },
            else => return error.InvalidVarintPrefix,
        }
    }

    /// A variable-length vector: varint length, then that many bytes,
    /// returned as a BORROWED slice. The length is checked against what is
    /// actually present before anything is trusted.
    pub fn readVector(r: *Reader) ReadError![]const u8 {
        const len = try r.readVarint();
        return r.readBytes(len);
    }
};

// ---------------------------------------------------------------------------
// Writing — free functions appending to a caller-owned list (C1: the
// allocator is explicit at every call site).
// ---------------------------------------------------------------------------

pub fn writeU8(gpa: Allocator, out: *std.ArrayList(u8), v: u8) error{OutOfMemory}!void {
    try out.append(gpa, v);
}

pub fn writeU16(gpa: Allocator, out: *std.ArrayList(u8), v: u16) error{OutOfMemory}!void {
    var b: [2]u8 = undefined;
    std.mem.writeInt(u16, &b, v, .big);
    try out.appendSlice(gpa, &b);
}

pub fn writeU32(gpa: Allocator, out: *std.ArrayList(u8), v: u32) error{OutOfMemory}!void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .big);
    try out.appendSlice(gpa, &b);
}

pub fn writeU64(gpa: Allocator, out: *std.ArrayList(u8), v: u64) error{OutOfMemory}!void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, v, .big);
    try out.appendSlice(gpa, &b);
}

/// Minimal-width varint — the only encoding the reader accepts.
pub fn writeVarint(gpa: Allocator, out: *std.ArrayList(u8), v: u32) WriteError!void {
    if (v < 64) {
        try out.append(gpa, @intCast(v));
    } else if (v < 16384) {
        try out.appendSlice(gpa, &.{ @intCast(0x40 | (v >> 8)), @intCast(v & 0xff) });
    } else if (v <= varint_max) {
        try out.appendSlice(gpa, &.{
            @intCast(0x80 | (v >> 24)),
            @intCast((v >> 16) & 0xff),
            @intCast((v >> 8) & 0xff),
            @intCast(v & 0xff),
        });
    } else {
        return error.ValueTooLarge;
    }
}

pub fn writeVector(gpa: Allocator, out: *std.ArrayList(u8), bytes: []const u8) WriteError!void {
    if (bytes.len > varint_max) return error.ValueTooLarge;
    try writeVarint(gpa, out, @intCast(bytes.len));
    try out.appendSlice(gpa, bytes);
}

// ---------------------------------------------------------------------------
// Tests (C6: leak-checked). The boundary values are the RFC's width
// breakpoints; the rejections are the rules a hostile peer will probe.
// ---------------------------------------------------------------------------

const testing = std.testing;

test "varint: boundary values round-trip in minimal width" {
    const gpa = testing.allocator;
    const cases = [_]struct { v: u32, bytes: []const u8 }{
        .{ .v = 0, .bytes = &.{0x00} },
        .{ .v = 37, .bytes = &.{0x25} },
        .{ .v = 63, .bytes = &.{0x3f} },
        .{ .v = 64, .bytes = &.{ 0x40, 0x40 } },
        .{ .v = 16383, .bytes = &.{ 0x7f, 0xff } },
        .{ .v = 16384, .bytes = &.{ 0x80, 0x00, 0x40, 0x00 } },
        .{ .v = varint_max, .bytes = &.{ 0xbf, 0xff, 0xff, 0xff } },
    };
    for (cases) |c| {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        try writeVarint(gpa, &out, c.v);
        try testing.expectEqualSlices(u8, c.bytes, out.items);
        var r = Reader.init(out.items);
        try testing.expectEqual(c.v, try r.readVarint());
        try r.finish();
    }
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try testing.expectError(error.ValueTooLarge, writeVarint(gpa, &out, varint_max + 1));
}

test "varint: non-minimal and invalid prefixes are rejected" {
    // 37 padded into two bytes: one value, two encodings — forbidden.
    var r1 = Reader.init(&.{ 0x40, 0x25 });
    try testing.expectError(error.NonMinimalEncoding, r1.readVarint());
    // 37 padded into four bytes.
    var r2 = Reader.init(&.{ 0x80, 0x00, 0x00, 0x25 });
    try testing.expectError(error.NonMinimalEncoding, r2.readVarint());
    // The 11 prefix has no meaning in MLS.
    var r3 = Reader.init(&.{0xc0});
    try testing.expectError(error.InvalidVarintPrefix, r3.readVarint());
    // A width promise the input can't keep.
    var r4 = Reader.init(&.{0x80});
    try testing.expectError(error.Truncated, r4.readVarint());
}

test "vectors: round-trip, nesting, hostile lengths, trailing bytes" {
    const gpa = testing.allocator;

    // A vector of two inner vectors — the nesting every MLS struct uses.
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var inner: std.ArrayList(u8) = .empty;
    defer inner.deinit(gpa);
    try writeVector(gpa, &inner, "hello");
    try writeVector(gpa, &inner, "");
    try writeVector(gpa, &out, inner.items);

    var r = Reader.init(out.items);
    var body = Reader.init(try r.readVector());
    try r.finish();
    try testing.expectEqualSlices(u8, "hello", try body.readVector());
    try testing.expectEqualSlices(u8, "", try body.readVector());
    try body.finish();

    // A length that promises more than the input holds: rejected before
    // anything downstream sees it (and nothing was allocated to size it).
    var hostile = Reader.init(&.{ 0xbf, 0xff, 0xff, 0xff, 'x' });
    try testing.expectError(error.Truncated, hostile.readVector());

    // Trailing garbage after a complete parse is an error, not slack.
    var trailing = Reader.init(&.{ 0x01, 'a', 'z' });
    _ = try trailing.readVector();
    try testing.expectError(error.TrailingBytes, trailing.finish());
}

test "fixed-width integers round-trip big-endian" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try writeU8(gpa, &out, 0xab);
    try writeU16(gpa, &out, 0x0102);
    try writeU32(gpa, &out, 0xdeadbeef);
    try writeU64(gpa, &out, 0x0123456789abcdef);
    var r = Reader.init(out.items);
    try testing.expectEqual(@as(u8, 0xab), try r.readU8());
    try testing.expectEqual(@as(u16, 0x0102), try r.readU16());
    try testing.expectEqual(@as(u32, 0xdeadbeef), try r.readU32());
    try testing.expectEqual(@as(u64, 0x0123456789abcdef), try r.readU64());
    try r.finish();
}

test "fuzz: the reader tolerates arbitrary bytes (no crash, no allocation)" {
    const fuzzgen = @import("fuzzgen.zig");
    var g = fuzzgen.Gen.init(0x9420);
    var buf: [256]u8 = undefined;
    // Seeds shaped like real framing: nested vectors, fixed ints, varints.
    const seeds = [_][]const u8{
        &.{ 0x08, 0x01, 0x00, 0x01, 0x05, 'h', 'e', 'l', 'l', 'o' },
        &.{ 0x7f, 0xff, 0x00 },
        &.{ 0xbf, 0xff, 0xff, 0xff },
        &.{0x00},
    };
    // Width-prefix bytes reach every varint branch; the rest is noise.
    const heads = [_]u8{ 0x00, 0x3f, 0x40, 0x7f, 0x80, 0xbf, 0xc0, 0xff, 0x01, 0x05 };
    var i: usize = 0;
    while (i < 4000) : (i += 1) {
        const input = g.next(&buf, &seeds, &heads, i);
        // Drive a plausible parse shape over hostile bytes: any error is
        // fine; a crash, hang, or out-of-bounds read is the failure.
        var r = Reader.init(input);
        _ = r.readU16() catch continue;
        var depth: usize = 0;
        while (depth < 8) : (depth += 1) {
            const vec = r.readVector() catch break;
            var innr = Reader.init(vec);
            _ = innr.readVarint() catch {};
            _ = r.readU64() catch break;
        }
        r.finish() catch continue;
    }
}
