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

//! B1 classification: CORE (pure over its own data). **The runtime algorithm
//! LIBRARY** — the algorithms a user OWNS: the ones they built (the simple
//! Create flow) and the ones they downloaded from the marketplace. It is the
//! runtime sibling of the comptime `lens_catalog.Builtin` table: a built-in is a
//! first-party algorithm baked into the binary; a library record is one that came
//! into being at runtime and so must be stored, resolved, and persisted like any
//! other owned data.
//!
//! Each record carries the "cartridge identity" every algorithm surface reads: a
//! name, a one-line "what it ranks for", a description (the public/detail page), a
//! default accent color (the socket tint), the creator, a visibility (private —
//! just for you — vs public — submitted to the marketplace), a rating aggregate,
//! and the algorithm's LOGIC as a serialized `FeedConfig` (the same byte-exact form
//! `core/algorithm.serialize` produces and a marketplace record carries — parse on
//! demand, never a live config with dangling slices to own).
//!
//! The strings + config bytes live in one owned BLOB; records hold spans into it
//! (A6, the tray-blob pattern). A record's `id` is the only thing that crosses a
//! module boundary (A5) — a local uid for a created algorithm, the CID for a
//! downloaded one; the caller mints it (no clock/RNG in the core).

const std = @import("std");
const Allocator = std.mem.Allocator;

/// A half-open `[off, off+len)` window into the library blob. Same shape as the
/// tray/store span types; local so the module owns its layout.
pub const Span = struct {
    off: u32 = 0,
    len: u32 = 0,

    comptime {
        assert(@sizeOf(Span) == 8); // two u32, packed
    }
};

const assert = std.debug.assert;

/// Whether an algorithm is the user's own (private — never leaves the device / the
/// marketplace) or has been submitted to the marketplace (public). The simple
/// builder produces `private`; the code-submission flow produces `public`.
pub const Visibility = enum(u8) { private, public };

/// A star-rating aggregate (each rating is 1..5). Ratings are only shown on the
/// large marketplace detail page; a private algorithm carries a zeroed one.
pub const Rating = struct {
    sum: u32 = 0, // sum of star values across all ratings
    count: u32 = 0, // number of ratings

    comptime {
        assert(@sizeOf(Rating) == 8); // two u32, packed
    }
};

/// The average stars (0 when unrated), for display. Pure, total.
pub fn ratingAverage(r: Rating) f32 {
    if (r.count == 0) return 0;
    return @as(f32, @floatFromInt(r.sum)) / @as(f32, @floatFromInt(r.count));
}

/// One owned algorithm. Cold-ish (a user owns a handful to dozens, never iterated
/// in a per-frame/per-candidate hot loop), but held in a collection, so it carries
/// an exact size guard anyway (A7 — when in doubt, guard). All variable-length data
/// is a span into the library blob (A6); the config rides as serialized BYTES
/// (parse on demand) so a record owns no dangling `FeedConfig` slices.
pub const AlgoRecord = struct {
    id: Span, // stable id — a local uid (created) or a CID (downloaded); the boundary value (A5)
    name: Span,
    ranks: Span, // one-line "what it ranks for"
    desc: Span, // the detail/public-page paragraph
    creator: Span, // "@handle" or "you"
    config: Span, // serialized FeedConfig bytes; empty ⇒ the no-scoring chronological path
    color: u8, // default accent palette index (0..8) — the socket tint
    visibility: Visibility,
    rating: Rating,

    comptime {
        // Budget 60: 6 × Span(8) = 48, + Rating(8) = 56, + color(1) + visibility(1)
        // = 58, padded to 60 at the u32 alignment of Span/Rating. Exact. Every span
        // is earned (the cartridge-identity fields); the two enums/bytes ride in the
        // tail padding.
        assert(@sizeOf(AlgoRecord) == 60);
    }
};

/// The metadata for adding a record (plain values the caller supplies; the library
/// copies them into its blob). `config` is already-serialized bytes (or empty for a
/// no-scoring algorithm). A7.2: cold — one per `add` call, never held. Waived.
pub const NewAlgo = struct {
    id: []const u8,
    name: []const u8,
    ranks: []const u8,
    desc: []const u8,
    creator: []const u8,
    config: []const u8 = &.{},
    color: u8 = 0,
    visibility: Visibility = .private,
    rating: Rating = .{},
};

/// The user's owned algorithms: the records + the one blob their spans point into.
/// The shell owns exactly one of these, persists it, and hands it to the pure
/// resolvers (data-in, like the feed `Store`). A7.2: cold container — one per
/// session; its CONTENTS are the guarded records.
pub const Library = struct {
    blob: std.ArrayListUnmanaged(u8) = .empty,
    records: std.ArrayListUnmanaged(AlgoRecord) = .empty,

    pub fn deinit(self: *Library, gpa: Allocator) void {
        self.blob.deinit(gpa);
        self.records.deinit(gpa);
        self.* = undefined;
    }

    /// Intern a string into the blob, returning its span.
    fn intern(self: *Library, gpa: Allocator, s: []const u8) Allocator.Error!Span {
        const off: u32 = @intCast(self.blob.items.len);
        try self.blob.appendSlice(gpa, s);
        return .{ .off = off, .len = @intCast(s.len) };
    }

    /// Slice a span out of the blob (borrows; valid until the next mutating call).
    pub fn slice(self: *const Library, s: Span) []const u8 {
        return self.blob.items[s.off..][0..s.len];
    }

    /// Add an owned algorithm (created or downloaded). If a record with the same id
    /// already exists it is left untouched and its index returned (adopting the same
    /// algorithm twice is idempotent, not a duplicate — E4). Otherwise the strings +
    /// config are copied into the blob and a new record is appended.
    pub fn add(self: *Library, gpa: Allocator, a: NewAlgo) Allocator.Error!u32 {
        if (self.indexOf(a.id)) |i| return i;
        const rec: AlgoRecord = .{
            .id = try self.intern(gpa, a.id),
            .name = try self.intern(gpa, a.name),
            .ranks = try self.intern(gpa, a.ranks),
            .desc = try self.intern(gpa, a.desc),
            .creator = try self.intern(gpa, a.creator),
            .config = try self.intern(gpa, a.config),
            .color = a.color,
            .visibility = a.visibility,
            .rating = a.rating,
        };
        const idx: u32 = @intCast(self.records.items.len);
        try self.records.append(gpa, rec);
        return idx;
    }

    /// The record index for an id, or null (E4: absence is ordinary data).
    pub fn indexOf(self: *const Library, id: []const u8) ?u32 {
        for (self.records.items, 0..) |r, i| {
            if (std.mem.eql(u8, self.slice(r.id), id)) return @intCast(i);
        }
        return null;
    }

    /// The record for an id, or null.
    pub fn findById(self: *const Library, id: []const u8) ?AlgoRecord {
        const i = self.indexOf(id) orelse return null;
        return self.records.items[i];
    }

    /// The serialized config bytes for a record (empty ⇒ the no-scoring path).
    pub fn configBytes(self: *const Library, r: AlgoRecord) []const u8 {
        return self.slice(r.config);
    }

    /// Fold a new star rating (1..5, clamped) into a record's aggregate. A no-op on
    /// an unknown id or an out-of-range star. Returns the new average, or 0.
    pub fn rate(self: *Library, id: []const u8, stars: u8) f32 {
        const i = self.indexOf(id) orelse return 0;
        const s: u32 = @min(@max(stars, 1), 5);
        self.records.items[i].rating.sum += s;
        self.records.items[i].rating.count += 1;
        return ratingAverage(self.records.items[i].rating);
    }
};

// ---------------------------------------------------------------------------
// Persistence — a plain length-prefixed binary form (the shell writes it to disk).
// Deserialize is TOTAL on hostile/corrupt bytes: it returns whatever it parsed
// cleanly and drops any record whose spans fall outside the blob (E4, never a
// crash / OOB) — the same "bad data is ordinary data" posture as the config parse.
// ---------------------------------------------------------------------------

const magic = "ZALB"; // Zat4 ALgorithm-library Blob
const ser_version: u8 = 1;

fn putU32(gpa: Allocator, out: *std.ArrayListUnmanaged(u8), v: u32) Allocator.Error!void {
    try out.appendSlice(gpa, &std.mem.toBytes(v));
}

/// Serialize the library to bytes (caller owns them). Allocates in `gpa`.
pub fn serialize(gpa: Allocator, lib: *const Library) Allocator.Error![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, magic);
    try out.append(gpa, ser_version);
    try putU32(gpa, &out, @intCast(lib.blob.items.len));
    try out.appendSlice(gpa, lib.blob.items);
    try putU32(gpa, &out, @intCast(lib.records.items.len));
    for (lib.records.items) |r| {
        inline for (.{ r.id, r.name, r.ranks, r.desc, r.creator, r.config }) |s| {
            try putU32(gpa, &out, s.off);
            try putU32(gpa, &out, s.len);
        }
        try out.append(gpa, r.color);
        try out.append(gpa, @intFromEnum(r.visibility));
        try putU32(gpa, &out, r.rating.sum);
        try putU32(gpa, &out, r.rating.count);
    }
    return out.toOwnedSlice(gpa);
}

// A7.2: cold struct, size guard waived — a transient parse cursor, one per
// `deserialize` call, never held in a collection or a hot loop.
const Reader = struct {
    b: []const u8,
    i: usize = 0,
    fn readU32(self: *Reader) ?u32 {
        if (self.i + 4 > self.b.len) return null;
        const v = std.mem.readInt(u32, self.b[self.i..][0..4], .little);
        self.i += 4;
        return v;
    }
    fn byte(self: *Reader) ?u8 {
        if (self.i >= self.b.len) return null;
        defer self.i += 1;
        return self.b[self.i];
    }
    fn take(self: *Reader, n: usize) ?[]const u8 {
        if (self.i + n > self.b.len) return null;
        defer self.i += n;
        return self.b[self.i..][0..n];
    }
};

/// Parse a library from bytes (TOTAL — bad data ⇒ an empty or partial library, never
/// a crash). Allocates in `gpa`; caller owns the returned library.
pub fn deserialize(gpa: Allocator, bytes: []const u8) Allocator.Error!Library {
    var lib: Library = .{};
    errdefer lib.deinit(gpa);
    var r: Reader = .{ .b = bytes };
    const tag = r.take(magic.len) orelse return lib;
    if (!std.mem.eql(u8, tag, magic)) return lib;
    if ((r.byte() orelse return lib) != ser_version) return lib;
    const blob_len = r.readU32() orelse return lib;
    const blob = r.take(blob_len) orelse return lib;
    try lib.blob.appendSlice(gpa, blob);
    const n = r.readU32() orelse return lib;
    var k: u32 = 0;
    while (k < n) : (k += 1) {
        var spans: [6]Span = undefined;
        var ok = true;
        for (&spans) |*s| {
            s.off = r.readU32() orelse return lib;
            s.len = r.readU32() orelse return lib;
            if (@as(usize, s.off) + s.len > lib.blob.items.len) ok = false; // span outside the blob
        }
        const color = r.byte() orelse return lib;
        const vis = r.byte() orelse return lib;
        const sum = r.readU32() orelse return lib;
        const cnt = r.readU32() orelse return lib;
        if (!ok) continue; // drop a record with an out-of-range span (never OOB later)
        try lib.records.append(gpa, .{
            .id = spans[0],       .name = spans[1],    .ranks = spans[2],
            .desc = spans[3],     .creator = spans[4], .config = spans[5],
            .color = color,       .visibility = @enumFromInt(@min(vis, 1)),
            .rating = .{ .sum = sum, .count = cnt },
        });
    }
    return lib;
}

// ---------------------------------------------------------------------------
// Tests — pure, leak-checked (C6).
// ---------------------------------------------------------------------------

const t = std.testing;

test "guards + rating average" {
    try t.expectEqual(@as(usize, 60), @sizeOf(AlgoRecord));
    try t.expectEqual(@as(usize, 8), @sizeOf(Rating));
    try t.expectEqual(@as(f32, 0), ratingAverage(.{}));
    try t.expectEqual(@as(f32, 4.5), ratingAverage(.{ .sum = 9, .count = 2 }));
}

test "library: add, resolve, config bytes, idempotent adopt" {
    var lib: Library = .{};
    defer lib.deinit(t.allocator);

    const first = try lib.add(t.allocator, .{
        .id = "user:1",
        .name = "My Calm Feed",
        .ranks = "low-velocity first",
        .desc = "Down-ranks pile-ons.",
        .creator = "you",
        .config = "{\"version\":1}",
        .color = 7,
        .visibility = .private,
    });
    try t.expectEqual(@as(u32, 0), first);

    // Resolve it back — every field survives, config bytes intact.
    const r = lib.findById("user:1").?;
    try t.expectEqualStrings("My Calm Feed", lib.slice(r.name));
    try t.expectEqualStrings("you", lib.slice(r.creator));
    try t.expectEqualStrings("{\"version\":1}", lib.configBytes(r));
    try t.expectEqual(@as(u8, 7), r.color);
    try t.expectEqual(Visibility.private, r.visibility);

    // Adopting the same id again is idempotent — same index, no duplicate.
    const again = try lib.add(t.allocator, .{ .id = "user:1", .name = "dup", .ranks = "", .desc = "", .creator = "" });
    try t.expectEqual(@as(u32, 0), again);
    try t.expectEqual(@as(usize, 1), lib.records.items.len);

    // A downloaded public algorithm is a second record.
    _ = try lib.add(t.allocator, .{ .id = "cid:abc", .name = "Desh Sports", .ranks = "sports", .desc = "", .creator = "@desh.zat", .visibility = .public });
    try t.expectEqual(@as(usize, 2), lib.records.items.len);
    try t.expect(lib.findById("cid:xyz") == null); // unknown id
}

test "library: serialize/deserialize round-trips; corrupt bytes are total (empty)" {
    var lib: Library = .{};
    defer lib.deinit(t.allocator);
    _ = try lib.add(t.allocator, .{ .id = "user:1", .name = "Mine", .ranks = "engagement", .desc = "d", .creator = "you", .config = "{\"v\":1}", .color = 5, .visibility = .private, .rating = .{ .sum = 8, .count = 2 } });
    _ = try lib.add(t.allocator, .{ .id = "cid:a", .name = "Desh", .ranks = "sports", .desc = "", .creator = "@desh", .visibility = .public });

    const bytes = try serialize(t.allocator, &lib);
    defer t.allocator.free(bytes);
    var back = try deserialize(t.allocator, bytes);
    defer back.deinit(t.allocator);
    try t.expectEqual(@as(usize, 2), back.records.items.len);
    const r0 = back.findById("user:1").?;
    try t.expectEqualStrings("Mine", back.slice(r0.name));
    try t.expectEqualStrings("{\"v\":1}", back.configBytes(r0));
    try t.expectEqual(@as(u8, 5), r0.color);
    try t.expectEqual(@as(u32, 8), r0.rating.sum);
    try t.expectEqual(Visibility.public, back.findById("cid:a").?.visibility);

    // Corrupt / truncated / empty input is an empty library, never a crash.
    var e1 = try deserialize(t.allocator, "");
    e1.deinit(t.allocator);
    var e2 = try deserialize(t.allocator, "ZALBnonsense");
    e2.deinit(t.allocator);
    var e3 = try deserialize(t.allocator, bytes[0 .. bytes.len - 5]); // truncated tail
    e3.deinit(t.allocator);
}

test "library: ratings fold in and clamp" {
    var lib: Library = .{};
    defer lib.deinit(t.allocator);
    _ = try lib.add(t.allocator, .{ .id = "cid:a", .name = "A", .ranks = "", .desc = "", .creator = "@x", .visibility = .public });
    _ = lib.rate("cid:a", 5);
    _ = lib.rate("cid:a", 9); // clamps to 5
    const avg = lib.rate("cid:a", 2); // (5 + 5 + 2) / 3 = 4.0
    try t.expectEqual(@as(f32, 4.0), avg);
    try t.expectEqual(@as(f32, 0), lib.rate("cid:missing", 5)); // unknown id ⇒ no-op
}
