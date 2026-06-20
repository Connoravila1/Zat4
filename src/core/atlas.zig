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

//! B1 classification: CORE (pure). The glyph atlas: ONE packed alpha
//! bitmap plus a table mapping (weight, codepoint, px) → the rectangle
//! that glyph occupies in it. This is the CPU half of the GPU text path
//! (Phase 6.1): the shell uploads `bitmap` to a single GL texture once,
//! then every TextItem/CellItem becomes a textured quad sampling its
//! rect — instead of the software rasterizer re-blending coverage into
//! the framebuffer per glyph per frame.
//!
//! It hides nothing of GL and imports none of it (D3): the atlas is just
//! a bitmap and a table of rectangles. `text.zig` still owns "how a glyph
//! is produced"; this module only PACKS the coverage it returns. Pure in
//! the B2 sense — same (engine, requests) ⇒ same bitmap and same rects.
//!
//! Packing is a simple shelf/row packer with 1px gutters (insurance
//! against bilinear bleed even though Phase 6.1 samples at native size).
//! The glyph set is bounded — ASCII × a handful of device sizes × two
//! weights — so a single modest texture holds it with room to spare; a
//! genuine overflow is an explicit error (E3), never a silent wrap.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const text = @import("text.zig");

pub const Error = error{AtlasFull} || Allocator.Error;

/// One glyph's place in the atlas: its rectangle in the bitmap plus the
/// pen-relative placement layout already computed against. The GPU adapter
/// draws a quad of size (w,h) at (item.x + bear_x, item.baseline + bear_y),
/// sampling the atlas at (x, y). HOT — one per distinct glyph, read once
/// per glyph instance every frame → A7.
pub const AtlasGlyph = struct {
    x: u16,
    y: u16,
    w: u16,
    h: u16,
    bear_x: i16,
    bear_y: i16,

    comptime {
        // Budget: 4×u16 (rect) + 2×i16 (bearing) = 12 bytes, exact, no
        // padding (all 2-byte fields, 2-byte alignment). Raising this
        // requires an A7.1 justification here.
        assert(@sizeOf(AtlasGlyph) == 12);
    }
};

/// The atlas: one R8 coverage bitmap + the (weight,cp,px)→rect table +
/// the shelf cursor. A7.2: cold struct, size guard waived — exactly one
/// per font engine / window, never held in a collection. Its CONTENTS
/// (the bitmap and the table) are the hot arrays.
pub const Atlas = struct {
    /// R8 alpha coverage, row-major, length = dim*dim. Caller-owned (C1).
    bitmap: []u8 = &.{},
    /// Square edge in pixels (texture is dim×dim).
    dim: u32 = 0,
    /// Shelf packer cursor: current row origin x, the row's top y, and the
    /// tallest glyph placed on the current row.
    pen_x: u32 = 0,
    pen_y: u32 = 0,
    shelf_h: u32 = 0,
    table: std.AutoHashMapUnmanaged(u64, AtlasGlyph) = .empty,
    /// Set whenever the bitmap changes; the shell re-uploads the texture
    /// and clears it. Starts true so the first upload always happens.
    dirty: bool = true,
};

/// Same key scheme text.zig uses for its glyph cache: weight in the top
/// bit, pixel size in the middle, codepoint in the low 32. One stable u64
/// per distinct glyph.
fn keyFor(weight: text.Weight, cp: u32, px: u32) u64 {
    return (@as(u64, @intFromEnum(weight)) << 63) | (@as(u64, px) << 32) | cp;
}

pub fn init(gpa: Allocator, atlas: *Atlas, dim: u32) Allocator.Error!void {
    const bitmap = try gpa.alloc(u8, @as(usize, dim) * dim);
    @memset(bitmap, 0);
    atlas.* = .{ .bitmap = bitmap, .dim = dim };
}

pub fn deinit(gpa: Allocator, atlas: *Atlas) void {
    gpa.free(atlas.bitmap);
    atlas.table.deinit(gpa);
    atlas.* = undefined;
}

/// Ensure the glyph for (weight, cp, px) is in the atlas, returning its
/// rectangle. Cached: a repeat request is a table hit with no rasterizing
/// and no bitmap change. Whitespace and zero-extent glyphs are stored as
/// an empty rect (w=h=0) — a valid, inkless result, never an error (E4).
pub fn ensure(
    gpa: Allocator,
    engine: *text.Engine,
    atlas: *Atlas,
    weight: text.Weight,
    cp: u32,
    px: u32,
) Error!AtlasGlyph {
    const key = keyFor(weight, cp, px);
    const slot = try atlas.table.getOrPut(gpa, key);
    if (slot.found_existing) return slot.value_ptr.*;

    // text.glyph returns a view into the engine pool valid only until the
    // next glyph() call — we consume it (blit) immediately below, before
    // any other glyph request, so it stays valid.
    const g = text.glyph(gpa, engine, weight, cp, px) catch |err| {
        // getOrPut reserved a slot with an undefined value; drop it so the
        // table never holds garbage (C5 in spirit), mirroring text.zig.
        _ = atlas.table.remove(key);
        return err;
    };

    // Inkless glyph: record an empty rect, no packing, no bitmap change.
    if (g.w == 0 or g.h == 0) {
        const empty: AtlasGlyph = .{ .x = 0, .y = 0, .w = 0, .h = 0, .bear_x = g.bear_x, .bear_y = g.bear_y };
        slot.value_ptr.* = empty;
        return empty;
    }

    const gw: u32 = g.w;
    const gh: u32 = g.h;

    // Shelf packing with a 1px gutter. Wrap to a fresh shelf when the row
    // is full; fail explicitly if the atlas cannot hold the glyph (E3).
    if (atlas.pen_x + gw > atlas.dim) {
        atlas.pen_y += atlas.shelf_h + 1;
        atlas.pen_x = 0;
        atlas.shelf_h = 0;
    }
    if (atlas.pen_x + gw > atlas.dim or atlas.pen_y + gh > atlas.dim) {
        _ = atlas.table.remove(key);
        return Error.AtlasFull;
    }

    const ox = atlas.pen_x;
    const oy = atlas.pen_y;
    var row: u32 = 0;
    while (row < gh) : (row += 1) {
        const src = g.alpha[row * gw ..][0..gw];
        const dst_off = (oy + row) * atlas.dim + ox;
        @memcpy(atlas.bitmap[dst_off..][0..gw], src);
    }

    atlas.pen_x += gw + 1;
    if (gh > atlas.shelf_h) atlas.shelf_h = gh;
    atlas.dirty = true;

    const placed: AtlasGlyph = .{
        .x = @intCast(ox),
        .y = @intCast(oy),
        .w = g.w,
        .h = g.h,
        .bear_x = g.bear_x,
        .bear_y = g.bear_y,
    };
    slot.value_ptr.* = placed;
    return placed;
}

// ---------------------------------------------------------------------------
// Tests (B2, C6 — leak-checked)
// ---------------------------------------------------------------------------

const testing = std.testing;

test "atlas: packs glyphs, caches by key, and blits coverage exactly" {
    const gpa = testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);

    var atlas: Atlas = .{};
    try init(gpa, &atlas, 256);
    defer deinit(gpa, &atlas);

    // First 'A' packs and marks the atlas dirty.
    atlas.dirty = false;
    const a1 = try ensure(gpa, &engine, &atlas, .semibold, 'A', 17);
    try testing.expect(a1.w > 0 and a1.h > 0);
    try testing.expect(atlas.dirty);

    // The blitted region must match the engine's coverage byte-for-byte —
    // this is the property the GPU text path relies on for parity.
    const cov = try text.glyph(gpa, &engine, .semibold, 'A', 17);
    var row: u32 = 0;
    while (row < a1.h) : (row += 1) {
        var col: u32 = 0;
        while (col < a1.w) : (col += 1) {
            const in_atlas = atlas.bitmap[(@as(u32, a1.y) + row) * atlas.dim + a1.x + col];
            try testing.expectEqual(cov.alpha[row * a1.w + col], in_atlas);
        }
    }

    // A repeat request is a pure cache hit: same rect, no further packing.
    const pen_before = atlas.pen_x;
    const a2 = try ensure(gpa, &engine, &atlas, .semibold, 'A', 17);
    try testing.expectEqual(a1, a2);
    try testing.expectEqual(pen_before, atlas.pen_x);

    // A different glyph gets a distinct, non-overlapping rect on the row.
    const g = try ensure(gpa, &engine, &atlas, .semibold, 'g', 17);
    try testing.expect(g.x >= a1.x + a1.w); // packed to the right, past the gutter

    // Whitespace is an inkless, empty-rect result — valid, never an error.
    const sp = try ensure(gpa, &engine, &atlas, .regular, ' ', 17);
    try testing.expectEqual(@as(u16, 0), sp.w);
    try testing.expectEqual(@as(u16, 0), sp.h);
}

test "atlas: overflow is an explicit error, not a silent wrap" {
    const gpa = testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);

    // A texture far too small to hold a 40px glyph row forces the packer to
    // run out of vertical room and report it (E3).
    var atlas: Atlas = .{};
    try init(gpa, &atlas, 8);
    defer deinit(gpa, &atlas);

    try testing.expectError(Error.AtlasFull, ensure(gpa, &engine, &atlas, .regular, 'M', 40));
}
