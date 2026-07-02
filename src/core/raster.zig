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

//! B1 classification: CORE (pure). The rasterizer — a flat draw list
//! plus glyph coverage becomes one ARGB framebuffer (PHASE5_GUI_ROADMAP
//! §2). This module hides the decision "how a draw list becomes pixels":
//! software blending today; if a GPU backend ever appears it slots in
//! behind this same interface (D1/D3).
//!
//! This module defines the draw-list vocabulary it can paint (the same
//! way core/x11.zig defines the requests the window can send); layout
//! PRODUCES that vocabulary, this module CONSUMES it, and the items
//! never cross any other boundary (A5 — an index into the list, and the
//! items themselves, stay between layout and raster; the shell holds
//! the list only as opaque frame transport, B5/D3).
//!
//! Pure in the B2 sense: same draw list ⇒ same pixels. No I/O, no clock,
//! no styles, no cells — it does not import tui and never learns what a
//! Surface is. The framebuffer is the hot data and it is already the
//! ideal shape: one contiguous []u32, row-major (A3 in spirit; there is
//! nothing to SoA).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const text = @import("text.zig");

/// A7.2: cold struct, size guard waived — one per window, never in a
/// collection. Its CONTENTS (pixels) are the hot array.
pub const Framebuffer = struct {
    width: u32 = 0,
    height: u32 = 0,
    /// 0xAARRGGBB, row-major, length = width * height. Caller-owned (C1).
    pixels: []u32 = &.{},
};

/// One terminal-grade cell glyph: position plus colors already resolved
/// by layout. Painted from the embedded strike, opaque fg-or-bg — the
/// fallback screens and the golden tests ride this exact path. HOT →
/// A7 guard mandatory.
pub const CellItem = struct {
    x: u16,
    y: u16,
    codepoint: u32,
    fg: u32,
    bg: u32,

    comptime {
        // Budget: 2+2 (position) + 4 (codepoint) + 4+4 (colors) = 16
        // bytes, exact, no padding. Raising this requires an A7.1
        // justification here.
        assert(@sizeOf(CellItem) == 16);
    }
};

/// One proportional, antialiased glyph: pen position + baseline,
/// blended over whatever is already beneath it. Coordinates are SIGNED
/// — scrolling legitimately places the topmost partial card above the
/// viewport; the painter clips. HOT → A7.
pub const TextItem = struct {
    x: i16,
    baseline: i16,
    codepoint: u32,
    color: u32,
    px: u16,
    weight: u8, // @intFromEnum(text.Weight)
    _pad: u8 = 0, // A6: explicit

    comptime {
        // Budget: 2+2 + 4 + 4 + 2+1+1 = 16 bytes, exact (A7).
        assert(@sizeOf(TextItem) == 16);
    }
};

/// One filled rectangle, optionally rounded, with an alpha channel —
/// alpha < 0xFF blends over the pixels beneath (hover tints, pills).
/// HOT → A7.
pub const RectItem = struct {
    x: i16,
    y: i16,
    w: u16,
    h: u16,
    /// 0xAARRGGBB; AA respected.
    color: u32,
    radius: u8,
    _pad: [3]u8 = @splat(0), // A6: explicit

    comptime {
        // Budget: 2+2+2+2 + 4 + 1 + 3 pad = 16 bytes, exact (A7).
        assert(@sizeOf(RectItem) == 16);
    }
};

/// One straight stroke between two signed points, alpha-blended, with a
/// square pen of `thickness` px — the primitive vector icons (reply,
/// repost, heart) are built from. HOT → A7.
pub const LineItem = struct {
    x0: i16,
    y0: i16,
    x1: i16,
    y1: i16,
    color: u32,
    thickness: u8,
    _pad: [3]u8 = @splat(0), // A6: explicit

    comptime {
        // Budget: 2+2+2+2 + 4 + 1 + 3 pad = 16 bytes, exact (A7).
        assert(@sizeOf(LineItem) == 16);
    }
};

/// One solid triangle, alpha-blended — the speech-bubble tail's primitive
/// (Zat Chat), available to any surface that needs a pointed shape the
/// rect/line vocabulary can't make. HOT → A7.
pub const TriItem = struct {
    x0: i16,
    y0: i16,
    x1: i16,
    y1: i16,
    x2: i16,
    y2: i16,
    /// 0xAARRGGBB; AA respected.
    color: u32,

    comptime {
        // Budget: 6×2 + 4 = 16 bytes, exact (A7) — the vocabulary's
        // common payload size.
        assert(@sizeOf(TriItem) == 16);
    }
};

/// The paint vocabulary. Each variant is guarded above; the union's
/// bare payload is their common 16 bytes, the tag rides its own SoA
/// array (MultiArrayList splits tagged unions exactly this way).
pub const DrawItem = union(enum) {
    cell: CellItem,
    text: TextItem,
    rect: RectItem,
    line: LineItem,
    tri: TriItem,

    comptime {
        // HOT (thousands per frame, stored in DrawList). Each variant is a
        // guarded 16 bytes; the union adds the active-variant tag, padded up
        // to the payload's 4-byte alignment → 20. An exact guard so a new
        // variant with a WIDENED payload fails the build (A7; `tri` joined
        // at the same 16 — the guard held). NOTE the bulk cost is lower
        // than this: DrawList is a MultiArrayList, which stores the 1-byte
        // tag and the 16-byte payload in SEPARATE arrays.
        assert(@sizeOf(DrawItem) == 20);
    }
};

/// The frame's draw list: struct-of-arrays (tags / payloads) of
/// DrawItem (A3). Owned by the shell as opaque transport (cleared and
/// refilled each frame by layout, painted here), but only layout and
/// raster ever see inside.
pub const DrawList = std.MultiArrayList(DrawItem);

pub fn resize(gpa: Allocator, fb: *Framebuffer, width: u32, height: u32, clear: u32) error{OutOfMemory}!void {
    const count: usize = @as(usize, width) * height;
    if (fb.pixels.len != count) {
        gpa.free(fb.pixels);
        fb.pixels = try gpa.alloc(u32, count);
    }
    fb.width = width;
    fb.height = height;
    @memset(fb.pixels, clear);
}

pub fn deinit(gpa: Allocator, fb: *Framebuffer) void {
    gpa.free(fb.pixels);
    fb.* = undefined;
}

// ---------------------------------------------------------------------------
// Paint
// ---------------------------------------------------------------------------

/// Paint the whole frame: clear to `clear`, then draw every item in
/// list order (later items over earlier — layout's z-order IS the list
/// order). Deterministic: same list + same engine cache state ⇒ same
/// pixels; the only mutation is the engine's memoization (the PoW-
/// verify allocator caveat, in glyph form), the only error a cache
/// fill's OOM (E3). `engine` may be null for cell-only lists (the
/// fallback screens); text items then degrade to nothing drawn (E4).
pub fn paint(
    gpa: Allocator,
    engine: ?*text.Engine,
    list: DrawList.Slice,
    fb: *Framebuffer,
    clear: u32,
) error{OutOfMemory}!void {
    @memset(fb.pixels, clear);
    const tags = list.items(.tags);
    const data = list.items(.data);
    for (tags, data) |tag, bare| switch (tag) {
        .cell => {
            const it = bare.cell;
            drawCell(fb, it.x, it.y, it.codepoint, it.fg, it.bg);
        },
        .rect => drawRect(fb, bare.rect),
        .line => drawLine(fb, bare.line),
        .tri => drawTri(fb, bare.tri),
        .text => if (engine) |e| {
            const it = bare.text;
            const g = try text.glyph(gpa, e, @enumFromInt(it.weight), it.codepoint, it.px);
            drawCoverage(fb, it.x + g.bear_x, it.baseline + g.bear_y, g, it.color);
        },
    };
}

/// Blend an alpha-coverage bitmap over the framebuffer at a signed
/// position, clipping every edge. This is the antialiasing path the
/// carve built the blend arm for — now live.
fn drawCoverage(fb: *Framebuffer, x: i32, y: i32, g: text.GlyphRaster, color: u32) void {
    var row: i32 = 0;
    while (row < g.h) : (row += 1) {
        const py = y + row;
        if (py < 0 or py >= fb.height) continue;
        var col: i32 = 0;
        while (col < g.w) : (col += 1) {
            const px = x + col;
            if (px < 0 or px >= fb.width) continue;
            const a = g.alpha[@as(usize, @intCast(row)) * g.w + @as(usize, @intCast(col))];
            if (a == 0) continue;
            const at = @as(usize, @intCast(py)) * fb.width + @as(usize, @intCast(px));
            fb.pixels[at] = if (a == 255) (color | 0xFF000000) else blend(color, fb.pixels[at], a);
        }
    }
}

/// Bresenham stroke with a square pen, alpha-blended and clipped. Built
/// for small UI icons, not long fills (those are RectItems).
fn drawLine(fb: *Framebuffer, it: LineItem) void {
    var x0: i32 = it.x0;
    var y0: i32 = it.y0;
    const x1: i32 = it.x1;
    const y1: i32 = it.y1;
    const dx: i32 = if (x1 > x0) x1 - x0 else x0 - x1;
    const dy: i32 = if (y1 > y0) -(y1 - y0) else -(y0 - y1);
    const sx: i32 = if (x0 < x1) 1 else -1;
    const sy: i32 = if (y0 < y1) 1 else -1;
    var err: i32 = dx + dy;
    const t: i32 = @max(1, @as(i32, it.thickness));
    const half: i32 = @divTrunc(t, 2);
    while (true) {
        penDot(fb, x0, y0, half, it.color);
        if (x0 == x1 and y0 == y1) break;
        const e2: i32 = 2 * err;
        if (e2 >= dy) {
            err += dy;
            x0 += sx;
        }
        if (e2 <= dx) {
            err += dx;
            y0 += sy;
        }
    }
}

fn penDot(fb: *Framebuffer, cx: i32, cy: i32, half: i32, color: u32) void {
    const a: u32 = color >> 24;
    if (a == 0) return;
    var oy: i32 = -half;
    while (oy <= half) : (oy += 1) {
        var ox: i32 = -half;
        while (ox <= half) : (ox += 1) {
            const px = cx + ox;
            const py = cy + oy;
            if (px < 0 or py < 0 or px >= fb.width or py >= fb.height) continue;
            const at = @as(usize, @intCast(py)) * fb.width + @as(usize, @intCast(px));
            fb.pixels[at] = if (a == 0xFF) (color | 0xFF000000) else blend(color, fb.pixels[at], a);
        }
    }
}

/// Filled, optionally-rounded rectangle with source alpha, clipped to
/// the buffer. Corner rounding is the quarter-circle test on the four
/// corner boxes — exact enough at UI radii, branch-free elsewhere.
fn drawRect(fb: *Framebuffer, r: RectItem) void {
    if (r.w == 0 or r.h == 0) return;
    const src_a: u32 = r.color >> 24;
    if (src_a == 0) return;
    const rad: i32 = @min(@as(i32, r.radius), @min(r.w / 2, r.h / 2));
    const rad2: i32 = rad * rad;
    var row: i32 = 0;
    while (row < r.h) : (row += 1) {
        const py = @as(i32, r.y) + row;
        if (py < 0 or py >= fb.height) continue;
        // Horizontal inset for this row inside the rounded corners.
        var inset: i32 = 0;
        if (rad > 0) {
            const dy: i32 = if (row < rad) rad - row - 1 else if (row >= @as(i32, r.h) - rad) row - (@as(i32, r.h) - rad) else -1;
            if (dy >= 0) {
                // Largest dx with dx² + dy² ≤ r² (integer circle edge).
                var dx: i32 = rad;
                while (dx > 0 and dx * dx + dy * dy > rad2) dx -= 1;
                inset = rad - dx;
            }
        }
        var col: i32 = inset;
        const col_end: i32 = @as(i32, r.w) - inset;
        while (col < col_end) : (col += 1) {
            const px = @as(i32, r.x) + col;
            if (px < 0 or px >= fb.width) continue;
            const at = @as(usize, @intCast(py)) * fb.width + @as(usize, @intCast(px));
            fb.pixels[at] = if (src_a == 255) r.color else blend(r.color, fb.pixels[at], src_a);
        }
    }
}

/// Solid triangle fill: integer edge functions over the bounding box —
/// a pixel is in when all three half-plane tests agree with the winding
/// (either winding accepted). Small shapes by design (a bubble tail is
/// ~16px); the bounding-box loop is exact and cheap at that size.
fn drawTri(fb: *Framebuffer, t: TriItem) void {
    const src_a: u32 = t.color >> 24;
    if (src_a == 0) return;
    const x0: i32 = t.x0;
    const y0: i32 = t.y0;
    const x1: i32 = t.x1;
    const y1: i32 = t.y1;
    const x2: i32 = t.x2;
    const y2: i32 = t.y2;
    const area = (x1 - x0) * (y2 - y0) - (y1 - y0) * (x2 - x0);
    if (area == 0) return;
    const fbw: i32 = @intCast(fb.width);
    const fbh: i32 = @intCast(fb.height);
    const minx = @max(0, @min(x0, @min(x1, x2)));
    const maxx = @min(fbw - 1, @max(x0, @max(x1, x2)));
    const miny = @max(0, @min(y0, @min(y1, y2)));
    const maxy = @min(fbh - 1, @max(y0, @max(y1, y2)));
    var py = miny;
    while (py <= maxy) : (py += 1) {
        var px = minx;
        while (px <= maxx) : (px += 1) {
            const w0 = (x1 - x0) * (py - y0) - (y1 - y0) * (px - x0);
            const w1 = (x2 - x1) * (py - y1) - (y2 - y1) * (px - x1);
            const w2 = (x0 - x2) * (py - y2) - (y0 - y2) * (px - x2);
            const in = if (area > 0)
                w0 >= 0 and w1 >= 0 and w2 >= 0
            else
                w0 <= 0 and w1 <= 0 and w2 <= 0;
            if (!in) continue;
            const at = @as(usize, @intCast(py)) * fb.width + @as(usize, @intCast(px));
            fb.pixels[at] = if (src_a == 255) t.color else blend(t.color, fb.pixels[at], src_a);
        }
    }
}

fn drawCell(fb: *Framebuffer, px: u32, py: u32, codepoint: u32, fg: u32, bg: u32) void {
    const cov = text.coverage(codepoint, text.cell_h);
    if (px + cov.w > fb.width or py + cov.h > fb.height) return;
    var row: u32 = 0;
    while (row < cov.h) : (row += 1) {
        const base = @as(usize, py + row) * fb.width + px;
        const src = cov.alpha[@as(usize, row) * cov.w ..][0..cov.w];
        for (src, 0..) |a, col| {
            // Exact at the endpoints by construction: a 1-bit strike
            // produces only 0 and 255, so Cut 5.0 output is pixel-
            // identical to the pre-carve renderer. The blend arm is the
            // antialiasing seam Cut 5.5 lights up — already correct,
            // currently unreachable.
            fb.pixels[base + col] = switch (a) {
                0 => bg,
                255 => fg,
                else => blend(fg, bg, a),
            };
        }
    }
}

/// Integer alpha blend, exact at both endpoints: a=0 ⇒ bg, a=255 ⇒ fg.
fn blend(fg: u32, bg: u32, a: u32) u32 {
    const inv = 255 - a;
    var out: u32 = 0xFF000000;
    inline for ([_]u5{ 16, 8, 0 }) |shift| {
        const f = (fg >> shift) & 0xFF;
        const b = (bg >> shift) & 0xFF;
        const c = (f * a + b * inv + 127) / 255;
        out |= c << shift;
    }
    return out;
}

/// The inclusive band of rows that changed between two frames. A7.2: cold,
/// waived — a transient result returned by value, one per blit, never held
/// in a collection.
pub const Band = struct {
    first: u32,
    last: u32,
};

/// Pure: the inclusive row range where `new` differs from `old` — both
/// row-major ARGB, `w` wide and `h` tall — or null if the two frames are
/// pixel-identical. Scans top-down for the first changed row, then bottom-up
/// for the last, so the band is exactly the rows that moved and the rows
/// BETWEEN the change and each edge are never compared. No I/O, no
/// allocation: this is just the decision the shell's blit acts on, kept here
/// in the pure core so a frame's changed region is checkable WITHOUT an X
/// server (the X-window session's hard-won lesson — make the thing
/// observable and test it strictly). B2.
///
/// Cost, measured (bench "blit damage", 1280x800): a CHANGED frame scans
/// from each edge inward to the change (~0.34 ms when the change sits near
/// the middle — most rows still get compared); an UNCHANGED frame must
/// compare every row to conclude "no change" (~0.36 ms). Both are ~2% of a
/// 60 fps budget and, crucially, are cheap LOCAL memcmp that never blocks —
/// which is the whole point: they replace a full-frame PutImage (megabytes
/// over the X socket, and a write that BLOCKS the loop when the socket backs
/// up). raster.paint rewrites the whole framebuffer each frame, but the
/// resulting PIXELS barely move — only the animating region (the heart, a
/// few rows) actually changes — so sending just this band turns ~4 MB/frame
/// into a few hundred KB and removes the blocking write that stuttered the
/// animation and let clicks queue behind it. (G1: the bench carries the
/// number; G3: the scan is trivial against the socket I/O it saves.)
pub fn damageBand(old: []const u32, new: []const u32, w: u32, h: u32) ?Band {
    assert(old.len == new.len);
    if (w == 0 or h == 0) return null;
    var first: u32 = 0;
    while (first < h) : (first += 1) {
        const a = new[first * w ..][0..w];
        const b = old[first * w ..][0..w];
        if (!std.mem.eql(u32, a, b)) break;
    }
    if (first == h) return null; // identical — the caller skips the blit

    var last: u32 = h - 1;
    while (last > first) : (last -= 1) {
        const a = new[last * w ..][0..w];
        const b = old[last * w ..][0..w];
        if (!std.mem.eql(u32, a, b)) break;
    }
    return .{ .first = first, .last = last };
}

// ---------------------------------------------------------------------------
// Tests (B2, C6)
// ---------------------------------------------------------------------------

const testing = std.testing;

test "damageBand: identical frames report no damage" {
    const w: u32 = 8;
    const h: u32 = 6;
    var a = [_]u32{0xFF101014} ** (8 * 6);
    const b = [_]u32{0xFF101014} ** (8 * 6);
    try testing.expectEqual(@as(?Band, null), damageBand(&a, &b, w, h));
    // A no-op write must also be reported clean (defends the skip path).
    a[0] = 0xFF101014;
    try testing.expectEqual(@as(?Band, null), damageBand(&a, &b, w, h));
}

test "damageBand: a single changed row is the whole band" {
    const w: u32 = 8;
    const h: u32 = 6;
    const old = [_]u32{0} ** (8 * 6);
    var new = [_]u32{0} ** (8 * 6);
    new[3 * w + 2] = 0xFFFFFFFF; // one pixel on row 3
    const band = damageBand(&old, &new, w, h) orelse return error.ExpectedDamage;
    try testing.expectEqual(@as(u32, 3), band.first);
    try testing.expectEqual(@as(u32, 3), band.last);
}

test "damageBand: spans from the first to the last changed row only" {
    const w: u32 = 8;
    const h: u32 = 10;
    const old = [_]u32{0} ** (8 * 10);
    var new = [_]u32{0} ** (8 * 10);
    new[2 * w + 0] = 1; // row 2
    new[7 * w + 5] = 1; // row 7 — rows 0,1 and 8,9 unchanged
    const band = damageBand(&old, &new, w, h) orelse return error.ExpectedDamage;
    try testing.expectEqual(@as(u32, 2), band.first);
    try testing.expectEqual(@as(u32, 7), band.last);
    // The band is the rows actually touched, not the whole frame.
    try testing.expect(band.first > 0 and band.last < h - 1);
}

test "paint: a glyph lands pixel-exact against the strike itself" {
    const gpa = testing.allocator; // C6
    var fb: Framebuffer = .{};
    defer deinit(gpa, &fb);
    const clear: u32 = 0xFF101014;
    try resize(gpa, &fb, 16, 16, clear);

    var list: DrawList = .empty;
    defer list.deinit(gpa);
    const fg: u32 = 0xFF8ABEB7;
    try list.append(gpa, .{ .cell = .{ .x = 0, .y = 0, .codepoint = 'A', .fg = fg, .bg = clear } });
    try paint(gpa, null, list.slice(), &fb, clear);

    const cov = text.coverage('A', 16);
    var row: u32 = 0;
    while (row < cov.h) : (row += 1) {
        var col: u32 = 0;
        while (col < cov.w) : (col += 1) {
            const a = cov.alpha[row * cov.w + col];
            const pixel = fb.pixels[row * fb.width + col];
            try testing.expectEqual(if (a == 255) fg else clear, pixel);
        }
    }
    // The untouched cell to the right stays background.
    try testing.expectEqual(clear, fb.pixels[8]);
}

test "paint: out-of-bounds items are skipped whole, never written" {
    const gpa = testing.allocator;
    var fb: Framebuffer = .{};
    defer deinit(gpa, &fb);
    try resize(gpa, &fb, 8, 16, 0);

    var list: DrawList = .empty;
    defer list.deinit(gpa);
    // One column past the right edge: 8 + 8 > 8.
    try list.append(gpa, .{ .cell = .{ .x = 1, .y = 0, .codepoint = 'X', .fg = 0xFFFFFFFF, .bg = 0 } });
    try paint(gpa, null, list.slice(), &fb, 0);
    for (fb.pixels) |p| try testing.expectEqual(@as(u32, 0), p);
}

test "tri: fills inside, leaves outside, clips the frame edge, blends alpha" {
    const gpa = testing.allocator;
    var fb: Framebuffer = .{};
    defer deinit(gpa, &fb);
    try resize(gpa, &fb, 32, 32, 0xFF000000);

    var list: DrawList = .empty;
    defer list.deinit(gpa);
    // A right triangle: (4,4) (20,4) (4,20) — both windings must fill.
    try list.append(gpa, .{ .tri = .{ .x0 = 4, .y0 = 4, .x1 = 20, .y1 = 4, .x2 = 4, .y2 = 20, .color = 0xFFFF0000 } });
    // A second, half-alpha, poking past the right edge: clipped, not wrapped.
    try list.append(gpa, .{ .tri = .{ .x0 = 28, .y0 = 24, .x1 = 40, .y1 = 24, .x2 = 28, .y2 = 30, .color = 0x80FFFFFF } });
    try paint(gpa, null, list.slice(), &fb, 0xFF000000);

    const at = struct {
        fn px(f: *const Framebuffer, x: usize, y: usize) u32 {
            return f.pixels[y * f.width + x];
        }
    };
    try testing.expectEqual(@as(u32, 0xFFFF0000), at.px(&fb, 6, 6)); // inside
    try testing.expectEqual(@as(u32, 0xFF000000), at.px(&fb, 19, 19)); // outside the hypotenuse
    try testing.expect(at.px(&fb, 29, 25) != 0xFF000000); // clipped tri still fills in-frame
    // Half-alpha blended over black: grey, not white, not black.
    const g = at.px(&fb, 29, 25) & 0xFF;
    try testing.expect(g > 0x40 and g < 0xC0);
    // Degenerate (zero area) draws nothing.
    var list2: DrawList = .empty;
    defer list2.deinit(gpa);
    try list2.append(gpa, .{ .tri = .{ .x0 = 2, .y0 = 2, .x1 = 2, .y1 = 2, .x2 = 2, .y2 = 2, .color = 0xFFFFFFFF } });
    try paint(gpa, null, list2.slice(), &fb, 0xFF000000);
    for (fb.pixels) |p| try testing.expectEqual(@as(u32, 0xFF000000), p);
}

test "blend: exact at both endpoints, monotone between" {
    const fg: u32 = 0xFFC8C8C8;
    const bg: u32 = 0xFF101014;
    try testing.expectEqual(bg, blend(fg, bg, 0));
    try testing.expectEqual(fg, blend(fg, bg, 255));
    const mid = blend(fg, bg, 128);
    const mid_r = (mid >> 16) & 0xFF;
    try testing.expect(mid_r > 0x10 and mid_r < 0xC8);
}

test "rect: rounded corners stay inside, alpha blends, clipping holds" {
    const gpa = testing.allocator;
    var fb: Framebuffer = .{};
    defer deinit(gpa, &fb);
    try resize(gpa, &fb, 32, 32, 0xFF000000);

    var list: DrawList = .empty;
    defer list.deinit(gpa);
    // Opaque rounded card…
    try list.append(gpa, .{ .rect = .{ .x = 2, .y = 2, .w = 20, .h = 16, .color = 0xFF202020, .radius = 5 } });
    // …with a half-alpha tint over part of it, and one rect hanging off
    // the left edge to prove the clip.
    try list.append(gpa, .{ .rect = .{ .x = 4, .y = 4, .w = 8, .h = 8, .color = 0x80FFFFFF, .radius = 0 } });
    try list.append(gpa, .{ .rect = .{ .x = -5, .y = 30, .w = 10, .h = 4, .color = 0xFF445566, .radius = 0 } });
    try paint(gpa, null, list.slice(), &fb, 0xFF000000);

    // Corner pixel of the rounded card is outside the radius: untouched.
    try testing.expectEqual(@as(u32, 0xFF000000), fb.pixels[2 * 32 + 2]);
    // Card center is the card color.
    try testing.expectEqual(@as(u32, 0xFF202020), fb.pixels[10 * 32 + 12]);
    // Tinted region is brighter than the card but not white.
    const tinted = fb.pixels[6 * 32 + 6] & 0xFF;
    try testing.expect(tinted > 0x20 and tinted < 0xFF);
    // The off-edge rect painted only its on-screen half (x 0..4).
    try testing.expectEqual(@as(u32, 0xFF445566), fb.pixels[30 * 32 + 0]);
    try testing.expectEqual(@as(u32, 0xFF000000), fb.pixels[30 * 32 + 6]);
}

test "text item: antialiased glyph blends over the background" {
    const gpa = testing.allocator;
    var e = try text.initEngine();
    defer text.deinitEngine(gpa, &e);
    var fb: Framebuffer = .{};
    defer deinit(gpa, &fb);
    try resize(gpa, &fb, 40, 40, 0xFF101014);

    var list: DrawList = .empty;
    defer list.deinit(gpa);
    try list.append(gpa, .{ .text = .{ .x = 4, .baseline = 24, .codepoint = 'A', .color = 0xFFE6E9EF, .px = 20, .weight = 0 } });
    try paint(gpa, &e, list.slice(), &fb, 0xFF101014);

    var lit: usize = 0;
    var mid: usize = 0;
    for (fb.pixels) |p| {
        const ch = p & 0xFF;
        if (ch > 0x14) lit += 1;
        if (ch > 0x30 and ch < 0xD0) mid += 1; // genuinely blended pixels
    }
    try testing.expect(lit > 10); // the glyph has ink
    try testing.expect(mid > 0); // and antialiased edges, not 1-bit
}
