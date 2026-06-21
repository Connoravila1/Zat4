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

//! B1 classification: CORE (pure). The font engine — THE deep module
//! that hides "how glyphs are produced" (D1/D3, PHASE5_GUI_ROADMAP §2/§4).
//! The rest of the app asks one question — coverage for codepoint C at
//! N pixels — and never learns whether the answer came from a bitmap
//! strike, a TrueType rasterizer, or an SDF. Swapping the body is the
//! planned Option A → C → B path; this interface is the part that holds.
//!
//! Cut 5.0 body: the embedded Spleen 8x16 strike (font.zig, the asset),
//! comptime-expanded from 1-bit rows to 8-bit alpha coverage so the
//! interface is ALREADY the antialiasing-shaped one later bodies need.
//! Exactly one strike exists, so every requested size is served by it —
//! the caller draws at the RETURNED geometry, never the requested one
//! (the honest contract for bitmap strikes; integer scaling lands in
//! Cut 5.3 behind this same function).
//!
//! font.zig is private to this module from here on: no other file may
//! import it (D3 — the asset is an implementation detail of the engine).

const std = @import("std");
const assert = std.debug.assert;
const font = @import("font.zig");

/// Glyph geometry of the native strike, exported for the Cut-5.0 shells
/// that still derive cols/rows from pixel size. These become per-frame
/// values from `metrics()` when Cut 5.3 makes size an input; the consts
/// are the bridge, not the destination.
pub const cell_w: u32 = font.glyph_w;
pub const cell_h: u32 = font.glyph_h;

/// One glyph's coverage: alpha per pixel, 0 = fully background,
/// 255 = fully foreground, row-major w×h. A transient VIEW into the
/// comptime strike table (immutable, 'static lifetime) — created per
/// glyph draw, never stored in a collection. Treated hot anyway (A7:
/// when ambiguous, guard it): the loop that consumes it is the hottest
/// in the renderer.
pub const Coverage = struct {
    alpha: []const u8,
    w: u16,
    h: u16,
    advance: u16,

    comptime {
        // Budget: 16 (slice ptr+len) + 3×2 (w,h,advance) + 2 pad = 24
        // bytes, exact. Raising this requires an A7.1 justification here.
        assert(@sizeOf(Coverage) == 24);
    }
};

/// Strike metrics for layout: how big is a cell, how far does the pen
/// advance. Cut 5.0: one answer regardless of the requested size (one
/// strike exists). Cut 5.3 returns scaled metrics from this same call.
/// A7.2: cold struct, size guard waived — returned by value, never held
/// in quantity.
pub const Metrics = struct {
    cell_w: u32,
    cell_h: u32,
};

pub fn metrics(px_h: u32) Metrics {
    _ = px_h; // One strike in Cut 5.0; the parameter is the 5.3 seam.
    return .{ .cell_w = cell_w, .cell_h = cell_h };
}

// ---------------------------------------------------------------------------
// The strike: 1-bit rows expanded to 8-bit coverage, once, at comptime.
// 95 ASCII glyphs + 1 replacement box, 8×16 px each = 12,288 bytes of
// immutable table in the binary — zero runtime work, zero allocation
// (F2: comptime over machinery).
// ---------------------------------------------------------------------------

const glyph_px: usize = @as(usize, font.glyph_w) * font.glyph_h;
const glyph_count = font.bitmaps.len; // 95

const strike16: [glyph_count + 1][glyph_px]u8 = blk: {
    @setEvalBranchQuota(glyph_count * glyph_px * 4);
    var table: [glyph_count + 1][glyph_px]u8 = undefined;
    for (font.bitmaps, 0..) |rows, g| table[g] = expand(rows);
    table[glyph_count] = expand(font.replacement); // fallback box, last slot
    break :blk table;
};

fn expand(rows: [16]u8) [glyph_px]u8 {
    var out: [glyph_px]u8 = undefined;
    for (rows, 0..) |bits, row| {
        for (0..font.glyph_w) |col| {
            const on = (bits >> @intCast(7 - col)) & 1 == 1;
            out[row * font.glyph_w + col] = if (on) 255 else 0;
        }
    }
    return out;
}

/// Pure lookup (B2): same (codepoint, size) ⇒ same coverage. ASCII
/// 32–126 serves its glyph; anything else (wide/emoji/continuation)
/// serves the replacement box — the same honest fallback font.zig has
/// always had, so layout survives unknown text (E4: defined out of
/// existence, never an error).
pub fn coverage(codepoint: u32, px_h: u32) Coverage {
    _ = px_h; // One strike in Cut 5.0; see metrics().
    const index: usize = if (codepoint >= font.first and codepoint <= font.last)
        codepoint - font.first
    else
        glyph_count;
    return .{
        .alpha = &strike16[index],
        .w = @intCast(font.glyph_w),
        .h = @intCast(font.glyph_h),
        .advance = @intCast(font.glyph_w),
    };
}

// ---------------------------------------------------------------------------
// Tests (B2, C6)
// ---------------------------------------------------------------------------

const testing = std.testing;

test "coverage: every strike pixel mirrors the source bitmap exactly" {
    // The expansion is load-bearing for pixel-exactness downstream: a
    // set bit must be 255, a clear bit 0, nothing in between (Cut 5.0
    // has no antialiasing to hide behind).
    var cp: u32 = font.first;
    while (cp <= font.last) : (cp += 1) {
        const cov = coverage(cp, 16);
        try testing.expectEqual(@as(u16, 8), cov.w);
        try testing.expectEqual(@as(u16, 16), cov.h);
        try testing.expectEqual(@as(u16, 8), cov.advance);
        const rows = font.glyph(cp);
        for (0..16) |row| {
            for (0..8) |col| {
                const on = (rows[row] >> @intCast(7 - col)) & 1 == 1;
                const a = cov.alpha[row * 8 + col];
                try testing.expectEqual(@as(u8, if (on) 255 else 0), a);
            }
        }
    }
}

test "coverage: out-of-range codepoints serve the replacement box" {
    for ([_]u32{ 0, 31, 127, 0x4E2D, 0x1F600 }) |cp| {
        const cov = coverage(cp, 16);
        for (0..16) |row| {
            for (0..8) |col| {
                const on = (font.replacement[row] >> @intCast(7 - col)) & 1 == 1;
                try testing.expectEqual(@as(u8, if (on) 255 else 0), cov.alpha[row * 8 + col]);
            }
        }
    }
}

test "metrics: the native strike geometry" {
    const m = metrics(16);
    try testing.expectEqual(@as(u32, 8), m.cell_w);
    try testing.expectEqual(@as(u32, 16), m.cell_h);
}

// ===========================================================================
// THE FONT ENGINE (GUI roadmap Option C, pulled forward by owner
// direction — see PHASE5_GUI_ROADMAP §7 amendment).
//
// Everything above this line is the CELL strike: the terminal-grade
// path that fallback screens and the loopback/golden tests still ride.
// Everything below is the proportional, antialiased engine the modern
// window timeline rides. One module, one decision sealed (D1): "how
// glyphs are produced" — callers see coverage and metrics, never stb.
//
// F1: the sole third-party import (vendor/stb_truetype.h, public
// domain) — full written justification at vendor/stb_impl.c. Fonts are
// our OWN embedded assets (IBM Plex Sans, OFL, license in assets/);
// user font files are never loaded, which removes stb's documented
// untrusted-input caveat entirely.
// ===========================================================================

const c = @cImport(@cInclude("stb_truetype.h"));
const regular_ttf = @embedFile("font_regular_ttf");
const semibold_ttf = @embedFile("font_semibold_ttf");

/// One rasterized-glyph record in the engine cache. HOT — hundreds
/// accumulate (codepoint × size × weight) and the paint loop reads them
/// every frame → A7.
pub const Cached = struct {
    /// Offset of the alpha bytes in the engine's pool.
    off: u32,
    w: u16,
    h: u16,
    /// Pen advance and bitmap placement, in pixels at the cached size:
    /// blit at (pen_x + bear_x, baseline_y + bear_y).
    advance: i16,
    bear_x: i16,
    bear_y: i16,

    comptime {
        // Budget: 4 + 2+2 + 2+2+2 = 14 → 16 with u32 alignment; exact.
        // Raising this requires an A7.1 justification here.
        assert(@sizeOf(Cached) == 16);
    }
};

/// A view of one glyph's coverage, handed to the rasterizer. Valid only
/// until the NEXT glyph() call (a cache fill may grow the pool and move
/// it) — consume immediately, never store. Treated hot (A7).
pub const GlyphRaster = struct {
    alpha: []const u8,
    w: u16,
    h: u16,
    advance: i16,
    bear_x: i16,
    bear_y: i16,
    _pad: [6]u8 = @splat(0),

    comptime {
        // Budget: 16 (slice) + 5×2 + 6 pad = 32 bytes, exact (A7).
        assert(@sizeOf(GlyphRaster) == 32);
    }
};

/// Vertical metrics for one pixel size. A7.2: cold struct, size guard
/// waived — returned by value, never held in quantity.
pub const Line = struct {
    ascent: i32,
    descent: i32,
    height: u32,
};

pub const Weight = enum(u1) { regular, semibold };

/// The engine: two parsed font faces + the glyph cache. One per window,
/// owned by the shell that opened it (C4), every cache fill takes the
/// caller's allocator (C1). A7.2: cold struct, size guard waived — one
/// per session; its CONTENTS (cache + pool) are the hot arrays.
pub const Engine = struct {
    regular: c.stbtt_fontinfo,
    semibold: c.stbtt_fontinfo,
    cache: std.AutoHashMapUnmanaged(u64, Cached) = .empty,
    pool: std.ArrayList(u8) = .empty,
};

/// Parse the embedded faces. Pure over comptime bytes; failure means
/// the embedded asset itself is bad, which is a build-time defect
/// surfaced at first run (E3: explicit, never silent).
pub fn initEngine() error{FontInitFailed}!Engine {
    var e: Engine = .{ .regular = undefined, .semibold = undefined };
    if (c.stbtt_InitFont(&e.regular, regular_ttf.ptr, c.stbtt_GetFontOffsetForIndex(regular_ttf.ptr, 0)) == 0)
        return error.FontInitFailed;
    if (c.stbtt_InitFont(&e.semibold, semibold_ttf.ptr, c.stbtt_GetFontOffsetForIndex(semibold_ttf.ptr, 0)) == 0)
        return error.FontInitFailed;
    return e;
}

pub fn deinitEngine(gpa: std.mem.Allocator, e: *Engine) void {
    e.cache.deinit(gpa);
    e.pool.deinit(gpa);
    e.* = undefined;
}

fn face(e: *const Engine, weight: Weight) *const c.stbtt_fontinfo {
    return switch (weight) {
        .regular => &e.regular,
        .semibold => &e.semibold,
    };
}

fn scaleFor(e: *const Engine, weight: Weight, px: u32) f32 {
    return c.stbtt_ScaleForPixelHeight(face(e, weight), @floatFromInt(px));
}

pub fn lineMetrics(e: *const Engine, weight: Weight, px: u32) Line {
    var ascent: c_int = 0;
    var descent: c_int = 0;
    var gap: c_int = 0;
    c.stbtt_GetFontVMetrics(face(e, weight), &ascent, &descent, &gap);
    const s = scaleFor(e, weight, px);
    const a: i32 = @intFromFloat(@ceil(@as(f32, @floatFromInt(ascent)) * s));
    const d: i32 = @intFromFloat(@floor(@as(f32, @floatFromInt(descent)) * s));
    const g: i32 = @intFromFloat(@ceil(@as(f32, @floatFromInt(gap)) * s));
    return .{ .ascent = a, .descent = d, .height = @intCast(a - d + g) };
}

/// Unknown codepoints fall back to U+FFFD, then to a blank — layout
/// always survives text the face does not cover (E4).
fn glyphIndex(info: *const c.stbtt_fontinfo, cp: u32) c_int {
    const direct = c.stbtt_FindGlyphIndex(info, @intCast(cp));
    if (direct != 0) return direct;
    return c.stbtt_FindGlyphIndex(info, 0xFFFD);
}

/// Pen advance for one codepoint, in pixels. Table lookup + multiply —
/// cheap enough that measurement needs no cache (G3).
pub fn advance(e: *const Engine, weight: Weight, cp: u32, px: u32) u32 {
    const info = face(e, weight);
    const gi = glyphIndex(info, cp);
    if (gi == 0) return 0;
    var adv: c_int = 0;
    var lsb: c_int = 0;
    c.stbtt_GetGlyphHMetrics(info, gi, &adv, &lsb);
    const w = @as(f32, @floatFromInt(adv)) * scaleFor(e, weight, px);
    return @intFromFloat(@max(0, @round(w)));
}

/// Pixel width of a UTF-8 run. Invalid bytes are skipped, not errors
/// (E4) — network text must never break measurement.
pub fn measure(e: *const Engine, weight: Weight, str: []const u8, px: u32) u32 {
    var total: u32 = 0;
    var i: usize = 0;
    while (i < str.len) {
        const n = std.unicode.utf8ByteSequenceLength(str[i]) catch {
            i += 1;
            continue;
        };
        if (i + n > str.len) break;
        const cp = std.unicode.utf8Decode(str[i..][0..n]) catch {
            i += 1;
            continue;
        };
        total += advance(e, weight, cp, px);
        i += n;
    }
    return total;
}

/// Antialiased coverage for one glyph at one size, cached forever (the
/// roadmap's §9.3 eviction question stays deferred until a measurement
/// indicts it — ASCII × a handful of sizes is kilobytes). The returned
/// view is valid until the next glyph() call; consume immediately.
pub fn glyph(
    gpa: std.mem.Allocator,
    e: *Engine,
    weight: Weight,
    cp: u32,
    px: u32,
) error{OutOfMemory}!GlyphRaster {
    const key: u64 = (@as(u64, @intFromEnum(weight)) << 63) | (@as(u64, px) << 32) | cp;
    const slot = try e.cache.getOrPut(gpa, key);
    if (!slot.found_existing) {
        slot.value_ptr.* = rasterizeInto(gpa, e, weight, cp, px) catch |err| {
            // getOrPut left an undefined value; remove it before erroring
            // so the cache never holds garbage (C5 in spirit).
            _ = e.cache.remove(key);
            return err;
        };
    }
    const v = slot.value_ptr.*;
    return .{
        .alpha = e.pool.items[v.off..][0 .. @as(usize, v.w) * v.h],
        .w = v.w,
        .h = v.h,
        .advance = v.advance,
        .bear_x = v.bear_x,
        .bear_y = v.bear_y,
    };
}

fn rasterizeInto(
    gpa: std.mem.Allocator,
    e: *Engine,
    weight: Weight,
    cp: u32,
    px: u32,
) error{OutOfMemory}!Cached {
    const info = face(e, weight);
    const s = scaleFor(e, weight, px);
    const gi = glyphIndex(info, cp);
    var adv: c_int = 0;
    var lsb: c_int = 0;
    if (gi != 0) c.stbtt_GetGlyphHMetrics(info, gi, &adv, &lsb);
    const advance_px: i16 = @intFromFloat(@round(@as(f32, @floatFromInt(adv)) * s));
    if (gi == 0) return .{ .off = 0, .w = 0, .h = 0, .advance = advance_px, .bear_x = 0, .bear_y = 0 };

    var w: c_int = 0;
    var h: c_int = 0;
    var x0: c_int = 0;
    var y0: c_int = 0;
    const bmp = c.stbtt_GetGlyphBitmap(info, s, s, gi, &w, &h, &x0, &y0);
    defer c.stbtt_FreeBitmap(bmp, null);
    if (bmp == null or w <= 0 or h <= 0) {
        // Whitespace and zero-extent glyphs: advance, no ink.
        return .{ .off = 0, .w = 0, .h = 0, .advance = advance_px, .bear_x = 0, .bear_y = 0 };
    }
    const count: usize = @as(usize, @intCast(w)) * @as(usize, @intCast(h));
    const off: u32 = @intCast(e.pool.items.len);
    try e.pool.appendSlice(gpa, bmp[0..count]);
    return .{
        .off = off,
        .w = @intCast(w),
        .h = @intCast(h),
        .advance = advance_px,
        .bear_x = @intCast(x0),
        .bear_y = @intCast(y0),
    };
}

test "engine: faces parse, metrics are sane, 'A' has ink" {
    const gpa = testing.allocator; // C6
    var e = try initEngine();
    defer deinitEngine(gpa, &e);

    const lm = lineMetrics(&e, .regular, 17);
    try testing.expect(lm.ascent > 0);
    try testing.expect(lm.descent < 0);
    try testing.expect(lm.height >= 17);

    try testing.expect(advance(&e, .regular, 'A', 17) > 0);
    try testing.expect(measure(&e, .regular, "zat", 17) > measure(&e, .regular, "z", 17));
    // The UI face is PROPORTIONAL (Inter): a narrow glyph advances less than a
    // wide one. This is what the premium feed lays out against (real advances,
    // not a fixed cell). The prior monospace face (JetBrains Mono) made these
    // equal; the cell-path fallback's fixed-cell sizing assumes that uniformity,
    // so it is the one surface a proportional face renders loosely on.
    try testing.expect(advance(&e, .regular, 'i', 17) < advance(&e, .regular, 'W', 17));
    try testing.expect(advance(&e, .regular, '.', 17) < advance(&e, .regular, 'M', 17));

    // The 'M' advance-to-pixel RATIO is the reference the shell's cell-path
    // fallback uses for cell WIDTH (`glyph_advance_ratio`). Inter's 'M' (a wide
    // glyph in a proportional face) advances ~0.765× its px height; pin it
    // across a few sizes so a silent font swap that changed cell metrics fails
    // HERE, forcing `glyph_advance_ratio` to be re-measured. (On the premium GPU
    // path this is irrelevant — that path uses real per-glyph advances.)
    for ([_]u32{ 17, 28, 40 }) |px| {
        const ratio = @as(f32, @floatFromInt(advance(&e, .regular, 'M', px))) / @as(f32, @floatFromInt(px));
        try testing.expect(ratio > 0.70 and ratio < 0.82);
    }

    const g = try glyph(gpa, &e, .semibold, 'A', 17);
    try testing.expect(g.w > 0 and g.h > 0);
    var any: bool = false;
    for (g.alpha) |a| any = any or a > 0;
    try testing.expect(any);

    // Second lookup is the cache hit: identical view, no growth needed.
    const before = e.pool.items.len;
    _ = try glyph(gpa, &e, .semibold, 'A', 17);
    try testing.expectEqual(before, e.pool.items.len);
}

test "engine: uncovered codepoints degrade to the FFFD box, never an error" {
    const gpa = testing.allocator;
    var e = try initEngine();
    defer deinitEngine(gpa, &e);
    const g = try glyph(gpa, &e, .regular, 0x1F600, 17); // emoji: not in Plex
    _ = g; // any outcome but a crash/error is acceptable; FFFD has ink in Plex
    try testing.expect(advance(&e, .regular, ' ', 17) > 0);
}

/// Fill an ASCII advance table for one (weight, size): 128 metric
/// lookups once per frame instead of one per character measured — the
/// jk-test lesson (SESSION_FINDINGS §3.3) applied BEFORE the lag, with
/// the bench standing by to confirm (G1).
pub fn asciiAdvances(e: *const Engine, weight: Weight, px: u32, out: *[128]u16) void {
    for (out, 0..) |*slot, cp| slot.* = @intCast(advance(e, weight, @intCast(cp), px));
}
