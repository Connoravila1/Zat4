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

//! B1 classification: CORE (pure). Read-only, webpage-style text selection over
//! a captured run of placed glyphs. The feed lays text out per-glyph; the rooted
//! post's body glyphs are captured into a `Glyph` run (feed_view.captureBody),
//! and this module turns a pointer drag over that run into a caret range,
//! highlight rectangles, and the selected text in reading order. No I/O, no
//! clock, no allocation that isn't handed an allocator (B2/C1).
//!
//! The model: a CARET sits between glyphs, indexed 0..len (caret i is "before
//! glyph i"; len is "after the last"). A selection is an unordered pair
//! (anchor, focus) of caret indices; the selected glyphs are [min, max).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

/// One placed glyph: the geometry a selection needs, in the layout's logical
/// (scroll-applied) space. Produced by the view layer (feed_view.SelGlyph is an
/// alias). HOT (one per body glyph, scanned per drag) → A7.
pub const Glyph = struct {
    cp: u32, // codepoint (for reading-order copy)
    x: i16, // pen left
    baseline: i16, // text baseline y
    w: u16, // advance width
    line: u16, // 0-based wrapped-line index (a rise = a '\n' when copied)

    comptime {
        assert(@sizeOf(Glyph) == 12); // 4 + 2+2+2+2, exact (A7)
    }
};

pub const Glyphs = std.ArrayListUnmanaged(Glyph);

/// A highlight span in logical pixels — one per selected line. The shell turns
/// these into the draw vocabulary (rounded rects); keeping raster out of here
/// holds the core pure and the dependency one-way (D3). A7.2: cold — a handful
/// per frame, returned in a small list, never held in bulk.
pub const Rect = struct { x: i32, y: i32, w: i32, h: i32 };

fn absI(v: i32) i32 {
    return if (v < 0) -v else v;
}

/// The caret index (0..glyphs.len) nearest the point: the line whose baseline
/// is closest to `py`, then the inter-glyph gap nearest `px` within that line.
/// Empty run ⇒ 0 (E4: an ordinary result, not an error).
pub fn caretAtPoint(glyphs: []const Glyph, px: i32, py: i32) u32 {
    if (glyphs.len == 0) return 0;

    // 1. The target line: minimise |py - baseline|. (Glyphs of a line share a
    //    baseline; line indices are non-decreasing in reading order.)
    var target_line: u16 = glyphs[0].line;
    var best: i32 = absI(py - glyphs[0].baseline);
    for (glyphs) |g| {
        const d = absI(py - g.baseline);
        if (d < best) {
            best = d;
            target_line = g.line;
        }
    }

    // 2. Within that line, the caret falls before the first glyph whose
    //    horizontal midpoint is past `px`; otherwise after the line's last glyph.
    var caret: u32 = @intCast(glyphs.len);
    var in_line = false;
    for (glyphs, 0..) |g, idx| {
        if (g.line != target_line) {
            if (in_line) {
                caret = @intCast(idx); // first glyph of the NEXT line = after this line
                break;
            }
            continue;
        }
        in_line = true;
        const mid = @as(i32, g.x) + @divTrunc(@as(i32, g.w), 2); // glyph horizontal midpoint
        if (px < mid) {
            caret = @intCast(idx);
            break;
        }
        caret = @intCast(idx + 1);
    }
    return caret;
}

/// A caret range [lo, hi) — an anchor/focus pair already ordered.
pub const Span = struct {
    lo: u32,
    hi: u32,
    comptime {
        assert(@sizeOf(Span) == 8);
    }
};

/// The selected glyph range [lo, hi) for a caret pair, clamped to the run.
pub fn range(glyphs_len: usize, anchor: u32, focus: u32) Span {
    const n: u32 = @intCast(glyphs_len);
    const a = @min(anchor, n);
    const f = @min(focus, n);
    return .{ .lo = @min(a, f), .hi = @max(a, f) };
}

/// The glyph the caret sits on (caret == len ⇒ the last glyph).
fn glyphAt(glyphs_len: usize, caret: u32) u32 {
    return if (caret >= glyphs_len) @intCast(glyphs_len - 1) else caret;
}

/// The word under `caret` — the maximal run of same-class (space vs non-space)
/// glyphs around it, not crossing a wrapped line. The double-click selection.
/// Empty run ⇒ an empty span.
pub fn wordAt(glyphs: []const Glyph, caret: u32) Span {
    if (glyphs.len == 0) return .{ .lo = 0, .hi = 0 };
    const idx = glyphAt(glyphs.len, caret);
    const line = glyphs[idx].line;
    const want_space = glyphs[idx].cp == ' ';
    var lo = idx;
    while (lo > 0 and glyphs[lo - 1].line == line and (glyphs[lo - 1].cp == ' ') == want_space) lo -= 1;
    var hi = idx + 1;
    while (hi < glyphs.len and glyphs[hi].line == line and (glyphs[hi].cp == ' ') == want_space) hi += 1;
    return .{ .lo = lo, .hi = @intCast(hi) };
}


/// Append one highlight Rect per selected line into `out`. `asc`/`desc` are the
/// pixels above/below the baseline the band should cover (the font's rough
/// extent at the body size). Empty selection ⇒ nothing appended.
pub fn highlightRects(
    gpa: Allocator,
    out: *std.ArrayListUnmanaged(Rect),
    glyphs: []const Glyph,
    anchor: u32,
    focus: u32,
    asc: i32,
    desc: i32,
) !void {
    const r = range(glyphs.len, anchor, focus);
    if (r.hi <= r.lo) return;
    var i: u32 = r.lo;
    while (i < r.hi) {
        const line = glyphs[i].line;
        const baseline: i32 = glyphs[i].baseline;
        var min_x: i32 = glyphs[i].x;
        var max_x: i32 = @as(i32, glyphs[i].x) + glyphs[i].w;
        // Extend over every selected glyph on this line.
        while (i < r.hi and glyphs[i].line == line) : (i += 1) {
            min_x = @min(min_x, glyphs[i].x);
            max_x = @max(max_x, @as(i32, glyphs[i].x) + glyphs[i].w);
        }
        try out.append(gpa, .{ .x = min_x, .y = baseline - asc, .w = max_x - min_x, .h = asc + desc });
    }
}

/// Append the selected text (UTF-8, reading order) into `out`. A line break is
/// inserted wherever the selected glyphs cross a wrapped-line boundary, so a
/// multi-line selection pastes as multiple lines.
pub fn copyInto(
    gpa: Allocator,
    out: *std.ArrayListUnmanaged(u8),
    glyphs: []const Glyph,
    anchor: u32,
    focus: u32,
) !void {
    const r = range(glyphs.len, anchor, focus);
    if (r.hi <= r.lo) return;
    var prev_line: ?u16 = null;
    var i: u32 = r.lo;
    while (i < r.hi) : (i += 1) {
        const g = glyphs[i];
        if (prev_line) |pl| {
            if (g.line != pl) try out.append(gpa, '\n');
        }
        prev_line = g.line;
        var buf: [4]u8 = undefined;
        const n = std.unicode.utf8Encode(@intCast(g.cp), &buf) catch continue;
        try out.appendSlice(gpa, buf[0..n]);
    }
}

// ---------------------------------------------------------------------------
// Tests (C6)
// ---------------------------------------------------------------------------

const testing = std.testing;

/// "ab\ncd" laid out as two lines: a,b on line 0 (baseline 20), c,d on line 1
/// (baseline 40). Each glyph 10px wide, packed left to right from x=0.
fn sample() [4]Glyph {
    return .{
        .{ .cp = 'a', .x = 0, .baseline = 20, .w = 10, .line = 0 },
        .{ .cp = 'b', .x = 10, .baseline = 20, .w = 10, .line = 0 },
        .{ .cp = 'c', .x = 0, .baseline = 40, .w = 10, .line = 1 },
        .{ .cp = 'd', .x = 10, .baseline = 40, .w = 10, .line = 1 },
    };
}

test "text_select: caretAtPoint maps pixels to inter-glyph carets" {
    const g = sample();
    // Far left of line 0 → before glyph 0.
    try testing.expectEqual(@as(u32, 0), caretAtPoint(&g, -5, 20));
    // Past the midpoint of 'a' (mid=5) but before 'b' (mid=15) → between a,b = 1.
    try testing.expectEqual(@as(u32, 1), caretAtPoint(&g, 8, 20));
    // Far right of line 0 → after 'b' = caret 2.
    try testing.expectEqual(@as(u32, 2), caretAtPoint(&g, 100, 20));
    // A point nearer line 1's baseline lands on that line: before 'c' = 2.
    try testing.expectEqual(@as(u32, 2), caretAtPoint(&g, -5, 39));
    // Right end of line 1 → after 'd' = 4 (== len).
    try testing.expectEqual(@as(u32, 4), caretAtPoint(&g, 100, 40));
    // Empty run is an ordinary 0.
    try testing.expectEqual(@as(u32, 0), caretAtPoint(&.{}, 10, 10));
}

test "text_select: range is order-independent and clamped" {
    try testing.expectEqual(@as(u32, 1), range(4, 3, 1).lo);
    try testing.expectEqual(@as(u32, 3), range(4, 3, 1).hi);
    try testing.expectEqual(@as(u32, 4), range(4, 9, 2).hi); // clamped to len
}

test "text_select: wordAt selects the run under the caret, bounded by line" {
    // Line 0: "ab cd" → glyphs a,b,space,c,d (5). Line 1: "ef" → e,f.
    const g = [_]Glyph{
        .{ .cp = 'a', .x = 0, .baseline = 20, .w = 10, .line = 0 },
        .{ .cp = 'b', .x = 10, .baseline = 20, .w = 10, .line = 0 },
        .{ .cp = ' ', .x = 20, .baseline = 20, .w = 6, .line = 0 },
        .{ .cp = 'c', .x = 26, .baseline = 20, .w = 10, .line = 0 },
        .{ .cp = 'd', .x = 36, .baseline = 20, .w = 10, .line = 0 },
        .{ .cp = 'e', .x = 0, .baseline = 40, .w = 10, .line = 1 },
        .{ .cp = 'f', .x = 10, .baseline = 40, .w = 10, .line = 1 },
    };
    // Caret 1 sits on glyph 1 ('b') → word "ab" = [0,2).
    try testing.expectEqual(@as(u32, 0), wordAt(&g, 1).lo);
    try testing.expectEqual(@as(u32, 2), wordAt(&g, 1).hi);
    // Caret 4 sits on glyph 4 ('d') → word "cd" = [3,5), not crossing into line 1.
    try testing.expectEqual(@as(u32, 3), wordAt(&g, 4).lo);
    try testing.expectEqual(@as(u32, 5), wordAt(&g, 4).hi);
}

test "text_select: copyInto reconstructs reading order with line breaks" {
    const g = sample();
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(testing.allocator);
    // Select all four glyphs (caret 0..4): "ab\ncd".
    try copyInto(testing.allocator, &out, &g, 0, 4);
    try testing.expectEqualStrings("ab\ncd", out.items);
    // A sub-selection within one line: glyphs [1,3) span line 0→1 → "b\nc".
    out.clearRetainingCapacity();
    try copyInto(testing.allocator, &out, &g, 1, 3);
    try testing.expectEqualStrings("b\nc", out.items);
    // Empty selection copies nothing.
    out.clearRetainingCapacity();
    try copyInto(testing.allocator, &out, &g, 2, 2);
    try testing.expectEqual(@as(usize, 0), out.items.len);
}

test "text_select: highlightRects is one span per selected line" {
    const g = sample();
    var rects: std.ArrayListUnmanaged(Rect) = .empty;
    defer rects.deinit(testing.allocator);
    // Select all: one rect for line 0 (x 0..20), one for line 1.
    try highlightRects(testing.allocator, &rects, &g, 0, 4, 14, 4);
    try testing.expectEqual(@as(usize, 2), rects.items.len);
    try testing.expectEqual(@as(i32, 0), rects.items[0].x);
    try testing.expectEqual(@as(i32, 20), rects.items[0].w);
    try testing.expectEqual(@as(i32, 20 - 14), rects.items[0].y); // baseline - asc
    try testing.expectEqual(@as(i32, 18), rects.items[0].h); // asc + desc
    // A partial first line: caret 1..4 → line 0 covers only 'b' (x 10..20).
    rects.clearRetainingCapacity();
    try highlightRects(testing.allocator, &rects, &g, 1, 4, 14, 4);
    try testing.expectEqual(@as(usize, 2), rects.items.len);
    try testing.expectEqual(@as(i32, 10), rects.items[0].x);
    try testing.expectEqual(@as(i32, 10), rects.items[0].w);
}
