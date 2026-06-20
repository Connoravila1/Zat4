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

//! B1 classification: CORE (pure). The premium feed view — a slice of
//! plain post records becomes proportional draw items (avatars, names,
//! body, an engagement row, dividers) layered OVER the living field
//! (PHASE5_GUI_ROADMAP cut 5.6, the deferred visual pass). It speaks the
//! raster draw-list vocabulary and nothing else: same posts + same engine
//! ⇒ same items (B2). No I/O, no clock, no network. Positioning is
//! measured through the font engine (a pure advance lookup), so the layout
//! is proportional, not locked to the field's cell grid — the decoupling
//! the mockups proved out.
//!
//! D6: this is one vertical slice. The field stays exactly as it was; this
//! module only appends a content layer on top. Wiring it in is a single
//! call in the shell's paint path after the field composes.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const text = @import("text.zig");
const raster = @import("raster.zig");

// Palette, copied from field.zig so the view never reaches across a module
// for a constant (D4: only the value crosses, by copy). ARGB.
const bg: u32 = 0xFF181812;
const ink: u32 = 0xFFEDEAE0;
const body_c: u32 = 0xFFD8D3C8;
const muted: u32 = 0xFF9A968A;
const faint: u32 = 0xFF6A655A;
const accent: u32 = 0xFFE8B84B;
const like_c: u32 = 0xFFF0617A;
const boost_c: u32 = 0xFF8FD18F;
const veil: u32 = 0xD4181812; // ~83% over the field — texture glows faintly through
// ambient-texture slice will lower this so the living field glows through.
const divider: u32 = 0x18EDEAE0; // ~9% ink hairline

/// Which control a hit region belongs to. The button slice maps these to
/// effects/writes; the view only reports geometry (B5).
pub const Action = enum(u8) { reply, repost, like };

/// One tappable button region in window pixels, tagged with the post it
/// belongs to and the control. Emitted alongside the draw items so a click
/// can be resolved without re-deriving the layout. HOT (a few per screen,
/// scanned per click) → A7.
pub const Region = struct {
    x: i16,
    y: i16,
    w: u16,
    h: u16,
    post: u16,
    kind: Action,
    _pad: u8 = 0, // A6: explicit

    comptime {
        assert(@sizeOf(Region) == 12); // 2+2+2+2+2+1+1, exact (A7)
    }
};

pub const Regions = std.ArrayListUnmanaged(Region);

/// First region (in reverse paint order) containing the pixel, or null.
pub fn hitTest(regions: []const Region, px: i32, py: i32) ?Region {
    var i: usize = regions.len;
    while (i > 0) {
        i -= 1;
        const r = regions[i];
        if (px >= r.x and px < @as(i32, r.x) + r.w and py >= r.y and py < @as(i32, r.y) + r.h) return r;
    }
    return null;
}

/// One visible post, as the view needs it — plain display data, already
/// resolved by whatever produced it (sample content today; a transform
/// over real timeline items tomorrow, B5). Built fresh each frame for the
/// handful of on-screen rows, never the bulk store — but it rides a
/// per-frame loop, so it carries the guard.
pub const PostView = struct {
    name: []const u8,
    handle: []const u8,
    age: []const u8,
    body: []const u8,
    tint: u32, // avatar fill (ARGB)
    reply: u32,
    boost: u32,
    like: u32,
    initial: u8, // avatar letter (ASCII)
    liked: bool,
    boosted: bool,
    _pad: u8 = 0, // A6: explicit

    comptime {
        // Budget: 4 slices (4×16) + 4 u32 (16) + 4 bytes, padded to the
        // 8-byte slice alignment = 88. Exact (A7); raising needs an A7.1
        // note here.
        assert(@sizeOf(PostView) == 88);
    }
};

const rail_w: i32 = 248;
const feed_w: i32 = 604;
const side_w: i32 = 352;
const wide_min: i32 = rail_w + feed_w + side_w + 40; // ~1244

const panel: u32 = 0xCC1E1C16; // sidebar cards: mostly solid over the field

const Metrics = struct {
    col_x: i32, // feed column
    col_w: i32,
    lx: i32,
    cw: i32,
    rail_x: i32,
    side_x: i32,
    wide: bool,
    _pad: [3]u8 = .{ 0, 0, 0 }, // A6

    comptime {
        assert(@sizeOf(Metrics) == 28); // 6×i32 + bool + 3 pad
    }
};

fn metricsFor(width: i32) Metrics {
    if (width >= wide_min) {
        const bx = @divTrunc(width - (rail_w + feed_w + side_w), 2);
        return .{ .rail_x = bx, .col_x = bx + rail_w, .col_w = feed_w, .lx = bx + rail_w + 22, .cw = feed_w - 44, .side_x = bx + rail_w + feed_w, .wide = true };
    }
    const col_w = @min(width, 600);
    const col_x = @divTrunc(width - col_w, 2);
    return .{ .rail_x = 0, .col_x = col_x, .col_w = col_w, .lx = col_x + 18, .cw = col_w - 36, .side_x = 0, .wide = false };
}

fn rect(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, w: i32, h: i32, color: u32, radius: u8) !void {
    try dl.append(gpa, .{ .rect = .{
        .x = @intCast(x),
        .y = @intCast(y),
        .w = @intCast(@max(0, w)),
        .h = @intCast(@max(0, h)),
        .color = color,
        .radius = radius,
    } });
}

/// One proportional glyph; returns the pen x after it.
fn glyph1(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, weight: text.Weight, x: i32, baseline: i32, color: u32, px: u16, cp: u32) !i32 {
    try dl.append(gpa, .{ .text = .{
        .x = @intCast(x),
        .baseline = @intCast(baseline),
        .codepoint = cp,
        .color = color,
        .px = px,
        .weight = @intFromEnum(weight),
    } });
    return x + @as(i32, @intCast(text.advance(e, weight, cp, px)));
}

/// A UTF-8 run; returns the pen x after it.
fn str(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, weight: text.Weight, x0: i32, baseline: i32, color: u32, px: u16, s: []const u8) !i32 {
    var x = x0;
    var it = (std.unicode.Utf8View.init(s) catch return x).iterator();
    while (it.nextCodepoint()) |cp| x = try glyph1(gpa, dl, e, weight, x, baseline, color, px, cp);
    return x;
}


/// Word-wrap `body` to `maxw`; returns the baseline after the last line.
/// When `draw_it` is false it only measures (advances the baseline) without
/// emitting glyphs — used to size off-screen posts without painting them.
fn wrapBody(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, x0: i32, first_baseline: i32, maxw: i32, color: u32, px: u16, body: []const u8, line_h: i32, draw_it: bool) !i32 {
    var baseline = first_baseline;
    var line_start: usize = 0;
    var last_space: usize = 0;
    var have_space = false;
    var i: usize = 0;
    while (i <= body.len) : (i += 1) {
        const at_end = i == body.len;
        if (!at_end and body[i] != ' ') continue;
        const candidate = body[line_start..i];
        if (text.measure(e, .regular, candidate, px) > @as(u32, @intCast(@max(0, maxw))) and have_space) {
            if (draw_it) _ = try str(gpa, dl, e, .regular, x0, baseline, color, px, body[line_start..last_space]);
            baseline += line_h;
            line_start = last_space + 1;
            have_space = false;
            i = line_start;
            continue;
        }
        if (at_end) {
            if (draw_it) _ = try str(gpa, dl, e, .regular, x0, baseline, color, px, body[line_start..i]);
            baseline += line_h;
            break;
        }
        last_space = i;
        have_space = true;
    }
    return baseline;
}

fn fxi(v: f32) i32 {
    return @intFromFloat(@round(v));
}

fn line(gpa: Allocator, dl: *raster.DrawList, x0: i32, y0: i32, x1: i32, y1: i32, color: u32, th: u8) !void {
    try dl.append(gpa, .{ .line = .{ .x0 = @intCast(x0), .y0 = @intCast(y0), .x1 = @intCast(x1), .y1 = @intCast(y1), .color = color, .thickness = th } });
}

// Minimalist line-art icons in an s×s box at (x,y). Reply and repost are
// outlines; the heart is filled (its colour carries the liked state).
fn iconReply(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, color: u32) !void {
    const f: f32 = @floatFromInt(s);
    const bh = fxi(f * 0.64);
    try line(gpa, dl, x, y, x + s, y, color, 2); // top
    try line(gpa, dl, x, y, x, y + bh, color, 2); // left
    try line(gpa, dl, x + s, y, x + s, y + bh, color, 2); // right
    try line(gpa, dl, x, y + bh, x + fxi(f * 0.40), y + bh, color, 2); // bottom-left
    try line(gpa, dl, x + fxi(f * 0.64), y + bh, x + s, y + bh, color, 2); // bottom-right
    try line(gpa, dl, x + fxi(f * 0.40), y + bh, x + fxi(f * 0.26), y + s, color, 2); // tail down
    try line(gpa, dl, x + fxi(f * 0.26), y + s, x + fxi(f * 0.64), y + bh, color, 2); // tail back
}

fn iconRepost(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, color: u32) !void {
    const f: f32 = @floatFromInt(s);
    // top arrow → right
    try line(gpa, dl, x + fxi(f * 0.06), y + fxi(f * 0.34), x + fxi(f * 0.82), y + fxi(f * 0.34), color, 2);
    try line(gpa, dl, x + fxi(f * 0.82), y + fxi(f * 0.34), x + fxi(f * 0.62), y + fxi(f * 0.16), color, 2);
    try line(gpa, dl, x + fxi(f * 0.82), y + fxi(f * 0.34), x + fxi(f * 0.62), y + fxi(f * 0.52), color, 2);
    // bottom arrow ← left
    try line(gpa, dl, x + fxi(f * 0.18), y + fxi(f * 0.70), x + fxi(f * 0.94), y + fxi(f * 0.70), color, 2);
    try line(gpa, dl, x + fxi(f * 0.18), y + fxi(f * 0.70), x + fxi(f * 0.38), y + fxi(f * 0.52), color, 2);
    try line(gpa, dl, x + fxi(f * 0.18), y + fxi(f * 0.70), x + fxi(f * 0.38), y + fxi(f * 0.88), color, 2);
}

fn iconHeart(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, color: u32) !void {
    const f: f32 = @floatFromInt(s);
    const rr = f * 0.27;
    const cyb = f * 0.32;
    try rect(gpa, dl, x + fxi(f * 0.30 - rr), y + fxi(cyb - rr), fxi(rr * 2), fxi(rr * 2), color, @intCast(fxi(rr)));
    try rect(gpa, dl, x + fxi(f * 0.70 - rr), y + fxi(cyb - rr), fxi(rr * 2), fxi(rr * 2), color, @intCast(fxi(rr)));
    const top = f * 0.22;
    const bot = f * 0.96;
    const cxh = f * 0.5;
    const half_top = f * 0.47;
    var ry: i32 = fxi(top);
    const ry_bot: i32 = fxi(bot);
    while (ry <= ry_bot) : (ry += 1) {
        const tp = (@as(f32, @floatFromInt(ry)) - top) / (bot - top);
        const hw = half_top * (1.0 - tp);
        const lx_ = if (hw <= 0) fxi(cxh) else fxi(cxh - hw);
        const rx_ = if (hw <= 0) fxi(cxh) else fxi(cxh + hw);
        try line(gpa, dl, x + lx_, y + ry, x + rx_, y + ry, color, 1);
    }
}

fn ring(gpa: Allocator, dl: *raster.DrawList, cx: i32, cy: i32, r: f32, color: u32, th: u8, segs: usize) !void {
    var i: usize = 0;
    while (i < segs) : (i += 1) {
        const a0 = @as(f32, @floatFromInt(i)) / @as(f32, @floatFromInt(segs)) * std.math.tau;
        const a1 = @as(f32, @floatFromInt(i + 1)) / @as(f32, @floatFromInt(segs)) * std.math.tau;
        try line(gpa, dl, cx + fxi(std.math.cos(a0) * r), cy + fxi(std.math.sin(a0) * r), cx + fxi(std.math.cos(a1) * r), cy + fxi(std.math.sin(a1) * r), color, th);
    }
}

fn iconHome(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, c: u32) !void {
    const f: f32 = @floatFromInt(s);
    try line(gpa, dl, x + fxi(f * 0.5), y, x + s, y + fxi(f * 0.46), c, 2);
    try line(gpa, dl, x + fxi(f * 0.5), y, x, y + fxi(f * 0.46), c, 2);
    try line(gpa, dl, x + fxi(f * 0.16), y + fxi(f * 0.42), x + fxi(f * 0.16), y + s, c, 2);
    try line(gpa, dl, x + fxi(f * 0.84), y + fxi(f * 0.42), x + fxi(f * 0.84), y + s, c, 2);
    try line(gpa, dl, x + fxi(f * 0.16), y + s, x + fxi(f * 0.84), y + s, c, 2);
}

fn iconSearch(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, c: u32) !void {
    const f: f32 = @floatFromInt(s);
    try ring(gpa, dl, x + fxi(f * 0.42), y + fxi(f * 0.42), f * 0.34, c, 2, 10);
    try line(gpa, dl, x + fxi(f * 0.66), y + fxi(f * 0.66), x + s, y + s, c, 2);
}

fn iconPerson(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, c: u32) !void {
    const f: f32 = @floatFromInt(s);
    const hr = f * 0.20;
    try rect(gpa, dl, x + fxi(f * 0.5 - hr), y + fxi(f * 0.04), fxi(hr * 2), fxi(hr * 2), c, @intCast(fxi(hr)));
    try line(gpa, dl, x + fxi(f * 0.16), y + s, x + fxi(f * 0.30), y + fxi(f * 0.58), c, 2);
    try line(gpa, dl, x + fxi(f * 0.84), y + s, x + fxi(f * 0.70), y + fxi(f * 0.58), c, 2);
    try line(gpa, dl, x + fxi(f * 0.30), y + fxi(f * 0.58), x + fxi(f * 0.70), y + fxi(f * 0.58), c, 2);
    try line(gpa, dl, x + fxi(f * 0.16), y + s, x + fxi(f * 0.84), y + s, c, 2);
}

fn iconGear(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, c: u32) !void {
    const f: f32 = @floatFromInt(s);
    const cx = x + fxi(f * 0.5);
    const cy = y + fxi(f * 0.5);
    try ring(gpa, dl, cx, cy, f * 0.32, c, 2, 8);
    try rect(gpa, dl, cx - fxi(f * 0.09), cy - fxi(f * 0.09), fxi(f * 0.18), fxi(f * 0.18), c, @intCast(fxi(f * 0.09)));
}

fn navIcon(idx: usize, gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, c: u32) !void {
    switch (idx) {
        0 => try iconHome(gpa, dl, x, y, s, c),
        1 => try iconSearch(gpa, dl, x, y, s, c),
        2 => try iconHeart(gpa, dl, x, y, s, c),
        3 => try iconReply(gpa, dl, x, y, s, c),
        4 => try iconPerson(gpa, dl, x, y, s, c),
        else => try iconGear(gpa, dl, x, y, s, c),
    }
}

fn drawRail(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, rx: i32, height: i32) !void {
    const x0 = rx + 14;
    const wm = try str(gpa, dl, e, .semibold, x0 + 8, 58, accent, 26, "zat4");
    _ = try str(gpa, dl, e, .semibold, wm, 58, ink, 26, ".");

    const labels = [_][]const u8{ "Home", "Explore", "Activity", "Messages", "Profile", "Settings" };
    var ny: i32 = 108;
    for (labels, 0..) |label, idx| {
        const on = idx == 0;
        const col = if (on) ink else muted;
        try navIcon(idx, gpa, dl, x0 + 10, ny, 22, if (on) accent else muted);
        _ = try str(gpa, dl, e, if (on) .semibold else .regular, x0 + 48, ny + 17, col, 16, label);
        ny += 50;
    }

    ny += 16;
    try rect(gpa, dl, x0 + 6, ny, rail_w - 44, 50, accent, 14);
    const npw: i32 = @intCast(text.measure(e, .semibold, "New post", 16));
    _ = try str(gpa, dl, e, .semibold, x0 + 6 + @divTrunc(rail_w - 44 - npw, 2), ny + 32, bg, 16, "New post");

    const by = height - 60;
    try rect(gpa, dl, x0 + 6, by, 38, 38, 0xFF3F3B2D, 19);
    _ = try str(gpa, dl, e, .semibold, x0 + 54, by + 16, ink, 14, "you");
    _ = try str(gpa, dl, e, .regular, x0 + 54, by + 33, faint, 12, "@you.zat");
}

fn drawSidebar(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, sx: i32, height: i32) !void {
    const x0 = sx + 16;
    const w = side_w - 32;

    // search field
    try rect(gpa, dl, x0, 28, w, 46, panel, 13);
    try iconSearch(gpa, dl, x0 + 14, 41, 20, faint);
    _ = try str(gpa, dl, e, .regular, x0 + 46, 57, faint, 14, "Search zat4");

    // trending
    const ty: i32 = 92;
    const th: i32 = 234;
    try rect(gpa, dl, x0, ty, w, th, panel, 15);
    _ = try str(gpa, dl, e, .semibold, x0 + 18, ty + 28, faint, 12, "TRENDING");
    const trends = [_][3][]const u8{
        .{ "protocol", "at://small-net", "2,481 posts" },
        .{ "design", "glyph fields", "913 posts" },
        .{ "zig", "0.16 release", "1,204 posts" },
        .{ "monospace", "one column", "640 posts" },
    };
    var yy: i32 = ty + 54;
    for (trends) |t| {
        _ = try str(gpa, dl, e, .regular, x0 + 18, yy, faint, 12, t[0]);
        _ = try str(gpa, dl, e, .semibold, x0 + 18, yy + 19, ink, 15, t[1]);
        _ = try str(gpa, dl, e, .regular, x0 + 18, yy + 35, faint, 12, t[2]);
        yy += 48;
    }

    // who to follow
    const wy: i32 = ty + th + 18;
    const wh: i32 = 196;
    try rect(gpa, dl, x0, wy, w, wh, panel, 15);
    _ = try str(gpa, dl, e, .semibold, x0 + 18, wy + 28, faint, 12, "WHO TO FOLLOW");
    const who = [_][2][]const u8{ .{ "Desh", "@desh.zat" }, .{ "atlas", "@atlas.zat" }, .{ "rune", "@rune.zat" } };
    const tints = [_]u32{ 0xFF9FB0C7, 0xFFC9A87A, 0xFFB59EC9 };
    var py: i32 = wy + 46;
    for (who, tints) |p, tint| {
        try rect(gpa, dl, x0 + 16, py, 38, 38, tint, 19);
        const iadv: i32 = @intCast(text.advance(e, .semibold, p[0][0], 18));
        _ = try glyph1(gpa, dl, e, .semibold, x0 + 16 + @divTrunc(38 - iadv, 2), py + 25, bg, 18, p[0][0]);
        _ = try str(gpa, dl, e, .semibold, x0 + 62, py + 16, ink, 14, p[0]);
        _ = try str(gpa, dl, e, .regular, x0 + 62, py + 33, faint, 12, p[1]);
        const fbw: i32 = 76;
        const fbx = x0 + w - fbw - 12;
        try rect(gpa, dl, fbx, py + 5, fbw, 29, ink, 14);
        const flw: i32 = @intCast(text.measure(e, .semibold, "Follow", 13));
        _ = try str(gpa, dl, e, .semibold, fbx + @divTrunc(fbw - flw, 2), py + 24, bg, 13, "Follow");
        py += 48;
    }

    // §13 (AGPL): Zat4 is served over a network, so every interacting user must
    // be OFFERED the Corresponding Source. This persistent footer is that offer —
    // a visible pointer to the canonical repository, pinned to the sidebar bottom.
    // Putting the licence in the repo alone does not satisfy §13; the offer has to
    // reach network users of the running instance. Keep this visible.
    const fy = @max(py + 8, height - 40);
    _ = try str(gpa, dl, e, .regular, x0, fy, faint, 12, "Zat4 — free software, GNU AGPL-3.0");
    _ = try str(gpa, dl, e, .regular, x0, fy + 18, muted, 12, "source: codeberg.org/connoravila/zat4");
}

/// Emit the whole premium feed for `posts` into `dl`, OVER whatever the
/// field already composed. `scroll` shifts the post stack (≤0 scrolls up);
/// the top bar stays pinned. Appends only — the caller cleared the list.
pub fn layout(
    gpa: Allocator,
    e: *const text.Engine,
    width: i32,
    height: i32,
    posts: []const PostView,
    scroll: i32,
    dl: *raster.DrawList,
    regions: ?*Regions,
    /// Optional per-post height cache (advance from post_top to the next post),
    /// indexed by post. A post's height is SCROLL-INVARIANT — it depends only on
    /// the body text + column width — so the caller may keep this filled across
    /// scrolls and reset it only when the feed content or width changes, turning
    /// the costly per-post text-measure pass into a one-time cost. A slot < 0 (or
    /// a too-short cache) means "not measured yet": layout measures and fills it.
    /// Pass null to always measure (the original behaviour).
    heights: ?[]i32,
) error{OutOfMemory}!i32 {
    const m = metricsFor(width);
    if (regions) |rg| rg.clearRetainingCapacity();

    // 1. Feed column readability panel.
    try rect(gpa, dl, m.col_x, 0, m.col_w, height, veil, 0);

    var feed_y0: i32 = 112;
    if (m.wide) {
        // 2a. Desktop three-pane: nav rail + sidebar flank the feed.
        try drawRail(gpa, dl, e, m.rail_x, height);
        try drawSidebar(gpa, dl, e, m.side_x, height);
        // feed header: "Home" + tabs
        _ = try str(gpa, dl, e, .semibold, m.lx, 50, ink, 27, "Home");
        _ = try str(gpa, dl, e, .semibold, m.lx, 88, ink, 16, "Following");
        const fw2: i32 = @intCast(text.measure(e, .semibold, "Following", 16));
        _ = try str(gpa, dl, e, .regular, m.lx + fw2 + 28, 88, faint, 16, "Discover");
        try rect(gpa, dl, m.lx, 98, fw2, 3, accent, 2);
        try rect(gpa, dl, m.col_x, 110, m.col_w, 1, divider, 0);
        feed_y0 = 126;
    } else {
        // 2b. Mobile: wordmark + tabs pinned in the feed column.
        const wm = try str(gpa, dl, e, .semibold, m.lx, 42, accent, 22, "zat4");
        _ = try str(gpa, dl, e, .semibold, wm, 42, ink, 22, ".");
        _ = try str(gpa, dl, e, .semibold, m.lx, 76, ink, 15, "Following");
        const fw: i32 = @intCast(text.measure(e, .semibold, "Following", 15));
        _ = try str(gpa, dl, e, .regular, m.lx + fw + 26, 76, faint, 15, "Discover");
        try rect(gpa, dl, m.lx, 86, fw, 3, accent, 2);
        try rect(gpa, dl, m.col_x, 96, m.col_w, 1, divider, 0);
        feed_y0 = 112;
    }

    // 3. Posts.
    const av: i32 = 46;
    const gap: i32 = 13;
    const cx = m.lx + av + gap;
    const content_w = m.cw - av - gap;
    const body_line: i32 = @max(23, @as(i32, @intCast(text.lineMetrics(e, .regular, 16).height)));

    var y: i32 = feed_y0 + scroll;
    for (posts, 0..) |p, pi| {
        var nb: [12]u8 = undefined;
        const post_top = y;

        // Measure the post's height WITHOUT drawing (no i16 casts), so we can
        // both advance the scroll accounting and decide visibility. Only posts
        // that actually intersect the viewport get painted — otherwise a long
        // timeline pushes y past the 16-bit draw coordinates and overflows.
        //
        // The body wrap (text shaping) is the costly step and it is SCROLL-
        // INVARIANT. When the caller supplies a `heights` cache, reuse a filled
        // slot and skip the measure entirely — this is what keeps SCROLLING
        // cheap over a long feed (otherwise every post re-shapes every scroll
        // frame). Geometry: next_y = body_end + 48 (erow +16, row +20, gap +12),
        // so body_end = next_y - 48 reconstructs it from a cached advance.
        const cached: ?i32 = if (heights) |hh| (if (pi < hh.len and hh[pi] >= 0) hh[pi] else null) else null;
        var body_end: i32 = undefined;
        var next_y: i32 = undefined;
        if (cached) |adv| {
            next_y = post_top + adv;
            body_end = next_y - 48;
        } else {
            body_end = try wrapBody(gpa, dl, e, cx, post_top + 18 + body_line, content_w, body_c, 16, p.body, body_line, false);
            next_y = body_end + 48;
            if (heights) |hh| if (pi < hh.len) {
                hh[pi] = next_y - post_top;
            };
        }
        const erow = body_end + 16;
        const bottom = erow + 20;
        const visible = next_y > 0 and post_top < height;

        if (visible) {
            // avatar disc + initial
            try rect(gpa, dl, m.lx, post_top, av, av, p.tint, @intCast(av >> 1));
            const iadv: i32 = @intCast(text.advance(e, .semibold, p.initial, 22));
            _ = try glyph1(gpa, dl, e, .semibold, m.lx + @divTrunc(av - iadv, 2), post_top + 31, bg, 22, p.initial);

            // name · handle · age
            var bx = try str(gpa, dl, e, .semibold, cx, post_top + 17, ink, 17, p.name);
            bx = try str(gpa, dl, e, .regular, bx + 8, post_top + 17, faint, 14, p.handle);
            bx = try str(gpa, dl, e, .regular, bx + 7, post_top + 17, faint, 14, "·");
            _ = try str(gpa, dl, e, .regular, bx + 7, post_top + 17, faint, 14, p.age);

            // body (draw)
            _ = try wrapBody(gpa, dl, e, cx, post_top + 18 + body_line, content_w, body_c, 16, p.body, body_line, true);

            // engagement row — vector icons + counts (+ tap regions)
            const is: i32 = 16;
            const iy = erow - 13;
            const tap_h: u16 = 30;
            const tap_y: i32 = erow - 20;
            var ex = cx;
            try iconReply(gpa, dl, ex, iy, is, faint);
            const reply_x = ex;
            ex += is + 7;
            ex = try str(gpa, dl, e, .regular, ex, erow, muted, 13, std.fmt.bufPrint(&nb, "{d}", .{p.reply}) catch "0");
            try emitRegion(gpa, regions, reply_x, tap_y, ex - reply_x, tap_h, @intCast(pi), .reply);
            ex += 22;
            try iconRepost(gpa, dl, ex, iy, is, if (p.boosted) boost_c else faint);
            const rt_x = ex;
            ex += is + 7;
            ex = try str(gpa, dl, e, .regular, ex, erow, if (p.boosted) boost_c else muted, 13, std.fmt.bufPrint(&nb, "{d}", .{p.boost}) catch "0");
            try emitRegion(gpa, regions, rt_x, tap_y, ex - rt_x, tap_h, @intCast(pi), .repost);
            ex += 22;
            try iconHeart(gpa, dl, ex, iy, is, if (p.liked) like_c else faint);
            const like_x = ex;
            ex += is + 7;
            ex = try str(gpa, dl, e, .regular, ex, erow, if (p.liked) like_c else muted, 13, std.fmt.bufPrint(&nb, "{d}", .{p.like}) catch "0");
            try emitRegion(gpa, regions, like_x, tap_y, ex - like_x, tap_h, @intCast(pi), .like);

            // divider
            try rect(gpa, dl, m.col_x, bottom, m.col_w, 1, divider, 0);
        }
        y = next_y;
    }
    return y - scroll; // total content height (scroll-independent), for clamping
}

fn emitRegion(gpa: Allocator, regions: ?*Regions, x: i32, y: i32, w: i32, h: u16, post: u16, kind: Action) !void {
    const rg = regions orelse return;
    try rg.append(gpa, .{ .x = @intCast(std.math.clamp(x, -32768, 32767)), .y = @intCast(std.math.clamp(y, -32768, 32767)), .w = @intCast(@max(0, @min(32767, w))), .h = h, .post = post, .kind = kind });
}

// ---------------------------------------------------------------------------
// View-model construction (B2): real timeline items → PostViews. Pure — the
// shell hands plain TimelineItems in, plain PostViews come out (B5). Strings
// are borrowed from the store for the frame; only the derived "@handle" and
// the age string are allocated, into the per-frame arena (C3). Viewer
// like/repost state lives in the store, not the item, so it defaults off
// here — the input slice that wires the buttons will thread it.
// ---------------------------------------------------------------------------

const feed = @import("feed.zig");

pub fn fromTimeline(arena: Allocator, items: []const feed.TimelineItem, now: i64) error{OutOfMemory}![]PostView {
    const out = try arena.alloc(PostView, items.len);
    for (items, out) |it, *pv| {
        const name = if (it.author_display_name.len > 0) it.author_display_name else it.author_handle;
        pv.* = .{
            .name = name,
            .handle = try std.fmt.allocPrint(arena, "@{s}", .{it.author_handle}),
            .age = try ageStr(arena, now, it.created_at),
            .body = it.text,
            .tint = tintFor(it.author_handle),
            .reply = it.reply_count,
            .boost = it.repost_count,
            .like = it.like_count,
            .initial = initialOf(name),
            .liked = it.item_flags.viewer_liked,
            .boosted = it.item_flags.viewer_reposted,
        };
    }
    return out;
}

/// Mirrors timeline_ui.formatAge's unit logic (seconds), kept local so the
/// view does not drag the whole timeline module into its graph (F1 spirit).
fn ageStr(arena: Allocator, now: i64, created: i64) error{OutOfMemory}![]const u8 {
    const d = if (now > created) now - created else 0;
    if (d < 60) return arena.dupe(u8, "now");
    if (d < 3_600) return std.fmt.allocPrint(arena, "{d}m", .{@divFloor(d, 60)});
    if (d < 86_400) return std.fmt.allocPrint(arena, "{d}h", .{@divFloor(d, 3_600)});
    if (d < 604_800) return std.fmt.allocPrint(arena, "{d}d", .{@divFloor(d, 86_400)});
    return std.fmt.allocPrint(arena, "{d}w", .{@divFloor(d, 604_800)});
}

const avatar_tints = [_]u32{ 0xFFCAA3A8, 0xFF9FC7A0, 0xFFE0C074, 0xFFA9B6D6, 0xFFD6A87F, 0xFFB5A9CC };

/// Deterministic muted tint from the handle (FNV-1a) — same author, same
/// colour, every frame, with no per-author state to store.
fn tintFor(handle: []const u8) u32 {
    var x: u64 = 1469598103934665603;
    for (handle) |b| {
        x ^= b;
        x *%= 1099511628211;
    }
    return avatar_tints[@intCast(x % avatar_tints.len)];
}

fn initialOf(name: []const u8) u8 {
    for (name) |ch| if (ch > ' ' and ch < 128) return ch;
    return '#';
}

test "fromTimeline: display-name fallback, counts, age, deterministic tint" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const items = [_]feed.TimelineItem{
        .{ .uri = "", .cid = "", .author_handle = "mara.zat", .author_display_name = "Mara Vesper", .reposted_by_handle = "", .replying_to_handle = "", .text = "hello field", .created_at = 1000, .like_count = 48, .repost_count = 9, .reply_count = 6, .quote_count = 0, .label_flags = .{}, .item_flags = .{ .viewer_liked = true } },
        .{ .uri = "", .cid = "", .author_handle = "oko.zat", .author_display_name = "", .reposted_by_handle = "", .replying_to_handle = "", .text = "monospace", .created_at = 0, .like_count = 73, .repost_count = 18, .reply_count = 24, .quote_count = 0, .label_flags = .{}, .item_flags = .{} },
    };
    const out = try fromTimeline(arena, &items, 1000 + 120);

    try std.testing.expectEqualStrings("Mara Vesper", out[0].name);
    try std.testing.expectEqualStrings("@mara.zat", out[0].handle);
    try std.testing.expectEqualStrings("2m", out[0].age);
    try std.testing.expectEqual(@as(u32, 48), out[0].like);
    try std.testing.expectEqual(@as(u8, 'M'), out[0].initial);
    try std.testing.expect(out[0].liked);
    try std.testing.expect(!out[1].liked);
    // empty display name falls back to the handle
    try std.testing.expectEqualStrings("oko.zat", out[1].name);
    try std.testing.expectEqual(@as(u8, 'o'), out[1].initial);
    // tint is a pure function of the handle
    try std.testing.expectEqual(tintFor("mara.zat"), out[0].tint);
}

test "layout emits 3 tap regions per post; hitTest resolves each at its center" {
    const gpa = std.testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);
    var regions: Regions = .empty;
    defer regions.deinit(gpa);

    const posts = [_]PostView{
        .{ .name = "A", .handle = "@a.zat", .age = "1m", .body = "hello there field", .tint = 0xFFAAAAAA, .reply = 1, .boost = 2, .like = 3, .initial = 'A', .liked = true, .boosted = false },
    };
    const h = try layout(gpa, &engine, 460, 940, &posts, 0, &dl, &regions, null);
    try std.testing.expect(h > 112); // content extends below the top bar
    try std.testing.expectEqual(@as(usize, 3), regions.items.len);

    var saw_like = false;
    for (regions.items) |r| {
        const cxp = @as(i32, r.x) + @as(i32, r.w) / 2;
        const cyp = @as(i32, r.y) + @as(i32, r.h) / 2;
        const hit = hitTest(regions.items, cxp, cyp) orelse return error.NoHit;
        try std.testing.expectEqual(r.kind, hit.kind);
        try std.testing.expectEqual(@as(u16, 0), hit.post);
        if (r.kind == .like) saw_like = true;
    }
    try std.testing.expect(saw_like);
    // a click far outside every region resolves to nothing
    try std.testing.expect(hitTest(regions.items, 5, 5) == null);
}

test "long timeline does not overflow draw coordinates (off-screen posts skipped)" {
    const gpa = std.testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);
    var regions: Regions = .empty;
    defer regions.deinit(gpa);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // 800 posts would push y well past the 16-bit draw coordinate limit if
    // every post were painted — this is exactly the crash from a real feed.
    const n: usize = 800;
    const posts = try arena.alloc(PostView, n);
    for (posts) |*pv| pv.* = .{ .name = "x", .handle = "@x.zat", .age = "1m", .body = "a body line that wraps a little across the feed column width here", .tint = 0xFF888888, .reply = 1, .boost = 2, .like = 3, .initial = 'x', .liked = false, .boosted = false };

    const h = try layout(gpa, &engine, 460, 940, posts, 0, &dl, &regions, null); // must not panic
    try std.testing.expect(h > 940 * 10); // height accounts for the whole list
    try std.testing.expect(regions.items.len < 3 * 24); // only on-screen posts are tappable

    // The height cache (the scroll-lag fix) must yield IDENTICAL geometry. A
    // first pass with an all-(-1) cache measures + fills it; a second pass that
    // reuses the filled cache (the per-frame scroll path) must return the same
    // total height and the same tappable region set — i.e. the cached advance
    // reconstructs body_end exactly. A regression here means cached scrolling
    // would drift from a fresh layout.
    const heights = try arena.alloc(i32, n);
    @memset(heights, -1);
    dl.len = 0;
    regions.clearRetainingCapacity();
    const h_fill = try layout(gpa, &engine, 460, 940, posts, 0, &dl, &regions, heights);
    const fill_regions = regions.items.len;
    dl.len = 0;
    regions.clearRetainingCapacity();
    const h_cached = try layout(gpa, &engine, 460, 940, posts, 0, &dl, &regions, heights);
    try std.testing.expectEqual(h, h_fill);
    try std.testing.expectEqual(h, h_cached);
    try std.testing.expectEqual(fill_regions, regions.items.len);
}
