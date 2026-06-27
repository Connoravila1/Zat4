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
const lens_socket = @import("lens_socket.zig");
const text_select = @import("text_select.zig");

// Palette, copied from field.zig so the view never reaches across a module
// for a constant (D4: only the value crosses, by copy). ARGB.
const bg: u32 = 0xFF181812;
const ink: u32 = 0xFFEDEAE0;
const body_c: u32 = 0xFFD8D3C8;
const muted: u32 = 0xFF9A968A;
const faint: u32 = 0xFF6A655A;
/// The HOUSE accent (amber) — the default and the composer's fixed accent.
/// On Home the live accent is the SEATED LENS's palette color (§11.5),
/// threaded into `layout` as `accent` and passed down to the chrome; this
/// const is the fallback for surfaces with no seated lens.
pub const accent_house: u32 = 0xFFE8B84B;
/// Text-selection highlight (translucent steel, drawn behind selected glyphs).
const sel_fill: u32 = 0x553A6EA5;
const like_c: u32 = 0xFFF0617A;
const boost_c: u32 = 0xFF8FD18F;
/// Resting engagement-icon colour — a soft neutral grey-white (no blue cast),
/// so the reply, repost, and hollow-heart icons read as one calm set without
/// pulling cool/blue or going bright white.
const icon_grey: u32 = 0xFFB4B1A8;
const veil: u32 = 0xD4181812; // ~83% over the field — texture glows faintly through
const header_veil: u32 = 0xF2181812; // ~95%: the sticky top bar, drawn OVER the posts so
// they scroll BEHIND it (firmly dimmed), the title/tabs crisp on top — a frosted header
// ambient-texture slice will lower this so the living field glows through.
const divider: u32 = 0x18EDEAE0; // ~9% ink hairline

/// Which control a hit region belongs to. The button slice maps these to
/// effects/writes; the view only reports geometry (B5). `nav` (a left-rail
/// destination; the region's `post` field carries the Screen index) and
/// `compose` (the New-post button) route navigation rather than engagement.
/// `compose_send` / `compose_cancel` are the premium composer's footer buttons
/// (the shell turns a tap into the same control byte the keyboard sends).
pub const Action = enum(u8) { reply, repost, like, nav, compose, author, edit_profile, compose_send, compose_cancel, post_body, back, reveal_new, bookmark, share, more, profile_tab, loadout_tab, collapse };

/// The six top-level rail destinations, in order. The `Screen` index a nav
/// region carries is an index into this. Shared by the rail (draw + hit) and
/// the body (the screen title), so the two never drift.
/// Rail destinations. Slot 4 is "Algorithms" (the loadout page) — it took the
/// old Profile slot, since the bottom-left "you" card already opens Profile.
pub const nav_labels = [_][]const u8{ "Home", "Explore", "Activity", "Messages", "Algorithms", "Settings" };

/// Named screen indices. The rail nav posts its index as the screen; slots
/// rendered as real surfaces (home, loadout) have their own branch, the rest
/// fall through to a placeholder.
pub const screen_home: u8 = 0;
/// The loadout page — the rail's "Algorithms" slot (index 4). Renders the
/// three per-surface sockets (feed / replies / zones) stacked for editing.
pub const screen_loadout: u8 = 4;
/// The rail's "Settings" slot (index 5) — the gear nav icon.
pub const screen_settings: u8 = 5;
/// A transient sub-screen (not a rail destination): a post's thread, shown when
/// a post body is tapped. Past the nav labels, so the rail highlights none.
pub const screen_thread: u8 = 6;
/// Profile is no longer a rail slot; reached via the bottom-left "you" card
/// and avatar taps (which set this screen explicitly). Off the rail range.
pub const screen_profile: u8 = 7;

/// The profile screen's header band — the viewed account's identity over its
/// post list. Plain data handed in by the shell (B5); the post count is the
/// number of posts fetched for the profile. A7.2: cold struct — one per frame,
/// never held in a collection, so no size guard.
pub const ProfileHeader = struct {
    display_name: []const u8,
    handle: []const u8, // already "@handle" form, as the post rows carry it
    post_count: u32,
    /// True when this is the viewer's OWN profile — draws an "Edit profile"
    /// button (a `.edit_profile` tap region) so they can set their display name.
    editable: bool = false,
};

/// The kind of composition the premium composer is hosting — sets the context
/// line, the placeholder, and the send-button label. Reply is distinguished
/// from a fresh post by a non-empty target handle (the shell already tracks the
/// reply target separately; this only drives the look).
pub const ComposeContext = enum(u8) { post, reply, profile };

/// A pen position (where the next glyph — and so the text cursor — would land)
/// returned by the draft wrapper. A7.2: cold — a single transient value per
/// compose frame, never held in a collection.
const Pen = struct { x: i32, baseline: i32 };

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

/// The rooted post's body glyphs, for read-only text selection, are produced
/// here and consumed by `text_select` (the deep module that owns the selection
/// math); the glyph vocabulary lives there, aliased here for the producers.
pub const SelGlyph = text_select.Glyph;
pub const SelGlyphs = text_select.Glyphs;

/// The chain (OP stitched self-thread) extent, reported by `layout` so the shell
/// can draw the sticky "chain header" that pins while you scroll the chain and is
/// pushed out at its end. Offsets are CONTENT-space (scroll-independent): the
/// shell computes screen-y as `off + scroll`. A7.2: cold — one transient per
/// layout call, never collected.
pub const ChainSticky = struct {
    present: bool = false,
    head_index: u32 = 0, // index into `posts` for the chain header's identity
    top_off: i32 = 0, // chain header content top
    bottom_off: i32 = 0, // chain end content top (first non-chain post, or thread end)
    pin_y: i32 = 0, // where the sticky pins (the feed origin, below the top bar)
};

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
    /// "@handle" of the post this replies to, or "" — drives the feed's
    /// "Replying to @x" context line so a reply doesn't read as a standalone
    /// post (Twitter/Bluesky parity).
    replying_to: []const u8 = "",
    tint: u32, // avatar fill (ARGB)
    reply: u32,
    boost: u32,
    like: u32,
    initial: u8, // avatar letter (ASCII)
    liked: bool,
    boosted: bool,
    /// Thread nesting depth (0 = root) + whether this is the focused post —
    /// VIEW-DERIVED (the reader's lens), 0/false outside the thread view. Both
    /// ride the tail padding, so the size is unchanged.
    depth: u8 = 0,
    is_focus: bool = false,
    /// The root author's self-reply continuation — render STITCHED (no header,
    /// flush, thin separator) into one continuous post. Rides the tail padding.
    stitched: bool = false,
    /// Thread lens: this post has replies, and the reader has collapsed it.
    has_kids: bool = false,
    collapsed: bool = false,

    comptime {
        // Budget: 5 slices (5×16=80) + 4 u32 (16) + 8 bytes (initial/liked/boosted/
        // depth/is_focus/stitched/has_kids/collapsed) = 104, no padding.
        // (A7.1 raise 88 → 104: the `replying_to` handle is a real view field —
        // the feed's reply-context line needs the parent handle on the
        // view-model. Built for a handful of visible rows, so the +16 is fine.)
        assert(@sizeOf(PostView) == 104);
    }
};

const rail_w: i32 = 248;
const feed_w: i32 = 604;
const side_w: i32 = 352;
/// Height of the sticky PROFILE identity header: the compact horizontal identity
/// band (avatar + name + handle·count + Edit profile) PLUS a profile-nav tab row
/// (Posts · Replies · Media · Likes) below it. Both stay pinned so identity AND
/// the tabs remain visible while posts scroll under them.
const profile_header_h_wide: i32 = 152;
const profile_header_h_narrow: i32 = 134;
/// Home's sticky header grew to seat the LENS SOCKET (it replaces the old
/// Following/Discover tab labels). Title on top, the resting socket below,
/// then the divider — posts start beneath it (feed_y0).
const home_header_h_wide: i32 = 140;
const home_header_h_narrow: i32 = 122;
const socket_y_wide: i32 = 66; // socket top, under the "Home" title
const socket_y_narrow: i32 = 52; // socket top, under the wordmark
/// Profile-nav tabs (visual for now — the regions carry the tab index for a
/// later slice; "Posts" is active). The Links page attaches as another tab.
const profile_tabs = [_][]const u8{ "Posts", "Replies", "Media", "Likes" };

/// The bottom edge (logical y) of the sticky header for a screen — the single
/// source of truth so other passes (e.g. the GPU heart clip) can't drift from
/// the header heights. The GPU feed lays out at the WIDE design width, so these
/// are the wide values; the plain top bar is 111.
pub fn headerBottom(active_screen: u8) i32 {
    if (active_screen == screen_profile) return profile_header_h_wide;
    if (active_screen == screen_home) return home_header_h_wide;
    return 111;
}

/// The logical y the HOME header occludes down to, accounting for the lens
/// socket's OPEN tray (which drops over the posts). The shell clips the
/// separate GPU heart pass to this so hearts behind the open tray don't
/// bleed over it. Resting → the plain home header height. (Wide layout —
/// the GPU path lays out at the design width.)
pub fn homeSocketBottom(socket_tray: ?lens_socket.TrayView, socket_ui: lens_socket.SocketUi) i32 {
    const base = home_header_h_wide;
    const tray = socket_tray orelse return base;
    if (!socket_ui.open) return base;
    return @max(base, socket_y_wide + lens_socket.measuredHeight(tray, socket_ui, homeSocketGeom(wide_min)));
}

/// The exact geometry the Home header lays the socket out at, for a given
/// layout width — so the shell can run `lens_socket.dropIndex` (the drag
/// insertion math) against the same grid the widget drew.
pub fn homeSocketGeom(width: i32) lens_socket.Geometry {
    const m = metricsFor(width);
    return .{ .x = m.lx, .y = if (m.wide) socket_y_wide else socket_y_narrow, .w = m.cw, .scale = 1.0 };
}
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

/// The content column's x-range (logical px) at a given window width — the panel
/// the GPU field softens beneath (the glass backdrop blur). Mirrors metricsFor.
pub fn contentColumn(width: i32) struct { x: i32, w: i32 } {
    const m = metricsFor(width);
    return .{ .x = m.col_x, .w = m.col_w };
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

/// Record the body glyphs just appended to `dl` (the range [from, dl.len)) into
/// `out`: the `.text` items only, each with its advance width and a line index
/// that rises on every baseline jump (so copy can reinsert the line breaks).
/// Pure — called for the rooted post's body alone. Replaces whatever `out` held.
fn captureBody(out: *SelGlyphs, gpa: Allocator, e: *const text.Engine, dl: *const raster.DrawList, from: usize) !void {
    out.clearRetainingCapacity();
    var lineno: u16 = 0;
    var prev_baseline: ?i16 = null;
    var i: usize = from;
    while (i < dl.len) : (i += 1) {
        switch (dl.get(i)) {
            .text => |t| {
                if (prev_baseline) |pb| {
                    if (t.baseline != pb) lineno += 1;
                }
                prev_baseline = t.baseline;
                const adv = text.advance(e, @enumFromInt(t.weight), t.codepoint, t.px);
                try out.append(gpa, .{
                    .cp = t.codepoint,
                    .x = t.x,
                    .baseline = t.baseline,
                    .w = @intCast(@min(@as(u32, std.math.maxInt(u16)), adv)),
                    .line = lineno,
                });
            },
            else => {},
        }
    }
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

/// Bookmark: an outline tag with a V-notch at the bottom.
fn iconBookmark(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, c: u32) !void {
    const f: f32 = @floatFromInt(s);
    const left = x + fxi(f * 0.24);
    const right = x + fxi(f * 0.76);
    const top = y + fxi(f * 0.08);
    const bot = y + fxi(f * 0.92);
    const mid = x + fxi(f * 0.5);
    const notch = y + fxi(f * 0.64);
    try line(gpa, dl, left, top, right, top, c, 2);
    try line(gpa, dl, left, top, left, bot, c, 2);
    try line(gpa, dl, right, top, right, bot, c, 2);
    try line(gpa, dl, left, bot, mid, notch, c, 2);
    try line(gpa, dl, right, bot, mid, notch, c, 2);
}

/// Share: an up-arrow rising out of an open tray (the familiar share glyph).
fn iconShare(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, c: u32) !void {
    const f: f32 = @floatFromInt(s);
    const cx = x + fxi(f * 0.5);
    try line(gpa, dl, cx, y + fxi(f * 0.06), cx, y + fxi(f * 0.62), c, 2); // shaft
    try line(gpa, dl, cx, y + fxi(f * 0.06), x + fxi(f * 0.28), y + fxi(f * 0.30), c, 2); // left head
    try line(gpa, dl, cx, y + fxi(f * 0.06), x + fxi(f * 0.72), y + fxi(f * 0.30), c, 2); // right head
    const left = x + fxi(f * 0.20);
    const right = x + fxi(f * 0.80);
    const ttop = y + fxi(f * 0.46);
    const bot = y + fxi(f * 0.92);
    try line(gpa, dl, left, ttop, left, bot, c, 2);
    try line(gpa, dl, right, ttop, right, bot, c, 2);
    try line(gpa, dl, left, bot, right, bot, c, 2);
}

/// More: three dots (⋯).
fn iconMore(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, c: u32) !void {
    const f: f32 = @floatFromInt(s);
    const r = @max(1, fxi(f * 0.09));
    const cy = y + fxi(f * 0.5);
    for ([_]f32{ 0.16, 0.5, 0.84 }) |px| {
        try rect(gpa, dl, x + fxi(f * px) - r, cy - r, r * 2, r * 2, c, @intCast(r));
    }
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

/// The UNLIKED like button: a HOLLOW heart OUTLINE, so a tap can visibly fill
/// it with red. Traced as the parametric heart curve (x=16sin³t, y=13cos t −
/// 5cos2t − 2cos3t − cos4t) — one clean closed stroke, normalized into the s×s
/// icon box — rather than a scanline fill, which is solid and cannot read as
/// empty. The filled `iconHeart` above is the LIKED state.
fn iconHeartHollow(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, color: u32) !void {
    const f: f32 = @floatFromInt(s);
    const segs: usize = 28;
    var prev_x: i32 = 0;
    var prev_y: i32 = 0;
    var i: usize = 0;
    while (i <= segs) : (i += 1) {
        const t = (@as(f32, @floatFromInt(i)) / @as(f32, @floatFromInt(segs))) * 6.2831853;
        const st = @sin(t);
        const hx = 16.0 * st * st * st;
        const hy = 13.0 * @cos(t) - 5.0 * @cos(2.0 * t) - 2.0 * @cos(3.0 * t) - @cos(4.0 * t);
        // Normalize: hx∈[-16,16] → centred horizontally; hy∈[-17,12], flipped to
        // screen-y-down and centred so the lobes sit high and the point at ~0.96.
        const nx = 0.5 + (hx / 16.0) * 0.46;
        const ny = 0.52 - (hy / 17.0) * 0.44;
        const px = x + fxi(nx * f);
        const py = y + fxi(ny * f);
        if (i > 0) try line(gpa, dl, prev_x, prev_y, px, py, color, 1);
        prev_x = px;
        prev_y = py;
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

/// Sliders / equalizer — "Algorithms" (tuning your lenses). Three rails, each
/// with a knob at a different position, so it reads as adjustable controls.
fn iconAlgorithms(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, c: u32) !void {
    const f: f32 = @floatFromInt(s);
    const x0 = x + fxi(f * 0.10);
    const x1 = x + fxi(f * 0.90);
    const kr = @max(3, fxi(f * 0.16));
    const rows = [_]f32{ 0.24, 0.5, 0.76 };
    const knobs = [_]f32{ 0.66, 0.34, 0.58 };
    for (rows, knobs) |ry, kx| {
        const yy = y + fxi(f * ry);
        try line(gpa, dl, x0, yy, x1, yy, c, 2);
        const cx = x + fxi(f * kx);
        try rect(gpa, dl, cx - @divTrunc(kr, 2), yy - @divTrunc(kr, 2), kr, kr, c, @intCast(@divTrunc(kr, 2)));
    }
}

fn navIcon(idx: usize, gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, c: u32) !void {
    switch (idx) {
        0 => try iconHome(gpa, dl, x, y, s, c),
        1 => try iconSearch(gpa, dl, x, y, s, c),
        2 => try iconHeartHollow(gpa, dl, x, y, s, c),
        3 => try iconReply(gpa, dl, x, y, s, c),
        4 => try iconAlgorithms(gpa, dl, x, y, s, c), // the "Algorithms" loadout page
        else => try iconGear(gpa, dl, x, y, s, c),
    }
}

fn drawRail(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, rx: i32, height: i32, active: usize, regions: ?*Regions, accent: u32, skip_nav: bool) !void {
    const x0 = rx + 14;
    const wm = try str(gpa, dl, e, .semibold, x0 + 8, 58, accent, 26, "zat4");
    _ = try str(gpa, dl, e, .semibold, wm, 58, ink, 26, ".");

    // The nav GROUP (Home…Settings) sits on its OWN box — the logo above and
    // the New-post button below stay on the field, each its own section.
    try rect(gpa, dl, x0 - 2, 94, rail_w - 24, 304, panel, 18);

    var ny: i32 = 108;
    for (nav_labels, 0..) |label, idx| {
        const on = idx == active;
        const col = if (on) ink else muted;
        // A faint accent pill marks the active destination.
        if (on) try rect(gpa, dl, x0 + 2, ny - 8, rail_w - 32, 42, (0x1F << 24) | (accent & 0x00FFFFFF), 12);
        // GPU path: all nav icons are drawn by the SDF-icon pass; only software
        // strokes the line-art. (The active-pill + label + region still emit.)
        if (!skip_nav) try navIcon(idx, gpa, dl, x0 + 10, ny, 22, if (on) accent else muted);
        _ = try str(gpa, dl, e, if (on) .semibold else .regular, x0 + 48, ny + 17, col, 16, label);
        // Full-row tap target → the Screen at this index (post carries it).
        try emitRegion(gpa, regions, rx + 14, ny - 8, rail_w - 28, 42, @intCast(idx), .nav);
        ny += 50;
    }

    ny += 16;
    try rect(gpa, dl, x0 + 6, ny, rail_w - 44, 50, accent, 14);
    const npw: i32 = @intCast(text.measure(e, .semibold, "New post", 16));
    _ = try str(gpa, dl, e, .semibold, x0 + 6 + @divTrunc(rail_w - 44 - npw, 2), ny + 32, bg, 16, "New post");
    try emitRegion(gpa, regions, x0 + 6, ny, rail_w - 44, 50, 0, .compose);

    const by = height - 60;
    // The account card gets its own small box.
    try rect(gpa, dl, x0 - 2, by - 10, rail_w - 24, 58, panel, 16);
    try rect(gpa, dl, x0 + 6, by, 38, 38, 0xFF3F3B2D, 19);
    _ = try str(gpa, dl, e, .semibold, x0 + 54, by + 16, ink, 14, "you");
    _ = try str(gpa, dl, e, .regular, x0 + 54, by + 33, faint, 12, "@you.zat");
    // The "you" card opens the Profile screen (Profile is no longer a rail
    // slot — this card is its entry point, alongside avatar taps).
    try emitRegion(gpa, regions, x0 + 6, by - 4, rail_w - 40, 46, screen_profile, .nav);
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
    /// When true, the per-post engagement HEART icon is NOT drawn — the GPU path
    /// draws it as an SDF heart instead, so it fills + pops IN PLACE. The like
    /// region, count, and reserved space are still emitted. False (software /
    /// preview) draws the heart here as before.
    skip_heart: bool,
    /// The active top-level Screen (index into `nav_labels`). 0 = Home renders
    /// the feed; any other index renders that screen's body (a titled premium
    /// placeholder for now) while the rail + sidebar chrome stay put. The rail
    /// highlights this index.
    active_screen: u8,
    /// The profile header to draw when `active_screen == screen_profile`. The
    /// posts in `posts` are then that account's own posts (read-only Cut 1).
    /// Null on every other screen (Home draws the feed; the rest are
    /// placeholders).
    profile: ?ProfileHeader,
    /// Count of staged-but-unrevealed new posts. When > 0 on Home, a pinned
    /// "N new posts" pill is drawn below the header (a `.reveal_new` tap region).
    pending_new: usize,
    /// The app accent token — the SEATED LENS's palette color on Home
    /// (§11.5), else the house amber. Threaded down to all the chrome that
    /// re-tints (wordmark, active-nav pill + icon, New-post, tab underline,
    /// the socket cartridge). Neutrals (glass, ink, field) ignore it.
    accent: u32,
    /// The home feed's lens tray (the user's carried set, invariant 12);
    /// null = no socket on this surface. On Home it is drawn in the header
    /// — it REPLACES the Following/Discover tab labels (there is no tab
    /// strip; the seated lens is the feed's order).
    socket_tray: ?lens_socket.TrayView,
    socket_ui: lens_socket.SocketUi,
    /// The socket's tap targets for this frame (its own hit space, distinct
    /// from the feed `regions`); the shell tests these first. Null = draw-only.
    socket_hits: ?*lens_socket.HitList,
    /// Out: the chain (OP self-thread) extent for the sticky chain header (thread
    /// screen). Null = don't report.
    chain_out: ?*ChainSticky,
    /// Out: the ROOTED post's body glyphs, for read-only text selection (thread
    /// screen only — the rooted post is the one selectable post, ZONES inv. 4).
    /// Filled when the focused post is laid out; cleared otherwise. Null = the
    /// caller doesn't support selection (software path / preview / tests).
    sel_out: ?*SelGlyphs,
) error{OutOfMemory}!i32 {
    const m = metricsFor(width);
    if (regions) |rg| rg.clearRetainingCapacity();
    if (socket_hits) |sh| sh.clearRetainingCapacity();
    // No focused post laid out this frame ⇒ no selectable body. Cleared up front;
    // refilled only if the rooted post's body is drawn below.
    if (sel_out) |so| so.clearRetainingCapacity();

    // 1. The content column as GLASS floating over the field (P.0, layout layer).
    //    A soft slab shadow falls off both gutter edges so the column reads as a
    //    raised plane (the figure/ground fix), then the glass fill, then a 1px lit
    //    inner edge — the universal "raised surface" cue. (The GPU backdrop blur
    //    of the field UNDER the glass is the finishing layer on the GPU path.)
    if (m.wide) {
        const sw: i32 = 20;
        const steps: i32 = 5;
        const step = @divTrunc(sw, steps);
        var k: i32 = 0;
        while (k < steps) : (k += 1) {
            const t = @as(f32, @floatFromInt(steps - k)) / @as(f32, @floatFromInt(steps));
            const shade: u32 = @as(u32, @intFromFloat(74.0 * t)) << 24; // black, fading out
            try rect(gpa, dl, m.col_x - (k + 1) * step, 0, step, height, shade, 0); // left gutter
            try rect(gpa, dl, m.col_x + m.col_w + k * step, 0, step, height, shade, 0); // right gutter
        }
    }
    try rect(gpa, dl, m.col_x, 0, m.col_w, height, veil, 0); // glass fill
    if (m.wide) {
        try rect(gpa, dl, m.col_x, 0, 1, height, 0x24EDEAE0, 0); // left lit edge
        try rect(gpa, dl, m.col_x + m.col_w - 1, 0, 1, height, 0x24EDEAE0, 0); // right lit edge
    }

    // The feed-column TOP BAR (title, tabs, divider, and its frosted box) is
    // drawn LAST — see drawTopBar at the end — so the posts scroll BEHIND it.
    // Here we only place the rail/sidebar (their own columns, nothing scrolls
    // under them) and fix where the post stack begins.
    var feed_y0: i32 = 112;
    if (m.wide) {
        // 2a. Desktop three-pane: nav rail + sidebar flank the feed. Each
        // SECTION draws its own box (the nav group, the account card, the
        // sidebar cards) so the field stays visible between them.
        try drawRail(gpa, dl, e, m.rail_x, height, active_screen, regions, accent, skip_heart);
        try drawSidebar(gpa, dl, e, m.side_x, height);
        feed_y0 = 126;
    } else {
        feed_y0 = 112;
    }
    // Home seats the socket in its header, so the post stack starts below it.
    if (active_screen == screen_home and socket_tray != null) {
        feed_y0 = if (m.wide) home_header_h_wide + 14 else home_header_h_narrow + 12;
    }

    // The Profile screen draws an identity header band, then falls through to
    // the SAME post loop below (the posts handed in are this account's own —
    // read-only in Cut 1). Every OTHER non-Home screen is still a titled
    // placeholder until it is built.
    if (active_screen == screen_profile) {
        // The identity band is now the STICKY header (drawn pinned in
        // drawProfileHeader, called from drawTopBar) — posts scroll UNDER it, so
        // the handle/name (and, later, profile-level nav like Links) stay visible
        // without scrolling back up. Here we only fix where the post stack begins
        // — just below the header's height.
        feed_y0 = if (m.wide) profile_header_h_wide + 14 else profile_header_h_narrow + 12;
    } else if (active_screen == screen_thread) {
        // A post's thread: the `posts` handed in ARE the thread (ancestors, the
        // focused post, then replies, in that order) — fall through to the post
        // loop. The top bar shows "Thread" + a back button (drawTopBar).
    } else if (active_screen != 0) {
        const msg = "Coming soon";
        const tw: i32 = @intCast(text.measure(e, .regular, msg, 16));
        _ = try str(gpa, dl, e, .regular, m.col_x + @divTrunc(m.col_w - tw, 2), @divTrunc(height, 2), muted, 16, msg);
        try drawTopBar(gpa, dl, e, m, active_screen, regions, profile, accent, socket_tray, socket_ui, socket_hits); // no posts scroll here, but keep the title consistent
        return height;
    }

    // 3. Posts. On the THREAD screen the view nests: each post is indented by its
    // (view-derived) depth and gets vertical guide rails for its ancestor levels,
    // with a smaller avatar so the staircase fits the column. Depth is 0 on every
    // other screen, so this collapses to the flat feed there.
    const is_thread = active_screen == screen_thread;
    const av: i32 = if (is_thread) 32 else 46;
    const gap: i32 = 13;
    const indent_step: i32 = 30;
    const max_levels: i32 = 7; // cap the indent so a deep thread can't run off-column
    const init_px: u16 = if (is_thread) 17 else 22;
    const av_base: i32 = @divTrunc(av * 2, 3) + 1; // avatar-initial baseline within the disc
    const body_line: i32 = @max(23, @as(i32, @intCast(text.lineMetrics(e, .regular, 16).height)));

    // THE REPLY SOCKET (thread screen). It sits after the root + the author's
    // leading self-thread run (consecutive posts by the root author), before
    // everyone else's replies. All-same-author → end of the thread. `*_at` is
    // the post index it precedes; == posts.len means "after the last post".
    const reply_socket_at: usize = blk: {
        if (!is_thread or socket_tray == null or posts.len == 0) break :blk std.math.maxInt(usize);
        var i: usize = 1;
        while (i < posts.len) : (i += 1) {
            if (!std.mem.eql(u8, posts[i].handle, posts[0].handle)) break :blk i;
        }
        break :blk posts.len; // all the same author → end of thread
    };
    // Narrower than the feed socket, inset to sit within the reply column.
    const reply_inset: i32 = 26;

    // Chain (OP self-thread) extent tracking for the sticky chain header.
    var chain_seen_head = false;
    var chain_ended = false;
    var chain_top_off: i32 = 0;
    var chain_bottom_off: i32 = 0;
    var chain_head_idx: u32 = 0;

    var y: i32 = feed_y0 + scroll;
    for (posts, 0..) |p, pi| {
        // The reply socket precedes this post (its seam in the thread).
        if (pi == reply_socket_at) if (socket_tray) |st| {
            const sg: lens_socket.Geometry = .{ .x = m.lx + reply_inset, .y = y, .w = m.cw - reply_inset * 2, .scale = 1.0 };
            const sh = lens_socket.measuredHeight(st, socket_ui, sg);
            if (y + sh > 0 and y < height) _ = try lens_socket.build(gpa, e, st, socket_ui, sg, dl, socket_hits);
            y += sh + 18;
        };
        var nb: [12]u8 = undefined;
        const post_top = y;

        // Re-root ANCESTOR (condensed context above the re-rooted post): a smaller
        // avatar + dimmed name/body, tappable to re-root on it, linked by a thin
        // connector down the chain. Drawn compact; skips the full post render.
        if (is_thread and p.depth == feed.thread_ancestor_depth) {
            const aav: i32 = 22;
            const agap: i32 = 10;
            const aax = m.lx;
            const acx = aax + aav + agap;
            const acw = m.cw - aav - agap;
            const aline: i32 = @max(19, @as(i32, @intCast(text.lineMetrics(e, .regular, 13).height)));
            const abody_top: i32 = post_top + 14 + aline;
            const acached: ?i32 = if (heights) |hh| (if (pi < hh.len and hh[pi] >= 0) hh[pi] else null) else null;
            var anext_y: i32 = undefined;
            if (acached) |adv| {
                anext_y = post_top + adv;
            } else {
                const abe = try wrapBody(gpa, dl, e, acx, abody_top, acw, muted, 13, p.body, aline, false);
                anext_y = abe + 16;
                if (heights) |hh| if (pi < hh.len) {
                    hh[pi] = anext_y - post_top;
                };
            }
            if (anext_y > 0 and post_top < height) {
                try emitRegion(gpa, regions, m.col_x, post_top, m.col_w, @intCast(@max(0, @min(32767, anext_y - post_top))), @intCast(pi), .post_body);
                try rect(gpa, dl, aax, post_top, aav, aav, p.tint, @intCast(aav >> 1));
                const aiadv: i32 = @intCast(text.advance(e, .semibold, p.initial, 13));
                _ = try glyph1(gpa, dl, e, .semibold, aax + @divTrunc(aav - aiadv, 2), post_top + 16, bg, 13, p.initial);
                try emitRegion(gpa, regions, aax, post_top, aav, @intCast(aav), @intCast(pi), .author);
                const abx = try str(gpa, dl, e, .semibold, acx, post_top + 13, muted, 14, p.name);
                _ = try str(gpa, dl, e, .regular, abx + 7, post_top + 13, faint, 11, p.handle);
                _ = try wrapBody(gpa, dl, e, acx, abody_top, acw, muted, 13, p.body, aline, true);
                // Connector down the avatar column linking the chain to the focus.
                try rect(gpa, dl, aax + @divTrunc(aav, 2) - 1, post_top + aav, 2, anext_y - (post_top + aav), 0x44B7B3A8, 0);
            }
            y = anext_y;
            continue;
        }

        // Chain extent: the first non-ancestor post is the chain HEAD; the chain
        // runs through its stitched continuation; the first non-stitched post
        // after it ends the chain (where the regular replies begin).
        if (is_thread) {
            if (!chain_seen_head) {
                chain_seen_head = true;
                chain_head_idx = @intCast(pi);
                chain_top_off = post_top - scroll;
            } else if (!p.stitched and !chain_ended) {
                chain_bottom_off = post_top - scroll;
                chain_ended = true;
            }
        }

        // View-derived nesting geometry (thread screen only).
        const dep: i32 = if (is_thread) @min(@as(i32, p.depth), max_levels) else 0;
        const indent: i32 = dep * indent_step;
        const ax = m.lx + indent; // avatar left
        const cx = ax + av + gap; // text/body left
        const content_w = m.cw - indent - av - gap;
        // A reply reserves a row for its "Replying to @x" context line above the
        // body — but ONLY on the flat feed; in a thread the rails already convey
        // the relationship. Stable per post, so the height cache stays valid.
        const show_reply_to = !is_thread and p.replying_to.len > 0;
        const reply_h: i32 = if (show_reply_to) 19 else 0;
        // A stitched segment (the root author continuing their own thread) drops
        // the header — no avatar, no name row — and starts the body near the top,
        // joined to the post above by a thin separator. Non-stitched posts keep
        // the name row above the body.
        const stitch = is_thread and p.stitched;
        const body_top_off: i32 = if (stitch) (14 + body_line) else (18 + reply_h + body_line);
        // "Chain" = the OP's stitched self-thread. A post is in the chain if it is
        // a stitched segment OR the header immediately above one. Chain posts use
        // the vertical stem + per-post elbow instead of a horizontal divider.
        const next_stitched = is_thread and pi + 1 < posts.len and posts[pi + 1].stitched;
        const in_chain = is_thread and (p.stitched or next_stitched);

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
            body_end = next_y - 60;
        } else {
            body_end = try wrapBody(gpa, dl, e, cx, post_top + body_top_off, content_w, body_c, 16, p.body, body_line, false);
            next_y = body_end + 60;
            if (heights) |hh| if (pi < hh.len) {
                hh[pi] = next_y - post_top;
            };
        }
        // Roomier vertical rhythm (was 48): more air between body→actions and
        // post→post, so the feed doesn't read cramped. body_end + 60 = erow(+22)
        // + row(+22) + gap(+16). Keep the cache reconstruction above in sync.
        const erow = body_end + 22;
        const bottom = erow + 22;
        const visible = next_y > 0 and post_top < height;

        if (visible) {
            // The focused post (thread screen): a neutral light-grey wash behind
            // it (NOT the accent — that clashed with the socket colour and muddied
            // the accent selection drawn on top). A touch stronger than the hover
            // wash (~0x16 white) so the focus still reads. Drawn first; everything
            // else sits on top.
            if (p.is_focus) try rect(gpa, dl, m.col_x, post_top - 6, m.col_w, (next_y - post_top), (0x1A << 24) | 0x00FFFFFF, 8);

            // Chain stem + elbow: a continuous vertical line at the OP avatar
            // column runs down through the headerless continuation segments
            // (tying them into one post), and turns with a SHARP right-angle
            // elbow into each segment. The header (avatar present) anchors the top
            // of the stem; segments branch off it. No horizontal divider in the
            // chain (handled below) — the stem + elbow are the structure.
            if (in_chain) {
                const sx = m.lx + @divTrunc(av, 2) - 1;
                const top = if (p.stitched) post_top else post_top + av; // stitched: row top; header: avatar bottom
                try rect(gpa, dl, sx, top, 2, next_y - top, 0x44B7B3A8, 0); // vertical spine
                if (p.stitched) {
                    // Elbow: turn right from the spine into this segment's body
                    // (sharp corner — two rects meeting, no curve).
                    const ey = post_top + body_top_off - body_line + 4; // ~first body line
                    try rect(gpa, dl, sx, ey, (cx - 10) - sx, 2, 0x44B7B3A8, 0);
                }
            }

            // Whole-post tap target → open this post's thread. Emitted FIRST so
            // the avatar + engagement regions (emitted after, found first in the
            // reverse hit-test) punch through it — "whole post minus carve-outs".
            try emitRegion(gpa, regions, m.col_x, post_top, m.col_w, @intCast(@max(0, @min(32767, bottom - post_top))), @intCast(pi), .post_body);

            // Nesting rails: a thin vertical guide at each ancestor level's avatar
            // column, spanning the row. DFS order keeps a subtree contiguous, so
            // consecutive rows form one continuous line per level (the Reddit rail).
            if (is_thread and dep > 0) {
                var l: i32 = 0;
                while (l < dep) : (l += 1) {
                    const rx = m.lx + l * indent_step + @divTrunc(av, 2);
                    try rect(gpa, dl, rx, post_top - 6, 2, (next_y - post_top), 0x33B7B3A8, 0);
                }
            }

            // Stitched continuation (root author's own chain): NO header — no
            // avatar, no name row — so the body flows directly under the previous
            // segment in the OP's column (the avatar gutter stays empty, reading as
            // one continuous post). The thin separator between segments is the
            // per-post bottom divider below (each segment sits at depth 0).
            if (!stitch) {
                // avatar disc + initial — tapping it opens that author's profile.
                try rect(gpa, dl, ax, post_top, av, av, p.tint, @intCast(av >> 1));
                const iadv: i32 = @intCast(text.advance(e, .semibold, p.initial, init_px));
                _ = try glyph1(gpa, dl, e, .semibold, ax + @divTrunc(av - iadv, 2), post_top + av_base, bg, init_px, p.initial);
                try emitRegion(gpa, regions, ax, post_top, av, @intCast(av), @intCast(pi), .author);

                // name · handle · age — three weight TIERS, baseline-aligned (P.1):
                // the name is STRONG (heaviest, brightest, biggest 18px) so the eye
                // lands there first; handle + · + age are MUTED metadata (faint,
                // smaller 13px) that recede. Body is the PRIMARY tier below.
                var bx = try str(gpa, dl, e, .semibold, cx, post_top + 18, ink, 18, p.name);
                bx = try str(gpa, dl, e, .regular, bx + 9, post_top + 18, faint, 13, p.handle);
                bx = try str(gpa, dl, e, .regular, bx + 7, post_top + 18, faint, 13, "·");
                _ = try str(gpa, dl, e, .regular, bx + 7, post_top + 18, faint, 13, p.age);

                // "Replying to @x" with a subtle ↳ hook — reads as a threaded reply
                // rather than a standalone post (Twitter/Bluesky parity).
                if (show_reply_to) {
                    const hk = try str(gpa, dl, e, .regular, cx, post_top + 36, faint, 13, "\xE2\x86\xB3 ");
                    const rl = try str(gpa, dl, e, .regular, hk, post_top + 36, muted, 13, "Replying to ");
                    _ = try str(gpa, dl, e, .regular, rl, post_top + 36, accent, 13, p.replying_to);
                }
            }

            // Collapse toggle (Reddit-style): a nested reply WITH replies gets a
            // small −/+ on its thread-line column; tapping it hides/shows the
            // subtree (per-view state, never on the post). Stitched OP segments
            // are one continuous post, so they have no toggle.
            if (is_thread and !stitch and dep > 0 and p.has_kids) {
                const tgx = ax + @divTrunc(av, 2);
                const sym: u21 = if (p.collapsed) '+' else '-';
                const sadv: i32 = @intCast(text.advance(e, .semibold, sym, 15));
                _ = try glyph1(gpa, dl, e, .semibold, tgx - @divTrunc(sadv, 2), post_top + av + 16, muted, 15, sym);
                try emitRegion(gpa, regions, tgx - 12, post_top + av + 2, 24, 24, @intCast(pi), .collapse);
            }

            // body (draw)
            const body_from = dl.len;
            _ = try wrapBody(gpa, dl, e, cx, post_top + body_top_off, content_w, body_c, 16, p.body, body_line, true);
            // The rooted post (thread screen) is the one selectable post: capture
            // its body glyphs for the read-only selection layer (ZONES inv. 4 —
            // selection is a query over this transient map, never a stored copy).
            if (is_thread and p.is_focus) if (sel_out) |so| try captureBody(so, gpa, e, dl, body_from);

            // Engagement row — roomier spacing + a fuller action set. LEFT group:
            // reply · repost · like (icon + count); RIGHT group: bookmark · share ·
            // more, right-aligned (decorative for now — the regions carry the post
            // so hover can highlight them and a later slice can wire them).
            const is: i32 = 17;
            const iy = erow - 13;
            const tap_h: u16 = 32;
            const tap_y: i32 = erow - 21;
            const cgap: i32 = 9; // icon → count
            const ggap: i32 = 36; // count → next group's icon (the "less cramped" gap)
            const slot_w: i32 = is + cgap + 18; // generous tap target per item
            var ex = cx;
            const reply_x = ex;
            // GPU path: the SDF-icon pass draws all these crisply in place; only
            // the software path strokes the line-art. Counts + regions still emit.
            if (!skip_heart) try iconReply(gpa, dl, ex, iy, is, icon_grey);
            ex += is + cgap;
            ex = try str(gpa, dl, e, .regular, ex, erow, muted, 13, std.fmt.bufPrint(&nb, "{d}", .{p.reply}) catch "0");
            try emitRegion(gpa, regions, reply_x, tap_y, slot_w, tap_h, @intCast(pi), .reply);
            ex = reply_x + slot_w + ggap;
            const rt_x = ex;
            // On the GPU path (skip_heart) the SDF-icon pass draws the repost
            // crisply in place — like the heart; here only the software path
            // strokes the line-art version. The count + region still emit below.
            if (!skip_heart) try iconRepost(gpa, dl, ex, iy, is, if (p.boosted) boost_c else icon_grey);
            ex += is + cgap;
            _ = try str(gpa, dl, e, .regular, ex, erow, if (p.boosted) boost_c else muted, 13, std.fmt.bufPrint(&nb, "{d}", .{p.boost}) catch "0");
            try emitRegion(gpa, regions, rt_x, tap_y, slot_w, tap_h, @intCast(pi), .repost);
            const like_x = rt_x + slot_w + ggap;
            // Liked → FILLED red heart; unliked → HOLLOW outline. On the GPU path
            // this is SKIPPED — the SDF heart pass draws it in place.
            if (!skip_heart) {
                if (p.liked) {
                    try iconHeart(gpa, dl, like_x, iy, is, like_c);
                } else {
                    try iconHeartHollow(gpa, dl, like_x, iy, is, icon_grey);
                }
            }
            _ = try str(gpa, dl, e, .regular, like_x + is + cgap, erow, if (p.liked) like_c else muted, 13, std.fmt.bufPrint(&nb, "{d}", .{p.like}) catch "0");
            try emitRegion(gpa, regions, like_x, tap_y, slot_w, tap_h, @intCast(pi), .like);

            // RIGHT group: bookmark · share · more, right-aligned at the content
            // edge. A stitched segment shows the COMPACT row (reply/repost/like
            // only — image #2), so the right group is omitted there.
            if (!stitch) {
                const rgap: i32 = 32;
                var rxp = cx + content_w - is;
                if (!skip_heart) try iconMore(gpa, dl, rxp, iy, is, icon_grey);
                try emitRegion(gpa, regions, rxp - 7, tap_y, is + 14, tap_h, @intCast(pi), .more);
                rxp -= rgap;
                if (!skip_heart) try iconShare(gpa, dl, rxp, iy, is, icon_grey);
                try emitRegion(gpa, regions, rxp - 7, tap_y, is + 14, tap_h, @intCast(pi), .share);
                rxp -= rgap;
                if (!skip_heart) try iconBookmark(gpa, dl, rxp, iy, is, icon_grey);
                try emitRegion(gpa, regions, rxp - 7, tap_y, is + 14, tap_h, @intCast(pi), .bookmark);
            }

            // divider — full-width on the flat feed; the thread uses a short
            // divider under the indented content. CHAIN posts get NO horizontal
            // divider — the vertical stem + elbow are their separation instead.
            if (is_thread) {
                if (!in_chain) try rect(gpa, dl, ax, bottom, m.col_x + m.col_w - ax - 4, 1, divider, 0);
            } else {
                try rect(gpa, dl, m.col_x, bottom, m.col_w, 1, divider, 0);
            }
        }
        y = next_y;
    }
    // All-same-author thread: the reply socket lands at the very end.
    if (is_thread and reply_socket_at == posts.len) if (socket_tray) |st| {
        const sg: lens_socket.Geometry = .{ .x = m.lx + reply_inset, .y = y, .w = m.cw - reply_inset * 2, .scale = 1.0 };
        const sh = lens_socket.measuredHeight(st, socket_ui, sg);
        if (y + sh > 0 and y < height) _ = try lens_socket.build(gpa, e, st, socket_ui, sg, dl, socket_hits);
        y += sh + 18;
    };
    // The sticky top bar, drawn LAST so the posts above scroll BEHIND its
    // frosted box with the title/tabs crisp on top.
    try drawTopBar(gpa, dl, e, m, active_screen, regions, profile, accent, socket_tray, socket_ui, socket_hits);

    // The "N new posts" pill (Home only): staged arrivals waiting to be revealed.
    // Pinned just below the header, centered; tapping it reveals + scrolls to top
    // — the reader is never displaced involuntarily (Twitter/Bluesky pattern).
    if (active_screen == screen_home and pending_new > 0) {
        var pb: [40]u8 = undefined;
        const label = std.fmt.bufPrint(&pb, "\xE2\x86\x91 {d} new post{s}", .{ pending_new, if (pending_new == 1) "" else "s" }) catch "new posts";
        const lw: i32 = @intCast(text.measure(e, .semibold, label, 14));
        const pw = lw + 40;
        const pill_h: i32 = 38;
        const px = m.col_x + @divTrunc(m.col_w - pw, 2);
        const py: i32 = if (m.wide) 120 else 104;
        try rect(gpa, dl, px, py, pw, pill_h, accent, 19);
        _ = try str(gpa, dl, e, .semibold, px + 20, py + 25, bg, 14, label);
        try emitRegion(gpa, regions, px, py, pw, pill_h, 0, .reveal_new);
    }
    if (chain_out) |co| co.* = .{
        .present = is_thread and chain_seen_head,
        .head_index = chain_head_idx,
        .top_off = chain_top_off,
        .bottom_off = if (chain_ended) chain_bottom_off else (y - scroll), // all-chain → thread end
        .pin_y = feed_y0,
    };
    return y - scroll; // total content height (scroll-independent), for clamping
}

/// Scale a color's alpha by `al` (0..1), keeping its RGB — for fading an overlay.
fn aScale(c: u32, al: f32) u32 {
    const a8: u32 = @intFromFloat(@as(f32, @floatFromInt(c >> 24)) * std.math.clamp(al, 0.0, 1.0));
    return (a8 << 24) | (c & 0x00FFFFFF);
}

/// Draw the sticky CHAIN header bar into `dl` (a shell overlay): a frosted band
/// across the feed column with the chain author's avatar + display name + @handle,
/// faded by `alpha`. The bar is clamped to start at `pin_y` (so it grows out from
/// under the top bar during the catch-up rather than covering it); the avatar +
/// text center vertically in the visible band. The shell positions `draw_y` (the
/// pure-sticky + catch-up math) and animates `alpha`.
pub fn buildChainHeaderBar(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, width: i32, draw_y: i32, header_h: i32, pin_y: i32, tint: u32, initial: u21, name: []const u8, handle: []const u8, accent: u32, alpha: f32) error{OutOfMemory}!void {
    _ = accent;
    _ = pin_y;
    const m = metricsFor(width);
    // The frosted band fills from the thread top bar's BOTTOM (drawTopBar box_h:
    // 111 wide / 96 narrow) down to the header — so it CONNECTS to the "Thread"
    // bar with no gap (the content still rides at `draw_y` for the seamless seam).
    const band_top: i32 = if (m.wide) 111 else 96;
    const band_bottom = draw_y + header_h;
    if (band_bottom > band_top) {
        try rect(gpa, dl, m.col_x, band_top, m.col_w, band_bottom - band_top, aScale(header_veil, alpha), 0);
        try rect(gpa, dl, m.col_x, band_bottom - 1, m.col_w, 1, aScale((0x66 << 24) | (divider & 0x00FFFFFF), alpha), 0);
    }
    // Avatar + name + @handle drawn at the EXACT geometry of the inline thread
    // header (av=32, gap=13, avatar initial baseline +22 @17px, name +18 @18px ink,
    // handle @13px faint) so when `draw_y` == the inline post_top the pinned bar is
    // pixel-identical to the original — the scroll-up handoff has no seam.
    const av: i32 = 32;
    const gap: i32 = 13;
    const ax = m.lx;
    try rect(gpa, dl, ax, draw_y, av, av, aScale(tint, alpha), @intCast(av >> 1));
    const iadv: i32 = @intCast(text.advance(e, .semibold, initial, 17));
    _ = try glyph1(gpa, dl, e, .semibold, ax + @divTrunc(av - iadv, 2), draw_y + 22, aScale(bg, alpha), 17, initial);
    const cx = ax + av + gap;
    const nx = try str(gpa, dl, e, .semibold, cx, draw_y + 18, aScale(ink, alpha), 18, name);
    _ = try str(gpa, dl, e, .regular, nx + 9, draw_y + 18, aScale(faint, alpha), 13, handle);
}

/// The end pen and the caret pen returned by the draft wrapper.
/// A7.2: cold — a single transient value per compose frame, never collected.
const DraftPens = struct { end: Pen, caret: Pen };

/// Word-wrap `draft` into `maxw`, honouring explicit '\n' line breaks, drawing
/// as it goes. Returns the pen after the last glyph AND the pen at byte offset
/// `caret_at` — the composer now supports mid-text editing, so the caret can sit
/// anywhere, not only at the end. A word longer than the column is not split
/// mid-word (it overhangs) — drafts are short and this keeps the wrapper a single
/// honest pass. The inverse query (a click → byte offset) is `composeCaretAtPoint`
/// below; the two share the wrap rule and must stay in step.
fn wrapDraft(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, x0: i32, first_baseline: i32, maxw: i32, color: u32, px: u16, draft: []const u8, line_h: i32, caret_at: usize, sel_start: usize, sel_end: usize) !DraftPens {
    var baseline = first_baseline;
    var x = x0;
    var caret_pen: Pen = .{ .x = x0, .baseline = first_baseline };
    var word_start: usize = 0;
    var i: usize = 0;
    while (i <= draft.len) : (i += 1) {
        const at_end = i == draft.len;
        const ch: u8 = if (at_end) 0 else draft[i];
        if (!at_end and ch != ' ' and ch != '\n') continue;
        const word = draft[word_start..i];
        if (word.len > 0) {
            const ww: i32 = @intCast(text.measure(e, .regular, word, px));
            if (x > x0 and x + ww > x0 + maxw) { // wrap BEFORE this word
                baseline += line_h;
                x = x0;
            }
            // Selection highlight behind the selected sub-run of this word.
            if (sel_end > sel_start) {
                const ss = @max(sel_start, word_start);
                const se = @min(sel_end, i);
                if (se > ss) {
                    const hx0 = x + @as(i32, @intCast(text.measure(e, .regular, draft[word_start..ss], px)));
                    const hx1 = x + @as(i32, @intCast(text.measure(e, .regular, draft[word_start..se], px)));
                    try rect(gpa, dl, hx0, baseline - 15, hx1 - hx0, 20, sel_fill, 2);
                }
            }
            // Caret inside this word (or at its edges): measure the sub-run.
            if (caret_at >= word_start and caret_at <= i) {
                const sw: i32 = @intCast(text.measure(e, .regular, draft[word_start..caret_at], px));
                caret_pen = .{ .x = x + sw, .baseline = baseline };
            }
            x = try str(gpa, dl, e, .regular, x, baseline, color, px, word);
        } else if (caret_at == word_start) {
            // Empty segment (leading/again-consecutive separator): caret here.
            caret_pen = .{ .x = x, .baseline = baseline };
        }
        if (at_end) break;
        if (ch == ' ') {
            if (x > x0) {
                // A selected space gets its own highlight cell.
                if (sel_end > sel_start and i >= sel_start and i < sel_end)
                    try rect(gpa, dl, x, baseline - 15, @intCast(text.advance(e, .regular, ' ', px)), 20, sel_fill, 2);
                x += @intCast(text.advance(e, .regular, ' ', px)); // no leading space
            }
        } else { // '\n' — explicit break
            baseline += line_h;
            x = x0;
        }
        word_start = i + 1;
    }
    return .{ .end = .{ .x = x, .baseline = baseline }, .caret = caret_pen };
}

/// The composer text-box geometry, shared by `layoutCompose` (drawing + caret)
/// and `composeCaretAtPoint` (click → offset) so the two never drift.
/// A7.2: cold — a single transient value computed per compose frame.
const ComposeGeom = struct { lx: i32, text_top: i32, inner_w: i32, line_h: i32 };
fn composeGeom(e: *const text.Engine, width: i32) ComposeGeom {
    const m = metricsFor(width);
    const cx0 = m.col_x + 16;
    const cw = m.col_w - 32;
    const card_y: i32 = 92;
    const pad: i32 = 24;
    const body_line: i32 = @max(24, @as(i32, @intCast(text.lineMetrics(e, .regular, 17).height)));
    return .{ .lx = cx0 + pad, .text_top = card_y + 50 + 14 + body_line, .inner_w = cw - pad * 2, .line_h = body_line };
}

/// Keep the candidate boundary nearest the hit point — line distance dominates
/// (scaled), then horizontal distance breaks ties within the line.
fn nearerBoundary(off: u32, bx: i32, bbaseline: i32, hx: i32, hy: i32, best_off: *u32, best_score: *i64) void {
    const dy: i64 = @intCast(@abs(@as(i64, bbaseline) - hy));
    const dx: i64 = @intCast(@abs(@as(i64, bx) - hx));
    const score = dy * 4096 + dx;
    if (score < best_score.*) {
        best_score.* = score;
        best_off.* = off;
    }
}

/// Map a click at logical (`hx`,`hy`) to the nearest caret byte offset in
/// `draft`, replaying the same wrap as `wrapDraft`/`layoutCompose`. Pure: the
/// shell calls it on a composer click, then `textedit.setCaret`.
pub fn composeCaretAtPoint(e: *const text.Engine, width: i32, draft: []const u8, hx: i32, hy: i32) u32 {
    if (draft.len == 0) return 0;
    const px: u16 = 17;
    const g = composeGeom(e, width);
    var baseline = g.text_top;
    var x = g.lx;
    var best_off: u32 = 0;
    var best_score: i64 = std.math.maxInt(i64);
    var word_start: usize = 0;
    var i: usize = 0;
    while (i <= draft.len) : (i += 1) {
        const at_end = i == draft.len;
        const ch: u8 = if (at_end) 0 else draft[i];
        if (!at_end and ch != ' ' and ch != '\n') continue;
        const word = draft[word_start..i];
        if (word.len > 0) {
            const ww: i32 = @intCast(text.measure(e, .regular, word, px));
            if (x > g.lx and x + ww > g.lx + g.inner_w) {
                baseline += g.line_h;
                x = g.lx;
            }
            // Boundary before the word, then after each codepoint within it.
            nearerBoundary(@intCast(word_start), x, baseline, hx, hy, &best_off, &best_score);
            var k: usize = word_start;
            var wx = x;
            while (k < i) {
                const clen: usize = std.unicode.utf8ByteSequenceLength(draft[k]) catch 1;
                const adv: i32 = @intCast(text.measure(e, .regular, draft[k .. k + clen], px));
                wx += adv;
                k += clen;
                nearerBoundary(@intCast(k), wx, baseline, hx, hy, &best_off, &best_score);
            }
            x += ww;
        } else {
            nearerBoundary(@intCast(word_start), x, baseline, hx, hy, &best_off, &best_score);
        }
        if (at_end) break;
        if (ch == ' ') {
            if (x > g.lx) x += @intCast(text.advance(e, .regular, ' ', px));
        } else {
            baseline += g.line_h;
            x = g.lx;
        }
        nearerBoundary(@intCast(i + 1), x, baseline, hx, hy, &best_off, &best_score);
        word_start = i + 1;
    }
    return best_off;
}

/// The premium composer (PHASE C1): the New-post / reply / profile-editor input
/// surface, rendered in the feed_view vocabulary over the living field instead
/// of the cell-grid composer. Pure (B2): same draft + engine ⇒ same draw list.
/// The shell keeps the draft buffer and the keyboard input path unchanged; this
/// only renders it and emits the footer button regions (`compose_send` /
/// `compose_cancel`) so a mouse can drive what Ctrl-D / Esc already do.
pub fn layoutCompose(
    gpa: Allocator,
    e: *const text.Engine,
    width: i32,
    height: i32,
    /// The app's live accent (the seated lens's color) — so the composer matches
    /// the rest of the site, not the static house amber.
    accent: u32,
    ctx: ComposeContext,
    /// "@handle" of the post being replied to, when `ctx == .reply`; else "".
    reply_handle: []const u8,
    draft: []const u8,
    /// Byte offset of the insertion point in `draft` (the textedit caret).
    caret: usize,
    /// Selected byte range `[sel_start, sel_end)` (equal ⇒ no selection).
    sel_start: usize,
    sel_end: usize,
    /// Whether to paint the caret this frame (the shell's blink clock).
    blink_on: bool,
    /// A status / hint line shown in the footer (the shell's compose status).
    status: []const u8,
    dl: *raster.DrawList,
    regions: ?*Regions,
) error{OutOfMemory}!void {
    const m = metricsFor(width);
    if (regions) |rg| rg.clearRetainingCapacity();

    // A heavy veil over the WHOLE surface dims the feed/field uniformly so the
    // composer reads as a focused overlay; the field still glows faintly through.
    try rect(gpa, dl, 0, 0, width, height, header_veil, 0);

    // The card: centred in the feed column, a comfortable fixed height.
    const cx0 = m.col_x + 16;
    const cw = m.col_w - 32;
    const card_y: i32 = 92;
    const card_h: i32 = @min(height - card_y - 40, 380);
    try rect(gpa, dl, cx0, card_y, cw, card_h, panel, 18);

    const pad: i32 = 24;
    const lx = cx0 + pad;
    const inner_w = cw - pad * 2;

    // Context line: who/what this is.
    const send_label: []const u8 = switch (ctx) {
        .reply => "Reply",
        .post => "Post",
        .profile => "Save",
    };
    const hx = try str(gpa, dl, e, .semibold, lx, card_y + 34, ink, 18, switch (ctx) {
        .reply => "Replying to ",
        .post => "New post",
        .profile => "Edit your display name",
    });
    if (ctx == .reply and reply_handle.len > 0) _ = try str(gpa, dl, e, .semibold, hx, card_y + 34, accent, 18, reply_handle);
    try rect(gpa, dl, cx0, card_y + 50, cw, 1, divider, 0);

    // The draft (or a faint placeholder), wrapped from just under the divider.
    const body_line: i32 = @max(24, @as(i32, @intCast(text.lineMetrics(e, .regular, 17).height)));
    const text_top = card_y + 50 + 14 + body_line;
    const cursor: Pen = if (draft.len == 0) blk: {
        const ph: []const u8 = switch (ctx) {
            .reply => "Write your reply…",
            .post => "What's on the field?",
            .profile => "Your display name",
        };
        _ = try str(gpa, dl, e, .regular, lx, text_top, faint, 17, ph);
        break :blk .{ .x = lx, .baseline = text_top };
    } else (try wrapDraft(gpa, dl, e, lx, text_top, inner_w, body_c, 17, draft, body_line, caret, sel_start, sel_end)).caret;

    // The text cursor: a thin accent bar at the caret, one cap-height tall —
    // painted only on the "on" half of the shell's blink cycle.
    if (blink_on) try rect(gpa, dl, cursor.x + 1, cursor.baseline - 15, 2, 19, accent, 1);

    // Footer: Cancel (left, text) · char count · Send pill (right).
    const fy = card_y + card_h - 46;
    // Cancel
    const cancel_w: i32 = @intCast(text.measure(e, .semibold, "Cancel", 14) + 28);
    try rect(gpa, dl, lx, fy, cancel_w, 34, 0x33000000, 14);
    _ = try str(gpa, dl, e, .semibold, lx + 14, fy + 22, muted, 14, "Cancel");
    try emitRegion(gpa, regions, lx, fy, cancel_w, 34, 0, .compose_cancel);
    // Send pill (accent, dark label).
    const sw: i32 = @intCast(text.measure(e, .semibold, send_label, 14) + 40);
    const sx = cx0 + cw - pad - sw;
    try rect(gpa, dl, sx, fy, sw, 34, accent, 16);
    _ = try str(gpa, dl, e, .semibold, sx + 20, fy + 22, bg, 14, send_label);
    try emitRegion(gpa, regions, sx, fy, sw, 34, 0, .compose_send);
    // Char count (posts/replies only) between the two buttons.
    if (ctx != .profile) {
        var cb: [16]u8 = undefined;
        const n = std.unicode.utf8CountCodepoints(draft) catch draft.len;
        const cc = std.fmt.bufPrint(&cb, "{d}/300", .{n}) catch "";
        const over = n > 300;
        _ = try str(gpa, dl, e, .regular, lx + cancel_w + 16, fy + 22, if (over) like_c else faint, 13, cc);
    }
    // Status / hint, just above the footer.
    if (status.len > 0) {
        _ = try str(gpa, dl, e, .regular, lx, fy - 14, muted, 13, status);
    } else {
        _ = try str(gpa, dl, e, .regular, lx, fy - 14, faint, 13, "Ctrl+D to send · Esc to cancel");
    }
}

/// THE LOADOUT PAGE (screen_loadout / the rail's "Algorithms"). Renders the
/// three per-surface sockets — Feed, Replies, Zones — stacked and OPEN for
/// editing, over the same glass column + rail + sidebar chrome. Each socket
/// is the SAME portable widget; only the tray/ui/hits differ per surface
/// (invariant 12). A separate entry point (like layoutCompose) so `layout`'s
/// signature stays lean. Each surface's tap targets go to its own hit list.
/// Loadout-page sub-tabs (the row under the title). Loadout is built; the
/// other two are placeholders for later tracks.
pub const loadout_tabs = [_][]const u8{ "Loadout", "Marketplace", "Create" };

pub fn layoutLoadout(
    gpa: Allocator,
    e: *const text.Engine,
    width: i32,
    height: i32,
    dl: *raster.DrawList,
    regions: ?*Regions,
    accent: u32,
    scroll: i32, // pixel scroll (≤ 0); the socket stack rides under the sticky header
    tab: u8, // 0 = Loadout, 1 = Marketplace, 2 = Create
    /// Out: each surface socket's on-page geometry (feed/reply/zone), so the
    /// shell can run the drag math (dropIndex / reflow) at the right position.
    /// Zeroed for surfaces not drawn (non-Loadout tab).
    out_geoms: ?*[3]lens_socket.Geometry,
    feed_tray: lens_socket.TrayView,
    feed_ui: lens_socket.SocketUi,
    feed_hits: *lens_socket.HitList,
    reply_tray: lens_socket.TrayView,
    reply_ui: lens_socket.SocketUi,
    reply_hits: *lens_socket.HitList,
    zone_tray: lens_socket.TrayView,
    zone_ui: lens_socket.SocketUi,
    zone_hits: *lens_socket.HitList,
) error{OutOfMemory}!i32 {
    const m = metricsFor(width);
    if (regions) |rg| rg.clearRetainingCapacity();
    // Sockets are only built (and so only hit-testable) on the Loadout tab.
    feed_hits.clearRetainingCapacity();
    reply_hits.clearRetainingCapacity();
    zone_hits.clearRetainingCapacity();
    if (out_geoms) |g| g.* = .{ .{ .x = 0, .y = 0, .w = 0 }, .{ .x = 0, .y = 0, .w = 0 }, .{ .x = 0, .y = 0, .w = 0 } };

    // Glass column over the field + the flanking chrome (desktop three-pane).
    try rect(gpa, dl, m.col_x, 0, m.col_w, height, veil, 0);
    if (m.wide) {
        try rect(gpa, dl, m.col_x, 0, 1, height, 0x24EDEAE0, 0);
        try rect(gpa, dl, m.col_x + m.col_w - 1, 0, 1, height, 0x24EDEAE0, 0);
        try drawRail(gpa, dl, e, m.rail_x, height, screen_loadout, regions, accent, false);
        try drawSidebar(gpa, dl, e, m.side_x, height);
    }

    const header_h: i32 = 130;
    const content_top: i32 = header_h + 10;
    var content_h: i32 = content_top;

    // The active sub-view, drawn FIRST + scrolled so it passes under the sticky
    // header (drawn last). Only the Loadout tab scrolls / has sockets.
    if (tab == 0) {
        const Surface = struct { label: []const u8, tray: lens_socket.TrayView, ui: lens_socket.SocketUi, hits: *lens_socket.HitList };
        const surfaces = [_]Surface{
            .{ .label = "FEED", .tray = feed_tray, .ui = feed_ui, .hits = feed_hits },
            .{ .label = "REPLIES", .tray = reply_tray, .ui = reply_ui, .hits = reply_hits },
            .{ .label = "ZONES", .tray = zone_tray, .ui = zone_ui, .hits = zone_hits },
        };
        var y: i32 = content_top + scroll;
        for (surfaces, 0..) |s, i| {
            _ = try str(gpa, dl, e, .semibold, m.lx, y + 4, faint, 12, s.label);
            y += 18;
            var ui = s.ui;
            ui.open = true; // always open on this page
            ui.open_t = 1.0; // fully revealed (no spring-open on the page)
            const geom: lens_socket.Geometry = .{ .x = m.lx, .y = y, .w = m.cw, .scale = 1.0 };
            if (out_geoms) |g| g[i] = geom;
            const sh = try lens_socket.build(gpa, e, s.tray, ui, geom, dl, s.hits);
            y += sh + 28;
        }
        content_h = (y - scroll) + 20; // total (unscrolled) height for scroll clamping
    } else {
        const msg = if (tab == 1) "Marketplace" else "Create an algorithm";
        _ = try str(gpa, dl, e, .semibold, m.lx, content_top + 70, ink, 19, msg);
        _ = try str(gpa, dl, e, .regular, m.lx, content_top + 98, muted, 14, "Coming soon.");
        content_h = height; // nothing to scroll
    }

    // Sticky header: frosted box, title, the tab row, divider — drawn LAST.
    try rect(gpa, dl, m.col_x, 0, m.col_w, header_h, header_veil, 0);
    _ = try str(gpa, dl, e, .semibold, m.lx, 50, ink, 27, "Algorithms");
    var tx = m.lx;
    const tab_baseline: i32 = 96;
    for (loadout_tabs, 0..) |label, i| {
        const on = i == tab;
        const tw: i32 = @intCast(text.measure(e, .semibold, label, 15));
        _ = try str(gpa, dl, e, .semibold, tx, tab_baseline, if (on) ink else muted, 15, label);
        if (on) try rect(gpa, dl, tx, tab_baseline + 9, tw, 3, accent, 2);
        try emitRegion(gpa, regions, tx - 8, tab_baseline - 19, tw + 16, 32, @intCast(i), .loadout_tab);
        tx += tw + 28;
    }
    try rect(gpa, dl, m.col_x, header_h - 1, m.col_w, 1, divider, 0);
    return content_h;
}

/// The feed column's sticky TOP BAR: a frosted box over the top strip, then the
/// screen title (+ Following/Discover tabs on Home / mobile), then the hairline
/// divider. Emitted AFTER the posts so they pass behind it (occluded + dimmed),
/// the chrome reading crisply on top. The box spans the feed column width; the
/// rail/sidebar live in their own columns and are untouched.
fn drawTopBar(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, m: Metrics, active_screen: u8, regions: ?*Regions, profile: ?ProfileHeader, accent: u32, socket_tray: ?lens_socket.TrayView, socket_ui: lens_socket.SocketUi, socket_hits: ?*lens_socket.HitList) error{OutOfMemory}!void {
    if (active_screen == screen_profile) return drawProfileHeader(gpa, dl, e, m, regions, profile orelse .{ .display_name = "", .handle = "", .post_count = 0 }, accent);
    const is_thread = active_screen == screen_thread;
    // screen_thread is past nav_labels, so guard the index → a "Thread" title.
    const title: []const u8 = if (active_screen < nav_labels.len) nav_labels[active_screen] else "Thread";
    const is_home = active_screen == screen_home;
    if (m.wide) {
        const box_h: i32 = if (is_home) home_header_h_wide else 111;
        try rect(gpa, dl, m.col_x, 0, m.col_w, box_h, header_veil, 0);
        // The thread screen gets a back button on the left; the title sits after.
        var tx = m.lx;
        if (is_thread) {
            const bl = "<  Back";
            const blw: i32 = @intCast(text.measure(e, .semibold, bl, 15) + 26);
            try rect(gpa, dl, m.lx, 30, blw, 36, panel, 16);
            _ = try str(gpa, dl, e, .semibold, m.lx + 13, 53, ink, 15, bl);
            try emitRegion(gpa, regions, m.lx, 30, blw, 36, 0, .back);
            tx = m.lx + blw + 22;
        }
        _ = try str(gpa, dl, e, .semibold, tx, 50, ink, 27, title);
        // THE LENS SOCKET seats here, replacing the Following/Discover tabs.
        if (is_home) if (socket_tray) |tray| {
            const geom: lens_socket.Geometry = .{ .x = m.lx, .y = socket_y_wide, .w = m.cw, .scale = 1.0 };
            _ = try lens_socket.build(gpa, e, tray, socket_ui, geom, dl, socket_hits);
        };
        try rect(gpa, dl, m.col_x, box_h - 1, m.col_w, 1, divider, 0);
    } else {
        const box_h: i32 = if (is_home) home_header_h_narrow else 97;
        try rect(gpa, dl, m.col_x, 0, m.col_w, box_h, header_veil, 0);
        if (is_thread) {
            const bl = "<  Back";
            const blw: i32 = @intCast(text.measure(e, .semibold, bl, 14) + 22);
            try rect(gpa, dl, m.lx, 16, blw, 32, panel, 15);
            _ = try str(gpa, dl, e, .semibold, m.lx + 11, 37, ink, 14, bl);
            try emitRegion(gpa, regions, m.lx, 16, blw, 32, 0, .back);
            _ = try str(gpa, dl, e, .semibold, m.lx + blw + 18, 38, ink, 18, "Thread");
            try rect(gpa, dl, m.col_x, 96, m.col_w, 1, divider, 0);
            return;
        }
        const wm = try str(gpa, dl, e, .semibold, m.lx, 42, accent, 22, "zat4");
        _ = try str(gpa, dl, e, .semibold, wm, 42, ink, 22, ".");
        if (is_home) if (socket_tray) |tray| {
            const geom: lens_socket.Geometry = .{ .x = m.lx, .y = socket_y_narrow, .w = m.cw, .scale = 1.0 };
            _ = try lens_socket.build(gpa, e, tray, socket_ui, geom, dl, socket_hits);
        };
        try rect(gpa, dl, m.col_x, box_h - 1, m.col_w, 1, divider, 0);
    }
}

/// The sticky PROFILE identity header: a compact HORIZONTAL band — avatar on the
/// left, the name on line 1 and "@handle · N posts" on line 2 to its right, an
/// Edit-profile pill far right — pinned so identity stays visible as posts scroll
/// under it (the old band was tall, vertical, and scrolled away). The natural
/// anchor for future profile-level nav (Links / Posts·Replies tabs): a row would
/// attach below the identity line, growing `profile_header_h_*`.
fn drawProfileHeader(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, m: Metrics, regions: ?*Regions, ph: ProfileHeader, accent: u32) error{OutOfMemory}!void {
    const name = if (ph.display_name.len > 0) ph.display_name else ph.handle;
    var cb: [24]u8 = undefined;
    const counts = std.fmt.bufPrint(&cb, "{d} posts", .{ph.post_count}) catch "0 posts";

    if (m.wide) {
        const band_h = profile_header_h_wide;
        try rect(gpa, dl, m.col_x, 0, m.col_w, band_h, header_veil, 0);
        const av: i32 = 56;
        const ay: i32 = 26;
        try rect(gpa, dl, m.lx, ay, av, av, tintFor(ph.handle), @intCast(av >> 1));
        const iadv: i32 = @intCast(text.advance(e, .semibold, initialOf(name), 28));
        _ = try glyph1(gpa, dl, e, .semibold, m.lx + @divTrunc(av - iadv, 2), ay + 38, bg, 28, initialOf(name));
        const tx = m.lx + av + 16;
        _ = try str(gpa, dl, e, .semibold, tx, 50, ink, 22, name);
        var bx = try str(gpa, dl, e, .regular, tx, 78, faint, 15, ph.handle);
        bx = try str(gpa, dl, e, .regular, bx + 8, 78, faint, 15, "·");
        _ = try str(gpa, dl, e, .regular, bx + 8, 78, muted, 15, counts);
        if (ph.editable) {
            const label = "Edit profile";
            const bw: i32 = @intCast(text.measure(e, .semibold, label, 14) + 28);
            const bx2 = m.lx + m.cw - bw;
            try rect(gpa, dl, bx2, 41, bw, 34, panel, 16);
            _ = try str(gpa, dl, e, .semibold, bx2 + 14, 63, ink, 14, label);
            try emitRegion(gpa, regions, bx2, 41, bw, 34, 0, .edit_profile);
        }
        // Profile-nav tabs row, below the identity line (Posts active).
        try drawProfileTabs(gpa, dl, e, m.lx, 116, 15, regions, accent);
        try rect(gpa, dl, m.col_x, band_h - 1, m.col_w, 1, divider, 0);
        return;
    }

    // Narrow (mobile) profile band — same idea, tighter.
    const band_h = profile_header_h_narrow;
    try rect(gpa, dl, m.col_x, 0, m.col_w, band_h, header_veil, 0);
    const av: i32 = 44;
    const ay: i32 = 14;
    try rect(gpa, dl, m.lx, ay, av, av, tintFor(ph.handle), @intCast(av >> 1));
    const iadv: i32 = @intCast(text.advance(e, .semibold, initialOf(name), 22));
    _ = try glyph1(gpa, dl, e, .semibold, m.lx + @divTrunc(av - iadv, 2), ay + 30, bg, 22, initialOf(name));
    const tx = m.lx + av + 12;
    _ = try str(gpa, dl, e, .semibold, tx, 36, ink, 18, name);
    var bx = try str(gpa, dl, e, .regular, tx, 58, faint, 13, ph.handle);
    bx = try str(gpa, dl, e, .regular, bx + 6, 58, faint, 13, "·");
    _ = try str(gpa, dl, e, .regular, bx + 6, 58, muted, 13, counts);
    if (ph.editable) {
        const label = "Edit";
        const bw: i32 = @intCast(text.measure(e, .semibold, label, 13) + 22);
        const bx2 = m.lx + m.cw - bw;
        try rect(gpa, dl, bx2, 30, bw, 30, panel, 14);
        _ = try str(gpa, dl, e, .semibold, bx2 + 11, 50, ink, 13, label);
        try emitRegion(gpa, regions, bx2, 30, bw, 30, 0, .edit_profile);
    }
    try drawProfileTabs(gpa, dl, e, m.lx, 100, 14, regions, accent);
    try rect(gpa, dl, m.col_x, band_h - 1, m.col_w, 1, divider, 0);
}

/// The profile-nav tab row (Posts · Replies · Media · Likes). "Posts" is active
/// (ink + an accent underline); the rest are muted. Each emits a `.profile_tab`
/// region carrying its index — visual for now, wired by a later slice (the Links
/// page attaches here too). `baseline` is the tab-label baseline.
fn drawProfileTabs(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, x0: i32, baseline: i32, px: u16, regions: ?*Regions, accent: u32) error{OutOfMemory}!void {
    var tx = x0;
    for (profile_tabs, 0..) |tab, i| {
        const on = i == 0;
        const tw: i32 = @intCast(text.measure(e, .semibold, tab, px));
        _ = try str(gpa, dl, e, .semibold, tx, baseline, if (on) ink else muted, px, tab);
        if (on) try rect(gpa, dl, tx, baseline + 8, tw, 3, accent, 2);
        try emitRegion(gpa, regions, tx - 6, baseline - @as(i32, px) - 4, tw + 12, 30, @intCast(i), .profile_tab);
        tx += tw + 30;
    }
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
            .replying_to = if (it.replying_to_handle.len > 0)
                try std.fmt.allocPrint(arena, "@{s}", .{it.replying_to_handle})
            else
                "",
            .tint = tintFor(it.author_handle),
            .reply = it.reply_count,
            .boost = it.repost_count,
            .like = it.like_count,
            .initial = initialOf(name),
            .liked = it.item_flags.viewer_liked,
            .boosted = it.item_flags.viewer_reposted,
            .depth = it.depth,
            .is_focus = it.is_focus,
            .stitched = it.stitched,
            .has_kids = it.has_kids,
            .collapsed = it.collapsed,
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

test "layout emits 4 tap regions per post (avatar + 3 engagement); hitTest resolves each" {
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
    const h = try layout(gpa, &engine, 460, 940, &posts, 0, &dl, &regions, null, false, screen_home, null, 0, accent_house, null, .{}, null, null, null);
    try std.testing.expect(h > 112); // content extends below the top bar
    // 8 regions per post: body tap + avatar + reply/repost/like + bookmark/share/more.
    try std.testing.expectEqual(@as(usize, 8), regions.items.len);

    var saw_like = false;
    var saw_author = false;
    var saw_body = false;
    for (regions.items) |r| {
        const cxp = @as(i32, r.x) + @divTrunc(@as(i32, r.w), 2);
        const cyp = @as(i32, r.y) + @divTrunc(@as(i32, r.h), 2);
        const hit = hitTest(regions.items, cxp, cyp) orelse return error.NoHit;
        try std.testing.expectEqual(r.kind, hit.kind);
        try std.testing.expectEqual(@as(u16, 0), hit.post);
        if (r.kind == .like) saw_like = true;
        if (r.kind == .author) saw_author = true;
        if (r.kind == .post_body) saw_body = true;
    }
    try std.testing.expect(saw_like);
    try std.testing.expect(saw_author);
    try std.testing.expect(saw_body);
    // The avatar + engagement regions PUNCH THROUGH the whole-post body region:
    // each self-hit-tests to itself (verified in the loop above) even though the
    // body region covers them, because they are emitted AFTER it (found first in
    // the reverse hit-test). So a tap on the avatar opens the profile, the body
    // opens the thread.
    // a click far outside every region (above the first post) resolves to nothing
    try std.testing.expect(hitTest(regions.items, 5, 5) == null);
}

test "layout captures the rooted post's body glyphs for selection (thread screen)" {
    const gpa = std.testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);
    var regions: Regions = .empty;
    defer regions.deinit(gpa);
    var sel: SelGlyphs = .empty;
    defer sel.deinit(gpa);

    const posts = [_]PostView{
        .{ .name = "A", .handle = "@a.zat", .age = "1m", .body = "hello there field", .tint = 0xFFAAAAAA, .reply = 0, .boost = 0, .like = 0, .initial = 'A', .liked = false, .boosted = false, .is_focus = true },
    };
    // A WIDE layout so the focus post is on-screen and the body is drawn.
    _ = try layout(gpa, &engine, 1280, 940, &posts, 0, &dl, &regions, null, true, screen_thread, null, 0, accent_house, null, .{}, null, null, &sel);
    // "hello there field" = 15 visible glyphs (spaces are emitted too): the body
    // captured into the selection map, in reading order.
    try std.testing.expect(sel.items.len > 0);
    try std.testing.expectEqual(@as(u32, 'h'), sel.items[0].cp);

    // A non-thread screen captures nothing (only the rooted post is selectable).
    _ = try layout(gpa, &engine, 1280, 940, &posts, 0, &dl, &regions, null, true, screen_home, null, 0, accent_house, null, .{}, null, null, &sel);
    try std.testing.expectEqual(@as(usize, 0), sel.items.len);
}

test "layoutCompose emits send + cancel regions; multi-line draft + empty draft both render" {
    const gpa = std.testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);
    var regions: Regions = .empty;
    defer regions.deinit(gpa);

    // A reply draft spanning an explicit newline (Enter inserts '\n').
    const draft_ml = "line one\nline two is a bit longer so it wraps";
    try layoutCompose(gpa, &engine, 1300, 900, accent_house, .reply, "@mara.zat", draft_ml, 5, 9, 17, true, "", &dl, &regions);
    try std.testing.expect(dl.len > 0);
    var saw_send = false;
    var saw_cancel = false;
    for (regions.items) |r| {
        if (r.kind == .compose_send) saw_send = true;
        if (r.kind == .compose_cancel) saw_cancel = true;
    }
    try std.testing.expect(saw_send);
    try std.testing.expect(saw_cancel);
    // Both buttons must hit-test back to themselves.
    for (regions.items) |r| {
        const cxp = @as(i32, r.x) + @divTrunc(@as(i32, r.w), 2);
        const cyp = @as(i32, r.y) + @divTrunc(@as(i32, r.h), 2);
        const hit = hitTest(regions.items, cxp, cyp) orelse return error.NoHit;
        try std.testing.expectEqual(r.kind, hit.kind);
    }

    // An empty profile draft renders the placeholder path without crashing.
    dl.len = 0;
    try layoutCompose(gpa, &engine, 700, 800, accent_house, .profile, "", "", 0, 0, 0, true, "saving...", &dl, &regions);
    try std.testing.expect(dl.len > 0);

    // The inverse (click → caret offset) replays the same wrap: a click far
    // before the text lands at 0; a click far past it lands at the end.
    try std.testing.expectEqual(@as(u32, 0), composeCaretAtPoint(&engine, 1300, draft_ml, -10000, -10000));
    try std.testing.expectEqual(@as(u32, draft_ml.len), composeCaretAtPoint(&engine, 1300, draft_ml, 1_000_000, 1_000_000));
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

    const h = try layout(gpa, &engine, 460, 940, posts, 0, &dl, &regions, null, false, screen_home, null, 0, accent_house, null, .{}, null, null, null); // must not panic
    try std.testing.expect(h > 940 * 10); // height accounts for the whole list
    try std.testing.expect(regions.items.len < 4 * 24); // only on-screen posts are tappable

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
    const h_fill = try layout(gpa, &engine, 460, 940, posts, 0, &dl, &regions, heights, false, screen_home, null, 0, accent_house, null, .{}, null, null, null);
    const fill_regions = regions.items.len;
    dl.len = 0;
    regions.clearRetainingCapacity();
    const h_cached = try layout(gpa, &engine, 460, 940, posts, 0, &dl, &regions, heights, false, screen_home, null, 0, accent_house, null, .{}, null, null, null);
    try std.testing.expectEqual(h, h_fill);
    try std.testing.expectEqual(h, h_cached);
    try std.testing.expectEqual(fill_regions, regions.items.len);
}

test "profile screen renders the author's posts under a header; other screens stay placeholders" {
    const gpa = std.testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);
    var regions: Regions = .empty;
    defer regions.deinit(gpa);

    const posts = [_]PostView{
        .{ .name = "Connor", .handle = "@connor.zat4.com", .age = "2h", .body = "hello world", .tint = 0xFFAAAAAA, .reply = 0, .boost = 0, .like = 1, .initial = 'C', .liked = false, .boosted = false },
    };
    const header: ProfileHeader = .{ .display_name = "connor.zat4.com", .handle = "@connor.zat4.com", .post_count = 1 };

    // Profile screen: 8 post tap regions (body + avatar + reply/repost/like +
    // bookmark/share/more) + 4 profile-nav tab regions in the sticky header
    // (the header here isn't editable, so no edit-profile region).
    const hp = try layout(gpa, &engine, 460, 940, &posts, 0, &dl, &regions, null, false, screen_profile, header, 0, accent_house, null, .{}, null, null, null);
    try std.testing.expect(hp > 112);
    try std.testing.expectEqual(@as(usize, 12), regions.items.len);

    // A non-Home, non-Profile screen is a titled placeholder: no posts render,
    // so no tap regions, and the height clamps to the viewport (no post stack).
    dl.len = 0;
    regions.clearRetainingCapacity();
    const he = try layout(gpa, &engine, 460, 940, &posts, 0, &dl, &regions, null, false, 1, null, 0, accent_house, null, .{}, null, null, null); // Explore
    try std.testing.expectEqual(@as(i32, 940), he);
    try std.testing.expectEqual(@as(usize, 0), regions.items.len);
}
