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

//! B1 classification: CORE (pure). THE CALL SURFACE — what a call looks like
//! and where you can press it. Plain data in, draw items and tap targets out.
//! No clock, no I/O, no knowledge that a microphone exists.
//!
//! TRUE BLACK BY DESIGN, not by taste (ZAT_CHAT_CALLING_ROADMAP §8.1). On an
//! OLED panel a pure-black pixel is a pixel that is switched OFF and drawing no
//! current. A call is the one screen a person leaves up, untouched, for minutes
//! at a time — often held to a face where nothing is even being looked at — so
//! it is the screen where that matters most. Everything here is therefore black
//! ground with thin light-on-dark chrome: no cards, no fills, no gradients, no
//! translucent panels that keep the pixels beneath half-lit.
//!
//! The same restraint reads as calm rather than cheap, which is the point: a
//! ringing phone should feel composed. That the composed version is also the
//! one that draws the least power is the happy case where the aesthetic and the
//! engineering want the same thing.
//!
//! Layout is resolution-independent — everything derives from the surface box
//! handed in — so the phone and the desktop get the same surface at their own
//! sizes without a second code path.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const raster = @import("raster.zig");
const text = @import("text.zig");

/// What the call surface is showing. Mirrors `shell/call_ctl.Phase`, but as the
/// VIEW's own vocabulary — the core does not import the shell (B4), and the
/// shell hands this across as a plain value.
pub const Phase = enum(u8) {
    /// Not in a call: the surface draws nothing at all.
    idle = 0,
    /// Someone is calling. The only screen with an Accept button.
    ringing_in = 1,
    /// We are calling someone and they have not picked up.
    ringing_out = 2,
    /// Connected, or connecting. Mute and Hang up.
    active = 3,
};

/// Everything the surface renders from. PLAIN DATA (A1). A7.2: cold struct,
/// size guard waived — one per frame, never in a collection.
pub const CallView = struct {
    phase: Phase = .idle,
    /// Who the call is with, already resolved to something a person recognises
    /// by the time it reaches here. May be empty, and the surface copes.
    peer: []const u8 = "",
    /// Is our microphone currently withheld?
    muted: bool = false,
    /// Whole seconds the call has been connected. The shell owns the clock
    /// (B3); this only formats it.
    seconds: u32 = 0,
    /// 0..1, advanced by the shell, for the ring pulse. A pure function of it,
    /// so the animation carries no state here (B2).
    pulse: f32 = 0,
};

/// What a press on the surface means. Never an index (A5) — the shell knows
/// which call is up; it only needs the intent.
pub const Action = enum(u8) { accept, decline, hangup, mute };

/// One tap target. HOT-ish (iterated by `hitTest`), so it is guarded (A7).
pub const HitRect = struct {
    x: i16,
    y: i16,
    w: u16,
    h: u16,
    action: Action,
    _pad: u8 = 0, // A6: explicit pad to the 2-byte boundary

    comptime {
        // Budget: 4x2 = 8, then action(1) + pad(1) = 2. 10 exact, align 2.
        assert(@sizeOf(HitRect) == 10);
    }
};

pub const HitList = std.ArrayListUnmanaged(HitRect);

// --- The palette. Four values, and three of them are grey. -------------------

/// Not "very dark". Zero. On OLED these pixels are off.
const ground: u32 = 0xFF00_0000;
const label_bright: u32 = 0xFFF2_F2F2;
const label_dim: u32 = 0xFF8A_8A8A;
const hairline: u32 = 0xFF2E_2E2E;
/// Accept and hang-up are the two irreversible presses on this screen, so they
/// are the only two things allowed any colour at all. Used as a thin ring, not
/// a fill — a filled 72px circle is 5,000 lit pixels for no added clarity.
const accept_ring: u32 = 0xFF3D_D68C;
const end_ring: u32 = 0xFFE5_5C5C;

const button_d: i32 = 72; // diameter of a control
const button_gap: i32 = 40;

/// Draw the call surface across the whole box and push its tap targets.
/// Returns true if anything was drawn — i.e. whether the surface is claiming
/// the screen, which is what the shell gates its other passes on.
///
/// `top` is the safe-area inset the phone's status bar occupies.
pub fn draw(
    gpa: Allocator,
    dl: *raster.DrawList,
    e: *const text.Engine,
    v: CallView,
    w: i32,
    h: i32,
    top: i32,
    hits: ?*HitList,
) !bool {
    if (v.phase == .idle) return false;

    // The ground. Opaque, so nothing beneath shows through, and black, so the
    // panel costs nothing to display.
    try rect(gpa, dl, 0, 0, w, h, ground, 0);

    const cx = @divTrunc(w, 2);
    const usable_top = top;
    const centre_y = usable_top + @divTrunc(h - usable_top, 2);

    // --- who, and what is happening ------------------------------------------
    const name = if (v.peer.len > 0) v.peer else "Unknown";
    const name_px: u16 = 30;
    const name_w: i32 = @intCast(text.measure(e, .semibold, name, name_px));
    _ = try str(gpa, dl, e, .semibold, cx - @divTrunc(name_w, 2), centre_y - 120, label_bright, name_px, name);

    var status_buf: [32]u8 = undefined;
    const status: []const u8 = switch (v.phase) {
        .idle => unreachable,
        .ringing_in => "is calling",
        .ringing_out => "calling…",
        .active => formatDuration(&status_buf, v.seconds),
    };
    const status_px: u16 = 16;
    const status_w: i32 = @intCast(text.measure(e, .regular, status, status_px));
    _ = try str(gpa, dl, e, .regular, cx - @divTrunc(status_w, 2), centre_y - 84, label_dim, status_px, status);

    // --- the controls ---------------------------------------------------------
    const by = centre_y + 60;
    switch (v.phase) {
        .idle => unreachable,

        .ringing_in => {
            // Decline left, accept right. Accept pulses, so a glance at a dark
            // screen still reads as "something wants you" — motion is legible
            // in peripheral vision where a static shape is not, and one
            // breathing ring is far cheaper than a lit panel.
            const half = @divTrunc(button_d + button_gap, 2);
            try control(gpa, dl, e, cx - half - @divTrunc(button_d, 2), by, end_ring, .end, 1.0);
            try pushHit(gpa, hits, cx - half - @divTrunc(button_d, 2), by, .decline);

            try control(gpa, dl, e, cx + half - @divTrunc(button_d, 2), by, accept_ring, .accept, 0.75 + 0.25 * v.pulse);
            try pushHit(gpa, hits, cx + half - @divTrunc(button_d, 2), by, .accept);

            try caption(gpa, dl, e, cx - half, by + button_d + 24, "Decline");
            try caption(gpa, dl, e, cx + half, by + button_d + 24, "Accept");
        },

        .ringing_out => {
            // Only one thing to do while it rings: stop.
            try control(gpa, dl, e, cx - @divTrunc(button_d, 2), by, end_ring, .end, 1.0);
            try pushHit(gpa, hits, cx - @divTrunc(button_d, 2), by, .hangup);
            try caption(gpa, dl, e, cx, by + button_d + 24, "Cancel");
        },

        .active => {
            const half = @divTrunc(button_d + button_gap, 2);
            try control(gpa, dl, e, cx - half - @divTrunc(button_d, 2), by, if (v.muted) label_bright else hairline, .mic, 1.0);
            try pushHit(gpa, hits, cx - half - @divTrunc(button_d, 2), by, .mute);

            try control(gpa, dl, e, cx + half - @divTrunc(button_d, 2), by, end_ring, .end, 1.0);
            try pushHit(gpa, hits, cx + half - @divTrunc(button_d, 2), by, .hangup);

            try caption(gpa, dl, e, cx - half, by + button_d + 24, if (v.muted) "Unmute" else "Mute");
            try caption(gpa, dl, e, cx + half, by + button_d + 24, "End");
        },
    }

    return true;
}

/// Which control a press landed on, or null. Iterated in reverse so the most
/// recently pushed target wins an overlap, matching every other surface here.
pub fn hitTest(hits: []const HitRect, px: i32, py: i32) ?Action {
    var i = hits.len;
    while (i > 0) {
        i -= 1;
        const r = hits[i];
        if (px >= r.x and py >= r.y and px < @as(i32, r.x) + r.w and py < @as(i32, r.y) + r.h) return r.action;
    }
    return null;
}

// --- drawing helpers ---------------------------------------------------------

/// The glyph inside a control ring.
const Icon = enum { accept, end, mic };

/// A control: a thin ring with a line-drawn glyph inside. `intensity` scales the
/// ring's brightness for the accept pulse.
fn control(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, x: i32, y: i32, colour: u32, icon: Icon, intensity: f32) !void {
    _ = e;
    const r = @divTrunc(button_d, 2);
    const cx = x + r;
    const cy = y + r;

    // The ring, approximated by a square with a full corner radius — the
    // rasterizer's rounded rect at radius == half the side IS a circle, so this
    // costs one draw item rather than an arc primitive we would otherwise have
    // to add.
    const lit = scaleColour(colour, intensity);
    try rect(gpa, dl, x, y, button_d, button_d, lit, @intCast(r));
    // Punch the centre back to ground, leaving a 2px ring. Cheaper than
    // stroking, and on this screen "punch back to black" is free in display
    // power as well as in draw calls.
    const inner = button_d - 4;
    try rect(gpa, dl, x + 2, y + 2, inner, inner, ground, @intCast(@divTrunc(inner, 2)));

    switch (icon) {
        // A handset: a diagonal body with an earpiece and a mouthpiece square
        // across each end, both turned the SAME way so the three strokes read
        // as one C-shaped object rather than a zigzag. Accept lies along one
        // diagonal, End along the other — the familiar "answer up, hang up
        // down" pair, and the only difference between the two glyphs.
        .accept, .end => {
            const s: i32 = 9; // half the body's length along each axis
            const c: i32 = 5; // how far the end caps stand off the body
            // Accept runs lower-left to upper-right; End is its mirror.
            const dy: i32 = if (icon == .end) -1 else 1;
            const ax = cx - s;
            const ay = cy + s * dy;
            const bx = cx + s;
            const by = cy - s * dy;
            // The body.
            try line(gpa, dl, ax, ay, bx, by, lit, 3);
            // Both caps step perpendicular to the body, in the same direction,
            // so they close the C instead of opening a zigzag.
            try line(gpa, dl, ax, ay, ax + c, ay + c * dy, lit, 3);
            try line(gpa, dl, bx, by, bx + c, by + c * dy, lit, 3);
        },
        // A capsule on a stem.
        .mic => {
            try rect(gpa, dl, cx - 5, cy - 13, 10, 17, lit, 5);
            try line(gpa, dl, cx, cy + 6, cx, cy + 12, lit, 2);
            try line(gpa, dl, cx - 7, cy + 12, cx + 7, cy + 12, lit, 2);
        },
    }
}

/// A centred caption under a control.
fn caption(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, cx: i32, baseline: i32, s: []const u8) !void {
    const px: u16 = 13;
    const w: i32 = @intCast(text.measure(e, .regular, s, px));
    _ = try str(gpa, dl, e, .regular, cx - @divTrunc(w, 2), baseline, label_dim, px, s);
}

/// Scale a colour's channels toward black, for the pulse. Alpha is untouched:
/// dimming by alpha would blend against whatever is behind, and behind this is
/// black anyway, so scaling the channels is both simpler and exact.
fn scaleColour(c: u32, k: f32) u32 {
    const f = std.math.clamp(k, 0.0, 1.0);
    const r: u32 = @intFromFloat(@as(f32, @floatFromInt((c >> 16) & 0xFF)) * f);
    const g: u32 = @intFromFloat(@as(f32, @floatFromInt((c >> 8) & 0xFF)) * f);
    const b: u32 = @intFromFloat(@as(f32, @floatFromInt(c & 0xFF)) * f);
    return (c & 0xFF00_0000) | (r << 16) | (g << 8) | b;
}

/// `m:ss`, or `h:mm:ss` once a call has run long enough to deserve it.
fn formatDuration(buf: []u8, seconds: u32) []const u8 {
    const h = seconds / 3600;
    const m = (seconds % 3600) / 60;
    const s = seconds % 60;
    if (h > 0) return std.fmt.bufPrint(buf, "{d}:{d:0>2}:{d:0>2}", .{ h, m, s }) catch "…";
    return std.fmt.bufPrint(buf, "{d}:{d:0>2}", .{ m, s }) catch "…";
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

fn line(gpa: Allocator, dl: *raster.DrawList, x0: i32, y0: i32, x1: i32, y1: i32, color: u32, th: u8) !void {
    try dl.append(gpa, .{ .line = .{
        .x0 = @intCast(x0),
        .y0 = @intCast(y0),
        .x1 = @intCast(x1),
        .y1 = @intCast(y1),
        .color = color,
        .thickness = th,
    } });
}

fn str(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, weight: text.Weight, x0: i32, baseline: i32, color: u32, px: u16, s: []const u8) !i32 {
    var x = x0;
    var it = (std.unicode.Utf8View.init(s) catch return x).iterator();
    while (it.nextCodepoint()) |cp| {
        try dl.append(gpa, .{ .text = .{
            .x = @intCast(x),
            .baseline = @intCast(baseline),
            .codepoint = cp,
            .color = color,
            .px = px,
            .weight = @intFromEnum(weight),
        } });
        x += @as(i32, @intCast(text.advance(e, weight, cp, px)));
    }
    return x;
}

fn pushHit(gpa: Allocator, hits: ?*HitList, x: i32, y: i32, action: Action) !void {
    const list = hits orelse return;
    try list.append(gpa, .{
        .x = @intCast(x),
        .y = @intCast(y),
        .w = @intCast(button_d),
        .h = @intCast(button_d),
        .action = action,
    });
}

// ---------------------------------------------------------------------------
// Tests (B2/C6 — pure, deterministic, leak-checked)
// ---------------------------------------------------------------------------

const testing = std.testing;

fn testEngine() !text.Engine {
    return text.initEngine();
}

test "an idle call draws nothing and claims no input" {
    const gpa = testing.allocator;
    var e = try testEngine();
    var dl: raster.DrawList = .empty;
    defer dl.deinit(gpa);
    var hits: HitList = .empty;
    defer hits.deinit(gpa);

    const drawn = try draw(gpa, &dl, &e, .{ .phase = .idle }, 430, 900, 0, &hits);
    try testing.expect(!drawn);
    try testing.expectEqual(@as(usize, 0), dl.len);
    try testing.expectEqual(@as(usize, 0), hits.items.len);
}

test "a ringing call offers exactly accept and decline" {
    const gpa = testing.allocator;
    var e = try testEngine();
    var dl: raster.DrawList = .empty;
    defer dl.deinit(gpa);
    var hits: HitList = .empty;
    defer hits.deinit(gpa);

    const drawn = try draw(gpa, &dl, &e, .{ .phase = .ringing_in, .peer = "connor.zat4.com" }, 430, 900, 0, &hits);
    try testing.expect(drawn);
    try testing.expectEqual(@as(usize, 2), hits.items.len);

    var saw_accept = false;
    var saw_decline = false;
    for (hits.items) |hr| switch (hr.action) {
        .accept => saw_accept = true,
        .decline => saw_decline = true,
        else => return error.UnexpectedControl,
    };
    try testing.expect(saw_accept and saw_decline);
}

test "an outgoing call offers no way to answer itself" {
    const gpa = testing.allocator;
    var e = try testEngine();
    var dl: raster.DrawList = .empty;
    defer dl.deinit(gpa);
    var hits: HitList = .empty;
    defer hits.deinit(gpa);

    _ = try draw(gpa, &dl, &e, .{ .phase = .ringing_out, .peer = "a.zat4.com" }, 430, 900, 0, &hits);
    try testing.expectEqual(@as(usize, 1), hits.items.len);
    try testing.expectEqual(Action.hangup, hits.items[0].action);
}

test "a live call offers mute and hangup, and nothing that could answer it again" {
    const gpa = testing.allocator;
    var e = try testEngine();
    var dl: raster.DrawList = .empty;
    defer dl.deinit(gpa);
    var hits: HitList = .empty;
    defer hits.deinit(gpa);

    _ = try draw(gpa, &dl, &e, .{ .phase = .active, .peer = "a.zat4.com", .seconds = 75 }, 430, 900, 0, &hits);
    try testing.expectEqual(@as(usize, 2), hits.items.len);
    for (hits.items) |hr| switch (hr.action) {
        .mute, .hangup => {},
        else => return error.UnexpectedControl,
    };
}

test "pressing a control resolves to it, and pressing the empty screen does not" {
    const gpa = testing.allocator;
    var e = try testEngine();
    var dl: raster.DrawList = .empty;
    defer dl.deinit(gpa);
    var hits: HitList = .empty;
    defer hits.deinit(gpa);

    _ = try draw(gpa, &dl, &e, .{ .phase = .ringing_in, .peer = "a.zat4.com" }, 430, 900, 0, &hits);

    // Centre of each control must resolve to that control.
    for (hits.items) |hr| {
        const cx = @as(i32, hr.x) + @divTrunc(@as(i32, hr.w), 2);
        const cy = @as(i32, hr.y) + @divTrunc(@as(i32, hr.h), 2);
        try testing.expectEqual(hr.action, hitTest(hits.items, cx, cy).?);
    }
    // The top-left corner of the screen is nothing. A call surface that
    // swallowed a stray tap into "accept" would be a genuinely bad bug.
    try testing.expectEqual(@as(?Action, null), hitTest(hits.items, 2, 2));
}

test "the controls stay on screen at phone and desktop widths alike" {
    const gpa = testing.allocator;
    var e = try testEngine();

    const sizes = [_][2]i32{ .{ 430, 900 }, .{ 360, 640 }, .{ 1920, 1080 }, .{ 800, 600 } };
    for (sizes) |wh| {
        var dl: raster.DrawList = .empty;
        defer dl.deinit(gpa);
        var hits: HitList = .empty;
        defer hits.deinit(gpa);

        _ = try draw(gpa, &dl, &e, .{ .phase = .ringing_in, .peer = "someone.zat4.com" }, wh[0], wh[1], 0, &hits);
        for (hits.items) |hr| {
            try testing.expect(hr.x >= 0);
            try testing.expect(hr.y >= 0);
            try testing.expect(@as(i32, hr.x) + hr.w <= wh[0]);
            try testing.expect(@as(i32, hr.y) + hr.h <= wh[1]);
        }
    }
}

test "an empty peer name still produces a usable screen" {
    const gpa = testing.allocator;
    var e = try testEngine();
    var dl: raster.DrawList = .empty;
    defer dl.deinit(gpa);
    var hits: HitList = .empty;
    defer hits.deinit(gpa);

    const drawn = try draw(gpa, &dl, &e, .{ .phase = .ringing_in, .peer = "" }, 430, 900, 0, &hits);
    try testing.expect(drawn);
    try testing.expectEqual(@as(usize, 2), hits.items.len);
}

test "the ground is opaque black — the point of the whole screen" {
    const gpa = testing.allocator;
    var e = try testEngine();
    var dl: raster.DrawList = .empty;
    defer dl.deinit(gpa);

    _ = try draw(gpa, &dl, &e, .{ .phase = .active, .peer = "a.zat4.com" }, 430, 900, 0, null);

    // The first item must be a full-bleed, fully opaque, pure black rect. If
    // this ever becomes a dark grey or picks up alpha, the OLED saving is gone
    // and whatever is underneath starts showing through.
    const first = dl.get(0);
    try testing.expect(first == .rect);
    try testing.expectEqual(@as(u32, 0xFF00_0000), first.rect.color);
    try testing.expectEqual(@as(u16, 430), first.rect.w);
    try testing.expectEqual(@as(u16, 900), first.rect.h);
}

test "durations format as a person reads them" {
    var buf: [32]u8 = undefined;
    try testing.expectEqualStrings("0:00", formatDuration(&buf, 0));
    try testing.expectEqualStrings("0:09", formatDuration(&buf, 9));
    try testing.expectEqualStrings("1:15", formatDuration(&buf, 75));
    try testing.expectEqualStrings("59:59", formatDuration(&buf, 3599));
    try testing.expectEqualStrings("1:00:00", formatDuration(&buf, 3600));
    try testing.expectEqualStrings("2:03:04", formatDuration(&buf, 7384));
}

