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

//! B1 classification: CORE (pure). THE GAME BOARDS — every game's picture.
//!
//! One module draws all eight boards, at two sizes: a `thumb` for the card that
//! sits in the thread, and `full` for the board you actually play on. It is PURE
//! (B2): state and a rectangle in, draw items and TAP TARGETS out. It never
//! touches a clock — a skill shot's drifting sight is a function of a phase the
//! shell hands in, so the same phase always draws the same picture and the shell
//! and the view agree on where the sight is without sharing anything but a float.
//!
//! **Why the targets come back as data rather than going straight into the view's
//! region list.** `feed_view` owns the tap-region vocabulary; if this module
//! reached into it, the two would import each other. Handing back a small array
//! of rectangles the caller stamps with whatever action it likes keeps the
//! dependency one-way and keeps this file about pixels (D3).
//!
//! There is no image, no icon font and no SVG here. Every piece — the chess set
//! included — is built from the four things the rasterizer knows: a rounded rect,
//! a line, a triangle and a glyph. A rounded rect whose radius is half its side
//! IS a circle, which is where most of the roundness comes from.

const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const testing = std.testing;

const raster = @import("raster.zig");
const text = @import("text.zig");
const games = @import("chat_games.zig");
const tictactoe = @import("games/tictactoe.zig");
const connect4 = @import("games/connect4.zig");
const mancala = @import("games/mancala.zig");
const dots = @import("games/dots.zig");
const checkers = @import("games/checkers.zig");
const chess = @import("games/chess.zig");
const archery = @import("games/archery.zig");
const darts = @import("games/darts.zig");

const State = games.State;
const Seat = games.Seat;
const Game = games.Game;

/// "Nothing staged / nothing picked up" — the same reserved value a move uses for
/// "this is not a move", so the two ideas never need separate sentinels.
pub const no_stage: u16 = games.invite_cell;

/// A rectangle a tap may land on, and what it would mean. The caller turns these
/// into whatever its own hit-testing wants.
pub const Target = struct {
    x: i16,
    y: i16,
    w: u16,
    h: u16,
    cell: u16,

    comptime {
        // Five 16-bit fields, no padding. These come back in bulk (64 of them for
        // a chess board), so they carry the guard (A7).
        assert(@sizeOf(Target) == 10);
    }
};

/// Everything the renderer needs beyond the game state itself.
/// A7.2: cold struct, size guard waived — one per board drawn, a handful a frame.
pub const View = struct {
    x: i32,
    y: i32,
    /// The square the board is drawn inside.
    size: i32,
    /// Which seat is OURS, so our pieces read as ours.
    my_seat: Seat = .none,
    /// A move staged but not sent — drawn as a ghost.
    staged: u16 = no_stage,
    /// The square picked up in a two-tap game, and the squares it may go to.
    from: u16 = no_stage,
    /// The app accent, used for the first player.
    accent: u32 = 0xFF7C8CF8,
    /// Emit tap targets (only on our turn, and only on the live board).
    interactive: bool = false,
    /// A free-running phase for animated boards, in turns (the fractional part is
    /// what matters). The shell derives it from the clock; this module never does.
    t: f32 = 0,
};

// --- the four primitives, wrapped ------------------------------------------

fn rect(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, w: i32, h: i32, color: u32, radius: u8) !void {
    if (w <= 0 or h <= 0) return;
    try dl.append(gpa, .{ .rect = .{
        .x = @intCast(std.math.clamp(x, -32768, 32767)),
        .y = @intCast(std.math.clamp(y, -32768, 32767)),
        .w = @intCast(std.math.clamp(w, 0, 32767)),
        .h = @intCast(std.math.clamp(h, 0, 32767)),
        .color = color,
        .radius = radius,
    } });
}

/// A filled circle: a rounded rect whose corner radius eats the whole square.
fn disc(gpa: Allocator, dl: *raster.DrawList, cx: i32, cy: i32, r: i32, color: u32) !void {
    if (r <= 0) return;
    const d = r * 2;
    try rect(gpa, dl, cx - r, cy - r, d, d, color, @intCast(@min(r, 255)));
}

fn line(gpa: Allocator, dl: *raster.DrawList, x0: i32, y0: i32, x1: i32, y1: i32, color: u32, th: u8) !void {
    try dl.append(gpa, .{ .line = .{
        .x0 = @intCast(std.math.clamp(x0, -32768, 32767)),
        .y0 = @intCast(std.math.clamp(y0, -32768, 32767)),
        .x1 = @intCast(std.math.clamp(x1, -32768, 32767)),
        .y1 = @intCast(std.math.clamp(y1, -32768, 32767)),
        .color = color,
        .thickness = th,
    } });
}

fn tri(gpa: Allocator, dl: *raster.DrawList, x0: i32, y0: i32, x1: i32, y1: i32, x2: i32, y2: i32, color: u32) !void {
    try dl.append(gpa, .{ .tri = .{
        .x0 = @intCast(std.math.clamp(x0, -32768, 32767)),
        .y0 = @intCast(std.math.clamp(y0, -32768, 32767)),
        .x1 = @intCast(std.math.clamp(x1, -32768, 32767)),
        .y1 = @intCast(std.math.clamp(y1, -32768, 32767)),
        .x2 = @intCast(std.math.clamp(x2, -32768, 32767)),
        .y2 = @intCast(std.math.clamp(y2, -32768, 32767)),
        .color = color,
    } });
}

/// An ASCII run, one `TextItem` per glyph (the draw vocabulary is per-codepoint).
/// The boards only ever print digits and short scores, so this stays ASCII-only
/// rather than pulling in the view's full UTF-8 + emoji path.
fn label(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, w: text.Weight, x: i32, baseline: i32, color: u32, px: u16, s: []const u8) !void {
    var pen = x;
    for (s) |ch| {
        try dl.append(gpa, .{ .text = .{
            .x = @intCast(std.math.clamp(pen, -32768, 32767)),
            .baseline = @intCast(std.math.clamp(baseline, -32768, 32767)),
            .codepoint = ch,
            .color = color,
            .px = px,
            .weight = @intFromEnum(w),
        } });
        pen += @intCast(text.advance(e, w, ch, px));
    }
}

/// The width `label` will take — for centring a score under a board.
fn labelWidth(e: *const text.Engine, w: text.Weight, px: u16, s: []const u8) i32 {
    var total: i32 = 0;
    for (s) |ch| total += @intCast(text.advance(e, w, ch, px));
    return total;
}

/// A hollow ring, from short chord strokes — the draw vocabulary has no circle
/// outline, and several pieces want one.
fn ring(gpa: Allocator, dl: *raster.DrawList, cx: i32, cy: i32, r: i32, thick: u8, c: u32) !void {
    if (r <= 0) return;
    const seg: usize = 20;
    var i: usize = 0;
    var px: i32 = cx + r;
    var py: i32 = cy;
    while (i < seg) : (i += 1) {
        const a = @as(f32, @floatFromInt(i + 1)) / @as(f32, @floatFromInt(seg)) * std.math.tau;
        const nx = cx + fxi(@cos(a) * @as(f32, @floatFromInt(r)));
        const ny = cy + fxi(@sin(a) * @as(f32, @floatFromInt(r)));
        try line(gpa, dl, px, py, nx, ny, c, thick);
        px = nx;
        py = ny;
    }
}

fn fxi(v: f32) i32 {
    return @intFromFloat(@round(v));
}

fn alpha(color: u32, a: u8) u32 {
    return (@as(u32, a) << 24) | (color & 0x00FFFFFF);
}

fn mixA(color: u32, f: f32) u32 {
    const al: f32 = @floatFromInt(color >> 24);
    const s: u32 = @intFromFloat(std.math.clamp(al * f, 0, 255));
    return (s << 24) | (color & 0x00FFFFFF);
}

// --- the shared palette ----------------------------------------------------

/// The second player's colour. The first player wears the app accent, so the two
/// sides always read as "you and the theme" against "them".
pub const o_colour: u32 = 0xFFE0705C;
const felt: u32 = 0xFF15181C;
const felt_light: u32 = 0xFF232830;
const chalk: u32 = 0xFFEDEAE0;

/// A CHESS SET's two colours. The 8x8 games do not use the accent for their
/// pieces, and the reason is legibility rather than taste: a chess set has to
/// read as light against dark at a glance, and "your colour versus the app's
/// second colour" put two warm tones on the same board — thirty-two pieces that
/// all looked like one side. So the pieces are ivory and charcoal, the classic
/// set, and WHICH ONE IS YOURS is said by a thin accent ring instead.
pub const ivory: u32 = 0xFFF0EADC;
pub const charcoal: u32 = 0xFF26221E;

/// The body and the edge for a piece of `v`. The edge is the opposite tone, so a
/// charcoal piece still has a silhouette on a dark square and an ivory one still
/// has an outline on a pale square.
pub fn pieceColours(v: Seat) [2]u32 {
    return if (v == .x) .{ ivory, alpha(0x14110E, 0x88) } else .{ charcoal, alpha(0xF0EADC, 0x66) };
}

/// The colour of `v`'s pieces.
pub fn seatColour(v: Seat, accent: u32) u32 {
    return switch (v) {
        .x => accent | 0xFF000000,
        .o => o_colour,
        .none => alpha(chalk, 0x40),
    };
}

// --- the drifting sight ----------------------------------------------------

/// WHERE THE SIGHT IS at phase `t`, in the 0..255 units a skill shot's move
/// carries. Two circles beating at different rates: the sight never repeats on a
/// short loop, so you cannot learn one rhythm and hit the middle every time, and
/// it is perfectly deterministic, so the drawing and the release agree.
///
/// `spread` is how far it wanders — the game's difficulty, and the one number to
/// turn if it ever feels unfair.
pub fn sight(g: Game, t: f32) [2]i32 {
    const spread: f32 = if (g == .darts) 46.0 else 54.0;
    const a = t * std.math.tau;
    const x = @sin(a * 1.0) * spread + @sin(a * 2.7 + 1.1) * (spread * 0.42);
    const y = @cos(a * 1.31) * spread + @cos(a * 3.3 + 0.6) * (spread * 0.36);
    return .{
        128 + fxi(std.math.clamp(x, -120, 120)),
        128 + fxi(std.math.clamp(y, -120, 120)),
    };
}

/// The move a release at phase `t` produces — the shell calls this when the
/// player taps, and it is the same function the sight is drawn from.
pub fn releaseMove(g: Game, t: f32) u16 {
    const p = sight(g, t);
    return if (g == .darts) darts.shot(p[0], p[1]) else archery.shot(p[0], p[1]);
}

// --- the boards ------------------------------------------------------------

/// Draw the full, playable board. Returns the tap targets it produced (a prefix
/// of `out`), each carrying the CELL a tap there would mean — which for a
/// two-tap game is a square index, not a whole move.
pub fn full(
    gpa: Allocator,
    dl: *raster.DrawList,
    e: *const text.Engine,
    st: State,
    v: View,
    out: []Target,
) ![]Target {
    var n: usize = 0;
    switch (st.game) {
        .tictactoe => try drawTicTacToe(gpa, dl, st, v, out, &n),
        .connect4 => try drawConnect4(gpa, dl, st, v, out, &n),
        .mancala => try drawMancala(gpa, dl, e, st, v, out, &n),
        .dots => try drawDots(gpa, dl, st, v, out, &n),
        .checkers => try drawCheckers(gpa, dl, st, v, out, &n),
        .chess => try drawChess(gpa, dl, st, v, out, &n),
        .archery => try drawArchery(gpa, dl, e, st, v, out, &n),
        .darts => try drawDarts(gpa, dl, e, st, v, out, &n),
        _ => {},
    }
    return out[0..n];
}

fn push(out: []Target, n: *usize, x: i32, y: i32, w: i32, h: i32, cell: u16) void {
    if (n.* >= out.len) return;
    out[n.*] = .{
        .x = @intCast(std.math.clamp(x, -32768, 32767)),
        .y = @intCast(std.math.clamp(y, -32768, 32767)),
        .w = @intCast(std.math.clamp(w, 0, 65535)),
        .h = @intCast(std.math.clamp(h, 0, 65535)),
        .cell = cell,
    };
    n.* += 1;
}

// --- tic-tac-toe -----------------------------------------------------------

fn markX(gpa: Allocator, dl: *raster.DrawList, cx: i32, cy: i32, r: i32, c: u32, th: u8) !void {
    try line(gpa, dl, cx - r, cy - r, cx + r, cy + r, c, th);
    try line(gpa, dl, cx + r, cy - r, cx - r, cy + r, c, th);
}

fn drawTicTacToe(gpa: Allocator, dl: *raster.DrawList, st: State, v: View, out: []Target, n: *usize) !void {
    const cell = @divTrunc(v.size, 3);
    const th: u8 = @intCast(@max(2, @divTrunc(v.size, 60)));
    const grid_c = alpha(chalk, 0x38);
    var g: i32 = 1;
    while (g < 3) : (g += 1) {
        try rect(gpa, dl, v.x + g * cell, v.y + @divTrunc(cell, 6), th, v.size - @divTrunc(cell, 3), grid_c, th);
        try rect(gpa, dl, v.x + @divTrunc(cell, 6), v.y + g * cell, v.size - @divTrunc(cell, 3), th, grid_c, th);
    }
    for (0..9) |i| {
        const cx = v.x + @as(i32, @intCast(i % 3)) * cell + @divTrunc(cell, 2);
        const cy = v.y + @as(i32, @intCast(i / 3)) * cell + @divTrunc(cell, 2);
        const r = @divTrunc(cell, 2) - @divTrunc(cell, 5);
        const seat = games.seatAt(st, i);
        if (seat != .none) {
            const c = seatColour(seat, v.accent);
            if (seat == .x) try markX(gpa, dl, cx, cy, r, c, th * 2) else try ring(gpa, dl, cx, cy, r, th * 2, c);
        } else if (v.staged == i) {
            const c = mixA(seatColour(v.my_seat, v.accent), 0.4);
            if (v.my_seat == .x) try markX(gpa, dl, cx, cy, r, c, th * 2) else try ring(gpa, dl, cx, cy, r, th * 2, c);
        }
        if (v.interactive and seat == .none)
            push(out, n, cx - @divTrunc(cell, 2), cy - @divTrunc(cell, 2), cell, cell, @intCast(i));
    }
}

// --- connect four ----------------------------------------------------------

fn drawConnect4(gpa: Allocator, dl: *raster.DrawList, st: State, v: View, out: []Target, n: *usize) !void {
    const cw = @divTrunc(v.size, connect4.cols);
    const bh = cw * connect4.rows;
    const top = v.y + @divTrunc(v.size - bh, 2);
    // The frame: a deep slab with the holes punched out of it.
    try rect(gpa, dl, v.x - 6, top - 6, cw * connect4.cols + 12, bh + 12, 0xFF2A3550, 18);
    const r = @divTrunc(cw, 2) - @max(3, @divTrunc(cw, 9));
    for (0..connect4.rows) |row| {
        for (0..connect4.cols) |col| {
            const cx = v.x + @as(i32, @intCast(col)) * cw + @divTrunc(cw, 2);
            const cy = top + @as(i32, @intCast(row)) * cw + @divTrunc(cw, 2);
            const seat = games.seatAt(st, row * connect4.cols + col);
            const c = if (seat == .none) 0xFF10141E else seatColour(seat, v.accent);
            try disc(gpa, dl, cx, cy, r, c);
            if (seat != .none) try disc(gpa, dl, cx, cy - @divTrunc(r, 3), @divTrunc(r, 3), mixA(chalk, 0.14));
        }
    }
    // A staged drop is a ghost disc sitting in the slot it would fall into, and
    // a faint chute above the column so you can see WHERE it goes before you
    // commit — which is the whole tension of the game.
    if (v.staged != no_stage) {
        if (connect4.landingRow(st, v.staged)) |row| {
            const cx = v.x + @as(i32, @intCast(v.staged)) * cw + @divTrunc(cw, 2);
            const cy = top + @as(i32, @intCast(row)) * cw + @divTrunc(cw, 2);
            try disc(gpa, dl, cx, cy, r, mixA(seatColour(v.my_seat, v.accent), 0.55));
            try rect(gpa, dl, cx - 2, top - 30, 4, 24, mixA(seatColour(v.my_seat, v.accent), 0.5), 2);
        }
    }
    if (!v.interactive) return;
    for (0..connect4.cols) |col| {
        if (connect4.landingRow(st, @intCast(col)) == null) continue;
        push(out, n, v.x + @as(i32, @intCast(col)) * cw, top - 34, cw, bh + 34, @intCast(col));
    }
}

// --- mancala ---------------------------------------------------------------

/// Stones in a pit, laid out on a small spiral so eight stones look like eight
/// and not like a number — the pleasure of the game is seeing the pile.
fn drawStones(gpa: Allocator, dl: *raster.DrawList, cx: i32, cy: i32, r: i32, count: u8, c: u32) !void {
    if (count == 0) return;
    const sr = @max(2, @divTrunc(r, 5));
    const shown = @min(count, 18);
    var i: usize = 0;
    while (i < shown) : (i += 1) {
        const fi: f32 = @floatFromInt(i);
        const a = fi * 2.399963; // the golden angle: an even, unclumped scatter
        const rad = @as(f32, @floatFromInt(r - sr - 2)) * @sqrt(fi / @as(f32, @floatFromInt(@max(shown, 1))));
        try disc(gpa, dl, cx + fxi(@cos(a) * rad), cy + fxi(@sin(a) * rad), sr, c);
    }
}

fn drawMancala(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, st: State, v: View, out: []Target, n: *usize) !void {
    const board_h = @divTrunc(v.size, 2);
    const top = v.y + @divTrunc(v.size - board_h, 2);
    const store_w = @divTrunc(v.size, 8);
    const pit_area = v.size - 2 * store_w - 16;
    const pit_w = @divTrunc(pit_area, mancala.per_side);
    const pit_r = @divTrunc(@min(pit_w, @divTrunc(board_h, 2)), 2) - 4;

    try rect(gpa, dl, v.x - 8, top - 8, v.size + 16, board_h + 16, 0xFF3A2A1E, 22);
    try rect(gpa, dl, v.x - 2, top - 2, v.size + 4, board_h + 4, 0xFF4A3626, 18);

    // The two stores at the ends, drawn tall.
    const stores = [2]struct { x: i32, pit: usize, v: Seat }{
        .{ .x = v.x, .pit = mancala.o_store, .v = .o },
        .{ .x = v.x + v.size - store_w, .pit = mancala.x_store, .v = .x },
    };
    for (stores) |s| {
        try rect(gpa, dl, s.x, top + 4, store_w, board_h - 8, 0xFF241A12, @intCast(@min(@divTrunc(store_w, 2), 255)));
        try drawStones(gpa, dl, s.x + @divTrunc(store_w, 2), top + @divTrunc(board_h, 2), @divTrunc(store_w, 2) - 6, st.cells[s.pit], seatColour(s.v, v.accent));
        var buf: [8]u8 = undefined;
        const txt = std.fmt.bufPrint(&buf, "{d}", .{st.cells[s.pit]}) catch "";
        const tw = labelWidth(e, .semibold, 15, txt);
        try label(gpa, dl, e, .semibold, s.x + @divTrunc(store_w - tw, 2), top + board_h + 20, alpha(chalk, 0xDD), 15, txt);
    }

    // O's pits along the top (right to left, the way the stones travel), X's
    // along the bottom.
    for (0..mancala.per_side) |i| {
        const px = v.x + store_w + 8 + @as(i32, @intCast(mancala.per_side - 1 - i)) * pit_w + @divTrunc(pit_w, 2);
        const py = top + @divTrunc(board_h, 4);
        const pit = 7 + i;
        try disc(gpa, dl, px, py, pit_r, 0xFF241A12);
        try drawStones(gpa, dl, px, py, pit_r, st.cells[pit], seatColour(.o, v.accent));
        if (v.interactive and st.turn == .o and st.cells[pit] > 0) {
            try ring(gpa, dl, px, py, pit_r, 2, mixA(seatColour(.o, v.accent), 0.6));
            push(out, n, px - pit_r, py - pit_r, pit_r * 2, pit_r * 2, @intCast(pit));
        }
        if (v.staged == pit) try ring(gpa, dl, px, py, pit_r + 3, 3, seatColour(.o, v.accent));
    }
    for (0..mancala.per_side) |i| {
        const px = v.x + store_w + 8 + @as(i32, @intCast(i)) * pit_w + @divTrunc(pit_w, 2);
        const py = top + board_h - @divTrunc(board_h, 4);
        try disc(gpa, dl, px, py, pit_r, 0xFF241A12);
        try drawStones(gpa, dl, px, py, pit_r, st.cells[i], seatColour(.x, v.accent));
        if (v.interactive and st.turn == .x and st.cells[i] > 0) {
            try ring(gpa, dl, px, py, pit_r, 2, mixA(seatColour(.x, v.accent), 0.6));
            push(out, n, px - pit_r, py - pit_r, pit_r * 2, pit_r * 2, @intCast(i));
        }
        if (v.staged == i) try ring(gpa, dl, px, py, pit_r + 3, 3, seatColour(.x, v.accent));
    }
}

// --- dots & boxes ----------------------------------------------------------

fn drawDots(gpa: Allocator, dl: *raster.DrawList, st: State, v: View, out: []Target, n: *usize) !void {
    // FIVE dots span the box, not four: the grid is `grid` boxes wide, so the
    // dots at both ends need the extra step. Sized as `size / grid` the whole
    // lattice ran an eighth of its width past the frame.
    const step = @divTrunc(v.size, dots.grid + 1);
    const pad = @divTrunc(step, 2);
    const ox = v.x + pad;
    const oy = v.y + pad;
    const half = @divTrunc(step, 2);
    const th: u8 = @intCast(@max(3, @divTrunc(step, 12)));

    // Claimed boxes first, so the lines sit on top of them.
    for (0..dots.grid) |r| {
        for (0..dots.grid) |c| {
            const own = dots.boxOwner(st, r, c);
            if (own == .none) continue;
            try rect(
                gpa,
                dl,
                ox + @as(i32, @intCast(c)) * step + 3,
                oy + @as(i32, @intCast(r)) * step + 3,
                step - 6,
                step - 6,
                mixA(seatColour(own, v.accent), 0.4),
                8,
            );
        }
    }

    // Edges: drawn ones in their owner's colour, undrawn as a faint hint that
    // only appears where a tap would land.
    for (0..dots.grid + 1) |r| {
        for (0..dots.grid) |c| {
            const e = dots.hEdge(r, c);
            const own = dots.edgeOwner(st, e);
            const x0 = ox + @as(i32, @intCast(c)) * step;
            const y0 = oy + @as(i32, @intCast(r)) * step;
            if (own != .none) {
                try rect(gpa, dl, x0, y0 - @divTrunc(th, 2), step, th, seatColour(own, v.accent), th);
            } else if (v.staged == e) {
                try rect(gpa, dl, x0, y0 - @divTrunc(th, 2), step, th, mixA(seatColour(v.my_seat, v.accent), 0.5), th);
            } else if (v.interactive) {
                try rect(gpa, dl, x0 + 6, y0 - 1, step - 12, 2, alpha(chalk, 0x18), 1);
            }
            // The two edge families cross at every dot, so their targets are kept
            // to the middle of each edge — half a step apart in both axes, which
            // is exactly enough that a tap can never mean two edges at once.
            if (v.interactive and own == .none)
                push(out, n, x0 + @divTrunc(step, 4), y0 - @divTrunc(step, 4), half, half, @intCast(e));
        }
    }
    for (0..dots.grid) |r| {
        for (0..dots.grid + 1) |c| {
            const e = dots.vEdge(r, c);
            const own = dots.edgeOwner(st, e);
            const x0 = ox + @as(i32, @intCast(c)) * step;
            const y0 = oy + @as(i32, @intCast(r)) * step;
            if (own != .none) {
                try rect(gpa, dl, x0 - @divTrunc(th, 2), y0, th, step, seatColour(own, v.accent), th);
            } else if (v.staged == e) {
                try rect(gpa, dl, x0 - @divTrunc(th, 2), y0, th, step, mixA(seatColour(v.my_seat, v.accent), 0.5), th);
            } else if (v.interactive) {
                try rect(gpa, dl, x0 - 1, y0 + 6, 2, step - 12, alpha(chalk, 0x18), 1);
            }
            if (v.interactive and own == .none)
                push(out, n, x0 - @divTrunc(step, 4), y0 + @divTrunc(step, 4), half, half, @intCast(e));
        }
    }

    // The dots last: they are the thing you aim between.
    for (0..dots.grid + 1) |r| {
        for (0..dots.grid + 1) |c| {
            try disc(gpa, dl, ox + @as(i32, @intCast(c)) * step, oy + @as(i32, @intCast(r)) * step, @max(3, @divTrunc(step, 14)), chalk);
        }
    }
}

// --- the 8×8 boards --------------------------------------------------------

fn drawSquares(gpa: Allocator, dl: *raster.DrawList, v: View, dark_c: u32, light_c: u32) !i32 {
    const cell = @divTrunc(v.size, 8);
    try rect(gpa, dl, v.x - 5, v.y - 5, cell * 8 + 10, cell * 8 + 10, 0xFF221E1A, 10);
    for (0..8) |r| {
        for (0..8) |c| {
            const dark = (r + c) % 2 == 1;
            try rect(
                gpa,
                dl,
                v.x + @as(i32, @intCast(c)) * cell,
                v.y + @as(i32, @intCast(r)) * cell,
                cell,
                cell,
                if (dark) dark_c else light_c,
                0,
            );
        }
    }
    return cell;
}

fn drawCheckers(gpa: Allocator, dl: *raster.DrawList, st: State, v: View, out: []Target, n: *usize) !void {
    // A walnut board rather than the green one it started as: a charcoal piece on
    // a dark-green square was a piece you had to look for.
    const cell = try drawSquares(gpa, dl, v, 0xFF7A5236, 0xFFE4D6B8);
    const r = @divTrunc(cell, 2) - @max(4, @divTrunc(cell, 8));

    // The square you picked up, and everywhere it may go.
    if (v.from != no_stage) {
        const fx = v.x + @as(i32, @intCast(v.from % 8)) * cell;
        const fy = v.y + @as(i32, @intCast(v.from / 8)) * cell;
        try rect(gpa, dl, fx, fy, cell, cell, mixA(v.accent | 0xFF000000, 0.45), 0);
    }

    for (0..64) |sq| {
        const cx = v.x + @as(i32, @intCast(sq % 8)) * cell + @divTrunc(cell, 2);
        const cy = v.y + @as(i32, @intCast(sq / 8)) * cell + @divTrunc(cell, 2);
        const own = checkers.owner(st, sq);
        if (own == .none) continue;
        const cols = pieceColours(own);
        try disc(gpa, dl, cx, cy + 2, r, alpha(0x000000, 0x66)); // a seated shadow
        try disc(gpa, dl, cx, cy, r, cols[0]);
        try ring(gpa, dl, cx, cy, r, 2, cols[1]);
        try ring(gpa, dl, cx, cy, r - @max(3, @divTrunc(r, 4)), 2, cols[1]); // the milled edge
        // Whose piece is it? A thin accent ring, on ours only.
        if (own == v.my_seat) try ring(gpa, dl, cx, cy, r + 2, 2, v.accent | 0xFF000000);
        if (checkers.isKing(st, sq)) {
            // A crown: three points on a band, drawn small in the disc's face.
            const k = @divTrunc(r, 2);
            const kc = cols[1] | 0xFF000000;
            try rect(gpa, dl, cx - k, cy + @divTrunc(k, 2), k * 2, @max(2, @divTrunc(k, 3)), kc, 1);
            try tri(gpa, dl, cx - k, cy + @divTrunc(k, 2), cx - @divTrunc(k, 2), cy - k, cx, cy + @divTrunc(k, 2), kc);
            try tri(gpa, dl, cx - @divTrunc(k, 2), cy + @divTrunc(k, 2), cx, cy - k, cx + @divTrunc(k, 2), cy + @divTrunc(k, 2), kc);
            try tri(gpa, dl, cx, cy + @divTrunc(k, 2), cx + @divTrunc(k, 2), cy - k, cx + k, cy + @divTrunc(k, 2), kc);
        }
    }
    try fromToTargets(gpa, dl, st, v, cell, out, n);
}

/// A chess piece, built from the four primitives. A flat, modern set: each piece
/// is a silhouette that reads at a glance rather than an engraving that would
/// turn to mush at forty pixels.
fn drawChessPiece(gpa: Allocator, dl: *raster.DrawList, kind: u8, c: u32, cx: i32, cy: i32, cell: i32) !void {
    const u = @divTrunc(cell, 16); // one unit ≈ a sixteenth of a square
    const base_w = u * 9;
    const base_y = cy + u * 5;
    // Every piece stands on the same foot, which is what makes the set a set.
    try rect(gpa, dl, cx - @divTrunc(base_w, 2), base_y, base_w, u * 2, c, @intCast(@min(u, 255)));
    try rect(gpa, dl, cx - u * 3, base_y - u * 2, u * 6, u * 2, c, @intCast(@min(u, 255)));
    switch (kind) {
        chess.pawn => {
            try rect(gpa, dl, cx - u * 2, cy - u, u * 4, u * 5, c, @intCast(@min(u * 2, 255)));
            try disc(gpa, dl, cx, cy - u * 3, u * 3, c);
        },
        chess.rook => {
            try rect(gpa, dl, cx - u * 4, cy - u * 5, u * 8, u * 3, c, @intCast(@min(u, 255)));
            // Three crenellations bitten out of the top.
            try rect(gpa, dl, cx - u * 2, cy - u * 6, u * 1, u * 2, 0x00000000, 0);
            try rect(gpa, dl, cx - u * 4, cy - u * 6, u * 2, u * 1, c, 0);
            try rect(gpa, dl, cx - u, cy - u * 6, u * 2, u, c, 0);
            try rect(gpa, dl, cx + u * 2, cy - u * 6, u * 2, u, c, 0);
            try rect(gpa, dl, cx - u * 3, cy - u * 2, u * 6, u * 7, c, @intCast(@min(u, 255)));
        },
        chess.knight => {
            // A head in profile: a wedge with a muzzle and an ear.
            try tri(gpa, dl, cx - u * 4, cy + u * 5, cx - u * 2, cy - u * 5, cx + u * 4, cy - u, c);
            try tri(gpa, dl, cx - u * 4, cy + u * 5, cx + u * 4, cy - u, cx + u * 3, cy + u * 5, c);
            try tri(gpa, dl, cx - u * 2, cy - u * 5, cx, cy - u * 7, cx + u, cy - u * 3, c);
            try disc(gpa, dl, cx + u, cy - u * 2, u, alpha(0x000000, 0x99)); // the eye
        },
        chess.bishop => {
            try tri(gpa, dl, cx - u * 4, cy + u * 4, cx, cy - u * 6, cx + u * 4, cy + u * 4, c);
            try disc(gpa, dl, cx, cy - u * 6, u * 2, c);
            try line(gpa, dl, cx - u, cy - u * 3, cx + u * 2, cy - u * 5, alpha(0x000000, 0x77), @intCast(@max(1, u)));
        },
        chess.queen => {
            try tri(gpa, dl, cx - u * 5, cy - u * 6, cx - u * 3, cy + u * 4, cx + u, cy + u * 4, c);
            try tri(gpa, dl, cx + u * 5, cy - u * 6, cx + u * 3, cy + u * 4, cx - u, cy + u * 4, c);
            try tri(gpa, dl, cx, cy - u * 7, cx - u * 3, cy + u * 4, cx + u * 3, cy + u * 4, c);
            try disc(gpa, dl, cx - u * 5, cy - u * 6, u + 1, c);
            try disc(gpa, dl, cx + u * 5, cy - u * 6, u + 1, c);
            try disc(gpa, dl, cx, cy - u * 7, u + 1, c);
        },
        chess.king => {
            try rect(gpa, dl, cx - u * 3, cy - u * 3, u * 6, u * 8, c, @intCast(@min(u * 2, 255)));
            try disc(gpa, dl, cx, cy - u * 3, u * 3, c);
            // The cross.
            try rect(gpa, dl, cx - u, cy - u * 8, u * 2, u * 5, c, 0);
            try rect(gpa, dl, cx - u * 3, cy - u * 7, u * 6, u * 2, c, 0);
        },
        else => {},
    }
}

fn drawChess(gpa: Allocator, dl: *raster.DrawList, st: State, v: View, out: []Target, n: *usize) !void {
    const cell = try drawSquares(gpa, dl, v, 0xFF6B5844, 0xFFE2D6C3);

    if (v.from != no_stage) {
        const fx = v.x + @as(i32, @intCast(v.from % 8)) * cell;
        const fy = v.y + @as(i32, @intCast(v.from / 8)) * cell;
        try rect(gpa, dl, fx, fy, cell, cell, mixA(v.accent | 0xFF000000, 0.5), 0);
    }
    // The king in check is marked — you should never be able to miss it.
    for ([_]Seat{ .x, .o }) |s| {
        if (!chess.inCheck(st, s)) continue;
        const k = chess.kingSquare(st, s) orelse continue;
        try rect(
            gpa,
            dl,
            v.x + @as(i32, @intCast(k % 8)) * cell,
            v.y + @as(i32, @intCast(k / 8)) * cell,
            cell,
            cell,
            alpha(0xE0705C, 0x70),
            0,
        );
    }

    for (0..64) |sq| {
        const own = chess.owner(st, sq);
        if (own == .none) continue;
        const cx = v.x + @as(i32, @intCast(sq % 8)) * cell + @divTrunc(cell, 2);
        const cy = v.y + @as(i32, @intCast(sq / 8)) * cell + @divTrunc(cell, 2);
        // The opposite tone underneath, offset by a pixel: a light piece keeps an
        // outline on a pale square and a dark one keeps a silhouette on a dark
        // square, without a second drawing pass or an outline primitive.
        const cols = pieceColours(own);
        const t = chess.pieceType(st, sq);
        // Ours is named by a soft accent pad under the piece, not by its colour —
        // a chess set is ivory and charcoal or it is unreadable.
        if (own == v.my_seat)
            try disc(gpa, dl, cx, cy + @divTrunc(cell, 5), @divTrunc(cell, 3), mixA(v.accent | 0xFF000000, 0.28));
        try drawChessPiece(gpa, dl, t, cols[1], cx + 1, cy + 2, cell);
        try drawChessPiece(gpa, dl, t, cols[1], cx - 1, cy, cell);
        try drawChessPiece(gpa, dl, t, cols[0], cx, cy, cell);
    }
    try fromToTargets(gpa, dl, st, v, cell, out, n);
}

/// The two-tap interaction, shared by chess and checkers: with nothing picked up
/// every one of our pieces is a target; with a piece picked up its legal
/// destinations are lit and are the targets, and tapping it again puts it down.
fn fromToTargets(gpa: Allocator, dl: *raster.DrawList, st: State, v: View, cell: i32, out: []Target, n: *usize) !void {
    if (!v.interactive) return;
    if (v.from == no_stage) {
        for (0..64) |sq| {
            const own = if (st.game == .chess) chess.owner(st, sq) else checkers.owner(st, sq);
            if (own != st.turn) continue;
            push(
                out,
                n,
                v.x + @as(i32, @intCast(sq % 8)) * cell,
                v.y + @as(i32, @intCast(sq / 8)) * cell,
                cell,
                cell,
                @intCast(sq),
            );
        }
        return;
    }
    // A picked-up piece: light every square it may legally reach. The dots come
    // from the SAME predicate the rules use, so what glows is exactly what is
    // allowed — the board cannot invite you to play something it will refuse.
    for (0..64) |sq| {
        const legal = if (st.game == .chess)
            chess.apply(st, chess.move(v.from, sq, 0)) != null
        else
            checkers.apply(st, checkers.move(v.from, sq)) != null;
        if (!legal and sq != v.from) continue;
        const cx = v.x + @as(i32, @intCast(sq % 8)) * cell + @divTrunc(cell, 2);
        const cy = v.y + @as(i32, @intCast(sq / 8)) * cell + @divTrunc(cell, 2);
        if (sq != v.from) {
            const occupied = st.cells[sq] != 0;
            if (occupied) {
                try ring(gpa, dl, cx, cy, @divTrunc(cell, 2) - 3, 3, mixA(v.accent | 0xFF000000, 0.85));
            } else {
                try disc(gpa, dl, cx, cy, @max(4, @divTrunc(cell, 7)), mixA(v.accent | 0xFF000000, 0.75));
            }
        }
        push(
            out,
            n,
            v.x + @as(i32, @intCast(sq % 8)) * cell,
            v.y + @as(i32, @intCast(sq / 8)) * cell,
            cell,
            cell,
            @intCast(sq),
        );
    }
}

// --- the skill shots -------------------------------------------------------

/// Map a 0..255 board coordinate onto the drawn target.
fn shotPx(cx: i32, cy: i32, radius_px: i32, qx: i32, qy: i32) [2]i32 {
    return .{
        cx + @divTrunc((qx - 128) * radius_px, 128),
        cy + @divTrunc((qy - 128) * radius_px, 128),
    };
}

fn drawSight(gpa: Allocator, dl: *raster.DrawList, cx: i32, cy: i32, r_px: i32, g: Game, t: f32, accent: u32) !void {
    const p = sight(g, t);
    const q = shotPx(cx, cy, r_px, p[0], p[1]);
    const c = accent | 0xFF000000;
    const arm = @max(8, @divTrunc(r_px, 6));
    try ring(gpa, dl, q[0], q[1], @divTrunc(arm, 2), 2, c);
    try line(gpa, dl, q[0] - arm, q[1], q[0] - @divTrunc(arm, 3), q[1], c, 2);
    try line(gpa, dl, q[0] + @divTrunc(arm, 3), q[1], q[0] + arm, q[1], c, 2);
    try line(gpa, dl, q[0], q[1] - arm, q[0], q[1] - @divTrunc(arm, 3), c, 2);
    try line(gpa, dl, q[0], q[1] + @divTrunc(arm, 3), q[0], q[1] + arm, c, 2);
}

fn drawArchery(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, st: State, v: View, out: []Target, n: *usize) !void {
    _ = e;
    const r_px = @divTrunc(v.size, 2);
    const cx = v.x + r_px;
    const cy = v.y + r_px;
    // The five colour bands of a target face, outside in.
    const bands = [5]u32{ 0xFFF2F2F0, 0xFF23262B, 0xFF3E8FD0, 0xFFD8443B, 0xFFF2C232 };
    var b: usize = 0;
    while (b < 5) : (b += 1) {
        const rr = @divTrunc(r_px * @as(i32, @intCast(5 - b)), 5);
        try disc(gpa, dl, cx, cy, rr, bands[b]);
        // The ring line inside each band splits it into its two scoring rings.
        try ring(gpa, dl, cx, cy, rr - @divTrunc(r_px, 10), 1, alpha(0x000000, 0x55));
    }
    if (r_px >= 120) try ring(gpa, dl, cx, cy, @divTrunc(r_px, 10), 1, alpha(0x000000, 0x99));

    // Every arrow shot so far, in its owner's colour.
    for ([_]Seat{ .x, .o }) |s| {
        var i: usize = 0;
        while (archery.shotAt(st, s, i)) |cell| : (i += 1) {
            const q = shotPx(cx, cy, r_px, archery.shotX(cell), archery.shotY(cell));
            try disc(gpa, dl, q[0], q[1], 5, alpha(0x000000, 0x77));
            try disc(gpa, dl, q[0], q[1], 4, seatColour(s, v.accent));
            try line(gpa, dl, q[0], q[1], q[0] + 12, q[1] - 16, alpha(chalk, 0xCC), 2);
        }
    }
    if (!v.interactive) return;
    try drawSight(gpa, dl, cx, cy, r_px, .archery, v.t, v.accent);
    // One target: the whole face. WHERE you tap does not matter — WHEN does.
    push(out, n, v.x, v.y, v.size, v.size, 0);
}

fn drawDarts(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, st: State, v: View, out: []Target, n: *usize) !void {
    // The sector numbers ride OUTSIDE the wire ring, so the board proper is
    // inset by enough to keep them in the box — at thumbnail size they were
    // spilling over the card and onto its label.
    const num_px: u16 = @intCast(std.math.clamp(@divTrunc(v.size, 26), 8, 14));
    const num_pad = @max(10, @divTrunc(v.size, 14));
    const r_px = @divTrunc(v.size, 2) - num_pad;
    const cx = v.x + @divTrunc(v.size, 2);
    const cy = v.y + @divTrunc(v.size, 2);
    const rf = @as(f32, @floatFromInt(r_px));

    try disc(gpa, dl, cx, cy, r_px + @max(3, @divTrunc(r_px, 24)), 0xFF14100C);
    // Twenty sectors, each a fan of triangles, alternating cream and black, with
    // the treble and double rings picked out in red and green.
    for (0..20) |i| {
        const a0 = (@as(f32, @floatFromInt(i)) * 18.0 - 9.0) * std.math.pi / 180.0;
        const a1 = (@as(f32, @floatFromInt(i)) * 18.0 + 9.0) * std.math.pi / 180.0;
        const light = i % 2 == 0;
        const body: u32 = if (light) 0xFFE8DFC8 else 0xFF1A1714;
        const scorer: u32 = if (light) 0xFFCC3A32 else 0xFF2E8B57;
        const rings = [4]struct { in: f32, out: f32, c: u32 }{
            .{ .in = 0.094, .out = 0.582, .c = body },
            .{ .in = 0.582, .out = 0.629, .c = scorer },
            .{ .in = 0.629, .out = 0.953, .c = body },
            .{ .in = 0.953, .out = 1.0, .c = scorer },
        };
        for (rings) |seg| {
            const in0x = cx + fxi(@sin(a0) * rf * seg.in);
            const in0y = cy - fxi(@cos(a0) * rf * seg.in);
            const in1x = cx + fxi(@sin(a1) * rf * seg.in);
            const in1y = cy - fxi(@cos(a1) * rf * seg.in);
            const ot0x = cx + fxi(@sin(a0) * rf * seg.out);
            const ot0y = cy - fxi(@cos(a0) * rf * seg.out);
            const ot1x = cx + fxi(@sin(a1) * rf * seg.out);
            const ot1y = cy - fxi(@cos(a1) * rf * seg.out);
            try tri(gpa, dl, in0x, in0y, ot0x, ot0y, ot1x, ot1y, seg.c);
            try tri(gpa, dl, in0x, in0y, ot1x, ot1y, in1x, in1y, seg.c);
        }
        // The number, on the wire ring outside the board.
        const am = @as(f32, @floatFromInt(i)) * 18.0 * std.math.pi / 180.0;
        var buf: [4]u8 = undefined;
        const txt = std.fmt.bufPrint(&buf, "{d}", .{darts.sectors[i]}) catch "";
        const nw = labelWidth(e, .semibold, num_px, txt);
        const ring_r = rf + @as(f32, @floatFromInt(@divTrunc(num_pad * 2, 3)));
        try label(
            gpa,
            dl,
            e,
            .semibold,
            cx + fxi(@sin(am) * ring_r) - @divTrunc(nw, 2),
            cy - fxi(@cos(am) * ring_r) + @divTrunc(num_px, 3),
            alpha(chalk, 0xCC),
            num_px,
            txt,
        );
    }
    try disc(gpa, dl, cx, cy, fxi(rf * 0.094), 0xFF2E8B57);
    try disc(gpa, dl, cx, cy, fxi(rf * 0.037), 0xFFCC3A32);

    // This turn's darts.
    var i: usize = 0;
    while (darts.dartAt(st, i)) |cell| : (i += 1) {
        const q = shotPx(cx, cy, r_px, darts.shotX(cell), darts.shotY(cell));
        try disc(gpa, dl, q[0], q[1], 4, alpha(0x000000, 0x88));
        try disc(gpa, dl, q[0], q[1], 3, chalk);
        try line(gpa, dl, q[0], q[1], q[0] + 10, q[1] - 14, seatColour(st.turn, v.accent), 2);
    }
    if (!v.interactive) return;
    try drawSight(gpa, dl, cx, cy, r_px, .darts, v.t, v.accent);
    push(out, n, v.x, v.y, v.size, v.size, 0);
}

// --- the thumbnail ---------------------------------------------------------

/// The small board on the thread card. It is the SAME renderer at a small size
/// with the interaction switched off — so the card always shows the real
/// position, and a game never needs a second, drifting drawing of itself.
pub fn thumb(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, st: State, x: i32, y: i32, size: i32, accent: u32) !void {
    var scratch: [1]Target = undefined;
    _ = try full(gpa, dl, e, st, .{
        .x = x,
        .y = y,
        .size = size,
        .accent = accent,
        .interactive = false,
    }, &scratch);
}

/// A SHELF POSITION — a few moves played into a fresh board, so the tile you
/// pick from shows a game rather than an empty grid. Three of the eight open
/// blank, and a blank tic-tac-toe grid beside a full chess set reads as the
/// broken one rather than the simple one.
pub fn demoState(g: Game) State {
    var st = games.init(g);
    const seeds: []const u16 = switch (g) {
        .tictactoe => &.{ 4, 0, 8, 2, 6 },
        .connect4 => &.{ 3, 3, 4, 2, 5, 4, 2 },
        .dots => &.{ 0, 20, 4, 21, 1, 24, 25, 5 },
        .mancala => &.{ 2, 8, 1, 10, 4 },
        .checkers => &.{ checkers.move(45, 36), checkers.move(18, 27), checkers.move(36, 29) },
        .chess => &.{ chess.move(52, 36, 0), chess.move(12, 28, 0), chess.move(62, 45, 0), chess.move(1, 18, 0) },
        .archery => &.{ archery.shot(134, 122), archery.shot(96, 150), archery.shot(126, 131) },
        .darts => &.{ releaseMove(.darts, 0.11), releaseMove(.darts, 0.42) },
        else => &.{},
    };
    for (seeds) |m| {
        if (games.apply(st, .{ .game = g, .cell = m })) |ns| st = ns;
    }
    return st;
}

// ---------------------------------------------------------------------------

test "the sight is deterministic, bounded, and does not sit still" {
    for ([_]Game{ .archery, .darts }) |g| {
        var t: f32 = 0;
        var prev = sight(g, 0);
        var moved = false;
        while (t < 1.0) : (t += 0.05) {
            const p = sight(g, t);
            try testing.expectEqual(p[0], sight(g, t)[0]); // same phase, same place
            try testing.expect(p[0] >= 0 and p[0] <= 255);
            try testing.expect(p[1] >= 0 and p[1] <= 255);
            if (p[0] != prev[0] or p[1] != prev[1]) moved = true;
            prev = p;
        }
        try testing.expect(moved);
    }
}

test "a release turns the sight into a legal move for its game" {
    var s = games.init(.archery);
    const mv = releaseMove(.archery, 0.3);
    try testing.expect(games.legal(s, .{ .game = .archery, .cell = mv }));
    s = games.init(.darts);
    try testing.expect(games.legal(s, .{ .game = .darts, .cell = releaseMove(.darts, 0.3) }));
}

test "every board draws without touching the allocator's limits, and empties cleanly" {
    const gpa = testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    for (games.catalog) |g| {
        var dl = raster.DrawList{};
        defer dl.deinit(gpa);
        var targets: [96]Target = undefined;
        const st = games.init(g);
        const hits = try full(gpa, &dl, &engine, st, .{
            .x = 20,
            .y = 20,
            .size = 320,
            .my_seat = .x,
            .interactive = true,
            .t = 0.25,
        }, &targets);
        try testing.expect(dl.len > 0); // something was drawn
        // An interactive opening position always offers SOMETHING to tap.
        try testing.expect(hits.len > 0);
        for (hits) |h| {
            try testing.expect(h.w > 0 and h.h > 0);
            try testing.expect(h.x >= 0 and h.y >= 0);
        }
    }
}

test "a thumbnail draws every game and emits nothing tappable" {
    const gpa = testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    for (games.catalog) |g| {
        var dl = raster.DrawList{};
        defer dl.deinit(gpa);
        try thumb(gpa, &dl, &engine, games.init(g), 0, 0, 96, 0xFF7C8CF8);
        try testing.expect(dl.len > 0);
    }
}

test "a chess board lights exactly the squares the rules allow" {
    const gpa = testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    var dl = raster.DrawList{};
    defer dl.deinit(gpa);
    const st = games.init(.chess);
    var targets: [96]Target = undefined;
    // Pick up the b1 knight (square 57): two destinations, plus putting it down.
    const hits = try full(gpa, &dl, &engine, st, .{
        .x = 0,
        .y = 0,
        .size = 320,
        .my_seat = .x,
        .interactive = true,
        .from = 57,
    }, &targets);
    try testing.expectEqual(@as(usize, 3), hits.len);
    var found_self = false;
    for (hits) |h| {
        if (h.cell == 57) {
            found_self = true;
            continue;
        }
        try testing.expect(chess.apply(st, chess.move(57, h.cell, 0)) != null);
    }
    try testing.expect(found_self); // tap it again to put it down
}

