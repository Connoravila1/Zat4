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

//! B1 classification: CORE (pure). ARCHERY — the rules and the scoring.
//!
//! The first game here that is not played by choosing a square. You hold a
//! drifting sight over a target and release; the move carries WHERE THE ARROW
//! LANDED, quantized to a byte per axis:
//!
//!   ```
//!   cell = x | (y << 8)     x, y ∈ 0..255, the target centred at (128,128)
//!   ```
//!
//! Five arrows each, alternating, highest total wins.
//!
//! **On trust.** A skill shot is self-reported: the sender's own client decides
//! where the arrow went, so a modified client could always claim a ten. That is
//! true of every casual skill game played this way, and the honest fix — a shared
//! deterministic simulation with the release TIMING on the wire — buys very
//! little here, because the timing is just as forgeable as the landing. So the
//! landing is what travels, the scoring is done identically on both ends from it,
//! and a cheat degrades to "they claimed a perfect round", which is visible in
//! the thread. Nothing else in the app trusts a peer this way; a game does.

const std = @import("std");
const testing = std.testing;
const board = @import("board.zig");
const State = board.State;
const Seat = board.Seat;
const Outcome = board.Outcome;

/// Arrows each player shoots.
pub const arrows = 5;
/// The target's outer radius in the quantized units the move carries.
pub const radius = 128;
/// The quantized centre of the target.
pub const centre = 128;

/// Where each side's arrows are recorded, two bytes (x, y) per arrow.
const x_shots: usize = 0; // cells[0..9]
const o_shots: usize = arrows * 2; // cells[10..19]

const aux_x_total: usize = 0; // u16
const aux_o_total: usize = 2; // u16
const aux_x_count: usize = 4;
const aux_o_count: usize = 5;

pub fn setup(s: *State) void {
    _ = s;
}

/// Unpack a landing point.
pub fn shotX(cell: u16) i32 {
    return @intCast(cell & 0xFF);
}
pub fn shotY(cell: u16) i32 {
    return @intCast((cell >> 8) & 0xFF);
}
/// Pack a landing point.
pub fn shot(x: i32, y: i32) u16 {
    const cx: u16 = @intCast(std.math.clamp(x, 0, 255));
    const cy: u16 = @intCast(std.math.clamp(y, 0, 255));
    return cx | (cy << 8);
}

/// What an arrow landing at `cell` is worth: ten rings, ten in the middle, and
/// nothing at all off the target.
pub fn scoreOf(cell: u16) u8 {
    const dx = shotX(cell) - centre;
    const dy = shotY(cell) - centre;
    const d2 = dx * dx + dy * dy;
    if (d2 >= radius * radius) return 0;
    const d: i32 = @intFromFloat(@sqrt(@as(f32, @floatFromInt(d2))));
    const ring = 10 - @divTrunc(d * 10, radius);
    return @intCast(std.math.clamp(ring, 1, 10));
}

/// How many arrows `v` has shot.
pub fn shotCount(s: State, v: Seat) u8 {
    return s.aux[if (v == .x) aux_x_count else aux_o_count];
}

/// `v`'s running total.
pub fn total(s: State, v: Seat) u16 {
    return board.auxU16(s, if (v == .x) aux_x_total else aux_o_total);
}

/// The `i`-th arrow `v` shot, or null if it has not been shot yet. The renderer
/// walks these to draw the arrows standing in the target.
pub fn shotAt(s: State, v: Seat, i: usize) ?u16 {
    if (i >= shotCount(s, v)) return null;
    const base = (if (v == .x) x_shots else o_shots) + i * 2;
    return @as(u16, s.cells[base]) | (@as(u16, s.cells[base + 1]) << 8);
}

/// Loose an arrow at `cell`.
pub fn apply(s: State, cell: u16) ?State {
    const v = s.turn;
    const n = shotCount(s, v);
    if (n >= arrows) return null; // out of arrows

    var ns = s;
    const base = (if (v == .x) x_shots else o_shots) + @as(usize, n) * 2;
    ns.cells[base] = @intCast(cell & 0xFF);
    ns.cells[base + 1] = @intCast((cell >> 8) & 0xFF);
    ns.aux[if (v == .x) aux_x_count else aux_o_count] = n + 1;
    board.setAuxU16(
        &ns,
        if (v == .x) aux_x_total else aux_o_total,
        total(s, v) + scoreOf(cell),
    );
    ns.turn = v.other();

    if (shotCount(ns, .x) >= arrows and shotCount(ns, .o) >= arrows) {
        const tx = total(ns, .x);
        const to = total(ns, .o);
        ns.outcome = if (tx > to) .x_wins else if (to > tx) .o_wins else .draw;
    }
    return ns;
}

// ---------------------------------------------------------------------------

fn fresh() State {
    var s = board.blank(.archery);
    setup(&s);
    return s;
}

test "the middle is a ten, the rim is a one, and off the target is nothing" {
    try testing.expectEqual(@as(u8, 10), scoreOf(shot(centre, centre)));
    try testing.expectEqual(@as(u8, 10), scoreOf(shot(centre + 12, centre)));
    try testing.expectEqual(@as(u8, 1), scoreOf(shot(centre + 127, centre)));
    try testing.expectEqual(@as(u8, 0), scoreOf(shot(0, 0))); // a corner is off the round target
    try testing.expectEqual(@as(u8, 0), scoreOf(shot(centre + 100, centre + 100)));
    // The byte range cannot express a point further than 127 out, so the rim is
    // as far as a recorded arrow ever lands on the axis — it still scores 1.
    try testing.expectEqual(@as(u8, 1), scoreOf(shot(centre + 200, centre)));
    // The rings step down monotonically as the arrow lands further out.
    var prev: u8 = 11;
    var d: i32 = 0;
    while (d < radius) : (d += 8) {
        const v = scoreOf(shot(centre + d, centre));
        try testing.expect(v <= prev);
        prev = v;
    }
}

test "arrows alternate and are recorded for the renderer" {
    var s = fresh();
    s = apply(s, shot(centre, centre)).?;
    try testing.expectEqual(Seat.o, s.turn);
    try testing.expectEqual(@as(u16, 10), total(s, .x));
    try testing.expectEqual(@as(u8, 1), shotCount(s, .x));
    try testing.expectEqual(shot(centre, centre), shotAt(s, .x, 0).?);
    try testing.expectEqual(@as(?u16, null), shotAt(s, .x, 1));
    try testing.expectEqual(@as(?u16, null), shotAt(s, .o, 0));
}

test "a full round of five arrows each decides it on the totals" {
    var s = fresh();
    var i: usize = 0;
    while (i < arrows) : (i += 1) {
        s = apply(s, shot(centre, centre)).?; // X: bullseye every time
        s = apply(s, shot(centre + 100, centre)).?; // O: out near the rim
    }
    try testing.expectEqual(@as(u16, 50), total(s, .x));
    try testing.expect(total(s, .o) < 50);
    try testing.expectEqual(Outcome.x_wins, s.outcome);
    try testing.expectEqual(@as(?State, null), apply(s, shot(centre, centre))); // no arrows left
}

test "identical rounds are a draw" {
    var s = fresh();
    var i: usize = 0;
    while (i < arrows) : (i += 1) {
        s = apply(s, shot(centre + 40, centre)).?;
        s = apply(s, shot(centre, centre + 40)).?;
    }
    try testing.expectEqual(total(s, .x), total(s, .o));
    try testing.expectEqual(Outcome.draw, s.outcome);
}
