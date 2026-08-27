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

//! B1 classification: CORE (pure). DARTS — 501, three darts a turn, double out.
//!
//! Like archery, the move carries WHERE THE DART LANDED (see that module's note
//! on trusting a skill shot):
//!
//!   ```
//!   cell = x | (y << 8)     x, y ∈ 0..255, the board centred at (128,128)
//!   ```
//!
//! The scoring is the real board: twenty sectors in the standard order with 20 at
//! the top, a treble ring, a double ring, a 25 outer bull and a 50 inner bull.
//! You start on 501 and subtract; you must land EXACTLY on zero with a double (or
//! the inner bull, which counts as a double 25). Going below zero, landing on
//! one, or hitting zero with anything but a double is a BUST: the turn's darts
//! are undone and play passes.
//!
//! `aux`: [0..1] X's remaining, [2..3] O's, [4] darts thrown this turn,
//! [5..6] the score this turn started on (what a bust reverts to), [7] the last
//! dart's face value, [8] its multiplier.

const std = @import("std");
const testing = std.testing;
const board = @import("board.zig");
const State = board.State;
const Seat = board.Seat;
const Outcome = board.Outcome;

pub const start_score: u16 = 501;
pub const darts_per_turn = 3;
pub const radius = 128;
pub const centre = 128;

/// The twenty sectors clockwise from the top.
pub const sectors = [20]u8{ 20, 1, 18, 4, 13, 6, 10, 15, 2, 17, 3, 19, 7, 16, 8, 11, 14, 9, 12, 5 };

// Ring radii as a fraction of the board radius, from the real board's geometry.
const r_inner_bull = 0.037;
const r_outer_bull = 0.094;
const r_treble_in = 0.582;
const r_treble_out = 0.629;
const r_double_in = 0.953;

const aux_x_rem: usize = 0;
const aux_o_rem: usize = 2;
const aux_darts: usize = 4;
const aux_turn_start: usize = 5;
const aux_last_face: usize = 7;
const aux_last_mult: usize = 8;

/// Where the current turn's darts are recorded, two bytes (x, y) each.
const shots_base: usize = 0;

pub fn setup(s: *State) void {
    board.setAuxU16(s, aux_x_rem, start_score);
    board.setAuxU16(s, aux_o_rem, start_score);
    board.setAuxU16(s, aux_turn_start, start_score);
}

pub fn shotX(cell: u16) i32 {
    return @intCast(cell & 0xFF);
}
pub fn shotY(cell: u16) i32 {
    return @intCast((cell >> 8) & 0xFF);
}
pub fn shot(x: i32, y: i32) u16 {
    const cx: u16 = @intCast(std.math.clamp(x, 0, 255));
    const cy: u16 = @intCast(std.math.clamp(y, 0, 255));
    return cx | (cy << 8);
}

/// What a dart landing at `cell` is worth: the face value and the multiplier
/// (1 single, 2 double, 3 treble). A miss is 0 × 0.
pub const Hit = struct {
    face: u8,
    mult: u8,

    /// The points it takes off.
    pub fn points(h: Hit) u16 {
        return @as(u16, h.face) * @as(u16, h.mult);
    }
};

/// Score a landing point against the real board's geometry.
pub fn hitOf(cell: u16) Hit {
    const dx: f32 = @floatFromInt(shotX(cell) - centre);
    const dy: f32 = @floatFromInt(shotY(cell) - centre);
    const d = @sqrt(dx * dx + dy * dy) / @as(f32, radius);
    if (d <= r_inner_bull) return .{ .face = 25, .mult = 2 }; // the 50 counts as a double
    if (d <= r_outer_bull) return .{ .face = 25, .mult = 1 };
    if (d > 1.0) return .{ .face = 0, .mult = 0 }; // off the board

    // Clockwise from straight up; the 20 sector straddles the top, so shift by
    // half a sector before dividing.
    const ang = std.math.atan2(dx, -dy); // −π..π, 0 = up
    var deg = ang * 180.0 / std.math.pi + 9.0;
    if (deg < 0) deg += 360.0;
    if (deg >= 360.0) deg -= 360.0;
    const idx: usize = @intFromFloat(deg / 18.0);
    const face = sectors[@min(idx, sectors.len - 1)];

    if (d >= r_treble_in and d <= r_treble_out) return .{ .face = face, .mult = 3 };
    if (d >= r_double_in) return .{ .face = face, .mult = 2 };
    return .{ .face = face, .mult = 1 };
}

/// What `v` still has to take off.
pub fn remaining(s: State, v: Seat) u16 {
    return board.auxU16(s, if (v == .x) aux_x_rem else aux_o_rem);
}

/// Darts thrown so far in this turn (0..2 while it is still going).
pub fn dartsThrown(s: State) u8 {
    return s.aux[aux_darts];
}

/// The `i`-th dart of the CURRENT turn, for the renderer.
pub fn dartAt(s: State, i: usize) ?u16 {
    if (i >= dartsThrown(s)) return null;
    const base = shots_base + i * 2;
    return @as(u16, s.cells[base]) | (@as(u16, s.cells[base + 1]) << 8);
}

/// The last dart's face and multiplier — what the "TREBLE 20" flash reads from.
pub fn lastHit(s: State) Hit {
    return .{ .face = s.aux[aux_last_face], .mult = s.aux[aux_last_mult] };
}

fn setRemaining(s: *State, v: Seat, val: u16) void {
    board.setAuxU16(s, if (v == .x) aux_x_rem else aux_o_rem, val);
}

/// Hand the turn over: reset the dart count and remember what the new player is
/// starting from, so THEIR bust reverts to the right number.
fn passTurn(s: *State, to: Seat) void {
    s.turn = to;
    s.aux[aux_darts] = 0;
    board.setAuxU16(s, aux_turn_start, remaining(s.*, to));
    for (0..darts_per_turn * 2) |i| s.cells[shots_base + i] = 0;
}

/// Throw a dart at `cell`.
pub fn apply(s: State, cell: u16) ?State {
    const v = s.turn;
    const n = dartsThrown(s);
    if (n >= darts_per_turn) return null; // the turn is spent

    var ns = s;
    const base = shots_base + @as(usize, n) * 2;
    ns.cells[base] = @intCast(cell & 0xFF);
    ns.cells[base + 1] = @intCast((cell >> 8) & 0xFF);
    ns.aux[aux_darts] = n + 1;

    const h = hitOf(cell);
    ns.aux[aux_last_face] = h.face;
    ns.aux[aux_last_mult] = h.mult;

    const rem = remaining(s, v);
    const pts = h.points();

    // BUST: below zero, stranded on one, or checking out on something that is
    // not a double. The whole turn is undone — that is the rule that makes the
    // last hundred points the hard part.
    const bust = pts > rem or rem - pts == 1 or (pts == rem and h.mult != 2);
    if (bust) {
        setRemaining(&ns, v, board.auxU16(s, aux_turn_start));
        passTurn(&ns, v.other());
        return ns;
    }

    setRemaining(&ns, v, rem - pts);
    if (rem - pts == 0) {
        ns.outcome = board.winFor(v);
        return ns;
    }
    if (n + 1 >= darts_per_turn) passTurn(&ns, v.other());
    return ns;
}

// ---------------------------------------------------------------------------

fn fresh() State {
    var s = board.blank(.darts);
    setup(&s);
    return s;
}

/// A landing point in sector `face` at radius fraction `frac`.
fn aim(face: u8, frac: f32) u16 {
    var idx: usize = 0;
    for (sectors, 0..) |f, i| {
        if (f == face) idx = i;
    }
    const deg = @as(f32, @floatFromInt(idx)) * 18.0;
    const rad = deg * std.math.pi / 180.0;
    const r = frac * @as(f32, radius);
    const x = centre + @as(i32, @intFromFloat(@sin(rad) * r));
    const y = centre - @as(i32, @intFromFloat(@cos(rad) * r));
    return shot(x, y);
}

test "the bull, the outer bull and a miss score what they should" {
    try testing.expectEqual(@as(u16, 50), hitOf(shot(centre, centre)).points());
    try testing.expectEqual(@as(u8, 2), hitOf(shot(centre, centre)).mult); // a double, so it can check out
    try testing.expectEqual(@as(u16, 25), hitOf(aim(20, 0.07)).points());
    try testing.expectEqual(@as(u16, 0), hitOf(shot(0, 0)).points());
}

test "the sectors sit where the real board puts them" {
    try testing.expectEqual(@as(u8, 20), hitOf(aim(20, 0.4)).face); // straight up
    try testing.expectEqual(@as(u8, 6), hitOf(aim(6, 0.4)).face); // three o'clock
    try testing.expectEqual(@as(u8, 3), hitOf(aim(3, 0.4)).face); // straight down
    try testing.expectEqual(@as(u8, 11), hitOf(aim(11, 0.4)).face); // nine o'clock
    // Every sector round the board maps back to itself.
    for (sectors) |f| try testing.expectEqual(f, hitOf(aim(f, 0.4)).face);
}

test "the treble and double rings multiply" {
    try testing.expectEqual(@as(u16, 60), hitOf(aim(20, 0.605)).points());
    try testing.expectEqual(@as(u16, 40), hitOf(aim(20, 0.98)).points());
    try testing.expectEqual(@as(u16, 20), hitOf(aim(20, 0.4)).points());
}

test "three darts pass the turn and the score comes down" {
    var s = fresh();
    try testing.expectEqual(@as(u16, 501), remaining(s, .x));
    s = apply(s, aim(20, 0.605)).?; // T20
    try testing.expectEqual(@as(u16, 441), remaining(s, .x));
    try testing.expectEqual(Seat.x, s.turn); // still throwing
    s = apply(s, aim(20, 0.605)).?;
    s = apply(s, aim(20, 0.605)).?;
    try testing.expectEqual(@as(u16, 321), remaining(s, .x));
    try testing.expectEqual(Seat.o, s.turn); // three darts, hand over
    try testing.expectEqual(@as(u8, 0), dartsThrown(s));
}

test "BUST: going below zero undoes the whole turn" {
    var s = fresh();
    board.setAuxU16(&s, aux_x_rem, 40);
    board.setAuxU16(&s, aux_turn_start, 40);
    s = apply(s, aim(20, 0.4)).?; // single 20 → 20 left
    try testing.expectEqual(@as(u16, 20), remaining(s, .x));
    s = apply(s, aim(20, 0.605)).?; // treble 20 → far past zero
    try testing.expectEqual(@as(u16, 40), remaining(s, .x)); // reverted to the turn's start
    try testing.expectEqual(Seat.o, s.turn);
}

test "BUST: you may not be left on one, and you may not check out on a single" {
    var s = fresh();
    board.setAuxU16(&s, aux_x_rem, 21);
    board.setAuxU16(&s, aux_turn_start, 21);
    const stranded = apply(s, aim(20, 0.4)).?; // 21 − 20 = 1
    try testing.expectEqual(@as(u16, 21), remaining(stranded, .x));
    try testing.expectEqual(Seat.o, stranded.turn);

    board.setAuxU16(&s, aux_x_rem, 20);
    board.setAuxU16(&s, aux_turn_start, 20);
    const single_out = apply(s, aim(20, 0.4)).?; // exactly zero, but on a single
    try testing.expectEqual(@as(u16, 20), remaining(single_out, .x));
    try testing.expectEqual(Outcome.ongoing, single_out.outcome);
}

test "checking out on a double wins it" {
    var s = fresh();
    board.setAuxU16(&s, aux_x_rem, 40);
    board.setAuxU16(&s, aux_turn_start, 40);
    const won = apply(s, aim(20, 0.98)).?; // double 20
    try testing.expectEqual(@as(u16, 0), remaining(won, .x));
    try testing.expectEqual(Outcome.x_wins, won.outcome);
}

test "the inner bull is a double, so it checks out from 50" {
    var s = fresh();
    board.setAuxU16(&s, aux_x_rem, 50);
    board.setAuxU16(&s, aux_turn_start, 50);
    const won = apply(s, shot(centre, centre)).?;
    try testing.expectEqual(Outcome.x_wins, won.outcome);
}

test "a bust reverts to the score THIS player started the turn on, not the opponent's" {
    var s = fresh();
    // X throws three, handing over; O then busts and must revert to 501.
    s = apply(s, aim(20, 0.605)).?;
    s = apply(s, aim(20, 0.605)).?;
    s = apply(s, aim(20, 0.605)).?;
    try testing.expectEqual(Seat.o, s.turn);
    try testing.expectEqual(@as(u16, 501), board.auxU16(s, aux_turn_start));
    board.setAuxU16(&s, aux_o_rem, 5);
    board.setAuxU16(&s, aux_turn_start, 5);
    const busted = apply(s, aim(20, 0.4)).?;
    try testing.expectEqual(@as(u16, 5), remaining(busted, .o));
    try testing.expectEqual(@as(u16, 321), remaining(busted, .x)); // X's score untouched
}
