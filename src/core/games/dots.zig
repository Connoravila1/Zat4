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

//! B1 classification: CORE (pure). DOTS & BOXES — the rules only.
//!
//! A 5×5 grid of dots, so 4×4 = 16 boxes and 40 edges. Layout in `cells`:
//!
//!   ```
//!   [ 0 ..19]  horizontal edges, `row * 4 + col`  (5 rows × 4 columns)
//!   [20 ..39]  vertical edges,   20 + `row * 5 + col` (4 rows × 5 columns)
//!   [40 ..55]  box owners,       40 + `row * 4 + col`
//!   ```
//!
//! Move: the edge you draw. The rule that makes it a game: closing a box scores
//! it AND gives you another turn, so a chain of boxes falls to one player.

const std = @import("std");
const testing = std.testing;
const board = @import("board.zig");
const State = board.State;
const Seat = board.Seat;
const Outcome = board.Outcome;

pub const grid = 4; // boxes per side
pub const h_edges = (grid + 1) * grid; // 20
pub const v_edges = grid * (grid + 1); // 20
pub const edges = h_edges + v_edges; // 40
pub const box_base = edges; // 40
pub const boxes = grid * grid; // 16

/// The horizontal edge above row `r`, column `c`.
pub fn hEdge(r: usize, c: usize) usize {
    return r * grid + c;
}
/// The vertical edge left of row `r`, column `c`.
pub fn vEdge(r: usize, c: usize) usize {
    return h_edges + r * (grid + 1) + c;
}

pub fn setup(s: *State) void {
    _ = s;
}

/// Has this edge been drawn, and by whom?
pub fn edgeOwner(s: State, e: usize) Seat {
    if (e >= edges) return .none;
    return board.seatAt(s, e);
}

/// Who closed box (r,c)?
pub fn boxOwner(s: State, r: usize, c: usize) Seat {
    return board.seatAt(s, box_base + r * grid + c);
}

/// The four edges of box (r,c).
fn boxEdges(r: usize, c: usize) [4]usize {
    return .{ hEdge(r, c), hEdge(r + 1, c), vEdge(r, c), vEdge(r, c + 1) };
}

/// Draw `edge` for `s.turn`, claiming any box it closes.
pub fn apply(s: State, edge: u16) ?State {
    const e: usize = edge;
    if (e >= edges) return null;
    if (edgeOwner(s, e) != .none) return null; // already drawn

    var ns = s;
    board.setSeat(&ns, e, s.turn);

    // Any box this edge just completed is claimed, and claiming means another go.
    var claimed = false;
    for (0..grid) |r| {
        for (0..grid) |c| {
            if (boxOwner(ns, r, c) != .none) continue;
            var closed = true;
            for (boxEdges(r, c)) |be| {
                if (edgeOwner(ns, be) == .none) closed = false;
            }
            if (!closed) continue;
            board.setSeat(&ns, box_base + r * grid + c, s.turn);
            claimed = true;
        }
    }
    ns.turn = if (claimed) s.turn else s.turn.other();

    // The game ends when every box is claimed; the bigger score wins.
    var mine: u8 = 0;
    var theirs: u8 = 0;
    for (0..boxes) |b| {
        switch (board.seatAt(ns, box_base + b)) {
            .x => mine += 1,
            .o => theirs += 1,
            .none => {},
        }
    }
    if (mine + theirs >= boxes) {
        ns.outcome = if (mine > theirs) .x_wins else if (theirs > mine) .o_wins else .draw;
    }
    return ns;
}

/// How many boxes `v` has closed — the score line the view prints.
pub fn score(s: State, v: Seat) u8 {
    var n: u8 = 0;
    for (0..boxes) |b| {
        if (board.seatAt(s, box_base + b) == v) n += 1;
    }
    return n;
}

// ---------------------------------------------------------------------------

fn fresh() State {
    var s = board.blank(.dots);
    setup(&s);
    return s;
}

fn play(s0: State, seq: []const u16) State {
    var s = s0;
    for (seq) |e| {
        if (s.outcome != .ongoing) break;
        if (apply(s, e)) |ns| s = ns;
    }
    return s;
}

test "the layout numbers 40 edges and 16 boxes without overlapping" {
    try testing.expectEqual(@as(usize, 40), edges);
    try testing.expectEqual(@as(usize, 0), hEdge(0, 0));
    try testing.expectEqual(@as(usize, 19), hEdge(4, 3));
    try testing.expectEqual(@as(usize, 20), vEdge(0, 0));
    try testing.expectEqual(@as(usize, 39), vEdge(3, 4));
    try testing.expect(box_base + boxes <= board.board_cells);
}

test "drawing an edge passes the turn; drawing it twice is illegal" {
    const s = play(fresh(), &.{@intCast(hEdge(0, 0))});
    try testing.expectEqual(Seat.o, s.turn);
    try testing.expectEqual(@as(?State, null), apply(s, @intCast(hEdge(0, 0))));
    try testing.expectEqual(@as(?State, null), apply(s, 40));
}

test "closing a box scores it AND gives you another turn" {
    // X draws three sides of box (0,0); O is forced to take an edge elsewhere;
    // X closes it and goes again.
    var s = fresh();
    s = play(s, &.{
        @intCast(hEdge(0, 0)), // X
        @intCast(hEdge(4, 3)), // O, far away
        @intCast(vEdge(0, 0)), // X
        @intCast(hEdge(4, 2)), // O
        @intCast(vEdge(0, 1)), // X
        @intCast(hEdge(4, 1)), // O
        @intCast(hEdge(1, 0)), // X closes box (0,0)
    });
    try testing.expectEqual(Seat.x, boxOwner(s, 0, 0));
    try testing.expectEqual(@as(u8, 1), score(s, .x));
    try testing.expectEqual(Seat.x, s.turn); // another go
}

test "ONE edge can close TWO boxes at once, and both are scored" {
    // Box (0,0) and box (0,1) share the vertical edge between them; give both
    // their other three sides, then draw the shared one.
    var s = fresh();
    board.setSeat(&s, hEdge(0, 0), .x);
    board.setSeat(&s, hEdge(1, 0), .x);
    board.setSeat(&s, vEdge(0, 0), .x);
    board.setSeat(&s, hEdge(0, 1), .x);
    board.setSeat(&s, hEdge(1, 1), .x);
    board.setSeat(&s, vEdge(0, 2), .x);
    const ns = apply(s, @intCast(vEdge(0, 1))).?;
    try testing.expectEqual(@as(u8, 2), score(ns, .x));
    try testing.expectEqual(Seat.x, ns.turn);
}

test "a filled board ends the game and the bigger score wins" {
    // Draw every edge in order. Whoever is on move when a box closes keeps the
    // move, so the result is lopsided — the point here is that it TERMINATES
    // with all sixteen boxes owned.
    var s = fresh();
    var e: u16 = 0;
    while (e < edges) : (e += 1) {
        if (s.outcome != .ongoing) break;
        if (apply(s, e)) |ns| s = ns;
    }
    try testing.expectEqual(@as(u8, boxes), score(s, .x) + score(s, .o));
    try testing.expect(s.outcome != .ongoing);
}
