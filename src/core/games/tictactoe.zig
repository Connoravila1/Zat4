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

//! B1 classification: CORE (pure). TIC-TAC-TOE — the rules only.
//!
//! The smallest turn-based game, and the one the move-as-message loop was proved
//! on. Board: cells 0..8, row-major (row*3 + col), each holding a `Seat`.
//! Move: the target cell.

const std = @import("std");
const testing = std.testing;
const board = @import("board.zig");
const State = board.State;
const Seat = board.Seat;
const Outcome = board.Outcome;

pub const size = 3;
pub const cells = size * size;

/// An empty board is the opening position, so there is nothing to lay out.
pub fn setup(s: *State) void {
    _ = s;
}

/// The eight winning lines (rows, columns, diagonals).
const lines = [8][3]u8{
    .{ 0, 1, 2 }, .{ 3, 4, 5 }, .{ 6, 7, 8 }, // rows
    .{ 0, 3, 6 }, .{ 1, 4, 7 }, .{ 2, 5, 8 }, // columns
    .{ 0, 4, 8 }, .{ 2, 4, 6 }, // diagonals
};

/// Compute the outcome of a board. A legally-reached board never has two
/// completed lines of different seats, so the first completed line decides it.
fn judge(s: State) Outcome {
    for (lines) |ln| {
        const a = board.seatAt(s, ln[0]);
        if (a != .none and a == board.seatAt(s, ln[1]) and a == board.seatAt(s, ln[2])) {
            return board.winFor(a);
        }
    }
    var filled: usize = 0;
    for (0..cells) |i| {
        if (board.seatAt(s, i) != .none) filled += 1;
    }
    return if (filled >= cells) .draw else .ongoing;
}

/// Place `s.turn`'s mark on an empty cell. `null` if the cell is out of range or
/// already taken — an illegal move is an ordinary "no" (E4).
pub fn apply(s: State, cell: u16) ?State {
    if (cell >= cells) return null;
    if (board.seatAt(s, cell) != .none) return null;
    var ns = s;
    board.setSeat(&ns, cell, s.turn);
    ns.outcome = judge(ns);
    ns.turn = s.turn.other();
    return ns;
}

// ---------------------------------------------------------------------------

fn play(seq: []const u16) State {
    var s = board.blank(.tictactoe);
    setup(&s);
    for (seq) |c| {
        if (apply(s, c)) |ns| s = ns;
    }
    return s;
}

test "turns alternate and an occupied / out-of-range cell is illegal" {
    var s = play(&.{4});
    try testing.expectEqual(Seat.o, s.turn);
    try testing.expectEqual(Seat.x, board.seatAt(s, 4));
    try testing.expectEqual(@as(?State, null), apply(s, 4));
    try testing.expectEqual(@as(?State, null), apply(s, 9));
    s = play(&.{ 4, 0 });
    try testing.expectEqual(Seat.x, s.turn);
    try testing.expectEqual(Seat.o, board.seatAt(s, 0));
}

test "a row, a column, and a diagonal each win for the right seat" {
    try testing.expectEqual(Outcome.x_wins, play(&.{ 0, 3, 1, 4, 2 }).outcome);
    try testing.expectEqual(Outcome.o_wins, play(&.{ 1, 0, 2, 3, 5, 6 }).outcome);
    try testing.expectEqual(Outcome.x_wins, play(&.{ 0, 1, 4, 2, 8 }).outcome);
}

test "a full board with no line is a draw" {
    const s = play(&.{ 4, 0, 8, 5, 2, 6, 3, 1, 7 });
    try testing.expectEqual(Outcome.draw, s.outcome);
}

test "no move lands after the game is won" {
    const won = play(&.{ 0, 3, 1, 4, 2 });
    try testing.expectEqual(Outcome.x_wins, won.outcome);
    // The dispatcher refuses a finished board, but the rules agree: cell 5 is
    // empty, so only the outcome check stops it.
    try testing.expect(apply(won, 5) != null);
}
