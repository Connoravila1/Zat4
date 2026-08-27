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

//! B1 classification: CORE (pure). CONNECT FOUR — the rules only.
//!
//! Board: 7 columns × 6 rows, cells laid out row-major from the TOP, so
//! `cells[row * 7 + col]`; row 5 is the floor. Move: the COLUMN you drop into —
//! the row is not the player's to choose, which is the whole game, and it means a
//! move is three bits.

const std = @import("std");
const testing = std.testing;
const board = @import("board.zig");
const State = board.State;
const Seat = board.Seat;
const Outcome = board.Outcome;

pub const cols = 7;
pub const rows = 6;
pub const cells = cols * rows;

pub fn setup(s: *State) void {
    _ = s;
}

/// The lowest empty row in `col`, or null if the column is full.
pub fn landingRow(s: State, col: u16) ?u16 {
    if (col >= cols) return null;
    var r: u16 = rows;
    while (r > 0) {
        r -= 1;
        if (board.seatAt(s, r * cols + col) == .none) return r;
    }
    return null;
}

/// Four in a row through (r,c), in any of the four directions.
fn wins(s: State, r: i32, c: i32, v: Seat) bool {
    const dirs = [4][2]i32{ .{ 0, 1 }, .{ 1, 0 }, .{ 1, 1 }, .{ 1, -1 } };
    for (dirs) |d| {
        var run: i32 = 1;
        var sign: i32 = -1;
        while (sign <= 1) : (sign += 2) {
            var k: i32 = 1;
            while (k < 4) : (k += 1) {
                const rr = r + d[0] * k * sign;
                const cc = c + d[1] * k * sign;
                if (rr < 0 or rr >= rows or cc < 0 or cc >= cols) break;
                if (board.seatAt(s, @intCast(rr * cols + cc)) != v) break;
                run += 1;
            }
        }
        if (run >= 4) return true;
    }
    return false;
}

/// Drop `s.turn`'s disc into `col`.
pub fn apply(s: State, col: u16) ?State {
    const r = landingRow(s, col) orelse return null;
    var ns = s;
    board.setSeat(&ns, r * cols + col, s.turn);
    if (wins(ns, @intCast(r), @intCast(col), s.turn)) {
        ns.outcome = board.winFor(s.turn);
    } else {
        var filled: usize = 0;
        for (0..cells) |i| {
            if (board.seatAt(ns, i) != .none) filled += 1;
        }
        if (filled >= cells) ns.outcome = .draw;
    }
    ns.turn = s.turn.other();
    return ns;
}

// ---------------------------------------------------------------------------

fn play(seq: []const u16) State {
    var s = board.blank(.connect4);
    setup(&s);
    for (seq) |c| {
        if (s.outcome != .ongoing) break; // the dispatcher's rule, mirrored
        if (apply(s, c)) |ns| s = ns;
    }
    return s;
}

test "a disc falls to the floor and stacks on the one below it" {
    const s = play(&.{ 3, 3 });
    try testing.expectEqual(Seat.x, board.seatAt(s, 5 * cols + 3)); // floor
    try testing.expectEqual(Seat.o, board.seatAt(s, 4 * cols + 3)); // on top of it
}

test "a full column refuses another disc, and an out-of-range column is illegal" {
    var s = play(&.{ 0, 0, 0, 0, 0, 0 });
    try testing.expectEqual(@as(?State, null), apply(s, 0));
    try testing.expectEqual(@as(?State, null), apply(s, 7));
    s = play(&.{1});
    try testing.expect(apply(s, 0) != null); // a different column is fine
}

test "four in a row wins horizontally, vertically and on both diagonals" {
    // Horizontal: X takes 0,1,2,3 on the floor while O stacks column 6.
    try testing.expectEqual(Outcome.x_wins, play(&.{ 0, 6, 1, 6, 2, 6, 3 }).outcome);
    // Vertical: X stacks column 2.
    try testing.expectEqual(Outcome.x_wins, play(&.{ 2, 3, 2, 3, 2, 3, 2 }).outcome);
    // Diagonal up-right: the classic staircase.
    const diag = play(&.{ 0, 1, 1, 2, 2, 3, 2, 3, 3, 6, 3 });
    try testing.expectEqual(Outcome.x_wins, diag.outcome);
}

test "a filled board with no line is a draw" {
    // Fill every column in a pattern that never makes four: pairs of columns
    // played in a 2-2 rhythm so colours alternate in blocks.
    var s = board.blank(.connect4);
    // Column order chosen so no four ever lines up: 0011 2233 4455 66 pattern
    // per row, repeated — verified by the assertion below.
    const order = [_]u16{
        0, 1, 0, 1, 2, 3, 2, 3, 4, 5, 4, 5, 6, 6,
        1, 0, 1, 0, 3, 2, 3, 2, 5, 4, 5, 4, 6, 6,
        0, 1, 0, 1, 2, 3, 2, 3, 4, 5, 4, 5, 6, 6,
    };
    for (order) |c| {
        try testing.expectEqual(Outcome.ongoing, s.outcome);
        if (apply(s, c)) |ns| s = ns;
    }
    var filled: usize = 0;
    for (0..cells) |i| {
        if (board.seatAt(s, i) != .none) filled += 1;
    }
    try testing.expectEqual(@as(usize, cells), filled);
    try testing.expectEqual(Outcome.draw, s.outcome);
}
