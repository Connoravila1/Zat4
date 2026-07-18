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

//! B1 classification: CORE (pure). IN-THREAD GAMES — the turn-based game logic
//! behind "send a game" (ZAT_CHAT_STANDALONE_ROADMAP §3). The governing idea, and
//! the reason this fits the chat model so cleanly: **a move is a message.** Each
//! player's move is an ordinary E2EE chat message carrying a compact move byte;
//! the game state is not stored anywhere — it is DERIVED by replaying the moves in
//! the thread (`replay`), exactly as the timeline is derived from posts. So the
//! thread IS the game, the same way it is the receipt for a payment.
//!
//! This module owns the RULES only — legality, whose turn, who won. The board
//! rendering, the tap→move, and wrapping a move in a chat message are the shell's
//! and the view's job. PURE (B2): same moves ⇒ same state, no clock/RNG/I/O, so
//! the whole engine is golden-tested headless (tests at the foot).
//!
//! First game: TIC-TAC-TOE — the smallest turn-based game, chosen to prove the
//! move-as-message replay loop end to end. The shape here (a compact `Move`, an
//! `apply` that validates, an `outcome` predicate, a `replay`) generalizes to
//! connect-four and beyond; those are new rule sets, not new plumbing.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

/// Which game a move belongs to — so a thread can host more than one over its
/// life, and a stray/duplicate move for another game is ignored on replay.
/// Serialized; append-only.
pub const Game = enum(u8) {
    tictactoe = 0,
    _,
};

/// A cell's owner. `.none` is empty. In tic-tac-toe the two seats are X and O;
/// by convention the game's INITIATOR (the one who sent the invite) is X and
/// moves first.
pub const Seat = enum(u8) {
    none = 0,
    x = 1,
    o = 2,

    /// The other seat (X↔O); `.none` maps to itself.
    pub fn other(s: Seat) Seat {
        return switch (s) {
            .x => .o,
            .o => .x,
            .none => .none,
        };
    }
};

/// The result of a game so far.
pub const Outcome = enum(u8) { ongoing, x_wins, o_wins, draw };

/// One move, as it travels ON THE WIRE inside a chat message: which game, and the
/// target cell (0..8, row-major). The mover is NOT encoded — it is implied by the
/// replay position (turns strictly alternate from X), so a forged "I am X twice"
/// move is rejected by `apply`, not trusted from the payload. Encodes to one byte.
pub const Move = struct {
    game: Game = .tictactoe,
    cell: u8, // 0..8, row-major (row*3 + col)

    /// The single wire byte: high nibble = game, low nibble = cell. (Cell 0..8
    /// fits a nibble; games fit the other. A tidy, forward-checkable encoding.)
    pub fn encode(m: Move) u8 {
        return (@as(u8, @intFromEnum(m.game)) << 4) | (m.cell & 0x0F);
    }

    /// Decode a wire byte back to a Move. Pure and total — an out-of-range cell
    /// is returned as-is and rejected later by `apply` (E4: legality is one
    /// checkpoint, not scattered).
    pub fn decode(b: u8) Move {
        return .{ .game = @enumFromInt(b >> 4), .cell = b & 0x0F };
    }

    comptime {
        // Two u8 (game tag + cell), no padding — a move is a byte pair, and it
        // rides a message slice in bulk on replay, so it carries the guard (A7).
        assert(@sizeOf(Move) == 2);
    }
};

/// The derived game state — never stored, always a `replay` of the moves. Cold
/// (one per open game board, a handful at most), but plain data, so it carries a
/// guard anyway: the layout is a wire-adjacent fact worth pinning.
pub const State = struct {
    board: [9]Seat, // row-major cells
    turn: Seat, // whose move it is (X first)
    outcome: Outcome,
    moves: u8, // how many moves have been played (0..9)

    comptime {
        // 9 (board) + 1 (turn) + 1 (outcome) + 1 (moves) = 12, no padding.
        assert(@sizeOf(State) == 12);
    }
};

/// A fresh tic-tac-toe game: empty board, X to move.
pub fn init() State {
    return .{
        .board = @splat(.none),
        .turn = .x,
        .outcome = .ongoing,
        .moves = 0,
    };
}

/// The eight winning lines (rows, columns, diagonals).
const lines = [8][3]u8{
    .{ 0, 1, 2 }, .{ 3, 4, 5 }, .{ 6, 7, 8 }, // rows
    .{ 0, 3, 6 }, .{ 1, 4, 7 }, .{ 2, 5, 8 }, // columns
    .{ 0, 4, 8 }, .{ 2, 4, 6 }, // diagonals
};

/// Compute the outcome of a board. Pure. A board can only ever have one winner
/// (a legally-reached board never has two completed lines of different seats),
/// so the first completed line decides it.
fn judge(board: [9]Seat, moves: u8) Outcome {
    for (lines) |ln| {
        const a = board[ln[0]];
        if (a != .none and a == board[ln[1]] and a == board[ln[2]]) {
            return if (a == .x) .x_wins else .o_wins;
        }
    }
    return if (moves >= 9) .draw else .ongoing;
}

/// Is `m` a legal next move in `s`? Pure predicate: the game must be ongoing, the
/// cell in range, and the cell empty. Whose move it is comes from `s.turn`, not
/// from the move — so a player cannot move twice or move for the opponent.
pub fn legal(s: State, m: Move) bool {
    return m.game == .tictactoe and
        s.outcome == .ongoing and
        m.cell < 9 and
        s.board[m.cell] == .none;
}

/// Apply a move, returning the new state, or `null` if the move is illegal (E4:
/// an illegal move is an ordinary "no", not an error path — a replay simply skips
/// a move that does not fit, which is how a duplicate/forged/out-of-order message
/// is neutralised). The mover is `s.turn`; turns alternate from X.
pub fn apply(s: State, m: Move) ?State {
    if (!legal(s, m)) return null;
    var ns = s;
    ns.board[m.cell] = s.turn;
    ns.moves = s.moves + 1;
    ns.outcome = judge(ns.board, ns.moves);
    // The turn only advances while the game continues (a finished game has no
    // "next to move"; leaving turn on the winner would be a lie the UI reads).
    ns.turn = if (ns.outcome == .ongoing) s.turn.other() else .none;
    return ns;
}

/// Derive the current state by replaying a sequence of moves (the thread's game
/// messages, oldest first). Illegal moves are SKIPPED, not fatal — so a replay is
/// robust to duplicates and to a peer that sent a move out of turn. Pure: same
/// moves ⇒ same state, which is the whole reason the game needs no stored state.
pub fn replay(moves: []const Move) State {
    var s = init();
    for (moves) |m| {
        if (apply(s, m)) |ns| s = ns;
    }
    return s;
}

/// Which seat, if any, has WON — a convenience over `outcome` for the view.
pub fn winner(s: State) Seat {
    return switch (s.outcome) {
        .x_wins => .x,
        .o_wins => .o,
        .ongoing, .draw => .none,
    };
}

// ---------------------------------------------------------------------------
// Golden tests (C6). Pure value assertions — the rules pinned by numbers.
// ---------------------------------------------------------------------------

test "guards + a fresh game: empty board, X to move, ongoing" {
    try testing.expectEqual(@as(usize, 12), @sizeOf(State));
    const s = init();
    try testing.expectEqual(Seat.x, s.turn);
    try testing.expectEqual(Outcome.ongoing, s.outcome);
    try testing.expectEqual(@as(u8, 0), s.moves);
    for (s.board) |c| try testing.expectEqual(Seat.none, c);
}

test "turns alternate and an occupied / out-of-range / wrong-game cell is illegal" {
    var s = init();
    s = apply(s, .{ .cell = 4 }).?; // X centre
    try testing.expectEqual(Seat.o, s.turn);
    try testing.expectEqual(Seat.x, s.board[4]);

    // O cannot take the centre (occupied), nor cell 9 (out of range), nor a move
    // tagged for a different game.
    try testing.expect(!legal(s, .{ .cell = 4 }));
    try testing.expect(!legal(s, .{ .cell = 9 }));
    try testing.expect(!legal(s, .{ .game = @enumFromInt(7), .cell = 0 }));
    try testing.expectEqual(@as(?State, null), apply(s, .{ .cell = 4 }));

    s = apply(s, .{ .cell = 0 }).?; // O corner
    try testing.expectEqual(Seat.x, s.turn);
    try testing.expectEqual(Seat.o, s.board[0]);
}

test "a row, a column, and a diagonal each win for the right seat" {
    // X wins the top ROW: X0 O3 X1 O4 X2
    {
        const s = replay(&.{ .{ .cell = 0 }, .{ .cell = 3 }, .{ .cell = 1 }, .{ .cell = 4 }, .{ .cell = 2 } });
        try testing.expectEqual(Outcome.x_wins, s.outcome);
        try testing.expectEqual(Seat.x, winner(s));
        try testing.expectEqual(Seat.none, s.turn); // finished: nobody to move
    }
    // O wins the left COLUMN: X1 O0 X2 O3 X5 O6
    {
        const s = replay(&.{ .{ .cell = 1 }, .{ .cell = 0 }, .{ .cell = 2 }, .{ .cell = 3 }, .{ .cell = 5 }, .{ .cell = 6 } });
        try testing.expectEqual(Outcome.o_wins, s.outcome);
        try testing.expectEqual(Seat.o, winner(s));
    }
    // X wins the main DIAGONAL: X0 O1 X4 O2 X8
    {
        const s = replay(&.{ .{ .cell = 0 }, .{ .cell = 1 }, .{ .cell = 4 }, .{ .cell = 2 }, .{ .cell = 8 } });
        try testing.expectEqual(Outcome.x_wins, s.outcome);
    }
}

test "a full board with no line is a draw" {
    // X O X / X O O / O X X  →  cells: X0 O1 X2 X3 O4 O5 O6 X7 X8, interleaved legally.
    // Sequence (X,O,X,O,...): X4 O0 X8 O5 X2 O6 X3 O1 X7  → fills the board, no 3-line.
    const s = replay(&.{
        .{ .cell = 4 }, .{ .cell = 0 }, .{ .cell = 8 }, .{ .cell = 5 },
        .{ .cell = 2 }, .{ .cell = 6 }, .{ .cell = 3 }, .{ .cell = 1 },
        .{ .cell = 7 },
    });
    try testing.expectEqual(@as(u8, 9), s.moves);
    try testing.expectEqual(Outcome.draw, s.outcome);
    try testing.expectEqual(Seat.none, winner(s));
}

test "replay skips illegal / duplicate / out-of-turn moves (robust to bad messages)" {
    // A duplicated move byte (the same cell sent twice — a resend) must not let one
    // side move twice: the second is illegal (occupied) and skipped.
    const s = replay(&.{
        .{ .cell = 0 }, // X
        .{ .cell = 0 }, // duplicate/forged — skipped (occupied)
        .{ .cell = 3 }, // O
        .{ .cell = 1 }, // X
        .{ .cell = 9 }, // garbage cell — skipped
        .{ .cell = 4 }, // O
        .{ .cell = 2 }, // X wins the top row
    });
    try testing.expectEqual(Outcome.x_wins, s.outcome);
    // Exactly the five legal moves landed.
    try testing.expectEqual(@as(u8, 5), s.moves);
}

test "no moves land after the game is won (a late message is inert)" {
    var s = replay(&.{ .{ .cell = 0 }, .{ .cell = 3 }, .{ .cell = 1 }, .{ .cell = 4 }, .{ .cell = 2 } });
    try testing.expectEqual(Outcome.x_wins, s.outcome);
    // O tries to play on after losing — rejected.
    try testing.expectEqual(@as(?State, null), apply(s, .{ .cell = 5 }));
    s = replay(&.{ .{ .cell = 0 }, .{ .cell = 3 }, .{ .cell = 1 }, .{ .cell = 4 }, .{ .cell = 2 }, .{ .cell = 5 } });
    try testing.expectEqual(@as(u8, 5), s.moves); // the 6th move never counted
}

test "Move encodes and decodes round-trip through one wire byte" {
    for (0..9) |cell| {
        const m = Move{ .game = .tictactoe, .cell = @intCast(cell) };
        const b = m.encode();
        const d = Move.decode(b);
        try testing.expectEqual(m.game, d.game);
        try testing.expectEqual(m.cell, d.cell);
    }
    // The byte is compact: tic-tac-toe cell 8 → 0x08.
    try testing.expectEqual(@as(u8, 0x08), (Move{ .cell = 8 }).encode());
}
