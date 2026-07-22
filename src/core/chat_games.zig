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
/// replay position (turns strictly alternate from X), so there is no "I am X"
/// claim in the payload to forge in the first place. Encodes to one byte.
///
/// NOTE: not encoding the mover is what makes a lie unrepresentable, but it is
/// NOT by itself what stops a player moving twice — `apply` cannot see who sent
/// anything. `replaySent` is where authorship is checked; use it for any move a
/// peer can influence.
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
/// from the move — this layer knows the RULES, not the players. Whether the right
/// person sent it is a separate question, answered by `replaySent`.
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

/// Derive the current state by replaying a sequence of moves (oldest first),
/// TRUSTING that they are in turn order. Illegal moves are SKIPPED, not fatal, so
/// this is robust to duplicates and to a move that no longer fits the board. Pure:
/// same moves ⇒ same state, which is why the game needs no stored state.
///
/// This is the RULES-ONLY form. It cannot tell one player's move from the other's,
/// so a sequence where the same person moved twice replays as if they alternated.
/// For anything a peer can influence, use `replaySent`.
pub fn replay(moves: []const Move) State {
    var s = init();
    for (moves) |m| {
        if (apply(s, m)) |ns| s = ns;
    }
    return s;
}

/// The INVITE move: opens a game with an empty board. Its cell (15) is out of
/// range, so `apply` skips it and the board stays empty — but it is still the
/// FIRST move of the game, so it seats the sender as X (`currentGame`/`replaySent`
/// take X from the first move's sender). One tap on "Games" sends this; the board
/// then appears for both, the inviter to move first.
pub const invite_cell: u8 = 15;
pub fn inviteMove() Move {
    return .{ .game = .tictactoe, .cell = invite_cell };
}

/// A move as it actually ARRIVES in a thread: the move, plus who sent it.
///
/// `mine` is the store's own "did I send this" bit — the one fact the wire cannot
/// forge, because it comes from which E2EE session the message was decrypted on,
/// not from anything the sender wrote.
pub const SentMove = struct {
    move: Move,
    mine: bool,

    comptime {
        // 2 (Move) + 1 (bool), all byte-aligned — no padding.
        assert(@sizeOf(SentMove) == 3);
    }
};

/// Replay a thread's moves, VERIFYING AUTHORSHIP. This is the one to use for
/// anything a peer can influence; plain `replay` is the rules-only form and
/// trusts its input to be in turn order.
///
/// Why it must exist: `apply` takes the mover from `s.turn`, so it cannot tell a
/// legitimate reply from a second move by the same player — replaying Alice,
/// Alice would seat the first as X and the SECOND AS O, letting Alice play her
/// opponent's move. The rules layer has no authorship information to catch that
/// with, and adding a "mover" field to the wire would only invite a lie. The fix
/// is to check the sender against the seat whose turn it is, here, where both
/// facts are in hand.
///
/// Seats come from the thread itself: **the initiator is X** — whoever sent the
/// first move of the game — and the other participant is O. A move from the
/// player whose turn it is NOT is skipped exactly like an illegal one (E4), so a
/// cheating or confused peer degrades to "that move didn't happen" rather than
/// corrupting the board.
pub fn replaySent(moves: []const SentMove) State {
    var s = init();
    if (moves.len == 0) return s;
    // X is whoever moved first; every later move is X's if it came from the same
    // side, O's otherwise.
    const x_is_mine = moves[0].mine;
    for (moves) |sm| {
        const sender: Seat = if (sm.mine == x_is_mine) .x else .o;
        if (sender != s.turn) continue; // not their turn: a move for someone else
        if (apply(s, sm.move)) |ns| s = ns;
    }
    return s;
}

/// The moves belonging to the CURRENT game — the tail of `moves` after the last
/// finished one.
///
/// A thread outlives a game: once a board is won or drawn it can take no further
/// move, so the next move that arrives is not an illegal move on the old board,
/// it is the opening of a REMATCH. Without this, `replaySent` would skip every
/// move after the first game ended and the pair could never play again — the
/// board would be permanently frozen on the last result.
///
/// Segmenting here, in a pure function over the same move list, means a rematch
/// needs no "new game" message kind and no stored state: the boundary is derived
/// from the moves exactly as the board is.
pub fn currentGame(moves: []const SentMove) []const SentMove {
    var start: usize = 0;
    var s = init();
    var x_is_mine = if (moves.len > 0) moves[0].mine else true;
    for (moves, 0..) |sm, i| {
        if (s.outcome != .ongoing) {
            // The previous game is over; this move opens the next one, and
            // whoever sent it is that game's X.
            start = i;
            s = init();
            x_is_mine = sm.mine;
        }
        const sender: Seat = if (sm.mine == x_is_mine) .x else .o;
        if (sender != s.turn) continue;
        if (apply(s, sm.move)) |ns| s = ns;
    }
    return moves[start..];
}

/// Which seat WE hold in this game, or `.none` before anyone has moved. The
/// initiator is X, so if we sent the first move we are X.
pub fn mySeat(moves: []const SentMove) Seat {
    if (moves.len == 0) return .none;
    return if (moves[0].mine) .x else .o;
}

/// Is it OUR move? The question every board renderer actually asks.
pub fn myTurn(moves: []const SentMove) bool {
    const s = replaySent(moves);
    if (s.outcome != .ongoing) return false;
    // Before the first move the board is open and either side may open it.
    if (moves.len == 0) return true;
    return s.turn == mySeat(moves);
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

test "replaySent: a player cannot move twice in a row" {
    // THE CHEAT the rules layer cannot see. We open at 0, then send a second
    // move immediately. Plain `replay` would seat that second move as O — we
    // would have played our opponent's move for them.
    const cheat = [_]SentMove{
        .{ .move = .{ .cell = 0 }, .mine = true },
        .{ .move = .{ .cell = 4 }, .mine = true }, // not our turn
    };

    const rules_only = replay(&[_]Move{ .{ .cell = 0 }, .{ .cell = 4 } });
    try testing.expectEqual(Seat.o, rules_only.board[4]); // the gap, demonstrated

    const checked = replaySent(&cheat);
    try testing.expectEqual(Seat.x, checked.board[0]); // our legitimate move stands
    try testing.expectEqual(Seat.none, checked.board[4]); // the second is skipped
    try testing.expectEqual(Seat.o, checked.turn); // still waiting on them
    try testing.expectEqual(@as(u8, 1), checked.moves);
}

test "replaySent: a peer cannot move for us either" {
    const cheat = [_]SentMove{
        .{ .move = .{ .cell = 0 }, .mine = false }, // they open, so they are X
        .{ .move = .{ .cell = 1 }, .mine = false }, // and try to play our O
    };
    const s = replaySent(&cheat);
    try testing.expectEqual(Seat.x, s.board[0]);
    try testing.expectEqual(Seat.none, s.board[1]);
    try testing.expectEqual(Seat.x, mySeat(&cheat).other()); // we are O
    try testing.expectEqual(Seat.o, mySeat(&cheat));
}

test "replaySent: a legitimate alternating game plays out normally" {
    // X takes the top row; every move is from the side whose turn it is.
    const game = [_]SentMove{
        .{ .move = .{ .cell = 0 }, .mine = true },
        .{ .move = .{ .cell = 3 }, .mine = false },
        .{ .move = .{ .cell = 1 }, .mine = true },
        .{ .move = .{ .cell = 4 }, .mine = false },
        .{ .move = .{ .cell = 2 }, .mine = true },
    };
    const s = replaySent(&game);
    try testing.expectEqual(Outcome.x_wins, s.outcome);
    try testing.expectEqual(Seat.x, winner(s));
    try testing.expectEqual(Seat.x, mySeat(&game)); // we opened, so we are X
    try testing.expectEqual(false, myTurn(&game)); // a finished game is nobody's turn
}

test "replaySent: a duplicate resend of the SAME move changes nothing" {
    // Delivery can repeat a message; the cell is already taken, so it is skipped
    // as illegal — and skipping must not hand the turn to the wrong player.
    const dup = [_]SentMove{
        .{ .move = .{ .cell = 0 }, .mine = true },
        .{ .move = .{ .cell = 0 }, .mine = true },
        .{ .move = .{ .cell = 4 }, .mine = false },
    };
    const s = replaySent(&dup);
    try testing.expectEqual(Seat.x, s.board[0]);
    try testing.expectEqual(Seat.o, s.board[4]);
    try testing.expectEqual(@as(u8, 2), s.moves);
    try testing.expectEqual(Seat.x, s.turn); // back to us, correctly
}

test "replaySent: an empty thread is an open board that we may start" {
    const none = [_]SentMove{};
    try testing.expectEqual(Seat.none, mySeat(&none));
    try testing.expectEqual(true, myTurn(&none)); // anyone may open
    try testing.expectEqual(Outcome.ongoing, replaySent(&none).outcome);
}

test "replaySent: an out-of-range cell from a hostile peer is refused" {
    const bad = [_]SentMove{
        .{ .move = Move.decode(0x0F), .mine = false }, // cell 15
        .{ .move = .{ .cell = 0 }, .mine = false }, // they are still X, still first
    };
    const s = replaySent(&bad);
    try testing.expectEqual(Seat.x, s.board[0]);
    try testing.expectEqual(@as(u8, 1), s.moves);
}

test "currentGame: a rematch starts a new board instead of freezing the old one" {
    // We win the top row; then THEY open a rematch at centre.
    const thread = [_]SentMove{
        .{ .move = .{ .cell = 0 }, .mine = true },
        .{ .move = .{ .cell = 3 }, .mine = false },
        .{ .move = .{ .cell = 1 }, .mine = true },
        .{ .move = .{ .cell = 4 }, .mine = false },
        .{ .move = .{ .cell = 2 }, .mine = true }, // X wins here
        .{ .move = .{ .cell = 4 }, .mine = false }, // rematch: they open
    };
    // Without segmenting, that last move is illegal on a finished board and the
    // pair could never play again.
    const cur = currentGame(&thread);
    try testing.expectEqual(@as(usize, 1), cur.len);

    const s = replaySent(cur);
    try testing.expectEqual(Outcome.ongoing, s.outcome);
    try testing.expectEqual(Seat.x, s.board[4]); // THEY opened, so they are X now
    try testing.expectEqual(Seat.o, mySeat(cur)); // and we are O
    try testing.expectEqual(true, myTurn(cur)); // our move
}

test "currentGame: an unfinished game is returned whole" {
    const thread = [_]SentMove{
        .{ .move = .{ .cell = 0 }, .mine = true },
        .{ .move = .{ .cell = 4 }, .mine = false },
    };
    try testing.expectEqual(@as(usize, 2), currentGame(&thread).len);
    try testing.expectEqual(@as(usize, 0), currentGame(&[_]SentMove{}).len);
}

test "currentGame: a DRAW also ends a game, so a rematch can follow it" {
    // A full board with no winner, then one more move.
    const thread = [_]SentMove{
        .{ .move = .{ .cell = 0 }, .mine = true }, // X
        .{ .move = .{ .cell = 1 }, .mine = false }, // O
        .{ .move = .{ .cell = 2 }, .mine = true }, // X
        .{ .move = .{ .cell = 4 }, .mine = false }, // O
        .{ .move = .{ .cell = 3 }, .mine = true }, // X
        .{ .move = .{ .cell = 5 }, .mine = false }, // O
        .{ .move = .{ .cell = 7 }, .mine = true }, // X
        .{ .move = .{ .cell = 6 }, .mine = false }, // O
        .{ .move = .{ .cell = 8 }, .mine = true }, // X — board full
        .{ .move = .{ .cell = 0 }, .mine = true }, // rematch, we open
    };
    const full = replaySent(thread[0..9]);
    try testing.expectEqual(Outcome.draw, full.outcome);

    const cur = currentGame(&thread);
    try testing.expectEqual(@as(usize, 1), cur.len);
    try testing.expectEqual(Seat.x, mySeat(cur)); // we opened the rematch
}
