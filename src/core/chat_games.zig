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
//! behind "send a game". The governing idea, and the reason this fits the chat
//! model so cleanly: **a move is a message.** Each player's move is an ordinary
//! E2EE chat message carrying a compact move; the game state is not stored
//! anywhere — it is DERIVED by replaying the moves in the thread (`replaySent`),
//! exactly as the timeline is derived from posts. So the thread IS the game, the
//! same way it is the receipt for a payment.
//!
//! THIS module owns the shared vocabulary and the replay machinery. The RULES of
//! each individual game live in `core/games/*.zig`, one file per game, and are
//! reached only through the `apply` dispatch below. Board rendering, tap→move,
//! and wrapping a move in a chat message are the shell's and the view's job.
//! PURE (B2): same moves ⇒ same state, no clock/RNG/I/O, so every engine is
//! golden-tested headless.
//!
//! **One state shape for every game.** A game is a byte board plus a little side
//! data; making that concrete — `cells` + `aux` — is what lets one replay loop,
//! one wire encoding, one persistence column and one renderer serve chess and
//! darts alike. The alternative (a tagged union per game) would have pushed a
//! switch into the store, the codec, the view and the shell: change amplification
//! (D6) for no gain, since the largest board is 64 bytes either way.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;

const board = @import("games/board.zig");
const tictactoe = @import("games/tictactoe.zig");
const connect4 = @import("games/connect4.zig");
const mancala = @import("games/mancala.zig");
const dots = @import("games/dots.zig");
const checkers = @import("games/checkers.zig");
const chess = @import("games/chess.zig");
const archery = @import("games/archery.zig");
const darts = @import("games/darts.zig");

/// The shared board vocabulary, re-exported so the rest of the app has ONE
/// import for games. `games/board.zig` is a leaf both this file and the rule
/// modules depend on; see its header for why it is separate.
pub const Game = board.Game;
pub const Seat = board.Seat;
pub const Outcome = board.Outcome;
pub const Move = board.Move;
pub const State = board.State;
pub const invite_cell = board.invite_cell;
pub const board_cells = board.board_cells;
pub const aux_bytes = board.aux_bytes;
pub const seatAt = board.seatAt;

/// Every game we know how to play, in shelf order — the picker walks this, so a
/// new game appears in the UI by being added here and nowhere else.
pub const catalog = [_]Game{ .tictactoe, .connect4, .chess, .checkers, .mancala, .dots, .archery, .darts };

/// The game's display name.
pub fn name(g: Game) []const u8 {
    return switch (g) {
        .tictactoe => "Tic-Tac-Toe",
        .connect4 => "Connect Four",
        .mancala => "Mancala",
        .dots => "Dots & Boxes",
        .checkers => "Checkers",
        .chess => "Chess",
        .archery => "Archery",
        .darts => "Darts",
        _ => "Game",
    };
}

/// A one-line "what is this" for the picker shelf.
pub fn blurb(g: Game) []const u8 {
    return switch (g) {
        .tictactoe => "Three in a row",
        .connect4 => "Drop four in a line",
        .mancala => "Sow and capture",
        .dots => "Close the most boxes",
        .checkers => "Jump and crown",
        .chess => "The full game",
        .archery => "Five arrows each",
        .darts => "501, double to finish",
        _ => "",
    };
}

/// Is this game played by pointing at a moving reticle (a skill shot) rather than
/// by choosing a square? The overlay needs to know: skill games animate, and
/// their "move" is a landing point rather than a board index.
pub fn isSkillShot(g: Game) bool {
    return g == .archery or g == .darts;
}

/// Does a move in this game need TWO taps — pick a piece, then pick where it
/// goes? (Chess and checkers; everything else is a single cell.)
pub fn isFromTo(g: Game) bool {
    return g == .chess or g == .checkers;
}

/// A fresh game of `g`: the opening position, X to move.
pub fn init(g: Game) State {
    var s = board.blank(g);
    switch (g) {
        .tictactoe => tictactoe.setup(&s),
        .connect4 => connect4.setup(&s),
        .mancala => mancala.setup(&s),
        .dots => dots.setup(&s),
        .checkers => checkers.setup(&s),
        .chess => chess.setup(&s),
        .archery => archery.setup(&s),
        .darts => darts.setup(&s),
        _ => {},
    }
    return s;
}

/// Apply a move, returning the new state, or `null` if the move is illegal (E4:
/// an illegal move is an ordinary "no", not an error path — a replay simply skips
/// a move that does not fit, which is how a duplicate/forged/out-of-order message
/// is neutralised). The mover is `s.turn`.
///
/// The three refusals here are the ones EVERY game shares, checked once so no
/// rule module can forget one: a move for a different game, a move on a finished
/// board, and the reserved invite cell.
pub fn apply(s: State, m: Move) ?State {
    if (m.game != s.game) return null;
    if (s.outcome != .ongoing) return null;
    if (m.cell == invite_cell) return null;
    var ns = switch (s.game) {
        .tictactoe => tictactoe.apply(s, m.cell),
        .connect4 => connect4.apply(s, m.cell),
        .mancala => mancala.apply(s, m.cell),
        .dots => dots.apply(s, m.cell),
        .checkers => checkers.apply(s, m.cell),
        .chess => chess.apply(s, m.cell),
        .archery => archery.apply(s, m.cell),
        .darts => darts.apply(s, m.cell),
        _ => null,
    } orelse return null;
    ns.moves +|= 1;
    // A finished game has no "next to move"; leaving `turn` on the winner would
    // be a lie the UI reads. Enforced here so no rule module can forget it.
    if (ns.outcome != .ongoing) ns.turn = .none;
    return ns;
}

/// Is `m` a legal next move in `s`? The one legality checkpoint, expressed in
/// terms of `apply` so there is no second copy of the rules to drift (E4).
pub fn legal(s: State, m: Move) bool {
    return apply(s, m) != null;
}

/// Derive the current state by replaying a sequence of moves (oldest first),
/// TRUSTING that they are in turn order. Illegal moves are SKIPPED, not fatal, so
/// this is robust to duplicates and to a move that no longer fits the board.
///
/// This is the RULES-ONLY form. It cannot tell one player's move from the
/// other's, so a sequence where the same person moved twice replays as if they
/// alternated. For anything a peer can influence, use `replaySent`.
pub fn replay(moves: []const Move) State {
    var s = init(if (moves.len > 0) moves[0].game else .tictactoe);
    for (moves) |m| {
        if (apply(s, m)) |ns| s = ns;
    }
    return s;
}

/// The INVITE move: opens a game of `g` with a fresh board. Its cell is the
/// reserved `invite_cell`, so `apply` skips it and the board stays at the opening
/// position — but it is still the FIRST move of the game, so it seats the sender
/// as X and it names WHICH game the thread is now playing. One tap in the picker
/// sends this; the board then appears for both, the inviter to move first.
pub fn inviteMove(g: Game) Move {
    return .{ .game = g, .cell = invite_cell };
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
        // 4 (Move) + 1 (bool) + 3 padding to the Move's u16 alignment. A7.1:
        // was 3 when a Move was two bytes.
        assert(@sizeOf(SentMove) == 6);
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
    var s = init(if (moves.len > 0) moves[0].move.game else .tictactoe);
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
/// A move naming a DIFFERENT game also opens a new one, for the same reason: you
/// finish a chess game and send darts, and the thread carries both.
///
/// Segmenting here, in a pure function over the same move list, means a rematch
/// needs no "new game" message kind and no stored state: the boundary is derived
/// from the moves exactly as the board is.
pub fn currentGame(moves: []const SentMove) []const SentMove {
    var start: usize = 0;
    var s = init(if (moves.len > 0) moves[0].move.game else .tictactoe);
    var x_is_mine = if (moves.len > 0) moves[0].mine else true;
    for (moves, 0..) |sm, i| {
        if (s.outcome != .ongoing or sm.move.game != s.game) {
            // The previous game is over (or this move is for another game
            // entirely); this move opens the next one, and whoever sent it is
            // that game's X.
            if (i != start or sm.move.game != s.game) {
                start = i;
                s = init(sm.move.game);
                x_is_mine = sm.mine;
            }
        }
        const sender: Seat = if (sm.mine == x_is_mine) .x else .o;
        if (sender != s.turn) continue;
        if (apply(s, sm.move)) |ns| s = ns;
    }
    return moves[start..];
}

/// One finished (or running) game pulled out of a thread — what the scoreboard
/// and the "games played" history are built from.
pub const Chapter = struct {
    /// Index range into the thread's move list: `moves[first..first+count]`.
    first: u16,
    count: u16,
    game: Game,
    /// Which seat WE held in it.
    my_seat: Seat,
    outcome: Outcome,

    comptime {
        // 2 + 2 + 1 + 1 + 1 = 7, padded to the u16 alignment.
        assert(@sizeOf(Chapter) == 8);
    }
};

/// The running SCORE between the two players in this thread — wins, losses and
/// draws, counting only FINISHED games. Derived, like everything else here: no
/// scoreboard is stored or transmitted, so there is nothing to disagree about
/// and nothing to forge. Both ends compute the same number from the same thread.
pub const Tally = struct {
    mine: u16 = 0,
    theirs: u16 = 0,
    draws: u16 = 0,
    /// Finished games in this thread (mine + theirs + draws).
    played: u16 = 0,

    comptime {
        assert(@sizeOf(Tally) == 8);
    }
};

/// Split a thread's moves into chapters — one per game played — writing them into
/// `out` and returning the prefix used. Pure; `out` is the caller's buffer, so
/// this allocates nothing (C1: nothing to allocate means no allocator to pass).
/// Chapters beyond `out.len` are dropped oldest-last, which only ever costs
/// history depth in a very long thread.
pub fn chapters(moves: []const SentMove, out: []Chapter) []Chapter {
    if (moves.len == 0 or out.len == 0) return out[0..0];
    var n: usize = 0;
    var start: usize = 0;
    var s = init(moves[0].move.game);
    var x_is_mine = moves[0].mine;
    for (moves, 0..) |sm, i| {
        if ((s.outcome != .ongoing or sm.move.game != s.game) and !(i == start and sm.move.game == s.game)) {
            if (n < out.len) {
                out[n] = .{
                    .first = @intCast(@min(start, 0xFFFF)),
                    .count = @intCast(@min(i - start, 0xFFFF)),
                    .game = s.game,
                    .my_seat = if (x_is_mine) .x else .o,
                    .outcome = s.outcome,
                };
                n += 1;
            }
            start = i;
            s = init(sm.move.game);
            x_is_mine = sm.mine;
        }
        const sender: Seat = if (sm.mine == x_is_mine) .x else .o;
        if (sender != s.turn) continue;
        if (apply(s, sm.move)) |ns| s = ns;
    }
    if (n < out.len) {
        out[n] = .{
            .first = @intCast(@min(start, 0xFFFF)),
            .count = @intCast(@min(moves.len - start, 0xFFFF)),
            .game = s.game,
            .my_seat = if (x_is_mine) .x else .o,
            .outcome = s.outcome,
        };
        n += 1;
    }
    return out[0..n];
}

/// The head-to-head record across every finished game in the thread.
pub fn tally(moves: []const SentMove) Tally {
    var buf: [64]Chapter = undefined;
    var t = Tally{};
    for (chapters(moves, &buf)) |c| {
        switch (c.outcome) {
            .ongoing => continue,
            .draw => t.draws += 1,
            .x_wins => if (c.my_seat == .x) {
                t.mine += 1;
            } else {
                t.theirs += 1;
            },
            .o_wins => if (c.my_seat == .o) {
                t.mine += 1;
            } else {
                t.theirs += 1;
            },
        }
        t.played += 1;
    }
    return t;
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

/// Decode a move from the FIRST wire encoding, where the game and the cell shared
/// one byte (high nibble the game, low nibble the cell). Kept for the persisted
/// history and for a peer still running the old build; nothing new writes it.
pub fn fromLegacyByte(b: u8) Move {
    return .{ .game = @enumFromInt(b >> 4), .cell = b & 0x0F };
}

// ---------------------------------------------------------------------------
// Golden tests (C6). Pure value assertions — the rules pinned by numbers.
// The per-game rule tests live beside each game in `games/*.zig`; these cover the
// SHARED machinery: dispatch, replay, authorship, segmentation, scoring.
// ---------------------------------------------------------------------------

test "guards + a fresh game: empty board, X to move, ongoing" {
    try testing.expectEqual(@as(usize, 84), @sizeOf(State));
    const s = init(.tictactoe);
    try testing.expectEqual(Seat.x, s.turn);
    try testing.expectEqual(Outcome.ongoing, s.outcome);
    try testing.expectEqual(@as(u8, 0), s.moves);
    for (0..9) |i| try testing.expectEqual(Seat.none, seatAt(s, i));
}

test "dispatch refuses a move for the wrong game, a finished board, and the invite cell" {
    const s = init(.tictactoe);
    try testing.expect(!legal(s, .{ .game = .chess, .cell = 0 }));
    try testing.expect(!legal(s, .{ .cell = invite_cell }));
    try testing.expect(legal(s, .{ .cell = 4 }));

    const won = replay(&.{ .{ .cell = 0 }, .{ .cell = 3 }, .{ .cell = 1 }, .{ .cell = 4 }, .{ .cell = 2 } });
    try testing.expectEqual(Outcome.x_wins, won.outcome);
    try testing.expectEqual(Seat.none, won.turn); // finished: nobody to move
    try testing.expect(!legal(won, .{ .cell = 5 }));
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
    try testing.expectEqual(Seat.o, seatAt(rules_only, 4)); // the gap, demonstrated

    const checked = replaySent(&cheat);
    try testing.expectEqual(Seat.x, seatAt(checked, 0)); // our legitimate move stands
    try testing.expectEqual(Seat.none, seatAt(checked, 4)); // the second is skipped
    try testing.expectEqual(Seat.o, checked.turn); // still waiting on them
    try testing.expectEqual(@as(u8, 1), checked.moves);
}

test "replaySent: a peer cannot move for us either" {
    const cheat = [_]SentMove{
        .{ .move = .{ .cell = 0 }, .mine = false }, // they open, so they are X
        .{ .move = .{ .cell = 1 }, .mine = false }, // and try to play our O
    };
    const s = replaySent(&cheat);
    try testing.expectEqual(Seat.x, seatAt(s, 0));
    try testing.expectEqual(Seat.none, seatAt(s, 1));
    try testing.expectEqual(Seat.o, mySeat(&cheat));
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
    try testing.expectEqual(Seat.x, seatAt(s, 0));
    try testing.expectEqual(Seat.o, seatAt(s, 4));
    try testing.expectEqual(@as(u8, 2), s.moves);
    try testing.expectEqual(Seat.x, s.turn); // back to us, correctly
}

test "replaySent: an empty thread is an open board that we may start" {
    const none = [_]SentMove{};
    try testing.expectEqual(Seat.none, mySeat(&none));
    try testing.expectEqual(true, myTurn(&none)); // anyone may open
    try testing.expectEqual(Outcome.ongoing, replaySent(&none).outcome);
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
    try testing.expectEqual(Seat.x, seatAt(s, 4)); // THEY opened, so they are X now
    try testing.expectEqual(Seat.o, mySeat(cur)); // and we are O
    try testing.expectEqual(true, myTurn(cur)); // our move
}

test "currentGame: switching to a DIFFERENT game opens a new board mid-thread" {
    const thread = [_]SentMove{
        .{ .move = .{ .cell = 0 }, .mine = true }, // tic-tac-toe, unfinished
        .{ .move = .{ .cell = 4 }, .mine = false },
        .{ .move = inviteMove(.connect4), .mine = false }, // they send Connect Four
        .{ .move = .{ .game = .connect4, .cell = 3 }, .mine = false },
    };
    const cur = currentGame(&thread);
    try testing.expectEqual(@as(usize, 2), cur.len);
    const s = replaySent(cur);
    try testing.expectEqual(Game.connect4, s.game);
    try testing.expectEqual(Seat.o, mySeat(cur)); // they opened it
}

test "currentGame: an unfinished game is returned whole" {
    const thread = [_]SentMove{
        .{ .move = .{ .cell = 0 }, .mine = true },
        .{ .move = .{ .cell = 4 }, .mine = false },
    };
    try testing.expectEqual(@as(usize, 2), currentGame(&thread).len);
    try testing.expectEqual(@as(usize, 0), currentGame(&[_]SentMove{}).len);
}

test "tally: the head-to-head record is derived from the thread, not stored" {
    // Game 1: we open and win the top row. Game 2: they open and win theirs.
    const thread = [_]SentMove{
        .{ .move = .{ .cell = 0 }, .mine = true },
        .{ .move = .{ .cell = 3 }, .mine = false },
        .{ .move = .{ .cell = 1 }, .mine = true },
        .{ .move = .{ .cell = 4 }, .mine = false },
        .{ .move = .{ .cell = 2 }, .mine = true }, // we win
        .{ .move = .{ .cell = 0 }, .mine = false }, // they open game 2
        .{ .move = .{ .cell = 3 }, .mine = true },
        .{ .move = .{ .cell = 1 }, .mine = false },
        .{ .move = .{ .cell = 4 }, .mine = true },
        .{ .move = .{ .cell = 2 }, .mine = false }, // they win
    };
    const t = tally(&thread);
    try testing.expectEqual(@as(u16, 1), t.mine);
    try testing.expectEqual(@as(u16, 1), t.theirs);
    try testing.expectEqual(@as(u16, 0), t.draws);
    try testing.expectEqual(@as(u16, 2), t.played);

    var buf: [8]Chapter = undefined;
    const ch = chapters(&thread, &buf);
    try testing.expectEqual(@as(usize, 2), ch.len);
    try testing.expectEqual(Seat.x, ch[0].my_seat);
    try testing.expectEqual(Seat.o, ch[1].my_seat);
    try testing.expectEqual(@as(u16, 5), ch[1].first);
}

test "tally: a game still running counts for nobody" {
    const thread = [_]SentMove{
        .{ .move = .{ .cell = 0 }, .mine = true },
        .{ .move = .{ .cell = 4 }, .mine = false },
    };
    const t = tally(&thread);
    try testing.expectEqual(@as(u16, 0), t.played);
}

test "the legacy wire byte still decodes (old threads keep their games)" {
    const m = fromLegacyByte(0x08);
    try testing.expectEqual(Game.tictactoe, m.game);
    try testing.expectEqual(@as(u16, 8), m.cell);
    // The old invite (cell 15) is out of range for tic-tac-toe, so it still
    // seats its sender without marking the board.
    try testing.expectEqual(@as(u16, 15), fromLegacyByte(0x0F).cell);
}

test "every game in the catalog sets up, names itself, and refuses the invite cell" {
    for (catalog) |g| {
        const s = init(g);
        try testing.expectEqual(g, s.game);
        try testing.expectEqual(Seat.x, s.turn);
        try testing.expectEqual(Outcome.ongoing, s.outcome);
        try testing.expect(name(g).len > 0);
        try testing.expect(blurb(g).len > 0);
        try testing.expect(!legal(s, .{ .game = g, .cell = invite_cell }));
        // An invite replays as "the board is open and its sender is X".
        const opened = replaySent(&[_]SentMove{.{ .move = inviteMove(g), .mine = true }});
        try testing.expectEqual(g, opened.game);
        try testing.expectEqual(Seat.x, mySeat(&[_]SentMove{.{ .move = inviteMove(g), .mine = true }}));
        try testing.expectEqual(@as(u8, 0), opened.moves);
    }
}
