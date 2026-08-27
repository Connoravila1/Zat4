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

//! B1 classification: CORE (pure). THE SHARED BOARD VOCABULARY — the handful of
//! types every game and the replay machinery both need.
//!
//! It lives in its own file for one reason: `core/chat_games.zig` dispatches INTO
//! the game modules and the game modules need the state type, which would make
//! the two files import each other. A leaf both sides depend on is the honest
//! shape of that dependency, and it keeps the rule modules unable to reach the
//! replay machinery at all — a game can only see a board (D3).
//!
//! Everything here is re-exported by `core/chat_games.zig`; nothing outside
//! `games/` should import this file directly.

const std = @import("std");
const assert = std.debug.assert;

/// Which game a move belongs to — so a thread can host more than one over its
/// life, and a stray/duplicate move for another game is ignored on replay.
/// Serialized; APPEND-ONLY (a number here is on the wire and on disk forever).
pub const Game = enum(u8) {
    tictactoe = 0,
    connect4 = 1,
    mancala = 2,
    dots = 3,
    checkers = 4,
    chess = 5,
    archery = 6,
    darts = 7,
    _,
};

/// A seat at the board. `.x` is always the game's INITIATOR — whoever sent the
/// first move — and `.o` is the other player. The names are historical (they
/// began as tic-tac-toe marks); read them as "first player" and "second player".
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

/// One move, as it travels ON THE WIRE inside a chat message: which game, and
/// what was played. The mover is NOT encoded — it is implied by the replay
/// position (turns alternate from X), so there is no "I am X" claim in the
/// payload to forge in the first place.
///
/// `cell`'s meaning is the GAME's business: a board index in tic-tac-toe, a
/// column in Connect Four, a packed from/to in chess, a quantized landing point
/// in darts. Sixteen bits because chess needs twelve and a landing point needs
/// sixteen; the four-bit nibble the first version used could only ever have held
/// tic-tac-toe.
///
/// NOTE: not encoding the mover is what makes a lie unrepresentable, but it is
/// NOT by itself what stops a player moving twice — `apply` cannot see who sent
/// anything. `chat_games.replaySent` is where authorship is checked; use it for
/// any move a peer can influence.
pub const Move = struct {
    game: Game = .tictactoe,
    cell: u16,

    comptime {
        // A7.1: was 2 (u8 game + u8 cell). The cell is a u16 now — see the doc
        // comment: twelve bits of chess do not fit a nibble. u8 + pad + u16 = 4.
        // It rides a message slice in bulk on replay, so it keeps its guard (A7).
        assert(@sizeOf(Move) == 4);
    }
};

/// The reserved cell that means "no move" — an INVITE, or a malformed payload.
/// `chat_games.apply` refuses it for EVERY game before dispatch, so no game has
/// to defend against it and no landing-point game can mistake it for a legal shot
/// at the corner of the target.
pub const invite_cell: u16 = 0xFFFF;

/// Bytes of board every game shares. 64 is chess and checkers; everything else
/// uses a prefix of it.
pub const board_cells = 64;
/// Bytes of per-game side data (castling rights, running scores, stones in hand).
pub const aux_bytes = 16;

/// The derived game state — never stored, always a replay of the moves.
///
/// `cells` and `aux` are the GAME's to interpret; nothing outside `games/*.zig`
/// should read a byte of them without going through that game's accessors. The
/// header (`game`/`turn`/`outcome`/`moves`) is the part every caller may read,
/// and is what the view renders its status line from.
pub const State = struct {
    cells: [board_cells]u8,
    aux: [aux_bytes]u8,
    game: Game,
    turn: Seat, // whose move it is (X first)
    outcome: Outcome,
    moves: u8, // how many moves have LANDED (saturating)

    comptime {
        // 64 (cells) + 16 (aux) + 4 header bytes = 84, all byte-aligned, no
        // padding. A7.1: was 12 when the only board was 3×3. The size is set by
        // chess — 64 squares is the largest board we host — and one of these
        // exists per open board (a handful), so 84 bytes is not a bulk cost.
        assert(@sizeOf(State) == 84);
    }
};

/// A blank state for `game`, before that game's `setup` lays out its opening
/// position. Every rule module starts from this, so "empty" means one thing.
pub fn blank(game: Game) State {
    return .{
        .cells = @splat(0),
        .aux = @splat(0),
        .game = game,
        .turn = .x,
        .outcome = .ongoing,
        .moves = 0,
    };
}

/// The seat occupying board cell `i` — for the games whose cells ARE seats
/// (tic-tac-toe, Connect Four, Dots & Boxes). Games with richer cells (chess
/// pieces, mancala stone counts) expose their own readers.
pub fn seatAt(s: State, i: usize) Seat {
    if (i >= board_cells) return .none;
    return switch (s.cells[i]) {
        1 => .x,
        2 => .o,
        else => .none,
    };
}

/// Write a seat into board cell `i`.
pub fn setSeat(s: *State, i: usize, v: Seat) void {
    if (i >= board_cells) return;
    s.cells[i] = @intFromEnum(v);
}

/// The outcome for "this seat just won".
pub fn winFor(v: Seat) Outcome {
    return switch (v) {
        .x => .x_wins,
        .o => .o_wins,
        .none => .ongoing,
    };
}

/// Read a u16 out of `aux` at byte `at` (little-endian). The scoring games keep
/// numbers larger than a byte there — 501 does not fit in eight bits.
pub fn auxU16(s: State, at: usize) u16 {
    if (at + 1 >= aux_bytes) return 0;
    return @as(u16, s.aux[at]) | (@as(u16, s.aux[at + 1]) << 8);
}

/// Write a u16 into `aux` at byte `at` (little-endian).
pub fn setAuxU16(s: *State, at: usize, v: u16) void {
    if (at + 1 >= aux_bytes) return;
    s.aux[at] = @truncate(v);
    s.aux[at + 1] = @truncate(v >> 8);
}
