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

//! B1 classification: CORE (pure). CHECKERS (English draughts) — the rules only.
//!
//! Board: 64 squares in `cells`, `row * 8 + col`, row 0 at the TOP. Play is on
//! the dark squares, where `(row + col)` is odd. X sits at the bottom and moves
//! UP the board; O sits at the top and moves down.
//!
//! Piece bytes: 0 empty, 1 X man, 2 O man, 3 X king, 4 O king.
//!
//! Move: `from | (to << 6)` — twelve bits, which is why a move is a u16.
//!
//! Two rules carry the game and both are enforced here, because leaving either
//! to the UI would let a peer's client (or a hand-written frame) play a game we
//! are not playing: **capture is compulsory**, and a jump that can continue MUST
//! continue — the same piece keeps the turn until it runs out of jumps. The
//! square that must keep jumping is remembered in `aux[0]` as `square + 1`, so
//! zero means "no chain in progress" without stealing square 0.

const std = @import("std");
const testing = std.testing;
const board = @import("board.zig");
const State = board.State;
const Seat = board.Seat;
const Outcome = board.Outcome;

pub const side = 8;
pub const squares = side * side;

pub const empty: u8 = 0;
pub const x_man: u8 = 1;
pub const o_man: u8 = 2;
pub const x_king: u8 = 3;
pub const o_king: u8 = 4;

/// `aux[0]`: the square whose jump chain is unfinished, plus one. 0 = none.
const aux_chain = 0;

/// Is this a dark (playable) square?
pub fn dark(sq: usize) bool {
    return ((sq / side) + (sq % side)) % 2 == 1;
}

/// Whose piece is on `sq` — `.none` for empty or off-board.
pub fn owner(s: State, sq: usize) Seat {
    if (sq >= squares) return .none;
    return switch (s.cells[sq]) {
        x_man, x_king => .x,
        o_man, o_king => .o,
        else => .none,
    };
}

/// Is the piece on `sq` a king?
pub fn isKing(s: State, sq: usize) bool {
    if (sq >= squares) return false;
    return s.cells[sq] == x_king or s.cells[sq] == o_king;
}

/// The square a chain must continue from, or null.
pub fn chainSquare(s: State) ?usize {
    if (s.aux[aux_chain] == 0) return null;
    return s.aux[aux_chain] - 1;
}

pub fn setup(s: *State) void {
    for (0..squares) |sq| {
        if (!dark(sq)) continue;
        const r = sq / side;
        if (r < 3) s.cells[sq] = o_man;
        if (r > 4) s.cells[sq] = x_man;
    }
}

/// Pack a move.
pub fn move(from: usize, to: usize) u16 {
    return @intCast((from & 63) | ((to & 63) << 6));
}
pub fn moveFrom(m: u16) usize {
    return m & 63;
}
pub fn moveTo(m: u16) usize {
    return (m >> 6) & 63;
}

/// May a piece of `v` (king or not) travel in row-direction `dr`? Men only go
/// forward: X up the board (dr = -1), O down (dr = +1).
fn dirOk(v: Seat, king: bool, dr: i32) bool {
    if (king) return true;
    return if (v == .x) dr < 0 else dr > 0;
}

/// Can the piece on `sq` jump something right now?
pub fn canJumpFrom(s: State, sq: usize) bool {
    const v = owner(s, sq);
    if (v == .none) return false;
    const king = isKing(s, sq);
    const r: i32 = @intCast(sq / side);
    const c: i32 = @intCast(sq % side);
    const steps = [4][2]i32{ .{ -1, -1 }, .{ -1, 1 }, .{ 1, -1 }, .{ 1, 1 } };
    for (steps) |d| {
        if (!dirOk(v, king, d[0])) continue;
        const mr = r + d[0];
        const mc = c + d[1];
        const tr = r + 2 * d[0];
        const tc = c + 2 * d[1];
        if (tr < 0 or tr >= side or tc < 0 or tc >= side) continue;
        const mid: usize = @intCast(mr * side + mc);
        const dst: usize = @intCast(tr * side + tc);
        if (owner(s, mid) != v.other()) continue;
        if (owner(s, mid) == .none) continue;
        if (s.cells[dst] != empty) continue;
        return true;
    }
    return false;
}

/// Does `v` have any jump available? Compulsory capture is decided from this.
pub fn anyJump(s: State, v: Seat) bool {
    for (0..squares) |sq| {
        if (owner(s, sq) != v) continue;
        if (canJumpFrom(s, sq)) return true;
    }
    return false;
}

/// Does `v` have any legal move at all? A side with none has LOST — being frozen
/// loses at checkers exactly as being wiped out does.
pub fn anyMove(s: State, v: Seat) bool {
    if (anyJump(s, v)) return true;
    for (0..squares) |sq| {
        if (owner(s, sq) != v) continue;
        const king = isKing(s, sq);
        const r: i32 = @intCast(sq / side);
        const c: i32 = @intCast(sq % side);
        const steps = [4][2]i32{ .{ -1, -1 }, .{ -1, 1 }, .{ 1, -1 }, .{ 1, 1 } };
        for (steps) |d| {
            if (!dirOk(v, king, d[0])) continue;
            const tr = r + d[0];
            const tc = c + d[1];
            if (tr < 0 or tr >= side or tc < 0 or tc >= side) continue;
            if (s.cells[@intCast(tr * side + tc)] == empty) return true;
        }
    }
    return false;
}

/// Promote a man that has reached the far row. Returns true if it happened —
/// a promotion ENDS a jump chain, which is the standard rule.
fn crown(s: *State, sq: usize) bool {
    const r = sq / side;
    if (s.cells[sq] == x_man and r == 0) {
        s.cells[sq] = x_king;
        return true;
    }
    if (s.cells[sq] == o_man and r == side - 1) {
        s.cells[sq] = o_king;
        return true;
    }
    return false;
}

/// Play `from → to` for `s.turn`.
pub fn apply(s: State, m: u16) ?State {
    const from = moveFrom(m);
    const to = moveTo(m);
    if (from == to) return null;
    if (from >= squares or to >= squares) return null;
    if (owner(s, from) != s.turn) return null;
    if (s.cells[to] != empty) return null;

    // A chain in progress belongs to ONE piece; nothing else may move.
    if (chainSquare(s)) |must| {
        if (from != must) return null;
    }

    const king = isKing(s, from);
    const fr: i32 = @intCast(from / side);
    const fc: i32 = @intCast(from % side);
    const tr: i32 = @intCast(to / side);
    const tc: i32 = @intCast(to % side);
    const dr = tr - fr;
    const dc = tc - fc;
    if (@abs(dc) != @abs(dr)) return null; // not a diagonal
    if (!dirOk(s.turn, king, dr)) return null;

    var ns = s;
    var jumped = false;
    if (@abs(dr) == 2) {
        const mid: usize = @intCast((fr + @divTrunc(dr, 2)) * side + (fc + @divTrunc(dc, 2)));
        if (owner(s, mid) != s.turn.other()) return null;
        ns.cells[mid] = empty;
        jumped = true;
    } else if (@abs(dr) == 1) {
        // A quiet move is only legal when no capture is on offer anywhere.
        if (anyJump(s, s.turn)) return null;
        if (chainSquare(s) != null) return null; // mid-chain: only jumps
    } else return null;

    ns.cells[to] = ns.cells[from];
    ns.cells[from] = empty;
    const promoted = crown(&ns, to);

    if (jumped and !promoted and canJumpFrom(ns, to)) {
        // The chain continues, and only with this piece.
        ns.aux[aux_chain] = @intCast(to + 1);
        ns.turn = s.turn;
    } else {
        ns.aux[aux_chain] = 0;
        ns.turn = s.turn.other();
        // The side to move with nothing to do — no pieces, or every piece
        // blocked — has lost.
        if (!anyMove(ns, ns.turn)) ns.outcome = board.winFor(s.turn);
    }
    return ns;
}

/// How many pieces `v` still has — the count the view prints beside the board.
pub fn pieceCount(s: State, v: Seat) u8 {
    var n: u8 = 0;
    for (0..squares) |sq| {
        if (owner(s, sq) == v) n += 1;
    }
    return n;
}

// ---------------------------------------------------------------------------

fn fresh() State {
    var s = board.blank(.checkers);
    setup(&s);
    return s;
}

fn bare() State {
    return board.blank(.checkers);
}

fn at(r: usize, c: usize) usize {
    return r * side + c;
}

test "the opening position seats twelve men a side on dark squares only" {
    const s = fresh();
    try testing.expectEqual(@as(u8, 12), pieceCount(s, .x));
    try testing.expectEqual(@as(u8, 12), pieceCount(s, .o));
    try testing.expectEqual(@as(u8, 0), s.cells[at(3, 0)]); // the empty middle
    try testing.expectEqual(@as(u8, 0), s.cells[at(4, 1)]);
    for (0..squares) |i| {
        if (!dark(i)) try testing.expectEqual(@as(u8, 0), s.cells[i]);
    }
}

test "a man steps forward one diagonal and no further, and never backward" {
    const s = fresh();
    // X's man on (5,0) may step to (4,1).
    try testing.expect(apply(s, move(at(5, 0), at(4, 1))) != null);
    // …but not backward to (6,1), nor straight, nor onto an occupied square.
    try testing.expectEqual(@as(?State, null), apply(s, move(at(5, 0), at(6, 1))));
    try testing.expectEqual(@as(?State, null), apply(s, move(at(5, 0), at(4, 0))));
    try testing.expectEqual(@as(?State, null), apply(s, move(at(5, 2), at(6, 1))));
    // …and O's pieces are not X's to move.
    try testing.expectEqual(@as(?State, null), apply(s, move(at(2, 1), at(3, 0))));
}

test "CAPTURE IS COMPULSORY: a quiet move is refused while a jump is on offer" {
    var s = bare();
    s.cells[at(5, 2)] = x_man;
    s.cells[at(4, 3)] = o_man; // jumpable to (3,4)
    s.cells[at(5, 6)] = x_man; // a free quiet move elsewhere
    try testing.expectEqual(@as(?State, null), apply(s, move(at(5, 6), at(4, 7))));
    try testing.expectEqual(@as(?State, null), apply(s, move(at(5, 2), at(4, 1))));
    const ns = apply(s, move(at(5, 2), at(3, 4))).?;
    try testing.expectEqual(@as(u8, 0), ns.cells[at(4, 3)]); // taken
    try testing.expectEqual(x_man, ns.cells[at(3, 4)]);
}

test "a jump that can continue KEEPS the turn, and only that piece may move" {
    var s = bare();
    s.cells[at(5, 2)] = x_man;
    s.cells[at(4, 3)] = o_man;
    s.cells[at(2, 3)] = o_man; // a second jump waits at (3,4) → (1,2)
    s.cells[at(7, 0)] = x_man; // an idle X man that must NOT be allowed to move
    const ns = apply(s, move(at(5, 2), at(3, 4))).?;
    try testing.expectEqual(Seat.x, ns.turn); // still ours
    try testing.expectEqual(@as(usize, at(3, 4)), chainSquare(ns).?);
    try testing.expectEqual(@as(?State, null), apply(ns, move(at(7, 0), at(6, 1))));
    const done = apply(ns, move(at(3, 4), at(1, 2))).?;
    try testing.expectEqual(@as(u8, 0), done.cells[at(2, 3)]);
    try testing.expectEqual(Seat.o, done.turn);
    try testing.expectEqual(@as(?usize, null), chainSquare(done));
}

test "reaching the far row crowns a king, and a king may travel backward" {
    var s = bare();
    s.cells[at(1, 2)] = x_man;
    s.cells[at(4, 4)] = o_man; // so O still has a move and the game continues
    const ns = apply(s, move(at(1, 2), at(0, 1))).?;
    try testing.expectEqual(x_king, ns.cells[at(0, 1)]);
    // Hand the turn back and the king can now step DOWN the board.
    var back = ns;
    back.turn = .x;
    try testing.expect(apply(back, move(at(0, 1), at(1, 2))) != null);
}

test "a promotion ENDS the jump chain even when another jump is available" {
    var s = bare();
    s.cells[at(2, 1)] = x_man;
    s.cells[at(1, 2)] = o_man; // jump to (0,3) → crowns
    s.cells[at(1, 4)] = o_man; // a king on (0,3) could jump this next
    s.cells[at(6, 6)] = o_man; // give O a legal reply so the game continues
    const ns = apply(s, move(at(2, 1), at(0, 3))).?;
    try testing.expectEqual(x_king, ns.cells[at(0, 3)]);
    try testing.expectEqual(Seat.o, ns.turn); // crowned, so the chain stops
    try testing.expectEqual(@as(?usize, null), chainSquare(ns));
}

test "taking the last piece wins, and so does freezing the opponent" {
    // Wiped out.
    var s = bare();
    s.cells[at(5, 2)] = x_man;
    s.cells[at(4, 3)] = o_man;
    const won = apply(s, move(at(5, 2), at(3, 4))).?;
    try testing.expectEqual(Outcome.x_wins, won.outcome);

    // Frozen: O's only man is boxed into the corner with nowhere to go.
    var f = bare();
    f.cells[at(7, 0)] = o_man; // O moves DOWN the board; row 7 is the last row…
    f.cells[at(6, 1)] = x_man;
    f.cells[at(5, 2)] = x_man;
    f.turn = .x;
    // X steps somewhere harmless; O then has no move at all.
    const frozen = apply(f, move(at(5, 2), at(4, 3))).?;
    try testing.expectEqual(Outcome.x_wins, frozen.outcome);
}

test "an off-board, non-diagonal or same-square move is refused" {
    const s = fresh();
    try testing.expectEqual(@as(?State, null), apply(s, move(at(5, 0), at(5, 0))));
    try testing.expectEqual(@as(?State, null), apply(s, 0xFFF));
}
