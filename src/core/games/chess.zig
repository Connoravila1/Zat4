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

//! B1 classification: CORE (pure). CHESS — the rules only, and all of them.
//!
//! Board: 64 squares in `cells`, `row * 8 + col`, ROW 0 IS RANK 8 (O's home, at
//! the top of the screen) and row 7 is rank 1 (X's home, at the bottom). X is
//! White and moves up the board; X moves first, which is also the seat rule
//! everywhere else in the thread — the player who sends the invite is X.
//!
//! Piece bytes: the low three bits are the type, bit 3 is the colour (clear = X).
//!
//!   ```
//!   1 pawn   2 knight   3 bishop   4 rook   5 queen   6 king   (+8 for O)
//!   ```
//!
//! Move: `from | (to << 6) | (promotion << 12)` — the promotion field names the
//! piece type a pawn becomes, and 0 means queen (the choice you make 97% of the
//! time; the UI still offers the other three).
//!
//! `aux`: [0] castling rights bitmask, [1] the en-passant target square + 1
//! (0 = none), [2] the halfmove clock for the fifty-move rule.
//!
//! Everything the real game has is here — castling through and out of check, en
//! passant, under-promotion, checkmate, stalemate, the fifty-move rule and
//! insufficient material. It is all in the CORE because the rules must be the
//! same on both phones: a client that lets its owner play an illegal move would
//! simply be replaying a different game than their opponent, and the board would
//! silently diverge. `apply` returning `null` is the whole enforcement.

const std = @import("std");
const testing = std.testing;
const board = @import("board.zig");
const State = board.State;
const Seat = board.Seat;
const Outcome = board.Outcome;

pub const side = 8;
pub const squares = side * side;

pub const pawn: u8 = 1;
pub const knight: u8 = 2;
pub const bishop: u8 = 3;
pub const rook: u8 = 4;
pub const queen: u8 = 5;
pub const king: u8 = 6;
pub const o_bit: u8 = 8;

/// Castling rights, one bit each.
pub const cr_x_king: u8 = 1;
pub const cr_x_queen: u8 = 2;
pub const cr_o_king: u8 = 4;
pub const cr_o_queen: u8 = 8;

const aux_rights = 0;
const aux_ep = 1; // en-passant target square + 1
const aux_clock = 2; // halfmove clock (fifty-move rule)

/// The type of the piece on `sq` (0 = empty).
pub fn pieceType(s: State, sq: usize) u8 {
    if (sq >= squares) return 0;
    return s.cells[sq] & 7;
}

/// Whose piece is on `sq`.
pub fn owner(s: State, sq: usize) Seat {
    if (sq >= squares) return .none;
    const b = s.cells[sq];
    if (b == 0) return .none;
    return if (b & o_bit == 0) .x else .o;
}

fn code(v: Seat, t: u8) u8 {
    return t | (if (v == .o) o_bit else 0);
}

fn rowOf(sq: usize) i32 {
    return @intCast(sq / side);
}
fn colOf(sq: usize) i32 {
    return @intCast(sq % side);
}
fn sqAt(r: i32, c: i32) usize {
    return @intCast(r * side + c);
}
fn onBoard(r: i32, c: i32) bool {
    return r >= 0 and r < side and c >= 0 and c < side;
}

/// The row a pawn of `v` moves TOWARD (X up the board, O down).
fn pawnStep(v: Seat) i32 {
    return if (v == .x) -1 else 1;
}
/// The row `v`'s pawns start on.
fn pawnHome(v: Seat) i32 {
    return if (v == .x) 6 else 1;
}
/// The row `v`'s pawns promote on.
fn promoRow(v: Seat) i32 {
    return if (v == .x) 0 else 7;
}
/// The back rank of `v`.
fn backRow(v: Seat) i32 {
    return if (v == .x) 7 else 0;
}

pub fn setup(s: *State) void {
    const order = [side]u8{ rook, knight, bishop, queen, king, bishop, knight, rook };
    for (0..side) |c| {
        s.cells[sqAt(0, @intCast(c))] = code(.o, order[c]);
        s.cells[sqAt(1, @intCast(c))] = code(.o, pawn);
        s.cells[sqAt(6, @intCast(c))] = code(.x, pawn);
        s.cells[sqAt(7, @intCast(c))] = code(.x, order[c]);
    }
    s.aux[aux_rights] = cr_x_king | cr_x_queen | cr_o_king | cr_o_queen;
    s.aux[aux_ep] = 0;
    s.aux[aux_clock] = 0;
}

/// Pack a move. `promo` is a piece type (0 = queen when a pawn promotes).
pub fn move(from: usize, to: usize, promo: u8) u16 {
    return @intCast((from & 63) | ((to & 63) << 6) | ((@as(usize, promo) & 7) << 12));
}
pub fn moveFrom(m: u16) usize {
    return m & 63;
}
pub fn moveTo(m: u16) usize {
    return (m >> 6) & 63;
}
pub fn movePromo(m: u16) u8 {
    return @intCast((m >> 12) & 7);
}

/// The en-passant target square, if the last move was a double pawn push.
pub fn epTarget(s: State) ?usize {
    if (s.aux[aux_ep] == 0) return null;
    return s.aux[aux_ep] - 1;
}

const knight_steps = [8][2]i32{ .{ -2, -1 }, .{ -2, 1 }, .{ -1, -2 }, .{ -1, 2 }, .{ 1, -2 }, .{ 1, 2 }, .{ 2, -1 }, .{ 2, 1 } };
const king_steps = [8][2]i32{ .{ -1, -1 }, .{ -1, 0 }, .{ -1, 1 }, .{ 0, -1 }, .{ 0, 1 }, .{ 1, -1 }, .{ 1, 0 }, .{ 1, 1 } };
const rook_dirs = [4][2]i32{ .{ -1, 0 }, .{ 1, 0 }, .{ 0, -1 }, .{ 0, 1 } };
const bishop_dirs = [4][2]i32{ .{ -1, -1 }, .{ -1, 1 }, .{ 1, -1 }, .{ 1, 1 } };

/// Is `target` attacked by any piece of `by`? The one question castling, check
/// and checkmate all reduce to.
pub fn attacked(s: State, target: usize, by: Seat) bool {
    const tr = rowOf(target);
    const tc = colOf(target);

    // Pawns: a pawn of `by` attacks the square one step AHEAD of itself, so it
    // must be sitting one step BACK from the target.
    const back = -pawnStep(by);
    for ([_]i32{ -1, 1 }) |dc| {
        const r = tr + back;
        const c = tc + dc;
        if (!onBoard(r, c)) continue;
        const q = sqAt(r, c);
        if (owner(s, q) == by and pieceType(s, q) == pawn) return true;
    }
    // Knights and the king: fixed offsets.
    for (knight_steps) |d| {
        const r = tr + d[0];
        const c = tc + d[1];
        if (!onBoard(r, c)) continue;
        const q = sqAt(r, c);
        if (owner(s, q) == by and pieceType(s, q) == knight) return true;
    }
    for (king_steps) |d| {
        const r = tr + d[0];
        const c = tc + d[1];
        if (!onBoard(r, c)) continue;
        const q = sqAt(r, c);
        if (owner(s, q) == by and pieceType(s, q) == king) return true;
    }
    // Sliders: walk out until something blocks.
    for (rook_dirs) |d| {
        var r = tr + d[0];
        var c = tc + d[1];
        while (onBoard(r, c)) : ({
            r += d[0];
            c += d[1];
        }) {
            const q = sqAt(r, c);
            if (s.cells[q] == 0) continue;
            if (owner(s, q) == by and (pieceType(s, q) == rook or pieceType(s, q) == queen)) return true;
            break;
        }
    }
    for (bishop_dirs) |d| {
        var r = tr + d[0];
        var c = tc + d[1];
        while (onBoard(r, c)) : ({
            r += d[0];
            c += d[1];
        }) {
            const q = sqAt(r, c);
            if (s.cells[q] == 0) continue;
            if (owner(s, q) == by and (pieceType(s, q) == bishop or pieceType(s, q) == queen)) return true;
            break;
        }
    }
    return false;
}

/// Where `v`'s king stands (or null on a board with no king — only reachable
/// from a hand-built position, never from a real game).
pub fn kingSquare(s: State, v: Seat) ?usize {
    for (0..squares) |sq| {
        if (owner(s, sq) == v and pieceType(s, sq) == king) return sq;
    }
    return null;
}

/// Is `v` in check?
pub fn inCheck(s: State, v: Seat) bool {
    const k = kingSquare(s, v) orelse return false;
    return attacked(s, k, v.other());
}

/// Is the geometry of `from → to` legal for the piece standing there, ignoring
/// whether it leaves our own king in check? Castling is handled by `castleSide`.
fn pseudoLegal(s: State, from: usize, to: usize) bool {
    const v = owner(s, from);
    if (v == .none or v != s.turn) return false;
    if (from == to) return false;
    if (owner(s, to) == v) return false; // never capture your own
    const fr = rowOf(from);
    const fc = colOf(from);
    const tr = rowOf(to);
    const tc = colOf(to);
    const dr = tr - fr;
    const dc = tc - fc;
    switch (pieceType(s, from)) {
        pawn => {
            const step = pawnStep(v);
            if (dc == 0) {
                if (dr == step and s.cells[to] == 0) return true;
                if (dr == 2 * step and fr == pawnHome(v) and
                    s.cells[to] == 0 and s.cells[sqAt(fr + step, fc)] == 0) return true;
                return false;
            }
            if (@abs(dc) == 1 and dr == step) {
                if (owner(s, to) == v.other()) return true;
                // En passant: the target square is empty, but the pawn that
                // just passed it is taken.
                if (epTarget(s)) |ep| {
                    if (ep == to and s.cells[to] == 0) return true;
                }
            }
            return false;
        },
        knight => {
            for (knight_steps) |d| {
                if (d[0] == dr and d[1] == dc) return true;
            }
            return false;
        },
        king => {
            return @abs(dr) <= 1 and @abs(dc) <= 1;
        },
        bishop, rook, queen => {
            const t = pieceType(s, from);
            const diagonal = @abs(dr) == @abs(dc);
            const straight = dr == 0 or dc == 0;
            if (t == bishop and !diagonal) return false;
            if (t == rook and !straight) return false;
            if (t == queen and !(diagonal or straight)) return false;
            const sr: i32 = std.math.sign(dr);
            const sc: i32 = std.math.sign(dc);
            var r = fr + sr;
            var c = fc + sc;
            while (r != tr or c != tc) : ({
                r += sr;
                c += sc;
            }) {
                if (!onBoard(r, c)) return false;
                if (s.cells[sqAt(r, c)] != 0) return false; // blocked
            }
            return true;
        },
        else => return false,
    }
}

/// If `from → to` is a castling attempt for `s.turn`, which side is it? Returns
/// null when the move is not a castle at all.
fn castleSide(s: State, from: usize, to: usize) ?enum { kingside, queenside } {
    if (pieceType(s, from) != king) return null;
    const v = s.turn;
    if (from != sqAt(backRow(v), 4)) return null;
    if (to == sqAt(backRow(v), 6)) return .kingside;
    if (to == sqAt(backRow(v), 2)) return .queenside;
    return null;
}

/// May `s.turn` castle to that side right now? Checks the rights, the empty
/// squares, the rook, and the three squares the king must not be attacked on —
/// you may not castle out of, through, or into check.
fn canCastle(s: State, kingside: bool) bool {
    const v = s.turn;
    const br = backRow(v);
    const right: u8 = if (v == .x)
        (if (kingside) cr_x_king else cr_x_queen)
    else
        (if (kingside) cr_o_king else cr_o_queen);
    if (s.aux[aux_rights] & right == 0) return false;
    const rook_sq = sqAt(br, if (kingside) 7 else 0);
    if (owner(s, rook_sq) != v or pieceType(s, rook_sq) != rook) return false;
    const empties: []const i32 = if (kingside) &[_]i32{ 5, 6 } else &[_]i32{ 1, 2, 3 };
    for (empties) |c| {
        if (s.cells[sqAt(br, c)] != 0) return false;
    }
    const path: []const i32 = if (kingside) &[_]i32{ 4, 5, 6 } else &[_]i32{ 4, 3, 2 };
    for (path) |c| {
        if (attacked(s, sqAt(br, c), v.other())) return false;
    }
    return true;
}

/// Clear the castling rights a move touches: a king that moves loses both, and a
/// rook that leaves (or is captured on) its home square loses that one.
fn touchRights(s: *State, sq: usize) void {
    const map = [_]struct { sq: usize, bit: u8 }{
        .{ .sq = sqAt(7, 4), .bit = cr_x_king | cr_x_queen },
        .{ .sq = sqAt(0, 4), .bit = cr_o_king | cr_o_queen },
        .{ .sq = sqAt(7, 7), .bit = cr_x_king },
        .{ .sq = sqAt(7, 0), .bit = cr_x_queen },
        .{ .sq = sqAt(0, 7), .bit = cr_o_king },
        .{ .sq = sqAt(0, 0), .bit = cr_o_queen },
    };
    for (map) |m| {
        if (m.sq == sq) s.aux[aux_rights] &= ~m.bit;
    }
}

/// Play the move on the board without asking whether it is legal — the caller
/// has already decided. Handles the three moves that are not just "piece goes
/// there": castling moves the rook too, en passant takes a pawn that is not on
/// the destination square, and a promoting pawn arrives as something else.
fn applyRaw(s: State, from: usize, to: usize, promo: u8) State {
    var ns = s;
    const v = s.turn;
    const moved = pieceType(s, from);
    const capture = s.cells[to] != 0;

    if (castleSide(s, from, to)) |cs| {
        const br = backRow(v);
        const rf = sqAt(br, if (cs == .kingside) 7 else 0);
        const rt = sqAt(br, if (cs == .kingside) 5 else 3);
        ns.cells[rt] = ns.cells[rf];
        ns.cells[rf] = 0;
    }

    var ep_capture = false;
    if (moved == pawn) {
        if (epTarget(s)) |ep| {
            if (to == ep and s.cells[to] == 0 and colOf(from) != colOf(to)) {
                // The captured pawn sits BESIDE us, not on the square we land on.
                ns.cells[sqAt(rowOf(from), colOf(to))] = 0;
                ep_capture = true;
            }
        }
    }

    ns.cells[to] = ns.cells[from];
    ns.cells[from] = 0;

    if (moved == pawn and rowOf(to) == promoRow(v)) {
        var t = promo;
        if (t < knight or t > queen) t = queen; // 0 (and anything odd) means queen
        ns.cells[to] = code(v, t);
    }

    // A new en-passant target only exists for the one move after a double push.
    ns.aux[aux_ep] = 0;
    if (moved == pawn and @abs(rowOf(to) - rowOf(from)) == 2) {
        ns.aux[aux_ep] = @intCast(sqAt(@divTrunc(rowOf(to) + rowOf(from), 2), colOf(from)) + 1);
    }

    touchRights(&ns, from);
    touchRights(&ns, to);

    // The fifty-move clock resets on a pawn move or a capture and counts
    // half-moves otherwise.
    if (moved == pawn or capture or ep_capture) ns.aux[aux_clock] = 0 else ns.aux[aux_clock] +|= 1;

    ns.turn = v.other();
    return ns;
}

/// Does `v` have ANY legal move? Checkmate and stalemate are the same question
/// asked of a side in check and a side not in check.
pub fn anyLegalMove(s: State, v: Seat) bool {
    var probe = s;
    probe.turn = v;
    probe.outcome = .ongoing;
    for (0..squares) |from| {
        if (owner(probe, from) != v) continue;
        for (0..squares) |to| {
            if (legalGeometry(probe, from, to)) return true;
        }
    }
    return false;
}

/// Geometry + castling + the king-safety filter, without any of the bookkeeping
/// `apply` layers on top. The shared predicate behind `apply` and `anyLegalMove`.
fn legalGeometry(s: State, from: usize, to: usize) bool {
    if (from >= squares or to >= squares) return false;
    if (owner(s, from) != s.turn) return false;
    var ok = pseudoLegal(s, from, to);
    if (!ok) {
        if (castleSide(s, from, to)) |cs| ok = canCastle(s, cs == .kingside);
    }
    if (!ok) return false;
    const after = applyRaw(s, from, to, 0);
    return !inCheck(after, s.turn);
}

/// Every square `from` can legally move to, written into `out`. The view uses it
/// to light up destinations when you pick a piece up — the same predicate the
/// rules use, so what is highlighted is exactly what is allowed.
pub fn destinations(s: State, from: usize, out: []u8) []u8 {
    var n: usize = 0;
    if (owner(s, from) != s.turn) return out[0..0];
    for (0..squares) |to| {
        if (!legalGeometry(s, from, to)) continue;
        if (n >= out.len) break;
        out[n] = @intCast(to);
        n += 1;
    }
    return out[0..n];
}

/// Neither side can force mate: K vs K, K+minor vs K, and K+B vs K+B on the same
/// colour. A game that cannot be won is a draw, and saying so here stops a dead
/// position sitting "ongoing" in the thread forever.
fn insufficientMaterial(s: State) bool {
    var minors: usize = 0;
    var bishop_colours: [2]bool = .{ false, false };
    for (0..squares) |sq| {
        const t = pieceType(s, sq);
        switch (t) {
            0, king => {},
            bishop => {
                minors += 1;
                bishop_colours[@intCast(@mod(rowOf(sq) + colOf(sq), 2))] = true;
            },
            knight => minors += 1,
            else => return false, // a pawn, rook or queen can still mate
        }
    }
    if (minors <= 1) return true;
    // Only bishops left, and all of them on one colour: nobody can ever be mated.
    return minors >= 2 and !(bishop_colours[0] and bishop_colours[1]);
}

/// Play `m` for `s.turn`.
pub fn apply(s: State, m: u16) ?State {
    const from = moveFrom(m);
    const to = moveTo(m);
    if (!legalGeometry(s, from, to)) return null;
    var ns = applyRaw(s, from, to, movePromo(m));

    const them = ns.turn;
    if (!anyLegalMove(ns, them)) {
        ns.outcome = if (inCheck(ns, them)) board.winFor(them.other()) else .draw;
    } else if (ns.aux[aux_clock] >= 100) {
        ns.outcome = .draw; // fifty moves by each side without a pawn or a capture
    } else if (insufficientMaterial(ns)) {
        ns.outcome = .draw;
    }
    return ns;
}

/// The material count for `v` in pawns — the little advantage number beside the
/// board. Kings are not counted; they are never captured.
pub fn material(s: State, v: Seat) u8 {
    var total: u8 = 0;
    for (0..squares) |sq| {
        if (owner(s, sq) != v) continue;
        total +|= switch (pieceType(s, sq)) {
            pawn => 1,
            knight, bishop => 3,
            rook => 5,
            queen => 9,
            else => 0,
        };
    }
    return total;
}

// ---------------------------------------------------------------------------

fn fresh() State {
    var s = board.blank(.chess);
    setup(&s);
    return s;
}

fn bare() State {
    var s = board.blank(.chess);
    s.aux[aux_rights] = 0;
    return s;
}

fn at(r: i32, c: i32) usize {
    return sqAt(r, c);
}

fn play(s0: State, seq: []const [2]usize) State {
    var s = s0;
    for (seq) |mv| {
        if (s.outcome != .ongoing) break;
        if (apply(s, move(mv[0], mv[1], 0))) |ns| s = ns;
    }
    return s;
}

test "the opening position is thirty-two pieces, X to move, all rights intact" {
    const s = fresh();
    try testing.expectEqual(@as(u8, 39), material(s, .x)); // 8+2*3+2*3+2*5+9
    try testing.expectEqual(@as(u8, 39), material(s, .o));
    try testing.expectEqual(cr_x_king | cr_x_queen | cr_o_king | cr_o_queen, s.aux[aux_rights]);
    try testing.expectEqual(Seat.x, s.turn);
    try testing.expectEqual(@as(usize, at(7, 4)), kingSquare(s, .x).?);
}

test "a pawn steps one or two from home, one thereafter, and never onto a piece" {
    var s = fresh();
    try testing.expect(apply(s, move(at(6, 4), at(5, 4), 0)) != null);
    try testing.expect(apply(s, move(at(6, 4), at(4, 4), 0)) != null);
    try testing.expectEqual(@as(?State, null), apply(s, move(at(6, 4), at(3, 4), 0)));
    s = play(s, &.{ .{ at(6, 4), at(4, 4) }, .{ at(1, 4), at(3, 4) } });
    // The two pawns now face each other: neither can advance.
    try testing.expectEqual(@as(?State, null), apply(s, move(at(4, 4), at(3, 4), 0)));
}

test "a knight jumps over its own pawns; a bishop does not" {
    const s = fresh();
    try testing.expect(apply(s, move(at(7, 1), at(5, 2), 0)) != null);
    try testing.expectEqual(@as(?State, null), apply(s, move(at(7, 2), at(5, 4), 0)));
}

test "you may not leave your own king in check (a pinned piece cannot move)" {
    var s = bare();
    s.cells[at(7, 4)] = code(.x, king);
    s.cells[at(6, 4)] = code(.x, rook); // pinned by the rook down the e-file
    s.cells[at(0, 4)] = code(.o, rook);
    s.cells[at(0, 0)] = code(.o, king);
    s.turn = .x;
    try testing.expectEqual(@as(?State, null), apply(s, move(at(6, 4), at(6, 3), 0))); // steps off the file
    try testing.expect(apply(s, move(at(6, 4), at(5, 4), 0)) != null); // along the pin is fine
}

test "castling moves the rook too, and is refused through, out of, or into check" {
    var s = bare();
    s.cells[at(7, 4)] = code(.x, king);
    s.cells[at(7, 7)] = code(.x, rook);
    s.cells[at(0, 0)] = code(.o, king);
    s.aux[aux_rights] = cr_x_king;
    s.turn = .x;
    const castled = apply(s, move(at(7, 4), at(7, 6), 0)).?;
    try testing.expectEqual(code(.x, king), castled.cells[at(7, 6)]);
    try testing.expectEqual(code(.x, rook), castled.cells[at(7, 5)]);
    try testing.expectEqual(@as(u8, 0), castled.aux[aux_rights]); // spent

    // THROUGH check: a rook eyeing f1.
    var t = s;
    t.cells[at(0, 5)] = code(.o, rook);
    try testing.expectEqual(@as(?State, null), apply(t, move(at(7, 4), at(7, 6), 0)));
    // OUT of check: a rook eyeing e1.
    var u = s;
    u.cells[at(0, 4)] = code(.o, rook);
    try testing.expectEqual(@as(?State, null), apply(u, move(at(7, 4), at(7, 6), 0)));
    // INTO check: a rook eyeing g1.
    var w = s;
    w.cells[at(0, 6)] = code(.o, rook);
    try testing.expectEqual(@as(?State, null), apply(w, move(at(7, 4), at(7, 6), 0)));
    // A blocking piece also refuses it.
    var b = s;
    b.cells[at(7, 5)] = code(.x, bishop);
    try testing.expectEqual(@as(?State, null), apply(b, move(at(7, 4), at(7, 6), 0)));
}

test "moving the king or a rook spends the castling right" {
    var s = bare();
    s.cells[at(7, 4)] = code(.x, king);
    s.cells[at(7, 7)] = code(.x, rook);
    s.cells[at(0, 0)] = code(.o, king);
    s.aux[aux_rights] = cr_x_king;
    s.turn = .x;
    const moved = apply(s, move(at(7, 7), at(6, 7), 0)).?;
    try testing.expectEqual(@as(u8, 0), moved.aux[aux_rights]);
}

test "en passant takes a pawn that is not on the destination square" {
    var s = bare();
    s.cells[at(3, 4)] = code(.x, pawn); // our pawn on the fifth rank
    s.cells[at(1, 3)] = code(.o, pawn);
    s.cells[at(7, 4)] = code(.x, king);
    s.cells[at(0, 0)] = code(.o, king);
    s.turn = .o;
    const pushed = apply(s, move(at(1, 3), at(3, 3), 0)).?; // double push past us
    try testing.expectEqual(@as(usize, at(2, 3)), epTarget(pushed).?);
    const taken = apply(pushed, move(at(3, 4), at(2, 3), 0)).?;
    try testing.expectEqual(@as(u8, 0), taken.cells[at(3, 3)]); // the passing pawn is gone
    try testing.expectEqual(code(.x, pawn), taken.cells[at(2, 3)]);
    try testing.expectEqual(@as(?usize, null), epTarget(taken)); // and the window closes
}

test "a pawn reaching the last rank promotes — to a queen by default, or your pick" {
    var s = bare();
    s.cells[at(1, 0)] = code(.x, pawn);
    s.cells[at(7, 4)] = code(.x, king);
    s.cells[at(4, 7)] = code(.o, king);
    s.turn = .x;
    const q = apply(s, move(at(1, 0), at(0, 0), 0)).?;
    try testing.expectEqual(code(.x, queen), q.cells[at(0, 0)]);
    const n = apply(s, move(at(1, 0), at(0, 0), knight)).?;
    try testing.expectEqual(code(.x, knight), n.cells[at(0, 0)]);
}

test "the back-rank mate ends the game" {
    var s = bare();
    s.cells[at(0, 4)] = code(.o, king);
    s.cells[at(1, 3)] = code(.o, pawn);
    s.cells[at(1, 4)] = code(.o, pawn);
    s.cells[at(1, 5)] = code(.o, pawn);
    s.cells[at(7, 0)] = code(.x, king);
    s.cells[at(6, 0)] = code(.x, rook);
    s.turn = .x;
    const mate = apply(s, move(at(6, 0), at(0, 0), 0)).?;
    try testing.expectEqual(Outcome.x_wins, mate.outcome);
    try testing.expect(inCheck(mate, .o));
}

test "stalemate is a draw, not a win" {
    // The textbook corner: O's king is boxed in and it is not in check — the
    // rook covers the two squares the enemy king's own neighbour does not, and
    // is itself defended, so it cannot be taken either.
    var s = bare();
    s.cells[at(0, 0)] = code(.o, king);
    s.cells[at(1, 2)] = code(.x, king);
    s.cells[at(7, 1)] = code(.x, rook);
    s.turn = .x;
    const stale = apply(s, move(at(7, 1), at(1, 1), 0)).?;
    try testing.expectEqual(Outcome.draw, stale.outcome);
    try testing.expect(!inCheck(stale, .o));
}

test "king against king is a dead draw the moment it happens" {
    var s = bare();
    s.cells[at(7, 0)] = code(.x, king);
    s.cells[at(4, 4)] = code(.x, rook); // X's last piece besides the king
    s.cells[at(0, 0)] = code(.o, king);
    s.cells[at(7, 7)] = code(.o, bishop);
    s.turn = .o;
    const dead = apply(s, move(at(7, 7), at(4, 4), 0)).?; // takes the rook
    // King and bishop against a lone king: nobody can force mate, so the game is
    // over the moment the last mating piece leaves the board.
    try testing.expectEqual(Outcome.draw, dead.outcome);
}

test "destinations lists exactly what apply would accept" {
    const s = fresh();
    var buf: [64]u8 = undefined;
    const dst = destinations(s, at(7, 1), &buf); // the b1 knight
    try testing.expectEqual(@as(usize, 2), dst.len);
    for (dst) |d| try testing.expect(apply(s, move(at(7, 1), d, 0)) != null);
    // A piece that is not ours offers nothing.
    try testing.expectEqual(@as(usize, 0), destinations(s, at(0, 1), &buf).len);
}

test "a move for the wrong side, off the board, or onto our own piece is refused" {
    const s = fresh();
    try testing.expectEqual(@as(?State, null), apply(s, move(at(1, 0), at(2, 0), 0))); // O's pawn
    try testing.expectEqual(@as(?State, null), apply(s, move(at(7, 0), at(6, 0), 0))); // own pawn there
    try testing.expectEqual(@as(?State, null), apply(s, 0));
}

test "the fifty-move rule draws a game nobody is winning" {
    var s = bare();
    s.cells[at(7, 4)] = code(.x, king);
    s.cells[at(0, 4)] = code(.o, king);
    s.cells[at(7, 0)] = code(.x, rook);
    s.cells[at(0, 0)] = code(.o, rook);
    s.aux[aux_clock] = 99;
    s.turn = .x;
    const drawn = apply(s, move(at(7, 4), at(6, 4), 0)).?;
    try testing.expectEqual(@as(u8, 100), drawn.aux[aux_clock]);
    try testing.expectEqual(Outcome.draw, drawn.outcome);
}
