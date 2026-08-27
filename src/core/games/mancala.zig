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

//! B1 classification: CORE (pure). MANCALA (Kalah, 6×4) — the rules only.
//!
//! Board: 14 pits in `cells[0..13]`, each holding a STONE COUNT (not a seat —
//! this is the first game whose cells are numbers). Counterclockwise:
//!
//!   ```
//!   pit:   0  1  2  3  4  5   6      7  8  9 10 11 12  13
//!          └── X's pits ──┘  X store └── O's pits ──┘  O store
//!   ```
//!
//! Move: the pit you pick up. Sow one stone into each following pit, skipping the
//! OPPONENT's store. Two rules give the game its shape and both are here: land
//! your last stone in your own store and you go AGAIN, and land it in an empty pit
//! on your own side and you CAPTURE that stone plus everything opposite. When one
//! side has no stones left the other sweeps its remaining stones into its store
//! and the larger store wins.

const std = @import("std");
const testing = std.testing;
const board = @import("board.zig");
const State = board.State;
const Seat = board.Seat;
const Outcome = board.Outcome;

pub const pits = 14;
pub const per_side = 6;
pub const x_store: usize = 6;
pub const o_store: usize = 13;
pub const start_stones = 4;

pub fn setup(s: *State) void {
    for (0..pits) |i| {
        s.cells[i] = if (i == x_store or i == o_store) 0 else start_stones;
    }
}

/// The store belonging to `v`.
pub fn storeOf(v: Seat) usize {
    return if (v == .x) x_store else o_store;
}

/// Is `pit` one of `v`'s playable pits (not a store)?
pub fn ownsPit(v: Seat, pit: usize) bool {
    return if (v == .x) pit < per_side else (pit > x_store and pit < o_store);
}

/// The pit facing `pit` across the board — where a capture takes from.
fn opposite(pit: usize) usize {
    return 12 - pit;
}

/// Does `v` still have a stone to play?
fn hasStones(s: State, v: Seat) bool {
    var i: usize = 0;
    while (i < pits) : (i += 1) {
        if (i == x_store or i == o_store) continue;
        if (ownsPit(v, i) and s.cells[i] > 0) return true;
    }
    return false;
}

/// End the game: whoever still has stones sweeps them into their store, and the
/// larger store wins. Stone counts can reach 48, which still fits a byte.
fn settle(s: *State) void {
    for (0..pits) |i| {
        if (i == x_store or i == o_store) continue;
        if (s.cells[i] == 0) continue;
        const to: usize = if (ownsPit(.x, i)) x_store else o_store;
        s.cells[to] +|= s.cells[i];
        s.cells[i] = 0;
    }
    s.outcome = if (s.cells[x_store] > s.cells[o_store])
        .x_wins
    else if (s.cells[o_store] > s.cells[x_store])
        .o_wins
    else
        .draw;
}

/// Pick up `pit` and sow.
pub fn apply(s: State, pit: u16) ?State {
    const p: usize = pit;
    if (p >= pits) return null;
    if (!ownsPit(s.turn, p)) return null; // not your pit (or a store)
    var hand = s.cells[p];
    if (hand == 0) return null;

    var ns = s;
    ns.cells[p] = 0;
    const skip = storeOf(s.turn.other());
    var at = p;
    while (hand > 0) {
        at = (at + 1) % pits;
        if (at == skip) continue; // never sow into the opponent's store
        ns.cells[at] +|= 1;
        hand -= 1;
    }

    // Capture: the last stone landed alone in one of OUR pits, and the pit
    // facing it holds something.
    if (ownsPit(s.turn, at) and ns.cells[at] == 1 and ns.cells[opposite(at)] > 0) {
        const mine = storeOf(s.turn);
        ns.cells[mine] +|= ns.cells[at] + ns.cells[opposite(at)];
        ns.cells[at] = 0;
        ns.cells[opposite(at)] = 0;
    }

    // A free turn if the last stone landed in our own store; otherwise pass.
    const again = at == storeOf(s.turn);
    ns.turn = if (again) s.turn else s.turn.other();

    // The game ends the moment either side is out of stones — not only the side
    // about to move, because a capture can empty the opponent.
    if (!hasStones(ns, .x) or !hasStones(ns, .o)) settle(&ns);
    return ns;
}

// ---------------------------------------------------------------------------

fn fresh() State {
    var s = board.blank(.mancala);
    setup(&s);
    return s;
}

test "the opening position is four stones in each of the twelve pits" {
    const s = fresh();
    try testing.expectEqual(@as(u8, 4), s.cells[0]);
    try testing.expectEqual(@as(u8, 4), s.cells[12]);
    try testing.expectEqual(@as(u8, 0), s.cells[x_store]);
    try testing.expectEqual(@as(u8, 0), s.cells[o_store]);
}

test "sowing walks counterclockwise and drops one stone per pit" {
    const s = apply(fresh(), 0).?;
    try testing.expectEqual(@as(u8, 0), s.cells[0]);
    try testing.expectEqual(@as(u8, 5), s.cells[1]);
    try testing.expectEqual(@as(u8, 5), s.cells[4]);
    try testing.expectEqual(@as(u8, 4), s.cells[5]); // untouched: only four stones
    try testing.expectEqual(Seat.o, s.turn);
}

test "landing in your own store is a FREE TURN" {
    // X's pit 2 holds four stones; they reach 3,4,5 and the store at 6.
    const s = apply(fresh(), 2).?;
    try testing.expectEqual(@as(u8, 1), s.cells[x_store]);
    try testing.expectEqual(Seat.x, s.turn); // go again
}

test "you never sow into the opponent's store" {
    // Give X a long pit so the sowing wraps past O's side.
    var s = fresh();
    s.cells[5] = 10; // reaches store(6), 7..12, then 0,1,2 — skipping 13
    const ns = apply(s, 5).?;
    try testing.expectEqual(@as(u8, 0), ns.cells[o_store]);
    try testing.expectEqual(@as(u8, 1), ns.cells[x_store]);
    try testing.expectEqual(@as(u8, 5), ns.cells[0]);
}

test "landing alone in your own empty pit CAPTURES it and the pit opposite" {
    var s = fresh();
    s.cells[0] = 0;
    s.cells[5] = 0;
    s.cells[4] = 1; // one stone, landing in the empty pit 5
    s.cells[7] = 4; // opposite pit 5 is pit 7
    const ns = apply(s, 4).?;
    try testing.expectEqual(@as(u8, 0), ns.cells[5]);
    try testing.expectEqual(@as(u8, 0), ns.cells[7]);
    try testing.expectEqual(@as(u8, 5), ns.cells[x_store]); // 1 + 4
    try testing.expectEqual(Seat.o, ns.turn);
}

test "a capture on an EMPTY opposite pit takes nothing" {
    var s = fresh();
    s.cells[5] = 0;
    s.cells[4] = 1;
    s.cells[7] = 0;
    const ns = apply(s, 4).?;
    try testing.expectEqual(@as(u8, 1), ns.cells[5]); // the stone stays put
    try testing.expectEqual(@as(u8, 0), ns.cells[x_store]);
}

test "an empty pit, an opponent's pit, and a store are all illegal picks" {
    var s = fresh();
    s.cells[0] = 0;
    try testing.expectEqual(@as(?State, null), apply(s, 0)); // empty
    try testing.expectEqual(@as(?State, null), apply(s, 7)); // O's pit, X to move
    try testing.expectEqual(@as(?State, null), apply(s, x_store)); // a store
    try testing.expectEqual(@as(?State, null), apply(s, 14)); // off the board
}

test "emptying a side ends the game and the other side sweeps its stones" {
    var s = fresh();
    for (0..pits) |i| s.cells[i] = 0;
    s.cells[5] = 1; // X's last stone, landing in the store → free turn, but empty
    s.cells[12] = 7; // O's remaining stones get swept
    s.cells[x_store] = 20;
    const ns = apply(s, 5).?;
    try testing.expectEqual(@as(u8, 21), ns.cells[x_store]);
    try testing.expectEqual(@as(u8, 7), ns.cells[o_store]); // swept
    try testing.expectEqual(Outcome.x_wins, ns.outcome);
}

test "equal stores at the end is a draw" {
    var s = fresh();
    for (0..pits) |i| s.cells[i] = 0;
    s.cells[5] = 1;
    s.cells[x_store] = 23;
    s.cells[o_store] = 24;
    const ns = apply(s, 5).?;
    try testing.expectEqual(Outcome.draw, ns.outcome);
}
