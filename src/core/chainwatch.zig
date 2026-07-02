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

//! B1 classification: CORE (pure). The confirmation-watcher's decisions
//! (ZAT_CHAT_ROADMAP PART II §4, slice A5): what a chain source's answer
//! MEANS for a payment card. The shell (`shell/chainwatch.zig`) fetches;
//! this module parses the untrusted bytes and decides — same input, same
//! verdict (B2), and nothing explorer-shaped leaks past it (D3: the shell
//! hands bytes in, plain observations come out).
//!
//! The watcher watches an ADDRESS + EXPECTED AMOUNT, not a txid — the A3
//! honesty amendment: wallet URIs return nothing, so the txid usually
//! isn't ours to know; the address and amount always are (both sides hold
//! them from the card + the A2 record).
//!
//! THE CONSERVATIVE RULE, recorded: a static address (A2 v1) can carry
//! several exact-amount matches — an old settled 5k payment must never
//! vouch for a new 5k card. Among matching transactions we report the
//! SHALLOWEST (a mempool match beats any confirmed one; the newest block
//! beats an older one). Understating is a late card; overstating would be
//! a false receipt (§6 — we never assert settlement the network didn't
//! give for THIS payment). The store's monotonic `setConfirmations`
//! absorbs any later regression a newer unrelated match would suggest.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

pub const ParseError = error{ Malformed, OutOfMemory };

/// What the chain says about (address, amount): nothing yet, a matching
/// transaction in the mempool, or a matching transaction confirmed at a
/// block height. A7.2: cold union, size guard waived — transient result.
pub const Observation = union(enum) {
    none,
    mempool,
    confirmed: u32,
};

/// `GET /api/blocks/tip/height` — the answer is a bare decimal number.
pub fn parseTipHeight(bytes: []const u8) ParseError!u32 {
    const trimmed = std.mem.trim(u8, bytes, " \t\r\n");
    if (trimmed.len == 0 or trimmed.len > 10) return error.Malformed;
    return std.fmt.parseInt(u32, trimmed, 10) catch error.Malformed;
}

// The esplora-style address-transactions page: the fields we read. Absent
// fields default inert and the match below just fails (E4) — a hostile
// blob can hide a payment (it always could), never invent one with the
// wrong shape.
/// A7.2: cold struct, size guard waived — transient parse target.
const Vout = struct {
    scriptpubkey_address: []const u8 = "",
    value: u64 = 0,
};
/// A7.2: cold struct, size guard waived — transient parse target.
const TxStatus = struct {
    confirmed: bool = false,
    block_height: u32 = 0,
};
/// A7.2: cold struct, size guard waived — transient parse target.
const Tx = struct {
    status: TxStatus = .{},
    vout: []Vout = &.{},
};

/// `GET /api/address/<addr>/txs` (the newest ~50, mempool first): find the
/// transactions paying EXACTLY `amount_sat` to `address` and report the
/// shallowest (module-header rule). Unknown JSON fields are ignored; a
/// blob that isn't the expected shape at all is `Malformed` (E3).
pub fn matchAddressTxs(
    arena: Allocator,
    bytes: []const u8,
    address: []const u8,
    amount_sat: u64,
) ParseError!Observation {
    const txs = std.json.parseFromSliceLeaky([]Tx, arena, bytes, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Malformed,
    };
    var best: Observation = .none;
    for (txs) |tx| {
        var pays = false;
        for (tx.vout) |v| {
            if (v.value == amount_sat and std.mem.eql(u8, v.scriptpubkey_address, address)) {
                pays = true;
                break;
            }
        }
        if (!pays) continue;
        if (!tx.status.confirmed) return .mempool; // shallowest possible: done
        const h = tx.status.block_height;
        if (h == 0) return .mempool; // confirmed without a height: treat as shallow
        best = switch (best) {
            .none => .{ .confirmed = h },
            .confirmed => |old| .{ .confirmed = @max(old, h) }, // newest block = shallowest
            .mempool => unreachable,
        };
    }
    return best;
}

/// Observation + tip → the card's depth: null = not seen, 0 = mempool
/// (the store maps it to `broadcast`), n ≥ 1 = confirmations (saturating —
/// past `settle_depth` the exact number stops mattering).
pub fn depthOf(obs: Observation, tip: u32) ?u8 {
    return switch (obs) {
        .none => null,
        .mempool => 0,
        .confirmed => |h| blk: {
            if (tip < h) break :blk 1; // a lagging tip never zeroes a confirmed tx
            const d = @as(u64, tip) - h + 1;
            break :blk if (d > 255) 255 else @intCast(d);
        },
    };
}

// ---------------------------------------------------------------------------
// Tests (B2, C6)
// ---------------------------------------------------------------------------

const testing = std.testing;

test "parseTipHeight: bare number, trimmed; junk refused" {
    try testing.expectEqual(@as(u32, 905_121), try parseTipHeight("905121\n"));
    try testing.expectError(error.Malformed, parseTipHeight(""));
    try testing.expectError(error.Malformed, parseTipHeight("not-a-number"));
    try testing.expectError(error.Malformed, parseTipHeight("99999999999"));
}

const addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

fn obsOf(arena: Allocator, json: []const u8, amount: u64) !Observation {
    return matchAddressTxs(arena, json, addr, amount);
}

test "matchAddressTxs: exact match confirmed, wrong amount and wrong address ignored" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const json =
        \\[{"txid":"aa","status":{"confirmed":true,"block_height":900000,"block_time":1},
        \\  "vout":[{"scriptpubkey_address":"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4","value":5000},
        \\          {"scriptpubkey_address":"bc1qother","value":123}]},
        \\ {"txid":"bb","status":{"confirmed":true,"block_height":899000},
        \\  "vout":[{"scriptpubkey_address":"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4","value":7777}]}]
    ;
    try testing.expectEqual(Observation{ .confirmed = 900_000 }, try obsOf(arena, json, 5000));
    // 7777 pays the address but not OUR amount at 5000; 123 pays another address.
    try testing.expectEqual(Observation.none, try obsOf(arena, json, 9999));
    try testing.expectEqual(Observation{ .confirmed = 899_000 }, try obsOf(arena, json, 7777));
}

test "matchAddressTxs: the conservative rule — shallowest match wins" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // An OLD settled 5k payment and a NEW unconfirmed 5k payment: the card
    // must read mempool, never inherit the old receipt.
    const json =
        \\[{"status":{"confirmed":false},
        \\  "vout":[{"scriptpubkey_address":"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4","value":5000}]},
        \\ {"status":{"confirmed":true,"block_height":890000},
        \\  "vout":[{"scriptpubkey_address":"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4","value":5000}]}]
    ;
    try testing.expectEqual(Observation.mempool, try obsOf(arena, json, 5000));

    // Two confirmed matches: the newest block (shallowest depth) wins.
    const json2 =
        \\[{"status":{"confirmed":true,"block_height":880000},
        \\  "vout":[{"scriptpubkey_address":"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4","value":5000}]},
        \\ {"status":{"confirmed":true,"block_height":901000},
        \\  "vout":[{"scriptpubkey_address":"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4","value":5000}]}]
    ;
    try testing.expectEqual(Observation{ .confirmed = 901_000 }, try obsOf(arena, json2, 5000));
}

test "matchAddressTxs: empty page, absent fields, and junk" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectEqual(Observation.none, try obsOf(arena, "[]", 5000));
    // Confirmed with no height reads shallow, never deep.
    const no_height =
        \\[{"status":{"confirmed":true},
        \\  "vout":[{"scriptpubkey_address":"bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4","value":5000}]}]
    ;
    try testing.expectEqual(Observation.mempool, try obsOf(arena, no_height, 5000));
    try testing.expectError(error.Malformed, obsOf(arena, "{\"not\":\"a list\"}", 5000));
    try testing.expectError(error.Malformed, obsOf(arena, "garbage", 5000));
}

test "depthOf: none/mempool/confirmed against the tip, saturating" {
    try testing.expectEqual(@as(?u8, null), depthOf(.none, 900_000));
    try testing.expectEqual(@as(?u8, 0), depthOf(.mempool, 900_000));
    try testing.expectEqual(@as(?u8, 1), depthOf(.{ .confirmed = 900_000 }, 900_000));
    try testing.expectEqual(@as(?u8, 6), depthOf(.{ .confirmed = 899_995 }, 900_000));
    try testing.expectEqual(@as(?u8, 255), depthOf(.{ .confirmed = 1 }, 900_000)); // genesis-deep saturates
    try testing.expectEqual(@as(?u8, 1), depthOf(.{ .confirmed = 900_001 }, 900_000)); // lagging tip
}
