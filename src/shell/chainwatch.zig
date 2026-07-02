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

//! B1 classification: SHELL (network). The confirmation-watcher's fetch
//! legs (ZAT_CHAT_ROADMAP PART II §4, slice A5): ask a chain source how
//! the network sees (address, amount), hand the bytes to the pure core
//! for the verdict. The DEEP-MODULE boundary (D2/D3): callers see
//! `tipHeight` and `observe` — nothing explorer-shaped leaks out; a chain
//! source failure is an error the caller skips (E2/E4: a stale card,
//! never a broken thread).
//!
//! CHAIN SOURCE — the recorded hybrid (§4): the default is a PUBLIC
//! esplora-compatible API. F1 justification, recorded here at the site:
//! we do not run global chain infrastructure, and requiring every user to
//! run a node would gate the feature on sysadmin skill; the honest cost —
//! the operator of the source learns "this client watches this address" —
//! is disclosed (§6) and avoidable: `ZAT_CHAIN_API` points the watcher at
//! the user's OWN esplora-compatible endpoint (their node's, e.g. a
//! self-hosted mempool/esplora), and then no third party is consulted.
//! (A native Electrum/bitcoind-RPC source is the recorded follow-up.)
//!
//! SSRF posture: the default host is ours-chosen and public → the
//! untrusted guard stays on. An operator override is THEIR configuration
//! (often a LAN address, exactly the thing the guard blocks) → trusted,
//! the same posture as every operator-configured endpoint (http.zig).

const std = @import("std");
const Allocator = std.mem.Allocator;
const http = @import("http.zig");
const chainwatch = @import("../core/chainwatch.zig");

pub const default_api = "https://mempool.space";

/// An address-txs page is bounded (the newest ~50 transactions), but embeds
/// can be fat; half a MiB is generous headroom over a real page.
const max_chain_bytes: usize = 512 * 1024;

/// The configured chain source + the guard its origin earns.
/// A7.2: cold struct, size guard waived — one per poll cycle.
pub const Source = struct {
    base: []const u8,
    guard: http.Guard,
};

pub fn source(environ: ?*const std.process.Environ.Map) Source {
    if (environ) |env| {
        if (env.get("ZAT_CHAIN_API")) |base| {
            if (base.len > 0)
                return .{ .base = base, .guard = .trusted }; // operator's own endpoint
        }
    }
    return .{ .base = default_api, .guard = .untrusted };
}

pub const FetchError = error{ SourceDown, Malformed, OutOfMemory };

/// The current tip height.
pub fn tipHeight(
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    src: Source,
) FetchError!u32 {
    var url_buf: [512]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "{s}/api/blocks/tip/height", .{src.base}) catch
        return error.Malformed;
    const resp = http.request(arena, io, environ, url, .{
        .guard = src.guard,
        .max_response_bytes = 256,
    }) catch return error.SourceDown;
    if (resp.status != 200) return error.SourceDown;
    return chainwatch.parseTipHeight(resp.body) catch error.Malformed;
}

/// How the network sees (address, amount) right now — the pure core's
/// conservative verdict over the source's newest transactions page.
pub fn observe(
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    src: Source,
    address: []const u8,
    amount_sat: u64,
) FetchError!chainwatch.Observation {
    var url_buf: [512]u8 = undefined;
    const url = std.fmt.bufPrint(&url_buf, "{s}/api/address/{s}/txs", .{ src.base, address }) catch
        return error.Malformed;
    const resp = http.request(arena, io, environ, url, .{
        .guard = src.guard,
        .max_response_bytes = max_chain_bytes,
    }) catch return error.SourceDown;
    if (resp.status != 200) return error.SourceDown;
    return chainwatch.matchAddressTxs(arena, resp.body, address, amount_sat) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => error.Malformed,
    };
}

// ---------------------------------------------------------------------------
// Tests (C6) — the source selection is pure decision; the network legs are
// typed through the exe build and live-proven by the --watch-address
// harness (main.zig).
// ---------------------------------------------------------------------------

const testing = std.testing;

test "source: default is the public API guarded; an override is trusted" {
    const gpa = testing.allocator;
    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();

    const def = source(&env);
    try testing.expectEqualStrings(default_api, def.base);
    try testing.expectEqual(http.Guard.untrusted, def.guard);

    try env.put("ZAT_CHAIN_API", "http://192.168.1.50:3006");
    const own = source(&env);
    try testing.expectEqualStrings("http://192.168.1.50:3006", own.base);
    try testing.expectEqual(http.Guard.trusted, own.guard);

    try testing.expectEqual(http.Guard.untrusted, source(null).guard);
}
