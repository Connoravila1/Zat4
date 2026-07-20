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

//! B1 classification: SHELL — the Constellation Gate process entry: argv, env,
//! secrets, then the serve loop. `CONSTELLATION_GATE_DESIGN.md` §9.
//!
//!   zat4-gate                 serve on 127.0.0.1:2590 until killed
//!   zat4-gate --port 9999     pick the port
//!
//! Secrets come from the environment, never from argv (argv is world-readable
//! via /proc on a shared box):
//!   ZAT_GATE_TICKET_KEY   64 hex chars — the ticket-signing HMAC key
//!   ZAT_GATE_SALT         64 hex chars — the coordination-token salt
//!
//! ⚠️ These two have OPPOSITE rotation properties (§9.8) and are deliberately
//! separate variables rather than one blob:
//!   • TICKET_KEY is freely rotatable — losing it invalidates only in-flight
//!     tickets, so at worst a handful of enrollments retry.
//!   • SALT must NOT be rotated casually — every stored coordination token is
//!     keyed to it, so rotating invalidates the entire store and grants a full
//!     amnesty to every cluster the gate has ever observed.
//! Combining them into one secret would make the cheap rotation impossible
//! without paying the expensive one.
//!
//! Both are REQUIRED. There is no generate-a-random-one-on-startup fallback,
//! and that omission is deliberate: an ephemeral salt would silently produce a
//! gate whose store resets every restart — it would look like it was working
//! while learning nothing, which is worse than refusing to start.

const std = @import("std");
const gate = @import("shell/gate_serve.zig");
const pow_issue = @import("core/pow_issue.zig");
const constellation = @import("core/constellation.zig");
const gate_store = @import("shell/gate_store.zig");

/// Replay-guard capacity: how many SOLVED tickets can be in flight inside one
/// TTL. Sized generously because the set is naturally small — an entry only
/// exists for work an attacker actually paid for (`pow_issue.checkAndSpend`),
/// so it is bounded by honest enrollment rate × TTL, not by request rate.
/// 4096 × 16 bytes = 64 KiB.
const spent_capacity = 4096;

/// Shadow-store capacity, in tokens (≈ 6 per enrollment). 65536 × 16 bytes =
/// 1 MiB, so roughly 10,000 observed enrollments before it fills and starts
/// counting drops. This bounds the in-memory INDEX, not the durable log — the
/// log keeps everything; this is how much of it the scorer can hold at once.
/// A replay that overflows it is reported at startup rather than silently
/// truncating the gate's view of history.
const token_capacity = 65536;

const default_port: u16 = 2590;

/// Where the durable log lives if `ZAT_GATE_STORE` does not say otherwise.
const default_store_path = "/var/lib/zat4-gate/enrollments.log";

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const env = init.environ_map;

    var out_buf: [1024]u8 = undefined;
    var out_writer: std.Io.File.Writer = .init(.stdout(), io, &out_buf);
    const out = &out_writer.interface;

    var arena_state = std.heap.ArenaAllocator.init(gpa); // C3: argv lives here
    defer arena_state.deinit();

    var port: u16 = default_port;
    const args = try init.minimal.args.toSlice(arena_state.allocator());
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--port") and i + 1 < args.len) {
            i += 1;
            port = std.fmt.parseInt(u16, args[i], 10) catch default_port;
        }
    }

    const ticket_key = try requiredSecret(env, out, "ZAT_GATE_TICKET_KEY");
    const salt = try requiredSecret(env, out, "ZAT_GATE_SALT");

    const spent = try gpa.alloc(pow_issue.SpentEntry, spent_capacity);
    defer gpa.free(spent);
    @memset(spent, .{ .tag = 0, .expires_at = 0 });

    const tokens = try gpa.alloc(constellation.Token, token_capacity);
    defer gpa.free(tokens);

    // ── The durable store (§9.10 step 2) ──
    // Shadow mode exists to accumulate calibration data; an in-memory store
    // would lose all of it on every restart while still looking like a working
    // gate. Path from ZAT_GATE_STORE, defaulting to a sensible box location.
    const store_path = env.get("ZAT_GATE_STORE") orelse default_store_path;

    var store = gate_store.open(store_path);
    defer gate_store.close(&store);

    const rp = gate_store.replay(gpa, store_path, tokens);

    const rate = try gpa.alloc(gate.RateSlot, gate.rate_slot_count);
    defer gpa.free(rate);
    @memset(rate, .{ .key = 0, .bucket = .{ .tokens = 0, .capacity = 0, .refill_per_sec = 0, .last = 0 } });

    var state: gate.GateState = .{
        .rate = rate,
        .spent = spent,
        .tokens = tokens,
        .token_len = rp.len,
        .store = store,
    };

    // Report what the replay found, including what it SHED. A store quietly
    // dropping records must show up as a number at startup rather than as an
    // unexplained gap in the calibration data months later.
    try out.print(
        "zat4-gate: store {s} — {d} enrollments replayed, {d} tokens indexed\n",
        .{ if (gate_store.enabled(store)) store_path else "(DISABLED — running in memory)", rp.result.applied, rp.len },
    );
    if (rp.result.corrupt > 0 or rp.result.trailing_bytes > 0 or rp.result.dropped_full > 0) {
        try out.print(
            "zat4-gate: ⚠ replay shed data — {d} corrupt, {d} trailing bytes, {d} dropped (index full)\n",
            .{ rp.result.corrupt, rp.result.trailing_bytes, rp.result.dropped_full },
        );
    }
    if (!gate_store.enabled(store)) {
        try out.print(
            "zat4-gate: ⚠ NOTHING WILL BE PERSISTED. Observations die with this process.\n",
            .{},
        );
    }
    const cfg: gate.ServeConfig = .{
        .port = port,
        .ticket_key = ticket_key,
        .salt = salt,
    };

    try out.print(
        \\zat4-gate: serving on http://127.0.0.1:{d}/gate/  (ctrl-c to stop)
        \\  GET  /gate/challenge          -> a PoW ticket
        \\  POST /gate/redeem?t=..&n=..   -> ticket + solved nonce
        \\  MODE: SHADOW — assessments are logged, never charged.
        \\
    , .{port});
    try out.flush();

    try gate.run(gpa, io, cfg, &state);
}

/// Read a required 32-byte secret from the environment as 64 hex characters.
///
/// Fails CLOSED with a specific message naming the variable. A gate that starts
/// without its secrets is worse than one that refuses to: it would serve
/// happily while either issuing forgeable tickets or accumulating a store that
/// resets on every restart.
fn requiredSecret(
    env: ?*const std.process.Environ.Map,
    out: *std.Io.Writer,
    name: []const u8,
) ![32]u8 {
    const hex = if (env) |e| e.get(name) else null;
    if (hex == null or hex.?.len != 64) {
        try out.print(
            \\zat4-gate: {s} must be set to 64 hex characters (32 bytes).
            \\  Generate one with:  head -c32 /dev/urandom | xxd -p -c32
            \\  NOTE: ZAT_GATE_TICKET_KEY may be rotated freely; ZAT_GATE_SALT
            \\  must NOT be — rotating it invalidates every stored coordination
            \\  token and grants a full amnesty to every observed cluster.
            \\
        , .{name});
        try out.flush();
        return error.MissingSecret;
    }

    var bytes: [32]u8 = undefined;
    for (&bytes, 0..) |*b, i| {
        const hi = hexValue(hex.?[i * 2]) orelse return error.BadSecret;
        const lo = hexValue(hex.?[i * 2 + 1]) orelse return error.BadSecret;
        b.* = (hi << 4) | lo;
    }
    return bytes;
}

fn hexValue(c: u8) ?u8 {
    return switch (c) {
        '0'...'9' => c - '0',
        'a'...'f' => c - 'a' + 10,
        'A'...'F' => c - 'A' + 10,
        else => null,
    };
}
