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

//! B1 classification: SHELL (network + memory-hard CPU). The **client half of
//! the Constellation Gate** — fetch a challenge, do the work, redeem it for the
//! invite code that `createAccount` needs.
//!
//! This replaces reading `ZAT_INVITE_CODE` from the environment. That env var
//! was a hand-distributed bootstrap credential; this is the real path, where a
//! code is earned per-signup and the server observes the enrollment while
//! issuing it.
//!
//! ── MUST run off the UI thread ──
//! `exchange` does two network round-trips AND a memory-hard solve that takes
//! ~2 s on a fast phone and ~7 s on a slow one. Calling it from the render
//! thread would freeze the app for that whole time. It takes a `cancel` flag and
//! is designed to be driven from a worker (see `enroll_run.PowJob`), per the
//! standing law that network and PoW never touch the render thread.
//!
//! ── What it does NOT do ──
//! It does not create the account. It returns an invite code; the caller passes
//! that to `auth.createAccount`. Keeping those separate means a failure to
//! enroll and a failure to *create* stay distinguishable, which matters because
//! the second one wastes a code (§9.5: the gate cannot revoke).
//!
//! Interface, in full: `Outcome`, `Failure`, `exchange`, `default_gate_url`,
//! `gate_url_env`.

const std = @import("std");
const Allocator = std.mem.Allocator;

const pow = @import("../core/pow.zig");
const wire = @import("../core/gate_wire.zig");
const pow_issue = @import("../core/pow_issue.zig");
const pow_shell = @import("pow.zig");
const http = @import("http.zig");

/// Where the gate lives. Caddy fronts it at this path; the service itself binds
/// loopback only (Gate §9.2).
pub const default_gate_url = "https://pds.zat4.com/gate";
pub const gate_url_env = "ZAT_GATE_URL";

/// Why an exchange did not produce a code.
///
/// Distinguished rather than collapsed, because the right RESPONSE differs and
/// two of these are not the user's fault:
///   • `unreachable_gate` / `bad_response` — infrastructure; retry later.
///   • `no_invite_available` — the pool is dry. The user did the work and there
///     is nothing to give them; they must come back, and someone must refill.
///   • `refused` — the gate rejected the submission (see the wire code).
///   • `canceled` — the user backed out mid-solve; not an error at all.
pub const Failure = enum {
    unreachable_gate,
    bad_response,
    no_invite_available,
    refused,
    canceled,
};

/// A7.2: cold — one per signup attempt, returned once and consumed. Size guard
/// waived; it carries a slice and its size is not a hot-path concern.
pub const Outcome = union(enum) {
    /// The invite code, owned by the caller's allocator.
    ok: []const u8,
    /// Failed, with the gate's wire code when it gave one (`refusal` is empty
    /// otherwise). `refusal` is owned by the caller's allocator.
    failed: struct { why: Failure, refusal: []const u8 = "" },
};

/// The challenge as the gate advertises it. A fixed, small shape — parsed with
/// `std.json` because this is OUR server over TLS, unlike the gate's own
/// hostile-input path which deliberately has no parser at all.
/// A7.2: cold — one per signup attempt, parsed from a 4 KiB response and
/// discarded. Size guard waived.
const Challenge = struct {
    ticket: []const u8,
    mem_kib: u32,
    iters: u32,
    lanes: u8,
    zero_bits: u8,
    ttl: i64,
};

/// A7.2: cold — one per signup attempt. Size guard waived.
const Redeemed = struct {
    ok: bool = false,
    mode: []const u8 = "",
    inviteCode: []const u8 = "",
};

/// A7.2: cold — one per failed request. Size guard waived.
const Refused = struct {
    @"error": []const u8 = "",
};

/// SHELL (B3): run the whole exchange and return an invite code.
///
/// `cancel` is checked before each network call and threaded into the solver,
/// which checks it every attempt — so backing out of signup stops the work
/// promptly instead of burning a phone's battery to completion.
///
/// On success the returned code is owned by `gpa`. On failure any refusal
/// string is owned by `gpa`.
pub fn exchange(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    gate_url: []const u8,
    cancel: *const std.atomic.Value(bool),
) Outcome {
    var arena_state = std.heap.ArenaAllocator.init(gpa); // C3: per-exchange
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    if (cancel.load(.acquire)) return .{ .failed = .{ .why = .canceled } };

    // ── 1. Ask for a challenge ──
    const challenge_url = std.fmt.allocPrint(arena, "{s}/challenge", .{gate_url}) catch
        return .{ .failed = .{ .why = .bad_response } };

    const ch_res = http.request(arena, io, environ, challenge_url, .{
        .method = .GET,
        .accept = "application/json",
        .max_response_bytes = 4096,
    }) catch return .{ .failed = .{ .why = .unreachable_gate } };

    if (ch_res.status != 200) {
        return .{ .failed = .{
            .why = if (ch_res.status == 429) .refused else .unreachable_gate,
            .refusal = refusalOf(gpa, arena, ch_res.body),
        } };
    }

    const parsed = std.json.parseFromSlice(Challenge, arena, ch_res.body, .{
        .ignore_unknown_fields = true,
    }) catch return .{ .failed = .{ .why = .bad_response } };
    const ch = parsed.value;

    // The ticket is a fixed-length hex blob; anything else means we are not
    // talking to a gate we understand, and solving against it would waste the
    // user's battery for nothing.
    if (ch.ticket.len != wire.ticket_wire_len) return .{ .failed = .{ .why = .bad_response } };
    if (ch.zero_bits == 0 or ch.mem_kib == 0 or ch.iters == 0 or ch.lanes == 0) {
        return .{ .failed = .{ .why = .bad_response } };
    }

    const ticket = wire.decodeTicket(ch.ticket) orelse
        return .{ .failed = .{ .why = .bad_response } };

    // ── 2. Do the work ──
    // The difficulty is SERVER-SUPPLIED, which is the entire point of the
    // server-issued design — but it is validated first, because a malicious or
    // broken response could otherwise ask the device for something that will
    // never finish or that exhausts its memory. `pow.validate` rejects params
    // Argon2 itself would refuse; the ceiling below is ours.
    const difficulty: pow.Difficulty = .{
        .mem_kib = ch.mem_kib,
        .iters = ch.iters,
        .lanes = ch.lanes,
        .leading_zero_bits = ch.zero_bits,
    };
    pow.validate(difficulty) catch return .{ .failed = .{ .why = .bad_response } };
    if (ch.mem_kib > max_accepted_mem_kib or ch.zero_bits > max_accepted_zero_bits) {
        return .{ .failed = .{ .why = .bad_response } };
    }

    if (cancel.load(.acquire)) return .{ .failed = .{ .why = .canceled } };

    // Argon2's buffers come from the page allocator: this runs on a worker, and
    // the render allocator is single-threaded (same posture as `powWorker`).
    const solver = std.heap.page_allocator;
    const challenge = pow.challengeFor(ticket.seed, ticket.tier);
    const solution = pow_shell.solve(solver, io, challenge, difficulty, cancel) catch {
        return .{ .failed = .{ .why = if (cancel.load(.acquire)) .canceled else .bad_response } };
    };

    if (cancel.load(.acquire)) return .{ .failed = .{ .why = .canceled } };

    // ── 3. Redeem ──
    var nonce_buf: [wire.nonce_wire_max]u8 = undefined;
    const nonce_text = wire.encodeNonce(&nonce_buf, solution.nonce);
    const redeem_url = std.fmt.allocPrint(
        arena,
        "{s}/redeem?t={s}&n={s}",
        .{ gate_url, ch.ticket, nonce_text },
    ) catch return .{ .failed = .{ .why = .bad_response } };

    const rd_res = http.request(arena, io, environ, redeem_url, .{
        .method = .POST,
        .accept = "application/json",
        .max_response_bytes = 4096,
    }) catch return .{ .failed = .{ .why = .unreachable_gate } };

    if (rd_res.status == 503) {
        // The pool is dry: the user did the work and there is nothing to give
        // them. Its own case so the UI can say "come back shortly" rather than
        // implying they failed something.
        return .{ .failed = .{
            .why = .no_invite_available,
            .refusal = refusalOf(gpa, arena, rd_res.body),
        } };
    }
    if (rd_res.status != 200) {
        return .{ .failed = .{ .why = .refused, .refusal = refusalOf(gpa, arena, rd_res.body) } };
    }

    const done = std.json.parseFromSlice(Redeemed, arena, rd_res.body, .{
        .ignore_unknown_fields = true,
    }) catch return .{ .failed = .{ .why = .bad_response } };

    if (!done.value.ok or done.value.inviteCode.len == 0) {
        return .{ .failed = .{ .why = .bad_response } };
    }

    const owned = gpa.dupe(u8, done.value.inviteCode) catch
        return .{ .failed = .{ .why = .bad_response } };
    return .{ .ok = owned };
}

/// Client-side ceilings on a server-supplied difficulty.
///
/// The server issues the difficulty, which is what makes the tax enforceable —
/// but the client must not be a machine that will do literally anything it is
/// told. 128 MiB is past any calibrated value and would OOM a modest phone;
/// 2^24 attempts would run for days. These are not tuning knobs, they are the
/// line past which we assume the response is wrong rather than demanding.
const max_accepted_mem_kib: u32 = 128 * 1024;
const max_accepted_zero_bits: u8 = 24;

/// Pull the gate's `{"error":"Code"}` out of a body, duped into `gpa`. Returns
/// an empty string if the body is not that shape — a missing explanation must
/// never turn into a failure to report the failure.
fn refusalOf(gpa: Allocator, arena: Allocator, body: []const u8) []const u8 {
    const parsed = std.json.parseFromSlice(Refused, arena, body, .{
        .ignore_unknown_fields = true,
    }) catch return "";
    if (parsed.value.@"error".len == 0) return "";
    return gpa.dupe(u8, parsed.value.@"error") catch "";
}

// ── Tests ──
// The network path is exercised by running the client against a live gate
// (see the drive scripts); these pin the decision logic that would otherwise
// only fail in front of a user.

test "a server-supplied difficulty is bounded before any work is done" {
    // A client that solves whatever it is told can be handed a request that
    // never finishes or that OOMs the device.
    try std.testing.expect(max_accepted_mem_kib >= 64 * 1024); // room for calibrated values
    try std.testing.expect(max_accepted_mem_kib <= 256 * 1024); // but not unbounded
    try std.testing.expect(max_accepted_zero_bits >= 8);
    try std.testing.expect(max_accepted_zero_bits <= 32);

    // The calibrated production difficulty must sit inside those bounds, or the
    // client would refuse the very challenge the gate issues.
    const heavy = pow.difficultyFor(.heavy).?;
    try std.testing.expect(heavy.mem_kib <= max_accepted_mem_kib);
    try std.testing.expect(heavy.leading_zero_bits <= max_accepted_zero_bits);
    try std.testing.expectEqual({}, try pow.validate(heavy));
}

test "the advertised ticket length matches what the wire format expects" {
    // If these drifted the client would reject every real challenge, which is
    // a total signup outage that no unit test would otherwise catch.
    const t = pow_issue.issue([_]u8{7} ** 32, [_]u8{9} ** 32, 1_767_323_045, .heavy);
    const hex = wire.encodeTicket(t);
    try std.testing.expectEqual(wire.ticket_wire_len, hex.len);
    try std.testing.expect(wire.decodeTicket(&hex) != null);
}

test "every failure mode is distinct" {
    // Collapsing these would leave the UI unable to tell "our pool is empty"
    // (not your fault, come back) from "you were refused" (something is wrong).
    const all = [_]Failure{ .unreachable_gate, .bad_response, .no_invite_available, .refused, .canceled };
    for (all, 0..) |a, i| {
        for (all[i + 1 ..]) |b| try std.testing.expect(a != b);
    }
}
