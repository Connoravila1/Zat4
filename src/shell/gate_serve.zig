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

//! B1 classification: SHELL (all the I/O). The **Constellation Gate service** —
//! the enrollment trust boundary. Specced in `CONSTELLATION_GATE_DESIGN.md` §9.
//!
//! Two endpoints, and the whole security story lives between them:
//!
//!   GET  /gate/challenge          → a stateless PoW ticket (hex)
//!   POST /gate/redeem?t=..&n=..   → ticket + solved nonce → pass or refusal
//!
//! ── SHADOW MODE (§9.10 step 2) ──
//! This service currently OBSERVES and never charges. It derives coordination
//! tokens, scores them, and logs the assessment — then admits the enrollment
//! regardless of the result. That is deliberate and is the safe way to start:
//! it begins the calibration clock (every `[CALIBRATE]` number in the Gate spec
//! is empirical) while being structurally incapable of harming an honest user.
//! Nothing here can price anyone until a deposit spine exists AND someone
//! deliberately flips it from observed to enforced.
//!
//! ── Where the invite code is NOT ──
//! Handing out a real invite code is the next slice. The gate holds no PDS
//! admin credential by design (§9.5, the pool model) — a compromised gate must
//! not be able to mint accounts, and it holds no session token, no password and
//! no OAuth material either, so it cannot impersonate anyone. Keeping that true
//! is worth more than the convenience of self-minting.
//!
//! ── The concurrency cap, for free (§9.7) ──
//! The accept loop is SEQUENTIAL: accept → handle → close. So exactly one
//! memory-hard verification runs at a time, which is the hard cap §9.7 requires
//! against memory exhaustion (64 MiB × 32 concurrent = 2 GB would OOM the box).
//! If this ever becomes threaded, that cap must be reintroduced EXPLICITLY as a
//! semaphore — the protection is currently a property of the loop's shape, and
//! that is exactly the kind of invariant that gets lost in a refactor.

const std = @import("std");
const Allocator = std.mem.Allocator;

const pow = @import("../core/pow.zig");
const pow_issue = @import("../core/pow_issue.zig");
const wire = @import("../core/gate_wire.zig");
const constellation = @import("../core/constellation.zig");
const pow_shell = @import("pow.zig");
const clock = @import("clock.zig");

/// Service configuration.
///
/// A7.2: cold struct — one instance, set once at startup, never in a hot loop.
pub const ServeConfig = struct {
    /// Loopback port. The gate NEVER binds a public interface: Caddy fronts it
    /// and terminates TLS (§9.2). That is also what makes trusting
    /// `X-Forwarded-For` sound — see `observedIp`.
    port: u16,
    /// The ticket-signing key (§9.8). Freely rotatable: rotating invalidates
    /// only in-flight tickets, so at worst a few enrollments retry.
    ticket_key: pow_issue.Key,
    /// The token-keying salt (§9.8). ⚠️ NOT freely rotatable — rotating
    /// invalidates every stored token and grants a full amnesty to every
    /// existing cluster. Held separately from `ticket_key` on purpose: their
    /// rotation properties are opposites and must not share a config path.
    salt: [32]u8,
    /// Which difficulty enrolment draws.
    tier: pow.Tier = .heavy,
    ttl_secs: i64 = pow_issue.default_ttl_secs,
    skew_secs: i64 = pow_issue.default_skew_secs,
};

/// Mutable service state, owned by the caller.
///
/// A7.2: cold struct — one instance for the process's lifetime.
pub const GateState = struct {
    /// The replay guard (`pow_issue.checkAndSpend`). Caller-sized: the shell
    /// knows the box, and the core must not allocate (C1/C2).
    spent: []pow_issue.SpentEntry,
    /// The shadow-mode coordination store. In-memory and bounded for this
    /// slice; the durable append-only log (the `appview_store.zig` pattern) is
    /// the next slice. When it fills, new tokens are DROPPED rather than
    /// evicted — see `record`.
    tokens: []constellation.Token,
    token_len: usize = 0,
    /// Count of enrollments whose tokens were dropped because the store was
    /// full. Surfaced so a silently-degraded gate is visible (§"no silent
    /// caps") rather than looking like a quiet, well-behaved one.
    dropped: u64 = 0,
};

/// SHELL (B3): bind loopback and serve until killed.
pub fn run(gpa: Allocator, io: std.Io, cfg: ServeConfig, state: *GateState) !void {
    var address: std.Io.net.IpAddress = .{ .ip4 = .loopback(cfg.port) };
    var server = try address.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);

    while (true) {
        // E2: a refused accept is the next loop's problem, not a crash. The
        // gate failing must never take down anything else — and conversely a
        // gate that dies stops signups, which is the correct fail-CLOSED
        // posture for a Sybil gate (§9.9): failing OPEN would let an attacker
        // DoS the gate in order to mint unobserved accounts.
        const stream = server.accept(io) catch continue;
        handleConn(gpa, io, cfg, state, stream) catch {}; // E2: contained
        stream.close(io);
    }
}

fn handleConn(
    gpa: Allocator,
    io: std.Io,
    cfg: ServeConfig,
    state: *GateState,
    stream: std.Io.net.Stream,
) !void {
    var read_buf: [8 * 1024]u8 = undefined;
    var write_buf: [8 * 1024]u8 = undefined;
    var stream_reader = stream.reader(io, &read_buf);
    var stream_writer = stream.writer(io, &write_buf);
    var http_server: std.http.Server = .init(&stream_reader.interface, &stream_writer.interface);

    var req = http_server.receiveHead() catch return;
    const target = req.head.target;
    const path = pathOf(target);

    // NOTE: no authorization gate here, and that is not an oversight. The
    // enrolling user has no account yet, so this endpoint is necessarily
    // public and unauthenticated (§9.7). Everything it parses is therefore
    // hostile input, which is why the wire format is fixed-size hex with no
    // body and no JSON parser (`core/gate_wire.zig`).

    if (std.mem.eql(u8, path, "/gate/challenge")) {
        return serveChallenge(io, cfg, &req);
    }
    if (std.mem.eql(u8, path, "/gate/redeem")) {
        return serveRedeem(gpa, io, cfg, state, &req, target);
    }
    respondJson(&req, .not_found, "{\"error\":\"NotFound\"}");
}

/// SHELL: issue a ticket. O(1), allocates nothing, and stores NOTHING —
/// statelessness is what stops an adversary exhausting memory by requesting
/// millions of challenges for free (§9.7).
fn serveChallenge(io: std.Io, cfg: ServeConfig, req: *std.http.Server.Request) !void {
    var seed: [32]u8 = undefined;
    io.randomSecure(&seed) catch {
        // Without real entropy a ticket would be predictable, which would let
        // work be precomputed. Refuse rather than emit a weak challenge.
        respondJson(req, .service_unavailable, "{\"error\":\"Unavailable\"}");
        return;
    };

    const ticket = pow_issue.issue(cfg.ticket_key, seed, clock.unixSeconds(), cfg.tier);
    const hex = wire.encodeTicket(ticket);
    const d = pow.difficultyFor(cfg.tier);

    // Fixed-size response, formatted into a stack buffer: nothing on this path
    // allocates, so nothing on it can be driven to allocate.
    var body: [512]u8 = undefined;
    const out = std.fmt.bufPrint(&body,
        "{{\"ticket\":\"{s}\",\"mem_kib\":{d},\"iters\":{d},\"lanes\":{d},\"zero_bits\":{d},\"ttl\":{d}}}",
        .{
            hex,
            if (d) |dd| dd.mem_kib else 0,
            if (d) |dd| dd.iters else 0,
            if (d) |dd| dd.lanes else 0,
            if (d) |dd| dd.leading_zero_bits else 0,
            cfg.ttl_secs,
        },
    ) catch return;

    respondJson(req, .ok, out);
}

/// SHELL: redeem a solved ticket.
///
/// Order is security-relevant and deliberate — CHEAPEST checks first, so the
/// expensive memory-hard verification only ever runs for input that already
/// proved it came from us:
///   1. decode          (bounded, no allocation)
///   2. authenticate    (one HMAC — rejects everything not ours)
///   3. verify the work (ONE argon2id — the only costly step)
///   4. spend           (replay guard)
/// Doing (3) before (2) would let an unauthenticated stranger burn 64 MiB of
/// server memory per request with no work of their own — inverting the whole
/// cost asymmetry the PoW exists to create.
fn serveRedeem(
    gpa: Allocator,
    io: std.Io,
    cfg: ServeConfig,
    state: *GateState,
    req: *std.http.Server.Request,
    target: []const u8,
) !void {
    const t_param = queryValue(target, "t") orelse return refuse(req, .malformed);
    const n_param = queryValue(target, "n") orelse return refuse(req, .malformed);

    // 1. Decode. Fixed length, fixed offsets, no allocation.
    const ticket = wire.decodeTicket(t_param) orelse return refuse(req, .malformed);
    const nonce = wire.decodeNonce(n_param) orelse return refuse(req, .malformed);

    // 2. Authenticate BEFORE doing any work.
    const now = clock.unixSeconds();
    switch (pow_issue.checkTicket(cfg.ticket_key, ticket, now, cfg.ttl_secs, cfg.skew_secs)) {
        .valid => {},
        .forged => return refuse(req, .forged),
        .expired => return refuse(req, .expired),
        .from_the_future => return refuse(req, .clock_skew),
    }

    // A `.none` tier demands no work, so it could never prove anything. Such a
    // ticket must not buy an enrollment.
    const difficulty = pow.difficultyFor(ticket.tier) orelse
        return refuse(req, .no_work_required);

    // 3. The one expensive step. Sequential accept loop ⇒ one at a time.
    const challenge = pow.challengeFor(ticket.seed, ticket.tier);
    const solved = pow_shell.verify(gpa, io, challenge, .{ .nonce = nonce }, difficulty) catch false;
    if (!solved) return refuse(req, .unsolved);

    // 4. Spend it. A stateless ticket is replayable by construction until this
    //    records it, so one solve would otherwise buy unlimited enrollments.
    const tag = pow_issue.spentTag(ticket);
    switch (pow_issue.checkAndSpend(state.spent, tag, now, ticket.issued_at + cfg.ttl_secs)) {
        .recorded => {},
        .replay => return refuse(req, .replayed),
        .full => return refuse(req, .at_capacity),
    }

    // ── Observe → derive → discard (§2) ──
    // The raw observation is a stack value that dies with this function; only
    // the derived tokens outlive it. That is the privacy doctrine made
    // structural rather than promised.
    const obs: constellation.Observation = .{
        .enrolled_at = now,
        .ip = observedIp(req) orelse .{0} ** 16,
        .pow_solve_ms = solveMillis(ticket.issued_at, now),
        .pow_tier = @intFromEnum(ticket.tier),
        .graph_shape = 0, // always absent at enrollment; accrues over weeks
        .ip_class = .unknown, // datacenter-range classification: next slice
        .platform = constellation.classifyPlatform(headerValue(req, "user-agent") orelse ""),
    };
    const derived = constellation.derive(obs, cfg.salt);
    const factor = constellation.assess(derived, state.tokens[0..state.token_len]);

    // SHADOW MODE: log the assessment, admit regardless.
    std.debug.print(
        "[gate] enroll observed: signals={d} factor_x100={d} store={d} dropped={d}\n",
        .{ derived.len, factor, state.token_len, state.dropped },
    );

    record(state, derived);

    respondJson(req, .ok, "{\"ok\":true,\"mode\":\"shadow\"}");
}

/// Append a derivation to the shadow store.
///
/// On a full store the tokens are DROPPED and counted, never evicted. Evicting
/// would silently rewrite history — an old cluster would dissolve as new
/// enrollments pushed its tokens out, and the gate would report innocence it
/// had not established. A dropped-count that climbs is a visible, actionable
/// capacity signal; a quietly shrinking store is a lie.
fn record(state: *GateState, derived: constellation.Derived) void {
    if (state.token_len + derived.len > state.tokens.len) {
        state.dropped +|= 1;
        return;
    }
    for (derived.tokens[0..derived.len]) |t| {
        state.tokens[state.token_len] = t;
        state.token_len += 1;
    }
}

/// The client's address, per `X-Forwarded-For`.
///
/// ── Why trusting this header is sound HERE and nowhere else ──
/// `X-Forwarded-For` is client-settable and must normally be treated as a lie.
/// It is trustworthy in this one position because the gate binds LOOPBACK only
/// (`run`), so the sole party that can reach it is the local reverse proxy,
/// which overwrites the header. If this service is ever bound to a public
/// interface, this function becomes an attacker-controlled input and signals 4
/// and 5 become forgeable — the loopback bind is load-bearing, not incidental.
///
/// Only the FIRST entry is read: a proxy appends, so anything after the first
/// is client-supplied history.
fn observedIp(req: *std.http.Server.Request) ?[16]u8 {
    const xff = headerValue(req, "x-forwarded-for") orelse return null;
    var it = std.mem.splitScalar(u8, xff, ',');
    const first = std.mem.trim(u8, it.next() orelse return null, " \t");
    return wire.parseIpV4Mapped(first);
}

/// The server-measured solve-time residual, in milliseconds (signal 3).
///
/// ⚠️ COARSE, and knowingly so. The honest measure is (solution received −
/// challenge issued) minus an estimated network baseline, at millisecond
/// resolution. `clock.unixSeconds` gives whole seconds, so this is quantized to
/// 1000 ms — far too coarse for `pow_issue`'s bands to say much. Signal 3 is
/// therefore WEAK until this reads a millisecond clock; it is wired end-to-end
/// so the plumbing is proven, and sharpening it is a follow-up. Recorded here
/// rather than left for someone to discover in the calibration data.
fn solveMillis(issued_at: i64, now: i64) u32 {
    const elapsed = now -| issued_at;
    if (elapsed <= 0) return 0; // 0 means "not measured" to `derive`
    const ms = std.math.mul(i64, elapsed, 1000) catch return std.math.maxInt(u32);
    return std.math.cast(u32, ms) orelse std.math.maxInt(u32);
}

fn refuse(req: *std.http.Server.Request, r: wire.Refusal) !void {
    var body: [128]u8 = undefined;
    const out = std.fmt.bufPrint(&body, "{{\"error\":\"{s}\"}}", .{wire.refusalCode(r)}) catch
        return;
    // 403 across the board: the distinction lives in the code, not the status,
    // so a network observer counting status codes learns nothing.
    respondJson(req, .forbidden, out);
}

/// The ONE place this service writes a response.
///
/// ⚠️ `keep_alive = false` is load-bearing, not a tuning choice. std's
/// `Server.discardBody` asserts, on the keep-alive path, that a
/// body-carrying method declared either a `content-length` or a
/// `transfer-encoding`:
///
///     assert(head.transfer_encoding != .none or head.content_length != null);
///
/// A bare `POST /gate/redeem` with neither header satisfies neither branch, so
/// the assert fires — and an assert is a PANIC, which `catch {}` cannot
/// contain. On an endpoint that is public and unauthenticated by construction,
/// that is a remote crash any stranger can trigger before any check runs. It
/// was found by driving the running service, not by reading the code.
///
/// Declining keep-alive skips that path entirely (the assert sits inside
/// `if (keep_alive and request.head.keep_alive)`). It costs nothing here: an
/// enrollment is two requests, so connection reuse buys no measurable
/// throughput, and closing after each response also bounds what a single
/// connection can hold open — the right default for an unauthenticated port.
///
/// Every response goes through this function so a handler added later cannot
/// reintroduce the panic by forgetting the flag.
fn respondJson(req: *std.http.Server.Request, status: std.http.Status, body: []const u8) void {
    req.respond(body, .{
        .status = status,
        .extra_headers = jsonHeaders(),
        .keep_alive = false, // see above — NOT a performance knob
    }) catch {};
}

fn jsonHeaders() []const std.http.Header {
    return &.{.{ .name = "content-type", .value = "application/json" }};
}

fn headerValue(req: *std.http.Server.Request, name: []const u8) ?[]const u8 {
    var it = req.iterateHeaders();
    while (it.next()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, name)) return h.value;
    }
    return null;
}

fn pathOf(target: []const u8) []const u8 {
    const q = std.mem.indexOfScalar(u8, target, '?') orelse return target;
    return target[0..q];
}

fn queryValue(target: []const u8, name: []const u8) ?[]const u8 {
    const q = std.mem.indexOfScalar(u8, target, '?') orelse return null;
    var it = std.mem.splitScalar(u8, target[q + 1 ..], '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        if (std.mem.eql(u8, pair[0..eq], name)) return pair[eq + 1 ..];
    }
    return null;
}

// ── Tests: the pure helpers. The socket path is exercised by running the
// binary (`zig build gate`) and curling it — see gate_main.zig.

test "queryValue pulls named params and tolerates junk" {
    const t = "/gate/redeem?t=abc&n=42";
    try std.testing.expectEqualStrings("abc", queryValue(t, "t").?);
    try std.testing.expectEqualStrings("42", queryValue(t, "n").?);
    try std.testing.expect(queryValue(t, "z") == null);
    try std.testing.expect(queryValue("/gate/redeem", "t") == null);
    try std.testing.expect(queryValue("/gate/redeem?", "t") == null);
    try std.testing.expect(queryValue("/gate/redeem?novalue", "novalue") == null);
    // A prefix of a real name must not match it.
    try std.testing.expect(queryValue("/x?tt=1", "t") == null);
}

test "pathOf strips the query string" {
    try std.testing.expectEqualStrings("/gate/redeem", pathOf("/gate/redeem?t=1"));
    try std.testing.expectEqualStrings("/gate/challenge", pathOf("/gate/challenge"));
    try std.testing.expectEqualStrings("", pathOf("?a=1"));
}

test "solveMillis: zero means not-measured, and it cannot overflow" {
    try std.testing.expectEqual(@as(u32, 0), solveMillis(100, 100)); // no elapsed
    try std.testing.expectEqual(@as(u32, 0), solveMillis(100, 50)); // clock went back
    try std.testing.expectEqual(@as(u32, 5000), solveMillis(100, 105));
    // An absurd interval saturates rather than wrapping to a small, innocent
    // number — the same posture as the constellation's scoring arithmetic.
    try std.testing.expectEqual(
        std.math.maxInt(u32),
        solveMillis(std.math.minInt(i64) + 1, std.math.maxInt(i64) - 1),
    );
}

test "record drops rather than evicts when the store is full" {
    var spent: [4]pow_issue.SpentEntry = undefined;
    var tokens: [8]constellation.Token = undefined;
    var state: GateState = .{ .spent = &spent, .tokens = &tokens, .token_len = 0 };

    const obs: constellation.Observation = .{
        .enrolled_at = 1_767_323_045,
        .ip = .{0} ** 16,
        .pow_solve_ms = 0,
        .pow_tier = 2,
        .graph_shape = 0,
        .ip_class = .residential,
        .platform = .desktop_linux,
    };
    const d = constellation.derive(obs, [_]u8{0x5A} ** 32); // 4 tokens

    record(&state, d);
    try std.testing.expectEqual(@as(usize, 4), state.token_len);
    record(&state, d);
    try std.testing.expectEqual(@as(usize, 8), state.token_len); // exactly full

    // Full: the next one is dropped and COUNTED, and nothing already stored
    // is disturbed. A silently shrinking store would report innocence it had
    // not established.
    record(&state, d);
    try std.testing.expectEqual(@as(usize, 8), state.token_len);
    try std.testing.expectEqual(@as(u64, 1), state.dropped);
}
