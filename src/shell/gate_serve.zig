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
//! ── The invite code (§9.5, the pool model) ──
//! A successful redemption hands out one pre-minted single-use invite code,
//! which is what actually lets `createAccount` succeed. The gate holds NO PDS
//! admin credential and cannot mint more — so a fully compromised gate can
//! exhaust a small pool, which the owner refills, but it can never mint
//! unlimited accounts. It holds no session token, no password and no OAuth
//! material either, so it cannot impersonate anyone. That containment is worth
//! more than the convenience of self-minting.
//!
//! ── The concurrency cap, for free (§9.7) ──
//! The accept loop is SEQUENTIAL: accept → handle → close. So exactly one
//! memory-hard verification runs at a time, which is the hard cap §9.7 requires
//! against memory exhaustion (64 MiB × 32 concurrent = 2 GB would OOM the box).
//! If this ever becomes threaded, that cap must be reintroduced EXPLICITLY as a
//! semaphore — the protection is currently a property of the loop's shape, and
//! that is exactly the kind of invariant that gets lost in a refactor.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

const pow = @import("../core/pow.zig");
const pow_issue = @import("../core/pow_issue.zig");
const wire = @import("../core/gate_wire.zig");
const constellation = @import("../core/constellation.zig");
// Reuses the chat relay's TokenBucket rather than writing a second one: it is a
// plain, size-guarded, already-tested value type (F4 - do not duplicate).
const relay = @import("../core/relay.zig");
const gate_record = @import("../core/gate_record.zig");
const gate_store = @import("gate_store.zig");
const gate_pool = @import("gate_pool.zig");
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

/// One address's rate-limit slot.
///
/// A7: held in quantity — one per recently-seen address, scanned on every
/// request. Guarded.
pub const RateSlot = struct {
    /// Hashed client address. 0 means the slot is free.
    key: u64,
    bucket: relay.TokenBucket,

    comptime {
        // Budget: 8 (key) + 32 (TokenBucket: 4 × f64) = 40 bytes, exact.
        assert(@sizeOf(RateSlot) == 40);
    }
};

/// Per-address limits (§9.7). Deliberately generous — these must never bite a
/// real person, only a flood.
///
/// The load-bearing one is CHALLENGE issuance, because spending the ticket
/// before verifying (see `serveRedeem`) makes one issued ticket the ceiling on
/// one memory-hard verification. Capping issuance therefore caps the server's
/// total argon2 work directly: 0.5/sec sustained is ~9 ms/sec of CPU at the
/// calibrated difficulty, which is nothing.
///
/// Sized for shared addresses, not single users: a burst of 10 covers a
/// household or a small office arriving together, and 0.5/sec sustained is
/// 1,800 enrollments an hour from ONE address — far past any honest pattern
/// and still far below what would hurt.
const rate_burst: f64 = 10;
const rate_per_sec: f64 = 0.5;

/// How many addresses are tracked at once. A full table falls back to shared
/// accounting rather than to no limit — see `allow`.
pub const rate_slot_count = 1024;

/// Mutable service state, owned by the caller.
///
/// A7.2: cold struct — one instance for the process's lifetime.
pub const GateState = struct {
    /// Per-address rate limiters. Caller-owned and caller-sized (C1/C4).
    rate: []RateSlot = &.{},
    /// Requests refused for rate. Counted so a limit that is actually biting
    /// real users is visible as a number rather than as silence.
    rate_refusals: u64 = 0,
    /// The replay guard (`pow_issue.checkAndSpend`). Caller-sized: the shell
    /// knows the box, and the core must not allocate (C1/C2).
    spent: []pow_issue.SpentEntry,
    /// The in-memory index the scorer reads: every token the gate has observed,
    /// rebuilt from `store` at startup. When it fills, new tokens are DROPPED
    /// rather than evicted — see `record`.
    tokens: []constellation.Token,
    token_len: usize = 0,
    /// Count of enrollments whose tokens were dropped because the index was
    /// full. Surfaced so a silently-degraded gate is visible (§"no silent
    /// caps") rather than looking like a quiet, well-behaved one.
    dropped: u64 = 0,
    /// The durable append-only log. A disabled store (`fd < 0`) degrades the
    /// gate to in-memory operation rather than failing it (E2) — but see
    /// `persist_failures`, because "degraded" must never look like "fine".
    store: gate_store.Store = .{},
    /// Observations that were assessed but did NOT reach disk. Every one is a
    /// permanently lost calibration data point, so it is counted and printed
    /// rather than ignored: shadow mode exists to accumulate this data, and a
    /// gate quietly failing to write is indistinguishable from a healthy one
    /// unless someone is counting.
    persist_failures: u64 = 0,
    /// The invite-code pool (§9.5). A gate with an empty pool still observes
    /// and scores; it simply cannot complete an enrollment.
    pool: gate_pool.Pool = .{},
    /// Enrollments refused because the pool ran dry. This is an OUTAGE counter:
    /// every one is a real person who did the work and could not join.
    pool_exhausted: u64 = 0,
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

    // Per-address rate limit, BEFORE any work (§9.7). Applied to both
    // endpoints: capping challenge issuance caps memory-hard verification,
    // because a spent-before-verify ticket makes one issued ticket the ceiling
    // on one argon2 (see serveRedeem).
    if (std.mem.eql(u8, path, "/gate/challenge") or std.mem.eql(u8, path, "/gate/redeem")) {
        if (!allow(state.rate, rateKey(&req), nowSeconds())) {
            state.rate_refusals +|= 1;
            respondJson(&req, .too_many_requests, "{\"error\":\"RateLimited\"}");
            return;
        }
    }

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

    // 3. SPEND THE TICKET *BEFORE* VERIFYING. This ordering is the pre-filter
    //    §9.7 asks for, and it is structural rather than heuristic.
    //
    //    The MAC check above already rejects forged tickets for microseconds.
    //    But it does nothing about the actual attack, which is cheaper than
    //    forgery: request a legitimate ticket (issuance is free and O(1)), then
    //    submit wrong nonces to it forever. Verifying after spending would let
    //    ONE ticket absorb unlimited memory-hard verifications — measured at
    //    18.8 ms each on the box, against a sequential accept loop.
    //
    //    Spending first caps it at exactly ONE argon2 per issued ticket, so the
    //    server's total memory-hard work is bounded by the ticket ISSUANCE
    //    rate — which costs nothing to serve and is rate-limited per address
    //    above. The expensive operation is now gated by a cheap one.
    //
    //    The cost is that a wrong solve burns the ticket: an honest client that
    //    submits a bad nonce must request another. That is a fair trade, since
    //    a correct client submits exactly once and a new ticket is free.
    const tag = pow_issue.spentTag(ticket);
    switch (pow_issue.checkAndSpend(state.spent, tag, now, ticket.issued_at + cfg.ttl_secs)) {
        .recorded => {},
        .replay => return refuse(req, .replayed),
        .full => return refuse(req, .at_capacity),
    }

    // 4. The one expensive step, now provably at most once per ticket.
    //    Sequential accept loop ⇒ one at a time (the memory cap, §9.7).
    const challenge = pow.challengeFor(ticket.seed, ticket.tier);
    const solved = pow_shell.verify(gpa, io, challenge, .{ .nonce = nonce }, difficulty) catch false;
    if (!solved) return refuse(req, .unsolved);

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

    // ── Persist BEFORE indexing (§8A, the freeze rule) ──
    // The factor is computed against the store as it stands RIGHT NOW and is
    // written down with the tokens. Charge time reads this number; it must
    // never re-run `assess`, or a user who waited would be priced against
    // months of growth they had no part in.
    //
    // Disk first, then the in-memory index: if the write fails we still want
    // the observation scoring this session, but we must not let a successful
    // in-memory update disguise a failed durable one.
    // Draw the invite code BEFORE writing the observation, so the record can
    // carry the slot as its join key (`code_index`) — that is the only thing
    // linking this observation to the account that gets created later, since
    // no DID exists yet.
    const issued = gate_pool.take(&state.pool, now);
    if (issued == null) state.pool_exhausted +|= 1;

    const entry: gate_record.Enrollment = .{
        .subject_tag = tag,
        .observed_at = now,
        .factor_x100 = factor,
        .token_len = derived.len,
        .code_index = if (issued) |x| x.index else gate_record.no_code,
        .tokens = derived.tokens,
    };
    if (!gate_store.append(state.store, entry)) {
        state.persist_failures +|= 1;
    }

    // SHADOW MODE: log the assessment, admit regardless of the score.
    std.debug.print(
        "[gate] enroll observed: signals={d} factor_x100={d} index={d} dropped={d} unpersisted={d} pool_left={d}\n",
        .{ derived.len, factor, state.token_len, state.dropped, state.persist_failures, gate_pool.remaining(state.pool) },
    );

    record(state, derived);

    // An empty pool is an enrollment OUTAGE, not a quiet degradation: the user
    // solved the work and there is nothing to give them. Say so plainly with a
    // distinct code so the client can tell "come back later" from "you failed".
    const out = issued orelse {
        respondJson(req, .service_unavailable, "{\"error\":\"NoInviteAvailable\"}");
        return;
    };

    var body: [256]u8 = undefined;
    const payload = std.fmt.bufPrint(
        &body,
        "{{\"ok\":true,\"mode\":\"shadow\",\"inviteCode\":\"{s}\"}}",
        .{out.code},
    ) catch {
        respondJson(req, .internal_server_error, "{\"error\":\"Internal\"}");
        return;
    };
    respondJson(req, .ok, payload);
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

/// Spend one rate token for `key`, returning false if the address is over its
/// rate. `now_s` is monotonic seconds — never wall time, so an NTP step cannot
/// hand an attacker a free refill.
///
/// A linear scan over a small fixed table: no allocation (C1/C2), and at 1024
/// slots the scan is trivial next to the 18.8 ms verification it protects.
///
/// ── On a full table, accounting is SHARED, never skipped ──
/// If every slot is taken by a live address, the newcomer is folded into the
/// slot its key lands on rather than being waved through. That is deliberately
/// the unfair-but-safe direction: under a flood from many addresses, honest
/// users may be throttled alongside the flood, but the flood is never granted
/// unlimited memory-hard work. Failing open here would mean the limiter
/// disappears exactly when it is needed.
fn allow(slots: []RateSlot, key: u64, now_s: f64) bool {
    if (slots.len == 0) return true; // limiter not configured
    const k = if (key == 0) 1 else key; // 0 marks a free slot

    // Known address?
    for (slots) |*s| {
        if (s.key == k) return s.bucket.take(now_s);
    }
    // No: claim a free slot. Kept as a second pass so the hit path above is one
    // comparison per slot.
    for (slots) |*s| {
        if (s.key == 0) {
            s.* = .{ .key = k, .bucket = relay.TokenBucket.init(rate_burst, rate_per_sec, now_s) };
            return s.bucket.take(now_s);
        }
    }
    // Table full: share a slot rather than skip the check.
    const shared = &slots[@intCast(k % slots.len)];
    return shared.bucket.take(now_s);
}

/// The rate-limit key for a request: its observed address, or a single shared
/// key when the address is unknown. Unknown-address traffic is throttled as one
/// bucket — if we cannot tell clients apart, they do not get to be counted
/// separately.
fn rateKey(req: *std.http.Server.Request) u64 {
    const ip = observedIp(req) orelse return 1;
    return std.hash.Wyhash.hash(0, &ip);
}

/// Monotonic seconds for the rate limiter.
fn nowSeconds() f64 {
    return @as(f64, @floatFromInt(clock.monotonicNanos())) / 1_000_000_000.0;
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

test "the rate limiter allows a burst then throttles the same address" {
    var slots: [8]RateSlot = undefined;
    @memset(&slots, .{ .key = 0, .bucket = .{ .tokens = 0, .capacity = 0, .refill_per_sec = 0, .last = 0 } });

    // The burst is spendable...
    var i: usize = 0;
    while (i < @as(usize, @intFromFloat(rate_burst))) : (i += 1) {
        try std.testing.expect(allow(&slots, 42, 1000.0));
    }
    // ...and then the same address is refused at the same instant.
    try std.testing.expect(!allow(&slots, 42, 1000.0));

    // A DIFFERENT address is unaffected — the limit is per-address, not global.
    try std.testing.expect(allow(&slots, 43, 1000.0));
}

test "rate tokens refill over time" {
    var slots: [4]RateSlot = undefined;
    @memset(&slots, .{ .key = 0, .bucket = .{ .tokens = 0, .capacity = 0, .refill_per_sec = 0, .last = 0 } });

    var i: usize = 0;
    while (i < @as(usize, @intFromFloat(rate_burst))) : (i += 1) _ = allow(&slots, 7, 0.0);
    try std.testing.expect(!allow(&slots, 7, 0.0));

    // rate_per_sec = 0.5, so one token is back after two seconds.
    try std.testing.expect(allow(&slots, 7, 2.0));
    try std.testing.expect(!allow(&slots, 7, 2.0));
}

test "a full rate table SHARES accounting rather than skipping the check" {
    // Failing open here would remove the limiter exactly when a flood from many
    // addresses is filling the table — i.e. precisely when it is needed.
    var slots: [2]RateSlot = undefined;
    @memset(&slots, .{ .key = 0, .bucket = .{ .tokens = 0, .capacity = 0, .refill_per_sec = 0, .last = 0 } });

    // Two addresses claim both slots and drain them.
    for ([_]u64{ 100, 200 }) |k| {
        var i: usize = 0;
        while (i < @as(usize, @intFromFloat(rate_burst))) : (i += 1) _ = allow(&slots, k, 0.0);
    }
    // A third address finds no free slot. It must still be accounted, not
    // waved through — it folds into an existing (already drained) bucket.
    try std.testing.expect(!allow(&slots, 300, 0.0));
}

test "an unconfigured limiter allows everything rather than blocking everything" {
    // E4/E2: a limiter that was never wired must not become an accidental
    // outage. The gate binary always allocates one; this is the safety net.
    var none: [0]RateSlot = .{};
    try std.testing.expect(allow(&none, 1, 0.0));
}

test "key 0 is remapped so it cannot alias a free slot" {
    var slots: [2]RateSlot = undefined;
    @memset(&slots, .{ .key = 0, .bucket = .{ .tokens = 0, .capacity = 0, .refill_per_sec = 0, .last = 0 } });
    // A hash of exactly 0 must still be rate limited, not treated as "empty".
    var i: usize = 0;
    while (i < @as(usize, @intFromFloat(rate_burst))) : (i += 1) {
        try std.testing.expect(allow(&slots, 0, 0.0));
    }
    try std.testing.expect(!allow(&slots, 0, 0.0));
}

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
