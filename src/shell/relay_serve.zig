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

//! B1 classification: SHELL (sockets, threads, the clock). The Zat Chat
//! thin relay service (ZAT_CHAT_ROADMAP slice U4) — a sibling of
//! `appview_serve.zig`: store-and-forward of fixed-size padded ciphertext
//! blobs by opaque mailbox ID, over WebSocket. Every decision lives in
//! `core/relay.zig` (the store, the op codec, TTL/cap policy — B2); this
//! layer pumps bytes, rolls no dice (the server side of RFC 6455 needs no
//! randomness), and owns the clock.
//!
//! Shape: one accept loop (poll with a timeout so the TTL sweep runs even
//! when idle), one thread per connection — connection counts here are one
//! socket per online user, so a worker pool is a G3 violation until a
//! profiler says otherwise. ALL store access (and therefore all gpa use)
//! happens under one spinlock, the appview IndexLock/stream Mailbox
//! pattern; connection-local state lives on each thread's stack.
//!
//! A connection: HTTP upgrade (service-token gate, fail closed) → binary
//! frames carrying the relay ops. Deposits are answered ok/refused;
//! `subscribe` registers the ONE mailbox this connection drains; queued
//! blobs are pushed as `deliver` frames, deleted only on `ack`
//! (at-least-once — the MLS layer above rejects replays). A dead
//! connection re-delivers unacked blobs on reconnect. Anything malformed
//! tears down its own connection and nothing else (E2).
//!
//! Deployment (per DEPLOY_STATE): loopback listen; Caddy terminates TLS
//! and proxies the WebSocket route to this port. `zig build relay`.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const relay = @import("../core/relay.zig");
const websocket = @import("../core/websocket.zig");
const anchor = @import("../core/anchor.zig");
const clock = @import("clock.zig");

/// Resolve a DID's PUBLISHED anchor key — the directory half of A4 slice 2.
/// A signature proves the client HOLDS an anchor key; only the directory
/// proves that key is this ACCOUNT's, and an identity nobody can mint for
/// free is the entire point (a flooder who can generate keys can generate
/// identities, and per-identity limits mean nothing).
///
/// A function pointer, so the network lives in the relay BINARY and the serve
/// loop stays offline and testable (B3/D1). Returns false = no such account,
/// no published record, or the fetch failed — in every case the relay does
/// not know this DID and will not admit it.
pub const VerifyDidFn = *const fn (
    gpa: Allocator,
    io: std.Io,
    did: []const u8,
    out: *[relay.anchor_pub_len]u8,
) bool;

/// The header a client sends on the upgrade to say "I speak auth — challenge
/// me." Its absence is what keeps OLD clients working: they never see an op
/// byte they cannot parse (a client that meets an unknown op tears the
/// connection down and reconnects forever), so the relay can ship auth today
/// and require it later.
const auth_offer_header = "X-Zat-Auth: ";

/// A7.2: cold config, one per process.
pub const ServeConfig = struct {
    port: u16 = 2589,
    /// Shared service token (`Authorization: Bearer <token>` on the upgrade
    /// request). Empty ⇒ FAIL CLOSED, same posture as the AppView gate. A
    /// SERVICE gate ("is this a Zat4 client?"), not identity — identity is
    /// `require_auth` below.
    token: []const u8 = "",
    limits: relay.Limits = .{},
    /// How often the TTL sweep runs, seconds.
    sweep_every: i64 = 60,
    /// Test hook: set true to make `run` return (and its threads exit).
    stop: ?*std.atomic.Value(bool) = null,
    /// THE FLIP (A4 slice 2). False = the transition window: authenticated
    /// clients are challenged and verified, unauthenticated ones are served
    /// exactly as they always were. True = every connection must prove a DID
    /// or it deposits nothing. Ship false, upgrade the clients, then flip —
    /// the other order locks live clients out mid-swap.
    require_auth: bool = false,
    /// The directory leg. Null = the relay cannot bind a key to an account,
    /// so a "verified" identity would only mean "holds some key" — which is
    /// free to mint and therefore worth nothing. `run` refuses to enforce
    /// `require_auth` without it.
    verify_did: ?VerifyDidFn = null,
    /// Shared DID → anchor-key cache (see `AuthCache`). Null = no cache: every
    /// connection re-fetches.
    auth_cache: ?*AuthCache = null,
};

/// How long a verified DID→anchor binding is trusted before it is re-fetched.
/// A published key changes about never; an hour is short enough that a
/// rotation takes effect while a reconnect storm still costs one fetch.
const auth_cache_ttl_s: i64 = 3600;
/// Bounded, because every entry is attacker-suggested (anyone may claim any
/// DID and make us look it up). At the cap we stop inserting rather than grow
/// an allocation a stranger steers.
const auth_cache_max: usize = 1024;

/// DID → published anchor key, with a TTL. Two jobs, and the second matters
/// more: it stops the relay being used as a FETCH AMPLIFIER. Without it, every
/// reconnect (and every stranger claiming any DID) makes the relay resolve a
/// DID and hit somebody's PDS — a request one line of client code can aim at a
/// third party. With it, repeats are free and misses are bounded by the
/// connection cap.
/// A7.2: cold struct, one per process, size guard waived.
pub const AuthCache = struct {
    locked: std.atomic.Value(bool) = .init(false),
    dids: std.ArrayList([]u8) = .empty,
    anchors: std.ArrayList([relay.anchor_pub_len]u8) = .empty,
    /// When the entry was fetched. A NEGATIVE entry (no such account) is
    /// recorded too — `found` — so a flood of bogus DIDs is not a flood of
    /// fetches.
    at: std.ArrayList(i64) = .empty,
    found: std.ArrayList(bool) = .empty,

    fn lock(c: *AuthCache) void {
        while (c.locked.swap(true, .acquire)) std.atomic.spinLoopHint();
    }
    fn unlock(c: *AuthCache) void {
        c.locked.store(false, .release);
    }

    pub fn deinit(c: *AuthCache, gpa: Allocator) void {
        for (c.dids.items) |d| gpa.free(d);
        c.dids.deinit(gpa);
        c.anchors.deinit(gpa);
        c.at.deinit(gpa);
        c.found.deinit(gpa);
    }
};

/// A cached verdict: null = unknown/expired (go ask the directory).
fn cacheLookup(c: *AuthCache, did: []const u8, now: i64) ??[relay.anchor_pub_len]u8 {
    c.lock();
    defer c.unlock();
    for (c.dids.items, 0..) |d, i| {
        if (!std.mem.eql(u8, d, did)) continue;
        if (now - c.at.items[i] > auth_cache_ttl_s) return null; // stale: re-fetch
        return if (c.found.items[i]) c.anchors.items[i] else @as(?[relay.anchor_pub_len]u8, null);
    }
    return null;
}

fn cacheStore(gpa: Allocator, c: *AuthCache, did: []const u8, anchor_pub: ?[relay.anchor_pub_len]u8, now: i64) void {
    c.lock();
    defer c.unlock();
    for (c.dids.items, 0..) |d, i| {
        if (!std.mem.eql(u8, d, did)) continue;
        c.anchors.items[i] = anchor_pub orelse @splat(0);
        c.found.items[i] = anchor_pub != null;
        c.at.items[i] = now;
        return;
    }
    if (c.dids.items.len >= auth_cache_max) return; // the cap; see `auth_cache_max`
    // Reserve across ALL four arrays before any of them grows: a half-inserted
    // row would desync the parallel arrays for the life of the process.
    c.dids.ensureUnusedCapacity(gpa, 1) catch return;
    c.anchors.ensureUnusedCapacity(gpa, 1) catch return;
    c.at.ensureUnusedCapacity(gpa, 1) catch return;
    c.found.ensureUnusedCapacity(gpa, 1) catch return;
    const copy = gpa.dupe(u8, did) catch return;
    c.dids.appendAssumeCapacity(copy);
    c.anchors.appendAssumeCapacity(anchor_pub orelse @splat(0));
    c.at.appendAssumeCapacity(now);
    c.found.appendAssumeCapacity(anchor_pub != null);
}

/// The connection's identity (A4 slice 2): unproven until an `auth` frame's
/// signature verifies against the anchor key the DIRECTORY publishes for the
/// claimed DID. `did_len == 0` = anonymous — served in the transition window,
/// refused once `require_auth` is on.
/// A7.2: cold struct, one per connection (on its thread's stack), waived.
const ConnAuth = struct {
    challenge: [relay.challenge_len]u8,
    did_buf: [relay.max_auth_did_len]u8 = undefined,
    did_len: usize = 0,
    /// The client asked to be challenged on the upgrade. Only such a client is
    /// ever sent a `challenge` op — see `auth_offer_header`.
    offered: bool = false,
    /// One auth attempt per connection. The directory leg is a NETWORK FETCH;
    /// letting a connection retry it in a loop would hand an attacker a fetch
    /// amplifier that the cache alone cannot bound (each miss is a new DID).
    spent: bool = false,

    fn did(a: *const ConnAuth) []const u8 {
        return a.did_buf[0..a.did_len];
    }
    fn authed(a: *const ConnAuth) bool {
        return a.did_len > 0;
    }
};

/// The full identity check for one auth frame: the signature must be over THIS
/// connection's challenge (so it cannot be replayed from another), and the key
/// that made it must be the one the claimed DID PUBLISHES. Either half alone
/// proves nothing worth having.
fn verifyAuth(gpa: Allocator, io: std.Io, cfg: ServeConfig, a: *ConnAuth, op: anytype) bool {
    if (op.did.len == 0 or op.did.len > relay.max_auth_did_len) return false;
    anchor.verifyRelayAuth(op.anchor_pub, a.challenge, op.did, &op.sig) catch return false;

    // The directory: is this key actually that account's? Without this the
    // client has only proved it holds A key, and keys are free to mint.
    const verify = cfg.verify_did orelse return false;
    const now = clock.unixSeconds();
    var published: [relay.anchor_pub_len]u8 = undefined;
    var known = false;
    if (cfg.auth_cache) |c| {
        if (cacheLookup(c, op.did, now)) |hit| {
            const found = hit orelse return false; // cached NEGATIVE: no such account
            published = found;
            known = true;
        }
    }
    if (!known) {
        const ok = verify(gpa, io, op.did, &published);
        if (cfg.auth_cache) |c| cacheStore(gpa, c, op.did, if (ok) published else null, now);
        if (!ok) return false;
    }
    if (!std.mem.eql(u8, &published, &op.anchor_pub)) return false;

    a.did_len = op.did.len;
    @memcpy(a.did_buf[0..op.did.len], op.did);
    return true;
}

/// How many mailboxes one connection may drain.
///
/// A client needs its bootstrap inbox plus one traffic mailbox per open
/// conversation, and the traffic IDs rotate with the MLS epoch — so a busy
/// client re-subscribes as its groups advance. 64 is far above any real client
/// and still a hard bound on per-connection memory (64 × 32 bytes + counters).
/// Over the cap we simply stop adding: a client that needs more than 64 live
/// mailboxes is not a client we have, and silently dropping the 65th is better
/// than growing an attacker-steerable allocation on the serving thread.
const max_subs: usize = 64;

/// Guards the store (and every gpa call that touches it) across the accept
/// loop's sweep and all connection threads. Spinlock, the codebase's
/// cross-thread pattern (stream.zig Mailbox / appview IndexLock: brief
/// critical sections, `std.atomic` stable where Thread.Mutex is not).
/// A7.2: cold struct, size guard waived.
pub const StoreLock = struct {
    locked: std.atomic.Value(bool) = .init(false),
    pub fn lock(self: *StoreLock) void {
        while (self.locked.swap(true, .acquire)) std.atomic.spinLoopHint();
    }
    pub fn unlock(self: *StoreLock) void {
        self.locked.store(false, .release);
    }
};

const max_connections = 64;
const max_head_len = 8 * 1024;

/// Serve until `cfg.stop` is set (or forever). The caller owns the store.
/// run() minus the bind — public for SIBLING loopback tests (chat_relay)
/// that must own a fixture-probed port before the server thread exists.
/// Unique per-binary ports are load-bearing: `zig build test` runs its test
/// binaries IN PARALLEL, and two suites sharing a hardcoded port cross-talk
/// — clients of one binary reach the other's server, and the orphaned
/// listener blocks its join forever (the 51-minute hang, 2026-07-11).
pub fn runBound(gpa: Allocator, io: std.Io, server: *std.Io.net.Server, store: *relay.Store, cfg: ServeConfig, lock: *StoreLock) !void {
    try serveLoop(gpa, io, server, store, cfg, lock);
}

pub const ConfigError = error{AuthRequiresDirectory};

pub fn run(gpa: Allocator, io: std.Io, store: *relay.Store, cfg: ServeConfig, lock: *StoreLock) !void {
    // Requiring auth with no directory to check against would enforce a check
    // that means nothing — "this connection holds SOME key," and keys cost
    // nothing to mint. Refusing to start is the honest failure: a relay that
    // claimed to require identity while admitting anyone is worse than one
    // that admits it does not.
    if (cfg.require_auth and cfg.verify_did == null) return error.AuthRequiresDirectory;
    var address: std.Io.net.IpAddress = .{ .ip4 = .loopback(cfg.port) };
    var server = try address.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);
    try serveLoop(gpa, io, &server, store, cfg, lock);
}

/// The accept/sweep loop, split from the bind so the loopback test can drive
/// the REAL loop against a listener it already bound (it needs the port
/// before the server thread exists).
fn serveLoop(gpa: Allocator, io: std.Io, server: *std.Io.net.Server, store: *relay.Store, cfg: ServeConfig, lock: *StoreLock) !void {
    var threads: std.ArrayList(std.Thread) = .empty;
    defer {
        for (threads.items) |t| t.join();
        threads.deinit(gpa);
    }
    var conn_count: std.atomic.Value(u32) = .init(0);
    var last_sweep: i64 = clock.unixSeconds();

    while (true) {
        if (cfg.stop) |s| {
            if (s.load(.acquire)) return;
        }
        // The sweep must run even on an idle relay — ephemerality is a
        // server-side promise (M3), not a side effect of traffic.
        const now = clock.unixSeconds();
        if (now - last_sweep >= cfg.sweep_every) {
            lock.lock();
            _ = relay.sweep(gpa, store, cfg.limits, now);
            lock.unlock();
            last_sweep = now;
        }
        // Poll the listener so this loop stays responsive to stop + sweep.
        var lfds = [_]std.posix.pollfd{.{ .fd = server.socket.handle, .events = std.posix.POLL.IN, .revents = 0 }};
        const ready = std.posix.poll(&lfds, 500) catch 0;
        if (ready == 0) continue;

        const stream = server.accept(io) catch continue; // E2: next loop's problem
        if (conn_count.load(.acquire) >= max_connections) {
            stream.close(io);
            continue;
        }
        _ = conn_count.fetchAdd(1, .acq_rel);
        const t = std.Thread.spawn(.{}, connMain, .{ gpa, io, stream, store, cfg, lock, &conn_count }) catch {
            _ = conn_count.fetchSub(1, .acq_rel);
            stream.close(io);
            continue;
        };
        threads.append(gpa, t) catch {
            // OOM tracking a thread: join it now (it exits when its peer
            // closes or stop is set) rather than leak it at shutdown.
            t.join();
            continue;
        };
    }
}

fn connMain(gpa: Allocator, io: std.Io, stream: std.Io.net.Stream, store: *relay.Store, cfg: ServeConfig, lock: *StoreLock, conn_count: *std.atomic.Value(u32)) void {
    defer _ = conn_count.fetchSub(1, .acq_rel);
    defer stream.close(io);
    serveConn(gpa, io, stream, store, cfg, lock) catch {}; // E2: contained
}

const ConnError = error{ ReadFailed, WriteFailed, BadRequest, Closed };

fn serveConn(gpa: Allocator, io: std.Io, stream: std.Io.net.Stream, store: *relay.Store, cfg: ServeConfig, lock: *StoreLock) ConnError!void {
    var read_buf: [16 * 1024]u8 = undefined;
    var write_buf: [8 * 1024]u8 = undefined;
    var tcp_reader = stream.reader(io, &read_buf);
    var tcp_writer = stream.writer(io, &write_buf);
    const reader = &tcp_reader.interface;
    const writer = &tcp_writer.interface;

    // --- The HTTP upgrade -------------------------------------------------
    // Read the head (bounded; a silent or trickling peer is cut off by the
    // poll ticks). The relay's one route is a websocket GET on /relay.
    var head: [max_head_len]u8 = undefined;
    var head_len: usize = 0;
    while (std.mem.indexOf(u8, head[0..head_len], "\r\n\r\n") == null) {
        if (head_len == head.len) return error.BadRequest;
        if (!pollReadable(stream, cfg, 5_000)) return error.BadRequest;
        const n = (readAvailable(reader, head[head_len..]) catch return error.ReadFailed) orelse return error.Closed;
        head_len += n;
    }
    const head_str = head[0..head_len];

    // Service gate first (fail closed), before the route is even looked at.
    if (!relay.tokenMatches(cfg.token, headerValue(head_str, "Authorization: "))) {
        writer.writeAll("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n") catch {};
        writer.flush() catch {};
        return error.BadRequest;
    }
    if (!std.mem.startsWith(u8, head_str, "GET /relay")) return error.BadRequest;

    // IDENTITY (A4 slice 2). A client that speaks auth SAYS SO here; only such
    // a client is ever sent a `challenge` op, so an old client never meets a
    // byte it cannot parse. Once `require_auth` is on, a client that does not
    // say so is refused right here — before a socket is upgraded, let alone a
    // blob stored.
    var conn_auth: ConnAuth = .{ .challenge = @splat(0) };
    conn_auth.offered = headerValue(head_str, auth_offer_header) != null;
    if (cfg.require_auth and !conn_auth.offered) {
        writer.writeAll("HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n") catch {};
        writer.flush() catch {};
        return error.BadRequest;
    }

    const key = headerValue(head_str, "Sec-WebSocket-Key: ") orelse return error.BadRequest;
    var accept_buf: [websocket.accept_len]u8 = undefined;
    const accept = websocket.acceptKeyFor(key, &accept_buf);
    var resp_buf: [256]u8 = undefined;
    const resp = std.fmt.bufPrint(
        &resp_buf,
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n",
        .{accept},
    ) catch return error.BadRequest;
    writer.writeAll(resp) catch return error.WriteFailed;
    writer.flush() catch return error.WriteFailed;

    // The challenge is per-connection and random, which is what makes a
    // captured signature worthless anywhere else: it authenticates THIS socket
    // and nothing more. Entropy failure is fatal to the connection — a
    // predictable nonce is worse than no auth, because it would look like auth.
    if (conn_auth.offered) {
        io.randomSecure(&conn_auth.challenge) catch return error.BadRequest;
        var ch_op: [relay.challenge_frame_len]u8 = undefined;
        var ch_frame: [relay.challenge_frame_len + websocket.max_header_len]u8 = undefined;
        const f = websocket.encodeFrame(&ch_frame, .binary, relay.buildChallenge(&ch_op, conn_auth.challenge), null) catch return error.BadRequest;
        writer.writeAll(f) catch return error.WriteFailed;
        writer.flush() catch return error.WriteFailed;
    }

    // --- The frame loop -----------------------------------------------------
    // Connection-local state: the accumulation buffer (frames can split and
    // coalesce arbitrarily on TCP) and the connection's SUBSCRIPTIONS.
    //
    // Plural, and that plurality is load-bearing. This used to be a single
    // mailbox that each `subscribe` OVERWROTE — while the client subscribes to
    // several: its bootstrap inbox (where Welcomes are delivered) AND every open
    // conversation's per-epoch traffic mailbox. So the moment a client had even
    // one conversation, its traffic subscription clobbered its bootstrap one, and
    // it could never receive another Welcome. Not "rarely" — NEVER. A
    // conversation whose two halves drifted apart could not be repaired, because
    // the repair travels by Welcome, and the mailbox it arrives in was no longer
    // being drained. Days of "why can't I message my other account" ended here.
    var acc: [16 * 1024]u8 = undefined;
    var acc_len: usize = 0;
    // This connection's deposit rate limiter. Full at connect so a legitimate
    // burst (subscribing + a first message) is never throttled.
    var bucket = relay.TokenBucket.init(
        relay.deposit_rate_capacity,
        relay.deposit_rate_per_sec,
        @as(f64, @floatFromInt(clock.monotonicNanos())) / 1_000_000_000.0,
    );
    var subs: [max_subs][relay.mailbox_id_len]u8 = undefined;
    // Per-subscription: how many queued blobs this connection has already pushed
    // (unacked). Reset on (re)subscribe; an ack pops that mailbox's store head,
    // so it decrements. Parallel to `subs` — one counter per mailbox, because a
    // shared counter across mailboxes would skip mail.
    var sent: [max_subs]u32 = @splat(0);
    var subs_n: usize = 0;

    while (true) {
        if (cfg.stop) |s| {
            if (s.load(.acquire)) return;
        }
        // Ingest whatever arrived (a bounded wait, so stop + delivery tick).
        if (pollReadable(stream, cfg, 250)) {
            const n = (readAvailable(reader, acc[acc_len..]) catch return error.ReadFailed) orelse return error.Closed;
            acc_len += n;
        }

        // Drain complete frames.
        var at: usize = 0;
        while (true) {
            const got = websocket.decodeFrame(acc[at..acc_len]) catch return error.BadRequest;
            const decoded = got orelse break;
            at += decoded.consumed;
            switch (decoded.frame.opcode) {
                .binary => try handleOp(gpa, io, decoded.frame.payload, store, cfg, lock, &bucket, writer, &subs, &sent, &subs_n, &conn_auth),
                .ping => {
                    var pong_buf: [256]u8 = undefined;
                    if (decoded.frame.payload.len <= 125) {
                        const pong = websocket.encodeFrame(&pong_buf, .pong, decoded.frame.payload, null) catch return error.BadRequest;
                        writer.writeAll(pong) catch return error.WriteFailed;
                        writer.flush() catch return error.WriteFailed;
                    }
                },
                .close => {
                    var close_buf: [8]u8 = undefined;
                    const close_frame = websocket.encodeFrame(&close_buf, .close, "", null) catch return error.BadRequest;
                    writer.writeAll(close_frame) catch {};
                    writer.flush() catch {};
                    return;
                },
                .pong => {},
                else => return error.BadRequest, // text/continuation: not this protocol
            }
        }
        if (at > 0) {
            std.mem.copyForwards(u8, acc[0 .. acc_len - at], acc[at..acc_len]);
            acc_len -= at;
        }
        if (acc_len == acc.len) return error.BadRequest; // a frame larger than the vocabulary allows

        // Push undelivered blobs for EVERY subscription this connection holds.
        // Copy each blob out under the lock, write it outside (the socket is slow;
        // the sweep could free the borrowed pointer mid-write otherwise).
        for (subs[0..subs_n], sent[0..subs_n]) |id, *n| {
            while (true) {
                var blob: [relay.bucket_len]u8 = undefined;
                lock.lock();
                const have = relay.nthFor(store, id, n.*);
                if (have) |b| blob = b.*;
                lock.unlock();
                if (have == null) break;
                var frame_buf: [relay.deliver_frame_len + websocket.max_header_len]u8 = undefined;
                var op_buf: [relay.deliver_frame_len]u8 = undefined;
                const op = relay.buildDeliver(&op_buf, id, &blob);
                const frame = websocket.encodeFrame(&frame_buf, .binary, op, null) catch return error.BadRequest;
                writer.writeAll(frame) catch return error.WriteFailed;
                writer.flush() catch return error.WriteFailed;
                n.* += 1;
            }
        }
    }
}

fn handleOp(
    gpa: Allocator,
    io: std.Io,
    payload: []u8,
    store: *relay.Store,
    cfg: ServeConfig,
    lock: *StoreLock,
    bucket: *relay.TokenBucket,
    writer: *std.Io.Writer,
    subs: *[max_subs][relay.mailbox_id_len]u8,
    sent: *[max_subs]u32,
    subs_n: *usize,
    conn_auth: *ConnAuth,
) ConnError!void {
    const op = relay.parseClientOp(payload) catch return error.BadRequest;

    // The IDENTITY GATE (A4 slice 2). Once the operator flips `require_auth`,
    // a connection that has not proved a DID does nothing at all — it cannot
    // deposit, and it cannot subscribe (a mailbox it drains is mail somebody
    // else never receives, so reading is as much a capability as writing).
    // Before the flip this is dead code, and the relay behaves exactly as it
    // did — that is the transition window, and it is deliberate.
    if (cfg.require_auth and op != .auth and !conn_auth.authed()) {
        if (!builtin.is_test) std.debug.print("[relay] op REFUSED (unauthenticated)\n", .{});
        var ref_buf: [2]u8 = undefined;
        var out_buf: [16]u8 = undefined;
        const frame = websocket.encodeFrame(&out_buf, .binary, relay.buildRefused(&ref_buf, .unauthenticated), null) catch return error.BadRequest;
        writer.writeAll(frame) catch return error.WriteFailed;
        writer.flush() catch return error.WriteFailed;
        return;
    }

    switch (op) {
        // "I am this DID." The signature proves key custody over THIS
        // connection's nonce; the directory proves the key is that account's.
        // One attempt per connection: the directory leg is a network fetch,
        // and a retryable one is a fetch amplifier pointed at other people's
        // servers. Failure closes the connection rather than leaving a socket
        // that looks authenticated and is not.
        .auth => |a| {
            if (conn_auth.spent or !conn_auth.offered) return error.BadRequest;
            conn_auth.spent = true;
            if (!verifyAuth(gpa, io, cfg, conn_auth, a)) {
                if (!builtin.is_test) std.debug.print("[relay] auth REFUSED (bad signature or unpublished key)\n", .{});
                // IN THE TRANSITION WINDOW, A FAILED AUTH IS NOT FATAL. The
                // directory leg is a network fetch to somebody else's PDS, and
                // if we killed the connection whenever it failed we would have
                // made every client's chat depend on that fetch succeeding —
                // turning a hardening feature into a new way for messaging to
                // break. Unauthenticated is exactly what this relay already
                // serves, so fall back to it and say so in the log.
                //
                // Once auth is REQUIRED, the same failure is fatal: a socket
                // that cannot prove who it is has no business staying open, and
                // pretending otherwise is how a gate becomes decoration.
                if (cfg.require_auth) return error.BadRequest;
                return;
            }
            if (!builtin.is_test) std.debug.print("[relay] authenticated {s}\n", .{conn_auth.did()});
            var ok_buf: [relay.auth_ok_frame_len]u8 = undefined;
            var out_buf: [16]u8 = undefined;
            const frame = websocket.encodeFrame(&out_buf, .binary, relay.buildAuthOk(&ok_buf), null) catch return error.BadRequest;
            writer.writeAll(frame) catch return error.WriteFailed;
            writer.flush() catch return error.WriteFailed;
        },
        .deposit => |d| {
            const now = clock.unixSeconds();
            // RATE LIMIT FIRST, before the store is touched at all. One connection
            // must not be able to consume the shared store faster than its fair
            // rate — the first, cheapest defense against a flood from anyone
            // holding the (shared) relay token.
            const mono_s = @as(f64, @floatFromInt(clock.monotonicNanos())) / 1_000_000_000.0;
            const result: relay.DepositResult = if (!bucket.take(mono_s)) blk: {
                if (!builtin.is_test) std.debug.print("[relay] deposit REFUSED (rate limit)\n", .{});
                break :blk .rate_limited;
            } else res: {
                lock.lock();
                const r = relay.deposit(gpa, store, cfg.limits, d.id, d.blob, now) catch {
                    lock.unlock();
                    return error.BadRequest; // OOM: shed this connection, keep the store
                };
                lock.unlock();
                break :res r;
            };
            var out_buf: [16]u8 = undefined;
            var ok_buf: [1]u8 = undefined;
            var ref_buf: [2]u8 = undefined;
            const reply = if (result == .ok) relay.buildDepositOk(&ok_buf) else relay.buildRefused(&ref_buf, result);
            const frame = websocket.encodeFrame(&out_buf, .binary, reply, null) catch return error.BadRequest;
            writer.writeAll(frame) catch return error.WriteFailed;
            writer.flush() catch return error.WriteFailed;
        },
        // ADD a mailbox to this connection's set — never replace the set. A
        // client legitimately drains several: its bootstrap inbox (Welcomes) and
        // one traffic mailbox per open conversation, whose IDs rotate every epoch.
        .subscribe => |s| {
            for (subs[0..subs_n.*], 0..) |have, i| {
                if (std.mem.eql(u8, &have, &s.id)) {
                    sent[i] = 0; // re-arm: re-deliver anything unacked (at-least-once)
                    return;
                }
            }
            if (subs_n.* >= max_subs) return; // the cap; see `max_subs`
            subs[subs_n.*] = s.id;
            sent[subs_n.*] = 0;
            subs_n.* += 1;
        },
        .ack => |a| {
            lock.lock();
            const popped = relay.ackOldest(gpa, store, a.id);
            lock.unlock();
            if (!popped) return;
            // Decrement the counter for the mailbox that was actually acked —
            // one counter per subscription, or an ack on one would let another's
            // mail be skipped.
            for (subs[0..subs_n.*], 0..) |have, i| {
                if (std.mem.eql(u8, &have, &a.id)) {
                    if (sent[i] > 0) sent[i] -= 1;
                    return;
                }
            }
        },
    }
}

/// Bounded readiness wait on the raw fd — the stream.zig/oauth poll idiom:
/// poll is a bounded sleep that keeps the loop responsive; the read itself
/// decides what arrived.
fn pollReadable(stream: std.Io.net.Stream, cfg: ServeConfig, timeout_ms: i32) bool {
    _ = cfg;
    var pfds = [_]std.posix.pollfd{.{ .fd = stream.socket.handle, .events = std.posix.POLL.IN, .revents = 0 }};
    const ready = std.posix.poll(&pfds, timeout_ms) catch 0;
    return ready > 0;
}

/// Copy whatever the reader has buffered (filling once if empty) into `dst`.
/// Null = clean end of stream (E4). The stream.zig idiom.
fn readAvailable(reader: *std.Io.Reader, dst: []u8) error{ReadFailed}!?usize {
    while (reader.bufferedLen() == 0) {
        reader.fillMore() catch |err| switch (err) {
            error.EndOfStream => return null,
            error.ReadFailed => return error.ReadFailed,
        };
    }
    const available = reader.buffered();
    const n = @min(available.len, dst.len);
    @memcpy(dst[0..n], available[0..n]);
    reader.toss(n);
    return n;
}

/// The value of the first header whose name (with ": ") matches exactly —
/// the fixture idiom. Exact casing is fine here: the only clients are ours
/// (core/websocket.buildHandshake and this file's tests emit these forms).
fn headerValue(head: []const u8, comptime label: []const u8) ?[]const u8 {
    const at = std.mem.indexOf(u8, head, "\r\n" ++ label) orelse return null;
    const start = at + 2 + label.len;
    const end = std.mem.indexOfScalarPos(u8, head, start, '\r') orelse return null;
    return head[start..end];
}

// ---------------------------------------------------------------------------
// Tests (C6) — a REAL loopback client: raw TCP + the shared websocket codec,
// driving upgrade → deposit → subscribe → deliver → ack → delete end to end.
// ---------------------------------------------------------------------------

const testing = std.testing;
const fixture = @import("test_fixture.zig");

/// A7.2: cold struct, size guard waived — test-only, two per test.
const TestClient = struct {
    stream: std.Io.net.Stream,
    reader: std.Io.net.Stream.Reader,
    writer: std.Io.net.Stream.Writer,
    read_buf: [16 * 1024]u8,
    write_buf: [8 * 1024]u8,
    acc: [16 * 1024]u8 = undefined,
    acc_len: usize = 0,

    fn sendFrame(c: *TestClient, opcode: websocket.Opcode, payload: []const u8) !void {
        var frame_buf: [relay.deposit_frame_len + websocket.max_header_len]u8 = undefined;
        // A fixed mask is fine in a test; the server unmasks either way.
        const frame = try websocket.encodeFrame(&frame_buf, opcode, payload, .{ 1, 2, 3, 4 });
        try c.writer.interface.writeAll(frame);
        try c.writer.interface.flush();
    }

    /// Wait (bounded) for the next binary frame and return its payload,
    /// copied into `out`.
    fn nextBinary(c: *TestClient, out: []u8) !?[]u8 {
        var waited_ms: u64 = 0;
        while (waited_ms < 5_000) {
            const decoded = try websocket.decodeFrame(c.acc[0..c.acc_len]);
            if (decoded) |d| {
                defer {
                    std.mem.copyForwards(u8, c.acc[0 .. c.acc_len - d.consumed], c.acc[d.consumed..c.acc_len]);
                    c.acc_len -= d.consumed;
                }
                if (d.frame.opcode == .binary) {
                    @memcpy(out[0..d.frame.payload.len], d.frame.payload);
                    return out[0..d.frame.payload.len];
                }
                continue;
            }
            const n = (readAvailable(&c.reader.interface, c.acc[c.acc_len..]) catch return error.ReadFailed) orelse return null;
            if (n == 0) {
                clock.sleepMillis(10);
                waited_ms += 10;
            }
            c.acc_len += n;
        }
        return null;
    }
};

fn connectClient(c: *TestClient, io: std.Io, port: u16, token: []const u8) !void {
    return connectClientAuth(c, io, port, token, false);
}

fn connectClientAuth(c: *TestClient, io: std.Io, port: u16, token: []const u8, offer_auth: bool) !void {
    const addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    c.stream = try addr.connect(io, .{ .mode = .stream });
    c.reader = c.stream.reader(io, &c.read_buf);
    c.writer = c.stream.writer(io, &c.write_buf);

    // The upgrade, with the service token (buildHandshake carries no
    // Authorization — U5's client gains that; the raw form here IS the test
    // that the server's gate reads it). `X-Zat-Auth: 1` is the A4-slice-2
    // OFFER: only a client that sends it is ever challenged.
    var req_buf: [512]u8 = undefined;
    const req = try std.fmt.bufPrint(
        &req_buf,
        "GET /relay HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n{s}Authorization: Bearer {s}\r\n\r\n",
        .{ if (offer_auth) "X-Zat-Auth: 1\r\n" else "", token },
    );
    try c.writer.interface.writeAll(req);
    try c.writer.interface.flush();

    // Read to the end of the 101 head; whatever follows seeds the frame acc.
    var head: [2048]u8 = undefined;
    var head_len: usize = 0;
    while (std.mem.indexOf(u8, head[0..head_len], "\r\n\r\n") == null) {
        const n = (readAvailable(&c.reader.interface, head[head_len..]) catch return error.ReadFailed) orelse return error.Closed;
        head_len += n;
    }
    if (!std.mem.startsWith(u8, head[0..head_len], "HTTP/1.1 101")) return error.BadRequest;
    const body_at = std.mem.indexOf(u8, head[0..head_len], "\r\n\r\n").? + 4;
    const tail = head[body_at..head_len];
    @memcpy(c.acc[0..tail.len], tail);
    c.acc_len = tail.len;
}

test "relay loopback: ONE connection drains MANY mailboxes (the bootstrap + traffic bug)" {
    // ── The bug this pins cost days. ──
    //
    // The server kept ONE subscription per connection and each `subscribe`
    // OVERWROTE it. But a client legitimately drains several: its BOOTSTRAP inbox
    // — where Welcomes, i.e. every first contact and every repair, are delivered —
    // AND one traffic mailbox per open conversation.
    //
    // So the instant a client had a single conversation, its traffic subscription
    // clobbered its bootstrap one. It could then never receive another Welcome.
    // Not rarely: NEVER. And because a broken conversation is repaired BY a
    // Welcome, a conversation that fell out of sync could not be fixed either. The
    // client showed no error; the mail simply sat in a mailbox nobody drained.
    const gpa = testing.allocator;
    const io = std.testing.io;

    var store: relay.Store = .{};
    defer relay.deinit(gpa, &store);
    var lock: StoreLock = .{};
    var stop: std.atomic.Value(bool) = .init(false);

    var bound = try fixture.listenLoopback(io, 25893);
    const port = bound.port;
    const cfg: ServeConfig = .{ .port = port, .token = "relay-test-token", .stop = &stop };
    const server_thread = try std.Thread.spawn(.{}, runBoundForTest, .{ gpa, io, &bound.server, &store, cfg, &lock });
    defer {
        stop.store(true, .release);
        server_thread.join();
        bound.server.deinit(io);
    }

    var alice: TestClient = undefined;
    try connectClient(&alice, io, port, "relay-test-token");
    defer alice.stream.close(io);
    var bob: TestClient = undefined;
    try connectClient(&bob, io, port, "relay-test-token");
    defer bob.stream.close(io);

    // Bob's two mailboxes: his bootstrap inbox, and one conversation's traffic box.
    const bootstrap: [relay.mailbox_id_len]u8 = @splat(0xB0);
    const traffic: [relay.mailbox_id_len]u8 = @splat(0x77);

    var blob_w: [relay.bucket_len]u8 = @splat(0xAA); // a Welcome
    var blob_m: [relay.bucket_len]u8 = @splat(0xCC); // an ordinary message

    var dep_buf: [relay.deposit_frame_len]u8 = undefined;
    var reply_buf: [relay.deliver_frame_len]u8 = undefined;
    try alice.sendFrame(.binary, relay.buildDeposit(&dep_buf, bootstrap, &blob_w));
    _ = (try alice.nextBinary(&reply_buf)) orelse return error.TestUnexpectedResult;
    try alice.sendFrame(.binary, relay.buildDeposit(&dep_buf, traffic, &blob_m));
    _ = (try alice.nextBinary(&reply_buf)) orelse return error.TestUnexpectedResult;

    // Bob subscribes to BOTH — bootstrap first, then traffic, exactly as a real
    // client does (`chat_e2ee.subscriptions` returns the inbox, then each group).
    // Under the old server the second frame would silently discard the first.
    var sub_buf: [relay.subscribe_frame_len]u8 = undefined;
    try bob.sendFrame(.binary, relay.buildSubscribe(&sub_buf, bootstrap));
    try bob.sendFrame(.binary, relay.buildSubscribe(&sub_buf, traffic));

    // BOTH must arrive. Order is not guaranteed; presence is the assertion.
    var got_welcome = false;
    var got_message = false;
    var tries: usize = 0;
    while ((!got_welcome or !got_message) and tries < 40) : (tries += 1) {
        const d = (try bob.nextBinary(&reply_buf)) orelse continue;
        switch (try relay.parseServerOp(d)) {
            .deliver => |dv| {
                if (std.mem.eql(u8, &dv.id, &bootstrap)) {
                    try testing.expectEqualSlices(u8, &blob_w, dv.blob);
                    got_welcome = true;
                } else if (std.mem.eql(u8, &dv.id, &traffic)) {
                    try testing.expectEqualSlices(u8, &blob_m, dv.blob);
                    got_message = true;
                }
            },
            else => {},
        }
    }
    // The Welcome is the one that used to vanish, and with it every first contact
    // and every repair a client with an existing conversation could ever make.
    try testing.expect(got_welcome);
    try testing.expect(got_message);

    // An ack on ONE mailbox must not disturb the other's delivery accounting.
    var ack_buf: [relay.ack_frame_len]u8 = undefined;
    try bob.sendFrame(.binary, relay.buildAck(&ack_buf, bootstrap));
    var waited: u64 = 0;
    while (waited < 5_000) {
        lock.lock();
        const b_left = relay.pendingCount(&store, bootstrap);
        lock.unlock();
        if (b_left == 0) break;
        clock.sleepMillis(10);
        waited += 10;
    }
    lock.lock();
    try testing.expectEqual(@as(u32, 0), relay.pendingCount(&store, bootstrap));
    try testing.expectEqual(@as(u32, 1), relay.pendingCount(&store, traffic)); // untouched
    lock.unlock();
}

test "relay loopback: deposit -> subscribe -> deliver -> ack deletes; the gate holds" {
    const gpa = testing.allocator;
    const io = std.testing.io;

    var store: relay.Store = .{};
    defer relay.deinit(gpa, &store);
    var lock: StoreLock = .{};
    var stop: std.atomic.Value(bool) = .init(false);

    var bound = try fixture.listenLoopback(io, 25890);
    const port = bound.port;
    const cfg: ServeConfig = .{ .port = port, .token = "relay-test-token", .stop = &stop };

    // Run the real serve loop on its own thread, against the already-bound
    // listener (runBound is run() minus the bind, so the test owns the port).
    const server_thread = try std.Thread.spawn(.{}, runBoundForTest, .{ gpa, io, &bound.server, &store, cfg, &lock });
    defer {
        stop.store(true, .release);
        server_thread.join();
        bound.server.deinit(io);
    }

    // A wrong token is refused before anything else.
    {
        var bad: TestClient = undefined;
        try testing.expectError(error.BadRequest, connectClient(&bad, io, port, "wrong"));
        bad.stream.close(io);
    }

    var alice: TestClient = undefined;
    try connectClient(&alice, io, port, "relay-test-token");
    defer alice.stream.close(io);
    var bob: TestClient = undefined;
    try connectClient(&bob, io, port, "relay-test-token");
    defer bob.stream.close(io);

    const mailbox: [relay.mailbox_id_len]u8 = @splat(0x42);
    var blob: [relay.bucket_len]u8 = undefined;
    for (&blob, 0..) |*b, i| b.* = @truncate(i * 7);

    // Alice deposits into Bob's mailbox and hears ok.
    var dep_buf: [relay.deposit_frame_len]u8 = undefined;
    try alice.sendFrame(.binary, relay.buildDeposit(&dep_buf, mailbox, &blob));
    var reply_buf: [relay.deliver_frame_len]u8 = undefined;
    const ok = (try alice.nextBinary(&reply_buf)) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(relay.ServerOp.deposit_ok, try relay.parseServerOp(ok));

    // Bob subscribes and the blob arrives, byte-identical.
    var sub_buf: [relay.subscribe_frame_len]u8 = undefined;
    try bob.sendFrame(.binary, relay.buildSubscribe(&sub_buf, mailbox));
    const delivered = (try bob.nextBinary(&reply_buf)) orelse return error.TestUnexpectedResult;
    switch (try relay.parseServerOp(delivered)) {
        .deliver => |d| {
            try testing.expectEqualSlices(u8, &mailbox, &d.id);
            try testing.expectEqualSlices(u8, &blob, d.blob);
        },
        else => return error.TestUnexpectedResult,
    }

    // Delivered is NOT deleted until acked (a drop here must re-deliver).
    lock.lock();
    try testing.expectEqual(@as(u32, 1), relay.pendingCount(&store, mailbox));
    lock.unlock();

    // The ack deletes it.
    var ack_buf: [relay.ack_frame_len]u8 = undefined;
    try bob.sendFrame(.binary, relay.buildAck(&ack_buf, mailbox));
    var waited_ms: u64 = 0;
    while (waited_ms < 5_000) {
        lock.lock();
        const left = relay.pendingCount(&store, mailbox);
        lock.unlock();
        if (left == 0) break;
        clock.sleepMillis(10);
        waited_ms += 10;
    }
    lock.lock();
    try testing.expectEqual(@as(u32, 0), relay.pendingCount(&store, mailbox));
    lock.unlock();
}

/// run()'s loop against a listener the test already bound (so the test knows
/// the port before the server thread exists).
fn runBoundForTest(gpa: Allocator, io: std.Io, server: *std.Io.net.Server, store: *relay.Store, cfg: ServeConfig, lock: *StoreLock) void {
    serveLoop(gpa, io, server, store, cfg, lock) catch {};
}

// ---------------------------------------------------------------------------
// A4 slice 2 — per-DID auth, end to end on the loopback.
// ---------------------------------------------------------------------------

const anchor_core = @import("../core/anchor.zig");

/// The test's directory: one account exists, everyone else is a stranger. This
/// stands in for the real fetch (relay_main's `verifyDid`), which resolves the
/// DID to its PDS and reads the published keyPackage — the serve loop only ever
/// sees the function pointer, which is exactly why it can be tested offline.
const auth_test_did = "did:plc:relayauthtestaccount";
const auth_test_seed: [32]u8 = @splat(0x4A);

fn testVerifyDid(gpa: Allocator, io: std.Io, did: []const u8, out: *[relay.anchor_pub_len]u8) bool {
    _ = gpa;
    _ = io;
    if (!std.mem.eql(u8, did, auth_test_did)) return false; // no such account
    out.* = anchor_core.publicKey(auth_test_seed) catch return false;
    return true;
}

test "relay loopback: a connection PROVES who it is, or (once required) does nothing" {
    // The relay used to know no one: one shared bearer token, baked into every
    // client. Extract it from an APK and you could fill the store — a trivial
    // denial of service for everyone, and a targeted one against any person
    // whose bootstrap mailbox you can derive from their PUBLIC anchor key.
    //
    // Now a connection can prove a DID: it signs a nonce THIS relay chose, with
    // the anchor key that DID's directory record publishes. Two halves, both
    // load-bearing — the signature proves key custody (and, being bound to this
    // connection's nonce, cannot be replayed from another socket), and the
    // directory proves the key is that account's (a key alone is free to mint,
    // so a limit per key would bound nothing).
    const gpa = testing.allocator;
    const io = std.testing.io;

    var store: relay.Store = .{};
    defer relay.deinit(gpa, &store);
    var lock: StoreLock = .{};
    var cache: AuthCache = .{};
    defer cache.deinit(gpa);
    var stop: std.atomic.Value(bool) = .init(false);

    var bound = try fixture.listenLoopback(io, 25895);
    const port = bound.port;
    // The TRANSITION WINDOW first: auth is offered and verified, but not
    // required — an old client must keep working exactly as before.
    const cfg: ServeConfig = .{
        .port = port,
        .token = "relay-test-token",
        .stop = &stop,
        .verify_did = testVerifyDid,
        .auth_cache = &cache,
    };
    const server_thread = try std.Thread.spawn(.{}, runBoundForTest, .{ gpa, io, &bound.server, &store, cfg, &lock });
    defer {
        stop.store(true, .release);
        server_thread.join();
        bound.server.deinit(io);
    }

    // An OLD client (no offer) is never challenged and works untouched. This is
    // the assertion that makes the deploy safe: shipping auth must not break a
    // single client in the wild, because a client that met an unknown op would
    // tear its connection down and reconnect forever.
    {
        var old: TestClient = undefined;
        try connectClient(&old, io, port, "relay-test-token");
        defer old.stream.close(io);
        const mailbox: [relay.mailbox_id_len]u8 = @splat(0x31);
        const blob: [relay.bucket_len]u8 = @splat(0x99);
        var dep_buf: [relay.deposit_frame_len]u8 = undefined;
        try old.sendFrame(.binary, relay.buildDeposit(&dep_buf, mailbox, &blob));
        var reply: [relay.deliver_frame_len]u8 = undefined;
        const got = (try old.nextBinary(&reply)) orelse return error.TestUnexpectedResult;
        // deposit_ok — NOT a challenge, and not a refusal.
        try testing.expectEqual(relay.ServerOp.deposit_ok, try relay.parseServerOp(got));
    }

    // A NEW client offers auth, is challenged, signs, and is admitted.
    {
        var newc: TestClient = undefined;
        try connectClientAuth(&newc, io, port, "relay-test-token", true);
        defer newc.stream.close(io);
        var reply: [relay.deliver_frame_len]u8 = undefined;
        const chal_frame = (try newc.nextBinary(&reply)) orelse return error.TestUnexpectedResult;
        const challenge = switch (try relay.parseServerOp(chal_frame)) {
            .challenge => |c| c,
            else => return error.TestUnexpectedResult,
        };
        const anchor_pub = try anchor_core.publicKey(auth_test_seed);
        const sig = try anchor_core.signRelayAuth(auth_test_seed, challenge, auth_test_did);
        var auth_buf: [relay.auth_frame_max]u8 = undefined;
        try newc.sendFrame(.binary, try relay.buildAuth(&auth_buf, anchor_pub, sig, auth_test_did));
        const ok = (try newc.nextBinary(&reply)) orelse return error.TestUnexpectedResult;
        try testing.expectEqual(relay.ServerOp.auth_ok, try relay.parseServerOp(ok));
    }

    // A key the directory does NOT publish for that DID gets no auth_ok — the
    // whole point of the second half. The signature here is perfectly valid; it
    // is just made with a key that is nobody's.
    //
    // And in the TRANSITION WINDOW the connection SURVIVES that failure and is
    // served anonymously. That is deliberate and it is the property this block
    // exists to pin: the directory leg is a network fetch to someone else's
    // PDS, and if a failed fetch killed the connection we would have made every
    // client's chat depend on it — turning a hardening feature into a new way
    // for messaging to break. Here the next deposit still lands.
    {
        var impostor: TestClient = undefined;
        try connectClientAuth(&impostor, io, port, "relay-test-token", true);
        defer impostor.stream.close(io);
        var reply: [relay.deliver_frame_len]u8 = undefined;
        const chal_frame = (try impostor.nextBinary(&reply)) orelse return error.TestUnexpectedResult;
        const challenge = switch (try relay.parseServerOp(chal_frame)) {
            .challenge => |c| c,
            else => return error.TestUnexpectedResult,
        };
        const other_seed: [32]u8 = @splat(0x77);
        const anchor_pub = try anchor_core.publicKey(other_seed);
        const sig = try anchor_core.signRelayAuth(other_seed, challenge, auth_test_did);
        var auth_buf: [relay.auth_frame_max]u8 = undefined;
        try impostor.sendFrame(.binary, try relay.buildAuth(&auth_buf, anchor_pub, sig, auth_test_did));

        // No auth_ok comes back — the NEXT frame is the answer to the deposit
        // below, never an admission. (Asserting "nothing arrives" would mean
        // blocking on a socket that is deliberately still open, so the
        // assertion is made on what DOES arrive.)
        const mailbox: [relay.mailbox_id_len]u8 = @splat(0x32);
        const blob: [relay.bucket_len]u8 = @splat(0x88);
        var dep_buf: [relay.deposit_frame_len]u8 = undefined;
        try impostor.sendFrame(.binary, relay.buildDeposit(&dep_buf, mailbox, &blob));
        const got = (try impostor.nextBinary(&reply)) orelse return error.TestUnexpectedResult;
        try testing.expectEqual(relay.ServerOp.deposit_ok, try relay.parseServerOp(got));
    }
}

test "relay: the flip — with auth REQUIRED, an anonymous connection deposits nothing" {
    const gpa = testing.allocator;
    const io = std.testing.io;

    var store: relay.Store = .{};
    defer relay.deinit(gpa, &store);
    var lock: StoreLock = .{};
    var cache: AuthCache = .{};
    defer cache.deinit(gpa);
    var stop: std.atomic.Value(bool) = .init(false);

    var bound = try fixture.listenLoopback(io, 25897);
    const port = bound.port;
    const cfg: ServeConfig = .{
        .port = port,
        .token = "relay-test-token",
        .stop = &stop,
        .require_auth = true,
        .verify_did = testVerifyDid,
        .auth_cache = &cache,
    };
    const server_thread = try std.Thread.spawn(.{}, runBoundForTest, .{ gpa, io, &bound.server, &store, cfg, &lock });
    defer {
        stop.store(true, .release);
        server_thread.join();
        bound.server.deinit(io);
    }

    // A client with the shared token but no identity is refused at the UPGRADE —
    // before a socket is spoken on, let alone a blob stored. The baked token is
    // no longer enough to be anybody, which was the whole vulnerability.
    {
        var anon: TestClient = undefined;
        try testing.expectError(error.BadRequest, connectClient(&anon, io, port, "relay-test-token"));
        anon.stream.close(io);
    }

    // An IMPOSTOR — a valid signature under a key the directory does not
    // publish for that DID — is cut off. With auth required, a socket that
    // cannot prove who it is has no business staying open; the server closes
    // it, and the client's next read is a clean end of stream.
    {
        var impostor: TestClient = undefined;
        try connectClientAuth(&impostor, io, port, "relay-test-token", true);
        defer impostor.stream.close(io);
        var reply: [relay.deliver_frame_len]u8 = undefined;
        const chal_frame = (try impostor.nextBinary(&reply)) orelse return error.TestUnexpectedResult;
        const challenge = switch (try relay.parseServerOp(chal_frame)) {
            .challenge => |c| c,
            else => return error.TestUnexpectedResult,
        };
        const other_seed: [32]u8 = @splat(0x77);
        const anchor_pub = try anchor_core.publicKey(other_seed);
        const sig = try anchor_core.signRelayAuth(other_seed, challenge, auth_test_did);
        var auth_buf: [relay.auth_frame_max]u8 = undefined;
        try impostor.sendFrame(.binary, try relay.buildAuth(&auth_buf, anchor_pub, sig, auth_test_did));
        try testing.expect((try impostor.nextBinary(&reply)) == null); // closed, never admitted
    }

    // An authenticated client is served normally — and its deposit lands.
    var good: TestClient = undefined;
    try connectClientAuth(&good, io, port, "relay-test-token", true);
    defer good.stream.close(io);
    var reply: [relay.deliver_frame_len]u8 = undefined;
    const chal_frame = (try good.nextBinary(&reply)) orelse return error.TestUnexpectedResult;
    const challenge = switch (try relay.parseServerOp(chal_frame)) {
        .challenge => |c| c,
        else => return error.TestUnexpectedResult,
    };
    const anchor_pub = try anchor_core.publicKey(auth_test_seed);
    const sig = try anchor_core.signRelayAuth(auth_test_seed, challenge, auth_test_did);
    var auth_buf: [relay.auth_frame_max]u8 = undefined;
    try good.sendFrame(.binary, try relay.buildAuth(&auth_buf, anchor_pub, sig, auth_test_did));
    try testing.expectEqual(relay.ServerOp.auth_ok, try relay.parseServerOp((try good.nextBinary(&reply)) orelse return error.TestUnexpectedResult));

    const mailbox: [relay.mailbox_id_len]u8 = @splat(0x64);
    const blob: [relay.bucket_len]u8 = @splat(0x21);
    var dep_buf: [relay.deposit_frame_len]u8 = undefined;
    try good.sendFrame(.binary, relay.buildDeposit(&dep_buf, mailbox, &blob));
    try testing.expectEqual(relay.ServerOp.deposit_ok, try relay.parseServerOp((try good.nextBinary(&reply)) orelse return error.TestUnexpectedResult));

    // And a relay that REQUIRES identity with no directory to check it against
    // refuses to start: enforcing a check that means nothing is worse than
    // admitting there is none.
    try testing.expectError(error.AuthRequiresDirectory, run(gpa, io, &store, .{ .port = 1, .token = "t", .require_auth = true }, &lock));
}
