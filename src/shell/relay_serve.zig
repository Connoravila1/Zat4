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
const Allocator = std.mem.Allocator;
const relay = @import("../core/relay.zig");
const websocket = @import("../core/websocket.zig");
const clock = @import("clock.zig");

/// A7.2: cold config, one per process.
pub const ServeConfig = struct {
    port: u16 = 2589,
    /// Shared service token (`Authorization: Bearer <token>` on the upgrade
    /// request). Empty ⇒ FAIL CLOSED, same posture as the AppView gate. A
    /// service gate, deliberately not identity — the relay knows no one.
    token: []const u8 = "",
    limits: relay.Limits = .{},
    /// How often the TTL sweep runs, seconds.
    sweep_every: i64 = 60,
    /// Test hook: set true to make `run` return (and its threads exit).
    stop: ?*std.atomic.Value(bool) = null,
};

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

pub fn run(gpa: Allocator, io: std.Io, store: *relay.Store, cfg: ServeConfig, lock: *StoreLock) !void {
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
                .binary => try handleOp(gpa, decoded.frame.payload, store, cfg, lock, writer, &subs, &sent, &subs_n),
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
    payload: []u8,
    store: *relay.Store,
    cfg: ServeConfig,
    lock: *StoreLock,
    writer: *std.Io.Writer,
    subs: *[max_subs][relay.mailbox_id_len]u8,
    sent: *[max_subs]u32,
    subs_n: *usize,
) ConnError!void {
    const op = relay.parseClientOp(payload) catch return error.BadRequest;
    switch (op) {
        .deposit => |d| {
            const now = clock.unixSeconds();
            lock.lock();
            const result = relay.deposit(gpa, store, cfg.limits, d.id, d.blob, now) catch {
                lock.unlock();
                return error.BadRequest; // OOM: shed this connection, keep the store
            };
            lock.unlock();
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
    const addr: std.Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    c.stream = try addr.connect(io, .{ .mode = .stream });
    c.reader = c.stream.reader(io, &c.read_buf);
    c.writer = c.stream.writer(io, &c.write_buf);

    // The upgrade, with the service token (buildHandshake carries no
    // Authorization — U5's client gains that; the raw form here IS the test
    // that the server's gate reads it).
    var req_buf: [512]u8 = undefined;
    const req = try std.fmt.bufPrint(
        &req_buf,
        "GET /relay HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nAuthorization: Bearer {s}\r\n\r\n",
        .{token},
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
