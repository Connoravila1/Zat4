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

//! B1 classification: SHELL (socket, worker thread, entropy). The Zat Chat
//! relay CLIENT (ZAT_CHAT_ROADMAP slice U5), built on `shell/stream.zig`'s
//! doctrine to the letter: a worker thread owns the socket and reconnects
//! with backoff; the render thread sees only plain-data mail drained from a
//! spinlocked Mailbox — **the network never drives the render thread.** A
//! dead relay is an empty drain and a status line, never a dead screen
//! (E2/E4); conversation state cannot be corrupted from here because none
//! crosses this boundary.
//!
//! What it speaks: the relay op vocabulary (`core/relay.zig`, the same
//! codec the server parses with) inside WebSocket binary frames
//! (`core/websocket.zig`). On connect it subscribes to ONE mailbox (ours)
//! and re-arms that subscription every reconnect — the server re-delivers
//! anything unacked, and the MLS layer above rejects replays, so
//! at-least-once composes instead of needing a reliability protocol here.
//! A delivered blob is acked as soon as its gpa-owned copy is safely in
//! the Mailbox. Outbound deposits are queued by the render thread and
//! flushed by the worker; a refusal comes back as mail, not silence (E3).
//!
//! Trust posture of the dial: the relay endpoint is OPERATOR CONFIG (env),
//! the same trusted class as the AppView tunnel and the jetstream host —
//! netguard's SSRF verdicts apply to attacker-influenced URLs, not here
//! (core/netguard.zig's own header draws exactly this line). v1 dials
//! plaintext TCP: the deployed relay is reached through the SSH tunnel,
//! the AppView's existing posture; TLS-to-Caddy is the recorded upgrade.
//!
//! This module carries OPAQUE bytes only: it neither packs nor reads the
//! bucket payload. `shell/chat_e2ee.zig` frames the MLS ciphertext into the
//! fixed bucket and derives mailbox IDs; here a bucket is just
//! `relay.bucket_len` bytes in and out.

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const Allocator = std.mem.Allocator;
const clock = @import("clock.zig");
const stream_shell = @import("stream.zig");
const relay = @import("../core/relay.zig");
const websocket = @import("../core/websocket.zig");

/// Re-exported so callers size their buckets without importing the relay
/// core (D3: the wire module stays behind this client's interface).
pub const bucket_len = relay.bucket_len;
pub const mailbox_id_len = relay.mailbox_id_len;

// ---------------------------------------------------------------------------
// The mailbox — plain-data messages, the only thing that crosses out
// ---------------------------------------------------------------------------

/// A7.2: cold union, size guard waived — slice-carrying hand-off message at
/// chat rates (the stream.zig Mail reasoning).
pub const Mail = union(enum) {
    /// One delivered bucket; `data` is gpa-owned by the message (always
    /// exactly `relay.bucket_len` bytes). Consumer calls `freeMail`.
    blob: []u8,
    /// The relay refused a deposit (mailbox_full / store_full) — surfaced
    /// so a send failure is a visible state, never silence (E3).
    refused: relay.DepositResult,
    status: []const u8,
    failure: anyerror,
};

pub fn freeMail(gpa: Allocator, mail: Mail) void {
    if (mail == .blob) gpa.free(mail.blob);
}

/// A7.2: cold struct, size guard waived — one per relay link; the
/// cross-thread hand-off point (spinlock, the stream.zig reasoning).
pub const Mailbox = struct {
    locked: std.atomic.Value(bool) = .init(false),
    items: std.ArrayList(Mail) = .empty,

    fn acquire(box: *Mailbox) void {
        while (box.locked.swap(true, .acquire)) std.atomic.spinLoopHint();
    }
    fn release(box: *Mailbox) void {
        box.locked.store(false, .release);
    }

    fn push(box: *Mailbox, gpa: Allocator, mail: Mail) void {
        box.acquire();
        defer box.release();
        // OOM drops the message; the blob was NOT acked yet in that case?
        // No — see the ack ordering in runConnection: ack is sent only
        // after a successful push, so a dropped push re-delivers later.
        box.items.append(gpa, mail) catch freeMail(gpa, mail);
    }

    /// Move all pending mail into `out` (caller frees via freeMail).
    pub fn drain(box: *Mailbox, gpa: Allocator, out: *std.ArrayList(Mail)) error{OutOfMemory}!void {
        box.acquire();
        defer box.release();
        try out.appendSlice(gpa, box.items.items);
        box.items.clearRetainingCapacity();
    }

    pub fn deinit(box: *Mailbox, gpa: Allocator) void {
        for (box.items.items) |mail| freeMail(gpa, mail);
        box.items.deinit(gpa);
    }
};

// ---------------------------------------------------------------------------
// The subsystem handle
// ---------------------------------------------------------------------------

/// One queued outbound deposit. A7.2: cold struct, size guard waived —
/// transient hand-off, a handful in flight at human send rates.
const Out = struct {
    id: [relay.mailbox_id_len]u8,
    blob: *[relay.bucket_len]u8, // gpa-owned until sent
};

/// A7.2: cold struct, size guard waived — one per live chat session.
pub const ChatRelay = struct {
    gpa: Allocator,
    io: std.Io,
    mailbox: *Mailbox,
    thread: std.Thread,
    stop: std.atomic.Value(bool),
    socket_fd: std.atomic.Value(i64),
    host: []const u8,
    port: u16,
    token: []const u8,
    /// The one mailbox this client drains (ours).
    sub: [relay.mailbox_id_len]u8,
    /// Outbound deposits, render thread → worker (spinlock hand-off).
    out_locked: std.atomic.Value(bool),
    outbox: std.ArrayList(Out),
};

/// Spawn the link. `host`/`token` are copied (E1).
pub fn start(
    gpa: Allocator,
    io: std.Io,
    mailbox: *Mailbox,
    host: []const u8,
    port: u16,
    token: []const u8,
    sub: [relay.mailbox_id_len]u8,
) !*ChatRelay {
    const cr = try gpa.create(ChatRelay);
    errdefer gpa.destroy(cr);
    const host_copy = try gpa.dupe(u8, host);
    errdefer gpa.free(host_copy);
    const token_copy = try gpa.dupe(u8, token);
    errdefer gpa.free(token_copy);
    cr.* = .{
        .gpa = gpa,
        .io = io,
        .mailbox = mailbox,
        .thread = undefined,
        .stop = .init(false),
        .socket_fd = .init(-1),
        .host = host_copy,
        .port = port,
        .token = token_copy,
        .sub = sub,
        .out_locked = .init(false),
        .outbox = .empty,
    };
    cr.thread = try std.Thread.spawn(.{}, threadMain, .{cr});
    return cr;
}

/// Queue one bucket for `id` (copied; the caller keeps its buffer). Called
/// from the render thread; the worker sends it within a poll tick.
pub fn deposit(cr: *ChatRelay, id: [relay.mailbox_id_len]u8, blob: *const [relay.bucket_len]u8) error{OutOfMemory}!void {
    const copy = try cr.gpa.create([relay.bucket_len]u8);
    errdefer cr.gpa.destroy(copy);
    copy.* = blob.*;
    while (cr.out_locked.swap(true, .acquire)) std.atomic.spinLoopHint();
    defer cr.out_locked.store(false, .release);
    try cr.outbox.append(cr.gpa, .{ .id = id, .blob = copy });
}

fn takeOutbox(cr: *ChatRelay, into: *std.ArrayList(Out)) error{OutOfMemory}!void {
    while (cr.out_locked.swap(true, .acquire)) std.atomic.spinLoopHint();
    defer cr.out_locked.store(false, .release);
    try into.appendSlice(cr.gpa, cr.outbox.items);
    cr.outbox.clearRetainingCapacity();
}

/// Stop the thread (waking a blocked read via shutdown(2)), join, free.
/// Deterministic teardown (C5).
pub fn shutdown(cr: *ChatRelay) void {
    cr.stop.store(true, .release);
    const fd = cr.socket_fd.swap(-1, .acq_rel);
    if (fd >= 0) stream_shell.shutdownSocket(fd);
    cr.thread.join();
    for (cr.outbox.items) |out| cr.gpa.destroy(out.blob);
    cr.outbox.deinit(cr.gpa);
    cr.gpa.free(cr.host);
    cr.gpa.free(cr.token);
    cr.gpa.destroy(cr);
}

// ---------------------------------------------------------------------------
// The worker
// ---------------------------------------------------------------------------

fn threadMain(cr: *ChatRelay) void {
    var attempt: u32 = 0;
    while (!cr.stop.load(.acquire)) {
        var healthy = false;
        runConnection(cr, &healthy) catch |err| {
            if (!cr.stop.load(.acquire)) cr.mailbox.push(cr.gpa, .{ .failure = err });
        };
        if (cr.stop.load(.acquire)) return;
        if (healthy) attempt = 0;
        sleepInterruptible(cr, backoffMs(attempt));
        attempt +|= 1;
    }
}

/// 1s, 2s, 4s … capped at 30s — the stream.zig shape, local so this module
/// carries no jetstream coupling.
fn backoffMs(attempt: u32) u64 {
    const shifted = @as(u64, 1_000) << @min(attempt, 5);
    return @min(shifted, 30_000);
}

fn sleepInterruptible(cr: *ChatRelay, total_ms: u64) void {
    var remaining = total_ms;
    while (remaining > 0 and !cr.stop.load(.acquire)) {
        const slice_ms: u64 = @min(remaining, 200);
        clock.sleepMillis(slice_ms);
        remaining -= slice_ms;
    }
}

fn fillRandom(io: std.Io, buf: []u8) void {
    io.randomSecure(buf) catch {
        // Masking keys and handshake nonces need unpredictability, not
        // secrecy-grade entropy; a failed syscall falls back to the clock
        // (the stream.zig posture for exactly these two uses).
        var v: u64 = @bitCast(clock.unixMicros());
        for (buf) |*b| {
            v = v *% 6364136223846793005 +% 1442695040888963407;
            b.* = @truncate(v >> 33);
        }
    };
}

fn runConnection(cr: *ChatRelay, healthy: *bool) !void {
    const gpa = cr.gpa;
    const io = cr.io;

    // Dial (operator-configured endpoint — see the header's trust note).
    var tcp: std.Io.net.Stream = blk: {
        if (std.Io.net.IpAddress.resolve(io, cr.host, cr.port)) |address| {
            var addr = address;
            break :blk try addr.connect(io, .{ .mode = .stream });
        } else |_| {}
        const name = try std.Io.net.HostName.init(cr.host);
        break :blk try name.connect(io, cr.port, .{ .mode = .stream });
    };
    defer {
        _ = cr.socket_fd.swap(-1, .acq_rel);
        tcp.close(io);
    }
    cr.socket_fd.store(stream_shell.handleToI64(tcp.socket.handle), .release);

    var read_buf: [16 * 1024]u8 = undefined;
    var write_buf: [8 * 1024]u8 = undefined;
    var tcp_reader = tcp.reader(io, &read_buf);
    var tcp_writer = tcp.writer(io, &write_buf);
    const reader = &tcp_reader.interface;
    const writer = &tcp_writer.interface;

    // --- Handshake. Emitted directly (not websocket.buildHandshake): the
    // relay's upgrade carries the Authorization service token, which the
    // fixed builder has no seat for.
    var nonce: [16]u8 = undefined;
    fillRandom(io, &nonce);
    var key_buf: [websocket.key_len]u8 = undefined;
    const key = websocket.encodeKey(nonce, &key_buf);
    var req_buf: [1024]u8 = undefined;
    const request = std.fmt.bufPrint(
        &req_buf,
        "GET /relay HTTP/1.1\r\n" ++
            "Host: {s}\r\n" ++
            "Upgrade: websocket\r\n" ++
            "Connection: Upgrade\r\n" ++
            "Sec-WebSocket-Key: {s}\r\n" ++
            "Sec-WebSocket-Version: 13\r\n" ++
            "Authorization: Bearer {s}\r\n\r\n",
        .{ cr.host, key, cr.token },
    ) catch return error.HandshakeRefused;
    try writer.writeAll(request);
    try writer.flush();

    var response_buf: [4096]u8 = undefined;
    var response_len: usize = 0;
    while (true) {
        if (websocket.handshakeAccepted(response_buf[0..response_len], key)) |ok| {
            if (!ok) return error.HandshakeRefused;
            break;
        }
        if (response_len == response_buf.len) return error.HandshakeRefused;
        const n = try readAvailable(reader, response_buf[response_len..]) orelse
            return error.ConnectionClosed;
        response_len += n;
    }

    // Frame stream may begin in the same read as the 101 — seed it (the
    // stream.zig field lesson).
    var acc: [16 * 1024]u8 = undefined;
    const head_end = (std.mem.indexOf(u8, response_buf[0..response_len], "\r\n\r\n") orelse
        return error.HandshakeRefused) + 4;
    const leftover = response_buf[head_end..response_len];
    @memcpy(acc[0..leftover.len], leftover);
    var acc_len: usize = leftover.len;

    // Subscribe (re-armed on every reconnect; the server re-delivers unacked).
    {
        var sub_op: [relay.subscribe_frame_len]u8 = undefined;
        try sendFrame(cr, writer, .binary, relay.buildSubscribe(&sub_op, cr.sub));
    }
    cr.mailbox.push(gpa, .{ .status = "relay: connected" });
    healthy.* = true;

    var pending_out: std.ArrayList(Out) = .empty;
    defer {
        for (pending_out.items) |out| gpa.destroy(out.blob);
        pending_out.deinit(gpa);
    }

    var idle_ms: u64 = 0;
    var sent_ping = false;
    while (!cr.stop.load(.acquire)) {
        // Flush queued deposits first — a send should not wait on quiet RX.
        try takeOutbox(cr, &pending_out);
        while (pending_out.items.len > 0) {
            const out = pending_out.items[0];
            var dep_op: [relay.deposit_frame_len]u8 = undefined;
            try sendFrame(cr, writer, .binary, relay.buildDeposit(&dep_op, out.id, out.blob));
            gpa.destroy(out.blob);
            _ = pending_out.orderedRemove(0);
        }

        // Drain complete frames.
        var at: usize = 0;
        while (try websocket.decodeFrame(acc[at..acc_len])) |decoded| {
            at += decoded.consumed;
            idle_ms = 0;
            sent_ping = false;
            switch (decoded.frame.opcode) {
                .binary => switch (relay.parseServerOp(decoded.frame.payload) catch return error.ProtocolViolation) {
                    .deliver => |d| {
                        // Copy → mailbox → ONLY THEN ack. If the push (or
                        // this process) dies first, the un-acked blob
                        // re-delivers on reconnect: at-least-once.
                        const copy = try gpa.dupe(u8, d.blob);
                        cr.mailbox.push(gpa, .{ .blob = copy });
                        var ack_op: [relay.ack_frame_len]u8 = undefined;
                        try sendFrame(cr, writer, .binary, relay.buildAck(&ack_op, d.id));
                    },
                    .deposit_ok => {},
                    .refused => |r| cr.mailbox.push(gpa, .{ .refused = r }),
                },
                .ping => try sendFrame(cr, writer, .pong, decoded.frame.payload),
                .close => return error.ConnectionClosed,
                .pong => {},
                else => return error.ProtocolViolation,
            }
        }
        if (at > 0) {
            std.mem.copyForwards(u8, acc[0 .. acc_len - at], acc[at..acc_len]);
            acc_len -= at;
        }
        if (acc_len == acc.len) return error.ProtocolViolation;

        // The stream.zig read rule: poll is a bounded sleep for stop
        // responsiveness only; if userspace already buffers bytes, read now.
        if (reader.bufferedLen() == 0) {
            const ready: usize = if (comptime builtin.os.tag == .windows) 1 else blk: {
                var pfds = [_]posix.pollfd{.{ .fd = tcp.socket.handle, .events = posix.POLL.IN, .revents = 0 }};
                break :blk posix.poll(&pfds, 250) catch 0;
            };
            if (ready == 0) {
                // Liveness is probed, not assumed (the stream.zig clock):
                // 30 s quiet → ping; 30 s more without ANY frame → dead.
                idle_ms += 250;
                if (sent_ping and idle_ms >= 60_000) return error.PingUnanswered;
                if (!sent_ping and idle_ms >= 30_000) {
                    try sendFrame(cr, writer, .ping, "");
                    sent_ping = true;
                }
                continue;
            }
        }
        const n = try readAvailable(reader, acc[acc_len..]) orelse return error.ConnectionClosed;
        acc_len += n;
    }
}

fn sendFrame(cr: *ChatRelay, writer: *std.Io.Writer, opcode: websocket.Opcode, payload: []const u8) !void {
    var mask: [4]u8 = undefined;
    fillRandom(cr.io, &mask);
    var frame_buf: [relay.deposit_frame_len + websocket.max_header_len]u8 = undefined;
    const frame = websocket.encodeFrame(&frame_buf, opcode, payload, mask) catch return error.ProtocolViolation;
    try writer.writeAll(frame);
    try writer.flush();
}

/// The stream.zig read idiom (local copy; plaintext TCP, no TLS layer).
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

// ---------------------------------------------------------------------------
// Tests (C6) — the full loopback E2E: two REAL clients exchanging an opaque
// bucket through the REAL relay server (relay_serve.run's own loop). The
// payload here is arbitrary bytes; the relay carries them blind, exactly as
// it carries MLS ciphertext in production.
// ---------------------------------------------------------------------------

const testing = std.testing;
const relay_serve = @import("relay_serve.zig");

test "chat_relay loopback: two clients exchange an opaque bucket through the real relay" {
    const gpa = testing.allocator;
    const io = std.testing.io;

    // The real U4 server, own thread, own port.
    var store: relay.Store = .{};
    defer relay.deinit(gpa, &store);
    var lock: relay_serve.StoreLock = .{};
    var stop: std.atomic.Value(bool) = .init(false);
    const port: u16 = 25911;
    const server_thread = try std.Thread.spawn(.{}, serveForTest, .{
        gpa, io, &store, relay_serve.ServeConfig{ .port = port, .token = "u5-test-token", .stop = &stop }, &lock,
    });
    defer {
        stop.store(true, .release);
        server_thread.join();
    }
    // Give the listener a beat to bind before dialing (the client retries
    // with backoff anyway; this just keeps the test fast).
    clock.sleepMillis(100);

    // Opaque mailbox IDs and a bucket of arbitrary bytes (the relay never
    // interprets either — chat_e2ee owns framing + addressing).
    const alice_box_id: [relay.mailbox_id_len]u8 = @splat(0xA1);
    const bob_box_id: [relay.mailbox_id_len]u8 = @splat(0xB2);
    var payload: [relay.bucket_len]u8 = undefined;
    for (&payload, 0..) |*b, i| b.* = @truncate(i *% 31 +% 7);

    var alice_box: Mailbox = .{};
    defer alice_box.deinit(gpa);
    var bob_box: Mailbox = .{};
    defer bob_box.deinit(gpa);

    const alice = try start(gpa, io, &alice_box, "127.0.0.1", port, "u5-test-token", alice_box_id);
    defer shutdown(alice);
    const bob = try start(gpa, io, &bob_box, "127.0.0.1", port, "u5-test-token", bob_box_id);
    defer shutdown(bob);

    // Alice → Bob: deposit the bucket to Bob's mailbox.
    try deposit(alice, bob_box_id, &payload);

    // Bob's drain sees it, byte-identical (bounded, politely).
    var drained: std.ArrayList(Mail) = .empty;
    defer {
        for (drained.items) |m| freeMail(gpa, m);
        drained.deinit(gpa);
    }
    var got = false;
    var waited_ms: u64 = 0;
    while (waited_ms < 10_000 and !got) {
        try bob_box.drain(gpa, &drained);
        for (drained.items) |m| {
            if (m == .blob) {
                try testing.expectEqualSlices(u8, &payload, m.blob);
                got = true;
            }
        }
        if (got) break;
        clock.sleepMillis(20);
        waited_ms += 20;
    }
    try testing.expect(got);

    // Bob acked on receipt → the store forgets (delivered means deleted).
    waited_ms = 0;
    while (waited_ms < 5_000) {
        lock.lock();
        const left = relay.pendingCount(&store, bob_box_id);
        lock.unlock();
        if (left == 0) break;
        clock.sleepMillis(20);
        waited_ms += 20;
    }
    lock.lock();
    const left = relay.pendingCount(&store, bob_box_id);
    lock.unlock();
    try testing.expectEqual(@as(u32, 0), left);
}

fn serveForTest(gpa: Allocator, io: std.Io, store: *relay.Store, cfg: relay_serve.ServeConfig, lock: *relay_serve.StoreLock) void {
    relay_serve.run(gpa, io, store, cfg, lock) catch {};
}
