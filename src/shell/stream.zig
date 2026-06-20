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

//! B1 classification: SHELL. The **stream subsystem** — the philosophy's
//! actor pattern made concrete: it runs on its own thread, owns its own
//! socket, buffers, and arena (C4), talks to the rest of the app ONLY by
//! plain-data messages through a mailbox (E1), and fails alone — any
//! error tears down the connection, never the app, and the thread
//! reconnects on the core's backoff schedule, resuming from the last
//! cursor (E2).
//!
//! Wire knowledge lives elsewhere: frames in core/websocket.zig, events
//! in core/jetstream.zig (both sealed, D1). This file only moves bytes
//! and copies values.
//!
//! Subscription doctrine, learned the hard way: Jetstream streams per the
//! CURRENT options from the instant of the 101, and an absent `wantedDids`
//! means the whole network. The full filter therefore rides in the
//! subscribe URL (repeated `wantedDids=` params, the documented form);
//! `options_update` remains the recorded upgrade for >64 DIDs.
//!
//! TLS note, recorded: Zig 0.16 is pre-release and `tls.Client.Options`
//! differs between snapshots (the `ca` payload and the realtime field).
//! `dialTls` comptime-detects the shape the building std declares, with
//! each branch cribbed from that std's own http.Client — the same drift
//! containment as the clock fix (roadmap caution 1a).

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const Allocator = std.mem.Allocator;
const clock = @import("clock.zig");
const websocket = @import("../core/websocket.zig");
const jetstream = @import("../core/jetstream.zig");
const feed_core = @import("../core/feed.zig");
const lexicon = @import("../core/lexicon.zig");

// ---------------------------------------------------------------------------
// The mailbox — plain-data messages, the only thing that crosses out
// ---------------------------------------------------------------------------

pub const Mail = union(enum) {
    /// A live post; every string is gpa-owned by the message. The
    /// consumer ingests, then calls `freePost`.
    post: feed_core.LivePostInput,
    /// A static status line.
    status: []const u8,
    /// A connection failure, as a value — the UI formats the error name,
    /// so a field report can say WHICH error is cycling (E1/E3).
    failure: anyerror,
};

pub const Mailbox = struct {
    // A7.2: cold struct, size guard waived — one per stream; the cross-thread hand-off point.

    // A spinlock rather than a mutex, deliberately: exactly two threads,
    // critical sections of a few instructions, contention at human posting
    // rates — and `std.atomic` is stable across 0.16-dev snapshots where
    // the mutex API is not (roadmap caution 1a).
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
        // A full mailbox under OOM drops the message — the stream replays
        // from its cursor on the next connection, so nothing is lost for
        // long (recorded policy).
        box.items.append(gpa, mail) catch {
            if (mail == .post) freePost(gpa, mail.post);
        };
    }

    /// Move all pending mail into `out` (caller frees post strings).
    pub fn drain(box: *Mailbox, gpa: Allocator, out: *std.ArrayList(Mail)) error{OutOfMemory}!void {
        box.acquire();
        defer box.release();
        try out.appendSlice(gpa, box.items.items);
        box.items.clearRetainingCapacity();
    }

    pub fn deinit(box: *Mailbox, gpa: Allocator) void {
        for (box.items.items) |mail| {
            if (mail == .post) freePost(gpa, mail.post);
        }
        box.items.deinit(gpa);
    }
};

pub fn freePost(gpa: Allocator, post: feed_core.LivePostInput) void {
    gpa.free(post.did);
    gpa.free(post.uri);
    gpa.free(post.cid);
    gpa.free(post.text);
    if (post.reply_parent_cid.len > 0) gpa.free(post.reply_parent_cid);
    if (post.reply_root_cid.len > 0) gpa.free(post.reply_root_cid);
}

fn dupePost(gpa: Allocator, live: jetstream.LivePost) error{OutOfMemory}!feed_core.LivePostInput {
    const did = try gpa.dupe(u8, live.did);
    errdefer gpa.free(did);
    const uri = try gpa.dupe(u8, live.uri);
    errdefer gpa.free(uri);
    const cid = try gpa.dupe(u8, live.cid);
    errdefer gpa.free(cid);
    const text = try gpa.dupe(u8, live.text);
    errdefer gpa.free(text);
    const parent = if (live.reply_parent_cid.len > 0) try gpa.dupe(u8, live.reply_parent_cid) else "";
    errdefer if (parent.len > 0) gpa.free(parent);
    const root = if (live.reply_root_cid.len > 0) try gpa.dupe(u8, live.reply_root_cid) else "";
    return .{
        .did = did,
        .handle = "", // the store maps known DIDs; unknowns render by DID
        .uri = uri,
        .cid = cid,
        .text = text,
        .reply_parent_cid = parent,
        .reply_root_cid = root,
        .created_at = live.created_at,
    };
}

// ---------------------------------------------------------------------------
// The subsystem handle
// ---------------------------------------------------------------------------

pub const Stream = struct {
    // A7.2: cold struct, size guard waived — one per live session.

    gpa: Allocator,
    io: std.Io,
    mailbox: *Mailbox,
    thread: std.Thread,
    stop: std.atomic.Value(bool),
    socket_fd: std.atomic.Value(i64),
    host: []const u8,
    port: u16,
    use_tls: bool,
    dids: []const []const u8,
    /// Optional transcript fd (ZAT_STREAM_LOG): every connect, frame,
    /// reduce verdict, and error, timestamp-free and append-only — the
    /// instrument that turns "it doesn't work" into a line number. -1 off.
    log_fd: i32,
    /// Subscription growth channel: the UI deposits a fresh full DID list
    /// (gpa-duped, E1); the thread installs it and re-arms the server with
    /// an options_update. Spinlock for the same reasons as the mailbox.
    pending_locked: std.atomic.Value(bool),
    pending_dids: ?[]const []const u8,
};

fn freeDidList(gpa: Allocator, list: []const []const u8) void {
    for (list) |d| gpa.free(d);
    gpa.free(list);
}

/// Replace the subscription with `dids` (copied). Takes effect within a
/// second while connected (in-band options_update) and shapes the next
/// reconnect URL either way.
pub fn updateDids(stream: *Stream, dids: []const []const u8) error{OutOfMemory}!void {
    const copy = try stream.gpa.alloc([]const u8, dids.len);
    var copied: usize = 0;
    errdefer {
        for (copy[0..copied]) |d| stream.gpa.free(d);
        stream.gpa.free(copy);
    }
    for (dids, copy) |src, *dst| {
        dst.* = try stream.gpa.dupe(u8, src);
        copied += 1;
    }
    while (stream.pending_locked.swap(true, .acquire)) std.atomic.spinLoopHint();
    const old = stream.pending_dids;
    stream.pending_dids = copy;
    stream.pending_locked.store(false, .release);
    if (old) |list| freeDidList(stream.gpa, list);
}

fn takePending(stream: *Stream) ?[]const []const u8 {
    while (stream.pending_locked.swap(true, .acquire)) std.atomic.spinLoopHint();
    const taken = stream.pending_dids;
    stream.pending_dids = null;
    stream.pending_locked.store(false, .release);
    return taken;
}

/// Install a pending DID list as the canonical subscription and, when
/// connected, re-arm the server with an options_update carrying it.
fn applyPendingDids(stream: *Stream, conn: ?*Conn) !void {
    const fresh = takePending(stream) orelse return;
    freeDidList(stream.gpa, stream.dids);
    stream.dids = fresh;
    logLine(stream, "subscription: now {d} dids", .{fresh.len});
    if (conn) |live| {
        var arena_state = std.heap.ArenaAllocator.init(stream.gpa);
        defer arena_state.deinit();
        const message = try jetstream.buildOptionsUpdate(arena_state.allocator(), stream.dids);
        try sendFrame(stream, live, .text, message);
        logLine(stream, "options_update: sent ({d} dids)", .{stream.dids.len});
    }
}

/// Spawn the subsystem. `host`/`dids` are copied — the caller's memory
/// is not shared with the thread (E1).
pub fn start(
    gpa: Allocator,
    io: std.Io,
    mailbox: *Mailbox,
    host: []const u8,
    port: u16,
    use_tls: bool,
    dids: []const []const u8,
    log_path: ?[]const u8,
) !*Stream {
    const stream = try gpa.create(Stream);
    errdefer gpa.destroy(stream);
    const host_copy = try gpa.dupe(u8, host);
    errdefer gpa.free(host_copy);
    const dids_copy = try gpa.alloc([]const u8, dids.len);
    var copied: usize = 0;
    errdefer {
        for (dids_copy[0..copied]) |d| gpa.free(d);
        gpa.free(dids_copy);
    }
    for (dids, dids_copy) |src, *dst| {
        dst.* = try gpa.dupe(u8, src);
        copied += 1;
    }
    stream.* = .{
        .gpa = gpa,
        .io = io,
        .mailbox = mailbox,
        .thread = undefined,
        .stop = .init(false),
        .socket_fd = .init(-1),
        .host = host_copy,
        .port = port,
        .use_tls = use_tls,
        .dids = dids_copy,
        .log_fd = if (log_path) |path| openLogFd(path) else -1,
        .pending_locked = .init(false),
        .pending_dids = null,
    };
    logLine(stream, "start: host={s} dids={d} tls={}", .{ host, dids.len, use_tls });
    stream.thread = try std.Thread.spawn(.{}, threadMain, .{stream});
    return stream;
}

// --- cross-OS socket plumbing (the shutdown-wake trick must work on both) ---

/// Darwin socket/file primitives, self-declared from libSystem (the
/// kernel32 doctrine). `open` is variadic because it is variadic in C —
/// Apple's arm64 ABI passes variadic arguments on the stack.
const dstream = struct {
    // Not a record: an extern-fn namespace (no fields). A1/A7 do not apply.
    extern "c" fn shutdown(fd: c_int, how: c_int) c_int;
    extern "c" fn open(path: [*:0]const u8, flags: c_int, ...) c_int;
    extern "c" fn write(fd: c_int, buf: [*]const u8, n: usize) isize;
    extern "c" fn close(fd: c_int) c_int;
};

const ws2 = struct {
    // Not a record: an extern-fn namespace (no fields). A1/A7 do not apply.

    extern "ws2_32" fn shutdown(s: usize, how: i32) callconv(.winapi) i32;
};

fn handleToI64(h: anytype) i64 {
    const u: u64 = switch (@typeInfo(@TypeOf(h))) {
        .pointer => @intFromPtr(h),
        else => @intCast(h),
    };
    return @bitCast(u);
}

fn shutdownSocket(fd: i64) void {
    if (comptime builtin.os.tag == .windows) {
        _ = ws2.shutdown(@intCast(@as(u64, @bitCast(fd))), 2); // SD_BOTH
    } else if (comptime builtin.os.tag.isDarwin()) {
        _ = dstream.shutdown(@intCast(fd), 2); // SHUT_RDWR
    } else {
        _ = std.os.linux.shutdown(@intCast(fd), std.os.linux.SHUT.RDWR);
    }
}

/// Stop the thread (waking any blocked read via shutdown(2)), join it,
/// and free everything it owned. Deterministic teardown (C5).
pub fn shutdown(stream: *Stream) void {
    stream.stop.store(true, .release);
    const fd = stream.socket_fd.swap(-1, .acq_rel);
    if (fd >= 0) shutdownSocket(fd);
    stream.thread.join();
    if (takePending(stream)) |pending| freeDidList(stream.gpa, pending);
    if (comptime builtin.os.tag == .linux) {
        if (stream.log_fd >= 0) _ = std.os.linux.close(stream.log_fd);
    } else if (comptime builtin.os.tag.isDarwin()) {
        if (stream.log_fd >= 0) _ = dstream.close(stream.log_fd);
    }
    const gpa = stream.gpa;
    gpa.free(stream.host);
    for (stream.dids) |d| gpa.free(d);
    gpa.free(stream.dids);
    gpa.destroy(stream);
}

// ---------------------------------------------------------------------------
// The thread
// ---------------------------------------------------------------------------

fn threadMain(stream: *Stream) void {
    var cursor: i64 = 0;
    var attempt: u32 = 0;
    while (!stream.stop.load(.acquire)) {
        applyPendingDids(stream, null) catch |err| {
            stream.mailbox.push(stream.gpa, .{ .failure = err });
        };
        var delivered = false;
        runConnection(stream, &cursor, &delivered) catch |err| {
            if (!stream.stop.load(.acquire)) {
                logLine(stream, "error: {s}", .{@errorName(err)});
                stream.mailbox.push(stream.gpa, .{ .failure = err });
            }
        };
        if (stream.stop.load(.acquire)) return;
        if (delivered) attempt = 0; // a healthy connection resets patience
        sleepInterruptible(stream, jetstream.streamBackoffMs(attempt));
        attempt +|= 1;
    }
}

/// Sleep in slices so a shutdown never waits out a 30 s backoff.
fn sleepInterruptible(stream: *Stream, total_ms: u64) void {
    var remaining = total_ms;
    while (remaining > 0 and !stream.stop.load(.acquire)) {
        const slice_ms: u64 = @min(remaining, 200);
        clock.sleepMillis(slice_ms);
        remaining -= slice_ms;
    }
}

/// The transcript fd lives on the kernel-stable syscall surface
/// (`posix.open` exists on master but not on every 0.16-dev snapshot —
/// caution 1a, in the other direction this time).
fn openLogFd(path: []const u8) i32 {
    if (comptime builtin.os.tag == .windows) return -1; // transcript: POSIX-only v1 (recorded)
    if (path.len == 0 or path.len >= 255) return -1;
    var z: [256]u8 = undefined;
    @memcpy(z[0..path.len], path);
    z[path.len] = 0;
    if (comptime builtin.os.tag.isDarwin()) {
        // O_WRONLY|O_CREAT|O_APPEND, 0o644 — the stream transcript works
        // on macOS through the same libSystem doctrine as the cache.
        return dstream.open(z[0..path.len :0].ptr, 0x209, @as(c_int, 0o644));
    }
    const rc = std.os.linux.open(
        z[0..path.len :0].ptr,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true },
        0o644,
    );
    const signed: isize = @bitCast(rc);
    return if (signed < 0) -1 else @intCast(signed);
}

fn logLine(stream: *Stream, comptime fmt: []const u8, args: anytype) void {
    if (stream.log_fd < 0) return;
    var buf: [512]u8 = undefined;
    const line = std.fmt.bufPrint(&buf, fmt ++ "\n", args) catch return;
    if (comptime builtin.os.tag == .linux) {
        _ = std.os.linux.write(stream.log_fd, line.ptr, line.len);
    } else if (comptime builtin.os.tag.isDarwin()) {
        _ = dstream.write(stream.log_fd, line.ptr, line.len);
    }
}

fn fillRandom(io: std.Io, buf: []u8) void {
    // Pre-release drift: my snapshot routes entropy through Io; master
    // uses std.crypto.random (its own http.Client does the same).
    if (comptime @hasDecl(std.Io, "random")) {
        io.random(buf);
    } else {
        std.crypto.random.bytes(buf);
    }
}

/// One POSIX-read-shaped pull through a Reader interface: at least one
/// byte, or null at end of stream. (`readSliceShort` blocks until its
/// whole buffer fills, and `readVec` may return 0 after filling only the
/// reader's INTERNAL buffer — e.g. the TLS reader decrypts there. Serve
/// from `buffered`, refilling with exactly one underlying read first.)
fn readAvailable(reader: *std.Io.Reader, dst: []u8) error{ReadFailed}!?usize {
    // Loop: a fill can succeed yet yield zero cleartext (TLS 1.3
    // post-handshake records such as session tickets decrypt to nothing).
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

const Conn = struct {
    // A7.2: cold struct, size guard waived — one per connection attempt.

    tcp: std.Io.net.Stream,
    tcp_reader: std.Io.net.Stream.Reader,
    tcp_writer: std.Io.net.Stream.Writer,
    tls: ?std.crypto.tls.Client,
    bufs: [4][]u8,

    fn reader(conn: *Conn) *std.Io.Reader {
        if (conn.tls) |*client| return &client.reader;
        return &conn.tcp_reader.interface;
    }
    fn writer(conn: *Conn) *std.Io.Writer {
        if (conn.tls) |*client| return &client.writer;
        return &conn.tcp_writer.interface;
    }

    /// Flush all the way to the wire. The TLS writer's flush only STAGES
    /// ciphertext into the socket writer's buffer — the socket writer must
    /// then be flushed itself, or the bytes never leave the process.
    fn flushOut(conn: *Conn) !void {
        try conn.writer().flush();
        if (conn.tls != null) try conn.tcp_writer.interface.flush();
    }
};

fn runConnection(stream: *Stream, cursor: *i64, delivered: *bool) !void {
    const gpa = stream.gpa;
    const io = stream.io;

    var conn: Conn = undefined;
    try dial(stream, &conn);
    defer {
        _ = stream.socket_fd.swap(-1, .acq_rel);
        conn.tcp.close(io);
        for (conn.bufs) |buf| gpa.free(buf);
    }
    stream.socket_fd.store(handleToI64(conn.tcp.socket.handle), .release);

    // --- WebSocket handshake (core builds the strings; we move them) ---
    var nonce: [16]u8 = undefined;
    fillRandom(io, &nonce);
    var key_buf: [websocket.key_len]u8 = undefined;
    const key = websocket.encodeKey(nonce, &key_buf);

    var path_builder: std.ArrayList(u8) = .empty;
    defer path_builder.deinit(gpa);
    try path_builder.appendSlice(gpa, "/subscribe?wantedCollections=");
    try path_builder.appendSlice(gpa, lexicon.collection.post);
    // The URL bootstraps with at most 64 DIDs; the authoritative full
    // list follows in-band the moment the socket opens (options_update).
    const url_dids = stream.dids[0..@min(stream.dids.len, 64)];
    for (url_dids) |did| {
        try path_builder.appendSlice(gpa, "&wantedDids=");
        try path_builder.appendSlice(gpa, did);
    }
    // Clamp the replay window: the server replays by scanning its whole
    // firehose DB from the cursor (rate-limited) and tears down slow
    // subscribers mid-burst — a stale cursor is an invitation to both.
    const now_us: i64 = clock.unixMicros();
    const send_cursor = jetstream.clampCursor(cursor.*, now_us);
    if (send_cursor > 0) {
        var cursor_buf: [40]u8 = undefined;
        try path_builder.appendSlice(gpa, std.fmt.bufPrint(&cursor_buf, "&cursor={d}", .{send_cursor}) catch unreachable);
    }
    const path = path_builder.items;
    logLine(stream, "cursor: saved={d} sent={d}", .{ cursor.*, send_cursor });
    logLine(stream, "subscribe: {s}", .{path[0..@min(path.len, 380)]});

    // Sized for what it carries: a 64-DID filter alone is ~2.6 KB of URL.
    // (The original fixed 512 bytes failed instantly in the field — the
    // single-DID loopback never exercised scale; now one does.)
    const handshake_buf = try gpa.alloc(u8, path.len + stream.host.len + 256);
    defer gpa.free(handshake_buf);
    const request = try websocket.buildHandshake(handshake_buf, stream.host, path, key);
    try conn.writer().writeAll(request);
    try conn.flushOut();
    logLine(stream, "handshake: sent ({d}B path)", .{path.len});

    var response_buf: [8192]u8 = undefined;
    var response_len: usize = 0;
    while (true) {
        if (websocket.handshakeAccepted(response_buf[0..response_len], key)) |ok| {
            if (!ok) return error.HandshakeRefused;
            break;
        }
        if (response_len == response_buf.len) return error.HandshakeRefused;
        const n = try readAvailable(conn.reader(), response_buf[response_len..]) orelse
            return error.ConnectionClosed;
        response_len += n;
    }

    // --- The frame loop ---
    const frame_buf = try gpa.alloc(u8, 256 * 1024);
    defer gpa.free(frame_buf);

    // Whatever followed the 101 in the same read IS the start of the frame
    // stream — discard it and every later frame boundary is misaligned
    // (the original Phase 7 field failure: a permanent ProtocolViolation →
    // reconnect loop). Seed it.
    const head_end = (std.mem.indexOf(u8, response_buf[0..response_len], "\r\n\r\n") orelse
        return error.HandshakeRefused) + 4;
    const leftover = response_buf[head_end..response_len];
    @memcpy(frame_buf[0..leftover.len], leftover);
    var buffered: usize = leftover.len;
    stream.mailbox.push(gpa, .{ .status = "live: connected" });
    logLine(stream, "handshake: accepted ({d}B leftover seeded)", .{leftover.len});

    // Re-arm the filter in-band, every connect: the URL was the bootstrap,
    // this is the authority (and the full list when it exceeds the URL cap).
    {
        var options_arena = std.heap.ArenaAllocator.init(gpa);
        defer options_arena.deinit();
        const message = try jetstream.buildOptionsUpdate(options_arena.allocator(), stream.dids);
        try sendFrame(stream, &conn, .text, message);
        logLine(stream, "options_update: sent ({d} dids)", .{stream.dids.len});
    }

    var event_arena = std.heap.ArenaAllocator.init(gpa);
    defer event_arena.deinit();

    var idle_ms: u64 = 0;
    var sent_ping = false;
    while (!stream.stop.load(.acquire)) {
        while (try websocket.decodeFrame(frame_buf[0..buffered])) |decoded| {
            idle_ms = 0;
            sent_ping = false;
            switch (decoded.frame.opcode) {
                .text => {
                    _ = event_arena.reset(.retain_capacity);
                    if (try jetstream.reduce(event_arena.allocator(), decoded.frame.payload)) |live| {
                        logLine(stream, "event: post {s}", .{live.cid});
                        const post = try dupePost(gpa, live);
                        stream.mailbox.push(gpa, .{ .post = post });
                        cursor.* = live.time_us;
                        delivered.* = true;
                    } else {
                        logLine(stream, "event: skipped ({d}B)", .{decoded.frame.payload.len});
                    }
                },
                .ping => {
                    logLine(stream, "ping: received, pong sent", .{});
                    try sendFrame(stream, &conn, .pong, decoded.frame.payload);
                },
                .close => return error.ConnectionClosed,
                .pong => logLine(stream, "pong: received", .{}),
                else => {},
            }
            std.mem.copyForwards(u8, frame_buf, frame_buf[decoded.consumed..buffered]);
            buffered -= decoded.consumed;
        }
        if (buffered == frame_buf.len) return error.FrameTooLong;
        try applyPendingDids(stream, &conn);

        // Nothing decodable in `frame_buf`. On a TLS connection the bytes
        // we need may already have left the kernel socket: the TLS client
        // pulls ciphertext into `tcp_reader.interface` and decrypts into
        // `tls.reader`, so `poll` on the raw socket fd can read 0 forever
        // while a whole record sits in userspace waiting to be read.
        // (The original code polled the raw fd and SKIPPED the read when it
        // returned 0 — so the read that drains those buffers was never
        // reached: a connected socket that never speaks again, the exact
        // field bug. No loopback test caught it because those run plaintext;
        // the TLS path is the one path they cannot cover — this file's
        // header says as much.)
        //
        // The rule that dissolves it: poll is a bounded sleep for shutdown
        // responsiveness ONLY; it never gates the read. If either userspace
        // buffer already holds bytes, read immediately without polling;
        // otherwise poll the raw fd as a 1 s timeout and read regardless of
        // its verdict. `readAvailable` already tolerates a fill that yields
        // no cleartext (TLS post-handshake records), looping until it has
        // plaintext or the stream ends — so a poll that read 0 while a
        // record was still buffered resolves on the very next read.
        const buffered_in_userspace =
            conn.reader().bufferedLen() != 0 or conn.tcp_reader.interface.bufferedLen() != 0;
        if (!buffered_in_userspace) {
            // Windows v1 takes no poll-tick: straight to the read. The
            // server's own 30 s pings keep a quiet loop waking, and
            // shutdown() still unblocks the read — the quiet-second
            // liveness bookkeeping below is the only nicety lost
            // (recorded in the roadmap's port notes).
            const ready: usize = if (comptime builtin.os.tag == .windows) 1 else blk: {
                var pfds = [_]posix.pollfd{.{
                    .fd = conn.tcp.socket.handle,
                    .events = posix.POLL.IN,
                    .revents = 0,
                }};
                break :blk posix.poll(&pfds, 1_000) catch 0;
            };
            if (ready == 0) {
                // A genuine quiet second: nothing in userspace, nothing on
                // the socket — provably nothing to read, so advance the
                // liveness clock and continue without a read. Quiet is NOT
                // dead: a followed-author filter can be silent for minutes
                // while perfectly healthy. Liveness is PROBED: 30 s of quiet
                // sends a ping; a ping unanswered for a further 30 s declares
                // death — any inbound frame, pong included, resets the clock
                // (reconnect resumes from the cursor, so nothing is lost).
                idle_ms += 1_000;
                if (sent_ping and idle_ms >= 60_000) {
                    logLine(stream, "liveness: ping unanswered 30s — declaring dead", .{});
                    return error.PingUnanswered;
                }
                if (!sent_ping and idle_ms >= 30_000) {
                    try sendFrame(stream, &conn, .ping, "");
                    sent_ping = true;
                    logLine(stream, "liveness: 30s quiet, ping sent", .{});
                }
                continue;
            }
        }
        // Either userspace already held bytes, or the socket signalled
        // readable: drain through the TLS-aware reader. This is the line the
        // raw-fd poll used to skip.
        const n = try readAvailable(conn.reader(), frame_buf[buffered..]) orelse
            return error.ConnectionClosed;
        buffered += n;
        idle_ms = 0;
        sent_ping = false;
    }
}

fn sendFrame(stream: *Stream, conn: *Conn, opcode: websocket.Opcode, payload: []const u8) !void {
    var mask: [4]u8 = undefined;
    fillRandom(stream.io, &mask);
    const out = try stream.gpa.alloc(u8, payload.len + websocket.max_header_len);
    defer stream.gpa.free(out);
    const frame = try websocket.encodeFrame(out, opcode, payload, mask);
    try conn.writer().writeAll(frame);
    try conn.flushOut();
}

// ---------------------------------------------------------------------------
// Dialing — numeric addresses directly; hostnames through HostName.connect,
// the same call std's own http.Client makes (identical on both 0.16-dev
// snapshots; roadmap caution 1a)
// ---------------------------------------------------------------------------

fn dialTcp(stream: *Stream) !std.Io.net.Stream {
    if (std.Io.net.IpAddress.resolve(stream.io, stream.host, stream.port)) |address| {
        var addr = address;
        return addr.connect(stream.io, .{ .mode = .stream });
    } else |_| {}
    const name = try std.Io.net.HostName.init(stream.host);
    return name.connect(stream.io, stream.port, .{ .mode = .stream });
}

/// Fills `conn` in place: the TLS client captures pointers to the tcp
/// reader/writer interfaces, so their addresses must be final — the
/// caller owns the storage for the connection's whole lifetime. (Returning
/// Conn by value moved those interfaces and left the TLS client pointing
/// into a dead frame; std's http.Client pins the same way, on the heap.)
fn dial(stream: *Stream, conn: *Conn) !void {
    const gpa = stream.gpa;
    const io = stream.io;

    // Buffer sizes mirror std http.Client's own TLS carving exactly: the
    // SOCKET writer and reader get precisely `min_buffer_len` (the tls
    // flush stages whole ciphertext records there and its accounting
    // assumes that size — slack trips an advance assert); the tls-side
    // read buffer is min + our cleartext window; the tls write buffer is
    // small plaintext staging.
    const tls_min: usize = if (comptime @hasDecl(std.crypto.tls.Client, "min_buffer_len"))
        std.crypto.tls.Client.min_buffer_len
    else
        17 * 1024;
    var bufs: [4][]u8 = undefined;
    var allocated: usize = 0;
    errdefer for (bufs[0..allocated]) |buf| gpa.free(buf);
    for (&bufs, [_]usize{
        tls_min, // socket read
        tls_min, // socket write
        tls_min + 64 * 1024, // tls cleartext in
        8 * 1024, // tls plaintext staging out
    }) |*buf, len| {
        buf.* = try gpa.alloc(u8, len);
        allocated += 1;
    }

    const tcp = try dialTcp(stream);
    errdefer tcp.close(io);

    conn.* = .{
        .tcp = tcp,
        .tcp_reader = undefined,
        .tcp_writer = undefined,
        .tls = null,
        .bufs = bufs,
    };
    conn.tcp_reader = conn.tcp.reader(io, bufs[0]);
    conn.tcp_writer = conn.tcp.writer(io, bufs[1]);
    if (stream.use_tls) conn.tls = try dialTls(stream, conn, bufs[2], bufs[3]);
}

fn dialTls(
    stream: *Stream,
    conn: *Conn,
    tls_read_buf: []u8,
    tls_write_buf: []u8,
) !std.crypto.tls.Client {
    const gpa = stream.gpa;
    const io = stream.io;
    const Options = std.crypto.tls.Client.Options;

    const now_sec: i64 = clock.unixSeconds();
    const now_timestamp: std.Io.Timestamp = .{
        .nanoseconds = @as(i96, now_sec) * std.time.ns_per_s,
    };

    // `.empty` decl on my snapshot, field defaults on master — gate it.
    var ca_bundle: std.crypto.Certificate.Bundle =
        if (comptime @hasDecl(std.crypto.Certificate.Bundle, "empty")) .empty else .{};
    // The bundle must outlive the handshake only; certificates are
    // verified during init.
    defer ca_bundle.deinit(gpa);
    try ca_bundle.rescan(gpa, io, now_timestamp);

    const entropy_len = if (comptime @hasDecl(Options, "entropy_len")) Options.entropy_len else 176;
    var entropy: [entropy_len]u8 = undefined;
    fillRandom(io, &entropy);

    // Shape gates, each branch cribbed from that std's own http.Client.
    const CaUnion = @FieldType(Options, "ca");
    const BundlePayload = @FieldType(CaUnion, "bundle");
    var lock: std.Io.RwLock = if (comptime BundlePayload != std.crypto.Certificate.Bundle) .init else undefined;

    if (comptime @hasField(Options, "realtime_now_seconds")) {
        return std.crypto.tls.Client.init(
            &conn.tcp_reader.interface,
            &conn.tcp_writer.interface,
            .{
                .host = .{ .explicit = stream.host },
                .ca = .{ .bundle = ca_bundle },
                .read_buffer = tls_read_buf,
                .write_buffer = tls_write_buf,
                .entropy = &entropy,
                .realtime_now_seconds = now_sec,
            },
        );
    } else {
        return std.crypto.tls.Client.init(
            &conn.tcp_reader.interface,
            &conn.tcp_writer.interface,
            .{
                .host = .{ .explicit = stream.host },
                .ca = .{ .bundle = .{
                    .gpa = gpa,
                    .io = io,
                    .lock = &lock,
                    .bundle = &ca_bundle,
                } },
                .read_buffer = tls_read_buf,
                .write_buffer = tls_write_buf,
                .entropy = &entropy,
                .realtime_now = now_timestamp,
            },
        );
    }
}

/// Live-test entry (`zig build test-live`): TLS-dial `host`:443, send a
/// minimal GET, return the first response bytes. Proves the TLS leg —
/// the one path the loopback test cannot cover — against a real endpoint.
pub fn tlsSmoke(gpa: Allocator, io: std.Io, host: []const u8, out: []u8) !usize {
    var probe: Stream = .{
        .gpa = gpa,
        .io = io,
        .mailbox = undefined, // never touched on the dial path
        .thread = undefined,
        .stop = .init(false),
        .socket_fd = .init(-1),
        .host = host,
        .port = 443,
        .use_tls = true,
        .dids = &.{},
        .log_fd = -1,
        .pending_locked = .init(false),
        .pending_dids = null,
    };
    var conn: Conn = undefined;
    try dial(&probe, &conn);
    defer {
        conn.tcp.close(io);
        for (conn.bufs) |buf| gpa.free(buf);
    }
    var req_buf: [256]u8 = undefined;
    const request = try std.fmt.bufPrint(
        &req_buf,
        "GET / HTTP/1.1\r\nHost: {s}\r\nConnection: close\r\n\r\n",
        .{host},
    );
    try conn.writer().writeAll(request);
    try conn.flushOut();
    return try readAvailable(conn.reader(), out) orelse error.ConnectionClosed;
}

// ---------------------------------------------------------------------------
// Loopback round trip (C6): a scripted WebSocket server — handshake
// verified with the core's own accept math, the options frame asserted,
// one live event delivered into the mailbox, clean teardown
// ---------------------------------------------------------------------------

const fixture = @import("test_fixture.zig");

const live_event_json =
    \\{"did":"did:plc:wwwwwwwwwwwwwwwwwwwwwwww","time_us":1767323050000009,"kind":"commit",
    \\ "commit":{"rev":"3kr","operation":"create","collection":"app.zat4.feed.post",
    \\ "rkey":"3kws1","cid":"bafyreiwslive1",
    \\ "record":{"$type":"app.zat4.feed.post","text":"over the socket",
    \\ "createdAt":"2026-01-02T03:04:05Z"}}}
;

fn serveWebSocket(server: *std.Io.net.Server, io: std.Io, expect_in_head: []const u8) void {
    const tcp = server.accept(io) catch return;
    defer tcp.close(io);
    var read_buf: [8192]u8 = undefined;
    var write_buf: [8192]u8 = undefined;
    var tcp_reader = tcp.reader(io, &read_buf);
    var tcp_writer = tcp.writer(io, &write_buf);
    const reader = &tcp_reader.interface;
    const writer = &tcp_writer.interface;

    // Handshake: read the request head, echo the accept key.
    var head: [8192]u8 = undefined;
    var head_len: usize = 0;
    while (std.mem.indexOf(u8, head[0..head_len], "\r\n\r\n") == null) {
        const n = (readAvailable(reader, head[head_len..]) catch return) orelse return;
        head_len += n;
    }
    if (std.mem.indexOf(u8, head[0..head_len], "wantedCollections=app.zat4.feed.post") == null) return;
    if (std.mem.indexOf(u8, head[0..head_len], expect_in_head) == null) return;
    const key_label = "Sec-WebSocket-Key: ";
    const key_at = std.mem.indexOf(u8, head[0..head_len], key_label) orelse return;
    const key_start = key_at + key_label.len;
    const key_end = std.mem.indexOfScalarPos(u8, head[0..head_len], key_start, '\r') orelse return;
    var accept_buf: [websocket.accept_len]u8 = undefined;
    const accept = websocket.acceptKeyFor(head[key_start..key_end], &accept_buf);

    // Regression for the field failure: deliver the 101, the event frame,
    // and the close frame in ONE write, so the client necessarily reads
    // frame bytes in the same chunk as the handshake tail and must seed
    // them into its frame buffer.
    var combined: [4096]u8 = undefined;
    var used: usize = 0;
    const head_bytes = std.fmt.bufPrint(
        combined[used..],
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n",
        .{accept},
    ) catch return;
    used += head_bytes.len;
    const event_frame = websocket.encodeFrame(combined[used..], .text, live_event_json, null) catch return;
    used += event_frame.len;
    const close_frame = websocket.encodeFrame(combined[used..], .close, "", null) catch return;
    used += close_frame.len;
    writer.writeAll(combined[0..used]) catch return;
    writer.flush() catch return;
}

test "stream loopback: handshake, options frame, one live post into the mailbox" {
    const gpa = std.testing.allocator; // C6
    const io = std.testing.io;

    var bound = try fixture.listenLoopback(io, 38820);
    defer bound.server.deinit(io);
    const server_thread = try std.Thread.spawn(.{}, serveWebSocket, .{
        &bound.server, io, "wantedDids=did:plc:test",
    });
    defer server_thread.join();

    var mailbox: Mailbox = .{};
    defer mailbox.deinit(gpa);

    var host_buf: [32]u8 = undefined;
    const host = try std.fmt.bufPrint(&host_buf, "127.0.0.1", .{});
    const stream = try start(gpa, io, &mailbox, host, bound.port, false, &.{"did:plc:test"}, null);
    defer shutdown(stream);

    // Wait (briefly, politely) for the post to land.
    var drained: std.ArrayList(Mail) = .empty;
    defer {
        for (drained.items) |mail| {
            if (mail == .post) freePost(gpa, mail.post);
        }
        drained.deinit(gpa);
    }
    var waited_ms: u64 = 0;
    var got_post = false;
    while (waited_ms < 3_000 and !got_post) {
        try mailbox.drain(gpa, &drained);
        for (drained.items) |mail| {
            if (mail == .post) got_post = true;
        }
        if (got_post) break;
        clock.sleepMillis(20);
        waited_ms += 20;
    }
    try std.testing.expect(got_post);
    for (drained.items) |mail| switch (mail) {
        .post => |post| {
            try std.testing.expectEqualStrings("bafyreiwslive1", post.cid);
            try std.testing.expectEqualStrings("over the socket", post.text);
            try std.testing.expectEqualStrings("did:plc:wwwwwwwwwwwwwwwwwwwwwwww", post.did);
        },
        .status, .failure => {},
    };
}

test "stream loopback: a 64-did subscription survives the long URL" {
    const gpa = std.testing.allocator; // C6
    const io = std.testing.io;

    // Sixty-four realistic-length DIDs: the URL this builds is ~2.6 KB —
    // the exact scale that broke the fixed handshake buffer in the field.
    var did_storage: [64][32]u8 = undefined;
    var dids: [64][]const u8 = undefined;
    for (&did_storage, &dids, 0..) |*buf, *did, i| {
        did.* = std.fmt.bufPrint(buf, "did:plc:longurl{d:0>2}aaaaaaaaaaaaaaa", .{i}) catch unreachable;
    }

    var bound = try fixture.listenLoopback(io, 38824);
    defer bound.server.deinit(io);
    const server_thread = try std.Thread.spawn(.{}, serveWebSocket, .{
        &bound.server, io, dids[63],
    });
    defer server_thread.join();

    var mailbox: Mailbox = .{};
    defer mailbox.deinit(gpa);
    const stream = try start(gpa, io, &mailbox, "127.0.0.1", bound.port, false, &dids, null);
    defer shutdown(stream);

    var drained: std.ArrayList(Mail) = .empty;
    defer {
        for (drained.items) |mail| {
            if (mail == .post) freePost(gpa, mail.post);
        }
        drained.deinit(gpa);
    }
    var waited_ms: u64 = 0;
    var got_post = false;
    while (waited_ms < 3_000 and !got_post) {
        try mailbox.drain(gpa, &drained);
        for (drained.items) |mail| {
            if (mail == .post) got_post = true;
        }
        if (got_post) break;
        clock.sleepMillis(20);
        waited_ms += 20;
    }
    try std.testing.expect(got_post);
}

const live_event_2 =
    \\{"did":"did:plc:wwwwwwwwwwwwwwwwwwwwwwww","time_us":1767323050000010,"kind":"commit",
    \\ "commit":{"rev":"3kr","operation":"create","collection":"app.zat4.feed.post",
    \\ "rkey":"3kws2","cid":"bafyreiwslive2",
    \\ "record":{"$type":"app.zat4.feed.post","text":"second","createdAt":"2026-01-02T03:04:06Z"}}}
;
const live_event_3 =
    \\{"did":"did:plc:wwwwwwwwwwwwwwwwwwwwwwww","time_us":1767323050000011,"kind":"commit",
    \\ "commit":{"rev":"3kr","operation":"create","collection":"app.zat4.feed.post",
    \\ "rkey":"3kws3","cid":"bafyreiwslive3",
    \\ "record":{"$type":"app.zat4.feed.post","text":"third","createdAt":"2026-01-02T03:04:07Z"}}}
;

fn sleepMs(ms: u64) void {
    var ts: std.os.linux.timespec = .{
        .sec = @intCast(ms / 1_000),
        .nsec = @intCast((ms % 1_000) * 1_000_000),
    };
    _ = std.os.linux.nanosleep(&ts, null);
}

/// Waits for a masked client frame of `want`, consuming and skipping any
/// other frames on the way (the client volunteers options_update texts
/// and pings of its own).
fn awaitClientFrame(reader: *std.Io.Reader, want: websocket.Opcode) bool {
    return awaitClient(reader, want, null);
}

/// Waits for a client TEXT frame whose payload contains `must`.
fn awaitClientText(reader: *std.Io.Reader, must: []const u8) bool {
    return awaitClient(reader, .text, must);
}

fn awaitClient(reader: *std.Io.Reader, want: websocket.Opcode, must: ?[]const u8) bool {
    var storage: [4096]u8 = undefined;
    var len: usize = 0;
    while (true) {
        while (websocket.decodeFrame(storage[0..len]) catch return false) |decoded| {
            const matched = decoded.frame.opcode == want and
                (must == null or std.mem.indexOf(u8, decoded.frame.payload, must.?) != null);
            std.mem.copyForwards(u8, &storage, storage[decoded.consumed..len]);
            len -= decoded.consumed;
            if (matched) return true;
        }
        const n = (readAvailable(reader, storage[len..]) catch return false) orelse return false;
        len += n;
    }
}

/// A server that behaves like the real one: it pings first, goes quiet
/// long enough to force the client through a poll-timeout lap, splits a
/// frame mid-header across writes, and coalesces a ping with an event.
fn serveFaithful(server: *std.Io.net.Server, io: std.Io) void {
    const tcp = server.accept(io) catch return;
    defer tcp.close(io);
    var read_buf: [8192]u8 = undefined;
    var write_buf: [8192]u8 = undefined;
    var tcp_reader = tcp.reader(io, &read_buf);
    var tcp_writer = tcp.writer(io, &write_buf);
    const reader = &tcp_reader.interface;
    const writer = &tcp_writer.interface;

    var head: [8192]u8 = undefined;
    var head_len: usize = 0;
    while (std.mem.indexOf(u8, head[0..head_len], "\r\n\r\n") == null) {
        const n = (readAvailable(reader, head[head_len..]) catch return) orelse return;
        head_len += n;
    }
    if (std.mem.indexOf(u8, head[0..head_len], "wantedCollections=app.zat4.feed.post") == null) return;
    const key_label = "Sec-WebSocket-Key: ";
    const key_at = std.mem.indexOf(u8, head[0..head_len], key_label) orelse return;
    const key_start = key_at + key_label.len;
    const key_end = std.mem.indexOfScalarPos(u8, head[0..head_len], key_start, '\r') orelse return;
    var accept_buf: [websocket.accept_len]u8 = undefined;
    const accept = websocket.acceptKeyFor(head[key_start..key_end], &accept_buf);
    writer.print(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n",
        .{accept},
    ) catch return;
    writer.flush() catch return;
    sleepMs(50);

    var out: [4096]u8 = undefined;

    // 1) The server speaks first with a ping; the client must pong.
    const ping1 = websocket.encodeFrame(&out, .ping, "hb", null) catch return;
    writer.writeAll(ping1) catch return;
    writer.flush() catch return;
    if (!awaitClientFrame(reader, .pong)) return;

    // 2) First event, then a quiet stretch longer than one poll tick.
    const ev1 = websocket.encodeFrame(&out, .text, live_event_json, null) catch return;
    writer.writeAll(ev1) catch return;
    writer.flush() catch return;
    sleepMs(1_300);

    // 3) Second event split mid-header across two writes.
    const ev2 = websocket.encodeFrame(&out, .text, live_event_2, null) catch return;
    writer.writeAll(ev2[0..3]) catch return;
    writer.flush() catch return;
    sleepMs(80);
    writer.writeAll(ev2[3..]) catch return;
    writer.flush() catch return;

    // 4) A ping coalesced with the third event in ONE write.
    var combined: [4096]u8 = undefined;
    var used: usize = 0;
    const ping2 = websocket.encodeFrame(combined[used..], .ping, "hb2", null) catch return;
    used += ping2.len;
    const ev3 = websocket.encodeFrame(combined[used..], .text, live_event_3, null) catch return;
    used += ev3.len;
    writer.writeAll(combined[0..used]) catch return;
    writer.flush() catch return;
    if (!awaitClientFrame(reader, .pong)) return;

    sleepMs(200);
    const close_frame = websocket.encodeFrame(&out, .close, "", null) catch return;
    writer.writeAll(close_frame) catch return;
    writer.flush() catch return;
}

test "stream loopback: faithful server — pings, a quiet lap, a split frame, coalescing" {
    const gpa = std.testing.allocator; // C6
    const io = std.testing.io;

    var bound = try fixture.listenLoopback(io, 38826);
    defer bound.server.deinit(io);
    const server_thread = try std.Thread.spawn(.{}, serveFaithful, .{ &bound.server, io });
    defer server_thread.join();

    var mailbox: Mailbox = .{};
    defer mailbox.deinit(gpa);
    const stream = try start(gpa, io, &mailbox, "127.0.0.1", bound.port, false, &.{"did:plc:test"}, null);
    defer shutdown(stream);

    var drained: std.ArrayList(Mail) = .empty;
    defer {
        for (drained.items) |mail| {
            if (mail == .post) freePost(gpa, mail.post);
        }
        drained.deinit(gpa);
    }
    var waited_ms: u64 = 0;
    var posts: usize = 0;
    while (waited_ms < 6_000 and posts < 3) {
        try mailbox.drain(gpa, &drained);
        posts = 0;
        for (drained.items) |mail| {
            if (mail == .post) posts += 1;
        }
        if (posts >= 3) break;
        sleepMs(20);
        waited_ms += 20;
    }
    try std.testing.expectEqual(@as(usize, 3), posts);
    var seen: usize = 0;
    const expected = [_][]const u8{ "bafyreiwslive1", "bafyreiwslive2", "bafyreiwslive3" };
    for (drained.items) |mail| {
        if (mail == .post) {
            try std.testing.expectEqualStrings(expected[seen], mail.post.cid);
            seen += 1;
        }
    }
}

const grow_event_a =
    \\{"did":"did:plc:aaagrow","time_us":1767323050000020,"kind":"commit",
    \\ "commit":{"operation":"create","collection":"app.zat4.feed.post","rkey":"ga","cid":"bafyreigrowa",
    \\ "record":{"$type":"app.zat4.feed.post","text":"from a","createdAt":"2026-01-02T03:04:08Z"}}}
;
const grow_event_b =
    \\{"did":"did:plc:bbbgrow","time_us":1767323050000021,"kind":"commit",
    \\ "commit":{"operation":"create","collection":"app.zat4.feed.post","rkey":"gb","cid":"bafyreigrowb",
    \\ "record":{"$type":"app.zat4.feed.post","text":"from b","createdAt":"2026-01-02T03:04:09Z"}}}
;

/// A server that proves the subscription GROWS: it withholds B's event
/// until the client re-arms with an options_update naming B.
fn serveGrowing(server: *std.Io.net.Server, io: std.Io) void {
    const tcp = server.accept(io) catch return;
    defer tcp.close(io);
    var read_buf: [8192]u8 = undefined;
    var write_buf: [8192]u8 = undefined;
    var tcp_reader = tcp.reader(io, &read_buf);
    var tcp_writer = tcp.writer(io, &write_buf);
    const reader = &tcp_reader.interface;
    const writer = &tcp_writer.interface;

    var head: [8192]u8 = undefined;
    var head_len: usize = 0;
    while (std.mem.indexOf(u8, head[0..head_len], "\r\n\r\n") == null) {
        const n = (readAvailable(reader, head[head_len..]) catch return) orelse return;
        head_len += n;
    }
    if (std.mem.indexOf(u8, head[0..head_len], "wantedDids=did:plc:aaagrow") == null) return;
    const key_label = "Sec-WebSocket-Key: ";
    const key_at = std.mem.indexOf(u8, head[0..head_len], key_label) orelse return;
    const key_start = key_at + key_label.len;
    const key_end = std.mem.indexOfScalarPos(u8, head[0..head_len], key_start, '\r') orelse return;
    var accept_buf: [websocket.accept_len]u8 = undefined;
    const accept = websocket.acceptKeyFor(head[key_start..key_end], &accept_buf);
    writer.print(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {s}\r\n\r\n",
        .{accept},
    ) catch return;
    writer.flush() catch return;

    // The connect-time re-arm names only A.
    if (!awaitClientText(reader, "did:plc:aaagrow")) return;
    var out: [4096]u8 = undefined;
    const ev_a = websocket.encodeFrame(&out, .text, grow_event_a, null) catch return;
    writer.writeAll(ev_a) catch return;
    writer.flush() catch return;

    // B's event is withheld until the growth update names B.
    if (!awaitClientText(reader, "did:plc:bbbgrow")) return;
    const ev_b = websocket.encodeFrame(&out, .text, grow_event_b, null) catch return;
    writer.writeAll(ev_b) catch return;
    const close_frame = websocket.encodeFrame(&out, .close, "", null) catch return;
    writer.writeAll(close_frame) catch return;
    writer.flush() catch return;
}

test "stream loopback: the subscription grows mid-connection via options_update" {
    const gpa = std.testing.allocator; // C6
    const io = std.testing.io;

    var bound = try fixture.listenLoopback(io, 38830);
    defer bound.server.deinit(io);
    const server_thread = try std.Thread.spawn(.{}, serveGrowing, .{ &bound.server, io });
    defer server_thread.join();

    var mailbox: Mailbox = .{};
    defer mailbox.deinit(gpa);
    const stream = try start(gpa, io, &mailbox, "127.0.0.1", bound.port, false, &.{"did:plc:aaagrow"}, null);
    defer shutdown(stream);

    var drained: std.ArrayList(Mail) = .empty;
    defer {
        for (drained.items) |mail| {
            if (mail == .post) freePost(gpa, mail.post);
        }
        drained.deinit(gpa);
    }
    var waited_ms: u64 = 0;
    var posts: usize = 0;
    var grew = false;
    while (waited_ms < 6_000 and posts < 2) {
        try mailbox.drain(gpa, &drained);
        posts = 0;
        for (drained.items) |mail| {
            if (mail == .post) posts += 1;
        }
        if (posts >= 1 and !grew) {
            try updateDids(stream, &.{ "did:plc:aaagrow", "did:plc:bbbgrow" });
            grew = true;
        }
        if (posts >= 2) break;
        sleepMs(20);
        waited_ms += 20;
    }
    try std.testing.expectEqual(@as(usize, 2), posts);
    var seen: usize = 0;
    const expected = [_][]const u8{ "bafyreigrowa", "bafyreigrowb" };
    for (drained.items) |mail| {
        if (mail == .post) {
            try std.testing.expectEqualStrings(expected[seen], mail.post.cid);
            seen += 1;
        }
    }
}
