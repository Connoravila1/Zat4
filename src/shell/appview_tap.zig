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

//! B1 classification: SHELL (network I/O). The Tap consumer (STANDALONE_ROADMAP
//! "Cut 2"): connects Tap's loopback `/channel` WebSocket, reduces each message
//! (core/tap.zig — the sealed wire module), and applies it to the index + the
//! durable log. This REPLACES PDS polling: Tap discovers, backfills, and streams
//! every repo that posts Zat4 content, so the AppView no longer enumerates a
//! follow graph or polls each PDS.
//!
//! PLAINTEXT WebSocket (Tap binds loopback, no TLS), reusing the hand-rolled
//! framing in core/websocket.zig. Tap replays its outbox on every (re)connect;
//! that is SAFE here because the index dedups posts by cid, the `seen` set
//! (rebuilt from the durable log — step 6) dedups follow/like/repost RECORDS by
//! their cid, and out-of-order engagements are held pending — so a replay or a
//! reconnect never double-applies. Tap runs with `--disable-acks`, so this is a
//! plain read loop (no per-event acknowledgment).
//!
//! Failure isolation (E2): any stream error tears down the connection and the
//! caller reconnects with backoff; the index and the serve thread are untouched.

const std = @import("std");
const Allocator = std.mem.Allocator;
const websocket = @import("../core/websocket.zig");
const tap = @import("../core/tap.zig");
const appview = @import("../core/appview.zig");
const feed = @import("../core/feed.zig");
const lexicon = @import("../core/lexicon.zig");
const serve = @import("appview_serve.zig");
const store = @import("appview_store.zig");

/// A7.2: cold struct, size guard waived — one per connection attempt.
const Conn = struct {
    tcp: std.Io.net.Stream,
    tcp_reader: std.Io.net.Stream.Reader,
    tcp_writer: std.Io.net.Stream.Writer,
    read_buf: []u8,
    write_buf: []u8,

    fn reader(conn: *Conn) *std.Io.Reader {
        return &conn.tcp_reader.interface;
    }
    fn writer(conn: *Conn) *std.Io.Writer {
        return &conn.tcp_writer.interface;
    }
};

/// Run the Tap consumer until the process dies: connect, stream, and reconnect
/// with backoff on any drop. `seen` is the applied-record dedup set (refilled
/// from the durable log before this runs); `log` persists newly-applied records.
pub fn run(
    gpa: Allocator,
    io: std.Io,
    host: []const u8,
    port: u16,
    idx: *appview.Index,
    lock: *serve.IndexLock,
    log: *store.Store,
    seen: *store.SeenSet,
    out: *std.Io.Writer,
) void {
    var attempt: u32 = 0;
    while (true) {
        var delivered = false;
        runConnection(gpa, io, host, port, idx, lock, log, seen, out, &delivered) catch |err| {
            out.print("zat4-appview: tap stream {s}; reconnecting\n", .{@errorName(err)}) catch {};
            out.flush() catch {};
        };
        if (delivered) attempt = 0; // a good connection resets the backoff
        const ms = backoffMs(attempt);
        attempt +|= 1;
        var nofds = [_]std.posix.pollfd{};
        _ = std.posix.poll(&nofds, ms) catch 0; // poll with no fds = a portable sleep
    }
}

fn backoffMs(attempt: u32) i32 {
    return switch (attempt) {
        0 => 1_000,
        1 => 2_000,
        2 => 5_000,
        3 => 10_000,
        else => 30_000,
    };
}

fn runConnection(
    gpa: Allocator,
    io: std.Io,
    host: []const u8,
    port: u16,
    idx: *appview.Index,
    lock: *serve.IndexLock,
    log: *store.Store,
    seen: *store.SeenSet,
    out: *std.Io.Writer,
    delivered: *bool,
) !void {
    var conn: Conn = .{
        .tcp = undefined,
        .tcp_reader = undefined,
        .tcp_writer = undefined,
        .read_buf = try gpa.alloc(u8, 64 * 1024),
        .write_buf = try gpa.alloc(u8, 16 * 1024),
    };
    defer {
        gpa.free(conn.read_buf);
        gpa.free(conn.write_buf);
    }
    conn.tcp = try dialTcp(io, host, port);
    defer conn.tcp.close(io);
    conn.tcp_reader = conn.tcp.reader(io, conn.read_buf);
    conn.tcp_writer = conn.tcp.writer(io, conn.write_buf);

    // --- WebSocket handshake (plaintext) ---
    var nonce: [16]u8 = undefined;
    fillRandom(io, &nonce);
    var key_buf: [websocket.key_len]u8 = undefined;
    const key = websocket.encodeKey(nonce, &key_buf);
    var hs_buf: [256]u8 = undefined;
    // No cursor: connecting replays Tap's outbox from the start, which the
    // index + `seen` dedup absorbs idempotently (cursor-resume is a scale
    // optimization, deferred).
    const request = try websocket.buildHandshake(&hs_buf, host, "/channel", key);
    try conn.writer().writeAll(request);
    try conn.writer().flush();

    var response_buf: [8192]u8 = undefined;
    var response_len: usize = 0;
    while (true) {
        if (websocket.handshakeAccepted(response_buf[0..response_len], key)) |ok| {
            if (!ok) return error.HandshakeRefused;
            break;
        }
        if (response_len == response_buf.len) return error.HandshakeRefused;
        const n = try readAvailable(conn.reader(), response_buf[response_len..]) orelse return error.ConnectionClosed;
        response_len += n;
    }
    delivered.* = true;
    out.print("zat4-appview: tap connected ({s}:{d}/channel)\n", .{ host, port }) catch {};
    out.flush() catch {};

    // --- frame loop ---
    const frame_buf = try gpa.alloc(u8, 256 * 1024);
    defer gpa.free(frame_buf);
    // Bytes after the 101 in the same read ARE the start of the frame stream —
    // seed them or every later frame boundary is misaligned.
    const head_end = (std.mem.indexOf(u8, response_buf[0..response_len], "\r\n\r\n") orelse
        return error.HandshakeRefused) + 4;
    const leftover = response_buf[head_end..response_len];
    @memcpy(frame_buf[0..leftover.len], leftover);
    var buffered: usize = leftover.len;

    var event_arena = std.heap.ArenaAllocator.init(gpa);
    defer event_arena.deinit();
    var applied: usize = 0;

    while (true) {
        while (try websocket.decodeFrame(frame_buf[0..buffered])) |decoded| {
            switch (decoded.frame.opcode) {
                .text => {
                    _ = event_arena.reset(.retain_capacity);
                    const ea = event_arena.allocator();
                    if (tap.reduce(ea, decoded.frame.payload) catch null) |ev| {
                        if (applyEvent(gpa, ea, idx, lock, log, seen, ev)) applied += 1;
                    }
                },
                .ping => try sendFrame(io, gpa, &conn, .pong, decoded.frame.payload),
                .close => return,
                else => {},
            }
            std.mem.copyForwards(u8, frame_buf, frame_buf[decoded.consumed..buffered]);
            buffered -= decoded.consumed;
        }
        if (buffered == frame_buf.len) return error.FrameTooLong;
        if (applied > 0) {
            out.print("zat4-appview: tap indexed +{d} record(s)\n", .{applied}) catch {};
            out.flush() catch {};
            applied = 0;
        }
        const n = try readAvailable(conn.reader(), frame_buf[buffered..]) orelse return error.ConnectionClosed;
        buffered += n;
    }
}

/// Apply one reduced Tap event to the index + durable log. Returns true if it
/// indexed something countable. The index mutation runs under `lock` (the serve
/// thread reads concurrently); the durable-log append runs OUTSIDE the lock (the
/// log is single-writer — only this consumer appends — and a disk stall must not
/// hold the serve thread's spinlock).
fn applyEvent(
    gpa: Allocator,
    arena: Allocator,
    idx: *appview.Index,
    lock: *serve.IndexLock,
    log: *store.Store,
    seen: *store.SeenSet,
    ev: tap.Event,
) bool {
    switch (ev.reduced) {
        .ignored, .identity => return false, // identity/profile indexing deferred (Cut-1)
        .post => |p| {
            lock.lock();
            const is_new = appview.indexPost(gpa, idx, .{
                .cid = p.cid,
                .author_did = p.did,
                .text = p.text,
                .created_at = feed.parseTimestamp(p.created_at) catch 0,
                .reply_parent_cid = p.reply_parent_cid,
                .reply_root_cid = p.reply_root_cid,
                .quote_of_cid = p.quote_of_cid,
                .tags = lexicon.collectTags(arena, p.facets, p.record_tags) catch &.{}, // zone routing
            }) catch false;
            lock.unlock();
            if (is_new) {
                // Rebuild the reply refs (cid-only; the durable replay reads cids)
                // so a restart restores the thread linkage.
                const reply: ?lexicon.ReplyRefOut = if (p.reply_parent_cid.len > 0 or p.reply_root_cid.len > 0)
                    .{ .root = .{ .cid = p.reply_root_cid }, .parent = .{ .cid = p.reply_parent_cid } }
                else
                    null;
                // Cid-only embed (the durable replay reads the quoted cid).
                const embed: ?lexicon.EmbedRecordOut = if (p.quote_of_cid.len > 0)
                    .{ .record = .{ .cid = p.quote_of_cid } }
                else
                    null;
                store.appendPost(log, arena, p.did, p.rkey, p.cid, p.text, p.created_at, reply, p.facets, embed, p.record_tags);
            }
            return is_new;
        },
        .follow => |f| {
            if (markSeen(gpa, seen, f.record_cid)) return false; // already applied (replay/reconnect)
            lock.lock();
            appview.indexFollow(gpa, idx, f.did, f.subject_did) catch {};
            lock.unlock();
            store.appendFollow(log, arena, f.did, f.subject_did, f.record_cid);
            return true;
        },
        .engagement => |e| {
            if (markSeen(gpa, seen, e.record_cid)) return false;
            const kind: appview.Engagement = switch (e.kind) {
                .like => .like,
                .repost => .repost,
            };
            lock.lock();
            appview.indexEngagement(gpa, idx, kind, e.subject_cid) catch {};
            lock.unlock();
            // record_uri "" for now: the Tap engagement doesn't carry the like
            // record's rkey, so a tap-ingested like's viewer.like edge is not
            // rebuilt on replay (the poll path covers it). Wire when Tap lands.
            store.appendEngagement(log, arena, kind, e.did, e.subject_cid, e.record_cid, "");
            return true;
        },
    }
}

/// True if `cid` was ALREADY applied (caller skips); otherwise records it. On
/// OOM, treat as seen (skip this record — a reconnect replay re-offers it).
fn markSeen(gpa: Allocator, seen: *store.SeenSet, cid: []const u8) bool {
    const gop = seen.getOrPut(gpa, store.seenKey(cid)) catch return true;
    return gop.found_existing;
}

fn dialTcp(io: std.Io, host: []const u8, port: u16) !std.Io.net.Stream {
    if (std.Io.net.IpAddress.resolve(io, host, port)) |address| {
        var addr = address;
        return addr.connect(io, .{ .mode = .stream });
    } else |_| {}
    const name = try std.Io.net.HostName.init(host);
    return name.connect(io, port, .{ .mode = .stream });
}

fn sendFrame(io: std.Io, gpa: Allocator, conn: *Conn, opcode: websocket.Opcode, payload: []const u8) !void {
    var mask: [4]u8 = undefined;
    fillRandom(io, &mask);
    const out_buf = try gpa.alloc(u8, payload.len + websocket.max_header_len);
    defer gpa.free(out_buf);
    const frame = try websocket.encodeFrame(out_buf, opcode, payload, mask);
    try conn.writer().writeAll(frame);
    try conn.writer().flush();
}

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

fn fillRandom(io: std.Io, buf: []u8) void {
    if (comptime @hasDecl(std.Io, "random")) {
        io.random(buf);
    } else {
        std.crypto.random.bytes(buf);
    }
}

test {
    std.testing.refAllDecls(@This());
}
