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

//! B1 classification: SHELL (the AppView process entry — argv, stdin, the
//! serve loop). The standalone Zat4 AppView binary (STANDALONE_ROADMAP Phase
//! C, Cut 1): ingest `app.zat4.*` events off stdin into the in-memory index,
//! then serve the read query surface on a loopback port.
//!
//! Usage (Cut 1):
//!   zat4-appview                 read Jetstream JSONL on stdin, build the
//!                                index, then serve until killed.
//!   zat4-appview --port 2584     pick the serve port (default 2584).
//!   zat4-appview --ingest-only   build the index from stdin and exit (prints
//!                                a count) — useful to verify ingest alone.
//!
//! The live source: pipe a Jetstream tail in, e.g.
//!   websocat 'wss://jetstream.example/subscribe?wantedCollections=app.zat4.feed.post' | zat4-appview
//! Cut 1 reads a finite/era of stdin then serves a static snapshot; the live
//! WebSocket source that keeps ingesting WHILE serving is the next increment
//! (recorded in the setup doc and the ingest module header).

const std = @import("std");
const appview = @import("core/appview.zig");
const ingest = @import("shell/appview_ingest.zig");
const serve = @import("shell/appview_serve.zig");
const stream = @import("shell/stream.zig");
const poll = @import("shell/appview_poll.zig");
const store = @import("shell/appview_store.zig");
const tap_consume = @import("shell/appview_tap.zig");
const identity = @import("shell/identity.zig");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const env = init.environ_map;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = try init.minimal.args.toSlice(arena);
    var port: u16 = 2584;
    var ingest_only = false;
    var live = false;
    var do_poll = false;
    var do_tap = false;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--ingest-only")) {
            ingest_only = true;
        } else if (std.mem.eql(u8, a, "--live")) {
            live = true;
        } else if (std.mem.eql(u8, a, "--poll")) {
            do_poll = true;
        } else if (std.mem.eql(u8, a, "--tap")) {
            do_tap = true;
        } else if (std.mem.eql(u8, a, "--port") and i + 1 < args.len) {
            i += 1;
            port = std.fmt.parseInt(u16, args[i], 10) catch 2584;
        }
    }

    var out_buf: [512]u8 = undefined;
    var out_writer: std.Io.File.Writer = .init(.stdout(), io, &out_buf);
    const out = &out_writer.interface;

    // Ingest stdin into the index (C4: this owns the index memory).
    var idx: appview.Index = .{};
    defer appview.deinit(gpa, &idx);

    var in_buf: [64 * 1024]u8 = undefined;
    var in_reader: std.Io.File.Reader = .init(.stdin(), io, &in_buf);
    // Cap the stdin read so a hostile/endless source cannot exhaust memory
    // (C2 — the cost is visible here). 512 MiB is ample for a Cut-1 snapshot.
    const max_ingest_bytes: usize = 512 * 1024 * 1024;
    const indexed = ingest.runFromReader(gpa, &in_reader.interface, &idx, max_ingest_bytes) catch |err| {
        try out.print("ingest error: {s}\n", .{@errorName(err)});
        try out.flush();
        return err;
    };

    try out.print(
        \\zat4-appview: indexed {d} records ({d} posts, {d} follows)
        \\
    , .{ indexed, idx.posts.len, idx.follows.len });
    try out.flush();

    if (ingest_only) return;

    try out.print("zat4-appview: serving on http://127.0.0.1:{d}/xrpc/  (ctrl-c to stop)\n", .{port});
    try out.flush();

    // The index lock guards reads against the ingest thread; in the static
    // (snapshot) path it is uncontended.
    var lock: serve.IndexLock = .{};

    // Shared bearer token gating the serve surface (ZAT_APPVIEW_TOKEN). Empty ⇒
    // the serve layer FAILS CLOSED (rejects every request); warn loudly so an
    // unconfigured server's "nothing works" is diagnosable, not silent (E3).
    const serve_token = env.get("ZAT_APPVIEW_TOKEN") orelse "";
    if (serve_token.len == 0) {
        try out.print("zat4-appview: WARNING — ZAT_APPVIEW_TOKEN unset; the gate is fail-closed, ALL requests will be 401. Set it to serve.\n", .{});
        try out.flush();
    }

    // --- PDS-POLLING INGEST (--poll) ----------------------------------------
    // The public Jetstream is live-only and not built for custom-lexicon
    // discovery, so the AppView reads app.zat4.feed.post records DIRECTLY from
    // each author's PDS via listRecords (a public read), indexing new ones every
    // few seconds. The author set is the WHOLE follow graph the index knows
    // (post authors + follow endpoints), each DID resolved to its PDS once;
    // invalid/placeholder DIDs are skipped. A serve thread answers queries
    // meanwhile; the index lock guards the two against each other. Correct +
    // cheap for a small network; the firehose (own Jetstream / Tap) is the
    // scale-up.
    // --- TAP INGEST (--tap): the firehose path (STANDALONE "Cut 2"). ---------
    // Connect Tap's loopback /channel WS; Tap discovers/backfills/streams every
    // Zat4 repo, so there is no follow-graph enumeration or per-PDS polling. The
    // durable log + `seen` are restored first (idempotent against Tap's outbox
    // replay), a serve thread answers queries, and this thread runs the consumer.
    if (do_tap) {
        const log_path = env.get("ZAT_APPVIEW_LOG") orelse "";
        var log = store.open(log_path);
        defer store.close(&log);

        var seen: store.SeenSet = .empty;
        defer seen.deinit(gpa);

        const replayed = store.replay(gpa, &idx, &seen, log_path) catch 0;
        if (replayed > 0) {
            try out.print("zat4-appview: restored {d} record(s) from {s}\n", .{ replayed, log_path });
            try out.flush();
        }

        const tap_host = env.get("ZAT_TAP_HOST") orelse "127.0.0.1";
        const tap_port: u16 = if (env.get("ZAT_TAP_PORT")) |p|
            (std.fmt.parseInt(u16, p, 10) catch 2480)
        else
            2480;

        const serve_thread = try std.Thread.spawn(.{}, serveThread, .{ gpa, io, &idx, port, &lock, serve_token });
        _ = serve_thread; // runs until the process is killed

        try out.print("zat4-appview: tap ingest from {s}:{d} (app.zat4.*, all repos Tap tracks)\n", .{ tap_host, tap_port });
        try out.flush();

        tap_consume.run(gpa, io, tap_host, tap_port, &idx, &lock, &log, &seen, out); // loops forever
        return;
    }

    if (do_poll) {
        // Durable log (STANDALONE persistence): restore previously-polled posts/
        // follows/likes from disk BEFORE discovery, so a restart neither loses
        // indexed content nor re-polls from zero, and the restored follow graph
        // widens the poll target set. Path from ZAT_APPVIEW_LOG; unset/unwritable
        // ⇒ disabled (in-memory only, as before). C2: the disk cost is visible here.
        const log_path = env.get("ZAT_APPVIEW_LOG") orelse "";
        var log = store.open(log_path);
        defer store.close(&log);

        // Applied-record dedup (follow/like/repost record cids), refilled by the
        // replay below so a re-poll after restart skips already-applied records.
        // Poll-thread-only after this point; gpa-owned.
        var seen: store.SeenSet = .empty;
        defer seen.deinit(gpa);

        const replayed = store.replay(gpa, &idx, &seen, log_path) catch 0;
        if (replayed > 0) {
            try out.print("zat4-appview: restored {d} record(s) from {s}\n", .{ replayed, log_path });
            try out.flush();
        }

        // Targets live for the process; resolved once before the serve thread
        // starts (no concurrent mutation yet).
        var target_arena = std.heap.ArenaAllocator.init(gpa);
        const ta = target_arena.allocator();
        const Target = struct { did: []const u8, pds: []const u8 };
        var targets: std.ArrayList(Target) = .empty;

        const dids = appview.authorDids(ta, &idx) catch &[_][]const u8{};
        for (dids) |did| {
            const pds = identity.pdsForDid(gpa, io, env, .{}, did) catch |err| {
                try out.print("zat4-appview: skip {s} ({s})\n", .{ did, @errorName(err) });
                continue;
            };
            targets.append(ta, .{ .did = did, .pds = pds }) catch continue;
            try out.print("zat4-appview: polling {s} on {s}\n", .{ did, pds });
        }
        try out.flush();
        if (targets.items.len == 0) {
            try out.print("zat4-appview: no resolvable authors to poll yet (seed a follow graph with real DIDs)\n", .{});
            try out.flush();
        }

        const serve_thread = try std.Thread.spawn(.{}, serveThread, .{ gpa, io, &idx, port, &lock, serve_token });
        _ = serve_thread; // runs until the process is killed

        var poll_arena = std.heap.ArenaAllocator.init(gpa);
        defer poll_arena.deinit();
        while (true) {
            var total: usize = 0;
            for (targets.items) |t| {
                _ = poll_arena.reset(.retain_capacity);
                total += poll.pollRepo(gpa, poll_arena.allocator(), io, env, t.pds, t.did, &idx, &lock, &seen, &log) catch 0;
            }
            if (total > 0) {
                try out.print("zat4-appview: indexed +{d} new post(s) across {d} author(s)\n", .{ total, targets.items.len });
                try out.flush();
            }
            var nofds = [_]std.posix.pollfd{};
            _ = std.posix.poll(&nofds, 5000) catch 0; // ~5 s between polls
        }
    }

    if (!live) {
        try serve.run(gpa, io, &idx, .{ .port = port, .token = serve_token }, &lock);
        return;
    }

    // --- LIVE INGEST (Cut 2): keep indexing the firehose WHILE serving. ------
    // stream.zig (reused unchanged) connects to Jetstream on its own thread and
    // posts new app.zat4.feed.post events to a mailbox; a serve thread answers
    // queries; THIS thread drains the mailbox into the index under the lock. So
    // a post that hits the network now appears in getTimeline within seconds.
    // Empty DID filter ⇒ all repos (every Zat4 post on the network).
    const jetstream_host = env.get("ZAT_JETSTREAM") orelse "jetstream2.us-east.bsky.network";
    const log_path: ?[]const u8 = env.get("ZAT_STREAM_LOG") orelse "zat-appview-stream.log";

    var mailbox: stream.Mailbox = .{};
    defer mailbox.deinit(gpa);
    const live_stream = stream.start(gpa, io, &mailbox, jetstream_host, 443, true, &[_][]const u8{}, log_path) catch |err| {
        try out.print("zat4-appview: live stream failed to start: {s}\n", .{@errorName(err)});
        return err;
    };
    defer stream.shutdown(live_stream);

    try out.print("zat4-appview: live ingest on {s} (app.zat4.feed.post, all repos)\n", .{jetstream_host});
    try out.flush();

    const serve_thread = try std.Thread.spawn(.{}, serveThread, .{ gpa, io, &idx, port, &lock, serve_token });
    _ = serve_thread; // runs until the process is killed

    var mail: std.ArrayList(stream.Mail) = .empty;
    defer mail.deinit(gpa);
    while (true) {
        mail.clearRetainingCapacity();
        mailbox.drain(gpa, &mail) catch {};
        if (mail.items.len > 0) {
            lock.lock();
            for (mail.items) |m| switch (m) {
                .post => |p| {
                    _ = appview.indexPost(gpa, &idx, .{
                        .cid = p.cid,
                        .author_did = p.did,
                        .text = p.text,
                        .created_at = p.created_at,
                    }) catch false;
                    stream.freePost(gpa, p);
                },
                .status => |s| {
                    out.print("zat4-appview: {s}\n", .{s}) catch {};
                    out.flush() catch {};
                },
                .failure => |e| {
                    out.print("zat4-appview: stream {s}; retrying\n", .{@errorName(e)}) catch {};
                    out.flush() catch {};
                },
            };
            lock.unlock();
        }
        // Poll the mailbox at ~20 Hz. No condvar on the mailbox, so a short
        // timed wait (poll with no fds = a portable sleep, the codebase's
        // pattern) keeps this loop off a busy-spin; 50 ms is invisible against
        // human posting rates.
        var nofds = [_]std.posix.pollfd{};
        _ = std.posix.poll(&nofds, 50) catch 0;
    }
}

/// The query server, on its own thread for the live path (the main thread is
/// busy draining the firehose into the index). Reads the index under `lock`.
fn serveThread(gpa: std.mem.Allocator, io: std.Io, idx: *const appview.Index, port: u16, lock: *serve.IndexLock, token: []const u8) void {
    serve.run(gpa, io, idx, .{ .port = port, .token = token }, lock) catch {};
}

test {
    _ = appview;
    _ = ingest;
    _ = serve;
    _ = poll;
    _ = store;
    _ = tap_consume;
    _ = @import("core/tap.zig");
}
