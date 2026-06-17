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
    var poll_handle: ?[]const u8 = null;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--ingest-only")) {
            ingest_only = true;
        } else if (std.mem.eql(u8, a, "--live")) {
            live = true;
        } else if (std.mem.eql(u8, a, "--poll") and i + 1 < args.len) {
            i += 1;
            poll_handle = args[i];
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

    // --- PDS-POLLING INGEST (--poll <handle>) -------------------------------
    // The public Jetstream is live-only and not built for custom-lexicon
    // discovery, so the AppView reads app.zat4.feed.post records DIRECTLY from
    // the handle's PDS via listRecords (a public read), indexing new ones every
    // few seconds. Correct + cheap for a small network; the firehose (own
    // Jetstream / Tap) is the scale-up. A serve thread answers queries
    // meanwhile; the index lock guards the two against each other.
    if (poll_handle) |handle| {
        const id = identity.resolve(arena, io, env, .{}, handle) catch |err| {
            try out.print("zat4-appview: could not resolve {s}: {s}\n", .{ handle, @errorName(err) });
            return err;
        };
        try out.print("zat4-appview: polling {s} ({s}) on {s} every 5s\n", .{ handle, id.did, id.pds_url });
        try out.flush();

        const serve_thread = try std.Thread.spawn(.{}, serveThread, .{ gpa, io, &idx, port, &lock });
        _ = serve_thread; // runs until the process is killed

        var poll_arena = std.heap.ArenaAllocator.init(gpa);
        defer poll_arena.deinit();
        while (true) {
            _ = poll_arena.reset(.retain_capacity);
            const added = poll.pollRepo(gpa, poll_arena.allocator(), io, env, id.pds_url, id.did, &idx, &lock) catch |err| blk: {
                try out.print("zat4-appview: poll error: {s}\n", .{@errorName(err)});
                try out.flush();
                break :blk 0;
            };
            if (added > 0) {
                try out.print("zat4-appview: indexed +{d} new post(s) from {s}\n", .{ added, handle });
                try out.flush();
            }
            var nofds = [_]std.posix.pollfd{};
            _ = std.posix.poll(&nofds, 5000) catch 0; // ~5 s between polls
        }
    }

    if (!live) {
        try serve.run(gpa, io, &idx, .{ .port = port }, &lock);
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

    const serve_thread = try std.Thread.spawn(.{}, serveThread, .{ gpa, io, &idx, port, &lock });
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
fn serveThread(gpa: std.mem.Allocator, io: std.Io, idx: *const appview.Index, port: u16, lock: *serve.IndexLock) void {
    serve.run(gpa, io, idx, .{ .port = port }, lock) catch {};
}

test {
    _ = appview;
    _ = ingest;
    _ = serve;
}
