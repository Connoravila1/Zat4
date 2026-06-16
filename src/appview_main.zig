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

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const args = try init.minimal.args.toSlice(arena);
    var port: u16 = 2584;
    var ingest_only = false;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        const a = args[i];
        if (std.mem.eql(u8, a, "--ingest-only")) {
            ingest_only = true;
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

    try serve.run(gpa, io, &idx, .{ .port = port });
}

test {
    _ = appview;
    _ = ingest;
    _ = serve;
}
