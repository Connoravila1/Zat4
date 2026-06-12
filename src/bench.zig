//! B1 classification: SHELL. The G1 performance ledger — a measurement
//! harness, not a test. It drives the PURE cores (feed transforms, the
//! snapshot codec, frame building, rasterization) with the monotonic
//! clock and prints wall-clock per record plus bytes-per-record: the two
//! standard metrics G1 names. Run with `zig build bench`; numbers are
//! recorded in TECHNICAL_ROADMAP.md's Performance ledger, where the G3
//! stop-rule verdicts live beside them.

const std = @import("std");
const feed = @import("core/feed.zig");
const snapshot = @import("core/snapshot.zig");
const timeline_ui = @import("core/timeline_ui.zig");
const tui = @import("core/tui.zig");
const pixel = @import("core/pixel.zig");
const x11 = @import("core/x11.zig");
const clock = @import("shell/clock.zig");

const posts_n = 10_000;
const authors_n = 197; // prime-ish: spreads the synthetic handles

pub fn main() !void {
    const gpa = std.heap.page_allocator;

    // ---- synthesize a realistic store: 10k posts, ~200 authors ----
    var store: feed.Store = .{};
    defer feed.deinitStore(gpa, &store);

    const ingest_t0 = clock.monotonicNanos();
    var i: usize = 0;
    while (i < posts_n) : (i += 1) {
        var did_buf: [64]u8 = undefined;
        var cid_buf: [64]u8 = undefined;
        var uri_buf: [96]u8 = undefined;
        var text_buf: [128]u8 = undefined;
        const did = std.fmt.bufPrint(&did_buf, "did:plc:bench{d:0>6}aaaaaaaaaaa", .{i % authors_n}) catch unreachable;
        const cid = std.fmt.bufPrint(&cid_buf, "bafyreibench{d:0>10}", .{i}) catch unreachable;
        const uri = std.fmt.bufPrint(&uri_buf, "at://{s}/app.bsky.feed.post/{d}", .{ did, i }) catch unreachable;
        const text = std.fmt.bufPrint(&text_buf, "post {d}: a line of ordinary timeline text, long enough to wrap once on a narrow surface", .{i}) catch unreachable;
        _ = try feed.ingestLivePost(gpa, &store, .{
            .did = did,
            .handle = "",
            .uri = uri,
            .cid = cid,
            .text = text,
            .reply_parent_cid = "",
            .reply_root_cid = "",
            .created_at = @intCast(1_700_000_000 + i),
        });
    }
    const ingest_ns = clock.monotonicNanos() - ingest_t0;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    // ---- buildTimeline: the core transform on the hot path ----
    var build_total: u64 = 0;
    var items: []feed.TimelineItem = undefined;
    var rep: usize = 0;
    while (rep < 20) : (rep += 1) {
        _ = arena_state.reset(.retain_capacity);
        const t0 = clock.monotonicNanos();
        items = try feed.buildTimeline(arena_state.allocator(), &store);
        build_total += clock.monotonicNanos() - t0;
    }
    const build_ns = build_total / 20;

    // ---- snapshot codec: the cold-start path ----
    var encode_total: u64 = 0;
    var image: []u8 = undefined;
    rep = 0;
    var codec_arena = std.heap.ArenaAllocator.init(gpa);
    defer codec_arena.deinit();
    while (rep < 10) : (rep += 1) {
        _ = codec_arena.reset(.retain_capacity);
        const t0 = clock.monotonicNanos();
        image = try snapshot.encode(codec_arena.allocator(), &store);
        encode_total += clock.monotonicNanos() - t0;
    }
    const encode_ns = encode_total / 10;

    var decode_total: u64 = 0;
    rep = 0;
    while (rep < 10) : (rep += 1) {
        const t0 = clock.monotonicNanos();
        var loaded = try snapshot.decode(gpa, image);
        decode_total += clock.monotonicNanos() - t0;
        feed.deinitStore(gpa, &loaded);
    }
    const decode_ns = decode_total / 10;

    // ---- the per-frame pair: frame build + rasterize at window size ----
    var surface: tui.Surface = .{};
    defer tui.deinitSurface(gpa, &surface);
    try tui.resizeSurface(gpa, &surface, 110, 32);
    var state: timeline_ui.UiState = .{};
    var frame_total: u64 = 0;
    rep = 0;
    while (rep < 200) : (rep += 1) {
        const t0 = clock.monotonicNanos();
        timeline_ui.buildFrame(&surface, items, &state, &.{}, 1_700_010_000, "bench.test", "bench");
        frame_total += clock.monotonicNanos() - t0;
    }
    const frame_ns = frame_total / 200;

    var fb: pixel.Framebuffer = .{};
    defer pixel.deinit(gpa, &fb);
    try pixel.resize(gpa, &fb, 110 * 8, 32 * 16);
    var raster_total: u64 = 0;
    rep = 0;
    while (rep < 200) : (rep += 1) {
        const t0 = clock.monotonicNanos();
        pixel.rasterize(&surface, &fb);
        raster_total += clock.monotonicNanos() - t0;
    }
    const raster_ns = raster_total / 200;

    // ---- the ledger ----
    const p = std.debug.print;
    p("zat performance ledger (G1) — {d} posts, {d} authors, ReleaseFast\n", .{ posts_n, authors_n });
    p("--------------------------------------------------------------\n", .{});
    p("bytes-per-record (A7 budgets, observed):\n", .{});
    p("  Post={d}  Author={d}  FeedItem={d}  TimelineItem={d}  x11.Event={d}\n", .{
        @sizeOf(feed.Post),         @sizeOf(feed.Author), @sizeOf(feed.FeedItem),
        @sizeOf(feed.TimelineItem), @sizeOf(x11.Event),
    });
    p("  snapshot: {d} bytes total = {d} bytes/post on disk\n", .{ image.len, image.len / posts_n });
    p("wall-clock of core transforms (avg):\n", .{});
    p("  ingestLivePost      {d:>8} ns/post   ({d} ms for {d})\n", .{ ingest_ns / posts_n, ingest_ns / 1_000_000, posts_n });
    p("  buildTimeline       {d:>8} ns/post   ({d} us per full rebuild)\n", .{ build_ns / posts_n, build_ns / 1_000 });
    p("  snapshot.encode     {d:>8} us        ({d} MB/s)\n", .{ encode_ns / 1_000, if (encode_ns > 0) image.len * 1_000 / encode_ns else 0 });
    p("  snapshot.decode     {d:>8} us        ({d} MB/s)\n", .{ decode_ns / 1_000, if (decode_ns > 0) image.len * 1_000 / decode_ns else 0 });
    p("  buildFrame 110x32   {d:>8} us/frame\n", .{frame_ns / 1_000});
    p("  rasterize  880x512  {d:>8} us/frame\n", .{raster_ns / 1_000});
}
