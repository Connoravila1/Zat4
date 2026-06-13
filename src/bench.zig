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
const layout = @import("core/layout.zig");
const raster = @import("core/raster.zig");
const text_engine = @import("core/text.zig");
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

    // Phase 5 seam (GUI roadmap §5): the old single rasterize number is
    // now the layout half (surface → draw list) and the paint half (draw
    // list → pixels), timed separately so each module answers for its
    // own cost — plus the sum, comparable to the pre-carve ledger line.
    var fb: raster.Framebuffer = .{};
    defer raster.deinit(gpa, &fb);
    try raster.resize(gpa, &fb, 110 * 8, 32 * 16, layout.palette_bg);
    var dlist: raster.DrawList = .empty;
    defer dlist.deinit(gpa);
    var layout_total: u64 = 0;
    var paint_total: u64 = 0;
    rep = 0;
    while (rep < 200) : (rep += 1) {
        const t0 = clock.monotonicNanos();
        try layout.fromSurface(gpa, &dlist, &surface);
        const t1 = clock.monotonicNanos();
        try raster.paint(gpa, null, dlist.slice(), &fb, layout.palette_bg);
        const t2 = clock.monotonicNanos();
        layout_total += t1 - t0;
        paint_total += t2 - t1;
    }
    const layout_ns = layout_total / 200;
    const paint_ns = paint_total / 200;

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
    p("  layout     110x32   {d:>8} us/frame  (surface -> draw list)\n", .{layout_ns / 1_000});
    p("  paint      880x512  {d:>8} us/frame  (draw list -> pixels)\n", .{paint_ns / 1_000});
    p("  layout+paint        {d:>8} us/frame  (pre-carve 'rasterize' equivalent)\n", .{(layout_ns + paint_ns) / 1_000});

    // ---- the modern pixel timeline (5.2/5.5/5.6): the number that
    // judges the look. 40 synthetic cards, full build + AA paint at a
    // 1280x800 window — the whole per-frame cost of the new pipeline.
    {
        var engine = try text_engine.initEngine();
        defer text_engine.deinitEngine(gpa, &engine);
        var pix_fb: raster.Framebuffer = .{};
        defer raster.deinit(gpa, &pix_fb);
        try raster.resize(gpa, &pix_fb, 1280, 800, layout.theme.bg);
        var dl: raster.DrawList = .empty;
        defer dl.deinit(gpa);
        var hr: layout.HitList = .empty;
        defer hr.deinit(gpa);

        var cards: [40]feed.TimelineItem = undefined;
        for (&cards, 0..) |*it, ci| it.* = .{
            .uri = "at://bench",
            .cid = "bench-cid",
            .author_handle = "someone.bsky.social",
            .author_display_name = "Bench Author",
            .reposted_by_handle = if (ci % 5 == 0) "booster.bsky.social" else "",
            .replying_to_handle = if (ci % 3 == 0) "parent.bsky.social" else "",
            .text = "Measured, not claimed: the pixel pipeline lays out wrapped body text across several lines, antialiases every glyph through the cache, and still has to land under the frame budget. " ** 1,
            .created_at = 1_700_000_000,
            .like_count = @intCast(ci * 3),
            .repost_count = @intCast(ci),
            .reply_count = @intCast(ci % 7),
            .quote_count = 0,
            .label_flags = .{},
            .item_flags = .{ .viewer_liked = ci % 4 == 0 },
        };

        var view: layout.ViewState = .{};
        // Warm the glyph cache out of the measurement (first frame pays
        // rasterization once per glyph/size; steady state is the number
        // that matters for a 60fps loop — both are printed).
        const cold_t0 = clock.monotonicNanos();
        _ = try layout.buildTimeline(gpa, &engine, &dl, &hr, &cards, 3, &view, &.{}, 1_700_000_500, "bench.bsky.social", "live", 1280, 800);
        try raster.paint(gpa, &engine, dl.slice(), &pix_fb, layout.theme.bg);
        const cold_ns = clock.monotonicNanos() - cold_t0;

        const runs: usize = 50;
        const warm_t0 = clock.monotonicNanos();
        for (0..runs) |_| {
            _ = try layout.buildTimeline(gpa, &engine, &dl, &hr, &cards, 3, &view, &.{}, 1_700_000_500, "bench.bsky.social", "live", 1280, 800);
            try raster.paint(gpa, &engine, dl.slice(), &pix_fb, layout.theme.bg);
        }
        const warm_ns = (clock.monotonicNanos() - warm_t0) / runs;
        p("  pixel timeline 1280x800  cold {d:>6} us, steady {d:>6} us/frame ({d} cards, {d} hit zones)\n", .{ cold_ns / 1_000, warm_ns / 1_000, cards.len, hr.len });
    }

    // ---- the glyph-field frame (G.0): the FULL per-frame cost the
    // wired window loop pays — build + effect.advance + field.step +
    // compose. Measured idle (a static grid, the common case the
    // dynamic pump blocks on) AND saturated (effects live + a heavy
    // particle population), so the G.4 active-list decision (deferred
    // until indicted) rests on a real number, not a guess (G1/G2).
    {
        const fieldm = @import("core/field.zig");
        const field_ui = @import("core/field_ui.zig");
        const effect = @import("core/effect.zig");
        const cols: u16 = 140;
        const rows: u16 = 44; // ~1280x800 at the 9x17 grid cell
        var fld: fieldm.Field = .{};
        try fieldm.init(gpa, &fld, cols, rows);
        defer fieldm.deinit(gpa, &fld);
        var parts: fieldm.ParticleList = .empty;
        defer parts.deinit(gpa);
        var acts: effect.ActiveList = .empty;
        defer acts.deinit(gpa);
        var fdl: raster.DrawList = .empty;
        defer fdl.deinit(gpa);
        var fhr: field_ui.HitList = .empty;
        defer fhr.deinit(gpa);
        var spawn: std.ArrayList(fieldm.SpawnEvent) = .empty;
        defer spawn.deinit(gpa);
        var fview: field_ui.ViewState = .{};
        var frng = std.Random.DefaultPrng.init(1);

        var fitems: [40]feed.TimelineItem = undefined;
        for (&fitems, 0..) |*it, k| it.* = .{
            .uri = "at://bench",
            .cid = "bench-cid",
            .author_handle = "someone.bsky.social",
            .author_display_name = "Bench Author",
            .reposted_by_handle = if (k % 5 == 0) "booster.bsky.social" else "",
            .replying_to_handle = "",
            .text = "Measured, not claimed: the glyph field lays out the feed, advances effects, steps the physics, and composes every frame.",
            .created_at = 1_700_000_000,
            .like_count = @intCast(k),
            .repost_count = @intCast(k % 7),
            .reply_count = 0,
            .quote_count = 0,
            .label_flags = .{},
            .item_flags = .{},
        };
        const light: fieldm.Light = .{ .x = 70, .y = 14, .radius = 140, .ambient = 0.64 };
        const dt: f32 = 1.0 / 60.0;

        const frame = struct {
            fn run(g: std.mem.Allocator, fl: *fieldm.Field, pt: *fieldm.ParticleList, ac: *effect.ActiveList, hr2: *field_ui.HitList, vw: *field_ui.ViewState, sb: *std.ArrayList(fieldm.SpawnEvent), dl2: *raster.DrawList, its: []const feed.TimelineItem, lt: fieldm.Light, d: f32, r: std.Random) !void {
                _ = try field_ui.build(fl, hr2, its, 0, vw, &.{}, 1_700_000_500, "bench.bsky.social", "live", g);
                try effect.advance(g, ac, fl, d, sb);
                try fieldm.step(g, fl, pt, sb.items, d, r);
                try fieldm.compose(g, fl, pt.slice(), lt, 9, 17, dl2);
            }
        }.run;

        // Idle: a static grid, no effects, no particles. This is what
        // the dynamic pump blocks on — but it is also the per-frame
        // floor whenever ANY animation is live, so it must be cheap.
        var n: usize = 0;
        const idle_t0 = clock.monotonicNanos();
        while (n < 200) : (n += 1) try frame(gpa, &fld, &parts, &acts, &fhr, &fview, &spawn, &fdl, &fitems, light, dt, frng.random());
        const idle_ns = (clock.monotonicNanos() - idle_t0) / 200;

        // Saturated: several effects firing + their particle output in
        // flight — the worst frame a burst of likes produces.
        for (0..6) |k| effect.trigger(gpa, &acts, &effect.like_heart, @intCast(20 + k * 15), @intCast(8 + k * 4), 1.0) catch {};
        n = 0;
        const busy_t0 = clock.monotonicNanos();
        while (n < 200) : (n += 1) try frame(gpa, &fld, &parts, &acts, &fhr, &fview, &spawn, &fdl, &fitems, light, dt, frng.random());
        const busy_ns = (clock.monotonicNanos() - busy_t0) / 200;
        p("  glyph field {d}x{d}      idle {d:>6} us, saturated {d:>6} us/frame ({d} cells; {d} particles live)\n", .{ cols, rows, idle_ns / 1_000, busy_ns / 1_000, @as(u32, cols) * rows, parts.len });
    }
}
