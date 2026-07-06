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
const spring = @import("core/spring.zig");
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
        const uri = std.fmt.bufPrint(&uri_buf, "at://{s}/app.zat4.feed.post/{d}", .{ did, i }) catch unreachable;
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

    // ---- the blit damage decision (the render-path cure): the window
    // loop's per-frame cost is dominated NOT by paint (~1 ms above) but by
    // the PutImage that ships the framebuffer over the X socket. A full
    // frame at 1280x800 is ~4 MB; the heart animation changes only a few
    // rows. raster.damageBand finds that band so blit() sends just it. This
    // measures the band scan itself and the bytes it saves — the number
    // behind "the animation stopped stuttering and clicks stopped dropping."
    {
        const w: u32 = 1280;
        const h: u32 = 800;
        const shadow = try gpa.alloc(u32, w * h);
        defer gpa.free(shadow);
        const frame = try gpa.alloc(u32, w * h);
        defer gpa.free(frame);
        @memset(shadow, 0xFF0E1116);
        @memcpy(frame, shadow);

        // The unchanged-frame case: the heart resting, or any static frame.
        // Proving "no change" means comparing every row (there is no row to
        // early-out on), so this scan is ~full-frame — but it is cheap local
        // memcmp that NEVER blocks, and it lets blit() skip the socket write
        // entirely. That is the trade: ~0.35 ms of CPU to avoid a 4 MB
        // blocking PutImage. The number is printed so the trade is honest.
        const reps: usize = 200;
        var t_same = clock.monotonicNanos();
        var sink_same: usize = 0;
        for (0..reps) |_| {
            if (raster.damageBand(shadow, frame, w, h)) |_| sink_same += 1;
        }
        const same_ns = (clock.monotonicNanos() - t_same) / reps;

        // A heart-sized change: ~3 cell-rows of pixels in one band, the
        // realistic per-frame delta of the animating heart.
        const band_top: u32 = 360;
        const band_rows: u32 = 60; // ~3 rows at a typical cell height
        var r: u32 = band_top;
        while (r < band_top + band_rows) : (r += 1) {
            var c: u32 = 40;
            while (c < 120) : (c += 1) frame[r * w + c] = 0xFFE0245E; // heart red
        }
        t_same = clock.monotonicNanos();
        var first: u32 = 0;
        var last: u32 = 0;
        for (0..reps) |_| {
            const band = raster.damageBand(shadow, frame, w, h).?;
            first = band.first;
            last = band.last;
        }
        const change_ns = (clock.monotonicNanos() - t_same) / reps;

        const full_bytes: usize = w * h * 4;
        const band_bytes: usize = @as(usize, (last - first + 1)) * w * 4;
        p("  blit damage 1280x800     scan unchanged {d:>4} ns, scan changed {d:>5} ns/frame\n", .{ same_ns, change_ns });
        p("                           band rows {d} -> blit {d} KB vs full {d} KB ({d}x less over the socket)\n", .{ last - first + 1, band_bytes / 1024, full_bytes / 1024, full_bytes / @max(band_bytes, 1) });
        if (sink_same != 0) p("", .{}); // keep sink_same observed
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
        var fht: field_ui.HeartList = .empty;
        defer fht.deinit(gpa);
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
            fn run(g: std.mem.Allocator, fl: *fieldm.Field, pt: *fieldm.ParticleList, ac: *effect.ActiveList, hr2: *field_ui.HitList, ht2: *field_ui.HeartList, vw: *field_ui.ViewState, sb: *std.ArrayList(fieldm.SpawnEvent), dl2: *raster.DrawList, its: []const feed.TimelineItem, lt: fieldm.Light, d: f32, r: std.Random) !void {
                _ = try field_ui.build(fl, hr2, ht2, its, 0, vw, &.{}, 1_700_000_500, "bench.bsky.social", "live", g);
                try effect.advance(g, ac, fl, d, sb);
                try fieldm.step(g, fl, pt, sb.items, d, r);
                try fieldm.compose(g, fl, pt.slice(), lt, 9, 17, dl2);
                // The effect render (heart glyphs + ring) is part of every
                // animated frame — measure it, do not assume it is free.
                try effect.composeEffects(g, ac.slice(), 9, 17, dl2);
            }
        }.run;

        // Idle: a static grid, no effects, no particles. This is what
        // the dynamic pump blocks on — but it is also the per-frame
        // floor whenever ANY animation is live, so it must be cheap.
        var n: usize = 0;
        const idle_t0 = clock.monotonicNanos();
        while (n < 200) : (n += 1) try frame(gpa, &fld, &parts, &acts, &fhr, &fht, &fview, &spawn, &fdl, &fitems, light, dt, frng.random());
        const idle_ns = (clock.monotonicNanos() - idle_t0) / 200;

        // Saturated: several effects firing + their particle output in
        // flight — the worst frame a burst of likes produces.
        for (0..6) |k| effect.trigger(gpa, &acts, &effect.like_heart, @intCast(20 + k * 15), @intCast(8 + k * 4), 1.0) catch {};
        n = 0;
        const busy_t0 = clock.monotonicNanos();
        while (n < 200) : (n += 1) try frame(gpa, &fld, &parts, &acts, &fhr, &fht, &fview, &spawn, &fdl, &fitems, light, dt, frng.random());
        const busy_ns = (clock.monotonicNanos() - busy_t0) / 200;
        p("  glyph field {d}x{d}      idle {d:>6} us, saturated {d:>6} us/frame ({d} cells; {d} particles live)\n", .{ cols, rows, idle_ns / 1_000, busy_ns / 1_000, @as(u32, cols) * rows, parts.len });

        // PER-FRAME PEAK over ONE like effect's whole lifetime. The averaged
        // numbers above hide the burst: an effect lasts ~0.82 s but the bench
        // loop runs 3.3 s, so ~150 idle frames wash the peak out (that is why
        // "saturated" can report 0 particles). What actually matters for
        // smoothness is the WORST single frame, and where the changed-pixel
        // band peaks — the blit cost the dirty-band path must carry. Measured,
        // not averaged. (G1; this is the tripwire that would have caught the
        // averaging flaw.)
        {
            var engine2 = try text_engine.initEngine();
            defer text_engine.deinitEngine(gpa, &engine2);
            const pw: u32 = cols * 9;
            const ph: u32 = rows * 17;
            var fb2: raster.Framebuffer = .{};
            defer raster.deinit(gpa, &fb2);
            try raster.resize(gpa, &fb2, pw, ph, 0xFF0E1116);
            const shadow2 = try gpa.alloc(u32, pw * ph);
            defer gpa.free(shadow2);
            @memcpy(shadow2, fb2.pixels);

            var fld2: fieldm.Field = .{};
            try fieldm.init(gpa, &fld2, cols, rows);
            defer fieldm.deinit(gpa, &fld2);
            var parts2: fieldm.ParticleList = .empty;
            defer parts2.deinit(gpa);
            var acts2: effect.ActiveList = .empty;
            defer acts2.deinit(gpa);
            var dl2: raster.DrawList = .empty;
            defer dl2.deinit(gpa);
            var hr2b: field_ui.HitList = .empty;
            defer hr2b.deinit(gpa);
            var ht2b: field_ui.HeartList = .empty;
            defer ht2b.deinit(gpa);
            var spawn2: std.ArrayList(fieldm.SpawnEvent) = .empty;
            defer spawn2.deinit(gpa);
            var vw2: field_ui.ViewState = .{};
            var rng2 = std.Random.DefaultPrng.init(7);

            // Prime: paint ONE static frame (the resting feed) into the shadow
            // first, so the band below measures the effect's INCREMENTAL change
            // against an already-drawn feed — exactly what the live loop blits
            // mid-animation. Without this, frame 0 diffs against a blank shadow
            // and reports a full-frame "change" (the whole feed appearing),
            // which is the one-time first-paint, not the animation.
            _ = try field_ui.build(&fld2, &hr2b, &ht2b, &fitems, 0, &vw2, &.{}, 1_700_000_500, "bench.bsky.social", "live", gpa);
            try fieldm.step(gpa, &fld2, &parts2, &.{}, dt, rng2.random());
            const light0: fieldm.Light = .{ .x = 70, .y = 14, .radius = 140, .ambient = 0.64 };
            try fieldm.compose(gpa, &fld2, parts2.slice(), light0, 9, 17, &dl2);
            try raster.paint(gpa, &engine2, dl2.slice(), &fb2, 0xFF0E1116);
            @memcpy(shadow2, fb2.pixels);

            effect.trigger(gpa, &acts2, &effect.like_heart, 20, 12, 1.0) catch {};
            const life = effect.like_heart.lifetime();
            const frames: usize = @intFromFloat(@ceil((life + 0.15) / dt));
            var peak_compute: u64 = 0;
            var peak_band: u32 = 0;
            var fr: usize = 0;
            while (fr < frames) : (fr += 1) {
                const c0 = clock.monotonicNanos();
                _ = try field_ui.build(&fld2, &hr2b, &ht2b, &fitems, 0, &vw2, &.{}, 1_700_000_500, "bench.bsky.social", "live", gpa);
                try effect.advance(gpa, &acts2, &fld2, dt, &spawn2);
                try fieldm.step(gpa, &fld2, &parts2, spawn2.items, dt, rng2.random());
                const light2: fieldm.Light = .{ .x = 70, .y = 14, .radius = 140, .ambient = 0.64 };
                try fieldm.compose(gpa, &fld2, parts2.slice(), light2, 9, 17, &dl2);
                try effect.composeEffects(gpa, acts2.slice(), 9, 17, &dl2);
                const compute_ns = clock.monotonicNanos() - c0;
                try raster.paint(gpa, &engine2, dl2.slice(), &fb2, 0xFF0E1116);
                const band = raster.damageBand(shadow2, fb2.pixels, pw, ph);
                const rows_changed: u32 = if (band) |b| b.last - b.first + 1 else 0;
                @memcpy(shadow2, fb2.pixels);
                if (compute_ns > peak_compute) peak_compute = compute_ns;
                if (rows_changed > peak_band) peak_band = rows_changed;
            }
            p("  like effect peak ({d:.2}s)  worst-frame compute {d} us, peak band {d}/{d} rows ({d} KB blit)\n", .{ life, peak_compute / 1000, peak_band, ph, peak_band * pw * 4 / 1024 });
        }
    }

    // ── Spring integrator (BUBBLE_SPRING_PHYSICS_ROADMAP §6) ──────────────────
    // 64 bubbles = 128 channels (scale + offset_y each), ALL active, one frame.
    // Worst case: every channel is retargeted each frame so none ever rests, so
    // the full set stays in the active sweep. The retarget is done OUTSIDE the
    // timing window; only `World.step` is measured (the number the stop-rule
    // judges).
    {
        var world: spring.World = .empty;
        defer world.deinit(gpa);
        const c_scale = spring.springConstants(0.25, 0.35);
        const c_off = spring.springConstants(0.15, 0.40);

        var hs: [128]spring.Handle = undefined;
        var bidx: usize = 0;
        while (bidx < 64) : (bidx += 1) {
            hs[bidx * 2] = try world.spawn(gpa, 0.2, 1.0, c_scale); // scale
            hs[bidx * 2 + 1] = try world.spawn(gpa, 40.0, 0.0, c_off); // offset_y
        }

        const dt: f32 = 1.0 / 120.0; // a 120 Hz frame → 2 fixed sub-steps
        const reps = 2000;
        var total: u64 = 0;
        var n: usize = 0;
        while (n < reps) : (n += 1) {
            // Keep every channel in motion (flip targets), outside the clock.
            const a: f32 = if (n % 2 == 0) 1.0 else 0.0;
            for (hs) |h| world.retarget(h, a);
            const t0 = clock.monotonicNanos();
            world.step(dt);
            total += clock.monotonicNanos() - t0;
        }
        p("  spring step 64 bubbles   {d:>6} ns/frame  (128 channels, all active, 2 sub-steps)\n", .{total / reps});
    }

    // ── Pool visibility (POOL_VISIBILITY_ROADMAP slice 5, G1) ─────────────────
    // The user-protection wall is pool_size_cap × the fuel ceiling; the value of
    // each is a MEASUREMENT question, never a safety one. Two numbers: (1) raw
    // guest-VM throughput on a pool-reading loop (VM dispatch + call_host seam;
    // the unit the ceiling-case derives from), and (2) the WORST refresh the
    // default budget admits — pool_size_cap candidates, every score() burning
    // its whole default fuel on cross-item reads, plus an arrange() burning the
    // same — run END-TO-END through discover.score (the real hosts, the real
    // marshaling). The max_fuel ceiling case is derived from (1), not run: at
    // 5M fuel × 257 runs it is deliberately absurd, and the derived number is
    // exactly what shows it must never be the DEFAULT.
    {
        const discover_m = @import("core/discover.zig");
        const gvm = @import("core/guest_vm.zig");
        const gabi = @import("core/guest_abi.zig");

        // (1) Throughput: an endless pool_read loop, stopped only by fuel.
        const reader_loop = [_]gvm.Instr{
            .{ .op = .push_const, .value = 3 }, // arg0: a pool index
            .{ .op = .push_const, .value = 1 }, // arg1: a fact id
            .{ .op = .call_host, .arg = @intFromEnum(gabi.Capability.pool_read) },
            .{ .op = .pop },
            .{ .op = .jump, .arg = 0 },
        };
        const H = struct {
            fn call(_: *anyopaque, _: gabi.Capability, a0: f64, a1: f64) f64 {
                return a0 + a1; // flat mock: measures the VM+seam, not the table walk
            }
        };
        var hctx: u8 = 0;
        const mock = gvm.Host{ .ctx = &hctx, .call = H.call };
        const spin_fuel: u32 = 1_000_000;
        const vm_t0 = clock.monotonicNanos();
        _ = gvm.run(&reader_loop, .{ .like_count = 0, .repost_count = 0, .reply_count = 0, .age_hrs = 0, .author_rep = 0, .in_network = false }, 0, spin_fuel, &mock);
        const vm_ns = clock.monotonicNanos() - vm_t0;
        const ns_per_instr = @as(f64, @floatFromInt(vm_ns)) / @as(f64, @floatFromInt(spin_fuel));

        // (2) The worst default-budget refresh, end-to-end. score() spins on
        // pool reads (burns all default fuel per candidate, produces base_score);
        // arrange() does the same and never emits (the fallback keeps the order).
        var pool: discover_m.Candidates = .{};
        defer pool.deinit(gpa);
        var ci: u32 = 0;
        while (ci < gabi.pool_size_cap) : (ci += 1) {
            try pool.append(gpa, .{
                .ref = discover_m.Ref.from(ci),
                .created_at = @intCast(1_700_000_000 - @as(i64, ci) * 60),
                .like_count = ci * 3,
                .repost_count = ci % 11,
                .reply_count = ci % 7,
                .reply_chain_count = 0,
                .bookmark_count = 0,
                .profile_click_count = 0,
                .link_click_count = 0,
                .negative_count = 0,
                .author_rep = 0.5,
                .relevance = 0,
                .behavioral = 0,
            }, ci % 2 == 0);
        }
        var wcfg = discover_m.DEFAULT_CONFIG;
        wcfg.guest_program = &reader_loop;
        wcfg.guest_arrange = &reader_loop;
        var pool_arena = std.heap.ArenaAllocator.init(gpa);
        defer pool_arena.deinit();
        const wc_t0 = clock.monotonicNanos();
        const worst_order = try discover_m.score(pool_arena.allocator(), &pool, wcfg, 1_700_000_000);
        const wc_ns = clock.monotonicNanos() - wc_t0;

        const ceiling_runs: f64 = @floatFromInt(gabi.pool_size_cap + 1);
        const ceiling_ms = ceiling_runs * @as(f64, @floatFromInt(gvm.max_fuel)) * ns_per_instr / 1_000_000.0;
        p("  guest VM pool_read loop  {d:.1} ns/instr  ({d} instr in {d} us, call_host-heavy)\n", .{ ns_per_instr, spin_fuel, vm_ns / 1_000 });
        p("  pool worst refresh       {d:>6} ms  ({d} candidates x {d} default fuel, score+arrange all-burn, end-to-end)\n", .{ wc_ns / 1_000_000, worst_order.len, gvm.default_fuel });
        p("  pool ceiling (derived)   {d:>6} ms  IF every run burned max_fuel={d} — why max is a wall, not a default\n", .{ @as(u64, @intFromFloat(ceiling_ms)), gvm.max_fuel });
    }
}
