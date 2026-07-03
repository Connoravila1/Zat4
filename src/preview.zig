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

//! Headless render preview (a dev tool — shell-side I/O, not in the app
//! graph). It drives the REAL core path — feed_view.layout → raster.paint
//! — into an in-memory framebuffer and writes it as a PPM, so the premium
//! feed can be eyeballed without an X server. `zig build preview`.

const std = @import("std");
const text = @import("core/text.zig");
const raster = @import("core/raster.zig");
const feed_view = @import("core/feed_view.zig");
const settings_view = @import("core/settings_view.zig");
const feed = @import("core/feed.zig");
const field = @import("core/field.zig");
const lens_socket = @import("core/lens_socket.zig");
const lens_catalog = @import("core/lens_catalog.zig");
const discover = @import("core/discover.zig");
const transparency = @import("core/transparency.zig");
const rules = @import("core/rules.zig");
const algo_vm = @import("core/algo_vm.zig");
const enroll_view = @import("core/enroll_view.zig");
const tiling = @import("core/tiling.zig");
const chat = @import("core/chat.zig");
const chat_view = @import("core/chat_view.zig");

/// Solve the three-pane as a PARTITION: nav (fixed 248) | feed (weight) |
/// sidebar (fixed 352), then map the placed rects into feed_view's PaneGeom.
/// This is the S.1 seam — the shell solves geometry, feed_view renders into it.
fn partitionGeom(arena: std.mem.Allocator, w: i32, h: i32, feed_weight: f32) !feed_view.PaneGeom {
    const wi: u16 = @intFromFloat(feed_weight * 128.0);
    const tree: tiling.Node = .{ .split = .{ .dir = .h, .children = &.{
        .{ .leaf = .{ .kind = .nav, .weight = 0, .min = 248 } },
        .{ .leaf = .{ .kind = .feed, .weight = wi, .min = 0 } },
        .{ .leaf = .{ .kind = .widgets, .weight = 0, .min = 352 } },
    } } };
    const carve = try tiling.tile(arena, &tree, @intCast(w), @intCast(h), .{ .seam = 0 });
    var rail_x: i32 = 0;
    var col_x: i32 = 0;
    var col_w: i32 = 0;
    var side_x: i32 = 0;
    for (carve.viewports) |vp| switch (vp.kind) {
        .nav => rail_x = vp.x,
        .feed => {
            col_x = vp.x;
            col_w = vp.w;
        },
        .widgets => side_x = vp.x,
        else => {},
    };
    return .{ .rail_x = rail_x, .col_x = col_x, .col_w = col_w, .lx = col_x + 22, .cw = col_w - 44, .side_x = side_x, .wide = true };
}

const W: u32 = 1280;
const H: u32 = 880;
const clear: u32 = 0xFF181812;
const cell_w: u16 = 11;
const cell_h: u16 = 17;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;

    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);

    var fb: raster.Framebuffer = .{};
    try raster.resize(gpa, &fb, W, H, clear);
    defer raster.deinit(gpa, &fb);

    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Background: the static ambient field, lit and composed exactly as the
    // live window does (just without the per-frame clock).
    const cols: u16 = @intCast(W / cell_w);
    const rows: u16 = @intCast(H / cell_h);
    var f: field.Field = .{};
    try field.init(gpa, &f, cols, rows);
    defer field.deinit(gpa, &f);
    field.fillAmbient(&f);
    var particles: field.ParticleList = .{};
    defer particles.deinit(gpa);
    const light: field.Light = .{
        .x = @floatFromInt(cols / 2),
        .y = @floatFromInt(rows / 4),
        .radius = @floatFromInt(cols),
        .ambient = 0.30,
    };
    try field.compose(gpa, &f, particles.slice(), light, cell_w, cell_h, &dl);

    // Drive the REAL path: plain TimelineItems → fromTimeline → PostViews,
    // exactly as the live window does (the only difference is the source of
    // the items). created_at values are now-relative so the ages render.
    const now: i64 = 1_000_000;
    var items = [_]feed.TimelineItem{
        mk("mara.zat", "Mara Vesper", "the whole point of a #smallweb is that you can actually read the room. ten thousand strangers isn't a room, it's weather.", now - 120, 48, 9, 6, true, false),
        mk("fieldnotes.zat", "field notes", "shipped the lighting pass tonight. the letters catch the light now, and the whole field moves when you touch it.", now - 840, 121, 31, 12, false, true),
        mk("oko.zat", "Okonkwo", "#monospace is the most honest a feed can be. same column, same weight, nobody shouts louder by being wider.", now - 3600, 73, 18, 24, false, false),
        mk("lune.zat", "lune", "woke up to the field still drifting where i left it. it kept the light on.", now - 10800, 39, 7, 3, false, false),
    };
    // Make one feed item a reply, to show the "Replying to @x" context line.
    items[1].replying_to_handle = "mara.zat";
    // Tag a couple of posts so the zone tray (the row of tappable #pills below a
    // post) renders in the proof — preview-only sample data, shell side.
    items[0].tags = &.{ "smallweb", "community" };
    items[2].tags = &.{ "monospace", "design", "typography" };
    const posts = try feed_view.fromTimeline(arena, &items, now, &.{});

    // The integrated home feed uses the REAL default loadout (the catalog),
    // so the proof matches what the live app loads with.
    const hc, const hb = try lens_catalog.defaultFeedLoadout(arena);
    const home_tray: lens_socket.TrayView = .{ .cards = hc, .text = hb, .seated = lens_catalog.default_feed_seated };
    _ = try feed_view.layout(gpa, &engine, @intCast(W), @intCast(H), posts, 0, &dl, null, null, false, 0, null, 3, lens_socket.seatedAccent(home_tray), home_tray, .{}, null, null, null, "", &.{}, null, 0, 0, .{}, 0, 255, null);
    try raster.paint(gpa, &engine, dl.slice(), &fb, clear);

    const io = init.io;
    try writePpm(io, gpa, &fb, "/tmp/zat_preview.ppm");

    // ALGORITHM TRANSPARENCY page (DISCOVER invariant 5): the real
    // transparency.buildPage → feed_view.layoutTransparency path, on the Zat4
    // Discover config (learns + reads attention, so the behavioral markers +
    // "learns" verdict show). Every field, its value, and its meaning.
    {
        @memset(fb.pixels, clear);
        dl.len = 0;
        var disc = discover.DEFAULT_CONFIG;
        disc.behavioral_weight = 1.0; // the adaptive default
        // Some authored Level-2 logic, so the readable "AUTHORED RULES" section
        // renders in the proof (the L2-slice-3 view).
        const demo_rules = [_]rules.Rule{
            .{ .predicate = .{ .kind = .out_of_network }, .action = .{ .kind = .boost, .factor = 1.5 } },
            .{ .predicate = .{ .kind = .min_engagement, .param = 50 }, .action = .{ .kind = .boost, .factor = 1.25 } },
            .{ .predicate = .{ .kind = .older_than_hrs, .param = 48 }, .action = .{ .kind = .exclude } },
        };
        disc.rules = &demo_rules;
        // An authored Level-3 scoring formula, so the "SCORING FORMULA" section
        // renders: (base score × 1.5) + (likes ÷ (age (hrs) + 1)).
        const demo_program = [_]algo_vm.Instr{
            .{ .op = .push_fact, .fact = .base_score },
            .{ .op = .push_const, .value = 1.5 },
            .{ .op = .mul },
            .{ .op = .push_fact, .fact = .like_count },
            .{ .op = .push_fact, .fact = .age_hrs },
            .{ .op = .push_const, .value = 1 },
            .{ .op = .add },
            .{ .op = .div },
            .{ .op = .add },
        };
        disc.vm_program = &demo_program;
        const page = try transparency.buildPage(arena, "Zat4 Discover", "zat4:discover", disc);
        _ = try feed_view.layoutTransparency(gpa, &engine, @intCast(W), @intCast(H), &dl, null, feed_view.accent_house, 0, page);
        try raster.paint(gpa, &engine, dl.slice(), &fb, clear);
        try writePpm(io, gpa, &fb, "/tmp/zat_transparency.ppm");
        std.debug.print("wrote /tmp/zat_transparency.ppm (algorithm transparency page)\n", .{});

        // A scrolled capture so the AUTHORED RULES section (below the field rows)
        // is visible in the proof.
        @memset(fb.pixels, clear);
        dl.len = 0;
        _ = try feed_view.layoutTransparency(gpa, &engine, @intCast(W), @intCast(H), &dl, null, feed_view.accent_house, -1820, page);
        try raster.paint(gpa, &engine, dl.slice(), &fb, clear);
        try writePpm(io, gpa, &fb, "/tmp/zat_transparency_rules.ppm");
        std.debug.print("wrote /tmp/zat_transparency_rules.ppm (authored-rules section)\n", .{});
    }

    // ZAT CHAT (ZAT_CHAT_ROADMAP U2): the Messages master–detail surface —
    // a real chat store → chat_view queries → layoutChat, over the ambient
    // field, with the honesty banner, stamps, bubbles, and the composer.
    {
        @memset(fb.pixels, clear);
        dl.len = 0;
        try field.compose(gpa, &f, particles.slice(), light, cell_w, cell_h, &dl);

        var cstore: chat.Store = .{};
        defer chat.deinitStore(gpa, &cstore);
        const maya = try chat.openConversation(gpa, &cstore, "did:plc:maya", "maya.zat4.com");
        const oko = try chat.openConversation(gpa, &cstore, "did:plc:oko", "oko.zat");
        _ = try chat.openConversation(gpa, &cstore, "did:plc:lune", "lune.zat");
        _ = try chat.appendMessage(gpa, &cstore, maya, .system, "conversation started", now - 7300, false);
        _ = try chat.appendMessage(gpa, &cstore, maya, .text, "hey — did the lighting pass land?", now - 7200, false);
        _ = try chat.appendMessage(gpa, &cstore, maya, .text, "It did. The letters catch the light now, and the whole field moves when you touch it.", now - 7100, true);
        _ = try chat.appendMessage(gpa, &cstore, maya, .text, "show me tonight?", now - 300, false);
        _ = try chat.appendMessage(gpa, &cstore, maya, .text, "one condition: you bring the coffee", now - 240, true);
        _ = try chat.appendMessage(gpa, &cstore, oko, .text, "monospace is the most honest a feed can be", now - 86400, false);
        // Payments (M5 A4): a peer's open lightning request (offers Pay)
        // and our on-chain send mid-confirmation (the six-block row).
        _ = try chat.appendPayment(gpa, &cstore, maya, .payment_request, 0xCAFE, .lightning, 5_000, "dinner split", now - 180, false);
        const psent = try chat.appendPayment(gpa, &cstore, maya, .payment_sent, 0xBEEF, .onchain, 250_000, "rent", now - 120, true);
        _ = chat.setConfirmations(&cstore, psent, 3);
        chat.markRead(&cstore, maya);

        const clist = try chat_view.buildList(arena, &cstore, now);
        const cthread = try chat_view.buildThread(arena, &cstore, maya, now);
        _ = try feed_view.layoutChat(gpa, &engine, @intCast(W), @intCast(H), &dl, null, feed_view.accent_house, 0, false, false, null, clist, cthread.rows, cthread.cards, 0, "maya.zat4.com", "", true, false, "", "", .{}, .{});
        try raster.paint(gpa, &engine, dl.slice(), &fb, clear);
        try writePpm(io, gpa, &fb, "/tmp/zat_chat.ppm");
        std.debug.print("wrote /tmp/zat_chat.ppm (Zat Chat messages surface)\n", .{});

        // The compose-new-conversation flow: the recipient bar open with a
        // half-typed handle, plus a refusal status line — both states in one
        // frame ("+ New" pill lit, ring, caret, hint replaced by the status).
        @memset(fb.pixels, clear);
        dl.len = 0;
        try field.compose(gpa, &f, particles.slice(), light, cell_w, cell_h, &dl);
        _ = try feed_view.layoutChat(gpa, &engine, @intCast(W), @intCast(H), &dl, null, feed_view.accent_house, 0, false, false, null, clist, cthread.rows, cthread.cards, 0, "maya.zat4.com", "", false, true, "chattest.zat4.com", "No chat keys published for that account", .{}, .{});
        try raster.paint(gpa, &engine, dl.slice(), &fb, clear);
        try writePpm(io, gpa, &fb, "/tmp/zat_chat_compose.ppm");
        std.debug.print("wrote /tmp/zat_chat_compose.ppm (compose-new-conversation bar)\n", .{});

        // The U6a motion, mid-flight: the newest own bubble halfway between
        // the composer and its seat, the typing indicator fully grown with
        // its dots mid-pulse — one frame of the live animation.
        @memset(fb.pixels, clear);
        dl.len = 0;
        try field.compose(gpa, &f, particles.slice(), light, cell_w, cell_h, &dl);
        _ = try feed_view.layoutChat(gpa, &engine, @intCast(W), @intCast(H), &dl, null, feed_view.accent_house, 0, false, false, null, clist, cthread.rows, cthread.cards, 0, "maya.zat4.com", "", true, false, "", "", .{}, .{ .send_t = 0.45, .typing_t = 1.0, .typing_phase = 0.6 });
        try raster.paint(gpa, &engine, dl.slice(), &fb, clear);
        try writePpm(io, gpa, &fb, "/tmp/zat_chat_motion.ppm");
        std.debug.print("wrote /tmp/zat_chat_motion.ppm (U6a mid-send + typing indicator)\n", .{});

        // The pay sheet (M5 A4), open over the same thread: rail toggle,
        // amount chips, both inputs (amount focused, mid-draft), the three
        // verbs — plus the cards above it (Pay pill, six-block row).
        @memset(fb.pixels, clear);
        dl.len = 0;
        try field.compose(gpa, &f, particles.slice(), light, cell_w, cell_h, &dl);
        _ = try feed_view.layoutChat(gpa, &engine, @intCast(W), @intCast(H), &dl, null, feed_view.accent_house, 0, false, false, null, clist, cthread.rows, cthread.cards, 0, "maya.zat4.com", "", false, false, "", "", .{ .open = true, .rail = .lightning, .amount = "5000", .note = "dinner split" }, .{});
        try raster.paint(gpa, &engine, dl.slice(), &fb, clear);
        try writePpm(io, gpa, &fb, "/tmp/zat_chat_pay.ppm");
        std.debug.print("wrote /tmp/zat_chat_pay.ppm (payment cards + the pay sheet)\n", .{});
    }

    // TILING FOUNDATION (S.1) PROOF: the SAME real feed, but its pane geometry
    // SOLVED by the partition carve (core/tiling.zig) and handed to layout()
    // via `geom`, instead of feed_view's own metricsPage. The rail/feed/sidebar
    // here are placed by the partition; everything rendered is the real UI.
    inline for (.{ .{ @as(f32, 3.0), "/tmp/zat_tiling_real.ppm" }, .{ @as(f32, 6.0), "/tmp/zat_tiling_real_wide.ppm" } }) |variant| {
        @memset(fb.pixels, clear);
        dl.len = 0;
        try field.compose(gpa, &f, particles.slice(), light, cell_w, cell_h, &dl);
        const geom = try partitionGeom(arena, @intCast(W), @intCast(H), variant[0]);
        _ = try feed_view.layout(gpa, &engine, @intCast(W), @intCast(H), posts, 0, &dl, null, null, false, 0, null, 3, lens_socket.seatedAccent(home_tray), home_tray, .{}, null, null, null, "", &.{}, geom, 0, 0, .{}, 0, 255, null);
        try raster.paint(gpa, &engine, dl.slice(), &fb, clear);
        try writePpm(io, gpa, &fb, variant[1]);
        std.debug.print("wrote {s} (real feed via partition, feed weight {d})\n", .{ variant[1], variant[0] });
    }
    // Content-driven SEARCH tile push: the real sidebar with search OPEN — the
    // results tile grows and pushes trending/follow down (cheap reposition).
    {
        @memset(fb.pixels, clear);
        dl.len = 0;
        try field.compose(gpa, &f, particles.slice(), light, cell_w, cell_h, &dl);
        var geom = try partitionGeom(arena, @intCast(W), @intCast(H), 3.0);
        geom.search_open = 1.0;
        _ = try feed_view.layout(gpa, &engine, @intCast(W), @intCast(H), posts, 0, &dl, null, null, false, 0, null, 3, lens_socket.seatedAccent(home_tray), home_tray, .{}, null, null, null, "", &.{}, geom, 0, 0, .{}, 0, 255, null);
        try raster.paint(gpa, &engine, dl.slice(), &fb, clear);
        try writePpm(io, gpa, &fb, "/tmp/zat_tiling_search.ppm");
        std.debug.print("wrote /tmp/zat_tiling_search.ppm (real sidebar, search open)\n", .{});
    }
    // DECOMPOSED rail: layout draws content+sidebar (rail_external), then the
    // rail is rendered SEPARATELY via renderRail — proving the decomposition
    // produces the same full UI (the shell does these as two GPU buffers).
    {
        @memset(fb.pixels, clear);
        dl.len = 0;
        try field.compose(gpa, &f, particles.slice(), light, cell_w, cell_h, &dl);
        var geom = try partitionGeom(arena, @intCast(W), @intCast(H), 3.0);
        geom.rail_external = true;
        _ = try feed_view.layout(gpa, &engine, @intCast(W), @intCast(H), posts, 0, &dl, null, null, false, 0, null, 3, lens_socket.seatedAccent(home_tray), home_tray, .{}, null, null, null, "", &.{}, geom, 0, 0, .{}, 0, 255, null);
        // The CONDENSED rail (expand 0 = icons-only) on the right + the FULL rail
        // (expand 1) on the left — the two states the Zones slide moves between.
        try feed_view.renderRail(gpa, &dl, &engine, geom.rail_x, @intCast(H), 1, null, feed_view.accent_house, false, 1.0);
        try feed_view.renderRail(gpa, &dl, &engine, @as(i32, @intCast(W)) - 76, @intCast(H), 1, null, feed_view.accent_house, false, 0.0);
        try raster.paint(gpa, &engine, dl.slice(), &fb, clear);
        try writePpm(io, gpa, &fb, "/tmp/zat_tiling_decomposed.ppm");
        std.debug.print("wrote /tmp/zat_tiling_decomposed.ppm (full rail left + condensed rail right)\n", .{});
    }
    std.debug.print("wrote /tmp/zat_preview.ppm ({d}x{d}, {d} items)\n", .{ W, H, dl.len });

    // The socket OPEN on the feed, with Discover (blue) seated — proof that
    // seating re-tints the WHOLE UI (wordmark, active nav, New post) to the
    // seated lens's palette color (§11.5), the open tray over the posts.
    @memset(fb.pixels, clear);
    dl.len = 0;
    try field.compose(gpa, &f, particles.slice(), light, cell_w, cell_h, &dl);
    var blue_tray = home_tray;
    blue_tray.seated = 2; // Discover → blue
    _ = try feed_view.layout(gpa, &engine, @intCast(W), @intCast(H), posts, 0, &dl, null, null, false, 0, null, 0, lens_socket.seatedAccent(blue_tray), blue_tray, .{ .open = true, .open_t = 1.0 }, null, null, null, "", &.{}, null, 0, 0, .{}, 0, 255, null);
    try raster.paint(gpa, &engine, dl.slice(), &fb, clear);
    try writePpm(io, gpa, &fb, "/tmp/zat_feed_open.ppm");
    std.debug.print("wrote /tmp/zat_feed_open.ppm ({d}x{d}, {d} items)\n", .{ W, H, dl.len });

    // The premium composer (PHASE C1): same field background, the composer card
    // over it via the REAL layoutCompose path → a second PPM proof.
    @memset(fb.pixels, clear);
    dl.len = 0;
    try field.compose(gpa, &f, particles.slice(), light, cell_w, cell_h, &dl);
    const draft_demo = "a small network is one where you can actually read the room — not weather, a room.";
    try feed_view.layoutCompose(gpa, &engine, @intCast(W), @intCast(H), feed_view.accent_house, .reply, "@mara.zat", "", draft_demo, draft_demo.len, 0, 0, true, "", &.{}, &dl, null);
    try raster.paint(gpa, &engine, dl.slice(), &fb, clear);
    try writePpm(io, gpa, &fb, "/tmp/zat_compose.ppm");
    std.debug.print("wrote /tmp/zat_compose.ppm ({d}x{d}, {d} items)\n", .{ W, H, dl.len });

    // The thread view: the root author's self-thread STITCHES (one continuous
    // post — header once, segments flow, thin separators), while replies from
    // OTHER users nest Reddit-style (indent + guide rail). Mara is the OP here:
    // root + two self-continuations, then two nested replies from others.
    @memset(fb.pixels, clear);
    dl.len = 0;
    try field.compose(gpa, &f, particles.slice(), light, cell_w, cell_h, &dl);
    // A RE-ROOTED view: a condensed ancestor (sentinel depth) on top, then the
    // re-rooted post (focus) + its stitched chain, then a nested reply. Shows the
    // condensed-ancestor style, the stem + sharp elbow, and the nesting together.
    const thread = [_]feed_view.PostView{
        tv("desh.zat", "Desh", "what's the plan for the algorithm marketplace? curious how creators get paid.", 0xFFB6C2D6, 'D', feed.thread_ancestor_depth, false, false, false),
        tv("mara.zat", "Mara Vesper", "the whole point of a small network is that you can actually read the room.", 0xFFCAA3A8, 'M', 0, true, false, false),
        tv("mara.zat", "Mara Vesper", "you stop performing for an audience and start talking to people.", 0xFFCAA3A8, 'M', 0, false, true, false),
        tv("mara.zat", "Mara Vesper", "and the field keeps the light at human scale — nobody shouts louder by being wider.", 0xFFCAA3A8, 'M', 0, false, true, false),
        tv("oko.zat", "Okonkwo", "agreed — ten thousand strangers isn't a room, it's weather.", 0xFF9FC7A0, 'O', 1, false, false, true),
        tv("lune.zat", "lune", "weather you can't even reply to without getting rained on.", 0xFFA9B6D6, 'l', 2, false, false, false),
    };
    const trc, const trb = try lens_catalog.defaultReplyLoadout(arena);
    const reply_t2: lens_socket.TrayView = .{ .cards = trc, .text = trb, .seated = lens_catalog.default_reply_seated };
    var thr_hits: lens_socket.HitList = .empty;
    defer thr_hits.deinit(gpa);
    // All-same-author thread → the reply socket lands at the end (the screenshot case).
    // Use a BLUE accent here to prove the seated-lens color flows to the focus
    // wash (and everywhere else), not the static house amber.
    _ = try feed_view.layout(gpa, &engine, @intCast(W), @intCast(H), &thread, 0, &dl, null, null, false, feed_view.screen_thread, null, 0, 0xFF4DA3FF, reply_t2, .{}, &thr_hits, null, null, "", &.{}, null, 0, 0, .{}, 0, 255, null);
    try raster.paint(gpa, &engine, dl.slice(), &fb, clear);
    try writePpm(io, gpa, &fb, "/tmp/zat_thread.ppm");
    std.debug.print("wrote /tmp/zat_thread.ppm ({d}x{d}, {d} items)\n", .{ W, H, dl.len });

    // The Profile screen: the new COMPACT, STICKY identity header over the posts.
    @memset(fb.pixels, clear);
    dl.len = 0;
    try field.compose(gpa, &f, particles.slice(), light, cell_w, cell_h, &dl);
    const header: feed_view.ProfileHeader = .{ .display_name = "connor.zat4.com", .handle = "@connor.zat4.com", .post_count = 11, .editable = true };
    _ = try feed_view.layout(gpa, &engine, @intCast(W), @intCast(H), posts, 0, &dl, null, null, false, feed_view.screen_profile, header, 0, feed_view.accent_house, null, .{}, null, null, null, "", &.{}, null, 0, 0, .{}, 0, 255, null);
    try raster.paint(gpa, &engine, dl.slice(), &fb, clear);
    try writePpm(io, gpa, &fb, "/tmp/zat_profile.ppm");
    std.debug.print("wrote /tmp/zat_profile.ppm ({d}x{d}, {d} items)\n", .{ W, H, dl.len });

    // A ZONE page (Zat Zones slice 4): the "#tag" sticky header with a Back
    // button and the zone socket present, over the zone's feed (here, the sample
    // posts stand in for a tag query result).
    @memset(fb.pixels, clear);
    dl.len = 0;
    try field.compose(gpa, &f, particles.slice(), light, cell_w, cell_h, &dl);
    _ = try feed_view.layout(gpa, &engine, @intCast(W), @intCast(H), posts, 0, &dl, null, null, false, feed_view.screen_zones, null, 0, lens_socket.seatedAccent(home_tray), home_tray, .{}, null, null, null, "smallweb", &.{}, null, 0, 0, .{}, 0, 255, null);
    try raster.paint(gpa, &engine, dl.slice(), &fb, clear);
    try writePpm(io, gpa, &fb, "/tmp/zat_zone.ppm");
    std.debug.print("wrote /tmp/zat_zone.ppm ({d}x{d}, {d} items)\n", .{ W, H, dl.len });

    // The Zones BROWSE catalog (slice 5): title + sub-tabs + search + categories
    // + the manifest grid, over the field. A handful of sample zones stand in for
    // a `listTags` result so the grid + cards render in the proof.
    @memset(fb.pixels, clear);
    dl.len = 0;
    try field.compose(gpa, &f, particles.slice(), light, cell_w, cell_h, &dl);
    const sample_zones = [_]feed_view.ZoneCard{
        .{ .tag = "deep", .count = 2481 },
        .{ .tag = "zig", .count = 913 },
        .{ .tag = "small-net", .count = 2481 },
        .{ .tag = "zathelp", .count = 204 },
        .{ .tag = "design", .count = 1130 },
        .{ .tag = "music", .count = 642 },
    };
    _ = try feed_view.layout(gpa, &engine, @intCast(W), @intCast(H), posts, 0, &dl, null, null, false, feed_view.screen_zones_browse, null, 0, lens_socket.seatedAccent(home_tray), home_tray, .{}, null, null, null, "", &sample_zones, null, 0, 0, .{}, 0, 255, null);
    try raster.paint(gpa, &engine, dl.slice(), &fb, clear);
    try writePpm(io, gpa, &fb, "/tmp/zat_zones_browse.ppm");
    std.debug.print("wrote /tmp/zat_zones_browse.ppm ({d}x{d}, {d} items)\n", .{ W, H, dl.len });

    // SETTINGS (master–detail): the section list on the left, the selected
    // section's grouped rows on the right. Two frames prove the section switch
    // and the row archetypes (info / choice / toggle / disclosure / action).
    @memset(fb.pixels, clear);
    dl.len = 0;
    try field.compose(gpa, &f, particles.slice(), light, cell_w, cell_h, &dl);
    _ = try feed_view.layout(gpa, &engine, @intCast(W), @intCast(H), posts, 0, &dl, null, null, false, feed_view.screen_settings, null, 0, lens_socket.seatedAccent(home_tray), home_tray, .{}, null, null, null, "", &.{}, null, settings_view.sec_appearance, 0, .{ .handle = "@connor.zat4.com", .did = "did:plc:5x7q2k9m4w8t1n3p6r0a", .pds = "pds.zat4.com" }, 0, settings_view.act_accent);
    try raster.paint(gpa, &engine, dl.slice(), &fb, clear);
    try writePpm(io, gpa, &fb, "/tmp/zat_settings.ppm");
    std.debug.print("wrote /tmp/zat_settings.ppm ({d}x{d}, {d} items)\n", .{ W, H, dl.len });

    @memset(fb.pixels, clear);
    dl.len = 0;
    try field.compose(gpa, &f, particles.slice(), light, cell_w, cell_h, &dl);
    _ = try feed_view.layout(gpa, &engine, @intCast(W), @intCast(H), posts, 0, &dl, null, null, false, feed_view.screen_settings, null, 0, lens_socket.seatedAccent(home_tray), home_tray, .{}, null, null, null, "", &.{}, null, settings_view.sec_toybox, 0, .{}, 0, 255, null);
    try raster.paint(gpa, &engine, dl.slice(), &fb, clear);
    try writePpm(io, gpa, &fb, "/tmp/zat_settings_toybox.ppm");
    std.debug.print("wrote /tmp/zat_settings_toybox.ppm ({d}x{d}, {d} items)\n", .{ W, H, dl.len });

    // THE LENS SOCKET (L.0 resting + L.1 open) over the living field, the
    // real pure path: lens_socket.build → raster.paint. A few placeholder
    // lenses; the socket replaces the feed's Following/Discover tab labels.
    const tray = try sampleTray(arena);
    const sock_geom: lens_socket.Geometry = .{ .x = 300, .y = 60, .w = 680, .scale = 1.0 };

    @memset(fb.pixels, clear);
    dl.len = 0;
    try field.compose(gpa, &f, particles.slice(), light, cell_w, cell_h, &dl);
    _ = try lens_socket.build(arena, &engine, tray, .{ .open = false }, sock_geom, &dl, null);
    try raster.paint(gpa, &engine, dl.slice(), &fb, clear);
    try writePpm(io, gpa, &fb, "/tmp/zat_socket_rest.ppm");
    std.debug.print("wrote /tmp/zat_socket_rest.ppm ({d}x{d}, {d} items)\n", .{ W, H, dl.len });

    @memset(fb.pixels, clear);
    dl.len = 0;
    try field.compose(gpa, &f, particles.slice(), light, cell_w, cell_h, &dl);
    _ = try lens_socket.build(arena, &engine, tray, .{ .open = true, .open_t = 1.0 }, sock_geom, &dl, null);
    try raster.paint(gpa, &engine, dl.slice(), &fb, clear);
    try writePpm(io, gpa, &fb, "/tmp/zat_socket_open.ppm");
    std.debug.print("wrote /tmp/zat_socket_open.ppm ({d}x{d}, {d} items)\n", .{ W, H, dl.len });

    // L.3 — a card EXPANDED: the inline detail panel under Quiet Mode (index 3),
    // showing author / description / ranks / privacy / CID + seat + close.
    @memset(fb.pixels, clear);
    dl.len = 0;
    try field.compose(gpa, &f, particles.slice(), light, cell_w, cell_h, &dl);
    _ = try lens_socket.build(arena, &engine, tray, .{ .open = true, .open_t = 1.0, .expanded = 3 }, sock_geom, &dl, null);
    try raster.paint(gpa, &engine, dl.slice(), &fb, clear);
    try writePpm(io, gpa, &fb, "/tmp/zat_socket_detail.ppm");
    std.debug.print("wrote /tmp/zat_socket_detail.ppm ({d}x{d}, {d} items)\n", .{ W, H, dl.len });

    // L.4 — a card mid-DRAG: Zig Only (index 4) lifted, its slot a hole, the
    // ghost following the cursor, the slot under the cursor (Following) marked.
    @memset(fb.pixels, clear);
    dl.len = 0;
    try field.compose(gpa, &f, particles.slice(), light, cell_w, cell_h, &dl);
    // slide reflects mid-drag of card 4 with the gap opening at slot 1:
    // cards 1,2,3 have slid right one slot; the ghost is lifted at the cursor.
    var drag_slide = [_]f32{0} ** lens_socket.max_lenses;
    drag_slide[1] = 1.0;
    drag_slide[2] = 1.0;
    drag_slide[3] = 1.0;
    _ = try lens_socket.build(arena, &engine, tray, .{ .open = true, .open_t = 1.0, .drag_active = 4, .drag_x = sock_geom.x + 120, .drag_y = sock_geom.y + 130, .lift = 1.0, .slide = drag_slide }, sock_geom, &dl, null);
    try raster.paint(gpa, &engine, dl.slice(), &fb, clear);
    try writePpm(io, gpa, &fb, "/tmp/zat_socket_drag.ppm");
    std.debug.print("wrote /tmp/zat_socket_drag.ppm ({d}x{d}, {d} items)\n", .{ W, H, dl.len });

    // §11.5 — the color PICKER open on Discover (index 2): a 3×3 palette popover.
    @memset(fb.pixels, clear);
    dl.len = 0;
    try field.compose(gpa, &f, particles.slice(), light, cell_w, cell_h, &dl);
    _ = try lens_socket.build(arena, &engine, tray, .{ .open = true, .open_t = 1.0, .picking = 2 }, sock_geom, &dl, null);
    try raster.paint(gpa, &engine, dl.slice(), &fb, clear);
    try writePpm(io, gpa, &fb, "/tmp/zat_socket_recolor.ppm");
    std.debug.print("wrote /tmp/zat_socket_recolor.ppm ({d}x{d}, {d} items)\n", .{ W, H, dl.len });

    // TOY BOX — "Julia mode": the same picker, but `julia` forces every swatch
    // (and card accent) pink, so no colour but pink can be chosen. The whole-UI
    // accent the shell forces to match is the same `julia_pink`.
    @memset(fb.pixels, clear);
    dl.len = 0;
    try field.compose(gpa, &f, particles.slice(), light, cell_w, cell_h, &dl);
    _ = try lens_socket.build(arena, &engine, tray, .{ .open = true, .open_t = 1.0, .picking = 2, .julia = true }, sock_geom, &dl, null);
    try raster.paint(gpa, &engine, dl.slice(), &fb, clear);
    try writePpm(io, gpa, &fb, "/tmp/zat_julia_socket.ppm");
    std.debug.print("wrote /tmp/zat_julia_socket.ppm ({d}x{d}, {d} items)\n", .{ W, H, dl.len });

    // Julia mode on the FEED: the chrome accent forced to pink (wordmark, nav
    // pill, New-post, the seated socket cartridge). The software preview field
    // stays grey — the pink FIELD glyphs are a GPU-only effect (uInk uniform),
    // verified live; this frame proves the accent + socket path.
    // Simulate the LIGHT theme: white field backdrop + the dark-text remap the
    // shell applies (the live field/spark are GPU-only; this proves readability).
    const julia_white: u32 = 0xFFF7E9F1;
    @memset(fb.pixels, julia_white);
    dl.len = 0;
    _ = try feed_view.layout(gpa, &engine, @intCast(W), @intCast(H), posts, 0, &dl, null, null, false, 0, null, 3, lens_socket.julia_pink, home_tray, .{}, null, null, null, "", &.{}, null, 0, 0, .{}, 0, 255, null);
    feed_view.juliaRemapText(&dl);
    try raster.paint(gpa, &engine, dl.slice(), &fb, julia_white);
    try writePpm(io, gpa, &fb, "/tmp/zat_julia_feed.ppm");
    std.debug.print("wrote /tmp/zat_julia_feed.ppm ({d}x{d}, {d} items)\n", .{ W, H, dl.len });

    // The seat animation (L.2): a still at the plug-in moment — seating
    // lens index 2 (Discover, blue), mid drop-in with the seat-glow rising.
    // swap_from = 0 (For You, amber) → swap_to = 2 (Discover, blue).
    var swap_tray = tray;
    swap_tray.seated = 2;
    const swap_ui: lens_socket.SocketUi = .{ .open = false, .swap_phase = 13, .swap_from = 0, .swap_to = 2 };
    @memset(fb.pixels, clear);
    dl.len = 0;
    try field.compose(gpa, &f, particles.slice(), light, cell_w, cell_h, &dl);
    _ = try lens_socket.build(arena, &engine, swap_tray, swap_ui, sock_geom, &dl, null);
    try raster.paint(gpa, &engine, dl.slice(), &fb, clear);
    try writePpm(io, gpa, &fb, "/tmp/zat_socket_seat.ppm");
    std.debug.print("wrote /tmp/zat_socket_seat.ppm ({d}x{d}, {d} items)\n", .{ W, H, dl.len });

    // PHASE 2 — the loadout PAGE: three stacked sockets (Feed / Replies / Zones)
    // from the catalog defaults, over the field, via the real layoutLoadout path.
    const lf_c, const lf_b = try lens_catalog.defaultFeedLoadout(arena);
    const lr_c, const lr_b = try lens_catalog.defaultReplyLoadout(arena);
    const lz_c, const lz_b = try lens_catalog.defaultZoneLoadout(arena);
    const feed_t: lens_socket.TrayView = .{ .cards = lf_c, .text = lf_b, .seated = lens_catalog.default_feed_seated };
    const reply_t: lens_socket.TrayView = .{ .cards = lr_c, .text = lr_b, .seated = lens_catalog.default_reply_seated };
    const zone_t: lens_socket.TrayView = .{ .cards = lz_c, .text = lz_b, .seated = lens_catalog.default_zone_seated };
    var fh: lens_socket.HitList = .empty;
    defer fh.deinit(gpa);
    var rh: lens_socket.HitList = .empty;
    defer rh.deinit(gpa);
    var zh: lens_socket.HitList = .empty;
    defer zh.deinit(gpa);
    @memset(fb.pixels, clear);
    dl.len = 0;
    try field.compose(gpa, &f, particles.slice(), light, cell_w, cell_h, &dl);
    _ = try feed_view.layoutLoadout(gpa, &engine, @intCast(W), @intCast(H), &dl, null, lens_socket.seatedAccent(feed_t), 0, 0, null, feed_t, .{}, &fh, reply_t, .{}, &rh, zone_t, .{}, &zh, false, false, null, &.{}, .{ .step = .landing, .answers = .{}, .config = discover.DEFAULT_CONFIG, .name = "", .color = 0 }, .{ .cards = &.{}, .text = "", .seated = 0 });
    try raster.paint(gpa, &engine, dl.slice(), &fb, clear);
    try writePpm(io, gpa, &fb, "/tmp/zat_loadout.ppm");
    std.debug.print("wrote /tmp/zat_loadout.ppm ({d}x{d}, {d} items)\n", .{ W, H, dl.len });

    // ── THE ENROLLMENT SURFACE — the calm card over a DETUNED field ──
    // A wispier field: bigger cells (wider spacing), lower ambient, smaller
    // light radius — present but quiet, not the feed's full material.
    const ecw: u16 = 20;
    const ech: u16 = 28;
    const ecols: u16 = @intCast(W / ecw);
    const erows: u16 = @intCast(H / ech);
    var ef: field.Field = .{};
    try field.init(gpa, &ef, ecols, erows);
    defer field.deinit(gpa, &ef);
    field.fillAmbient(&ef);
    const elight: field.Light = .{
        .x = @floatFromInt(ecols / 2),
        .y = @floatFromInt(erows / 3),
        .radius = @floatFromInt(ecols / 2),
        .ambient = 0.14,
    };

    const pw = "River-Anchor-Velvet-Tide";
    const EStep = struct { name: []const u8, view: enroll_view.EnrollView };
    const esteps = [_]EStep{
        .{ .name = "enroll_0_provenance", .view = .{ .step = .provenance } },
        .{ .name = "enroll_0_hover", .view = .{ .step = .provenance, .hover_on = true, .hover = .choose_new, .hover_t = 1.0 } },
        .{ .name = "enroll_1_new", .view = .{ .step = .identity, .branch = .new, .username = "connor", .email = "connor@example.com", .age_ok = true, .tos_ok = true, .focus = .username } },
        .{ .name = "enroll_1_new_recovery", .view = .{ .step = .identity, .branch = .new, .username = "connor", .use_email = false } }, // consent unchecked → button disabled
        .{ .name = "enroll_1_tos", .view = .{ .step = .identity, .branch = .new, .username = "connor", .info = .tos } },
        .{ .name = "enroll_1_existing", .view = .{ .step = .identity, .branch = .existing, .handle = "connor.bsky.social", .age_ok = true, .tos_ok = true, .focus = .handle } },
        .{ .name = "enroll_2_membership", .view = .{ .step = .membership, .branch = .new } }, // nothing selected yet
        .{ .name = "enroll_2_secure", .view = .{ .step = .membership, .branch = .new, .tier = .secure, .tier_chosen = true, .bar_t = 1.0 } },
        .{ .name = "enroll_2_super", .view = .{ .step = .membership, .branch = .new, .tier = .super_secure, .tier_chosen = true, .bar_t = 1.0 } },
        .{ .name = "enroll_2_overkill", .view = .{ .step = .membership, .branch = .new, .tier = .ultra_secure, .tier_chosen = true, .bar_t = 1.0, .bar_phase = 2.0 } },
        .{ .name = "enroll_2_popover", .view = .{ .step = .membership, .branch = .new, .hover_on = true, .hover = .tier_overkill, .hover_t = 1.0 } },
        .{ .name = "enroll_2_info", .view = .{ .step = .membership, .branch = .new, .tier = .secure, .tier_chosen = true, .bar_t = 1.0, .info = .membership } },
        .{ .name = "enroll_2_deposit", .view = .{ .step = .membership, .branch = .new, .tier = .super_secure, .tier_chosen = true, .bar_t = 1.0, .hover_on = true, .hover = .deposit, .hover_t = 1.0 } },
        .{ .name = "enroll_3_password", .view = .{ .step = .password, .branch = .new, .password = pw, .saved = true } },
        .{ .name = "enroll_3_overkill", .view = .{ .step = .password, .branch = .new, .password = "Lanky-Giddy-Fiber-Routing-Rundown-Dweeb-Ageless-Cactus-Garage", .saved = true } },
        .{ .name = "enroll_3_crafting", .view = .{ .step = .password, .branch = .new, .password = "Lanky-Giddy-Fiber-Routing-Rundown-Dweeb-Ageless-Cactus-Garage", .craft_t = 0.45 } },
        .{ .name = "enroll_4_confirm_spot", .view = .{ .step = .confirm, .branch = .new, .confirm_stage = .spot, .spot_positions = .{ 2, 4, 6 }, .spot = .{ "anchor", "", "" }, .focus = .spot0 } },
        .{ .name = "enroll_4_confirm_full", .view = .{ .step = .confirm, .branch = .new, .confirm_stage = .full, .full = "River-Anchor-Velvet", .focus = .full } },
        .{ .name = "enroll_4_confirm_checking", .view = .{ .step = .confirm, .branch = .new, .confirm_stage = .full, .full = "River-Anchor-Velvet-Tide", .confirm_checking = true } },
        .{ .name = "enroll_4_confirm_error", .view = .{ .step = .confirm, .branch = .new, .confirm_stage = .spot, .spot_positions = .{ 1, 3, 5 }, .confirm_error = true } },
        .{ .name = "enroll_4b_recovery", .view = .{ .step = .recovery, .branch = .new, .use_email = false, .recovery_key = "8F2A 1C9B 44D7 E013 A6B5 2F8C 90D1 7E4A 3C5D 6E2F 18A0 BB47 92E1 04CF D6A3 5B19", .rec_saved = true } },
        .{ .name = "enroll_5_done", .view = .{ .step = .done, .branch = .new, .did = "did:plc:7mock4example", .final_handle = "connor.zat4.com" } },
        .{ .name = "enroll_6_verifying", .view = .{ .step = .verifying, .pow_t = 0.62, .bar_phase = 2.0 } },
        .{ .name = "enroll_6_verified", .view = .{ .step = .verifying, .pow_t = 1.0 } },
        .{ .name = "enroll_6_seal", .view = .{ .step = .verifying, .pow_t = 1.0, .seal_t = 0.74 } },
    };
    var epath_buf: [64]u8 = undefined;
    for (esteps) |es| {
        @memset(fb.pixels, clear);
        dl.len = 0;
        try field.compose(gpa, &ef, particles.slice(), elight, ecw, ech, &dl);
        try enroll_view.layout(gpa, &engine, @intCast(W), @intCast(H), es.view, &dl, null);
        try raster.paint(gpa, &engine, dl.slice(), &fb, clear);
        const path = try std.fmt.bufPrint(&epath_buf, "/tmp/zat_{s}.ppm", .{es.name});
        try writePpm(io, gpa, &fb, path);
        std.debug.print("wrote {s} ({d} items)\n", .{ path, dl.len });
    }
}

/// A few placeholder lenses (preview-only sample data, shell side). Builds
/// the SoA tray + text blob the pure widget reads. Colors mirror §11.5:
/// For You = amber, Following = grey, Discover = blue.
fn sampleTray(arena: std.mem.Allocator) !lens_socket.TrayView {
    var blob: std.ArrayListUnmanaged(u8) = .empty;
    const Spec = struct {
        name: []const u8,
        author: []const u8,
        ranks: []const u8,
        desc: []const u8,
        cid: []const u8,
        color: u8,
        flags: lens_socket.LensFlags,
    };
    const specs = [_]Spec{
        .{ .name = "For You", .author = "zat4 default", .ranks = "engagement + recency", .desc = "The adaptive default.", .cid = "bafy7x2a", .color = 0, .flags = .{ .learns = true, .is_default = true } },
        .{ .name = "Following", .author = "zat4 default", .ranks = "chronological", .desc = "Reverse-chron of your follows.", .cid = "bafy0c11", .color = 2, .flags = .{ .is_default = true } },
        .{ .name = "Discover", .author = "zat4 default", .ranks = "popularity + topics", .desc = "Strong posts beyond your follows.", .cid = "bafy9f3d", .color = 1, .flags = .{ .learns = true } },
        .{ .name = "Quiet Mode", .author = "@desh.zat", .ranks = "low-velocity first", .desc = "Down-ranks pile-ons.", .cid = "bafy4a8e", .color = 7, .flags = .{} },
        .{ .name = "Zig Only", .author = "@atlas.zat", .ranks = "tag: zig", .desc = "A topic lens for the zig tag.", .cid = "bafy2b6c", .color = 4, .flags = .{} },
        // 5 lenses in a 6-slot socket → one empty "add a lens" placeholder shows.
    };
    const cards = try arena.alloc(lens_socket.LensCard, specs.len);
    for (specs, 0..) |s, i| {
        const name: lens_socket.TextSpan = .{ .off = @intCast(blob.items.len), .len = @intCast(s.name.len) };
        try blob.appendSlice(arena, s.name);
        const author: lens_socket.TextSpan = .{ .off = @intCast(blob.items.len), .len = @intCast(s.author.len) };
        try blob.appendSlice(arena, s.author);
        const ranks: lens_socket.TextSpan = .{ .off = @intCast(blob.items.len), .len = @intCast(s.ranks.len) };
        try blob.appendSlice(arena, s.ranks);
        const desc: lens_socket.TextSpan = .{ .off = @intCast(blob.items.len), .len = @intCast(s.desc.len) };
        try blob.appendSlice(arena, s.desc);
        const cid: lens_socket.TextSpan = .{ .off = @intCast(blob.items.len), .len = @intCast(s.cid.len) };
        try blob.appendSlice(arena, s.cid);
        cards[i] = .{ .cid = cid, .name = name, .author = author, .ranks = ranks, .desc = desc, .color = s.color, .flags = s.flags };
    }
    return .{ .cards = cards, .text = blob.items, .seated = 0 };
}

/// A thread PostView with an explicit nesting depth + focus + stitched flag (preview only).
fn tv(handle: []const u8, name: []const u8, body: []const u8, tint: u32, initial: u8, depth: u8, is_focus: bool, stitched: bool, has_kids: bool) feed_view.PostView {
    _ = handle;
    return .{
        .name = name,
        .handle = "@x.zat",
        .age = "2h",
        .body = body,
        .tint = tint,
        .reply = 1,
        .boost = 0,
        .like = 0,
        .initial = initial,
        .liked = false,
        .boosted = false,
        .depth = depth,
        .is_focus = is_focus,
        .stitched = stitched,
        .has_kids = has_kids,
    };
}

fn writePpm(io: std.Io, gpa: std.mem.Allocator, fb: *const raster.Framebuffer, path: []const u8) !void {
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(gpa);
    var hdr: [32]u8 = undefined;
    try buf.appendSlice(gpa, try std.fmt.bufPrint(&hdr, "P6\n{d} {d}\n255\n", .{ fb.width, fb.height }));
    for (fb.pixels) |px| {
        try buf.append(gpa, @intCast((px >> 16) & 0xFF));
        try buf.append(gpa, @intCast((px >> 8) & 0xFF));
        try buf.append(gpa, @intCast(px & 0xFF));
    }
    const file = try std.Io.Dir.createFileAbsolute(io, path, .{});
    defer file.close(io);
    var wbuf: [16384]u8 = undefined;
    var fw = file.writer(io, &wbuf);
    try fw.interface.writeAll(buf.items);
    try fw.interface.flush();
}

fn mk(handle: []const u8, name: []const u8, body: []const u8, created: i64, like: u32, boost: u32, reply: u32, liked: bool, reposted: bool) feed.TimelineItem {
    return .{
        .uri = "",
        .cid = "",
        .author_handle = handle,
        .author_display_name = name,
        .reposted_by_handle = "",
        .replying_to_handle = "",
        .text = body,
        .created_at = created,
        .like_count = like,
        .repost_count = boost,
        .reply_count = reply,
        .quote_count = 0,
        .label_flags = .{},
        .item_flags = .{ .viewer_liked = liked, .viewer_reposted = reposted },
    };
}
