// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Zat4 — a social-media client built on the AT Protocol.
// Copyright (C) 2026  Connor Avila

//! TILING LIVE — the interactive sandbox (`zig build tiling-live`).
//!
//! B1 classification: SHELL. A preview of the REAL app look rebuilt on the
//! partition-layout foundation.
//!
//! TWO load-bearing ideas:
//!   1. LAYOUT IS DATA. `layout_structure` is a flat array of plain node
//!      records (A1 plain data, A4 index children — DOD). A page is just an
//!      array of parameter values over that structure. Adding a region = a row
//!      in the data; resizing one = a number in a page. No layout code per page.
//!   2. GEOMETRY IS A SOLVED PARTITION. Each frame the parameters spring toward
//!      the page targets (the physics), the tree is generated from the data,
//!      and the PURE CARVE (`core/tiling.zig`) solves it into a partition.
//!      Regions share boundaries → overlap is unrepresentable. Window resize is
//!      free: the carve takes (W,H), so a new size just re-solves — smooth and
//!      always consistent, no second code path.
//!
//! Renders on the GPU (build vertices -> draw -> swap, no per-frame socket
//! blit), software present as fallback. Touches NONE of the live app render
//! path — delete this file + the build step → gone.
//!
//! Controls: any key / click -> next page · right-click -> back · 1-4 -> jump ·
//!           Esc / close -> quit.   `--snapshot <dir>` writes PPMs (software).

const std = @import("std");
const text = @import("core/text.zig");
const raster = @import("core/raster.zig");
const tiling = @import("core/tiling.zig");
const gpu = @import("shell/gpu.zig");
const window_shell = @import("shell/window.zig");
const layout_core = @import("core/layout.zig");

const Node = tiling.Node;
const RegionKind = tiling.RegionKind;

// ---- the real app palette (from feed_view.zig) ----
const bg: u32 = 0xFF181812;
const ink: u32 = 0xFFEDEAE0;
const body_c: u32 = 0xFFD8D3C8;
const muted: u32 = 0xFF9A968A;
const faint: u32 = 0xFF6A655A;
const amber: u32 = 0xFFE8B84B;
const like_c: u32 = 0xFFF0617A;
const boost_c: u32 = 0xFF8FD18F;
const blue: u32 = 0xFF4DA3FF;
const icon_grey: u32 = 0xFFB4B1A8;
const panel: u32 = 0xFF211F1A;
const panel_edge: u32 = 0xFF2C2A22;
const av_bg: u32 = 0xFF3F3B2D;

const cfg0: tiling.Config = .{ .seam = 0 };
const gap_px: f32 = 1; // partition is edge-to-edge; tiny visual breathing room
const spring_k: f32 = 130.0;
const spring_c: f32 = 24.0;

// Content-driven tile demo (the cheap, within-screen movement): the search
// tile's height grows with its RESULTS, and in PUSH mode that shoves the
// trending + follow tiles down — pure repositioning, no relayout, so it costs
// nothing. `overlay` switches to drawing the results OVER the trending instead
// (the "or it could just go over it" creative-freedom choice).
var search_t: f32 = 0; // 0 = collapsed, 1 = results fully shown (animated)
var search_v: f32 = 0;
var search_want: bool = false;
var overlay: bool = false;
const results_h: f32 = 188; // natural height the search results want when open

// ---- LAYOUT AS DATA -------------------------------------------------------
// A flat node array. Splits reference children by an index RANGE (A4: indexes,
// not pointers). `param` selects which page parameter drives a leaf's size
// (0xFF = a fixed pixel size in `fixed`). Add a box → add rows here.
const LKind = enum(u8) { split_h, split_v, nav, feed, sidebar, masthead };
const LNode = struct {
    // A7.2: cold — the layout-as-data node record, a tiny static array.
    kind: LKind,
    param: u8 = no_param, // index into page params (weight or height)
    fixed: f32 = 0, // size when param == no_param
    first: u8 = 0, // first child index (splits)
    count: u8 = 0, // child count (splits)
    const no_param: u8 = 0xFF;
};

const P_PRIMARY = 0;
const P_CONTEXT = 1;
const P_MAST = 2;
const N_PARAM = 3;

// nav | ( masthead / ( feed | sidebar ) )
const layout_structure = [_]LNode{
    .{ .kind = .split_h, .first = 1, .count = 2 }, // 0 root
    .{ .kind = .nav, .param = LNode.no_param, .fixed = 210 }, // 1 fixed rail
    .{ .kind = .split_v, .first = 3, .count = 2 }, // 2 main area
    .{ .kind = .masthead, .param = P_MAST }, // 3 (height param; 0 = absent)
    .{ .kind = .split_h, .first = 5, .count = 2 }, // 4 content row
    .{ .kind = .feed, .param = P_PRIMARY }, // 5 primary column (weight)
    .{ .kind = .sidebar, .param = P_CONTEXT }, // 6 context panel (weight)
};

const Page = struct {
    // A7.2: cold — a 4-element static table.
    name: []const u8,
    params: [N_PARAM]f32,
};
const pages = [_]Page{
    // primary  context  mastH(px)
    .{ .name = "Home", .params = .{ 3.0, 2.0, 0.0 } },
    .{ .name = "Algorithm", .params = .{ 6.0, 1.6, 0.0 } }, // feed widens, context slim
    .{ .name = "Reading", .params = .{ 2.0, 0.0, 0.0 } }, // context gone → feed fills
    .{ .name = "Profile", .params = .{ 3.0, 2.0, 150.0 } }, // masthead appears
};

fn kindFor(lk: LKind) RegionKind {
    return switch (lk) {
        .nav => .nav,
        .feed => .feed,
        .sidebar => .widgets,
        .masthead => .profile_id,
        else => .feed,
    };
}

/// Generate the carve's Node tree from the flat data + current parameters.
/// Children are arena-allocated each frame (cheap; reset wholesale).
fn buildFromData(arena: std.mem.Allocator, idx: usize, p: [N_PARAM]f32) !Node {
    const n = layout_structure[idx];
    switch (n.kind) {
        .nav, .feed, .sidebar, .masthead => {
            const kind = kindFor(n.kind);
            if (n.param == LNode.no_param) {
                return .{ .leaf = .{ .kind = kind, .weight = 0, .min = @intFromFloat(@max(0.0, n.fixed)) } };
            }
            const val = p[n.param];
            if (n.kind == .masthead) // height param (fixed-size leaf)
                return .{ .leaf = .{ .kind = kind, .weight = 0, .min = @intFromFloat(@max(0.0, val)) } };
            const wi: u16 = @max(1, @as(u16, @intFromFloat(@max(0.0, val) * 128.0)));
            return .{ .leaf = .{ .kind = kind, .weight = wi, .min = 0 } };
        },
        .split_h, .split_v => {
            const kids = try arena.alloc(Node, n.count);
            for (0..n.count) |i| kids[i] = try buildFromData(arena, n.first + i, p);
            return .{ .split = .{ .dir = if (n.kind == .split_h) .h else .v, .children = kids } };
        },
    }
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const env = init.environ_map;

    const argv = try init.minimal.args.toSlice(gpa);
    defer gpa.free(argv);
    if (argv.len > 1 and std.mem.eql(u8, argv[1], "--snapshot")) {
        try snapshot(gpa, init.io, if (argv.len > 2) argv[2] else "/tmp");
        return;
    }

    const win = window_shell.open(gpa, env, "zat - tiling", 150, 56) catch |err| {
        std.debug.print("window.open failed: {s} (on X11, is DISPLAY set?)\n", .{@errorName(err)});
        return;
    };
    defer window_shell.close(win);

    var W: u32 = win.fb.width;
    var H: u32 = win.fb.height;

    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);

    var g_opt: ?gpu.Gpu = gpu.init(win.wid) catch null;
    defer if (g_opt) |*g| gpu.deinit(g);
    var feed_opt: ?gpu.Feed = null;
    defer if (feed_opt) |*fp| gpu.feedDeinit(fp, gpa);
    if (g_opt != null) {
        gpu.setViewport(@intCast(W), @intCast(H));
        feed_opt = gpu.initFeed(gpa) catch null;
        if (feed_opt == null) g_opt = null;
    }
    if (g_opt == null) std.debug.print("GPU unavailable — using the software path (may be laggy).\n", .{});

    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var events: std.ArrayList(layout_core.InputEvent) = .empty;
    defer events.deinit(gpa);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var cur_page: usize = 0;
    var p: [N_PARAM]f32 = pages[0].params;
    var v: [N_PARAM]f32 = .{0} ** N_PARAM;

    const dt: f32 = 1.0 / 60.0;
    const cr: f32 = @as(f32, (bg >> 16) & 0xFF) / 255.0;
    const cg: f32 = @as(f32, (bg >> 8) & 0xFF) / 255.0;
    const cb: f32 = @as(f32, bg & 0xFF) / 255.0;

    while (true) {
        const pr = window_shell.pump(win, 16, gpa, &out, &events) catch break;
        if (pr.closed) break;
        if (win.fb.width != W or win.fb.height != H) {
            W = win.fb.width;
            H = win.fb.height;
            if (g_opt != null) gpu.setViewport(@intCast(W), @intCast(H));
        }

        var nav: ?usize = null;
        var quit = false;
        for (out.items) |b| {
            if (b == 27) quit = true //
            else if (b == 's' or b == 'S') search_want = !search_want //
            else if (b == 'o' or b == 'O') overlay = !overlay //
            else if (b >= '1' and b <= '4') nav = @as(usize, b - '1') //
            else nav = (cur_page + 1) % pages.len;
        }
        out.clearRetainingCapacity();
        for (events.items) |ev| {
            if (ev.kind == .button_down) nav = if (ev.button == 3) (cur_page + pages.len - 1) % pages.len else (cur_page + 1) % pages.len;
        }
        events.clearRetainingCapacity();
        if (quit) break;
        if (nav) |pg| cur_page = pg;

        const tg = pages[cur_page].params;
        for (0..N_PARAM) |i| springTo(&p[i], &v[i], tg[i], dt);
        // The content-driven search tile springs open/closed (cheap repositioning).
        springTo(&search_t, &search_v, if (search_want) @as(f32, 1.0) else 0.0, dt);

        _ = arena_state.reset(.retain_capacity);
        dl.len = 0;
        try composeFrame(gpa, &dl, &engine, arena_state.allocator(), p, W, H, cur_page);

        if (g_opt) |*g| {
            if (feed_opt) |*fp| {
                gpu.clear(cr, cg, cb);
                gpu.feedBuild(fp, gpa, &engine, dl.slice(), 1.0) catch {};
                gpu.feedDraw(fp, @intCast(W), @intCast(H));
                gpu.swap(g);
            }
        } else {
            window_shell.presentDrawList(win, gpa, &engine, dl.slice(), bg) catch break;
        }
    }
}

fn springTo(pos: *f32, vel: *f32, target: f32, dt: f32) void {
    vel.* += (-spring_k * (pos.* - target) - spring_c * vel.*) * dt;
    pos.* += vel.* * dt;
}

fn composeFrame(
    gpa: std.mem.Allocator,
    dl: *raster.DrawList,
    engine: *text.Engine,
    arena: std.mem.Allocator,
    p: [N_PARAM]f32,
    W: u32,
    H: u32,
    cur_page: usize,
) !void {
    const root = try buildFromData(arena, 0, p);
    const carve = tiling.tile(arena, &root, @intCast(W), @intCast(H), cfg0) catch return;

    for (carve.viewports) |vp| {
        const r: Rect = .{
            .x = @as(f32, @floatFromInt(vp.x)) + gap_px,
            .y = @as(f32, @floatFromInt(vp.y)) + gap_px,
            .w = @as(f32, @floatFromInt(vp.w)) - gap_px * 2,
            .h = @as(f32, @floatFromInt(vp.h)) - gap_px * 2,
        };
        if (r.w < 12 or r.h < 12) continue;
        const a = std.math.clamp((@min(r.w, r.h) - 8) / 80.0, 0, 1);
        switch (vp.kind) {
            .nav => try drawNav(gpa, dl, r, a, cur_page),
            .widgets => try drawSidebar(gpa, dl, engine, r, a, cur_page),
            .profile_id => try drawMasthead(gpa, dl, engine, r, a),
            else => try drawFeed(gpa, dl, engine, r, a, cur_page),
        }
    }

    var hud: [128]u8 = undefined;
    const line = std.fmt.bufPrint(&hud, "{s}    [s] search (pushes trending)    [o] push/overlay: {s}    1-4: page    esc: quit", .{ pages[cur_page].name, if (overlay) "overlay" else "push" }) catch pages[cur_page].name;
    try drawText(gpa, dl, line, 16, @as(i32, @intCast(H)) - 14, 13, 0, muted, a_full);
}

const a_full: f32 = 1.0;
const Rect = struct { x: f32, y: f32, w: f32, h: f32 }; // A7.2: cold transient

// ---- content: the real app look, region by region ----

const nav_items = [_][]const u8{ "Home", "Zones", "Activity", "Messages", "Algorithms", "Settings" };

fn drawNav(gpa: std.mem.Allocator, dl: *raster.DrawList, r: Rect, a: f32, cur_page: usize) !void {
    // wordmark
    try drawText(gpa, dl, "zat4.", @as(i32, @intFromFloat(r.x)) + 26, @as(i32, @intFromFloat(r.y)) + 44, 26, 1, amber, a);
    // nav rows
    // page → which nav row is active (-1 = none, e.g. Profile isn't in the rail)
    const page_nav = [_]i8{ 0, 4, 0, -1 };
    var y = r.y + 84;
    for (nav_items, 0..) |label, i| {
        const active = page_nav[cur_page] == @as(i8, @intCast(i));
        if (active) try rrect(gpa, dl, r.x + 14, y - 4, r.w - 28, 44, 0xFF26241B, a, 12);
        // icon dot
        try rrect(gpa, dl, r.x + 30, y + 8, 22, 22, if (active) amber else icon_grey, a * 0.9, 6);
        try drawText(gpa, dl, label, @as(i32, @intFromFloat(r.x)) + 66, @as(i32, @intFromFloat(y)) + 28, 16, if (active) @as(u8, 1) else 0, if (active) ink else body_c, a);
        y += 50;
    }
    // New post button
    const by = y + 16;
    try rrect(gpa, dl, r.x + 14, by, r.w - 28, 50, amber, a, 14);
    try drawTextCentered(gpa, dl, "New post", r.x + 14, by + 32, r.w - 28, 16, 1, 0xFF1A1710, a);
    // profile chip pinned near bottom
    const py = r.y + r.h - 64;
    try rrect(gpa, dl, r.x + 14, py, r.w - 28, 50, panel, a, 14);
    try circle(gpa, dl, r.x + 28, py + 9, 32, 0xFF6E6450, a);
    try drawText(gpa, dl, "you", @as(i32, @intFromFloat(r.x)) + 70, @as(i32, @intFromFloat(py)) + 22, 14, 1, ink, a);
    try drawText(gpa, dl, "@you.zat", @as(i32, @intFromFloat(r.x)) + 70, @as(i32, @intFromFloat(py)) + 40, 12, 0, muted, a);
}

const Post = struct {
    // A7.2: cold — sample feed data, a fixed 4-element array.
    initial: []const u8,
    tint: u32,
    name: []const u8,
    handle: []const u8,
    age: []const u8,
    body: []const u8,
    reply: []const u8,
    boost: []const u8,
    like: []const u8,
    tags: []const []const u8,
};
const posts = [_]Post{
    .{ .initial = "M", .tint = 0xFF9FB0C7, .name = "Mara Vesper", .handle = "@mara.zat", .age = "2m", .body = "the whole point of a #smallweb is that you can actually read the room. ten thousand strangers isn't a room, it's weather.", .reply = "6", .boost = "9", .like = "48", .tags = &.{ "#smallweb", "#community" } },
    .{ .initial = "f", .tint = 0xFFC9A87A, .name = "field notes", .handle = "@fieldnotes.zat", .age = "14m", .body = "shipped the lighting pass tonight. the letters catch the light now, and the whole field moves when you touch it.", .reply = "12", .boost = "31", .like = "121", .tags = &.{} },
    .{ .initial = "O", .tint = 0xFF8FD18F, .name = "Okonkwo", .handle = "@oko.zat", .age = "1h", .body = "#monospace is the most honest a feed can be. same column, same weight, nobody shouts louder by being wider.", .reply = "24", .boost = "18", .like = "73", .tags = &.{ "#monospace", "#design", "#typography" } },
    .{ .initial = "l", .tint = 0xFFB59EC9, .name = "lune", .handle = "@lune.zat", .age = "3h", .body = "woke up to the field still drifting where i left it. it kept the light on.", .reply = "3", .boost = "7", .like = "39", .tags = &.{} },
};

fn drawFeed(gpa: std.mem.Allocator, dl: *raster.DrawList, engine: *text.Engine, r: Rect, a: f32, cur_page: usize) !void {
    const lx = r.x + 26;
    const cw = r.w - 52;
    // page title
    try drawText(gpa, dl, pages[cur_page].name, @as(i32, @intFromFloat(lx)), @as(i32, @intFromFloat(r.y)) + 44, 26, 1, ink, a);
    // a socket/tray bar
    try rrect(gpa, dl, lx, r.y + 64, cw, 46, panel, a, 12);
    try circle(gpa, dl, lx + 14, r.y + 64 + 16, 12, amber, a);
    try drawText(gpa, dl, "Zat4 Discover", @as(i32, @intFromFloat(lx)) + 36, @as(i32, @intFromFloat(r.y)) + 64 + 28, 14, 1, ink, a);

    var y = r.y + 132;
    for (posts) |post| {
        if (y > r.y + r.h - 40) break;
        y = try drawPost(gpa, dl, engine, lx, y, cw, post, a);
        // divider
        try rect(gpa, dl, lx, y + 6, cw, 1, panel_edge, a);
        y += 24;
    }
}

fn drawPost(gpa: std.mem.Allocator, dl: *raster.DrawList, engine: *text.Engine, x: f32, y0: f32, w: f32, post: Post, a: f32) !f32 {
    // avatar
    try circle(gpa, dl, x, y0, 38, av_bg, a);
    try drawTextCentered(gpa, dl, post.initial, x, y0 + 25, 38, 16, 1, post.tint, a);
    const tx = x + 38 + 16;
    const tw = w - (38 + 16);
    // name + handle · age  (the dot is DRAWN, never a UTF-8 byte)
    try drawText(gpa, dl, post.name, @as(i32, @intFromFloat(tx)), @as(i32, @intFromFloat(y0)) + 14, 16, 1, ink, a);
    const mx = tx + textWidth(post.name, 16) + 14;
    try drawText(gpa, dl, post.handle, @as(i32, @intFromFloat(mx)), @as(i32, @intFromFloat(y0)) + 14, 14, 0, muted, a);
    const hw = textWidth(post.handle, 14);
    try circle(gpa, dl, mx + hw + 7, y0 + 6, 3, muted, a);
    try drawText(gpa, dl, post.age, @as(i32, @intFromFloat(mx + hw + 18)), @as(i32, @intFromFloat(y0)) + 14, 14, 0, muted, a);
    // body — real word wrap, with #tags / @mentions in blue (reflows on resize)
    var by = y0 + 38;
    by = try drawWrapped(gpa, dl, engine, tx, by, tw, 16, post.body, a);
    // engagement row
    const ey = by + 14;
    try engGlyph(gpa, dl, tx, ey, icon_grey, a);
    try drawText(gpa, dl, post.reply, @as(i32, @intFromFloat(tx)) + 22, @as(i32, @intFromFloat(ey)) + 5, 13, 0, muted, a);
    try engGlyph(gpa, dl, tx + 90, ey, boost_c, a);
    try drawText(gpa, dl, post.boost, @as(i32, @intFromFloat(tx)) + 90 + 22, @as(i32, @intFromFloat(ey)) + 5, 13, 0, muted, a);
    try heartGlyph(gpa, dl, tx + 180, ey, like_c, a);
    try drawText(gpa, dl, post.like, @as(i32, @intFromFloat(tx)) + 180 + 22, @as(i32, @intFromFloat(ey)) + 5, 13, 0, muted, a);
    var ny = ey + 24;
    // hashtag pills
    if (post.tags.len > 0) {
        var px = tx;
        for (post.tags) |tag| {
            const pw = textWidth(tag, 13) + 24;
            try rrect(gpa, dl, px, ny, pw, 26, 0xFF223042, a, 13);
            try drawText(gpa, dl, tag, @as(i32, @intFromFloat(px)) + 12, @as(i32, @intFromFloat(ny)) + 17, 13, 0, blue, a);
            px += pw + 10;
        }
        ny += 34;
    }
    return ny;
}

fn drawSidebar(gpa: std.mem.Allocator, dl: *raster.DrawList, engine: *text.Engine, r: Rect, a: f32, cur_page: usize) !void {
    _ = engine;
    const lx = r.x + 20;
    const cw = r.w - 40;
    if (cw < 60) return; // too narrow to read — just the panel

    const st = std.math.clamp(search_t, 0, 1);
    // PUSH: the live height of the search-results tile shoves everything below it.
    // OVERLAY: the results float over the trending instead (push = 0).
    const grow = results_h * st;
    const push: f32 = if (overlay) 0 else grow;

    // the search bar (active-looking while results are open)
    const searching = st > 0.02;
    try rrect(gpa, dl, lx, r.y + 24, cw, 44, panel, a, if (searching) @as(u8, 12) else 12);
    if (searching) try strokeRoundFake(gpa, dl, lx, r.y + 24, cw, 44, amber, a * 0.7);
    try circle(gpa, dl, lx + 12, r.y + 24 + 14, 16, if (searching) amber else muted, a * 0.8);
    try drawText(gpa, dl, if (searching) "smal" else "Search zat4", @as(i32, @intFromFloat(lx)) + 40, @as(i32, @intFromFloat(r.y)) + 24 + 28, 14, 0, if (searching) ink else muted, a);

    // TRENDING (pushed down by `push`)
    const trend_y = r.y + 86 + push;
    try rrect(gpa, dl, lx, trend_y, cw, 230, panel, a, 14);
    const head = if (cur_page == 1) "ALGORITHM" else "TRENDING";
    try drawText(gpa, dl, head, @as(i32, @intFromFloat(lx)) + 18, @as(i32, @intFromFloat(trend_y)) + 26, 12, 1, muted, a);
    const trend = [_][2][]const u8{
        .{ "at://small-net", "2,481 posts" },
        .{ "glyph fields", "913 posts" },
        .{ "0.16 release", "1,204 posts" },
        .{ "one column", "640 posts" },
    };
    var ty = trend_y + 48;
    for (trend) |t| {
        if (cw > 80) {
            try drawText(gpa, dl, t[0], @as(i32, @intFromFloat(lx)) + 18, @as(i32, @intFromFloat(ty)) + 4, 15, 1, ink, a);
            try drawText(gpa, dl, t[1], @as(i32, @intFromFloat(lx)) + 18, @as(i32, @intFromFloat(ty)) + 24, 12, 0, faint, a);
        }
        ty += 44;
    }

    // WHO TO FOLLOW (pushed down too)
    const who_y = r.y + 340 + push;
    try rrect(gpa, dl, lx, who_y, cw, 200, panel, a, 14);
    try drawText(gpa, dl, "WHO TO FOLLOW", @as(i32, @intFromFloat(lx)) + 18, @as(i32, @intFromFloat(who_y)) + 26, 12, 1, muted, a);
    const who = [_][2][]const u8{ .{ "Desh", "@desh.zat" }, .{ "atlas", "@atlas.zat" }, .{ "rune", "@rune.zat" } };
    var wy = who_y + 50;
    for (who) |u| {
        try circle(gpa, dl, lx + 18, wy, 30, av_bg, a);
        if (cw > 120) {
            try drawText(gpa, dl, u[0], @as(i32, @intFromFloat(lx)) + 60, @as(i32, @intFromFloat(wy)) + 12, 14, 1, ink, a);
            try drawText(gpa, dl, u[1], @as(i32, @intFromFloat(lx)) + 60, @as(i32, @intFromFloat(wy)) + 30, 12, 0, muted, a);
            try rrect(gpa, dl, lx + cw - 78, wy + 4, 70, 30, ink, a, 15);
            try drawTextCentered(gpa, dl, "Follow", lx + cw - 78, wy + 24, 70, 12, 1, 0xFF1A1710, a);
        }
        wy += 48;
    }

    // SEARCH RESULTS — content-driven height, drawn LAST so OVERLAY mode floats
    // it over the trending. The rows are clipped to the live height, so they
    // appear as the tile grows. None of this re-lays-out anything (cheap).
    if (searching) {
        const ry = r.y + 24 + 44 + 8;
        const ra = a * st; // fade with the grow
        if (overlay) try rrect(gpa, dl, lx - 4, ry - 4, cw + 8, grow + 8, 0xFF0C0B08, a * 0.45 * st, 16); // drop shadow
        try rrect(gpa, dl, lx, ry, cw, grow, 0xFF26241B, ra, 14);
        const results = [_][2][]const u8{
            .{ "#smallweb", "zone · 412 posts" },
            .{ "#small-net", "zone · 2,481 posts" },
            .{ "@mara.zat", "Mara Vesper" },
            .{ "smallweb manifesto", "post · 2d" },
        };
        var sy = ry + 20;
        for (results) |res| {
            if (sy + 30 > ry + grow) break; // clip rows to the live height
            try circle(gpa, dl, lx + 16, sy, 20, amber, ra * 0.8);
            try drawText(gpa, dl, res[0], @as(i32, @intFromFloat(lx)) + 46, @as(i32, @intFromFloat(sy)) + 9, 14, 1, ink, ra);
            try drawText(gpa, dl, res[1], @as(i32, @intFromFloat(lx)) + 46, @as(i32, @intFromFloat(sy)) + 27, 12, 0, muted, ra);
            sy += 44;
        }
    }
}

/// A faint rounded outline (four thin rounded bars) — a focus ring for the bar.
fn strokeRoundFake(gpa: std.mem.Allocator, dl: *raster.DrawList, x: f32, y: f32, w: f32, h: f32, rgb: u32, a: f32) !void {
    try rrect(gpa, dl, x, y, w, 2, rgb, a, 0);
    try rrect(gpa, dl, x, y + h - 2, w, 2, rgb, a, 0);
    try rrect(gpa, dl, x, y, 2, h, rgb, a, 0);
    try rrect(gpa, dl, x + w - 2, y, 2, h, rgb, a, 0);
}

fn drawMasthead(gpa: std.mem.Allocator, dl: *raster.DrawList, engine: *text.Engine, r: Rect, a: f32) !void {
    _ = engine;
    if (r.h < 30) return;
    const avs: f32 = @min(72, r.h - 30);
    try circle(gpa, dl, r.x + 26, r.y + (r.h - avs) * 0.5, avs, 0xFF6E6450, a);
    const tx = r.x + 26 + avs + 22;
    try drawText(gpa, dl, "connor.zat4.com", @as(i32, @intFromFloat(tx)), @as(i32, @intFromFloat(r.y + r.h * 0.5)) - 6, 22, 1, ink, a);
    try drawText(gpa, dl, "@connor.zat4.com", @as(i32, @intFromFloat(tx)), @as(i32, @intFromFloat(r.y + r.h * 0.5)) + 18, 14, 0, muted, a);
    const hw = textWidth("@connor.zat4.com", 14);
    try circle(gpa, dl, tx + hw + 8, r.y + r.h * 0.5 + 12, 3, muted, a);
    try drawText(gpa, dl, "11 posts", @as(i32, @intFromFloat(tx + hw + 18)), @as(i32, @intFromFloat(r.y + r.h * 0.5)) + 18, 14, 0, muted, a);
}

// ---- word wrap with inline #tag / @mention colouring ----
fn drawWrapped(gpa: std.mem.Allocator, dl: *raster.DrawList, engine: *text.Engine, x: f32, y0: f32, maxw: f32, px: u16, str: []const u8, a: f32) !f32 {
    _ = engine;
    const space = textWidth(" ", px);
    var penx = x;
    var y = y0;
    const line_h: f32 = @as(f32, @floatFromInt(px)) * 1.35;
    var it = std.mem.tokenizeScalar(u8, str, ' ');
    while (it.next()) |word| {
        const ww = textWidth(word, px);
        if (penx > x and penx + ww > x + maxw) {
            penx = x;
            y += line_h;
        }
        const col = if (word.len > 0 and (word[0] == '#' or word[0] == '@')) blue else body_c;
        try drawText(gpa, dl, word, @as(i32, @intFromFloat(penx)), @as(i32, @intFromFloat(y)) + @as(i32, px) - 4, px, 0, col, a);
        penx += ww + space;
    }
    return y + line_h;
}

// ---- tiny "icons" (placeholder vector marks) ----
fn engGlyph(gpa: std.mem.Allocator, dl: *raster.DrawList, x: f32, y: f32, color: u32, a: f32) !void {
    try strokeRect(gpa, dl, x, y, 16, 13, color, a);
}
fn heartGlyph(gpa: std.mem.Allocator, dl: *raster.DrawList, x: f32, y: f32, color: u32, a: f32) !void {
    try circle(gpa, dl, x, y, 14, color, a * 0.9);
}

// ---- snapshot (software, off-display verification) ----
fn snapshot(gpa: std.mem.Allocator, io: std.Io, dir: []const u8) !void {
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    var fb: raster.Framebuffer = .{};
    defer raster.deinit(gpa, &fb);
    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    var pbuf: [256]u8 = undefined;
    const dt: f32 = 1.0 / 60.0;

    // each page settled at two window sizes (shows resize re-solve)
    const sizes = [_][2]u32{ .{ 1340, 860 }, .{ 1000, 720 } };
    inline for (.{ .{ 0, "home" }, .{ 1, "algorithm" }, .{ 2, "reading" }, .{ 3, "profile" } }) |pg| {
        for (sizes, 0..) |sz, si| {
            try raster.resize(gpa, &fb, sz[0], sz[1], bg);
            _ = arena_state.reset(.retain_capacity);
            dl.len = 0;
            try composeFrame(gpa, &dl, &engine, arena_state.allocator(), pages[pg[0]].params, sz[0], sz[1], pg[0]);
            try raster.paint(gpa, &engine, dl.slice(), &fb, bg);
            const tag = if (si == 0) "wide" else "small";
            try writePpm(io, gpa, &fb, try std.fmt.bufPrint(&pbuf, "{s}/app_{s}_{s}.ppm", .{ dir, pg[1], tag }));
        }
    }

    // morph Home -> Algorithm (feed widens, context slims, reflow)
    try raster.resize(gpa, &fb, 1340, 860, bg);
    var p: [N_PARAM]f32 = pages[0].params;
    var v: [N_PARAM]f32 = .{0} ** N_PARAM;
    var frame: u32 = 0;
    while (frame < 28) : (frame += 1) {
        for (0..N_PARAM) |i| springTo(&p[i], &v[i], pages[1].params[i], dt);
        _ = arena_state.reset(.retain_capacity);
        dl.len = 0;
        try composeFrame(gpa, &dl, &engine, arena_state.allocator(), p, 1340, 860, 1);
        try raster.paint(gpa, &engine, dl.slice(), &fb, bg);
        try writePpm(io, gpa, &fb, try std.fmt.bufPrint(&pbuf, "{s}/appflow_{d:0>2}.ppm", .{ dir, frame }));
    }
    // SEARCH → TRENDING PUSH (the cheap content-driven tile movement): render
    // Home with the search results open in PUSH mode and in OVERLAY mode.
    try raster.resize(gpa, &fb, 1340, 860, bg);
    search_t = 1.0;
    inline for (.{ .{ false, "search_push" }, .{ true, "search_overlay" } }) |mode| {
        overlay = mode[0];
        _ = arena_state.reset(.retain_capacity);
        dl.len = 0;
        try composeFrame(gpa, &dl, &engine, arena_state.allocator(), pages[0].params, 1340, 860, 0);
        try raster.paint(gpa, &engine, dl.slice(), &fb, bg);
        try writePpm(io, gpa, &fb, try std.fmt.bufPrint(&pbuf, "{s}/{s}.ppm", .{ dir, mode[1] }));
    }
    search_t = 0;
    overlay = false;
    std.debug.print("snapshot: wrote app_*_{{wide,small}}.ppm + appflow_*.ppm + search_*.ppm to {s}\n", .{dir});
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

// ---- draw primitives ----
fn rect(gpa: std.mem.Allocator, dl: *raster.DrawList, x: f32, y: f32, w: f32, h: f32, rgb: u32, a: f32) !void {
    try rrect(gpa, dl, x, y, w, h, rgb, a, 0);
}
fn rrect(gpa: std.mem.Allocator, dl: *raster.DrawList, x: f32, y: f32, w: f32, h: f32, rgb: u32, a: f32, radius: u8) !void {
    if (w < 1 or h < 1) return;
    const av: u32 = @intFromFloat(std.math.clamp(a, 0, 1) * 255);
    try dl.append(gpa, .{ .rect = .{ .x = ci16(x), .y = ci16(y), .w = cu16(w), .h = cu16(h), .color = (rgb & 0x00FFFFFF) | (av << 24), .radius = radius } });
}
fn circle(gpa: std.mem.Allocator, dl: *raster.DrawList, x: f32, y: f32, d: f32, rgb: u32, a: f32) !void {
    try rrect(gpa, dl, x, y, d, d, rgb, a, @intFromFloat(d / 2));
}
fn strokeRect(gpa: std.mem.Allocator, dl: *raster.DrawList, x: f32, y: f32, w: f32, h: f32, rgb: u32, a: f32) !void {
    const t: f32 = 1.5;
    try rrect(gpa, dl, x, y, w, t, rgb, a, 0);
    try rrect(gpa, dl, x, y + h - t, w, t, rgb, a, 0);
    try rrect(gpa, dl, x, y, t, h, rgb, a, 0);
    try rrect(gpa, dl, x + w - t, y, t, h, rgb, a, 0);
}

fn textWidth(str: []const u8, px: u16) f32 {
    return @as(f32, @floatFromInt(str.len)) * @as(f32, @floatFromInt(px)) * 0.52;
}
fn drawText(gpa: std.mem.Allocator, dl: *raster.DrawList, str: []const u8, x: i32, baseline: i32, px: u16, weight: u8, color: u32, a: f32) !void {
    const av: u32 = @intFromFloat(std.math.clamp(a, 0, 1) * 255);
    const col = (color & 0x00FFFFFF) | (av << 24);
    var pen: i32 = x;
    const adv: i32 = @intFromFloat(@as(f32, @floatFromInt(px)) * 0.52);
    for (str) |ch| {
        if (ch != ' ')
            try dl.append(gpa, .{ .text = .{ .x = ci16f(pen), .baseline = ci16f(baseline), .codepoint = ch, .color = col, .px = px, .weight = weight } });
        pen += adv;
    }
}
fn drawTextCentered(gpa: std.mem.Allocator, dl: *raster.DrawList, str: []const u8, x: f32, baseline: f32, w: f32, px: u16, weight: u8, color: u32, a: f32) !void {
    const tw = textWidth(str, px);
    try drawText(gpa, dl, str, @intFromFloat(x + (w - tw) * 0.5), @intFromFloat(baseline), px, weight, color, a);
}

fn ci16(v: f32) i16 {
    return @intFromFloat(std.math.clamp(v, -32768, 32767));
}
fn ci16f(v: i32) i16 {
    return @intCast(std.math.clamp(v, -32768, 32767));
}
fn cu16(v: f32) u16 {
    return @intFromFloat(std.math.clamp(v, 0, 65535));
}
