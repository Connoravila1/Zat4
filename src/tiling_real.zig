// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Zat4 — a social-media client built on the AT Protocol.
// Copyright (C) 2026  Connor Avila

//! B1 classification: SHELL. TILING-REAL (`zig build tiling-real`).
//!
//! Runs the REAL feed (`feed_view.layout` — real icons, typography, socket,
//! sidebar, over the living glyph field) but with its pane geometry SOLVED BY
//! THE PARTITION (`core/tiling.zig`) and handed in through the new `geom` seam.
//! So this is the actual app rendering on the tiling foundation, interactive:
//!
//!   space / click → morph the feed wider (sidebar slides out) and back
//!   resize / maximize → the layout RE-SOLVES live (the high-quality resize)
//!   esc / close → quit
//!
//! Isolated from the live run loop (tui.zig) — a harness, like gpu-preview.

const std = @import("std");
const window_shell = @import("shell/native.zig");
const gpu = @import("shell/gpu.zig");
const layout_core = @import("core/layout.zig");
const text = @import("core/text.zig");
const raster = @import("core/raster.zig");
const feed_view = @import("core/feed_view.zig");
const feed = @import("core/feed.zig");
const tiling = @import("core/tiling.zig");
const lens_socket = @import("core/lens_socket.zig");
const lens_catalog = @import("core/lens_catalog.zig");
const glyph_field = @import("core/glyph_field.zig");
const clock_shell = @import("shell/clock.zig");

const cell_w: u16 = 13;
const cell_h: u16 = 17;
const design_w: u32 = 1340;
fn uiScale(physical_w: u32) f32 {
    return @as(f32, @floatFromInt(physical_w)) / @as(f32, @floatFromInt(design_w));
}
fn logicalH(pw: u32, ph: u32) u32 {
    return @max(1, @as(u32, @intFromFloat(@as(f32, @floatFromInt(ph)) / uiScale(pw))));
}
const clear_r: f32 = @as(f32, 0x18) / 255.0;
const clear_g: f32 = @as(f32, 0x18) / 255.0;
const clear_b: f32 = @as(f32, 0x12) / 255.0;

// Fixed pane widths the real rail/sidebar are authored at (logical px).
const rail_w: f32 = 248;
const side_w_full: f32 = 352;
const spring_k: f32 = 130.0;
const spring_c: f32 = 24.0;

/// Solve nav(248) | feed(weight) | sidebar(side_w) as a partition at the logical
/// size, and map the placed rects to feed_view's PaneGeom (the S.1 seam).
fn partitionGeom(arena: std.mem.Allocator, lw: i32, lh: i32, side_w: f32) !feed_view.PaneGeom {
    const tree: tiling.Node = .{ .split = .{ .dir = .h, .children = &.{
        .{ .leaf = .{ .kind = .nav, .weight = 0, .min = @intFromFloat(rail_w) } },
        .{ .leaf = .{ .kind = .feed, .weight = 100, .min = 0 } },
        .{ .leaf = .{ .kind = .widgets, .weight = 0, .min = @intFromFloat(@max(0.0, side_w)) } },
    } } };
    const carve = try tiling.tile(arena, &tree, @intCast(lw), @intCast(lh), .{ .seam = 0 });
    var rx: i32 = 0;
    var cx: i32 = 0;
    var cwd: i32 = 0;
    var sx: i32 = 0;
    for (carve.viewports) |vp| switch (vp.kind) {
        .nav => rx = vp.x,
        .feed => {
            cx = vp.x;
            cwd = vp.w;
        },
        .widgets => sx = vp.x,
        else => {},
    };
    return .{ .rail_x = rx, .col_x = cx, .col_w = cwd, .lx = cx + 22, .cw = cwd - 44, .side_x = sx, .wide = true };
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const env = init.environ_map;

    const win = window_shell.open(gpa, env, "zat - tiling-real", 160, 55) catch |err| {
        std.debug.print("window.open failed: {s} (on X11, is DISPLAY set?)\n", .{@errorName(err)});
        return;
    };
    defer window_shell.close(win);
    var W: u32 = win.fb.width;
    var H: u32 = win.fb.height;

    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);

    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);
    // Persistent arena (posts + tray) — NEVER reset. Separate from the per-frame
    // arena below, or resetting it each frame would free this data (UAF).
    var persist_state = std.heap.ArenaAllocator.init(gpa);
    defer persist_state.deinit();
    const persist = persist_state.allocator();
    // Per-frame arena: only the partition solve. Reset wholesale each loop.
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    // Real posts (the same sample the previews use).
    const now: i64 = 1_000_000;
    var items = [_]feed.TimelineItem{
        mk("mara.zat", "Mara Vesper", "the whole point of a #smallweb is that you can actually read the room. ten thousand strangers isn't a room, it's weather.", now - 120, 48, 9, 6, true, false),
        mk("fieldnotes.zat", "field notes", "shipped the lighting pass tonight. the letters catch the light now, and the whole field moves when you touch it.", now - 840, 121, 31, 12, false, true),
        mk("oko.zat", "Okonkwo", "#monospace is the most honest a feed can be. same column, same weight, nobody shouts louder by being wider.", now - 3600, 73, 18, 24, false, false),
        mk("lune.zat", "lune", "woke up to the field still drifting where i left it. it kept the light on.", now - 10800, 39, 7, 3, false, false),
    };
    items[1].replying_to_handle = "mara.zat";
    items[0].tags = &.{ "smallweb", "community" };
    items[2].tags = &.{ "monospace", "design", "typography" };
    const posts = try feed_view.fromTimeline(persist, &items, now);
    const hc, const hb = try lens_catalog.defaultFeedLoadout(persist);
    const home_tray: lens_socket.TrayView = .{ .cards = hc, .text = hb, .seated = lens_catalog.default_feed_seated };

    // GPU bring-up (real app path).
    var g = gpu.init(win.wid) catch {
        std.debug.print("GPU init failed — see [gpu] lines above.\n", .{});
        return;
    };
    defer gpu.deinit(&g);
    gpu.setViewport(@intCast(W), @intCast(H));
    var feed_path = gpu.initFeed(gpa) catch return;
    defer gpu.feedDeinit(&feed_path, gpa);
    var field_renderer = gpu.initFieldRenderer(gpa, &engine, cell_w, cell_h) catch return;
    var field_grid = gpu.initFieldGrid() catch return;

    var gcols: u32 = @max(8, W / cell_w);
    var grows: u32 = @max(8, H / cell_h);
    var field: glyph_field.Field = undefined;
    try glyph_field.init(gpa, &field, gcols, grows);
    defer glyph_field.deinit(gpa, &field);
    var bias: []f32 = try gpa.alloc(f32, gcols * grows);
    defer gpa.free(bias);
    const fparams: glyph_field.Params = .{};

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var events: std.ArrayList(layout_core.InputEvent) = .empty;
    defer events.deinit(gpa);

    // The ONE animated partition parameter: the sidebar width (352 ↔ 0).
    var side_w: f32 = side_w_full;
    var side_v: f32 = 0;
    var want_sidebar = true;

    var t: f32 = 0;
    var last_step_ns: u64 = 0;
    const amb_amp: f32 = 0.010;
    const amb_scale: f32 = 0.060;
    const amb_drift: f32 = 0.10;
    const dt: f32 = 1.0 / 60.0;

    while (true) {
        const pr = window_shell.pump(win, 16, gpa, &out, &events) catch break;
        if (pr.closed) break;

        if (win.fb.width != W or win.fb.height != H) {
            W = win.fb.width;
            H = win.fb.height;
            gpu.setViewport(@intCast(W), @intCast(H));
            gcols = @max(8, W / cell_w);
            grows = @max(8, H / cell_h);
            var nf: glyph_field.Field = undefined;
            glyph_field.init(gpa, &nf, gcols, grows) catch break;
            glyph_field.deinit(gpa, &field);
            field = nf;
            const nb = gpa.alloc(f32, gcols * grows) catch break;
            gpa.free(bias);
            bias = nb;
        }

        // input → toggle the morph
        for (out.items) |b| {
            if (b == 27) return; // esc
            want_sidebar = !want_sidebar;
        }
        out.clearRetainingCapacity();
        for (events.items) |ev| {
            if (ev.kind == .button_down) want_sidebar = !want_sidebar;
        }
        events.clearRetainingCapacity();

        // physics on the partition parameter
        const target: f32 = if (want_sidebar) side_w_full else 0;
        side_v += (-spring_k * (side_w - target) - spring_c * side_v) * dt;
        side_w += side_v * dt;

        // advance the field (fixed timestep)
        const dt_ns: u64 = 16_666_667;
        const now_ns = clock_shell.monotonicNanos();
        if (last_step_ns == 0 or (now_ns -| last_step_ns) >= dt_ns) {
            var yy: u32 = 0;
            while (yy < grows) : (yy += 1) {
                const fy: f32 = @floatFromInt(yy);
                var xx: u32 = 0;
                while (xx < gcols) : (xx += 1) {
                    const fx: f32 = @floatFromInt(xx);
                    const base = std.math.sin(fx * amb_scale + t * amb_drift) * std.math.sin(fy * amb_scale * 1.3 - t * amb_drift * 0.8);
                    const fine = std.math.sin(fx * 0.21 - t * 0.07) * std.math.sin(fy * 0.18 + t * 0.06);
                    bias[yy * gcols + xx] = amb_amp * (base + 0.5 * fine);
                }
            }
            glyph_field.step(&field, fparams, &.{}, bias);
            t += 1.0 / 60.0;
            last_step_ns = if (last_step_ns == 0 or (now_ns -| last_step_ns) > dt_ns * 4) now_ns else last_step_ns + dt_ns;
        }

        // SOLVE the layout as a partition, render the REAL feed into it.
        _ = arena_state.reset(.retain_capacity);
        const arena = arena_state.allocator();
        const lh = logicalH(W, H);
        const geom = partitionGeom(arena, @intCast(design_w), @intCast(lh), side_w) catch continue;
        dl.len = 0;
        _ = feed_view.layout(gpa, &engine, @intCast(design_w), @intCast(lh), posts, 0, &dl, null, null, false, 0, null, 3, lens_socket.seatedAccent(home_tray), home_tray, .{}, null, null, null, "", &.{}, geom, 0, 0, .{}) catch {};
        gpu.feedBuild(&feed_path, gpa, &engine, dl.slice(), uiScale(W)) catch {};

        gpu.uploadField(&field_grid, field.height, field.dye, field.cols, field.rows);
        gpu.clear(clear_r, clear_g, clear_b);
        gpu.drawFieldGrid(&field_grid, &field_renderer, -1, -1, t, @intCast(W), @intCast(H), 0, 0);
        gpu.feedDraw(&feed_path, @intCast(W), @intCast(H));
        gpu.swap(&g);
    }
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
