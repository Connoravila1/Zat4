// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Zat4 — a social-media client built on the AT Protocol.
// Copyright (C) 2026  Connor Avila

//! TILING SPIKE harness (`zig build tiling-spike`). A SANDBOX — it imports the
//! pure `core/tiling.zig` carve and the real `raster` painter, but it touches
//! NONE of the live render path (feed_view is untouched). Delete this file and
//! the build step and the spike is gone.
//!
//! It writes two kinds of proof to a directory (default the system tmp, or
//! argv[1]):
//!
//!   1. STATIC carve — each page expressed as a split tree, tiled at a WIDE
//!      and a NARROW width, so you can see the layout DERIVED from the tree
//!      and the side region COLLAPSE on the narrow width (E4). One PPM each.
//!
//!   2. FLOW flipbook — Home → Profile as a re-target + settle. The feed's
//!      content keeps identity and FLOWS from full-width into the left split
//!      pane while the widgets region is BORN on the right. This is a small
//!      LOCAL spring-mover at the draw-item level — a working stand-in for the
//!      physics extension the field would need (its content cells only wobble
//!      in place today). One PPM per frame.

const std = @import("std");
const text = @import("core/text.zig");
const raster = @import("core/raster.zig");
const tiling = @import("core/tiling.zig");

const RegionKind = tiling.RegionKind;
const Node = tiling.Node;

const W: u32 = 1280;
const W_NARROW: u32 = 560;
const H: u32 = 860;
const clear: u32 = 0xFF181812;
const seam_color: u32 = 0xFF34342B;

// ---------------------------------------------------------------------------
// The pages, as trees (this is the whole point: a page IS data).
// ---------------------------------------------------------------------------

const home_tree: Node = .{ .split = .{ .dir = .v, .children = &.{
    .{ .leaf = .{ .kind = .masthead, .weight = 0, .min = 128 } },
    .{ .leaf = .{ .kind = .feed, .weight = 1, .min = 320 } },
} } };

const profile_tree: Node = .{ .split = .{ .dir = .v, .children = &.{
    .{ .leaf = .{ .kind = .profile_id, .weight = 0, .min = 150 } },
    .{ .split = .{ .dir = .h, .children = &.{
        .{ .leaf = .{ .kind = .profile_feed, .weight = 2, .min = 340 } },
        .{ .leaf = .{ .kind = .widgets, .weight = 1, .min = 260 } },
    } } },
} } };

const zones_tree: Node = .{ .split = .{ .dir = .v, .children = &.{
    .{ .leaf = .{ .kind = .zone_masthead, .weight = 0, .min = 210 } },
    .{ .split = .{ .dir = .h, .children = &.{
        .{ .leaf = .{ .kind = .zone_feed, .weight = 2, .min = 340 } },
        .{ .leaf = .{ .kind = .widgets, .weight = 1, .min = 240 } },
    } } },
} } };

const messages_tree: Node = .{ .split = .{ .dir = .h, .children = &.{
    .{ .leaf = .{ .kind = .conv_list, .weight = 1, .min = 240 } },
    .{ .leaf = .{ .kind = .thread, .weight = 2, .min = 360 } },
} } };

const cfg: tiling.Config = .{ .seam = 6 };

// ---------------------------------------------------------------------------
// Content "streams" — a logical content surface, mapped into whatever rect a
// layout gives it. Two regions with the SAME stream are the same content, so
// they keep identity across a navigation and FLOW. Several kinds share one
// stream (Home.feed and Profile.profile_feed are both stream 0).
// ---------------------------------------------------------------------------

const Stream = struct {
    // A7.2: cold struct — a constant config-table row (one per stream kind),
    // read at setup, never in a hot loop. Size guard waived by rule.
    nc: u16,
    nr: u16,
    base: u32,
    label: []const u8,
};

fn streamId(kind: RegionKind) u8 {
    return switch (kind) {
        .feed, .profile_feed, .zone_feed => 0, // the main content surface
        .masthead, .profile_id, .zone_masthead => 1, // the header band
        .widgets => 2,
        .conv_list => 3,
        .thread => 4,
        .activity => 5,
        .settings => 6,
        .composer => 7,
    };
}

const streams = [_]Stream{
    .{ .nc = 5, .nr = 16, .base = 0xFFB9C4D2, .label = "feed" },
    .{ .nc = 8, .nr = 2, .base = 0xFFD8B27A, .label = "header" },
    .{ .nc = 3, .nr = 10, .base = 0xFF9FC7A0, .label = "widgets" },
    .{ .nc = 3, .nr = 14, .base = 0xFFC9A7CE, .label = "messages" },
    .{ .nc = 4, .nr = 16, .base = 0xFFB9C4D2, .label = "thread" },
    .{ .nc = 4, .nr = 12, .base = 0xFFCAB78A, .label = "activity" },
    .{ .nc = 3, .nr = 12, .base = 0xFFA9B6D6, .label = "settings" },
    .{ .nc = 4, .nr = 6, .base = 0xFFCAA3A8, .label = "composer" },
};

const ramp = ".:;+=*o%#";

fn glyphFor(sid: u8, i: u16, j: u16) u8 {
    const h: usize = (@as(usize, i) * 7 + @as(usize, j) * 13 + @as(usize, sid) * 5) % ramp.len;
    return ramp[h];
}

// ---------------------------------------------------------------------------
pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;

    const argv = try init.minimal.args.toSlice(gpa);
    defer gpa.free(argv);
    const out_dir: []const u8 = if (argv.len > 1) argv[1] else "/tmp";

    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);

    var fb: raster.Framebuffer = .{};
    try raster.resize(gpa, &fb, W, H, clear);
    defer raster.deinit(gpa, &fb);

    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    // ---- 1. STATIC carve proofs: each page, wide and narrow ----
    const Page = struct { name: []const u8, tree: *const Node };
    const pages = [_]Page{
        .{ .name = "home", .tree = &home_tree },
        .{ .name = "profile", .tree = &profile_tree },
        .{ .name = "zones", .tree = &zones_tree },
        .{ .name = "messages", .tree = &messages_tree },
    };

    var path_buf: [256]u8 = undefined;
    for (pages) |pg| {
        inline for (.{ .{ W, "wide" }, .{ W_NARROW, "narrow" } }) |variant| {
            const wpx: u32 = variant[0];
            const tag: []const u8 = variant[1];
            _ = arena_state.reset(.retain_capacity);
            const arena = arena_state.allocator();

            try raster.resize(gpa, &fb, wpx, H, clear);
            dl.len = 0;
            const carve = try tiling.tile(arena, pg.tree, @intCast(wpx), @intCast(H), cfg);
            try drawStatic(gpa, &dl, carve, &engine, arena);
            try raster.paint(gpa, &engine, dl.slice(), &fb, clear);

            const path = try std.fmt.bufPrint(&path_buf, "{s}/tile_{s}_{s}.ppm", .{ out_dir, pg.name, tag });
            try writePpm(io, gpa, &fb, path);
            std.debug.print("wrote {s}  ({d}x{d}, {d} regions, {d} items)\n", .{ path, wpx, H, carve.viewports.len, dl.len });
        }
    }

    // ---- 2. FLOW flipbook: Home -> Profile, re-target and settle ----
    try raster.resize(gpa, &fb, W, H, clear);
    _ = arena_state.reset(.retain_capacity);
    const farena = arena_state.allocator();
    const src = try tiling.tile(farena, &home_tree, @intCast(W), @intCast(H), cfg);
    const dst = try tiling.tile(farena, &profile_tree, @intCast(W), @intCast(H), cfg);

    const toks = try buildFlow(farena, src, dst);
    const frames: u32 = 30;
    const fade_frames: f32 = 12.0;
    const dt: f32 = 1.0 / 60.0;
    const k: f32 = 70.0; // mirror field spring_k
    const c: f32 = 11.0; // mirror field spring_c

    var frame: u32 = 0;
    while (frame < frames) : (frame += 1) {
        dl.len = 0;
        const ez = smooth(@as(f32, @floatFromInt(frame)) / @as(f32, @floatFromInt(frames - 1)));

        // Faint backing panes (lerp the rect; born/dead fade).
        try drawFlowBacks(gpa, &dl, src, dst, ez);

        // Tokens settle under the spring.
        for (toks) |*t| {
            if (!t.born and !t.dead) {
                t.vx += (-k * (t.x - t.tx) - c * t.vx) * dt;
                t.vy += (-k * (t.y - t.ty) - c * t.vy) * dt;
                t.x += t.vx * dt;
                t.y += t.vy * dt;
            }
            const alpha: f32 = if (t.born)
                std.math.clamp(@as(f32, @floatFromInt(frame)) / fade_frames, 0, 1)
            else if (t.dead)
                1.0 - std.math.clamp(@as(f32, @floatFromInt(frame)) / fade_frames, 0, 1)
            else
                1.0;
            if (alpha <= 0.02) continue;
            const col = lerpColor(clear, t.base, alpha);
            try dl.append(gpa, .{ .text = .{
                .x = clampI16(t.x),
                .baseline = clampI16(t.y),
                .codepoint = t.glyph,
                .color = col,
                .px = 18,
                .weight = 0,
            } });
        }

        // Destination seams fade in.
        const sc = lerpColor(clear, seam_color, ez);
        for (dst.seams) |s| try drawSeam(gpa, &dl, s, sc);

        try raster.paint(gpa, &engine, dl.slice(), &fb, clear);
        const path = try std.fmt.bufPrint(&path_buf, "{s}/flow_{d:0>2}.ppm", .{ out_dir, frame });
        try writePpm(io, gpa, &fb, path);
    }
    std.debug.print("wrote {d} flow frames flow_00..flow_{d:0>2}.ppm to {s}\n", .{ frames, frames - 1, out_dir });
}

// ---------------------------------------------------------------------------
// Static rendering of one carve.
// ---------------------------------------------------------------------------

fn drawStatic(
    gpa: std.mem.Allocator,
    dl: *raster.DrawList,
    carve: tiling.Carve,
    engine: *text.Engine,
    arena: std.mem.Allocator,
) !void {
    _ = engine;
    _ = arena;
    for (carve.viewports) |v| {
        const sid = streamId(v.kind);
        const st = streams[sid];
        // Faint backing pane.
        try dl.append(gpa, .{ .rect = .{
            .x = @intCast(v.x),
            .y = @intCast(v.y),
            .w = v.w,
            .h = v.h,
            .color = (st.base & 0x00FFFFFF) | 0x14000000,
            .radius = 10,
        } });
        // Content tokens.
        var j: u16 = 0;
        while (j < st.nr) : (j += 1) {
            var i: u16 = 0;
            while (i < st.nc) : (i += 1) {
                const x = @as(f32, @floatFromInt(v.x)) + (@as(f32, @floatFromInt(i)) + 0.5) / @as(f32, @floatFromInt(st.nc)) * @as(f32, @floatFromInt(v.w));
                const y = @as(f32, @floatFromInt(v.y)) + 34 + (@as(f32, @floatFromInt(j)) + 0.5) / @as(f32, @floatFromInt(st.nr)) * (@as(f32, @floatFromInt(v.h)) - 34);
                try dl.append(gpa, .{ .text = .{
                    .x = clampI16(x),
                    .baseline = clampI16(y),
                    .codepoint = glyphFor(sid, i, j),
                    .color = lerpColor(clear, st.base, 0.85),
                    .px = 18,
                    .weight = 0,
                } });
            }
        }
        // Bold label.
        try drawText(gpa, dl, st.label, @as(i32, v.x) + 14, @as(i32, v.y) + 26, 22, 0xFFEDE6D6);
        try drawText(gpa, dl, @tagName(v.kind), @as(i32, v.x) + 14, @as(i32, v.y) + 50, 13, 0xFF8C8C82);
    }
    // Seams over the top.
    for (carve.seams) |s| try drawSeam(gpa, dl, s, seam_color);
}

// ---------------------------------------------------------------------------
// Flow: build the moving token set from a source and dest carve.
// ---------------------------------------------------------------------------

const Tok = struct {
    x: f32,
    y: f32,
    vx: f32 = 0,
    vy: f32 = 0,
    tx: f32,
    ty: f32,
    base: u32,
    glyph: u8,
    born: bool,
    dead: bool,

    comptime {
        // 6×f32 (24) + u32 (4) = 28, then u8 + 2×bool (3) → padded to 32. The
        // hot struct here (one per content token, settled each frame). EXACT.
        std.debug.assert(@sizeOf(Tok) == 32);
    }
};

const Rect = struct {
    // A7.2: cold struct — a transient per-stream aggregate held in a fixed
    // streams.len array, never a bulk collection. Size guard waived.
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    present: bool = false,
};

fn streamRects(carve: tiling.Carve) [streams.len]Rect {
    var out: [streams.len]Rect = undefined;
    for (&out) |*r| r.* = .{ .x = 0, .y = 0, .w = 0, .h = 0, .present = false };
    for (carve.viewports) |v| {
        out[streamId(v.kind)] = .{
            .x = @floatFromInt(v.x),
            .y = @floatFromInt(v.y),
            .w = @floatFromInt(v.w),
            .h = @floatFromInt(v.h),
            .present = true,
        };
    }
    return out;
}

fn cellPos(r: Rect, st: Stream, i: u16, j: u16) struct { x: f32, y: f32 } {
    const x = r.x + (@as(f32, @floatFromInt(i)) + 0.5) / @as(f32, @floatFromInt(st.nc)) * r.w;
    const y = r.y + 34 + (@as(f32, @floatFromInt(j)) + 0.5) / @as(f32, @floatFromInt(st.nr)) * (r.h - 34);
    return .{ .x = x, .y = y };
}

fn buildFlow(arena: std.mem.Allocator, src: tiling.Carve, dst: tiling.Carve) ![]Tok {
    const sr = streamRects(src);
    const dr = streamRects(dst);
    var list: std.ArrayListUnmanaged(Tok) = .empty;
    for (streams, 0..) |st, sid| {
        const s = sr[sid];
        const d = dr[sid];
        if (!s.present and !d.present) continue;
        var j: u16 = 0;
        while (j < st.nr) : (j += 1) {
            var i: u16 = 0;
            while (i < st.nc) : (i += 1) {
                const g = glyphFor(@intCast(sid), i, j);
                const col = lerpColor(clear, st.base, 0.9);
                if (s.present and d.present) {
                    const a = cellPos(s, st, i, j);
                    const b = cellPos(d, st, i, j);
                    try list.append(arena, .{ .x = a.x, .y = a.y, .tx = b.x, .ty = b.y, .glyph = g, .base = col, .born = false, .dead = false });
                } else if (d.present) {
                    const b = cellPos(d, st, i, j);
                    try list.append(arena, .{ .x = b.x, .y = b.y, .tx = b.x, .ty = b.y, .glyph = g, .base = col, .born = true, .dead = false });
                } else {
                    const a = cellPos(s, st, i, j);
                    try list.append(arena, .{ .x = a.x, .y = a.y, .tx = a.x, .ty = a.y, .glyph = g, .base = col, .born = false, .dead = true });
                }
            }
        }
    }
    return list.items;
}

fn drawFlowBacks(gpa: std.mem.Allocator, dl: *raster.DrawList, src: tiling.Carve, dst: tiling.Carve, ez: f32) !void {
    const sr = streamRects(src);
    const dr = streamRects(dst);
    for (streams, 0..) |st, sid| {
        const s = sr[sid];
        const d = dr[sid];
        var r: Rect = undefined;
        var a: f32 = undefined;
        if (s.present and d.present) {
            r = .{ .x = lerp(s.x, d.x, ez), .y = lerp(s.y, d.y, ez), .w = lerp(s.w, d.w, ez), .h = lerp(s.h, d.h, ez) };
            a = 1.0;
        } else if (d.present) {
            r = d;
            a = ez;
        } else if (s.present) {
            r = s;
            a = 1.0 - ez;
        } else continue;
        const av: u32 = @intFromFloat(@max(0, @min(0x16, a * 0x16)));
        try dl.append(gpa, .{ .rect = .{
            .x = clampI16(r.x),
            .y = clampI16(r.y),
            .w = @intFromFloat(@max(0, r.w)),
            .h = @intFromFloat(@max(0, r.h)),
            .color = (st.base & 0x00FFFFFF) | (av << 24),
            .radius = 10,
        } });
    }
}

// ---------------------------------------------------------------------------
// Small drawing + math helpers.
// ---------------------------------------------------------------------------

fn drawSeam(gpa: std.mem.Allocator, dl: *raster.DrawList, s: tiling.Seam, color: u32) !void {
    if (s.dir == .v) {
        try dl.append(gpa, .{ .rect = .{ .x = @intCast(s.x), .y = clampI16(@as(f32, @floatFromInt(s.y)) - @as(f32, @floatFromInt(cfg.seam))), .w = s.len, .h = cfg.seam, .color = color, .radius = 0 } });
    } else {
        try dl.append(gpa, .{ .rect = .{ .x = clampI16(@as(f32, @floatFromInt(s.x)) - @as(f32, @floatFromInt(cfg.seam))), .y = @intCast(s.y), .w = cfg.seam, .h = s.len, .color = color, .radius = 0 } });
    }
}

fn drawText(gpa: std.mem.Allocator, dl: *raster.DrawList, str: []const u8, x: i32, baseline: i32, px: u16, color: u32) !void {
    var pen: i32 = x;
    const adv: i32 = @divTrunc(@as(i32, @intCast(px)) * 56, 100); // rough monospace advance
    for (str) |ch| {
        try dl.append(gpa, .{ .text = .{
            .x = clampI16(@floatFromInt(pen)),
            .baseline = clampI16(@floatFromInt(baseline)),
            .codepoint = ch,
            .color = color,
            .px = px,
            .weight = 1,
        } });
        pen += adv;
    }
}

fn clampI16(v: f32) i16 {
    return @intFromFloat(std.math.clamp(v, -32768, 32767));
}

fn lerp(a: f32, b: f32, t: f32) f32 {
    return a + (b - a) * t;
}

fn smooth(t: f32) f32 {
    const x = std.math.clamp(t, 0, 1);
    return x * x * (3.0 - 2.0 * x);
}

fn lerpColor(a: u32, b: u32, t: f32) u32 {
    const tt = std.math.clamp(t, 0, 1);
    const ar: f32 = @floatFromInt((a >> 16) & 0xFF);
    const ag: f32 = @floatFromInt((a >> 8) & 0xFF);
    const ab: f32 = @floatFromInt(a & 0xFF);
    const br: f32 = @floatFromInt((b >> 16) & 0xFF);
    const bg: f32 = @floatFromInt((b >> 8) & 0xFF);
    const bb: f32 = @floatFromInt(b & 0xFF);
    const r: u32 = @intFromFloat(lerp(ar, br, tt));
    const g: u32 = @intFromFloat(lerp(ag, bg, tt));
    const bl: u32 = @intFromFloat(lerp(ab, bb, tt));
    return 0xFF000000 | (r << 16) | (g << 8) | bl;
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
