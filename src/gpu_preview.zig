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

//! B1 classification: SHELL. GPU preview (`zig build gpu-preview`).
//!
//! Drives the real render path on a window: the premium feed (GPU draw list,
//! DPI-scaled) over the living glyph field. The field is the PURE CPU
//! simulation (core/glyph_field.zig) — a neighbor-coupled wave medium — stepped
//! here each frame with shell-side ambient forcing + mouse splashes, its height
//! uploaded to a texture and rendered grid-intensity (the mockup look) by
//! shell/gpu.zig. This is the harness for tuning the field + feed.

const std = @import("std");
const window_shell = @import("shell/native.zig");
const gpu = @import("shell/gpu.zig");
const layout_core = @import("core/layout.zig"); // InputEvent type for pump
const text = @import("core/text.zig");
const raster = @import("core/raster.zig");
const atlas_mod = @import("core/atlas.zig");
const feed_view = @import("core/feed_view.zig");
const feed = @import("core/feed.zig");
const glyph_field = @import("core/glyph_field.zig");
const clock_shell = @import("shell/clock.zig");

// Field glyph cell: big enough to read the actual symbols, still many of them.
const cell_w: u16 = 13;
const cell_h: u16 = 17;

// Responsive UI scale: the feed is authored for a fixed LOGICAL width and
// scaled to FILL the window — so the three-pane keeps its cohesion at ANY
// window size (shrink → it scales down together, no pane is cut off; maximize
// → it scales up, big and crisp). scale = window_width / design_width.
const design_w: u32 = 1340;
fn uiScale(physical_w: u32) f32 {
    return @as(f32, @floatFromInt(physical_w)) / @as(f32, @floatFromInt(design_w));
}
fn logicalH(physical_w: u32, physical_h: u32) u32 {
    return @max(1, @as(u32, @intFromFloat(@as(f32, @floatFromInt(physical_h)) / uiScale(physical_w))));
}
// 0xFF181812 — the same clear colour the software path uses.
const clear_r: f32 = @as(f32, 0x18) / 255.0;
const clear_g: f32 = @as(f32, 0x18) / 255.0;
const clear_b: f32 = @as(f32, 0x12) / 255.0;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const env = init.environ_map;

    // ~1280×880 at 8×16 cells, matching the software preview's canvas.
    const win = window_shell.open(gpa, env, "zat-gpu-preview", 160, 55) catch |err| {
        std.debug.print("window.open failed: {s} (on X11, is DISPLAY set?)\n", .{@errorName(err)});
        return;
    };
    defer window_shell.close(win);
    const W: u32 = win.fb.width;
    const H: u32 = win.fb.height;
    std.debug.print("window opened: wid=0x{x} fb={d}x{d}\n", .{ win.wid, W, H });

    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);

    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The field is no longer in the draw list — it is the GPU field shader
    // (a full-screen animated pass drawn behind the feed each frame, below).
    // The draw list holds ONLY the feed content now.

    // The real feed transform → layout, same items as the software preview.
    const now: i64 = 1_000_000;
    const items = [_]feed.TimelineItem{
        mk("mara.zat", "Mara Vesper", "the whole point of a small network is that you can actually read the room. ten thousand strangers isn't a room, it's weather.", now - 120, 48, 9, 6, true, false),
        mk("fieldnotes.zat", "field notes", "shipped the lighting pass tonight. the letters catch the light now, and the whole field moves when you touch it.", now - 840, 121, 31, 12, false, true),
        mk("oko.zat", "Okonkwo", "monospace is the most honest a feed can be. same column, same weight, nobody shouts louder by being wider.", now - 3600, 73, 18, 24, false, false),
        mk("lune.zat", "lune", "woke up to the field still drifting where i left it. it kept the light on.", now - 10800, 39, 7, 3, false, false),
    };
    const posts = try feed_view.fromTimeline(arena, &items, now);
    // Lay the feed out at the fixed logical design width and a proportional
    // logical height; buildVertices scales it to fill the window, crisp.
    _ = try feed_view.layout(gpa, &engine, @intCast(design_w), @intCast(logicalH(W, H)), posts, 0, &dl, null, null, false, 0, null, 0, feed_view.accent_house, null, .{}, null, null, null, "", &.{}, null);

    // Bring up GL and the renderer.
    var g = gpu.init(win.wid) catch {
        std.debug.print("GPU init failed — see [gpu] lines above for the exact step.\n", .{});
        return;
    };
    defer gpu.deinit(&g);
    gpu.setViewport(@intCast(W), @intCast(H));

    var feed_path = gpu.initFeed(gpa) catch {
        std.debug.print("renderer init failed — see [gpu] lines above.\n", .{});
        return;
    };
    defer gpu.feedDeinit(&feed_path, gpa);
    var field_renderer = gpu.initFieldRenderer(gpa, &engine, cell_w, cell_h) catch {
        std.debug.print("field renderer init failed — see [gpu] lines above.\n", .{});
        return;
    };
    var field_grid = gpu.initFieldGrid() catch {
        std.debug.print("field-grid init failed — see [gpu] lines above.\n", .{});
        return;
    };

    // The PURE CPU simulation (core/glyph_field.zig): one cell per glyph. The
    // shell owns the buffers + the time-driven ambient-bias forcing; the pure
    // core steps the medium.
    var gcols: u32 = @max(8, W / cell_w);
    var grows: u32 = @max(8, H / cell_h);
    var field: glyph_field.Field = undefined;
    try glyph_field.init(gpa, &field, gcols, grows);
    defer glyph_field.deinit(gpa, &field);
    var bias: []f32 = try gpa.alloc(f32, gcols * grows);
    defer gpa.free(bias);
    var splashes: std.ArrayList(glyph_field.Splash) = .empty;
    defer splashes.deinit(gpa);
    const fparams: glyph_field.Params = .{};

    // Build the feed vertices once (the scene is static) via the Feed facade,
    // which packs the atlas + uploads it.
    gpu.feedBuild(&feed_path, gpa, &engine, dl.slice(), uiScale(W)) catch |err| {
        std.debug.print("feedBuild failed: {s}\n", .{@errorName(err)});
        return;
    };
    std.debug.print("[gpu] scene: {d} draw items -> {d} vertices ({d} quads)\n", .{ dl.len, feed_path.verts.items.len, feed_path.verts.items.len / 6 });
    gpu.glError("after feedBuild");

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var events: std.ArrayList(layout_core.InputEvent) = .empty;
    defer events.deinit(gpa);

    var cur_w: u32 = W;
    var cur_h: u32 = H;
    var frames: u32 = 0;
    var t: f32 = 0;
    var last_step_ns: u64 = 0; // monotonic clock of the last sim step (fixed timestep)
    var mcx: f32 = -1; // cursor cell (top-down) for the cursor-light hover; <0 = none
    var mcy: f32 = -1;
    // ambient-bias forcing (§4.3): a slow drifting two-sine swell so the still
    // field breathes. amp/scale/drift are the "alive at rest" tuning knobs.
    const amb_amp: f32 = 0.010;
    const amb_scale: f32 = 0.060;
    const amb_drift: f32 = 0.10;
    while (true) {
        const pr = window_shell.pump(win, 16, gpa, &out, &events) catch break;
        if (pr.closed) break;
        // Resize / maximize: refit the viewport, the sim grid (one node per
        // cell), and the feed layout to the live window size.
        if (win.fb.width != cur_w or win.fb.height != cur_h) {
            cur_w = win.fb.width;
            cur_h = win.fb.height;
            gpu.setViewport(@intCast(cur_w), @intCast(cur_h));
            // refit the CPU field grid + bias buffer (alloc new BEFORE freeing
            // old, so a failed alloc leaves the deferred frees valid).
            gcols = @max(8, cur_w / @as(u32, cell_w));
            grows = @max(8, cur_h / @as(u32, cell_h));
            var newfield: glyph_field.Field = undefined;
            glyph_field.init(gpa, &newfield, gcols, grows) catch break;
            glyph_field.deinit(gpa, &field);
            field = newfield;
            const new_bias = gpa.alloc(f32, gcols * grows) catch break;
            gpa.free(bias);
            bias = new_bias;
            dl.len = 0;
            _ = feed_view.layout(gpa, &engine, @intCast(design_w), @intCast(logicalH(cur_w, cur_h)), posts, 0, &dl, null, null, false, 0, null, 0, feed_view.accent_house, null, .{}, null, null, null, "", &.{}, null) catch break;
            gpu.feedBuild(&feed_path, gpa, &engine, dl.slice(), uiScale(cur_w)) catch break;
        }

        // Mouse → splashes: energy injected into the medium (a drag leaves a
        // wake that propagates and reflects). Cell coords are top-down, which
        // is how the render samples the field.
        for (events.items) |ev| {
            if (ev.kind == .move or ev.kind == .button_down) {
                const cxf = @as(f32, @floatFromInt(ev.x)) / @as(f32, @floatFromInt(cell_w));
                const cyf = @as(f32, @floatFromInt(ev.y)) / @as(f32, @floatFromInt(cell_h));
                mcx = cxf; // the cursor light follows here
                mcy = cyf;
                const sx: u32 = @intFromFloat(std.math.clamp(cxf, 0.0, @as(f32, @floatFromInt(gcols - 1))));
                const sy: u32 = @intFromFloat(std.math.clamp(cyf, 0.0, @as(f32, @floatFromInt(grows - 1))));
                if (ev.kind == .button_down) {
                    // LIKE burst (a splash RECIPE): a strong central kick plus a
                    // ring of satellite impulses, so it radiates in several
                    // directions — a real burst, not one soft ring. All stain red.
                    // (In the app this fires on the post's heart.)
                    splashes.append(gpa, .{ .x = sx, .y = sy, .radius = 4, .amp = 2.0, .dye = 1.0 }) catch {};
                    var k: u32 = 0;
                    while (k < 6) : (k += 1) {
                        const ang = @as(f32, @floatFromInt(k)) * (6.2831853 / 6.0);
                        const ox: i32 = @intFromFloat(@cos(ang) * 5.0);
                        const oy: i32 = @intFromFloat(@sin(ang) * 5.0);
                        const rx = std.math.clamp(@as(i32, @intCast(sx)) + ox, 0, @as(i32, @intCast(gcols - 1)));
                        const ry = std.math.clamp(@as(i32, @intCast(sy)) + oy, 0, @as(i32, @intCast(grows - 1)));
                        splashes.append(gpa, .{ .x = @intCast(rx), .y = @intCast(ry), .radius = 3, .amp = 1.0, .dye = 0.85 }) catch {};
                    }
                } else {
                    // hover wake: a gentle, colourless ripple.
                    splashes.append(gpa, .{ .x = sx, .y = sy, .radius = 3, .amp = 0.4 }) catch {};
                }
            }
        }
        events.clearRetainingCapacity();

        // Advance the medium on a FIXED WALL-CLOCK timestep (≈60 Hz), at most
        // once per frame, so the field evolves at a constant real-time rate no
        // matter how fast this loop spins. Stepping once per loop iteration
        // coupled the sim to the INPUT rate: streaming mouse-motion events drove
        // the loop far above 60 fps, speeding up the WHOLE field whenever the
        // pointer moved (the live app had the same bug — this mirrors its fix).
        const dt_ns: u64 = 16_666_667; // 1/60 s
        const now_ns = clock_shell.monotonicNanos();
        const due = last_step_ns == 0 or (now_ns -| last_step_ns) >= dt_ns;
        if (due) {
            // Fill the time-driven ambient bias (shell side → the core stays pure).
            var yy: u32 = 0;
            while (yy < grows) : (yy += 1) {
                const fy: f32 = @floatFromInt(yy);
                var xx: u32 = 0;
                while (xx < gcols) : (xx += 1) {
                    const fx: f32 = @floatFromInt(xx);
                    const base = std.math.sin(fx * amb_scale + t * amb_drift) *
                        std.math.sin(fy * amb_scale * 1.3 - t * amb_drift * 0.8);
                    // a finer, slowly-drifting term → cell-scale variation, so the
                    // dense interior is an ASSORTMENT of glyphs, not a wall of '#'.
                    const fine = std.math.sin(fx * 0.21 - t * 0.07) *
                        std.math.sin(fy * 0.18 + t * 0.06);
                    bias[yy * gcols + xx] = amb_amp * (base + 0.5 * fine);
                }
            }
            // Advance the medium one step (calm). Splashes injected once.
            glyph_field.step(&field, fparams, splashes.items, bias);
            splashes.clearRetainingCapacity();
            t += 1.0 / 60.0;
            last_step_ns = if (last_step_ns == 0 or (now_ns -| last_step_ns) > dt_ns * 4)
                now_ns
            else
                last_step_ns + dt_ns;
        }

        // Upload the height field, render it grid-intensity behind the feed.
        gpu.uploadField(&field_grid, field.height, field.dye, field.cols, field.rows);
        gpu.clear(clear_r, clear_g, clear_b);
        gpu.drawFieldGrid(&field_grid, &field_renderer, mcx, mcy, t, @intCast(cur_w), @intCast(cur_h), 0, 0);
        gpu.feedDraw(&feed_path, @intCast(cur_w), @intCast(cur_h)); // feed, on top
        gpu.swap(&g);
        if (frames == 0) gpu.glError("after first draw");

        frames += 1;
        if (frames > 3600) break; // ~60s safety cap
    }
    std.debug.print("gpu preview done ({d} frames).\n", .{frames});
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
