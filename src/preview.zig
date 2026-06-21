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
const feed = @import("core/feed.zig");
const field = @import("core/field.zig");

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
        mk("mara.zat", "Mara Vesper", "the whole point of a small network is that you can actually read the room. ten thousand strangers isn't a room, it's weather.", now - 120, 48, 9, 6, true, false),
        mk("fieldnotes.zat", "field notes", "shipped the lighting pass tonight. the letters catch the light now, and the whole field moves when you touch it.", now - 840, 121, 31, 12, false, true),
        mk("oko.zat", "Okonkwo", "monospace is the most honest a feed can be. same column, same weight, nobody shouts louder by being wider.", now - 3600, 73, 18, 24, false, false),
        mk("lune.zat", "lune", "woke up to the field still drifting where i left it. it kept the light on.", now - 10800, 39, 7, 3, false, false),
    };
    // Make one feed item a reply, to show the "Replying to @x" context line.
    items[1].replying_to_handle = "mara.zat";
    const posts = try feed_view.fromTimeline(arena, &items, now);

    _ = try feed_view.layout(gpa, &engine, @intCast(W), @intCast(H), posts, 0, &dl, null, null, false, 0, null, 3);
    try raster.paint(gpa, &engine, dl.slice(), &fb, clear);

    const io = init.io;
    try writePpm(io, gpa, &fb, "/tmp/zat_preview.ppm");
    std.debug.print("wrote /tmp/zat_preview.ppm ({d}x{d}, {d} items)\n", .{ W, H, dl.len });

    // The premium composer (PHASE C1): same field background, the composer card
    // over it via the REAL layoutCompose path → a second PPM proof.
    @memset(fb.pixels, clear);
    dl.len = 0;
    try field.compose(gpa, &f, particles.slice(), light, cell_w, cell_h, &dl);
    try feed_view.layoutCompose(gpa, &engine, @intCast(W), @intCast(H), .reply, "@mara.zat", "a small network is one where you can actually read the room — not weather, a room.", "", &dl, null);
    try raster.paint(gpa, &engine, dl.slice(), &fb, clear);
    try writePpm(io, gpa, &fb, "/tmp/zat_compose.ppm");
    std.debug.print("wrote /tmp/zat_compose.ppm ({d}x{d}, {d} items)\n", .{ W, H, dl.len });

    // The thread view (PHASE C4): Reddit-style NESTED. A small tree with depths
    // (the view-derived nesting buildThreadView produces) — root, two replies,
    // a reply-to-a-reply — to show the indent + guide rails + focus highlight.
    @memset(fb.pixels, clear);
    dl.len = 0;
    try field.compose(gpa, &f, particles.slice(), light, cell_w, cell_h, &dl);
    const thread = [_]feed_view.PostView{
        tv("mara.zat", "Mara Vesper", "the whole point of a small network is that you can actually read the room.", 0xFFCAA3A8, 'M', 0, false),
        tv("oko.zat", "Okonkwo", "agreed — ten thousand strangers isn't a room, it's weather.", 0xFF9FC7A0, 'O', 1, false),
        tv("lune.zat", "lune", "weather you can't even reply to without getting rained on.", 0xFFA9B6D6, 'l', 2, true),
        tv("rune.zat", "rune", "this is why i kept the field on. it keeps the light at human scale.", 0xFFB5A9CC, 'r', 1, false),
    };
    _ = try feed_view.layout(gpa, &engine, @intCast(W), @intCast(H), &thread, 0, &dl, null, null, false, feed_view.screen_thread, null, 0);
    try raster.paint(gpa, &engine, dl.slice(), &fb, clear);
    try writePpm(io, gpa, &fb, "/tmp/zat_thread.ppm");
    std.debug.print("wrote /tmp/zat_thread.ppm ({d}x{d}, {d} items)\n", .{ W, H, dl.len });
}

/// A thread PostView with an explicit nesting depth + focus flag (preview only).
fn tv(handle: []const u8, name: []const u8, body: []const u8, tint: u32, initial: u8, depth: u8, is_focus: bool) feed_view.PostView {
    _ = handle;
    return .{
        .name = name,
        .handle = "@x.zat",
        .age = "2h",
        .body = body,
        .tint = tint,
        .reply = 0,
        .boost = 0,
        .like = 0,
        .initial = initial,
        .liked = false,
        .boosted = false,
        .depth = depth,
        .is_focus = is_focus,
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
