//! Zat4 Algorithms binding for Rover's resolved scene runtime.
//!
//! Algorithms emits page controls and three independent lens-socket hit lists.
//! This module hides their node identities inside one retained Rover scene so
//! sticky header/bottom clipping and cross-list z order are resolved once.

const std = @import("std");
const assert = std.debug.assert;
const feed_view = @import("../core/feed_view.zig");
const lens_socket = @import("../core/lens_socket.zig");
const rover = @import("../ui/runtime.zig");

const page_base: u32 = 0x1000;
const socket_base = [_]u32{ 0x100000, 0x200000, 0x300000 };

pub const Scene = struct {
    runtime: rover.Scene,
    page_count: usize = 0,
    socket_count: [3]usize = .{ 0, 0, 0 },
    active: bool = false,

    // A7.2: cold owner, exactly one retained Algorithms surface.

    pub fn init(gpa: std.mem.Allocator) Scene {
        return .{ .runtime = rover.Scene.init(gpa) };
    }

    pub fn deinit(s: *Scene) void {
        s.runtime.deinit();
        s.* = undefined;
    }

    pub fn clear(s: *Scene) void {
        s.runtime.reset();
        s.page_count = 0;
        s.socket_count = .{ 0, 0, 0 };
        s.active = false;
    }
};

pub const BuildError = rover.AddError || rover.ResolveError;

pub fn isScreen(screen: u8) bool {
    return screen == feed_view.screen_loadout or
        screen == feed_view.screen_algo_detail or
        screen == feed_view.screen_algo_docs or
        screen == feed_view.screen_transparency;
}

pub fn rebuild(
    s: *Scene,
    gpa: std.mem.Allocator,
    screen: u8,
    page: []const feed_view.Region,
    sockets: [3][]const lens_socket.HitRect,
    width: i32,
    height: i32,
    body_top: i32,
    body_bottom: i32,
    scroll: i32,
) BuildError!void {
    s.clear();
    errdefer s.clear();
    if (!isScreen(screen)) return;

    const safe_w = @max(0, width);
    const safe_h = @max(0, height);
    const top = std.math.clamp(body_top, 0, safe_h);
    const bottom = std.math.clamp(body_bottom, top, safe_h);
    const root = try s.runtime.addRoot(gpa, .{
        .id = @enumFromInt(1),
        .rect = rectOf(0, 0, safe_w, safe_h),
        .overflow = .clip,
    });
    const body = try s.runtime.addChild(gpa, root, .{
        .id = @enumFromInt(2),
        .rect = rectOf(0, top, safe_w, bottom - top),
        .overflow = .scroll,
    });
    const content = try s.runtime.addChild(gpa, body, .{
        .id = @enumFromInt(3),
        .rect = rectOf(0, -top, safe_w, @max(safe_h, bottom - scroll)),
        .translation = .{ .y = @floatFromInt(scroll) },
    });

    for (page, 0..) |r, i| {
        const fixed = screen == feed_view.screen_loadout and isFixedPageAction(r.kind);
        const overlay = screen == feed_view.screen_loadout and isOverlayAction(r.kind);
        const y = if (fixed or overlay) @as(i32, r.y) else @as(i32, r.y) - scroll;
        _ = try s.runtime.addChild(gpa, if (fixed or overlay) root else content, .{
            .id = idAt(page_base, i),
            .rect = rectOf(r.x, y, r.w, r.h),
            .flags = .{ .hittable = true, .focusable = true },
            .z = if (overlay) 30 else if (fixed) 20 else 0,
        });
    }

    for (sockets, 0..) |hits, surface| {
        for (hits, 0..) |r, i| {
            _ = try s.runtime.addChild(gpa, content, .{
                .id = idAt(socket_base[surface], i),
                .rect = rectOf(r.x, @as(i32, r.y) - scroll, r.w, r.h),
                .flags = .{ .hittable = true, .focusable = true },
                // Socket controls are painted after their page card and beat it.
                .z = 5,
            });
        }
    }

    try s.runtime.resolve(rectOf(0, 0, safe_w, safe_h));
    s.page_count = page.len;
    for (sockets, 0..) |hits, i| s.socket_count[i] = hits.len;
    s.active = true;
}

pub fn pageHitTest(s: *const Scene, page: []const feed_view.Region, x: i32, y: i32) ?feed_view.Region {
    if (!s.active) return feed_view.hitTest(page, x, y);
    const raw = @intFromEnum(s.runtime.hitTest(@floatFromInt(x), @floatFromInt(y)));
    if (raw < page_base or raw >= socket_base[0]) return null;
    const i = raw - page_base;
    if (i >= s.page_count or i >= page.len) return null;
    return page[i];
}

pub fn socketHitTest(
    s: *const Scene,
    surface: u8,
    hits: []const lens_socket.HitRect,
    x: i32,
    y: i32,
) ?lens_socket.SocketAction {
    if (!s.active) return lens_socket.hitTest(hits, x, y);
    if (surface >= socket_base.len) return null;
    const raw = @intFromEnum(s.runtime.hitTest(@floatFromInt(x), @floatFromInt(y)));
    const base = socket_base[surface];
    const limit = if (surface + 1 < socket_base.len) socket_base[surface + 1] else std.math.maxInt(u32);
    if (raw < base or raw >= limit) return null;
    const i = raw - base;
    if (i >= s.socket_count[surface] or i >= hits.len) return null;
    return lens_socket.actionForHit(hits[i]);
}

fn isFixedPageAction(action: feed_view.Action) bool {
    return action == .nav or action == .loadout_tab or action == .drawer_open or action == .drawer_close;
}

fn isOverlayAction(action: feed_view.Action) bool {
    return action == .bench_confirm or action == .bench_cancel or action == .blocker;
}

fn idAt(base: u32, index: usize) rover.Id {
    const offset = std.math.cast(u32, index).?;
    assert(offset < 0x100000 - page_base);
    return @enumFromInt(base + offset);
}

fn rectOf(x: anytype, y: anytype, w: anytype, h: anytype) rover.Rect {
    return .{
        .x = @floatFromInt(x),
        .y = @floatFromInt(y),
        .w = @floatFromInt(w),
        .h = @floatFromInt(h),
    };
}

fn pageRegion(x: i16, y: i16, w: u16, h: u16, kind: feed_view.Action) feed_view.Region {
    return .{ .x = x, .y = y, .w = w, .h = h, .post = 0, .kind = kind };
}

fn socketRegion(x: i16, y: i16, w: u16, h: u16) lens_socket.HitRect {
    return .{ .cid = "cid", .x = x, .y = y, .w = w, .h = h, .target = .seat };
}

test "Algorithms scene clips page and socket controls through one body" {
    var scene = Scene.init(std.testing.allocator);
    defer scene.deinit();
    const page = [_]feed_view.Region{
        pageRegion(20, 80, 80, 30, .algo_open),
        pageRegion(20, 160, 80, 30, .algo_open),
        pageRegion(20, 20, 100, 30, .loadout_tab),
    };
    const feed_hits = [_]lens_socket.HitRect{
        socketRegion(140, 80, 80, 30),
        socketRegion(140, 160, 80, 30),
    };
    try rebuild(&scene, std.testing.allocator, feed_view.screen_loadout, &page, .{ &feed_hits, &.{}, &.{} }, 320, 300, 130, 270, -40);

    try std.testing.expect(pageHitTest(&scene, &page, 40, 90) == null);
    try std.testing.expectEqual(feed_view.Action.algo_open, pageHitTest(&scene, &page, 40, 170).?.kind);
    try std.testing.expect(socketHitTest(&scene, 0, &feed_hits, 160, 90) == null);
    try std.testing.expect(socketHitTest(&scene, 0, &feed_hits, 160, 170) != null);
    try std.testing.expectEqual(feed_view.Action.loadout_tab, pageHitTest(&scene, &page, 40, 30).?.kind);
}

test "Algorithms modal blocks page and all socket lists" {
    var scene = Scene.init(std.testing.allocator);
    defer scene.deinit();
    const page = [_]feed_view.Region{
        pageRegion(20, 160, 100, 40, .algo_open),
        pageRegion(0, 0, 320, 300, .bench_cancel),
        pageRegion(80, 150, 120, 40, .bench_confirm),
    };
    const feed_hits = [_]lens_socket.HitRect{socketRegion(20, 160, 100, 40)};
    try rebuild(&scene, std.testing.allocator, feed_view.screen_loadout, &page, .{ &feed_hits, &.{}, &.{} }, 320, 300, 130, 300, 0);

    try std.testing.expectEqual(feed_view.Action.bench_cancel, pageHitTest(&scene, &page, 40, 170).?.kind);
    try std.testing.expectEqual(feed_view.Action.bench_confirm, pageHitTest(&scene, &page, 100, 170).?.kind);
    try std.testing.expect(socketHitTest(&scene, 0, &feed_hits, 40, 170) == null);
}
