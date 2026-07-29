//! Zat4 Home-feed binding for Rover's resolved scene runtime.
//!
//! `feed_view` still performs text measurement and emits draw commands during
//! the migration. This retained binding takes the exact interactive rectangles
//! emitted by that layout and declares their structure once: scrolling post
//! controls live below the sticky Home/socket header and above bottom chrome;
//! fixed chrome and popovers live above that clipped body. Painting eligibility
//! and input then query the same resolved Rover scene.

const std = @import("std");
const assert = std.debug.assert;
const feed_view = @import("../core/feed_view.zig");
const rover = @import("../ui/runtime.zig");

const first_region_id: u32 = 16;
const root_id: rover.Id = @enumFromInt(1);
const body_id: rover.Id = @enumFromInt(2);
const content_id: rover.Id = @enumFromInt(3);

pub const Scene = struct {
    runtime: rover.Scene,
    region_count: usize = 0,
    active: bool = false,

    // A7.2: cold owner, exactly one retained Home surface.

    pub fn init(gpa: std.mem.Allocator) Scene {
        return .{ .runtime = rover.Scene.init(gpa) };
    }

    pub fn deinit(s: *Scene) void {
        s.runtime.deinit();
        s.* = undefined;
    }

    pub fn clear(s: *Scene) void {
        s.runtime.reset();
        s.region_count = 0;
        s.active = false;
    }
};

pub const BuildError = rover.AddError || rover.ResolveError;

pub fn rebuild(
    s: *Scene,
    gpa: std.mem.Allocator,
    regions: []const feed_view.Region,
    width: i32,
    height: i32,
    body_top: i32,
    body_bottom: i32,
    scroll: i32,
) BuildError!void {
    s.clear();
    errdefer s.clear();

    const safe_w = @max(0, width);
    const safe_h = @max(0, height);
    const top = std.math.clamp(body_top, 0, safe_h);
    const bottom = std.math.clamp(body_bottom, top, safe_h);
    const root = try s.runtime.addRoot(gpa, .{
        .id = root_id,
        .rect = rectOf(0, 0, safe_w, safe_h),
        .overflow = .clip,
    });
    const body = try s.runtime.addChild(gpa, root, .{
        .id = body_id,
        .rect = rectOf(0, top, safe_w, bottom - top),
        .overflow = .scroll,
    });
    const content = try s.runtime.addChild(gpa, body, .{
        .id = content_id,
        .rect = rectOf(0, -top, safe_w, @max(safe_h, bottom - scroll)),
        .translation = .{ .y = @floatFromInt(scroll) },
    });

    for (regions, 0..) |region, i| {
        const id = regionId(i);
        const content_control = isContent(region.kind);
        const parent = if (content_control) content else root;
        const z: i16 = if (isOverlay(region.kind)) 20 else if (content_control) 0 else 10;
        const y = if (content_control) @as(i32, region.y) - scroll else @as(i32, region.y);
        _ = try s.runtime.addChild(gpa, parent, .{
            .id = id,
            .rect = rectOf(region.x, y, region.w, region.h),
            .flags = .{ .hittable = true, .focusable = true },
            .z = z,
        });
    }

    try s.runtime.resolve(rectOf(0, 0, safe_w, safe_h));
    s.region_count = regions.len;
    s.active = true;
}

/// Home input must not fall back to the raw region list when Rover reports no
/// hit: that miss is often the proof that sticky/bottom chrome clipped content.
pub fn hitTest(s: *const Scene, regions: []const feed_view.Region, x: i32, y: i32) ?feed_view.Region {
    if (!s.active) return feed_view.hitTest(regions, x, y);
    const id = s.runtime.hitTest(@floatFromInt(x), @floatFromInt(y));
    const raw = @intFromEnum(id);
    if (raw < first_region_id) return null;
    const i = raw - first_region_id;
    if (i >= s.region_count or i >= regions.len) return null;
    return regions[i];
}

/// True when the original region's centre survives Rover's inherited clipping.
/// Separate GPU icon passes use this rather than rebuilding the header bounds.
pub fn regionCenterVisible(s: *const Scene, region_index: usize, region: feed_view.Region) bool {
    if (!s.active or region_index >= s.region_count) return true;
    const node: rover.Node = @enumFromInt(3 + region_index);
    const resolved = s.runtime.result(node) orelse return false;
    if (!resolved.flags.visible) return false;
    const visible = rover.intersection(resolved.world, resolved.clip);
    const cx = @as(f32, @floatFromInt(region.x)) + @as(f32, @floatFromInt(region.w)) * 0.5;
    const cy = @as(f32, @floatFromInt(region.y)) + @as(f32, @floatFromInt(region.h)) * 0.5;
    return rover.contains(visible, cx, cy);
}

fn regionId(index: usize) rover.Id {
    const raw = first_region_id + std.math.cast(u32, index).?;
    assert(raw != 0);
    return @enumFromInt(raw);
}

fn rectOf(x: anytype, y: anytype, w: anytype, h: anytype) rover.Rect {
    return .{
        .x = @floatFromInt(x),
        .y = @floatFromInt(y),
        .w = @floatFromInt(w),
        .h = @floatFromInt(h),
    };
}

fn isContent(action: feed_view.Action) bool {
    return switch (action) {
        .reply,
        .repost,
        .like,
        .author,
        .post_body,
        .bookmark,
        .share,
        .more,
        .tag_inline,
        .expand,
        => true,
        else => false,
    };
}

fn isOverlay(action: feed_view.Action) bool {
    return switch (action) {
        .repost_do, .quote_open, .quote_new, .blocker => true,
        else => false,
    };
}

fn testRegion(x: i16, y: i16, w: u16, h: u16, post: u16, kind: feed_view.Action) feed_view.Region {
    return .{ .x = x, .y = y, .w = w, .h = h, .post = post, .kind = kind };
}

test "Home scene clips scrolled post input under sticky and bottom chrome" {
    var scene = Scene.init(std.testing.allocator);
    defer scene.deinit();
    const regions = [_]feed_view.Region{
        testRegion(20, 90, 80, 30, 0, .like),
        testRegion(20, 150, 80, 30, 1, .post_body),
        testRegion(20, 275, 80, 30, 2, .reply),
        testRegion(10, 10, 100, 40, 0, .nav),
    };
    try rebuild(&scene, std.testing.allocator, &regions, 320, 300, 120, 270, -60);

    try std.testing.expect(hitTest(&scene, &regions, 40, 100) == null);
    try std.testing.expectEqual(feed_view.Action.post_body, hitTest(&scene, &regions, 40, 160).?.kind);
    try std.testing.expect(hitTest(&scene, &regions, 40, 280) == null);
    try std.testing.expectEqual(feed_view.Action.nav, hitTest(&scene, &regions, 20, 20).?.kind);
    try std.testing.expect(!regionCenterVisible(&scene, 0, regions[0]));
    try std.testing.expect(regionCenterVisible(&scene, 1, regions[1]));
    try std.testing.expect(!regionCenterVisible(&scene, 2, regions[2]));
}

test "Home chrome wins over content by resolved z order" {
    var scene = Scene.init(std.testing.allocator);
    defer scene.deinit();
    const regions = [_]feed_view.Region{
        testRegion(20, 150, 100, 40, 4, .post_body),
        testRegion(20, 150, 100, 40, 0, .nav),
    };
    try rebuild(&scene, std.testing.allocator, &regions, 320, 300, 120, 300, 0);
    try std.testing.expectEqual(feed_view.Action.nav, hitTest(&scene, &regions, 40, 160).?.kind);
}
