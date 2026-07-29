//! Rover · runtime input — interaction routed from resolved scene geometry.
//!
//! Composition module: imports Rover's `runtime` and `input` kernels, but no host
//! or renderer code. This is the join that prevents pixels and hit regions from
//! drifting: the scene's world rect, inherited clip, visibility, disabled state,
//! z, and paint order select the target; the input kernel owns capture, click, and
//! focus transitions.

const std = @import("std");
const runtime = @import("runtime.zig");
const input = @import("input.zig");

fn toInputId(id: runtime.Id) input.Id {
    return @intFromEnum(id);
}

fn toRuntimeId(id: input.Id) runtime.Id {
    return @enumFromInt(id);
}

/// Advance pointer interaction directly from a resolved scene. No region list is
/// allocated or reconstructed.
pub fn update(scene: *const runtime.Scene, state: *input.State, pointer: input.Pointer) input.Event {
    // Stable state cannot continue referring to a control removed by a rebuild.
    if (state.capture != input.none and scene.flagsForId(toRuntimeId(state.capture)) == null) {
        state.capture = input.none;
        state.pressed = input.none;
    }
    if (state.focus != input.none) {
        const flags = scene.flagsForId(toRuntimeId(state.focus));
        if (flags == null or !flags.?.focusable) {
            state.focus = input.none;
            state.focus_visible = false;
        }
    }

    const target = scene.hitTest(pointer.x, pointer.y);
    const flags = scene.flagsForId(target);
    return input.updateHit(state, .{
        .id = toInputId(target),
        .focusable = if (flags) |f| f.focusable else false,
    }, pointer);
}

/// Move focus in resolved paint order, skipping clipped, hidden, and disabled
/// nodes because their resolved `focusable` bit is false.
pub fn focusNext(scene: *const runtime.Scene, state: *input.State, forward: bool) void {
    const next = scene.nextFocusable(toRuntimeId(state.focus), forward);
    if (next == .none) return;
    state.focus = toInputId(next);
    state.focus_visible = true;
}

pub fn ownsKeyboard(scene: *const runtime.Scene, state: input.State) bool {
    if (state.focus == input.none) return false;
    const flags = scene.flagsForId(toRuntimeId(state.focus)) orelse return false;
    return flags.focusable and flags.keyboard and !flags.disabled;
}

fn testId(n: u32) runtime.Id {
    return @enumFromInt(n);
}

test "runtime input: transformed clipped geometry is the only hit source" {
    var scene = runtime.Scene.init(std.testing.allocator);
    defer scene.deinit();

    const viewport = try scene.addRoot(std.testing.allocator, .{
        .id = testId(1),
        .rect = .{ .w = 100, .h = 100 },
        .translation = .{ .x = 20 },
        .overflow = .clip,
    });
    _ = try scene.addChild(std.testing.allocator, viewport, .{
        .id = testId(2),
        .rect = .{ .x = 10, .y = 10, .w = 30, .h = 30 },
        .flags = .{ .hittable = true },
    });
    _ = try scene.addChild(std.testing.allocator, viewport, .{
        .id = testId(3),
        .rect = .{ .x = 110, .y = 10, .w = 30, .h = 30 },
        .flags = .{ .hittable = true },
        .z = 50,
    });
    try scene.resolve(.{ .w = 200, .h = 200 });

    var state: input.State = .{};
    const transformed = update(&scene, &state, .{ .x = 35, .y = 15 });
    try std.testing.expectEqual(@as(input.Id, 2), transformed.hover);
    const stale_local = update(&scene, &state, .{ .x = 15, .y = 15 });
    try std.testing.expectEqual(input.none, stale_local.hover);
    const clipped = update(&scene, &state, .{ .x = 135, .y = 15 });
    try std.testing.expectEqual(input.none, clipped.hover);
}

test "runtime input: click, capture, and focus share the resolved target" {
    var scene = runtime.Scene.init(std.testing.allocator);
    defer scene.deinit();
    _ = try scene.addRoot(std.testing.allocator, .{
        .id = testId(7),
        .rect = .{ .x = 10, .y = 10, .w = 40, .h = 40 },
        .flags = .{ .hittable = true, .focusable = true },
    });
    try scene.resolve(.{ .w = 100, .h = 100 });

    var state: input.State = .{};
    const press = update(&scene, &state, .{ .x = 20, .y = 20, .down = true });
    try std.testing.expectEqual(@as(input.Id, 7), press.active);
    try std.testing.expectEqual(@as(input.Id, 7), state.focus);
    const drag = update(&scene, &state, .{ .x = 90, .y = 90, .down = true });
    try std.testing.expectEqual(@as(input.Id, 7), drag.pressed);
    try std.testing.expectEqual(input.none, drag.active);
    const release_off = update(&scene, &state, .{ .x = 90, .y = 90, .down = false });
    try std.testing.expectEqual(input.none, release_off.clicked);

    _ = update(&scene, &state, .{ .x = 20, .y = 20, .down = true });
    const release_on = update(&scene, &state, .{ .x = 20, .y = 20, .down = false });
    try std.testing.expectEqual(@as(input.Id, 7), release_on.clicked);
}

test "runtime input: focus traversal and keyboard ownership use resolved flags" {
    var scene = runtime.Scene.init(std.testing.allocator);
    defer scene.deinit();
    _ = try scene.addRoot(std.testing.allocator, .{
        .id = testId(1),
        .rect = .{ .w = 20, .h = 20 },
        .flags = .{ .hittable = true, .focusable = true },
    });
    _ = try scene.addRoot(std.testing.allocator, .{
        .id = testId(2),
        .rect = .{ .x = 30, .w = 20, .h = 20 },
        .flags = .{ .hittable = true, .focusable = true, .keyboard = true },
    });
    _ = try scene.addRoot(std.testing.allocator, .{
        .id = testId(3),
        .rect = .{ .x = 60, .w = 20, .h = 20 },
        .flags = .{ .hittable = true, .focusable = true, .keyboard = true, .disabled = true },
    });
    try scene.resolve(.{ .w = 100, .h = 100 });

    var state: input.State = .{};
    focusNext(&scene, &state, true);
    try std.testing.expectEqual(@as(input.Id, 1), state.focus);
    try std.testing.expect(!ownsKeyboard(&scene, state));
    focusNext(&scene, &state, true);
    try std.testing.expectEqual(@as(input.Id, 2), state.focus);
    try std.testing.expect(ownsKeyboard(&scene, state));
    focusNext(&scene, &state, true);
    try std.testing.expectEqual(@as(input.Id, 1), state.focus); // disabled 3 skipped
}

test "runtime input: removing focused and captured ids clears stale state" {
    var scene = runtime.Scene.init(std.testing.allocator);
    defer scene.deinit();
    _ = try scene.addRoot(std.testing.allocator, .{
        .id = testId(9),
        .rect = .{ .w = 20, .h = 20 },
        .flags = .{ .hittable = true, .focusable = true },
    });
    try scene.resolve(.{ .w = 100, .h = 100 });

    var state: input.State = .{};
    _ = update(&scene, &state, .{ .x = 10, .y = 10, .down = true });
    try std.testing.expectEqual(@as(input.Id, 9), state.capture);
    try std.testing.expectEqual(@as(input.Id, 9), state.focus);

    scene.reset();
    _ = try scene.addRoot(std.testing.allocator, .{ .id = testId(10), .rect = .{ .w = 20, .h = 20 } });
    try scene.resolve(.{ .w = 100, .h = 100 });
    _ = update(&scene, &state, .{ .x = 80, .y = 80, .down = true });
    try std.testing.expectEqual(input.none, state.capture);
    try std.testing.expectEqual(input.none, state.pressed);
    try std.testing.expectEqual(input.none, state.focus);
}
