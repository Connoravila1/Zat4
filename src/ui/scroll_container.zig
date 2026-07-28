//! Rover · scroll container — structural scrolling without renderer or physics.
//!
//! Composition module: owns the browser-like rules around a scroll surface while
//! leaving motion feel to Spunky. It derives the valid range from viewport/content
//! extents, locks when content fits, converts a positive scroll position into the
//! negative descendant translation used for painting and input, consumes drag
//! deltas for nested chaining, brings a target interval into view, and returns
//! scrollbar geometry.
//!
//! Coordinate convention:
//! - `position == 0` is the content start.
//! - positive position moves toward later content.
//! - descendant translation is `-position`.
//! - positive finger delta moves the finger toward the viewport end and therefore
//!   decreases position (reveals earlier content).

const std = @import("std");
const assert = std.debug.assert;
const runtime = @import("runtime.zig");

pub const Metrics = struct {
    viewport: f32 = 0,
    content: f32 = 0,

    comptime {
        assert(@sizeOf(Metrics) == 8);
    }
};

pub const State = struct {
    position: f32 = 0,

    comptime {
        assert(@sizeOf(State) == 4);
    }
};

/// Result of consuming one delta. `consumed` changed this container; `remaining`
/// is offered to an ancestor scroll container.
pub const Consumption = struct {
    consumed: f32 = 0,
    remaining: f32 = 0,

    comptime {
        assert(@sizeOf(Consumption) == 8);
    }
};

pub const Align = enum(u8) {
    /// Move only when necessary, choosing the nearest edge.
    nearest,
    start,
    center,
    end,
};

pub const Thumb = struct {
    offset: f32 = 0,
    extent: f32 = 0,
    visible: bool = false,
    // A7.2: transient renderer geometry.
};

pub fn valid(m: Metrics) bool {
    return std.math.isFinite(m.viewport) and
        std.math.isFinite(m.content) and
        m.viewport >= 0 and
        m.content >= 0;
}

pub fn maxPosition(m: Metrics) f32 {
    if (!valid(m)) return 0;
    return @max(0.0, m.content - m.viewport);
}

pub fn scrollable(m: Metrics) bool {
    return maxPosition(m) > 0;
}

pub fn clamp(s: *State, m: Metrics) void {
    if (!std.math.isFinite(s.position)) s.position = 0;
    s.position = std.math.clamp(s.position, 0.0, maxPosition(m));
}

/// Positive delta advances through content. Returns the part that could not be
/// consumed at an edge.
pub fn scrollBy(s: *State, m: Metrics, delta: f32) Consumption {
    if (!std.math.isFinite(delta) or !scrollable(m)) {
        clamp(s, m);
        return .{ .remaining = if (std.math.isFinite(delta)) delta else 0 };
    }
    clamp(s, m);
    const before = s.position;
    s.position = std.math.clamp(before + delta, 0.0, maxPosition(m));
    const consumed = s.position - before;
    return .{ .consumed = consumed, .remaining = delta - consumed };
}

/// Finger-space convenience. A finger moving toward the viewport start (negative
/// delta on a vertical list) advances content; remaining delta keeps the original
/// finger-space sign for direct nested chaining.
pub fn dragBy(s: *State, m: Metrics, finger_delta: f32) Consumption {
    const content = scrollBy(s, m, -finger_delta);
    return .{
        .consumed = -content.consumed,
        .remaining = -content.remaining,
    };
}

/// Inner consumes first; only its exhausted-edge remainder reaches the ancestor.
pub fn chainDrag(
    inner: *State,
    inner_metrics: Metrics,
    outer: *State,
    outer_metrics: Metrics,
    finger_delta: f32,
) Consumption {
    const first = dragBy(inner, inner_metrics, finger_delta);
    const second = dragBy(outer, outer_metrics, first.remaining);
    return .{
        .consumed = first.consumed + second.consumed,
        .remaining = second.remaining,
    };
}

/// Content translation to apply to the runtime node containing descendants.
pub fn translationY(s: State) runtime.Translation {
    return .{ .y = -s.position };
}

/// Bring `[item_start,item_end]` (content coordinates) into the viewport.
pub fn reveal(s: *State, m: Metrics, item_start: f32, item_end: f32, alignment: Align) void {
    if (!valid(m) or
        !std.math.isFinite(item_start) or
        !std.math.isFinite(item_end))
    {
        clamp(s, m);
        return;
    }
    const start = @min(item_start, item_end);
    const end = @max(item_start, item_end);
    const extent = end - start;
    const target = switch (alignment) {
        .start => start,
        .center => start - (m.viewport - extent) / 2,
        .end => end - m.viewport,
        .nearest => blk: {
            clamp(s, m);
            const view_start = s.position;
            const view_end = s.position + m.viewport;
            if (start < view_start) break :blk start;
            if (end > view_end) {
                // Oversized intervals seat their start; otherwise reveal the end.
                break :blk if (extent > m.viewport) start else end - m.viewport;
            }
            break :blk s.position;
        },
    };
    s.position = std.math.clamp(target, 0.0, maxPosition(m));
}

/// Scrollbar thumb in track coordinates. A fitting/empty surface has no thumb.
pub fn thumb(s: State, m: Metrics, track_extent: f32, min_extent: f32) Thumb {
    if (!scrollable(m) or
        !std.math.isFinite(track_extent) or
        !std.math.isFinite(min_extent) or
        track_extent <= 0)
    {
        return .{};
    }
    const minimum = std.math.clamp(min_extent, 0.0, track_extent);
    const extent = std.math.clamp(track_extent * (m.viewport / m.content), minimum, track_extent);
    const travel = track_extent - extent;
    const progress = std.math.clamp(s.position, 0.0, maxPosition(m)) / maxPosition(m);
    return .{
        .offset = travel * progress,
        .extent = extent,
        .visible = true,
    };
}

fn approx(a: f32, b: f32) bool {
    return @abs(a - b) < 0.001;
}

test "scroll container: fitting content locks exactly at zero" {
    const cases = [_]Metrics{
        .{ .viewport = 100, .content = 0 },
        .{ .viewport = 100, .content = 80 },
        .{ .viewport = 100, .content = 100 },
    };
    for (cases) |m| {
        var s: State = .{ .position = 30 };
        const result = scrollBy(&s, m, 20);
        try std.testing.expectEqual(@as(f32, 0), s.position);
        try std.testing.expectEqual(@as(f32, 20), result.remaining);
        try std.testing.expect(!scrollable(m));
        try std.testing.expect(!thumb(s, m, 100, 16).visible);
    }
}

test "scroll container: ranges and translation share one position" {
    const m: Metrics = .{ .viewport = 100, .content = 350 };
    var s: State = .{};
    const a = scrollBy(&s, m, 80);
    try std.testing.expect(approx(a.consumed, 80) and approx(a.remaining, 0));
    try std.testing.expect(approx(s.position, 80));
    try std.testing.expect(approx(translationY(s).y, -80));
    const b = scrollBy(&s, m, 500);
    try std.testing.expect(approx(s.position, 250));
    try std.testing.expect(approx(b.consumed, 170));
    try std.testing.expect(approx(b.remaining, 330));
}

test "scroll container: drag preserves finger-space signs" {
    const m: Metrics = .{ .viewport = 100, .content = 300 };
    var s: State = .{ .position = 100 };
    const up = dragBy(&s, m, -30);
    try std.testing.expect(approx(s.position, 130));
    try std.testing.expect(approx(up.consumed, -30));
    const down_past_start = dragBy(&s, m, 200);
    try std.testing.expect(approx(s.position, 0));
    try std.testing.expect(approx(down_past_start.consumed, 130));
    try std.testing.expect(approx(down_past_start.remaining, 70));
}

test "scroll container: nested chaining forwards only edge remainder" {
    const inner_m: Metrics = .{ .viewport = 100, .content = 200 };
    const outer_m: Metrics = .{ .viewport = 200, .content = 500 };
    var inner: State = .{ .position = 90 };
    var outer: State = .{ .position = 40 };
    const result = chainDrag(&inner, inner_m, &outer, outer_m, -50);
    try std.testing.expect(approx(inner.position, 100)); // consumed first 10
    try std.testing.expect(approx(outer.position, 80)); // ancestor consumed remaining 40
    try std.testing.expect(approx(result.remaining, 0));
}

test "scroll container: reveal follows nearest and explicit alignment" {
    const m: Metrics = .{ .viewport = 100, .content = 500 };
    var s: State = .{ .position = 100 };
    reveal(&s, m, 120, 150, .nearest); // already visible
    try std.testing.expect(approx(s.position, 100));
    reveal(&s, m, 240, 270, .nearest);
    try std.testing.expect(approx(s.position, 170)); // reveal end
    reveal(&s, m, 300, 340, .center);
    try std.testing.expect(approx(s.position, 270));
    reveal(&s, m, 490, 500, .end);
    try std.testing.expect(approx(s.position, 400)); // max clamp
}

test "scroll container: oversized reveal seats the item start" {
    const m: Metrics = .{ .viewport = 100, .content = 500 };
    var s: State = .{ .position = 250 };
    reveal(&s, m, 80, 240, .nearest);
    try std.testing.expect(approx(s.position, 80));
}

test "scroll container: thumb tracks progress and honors minimum extent" {
    const m: Metrics = .{ .viewport = 100, .content = 400 };
    const top = thumb(.{ .position = 0 }, m, 200, 24);
    try std.testing.expect(top.visible);
    try std.testing.expect(approx(top.extent, 50));
    try std.testing.expect(approx(top.offset, 0));
    const bottom = thumb(.{ .position = 300 }, m, 200, 24);
    try std.testing.expect(approx(bottom.offset, 150));

    const tiny_view: Metrics = .{ .viewport = 1, .content = 1000 };
    try std.testing.expect(approx(thumb(.{}, tiny_view, 100, 20).extent, 20));
}

test "scroll container: invalid values collapse safely" {
    var s: State = .{ .position = std.math.nan(f32) };
    clamp(&s, .{ .viewport = -1, .content = 100 });
    try std.testing.expectEqual(@as(f32, 0), s.position);
    const r = scrollBy(&s, .{ .viewport = 100, .content = 200 }, std.math.inf(f32));
    try std.testing.expectEqual(@as(f32, 0), r.consumed);
    try std.testing.expectEqual(@as(f32, 0), r.remaining);
}
