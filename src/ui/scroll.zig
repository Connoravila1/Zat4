//! Rover · scroll — momentum + rubber-band SCROLL physics.
//!
//! PORTABLE (Rover rule): PURE, standalone, `std`-only. No renderer, no window
//! backend, no app types cross this boundary. The reusable artifact is the
//! OFFSET, not the pixels — you hand it a release velocity (`fling`) and the real
//! elapsed time (`step`); it carries an inertial `offset` that glides and decays
//! inside the content bounds and rubber-bands back when dragged past an edge. The
//! host reads `offset` and scrolls its content by it however it draws. One
//! primitive for feeds, thread views, side panels — anything that scrolls with
//! the browser's inertial / overscroll feel.
//!
//! Two regimes, both frame-rate INDEPENDENT via a fixed sub-step integrator (the
//! same wall-clock produces the same motion at 60 Hz, 144 Hz, or across a dropped
//! frame):
//!   · INSIDE  [min, max] — a free glide with exponential friction decay.
//!   · PAST a bound (overscroll) — a spring pulls the offset back to the bound and
//!     damps velocity harder, so the content springs home instead of running off.
//! Dragging past a bound is separately resisted by `overscrollResist` (the further
//! past the edge, the less each dragged pixel moves — the rubber-band drag feel).

const std = @import("std");
const assert = std.debug.assert;

/// PLAIN DATA (A1): the scroll's physics state. `offset` is what the host reads
/// (logical px of content displacement); `velocity` is integrator carry (px/sec).
/// One per scrollable surface — tiny, guarded regardless.
pub const Scroll = struct {
    offset: f32 = 0, // current scroll position (logical px)
    velocity: f32 = 0, // integrator carry (px/second)

    comptime {
        // Two f32, no padding.
        assert(@sizeOf(Scroll) == 8);
    }
};

/// Fixed integrator sub-step — smaller than any real frame, so every frame takes
/// at least one and the motion is frame-rate independent.
pub const sub_step: f32 = 1.0 / 240.0;

/// After a long stall (backgrounded, a breakpoint) do not run thousands of
/// catch-up sub-steps; clamp the accumulated time and fast-forward the settle.
pub const max_accum: f32 = 0.25;

/// Exponential friction for a free glide inside bounds: velocity decays as
/// `v * exp(-friction * dt)`, so a fling travels ~`v0 / friction` px before
/// resting. Higher = shorter, snappier throws.
pub const friction: f32 = 2.5;

/// Overscroll spring (the rubber-band pull-back when the offset is past a bound).
/// Stiffness `k` and damping `c` are chosen near-critical so the offset returns to
/// the bound quickly without ringing. omega ~= sqrt(k) ~= 15 rad/s; c a hair over
/// 2*omega to guarantee no overshoot from the discrete integrator.
pub const overscroll_stiffness: f32 = 225.0;
pub const overscroll_damping: f32 = 32.0;

/// Characteristic length (logical px) of the drag rubber-band in
/// `overscrollResist`: at `rubber_band_ref` px past a bound each dragged pixel
/// moves the offset half as far, and the resistance keeps climbing past that.
pub const rubber_band_ref: f32 = 220.0;

/// Rest thresholds. Below `rest_vel` (px/sec) a free glide is imperceptible and
/// snaps to a stop; within `rest_offset_eps` (px) of a bound an overscroll snaps
/// exactly to the bound. Both let `active` go false so the host stops rebuilding.
pub const rest_vel: f32 = 4.0;
pub const rest_offset_eps: f32 = 0.5;

/// Start a momentum scroll from a release velocity `v0` (logical px/second, the
/// sign of the content's motion). Replaces any current velocity — a fresh throw.
pub fn fling(s: *Scroll, v0: f32) void {
    s.velocity = v0;
}

/// Advance the scroll one frame over real elapsed `dt` seconds, given the valid
/// content range `[min, max]`. Inside the range the offset glides with friction;
/// past a bound a spring pulls it back and damps velocity harder. Settles (snaps
/// to a stop / exactly to the bound) once imperceptibly slow.
pub fn step(s: *Scroll, dt: f32, min: f32, max: f32) void {
    // Guard against an inverted range: collapse to a single valid point.
    const lo = @min(min, max);
    const hi = @max(min, max);

    var remaining = std.math.clamp(dt, 0.0, max_accum);
    while (remaining > 0.0) {
        const h = @min(sub_step, remaining);
        remaining -= h;

        if (s.offset >= lo and s.offset <= hi) {
            // INSIDE: free glide with exponential friction. Advancing position
            // first then decaying velocity keeps the integral of `v*exp(-f*t)`
            // frame-rate independent (products of exps compose exactly).
            s.offset += s.velocity * h;
            s.velocity *= @exp(-friction * h);
        } else {
            // OVERSCROLL: a spring toward the nearest bound, damped hard.
            // Semi-implicit Euler (update velocity, then position) is stable for
            // this stiff spring.
            const bound = std.math.clamp(s.offset, lo, hi);
            const disp = s.offset - bound;
            const accel = -overscroll_stiffness * disp - overscroll_damping * s.velocity;
            s.velocity += accel * h;
            s.offset += s.velocity * h;
        }
    }

    // Settle. Inside bounds: an imperceptibly slow glide stops.
    if (s.offset >= lo and s.offset <= hi) {
        if (@abs(s.velocity) < rest_vel) s.velocity = 0;
    } else {
        // Overscroll: within a whisker of the bound and barely moving -> snap home.
        const bound = std.math.clamp(s.offset, lo, hi);
        if (@abs(s.offset - bound) < rest_offset_eps and @abs(s.velocity) < rest_vel) {
            s.offset = bound;
            s.velocity = 0;
        }
    }
}

/// While the user DRAGS, convert a raw pointer delta into the resisted offset
/// delta. Inside `[min, max]` movement is 1:1. Past a bound, movement heading
/// FURTHER out is progressively resisted (the rubber-band drag feel: the further
/// past the edge, the smaller each dragged pixel's effect); movement heading BACK
/// toward the content is unresisted so the edge releases cleanly.
pub fn overscrollResist(raw_delta: f32, offset: f32, min: f32, max: f32) f32 {
    const lo = @min(min, max);
    const hi = @max(min, max);

    const past: f32 = if (offset < lo) lo - offset else if (offset > hi) offset - hi else 0;
    if (past <= 0) return raw_delta; // inside bounds: 1:1

    const going_further_out = (offset > hi and raw_delta > 0) or (offset < lo and raw_delta < 0);
    if (!going_further_out) return raw_delta; // returning toward content: unresisted

    // Resistance factor in (0, 1]: 1 at the bound, falling as we go further past.
    const factor = rubber_band_ref / (rubber_band_ref + past);
    return raw_delta * factor;
}

/// True while the scroll still needs to render: it is moving faster than the rest
/// threshold, or it is out of bounds (a rubber-band still settling). The host
/// keeps rendering while this is true, then goes quiet.
pub fn active(s: Scroll, min: f32, max: f32) bool {
    const lo = @min(min, max);
    const hi = @max(min, max);
    if (@abs(s.velocity) >= rest_vel) return true;
    if (s.offset < lo - rest_offset_eps or s.offset > hi + rest_offset_eps) return true;
    return false;
}

/// How far the offset is currently past a bound (logical px, 0 when inside). A
/// convenience for hosts that want to draw the stretched overscroll gap.
pub fn overscrollAmount(s: Scroll, min: f32, max: f32) f32 {
    const lo = @min(min, max);
    const hi = @max(min, max);
    if (s.offset < lo) return lo - s.offset;
    if (s.offset > hi) return s.offset - hi;
    return 0;
}

// ---------------------------------------------------------------------------

test "scroll: a fling decays to rest inside bounds" {
    var s: Scroll = .{ .offset = 500 };
    fling(&s, 600); // v0/friction = 240px of travel -> ends ~740, inside [0,1000]
    var i: usize = 0;
    while (i < 600) : (i += 1) step(&s, 1.0 / 60.0, 0, 1000);
    try std.testing.expect(!active(s, 0, 1000));
    try std.testing.expectEqual(@as(f32, 0), s.velocity);
    // Moved forward but stayed strictly inside the bounds.
    try std.testing.expect(s.offset > 500 and s.offset < 1000);
}

test "scroll: releasing past a bound springs back exactly to the bound" {
    // Released 50px past the min bound with no velocity.
    var s: Scroll = .{ .offset = -50, .velocity = 0 };
    var i: usize = 0;
    while (i < 600) : (i += 1) step(&s, 1.0 / 60.0, 0, 1000);
    try std.testing.expect(!active(s, 0, 1000));
    try std.testing.expectEqual(@as(f32, 0), s.offset); // snapped exactly to min
    try std.testing.expectEqual(@as(f32, 0), s.velocity);
}

test "scroll: a fling PAST the far edge springs back to that bound" {
    // A hard throw upward that overshoots max, then rubber-bands home.
    var s: Scroll = .{ .offset = 980 };
    fling(&s, 1500);
    var i: usize = 0;
    while (i < 900) : (i += 1) {
        step(&s, 1.0 / 60.0, 0, 1000);
        // The spring must never let it run away past the bound unboundedly.
        try std.testing.expect(s.offset < 1200);
    }
    try std.testing.expect(!active(s, 0, 1000));
    try std.testing.expectEqual(@as(f32, 1000), s.offset);
    try std.testing.expectEqual(@as(f32, 0), s.velocity);
}

test "scroll: overscrollResist is 1:1 inside, resisted past a bound" {
    // Inside bounds: full delta.
    try std.testing.expectEqual(@as(f32, 100), overscrollResist(100, 500, 0, 1000));
    try std.testing.expectEqual(@as(f32, -40), overscrollResist(-40, 10, 0, 1000));

    // 30px past the min, dragging FURTHER out (negative): resisted, |result| < |raw|.
    const r_out = overscrollResist(-20, -30, 0, 1000);
    try std.testing.expect(r_out < 0); // same direction
    try std.testing.expect(@abs(r_out) < 20); // resisted
    try std.testing.expect(@abs(r_out) > 0);

    // Same position but dragging BACK toward content (positive): unresisted.
    try std.testing.expectEqual(@as(f32, 20), overscrollResist(20, -30, 0, 1000));

    // Further past the edge = stronger resistance (smaller factor).
    const near = overscrollResist(-10, -20, 0, 1000);
    const far = overscrollResist(-10, -400, 0, 1000);
    try std.testing.expect(@abs(far) < @abs(near));
}

test "scroll: overscrollResist past the max bound" {
    // 50px past max, dragging further out (positive) -> resisted.
    const r = overscrollResist(30, 1050, 0, 1000);
    try std.testing.expect(r > 0 and r < 30);
    // Coming back (negative) -> unresisted.
    try std.testing.expectEqual(@as(f32, -30), overscrollResist(-30, 1050, 0, 1000));
}

test "scroll: frame-rate independent (one big step ~= many small)" {
    var a: Scroll = .{ .offset = 500 };
    var b: Scroll = .{ .offset = 500 };
    fling(&a, 900);
    fling(&b, 900);
    // 0.1s delivered as one step vs six.
    step(&a, 0.1, 0, 1000);
    var i: usize = 0;
    while (i < 6) : (i += 1) step(&b, 0.1 / 6.0, 0, 1000);
    try std.testing.expect(@abs(a.offset - b.offset) < 1.0);
    try std.testing.expect(@abs(a.velocity - b.velocity) < 1.0);
}

test "scroll: frame-rate independent through an overscroll spring" {
    var a: Scroll = .{ .offset = -40 };
    var b: Scroll = .{ .offset = -40 };
    step(&a, 0.05, 0, 1000);
    var i: usize = 0;
    while (i < 10) : (i += 1) step(&b, 0.05 / 10.0, 0, 1000);
    try std.testing.expect(@abs(a.offset - b.offset) < 1.0);
}

test "scroll: active reports motion and out-of-bounds, quiet at rest" {
    var s: Scroll = .{ .offset = 500, .velocity = 0 };
    try std.testing.expect(!active(s, 0, 1000)); // at rest inside
    s.velocity = 100;
    try std.testing.expect(active(s, 0, 1000)); // moving
    s.velocity = 0;
    s.offset = -20;
    try std.testing.expect(active(s, 0, 1000)); // out of bounds, still settling
}

test "scroll: overscrollAmount measures the gap past a bound" {
    try std.testing.expectEqual(@as(f32, 0), overscrollAmount(.{ .offset = 500 }, 0, 1000));
    try std.testing.expectEqual(@as(f32, 25), overscrollAmount(.{ .offset = -25 }, 0, 1000));
    try std.testing.expectEqual(@as(f32, 30), overscrollAmount(.{ .offset = 1030 }, 0, 1000));
}

test "scroll: an inverted range does not explode" {
    // min > max collapses to a point; the offset must settle there, not diverge.
    var s: Scroll = .{ .offset = 200 };
    fling(&s, 500);
    var i: usize = 0;
    while (i < 600) : (i += 1) {
        step(&s, 1.0 / 60.0, 300, 300);
        try std.testing.expect(std.math.isFinite(s.offset));
    }
    try std.testing.expect(!active(s, 300, 300));
    try std.testing.expectEqual(@as(f32, 300), s.offset);
}
