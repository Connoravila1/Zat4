//! Rover · reveal — a present / dismiss transition primitive.
//!
//! PORTABLE (Rover rule): PURE, standalone, `std`-only. No renderer, no window
//! backend, no app types cross this boundary. The reusable artifact is the
//! PROGRESS, not the pixels — you hand it a target (present / dismiss) and the
//! real elapsed time; it springs a `progress` in [0, 1]; the host maps that to a
//! slide offset / fade alpha / scale and draws it however it draws. One primitive
//! for keyboards, sheets, overlays, menus — anything that animates in and out
//! instead of popping (POLISH_STANDARD root-cause A).
//!
//! Motion is a CRITICALLY-DAMPED spring: it eases to the target with no overshoot
//! (a keyboard or sheet that bounced would read as cheap), and it is FRAME-RATE
//! INDEPENDENT — a fixed sub-step integrator, so the same wall-clock produces the
//! same motion at 60 Hz, 144 Hz, or across a dropped frame.

const std = @import("std");
const assert = std.debug.assert;

/// PLAIN DATA (A1): the transition's state. `progress` is what the host reads;
/// `velocity` is integrator state. One per animated surface — a handful exist,
/// but the record is tiny and guarded regardless.
pub const Reveal = struct {
    progress: f32 = 0, // 0 = fully dismissed, 1 = fully present
    velocity: f32 = 0, // integrator carry (progress/second)

    comptime {
        // Two f32, no padding.
        assert(@sizeOf(Reveal) == 8);
    }
};

/// Fixed integrator sub-step — smaller than any real frame, so every frame takes
/// at least one and the motion is frame-rate independent.
pub const sub_step: f32 = 1.0 / 240.0;

/// After a long stall (backgrounded, a breakpoint) do not run thousands of
/// catch-up sub-steps; clamp the accumulated time and fast-forward the settle.
pub const max_accum: f32 = 0.25;

/// Rest thresholds: the spring never mathematically reaches the target, so we
/// declare rest when the motion is imperceptible and snap exactly.
pub const rest_eps: f32 = 1.0e-3;
pub const rest_vel_eps: f32 = 1.0e-3;

/// The default perceptual settle time (seconds) — snappy, phone-keyboard feel.
pub const default_duration: f32 = 0.26;

/// Advance the transition toward `target` (true = present) over real elapsed
/// `dt` seconds, settling in ~`duration`. Critically damped: no overshoot.
pub fn step(r: *Reveal, target: bool, dt: f32, duration: f32) void {
    const goal: f32 = if (target) 1.0 else 0.0;
    // Critical spring: mass 1, natural frequency omega = 2*pi/duration, damping
    // = 2*omega (== 2*sqrt(k), the critical value), so it eases without ringing.
    const dur = @max(duration, 1.0e-3);
    const omega = (2.0 * std.math.pi) / dur;
    const k = omega * omega;
    const c = 2.0 * omega;

    var remaining = std.math.clamp(dt, 0.0, max_accum);
    while (remaining > 0.0) {
        const h = @min(sub_step, remaining);
        remaining -= h;
        // Semi-implicit Euler: update velocity from the current position, then
        // position from the new velocity (stable for stiff springs).
        const accel = -k * (r.progress - goal) - c * r.velocity;
        r.velocity += accel * h;
        r.progress += r.velocity * h;
    }

    // Snap to rest when imperceptibly close, so `active` can go false and the host
    // stops rebuilding.
    if (@abs(r.progress - goal) < rest_eps and @abs(r.velocity) < rest_vel_eps) {
        r.progress = goal;
        r.velocity = 0;
    }
    // A critically-damped spring can dip a hair past its target from numerical
    // slack; clamp to the visible range so offsets/alphas never go out of bounds.
    r.progress = std.math.clamp(r.progress, 0.0, 1.0);
}

/// Convenience: step with the default duration.
pub fn advance(r: *Reveal, target: bool, dt: f32) void {
    step(r, target, dt, default_duration);
}

/// True while the transition is still moving toward a target it has not reached —
/// the host keeps rendering (and rebuilding) while this is true, then goes quiet.
pub fn active(r: Reveal, target: bool) bool {
    const goal: f32 = if (target) 1.0 else 0.0;
    return @abs(r.progress - goal) >= rest_eps or @abs(r.velocity) >= rest_vel_eps;
}

/// True once the transition has fully dismissed (progress at 0). The host uses
/// this to know it may stop drawing the surface entirely.
pub fn dismissed(r: Reveal) bool {
    return r.progress <= rest_eps;
}

/// A panel of height `h` slides UP from the bottom edge: the amount (px) it should
/// still be pushed DOWN by, i.e. `(1 - progress) * h`. At progress 1 it is seated.
pub fn slideUp(r: Reveal, h: f32) f32 {
    return (1.0 - r.progress) * h;
}

/// Fade alpha in [0, 255] tracking progress — for surfaces that fade rather than
/// (or as well as) slide.
pub fn alpha8(r: Reveal) u8 {
    return @intFromFloat(std.math.clamp(r.progress, 0.0, 1.0) * 255.0);
}

// ---------------------------------------------------------------------------

test "reveal: presents to 1 and settles" {
    var r: Reveal = .{};
    try std.testing.expectEqual(@as(f32, 0), r.progress);
    // ~1 second at 60fps is far more than a 0.26s settle.
    var i: usize = 0;
    while (i < 120) : (i += 1) step(&r, true, 1.0 / 60.0, default_duration);
    try std.testing.expect(!active(r, true));
    try std.testing.expectEqual(@as(f32, 1), r.progress);
}

test "reveal: dismisses to 0 and reports dismissed" {
    var r: Reveal = .{ .progress = 1, .velocity = 0 };
    var i: usize = 0;
    while (i < 120) : (i += 1) step(&r, false, 1.0 / 60.0, default_duration);
    try std.testing.expect(!active(r, false));
    try std.testing.expect(dismissed(r));
    try std.testing.expectEqual(@as(f32, 0), r.progress);
}

test "reveal: no overshoot (stays within [0,1])" {
    var r: Reveal = .{};
    var i: usize = 0;
    while (i < 200) : (i += 1) {
        step(&r, true, 1.0 / 60.0, default_duration);
        try std.testing.expect(r.progress >= 0.0 and r.progress <= 1.0);
    }
}

test "reveal: frame-rate independent (one big step ~= many small)" {
    var a: Reveal = .{};
    var b: Reveal = .{};
    // 0.1s delivered as one step vs six.
    step(&a, true, 0.1, default_duration);
    var i: usize = 0;
    while (i < 6) : (i += 1) step(&b, true, 0.1 / 6.0, default_duration);
    try std.testing.expect(@abs(a.progress - b.progress) < 0.02);
}

test "reveal: slideUp maps progress to a downward offset" {
    var r: Reveal = .{ .progress = 0 };
    try std.testing.expectEqual(@as(f32, 300), slideUp(r, 300)); // fully hidden: pushed full height down
    r.progress = 1;
    try std.testing.expectEqual(@as(f32, 0), slideUp(r, 300)); // seated
    r.progress = 0.5;
    try std.testing.expectEqual(@as(f32, 150), slideUp(r, 300));
}
