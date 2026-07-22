//! Rover · ease — easing curves + tweening, as pure logic.
//!
//! PORTABLE (Rover rule): PURE, standalone, `std`-only. No renderer, no window
//! backend, no app types cross this boundary. This is the browser's CSS
//! `transition-timing-function` / `cubic-bezier()` and the classic Penner easing
//! family, expressed as free functions over plain data. All time is passed IN as
//! `dt` / `elapsed` — the module never reads a clock, allocates, or does I/O.
//!
//! Where `reveal.zig` is a critically-damped SPRING (physical, no fixed duration),
//! this is the complementary tool: a fixed-DURATION curve. You give it progress in
//! [0, 1] and it hands back an eased [0, 1] you map to an offset / alpha / scale;
//! or you hold a tiny `Tween` and `step` it by real elapsed time. One primitive for
//! every "animate A to B over N seconds along a named curve" the host needs.

const std = @import("std");
const assert = std.debug.assert;

// ---------------------------------------------------------------------------
// Scalar helpers
// ---------------------------------------------------------------------------

/// Linear interpolation from `a` to `b` by `t`. `t` is NOT clamped — callers that
/// want a bounded result clamp `t` first (see `clamp01`).
pub fn lerp(a: f32, b: f32, t: f32) f32 {
    return a + (b - a) * t;
}

/// Clamp progress to the visible [0, 1] range.
pub fn clamp01(t: f32) f32 {
    return std.math.clamp(t, 0.0, 1.0);
}

/// The inverse of `lerp`: where does `v` sit in [a, b] as a fraction? Returns 0 for
/// a degenerate span (a == b) so the result is always defined (E4: no error path).
pub fn inverseLerp(a: f32, b: f32, v: f32) f32 {
    const span = b - a;
    if (span == 0.0) return 0.0;
    return (v - a) / span;
}

/// Remap `v` from the input range [in_lo, in_hi] onto the output range
/// [out_lo, out_hi], preserving its relative position. The result is NOT clamped.
pub fn remap(in_lo: f32, in_hi: f32, out_lo: f32, out_hi: f32, v: f32) f32 {
    return lerp(out_lo, out_hi, inverseLerp(in_lo, in_hi, v));
}

// ---------------------------------------------------------------------------
// Named easing functions — `t` in [0, 1] -> eased [0, 1].
//
// Each is the direct algebraic form (F2: prefer the closed form over a table).
// All map 0 -> 0 and 1 -> 1. The "Out" variants are the "In" variants mirrored,
// and "InOut" splits the domain at 0.5.
// ---------------------------------------------------------------------------

/// Signature shared by every easing function — the type a `Tween` samples through.
pub const EaseFn = *const fn (f32) f32;

pub fn linear(t: f32) f32 {
    return t;
}

pub fn easeInQuad(t: f32) f32 {
    return t * t;
}

pub fn easeOutQuad(t: f32) f32 {
    return t * (2.0 - t); // 1 - (1 - t)^2
}

pub fn easeInOutQuad(t: f32) f32 {
    if (t < 0.5) return 2.0 * t * t;
    const u = -2.0 * t + 2.0;
    return 1.0 - (u * u) / 2.0;
}

pub fn easeInCubic(t: f32) f32 {
    return t * t * t;
}

pub fn easeOutCubic(t: f32) f32 {
    const u = 1.0 - t;
    return 1.0 - u * u * u;
}

pub fn easeInOutCubic(t: f32) f32 {
    if (t < 0.5) return 4.0 * t * t * t;
    const u = -2.0 * t + 2.0;
    return 1.0 - (u * u * u) / 2.0;
}

/// Overshoots slightly past 1 near the end, then settles back to exactly 1 — the
/// "pop" that reads as lively (Penner's back ease, standard 1.70158 constant).
pub fn easeOutBack(t: f32) f32 {
    const c1: f32 = 1.70158;
    const c3: f32 = c1 + 1.0;
    const u = t - 1.0;
    return 1.0 + c3 * u * u * u + c1 * u * u;
}

/// A damped sinusoid that overshoots and rings toward 1 — a springy "boing".
/// Endpoints are pinned exactly (0 -> 0, 1 -> 1) so it is Tween-safe.
pub fn easeOutElastic(t: f32) f32 {
    if (t <= 0.0) return 0.0;
    if (t >= 1.0) return 1.0;
    const c4: f32 = (2.0 * std.math.pi) / 3.0;
    // 2^(-10 t) * sin((10 t - 0.75) * c4) + 1
    const decay = std.math.pow(f32, 2.0, -10.0 * t);
    return decay * @sin((10.0 * t - 0.75) * c4) + 1.0;
}

// ---------------------------------------------------------------------------
// Cubic-bezier timing function (CSS `cubic-bezier(x1,y1,x2,y2)`)
// ---------------------------------------------------------------------------

/// Evaluate the y of a CSS cubic-bezier timing curve at progress `x = t`.
///
/// The curve has fixed endpoints P0 = (0,0) and P3 = (1,1); the caller supplies the
/// two control points P1 = (x1,y1), P2 = (x2,y2). Because the curve is parameterized
/// by an internal `s` in [0,1] and CSS wants "y at a given x", we first solve
/// `bezierX(s) = t` for `s` (Newton-Raphson, with a bisection fallback when the
/// derivative is too flat to trust), then return `bezierY(s)`. This is the standard
/// approach browsers use. Pure — no state, no allocation.
pub fn cubicBezier(x1: f32, y1: f32, x2: f32, y2: f32, t: f32) f32 {
    // Clamp the query to the defined domain; endpoints are exact.
    if (t <= 0.0) return 0.0;
    if (t >= 1.0) return 1.0;

    const s = solveBezierX(x1, x2, t);
    return bezierAxis(y1, y2, s);
}

/// One axis of the cubic bezier with fixed 0 / 1 endpoints, at parameter `s`.
/// B(s) = 3(1-s)^2 s * p1 + 3(1-s) s^2 * p2 + s^3   (the (1-s)^3 * 0 term drops).
fn bezierAxis(p1: f32, p2: f32, s: f32) f32 {
    const u = 1.0 - s;
    return 3.0 * u * u * s * p1 + 3.0 * u * s * s * p2 + s * s * s;
}

/// d/ds of `bezierAxis` — the axis slope, used by Newton-Raphson.
fn bezierAxisDeriv(p1: f32, p2: f32, s: f32) f32 {
    const u = 1.0 - s;
    return 3.0 * u * u * p1 + 6.0 * u * s * (p2 - p1) + 3.0 * s * s * (1.0 - p2);
}

/// Solve bezierX(s) = target_x for s in [0,1]. Newton-Raphson from a good seed,
/// falling back to bisection when the derivative is too small to step safely.
fn solveBezierX(x1: f32, x2: f32, target_x: f32) f32 {
    const newton_iters = 8;
    const min_slope: f32 = 1.0e-4;

    // Seed with the query itself — for well-behaved curves x ≈ s, so this converges
    // in a couple of iterations.
    var s = target_x;
    var i: usize = 0;
    while (i < newton_iters) : (i += 1) {
        const x = bezierAxis(x1, x2, s) - target_x;
        if (@abs(x) < 1.0e-6) return s;
        const d = bezierAxisDeriv(x1, x2, s);
        if (@abs(d) < min_slope) break; // slope too flat: hand off to bisection
        s -= x / d;
    }

    // Bisection fallback — guaranteed to converge since bezierX is monotonic in x
    // for any valid CSS timing function (control x's are conceptually in [0,1]).
    var lo: f32 = 0.0;
    var hi: f32 = 1.0;
    s = target_x;
    var j: usize = 0;
    while (j < 32) : (j += 1) {
        const x = bezierAxis(x1, x2, s);
        if (@abs(x - target_x) < 1.0e-6) return s;
        if (x < target_x) {
            lo = s;
        } else {
            hi = s;
        }
        s = (lo + hi) * 0.5;
    }
    return s;
}

// ---------------------------------------------------------------------------
// Cubic-bezier PRESETS — the common CSS / Material Design curves.
// ---------------------------------------------------------------------------

/// PLAIN DATA (A1): four control-point coordinates of a `cubic-bezier(x1,y1,x2,y2)`
/// timing function. Cheap to copy; guarded so the layout never drifts.
pub const BezierPreset = struct {
    x1: f32,
    y1: f32,
    x2: f32,
    y2: f32,

    comptime {
        // Four f32, no padding.
        assert(@sizeOf(BezierPreset) == 16);
    }
};

/// CSS `ease` — the default web transition curve.
pub const ease: BezierPreset = .{ .x1 = 0.25, .y1 = 0.1, .x2 = 0.25, .y2 = 1.0 };

/// CSS `ease-in` — slow start, linear-ish finish.
pub const ease_in: BezierPreset = .{ .x1 = 0.42, .y1 = 0.0, .x2 = 1.0, .y2 = 1.0 };

/// CSS `ease-out` — quick start, gentle finish.
pub const ease_out: BezierPreset = .{ .x1 = 0.0, .y1 = 0.0, .x2 = 0.58, .y2 = 1.0 };

/// CSS `ease-in-out` — symmetric slow-in / slow-out.
pub const ease_in_out: BezierPreset = .{ .x1 = 0.42, .y1 = 0.0, .x2 = 0.58, .y2 = 1.0 };

/// Material "standard" curve — the everyday move (enter + move on screen).
pub const standard: BezierPreset = .{ .x1 = 0.4, .y1 = 0.0, .x2 = 0.2, .y2 = 1.0 };

/// Material "decelerate" — an element entering the screen (fast in, eased stop).
pub const decelerate: BezierPreset = .{ .x1 = 0.0, .y1 = 0.0, .x2 = 0.2, .y2 = 1.0 };

/// Material "accelerate" — an element leaving the screen (eased start, fast out).
pub const accelerate: BezierPreset = .{ .x1 = 0.4, .y1 = 0.0, .x2 = 1.0, .y2 = 1.0 };

/// Evaluate a preset curve at progress `t`.
pub fn evalPreset(p: BezierPreset, t: f32) f32 {
    return cubicBezier(p.x1, p.y1, p.x2, p.y2, t);
}

// ---------------------------------------------------------------------------
// Tween — a fixed-duration timeline you advance by real elapsed time.
// ---------------------------------------------------------------------------

/// PLAIN DATA (A1): a running timeline. It carries only TIME — the from / to bounds
/// and the easing function are supplied at sample time, so one tiny record drives
/// any interpolation (colors, offsets, scalars) without growing. `duration` is in
/// the same unit as the `dt` handed to `step` (seconds, by convention).
pub const Tween = struct {
    elapsed: f32 = 0,
    duration: f32 = 0,

    comptime {
        // Two f32, no padding.
        assert(@sizeOf(Tween) == 8);
    }
};

/// Start (or restart) a tween that runs for `duration` seconds from t = 0.
pub fn start(duration: f32) Tween {
    return .{ .elapsed = 0, .duration = @max(duration, 0.0) };
}

/// Advance `elapsed` by real `dt` seconds, clamped so it never runs past `duration`.
/// Negative `dt` is ignored (time only moves forward).
pub fn step(w: *Tween, dt: f32) void {
    if (dt > 0.0) {
        w.elapsed = @min(w.elapsed + dt, w.duration);
    }
}

/// Normalized progress in [0, 1] — `elapsed / duration`. A zero-duration tween is
/// treated as already complete (returns 1), so it has no divide-by-zero path.
pub fn progress(w: Tween) f32 {
    if (w.duration <= 0.0) return 1.0;
    return clamp01(w.elapsed / w.duration);
}

/// The interpolated value at the current time: `lerp(from, to, easeFn(progress))`.
/// The host picks the curve by passing any `EaseFn` (`easeOutCubic`, `linear`, …)
/// or a preset via a small closure over `evalPreset`.
pub fn value(w: Tween, from: f32, to: f32, easeFn: EaseFn) f32 {
    return lerp(from, to, easeFn(progress(w)));
}

/// True once the tween has run its full duration.
pub fn done(w: Tween) bool {
    return w.elapsed >= w.duration;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const eps: f32 = 1.0e-4;

test "ease: lerp and clamp01" {
    try std.testing.expectApproxEqAbs(@as(f32, 5), lerp(0, 10, 0.5), eps);
    try std.testing.expectApproxEqAbs(@as(f32, 0), lerp(0, 10, 0), eps);
    try std.testing.expectApproxEqAbs(@as(f32, 10), lerp(0, 10, 1), eps);
    // lerp is not clamped by itself.
    try std.testing.expectApproxEqAbs(@as(f32, 20), lerp(0, 10, 2), eps);

    try std.testing.expectEqual(@as(f32, 0), clamp01(-0.5));
    try std.testing.expectEqual(@as(f32, 1), clamp01(1.5));
    try std.testing.expectEqual(@as(f32, 0.3), clamp01(0.3));
}

test "ease: inverseLerp and remap" {
    try std.testing.expectApproxEqAbs(@as(f32, 0.5), inverseLerp(0, 10, 5), eps);
    try std.testing.expectApproxEqAbs(@as(f32, 0.25), inverseLerp(4, 8, 5), eps);
    // Degenerate span is defined, not an error.
    try std.testing.expectEqual(@as(f32, 0), inverseLerp(3, 3, 3));

    // Remap 0..100 onto -1..1.
    try std.testing.expectApproxEqAbs(@as(f32, -1), remap(0, 100, -1, 1, 0), eps);
    try std.testing.expectApproxEqAbs(@as(f32, 0), remap(0, 100, -1, 1, 50), eps);
    try std.testing.expectApproxEqAbs(@as(f32, 1), remap(0, 100, -1, 1, 100), eps);
}

test "ease: every easing maps 0->0 and 1->1" {
    const fns = [_]EaseFn{
        linear,       easeInQuad,   easeOutQuad,  easeInOutQuad,
        easeInCubic,  easeOutCubic, easeInOutCubic, easeOutBack,
        easeOutElastic,
    };
    for (fns) |f| {
        try std.testing.expectApproxEqAbs(@as(f32, 0), f(0), eps);
        try std.testing.expectApproxEqAbs(@as(f32, 1), f(1), eps);
    }
}

test "ease: monotone easings stay within [0,1] on the interior" {
    // The overshoot easings (Back/Elastic) are excluded — they legitimately exceed
    // the range mid-flight; the monotone family must not.
    const fns = [_]EaseFn{
        linear,      easeInQuad,   easeOutQuad,    easeInOutQuad,
        easeInCubic, easeOutCubic, easeInOutCubic,
    };
    for (fns) |f| {
        var i: usize = 0;
        while (i <= 100) : (i += 1) {
            const t = @as(f32, @floatFromInt(i)) / 100.0;
            const y = f(t);
            try std.testing.expect(y >= -eps and y <= 1.0 + eps);
        }
    }
}

test "ease: easeInOutCubic is symmetric around 0.5" {
    // An in-out curve satisfies f(t) == 1 - f(1 - t).
    var i: usize = 0;
    while (i <= 100) : (i += 1) {
        const t = @as(f32, @floatFromInt(i)) / 100.0;
        try std.testing.expectApproxEqAbs(easeInOutCubic(t), 1.0 - easeInOutCubic(1.0 - t), 1.0e-3);
    }
    try std.testing.expectApproxEqAbs(@as(f32, 0.5), easeInOutCubic(0.5), eps);
}

test "ease: easeInOutQuad is symmetric around 0.5" {
    try std.testing.expectApproxEqAbs(@as(f32, 0.5), easeInOutQuad(0.5), eps);
    var i: usize = 0;
    while (i <= 100) : (i += 1) {
        const t = @as(f32, @floatFromInt(i)) / 100.0;
        try std.testing.expectApproxEqAbs(easeInOutQuad(t), 1.0 - easeInOutQuad(1.0 - t), 1.0e-3);
    }
}

test "ease: easeOutBack overshoots then returns to 1" {
    // Somewhere in the back half it must exceed 1 (the "pop"), and end exactly at 1.
    var overshot = false;
    var i: usize = 0;
    while (i <= 100) : (i += 1) {
        const t = @as(f32, @floatFromInt(i)) / 100.0;
        if (easeOutBack(t) > 1.0 + 1.0e-3) overshot = true;
    }
    try std.testing.expect(overshot);
    try std.testing.expectApproxEqAbs(@as(f32, 1), easeOutBack(1), eps);
}

test "ease: cubicBezier of the linear curve approximates t" {
    // cubic-bezier(0,0,1,1) is the identity timing function.
    var i: usize = 0;
    while (i <= 100) : (i += 1) {
        const t = @as(f32, @floatFromInt(i)) / 100.0;
        try std.testing.expectApproxEqAbs(t, cubicBezier(0, 0, 1, 1, t), 1.0e-3);
    }
}

test "ease: cubicBezier endpoints and monotonicity" {
    try std.testing.expectApproxEqAbs(@as(f32, 0), cubicBezier(0.42, 0, 0.58, 1, 0), eps);
    try std.testing.expectApproxEqAbs(@as(f32, 1), cubicBezier(0.42, 0, 0.58, 1, 1), eps);
    // ease-in-out is monotonically non-decreasing.
    var prev: f32 = 0;
    var i: usize = 0;
    while (i <= 100) : (i += 1) {
        const t = @as(f32, @floatFromInt(i)) / 100.0;
        const y = cubicBezier(0.42, 0, 0.58, 1, t);
        try std.testing.expect(y >= prev - 1.0e-3);
        prev = y;
    }
}

test "ease: evalPreset matches the raw curve; standard curve is well-formed" {
    // The helper just forwards the four control points.
    try std.testing.expectApproxEqAbs(
        cubicBezier(standard.x1, standard.y1, standard.x2, standard.y2, 0.5),
        evalPreset(standard, 0.5),
        eps,
    );
    // Decelerate leads ahead of linear early (fast in), accelerate lags (slow in).
    try std.testing.expect(evalPreset(decelerate, 0.25) > 0.25);
    try std.testing.expect(evalPreset(accelerate, 0.25) < 0.25);
}

test "ease: Tween reaches `to` at completion and reports done" {
    var w = start(1.0);
    try std.testing.expect(!done(w));
    try std.testing.expectApproxEqAbs(@as(f32, 0), progress(w), eps);
    try std.testing.expectApproxEqAbs(@as(f32, 0), value(w, 0, 100, linear), eps);

    // Advance halfway.
    step(&w, 0.5);
    try std.testing.expectApproxEqAbs(@as(f32, 0.5), progress(w), eps);
    try std.testing.expectApproxEqAbs(@as(f32, 50), value(w, 0, 100, linear), eps);
    try std.testing.expect(!done(w));

    // Overshoot the duration — elapsed clamps, progress pins to 1, done is true.
    step(&w, 5.0);
    try std.testing.expect(done(w));
    try std.testing.expectApproxEqAbs(@as(f32, 1), progress(w), eps);
    try std.testing.expectApproxEqAbs(@as(f32, 100), value(w, 0, 100, linear), eps);
    try std.testing.expectApproxEqAbs(@as(f32, 100), value(w, 0, 100, easeOutCubic), eps);
}

test "ease: Tween ignores negative dt and handles zero duration" {
    var w = start(2.0);
    step(&w, -1.0); // time only moves forward
    try std.testing.expectApproxEqAbs(@as(f32, 0), w.elapsed, eps);

    // A zero-duration tween is already complete — no divide by zero.
    var z = start(0.0);
    try std.testing.expect(done(z));
    try std.testing.expectApproxEqAbs(@as(f32, 1), progress(z), eps);
    try std.testing.expectApproxEqAbs(@as(f32, 7), value(z, 3, 7, linear), eps);
    step(&z, 0.1);
    try std.testing.expect(done(z));
}
