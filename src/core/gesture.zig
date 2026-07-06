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

//! B1 classification: CORE (pure). The gesture feel primitives — velocity
//! estimation over a finger's recent samples, momentum projection, and the
//! rubber-band boundary curve. Spec: GESTURE_SYSTEM_ROADMAP.md §2–§3.
//!
//! The prime directive (roadmap §0): a gesture is a continuous function of the
//! finger's position and velocity RIGHT NOW, not an event that fires on
//! completion. This module supplies the three pure computations that doctrine
//! needs and the shell's pump cannot be trusted to inline ad hoc:
//!
//!   1. VELOCITY — a finite difference over a short ring of timestamped
//!      samples (§4), so release velocity is the finger's real speed, not a
//!      single-frame delta.
//!   2. PROJECTION (§2.2) — where the content WOULD come to rest if it
//!      decelerated naturally from that velocity. Settle decisions (open the
//!      drawer? close it?) test the projected end, never the raw release
//!      position — a small flick still sends a panel all the way, because the
//!      interface predicted the intent.
//!   3. RUBBER-BAND (§3) — resistance past a hard limit that grows nonlinearly
//!      and springs back on release. The absence of hard walls is most of what
//!      "polished" feels like.
//!
//! The settle spring itself is NOT here: `core/spring.zig` already owns damped
//! harmonic motion (position + velocity state, interruption for free), so this
//! module deliberately deviates from the roadmap's §6 own-spring listing and
//! reuses it (F4 — the cut point already emerged; a second spring would be the
//! near-copy that drifts). Callers seed `spring.stepScalar` with the release
//! velocity from here — that hand-off IS roadmap §2.3.
//!
//! PURE (B2/B3/B4): no clock, no RNG, no I/O, no allocation. Timestamps are
//! shell-supplied milliseconds; the core only ever subtracts them.

const std = @import("std");
const assert = std.debug.assert;

// ─────────────────────────────────────────────────────────────────────────────
// Feel parameters (roadmap §10: named constants, tuned in one place, never
// inline in logic).
// ─────────────────────────────────────────────────────────────────────────────

/// Per-millisecond velocity retention of a naturally decelerating fling —
/// the normal scroll-view deceleration rate. Feeds the projection's closed
/// form; also the friction a shell applies if it decays a fling per-ms.
pub const decel_rate: f32 = 0.998;

/// The projection horizon in ms-equivalents: sum of the geometric decay,
/// r/(1-r). At r = 0.998 this is 499 — a fling coasts about half a second of
/// its release velocity into distance.
pub const projection_ms: f32 = decel_rate / (1.0 - decel_rate);

/// How far back the velocity estimate looks. Samples older than this are
/// stale finger history, not current intent.
pub const velocity_window_ms: u32 = 100;

/// Rubber-band firmness: 0.55 is the classic scroll-view coefficient. Lower
/// is stiffer (less give past the edge).
pub const rubber_coeff: f32 = 0.55;

/// Below this speed a release is a placement, not a flick: the settle decision
/// falls back to position alone. In units-per-second of whatever axis the
/// caller measures (for a 0..1 panel fraction: 5% of the panel per second).
pub const flick_min_per_s: f32 = 0.05;

// ─────────────────────────────────────────────────────────────────────────────
// Samples
// ─────────────────────────────────────────────────────────────────────────────

/// PLAIN DATA (A1). One timestamped finger sample — the value that crosses the
/// shell→core boundary (B5). `t_ms` is a shell-stamped monotonic millisecond
/// count; only differences are ever taken, so 49-day u32 wraparound is
/// harmless (wrapping subtraction below).
pub const PointerSample = struct {
    x: f32,
    y: f32,
    t_ms: u32,

    comptime {
        // Budget: 4 + 4 + 4 = 12, no padding. Raising this requires a
        // recorded justification per A7.1.
        assert(@sizeOf(PointerSample) == 12);
    }
};

/// Ring capacity. At 120 Hz input with batched same-frame delivery, ~100 ms of
/// history is well under 32 samples; the oldest are overwritten silently.
pub const ring_cap = 32;

/// A fixed ring of recent samples for ONE pointer. Struct-of-arrays inside
/// (A3): the velocity sweep reads the t column first and touches x/y only at
/// the two ends it selects. Inline fixed arrays — never grows, never
/// allocates (C2); a phone reports a handful of pointers at most, and the
/// pump owns one ring per gesture surface.
pub const SampleRing = struct {
    xs: [ring_cap]f32,
    ys: [ring_cap]f32,
    ts: [ring_cap]u32,
    head: u8, // next write slot
    len: u8, // filled slots, saturates at ring_cap

    pub const empty: SampleRing = .{
        .xs = @splat(0),
        .ys = @splat(0),
        .ts = @splat(0),
        .head = 0,
        .len = 0,
    };

    comptime {
        // Budget: 3 columns * 32 * 4 = 384, + 2 u8, padded to 388 (align 4).
        // One ring per gesture surface on the frame path — hot, guarded.
        assert(@sizeOf(SampleRing) == 388);
    }
};

/// Push one sample, overwriting the oldest once full. Free function over plain
/// data (A1); never allocates.
pub fn push(r: *SampleRing, s: PointerSample) void {
    r.xs[r.head] = s.x;
    r.ys[r.head] = s.y;
    r.ts[r.head] = s.t_ms;
    r.head = @intCast((@as(u32, r.head) + 1) % ring_cap);
    if (r.len < ring_cap) r.len += 1;
}

/// Forget the gesture's history — call on touch-down so a new press never
/// inherits the previous fling's tail.
pub fn clear(r: *SampleRing) void {
    r.head = 0;
    r.len = 0;
}

/// A 2-D velocity in px/s. A7.2: cold struct, size guard waived — a transient
/// return value, never stored in a collection.
pub const Velocity = struct {
    x: f32,
    y: f32,
};

/// Estimate the finger's velocity from the ring: the finite difference between
/// the newest sample and the oldest sample still inside `velocity_window_ms`
/// of it. Robust to batched delivery (several samples stamped the same ms —
/// the window spans frames, so the denominator is real time) and to a
/// press-and-hold before release (old motion ages out of the window and the
/// estimate decays to zero, which is the correct reading of "the finger
/// stopped"). Returns zero when there is no story to tell (fewer than two
/// samples, or zero elapsed time).
pub fn velocity(r: *const SampleRing) Velocity {
    if (r.len < 2) return .{ .x = 0, .y = 0 };
    const newest_i = (@as(u32, r.head) + ring_cap - 1) % ring_cap;
    const t_new = r.ts[newest_i];
    // Walk backward from the newest, keeping the oldest sample within the
    // window. Wrapping subtraction: only differences are meaningful.
    var oldest_i = newest_i;
    var k: u32 = 1;
    while (k < r.len) : (k += 1) {
        const i = (newest_i + ring_cap - k) % ring_cap;
        if (t_new -% r.ts[i] > velocity_window_ms) break;
        oldest_i = i;
    }
    const dt_ms = t_new -% r.ts[oldest_i];
    if (dt_ms == 0) return .{ .x = 0, .y = 0 };
    const scale = 1000.0 / @as(f32, @floatFromInt(dt_ms));
    return .{
        .x = (r.xs[newest_i] - r.xs[oldest_i]) * scale,
        .y = (r.ys[newest_i] - r.ys[oldest_i]) * scale,
    };
}

// ─────────────────────────────────────────────────────────────────────────────
// Projection (§2.2)
// ─────────────────────────────────────────────────────────────────────────────

/// Where a value coasting at `vel_per_s` from `pos` would come to rest under
/// natural deceleration — the closed form of the geometric decay, no
/// simulation. Feed THIS into threshold tests, never the raw release
/// position: it is why a small flick still sends a panel all the way.
pub fn projectEnd(pos: f32, vel_per_s: f32) f32 {
    return pos + (vel_per_s / 1000.0) * projection_ms;
}

/// The settle decision for a 0..1 surface fraction (drawer, sheet): open when
/// the PROJECTED end passes halfway. A release slower than `flick_min_per_s`
/// carries no directional intent, so it degrades to the plain halfway rule on
/// position — a slow placement means exactly where the finger left it.
pub fn settleOpen(t: f32, vel_t_per_s: f32) bool {
    const v = if (@abs(vel_t_per_s) < flick_min_per_s) 0.0 else vel_t_per_s;
    return projectEnd(t, v) >= 0.5;
}

// ─────────────────────────────────────────────────────────────────────────────
// Rubber-band (§3)
// ─────────────────────────────────────────────────────────────────────────────

/// Map a raw overshoot past a hard limit to the displayed give: the classic
/// asymptotic curve d·(1 − 1/(|x|·c/d + 1)), sign-preserving. Zero at zero,
/// monotone, and bounded by `dim` (the view dimension) — the finger can pull
/// forever and the content approaches but never passes one screen of give.
pub fn rubberBand(offset: f32, dim: f32) f32 {
    if (offset == 0 or dim <= 0) return 0;
    const mag = @abs(offset);
    const banded = (1.0 - 1.0 / (mag * rubber_coeff / dim + 1.0)) * dim;
    return if (offset < 0) -banded else banded;
}

/// The band's inverse: recover the raw finger travel that displays as
/// `banded` give. This is what makes a mid-bounce touch fully interruptible
/// (§2.4) — the shell hands the springing offset back to the drag as raw
/// travel, and the finger resumes the same stretch with no snap. `banded`
/// must be inside the curve's range (|banded| < dim); the caller feeds back a
/// value the forward map produced, so that holds by construction.
pub fn rubberBandInv(banded: f32, dim: f32) f32 {
    if (banded == 0 or dim <= 0) return 0;
    const mag = @abs(banded);
    assert(mag < dim);
    const raw = (dim / rubber_coeff) * (mag / (dim - mag));
    return if (banded < 0) -raw else raw;
}

/// The band's local slope at raw travel `offset` — the factor that converts a
/// finger velocity into displayed-give velocity at the moment of release, so
/// the spring-back starts at the speed the stretch was visibly moving (§2.3).
pub fn rubberBandSlope(offset: f32, dim: f32) f32 {
    if (dim <= 0) return 0;
    const u = @abs(offset) * rubber_coeff / dim + 1.0;
    return rubber_coeff / (u * u);
}

// ─────────────────────────────────────────────────────────────────────────────
// Tests (C6 — pure math, no allocation to leak; the harness allocator still
// arms the leak gate for the whole block)
// ─────────────────────────────────────────────────────────────────────────────

const testing = std.testing;

test "ring: push wraps and saturates len" {
    var r: SampleRing = .empty;
    var i: u32 = 0;
    while (i < ring_cap + 5) : (i += 1) {
        push(&r, .{ .x = @floatFromInt(i), .y = 0, .t_ms = i });
    }
    try testing.expectEqual(@as(u8, ring_cap), r.len);
    // The newest sample is the last pushed; the oldest 5 were overwritten.
    const newest_i = (@as(u32, r.head) + ring_cap - 1) % ring_cap;
    try testing.expectEqual(@as(u32, ring_cap + 4), r.ts[newest_i]);
}

test "velocity: constant-speed stream reads back its speed" {
    var r: SampleRing = .empty;
    // 800 px/s: 8 px every 10 ms.
    var i: u32 = 0;
    while (i < 12) : (i += 1) {
        push(&r, .{ .x = @floatFromInt(8 * i), .y = 0, .t_ms = 10 * i });
    }
    const v = velocity(&r);
    try testing.expectApproxEqRel(@as(f32, 800.0), v.x, 0.01);
    try testing.expectApproxEqAbs(@as(f32, 0.0), v.y, 0.001);
}

test "velocity: batched same-ms samples do not divide by zero" {
    var r: SampleRing = .empty;
    // Two frames of batched delivery: 3 samples at t=0, 3 at t=16.
    for ([_]f32{ 0, 2, 4 }) |x| push(&r, .{ .x = x, .y = 0, .t_ms = 0 });
    for ([_]f32{ 10, 12, 14 }) |x| push(&r, .{ .x = x, .y = 0, .t_ms = 16 });
    const v = velocity(&r);
    // 14 px over 16 ms = 875 px/s.
    try testing.expectApproxEqRel(@as(f32, 875.0), v.x, 0.01);

    // All samples in the same ms: no story, zero velocity, no NaN.
    var same: SampleRing = .empty;
    for ([_]f32{ 0, 5, 9 }) |x| push(&same, .{ .x = x, .y = 0, .t_ms = 7 });
    const vs = velocity(&same);
    try testing.expectEqual(@as(f32, 0.0), vs.x);
}

test "velocity: a hold before release decays the estimate to zero" {
    var r: SampleRing = .empty;
    // Fast motion, then the finger parks well past the window.
    push(&r, .{ .x = 0, .y = 0, .t_ms = 0 });
    push(&r, .{ .x = 100, .y = 0, .t_ms = 20 });
    push(&r, .{ .x = 100, .y = 0, .t_ms = 200 });
    push(&r, .{ .x = 100, .y = 0, .t_ms = 240 });
    const v = velocity(&r);
    // Only the parked samples are inside the window: zero.
    try testing.expectEqual(@as(f32, 0.0), v.x);
}

test "projection: closed form matches the simulated per-ms decay" {
    // Simulate the discrete fling the closed form summarizes: each ms the
    // velocity decays THEN moves (matching r/(1-r)).
    var pos: f32 = 0;
    var v: f32 = 800.0 / 1000.0; // px per ms
    var i: u32 = 0;
    while (i < 6000) : (i += 1) {
        v *= decel_rate;
        pos += v;
    }
    try testing.expectApproxEqRel(projectEnd(0, 800), pos, 0.01);
    // Zero velocity projects nowhere.
    try testing.expectEqual(@as(f32, 0.25), projectEnd(0.25, 0));
}

test "settle: a flick's projection beats the halfway rule both ways" {
    // Barely open, flicked hard toward open: the old halfway rule said close;
    // projection says open.
    try testing.expect(settleOpen(0.2, 1.0));
    // Mostly open, flicked hard toward closed: halfway said open; projection
    // says close.
    try testing.expect(!settleOpen(0.8, -1.0));
    // A slow placement (sub-flick speed) falls back to position alone.
    try testing.expect(settleOpen(0.6, 0.01));
    try testing.expect(!settleOpen(0.4, 0.01));
}

test "rubber-band: zero at zero, monotone, bounded, sign-symmetric" {
    const dim: f32 = 800;
    try testing.expectEqual(@as(f32, 0.0), rubberBand(0, dim));
    var prev: f32 = 0;
    var x: f32 = 10;
    while (x < 10_000) : (x += 100) {
        const b = rubberBand(x, dim);
        try testing.expect(b > prev); // monotone
        try testing.expect(b < dim); // bounded by the view dimension
        try testing.expectEqual(-b, rubberBand(-x, dim)); // sign-symmetric
        prev = b;
    }
    // The band's initial slope is rubber_coeff — a small pull gives ~55% of
    // the drag, tightening asymptotically from there.
    try testing.expectApproxEqRel(rubber_coeff * 10.0, rubberBand(10, dim), 0.01);
}

test "rubber-band inverse round-trips and the slope matches the curve" {
    const dim: f32 = 800;
    var x: f32 = -3000;
    while (x <= 3000) : (x += 250) {
        try testing.expectApproxEqAbs(x, rubberBandInv(rubberBand(x, dim), dim), 0.1);
    }
    // Slope ≈ finite difference of the forward map (f32: keep h coarse enough
    // that the difference is well above the mantissa floor).
    const h: f32 = 1.0;
    const fd = (rubberBand(500 + h, dim) - rubberBand(500 - h, dim)) / (2 * h);
    try testing.expectApproxEqRel(fd, rubberBandSlope(500, dim), 0.005);
}
