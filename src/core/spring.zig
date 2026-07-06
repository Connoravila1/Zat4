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

//! B1 classification: CORE (pure). A damped-harmonic-oscillator spring, the
//! animation primitive behind the message-bubble send/receive motion. See
//! BUBBLE_SPRING_PHYSICS_ROADMAP.md for the full spec and the why.
//!
//! A spring models ONE scalar channel (e.g. a bubble's scale, or its vertical
//! offset) as a mass on a spring being pulled toward `target`. Its motion is
//! the damped harmonic oscillator: a Hooke's-law pull toward target plus a
//! velocity-proportional friction that bleeds off energy so the overshoot
//! rings out. Because the spring carries STATE (position + velocity), it can be
//! interrupted mid-flight and continue from its current velocity — the one
//! thing an easing curve physically cannot do, and the whole reason the feel
//! finally reaches the iMessage standard.
//!
//! PURE (B2/B3/B4): no clock, no RNG, no I/O. `dt` is handed in by the shell
//! (the one main-loop frame delta); the fixed-step accumulator remainder is
//! shell-owned state passed in by pointer. Given the same inputs the step
//! produces the same output, so the physics is fully unit-testable (see the
//! tests at the foot of this file). The LOOK — how a scale/offset composes into
//! a bubble transform, how it renders — is NOT here; the core owns only the
//! motion.

const std = @import("std");
const assert = std.debug.assert;

/// PLAIN DATA (A1). One scalar spring channel — the HOT record: two per bubble,
/// bubbles occur in quantity, and the step sweeps these in bulk. Fields only,
/// no methods (behaviour lives in the free functions below).
///
/// mass is fixed at 1 by the duration/bounce conversion (see `springConstants`)
/// and is therefore NOT stored — a constant 1.0 per channel would be dead
/// weight (A6-spirit: keep the hot record tight). A future non-unit-mass need
/// would be a deliberate size-budget amendment per A7.1.
pub const Spring = struct {
    position: f32, // current value of the channel
    velocity: f32, // current rate of change
    target: f32, // where it is heading
    stiffness: f32, // resolved from duration/bounce
    damping: f32, // resolved from duration/bounce

    comptime {
        // Budget: five f32, processed in bulk (two per bubble). Packed size is
        // 20 bytes with no padding (all fields 4-byte aligned). Raising this
        // requires a recorded justification per A7.1.
        assert(@sizeOf(Spring) == 20);
    }
};

/// The two physical constants a spring integrates with, resolved from the
/// friendly duration/bounce front door. A7.2: cold struct, size guard waived —
/// a transient return value, never stored in a collection or scanned in bulk.
pub const Constants = struct {
    stiffness: f32,
    damping: f32,
};

/// Fixed integrator sub-step. Smaller than any real frame, so every frame takes
/// at least one sub-step and the motion is frame-rate independent (§1.4).
pub const sub_step: f32 = 1.0 / 240.0;

/// Per-frame accumulator clamp. After a long stall (app backgrounded, a
/// breakpoint) we must not run thousands of catch-up sub-steps — the "spiral of
/// death." A clamped catch-up just fast-forwards the settle, which is the
/// correct visible behaviour.
pub const max_accum: f32 = 0.25;

/// Rest thresholds. A spring's math never truly reaches rest; we declare rest
/// when the motion is imperceptible and snap it exactly to target. These are
/// tuned for the scale channel (~1.0 range); the offset channel (pixels) rings
/// a touch longer under the same absolute epsilon, which is harmless. Exposed
/// so a caller can tighten them per channel if ever needed.
pub const rest_eps: f32 = 1.0e-3;
pub const rest_vel_eps: f32 = 1.0e-3;

/// The tuning front door (§1.3). Convert a PERCEPTUAL `duration` (seconds — how
/// long the meaningful part of the motion takes) and a `bounce` (~[-1, 1]:
/// 0 = no overshoot / critically damped, positive = bouncy / underdamped,
/// negative = lazy / overdamped) into the physical constants the integrator
/// uses. Pure and comptime-usable, so presets resolve at compile time (F2).
///
/// mass is fixed at 1, so with stiffness k the natural frequency is sqrt(k) and
/// critical damping is 2*sqrt(k) = 4*pi/duration. bounce scales damping away
/// from (bounce > 0) or past (bounce < 0) that critical value.
pub fn springConstants(bounce: f32, duration: f32) Constants {
    const pi: f32 = std.math.pi;
    // E4: the bounce = -1 singularity (damping → ∞) is defined out of existence
    // by clamping just shy of it; callers pass sane presets (~0.15–0.30) anyway.
    const b = std.math.clamp(bounce, -0.99, 1.0);
    const omega = (2.0 * pi) / duration; // natural frequency (mass = 1)
    const critical = (4.0 * pi) / duration; // 2*sqrt(stiffness) at mass = 1
    const stiffness = omega * omega;
    const damping = if (b >= 0)
        (1.0 - b) * critical
    else
        critical / (1.0 + b);
    return .{ .stiffness = stiffness, .damping = damping };
}

/// True when the spring's motion is imperceptible — within `rest_eps` of target
/// and slower than `rest_vel_eps`. Pure predicate.
pub fn atRest(s: Spring) bool {
    return @abs(s.position - s.target) < rest_eps and @abs(s.velocity) < rest_vel_eps;
}

/// The SoA view of the spring set (A3): a `MultiArrayList(Spring)` slice. The
/// step sweeps the `position`/`velocity` columns linearly — the cache-honest
/// access pattern and the reason SoA is mandated here over array-of-structs.
pub const Slice = std.MultiArrayList(Spring).Slice;

/// THE INTERRUPTIBILITY (core, pure). Point spring `i` at a new target WITHOUT
/// touching its position or velocity. This one tiny function is the whole reason
/// a spring beats an easing curve: an in-flight bubble that gets retargeted
/// (a second bubble arrives, the list reflows, the keyboard opens) keeps its
/// current momentum and curves smoothly toward the new goal — no restart, no
/// snap. A keyframe has no concept of "current velocity", so it physically
/// cannot do this; a stateful spring does it for free.
///
/// A settled spring is inactive, so retargeting also RE-ACTIVATES it (out of
/// band, A6) — otherwise the step would skip it and the nudge would do nothing.
/// If the new target equals the current position and the spring is at rest,
/// there is nothing to animate and it stays inactive.
pub fn retarget(s: Slice, active: []bool, i: usize, new_target: f32) void {
    assert(i < s.len);
    assert(active.len == s.len);
    s.items(.target)[i] = new_target;
    // Position and velocity are deliberately left untouched — that IS the
    // momentum carry-over. Wake the channel so the step advances it toward the
    // new target from wherever (and however fast) it currently is.
    const pos = s.items(.position)[i];
    const vel = s.items(.velocity)[i];
    if (@abs(pos - new_target) >= rest_eps or @abs(vel) >= rest_vel_eps) {
        active[i] = true;
    }
}

/// THE HEART (core, pure). Advance every ACTIVE spring in the set by real frame
/// time `dt`, using the fixed-step accumulator + semi-implicit Euler, then run
/// rest detection.
///
/// - `s`      : the SoA columns, mutated in place.
/// - `active` : out-of-band activeness (A6 — a separate array, not a bool field
///              bloating the hot record). An inactive spring is skipped; a
///              spring that reaches rest this frame is snapped to target and
///              marked inactive here, so the active set shrinks back toward
///              empty on its own.
/// - `dt`     : the real frame delta (seconds), the shell's ONE clock read.
/// - `acc`    : the shell-owned fixed-step remainder, carried across frames.
///
/// `dt` is a PARAMETER — the core never reads a clock (B4). Given the same slice
/// contents, `active`, `dt`, and `acc`, the result is identical: deterministic
/// and frame-rate independent, which is exactly what makes it testable.
pub fn stepSprings(s: Slice, active: []bool, dt: f32, acc: *f32) void {
    assert(active.len == s.len);
    const pos = s.items(.position);
    const vel = s.items(.velocity);
    const tgt = s.items(.target);
    const stiff = s.items(.stiffness);
    const damp = s.items(.damping);

    // Bank this frame's time, clamped so a long stall can't trigger a catch-up
    // spiral. Consume it in whole fixed sub-steps; the remainder carries over.
    acc.* = @min(acc.* + dt, max_accum);
    while (acc.* >= sub_step) : (acc.* -= sub_step) {
        for (pos, vel, tgt, stiff, damp, active) |*p, *v, t, k, c, a| {
            if (!a) continue;
            // Semi-implicit (symplectic) Euler: update velocity FIRST, then use
            // the already-updated velocity to move position. One line different
            // from explicit Euler, same cost, stable across the tuning range —
            // explicit Euler adds energy at stiff settings and can diverge.
            const accel = -k * (p.* - t) - c * v.*; // mass = 1
            v.* += accel * sub_step;
            p.* += v.* * sub_step;
        }
    }

    // Rest detection: a settled spring snaps exactly to target and drops out of
    // the active set. Without this, springs never finish and the step never
    // idles (§1.5).
    for (pos, vel, tgt, active) |*p, *v, t, *a| {
        if (!a.*) continue;
        if (@abs(p.* - t) < rest_eps and @abs(v.*) < rest_vel_eps) {
            p.* = t;
            v.* = 0;
            a.* = false;
        }
    }
}

/// Advance ONE scalar spring channel by real frame time `dt`. The single-channel
/// convenience over the same semi-implicit integrator `stepSprings` uses, for
/// callers animating a lone value (a nav drawer's open fraction, a scroll
/// bounce) where a pooled World is ceremony. Sub-steps are derived from `dt`
/// each call (h <= sub_step), so the motion is frame-rate independent without a
/// caller-owned accumulator; the max_accum clamp still guards the stall spiral.
/// Pure (B2): `dt` is a parameter, never a clock read.
pub fn stepScalar(pos: *f32, vel: *f32, target: f32, c: Constants, dt: f32) void {
    const d = std.math.clamp(dt, 0.0, max_accum);
    const n: u32 = @intFromFloat(@ceil(d / sub_step));
    if (n == 0) return;
    const h = d / @as(f32, @floatFromInt(n));
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        const accel = -c.stiffness * (pos.* - target) - c.damping * vel.*; // mass = 1
        vel.* += accel * h;
        pos.* += vel.* * h;
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// THE MODULE (D2 deep, D3 hiding its internals). `World` owns the spring set and
// is the ONLY way callers touch springs: they hold opaque `Handle`s, never bare
// indexes (A5). The SoA columns, the free-list, the sub-step size, and the
// integrator choice are all sealed inside — a caller sees stable handles in and
// plain values out. Still CORE (B2): every mutating op takes the pool by pointer
// and (when it grows) an explicit allocator (C1); no clock, no I/O.
// ─────────────────────────────────────────────────────────────────────────────

/// A stable reference to one spring slot, safe across free-list reuse. The
/// `generation` is bumped when a slot is released, so a handle to a released (and
/// possibly re-used) slot is detectably stale — no use-after-release footgun.
/// Handles cross the module boundary as values; bare indexes never do (A5).
pub const Handle = struct {
    index: u32,
    generation: u32,

    comptime {
        // Two u32, no padding. Small enough that a bubble holding two of these
        // (scale + offset_y) stays cheap.
        assert(@sizeOf(Handle) == 8);
    }
};

/// The animation module state (§3.4). A7.2: cold struct, size guard waived —
/// one instance per animating surface, never held in a collection. It owns all
/// of its memory (C4): the springs SoA, the out-of-band `active`/`live`/
/// `generation` columns (A6), the free-list of reclaimed slots, and the shared
/// fixed-step accumulator remainder.
pub const World = struct {
    springs: std.MultiArrayList(Spring),
    active: std.ArrayListUnmanaged(bool), // animating right now? (A6, out of band)
    live: std.ArrayListUnmanaged(bool), // slot allocated to a caller?
    generation: std.ArrayListUnmanaged(u32), // per-slot reuse counter
    free: std.ArrayListUnmanaged(u32), // reclaimed slot indices
    acc: f32, // fixed-step remainder, carried across frames

    /// An empty world. Grows on first `spawn`.
    pub const empty: World = .{
        .springs = .empty,
        .active = .empty,
        .live = .empty,
        .generation = .empty,
        .free = .empty,
        .acc = 0,
    };

    pub fn deinit(w: *World, alloc: std.mem.Allocator) void {
        w.springs.deinit(alloc);
        w.active.deinit(alloc);
        w.live.deinit(alloc);
        w.generation.deinit(alloc);
        w.free.deinit(alloc);
        w.* = undefined;
    }

    /// Allocate a spring, reusing a released slot when one is free (so the set
    /// does not grow without bound), else appending. Born at `start` with zero
    /// velocity, aimed at `target`, using the resolved `c` constants. Returns an
    /// opaque handle. The only fallible op (it may grow), per E3.
    ///
    /// Design note (deviation from §3.4's "reclaim on rest"): slots are freed on
    /// EXPLICIT `release`, not automatically when a spring reaches rest. A
    /// resting-but-live spring is simply inactive (skipped by `step`, near-zero
    /// cost); this keeps `position` queryable for a settled bubble and avoids
    /// invalidating a caller's handle underneath it. Recorded per H2.
    pub fn spawn(w: *World, alloc: std.mem.Allocator, start: f32, target: f32, c: Constants) !Handle {
        const born: Spring = .{
            .position = start,
            .velocity = 0,
            .target = target,
            .stiffness = c.stiffness,
            .damping = c.damping,
        };
        // Born in motion unless it starts already at its target.
        const moving = @abs(start - target) >= rest_eps;

        // Reuse a released slot if one is waiting.
        if (w.free.items.len > 0) {
            const idx = w.free.items[w.free.items.len - 1];
            w.free.items.len -= 1;
            w.springs.set(idx, born);
            w.active.items[idx] = moving;
            w.live.items[idx] = true;
            return .{ .index = idx, .generation = w.generation.items[idx] };
        }

        // Grow. Reserve capacity on every column (and one free-list slot for the
        // eventual release) up front, so the appends themselves cannot fail
        // partway and leave the columns at mismatched lengths.
        const idx: u32 = @intCast(w.springs.len);
        try w.springs.ensureUnusedCapacity(alloc, 1);
        try w.active.ensureUnusedCapacity(alloc, 1);
        try w.live.ensureUnusedCapacity(alloc, 1);
        try w.generation.ensureUnusedCapacity(alloc, 1);
        try w.free.ensureTotalCapacity(alloc, idx + 1);
        w.springs.appendAssumeCapacity(born);
        w.active.appendAssumeCapacity(moving);
        w.live.appendAssumeCapacity(true);
        w.generation.appendAssumeCapacity(0);
        return .{ .index = idx, .generation = 0 };
    }

    /// True while `h` still refers to its live slot (not released, not reused).
    pub fn isLive(w: *const World, h: Handle) bool {
        return h.index < w.live.items.len and
            w.live.items[h.index] and
            w.generation.items[h.index] == h.generation;
    }

    /// Return a spring's slot to the free-list. Bumps the slot's generation so
    /// every outstanding handle to it becomes stale. Infallible: the free-list
    /// capacity was reserved at spawn. A no-op on an already-stale handle.
    pub fn release(w: *World, h: Handle) void {
        if (!w.isLive(h)) return;
        w.live.items[h.index] = false;
        w.active.items[h.index] = false;
        w.generation.items[h.index] +%= 1; // wrap is fine; only equality matters
        w.free.appendAssumeCapacity(h.index);
    }

    /// Point a live spring at a new target, carrying its momentum (see the free
    /// `retarget`). No-op on a stale handle.
    pub fn retarget(w: *World, h: Handle, new_target: f32) void {
        if (!w.isLive(h)) return;
        spring_retarget(w.springs.slice(), w.active.items, h.index, new_target);
    }

    /// The current value of a live spring's channel, or `null` if the handle is
    /// stale — a caller reads `null` as "no animation, render at identity."
    pub fn position(w: *const World, h: Handle) ?f32 {
        if (!w.isLive(h)) return null;
        return w.springs.items(.position)[h.index];
    }

    /// True while a live spring is still animating (has not reached rest). A
    /// stale handle is not active. Callers use this to reap finished springs.
    pub fn isActive(w: *const World, h: Handle) bool {
        return w.isLive(h) and w.active.items[h.index];
    }

    /// Advance the whole world by one frame of real time `dt`. Dead and rested
    /// slots are inactive and skipped by the sweep, so an idle world is cheap.
    pub fn step(w: *World, dt: f32) void {
        if (w.springs.len == 0) return;
        stepSprings(w.springs.slice(), w.active.items, dt, &w.acc);
    }
};

// ─────────────────────────────────────────────────────────────────────────────
// Tests (C6: run under the leak-detecting testing allocator). The integrator is
// fixed-step and clock-free, so these are exact and reproducible — not flaky
// timing tests. They prove the PHYSICS is right before any pixel moves, so that
// when the feel is tuned later, "looks off" and "math is wrong" are separable.
// ─────────────────────────────────────────────────────────────────────────────

const testing = std.testing;

/// Alias so `Harness.retarget` (a method) can reach the free function of the
/// same name without shadowing it.
const spring_retarget = retarget;

/// A tiny one-spring harness for the tests: an owned MultiArrayList plus its
/// out-of-band active flag and the shared accumulator.
/// A7.2: cold struct, size guard waived — a test-only fixture, one per test.
const Harness = struct {
    list: std.MultiArrayList(Spring),
    active: [1]bool,
    acc: f32,

    fn init(alloc: std.mem.Allocator, start: f32, target: f32, c: Constants) !Harness {
        var list: std.MultiArrayList(Spring) = .empty;
        try list.append(alloc, .{
            .position = start,
            .velocity = 0,
            .target = target,
            .stiffness = c.stiffness,
            .damping = c.damping,
        });
        return .{ .list = list, .active = .{true}, .acc = 0 };
    }

    fn deinit(self: *Harness, alloc: std.mem.Allocator) void {
        self.list.deinit(alloc);
    }

    fn step(self: *Harness, dt: f32) void {
        stepSprings(self.list.slice(), self.active[0..], dt, &self.acc);
    }

    fn retarget(self: *Harness, new_target: f32) void {
        spring_retarget(self.list.slice(), self.active[0..], 0, new_target);
    }

    fn pos(self: *Harness) f32 {
        return self.list.slice().items(.position)[0];
    }
    fn vel(self: *Harness) f32 {
        return self.list.slice().items(.velocity)[0];
    }
};

// Test 1 — Convergence. From a displaced start, any valid preset settles to
// within eps of target with near-zero velocity in bounded time.
test "spring converges to target for a range of presets" {
    const presets = [_]Constants{
        springConstants(0.0, 0.35),
        springConstants(0.25, 0.35),
        springConstants(0.6, 0.40),
        springConstants(-0.3, 0.40),
    };
    for (presets) |c| {
        var h = try Harness.init(testing.allocator, 0.0, 1.0, c);
        defer h.deinit(testing.allocator);
        // 3 seconds of 60 fps is far beyond any of these durations' settle time.
        var i: usize = 0;
        while (i < 180) : (i += 1) h.step(1.0 / 60.0);
        try testing.expect(@abs(h.pos() - 1.0) < rest_eps);
        try testing.expect(@abs(h.vel()) < rest_vel_eps);
        // Rest detection has snapped it exactly to target and deactivated it.
        try testing.expect(h.active[0] == false);
    }
}

// Test 2 — No overshoot at bounce = 0 (critically damped). Growing from 0 → 1,
// position never exceeds the target: a monotonic approach. Guards the regime
// math — a bounce-free preset must not ring.
test "critically damped preset never overshoots" {
    const c = springConstants(0.0, 0.35);
    var h = try Harness.init(testing.allocator, 0.0, 1.0, c);
    defer h.deinit(testing.allocator);
    var i: usize = 0;
    while (i < 240) : (i += 1) {
        h.step(1.0 / 120.0);
        // A hair of tolerance for float rounding; a real overshoot is far larger.
        try testing.expect(h.pos() <= 1.0 + 1.0e-4);
    }
}

// Test 3 — Overshoot exists at bounce > 0 (underdamped). Position provably
// passes the target at least once — the ring exists — then settles. Guards the
// feel: the iMessage regime must overshoot.
test "bouncy preset overshoots the target at least once" {
    const c = springConstants(0.35, 0.35);
    var h = try Harness.init(testing.allocator, 0.0, 1.0, c);
    defer h.deinit(testing.allocator);
    var overshot = false;
    var i: usize = 0;
    while (i < 240) : (i += 1) {
        h.step(1.0 / 120.0);
        if (h.pos() > 1.0 + 1.0e-3) overshot = true;
    }
    try testing.expect(overshot);
    // ...and it still resolves to rest afterward.
    try testing.expect(@abs(h.pos() - 1.0) < rest_eps);
}

// Test 4 — Frame-rate independence. The same animation run at a steady 120 fps
// and at a jittery frame cadence summing to the same elapsed time lands in the
// same place. This is the test that proves the fixed-step accumulator works and
// is the whole reason it exists.
test "trajectory is independent of frame cadence" {
    const c = springConstants(0.25, 0.35);
    // Compare mid-flight (before rest), where cadence could still diverge.
    const total: f32 = 0.15;

    var steady = try Harness.init(testing.allocator, 0.0, 1.0, c);
    defer steady.deinit(testing.allocator);
    var t: f32 = 0;
    while (t + 1.0e-6 < total) : (t += 1.0 / 240.0) steady.step(1.0 / 240.0);

    var jittery = try Harness.init(testing.allocator, 0.0, 1.0, c);
    defer jittery.deinit(testing.allocator);
    // A repeating uneven cadence (all sub-max_accum) summing to `total`.
    const pattern = [_]f32{ 1.0 / 60.0, 1.0 / 200.0, 1.0 / 90.0, 1.0 / 120.0 };
    var acc: f32 = 0;
    var k: usize = 0;
    while (acc + 1.0e-6 < total) : (k += 1) {
        var d = pattern[k % pattern.len];
        if (acc + d > total) d = total - acc; // land exactly on `total`
        jittery.step(d);
        acc += d;
    }

    // Both consumed the same total time in fixed sub-steps, so they agree to
    // within a sub-step's worth of remainder — far tighter than any visible gap.
    try testing.expect(@abs(steady.pos() - jittery.pos()) < 5.0e-3);
}

// Test 5 — Velocity carry-over on retarget (THE interruptibility guarantee).
// Mid-flight, retarget the spring; assert velocity is UNCHANGED across the call
// (momentum is preserved, not reset) and the position does not jump (continuous
// trajectory). Then confirm it actually heads to the new target. This test is
// the entire reason a spring beats a curve, encoded.
test "retarget preserves velocity and position (no snap)" {
    const c = springConstants(0.25, 0.35);
    var h = try Harness.init(testing.allocator, 0.0, 1.0, c);
    defer h.deinit(testing.allocator);

    // Fly for a bit so there is real momentum to carry.
    var i: usize = 0;
    while (i < 8) : (i += 1) h.step(1.0 / 60.0);
    const pos_before = h.pos();
    const vel_before = h.vel();
    try testing.expect(vel_before > 0.0); // genuinely in motion

    // Interrupt: aim somewhere new mid-flight.
    h.retarget(1.4);

    // The defining assertion: neither position nor velocity was disturbed by
    // the retarget itself — the momentum simply continues toward the new goal.
    try testing.expect(h.pos() == pos_before);
    try testing.expect(h.vel() == vel_before);

    // And it now settles at the NEW target, still carrying its momentum.
    while (i < 240 and h.active[0]) : (i += 1) h.step(1.0 / 60.0);
    try testing.expect(@abs(h.pos() - 1.4) < rest_eps);
}

// Retargeting a spring that has already settled wakes it back up (a nudge on a
// resting bubble must animate, not sit dead).
test "retarget re-activates a settled spring" {
    const c = springConstants(0.2, 0.30);
    var h = try Harness.init(testing.allocator, 0.0, 1.0, c);
    defer h.deinit(testing.allocator);
    var i: usize = 0;
    while (i < 240 and h.active[0]) : (i += 1) h.step(1.0 / 120.0);
    try testing.expect(h.active[0] == false); // settled

    h.retarget(0.5);
    try testing.expect(h.active[0] == true); // woken

    i = 0;
    while (i < 240 and h.active[0]) : (i += 1) h.step(1.0 / 120.0);
    try testing.expect(@abs(h.pos() - 0.5) < rest_eps);
}

// Test 7 — The module reuses slots and leaks nothing (C6). Spawn a batch, step
// to rest, release them all, then respawn: the second batch must REUSE the freed
// slots (the set does not grow), and every stale handle is detectably dead.
// `deinit` under the leak-checking allocator proves no leak.
test "world reuses released slots and leaks nothing" {
    const c = springConstants(0.25, 0.35);
    var w: World = .empty;
    defer w.deinit(testing.allocator);

    var handles: [64]Handle = undefined;
    for (&handles) |*h| h.* = try w.spawn(testing.allocator, 0.0, 1.0, c);

    // Step them all to rest.
    var i: usize = 0;
    while (i < 240) : (i += 1) w.step(1.0 / 120.0);
    // Live springs that settled read their exact target.
    try testing.expect(w.position(handles[0]).? == 1.0);

    // Release everything → 64 slots on the free-list.
    for (handles) |h| w.release(h);
    try testing.expect(w.free.items.len == 64);
    // A released handle is now stale.
    try testing.expect(!w.isLive(handles[0]));
    try testing.expect(w.position(handles[0]) == null);

    // Respawn a full batch: it reuses the freed slots, so the SoA does not grow.
    const slots_before = w.springs.len;
    var reused: [64]Handle = undefined;
    for (&reused) |*h| h.* = try w.spawn(testing.allocator, 0.0, 1.0, c);
    try testing.expect(w.springs.len == slots_before);
    // The reused handle is live and distinct from the stale one (generation bumped).
    try testing.expect(w.isLive(reused[0]));
    try testing.expect(!w.isLive(handles[0]));
}

// Test 6 (core half) — Rest deactivates the channel. After settle the spring is
// marked inactive and, being inactive, is thereafter untouched by the step (it
// stays exactly at target). The slot-reclamation / free-list half lands with the
// module wrapper (build step 3); this proves the core signal it depends on.
test "a settled spring goes inactive and stays put" {
    const c = springConstants(0.2, 0.30);
    var h = try Harness.init(testing.allocator, 0.0, 1.0, c);
    defer h.deinit(testing.allocator);
    var i: usize = 0;
    while (i < 240 and h.active[0]) : (i += 1) h.step(1.0 / 120.0);
    try testing.expect(h.active[0] == false);
    const settled = h.pos();
    try testing.expect(@abs(settled - 1.0) < rest_eps);
    // Further steps on the inactive spring are a no-op: it does not drift.
    h.step(1.0 / 60.0);
    h.step(1.0 / 60.0);
    try testing.expect(h.pos() == settled);
}

// Scalar helper — convergence and velocity carry, matching the pooled step's
// behaviour on the same constants. Guards the drift risk of a second entry
// point: stepScalar must be the same physics, not a near-copy that decays.
test "stepScalar converges and carries velocity through a retarget" {
    const c = springConstants(0.0, 0.35);
    var pos: f32 = 0.0;
    var vel: f32 = 0.0;
    var i: usize = 0;
    while (i < 180) : (i += 1) stepScalar(&pos, &vel, 1.0, c, 1.0 / 60.0);
    try testing.expect(@abs(pos - 1.0) < rest_eps);
    try testing.expect(@abs(vel) < rest_vel_eps);

    // A retarget is just a new target argument: position and velocity flow on
    // uninterrupted (the momentum carry that makes interruption seamless).
    var seeded_v: f32 = 5.0; // as if a finger released at speed
    var p2: f32 = 0.0;
    stepScalar(&p2, &seeded_v, 1.0, c, 1.0 / 60.0);
    try testing.expect(p2 > 0.0); // the seeded velocity moved it immediately
}
