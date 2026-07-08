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

//! B1 classification: CORE (pure). The Toy Box "Gravity" simulation: on-screen
//! postcards fall under gravity and pile up at the bottom of the viewport, with
//! heavier posts (more likes) dropping faster. It is the physics family's first
//! member; Zero-G and Liquid will reuse the same integrator with different
//! parameters.
//!
//! The model is deliberately the simplest thing that reads as "gravity": each
//! card owns a fixed RESTING SLOT in a bottom-anchored stack (uniform card
//! height, so no per-pair collision resolution is needed) and free-falls toward
//! it, bouncing with restitution and settling once its speed drops below a
//! threshold. Cards that overshoot their slot mid-air may briefly overlap — an
//! accepted artifact for a cosmetic toy (G3), not a bug.
//!
//! PURE (B2/B3/B4): no clock, no RNG, no I/O, no allocation. The shell owns the
//! three parallel state arrays (position, velocity, settled — struct-of-arrays
//! per A3) and hands in the frame `dt`, the per-card rest slots, and the per-card
//! mass (all plain values). Given the same inputs the step is deterministic and
//! fully unit-testable (see the tests at the foot of this file). The LOOK — how a
//! resolved position becomes a drawn card — lives in the renderer, not here.

const std = @import("std");
const assert = std.debug.assert;

/// Tuned constants. Not clocks — parameters. Pixels, seconds.
pub const base_accel: f32 = 2600.0; // px/s^2 at mass 1
pub const restitution: f32 = 0.42; // fraction of speed kept per bounce
pub const settle_speed: f32 = 34.0; // |vy| below which a resting card stops
pub const stack_gap: f32 = 10.0; // px between stacked cards

/// The resting TOP-Y of card `i` in a bottom-anchored stack of `n` uniform cards
/// of height `card_h`: the last card sits on the floor, each earlier card rests
/// on the one below it. Cards above the viewport top (a pile taller than the
/// screen) get a negative slot — correct; the renderer culls them.
pub fn restY(i: usize, n: usize, floor_y: f32, card_h: f32) f32 {
    const from_bottom: f32 = @floatFromInt(n - 1 - i);
    return floor_y - card_h - from_bottom * (card_h + stack_gap);
}

/// Map a like count to a fall MASS in [1, 3.5] — louder posts drop harder. Pure.
pub fn massOf(likes: u32) f32 {
    const l: f32 = @floatFromInt(likes);
    return 1.0 + @min(l / 160.0, 2.5);
}

/// Advance the whole stack one frame. `y`/`vy`/`settled` are the shell-owned SoA
/// state (parallel, same length); `rest`/`mass` are plain per-card inputs; `dt`
/// is the frame delta in seconds. A settled card is skipped (no jitter). PURE.
pub fn step(y: []f32, vy: []f32, settled: []bool, rest: []const f32, mass: []const f32, dt: f32) void {
    assert(y.len == vy.len and y.len == settled.len);
    assert(y.len == rest.len and y.len == mass.len);
    const d = std.math.clamp(dt, 0.0, 0.05); // guard a stalled frame from exploding
    for (y, vy, settled, rest, mass) |*yi, *vi, *si, ri, mi| {
        if (si.*) continue;
        vi.* += base_accel * mi * d;
        yi.* += vi.* * d;
        if (yi.* >= ri) {
            yi.* = ri;
            if (@abs(vi.*) < settle_speed) {
                vi.* = 0;
                si.* = true;
            } else {
                vi.* = -vi.* * restitution;
            }
        }
    }
}

/// True once every card has come to rest — the shell stops forcing a per-frame
/// rebuild when this holds, so a settled pile is cached like any static frame.
pub fn allSettled(settled: []const bool) bool {
    for (settled) |s| if (!s) return false;
    return true;
}

test "gravity: a card above its slot falls, bounces, and settles at rest" {
    var y = [_]f32{0.0};
    var vy = [_]f32{0.0};
    var settled = [_]bool{false};
    const rest = [_]f32{500.0};
    const mass = [_]f32{1.0};
    // Step a generous second of 60fps frames — plenty to fall 500px and settle.
    var i: usize = 0;
    while (i < 120) : (i += 1) step(&y, &vy, &settled, &rest, &mass, 1.0 / 60.0);
    try std.testing.expect(settled[0]);
    try std.testing.expectApproxEqAbs(@as(f32, 500.0), y[0], 0.001);
    try std.testing.expectEqual(@as(f32, 0.0), vy[0]);
}

test "gravity: a settled card is untouched, and heavier falls faster" {
    // Settled card ignores further steps.
    var y = [_]f32{100.0};
    var vy = [_]f32{0.0};
    var settled = [_]bool{true};
    const rest = [_]f32{500.0};
    const mass = [_]f32{1.0};
    step(&y, &vy, &settled, &rest, &mass, 1.0 / 60.0);
    try std.testing.expectEqual(@as(f32, 100.0), y[0]); // unmoved

    // Over one frame from rest, the heavier card gains more downward speed.
    var yh = [_]f32{ 0.0, 0.0 };
    var vyh = [_]f32{ 0.0, 0.0 };
    var sh = [_]bool{ false, false };
    const resth = [_]f32{ 1e9, 1e9 }; // far away → no clamp this frame
    const massh = [_]f32{ 1.0, 3.0 };
    step(&yh, &vyh, &sh, &resth, &massh, 1.0 / 60.0);
    try std.testing.expect(yh[1] > yh[0]); // heavier dropped further
}

test "gravity: rest slots stack bottom-up without overlap" {
    const floor: f32 = 900.0;
    const card_h: f32 = 176.0;
    const r_last = restY(2, 3, floor, card_h); // bottom card on the floor
    const r_mid = restY(1, 3, floor, card_h);
    try std.testing.expectApproxEqAbs(@as(f32, 900.0 - 176.0), r_last, 0.001);
    // Each earlier card sits exactly one card + gap higher.
    try std.testing.expectApproxEqAbs(r_last - (card_h + stack_gap), r_mid, 0.001);
}
