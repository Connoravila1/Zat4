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

//! B1 classification: CORE (pure). The Toy Box "Gravity" SHATTER: every INDIVIDUAL
//! asset on the page — each word/glyph, each icon stroke, each toggle, each panel —
//! becomes its own falling, grabbable, throwable rigid body. Toggle it on and the
//! whole interface loses cohesion and rains to the floor; the only way out is to
//! find the Gravity control in the debris and tap it.
//!
//! One body PER DRAW ITEM (not an arbitrary grid — the actual drawn elements fall).
//! This module owns only the MOTION: a struct-of-arrays of each body's current
//! top-left, velocity, and (constant) size (A3). The shell captures each item's
//! home anchor + size once, seeds a launch impulse, and every frame steps the sim
//! and translates each draw item by its body's displacement from home.
//!
//! PURE (B2/B3/B4): no clock, no RNG, no I/O, no allocation. `dt`, the bounds, and
//! the grabbed body are handed in. Arcade physics, not rigorous (G3): per-body
//! gravity with floor/wall bounce and drag, plus relaxation passes that shove
//! overlapping bodies apart so a lively heap forms. A held body is immovable (the
//! shell pins it to the cursor) but still bulldozes its neighbours.

const std = @import("std");

pub const gravity_accel: f32 = 4200.0; // strong → an instant, heavy drop
pub const restitution: f32 = 0.30; // energy kept on a bounce
pub const air_drag: f32 = 1.1; // horizontal velocity bleed per second
pub const land_stick: f32 = 190.0; // land slower than this → stick (must exceed g·dt)
pub const separation_passes: u8 = 1; // heap-forming relaxation iterations (1 = calm)

/// Advance every body one frame. `held` (if any) is skipped by the integrator but
/// still shoves neighbours in the separation pass. Bodies live in
/// `[0, wall_w] × (.., floor_y]`. PURE.
pub fn step(
    x: []f32,
    y: []f32,
    vx: []f32,
    vy: []f32,
    w: []const f32,
    h: []const f32,
    held: ?usize,
    floor_y: f32,
    wall_w: f32,
    dt: f32,
) void {
    const d = std.math.clamp(dt, 0.0, 0.033);
    for (x, y, vx, vy, w, h, 0..) |*xi, *yi, *vxi, *vyi, wi, hi, i| {
        if (held == i) continue;
        vyi.* += gravity_accel * d;
        vxi.* -= vxi.* * std.math.clamp(air_drag * d, 0.0, 1.0);
        xi.* += vxi.* * d;
        yi.* += vyi.* * d;
        if (xi.* < 0) {
            xi.* = 0;
            vxi.* = -vxi.* * restitution;
        } else if (xi.* + wi > wall_w) {
            xi.* = wall_w - wi;
            vxi.* = -vxi.* * restitution;
        }
        if (yi.* + hi > floor_y) {
            yi.* = floor_y - hi;
            if (vyi.* > land_stick) {
                vyi.* = -vyi.* * restitution;
            } else if (vyi.* > 0) {
                vyi.* = 0;
            }
        }
    }
    var pass: u8 = 0;
    while (pass < separation_passes) : (pass += 1) separateOnce(x, y, vx, vy, w, h, held);
}

/// One pairwise separation pass (O(n²); n is the on-screen draw-item count — a few
/// hundred, trivial). Overlapping bodies are pushed apart on their least-penetrating
/// axis; a held body is immovable (shoves, never shoved).
fn separateOnce(x: []f32, y: []f32, vx: []f32, vy: []f32, w: []const f32, h: []const f32, held: ?usize) void {
    var i: usize = 0;
    while (i < x.len) : (i += 1) {
        var j: usize = i + 1;
        while (j < x.len) : (j += 1) {
            const ox = @min(x[i] + w[i], x[j] + w[j]) - @max(x[i], x[j]);
            if (ox <= 0) continue;
            const oy = @min(y[i] + h[i], y[j] + h[j]) - @max(y[i], y[j]);
            if (oy <= 0) continue;
            const i_held = held == i;
            const j_held = held == j;
            if (i_held and j_held) continue;
            const push_i: f32 = if (i_held) 0.0 else if (j_held) 1.0 else 0.5;
            const push_j: f32 = 1.0 - push_i;
            // Positional-only separation (no velocity injection) so a settled heap
            // stays calm instead of buzzing; bleed a little energy on contact.
            if (ox < oy) {
                const dir: f32 = if (x[i] < x[j]) -1.0 else 1.0;
                x[i] += dir * ox * push_i;
                x[j] -= dir * ox * push_j;
                vx[i] *= 0.5;
                vx[j] *= 0.5;
            } else {
                const dir: f32 = if (y[i] < y[j]) -1.0 else 1.0;
                y[i] += dir * oy * push_i;
                y[j] -= dir * oy * push_j;
                vy[i] *= 0.5;
                vy[j] *= 0.5;
            }
        }
    }
}

/// The body whose CURRENT rect contains the point, topmost-first (a body drawn
/// later — higher index — is on top). Used by the shell to grab/tap. Pure.
pub fn pick(x: []const f32, y: []const f32, w: []const f32, h: []const f32, px: f32, py: f32) ?usize {
    var i: usize = x.len;
    while (i > 0) {
        i -= 1;
        if (px >= x[i] and px < x[i] + w[i] and py >= y[i] and py < y[i] + h[i]) return i;
    }
    return null;
}

test "shatter: a body falls to the floor and comes to rest" {
    var x = [_]f32{100.0};
    var y = [_]f32{0.0};
    var vx = [_]f32{0.0};
    var vy = [_]f32{0.0};
    const w = [_]f32{40.0};
    const h = [_]f32{20.0};
    var i: usize = 0;
    while (i < 200) : (i += 1) step(&x, &y, &vx, &vy, &w, &h, null, 900, 1400, 1.0 / 60.0);
    try std.testing.expectApproxEqAbs(@as(f32, 880.0), y[0], 1.0); // floor(900) - h(20)
    try std.testing.expect(@abs(vy[0]) < 1.0);
}

test "shatter: two overlapping bodies get pushed apart" {
    var x = [_]f32{ 100.0, 120.0 };
    var y = [_]f32{ 500.0, 500.0 };
    var vx = [_]f32{ 0.0, 0.0 };
    var vy = [_]f32{ 0.0, 0.0 };
    const w = [_]f32{ 40.0, 40.0 };
    const h = [_]f32{ 40.0, 40.0 };
    separateOnce(&x, &y, &vx, &vy, &w, &h, null);
    const ox = @min(x[0] + 40, x[1] + 40) - @max(x[0], x[1]);
    try std.testing.expect(ox < 20.0); // overlap reduced from 20
}

test "shatter: a held body is immovable" {
    var x = [_]f32{ 100.0, 110.0 };
    var y = [_]f32{ 300.0, 300.0 };
    var vx = [_]f32{ 0.0, 0.0 };
    var vy = [_]f32{ 0.0, 0.0 };
    const w = [_]f32{ 40.0, 40.0 };
    const h = [_]f32{ 40.0, 40.0 };
    step(&x, &y, &vx, &vy, &w, &h, 0, 2000, 1400, 1.0 / 60.0); // body 0 held
    try std.testing.expectEqual(@as(f32, 100.0), x[0]);
    try std.testing.expectEqual(@as(f32, 300.0), y[0]);
    try std.testing.expect(x[1] != 110.0); // the free one got shoved off
}

test "shatter: pick returns the topmost body under a point, or null" {
    const x = [_]f32{ 100.0, 120.0 }; // body 1 overlaps 0 and, drawn later, wins
    const y = [_]f32{ 300.0, 300.0 };
    const w = [_]f32{ 40.0, 40.0 };
    const h = [_]f32{ 40.0, 40.0 };
    try std.testing.expectEqual(@as(?usize, 1), pick(&x, &y, &w, &h, 130, 320));
    try std.testing.expectEqual(@as(?usize, 0), pick(&x, &y, &w, &h, 105, 320));
    try std.testing.expectEqual(@as(?usize, null), pick(&x, &y, &w, &h, 900, 900));
}

