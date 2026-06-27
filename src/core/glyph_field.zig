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

//! B1 classification: CORE (pure). The glyph field as a TRUE SIMULATION — a
//! neighbor-coupled wave medium, not a sampled f(x,y,t). See
//! GLYPH_FIELD_SIM_BUILD.md for the full spec and the why.
//!
//! Each cell holds `height` (displacement) and `vel` (its rate of change),
//! stored as two flat f32 slices (A3 struct-of-arrays: the step reads all
//! heights, then writes all velocities — SoA is the cache-honest shape). Every
//! `step` advances the medium by the discrete wave equation: the Laplacian of
//! `height` is the restoring force; motion EMERGES from the rule. A splash
//! injects velocity; that energy then propagates, reflects off the edges,
//! interferes, and dissipates because the PHYSICS dissipates it — no timers,
//! no scripted overlays.
//!
//! PURE (B2/B3): no clock, no RNG, no I/O. `dt` is a fixed sub-step; the only
//! time-driven term (the ambient "breathing") is precomputed by the SHELL into
//! a plain `ambient_bias` slice and handed in as data, so the core stays
//! deterministic and unit-testable. The LOOK (light gate, glyph ramp, colour)
//! is NOT here — it is a rendering concern the shell/GPU owns; the core owns
//! only the physics.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

/// PLAIN DATA (A1). The field's storage + dims. A7.2: cold struct, size guard
/// waived — exactly one instance, never held in a collection or scanned in
/// bulk. Its hot data is the `height`/`vel` f32 slices, primitives that need
/// no struct guard.
pub const Field = struct {
    height: []f32, // len == cols*rows
    vel: []f32, // len == cols*rows
    dye: []f32, // per-cell colour charge 0..1 (effects stain it; it persists)
    dye_tmp: []f32, // double-buffer scratch for the dye transport sweep
    // Latch: false until the FIRST dye is ever stamped (a like). While false the
    // medium is provably dye-free everywhere, so the transport sweep is a no-op
    // over zeros — skip it. Once a like stains the field, dye persists (never
    // decays) and spreads, so this stays true for the session and the sweep runs
    // as before. A pure cost gate; the result is identical either way.
    dye_present: bool,
    cols: u32,
    rows: u32,
};

/// PLAIN DATA (A1). One disturbance injected into the medium this frame — the
/// ONLY way energy enters the field. HOT: a frame may carry many, processed in
/// a loop → A7 size guard required.
pub const Splash = struct {
    x: u32, // cell column (the shell converted from pixels)
    y: u32, // cell row
    radius: u16, // cells affected (a splash never spans 65k cells)
    _pad: u16 = 0, // A6: explicit pad to the f32 alignment boundary
    amp: f32, // signed velocity added at the centre, falling off to the rim
    dye: f32 = 0, // colour charge stamped at the centre (0 for a plain ripple)

    comptime {
        // A7.1: budget raised 16 → 20 for `dye` — a genuinely-needed field. The
        // persistent-colour effect (a like stains the medium) rides the SAME
        // event as the velocity burst. u32+u32+u16+u16+f32+f32 = 20, exact.
        assert(@sizeOf(Splash) == 20);
    }
};

/// PLAIN DATA (A1). Physics tuning knobs. Cold config (A7.2: one instance, set
/// at startup). The LOOK knobs (light gate, ramp, colour) and the ambient-
/// forcing magnitude live in the SHELL — this struct is physics only.
pub const Params = struct {
    wave_speed: f32 = 0.18, // propagation per step; kept under the CFL limit
    slope_pull: f32 = 1.0, // strength of the restoring pull toward neighbours
    damping: f32 = 0.992, // velocity retained per step (<1 ⇒ energy dissipates)
    // Spec deviation, deliberate: a pure wave equation (height += vel) is
    // mass-conserving — a disturbance FREEZES into a static ripple instead of
    // healing. We want the medium to relax back to FLAT so disturbances fade
    // and the ambient layer breathes a calm surface. `decay` < 1 leaks height
    // toward zero each step (~6 s half-life at 120 Hz with 0.999).
    decay: f32 = 0.999,
    // dye transport: how fast colour charge drifts downhill (carried by wave
    // troughs) and how much it diffuses. It NEVER decays — effects persist.
    dye_flow: f32 = 0.85,
    dye_diffuse: f32 = 0.04,
    // A7.2: cold struct, size guard waived (single config instance).
};

/// Allocate the two field buffers, zeroed (a flat, still medium). The shell
/// owns the Field and frees it with `deinit` (C4/C5); the core only mutates the
/// slices it is handed. Explicit allocator (C1).
pub fn init(gpa: Allocator, field: *Field, cols: u32, rows: u32) Allocator.Error!void {
    const n: usize = @as(usize, cols) * rows;
    const height = try gpa.alloc(f32, n);
    errdefer gpa.free(height);
    const vel = try gpa.alloc(f32, n);
    errdefer gpa.free(vel);
    const dye = try gpa.alloc(f32, n);
    errdefer gpa.free(dye);
    const dye_tmp = try gpa.alloc(f32, n);
    @memset(height, 0);
    @memset(vel, 0);
    @memset(dye, 0);
    @memset(dye_tmp, 0);
    field.* = .{ .height = height, .vel = vel, .dye = dye, .dye_tmp = dye_tmp, .dye_present = false, .cols = cols, .rows = rows };
}

pub fn deinit(gpa: Allocator, field: *Field) void {
    gpa.free(field.height);
    gpa.free(field.vel);
    gpa.free(field.dye);
    gpa.free(field.dye_tmp);
    field.* = undefined;
}

/// PURE (B2). Advance the medium one fixed sub-step. No clock, no RNG, no I/O.
/// `ambient_bias` (len == cols*rows, or empty for none) is the shell's
/// precomputed, time-driven forcing — passed as plain data so no time/noise
/// call happens in the core. Splashes and ambient go into velocity; then the
/// wave step integrates.
pub fn step(field: *Field, p: Params, splashes: []const Splash, ambient_bias: []const f32) void {
    const cols = field.cols;
    const rows = field.rows;
    if (cols == 0 or rows == 0) return;
    const height = field.height;
    const vel = field.vel;

    // 1. Splashes inject velocity (a smooth falloff within the radius).
    for (splashes) |s| applySplash(field, s);

    // 2. Ambient forcing (the shell baked the magnitude in) — gentle breathing.
    if (ambient_bias.len == vel.len) {
        for (vel, ambient_bias) |*v, ab| v.* += ab;
    }

    // CFL stability bound for the explicit wave stencil — above ~0.5 the
    // integration diverges to NaN, so this is a correctness clamp, not a knob.
    const cfl = @min(p.wave_speed * p.slope_pull, 0.49);

    // 3. Sweep A — velocity from the Laplacian of height (read-only). Edges
    //    REFLECT: a clamped neighbour index reads the edge cell itself, so the
    //    off-grid term contributes 0 (Neumann boundary) and waves bounce.
    var y: u32 = 0;
    while (y < rows) : (y += 1) {
        const ym = if (y > 0) y - 1 else y;
        const yp = if (y < rows - 1) y + 1 else y;
        var x: u32 = 0;
        while (x < cols) : (x += 1) {
            const xm = if (x > 0) x - 1 else x;
            const xp = if (x < cols - 1) x + 1 else x;
            const i = y * cols + x;
            const lap = height[y * cols + xm] + height[y * cols + xp] +
                height[ym * cols + x] + height[yp * cols + x] - 4.0 * height[i];
            vel[i] = (vel[i] + cfl * lap) * p.damping;
        }
    }

    // 4. Sweep B — integrate height, leak toward flat (relax-to-rest), and
    //    clamp as a NaN/blowup firewall (E2: contain a bad frame).
    for (height, vel) |*h, v| h.* = std.math.clamp((h.* + v) * p.decay, -8.0, 8.0);

    // 5. DYE transport — colour charge stamped by effects drifts DOWNHILL, so
    //    the wave troughs CARRY it (the physics moves it), with a little
    //    diffusion, and NO decay (it persists for the session). Double-buffered.
    //    Skipped entirely while the medium has never been stained (dye all zero,
    //    sweep is a no-op) — identical result, no per-cell work until a like.
    if (!field.dye_present) return;
    const dye = field.dye;
    const dst = field.dye_tmp;
    var dy: u32 = 0;
    while (dy < rows) : (dy += 1) {
        const dym = if (dy > 0) dy - 1 else dy;
        const dyp = if (dy < rows - 1) dy + 1 else dy;
        var dx: u32 = 0;
        while (dx < cols) : (dx += 1) {
            const dxm = if (dx > 0) dx - 1 else dx;
            const dxp = if (dx < cols - 1) dx + 1 else dx;
            const i = dy * cols + dx;
            const hi = height[i];
            const nL = dy * cols + dxm;
            const nR = dy * cols + dxp;
            const nU = dym * cols + dx;
            const nD = dyp * cols + dx;
            var nd = dye[i];
            // flux with each neighbour: a HIGHER neighbour feeds dye in, a LOWER
            // one draws it out (downhill flow). Capped per neighbour for stability.
            inline for (.{ nL, nR, nU, nD }) |nb| {
                const dh = height[nb] - hi;
                if (dh > 0) {
                    nd += @min(dye[nb] * 0.15, dh * p.dye_flow);
                } else {
                    nd -= @min(dye[i] * 0.15, -dh * p.dye_flow);
                }
            }
            const avg = (dye[nL] + dye[nR] + dye[nU] + dye[nD]) * 0.25;
            nd += (avg - dye[i]) * p.dye_diffuse;
            dst[i] = std.math.clamp(nd, 0.0, 1.0);
        }
    }
    field.dye = dst;
    field.dye_tmp = dye;
}

/// Inject a splash's velocity into the cells within its radius (smooth falloff
/// to the rim). Internal — operates on the field's own index space (A4: the
/// index never leaves this module).
fn applySplash(field: *Field, s: Splash) void {
    const cols = field.cols;
    const rows = field.rows;
    const r: i32 = @intCast(@max(@as(u16, 1), s.radius));
    const rf: f32 = @floatFromInt(r);
    const cx: i32 = @intCast(s.x);
    const cy: i32 = @intCast(s.y);
    // Latch the dye gate the moment any effect stains the medium (§5 skip).
    if (s.dye != 0) field.dye_present = true;
    var dy: i32 = -r;
    while (dy <= r) : (dy += 1) {
        const yy = cy + dy;
        if (yy < 0 or yy >= rows) continue;
        var dx: i32 = -r;
        while (dx <= r) : (dx += 1) {
            const xx = cx + dx;
            if (xx < 0 or xx >= cols) continue;
            const dist = @sqrt(@as(f32, @floatFromInt(dx * dx + dy * dy)));
            if (dist > rf) continue;
            const t01 = 1.0 - dist / rf;
            const i: usize = @intCast(yy * @as(i32, @intCast(cols)) + xx);
            field.vel[i] += s.amp * t01;
            if (s.dye != 0) field.dye[i] = std.math.clamp(field.dye[i] + s.dye * t01, 0.0, 1.0);
        }
    }
}

// ---------------------------------------------------------------------------
// Golden tests (design §8 spirit, B2/C6 — leak-checked, deterministic)
// ---------------------------------------------------------------------------

const testing = std.testing;

fn totalEnergy(field: *const Field) f32 {
    var e: f32 = 0;
    for (field.height) |h| e += @abs(h);
    return e;
}

test "a splash propagates outward, reflects, and stays finite (no NaN)" {
    const gpa = testing.allocator; // C6
    var f: Field = undefined;
    try init(gpa, &f, 32, 32);
    defer deinit(gpa, &f);

    const center = 16 * 32 + 16;
    const off = 16 * 32 + 24; // 8 cells to the right of centre
    const splashes = [_]Splash{.{ .x = 16, .y = 16, .radius = 3, .amp = 1.0 }};

    // Inject once, then let the medium carry it.
    step(&f, .{}, &splashes, &.{});
    try testing.expect(f.height[center] != 0); // the splash landed

    var n: u32 = 0;
    while (n < 60) : (n += 1) step(&f, .{}, &.{}, &.{});

    // The disturbance reached a cell well away from the centre — it PROPAGATED
    // (a sampled f(x,y,t) field could never carry energy between cells).
    try testing.expect(@abs(f.height[off]) > 0.0001);
    // Everything stays finite and bounded (CFL + firewall hold).
    for (f.height) |h| try testing.expect(std.math.isFinite(h) and @abs(h) <= 8.0);
}

test "damping dissipates energy over time (the field settles)" {
    const gpa = testing.allocator;
    var f: Field = undefined;
    try init(gpa, &f, 24, 24);
    defer deinit(gpa, &f);

    const splashes = [_]Splash{.{ .x = 12, .y = 12, .radius = 4, .amp = 2.0 }};
    step(&f, .{}, &splashes, &.{});
    var n: u32 = 0;
    while (n < 40) : (n += 1) step(&f, .{}, &.{}, &.{});
    const early = totalEnergy(&f);

    n = 0;
    while (n < 4000) : (n += 1) step(&f, .{}, &.{}, &.{});
    const late = totalEnergy(&f);

    // With damping < 1 and no new energy, the medium calms toward flat.
    try testing.expect(late < early);
}

test "dye is stamped, persists (no decay), spreads, and stays in [0,1]" {
    const gpa = testing.allocator;
    var f: Field = undefined;
    try init(gpa, &f, 24, 24);
    defer deinit(gpa, &f);

    // A "like": a velocity burst that also stains the medium red.
    const like = [_]Splash{.{ .x = 12, .y = 12, .radius = 3, .amp = 1.5, .dye = 1.0 }};
    step(&f, .{}, &like, &.{});
    var stamped: f32 = 0;
    for (f.dye) |d| stamped += d;
    try testing.expect(stamped > 0.0); // the like stained the medium somewhere

    var n: u32 = 0;
    while (n < 200) : (n += 1) step(&f, .{}, &.{}, &.{});

    var total: f32 = 0;
    var spread: u32 = 0;
    for (f.dye) |d| {
        total += d;
        if (d > 0.001) spread += 1;
        try testing.expect(d >= 0.0 and d <= 1.0); // bounded (E2)
    }
    try testing.expect(total > 0.0); // still there after 200 steps — it persists
    try testing.expect(spread > 1); // it moved/spread beyond the stamp point
}

test "step is deterministic — same input, same output (B2)" {
    const gpa = testing.allocator;
    var a: Field = undefined;
    var b: Field = undefined;
    try init(gpa, &a, 20, 20);
    defer deinit(gpa, &a);
    try init(gpa, &b, 20, 20);
    defer deinit(gpa, &b);

    const splashes = [_]Splash{.{ .x = 10, .y = 7, .radius = 2, .amp = 1.5 }};
    var n: u32 = 0;
    while (n < 100) : (n += 1) {
        step(&a, .{}, if (n == 0) &splashes else &.{}, &.{});
        step(&b, .{}, if (n == 0) &splashes else &.{}, &.{});
    }
    try testing.expectEqualSlices(f32, a.height, b.height);
    try testing.expectEqualSlices(f32, a.vel, b.vel);
}
