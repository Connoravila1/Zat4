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

//! B1 classification: CORE (pure). SCREEN EFFECTS — the full-thread celebration
//! particle system behind a message's `ScreenEffect` (balloons, confetti,
//! fireworks, lasers … — ZAT_CHAT_STANDALONE_ROADMAP §2.1). Distinct from
//! `effect.zig`, which injects into the glyph FIELD; this is an OVERLAY drawn on
//! top of the whole conversation, the direct iMessage-match layer. (The
//! field-native "exceed" versions are a later slice.)
//!
//! PURE (B2/B3/B4): no clock, no RNG, no I/O. `dt` and a spawn `seed` are handed
//! in by the shell (its one clock/entropy read); the seeding uses a deterministic
//! splitmix PRNG, so the same (effect, size, seed) produces the same particles and
//! the same evolution — fully golden-testable headless. The particle pool is the
//! caller's `Pool` (a MultiArrayList), grown with an explicit allocator (C1/C2);
//! the LOOK (colours, counts, speeds) is [TUNE] data a later live pass will dial.
//!
//! Governing law: A1 (plain data), A3 (SoA pool), A7 (the hot Particle is guarded),
//! B2 (pure), C1/C2 (explicit alloc), E4 (a spent particle is an ordinary cull).

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const raster = @import("raster.zig");
const chat_effects = @import("chat_effects.zig");

pub const ScreenEffect = chat_effects.ScreenEffect;

/// What a particle IS — its motion rule and how compose draws it.
pub const Kind = enum(u8) {
    balloon, // buoyant, rises, sways; a rounded body + a string
    confetti, // gravity, flutters side to side; a small chip
    spark, // firework ember: radial launch, gravity, quick fade
    beam, // laser: a bright line sweeping across, pulsing
};

/// One particle. HOT — hundreds live during a show, swept in bulk (A7).
pub const Particle = struct {
    x: f32,
    y: f32,
    vx: f32,
    vy: f32,
    life: f32, // seconds remaining
    max_life: f32, // original life, for the fade fraction
    size: f32, // px (body size / beam thickness)
    seed: u16, // per-particle phase — sway/flutter variation, pure
    kind: Kind,
    hue: u8, // palette bucket (festive colours / laser colours)

    comptime {
        // Budget: 7×f32 (28) + u16 (2) + 2×u8 (2) = 32, exact, no padding (A7).
        assert(@sizeOf(Particle) == 32);
    }
};

/// The particle population for the active show (A3: SoA). Caller-owned; grown by
/// `seedShow`, drained by `step`, read by `compose`.
pub const Pool = std.MultiArrayList(Particle);

// ── Tunable recipe constants (a later live pass dials these — [TUNE]) ────────
const balloon_count: u32 = 18;
const confetti_count: u32 = 90;
const firework_bursts: u32 = 5;
const spark_per_burst: u32 = 26;
const laser_beams: u32 = 7;

const balloon_rise: f32 = -150.0; // px/s upward
const confetti_fall: f32 = 190.0; // px/s downward
const gravity: f32 = 520.0; // px/s² for sparks
const show_seconds: f32 = 2.6; // nominal show length (balloons/confetti travel)

// Festive palette (opaque 0xAARRGGBB); compose applies the fade to the alpha.
const festive = [_]u32{ 0xFFE0466E, 0xFF4A9EE0, 0xFF57C46A, 0xFFF2C14E, 0xFFB06AD8, 0xFFE07A3F };
const laser_hues = [_]u32{ 0xFF39E08A, 0xFF39D6E0, 0xFFE039C4, 0xFFE0C039 };

// ── A tiny deterministic PRNG (pure; the shell owns the seed) ────────────────
fn mix(state: *u64) u64 {
    state.* +%= 0x9E3779B97F4A7C15;
    var z = state.*;
    z = (z ^ (z >> 30)) *% 0xBF58476D1CE4E5B9;
    z = (z ^ (z >> 27)) *% 0x94D049BB133111EB;
    return z ^ (z >> 31);
}
/// Uniform in [0,1). Pure given the state.
fn rnd(state: *u64) f32 {
    return @as(f32, @floatFromInt(mix(state) >> 40)) / 16_777_216.0; // /2^24
}
/// Uniform in [lo,hi).
fn rndR(state: *u64, lo: f32, hi: f32) f32 {
    return lo + (hi - lo) * rnd(state);
}

/// Seed the pool for `effect` over a `w`×`h` logical viewport. Deterministic in
/// `seed` (B2) — same inputs, same particles. Appends to whatever is already in
/// the pool, so two shows can overlap. Effects without a recipe yet
/// (hearts/celebration→confetti reuse; spotlight/echo/shooting_star: none) are
/// documented at the switch. C1/C2: explicit allocator, the only growth.
pub fn seedShow(gpa: Allocator, pool: *Pool, effect: ScreenEffect, w: u16, h: u16, seed: u64) error{OutOfMemory}!void {
    var st: u64 = seed ^ 0xD1B54A32D192ED03;
    const fw: f32 = @floatFromInt(w);
    const fh: f32 = @floatFromInt(h);
    switch (effect) {
        .balloons => {
            var i: u32 = 0;
            while (i < balloon_count) : (i += 1) {
                const sz = rndR(&st, 26, 44);
                try pool.append(gpa, .{
                    .x = rndR(&st, 0.06 * fw, 0.94 * fw),
                    .y = fh + rndR(&st, 0, 0.5 * fh), // start below the screen
                    .vx = rndR(&st, -12, 12),
                    .vy = balloon_rise * rndR(&st, 0.75, 1.25),
                    .life = show_seconds * rndR(&st, 0.85, 1.15),
                    .max_life = show_seconds,
                    .size = sz,
                    .seed = @truncate(mix(&st)),
                    .kind = .balloon,
                    .hue = @intCast(mix(&st) % festive.len),
                });
            }
        },
        .confetti, .celebration => {
            var i: u32 = 0;
            while (i < confetti_count) : (i += 1) {
                try pool.append(gpa, .{
                    .x = rndR(&st, 0, fw),
                    .y = rndR(&st, -0.5 * fh, 0), // start above the screen
                    .vx = rndR(&st, -40, 40),
                    .vy = confetti_fall * rndR(&st, 0.7, 1.3),
                    .life = show_seconds * rndR(&st, 0.8, 1.2),
                    .max_life = show_seconds,
                    .size = rndR(&st, 6, 11),
                    .seed = @truncate(mix(&st)),
                    .kind = .confetti,
                    .hue = @intCast(mix(&st) % festive.len),
                });
            }
        },
        .fireworks => {
            var b: u32 = 0;
            while (b < firework_bursts) : (b += 1) {
                const cx = rndR(&st, 0.15 * fw, 0.85 * fw);
                const cy = rndR(&st, 0.15 * fh, 0.55 * fh);
                const hue: u8 = @intCast(mix(&st) % festive.len);
                const delay = rndR(&st, 0.0, 0.9); // staggered bursts (as shorter life)
                var p: u32 = 0;
                while (p < spark_per_burst) : (p += 1) {
                    const ang = rndR(&st, 0, std.math.tau);
                    const spd = rndR(&st, 90, 240);
                    try pool.append(gpa, .{
                        .x = cx,
                        .y = cy,
                        .vx = @cos(ang) * spd,
                        .vy = @sin(ang) * spd,
                        .life = (1.4 - delay) * rndR(&st, 0.8, 1.1),
                        .max_life = 1.4,
                        .size = rndR(&st, 3, 5),
                        .seed = @truncate(mix(&st)),
                        .kind = .spark,
                        .hue = hue,
                    });
                }
            }
        },
        .lasers => {
            var i: u32 = 0;
            while (i < laser_beams) : (i += 1) {
                try pool.append(gpa, .{
                    .x = 0,
                    .y = rndR(&st, 0.15 * fh, 0.85 * fh),
                    .vx = 0,
                    .vy = rndR(&st, -60, 60), // slight drift
                    .life = show_seconds * rndR(&st, 0.6, 1.0),
                    .max_life = show_seconds,
                    .size = rndR(&st, 2, 5), // beam thickness
                    .seed = @truncate(mix(&st)),
                    .kind = .beam,
                    .hue = @intCast(mix(&st) % laser_hues.len),
                });
            }
        },
        // No recipe yet — an honest no-op rather than a wrong effect. (hearts,
        // spotlight, echo, shooting_star, none, and any future/unknown id.)
        else => {},
    }
}

/// Advance every particle by `dt` and cull the spent ones (E4). PURE (B2).
/// Balloons rise and sway; confetti falls and flutters; sparks arc under gravity;
/// beams drift. Motion rules are per-kind; the sway/flutter is a pure function of
/// the particle's own `seed` and remaining life, so no RNG is read here.
pub fn step(pool: *Pool, dt: f32) void {
    var i: usize = 0;
    const s = pool.slice();
    const xs = s.items(.x);
    const ys = s.items(.y);
    const vxs = s.items(.vx);
    const vys = s.items(.vy);
    const lives = s.items(.life);
    const kinds = s.items(.kind);
    const seeds = s.items(.seed);
    while (i < pool.len) {
        lives[i] -= dt;
        if (lives[i] <= 0) {
            pool.swapRemove(i);
            continue; // slice columns still valid (swapRemove moved the last in)
        }
        const phase = @as(f32, @floatFromInt(seeds[i])) * 0.001;
        switch (kinds[i]) {
            .balloon => {
                // Gentle horizontal sway layered on the base drift.
                xs[i] += (vxs[i] + @sin(lives[i] * 2.0 + phase) * 16.0) * dt;
                ys[i] += vys[i] * dt;
            },
            .confetti => {
                xs[i] += (vxs[i] + @sin(lives[i] * 6.0 + phase) * 55.0) * dt;
                ys[i] += vys[i] * dt;
            },
            .spark => {
                vys[i] += gravity * dt; // arc back down
                xs[i] += vxs[i] * dt;
                ys[i] += vys[i] * dt;
            },
            .beam => {
                ys[i] += vys[i] * dt;
            },
        }
        i += 1;
    }
}

/// True while the show still has particles — the shell keeps ticking/redrawing
/// (and folding this into its rebuild signature) until it drains.
pub fn active(pool: *const Pool) bool {
    return pool.len > 0;
}

/// Colour with its alpha byte scaled by `a` (0..1) — the fade.
fn fade(color: u32, a: f32) u32 {
    const base_a: f32 = @floatFromInt(color >> 24);
    const na: u32 = @intFromFloat(std.math.clamp(base_a * std.math.clamp(a, 0, 1), 0, 255));
    return (na << 24) | (color & 0x00FFFFFF);
}

fn clamp16(v: f32) i16 {
    return @intFromFloat(std.math.clamp(v, -32768, 32767));
}
fn clampU16(v: f32) u16 {
    return @intFromFloat(std.math.clamp(v, 0, 65535));
}

/// Emit the pool's draw items into `dl` (B2: same pool ⇒ same items). Balloons are
/// a rounded body + a string line; confetti and sparks are small rounded chips;
/// beams are lines across `w`. Fade rides the life fraction. C1/C2: the only
/// growth is the draw list, visible at the call site.
pub fn compose(gpa: Allocator, pool: *const Pool, w: u16, dl: *raster.DrawList) error{OutOfMemory}!void {
    const s = pool.slice();
    const fwv: f32 = @floatFromInt(w);
    for (0..pool.len) |i| {
        const kind = s.items(.kind)[i];
        const x = s.items(.x)[i];
        const y = s.items(.y)[i];
        const size = s.items(.size)[i];
        const life = s.items(.life)[i];
        const max_life = s.items(.max_life)[i];
        const hue = s.items(.hue)[i];
        // Fade in over the first 12%, out over the last 25% of life.
        const f = life / @max(0.0001, max_life);
        const a: f32 = if (f > 0.88) (1.0 - f) / 0.12 else if (f < 0.25) f / 0.25 else 1.0;
        switch (kind) {
            .balloon => {
                const col = fade(festive[hue % festive.len], a);
                const bw = clampU16(size);
                const bh = clampU16(size * 1.2);
                // The string first (under the body), then the rounded body.
                try dl.append(gpa, .{ .line = .{
                    .x0 = clamp16(x),
                    .y0 = clamp16(y + size * 1.2),
                    .x1 = clamp16(x + @sin(life * 3.0) * 3.0),
                    .y1 = clamp16(y + size * 2.0),
                    .color = fade(0xFFBFC6D0, a),
                    .thickness = 1,
                } });
                try dl.append(gpa, .{ .rect = .{
                    .x = clamp16(x - size * 0.5),
                    .y = clamp16(y),
                    .w = bw,
                    .h = bh,
                    .color = col,
                    .radius = @intCast(@min(@as(u16, 255), clampU16(size * 0.5))),
                } });
            },
            .confetti => {
                const col = fade(festive[hue % festive.len], a);
                // A flutter-thinned chip: height pinches as it spins (a cheap 2D
                // spin read without a rotation primitive).
                const hh = size * (0.35 + 0.65 * @abs(@sin(life * 8.0 + @as(f32, @floatFromInt(s.items(.seed)[i])) * 0.01)));
                try dl.append(gpa, .{ .rect = .{
                    .x = clamp16(x),
                    .y = clamp16(y),
                    .w = clampU16(size),
                    .h = clampU16(hh),
                    .color = col,
                    .radius = 1,
                } });
            },
            .spark => {
                const col = fade(festive[hue % festive.len], a);
                try dl.append(gpa, .{ .rect = .{
                    .x = clamp16(x),
                    .y = clamp16(y),
                    .w = clampU16(size),
                    .h = clampU16(size),
                    .color = col,
                    .radius = @intCast(@min(@as(u16, 255), clampU16(size * 0.5))),
                } });
            },
            .beam => {
                // A bright line across the viewport, slightly diagonal, pulsing.
                const col = fade(laser_hues[hue % laser_hues.len], a * (0.6 + 0.4 * @abs(@sin(life * 12.0))));
                try dl.append(gpa, .{ .line = .{
                    .x0 = 0,
                    .y0 = clamp16(y),
                    .x1 = clamp16(fwv),
                    .y1 = clamp16(y + @sin(life * 2.0) * 24.0),
                    .color = col,
                    .thickness = @intFromFloat(std.math.clamp(size, 1, 255)),
                } });
            },
        }
    }
}

// ---------------------------------------------------------------------------
// Golden tests (C6: leak-checked allocator). The physics is deterministic and
// clock-free, so these are exact — the LOOK is tuned later, the MECHANISM is
// pinned here.
// ---------------------------------------------------------------------------

fn meanY(pool: *const Pool) f32 {
    if (pool.len == 0) return 0;
    var sum: f32 = 0;
    for (pool.slice().items(.y)) |y| sum += y;
    return sum / @as(f32, @floatFromInt(pool.len));
}

test "balloons rise and confetti falls (opposite Y motion), both deterministic" {
    const gpa = testing.allocator;
    var balloons: Pool = .empty;
    defer balloons.deinit(gpa);
    var conf: Pool = .empty;
    defer conf.deinit(gpa);

    try seedShow(gpa, &balloons, .balloons, 400, 800, 12345);
    try seedShow(gpa, &conf, .confetti, 400, 800, 12345);
    try testing.expect(balloons.len == balloon_count);
    try testing.expect(conf.len == confetti_count);

    const y0_bal = meanY(&balloons);
    const y0_conf = meanY(&conf);
    // Tick ~0.3s.
    var n: usize = 0;
    while (n < 18) : (n += 1) {
        step(&balloons, 1.0 / 60.0);
        step(&conf, 1.0 / 60.0);
    }
    try testing.expect(meanY(&balloons) < y0_bal); // rose (y decreased)
    try testing.expect(meanY(&conf) > y0_conf); // fell (y increased)

    // Determinism: two fresh seedings with the same seed are byte-identical.
    var bal2: Pool = .empty;
    defer bal2.deinit(gpa);
    try seedShow(gpa, &bal2, .balloons, 400, 800, 12345);
    var bal3: Pool = .empty;
    defer bal3.deinit(gpa);
    try seedShow(gpa, &bal3, .balloons, 400, 800, 12345);
    for (bal2.slice().items(.x), bal3.slice().items(.x)) |x2, x3| try testing.expectEqual(x2, x3);
    // A different seed diverges.
    var bal4: Pool = .empty;
    defer bal4.deinit(gpa);
    try seedShow(gpa, &bal4, .balloons, 400, 800, 999);
    try testing.expect(bal4.slice().items(.x)[0] != bal2.slice().items(.x)[0]);
}

test "every show self-drains within its lifetime (E4, no leak)" {
    const gpa = testing.allocator;
    for ([_]ScreenEffect{ .balloons, .confetti, .fireworks, .lasers, .celebration }) |fx| {
        var pool: Pool = .empty;
        defer pool.deinit(gpa);
        try seedShow(gpa, &pool, fx, 400, 800, 7);
        try testing.expect(active(&pool));
        var t: f32 = 0;
        while (t < show_seconds + 1.0) : (t += 1.0 / 60.0) step(&pool, 1.0 / 60.0);
        try testing.expect(!active(&pool)); // fully culled
        try testing.expectEqual(@as(usize, 0), pool.len);
    }
}

test "effects without a recipe yet seed nothing (honest no-op)" {
    const gpa = testing.allocator;
    for ([_]ScreenEffect{ .none, .hearts, .spotlight, .echo, .shooting_star }) |fx| {
        var pool: Pool = .empty;
        defer pool.deinit(gpa);
        try seedShow(gpa, &pool, fx, 400, 800, 3);
        try testing.expectEqual(@as(usize, 0), pool.len);
    }
}

test "fireworks sparks arc under gravity (downward velocity grows)" {
    const gpa = testing.allocator;
    var pool: Pool = .empty;
    defer pool.deinit(gpa);
    try seedShow(gpa, &pool, .fireworks, 400, 800, 55);
    try testing.expect(pool.len == firework_bursts * spark_per_burst);
    // Sum vy before and after a few ticks: gravity must increase it (more downward).
    var vy0: f32 = 0;
    for (pool.slice().items(.vy)) |v| vy0 += v;
    var n: usize = 0;
    while (n < 6) : (n += 1) step(&pool, 1.0 / 60.0);
    var vy1: f32 = 0;
    for (pool.slice().items(.vy)) |v| vy1 += v;
    try testing.expect(vy1 > vy0); // gravity pulled them down
}

test "compose emits at least one draw item per live particle and leaks nothing" {
    const gpa = testing.allocator;
    var pool: Pool = .empty;
    defer pool.deinit(gpa);
    var dl: raster.DrawList = .empty;
    defer dl.deinit(gpa);

    try seedShow(gpa, &pool, .confetti, 300, 600, 21);
    try compose(gpa, &pool, 300, &dl);
    try testing.expect(dl.len >= pool.len); // one rect per confetti chip
    // Guard the record size stayed put (A7).
    try testing.expectEqual(@as(usize, 32), @sizeOf(Particle));
}
