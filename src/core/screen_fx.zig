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
const emoji_atlas = @import("emoji_atlas.zig");
const chat_effects = @import("chat_effects.zig");

pub const ScreenEffect = chat_effects.ScreenEffect;

/// What a particle IS — its motion rule and how compose draws it.
pub const Kind = enum(u8) {
    balloon, // buoyant, rises, sways; a rounded body + a string
    confetti, // gravity, flutters side to side; a small chip
    spark, // firework ember: radial launch, gravity, quick fade
    beam, // laser: a bright line sweeping across, pulsing
    heart, // "love": a heart that rises and sways, like a warmer balloon
    sprite, // an EMOJI sprite (cell index in `hue`): goats, gloves, notes, waves…
    pig_king, // a pig wearing a crown — Technoblade's mark, drawn as two sprites
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

// ── Tunable recipe constants (owner live pass 2026-07-17 — [TUNE]) ───────────
// Confetti is the owner's favourite and is left as the template; balloons were
// starting too far below to climb into view (barely-visible/inconsistent) and now
// launch just under the bottom edge and rise fast enough to cross the screen;
// fireworks read "too simple/short" → more bursts, more sparks, longer life.
const balloon_count: u32 = 24;
const confetti_count: u32 = 90;
const firework_bursts: u32 = 9;
const spark_per_burst: u32 = 40;
const laser_beams: u32 = 11;

const balloon_rise: f32 = -320.0; // px/s upward — must actually cross the viewport
const confetti_fall: f32 = 190.0; // px/s downward
const gravity: f32 = 520.0; // px/s² for sparks
const firework_life: f32 = 2.2; // per-spark seconds (was 1.4 — read too short)
const show_seconds: f32 = 2.8; // nominal show length (balloons/confetti travel)
const egg_seconds: f32 = 3.2; // name eggs linger a touch longer — they are the treat

// Resolve an emoji cell by codepoint (robust to the atlas being repacked — never
// a hardcoded index). A missing glyph yields a benign 0 rather than an error; the
// egg simply draws the wrong-but-present sprite, never crashes (E4).
fn egCell(cp: u21) u8 {
    return @intCast(@min(emoji_atlas.cellOf(cp) orelse 0, 255));
}
const cp_goat: u21 = 0x1F410;
const cp_pig: u21 = 0x1F437;
const cp_crown: u21 = 0x1F451;
const cp_glove: u21 = 0x1F94A;
const cp_note: u21 = 0x1F3B5;
const cp_blue_heart: u21 = 0x1F499;
const cp_wave: u21 = 0x1F30A;
const cp_cyclone: u21 = 0x1F32A;
const cp_lifter: u21 = 0x1F3CB; // weightlifter — Vicki's singing lifter
const cp_biceps: u21 = 0x1F4AA;

// Festive palette (opaque 0xAARRGGBB); compose applies the fade to the alpha.
const festive = [_]u32{ 0xFFE0466E, 0xFF4A9EE0, 0xFF57C46A, 0xFFF2C14E, 0xFFB06AD8, 0xFFE07A3F };
const laser_hues = [_]u32{ 0xFF39E08A, 0xFF39D6E0, 0xFFE039C4, 0xFFE0C039 };
const heart_hues = [_]u32{ 0xFFE0466E, 0xFFF25C8A, 0xFFE0397A, 0xFFFF7FA8 };
const heart_count: u32 = 22;

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
                const sz = rndR(&st, 34, 56);
                try pool.append(gpa, .{
                    .x = rndR(&st, 0.05 * fw, 0.95 * fw),
                    .y = fh + rndR(&st, 0, 0.15 * fh), // JUST below the bottom edge (small stagger)
                    .vx = rndR(&st, -16, 16),
                    .vy = balloon_rise * rndR(&st, 0.85, 1.2),
                    .life = show_seconds * rndR(&st, 0.9, 1.15),
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
        .hearts => {
            var i: u32 = 0;
            while (i < heart_count) : (i += 1) {
                try pool.append(gpa, .{
                    .x = rndR(&st, 0.08 * fw, 0.92 * fw),
                    .y = fh + rndR(&st, 0, 0.2 * fh),
                    .vx = rndR(&st, -14, 14),
                    .vy = balloon_rise * rndR(&st, 0.7, 1.05), // a touch slower than balloons
                    .life = show_seconds * rndR(&st, 0.9, 1.15),
                    .max_life = show_seconds,
                    .size = rndR(&st, 20, 34),
                    .seed = @truncate(mix(&st)),
                    .kind = .heart,
                    .hue = @intCast(mix(&st) % heart_hues.len),
                });
            }
        },
        .fireworks => {
            var b: u32 = 0;
            while (b < firework_bursts) : (b += 1) {
                const cx = rndR(&st, 0.12 * fw, 0.88 * fw);
                const cy = rndR(&st, 0.12 * fh, 0.62 * fh);
                const hue: u8 = @intCast(mix(&st) % festive.len);
                var p: u32 = 0;
                while (p < spark_per_burst) : (p += 1) {
                    const ang = rndR(&st, 0, std.math.tau);
                    const spd = rndR(&st, 90, 320); // wider spread → a fuller burst
                    try pool.append(gpa, .{
                        .x = cx,
                        .y = cy,
                        .vx = @cos(ang) * spd,
                        .vy = @sin(ang) * spd,
                        .life = firework_life * rndR(&st, 0.75, 1.1),
                        .max_life = firework_life,
                        .size = rndR(&st, 3, 6),
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
                    .life = show_seconds * rndR(&st, 0.55, 1.0),
                    .max_life = show_seconds,
                    .size = rndR(&st, 3, 7), // beam thickness — a touch punchier
                    .seed = @truncate(mix(&st)),
                    .kind = .beam,
                    .hue = @intCast(mix(&st) % laser_hues.len),
                });
            }
        },
        // No recipe yet — an honest no-op rather than a wrong effect. (hearts,
        // spotlight, echo, shooting_star, none, and any future/unknown id.)
        // ── NAME EASTER EGGS ────────────────────────────────────────────────
        .eg_goats => {
            // A STAMPEDE — a whole herd runs across, at every height, and some are
            // already on screen so it reads instantly. Left-to-right, staggered.
            var i: u32 = 0;
            while (i < 46) : (i += 1) {
                try pool.append(gpa, .{
                    .x = rndR(&st, -0.6 * fw, 0.95 * fw), // spread: some mid-screen already
                    .y = rndR(&st, 0.04 * fh, 0.94 * fh),
                    .vx = rndR(&st, 230, 380), // gallop rightward
                    .vy = 0,
                    .life = egg_seconds * rndR(&st, 0.85, 1.15),
                    .max_life = egg_seconds,
                    .size = rndR(&st, 36, 54),
                    .seed = @truncate(mix(&st)),
                    .kind = .sprite,
                    .hue = egCell(cp_goat),
                });
            }
        },
        .eg_pigs => {
            // Crowned pigs fill the screen — Technoblade never dies.
            var i: u32 = 0;
            while (i < 26) : (i += 1) {
                try pool.append(gpa, .{
                    .x = rndR(&st, 0.05 * fw, 0.95 * fw),
                    // Spread from mid-screen to just below, so the first ones show
                    // at once and the rest rise up behind them.
                    .y = rndR(&st, 0.35 * fh, 1.05 * fh),
                    .vx = rndR(&st, -20, 20),
                    .vy = balloon_rise * rndR(&st, 0.75, 1.05),
                    .life = egg_seconds * rndR(&st, 0.85, 1.15),
                    .max_life = egg_seconds,
                    .size = rndR(&st, 42, 60),
                    .seed = @truncate(mix(&st)),
                    .kind = .pig_king,
                    .hue = egCell(cp_pig),
                });
            }
        },
        .eg_gloves => {
            // A flurry of jabs SMACKING in from both walls — the shell shakes the
            // whole screen while these fly (the rumble the owner asked for; it keys
            // off this effect being live, see `shakeActive`).
            var i: u32 = 0;
            while (i < 18) : (i += 1) {
                const from_left = (i & 1) == 0;
                try pool.append(gpa, .{
                    .x = if (from_left) rndR(&st, -0.35 * fw, -0.05 * fw) else rndR(&st, 1.05 * fw, 1.35 * fw),
                    .y = rndR(&st, 0.08 * fh, 0.92 * fh),
                    .vx = if (from_left) rndR(&st, 420, 640) else rndR(&st, -640, -420), // fast jabs
                    .vy = rndR(&st, -40, 40),
                    .life = egg_seconds * rndR(&st, 0.55, 0.85),
                    .max_life = egg_seconds,
                    .size = rndR(&st, 42, 58),
                    .seed = @truncate(mix(&st)),
                    .kind = .sprite,
                    .hue = egCell(cp_glove),
                });
            }
        },
        .eg_notes => {
            // A WEIGHTLIFTER stands lower-centre and FLINGS musical notes out of a
            // single spot — sung and thrown, with the fitness reference right there
            // in the source. Notes spray up-and-out on radial paths; a couple of
            // flexed biceps fly with them.
            const sx = 0.5 * fw;
            const sy = 0.72 * fh;
            // The lifter — big, parked, a gentle bob (near-zero velocity).
            try pool.append(gpa, .{
                .x = sx, .y = sy,
                .vx = 0, .vy = rndR(&st, -6, 0),
                .life = egg_seconds, .max_life = egg_seconds,
                .size = rndR(&st, 62, 74),
                .seed = @truncate(mix(&st)),
                .kind = .sprite, .hue = egCell(cp_lifter),
            });
            var i: u32 = 0;
            while (i < 24) : (i += 1) {
                // A radial spray biased UPWARD (angles from ~200° to ~340°, i.e.
                // up-left through up-right), flung from the lifter's spot.
                const ang = rndR(&st, 3.5, 6.0); // radians, upper hemisphere-ish
                const spd = rndR(&st, 150, 340);
                const biceps = (i % 8) == 0;
                try pool.append(gpa, .{
                    .x = sx + rndR(&st, -12, 12),
                    .y = sy + rndR(&st, -12, 12),
                    .vx = @cos(ang) * spd,
                    .vy = -@abs(@sin(ang)) * spd - rndR(&st, 20, 80), // always up-ish
                    .life = egg_seconds * rndR(&st, 0.55, 0.9),
                    .max_life = egg_seconds,
                    .size = if (biceps) rndR(&st, 30, 40) else rndR(&st, 30, 46),
                    .seed = @truncate(mix(&st)),
                    .kind = .sprite,
                    .hue = if (biceps) egCell(cp_biceps) else egCell(cp_note),
                });
            }
        },
        .eg_blue_hearts => {
            // A LITERAL OCEAN: a rolling body of wave-water fills the lower screen,
            // undulating in place, and blue hearts float UP out of the sea. The
            // waves are the water; the hearts are what rise from it (owner: "an
            // ocean feel... literal ocean water and stuff").
            const ocean_secs = egg_seconds * 1.5;
            // THE SEA — overlapping wave tiles across the bottom band, many, packed,
            // barely drifting so the surface churns rather than travels. Big enough
            // to overlap into a continuous body of water.
            var wx: f32 = -0.1 * fw;
            while (wx < 1.1 * fw) : (wx += 0.11 * fw) {
                var row: u32 = 0;
                while (row < 3) : (row += 1) {
                    const fr: f32 = @floatFromInt(row);
                    try pool.append(gpa, .{
                        .x = wx + rndR(&st, -0.04 * fw, 0.04 * fw),
                        .y = fh - fr * 0.11 * fh - rndR(&st, 0, 0.05 * fh), // stacked up from the floor
                        .vx = rndR(&st, -10, 10),
                        .vy = rndR(&st, -6, 6), // churn in place, not travel
                        .life = ocean_secs * rndR(&st, 0.9, 1.1),
                        .max_life = ocean_secs,
                        .size = rndR(&st, 64, 92), // large, so they overlap into a sea
                        .seed = @truncate(mix(&st)),
                        .kind = .sprite,
                        .hue = egCell(cp_wave),
                    });
                }
            }
            // THE HEARTS — rising out of the water, gently.
            var i: u32 = 0;
            while (i < 34) : (i += 1) {
                try pool.append(gpa, .{
                    .x = rndR(&st, 0.02 * fw, 0.98 * fw),
                    .y = rndR(&st, 0.45 * fh, fh), // born in/above the sea
                    .vx = rndR(&st, -8, 8),
                    .vy = rndR(&st, -60, -24), // float up off the surface
                    .life = ocean_secs * rndR(&st, 0.8, 1.1),
                    .max_life = ocean_secs,
                    .size = rndR(&st, 22, 38),
                    .seed = @truncate(mix(&st)),
                    .kind = .sprite,
                    .hue = egCell(cp_blue_heart),
                });
            }
        },
        .eg_hearts_fall => {
            // A DOWNPOUR of hearts — many, and some already mid-fall so the screen
            // is full at once. Rose vector hearts, tumbling.
            var i: u32 = 0;
            while (i < 64) : (i += 1) {
                try pool.append(gpa, .{
                    .x = rndR(&st, 0, fw),
                    .y = rndR(&st, -0.7 * fh, fh), // spread top-to-bottom already
                    .vx = rndR(&st, -26, 26),
                    .vy = confetti_fall * rndR(&st, 0.6, 1.0),
                    .life = egg_seconds * rndR(&st, 0.85, 1.2),
                    .max_life = egg_seconds,
                    .size = rndR(&st, 18, 32),
                    .seed = @truncate(mix(&st)),
                    .kind = .heart,
                    .hue = @intCast(mix(&st) % heart_hues.len),
                });
            }
        },
        .eg_hurricane => {
            // ONE big cyclone sweeps across, plus torn debris — Roger's storm. The
            // message-displacement "bonus" rides the toy transform in the shell,
            // not here; this is the visible weather.
            try pool.append(gpa, .{
                .x = -0.2 * fw,
                .y = 0.45 * fh,
                .vx = (1.4 * fw) / egg_seconds, // cross the whole screen in the show
                .vy = 0,
                .life = egg_seconds,
                .max_life = egg_seconds,
                .size = @min(fw, fh) * 0.7, // huge
                .seed = @truncate(mix(&st)),
                .kind = .sprite,
                .hue = egCell(cp_cyclone),
            });
            var i: u32 = 0;
            while (i < 10) : (i += 1) {
                try pool.append(gpa, .{
                    .x = rndR(&st, -0.3 * fw, 0.2 * fw),
                    .y = rndR(&st, 0.1 * fh, 0.9 * fh),
                    .vx = rndR(&st, 260, 520),
                    .vy = rndR(&st, -60, 60),
                    .life = egg_seconds * rndR(&st, 0.6, 1.0),
                    .max_life = egg_seconds,
                    .size = rndR(&st, 26, 40),
                    .seed = @truncate(mix(&st)),
                    .kind = .sprite,
                    .hue = egCell(cp_wave),
                });
            }
        },
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
            .heart => {
                xs[i] += (vxs[i] + @sin(lives[i] * 2.4 + phase) * 20.0) * dt;
                ys[i] += vys[i] * dt;
            },
            .sprite, .pig_king => {
                // Straight drift + a little sway, so a herd/flock does not look
                // like it is on rails. Risers (negative vy) sway more.
                const sway: f32 = if (vys[i] < 0) 18.0 else 8.0;
                xs[i] += (vxs[i] + @sin(lives[i] * 2.2 + phase) * sway) * dt;
                ys[i] += vys[i] * dt;
            },
        }
        i += 1;
    }
}

/// Should the SCREEN rumble right now? True while any boxing-glove sprite is in
/// flight — the gloves smack the walls and the whole frame shakes with the
/// impacts (owner's ask). Pure over the pool: the shell reads this and applies
/// the offset, so the shake lives and dies with the effect and needs no timer of
/// its own. Returns 0..1 intensity (fades as the flurry thins).
pub fn shakeActive(pool: *const Pool) f32 {
    const kinds = pool.items(.kind);
    const hues = pool.items(.hue);
    const lives = pool.items(.life);
    const maxes = pool.items(.max_life);
    const glove = @min(emoji_atlas.cellOf(cp_glove) orelse 0, 255);
    var peak: f32 = 0;
    for (kinds, hues, lives, maxes) |k, h, life, ml| {
        if (k != .sprite or h != glove or ml <= 0) continue;
        const frac = std.math.clamp(life / ml, 0, 1);
        if (frac > peak) peak = frac;
    }
    return peak;
}

/// True while the show still has particles — the shell keeps ticking/redrawing
/// (and folding this into its rebuild signature) until it drains.
pub fn active(pool: *const Pool) bool {
    return pool.len > 0;
}

/// How dark the screen behind the show should be, 0..1. iMessage DIMS the whole
/// conversation for the beat an effect plays, then lifts it — the dim is what
/// makes the balloons read as "over everything" rather than "in front of the
/// feed". Derived from the show's own life: the freshest particle's remaining
/// fraction, so the dim holds while anything is mid-flight and releases as the
/// last of them die. Peak is capped well below opaque — the messages must stay
/// readable underneath. Empty pool ⇒ 0 (no show, no dim).
pub const dim_peak: f32 = 0.45;
pub fn dimAlpha(pool: *const Pool) f32 {
    const lives = pool.items(.life);
    const maxes = pool.items(.max_life);
    var peak: f32 = 0;
    for (lives, maxes) |life, ml| {
        if (ml <= 0) continue;
        const frac = std.math.clamp(life / ml, 0, 1);
        if (frac > peak) peak = frac;
    }
    // Ease the tail so the lift is smooth, not a step, as the peak falls to 0.
    const eased = peak * peak * (3.0 - 2.0 * peak);
    return eased * dim_peak;
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
            .heart => {
                // A heart at particle scale: two rounded lobes side by side and a
                // triangle closing to a point below — cheaper and rounder than a
                // glyph, and it reads at 20-34px.
                const col = fade(heart_hues[hue % heart_hues.len], a);
                const lobe = clampU16(size * 0.58);
                const r: u8 = @intCast(@min(@as(u16, 255), clampU16(size * 0.29)));
                try dl.append(gpa, .{ .rect = .{ .x = clamp16(x - size * 0.5), .y = clamp16(y), .w = lobe, .h = lobe, .color = col, .radius = r } });
                try dl.append(gpa, .{ .rect = .{ .x = clamp16(x - size * 0.08), .y = clamp16(y), .w = lobe, .h = lobe, .color = col, .radius = r } });
                try dl.append(gpa, .{ .tri = .{
                    .x0 = clamp16(x - size * 0.5),
                    .y0 = clamp16(y + size * 0.34),
                    .x1 = clamp16(x + size * 0.5),
                    .y1 = clamp16(y + size * 0.34),
                    .x2 = clamp16(x),
                    .y2 = clamp16(y + size * 0.92),
                    .color = col,
                } });
            },
            .sprite => {
                // An emoji sprite (cell in `hue`). The fade rides the alpha of the
                // whole item — drawEmoji multiplies its own texel alpha by this.
                const box: u16 = clampU16(size);
                const av: u8 = @intFromFloat(std.math.clamp(a * 255.0, 0, 255));
                try dl.append(gpa, .{ .emoji = .{
                    .x = clamp16(x - size * 0.5),
                    .y = clamp16(y - size * 0.5),
                    .px = box,
                    .cell = hue,
                    .alpha = av,
                } });
            },
            .pig_king => {
                // A pig with a crown perched above it — Technoblade's mark.
                const box: u16 = clampU16(size);
                const av: u8 = @intFromFloat(std.math.clamp(a * 255.0, 0, 255));
                try dl.append(gpa, .{ .emoji = .{
                    .x = clamp16(x - size * 0.5),
                    .y = clamp16(y - size * 0.5),
                    .px = box,
                    .cell = hue, // the pig
                    .alpha = av,
                } });
                const crown: u16 = clampU16(size * 0.6);
                try dl.append(gpa, .{ .emoji = .{
                    .x = clamp16(x - size * 0.3),
                    .y = clamp16(y - size * 0.5 - size * 0.42),
                    .px = crown,
                    .cell = egCell(cp_crown),
                    .alpha = av,
                } });
            },
            .beam => {
                // A bright line across the viewport. Each beam has a FIXED diagonal
                // slope from its seed, so the beams CROSS at varied angles (punchier
                // than parallel near-horizontal lines), and pulses on its own phase.
                const sd: f32 = @floatFromInt(s.items(.seed)[i]);
                const slope = (@mod(sd, 100.0) / 100.0 - 0.5) * fwv * 0.9;
                const col = fade(laser_hues[hue % laser_hues.len], a * (0.55 + 0.45 * @abs(@sin(life * 14.0 + sd * 0.01))));
                try dl.append(gpa, .{ .line = .{
                    .x0 = 0,
                    .y0 = clamp16(y),
                    .x1 = clamp16(fwv),
                    .y1 = clamp16(y + slope),
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
    for ([_]ScreenEffect{ .none, .spotlight, .echo, .shooting_star }) |fx| {
        var pool: Pool = .empty;
        defer pool.deinit(gpa);
        try seedShow(gpa, &pool, fx, 400, 800, 3);
        try testing.expectEqual(@as(usize, 0), pool.len);
    }
}

test "hearts seed and rise (a real recipe now, not a no-op)" {
    const gpa = testing.allocator;
    var pool: Pool = .empty;
    defer pool.deinit(gpa);
    try seedShow(gpa, &pool, .hearts, 400, 800, 7);
    try testing.expect(pool.len > 0);
    // Every heart rises (negative vy) and is tagged as a heart.
    for (pool.items(.vy), pool.items(.kind)) |vy, k| {
        try testing.expect(vy < 0);
        try testing.expectEqual(Kind.heart, k);
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

test "name eggs: each seeds particles of the right kind" {
    const gpa = testing.allocator;
    const cases = [_]struct { fx: ScreenEffect, kind: Kind }{
        .{ .fx = .eg_goats, .kind = .sprite },
        .{ .fx = .eg_pigs, .kind = .pig_king },
        .{ .fx = .eg_gloves, .kind = .sprite },
        .{ .fx = .eg_notes, .kind = .sprite },
        .{ .fx = .eg_blue_hearts, .kind = .sprite },
        .{ .fx = .eg_hearts_fall, .kind = .heart },
        .{ .fx = .eg_hurricane, .kind = .sprite },
    };
    for (cases) |c| {
        var pool: Pool = .empty;
        defer pool.deinit(gpa);
        try seedShow(gpa, &pool, c.fx, 400, 800, 11);
        try testing.expect(pool.len > 0);
        // At least one particle is the expected kind (hurricane mixes cyclone+debris,
        // both sprite; pig_king is all pig_king).
        var found = false;
        for (pool.items(.kind)) |k| {
            if (k == c.kind) found = true;
        }
        try testing.expect(found);
    }
}

test "name eggs: compose emits draw items without tripping (the sprite path)" {
    const gpa = testing.allocator;
    for ([_]ScreenEffect{ .eg_goats, .eg_pigs, .eg_gloves, .eg_notes, .eg_blue_hearts, .eg_hurricane }) |fx| {
        var pool: Pool = .empty;
        defer pool.deinit(gpa);
        try seedShow(gpa, &pool, fx, 400, 700, 5);
        var i: u32 = 0;
        while (i < 30) : (i += 1) step(&pool, 0.016);
        var dl: raster.DrawList = .empty;
        defer dl.deinit(gpa);
        try compose(gpa, &pool, 400, &dl);
        // Something was drawn, and every emoji item names a real atlas cell.
        try testing.expect(dl.len > 0);
        for (dl.items(.tags), dl.items(.data)) |tag, d| {
            if (tag == .emoji) try testing.expect(d.emoji.cell < emoji_atlas.count);
        }
    }
}
