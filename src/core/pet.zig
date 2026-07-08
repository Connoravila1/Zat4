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

//! B1 classification: CORE (pure). The Toy Box "Pet" — a Tamagotchi as a
//! counter-driven state machine: old state + elapsed time + a summary of what the
//! user just did → new state. Feeding/petting cheers it, doom-scrolling sours its
//! mood, idleness makes it sleepy, and time makes it hungry. Deterministic and
//! frame-testable; the LOOK (how a mood becomes a drawn creature) lives in the
//! renderer, not here.
//!
//! PURE (B2/B3/B4): no clock, no RNG, no I/O, no allocation. The shell reads the
//! clock and the recent-activity summary and hands them in as plain values.

const std = @import("std");
const assert = std.debug.assert;

/// The pet's current expression, chosen from the counters — the renderer draws
/// the matching face.
pub const Anim = enum(u8) { idle, happy, sulk, sleep };

/// A summary of what the user did since the last step — the shell fills it from
/// the event stream (B5), the core never watches the clock or the input itself.
/// A7.2: cold struct — one per frame, never held in a collection. Guard waived.
pub const Activity = struct {
    petted: bool = false, // the user tapped the pet (feed + cheer)
    tossed: bool = false, // the user flung the pet this step
    scroll_ms: u16 = 0, // ms spent scrolling since the last step (doom-scroll signal)
    interacted: bool = false, // any click/scroll this step → the pet stays awake
};

/// The whole pet. A7.2: cold struct — exactly ONE pet, never in a hot loop; the
/// size guard is waived (it exists in single quantity).
pub const State = struct {
    hunger: u8 = 200, // 0 = starving, 255 = full
    energy: u8 = 210, // 0 = asleep, 255 = lively
    mood: u8 = 190, // 0 = sulking, 255 = delighted
    anim: Anim = .idle,
    ms_idle: u32 = 0, // ms since the last interaction (drives sleepiness)
    toss_streak: u8 = 0, // recent tossing intensity; decays — a little is fun, a lot annoys
};

fn subSat(v: u8, d: u8) u8 {
    return if (v > d) v - d else 0;
}
fn addSat(v: u8, a: u16) u8 {
    return @intCast(@min(255, @as(u16, v) + a));
}

/// Advance the pet one frame. PURE — same (state, dt, activity) ⇒ same result.
pub fn step(s: State, dt_ms: u32, act: Activity) State {
    var n = s;
    // Idle clock: any interaction resets it; otherwise it climbs.
    if (act.interacted) n.ms_idle = 0 else n.ms_idle +|= dt_ms;

    // Time makes it hungry; interaction wakes/energizes it, long idleness makes it
    // sleepy (never charge on idle — that is what put it to sleep).
    const t: u8 = @intCast(@min(60, dt_ms / 100)); // ~1 tick per 100 ms
    n.hunger = subSat(n.hunger, t);
    if (act.interacted) {
        n.energy = addSat(n.energy, @as(u16, t) * 2);
    } else if (n.ms_idle > 6000) {
        n.energy = subSat(n.energy, t);
    }

    // Doom-scrolling sours the mood; hunger makes it grumpy; but when it isn't
    // being doom-scrolled and is fed, the mood gently drifts back toward calm so it
    // never stays sad forever.
    n.mood = subSat(n.mood, @intCast(@min(120, act.scroll_ms / 30)));
    if (n.hunger < 60) n.mood = subSat(n.mood, t); // hungry → grumpy
    if (act.scroll_ms == 0 and n.hunger > 80 and n.mood < 160) n.mood = addSat(n.mood, t);

    // Petting/feeding lifts it to CONTENT (the shell flashes the happy face as the
    // brief reaction; the mood itself just recovers to a calm idle, not a locked
    // grin — so the smile is a moment, then it settles back to neutral).
    if (act.petted) {
        n.hunger = addSat(n.hunger, 90);
        n.mood = @max(addSat(n.mood, 85), 175);
        n.energy = addSat(n.energy, 45);
        n.ms_idle = 0;
    }

    // Tossing: fatigue that decays over time. A little is fun (a small lift); too
    // much flinging in a short span annoys it (mood drops → it sulks).
    n.toss_streak = subSat(n.toss_streak, @intCast(@min(255, dt_ms / 350)));
    if (act.tossed) {
        n.toss_streak = addSat(n.toss_streak, 1);
        if (n.toss_streak <= 2) {
            n.mood = addSat(n.mood, 12); // wheee — good fun
        } else {
            n.mood = subSat(n.mood, 55); // too much roughhousing → upset
        }
        n.ms_idle = 0;
    }

    // The face falls out of the counters, sleep winning over mood.
    n.anim = if (n.energy < 55)
        .sleep
    else if (n.mood > 205)
        .happy
    else if (n.mood < 85)
        .sulk
    else
        .idle;
    return n;
}

test "pet: time makes it hungry and, when idle, sleepy" {
    var s = State{ .hunger = 200, .energy = 200, .mood = 190, .anim = .idle, .ms_idle = 0 };
    // Ten seconds of idle 100ms frames.
    var i: usize = 0;
    while (i < 100) : (i += 1) s = step(s, 100, .{});
    try std.testing.expect(s.hunger < 200); // got hungrier
    try std.testing.expect(s.energy < 200); // got sleepier (idle past 6s)
}

test "pet: petting a sulking pet lifts it out of the sulk (to content)" {
    var s = State{ .hunger = 40, .energy = 40, .mood = 20, .anim = .sulk, .ms_idle = 20000 };
    s = step(s, 16, .{ .petted = true, .interacted = true });
    try std.testing.expect(s.hunger > 40);
    try std.testing.expect(s.energy > 40);
    try std.testing.expect(s.mood >= 175); // recovered to a calm idle
    try std.testing.expectEqual(@as(u32, 0), s.ms_idle);
    try std.testing.expectEqual(Anim.idle, s.anim); // no longer sulking (the smile is the shell's reaction)
}

test "pet: an occasional toss is fun, but rapid-fire tossing upsets it" {
    // A single toss nudges the mood up a touch.
    var s = State{ .hunger = 255, .energy = 255, .mood = 180, .anim = .idle };
    const before = s.mood;
    s = step(s, 16, .{ .tossed = true, .interacted = true });
    try std.testing.expect(s.mood >= before);
    // Rapid-fire tossing (no time to decay the streak) sours the mood into a sulk.
    var r = State{ .hunger = 255, .energy = 255, .mood = 200, .anim = .idle };
    var i: usize = 0;
    while (i < 8) : (i += 1) r = step(r, 16, .{ .tossed = true, .interacted = true });
    try std.testing.expect(r.mood < 85);
    try std.testing.expectEqual(Anim.sulk, r.anim);
}

test "pet: sustained doom-scrolling drops the mood to sulking" {
    var s = State{ .hunger = 255, .energy = 255, .mood = 200, .anim = .idle, .ms_idle = 0 };
    var i: usize = 0;
    while (i < 60) : (i += 1) s = step(s, 100, .{ .scroll_ms = 100, .interacted = true });
    try std.testing.expect(s.mood < 85);
    try std.testing.expectEqual(Anim.sulk, s.anim);
}

test "pet: idle drains energy to sleep" {
    var s = State{ .hunger = 255, .energy = 255, .mood = 190, .anim = .idle, .ms_idle = 0 };
    var i: usize = 0;
    while (i < 300) : (i += 1) s = step(s, 100, .{}); // 30s idle
    try std.testing.expectEqual(Anim.sleep, s.anim);
}
