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

//! B1 classification: SHELL. THE SFX PLAYER — the desktop voice of the sound
//! vocabulary. Same actor pattern as `refresh_worker`/`write_worker`: its own
//! thread, a plain-data mailbox in, failure contained behind the boundary.
//!
//! WHY A THREAD: `audio_alsa.play` BLOCKS until the clip is handed to the
//! device (tens to hundreds of ms). On the render thread that would be the
//! very stall the whole architecture forbids (the "no blocking I/O on the UI
//! thread" law). So `play()` only drops an `Event` in the mailbox and returns;
//! this worker decodes and writes to ALSA off-frame.
//!
//! WHAT CROSSES THE BOUNDARY: `sfx.Event` values only — the clip bytes live in
//! the core table, the decode is pure, and the device handle never leaves this
//! module (E1/E2). If ALSA is absent the worker still drains the mailbox as a
//! no-op, so a machine with no audio simply makes no sound rather than
//! wedging.
//!
//! v1 is single-voice: one-shots play sequentially and a backlog is dropped
//! (a 41 ms keystroke tick rarely overlaps at typing speed). Concurrent mixing
//! is a later upgrade, not a correctness gap.

const std = @import("std");
const Allocator = std.mem.Allocator;
const sfx = @import("../core/sfx.zig");
const alsa = @import("audio_alsa.zig");
const clock = @import("clock.zig");
const write_worker = @import("write_worker.zig");

/// The clips are all this shape (core/sfx.zig guarantees it); the device is
/// opened once to match, and the decode asserts it.
const rate_hz: u32 = 24000;
const channels: u32 = 1;

pub const Inbox = write_worker.Mailbox(sfx.Event);

/// A7.2: cold struct, size guard waived — exactly one per session; holds the
/// device handle and the cross-thread flags, never sits in a collection.
pub const Player = struct {
    gpa: Allocator,
    inbox: *Inbox,
    thread: std.Thread,
    stop: std.atomic.Value(bool),
    /// UI-feedback clips (taps, keystrokes, likes) are silenced when this is
    /// false — the "Sound effects" setting. Alerts ignore it (they follow
    /// notification policy, added later).
    fx_on: std.atomic.Value(bool),
    /// Master kill for everything, e.g. a future "all sounds off" / phone
    /// silent switch. Independent of `fx_on`.
    all_on: std.atomic.Value(bool),
    /// The ringtone loops until cleared — set by `play(.ringtone)`, cleared by
    /// `stopRing`. Read every loop pass so a stop lands within one clip length.
    ring: std.atomic.Value(bool),
};

/// Start the worker. On success the caller owns the returned `*Player` and the
/// `inbox` it points at (declared on the caller's stack, like the other
/// workers' mailboxes).
pub fn start(gpa: Allocator, inbox: *Inbox, fx_on: bool) !*Player {
    const p = try gpa.create(Player);
    p.* = .{
        .gpa = gpa,
        .inbox = inbox,
        .thread = undefined,
        .stop = .init(false),
        .fx_on = .init(fx_on),
        .all_on = .init(true),
        .ring = .init(false),
    };
    p.thread = try std.Thread.spawn(.{}, threadMain, .{p});
    return p;
}

/// Enqueue a sound from the UI thread — returns immediately, never blocks.
/// The ringtone is a loop toggle rather than a queued one-shot so that a stop
/// can never sit behind a backlog.
pub fn play(p: *Player, event: sfx.Event) void {
    if (sfx.loops(event)) {
        p.ring.store(true, .release);
        return;
    }
    _ = p.inbox.push(p.gpa, event); // dropped on OOM — an inaudible loss
}

/// Stop the looping ringtone.
pub fn stopRing(p: *Player) void {
    p.ring.store(false, .release);
}

/// Mirror the "Sound effects" setting onto the worker.
pub fn setFxOn(p: *Player, on: bool) void {
    p.fx_on.store(on, .release);
}

/// Master gate for all audio (silent switch / global mute).
pub fn setAllOn(p: *Player, on: bool) void {
    p.all_on.store(on, .release);
}

pub fn shutdown(p: *Player) void {
    p.stop.store(true, .release);
    p.thread.join();
    // Drain and discard anything still queued (the events carry no owned
    // memory, so there is nothing to free — just clear the backlog). C5.
    var pending: std.ArrayList(sfx.Event) = .empty;
    defer pending.deinit(p.gpa);
    p.inbox.drain(p.gpa, &pending) catch {};
    p.gpa.destroy(p);
}

fn allowed(p: *Player, event: sfx.Event) bool {
    if (!p.all_on.load(.acquire)) return false;
    if (sfx.class(event) == .feedback and !p.fx_on.load(.acquire)) return false;
    return true;
}

fn threadMain(p: *Player) void {
    const gpa = p.gpa;

    // Open the device once. Absent ALSA -> `dev` stays null and every play is
    // a silent no-op, but the mailbox is still drained so it cannot grow.
    var dev: ?alsa.Pcm = alsa.open(alsa.stream_playback, rate_hz, channels, 40_000) catch null;
    defer if (dev) |*d| alsa.close(d);

    // Worker-owned scratch: decoded+gained samples for the current clip. Grown
    // as needed, freed at exit (C4/C5).
    var scratch: std.ArrayList(i16) = .empty;
    defer scratch.deinit(gpa);

    var batch: std.ArrayList(sfx.Event) = .empty;
    defer batch.deinit(gpa);

    while (!p.stop.load(.acquire)) {
        batch.clearRetainingCapacity();
        p.inbox.drain(gpa, &batch) catch {
            clock.sleepMillis(10);
            continue;
        };

        for (batch.items) |event| {
            if (p.stop.load(.acquire)) break;
            if (allowed(p, event)) voice(p, &dev, &scratch, event);
        }

        // Ringtone: play one pass per iteration while it is held on, so a
        // stopRing lands within a clip length. Gated the same as any alert.
        if (p.ring.load(.acquire) and allowed(p, .ringtone)) {
            voice(p, &dev, &scratch, .ringtone);
        } else if (batch.items.len == 0) {
            // Idle poll: a keystroke's tick tolerates 10 ms of latency
            // invisibly, and the thread otherwise sleeps.
            clock.sleepMillis(10);
        }
    }
}

/// Decode one clip, apply per-event × master gain into `scratch`, and hand it
/// to the device. Blocks for the clip's duration — that is the whole reason
/// this runs off the render thread. A malformed clip is skipped, not fatal.
fn voice(p: *Player, dev: *?alsa.Pcm, scratch: *std.ArrayList(i16), event: sfx.Event) void {
    var d = dev.* orelse return; // no device -> silent (mutable copy: play recovers on it)
    const f = sfx.decode(sfx.wavBytes(event)) catch return;
    const frames = sfx.frameCount(f);
    if (frames == 0) return;

    scratch.resize(p.gpa, frames) catch return;
    const gain: u32 = sfx.gainQ8(event); // 256 == unity
    var i: usize = 0;
    while (i < frames) : (i += 1) {
        const s = std.mem.readInt(i16, f.data[i * 2 ..][0..2], .little);
        const scaled = @divTrunc(@as(i32, s) * @as(i32, @intCast(gain)), 256);
        scratch.items[i] = @intCast(std.math.clamp(scaled, -32768, 32767));
    }
    alsa.play(&d, scratch.items, frames);
}

// ── tests (C6) — the boundary logic; no device, no sound ────────────────────

const testing = std.testing;

test "sfx_player: play enqueues one-shots and the ringtone toggles the loop" {
    const gpa = testing.allocator;
    var inbox: Inbox = .{};
    defer inbox.deinit(gpa);

    // A Player whose thread we never start — we only exercise the enqueue
    // logic, which must not touch the device.
    var p: Player = .{
        .gpa = gpa,
        .inbox = &inbox,
        .thread = undefined,
        .stop = .init(false),
        .fx_on = .init(true),
        .all_on = .init(true),
        .ring = .init(false),
    };

    play(&p, .key);
    play(&p, .like);
    try testing.expect(!p.ring.load(.acquire));

    play(&p, .ringtone); // a loop toggle, not a queued item
    try testing.expect(p.ring.load(.acquire));
    stopRing(&p);
    try testing.expect(!p.ring.load(.acquire));

    var out: std.ArrayList(sfx.Event) = .empty;
    defer out.deinit(gpa);
    try inbox.drain(gpa, &out);
    try testing.expectEqual(@as(usize, 2), out.items.len); // key + like, not ringtone
}

test "sfx_player: gating — fx toggle silences feedback but never alerts" {
    const gpa = testing.allocator;
    var inbox: Inbox = .{};
    defer inbox.deinit(gpa);
    var p: Player = .{
        .gpa = gpa,
        .inbox = &inbox,
        .thread = undefined,
        .stop = .init(false),
        .fx_on = .init(false), // "Sound effects" off
        .all_on = .init(true),
        .ring = .init(false),
    };

    try testing.expect(!allowed(&p, .key)); // feedback: silenced
    try testing.expect(!allowed(&p, .like));
    try testing.expect(allowed(&p, .notify)); // alert: still plays
    try testing.expect(allowed(&p, .ringtone));

    setAllOn(&p, false); // master kill
    try testing.expect(!allowed(&p, .notify));
    try testing.expect(!allowed(&p, .ringtone));
}
