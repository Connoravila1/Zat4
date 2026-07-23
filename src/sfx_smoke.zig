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

//! SFX audition harness (`zig build sfx-smoke`): starts the real player worker
//! and plays every clip in turn through the actual ALSA path, printing the
//! event name as each fires. This is the "hear the curated set" tool — the same
//! role gpu-smoke plays for the GPU bring-up. Needs a working audio device.
//!
//! It exercises the whole audio stack end to end: the core event table, the
//! pure WAV decode, the shell worker, and ALSA — so a regression anywhere shows
//! up here as silence or a wrong sound, live.

const std = @import("std");
const sfx = @import("core/sfx.zig");
const sfx_player = @import("shell/sfx_player.zig");
const clock = @import("shell/clock.zig");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const stdout = std.debug;

    var inbox: sfx_player.Inbox = .{};
    defer inbox.deinit(gpa);

    const player = sfx_player.start(gpa, &inbox, true) catch |e| {
        stdout.print("[sfx] player start failed: {s}\n", .{@errorName(e)});
        return;
    };
    defer sfx_player.shutdown(player);

    stdout.print("[sfx] auditioning {d} clips (24 kHz mono)\n", .{sfx.Event.count});

    // Every one-shot in enum order, spaced so each is heard on its own.
    inline for (std.meta.fields(sfx.Event)) |field| {
        const e: sfx.Event = @enumFromInt(field.value);
        if (!sfx.loops(e)) {
            stdout.print("  {s}\n", .{field.name});
            sfx_player.play(player, e);
            clock.sleepMillis(1100);
        }
    }

    // The looping ringtone: let it ring for a few seconds, then stop it.
    stdout.print("  ringtone (3s loop)\n", .{});
    sfx_player.play(player, .ringtone);
    clock.sleepMillis(3000);
    sfx_player.stopRing(player);
    clock.sleepMillis(300);

    stdout.print("[sfx] done\n", .{});
}
