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

//! B3 classification: SHELL. ALSA playback smoke (`zig build audio-smoke`).
//!
//! Plays a 1-second 440 Hz sine tone through the desktop speaker via
//! `shell/audio_alsa.zig`. Confirms the runtime `libasound` binding opens the
//! default device and streams S16 PCM — the audible check that the desktop
//! audio half of a call works, before it is wired into the media pipeline.

const std = @import("std");
const audio = @import("shell/audio_alsa.zig");

pub fn main(init: std.process.Init) !void {
    _ = init;
    const rate: u32 = 48000;
    const seconds: u32 = 1;
    const freq: f32 = 440.0;
    const amp: f32 = 8000.0; // ~1/4 scale — audible but not blaring

    if (!audio.available()) {
        std.debug.print("[audio] ALSA (libasound.so.2) not available on this machine\n", .{});
        return error.NoAudio;
    }
    var pcm = audio.open(audio.stream_playback, rate, 1, 100_000) catch |e| {
        std.debug.print("[audio] open failed: {s}\n", .{@errorName(e)});
        return e;
    };
    defer audio.close(&pcm);

    const n: usize = rate * seconds;
    var buf: [48000]i16 = undefined;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const t: f32 = @as(f32, @floatFromInt(i)) / @as(f32, @floatFromInt(rate));
        buf[i] = @intFromFloat(amp * std.math.sin(2.0 * std.math.pi * freq * t));
    }
    std.debug.print("[audio] playing a 1s 440Hz tone through the default output…\n", .{});
    audio.play(&pcm, buf[0..n], n);
    std.debug.print("[audio] done — did you hear a beep?\n", .{});
}
