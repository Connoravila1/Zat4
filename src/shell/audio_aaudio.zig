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

//! B3 classification: SHELL (impure). The **Android** audio-playback device —
//! the phone counterpart to `audio_alsa` (the desktop half). Same posture: the
//! library (`libaaudio.so`, present on every Android since API 26) is resolved
//! with `dlopen` at runtime, not linked, so there is no NDK -dev dependency and
//! a device without it degrades to "unavailable" (null) rather than a link or
//! load failure. It deals only in interleaved signed 16-bit PCM.
//!
//! It exposes the SAME surface as `audio_alsa` (`stream_playback`/
//! `stream_capture`, `Pcm`, `open`/`close`/`play`/`capture`) so `sfx_player`
//! (playback only) and the calling engine (which also captures the mic) select
//! one backend or the other at comptime by target and use it through one name.
//!
//! The `dlopen`/`dlsym` CALLS live behind a comptime `is_android` branch, so on
//! any other target this module is present but inert (open returns Unavailable)
//! and references no Android symbols — it compiles and links clean everywhere,
//! exactly like `audio_alsa`'s Linux gate.

const std = @import("std");
const builtin = @import("builtin");

const is_android = builtin.abi.isAndroid();

extern fn dlopen(path: [*:0]const u8, mode: c_int) callconv(.c) ?*anyopaque;
extern fn dlsym(handle: ?*anyopaque, symbol: [*:0]const u8) callconv(.c) ?*anyopaque;
const RTLD_NOW: c_int = 2;

const AAudioStreamBuilder = anyopaque;
const AAudioStream = anyopaque;

// Interface parity with audio_alsa: the direction tag sfx passes to `open`.
// AAudio's AAUDIO_DIRECTION_OUTPUT is 0.
pub const stream_playback: c_int = 0;
pub const stream_capture: c_int = 1;

// aaudio constants (aaudio/AAudio.h)
const AAUDIO_OK: i32 = 0;
const AAUDIO_DIRECTION_OUTPUT: i32 = 0;
const AAUDIO_DIRECTION_INPUT: i32 = 1;
const AAUDIO_FORMAT_PCM_I16: i32 = 1;
const AAUDIO_PERFORMANCE_MODE_LOW_LATENCY: i32 = 12;

const CreateBuilderFn = *const fn (**AAudioStreamBuilder) callconv(.c) i32;
const SetI32Fn = *const fn (*AAudioStreamBuilder, i32) callconv(.c) void;
const OpenStreamFn = *const fn (*AAudioStreamBuilder, **AAudioStream) callconv(.c) i32;
const BuilderResultFn = *const fn (*AAudioStreamBuilder) callconv(.c) i32;
const StreamResultFn = *const fn (*AAudioStream) callconv(.c) i32;
const WriteFn = *const fn (*AAudioStream, *const anyopaque, i32, i64) callconv(.c) i32;
const ReadFn = *const fn (*AAudioStream, *anyopaque, i32, i64) callconv(.c) i32;

/// A7.2: cold struct, size guard waived — the resolved libaaudio entry points,
/// one process-wide instance.
const Lib = struct {
    create_builder: CreateBuilderFn,
    set_direction: SetI32Fn,
    set_format: SetI32Fn,
    set_sample_rate: SetI32Fn,
    set_channel_count: SetI32Fn,
    set_performance_mode: SetI32Fn,
    open_stream: OpenStreamFn,
    builder_delete: BuilderResultFn,
    request_start: StreamResultFn,
    request_stop: StreamResultFn,
    stream_close: StreamResultFn,
    write: WriteFn,
    read: ReadFn,
};

var cached: ?Lib = null;
var tried: bool = false;

fn load() ?Lib {
    if (cached) |l| return l;
    if (tried) return null;
    tried = true;
    // Comptime-false off Android → this branch is never analyzed or codegen'd,
    // so no AAudio/dl symbol is referenced and every other target links clean.
    if (is_android) {
        const lib = dlopen("libaaudio.so", RTLD_NOW) orelse return null;
        cached = .{
            .create_builder = @ptrCast(@alignCast(dlsym(lib, "AAudio_createStreamBuilder") orelse return null)),
            .set_direction = @ptrCast(@alignCast(dlsym(lib, "AAudioStreamBuilder_setDirection") orelse return null)),
            .set_format = @ptrCast(@alignCast(dlsym(lib, "AAudioStreamBuilder_setFormat") orelse return null)),
            .set_sample_rate = @ptrCast(@alignCast(dlsym(lib, "AAudioStreamBuilder_setSampleRate") orelse return null)),
            .set_channel_count = @ptrCast(@alignCast(dlsym(lib, "AAudioStreamBuilder_setChannelCount") orelse return null)),
            .set_performance_mode = @ptrCast(@alignCast(dlsym(lib, "AAudioStreamBuilder_setPerformanceMode") orelse return null)),
            .open_stream = @ptrCast(@alignCast(dlsym(lib, "AAudioStreamBuilder_openStream") orelse return null)),
            .builder_delete = @ptrCast(@alignCast(dlsym(lib, "AAudioStreamBuilder_delete") orelse return null)),
            .request_start = @ptrCast(@alignCast(dlsym(lib, "AAudioStream_requestStart") orelse return null)),
            .request_stop = @ptrCast(@alignCast(dlsym(lib, "AAudioStream_requestStop") orelse return null)),
            .stream_close = @ptrCast(@alignCast(dlsym(lib, "AAudioStream_close") orelse return null)),
            .write = @ptrCast(@alignCast(dlsym(lib, "AAudioStream_write") orelse return null)),
            .read = @ptrCast(@alignCast(dlsym(lib, "AAudioStream_read") orelse return null)),
        };
        return cached;
    }
    return null;
}

/// True if AAudio is present (Android only).
pub fn available() bool {
    return load() != null;
}

/// A7.2: cold struct, size guard waived — one per open stream, holds an OS
/// handle; never in a collection.
pub const Pcm = struct {
    stream: *AAudioStream,
    lib: Lib,
    channels: u32,
};

pub const OpenError = error{ Unavailable, OpenFailed, ConfigFailed };

/// Open a playback OR capture stream at `rate` Hz / `channels`, interleaved
/// S16. `stream` selects the direction (`stream_playback` / `stream_capture`);
/// `latency_us` is accepted for interface parity with the ALSA shim (AAudio
/// picks its own buffer from the performance-mode hint). Capture is what the
/// calling engine uses for the mic; the SFX player only ever opens playback.
pub fn open(stream: c_int, rate: u32, channels: u32, latency_us: u32) OpenError!Pcm {
    _ = latency_us;
    const lib = load() orelse return error.Unavailable;

    var builder: *AAudioStreamBuilder = undefined;
    if (lib.create_builder(&builder) != AAUDIO_OK) return error.OpenFailed;
    // The builder is finished with the moment the stream opens; deleted on
    // every path below.
    lib.set_direction(builder, if (stream == stream_capture) AAUDIO_DIRECTION_INPUT else AAUDIO_DIRECTION_OUTPUT);
    lib.set_format(builder, AAUDIO_FORMAT_PCM_I16);
    lib.set_sample_rate(builder, @intCast(rate));
    lib.set_channel_count(builder, @intCast(channels));
    lib.set_performance_mode(builder, AAUDIO_PERFORMANCE_MODE_LOW_LATENCY);

    var s: *AAudioStream = undefined;
    const rc = lib.open_stream(builder, &s);
    _ = lib.builder_delete(builder);
    if (rc != AAUDIO_OK) return error.ConfigFailed;

    if (lib.request_start(s) != AAUDIO_OK) {
        _ = lib.stream_close(s);
        return error.ConfigFailed;
    }
    return .{ .stream = s, .lib = lib, .channels = channels };
}

pub fn close(p: *Pcm) void {
    _ = p.lib.request_stop(p.stream);
    _ = p.lib.stream_close(p.stream);
    p.* = undefined;
}

/// Play `frames` of interleaved S16 (`buf.len == frames * channels`). Blocks
/// until the buffer is handed to the device (a bounded per-write timeout).
/// A negative result is a device error — contained by stopping this clip (E2),
/// never a crash.
pub fn play(p: *Pcm, buf: []const i16, frames: usize) void {
    const timeout_ns: i64 = 1_000_000_000; // 1s: ample for one short UI clip
    var off: usize = 0; // in frames
    while (off < frames) {
        const ptr: *const anyopaque = @ptrCast(buf.ptr + off * p.channels);
        const wrote = p.lib.write(p.stream, ptr, @intCast(frames - off), timeout_ns);
        if (wrote <= 0) return; // error or timeout → drop the rest of this clip
        off += @intCast(wrote);
    }
}

/// Capture up to `frames` of interleaved S16 into `buf` (a blocking read with a
/// bounded timeout). Returns the frames actually read (0 on error/timeout — the
/// caller sends silence rather than crashing, E2). The calling engine's mic path
/// on Android; the ALSA shim has the matching `capture` on the desktop.
pub fn capture(p: *Pcm, buf: []i16, frames: usize) usize {
    const timeout_ns: i64 = 200_000_000; // 200ms: well over one 10ms frame
    const ptr: *anyopaque = @ptrCast(buf.ptr);
    const got = p.lib.read(p.stream, ptr, @intCast(frames), timeout_ns);
    if (got <= 0) return 0;
    return @intCast(got);
}
