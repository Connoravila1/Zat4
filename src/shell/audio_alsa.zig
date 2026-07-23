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

//! B3 classification: SHELL (impure). The Linux desktop audio device — mic
//! capture and speaker playback via ALSA (`libasound.so.2`), loaded with
//! `dlopen` at runtime exactly like the GPU/keystore shims (no `-dev` package,
//! no link-time dependency). This is the desktop half of a call's audio; the
//! Android half is AAudio in the app. It deals only in interleaved signed
//! 16-bit PCM; codecs and the media pipeline live elsewhere (`core/rtp`,
//! `core/srtp`, `core/jitter`).
//!
//! Only libc/dl symbols are used through hand-declared externs; ALSA itself is
//! resolved at runtime and degrades to "unavailable" (null) if the library is
//! absent, so a machine without ALSA simply has no desktop audio rather than a
//! link failure.

const std = @import("std");
const builtin = @import("builtin");

// ALSA + the `dl` loader are Linux-only. On any other target this shim is
// present but inert (`load` returns null → `available()` is false → no audio),
// so the client — which now reaches this module via the SFX player — links
// clean when cross-compiled for Windows/macOS. The `dlopen`/`dlsym` CALLS live
// behind a comptime `is_linux` branch below so they are never codegen'd off
// Linux (an unreferenced extern declaration creates no linker dependency).
const is_linux = builtin.os.tag == .linux;

extern fn dlopen(path: [*:0]const u8, mode: c_int) callconv(.c) ?*anyopaque;
extern fn dlsym(handle: ?*anyopaque, symbol: [*:0]const u8) callconv(.c) ?*anyopaque;
const RTLD_NOW: c_int = 2;

const snd_pcm_t = anyopaque;

// snd_pcm_stream_t
pub const stream_playback: c_int = 0;
pub const stream_capture: c_int = 1;
// snd_pcm_format_t: S16_LE
const format_s16_le: c_int = 2;
// snd_pcm_access_t: RW_INTERLEAVED
const access_rw_interleaved: c_int = 3;

const OpenFn = *const fn (**snd_pcm_t, [*:0]const u8, c_int, c_int) callconv(.c) c_int;
const SetParamsFn = *const fn (*snd_pcm_t, c_int, c_int, c_uint, c_uint, c_int, c_uint) callconv(.c) c_int;
const WriteiFn = *const fn (*snd_pcm_t, *const anyopaque, c_ulong) callconv(.c) c_long;
const ReadiFn = *const fn (*snd_pcm_t, *anyopaque, c_ulong) callconv(.c) c_long;
const RecoverFn = *const fn (*snd_pcm_t, c_int, c_int) callconv(.c) c_int;
const PrepareFn = *const fn (*snd_pcm_t) callconv(.c) c_int;
const DrainFn = *const fn (*snd_pcm_t) callconv(.c) c_int;
const CloseFn = *const fn (*snd_pcm_t) callconv(.c) c_int;

/// A7.2: cold struct, size guard waived — the resolved libasound entry points,
/// one process-wide instance.
const Lib = struct {
    open: OpenFn,
    set_params: SetParamsFn,
    writei: WriteiFn,
    readi: ReadiFn,
    recover: RecoverFn,
    prepare: PrepareFn,
    drain: DrainFn,
    close: CloseFn,
};

var cached: ?Lib = null;
var tried: bool = false;

fn load() ?Lib {
    if (cached) |l| return l;
    if (tried) return null;
    tried = true;
    // Comptime-false off Linux → this whole branch is never analyzed or
    // codegen'd there, so `dlopen`/`dlsym` are not referenced and the
    // Windows/macOS client links clean.
    if (is_linux) {
        const lib = dlopen("libasound.so.2", RTLD_NOW) orelse return null;
        cached = .{
            .open = @ptrCast(@alignCast(dlsym(lib, "snd_pcm_open") orelse return null)),
            .set_params = @ptrCast(@alignCast(dlsym(lib, "snd_pcm_set_params") orelse return null)),
            .writei = @ptrCast(@alignCast(dlsym(lib, "snd_pcm_writei") orelse return null)),
            .readi = @ptrCast(@alignCast(dlsym(lib, "snd_pcm_readi") orelse return null)),
            .recover = @ptrCast(@alignCast(dlsym(lib, "snd_pcm_recover") orelse return null)),
            .prepare = @ptrCast(@alignCast(dlsym(lib, "snd_pcm_prepare") orelse return null)),
            .drain = @ptrCast(@alignCast(dlsym(lib, "snd_pcm_drain") orelse return null)),
            .close = @ptrCast(@alignCast(dlsym(lib, "snd_pcm_close") orelse return null)),
        };
        return cached;
    }
    return null;
}

/// True if ALSA is present on this machine.
pub fn available() bool {
    return load() != null;
}

/// A7.2: cold struct, size guard waived — one per open stream, holds an OS
/// handle; never in a collection.
pub const Pcm = struct {
    handle: *snd_pcm_t,
    lib: Lib,
    channels: u32,
};

pub const OpenError = error{ Unavailable, OpenFailed, ConfigFailed };

/// Open the default device for `stream` at `rate` Hz / `channels`, targeting
/// roughly `latency_us` microseconds of buffering (ALSA's simple setup path).
pub fn open(stream: c_int, rate: u32, channels: u32, latency_us: u32) OpenError!Pcm {
    const lib = load() orelse return error.Unavailable;
    var h: *snd_pcm_t = undefined;
    if (lib.open(&h, "default", stream, 0) < 0) return error.OpenFailed;
    if (lib.set_params(h, format_s16_le, access_rw_interleaved, channels, rate, 1, latency_us) < 0) {
        _ = lib.close(h);
        return error.ConfigFailed;
    }
    return .{ .handle = h, .lib = lib, .channels = channels };
}

pub fn close(p: *Pcm) void {
    _ = p.lib.drain(p.handle);
    _ = p.lib.close(p.handle);
    p.* = undefined;
}

/// Play `frames` of interleaved S16 samples (`buf.len == frames * channels`),
/// recovering from underruns. Blocks until the buffer is handed to the device.
pub fn play(p: *Pcm, buf: []const i16, frames: usize) void {
    var off: usize = 0; // in frames
    while (off < frames) {
        const ptr: *const anyopaque = @ptrCast(buf.ptr + off * p.channels);
        const rc = p.lib.writei(p.handle, ptr, @intCast(frames - off));
        if (rc < 0) {
            _ = p.lib.recover(p.handle, @intCast(rc), 1);
            continue;
        }
        off += @intCast(rc);
    }
}

/// Capture up to `frames` of interleaved S16 samples into `buf`, recovering
/// from overruns. Returns the frames actually read.
pub fn capture(p: *Pcm, buf: []i16, frames: usize) usize {
    while (true) {
        const ptr: *anyopaque = @ptrCast(buf.ptr);
        const rc = p.lib.readi(p.handle, ptr, @intCast(frames));
        if (rc < 0) {
            _ = p.lib.recover(p.handle, @intCast(rc), 1);
            continue;
        }
        return @intCast(rc);
    }
}
