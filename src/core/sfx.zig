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

//! B1 classification: CORE (pure). THE SOUND VOCABULARY — the mapping from a
//! semantic UI event (a tap, a like, an incoming message) to the audio clip
//! that voices it, plus the pure WAV decode that turns an embedded file into
//! playable PCM. No device, no clock, no thread: the shell (`sfx_player.zig`)
//! owns all of that and calls in here for the bytes.
//!
//! The clips are the curated Material Design set (CC-BY 4.0 — see
//! `assets/sounds/LICENSE.md`), embedded exactly the way the fonts and the
//! emoji atlas are (`@embedFile` via a build import), so the binary is
//! self-contained and there is no runtime file dependency. Every clip is the
//! same shape by construction (mono, 24 kHz, signed 16-bit LE) because we
//! resample them to it offline; `decode` still reads the real header rather
//! than trusting the offset, so a re-encoded asset can never silently misplay.
//!
//! PURE (B2): `wavBytes`/`gainQ8`/`class` are comptime table lookups and
//! `decode` is a total parse over a byte slice — all golden-tested headless.

const std = @import("std");
const assert = std.debug.assert;

/// The semantic events the app can voice. The enum *is* the table key; the
/// per-event data (which clip, how loud, what class) lives in the free
/// functions below — records are plain, behaviour is in functions (A1).
///
/// Explicit values so the ordering is a deliberate, stable fact rather than a
/// side effect of source position.
pub const Event = enum(u8) {
    // ── UI feedback: gated by the "Sound effects" setting ──
    tap = 0, // a generic press / button
    key = 1, // one keystroke on the in-app keyboard
    hover = 2, // pointer settling on a target (desktop)
    nav_forward = 3, // pushing into a screen / thread
    nav_back = 4, // popping back out
    like = 5, // a like lands
    unlike = 6, // a like is taken back
    send = 7, // a post / message leaves
    refresh = 8, // pull-to-refresh fires
    unavailable = 9, // a disabled / not-allowed target
    success = 10, // a multi-step flow completes (enrol, payment)
    // ── alerts: a separate class (see `class`), gated by notification policy ──
    msg_receive = 11, // an incoming chat message
    notify = 12, // a mention / social notification
    @"error" = 13, // something failed
    ringtone = 14, // an incoming Zat Chat call (loops)

    pub const count = @typeInfo(Event).@"enum".fields.len;
};

/// How an event is gated. UI feedback is silenced wholesale by the "Sound
/// effects" toggle; alerts follow notification/ringer policy instead (and on
/// phone, later, the system silent switch). Kept as plain data so the shell's
/// gating is a lookup, not a scattered set of special cases.
pub const Class = enum(u8) { feedback, alert };

pub fn class(e: Event) Class {
    return switch (e) {
        .msg_receive, .notify, .ringtone => .alert,
        else => .feedback,
    };
}

/// True for clips meant to play on repeat until dismissed (the ringtone). The
/// player loops these instead of firing once.
pub fn loops(e: Event) bool {
    return e == .ringtone;
}

// ── embedded clips (build wires these imports; see build.zig addSounds) ──
const wav_tap = @embedFile("sfx_tap");
const wav_key = @embedFile("sfx_key");
const wav_hover = @embedFile("sfx_hover");
const wav_nav_forward = @embedFile("sfx_nav_forward");
const wav_nav_back = @embedFile("sfx_nav_back");
const wav_like = @embedFile("sfx_like");
const wav_unlike = @embedFile("sfx_unlike");
const wav_send = @embedFile("sfx_send");
const wav_refresh = @embedFile("sfx_refresh");
const wav_unavailable = @embedFile("sfx_unavailable");
const wav_success = @embedFile("sfx_success");
const wav_msg_receive = @embedFile("sfx_msg_receive");
const wav_notify = @embedFile("sfx_notify");
const wav_error = @embedFile("sfx_error");
const wav_ringtone = @embedFile("sfx_ringtone");

/// The raw embedded WAV bytes for an event.
pub fn wavBytes(e: Event) []const u8 {
    return switch (e) {
        .tap => wav_tap,
        .key => wav_key,
        .hover => wav_hover,
        .nav_forward => wav_nav_forward,
        .nav_back => wav_nav_back,
        .like => wav_like,
        .unlike => wav_unlike,
        .send => wav_send,
        .refresh => wav_refresh,
        .unavailable => wav_unavailable,
        .success => wav_success,
        .msg_receive => wav_msg_receive,
        .notify => wav_notify,
        .@"error" => wav_error,
        .ringtone => wav_ringtone,
    };
}

/// Per-event playback gain, fixed-point where 256 == unity. The Google set is
/// already balanced across itself, so most events play at unity; the constant
/// ticks are pulled down because they fire many times a second and want to sit
/// under the interface, not on top of it. Final master volume is the shell's.
pub fn gainQ8(e: Event) u16 {
    return switch (e) {
        .key => 140, // ~0.55 — a keystroke is a whisper, not an event
        .tap, .hover => 180, // ~0.70
        .unavailable => 200,
        else => 256, // unity
    };
}

/// A decoded clip: the interleaved PCM sample bytes plus the format read from
/// the header. `data` still borrows the embedded bytes — decode neither copies
/// nor allocates (C2); the shell reads samples straight out of it.
pub const Format = struct {
    data: []const u8,
    rate: u32,
    channels: u16,
    bits: u16,

    comptime {
        // Budget: a borrowed slice (16) + a u32 + two u16 = 24, no padding.
        // Cold (one transient per decode), but guarded anyway — it is cheap and
        // catches a stray field before it becomes a habit.
        assert(@sizeOf(Format) == 24);
    }
};

pub const DecodeError = error{ NotRiff, NotWave, Truncated, NoFmt, NoData, Unsupported };

fn rdU32(b: []const u8, off: usize) u32 {
    return std.mem.readInt(u32, b[off..][0..4], .little);
}
fn rdU16(b: []const u8, off: usize) u16 {
    return std.mem.readInt(u16, b[off..][0..2], .little);
}

/// Parse a canonical RIFF/WAVE PCM file into `Format`. TOTAL over arbitrary
/// bytes: every malformed input is a named error, never a panic or a bad slice
/// (E3). Walks the chunk list rather than assuming a 44-byte header, so an
/// asset carrying an extra `LIST`/`fact` chunk still decodes.
pub fn decode(bytes: []const u8) DecodeError!Format {
    if (bytes.len < 12) return error.Truncated;
    if (!std.mem.eql(u8, bytes[0..4], "RIFF")) return error.NotRiff;
    if (!std.mem.eql(u8, bytes[8..12], "WAVE")) return error.NotWave;

    var rate: u32 = 0;
    var channels: u16 = 0;
    var bits: u16 = 0;
    var have_fmt = false;
    var data: ?[]const u8 = null;

    var off: usize = 12;
    while (off + 8 <= bytes.len) {
        const id = bytes[off .. off + 4];
        const size = rdU32(bytes, off + 4);
        const body = off + 8;
        if (body + size > bytes.len) return error.Truncated;
        if (std.mem.eql(u8, id, "fmt ")) {
            if (size < 16) return error.Unsupported;
            const audio_format = rdU16(bytes, body);
            if (audio_format != 1) return error.Unsupported; // PCM only
            channels = rdU16(bytes, body + 2);
            rate = rdU32(bytes, body + 4);
            bits = rdU16(bytes, body + 14);
            have_fmt = true;
        } else if (std.mem.eql(u8, id, "data")) {
            data = bytes[body .. body + size];
        }
        // Chunks are word-aligned: an odd size carries a pad byte.
        off = body + size + (size & 1);
    }

    if (!have_fmt) return error.NoFmt;
    const d = data orelse return error.NoData;
    if (bits != 16 or channels == 0) return error.Unsupported;
    return .{ .data = d, .rate = rate, .channels = channels, .bits = bits };
}

/// Sample count (per channel) of a decoded 16-bit clip.
pub fn frameCount(f: Format) usize {
    return f.data.len / (@as(usize, f.bits / 8) * f.channels);
}

// ── tests (pure, headless) ──────────────────────────────────────────────────

const testing = std.testing;

test "sfx: every event has non-empty bytes and decodes to our house format" {
    inline for (std.meta.fields(Event)) |field| {
        const e: Event = @enumFromInt(field.value);
        const raw = wavBytes(e);
        try testing.expect(raw.len > 44);
        const f = try decode(raw);
        // The whole set is resampled to this shape offline; if a re-encode
        // drifts, this is where we find out rather than in the speaker.
        try testing.expectEqual(@as(u16, 1), f.channels);
        try testing.expectEqual(@as(u32, 24000), f.rate);
        try testing.expectEqual(@as(u16, 16), f.bits);
        try testing.expect(frameCount(f) > 0);
    }
}

test "sfx: classes and looping are assigned as designed" {
    try testing.expectEqual(Class.feedback, class(.key));
    try testing.expectEqual(Class.feedback, class(.like));
    try testing.expectEqual(Class.alert, class(.ringtone));
    try testing.expectEqual(Class.alert, class(.msg_receive));
    try testing.expect(loops(.ringtone));
    try testing.expect(!loops(.tap));
}

test "sfx: the keystroke tick is quieter than a unity event" {
    try testing.expect(gainQ8(.key) < gainQ8(.like));
    try testing.expectEqual(@as(u16, 256), gainQ8(.like));
}

test "sfx: decode rejects malformed input as named errors, never panics" {
    try testing.expectError(error.Truncated, decode(""));
    try testing.expectError(error.NotRiff, decode("XXXXxxxxWAVE"));
    try testing.expectError(error.NotWave, decode("RIFF\x00\x00\x00\x00XXXX"));
    // RIFF/WAVE header but no chunks at all -> no fmt.
    try testing.expectError(error.NoFmt, decode("RIFF\x04\x00\x00\x00WAVE"));
}

test "sfx: decode walks past an unknown chunk to reach fmt and data" {
    // RIFF header, then a bogus "LIST" chunk (4 bytes), then fmt + data, laid
    // out by hand so the test depends on nothing but the parser.
    var buf: [64]u8 = undefined;
    var n: usize = 0;
    const put = struct {
        fn s(b: []u8, o: *usize, str: []const u8) void {
            @memcpy(b[o.*..][0..str.len], str);
            o.* += str.len;
        }
        fn u32le(b: []u8, o: *usize, v: u32) void {
            std.mem.writeInt(u32, b[o.*..][0..4], v, .little);
            o.* += 4;
        }
        fn u16le(b: []u8, o: *usize, v: u16) void {
            std.mem.writeInt(u16, b[o.*..][0..2], v, .little);
            o.* += 2;
        }
    };
    put.s(&buf, &n, "RIFF");
    put.u32le(&buf, &n, 0); // riff size (unused by decode)
    put.s(&buf, &n, "WAVE");
    put.s(&buf, &n, "LIST"); // unknown chunk decode must skip
    put.u32le(&buf, &n, 4);
    put.s(&buf, &n, "junk");
    put.s(&buf, &n, "fmt ");
    put.u32le(&buf, &n, 16);
    put.u16le(&buf, &n, 1); // PCM
    put.u16le(&buf, &n, 1); // mono
    put.u32le(&buf, &n, 24000); // rate
    put.u32le(&buf, &n, 48000); // byte rate
    put.u16le(&buf, &n, 2); // block align
    put.u16le(&buf, &n, 16); // bits
    put.s(&buf, &n, "data");
    put.u32le(&buf, &n, 4);
    put.u16le(&buf, &n, 1000);
    put.u16le(&buf, &n, 0xFC18); // -1000 as u16 LE

    const f = try decode(buf[0..n]);
    try testing.expectEqual(@as(u32, 24000), f.rate);
    try testing.expectEqual(@as(usize, 2), frameCount(f));
}
