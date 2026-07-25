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

//! B3 classification: SHELL (impure). THE SEALED AUDIO CODEC (D1) — the only
//! place in the tree that knows Opus exists. Everything above it speaks PCM
//! frames in and opaque payload bytes out; the RTP layer knows only a payload
//! type number. Swapping codecs is a rewrite of this file and nothing else.
//!
//! WHY THIS EXISTS: the call used to put raw S16 PCM on the wire. That pins the
//! cellular radio in continuous reception for the whole call, which is the
//! dominant battery cost (ZAT_CHAT_CALLING_ROADMAP §5), and leaves no gaps for
//! any of the pacing work in §5/§10 to exploit.
//!
//! MEASURED (G1), 48 kHz mono, per 20 ms of speech at the 32 kbps default:
//!
//!     payload    raw 1920 B  ->  coded 77 B          24.9x
//!     on-wire    812.8 kbps  ->  53.2 kbps           15.3x
//!     in silence               ->  23.2 kbps (DTX)   35.0x
//!
//! The on-wire figure counts the fixed 56 B of RTP + SRTP tag + UDP + IP that
//! rides every packet, and the halving of the packet RATE (10 ms frames became
//! 20 ms ones). It is deliberately the smaller, honest number: the payload
//! shrinks 25x but the headers do not, so the wire only shrinks 15x.
//!
//! That residue is itself the signpost for what comes next — 56 of every 133
//! bytes is now header, so batching packets (§5, §10.1) has real leverage where
//! against an 810 kbps stream it had almost none.
//!
//! C1/C2 — NO HIDDEN ALLOCATION. Opus offers `opus_encoder_create`, which
//! mallocs behind our back. We deliberately use the `get_size` + `init` pair
//! instead, so the codec state comes from OUR allocator and is visible at the
//! call site like every other allocation in the project.
//!
//! The dependency itself is justified in `build.zig`'s `addOpus` (F1).

const std = @import("std");
const Allocator = std.mem.Allocator;

const c = @cImport({
    @cInclude("opus.h");
});

/// The one sample rate the call runs at. Opus is internally 48 kHz for
/// fullband; matching it means no resampling anywhere in the path.
pub const sample_rate: u32 = 48_000;

/// 20 ms at 48 kHz. Opus's natural voice frame, and the interval `call_engine`'s
/// RTP timestamp advance already assumes. (Smaller frames cut latency slightly
/// but cost proportionally more packet overhead and more radio wakeups — the
/// wrong trade for a battery-first call.)
pub const frame_samples: u32 = 960;

/// The largest packet a single Opus frame can produce (RFC 6716 §3.2). Callers
/// size their scratch buffer with this; a 48 kbps voice frame is nearer 120
/// bytes, so this is a ceiling, not an expectation.
pub const max_packet_bytes: usize = 1275;

/// Opus state wants the alignment of the widest scalar it stores. 16 covers
/// every target we build for, and over-aligning costs a handful of bytes once
/// per call.
const state_align: std.mem.Alignment = .@"16";

pub const Error = error{
    /// Opus rejected the configuration or the buffer (bad rate, bad channel
    /// count, frame size that is not a legal Opus duration).
    OpusBadArgument,
    /// Opus failed internally — a corrupt packet, or state we cannot recover.
    OpusFailed,
};

// The C surface. Declared by hand rather than pulled wholesale so the exact
// set of Opus entry points this file may use is visible in one place.
extern fn opus_encoder_get_size(channels: c_int) c_int;
extern fn opus_encoder_init(st: *anyopaque, fs: i32, channels: c_int, application: c_int) c_int;
extern fn opus_encode(st: *anyopaque, pcm: [*]const i16, frame_size: c_int, data: [*]u8, max_data_bytes: i32) i32;
extern fn opus_encoder_ctl(st: *anyopaque, request: c_int, ...) c_int;
extern fn opus_decoder_get_size(channels: c_int) c_int;
extern fn opus_decoder_init(st: *anyopaque, fs: i32, channels: c_int) c_int;
extern fn opus_decode(st: *anyopaque, data: ?[*]const u8, len: i32, pcm: [*]i16, frame_size: c_int, decode_fec: c_int) c_int;

/// PLAIN DATA (A1). One direction's encoder. A7.2: cold struct, size guard
/// waived — one per call, never in a collection. `state` is Opus's opaque
/// working memory, owned by us.
pub const Encoder = struct {
    state: []align(16) u8,
    channels: u8,
};

/// PLAIN DATA (A1). One direction's decoder. A7.2: cold struct, size guard
/// waived — one per call.
pub const Decoder = struct {
    state: []align(16) u8,
    channels: u8,
};

/// Bring up an encoder tuned for a voice call: VoIP application, voice signal
/// hint, in-band FEC on (so a lost packet is reconstructible from the next
/// one), and DTX on — DTX is the one that matters for battery, because it stops
/// sending almost entirely during silence, which is most of a conversation for
/// one side at a time.
pub fn encoderInit(gpa: Allocator, e: *Encoder, channels: u8, bitrate_bps: i32) !void {
    const size = opus_encoder_get_size(@intCast(channels));
    if (size <= 0) return Error.OpusBadArgument;

    const state = try gpa.alignedAlloc(u8, state_align, @intCast(size));
    errdefer gpa.free(state);

    if (opus_encoder_init(state.ptr, @intCast(sample_rate), @intCast(channels), c.OPUS_APPLICATION_VOIP) != c.OPUS_OK)
        return Error.OpusBadArgument;

    e.* = .{ .state = state, .channels = channels };

    // Configuration failures here are not fatal — Opus keeps working at its
    // defaults — so they are applied and not checked individually (E4).
    _ = opus_encoder_ctl(state.ptr, c.OPUS_SET_BITRATE_REQUEST, @as(i32, bitrate_bps));
    _ = opus_encoder_ctl(state.ptr, c.OPUS_SET_SIGNAL_REQUEST, @as(i32, c.OPUS_SIGNAL_VOICE));
    _ = opus_encoder_ctl(state.ptr, c.OPUS_SET_INBAND_FEC_REQUEST, @as(i32, 1));
    _ = opus_encoder_ctl(state.ptr, c.OPUS_SET_DTX_REQUEST, @as(i32, 1));
    // Complexity trades CPU for quality at a given bitrate. 5 is the middle of
    // the 0–10 range: clearly better than the low end, and well short of the
    // top where cost climbs faster than perceived quality. A battery-first
    // default; G2 says tune it against a measurement, not a guess.
    _ = opus_encoder_ctl(state.ptr, c.OPUS_SET_COMPLEXITY_REQUEST, @as(i32, 5));
}

pub fn encoderDeinit(gpa: Allocator, e: *Encoder) void {
    gpa.free(e.state);
    e.* = undefined;
}

/// Retarget the encoder mid-call. This is the knob the adaptive brain
/// (`core/call_decision.zig`) drives: its `audio_bitrate_kbps` output lands
/// here. Opus applies it on the next frame with no glitch and no renegotiation.
pub fn setBitrate(e: *Encoder, bitrate_bps: i32) void {
    _ = opus_encoder_ctl(e.state.ptr, c.OPUS_SET_BITRATE_REQUEST, bitrate_bps);
}

/// Tell the encoder how lossy the path is, so it can size its in-band FEC to
/// match. Fed from the congestion estimator's measured loss.
pub fn setExpectedLoss(e: *Encoder, percent: u8) void {
    _ = opus_encoder_ctl(e.state.ptr, c.OPUS_SET_PACKET_LOSS_PERC_REQUEST, @as(i32, @min(percent, 100)));
}

/// Compress exactly one frame. `pcm` must be `frame_samples * channels` long.
/// Returns the slice of `out` that was written.
///
/// A return of 1..2 bytes is NOT an error: that is Opus's DTX comfort-noise
/// packet, meaning "still silent." Whether to put it on the wire is the
/// caller's decision, not the codec's.
pub fn encode(e: *Encoder, pcm: []const i16, out: []u8) Error![]const u8 {
    if (pcm.len != frame_samples * e.channels) return Error.OpusBadArgument;
    const n = opus_encode(e.state.ptr, pcm.ptr, @intCast(frame_samples), out.ptr, @intCast(@min(out.len, max_packet_bytes)));
    if (n < 0) return Error.OpusFailed;
    return out[0..@intCast(n)];
}

pub fn decoderInit(gpa: Allocator, d: *Decoder, channels: u8) !void {
    const size = opus_decoder_get_size(@intCast(channels));
    if (size <= 0) return Error.OpusBadArgument;

    const state = try gpa.alignedAlloc(u8, state_align, @intCast(size));
    errdefer gpa.free(state);

    if (opus_decoder_init(state.ptr, @intCast(sample_rate), @intCast(channels)) != c.OPUS_OK)
        return Error.OpusBadArgument;

    d.* = .{ .state = state, .channels = channels };
}

pub fn decoderDeinit(gpa: Allocator, d: *Decoder) void {
    gpa.free(d.state);
    d.* = undefined;
}

/// Decompress one frame into `out` (which must hold `frame_samples * channels`).
/// Returns the samples written.
///
/// Pass `null` for `packet` when a packet was lost: Opus then runs packet-loss
/// concealment and invents a plausible continuation rather than leaving a hole,
/// which is the difference between a call that sounds lossy and one that sounds
/// broken.
pub fn decode(d: *Decoder, packet: ?[]const u8, out: []i16) Error![]const i16 {
    const want = frame_samples * d.channels;
    if (out.len < want) return Error.OpusBadArgument;
    const n = if (packet) |p|
        opus_decode(d.state.ptr, p.ptr, @intCast(p.len), out.ptr, @intCast(frame_samples), 0)
    else
        opus_decode(d.state.ptr, null, 0, out.ptr, @intCast(frame_samples), 0);
    if (n < 0) return Error.OpusFailed;
    return out[0..@intCast(@as(u32, @intCast(n)) * d.channels)];
}

// ---------------------------------------------------------------------------
// Tests — a round trip through the real codec, which is also the proof that the
// vendored build is wired correctly on whatever target the suite runs on.
// ---------------------------------------------------------------------------

const testing = std.testing;

/// One 20 ms frame of a 440 Hz tone, generated without a clock or RNG so the
/// test is deterministic.
fn toneFrame(buf: []i16) void {
    for (buf, 0..) |*s, i| {
        const t = @as(f32, @floatFromInt(i)) / @as(f32, @floatFromInt(sample_rate));
        s.* = @intFromFloat(@round(8000.0 * @sin(2.0 * std.math.pi * 440.0 * t)));
    }
}

test "opus round-trips a voice frame and compresses it hard" {
    const gpa = testing.allocator;

    var enc: Encoder = undefined;
    try encoderInit(gpa, &enc, 1, 32_000);
    defer encoderDeinit(gpa, &enc);

    var dec: Decoder = undefined;
    try decoderInit(gpa, &dec, 1);
    defer decoderDeinit(gpa, &dec);

    var pcm: [frame_samples]i16 = undefined;
    toneFrame(&pcm);

    var packet: [max_packet_bytes]u8 = undefined;
    var out: [frame_samples]i16 = undefined;

    // Opus needs a few frames to leave its startup transient before the
    // bitrate and the output settle, so drive it like a real call would.
    var last_packet_len: usize = 0;
    for (0..10) |_| {
        const p = try encode(&enc, &pcm, &packet);
        last_packet_len = p.len;
        const decoded = try decode(&dec, p, &out);
        try testing.expectEqual(@as(usize, frame_samples), decoded.len);
    }

    // THE POINT OF THE WHOLE EXERCISE: the raw frame is 1920 bytes on the wire;
    // the coded frame must be a small fraction of that. At 32 kbps a 20 ms
    // frame is ~80 bytes, so 200 is a loose ceiling that still fails loudly if
    // the codec is ever bypassed or misconfigured.
    try testing.expect(last_packet_len > 0);
    try testing.expect(last_packet_len < 200);

    // The decoded tone must actually carry signal, not silence — a codec that
    // "succeeds" into a flat buffer would otherwise pass every check above.
    var peak: u32 = 0;
    for (out) |s| peak = @max(peak, @abs(@as(i32, s)));
    try testing.expect(peak > 2000);
}

test "packet loss concealment produces a frame instead of a hole" {
    const gpa = testing.allocator;

    var enc: Encoder = undefined;
    try encoderInit(gpa, &enc, 1, 32_000);
    defer encoderDeinit(gpa, &enc);

    var dec: Decoder = undefined;
    try decoderInit(gpa, &dec, 1);
    defer decoderDeinit(gpa, &dec);

    var pcm: [frame_samples]i16 = undefined;
    toneFrame(&pcm);
    var packet: [max_packet_bytes]u8 = undefined;
    var out: [frame_samples]i16 = undefined;

    for (0..5) |_| {
        const p = try encode(&enc, &pcm, &packet);
        _ = try decode(&dec, p, &out);
    }

    // The packet never arrived. The decoder must still hand back a full frame.
    const concealed = try decode(&dec, null, &out);
    try testing.expectEqual(@as(usize, frame_samples), concealed.len);
}

test "a wrong-length frame is refused rather than misread" {
    const gpa = testing.allocator;

    var enc: Encoder = undefined;
    try encoderInit(gpa, &enc, 1, 32_000);
    defer encoderDeinit(gpa, &enc);

    var short: [frame_samples / 2]i16 = @splat(0);
    var packet: [max_packet_bytes]u8 = undefined;
    try testing.expectError(Error.OpusBadArgument, encode(&enc, &short, &packet));
}
