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

//! B1 classification: CORE (pure). The adaptive decision function — "the brain"
//! of Zat Chat video calling and, per ZAT_CHAT_CALLING_ROADMAP.md §4/§14, the
//! product itself: the encoder knobs are commodity hardware; the intelligence
//! in HOW they are driven is the differentiator. It takes a struct of
//! measurements the shell samples once or twice a second and returns the
//! configuration the shell applies to the hardware encoder, the transport, and
//! the display.
//!
//! PURE (B2/B3/B4): no clock, no RNG, no I/O, no camera, no network. Every
//! input arrives in `CallMetrics`; the output `EncoderConfig` is a pure
//! function of it. That is what makes the whole policy golden-testable
//! headlessly (see the pinned-scenario tests at the foot) — the same discipline
//! as the size guard: an output that changes fails the test and forces a human
//! decision. The boundaries here are TUNABLE; the shell never reaches in.
//!
//! Implements the §4.3 priority-ordered rules (codec, resolution, adaptive
//! bitrate + framerate, audio-gated bias, encoder hibernation, dynamic keyframe
//! interval, thermal degradation, brightness-aware ceiling, radio-sleep
//! transmit mode) and the §7.3 audio priority (an Opus floor video degradation
//! never breaches).

const std = @import("std");
const assert = std.debug.assert;

// ---------------------------------------------------------------------------
// Vocabulary
// ---------------------------------------------------------------------------

/// Which hardware video codecs the receiver can decode (negotiated at call
/// setup). Out-of-band flags (A6). `h264` is the universal baseline and defaults
/// on so a call always finds a codec.
pub const CodecSupport = packed struct(u8) {
    av1: bool = false,
    h265: bool = false,
    h264: bool = true,
    _pad: u5 = 0,

    comptime {
        // A fixed u8-backed bitset; the backing int pins the size at 1 byte.
        assert(@sizeOf(CodecSupport) == 1);
    }
};

pub const CodecChoice = enum(u8) { h264_high = 0, h265 = 1, av1 = 2 };

/// How the transport paces outgoing media (§4.9/§5). `.immediate` sends as
/// encoded; the batched modes create deliberate gaps so the cellular radio can
/// drop into DRX during low-motion stretches (measurement-gated per §10.2).
pub const TransmitMode = enum(u8) { immediate = 0, batched_short = 1, batched_long = 2 };

/// Opus operating mode selected by available bandwidth (§7.3/§7.4).
pub const AudioMode = enum(u8) { silk_narrow = 0, silk_wide = 1, opus_fullband = 2 };

/// The Opus audio-bitrate FLOOR (kbps, §7.3): video bitrate/framerate/resolution
/// all degrade before audio is touched, and audio is never taken below this.
/// A pixelated face with clear voice feels like a good connection; the reverse
/// feels broken.
pub const audio_floor_kbps: u16 = 24;

/// PLAIN DATA (A1). The measurements the shell samples each interval. A7.2:
/// cold struct, size guard waived — exactly one instance per call, never held
/// in a collection or scanned in a loop.
pub const CallMetrics = struct {
    // Content
    motion_level: f32, // 0.0 (still) .. 1.0 (rapid movement)
    seconds_since_significant_motion: u32,
    audio_activity_local: bool, // am I speaking?
    audio_activity_remote: bool, // are they speaking?
    remote_still: bool, // peer signaled it is also in heartbeat (enables batched_long)

    // Network
    network_rtt_ms: u16,
    network_loss_percent: u8,
    network_bandwidth_estimate_kbps: u32,

    // Device
    thermal_headroom: f32, // 1.0 (cool) .. 0.0 (throttle imminent)
    battery_percent: u8,
    screen_brightness: f32, // 0.0 .. 1.0

    // Receiver (negotiated at setup, updated on change)
    receiver_display_width: u16,
    receiver_codec_support: CodecSupport,
};

/// PLAIN DATA (A1). The configuration the shell applies. A7.2: cold struct,
/// size guard waived — one instance per call. `target_framerate == 0` means
/// HEARTBEAT mode (§4.6): the shell emits one frame per `keyframe_interval_s`
/// and holds the last decoded frame in between.
pub const EncoderConfig = struct {
    target_bitrate_kbps: u32,
    target_framerate: u8, // 0 = heartbeat; otherwise >= framerate_floor
    resolution_width: u16,
    resolution_height: u16,
    keyframe_interval_s: u8,
    codec: CodecChoice,
    transmit_mode: TransmitMode,
    audio_bitrate_kbps: u16,
    audio_mode: AudioMode,
};

// Tunable bounds (all recorded here so the policy is one readable table).
const framerate_floor: u8 = 24; // cinema-grade minimum while the user is watched (§4.4)
const bitrate_still: u32 = 500; // low-motion still-face target (§4.3)
const bitrate_gesture: u32 = 800;
const bitrate_active: u32 = 1300;
const min_width: u16 = 240;
const max_width: u16 = 1920;

// ---------------------------------------------------------------------------
// The decision function
// ---------------------------------------------------------------------------

/// Compute the encoder/transport/audio configuration from the current metrics.
/// The rules apply in priority order and compose; the ordering matters — audio
/// protection and thermal safety are applied last so they win over the
/// content-driven targets.
pub fn computeEncoderConfig(m: CallMetrics) EncoderConfig {
    // Rule 1 — codec selection (best mutually supported; one-time at setup).
    const codec: CodecChoice = if (m.receiver_codec_support.av1)
        .av1
    else if (m.receiver_codec_support.h265)
        .h265
    else
        .h264_high;

    // Rule 2 — resolution targeting: match the receiver's display width (16:9),
    // clamped to a sane range and rounded to even dimensions the encoder wants.
    var width = evenClamp(m.receiver_display_width, min_width, max_width);
    var height = even(@intFromFloat(@round(@as(f32, @floatFromInt(width)) * 9.0 / 16.0)));

    // Rule 3 — adaptive bitrate from the motion curve.
    var bitrate = motionBitrate(m.motion_level);

    // Rule 8.3 — brightness-aware ceiling: at low brightness the eye can't
    // resolve the extra detail, so the bits are wasted. Trim ~30%.
    if (m.screen_brightness < 0.3) bitrate = bitrate * 7 / 10;

    // Rule 4 — adaptive framerate from the motion curve.
    var framerate = motionFramerate(m.motion_level);

    // Rule 5 — audio-gated bias: when I'm listening (not speaking), the other
    // person is watching the speaker, not me. Bias framerate and bitrate down
    // ~20%, but never below the framerate floor.
    if (!m.audio_activity_local) {
        bitrate = bitrate * 8 / 10;
        framerate = @max(framerate_floor, framerate - framerate / 5);
    }

    // Rule 6 — encoder hibernation: after sustained stillness, drop to heartbeat.
    // The receiver holds the last frame (identical to the camera, nothing moved).
    var transmit: TransmitMode = .immediate;
    if (m.seconds_since_significant_motion > 2) {
        framerate = 0; // heartbeat
        bitrate = bitrate_still; // few frames; keep the still-face target
        // Rule 9 — radio sleep: batch heartbeats to open DRX gaps. If the peer
        // is also still, stretch the gaps further (mutual heartbeat).
        transmit = if (m.remote_still) .batched_long else .batched_short;
    } else if (m.motion_level < 0.2 and !m.audio_activity_local) {
        // Low motion while listening: create short DRX gaps without hibernating.
        transmit = .batched_short;
    }

    // Rule 7 — dynamic keyframe interval: stretch when the network is clean
    // (better compression), shorten under loss (faster recovery).
    const keyframe_interval_s: u8 = if (m.network_loss_percent < 2)
        5
    else if (m.network_loss_percent < 5)
        2
    else
        1;

    // Rule 8 — thermal-aware graceful degradation, applied LAST so safety wins.
    // Smooth steps, never a cliff: framerate, then resolution, then bitrate.
    if (m.thermal_headroom < 0.5 and framerate > framerate_floor) framerate = framerate_floor;
    if (m.thermal_headroom < 0.3) {
        width = even(@intCast(@as(u32, width) * 2 / 3));
        height = even(@intCast(@as(u32, height) * 2 / 3));
    }
    if (m.thermal_headroom < 0.15) bitrate = bitrate * 6 / 10;

    // Clamp the video bitrate to what the network can carry, RESERVING the audio
    // floor first (Rule 3 clamp + §7.3 priority): audio always gets its share.
    const audio = audioPlan(m.network_bandwidth_estimate_kbps);
    if (m.network_bandwidth_estimate_kbps > audio.bitrate_kbps) {
        const video_ceiling = m.network_bandwidth_estimate_kbps - audio.bitrate_kbps;
        if (bitrate > video_ceiling) bitrate = video_ceiling;
    }
    // Never drive the video encoder to zero while it is expected to produce frames.
    if (bitrate < 100) bitrate = 100;

    return .{
        .target_bitrate_kbps = bitrate,
        .target_framerate = framerate,
        .resolution_width = width,
        .resolution_height = height,
        .keyframe_interval_s = keyframe_interval_s,
        .codec = codec,
        .transmit_mode = transmit,
        .audio_bitrate_kbps = audio.bitrate_kbps,
        .audio_mode = audio.mode,
    };
}

/// A7.2: cold struct, size guard waived — a transient return value from
/// `audioPlan`, never stored in a collection or scanned in bulk.
const AudioPlan = struct { mode: AudioMode, bitrate_kbps: u16 };

/// Select the Opus mode and bitrate from available bandwidth (§7.3/§7.4). The
/// bitrate is never below `audio_floor_kbps`, whatever the bandwidth.
fn audioPlan(bandwidth_kbps: u32) AudioPlan {
    if (bandwidth_kbps >= 128) return .{ .mode = .opus_fullband, .bitrate_kbps = 48 };
    if (bandwidth_kbps >= 48) return .{ .mode = .silk_wide, .bitrate_kbps = 32 };
    return .{ .mode = .silk_narrow, .bitrate_kbps = audio_floor_kbps };
}

/// The motion → bitrate curve (§4.3): still face → ~500 kbps, conversational
/// gesture → ~800, active movement → ~1300, interpolated within each band.
fn motionBitrate(motion: f32) u32 {
    const mo = std.math.clamp(motion, 0.0, 1.0);
    if (mo <= 0.2) return lerp(bitrate_still, bitrate_gesture, mo / 0.2);
    if (mo <= 0.5) return lerp(bitrate_gesture, bitrate_active, (mo - 0.2) / 0.3);
    return lerp(bitrate_active, bitrate_active + 200, (mo - 0.5) / 0.5);
}

/// The motion → framerate curve (§4.4): low motion → 24fps, moderate → 27,
/// active → 30. 24 is the floor for any watched moment.
fn motionFramerate(motion: f32) u8 {
    const mo = std.math.clamp(motion, 0.0, 1.0);
    if (mo < 0.2) return 24;
    if (mo < 0.5) return 27;
    return 30;
}

fn lerp(a: u32, b: u32, t: f32) u32 {
    const tt = std.math.clamp(t, 0.0, 1.0);
    const af: f32 = @floatFromInt(a);
    const bf: f32 = @floatFromInt(b);
    return @intFromFloat(@round(af + (bf - af) * tt));
}

fn even(v: u16) u16 {
    return v & ~@as(u16, 1);
}

fn evenClamp(v: u16, lo: u16, hi: u16) u16 {
    return even(std.math.clamp(v, lo, hi));
}

// ---------------------------------------------------------------------------
// Golden / invariant tests (B2/C6 — pinned outputs, no allocator needed)
// ---------------------------------------------------------------------------

const testing = std.testing;

/// A comfortable baseline: cool device, bright screen, ample bandwidth, an AV1
/// receiver, active conversation with moderate motion. Used as the mutation
/// base for the scenario tests.
fn baseline() CallMetrics {
    return .{
        .motion_level = 0.35,
        .seconds_since_significant_motion = 0,
        .audio_activity_local = true,
        .audio_activity_remote = true,
        .remote_still = false,
        .network_rtt_ms = 40,
        .network_loss_percent = 0,
        .network_bandwidth_estimate_kbps = 4000,
        .thermal_headroom = 1.0,
        .battery_percent = 90,
        .screen_brightness = 0.9,
        .receiver_display_width = 1280,
        .receiver_codec_support = .{ .av1 = true, .h265 = true, .h264 = true },
    };
}

test "GOLDEN: comfortable conditions pick the best codec and full quality" {
    const c = computeEncoderConfig(baseline());
    try testing.expectEqual(CodecChoice.av1, c.codec);
    try testing.expectEqual(@as(u16, 1280), c.resolution_width);
    try testing.expectEqual(@as(u16, 720), c.resolution_height);
    try testing.expectEqual(@as(u8, 27), c.target_framerate); // moderate motion band
    try testing.expectEqual(@as(u8, 5), c.keyframe_interval_s); // clean network
    try testing.expectEqual(TransmitMode.immediate, c.transmit_mode);
    try testing.expectEqual(AudioMode.opus_fullband, c.audio_mode);
    try testing.expectEqual(@as(u16, 48), c.audio_bitrate_kbps);
    try testing.expectEqual(@as(u32, 1050), c.target_bitrate_kbps); // lerp(800,1300,0.5) at motion 0.35
}

test "GOLDEN: sustained stillness hibernates and batches for radio sleep" {
    var m = baseline();
    m.motion_level = 0.0;
    m.seconds_since_significant_motion = 5;
    m.audio_activity_local = false;
    m.remote_still = true;
    const c = computeEncoderConfig(m);
    try testing.expectEqual(@as(u8, 0), c.target_framerate); // heartbeat
    try testing.expectEqual(TransmitMode.batched_long, c.transmit_mode); // both still
    try testing.expectEqual(@as(u32, 500), c.target_bitrate_kbps); // still-face target
}

test "GOLDEN: listening (not speaking) biases motion quality down but not audio" {
    var m = baseline();
    m.audio_activity_local = false;
    const c = computeEncoderConfig(m);
    // Framerate biased from 27 down ~20% but never below the 24 floor.
    try testing.expectEqual(@as(u8, 24), c.target_framerate);
    try testing.expect(c.audio_bitrate_kbps >= audio_floor_kbps);
    // Low motion while listening opens short DRX gaps.
    try testing.expectEqual(TransmitMode.immediate, c.transmit_mode); // motion 0.35 >= 0.2
}

test "GOLDEN: thermal throttle degrades framerate, then resolution, then bitrate" {
    var m = baseline();
    m.thermal_headroom = 0.1; // below every threshold
    const c = computeEncoderConfig(m);
    try testing.expectEqual(@as(u8, 24), c.target_framerate); // capped to floor
    try testing.expect(c.resolution_width < 1280); // resolution reduced
    // Bitrate cut by the <0.15 step (1050 * 6/10 = 630).
    try testing.expectEqual(@as(u32, 630), c.target_bitrate_kbps);
}

test "GOLDEN: a constrained network protects audio and clamps video" {
    var m = baseline();
    // Moderately tight: audio still comfortable (fullband), video clamped to fit.
    m.network_bandwidth_estimate_kbps = 600;
    var c = computeEncoderConfig(m);
    try testing.expectEqual(AudioMode.opus_fullband, c.audio_mode);
    try testing.expectEqual(@as(u16, 48), c.audio_bitrate_kbps);
    // Video clamped to bandwidth minus the audio reservation (600 - 48 = 552).
    try testing.expectEqual(@as(u32, 552), c.target_bitrate_kbps);

    // Severely constrained: audio drops to the narrow SILK floor and is protected;
    // video is never taken to zero (the 100 kbps producing-frames floor holds).
    m.network_bandwidth_estimate_kbps = 40;
    c = computeEncoderConfig(m);
    try testing.expectEqual(AudioMode.silk_narrow, c.audio_mode);
    try testing.expectEqual(audio_floor_kbps, c.audio_bitrate_kbps);
}

test "GOLDEN: an H.264-only receiver gets H.264 High" {
    var m = baseline();
    m.receiver_codec_support = .{ .av1 = false, .h265 = false, .h264 = true };
    const c = computeEncoderConfig(m);
    try testing.expectEqual(CodecChoice.h264_high, c.codec);
}

test "GOLDEN: low screen brightness trims the video bitrate ceiling" {
    var m = baseline();
    m.screen_brightness = 0.1;
    const c = computeEncoderConfig(m);
    // 1050 * 7/10 = 735.
    try testing.expectEqual(@as(u32, 735), c.target_bitrate_kbps);
}

test "GOLDEN: packet loss shortens the keyframe interval for fast recovery" {
    var m = baseline();
    m.network_loss_percent = 8;
    try testing.expectEqual(@as(u8, 1), computeEncoderConfig(m).keyframe_interval_s);
    m.network_loss_percent = 3;
    try testing.expectEqual(@as(u8, 2), computeEncoderConfig(m).keyframe_interval_s);
}

test "INVARIANT: audio is never starved and framerate never drops below the floor while watched" {
    // Sweep a wide grid of conditions; the two sacred invariants hold throughout.
    var motion: f32 = 0.0;
    while (motion <= 1.0) : (motion += 0.25) {
        var loss: u8 = 0;
        while (loss <= 10) : (loss += 5) {
            var bw: u32 = 50;
            while (bw <= 4000) : (bw += 950) {
                var thermal: f32 = 0.0;
                while (thermal <= 1.0) : (thermal += 0.5) {
                    for ([_]bool{ true, false }) |speaking| {
                        var m = baseline();
                        m.motion_level = motion;
                        m.network_loss_percent = loss;
                        m.network_bandwidth_estimate_kbps = bw;
                        m.thermal_headroom = thermal;
                        m.audio_activity_local = speaking;
                        m.seconds_since_significant_motion = 0; // not hibernating
                        const c = computeEncoderConfig(m);
                        try testing.expect(c.audio_bitrate_kbps >= audio_floor_kbps);
                        try testing.expect(c.target_framerate >= framerate_floor);
                        try testing.expect(c.target_bitrate_kbps >= 100);
                    }
                }
            }
        }
    }
}

test "determinism — same metrics, same config (B2)" {
    const m = baseline();
    const a = computeEncoderConfig(m);
    const b = computeEncoderConfig(m);
    try testing.expectEqual(a, b);
}
