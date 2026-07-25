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

//! B3 classification: SHELL (impure). The call session — a worker thread that
//! runs one live call end to end: ICE connectivity checks over the socket, then
//! the media loop (capture the mic → RTP/SRTP → send; receive → de-jitter →
//! play the speaker). It ties `call_ice` + `call_engine` + the target-selected
//! audio backend into one thing the render thread starts and stops without ever
//! blocking on the network or the audio device (the "network never drives the
//! render thread" rule).
//!
//! The render thread (tui/mobile) owns SIGNALING — it exchanges the offer/
//! answer/candidate over the E2EE chat channel and, once it knows the peer's
//! transport address + the call's MLS-derived key material, hands them here and
//! spawns the worker. Everything blocking (poll, recvfrom, ALSA/AAudio read/
//! write) lives on this thread.
//!
//! Audio is target-selected exactly as `sfx_player` does it: AAudio on Android,
//! ALSA on the Linux desktop — same `open/close/play/capture` surface either
//! way, so this file is platform-agnostic.

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const call_ice = @import("call_ice.zig");
const call_engine = @import("call_engine.zig");
const media_keys = @import("../core/media_keys.zig");
const ice = @import("../core/ice.zig");
const opus = @import("opus_codec.zig");
const device_power = @import("device_power.zig");
const call_decision = @import("../core/call_decision.zig");
const congestion = @import("../core/congestion.zig");
const clock_shell = @import("clock.zig");

const audio = if (builtin.abi.isAndroid())
    @import("audio_aaudio.zig")
else
    @import("audio_alsa.zig");

// Android routes logs through liblog (stderr is dropped); the desktop uses
// stderr. `callLog` picks the right one so the call's diagnostics show on both
// (mirrors `android_dns.trace`). The extern is only referenced under the
// comptime-android branch, so off-Android nothing links against liblog.
extern fn __android_log_write(prio: c_int, tag: [*:0]const u8, text: [*:0]const u8) c_int;
fn callLog(comptime fmt: []const u8, args: anytype) void {
    var buf: [256]u8 = undefined;
    const msg = std.fmt.bufPrintZ(&buf, fmt, args) catch return;
    if (comptime builtin.abi.isAndroid()) {
        _ = __android_log_write(4, "zat4", msg);
    } else {
        std.debug.print("{s}\n", .{msg});
    }
}

const rate: u32 = opus.sample_rate;
const channels: u32 = 1;
/// 20 ms mono @ 48 kHz — Opus's voice frame, and the interval `call_engine`'s
/// RTP timestamp advance has always assumed. (The pre-codec path captured 10 ms
/// frames while stamping them as 20 ms; nothing read the timestamp yet, so it
/// never showed, but the two agree now.)
const frame_samples: usize = opus.frame_samples;

/// The starting audio bitrate. `core/call_decision.zig` moves it from here as
/// the call runs; 32 kbps is its wideband-SILK operating point and a sane
/// opening bid for voice on any network.
const initial_bitrate_bps: i32 = 32_000;

/// How often the adaptive brain re-decides (ZAT_CHAT_CALLING_ROADMAP §4.1 —
/// "sampled every 1–2 seconds"). Fast enough to follow a network that turns
/// bad, slow enough that the encoder is not thrashed between settings.
const decide_interval_ns: u64 = 1_000_000_000;

/// A microphone frame whose loudest sample clears this is speech rather than
/// room noise. Ambient sits at 3–8 on the phone and 30–100 on the desktop with
/// a sane capture gain, so 400 is comfortably above both while still catching
/// quiet talking. Feeds `CallMetrics.audio_activity_local`, which is what makes
/// the brain bias a call toward the person who is actually speaking.
const speech_peak_threshold: u32 = 400;

pub const State = enum(u8) { connecting = 0, active = 1, ended = 2 };

/// PLAIN DATA (A1). One live call's session. A7.2: cold struct, size guard
/// waived — one per call; owns a thread, a socket, and cross-thread atomics,
/// never held in a collection.
pub const Session = struct {
    gpa: Allocator,
    thread: std.Thread,
    stop: std.atomic.Value(bool),
    state: std.atomic.Value(u8), // a `State`, read by the render thread
    agent: call_ice.Agent,
    peer_ip: [4]u8,
    peer_port: u16,
    exporter: [media_keys.key_len]u8,
    call_id: u64,
    is_caller: bool,

    // --- the adaptive brain's crossing points between the two media threads.
    //
    // The DECISION is made on the rx thread (which is where the path is
    // measured) but must be APPLIED on the tx thread, because Opus encoder
    // state belongs to whoever calls `opus_encode` and a control call from
    // another thread would race it. So the decision crosses as plain numbers in
    // atomics and the tx thread applies them between frames — E1's "pass
    // values, never reach into a neighbour" at thread scale.
    /// Loudest sample in the last captured frame; written by tx, read by the
    /// sampler to answer "is this person speaking?".
    mic_peak: std.atomic.Value(u32),
    /// What the brain wants the encoder set to next.
    want_bitrate_bps: std.atomic.Value(u32),
    want_loss_percent: std.atomic.Value(u32),
};

/// The short-term ICE credential (STUN MESSAGE-INTEGRITY key), derived from the
/// shared MLS-exporter material so both ends agree without a separate exchange.
fn icePwd(exporter: [media_keys.key_len]u8, call_id: u64) [media_keys.key_len]u8 {
    return media_keys.derive(exporter, call_id, .send).key;
}

/// A deterministic per-role STUN transaction id from the session key material
/// (no clock/RNG on this thread; MESSAGE-INTEGRITY authenticates checks anyway).
fn iceTxid(exporter: [media_keys.key_len]u8, call_id: u64, is_caller: bool) [ice.txid_len]u8 {
    const k = media_keys.derive(exporter, call_id, if (is_caller) .send else .recv).key;
    var t: [ice.txid_len]u8 = undefined;
    @memcpy(&t, k[0..ice.txid_len]);
    return t;
}

/// Start a call worker. The render thread supplies the already-bound ICE socket
/// (`agent`), the peer's transport address (from signaling), and the call's
/// MLS-derived key material. `is_caller` selects the media key direction so the
/// two ends decrypt each other. The returned `*Session` is owned by the caller;
/// stop it with `shutdown`.
pub fn start(
    gpa: Allocator,
    agent: call_ice.Agent,
    peer_ip: [4]u8,
    peer_port: u16,
    exporter: [media_keys.key_len]u8,
    call_id: u64,
    is_caller: bool,
) !*Session {
    const s = try gpa.create(Session);
    errdefer gpa.destroy(s);
    s.* = .{
        .gpa = gpa,
        .thread = undefined,
        .stop = .init(false),
        .state = .init(@intFromEnum(State.connecting)),
        .agent = agent,
        .peer_ip = peer_ip,
        .peer_port = peer_port,
        .exporter = exporter,
        .call_id = call_id,
        .is_caller = is_caller,
        .mic_peak = .init(0),
        .want_bitrate_bps = .init(@intCast(initial_bitrate_bps)),
        .want_loss_percent = .init(0),
    };
    s.thread = try std.Thread.spawn(.{}, threadMain, .{s});
    return s;
}

pub fn state(s: *const Session) State {
    return @enumFromInt(s.state.load(.acquire));
}

/// Signal the worker to stop, join it, and release the socket + session. The
/// worker checks `stop` every poll/frame, so this returns within ~one frame.
pub fn shutdown(s: *Session) void {
    s.stop.store(true, .release);
    s.thread.join();
    call_ice.close(&s.agent);
    const gpa = s.gpa;
    gpa.destroy(s);
}

fn threadMain(s: *Session) void {
    const pwd = icePwd(s.exporter, s.call_id);
    const txid = iceTxid(s.exporter, s.call_id, s.is_caller);

    // --- ICE connectivity: both ends send checks and answer until each has a
    // validated path, ~15s budget; abort early if stopped.
    var peer: ice.Address = undefined;
    var got_resp = false;
    var got_req = false;
    var tries: usize = 0;
    while (!(got_resp and got_req) and tries < 300 and !s.stop.load(.acquire)) : (tries += 1) {
        call_ice.sendCheck(&s.agent, s.peer_ip, s.peer_port, txid, &pwd) catch {};
        switch (call_ice.poll(&s.agent, 50, &pwd, &peer)) {
            .got_response => got_resp = true,
            .got_request => got_req = true,
            else => {},
        }
    }
    if (!(got_resp and got_req)) {
        s.state.store(@intFromEnum(State.ended), .release);
        return;
    }
    s.state.store(@intFromEnum(State.active), .release);

    // --- Media: bring up the engine + the audio devices, then run the loop.
    var eng: call_engine.Engine = undefined;
    call_engine.init(
        s.gpa,
        &eng,
        &s.agent,
        s.peer_ip,
        s.peer_port,
        s.exporter,
        s.call_id,
        if (s.is_caller) 0x0A0A_0A0A else 0x0B0B_0B0B,
        if (s.is_caller) .send else .recv,
    ) catch {
        s.state.store(@intFromEnum(State.ended), .release);
        return;
    };
    defer call_engine.deinit(s.gpa, &eng);

    var mic = audio.open(audio.stream_capture, rate, channels, 40_000) catch {
        s.state.store(@intFromEnum(State.ended), .release);
        return;
    };
    defer audio.close(&mic);
    var spk = audio.open(audio.stream_playback, rate, channels, 60_000) catch {
        s.state.store(@intFromEnum(State.ended), .release);
        return;
    };
    defer audio.close(&spk);

    // The codec. One encoder and one decoder per call, both owned here so their
    // state dies with the session. Bring them up AFTER the devices so a machine
    // with no microphone fails before it allocates them.
    var enc: opus.Encoder = undefined;
    opus.encoderInit(s.gpa, &enc, @intCast(channels), initial_bitrate_bps) catch {
        s.state.store(@intFromEnum(State.ended), .release);
        return;
    };
    defer opus.encoderDeinit(s.gpa, &enc);

    var dec: opus.Decoder = undefined;
    opus.decoderInit(s.gpa, &dec, @intCast(channels)) catch {
        s.state.store(@intFromEnum(State.ended), .release);
        return;
    };
    defer opus.decoderDeinit(s.gpa, &dec);

    const role = if (s.is_caller) "caller" else "callee";

    // FULL DUPLEX ON TWO THREADS. Capture→send runs on its own thread so a
    // blocking/slow mic read can't stall playout, and receive→play runs here so
    // a playout backlog can't stall capture. The engine's send state (seq/ts/
    // ROC) is touched only by the tx thread and its receive state (jitter/replay)
    // only by this thread — disjoint, so no lock is needed; the shared UDP socket
    // does concurrent sendto/recvfrom, which is safe.
    var tx = TxThread{ .eng = &eng, .mic = &mic, .enc = &enc, .sess = s, .stop = &s.stop, .role = role };
    const tx_handle = std.Thread.spawn(.{}, txLoop, .{&tx}) catch {
        s.state.store(@intFromEnum(State.ended), .release);
        return;
    };

    // Wire → SRTP/jitter → Opus → speaker, with the adaptive brain sampling the
    // path once a second alongside.
    var coded: [opus.max_packet_bytes]u8 = undefined;
    var play_i16: [frame_samples]i16 = undefined;
    var n_recv: usize = 0;
    var n_play: usize = 0;
    var loops: usize = 0;

    var sampler = Sampler{
        .bandwidth = congestion.init(@intCast(initial_bitrate_bps / 1000)),
        .last_ns = clock_shell.monotonicNanos(),
        .last_packets = 0,
        .last_bytes = 0,
        .last_seq = 0,
        .remote_active = false,
    };

    while (!s.stop.load(.acquire)) {
        if (call_engine.pump(&eng, 20) == .media) n_recv += 1; // blocks ≤20ms for a packet
        while (call_engine.playout(&eng, &coded)) |payload| {
            const pcm = opus.decode(&dec, payload, &play_i16) catch continue;
            audio.play(&spk, pcm, pcm.len);
            n_play += 1;
            // A 1–2 byte packet is the peer's DTX comfort noise: they are not
            // talking. Anything larger is speech. This is the cheapest honest
            // read of "is the remote party active" available without decoding
            // energy, and it costs one comparison.
            sampler.remote_active = payload.len > 2;
        }
        decide(s, &sampler, &eng, role);
        loops += 1;
        if (loops % 200 == 0) callLog("[call {s} rx] recv={d} play={d}", .{ role, n_recv, n_play });
    }
    tx_handle.join(); // BEFORE the audio/engine defers free what tx points at
    s.state.store(@intFromEnum(State.ended), .release);
}

/// PLAIN DATA (A1). What the adaptive brain needs to remember between samples.
/// A7.2: cold struct, size guard waived — one per call, lives on the rx
/// thread's stack, never in a collection.
const Sampler = struct {
    bandwidth: congestion.Controller,
    last_ns: u64,
    last_packets: u64,
    last_bytes: u64,
    last_seq: u16,
    remote_active: bool,
};

/// ONE INTERVAL OF THE ADAPTIVE LOOP (ZAT_CHAT_CALLING_ROADMAP §4).
///
/// This is where the brain that `core/call_decision.zig` has always contained
/// finally gets driven. Measure the path and the device, hand the plain numbers
/// to the pure decision function, and publish its answer for the tx thread to
/// apply. The shell measures and applies; it never decides — every threshold
/// and every rule lives in the core, where it is golden-tested without a
/// network, a microphone or a phone (B2/B5).
///
/// v1 drives AUDIO only, because audio is all that exists to drive. The video
/// half of the returned config (framerate, resolution, keyframe interval,
/// transmit mode) is computed and currently ignored — when the video pipeline
/// lands it reads the same struct, and this loop does not change.
fn decide(s: *Session, sm: *Sampler, eng: *call_engine.Engine, role: []const u8) void {
    const now_ns = clock_shell.monotonicNanos();
    const elapsed_ns = now_ns -% sm.last_ns;
    if (elapsed_ns < decide_interval_ns) return;

    // --- measure the path -----------------------------------------------------
    //
    // Counters are free-running totals, so this takes differences and never
    // resets anything the rx path owns. `%` arithmetic throughout: the sequence
    // number is a u16 that wraps every ~22 minutes of call at 50 packets/sec.
    const packets_now = eng.recv_packets;
    const bytes_now = eng.recv_bytes;
    const seq_now = eng.recv_highest_seq;

    const got_packets = packets_now -| sm.last_packets;
    const got_bytes = bytes_now -| sm.last_bytes;
    const expected: u32 = if (sm.last_packets == 0) @intCast(got_packets) else seq_now -% sm.last_seq;

    // Loss is what should have arrived minus what did. A negative result means
    // reordering delivered more than the sequence span suggests, which is not
    // loss — clamp it away rather than let it read as a perfect link.
    const lost: u32 = if (expected > got_packets) expected - @as(u32, @intCast(got_packets)) else 0;
    const loss_fraction: f32 = if (expected == 0)
        0.0
    else
        @min(1.0, @as(f32, @floatFromInt(lost)) / @as(f32, @floatFromInt(expected)));

    const elapsed_s = @as(f32, @floatFromInt(elapsed_ns)) / 1_000_000_000.0;
    const acked_kbps: u32 = if (elapsed_s <= 0)
        0
    else
        @intFromFloat(@as(f32, @floatFromInt(got_bytes)) * 8.0 / elapsed_s / 1000.0);

    // RTT and the delay gradient want RTCP receiver reports, or at minimum a
    // periodic STUN keepalive round trip — neither exists yet, so both are
    // reported as "no evidence of a problem" and the estimator runs on its loss
    // controller alone. Wiring the ICE keepalive RTT in is the next slice; it
    // changes only these two lines.
    const bandwidth_kbps = congestion.update(&sm.bandwidth, .{
        .rtt_ms = 0,
        .loss_fraction = loss_fraction,
        .delay_gradient_ms = 0,
        .acked_bitrate_kbps = acked_kbps,
    });

    // --- measure the device ---------------------------------------------------
    //
    // Both are optional. A desktop has no battery and a container may hide the
    // thermal zones; the neutral substitutes below mean the call behaves on
    // such a machine exactly as it would on one that is cool and plugged in,
    // which is the truthful reading in both cases.
    const battery = device_power.batteryPercent() orelse 100;
    const headroom = device_power.thermalHeadroom() orelse 1.0;

    const speaking = s.mic_peak.load(.acquire) >= speech_peak_threshold;

    // --- decide (pure) --------------------------------------------------------
    const cfg = call_decision.computeEncoderConfig(.{
        // No camera yet: report a still scene rather than inventing motion.
        .motion_level = 0.0,
        .seconds_since_significant_motion = 0,
        .audio_activity_local = speaking,
        .audio_activity_remote = sm.remote_active,
        .remote_still = false,

        .network_rtt_ms = 0,
        .network_loss_percent = @intFromFloat(@round(loss_fraction * 100.0)),
        .network_bandwidth_estimate_kbps = bandwidth_kbps,

        .thermal_headroom = headroom,
        .battery_percent = battery,
        .screen_brightness = 1.0,

        .receiver_display_width = 0,
        .receiver_codec_support = .{},
    });

    // --- publish for the tx thread to apply ----------------------------------
    s.want_bitrate_bps.store(@as(u32, cfg.audio_bitrate_kbps) * 1000, .release);
    s.want_loss_percent.store(@intFromFloat(@round(loss_fraction * 100.0)), .release);

    callLog("[call {s} brain] rx={d}kbps loss={d}% est={d}kbps batt={d}% therm={d} -> audio {d}kbps", .{
        role,
        acked_kbps,
        @as(u32, @intFromFloat(@round(loss_fraction * 100.0))),
        bandwidth_kbps,
        battery,
        @as(u32, @intFromFloat(@round(headroom * 100.0))),
        cfg.audio_bitrate_kbps,
    });

    sm.last_ns = now_ns;
    sm.last_packets = packets_now;
    sm.last_bytes = bytes_now;
    sm.last_seq = seq_now;
}

/// Capture→send worker state (the tx thread). Points at threadMain's engine,
/// mic and encoder, which outlive it (threadMain joins before its defers run).
/// A7.2: cold struct, size guard waived — one per call, never in a collection.
const TxThread = struct {
    eng: *call_engine.Engine,
    mic: *audio.Pcm,
    enc: *opus.Encoder,
    sess: *Session,
    stop: *std.atomic.Value(bool),
    role: []const u8,
};

/// Capture → Opus → RTP/SRTP → wire.
///
/// The device hands back whatever it has, which is not necessarily a whole
/// frame, so samples accumulate here until exactly one Opus frame is ready.
/// Opus refuses a partial frame outright (there is no "encode what you have"),
/// and that strictness is what keeps sender and receiver on the same 20 ms
/// grid.
fn txLoop(t: *TxThread) void {
    var pending: [frame_samples]i16 = undefined;
    var have: usize = 0;
    var scratch: [frame_samples]i16 = undefined;
    var packet: [opus.max_packet_bytes]u8 = undefined;

    var n_cap: usize = 0;
    var coded_bytes: usize = 0;
    var loops: usize = 0;
    var last_peak: u32 = 0;
    // What the encoder is currently set to, so the brain's decision is applied
    // only when it actually changes rather than on every frame.
    var applied_bitrate: u32 = @intCast(initial_bitrate_bps);
    var applied_loss: u32 = 0;

    while (!t.stop.load(.acquire)) {
        const n = audio.capture(t.mic, &scratch, frame_samples - have);
        if (n == 0) {
            loops += 1;
            continue;
        }
        var peak: u32 = 0;
        for (scratch[0..n]) |sample| {
            const a: u32 = @abs(@as(i32, sample));
            if (a > peak) peak = a;
        }
        last_peak = peak;
        t.sess.mic_peak.store(peak, .release);

        // Apply whatever the brain decided since the last frame. Opus takes a
        // new bitrate mid-stream with no glitch and no renegotiation, which is
        // the whole reason the adaptation can be continuous instead of stepped.
        const want_bitrate = t.sess.want_bitrate_bps.load(.acquire);
        if (want_bitrate != applied_bitrate) {
            opus.setBitrate(t.enc, @intCast(want_bitrate));
            applied_bitrate = want_bitrate;
        }
        const want_loss = t.sess.want_loss_percent.load(.acquire);
        if (want_loss != applied_loss) {
            opus.setExpectedLoss(t.enc, @intCast(@min(want_loss, 100)));
            applied_loss = want_loss;
        }

        @memcpy(pending[have .. have + n], scratch[0..n]);
        have += n;
        if (have < frame_samples) continue;
        have = 0;

        const coded = opus.encode(t.enc, &pending, &packet) catch continue;
        // A 1–2 byte packet is Opus's DTX comfort-noise update, not a failure:
        // it means "still silent." It is still transmitted — the decoder needs
        // it to keep its comfort noise in step — and at 2 bytes per 20 ms the
        // silent direction of a conversation costs under a kilobit per second.
        call_engine.sendFrame(t.eng, coded) catch {};
        n_cap += 1;
        coded_bytes += coded.len;

        loops += 1;
        if (n_cap % 50 == 0) callLog(
            "[call {s} tx] frames={d} mic_peak={d} avg_bytes={d} kbps~{d}",
            .{ t.role, n_cap, last_peak, coded_bytes / n_cap, (coded_bytes / n_cap) * 8 * 50 / 1000 },
        );
    }
}
