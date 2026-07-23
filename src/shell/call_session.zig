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

const audio = if (builtin.abi.isAndroid())
    @import("audio_aaudio.zig")
else
    @import("audio_alsa.zig");

const rate: u32 = 48000;
const channels: u32 = 1;
const frame_samples: usize = 480; // 10 ms mono @ 48 kHz

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

    var cap: [frame_samples]i16 = undefined;
    var play_i16: [frame_samples]i16 = undefined;
    const play_bytes = std.mem.sliceAsBytes(play_i16[0..]);

    // Capture-clocked full duplex: the mic read paces the loop at ~100 fps; each
    // pass we send one captured frame, drain whatever media has arrived, and
    // play it out. Blocking lives here, off the render thread.
    while (!s.stop.load(.acquire)) {
        const n = audio.capture(&mic, &cap, frame_samples);
        if (n > 0) call_engine.sendFrame(&eng, std.mem.sliceAsBytes(cap[0..n])) catch {};
        while (call_engine.pump(&eng, 0) == .media) {}
        while (call_engine.playout(&eng, play_bytes)) |bytes| {
            audio.play(&spk, play_i16[0 .. bytes.len / 2], bytes.len / 2);
        }
    }
    s.state.store(@intFromEnum(State.ended), .release);
}
