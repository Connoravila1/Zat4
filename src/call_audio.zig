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

//! B3 classification: SHELL. Audible call harness (`zig build call-audio`).
//!
//! A call endpoint carrying REAL audio: the sender captures the desktop mic and
//! streams it through the full media stack (RTP + SRTP-AES-256-GCM + jitter over
//! ICE); the receiver de-jitters it and plays it out the speaker. Run one of
//! each on a LAN (or both on loopback) and you hear live voice cross the
//! encrypted path — the audible proof, on top of the packet-level `call-peer`.
//!
//!   call-audio <a|b> <bind-port> <peer-ip> <peer-port>
//!     a = capture mic → send      b = receive → play speaker
//!
//! Raw 48 kHz mono S16, 10 ms frames (480 samples / 960 bytes) — no Opus yet, so
//! it is bandwidth-heavy but fine on a LAN; the codec is a later slice.

const std = @import("std");
const call_ice = @import("shell/call_ice.zig");
const call_engine = @import("shell/call_engine.zig");
const audio = @import("shell/audio_alsa.zig");
const media_keys = @import("core/media_keys.zig");
const ice = @import("core/ice.zig");

const pwd = "debug-call-credential";
const call_id: u64 = 0xA0D10_CA11;
const rate: u32 = 48000;
const frame_samples: usize = 480; // 10 ms mono
const total_frames: usize = 800; // ~8 s of talk time

fn parseIp(s: []const u8) ![4]u8 {
    var out: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, s, '.');
    for (0..4) |i| out[i] = try std.fmt.parseInt(u8, it.next() orelse return error.BadIp, 10);
    return out;
}

fn connectIce(agent: *call_ice.Agent, peer_ip: [4]u8, peer_port: u16, txid: [ice.txid_len]u8) bool {
    var peer: ice.Address = undefined;
    var got_resp = false;
    var got_req = false;
    var tries: usize = 0;
    while (!(got_resp and got_req) and tries < 1000) : (tries += 1) { // ~50s: forgiving of launch skew
        call_ice.sendCheck(agent, peer_ip, peer_port, txid, pwd) catch {};
        switch (call_ice.poll(agent, 50, pwd, &peer)) {
            .got_response => got_resp = true,
            .got_request => got_req = true,
            else => {},
        }
    }
    return got_resp and got_req;
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const argv = try init.minimal.args.toSlice(gpa);
    defer gpa.free(argv);
    if (argv.len < 5) {
        std.debug.print("usage: call-audio <a|b> <bind-port> <peer-ip> <peer-port>\n", .{});
        return error.Args;
    }
    const is_sender = std.mem.eql(u8, argv[1], "a");
    const bind_port = try std.fmt.parseInt(u16, argv[2], 10);
    const peer_ip = try parseIp(argv[3]);
    const peer_port = try std.fmt.parseInt(u16, argv[4], 10);

    if (!audio.available()) {
        std.debug.print("[call-audio] ALSA not available\n", .{});
        return error.NoAudio;
    }

    var agent = try call_ice.open(bind_port);
    defer call_ice.close(&agent);
    var txid: [ice.txid_len]u8 = undefined;
    try init.io.randomSecure(&txid);
    std.debug.print("[call-audio {s}] :{d} → {d}.{d}.{d}.{d}:{d}; connecting…\n", .{ argv[1], agent.bound_port, peer_ip[0], peer_ip[1], peer_ip[2], peer_ip[3], peer_port });
    if (!connectIce(&agent, peer_ip, peer_port, txid)) {
        std.debug.print("[call-audio {s}] FAIL: ICE did not connect\n", .{argv[1]});
        return error.IceFailed;
    }
    std.debug.print("[call-audio {s}] ICE connected.\n", .{argv[1]});

    var exporter: [media_keys.key_len]u8 = undefined;
    for (&exporter, 0..) |*x, i| x.* = @intCast((i * 17 + 3) & 0xff);
    var eng: call_engine.Engine = undefined;
    try call_engine.init(gpa, &eng, &agent, peer_ip, peer_port, exporter, call_id, if (is_sender) 0x0A0A0A0A else 0x0B0B0B0B, if (is_sender) .send else .recv);
    defer call_engine.deinit(gpa, &eng);

    if (is_sender) {
        var mic = try audio.open(audio.stream_capture, rate, 1, 40_000);
        defer audio.close(&mic);
        std.debug.print("[call-audio a] SPEAK NOW — streaming mic for ~8s…\n", .{});
        var pcm: [frame_samples]i16 = undefined;
        var sent: usize = 0;
        while (sent < total_frames) : (sent += 1) {
            const n = audio.capture(&mic, &pcm, frame_samples);
            call_engine.sendFrame(&eng, std.mem.sliceAsBytes(pcm[0..n])) catch {};
            _ = call_engine.pump(&eng, 0); // non-blocking: drain any keepalive
        }
        std.debug.print("[call-audio a] done — sent {d} frames.\n", .{total_frames});
    } else {
        var spk = try audio.open(audio.stream_playback, rate, 1, 60_000);
        defer audio.close(&spk);
        std.debug.print("[call-audio b] playing received audio to the speaker…\n", .{});
        var played: usize = 0;
        var guard: usize = 0;
        var pbuf_i16: [frame_samples]i16 = undefined; // i16-aligned; play out of it directly
        const out_bytes = std.mem.sliceAsBytes(pbuf_i16[0..]);
        while (played < total_frames and guard < total_frames * 4) : (guard += 1) {
            _ = call_engine.pump(&eng, 50);
            while (call_engine.playout(&eng, out_bytes)) |bytes| {
                const nsamp = bytes.len / 2;
                audio.play(&spk, pbuf_i16[0..nsamp], nsamp);
                played += 1;
            }
        }
        std.debug.print("[call-audio b] done — played {d} frames.\n", .{played});
    }
}
