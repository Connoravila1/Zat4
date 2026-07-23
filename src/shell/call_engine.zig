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

//! B3 classification: SHELL (thin). The media engine glue — it ties the pure
//! core (rtp, srtp, jitter, media_keys) to the ICE socket (call_ice) so encoded
//! frames actually flow, encrypted, between two endpoints. This is deliberately
//! thin: every decision (packetize, encrypt, reorder, key-derive, rollover) is
//! a pure-core call; the engine only owns the counters, the buffer, and the
//! socket handoff.
//!
//! What it does per direction: on send, packetize a frame into RTP, protect it
//! with SRTP (keyed from the MLS-derived material), and hand it to the ICE
//! socket; on receive, demux RTP from STUN, recover the rollover counter,
//! unprotect, replay-check, and de-jitter into a clean playout stream. A
//! synthetic tone frame stands in for real audio until the ALSA/AAudio capture
//! shims land — proving the whole transport is real without touching hardware.

const std = @import("std");
const Allocator = std.mem.Allocator;
const call_ice = @import("call_ice.zig");
const rtp = @import("../core/rtp.zig");
const srtp = @import("../core/srtp.zig");
const jitter = @import("../core/jitter.zig");
const media_keys = @import("../core/media_keys.zig");

const samples_per_frame: u32 = 960; // 20 ms @ 48 kHz (Opus frame)
const max_packet = 1500;

/// PLAIN DATA (A1). One call's media state. A7.2: cold struct, size guard
/// waived — one per call, owns a jitter buffer (its own slices) + a socket,
/// never held in a collection.
pub const Engine = struct {
    agent: *call_ice.Agent, // borrowed; the engine does not own the socket
    peer_ip: [4]u8,
    peer_port: u16,
    ssrc: u32,

    send_keys: media_keys.MediaKeys,
    recv_keys: media_keys.MediaKeys,

    // Send-side RTP counters.
    seq: u16,
    ts: u32,
    send_roc: u32,

    // Receive-side rollover recovery + replay window.
    recv_roc: u32,
    recv_highest_seq: u16,
    recv_started: bool,
    replay: srtp.ReplayWindow,

    jb: jitter.JitterBuffer,
};

pub const PumpResult = enum { idle, media, stun, ignored };

/// Bring up a call's media state. Media keys derive from the shared MLS epoch
/// `exporter` + `call_id` (both sides pass the same values); `send_dir` is this
/// endpoint's outgoing direction, and it decrypts the peer's stream with the
/// opposite direction's key.
pub fn init(
    gpa: Allocator,
    e: *Engine,
    agent: *call_ice.Agent,
    peer_ip: [4]u8,
    peer_port: u16,
    exporter: [media_keys.key_len]u8,
    call_id: u64,
    ssrc: u32,
    send_dir: media_keys.Direction,
) Allocator.Error!void {
    const recv_dir: media_keys.Direction = if (send_dir == .send) .recv else .send;
    e.* = .{
        .agent = agent,
        .peer_ip = peer_ip,
        .peer_port = peer_port,
        .ssrc = ssrc,
        .send_keys = media_keys.derive(exporter, call_id, send_dir),
        .recv_keys = media_keys.derive(exporter, call_id, recv_dir),
        .seq = 0,
        .ts = 0,
        .send_roc = 0,
        .recv_roc = 0,
        .recv_highest_seq = 0,
        .recv_started = false,
        .replay = .{},
        .jb = undefined,
    };
    try jitter.init(gpa, &e.jb, 32, max_packet, 3);
}

pub fn deinit(gpa: Allocator, e: *Engine) void {
    jitter.deinit(gpa, &e.jb);
    e.* = undefined;
}

/// Packetize + encrypt + send one media frame to the peer.
pub fn sendFrame(e: *Engine, payload: []const u8) !void {
    var rtp_buf: [max_packet]u8 = undefined;
    const rtp_len = try rtp.serialize(.{
        .timestamp = e.ts,
        .ssrc = e.ssrc,
        .sequence = e.seq,
        .payload_type = rtp.opus_payload_type,
        .marker = false,
    }, payload, &rtp_buf);

    var srtp_buf: [max_packet + 16]u8 = undefined;
    const srtp_len = try srtp.protect(rtp_buf[0..rtp_len], e.send_keys, e.send_roc, &srtp_buf);
    try call_ice.sendRaw(e.agent, e.peer_ip, e.peer_port, srtp_buf[0..srtp_len]);

    const prev = e.seq;
    e.seq +%= 1;
    e.send_roc = srtp.senderRoc(e.send_roc, prev, e.seq);
    e.ts +%= samples_per_frame;
}

/// Receive one datagram, demux, and — if it is media — decrypt, replay-check,
/// and de-jitter it into the playout buffer. STUN keepalives are reported but
/// not handled here (the ICE agent owns those during setup).
pub fn pump(e: *Engine, timeout_ms: i32) PumpResult {
    var rx: [max_packet]u8 = undefined;
    const dg = call_ice.recvRaw(e.agent, timeout_ms, &rx) orelse return .idle;
    if (dg.len == 0) return .idle;
    const pkt = rx[0..dg.len];
    if (!call_ice.isRtp(pkt[0])) return .stun;

    // The RTP header is in the clear; read the sequence to recover the ROC.
    const peeked = rtp.parse(pkt) catch return .ignored;
    const seq = peeked.header.sequence;
    const est = if (e.recv_started) srtp.estimateRoc(e.recv_roc, e.recv_highest_seq, seq) else e.recv_roc;

    var plain: [max_packet]u8 = undefined;
    const rtp_len = srtp.unprotect(pkt, e.recv_keys, est, &plain) catch return .ignored;
    if (!srtp.accept(&e.replay, srtp.packetIndex(est, seq))) return .ignored; // replay / stale

    e.recv_roc = est;
    e.recv_highest_seq = seq;
    e.recv_started = true;

    const dparsed = rtp.parse(plain[0..rtp_len]) catch return .ignored;
    _ = jitter.insert(&e.jb, seq, dparsed.header.timestamp, dparsed.payload);
    return .media;
}

/// Pop the next in-order frame for playout, copied into `out`. Null when the
/// buffer is waiting. (The copy is required: the jitter slot is recycled after
/// pop.)
pub fn playout(e: *Engine, out: []u8) ?[]const u8 {
    const p = jitter.pop(&e.jb) orelse return null;
    const n = @min(out.len, p.payload.len);
    @memcpy(out[0..n], p.payload[0..n]);
    return out[0..n];
}
