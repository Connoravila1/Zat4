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

//! B3 classification: SHELL (impure). The call CONTROLLER — the render-thread
//! glue between chat signaling and the call session worker. It holds the
//! per-conversation call state, turns a "place a call" intent into an offer +
//! ICE candidate over the E2EE chat channel, answers an inbound offer, and
//! starts/stops the `call_session` worker once both ends know each other's
//! transport address. Kept OUT of `tui.zig` so the run-loop edit is a few thin
//! call points, not a sprawl in the 17k-line file.
//!
//! v1 is LAN-first and one-call-at-a-time: signaling carries a single host
//! candidate ("ip:port") in the SDP field; STUN/TURN and trickle are later.
//! Media keys + the ICE credential derive from the conversation's MLS exporter,
//! so nothing secret rides the signaling beyond the candidate + call id.

const std = @import("std");
const call = @import("../core/call.zig");
const call_ice = @import("call_ice.zig");
const call_session = @import("call_session.zig");
const chat_e2ee = @import("chat_e2ee.zig");
const chat_relay = @import("chat_relay.zig");

/// A route target used only to discover our own LAN address via
/// connect-getsockname (no packet is sent). Any routable address works.
const route_probe: [4]u8 = .{ 8, 8, 8, 8 };

/// PLAIN DATA (A1). The controller's state. A7.2: cold struct, size guard
/// waived — one per session (lives on RunState), never in a collection.
pub const CallCtl = struct {
    /// The live call, once ICE addresses are exchanged and the worker is up.
    sess: ?*call_session.Session = null,
    /// Outgoing call we placed, waiting for the peer's answer.
    pending: bool = false,
    pending_id: u64 = 0,
    pending_agent: call_ice.Agent = undefined,
    pending_exporter: [32]u8 = undefined,
};

/// A7.2: cold struct, size guard waived — a transient parsed address.
const Addr = struct { ip: [4]u8, port: u16 };

fn parseAddr(s: []const u8) ?Addr {
    const colon = std.mem.lastIndexOfScalar(u8, s, ':') orelse return null;
    const port = std.fmt.parseInt(u16, s[colon + 1 ..], 10) catch return null;
    var ip: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, s[0..colon], '.');
    for (0..4) |i| ip[i] = std.fmt.parseInt(u8, it.next() orelse return null, 10) catch return null;
    if (it.next() != null) return null;
    return .{ .ip = ip, .port = port };
}

fn fmtCandidate(agent: *call_ice.Agent, buf: []u8) ?[]const u8 {
    const cand = call_ice.localCandidate(agent, route_probe) orelse return null;
    return std.fmt.bufPrint(buf, "{d}.{d}.{d}.{d}:{d}", .{ cand.addr[0], cand.addr[1], cand.addr[2], cand.addr[3], cand.port }) catch null;
}

/// True while a call is being set up or is live.
pub fn busy(ctl: *const CallCtl) bool {
    return ctl.sess != null or ctl.pending;
}

/// Place a call to `peer_did`: open a socket, gather our host candidate, and
/// send an offer carrying it over the chat channel. Stores the pending state
/// until the answer arrives. A no-op if already in a call, or if there is no
/// conversation / no route.
pub fn startOutgoing(
    ctl: *CallCtl,
    gpa: std.mem.Allocator,
    io: std.Io,
    env: ?*const std.process.Environ.Map,
    st: *chat_e2ee.State,
    link: *chat_relay.ChatRelay,
    peer_did: []const u8,
) void {
    if (busy(ctl)) return;
    const exporter = chat_e2ee.exporterFor(st, peer_did) orelse return;

    var id_bytes: [8]u8 = undefined;
    io.randomSecure(&id_bytes) catch return;
    const call_id = std.mem.readInt(u64, &id_bytes, .little);

    var agent = call_ice.open(0) catch return;
    var cand_buf: [32]u8 = undefined;
    const sdp = fmtCandidate(&agent, &cand_buf) orelse {
        call_ice.close(&agent);
        return;
    };

    var frame: [256]u8 = undefined;
    const n = call.serializeOffer(.{
        .call_id = call_id,
        .epoch = 0,
        .fingerprint = [_]u8{0} ** call.fingerprint_len,
        .want_video = false,
        .sdp = sdp,
    }, &frame) catch {
        call_ice.close(&agent);
        return;
    };
    chat_e2ee.sendCallFrame(gpa, io, env, st, link, peer_did, frame[0..n]) catch {};

    ctl.pending = true;
    ctl.pending_id = call_id;
    ctl.pending_agent = agent;
    ctl.pending_exporter = exporter;
}

/// Handle an inbound call signaling frame (`bytes` = `[kind][payload]`). On an
/// offer we auto-answer (gather our candidate, send the answer, start the
/// session as callee); on an answer we start the session as caller; on a
/// hangup/busy/decline we tear the call down.
pub fn onSignal(
    ctl: *CallCtl,
    gpa: std.mem.Allocator,
    io: std.Io,
    env: ?*const std.process.Environ.Map,
    st: *chat_e2ee.State,
    link: *chat_relay.ChatRelay,
    peer_did: []const u8,
    bytes: []const u8,
) void {
    if (bytes.len == 0) return;
    switch (bytes[0]) {
        call.kind_call_offer_wire => {
            if (busy(ctl)) return; // v1: ignore a second call while in one
            const offer = call.parseOffer(bytes) catch return;
            const peer = parseAddr(offer.sdp) orelse return;
            const exporter = chat_e2ee.exporterFor(st, peer_did) orelse return;

            var agent = call_ice.open(0) catch return;
            var cand_buf: [32]u8 = undefined;
            const sdp = fmtCandidate(&agent, &cand_buf) orelse {
                call_ice.close(&agent);
                return;
            };
            var frame: [256]u8 = undefined;
            const n = call.serializeAnswer(.{
                .call_id = offer.call_id,
                .fingerprint = [_]u8{0} ** call.fingerprint_len,
                .accept_video = false,
                .sdp = sdp,
            }, &frame) catch {
                call_ice.close(&agent);
                return;
            };
            chat_e2ee.sendCallFrame(gpa, io, env, st, link, peer_did, frame[0..n]) catch {};

            ctl.sess = call_session.start(gpa, agent, peer.ip, peer.port, exporter, offer.call_id, false) catch {
                call_ice.close(&agent);
                return;
            };
        },
        call.kind_call_answer_wire => {
            if (!ctl.pending) return;
            const answer = call.parseAnswer(bytes) catch return;
            if (answer.call_id != ctl.pending_id) return;
            const peer = parseAddr(answer.sdp) orelse return;
            // The session takes ownership of the pending socket.
            ctl.sess = call_session.start(gpa, ctl.pending_agent, peer.ip, peer.port, ctl.pending_exporter, answer.call_id, true) catch {
                call_ice.close(&ctl.pending_agent);
                ctl.pending = false;
                return;
            };
            ctl.pending = false;
        },
        else => shutdown(ctl), // hangup / busy / decline
    }
}

/// Tear down any live or pending call.
pub fn shutdown(ctl: *CallCtl) void {
    if (ctl.sess) |s| {
        call_session.shutdown(s);
        ctl.sess = null;
    }
    if (ctl.pending) {
        call_ice.close(&ctl.pending_agent);
        ctl.pending = false;
    }
}
