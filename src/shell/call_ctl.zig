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

/// The longest DID we will remember as a call peer. `did:plc:` is 32 bytes and
/// `did:web:` is bounded by the hostname; 128 covers both with room to spare,
/// and a longer one simply doesn't get a courtesy hangup (E4 — an absent peer
/// name is an ordinary result, not an error).
const peer_cap = 128;

/// Where a call is in its life, as the UI needs to show it.
pub const Phase = enum(u8) {
    /// Nothing happening.
    idle,
    /// Someone is calling US and we have NOT answered. The microphone is not
    /// open and no media socket exists — see `onSignal`.
    ringing_in,
    /// We called someone and are waiting for them to pick up.
    ringing_out,
    /// A session worker is up: connecting, or connected and carrying media.
    active,
};

/// PLAIN DATA (A1). The controller's state. A7.2: cold struct, size guard
/// waived — one per session (lives on RunState), never in a collection.
pub const CallCtl = struct {
    phase: Phase = .idle,

    /// A CALL WANTS THE MICROPHONE and the OS has not been asked for it.
    ///
    /// The manifest has declared RECORD_AUDIO since calling landed, and nothing in
    /// this app has ever requested a runtime permission — which stopped being
    /// optional in Android 6. On any device where it was not granted by hand,
    /// capture just fails, and a call with no microphone looks like a broken
    /// microphone rather than a missing grant.
    ///
    /// Read-and-cleared by the shell each frame; the ask happens at call START,
    /// not at launch, because a permission prompt on first run for a feature
    /// nobody has reached for is the prompt people deny out of hand.
    mic_perm_wanted: bool = false,

    /// The live call, once ICE addresses are exchanged and the worker is up.
    sess: ?*call_session.Session = null,

    /// Outgoing call we placed, waiting for the peer's answer. The socket is
    /// already open and gathering, because the candidate had to go in the offer.
    pending_id: u64 = 0,
    pending_agent: call_ice.Agent = undefined,
    pending_exporter: [32]u8 = undefined,

    /// An UNANSWERED inbound offer. Deliberately just the plain facts of it —
    /// no socket, no worker, no capture device. Nothing that touches hardware
    /// happens until `accept`.
    incoming_id: u64 = 0,
    incoming_ip: [4]u8 = .{ 0, 0, 0, 0 },
    incoming_port: u16 = 0,
    incoming_exporter: [32]u8 = undefined,

    /// Who the call is with, and its id — kept so a teardown can send the peer a
    /// hangup instead of going silent on them.
    peer_buf: [peer_cap]u8 = undefined,
    peer_len: u8 = 0,
    live_id: u64 = 0,
};

/// The peer this call is with, for the UI to name. Empty when there is no call
/// (or the DID was too long to keep — see `rememberPeer`).
pub fn peerDid(ctl: *const CallCtl) []const u8 {
    return ctl.peer_buf[0..ctl.peer_len];
}

/// Remember the call's peer for the courtesy hangup. Silently keeps nothing for
/// an over-long DID — the call still works, it just ends without notice.
fn rememberPeer(ctl: *CallCtl, peer_did: []const u8) void {
    if (peer_did.len > peer_cap) {
        ctl.peer_len = 0;
        return;
    }
    @memcpy(ctl.peer_buf[0..peer_did.len], peer_did);
    ctl.peer_len = @intCast(peer_did.len);
}

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

/// True while a call is being set up, ringing, or live.
pub fn busy(ctl: *const CallCtl) bool {
    return ctl.phase != .idle;
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

    ctl.phase = .ringing_out;
    ctl.pending_id = call_id;
    ctl.pending_agent = agent;
    ctl.pending_exporter = exporter;
    ctl.live_id = call_id;
    rememberPeer(ctl, peer_did);
}

/// ANSWER the call that is ringing. THIS is the only path that opens the
/// microphone. Gathers our candidate, sends the answer, and starts the session
/// worker. A no-op unless something is actually ringing.
pub fn accept(
    ctl: *CallCtl,
    gpa: std.mem.Allocator,
    io: std.Io,
    env: ?*const std.process.Environ.Map,
    st: *chat_e2ee.State,
    link: *chat_relay.ChatRelay,
) void {
    if (ctl.phase != .ringing_in) return;

    var agent = call_ice.open(0) catch {
        ctl.phase = .idle;
        return;
    };
    var cand_buf: [32]u8 = undefined;
    const sdp = fmtCandidate(&agent, &cand_buf) orelse {
        call_ice.close(&agent);
        ctl.phase = .idle;
        return;
    };

    var frame: [256]u8 = undefined;
    const n = call.serializeAnswer(.{
        .call_id = ctl.incoming_id,
        .fingerprint = [_]u8{0} ** call.fingerprint_len,
        .accept_video = false,
        .sdp = sdp,
    }, &frame) catch {
        call_ice.close(&agent);
        ctl.phase = .idle;
        return;
    };
    chat_e2ee.sendCallFrame(gpa, io, env, st, link, peerDid(ctl), frame[0..n]) catch {};

    ctl.sess = call_session.start(gpa, agent, ctl.incoming_ip, ctl.incoming_port, ctl.incoming_exporter, ctl.incoming_id, false) catch {
        call_ice.close(&agent);
        ctl.phase = .idle;
        return;
    };
    ctl.phase = .active;
}

/// REFUSE the call that is ringing: tell the peer, and go back to idle without
/// ever having opened a device.
pub fn decline(
    ctl: *CallCtl,
    gpa: std.mem.Allocator,
    io: std.Io,
    env: ?*const std.process.Environ.Map,
    st: *chat_e2ee.State,
    link: *chat_relay.ChatRelay,
) void {
    if (ctl.phase != .ringing_in) return;
    var frame: [64]u8 = undefined;
    if (call.serializeBye(call.kind_call_decline_wire, .{ .call_id = ctl.incoming_id, .reason = 0 }, &frame)) |n| {
        chat_e2ee.sendCallFrame(gpa, io, env, st, link, peerDid(ctl), frame[0..n]) catch {};
    } else |_| {}
    ctl.phase = .idle;
    ctl.peer_len = 0;
    ctl.live_id = 0;
}

/// Is the microphone currently being sent to the peer? False while ringing —
/// there is nothing to mute yet.
pub fn muted(ctl: *const CallCtl) bool {
    const s = ctl.sess orelse return false;
    return call_session.muted(s);
}

/// Stop or resume sending our microphone. The capture device stays open and the
/// media clock keeps running; only the transmission stops, so the peer hears
/// silence rather than a stalled stream.
pub fn setMuted(ctl: *CallCtl, on: bool) void {
    const s = ctl.sess orelse return;
    call_session.setMuted(s, on);
}

/// Reap a call whose worker has finished. The session thread exits on its own
/// when ICE fails or the media loop stops, setting only its state — without
/// this the controller would keep a dead `sess` forever and `busy()` would stay
/// true, so every later offer was ignored until the app restarted. Called once
/// per frame from the render loop; cheap (one atomic load).
pub fn poll(ctl: *CallCtl) void {
    const s = ctl.sess orelse return;
    if (call_session.state(s) != .ended) return;
    call_session.shutdown(s);
    ctl.sess = null;
    ctl.phase = .idle;
    ctl.peer_len = 0;
    ctl.live_id = 0;
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
            if (busy(ctl)) {
                // Already in or setting up a call. Tell them rather than
                // letting the offer vanish into silence.
                const other = call.parseOffer(bytes) catch return;
                var frame: [64]u8 = undefined;
                if (call.serializeBye(call.kind_call_busy_wire, .{ .call_id = other.call_id, .reason = 0 }, &frame)) |n| {
                    chat_e2ee.sendCallFrame(gpa, io, env, st, link, peer_did, frame[0..n]) catch {};
                } else |_| {}
                return;
            }
            const offer = call.parseOffer(bytes) catch return;
            const peer = parseAddr(offer.sdp) orelse return;
            const exporter = chat_e2ee.exporterFor(st, peer_did) orelse return;

            // RING. Do NOT answer, do NOT open a socket, do NOT open the
            // microphone. An inbound offer is a REQUEST; until a person accepts
            // it, the only thing that happens is that we remember it.
            //
            // This used to auto-answer, which meant any peer in a conversation
            // could open this device's microphone silently and with no
            // indication. That was a bring-up convenience and it had no business
            // outliving bring-up.
            ctl.phase = .ringing_in;
            ctl.incoming_id = offer.call_id;
            ctl.incoming_ip = peer.ip;
            ctl.incoming_port = peer.port;
            ctl.incoming_exporter = exporter;
            ctl.live_id = offer.call_id;
            rememberPeer(ctl, peer_did);
        },
        call.kind_call_answer_wire => {
            if (ctl.phase != .ringing_out) return;
            const answer = call.parseAnswer(bytes) catch return;
            if (answer.call_id != ctl.pending_id) return;
            const peer = parseAddr(answer.sdp) orelse return;
            // The session takes ownership of the pending socket.
            ctl.sess = call_session.start(gpa, ctl.pending_agent, peer.ip, peer.port, ctl.pending_exporter, answer.call_id, true) catch {
                call_ice.close(&ctl.pending_agent);
                ctl.phase = .idle;
                return;
            };
            ctl.phase = .active;
            ctl.live_id = answer.call_id;
            rememberPeer(ctl, peer_did);
        },
        else => shutdown(ctl), // hangup / busy / decline
    }
}

/// End the call from THIS side: tell the peer first, then tear down. Separate
/// from `shutdown` because only this path has the chat channel to speak over —
/// `shutdown` is the resource teardown and is also what runs at app exit.
pub fn hangup(
    ctl: *CallCtl,
    gpa: std.mem.Allocator,
    io: std.Io,
    env: ?*const std.process.Environ.Map,
    st: *chat_e2ee.State,
    link: *chat_relay.ChatRelay,
) void {
    if (!busy(ctl)) return;
    if (ctl.peer_len > 0) {
        var frame: [64]u8 = undefined;
        if (call.serializeBye(call.kind_call_hangup_wire, .{ .call_id = ctl.live_id, .reason = 0 }, &frame)) |n| {
            chat_e2ee.sendCallFrame(gpa, io, env, st, link, ctl.peer_buf[0..ctl.peer_len], frame[0..n]) catch {};
        } else |_| {}
    }
    shutdown(ctl);
}

/// Tear down any live or pending call, releasing the worker + socket. Sends
/// nothing — use `hangup` when the peer should be told.
pub fn shutdown(ctl: *CallCtl) void {
    if (ctl.sess) |s| {
        call_session.shutdown(s);
        ctl.sess = null;
    }
    // An outgoing call still holds the socket it gathered its candidate on; a
    // ringing INBOUND call holds nothing, which is the whole point of the
    // consent gate.
    if (ctl.phase == .ringing_out) call_ice.close(&ctl.pending_agent);
    ctl.phase = .idle;
    ctl.peer_len = 0;
    ctl.live_id = 0;
}
