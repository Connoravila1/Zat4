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

//! B1 classification: CORE (pure). The call state machine and the call
//! signaling wire format for Zat Chat voice/video calling. See
//! ZAT_CHAT_CALLING_ROADMAP.md (Phase V0) and CALLING_ARCHITECTURE.md (§1.4,
//! §2) for the design and the why.
//!
//! PURE (B2/B3/B4): no clock, no RNG, no I/O, no sockets, no media library.
//! Timestamps and the call id are handed in by the shell; every transition is
//! a pure function of `(state, event)`. Given the same inputs the machine
//! produces the same next state and the same set of side-effects, so the whole
//! lifecycle is unit-testable headlessly (see the tests at the foot of this
//! file). The shell (`shell/call_signal.zig`, `shell/call_engine.zig` — not
//! built yet) INTERPRETS the returned effects; the core never performs one.
//!
//! Wire format ownership (D3/D4): this module owns the call signaling wire
//! vocabulary — the `kind_call_*_wire` bytes and the offer/answer/ice/hangup
//! framing. They ride the existing E2EE chat channel exactly like a text
//! message ([kind][payload] → mls.encrypt → 4096-byte bucket → peer mailbox),
//! so signaling is end-to-end encrypted for free with no new transport. The
//! bytes live in the reserved call range 24..31 (chat.zig documents the
//! reservation); chat's `parseKind` keeps rejecting them, so a call frame can
//! never leak into the message store.

const std = @import("std");
const assert = std.debug.assert;

// ---------------------------------------------------------------------------
// The state machine
// ---------------------------------------------------------------------------

/// The call lifecycle. `outgoing_ringing` (we placed the call, waiting for the
/// peer to answer) and `incoming_ringing` (a peer offer arrived, ringing us)
/// split the single "ringing" concept by role so the transition table needs no
/// separate role flag to decide what an event means. `ended` is terminal.
pub const CallState = enum(u8) {
    idle = 0,
    outgoing_ringing = 1,
    incoming_ringing = 2,
    connecting = 3,
    active = 4,
    ended = 5,
};

/// Everything that can drive the machine: local user intents (`place`,
/// `local_answer`, `local_hangup`), peer signaling messages (`incoming_offer`,
/// `remote_answer`, `ice`, `remote_hangup`, `decline`, `busy`), and transport
/// milestones (`connected`, `timeout`, `failed`). Plain data in (B5); the shell
/// maps a decoded signaling frame or a transport callback to one of these.
pub const CallEvent = enum(u8) {
    place,
    incoming_offer,
    local_answer,
    remote_answer,
    ice,
    connected,
    local_hangup,
    remote_hangup,
    decline,
    busy,
    timeout,
    failed,
};

/// The side-effects a transition asks the shell to perform, as an out-of-band
/// bitset (A6): a transition may need more than one (e.g. `local_hangup` sends
/// a hangup frame AND releases the media pipeline). The core never performs an
/// effect — it only names them; the shell interprets (B4).
pub const Effects = packed struct(u16) {
    send_offer: bool = false,
    send_answer: bool = false,
    send_hangup: bool = false,
    send_busy: bool = false,
    send_decline: bool = false,
    /// Ring the local device (an incoming call arrived).
    ring: bool = false,
    /// Bring up the media pipeline (transport is established, media may flow).
    start_media: bool = false,
    /// Tear down media, timers, and transport.
    release: bool = false,
    _pad: u8 = 0,

    comptime {
        // A fixed u16-backed bitset; the backing int pins the size at 2 bytes.
        assert(@sizeOf(Effects) == 2);
    }
};

/// The result of a transition. A7.2: cold struct, size guard waived — a
/// transient return value, never stored in a collection or scanned in bulk.
pub const Transition = struct {
    next: CallState,
    effects: Effects,
};

/// The pure transition function: `(state, event) -> (next state, effects)`.
///
/// Illegal or irrelevant `(state, event)` pairs are defined out of existence
/// (E4): they resolve to "stay in the current state with no effect" rather than
/// an error path, so a stray or duplicated signaling message can never crash a
/// call or corrupt its state (E2/E3). `ended` is terminal and absorbs every
/// event. The `ice` event never changes state — a trickled candidate is handed
/// straight to the transport by the shell — so it is a no-op in every live
/// state and ignored in `idle`/`ended`.
pub fn transition(state: CallState, event: CallEvent) Transition {
    // ICE candidates never move the machine; they flow to the transport.
    if (event == .ice) return .{ .next = state, .effects = .{} };

    return switch (state) {
        .idle => switch (event) {
            .place => .{ .next = .outgoing_ringing, .effects = .{ .send_offer = true } },
            .incoming_offer => .{ .next = .incoming_ringing, .effects = .{ .ring = true } },
            else => stay(state),
        },

        .outgoing_ringing => switch (event) {
            .remote_answer => .{ .next = .connecting, .effects = .{} },
            .connected => .{ .next = .active, .effects = .{ .start_media = true } },
            .decline => .{ .next = .ended, .effects = .{ .release = true } },
            .busy => .{ .next = .ended, .effects = .{ .release = true } },
            .remote_hangup => .{ .next = .ended, .effects = .{ .release = true } },
            // The caller cancels an un-answered call: tell the peer, then release.
            .local_hangup, .timeout => .{ .next = .ended, .effects = .{ .send_hangup = true, .release = true } },
            .failed => .{ .next = .ended, .effects = .{ .release = true } },
            else => stay(state),
        },

        .incoming_ringing => switch (event) {
            .local_answer => .{ .next = .connecting, .effects = .{ .send_answer = true } },
            // The user declines, or the ring times out into a missed call.
            .local_hangup, .decline, .timeout => .{ .next = .ended, .effects = .{ .send_decline = true, .release = true } },
            // The caller gave up before we answered.
            .remote_hangup => .{ .next = .ended, .effects = .{ .release = true } },
            .failed => .{ .next = .ended, .effects = .{ .release = true } },
            else => stay(state),
        },

        .connecting => switch (event) {
            .connected => .{ .next = .active, .effects = .{ .start_media = true } },
            .local_hangup => .{ .next = .ended, .effects = .{ .send_hangup = true, .release = true } },
            .remote_hangup => .{ .next = .ended, .effects = .{ .release = true } },
            .timeout, .failed => .{ .next = .ended, .effects = .{ .send_hangup = true, .release = true } },
            else => stay(state),
        },

        .active => switch (event) {
            // A re-established transport (e.g. an ICE restart, §7.5) is idempotent.
            .connected => stay(state),
            .local_hangup => .{ .next = .ended, .effects = .{ .send_hangup = true, .release = true } },
            .remote_hangup => .{ .next = .ended, .effects = .{ .release = true } },
            .failed => .{ .next = .ended, .effects = .{ .release = true } },
            else => stay(state),
        },

        // Terminal: nothing reactivates a call. The shell mints a new one.
        .ended => stay(state),
    };
}

inline fn stay(state: CallState) Transition {
    return .{ .next = state, .effects = .{} };
}

/// True once the call has reached its terminal state.
pub fn isTerminal(state: CallState) bool {
    return state == .ended;
}

/// True while media is (or is about to be) flowing.
pub fn isLive(state: CallState) bool {
    return state == .connecting or state == .active;
}

// ---------------------------------------------------------------------------
// The call record
// ---------------------------------------------------------------------------

/// A call id: a random 64-bit tag minted by the shell (`io.randomSecure`) when
/// a call is placed, echoed in every signaling frame so both ends and any
/// duplicate delivery agree which call a message belongs to. A stable id across
/// the module boundary (A5) — never an internal index.
pub const CallId = u64;

/// The DTLS certificate fingerprint length: SHA-256, raw bytes (RFC 8122). The
/// fingerprint travels inside the MLS-encrypted offer/answer, so the P2P
/// DTLS-SRTP connection is authenticated by the MLS channel — no separate MITM
/// surface (CALLING_ARCHITECTURE.md §5.1).
pub const fingerprint_len = 32;

/// PLAIN DATA (A1). One live call. A user has at most a handful of these ever
/// concurrently, but the tie-break rule (treat as hot when ambiguous) earns it
/// a guard. Fields only; behaviour is in the free functions above.
pub const Call = struct {
    started_at: i64, // wall-clock seconds at `place`/`incoming_offer` (shell-supplied)
    connected_at: i64, // wall-clock seconds at `active`; 0 until then
    id: CallId, // u64
    state: CallState, // u8
    outgoing: bool, // true if we placed it (false: we received the offer)
    has_audio: bool, // an audio track is present (always true once active)
    has_video: bool, // a video track is present (may toggle mid-call, §7.4)
    _pad: u32 = 0, // A6: explicit pad to the 8-byte alignment boundary

    comptime {
        // Budget: i64+i64+u64 = 24, then u8+bool+bool+bool = 4, then u32 pad = 4.
        // 32 exact, no tail padding. Raising this requires an A7.1 justification.
        assert(@sizeOf(Call) == 32);
    }
};

// ---------------------------------------------------------------------------
// Signaling wire format (owned here, D3/D4)
// ---------------------------------------------------------------------------

// The call signaling wire kind bytes. Reserved range 24..31 (chat.zig's Kind
// doc records the reservation so nobody reuses them). Wire-only: they ride the
// E2EE chat channel but are consumed at the call layer and never stored, so
// chat's `parseKind` keeps rejecting them.
pub const kind_call_offer_wire: u8 = 24;
pub const kind_call_answer_wire: u8 = 25;
pub const kind_call_ice_wire: u8 = 26;
pub const kind_call_hangup_wire: u8 = 27;
pub const kind_call_busy_wire: u8 = 28;
pub const kind_call_decline_wire: u8 = 29;

/// A call invitation. `epoch` selects which MLS epoch's exporter derives the
/// media keys (`media_keys.zig`), so both ends key media from the same secret.
/// A7.2: cold struct, size guard waived — one per call setup, never in bulk.
/// The `sdp` slice is borrowed from the frame buffer on parse.
pub const Offer = struct {
    call_id: CallId,
    epoch: u64,
    fingerprint: [fingerprint_len]u8,
    want_video: bool,
    sdp: []const u8,
};

/// The answer to an `Offer`. A7.2: cold struct, size guard waived.
pub const Answer = struct {
    call_id: CallId,
    fingerprint: [fingerprint_len]u8,
    accept_video: bool,
    sdp: []const u8,
};

/// One trickled ICE candidate (RFC 8838). A7.2: cold struct, size guard waived.
pub const Ice = struct {
    call_id: CallId,
    candidate: []const u8,
};

/// A hangup / busy / decline. All three share this shape; the kind byte
/// distinguishes intent. `reason` is a small application code. A7.2: cold
/// struct, size guard waived.
pub const Bye = struct {
    call_id: CallId,
    reason: u8,
};

pub const ParseError = error{ Truncated, WrongKind, TooLong };

/// The longest payload a call frame may carry, so serialization can bound-check
/// against the fixed relay bucket. SDP offers for a 1:1 call are well under
/// this; ICE candidates are tiny.
pub const max_blob_len = 3072;

// -- offer -------------------------------------------------------------------

/// Serialize an offer into `buf`, returning the frame length. Layout:
/// [kind:1][call_id:8 BE][epoch:8 BE][fingerprint:32][flags:1][sdp_len:2 BE][sdp...].
pub fn serializeOffer(o: Offer, buf: []u8) error{BufferTooSmall}!usize {
    if (o.sdp.len > max_blob_len) return error.BufferTooSmall;
    const total = 1 + 8 + 8 + fingerprint_len + 1 + 2 + o.sdp.len;
    if (buf.len < total) return error.BufferTooSmall;
    var p: usize = 0;
    buf[p] = kind_call_offer_wire;
    p += 1;
    std.mem.writeInt(u64, buf[p..][0..8], o.call_id, .big);
    p += 8;
    std.mem.writeInt(u64, buf[p..][0..8], o.epoch, .big);
    p += 8;
    @memcpy(buf[p..][0..fingerprint_len], &o.fingerprint);
    p += fingerprint_len;
    buf[p] = @intFromBool(o.want_video);
    p += 1;
    std.mem.writeInt(u16, buf[p..][0..2], @intCast(o.sdp.len), .big);
    p += 2;
    @memcpy(buf[p..][0..o.sdp.len], o.sdp);
    p += o.sdp.len;
    return p;
}

/// Parse an offer frame. The returned `sdp` borrows from `frame` (E4: absent
/// SDP is an empty slice, not an error).
pub fn parseOffer(frame: []const u8) ParseError!Offer {
    const head = 1 + 8 + 8 + fingerprint_len + 1 + 2;
    if (frame.len < head) return error.Truncated;
    if (frame[0] != kind_call_offer_wire) return error.WrongKind;
    var p: usize = 1;
    const call_id = std.mem.readInt(u64, frame[p..][0..8], .big);
    p += 8;
    const epoch = std.mem.readInt(u64, frame[p..][0..8], .big);
    p += 8;
    var fp: [fingerprint_len]u8 = undefined;
    @memcpy(&fp, frame[p..][0..fingerprint_len]);
    p += fingerprint_len;
    const want_video = frame[p] != 0;
    p += 1;
    const sdp_len = std.mem.readInt(u16, frame[p..][0..2], .big);
    p += 2;
    if (frame.len < head + sdp_len) return error.Truncated;
    return .{
        .call_id = call_id,
        .epoch = epoch,
        .fingerprint = fp,
        .want_video = want_video,
        .sdp = frame[p..][0..sdp_len],
    };
}

// -- answer ------------------------------------------------------------------

/// Serialize an answer. Layout:
/// [kind:1][call_id:8 BE][fingerprint:32][flags:1][sdp_len:2 BE][sdp...].
pub fn serializeAnswer(a: Answer, buf: []u8) error{BufferTooSmall}!usize {
    if (a.sdp.len > max_blob_len) return error.BufferTooSmall;
    const total = 1 + 8 + fingerprint_len + 1 + 2 + a.sdp.len;
    if (buf.len < total) return error.BufferTooSmall;
    var p: usize = 0;
    buf[p] = kind_call_answer_wire;
    p += 1;
    std.mem.writeInt(u64, buf[p..][0..8], a.call_id, .big);
    p += 8;
    @memcpy(buf[p..][0..fingerprint_len], &a.fingerprint);
    p += fingerprint_len;
    buf[p] = @intFromBool(a.accept_video);
    p += 1;
    std.mem.writeInt(u16, buf[p..][0..2], @intCast(a.sdp.len), .big);
    p += 2;
    @memcpy(buf[p..][0..a.sdp.len], a.sdp);
    p += a.sdp.len;
    return p;
}

pub fn parseAnswer(frame: []const u8) ParseError!Answer {
    const head = 1 + 8 + fingerprint_len + 1 + 2;
    if (frame.len < head) return error.Truncated;
    if (frame[0] != kind_call_answer_wire) return error.WrongKind;
    var p: usize = 1;
    const call_id = std.mem.readInt(u64, frame[p..][0..8], .big);
    p += 8;
    var fp: [fingerprint_len]u8 = undefined;
    @memcpy(&fp, frame[p..][0..fingerprint_len]);
    p += fingerprint_len;
    const accept_video = frame[p] != 0;
    p += 1;
    const sdp_len = std.mem.readInt(u16, frame[p..][0..2], .big);
    p += 2;
    if (frame.len < head + sdp_len) return error.Truncated;
    return .{
        .call_id = call_id,
        .fingerprint = fp,
        .accept_video = accept_video,
        .sdp = frame[p..][0..sdp_len],
    };
}

// -- ice ---------------------------------------------------------------------

/// Serialize one trickled ICE candidate. Layout:
/// [kind:1][call_id:8 BE][cand_len:2 BE][candidate...].
pub fn serializeIce(i: Ice, buf: []u8) error{BufferTooSmall}!usize {
    if (i.candidate.len > max_blob_len) return error.BufferTooSmall;
    const total = 1 + 8 + 2 + i.candidate.len;
    if (buf.len < total) return error.BufferTooSmall;
    var p: usize = 0;
    buf[p] = kind_call_ice_wire;
    p += 1;
    std.mem.writeInt(u64, buf[p..][0..8], i.call_id, .big);
    p += 8;
    std.mem.writeInt(u16, buf[p..][0..2], @intCast(i.candidate.len), .big);
    p += 2;
    @memcpy(buf[p..][0..i.candidate.len], i.candidate);
    p += i.candidate.len;
    return p;
}

pub fn parseIce(frame: []const u8) ParseError!Ice {
    const head = 1 + 8 + 2;
    if (frame.len < head) return error.Truncated;
    if (frame[0] != kind_call_ice_wire) return error.WrongKind;
    var p: usize = 1;
    const call_id = std.mem.readInt(u64, frame[p..][0..8], .big);
    p += 8;
    const cand_len = std.mem.readInt(u16, frame[p..][0..2], .big);
    p += 2;
    if (frame.len < head + cand_len) return error.Truncated;
    return .{ .call_id = call_id, .candidate = frame[p..][0..cand_len] };
}

// -- bye (hangup / busy / decline) ------------------------------------------

/// Serialize a hangup/busy/decline. `kind` must be one of the three bye kinds.
/// Layout: [kind:1][call_id:8 BE][reason:1].
pub fn serializeBye(kind: u8, b: Bye, buf: []u8) error{ BufferTooSmall, BadKind }!usize {
    if (kind != kind_call_hangup_wire and kind != kind_call_busy_wire and kind != kind_call_decline_wire)
        return error.BadKind;
    const total = 1 + 8 + 1;
    if (buf.len < total) return error.BufferTooSmall;
    buf[0] = kind;
    std.mem.writeInt(u64, buf[1..][0..8], b.call_id, .big);
    buf[9] = b.reason;
    return total;
}

/// Parse a bye frame; returns the kind byte alongside the record so the caller
/// can distinguish hangup/busy/decline.
pub fn parseBye(frame: []const u8) ParseError!struct { kind: u8, bye: Bye } {
    if (frame.len < 1 + 8 + 1) return error.Truncated;
    const kind = frame[0];
    if (kind != kind_call_hangup_wire and kind != kind_call_busy_wire and kind != kind_call_decline_wire)
        return error.WrongKind;
    return .{
        .kind = kind,
        .bye = .{ .call_id = std.mem.readInt(u64, frame[1..][0..8], .big), .reason = frame[9] },
    };
}

/// Map a decoded signaling kind byte to the `CallEvent` it drives. Returns null
/// for a byte that is not a call kind (the shell ignores it). The bye kinds map
/// to `remote_hangup`/`busy`/`decline`; local intents come from the UI, not the
/// wire, so they are not produced here.
pub fn eventForKind(kind: u8) ?CallEvent {
    return switch (kind) {
        kind_call_offer_wire => .incoming_offer,
        kind_call_answer_wire => .remote_answer,
        kind_call_ice_wire => .ice,
        kind_call_hangup_wire => .remote_hangup,
        kind_call_busy_wire => .busy,
        kind_call_decline_wire => .decline,
        else => null,
    };
}

// ---------------------------------------------------------------------------
// Tests (B2/C6 — pure, deterministic; no allocator needed here)
// ---------------------------------------------------------------------------

const testing = std.testing;

test "happy path: outgoing call places, answers, connects, hangs up" {
    // Place.
    var t = transition(.idle, .place);
    try testing.expectEqual(CallState.outgoing_ringing, t.next);
    try testing.expect(t.effects.send_offer);

    // Peer answers.
    t = transition(t.next, .remote_answer);
    try testing.expectEqual(CallState.connecting, t.next);

    // Transport up.
    t = transition(t.next, .connected);
    try testing.expectEqual(CallState.active, t.next);
    try testing.expect(t.effects.start_media);

    // We hang up.
    t = transition(t.next, .local_hangup);
    try testing.expectEqual(CallState.ended, t.next);
    try testing.expect(t.effects.send_hangup and t.effects.release);
}

test "happy path: incoming call rings, answers, connects" {
    var t = transition(.idle, .incoming_offer);
    try testing.expectEqual(CallState.incoming_ringing, t.next);
    try testing.expect(t.effects.ring);

    t = transition(t.next, .local_answer);
    try testing.expectEqual(CallState.connecting, t.next);
    try testing.expect(t.effects.send_answer);

    t = transition(t.next, .connected);
    try testing.expectEqual(CallState.active, t.next);
    try testing.expect(t.effects.start_media);
}

test "incoming call declined sends a decline and releases" {
    const t = transition(.incoming_ringing, .decline);
    try testing.expectEqual(CallState.ended, t.next);
    try testing.expect(t.effects.send_decline and t.effects.release);
}

test "outgoing ring timeout cancels toward the peer" {
    const t = transition(.outgoing_ringing, .timeout);
    try testing.expectEqual(CallState.ended, t.next);
    try testing.expect(t.effects.send_hangup and t.effects.release);
}

test "ended is terminal — every event is absorbed with no effect" {
    inline for (std.meta.fields(CallEvent)) |f| {
        const ev: CallEvent = @enumFromInt(f.value);
        const t = transition(.ended, ev);
        try testing.expectEqual(CallState.ended, t.next);
        try testing.expectEqual(@as(u16, 0), @as(u16, @bitCast(t.effects)));
    }
}

test "illegal transitions are defined out of existence (no crash, no move)" {
    // A remote answer while idle, a place while active, a busy while active:
    // all stay put with no effect rather than erroring (E4).
    try testing.expectEqual(CallState.idle, transition(.idle, .remote_answer).next);
    try testing.expectEqual(CallState.active, transition(.active, .place).next);
    try testing.expectEqual(CallState.active, transition(.active, .busy).next);
    try testing.expectEqual(@as(u16, 0), @as(u16, @bitCast(transition(.active, .place).effects)));
}

test "ice never changes state in any live state" {
    inline for (.{ CallState.outgoing_ringing, CallState.incoming_ringing, CallState.connecting, CallState.active }) |s| {
        const t = transition(s, .ice);
        try testing.expectEqual(s, t.next);
        try testing.expectEqual(@as(u16, 0), @as(u16, @bitCast(t.effects)));
    }
}

test "transition is total and never escapes to a non-terminal on failure" {
    // Sweep the whole (state × event) matrix: no combination panics, and
    // `failed` always drives a live call to `ended`.
    inline for (std.meta.fields(CallState)) |sf| {
        const s: CallState = @enumFromInt(sf.value);
        inline for (std.meta.fields(CallEvent)) |ef| {
            const e: CallEvent = @enumFromInt(ef.value);
            const t = transition(s, e);
            if (e == .failed and isLive(s)) {
                try testing.expectEqual(CallState.ended, t.next);
            }
        }
    }
}

test "offer round-trips through serialize/parse" {
    const sdp = "v=0\r\no=- 42 2 IN IP4 127.0.0.1\r\n";
    var fp: [fingerprint_len]u8 = undefined;
    for (&fp, 0..) |*b, i| b.* = @intCast(i);
    const o: Offer = .{ .call_id = 0xABCD_1234_5678_9EF0, .epoch = 7, .fingerprint = fp, .want_video = true, .sdp = sdp };

    var buf: [512]u8 = undefined;
    const n = try serializeOffer(o, &buf);
    const got = try parseOffer(buf[0..n]);
    try testing.expectEqual(o.call_id, got.call_id);
    try testing.expectEqual(o.epoch, got.epoch);
    try testing.expectEqualSlices(u8, &o.fingerprint, &got.fingerprint);
    try testing.expectEqual(o.want_video, got.want_video);
    try testing.expectEqualSlices(u8, o.sdp, got.sdp);
    try testing.expectEqual(CallEvent.incoming_offer, eventForKind(buf[0]).?);
}

test "answer and ice round-trip" {
    var fp: [fingerprint_len]u8 = [_]u8{9} ** fingerprint_len;
    fp[0] = 1;
    const a: Answer = .{ .call_id = 5, .fingerprint = fp, .accept_video = false, .sdp = "a=recvonly" };
    var buf: [256]u8 = undefined;
    var n = try serializeAnswer(a, &buf);
    const ga = try parseAnswer(buf[0..n]);
    try testing.expectEqual(a.call_id, ga.call_id);
    try testing.expectEqual(a.accept_video, ga.accept_video);
    try testing.expectEqualSlices(u8, a.sdp, ga.sdp);

    const ice: Ice = .{ .call_id = 5, .candidate = "candidate:1 1 udp 2130706431 192.0.2.1 54321 typ host" };
    n = try serializeIce(ice, &buf);
    const gi = try parseIce(buf[0..n]);
    try testing.expectEqual(ice.call_id, gi.call_id);
    try testing.expectEqualSlices(u8, ice.candidate, gi.candidate);
}

test "bye kinds serialize and map to the right event" {
    var buf: [16]u8 = undefined;
    const n = try serializeBye(kind_call_hangup_wire, .{ .call_id = 99, .reason = 3 }, &buf);
    const parsed = try parseBye(buf[0..n]);
    try testing.expectEqual(kind_call_hangup_wire, parsed.kind);
    try testing.expectEqual(@as(u64, 99), parsed.bye.call_id);
    try testing.expectEqual(@as(u8, 3), parsed.bye.reason);
    try testing.expectEqual(CallEvent.remote_hangup, eventForKind(kind_call_hangup_wire).?);
    try testing.expectEqual(CallEvent.busy, eventForKind(kind_call_busy_wire).?);
    try testing.expectEqual(CallEvent.decline, eventForKind(kind_call_decline_wire).?);
    try testing.expect(eventForKind(0) == null); // Kind.text is not a call kind
}

test "parse rejects truncated and mis-kinded frames explicitly (E3)" {
    var buf: [512]u8 = undefined;
    const n = try serializeOffer(.{ .call_id = 1, .epoch = 0, .fingerprint = undefined, .want_video = false, .sdp = "xyz" }, &buf);
    try testing.expectError(error.Truncated, parseOffer(buf[0 .. n - 1]));
    try testing.expectError(error.WrongKind, parseAnswer(buf[0..n])); // it's an offer frame
    try testing.expectError(error.Truncated, parseIce(buf[0..4]));
    try testing.expectError(error.BadKind, serializeBye(kind_call_offer_wire, .{ .call_id = 1, .reason = 0 }, &buf));
}
