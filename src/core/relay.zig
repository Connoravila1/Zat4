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

//! B1 classification: CORE (pure). The Zat Chat relay's model + wire
//! vocabulary (ZAT_CHAT_ROADMAP slice U4).
//!
//! The relay is a dumb store-and-forward pipe for E2EE chat: it holds
//! **fixed-size padded ciphertext blobs** keyed by opaque **mailbox IDs**
//! and forgets them the moment they are acknowledged (delivered means
//! deleted) or their TTL lapses (undelivered means expired — M3). It is
//! structurally incapable of knowing more: a mailbox ID is a capability,
//! not an account — no DIDs, no handles cross this boundary — and every
//! blob is exactly `bucket_len` bytes (padding is client-side), so the
//! relay never even learns a message's size.
//!
//! This module is everything about the relay that ISN'T a socket: the
//! mailbox store (plain data, SoA — A1/A3), the deposit/ack/expiry
//! decisions with `now` passed in (B4 — no clock here), and the binary op
//! vocabulary both ends speak inside WebSocket binary frames (one codec,
//! both directions — the core/websocket.zig precedent). The shell
//! (`shell/relay_serve.zig` today, `shell/chat_relay.zig` in U5) pumps
//! bytes and rolls entropy; this module only transforms.
//!
//! Wire ops (payloads of WebSocket BINARY frames; all fixed-size):
//!   client → server:
//!     0x01 deposit    [1 op][32 mailbox][4096 blob]
//!     0x02 subscribe  [1 op][32 mailbox]
//!     0x03 ack        [1 op][32 mailbox]   (acks the oldest delivered blob)
//!   server → client:
//!     0x11 deliver    [1 op][32 mailbox][4096 blob]
//!     0x12 deposit_ok [1 op]
//!     0x13 refused    [1 op][1 reason]     (reason = DepositResult)
//!
//! Delivery is at-least-once by design: a blob is deleted only on ack, so
//! a connection dropped mid-delivery re-delivers on reconnect. The MLS
//! layer above already rejects replays (StaleGeneration), so redelivery is
//! safe — the client acks after processing.

const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;

pub const mailbox_id_len = 32;

/// The ONE blob size class (v1). Every deposit is exactly this many bytes of
/// ciphertext, padded by the CLIENT — uniformity is the point (vision doc §6):
/// a relay that accepted variable sizes would become a message-size oracle.
/// Room check: an MLS PrivateMessage for this suite carries ~150 bytes of
/// framing over the padded application payload, so one bucket holds ~3.8 KiB
/// of padded plaintext — several paragraphs of chat.
pub const bucket_len = 4096;

// Op bytes (the full vocabulary, defined once — new ops append, never renumber).
pub const op_deposit: u8 = 0x01;
pub const op_subscribe: u8 = 0x02;
pub const op_ack: u8 = 0x03;
/// Client → server: the answer to a challenge (A4 slice 2).
pub const op_auth: u8 = 0x04;
pub const op_deliver: u8 = 0x11;
pub const op_deposit_ok: u8 = 0x12;
pub const op_refused: u8 = 0x13;
/// Server → client: this connection's login nonce (A4 slice 2).
pub const op_challenge: u8 = 0x14;
/// Server → client: the anchor key signed the nonce AND the directory binds
/// that key to the claimed DID. The relay now knows WHO is connected.
pub const op_auth_ok: u8 = 0x15;

pub const deposit_frame_len = 1 + mailbox_id_len + bucket_len;
pub const subscribe_frame_len = 1 + mailbox_id_len;
pub const ack_frame_len = 1 + mailbox_id_len;
pub const deliver_frame_len = 1 + mailbox_id_len + bucket_len;

// --- Auth frames (A4 slice 2) ---------------------------------------------
//
// A NOTE ON THE FLAG DAY, because it is the whole reason these are shaped this
// way. A client that meets an op byte it does not know tears its connection
// down (`parseServerOp` → BadOp → ProtocolViolation) and reconnects forever.
// So the relay must NOT send `challenge` to a client that has not asked for
// it: the upgrade carries an opt-in header, and only a client that sent it is
// challenged. Old clients see the protocol they have always seen. When every
// client speaks auth, the relay flips `require_auth` and the old ones are
// locked out on purpose — but not by accident, and not before.

pub const challenge_len = 32;
pub const anchor_pub_len = 32;
pub const auth_sig_len = 64;
/// The wire cap on a claimed DID. Generous against real DIDs (~32 bytes) and
/// small enough that the auth frame is a bounded, stack-sized thing.
pub const max_auth_did_len = 256;

pub const challenge_frame_len = 1 + challenge_len;
pub const auth_ok_frame_len = 1;
/// [1 op][32 anchor_pub][64 sig][1 did_len][did …]
pub const auth_frame_head = 1 + anchor_pub_len + auth_sig_len + 1;
pub const auth_frame_max = auth_frame_head + max_auth_did_len;

/// Why a deposit was refused. The numeric values ride the wire in the
/// `refused` op, so they are pinned (E3: the sender learns why, explicitly).
pub const DepositResult = enum(u8) {
    ok = 0,
    mailbox_full = 1,
    store_full = 2,
    /// This connection is depositing faster than the rate limit allows. The
    /// blob is NOT stored; the sender may retry after a beat. This is the first
    /// line against the shared-token flood: without it, one connection can fill
    /// the entire store (`max_total`) as fast as it can write, denying every
    /// other user — a trivial DoS for anyone who extracts the relay token from a
    /// client. See `TokenBucket`. (New reason: older clients that don't know it
    /// treat any nonzero reason as "refused, don't crash", so it's wire-safe.)
    rate_limited = 3,
    /// The relay requires an authenticated identity (A4 slice 2) and this
    /// connection has none. Only reachable once the operator flips
    /// `require_auth`; before that an unauthenticated connection is served
    /// exactly as it always was (the transition window).
    unauthenticated = 4,
};

/// A per-connection deposit rate limiter — pure, so it's testable and lives with
/// the policy it enforces, not buried in the serve loop.
///
/// The relay is deliberately dumb and identity-blind, which is a privacy virtue
/// and an abuse liability: it cannot tell a flooder from a friend. It CAN,
/// though, bound how fast any ONE connection consumes the shared store, and that
/// alone converts "instantly nuke the relay for everyone" into "trickle, heavily
/// throttled, every refusal logged, legitimate traffic interleaving the whole
/// time." Identity-based limits (per-DID auth) are the deeper layer and need a
/// coordinated client+relay change; this needs neither and ships to the relay
/// alone, breaking nothing.
///
/// A steady rate of `refill_per_sec` deposits, burstable up to `capacity`.
/// A7: hot-ish (one per live connection), guarded.
pub const TokenBucket = struct {
    /// Whole tokens available now.
    tokens: f64,
    capacity: f64,
    refill_per_sec: f64,
    /// Monotonic seconds of the last refill (the caller's clock; B4).
    last: f64,

    comptime {
        assert(@sizeOf(TokenBucket) == 32);
    }

    pub fn init(capacity: f64, refill_per_sec: f64, now_s: f64) TokenBucket {
        return .{ .tokens = capacity, .capacity = capacity, .refill_per_sec = refill_per_sec, .last = now_s };
    }

    /// Try to spend one token at time `now_s`. Refills for elapsed time first,
    /// clamped to `capacity`. Returns true if a token was available (allow), false
    /// if the connection is over its rate (refuse). Time going backwards is
    /// treated as no elapsed time — a clock is not a weapon we hand the caller.
    pub fn take(b: *TokenBucket, now_s: f64) bool {
        const dt = @max(0, now_s - b.last);
        b.last = now_s;
        b.tokens = @min(b.capacity, b.tokens + dt * b.refill_per_sec);
        if (b.tokens >= 1.0) {
            b.tokens -= 1.0;
            return true;
        }
        return false;
    }
};

/// The per-connection deposit rate: a steady 5/sec, burstable to 20. A human in
/// a fast conversation sends a handful of messages a minute; 5/sec is orders of
/// beyond that and still caps a flooder to 5 blobs/sec, so filling `max_total`
/// (8192) takes ~27 minutes of sustained, refused, logged flooding per
/// connection instead of an instant. Tune with real load; deliberately generous
/// so it never touches a real user.
pub const deposit_rate_capacity: f64 = 20;
pub const deposit_rate_per_sec: f64 = 5;

/// Service limits, all enforced in `deposit`. Defaults sized for the v1
/// deployment (a handful of users on one box): 8192 blobs × 4 KiB = 32 MiB
/// ceiling. A7.2: cold config, one per process, size guard waived.
pub const Limits = struct {
    max_mailboxes: u32 = 4096,
    max_per_mailbox: u32 = 128,
    max_total: u32 = 8192,
    /// Undelivered blobs older than this are swept (M3: ephemerality is a
    /// server-side promise, not a client courtesy). 7 days.
    ttl_seconds: i64 = 7 * 24 * 60 * 60,
};

/// The store: a mailbox table + one global FIFO message queue, parallel
/// arrays (A3). Per-mailbox FIFO order = the global order filtered, so
/// deposit is append and the oldest-for-a-mailbox is the first match.
/// Removal is orderedRemove, O(n) at n ≤ max_total — measured against the
/// scale (a few thousand tiny elements) this is nothing (G3); an index-per-
/// mailbox is the recorded upgrade if a profiler ever indicts it.
/// Mailbox rows are never removed (32 bytes each, capped by max_mailboxes;
/// the cap bounds memory and keeps message rows' u32 references stable).
/// A7.2: cold struct, one per process, size guard waived.
pub const Store = struct {
    ids: std.ArrayList([mailbox_id_len]u8) = .empty,
    msg_mailbox: std.ArrayList(u32) = .empty,
    msg_arrival: std.ArrayList(i64) = .empty,
    msg_blob: std.ArrayList(*[bucket_len]u8) = .empty,
};

pub fn deinit(gpa: Allocator, store: *Store) void {
    for (store.msg_blob.items) |blob| gpa.destroy(blob);
    store.msg_blob.deinit(gpa);
    store.msg_arrival.deinit(gpa);
    store.msg_mailbox.deinit(gpa);
    store.ids.deinit(gpa);
}

/// Mailbox row for `id`, or null. Linear scan — max_mailboxes ≤ 4096 rows of
/// 32 bytes is one cache-friendly sweep (G3; same recorded upgrade as above).
fn findMailbox(store: *const Store, id: [mailbox_id_len]u8) ?u32 {
    for (store.ids.items, 0..) |row, i| {
        if (std.mem.eql(u8, &row, &id)) return @intCast(i);
    }
    return null;
}

fn pendingOf(store: *const Store, mbox: u32) u32 {
    var n: u32 = 0;
    for (store.msg_mailbox.items) |m| {
        if (m == mbox) n += 1;
    }
    return n;
}

/// Queue one blob for `id`. Copies the blob (C4 — the store owns its
/// memory); `now` is the caller's clock (B4).
pub fn deposit(
    gpa: Allocator,
    store: *Store,
    limits: Limits,
    id: [mailbox_id_len]u8,
    blob: *const [bucket_len]u8,
    now: i64,
) error{OutOfMemory}!DepositResult {
    if (store.msg_blob.items.len >= limits.max_total) return .store_full;
    const mbox = findMailbox(store, id) orelse blk: {
        if (store.ids.items.len >= limits.max_mailboxes) return .store_full;
        try store.ids.append(gpa, id);
        break :blk @as(u32, @intCast(store.ids.items.len - 1));
    };
    if (pendingOf(store, mbox) >= limits.max_per_mailbox) return .mailbox_full;

    const copy = try gpa.create([bucket_len]u8);
    errdefer gpa.destroy(copy);
    copy.* = blob.*;
    try store.msg_mailbox.append(gpa, mbox);
    errdefer _ = store.msg_mailbox.pop();
    try store.msg_arrival.append(gpa, now);
    errdefer _ = store.msg_arrival.pop();
    try store.msg_blob.append(gpa, copy);
    return .ok;
}

/// How many blobs wait for `id`.
pub fn pendingCount(store: *const Store, id: [mailbox_id_len]u8) u32 {
    const mbox = findMailbox(store, id) orelse return 0;
    return pendingOf(store, mbox);
}

/// The n-th oldest blob queued for `id` (n=0 is next to deliver), or null.
/// Borrowed — the caller copies it out before releasing the store lock.
pub fn nthFor(store: *const Store, id: [mailbox_id_len]u8, n: u32) ?*const [bucket_len]u8 {
    const mbox = findMailbox(store, id) orelse return null;
    var seen: u32 = 0;
    for (store.msg_mailbox.items, 0..) |m, i| {
        if (m != mbox) continue;
        if (seen == n) return store.msg_blob.items[i];
        seen += 1;
    }
    return null;
}

/// Delete the oldest blob queued for `id` — the ack. Delivered means
/// deleted: this is the only path a delivered blob leaves by.
pub fn ackOldest(gpa: Allocator, store: *Store, id: [mailbox_id_len]u8) bool {
    const mbox = findMailbox(store, id) orelse return false;
    for (store.msg_mailbox.items, 0..) |m, i| {
        if (m != mbox) continue;
        removeAt(gpa, store, i);
        return true;
    }
    return false;
}

/// Delete every blob older than the TTL (undelivered means expired — M3).
/// Returns how many were swept. One backward pass so removal never skips.
pub fn sweep(gpa: Allocator, store: *Store, limits: Limits, now: i64) u32 {
    var removed: u32 = 0;
    var i = store.msg_arrival.items.len;
    while (i > 0) {
        i -= 1;
        if (now - store.msg_arrival.items[i] > limits.ttl_seconds) {
            removeAt(gpa, store, i);
            removed += 1;
        }
    }
    return removed;
}

fn removeAt(gpa: Allocator, store: *Store, i: usize) void {
    gpa.destroy(store.msg_blob.items[i]);
    _ = store.msg_blob.orderedRemove(i);
    _ = store.msg_arrival.orderedRemove(i);
    _ = store.msg_mailbox.orderedRemove(i);
}

// ---------------------------------------------------------------------------
// The op codec — parse and build, both directions, fixed sizes, no
// allocation. Parses BORROW the input frame (E1: plain bytes cross).
// ---------------------------------------------------------------------------

pub const ParseError = error{ BadOp, BadLength };

/// One client→server op, borrowed views into the frame payload.
/// A7.2: cold struct, size guard waived — transient parse view, one live at a time.
pub const ClientOp = union(enum) {
    deposit: struct { id: [mailbox_id_len]u8, blob: *const [bucket_len]u8 },
    subscribe: struct { id: [mailbox_id_len]u8 },
    ack: struct { id: [mailbox_id_len]u8 },
    /// "I am `did`, here is my anchor key, and here is that key's signature
    /// over the nonce you just sent me." The DID is BORROWED from the frame
    /// and is a CLAIM until the relay checks it against the directory —
    /// signing proves key custody, the directory proves the key is this
    /// account's (A4 slice 2).
    auth: struct { anchor_pub: [anchor_pub_len]u8, sig: [auth_sig_len]u8, did: []const u8 },
};

pub fn parseClientOp(frame: []const u8) ParseError!ClientOp {
    if (frame.len == 0) return error.BadLength;
    switch (frame[0]) {
        op_deposit => {
            if (frame.len != deposit_frame_len) return error.BadLength;
            return .{ .deposit = .{
                .id = frame[1..][0..mailbox_id_len].*,
                .blob = frame[1 + mailbox_id_len ..][0..bucket_len],
            } };
        },
        op_subscribe => {
            if (frame.len != subscribe_frame_len) return error.BadLength;
            return .{ .subscribe = .{ .id = frame[1..][0..mailbox_id_len].* } };
        },
        op_ack => {
            if (frame.len != ack_frame_len) return error.BadLength;
            return .{ .ack = .{ .id = frame[1..][0..mailbox_id_len].* } };
        },
        op_auth => {
            if (frame.len < auth_frame_head) return error.BadLength;
            const did_len = frame[auth_frame_head - 1];
            // The declared length must be EXACTLY the bytes that follow — no
            // slack, no truncation. A hostile frame gets an error, never a
            // silently shortened DID that then fails to match a real account.
            if (frame.len != auth_frame_head + @as(usize, did_len)) return error.BadLength;
            if (did_len == 0) return error.BadLength;
            return .{ .auth = .{
                .anchor_pub = frame[1..][0..anchor_pub_len].*,
                .sig = frame[1 + anchor_pub_len ..][0..auth_sig_len].*,
                .did = frame[auth_frame_head..],
            } };
        },
        else => return error.BadOp,
    }
}

/// One server→client op (U5's client parses these).
/// A7.2: cold struct, size guard waived — transient parse view, one live at a time.
pub const ServerOp = union(enum) {
    deliver: struct { id: [mailbox_id_len]u8, blob: *const [bucket_len]u8 },
    deposit_ok,
    refused: DepositResult,
    /// This connection's login nonce (A4 slice 2). Sent ONLY to a client that
    /// asked for it on the upgrade — see the flag-day note above.
    challenge: [challenge_len]u8,
    auth_ok,
};

pub fn parseServerOp(frame: []const u8) ParseError!ServerOp {
    if (frame.len == 0) return error.BadLength;
    switch (frame[0]) {
        op_deliver => {
            if (frame.len != deliver_frame_len) return error.BadLength;
            return .{ .deliver = .{
                .id = frame[1..][0..mailbox_id_len].*,
                .blob = frame[1 + mailbox_id_len ..][0..bucket_len],
            } };
        },
        op_deposit_ok => {
            if (frame.len != 1) return error.BadLength;
            return .deposit_ok;
        },
        op_refused => {
            if (frame.len != 2) return error.BadLength;
            return .{ .refused = switch (frame[1]) {
                1 => .mailbox_full,
                2 => .store_full,
                3 => .rate_limited,
                4 => .unauthenticated,
                else => return error.BadOp,
            } };
        },
        op_challenge => {
            if (frame.len != challenge_frame_len) return error.BadLength;
            return .{ .challenge = frame[1..][0..challenge_len].* };
        },
        op_auth_ok => {
            if (frame.len != auth_ok_frame_len) return error.BadLength;
            return .auth_ok;
        },
        else => return error.BadOp,
    }
}

pub fn buildDeposit(out: *[deposit_frame_len]u8, id: [mailbox_id_len]u8, blob: *const [bucket_len]u8) []const u8 {
    out[0] = op_deposit;
    out[1..][0..mailbox_id_len].* = id;
    out[1 + mailbox_id_len ..][0..bucket_len].* = blob.*;
    return out;
}

pub fn buildSubscribe(out: *[subscribe_frame_len]u8, id: [mailbox_id_len]u8) []const u8 {
    out[0] = op_subscribe;
    out[1..][0..mailbox_id_len].* = id;
    return out;
}

pub fn buildAck(out: *[ack_frame_len]u8, id: [mailbox_id_len]u8) []const u8 {
    out[0] = op_ack;
    out[1..][0..mailbox_id_len].* = id;
    return out;
}

pub fn buildDeliver(out: *[deliver_frame_len]u8, id: [mailbox_id_len]u8, blob: *const [bucket_len]u8) []const u8 {
    out[0] = op_deliver;
    out[1..][0..mailbox_id_len].* = id;
    out[1 + mailbox_id_len ..][0..bucket_len].* = blob.*;
    return out;
}

pub fn buildDepositOk(out: *[1]u8) []const u8 {
    out[0] = op_deposit_ok;
    return out;
}

pub fn buildRefused(out: *[2]u8, reason: DepositResult) []const u8 {
    out[0] = op_refused;
    out[1] = @intFromEnum(reason);
    return out;
}

pub fn buildChallenge(out: *[challenge_frame_len]u8, nonce: [challenge_len]u8) []const u8 {
    out[0] = op_challenge;
    out[1..][0..challenge_len].* = nonce;
    return out;
}

pub fn buildAuthOk(out: *[auth_ok_frame_len]u8) []const u8 {
    out[0] = op_auth_ok;
    return out;
}

/// Build the auth answer. `did` longer than the wire cap is an explicit
/// error — the DID is the caller's own, so this is a contract check, not a
/// hostile-input path (those live in `parseClientOp`).
pub fn buildAuth(
    out: *[auth_frame_max]u8,
    anchor_pub: [anchor_pub_len]u8,
    sig: [auth_sig_len]u8,
    did: []const u8,
) error{BadLength}![]const u8 {
    if (did.len == 0 or did.len > max_auth_did_len) return error.BadLength;
    out[0] = op_auth;
    out[1..][0..anchor_pub_len].* = anchor_pub;
    out[1 + anchor_pub_len ..][0..auth_sig_len].* = sig;
    out[auth_frame_head - 1] = @intCast(did.len);
    @memcpy(out[auth_frame_head..][0..did.len], did);
    return out[0 .. auth_frame_head + did.len];
}

/// Constant-time shared-bearer check for the relay's HTTP upgrade gate —
/// a SERVICE gate (is this a Zat4 client?), deliberately not an identity
/// check (the relay authenticates nothing about who). Empty `expected` ⇒
/// FAIL CLOSED (the appview_serve posture, E3).
pub fn tokenMatches(expected: []const u8, header: ?[]const u8) bool {
    if (expected.len == 0) return false;
    const h = header orelse return false;
    const prefix = "Bearer ";
    if (!std.mem.startsWith(u8, h, prefix)) return false;
    const got = h[prefix.len..];
    if (got.len != expected.len) return false;
    var diff: u8 = 0;
    for (got, expected) |a, b| diff |= a ^ b;
    return diff == 0;
}

// ---------------------------------------------------------------------------
// Tests (B2, C6) — the store's whole life cycle and the codec's edges,
// clock passed in throughout.
// ---------------------------------------------------------------------------

const testing = std.testing;

fn testId(fill: u8) [mailbox_id_len]u8 {
    return @splat(fill);
}

fn testBlob(fill: u8) [bucket_len]u8 {
    return @splat(fill);
}

test "relay store: deposit → deliver in FIFO order → ack deletes" {
    const gpa = testing.allocator;
    var store: Store = .{};
    defer deinit(gpa, &store);

    const a = testId(0xAA);
    const b = testId(0xBB);
    const blob1 = testBlob(1);
    const blob2 = testBlob(2);
    const blob3 = testBlob(3);

    try testing.expectEqual(DepositResult.ok, try deposit(gpa, &store, .{}, a, &blob1, 100));
    try testing.expectEqual(DepositResult.ok, try deposit(gpa, &store, .{}, b, &blob2, 101));
    try testing.expectEqual(DepositResult.ok, try deposit(gpa, &store, .{}, a, &blob3, 102));

    // Per-mailbox FIFO: a sees blob1 then blob3; b sees only blob2.
    try testing.expectEqual(@as(u32, 2), pendingCount(&store, a));
    try testing.expectEqual(@as(u32, 1), pendingCount(&store, b));
    try testing.expectEqualSlices(u8, &blob1, nthFor(&store, a, 0).?);
    try testing.expectEqualSlices(u8, &blob3, nthFor(&store, a, 1).?);
    try testing.expectEqualSlices(u8, &blob2, nthFor(&store, b, 0).?);
    try testing.expect(nthFor(&store, a, 2) == null);

    // Ack pops the OLDEST; delivered means deleted.
    try testing.expect(ackOldest(gpa, &store, a));
    try testing.expectEqual(@as(u32, 1), pendingCount(&store, a));
    try testing.expectEqualSlices(u8, &blob3, nthFor(&store, a, 0).?);
    try testing.expect(ackOldest(gpa, &store, a));
    try testing.expect(!ackOldest(gpa, &store, a)); // empty: nothing to ack
    try testing.expectEqual(@as(u32, 1), pendingCount(&store, b)); // untouched
}

test "relay store: an unknown mailbox is empty, not an error" {
    const gpa = testing.allocator;
    var store: Store = .{};
    defer deinit(gpa, &store);
    try testing.expectEqual(@as(u32, 0), pendingCount(&store, testId(9)));
    try testing.expect(nthFor(&store, testId(9), 0) == null);
    try testing.expect(!ackOldest(gpa, &store, testId(9)));
}

test "relay store: TTL sweep expires the old, keeps the young (M3)" {
    const gpa = testing.allocator;
    var store: Store = .{};
    defer deinit(gpa, &store);

    const a = testId(1);
    const limits: Limits = .{ .ttl_seconds = 100 };
    const blob = testBlob(7);
    _ = try deposit(gpa, &store, limits, a, &blob, 1000); // expires past 1100
    _ = try deposit(gpa, &store, limits, a, &blob, 1500);
    _ = try deposit(gpa, &store, limits, a, &blob, 1990);

    try testing.expectEqual(@as(u32, 0), sweep(gpa, &store, limits, 1050)); // nothing old yet
    try testing.expectEqual(@as(u32, 2), sweep(gpa, &store, limits, 2000)); // 1000 + 1500 lapse
    try testing.expectEqual(@as(u32, 1), pendingCount(&store, a));
    try testing.expectEqual(@as(u32, 1), sweep(gpa, &store, limits, 3000));
    try testing.expectEqual(@as(u32, 0), pendingCount(&store, a));
}

test "relay store: the caps refuse, explicitly, and nothing leaks" {
    const gpa = testing.allocator;
    var store: Store = .{};
    defer deinit(gpa, &store);

    const limits: Limits = .{ .max_per_mailbox = 2, .max_total = 3, .max_mailboxes = 2 };
    const blob = testBlob(0);

    // Per-mailbox cap.
    try testing.expectEqual(DepositResult.ok, try deposit(gpa, &store, limits, testId(1), &blob, 0));
    try testing.expectEqual(DepositResult.ok, try deposit(gpa, &store, limits, testId(1), &blob, 0));
    try testing.expectEqual(DepositResult.mailbox_full, try deposit(gpa, &store, limits, testId(1), &blob, 0));

    // Mailbox-table cap: a THIRD distinct mailbox is refused.
    try testing.expectEqual(DepositResult.ok, try deposit(gpa, &store, limits, testId(2), &blob, 0));
    try testing.expectEqual(DepositResult.store_full, try deposit(gpa, &store, limits, testId(3), &blob, 0));

    // Global cap: the store is at 3 blobs now; even room in a mailbox refuses.
    try testing.expectEqual(DepositResult.store_full, try deposit(gpa, &store, limits, testId(2), &blob, 0));
}

test "TokenBucket: bounds a flooder to its rate, never touches a real user" {
    // A steady 5/sec, burst 20.
    var b = TokenBucket.init(20, 5, 100.0);

    // The opening burst — 20 deposits at once — is allowed (a real client's
    // connect + first message must never be throttled).
    var allowed: u32 = 0;
    for (0..20) |_| if (b.take(100.0)) {
        allowed += 1;
    };
    try testing.expectEqual(@as(u32, 20), allowed);

    // The 21st in the same instant is refused — the bucket is empty.
    try testing.expect(!b.take(100.0));

    // A flooder hammering at one instant gets nothing more, no matter how hard.
    for (0..10_000) |_| _ = b.take(100.0);
    try testing.expect(!b.take(100.0));

    // One second later, exactly 5 tokens refilled → 5 allowed, 6th refused.
    var after: u32 = 0;
    for (0..10) |_| if (b.take(101.0)) {
        after += 1;
    };
    try testing.expectEqual(@as(u32, 5), after);

    // A long idle refills only up to capacity (no unbounded credit hoarding —
    // the burst is bounded whether you have been quiet for a second or a week).
    for (0..100) |_| _ = b.take(101.0); // drain
    var burst: u32 = 0;
    for (0..1000) |_| if (b.take(1_000_000.0)) {
        burst += 1;
    };
    try testing.expectEqual(@as(u32, 20), burst); // capacity, not 1000

    // A clock that jumps BACKWARDS grants no free tokens (not a weapon).
    var b2 = TokenBucket.init(1, 1, 500.0);
    try testing.expect(b2.take(500.0)); // spend the one token
    try testing.expect(!b2.take(400.0)); // time went back → still empty
}

test "relay codec: every op round-trips; malformed frames are explicit errors" {
    const id = testId(0x5A);
    const blob = testBlob(0xC3);

    var dep_buf: [deposit_frame_len]u8 = undefined;
    const dep = buildDeposit(&dep_buf, id, &blob);
    switch (try parseClientOp(dep)) {
        .deposit => |d| {
            try testing.expectEqualSlices(u8, &id, &d.id);
            try testing.expectEqualSlices(u8, &blob, d.blob);
        },
        else => return error.TestUnexpectedResult,
    }

    var sub_buf: [subscribe_frame_len]u8 = undefined;
    switch (try parseClientOp(buildSubscribe(&sub_buf, id))) {
        .subscribe => |s| try testing.expectEqualSlices(u8, &id, &s.id),
        else => return error.TestUnexpectedResult,
    }

    var ack_buf: [ack_frame_len]u8 = undefined;
    switch (try parseClientOp(buildAck(&ack_buf, id))) {
        .ack => |s| try testing.expectEqualSlices(u8, &id, &s.id),
        else => return error.TestUnexpectedResult,
    }

    var del_buf: [deliver_frame_len]u8 = undefined;
    switch (try parseServerOp(buildDeliver(&del_buf, id, &blob))) {
        .deliver => |d| {
            try testing.expectEqualSlices(u8, &id, &d.id);
            try testing.expectEqualSlices(u8, &blob, d.blob);
        },
        else => return error.TestUnexpectedResult,
    }

    var ok_buf: [1]u8 = undefined;
    try testing.expectEqual(ServerOp.deposit_ok, try parseServerOp(buildDepositOk(&ok_buf)));

    var ref_buf: [2]u8 = undefined;
    switch (try parseServerOp(buildRefused(&ref_buf, .mailbox_full))) {
        .refused => |r| try testing.expectEqual(DepositResult.mailbox_full, r),
        else => return error.TestUnexpectedResult,
    }
    // The rate-limit reason round-trips too (added after the wire was minted).
    switch (try parseServerOp(buildRefused(&ref_buf, .rate_limited))) {
        .refused => |r| try testing.expectEqual(DepositResult.rate_limited, r),
        else => return error.TestUnexpectedResult,
    }

    // Malformed: empty, unknown op, wrong length, bad refuse reason.
    try testing.expectError(error.BadLength, parseClientOp(""));
    try testing.expectError(error.BadOp, parseClientOp(&.{0x7F}));
    try testing.expectError(error.BadLength, parseClientOp(dep[0 .. dep.len - 1]));
    try testing.expectError(error.BadLength, parseServerOp(del_buf[0 .. del_buf.len - 1]));
    try testing.expectError(error.BadOp, parseServerOp(&.{ op_refused, 9 }));
    // A server op is not a client op and vice versa.
    try testing.expectError(error.BadOp, parseClientOp(del_buf[0..deliver_frame_len]));
    try testing.expectError(error.BadOp, parseServerOp(dep));
}

test "relay codec: the auth handshake round-trips; a hostile auth frame is refused" {
    // Challenge (server → client).
    const nonce: [challenge_len]u8 = @splat(0x9E);
    var ch_buf: [challenge_frame_len]u8 = undefined;
    switch (try parseServerOp(buildChallenge(&ch_buf, nonce))) {
        .challenge => |c| try testing.expectEqualSlices(u8, &nonce, &c),
        else => return error.TestUnexpectedResult,
    }
    var ok_buf: [auth_ok_frame_len]u8 = undefined;
    try testing.expectEqual(ServerOp.auth_ok, try parseServerOp(buildAuthOk(&ok_buf)));

    // The answer (client → server), with its variable-length DID.
    const anchor_pub: [anchor_pub_len]u8 = @splat(0x11);
    const sig: [auth_sig_len]u8 = @splat(0x22);
    const did = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";
    var auth_buf: [auth_frame_max]u8 = undefined;
    const frame = try buildAuth(&auth_buf, anchor_pub, sig, did);
    switch (try parseClientOp(frame)) {
        .auth => |a| {
            try testing.expectEqualSlices(u8, &anchor_pub, &a.anchor_pub);
            try testing.expectEqualSlices(u8, &sig, &a.sig);
            try testing.expectEqualStrings(did, a.did);
        },
        else => return error.TestUnexpectedResult,
    }

    // A declared DID length that DISAGREES with the bytes present is an error,
    // both ways. This is the one variable-length frame in the vocabulary, so it
    // is the one place a length can lie — a frame that claimed 200 bytes and
    // carried 20 must not parse as a 20-byte DID, and one that claimed 20 while
    // carrying 200 must not silently truncate to a DID that isn't what was signed.
    var bad = auth_buf;
    bad[auth_frame_head - 1] = 200;
    try testing.expectError(error.BadLength, parseClientOp(bad[0..frame.len]));
    bad[auth_frame_head - 1] = @intCast(did.len - 1);
    try testing.expectError(error.BadLength, parseClientOp(bad[0..frame.len]));
    // A zero-length DID is nobody.
    bad[auth_frame_head - 1] = 0;
    try testing.expectError(error.BadLength, parseClientOp(bad[0..auth_frame_head]));
    // Truncated below the fixed head at all.
    try testing.expectError(error.BadLength, parseClientOp(frame[0 .. auth_frame_head - 1]));
    // The builder refuses a DID the wire cannot carry (a contract check).
    const huge = [_]u8{'x'} ** (max_auth_did_len + 1);
    try testing.expectError(error.BadLength, buildAuth(&auth_buf, anchor_pub, sig, &huge));
    try testing.expectError(error.BadLength, buildAuth(&auth_buf, anchor_pub, sig, ""));

    // The new refusal reason rides the wire like the others.
    var ref_buf: [2]u8 = undefined;
    switch (try parseServerOp(buildRefused(&ref_buf, .unauthenticated))) {
        .refused => |r| try testing.expectEqual(DepositResult.unauthenticated, r),
        else => return error.TestUnexpectedResult,
    }
}

test "relay: the service gate fails closed and matches exactly" {
    try testing.expect(!tokenMatches("", "Bearer anything"));
    try testing.expect(!tokenMatches("", null));
    try testing.expect(tokenMatches("tok", "Bearer tok"));
    try testing.expect(!tokenMatches("tok", "Bearer nope"));
    try testing.expect(!tokenMatches("tok", "tok"));
    try testing.expect(!tokenMatches("tok", null));
}
