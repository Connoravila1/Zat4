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

//! B1 classification: SHELL (network, entropy, clock, persistence). Zat
//! Chat's E2EE session layer (ZAT_CHAT_ROADMAP milestone M1) — the module
//! where the crypto core, the key directory, and the relay transport
//! CONVERGE into conversations:
//!
//!   start   fetch the peer's keyPackage (directory-validated) →
//!           mls.createGroup + addPeer → the Welcome rides the relay to the
//!           peer's bootstrap mailbox.
//!   send    plaintext = [ChatMsg.kind byte][text] → mls.encrypt →
//!           length-framed into the one fixed bucket size → deposit.
//!           (Payment kinds carry the core's structured frame instead of
//!           text — same path, same bucket; the relay can't tell them
//!           apart. M5 A1.)
//!   receive a bucket routes by MLS message kind: a Welcome joins (and is
//!           believed ONLY after the sender's leaf key is re-verified
//!           against their PUBLISHED keyPackage record — a Welcome may
//!           claim any DID; the directory is the check); a PrivateMessage
//!           routes by group id to its conversation's group.
//!
//! Group state persists across relaunches (cache: keystore preferred, 0600
//! fallback, per account) and is REWRITTEN after every mutating operation —
//! an MLS ratchet advances on every send/receive, and a stale copy on disk
//! would replay-reject the world after a crash. Forward secrecy survives
//! persistence because the wipe points fire before serialization ever runs:
//! spent generations are already gone from what is written.
//!
//! v1 mailbox posture (recorded, honest): ONE standing inbox per account,
//! derived from the anchor public key — the same "bootstrap mailbox"
//! caveat U4 recorded (a relay operator who also scrapes repos could link
//! it to a DID). Per-epoch mailbox rotation out of the MLS secret tree is
//! the recorded follow-up; it needs multi-mailbox subscriptions at the
//! relay. v1 blocking posture (recorded): startConversation and the
//! Welcome-verify fetch run on the caller's thread — first-contact events,
//! rare by nature; a worker is the recorded upgrade if they ever jank.

const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const cache = @import("cache.zig");
const chat_keys = @import("chat_keys.zig");
const chat_relay = @import("chat_relay.zig");
const clock = @import("clock.zig");
const mls = @import("../core/mls.zig");
const anchor = @import("../core/anchor.zig");
const keydir = @import("../core/keydir.zig");
const relay = @import("../core/relay.zig");
const chat = @import("../core/chat.zig");

// ---------------------------------------------------------------------------
// Bucket framing (pure): [u32 LE payload len][payload][zero pad] in exactly
// one relay bucket. The relay sees one size; the length is inside the
// ciphertext-bearing blob, invisible to it.
// ---------------------------------------------------------------------------

pub const max_payload = relay.bucket_len - 4;

pub fn bucketPack(out: *[relay.bucket_len]u8, payload: []const u8) error{TooBig}!void {
    if (payload.len > max_payload) return error.TooBig;
    @memset(out, 0);
    std.mem.writeInt(u32, out[0..4], @intCast(payload.len), .little);
    @memcpy(out[4..][0..payload.len], payload);
}

pub fn bucketUnpack(blob: []const u8) ?[]const u8 {
    if (blob.len != relay.bucket_len) return null;
    const len = std.mem.readInt(u32, blob[0..4], .little);
    if (len > max_payload) return null;
    return blob[4 .. 4 + len];
}

// ---------------------------------------------------------------------------
// The session state
// ---------------------------------------------------------------------------

const groups_magic = [4]u8{ 'Z', 'A', 'T', 'C' };
const groups_version: u16 = 1;

/// One account's E2EE chat state: identity + the open conversations'
/// groups, parallel arrays keyed by peer DID (A3; the DID is the one
/// cross-module identity, A5). A7.2: cold struct, one per session.
pub const State = struct {
    my_did: []u8,
    anchor_seed: [32]u8,
    /// Our last-resort package (privates + published bytes) — what a
    /// peer's Welcome is addressed to.
    kp: cache.ChatKeyPackage,
    /// Our standing inbox (bootstrap mailbox, from the anchor public key).
    inbox: [relay.mailbox_id_len]u8,
    peer_dids: std.ArrayList([]u8) = .empty,
    peer_anchors: std.ArrayList([32]u8) = .empty,
    groups: std.ArrayList(mls.Group) = .empty,
};

pub const InitError = error{ NoAnchor, NoCacheDir, PublishFailed, OutOfMemory };

/// Bring the account's chat crypto up: publish-or-refresh our directory
/// entry (idempotent — also mints the package + anchor on first use),
/// restore persisted conversations. One network round-trip at startup.
pub fn init(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *@import("auth.zig").Session,
) !State {
    _ = chat_keys.ensurePublished(gpa, arena, io, environ, session) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.NoAnchor => return error.NoAnchor,
        error.NoCacheDir => return error.NoCacheDir,
        else => return error.PublishFailed,
    };
    var anchor_load = cache.loadOrCreateAnchorSeed(gpa, io, environ, session.did) orelse return error.NoAnchor;
    errdefer std.crypto.secureZero(u8, &anchor_load.seed);
    var kp_path_buf: [512]u8 = undefined;
    const kp_path = cache.chatKeyPackagePath(&kp_path_buf, environ, session.did) orelse return error.NoCacheDir;
    var kp = cache.loadChatKeyPackageAt(gpa, kp_path, session.did) orelse return error.NoCacheDir;
    errdefer cache.freeChatKeyPackage(gpa, &kp);

    const anchor_pub = anchor.publicKey(anchor_load.seed) catch return error.NoAnchor;
    var st: State = .{
        .my_did = try gpa.dupe(u8, session.did),
        .anchor_seed = anchor_load.seed,
        .kp = kp,
        .inbox = keydir.bootstrapMailbox(anchor_pub),
    };
    errdefer gpa.free(st.my_did);
    restoreGroups(gpa, environ, &st);
    return st;
}

pub fn deinit(gpa: Allocator, st: *State) void {
    std.crypto.secureZero(u8, &st.anchor_seed);
    cache.freeChatKeyPackage(gpa, &st.kp);
    gpa.free(st.my_did);
    for (st.peer_dids.items) |d| gpa.free(d);
    st.peer_dids.deinit(gpa);
    st.peer_anchors.deinit(gpa);
    for (st.groups.items) |*g| g.deinit(gpa);
    st.groups.deinit(gpa);
}

fn conversationIndex(st: *const State, peer_did: []const u8) ?usize {
    for (st.peer_dids.items, 0..) |d, i| {
        if (std.mem.eql(u8, d, peer_did)) return i;
    }
    return null;
}

pub fn hasConversation(st: *const State, peer_did: []const u8) bool {
    return conversationIndex(st, peer_did) != null;
}

/// The pinned anchor key for an open conversation — what the payment
/// record gate validates against (M5 A2/A4: the pin is why a compromised
/// PDS cannot redirect a payment inside an established conversation).
/// Null = no such conversation.
pub fn peerAnchor(st: *const State, peer_did: []const u8) ?[32]u8 {
    const idx = conversationIndex(st, peer_did) orelse return null;
    return st.peer_anchors.items[idx];
}

// ---------------------------------------------------------------------------
// Persistence: every group serialized into one per-account blob, rewritten
// after each mutating operation (ratchets advance on every send/receive).
// ---------------------------------------------------------------------------

fn groupsPath(buf: []u8, environ: ?*const std.process.Environ.Map, did: []const u8) ?[]const u8 {
    return cache.chatGroupsPath(buf, environ, did);
}

pub fn persist(gpa: Allocator, environ: ?*const std.process.Environ.Map, st: *const State) void {
    var blob: std.ArrayList(u8) = .empty;
    defer {
        std.crypto.secureZero(u8, blob.items);
        blob.deinit(gpa);
    }
    blob.appendSlice(gpa, &groups_magic) catch return;
    blob.appendSlice(gpa, std.mem.asBytes(&groups_version)) catch return;
    var count4: [4]u8 = undefined;
    std.mem.writeInt(u32, &count4, @intCast(st.groups.items.len), .little);
    blob.appendSlice(gpa, &count4) catch return;
    for (st.peer_dids.items, st.peer_anchors.items, st.groups.items) |did, apub, *g| {
        var len4: [4]u8 = undefined;
        std.mem.writeInt(u32, &len4, @intCast(did.len), .little);
        blob.appendSlice(gpa, &len4) catch return;
        blob.appendSlice(gpa, did) catch return;
        blob.appendSlice(gpa, &apub) catch return;
        const gb = mls.serializeGroup(gpa, g) catch return;
        defer {
            std.crypto.secureZero(u8, gb);
            gpa.free(gb);
        }
        std.mem.writeInt(u32, &len4, @intCast(gb.len), .little);
        blob.appendSlice(gpa, &len4) catch return;
        blob.appendSlice(gpa, gb) catch return;
    }
    var path_buf: [512]u8 = undefined;
    const path = groupsPath(&path_buf, environ, st.my_did) orelse return;
    _ = cache.saveChatGroupsAt(gpa, path, st.my_did, blob.items);
}

fn restoreGroups(gpa: Allocator, environ: ?*const std.process.Environ.Map, st: *State) void {
    var path_buf: [512]u8 = undefined;
    const path = groupsPath(&path_buf, environ, st.my_did) orelse return;
    const blob = cache.loadChatGroupsAt(gpa, path, st.my_did) orelse return;
    defer {
        std.crypto.secureZero(u8, blob);
        gpa.free(blob);
    }
    if (blob.len < 10 or !std.mem.eql(u8, blob[0..4], &groups_magic)) return;
    if (std.mem.bytesToValue(u16, blob[4..6]) != groups_version) return;
    const count = std.mem.readInt(u32, blob[6..10], .little);
    var at: usize = 10;
    var i: u32 = 0;
    while (i < count) : (i += 1) {
        if (blob.len - at < 4) return;
        const dlen = std.mem.readInt(u32, blob[at..][0..4], .little);
        at += 4;
        if (blob.len - at < dlen + 32 + 4) return;
        const did = blob[at .. at + dlen];
        at += dlen;
        const apub: [32]u8 = blob[at..][0..32].*;
        at += 32;
        const glen = std.mem.readInt(u32, blob[at..][0..4], .little);
        at += 4;
        if (blob.len - at < glen) return;
        const group = mls.deserializeGroup(gpa, blob[at .. at + glen]) catch return;
        at += glen;

        const did_copy = gpa.dupe(u8, did) catch {
            var g = group;
            g.deinit(gpa);
            return;
        };
        appendConversation(gpa, st, did_copy, apub, group) catch {
            var g = group;
            g.deinit(gpa);
            gpa.free(did_copy);
            return;
        };
    }
}

fn appendConversation(gpa: Allocator, st: *State, did_owned: []u8, apub: [32]u8, group: mls.Group) error{OutOfMemory}!void {
    try st.peer_dids.ensureUnusedCapacity(gpa, 1);
    try st.peer_anchors.ensureUnusedCapacity(gpa, 1);
    try st.groups.ensureUnusedCapacity(gpa, 1);
    st.peer_dids.appendAssumeCapacity(did_owned);
    st.peer_anchors.appendAssumeCapacity(apub);
    st.groups.appendAssumeCapacity(group);
}

// ---------------------------------------------------------------------------
// The three verbs
// ---------------------------------------------------------------------------

pub const StartError = error{ NoKeyPackage, AlreadyOpen, CryptoFailed, RelayDown, OutOfMemory };

/// First contact: fetch + validate the peer's directory entry, build the
/// two-member group, send the Welcome to THEIR bootstrap mailbox.
pub fn startConversation(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    st: *State,
    link: *chat_relay.ChatRelay,
    peer_did: []const u8,
) StartError!void {
    if (conversationIndex(st, peer_did) != null) return error.AlreadyOpen;
    const peer = (chat_keys.fetchPeer(gpa, arena, io, environ, peer_did) catch return error.NoKeyPackage) orelse
        return error.NoKeyPackage;

    var ce: mls.CreateEntropy = undefined;
    var ae: mls.AddEntropy = undefined;
    io.randomSecure(std.mem.asBytes(&ce)) catch return error.CryptoFailed;
    io.randomSecure(std.mem.asBytes(&ae)) catch return error.CryptoFailed;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&ce));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&ae));

    var group = mls.createGroup(gpa, st.my_did, st.anchor_seed, ce) catch return error.CryptoFailed;
    errdefer group.deinit(gpa);
    const welcome = mls.addPeer(gpa, &group, peer.kp_bytes, @intCast(@max(0, clock.unixSeconds())), ae) catch
        return error.CryptoFailed;
    defer gpa.free(welcome);

    var bucket: [relay.bucket_len]u8 = undefined;
    bucketPack(&bucket, welcome) catch return error.CryptoFailed;
    chat_relay.deposit(link, keydir.bootstrapMailbox(peer.anchor_pub), &bucket) catch return error.RelayDown;

    const did_copy = try gpa.dupe(u8, peer_did);
    errdefer gpa.free(did_copy);
    try appendConversation(gpa, st, did_copy, peer.anchor_pub, group);
    persist(gpa, environ, st);
}

pub const SendError = error{ NoConversation, TooLong, CryptoFailed, RelayDown, OutOfMemory };

/// The shared deposit leg of every send: encrypt one plaintext, persist,
/// bucket, deposit. ORDER IS LOAD-BEARING: the advanced ratchet reaches
/// disk BEFORE the ciphertext leaves. A crash after deposit but before
/// persist would restore yesterday's ratchet and re-issue this generation's
/// key and nonce for a DIFFERENT plaintext — AEAD nonce reuse, the one
/// catastrophic failure. Persist-first means a crash costs one lost
/// message, never a reused key.
fn depositPlain(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    st: *State,
    link: *chat_relay.ChatRelay,
    idx: usize,
    plaintext: []const u8,
) SendError!void {
    var guard: [4]u8 = undefined;
    io.randomSecure(&guard) catch return error.CryptoFailed;
    const msg = mls.encrypt(gpa, &st.groups.items[idx], plaintext, 0, guard) catch return error.CryptoFailed;
    defer gpa.free(msg);
    persist(gpa, environ, st);
    var bucket: [relay.bucket_len]u8 = undefined;
    bucketPack(&bucket, msg) catch return error.CryptoFailed;
    chat_relay.deposit(link, keydir.bootstrapMailbox(st.peer_anchors.items[idx]), &bucket) catch return error.RelayDown;
}

/// Encrypt one message ([kind][text]) into the peer's mailbox. Payment
/// kinds carry a structured frame and go through `sendPayment`.
pub fn send(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    st: *State,
    link: *chat_relay.ChatRelay,
    peer_did: []const u8,
    kind: chat.Kind,
    text: []const u8,
) SendError!void {
    assert(!chat.isPaymentKind(kind));
    const idx = conversationIndex(st, peer_did) orelse return error.NoConversation;
    if (text.len + 1 > max_payload) return error.TooLong; // ciphertext ≥ plaintext; cheap early cut
    var plaintext_buf: [1024]u8 = undefined;
    if (text.len + 1 > plaintext_buf.len) return error.TooLong;
    plaintext_buf[0] = @intFromEnum(kind);
    @memcpy(plaintext_buf[1..][0..text.len], text);
    const plaintext = plaintext_buf[0 .. 1 + text.len];
    defer std.crypto.secureZero(u8, plaintext);
    return depositPlain(gpa, io, environ, st, link, idx, plaintext);
}

/// One typing-indicator ping (U6a): [kind_typing_wire] alone, through the
/// full E2EE path — encrypt, persist-before-deposit (the same nonce rule as
/// a message; a ping advances the ratchet exactly like one), one fixed
/// bucket. The relay cannot tell it from a message; only the peer can. The
/// persist makes each ping cost a keystore write — throttled by the caller
/// (one ping per few seconds of typing), recorded as acceptable.
pub fn sendTyping(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    st: *State,
    link: *chat_relay.ChatRelay,
    peer_did: []const u8,
) SendError!void {
    const idx = conversationIndex(st, peer_did) orelse return error.NoConversation;
    const ping = [1]u8{chat.kind_typing_wire};
    return depositPlain(gpa, io, environ, st, link, idx, &ping);
}

/// Encrypt one payment CARD ([kind 16/17][frame]) into the peer's mailbox
/// (M5 A1). The frame is built by the pure core; this leg only frames,
/// encrypts and deposits — the same nonce rule as any send. The relay sees
/// one more fixed-size opaque bucket: a payment is indistinguishable from
/// a text message on the wire.
pub fn sendPayment(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    st: *State,
    link: *chat_relay.ChatRelay,
    peer_did: []const u8,
    kind: chat.Kind,
    frame: chat.PaymentFrame,
) SendError!void {
    assert(chat.isPaymentKind(kind));
    return sendPaymentBytes(gpa, io, environ, st, link, peer_did, @intFromEnum(kind), frame);
}

/// A settlement event (wire byte 18/19): the same frame, never a stored
/// kind — the receiver correlates by payment_id and flips its card.
pub fn sendPaymentEvent(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    st: *State,
    link: *chat_relay.ChatRelay,
    peer_did: []const u8,
    settled: bool,
    frame: chat.PaymentFrame,
) SendError!void {
    const byte: u8 = if (settled) chat.kind_pay_settled_wire else chat.kind_pay_failed_wire;
    return sendPaymentBytes(gpa, io, environ, st, link, peer_did, byte, frame);
}

fn sendPaymentBytes(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    st: *State,
    link: *chat_relay.ChatRelay,
    peer_did: []const u8,
    kind_byte: u8,
    frame: chat.PaymentFrame,
) SendError!void {
    const idx = conversationIndex(st, peer_did) orelse return error.NoConversation;
    var plaintext_buf: [1024]u8 = undefined;
    const need = 1 + chat.payment_frame_min + frame.note.len;
    if (need > plaintext_buf.len or need > max_payload) return error.TooLong;
    plaintext_buf[0] = kind_byte;
    const body = chat.buildPaymentFrame(plaintext_buf[1..], frame);
    const plaintext = plaintext_buf[0 .. 1 + body.len];
    defer std.crypto.secureZero(u8, plaintext); // amounts are content too
    return depositPlain(gpa, io, environ, st, link, idx, plaintext);
}

/// What one inbox bucket became. `peer_did`/`text` are gpa-owned by the
/// event; release with `freeIncoming`. A7.2: cold union, transient.
pub const Incoming = union(enum) {
    message: struct { peer_did: []u8, kind: chat.Kind, text: []u8 },
    started: struct { peer_did: []u8 },
    /// The peer is typing right now — ephemeral; the shell shows the
    /// indicator for a few seconds and lets it lapse. Never stored.
    typing: struct { peer_did: []u8 },
    /// A payment CARD (kind 16/17), frame already parsed by the pure core.
    /// The store creates the card — or, when the id names one this
    /// conversation already has, advances it (one card per payment,
    /// morphing in place; M5 A1).
    payment: struct {
        peer_did: []u8,
        note: []u8,
        id: u64,
        amount_sat: u64,
        /// txid / payment hash; all-zero = none carried.
        ref: [32]u8,
        kind: chat.Kind,
        rail: chat.Rail,
    },
    /// A settlement event (wire byte 18/19): flips an existing card to
    /// settled/failed. Never stored as a message.
    payment_update: struct {
        peer_did: []u8,
        id: u64,
        ref: [32]u8,
        settled: bool,
    },
};

pub fn freeIncoming(gpa: Allocator, inc: Incoming) void {
    switch (inc) {
        .message => |m| {
            gpa.free(m.peer_did);
            gpa.free(m.text);
        },
        .started => |s| gpa.free(s.peer_did),
        .typing => |t| gpa.free(t.peer_did),
        .payment => |p| {
            gpa.free(p.peer_did);
            gpa.free(p.note);
        },
        .payment_update => |u| gpa.free(u.peer_did),
    }
}

/// A joined-but-not-yet-believed Welcome: the group exists in memory only
/// until `acceptWelcome` verifies the sender against the directory.
/// A7.2: cold struct, size guard waived — transient, one per first contact.
pub const PendingWelcome = struct {
    group: mls.Group,
    /// The DID the Welcome CLAIMS (gpa-owned) — unverified until accept.
    peer_did: []u8,
};

/// Phase 1 (no network): try to join a Welcome with our stored package.
/// Null = not addressed to us / damaged / a duplicate conversation — the
/// bucket is quietly dropped (E4).
pub fn openWelcome(gpa: Allocator, st: *State, payload: []const u8) ?PendingWelcome {
    var group = mls.join(gpa, payload, st.kp.kp_bytes, .{
        .init_priv = st.kp.init_priv,
        .enc_priv = st.kp.enc_priv,
        .sig_seed = st.anchor_seed,
    }) catch return null;
    const peer_did_view = mls.peerIdentity(&group);
    if (peer_did_view.len == 0 or conversationIndex(st, peer_did_view) != null) {
        group.deinit(gpa);
        return null;
    }
    const did_copy = gpa.dupe(u8, peer_did_view) catch {
        group.deinit(gpa);
        return null;
    };
    return .{ .group = group, .peer_did = did_copy };
}

/// Phase 2: believe the Welcome ONLY if the claimed DID's published record
/// pins the same anchor key that signed the Welcome's leaf — a Welcome can
/// claim any DID; the directory is the check. Consumes `pw` either way.
pub fn acceptWelcome(
    gpa: Allocator,
    environ: ?*const std.process.Environ.Map,
    st: *State,
    pw: PendingWelcome,
    directory_anchor_pub: ?[32]u8,
) error{OutOfMemory}!?Incoming {
    var group = pw.group;
    const expected = directory_anchor_pub orelse {
        group.deinit(gpa);
        gpa.free(pw.peer_did);
        return null; // no published record for the claimed DID: refuse
    };
    const their_leaf = 1 - group.my_leaf;
    if (!std.mem.eql(u8, &expected, &group.leaf_sig_pub[their_leaf])) {
        group.deinit(gpa);
        gpa.free(pw.peer_did);
        return null; // an impostor's Welcome (M4 surfaces these refusals)
    }
    appendConversation(gpa, st, pw.peer_did, expected, group) catch {
        group.deinit(gpa);
        gpa.free(pw.peer_did);
        return error.OutOfMemory;
    };
    persist(gpa, environ, st);
    return .{ .started = .{ .peer_did = try gpa.dupe(u8, pw.peer_did) } };
}

/// Route one delivered bucket. Null = nothing user-visible (damage from a
/// stranger, an epoch advance, an unverifiable Welcome) — the connection
/// and every conversation stay intact (E2/E4). The Welcome branch performs
/// the one network fetch (directory verification) on this thread —
/// first-contact events, rare by nature (the module header's recorded v1
/// posture).
pub fn onBucket(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    st: *State,
    blob: []const u8,
) error{OutOfMemory}!?Incoming {
    const payload = bucketUnpack(blob) orelse return null;
    switch (mls.messageKind(payload)) {
        .welcome => {
            const pw = openWelcome(gpa, st, payload) orelse return null;
            const fetched = chat_keys.fetchPeer(gpa, arena, io, environ, pw.peer_did) catch null;
            return acceptWelcome(gpa, environ, st, pw, if (fetched) |p| p.anchor_pub else null);
        },
        .private_message => {
            const gid = mls.privateMessageGroupId(payload) catch return null;
            const idx = for (st.groups.items, 0..) |*g, i| {
                if (std.mem.eql(u8, g.group_id, gid)) break i;
            } else return null; // no such conversation here
            const received = mls.receive(gpa, &st.groups.items[idx], payload) catch {
                // A failed open burned that generation by design; state is
                // intact. Persist the burn so a crash cannot un-burn it.
                persist(gpa, environ, st);
                return null;
            };
            persist(gpa, environ, st);
            switch (received) {
                .epoch_advanced => return null,
                .application => |data| {
                    defer gpa.free(data);
                    if (data.len < 1) return null;
                    // The typing ping is consumed HERE — an ephemeral event,
                    // never a stored message (chat.kind_typing_wire).
                    if (data[0] == chat.kind_typing_wire) {
                        return .{ .typing = .{ .peer_did = try gpa.dupe(u8, st.peer_dids.items[idx]) } };
                    }
                    // Settlement events (18/19): wire-only, like the ping —
                    // but their effect persists (the card flips). A damaged
                    // frame is dropped, never a crash (E3/E4).
                    if (data[0] == chat.kind_pay_settled_wire or data[0] == chat.kind_pay_failed_wire) {
                        const f = chat.parsePaymentFrame(data[1..]) catch return null;
                        return .{ .payment_update = .{
                            .peer_did = try gpa.dupe(u8, st.peer_dids.items[idx]),
                            .id = f.payment_id,
                            .ref = f.ref,
                            .settled = data[0] == chat.kind_pay_settled_wire,
                        } };
                    }
                    const kind = chat.parseKind(data[0]) catch return null; // reserved kinds refused until their milestone
                    if (chat.isPaymentKind(kind)) {
                        const f = chat.parsePaymentFrame(data[1..]) catch return null;
                        const note = try gpa.dupe(u8, f.note);
                        errdefer gpa.free(note);
                        return .{ .payment = .{
                            .peer_did = try gpa.dupe(u8, st.peer_dids.items[idx]),
                            .note = note,
                            .id = f.payment_id,
                            .amount_sat = f.amount_sat,
                            .ref = f.ref,
                            .kind = kind,
                            .rail = f.rail,
                        } };
                    }
                    const text = try gpa.dupe(u8, data[1..]);
                    errdefer gpa.free(text);
                    return .{ .message = .{
                        .peer_did = try gpa.dupe(u8, st.peer_dids.items[idx]),
                        .kind = kind,
                        .text = text,
                    } };
                },
            }
        },
        .other => return null,
    }
}

// ---------------------------------------------------------------------------
// Tests (C6) — bucket framing, and the FULL two-account E2EE exchange with
// a relaunch in the middle, no network (the directory fetch is the one
// network leg, already live-proven; here the peers hand buckets directly).
// ---------------------------------------------------------------------------

const testing = std.testing;

test "chat_e2ee: bucket framing round-trips and rejects damage" {
    var bucket: [relay.bucket_len]u8 = undefined;
    try bucketPack(&bucket, "ciphertext-ish bytes");
    try testing.expectEqualStrings("ciphertext-ish bytes", bucketUnpack(&bucket).?);
    try testing.expect(bucketUnpack(bucket[0 .. relay.bucket_len - 1]) == null);
    var too_big: [relay.bucket_len]u8 = undefined;
    const huge = [_]u8{'x'} ** (max_payload + 1);
    try testing.expectError(error.TooBig, bucketPack(&too_big, &huge));
    // A zero-length payload is legal and distinct from damage.
    try bucketPack(&bucket, "");
    try testing.expectEqual(@as(usize, 0), bucketUnpack(&bucket).?.len);
}

fn testState(gpa: Allocator, did: []const u8, seed: [32]u8, kp_init: u8, kp_enc: u8) !State {
    const bundle = try mls.generateKeyPackage(gpa, did, seed, 0, std.math.maxInt(u64), .{
        .init_seed = @splat(kp_init),
        .enc_seed = @splat(kp_enc),
    });
    // Ownership of bundle.bytes moves into the state's kp.
    return .{
        .my_did = try gpa.dupe(u8, did),
        .anchor_seed = seed,
        .kp = .{ .init_priv = bundle.init_priv, .enc_priv = bundle.enc_priv, .kp_bytes = bundle.bytes },
        .inbox = keydir.bootstrapMailbox(try anchor.publicKey(seed)),
    };
}

test "chat_e2ee: the full E2EE exchange, with a relaunch and an impostor refused" {
    const gpa = testing.allocator;
    const io = std.testing.io;
    const seed_a: [32]u8 = @splat(0xA7);
    const seed_b: [32]u8 = @splat(0xB8);

    // A per-test cache dir so persist/restore runs for real.
    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    var tmp_buf: [64]u8 = undefined;
    const tmp = std.fmt.bufPrint(&tmp_buf, "/tmp/zat-e2ee-test-{d}", .{std.os.linux.getpid()}) catch unreachable;
    try env.put("ZAT_CACHE_DIR", tmp);
    defer {
        var pb: [512]u8 = undefined;
        if (cache.chatGroupsPath(&pb, &env, "did:plc:e2ee-bob")) |p| {
            var z: [512]u8 = undefined;
            if (std.fmt.bufPrintZ(&z, "{s}", .{p})) |zp| _ = std.os.linux.unlink(zp) else |_| {}
        }
        var z2: [512]u8 = undefined;
        if (std.fmt.bufPrintZ(&z2, "{s}", .{tmp})) |zp| _ = std.os.linux.rmdir(zp) else |_| {}
    }

    var a = try testState(gpa, "did:plc:e2ee-alice", seed_a, 0x01, 0x02);
    defer deinit(gpa, &a);
    var b = try testState(gpa, "did:plc:e2ee-bob", seed_b, 0x03, 0x04);
    defer deinit(gpa, &b);

    // A starts the conversation (the crypto leg of startConversation, sans
    // network/relay: build the group from B's package, hand over the
    // Welcome bucket directly).
    var group_a = try mls.createGroup(gpa, a.my_did, a.anchor_seed, .{
        .group_id = @splat(0x10),
        .enc_seed = @splat(0x11),
        .epoch_secret = @splat(0x12),
    });
    const welcome = try mls.addPeer(gpa, &group_a, b.kp.kp_bytes, 1000, .{
        .enc_seed = @splat(0x13),
        .path_secret = @splat(0x14),
        .welcome_seed = @splat(0x15),
    });
    defer gpa.free(welcome);
    const b_anchor_pub = try anchor.publicKey(seed_b);
    try appendConversation(gpa, &a, try gpa.dupe(u8, b.my_did), b_anchor_pub, group_a);

    var welcome_bucket: [relay.bucket_len]u8 = undefined;
    try bucketPack(&welcome_bucket, welcome);

    // An impostor first: same Welcome, but the directory pins a DIFFERENT
    // anchor key for the claimed DID → refused, no conversation.
    {
        const pw = openWelcome(gpa, &b, bucketUnpack(&welcome_bucket).?) orelse return error.TestUnexpectedResult;
        var wrong = try anchor.publicKey(seed_b);
        wrong[0] ^= 1;
        try testing.expect((try acceptWelcome(gpa, &env, &b, pw, wrong)) == null);
        try testing.expect(!hasConversation(&b, a.my_did));
    }
    // And a claimed DID with NO published record → refused.
    {
        const pw = openWelcome(gpa, &b, bucketUnpack(&welcome_bucket).?) orelse return error.TestUnexpectedResult;
        try testing.expect((try acceptWelcome(gpa, &env, &b, pw, null)) == null);
    }

    // The genuine accept: the directory pins A's real anchor key.
    {
        const pw = openWelcome(gpa, &b, bucketUnpack(&welcome_bucket).?) orelse return error.TestUnexpectedResult;
        const inc = (try acceptWelcome(gpa, &env, &b, pw, try anchor.publicKey(seed_a))) orelse return error.TestUnexpectedResult;
        defer freeIncoming(gpa, inc);
        try testing.expectEqualStrings(a.my_did, inc.started.peer_did);
    }
    try testing.expect(hasConversation(&b, a.my_did));

    // A → B: encrypt with the kind byte, bucket it, route it through
    // onBucket's private-message path (no network there).
    {
        var plaintext: [16]u8 = undefined;
        plaintext[0] = 0; // Kind.text
        @memcpy(plaintext[1..][0..10], "hello, bob");
        const msg = try mls.encrypt(gpa, &a.groups.items[0], plaintext[0..11], 0, .{ 1, 2, 3, 4 });
        defer gpa.free(msg);
        var bucket: [relay.bucket_len]u8 = undefined;
        try bucketPack(&bucket, msg);
        const inc = (try onBucket(gpa, gpa, io, &env, &b, &bucket)) orelse return error.TestUnexpectedResult;
        defer freeIncoming(gpa, inc);
        try testing.expectEqual(chat.Kind.text, inc.message.kind);
        try testing.expectEqualStrings("hello, bob", inc.message.text);
        try testing.expectEqualStrings(a.my_did, inc.message.peer_did);
    }

    // B "relaunches": a fresh State restores the persisted group and the
    // conversation KEEPS WORKING in both directions.
    var b2 = try testState(gpa, "did:plc:e2ee-bob", seed_b, 0x03, 0x04);
    defer deinit(gpa, &b2);
    restoreGroups(gpa, &env, &b2);
    try testing.expect(hasConversation(&b2, a.my_did));

    {
        var plaintext: [24]u8 = undefined;
        plaintext[0] = 0;
        @memcpy(plaintext[1..][0..15], "after a restart");
        const msg = try mls.encrypt(gpa, &a.groups.items[0], plaintext[0..16], 0, .{ 5, 6, 7, 8 });
        defer gpa.free(msg);
        var bucket: [relay.bucket_len]u8 = undefined;
        try bucketPack(&bucket, msg);
        const inc = (try onBucket(gpa, gpa, io, &env, &b2, &bucket)) orelse return error.TestUnexpectedResult;
        defer freeIncoming(gpa, inc);
        try testing.expectEqualStrings("after a restart", inc.message.text);
    }
    {
        // And B2 speaks back to A.
        var plaintext: [16]u8 = undefined;
        plaintext[0] = 0;
        @memcpy(plaintext[1..][0..8], "hi alice");
        const msg = try mls.encrypt(gpa, &b2.groups.items[0], plaintext[0..9], 0, .{ 9, 9, 9, 9 });
        defer gpa.free(msg);
        var bucket: [relay.bucket_len]u8 = undefined;
        try bucketPack(&bucket, msg);
        const inc = (try onBucket(gpa, gpa, io, &env, &a, &bucket)) orelse return error.TestUnexpectedResult;
        defer freeIncoming(gpa, inc);
        try testing.expectEqualStrings("hi alice", inc.message.text);
    }

    // A typing ping crosses as an ephemeral event (never a message), and
    // the ratchet keeps working after it.
    {
        var ping: [16]u8 = undefined;
        ping[0] = chat.kind_typing_wire;
        const msg = try mls.encrypt(gpa, &a.groups.items[0], ping[0..1], 0, .{ 7, 7, 7, 7 });
        defer gpa.free(msg);
        var bucket: [relay.bucket_len]u8 = undefined;
        try bucketPack(&bucket, msg);
        const inc = (try onBucket(gpa, gpa, io, &env, &b2, &bucket)) orelse return error.TestUnexpectedResult;
        defer freeIncoming(gpa, inc);
        try testing.expectEqualStrings(a.my_did, inc.typing.peer_did);

        var plaintext: [16]u8 = undefined;
        plaintext[0] = 0;
        @memcpy(plaintext[1..][0..10], "after ping");
        const msg2 = try mls.encrypt(gpa, &a.groups.items[0], plaintext[0..11], 0, .{ 8, 8, 8, 8 });
        defer gpa.free(msg2);
        var bucket2: [relay.bucket_len]u8 = undefined;
        try bucketPack(&bucket2, msg2);
        const inc2 = (try onBucket(gpa, gpa, io, &env, &b2, &bucket2)) orelse return error.TestUnexpectedResult;
        defer freeIncoming(gpa, inc2);
        try testing.expectEqualStrings("after ping", inc2.message.text);
    }

    // A payment request crosses as a parsed card (M5 A1): kind 16 + frame.
    {
        var fbuf: [128]u8 = undefined;
        const body = chat.buildPaymentFrame(&fbuf, .{
            .payment_id = 0xCAFE,
            .amount_sat = 5000,
            .note = "dinner split",
            .ref = chat.zero_ref,
            .rail = .lightning,
        });
        var plaintext: [160]u8 = undefined;
        plaintext[0] = @intFromEnum(chat.Kind.payment_request);
        @memcpy(plaintext[1..][0..body.len], body);
        const msg = try mls.encrypt(gpa, &a.groups.items[0], plaintext[0 .. 1 + body.len], 0, .{ 2, 2, 2, 2 });
        defer gpa.free(msg);
        var bucket: [relay.bucket_len]u8 = undefined;
        try bucketPack(&bucket, msg);
        const inc = (try onBucket(gpa, gpa, io, &env, &b2, &bucket)) orelse return error.TestUnexpectedResult;
        defer freeIncoming(gpa, inc);
        try testing.expectEqual(chat.Kind.payment_request, inc.payment.kind);
        try testing.expectEqual(@as(u64, 0xCAFE), inc.payment.id);
        try testing.expectEqual(@as(u64, 5000), inc.payment.amount_sat);
        try testing.expectEqual(chat.Rail.lightning, inc.payment.rail);
        try testing.expectEqualStrings("dinner split", inc.payment.note);
        try testing.expect(std.mem.allEqual(u8, &inc.payment.ref, 0));
    }

    // Its settlement event (wire byte 18) crosses as a card flip carrying
    // the proof ref, and is never a stored kind.
    {
        var fbuf: [128]u8 = undefined;
        const preimage: [32]u8 = @splat(0x77);
        const body = chat.buildPaymentFrame(&fbuf, .{
            .payment_id = 0xCAFE,
            .amount_sat = 5000,
            .note = "",
            .ref = preimage,
            .rail = .lightning,
        });
        var plaintext: [160]u8 = undefined;
        plaintext[0] = chat.kind_pay_settled_wire;
        @memcpy(plaintext[1..][0..body.len], body);
        const msg = try mls.encrypt(gpa, &a.groups.items[0], plaintext[0 .. 1 + body.len], 0, .{ 3, 3, 3, 3 });
        defer gpa.free(msg);
        var bucket: [relay.bucket_len]u8 = undefined;
        try bucketPack(&bucket, msg);
        const inc = (try onBucket(gpa, gpa, io, &env, &b2, &bucket)) orelse return error.TestUnexpectedResult;
        defer freeIncoming(gpa, inc);
        try testing.expect(inc.payment_update.settled);
        try testing.expectEqual(@as(u64, 0xCAFE), inc.payment_update.id);
        try testing.expectEqualSlices(u8, &preimage, &inc.payment_update.ref);
    }

    // A damaged payment frame (short) is dropped, and the ratchet survives.
    {
        var plaintext: [8]u8 = undefined;
        plaintext[0] = @intFromEnum(chat.Kind.payment_sent);
        @memset(plaintext[1..], 0);
        const msg = try mls.encrypt(gpa, &a.groups.items[0], &plaintext, 0, .{ 4, 4, 4, 4 });
        defer gpa.free(msg);
        var bucket: [relay.bucket_len]u8 = undefined;
        try bucketPack(&bucket, msg);
        try testing.expect((try onBucket(gpa, gpa, io, &env, &b2, &bucket)) == null);
    }

    // A stranger's random bucket is dropped without a mark.
    var junk: [relay.bucket_len]u8 = @splat(0x5A);
    try testing.expect((try onBucket(gpa, gpa, io, &env, &a, &junk)) == null);
}
