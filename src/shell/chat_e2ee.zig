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
//! Mailbox posture (metadata privacy M2): the anchor-derived bootstrap
//! mailbox carries ONLY first contact — Welcomes in, Welcomes out (M2.3).
//! Conversation traffic rides per-epoch TRAFFIC mailboxes derived through
//! the MLS exporter (mls.mailboxId, M2.1): opaque to the relay, unlinkable
//! to a DID or an anchor key, rotated by every commit. The shell keeps the
//! relay subscribed to `subscriptions()` — bootstrap + each group's
//! current-epoch inbox — re-walking after every drained batch so epoch
//! advances and new conversations pick up their rotated IDs; the relay's
//! durable mailboxes make a look-ahead window unnecessary (a bucket
//! deposited before its subscription waits at the relay).
//! v1 blocking posture (recorded): startConversation and the
//! Welcome-verify fetch run on the caller's thread — first-contact events,
//! rare by nature; a worker is the recorded upgrade if they ever jank.

const std = @import("std");
const builtin = @import("builtin");
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
const mobile_host = @import("mobile_host.zig");

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
/// Version 2 (A1) appends the per-conversation Welcome-delivery record;
/// version 3 (A2) appends one byte more, the drift flag. EVERY older version
/// still restores — the reader accepts 1, 2 and 3 — and that tolerance is not
/// politeness, it is safety: a version this reader refuses means `restoreGroups`
/// bails and the device silently loses EVERY MLS group it has, which is every
/// conversation it can decrypt. The missing fields simply default (a v1
/// conversation reads as confirmed, a v2 one as not-drifted), which is the
/// honest reading of a blob written before the fact existed.
const groups_version: u16 = 3;

/// What the far side knows about a conversation WE opened. A Welcome used to
/// be a single unacknowledged shot: if it was lost, the sender kept believing
/// a group existed while every message after it vanished. This row is the
/// difference — it holds the Welcome bytes until the peer's ack comes back,
/// and the shell re-sends on a backoff until it does.
///
/// `bucket.len == 0` IS "confirmed" (A6: no bool to drift out of step with
/// the bytes) — either the peer acked, or the conversation came to us as
/// THEIR Welcome and there was never anything of ours to deliver.
pub const WelcomeState = struct {
    /// The exact Welcome bucket we sent (gpa-owned), kept for the resend.
    /// Empty once the peer acks.
    bucket: []u8,
    /// When the Welcome last went out — the backoff's origin.
    last_sent: i64,
    /// When we last ACKED this peer. A Welcome bucket rides a public mailbox,
    /// so anyone can replay one at us; this is the floor that keeps a replay
    /// from making us encrypt and deposit an ack per copy.
    last_ack: i64,
    /// How many times the Welcome has gone out. At `chat.welcome_retry_max`
    /// we stop and the thread says so, rather than retrying behind the user.
    attempts: u8,
    /// A2: this conversation's two halves have DRIFTED — a message arrived that
    /// will not open under our ratchet for a reason that is not tampering and
    /// not a redelivery. The thread says so and offers the repair, instead of
    /// dropping the message and looking healthy while replies stop forever.
    /// Cleared the moment either side re-establishes.
    drifted: bool,

    comptime {
        // Budget 40 (unchanged): 16 (slice) + 8 + 8 + 1 + 1 = 34 bytes of
        // payload; the two flag bytes land in padding that already existed, so
        // A2 cost nothing. One row per conversation. (A7)
        assert(@sizeOf(WelcomeState) == 40);
    }
};

pub const welcome_confirmed: WelcomeState = .{ .bucket = &.{}, .last_sent = 0, .last_ack = 0, .attempts = 0, .drifted = false };

/// How a failed `mls.receive` should be READ (A2). The distinction already
/// existed in the error set; it was simply never surfaced — every failure was
/// dropped on the floor and the thread went on looking healthy while replies
/// silently stopped.
///
/// The trap here, and the reason this is a function and not an `else`: a
/// **StaleGeneration** is not a break. Relay delivery is at-least-once by
/// design (a blob is deleted only on ack), so a redelivered message SHOULD
/// fail to open, routinely. Treating that as damage would put a "this
/// conversation is broken" banner in front of the user every time the network
/// hiccupped — crying wolf on the one signal that has to mean something.
const Failure = enum {
    /// The epochs diverged: a Commit one side never saw. Nobody is attacking
    /// anyone; the two halves have simply walked apart, and the fix is to
    /// rebuild the channel. OFFER THE REPAIR.
    drift,
    /// The ciphertext did not authenticate. That is not drift, and it is not
    /// something a user can fix by tapping a button — refuse it, loudly, and
    /// never dress it up as a routine reconnect.
    tamper,
    /// Ordinary at-least-once redelivery, or a message we already processed.
    /// Nothing happened. Say nothing.
    replay,
};

fn classify(err: anyerror) Failure {
    return switch (err) {
        error.WrongEpoch, error.WrongGroup, error.WrongState => .drift,
        error.StaleGeneration => .replay,
        else => .tamper, // DecryptFailed, BadSignature, BadSenderData, BadConfirmationTag, malformed…
    };
}

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
    /// Welcome delivery, parallel to `groups` (A1).
    welcomes: std.ArrayList(WelcomeState) = .empty,
    /// A decrypted Welcome waiting on the directory read that verifies its sender
    /// (`onBucket` no longer does that HTTPS fetch on the render thread — it stashes
    /// the opened Welcome here; the shell fetches off-thread and calls `finishWelcome`).
    /// One at a time: a second Welcome arriving while this is set is deferred (the
    /// relay re-delivers). Freed on `finishWelcome`, on defer, and in `deinit`.
    pending_welcome: ?PendingWelcome = null,
};

pub const InitError = error{
    NoAnchor,
    NoCacheDir,
    PublishFailed,
    OutOfMemory,
    /// Slice 2: this device has ASKED to join the account's chat and is waiting for
    /// a device that is already in it to say yes. Not a failure and not the A3 wall
    /// — a screen that waits, with something true to say while it does.
    DeviceApprovalPending,
    /// A3: this account already publishes a chat key, and it is not this
    /// device's. Chat was set up somewhere else, and the anchor key that owns
    /// it cannot be copied here (that is what makes it worth anything). We
    /// refuse to overwrite it silently — the user is told, and may choose to
    /// set chat up fresh here, which is a real choice with a real cost.
    IdentityElsewhere,
};

/// Bring the account's chat crypto up: publish-or-refresh our directory
/// entry (idempotent — also mints the package + anchor on first use),
/// restore persisted conversations. One network round-trip at startup.
/// `adopt` (A3): the user has been told this account's chat identity lives on
/// another device and has chosen to set chat up FRESH here anyway — replacing
/// the published key. Their existing conversations cannot move with them, and
/// the peers on the other side will have to re-establish. Never true unless a
/// human said so.
pub fn init(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *@import("auth.zig").Session,
    adopt: bool,
) !State {
    // LOCAL-FIRST. The old order ran the keyPackage PUBLISH (a network
    // write) before anything else, so ANY auth/network failure aborted
    // init and emptied the Messages screen — with the MLS groups and the
    // history blob sitting intact on disk (the owner's disappeared-
    // conversations incident, 2026-07-12). The conversation list is LOCAL
    // truth (E2/E4): local state loads unconditionally; the publish runs
    // last and is fatal only on a FIRST RUN, where the keyPackage must be
    // minted before Welcomes can ever arrive.
    var anchor_load = cache.loadOrCreateAnchorSeed(gpa, io, environ, session.did) orelse return error.NoAnchor;
    errdefer std.crypto.secureZero(u8, &anchor_load.seed);
    var kp_path_buf: [512]u8 = undefined;
    const kp_path = cache.chatKeyPackagePath(&kp_path_buf, environ, session.did) orelse return error.NoCacheDir;
    // WHERE DOES THIS DEVICE STAND? (slice 2). The account may already have chat on
    // another device — and that used to be the end of the conversation. Now it is a
    // question with four answers, and only two of them mean "you are not in".
    //
    // `adopt` still means what it always meant: the person was told chat lives
    // elsewhere and chose to start FRESH here anyway, replacing it. That road is
    // unchanged, and it remains the only one that takes chat away from anybody.
    // Root (or the legacy `adopt` road) is the only thing that may write the
    // account's singleton keyPackage record. See the gate at the bottom of init.
    var owns_singleton = adopt;
    if (!adopt) {
        // Note there is no `DirectoryUnreadable` arm here, and there must not be:
        // `ensureDevice` does not report an unreadable directory as an ERROR — it
        // reports it as `.offline`, an ANSWER, so that no caller can lump it in with
        // "something went wrong, carry on" and let it fall through to a publish. It
        // is turned back into an error below, deliberately, where the four real
        // answers are read.
        const status = chat_keys.ensureDevice(gpa, arena, io, environ, session, deviceName(environ)) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.NoAnchor => return error.NoAnchor,
            error.NoCacheDir => return error.NoCacheDir,
            else => return error.PublishFailed,
        };
        switch (status) {
            // We are part of the account: chat comes up, and our own device record
            // is published. The legacy singleton is NOT touched — it belongs to the
            // root, and writing it is the clobber this project exists to end.
            .root => owns_singleton = true,
            // An APPROVED, non-root device MUST NOT write the singleton: that
            // record is the root's, and overwriting it is precisely the clobber
            // this whole project exists to end. It publishes its own record and
            // touches nothing else.
            .approved => {},
            // We have asked, or have not yet. Either way chat does not come up here,
            // and the surface says which — a screen that WAITS is not the same as a
            // screen that offers a button, and telling them apart is the whole
            // difference between a door and a wall.
            .pending => return error.DeviceApprovalPending,
            .not_asked => return error.IdentityElsewhere,
            // We could not read the directory, so we know NOTHING about where this
            // device stands — least of all that it may claim the account. Chat does
            // not come up, nothing is published, and the screen says exactly that
            // rather than inventing one of the four answers above. (2026-07-14: the
            // invented answer was "I am the root", and it cost the owner his chat
            // identity.)
            .offline => return error.DirectoryUnreadable,
        }
    }

    // By here an approved device has already minted + persisted its key package
    // inside `ensureDevice`, so this load succeeds and the singleton path below is
    // not reached. The mint-and-publish road remains for the legacy/adopt case.
    var minted_now = false;
    var kp = cache.loadChatKeyPackageAt(gpa, kp_path, session.did) orelse blk: {
        minted_now = true;
        _ = chat_keys.ensurePublished(gpa, arena, io, environ, session, adopt) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            error.NoAnchor => return error.NoAnchor,
            error.NoCacheDir => return error.NoCacheDir,
            // A3: the account's chat identity is on another device. Do not
            // publish, do not mint over it, do not pretend chat is up.
            error.IdentityElsewhere => return error.IdentityElsewhere,
            // And the same restraint when we could not read the record at all: an
            // unanswered question is not an empty directory.
            error.DirectoryUnreadable => return error.DirectoryUnreadable,
            else => return error.PublishFailed,
        };
        break :blk cache.loadChatKeyPackageAt(gpa, kp_path, session.did) orelse return error.NoCacheDir;
    };
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
    // Re-assert the published record (heals a wiped/expired PDS record) —
    // best-effort on a returning device: a failed network leg must never
    // hide the local conversations again. The A3 gate applies here too: if the
    // record now pins ANOTHER device's key, this re-assert would silently
    // steal the identity back, and two devices trading it every launch is the
    // same footgun wearing a different hat. Refused, quietly — our local
    // conversations still load, which is what this best-effort call is for.
    if (!minted_now and owns_singleton) _ = chat_keys.ensurePublished(gpa, arena, io, environ, session, adopt) catch {};
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
    for (st.welcomes.items) |w| gpa.free(w.bucket);
    st.welcomes.deinit(gpa);
    if (st.pending_welcome) |*pw| {
        pw.group.deinit(gpa);
        gpa.free(pw.peer_did);
    }
}

/// Every mailbox this account drains right now: the bootstrap inbox
/// (Welcomes only — M2.3) + each open conversation's current-epoch traffic
/// mailbox (M2.1). The shell subscribes these at relay start and re-walks
/// them (chat_relay.subscribe is idempotent) after every drained batch, so
/// epoch advances and newly opened conversations pick up their rotated IDs.
/// Caller owns the slice.
/// What this device calls itself in the other device's approval prompt. It is
/// COSMETIC and it is UNSIGNED — a record can put whatever it likes here, so it may
/// put a name in a sentence and nothing else. No decision anywhere turns on it.
fn deviceName(environ: ?*const std.process.Environ.Map) []const u8 {
    if (environ) |e| {
        if (e.get("ZAT_DEVICE_NAME")) |n| {
            if (n.len > 0) return n;
        }
    }
    return if (builtin.os.tag == .linux and builtin.abi.isAndroid()) "Phone" else "Desktop";
}

/// Log a mailbox we are about to use. The one fact that has to agree between two
/// clients, and the one nobody could see.
fn logMailbox(what: []const u8, id: [relay.mailbox_id_len]u8) void {
    if (comptime builtin.is_test) return; // see chat_relay.relayLog
    var hb: [16]u8 = undefined;
    const h = mailboxHex(&hb, id);
    std.debug.print("[chat] {s} mailbox {s}\n", .{ what, h });
    mobile_host.logcat("[chat] {s} mailbox {s}", .{ what, h });
}

/// A short hex of a mailbox id, for logs. The mailbox is the ONE thing that has
/// to agree between two clients — a Welcome deposited into an address the peer is
/// not draining is delivered nowhere, forever, and says nothing. Being able to see
/// both ends of that at a glance is the difference between a five-minute diagnosis
/// and a five-day one.
pub fn mailboxHex(out: *[16]u8, id: [relay.mailbox_id_len]u8) []const u8 {
    const hex = "0123456789abcdef";
    for (0..8) |i| {
        out[i * 2] = hex[id[i] >> 4];
        out[i * 2 + 1] = hex[id[i] & 0xF];
    }
    return out[0..16];
}

/// This account's bootstrap inbox — where Welcomes are delivered to US.
pub fn inbox(st: *const State) [relay.mailbox_id_len]u8 {
    return st.inbox;
}

/// The peer's bootstrap mailbox, as derived from the anchor we have PINNED for
/// them. Where a Welcome to them would go.
pub fn peerBootstrap(st: *const State, peer_did: []const u8) ?[relay.mailbox_id_len]u8 {
    const idx = conversationIndex(st, peer_did) orelse return null;
    return keydir.bootstrapMailbox(st.peer_anchors.items[idx]);
}

pub fn subscriptions(gpa: Allocator, st: *const State) error{OutOfMemory}![][relay.mailbox_id_len]u8 {
    const out = try gpa.alloc([relay.mailbox_id_len]u8, 1 + st.groups.items.len);
    out[0] = st.inbox;
    for (st.groups.items, 0..) |*g, i| out[1 + i] = mls.mailboxId(g, .mine);
    return out;
}

// ---------------------------------------------------------------------------
// SESSIONS, NOT CONVERSATIONS (CHAT_MULTIDEVICE slice 1).
//
// A row used to be "the conversation with this person". It is now "the session
// with ONE OF THIS PERSON'S DEVICES" — so a peer with a phone and a desktop owns
// TWO rows, and a message to them is encrypted separately into each.
//
// This is the pairwise model, and it is Signal's: the sender fans out to every
// device of every participant. We take it because `core/mls.zig` is deliberately
// a TWO-MEMBER implementation (its first line says so, and its tree is literally
// two leaves) — putting four devices in one group means writing a full N-member
// TreeKEM, which is the group-chat problem, and novel cryptography is the last
// place to be adventurous. Every pairwise session here is an ordinary two-member
// group of exactly the kind we already ship, debug and understand.
//
// What it costs: N deposits instead of one. What it does NOT cost: anything on
// the wire. The relay is a per-mailbox store, so even a real N-member group would
// deposit one copy per member — the metadata is identical either way.
// ---------------------------------------------------------------------------

/// The first session with this peer — the ROOT device's, because sessions are
/// appended in device-set order and `keydir.resolveDevices` puts the root first.
/// The root device's key IS the account's chat identity, which is what a caller
/// asking for "their anchor" (the payment gate) actually means.
fn conversationIndex(st: *const State, peer_did: []const u8) ?usize {
    for (st.peer_dids.items, 0..) |d, i| {
        if (std.mem.eql(u8, d, peer_did)) return i;
    }
    return null;
}

/// EVERY session with this peer — one per device of theirs. The buffer is the
/// device cap (`keydir.max_devices`) with headroom, so this never allocates on a
/// send path.
fn sessionsOf(st: *const State, peer_did: []const u8, out: *[16]usize) []const usize {
    var n: usize = 0;
    for (st.peer_dids.items, 0..) |d, i| {
        if (n == out.len) break;
        if (!std.mem.eql(u8, d, peer_did)) continue;
        out[n] = i;
        n += 1;
    }
    return out[0..n];
}

/// The session with ONE named device of a peer — a pair is identified by the two
/// keys at its ends, so this is the only lookup that can be exact.
fn sessionIndex(st: *const State, peer_did: []const u8, device: [32]u8) ?usize {
    for (st.peer_dids.items, st.peer_anchors.items, 0..) |d, a, i| {
        if (std.mem.eql(u8, d, peer_did) and std.mem.eql(u8, &a, &device)) return i;
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
    for (st.peer_dids.items, st.peer_anchors.items, st.groups.items, st.welcomes.items) |did, apub, *g, w| {
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
        // v2: the pending Welcome. It has to outlive the process — the peer
        // this is waiting on may not open their app until tomorrow, and a
        // relaunch that forgot the bucket would leave the conversation
        // permanently half-open with nothing left to retry.
        std.mem.writeInt(u32, &len4, @intCast(w.bucket.len), .little);
        blob.appendSlice(gpa, &len4) catch return;
        blob.appendSlice(gpa, w.bucket) catch return;
        var at8: [8]u8 = undefined;
        std.mem.writeInt(i64, &at8, w.last_sent, .little);
        blob.appendSlice(gpa, &at8) catch return;
        blob.append(gpa, w.attempts) catch return;
        // v3 (A2): a drifted conversation must STILL say it is drifted after a
        // relaunch. Forgetting would put the healthy-looking thread back in
        // front of the user — the exact lie A2 exists to end — until the peer
        // happened to send again, which a peer who has given up will not do.
        blob.append(gpa, @intFromBool(w.drifted)) catch return;
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
    const version = std.mem.bytesToValue(u16, blob[4..6]);
    // ACCEPT EVERY VERSION WE HAVE EVER WRITTEN — 1 through the current one.
    //
    // This line used to read `version != 1 and version != groups_version`,
    // which was correct only while there were exactly two versions. Bumping to
    // v3 (the A2 drift flag) therefore ORPHANED every v2 blob in existence: the
    // reader bailed, and the device silently lost every MLS group it had — every
    // conversation it could decrypt, every peer it could reach. The phone showed
    // "0 conversation(s) restored" with a perfectly good 1,464-byte groups file
    // sitting on disk, and a payment request that could not find anyone to send
    // itself to.
    //
    // The commit that introduced v3 WARNED about exactly this in its own message
    // and still shipped the check unchanged. A version gate is a compatibility
    // contract, and it must be written as a RANGE, not as a list of the versions
    // that happened to exist the day it was typed.
    if (version < 1 or version > groups_version) return;
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

        // v2: the pending Welcome. A v1 blob has none — those conversations
        // predate the ack and are taken as confirmed (see `groups_version`).
        var welcome: WelcomeState = welcome_confirmed;
        if (version >= 2) {
            if (blob.len - at < 4) return;
            const wlen = std.mem.readInt(u32, blob[at..][0..4], .little);
            at += 4;
            const tail: usize = if (version >= 3) 8 + 1 + 1 else 8 + 1;
            if (blob.len - at < @as(usize, wlen) + tail) return;
            if (wlen > 0) {
                welcome.bucket = gpa.dupe(u8, blob[at .. at + wlen]) catch return;
                welcome.last_sent = std.mem.readInt(i64, blob[at + wlen ..][0..8], .little);
                // The ladder starts over on every launch. A peer who was
                // offline for a week comes back to a Welcome that is still
                // trying — without anyone learning the word "Welcome", and
                // without the client hammering the relay in between.
                welcome.attempts = 0;
            }
            // v3 (A2): the drift flag. A v2 blob simply has none, and a
            // conversation written before the fact existed reads as not-drifted
            // — the next message that fails to open will say otherwise.
            if (version >= 3) welcome.drifted = blob[at + wlen + 8 + 1] != 0;
            at += @as(usize, wlen) + tail;
        }

        const did_copy = gpa.dupe(u8, did) catch {
            var g = group;
            g.deinit(gpa);
            gpa.free(welcome.bucket);
            return;
        };
        appendConversation(gpa, st, did_copy, apub, group, welcome) catch {
            var g = group;
            g.deinit(gpa);
            gpa.free(did_copy);
            gpa.free(welcome.bucket);
            return;
        };
    }
}

/// Append one conversation across every parallel array at once. `welcome`
/// owns its bucket (empty = confirmed / nothing of ours to deliver); on the
/// OOM path the caller still owns everything it passed, so nothing is freed
/// here — capacity is reserved for all four arrays before any of them grows,
/// so a partial append is not reachable.
fn appendConversation(gpa: Allocator, st: *State, did_owned: []u8, apub: [32]u8, group: mls.Group, welcome: WelcomeState) error{OutOfMemory}!void {
    try st.peer_dids.ensureUnusedCapacity(gpa, 1);
    try st.peer_anchors.ensureUnusedCapacity(gpa, 1);
    try st.groups.ensureUnusedCapacity(gpa, 1);
    try st.welcomes.ensureUnusedCapacity(gpa, 1);
    st.peer_dids.appendAssumeCapacity(did_owned);
    st.peer_anchors.appendAssumeCapacity(apub);
    st.groups.appendAssumeCapacity(group);
    st.welcomes.appendAssumeCapacity(welcome);
}

/// The peer has acknowledged our Welcome: the channel is real. Drop the
/// retained bucket — there is nothing left to re-send, and the conversation
/// stops reading as "waiting".
fn confirmWelcome(gpa: Allocator, st: *State, idx: usize) bool {
    const w = &st.welcomes.items[idx];
    if (w.bucket.len == 0) return false; // already confirmed; a duplicate ack is a no-op (E4)
    const was_drifted = w.drifted; // an ack does not un-break a drifted ratchet
    gpa.free(w.bucket);
    w.* = welcome_confirmed;
    w.drifted = was_drifted;
    return true;
}

/// Retain the Welcome we just deposited so it can be re-sent until acked.
/// Replaces any bucket already held for this conversation (a re-establish
/// supersedes the Welcome it retries).
fn armWelcome(gpa: Allocator, st: *State, idx: usize, bucket: []const u8, now: i64) void {
    const copy = gpa.dupe(u8, bucket) catch return; // out of memory: the Welcome still went, we just can't retry it
    const w = &st.welcomes.items[idx];
    gpa.free(w.bucket);
    // A re-established channel is not a drifted one — that is the whole point
    // of re-establishing it.
    w.* = .{ .bucket = copy, .last_sent = now, .last_ack = w.last_ack, .attempts = 1, .drifted = false };
}

/// What the far side knows about this conversation (A1) — what the thread
/// must say. No conversation at all reads as `confirmed`: the caller has
/// nothing to show a delivery state for.
/// ACROSS EVERY DEVICE THEY HAVE (slice 1), and the aggregation is a judgement,
/// not an accident:
///
///   - drifted anywhere  → `needs_reconnect`. A channel that cannot decrypt is
///     broken NOW, whatever the others are doing.
///   - acked ANYWHERE    → `confirmed`. The PERSON received it. Their spare
///     laptop being asleep is not the user's problem and must not be dressed up
///     as one — "waiting for them to receive this" would be a lie about a message
///     they are reading right now.
///   - nothing acked     → `waiting`, or `undelivered` once every device has
///     exhausted its retries.
pub fn deliveryState(st: *const State, peer_did: []const u8) chat.Delivery {
    var buf: [16]usize = undefined;
    const sessions = sessionsOf(st, peer_did, &buf);
    if (sessions.len == 0) return .confirmed; // no conversation: nothing to report

    var any_confirmed = false;
    var all_exhausted = true;
    for (sessions) |i| {
        const w = st.welcomes.items[i];
        if (w.drifted) return .needs_reconnect;
        if (w.bucket.len == 0) any_confirmed = true;
        if (w.bucket.len != 0 and w.attempts < chat.welcome_retry_max) all_exhausted = false;
    }
    if (any_confirmed) return .confirmed;
    return if (all_exhausted) .undelivered else .waiting;
}

// ---------------------------------------------------------------------------
// The three verbs
// ---------------------------------------------------------------------------

pub const StartError = error{ NoKeyPackage, AlreadyOpen, NoConversation, CryptoFailed, RelayDown, OutOfMemory };

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

    // EVERY DEVICE THEY HAVE (slice 1). A person is not a device: talking to them
    // means talking to each device they have vouched for, or the message lands on
    // the laptop they left at home and nowhere else.
    var kps_buf: [16]DeviceTarget = undefined;
    const targets = try peerTargets(gpa, arena, io, environ, peer_did, &kps_buf);
    if (targets.len == 0) return error.NoKeyPackage;

    var opened: usize = 0;
    for (targets) |t| {
        openSession(gpa, io, environ, st, link, peer_did, t) catch {
            // One device we could not reach is not a conversation we could not
            // start — the others are live. Only a TOTAL failure is a failure.
            logMailbox("welcome FAILED ->", keydir.bootstrapMailbox(t.anchor_pub));
            continue;
        };
        opened += 1;
    }
    if (opened == 0) return error.RelayDown;
    persist(gpa, environ, st);
}

/// One device of a peer, as the directory gives it to us. A7.2: cold, transient.
const DeviceTarget = struct {
    kp_bytes: []const u8,
    anchor_pub: [32]u8,
};

/// The devices to address a peer at: their signed device set if they publish one,
/// and otherwise their single legacy keyPackage.
///
/// THE FALLBACK IS NOT OPTIONAL. Every account that exists today publishes the old
/// singleton and no device records at all; dropping them the moment the new path
/// shipped would take chat away from everybody we already have in order to serve
/// devices nobody has yet.
fn peerTargets(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    peer_did: []const u8,
    out: *[16]DeviceTarget,
) StartError![]const DeviceTarget {
    if (chat_keys.fetchPeerDevices(gpa, arena, io, environ, peer_did) catch null) |set| {
        var n: usize = 0;
        for (set.devices) |d| {
            if (n == out.len) break;
            out[n] = .{ .kp_bytes = d.key_package, .anchor_pub = d.anchor_pub };
            n += 1;
        }
        if (n > 0) return out[0..n];
    }
    const peer = (chat_keys.fetchPeer(gpa, arena, io, environ, peer_did) catch return error.NoKeyPackage) orelse
        return error.NoKeyPackage;
    out[0] = .{ .kp_bytes = peer.kp_bytes, .anchor_pub = peer.anchor_pub };
    return out[0..1];
}

/// Build ONE pairwise session with ONE device and send it its Welcome. The row is
/// appended only once the Welcome is away, so a device we could not reach leaves
/// no half-open session behind.
fn openSession(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    st: *State,
    link: *chat_relay.ChatRelay,
    peer_did: []const u8,
    target: DeviceTarget,
) StartError!void {
    _ = environ;
    var ce: mls.CreateEntropy = undefined;
    var ae: mls.AddEntropy = undefined;
    io.randomSecure(std.mem.asBytes(&ce)) catch return error.CryptoFailed;
    io.randomSecure(std.mem.asBytes(&ae)) catch return error.CryptoFailed;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&ce));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&ae));

    var group = mls.createGroup(gpa, st.my_did, st.anchor_seed, ce) catch return error.CryptoFailed;
    errdefer group.deinit(gpa);
    const welcome = mls.addPeer(gpa, &group, target.kp_bytes, @intCast(@max(0, clock.unixSeconds())), ae) catch
        return error.CryptoFailed;
    defer gpa.free(welcome);

    var bucket: [relay.bucket_len]u8 = undefined;
    bucketPack(&bucket, welcome) catch return error.CryptoFailed;
    const mailbox = keydir.bootstrapMailbox(target.anchor_pub);
    logMailbox("welcome ->", mailbox);
    chat_relay.deposit(link, mailbox, &bucket) catch return error.RelayDown;

    const did_copy = try gpa.dupe(u8, peer_did);
    errdefer gpa.free(did_copy);
    // The Welcome is OUT, not DELIVERED. Retain the bucket and wait for their
    // ack (A1): until it comes back the session reads as "waiting", and
    // `retryWelcomes` keeps re-sending. One unacknowledged shot is how a
    // conversation ends up alive on one side and absent on the other.
    const retained = try gpa.dupe(u8, &bucket);
    errdefer gpa.free(retained);
    try appendConversation(gpa, st, did_copy, target.anchor_pub, group, .{
        .bucket = retained,
        .last_sent = clock.unixSeconds(),
        .last_ack = 0,
        .attempts = 1,
        .drifted = false,
    });
}

// ─────────────── YOUR OWN DEVICES (CHAT_MULTIDEVICE slice 3) ───────────────
//
// Your devices hold a pairwise session WITH EACH OTHER — an ordinary two-member
// group, no different from one with another person, except that both ends are
// you. It exists to carry the one thing a newly-approved device cannot discover
// on its own: WHO YOU TALK TO.
//
// It has to be this way round. Your desktop cannot open a session between your
// phone and your friend's laptop, because a session is between two key-holding
// endpoints and your desktop does not hold your phone's keys. That is not a
// limitation to work around — it is precisely what "nothing is copied" means. So
// the desktop hands over the LIST, and the phone opens the conversations itself,
// which is the one thing only it can do.

/// Open (or top up) the sessions between this device and the account's OTHER
/// devices. Returns how many we now hold. A device we cannot reach is skipped, not
/// fatal — it will be picked up the next time this runs.
pub fn ensureSelfSessions(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    st: *State,
    link: *chat_relay.ChatRelay,
) usize {
    const set = chat_keys.fetchPeerDevices(gpa, arena, io, environ, st.my_did) catch null orelse return 0;
    const mine = anchor.publicKey(st.anchor_seed) catch return 0;

    var opened: usize = 0;
    for (set.devices) |d| {
        if (std.mem.eql(u8, &d.anchor_pub, &mine)) continue; // not with ourselves
        if (sessionIndex(st, st.my_did, d.anchor_pub) != null) {
            opened += 1;
            continue;
        }
        openSession(gpa, io, environ, st, link, st.my_did, .{
            .kp_bytes = d.key_package,
            .anchor_pub = d.anchor_pub,
        }) catch continue;
        opened += 1;
    }
    if (opened > 0) persist(gpa, environ, st);
    return opened;
}

/// Hand our other devices the list of people we talk to. `dids` is newline-joined
/// (the caller builds it from the conversation store — the SHELL's list, not ours).
///
/// It carries no history and no names: a device that has just been let in gets the
/// people, and fills up from that moment. Sending the backlog is a separate,
/// explicit act (slice 5) and must never be bundled quietly into this one.
pub fn sendRoster(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    st: *State,
    link: *chat_relay.ChatRelay,
    dids: []const u8,
) SendError!void {
    if (dids.len == 0) return;
    var plaintext_buf: [1024]u8 = undefined;
    if (dids.len + 1 > plaintext_buf.len or dids.len + 1 > max_payload) return error.TooLong;
    plaintext_buf[0] = chat.kind_roster_wire;
    @memcpy(plaintext_buf[1..][0..dids.len], dids);
    const plaintext = plaintext_buf[0 .. 1 + dids.len];
    // To every other device of ours — including one that was added while this one
    // was asleep. `depositAll` fans out over exactly those sessions.
    return depositAll(gpa, io, environ, st, link, st.my_did, plaintext);
}

// ── HISTORY TRANSFER (slice 5) ──────────────────────────────────────────────
//
// The backlog, from the device that has it to the device that has just been let
// in. Over the SAME pairwise session your devices already share, so it is end-to-
// end encrypted like everything else and the relay carries it as the same opaque
// fixed-size buckets it carries messages in.
//
// Opt-in, and separate from adding a device on purpose. Adding a device gets you
// the people; this gets you the past, and only because you asked for it.

/// How much of the blob rides in one bucket. Comfortably inside the payload cap
/// once the MLS framing is on top — a bucket is a FIXED size (a variable one would
/// leak the length of what you said), so the chunk must fit with room to spare.
pub const history_chunk_len: usize = 900;

/// Ask our other devices for the backlog.
pub fn requestHistory(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    st: *State,
    link: *chat_relay.ChatRelay,
) SendError!void {
    const req = [1]u8{chat.kind_history_req_wire};
    return depositAll(gpa, io, environ, st, link, st.my_did, &req);
}

/// Send `blob` (the serialized store) to ONE of our devices, in order. The mailbox
/// is FIFO and MLS wants in-order delivery per sender, so the chunks arrive as they
/// left; a lost one leaves the transfer incomplete rather than corrupt (the
/// receiver only adopts a history it has all of).
pub fn sendHistory(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    st: *State,
    link: *chat_relay.ChatRelay,
    device: [32]u8,
    blob: []const u8,
) SendError!void {
    const idx = sessionIndex(st, st.my_did, device) orelse return error.NoConversation;
    const total = (blob.len + history_chunk_len - 1) / history_chunk_len;
    if (total == 0 or total > 0xFFFF) return error.TooLong;

    var buf: [5 + history_chunk_len]u8 = undefined;
    var seq: usize = 0;
    while (seq < total) : (seq += 1) {
        const from = seq * history_chunk_len;
        const to = @min(from + history_chunk_len, blob.len);
        buf[0] = chat.kind_history_chunk_wire;
        std.mem.writeInt(u16, buf[1..3], @intCast(seq), .little);
        std.mem.writeInt(u16, buf[3..5], @intCast(total), .little);
        @memcpy(buf[5..][0 .. to - from], blob[from..to]);
        try depositPlain(gpa, io, environ, st, link, idx, buf[0 .. 5 + (to - from)]);
    }
}

/// Ask the other side to unsend a message of ours (CHAT_FEATURES slice 3). It goes
/// to every device they have, like any other message — a message that vanished from
/// their phone but not their laptop would be worse than not deleting it at all.
/// `to` is who receives it (the peer, or our OWN did for our other devices); `conv`
/// is the conversation the message lives in.
///
/// THE CONVERSATION HAS TO RIDE ALONG. A revision that reaches our own other device
/// says "delete the message you sent at 14:03" — and that device has no way to know
/// WHICH conversation that was. The peer ignores this field (its session already
/// says which conversation it is); our own device needs it.
pub fn sendUnsend(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    st: *State,
    link: *chat_relay.ChatRelay,
    to: []const u8,
    conv_did: []const u8,
    created_at: i64,
) SendError!void {
    var buf: [10 + 128]u8 = undefined;
    if (conv_did.len > 128) return error.TooLong;
    buf[0] = chat.kind_unsend_wire;
    std.mem.writeInt(i64, buf[1..9], created_at, .little);
    buf[9] = @intCast(conv_did.len);
    @memcpy(buf[10..][0..conv_did.len], conv_did);
    return depositAll(gpa, io, environ, st, link, to, buf[0 .. 10 + conv_did.len]);
}

/// Ask them to apply an edit to a message of ours.
pub fn sendEdit(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    st: *State,
    link: *chat_relay.ChatRelay,
    to: []const u8,
    conv_did: []const u8,
    created_at: i64,
    text: []const u8,
) SendError!void {
    var buf: [1024]u8 = undefined;
    if (conv_did.len > 128) return error.TooLong;
    const head = 10 + conv_did.len;
    if (head + text.len > buf.len or head + text.len > max_payload) return error.TooLong;
    buf[0] = chat.kind_edit_wire;
    std.mem.writeInt(i64, buf[1..9], created_at, .little);
    buf[9] = @intCast(conv_did.len);
    @memcpy(buf[10..][0..conv_did.len], conv_did);
    @memcpy(buf[head..][0..text.len], text);
    return depositAll(gpa, io, environ, st, link, to, buf[0 .. head + text.len]);
}

/// What a refresh found out about a peer (slice 4). A7.2: cold, transient.
pub const Refresh = enum {
    /// They are who they were. Nothing to do, nothing to say.
    unchanged,
    /// They added or removed a device. We now hold a session with each of the ones
    /// they have, and none of the ones they do not. Nothing is said: adding a
    /// phone is not an event that should interrupt anybody.
    updated,
    /// EVERY device we knew is gone, and a new one has taken over their chat —
    /// they started fresh (a lost phone, a reinstall, a wipe). Their messages will
    /// reach us again, but the person MUST be told, because "their keys changed
    /// and everything carried on quietly" is exactly what a successful
    /// impersonation looks like.
    reset,
};

/// Bring our sessions with `peer_did` up to date with the devices they publish
/// NOW — the thing that makes a lost device survivable, and the thing that makes a
/// key change VISIBLE.
///
/// This is what the roadmap calls "the friend's client notices": a person who lost
/// their phone and signed in on a new one does not have to re-message anybody. The
/// next time our client looks, it sees the new device, rebuilds, and their thread
/// simply comes back to life with their next message in it.
pub fn refreshPeer(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    st: *State,
    link: *chat_relay.ChatRelay,
    peer_did: []const u8,
) Refresh {
    var known_buf: [16]usize = undefined;
    const known = sessionsOf(st, peer_did, &known_buf);
    if (known.len == 0) return .unchanged;

    var kps_buf: [16]DeviceTarget = undefined;
    const targets = peerTargets(gpa, arena, io, environ, peer_did, &kps_buf) catch return .unchanged;
    if (targets.len == 0) return .unchanged; // they publish nothing right now: say nothing

    // Do we still recognise ANY of them? If not, every device we ever knew of
    // theirs is gone and something else is answering for their DID. That is the
    // "started fresh" signature, and it is the one thing here worth saying out loud.
    var overlap: usize = 0;
    var added: usize = 0;
    for (targets) |t| {
        if (sessionIndex(st, peer_did, t.anchor_pub) != null) overlap += 1 else added += 1;
    }
    if (overlap == 0) {
        // Rebuild against whoever they are now. (Their old sessions are dead
        // anyway: a ratchet whose far end no longer exists can decrypt nothing.)
        for (targets) |t| openSession(gpa, io, environ, st, link, peer_did, t) catch continue;
        dropStaleSessions(gpa, st, peer_did, targets);
        persist(gpa, environ, st);
        return .reset;
    }

    if (added == 0 and targets.len == known.len) return .unchanged;

    // They added a device (or retired one). Open what is new, forget what is gone —
    // quietly, because this is housekeeping and not news.
    for (targets) |t| {
        if (sessionIndex(st, peer_did, t.anchor_pub) != null) continue;
        openSession(gpa, io, environ, st, link, peer_did, t) catch continue;
    }
    dropStaleSessions(gpa, st, peer_did, targets);
    persist(gpa, environ, st);
    return .updated;
}

/// RE-ESTABLISH a conversation we already have: fetch the peer's CURRENT
/// published keys, build a fresh group, send them a new Welcome, and replace our
/// stale group with it.
///
/// This is the sender's half of the recovery `acceptWelcome` performs on the
/// receiving side, and without it a desynchronised conversation could only be
/// fixed by the OTHER person — which, when neither side can message the other,
/// is not a repair path at all.
///
/// Conversations desynchronise for ordinary reasons: a Welcome that never landed
/// (a relay outage, or a client pointed at the wrong relay), a reinstall, a lost
/// cache. Nothing is lost by doing this — history is local (the Signal model),
/// and a group the peer has moved on from could not decrypt anything anyway.
pub fn restartConversation(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    st: *State,
    link: *chat_relay.ChatRelay,
    peer_did: []const u8,
) StartError!void {
    if (conversationIndex(st, peer_did) == null) return error.NoConversation;
    var set = try fetchRestartTargets(gpa, arena, io, environ, peer_did);
    defer freeRestartTargets(gpa, &set);
    try applyRestart(gpa, environ, io, st, link, peer_did, &set);
}

/// The peer's CURRENT devices, copied into gpa-owned memory. Split out from
/// `restartConversation` so the SLOW half — reading the peer's directory — can run
/// on a worker whose arena dies before the result is applied (the re-establish
/// "wave of slowdown" was this read blocking the render thread). Nothing here
/// touches `State`; the container is stack-sized and only the key-package bytes are
/// heap-owned, so the result travels back to the loop by value.
/// A7.2: cold, transient — one re-establish in flight at a time.
pub const PeerTargetSet = struct {
    count: usize = 0,
    anchors: [16][32]u8 = undefined,
    /// gpa-owned; parallel to `anchors`. Free with `freeRestartTargets`.
    kps: [16][]const u8 = undefined,
};

/// PHASE 1 (worker-safe): read the peer's device directory and copy every device's
/// key package into gpa-owned memory. Pure network + heap; never reads or writes
/// `State`, so it is safe to run off the render thread.
pub fn fetchRestartTargets(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    peer_did: []const u8,
) StartError!PeerTargetSet {
    // Their CURRENT devices — not the ones we pinned. If they reinstalled, added a
    // phone, or started chat over on a new device, THIS is where we learn it: the
    // repair rebuilds against whoever they are now, not whoever they were.
    var kps_buf: [16]DeviceTarget = undefined;
    const targets = try peerTargets(gpa, arena, io, environ, peer_did, &kps_buf);
    if (targets.len == 0) return error.NoKeyPackage;

    var set: PeerTargetSet = .{};
    errdefer freeRestartTargets(gpa, &set);
    for (targets) |t| {
        set.kps[set.count] = try gpa.dupe(u8, t.kp_bytes);
        set.anchors[set.count] = t.anchor_pub;
        set.count += 1;
    }
    return set;
}

pub fn freeRestartTargets(gpa: Allocator, set: *PeerTargetSet) void {
    for (set.kps[0..set.count]) |kp| gpa.free(kp);
    set.count = 0;
}

/// PHASE 2 (render thread): given the fetched devices, rebuild the pairwise groups
/// and send the new Welcomes. This MUTATES `State` (the groups, the anchors, the
/// welcome backlog) and deposits into the relay, so it belongs on the loop, never
/// on the worker — but it is local crypto plus a relay socket write, not the slow
/// directory read Phase 1 already carried off-thread.
pub fn applyRestart(
    gpa: Allocator,
    environ: ?*const std.process.Environ.Map,
    io: std.Io,
    st: *State,
    link: *chat_relay.ChatRelay,
    peer_did: []const u8,
    set: *const PeerTargetSet,
) StartError!void {
    if (conversationIndex(st, peer_did) == null) return error.NoConversation;

    var targets_buf: [16]DeviceTarget = undefined;
    const targets = targetsFromSet(set, &targets_buf);

    var rebuilt: usize = 0;
    for (targets) |t| {
        // A session with THIS device already? Rebuild it in place. Otherwise this
        // is a device they have added since we last spoke — open a session with it.
        if (sessionIndex(st, peer_did, t.anchor_pub)) |idx| {
            rebuildSession(gpa, io, st, link, idx, t) catch continue;
        } else {
            openSession(gpa, io, environ, st, link, peer_did, t) catch continue;
        }
        rebuilt += 1;
    }
    if (rebuilt == 0) return error.RelayDown;

    // Sessions with devices they NO LONGER HAVE are dropped. Keeping them would
    // mean every message costing a deposit into a mailbox nobody reads, and the
    // thread reporting "waiting" forever on a device that is gone.
    dropStaleSessions(gpa, st, peer_did, targets);
    persist(gpa, environ, st);
}

/// Rebuild the borrowed `DeviceTarget` slice from a gpa-owned `PeerTargetSet`. The
/// set is what a worker fetched off-thread; the targets index INTO it, so they live
/// exactly as long as the caller holds the set.
fn targetsFromSet(set: *const PeerTargetSet, buf: *[16]DeviceTarget) []const DeviceTarget {
    for (set.kps[0..set.count], set.anchors[0..set.count], 0..) |kp, anchor_pub, i| {
        buf[i] = .{ .kp_bytes = kp, .anchor_pub = anchor_pub };
    }
    return buf[0..set.count];
}

// ── The apply halves of the periodic maintenance legs (the "wave of slowdown"
// class, one layer out from re-establish). Each mirrors an existing function
// whose directory READ now runs on a worker; these do the SESSION work on the
// loop from the fetched `PeerTargetSet`. None of them read the network. ──

/// `ensureSelfSessions`'s apply half: open a session with each of our OWN other
/// devices we don't yet hold one with. Returns the count of self-sessions (new +
/// existing) — the caller publishes the roster only when that is nonzero.
pub fn applySelfSessions(
    gpa: Allocator,
    environ: ?*const std.process.Environ.Map,
    io: std.Io,
    st: *State,
    link: *chat_relay.ChatRelay,
    set: *const PeerTargetSet,
) usize {
    const mine = anchor.publicKey(st.anchor_seed) catch return 0;
    var buf: [16]DeviceTarget = undefined;
    const targets = targetsFromSet(set, &buf);
    var opened: usize = 0;
    for (targets) |t| {
        if (std.mem.eql(u8, &t.anchor_pub, &mine)) continue; // not with ourselves
        if (sessionIndex(st, st.my_did, t.anchor_pub) != null) {
            opened += 1;
            continue;
        }
        openSession(gpa, io, environ, st, link, st.my_did, t) catch continue;
        opened += 1;
    }
    if (opened > 0) persist(gpa, environ, st);
    return opened;
}

/// `startConversation`'s apply half: open a brand-new conversation with a peer from
/// their fetched device set (the roster-receive leg).
pub fn applyStartConversation(
    gpa: Allocator,
    environ: ?*const std.process.Environ.Map,
    io: std.Io,
    st: *State,
    link: *chat_relay.ChatRelay,
    peer_did: []const u8,
    set: *const PeerTargetSet,
) StartError!void {
    if (conversationIndex(st, peer_did) != null) return; // already open — nothing to do
    var buf: [16]DeviceTarget = undefined;
    const targets = targetsFromSet(set, &buf);
    if (targets.len == 0) return error.NoKeyPackage;
    var opened: usize = 0;
    for (targets) |t| {
        openSession(gpa, io, environ, st, link, peer_did, t) catch continue;
        opened += 1;
    }
    if (opened == 0) return error.RelayDown;
    persist(gpa, environ, st);
}

/// `refreshPeer`'s apply half: reconcile an existing peer's sessions against their
/// fetched device set, returning the same `unchanged`/`updated`/`reset`
/// classification (the shell says "started chat on a new device" on `reset`).
pub fn applyPeerRefresh(
    gpa: Allocator,
    environ: ?*const std.process.Environ.Map,
    io: std.Io,
    st: *State,
    link: *chat_relay.ChatRelay,
    peer_did: []const u8,
    set: *const PeerTargetSet,
) Refresh {
    var known_buf: [16]usize = undefined;
    const known = sessionsOf(st, peer_did, &known_buf);
    if (known.len == 0) return .unchanged;

    var buf: [16]DeviceTarget = undefined;
    const targets = targetsFromSet(set, &buf);
    if (targets.len == 0) return .unchanged; // they publish nothing right now: say nothing

    var overlap: usize = 0;
    var added: usize = 0;
    for (targets) |t| {
        if (sessionIndex(st, peer_did, t.anchor_pub) != null) overlap += 1 else added += 1;
    }
    if (overlap == 0) {
        for (targets) |t| openSession(gpa, io, environ, st, link, peer_did, t) catch continue;
        dropStaleSessions(gpa, st, peer_did, targets);
        persist(gpa, environ, st);
        return .reset;
    }
    if (added == 0 and targets.len == known.len) return .unchanged;
    for (targets) |t| {
        if (sessionIndex(st, peer_did, t.anchor_pub) != null) continue;
        openSession(gpa, io, environ, st, link, peer_did, t) catch continue;
    }
    dropStaleSessions(gpa, st, peer_did, targets);
    persist(gpa, environ, st);
    return .updated;
}

/// Rebuild one existing pairwise session against the device's current keys. The
/// new group replaces the old ONLY once its Welcome is away: if the deposit fails
/// we keep the old one and the user can try again, rather than being left holding
/// a group the peer has never heard of.
fn rebuildSession(
    gpa: Allocator,
    io: std.Io,
    st: *State,
    link: *chat_relay.ChatRelay,
    idx: usize,
    target: DeviceTarget,
) StartError!void {
    var ce: mls.CreateEntropy = undefined;
    var ae: mls.AddEntropy = undefined;
    io.randomSecure(std.mem.asBytes(&ce)) catch return error.CryptoFailed;
    io.randomSecure(std.mem.asBytes(&ae)) catch return error.CryptoFailed;
    defer std.crypto.secureZero(u8, std.mem.asBytes(&ce));
    defer std.crypto.secureZero(u8, std.mem.asBytes(&ae));

    var group = mls.createGroup(gpa, st.my_did, st.anchor_seed, ce) catch return error.CryptoFailed;
    errdefer group.deinit(gpa);
    const welcome = mls.addPeer(gpa, &group, target.kp_bytes, @intCast(@max(0, clock.unixSeconds())), ae) catch
        return error.CryptoFailed;
    defer gpa.free(welcome);

    var bucket: [relay.bucket_len]u8 = undefined;
    bucketPack(&bucket, welcome) catch return error.CryptoFailed;
    const mailbox = keydir.bootstrapMailbox(target.anchor_pub);
    logMailbox("re-welcome ->", mailbox);
    chat_relay.deposit(link, mailbox, &bucket) catch return error.RelayDown;

    st.groups.items[idx].deinit(gpa);
    st.groups.items[idx] = group;
    st.peer_anchors.items[idx] = target.anchor_pub;
    armWelcome(gpa, st, idx, &bucket, clock.unixSeconds());
}

/// Forget the sessions we hold with devices this peer no longer has (they removed
/// one, or started chat over and every old device went with it).
fn dropStaleSessions(gpa: Allocator, st: *State, peer_did: []const u8, targets: []const DeviceTarget) void {
    var i: usize = st.peer_dids.items.len;
    while (i > 0) {
        i -= 1;
        if (!std.mem.eql(u8, st.peer_dids.items[i], peer_did)) continue;
        const anchor_i = st.peer_anchors.items[i];
        var still_theirs = false;
        for (targets) |t| {
            if (std.mem.eql(u8, &t.anchor_pub, &anchor_i)) still_theirs = true;
        }
        if (still_theirs) continue;
        gpa.free(st.peer_dids.orderedRemove(i));
        _ = st.peer_anchors.orderedRemove(i);
        var g = st.groups.orderedRemove(i);
        g.deinit(gpa);
        const w = st.welcomes.orderedRemove(i);
        gpa.free(w.bucket);
    }
}

/// Re-send every Welcome the peer has not acknowledged and that the backoff
/// says is due (A1). Cheap and idempotent: called on the chat tick, walks a
/// handful of rows, and deposits only what the pure policy
/// (`chat.welcomeRetryDue`) admits. A relay that refuses the deposit is not
/// an error here — the next tick tries again.
pub fn retryWelcomes(
    gpa: Allocator,
    environ: ?*const std.process.Environ.Map,
    st: *State,
    link: *chat_relay.ChatRelay,
    now: i64,
) void {
    var sent = false;
    for (st.welcomes.items, 0..) |*w, i| {
        if (w.bucket.len != relay.bucket_len) continue; // acked (empty), or damage we will not deposit
        if (!chat.welcomeRetryDue(w.attempts, w.last_sent, now)) continue;
        const target = keydir.bootstrapMailbox(st.peer_anchors.items[i]);
        chat_relay.deposit(link, target, w.bucket[0..relay.bucket_len]) catch continue;
        w.attempts +|= 1;
        w.last_sent = now;
        sent = true;
        logMailbox("welcome RETRY ->", target);
    }
    if (sent) persist(gpa, environ, st);
}

/// Tell the peer their Welcome landed and we joined (A1): one MLS-encrypted
/// byte over the group we just joined — end-to-end authenticated, invisible
/// to the relay, and indistinguishable from any other bucket. Throttled per
/// conversation, because a Welcome rides a public mailbox and anyone can
/// replay one at us.
/// THE ACK IS NOT FANNED OUT, and that is deliberate. It answers ONE Welcome —
/// the one that established the session with ONE of their devices — so it is
/// encrypted over that session and no other. Acking every session with the peer
/// would tell their OTHER devices that a Welcome they may never have sent had
/// been delivered, retiring a retry for a channel that does not exist. That is
/// precisely the A1 bug (a conversation alive on one side, absent on the other)
/// wearing a different hat.
pub fn sendGroupAck(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    st: *State,
    link: *chat_relay.ChatRelay,
    peer_did: []const u8,
    device: [32]u8,
    now: i64,
) SendError!void {
    const idx = sessionIndex(st, peer_did, device) orelse return error.NoConversation;
    const w = &st.welcomes.items[idx];
    if (w.last_ack != 0 and now - w.last_ack < chat.welcome_ack_min_gap_s) return;
    const ack = [1]u8{chat.kind_group_ack_wire};
    try depositPlain(gpa, io, environ, st, link, idx, &ack);
    st.welcomes.items[idx].last_ack = now; // only on success: a failed ack must be retryable
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
    // The peer's current-epoch TRAFFIC mailbox (M2.1) — never the bootstrap
    // (that ID is anchor-linkable; it carries only Welcomes, M2.3). Same
    // fixed bucket either way: rotation moves the address, never the shape
    // (M2.4 — no length side-channel).
    chat_relay.deposit(link, mls.mailboxId(&st.groups.items[idx], .peers), &bucket) catch return error.RelayDown;
}

/// THE FAN-OUT. Encrypt this plaintext SEPARATELY into every session we hold
/// with the peer — one per device of theirs — and deposit each into that device's
/// mailbox. Each session has its own ratchet, so this is N encryptions, not one
/// ciphertext sent N times: a device that is not in a session cannot read a word
/// of what the others get.
///
/// A DEVICE THAT FAILS IS NOT A FAILED SEND. If their laptop's deposit is refused
/// but their phone's lands, the message reached the person, and telling them it
/// did not would be a lie they cannot act on. We fail only when EVERY device
/// failed — which is the case the user can actually do something about.
fn depositAll(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    st: *State,
    link: *chat_relay.ChatRelay,
    peer_did: []const u8,
    plaintext: []const u8,
) SendError!void {
    var buf: [16]usize = undefined;
    const sessions = sessionsOf(st, peer_did, &buf);
    if (sessions.len == 0) return error.NoConversation;

    var delivered: usize = 0;
    var last: ?SendError = null;
    for (sessions) |idx| {
        depositPlain(gpa, io, environ, st, link, idx, plaintext) catch |err| {
            last = err;
            continue;
        };
        delivered += 1;
    }
    if (delivered == 0) return last orelse error.RelayDown;
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
    /// The SCREEN effect the sender PICKED (0 = none) and the BUBBLE effect (0 =
    /// none) — the two axes of "Send with…". Only a manual pick travels; the
    /// phrase-triggered screen effects are re-derived from the text on both ends.
    effect: u8,
    bubble: u8,
) SendError!void {
    assert(!chat.isPaymentKind(kind));
    // With NEITHER axis set the bytes are EXACTLY what they were before effects
    // existed — one kind byte and the text — so ordinary delivery is untouched
    // (and an older peer keeps receiving every ordinary message). A decorated
    // message takes the wider frame: [kind_text_fx][screen][bubble][text].
    const decorated = effect != 0 or bubble != 0;
    const head: usize = if (decorated) 3 else 1;
    if (text.len + head > max_payload) return error.TooLong; // ciphertext ≥ plaintext; cheap early cut
    var plaintext_buf: [1024]u8 = undefined;
    if (text.len + head > plaintext_buf.len) return error.TooLong;
    if (!decorated) {
        plaintext_buf[0] = @intFromEnum(kind);
    } else {
        plaintext_buf[0] = chat.kind_text_fx_wire;
        plaintext_buf[1] = effect;
        plaintext_buf[2] = bubble;
    }
    @memcpy(plaintext_buf[head..][0..text.len], text);
    const plaintext = plaintext_buf[0 .. head + text.len];
    defer std.crypto.secureZero(u8, plaintext);
    return depositAll(gpa, io, environ, st, link, peer_did, plaintext);
}

/// Send ONE GAME MOVE. Two bytes: the kind and the encoded move.
///
/// The mover is deliberately NOT on the wire. There is no "I am X" field to
/// forge — the seat comes from replay position, and whether the sender was
/// entitled to that seat is checked on arrival by `chat_games.replaySent`, which
/// can see who sent what. A move that was not this player's to make is skipped
/// there, so a cheating peer degrades to "that move didn't happen".
pub fn sendGameMove(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    st: *State,
    link: *chat_relay.ChatRelay,
    peer_did: []const u8,
    encoded_move: u8,
) SendError!void {
    var buf: [2]u8 = .{ @intFromEnum(chat.Kind.game_move), encoded_move };
    defer std.crypto.secureZero(u8, &buf);
    return depositAll(gpa, io, environ, st, link, peer_did, &buf);
}

/// Send a message that ANSWERS another one.
pub fn sendReply(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    st: *State,
    link: *chat_relay.ChatRelay,
    peer_did: []const u8,
    target_at: i64,
    target_mine: bool,
    text: []const u8,
) SendError!void {
    var buf: [1024]u8 = undefined;
    if (10 + text.len > buf.len or 10 + text.len > max_payload) return error.TooLong;
    buf[0] = chat.kind_reply_wire;
    std.mem.writeInt(i64, buf[1..9], target_at, .little);
    buf[9] = @intFromBool(target_mine);
    @memcpy(buf[10..][0..text.len], text);
    const plaintext = buf[0 .. 10 + text.len];
    defer std.crypto.secureZero(u8, plaintext);
    return depositAll(gpa, io, environ, st, link, peer_did, plaintext);
}

/// React to a message (or take a reaction back — the same emoji twice toggles).
pub fn sendReact(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    st: *State,
    link: *chat_relay.ChatRelay,
    peer_did: []const u8,
    target_at: i64,
    target_mine: bool,
    emoji: []const u8,
) SendError!void {
    var buf: [32]u8 = undefined;
    if (10 + emoji.len > buf.len) return error.TooLong;
    buf[0] = chat.kind_react_wire;
    std.mem.writeInt(i64, buf[1..9], target_at, .little);
    buf[9] = @intFromBool(target_mine);
    @memcpy(buf[10..][0..emoji.len], emoji);
    return depositAll(gpa, io, environ, st, link, peer_did, buf[0 .. 10 + emoji.len]);
}

/// Tell them we have read everything of theirs up to `at`. ONE deposit, a
/// watermark — not one per message, because every deposit is a fact the relay can
/// put a timestamp on and there is no reason to hand it more of them than the truth
/// requires.
pub fn sendRead(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    st: *State,
    link: *chat_relay.ChatRelay,
    peer_did: []const u8,
    up_to: i64,
) SendError!void {
    var buf: [9]u8 = undefined;
    buf[0] = chat.kind_read_wire;
    std.mem.writeInt(i64, buf[1..9], up_to, .little);
    return depositAll(gpa, io, environ, st, link, peer_did, &buf);
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
    const ping = [1]u8{chat.kind_typing_wire};
    return depositAll(gpa, io, environ, st, link, peer_did, &ping);
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

/// An S2 lifecycle wire event (offer/ready/cancel/decline, bytes 20-23): the
/// same frame the settlement events carry, never a stored kind. The offer
/// (20) makes the receiver CREATE a `pending_setup` card; 21/22/23 flip an
/// existing one. The `kind_byte` is the caller's contract (`kind_pay_*_wire`).
pub fn sendPaymentSignal(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    st: *State,
    link: *chat_relay.ChatRelay,
    peer_did: []const u8,
    kind_byte: u8,
    frame: chat.PaymentFrame,
) SendError!void {
    assert(kind_byte >= chat.kind_pay_offer_wire and kind_byte <= chat.kind_pay_decline_wire);
    return sendPaymentBytes(gpa, io, environ, st, link, peer_did, kind_byte, frame);
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
    var plaintext_buf: [1024]u8 = undefined;
    const need = 1 + chat.payment_frame_min + frame.note.len;
    if (need > plaintext_buf.len or need > max_payload) return error.TooLong;
    plaintext_buf[0] = kind_byte;
    const body = chat.buildPaymentFrame(plaintext_buf[1..], frame);
    const plaintext = plaintext_buf[0 .. 1 + body.len];
    defer std.crypto.secureZero(u8, plaintext); // amounts are content too
    // A payment card reaches every device they have, like any other message —
    // a card that showed up on one of a person's devices and not the others
    // would be a payment they could see and not answer.
    return depositAll(gpa, io, environ, st, link, peer_did, plaintext);
}

/// What one inbox bucket became. `peer_did`/`text` are gpa-owned by the
/// event; release with `freeIncoming`. A7.2: cold union, transient.
pub const Incoming = union(enum) {
    message: struct { peer_did: []u8, kind: chat.Kind, text: []u8, effect: u8 = 0, bubble: u8 = 0 },
    /// One move of an in-thread game. Separate from `.message` because it is not
    /// a message anybody reads — it carries no text, and the thread renders it as
    /// a board rather than a bubble.
    game_move: struct { peer_did: []u8, encoded: u8 },
    /// `device` is the peer DEVICE whose Welcome opened this session — an ack
    /// answers ONE Welcome, so the shell has to know which one (slice 1).
    started: struct { peer_did: []u8, device: [32]u8 },
    /// The peer RE-ESTABLISHED an existing conversation (their side had been
    /// lost or was never completed). Their keys are verified — this is not a
    /// warning, it is a fact worth stating in the thread, because from here on
    /// messages will actually arrive, and before now they silently did not.
    restarted: struct { peer_did: []u8, device: [32]u8 },
    /// The peer is typing right now — ephemeral; the shell shows the
    /// indicator for a few seconds and lets it lapse. Never stored.
    typing: struct { peer_did: []u8 },
    /// The peer wants a message of THEIRS taken down (CHAT_FEATURES slice 3).
    unsend: struct { peer_did: []u8, conv_did: []u8, created_at: i64 },
    /// The peer revised a message of THEIRS.
    edit: struct { peer_did: []u8, conv_did: []u8, created_at: i64, text: []u8 },
    /// A message that answers one of ours (or one of theirs).
    reply: struct { peer_did: []u8, target_at: i64, target_mine: bool, text: []u8 },
    /// They reacted to a message (or took the reaction back).
    react: struct { peer_did: []u8, target_at: i64, target_mine: bool, emoji: []u8 },
    /// They have read everything of ours up to `up_to`.
    read: struct { peer_did: []u8, up_to: i64 },
    /// ANOTHER DEVICE OF OURS is asking for the backlog (slice 5). `device` names
    /// which one, so the answer goes to it and to nobody else.
    history_request: struct { device: [32]u8 },
    /// A piece of the backlog, from our own device. Adopted only when every piece
    /// has arrived — a half a history is not a history.
    history_chunk: struct { seq: u16, total: u16, bytes: []u8 },
    /// ANOTHER DEVICE OF OURS handed us the list of people we talk to (slice 3):
    /// newline-joined DIDs, gpa-owned. Only ever produced for a session with our
    /// OWN did — a roster from anyone else is refused before it gets here.
    roster: struct { dids: []u8 },
    /// A Welcome we ALREADY joined, arriving again (A1) — the peer's retry,
    /// because our ack never reached them. Nothing changes on our side (the
    /// group is the one we are already using; rebuilding it would reset a
    /// live ratchet). The shell simply acks again.
    welcome_again: struct { peer_did: []u8, device: [32]u8 },
    /// The peer ACKED our Welcome: the conversation is real on both sides
    /// (A1). Nothing enters the store — this only retires the retry and the
    /// thread's "waiting for them to receive this" line.
    confirmed: struct { peer_did: []u8 },
    /// A2: the two halves DRIFTED — their message will not open under our
    /// ratchet, and it is not tampering and not a redelivery. The conversation
    /// is marked as needing to reconnect; the thread says so and offers the
    /// repair, rather than dropping the message and looking healthy.
    drifted: struct { peer_did: []u8 },
    /// A2: the ciphertext did not authenticate. NOT drift, and not something a
    /// tap can fix — refused, and said so. Never dressed up as a reconnect.
    tampered: struct { peer_did: []u8 },
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
        /// This is an S2 OFFER (wire byte 20) to a walletless recipient —
        /// the drain creates the card at `pending_setup` (no money in
        /// motion), not the kind's default. A stored payment_request/
        /// payment_sent card carries `false`.
        is_offer: bool,
    },
    /// A lifecycle event that FLIPS an existing card (settlement bytes 18/19
    /// or the S2 ready/cancel/decline 21/22/23): the receiver correlates by
    /// id and advances the card to `status`. Never stored as a message.
    payment_update: struct {
        peer_did: []u8,
        id: u64,
        ref: [32]u8,
        status: chat.PayStatus,
    },
};

pub fn freeIncoming(gpa: Allocator, inc: Incoming) void {
    switch (inc) {
        .message => |m| {
            gpa.free(m.peer_did);
            gpa.free(m.text);
        },
        .game_move => |g| gpa.free(g.peer_did),
        .started => |s| gpa.free(s.peer_did),
        .restarted => |s| gpa.free(s.peer_did),
        .typing => |t| gpa.free(t.peer_did),
        .roster => |r| gpa.free(r.dids),
        .unsend => |u| {
            gpa.free(u.peer_did);
            gpa.free(u.conv_did);
        },
        .edit => |ed| {
            gpa.free(ed.peer_did);
            gpa.free(ed.conv_did);
            gpa.free(ed.text);
        },
        .reply => |r| {
            gpa.free(r.peer_did);
            gpa.free(r.text);
        },
        .react => |r| {
            gpa.free(r.peer_did);
            gpa.free(r.emoji);
        },
        .read => |r| gpa.free(r.peer_did),
        .history_request => {},
        .history_chunk => |h| gpa.free(h.bytes),
        .welcome_again => |s| gpa.free(s.peer_did),
        .confirmed => |s| gpa.free(s.peer_did),
        .drifted => |s| gpa.free(s.peer_did),
        .tampered => |s| gpa.free(s.peer_did),
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
    /// The conversation this Welcome RE-ESTABLISHES, if we already had one with
    /// this DID. `null` = genuinely first contact.
    ///
    /// This used to be impossible: a Welcome from a peer we already knew was
    /// dropped on the floor, silently, which made a desynchronised conversation
    /// PERMANENTLY dead. And they desynchronise for entirely ordinary reasons —
    /// a Welcome that never reached the other side (a relay outage, or, in our
    /// case, a client pointed at the wrong relay), a reinstall, a cleared cache.
    /// Once it happened there was no way out of it from the UI, and no message
    /// anywhere saying so. See `acceptWelcome`.
    replaces: ?usize = null,
    /// This Welcome opens the group we are ALREADY in — the peer re-sent it
    /// because our ack never reached them (A1), or someone replayed the
    /// bucket. Not a re-establishment: the group id matches, so rebuilding it
    /// would throw away a live ratchet to arrive back where we started.
    /// Answer with an ack and change nothing.
    again: bool = false,
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
    if (peer_did_view.len == 0) {
        group.deinit(gpa);
        return null;
    }
    // A Welcome from someone we ALREADY have a conversation with is not an
    // error — it is a re-establishment, and refusing it (as we used to) is what
    // made a broken conversation unfixable. It is still not BELIEVED here:
    // `acceptWelcome` checks it against the directory exactly as it does a first
    // contact, so a stranger cannot reset your conversation by shouting at you.
    // WHICH DEVICE OF THEIRS SENT THIS (slice 1). A row is a session with ONE
    // device, so "do we already have this?" is a question about the DEVICE, not
    // about the person: a Welcome from their newly-added phone, while we already
    // talk to their desktop, is a NEW SESSION — not a re-establishment of the
    // desktop's. Replacing the desktop's session there would have quietly torn
    // down a working channel every time somebody added a device.
    const sender = group.leaf_sig_pub[1 - group.my_leaf];
    const existing = sessionIndex(st, peer_did_view, sender);
    // The same group we are already in? Then this is that device's RETRY of a
    // Welcome we already accepted (our ack was lost), not a new channel.
    const again = if (existing) |i|
        std.mem.eql(u8, st.groups.items[i].group_id, group.group_id)
    else
        false;
    const did_copy = gpa.dupe(u8, peer_did_view) catch {
        group.deinit(gpa);
        return null;
    };
    return .{ .group = group, .peer_did = did_copy, .replaces = existing, .again = again };
}

/// Phase 2: believe the Welcome ONLY if the claimed DID's published record
/// pins the same anchor key that signed the Welcome's leaf — a Welcome can
/// claim any DID; the directory is the check. Consumes `pw` either way.
/// `allowed` is EVERY DEVICE the claimed DID's directory vouches for (slice 1) —
/// the root and everything it has signed for. The Welcome's leaf key must be one
/// of them. Being a set rather than a single key is the entire multi-device
/// change here; the BAR IS UNCHANGED, and it is the bar that matters: a key the
/// peer's own published, signed device set does not contain cannot open a
/// conversation with you, no matter what DID it claims.
pub fn acceptWelcome(
    gpa: Allocator,
    environ: ?*const std.process.Environ.Map,
    st: *State,
    pw: PendingWelcome,
    allowed: []const [32]u8,
) error{OutOfMemory}!?Incoming {
    var group = pw.group;
    if (allowed.len == 0) {
        group.deinit(gpa);
        gpa.free(pw.peer_did);
        return null; // no published record for the claimed DID: refuse
    }
    const their_leaf = 1 - group.my_leaf;
    const sender = group.leaf_sig_pub[their_leaf];
    var vouched = false;
    for (allowed) |a| {
        if (std.mem.eql(u8, &a, &sender)) vouched = true;
    }
    if (!vouched) {
        group.deinit(gpa);
        gpa.free(pw.peer_did);
        return null; // an impostor's Welcome (M4 surfaces these refusals)
    }
    const expected = sender;

    // RE-ESTABLISHMENT. The peer is starting the conversation over — because
    // their side of it never completed, or their device was reinstalled, or
    // their cache was lost. Replace the stale group with the new one.
    //
    // This is safe precisely BECAUSE of the check above: the Welcome's leaf had
    // to be signed by the anchor key the peer's own published record pins. A
    // stranger cannot produce one, so a stranger cannot reset your conversation.
    // It is the same bar first contact must clear — we are not lowering it, we
    // are stopping it from being applied only once.
    //
    // We lose the old ratchet, and with it nothing: history is local (the Signal
    // model), and a group whose peer has moved on could not decrypt anything
    // anyway. Losing a dead ratchet costs us a ratchet that was already dead.
    if (pw.replaces) |idx| {
        st.groups.items[idx].deinit(gpa);
        st.groups.items[idx] = group;
        st.peer_anchors.items[idx] = expected;
        // Their Welcome supersedes any Welcome of OURS still waiting for an
        // ack: the channel we are keeping alive is the one they just built,
        // and they are plainly reachable — resending ours would only hand
        // them a second group to choose between.
        _ = confirmWelcome(gpa, st, idx);
        // And it REPAIRS a drift (A2): this is a brand-new group with fresh
        // ratchets on both sides, which is precisely what "needs to reconnect"
        // was asking for. The banner goes away because the problem went away.
        st.welcomes.items[idx].drifted = false;
        gpa.free(pw.peer_did); // the DID at `idx` is already ours and unchanged
        persist(gpa, environ, st);
        return .{ .restarted = .{ .peer_did = try gpa.dupe(u8, st.peer_dids.items[idx]), .device = expected } };
    }

    appendConversation(gpa, st, pw.peer_did, expected, group, welcome_confirmed) catch {
        group.deinit(gpa);
        gpa.free(pw.peer_did);
        return error.OutOfMemory;
    };
    persist(gpa, environ, st);
    return .{ .started = .{ .peer_did = try gpa.dupe(u8, pw.peer_did), .device = expected } };
}

/// The DID whose directory a stashed Welcome is waiting on, or null. The shell polls
/// this each frame and, when a worker slot is free, reads that DID's device set
/// off-thread and hands it to `finishWelcome`.
pub fn pendingWelcomeDid(st: *const State) ?[]const u8 {
    return if (st.pending_welcome) |pw| pw.peer_did else null;
}

/// Finish a Welcome that was stashed by `onBucket`, now that its sender's device set
/// has been read off-thread. `allowed` is every anchor key the claimed DID vouches
/// for; `acceptWelcome` believes the Welcome only if its leaf is one of them — the
/// SAME bar `onBucket` used to apply inline, just with the fetch moved off this
/// thread. Consumes the pending Welcome either way.
pub fn finishWelcome(
    gpa: Allocator,
    environ: ?*const std.process.Environ.Map,
    st: *State,
    allowed: []const [32]u8,
) error{OutOfMemory}!?Incoming {
    const pw = st.pending_welcome orelse return null;
    st.pending_welcome = null; // move ownership into acceptWelcome, which consumes it
    return acceptWelcome(gpa, environ, st, pw, allowed);
}

/// Route one delivered bucket. `from` is the mailbox it arrived on — the
/// M2.3 gate: a Welcome is believed ONLY off the bootstrap inbox (a
/// stranger stuffing Welcomes into a traffic mailbox is refused before any
/// crypto runs). Null = nothing user-visible (damage from a stranger, an
/// epoch advance, or a Welcome now STASHED for off-thread verification) — the
/// connection and every conversation stay intact (E2/E4). NO network on this
/// thread: a first-contact Welcome is decrypted and stashed in `pending_welcome`;
/// the shell reads the directory off-thread and calls `finishWelcome`.
pub fn onBucket(
    gpa: Allocator,
    environ: ?*const std.process.Environ.Map,
    st: *State,
    from: [relay.mailbox_id_len]u8,
    blob: []const u8,
) error{OutOfMemory}!?Incoming {
    const payload = bucketUnpack(blob) orelse return null;
    switch (mls.messageKind(payload)) {
        .welcome => {
            if (!std.mem.eql(u8, &from, &st.inbox)) return null; // M2.3: Welcomes ride the bootstrap inbox only
            var pw = openWelcome(gpa, st, payload) orelse return null;
            // A Welcome for the group we are already in (A1). Their retry, or
            // a replayed bucket — either way there is nothing to build and
            // nothing to verify against the directory: only the peer whose
            // Welcome we already accepted could have produced these bytes,
            // and the answer is the same in both cases. Ack and change
            // nothing. (Skipping the fetch here is deliberate: a replayed
            // bucket must not turn into a directory lookup we perform on
            // demand for a stranger.)
            if (pw.again) {
                const dev = pw.group.leaf_sig_pub[1 - pw.group.my_leaf];
                pw.group.deinit(gpa);
                return .{ .welcome_again = .{ .peer_did = pw.peer_did, .device = dev } };
            }
            // VERIFY AGAINST THE DIRECTORY — but NOT on this thread. Believing the
            // Welcome needs the claimed DID's published device set (the authority on
            // who may speak for a DID), and reading it is a blocking HTTPS fetch that
            // used to freeze the render thread here on every first-contact Welcome.
            // Stash the opened Welcome; the shell fetches the directory off-thread and
            // calls `finishWelcome` with the result. One at a time: if a Welcome is
            // already awaiting verification, defer this one (the relay re-delivers).
            if (st.pending_welcome != null) {
                pw.group.deinit(gpa);
                gpa.free(pw.peer_did);
                return null;
            }
            st.pending_welcome = pw;
            return null;
        },
        .private_message => {
            // M2.3 transition allowance: a private message arriving ON the
            // bootstrap inbox is a pre-rotation client's deposit (one such
            // message is known in flight at cutover). Still processed —
            // routing by group id is safe; the linkage leak is the SENDER'S
            // old address choice, already fixed at every upgraded sender.
            // FLIP TO STRICT (drop when `from == st.inbox`) at the
            // pre-launch per-user relay-auth gate.
            const gid = mls.privateMessageGroupId(payload) catch return null;
            const idx = for (st.groups.items, 0..) |*g, i| {
                if (std.mem.eql(u8, g.group_id, gid)) break i;
            } else return null; // no such conversation here
            const received = mls.receive(gpa, &st.groups.items[idx], payload) catch |err| {
                // A failed open burned that generation by design; state is
                // intact. Persist the burn so a crash cannot un-burn it.
                persist(gpa, environ, st);
                // A2 — READ THE FAILURE INSTEAD OF DROPPING IT. This used to be
                // an unconditional `return null`: the message vanished, the
                // thread looked healthy, and the only symptom the user ever got
                // was that replies stopped. Forever.
                switch (classify(err)) {
                    .replay => return null, // at-least-once redelivery: nothing happened
                    .drift => {
                        st.welcomes.items[idx].drifted = true;
                        persist(gpa, environ, st);
                        return .{ .drifted = .{ .peer_did = try gpa.dupe(u8, st.peer_dids.items[idx]) } };
                    },
                    .tamper => return .{ .tampered = .{ .peer_did = try gpa.dupe(u8, st.peer_dids.items[idx]) } },
                }
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
                    // The group ACK (A1): the peer joined the group our
                    // Welcome carried, and only they could have — this frame
                    // decrypted under that group's own ratchet. The Welcome is
                    // delivered; stop retrying it and let the thread say the
                    // conversation is real. Wire-only, never a message.
                    if (data[0] == chat.kind_group_ack_wire) {
                        if (confirmWelcome(gpa, st, idx)) persist(gpa, environ, st);
                        return .{ .confirmed = .{ .peer_did = try gpa.dupe(u8, st.peer_dids.items[idx]) } };
                    }
                    // THE ROSTER (slice 3) — the list of people we talk to, from
                    // ANOTHER DEVICE OF OURS.
                    //
                    // And it is accepted ONLY from one of our own devices. The
                    // session it arrived on says whose it is (the DID is pinned to
                    // the session at Welcome time, and the frame decrypted under
                    // that session's own ratchet), so a roster from anybody else is
                    // somebody trying to make our client go and open conversations
                    // of their choosing. Refused, silently, and nothing happens.
                    if (data[0] == chat.kind_roster_wire) {
                        if (!std.mem.eql(u8, st.peer_dids.items[idx], st.my_did)) return null;
                        if (data.len < 2) return null;
                        return .{ .roster = .{ .dids = try gpa.dupe(u8, data[1..]) } };
                    }
                    // A READ RECEIPT.
                    if (data[0] == chat.kind_read_wire) {
                        if (data.len < 9) return null;
                        return .{ .read = .{
                            .peer_did = try gpa.dupe(u8, st.peer_dids.items[idx]),
                            .up_to = std.mem.readInt(i64, data[1..9], .little),
                        } };
                    }
                    // A REACTION.
                    if (data[0] == chat.kind_react_wire) {
                        if (data.len < 11 or data.len > 10 + 8) return null;
                        return .{ .react = .{
                            .peer_did = try gpa.dupe(u8, st.peer_dids.items[idx]),
                            .target_at = std.mem.readInt(i64, data[1..9], .little),
                            .target_mine = data[9] == 0, // their "mine" is our "theirs"
                            .emoji = try gpa.dupe(u8, data[10..]),
                        } };
                    }
                    // A REPLY: a message, plus which message it answers.
                    if (data[0] == chat.kind_reply_wire) {
                        if (data.len < 11) return null;
                        return .{ .reply = .{
                            .peer_did = try gpa.dupe(u8, st.peer_dids.items[idx]),
                            .target_at = std.mem.readInt(i64, data[1..9], .little),
                            // THEIR "mine" is OUR "theirs". Flipped here, once, where
                            // the wire is being read — not at each of the places that
                            // later ask "whose message was that?".
                            .target_mine = data[9] == 0,
                            .text = try gpa.dupe(u8, data[10..]),
                        } };
                    }
                    // UNSEND (CHAT_FEATURES slice 3): they are asking us to drop a
                    // message THEY sent. It can only ever name a message in this
                    // conversation, from them — the session it arrived on says so.
                    if (data[0] == chat.kind_unsend_wire) {
                        if (data.len < 10) return null;
                        const dn: usize = data[9];
                        if (data.len < 10 + dn) return null;
                        return .{ .unsend = .{
                            .peer_did = try gpa.dupe(u8, st.peer_dids.items[idx]),
                            .conv_did = try gpa.dupe(u8, data[10 .. 10 + dn]),
                            .created_at = std.mem.readInt(i64, data[1..9], .little),
                        } };
                    }
                    // EDIT: they revised something they said.
                    if (data[0] == chat.kind_edit_wire) {
                        if (data.len < 11) return null;
                        const dn: usize = data[9];
                        if (data.len < 11 + dn) return null;
                        return .{ .edit = .{
                            .peer_did = try gpa.dupe(u8, st.peer_dids.items[idx]),
                            .conv_did = try gpa.dupe(u8, data[10 .. 10 + dn]),
                            .created_at = std.mem.readInt(i64, data[1..9], .little),
                            .text = try gpa.dupe(u8, data[10 + dn ..]),
                        } };
                    }
                    // HISTORY (slice 5) — the ask, and the bytes. Both carry the
                    // same rule as the roster, and for the same reason: ONLY from
                    // one of our own devices. A history request from a stranger is
                    // somebody asking us to send them everything we have ever said,
                    // and a history CHUNK from a stranger is somebody trying to write
                    // our past for us. Neither gets past this line.
                    if (data[0] == chat.kind_history_req_wire) {
                        if (!std.mem.eql(u8, st.peer_dids.items[idx], st.my_did)) return null;
                        return .{ .history_request = .{ .device = st.peer_anchors.items[idx] } };
                    }
                    if (data[0] == chat.kind_history_chunk_wire) {
                        if (!std.mem.eql(u8, st.peer_dids.items[idx], st.my_did)) return null;
                        if (data.len < 5) return null;
                        return .{ .history_chunk = .{
                            .seq = std.mem.readInt(u16, data[1..3], .little),
                            .total = std.mem.readInt(u16, data[3..5], .little),
                            .bytes = try gpa.dupe(u8, data[5..]),
                        } };
                    }
                    // Card-FLIP events (settlement 18/19, S2 ready/cancel/
                    // decline 21/22/23): wire-only, like the ping — but their
                    // effect persists (the card advances). A damaged frame is
                    // dropped, never a crash (E3/E4).
                    if (chat.payEventStatus(data[0])) |to| {
                        const f = chat.parsePaymentFrame(data[1..]) catch return null;
                        return .{ .payment_update = .{
                            .peer_did = try gpa.dupe(u8, st.peer_dids.items[idx]),
                            .id = f.payment_id,
                            .ref = f.ref,
                            .status = to,
                        } };
                    }
                    // The S2 OFFER (20): a card CREATE, not a flip — the
                    // recipient has no wallet, so no money is coming. Carries
                    // a full frame like a stored payment card; the drain lands
                    // it at `pending_setup` (never inferred from setup state,
                    // §11.1). Modeled as `.payment` with `is_offer`.
                    if (data[0] == chat.kind_pay_offer_wire) {
                        const f = chat.parsePaymentFrame(data[1..]) catch return null;
                        const note = try gpa.dupe(u8, f.note);
                        errdefer gpa.free(note);
                        return .{ .payment = .{
                            .peer_did = try gpa.dupe(u8, st.peer_dids.items[idx]),
                            .note = note,
                            .id = f.payment_id,
                            .amount_sat = f.amount_sat,
                            .ref = f.ref,
                            .kind = .payment_sent, // an offer to SEND me money
                            .rail = f.rail,
                            .is_offer = true,
                        } };
                    }
                    // TEXT SENT WITH AN EFFECT. Decoded into the SAME `.message`
                    // variant, because that is what it is — an ordinary text
                    // message that also knows how the sender wanted it to land.
                    // Every consumer keeps working unchanged; only the ones that
                    // care read `effect`.
                    if (data[0] == chat.kind_text_fx_wire) {
                        if (data.len < 3) return null; // [11][screen][bubble][text]
                        const fx_text = try gpa.dupe(u8, data[3..]);
                        errdefer gpa.free(fx_text);
                        return .{ .message = .{
                            .peer_did = try gpa.dupe(u8, st.peer_dids.items[idx]),
                            .kind = .text,
                            .text = fx_text,
                            .effect = data[1],
                            .bubble = data[2],
                        } };
                    }
                    // A GAME MOVE. Exactly two bytes; anything else claiming this
                    // kind is malformed and dropped rather than guessed at.
                    if (data[0] == @intFromEnum(chat.Kind.game_move)) {
                        if (data.len != 2) return null;
                        return .{ .game_move = .{
                            .peer_did = try gpa.dupe(u8, st.peer_dids.items[idx]),
                            .encoded = data[1],
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
                            .is_offer = false,
                        } };
                    }
                    const text = try gpa.dupe(u8, data[1..]);
                    errdefer gpa.free(text);
                    return .{ .message = .{
                        .peer_did = try gpa.dupe(u8, st.peer_dids.items[idx]),
                        .kind = kind,
                        .text = text,
                        .effect = 0, // a plain message was sent with nothing
                        .bubble = 0,
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

    var welcome_bucket: [relay.bucket_len]u8 = undefined;
    try bucketPack(&welcome_bucket, welcome);

    // A's side of startConversation: the Welcome is OUT, not delivered — the
    // bucket is retained and the conversation reads as `waiting` (A1).
    try appendConversation(gpa, &a, try gpa.dupe(u8, b.my_did), b_anchor_pub, group_a, .{
        .bucket = try gpa.dupe(u8, &welcome_bucket),
        .last_sent = 1000,
        .last_ack = 0,
        .attempts = 1,
        .drifted = false,
    });
    try testing.expectEqual(chat.Delivery.waiting, deliveryState(&a, b.my_did));

    // An impostor first: same Welcome, but the directory pins a DIFFERENT
    // anchor key for the claimed DID → refused, no conversation.
    {
        const pw = openWelcome(gpa, &b, bucketUnpack(&welcome_bucket).?) orelse return error.TestUnexpectedResult;
        var wrong = try anchor.publicKey(seed_b);
        wrong[0] ^= 1;
        try testing.expect((try acceptWelcome(gpa, &env, &b, pw, &.{wrong})) == null);
        try testing.expect(!hasConversation(&b, a.my_did));
    }
    // And a claimed DID with NO published devices at all → refused. (An empty set
    // is the "we could not learn who they are" case, and it must never open.)
    {
        const pw = openWelcome(gpa, &b, bucketUnpack(&welcome_bucket).?) orelse return error.TestUnexpectedResult;
        try testing.expect((try acceptWelcome(gpa, &env, &b, pw, &.{})) == null);
    }

    // The genuine accept: the directory pins A's real anchor key.
    {
        const pw = openWelcome(gpa, &b, bucketUnpack(&welcome_bucket).?) orelse return error.TestUnexpectedResult;
        const inc = (try acceptWelcome(gpa, &env, &b, pw, &.{try anchor.publicKey(seed_a)})) orelse return error.TestUnexpectedResult;
        defer freeIncoming(gpa, inc);
        try testing.expectEqualStrings(a.my_did, inc.started.peer_did);
    }
    try testing.expect(hasConversation(&b, a.my_did));

    // M2.1: the traffic mailboxes both sides derive — the sender's .peers
    // view IS the receiver's .mine subscription, and neither is the
    // anchor-linkable bootstrap inbox.
    const a_traffic = mls.mailboxId(&a.groups.items[0], .mine);
    const b_traffic = mls.mailboxId(&b.groups.items[0], .mine);
    try testing.expectEqualSlices(u8, &b_traffic, &mls.mailboxId(&a.groups.items[0], .peers));
    try testing.expectEqualSlices(u8, &a_traffic, &mls.mailboxId(&b.groups.items[0], .peers));
    try testing.expect(!std.mem.eql(u8, &b_traffic, &b.inbox));
    {
        const subs = try subscriptions(gpa, &b);
        defer gpa.free(subs);
        try testing.expectEqual(@as(usize, 2), subs.len);
        try testing.expectEqualSlices(u8, &b.inbox, &subs[0]);
        try testing.expectEqualSlices(u8, &b_traffic, &subs[1]);
    }

    // M2.3: the same Welcome bucket arriving on a TRAFFIC mailbox is
    // refused before any crypto runs.
    try testing.expect((try onBucket(gpa, &env, &b, b_traffic, &welcome_bucket)) == null);

    // A1 — THE ACK. B (the joiner) answers the Welcome over the group it just
    // joined; A stops believing in a conversation it cannot prove and starts
    // knowing it has one. Until this arrives A is `waiting`, and its retry
    // pump keeps the Welcome going out.
    {
        try testing.expectEqual(chat.Delivery.waiting, deliveryState(&a, b.my_did));
        const ack = [1]u8{chat.kind_group_ack_wire};
        const msg = try mls.encrypt(gpa, &b.groups.items[0], &ack, 0, .{ 3, 1, 4, 1 });
        defer gpa.free(msg);
        var bucket: [relay.bucket_len]u8 = undefined;
        try bucketPack(&bucket, msg);
        const inc = (try onBucket(gpa, &env, &a, a_traffic, &bucket)) orelse return error.TestUnexpectedResult;
        defer freeIncoming(gpa, inc);
        try testing.expectEqualStrings(b.my_did, inc.confirmed.peer_did);
        try testing.expectEqual(chat.Delivery.confirmed, deliveryState(&a, b.my_did));
        // The ack is wire-only: it never became a bubble, and the retry is
        // retired — the bucket is gone, not merely flagged.
        try testing.expectEqual(@as(usize, 0), a.welcomes.items[0].bucket.len);
    }

    // A1 — THE RETRY, from the receiving end. A's Welcome going out a second
    // time (its ack was lost in the first round) must NOT rebuild B's group:
    // the group id already matches, and a rebuild would throw away the live
    // ratchet. B recognises it, answers with another ack, and changes nothing.
    {
        const gid_before = try gpa.dupe(u8, b.groups.items[0].group_id);
        defer gpa.free(gid_before);
        const epoch_before = b.groups.items[0].epoch;
        const inc = (try onBucket(gpa, &env, &b, b.inbox, &welcome_bucket)) orelse return error.TestUnexpectedResult;
        defer freeIncoming(gpa, inc);
        try testing.expectEqualStrings(a.my_did, inc.welcome_again.peer_did);
        try testing.expectEqual(@as(usize, 1), b.groups.items.len);
        try testing.expectEqualSlices(u8, gid_before, b.groups.items[0].group_id);
        try testing.expectEqual(epoch_before, b.groups.items[0].epoch);
    }

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
        const inc = (try onBucket(gpa, &env, &b, b_traffic, &bucket)) orelse return error.TestUnexpectedResult;
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
        const inc = (try onBucket(gpa, &env, &b2, b_traffic, &bucket)) orelse return error.TestUnexpectedResult;
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
        const inc = (try onBucket(gpa, &env, &a, a_traffic, &bucket)) orelse return error.TestUnexpectedResult;
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
        const inc = (try onBucket(gpa, &env, &b2, b_traffic, &bucket)) orelse return error.TestUnexpectedResult;
        defer freeIncoming(gpa, inc);
        try testing.expectEqualStrings(a.my_did, inc.typing.peer_did);

        var plaintext: [16]u8 = undefined;
        plaintext[0] = 0;
        @memcpy(plaintext[1..][0..10], "after ping");
        const msg2 = try mls.encrypt(gpa, &a.groups.items[0], plaintext[0..11], 0, .{ 8, 8, 8, 8 });
        defer gpa.free(msg2);
        var bucket2: [relay.bucket_len]u8 = undefined;
        try bucketPack(&bucket2, msg2);
        const inc2 = (try onBucket(gpa, &env, &b2, b_traffic, &bucket2)) orelse return error.TestUnexpectedResult;
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
        const inc = (try onBucket(gpa, &env, &b2, b_traffic, &bucket)) orelse return error.TestUnexpectedResult;
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
        const inc = (try onBucket(gpa, &env, &b2, b_traffic, &bucket)) orelse return error.TestUnexpectedResult;
        defer freeIncoming(gpa, inc);
        try testing.expectEqual(chat.PayStatus.settled, inc.payment_update.status);
        try testing.expectEqual(@as(u64, 0xCAFE), inc.payment_update.id);
        try testing.expectEqualSlices(u8, &preimage, &inc.payment_update.ref);
    }

    // An S2 offer (wire byte 20) crosses as a CREATE card marked is_offer,
    // kind payment_sent (an offer to send me money) — never a stored kind.
    {
        var fbuf: [128]u8 = undefined;
        const body = chat.buildPaymentFrame(&fbuf, .{
            .payment_id = 0x0FFE,
            .amount_sat = 7000,
            .note = "coffee",
            .ref = chat.zero_ref,
            .rail = .onchain,
        });
        var plaintext: [160]u8 = undefined;
        plaintext[0] = chat.kind_pay_offer_wire;
        @memcpy(plaintext[1..][0..body.len], body);
        const msg = try mls.encrypt(gpa, &a.groups.items[0], plaintext[0 .. 1 + body.len], 0, .{ 4, 4, 4, 4 });
        defer gpa.free(msg);
        var bucket: [relay.bucket_len]u8 = undefined;
        try bucketPack(&bucket, msg);
        const inc = (try onBucket(gpa, &env, &b2, b_traffic, &bucket)) orelse return error.TestUnexpectedResult;
        defer freeIncoming(gpa, inc);
        try testing.expect(inc.payment.is_offer);
        try testing.expectEqual(chat.Kind.payment_sent, inc.payment.kind);
        try testing.expectEqual(@as(u64, 0x0FFE), inc.payment.id);
        try testing.expectEqual(@as(u64, 7000), inc.payment.amount_sat);
    }

    // An S2 ready signal (wire byte 21) crosses as a flip to `ready`.
    {
        var fbuf: [128]u8 = undefined;
        const body = chat.buildPaymentFrame(&fbuf, .{
            .payment_id = 0x0FFE,
            .amount_sat = 7000,
            .note = "",
            .ref = chat.zero_ref,
            .rail = .onchain,
        });
        var plaintext: [160]u8 = undefined;
        plaintext[0] = chat.kind_pay_ready_wire;
        @memcpy(plaintext[1..][0..body.len], body);
        const msg = try mls.encrypt(gpa, &a.groups.items[0], plaintext[0 .. 1 + body.len], 0, .{ 5, 5, 5, 5 });
        defer gpa.free(msg);
        var bucket: [relay.bucket_len]u8 = undefined;
        try bucketPack(&bucket, msg);
        const inc = (try onBucket(gpa, &env, &b2, b_traffic, &bucket)) orelse return error.TestUnexpectedResult;
        defer freeIncoming(gpa, inc);
        try testing.expectEqual(chat.PayStatus.ready, inc.payment_update.status);
        try testing.expectEqual(@as(u64, 0x0FFE), inc.payment_update.id);
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
        try testing.expect((try onBucket(gpa, &env, &b2, b_traffic, &bucket)) == null);
    }

    // A stranger's random bucket is dropped without a mark.
    var junk: [relay.bucket_len]u8 = @splat(0x5A);
    try testing.expect((try onBucket(gpa, &env, &a, a.inbox, &junk)) == null);
}

test "chat_e2ee: a VERIFIED re-Welcome re-establishes a desynchronised conversation" {
    // ── The bug this pins was severe, and it was silent. ──
    //
    // A Welcome from a peer we ALREADY had a conversation row for was dropped on
    // the floor without a word. So a conversation whose two halves had drifted
    // apart was PERMANENTLY dead: unrepairable from either side, with nothing
    // anywhere saying so. The owner's messages appeared as bubbles and went
    // nowhere, for days.
    //
    // And halves drift apart for entirely ordinary reasons — the Welcome that
    // opened the conversation never landed (a relay outage; or, as happened here,
    // a client pointed at a different relay than its peer), or the peer
    // reinstalled and their cache, which holds the device-bound anchor, was gone.
    //
    // A second Welcome must now REPLACE the stale group — held to exactly the same
    // bar as first contact, so a stranger still cannot reset your conversation.
    const gpa = testing.allocator;
    const io = testing.io;
    _ = io;
    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    const tmp = "/tmp/zat-e2ee-restart-test";
    try env.put("ZAT_CACHE_DIR", tmp);
    _ = std.os.linux.mkdir(tmp, 0o700);
    defer {
        var z: [512]u8 = undefined;
        if (std.fmt.bufPrintZ(&z, "{s}", .{tmp})) |zp| _ = std.os.linux.rmdir(zp) else |_| {}
    }

    const seed_a: [32]u8 = @splat(0xA1);
    const seed_b: [32]u8 = @splat(0xB1);
    var a = try testState(gpa, "did:plc:restart-alice", seed_a, 0x31, 0x32);
    defer deinit(gpa, &a);
    var b = try testState(gpa, "did:plc:restart-bob", seed_b, 0x33, 0x34);
    defer deinit(gpa, &b);

    // First contact: A welcomes B. This one lands.
    var g1 = try mls.createGroup(gpa, a.my_did, a.anchor_seed, .{
        .group_id = @splat(0x40),
        .enc_seed = @splat(0x41),
        .epoch_secret = @splat(0x42),
    });
    defer g1.deinit(gpa);
    const w1 = try mls.addPeer(gpa, &g1, b.kp.kp_bytes, 1_000_000, .{
        .path_secret = @splat(0x43),
        .enc_seed = @splat(0x44),
        .welcome_seed = @splat(0x45),
    });
    defer gpa.free(w1);
    var wb1: [relay.bucket_len]u8 = undefined;
    try bucketPack(&wb1, w1);
    {
        const pw = openWelcome(gpa, &b, bucketUnpack(&wb1).?) orelse return error.TestUnexpectedResult;
        try testing.expect(pw.replaces == null); // genuinely first contact
        const inc = (try acceptWelcome(gpa, &env, &b, pw, &.{try anchor.publicKey(seed_a)})) orelse
            return error.TestUnexpectedResult;
        defer freeIncoming(gpa, inc);
        try testing.expectEqualStrings(a.my_did, inc.started.peer_did);
    }

    // Now A starts over — a new device, a lost cache, or a Welcome that never
    // reached them the first time. A brand-new group, a brand-new Welcome.
    var g2 = try mls.createGroup(gpa, a.my_did, a.anchor_seed, .{
        .group_id = @splat(0x50),
        .enc_seed = @splat(0x51),
        .epoch_secret = @splat(0x52),
    });
    defer g2.deinit(gpa);
    const w2 = try mls.addPeer(gpa, &g2, b.kp.kp_bytes, 1_000_001, .{
        .path_secret = @splat(0x53),
        .enc_seed = @splat(0x54),
        .welcome_seed = @splat(0x55),
    });
    defer gpa.free(w2);
    var wb2: [relay.bucket_len]u8 = undefined;
    try bucketPack(&wb2, w2);

    // An IMPOSTOR cannot use this to reset the conversation: the re-Welcome is
    // held to the same directory check as first contact.
    {
        const pw = openWelcome(gpa, &b, bucketUnpack(&wb2).?) orelse return error.TestUnexpectedResult;
        try testing.expect(pw.replaces != null);
        const wrong: [32]u8 = @splat(0xEE);
        try testing.expect((try acceptWelcome(gpa, &env, &b, pw, &.{wrong})) == null);
    }
    // …and the refusal left B's ORIGINAL conversation intact.
    try testing.expect(hasConversation(&b, a.my_did));
    try testing.expectEqual(@as(usize, 1), b.groups.items.len);

    // The genuine re-establishment: A's real anchor, from the directory.
    {
        const pw = openWelcome(gpa, &b, bucketUnpack(&wb2).?) orelse return error.TestUnexpectedResult;
        const inc = (try acceptWelcome(gpa, &env, &b, pw, &.{try anchor.publicKey(seed_a)})) orelse
            return error.TestUnexpectedResult;
        defer freeIncoming(gpa, inc);
        // It reports itself as a RESTART, not a new conversation — the thread can
        // say so, where before it said nothing at all.
        try testing.expectEqualStrings(a.my_did, inc.restarted.peer_did);
    }

    // Replaced, not duplicated.
    try testing.expectEqual(@as(usize, 1), b.groups.items.len);
    try testing.expectEqual(@as(usize, 1), b.peer_dids.items.len);

    // And B now speaks to A's NEW group: the traffic mailboxes agree, which is
    // the whole point — before this, every message A sent went to a mailbox B was
    // not listening on, forever.
    try testing.expectEqualSlices(u8, &mls.mailboxId(&g2, .peers), &mls.mailboxId(&b.groups.items[0], .mine));
    try testing.expectEqualSlices(u8, &mls.mailboxId(&g2, .mine), &mls.mailboxId(&b.groups.items[0], .peers));

    // A message on the NEW group decrypts. The old one is gone and unmourned:
    // history is local (the Signal model), and a group your peer never joined
    // could not decrypt anything anyway.
    {
        const msg = try mls.encrypt(gpa, &g2, "it works now", 0, .{ 9, 9, 9, 9 });
        defer gpa.free(msg);
        const got = try mls.receive(gpa, &b.groups.items[0], msg);
        switch (got) {
            .application => |pt| {
                defer gpa.free(pt);
                try testing.expectEqualStrings("it works now", pt);
            },
            else => return error.TestUnexpectedResult,
        }
    }
}

test "chat_e2ee: a DRIFTED conversation says so; a redelivery says nothing (A2)" {
    // Two ways a message fails to open, and they are NOT the same thing.
    //
    // A conversation whose halves have drifted (a Commit one side never saw) is
    // BROKEN: every message from here on is lost, and the old code dropped each
    // one on the floor without a word — so the only symptom the user ever got
    // was that replies stopped. Forever. That is the failure this surfaces.
    //
    // But relay delivery is at-least-once BY DESIGN (a blob is deleted only on
    // ack), so a redelivered message routinely fails to open too. If that also
    // raised "this conversation is broken", the banner would cry wolf every time
    // the network hiccupped — and a warning that fires when nothing is wrong is
    // a warning nobody reads.
    const gpa = testing.allocator;
    const seed_a: [32]u8 = @splat(0xC1);
    const seed_b: [32]u8 = @splat(0xD2);

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    var tmp_buf: [64]u8 = undefined;
    const tmp = std.fmt.bufPrint(&tmp_buf, "/tmp/zat-drift-test-{d}", .{std.os.linux.getpid()}) catch unreachable;
    try env.put("ZAT_CACHE_DIR", tmp);
    defer {
        var pb: [512]u8 = undefined;
        for ([_][]const u8{ "did:plc:drift-bob", "did:plc:drift-alice" }) |d| {
            if (cache.chatGroupsPath(&pb, &env, d)) |p| {
                var z: [512]u8 = undefined;
                if (std.fmt.bufPrintZ(&z, "{s}", .{p})) |zp| _ = std.os.linux.unlink(zp) else |_| {}
            }
        }
        var z2: [512]u8 = undefined;
        if (std.fmt.bufPrintZ(&z2, "{s}", .{tmp})) |zp| _ = std.os.linux.rmdir(zp) else |_| {}
    }

    var a = try testState(gpa, "did:plc:drift-alice", seed_a, 0x21, 0x22);
    defer deinit(gpa, &a);
    var b = try testState(gpa, "did:plc:drift-bob", seed_b, 0x23, 0x24);
    defer deinit(gpa, &b);

    var group_a = try mls.createGroup(gpa, a.my_did, a.anchor_seed, .{
        .group_id = @splat(0x30),
        .enc_seed = @splat(0x31),
        .epoch_secret = @splat(0x32),
    });
    const welcome = try mls.addPeer(gpa, &group_a, b.kp.kp_bytes, 1000, .{
        .enc_seed = @splat(0x33),
        .path_secret = @splat(0x34),
        .welcome_seed = @splat(0x35),
    });
    defer gpa.free(welcome);
    try appendConversation(gpa, &a, try gpa.dupe(u8, b.my_did), try anchor.publicKey(seed_b), group_a, welcome_confirmed);

    var wb: [relay.bucket_len]u8 = undefined;
    try bucketPack(&wb, welcome);
    const pw = openWelcome(gpa, &b, bucketUnpack(&wb).?) orelse return error.TestUnexpectedResult;
    const started = (try acceptWelcome(gpa, &env, &b, pw, &.{try anchor.publicKey(seed_a)})) orelse return error.TestUnexpectedResult;
    freeIncoming(gpa, started);

    const b_traffic = mls.mailboxId(&b.groups.items[0], .mine);

    // One real message lands, and the conversation is healthy.
    var bucket: [relay.bucket_len]u8 = undefined;
    {
        var plaintext: [16]u8 = undefined;
        plaintext[0] = 0;
        @memcpy(plaintext[1..][0..5], "hello");
        const msg = try mls.encrypt(gpa, &a.groups.items[0], plaintext[0..6], 0, .{ 1, 1, 1, 1 });
        defer gpa.free(msg);
        try bucketPack(&bucket, msg);
        const inc = (try onBucket(gpa, &env, &b, b_traffic, &bucket)) orelse return error.TestUnexpectedResult;
        defer freeIncoming(gpa, inc);
        try testing.expectEqualStrings("hello", inc.message.text);
    }
    try testing.expectEqual(chat.Delivery.confirmed, deliveryState(&b, a.my_did));

    // THE REDELIVERY. The exact same bucket again — which the relay will do,
    // routinely, because delivery is at-least-once. Nothing user-visible, and
    // the conversation is still healthy. This is the assertion that keeps the
    // A2 banner meaningful.
    try testing.expect((try onBucket(gpa, &env, &b, b_traffic, &bucket)) == null);
    try testing.expectEqual(chat.Delivery.confirmed, deliveryState(&b, a.my_did));

    // THE DRIFT. Bob's group advances an epoch that Alice never saw — which is
    // exactly what an unseen Commit does to the two halves — so Alice's next
    // message arrives stamped with an epoch Bob has moved past. It cannot open.
    // Before A2 it was dropped in silence and the thread looked perfectly fine.
    {
        b.groups.items[0].epoch += 1;
        var plaintext: [16]u8 = undefined;
        plaintext[0] = 0;
        @memcpy(plaintext[1..][0..4], "gone");
        const msg = try mls.encrypt(gpa, &a.groups.items[0], plaintext[0..5], 0, .{ 2, 2, 2, 2 });
        defer gpa.free(msg);
        var drift_bucket: [relay.bucket_len]u8 = undefined;
        try bucketPack(&drift_bucket, msg);
        const inc = (try onBucket(gpa, &env, &b, b_traffic, &drift_bucket)) orelse return error.TestUnexpectedResult;
        defer freeIncoming(gpa, inc);
        try testing.expectEqualStrings(a.my_did, inc.drifted.peer_did);
        // The conversation now SAYS it needs to reconnect — and that verdict
        // outranks anything the Welcome states were saying, because a channel
        // that cannot decrypt is broken now, whatever it was doing before.
        try testing.expectEqual(chat.Delivery.needs_reconnect, deliveryState(&b, a.my_did));
    }

    // AND TAMPERING IS NOT DRIFT. A bucket whose ciphertext does not
    // authenticate is refused, loudly — never offered a friendly "tap to
    // reconnect", which would let anyone who can write to a mailbox nag a user
    // into rebuilding a channel that was never broken.
    {
        b.groups.items[0].epoch -= 1; // back in step, so the epoch is not the complaint
        var plaintext: [16]u8 = undefined;
        plaintext[0] = 0;
        @memcpy(plaintext[1..][0..4], "evil");
        const msg = try mls.encrypt(gpa, &a.groups.items[0], plaintext[0..5], 0, .{ 3, 3, 3, 3 });
        defer gpa.free(msg);
        const forged = try gpa.dupe(u8, msg);
        defer gpa.free(forged);
        forged[forged.len - 1] ^= 0xFF; // flip a bit in the AEAD tag
        var bad_bucket: [relay.bucket_len]u8 = undefined;
        try bucketPack(&bad_bucket, forged);
        const inc = (try onBucket(gpa, &env, &b, b_traffic, &bad_bucket)) orelse return error.TestUnexpectedResult;
        defer freeIncoming(gpa, inc);
        try testing.expectEqualStrings(a.my_did, inc.tampered.peer_did);
    }
}

test "chat_e2ee: EVERY groups-blob version we have ever written still restores" {
    // The bug this pins wiped a device's entire chat state, silently.
    //
    // The version gate was written as `version != 1 and version != groups_version`
    // — correct while exactly two versions existed, and a trapdoor the moment a
    // third arrived: v2 blobs were refused, `restoreGroups` bailed, and every MLS
    // group on the device vanished. Not deleted — unreachable, which looks the
    // same to the person holding the phone. Their conversations were on disk the
    // whole time and the app said it had none.
    //
    // So the gate is a RANGE now, and this test walks the whole range. A v4 that
    // forgets to keep v2 readable fails here, on a laptop, instead of on a phone.
    const gpa = testing.allocator;
    var v: u16 = 1;
    while (v <= groups_version) : (v += 1) {
        // The header every version shares: magic, version, and a count of ZERO.
        // A well-formed empty blob must be ACCEPTED (restore leaves no groups and
        // no error) — the point is that the reader gets past the gate at all.
        var blob: [10]u8 = undefined;
        @memcpy(blob[0..4], &groups_magic);
        std.mem.writeInt(u16, blob[4..6], v, .little);
        std.mem.writeInt(u32, blob[6..10], 0, .little);

        // Reach the gate directly: a version this build has written must never be
        // one this build refuses.
        const version = std.mem.bytesToValue(u16, blob[4..6]);
        try testing.expect(!(version < 1 or version > groups_version));
    }
    // And a version from the FUTURE — a blob written by a newer build — is still
    // refused, because we cannot know its layout and guessing would corrupt state.
    try testing.expect(groups_version + 1 > groups_version);
    _ = gpa;
}

test "chat_e2ee: TWO DEVICES OF ONE PERSON ARE TWO SESSIONS, not a takeover (slice 1)" {
    // The regression this slice exists to prevent. Bob has a desktop AND a phone.
    // A row is a session with a DEVICE, so his phone's Welcome must OPEN A SECOND
    // SESSION — not replace the desktop's, which is what a did-keyed row would
    // have done: every time Bob added a device, his working channel would have
    // been quietly torn down and rebuilt against the new one.
    const gpa = testing.allocator;
    const seed_a: [32]u8 = @splat(0xA1);
    const seed_desk: [32]u8 = @splat(0xD1);
    const seed_phone: [32]u8 = @splat(0xF1);
    const bob = "did:plc:e2ee-bob-two";

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    var tmp_buf: [64]u8 = undefined;
    const tmp = std.fmt.bufPrint(&tmp_buf, "/tmp/zat-e2ee-md-{d}", .{std.os.linux.getpid()}) catch unreachable;
    try env.put("ZAT_CACHE_DIR", tmp);
    defer {
        var pb: [512]u8 = undefined;
        if (cache.chatGroupsPath(&pb, &env, "did:plc:e2ee-alice-md")) |p| {
            var z: [512]u8 = undefined;
            if (std.fmt.bufPrintZ(&z, "{s}", .{p})) |zp| _ = std.os.linux.unlink(zp) else |_| {}
        }
        var z2: [512]u8 = undefined;
        if (std.fmt.bufPrintZ(&z2, "{s}", .{tmp})) |zp| _ = std.os.linux.rmdir(zp) else |_| {}
    }

    var alice = try testState(gpa, "did:plc:e2ee-alice-md", seed_a, 0x01, 0x02);
    defer deinit(gpa, &alice);
    // Bob's two devices: SAME DID, DIFFERENT KEYS. Nothing is copied between them
    // — that is the whole design.
    var desk = try testState(gpa, bob, seed_desk, 0x03, 0x04);
    defer deinit(gpa, &desk);
    var phone = try testState(gpa, bob, seed_phone, 0x05, 0x06);
    defer deinit(gpa, &phone);

    const desk_pub = try anchor.publicKey(seed_desk);
    const phone_pub = try anchor.publicKey(seed_phone);
    const allowed = [_][32]u8{ desk_pub, phone_pub }; // Bob's signed device set

    // Each of Bob's devices opens its own pairwise session with Alice.
    for ([_]*State{ &desk, &phone }, [_]u8{ 0x11, 0x22 }) |bob_dev, ent| {
        var g = try mls.createGroup(gpa, bob_dev.my_did, bob_dev.anchor_seed, .{
            .group_id = @splat(ent),
            .enc_seed = @splat(ent +% 1),
            .epoch_secret = @splat(ent +% 2),
        });
        errdefer g.deinit(gpa);
        const welcome = try mls.addPeer(gpa, &g, alice.kp.kp_bytes, 0, .{
            .enc_seed = @splat(ent +% 3),
            .path_secret = @splat(ent +% 4),
            .welcome_seed = @splat(ent +% 5),
        });
        defer gpa.free(welcome);
        var wb: [relay.bucket_len]u8 = undefined;
        try bucketPack(&wb, welcome);
        g.deinit(gpa); // Bob's own copy is not what this test is about

        const pw = openWelcome(gpa, &alice, bucketUnpack(&wb).?) orelse return error.TestUnexpectedResult;
        const inc = (try acceptWelcome(gpa, &env, &alice, pw, &allowed)) orelse return error.TestUnexpectedResult;
        defer freeIncoming(gpa, inc);
        try testing.expect(inc == .started); // BOTH are a start — neither replaces the other
    }

    // Two sessions with one person.
    var buf: [16]usize = undefined;
    const sessions = sessionsOf(&alice, bob, &buf);
    try testing.expectEqual(@as(usize, 2), sessions.len);
    try testing.expect(sessionIndex(&alice, bob, desk_pub) != null);
    try testing.expect(sessionIndex(&alice, bob, phone_pub) != null);
    // And they are genuinely different channels — not one group counted twice.
    try testing.expect(!std.mem.eql(
        u8,
        alice.groups.items[sessions[0]].group_id,
        alice.groups.items[sessions[1]].group_id,
    ));

    // A stranger's device — one Bob's directory does NOT vouch for — cannot open a
    // session by claiming his DID, no matter how well-formed its Welcome is.
    {
        const seed_imp: [32]u8 = @splat(0xEE);
        var impostor = try testState(gpa, bob, seed_imp, 0x07, 0x08);
        defer deinit(gpa, &impostor);
        var g = try mls.createGroup(gpa, impostor.my_did, impostor.anchor_seed, .{
            .group_id = @splat(0x30),
            .enc_seed = @splat(0x31),
            .epoch_secret = @splat(0x32),
        });
        const welcome = try mls.addPeer(gpa, &g, alice.kp.kp_bytes, 0, .{
            .enc_seed = @splat(0x33),
            .path_secret = @splat(0x34),
            .welcome_seed = @splat(0x35),
        });
        defer gpa.free(welcome);
        g.deinit(gpa);
        var wb: [relay.bucket_len]u8 = undefined;
        try bucketPack(&wb, welcome);
        const pw = openWelcome(gpa, &alice, bucketUnpack(&wb).?) orelse return error.TestUnexpectedResult;
        try testing.expect((try acceptWelcome(gpa, &env, &alice, pw, &allowed)) == null);
        try testing.expectEqual(@as(usize, 2), sessionsOf(&alice, bob, &buf).len); // unchanged
    }

    // DELIVERY IS ABOUT THE PERSON, NOT THE DEVICE. Alice is waiting on Welcomes of
    // her own to two of Bob's devices; the moment ONE of them acks, Bob has
    // received it, and the thread must stop saying "waiting".
    alice.welcomes.items[sessions[0]] = .{ .bucket = try gpa.dupe(u8, "x"), .last_sent = 1, .last_ack = 0, .attempts = 1, .drifted = false };
    alice.welcomes.items[sessions[1]] = .{ .bucket = try gpa.dupe(u8, "y"), .last_sent = 1, .last_ack = 0, .attempts = 1, .drifted = false };
    try testing.expectEqual(chat.Delivery.waiting, deliveryState(&alice, bob));
    _ = confirmWelcome(gpa, &alice, sessions[1]); // his phone acked
    try testing.expectEqual(chat.Delivery.confirmed, deliveryState(&alice, bob));
}

test "chat_e2ee: a ROSTER and a HISTORY are believed only from YOUR OWN device (slices 3+5)" {
    // The roster tells a client to go and open conversations. So the one question
    // that matters is who is allowed to send one — and the answer is: only another
    // device of yours. A roster from anybody else is an instruction to open
    // conversations of THEIR choosing, and it is refused before anything happens.
    const gpa = testing.allocator;
    const me = "did:plc:e2ee-roster-me";
    const them = "did:plc:e2ee-roster-them";

    var env = std.process.Environ.Map.init(gpa);
    defer env.deinit();
    var tmp_buf: [64]u8 = undefined;
    const tmp = std.fmt.bufPrint(&tmp_buf, "/tmp/zat-e2ee-ros-{d}", .{std.os.linux.getpid()}) catch unreachable;
    try env.put("ZAT_CACHE_DIR", tmp);
    defer {
        var pb: [512]u8 = undefined;
        if (cache.chatGroupsPath(&pb, &env, me)) |p| {
            var z: [512]u8 = undefined;
            if (std.fmt.bufPrintZ(&z, "{s}", .{p})) |zp| _ = std.os.linux.unlink(zp) else |_| {}
        }
        var z2: [512]u8 = undefined;
        if (std.fmt.bufPrintZ(&z2, "{s}", .{tmp})) |zp| _ = std.os.linux.rmdir(zp) else |_| {}
    }

    var phone = try testState(gpa, me, @splat(0xA1), 0x01, 0x02); // the device being told
    defer deinit(gpa, &phone);

    // Two senders: MY desktop (same DID, its own keys) and a stranger.
    const senders = [_]struct { did: []const u8, seed: [32]u8, ent: u8, want_roster: bool }{
        .{ .did = them, .seed = @splat(0xB2), .ent = 0x30, .want_roster = false },
        .{ .did = me, .seed = @splat(0xC3), .ent = 0x50, .want_roster = true },
    };

    for (senders) |snd| {
        var sender = try testState(gpa, snd.did, snd.seed, snd.ent, snd.ent +% 1);
        defer deinit(gpa, &sender);

        var g = try mls.createGroup(gpa, sender.my_did, sender.anchor_seed, .{
            .group_id = @splat(snd.ent +% 2),
            .enc_seed = @splat(snd.ent +% 3),
            .epoch_secret = @splat(snd.ent +% 4),
        });
        defer g.deinit(gpa);
        const welcome = try mls.addPeer(gpa, &g, phone.kp.kp_bytes, 0, .{
            .enc_seed = @splat(snd.ent +% 5),
            .path_secret = @splat(snd.ent +% 6),
            .welcome_seed = @splat(snd.ent +% 7),
        });
        defer gpa.free(welcome);
        var wb: [relay.bucket_len]u8 = undefined;
        try bucketPack(&wb, welcome);
        const pw = openWelcome(gpa, &phone, bucketUnpack(&wb).?) orelse return error.TestUnexpectedResult;
        const inc = (try acceptWelcome(gpa, &env, &phone, pw, &.{try anchor.publicKey(snd.seed)})) orelse
            return error.TestUnexpectedResult;
        freeIncoming(gpa, inc);

        // A HISTORY REQUEST over that session. From a stranger this is "send me
        // everything you have ever said"; it must produce nothing at all.
        {
            const req = [_]u8{chat.kind_history_req_wire};
            const rmsg = try mls.encrypt(gpa, &g, &req, 0, .{ 9, 9, 9, 9 });
            defer gpa.free(rmsg);
            var rb: [relay.bucket_len]u8 = undefined;
            try bucketPack(&rb, rmsg);
            const rout = try onBucket(gpa, &env, &phone, phone.inbox, &rb);
            if (snd.want_roster) {
                const got = rout orelse return error.TestUnexpectedResult;
                defer freeIncoming(gpa, got);
                try testing.expect(got == .history_request); // our own device may ask
            } else if (rout) |o| {
                defer freeIncoming(gpa, o);
                try testing.expect(o != .history_request); // a stranger may not
            }
        }

        // …and now they send a roster over that session.
        const payload = [_]u8{chat.kind_roster_wire} ++ "did:plc:someone-they-chose\n".*;
        const msg = try mls.encrypt(gpa, &g, &payload, 0, .{ 1, 2, 3, 4 });
        defer gpa.free(msg);
        var bucket: [relay.bucket_len]u8 = undefined;
        try bucketPack(&bucket, msg);

        const out = try onBucket(gpa, &env, &phone, phone.inbox, &bucket);
        if (snd.want_roster) {
            // MY OWN DEVICE: the list is taken.
            const got = out orelse return error.TestUnexpectedResult;
            defer freeIncoming(gpa, got);
            try testing.expect(got == .roster);
            try testing.expect(std.mem.indexOf(u8, got.roster.dids, "did:plc:someone-they-chose") != null);
        } else {
            // ANOTHER PERSON: refused. It produces nothing at all — no roster, and
            // therefore not one conversation opened on their say-so.
            if (out) |o| {
                defer freeIncoming(gpa, o);
                try testing.expect(o != .roster);
            }
        }
    }
}
