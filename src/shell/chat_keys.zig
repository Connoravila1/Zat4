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

//! B1 classification: SHELL (network + entropy + clock). The chat key
//! directory's network leg (ZAT_CHAT_ROADMAP slice U6): publish OUR
//! last-resort `app.zat4.chat.keyPackage` record, fetch a COUNTERPARTY's,
//! and hand every decoded value to `core/keydir.zig` for the verdict —
//! this file owns JSON, base64, and timestamps; the core owns meaning (D3).
//!
//! Publish (`ensurePublished`) is idempotent by construction: the record is
//! a singleton at rkey "self" and putRecord overwrites. The private halves
//! (init + encryption keys) are persisted BEFORE the record goes public —
//! a published package whose privates were lost is a dead letter box, so
//! the order is load-or-mint → SAVE → publish. The record shape (vision
//! doc §5): did, cipherSuite, keyPackage (base64), anchorKeySig (base64),
//! lastResort, notAfter, createdAt. `prevKeyProof` (anchor succession) is
//! deferred with key rotation — absent, not faked.

const std = @import("std");
const Allocator = std.mem.Allocator;
const auth = @import("auth.zig");
const cache = @import("cache.zig");
const identity = @import("identity.zig");
const net = @import("xrpc.zig");
const clock = @import("clock.zig");
const xrpc = @import("../core/xrpc.zig");
const lexicon = @import("../core/lexicon.zig");
const feed_core = @import("../core/feed.zig");
const keydir = @import("../core/keydir.zig");
const mls = @import("../core/mls.zig");
const anchor = @import("../core/anchor.zig");

/// The last-resort package's lifetime: ~6 months, then a refresh republishes
/// (rotation + prevKeyProof are the recorded follow-up).
const lifetime_seconds: i64 = 180 * 24 * 60 * 60;

/// The WRITE shape. A7.2: cold record struct, size guard waived.
const KeyPackageRecordOut = struct {
    @"$type": []const u8 = lexicon.collection.chat_key_package,
    did: []const u8,
    cipherSuite: u16,
    keyPackage: []const u8, // base64(MLSMessage(KeyPackage))
    anchorKeySig: []const u8, // base64(anchor signature over the DID)
    lastResort: bool = true,
    notAfter: []const u8,
    createdAt: []const u8,
};

/// The READ shape (defaulted — absent fields fail validation downstream,
/// never here, E4). A7.2: cold parse target, size guard waived.
const KeyPackageRecordIn = struct {
    did: []const u8 = "",
    cipherSuite: u16 = 0,
    keyPackage: []const u8 = "",
    anchorKeySig: []const u8 = "",
    lastResort: bool = false,
    notAfter: []const u8 = "",
};

/// A7.2: cold result, size guard waived. Slices live in the caller's arena.
pub const Published = struct {
    uri: []const u8,
    cid: []const u8,
    /// True when this call MINTED a fresh package (first chat use);
    /// false when the stored one was republished (idempotent refresh).
    minted: bool,
};

/// Make sure our key-directory entry exists: load (or mint + persist) the
/// last-resort package + anchor, then put the record at rkey "self".
///
/// `replace_foreign` is the A3 gate. The record is a SINGLETON at rkey "self"
/// and putRecord overwrites, so publishing a freshly-minted anchor over an
/// existing one silently REPLACES the account's chat identity — which is what
/// a reinstall, a cleared cache, or one run with a different `ZAT_CACHE_DIR`
/// used to do, orphaning every conversation the account had, with no warning
/// and no way back (the anchor seed is device-bound and unrecoverable).
///
/// So the write is refused by default when the published record pins an anchor
/// that ISN'T this device's: `error.IdentityElsewhere`. The caller surfaces
/// that as a choice the user makes on purpose, and passes `replace_foreign`
/// only when they have made it.
pub fn ensurePublished(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    replace_foreign: bool,
) !Published {
    const did = session.did;
    var anchor_load = cache.loadOrCreateAnchorSeed(gpa, io, environ, did) orelse return error.NoAnchor;
    defer std.crypto.secureZero(u8, &anchor_load.seed);

    // A3 — DO NOT HIJACK AN IDENTITY THAT LIVES SOMEWHERE ELSE.
    //
    // The check is on the KEYS, not on `AnchorLoad.created`: a device that
    // minted a fresh anchor on a previous launch and failed to publish would
    // look "not new" the next time round and clobber the record then instead.
    // What matters is only ever the question this asks — does the account
    // already publish a chat key that is not ours?
    //
    // A record we cannot read or that fails validation is NOT a foreign
    // identity: it is a broken one, and publishing over it is the repair.
    if (!replace_foreign) {
        const mine = try anchor.publicKey(anchor_load.seed);
        if (fetchPeer(gpa, arena, io, environ, did) catch null) |published| {
            if (!std.mem.eql(u8, &published.anchor_pub, &mine)) return error.IdentityElsewhere;
        }
    }

    const now = clock.unixSeconds();
    var kp_path_buf: [512]u8 = undefined;
    const kp_path = cache.chatKeyPackagePath(&kp_path_buf, environ, did) orelse return error.NoCacheDir;

    var minted = false;
    var stored = cache.loadChatKeyPackageAt(gpa, kp_path, did) orelse blk: {
        // First chat use: mint the package (entropy is the shell's job, B3),
        // persist the privates FIRST, then let the record go public.
        var ep: mls.KeyPackageEntropy = undefined;
        try io.randomSecure(&ep.init_seed);
        try io.randomSecure(&ep.enc_seed);
        defer {
            std.crypto.secureZero(u8, &ep.init_seed);
            std.crypto.secureZero(u8, &ep.enc_seed);
        }
        var bundle = try mls.generateKeyPackage(
            gpa,
            did,
            anchor_load.seed,
            @intCast(@max(0, now - 300)),
            @intCast(now + lifetime_seconds),
            ep,
        );
        // Ownership of bundle.bytes moves into `fresh` (no copy) — from here
        // `fresh` is the one owner and freeChatKeyPackage its one freer (C5).
        var fresh: cache.ChatKeyPackage = .{
            .init_priv = bundle.init_priv,
            .enc_priv = bundle.enc_priv,
            .kp_bytes = bundle.bytes,
        };
        // The bundle's key material now lives in `fresh`; scrub the source
        // copies (the bytes slice moved by reference, not copy).
        std.crypto.secureZero(u8, &bundle.init_priv);
        std.crypto.secureZero(u8, &bundle.enc_priv);
        if (!cache.saveChatKeyPackageAt(gpa, kp_path, did, &fresh)) {
            cache.freeChatKeyPackage(gpa, &fresh);
            return error.PersistFailed; // never publish a package we could lose
        }
        minted = true;
        break :blk fresh;
    };
    defer cache.freeChatKeyPackage(gpa, &stored);

    // The record: base64 the wire bytes + the DID binding, stamp expiry from
    // the PACKAGE's own lifetime (one truth — re-derived, never re-invented).
    const info = try mls.checkKeyPackage(arena, stored.kp_bytes, @intCast(@max(0, now)));
    const sig = try anchor.signDidBinding(anchor_load.seed, did);

    const Enc = std.base64.standard.Encoder;
    const kp_b64 = try arena.alloc(u8, Enc.calcSize(stored.kp_bytes.len));
    _ = Enc.encode(kp_b64, stored.kp_bytes);
    const sig_b64 = try arena.alloc(u8, Enc.calcSize(sig.len));
    _ = Enc.encode(sig_b64, &sig);

    var na_buf: [24]u8 = undefined;
    var ca_buf: [24]u8 = undefined;
    const record = KeyPackageRecordOut{
        .did = did,
        .cipherSuite = mls.cipher_suite_id,
        .keyPackage = kp_b64,
        .anchorKeySig = sig_b64,
        .notAfter = feed_core.formatTimestamp(&na_buf, @intCast(info.not_after)),
        .createdAt = feed_core.formatTimestamp(&ca_buf, now),
    };
    const input = lexicon.PutRecordInput(@TypeOf(record)){
        .repo = did,
        .collection = lexicon.collection.chat_key_package,
        .rkey = "self",
        .record = record,
    };
    const outcome = try auth.procedure(gpa, arena, io, environ, session, lexicon.method.put_record, input, lexicon.RecordRef);
    return switch (outcome) {
        .ok => |r| .{ .uri = try arena.dupe(u8, r.uri), .cid = try arena.dupe(u8, r.cid), .minted = minted },
        .failed => error.PublishFailed,
    };
}

/// A validated counterparty. `kp_bytes` (arena) feeds `mls.addPeer` when the
/// conversation starts; `anchor_pub` is the identity a client may pin.
/// A7.2: cold result, size guard waived.
pub const PeerKeys = struct {
    kp_bytes: []const u8,
    anchor_pub: [anchor.pk_len]u8,
};

/// Fetch + validate `did`'s key-directory entry: resolve the DID to ITS
/// OWN PDS (never a guessed host), read the public record, decode, and let
/// the core gate decide (keydir.validate — the six checks). Null = no
/// record (the peer has never used chat: an ordinary result, E4). Every
/// validation failure is an explicit error (E3).
pub fn fetchPeer(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    did: []const u8,
) !?PeerKeys {
    const pds_url = try identity.pdsForDid(gpa, io, environ, .{}, did);
    defer gpa.free(pds_url);

    const params = [_]xrpc.Param{
        .{ .name = "repo", .value = did },
        .{ .name = "collection", .value = lexicon.collection.chat_key_package },
        .{ .name = "rkey", .value = "self" },
    };
    const outcome = try net.query(arena, io, environ, pds_url, lexicon.method.get_record, &params, lexicon.GetRecordResponse(KeyPackageRecordIn), .{ .guard = .untrusted });
    const rec = switch (outcome) {
        .ok => |r| r.value,
        .failed => return null, // absent record = peer not on chat yet (E4)
    };

    const Dec = std.base64.standard.Decoder;
    const kp_len = Dec.calcSizeForSlice(rec.keyPackage) catch return error.BadRecord;
    const kp_bytes = try arena.alloc(u8, kp_len);
    Dec.decode(kp_bytes, rec.keyPackage) catch return error.BadRecord;
    const sig_len = Dec.calcSizeForSlice(rec.anchorKeySig) catch return error.BadRecord;
    const sig_bytes = try arena.alloc(u8, sig_len);
    Dec.decode(sig_bytes, rec.anchorKeySig) catch return error.BadRecord;
    const not_after = feed_core.parseTimestamp(rec.notAfter) catch return error.BadRecord;

    const peer = try keydir.validate(arena, did, .{
        .did = rec.did,
        .cipher_suite = rec.cipherSuite,
        .key_package = kp_bytes,
        .anchor_sig = sig_bytes,
        .not_after = not_after,
    }, clock.unixSeconds());
    return .{ .kp_bytes = kp_bytes, .anchor_pub = peer.anchor_pub };
}

// ---------------------------------------------------------------------------
// THE DEVICE RECORD (CHAT_MULTIDEVICE slice 0) — one record PER DEVICE, at the
// device's own rkey, in `app.zat4.chat.device`.
//
// The singleton at rkey "self" is why we are here: putRecord overwrites, so a
// second device could only ever REPLACE the first. Give each device its own
// rkey and that clobber stops being possible rather than being guarded against.
//
// A record's existence still proves nothing (anybody with the account password
// can write to the repo) — a device is real only if an already-trusted device
// SIGNED for it. That check is pure and lives in `core/keydir.resolveDevices`;
// this file only carries JSON and base64 across the wire (D3).
// ---------------------------------------------------------------------------

/// A stable, self-derived id for a device: the rkey its record lives at. Derived
/// from the device's own anchor PUBLIC key, so a device can compute its own rkey
/// with nothing but its keys — and cannot claim another device's slot.
pub fn deviceId(buf: *[32]u8, anchor_pub: [anchor.pk_len]u8) []const u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("Zat4 Chat 1.0 DeviceId");
    h.update(&anchor_pub);
    var digest: [32]u8 = undefined;
    h.final(&digest);
    // Lowercase base32 (no padding) — an rkey must be URL-safe; 16 chars of it is
    // 80 bits, far past collision territory for a set that is capped at 8.
    const alphabet = "abcdefghijklmnopqrstuvwxyz234567";
    for (0..16) |i| buf[i] = alphabet[digest[i] & 31];
    return buf[0..16];
}

/// The WRITE shape. A7.2: cold record struct, size guard waived.
const DeviceRecordOut = struct {
    @"$type": []const u8 = lexicon.collection.chat_device,
    did: []const u8,
    cipherSuite: u16,
    keyPackage: []const u8, // base64(MLSMessage(KeyPackage)) — this device's own
    anchorKeySig: []const u8, // base64(this device's anchor signature over the DID)
    /// The first device of the account. A root self-attests; every other device
    /// must show an approval.
    root: bool,
    /// base64(an already-trusted device's signature over this device's key + the
    /// DID). Empty on the root. We do NOT say WHO signed: the reader tests it
    /// against every device it already trusts, so the record carries no claim it
    /// could lie about.
    approvalSig: []const u8 = "",
    /// A human name for the approval prompt ("Pixel 10 Pro"). Cosmetic, and
    /// treated as such — it is unsigned, so it may be a lie, and nothing but the
    /// wording of a prompt may ever depend on it.
    deviceName: []const u8 = "",
    notAfter: []const u8,
    createdAt: []const u8,
};

/// The READ shape. A7.2: cold parse target, size guard waived.
const DeviceRecordIn = struct {
    did: []const u8 = "",
    cipherSuite: u16 = 0,
    keyPackage: []const u8 = "",
    anchorKeySig: []const u8 = "",
    root: bool = false,
    approvalSig: []const u8 = "",
    deviceName: []const u8 = "",
    notAfter: []const u8 = "",
    createdAt: []const u8 = "",
};

fn ListingOf(comptime Value: type) type {
    return struct {
        const Rec = struct {
            uri: []const u8 = "",
            cid: []const u8 = "",
            value: Value = .{},
        };
        records: []const Rec = &.{},
        cursor: ?[]const u8 = null,
    };
}

/// Publish THIS device's record. `approval_sig` is empty for the root device (the
/// first ever to use chat on this account) and otherwise carries the signature an
/// already-approved device made over this device's key.
///
/// Unlike `ensurePublished`, this cannot clobber anybody: the rkey is derived from
/// our own key, so we write only our own slot. There is no A3 gate here because
/// there is nothing left for it to defend — that is the point of the slice.
pub fn publishDevice(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    device_name: []const u8,
    is_root: bool,
    approval_sig: []const u8,
) !Published {
    const did = session.did;
    var anchor_load = cache.loadOrCreateAnchorSeed(gpa, io, environ, did) orelse return error.NoAnchor;
    defer std.crypto.secureZero(u8, &anchor_load.seed);

    const now = clock.unixSeconds();
    var kp_path_buf: [512]u8 = undefined;
    const kp_path = cache.chatKeyPackagePath(&kp_path_buf, environ, did) orelse return error.NoCacheDir;

    var minted = false;
    var stored = cache.loadChatKeyPackageAt(gpa, kp_path, did) orelse blk: {
        var ep: mls.KeyPackageEntropy = undefined;
        try io.randomSecure(&ep.init_seed);
        try io.randomSecure(&ep.enc_seed);
        defer {
            std.crypto.secureZero(u8, &ep.init_seed);
            std.crypto.secureZero(u8, &ep.enc_seed);
        }
        var bundle = try mls.generateKeyPackage(gpa, did, anchor_load.seed, @intCast(@max(0, now - 300)), @intCast(now + lifetime_seconds), ep);
        var fresh: cache.ChatKeyPackage = .{
            .init_priv = bundle.init_priv,
            .enc_priv = bundle.enc_priv,
            .kp_bytes = bundle.bytes,
        };
        std.crypto.secureZero(u8, &bundle.init_priv);
        std.crypto.secureZero(u8, &bundle.enc_priv);
        if (!cache.saveChatKeyPackageAt(gpa, kp_path, did, &fresh)) {
            cache.freeChatKeyPackage(gpa, &fresh);
            return error.PersistFailed; // never publish a package we could lose
        }
        minted = true;
        break :blk fresh;
    };
    defer cache.freeChatKeyPackage(gpa, &stored);

    const info = try mls.checkKeyPackage(arena, stored.kp_bytes, @intCast(@max(0, now)));
    const sig = try anchor.signDidBinding(anchor_load.seed, did);
    const my_pub = try anchor.publicKey(anchor_load.seed);

    const Enc = std.base64.standard.Encoder;
    const kp_b64 = try arena.alloc(u8, Enc.calcSize(stored.kp_bytes.len));
    _ = Enc.encode(kp_b64, stored.kp_bytes);
    const sig_b64 = try arena.alloc(u8, Enc.calcSize(sig.len));
    _ = Enc.encode(sig_b64, &sig);
    const appr_b64 = if (approval_sig.len == 0) "" else blk: {
        const b = try arena.alloc(u8, Enc.calcSize(approval_sig.len));
        _ = Enc.encode(b, approval_sig);
        break :blk b;
    };

    var rkey_buf: [32]u8 = undefined;
    var na_buf: [24]u8 = undefined;
    var ca_buf: [24]u8 = undefined;
    const record = DeviceRecordOut{
        .did = did,
        .cipherSuite = mls.cipher_suite_id,
        .keyPackage = kp_b64,
        .anchorKeySig = sig_b64,
        .root = is_root,
        .approvalSig = appr_b64,
        .deviceName = device_name,
        .notAfter = feed_core.formatTimestamp(&na_buf, @intCast(info.not_after)),
        .createdAt = feed_core.formatTimestamp(&ca_buf, now),
    };
    const input = lexicon.PutRecordInput(@TypeOf(record)){
        .repo = did,
        .collection = lexicon.collection.chat_device,
        .rkey = deviceId(&rkey_buf, my_pub),
        .record = record,
    };
    const outcome = try auth.procedure(gpa, arena, io, environ, session, lexicon.method.put_record, input, lexicon.RecordRef);
    return switch (outcome) {
        .ok => |r| .{ .uri = try arena.dupe(u8, r.uri), .cid = try arena.dupe(u8, r.cid), .minted = minted },
        .failed => error.PublishFailed,
    };
}

// ---------------------------------------------------------------------------
// ANNOUNCE → APPROVE (CHAT_MULTIDEVICE slice 2).
//
// THE REQUEST IS NOT A NEW KIND OF THING. A device asking to join is simply a
// device record NOBODY HAS VOUCHED FOR YET — the same record it will keep once it
// is approved, minus the one signature that makes it real. Approving is that
// signature being added.
//
// This is why a stranger cannot make your desktop light up: the record lives in
// YOUR repo and takes your account's write authorisation to create. There is no
// inbound request channel from the outside world at all — no public inbox anyone
// can post to, and therefore no prompt-fatigue attack. (That inbox is the design
// we REJECTED; see the roadmap §3, where it is written down precisely so a future
// simplification cannot quietly reintroduce it.)
// ---------------------------------------------------------------------------

/// WHERE THIS DEVICE STANDS with the account's chat identity. The old model had
/// exactly two answers — "it's mine" or `IdentityElsewhere` — which is why the
/// phone's only door was to take chat away from the desktop.
pub const DeviceStatus = enum {
    /// The first device: it self-attests, and its key IS the account's chat
    /// identity. (Also the answer for every account that has only ever had one.)
    root,
    /// A device an already-trusted device has vouched for. It is fully part of the
    /// account: peers address it like any other.
    approved,
    /// We have ASKED and nobody has answered yet. The screen says so, and waits —
    /// it does not pretend to be broken.
    pending,
    /// Chat lives elsewhere and this device has not asked to join it. This is the
    /// A3 wall — but it is now a door: the person may ask, and their other device
    /// may say yes.
    not_asked,
};

/// Publish this device where it belongs and report where it stands. The ONE call
/// chat start-up makes, and the only place that decides whether this device may
/// speak for the account.
///
/// The order matters: a device that is genuinely part of the account refreshes its
/// own record and NEVER touches the legacy singleton — writing that would clobber
/// the root's, which is the exact bug this whole project exists to end.
pub fn ensureDevice(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    device_name: []const u8,
) !DeviceStatus {
    const did = session.did;
    var anchor_load = cache.loadOrCreateAnchorSeed(gpa, io, environ, did) orelse return error.NoAnchor;
    defer std.crypto.secureZero(u8, &anchor_load.seed);
    const mine = try anchor.publicKey(anchor_load.seed);

    const set = fetchPeerDevices(gpa, arena, io, environ, did) catch null;

    // NOBODY HAS PUBLISHED A DEVICE RECORD YET — every account alive today. The
    // device that already owns chat (or an account with no chat at all) becomes the
    // ROOT, which is what makes it possible for anything else to be approved.
    if (set == null) {
        const legacy = fetchPeer(gpa, arena, io, environ, did) catch null;
        const chat_is_ours = if (legacy) |l| std.mem.eql(u8, &l.anchor_pub, &mine) else true;
        if (chat_is_ours) {
            _ = try publishDevice(gpa, arena, io, environ, session, device_name, true, "");
            // The ROOT also keeps the legacy singleton alive, because every peer
            // running an older client still reads that and nothing else. Dropping
            // it the day the device model shipped would have taken chat away from
            // everyone we have in order to serve devices nobody has yet.
            _ = ensurePublished(gpa, arena, io, environ, session, false) catch {};
            return .root;
        }
        // Chat lives on another device, and that device has not upgraded to the
        // device model yet. We can still ASK — our record simply waits until it
        // does. (Asking is `publishDevice(root=false, approval="")`; the caller
        // does it when the person taps, never on our own initiative.)
        return if (try hasOwnRecord(gpa, arena, io, environ, did, mine)) .pending else .not_asked;
    }

    const devices = set.?;
    for (devices.devices) |d| {
        if (!std.mem.eql(u8, &d.anchor_pub, &mine)) continue;
        // We are part of the account. Refresh our own record (idempotent) and never
        // go near anybody else's.
        _ = try publishDevice(gpa, arena, io, environ, session, device_name, d.root, "");
        return if (d.root) .root else .approved;
    }
    return if (try hasOwnRecord(gpa, arena, io, environ, did, mine)) .pending else .not_asked;
}

/// Have we already published a record for THIS device (approved or not)? The
/// difference between "waiting" and "has not asked", which is the difference
/// between a screen that waits and a screen that offers a button.
fn hasOwnRecord(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    did: []const u8,
    mine: [anchor.pk_len]u8,
) !bool {
    const records = (try fetchDeviceListing(gpa, arena, io, environ, did)) orelse return false;
    var rkey_buf: [32]u8 = undefined;
    const ours = deviceId(&rkey_buf, mine);
    for (records) |r| {
        if (std.mem.eql(u8, rkeyOf(r.uri), ours)) return true;
    }
    return false;
}

/// ASK to join: publish this device's record with no approval on it. That record IS
/// the request (there is no second kind of thing, and no inbox a stranger could
/// post to). It waits, inert, until a device that is already part of the account
/// signs for it.
pub fn requestJoin(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    device_name: []const u8,
) !void {
    _ = try publishDevice(gpa, arena, io, environ, session, device_name, false, "");
}

/// A device of ours that has asked to join and nobody has vouched for. Arena-owned.
/// A7.2: cold, transient — a handful at most, and normally none.
pub const PendingDevice = struct {
    /// The device's own anchor key: what an approval SIGNS. Everything else here
    /// is for the prompt to have words in it.
    anchor_pub: [anchor.pk_len]u8,
    /// Unsigned, therefore capable of lying. It may put a name in a sentence and
    /// nothing else — no decision anywhere may turn on it.
    name: []const u8,
    created_at: i64,
    /// The record as published, so the approval can be written back into it
    /// without inventing any of the fields it already carries.
    rkey: []const u8,
    key_package_b64: []const u8,
    anchor_sig_b64: []const u8,
    not_after: []const u8,
};

/// Devices of OUR OWN account that are asking to join: records that are
/// structurally valid but that the trusted set does not contain.
///
/// A record that fails validation is not "pending" — it is junk, and junk must not
/// be able to put a prompt in front of a person.
pub fn fetchPending(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    did: []const u8,
    trusted: []const [anchor.pk_len]u8,
) ![]const PendingDevice {
    const listing = (try fetchDeviceListing(gpa, arena, io, environ, did)) orelse return &.{};
    var out = try std.ArrayListUnmanaged(PendingDevice).initCapacity(arena, listing.len);
    const now = clock.unixSeconds();

    for (listing) |r| {
        const v = r.value;
        if (v.root) continue; // the root vouches for itself; it is never pending
        const decoded = decodeDevice(arena, v) catch continue;
        // It must at least be a real device record — its own key, its own binding.
        const peer = keydir.validate(arena, did, .{
            .did = v.did,
            .cipher_suite = v.cipherSuite,
            .key_package = decoded.key_package,
            .anchor_sig = decoded.anchor_sig,
            .not_after = decoded.not_after,
        }, now) catch continue;

        // Already vouched for by somebody we trust? Then it is not asking — it is
        // in, and a prompt about it would be a prompt about nothing.
        var approved = false;
        for (trusted) |t| {
            if (std.mem.eql(u8, &t, &peer.anchor_pub)) {
                approved = true; // it IS one of the trusted devices
                break;
            }
            if (decoded.approval_sig.len == 0) continue; // asking, with no proof yet
            anchor.verifyDeviceApproval(t, did, peer.anchor_pub, decoded.approval_sig) catch continue;
            approved = true; // a trusted device has already vouched for it
            break;
        }
        if (approved) continue;

        out.appendAssumeCapacity(.{
            .anchor_pub = peer.anchor_pub,
            .name = v.deviceName,
            .created_at = feed_core.parseTimestamp(v.createdAt) catch 0,
            .rkey = rkeyOf(r.uri),
            .key_package_b64 = v.keyPackage,
            .anchor_sig_b64 = v.anchorKeySig,
            .not_after = v.notAfter,
        });
    }
    return out.items;
}

/// APPROVE: sign the pending device's key with THIS device's anchor key and write
/// the signature into its record. From here every peer that resolves the account's
/// devices will see it, and will address it like any other.
///
/// The approval signs the device's KEY, not its name or its rkey — so nothing a
/// liar could put in the record changes what was agreed to.
pub fn approveDevice(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    pending: PendingDevice,
) !void {
    const did = session.did;
    var anchor_load = cache.loadOrCreateAnchorSeed(gpa, io, environ, did) orelse return error.NoAnchor;
    defer std.crypto.secureZero(u8, &anchor_load.seed);

    const sig = try anchor.signDeviceApproval(anchor_load.seed, did, pending.anchor_pub);
    const Enc = std.base64.standard.Encoder;
    const sig_b64 = try arena.alloc(u8, Enc.calcSize(sig.len));
    _ = Enc.encode(sig_b64, &sig);

    var ca_buf: [24]u8 = undefined;
    const record = DeviceRecordOut{
        .did = did,
        .cipherSuite = mls.cipher_suite_id,
        .keyPackage = pending.key_package_b64, // unchanged: it is THEIR key, not ours to restate
        .anchorKeySig = pending.anchor_sig_b64,
        .root = false,
        .approvalSig = sig_b64, // …and this is the whole of what we are adding
        .deviceName = pending.name,
        .notAfter = pending.not_after,
        .createdAt = feed_core.formatTimestamp(&ca_buf, clock.unixSeconds()),
    };
    const input = lexicon.PutRecordInput(@TypeOf(record)){
        .repo = did,
        .collection = lexicon.collection.chat_device,
        .rkey = pending.rkey,
        .record = record,
    };
    const outcome = try auth.procedure(gpa, arena, io, environ, session, lexicon.method.put_record, input, lexicon.RecordRef);
    return switch (outcome) {
        .ok => {},
        .failed => error.PublishFailed,
    };
}

/// "NOT ME." Delete the record outright. This is not a dismiss: the device is
/// refused, its key is never vouched for, and the caller tells the user plainly
/// that somebody signed in as their account.
pub fn refuseDevice(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    rkey: []const u8,
) !void {
    const input = lexicon.DeleteRecordOut{
        .repo = session.did,
        .collection = lexicon.collection.chat_device,
        .rkey = rkey,
    };
    const outcome = try auth.procedure(gpa, arena, io, environ, session, lexicon.method.delete_record, input, lexicon.DeleteRecordResponse);
    return switch (outcome) {
        .ok => {},
        .failed => error.PublishFailed,
    };
}

/// The rkey is the last path segment of an at:// URI.
fn rkeyOf(uri: []const u8) []const u8 {
    const slash = std.mem.lastIndexOfScalar(u8, uri, '/') orelse return uri;
    return uri[slash + 1 ..];
}

const DecodedDevice = struct {
    // A7.2: cold, transient decode result.
    key_package: []const u8,
    anchor_sig: []const u8,
    approval_sig: []const u8,
    not_after: i64,
};

fn decodeDevice(arena: Allocator, v: DeviceRecordIn) !DecodedDevice {
    const Dec = std.base64.standard.Decoder;
    const kp = try arena.alloc(u8, try Dec.calcSizeForSlice(v.keyPackage));
    try Dec.decode(kp, v.keyPackage);
    const sig = try arena.alloc(u8, try Dec.calcSizeForSlice(v.anchorKeySig));
    try Dec.decode(sig, v.anchorKeySig);
    var appr: []const u8 = "";
    if (v.approvalSig.len > 0) {
        const a = try arena.alloc(u8, try Dec.calcSizeForSlice(v.approvalSig));
        try Dec.decode(a, v.approvalSig);
        appr = a;
    }
    return .{
        .key_package = kp,
        .anchor_sig = sig,
        .approval_sig = appr,
        .not_after = try feed_core.parseTimestamp(v.notAfter),
    };
}

/// The raw device records in a repo (public read). Null = no such collection.
fn fetchDeviceListing(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    did: []const u8,
) !?[]const ListingOf(DeviceRecordIn).Rec {
    const pds_url = try identity.pdsForDid(gpa, io, environ, .{}, did);
    defer gpa.free(pds_url);
    const params = [_]xrpc.Param{
        .{ .name = "repo", .value = did },
        .{ .name = "collection", .value = lexicon.collection.chat_device },
        .{ .name = "limit", .value = "20" }, // the set is capped at 8; 20 leaves room for junk
    };
    const outcome = try net.query(arena, io, environ, pds_url, lexicon.method.list_records, &params, ListingOf(DeviceRecordIn), .{ .guard = .untrusted });
    return switch (outcome) {
        .ok => |r| if (r.records.len == 0) null else r.records,
        .failed => null,
    };
}

/// Every device of `did` that the account's own devices vouch for, plus the root
/// key that identifies its chat identity. An account with no device records is not
/// an error — it simply has not moved to the device model yet (E4: the caller
/// falls back to the legacy singleton).
pub fn fetchPeerDevices(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    did: []const u8,
) !?keydir.DeviceSet {
    const records = (try fetchDeviceListing(gpa, arena, io, environ, did)) orelse return null;

    const Dec = std.base64.standard.Decoder;
    var decoded = try std.ArrayListUnmanaged(keydir.DeviceRecord).initCapacity(arena, records.len);
    for (records) |r| {
        const v = r.value;
        // A record we cannot even decode is DROPPED, not fatal: one piece of junk
        // in the repo must not take an account's whole chat identity offline.
        const kp_len = Dec.calcSizeForSlice(v.keyPackage) catch continue;
        const kp_bytes = try arena.alloc(u8, kp_len);
        Dec.decode(kp_bytes, v.keyPackage) catch continue;
        const sig_len = Dec.calcSizeForSlice(v.anchorKeySig) catch continue;
        const sig_bytes = try arena.alloc(u8, sig_len);
        Dec.decode(sig_bytes, v.anchorKeySig) catch continue;
        var appr: []const u8 = "";
        if (v.approvalSig.len > 0) {
            const a_len = Dec.calcSizeForSlice(v.approvalSig) catch continue;
            const a_bytes = try arena.alloc(u8, a_len);
            Dec.decode(a_bytes, v.approvalSig) catch continue;
            appr = a_bytes;
        }
        const not_after = feed_core.parseTimestamp(v.notAfter) catch continue;
        const created_at = feed_core.parseTimestamp(v.createdAt) catch 0;

        decoded.appendAssumeCapacity(.{
            .did = v.did,
            .cipher_suite = v.cipherSuite,
            .key_package = kp_bytes,
            .anchor_sig = sig_bytes,
            .not_after = not_after,
            .root = v.root,
            .approval_sig = appr,
            .created_at = created_at,
        });
    }

    // The verdict is the CORE's (D3): who is vouched for, and by whom.
    const set = try keydir.resolveDevices(arena, did, decoded.items, clock.unixSeconds());
    if (set.devices.len == 0) return null;
    return set;
}

// ---------------------------------------------------------------------------
// Tests (C6) — the record wire mapping round-trips through the same JSON +
// base64 + validation gate a real fetch uses; the network legs are typed
// through semantic analysis by the harness (main-reachable).
// ---------------------------------------------------------------------------

const testing = std.testing;

test "chat_keys: the record round-trips JSON+base64 into keydir's gate" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const did = "did:plc:recordroundtripaaaaaaaa";
    const seed: [anchor.seed_len]u8 = [_]u8{0x77} ** 32;
    const bundle = try mls.generateKeyPackage(arena, did, seed, 0, 4102444800, .{
        .init_seed = [_]u8{0x10} ** 32,
        .enc_seed = [_]u8{0x20} ** 32,
    });
    const sig = try anchor.signDidBinding(seed, did);

    const Enc = std.base64.standard.Encoder;
    const kp_b64 = try arena.alloc(u8, Enc.calcSize(bundle.bytes.len));
    _ = Enc.encode(kp_b64, bundle.bytes);
    const sig_b64 = try arena.alloc(u8, Enc.calcSize(sig.len));
    _ = Enc.encode(sig_b64, &sig);

    const out = KeyPackageRecordOut{
        .did = did,
        .cipherSuite = mls.cipher_suite_id,
        .keyPackage = kp_b64,
        .anchorKeySig = sig_b64,
        .notAfter = "2099-12-31T00:00:00Z",
        .createdAt = "2026-07-02T00:00:00Z",
    };
    const json = try std.json.Stringify.valueAlloc(arena, out, .{ .emit_null_optional_fields = false });
    const back = try std.json.parseFromSliceLeaky(KeyPackageRecordIn, arena, json, .{ .ignore_unknown_fields = true });

    // Decode exactly as fetchPeer does and pass the core gate.
    const Dec = std.base64.standard.Decoder;
    const kp_bytes = try arena.alloc(u8, try Dec.calcSizeForSlice(back.keyPackage));
    try Dec.decode(kp_bytes, back.keyPackage);
    const sig_bytes = try arena.alloc(u8, try Dec.calcSizeForSlice(back.anchorKeySig));
    try Dec.decode(sig_bytes, back.anchorKeySig);
    const peer = try keydir.validate(arena, did, .{
        .did = back.did,
        .cipher_suite = back.cipherSuite,
        .key_package = kp_bytes,
        .anchor_sig = sig_bytes,
        .not_after = try feed_core.parseTimestamp(back.notAfter),
    }, 1_751_400_000);
    try testing.expectEqualSlices(u8, &(try anchor.publicKey(seed)), &peer.anchor_pub);
    try testing.expect(back.lastResort);
}

test "chat_keys: a device record round-trips the wire and its approval survives it" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const did = "did:plc:deviceroundtripaaaaaaaa";
    const root_seed: [anchor.seed_len]u8 = [_]u8{0x21} ** 32;
    const phone_seed: [anchor.seed_len]u8 = [_]u8{0x32} ** 32;
    const phone_pub = try anchor.publicKey(phone_seed);

    const bundle = try mls.generateKeyPackage(arena, did, phone_seed, 0, 4102444800, .{
        .init_seed = [_]u8{0x40} ** 32,
        .enc_seed = [_]u8{0x50} ** 32,
    });
    const binding = try anchor.signDidBinding(phone_seed, did);
    // The desktop vouches for the phone — the signature this whole slice turns on.
    const approval = try anchor.signDeviceApproval(root_seed, did, phone_pub);

    const Enc = std.base64.standard.Encoder;
    const kp_b64 = try arena.alloc(u8, Enc.calcSize(bundle.bytes.len));
    _ = Enc.encode(kp_b64, bundle.bytes);
    const sig_b64 = try arena.alloc(u8, Enc.calcSize(binding.len));
    _ = Enc.encode(sig_b64, &binding);
    const appr_b64 = try arena.alloc(u8, Enc.calcSize(approval.len));
    _ = Enc.encode(appr_b64, &approval);

    const out = DeviceRecordOut{
        .did = did,
        .cipherSuite = mls.cipher_suite_id,
        .keyPackage = kp_b64,
        .anchorKeySig = sig_b64,
        .root = false,
        .approvalSig = appr_b64,
        .deviceName = "Pixel 10 Pro",
        .notAfter = "2099-12-31T00:00:00Z",
        .createdAt = "2026-07-13T00:00:00Z",
    };
    const json = try std.json.Stringify.valueAlloc(arena, out, .{ .emit_null_optional_fields = false });
    const back = try std.json.parseFromSliceLeaky(DeviceRecordIn, arena, json, .{ .ignore_unknown_fields = true });

    // Decode exactly as fetchPeerDevices does, then let the CORE decide who is real.
    const Dec = std.base64.standard.Decoder;
    const kp_bytes = try arena.alloc(u8, try Dec.calcSizeForSlice(back.keyPackage));
    try Dec.decode(kp_bytes, back.keyPackage);
    const sig_bytes = try arena.alloc(u8, try Dec.calcSizeForSlice(back.anchorKeySig));
    try Dec.decode(sig_bytes, back.anchorKeySig);
    const appr_bytes = try arena.alloc(u8, try Dec.calcSizeForSlice(back.approvalSig));
    try Dec.decode(appr_bytes, back.approvalSig);

    // The root's own record, so the phone has somebody to be vouched for BY.
    const root_bundle = try mls.generateKeyPackage(arena, did, root_seed, 0, 4102444800, .{
        .init_seed = [_]u8{0x60} ** 32,
        .enc_seed = [_]u8{0x70} ** 32,
    });
    const root_binding = try anchor.signDidBinding(root_seed, did);

    const set = try keydir.resolveDevices(arena, did, &.{
        .{
            .did = did,
            .cipher_suite = mls.cipher_suite_id,
            .key_package = root_bundle.bytes,
            .anchor_sig = &root_binding,
            .not_after = 4_102_444_800,
            .root = true,
            .approval_sig = "",
            .created_at = 100,
        },
        .{
            .did = back.did,
            .cipher_suite = back.cipherSuite,
            .key_package = kp_bytes,
            .anchor_sig = sig_bytes,
            .not_after = try feed_core.parseTimestamp(back.notAfter),
            .root = back.root,
            .approval_sig = appr_bytes,
            .created_at = try feed_core.parseTimestamp(back.createdAt),
        },
    }, 1_751_400_000);

    // Both devices survive the wire: the account has a desktop AND a phone.
    try testing.expectEqual(@as(usize, 2), set.devices.len);
    try testing.expectEqualSlices(u8, &(try anchor.publicKey(root_seed)), &set.root_pub);
    try testing.expectEqualStrings("Pixel 10 Pro", back.deviceName);
}

test "chat_keys: a device's rkey is derived from its own key, and is its own" {
    // A device can compute its own rkey from nothing but its keys — and cannot
    // land on another device's slot, which is what makes "no device overwrites
    // another" a property of the addressing rather than a promise.
    var a_buf: [32]u8 = undefined;
    var b_buf: [32]u8 = undefined;
    const a = deviceId(&a_buf, try anchor.publicKey([_]u8{0x11} ** 32));
    const b = deviceId(&b_buf, try anchor.publicKey([_]u8{0x12} ** 32));
    try testing.expectEqual(@as(usize, 16), a.len);
    try testing.expect(!std.mem.eql(u8, a, b));

    var again: [32]u8 = undefined;
    try testing.expectEqualStrings(a, deviceId(&again, try anchor.publicKey([_]u8{0x11} ** 32)));
    for (a) |c| try testing.expect(std.ascii.isLower(c) or std.ascii.isDigit(c)); // URL-safe rkey
}
