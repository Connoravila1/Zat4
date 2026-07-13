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
