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

//! B1 classification: SHELL (network + keystore + clock). The payment-
//! address directory's network leg (ZAT_CHAT_ROADMAP PART II §3, slice A2):
//! publish OUR `app.zat4.pay.address` record, fetch a PAYEE's, and hand
//! every decoded value to `core/payaddr.zig` for the verdict — this file
//! owns JSON, base64, and timestamps; the core owns meaning (D3). The
//! module mirrors `shell/chat_keys.zig` deliberately: same record idiom,
//! same singleton-at-rkey-"self" publish, same fetch-and-gate shape.
//!
//! Publish REFUSES a malformed address before anything leaves the machine:
//! the owner typing their own address wrong is the likeliest money-losing
//! failure in the whole feature, and the full checksum validation exists
//! exactly for that moment.
//!
//! Fetch validates against the anchor key the caller already PINS (the
//! E2EE conversation's peer anchor — payments are in-thread). The record's
//! own repo is never asked to vouch for itself.

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
const payaddr = @import("../core/payaddr.zig");
const anchor = @import("../core/anchor.zig");

/// The WRITE shape. Absent rails are omitted from the JSON, not written as
/// empty strings. A7.2: cold record struct, size guard waived.
const PayAddressRecordOut = struct {
    @"$type": []const u8 = lexicon.collection.pay_address,
    did: []const u8,
    lightning: ?[]const u8,
    bitcoin: ?[]const u8,
    anchorKeySig: []const u8, // base64(anchor signature over the binding)
    createdAt: []const u8,
};

/// The READ shape (defaulted — absent fields fail validation downstream,
/// never here, E4). A7.2: cold parse target, size guard waived.
const PayAddressRecordIn = struct {
    did: []const u8 = "",
    lightning: []const u8 = "",
    bitcoin: []const u8 = "",
    anchorKeySig: []const u8 = "",
    createdAt: []const u8 = "",
};

/// A7.2: cold result, size guard waived. Slices live in the caller's arena.
pub const Published = struct {
    uri: []const u8,
    cid: []const u8,
};

/// A7.2: cold result, size guard waived. Arena-owned.
pub const OwnAddresses = struct {
    lightning: []const u8 = "",
    bitcoin: []const u8 = "",
};

/// Read MY OWN receive record, to answer "have I set up payments?" and to
/// prefill the setup sheet. NO anchor validation: the anchor check exists so a
/// PAYER can trust a payee's record — reading my own record for my own UI is not
/// that trust boundary. `null` = no record published (= not set up yet, E4).
pub fn fetchOwn(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    did: []const u8,
) !?OwnAddresses {
    const pds_url = try identity.pdsForDid(gpa, io, environ, .{}, did);
    defer gpa.free(pds_url);
    const params = [_]xrpc.Param{
        .{ .name = "repo", .value = did },
        .{ .name = "collection", .value = lexicon.collection.pay_address },
        .{ .name = "rkey", .value = "self" },
    };
    const outcome = try net.query(arena, io, environ, pds_url, lexicon.method.get_record, &params, lexicon.GetRecordResponse(PayAddressRecordIn), .{ .guard = .untrusted });
    const rec = switch (outcome) {
        .ok => |r| r.value,
        .failed => return null,
    };
    if (rec.lightning.len == 0 and rec.bitcoin.len == 0) return null;
    return .{ .lightning = rec.lightning, .bitcoin = rec.bitcoin };
}

pub const PublishError = error{
    NoAddresses,
    BadLightning,
    BadBitcoin,
    NoAnchor,
    SignFailed,
    PublishFailed,
    OutOfMemory,
};

/// Publish (or overwrite — putRecord at rkey "self" is idempotent) this
/// account's payment addresses. Either rail may be empty, not both.
pub fn publish(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    lightning: []const u8,
    bitcoin: []const u8,
) !Published {
    // The local gate FIRST: never publish an address a wallet would refuse
    // (or worse, one it would pay). E3 by name.
    if (lightning.len == 0 and bitcoin.len == 0) return error.NoAddresses;
    if (lightning.len > 0)
        payaddr.validateLightning(lightning) catch return error.BadLightning;
    if (bitcoin.len > 0)
        payaddr.validateBitcoin(bitcoin) catch return error.BadBitcoin;

    const did = session.did;
    var anchor_load = cache.loadOrCreateAnchorSeed(gpa, io, environ, did) orelse
        return error.NoAnchor;
    defer std.crypto.secureZero(u8, &anchor_load.seed);

    var ca_buf: [24]u8 = undefined;
    const created = feed_core.formatTimestamp(&ca_buf, clock.unixSeconds());
    const sig = payaddr.signBinding(anchor_load.seed, did, created, lightning, bitcoin) catch
        return error.SignFailed;

    const Enc = std.base64.standard.Encoder;
    const sig_b64 = try arena.alloc(u8, Enc.calcSize(sig.len));
    _ = Enc.encode(sig_b64, &sig);

    const record = PayAddressRecordOut{
        .did = did,
        .lightning = if (lightning.len > 0) lightning else null,
        .bitcoin = if (bitcoin.len > 0) bitcoin else null,
        .anchorKeySig = sig_b64,
        .createdAt = created,
    };
    const input = lexicon.PutRecordInput(@TypeOf(record)){
        .repo = did,
        .collection = lexicon.collection.pay_address,
        .rkey = "self",
        .record = record,
    };
    const outcome = try auth.procedure(gpa, arena, io, environ, session, lexicon.method.put_record, input, lexicon.RecordRef);
    return switch (outcome) {
        .ok => |r| .{ .uri = try arena.dupe(u8, r.uri), .cid = try arena.dupe(u8, r.cid) },
        .failed => error.PublishFailed,
    };
}

/// Fetch + validate `did`'s payment addresses: resolve the DID to ITS OWN
/// PDS (never a guessed host), read the public record, decode, and let the
/// core gate decide against the anchor key the caller PINS. Null = no
/// record (the payee doesn't accept payments: an ordinary result, E4 —
/// the card composer greys out, nothing errors). Every validation failure
/// is an explicit error (E3).
pub fn fetchPayee(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    did: []const u8,
    expected_anchor: [anchor.pk_len]u8,
) !?payaddr.Payee {
    const pds_url = try identity.pdsForDid(gpa, io, environ, .{}, did);
    defer gpa.free(pds_url);

    const params = [_]xrpc.Param{
        .{ .name = "repo", .value = did },
        .{ .name = "collection", .value = lexicon.collection.pay_address },
        .{ .name = "rkey", .value = "self" },
    };
    const outcome = try net.query(arena, io, environ, pds_url, lexicon.method.get_record, &params, lexicon.GetRecordResponse(PayAddressRecordIn), .{ .guard = .untrusted });
    const rec = switch (outcome) {
        .ok => |r| r.value,
        .failed => return null, // absent record = payee takes no payments (E4)
    };

    const Dec = std.base64.standard.Decoder;
    const sig_len = Dec.calcSizeForSlice(rec.anchorKeySig) catch return error.BadRecord;
    const sig_bytes = try arena.alloc(u8, sig_len);
    Dec.decode(sig_bytes, rec.anchorKeySig) catch return error.BadRecord;

    return try payaddr.validate(did, .{
        .did = rec.did,
        .lightning = rec.lightning,
        .bitcoin = rec.bitcoin,
        .created_at = rec.createdAt,
        .anchor_sig = sig_bytes,
    }, expected_anchor);
}

// ---------------------------------------------------------------------------
// Tests (C6) — the record wire mapping round-trips through the same JSON +
// base64 + validation gate a real fetch uses; the network legs are typed
// through semantic analysis by the harness (main-reachable).
// ---------------------------------------------------------------------------

const testing = std.testing;

test "pay_addr: the record round-trips JSON+base64 into payaddr's gate" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const did = "did:plc:payrecordroundtripaaaa";
    const seed: [anchor.seed_len]u8 = [_]u8{0x88} ** 32;
    const ln = "maya@wallet.example";
    const btc = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";
    const created = "2026-07-02T00:00:00Z";
    const sig = try payaddr.signBinding(seed, did, created, ln, btc);

    const Enc = std.base64.standard.Encoder;
    const sig_b64 = try arena.alloc(u8, Enc.calcSize(sig.len));
    _ = Enc.encode(sig_b64, &sig);

    const out = PayAddressRecordOut{
        .did = did,
        .lightning = ln,
        .bitcoin = btc,
        .anchorKeySig = sig_b64,
        .createdAt = created,
    };
    const json = try std.json.Stringify.valueAlloc(arena, out, .{ .emit_null_optional_fields = false });
    const back = try std.json.parseFromSliceLeaky(PayAddressRecordIn, arena, json, .{ .ignore_unknown_fields = true });

    // Decode exactly as fetchPayee does and pass the core gate.
    const Dec = std.base64.standard.Decoder;
    const sig_bytes = try arena.alloc(u8, try Dec.calcSizeForSlice(back.anchorKeySig));
    try Dec.decode(sig_bytes, back.anchorKeySig);
    const payee = try payaddr.validate(did, .{
        .did = back.did,
        .lightning = back.lightning,
        .bitcoin = back.bitcoin,
        .created_at = back.createdAt,
        .anchor_sig = sig_bytes,
    }, try anchor.publicKey(seed));
    try testing.expectEqualStrings(ln, payee.lightning);
    try testing.expectEqualStrings(btc, payee.bitcoin);
}

test "pay_addr: a one-rail record omits the absent rail from the JSON" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const out = PayAddressRecordOut{
        .did = "did:plc:x",
        .lightning = "maya@wallet.example",
        .bitcoin = null,
        .anchorKeySig = "sig",
        .createdAt = "2026-07-02T00:00:00Z",
    };
    const json = try std.json.Stringify.valueAlloc(arena, out, .{ .emit_null_optional_fields = false });
    try testing.expect(std.mem.indexOf(u8, json, "bitcoin") == null);
    const back = try std.json.parseFromSliceLeaky(PayAddressRecordIn, arena, json, .{ .ignore_unknown_fields = true });
    try testing.expectEqual(@as(usize, 0), back.bitcoin.len); // absent → default empty
    try testing.expectEqualStrings("maya@wallet.example", back.lightning);
}

test "pay_addr: publish refuses a typo'd address before anything leaves" {
    // The local gate is pure-core validation; prove the wiring refuses by
    // name without a session (the checks run before any network or keystore
    // touch — a bad address must fail regardless).
    try testing.expectError(error.BadAddress, payaddr.validateBitcoin("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5"));
    try testing.expectError(error.BadAddress, payaddr.validateLightning("not-an-address"));
}
