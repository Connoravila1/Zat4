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

//! B1 classification: SHELL (network I/O). **Publish & import a feed algorithm
//! — Phase D5 network leg.** The thin I/O over the pure config: writes a
//! `discover.FeedConfig` as a record in the user's own repo (collection
//! `app.zat4.feed.algorithm`) and fetches one back, over the SAME authed XRPC
//! path the loadout and the rest of the writes use.
//!
//! The record EMBEDS the config as typed fields (not a JSON string), so the
//! record the PDS stores — and the CID it is addressed by — IS the algorithm
//! (invariant 5: what a user inspects/fetches is byte-identical to what runs).
//! A fetched config is `discover.validated` before it is ever returned, so a
//! malformed or hostile shared record is just bad data clamped to something safe
//! (E2/E4) — never a crash, never an unbounded weight.
//!
//! The pure record↔config shape and the human-readable export/paste form live
//! in the core (`core/algorithm.zig`); this module is only the network leg.
//! Deferred (the larger marketplace, F4): browsing OTHER users' algorithm
//! records (needs an AppView index over the collection), and adding a fetched
//! algorithm to the lens tray (the loadout/UI). This is the foundation they sit
//! on — publish and fetch-by-ref work; discovery and the tray come with the UI.

const std = @import("std");
const Allocator = std.mem.Allocator;
const auth = @import("auth.zig");
const lexicon = @import("../core/lexicon.zig");
const discover = @import("../core/discover.zig");
const algorithm_core = @import("../core/algorithm.zig");
const feed_core = @import("../core/feed.zig");
const xrpc = @import("../core/xrpc.zig");
const net = @import("xrpc.zig"); // the shell XRPC transport (unauthenticated reads)

/// The published record (WRITE shape, `*Out` convention — `$type` set, no
/// defaults): a named algorithm = its config + when it was published.
///
/// `config` is the algorithm's SERIALIZED form (core/algorithm.serialize), NOT
/// typed fields: the atproto data model forbids floating-point values in records
/// (a PDS rejects `0.5` with InvalidRequest), and a FeedConfig is all `f32`
/// weights. The serialized string is byte-exact and is itself the transparency
/// artifact (the CID commits to it — invariant 5), so nesting it as a string is
/// the atproto-legal shape, not a workaround that weakens transparency.
/// A7.2: cold build target, size guard waived.
const AlgorithmRecordOut = struct {
    @"$type": []const u8 = lexicon.collection.algorithm,
    name: []const u8,
    config: []const u8, // serialized FeedConfig (see above)
    createdAt: []const u8,
};

/// The READ shape (all defaulted — absent fields degrade to an empty config
/// string, which `parse` maps to the default, E4). A7.2: cold parse target.
const AlgorithmRecord = struct {
    name: []const u8 = "",
    config: []const u8 = "", // serialized FeedConfig
    createdAt: []const u8 = "",
};

/// What a publish returns: the record's at:// uri (its reference) and its CID
/// (its transparency anchor — what a user verifies, invariant 5). Slices live
/// in the caller's arena. A7.2: cold result, size guard waived.
pub const Published = struct {
    uri: []const u8,
    cid: []const u8,
};

/// Publish a config as an algorithm record in the user's repo at `rkey`
/// (a user can hold many — `rkey` is the per-algorithm key, not a singleton).
/// The config is `validated` before publishing, so you cannot publish a NaN.
/// Returns the uri + CID; a write failure is an explicit error (E3).
pub fn publish(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    name: []const u8,
    config: discover.FeedConfig,
    rkey: []const u8,
    now_epoch: i64,
) !Published {
    // DEFERRED SECURITY (SECURITY_ROADMAP Phase 12): publish-time validation gate.
    // `validated` below silently clamps/clips/drops a malformed config so we never
    // publish unsafe data — but when the authoring UI lands, also REJECT a
    // malformed program / over-cap rule-list here with a clear error to the author,
    // rather than letting it degrade to a no-op on every reader's device.
    var ts_buf: [24]u8 = undefined;
    const record = AlgorithmRecordOut{
        .name = name,
        // Serialize the VALIDATED config to its atproto-legal string form (no
        // floats on the wire). `serialize` runs on the sanitized config so a NaN
        // can never be published.
        .config = try algorithm_core.serialize(arena, discover.validated(config)),
        .createdAt = feed_core.formatTimestamp(&ts_buf, now_epoch),
    };
    const input = lexicon.PutRecordInput(@TypeOf(record)){
        .repo = session.did,
        .collection = lexicon.collection.algorithm,
        .rkey = rkey,
        .record = record,
    };
    const outcome = try auth.procedure(
        gpa,
        arena,
        io,
        environ,
        session,
        lexicon.method.put_record,
        input,
        lexicon.RecordRef,
    );
    return switch (outcome) {
        .ok => |r| .{ .uri = try arena.dupe(u8, r.uri), .cid = try arena.dupe(u8, r.cid) },
        .failed => error.PublishFailed,
    };
}

/// Fetch and import an algorithm record by (repo, rkey), returning its
/// VALIDATED config ready to run — or null when there is no such record or the
/// read fails (an ordinary result; the caller falls back to a built-in, E4).
/// The same engine runs it: there is no second code path for a fetched config
/// vs a built-in (D6, invariant 1).
pub fn fetch(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    repo: []const u8,
    rkey: []const u8,
) !?discover.FeedConfig {
    const params = [_]xrpc.Param{
        .{ .name = "repo", .value = repo },
        .{ .name = "collection", .value = lexicon.collection.algorithm },
        .{ .name = "rkey", .value = rkey },
    };
    // DEFERRED SECURITY (SECURITY_ROADMAP Phase 12): bound the response size
    // BEFORE the JSON is parsed/allocated. A hostile algorithm record could carry
    // a huge rules/vm_program array; `discover.validated` clips it, but only AFTER
    // std.json has already allocated it. When the marketplace lands, add an
    // explicit max-record-size guard at this fetch (the "bound before allocate"
    // rule). Bounded today by PDS record-size limits — do not rely on that.
    const outcome = try auth.query(
        gpa,
        arena,
        io,
        environ,
        session,
        lexicon.method.get_record,
        &params,
        lexicon.GetRecordResponse(AlgorithmRecord),
    );
    return switch (outcome) {
        // Parse the serialized config string; `parse` is depth-guarded, validated,
        // and falls back to DEFAULT on malformed/hostile input (never trust the wire).
        .ok => |r| try algorithm_core.parse(arena, r.value.config),
        .failed => null,
    };
}

/// Fetch an algorithm's config by (repo, rkey) over an UNAUTHENTICATED public
/// `getRecord` — a public repo read needs no session, so this can run on a WORKER
/// THREAD without touching the shared, mutable `auth.Session` (that is what the
/// marketplace "View details" fetch does, off the UI thread). Returns the
/// validated config, or null on a failed/absent read (E4, the caller falls back).
/// `pds_url` is the record's host; the SSRF guard is on (network content).
/// DEFERRED SECURITY (Phase 12): bound the response size before parse — same note
/// as `fetch` above; `parse` clips after std.json allocates.
pub fn fetchPublic(
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    pds_url: []const u8,
    repo: []const u8,
    rkey: []const u8,
) !?discover.FeedConfig {
    const params = [_]xrpc.Param{
        .{ .name = "repo", .value = repo },
        .{ .name = "collection", .value = lexicon.collection.algorithm },
        .{ .name = "rkey", .value = rkey },
    };
    const outcome = try net.query(arena, io, environ, pds_url, lexicon.method.get_record, &params, lexicon.GetRecordResponse(AlgorithmRecord), .{ .guard = .untrusted });
    return switch (outcome) {
        .ok => |r| algorithm_core.parse(arena, r.value.config) catch discover.DEFAULT_CONFIG,
        .failed => null,
    };
}

// ---------------------------------------------------------------------------
// Tests — the pure record↔config mapping is leak-checked (C6); the network
// functions are forced through semantic analysis so they cannot rot.
// ---------------------------------------------------------------------------

test "algorithm record carries the SERIALIZED config (no floats on the wire) and round-trips" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const retrieval = @import("../core/retrieval.zig");
    var cfg = discover.DEFAULT_CONFIG;
    cfg.w_reply = 33.0;
    cfg.velocity_boost = false;
    cfg.query.source_mix = 0.2;
    // A Phase-0 retrieval query rides with the config too (it IS part of the algorithm).
    const srcs = [_]retrieval.Source{
        .{ .kind = .follows, .weight = 2.0 },
        .{ .kind = .trending, .weight = 0.5, .threshold = 100 },
        .{ .kind = .tag_scope, .weight = 1.5, .tag = "zig" },
    };
    cfg.query.sources = &srcs;

    // The record carries the config as its serialized string — atproto forbids
    // floats in records, so the whole (float-bearing) config rides as one string.
    const out = AlgorithmRecordOut{ .name = "My Feed", .config = try algorithm_core.serialize(arena, cfg), .createdAt = "2026-06-30T00:00:00Z" };
    const json = try std.json.Stringify.valueAlloc(arena, out, .{ .emit_null_optional_fields = false });

    // The record's JSON must contain NO bare float — every number is inside the
    // quoted config string, so the PDS's "no floats" rule is satisfied. (A crude
    // but effective check: the top-level shape has name/config/createdAt strings.)
    const back = try std.json.parseFromSliceLeaky(AlgorithmRecord, arena, json, .{ .ignore_unknown_fields = true });
    try t.expectEqualStrings("My Feed", back.name);

    // The serialized config parses back to the same values (byte-exact transparency).
    const parsed = try algorithm_core.parse(arena, back.config);
    try t.expectEqual(@as(f32, 33.0), parsed.w_reply);
    try t.expectEqual(false, parsed.velocity_boost);
    try t.expectEqual(@as(f32, 0.2), parsed.query.source_mix);
    // The retrieval sources survive the round-trip intact (kind + weight + threshold + tag).
    try t.expectEqual(@as(usize, 3), parsed.query.sources.len);
    try t.expectEqual(retrieval.SourceKind.follows, parsed.query.sources[0].kind);
    try t.expectEqual(@as(f32, 2.0), parsed.query.sources[0].weight);
    try t.expectEqual(retrieval.SourceKind.trending, parsed.query.sources[1].kind);
    try t.expectEqual(@as(f32, 100), parsed.query.sources[1].threshold);
    try t.expectEqual(retrieval.SourceKind.tag_scope, parsed.query.sources[2].kind);
    try t.expectEqualStrings("zig", parsed.query.sources[2].tag);
    // The $type marks it as an algorithm record in the repo.
    try t.expect(std.mem.indexOf(u8, json, lexicon.collection.algorithm) != null);
}

test "publish/fetch compile and stay type-correct (network leg)" {
    // The live round-trip needs a session + PDS; here we only force the network
    // functions through analysis so a signature drift fails the build, not a
    // surprise at runtime.
    _ = &publish;
    _ = &fetch;
    _ = &fetchPublic;
}
