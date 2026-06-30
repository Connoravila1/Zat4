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
const feed_core = @import("../core/feed.zig");
const xrpc = @import("../core/xrpc.zig");

/// The published record (WRITE shape, `*Out` convention — `$type` set, no
/// defaults): a named algorithm = its config + when it was published.
/// A7.2: cold build target, size guard waived.
const AlgorithmRecordOut = struct {
    @"$type": []const u8 = lexicon.collection.algorithm,
    name: []const u8,
    config: discover.FeedConfig,
    createdAt: []const u8,
};

/// The READ shape (all defaulted — absent fields degrade to the default config,
/// E4). A7.2: cold parse target, size guard waived.
const AlgorithmRecord = struct {
    name: []const u8 = "",
    config: discover.FeedConfig = .{},
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
        .config = discover.validated(config),
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
        .ok => |r| discover.validated(r.value.config), // never trust the wire (D5)
        .failed => null,
    };
}

// ---------------------------------------------------------------------------
// Tests — the pure record↔config mapping is leak-checked (C6); the network
// functions are forced through semantic analysis so they cannot rot.
// ---------------------------------------------------------------------------

test "algorithm record embeds the config and round-trips through the put/get JSON shape" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var cfg = discover.DEFAULT_CONFIG;
    cfg.w_reply = 33.0;
    cfg.velocity_boost = false;
    cfg.query.source_mix = 0.2;

    const out = AlgorithmRecordOut{ .name = "My Feed", .config = cfg, .createdAt = "2026-06-30T00:00:00Z" };
    const json = try std.json.Stringify.valueAlloc(arena, out, .{ .emit_null_optional_fields = false });
    const back = try std.json.parseFromSliceLeaky(AlgorithmRecord, arena, json, .{ .ignore_unknown_fields = true });

    try t.expectEqualStrings("My Feed", back.name);
    try t.expectEqual(@as(f32, 33.0), back.config.w_reply);
    try t.expectEqual(false, back.config.velocity_boost);
    try t.expectEqual(@as(f32, 0.2), back.config.query.source_mix);
    // The $type marks it as an algorithm record in the repo.
    try t.expect(std.mem.indexOf(u8, json, lexicon.collection.algorithm) != null);
}

test "publish/fetch compile and stay type-correct (network leg)" {
    // The live round-trip needs a session + PDS; here we only force the network
    // functions through analysis so a signature drift fails the build, not a
    // surprise at runtime.
    _ = &publish;
    _ = &fetch;
}
