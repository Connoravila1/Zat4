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

//! B1 classification: SHELL (network I/O). The AppView's PDS-polling ingester.
//!
//! Bluesky's public Jetstream is LIVE-ONLY and was not built for custom-lexicon
//! backfill/discovery, so the AppView cannot find `app.zat4.*` content there.
//! The relay (`bsky.network`) IS lexicon-agnostic and carries our records, so
//! the proper firehose path is our own Jetstream against it (or Tap) — the
//! scale-up recorded in STANDALONE_ROADMAP / PDS_ROADMAP.
//!
//! Until then, this reads a repo's `app.zat4.*` records DIRECTLY from its PDS
//! via `com.atproto.repo.listRecords` (a PUBLIC read, no auth) and indexes new
//! ones: posts, follows, likes, reposts. `indexPost` dedups by cid, but
//! `indexFollow`/`indexEngagement` are append/bump — so polling re-reads them
//! every cycle, the caller's `seen` set (record-cid hashes) makes those applied
//! exactly once. Correct + cheap for a small/known author set; it does not scale
//! to the whole network (that is the firehose's job).

const std = @import("std");
const Allocator = std.mem.Allocator;
const xrpc = @import("xrpc.zig");
const lexicon = @import("../core/lexicon.zig");
const feed = @import("../core/feed.zig");
const appview = @import("../core/appview.zig");
const record_check = @import("../core/record_check.zig");
const serve = @import("appview_serve.zig");
const store = @import("appview_store.zig");

/// A follow record's value: `subject` is the followed DID (a bare string).
/// A7.2: cold transient parse target (one per record, never held in quantity).
const FollowValue = struct { subject: []const u8 = "" };
/// A like/repost record's `subject` strong ref (we want its cid).
/// A7.2: cold transient parse target.
const SubjectRef = struct { cid: []const u8 = "" };
/// A like/repost record's value. A7.2: cold transient parse target.
const RefValue = struct { subject: SubjectRef = .{} };
/// An `app.zat4.actor.profile` record's value — the display name (avatar is a
/// blob, deferred). A7.2: cold transient parse target.
const ProfileValue = struct { displayName: []const u8 = "" };

/// One `listRecords` entry over a record value of type `Value`.
fn Rec(comptime Value: type) type {
    return struct { uri: []const u8 = "", cid: []const u8 = "", value: Value = .{} };
}
/// The `com.atproto.repo.listRecords` response over a record value type.
fn Listing(comptime Value: type) type {
    return struct { records: []const Rec(Value) = &.{}, cursor: ?[]const u8 = null };
}

/// List one collection of a repo (public read, no auth). Returns the records,
/// or null on a refused/failed read (the caller skips that collection this
/// cycle; E2). Cut-1 reads the first page (limit 100) — pagination is a noted
/// follow-up when a single author exceeds it.
fn fetch(
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    pds_url: []const u8,
    did: []const u8,
    collection: []const u8,
    comptime Value: type,
) !?struct { records: []const Rec(Value), raw: []const u8 } {
    const params = [_]xrpc.Param{
        .{ .name = "repo", .value = did },
        .{ .name = "collection", .value = collection },
        .{ .name = "limit", .value = "100" },
    };
    // Capture the raw 2xx body alongside the typed records: the same bytes are
    // re-hashed to verify each record's CID against the PDS's claim (the trust
    // boundary — see verifyCids / record_check). One fetch, both uses.
    const captured = try xrpc.queryCapturingBody(arena, io, environ, pds_url, lexicon.method.list_records, &params, Listing(Value), .{});
    return switch (captured.outcome) {
        .ok => |r| .{ .records = r.records, .raw = captured.body },
        .failed => null,
    };
}

/// Re-derive and check every record CID in a raw listRecords body against the
/// PDS's claim (verify-don't-trust). LOG-ONLY for now: a mismatch is reported
/// to the journal but the record is still indexed, so we confirm our DAG-CBOR
/// reproduces every legitimate record's CID on real data BEFORE promoting this
/// to a hard reject. `total_bad` accumulates across a poll cycle for the
/// per-repo summary. Pure check; only the logging is a side effect (B3 — this
/// is the shell). Commit-signature verification (proving repo authorship) needs
/// the signed firehose commit and stays gated on the Tap cutover.
fn verifyCids(
    gpa: Allocator,
    raw: []const u8,
    did: []const u8,
    collection: []const u8,
    total_checked: *usize,
    total_bad: *usize,
) void {
    const report = record_check.checkListRecords(gpa, raw);
    total_checked.* += report.checked;
    total_bad.* += record_check.badCount(report);
    if (record_check.badCount(report) > 0) {
        std.debug.print(
            "[verify] CID MISMATCH {s} {s}: {d} checked, {d} mismatch, {d} unverifiable (first bad: {s})\n",
            .{ did, collection, report.checked, report.mismatched, report.unverifiable, record_check.firstBad(&report) },
        );
    }
}

/// True if `cid` was ALREADY applied (caller skips); otherwise records it. Keyed
/// by a 64-bit hash of the record cid — no string storage; collision risk is
/// negligible. Owned by the poll thread only, so no index lock needed.
fn markSeen(gpa: Allocator, seen: *std.AutoHashMapUnmanaged(u64, void), cid: []const u8) Allocator.Error!bool {
    const gop = try seen.getOrPut(gpa, store.seenKey(cid));
    return gop.found_existing;
}

/// The record key (last path segment) of an at-uri, e.g.
/// `at://did/app.zat4.feed.post/3kabc` → `3kabc`. The durable post line needs
/// it (the reducer rebuilds the uri from rkey); "" if the uri has no segment.
fn rkeyFromUri(uri: []const u8) []const u8 {
    const slash = std.mem.lastIndexOfScalar(u8, uri, '/') orelse return "";
    return uri[slash + 1 ..];
}

/// Poll one repo's `app.zat4.*` collections and index new records into `idx`
/// (under `lock`, since the serve thread reads concurrently). Returns the number
/// of new POSTS indexed (the headline count; follows/likes/reposts apply
/// silently). A failed read of one collection is skipped (E2). Strings are read
/// from `arena`, which the caller resets per poll; `seen` persists across calls.
pub fn pollRepo(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    pds_url: []const u8,
    did: []const u8,
    idx: *appview.Index,
    lock: *serve.IndexLock,
    seen: *std.AutoHashMapUnmanaged(u64, void),
    log: *store.Store,
) !usize {
    var added: usize = 0;
    // Trust-boundary CID verification tallies for this poll cycle (log-only).
    var v_checked: usize = 0;
    var v_bad: usize = 0;

    // Identity: resolve this author's DID → handle (describeRepo, a public read)
    // AND display name (their app.zat4.actor.profile record) ONCE, so posts serve
    // `@handle` + a human name instead of the DID. Gated on "handle not yet known"
    // so it costs ~two requests per author for the AppView's life, not per poll
    // cycle (G3). Both are persisted (appendIdentity) so a restart restores them
    // via replay — no re-resolve on boot. A failed/unverified resolve simply
    // leaves the DID showing (E2/E4).
    {
        lock.lock();
        const need_handle = appview.handleFor(idx, did).len == 0;
        lock.unlock();
        // The HANDLE resolves once (describeRepo — it won't change). The DISPLAY
        // NAME is re-fetched EACH cycle so a CHANGED profile name propagates (not
        // just a first-time one — the in-app editor relies on this), but it is
        // only WRITTEN when it actually differs, so setDisplayName + appendIdentity
        // (and the durable log) don't churn. One tiny listRecords per author per
        // cycle; throttle-able with a "tried recently" marker at network scale.
        var handle: []const u8 = "";
        if (need_handle) {
            const params = [_]xrpc.Param{.{ .name = "repo", .value = did }};
            const outcome = xrpc.query(arena, io, environ, pds_url, lexicon.method.describe_repo, &params, lexicon.RepoDescription, .{}) catch null;
            if (outcome) |o| switch (o) {
                .ok => |desc| if (desc.handle.len > 0 and desc.handleIsCorrect) {
                    handle = desc.handle;
                },
                .failed => {},
            };
        }
        var fetched_name: []const u8 = "";
        if (try fetch(arena, io, environ, pds_url, did, lexicon.collection.profile, ProfileValue)) |f| {
            verifyCids(gpa, f.raw, did, "profile", &v_checked, &v_bad);
            if (f.records.len > 0) fetched_name = f.records[0].value.displayName;
        }
        if (handle.len > 0 or fetched_name.len > 0) {
            lock.lock();
            if (handle.len > 0) appview.setHandle(gpa, idx, did, handle) catch {};
            // Compare under the lock; only write (and log) a genuine change.
            const name_changed = fetched_name.len > 0 and !std.mem.eql(u8, appview.displayNameFor(idx, did), fetched_name);
            if (name_changed) appview.setDisplayName(gpa, idx, did, fetched_name) catch {};
            lock.unlock();
            if (handle.len > 0 or name_changed) store.appendIdentity(log, arena, did, handle, if (name_changed) fetched_name else "");
        }
    }

    // Posts — indexPost dedups by cid, so this is idempotent on its own. A
    // newly-indexed post is also appended to the durable log (keyed by its cid)
    // so it survives a restart without a re-poll. (The append rides inside the
    // index lock; at Cut-1 author/post rates the write is trivial — G3.)
    if (try fetch(arena, io, environ, pds_url, did, lexicon.collection.post, lexicon.PostRecord)) |f| {
        verifyCids(gpa, f.raw, did, "post", &v_checked, &v_bad);
        lock.lock();
        defer lock.unlock();
        for (f.records) |r| {
            if (r.cid.len == 0) continue;
            const reply_parent_cid: []const u8 = if (r.value.reply) |rep| rep.parent.cid else "";
            const reply_root_cid: []const u8 = if (r.value.reply) |rep| rep.root.cid else "";
            const is_new = appview.indexPost(gpa, idx, .{
                .cid = r.cid,
                .author_did = did,
                .text = r.value.text,
                .created_at = feed.parseTimestamp(r.value.createdAt) catch 0,
                .reply_parent_cid = reply_parent_cid,
                .reply_root_cid = reply_root_cid,
            }) catch false;
            if (is_new) {
                added += 1;
                // Carry the reply refs into the durable log so a restart's
                // replay (jetstream.reduce) restores the linkage too.
                store.appendPost(log, arena, did, rkeyFromUri(r.uri), r.cid, r.value.text, r.value.createdAt, r.value.reply);
            }
        }
    }

    // Follows — indexFollow appends, so gate on the follow record's cid; a
    // newly-applied edge is persisted, and replay refills `seen` from it.
    if (try fetch(arena, io, environ, pds_url, did, lexicon.collection.follow, FollowValue)) |f| {
        verifyCids(gpa, f.raw, did, "follow", &v_checked, &v_bad);
        lock.lock();
        defer lock.unlock();
        for (f.records) |r| {
            if (r.cid.len == 0 or r.value.subject.len == 0) continue;
            if (try markSeen(gpa, seen, r.cid)) continue;
            appview.indexFollow(gpa, idx, did, r.value.subject) catch {};
            store.appendFollow(log, arena, did, r.value.subject, r.cid);
        }
    }

    // Likes — fully edge-managed: setLikeEdge maintains both the count and the
    // viewer.like uri (the single source of truth).
    if (try fetch(arena, io, environ, pds_url, did, lexicon.collection.like, RefValue)) |f| {
        verifyCids(gpa, f.raw, did, "like", &v_checked, &v_bad);
        lock.lock();
        defer lock.unlock();
        // Reconcile this actor's like edges with their CURRENT records: drop the
        // old set, then re-add what they still like below. A poll sees creates,
        // not deletes, so without this an UNLIKE would leave a stale edge (and a
        // stale count) that re-fills the heart on the next refresh.
        appview.clearLikeEdgesForActor(gpa, idx, did);
        for (f.records) |r| {
            if (r.cid.len == 0 or r.value.subject.cid.len == 0) continue;
            // setLikeEdge is idempotent and maintains the count; run it every
            // poll so prior-session likes are known (viewer.like) and un-likeable.
            appview.setLikeEdge(gpa, idx, did, r.value.subject.cid, r.uri) catch {};
            // The durable log still records each like once (replay rebuilds the
            // edge); gate that append on the record cid so the log stays compact.
            if (try markSeen(gpa, seen, r.cid)) continue;
            store.appendEngagement(log, arena, .like, did, r.value.subject.cid, r.cid, r.uri);
        }
    }

    // Reposts — same idempotency gate as likes.
    if (try fetch(arena, io, environ, pds_url, did, lexicon.collection.repost, RefValue)) |f| {
        verifyCids(gpa, f.raw, did, "repost", &v_checked, &v_bad);
        lock.lock();
        defer lock.unlock();
        for (f.records) |r| {
            if (r.cid.len == 0 or r.value.subject.cid.len == 0) continue;
            if (try markSeen(gpa, seen, r.cid)) continue;
            appview.indexEngagement(gpa, idx, .repost, r.value.subject.cid) catch {};
            store.appendEngagement(log, arena, .repost, did, r.value.subject.cid, r.cid, r.uri);
        }
    }

    // Per-repo trust-boundary summary (TEMP, log-only phase): positive proof the
    // check is running on real data. Anomalies already logged inline above. This
    // line goes away when CID verification is promoted to a hard reject.
    if (v_checked > 0) {
        std.debug.print("[verify] {s}: {d} record CIDs checked, {d} bad (log-only)\n", .{ did, v_checked, v_bad });
    }

    return added;
}

test {
    std.testing.refAllDecls(@This());
}
