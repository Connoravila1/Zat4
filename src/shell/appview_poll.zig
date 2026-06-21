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
) !?[]const Rec(Value) {
    const params = [_]xrpc.Param{
        .{ .name = "repo", .value = did },
        .{ .name = "collection", .value = collection },
        .{ .name = "limit", .value = "100" },
    };
    const outcome = try xrpc.query(arena, io, environ, pds_url, lexicon.method.list_records, &params, Listing(Value), .{});
    return switch (outcome) {
        .ok => |r| r.records,
        .failed => null,
    };
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

    // Handle: resolve this author's DID → handle ONCE (describeRepo is a public
    // read on the PDS), so posts serve `@handle` instead of the DID. Gated on
    // "not yet known" so it costs one request per author for the AppView's life,
    // not per poll cycle (G3). The verified handle is persisted (appendHandle)
    // so a restart restores it via replay — no re-resolve on boot. A failed or
    // unverified resolve simply leaves the DID showing (E2/E4).
    {
        lock.lock();
        const known = appview.handleFor(idx, did).len > 0;
        lock.unlock();
        if (!known) {
            const params = [_]xrpc.Param{.{ .name = "repo", .value = did }};
            const outcome = xrpc.query(arena, io, environ, pds_url, lexicon.method.describe_repo, &params, lexicon.RepoDescription, .{}) catch null;
            if (outcome) |o| switch (o) {
                .ok => |desc| if (desc.handle.len > 0 and desc.handleIsCorrect) {
                    lock.lock();
                    appview.setHandle(gpa, idx, did, desc.handle) catch {};
                    lock.unlock();
                    store.appendHandle(log, arena, did, desc.handle);
                },
                .failed => {},
            };
        }
    }

    // Posts — indexPost dedups by cid, so this is idempotent on its own. A
    // newly-indexed post is also appended to the durable log (keyed by its cid)
    // so it survives a restart without a re-poll. (The append rides inside the
    // index lock; at Cut-1 author/post rates the write is trivial — G3.)
    if (try fetch(arena, io, environ, pds_url, did, lexicon.collection.post, lexicon.PostRecord)) |recs| {
        lock.lock();
        defer lock.unlock();
        for (recs) |r| {
            if (r.cid.len == 0) continue;
            const is_new = appview.indexPost(gpa, idx, .{
                .cid = r.cid,
                .author_did = did,
                .text = r.value.text,
                .created_at = feed.parseTimestamp(r.value.createdAt) catch 0,
            }) catch false;
            if (is_new) {
                added += 1;
                store.appendPost(log, arena, did, rkeyFromUri(r.uri), r.cid, r.value.text, r.value.createdAt);
            }
        }
    }

    // Follows — indexFollow appends, so gate on the follow record's cid; a
    // newly-applied edge is persisted, and replay refills `seen` from it.
    if (try fetch(arena, io, environ, pds_url, did, lexicon.collection.follow, FollowValue)) |recs| {
        lock.lock();
        defer lock.unlock();
        for (recs) |r| {
            if (r.cid.len == 0 or r.value.subject.len == 0) continue;
            if (try markSeen(gpa, seen, r.cid)) continue;
            appview.indexFollow(gpa, idx, did, r.value.subject) catch {};
            store.appendFollow(log, arena, did, r.value.subject, r.cid);
        }
    }

    // Likes — fully edge-managed: setLikeEdge maintains both the count and the
    // viewer.like uri (the single source of truth).
    if (try fetch(arena, io, environ, pds_url, did, lexicon.collection.like, RefValue)) |recs| {
        lock.lock();
        defer lock.unlock();
        // Reconcile this actor's like edges with their CURRENT records: drop the
        // old set, then re-add what they still like below. A poll sees creates,
        // not deletes, so without this an UNLIKE would leave a stale edge (and a
        // stale count) that re-fills the heart on the next refresh.
        appview.clearLikeEdgesForActor(gpa, idx, did);
        for (recs) |r| {
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
    if (try fetch(arena, io, environ, pds_url, did, lexicon.collection.repost, RefValue)) |recs| {
        lock.lock();
        defer lock.unlock();
        for (recs) |r| {
            if (r.cid.len == 0 or r.value.subject.cid.len == 0) continue;
            if (try markSeen(gpa, seen, r.cid)) continue;
            appview.indexEngagement(gpa, idx, .repost, r.value.subject.cid) catch {};
            store.appendEngagement(log, arena, .repost, did, r.value.subject.cid, r.cid, r.uri);
        }
    }

    return added;
}

test {
    std.testing.refAllDecls(@This());
}
