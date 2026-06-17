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
    const gop = try seen.getOrPut(gpa, std.hash.Wyhash.hash(0, cid));
    return gop.found_existing;
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
) !usize {
    var added: usize = 0;

    // Posts — indexPost dedups by cid, so this is idempotent on its own.
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
            if (is_new) added += 1;
        }
    }

    // Follows — indexFollow appends, so gate on the follow record's cid.
    if (try fetch(arena, io, environ, pds_url, did, lexicon.collection.follow, FollowValue)) |recs| {
        lock.lock();
        defer lock.unlock();
        for (recs) |r| {
            if (r.cid.len == 0 or r.value.subject.len == 0) continue;
            if (try markSeen(gpa, seen, r.cid)) continue;
            appview.indexFollow(gpa, idx, did, r.value.subject) catch {};
        }
    }

    // Likes — indexEngagement bumps a count, so gate on the like record's cid.
    if (try fetch(arena, io, environ, pds_url, did, lexicon.collection.like, RefValue)) |recs| {
        lock.lock();
        defer lock.unlock();
        for (recs) |r| {
            if (r.cid.len == 0 or r.value.subject.cid.len == 0) continue;
            if (try markSeen(gpa, seen, r.cid)) continue;
            appview.indexEngagement(gpa, idx, .like, r.value.subject.cid) catch {};
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
        }
    }

    return added;
}

test {
    std.testing.refAllDecls(@This());
}
