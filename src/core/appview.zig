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

//! B1 classification: CORE (pure data + pure transforms). The Zat4 AppView
//! INDEX — the in-memory model the long-running service builds from the
//! firehose and queries to assemble timelines. The network ingest and the
//! HTTP serving are SHELL (shell/appview_ingest.zig, shell/appview_serve.zig);
//! this module is pure: same (index, inputs) ⇒ same outputs, no I/O, no clock
//! (B2/B4). The shell hands it plain records and asks it plain questions.
//!
//! This is the project's first genuinely BULK-RESIDENT store — every Zat4
//! post and follow in the network lives here in quantity — so the data laws
//! bite hardest: plain data (A1), struct-of-arrays (A3), tight size-guarded
//! hot records (A7), CID as the immutable-by-hash key (A8), and internal
//! references as u32 indexes that NEVER cross the module boundary (A4/A5 —
//! callers speak DIDs and CIDs, the stable ids, never a bare index).
//!
//! The wall, server side (STANDALONE_ROADMAP Phase C): the ingest only ever
//! hands this index `app.zat4.*` records (jetstream.reduce already filters to
//! lexicon.collection.post), so the index is STRUCTURALLY incapable of
//! holding Bluesky content — the separation is the namespace, not a runtime
//! filter.
//!
//! Cut 1 scope (F4 — do not build the cathedral): posts + the follow graph +
//! like/repost counts, enough to answer one reverse-chronological timeline.
//! Search, notifications, and algorithmic feeds are deferred, named, absent.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

/// A half-open byte span into the index's string pool. Strings (DIDs, CIDs,
/// post text) are interned once and referenced by span, so the hot records
/// hold u32s, not slices — the layout discipline the Phase A lexicon note
/// promised the resident records would carry.
pub const Span = packed struct(u64) {
    off: u32,
    len: u32,
};

/// A stable interned id for a DID or CID. An INDEX into the pool's span
/// table — internal to this module (A5); it never crosses the boundary, where
/// identity is the DID/CID string itself.
pub const StrId = u32;
pub const no_str: StrId = std.math.maxInt(u32);

/// One indexed post — the hot resident record (held in quantity, scanned to
/// build every timeline → A7). All references are u32 ids/spans; the i64 is
/// the sort key. A8: keyed by `cid`, immutable-by-hash — re-seeing a cid is a
/// no-op (dedup in indexPost).
pub const Post = struct {
    cid: StrId, // content id — the immutable key (A8)
    author: StrId, // author DID (interned)
    text: Span, // post text in the string pool
    created_at: i64, // record timestamp (sort key, reverse-chron)
    like_count: u32,
    repost_count: u32,

    comptime {
        // Budget: cid u32 + author u32 + text u64 + created_at i64 +
        // 2×u32 counts = 4+4+8+8+8 = 32, zero padding. Exact. Raising this
        // is an A7.1 act recorded here.
        assert(@sizeOf(Post) == 32);
    }
};

/// One follow edge — also hot (the graph is scanned to build a viewer's
/// follow set). Both endpoints are interned DID ids. A7.
pub const Follow = struct {
    follower: StrId,
    subject: StrId,

    comptime {
        // Budget: 2×u32 = 8, exact.
        assert(@sizeOf(Follow) == 8);
    }
};

pub const PostList = std.MultiArrayList(Post);
pub const FollowList = std.MultiArrayList(Follow);

/// The index. A7.2: cold container — one per process; its CONTENTS are the
/// guarded hot arrays above. Owns all its memory (C4); every mutator takes
/// an allocator (C1). Not pure-functional in the wholesale sense (it is the
/// resident store), but every operation is deterministic: same (index, input)
/// ⇒ same resulting index, no I/O, no clock (B2 in spirit; the impurity is
/// the network feeding it, which lives in the shell).
pub const Index = struct {
    posts: PostList = .empty,
    follows: FollowList = .empty,

    /// String pool: all interned bytes back-to-back, plus a span table so a
    /// StrId resolves to its bytes. A hash map interns DID/CID strings to
    /// their StrId so the same string is stored once (and cid dedup is O(1)).
    pool_bytes: std.ArrayList(u8) = .empty,
    pool_spans: std.ArrayList(Span) = .empty,
    intern: std.StringHashMapUnmanaged(StrId) = .empty,

    /// cid StrId -> post row, so a like/repost can find its subject in O(1)
    /// to bump a count, and a re-seen cid is deduped (A8).
    post_by_cid: std.AutoHashMapUnmanaged(StrId, u32) = .empty,

    /// Per-post reply linkage, OUT OF BAND (A6): the hot `Post` is exactly 32
    /// bytes with no spare room, so a post's reply parent / thread-root cid ids
    /// ride in these arrays, parallel to `posts` and indexed by row. `no_str` ⇒
    /// the post is not a reply. The child→parent edge lets a thread walk
    /// ancestors; a post's direct replies (and its reply_count) are a scan over
    /// `reply_parent`. Interned cid ids, so they match a parent post's own cid
    /// id (internStr dedups) — the reverse lookup is exact.
    reply_parent: std.ArrayList(StrId) = .empty,
    reply_root: std.ArrayList(StrId) = .empty,

    /// REPOSTS whose subject post is not indexed YET (out-of-order ingest, e.g.
    /// across repos). Keyed by the subject's cid; `indexPost` drains these into
    /// the post's repost_count when it arrives, so an early repost is never lost.
    /// (Likes need no pending map — they live in `like_edges`, keyed by cid, and
    /// `indexPost` counts them directly via `countLikeEdges`.)
    pending_reposts: std.AutoHashMapUnmanaged(StrId, u32) = .empty,

    /// Per-viewer LIKE edges: a packed (viewer_id, subject-cid_id) key → the
    /// viewer's like RECORD uri (interned). Lets getTimeline answer
    /// `viewer.like` — whether THIS viewer liked a post, and which record to
    /// delete to unlike. Keyed by the interned pair so lookup is O(1) and
    /// survives post-row reordering. Set by `setLikeEdge`, idempotently.
    like_edges: std.AutoHashMapUnmanaged(u64, StrId) = .empty,

    /// Author DID id → handle id (both interned). Lets the serve layer answer
    /// a post's `author.handle` with the real handle (`connor.zat4.com`) instead
    /// of echoing the DID. Resolved by the shell (describeRepo / identity
    /// events) and persisted, so it survives a restart.
    handles: std.AutoHashMapUnmanaged(StrId, StrId) = .empty,

    /// Author DID id → display-name id (both interned), from the author's
    /// `app.zat4.actor.profile` record. Lets the serve layer answer
    /// `author.displayName` with the human name; absent ⇒ the client falls back
    /// to the handle. Resolved + persisted alongside the handle.
    display_names: std.AutoHashMapUnmanaged(StrId, StrId) = .empty,

    // --- Zat Zones: the tag index (A6, all OUT OF BAND — the hot `Post` stays
    // 32 bytes). A zone is not a stored container; it is these derived indexes
    // over the post array. Normalized tag (case-folded + trimmed) is the key
    // (invariant 1); the first-seen display casing is shown.

    /// Normalized-tag id → the rows of every post bearing it: the zone's
    /// candidate pool, in ingest order. A `getPostsForTag` is a scan of this
    /// list (materialized reverse-chron). Each list is owned and freed in deinit.
    tag_posts: std.AutoHashMapUnmanaged(StrId, std.ArrayListUnmanaged(u32)) = .empty,
    /// Normalized-tag id → first-seen DISPLAY-form id (both interned). Its key
    /// set IS the set of known zones; the value is what the catalog shows.
    tag_display: std.AutoHashMapUnmanaged(StrId, StrId) = .empty,
    /// Normalized-tag ids in first-seen order — a stable catalog ordering for
    /// `listTags` (manifest-state / ranking are later phases).
    tag_order: std.ArrayList(StrId) = .empty,
    /// Per-post tag lists for the tray, parallel to `posts` (one Span per row)
    /// indexing into `post_tag_ids`. The display-form tag ids a post bears,
    /// deduped within the post. `{off,0}` ⇒ an untagged post.
    post_tag_spans: std.ArrayList(Span) = .empty,
    /// Flat pool of display-form tag ids, sliced by `post_tag_spans`.
    post_tag_ids: std.ArrayList(StrId) = .empty,
};

pub fn deinit(gpa: Allocator, idx: *Index) void {
    idx.posts.deinit(gpa);
    idx.follows.deinit(gpa);
    idx.pool_bytes.deinit(gpa);
    idx.pool_spans.deinit(gpa);
    // The intern map owns a dupe of each key (see internStr) — free them first.
    var kit = idx.intern.keyIterator();
    while (kit.next()) |k| gpa.free(k.*);
    idx.intern.deinit(gpa);
    idx.post_by_cid.deinit(gpa);
    idx.reply_parent.deinit(gpa);
    idx.reply_root.deinit(gpa);
    idx.pending_reposts.deinit(gpa);
    idx.like_edges.deinit(gpa);
    idx.handles.deinit(gpa);
    idx.display_names.deinit(gpa);
    // Each zone's row list is an owned ArrayListUnmanaged — free them, then the map.
    var tit = idx.tag_posts.valueIterator();
    while (tit.next()) |list| list.deinit(gpa);
    idx.tag_posts.deinit(gpa);
    idx.tag_display.deinit(gpa);
    idx.tag_order.deinit(gpa);
    idx.post_tag_spans.deinit(gpa);
    idx.post_tag_ids.deinit(gpa);
    idx.* = .{};
}

/// Resolve an interned id back to its bytes (for serialization at the
/// boundary). Returns "" for `no_str`.
pub fn str(idx: *const Index, id: StrId) []const u8 {
    if (id == no_str) return "";
    const s = idx.pool_spans.items[id];
    return idx.pool_bytes.items[s.off .. s.off + s.len];
}

/// Intern a string, returning its stable id. Same bytes ⇒ same id (stored
/// once). C1: takes the allocator.
pub fn internStr(gpa: Allocator, idx: *Index, bytes: []const u8) Allocator.Error!StrId {
    if (idx.intern.get(bytes)) |id| return id;
    const off: u32 = @intCast(idx.pool_bytes.items.len);
    try idx.pool_bytes.appendSlice(gpa, bytes);
    const id: StrId = @intCast(idx.pool_spans.items.len);
    try idx.pool_spans.append(gpa, .{ .off = off, .len = @intCast(bytes.len) });
    // The map key must outlive the call AND survive pool growth. A slice into
    // pool_bytes dangles the instant the pool reallocates, which made the intern
    // map rehash freed memory and panic (a use-after-realloc). So the map owns a
    // STABLE dupe of the key; pool_bytes still holds the bytes for str().
    const key = try gpa.dupe(u8, bytes);
    errdefer gpa.free(key);
    try idx.intern.put(gpa, key, id);
    return id;
}

/// A plain post to index, as the shell decoded it from the firehose. Values
/// only (E1) — the ingest hands these across the boundary; the index copies
/// what it keeps into its pool.
/// A7.2: cold struct, size guard waived — transient boundary value, one per
/// ingested event, decomposed immediately into the pooled hot `Post`.
pub const PostInput = struct {
    cid: []const u8,
    author_did: []const u8,
    text: []const u8,
    created_at: i64,
    /// The cid of the post this replies to (its immediate parent) and the
    /// thread root. "" when the post is not a reply. Indexed out of band (A6).
    reply_parent_cid: []const u8 = "",
    reply_root_cid: []const u8 = "",
    /// The post's zone tags ('#' stripped), as the shell extracted them from the
    /// record's facets (`lexicon.collectTags`). Plain values only (D3 — the wire
    /// facet type never reaches this core). Empty ⇒ untagged.
    tags: []const []const u8 = &.{},
};

/// Longest tag we index. Real hashtags are short; an absurdly long one is
/// almost certainly junk, so it is dropped (E4) rather than widening scratch.
pub const max_tag_bytes = 128;
/// Most distinct tags we index from one post (defends the per-post dedup scan
/// and the tray against a stuffed record). Extra tags are dropped (E4).
pub const max_tags_per_post = 32;

/// Normalize a tag for the zone key (invariant 1): trim surrounding ASCII
/// whitespace and fold ASCII case into `buf`. Returns the normalized bytes, or
/// null when the tag is empty or too long to be a zone (E4 — an ordinary skip).
fn normalizeTag(raw: []const u8, buf: []u8) ?[]const u8 {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0 or trimmed.len > buf.len) return null;
    for (trimmed, 0..) |c, i| buf[i] = std.ascii.toLower(c);
    return buf[0..trimmed.len];
}

/// Index one post. A8: if the cid is already present, this is a no-op (same
/// cid ⇒ same bytes ⇒ never re-process). Returns true if newly indexed.
pub fn indexPost(gpa: Allocator, idx: *Index, in: PostInput) Allocator.Error!bool {
    const cid_id = try internStr(gpa, idx, in.cid);
    if (idx.post_by_cid.contains(cid_id)) return false; // dedup (A8)

    const author_id = try internStr(gpa, idx, in.author_did);
    const text_off: u32 = @intCast(idx.pool_bytes.items.len);
    try idx.pool_bytes.appendSlice(gpa, in.text);
    const text_span: Span = .{ .off = text_off, .len = @intCast(in.text.len) };

    // Reply linkage (A6, out of band): intern the parent/root cids (or no_str
    // when this isn't a reply) so they share the parent post's own cid id.
    const reply_parent_id: StrId = if (in.reply_parent_cid.len > 0) try internStr(gpa, idx, in.reply_parent_cid) else no_str;
    const reply_root_id: StrId = if (in.reply_root_cid.len > 0) try internStr(gpa, idx, in.reply_root_cid) else no_str;

    const row: u32 = @intCast(idx.posts.len);
    // Out-of-order ingest. Reposts were held PENDING against this cid (drained
    // here). Likes were stored as EDGES (keyed by cid, order-independent) — so
    // seed the like_count from the edges already pointing at this cid.
    const pending_repost = if (idx.pending_reposts.fetchRemove(cid_id)) |kv| kv.value else 0;
    const like_count = countLikeEdges(idx, cid_id);

    try idx.posts.append(gpa, .{
        .cid = cid_id,
        .author = author_id,
        .text = text_span,
        .created_at = in.created_at,
        .like_count = like_count,
        .repost_count = pending_repost,
    });
    // Parallel to `posts`, one entry per row (A6 — kept in lockstep here, the
    // sole appender of `posts`).
    try idx.reply_parent.append(gpa, reply_parent_id);
    try idx.reply_root.append(gpa, reply_root_id);

    // Zone tag index (A6, out of band). For each distinct tag this post bears:
    // register the zone (normalized key, first-seen display casing — invariant
    // 1), add this row to the zone's candidate pool, and record the display id
    // in this row's tray list. Deduped within the post so "#water #Water" is one
    // zone membership and one tray entry.
    const tag_off: u32 = @intCast(idx.post_tag_ids.items.len);
    var tag_len: u32 = 0;
    var seen: [max_tags_per_post]StrId = undefined;
    var seen_n: usize = 0;
    var nbuf: [max_tag_bytes]u8 = undefined;
    for (in.tags) |raw_tag| {
        if (seen_n >= seen.len) break;
        const norm = normalizeTag(raw_tag, &nbuf) orelse continue;
        const norm_id = try internStr(gpa, idx, norm);
        var dup = false;
        for (seen[0..seen_n]) |sid| {
            if (sid == norm_id) {
                dup = true;
                break;
            }
        }
        if (dup) continue;
        seen[seen_n] = norm_id;
        seen_n += 1;

        const display_id = try internStr(gpa, idx, raw_tag);
        const dgop = try idx.tag_display.getOrPut(gpa, norm_id);
        if (!dgop.found_existing) {
            dgop.value_ptr.* = display_id; // first-seen casing wins
            try idx.tag_order.append(gpa, norm_id);
        }
        const pgop = try idx.tag_posts.getOrPut(gpa, norm_id);
        if (!pgop.found_existing) pgop.value_ptr.* = .empty;
        try pgop.value_ptr.append(gpa, row);

        // The tray shows the zone's established display casing, not this post's.
        try idx.post_tag_ids.append(gpa, idx.tag_display.get(norm_id).?);
        tag_len += 1;
    }
    try idx.post_tag_spans.append(gpa, .{ .off = tag_off, .len = tag_len });

    try idx.post_by_cid.put(gpa, cid_id, row);
    return true;
}

/// The unique set of DIDs the index knows as authors or graph endpoints (post
/// authors + follow followers + follow subjects) — the set the AppView polls
/// for content. DID strings are duped into `arena` so they stay valid across
/// index mutation. PURE read (B2). A5 note: these are stable did:plc/did:web
/// identifiers (not bare indexes), so handing them across the module boundary
/// is correct — they are the same kind of value a CID is.
pub fn authorDids(arena: Allocator, idx: *const Index) Allocator.Error![]const []const u8 {
    var seen: std.AutoHashMapUnmanaged(StrId, void) = .empty;
    defer seen.deinit(arena);
    var out: std.ArrayList([]const u8) = .empty;
    errdefer out.deinit(arena);
    const columns = [_][]const StrId{
        idx.posts.items(.author),
        idx.follows.items(.follower),
        idx.follows.items(.subject),
    };
    for (columns) |col| {
        for (col) |id| {
            const gop = try seen.getOrPut(arena, id);
            if (gop.found_existing) continue;
            try out.append(arena, try arena.dupe(u8, str(idx, id)));
        }
    }
    return out.toOwnedSlice(arena);
}

/// Index one follow edge (follower follows subject). C1.
pub fn indexFollow(gpa: Allocator, idx: *Index, follower_did: []const u8, subject_did: []const u8) Allocator.Error!void {
    const follower = try internStr(gpa, idx, follower_did);
    const subject = try internStr(gpa, idx, subject_did);
    try idx.follows.append(gpa, .{ .follower = follower, .subject = subject });
}

/// What a like/repost bumps. Subject is the post's cid.
pub const Engagement = enum { like, repost };

/// Bump a REPOST count on the subject post, or hold it PENDING against the cid
/// if the post is not indexed yet (out-of-order ingest), drained by indexPost.
///
/// LIKES are NOT handled here: they are edge-managed — `setLikeEdge` maintains
/// the like_count AND the per-viewer `viewer.like` uri as the SINGLE source of
/// truth (so an unlike, a re-poll, and a duplicate all reconcile correctly). A
/// `.like` kind is therefore a no-op, so a caller that still routes a like
/// through here cannot double-count it.
pub fn indexEngagement(gpa: Allocator, idx: *Index, kind: Engagement, subject_cid: []const u8) Allocator.Error!void {
    if (kind != .repost) return;
    const cid_id = try internStr(gpa, idx, subject_cid);
    if (idx.post_by_cid.get(cid_id)) |row| {
        idx.posts.items(.repost_count)[row] +|= 1;
        return;
    }
    // Subject post not indexed yet — hold PENDING against its cid (E4: not a
    // silent miss), drained by indexPost when the post arrives.
    const gop = try idx.pending_reposts.getOrPut(gpa, cid_id);
    if (!gop.found_existing) gop.value_ptr.* = 0;
    gop.value_ptr.* +|= 1;
}

/// Pack a (viewer, subject-cid) interned-id pair into one map key.
fn edgeKey(viewer: StrId, subject_cid: StrId) u64 {
    return (@as(u64, viewer) << 32) | @as(u64, subject_cid);
}

/// Count the like edges whose SUBJECT is `cid_id` (the low 32 bits of the key)
/// — the like_count a post inherits from edges stored before it arrived. O(edges)
/// once per post (G3: a flat scan is fine at Cut-1 scale; not tuned until a
/// profiler indicts it).
fn countLikeEdges(idx: *const Index, cid_id: StrId) u32 {
    var n: u32 = 0;
    var it = idx.like_edges.keyIterator();
    while (it.next()) |k| {
        if (@as(StrId, @truncate(k.*)) == cid_id) n +|= 1;
    }
    return n;
}

/// Record that `actor_did` liked the post with `subject_cid`, via the like
/// record at `record_uri` — the edge getTimeline reads to emit `viewer.like`.
/// Idempotent (a re-poll of the same like overwrites with the same uri) and
/// SEPARATE from the count (which `indexEngagement` gates by record cid), so
/// the poll can refresh edges for already-counted likes too — that is what
/// makes likes from PRIOR sessions un-likeable after a redeploy. C1.
pub fn setLikeEdge(gpa: Allocator, idx: *Index, actor_did: []const u8, subject_cid: []const u8, record_uri: []const u8) Allocator.Error!void {
    if (actor_did.len == 0 or subject_cid.len == 0 or record_uri.len == 0) return;
    const actor_id = try internStr(gpa, idx, actor_did);
    const cid_id = try internStr(gpa, idx, subject_cid);
    const uri_id = try internStr(gpa, idx, record_uri);
    const gop = try idx.like_edges.getOrPut(gpa, edgeKey(actor_id, cid_id));
    const was_new = !gop.found_existing;
    gop.value_ptr.* = uri_id;
    // The edge set is the SINGLE source of truth for likes — a NEW edge adds one
    // to the subject post's like_count. If the post isn't indexed yet, indexPost
    // counts the already-stored edges for its cid when it arrives (out-of-order).
    if (was_new) {
        if (idx.post_by_cid.get(cid_id)) |row| idx.posts.items(.like_count)[row] +|= 1;
    }
}

/// Drop every like edge authored by `actor_did`. The poll calls this before
/// re-adding the actor's CURRENT likes (via setLikeEdge), so a poll-only
/// AppView — which sees creates but not deletes — still reflects an UNLIKE: a
/// deleted like simply isn't re-added, so its edge is gone. Without it, the
/// stale edge would re-fill the heart on the next refresh. A no-op for an
/// unknown actor. Errors are swallowed (a failed reconcile keeps the old set).
pub fn clearLikeEdgesForActor(gpa: Allocator, idx: *Index, actor_did: []const u8) void {
    const actor_id = idx.intern.get(actor_did) orelse return;
    var to_remove: std.ArrayList(u64) = .empty;
    defer to_remove.deinit(gpa);
    var it = idx.like_edges.keyIterator();
    while (it.next()) |k| {
        if (@as(StrId, @truncate(k.* >> 32)) == actor_id) to_remove.append(gpa, k.*) catch return;
    }
    for (to_remove.items) |key| {
        if (idx.like_edges.remove(key)) {
            // Drop the like_count this edge contributed (the count tracks the
            // edge set). Low 32 bits of the key are the subject cid's id.
            const cid_id: StrId = @truncate(key);
            if (idx.post_by_cid.get(cid_id)) |row| idx.posts.items(.like_count)[row] -|= 1;
        }
    }
}

/// Record `did`'s handle (e.g. `connor.zat4.com`), so a post can be served
/// with its author's real handle instead of the DID. Idempotent — a re-resolve
/// overwrites with the same id. C1. An empty argument is a no-op (E4).
pub fn setHandle(gpa: Allocator, idx: *Index, did: []const u8, handle: []const u8) Allocator.Error!void {
    if (did.len == 0 or handle.len == 0) return;
    const did_id = try internStr(gpa, idx, did);
    const handle_id = try internStr(gpa, idx, handle);
    try idx.handles.put(gpa, did_id, handle_id);
}

/// The handle known for `did`, or "" if none is indexed yet (the serve layer
/// falls back to the DID). Pure.
pub fn handleFor(idx: *const Index, did: []const u8) []const u8 {
    const did_id = idx.intern.get(did) orelse return "";
    return handleForId(idx, did_id);
}

/// Internal: the handle for an already-interned DID id (what materializeRows
/// holds), or "" if none.
fn handleForId(idx: *const Index, did_id: StrId) []const u8 {
    return if (idx.handles.get(did_id)) |h| str(idx, h) else "";
}

/// Record `did`'s display name (from its `app.zat4.actor.profile` record), so a
/// post can be served with `author.displayName`. Idempotent. Empty ⇒ no-op (E4).
pub fn setDisplayName(gpa: Allocator, idx: *Index, did: []const u8, name: []const u8) Allocator.Error!void {
    if (did.len == 0 or name.len == 0) return;
    const did_id = try internStr(gpa, idx, did);
    const name_id = try internStr(gpa, idx, name);
    try idx.display_names.put(gpa, did_id, name_id);
}

/// The display name known for `did`, or "" if none. Pure.
pub fn displayNameFor(idx: *const Index, did: []const u8) []const u8 {
    const did_id = idx.intern.get(did) orelse return "";
    return displayNameForId(idx, did_id);
}

fn displayNameForId(idx: *const Index, did_id: StrId) []const u8 {
    return if (idx.display_names.get(did_id)) |n| str(idx, n) else "";
}

/// One row of an assembled timeline, as plain values crossing the boundary
/// (A5: DIDs/CIDs, never the internal index). The shell serializes these into
/// the lexicon's TimelinePage shape.
/// A7.2: cold struct, size guard waived — transient boundary value, arena-
/// built per request and serialized immediately, never bulk-resident.
/// A hydrated reply target (the parent or root of a reply) carried on a
/// TimelineRow — enough for the client to show "replying to @handle" and to
/// intern the referenced post. When the referenced post isn't indexed yet, only
/// `cid` is set (the client still learns the post IS a reply).
/// A7.2: cold struct, size guard waived — transient boundary value.
pub const ReplyTargetRow = struct {
    cid: []const u8 = "",
    author_did: []const u8 = "",
    author_handle: []const u8 = "",
    author_display_name: []const u8 = "",
    text: []const u8 = "",
};

/// A7.2: cold struct, size guard waived — transient boundary value, arena-built
/// per request and serialized immediately, never bulk-resident.
pub const TimelineRow = struct {
    cid: []const u8,
    uri: []const u8 = "", // built by the shell from author+cid if needed
    author_did: []const u8,
    /// The author's handle (e.g. `connor.zat4.com`), or "" if not yet indexed
    /// — the serve layer falls back to the DID for `author.handle` then.
    author_handle: []const u8 = "",
    /// The author's display name (from their profile record), or "" if none —
    /// the client falls back to the handle then.
    author_display_name: []const u8 = "",
    text: []const u8,
    created_at: i64,
    like_count: u32,
    repost_count: u32,
    /// The viewer's own like RECORD uri for this post, if they liked it — the
    /// AppView's `viewer.like`. Empty when the viewer hasn't liked it. The
    /// client shows the filled heart from it AND deletes it to unlike.
    viewer_like_uri: []const u8 = "",
    /// How many indexed posts reply directly to THIS post (derived from the
    /// reply_parent edges). The feed's reply count.
    reply_count: u32 = 0,
    /// When this post is a reply: its immediate parent and thread root, hydrated
    /// from the index. null ⇒ not a reply.
    reply_parent: ?ReplyTargetRow = null,
    reply_root: ?ReplyTargetRow = null,
    /// The post's zone tags (display casing) — its tray. Built into the request
    /// arena by `fillRow`. Empty ⇒ untagged.
    tags: []const []const u8 = &.{},
};

/// Build a reverse-chronological timeline for `viewer_did`: the most recent
/// `limit` posts authored by anyone the viewer follows. PURE (B2): same
/// (index, viewer, limit) ⇒ same rows. Allocates the result in `arena` (C1/
/// C3 — per-request arena, freed wholesale by the caller).
///
/// Cut 1 algorithm (F4): collect the viewer's followed-author id set, scan
/// posts for authors in it, sort by created_at desc, take `limit`. Honest
/// about cost: O(posts) per request. The stop-rule (G3) says don't index-tune
/// this until a profiler on real traffic indicts it against network wait —
/// for Cut 1 correctness and clarity win.
pub fn buildTimeline(arena: Allocator, idx: *const Index, viewer_did: []const u8, limit: usize) Allocator.Error![]TimelineRow {
    // Resolve the viewer's id; an unknown viewer simply follows no one ⇒ an
    // empty timeline (E4, not an error).
    const viewer_id = idx.intern.get(viewer_did) orelse return &.{};

    // The set of author ids the viewer follows. A viewer following few
    // accounts is the norm; a flat scan of the follow edges is fine for Cut 1.
    var followed: std.AutoHashMapUnmanaged(StrId, void) = .empty;
    defer followed.deinit(arena);
    const followers = idx.follows.items(.follower);
    const subjects = idx.follows.items(.subject);
    for (followers, subjects) |f, s| {
        if (f == viewer_id) try followed.put(arena, s, {});
    }
    if (followed.count() == 0) return &.{};

    // Gather candidate rows: posts whose author is followed.
    const authors = idx.posts.items(.author);
    var rows: std.ArrayList(u32) = .empty;
    defer rows.deinit(arena);
    for (authors, 0..) |a, row| {
        if (followed.contains(a)) try rows.append(arena, @intCast(row));
    }

    return materializeRows(arena, idx, viewer_id, rows.items, limit);
}

/// Build a reverse-chronological feed of a SINGLE author's posts — the
/// profile screen's body. PURE (B2), same shape as `buildTimeline`: same
/// (index, author, viewer, limit) ⇒ same rows, allocated in `arena`.
///
/// `viewer_did` is whose `viewer.like` state to stamp (the profile is shown
/// to a logged-in viewer, who may have liked the author's posts). An unknown
/// author yields an empty feed (E4, not an error); an unknown viewer simply
/// yields no viewer.like on any row.
pub fn buildAuthorFeed(
    arena: Allocator,
    idx: *const Index,
    author_did: []const u8,
    viewer_did: []const u8,
    limit: usize,
) Allocator.Error![]TimelineRow {
    const author_id = idx.intern.get(author_did) orelse return &.{};
    const viewer_id: ?StrId = idx.intern.get(viewer_did);

    const authors = idx.posts.items(.author);
    var rows: std.ArrayList(u32) = .empty;
    defer rows.deinit(arena);
    for (authors, 0..) |a, row| {
        if (a == author_id) try rows.append(arena, @intCast(row));
    }

    return materializeRows(arena, idx, viewer_id, rows.items, limit);
}

/// Build a reverse-chronological feed of the posts bearing `tag` — a ZONE feed.
/// PURE (B2): same (index, tag, viewer, limit) ⇒ same rows. The zone is not a
/// stored container; this is the tag index materialized on demand (invariant 4 —
/// a zone feed is a query). `tag` is normalized (case-fold + trim — invariant 1)
/// before lookup, so `#Water`/`#water` resolve to the same zone. An unknown tag
/// yields an empty feed (E4, not an error).
///
/// Cut-1 ordering is reverse-chron over the whole candidate pool; the choosable
/// scored lenses (Discover/Calm/the user's config) arrive when the discover
/// engine lands — a zone feed is that engine pointed at this pool (invariant 6).
pub fn buildTagFeed(
    arena: Allocator,
    idx: *const Index,
    tag: []const u8,
    viewer_did: []const u8,
    limit: usize,
) Allocator.Error![]TimelineRow {
    var nbuf: [max_tag_bytes]u8 = undefined;
    const norm = normalizeTag(tag, &nbuf) orelse return &.{};
    const norm_id = idx.intern.get(norm) orelse return &.{};
    const pool = idx.tag_posts.get(norm_id) orelse return &.{};
    const viewer_id: ?StrId = idx.intern.get(viewer_did);

    var rows: std.ArrayList(u32) = .empty;
    defer rows.deinit(arena);
    try rows.appendSlice(arena, pool.items);

    return materializeRows(arena, idx, viewer_id, rows.items, limit);
}

/// The zone catalog: every known tag with its display casing and post count, in
/// first-seen order. PURE (B2), allocated into `arena`. Manifest-state and
/// ranking are later phases (Z3/Z7); this is the flat set (the latent layer).
pub fn listZones(arena: Allocator, idx: *const Index) Allocator.Error![]ZoneInfo {
    const out = try arena.alloc(ZoneInfo, idx.tag_order.items.len);
    for (out, idx.tag_order.items) |*z, norm_id| {
        const display_id = idx.tag_display.get(norm_id) orelse norm_id;
        const count: usize = if (idx.tag_posts.get(norm_id)) |pool| pool.items.len else 0;
        z.* = .{ .tag = str(idx, display_id), .count = count };
    }
    return out;
}

/// One catalog entry — a zone's display tag and how many posts bear it. Boundary
/// value (the shell serializes it). A7.2: cold struct, transient, size guard
/// waived.
pub const ZoneInfo = struct {
    tag: []const u8,
    count: usize,
};

/// Shared tail of both feed builders (D2/F4 — extracted once a SECOND caller
/// appeared): sort the candidate post rows reverse-chron, take `limit`, and
/// fill plain `TimelineRow`s, stamping each with `viewer_id`'s like record uri
/// when present. `rows` is sorted in place (caller owns its arena backing).
fn materializeRows(
    arena: Allocator,
    idx: *const Index,
    viewer_id: ?StrId,
    rows: []u32,
    limit: usize,
) Allocator.Error![]TimelineRow {
    const createds = idx.posts.items(.created_at);
    // Reverse-chron: newest first. Sort row indices by created_at desc.
    const Ctx = struct {
        createds: []const i64,
        pub fn lessThan(ctx: @This(), a: u32, b: u32) bool {
            return ctx.createds[a] > ctx.createds[b]; // desc
        }
    };
    std.sort.block(u32, rows, Ctx{ .createds = createds }, Ctx.lessThan);

    const n = @min(limit, rows.len);
    const out = try arena.alloc(TimelineRow, n);

    var reply_counts = try buildReplyCounts(arena, idx);
    defer reply_counts.deinit(arena);
    for (out, rows[0..n]) |*o, row| o.* = try fillRow(arena, idx, viewer_id, row, &reply_counts);
    return out;
}

/// Direct-reply tally: parent cid id ⇒ number of posts replying to it. One pass
/// over ALL posts' parent edges (O(posts)). Keyed by the parent's interned cid
/// id, which equals the parent post's own cid id (internStr dedups), so a row
/// reads its count by its own cid id. Caller owns the arena backing.
fn buildReplyCounts(arena: Allocator, idx: *const Index) Allocator.Error!std.AutoHashMapUnmanaged(StrId, u32) {
    var reply_counts: std.AutoHashMapUnmanaged(StrId, u32) = .empty;
    for (idx.reply_parent.items) |pid| {
        if (pid == no_str) continue;
        const gop = try reply_counts.getOrPut(arena, pid);
        gop.value_ptr.* = (if (gop.found_existing) gop.value_ptr.* else 0) + 1;
    }
    return reply_counts;
}

/// Fill one indexed post `row` into a plain `TimelineRow`, stamping the viewer's
/// like uri + the reply count + hydrated reply targets. PURE read — the single
/// per-post boundary projection, shared by every feed/thread builder.
fn fillRow(arena: Allocator, idx: *const Index, viewer_id: ?StrId, row: u32, reply_counts: *const std.AutoHashMapUnmanaged(StrId, u32)) Allocator.Error!TimelineRow {
    const cid_id = idx.posts.items(.cid)[row];
    const author_id = idx.posts.items(.author)[row];
    const s = idx.posts.items(.text)[row];
    const viewer_like: []const u8 = if (viewer_id) |vid|
        (if (idx.like_edges.get(edgeKey(vid, cid_id))) |uid| str(idx, uid) else "")
    else
        "";
    // The tray: resolve this row's display-form tag ids into strings (C1 — into
    // the request arena). Empty when the post bears no tags.
    const span = idx.post_tag_spans.items[row];
    var tags: []const []const u8 = &.{};
    if (span.len > 0) {
        const out = try arena.alloc([]const u8, span.len);
        for (out, 0..) |*t, i| t.* = str(idx, idx.post_tag_ids.items[span.off + i]);
        tags = out;
    }
    return .{
        .cid = str(idx, cid_id),
        .author_did = str(idx, author_id),
        .author_handle = handleForId(idx, author_id),
        .author_display_name = displayNameForId(idx, author_id),
        .text = idx.pool_bytes.items[s.off .. s.off + s.len],
        .created_at = idx.posts.items(.created_at)[row],
        .like_count = idx.posts.items(.like_count)[row],
        .repost_count = idx.posts.items(.repost_count)[row],
        .viewer_like_uri = viewer_like,
        .reply_count = reply_counts.get(cid_id) orelse 0,
        .reply_parent = hydrateReplyTarget(idx, idx.reply_parent.items[row]),
        .reply_root = hydrateReplyTarget(idx, idx.reply_root.items[row]),
        .tags = tags,
    };
}

/// A post's whole thread, as a FLAT set of boundary rows (its root + the whole
/// descendant tree). No tree/depth here — the client derives structure from the
/// reply edges (the post is the post; nesting is the reader's lens). `found` is
/// false when the focus cid isn't indexed (E4 — an empty thread, not an error).
/// A7.2: cold struct, size guard waived — transient boundary value.
pub const ThreadRows = struct {
    posts: []TimelineRow = &.{},
    found: bool = false,
};

/// Build the whole thread containing the post with cid `focus_cid`: walk
/// `reply_parent` up to the thread root, then collect the entire descendant tree
/// (BFS over the child edges), `limit` posts. Reply ROOTS may be stale on older
/// records, so the tree is built from immediate-PARENT edges, which are exact.
/// PURE (B2); allocates into `arena`. Unknown focus cid ⇒ `found = false` (E4).
pub fn buildPostThread(
    arena: Allocator,
    idx: *const Index,
    focus_cid: []const u8,
    viewer_did: []const u8,
    limit: usize,
) Allocator.Error!ThreadRows {
    const focus_cid_id = idx.intern.get(focus_cid) orelse return .{};
    const focus_row = idx.post_by_cid.get(focus_cid_id) orelse return .{};
    const viewer_id: ?StrId = idx.intern.get(viewer_did);

    var reply_counts = try buildReplyCounts(arena, idx);
    defer reply_counts.deinit(arena);

    // Walk the parent chain up to the thread root (cycle-guarded).
    var root_row = focus_row;
    var guard: usize = 0;
    while (guard < 4096) : (guard += 1) {
        const pid = idx.reply_parent.items[root_row];
        if (pid == no_str) break;
        const prow = idx.post_by_cid.get(pid) orelse break;
        root_row = prow;
    }

    // parent row → child rows, then BFS the whole tree from the root. Order
    // doesn't matter (the client re-derives the nesting); BFS just bounds it.
    var children: std.AutoHashMapUnmanaged(u32, std.ArrayListUnmanaged(u32)) = .empty;
    defer {
        var vit = children.valueIterator();
        while (vit.next()) |v| v.deinit(arena);
        children.deinit(arena);
    }
    for (idx.reply_parent.items, 0..) |pid, row| {
        if (pid == no_str) continue;
        const prow = idx.post_by_cid.get(pid) orelse continue;
        const gop = try children.getOrPut(arena, prow);
        if (!gop.found_existing) gop.value_ptr.* = .empty;
        try gop.value_ptr.append(arena, @intCast(row));
    }

    var out: std.ArrayList(TimelineRow) = .empty;
    defer out.deinit(arena);
    var queue: std.ArrayList(u32) = .empty;
    defer queue.deinit(arena);
    try queue.append(arena, root_row);
    var head: usize = 0;
    while (head < queue.items.len and out.items.len < limit) : (head += 1) {
        const row = queue.items[head];
        try out.append(arena, try fillRow(arena, idx, viewer_id, row, &reply_counts));
        if (children.get(row)) |kids| {
            for (kids.items) |k| try queue.append(arena, k);
        }
    }

    return .{ .posts = try out.toOwnedSlice(arena), .found = true };
}

/// Hydrate a reply target from an interned cid id: if the referenced post is
/// indexed, fill its author + text; otherwise return cid-only (the client still
/// learns the post is a reply). null for `no_str` (not a reply). PURE read.
fn hydrateReplyTarget(idx: *const Index, cid_id: StrId) ?ReplyTargetRow {
    if (cid_id == no_str) return null;
    const cid_str = str(idx, cid_id);
    if (idx.post_by_cid.get(cid_id)) |prow| {
        const a = idx.posts.items(.author)[prow];
        const s = idx.posts.items(.text)[prow];
        return .{
            .cid = cid_str,
            .author_did = str(idx, a),
            .author_handle = handleForId(idx, a),
            .author_display_name = displayNameForId(idx, a),
            .text = idx.pool_bytes.items[s.off .. s.off + s.len],
        };
    }
    return .{ .cid = cid_str };
}

// ---------------------------------------------------------------------------
// Tests (B2, C6) — the loop's core, proven headless without a network.
// ---------------------------------------------------------------------------

const testing = std.testing;

test "guard: hot records are exactly sized" {
    try testing.expectEqual(@as(usize, 32), @sizeOf(Post));
    try testing.expectEqual(@as(usize, 8), @sizeOf(Follow));
    try testing.expectEqual(@as(usize, 8), @sizeOf(Span));
}

test "index: a post dedups by cid (A8 immutable-by-hash)" {
    const gpa = testing.allocator;
    var idx: Index = .{};
    defer deinit(gpa, &idx);

    const p: PostInput = .{ .cid = "bafy1", .author_did = "did:plc:a", .text = "hello", .created_at = 100 };
    try testing.expect(try indexPost(gpa, &idx, p)); // newly indexed
    try testing.expect(!try indexPost(gpa, &idx, p)); // same cid ⇒ no-op
    try testing.expectEqual(@as(usize, 1), idx.posts.len);
}

test "zones: buildTagFeed returns a tag's posts, newest first, normalized key" {
    const gpa = testing.allocator;
    var idx: Index = .{};
    defer deinit(gpa, &idx);

    // Two posts in #water (different casing → one zone), one in #rivers only.
    _ = try indexPost(gpa, &idx, .{ .cid = "c1", .author_did = "did:a", .text = "older", .created_at = 100, .tags = &.{"water"} });
    _ = try indexPost(gpa, &idx, .{ .cid = "c2", .author_did = "did:b", .text = "newer", .created_at = 200, .tags = &.{ "Water", "rivers" } });
    _ = try indexPost(gpa, &idx, .{ .cid = "c3", .author_did = "did:c", .text = "untagged", .created_at = 300 });

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The query normalizes: "#WATER" finds both #water/#Water posts, newest first.
    const water = try buildTagFeed(arena, &idx, "WATER", "", 50);
    try testing.expectEqual(@as(usize, 2), water.len);
    try testing.expectEqualStrings("newer", water[0].text);
    try testing.expectEqualStrings("older", water[1].text);
    // The tray on a row carries the zone's first-seen display casing ("water").
    try testing.expectEqual(@as(usize, 2), water[0].tags.len); // water + rivers
    try testing.expectEqualStrings("water", water[1].tags[0]);

    // #rivers has just the one; an unknown tag is an empty feed (E4).
    try testing.expectEqual(@as(usize, 1), (try buildTagFeed(arena, &idx, "rivers", "", 50)).len);
    try testing.expectEqual(@as(usize, 0), (try buildTagFeed(arena, &idx, "nope", "", 50)).len);
}

test "zones: a post with the same tag twice joins the zone once (dedup within post)" {
    const gpa = testing.allocator;
    var idx: Index = .{};
    defer deinit(gpa, &idx);

    _ = try indexPost(gpa, &idx, .{ .cid = "c1", .author_did = "did:a", .text = "p", .created_at = 1, .tags = &.{ "water", "Water", "WATER" } });

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const water = try buildTagFeed(arena, &idx, "water", "", 50);
    try testing.expectEqual(@as(usize, 1), water.len); // the post appears once, not 3×
    try testing.expectEqual(@as(usize, 1), water[0].tags.len); // one tray entry
}

test "zones: listZones lists every zone once with its post count, first-seen casing" {
    const gpa = testing.allocator;
    var idx: Index = .{};
    defer deinit(gpa, &idx);

    _ = try indexPost(gpa, &idx, .{ .cid = "c1", .author_did = "did:a", .text = "p1", .created_at = 1, .tags = &.{"Water"} });
    _ = try indexPost(gpa, &idx, .{ .cid = "c2", .author_did = "did:b", .text = "p2", .created_at = 2, .tags = &.{ "water", "rivers" } });

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const zones = try listZones(arena, &idx);
    try testing.expectEqual(@as(usize, 2), zones.len); // water + rivers, water not doubled
    try testing.expectEqualStrings("Water", zones[0].tag); // first-seen casing
    try testing.expectEqual(@as(usize, 2), zones[0].count); // two posts in water
    try testing.expectEqualStrings("rivers", zones[1].tag);
    try testing.expectEqual(@as(usize, 1), zones[1].count);
}

test "intern: same string returns the same id, stored once" {
    const gpa = testing.allocator;
    var idx: Index = .{};
    defer deinit(gpa, &idx);

    const a = try internStr(gpa, &idx, "did:plc:x");
    const b = try internStr(gpa, &idx, "did:plc:x");
    const c = try internStr(gpa, &idx, "did:plc:y");
    try testing.expectEqual(a, b);
    try testing.expect(a != c);
    try testing.expectEqualStrings("did:plc:x", str(&idx, a));
}

test "intern: stays valid across pool + map growth (no dangling keys)" {
    // Regression: the intern map once keyed on slices INTO pool_bytes, which
    // dangle when the pool reallocates — a map grow then rehashed freed memory
    // and panicked. Interning many distinct strings forces both growths; with
    // the dupe-key fix, dedup and resolution stay correct throughout.
    const gpa = testing.allocator;
    var idx: Index = .{};
    defer deinit(gpa, &idx);

    var buf: [32]u8 = undefined;
    var ids: [200]StrId = undefined;
    for (&ids, 0..) |*slot, i| {
        const s = std.fmt.bufPrint(&buf, "did:plc:user{d:0>5}", .{i}) catch unreachable;
        slot.* = try internStr(gpa, &idx, s);
        try testing.expectEqual(slot.*, try internStr(gpa, &idx, s)); // dedup holds
    }
    // Every earlier id still resolves to its exact bytes (no UAF corruption).
    for (ids, 0..) |id, i| {
        const want = std.fmt.bufPrint(&buf, "did:plc:user{d:0>5}", .{i}) catch unreachable;
        try testing.expectEqualStrings(want, str(&idx, id));
    }
}

test "timeline: reverse-chron over the followed set only" {
    const gpa = testing.allocator;
    var idx: Index = .{};
    defer deinit(gpa, &idx);

    // alice follows bob and carol, not dave.
    try indexFollow(gpa, &idx, "did:alice", "did:bob");
    try indexFollow(gpa, &idx, "did:alice", "did:carol");
    // posts at increasing times; dave's must NOT appear.
    _ = try indexPost(gpa, &idx, .{ .cid = "c1", .author_did = "did:bob", .text = "bob old", .created_at = 10 });
    _ = try indexPost(gpa, &idx, .{ .cid = "c2", .author_did = "did:carol", .text = "carol mid", .created_at = 20 });
    _ = try indexPost(gpa, &idx, .{ .cid = "c3", .author_did = "did:dave", .text = "dave hidden", .created_at = 30 });
    _ = try indexPost(gpa, &idx, .{ .cid = "c4", .author_did = "did:bob", .text = "bob new", .created_at = 40 });

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const rows = try buildTimeline(arena_state.allocator(), &idx, "did:alice", 10);

    try testing.expectEqual(@as(usize, 3), rows.len); // bob×2 + carol, not dave
    try testing.expectEqualStrings("bob new", rows[0].text); // newest first
    try testing.expectEqualStrings("carol mid", rows[1].text);
    try testing.expectEqualStrings("bob old", rows[2].text);
    // dave never appears.
    for (rows) |r| try testing.expect(!std.mem.eql(u8, r.author_did, "did:dave"));
}

test "timeline: limit caps the rows; unknown viewer is empty (E4)" {
    const gpa = testing.allocator;
    var idx: Index = .{};
    defer deinit(gpa, &idx);

    try indexFollow(gpa, &idx, "did:me", "did:author");
    var i: i64 = 0;
    while (i < 5) : (i += 1) {
        var cid_buf: [8]u8 = undefined;
        const cid = std.fmt.bufPrint(&cid_buf, "c{d}", .{i}) catch unreachable;
        _ = try indexPost(gpa, &idx, .{ .cid = cid, .author_did = "did:author", .text = "x", .created_at = i });
    }
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const capped = try buildTimeline(arena_state.allocator(), &idx, "did:me", 2);
    try testing.expectEqual(@as(usize, 2), capped.len);

    const unknown = try buildTimeline(arena_state.allocator(), &idx, "did:nobody", 10);
    try testing.expectEqual(@as(usize, 0), unknown.len);
}

test "author feed: one author's posts, reverse-chron, with the viewer's like; unknown author empty (E4)" {
    const gpa = testing.allocator;
    var idx: Index = .{};
    defer deinit(gpa, &idx);

    // Two authors post; the feed must carry only bob's, newest first — no
    // follow graph required (a profile is the author's own posts).
    _ = try indexPost(gpa, &idx, .{ .cid = "c1", .author_did = "did:bob", .text = "bob old", .created_at = 10 });
    _ = try indexPost(gpa, &idx, .{ .cid = "c2", .author_did = "did:carol", .text = "carol hidden", .created_at = 20 });
    _ = try indexPost(gpa, &idx, .{ .cid = "c3", .author_did = "did:bob", .text = "bob new", .created_at = 30 });
    // The viewing actor (alice) liked bob's newest post.
    try setLikeEdge(gpa, &idx, "did:alice", "c3", "at://did:alice/app.zat4.feed.like/r1");

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    const rows = try buildAuthorFeed(arena_state.allocator(), &idx, "did:bob", "did:alice", 10);
    try testing.expectEqual(@as(usize, 2), rows.len);
    try testing.expectEqualStrings("bob new", rows[0].text); // newest first
    try testing.expectEqualStrings("bob old", rows[1].text);
    for (rows) |r| try testing.expectEqualStrings("did:bob", r.author_did);
    // The viewer's like edge surfaces as viewer.like on the matching row.
    try testing.expectEqualStrings("at://did:alice/app.zat4.feed.like/r1", rows[0].viewer_like_uri);
    try testing.expectEqualStrings("", rows[1].viewer_like_uri);

    // An unknown viewer still sees the posts, just no viewer.like.
    const anon = try buildAuthorFeed(arena_state.allocator(), &idx, "did:bob", "did:nobody", 10);
    try testing.expectEqual(@as(usize, 2), anon.len);
    try testing.expectEqualStrings("", anon[0].viewer_like_uri);

    // An unknown author is an empty feed, not an error.
    const none = try buildAuthorFeed(arena_state.allocator(), &idx, "did:ghost", "did:alice", 10);
    try testing.expectEqual(@as(usize, 0), none.len);
}

test "reply linkage: a reply bumps its parent's reply_count and carries a hydrated parent" {
    const gpa = testing.allocator;
    var idx: Index = .{};
    defer deinit(gpa, &idx);

    // bob posts; alice replies to it; the parent's handle is known.
    _ = try indexPost(gpa, &idx, .{ .cid = "cParent", .author_did = "did:bob", .text = "the parent post", .created_at = 10 });
    try setHandle(gpa, &idx, "did:bob", "bob.zat4.com");
    _ = try indexPost(gpa, &idx, .{ .cid = "cReply", .author_did = "did:alice", .text = "a reply", .created_at = 20, .reply_parent_cid = "cParent", .reply_root_cid = "cParent" });

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    // The parent: reply_count == 1, not itself a reply.
    const parent_feed = try buildAuthorFeed(arena_state.allocator(), &idx, "did:bob", "did:x", 10);
    try testing.expectEqual(@as(usize, 1), parent_feed.len);
    try testing.expectEqual(@as(u32, 1), parent_feed[0].reply_count);
    try testing.expect(parent_feed[0].reply_parent == null);

    // The reply: reply_count 0, and a parent target hydrated from the index.
    const reply_feed = try buildAuthorFeed(arena_state.allocator(), &idx, "did:alice", "did:x", 10);
    try testing.expectEqual(@as(usize, 1), reply_feed.len);
    try testing.expectEqual(@as(u32, 0), reply_feed[0].reply_count);
    const parent = reply_feed[0].reply_parent orelse return error.NoReplyParent;
    try testing.expectEqualStrings("cParent", parent.cid);
    try testing.expectEqualStrings("did:bob", parent.author_did);
    try testing.expectEqualStrings("bob.zat4.com", parent.author_handle);
    try testing.expectEqualStrings("the parent post", parent.text);

    // A reply whose parent isn't indexed: cid-only target, still flagged a reply.
    _ = try indexPost(gpa, &idx, .{ .cid = "cOrphan", .author_did = "did:alice", .text = "reply to the void", .created_at = 30, .reply_parent_cid = "cMissing", .reply_root_cid = "cMissing" });
    const alice2 = try buildAuthorFeed(arena_state.allocator(), &idx, "did:alice", "did:x", 10);
    // newest first → cOrphan is row 0
    const orphan_parent = alice2[0].reply_parent orelse return error.NoReplyParent;
    try testing.expectEqualStrings("cMissing", orphan_parent.cid);
    try testing.expectEqualStrings("", orphan_parent.author_handle);
}

test "post thread: ancestors walk to root, direct replies in chronological order" {
    const gpa = testing.allocator;
    var idx: Index = .{};
    defer deinit(gpa, &idx);

    // A chain: root <- midA (reply to root) <- leaf (reply to midA); plus midB,
    // a second direct reply to root (newer than midA).
    _ = try indexPost(gpa, &idx, .{ .cid = "cRoot", .author_did = "did:a", .text = "root", .created_at = 10 });
    _ = try indexPost(gpa, &idx, .{ .cid = "cMidA", .author_did = "did:b", .text = "mid A", .created_at = 20, .reply_parent_cid = "cRoot", .reply_root_cid = "cRoot" });
    _ = try indexPost(gpa, &idx, .{ .cid = "cMidB", .author_did = "did:c", .text = "mid B", .created_at = 30, .reply_parent_cid = "cRoot", .reply_root_cid = "cRoot" });
    _ = try indexPost(gpa, &idx, .{ .cid = "cLeaf", .author_did = "did:d", .text = "leaf", .created_at = 40, .reply_parent_cid = "cMidA", .reply_root_cid = "cRoot" });

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Focus anywhere in the thread returns the WHOLE thread (root + all 3
    // descendants), flat — the client derives the nesting. Focusing midA still
    // yields all 4 posts (root, midA, midB, leaf).
    const t = try buildPostThread(arena, &idx, "cMidA", "did:x", 50);
    try testing.expect(t.found);
    try testing.expectEqual(@as(usize, 4), t.posts.len);
    var saw_root = false;
    var saw_leaf = false;
    var root_replies: u32 = 0;
    for (t.posts) |p| {
        if (std.mem.eql(u8, p.text, "root")) {
            saw_root = true;
            root_replies = p.reply_count;
        }
        if (std.mem.eql(u8, p.text, "leaf")) saw_leaf = true;
    }
    try testing.expect(saw_root and saw_leaf);
    try testing.expectEqual(@as(u32, 2), root_replies); // midA + midB reply to root

    // Focusing the root yields the same whole thread.
    const r = try buildPostThread(arena, &idx, "cRoot", "did:x", 50);
    try testing.expectEqual(@as(usize, 4), r.posts.len);

    // An unknown focus cid is an empty thread, not an error (E4).
    const none = try buildPostThread(arena, &idx, "cGhost", "did:x", 50);
    try testing.expect(!none.found);
    try testing.expectEqual(@as(usize, 0), none.posts.len);
}

test "handles: a post row carries the author's indexed handle; unknown stays empty" {
    const gpa = testing.allocator;
    var idx: Index = .{};
    defer deinit(gpa, &idx);

    _ = try indexPost(gpa, &idx, .{ .cid = "c1", .author_did = "did:plc:bob", .text = "hi", .created_at = 10 });
    try setHandle(gpa, &idx, "did:plc:bob", "bob.zat4.com");
    try setDisplayName(gpa, &idx, "did:plc:bob", "Bob Builder");
    // Idempotent re-resolve overwrites with the same value (no growth, no dup).
    try setHandle(gpa, &idx, "did:plc:bob", "bob.zat4.com");

    try testing.expectEqualStrings("bob.zat4.com", handleFor(&idx, "did:plc:bob"));
    try testing.expectEqualStrings("Bob Builder", displayNameFor(&idx, "did:plc:bob"));
    try testing.expectEqualStrings("", handleFor(&idx, "did:plc:nobody"));
    try testing.expectEqualStrings("", displayNameFor(&idx, "did:plc:nobody"));

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const rows = try buildAuthorFeed(arena_state.allocator(), &idx, "did:plc:bob", "did:plc:bob", 10);
    try testing.expectEqual(@as(usize, 1), rows.len);
    try testing.expectEqualStrings("bob.zat4.com", rows[0].author_handle);
    try testing.expectEqualStrings("Bob Builder", rows[0].author_display_name);
    try testing.expectEqualStrings("did:plc:bob", rows[0].author_did);
}

test "engagement: likes are edge-counted (one per actor, deduped); reposts bump; unknown subject pends" {
    const gpa = testing.allocator;
    var idx: Index = .{};
    defer deinit(gpa, &idx);

    _ = try indexPost(gpa, &idx, .{ .cid = "c1", .author_did = "did:a", .text = "p", .created_at = 1 });
    // Two DIFFERENT actors like c1 → count 2; the SAME actor liking again dedups
    // (an edge is keyed by (actor, subject), so a re-poll/duplicate never inflates).
    try setLikeEdge(gpa, &idx, "did:x", "c1", "at://did:x/app.zat4.feed.like/r1");
    try setLikeEdge(gpa, &idx, "did:y", "c1", "at://did:y/app.zat4.feed.like/r1");
    try setLikeEdge(gpa, &idx, "did:x", "c1", "at://did:x/app.zat4.feed.like/r1b");
    try indexEngagement(gpa, &idx, .repost, "c1");

    try testing.expectEqual(@as(u32, 2), idx.posts.items(.like_count)[0]);
    try testing.expectEqual(@as(u32, 1), idx.posts.items(.repost_count)[0]);
}

test "engagement: out-of-order likes/reposts apply when the post lands; an unlike drops the count" {
    const gpa = testing.allocator;
    var idx: Index = .{};
    defer deinit(gpa, &idx);

    // Engagements arrive BEFORE the post: a repost pends; likes live in the edge
    // set (keyed by cid, order-independent).
    try setLikeEdge(gpa, &idx, "did:x", "cLate", "at://did:x/app.zat4.feed.like/r1");
    try setLikeEdge(gpa, &idx, "did:y", "cLate", "at://did:y/app.zat4.feed.like/r1");
    try indexEngagement(gpa, &idx, .repost, "cLate");
    try testing.expectEqual(@as(usize, 0), idx.posts.len); // nothing indexed yet

    // The post arrives — it adopts the pending repost AND counts the like edges.
    try testing.expect(try indexPost(gpa, &idx, .{ .cid = "cLate", .author_did = "did:a", .text = "p", .created_at = 1 }));
    try testing.expectEqual(@as(u32, 2), idx.posts.items(.like_count)[0]);
    try testing.expectEqual(@as(u32, 1), idx.posts.items(.repost_count)[0]);

    // A new actor likes it now (post present) — the count bumps directly.
    try setLikeEdge(gpa, &idx, "did:z", "cLate", "at://did:z/app.zat4.feed.like/r1");
    try testing.expectEqual(@as(u32, 3), idx.posts.items(.like_count)[0]);

    // UNLIKE: clearing actor x's edges (and not re-adding) drops x's like — the
    // count reconciles. This is exactly what makes an unlike stick on a poll
    // AppView (the poll clears then re-adds each actor's CURRENT likes).
    clearLikeEdgesForActor(gpa, &idx, "did:x");
    try testing.expectEqual(@as(u32, 2), idx.posts.items(.like_count)[0]);
}

test "viewer.like: buildTimeline reports the viewer's own like record uri, and only theirs" {
    const gpa = testing.allocator;
    var idx: Index = .{};
    defer deinit(gpa, &idx);

    try indexFollow(gpa, &idx, "did:me", "did:auth");
    try indexFollow(gpa, &idx, "did:other", "did:auth");
    _ = try indexPost(gpa, &idx, .{ .cid = "cp", .author_did = "did:auth", .text = "hi", .created_at = 1 });
    try setLikeEdge(gpa, &idx, "did:me", "cp", "at://did:me/app.zat4.feed.like/rk");

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    const mine = try buildTimeline(arena_state.allocator(), &idx, "did:me", 10);
    try testing.expectEqual(@as(usize, 1), mine.len);
    try testing.expectEqualStrings("at://did:me/app.zat4.feed.like/rk", mine[0].viewer_like_uri);
    try testing.expectEqual(@as(u32, 1), mine[0].like_count);

    // A different viewer who did NOT like it sees no viewer.like.
    const theirs = try buildTimeline(arena_state.allocator(), &idx, "did:other", 10);
    try testing.expectEqualStrings("", theirs[0].viewer_like_uri);
}
