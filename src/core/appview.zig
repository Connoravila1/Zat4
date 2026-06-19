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

    /// Engagements whose subject post is not indexed YET (out-of-order ingest:
    /// a like seen before its post, common across repos / firehose ordering).
    /// Keyed by the subject post's cid; `indexPost` drains these into the post's
    /// counts when it arrives, so an early engagement is never lost (the bug a
    /// silent miss used to cause). Record-level dedup stays the caller's job
    /// (the `seen` set / durable log), so each engagement RECORD counts once.
    pending_likes: std.AutoHashMapUnmanaged(StrId, u32) = .empty,
    pending_reposts: std.AutoHashMapUnmanaged(StrId, u32) = .empty,
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
    idx.pending_likes.deinit(gpa);
    idx.pending_reposts.deinit(gpa);
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
};

/// Index one post. A8: if the cid is already present, this is a no-op (same
/// cid ⇒ same bytes ⇒ never re-process). Returns true if newly indexed.
pub fn indexPost(gpa: Allocator, idx: *Index, in: PostInput) Allocator.Error!bool {
    const cid_id = try internStr(gpa, idx, in.cid);
    if (idx.post_by_cid.contains(cid_id)) return false; // dedup (A8)

    const author_id = try internStr(gpa, idx, in.author_did);
    const text_off: u32 = @intCast(idx.pool_bytes.items.len);
    try idx.pool_bytes.appendSlice(gpa, in.text);
    const text_span: Span = .{ .off = text_off, .len = @intCast(in.text.len) };

    const row: u32 = @intCast(idx.posts.len);
    // Drain engagements that arrived before this post (out-of-order ingest):
    // their counts were held pending against this cid and apply now.
    const pending_like = if (idx.pending_likes.fetchRemove(cid_id)) |kv| kv.value else 0;
    const pending_repost = if (idx.pending_reposts.fetchRemove(cid_id)) |kv| kv.value else 0;

    try idx.posts.append(gpa, .{
        .cid = cid_id,
        .author = author_id,
        .text = text_span,
        .created_at = in.created_at,
        .like_count = pending_like,
        .repost_count = pending_repost,
    });
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

/// Bump a like/repost count on the subject post, if we have it. An
/// engagement for a post we have not indexed is an ordinary miss (E4), not an
/// error — backfill/ordering is a Phase E concern.
pub fn indexEngagement(gpa: Allocator, idx: *Index, kind: Engagement, subject_cid: []const u8) Allocator.Error!void {
    const cid_id = try internStr(gpa, idx, subject_cid);
    if (idx.post_by_cid.get(cid_id)) |row| {
        switch (kind) {
            .like => idx.posts.items(.like_count)[row] +|= 1,
            .repost => idx.posts.items(.repost_count)[row] +|= 1,
        }
        return;
    }
    // Subject post not indexed yet — hold the engagement PENDING against its cid
    // rather than dropping it (E4 was a silent miss; that lost out-of-order
    // likes/reposts permanently once the caller marked the record seen).
    // `indexPost` drains this when the post arrives.
    const map = switch (kind) {
        .like => &idx.pending_likes,
        .repost => &idx.pending_reposts,
    };
    const gop = try map.getOrPut(gpa, cid_id);
    if (!gop.found_existing) gop.value_ptr.* = 0;
    gop.value_ptr.* +|= 1;
}

/// One row of an assembled timeline, as plain values crossing the boundary
/// (A5: DIDs/CIDs, never the internal index). The shell serializes these into
/// the lexicon's TimelinePage shape.
/// A7.2: cold struct, size guard waived — transient boundary value, arena-
/// built per request and serialized immediately, never bulk-resident.
pub const TimelineRow = struct {
    cid: []const u8,
    uri: []const u8 = "", // built by the shell from author+cid if needed
    author_did: []const u8,
    text: []const u8,
    created_at: i64,
    like_count: u32,
    repost_count: u32,
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
    const createds = idx.posts.items(.created_at);
    var rows: std.ArrayList(u32) = .empty;
    defer rows.deinit(arena);
    for (authors, 0..) |a, row| {
        if (followed.contains(a)) try rows.append(arena, @intCast(row));
    }

    // Reverse-chron: newest first. Sort row indices by created_at desc.
    const Ctx = struct {
        createds: []const i64,
        pub fn lessThan(ctx: @This(), a: u32, b: u32) bool {
            return ctx.createds[a] > ctx.createds[b]; // desc
        }
    };
    std.sort.block(u32, rows.items, Ctx{ .createds = createds }, Ctx.lessThan);

    const n = @min(limit, rows.items.len);
    const out = try arena.alloc(TimelineRow, n);
    const cids = idx.posts.items(.cid);
    const texts = idx.posts.items(.text);
    const likes = idx.posts.items(.like_count);
    const reposts = idx.posts.items(.repost_count);
    for (out, rows.items[0..n]) |*o, row| {
        o.* = .{
            .cid = str(idx, cids[row]),
            .author_did = str(idx, authors[row]),
            .text = blk: {
                const s = texts[row];
                break :blk idx.pool_bytes.items[s.off .. s.off + s.len];
            },
            .created_at = createds[row],
            .like_count = likes[row],
            .repost_count = reposts[row],
        };
    }
    return out;
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

test "engagement: like/repost bump counts; an unknown subject is a miss (E4)" {
    const gpa = testing.allocator;
    var idx: Index = .{};
    defer deinit(gpa, &idx);

    _ = try indexPost(gpa, &idx, .{ .cid = "c1", .author_did = "did:a", .text = "p", .created_at = 1 });
    try indexEngagement(gpa, &idx, .like, "c1");
    try indexEngagement(gpa, &idx, .like, "c1");
    try indexEngagement(gpa, &idx, .repost, "c1");
    try indexEngagement(gpa, &idx, .like, "c-missing"); // no such post yet: held pending, not lost

    try testing.expectEqual(@as(u32, 2), idx.posts.items(.like_count)[0]);
    try testing.expectEqual(@as(u32, 1), idx.posts.items(.repost_count)[0]);
}

test "engagement: an out-of-order like/repost (seen before its post) is held pending, then applied" {
    // Regression: the poll/consumer marks an engagement record 'seen' right
    // after calling indexEngagement; when the subject post wasn't indexed yet
    // (arbitrary cross-repo / firehose order) the old silent miss dropped the
    // count permanently. Now it pends against the subject cid and applies the
    // moment the post lands.
    const gpa = testing.allocator;
    var idx: Index = .{};
    defer deinit(gpa, &idx);

    // Three engagements arrive BEFORE the post they reference.
    try indexEngagement(gpa, &idx, .like, "cLate");
    try indexEngagement(gpa, &idx, .like, "cLate");
    try indexEngagement(gpa, &idx, .repost, "cLate");
    try testing.expectEqual(@as(usize, 0), idx.posts.len); // nothing indexed yet

    // The post finally arrives — it adopts the pending counts.
    try testing.expect(try indexPost(gpa, &idx, .{ .cid = "cLate", .author_did = "did:a", .text = "p", .created_at = 1 }));
    try testing.expectEqual(@as(u32, 2), idx.posts.items(.like_count)[0]);
    try testing.expectEqual(@as(u32, 1), idx.posts.items(.repost_count)[0]);

    // A later engagement (post now present) bumps directly.
    try indexEngagement(gpa, &idx, .like, "cLate");
    try testing.expectEqual(@as(u32, 3), idx.posts.items(.like_count)[0]);
}
