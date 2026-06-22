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

//! B1 classification: CORE (pure). The **feed deep module's** data heart.
//!
//! This file is where the doctrine stops being headers and becomes layout.
//! The feed module spans two files: this one — the resident store and every
//! pure transform over it (ingest, dedup, view-model building) — and
//! src/shell/feed.zig, the thin fetch choreography. Consumers of DATA
//! (main today, the renderer in Phase 5) import this file; nothing here
//! touches the network or the clock (B2/B4) — timestamps are parsed from
//! bytes the shell handed over.
//!
//! Layout, by the law:
//!   * A2/A3 — there is no "single Post" anywhere: posts, authors, and feed
//!     items live in `MultiArrayList` struct-of-arrays from the first one.
//!   * A4 — every cross-record reference is a typed u32 index
//!     (`AuthorIndex`, `PostIndex`), modeled on the compiler's `Ast.Node`.
//!   * A5 — those indexes never leave this module: `buildTimeline` resolves
//!     everything into plain values before anything crosses the boundary.
//!   * A6 — no `bool` fields anywhere; absence is encoded in the data
//!     (a zero-length span, an `Optional*Index.none`).
//!   * A7 — every resident record carries an exact-size guard. The build
//!     fails the instant a layout regresses.
//!   * A8 — the CID is post identity: one interning map, same CID ⇒ same
//!     record ⇒ ingest skips ALL re-parsing work on a duplicate. Strings
//!     intern through std's `StringIndexContext` machinery — the same
//!     pattern the Zig compiler uses — so dedup keys are offsets into the
//!     one string buffer, never duplicated owned strings.
//!
//! String memory: every variable-length string (text, handles, CIDs, URIs)
//! is appended once to a single byte buffer and referenced by `TextSpan`.
//! Each entry is NUL-terminated (one byte) so any span can serve as an
//! interning key in place. The buffer is append-only; offsets are stable
//! forever, which is precisely why records hold spans and never slices.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const lexicon = @import("lexicon.zig");
const moderation = @import("moderation.zig");

// ---------------------------------------------------------------------------
// The resident records — hot, guarded, integer-only
// ---------------------------------------------------------------------------

/// Offset + length into `Store.string_bytes`.
pub const TextSpan = struct {
    offset: u32,
    len: u32,

    pub const empty: TextSpan = .{ .offset = 0, .len = 0 };

    comptime {
        // Budget: lives inside every hot record below. (A7)
        assert(@sizeOf(TextSpan) == 8);
    }
};

/// Index into `Store.posts`. Typed enums (per the Ast.Node pattern in the
/// project reference) so a post index cannot be handed where an author
/// index belongs.
pub const PostIndex = enum(u32) { _ };

pub const OptionalPostIndex = enum(u32) {
    none = std.math.maxInt(u32),
    _,

    pub fn unwrap(opt: OptionalPostIndex) ?PostIndex {
        return if (opt == .none) null else @enumFromInt(@intFromEnum(opt));
    }

    pub fn from(index: PostIndex) OptionalPostIndex {
        const result: OptionalPostIndex = @enumFromInt(@intFromEnum(index));
        assert(result != .none);
        return result;
    }
};

/// Index into `Store.authors`.
pub const AuthorIndex = enum(u32) { _ };

pub const OptionalAuthorIndex = enum(u32) {
    none = std.math.maxInt(u32),
    _,

    pub fn unwrap(opt: OptionalAuthorIndex) ?AuthorIndex {
        return if (opt == .none) null else @enumFromInt(@intFromEnum(opt));
    }

    pub fn from(index: AuthorIndex) OptionalAuthorIndex {
        const result: OptionalAuthorIndex = @enumFromInt(@intFromEnum(index));
        assert(result != .none);
        return result;
    }
};

/// One post — content only, deduplicated by CID (A8). Why a post appears in
/// the feed (organically, reposted) is the FeedItem's business, so the same
/// post seen twice is stored once.
pub const Post = struct {
    /// Unix seconds, parsed exactly once at ingest. Sorting and relative
    /// ages are integer work in the core, never string re-parsing.
    created_at: i64,
    text: TextSpan,
    cid: TextSpan,
    /// at:// URI — the target Phase 6 needs to like/reply to this post.
    uri: TextSpan,
    author: AuthorIndex,
    reply_parent: OptionalPostIndex,
    reply_root: OptionalPostIndex,
    like_count: u32,
    repost_count: u32,
    reply_count: u32,
    quote_count: u32,
    /// Moderation flags, stored out of band as bits (A6) — the feed holds
    /// them as data; only the moderation module knows what they mean.
    label_flags: moderation.LabelFlags,

    comptime {
        // Budget 64: 8 (i64) + 3×8 (spans) + 7×4 (u32) + 2 (flags) = 62
        // bytes of payload; @sizeOf reports 64 because i64 alignment pads
        // the tail — the flags rode in on existing padding, budget unmoved.
        // In the SoA store every field lives in its own array, so that pad
        // never materializes in memory — the guard pins the honest @sizeOf
        // and forces a decision the moment any field grows. (A7;
        // raising this number requires A7.1 justification.)
        assert(@sizeOf(Post) == 64);
    }
};

/// One author, deduplicated by DID. Zero-length spans encode absence
/// (display name, avatar) — no booleans (A6).
pub const Author = struct {
    did: TextSpan,
    handle: TextSpan,
    display_name: TextSpan,
    avatar_url: TextSpan,

    comptime {
        // Budget 32: four spans, packed exactly. (A7)
        assert(@sizeOf(Author) == 32);
    }
};

/// One timeline entry: which post, and — if it is here because someone
/// reposted it — who. The same post can appear as several feed items.
pub const FeedItem = struct {
    post: PostIndex,
    reposted_by: OptionalAuthorIndex,

    comptime {
        // Budget 8: two u32 indexes, packed exactly. (A7)
        assert(@sizeOf(FeedItem) == 8);
    }
};

// ---------------------------------------------------------------------------
// The store — the feed subsystem's resident state
// ---------------------------------------------------------------------------

/// Offset-keyed interning map: keys are u32 offsets of NUL-terminated
/// strings inside `string_bytes`; values are record indexes. std's
/// StringIndex machinery (the compiler's own interning pattern — F2).
const SpanIndexMap = std.HashMapUnmanaged(
    u32,
    u32,
    std.hash_map.StringIndexContext,
    std.hash_map.default_max_load_percentage,
);

/// The feed subsystem's state: one string buffer, three SoA collections,
/// two interning maps, one pagination cursor. Owned by the caller, operated
/// on exclusively through the free functions in this file; the fields are
/// interior (D3 by convention — the language exposes them, the module
/// boundary does not).
/// A7.2: cold struct, size guard waived — a singleton per feed, never in a
/// collection; its CONTENTS are the hot, guarded records above.
pub const Store = struct {
    string_bytes: std.ArrayList(u8) = .empty,
    posts: std.MultiArrayList(Post) = .empty,
    authors: std.MultiArrayList(Author) = .empty,
    feed: std.MultiArrayList(FeedItem) = .empty,
    /// STAGED feed rows — newer posts the refresh fetched but has NOT revealed,
    /// so the reader isn't displaced. They are resident CONTENT (in `posts`); only
    /// the Home ORDERING waits here behind the "N new posts" pill until the reader
    /// opts in (taps the pill / is at the very top). `revealPending` flushes them
    /// to the front of `feed`. (Ordering is a query; this is a deferred ordering.)
    pending: std.MultiArrayList(FeedItem) = .empty,
    post_by_cid: SpanIndexMap = .empty,
    author_by_did: SpanIndexMap = .empty,
    /// Whether THIS account has liked/reposted each post — booleans stored
    /// out of band as bitsets, parallel to `posts` (A6 as written).
    liked: std.DynamicBitSetUnmanaged = .{},
    reposted: std.DynamicBitSetUnmanaged = .{},
    /// Optimistic-write GUARD, parallel to `posts` (A6). A bit is set when WE
    /// just changed our like/repost locally and the server has not yet caught
    /// up. While set, a refresh must NOT overwrite the local like/repost state
    /// or count — the AppView polls every few seconds, so a refresh landing
    /// between our tap and the server reflecting it would otherwise revert the
    /// heart/count (the "glitchy" flicker). Cleared the moment the server's
    /// view AGREES with ours (or on a revert). Wire-derived, not snapshotted.
    like_pending: std.DynamicBitSetUnmanaged = .{},
    repost_pending: std.DynamicBitSetUnmanaged = .{},
    /// The session account's like/repost RECORD uris, parallel to `posts`
    /// (A6: out-of-band, same shape as the bitsets). `.empty` = no record
    /// uri known. WIRE-DERIVED, deliberately NOT snapshotted: a refresh
    /// repopulates them; a cache-only item says "refresh to unlike" (E4 —
    /// absence is ordinary data, not an error).
    like_uris: std.ArrayList(TextSpan) = .empty,
    repost_uris: std.ArrayList(TextSpan) = .empty,
    /// Pagination cursor for the next page; zero-length = no further pages
    /// known. (Old cursors orphan a few bytes in the append-only buffer per
    /// page — accepted, same trade the compiler's string table makes.)
    next_cursor: TextSpan = .empty,
    /// An optimistically-set OWN display name awaiting server confirmation.
    /// While armed, `internAuthor` will NOT overwrite this author's name from a
    /// re-ingest (the 5s refresh carries the OLD name until the AppView re-polls
    /// the profile) — so the new name shows at 0ms and doesn't flicker back. It
    /// clears when the server serves the matching name. (Same shape as the
    /// like_pending guard.)
    pending_display: ?PendingDisplay = null,
};

/// A7.2: cold struct, size guard waived — at most one in flight, transient.
pub const PendingDisplay = struct {
    author: u32,
    name: TextSpan,
};

/// Release everything the store owns (C4: this subsystem frees its own
/// memory and nobody else's).
pub fn deinitStore(gpa: Allocator, store: *Store) void {
    store.string_bytes.deinit(gpa);
    store.posts.deinit(gpa);
    store.authors.deinit(gpa);
    store.feed.deinit(gpa);
    store.pending.deinit(gpa);
    store.post_by_cid.deinit(gpa);
    store.author_by_did.deinit(gpa);
    store.liked.deinit(gpa);
    store.reposted.deinit(gpa);
    store.like_pending.deinit(gpa);
    store.repost_pending.deinit(gpa);
    store.like_uris.deinit(gpa);
    store.repost_uris.deinit(gpa);
    store.* = undefined;
}

/// The cursor to send for the next page ("" = none). Borrows the store's
/// bytes; use before the next mutating call.
pub fn nextCursor(store: *const Store) []const u8 {
    return sliceSpan(store, store.next_cursor);
}

pub fn sliceSpan(store: *const Store, span: TextSpan) []const u8 {
    return store.string_bytes.items[span.offset..][0..span.len];
}

/// Append a string (plus a NUL so the span can serve as an interning key)
/// and return its span. Offsets are u32: a 4 GiB text budget, generations
/// beyond any session this client will hold.
fn appendString(gpa: Allocator, store: *Store, s: []const u8) error{OutOfMemory}!TextSpan {
    const offset: u32 = @intCast(store.string_bytes.items.len);
    try store.string_bytes.ensureUnusedCapacity(gpa, s.len + 1);
    store.string_bytes.appendSliceAssumeCapacity(s);
    store.string_bytes.appendAssumeCapacity(0);
    return .{ .offset = offset, .len = @intCast(s.len) };
}

// ---------------------------------------------------------------------------
// Ingest — the pure transform: one wire page in, flat indexed records out
// ---------------------------------------------------------------------------

/// What one page contributed. A7.2: cold struct, size guard waived — one
/// per ingest call.
pub const IngestStats = struct {
    items_added: u32 = 0,
    posts_added: u32 = 0,
    /// Posts whose CID was already resident: re-parse skipped entirely (A8).
    posts_deduped: u32 = 0,
    authors_added: u32 = 0,
};

/// Flatten a wire page into the store. Deterministic data-in/data-out
/// (B2): same store + same page ⇒ same result, no I/O, no clock.
pub fn ingestPage(
    gpa: Allocator,
    store: *Store,
    page: lexicon.TimelinePage,
) error{OutOfMemory}!IngestStats {
    var stats: IngestStats = .{};

    for (page.feed) |item| {
        const post_index = try internPageItem(gpa, store, item, &stats);

        const reposted_by: OptionalAuthorIndex = blk: {
            const reason = item.reason orelse break :blk .none;
            if (reason.by.did.len == 0) break :blk .none; // a pin, or partial data (E4)
            break :blk .from(try internAuthor(gpa, store, reason.by, &stats));
        };

        try store.feed.append(gpa, .{ .post = post_index, .reposted_by = reposted_by });
        stats.items_added += 1;
    }

    store.next_cursor = if (page.cursor) |cursor|
        try appendString(gpa, store, cursor)
    else
        .empty;

    return stats;
}

/// Intern one page item's CONTENT (the post + its reply linkage) into the
/// store, returning its index. Shared by ingestPage (which also records a Home
/// feed-ordering row) and ingestPosts (which records no ordering at all). A8:
/// a resident CID returns its existing index.
fn internPageItem(gpa: Allocator, store: *Store, item: lexicon.FeedViewPost, stats: *IngestStats) error{OutOfMemory}!PostIndex {
    const post_index = try internPost(gpa, store, item.post, stats, false);
    // Reply context: parent/root arrive hydrated as PostViews and are interned
    // as ordinary posts (A2: the bulk path serves them too); notFound/blocked
    // variants parse to an empty cid and stay .none.
    if (item.reply) |reply| {
        const parent = try internPostIfPresent(gpa, store, reply.parent, stats);
        const root = try internPostIfPresent(gpa, store, reply.root, stats);
        const posts = store.posts.slice();
        posts.items(.reply_parent)[@intFromEnum(post_index)] = parent;
        posts.items(.reply_root)[@intFromEnum(post_index)] = root;
    }
    return post_index;
}

/// Ingest a page's posts as CONTENT ONLY — into the shared `store.posts`, with
/// NO Home feed-ordering rows and WITHOUT touching the Home pagination cursor.
/// This is how a non-Home VIEW (a profile, later a zone) populates the one
/// store it shares with everything else: the posts become resident and
/// engagement/identity stay unified, while the view's ORDERING is derived
/// separately by a query (e.g. `buildAuthorView`). A8 dedups by CID, so a post
/// already held (from Home or another view) is not duplicated.
pub fn ingestPosts(gpa: Allocator, store: *Store, page: lexicon.TimelinePage) error{OutOfMemory}!IngestStats {
    var stats: IngestStats = .{};
    for (page.feed) |item| {
        _ = try internPageItem(gpa, store, item, &stats);
        stats.items_added += 1;
    }
    return stats;
}

/// Refresh ingest: the page is the NEWEST slice (fetched without a
/// cursor), so its previously-unseen rows enter at the FRONT of the feed,
/// in page order — newest stays first, and the reader's place below only
/// shifts down. The pagination cursor is NOT touched: refresh looks up,
/// "load older" keeps walking down from wherever it was. Posts dedup by
/// CID as everywhere (A8); feed rows dedup by their (post, reposted_by)
/// pair, since a repost of a seen post is a genuinely new row. The pair
/// scan is linear over the feed — hundreds of items against a network
/// fetch (G3: not worth cleverness).
pub fn ingestPageRefresh(
    gpa: Allocator,
    store: *Store,
    page: lexicon.TimelinePage,
) error{OutOfMemory}!IngestStats {
    var stats: IngestStats = .{};
    var insert_at: usize = 0;

    for (page.feed) |item| {
        const post_index = try internPost(gpa, store, item.post, &stats, false);

        if (item.reply) |reply| {
            const parent = try internPostIfPresent(gpa, store, reply.parent, &stats);
            const root = try internPostIfPresent(gpa, store, reply.root, &stats);
            const posts = store.posts.slice();
            posts.items(.reply_parent)[@intFromEnum(post_index)] = parent;
            posts.items(.reply_root)[@intFromEnum(post_index)] = root;
        }

        const reposted_by: OptionalAuthorIndex = blk: {
            const reason = item.reason orelse break :blk .none;
            if (reason.by.did.len == 0) break :blk .none; // a pin, or partial data (E4)
            break :blk .from(try internAuthor(gpa, store, reason.by, &stats));
        };

        // Dedup against BOTH the revealed feed AND the staging area, so a post
        // already shown (or already waiting behind the pill) is not re-staged.
        const already_known = blk: {
            const feed_posts = store.feed.items(.post);
            const feed_reposters = store.feed.items(.reposted_by);
            for (feed_posts, feed_reposters) |fp, fr| {
                if (fp == post_index and fr == reposted_by) break :blk true;
            }
            const pend_posts = store.pending.items(.post);
            const pend_reposters = store.pending.items(.reposted_by);
            for (pend_posts, pend_reposters) |fp, fr| {
                if (fp == post_index and fr == reposted_by) break :blk true;
            }
            break :blk false;
        };
        if (!already_known) {
            // STAGE it (do not displace the reader). `revealPending` moves the
            // staged rows to the front of the feed when the reader opts in.
            try store.pending.insert(gpa, insert_at, .{
                .post = post_index,
                .reposted_by = reposted_by,
            });
            insert_at += 1;
            stats.items_added += 1;
        }
    }

    return stats;
}

/// Number of staged-but-unrevealed new posts — the "N new posts" pill count.
pub fn pendingCount(store: *const Store) usize {
    return store.pending.len;
}

/// Reveal the staged new posts: move them, in order, to the FRONT of the Home
/// feed (newest first), then clear the staging area. The caller scrolls to the
/// top so the reader lands on the new posts. Returns how many were revealed.
pub fn revealPending(gpa: Allocator, store: *Store) error{OutOfMemory}!usize {
    const n = store.pending.len;
    if (n == 0) return 0;
    var i: usize = n;
    while (i > 0) {
        i -= 1; // insert from the back so the staged order is preserved at the front
        try store.feed.insert(gpa, 0, .{
            .post = store.pending.items(.post)[i],
            .reposted_by = store.pending.items(.reposted_by)[i],
        });
    }
    store.pending.clearRetainingCapacity();
    return n;
}

/// Intern an author by DID. First sighting wins the display fields for now;
/// profile freshness becomes the cache module's concern (Phase 8).
fn internAuthor(
    gpa: Allocator,
    store: *Store,
    profile: lexicon.ProfileViewBasic,
    stats: *IngestStats,
) error{OutOfMemory}!AuthorIndex {
    const gop = try store.author_by_did.getOrPutContextAdapted(
        gpa,
        profile.did,
        std.hash_map.StringIndexAdapter{ .bytes = &store.string_bytes },
        std.hash_map.StringIndexContext{ .bytes = &store.string_bytes },
    );
    if (gop.found_existing) {
        const ai: u32 = gop.value_ptr.*;
        // Identity (handle, display name) is NOT content-addressed the way a
        // post's CID is — it can change, and an earlier page may have carried
        // the DID as a placeholder handle before the AppView resolved the real
        // one. Reconcile a fresher non-empty value, but only on an ACTUAL change
        // so the string pool doesn't grow on every refresh.
        const authors = store.authors.slice();
        if (profile.handle.len > 0 and
            !std.mem.eql(u8, sliceSpan(store, authors.items(.handle)[ai]), profile.handle))
        {
            authors.items(.handle)[ai] = try appendString(gpa, store, profile.handle);
        }
        if (profile.displayName) |dn| {
            if (dn.len > 0) {
                // Optimistic own-name guard: while a name change for THIS author
                // is pending, keep the optimistic value (don't let a stale
                // refresh overwrite it). When the server finally serves the
                // matching name, the change has landed — release the guard.
                if (store.pending_display) |pd| {
                    if (pd.author == ai) {
                        if (std.mem.eql(u8, sliceSpan(store, pd.name), dn)) store.pending_display = null;
                        return @enumFromInt(ai); // either way, don't overwrite
                    }
                }
                if (!std.mem.eql(u8, sliceSpan(store, authors.items(.display_name)[ai]), dn))
                    authors.items(.display_name)[ai] = try appendString(gpa, store, dn);
            }
        }
        return @enumFromInt(ai);
    }

    const did = try appendString(gpa, store, profile.did);
    const handle = try appendString(gpa, store, profile.handle);
    const display_name = if (profile.displayName) |name|
        try appendString(gpa, store, name)
    else
        TextSpan.empty;
    const avatar_url = if (profile.avatar) |url|
        try appendString(gpa, store, url)
    else
        TextSpan.empty;

    const index: u32 = @intCast(store.authors.len);
    try store.authors.append(gpa, .{
        .did = did,
        .handle = handle,
        .display_name = display_name,
        .avatar_url = avatar_url,
    });
    gop.key_ptr.* = did.offset;
    gop.value_ptr.* = index;
    stats.authors_added += 1;
    return @enumFromInt(index);
}

/// Intern a post by CID — A8 made executable: a resident CID returns the
/// existing index immediately, skipping the author intern, the timestamp
/// parse, and every string append. Same CID ⇒ same bytes ⇒ never re-parsed.
fn internPost(
    gpa: Allocator,
    store: *Store,
    view: lexicon.PostView,
    stats: *IngestStats,
    /// True when `view` is a CONTEXT reference (a reply's hydrated parent/root),
    /// not the post's own feed view. A reference carries no authoritative counts
    /// or viewer state (it defaults them to 0/absent), so on an already-resident
    /// post we must NOT reconcile from it — else a reply referencing a post
    /// CLOBBERS that post's real reply/like counts to zero (the "count flips to
    /// zero" bug). Identity (handle) is still reconciled; that's content-free.
    is_reference: bool,
) error{OutOfMemory}!PostIndex {
    const gop = try store.post_by_cid.getOrPutContextAdapted(
        gpa,
        view.cid,
        std.hash_map.StringIndexAdapter{ .bytes = &store.string_bytes },
        std.hash_map.StringIndexContext{ .bytes = &store.string_bytes },
    );
    if (gop.found_existing) {
        stats.posts_deduped += 1;
        const index = gop.value_ptr.*;
        // Authorship LINKAGE is sealed by the CID (the post keeps its author
        // index), but the author's mutable IDENTITY (handle / display name) is
        // NOT content-addressed — reconcile it so a handle the AppView resolved
        // AFTER this post was first cached reaches the resident copy too (the
        // home feed's "shows the DID" fix). internAuthor dedups by DID and
        // rewrites only on a real change, so this is cheap and idempotent.
        _ = try internAuthor(gpa, store, view.author, stats);
        // A reference never reconciles counts/viewer — it has none to give.
        if (is_reference) return @enumFromInt(index);
        // A8 boundary: the CID seals the RECORD bytes (text/refs are never
        // re-parsed). Counts and viewer state live on the VIEW wrapper, so
        // fresher server truth reconciles here — EXCEPT a like/repost we just
        // changed locally and the server hasn't reflected yet (the pending
        // guard), which we leave alone so a lagging refresh can't revert it.
        const posts = store.posts.slice();
        posts.items(.reply_count)[index] = view.replyCount;
        posts.items(.quote_count)[index] = view.quoteCount;

        // Like: the server reports our like via viewer.like (its record uri),
        // and OMITS viewer when we have not liked it — so absence means "not
        // liked", not "no info".
        const server_like: ?[]const u8 = if (view.viewer) |v| v.like else null;
        // If a pending optimistic change now AGREES with the server, it's
        // confirmed — clear the guard so server truth flows again.
        if (store.like_pending.isSet(index) and (server_like != null) == store.liked.isSet(index)) {
            store.like_pending.unset(index);
        }
        if (!store.like_pending.isSet(index)) {
            store.liked.setValue(index, server_like != null);
            store.like_uris.items[index] = if (server_like) |u| try appendString(gpa, store, u) else .empty;
            posts.items(.like_count)[index] = view.likeCount;
        }

        // Repost: same shape.
        const server_repost: ?[]const u8 = if (view.viewer) |v| v.repost else null;
        if (store.repost_pending.isSet(index) and (server_repost != null) == store.reposted.isSet(index)) {
            store.repost_pending.unset(index);
        }
        if (!store.repost_pending.isSet(index)) {
            store.reposted.setValue(index, server_repost != null);
            store.repost_uris.items[index] = if (server_repost) |u| try appendString(gpa, store, u) else .empty;
            posts.items(.repost_count)[index] = view.repostCount;
        }
        return @enumFromInt(index);
    }

    const author = try internAuthor(gpa, store, view.author, stats);
    const cid = try appendString(gpa, store, view.cid);
    const uri = try appendString(gpa, store, view.uri);
    const text = try appendString(gpa, store, view.record.text);

    // A malformed createdAt degrades that one post to the epoch instead of
    // failing the page — deliberate policy (E4): bad data from the network
    // is ordinary, and one post's bad clock must not sink its neighbors (E2).
    const created_at = parseTimestamp(view.record.createdAt) catch 0;

    const index: u32 = @intCast(store.posts.len);
    try store.posts.append(gpa, .{
        .created_at = created_at,
        .text = text,
        .cid = cid,
        .uri = uri,
        .author = author,
        .reply_parent = .none,
        .reply_root = .none,
        .like_count = view.likeCount,
        .repost_count = view.repostCount,
        .reply_count = view.replyCount,
        .quote_count = view.quoteCount,
        .label_flags = moderation.flagsFromLabels(view.labels),
    });
    try store.liked.resize(gpa, store.posts.len, false);
    try store.reposted.resize(gpa, store.posts.len, false);
    try store.like_pending.resize(gpa, store.posts.len, false);
    try store.repost_pending.resize(gpa, store.posts.len, false);
    try store.like_uris.resize(gpa, store.posts.len);
    try store.repost_uris.resize(gpa, store.posts.len);
    store.like_uris.items[index] = .empty;
    store.repost_uris.items[index] = .empty;
    if (view.viewer) |viewer| {
        if (viewer.like) |u| {
            store.liked.set(index);
            store.like_uris.items[index] = try appendString(gpa, store, u);
        }
        if (viewer.repost) |u| {
            store.reposted.set(index);
            store.repost_uris.items[index] = try appendString(gpa, store, u);
        }
    }
    gop.key_ptr.* = cid.offset;
    gop.value_ptr.* = index;
    stats.posts_added += 1;
    return @enumFromInt(index);
}

fn internPostIfPresent(
    gpa: Allocator,
    store: *Store,
    view: lexicon.PostView,
    stats: *IngestStats,
) error{OutOfMemory}!OptionalPostIndex {
    if (view.cid.len == 0) return .none;
    return .from(try internPost(gpa, store, view, stats, true));
}

// ---------------------------------------------------------------------------
// View-models — what crosses the boundary toward the renderer
// ---------------------------------------------------------------------------

/// Per-item viewer flags carried on the view-model as packed bits.
pub const ItemFlags = packed struct(u8) {
    viewer_liked: bool = false,
    viewer_reposted: bool = false,
    _reserved: u6 = 0,

    pub const none: ItemFlags = .{};

    comptime {
        // Budget 1: rides the TimelineItem tail padding. (A7)
        assert(@sizeOf(ItemFlags) == 1);
    }
};

/// One render-ready timeline entry: PLAIN VALUES ONLY. Indexes never leave
/// this module (A5) — every reference is resolved here; the post's
/// uri + cid travel along as the STABLE IDS the write path hands back when
/// acting on a post (A5's prescribed currency across the boundary). The
/// string slices BORROW the store's byte buffer read-only: self-contained
/// values, no mutable sharing (E1), valid until the next mutating call on
/// the store; the per-frame arena pattern (C3) makes that lifetime natural.
pub const TimelineItem = struct {
    uri: []const u8,
    cid: []const u8,
    author_handle: []const u8,
    /// "" when the author set no display name.
    author_display_name: []const u8,
    /// "" unless this entry is in the feed because this account reposted it.
    reposted_by_handle: []const u8,
    /// "" unless this post replies to someone (then: the parent's author).
    replying_to_handle: []const u8,
    text: []const u8,
    created_at: i64,
    like_count: u32,
    repost_count: u32,
    reply_count: u32,
    quote_count: u32,
    /// Moderation flags as plain data; the renderer asks the moderation
    /// module for the verdict — neither side knows the other's interior.
    label_flags: moderation.LabelFlags,
    item_flags: ItemFlags,
    /// Thread nesting depth (0 = root) and whether this is the focused post —
    /// VIEW-DERIVED state set only by `buildThreadView` (the reader's lens;
    /// never on the stored Post). Both default off, riding the tail padding.
    depth: u8 = 0,
    is_focus: bool = false,

    comptime {
        // Produced in bulk every build — hot, so guarded (A7). Slices make
        // the size pointer-width-dependent; the budget is pinned where the
        // record is its packed self and degrades to nothing off 64-bit.
        // (A7.1 record, third raise: 112 → 144. The write path needs uri +
        // cid on the item — they are the stable ids A5 prescribes for
        // crossing the boundary — and ItemFlags rides the tail padding
        // (7×16 slices + 8 i64 + 16 counts + 2 + 1 = 139 payload, 5 pad).
        // depth + is_focus take 2 of those 5 pad bytes — still 144. Second
        // raise: +2 LabelFlags for moderation. First raise: the guard caught
        // a budget that counted four slices when five were present.)
        if (@sizeOf(usize) == 8) assert(@sizeOf(TimelineItem) == 144);
    }
};

/// Build the render-ready timeline, in feed order, into the caller's arena.
/// Pure resolution over the arrays — the SoA layout means each loop reads
/// exactly the columns it touches.
pub fn buildTimeline(
    arena: Allocator,
    store: *const Store,
) error{OutOfMemory}![]TimelineItem {
    const out = try arena.alloc(TimelineItem, store.feed.len);
    const feed = store.feed.slice();
    for (feed.items(.post), feed.items(.reposted_by), out) |post_index, reposted_by, *item| {
        item.* = fillTimelineItem(store, @intFromEnum(post_index), reposted_by);
    }
    return out;
}

/// Build the render-ready view-model for ONE post + its (optional) reposter.
/// The single seam every VIEW shares: Home (store.feed order), a profile
/// (one author's posts), a zone (a tag query), an algorithm (a scored order)
/// are all just different ORDERINGS of post indices over the one store — the
/// post is the post (ZONES invariant 4), seen through N lenses. Pure.
fn fillTimelineItem(store: *const Store, p: usize, reposted_by: OptionalAuthorIndex) TimelineItem {
    const posts = store.posts.slice();
    const authors = store.authors.slice();
    const post_authors = posts.items(.author);
    const author_handles = authors.items(.handle);
    const author_display_names = authors.items(.display_name);
    const author = @intFromEnum(post_authors[p]);

    const replying_to: []const u8 = if (posts.items(.reply_parent)[p].unwrap()) |parent| blk: {
        const parent_author = @intFromEnum(post_authors[@intFromEnum(parent)]);
        break :blk sliceSpan(store, author_handles[parent_author]);
    } else "";

    const reposted_by_handle: []const u8 = if (reposted_by.unwrap()) |reposter|
        sliceSpan(store, author_handles[@intFromEnum(reposter)])
    else
        "";

    return .{
        .uri = sliceSpan(store, posts.items(.uri)[p]),
        .cid = sliceSpan(store, posts.items(.cid)[p]),
        .author_handle = sliceSpan(store, author_handles[author]),
        .author_display_name = sliceSpan(store, author_display_names[author]),
        .reposted_by_handle = reposted_by_handle,
        .replying_to_handle = replying_to,
        .text = sliceSpan(store, posts.items(.text)[p]),
        .created_at = posts.items(.created_at)[p],
        .like_count = posts.items(.like_count)[p],
        .repost_count = posts.items(.repost_count)[p],
        .reply_count = posts.items(.reply_count)[p],
        .quote_count = posts.items(.quote_count)[p],
        .label_flags = posts.items(.label_flags)[p],
        .item_flags = .{
            .viewer_liked = store.liked.isSet(p),
            .viewer_reposted = store.reposted.isSet(p),
        },
    };
}

/// Build a VIEW of one author's own posts over the SHARED store, reverse-chron
/// — the profile screen's body. PURE: a query, not a container (ZONES inv. 4).
/// The posts are the same records Home/zones/etc. reference; engagement and
/// identity therefore stay consistent across every view automatically. An
/// unknown author is an empty view (E4). Allocates in `arena` (C3).
pub fn buildAuthorView(
    arena: Allocator,
    store: *const Store,
    author_did: []const u8,
) error{OutOfMemory}![]TimelineItem {
    const author_index = store.author_by_did.getAdapted(
        author_did,
        std.hash_map.StringIndexAdapter{ .bytes = &store.string_bytes },
    ) orelse return &.{};

    const posts = store.posts.slice();
    const post_authors = posts.items(.author);
    const createds = posts.items(.created_at);

    // Collect this author's post rows, then sort reverse-chron. A flat scan over
    // the resident posts is right for Cut 1 (G3: trivial against network wait).
    var rows: std.ArrayList(u32) = .empty;
    defer rows.deinit(arena);
    for (post_authors, 0..) |a, p| {
        if (@intFromEnum(a) == author_index) try rows.append(arena, @intCast(p));
    }
    const Ctx = struct {
        createds: []const i64,
        pub fn lessThan(ctx: @This(), x: u32, y: u32) bool {
            return ctx.createds[x] > ctx.createds[y]; // newest first
        }
    };
    std.sort.block(u32, rows.items, Ctx{ .createds = createds }, Ctx.lessThan);

    const out = try arena.alloc(TimelineItem, rows.items.len);
    for (rows.items, out) |p, *item| item.* = fillTimelineItem(store, p, .none);
    return out;
}

/// Build a post's THREAD as a Reddit-style NESTED view over the shared store
/// (ZONES inv. 4 — a query, not a container): walk `reply_parent` up to the
/// thread root, then DFS the whole descendant tree in preorder (siblings
/// chronological), stamping each item's view-derived `depth` (root = 0) and
/// marking the focused post. The store already holds the reply linkage (every
/// ingested post interns its reply refs), so the nesting is derived locally —
/// engagement/identity stay unified with every other view, and the nesting is a
/// LENS over the same records, never a property of the post. An unknown focus
/// cid is an empty view (E4). Allocates in `arena`.
pub fn buildThreadView(
    arena: Allocator,
    store: *const Store,
    focus_cid: []const u8,
) error{OutOfMemory}![]TimelineItem {
    const focus_usize = lookupCid(store, focus_cid) orelse return &.{};
    const focus: u32 = @intCast(focus_usize);
    const posts = store.posts.slice();
    const parents = posts.items(.reply_parent);
    const createds = posts.items(.created_at);

    // Walk up to the thread root (cycle-guarded).
    var root: u32 = focus;
    var guard: usize = 0;
    while (guard < 4096) : (guard += 1) {
        const p = parents[root].unwrap() orelse break;
        root = @intFromEnum(p);
    }

    // parent row → child rows (the tree, built from the exact parent edges).
    var children: std.AutoHashMapUnmanaged(u32, std.ArrayListUnmanaged(u32)) = .empty;
    defer {
        var vit = children.valueIterator();
        while (vit.next()) |v| v.deinit(arena);
        children.deinit(arena);
    }
    for (parents, 0..) |pp, row| {
        if (pp.unwrap()) |pi| {
            const pr: u32 = @intFromEnum(pi);
            const gop = try children.getOrPut(arena, pr);
            if (!gop.found_existing) gop.value_ptr.* = .empty;
            try gop.value_ptr.append(arena, @intCast(row));
        }
    }

    const Asc = struct {
        createds: []const i64,
        pub fn lessThan(ctx: @This(), x: u32, y: u32) bool {
            return ctx.createds[x] < ctx.createds[y]; // oldest first
        }
    };

    // DFS preorder via an explicit stack: pop a node, emit it, push its children
    // in REVERSE chronological order so the oldest pops (and renders) first —
    // each subtree fully emitted before the next sibling (the nested order).
    const Frame = struct { row: u32, depth: u8 };
    var out: std.ArrayList(TimelineItem) = .empty;
    defer out.deinit(arena);
    var stack: std.ArrayList(Frame) = .empty;
    defer stack.deinit(arena);
    try stack.append(arena, .{ .row = root, .depth = 0 });
    while (stack.pop()) |fr| {
        var item = fillTimelineItem(store, fr.row, .none);
        item.depth = fr.depth;
        item.is_focus = fr.row == focus;
        try out.append(arena, item);
        if (children.get(fr.row)) |kids| {
            const ks = try arena.dupe(u32, kids.items);
            std.sort.block(u32, ks, Asc{ .createds = createds }, Asc.lessThan);
            var i = ks.len;
            while (i > 0) {
                i -= 1;
                try stack.append(arena, .{ .row = ks[i], .depth = fr.depth +| 1 });
            }
        }
    }
    return out.toOwnedSlice(arena);
}

// ---------------------------------------------------------------------------
// Live ingest — one post arriving off the stream, prepended (it is newer
// than everything held). Input is plain values defined HERE: the feed
// never imports the stream's wire module (D3); the shell translates.
// ---------------------------------------------------------------------------

/// A7.2: cold struct, size guard waived — one per event at the boundary.
pub const LivePostInput = struct {
    did: []const u8,
    handle: []const u8, // "" when the stream knows only the DID
    uri: []const u8,
    cid: []const u8,
    text: []const u8,
    reply_parent_cid: []const u8, // "" when not a reply
    reply_root_cid: []const u8,
    created_at: i64,
};

pub const LiveIngest = enum { added, duplicate };

/// Ingest one live post. A CID already held is a duplicate (A8) — the
/// stream often replays what the timeline already fetched. New posts
/// enter at feed position 0 with zero counts; server truth reconciles
/// them at the next page dedup, like everything else.
///
/// Recorded gap: the stream carries no moderation labels (labelers are a
/// separate channel), so live posts render unlabeled until a timeline
/// refresh reconciles them. Acceptable v1 because the subscription is
/// the already-followed graph; noted in the roadmap.
pub fn ingestLivePost(
    gpa: Allocator,
    store: *Store,
    input: LivePostInput,
) error{OutOfMemory}!LiveIngest {
    if (lookupCid(store, input.cid) != null) return .duplicate;

    var stats: IngestStats = .{};
    const author = try internAuthor(gpa, store, .{
        .did = input.did,
        .handle = if (input.handle.len > 0) input.handle else input.did,
    }, &stats);

    const cid = try appendString(gpa, store, input.cid);
    const uri = try appendString(gpa, store, input.uri);
    const text = try appendString(gpa, store, input.text);

    const index: u32 = @intCast(store.posts.len);
    try store.posts.append(gpa, .{
        .created_at = input.created_at,
        .text = text,
        .cid = cid,
        .uri = uri,
        .author = author,
        .reply_parent = if (input.reply_parent_cid.len > 0)
            optionalIndexForCid(store, input.reply_parent_cid)
        else
            .none,
        .reply_root = if (input.reply_root_cid.len > 0)
            optionalIndexForCid(store, input.reply_root_cid)
        else
            .none,
        .like_count = 0,
        .repost_count = 0,
        .reply_count = 0,
        .quote_count = 0,
        .label_flags = .none,
    });
    try store.liked.resize(gpa, store.posts.len, false);
    try store.reposted.resize(gpa, store.posts.len, false);
    try store.like_pending.resize(gpa, store.posts.len, false);
    try store.repost_pending.resize(gpa, store.posts.len, false);
    // The like/repost record-uri arrays are part of the same parallel
    // group as `posts`/`liked`/`reposted` (A3): they MUST grow together or
    // an index valid for `posts` overruns `like_uris`. The fetch path
    // resizes all four; this live path previously grew only the two
    // bitsets, so a freshly-arrived live post had no like_uris slot — and
    // liking then unliking it indexed past the end (the crash). A live
    // post is not yet engaged, so its new slots start empty.
    try store.like_uris.resize(gpa, store.posts.len);
    try store.repost_uris.resize(gpa, store.posts.len);
    store.like_uris.items[index] = .empty;
    store.repost_uris.items[index] = .empty;

    const gop = try store.post_by_cid.getOrPutContextAdapted(
        gpa,
        input.cid,
        std.hash_map.StringIndexAdapter{ .bytes = &store.string_bytes },
        std.hash_map.StringIndexContext{ .bytes = &store.string_bytes },
    );
    gop.key_ptr.* = cid.offset;
    gop.value_ptr.* = index;

    // Newest first: live posts lead the feed.
    try store.feed.insert(gpa, 0, .{
        .post = @enumFromInt(index),
        .reposted_by = .none,
    });
    return .added;
}

fn optionalIndexForCid(store: *const Store, cid_bytes: []const u8) OptionalPostIndex {
    const index = lookupCid(store, cid_bytes) orelse return .none;
    return OptionalPostIndex.from(@enumFromInt(index));
}

/// Optimistically bump the resident post's reply_count by one (the parent of a
/// just-sent reply), so the count moves INSTANTLY rather than waiting for the
/// next refresh. A no-op if the cid isn't resident. The server reconciles the
/// real count on the next fetch (and a reference can no longer downgrade it).
pub fn bumpReplyCount(store: *Store, cid_bytes: []const u8) void {
    const index = lookupCid(store, cid_bytes) orelse return;
    store.posts.items(.reply_count)[index] += 1;
}

/// Optimistically set an author's (your own) display name so it shows at 0ms,
/// arming the guard so a stale refresh can't overwrite it before the server
/// catches up. No-op if the author isn't resident. The server reconciles it (and
/// releases the guard) once it re-polls the profile and serves the new name.
pub fn setOwnDisplayName(gpa: Allocator, store: *Store, did: []const u8, name: []const u8) error{OutOfMemory}!void {
    const ai = store.author_by_did.getAdapted(did, std.hash_map.StringIndexAdapter{ .bytes = &store.string_bytes }) orelse return;
    const span = try appendString(gpa, store, name);
    store.authors.items(.display_name)[ai] = span;
    store.pending_display = .{ .author = ai, .name = span };
}

/// Release the optimistic display-name guard (e.g. the write failed) so the next
/// refresh restores the server's name.
pub fn clearPendingDisplay(store: *Store) void {
    store.pending_display = null;
}

/// Reconcile an OPTIMISTICALLY-inserted post (under a temporary cid) to its real
/// server identity once the create write confirms: repoint its cid + uri and
/// re-key the cid index. So the post persists AND the next refresh dedups it by
/// the real cid (A8) instead of adding a second copy. No-op if the temp cid
/// isn't resident (e.g. a refresh already replaced it).
pub fn reconcileOptimisticPost(
    gpa: Allocator,
    store: *Store,
    temp_cid: []const u8,
    real_cid: []const u8,
    real_uri: []const u8,
) error{OutOfMemory}!void {
    const index = lookupCid(store, temp_cid) orelse return;
    const adapter = std.hash_map.StringIndexAdapter{ .bytes = &store.string_bytes };
    const ctx = std.hash_map.StringIndexContext{ .bytes = &store.string_bytes };
    _ = store.post_by_cid.removeAdapted(temp_cid, adapter); // drop the temp key
    const cid = try appendString(gpa, store, real_cid);
    const uri = try appendString(gpa, store, real_uri);
    store.posts.items(.cid)[index] = cid;
    store.posts.items(.uri)[index] = uri;
    const gop = try store.post_by_cid.getOrPutContextAdapted(gpa, real_cid, adapter, ctx);
    gop.key_ptr.* = cid.offset;
    gop.value_ptr.* = index;
}

/// Detach an optimistic post whose create FAILED: remove its feed row(s), un-key
/// its cid, and null its reply edges so it vanishes from BOTH the feed and any
/// thread (buildThreadView reaches posts via parent edges; with none, this slot
/// is an unreachable island). The slot stays in `posts` but is invisible — a
/// rare path (a failed write), self-healed on the next full reload.
pub fn dropOptimisticPost(store: *Store, temp_cid: []const u8) void {
    const index = lookupCid(store, temp_cid) orelse return;
    const idx_enum: PostIndex = @enumFromInt(index);
    var i: usize = 0;
    while (i < store.feed.len) {
        if (store.feed.items(.post)[i] == idx_enum) {
            store.feed.orderedRemove(i);
        } else i += 1;
    }
    store.posts.items(.reply_parent)[index] = .none;
    store.posts.items(.reply_root)[index] = .none;
    const adapter = std.hash_map.StringIndexAdapter{ .bytes = &store.string_bytes };
    _ = store.post_by_cid.removeAdapted(temp_cid, adapter);
}

/// Up to `max` author DIDs currently held — what the stream subscribes
/// to. Slices borrow the store; the stream copies them (E1).
pub fn authorDids(arena: Allocator, store: *const Store, max: usize) error{OutOfMemory}![]const []const u8 {
    const count = @min(store.authors.len, max);
    const dids = try arena.alloc([]const u8, count);
    const spans = store.authors.items(.did);
    for (dids, spans[0..count]) |*out, span| out.* = sliceSpan(store, span);
    return dids;
}

// ---------------------------------------------------------------------------
// Write-side transforms — the read store doubles as the optimistic-update
// surface. Everything is keyed by CID, the stable id (A5/A8): the shell
// never sees an index.
// ---------------------------------------------------------------------------

fn lookupCid(store: *const Store, cid: []const u8) ?u32 {
    return store.post_by_cid.getAdapted(
        cid,
        std.hash_map.StringIndexAdapter{ .bytes = &store.string_bytes },
    );
}

/// Outcome of an optimistic mutation — values, not errors (E4): an unknown
/// cid or a duplicate action are ordinary states the caller branches on.
pub const Applied = enum { applied, already, unknown };

/// Optimistically record OUR like: flip the out-of-band bit and bump the
/// count, immediately visible to the next frame. The server call follows;
/// `revertLike` undoes this if it is refused; dedup-time reconciliation
/// later overwrites with server truth.
pub fn applyLike(store: *Store, cid: []const u8) Applied {
    const index = lookupCid(store, cid) orelse return .unknown;
    if (store.liked.isSet(index)) return .already;
    store.liked.set(index);
    store.like_pending.set(index); // unconfirmed local change — guard it from the lagging refresh
    store.posts.items(.like_count)[index] += 1;
    return .applied;
}

/// Record the uri of OUR newly-created like record (handed back by the write
/// once it lands) so a later UNLIKE can delete it. Without this the AppView's
/// missing `viewer.like` leaves the uri unknown and unlike is a no-op
/// (`.no_record_uri`). A no-op if the post has since scrolled out (E4). C1.
pub fn setLikeUri(gpa: Allocator, store: *Store, cid: []const u8, uri: []const u8) error{OutOfMemory}!void {
    const index = lookupCid(store, cid) orelse return;
    store.like_uris.items[index] = try appendString(gpa, store, uri);
}

/// As `setLikeUri`, for a repost record (so a later unrepost can delete it).
pub fn setRepostUri(gpa: Allocator, store: *Store, cid: []const u8, uri: []const u8) error{OutOfMemory}!void {
    const index = lookupCid(store, cid) orelse return;
    store.repost_uris.items[index] = try appendString(gpa, store, uri);
}

/// The disengage verdict: `applied` carries the like/repost RECORD uri
/// to delete. It BORROWS the store's bytes and is valid only until the
/// next store-mutating call — callers copy it out before reverting (the
/// revert path appends, which may realloc the buffer underneath it).
pub const Disengaged = union(enum) {
    applied: []const u8,
    not_engaged,
    /// Engaged, but the record uri is unknown (cache-warmed item, no
    /// refresh yet). The UI says so; nothing breaks (E4).
    no_record_uri,
    unknown,
};

fn spanSlice(store: *const Store, span: TextSpan) []const u8 {
    return store.string_bytes.items[span.offset..][0..span.len];
}

/// Optimistic unlike: clears the bit, drops the count, hands back the
/// record uri to delete, and forgets the uri (a second unlike before a
/// refresh is `.not_engaged`, never a dead-uri delete).
pub fn applyUnlike(store: *Store, cid: []const u8) Disengaged {
    const index = lookupCid(store, cid) orelse return .unknown;
    if (!store.liked.isSet(index)) return .not_engaged;
    const span = store.like_uris.items[index];
    if (span.len == 0) return .no_record_uri;
    store.liked.unset(index);
    store.like_pending.set(index); // unconfirmed local change — guard it from the lagging refresh
    store.posts.items(.like_count)[index] -|= 1;
    store.like_uris.items[index] = .empty;
    return .{ .applied = spanSlice(store, span) };
}

/// The server refused or the network failed: restore the bit, the count,
/// and the uri (re-appended from the caller's copy).
pub fn revertUnlike(gpa: Allocator, store: *Store, cid: []const u8, uri: []const u8) error{OutOfMemory}!void {
    const index = lookupCid(store, cid) orelse return;
    if (store.liked.isSet(index)) return;
    store.liked.set(index);
    store.like_pending.unset(index); // optimistic undone → back in sync with the server
    store.posts.items(.like_count)[index] += 1;
    store.like_uris.items[index] = try appendString(gpa, store, uri);
}

pub fn applyUnrepost(store: *Store, cid: []const u8) Disengaged {
    const index = lookupCid(store, cid) orelse return .unknown;
    if (!store.reposted.isSet(index)) return .not_engaged;
    const span = store.repost_uris.items[index];
    if (span.len == 0) return .no_record_uri;
    store.reposted.unset(index);
    store.repost_pending.set(index); // unconfirmed local change — guard it from the lagging refresh
    store.posts.items(.repost_count)[index] -|= 1;
    store.repost_uris.items[index] = .empty;
    return .{ .applied = spanSlice(store, span) };
}

pub fn revertUnrepost(gpa: Allocator, store: *Store, cid: []const u8, uri: []const u8) error{OutOfMemory}!void {
    const index = lookupCid(store, cid) orelse return;
    if (store.reposted.isSet(index)) return;
    store.reposted.set(index);
    store.repost_pending.unset(index); // optimistic undone → back in sync with the server
    store.posts.items(.repost_count)[index] += 1;
    store.repost_uris.items[index] = try appendString(gpa, store, uri);
}

/// Optimistic disengage when OUR like/repost record's uri is not known YET —
/// the create is still in flight, so `applyUnlike` would return `.no_record_uri`
/// and block undo until the round-trip finishes (the "can't unlike for a few
/// seconds" bug). Instead, hollow the heart and drop the count NOW, keeping the
/// pending guard so a lagging refresh can't re-fill it; the shell remembers to
/// delete the record the instant the create hands back its uri. Returns whether
/// it acted (false = not engaged / unknown post). The post is liked, so there's
/// always a record coming — undo just shouldn't wait for it.
pub fn applyUnlikeDeferred(store: *Store, cid: []const u8) bool {
    const index = lookupCid(store, cid) orelse return false;
    if (!store.liked.isSet(index)) return false;
    store.liked.unset(index);
    store.like_pending.set(index);
    store.posts.items(.like_count)[index] -|= 1;
    return true;
}

pub fn applyUnrepostDeferred(store: *Store, cid: []const u8) bool {
    const index = lookupCid(store, cid) orelse return false;
    if (!store.reposted.isSet(index)) return false;
    store.reposted.unset(index);
    store.repost_pending.set(index);
    store.posts.items(.repost_count)[index] -|= 1;
    return true;
}

pub fn revertLike(store: *Store, cid: []const u8) void {
    const index = lookupCid(store, cid) orelse return;
    if (!store.liked.isSet(index)) return;
    store.liked.unset(index);
    store.like_pending.unset(index); // optimistic undone → back in sync with the server
    const counts = store.posts.items(.like_count);
    counts[index] -|= 1;
}

pub fn applyRepost(store: *Store, cid: []const u8) Applied {
    const index = lookupCid(store, cid) orelse return .unknown;
    if (store.reposted.isSet(index)) return .already;
    store.reposted.set(index);
    store.repost_pending.set(index); // unconfirmed local change — guard it from the lagging refresh
    store.posts.items(.repost_count)[index] += 1;
    return .applied;
}

pub fn revertRepost(store: *Store, cid: []const u8) void {
    const index = lookupCid(store, cid) orelse return;
    if (!store.reposted.isSet(index)) return;
    store.reposted.unset(index);
    store.repost_pending.unset(index); // optimistic undone → back in sync with the server
    const counts = store.posts.items(.repost_count);
    counts[index] -|= 1;
}

/// Strong refs for replying to a post: parent is the post itself, root is
/// its thread root (or itself when it starts a thread).
/// A7.2: cold struct, size guard waived — one per composer open.
pub const ReplyRefs = struct {
    root_uri: []const u8,
    root_cid: []const u8,
    parent_uri: []const u8,
    parent_cid: []const u8,
};

/// Resolve the reply refs for a post by its CID. Borrows the store's
/// bytes — copy before the next mutating call if held across one.
pub fn replyRefsForCid(store: *const Store, cid: []const u8) ?ReplyRefs {
    const index = lookupCid(store, cid) orelse return null;
    const posts = store.posts.slice();
    const parent_uri = sliceSpan(store, posts.items(.uri)[index]);
    const parent_cid = sliceSpan(store, posts.items(.cid)[index]);
    if (posts.items(.reply_root)[index].unwrap()) |root| {
        const r = @intFromEnum(root);
        return .{
            .root_uri = sliceSpan(store, posts.items(.uri)[r]),
            .root_cid = sliceSpan(store, posts.items(.cid)[r]),
            .parent_uri = parent_uri,
            .parent_cid = parent_cid,
        };
    }
    return .{
        .root_uri = parent_uri,
        .root_cid = parent_cid,
        .parent_uri = parent_uri,
        .parent_cid = parent_cid,
    };
}

/// The DID of a post's author, by the post's CID ("" when unknown) —
/// what the follow verb needs.
pub fn authorDidForCid(store: *const Store, cid: []const u8) []const u8 {
    const index = lookupCid(store, cid) orelse return "";
    const author = @intFromEnum(store.posts.items(.author)[index]);
    return sliceSpan(store, store.authors.items(.did)[author]);
}

// ---------------------------------------------------------------------------
// Timestamps — ISO 8601 (the lexicon's datetime format) to unix seconds
// ---------------------------------------------------------------------------

/// Parse `YYYY-MM-DDTHH:MM:SS[.fraction](Z|±HH:MM)` to unix seconds.
/// Pure arithmetic (days-from-civil), no locale, no clock (B4 — even time
/// HANDLING is pure; only time READING would be shell).
pub fn parseTimestamp(s: []const u8) error{InvalidTimestamp}!i64 {
    if (s.len < 20) return error.InvalidTimestamp;
    if (s[4] != '-' or s[7] != '-' or (s[10] != 'T' and s[10] != 't') or
        s[13] != ':' or s[16] != ':') return error.InvalidTimestamp;

    const year = try parseDigits(s[0..4]);
    const month = try parseDigits(s[5..7]);
    const day = try parseDigits(s[8..10]);
    const hour = try parseDigits(s[11..13]);
    const minute = try parseDigits(s[14..16]);
    const second = try parseDigits(s[17..19]);
    if (month < 1 or month > 12 or day < 1 or day > 31) return error.InvalidTimestamp;
    if (hour > 23 or minute > 59 or second > 60) return error.InvalidTimestamp;

    var i: usize = 19;
    if (i < s.len and s[i] == '.') {
        i += 1;
        const frac_start = i;
        while (i < s.len and std.ascii.isDigit(s[i])) i += 1;
        if (i == frac_start) return error.InvalidTimestamp;
    }

    if (i >= s.len) return error.InvalidTimestamp;
    var offset_seconds: i64 = 0;
    switch (s[i]) {
        'Z', 'z' => if (i + 1 != s.len) return error.InvalidTimestamp,
        '+', '-' => {
            if (i + 6 != s.len or s[i + 3] != ':') return error.InvalidTimestamp;
            const oh = try parseDigits(s[i + 1 .. i + 3]);
            const om = try parseDigits(s[i + 4 .. i + 6]);
            if (oh > 23 or om > 59) return error.InvalidTimestamp;
            const magnitude: i64 = @as(i64, oh) * 3600 + @as(i64, om) * 60;
            offset_seconds = if (s[i] == '+') magnitude else -magnitude;
        },
        else => return error.InvalidTimestamp,
    }

    const days = daysFromCivil(year, month, day);
    const seconds_of_day: i64 = @as(i64, hour) * 3600 + @as(i64, minute) * 60 + second;
    return days * 86_400 + seconds_of_day - offset_seconds;
}

fn parseDigits(s: []const u8) error{InvalidTimestamp}!u32 {
    var value: u32 = 0;
    for (s) |c| {
        if (!std.ascii.isDigit(c)) return error.InvalidTimestamp;
        value = value * 10 + (c - '0');
    }
    return value;
}

/// Unix seconds to `YYYY-MM-DDTHH:MM:SSZ` — the inverse of
/// `parseTimestamp`, for outgoing records. The clock value always arrives
/// as an argument; only the shell reads time (B4).
pub fn formatTimestamp(buf: []u8, epoch: i64) []const u8 {
    const days = @divFloor(epoch, 86_400);
    const second_of_day = epoch - days * 86_400; // [0, 86399] for any sign
    const date = civilFromDays(days);
    return std.fmt.bufPrint(buf, "{d:0>4}-{d:0>2}-{d:0>2}T{d:0>2}:{d:0>2}:{d:0>2}Z", .{
        @as(u64, @intCast(date.year)),
        date.month,
        date.day,
        @as(u64, @intCast(@divFloor(second_of_day, 3_600))),
        @as(u64, @intCast(@mod(@divFloor(second_of_day, 60), 60))),
        @as(u64, @intCast(@mod(second_of_day, 60))),
    }) catch "";
}

const CivilDate = struct {
    // A7.2: cold struct, size guard waived — one per timestamp render.
    year: i64,
    month: u32,
    day: u32,
};

/// Hinnant's civil-from-days: the exact inverse of `daysFromCivil`.
fn civilFromDays(days: i64) CivilDate {
    const z = days + 719_468;
    const era = @divFloor(z, 146_097);
    const doe = z - era * 146_097; // [0, 146096]
    const yoe = @divFloor(doe - @divFloor(doe, 1_460) + @divFloor(doe, 36_524) - @divFloor(doe, 146_096), 365);
    const y = yoe + era * 400;
    const doy = doe - (365 * yoe + @divFloor(yoe, 4) - @divFloor(yoe, 100));
    const mp = @divFloor(5 * doy + 2, 153);
    const day = doy - @divFloor(153 * mp + 2, 5) + 1;
    const month: i64 = if (mp < 10) mp + 3 else mp - 9;
    return .{
        .year = if (month <= 2) y + 1 else y,
        .month = @intCast(month),
        .day = @intCast(day),
    };
}

/// Howard Hinnant's days-from-civil: proleptic Gregorian date to days since
/// 1970-01-01, in pure integer arithmetic.
fn daysFromCivil(year: u32, month: u32, day: u32) i64 {
    const y: i64 = if (month <= 2) @as(i64, year) - 1 else year;
    const era: i64 = @divFloor(y, 400);
    const yoe: i64 = y - era * 400; // [0, 399]
    const mp: i64 = @mod(@as(i64, month) + 9, 12); // March = 0
    const doy: i64 = @divFloor(153 * mp + 2, 5) + day - 1; // [0, 365]
    const doe: i64 = yoe * 365 + @divFloor(yoe, 4) - @divFloor(yoe, 100) + doy;
    return era * 146_097 + doe - 719_468;
}

// ---------------------------------------------------------------------------
// Tests — the heart of the doctrine, exercised entirely offline (B2),
// leak-checked (C6). The size guards above are themselves tests: they run
// at compile time on every build.
// ---------------------------------------------------------------------------

const testing = std.testing;

/// A realistic two-author page: alice posts; bob replies to alice (reply
/// refs carry alice's post AGAIN, exercising A8 within one page); bob
/// reposts alice's second post.
/// Shared by the snapshot and cache test suites (they need a realistically
/// populated store, and one fixture beats three drifting copies).
pub const fixture_page = lexicon.TimelinePage{
    .cursor = "CURSOR-1",
    .feed = &.{
        .{ .post = alice_post_1 },
        .{
            .post = .{
                .uri = "at://did:plc:bbbbbbbbbbbbbbbbbbbbbbbb/app.zat4.feed.post/3kbob1",
                .cid = "bafyreibob1",
                .author = bob,
                .record = .{ .text = "replying to alice", .createdAt = "2026-01-02T04:00:00Z" },
                .replyCount = 0,
                .repostCount = 0,
                .likeCount = 1,
                .quoteCount = 0,
            },
            .reply = .{ .root = alice_post_1, .parent = alice_post_1 },
        },
        .{
            .post = .{
                .uri = "at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/app.zat4.feed.post/3kali2",
                .cid = "bafyreialice2",
                .author = alice,
                .record = .{ .text = "alice's second post", .createdAt = "2026-01-02T05:00:00Z" },
                .replyCount = 0,
                .repostCount = 1,
                .likeCount = 7,
                .quoteCount = 2,
            },
            .reason = .{ .by = bob, .indexedAt = "2026-01-02T06:00:00Z" },
        },
    },
};

const alice = lexicon.ProfileViewBasic{
    .did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
    .handle = "alice.test",
    .displayName = "Alice",
};
const bob = lexicon.ProfileViewBasic{
    .did = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb",
    .handle = "bob.test",
};
const alice_post_1 = lexicon.PostView{
    .uri = "at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/app.zat4.feed.post/3kali1",
    .cid = "bafyreialice1",
    .author = alice,
    .record = .{ .text = "first post", .createdAt = "2026-01-02T03:04:05.678Z" },
    .replyCount = 1,
    .repostCount = 0,
    .likeCount = 3,
    .quoteCount = 0,
};

test "ingest: flattens a page into SoA records — authors and posts deduplicated" {
    const gpa = testing.allocator; // C6
    var store: Store = .{};
    defer deinitStore(gpa, &store);

    const stats = try ingestPage(gpa, &store, fixture_page);

    // 3 feed items; 3 distinct posts (alice1, bob-reply, alice2); alice's
    // post arrived three times in the wire page (item + root + parent) and
    // was parsed ONCE (A8): two dedup hits. Two authors, interned once each.
    try testing.expectEqual(@as(u32, 3), stats.items_added);
    try testing.expectEqual(@as(u32, 3), stats.posts_added);
    try testing.expectEqual(@as(u32, 2), stats.posts_deduped);
    try testing.expectEqual(@as(u32, 2), stats.authors_added);
    try testing.expectEqual(@as(usize, 3), store.posts.len);
    try testing.expectEqual(@as(usize, 2), store.authors.len);
    try testing.expectEqual(@as(usize, 3), store.feed.len);

    // The reply linkage points the bob post at alice's resident record.
    const bob_post = store.posts.get(1);
    const parent = bob_post.reply_parent.unwrap().?;
    try testing.expectEqualStrings(
        "bafyreialice1",
        sliceSpan(&store, store.posts.items(.cid)[@intFromEnum(parent)]),
    );

    // Timestamps were parsed once at ingest into integers.
    try testing.expectEqual(@as(i64, 1767323045), store.posts.items(.created_at)[0]);

    // Pagination cursor captured.
    try testing.expectEqualStrings("CURSOR-1", nextCursor(&store));
}

test "disengage: unlike hands out the record uri once, revert restores it" {
    const gpa = testing.allocator; // C6
    var store: Store = .{};
    defer deinitStore(gpa, &store);
    _ = try ingestPage(gpa, &store, fixture_page);

    // Seed what a wire viewer would have delivered for post 0, with a
    // deterministic count so the saturating math is observable.
    const seeded = "at://did:plc:alice/app.zat4.feed.like/3ktest";
    store.liked.set(0);
    store.like_uris.items[0] = try appendString(gpa, &store, seeded);
    store.posts.items(.like_count)[0] = 5;
    const cid0 = spanSlice(&store, store.posts.items(.cid)[0]);

    // Unlike: the uri comes out, the bit and count drop, the uri is
    // forgotten so a second press cannot send a dead delete.
    switch (applyUnlike(&store, cid0)) {
        .applied => |uri| try testing.expectEqualStrings(seeded, uri),
        else => return error.TestUnexpectedResult,
    }
    try testing.expect(!store.liked.isSet(0));
    try testing.expectEqual(@as(u32, 4), store.posts.items(.like_count)[0]);
    try testing.expectEqual(@as(u32, 0), store.like_uris.items[0].len);
    try testing.expect(applyUnlike(&store, cid0) == .not_engaged);

    // Revert restores all three — from a CALLER-OWNED copy, per the
    // documented borrow contract (the append may move the buffer).
    var copy_buf: [128]u8 = undefined;
    const copy = copy_buf[0..seeded.len];
    @memcpy(copy, seeded);
    try revertUnlike(gpa, &store, cid0, copy);
    try testing.expect(store.liked.isSet(0));
    try testing.expectEqual(@as(u32, 5), store.posts.items(.like_count)[0]);
    try testing.expectEqualStrings(seeded, spanSlice(&store, store.like_uris.items[0]));
}

test "disengage: a cache-warm like (no record uri) says so and touches nothing" {
    const gpa = testing.allocator; // C6
    var store: Store = .{};
    defer deinitStore(gpa, &store);
    _ = try ingestPage(gpa, &store, fixture_page);

    const cid0 = spanSlice(&store, store.posts.items(.cid)[0]);
    // applyLike is the optimistic local path: bit set, count up, NO uri —
    // exactly the state a snapshot-warmed store presents.
    try testing.expect(applyLike(&store, cid0) == .applied);
    const count = store.posts.items(.like_count)[0];

    switch (applyUnlike(&store, cid0)) {
        .no_record_uri => {},
        else => return error.TestUnexpectedResult,
    }
    // E4: the refusal is information, not mutation.
    try testing.expect(store.liked.isSet(0));
    try testing.expectEqual(count, store.posts.items(.like_count)[0]);

    // The DEFERRED unlike, by contrast, hollows the heart NOW (no uri needed):
    // the shell uses this so undo isn't blocked while the like's create is in
    // flight. The pending guard stays set so a lagging refresh can't re-fill it.
    try testing.expect(applyUnlikeDeferred(&store, cid0));
    try testing.expect(!store.liked.isSet(0));
    try testing.expect(store.like_pending.isSet(0));
    try testing.expectEqual(count - 1, store.posts.items(.like_count)[0]);
    // Not liked anymore ⇒ a second deferred unlike is a no-op.
    try testing.expect(!applyUnlikeDeferred(&store, cid0));
}

test "ingest: a second page deduplicates across pages by CID (A8)" {
    const gpa = testing.allocator; // C6
    var store: Store = .{};
    defer deinitStore(gpa, &store);

    _ = try ingestPage(gpa, &store, fixture_page);
    const second = lexicon.TimelinePage{
        .cursor = null, // end of feed
        .feed = &.{
            .{ .post = alice_post_1 }, // resident already
            .{
                .post = .{
                    .uri = "at://did:plc:bbbbbbbbbbbbbbbbbbbbbbbb/app.zat4.feed.post/3kbob2",
                    .cid = "bafyreibob2",
                    .author = bob,
                    .record = .{ .text = "fresh post", .createdAt = "2026-01-03T00:00:00Z" },
                },
            },
        },
    };
    const stats = try ingestPage(gpa, &store, second);

    try testing.expectEqual(@as(u32, 1), stats.posts_added);
    try testing.expectEqual(@as(u32, 1), stats.posts_deduped);
    try testing.expectEqual(@as(u32, 0), stats.authors_added); // bob resident
    try testing.expectEqual(@as(usize, 4), store.posts.len);
    try testing.expectEqual(@as(usize, 5), store.feed.len); // items always append
    try testing.expectEqualStrings("", nextCursor(&store)); // feed exhausted
}

test "view-models: indexes resolved to plain values, attribution correct" {
    const gpa = testing.allocator; // C6
    var store: Store = .{};
    defer deinitStore(gpa, &store);
    _ = try ingestPage(gpa, &store, fixture_page);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const items = try buildTimeline(arena_state.allocator(), &store);

    try testing.expectEqual(@as(usize, 3), items.len);

    try testing.expectEqualStrings("alice.test", items[0].author_handle);
    try testing.expectEqualStrings("Alice", items[0].author_display_name);
    try testing.expectEqualStrings("", items[0].replying_to_handle);
    try testing.expectEqualStrings("", items[0].reposted_by_handle);
    try testing.expectEqual(@as(u32, 3), items[0].like_count);

    // Bob's reply names the parent's author; bob has no display name.
    try testing.expectEqualStrings("bob.test", items[1].author_handle);
    try testing.expectEqualStrings("", items[1].author_display_name);
    try testing.expectEqualStrings("alice.test", items[1].replying_to_handle);

    // The repost item carries who put it in the feed.
    try testing.expectEqualStrings("alice.test", items[2].author_handle);
    try testing.expectEqualStrings("bob.test", items[2].reposted_by_handle);
    try testing.expectEqualStrings("alice's second post", items[2].text);
}

test "ingest: absent reply variants and pins degrade gracefully (E4)" {
    const gpa = testing.allocator; // C6
    var store: Store = .{};
    defer deinitStore(gpa, &store);

    const page = lexicon.TimelinePage{
        .feed = &.{.{
            .post = alice_post_1,
            // notFound/blocked parents parse to defaults: empty cid.
            .reply = .{ .root = .{}, .parent = .{} },
            // a reasonPin parses to an empty `by`.
            .reason = .{ .by = .{} },
        }},
    };
    _ = try ingestPage(gpa, &store, page);

    try testing.expectEqual(OptionalPostIndex.none, store.posts.items(.reply_parent)[0]);
    try testing.expectEqual(OptionalAuthorIndex.none, store.feed.items(.reposted_by)[0]);
    try testing.expectEqualStrings("", nextCursor(&store));
}

test "timestamps: civil-date arithmetic against known vectors" {
    try testing.expectEqual(@as(i64, 0), try parseTimestamp("1970-01-01T00:00:00Z"));
    try testing.expectEqual(@as(i64, 951_868_800), try parseTimestamp("2000-03-01T00:00:00Z"));
    try testing.expectEqual(@as(i64, 1_767_323_045), try parseTimestamp("2026-01-02T03:04:05Z"));
    try testing.expectEqual(@as(i64, 1_767_323_045), try parseTimestamp("2026-01-02T03:04:05.678Z"));
    try testing.expectEqual(@as(i64, 1_718_438_400), try parseTimestamp("2024-06-15T10:00:00+02:00"));
    try testing.expectEqual(@as(i64, -1), try parseTimestamp("1969-12-31T23:59:59Z"));

    try testing.expectError(error.InvalidTimestamp, parseTimestamp("not a date"));
    try testing.expectError(error.InvalidTimestamp, parseTimestamp("2026-01-02T03:04:05")); // zone required
    try testing.expectError(error.InvalidTimestamp, parseTimestamp("2026-13-02T03:04:05Z"));
    try testing.expectError(error.InvalidTimestamp, parseTimestamp("2026-01-02T03:04:05.Z"));
}

test "ingest: a malformed createdAt degrades one post, not the page" {
    const gpa = testing.allocator; // C6
    var store: Store = .{};
    defer deinitStore(gpa, &store);

    const page = lexicon.TimelinePage{ .feed = &.{.{
        .post = .{
            .uri = "at://x/app.zat4.feed.post/1",
            .cid = "bafyreibadclock",
            .author = alice,
            .record = .{ .text = "bad clock", .createdAt = "garbage" },
        },
    }} };
    const stats = try ingestPage(gpa, &store, page);
    try testing.expectEqual(@as(u32, 1), stats.posts_added);
    try testing.expectEqual(@as(i64, 0), store.posts.items(.created_at)[0]);
}

test "ingest: labels become out-of-band flags on the resident post" {
    const gpa = testing.allocator; // C6
    var store: Store = .{};
    defer deinitStore(gpa, &store);

    const page = lexicon.TimelinePage{ .feed = &.{.{
        .post = .{
            .uri = "at://x/app.zat4.feed.post/9",
            .cid = "bafyreilabeled",
            .author = alice,
            .record = .{ .text = "flagged", .createdAt = "2026-01-02T03:04:05Z" },
            .labels = &.{.{ .val = "spam" }},
        },
    }} };
    _ = try ingestPage(gpa, &store, page);
    const flags = store.posts.items(.label_flags)[0];
    try testing.expect(flags.spam);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const items = try buildTimeline(arena_state.allocator(), &store);
    try testing.expect(items[0].label_flags.spam);
}

test "timestamps: format is the exact inverse of parse" {
    var buf: [24]u8 = undefined;
    const vectors = [_][]const u8{
        "1970-01-01T00:00:00Z",
        "2000-03-01T00:00:00Z",
        "2026-01-02T03:04:05Z",
        "2024-06-15T08:00:00Z",
    };
    for (vectors) |v| {
        const epoch = try parseTimestamp(v);
        try testing.expectEqualStrings(v, formatTimestamp(&buf, epoch));
    }
    try testing.expectEqual(
        @as(i64, 1_718_438_400),
        try parseTimestamp(formatTimestamp(&buf, 1_718_438_400)),
    );
}

test "optimistic: like applies once, reverts cleanly, unknown cid is a value" {
    const gpa = testing.allocator; // C6
    var store: Store = .{};
    defer deinitStore(gpa, &store);
    _ = try ingestPage(gpa, &store, fixture_page);

    try testing.expectEqual(Applied.applied, applyLike(&store, "bafyreialice1"));
    try testing.expectEqual(Applied.already, applyLike(&store, "bafyreialice1"));
    try testing.expectEqual(@as(u32, 4), store.posts.items(.like_count)[0]); // 3 + ours, once
    try testing.expectEqual(Applied.unknown, applyLike(&store, "bafyreinope"));

    revertLike(&store, "bafyreialice1");
    try testing.expectEqual(@as(u32, 3), store.posts.items(.like_count)[0]);
    revertLike(&store, "bafyreialice1"); // double revert is a no-op
    try testing.expectEqual(@as(u32, 3), store.posts.items(.like_count)[0]);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    _ = applyRepost(&store, "bafyreialice2");
    const items = try buildTimeline(arena_state.allocator(), &store);
    try testing.expect(items[2].item_flags.viewer_reposted);
    try testing.expect(!items[0].item_flags.viewer_liked);
    try testing.expectEqualStrings("bafyreialice1", items[0].cid);
    try testing.expect(items[0].uri.len > 0);
}

test "reconcile: a fresh page overwrites counts and viewer state on dedup (A8 boundary)" {
    const gpa = testing.allocator; // C6
    var store: Store = .{};
    defer deinitStore(gpa, &store);
    _ = try ingestPage(gpa, &store, fixture_page);
    _ = applyLike(&store, "bafyreialice1"); // optimistic: 3 -> 4

    const fresh = lexicon.TimelinePage{
        .feed = &.{.{
            .post = .{
                .uri = alice_post_1.uri,
                .cid = alice_post_1.cid,
                .author = alice,
                .record = alice_post_1.record,
                .likeCount = 9, // server truth, includes our like by now
                .viewer = .{ .like = "at://did:plc:carol/app.zat4.feed.like/3xyz" },
            },
        }},
    };
    _ = try ingestPage(gpa, &store, fresh);
    try testing.expectEqual(@as(u32, 9), store.posts.items(.like_count)[0]);
    try testing.expect(store.liked.isSet(0));
}

test "reply refs: parent is the post, root is the thread root (or itself)" {
    const gpa = testing.allocator; // C6
    var store: Store = .{};
    defer deinitStore(gpa, &store);
    _ = try ingestPage(gpa, &store, fixture_page);

    // bob's post replies to alice: parent = bob's post, root = alice's.
    const refs = replyRefsForCid(&store, "bafyreibob1").?;
    try testing.expectEqualStrings("bafyreibob1", refs.parent_cid);
    try testing.expectEqualStrings("bafyreialice1", refs.root_cid);

    // a top-level post roots itself.
    const top = replyRefsForCid(&store, "bafyreialice1").?;
    try testing.expectEqualStrings("bafyreialice1", top.root_cid);
    try testing.expectEqual(@as(?ReplyRefs, null), replyRefsForCid(&store, "bafyreinope"));

    try testing.expectEqualStrings(
        "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
        authorDidForCid(&store, "bafyreialice1"),
    );
}

test "live ingest: prepends, dedups by cid, links replies, did fallback handle" {
    const gpa = testing.allocator; // C6
    var store: Store = .{};
    defer deinitStore(gpa, &store);
    _ = try ingestPage(gpa, &store, fixture_page);
    const items_before = store.feed.len;

    const added = try ingestLivePost(gpa, &store, .{
        .did = "did:plc:nnnnnnnnnnnnnnnnnnnnnnnn",
        .handle = "",
        .uri = "at://did:plc:nnnnnnnnnnnnnnnnnnnnnnnn/app.zat4.feed.post/3klive1",
        .cid = "bafyreilivenew",
        .text = "fresh off the wire",
        .reply_parent_cid = "bafyreialice1",
        .reply_root_cid = "bafyreialice1",
        .created_at = 1_767_323_045,
    });
    try testing.expectEqual(LiveIngest.added, added);
    try testing.expectEqual(items_before + 1, store.feed.len);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const items = try buildTimeline(arena_state.allocator(), &store);
    try testing.expectEqualStrings("fresh off the wire", items[0].text);
    // Unknown author renders by did until a refresh teaches us the handle.
    try testing.expectEqualStrings("did:plc:nnnnnnnnnnnnnnnnnnnnnnnn", items[0].author_handle);
    // The reply linked to the resident parent.
    try testing.expectEqualStrings("alice.test", items[0].replying_to_handle);
    try testing.expectEqual(@as(u32, 0), items[0].like_count);

    // The stream replaying a held post is a duplicate, not a double.
    const dup = try ingestLivePost(gpa, &store, .{
        .did = "did:plc:nnnnnnnnnnnnnnnnnnnnnnnn",
        .handle = "",
        .uri = items[0].uri,
        .cid = "bafyreilivenew",
        .text = "fresh off the wire",
        .reply_parent_cid = "",
        .reply_root_cid = "",
        .created_at = 1_767_323_045,
    });
    try testing.expectEqual(LiveIngest.duplicate, dup);
    try testing.expectEqual(items_before + 1, store.feed.len);
}

test "ingest: a later sighting reconciles a placeholder handle to the resolved one" {
    const gpa = testing.allocator; // C6
    var store: Store = .{};
    defer deinitStore(gpa, &store);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    // First sighting: only the DID is known, so the handle is the DID placeholder.
    _ = try ingestLivePost(gpa, &store, .{
        .did = "did:plc:bob",          .handle = "did:plc:bob",
        .uri = "at://did:plc:bob/app.zat4.feed.post/1", .cid = "c1",
        .text = "one", .reply_parent_cid = "", .reply_root_cid = "", .created_at = 10,
    });
    // A later post by the SAME author carries the resolved handle (the AppView
    // now serves it). internAuthor dedups by DID but must reconcile the handle.
    _ = try ingestLivePost(gpa, &store, .{
        .did = "did:plc:bob",          .handle = "bob.zat4.com",
        .uri = "at://did:plc:bob/app.zat4.feed.post/2", .cid = "c2",
        .text = "two", .reply_parent_cid = "", .reply_root_cid = "", .created_at = 20,
    });

    const items = try buildTimeline(arena_state.allocator(), &store);
    // BOTH posts (one author) now read the reconciled handle, not the DID.
    try testing.expectEqual(@as(usize, 2), items.len);
    for (items) |it| try testing.expectEqualStrings("bob.zat4.com", it.author_handle);
}

test "a reply's hydrated parent ref does NOT clobber the parent's real counts" {
    const gpa = testing.allocator;
    var store: Store = .{};
    defer deinitStore(gpa, &store);

    // The parent post arrives with a real reply count of 2 + 5 likes.
    const parent_full: lexicon.FeedViewPost = .{ .post = .{
        .uri = "at://did:plc:a/app.zat4.feed.post/cP",
        .cid = "cP",
        .author = .{ .did = "did:plc:a", .handle = "a.zat" },
        .record = .{ .text = "parent" },
        .replyCount = 2,
        .likeCount = 5,
    } };
    _ = try ingestPosts(gpa, &store, .{ .feed = &.{parent_full} });

    // A reply to it arrives; its hydrated PARENT ref carries the default 0 counts
    // (a context reference, not the post's own view). It must NOT zero cP.
    const reply_item: lexicon.FeedViewPost = .{
        .post = .{
            .uri = "at://did:plc:b/app.zat4.feed.post/cR",
            .cid = "cR",
            .author = .{ .did = "did:plc:b", .handle = "b.zat" },
            .record = .{ .text = "a reply" },
        },
        .reply = .{
            .parent = .{ .cid = "cP", .author = .{ .did = "did:plc:a", .handle = "a.zat" }, .record = .{ .text = "parent" } },
            .root = .{ .cid = "cP", .author = .{ .did = "did:plc:a", .handle = "a.zat" }, .record = .{ .text = "parent" } },
        },
    };
    _ = try ingestPosts(gpa, &store, .{ .feed = &.{reply_item} });

    const p = lookupCid(&store, "cP").?;
    try testing.expectEqual(@as(u32, 2), store.posts.items(.reply_count)[p]); // NOT clobbered to 0
    try testing.expectEqual(@as(u32, 5), store.posts.items(.like_count)[p]);

    // The real feed view of cP (counts present) still reconciles normally.
    const parent_now: lexicon.FeedViewPost = .{ .post = .{
        .uri = "at://did:plc:a/app.zat4.feed.post/cP",
        .cid = "cP",
        .author = .{ .did = "did:plc:a", .handle = "a.zat" },
        .record = .{ .text = "parent" },
        .replyCount = 3,
        .likeCount = 5,
    } };
    _ = try ingestPosts(gpa, &store, .{ .feed = &.{parent_now} });
    try testing.expectEqual(@as(u32, 3), store.posts.items(.reply_count)[p]); // authoritative view updates
}

test "optimistic display name: a stale refresh can't clobber it until the server catches up" {
    const gpa = testing.allocator;
    var store: Store = .{};
    defer deinitStore(gpa, &store);

    const mk = struct {
        fn post(cid: []const u8, name: []const u8) lexicon.FeedViewPost {
            return .{ .post = .{
                .uri = "at://did:me/app.zat4.feed.post/x",
                .cid = cid,
                .author = .{ .did = "did:me", .handle = "me.zat", .displayName = name },
                .record = .{ .text = "hi" },
            } };
        }
    };
    _ = try ingestPosts(gpa, &store, .{ .feed = &.{mk.post("c1", "Old")} });
    const ai = store.author_by_did.getAdapted("did:me", std.hash_map.StringIndexAdapter{ .bytes = &store.string_bytes }).?;
    const dn = struct {
        fn get(s: *const Store, a: u32) []const u8 {
            return sliceSpan(s, s.authors.items(.display_name)[a]);
        }
    }.get;
    try testing.expectEqualStrings("Old", dn(&store, ai));

    // Optimistically rename to "New" — shows instantly, guard armed.
    try setOwnDisplayName(gpa, &store, "did:me", "New");
    try testing.expectEqualStrings("New", dn(&store, ai));

    // A stale refresh still carrying "Old" must NOT clobber the optimistic name.
    _ = try ingestPosts(gpa, &store, .{ .feed = &.{mk.post("c1", "Old")} });
    try testing.expectEqualStrings("New", dn(&store, ai));
    try testing.expect(store.pending_display != null);

    // The server catches up (serves "New") → the guard releases.
    _ = try ingestPosts(gpa, &store, .{ .feed = &.{mk.post("c2", "New")} });
    try testing.expectEqualStrings("New", dn(&store, ai));
    try testing.expect(store.pending_display == null);

    // A genuine later change now propagates normally (no guard).
    _ = try ingestPosts(gpa, &store, .{ .feed = &.{mk.post("c3", "Newer")} });
    try testing.expectEqualStrings("Newer", dn(&store, ai));
}

test "optimistic post: reconcile re-keys temp→real; drop detaches on failure" {
    const gpa = testing.allocator;
    var store: Store = .{};
    defer deinitStore(gpa, &store);

    // An optimistic top-level post under a temp cid → present in the feed.
    _ = try ingestLivePost(gpa, &store, .{
        .did = "did:plc:me", .handle = "me.zat",
        .uri = "", .cid = "pending:0", .text = "hello",
        .reply_parent_cid = "", .reply_root_cid = "", .created_at = 100,
    });
    try testing.expect(lookupCid(&store, "pending:0") != null);
    const idx = lookupCid(&store, "pending:0").?;

    // Confirm: re-key to the real cid/uri; the temp key is gone, the slot kept.
    try reconcileOptimisticPost(gpa, &store, "pending:0", "bafyreal", "at://did:plc:me/app.zat4.feed.post/bafyreal");
    try testing.expect(lookupCid(&store, "pending:0") == null);
    try testing.expectEqual(idx, lookupCid(&store, "bafyreal").?);

    // An optimistic REPLY that then FAILS → detached from feed + thread.
    _ = try ingestLivePost(gpa, &store, .{
        .did = "did:plc:me", .handle = "me.zat",
        .uri = "", .cid = "pending:1", .text = "a reply",
        .reply_parent_cid = "bafyreal", .reply_root_cid = "bafyreal", .created_at = 110,
    });
    const before = store.feed.len;
    dropOptimisticPost(&store, "pending:1");
    try testing.expect(lookupCid(&store, "pending:1") == null); // un-keyed
    try testing.expectEqual(before - 1, store.feed.len); // feed row removed
    // The thread of the (real) parent no longer contains the dropped reply.
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const thread = try buildThreadView(arena_state.allocator(), &store, "bafyreal");
    try testing.expectEqual(@as(usize, 1), thread.len); // just the parent
}

test "buildThreadView: nested preorder with view-derived depth + focus" {
    const gpa = testing.allocator;
    var store: Store = .{};
    defer deinitStore(gpa, &store);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // root <- childA <- grandchild ; root <- childB (childA older than childB).
    const mk = struct {
        fn p(g: Allocator, s: *Store, cid: []const u8, text: []const u8, parent: []const u8, created: i64) !void {
            _ = try ingestLivePost(g, s, .{
                .did = "did:plc:a",
                .handle = "a.zat4.com",
                .uri = "at://did:plc:a/app.zat4.feed.post/x",
                .cid = cid,
                .text = text,
                .reply_parent_cid = parent,
                .reply_root_cid = if (parent.len > 0) "cRoot" else "",
                .created_at = created,
            });
        }
    }.p;
    try mk(gpa, &store, "cRoot", "root", "", 10);
    try mk(gpa, &store, "cA", "child A", "cRoot", 20);
    try mk(gpa, &store, "cB", "child B", "cRoot", 25);
    try mk(gpa, &store, "cG", "grandchild", "cA", 30);

    // Focus the grandchild; the view is the WHOLE thread from the root, nested.
    const t = try buildThreadView(arena, &store, "cG");
    try testing.expectEqual(@as(usize, 4), t.len);
    // Preorder, siblings chronological: root(0), childA(1), grandchild(2), childB(1).
    try testing.expectEqualStrings("root", t[0].text);
    try testing.expectEqual(@as(u8, 0), t[0].depth);
    try testing.expectEqualStrings("child A", t[1].text);
    try testing.expectEqual(@as(u8, 1), t[1].depth);
    try testing.expectEqualStrings("grandchild", t[2].text);
    try testing.expectEqual(@as(u8, 2), t[2].depth);
    try testing.expect(t[2].is_focus); // the focused post is marked
    try testing.expectEqualStrings("child B", t[3].text);
    try testing.expectEqual(@as(u8, 1), t[3].depth);
    // Only the focus is flagged.
    var focus_count: usize = 0;
    for (t) |it| {
        if (it.is_focus) focus_count += 1;
    }
    try testing.expectEqual(@as(usize, 1), focus_count);
}

test "view model: a profile view is a query over the shared store; engagement is unified" {
    const gpa = testing.allocator; // C6
    var store: Store = .{};
    defer deinitStore(gpa, &store);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    // Home: the fixture (alice ×2 posts, bob ×1) builds the Home ordering.
    _ = try ingestPage(gpa, &store, fixture_page);
    const home_len = store.feed.len;

    // Alice's profile view = a QUERY over the shared store, reverse-chron.
    const av0 = try buildAuthorView(arena_state.allocator(), &store, alice.did);
    try testing.expectEqual(@as(usize, 2), av0.len);
    try testing.expectEqualStrings("alice's second post", av0[0].text); // newer first
    try testing.expectEqualStrings("first post", av0[1].text);

    // A profile FETCH ingests content-only — a new alice post + her resident
    // one (dedup). It must NOT add Home feed-ordering rows (no container/copy).
    const profile_page = lexicon.TimelinePage{ .feed = &.{
        .{ .post = .{
            .uri = "at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/app.zat4.feed.post/3kali3",
            .cid = "bafyreialice3",
            .author = alice,
            .record = .{ .text = "alice newest", .createdAt = "2026-01-09T00:00:00Z" },
        } },
        .{ .post = alice_post_1 }, // already resident → dedup, no dup
    } };
    _ = try ingestPosts(gpa, &store, profile_page);
    try testing.expectEqual(home_len, store.feed.len); // Home ordering untouched

    const av1 = try buildAuthorView(arena_state.allocator(), &store, alice.did);
    try testing.expectEqual(@as(usize, 3), av1.len);
    try testing.expectEqualStrings("alice newest", av1[0].text);

    // Engagement is CID-keyed on the ONE store: liking from the profile view
    // shows liked in the HOME view too — same record, two lenses (ZONES inv. 4).
    _ = applyLike(&store, "bafyreialice1");
    const home = try buildTimeline(arena_state.allocator(), &store);
    for (home) |it| {
        if (std.mem.eql(u8, it.cid, "bafyreialice1")) try testing.expect(it.item_flags.viewer_liked);
    }
    const av2 = try buildAuthorView(arena_state.allocator(), &store, alice.did);
    for (av2) |it| {
        if (std.mem.eql(u8, it.cid, "bafyreialice1")) try testing.expect(it.item_flags.viewer_liked);
    }
}

test "refresh ingest: new rows prepend in order, cursor untouched, rows dedup by pair" {
    const gpa = testing.allocator; // C6
    var store: Store = .{};
    defer deinitStore(gpa, &store);
    _ = try ingestPage(gpa, &store, fixture_page);
    const len_before = store.feed.len;

    // A refresh page: one brand-new post, then an already-seen one.
    const refresh_page: lexicon.TimelinePage = .{
        .cursor = "must-not-replace",
        .feed = &.{
            .{ .post = .{
                .uri = "at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/app.zat4.feed.post/3knewest",
                .cid = "bafyreinewest",
                .author = .{ .did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", .handle = "alice.test" },
                .record = .{ .text = "the newest post", .createdAt = "2026-01-03T00:00:00Z" },
            } },
            .{ .post = .{
                .uri = "at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/app.zat4.feed.post/1",
                .cid = "bafyreialice1",
                .author = .{ .did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", .handle = "alice.test" },
                .record = .{ .text = "first", .createdAt = "2026-01-01T00:00:00Z" },
            } },
        },
    };
    const stats = try ingestPageRefresh(gpa, &store, refresh_page);
    try testing.expectEqual(@as(u32, 1), stats.items_added);
    // STAGED, not revealed: the feed is unchanged (the reader isn't displaced);
    // the new post waits behind the pill. The cursor is untouched.
    try testing.expectEqual(len_before, store.feed.len);
    try testing.expectEqual(@as(usize, 1), pendingCount(&store));
    try testing.expectEqualStrings("CURSOR-1", nextCursor(&store));

    // Reveal: the staged post lands on TOP, in order; the pill clears.
    _ = try revealPending(gpa, &store);
    try testing.expectEqual(len_before + 1, store.feed.len);
    try testing.expectEqual(@as(usize, 0), pendingCount(&store));

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const items = try buildTimeline(arena_state.allocator(), &store);
    try testing.expectEqualStrings("the newest post", items[0].text);

    // Refreshing the same page again stages nothing (now revealed in the feed).
    const again = try ingestPageRefresh(gpa, &store, refresh_page);
    try testing.expectEqual(@as(u32, 0), again.items_added);
    try testing.expectEqual(@as(usize, 0), pendingCount(&store));
    try testing.expectEqual(len_before + 1, store.feed.len);
}

test "regression: like+unlike a live-ingested post does not overrun like_uris" {
    const gpa = std.testing.allocator;
    var store: Store = .{};
    defer deinitStore(gpa, &store);

    // Ingest a live post (the path that previously skipped like_uris).
    const r = try ingestLivePost(gpa, &store, .{
        .did = "did:plc:test",
        .handle = "alice.test",
        .uri = "at://did:plc:test/app.zat4.feed.post/abc",
        .cid = "bafyLIVE1",
        .text = "live post",
        .reply_parent_cid = "",
        .reply_root_cid = "",
        .created_at = 1_700_000_000,
    });
    try std.testing.expectEqual(LiveIngest.added, r);

    // All four parallel arrays must match posts.len now.
    try std.testing.expectEqual(store.posts.len, store.like_uris.items.len);
    try std.testing.expectEqual(store.posts.len, store.repost_uris.items.len);

    // Like it, then unlike it — the exact crash sequence. No record uri
    // exists yet for an optimistic like, so unlike is .no_record_uri,
    // but crucially it must INDEX like_uris without overrunning.
    try std.testing.expectEqual(Applied.applied, applyLike(&store, "bafyLIVE1"));
    const dis = applyUnlike(&store, "bafyLIVE1");
    try std.testing.expect(dis == .no_record_uri or dis == .applied or dis == .not_engaged);
}
