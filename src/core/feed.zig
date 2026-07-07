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
const discover = @import("discover.zig");
const retrieval = @import("retrieval.zig");
const learner = @import("learner.zig");

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
    /// The post this one QUOTES (a quote-post), or `.none`. A store index like
    /// reply_parent/root: the quoted post is ingested into `posts` (CID-keyed,
    /// A8) and referenced here, so a quote card is a QUERY over the shared store
    /// (ZONES inv. 4), never a duplicated snapshot on the post.
    quote_of: OptionalPostIndex,
    like_count: u32,
    repost_count: u32,
    reply_count: u32,
    quote_count: u32,
    /// Moderation flags, stored out of band as bits (A6) — the feed holds
    /// them as data; only the moderation module knows what they mean.
    label_flags: moderation.LabelFlags,

    comptime {
        // Budget: 8 (i64) + 3×8 (spans) + 8×4 (u32: author + 3 post-indexes +
        // 4 counts) + 2 (flags) = 66 payload; i64 alignment pads the tail to 72.
        // In the SoA store every field lives in its own array, so that pad never
        // materializes; the guard pins the honest @sizeOf. (A7.1 raise 64 → 72:
        // `quote_of` is a real quote-post edge — the same kind of OptionalPostIndex
        // as reply_parent/root, +4 bytes, crossing the i64-alignment boundary.)
        assert(@sizeOf(Post) == 72);
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

/// A post's zone-tag slice, OUT OF BAND (A6): an `[off, len)` window into the
/// store's flat `tag_pool`, parallel to `posts` (one per post row). Keeps the
/// hot `Post` at 64 bytes while a post's variable-length tag set rides outside
/// it. `len == 0` ⇒ an untagged post. HOT (one per post, scanned to build the
/// tray) → A7.
pub const TagRange = struct {
    off: u32,
    len: u32,

    comptime {
        // Budget 8: two u32, packed exactly. (A7)
        assert(@sizeOf(TagRange) == 8);
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
    /// Zat Zones — a post's tags, OUT OF BAND (A6): `tag_pool` is a flat list of
    /// tag-string spans (into `string_bytes`); `post_tags` is parallel to `posts`,
    /// one `TagRange` per post windowing into `tag_pool`. The tray (the row of
    /// tappable zone-doorways below a post) is built from these. Content sealed by
    /// the post's CID (A8), so set once at first ingest, never reconciled.
    tag_pool: std.ArrayList(TextSpan) = .empty,
    post_tags: std.ArrayList(TagRange) = .empty,
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
    store.tag_pool.deinit(gpa);
    store.post_tags.deinit(gpa);
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
        // A8 caveat — the CID seals the record bytes, but a REFERENCE wire shape
        // OMITS createdAt and tags (a reply-ref carries only enough to say
        // "replying to @x"). So a post first seen as a reply-parent is created as
        // a PLACEHOLDER (created_at 0, empty tray); when its full feed view later
        // dedups onto it, fill those authoritative fields in — same CID ⇒ the
        // full view's createdAt/tags ARE the sealed values, the ref just lacked
        // them. (Without this, a reply-parent shows "2947w" and no tag tray.)
        const ca = parseTimestamp(view.record.createdAt) catch 0;
        if (ca != 0) posts.items(.created_at)[index] = ca;
        if (view.tags.len > 0 and index < store.post_tags.items.len and store.post_tags.items[index].len == 0) {
            const tag_off: u32 = @intCast(store.tag_pool.items.len);
            for (view.tags) |t| {
                if (t.len == 0) continue;
                try store.tag_pool.append(gpa, try appendString(gpa, store, t));
            }
            store.post_tags.items[index] = .{ .off = tag_off, .len = @intCast(store.tag_pool.items.len - tag_off) };
        }
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

    // Quote-post: ingest the AppView-hydrated quoted view as its own store post
    // (A8 dedup by CID) and reference it. It arrives as a QuotedView (author +
    // text + refs, no counts), so treat it like a context reference — it never
    // clobbers a resident post's counts. Ingested BEFORE this post so its index
    // is stable; a quote card is then a query over the store (ZONES inv. 4).
    var quote_of: OptionalPostIndex = .none;
    if (view.embed) |emb| if (emb.record.cid.len > 0) {
        const quoted: lexicon.PostView = .{
            .uri = emb.record.uri,
            .cid = emb.record.cid,
            .author = emb.record.author,
            .record = .{ .text = emb.record.text, .createdAt = emb.record.createdAt },
        };
        quote_of = OptionalPostIndex.from(try internPost(gpa, store, quoted, stats, true));
    };

    const index: u32 = @intCast(store.posts.len);
    try store.posts.append(gpa, .{
        .created_at = created_at,
        .text = text,
        .cid = cid,
        .uri = uri,
        .author = author,
        .reply_parent = .none,
        .reply_root = .none,
        .quote_of = quote_of,
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
    // Zone tags (A6, out of band): copy this post's tag set into the flat pool
    // and record its window, parallel to `posts`. Sealed by CID — set once here,
    // never reconciled (a re-seen post hits the dedup branch above and keeps it).
    {
        const tag_off: u32 = @intCast(store.tag_pool.items.len);
        for (view.tags) |t| {
            if (t.len == 0) continue;
            try store.tag_pool.append(gpa, try appendString(gpa, store, t));
        }
        try store.post_tags.append(gpa, .{ .off = tag_off, .len = @intCast(store.tag_pool.items.len - tag_off) });
    }
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
    /// VIEW-DERIVED (thread lens): this post is the root author's self-reply
    /// continuation — render it STITCHED (headerless, flush, thin separator)
    /// into one coherent post. Never on the stored Post (ZONES inv. 4); rides
    /// the tail padding like depth/is_focus.
    stitched: bool = false,
    /// VIEW-DERIVED (thread lens): this post has at least one reply, and the
    /// reader has collapsed it (its subtree is hidden in this view). Per-view
    /// state, never on the post. Ride the last of the tail padding.
    has_kids: bool = false,
    collapsed: bool = false,
    /// The post's zone tags (display casing) — its tray, a row of tappable
    /// doorways into zones. A slice like the rest of this struct's variable-length
    /// fields; the strings borrow the store's bytes, the outer slice the arena.
    /// Empty ⇒ untagged. (ZONES inv. 4: derived from the post's facets, never a
    /// stored container.)
    tags: []const []const u8 = &.{},
    /// Quote-post: the QUOTED post's snapshot for the quote card, resolved from
    /// the store's `quote_of` edge (ZONES inv. 4 — a query, not a stored copy).
    /// All "" ⇒ not a quote. `quote_uri`+`quote_cid` are the tap target (open the
    /// quoted thread); the strings borrow the store's bytes.
    quote_author_handle: []const u8 = "",
    quote_author_display_name: []const u8 = "",
    quote_text: []const u8 = "",
    quote_uri: []const u8 = "",
    quote_cid: []const u8 = "",

    comptime {
        // Produced in bulk every build — hot, so guarded (A7). Slices make
        // the size pointer-width-dependent; the budget is pinned where the
        // record is its packed self and degrades to nothing off 64-bit.
        // (A7.1 record, FIFTH raise: 160 → 240. Quote-posts put the quoted post's
        // display snapshot on the view-model — five more slices, the SAME kind of
        // variable-length view data as the tag tray (4th raise) and replying_to
        // (3rd). Empty on the ~non-quote majority; a quote is a minority of posts
        // but the field must exist on the one struct every view shares. 13×16
        // slices + 8 i64 + 16 counts + 8 (flags/depth) = 240, no padding.)
        if (@sizeOf(usize) == 8) assert(@sizeOf(TimelineItem) == 240);
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
        item.* = try fillTimelineItem(arena, store, @intFromEnum(post_index), reposted_by);
    }
    return out;
}

/// Build the render-ready view-model for ONE post + its (optional) reposter.
/// The single seam every VIEW shares: Home (store.feed order), a profile
/// (one author's posts), a zone (a tag query), an algorithm (a scored order)
/// are all just different ORDERINGS of post indices over the one store — the
/// post is the post (ZONES invariant 4), seen through N lenses. Pure.
fn fillTimelineItem(arena: Allocator, store: *const Store, p: usize, reposted_by: OptionalAuthorIndex) error{OutOfMemory}!TimelineItem {
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

    // Quote-post: resolve the `quote_of` edge into the quoted post's snapshot —
    // a query over the same store, exactly like replying_to above (ZONES inv. 4).
    var q_handle: []const u8 = "";
    var q_display: []const u8 = "";
    var q_text: []const u8 = "";
    var q_uri: []const u8 = "";
    var q_cid: []const u8 = "";
    if (posts.items(.quote_of)[p].unwrap()) |q| {
        const qi = @intFromEnum(q);
        const qa = @intFromEnum(post_authors[qi]);
        q_handle = sliceSpan(store, author_handles[qa]);
        q_display = sliceSpan(store, author_display_names[qa]);
        q_text = sliceSpan(store, posts.items(.text)[qi]);
        q_uri = sliceSpan(store, posts.items(.uri)[qi]);
        q_cid = sliceSpan(store, posts.items(.cid)[qi]);
    }

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
        .tags = try collectRowTags(arena, store, p),
        .quote_author_handle = q_handle,
        .quote_author_display_name = q_display,
        .quote_text = q_text,
        .quote_uri = q_uri,
        .quote_cid = q_cid,
    };
}

/// Resolve a post row's out-of-band tags into a plain `[]const []const u8` in
/// `arena` — the tray the renderer paints, in stored order. Empty when the post
/// is untagged (E4). PURE.
fn collectRowTags(arena: Allocator, store: *const Store, p: usize) error{OutOfMemory}![]const []const u8 {
    if (p >= store.post_tags.items.len) return &.{};
    const r = store.post_tags.items[p];
    if (r.len == 0) return &.{};
    const out = try arena.alloc([]const u8, r.len);
    for (out, 0..) |*t, i| t.* = sliceSpan(store, store.tag_pool.items[r.off + i]);
    return out;
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
    for (rows.items, out) |p, *item| item.* = try fillTimelineItem(arena, store, p, .none);
    return out;
}

/// Build a VIEW of one ZONE's posts over the SHARED store (ZONES inv. 4 — a
/// query, not a container): the posts bearing `tag`, reverse-chron. The tag is
/// normalized (case-fold + trim) before matching, so `#Water`/`#water` resolve
/// to the same zone (invariant 1). The posts are the same records Home/profile
/// reference; engagement/identity stay unified. Allocates in `arena` (C3). The
/// shell first fetches the zone's posts into the store (getPostsForTag); this is
/// then a pure query over what's resident — and naturally includes any other
/// resident post bearing the tag. Cut-1 ordering is reverse-chron; the choosable
/// scored lenses arrive with the discover engine (invariant 6).
pub fn buildTagView(arena: Allocator, store: *const Store, tag: []const u8) error{OutOfMemory}![]TimelineItem {
    var nbuf: [128]u8 = undefined;
    const want = normalizeTagClient(tag, &nbuf) orelse return &.{};

    const posts = store.posts.slice();
    const createds = posts.items(.created_at);
    var rows: std.ArrayList(u32) = .empty;
    defer rows.deinit(arena);
    var mbuf: [128]u8 = undefined;
    for (0..store.posts.len) |p| {
        if (p >= store.post_tags.items.len) continue;
        const r = store.post_tags.items[p];
        var hit = false;
        var i: u32 = 0;
        while (i < r.len) : (i += 1) {
            const norm = normalizeTagClient(sliceSpan(store, store.tag_pool.items[r.off + i]), &mbuf) orelse continue;
            if (std.mem.eql(u8, norm, want)) {
                hit = true;
                break;
            }
        }
        if (hit) try rows.append(arena, @intCast(p));
    }
    const Ctx = struct {
        createds: []const i64,
        pub fn lessThan(ctx: @This(), x: u32, y: u32) bool {
            return ctx.createds[x] > ctx.createds[y]; // newest first
        }
    };
    std.sort.block(u32, rows.items, Ctx{ .createds = createds }, Ctx.lessThan);
    const out = try arena.alloc(TimelineItem, rows.items.len);
    for (rows.items, out) |p, *item| item.* = try fillTimelineItem(arena, store, p, .none);
    return out;
}

/// The zone CATALOG derived from the SHARED store (ZONES inv. 4 — a query, not a
/// container): every distinct zone borne by a resident post, canonical lowercase,
/// with a resident-post count (a post counts once per zone). First-seen order.
/// This is what lets the browse page list a zone the client already knows even
/// before/without the AppView's `listTags` — the shell merges the server's wider
/// set on top. Allocates into `arena` (C3); the strings are arena-owned.
pub fn listZonesLocal(arena: Allocator, store: *const Store, since: i64) error{OutOfMemory}![]lexicon.TagView {
    // Per-zone accumulator: the same community stats the AppView serves
    // (count / distinct posters / posts at-or-after `since` / newest post),
    // derived from resident posts only. `since` is the shell's recency
    // watermark (B3 — the clock stays out of the core).
    const Zs = struct {
        count: usize = 0,
        recent: usize = 0,
        last_at: i64 = 0,
        authors: std.AutoHashMapUnmanaged(u32, void) = .empty,
    };
    var order: std.ArrayList([]const u8) = .empty; // zone names, first-seen order
    defer order.deinit(arena);
    var stats: std.StringHashMapUnmanaged(*Zs) = .empty;
    defer stats.deinit(arena);
    var nbuf: [128]u8 = undefined;
    var pbuf: [128]u8 = undefined;
    const createds = store.posts.items(.created_at);
    const post_authors = store.posts.items(.author);
    for (0..store.posts.len) |p| {
        if (p >= store.post_tags.items.len) continue;
        const r = store.post_tags.items[p];
        var i: u32 = 0;
        next_tag: while (i < r.len) : (i += 1) {
            const norm = normalizeTagClient(sliceSpan(store, store.tag_pool.items[r.off + i]), &nbuf) orelse continue;
            // Per-post dedup: skip if an earlier tag of THIS post folded the same
            // (so "#water #Water" counts the post once).
            var j: u32 = 0;
            while (j < i) : (j += 1) {
                const prev = normalizeTagClient(sliceSpan(store, store.tag_pool.items[r.off + j]), &pbuf) orelse continue;
                if (std.mem.eql(u8, prev, norm)) continue :next_tag;
            }
            const zs: *Zs = stats.get(norm) orelse blk: {
                const dup = try arena.dupe(u8, norm);
                const fresh = try arena.create(Zs);
                fresh.* = .{};
                try stats.put(arena, dup, fresh);
                try order.append(arena, dup);
                break :blk fresh;
            };
            zs.count += 1;
            if (createds[p] >= since) zs.recent += 1;
            if (createds[p] > zs.last_at) zs.last_at = createds[p];
            try zs.authors.put(arena, @intFromEnum(post_authors[p]), {});
        }
    }
    const out = try arena.alloc(lexicon.TagView, order.items.len);
    for (out, order.items) |*t, name| {
        const zs = stats.get(name).?;
        t.* = .{ .tag = name, .count = zs.count, .authors = zs.authors.count(), .recent = zs.recent, .lastAt = zs.last_at };
    }
    return out;
}

/// Normalize a tag for zone matching (invariant 1): trim + ASCII case-fold into
/// `buf`. Null when empty/too long (E4). Mirrors the AppView's `normalizeTag`.
fn normalizeTagClient(raw: []const u8, buf: []u8) ?[]const u8 {
    const trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len == 0 or trimmed.len > buf.len) return null;
    for (trimmed, 0..) |c, i| buf[i] = std.ascii.toLower(c);
    return buf[0..trimmed.len];
}

/// Build the SCORED Home view over the shared store: the same fillTimelineItem
/// seam as buildTimeline, but ORDERED by the discover engine (DISCOVER D3)
/// instead of feed order. This is the "an algorithm (a scored order)" lens the
/// fillTimelineItem comment names — Home through a `FeedConfig`. The candidate
/// pool is the resident TOP-LEVEL posts (replies excluded — invariant 11: a
/// reply is a candidate only in its parent's reply pool, never Home); for this
/// cut that resident set IS the in-network pool (the followed-graph posts the
/// timeline fetched). Out-of-network/topic sourcing (D2) widens the pool later;
/// the SCORING is unchanged when it does — one engine, a bigger pool.
///
/// A4/A5 hold across the discover boundary: a candidate carries this module's
/// post index packed into discover's OPAQUE `Ref`, which discover never
/// dereferences (it only sorts handles); we read it back here, where the index
/// is meaningful, to resolve each ranked post. `now` is passed in (the shell
/// reads the clock — invariant 9). Diversity caps + moderation are the D4 pass,
/// not applied here. Cut-1 limit: a scored row carries no repost attribution
/// (reposted_by = .none) since scoring reorders away from feed rows — noted for
/// D4. Allocates in `arena` (C3).
///
/// `prefs` is the on-device learner state (D9), or null. The behavioral signal
/// is computed for a candidate ONLY when the config's `behavioral_weight > 0`
/// AND `prefs` is non-null — the doorway in the core (invariant 6): a "no
/// behavioral data" algorithm (Discover Private, weight 0) never even reads the
/// vector, so it provably cannot consult attention data, and the shell never
/// hands a vector to such a config in the first place (double-walled). When used,
/// a candidate's `behavioral` is `learner.affinity` over the post's features
/// (its zone tags + author), which the scorer multiplies through
/// `behavioral_weight`. Until the shell captures real dwell the vector is empty
/// and affinity is 0 — inert, exactly like the pre-D2 sourcing was.
pub fn buildDiscoverView(
    arena: Allocator,
    store: *const Store,
    config: discover.FeedConfig,
    now: i64,
    prefs: ?*const learner.PrefVector,
) error{OutOfMemory}![]TimelineItem {
    const posts = store.posts.slice();
    const parents = posts.items(.reply_parent);
    const roots = posts.items(.reply_root);
    const createds = posts.items(.created_at);
    const likes = posts.items(.like_count);
    const reposts = posts.items(.repost_count);
    const replies = posts.items(.reply_count);
    const quotes = posts.items(.quote_count);
    const post_authors = posts.items(.author);
    const author_dids = store.authors.slice().items(.did);

    // Reply-chain: the author replying back into their OWN thread — the strongest
    // positive (D2, calibrated `w_reply_chain`). Computed from the resident thread
    // structure: for each resident reply whose thread-root has the SAME author,
    // credit the root post. One O(posts) pass, keyed by post index. PUBLIC + no
    // identity (it's a count on the post, not "who") → no targeting channel. A
    // thread-root that isn't resident is simply not credited (E4: absence is data).
    const reply_chain = try arena.alloc(u32, store.posts.len);
    @memset(reply_chain, 0);
    for (0..store.posts.len) |r| {
        const root = roots[r].unwrap() orelse continue; // r is a reply with a known root
        const ri = @intFromEnum(root);
        if (post_authors[r] == post_authors[ri]) reply_chain[ri] += 1;
    }

    // The behavioral doorway, in the core: only a config that opts in (weight > 0)
    // and was actually handed a vector reads attention data at all (invariant 6).
    const use_behavioral = config.behavioral_weight > 0 and prefs != null;

    // Build the candidate pool in bulk: capacity once, no per-append bitset
    // churn. Every resident top-level post is in-network for this cut.
    var cands: discover.Candidates = .{};
    try cands.list.ensureTotalCapacity(arena, store.posts.len);
    for (0..store.posts.len) |p| {
        if (parents[p].unwrap() != null) continue; // exclude replies (invariant 11)
        // D9: the learned per-user affinity for this post's features (tags +
        // author), or 0 when the config doesn't use behavioral data. Computed
        // only behind the doorway above.
        const behavioral: f32 = if (use_behavioral) blk: {
            const tags = try collectRowTags(arena, store, p);
            const feats = try arena.alloc([]const u8, tags.len + 1);
            @memcpy(feats[0..tags.len], tags);
            feats[tags.len] = sliceSpan(store, author_dids[@intFromEnum(post_authors[p])]);
            break :blk learner.affinity(prefs.?, feats);
        } else 0;
        cands.list.appendAssumeCapacity(.{
            .ref = discover.Ref.from(@intCast(p)),
            .created_at = createds[p],
            .like_count = likes[p],
            .repost_count = reposts[p],
            .reply_count = replies[p],
            // The author-replied-back count, computed above from the thread structure.
            .reply_chain_count = reply_chain[p],
            // Signals Zat4 doesn't capture yet (D1) — 0 until a source fills them.
            .bookmark_count = 0,
            .profile_click_count = 0,
            .link_click_count = 0,
            .negative_count = 0,
            // Off-graph signal is the shell's to supply (D2); on-device behavioral
            // is the learner's (D9), computed above behind the doorway.
            .author_rep = 0,
            .relevance = 0,
            .behavioral = behavioral,
        });
    }
    try cands.in_network.resize(arena, cands.list.len, true);

    // Developer-tier PUBLIC per-candidate signals (out of band, D2): whether the
    // viewer already engaged the post, and its topic-tag count — filled from the
    // resident store so a guest program (a Zal algorithm) can read them. Cheap; a
    // config algorithm never touches them. Each candidate's `ref` carries its post
    // index (that is how the pool was sourced).
    try cands.viewer_engaged.resize(arena, cands.list.len, false);
    try cands.tag_count.resize(arena, cands.list.len);
    try cands.quote_count.resize(arena, cands.list.len);
    // Materialize each candidate's tag STRINGS out of band when something reads them:
    // a `tag_scope` retrieval source, OR a guest program that carries tag literals
    // (its `has_tag`/`source_tag_scope` calls). A config with neither pays nothing
    // (F5), and the scorer then reads the empty list as "no tags per row".
    const scope_by_tag = retrieval.needsTags(config.query.sources) or config.guest_strings.len > 0;
    if (scope_by_tag) try cands.cand_tags.resize(arena, cands.list.len);
    const cand_refs = cands.list.items(.ref);
    for (0..cands.list.len) |ci| {
        const p = cand_refs[ci].raw();
        const engaged = (p < store.liked.capacity() and store.liked.isSet(p)) or
            (p < store.reposted.capacity() and store.reposted.isSet(p));
        cands.viewer_engaged.setValue(ci, engaged);
        cands.tag_count.items[ci] = @intCast(@min(store.post_tags.items[p].len, 255));
        cands.quote_count.items[ci] = quotes[p];
        if (scope_by_tag) cands.cand_tags.items[ci] = try collectRowTags(arena, store, p);
    }

    const order = try discover.score(arena, &cands, config, now);

    // D4: the post-scoring filters. Per ranked position, hand the engine the
    // post's author (the diversity grouping key) and a moderation keep-bit — the
    // non-bypassable, runs-last pass (invariant 8). The moderation VERDICT is the
    // sealed module's (feed knows only the LabelFlags bits); a hidden post is
    // removed from the algorithmic pool here, identically for every config. (The
    // chronological Following path keeps the renderer's show-behind-a-notice
    // behavior — that is a user's explicit follows, not algorithmic surfacing.)
    const label_flags = posts.items(.label_flags);
    const author_key = try arena.alloc(u32, order.len);
    const keep = try arena.alloc(bool, order.len);
    for (order, author_key, keep) |ref, *ak, *k| {
        const p = ref.raw();
        ak.* = @intFromEnum(post_authors[p]);
        k.* = moderation.verdictFor(label_flags[p]) == .show;
    }
    const final = try discover.applyCaps(arena, order, author_key, keep, config);

    const out = try arena.alloc(TimelineItem, final.len);
    for (final, out) |ref, *item| item.* = try fillTimelineItem(arena, store, ref.raw(), .none);
    return out;
}

/// Build a post's THREAD as a Reddit-style NESTED view over the shared store
/// (ZONES inv. 4 — a query, not a container): walk up to the absolute root, then
/// DFS the whole descendant tree in preorder (siblings chronological), stamping
/// each item's view-derived `depth` (root = 0), `is_focus` (the `focus_cid` post,
/// which the shell scrolls to the top — ancestors remain above), and `stitched`.
/// The root author's consecutive self-reply chain is `stitched` (one continuous
/// post, flush at depth 0); everyone else nests one level deeper. The
/// store already holds the reply linkage (every ingested post interns its reply
/// refs), so the structure is derived locally — engagement/identity stay unified
/// with every other view, and the whole shape is a LENS over the same records,
/// never a property of the post. An unknown focus cid is an empty view (E4).
/// Allocates in `arena`.
/// Sentinel `depth` for a re-rooted view's ANCESTOR posts (the condensed context
/// chain shown above the re-rooted post). The renderer keys the smaller/dimmed
/// "ancestor" style off this — no extra per-item flag needed (keeps the hot
/// struct's size). A real depth never reaches this (the indent caps far below).
pub const thread_ancestor_depth: u8 = 255;

pub fn buildThreadView(
    arena: Allocator,
    store: *const Store,
    focus_cid: []const u8,
    /// When true (a tap INSIDE the thread), RE-ROOT on the focus: show its
    /// ancestors as a condensed chain above it, then the focus + its subtree.
    /// When false (the first tap from the timeline), show the WHOLE thread.
    rerooted: bool,
    /// CIDs the reader has collapsed (per-view state, never on the post): a
    /// collapsed post is emitted but its descendants are skipped.
    collapsed: []const []const u8,
    /// `now` for the scorer (invariant 9); only read when `reply_config` orders
    /// by a recency-bearing algorithm. The shell reads the clock and hands it in.
    now: i64,
    /// The reply pool's chosen algorithm (DISCOVER D3.5), or null for the
    /// THREADED DEFAULT — siblings chronological (invariant 14). This composes
    /// ORDER onto the threading STRUCTURE (invariant 13): the tree shape is
    /// unchanged; only the order of SIBLINGS within each branch changes. So
    /// "Threaded + Most Liked" is a legible conversation with the best replies
    /// first at every level — never the flat-vs-threaded false choice. The same
    /// `FeedConfig` the feed uses; the tray is the user's, carried here too
    /// (invariant 12).
    reply_config: ?discover.FeedConfig,
) error{OutOfMemory}![]TimelineItem {
    const focus_usize = lookupCid(store, focus_cid) orelse return &.{};
    const focus: u32 = @intCast(focus_usize);
    const posts = store.posts.slice();
    const parents = posts.items(.reply_parent);
    const createds = posts.items(.created_at);
    const post_authors = posts.items(.author);

    // Compose ORDER onto structure: when a reply algorithm is chosen, score every
    // post once so siblings can be ranked within their branch. Null ⇒ no scores,
    // siblings stay chronological (the threaded default). Replies are scored with
    // the SAME core (scoreRow) the feed uses — one engine, a different pool.
    const reply_scores: ?[]f64 = if (reply_config) |cfg| blk: {
        const likes = posts.items(.like_count);
        const reposts = posts.items(.repost_count);
        const replies_c = posts.items(.reply_count);
        const s = try arena.alloc(f64, store.posts.len);
        for (0..store.posts.len) |p| {
            s[p] = discover.scoreRow(.{
                .ref = discover.Ref.from(@intCast(p)),
                .created_at = createds[p],
                .like_count = likes[p],
                .repost_count = reposts[p],
                .reply_count = replies_c[p],
                .reply_chain_count = 0,
                .bookmark_count = 0,
                .profile_click_count = 0,
                .link_click_count = 0,
                .negative_count = 0,
                .author_rep = 0,
                .relevance = 0,
                .behavioral = 0,
            }, cfg, now);
        }
        break :blk s;
    } else null;

    // Walk up to the ABSOLUTE thread root (cycle-guarded) so the whole thread
    // shows — ancestors ABOVE the focus, which the reader can scroll up to (the
    // shell auto-scrolls so the focused post lands at the top). Each post is its
    // own thing (ZONES inv. 4); the focus is just where you entered.
    var abs_root: u32 = focus;
    var guard: usize = 0;
    while (guard < 4096) : (guard += 1) {
        const pp = parents[abs_root].unwrap() orelse break;
        abs_root = @intFromEnum(pp);
    }
    // The DFS root: the whole thread roots at the absolute root; a re-rooted view
    // roots at the focus (its ancestors are emitted condensed, above). The view's
    // "OP" — whose self-reply chain STITCHES — is the author of the DFS root.
    const root: u32 = if (rerooted) focus else abs_root;
    const op = post_authors[root];

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

    // Sibling order: by the chosen algorithm's score (best first), else
    // chronological (oldest first — the threaded default). Same struct shape so
    // the DFS push logic is untouched; the comparator picks the axis. A score
    // tie falls back to oldest-first so the order is total and stable.
    const Order = struct {
        createds: []const i64,
        scores: ?[]const f64,
        pub fn lessThan(ctx: @This(), x: u32, y: u32) bool {
            if (ctx.scores) |sc| {
                if (sc[x] != sc[y]) return sc[x] > sc[y]; // higher score renders first
                return ctx.createds[x] < ctx.createds[y]; // tie → oldest first
            }
            return ctx.createds[x] < ctx.createds[y]; // chronological
        }
    };

    // DFS preorder via an explicit stack: pop a node, emit it, push its children
    // in REVERSE chronological order so the oldest pops (and renders) first —
    // each subtree fully emitted before the next sibling (the nested order).
    const Frame = struct { row: u32, depth: u8, stitched: bool };
    var out: std.ArrayList(TimelineItem) = .empty;
    defer out.deinit(arena);
    var stack: std.ArrayList(Frame) = .empty;
    defer stack.deinit(arena);

    // Re-rooted: emit the ancestor chain (focus's parents up to the absolute
    // root) FIRST, in root-first order, flagged condensed via the sentinel depth
    // — the "what this is replying to" context above the re-rooted post.
    if (rerooted and root != abs_root) {
        var chain: std.ArrayList(u32) = .empty;
        defer chain.deinit(arena);
        var cur = parents[focus].unwrap();
        while (cur) |pidx| {
            try chain.append(arena, @intFromEnum(pidx));
            cur = parents[@intFromEnum(pidx)].unwrap();
        }
        std.mem.reverse(u32, chain.items); // root → parent-of-focus
        for (chain.items) |arow| {
            var aitem = try fillTimelineItem(arena, store, arow, .none);
            aitem.depth = thread_ancestor_depth;
            try out.append(arena, aitem);
        }
    }

    try stack.append(arena, .{ .row = root, .depth = 0, .stitched = false });
    while (stack.pop()) |fr| {
        var item = try fillTimelineItem(arena, store, fr.row, .none);
        item.depth = fr.depth;
        item.is_focus = fr.row == focus;
        item.stitched = fr.stitched;
        const kids_here: bool = if (children.get(fr.row)) |k| k.items.len > 0 else false;
        item.has_kids = kids_here;
        // Collapsed (per-view): emit the post, skip its descendants.
        var is_collapsed = false;
        for (collapsed) |c| if (std.mem.eql(u8, c, item.cid)) {
            is_collapsed = true;
            break;
        };
        item.collapsed = is_collapsed and kids_here;
        try out.append(arena, item);
        if (item.collapsed) continue; // hide the subtree
        if (children.get(fr.row)) |kids| {
            const ks = try arena.dupe(u32, kids.items);
            std.sort.block(u32, ks, Order{ .createds = createds, .scores = reply_scores }, Order.lessThan);
            var i = ks.len;
            while (i > 0) {
                i -= 1;
                // A child STITCHES (the OP continuing their own chain) when it AND
                // its parent are the OP. Stitched segments stay flush at depth 0
                // (one continuous post); everyone else nests one level deeper.
                const child = ks[i];
                const child_stitch = post_authors[child] == op and post_authors[fr.row] == op;
                const cd: u8 = if (child_stitch) 0 else fr.depth +| 1;
                try stack.append(arena, .{ .row = child, .depth = cd, .stitched = child_stitch });
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
    quote_of_cid: []const u8 = "", // "" when not a quote-post
    created_at: i64,
    /// The post's zone tags ('#'-less) when the caller knows them — the
    /// composer's optimistic seat passes inline + bar tags so the tray shows
    /// the instant the post lands. Empty for stream posts (server truth
    /// reconciles the tray at the next page dedup).
    tags: []const []const u8 = &.{},
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
        .quote_of = if (input.quote_of_cid.len > 0)
            optionalIndexForCid(store, input.quote_of_cid)
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
    // Same parallel-array discipline for the zone tags (A6): post_tags MUST grow
    // with posts or a post index overruns it (the snapshot round-trip and the
    // internPost dedup both rely on post_tags.len == posts.len). The stream
    // paths carry no tags (empty tray, server truth reconciles); the
    // composer's optimistic seat passes its inline + bar tags so the tray
    // shows this frame.
    const tag_off: u32 = @intCast(store.tag_pool.items.len);
    for (input.tags) |t| {
        if (t.len == 0) continue;
        try store.tag_pool.append(gpa, try appendString(gpa, store, t));
    }
    try store.post_tags.append(gpa, .{ .off = tag_off, .len = @intCast(store.tag_pool.items.len - tag_off) });

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
/// A7.2: cold union, size guard waived — a one-shot unlike verdict, returned
/// and consumed immediately, never held in quantity.
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

test "zones: a post's tags are stored out of band and surface on the timeline item" {
    const gpa = testing.allocator; // C6
    var store: Store = .{};
    defer deinitStore(gpa, &store);

    const page: lexicon.TimelinePage = .{ .feed = &.{
        .{ .post = .{
            .uri = "at://did:plc:a/app.zat4.feed.post/r1",
            .cid = "bafytag1",
            .author = .{ .did = "did:plc:a", .handle = "a.zat4.com" },
            .record = .{ .text = "love #water", .createdAt = "2026-06-28T00:00:00Z" },
            .tags = &.{ "water", "rivers" },
        } },
        .{ .post = .{
            .uri = "at://did:plc:b/app.zat4.feed.post/r2",
            .cid = "bafynotag",
            .author = .{ .did = "did:plc:b", .handle = "b.zat4.com" },
            .record = .{ .text = "no tags here", .createdAt = "2026-06-28T00:00:01Z" },
        } },
    } };
    _ = try ingestPage(gpa, &store, page);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const items = try buildTimeline(arena_state.allocator(), &store);
    try testing.expectEqual(@as(usize, 2), items.len);
    // Out-of-band storage stays parallel to posts; the tray resolves in order.
    try testing.expectEqual(@as(usize, 2), items[0].tags.len);
    try testing.expectEqualStrings("water", items[0].tags[0]);
    try testing.expectEqualStrings("rivers", items[0].tags[1]);
    // An untagged post yields an empty tray (E4) — and the parallel arrays stay
    // aligned (the untagged row doesn't borrow the tagged row's window).
    try testing.expectEqual(@as(usize, 0), items[1].tags.len);
}

test "zones: listZonesLocal derives the catalog from resident posts, case-folded (ZONES inv. 4)" {
    const gpa = testing.allocator; // C6
    var store: Store = .{};
    defer deinitStore(gpa, &store);

    const page: lexicon.TimelinePage = .{
        .feed = &.{
            .{ .post = .{
                .uri = "at://did:plc:a/app.zat4.feed.post/r1",
                .cid = "bafyz1",
                .author = .{ .did = "did:plc:a", .handle = "a.zat4.com" },
                .record = .{ .text = "love #water", .createdAt = "2026-06-28T00:00:00Z" },
                .tags = &.{ "water", "rivers" },
            } },
            .{
                .post = .{
                    .uri = "at://did:plc:b/app.zat4.feed.post/r2",
                    .cid = "bafyz2",
                    .author = .{ .did = "did:plc:b", .handle = "b.zat4.com" },
                    .record = .{ .text = "more #Water", .createdAt = "2026-06-28T00:00:01Z" },
                    .tags = &.{"Water"}, // different casing → the same zone
                },
            },
        },
    };
    _ = try ingestPage(gpa, &store, page);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    // `since` at the second post's timestamp: only it is "recent".
    const zones = try listZonesLocal(arena_state.allocator(), &store, 1782604801);
    // water (×2, #Water folds in) + rivers (×1) — the browse page's catalog even
    // without the AppView, so a zone reachable by tapping its hashtag lists here.
    try testing.expectEqual(@as(usize, 2), zones.len);
    try testing.expectEqualStrings("water", zones[0].tag); // canonical lowercase, first-seen
    try testing.expectEqual(@as(usize, 2), zones[0].count);
    try testing.expectEqual(@as(usize, 2), zones[0].authors); // did:plc:a + did:plc:b
    try testing.expectEqual(@as(usize, 1), zones[0].recent); // only the t+1 post
    try testing.expectEqualStrings("rivers", zones[1].tag);
    try testing.expectEqual(@as(usize, 1), zones[1].count);
    try testing.expectEqual(@as(usize, 1), zones[1].authors);
}

test "zones/dates: a reply-parent placeholder gets created_at + tags filled by its full view" {
    const gpa = testing.allocator; // C6
    var store: Store = .{};
    defer deinitStore(gpa, &store);

    // A feed page where a REPLY is listed before its PARENT (#test) — the
    // newest-first reality. Ingesting the reply hydrates #test as a REFERENCE
    // (no createdAt, no tags) → a placeholder. Then #test arrives as its own
    // full feed view, carrying the real createdAt + tags. The dedup must fill
    // those in, not leave the placeholder (the "2947w + no tray" bug).
    const parent_ref: lexicon.PostView = .{
        .cid = "bafytest",
        .author = .{ .did = "did:plc:a", .handle = "a.zat4.com" },
        .record = .{ .text = "This is a #test", .createdAt = "" },
    };
    const page: lexicon.TimelinePage = .{ .feed = &.{
        .{
            .post = .{
                .uri = "at://did:plc:a/app.zat4.feed.post/reply1",
                .cid = "bafyreply",
                .author = .{ .did = "did:plc:a", .handle = "a.zat4.com" },
                .record = .{ .text = "wait a second", .createdAt = "2026-06-28T21:17:10Z" },
            },
            .reply = .{ .parent = parent_ref, .root = parent_ref },
        },
        .{ .post = .{
            .uri = "at://did:plc:a/app.zat4.feed.post/test1",
            .cid = "bafytest",
            .author = .{ .did = "did:plc:a", .handle = "a.zat4.com" },
            .record = .{ .text = "This is a #test", .createdAt = "2026-06-28T21:16:58Z" },
            .tags = &.{ "test", "deep" },
        } },
    } };
    _ = try ingestPage(gpa, &store, page);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const items = try buildTimeline(arena_state.allocator(), &store);
    var found = false;
    for (items) |it| {
        if (!std.mem.eql(u8, it.cid, "bafytest")) continue;
        found = true;
        try testing.expect(it.created_at != 0); // date filled, not the epoch-0 placeholder
        try testing.expectEqual(@as(usize, 2), it.tags.len); // tray filled from the full view
        try testing.expectEqualStrings("test", it.tags[0]);
    }
    try testing.expect(found);
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
        .did = "did:plc:bob",
        .handle = "did:plc:bob",
        .uri = "at://did:plc:bob/app.zat4.feed.post/1",
        .cid = "c1",
        .text = "one",
        .reply_parent_cid = "",
        .reply_root_cid = "",
        .created_at = 10,
    });
    // A later post by the SAME author carries the resolved handle (the AppView
    // now serves it). internAuthor dedups by DID but must reconcile the handle.
    _ = try ingestLivePost(gpa, &store, .{
        .did = "did:plc:bob",
        .handle = "bob.zat4.com",
        .uri = "at://did:plc:bob/app.zat4.feed.post/2",
        .cid = "c2",
        .text = "two",
        .reply_parent_cid = "",
        .reply_root_cid = "",
        .created_at = 20,
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
        .did = "did:plc:me",
        .handle = "me.zat",
        .uri = "",
        .cid = "pending:0",
        .text = "hello",
        .reply_parent_cid = "",
        .reply_root_cid = "",
        .created_at = 100,
    });
    try testing.expect(lookupCid(&store, "pending:0") != null);
    const idx = lookupCid(&store, "pending:0").?;

    // Confirm: re-key to the real cid/uri; the temp key is gone, the slot kept.
    try reconcileOptimisticPost(gpa, &store, "pending:0", "bafyreal", "at://did:plc:me/app.zat4.feed.post/bafyreal");
    try testing.expect(lookupCid(&store, "pending:0") == null);
    try testing.expectEqual(idx, lookupCid(&store, "bafyreal").?);

    // An optimistic REPLY that then FAILS → detached from feed + thread.
    _ = try ingestLivePost(gpa, &store, .{
        .did = "did:plc:me",
        .handle = "me.zat",
        .uri = "",
        .cid = "pending:1",
        .text = "a reply",
        .reply_parent_cid = "bafyreal",
        .reply_root_cid = "bafyreal",
        .created_at = 110,
    });
    const before = store.feed.len;
    dropOptimisticPost(&store, "pending:1");
    try testing.expect(lookupCid(&store, "pending:1") == null); // un-keyed
    try testing.expectEqual(before - 1, store.feed.len); // feed row removed
    // The thread of the (real) parent no longer contains the dropped reply.
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const thread = try buildThreadView(arena_state.allocator(), &store, "bafyreal", false, &.{}, 1_700_000_000, null);
    try testing.expectEqual(@as(usize, 1), thread.len); // just the parent
}

test "buildThreadView: whole thread, focus marked; OP self-chain stitches, others nest" {
    const gpa = testing.allocator;
    var store: Store = .{};
    defer deinitStore(gpa, &store);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // OP "a" stitches a self-thread (cRoot -> cA1 -> cA2); "b" replies to the
    // root (cB); then "a" replies into b's subthread (cBR).
    const mk = struct {
        fn p(g: Allocator, s: *Store, did: []const u8, handle: []const u8, cid: []const u8, text: []const u8, parent: []const u8, created: i64) !void {
            _ = try ingestLivePost(g, s, .{
                .did = did,
                .handle = handle,
                .uri = cid, // unique per post is enough for the store key here
                .cid = cid,
                .text = text,
                .reply_parent_cid = parent,
                .reply_root_cid = if (parent.len > 0) "cRoot" else "",
                .created_at = created,
            });
        }
    }.p;
    try mk(gpa, &store, "did:plc:a", "a.zat4.com", "cRoot", "root", "", 10);
    try mk(gpa, &store, "did:plc:a", "a.zat4.com", "cA1", "self 1", "cRoot", 20);
    try mk(gpa, &store, "did:plc:b", "b.zat4.com", "cB", "b reply", "cRoot", 25);
    try mk(gpa, &store, "did:plc:a", "a.zat4.com", "cA2", "self 2", "cA1", 30);
    try mk(gpa, &store, "did:plc:a", "a.zat4.com", "cBR", "a into b", "cB", 40);

    // Focus the root: the whole tree, preorder, siblings chronological.
    const t = try buildThreadView(arena, &store, "cRoot", false, &.{}, 1_700_000_000, null);
    try testing.expectEqual(@as(usize, 5), t.len);
    // root(0,—), self1(0,stitch), self2(0,stitch), b reply(1,nest), a-into-b(2,nest).
    try testing.expectEqualStrings("root", t[0].text);
    try testing.expectEqual(@as(u8, 0), t[0].depth);
    try testing.expect(!t[0].stitched and t[0].is_focus);
    try testing.expectEqualStrings("self 1", t[1].text);
    try testing.expectEqual(@as(u8, 0), t[1].depth);
    try testing.expect(t[1].stitched);
    try testing.expectEqualStrings("self 2", t[2].text);
    try testing.expectEqual(@as(u8, 0), t[2].depth);
    try testing.expect(t[2].stitched);
    try testing.expectEqualStrings("b reply", t[3].text);
    try testing.expectEqual(@as(u8, 1), t[3].depth);
    try testing.expect(!t[3].stitched);
    try testing.expectEqualStrings("a into b", t[4].text);
    try testing.expectEqual(@as(u8, 2), t[4].depth); // a replying into b's subtree → nests
    try testing.expect(!t[4].stitched);

    // Collapsing cB hides its subtree (cBR) but keeps cB, flagged collapsed.
    const tc = try buildThreadView(arena, &store, "cRoot", false, &.{"cB"}, 1_700_000_000, null);
    try testing.expectEqual(@as(usize, 4), tc.len); // cBR is hidden
    var saw_cb = false;
    for (tc) |it| {
        try testing.expect(!std.mem.eql(u8, it.cid, "cBR")); // subtree gone
        if (std.mem.eql(u8, it.cid, "cB")) {
            saw_cb = true;
            try testing.expect(it.collapsed and it.has_kids);
        }
    }
    try testing.expect(saw_cb);

    // Focusing the b reply still shows the WHOLE thread (ancestors above), with
    // cB marked as the focus — the shell scrolls to it; the tree is unchanged.
    const t2 = try buildThreadView(arena, &store, "cB", false, &.{}, 1_700_000_000, null);
    try testing.expectEqual(@as(usize, 5), t2.len);
    try testing.expectEqualStrings("root", t2[0].text); // ancestors are above the focus
    var f_idx: ?usize = null;
    for (t2, 0..) |it, ix| if (it.is_focus) {
        f_idx = ix;
    };
    try testing.expect(f_idx != null);
    try testing.expectEqualStrings("b reply", t2[f_idx.?].text);

    // RE-ROOTED on cB: its ancestor (cRoot) is emitted CONDENSED (sentinel depth)
    // above, then cB (focus, depth 0) + its subtree (cBR, depth 1).
    const tr = try buildThreadView(arena, &store, "cB", true, &.{}, 1_700_000_000, null);
    try testing.expectEqual(@as(usize, 3), tr.len);
    try testing.expectEqualStrings("root", tr[0].text);
    try testing.expectEqual(thread_ancestor_depth, tr[0].depth); // condensed ancestor
    try testing.expectEqualStrings("b reply", tr[1].text);
    try testing.expect(tr[1].is_focus and tr[1].depth == 0);
    try testing.expectEqualStrings("a into b", tr[2].text);
    try testing.expectEqual(@as(u8, 1), tr[2].depth);
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
    const profile_page = lexicon.TimelinePage{
        .feed = &.{
            .{ .post = .{
                .uri = "at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/app.zat4.feed.post/3kali3",
                .cid = "bafyreialice3",
                .author = alice,
                .record = .{ .text = "alice newest", .createdAt = "2026-01-09T00:00:00Z" },
            } },
            .{ .post = alice_post_1 }, // already resident → dedup, no dup
        },
    };
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

test "buildDiscoverView: the scorer reorders Home away from feed order" {
    const gpa = testing.allocator; // C6
    var store: Store = .{};
    defer deinitStore(gpa, &store);

    // Two posts at the SAME time so recency is equal and the difference is pure
    // engagement; the quiet one is FIRST in feed order, the popular one second.
    const page: lexicon.TimelinePage = .{ .feed = &.{
        .{ .post = .{
            .uri = "at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/app.zat4.feed.post/low",
            .cid = "bafyrelow",
            .author = .{ .did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", .handle = "a.test" },
            .record = .{ .text = "quiet post", .createdAt = "2026-01-01T00:00:00Z" },
        } },
        .{ .post = .{
            .uri = "at://did:plc:bbbbbbbbbbbbbbbbbbbbbbbb/app.zat4.feed.post/high",
            .cid = "bafyrehigh",
            .author = .{ .did = "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb", .handle = "b.test" },
            .record = .{ .text = "popular post", .createdAt = "2026-01-01T00:00:00Z" },
            .likeCount = 100,
            .repostCount = 5,
        } },
    } };
    _ = try ingestPage(gpa, &store, page);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Chronological/feed order keeps page order: quiet first.
    const chrono = try buildTimeline(arena, &store);
    try testing.expectEqualStrings("quiet post", chrono[0].text);

    // Scored: the popular post ranks first though it is SECOND in feed order —
    // proof the algorithm (not feed order) decides the scored view.
    // `now` ~1.3h after the posts: recency decay is equal and non-zero for both
    // (a far-future `now` would underflow both to 0 and the tiebreak — not the
    // weights — would decide). 2026-01-01T00:00:00Z ≈ 1_767_225_600.
    const scored = try buildDiscoverView(arena, &store, discover.DEFAULT_CONFIG, 1_767_230_400, null);
    try testing.expectEqual(@as(usize, 2), scored.len);
    try testing.expectEqualStrings("popular post", scored[0].text);
    try testing.expectEqualStrings("quiet post", scored[1].text);
}

test "buildDiscoverView D4: moderation removes hidden posts; per-author cap trims the rest" {
    const gpa = testing.allocator; // C6
    var store: Store = .{};
    defer deinitStore(gpa, &store);

    // Five posts by ONE author at the same time, decreasing likes (so the score
    // order is just the like order). The 80-like post is spam-labeled (hidden).
    const A = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    const page: lexicon.TimelinePage = .{ .feed = &.{
        .{ .post = .{ .uri = "at://" ++ A ++ "/app.zat4.feed.post/a100", .cid = "bafa100", .author = .{ .did = A, .handle = "a.test" }, .record = .{ .text = "a100", .createdAt = "2026-01-01T00:00:00Z" }, .likeCount = 100 } },
        .{ .post = .{ .uri = "at://" ++ A ++ "/app.zat4.feed.post/a80", .cid = "bafa80", .author = .{ .did = A, .handle = "a.test" }, .record = .{ .text = "a80", .createdAt = "2026-01-01T00:00:00Z" }, .likeCount = 80, .labels = &.{.{ .val = "spam" }} } },
        .{ .post = .{ .uri = "at://" ++ A ++ "/app.zat4.feed.post/a60", .cid = "bafa60", .author = .{ .did = A, .handle = "a.test" }, .record = .{ .text = "a60", .createdAt = "2026-01-01T00:00:00Z" }, .likeCount = 60 } },
        .{ .post = .{ .uri = "at://" ++ A ++ "/app.zat4.feed.post/a40", .cid = "bafa40", .author = .{ .did = A, .handle = "a.test" }, .record = .{ .text = "a40", .createdAt = "2026-01-01T00:00:00Z" }, .likeCount = 40 } },
        .{ .post = .{ .uri = "at://" ++ A ++ "/app.zat4.feed.post/a20", .cid = "bafa20", .author = .{ .did = A, .handle = "a.test" }, .record = .{ .text = "a20", .createdAt = "2026-01-01T00:00:00Z" }, .likeCount = 20 } },
    } };
    _ = try ingestPage(gpa, &store, page);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const scored = try buildDiscoverView(arena_state.allocator(), &store, discover.DEFAULT_CONFIG, 1_767_230_400, null);

    // Spam (a80) removed by the non-bypassable filter; of the four survivors the
    // per-author cap (default 3) keeps the top three, dropping a20.
    try testing.expectEqual(@as(usize, 3), scored.len);
    try testing.expectEqualStrings("a100", scored[0].text);
    try testing.expectEqualStrings("a60", scored[1].text);
    try testing.expectEqualStrings("a40", scored[2].text);
    for (scored) |it| {
        try testing.expect(!std.mem.eql(u8, it.text, "a80")); // moderation-hidden, gone
        try testing.expect(!std.mem.eql(u8, it.text, "a20")); // diversity-capped, gone
    }
}

test "buildThreadView D3.5: a reply algorithm orders siblings; threading structure is preserved" {
    const gpa = testing.allocator; // C6
    var store: Store = .{};
    defer deinitStore(gpa, &store);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const mk = struct {
        fn p(g: Allocator, s: *Store, did: []const u8, cid: []const u8, text: []const u8, parent: []const u8, created: i64) !void {
            _ = try ingestLivePost(g, s, .{
                .did = did,
                .handle = "x",
                .uri = cid,
                .cid = cid,
                .text = text,
                .reply_parent_cid = parent,
                .reply_root_cid = if (parent.len > 0) "cRoot" else "",
                .created_at = created,
            });
        }
    }.p;
    // Root "a"; three direct replies by distinct authors (so none stitch), one
    // nested under B. Times ascending A<B<C; likes B(50) > A(5) > C(1).
    try mk(gpa, &store, "did:plc:a", "cRoot", "root", "", 10);
    try mk(gpa, &store, "did:plc:b", "cA", "A", "cRoot", 20);
    try mk(gpa, &store, "did:plc:c", "cB", "B", "cRoot", 25);
    try mk(gpa, &store, "did:plc:d", "cC", "C", "cRoot", 30);
    try mk(gpa, &store, "did:plc:e", "cB1", "B1", "cB", 40);
    const likes = store.posts.slice().items(.like_count);
    likes[lookupCid(&store, "cA").?] = 5;
    likes[lookupCid(&store, "cB").?] = 50;
    likes[lookupCid(&store, "cC").?] = 1;

    // Threaded default (null config): siblings chronological → A, B, (B1), C.
    const chrono = try buildThreadView(arena, &store, "cRoot", false, &.{}, 1_700_000_000, null);
    const chrono_texts = [_][]const u8{ "root", "A", "B", "B1", "C" };
    try testing.expectEqual(chrono_texts.len, chrono.len);
    for (chrono, chrono_texts) |it, want| try testing.expectEqualStrings(want, it.text);

    // Most-Liked reply algorithm (likes only, no recency): siblings of root by
    // likes desc → B, A, C; B's child B1 STAYS under B (structure preserved).
    const most_liked = discover.FeedConfig{
        .w_repost = 0,
        .w_reply = 0,
        .w_reply_chain = 0,
        .w_bookmark = 0,
        .w_profile_click = 0,
        .w_link_click = 0,
        .recency_half_life_hrs = 0,
        .velocity_boost = false,
        .author_rep_weight = 0,
        .relevance_weight = 0,
    };
    const scored = try buildThreadView(arena, &store, "cRoot", false, &.{}, 1_700_000_000, most_liked);
    const scored_texts = [_][]const u8{ "root", "B", "B1", "A", "C" };
    try testing.expectEqual(scored_texts.len, scored.len);
    for (scored, scored_texts) |it, want| try testing.expectEqualStrings(want, it.text);
    // Order composed onto structure: B1 still nests one level under B (depth 2),
    // immediately after it — the tree shape is unchanged, only sibling order is.
    try testing.expectEqualStrings("B1", scored[2].text);
    try testing.expectEqual(@as(u8, 2), scored[2].depth);
    try testing.expectEqual(@as(u8, 1), scored[1].depth); // B at depth 1
}

test "buildDiscoverView D9: a learned affinity lifts a matching post, but only behind the doorway" {
    const gpa = testing.allocator; // C6
    var store: Store = .{};
    defer deinitStore(gpa, &store);

    // Two posts, same author, same time. The weather post is MORE engaged (12
    // vs 10 likes), so on engagement alone it wins — only a behavioral lift can
    // reorder them. The dolphins post is tagged #dolphins; the user's learner
    // has learned to love dolphins.
    const A = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa";
    const page: lexicon.TimelinePage = .{ .feed = &.{
        .{ .post = .{ .uri = "at://" ++ A ++ "/app.zat4.feed.post/d", .cid = "bafd", .author = .{ .did = A, .handle = "a.test" }, .record = .{ .text = "dolphins post", .createdAt = "2026-01-01T00:00:00Z" }, .likeCount = 10, .tags = &.{"dolphins"} } },
        .{ .post = .{ .uri = "at://" ++ A ++ "/app.zat4.feed.post/w", .cid = "bafw", .author = .{ .did = A, .handle = "a.test" }, .record = .{ .text = "weather post", .createdAt = "2026-01-01T00:00:00Z" }, .likeCount = 12, .tags = &.{"weather"} } },
    } };
    _ = try ingestPage(gpa, &store, page);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var v: learner.PrefVector = .{};
    for (0..10) |_| learner.update(&v, &.{"dolphins"}, 1.0); // attention on dolphins

    // A config that USES behavioral data + the trained vector → the dolphins post
    // overcomes its engagement deficit and ranks first.
    var learns = discover.DEFAULT_CONFIG;
    learns.behavioral_weight = 1.0;
    const adapted = try buildDiscoverView(arena, &store, learns, 1_767_230_400, &v);
    try testing.expectEqualStrings("dolphins post", adapted[0].text);

    // The doorway: a config with behavioral_weight 0 (e.g. Discover Private)
    // never reads the vector even when one is passed → engagement decides, the
    // weather post wins.
    const private_view = try buildDiscoverView(arena, &store, discover.DEFAULT_CONFIG, 1_767_230_400, &v);
    try testing.expectEqualStrings("weather post", private_view[0].text);

    // And with no vector at all, same result — engagement order.
    const no_prefs = try buildDiscoverView(arena, &store, learns, 1_767_230_400, null);
    try testing.expectEqualStrings("weather post", no_prefs[0].text);
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
