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

//! B1 classification: CORE (pure data). Lexicon wire shapes — THE
//! NAMESPACE WALL (STANDALONE_ROADMAP Phase A). This module is the one
//! seat that decides which lexicon Zat4 reads and writes; sealing it here
//! (D1/D3) is what makes the wall a single-module change. Every other
//! module asks for "posts," never for "`app.zat4` posts" — the namespace
//! string appears in NO other module's signatures.
//!
//! THE WALL, made real: Zat4 content lives in the `app.zat4.*` collections,
//! a disjoint universe from Bluesky's `app.bsky.*`. A Bluesky AppView does
//! not index `app.zat4.*`, so Zat4 content never surfaces there; a Zat4
//! client/AppView only reads `app.zat4.*`, so Bluesky content never
//! surfaces here. The separation is STRUCTURAL — the namespace itself, not
//! a runtime filter. `com.atproto.*` calls (createSession, createRecord,
//! resolveHandle, …) STAY: those are protocol, shared by every atproto
//! app, not Bluesky content.
//!
//! Phase A decisions, recorded deliberately (near-permanent — a published
//! schema is very hard to change; treat with A7 gravity):
//!  1. Own the AppView query methods too (`app.zat4.actor.getProfile`,
//!     `app.zat4.feed.getTimeline`) — a total wall at every layer, not just
//!     the record collections. Reads await the Phase C AppView (or a Phase
//!     B endpoint repoint to a stub); writes already land in `app.zat4.*`
//!     in the user's own repo via the protocol-level `createRecord`.
//!  2. Profile is a FRESH `app.zat4.actor.profile` record (a self-contained
//!     Zat4 identity), with an OPTIONAL one-time import of name/bio at
//!     enrollment as a UX nicety — never an ongoing dependency. The user's
//!     DID, handle, and follow graph carry over for free: they live in the
//!     open network, not in Bluesky.
//!  3. Versioning is NSID-as-version (the protocol's own convention): a
//!     breaking change bumps the collection NSID under a NEW name; the shape
//!     under a fixed name never silently changes. `revision` below records
//!     the current rev. Adding an OPTIONAL field is backward-compatible and
//!     does not bump it (E4 — an absent field is an ordinary state).
//!     Removing or retyping a field is a break and earns a new NSID.
//!
//! Plain-data record types (A1: fields only, behavior nowhere near them)
//! mirroring the lexicon JSON this client consumes — nothing more (start
//! narrow; expand on demand). Field names match the wire camelCase exactly:
//! that is what lets std.json map them with zero glue code (F2 — comptime
//! reflection instead of generated codecs). Wire fidelity deliberately wins
//! over Zig naming style inside this file.
//!
//! Every field the lexicon marks optional defaults here, so a document
//! missing it still parses: lexicons evolve, and an absent field is an
//! ordinary state, not an error (E4). Unknown fields are ignored at the
//! decode site for the same reason.
//!
//! A7 stance, recorded for review: these structs are TRANSIENT PARSE
//! TARGETS — one per response, slice-heavy, arena-bound, decomposed
//! immediately. They are not the bulk-resident records. When responses are
//! flattened into resident SoA collections (A3), THOSE record types (spans
//! + u32 indexes, no slices) carry the exact-size guards. Hardening at that
//! point, and not before, is F5 applied on purpose. Each struct below
//! claims its A7.2 waiver individually.

/// The lexicon revision (Phase A decision 3). NSID-as-version means this is
/// for observability and future migration tooling, not a per-record field:
/// records carry no version byte (that would bloat hot records for nothing).
/// Bump only on a coordinated, documented schema change; an additive,
/// optional-field change does not bump it. Not a record (a string const):
/// A1/A7 do not apply.
pub const revision = "zat4.2026-06-14";

/// XRPC method NSIDs live beside the shapes they return, so a lexicon
/// change lands in exactly one file (D6).
pub const method = struct {
    // Not a record: a string-constant namespace (no fields). A1/A7 do not apply.

    // Zat4 AppView query methods (Phase A decision 1 — owned, total wall).
    // These resolve against the Zat4 AppView (Phase C); until it exists they
    // 404 against any Bluesky endpoint, which is correct — Zat4 is not a
    // Bluesky client.
    pub const get_profile = "app.zat4.actor.getProfile";
    pub const get_timeline = "app.zat4.feed.getTimeline";
    pub const get_author_feed = "app.zat4.feed.getAuthorFeed";
    pub const get_post_thread = "app.zat4.feed.getPostThread";

    // Protocol methods — shared by every atproto app, NOT Bluesky content.
    // These stay exactly as they are (the wall self-check exempts them).
    pub const create_session = "com.atproto.server.createSession";
    pub const refresh_session = "com.atproto.server.refreshSession";
    pub const get_session = "com.atproto.server.getSession";
    pub const create_record = "com.atproto.repo.createRecord";
    pub const put_record = "com.atproto.repo.putRecord";
    pub const delete_record = "com.atproto.repo.deleteRecord";
    pub const list_records = "com.atproto.repo.listRecords";
    pub const resolve_handle = "com.atproto.identity.resolveHandle";
    pub const describe_repo = "com.atproto.repo.describeRepo";
};

/// Response of `com.atproto.repo.describeRepo` — the AppView reads a polled
/// author's verified handle from it (DID → handle) so posts show `@handle`.
/// `handleIsCorrect` is the PDS's bidirectional handle↔DID verification.
/// A7.2: cold struct, size guard waived — transient parse target, one per
/// repo per resolve.
pub const RepoDescription = struct {
    did: []const u8 = "",
    handle: []const u8 = "",
    handleIsCorrect: bool = false,
};

/// Record collections this client reads and writes — the wall itself.
/// Changing these four values is what severs Zat4 from Bluesky; every
/// production consumer references them symbolically, so the flip propagates
/// from this one seat (the architecture's central promise, cashed in).
pub const collection = struct {
    // Not a record: a string-constant namespace (no fields). A1/A7 do not apply.

    pub const post = "app.zat4.feed.post";
    pub const like = "app.zat4.feed.like";
    pub const repost = "app.zat4.feed.repost";
    pub const follow = "app.zat4.graph.follow";
    /// Fresh Zat4-native profile (Phase A decision 2). Self-contained; an
    /// optional one-time import at enrollment may prefill its fields, but the
    /// record is ours and depends on nothing in app.bsky.
    pub const profile = "app.zat4.actor.profile";
};

/// Richtext facet `$type` discriminators. Zat4 defines its own richtext
/// namespace (rather than reusing app.bsky.richtext) so NO app.bsky string
/// appears on any production write path — the wall is total. The facet
/// STRUCTURE (byte-offset index + a mention/link feature) is the same shape
/// the whole network uses; only the namespace is ours.
pub const richtext = struct {
    // Not a record: a string-constant namespace (no fields). A1/A7 do not apply.
    pub const facet_link = "app.zat4.richtext.facet#link";
    pub const facet_mention = "app.zat4.richtext.facet#mention";
};

/// Subset of `app.zat4.actor.defs#profileViewDetailed` we consume.
/// A7.2: cold struct, size guard waived — transient parse target (header note).
pub const ProfileViewDetailed = struct {
    did: []const u8 = "",
    handle: []const u8 = "",
    displayName: ?[]const u8 = null,
    description: ?[]const u8 = null,
    avatar: ?[]const u8 = null,
    followersCount: u64 = 0,
    followsCount: u64 = 0,
    postsCount: u64 = 0,
    createdAt: ?[]const u8 = null,
    /// Present on authenticated views; `following` is the session
    /// account's follow-record uri when one exists — presence IS the bool.
    viewer: ?ProfileViewerState = null,
};

/// A7.2: cold struct, size guard waived — transient parse target.
pub const ProfileViewerState = struct {
    following: ?[]const u8 = null,
};

/// Input for `com.atproto.server.createSession`.
/// A7.2: cold struct, size guard waived — one per login attempt.
pub const CreateSessionInput = struct {
    identifier: []const u8,
    password: []const u8,
    /// Email 2FA code; omitted from the wire when null.
    authFactorToken: ?[]const u8 = null,
};

/// Response of createSession AND refreshSession (same shape on the wire).
/// A7.2: cold struct, size guard waived — transient parse target.
pub const SessionResponse = struct {
    accessJwt: []const u8 = "",
    refreshJwt: []const u8 = "",
    handle: []const u8 = "",
    did: []const u8 = "",
};

/// Subset of `com.atproto.server.getSession` we consume (used to confirm an
/// authenticated round trip).
/// A7.2: cold struct, size guard waived — transient parse target.
pub const GetSessionResponse = struct {
    did: []const u8 = "",
    handle: []const u8 = "",
};

// ---------------------------------------------------------------------------
// Feed wire shapes (`app.zat4.feed.getTimeline`). Same A7.2 stance as the
// header: transient parse targets; the RESIDENT records with size guards
// live in core/feed.zig. Wire unions (reply refs that may be notFound /
// blocked, reasons that may be pins) are handled by defaulting: a variant
// whose fields are absent parses to empty strings, and ingest treats an
// empty cid/did as "not there" (E4 — absence is an ordinary state).
// ---------------------------------------------------------------------------

/// Subset of `app.zat4.actor.defs#profileViewBasic`.
/// A7.2: cold struct, size guard waived — transient parse target.
pub const ProfileViewBasic = struct {
    did: []const u8 = "",
    handle: []const u8 = "",
    displayName: ?[]const u8 = null,
    avatar: ?[]const u8 = null,
};

/// The original `app.zat4.feed.post` record carried inside a PostView.
/// A7.2: cold struct, size guard waived — transient parse target.
pub const PostRecord = struct {
    text: []const u8 = "",
    createdAt: []const u8 = "",
    /// The record schema's reply refs (strong refs to root + parent).
    /// Shared shape with the write side — it is the same wire object.
    reply: ?ReplyRefOut = null,
};

/// The session account's relationship to a post (present only on
/// authenticated views): the at-uris of this account's like/repost records
/// if they exist. v1 uses presence only; keeping the uris (for deletes) is
/// the recorded path to unlike/unboost.
/// A7.2: cold struct, size guard waived — transient parse target.
pub const Viewer = struct {
    like: ?[]const u8 = null,
    repost: ?[]const u8 = null,
};

/// One content label applied to a post (by the PDS, the AppView, or a
/// subscribed labeler). Only the value matters to policy.
/// A7.2: cold struct, size guard waived — transient parse target.
pub const Label = struct {
    val: []const u8 = "",
};

/// Subset of `app.zat4.feed.defs#postView`. Reply parents/roots arrive as
/// this same shape; notFound/blocked variants parse to defaults (empty cid).
/// A7.2: cold struct, size guard waived — transient parse target.
pub const PostView = struct {
    uri: []const u8 = "",
    cid: []const u8 = "",
    author: ProfileViewBasic = .{},
    record: PostRecord = .{},
    labels: []const Label = &.{},
    replyCount: u32 = 0,
    repostCount: u32 = 0,
    likeCount: u32 = 0,
    quoteCount: u32 = 0,
    indexedAt: []const u8 = "",
    viewer: ?Viewer = null,
};

/// `app.zat4.feed.defs#replyRef` — root and parent, hydrated.
/// A7.2: cold struct, size guard waived — transient parse target.
pub const ReplyRef = struct {
    root: PostView = .{},
    parent: PostView = .{},
};

/// `app.zat4.feed.defs#reasonRepost`; a reasonPin parses to an empty `by`.
/// A7.2: cold struct, size guard waived — transient parse target.
pub const ReasonRepost = struct {
    by: ProfileViewBasic = .{},
    indexedAt: []const u8 = "",
};

/// One timeline entry: the post, plus why it is in the feed.
/// A7.2: cold struct, size guard waived — transient parse target.
pub const FeedViewPost = struct {
    post: PostView = .{},
    reply: ?ReplyRef = null,
    reason: ?ReasonRepost = null,
};

/// Response of `app.zat4.feed.getTimeline`.
/// A7.2: cold struct, size guard waived — transient parse target.
pub const TimelinePage = struct {
    cursor: ?[]const u8 = null,
    feed: []const FeedViewPost = &.{},
};

/// Response of `app.zat4.feed.getPostThread`: every post in the focused post's
/// thread (its root + the whole descendant tree), as a FLAT reference set — no
/// tree, no depth on the wire (the post is the post; structure is the reader's
/// lens, derived client-side from the reply edges). The client builds the nested
/// order + per-post depth in `feed.buildThreadView`.
/// A7.2: cold struct, size guard waived — transient parse/build target.
pub const ThreadView = struct {
    posts: []const FeedViewPost = &.{},
};

// ---------------------------------------------------------------------------
// Write-path wire shapes (`com.atproto.repo.createRecord`). Creation-side
// records carry their "$type" as a defaulted field; optionals left null are
// omitted from the JSON (the encoder's emit-null-off policy). All A7.2:
// transient, built per request in the arena.
// ---------------------------------------------------------------------------

/// A record reference: the universal (uri, cid) pair — what createRecord
/// returns and what likes/reposts/replies point at.
/// A7.2: cold struct, size guard waived — transient parse/build target.
pub const RecordRef = struct {
    uri: []const u8 = "",
    cid: []const u8 = "",
};

/// `app.zat4.richtext.facet#byteSlice` — UTF-8 byte offsets into the text.
/// A7.2: cold struct, size guard waived — transient build target.
pub const ByteSlice = struct {
    byteStart: u32,
    byteEnd: u32,
};

/// One facet feature: a mention (did set) or a link (uri set). The unset
/// side is omitted from the wire.
/// A7.2: cold struct, size guard waived — transient build target.
pub const FacetFeature = struct {
    @"$type": []const u8,
    did: ?[]const u8 = null,
    uri: ?[]const u8 = null,
};

/// `app.zat4.richtext.facet`.
/// A7.2: cold struct, size guard waived — transient build target.
pub const Facet = struct {
    index: ByteSlice,
    features: []const FacetFeature,
};

/// Reply refs on an outgoing post: strong refs to the thread root and the
/// immediate parent.
/// A7.2: cold struct, size guard waived — transient build target.
pub const ReplyRefOut = struct {
    root: RecordRef,
    parent: RecordRef,
};

/// Outgoing `app.zat4.feed.post`.
/// A7.2: cold struct, size guard waived — transient build target.
pub const PostRecordOut = struct {
    @"$type": []const u8 = collection.post,
    text: []const u8,
    createdAt: []const u8,
    reply: ?ReplyRefOut = null,
    facets: ?[]const Facet = null,
};

/// Outgoing like/repost — the two share one shape, distinguished by $type.
/// A7.2: cold struct, size guard waived — transient build target.
/// `com.atproto.repo.deleteRecord` input and response.
/// A7.2: cold structs, size guard waived — transient wire shapes.
pub const DeleteRecordOut = struct {
    repo: []const u8,
    collection: []const u8,
    rkey: []const u8,
};

/// A7.2: cold struct, size guard waived — transient parse target.
pub const DeleteRecordResponse = struct {
    commit: ?CommitMeta = null,
};

/// A7.2: cold struct, size guard waived — transient parse target.
pub const CommitMeta = struct {
    cid: []const u8 = "",
    rev: []const u8 = "",
};

/// A7.2: cold struct, size guard waived — transient serialize source.
pub const SubjectRecordOut = struct {
    @"$type": []const u8,
    subject: RecordRef,
    createdAt: []const u8,
};

/// Outgoing `app.zat4.graph.follow`.
/// A7.2: cold struct, size guard waived — transient build target.
pub const FollowRecordOut = struct {
    @"$type": []const u8 = collection.follow,
    subject: []const u8, // the did being followed
    createdAt: []const u8,
};

/// Outgoing `app.zat4.actor.profile` — the fresh Zat4-native profile
/// (Phase A decision 2). Self-contained: the optional one-time enrollment
/// import (a UX nicety) prefills displayName/description from the user's
/// existing identity if they opt in, but the record is ours and depends on
/// nothing in app.bsky. Avatar/banner blobs are deferred (they need the
/// blob-upload path) — an absent avatar is an ordinary state (E4), not an
/// error, so the field is simply omitted until that lands.
/// A7.2: cold struct, size guard waived — one per profile edit, arena-built.
pub const ProfileRecordOut = struct {
    @"$type": []const u8 = collection.profile,
    displayName: ?[]const u8 = null,
    description: ?[]const u8 = null,
    createdAt: []const u8,
};

/// The createRecord envelope, generic over the record shape at comptime
/// (F2: the type system builds the wire forms; nothing is imported).
pub fn CreateRecordInput(comptime Record: type) type {
    return struct {
        repo: []const u8,
        collection: []const u8,
        record: Record,
    };
}

/// The putRecord envelope — create-or-REPLACE at a known rkey (used for the
/// self-keyed profile record, rkey "self"). Same shape as createRecord plus
/// the rkey, so editing the profile overwrites the one record rather than
/// piling up new ones.
pub fn PutRecordInput(comptime Record: type) type {
    return struct {
        repo: []const u8,
        collection: []const u8,
        rkey: []const u8,
        record: Record,
    };
}

/// Response of `com.atproto.identity.resolveHandle`.
/// A7.2: cold struct, size guard waived — transient parse target.
pub const ResolveHandleResponse = struct {
    did: []const u8 = "",
};

// ---------------------------------------------------------------------------
// Phase A exit-criterion tests (STANDALONE_ROADMAP). The schemas round-trip
// (build → serialize → parse → struct) under a leak-checked allocator (C6),
// and the namespace wall is asserted structurally: no content collection or
// owned method may name `app.bsky`. These run on every `zig build test`.
// ---------------------------------------------------------------------------

const std = @import("std");
const testing = std.testing;

/// The encode/decode policy mirrors xrpc.zig exactly (the real wire path):
/// omit null optionals on the way out, ignore unknown fields on the way in.
fn roundTrip(comptime T: type, arena: std.mem.Allocator, value: T) !T {
    const json = try std.json.Stringify.valueAlloc(arena, value, .{ .emit_null_optional_fields = false });
    return std.json.parseFromSliceLeaky(T, arena, json, .{ .ignore_unknown_fields = true });
}

test "wall: every content collection and owned method is app.zat4, never app.bsky" {
    // The structural wall (Phase A). If any of these regresses to app.bsky,
    // Zat4 content would land in Bluesky's universe — the build fails here.
    inline for (.{ collection.post, collection.like, collection.repost, collection.follow, collection.profile }) |nsid| {
        try testing.expect(std.mem.startsWith(u8, nsid, "app.zat4."));
        try testing.expect(std.mem.indexOf(u8, nsid, "app.bsky") == null);
    }
    inline for (.{ method.get_profile, method.get_timeline, method.get_author_feed }) |nsid| {
        try testing.expect(std.mem.startsWith(u8, nsid, "app.zat4."));
    }
    inline for (.{ richtext.facet_link, richtext.facet_mention }) |nsid| {
        try testing.expect(std.mem.startsWith(u8, nsid, "app.zat4.richtext."));
    }
    // Protocol methods are NOT walled — they are shared atproto, and must
    // stay com.atproto so writes/identity keep working across the network.
    try testing.expect(std.mem.startsWith(u8, method.create_record, "com.atproto."));
    try testing.expect(std.mem.startsWith(u8, method.resolve_handle, "com.atproto."));
    try testing.expect(std.mem.startsWith(u8, method.describe_repo, "com.atproto."));
}

test "round-trip: an app.zat4.feed.post survives build → JSON → struct" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator); // C6
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const post: PostRecordOut = .{
        .text = "hello from the zat4 universe",
        .createdAt = "2026-06-14T00:00:00Z",
    };
    const back = try roundTrip(PostRecordOut, arena, post);
    try testing.expectEqualStrings(collection.post, back.@"$type");
    try testing.expectEqualStrings("hello from the zat4 universe", back.text);
    try testing.expectEqualStrings("2026-06-14T00:00:00Z", back.createdAt);
    // The defaulted $type serialized as the zat4 NSID, not app.bsky.
    try testing.expect(std.mem.indexOf(u8, back.@"$type", "app.bsky") == null);
}

test "round-trip: the fresh app.zat4.actor.profile, with null fields omitted" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A profile with only a display name: description stays null and must be
    // omitted from the wire (emit_null_optional_fields = false), then parse
    // back as null — an absent field is an ordinary state (E4).
    const profile: ProfileRecordOut = .{
        .displayName = "Ada",
        .createdAt = "2026-06-14T00:00:00Z",
    };
    const json = try std.json.Stringify.valueAlloc(arena, profile, .{ .emit_null_optional_fields = false });
    try testing.expect(std.mem.indexOf(u8, json, "description") == null); // omitted
    try testing.expect(std.mem.indexOf(u8, json, collection.profile) != null); // $type present
    const back = try std.json.parseFromSliceLeaky(ProfileRecordOut, arena, json, .{ .ignore_unknown_fields = true });
    try testing.expectEqualStrings(collection.profile, back.@"$type");
    try testing.expectEqualStrings("Ada", back.displayName.?);
    try testing.expect(back.description == null);
}

test "round-trip: a post with zat4 facets serializes the owned richtext type" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const facets = [_]Facet{.{
        .index = .{ .byteStart = 0, .byteEnd = 5 },
        .features = &.{.{ .@"$type" = richtext.facet_link, .uri = "https://zat4.app" }},
    }};
    const post: PostRecordOut = .{
        .text = "zat4 link here",
        .createdAt = "2026-06-14T00:00:00Z",
        .facets = &facets,
    };
    const json = try std.json.Stringify.valueAlloc(arena, post, .{ .emit_null_optional_fields = false });
    try testing.expect(std.mem.indexOf(u8, json, "app.zat4.richtext.facet#link") != null);
    try testing.expect(std.mem.indexOf(u8, json, "app.bsky") == null);
}
