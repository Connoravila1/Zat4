//! B1 classification: CORE (pure data). Lexicon wire shapes.
//!
//! Plain-data record types (A1: fields only, behavior nowhere near them)
//! mirroring the atproto/Bluesky lexicon JSON this client actually consumes
//! — nothing more (start narrow; expand on demand). Field names match the
//! wire camelCase exactly: that is what lets std.json map them with zero
//! glue code (F2 — comptime reflection instead of generated codecs). Wire
//! fidelity deliberately wins over Zig naming style inside this file.
//!
//! Every field that the lexicon marks optional defaults here, so a document
//! missing it still parses: lexicons evolve, and an absent field is an
//! ordinary state, not an error (E4). Unknown fields are ignored at the
//! decode site for the same reason.
//!
//! A7 stance, recorded for review: these structs are TRANSIENT PARSE
//! TARGETS — one per response, slice-heavy, arena-bound, decomposed
//! immediately. They are not the bulk-resident records. When Phase 4
//! flattens responses into resident SoA collections (A3), THOSE record
//! types (spans + u32 indexes, no slices) carry the exact-size guards.
//! Hardening at that point, and not before, is F5 applied on purpose.
//! Each struct below claims its A7.2 waiver individually.

/// XRPC method NSIDs live beside the shapes they return, so a lexicon
/// change lands in exactly one file (D6).
pub const method = struct {
    // Not a record: a string-constant namespace (no fields). A1/A7 do not apply.
    pub const get_profile = "app.bsky.actor.getProfile";
    pub const create_session = "com.atproto.server.createSession";
    pub const refresh_session = "com.atproto.server.refreshSession";
    pub const get_session = "com.atproto.server.getSession";
    pub const get_timeline = "app.bsky.feed.getTimeline";
    pub const create_record = "com.atproto.repo.createRecord";
    pub const delete_record = "com.atproto.repo.deleteRecord";
    pub const resolve_handle = "com.atproto.identity.resolveHandle";
};

/// Record collections this client writes into.
pub const collection = struct {
    // Not a record: an extern-fn namespace (no fields). A1/A7 do not apply.

    pub const post = "app.bsky.feed.post";
    pub const like = "app.bsky.feed.like";
    pub const repost = "app.bsky.feed.repost";
    pub const follow = "app.bsky.graph.follow";
};

/// Subset of `app.bsky.actor.defs#profileViewDetailed` we consume.
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
// Feed wire shapes (`app.bsky.feed.getTimeline`). Same A7.2 stance as the
// header: transient parse targets; the RESIDENT records with size guards
// live in core/feed.zig. Wire unions (reply refs that may be notFound /
// blocked, reasons that may be pins) are handled by defaulting: a variant
// whose fields are absent parses to empty strings, and ingest treats an
// empty cid/did as "not there" (E4 — absence is an ordinary state).
// ---------------------------------------------------------------------------

/// Subset of `app.bsky.actor.defs#profileViewBasic`.
/// A7.2: cold struct, size guard waived — transient parse target.
pub const ProfileViewBasic = struct {
    did: []const u8 = "",
    handle: []const u8 = "",
    displayName: ?[]const u8 = null,
    avatar: ?[]const u8 = null,
};

/// The original `app.bsky.feed.post` record carried inside a PostView.
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

/// Subset of `app.bsky.feed.defs#postView`. Reply parents/roots arrive as
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

/// `app.bsky.feed.defs#replyRef` — root and parent, hydrated.
/// A7.2: cold struct, size guard waived — transient parse target.
pub const ReplyRef = struct {
    root: PostView = .{},
    parent: PostView = .{},
};

/// `app.bsky.feed.defs#reasonRepost`; a reasonPin parses to an empty `by`.
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

/// Response of `app.bsky.feed.getTimeline`.
/// A7.2: cold struct, size guard waived — transient parse target.
pub const TimelinePage = struct {
    cursor: ?[]const u8 = null,
    feed: []const FeedViewPost = &.{},
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

/// `app.bsky.richtext.facet#byteSlice` — UTF-8 byte offsets into the text.
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

/// `app.bsky.richtext.facet`.
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

/// Outgoing `app.bsky.feed.post`.
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

/// Outgoing `app.bsky.graph.follow`.
/// A7.2: cold struct, size guard waived — transient build target.
pub const FollowRecordOut = struct {
    @"$type": []const u8 = collection.follow,
    subject: []const u8, // the did being followed
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

/// Response of `com.atproto.identity.resolveHandle`.
/// A7.2: cold struct, size guard waived — transient parse target.
pub const ResolveHandleResponse = struct {
    did: []const u8 = "",
};
