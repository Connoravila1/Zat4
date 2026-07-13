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
    // Zat Zones: a zone feed is the posts bearing a tag; the catalog is the set
    // of known tags. Both are plain feed queries (not their own namespace).
    pub const get_posts_for_tag = "app.zat4.feed.getPostsForTag";
    pub const list_tags = "app.zat4.feed.listTags";
    // The algorithm marketplace: browse published feed algorithms.
    pub const get_algorithms = "app.zat4.feed.getAlgorithms";

    // Protocol methods — shared by every atproto app, NOT Bluesky content.
    // These stay exactly as they are (the wall self-check exempts them).
    pub const create_session = "com.atproto.server.createSession";
    pub const create_account = "com.atproto.server.createAccount";
    pub const refresh_session = "com.atproto.server.refreshSession";
    pub const get_session = "com.atproto.server.getSession";
    pub const create_record = "com.atproto.repo.createRecord";
    pub const put_record = "com.atproto.repo.putRecord";
    pub const get_record = "com.atproto.repo.getRecord";
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
    /// A quote-post's embed: a strong ref to the quoted record, carried in a
    /// post's `embed` (the atproto `app.bsky.embed.record` analogue). The quoted
    /// post is hydrated by the AppView into the served view's `embed`.
    pub const embed_record = "app.zat4.embed.record";
    pub const embed_record_view = "app.zat4.embed.record#view";
    pub const follow = "app.zat4.graph.follow";
    /// Fresh Zat4-native profile (Phase A decision 2). Self-contained; an
    /// optional one-time import at enrollment may prefill its fields, but the
    /// record is ours and depends on nothing in app.bsky.
    pub const profile = "app.zat4.actor.profile";
    /// The user's carried lens-socket loadout (SOCKET_LOADOUT_AND_MARKETPLACE
    /// §10). A singleton (rkey "self") in the user's own repo, so it travels
    /// with the account — invariant 12 made literal.
    pub const loadout = "app.zat4.socket.loadout";
    /// A published feed ALGORITHM (DISCOVER D5): a `discover.FeedConfig` serialized
    /// into a record in the author's own repo. Its CID is the algorithm's identity
    /// — what a user inspects is byte-identical to what runs (invariant 5). The
    /// pure serialize/parse is `core/algorithm.zig`; this is just the collection
    /// the publish/import shell leg writes to and fetches from.
    pub const algorithm = "app.zat4.feed.algorithm";
    /// The user's Zat4 MEMBERSHIP (IDENTITY_ENROLLMENT_DESIGN §13.2). A singleton
    /// (rkey "self") in the user's own repo: its mere EXISTENCE marks the DID as a
    /// Zat4 member, which drives the returning-vs-first-time sign-in fork. Carries
    /// the join timestamp, how they joined (new account vs imported DID), and the
    /// load-bearing consent record.
    pub const membership = "app.zat4.actor.membership";
    /// Zat Chat's ONE public record (ZAT_CHAT_ROADMAP U6): the last-resort
    /// keyPackage — the key-directory entry, a singleton (rkey "self").
    /// Messages themselves never enter the repo.
    pub const chat_key_package = "app.zat4.chat.keyPackage";
    /// device — ONE RECORD PER DEVICE (rkey = the device's own id), not a
    /// singleton. That is the whole point: no device can overwrite another's
    /// record, so a phone can no longer take chat away from a desktop simply by
    /// existing (CHAT_MULTIDEVICE slice 0).
    pub const chat_device = "app.zat4.chat.device";
    /// The payment-address directory entry (PART II §3, slice A2): where
    /// this DID accepts Bitcoin — lightning and/or on-chain — anchor-signed
    /// so a PDS can't swap addresses. A singleton (rkey "self"). Payment
    /// MESSAGES ride the E2EE channel and never enter the repo.
    pub const pay_address = "app.zat4.pay.address";
};

/// How a DID became a Zat4 member — a new Zat4 account on our PDS (with a Zat4
/// password) vs an imported existing identity (OAuth, no Zat4 password). Stored as
/// the `via` string on the membership record (§13.3).
pub const membership_via = struct {
    // Not a record: a string-constant namespace (no fields). A1/A7 do not apply.
    pub const created = "created";
    pub const imported = "imported";
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
    // A `#tag` facet: its `tag` value is the word WITHOUT the leading '#'.
    // It is the doorway into a Zat Zone — a tag-scoped slice of the feed.
    pub const facet_tag = "app.zat4.richtext.facet#tag";
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

/// Input for `com.atproto.server.createAccount`. The optional fields are omitted
/// from the wire when null (handle + password are the minimum; the PDS gates on
/// `inviteCode` while invite-only). Recovery-key / DID binding are a later slice.
/// A7.2: cold struct, size guard waived — one per sign-up attempt.
pub const CreateAccountInput = struct {
    handle: []const u8,
    password: []const u8,
    email: ?[]const u8 = null,
    inviteCode: ?[]const u8 = null,
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
    /// Rich-text facets, including `#tag` facets. The AppView reads these on
    /// ingest to route a post into its zones (see `collectTags`); absent ⇒ no
    /// facets. Same wire object as the write side's `PostRecordOut.facets`.
    facets: ?[]const Facet = null,
    /// A quote-post's embed — the strong ref to the quoted record. The AppView
    /// reads this on ingest to record the quote edge and hydrate on serve. Other
    /// embed types (images/external) parse with an empty `record` cid ⇒ no quote.
    embed: ?EmbedRecordIn = null,
    /// Record-level tags (composer tray authoring — tags chosen without
    /// appearing in the prose). Merged with the facet tags on ingest
    /// (`collectTags`); absent on older records (E4).
    tags: ?[]const []const u8 = null,
};

/// The `embed` as read off a fetched/firehose record: only the quoted record
/// ref matters to the AppView. A non-record embed leaves `record.cid` empty.
/// A7.2: cold struct, size guard waived — transient parse target.
pub const EmbedRecordIn = struct {
    record: RecordRef = .{},
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
    /// The post's zone tags (display casing, '#' stripped), derived by the
    /// AppView from the record's `#tag` facets — the post's tray. Each is a
    /// tappable doorway into a zone. Absent/empty ⇒ no tags.
    tags: []const []const u8 = &.{},
    /// A quote-post's HYDRATED embed: the quoted post's author + text + refs,
    /// resolved by the AppView from its own index. Absent ⇒ not a quote (or the
    /// quoted post is unknown to the AppView). One level only — the quoted view
    /// carries no nested embed, bounding recursion.
    embed: ?EmbedView = null,
};

/// The hydrated quoted post inside a quote-post's served view — enough to render
/// the quote card and open its thread. Deliberately lighter than a full PostView
/// (no counts/viewer/embed) so a quote never recurses.
/// A7.2: cold struct, size guard waived — transient parse/build target.
pub const QuotedView = struct {
    uri: []const u8 = "",
    cid: []const u8 = "",
    author: ProfileViewBasic = .{},
    text: []const u8 = "",
    createdAt: []const u8 = "",
};

/// `app.zat4.embed.record#view` — the quoted record, hydrated.
/// A7.2: cold struct, size guard waived — transient parse/build target.
pub const EmbedView = struct {
    record: QuotedView = .{},
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

/// One zone in the catalog: its display tag (canonical lowercase, '#' stripped)
/// plus the community stats that make the catalog read as live places — total
/// posts, distinct posters, posts inside the requester's `since` window, and
/// the newest post's unix-seconds timestamp. The stat fields default to 0 so an
/// older server's flat {tag,count} rows still parse (E4).
/// A7.2: cold struct, size guard waived — transient parse/build target.
pub const TagView = struct {
    tag: []const u8 = "",
    count: usize = 0,
    authors: usize = 0,
    recent: usize = 0,
    lastAt: i64 = 0,
};

/// Response of `app.zat4.feed.listTags`: the known zones (manifest-state and
/// ranking are later phases; this is the flat set).
/// A7.2: cold struct, size guard waived — transient parse/build target.
pub const TagsPage = struct {
    cursor: ?[]const u8 = null,
    tags: []const TagView = &.{},
};

/// One published algorithm in the marketplace browse list: its identity + fetch
/// ref + the PROVEN privacy label the AppView derived from the config itself
/// (never the author's claim — DISCOVER invariant 6). A client fetches the full
/// config with `get_record(author, algorithm, rkey)` to adopt/inspect it.
/// A7.2: cold struct, size guard waived — transient parse/build target.
pub const AlgorithmView = struct {
    cid: []const u8 = "", // record CID — the transparency anchor (invariant 5)
    author: []const u8 = "", // publisher DID
    handle: []const u8 = "", // resolved handle, or "" (client falls back to did)
    rkey: []const u8 = "", // fetch ref
    name: []const u8 = "",
    ranks: []const u8 = "", // author prose (schema rev)
    desc: []const u8 = "",
    tags: []const u8 = "", // joined ", "
    designedFor: []const []const u8 = &.{}, // declared sockets ("feed"/"replies"/"zones")
    usesBehavioral: bool = false, // proven from the config, not claimed
    learns: bool = false,
    stateBudgetBytes: u32 = 0,
};

/// Response of `app.zat4.feed.getAlgorithms`: the published algorithms (the
/// marketplace browse pool). Ranking is a later phase; this is the flat set,
/// newest first.
/// A7.2: cold struct, size guard waived — transient parse/build target.
pub const AlgorithmsPage = struct {
    cursor: ?[]const u8 = null,
    algorithms: []const AlgorithmView = &.{},
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

/// One facet feature: a mention (did set), a link (uri set), or a tag (tag
/// set, the word without its leading '#'). The unset sides are omitted from
/// the wire — the `$type` is the discriminant.
/// A7.2: cold struct, size guard waived — transient build target.
pub const FacetFeature = struct {
    @"$type": []const u8,
    did: ?[]const u8 = null,
    uri: ?[]const u8 = null,
    tag: ?[]const u8 = null,
};

/// `app.zat4.richtext.facet`.
/// A7.2: cold struct, size guard waived — transient build target.
pub const Facet = struct {
    index: ByteSlice,
    features: []const FacetFeature,
};

/// Pull the tag values (the words behind `#tag` facets, '#' already stripped)
/// out of a post's facets PLUS its record-level `tags` array (composer
/// tray-authoring: tags chosen without appearing in the prose) — the doorways
/// into its zones. PURE (B2); the returned slice and its strings borrow
/// `arena`. D3: this is the ONE place the tag wire shapes are read into plain
/// values, so the AppView core (ingest → index) takes a flat
/// `[]const []const u8` and never sees them. Per-post dedup stays downstream
/// (the index already folds casing).
pub fn collectTags(arena: std.mem.Allocator, facets: ?[]const Facet, record_tags: ?[]const []const u8) std.mem.Allocator.Error![]const []const u8 {
    var tags: std.ArrayList([]const u8) = .empty;
    if (facets) |fs| for (fs) |f| {
        for (f.features) |feat| {
            if (!std.mem.eql(u8, feat.@"$type", richtext.facet_tag)) continue;
            const t = feat.tag orelse continue;
            if (t.len > 0) try tags.append(arena, t);
        }
    };
    if (record_tags) |rt| for (rt) |t| {
        if (t.len > 0) try tags.append(arena, t);
    };
    return tags.toOwnedSlice(arena);
}

/// Reply refs on an outgoing post: strong refs to the thread root and the
/// immediate parent.
/// A7.2: cold struct, size guard waived — transient build target.
pub const ReplyRefOut = struct {
    root: RecordRef,
    parent: RecordRef,
};

/// Outgoing quote embed — a strong ref to the quoted record.
/// A7.2: cold struct, size guard waived — transient build target.
pub const EmbedRecordOut = struct {
    @"$type": []const u8 = collection.embed_record,
    record: RecordRef,
};

/// Outgoing `app.zat4.feed.post`.
/// A7.2: cold struct, size guard waived — transient build target.
pub const PostRecordOut = struct {
    @"$type": []const u8 = collection.post,
    text: []const u8,
    createdAt: []const u8,
    reply: ?ReplyRefOut = null,
    facets: ?[]const Facet = null,
    embed: ?EmbedRecordOut = null,
    /// Tags chosen in the composer's tag bar WITHOUT appearing in the prose
    /// (tray authoring — the zone-locked tag and the "+ tag" chips). '#'-less
    /// words, same as a facet's `tag` value. Absent when empty.
    tags: ?[]const []const u8 = null,
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

// ── Membership record (`app.zat4.actor.membership`, rkey "self") ──
// The read shapes are fully defaulted so `GetRecordResponse(MembershipRecord)`
// can parse a present record OR fall back cleanly when none exists (E4); the
// `*Out` shapes are the write forms. See IDENTITY_ENROLLMENT_DESIGN §13.

/// The consent captured at enrollment (read form). A7.2: cold struct, size guard
/// waived — one per membership read, never in a hot loop.
pub const MembershipConsent = struct {
    tosVersion: []const u8 = "",
    agreedAt: []const u8 = "",
    ageConfirmed: bool = false,
};

/// The membership record (read form). A7.2: cold struct, size guard waived — one
/// per sign-in membership check.
pub const MembershipRecord = struct {
    @"$type": []const u8 = collection.membership,
    createdAt: []const u8 = "",
    via: []const u8 = "",
    consent: MembershipConsent = .{},
};

/// The consent captured at enrollment (write form). A7.2: cold struct, size guard
/// waived — one per enrollment write.
pub const MembershipConsentOut = struct {
    tosVersion: []const u8,
    agreedAt: []const u8,
    ageConfirmed: bool,
};

/// The membership record (write form). A7.2: cold struct, size guard waived — one
/// per enrollment write.
pub const MembershipRecordOut = struct {
    @"$type": []const u8 = collection.membership,
    createdAt: []const u8,
    via: []const u8,
    consent: MembershipConsentOut,
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

// ── The lens-socket loadout record (app.zat4.socket.loadout, rkey "self").
// Phase 1b persists the FEED loadout (order + per-lens color + seated). The
// reply/zone surfaces and the marketplace `library` join the record when
// those exist (SOCKET_LOADOUT_AND_MARKETPLACE §10). Two type families per
// the codebase convention: `*Out` for the write (no defaults — every field
// is set), the bare names for the read parse (all defaulted — absent fields
// degrade to an empty/default loadout, E4). A7.2: cold parse/build targets.

/// One seated lens on a surface: a ref to the algorithm + the user's color.
// A7.2: cold build target, size guard waived.
pub const LoadoutLensOut = struct {
    algo: []const u8, // the algorithm ref (a built-in id today; a strong-ref uri later)
    color: u8,
};
// A7.2: cold build target, size guard waived.
pub const LoadoutSurfaceOut = struct {
    lenses: []const LoadoutLensOut,
    seated: u32,
};
// A7.2: cold build target, size guard waived.
pub const LoadoutRecordOut = struct {
    @"$type": []const u8 = collection.loadout,
    feed: LoadoutSurfaceOut,
    reply: LoadoutSurfaceOut,
    zone: LoadoutSurfaceOut,
    createdAt: []const u8,
};

// A7.2: cold parse target, size guard waived.
pub const LoadoutLens = struct {
    algo: []const u8 = "",
    color: u8 = 0,
};
// A7.2: cold parse target, size guard waived.
pub const LoadoutSurface = struct {
    lenses: []const LoadoutLens = &.{},
    seated: u32 = 0,
};
// A7.2: cold parse target, size guard waived.
pub const LoadoutRecord = struct {
    feed: LoadoutSurface = .{},
    reply: LoadoutSurface = .{},
    zone: LoadoutSurface = .{},
    createdAt: []const u8 = "",
};

/// `com.atproto.repo.getRecord` response envelope over a record value type.
pub fn GetRecordResponse(comptime Record: type) type {
    return struct {
        uri: []const u8 = "",
        cid: []const u8 = "",
        value: Record = .{},
    };
}

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
    inline for (.{ method.get_profile, method.get_timeline, method.get_author_feed, method.get_posts_for_tag, method.list_tags, method.get_algorithms }) |nsid| {
        try testing.expect(std.mem.startsWith(u8, nsid, "app.zat4."));
    }
    inline for (.{ richtext.facet_link, richtext.facet_mention, richtext.facet_tag }) |nsid| {
        try testing.expect(std.mem.startsWith(u8, nsid, "app.zat4.richtext."));
    }
    // Protocol methods are NOT walled — they are shared atproto, and must
    // stay com.atproto so writes/identity keep working across the network.
    try testing.expect(std.mem.startsWith(u8, method.create_record, "com.atproto."));
    try testing.expect(std.mem.startsWith(u8, method.resolve_handle, "com.atproto."));
    try testing.expect(std.mem.startsWith(u8, method.describe_repo, "com.atproto."));
}

test "round-trip: a loadout record (write type → JSON → read type) preserves order, colors, seated" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator); // C6
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const lenses = [_]LoadoutLensOut{
        .{ .algo = "zat4:discover", .color = 0 },
        .{ .algo = "zat4:following", .color = 5 }, // user recolored
        .{ .algo = "zat4:private-discover", .color = 1 },
    };
    const reply_lenses = [_]LoadoutLensOut{.{ .algo = "zat4:most-recent", .color = 2 }};
    const out = LoadoutRecordOut{
        .feed = .{ .lenses = &lenses, .seated = 2 },
        .reply = .{ .lenses = &reply_lenses, .seated = 0 },
        .zone = .{ .lenses = &.{}, .seated = 0 },
        .createdAt = "2026-06-22T09:00:00Z",
    };
    // Serialize the WRITE type, parse back as the READ type (the real wire path).
    const json = try std.json.Stringify.valueAlloc(arena, out, .{ .emit_null_optional_fields = false });
    const back = try std.json.parseFromSliceLeaky(LoadoutRecord, arena, json, .{ .ignore_unknown_fields = true });
    try testing.expectEqual(@as(usize, 3), back.feed.lenses.len);
    try testing.expectEqual(@as(u32, 2), back.feed.seated);
    try testing.expectEqual(@as(usize, 1), back.reply.lenses.len);
    try testing.expectEqualStrings("zat4:most-recent", back.reply.lenses[0].algo);
    try testing.expectEqual(@as(usize, 0), back.zone.lenses.len);
    try testing.expectEqualStrings("zat4:following", back.feed.lenses[1].algo);
    try testing.expectEqual(@as(u8, 5), back.feed.lenses[1].color);
    // The $type discriminator rides the wire.
    try testing.expect(std.mem.indexOf(u8, json, "app.zat4.socket.loadout") != null);
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

test "round-trip: a post with a tag facet serializes the owned tag type, tag without '#'" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // "love #water" — the tag span is bytes 5..11 ("#water"); the facet's
    // `tag` value carries the word with the '#' stripped.
    const facets = [_]Facet{.{
        .index = .{ .byteStart = 5, .byteEnd = 11 },
        .features = &.{.{ .@"$type" = richtext.facet_tag, .tag = "water" }},
    }};
    const post: PostRecordOut = .{
        .text = "love #water",
        .createdAt = "2026-06-28T00:00:00Z",
        .facets = &facets,
    };
    const json = try std.json.Stringify.valueAlloc(arena, post, .{ .emit_null_optional_fields = false });
    try testing.expect(std.mem.indexOf(u8, json, "app.zat4.richtext.facet#tag") != null);
    try testing.expect(std.mem.indexOf(u8, json, "\"tag\":\"water\"") != null);
    // The unset mention/link sides stay off the wire; no Bluesky namespace leaks.
    try testing.expect(std.mem.indexOf(u8, json, "\"did\"") == null);
    try testing.expect(std.mem.indexOf(u8, json, "\"uri\"") == null);
    try testing.expect(std.mem.indexOf(u8, json, "app.bsky") == null);
}

test "collectTags: pulls only #tag facet values, skips mentions and links" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const facets = [_]Facet{
        .{ .index = .{ .byteStart = 0, .byteEnd = 6 }, .features = &.{.{ .@"$type" = richtext.facet_tag, .tag = "water" }} },
        .{ .index = .{ .byteStart = 7, .byteEnd = 18 }, .features = &.{.{ .@"$type" = richtext.facet_mention, .did = "did:plc:x" }} },
        .{ .index = .{ .byteStart = 19, .byteEnd = 30 }, .features = &.{.{ .@"$type" = richtext.facet_tag, .tag = "rivers" }} },
    };
    const tags = try collectTags(arena, &facets, null);
    try testing.expectEqual(@as(usize, 2), tags.len);
    try testing.expectEqualStrings("water", tags[0]);
    try testing.expectEqualStrings("rivers", tags[1]);

    // Record-level tags (tray authoring) join after the facet tags.
    const both = try collectTags(arena, &facets, &.{ "deep", "" });
    try testing.expectEqual(@as(usize, 3), both.len); // the empty one is skipped
    try testing.expectEqualStrings("deep", both[2]);

    // No tags at all is an empty list, not an error (E4).
    try testing.expectEqual(@as(usize, 0), (try collectTags(arena, null, null)).len);
}
