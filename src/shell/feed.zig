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

//! B1 classification: SHELL. The **feed deep module's** fetch choreography.
//!
//! The feed module spans two files: src/core/feed.zig — the resident store
//! and every pure transform (that is the module's face toward consumers of
//! DATA: main today, the renderer in Phase 5) — and this one, the only part
//! that touches the network (B3). It does exactly three things: read the
//! store's cursor, make the authenticated getTimeline call through the auth
//! module, and hand the wire page to the pure ingest. Kept deliberately
//! thin: every decision of substance (layout, dedup, linkage, view-models)
//! lives in the core.

const std = @import("std");
const Allocator = std.mem.Allocator;
const auth = @import("auth.zig");
const xrpc = @import("xrpc.zig");
const feed_core = @import("../core/feed.zig");
const lexicon = @import("../core/lexicon.zig");

/// One page load resolves to ingest stats or the server's refusal — the
/// same value-not-error stance as everywhere else (E4).
/// A7.2: cold union, size guard waived — one page-load result, returned and matched.
pub const PageOutcome = union(enum) {
    ok: feed_core.IngestStats,
    failed: xrpc.Failure,
};

/// Load the next timeline page into the store: first call fetches the top
/// of the feed; subsequent calls continue from the stored cursor until the
/// server stops returning one (`nextCursor(store).len == 0`).
///
/// `gpa` owns the store's memory (and pays for token rotation inside auth);
/// `arena` is the caller's per-request arena for everything transient (C3).
pub fn loadTimelinePage(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    appview_url: []const u8,
    store: *feed_core.Store,
    limit: u32,
) !PageOutcome {
    var limit_buf: [12]u8 = undefined;
    const limit_str = std.fmt.bufPrint(&limit_buf, "{d}", .{limit}) catch unreachable;

    // The cursor slice borrows the store's bytes; it is consumed (URL built,
    // request sent) before ingest can mutate the store — sequence-safe.
    var params_buf: [3]xrpc.Param = undefined;
    var params_len: usize = 0;
    params_buf[params_len] = .{ .name = "limit", .value = limit_str };
    params_len += 1;
    // The Zat4 AppView (Cut 1) builds the timeline from the viewer's follow set
    // and takes the viewer DID as a query param (token-derived identity is a
    // Phase E hardening seat — appview_serve.zig). Send it, or the feed is empty.
    params_buf[params_len] = .{ .name = "viewer", .value = session.did };
    params_len += 1;
    const cursor = feed_core.nextCursor(store);
    if (cursor.len > 0) {
        params_buf[params_len] = .{ .name = "cursor", .value = cursor };
        params_len += 1;
    }

    const outcome = try auth.queryHost(
        gpa,
        arena,
        io,
        environ,
        session,
        appview_url,
        lexicon.method.get_timeline,
        params_buf[0..params_len],
        lexicon.TimelinePage,
    );
    switch (outcome) {
        .failed => |failure| return .{ .failed = failure },
        .ok => |page| return .{ .ok = try feed_core.ingestPage(gpa, store, page) },
    }
}

/// Fetch the NEWEST page (no cursor) and prepend its unseen rows: the
/// "look up" half of the feed. `loadTimelinePage` remains the "walk down"
/// half; the pagination cursor is untouched by design, so refreshing
/// never derails paging.
pub fn refreshTimeline(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    appview_url: []const u8,
    store: *feed_core.Store,
    limit: u32,
) !PageOutcome {
    const outcome = try fetchRefreshPage(gpa, arena, io, environ, session, appview_url, limit);
    switch (outcome) {
        .failed => |failure| return .{ .failed = failure },
        .ok => |page| return .{ .ok = try feed_core.ingestPageRefresh(gpa, store, page) },
    }
}

/// The NETWORK half of `refreshTimeline`, alone: fetch the newest page and
/// return it as a value, touching no store. The refresh worker calls this off
/// the render thread (the fetch is a blocking round trip — the render loop
/// must never wait on it) and hands the page back through its mailbox; the
/// ingest half then runs on the UI thread, which owns the store. Wire/lexicon
/// knowledge stays in this module (D3) — the worker only moves values.
pub fn fetchRefreshPage(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    appview_url: []const u8,
    limit: u32,
) !xrpc.Outcome(lexicon.TimelinePage) {
    var limit_buf: [12]u8 = undefined;
    const limit_str = std.fmt.bufPrint(&limit_buf, "{d}", .{limit}) catch unreachable;
    // viewer DID: the Cut-1 AppView builds the feed from it (see loadTimelinePage).
    const params = [_]xrpc.Param{
        .{ .name = "limit", .value = limit_str },
        .{ .name = "viewer", .value = session.did },
    };

    return auth.queryHost(
        gpa,
        arena,
        io,
        environ,
        session,
        appview_url,
        lexicon.method.get_timeline,
        &params,
        lexicon.TimelinePage,
    );
}

/// The NETWORK half of `loadTimelinePage`, alone: fetch the page after
/// `cursor` and return it as a value, touching no store — the "walk down"
/// counterpart of `fetchRefreshPage`, for the same reason (the frame
/// thread must never wait on the round trip; M_CORE_INVERSION). The caller
/// copies the cursor out of the store BEFORE submitting — the worker never
/// reads the store. An empty cursor fetches the newest page (first load).
pub fn fetchOlderPage(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    appview_url: []const u8,
    cursor: []const u8,
    limit: u32,
) !xrpc.Outcome(lexicon.TimelinePage) {
    var limit_buf: [12]u8 = undefined;
    const limit_str = std.fmt.bufPrint(&limit_buf, "{d}", .{limit}) catch unreachable;
    var params_buf: [3]xrpc.Param = undefined;
    var params_len: usize = 0;
    params_buf[params_len] = .{ .name = "limit", .value = limit_str };
    params_len += 1;
    // viewer DID: the Cut-1 AppView builds the feed from it (see loadTimelinePage).
    params_buf[params_len] = .{ .name = "viewer", .value = session.did };
    params_len += 1;
    if (cursor.len > 0) {
        params_buf[params_len] = .{ .name = "cursor", .value = cursor };
        params_len += 1;
    }
    return auth.queryHost(
        gpa,
        arena,
        io,
        environ,
        session,
        appview_url,
        lexicon.method.get_timeline,
        params_buf[0..params_len],
        lexicon.TimelinePage,
    );
}

/// The NETWORK half of the profile screen's load, alone: fetch one author's
/// posts (getAuthorFeed) and return the page as a value, touching no store —
/// the view worker calls this off the frame thread (the round trip must
/// never block a frame; M_CORE_INVERSION MC.3) and the UI ingests the
/// drained page as CONTENT (`feed_core.ingestPosts`, no Home feed-ordering
/// rows). The view's ORDERING stays a pure query over the shared store
/// (`feed_core.buildAuthorView`), so a post is one record seen through many
/// lenses (ZONES invariant 4): engagement and identity stay unified across
/// Home, profile, and zones. `actor` is whose feed; the viewer DID (session)
/// is sent so the AppView stamps each row's viewer.like.
pub fn fetchAuthorPage(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    appview_url: []const u8,
    actor: []const u8,
    limit: u32,
) !xrpc.Outcome(lexicon.TimelinePage) {
    var limit_buf: [12]u8 = undefined;
    const limit_str = std.fmt.bufPrint(&limit_buf, "{d}", .{limit}) catch unreachable;
    const params = [_]xrpc.Param{
        .{ .name = "actor", .value = actor },
        .{ .name = "viewer", .value = session.did },
        .{ .name = "limit", .value = limit_str },
    };

    return auth.queryHost(
        gpa,
        arena,
        io,
        environ,
        session,
        appview_url,
        lexicon.method.get_author_feed,
        &params,
        lexicon.TimelinePage,
    );
}

/// The NETWORK half of the thread screen's load, alone: fetch a post's
/// thread (`getPostThread?uri=&viewer=`) — ancestors, the focused post, and
/// its replies, arriving flat — and return it as a value, touching no store
/// (the view worker calls this off the frame thread; M_CORE_INVERSION MC.3).
/// The UI ingests the drained posts as CONTENT; the thread VIEW is then a
/// pure query (`feed_core.buildThreadView`), so engagement + identity stay
/// unified with every other view (ZONES inv. 4). The reply linkage rides on
/// each post's `reply` ref, so the store reconstructs the chain. `uri` is
/// the focused post's at-uri (as the feed served it).
pub fn fetchThreadPage(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    appview_url: []const u8,
    uri: []const u8,
    limit: u32,
) !xrpc.Outcome(lexicon.ThreadView) {
    var limit_buf: [12]u8 = undefined;
    const limit_str = std.fmt.bufPrint(&limit_buf, "{d}", .{limit}) catch unreachable;
    const params = [_]xrpc.Param{
        .{ .name = "uri", .value = uri },
        .{ .name = "viewer", .value = session.did },
        .{ .name = "limit", .value = limit_str },
    };

    return auth.queryHost(
        gpa,
        arena,
        io,
        environ,
        session,
        appview_url,
        lexicon.method.get_post_thread,
        &params,
        lexicon.ThreadView,
    );
}

/// The NETWORK half of the zone screen's load, alone: fetch a ZONE's feed
/// (`getPostsForTag?tag=&viewer=`) and return the page as a value, touching
/// no store (the view worker calls this off the frame thread;
/// M_CORE_INVERSION MC.3). The UI ingests the drained posts as CONTENT; the
/// zone VIEW is then a pure query (`feed_core.buildTagView`), so engagement
/// + identity stay unified with every other view (ZONES inv. 4). The server
/// normalizes the tag, so the display-form `tag` the user tapped resolves
/// to the same zone (invariant 1).
pub fn fetchZonePage(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    appview_url: []const u8,
    tag: []const u8,
    limit: u32,
) !xrpc.Outcome(lexicon.TimelinePage) {
    var limit_buf: [12]u8 = undefined;
    const limit_str = std.fmt.bufPrint(&limit_buf, "{d}", .{limit}) catch unreachable;
    const params = [_]xrpc.Param{
        .{ .name = "tag", .value = tag },
        .{ .name = "viewer", .value = session.did },
        .{ .name = "limit", .value = limit_str },
    };

    return auth.queryHost(
        gpa,
        arena,
        io,
        environ,
        session,
        appview_url,
        lexicon.method.get_posts_for_tag,
        &params,
        lexicon.TimelinePage,
    );
}

/// The result of a zone-catalog fetch: the known zones (display tag + post
/// count) on success, a contained failure otherwise. The `tags` slice is
/// allocated in the caller's `arena` (the caller copies what it keeps).
/// A7.2: cold union, size guard waived — one catalog-load result, matched once.
pub const ZonesOutcome = union(enum) {
    ok: []const lexicon.TagView,
    failed: xrpc.Failure,
};

/// Fetch the zone CATALOG (`listTags`) — the flat set of known zones with their
/// post counts. This is metadata, NOT posts, so it does not touch the store; the
/// caller copies the entries it keeps into its own catalog (the browse screen).
/// Ranking / manifest-state are later phases (Z3/Z7); this is the latent set.
pub fn loadZones(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    appview_url: []const u8,
) !ZonesOutcome {
    const outcome = try auth.queryHost(
        gpa,
        arena,
        io,
        environ,
        session,
        appview_url,
        lexicon.method.list_tags,
        &.{},
        lexicon.TagsPage,
    );
    switch (outcome) {
        .failed => |failure| return .{ .failed = failure },
        .ok => |page| return .{ .ok = page.tags },
    }
}

/// The marketplace-browse result: the published algorithms (metadata + fetch
/// refs + proven privacy labels) on success, a contained failure otherwise. The
/// `algorithms` slice is allocated in the caller's `arena`. A7.2: cold union,
/// size guard waived — one browse-load result, matched once.
pub const AlgorithmsOutcome = union(enum) {
    ok: []const lexicon.AlgorithmView,
    failed: xrpc.Failure,
};

/// Fetch the algorithm MARKETPLACE (`getAlgorithms`) — the flat set of published
/// feed algorithms, newest first. Metadata + fetch refs, NOT configs: the caller
/// fetches a chosen algorithm's full config by (author, rkey) via
/// `shell/algorithm.fetch` when it adopts one. Ranking is a later phase.
pub fn loadAlgorithms(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    appview_url: []const u8,
    limit: usize,
) !AlgorithmsOutcome {
    var limit_buf: [20]u8 = undefined;
    const params = [_]xrpc.Param{
        .{ .name = "limit", .value = std.fmt.bufPrint(&limit_buf, "{d}", .{limit}) catch "50" },
    };
    const outcome = try auth.queryHost(
        gpa,
        arena,
        io,
        environ,
        session,
        appview_url,
        lexicon.method.get_algorithms,
        &params,
        lexicon.AlgorithmsPage,
    );
    switch (outcome) {
        .failed => |failure| return .{ .failed = failure },
        .ok => |page| return .{ .ok = page.algorithms },
    }
}

test "loadAlgorithms stays type-correct (browse leg, not yet UI-wired)" {
    // No live AppView here — force the browse function through analysis so a
    // signature drift fails the build rather than surprising the marketplace UI.
    _ = &loadAlgorithms;
}

// ---------------------------------------------------------------------------
// Loopback round trip — a scripted fixture PDS serves two timeline pages;
// the second request must carry the first page's cursor on the wire, and a
// post repeated across pages must be stored once (A8 across pages).
// ---------------------------------------------------------------------------

const fixture = @import("test_fixture.zig");
const ScriptStep = fixture.ScriptStep;
const serveScript = fixture.serveScript;
const listenLoopback = fixture.listenLoopback;

const page_one_body =
    \\{"cursor":"CURSOR-1","feed":[
    \\ {"post":{"uri":"at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/app.zat4.feed.post/1",
    \\          "cid":"bafyreialice1",
    \\          "author":{"did":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","handle":"alice.test","displayName":"Alice"},
    \\          "record":{"$type":"app.zat4.feed.post","text":"first post","createdAt":"2026-01-02T03:04:05Z"},
    \\          "likeCount":3,"replyCount":0,"repostCount":0,"quoteCount":0}},
    \\ {"post":{"uri":"at://did:plc:bbbbbbbbbbbbbbbbbbbbbbbb/app.zat4.feed.post/1",
    \\          "cid":"bafyreibob1",
    \\          "author":{"did":"did:plc:bbbbbbbbbbbbbbbbbbbbbbbb","handle":"bob.test"},
    \\          "record":{"$type":"app.zat4.feed.post","text":"hello","createdAt":"2026-01-02T04:00:00Z"},
    \\          "likeCount":1,"replyCount":0,"repostCount":0,"quoteCount":0}}
    \\]}
;

// Page two repeats alice's post (already resident) and ends the feed.
const page_two_body =
    \\{"feed":[
    \\ {"post":{"uri":"at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/app.zat4.feed.post/1",
    \\          "cid":"bafyreialice1",
    \\          "author":{"did":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","handle":"alice.test","displayName":"Alice"},
    \\          "record":{"$type":"app.zat4.feed.post","text":"first post","createdAt":"2026-01-02T03:04:05Z"},
    \\          "likeCount":3,"replyCount":0,"repostCount":0,"quoteCount":0}}
    \\]}
;

test "loopback round trip: paginated timeline load, cursor on the wire, cross-page dedup" {
    const gpa = std.testing.allocator; // C6
    const io = std.testing.io;

    var bound = try listenLoopback(io, 38720);
    defer bound.server.deinit(io);
    const thread = try std.Thread.spawn(.{}, serveScript, .{
        &bound.server, io,
        &[_]ScriptStep{
            .{
                .must_contain_head = "GET /xrpc/app.zat4.feed.getTimeline?limit=2",
                .must_contain_head_b = "authorization: Bearer access-1",
                .status = .ok,
                .body = page_one_body,
            },
            .{
                // The second request must carry the first page's cursor.
                .must_contain_head = "cursor=CURSOR-1",
                .must_contain_head_b = "authorization: Bearer access-1",
                .status = .ok,
                .body = page_two_body,
            },
        },
    });
    defer thread.join();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var url_buf: [48]u8 = undefined;
    const pds = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}", .{bound.port});
    var session = auth.Session{
        .did = "did:plc:cccccccccccccccccccccccc",
        .handle = "carol.test",
        .pds_url = pds,
        .access_jwt = "access-1",
        .refresh_jwt = "refresh-1",
    };

    var store: feed_core.Store = .{};
    defer feed_core.deinitStore(gpa, &store);

    const first = try loadTimelinePage(gpa, arena, io, null, &session, pds, &store, 2);
    try std.testing.expectEqual(@as(u32, 2), first.ok.posts_added);
    try std.testing.expectEqualStrings("CURSOR-1", feed_core.nextCursor(&store));

    const second = try loadTimelinePage(gpa, arena, io, null, &session, pds, &store, 2);
    try std.testing.expectEqual(@as(u32, 0), second.ok.posts_added);
    try std.testing.expectEqual(@as(u32, 1), second.ok.posts_deduped); // A8 across pages
    try std.testing.expectEqualStrings("", feed_core.nextCursor(&store)); // feed exhausted

    try std.testing.expectEqual(@as(usize, 2), store.posts.len);
    try std.testing.expectEqual(@as(usize, 3), store.feed.len);

    const items = try feed_core.buildTimeline(arena, &store);
    try std.testing.expectEqual(@as(usize, 3), items.len);
    try std.testing.expectEqualStrings("alice.test", items[0].author_handle);
    try std.testing.expectEqualStrings("first post", items[2].text);
}

// A refresh page: one genuinely new post on top, then an already-seen row.
const refresh_body =
    \\{"cursor":"MUST-NOT-REPLACE","feed":[
    \\ {"post":{"uri":"at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/app.zat4.feed.post/9",
    \\          "cid":"bafyreinewest",
    \\          "author":{"did":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","handle":"alice.test","displayName":"Alice"},
    \\          "record":{"$type":"app.zat4.feed.post","text":"the newest one","createdAt":"2026-01-03T00:00:00Z"},
    \\          "likeCount":0,"replyCount":0,"repostCount":0,"quoteCount":0}},
    \\ {"post":{"uri":"at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/app.zat4.feed.post/1",
    \\          "cid":"bafyreialice1",
    \\          "author":{"did":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","handle":"alice.test","displayName":"Alice"},
    \\          "record":{"$type":"app.zat4.feed.post","text":"first post","createdAt":"2026-01-02T03:04:05Z"},
    \\          "likeCount":3,"replyCount":0,"repostCount":0,"quoteCount":0}}
    \\]}
;

test "loopback refresh: new rows land on top, the pagination cursor survives" {
    const gpa = std.testing.allocator; // C6
    const io = std.testing.io;

    var bound = try listenLoopback(io, 38732);
    defer bound.server.deinit(io);
    const thread = try std.Thread.spawn(.{}, serveScript, .{
        &bound.server, io,
        &[_]ScriptStep{
            .{ .must_contain_head = "getTimeline", .status = .ok, .body = page_one_body },
            .{ .must_contain_head = "getTimeline", .status = .ok, .body = refresh_body },
        },
    });
    defer thread.join();

    var url_buf: [40]u8 = undefined;
    const pds = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}", .{bound.port});
    var session = auth.Session{
        .did = "did:plc:cccccccccccccccccccccccc",
        .handle = "carol.test",
        .pds_url = pds,
        .access_jwt = "access-1",
        .refresh_jwt = "refresh-1",
    };
    var store: feed_core.Store = .{};
    defer feed_core.deinitStore(gpa, &store);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    const first = try loadTimelinePage(gpa, arena_state.allocator(), io, null, &session, pds, &store, 30);
    try std.testing.expect(first == .ok);
    _ = arena_state.reset(.retain_capacity);

    const refreshed = try refreshTimeline(gpa, arena_state.allocator(), io, null, &session, pds, &store, 30);
    switch (refreshed) {
        .failed => return error.TestUnexpectedXrpcFailure,
        .ok => |stats| try std.testing.expectEqual(@as(u32, 1), stats.items_added),
    }
    try std.testing.expectEqualStrings("CURSOR-1", feed_core.nextCursor(&store));

    // A passive refresh STAGES the new post behind the pill (no displacement);
    // reveal it (as the pill tap / at-top auto-reveal does) before it's in the feed.
    try std.testing.expectEqual(@as(usize, 1), feed_core.pendingCount(&store));
    _ = try feed_core.revealPending(gpa, &store);

    _ = arena_state.reset(.retain_capacity);
    const items = try feed_core.buildTimeline(arena_state.allocator(), &store);
    try std.testing.expectEqualStrings("the newest one", items[0].text);
}

// An author feed page — one author's posts (the profile body shape).
const author_feed_body =
    \\{"feed":[
    \\ {"post":{"uri":"at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/app.zat4.feed.post/2",
    \\          "cid":"bafyreialice2",
    \\          "author":{"did":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","handle":"alice.test","displayName":"Alice"},
    \\          "record":{"$type":"app.zat4.feed.post","text":"my newest","createdAt":"2026-01-04T00:00:00Z"},
    \\          "likeCount":2,"replyCount":0,"repostCount":0,"quoteCount":0}},
    \\ {"post":{"uri":"at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/app.zat4.feed.post/1",
    \\          "cid":"bafyreialice1",
    \\          "author":{"did":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","handle":"alice.test","displayName":"Alice"},
    \\          "record":{"$type":"app.zat4.feed.post","text":"my first","createdAt":"2026-01-02T03:04:05Z"},
    \\          "likeCount":3,"replyCount":0,"repostCount":0,"quoteCount":0}}
    \\]}
;

test "loopback author feed: the actor + viewer ride the wire; posts land in the store" {
    const gpa = std.testing.allocator; // C6
    const io = std.testing.io;

    var bound = try listenLoopback(io, 38744);
    defer bound.server.deinit(io);
    const thread = try std.Thread.spawn(.{}, serveScript, .{
        &bound.server, io,
        &[_]ScriptStep{
            .{
                .must_contain_head = "GET /xrpc/app.zat4.feed.getAuthorFeed?actor=did",
                .must_contain_head_b = "viewer=did",
                .status = .ok,
                .body = author_feed_body,
            },
        },
    });
    defer thread.join();

    var url_buf: [40]u8 = undefined;
    const pds = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}", .{bound.port});
    var session = auth.Session{
        .did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
        .handle = "alice.test",
        .pds_url = pds,
        .access_jwt = "access-1",
        .refresh_jwt = "refresh-1",
    };
    var store: feed_core.Store = .{};
    defer feed_core.deinitStore(gpa, &store);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    // Fetch + ingest as the live path runs them: the network half on the
    // view worker's thread, the ingest half on the store-owning UI thread.
    const outcome = try fetchAuthorPage(gpa, arena_state.allocator(), io, null, &session, pds, session.did, 30);
    switch (outcome) {
        .failed => return error.TestUnexpectedXrpcFailure,
        .ok => |page| {
            const stats = try feed_core.ingestPosts(gpa, &store, page);
            try std.testing.expectEqual(@as(u32, 2), stats.posts_added);
        },
    }

    // Content-only ingest: no Home feed-ordering rows; the profile VIEW is a
    // query over the shared store.
    try std.testing.expectEqual(@as(usize, 0), store.feed.len);
    const items = try feed_core.buildAuthorView(arena_state.allocator(), &store, session.did);
    try std.testing.expectEqual(@as(usize, 2), items.len);
    try std.testing.expectEqualStrings("my newest", items[0].text);
}
