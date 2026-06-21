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
    var limit_buf: [12]u8 = undefined;
    const limit_str = std.fmt.bufPrint(&limit_buf, "{d}", .{limit}) catch unreachable;
    // viewer DID: the Cut-1 AppView builds the feed from it (see loadTimelinePage).
    const params = [_]xrpc.Param{
        .{ .name = "limit", .value = limit_str },
        .{ .name = "viewer", .value = session.did },
    };

    const outcome = try auth.queryHost(
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
    switch (outcome) {
        .failed => |failure| return .{ .failed = failure },
        .ok => |page| return .{ .ok = try feed_core.ingestPageRefresh(gpa, store, page) },
    }
}

/// Load one author's posts into the SHARED `store` as CONTENT (no Home
/// feed-ordering rows) — the profile screen's body. The view's ORDERING is
/// derived by `feed_core.buildAuthorView` as a query over the store, so a post
/// is one record seen through many lenses (ZONES invariant 4): engagement and
/// identity stay unified across Home, profile, and future zones. Same thin
/// shape as `loadTimelinePage`: the only network seam is the authenticated
/// getAuthorFeed call. `actor` is whose feed; the viewer DID (session) is sent
/// so the AppView stamps each row's viewer.like.
pub fn loadAuthorFeed(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    appview_url: []const u8,
    store: *feed_core.Store,
    actor: []const u8,
    limit: u32,
) !PageOutcome {
    var limit_buf: [12]u8 = undefined;
    const limit_str = std.fmt.bufPrint(&limit_buf, "{d}", .{limit}) catch unreachable;
    const params = [_]xrpc.Param{
        .{ .name = "actor", .value = actor },
        .{ .name = "viewer", .value = session.did },
        .{ .name = "limit", .value = limit_str },
    };

    const outcome = try auth.queryHost(
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
    switch (outcome) {
        .failed => |failure| return .{ .failed = failure },
        .ok => |page| return .{ .ok = try feed_core.ingestPosts(gpa, store, page) },
    }
}

/// Fetch a post's thread (`getPostThread?uri=&viewer=`) and ingest its posts —
/// ancestors, the focused post, and its replies — as CONTENT into the SHARED
/// store. The thread VIEW is then a pure query (`feed_core.buildThreadView`), so
/// engagement + identity stay unified with every other view (ZONES inv. 4). The
/// reply linkage rides on each post's `reply` ref, so the store reconstructs the
/// chain. `uri` is the focused post's at-uri (as the feed served it).
pub fn loadThread(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    appview_url: []const u8,
    store: *feed_core.Store,
    uri: []const u8,
    limit: u32,
) !PageOutcome {
    var limit_buf: [12]u8 = undefined;
    const limit_str = std.fmt.bufPrint(&limit_buf, "{d}", .{limit}) catch unreachable;
    const params = [_]xrpc.Param{
        .{ .name = "uri", .value = uri },
        .{ .name = "viewer", .value = session.did },
        .{ .name = "limit", .value = limit_str },
    };

    const outcome = try auth.queryHost(
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
    switch (outcome) {
        .failed => |failure| return .{ .failed = failure },
        .ok => |thread| {
            // The whole thread arrives flat; ingest as content. The nested view
            // is then a query over the store (feed_core.buildThreadView).
            const page: lexicon.TimelinePage = .{ .feed = thread.posts };
            return .{ .ok = try feed_core.ingestPosts(gpa, store, page) };
        },
    }
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

    const outcome = try loadAuthorFeed(gpa, arena_state.allocator(), io, null, &session, pds, &store, session.did, 30);
    switch (outcome) {
        .failed => return error.TestUnexpectedXrpcFailure,
        .ok => |stats| try std.testing.expectEqual(@as(u32, 2), stats.posts_added),
    }

    // Content-only ingest: no Home feed-ordering rows; the profile VIEW is a
    // query over the shared store.
    try std.testing.expectEqual(@as(usize, 0), store.feed.len);
    const items = try feed_core.buildAuthorView(arena_state.allocator(), &store, session.did);
    try std.testing.expectEqual(@as(usize, 2), items.len);
    try std.testing.expectEqualStrings("my newest", items[0].text);
}
