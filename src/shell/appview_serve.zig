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

//! B1 classification: SHELL (network I/O — the HTTP query surface). The Zat4
//! AppView's read endpoints (STANDALONE_ROADMAP Phase C): a thin HTTP server
//! that turns a request into a pure call on the core index and serializes the
//! plain rows back out. All the assembly logic is core (core/appview.zig);
//! this layer only does sockets + JSON, and it is thin (B3).
//!
//! Serves the query surface Phase B's client expects:
//!   GET /xrpc/app.zat4.feed.getTimeline?viewer=<did>&limit=<n>
//!   GET /xrpc/app.zat4.actor.getProfile?actor=<did-or-handle>
//!
//! Cut 1 auth posture, recorded (F4, deferred-not-hidden): the viewer DID
//! arrives as a query param rather than from a verified bearer token. Real
//! token verification (the AppView confirming WHO is asking, per the roadmap)
//! is a Phase E hardening seat — named here so it is a deliberate gap, not an
//! oversight. On a public box, run behind the reverse proxy / on a trusted
//! network until that lands.
//!
//! Failure isolation (E2): one bad request tears down its own connection,
//! never the server or the index. The accept loop logs and continues.

const std = @import("std");
const Allocator = std.mem.Allocator;
const appview = @import("../core/appview.zig");
const lexicon = @import("../core/lexicon.zig");
const feed = @import("../core/feed.zig");

/// A7.2: cold config, one per process. The index is borrowed (owned by the
/// ingest side); serve only reads it.
pub const ServeConfig = struct {
    port: u16 = 2584,
    default_limit: usize = 50,
    max_limit: usize = 100,
    /// Shared bearer token gating every request (STANDALONE_ROADMAP Phase E,
    /// pulled forward so the AppView can be exposed past the SSH tunnel). The
    /// client sends `Authorization: Bearer <token>`. Empty ⇒ FAIL CLOSED: every
    /// request is rejected, so a server started without a token serves nothing
    /// rather than serving open (E3 — the gate never silently opens). Per-user
    /// atproto service-auth (verifying the requester's DID-signed JWT) is the
    /// larger Phase E end state; this shared gate is the access control for now.
    token: []const u8 = "",
};

/// Guards the index against concurrent mutation by the live-ingest thread
/// while a request reads it. A spinlock (the Mailbox's pattern): two threads,
/// brief critical sections, and `std.atomic` is stable across 0.16 snapshots
/// where `std.Thread.Mutex` is not (stream.zig records the same reason). In the
/// static (snapshot) serve path nothing else touches the index, so the lock is
/// uncontended there. A7.2: cold struct, size guard waived.
pub const IndexLock = struct {
    locked: std.atomic.Value(bool) = .init(false),
    pub fn lock(self: *IndexLock) void {
        while (self.locked.swap(true, .acquire)) std.atomic.spinLoopHint();
    }
    pub fn unlock(self: *IndexLock) void {
        self.locked.store(false, .release);
    }
};

/// Run the serve loop forever (until the process is killed). Each accepted
/// connection is handled inline on this thread for Cut 1 — single-threaded
/// serving is honest about scale (G3: do not build a worker pool before a
/// profiler on real traffic asks for one). `idx` is read-only here; the
/// caller guarantees it is not mutated concurrently in Cut 1 (ingest and
/// serve run as separate processes against separate index snapshots until
/// the shared-state design lands — recorded in the setup doc).
pub fn run(gpa: Allocator, io: std.Io, idx: *const appview.Index, cfg: ServeConfig, lock: *IndexLock) !void {
    var address: std.Io.net.IpAddress = .{ .ip4 = .loopback(cfg.port) };
    var server = try address.listen(io, .{ .reuse_address = true });
    defer server.deinit(io);

    while (true) {
        const stream = server.accept(io) catch continue; // E2: a refused accept is the next loop's problem
        handleConn(gpa, io, idx, cfg, stream, lock) catch {}; // E2: contained per-connection
        stream.close(io);
    }
}

fn handleConn(gpa: Allocator, io: std.Io, idx: *const appview.Index, cfg: ServeConfig, stream: std.Io.net.Stream, lock: *IndexLock) !void {
    var read_buf: [16 * 1024]u8 = undefined;
    var write_buf: [64 * 1024]u8 = undefined;
    var stream_reader = stream.reader(io, &read_buf);
    var stream_writer = stream.writer(io, &write_buf);
    var http_server: std.http.Server = .init(&stream_reader.interface, &stream_writer.interface);

    var req = http_server.receiveHead() catch return;

    // Auth gate (fail closed, E3): the request must carry a matching shared
    // bearer token. An empty configured token rejects everything — a server
    // without a token never serves open. Checked before routing so an
    // unauthenticated probe learns nothing about the method surface.
    if (!authorized(cfg.token, authHeader(&req))) {
        req.respond("{\"error\":\"AuthRequired\"}", .{ .status = .unauthorized, .extra_headers = jsonHeaders() }) catch {};
        return;
    }

    const target = req.head.target; // e.g. /xrpc/app.zat4.feed.getTimeline?viewer=...

    var arena_state = std.heap.ArenaAllocator.init(gpa); // C3: per-request arena
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Hold the lock only across the index read + serialization: route() builds
    // the response by copying what it needs out of the index into the arena, so
    // the returned body is independent of the index and the (slow) socket write
    // below runs unlocked. The live-ingest thread can mutate between requests.
    lock.lock();
    const routed = route(arena, idx, cfg, target);
    lock.unlock();
    const body = routed catch |err| switch (err) {
        error.OutOfMemory => return err,
        error.NotFound => {
            req.respond("{\"error\":\"MethodNotImplemented\"}", .{ .status = .not_found, .extra_headers = jsonHeaders() }) catch {};
            return;
        },
    };
    req.respond(body, .{ .status = .ok, .extra_headers = jsonHeaders() }) catch {};
}

fn jsonHeaders() []const std.http.Header {
    return &.{.{ .name = "content-type", .value = "application/json" }};
}

/// The request's `Authorization` header value, or null if absent (case-
/// insensitive name match — HTTP header names are case-insensitive).
fn authHeader(req: *std.http.Server.Request) ?[]const u8 {
    var it = req.iterateHeaders();
    while (it.next()) |h| {
        if (std.ascii.eqlIgnoreCase(h.name, "authorization")) return h.value;
    }
    return null;
}

/// Strict bearer check. Empty `expected` ⇒ false (FAIL CLOSED — see
/// ServeConfig.token). Otherwise the header must be exactly `Bearer <expected>`.
/// The token bytes are compared in constant time so a timing side-channel
/// cannot probe the secret out byte by byte.
fn authorized(expected: []const u8, header: ?[]const u8) bool {
    if (expected.len == 0) return false;
    const h = header orelse return false;
    const prefix = "Bearer ";
    if (!std.mem.startsWith(u8, h, prefix)) return false;
    const got = h[prefix.len..];
    if (got.len != expected.len) return false;
    var diff: u8 = 0;
    for (got, expected) |a, b| diff |= a ^ b;
    return diff == 0;
}

const RouteError = error{ OutOfMemory, NotFound };

/// Pure-ish routing: pick the method from the path, pull params, call the
/// core, serialize. (Reads the borrowed index; allocates the response in the
/// arena. No socket here — handleConn owns the wire.)
fn route(arena: Allocator, idx: *const appview.Index, cfg: ServeConfig, target: []const u8) RouteError![]const u8 {
    const path = pathOf(target);
    if (std.mem.endsWith(u8, path, "app.zat4.feed.getTimeline")) {
        return getTimeline(arena, idx, cfg, target);
    }
    if (std.mem.endsWith(u8, path, "app.zat4.feed.getAuthorFeed")) {
        return getAuthorFeed(arena, idx, cfg, target);
    }
    if (std.mem.endsWith(u8, path, "app.zat4.actor.getProfile")) {
        return getProfile(arena, idx, target);
    }
    return error.NotFound;
}

fn getTimeline(arena: Allocator, idx: *const appview.Index, cfg: ServeConfig, target: []const u8) RouteError![]const u8 {
    // The client percent-encodes query values (RFC 3986 unreserved set), so a
    // DID arrives with its ':' as %3A. Decode it, or the viewer never matches an
    // interned DID and the timeline comes back empty.
    const viewer = (try queryValueDecoded(arena, target, "viewer")) orelse "";
    var limit = cfg.default_limit;
    if (queryValue(target, "limit")) |l| {
        limit = @min(std.fmt.parseInt(usize, l, 10) catch cfg.default_limit, cfg.max_limit);
    }

    const rows = try appview.buildTimeline(arena, idx, viewer, limit);
    return serializeFeed(arena, rows);
}

fn getAuthorFeed(arena: Allocator, idx: *const appview.Index, cfg: ServeConfig, target: []const u8) RouteError![]const u8 {
    // The profile screen's body: one author's posts. `actor` is whose feed;
    // `viewer` is who is looking (their viewer.like is stamped on each row).
    // Both are percent-encoded DIDs on the wire (see getTimeline).
    const actor = (try queryValueDecoded(arena, target, "actor")) orelse "";
    const viewer = (try queryValueDecoded(arena, target, "viewer")) orelse "";
    var limit = cfg.default_limit;
    if (queryValue(target, "limit")) |l| {
        limit = @min(std.fmt.parseInt(usize, l, 10) catch cfg.default_limit, cfg.max_limit);
    }

    const rows = try appview.buildAuthorFeed(arena, idx, actor, viewer, limit);
    return serializeFeed(arena, rows);
}

/// Serialize feed rows into the lexicon's TimelinePage shape so the existing
/// client parser consumes them unchanged (D3 — the AppView speaks the same
/// wire the client already reads). Shared by getTimeline and getAuthorFeed.
fn serializeFeed(arena: Allocator, rows: []const appview.TimelineRow) RouteError![]const u8 {
    const feed_items = try arena.alloc(lexicon.FeedViewPost, rows.len);
    for (feed_items, rows) |*fv, r| {
        const uri_buf = try arena.alloc(u8, r.author_did.len + r.cid.len + 64);
        const uri = std.fmt.bufPrint(uri_buf, "at://{s}/{s}/{s}", .{ r.author_did, lexicon.collection.post, r.cid }) catch r.cid;
        // Format the indexed timestamp so the client shows a real age (an empty
        // createdAt parsed to epoch 0, hence the "2945w" ages).
        const ts_buf = try arena.alloc(u8, 32);
        const created_at = feed.formatTimestamp(ts_buf, r.created_at);
        fv.* = .{
            .post = .{
                .uri = uri,
                .cid = r.cid,
                .author = .{ .did = r.author_did, .handle = if (r.author_handle.len > 0) r.author_handle else r.author_did },
                .record = .{ .text = r.text, .createdAt = created_at },
                .likeCount = r.like_count,
                .repostCount = r.repost_count,
                .replyCount = 0,
                .quoteCount = 0,
                .indexedAt = "",
                // viewer.like: the viewer's own like record uri — the client
                // shows the filled heart from it on reload AND deletes it to
                // unlike. Absent (null) when the viewer hasn't liked this post.
                .viewer = if (r.viewer_like_uri.len > 0) .{ .like = r.viewer_like_uri } else null,
            },
        };
    }
    const page: lexicon.TimelinePage = .{ .cursor = null, .feed = feed_items };
    return std.json.Stringify.valueAlloc(arena, page, .{ .emit_null_optional_fields = false });
}

fn getProfile(arena: Allocator, idx: *const appview.Index, target: []const u8) RouteError![]const u8 {
    const actor = (try queryValueDecoded(arena, target, "actor")) orelse "";
    _ = idx;
    // Cut 1 profile is a stub shaped like the client's ProfileViewDetailed:
    // the standalone profile record (app.zat4.actor.profile) indexing lands
    // with Phase D enrollment. Returning the actor with zero counts keeps the
    // client's profile screen renderable end-to-end now.
    const profile: lexicon.ProfileViewDetailed = .{
        .did = actor,
        .handle = actor,
    };
    return std.json.Stringify.valueAlloc(arena, profile, .{ .emit_null_optional_fields = false });
}

// --- tiny URL helpers (no dependency — F2) -------------------------------

fn pathOf(target: []const u8) []const u8 {
    const q = std.mem.indexOfScalar(u8, target, '?') orelse return target;
    return target[0..q];
}

/// Find `name`'s value and percent-DECODE it into the arena (the client
/// encodes values to the RFC 3986 unreserved set — `core/xrpc.zig` — so a DID's
/// ':' is on the wire as %3A). Null if the param is absent.
fn queryValueDecoded(arena: Allocator, target: []const u8, name: []const u8) RouteError!?[]const u8 {
    const raw = queryValue(target, name) orelse return null;
    const buf = try arena.dupe(u8, raw);
    return std.Uri.percentDecodeInPlace(buf);
}

/// Find `name`'s value in the target's query string, VERBATIM (not decoded).
/// Returns null if absent. Used for URL-safe values (numeric limit); DID-
/// bearing params go through `queryValueDecoded`.
fn queryValue(target: []const u8, name: []const u8) ?[]const u8 {
    const q = std.mem.indexOfScalar(u8, target, '?') orelse return null;
    var it = std.mem.splitScalar(u8, target[q + 1 ..], '&');
    while (it.next()) |pair| {
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        if (std.mem.eql(u8, pair[0..eq], name)) return pair[eq + 1 ..];
    }
    return null;
}

// ---------------------------------------------------------------------------
// Tests (C6) — the pure routing/serialization, headless (no socket).
// ---------------------------------------------------------------------------

const testing = std.testing;

test "queryValue: pulls params, missing is null" {
    const t = "/xrpc/app.zat4.feed.getTimeline?viewer=did:plc:abc&limit=10";
    try testing.expectEqualStrings("did:plc:abc", queryValue(t, "viewer").?);
    try testing.expectEqualStrings("10", queryValue(t, "limit").?);
    try testing.expect(queryValue(t, "cursor") == null);
    try testing.expect(queryValue("/no/query", "viewer") == null);
}

test "route: getTimeline serializes a TimelinePage the client can parse" {
    const gpa = testing.allocator;
    var idx: appview.Index = .{};
    defer appview.deinit(gpa, &idx);

    try appview.indexFollow(gpa, &idx, "did:me", "did:author");
    _ = try appview.indexPost(gpa, &idx, .{ .cid = "bafyc1", .author_did = "did:author", .text = "first zat4 post", .created_at = 100 });

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const json = try route(arena, &idx, .{}, "/xrpc/app.zat4.feed.getTimeline?viewer=did:me&limit=10");
    // It round-trips through the client's own TimelinePage parser.
    const page = try std.json.parseFromSliceLeaky(lexicon.TimelinePage, arena, json, .{ .ignore_unknown_fields = true });
    try testing.expectEqual(@as(usize, 1), page.feed.len);
    try testing.expectEqualStrings("first zat4 post", page.feed[0].post.record.text);
    try testing.expectEqualStrings("bafyc1", page.feed[0].post.cid);
    // The uri is an app.zat4 at-uri, never app.bsky (the wall, server side).
    try testing.expect(std.mem.indexOf(u8, page.feed[0].post.uri, "app.zat4.feed.post") != null);
    try testing.expect(std.mem.indexOf(u8, page.feed[0].post.uri, "app.bsky") == null);
}

test "route: a percent-encoded viewer DID resolves (client encodes ':' as %3A)" {
    // Regression: the client percent-encodes query values (core/xrpc.zig), so a
    // real DID arrives as did%3Aplc%3A...; if the AppView reads it verbatim the
    // viewer never matches an interned DID and the timeline is empty -- the
    // "nothing shows when I refresh" bug. The AppView must decode it.
    const gpa = testing.allocator;
    var idx: appview.Index = .{};
    defer appview.deinit(gpa, &idx);
    try appview.indexFollow(gpa, &idx, "did:plc:me", "did:plc:author");
    _ = try appview.indexPost(gpa, &idx, .{ .cid = "c1", .author_did = "did:plc:author", .text = "decoded ok", .created_at = 1 });

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const json = try route(arena, &idx, .{}, "/xrpc/app.zat4.feed.getTimeline?limit=10&viewer=did%3Aplc%3Ame");
    const page = try std.json.parseFromSliceLeaky(lexicon.TimelinePage, arena, json, .{ .ignore_unknown_fields = true });
    try testing.expectEqual(@as(usize, 1), page.feed.len);
    try testing.expectEqualStrings("decoded ok", page.feed[0].post.record.text);
}

test "route: getAuthorFeed serves one author's posts with the viewer's like" {
    const gpa = testing.allocator;
    var idx: appview.Index = .{};
    defer appview.deinit(gpa, &idx);

    // Two authors post; the author feed must carry only the requested actor's,
    // newest first — no follow edge needed (a profile is the author's own posts).
    _ = try appview.indexPost(gpa, &idx, .{ .cid = "bafyc1", .author_did = "did:plc:author", .text = "older", .created_at = 100 });
    _ = try appview.indexPost(gpa, &idx, .{ .cid = "bafyc2", .author_did = "did:plc:other", .text = "not mine", .created_at = 150 });
    _ = try appview.indexPost(gpa, &idx, .{ .cid = "bafyc3", .author_did = "did:plc:author", .text = "newer", .created_at = 200 });
    try appview.setLikeEdge(gpa, &idx, "did:plc:me", "bafyc3", "at://did:plc:me/app.zat4.feed.like/r1");

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const json = try route(arena, &idx, .{}, "/xrpc/app.zat4.feed.getAuthorFeed?actor=did%3Aplc%3Aauthor&viewer=did%3Aplc%3Ame&limit=10");
    const page = try std.json.parseFromSliceLeaky(lexicon.TimelinePage, arena, json, .{ .ignore_unknown_fields = true });
    try testing.expectEqual(@as(usize, 2), page.feed.len); // author's two, not other's
    try testing.expectEqualStrings("newer", page.feed[0].post.record.text); // newest first
    try testing.expectEqualStrings("older", page.feed[1].post.record.text);
    // The viewer's like surfaces on the matching row, absent on the other.
    try testing.expect(page.feed[0].post.viewer != null);
    try testing.expect(page.feed[1].post.viewer == null);
}

test "auth: strict bearer gate — fail closed, exact match, reject the rest" {
    // Fail closed: an empty configured token rejects every request, even a
    // well-formed bearer — a server without a token serves nothing.
    try testing.expect(!authorized("", "Bearer anything"));
    try testing.expect(!authorized("", null));

    // With a token configured, only the exact `Bearer <token>` passes.
    const tok = "s3cret-zat4-token";
    try testing.expect(authorized(tok, "Bearer s3cret-zat4-token"));
    try testing.expect(!authorized(tok, "Bearer wrong"));
    try testing.expect(!authorized(tok, "Bearer s3cret-zat4-token-extra")); // length mismatch
    try testing.expect(!authorized(tok, "s3cret-zat4-token")); // missing scheme
    try testing.expect(!authorized(tok, "Basic s3cret-zat4-token")); // wrong scheme
    try testing.expect(!authorized(tok, null)); // no header
}

test "route: an unknown method is NotFound" {
    const gpa = testing.allocator;
    var idx: appview.Index = .{};
    defer appview.deinit(gpa, &idx);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    try testing.expectError(error.NotFound, route(arena_state.allocator(), &idx, .{}, "/xrpc/app.zat4.feed.getNonsense"));
}
