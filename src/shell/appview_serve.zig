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

const RouteError = error{ OutOfMemory, NotFound };

/// Pure-ish routing: pick the method from the path, pull params, call the
/// core, serialize. (Reads the borrowed index; allocates the response in the
/// arena. No socket here — handleConn owns the wire.)
fn route(arena: Allocator, idx: *const appview.Index, cfg: ServeConfig, target: []const u8) RouteError![]const u8 {
    const path = pathOf(target);
    if (std.mem.endsWith(u8, path, "app.zat4.feed.getTimeline")) {
        return getTimeline(arena, idx, cfg, target);
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

    // Serialize into the lexicon's TimelinePage shape so the existing client
    // parser consumes it unchanged (D3 — the AppView speaks the same wire the
    // client already reads). Build FeedViewPost entries from the plain rows.
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
                .author = .{ .did = r.author_did, .handle = r.author_did },
                .record = .{ .text = r.text, .createdAt = created_at },
                .likeCount = r.like_count,
                .repostCount = r.repost_count,
                .replyCount = 0,
                .quoteCount = 0,
                .indexedAt = "",
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

test "route: an unknown method is NotFound" {
    const gpa = testing.allocator;
    var idx: appview.Index = .{};
    defer appview.deinit(gpa, &idx);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    try testing.expectError(error.NotFound, route(arena_state.allocator(), &idx, .{}, "/xrpc/app.zat4.feed.getNonsense"));
}
