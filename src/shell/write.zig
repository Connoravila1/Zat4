//! B1 classification: SHELL. The **write deep module's** network half.
//!
//! The write module spans two files: src/core/compose.zig (pure facet
//! detection over composed text) and this one — the verbs. Every verb is
//! one `com.atproto.repo.createRecord` call through the auth module, so
//! bearer injection and expired-token refresh-and-retry come for free.
//! Outcomes are values (E4): the server's refusal is an ordinary result
//! the screen prints, never an error that unwinds the session.
//!
//! Mention resolution is the one extra network step: detected handle spans
//! are resolved to DIDs via `com.atproto.identity.resolveHandle` on the
//! session's PDS; a handle that does not resolve simply loses its facet —
//! the text posts unchanged (E4 again).

const std = @import("std");
const Allocator = std.mem.Allocator;
const auth = @import("auth.zig");
const xrpc = @import("xrpc.zig");
const compose = @import("../core/compose.zig");
const feed_core = @import("../core/feed.zig");
const lexicon = @import("../core/lexicon.zig");

/// What a write resolves to: the created record's (uri, cid) — slices
/// owned by the caller's arena — or the server's refusal.
pub const WriteOutcome = union(enum) {
    ok: lexicon.RecordRef,
    failed: xrpc.Failure,
};

/// Strong refs for a reply, as plain values (the shell copies these out of
/// the store before composing; see feed.replyRefsForCid).
/// A7.2: cold struct, size guard waived — one per composed reply.
pub const ReplyTarget = struct {
    root_uri: []const u8,
    root_cid: []const u8,
    parent_uri: []const u8,
    parent_cid: []const u8,
};

fn createRecord(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    record_collection: []const u8,
    record: anytype,
) !WriteOutcome {
    const input = lexicon.CreateRecordInput(@TypeOf(record)){
        .repo = session.did,
        .collection = record_collection,
        .record = record,
    };
    const outcome = try auth.procedure(
        gpa,
        arena,
        io,
        environ,
        session,
        lexicon.method.create_record,
        input,
        lexicon.RecordRef,
    );
    return switch (outcome) {
        .ok => |ref| .{ .ok = ref },
        .failed => |failure| .{ .failed = failure },
    };
}

/// Publish a post (optionally a reply, optionally faceted). `now_epoch`
/// arrives from the shell's clock; the core formats it (B3/B4 split).
pub fn createPost(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    text: []const u8,
    facets: []const lexicon.Facet,
    reply: ?ReplyTarget,
    now_epoch: i64,
) !WriteOutcome {
    var ts_buf: [24]u8 = undefined;
    const record = lexicon.PostRecordOut{
        .text = text,
        .createdAt = feed_core.formatTimestamp(&ts_buf, now_epoch),
        .reply = if (reply) |r| .{
            .root = .{ .uri = r.root_uri, .cid = r.root_cid },
            .parent = .{ .uri = r.parent_uri, .cid = r.parent_cid },
        } else null,
        .facets = if (facets.len > 0) facets else null,
    };
    return createRecord(gpa, arena, io, environ, session, lexicon.collection.post, record);
}

pub fn likePost(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    uri: []const u8,
    cid: []const u8,
    now_epoch: i64,
) !WriteOutcome {
    var ts_buf: [24]u8 = undefined;
    const record = lexicon.SubjectRecordOut{
        .@"$type" = lexicon.collection.like,
        .subject = .{ .uri = uri, .cid = cid },
        .createdAt = feed_core.formatTimestamp(&ts_buf, now_epoch),
    };
    return createRecord(gpa, arena, io, environ, session, lexicon.collection.like, record);
}

pub fn repostPost(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    uri: []const u8,
    cid: []const u8,
    now_epoch: i64,
) !WriteOutcome {
    var ts_buf: [24]u8 = undefined;
    const record = lexicon.SubjectRecordOut{
        .@"$type" = lexicon.collection.repost,
        .subject = .{ .uri = uri, .cid = cid },
        .createdAt = feed_core.formatTimestamp(&ts_buf, now_epoch),
    };
    return createRecord(gpa, arena, io, environ, session, lexicon.collection.repost, record);
}

pub fn followAccount(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    did: []const u8,
    now_epoch: i64,
) !WriteOutcome {
    var ts_buf: [24]u8 = undefined;
    const record = lexicon.FollowRecordOut{
        .subject = did,
        .createdAt = feed_core.formatTimestamp(&ts_buf, now_epoch),
    };
    return createRecord(gpa, arena, io, environ, session, lexicon.collection.follow, record);
}

/// Detect facet spans in composed text (pure core) and resolve mention
/// handles to DIDs over the session's PDS. Unresolvable mentions drop
/// their facet and stay prose. Returned facets (and everything inside)
/// live in the arena.
pub fn resolveFacets(
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *const auth.Session,
    text: []const u8,
) ![]const lexicon.Facet {
    const spans = try compose.detectFacetSpans(arena, text);
    var facets: std.ArrayList(lexicon.Facet) = .empty;
    for (spans) |span| {
        const raw = text[span.byte_start..span.byte_end];
        const feature: ?lexicon.FacetFeature = switch (span.kind) {
            .link => .{
                .@"$type" = "app.bsky.richtext.facet#link",
                .uri = raw,
            },
            .mention => blk: {
                const outcome = try xrpc.query(
                    arena,
                    io,
                    environ,
                    session.pds_url,
                    lexicon.method.resolve_handle,
                    &.{.{ .name = "handle", .value = raw[1..] }}, // strip '@'
                    lexicon.ResolveHandleResponse,
                    .{},
                );
                switch (outcome) {
                    .ok => |resolved| {
                        if (resolved.did.len == 0) break :blk null;
                        break :blk .{
                            .@"$type" = "app.bsky.richtext.facet#mention",
                            .did = resolved.did,
                        };
                    },
                    .failed => break :blk null, // stays prose (E4)
                }
            },
        };
        if (feature) |f| {
            const features = try arena.alloc(lexicon.FacetFeature, 1);
            features[0] = f;
            try facets.append(arena, .{
                .index = .{ .byteStart = span.byte_start, .byteEnd = span.byte_end },
                .features = features,
            });
        }
    }
    return facets.toOwnedSlice(arena);
}

// ---------------------------------------------------------------------------
// Loopback round trip — a scripted fixture PDS asserts the exact wire
// bodies of a faceted reply and a like, and serves the mention resolution.
// (Fourth copy of the loopback scaffold, now grown a body matcher; the
// consolidation pass recorded in the roadmap is overdue and next.)
// ---------------------------------------------------------------------------

const fixture = @import("test_fixture.zig");
const ScriptStep = fixture.ScriptStep;
const serveScript = fixture.serveScript;
const listenLoopback = fixture.listenLoopback;

test "loopback round trip: faceted reply posted with exact wire body, then a like" {
    const gpa = std.testing.allocator; // C6
    const io = std.testing.io;

    var bound = try listenLoopback(io, 38740);
    defer bound.server.deinit(io);
    const thread = try std.Thread.spawn(.{}, serveScript, .{
        &bound.server, io,
        &[_]ScriptStep{
            .{
                .must_contain_head = "GET /xrpc/com.atproto.identity.resolveHandle?handle=alice.test",
                .must_contain_body = "",
                .status = .ok,
                .body =
                \\{"did":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"}
                ,
            },
            .{
                .must_contain_head = "POST /xrpc/com.atproto.repo.createRecord",
                // The record must carry the mention facet's resolved did.
                .must_contain_body = "\"did\":\"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa\"",
                .status = .ok,
                .body =
                \\{"uri":"at://did:plc:cccccccccccccccccccccccc/app.bsky.feed.post/3knew1","cid":"bafyreinewpost"}
                ,
            },
            .{
                .must_contain_head = "POST /xrpc/com.atproto.repo.createRecord",
                .must_contain_body = "\"$type\":\"app.bsky.feed.like\"",
                .status = .ok,
                .body =
                \\{"uri":"at://did:plc:cccccccccccccccccccccccc/app.bsky.feed.like/3klike1","cid":"bafyreilike"}
                ,
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

    const text = "hey @alice.test nice thread";
    const facets = try resolveFacets(arena, io, null, &session, text);
    try std.testing.expectEqual(@as(usize, 1), facets.len);
    try std.testing.expectEqualStrings(
        "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
        facets[0].features[0].did.?,
    );

    const posted = try createPost(gpa, arena, io, null, &session, text, facets, .{
        .root_uri = "at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/app.bsky.feed.post/3kali1",
        .root_cid = "bafyreialice1",
        .parent_uri = "at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/app.bsky.feed.post/3kali1",
        .parent_cid = "bafyreialice1",
    }, 1_767_323_045);
    try std.testing.expectEqualStrings("bafyreinewpost", posted.ok.cid);
    try std.testing.expect(posted.ok.uri.len > 0);

    const liked = try likePost(
        gpa,
        arena,
        io,
        null,
        &session,
        "at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/app.bsky.feed.post/3kali1",
        "bafyreialice1",
        1_767_323_045,
    );
    try std.testing.expectEqualStrings("bafyreilike", liked.ok.cid);
}

/// Split an at-uri (`at://did/collection/rkey`) into its tail parts —
/// pure string slicing; malformed input yields null and the caller
/// reports a refusal rather than sending garbage (E4).
fn uriParts(uri: []const u8) ?struct { collection: []const u8, rkey: []const u8 } {
    const rkey_at = std.mem.lastIndexOfScalar(u8, uri, '/') orelse return null;
    if (rkey_at + 1 >= uri.len) return null;
    const head = uri[0..rkey_at];
    const coll_at = std.mem.lastIndexOfScalar(u8, head, '/') orelse return null;
    if (coll_at + 1 >= head.len) return null;
    return .{ .collection = head[coll_at + 1 ..], .rkey = uri[rkey_at + 1 ..] };
}

fn deleteRecord(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    record_uri: []const u8,
) !WriteOutcome {
    const parts = uriParts(record_uri) orelse
        return .{ .failed = .{ .status = 0, .code = "BadRecordUri", .message = "malformed record uri" } };
    const input = lexicon.DeleteRecordOut{
        .repo = session.did,
        .collection = parts.collection,
        .rkey = parts.rkey,
    };
    const outcome = try auth.procedure(
        gpa,
        arena,
        io,
        environ,
        session,
        lexicon.method.delete_record,
        input,
        lexicon.DeleteRecordResponse,
    );
    return switch (outcome) {
        .ok => .{ .ok = .{ .uri = "", .cid = "" } },
        .failed => |failure| .{ .failed = failure },
    };
}

/// Delete the session account's like record; the caller already cleared
/// the optimistic state and holds a COPY of the uri for the revert path.
pub fn unlikePost(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    like_uri: []const u8,
) !WriteOutcome {
    return deleteRecord(gpa, arena, io, environ, session, like_uri);
}

pub fn unrepostPost(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    repost_uri: []const u8,
) !WriteOutcome {
    return deleteRecord(gpa, arena, io, environ, session, repost_uri);
}

test "write: uriParts splits an at-uri and refuses malformed ones" {
    const p = uriParts("at://did:plc:abc/app.bsky.feed.like/3kxyz").?;
    try std.testing.expectEqualStrings("app.bsky.feed.like", p.collection);
    try std.testing.expectEqualStrings("3kxyz", p.rkey);
    try std.testing.expect(uriParts("at://did:plc:abc") == null);
    try std.testing.expect(uriParts("ends/with/") == null);
}
