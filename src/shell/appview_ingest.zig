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

//! B1 classification: split. The REDUCTION is CORE (pure: event JSON →
//! index mutation, no I/O); the SOURCE PUMP is SHELL (reads bytes off a
//! socket/pipe). The Zat4 AppView's ingest (STANDALONE_ROADMAP Phase C):
//! subscribe to the network event stream, keep only `app.zat4.*`, and feed
//! the core index.
//!
//! The wall, server side: every classifier below matches a `lexicon.*`
//! collection NSID, all `app.zat4.*`, so the index is STRUCTURALLY incapable
//! of holding Bluesky content — non-zat4 events reduce to "ignored," never
//! indexed (the separation is the namespace, not a runtime filter).
//!
//! Cut 1 ingest source (F4 — do not duplicate the client's 1200-line
//! WebSocket stack now): a line-delimited Jetstream feed read from an `io`
//! reader — a file, a pipe, or `jetstream-tail | zat4-appview`. This proves
//! the ingest→filter→index loop end-to-end and is fully testable headless;
//! swapping the live WebSocket source under `runFromReader` is a contained
//! follow-up that reuses core/websocket.zig + core/jetstream.zig. Recorded as
//! a deliberate Cut-1 boundary, not an oversight.
//!
//! Failure isolation (E2/E4): a malformed event reduces to "ignored" and the
//! pump continues — one bad line never corrupts the index or drops the feed.

const std = @import("std");
const Allocator = std.mem.Allocator;
const appview = @import("../core/appview.zig");
const jetstream = @import("../core/jetstream.zig");
const lexicon = @import("../core/lexicon.zig");

/// What a single event did to the index — returned so the pump (and tests)
/// can count without re-inspecting the index. Plain enum, no payload.
pub const Reduced = enum { post, follow, like, repost, identity, ignored };

/// Reduce one Jetstream event-JSON line into the index. PURE over (idx,
/// json) aside from the index mutation it performs; no I/O, no clock. A line
/// that is not an `app.zat4.*` create reduces to `.ignored` (E4 — an
/// uninteresting event is an ordinary state, not an error). C1: takes gpa
/// for the index's growth and `arena` for transient parse scratch.
pub fn ingestEvent(gpa: Allocator, arena: Allocator, idx: *appview.Index, event_json: []const u8) Allocator.Error!Reduced {
    // Posts go through the existing, tested jetstream reducer (it already
    // filters to lexicon.collection.post and parses reply refs).
    if (try jetstream.reduce(arena, event_json)) |p| {
        _ = try appview.indexPost(gpa, idx, .{
            .cid = p.cid,
            .author_did = p.did,
            .text = p.text,
            .created_at = p.created_at,
            .reply_parent_cid = p.reply_parent_cid,
            .reply_root_cid = p.reply_root_cid,
        });
        return .post;
    }

    // Everything else: parse the minimal commit envelope ourselves and match
    // the follow/like/repost collections. Malformed ⇒ ignored (E4).
    const ev = std.json.parseFromSliceLeaky(GraphEvent, arena, event_json, .{
        .ignore_unknown_fields = true,
    }) catch return .ignored;
    // Identity events carry a DID's handle (firehose `identity` frames + the
    // durable handle line). Index it so posts serve `@handle`, not the DID.
    if (std.mem.eql(u8, ev.kind, "identity")) {
        const info = ev.identity orelse return .ignored;
        const did = if (ev.did.len > 0) ev.did else info.did;
        if (did.len == 0) return .ignored;
        if (info.handle.len > 0) try appview.setHandle(gpa, idx, did, info.handle);
        if (info.displayName.len > 0) try appview.setDisplayName(gpa, idx, did, info.displayName);
        if (info.handle.len == 0 and info.displayName.len == 0) return .ignored;
        return .identity;
    }
    if (!std.mem.eql(u8, ev.kind, "commit")) return .ignored;
    const commit = ev.commit orelse return .ignored;
    if (!std.mem.eql(u8, commit.operation, "create")) return .ignored;
    const rec = commit.record orelse return .ignored;

    if (std.mem.eql(u8, commit.collection, lexicon.collection.follow)) {
        const subject = followSubject(rec);
        if (ev.did.len == 0 or subject.len == 0) return .ignored;
        try appview.indexFollow(gpa, idx, ev.did, subject);
        return .follow;
    }
    if (std.mem.eql(u8, commit.collection, lexicon.collection.like)) {
        const subject_cid = engagementSubjectCid(rec);
        if (subject_cid.len == 0) return .ignored;
        // Likes are edge-managed (setLikeEdge maintains the count + viewer.like).
        // Rebuild the record uri from did + rkey so a replayed/firehose like is
        // counted AND un-likeable; without the rkey we can't, so it's ignored.
        if (ev.did.len == 0 or commit.rkey.len == 0) return .ignored;
        const uri = try std.fmt.allocPrint(arena, "at://{s}/{s}/{s}", .{ ev.did, lexicon.collection.like, commit.rkey });
        try appview.setLikeEdge(gpa, idx, ev.did, subject_cid, uri);
        return .like;
    }
    if (std.mem.eql(u8, commit.collection, lexicon.collection.repost)) {
        const subject_cid = engagementSubjectCid(rec);
        if (subject_cid.len == 0) return .ignored;
        try appview.indexEngagement(gpa, idx, .repost, subject_cid);
        return .repost;
    }
    return .ignored;
}

// --- minimal graph-event wire shapes (transient parse targets, A7.2) ------
//
// The wire `subject` is union-typed: a follow's subject is a bare DID string,
// a like/repost's subject is a strong-ref object. Rather than a custom decoder,
// we parse `subject` as a generic json Value and read the right shape out of
// it (F2 — std reflection over a hand-rolled codec). One event struct, both
// record kinds, absent fields default (E4).

/// A7.2: cold struct, size guard waived — transient parse target.
const GraphEvent = struct {
    did: []const u8 = "",
    time_us: i64 = 0,
    kind: []const u8 = "",
    commit: ?GraphCommitFlat = null,
    identity: ?IdentityInfo = null,
};

/// A7.2: cold struct, size guard waived — transient parse target. The handle
/// payload of an `identity` event (`did` is usually on the envelope too).
const IdentityInfo = struct {
    did: []const u8 = "",
    handle: []const u8 = "",
    displayName: []const u8 = "",
};

/// A7.2: cold struct, size guard waived — transient parse target.
const GraphCommitFlat = struct {
    operation: []const u8 = "",
    collection: []const u8 = "",
    rkey: []const u8 = "",
    cid: []const u8 = "",
    record: ?FlatRecord = null,
};

/// A7.2: cold struct, size guard waived — transient parse target. `subject`
/// is a generic Value: a string for follows, an object for likes/reposts.
const FlatRecord = struct {
    subject: std.json.Value = .null,
};

/// The followed DID, when `subject` is a bare string (a follow record).
fn followSubject(rec: FlatRecord) []const u8 {
    return switch (rec.subject) {
        .string => |s| s,
        else => "",
    };
}

/// The subject post's cid, when `subject` is a strong-ref object (a
/// like/repost record).
fn engagementSubjectCid(rec: FlatRecord) []const u8 {
    return switch (rec.subject) {
        .object => |o| if (o.get("cid")) |v| switch (v) {
            .string => |s| s,
            else => "",
        } else "",
        else => "",
    };
}

/// Ingest a whole buffer of newline-delimited Jetstream events into the
/// index. PURE over (idx, bytes) aside from the index mutation; splits in
/// memory so there is no streaming-reader EOF subtlety. Returns the count
/// indexed (non-ignored). A bad line is skipped (E2). C1: gpa for index
/// growth, an internal arena for per-line parse scratch.
pub fn ingestAll(gpa: Allocator, idx: *appview.Index, bytes: []const u8) Allocator.Error!usize {
    var indexed: usize = 0;
    var line_arena = std.heap.ArenaAllocator.init(gpa);
    defer line_arena.deinit();
    var it = std.mem.splitScalar(u8, bytes, '\n');
    while (it.next()) |line| {
        const trimmed = std.mem.trimEnd(u8, line, "\r");
        if (trimmed.len == 0) continue;
        _ = line_arena.reset(.retain_capacity);
        const what = ingestEvent(gpa, line_arena.allocator(), idx, trimmed) catch |e| switch (e) {
            error.OutOfMemory => return e,
        };
        if (what != .ignored) indexed += 1;
    }
    return indexed;
}

/// Pump events from an `io` reader (SHELL — B3) into the index: read the
/// source to end, then `ingestAll`. Reading-then-splitting avoids the
/// streaming-delimiter EOF subtlety on pipes and is right for Cut 1's
/// snapshot-ingest model; a live WebSocket source that ingests continuously
/// while serving swaps in here later (recorded boundary). `max_bytes` caps
/// the read so a hostile/endless source cannot exhaust memory (C2 — visible).
pub fn runFromReader(gpa: Allocator, reader: *std.Io.Reader, idx: *appview.Index, max_bytes: usize) !usize {
    const bytes = try reader.allocRemaining(gpa, .limited(max_bytes));
    defer gpa.free(bytes);
    return ingestAll(gpa, idx, bytes);
}

// ---------------------------------------------------------------------------
// Tests (C6) — the reduction is proven headless, no socket.
// ---------------------------------------------------------------------------

const testing = std.testing;

test "ingest: an app.zat4 post create is indexed" {
    const gpa = testing.allocator;
    var idx: appview.Index = .{};
    defer appview.deinit(gpa, &idx);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    const ev =
        \\{"did":"did:plc:alice","time_us":1,"kind":"commit","commit":{"operation":"create","collection":"app.zat4.feed.post","rkey":"a","cid":"bafyc1","record":{"$type":"app.zat4.feed.post","text":"hi zat4","createdAt":"2026-06-14T00:00:00Z"}}}
    ;
    const what = try ingestEvent(gpa, arena_state.allocator(), &idx, ev);
    try testing.expectEqual(Reduced.post, what);
    try testing.expectEqual(@as(usize, 1), idx.posts.len);
}

test "ingest: a follow create lands in the graph" {
    const gpa = testing.allocator;
    var idx: appview.Index = .{};
    defer appview.deinit(gpa, &idx);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    const ev =
        \\{"did":"did:plc:alice","time_us":2,"kind":"commit","commit":{"operation":"create","collection":"app.zat4.graph.follow","rkey":"f","cid":"bafyf1","record":{"$type":"app.zat4.graph.follow","subject":"did:plc:bob","createdAt":"2026-06-14T00:00:00Z"}}}
    ;
    const what = try ingestEvent(gpa, arena_state.allocator(), &idx, ev);
    try testing.expectEqual(Reduced.follow, what);
    try testing.expectEqual(@as(usize, 1), idx.follows.len);
}

test "ingest: a like bumps the subject post's count; a non-zat4 event is ignored" {
    const gpa = testing.allocator;
    var idx: appview.Index = .{};
    defer appview.deinit(gpa, &idx);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    _ = try appview.indexPost(gpa, &idx, .{ .cid = "bafyc1", .author_did = "did:plc:a", .text = "p", .created_at = 1 });
    const like =
        \\{"did":"did:plc:b","time_us":3,"kind":"commit","commit":{"operation":"create","collection":"app.zat4.feed.like","rkey":"l","cid":"bafyl1","record":{"$type":"app.zat4.feed.like","subject":{"cid":"bafyc1","uri":"at://x"},"createdAt":"2026-06-14T00:00:00Z"}}}
    ;
    try testing.expectEqual(Reduced.like, try ingestEvent(gpa, arena, &idx, like));
    try testing.expectEqual(@as(u32, 1), idx.posts.items(.like_count)[0]);

    // A Bluesky post can never enter: its collection is not app.zat4.* so the
    // wall rejects it at ingest (structurally, not by filtering).
    const bsky =
        \\{"did":"did:plc:c","time_us":4,"kind":"commit","commit":{"operation":"create","collection":"app.bsky.feed.post","rkey":"x","cid":"bafyX","record":{"$type":"app.bsky.feed.post","text":"not here","createdAt":"2026-06-14T00:00:00Z"}}}
    ;
    try testing.expectEqual(Reduced.ignored, try ingestEvent(gpa, arena, &idx, bsky));
    try testing.expectEqual(@as(usize, 1), idx.posts.len); // unchanged
}

test "ingest: an identity event indexes the author's handle" {
    const gpa = testing.allocator;
    var idx: appview.Index = .{};
    defer appview.deinit(gpa, &idx);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    const ev =
        \\{"did":"did:plc:bob","kind":"identity","identity":{"did":"did:plc:bob","handle":"bob.zat4.com"}}
    ;
    try testing.expectEqual(Reduced.identity, try ingestEvent(gpa, arena_state.allocator(), &idx, ev));
    try testing.expectEqualStrings("bob.zat4.com", appview.handleFor(&idx, "did:plc:bob"));
}

test "ingest: ingestAll pumps newline-delimited events and counts" {
    const gpa = testing.allocator;
    var idx: appview.Index = .{};
    defer appview.deinit(gpa, &idx);

    const feed =
        \\{"did":"did:plc:alice","time_us":1,"kind":"commit","commit":{"operation":"create","collection":"app.zat4.graph.follow","rkey":"f","cid":"c0","record":{"subject":"did:plc:bob"}}}
        \\{"did":"did:plc:bob","time_us":2,"kind":"commit","commit":{"operation":"create","collection":"app.zat4.feed.post","rkey":"a","cid":"c1","record":{"text":"from bob","createdAt":"2026-06-14T00:00:00Z"}}}
        \\garbage line that is not json
        \\
    ;
    const n = try ingestAll(gpa, &idx, feed);
    try testing.expectEqual(@as(usize, 2), n); // follow + post; garbage skipped
    try testing.expectEqual(@as(usize, 1), idx.posts.len);
    try testing.expectEqual(@as(usize, 1), idx.follows.len);
}
