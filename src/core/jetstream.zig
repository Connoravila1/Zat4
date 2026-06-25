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

//! B1 classification: CORE (pure). The sealed **Jetstream wire module**
//! (D1): event JSON shapes in, plain values out. Jetstream is atproto's
//! lighter, JSON-encoded view of the firehose; like every wire format
//! here, its shapes never leak — the rest of the app sees only
//! `LivePost`, a struct of plain values.
//!
//! Scope, recorded: v1 reduces only `app.zat4.feed.post` *creates*.
//! Likes, deletes, identity and account events reduce to null today; the
//! upgrade path (live count updates, deletions) is noted in the roadmap.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const lexicon = @import("lexicon.zig");
const feed = @import("feed.zig");
const jsonguard = @import("jsonguard.zig");

// --- Wire shapes (transient parse targets, all A7.2) ---

/// A7.2: cold struct, size guard waived — transient parse target.
const Commit = struct {
    rev: []const u8 = "",
    operation: []const u8 = "",
    collection: []const u8 = "",
    rkey: []const u8 = "",
    cid: []const u8 = "",
    record: ?lexicon.PostRecord = null,
};

/// A7.2: cold struct, size guard waived — transient parse target.
const Event = struct {
    did: []const u8 = "",
    time_us: i64 = 0,
    kind: []const u8 = "",
    commit: ?Commit = null,
};

/// One live post as plain values. Strings borrow the reduction arena;
/// the consumer copies what it keeps (E1: values cross the boundary).
pub const LivePost = struct {
    did: []const u8,
    uri: []const u8,
    cid: []const u8,
    text: []const u8,
    reply_parent_cid: []const u8, // "" when not a reply
    reply_root_cid: []const u8, // "" when not a reply
    created_at: i64,
    time_us: i64, // the stream cursor: resume-from on reconnect

    comptime {
        // Budget: 6 slices + 2 i64 = 112 on 64-bit, zero padding. Reduced
        // per event at human posting rates, but it is a record in a loop —
        // ambiguous counts as hot (A7.2's own rule), so it is guarded. (A7)
        if (@sizeOf(usize) == 8) assert(@sizeOf(LivePost) == 112);
    }
};

/// Reduce one Jetstream event to a LivePost, or null for everything this
/// client does not (yet) consume — malformed JSON included: one bad event
/// must not drop the stream (E2/E4).
pub fn reduce(arena: Allocator, event_json: []const u8) error{OutOfMemory}!?LivePost {
    if (!jsonguard.depthWithinLimit(event_json, jsonguard.max_json_depth)) return null;
    const event = std.json.parseFromSliceLeaky(Event, arena, event_json, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };
    if (!std.mem.eql(u8, event.kind, "commit")) return null;
    const commit = event.commit orelse return null;
    if (!std.mem.eql(u8, commit.operation, "create")) return null;
    if (!std.mem.eql(u8, commit.collection, lexicon.collection.post)) return null;
    if (commit.cid.len == 0 or event.did.len == 0 or commit.rkey.len == 0) return null;
    const record = commit.record orelse return null;

    const uri = try std.fmt.allocPrint(arena, "at://{s}/{s}/{s}", .{
        event.did, lexicon.collection.post, commit.rkey,
    });
    var parent_cid: []const u8 = "";
    var root_cid: []const u8 = "";
    if (record.reply) |reply| {
        parent_cid = reply.parent.cid;
        root_cid = reply.root.cid;
    }
    return .{
        .did = event.did,
        .uri = uri,
        .cid = commit.cid,
        .text = record.text,
        .reply_parent_cid = parent_cid,
        .reply_root_cid = root_cid,
        .created_at = feed.parseTimestamp(record.createdAt) catch 0,
        .time_us = event.time_us,
    };
}

/// The subscriber-sourced options_update message: how a client with more
/// DIDs than fit in a URL narrows the stream after connecting.
pub fn buildOptionsUpdate(
    arena: Allocator,
    dids: []const []const u8,
) error{OutOfMemory}![]const u8 {
    const message = .{
        .type = "options_update",
        .payload = .{
            .wantedCollections = [_][]const u8{lexicon.collection.post},
            .wantedDids = dids,
        },
    };
    return std.json.Stringify.valueAlloc(arena, message, .{}) catch error.OutOfMemory;
}

/// Clamp a resume cursor to a short replay window. The server replays by
/// SCANNING its whole firehose DB from the cursor forward (rate-limited),
/// so a stale cursor means minutes of replay burst — and its outbox drops
/// slow subscribers mid-burst. A reconnect only ever needs to cover the
/// gap it just dropped: at most `max_replay_us`, with a small overlap that
/// CID dedup absorbs. Zero stays zero (no cursor; live tail).
pub const max_replay_us: i64 = 60 * std.time.us_per_s;

pub fn clampCursor(saved_us: i64, now_us: i64) i64 {
    if (saved_us <= 0) return 0;
    if (now_us - saved_us > max_replay_us) return now_us - 5 * std.time.us_per_s;
    return saved_us;
}

/// Reconnect backoff schedule (milliseconds): patient, capped, pure.
pub fn streamBackoffMs(attempt: u32) u64 {
    return switch (attempt) {
        0 => 1_000,
        1 => 2_000,
        2 => 5_000,
        3 => 10_000,
        else => 30_000,
    };
}

// ---------------------------------------------------------------------------
// Tests (B2, C6) — fixtures shaped like the real stream
// ---------------------------------------------------------------------------

const testing = std.testing;

const post_event =
    \\{"did":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","time_us":1767323045000001,"kind":"commit",
    \\ "commit":{"rev":"3krev","operation":"create","collection":"app.zat4.feed.post",
    \\ "rkey":"3klive1","cid":"bafyreilive1",
    \\ "record":{"$type":"app.zat4.feed.post","text":"hello from the firehose",
    \\ "createdAt":"2026-01-02T03:04:05Z"}}}
;

const reply_event =
    \\{"did":"did:plc:bbbbbbbbbbbbbbbbbbbbbbbb","time_us":1767323046000002,"kind":"commit",
    \\ "commit":{"rev":"3krev2","operation":"create","collection":"app.zat4.feed.post",
    \\ "rkey":"3klive2","cid":"bafyreilive2",
    \\ "record":{"$type":"app.zat4.feed.post","text":"a live reply","createdAt":"2026-01-02T03:04:06Z",
    \\ "reply":{"root":{"uri":"at://x/app.zat4.feed.post/1","cid":"bafyreiroot"},
    \\          "parent":{"uri":"at://x/app.zat4.feed.post/2","cid":"bafyreiparent"}}}}}
;

test "reduce: a post-create event becomes a LivePost, fields exact" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    const live = (try reduce(arena_state.allocator(), post_event)).?;
    try testing.expectEqualStrings("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", live.did);
    try testing.expectEqualStrings("bafyreilive1", live.cid);
    try testing.expectEqualStrings("hello from the firehose", live.text);
    try testing.expectEqualStrings(
        "at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/app.zat4.feed.post/3klive1",
        live.uri,
    );
    try testing.expectEqual(@as(i64, 1_767_323_045), live.created_at);
    try testing.expectEqual(@as(i64, 1_767_323_045_000_001), live.time_us);
    try testing.expectEqual(@as(usize, 0), live.reply_parent_cid.len);
}

test "reduce: replies carry their thread cids" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    const live = (try reduce(arena_state.allocator(), reply_event)).?;
    try testing.expectEqualStrings("bafyreiparent", live.reply_parent_cid);
    try testing.expectEqualStrings("bafyreiroot", live.reply_root_cid);
}

test "reduce: everything else is null — likes, deletes, identity, garbage" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const like =
        \\{"did":"did:plc:x","time_us":1,"kind":"commit","commit":{"operation":"create",
        \\ "collection":"app.zat4.feed.like","rkey":"r","cid":"c"}}
    ;
    const delete =
        \\{"did":"did:plc:x","time_us":1,"kind":"commit","commit":{"operation":"delete",
        \\ "collection":"app.zat4.feed.post","rkey":"r","cid":"c"}}
    ;
    const identity =
        \\{"did":"did:plc:x","time_us":1,"kind":"identity"}
    ;
    try testing.expectEqual(@as(?LivePost, null), try reduce(arena, like));
    try testing.expectEqual(@as(?LivePost, null), try reduce(arena, delete));
    try testing.expectEqual(@as(?LivePost, null), try reduce(arena, identity));
    try testing.expectEqual(@as(?LivePost, null), try reduce(arena, "not json at all"));
}

test "options_update carries the dids and the collection" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    const message = try buildOptionsUpdate(arena_state.allocator(), &.{
        "did:plc:aaaa", "did:plc:bbbb",
    });
    try testing.expect(std.mem.indexOf(u8, message, "\"type\":\"options_update\"") != null);
    try testing.expect(std.mem.indexOf(u8, message, "did:plc:bbbb") != null);
    try testing.expect(std.mem.indexOf(u8, message, "app.zat4.feed.post") != null);
}

test "backoff: patient and capped" {
    try testing.expectEqual(@as(u64, 1_000), streamBackoffMs(0));
    try testing.expectEqual(@as(u64, 5_000), streamBackoffMs(2));
    try testing.expectEqual(@as(u64, 30_000), streamBackoffMs(9));
}

test "clampCursor: fresh passes, stale clamps to a short window, zero stays zero" {
    const now: i64 = 1_767_323_045_000_000;
    try testing.expectEqual(@as(i64, 0), clampCursor(0, now));
    try testing.expectEqual(now - 10 * std.time.us_per_s, clampCursor(now - 10 * std.time.us_per_s, now));
    try testing.expectEqual(now - 5 * std.time.us_per_s, clampCursor(now - 40 * 60 * std.time.us_per_s, now));
}

test "reduce: real-world createdAt with fractional seconds parses" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const event =
        \\{"did":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","time_us":1,"kind":"commit",
        \\ "commit":{"operation":"create","collection":"app.zat4.feed.post","rkey":"r","cid":"c1",
        \\ "record":{"$type":"app.zat4.feed.post","text":"x","createdAt":"2026-01-02T03:04:05.102Z"}}}
    ;
    const live = (try reduce(arena_state.allocator(), event)).?;
    try testing.expectEqual(@as(i64, 1_767_323_045), live.created_at);
}

test "fuzz: reduce tolerates arbitrary bytes (no crash, no leak)" {
    const fuzzgen = @import("fuzzgen.zig");
    var g = fuzzgen.Gen.init(0x7E7);
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    var buf: [256]u8 = undefined;
    const seeds = [_][]const u8{ post_event, reply_event, "{}", "{\"kind\":\"commit\"}" };
    var i: usize = 0;
    while (i < 2500) : (i += 1) {
        const input = g.next(&buf, &seeds, "{}[]\":,kindcommitrecord0123 .Tz", i);
        _ = arena_state.reset(.retain_capacity);
        _ = reduce(arena_state.allocator(), input) catch {};
    }
}

test "isolation: a well-formed foreign-NSID record never becomes a LivePost (ingress)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const a = arena_state.allocator();
    // A genuine Bluesky post (identical shape, foreign collection) is rejected,
    // as is any third-party NSID — the reducer keys on the exact app.zat4 NSID.
    const bsky = "{\"did\":\"did:plc:x\",\"time_us\":1,\"kind\":\"commit\",\"commit\":{\"operation\":\"create\",\"collection\":\"app.bsky.feed.post\",\"rkey\":\"r\",\"cid\":\"c\",\"record\":{\"$type\":\"app.bsky.feed.post\",\"text\":\"hi\",\"createdAt\":\"2026-01-02T03:04:05Z\"}}}";
    try testing.expectEqual(@as(?LivePost, null), try reduce(a, bsky));
    const custom = "{\"did\":\"did:plc:x\",\"time_us\":1,\"kind\":\"commit\",\"commit\":{\"operation\":\"create\",\"collection\":\"com.example.post\",\"rkey\":\"r\",\"cid\":\"c\",\"record\":{\"text\":\"hi\",\"createdAt\":\"2026-01-02T03:04:05Z\"}}}";
    try testing.expectEqual(@as(?LivePost, null), try reduce(a, custom));
}

test "isolation: every write collection is in the app.zat4 namespace (egress)" {
    // A future typo pointing a write at another network would leak Zat4 content
    // OUT; this freezes the wall on the egress side too (Phase 7).
    inline for (.{
        lexicon.collection.post,    lexicon.collection.like,
        lexicon.collection.repost,  lexicon.collection.follow,
        lexicon.collection.profile, lexicon.collection.loadout,
    }) |nsid| {
        try testing.expect(std.mem.startsWith(u8, nsid, "app.zat4."));
    }
}
