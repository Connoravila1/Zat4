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

//! B1 classification: CORE (pure). The sealed **Tap wire module** (D1): a
//! Tap `/channel` message (JSON) in, a plain `Event` value out. Tap
//! (bluesky-social/indigo) subscribes to the relay firehose, backfills +
//! streams the repos that post a signal collection, and emits filtered events;
//! it is the SCALE path that replaces PDS polling (STANDALONE_ROADMAP "Cut 2").
//! Like every wire format here, Tap's shapes never leak — the consumer sees
//! only `Event`, a struct of plain values.
//!
//! Two message types (verified against real `/channel` output, captured in
//! test_fixtures/tap_channel_sample.jsonl):
//!   identity: {"id":N,"type":"identity","identity":{did,handle,is_active,status}}
//!   record:   {"id":N,"type":"record","record":{did,collection,rkey,action,
//!                                                record:{…},cid}}
//! The inner `record.subject` is union-typed exactly as the firehose: a bare
//! DID string for a follow, a {cid,uri} strong-ref for a like/repost — read via
//! a generic json.Value (the same tactic as shell/appview_ingest.zig, F2).
//!
//! Scope, recorded (F4): v1 reduces `app.zat4.*` CREATEs (post/follow/like/
//! repost) + identity. updates/deletes reduce to `.ignored` (count tombstones,
//! moderation takedowns) — deferred, named, absent. EVERY message still carries
//! its `id` so the consumer advances its resume cursor past ignored events too.

const std = @import("std");
const Allocator = std.mem.Allocator;
const lexicon = @import("lexicon.zig");

/// Like/repost discriminator — a plain value the consumer maps to its index.
pub const EngagementKind = enum { like, repost };

/// What a reduced Tap message asks the consumer to do. Plain values; strings
/// borrow the reduction arena (E1 — the consumer copies what it keeps).
pub const Reduced = union(enum) {
    /// Not a create we index (an identity-only signal carries no record, an
    /// update/delete, or a non-zat4 collection that slipped the server filter).
    ignored,
    identity: struct { did: []const u8, handle: []const u8 },
    post: struct {
        did: []const u8, // author
        cid: []const u8, // the post record's own cid (the index key)
        rkey: []const u8,
        text: []const u8,
        created_at: []const u8,
        reply_parent_cid: []const u8 = "", // "" when not a reply
        reply_root_cid: []const u8 = "",
    },
    follow: struct {
        did: []const u8, // follower
        subject_did: []const u8, // followed
        record_cid: []const u8, // the follow record's cid (dedup key)
    },
    engagement: struct {
        kind: EngagementKind,
        did: []const u8, // actor
        subject_cid: []const u8, // the engaged post's cid
        record_cid: []const u8, // the like/repost record's cid (dedup key)
    },
};

/// A reduced Tap message: its outbox `id` (the resume cursor) + what to do.
/// A7.2: cold struct, size guard waived — a transient reduce result, one per
/// message, decomposed immediately by the consumer.
pub const Event = struct {
    id: i64,
    reduced: Reduced,
};

// --- wire shapes (transient parse targets, all A7.2) ---

/// A7.2: cold struct, size guard waived — transient parse target. `subject` is
/// a generic Value: a DID string for a follow, a {cid,uri} object for a
/// like/repost.
const InnerRecord = struct {
    text: []const u8 = "",
    createdAt: []const u8 = "",
    subject: std.json.Value = .null,
    /// A post's reply refs (root + parent strong refs); null on a non-reply.
    reply: ?lexicon.ReplyRefOut = null,
};

/// A7.2: cold struct, size guard waived — transient parse target.
const RecordEnvelope = struct {
    did: []const u8 = "",
    collection: []const u8 = "",
    rkey: []const u8 = "",
    action: []const u8 = "",
    cid: []const u8 = "",
    record: ?InnerRecord = null,
};

/// A7.2: cold struct, size guard waived — transient parse target.
const IdentityBody = struct {
    did: []const u8 = "",
    handle: []const u8 = "",
};

/// A7.2: cold struct, size guard waived — transient parse target.
const Message = struct {
    id: i64 = 0,
    type: []const u8 = "",
    record: ?RecordEnvelope = null,
    identity: ?IdentityBody = null,
};

/// Reduce one Tap `/channel` message to an `Event`, or null for unparseable
/// input — one bad frame must not drop the stream (E2/E4). A well-formed
/// message that is not an indexed create still returns an `Event` (with
/// `.ignored` and its `id`) so the consumer's cursor advances.
pub fn reduce(arena: Allocator, message_json: []const u8) error{OutOfMemory}!?Event {
    const msg = std.json.parseFromSliceLeaky(Message, arena, message_json, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return null,
    };

    if (std.mem.eql(u8, msg.type, "identity")) {
        const ident = msg.identity orelse return .{ .id = msg.id, .reduced = .ignored };
        if (ident.did.len == 0) return .{ .id = msg.id, .reduced = .ignored };
        return .{ .id = msg.id, .reduced = .{ .identity = .{ .did = ident.did, .handle = ident.handle } } };
    }

    if (!std.mem.eql(u8, msg.type, "record")) return .{ .id = msg.id, .reduced = .ignored };
    const env = msg.record orelse return .{ .id = msg.id, .reduced = .ignored };

    // Cut-1: only creates are indexed (update/delete deferred, named above).
    if (!std.mem.eql(u8, env.action, "create") or env.cid.len == 0 or env.did.len == 0) {
        return .{ .id = msg.id, .reduced = .ignored };
    }
    const rec = env.record orelse return .{ .id = msg.id, .reduced = .ignored };

    if (std.mem.eql(u8, env.collection, lexicon.collection.post)) {
        return .{ .id = msg.id, .reduced = .{ .post = .{
            .did = env.did,
            .cid = env.cid,
            .rkey = env.rkey,
            .text = rec.text,
            .created_at = rec.createdAt,
            .reply_parent_cid = if (rec.reply) |rep| rep.parent.cid else "",
            .reply_root_cid = if (rec.reply) |rep| rep.root.cid else "",
        } } };
    }
    if (std.mem.eql(u8, env.collection, lexicon.collection.follow)) {
        const subject = followSubject(rec);
        if (subject.len == 0) return .{ .id = msg.id, .reduced = .ignored };
        return .{ .id = msg.id, .reduced = .{ .follow = .{
            .did = env.did,
            .subject_did = subject,
            .record_cid = env.cid,
        } } };
    }
    const eng: ?EngagementKind =
        if (std.mem.eql(u8, env.collection, lexicon.collection.like)) .like
        else if (std.mem.eql(u8, env.collection, lexicon.collection.repost)) .repost
        else null;
    if (eng) |kind| {
        const subject_cid = engagementSubjectCid(rec);
        if (subject_cid.len == 0) return .{ .id = msg.id, .reduced = .ignored };
        return .{ .id = msg.id, .reduced = .{ .engagement = .{
            .kind = kind,
            .did = env.did,
            .subject_cid = subject_cid,
            .record_cid = env.cid,
        } } };
    }
    return .{ .id = msg.id, .reduced = .ignored };
}

/// The followed DID, when `subject` is a bare string (a follow record).
fn followSubject(rec: InnerRecord) []const u8 {
    return switch (rec.subject) {
        .string => |s| s,
        else => "",
    };
}

/// The subject post's cid, when `subject` is a strong-ref object (like/repost).
fn engagementSubjectCid(rec: InnerRecord) []const u8 {
    return switch (rec.subject) {
        .object => |o| if (o.get("cid")) |v| switch (v) {
            .string => |s| s,
            else => "",
        } else "",
        else => "",
    };
}

// ---------------------------------------------------------------------------
// Tests (B2, C6) — the real captured /channel messages, inline (the codebase
// fixture pattern; the full capture lives in test_fixtures/tap_channel_sample.jsonl).
// ---------------------------------------------------------------------------

const testing = std.testing;

test "reduce: a post create becomes a post Event, fields exact" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const msg =
        \\{"id":3,"type":"record","record":{"live":false,"did":"did:plc:25ibud7srapkgasajlrnpxm3","rev":"3molxwaxioe2v","collection":"app.zat4.feed.post","rkey":"3mogxbez6xc24","action":"create","record":{"$type":"app.zat4.feed.post","createdAt":"2026-06-16T23:28:57Z","text":"Hi mom!"},"cid":"bafyreicfulxdjrjl3vvntoqj7ozbkaij65izrtgiqujqluue6gztr2ns2y"}}
    ;
    const ev = (try reduce(arena_state.allocator(), msg)).?;
    try testing.expectEqual(@as(i64, 3), ev.id);
    try testing.expectEqualStrings("did:plc:25ibud7srapkgasajlrnpxm3", ev.reduced.post.did);
    try testing.expectEqualStrings("bafyreicfulxdjrjl3vvntoqj7ozbkaij65izrtgiqujqluue6gztr2ns2y", ev.reduced.post.cid);
    try testing.expectEqualStrings("3mogxbez6xc24", ev.reduced.post.rkey);
    try testing.expectEqualStrings("Hi mom!", ev.reduced.post.text);
    try testing.expectEqualStrings("2026-06-16T23:28:57Z", ev.reduced.post.created_at);
}

test "reduce: a follow create carries follower + subject + record cid" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const msg =
        \\{"id":7,"type":"record","record":{"live":false,"did":"did:plc:25ibud7srapkgasajlrnpxm3","collection":"app.zat4.graph.follow","rkey":"3molxw3glhq2n","action":"create","record":{"$type":"app.zat4.graph.follow","createdAt":"2026-06-18T23:23:47Z","subject":"did:plc:t3v6z5csflxtdp4tlo2alxuw"},"cid":"bafyreihvuhuicdaykx6bkrqpjpjowclnrmkq5gi7ea4yw5hmtmhncgzldq"}}
    ;
    const ev = (try reduce(arena_state.allocator(), msg)).?;
    try testing.expectEqualStrings("did:plc:25ibud7srapkgasajlrnpxm3", ev.reduced.follow.did);
    try testing.expectEqualStrings("did:plc:t3v6z5csflxtdp4tlo2alxuw", ev.reduced.follow.subject_did);
    try testing.expectEqualStrings("bafyreihvuhuicdaykx6bkrqpjpjowclnrmkq5gi7ea4yw5hmtmhncgzldq", ev.reduced.follow.record_cid);
}

test "reduce: a like create carries the subject post cid + record cid" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const msg =
        \\{"id":2,"type":"record","record":{"live":false,"did":"did:plc:25ibud7srapkgasajlrnpxm3","collection":"app.zat4.feed.like","rkey":"3mobzohw26h2k","action":"create","record":{"$type":"app.zat4.feed.like","createdAt":"2026-06-15T00:28:44Z","subject":{"cid":"bafyreibmvopozfxg5rcbhstbwes6mukzhwt3owfb6zv4cujvbqqkjavuvq","uri":"at://did:plc:nzvnzrl2n6mf5msz7pttr45b/app.bsky.feed.post/3mo7hfnj53c24"}},"cid":"bafyreihtgjmfnuagdbi6g5efudftn5dqbmumktceetiweqsmm2dfn3j5qu"}}
    ;
    const ev = (try reduce(arena_state.allocator(), msg)).?;
    try testing.expectEqual(EngagementKind.like, ev.reduced.engagement.kind);
    try testing.expectEqualStrings("bafyreibmvopozfxg5rcbhstbwes6mukzhwt3owfb6zv4cujvbqqkjavuvq", ev.reduced.engagement.subject_cid);
    try testing.expectEqualStrings("bafyreihtgjmfnuagdbi6g5efudftn5dqbmumktceetiweqsmm2dfn3j5qu", ev.reduced.engagement.record_cid);
}

test "reduce: an identity message reduces to identity (did + handle)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const msg =
        \\{"id":1,"type":"identity","identity":{"did":"did:plc:25ibud7srapkgasajlrnpxm3","handle":"connor.zat4.com","is_active":true,"status":"active"}}
    ;
    const ev = (try reduce(arena_state.allocator(), msg)).?;
    try testing.expectEqual(@as(i64, 1), ev.id);
    try testing.expectEqualStrings("connor.zat4.com", ev.reduced.identity.handle);
}

test "reduce: a delete (and a non-zat4 collection) reduces to ignored but keeps its id" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const del =
        \\{"id":9,"type":"record","record":{"did":"did:plc:a","collection":"app.zat4.feed.post","rkey":"r","action":"delete","cid":"c"}}
    ;
    const ev = (try reduce(arena, del)).?;
    try testing.expectEqual(@as(i64, 9), ev.id);
    try testing.expect(ev.reduced == .ignored); // delete deferred, but cursor advances

    // Garbage is dropped entirely (null), never crashes the stream.
    try testing.expectEqual(@as(?Event, null), try reduce(arena, "not json"));
}

test {
    std.testing.refAllDecls(@This());
}
