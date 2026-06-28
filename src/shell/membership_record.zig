// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Zat4 — a social-media client built on the AT Protocol.
// Copyright (C) 2026  Connor Avila

//! B1 classification: SHELL. The Zat4 MEMBERSHIP RECORD in the user's own repo
//! (`app.zat4.actor.membership`, rkey "self"). Its mere EXISTENCE marks the DID
//! as a Zat4 member — the source of truth for the returning-vs-first-time sign-in
//! fork (IDENTITY_ENROLLMENT_DESIGN §13.1/§13.2). A self-keyed singleton: read
//! with `getRecord`, upserted with `putRecord`, exactly like the loadout record.
//!
//! NOTE — two different "memberships": this module is the on-NETWORK record in
//! the repo. `membership.zig` is the LOCAL Argon2id credential store (the Zat4
//! password verifier). They are unrelated; do not confuse them.
//!
//! The lexicon wire types do not escape this module (D3): `fetch` reshapes the
//! parsed record into the module-owned `Membership`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const auth = @import("auth.zig");
const lexicon = @import("../core/lexicon.zig");
const feed_core = @import("../core/feed.zig"); // formatTimestamp (shell clock → ISO)
const xrpc = @import("../core/xrpc.zig"); // Param

/// A member's record, reshaped off the wire so the lexicon types stay inside this
/// module (D3). Strings point into the `arena` passed to `fetch`. A7.2: cold
/// struct, size guard waived — one per sign-in membership check, never bulk.
pub const Membership = struct {
    /// How they joined: `lexicon.membership_via.created` (new Zat4 account) or
    /// `.imported` (existing identity brought in via OAuth).
    via: []const u8,
    created_at: []const u8,
    tos_version: []const u8,
    age_confirmed: bool,
};

/// Write (upsert) the session DID's membership record. `via` is one of
/// `lexicon.membership_via.*`; the consent triple is the legally-load-bearing
/// agreement captured at enrollment (§13.3). `now_epoch` (shell clock, B3) stamps
/// both the join time and the consent time — they coincide at enrollment.
/// Returns true on success; a refusal is logged and returns false (the caller
/// decides whether to retry / surface — recording membership is load-bearing).
pub fn put(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    via: []const u8,
    tos_version: []const u8,
    age_confirmed: bool,
    now_epoch: i64,
) !bool {
    var ts_buf: [24]u8 = undefined;
    const ts = feed_core.formatTimestamp(&ts_buf, now_epoch);
    const record = lexicon.MembershipRecordOut{
        .createdAt = ts,
        .via = via,
        .consent = .{
            .tosVersion = tos_version,
            .agreedAt = ts,
            .ageConfirmed = age_confirmed,
        },
    };
    const input = lexicon.PutRecordInput(@TypeOf(record)){
        .repo = session.did,
        .collection = lexicon.collection.membership,
        .rkey = "self",
        .record = record,
    };
    const outcome = try auth.procedure(
        gpa,
        arena,
        io,
        environ,
        session,
        lexicon.method.put_record,
        input,
        lexicon.RecordRef,
    );
    return switch (outcome) {
        .ok => true,
        .failed => |f| {
            std.debug.print("[membership] put failed: {d} {s}: {s}\n", .{ f.status, f.code, f.message });
            return false;
        },
    };
}

/// Read the DID's membership record. Returns the reshaped `Membership` when one
/// exists, or **null** when there is none (a 404) or the read fails — an ordinary
/// "not a member" result, never an error path (E4). This is the fork's question:
/// non-null ⇒ returning member (→ feed); null ⇒ first time (→ enrollment).
/// The returned strings live in `arena`.
pub fn fetch(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    did: []const u8,
) !?Membership {
    const params = [_]xrpc.Param{
        .{ .name = "repo", .value = did },
        .{ .name = "collection", .value = lexicon.collection.membership },
        .{ .name = "rkey", .value = "self" },
    };
    const outcome = try auth.query(
        gpa,
        arena,
        io,
        environ,
        session,
        lexicon.method.get_record,
        &params,
        lexicon.GetRecordResponse(lexicon.MembershipRecord),
    );
    const v = switch (outcome) {
        .ok => |r| r.value,
        .failed => return null, // 404 (no record) or any read failure → "not a member"
    };
    // A present-but-empty document (no createdAt) is treated as absent: the record
    // only counts when it actually carries the membership fields.
    if (v.createdAt.len == 0) return null;
    return .{
        .via = v.via,
        .created_at = v.createdAt,
        .tos_version = v.consent.tosVersion,
        .age_confirmed = v.consent.ageConfirmed,
    };
}

// ── Tests (C6) — the put/fetch round trip and the "not a member" path. ──

const fixture = @import("test_fixture.zig");
const ScriptStep = fixture.ScriptStep;
const serveScript = fixture.serveScript;
const listenLoopback = fixture.listenLoopback;

fn testSession(pds: []const u8) auth.Session {
    return .{
        .did = "did:plc:cccccccccccccccccccccccc",
        .handle = "carol.test",
        .pds_url = pds,
        .access_jwt = "access-1",
        .refresh_jwt = "refresh-1",
    };
}

test "loopback: put upserts the self membership record; fetch reads it back" {
    const gpa = std.testing.allocator; // C6
    const io = std.testing.io;

    var bound = try listenLoopback(io, 38792);
    defer bound.server.deinit(io);
    const thread = try std.Thread.spawn(.{}, serveScript, .{
        &bound.server, io,
        &[_]ScriptStep{
            .{
                .must_contain_head = "POST /xrpc/com.atproto.repo.putRecord",
                .must_contain_body = "\"$type\":\"app.zat4.actor.membership\"",
                .status = .ok,
                .body =
                \\{"uri":"at://did:plc:cccccccccccccccccccccccc/app.zat4.actor.membership/self","cid":"bafymember"}
                ,
            },
            .{
                .must_contain_head = "GET /xrpc/com.atproto.repo.getRecord",
                .status = .ok,
                .body =
                \\{"uri":"at://did:plc:cccccccccccccccccccccccc/app.zat4.actor.membership/self","cid":"bafymember","value":{"$type":"app.zat4.actor.membership","createdAt":"2026-01-02T03:04:05Z","via":"created","consent":{"tosVersion":"v1","agreedAt":"2026-01-02T03:04:05Z","ageConfirmed":true}}}
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
    var session = testSession(pds);

    const wrote = try put(gpa, arena, io, null, &session, lexicon.membership_via.created, "v1", true, 1_767_323_045);
    try std.testing.expect(wrote);

    const m = (try fetch(gpa, arena, io, null, &session, session.did)) orelse return error.ExpectedMember;
    try std.testing.expectEqualStrings("created", m.via);
    try std.testing.expect(m.age_confirmed);
    try std.testing.expectEqualStrings("v1", m.tos_version);
}

test "loopback: fetch returns null (not a member) when the record is absent" {
    const gpa = std.testing.allocator; // C6
    const io = std.testing.io;

    var bound = try listenLoopback(io, 38796);
    defer bound.server.deinit(io);
    const thread = try std.Thread.spawn(.{}, serveScript, .{
        &bound.server, io,
        &[_]ScriptStep{
            .{
                // atproto answers a missing record with 400 RecordNotFound; the
                // read treats any non-2xx as a plain "not a member" (E4).
                .must_contain_head = "GET /xrpc/com.atproto.repo.getRecord",
                .status = .bad_request,
                .body =
                \\{"error":"RecordNotFound","message":"Could not locate record"}
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
    var session = testSession(pds);

    const m = try fetch(gpa, arena, io, null, &session, session.did);
    try std.testing.expect(m == null);
}
