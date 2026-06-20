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

//! B1 classification: SHELL. Public face of the **auth deep module** (D1).
//!
//! Interface, in full: `Session`, `LoginOutcome`, `login`, `freeSession`,
//! `query`, `procedure`. Everything else — the credential mechanism (app
//! passwords today; OAuth later, swapped behind this same interface per the
//! recorded Phase 3 decision), bearer formatting, the ExpiredToken
//! refresh-and-retry choreography, token rotation — is hidden interior
//! (D2/D3). The exit-criterion promise is structural: the rest of the app
//! calls `auth.query`/`auth.procedure` and obtains a valid token without
//! knowing how.
//!
//! Refresh is REACTIVE by design: we never parse JWTs or consult a clock to
//! predict expiry — the server says `ExpiredToken`, we refresh once, we
//! retry once. No clock in the decision (the purest reading of B4: even
//! this shell module takes no time dependency), no clock-skew bugs, no
//! token introspection to churn when the token format does.
//!
//! Two allocators by design (C3): `gpa` owns the long-lived Session strings
//! and pays only for token rotation; `arena` is the caller's per-request
//! arena and absorbs every transient (URLs, bodies, bearer strings, decoded
//! outcomes). One unit of work, one arena — and a session that outlives
//! many of them.

const std = @import("std");
const Allocator = std.mem.Allocator;
const xrpc = @import("xrpc.zig");
const lexicon = @import("../core/lexicon.zig");

/// An authenticated session — plain values (A1), every string owned by the
/// `gpa` given to `login`. Free with `freeSession`. Callers read `did`,
/// `handle`, `pds_url`; the jwt fields are data like any other (D5:
/// records get no encapsulation — the SUBSYSTEM is the sealed thing), but
/// only this module has a reason to touch them.
/// A7.2: cold struct, size guard waived — one per logged-in account.
pub const Session = struct {
    did: []const u8,
    handle: []const u8,
    pds_url: []const u8,
    access_jwt: []const u8,
    refresh_jwt: []const u8,
};

/// Login resolves to a session or the server's stated refusal (wrong
/// password, 2FA required, rate limit) — a routine outcome carried as plain
/// data the caller can show or branch on (E4). Zig errors remain reserved
/// for transport/codec failure (E3). `refused` strings live in the arena
/// passed to `login`.
pub const LoginOutcome = union(enum) {
    ok: Session,
    refused: xrpc.Failure,
};

/// Establish a session against `pds_url` with an identifier (handle or DID)
/// and an app password, via `com.atproto.server.createSession`.
pub fn login(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    pds_url: []const u8,
    identifier: []const u8,
    password: []const u8,
) !LoginOutcome {
    const outcome = try xrpc.procedure(
        arena,
        io,
        environ,
        pds_url,
        lexicon.method.create_session,
        lexicon.CreateSessionInput{ .identifier = identifier, .password = password },
        lexicon.SessionResponse,
        .{},
    );
    switch (outcome) {
        .failed => |failure| return .{ .refused = failure },
        .ok => |resp| return .{ .ok = try dupeSession(gpa, pds_url, resp) },
    }
}

/// Free a `Session` produced by `login` (A1: behavior as a free function).
pub fn freeSession(gpa: Allocator, session: Session) void {
    gpa.free(session.did);
    gpa.free(session.handle);
    gpa.free(session.pds_url);
    gpa.free(session.access_jwt);
    gpa.free(session.refresh_jwt);
}

/// Authenticated XRPC query against the session's own PDS. On
/// `ExpiredToken`, refreshes the session in place (token rotation pays from
/// `gpa`) and retries exactly once. Any other refusal — including a failed
/// refresh — comes back as the `Failure` value for the caller to act on
/// (`InvalidToken` there means the session is dead: re-login).
pub fn query(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *Session,
    nsid: []const u8,
    params: []const xrpc.Param,
    comptime Response: type,
) !xrpc.Outcome(Response) {
    return queryHost(gpa, arena, io, environ, session, session.pds_url, nsid, params, Response);
}

/// Authenticated XRPC query against an EXPLICIT host — the seam Phase B
/// needs (STANDALONE_ROADMAP): reads target the Zat4 AppView, not the
/// user's PDS, while still carrying the session's bearer token (the AppView
/// authenticates the requester to serve a personalized timeline) and the
/// same refresh-and-retry-once choreography. The token REFRESH still goes to
/// the PDS inside `refreshInPlace` — refresh is a protocol operation on the
/// user's own server, never on the AppView. `query` above is the PDS-host
/// convenience over this.
pub fn queryHost(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *Session,
    host: []const u8,
    nsid: []const u8,
    params: []const xrpc.Param,
    comptime Response: type,
) !xrpc.Outcome(Response) {
    // The Zat4 AppView gates on a SHARED bearer token (appview_serve.zig), not
    // the user's PDS session JWT. When ZAT_APPVIEW_TOKEN is configured, send it
    // for AppView-host calls — a shared token does not expire, so the refresh-
    // and-retry dance below (a PDS protocol op on the session JWT) does not
    // apply and is skipped. PDS-host calls (the `query` convenience above passes
    // `session.pds_url`) MUST keep the session JWT, so the token is scoped to a
    // host that is NOT the user's PDS.
    if (!std.mem.eql(u8, host, session.pds_url)) {
        const appview_token: ?[]const u8 = if (environ) |e| e.get("ZAT_APPVIEW_TOKEN") else null;
        if (appview_token) |tok| {
            if (tok.len > 0) {
                return xrpc.query(arena, io, environ, host, nsid, params, Response, .{
                    .authorization = try bearer(arena, tok),
                });
            }
        }
    }

    const first = try xrpc.query(arena, io, environ, host, nsid, params, Response, .{
        .authorization = try bearer(arena, session.access_jwt),
    });
    switch (first) {
        .ok => return first,
        .failed => |failure| if (!shouldRefresh(failure)) return first,
    }
    switch (try refreshInPlace(gpa, arena, io, environ, session)) {
        .failed => |failure| return .{ .failed = failure },
        .ok => {},
    }
    return xrpc.query(arena, io, environ, host, nsid, params, Response, .{
        .authorization = try bearer(arena, session.access_jwt),
    });
}

/// Authenticated XRPC procedure with the same refresh-and-retry-once
/// choreography as `query`. A 429-refused procedure was never processed, so
/// the retry (in xrpc) and the refresh-retry (here) are safe for writes.
pub fn procedure(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *Session,
    nsid: []const u8,
    input: anytype,
    comptime Response: type,
) !xrpc.Outcome(Response) {
    const first = try xrpc.procedure(arena, io, environ, session.pds_url, nsid, input, Response, .{
        .authorization = try bearer(arena, session.access_jwt),
    });
    switch (first) {
        .ok => return first,
        .failed => |failure| if (!shouldRefresh(failure)) return first,
    }
    switch (try refreshInPlace(gpa, arena, io, environ, session)) {
        .failed => |failure| return .{ .failed = failure },
        .ok => {},
    }
    return xrpc.procedure(arena, io, environ, session.pds_url, nsid, input, Response, .{
        .authorization = try bearer(arena, session.access_jwt),
    });
}

// ---------------------------------------------------------------------------
// Interior
// ---------------------------------------------------------------------------

/// Pure decision (core-grade logic, colocated: one line does not earn a
/// core file yet — F4; it moves the day refresh policy grows).
fn shouldRefresh(failure: xrpc.Failure) bool {
    return std.mem.eql(u8, failure.code, "ExpiredToken");
}

fn bearer(arena: Allocator, jwt: []const u8) Allocator.Error![]u8 {
    return std.fmt.allocPrint(arena, "Bearer {s}", .{jwt});
}

/// `com.atproto.server.refreshSession`: POST with the REFRESH token as
/// bearer and no body. On success both tokens rotate in place — new strings
/// duped into `gpa` before the old pair is freed (C5: no window where the
/// session holds freed memory).
fn refreshInPlace(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *Session,
) !xrpc.Outcome(void) {
    const outcome = try xrpc.procedure(
        arena,
        io,
        environ,
        session.pds_url,
        lexicon.method.refresh_session,
        null, // no input body
        lexicon.SessionResponse,
        .{ .authorization = try bearer(arena, session.refresh_jwt) },
    );
    switch (outcome) {
        .failed => |failure| return .{ .failed = failure },
        .ok => |resp| {
            const new_access = try gpa.dupe(u8, resp.accessJwt);
            errdefer gpa.free(new_access);
            const new_refresh = try gpa.dupe(u8, resp.refreshJwt);
            gpa.free(session.access_jwt);
            gpa.free(session.refresh_jwt);
            session.access_jwt = new_access;
            session.refresh_jwt = new_refresh;
            return .{ .ok = {} };
        },
    }
}

/// Copy the response strings out of the arena into the session's allocator.
/// C5: errdefer chain releases partial work on a mid-sequence OOM.
fn dupeSession(gpa: Allocator, pds_url: []const u8, resp: lexicon.SessionResponse) Allocator.Error!Session {
    const did = try gpa.dupe(u8, resp.did);
    errdefer gpa.free(did);
    const handle = try gpa.dupe(u8, resp.handle);
    errdefer gpa.free(handle);
    const pds = try gpa.dupe(u8, pds_url);
    errdefer gpa.free(pds);
    const access = try gpa.dupe(u8, resp.accessJwt);
    errdefer gpa.free(access);
    const refresh = try gpa.dupe(u8, resp.refreshJwt);
    return .{ .did = did, .handle = handle, .pds_url = pds, .access_jwt = access, .refresh_jwt = refresh };
}

// ---------------------------------------------------------------------------
// Loopback round trips — a scripted fixture PDS on 127.0.0.1 plays each
// step; every step demands the right substrings on the wire (request line,
// authorization header) or answers 418, so the client-side assertions are
// the oracle. Real sockets, real HTTP, ordinary `zig build test`, leak
// detector on (C6).
// ---------------------------------------------------------------------------

/// One scripted exchange. A7.2: cold struct, size guard waived — test
/// scaffolding.
const fixture = @import("test_fixture.zig");
const ScriptStep = fixture.ScriptStep;
const serveScript = fixture.serveScript;
const listenLoopback = fixture.listenLoopback;

fn testSession(gpa: Allocator, port: u16) !Session {
    var url_buf: [48]u8 = undefined;
    const pds = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}", .{port});
    return dupeSession(gpa, pds, .{
        .did = "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
        .handle = "alice.test",
        .accessJwt = "access-old",
        .refreshJwt = "refresh-old",
    });
}

test "loopback round trip: login POSTs credentials, session strings owned by gpa" {
    const gpa = std.testing.allocator; // C6
    const io = std.testing.io;

    var bound = try listenLoopback(io, 38630);
    defer bound.server.deinit(io);
    const thread = try std.Thread.spawn(.{}, serveScript, .{
        &bound.server, io,
        &[_]ScriptStep{
            .{
                .must_contain_head = "POST /xrpc/com.atproto.server.createSession",
                .must_contain_head_b = "content-type: application/json",
                .status = .ok,
                .body =
                \\{"accessJwt":"access-1","refreshJwt":"refresh-1",
                \\ "handle":"alice.test","did":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"}
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

    const outcome = try login(gpa, arena, io, null, pds, "alice.test", "app-password-1234");
    const session = outcome.ok;
    defer freeSession(gpa, session);

    try std.testing.expectEqualStrings("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", session.did);
    try std.testing.expectEqualStrings("access-1", session.access_jwt);
    try std.testing.expectEqualStrings("refresh-1", session.refresh_jwt);
    try std.testing.expectEqualStrings(pds, session.pds_url);
}

test "loopback round trip: a login refusal is a value the caller can show" {
    const gpa = std.testing.allocator; // C6
    const io = std.testing.io;

    var bound = try listenLoopback(io, 38652);
    defer bound.server.deinit(io);
    const thread = try std.Thread.spawn(.{}, serveScript, .{
        &bound.server, io,
        &[_]ScriptStep{
            .{
                .must_contain_head = "POST /xrpc/com.atproto.server.createSession",
                .must_contain_head_b = "content-type: application/json",
                .status = .unauthorized,
                .body =
                \\{"error":"AuthenticationRequired","message":"Invalid identifier or password"}
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

    const outcome = try login(gpa, arena, io, null, pds, "alice.test", "wrong");
    try std.testing.expectEqual(@as(u16, 401), outcome.refused.status);
    try std.testing.expectEqualStrings("AuthenticationRequired", outcome.refused.code);
}

test "loopback round trip: ExpiredToken triggers refresh, tokens rotate, call retried once" {
    const gpa = std.testing.allocator; // C6
    const io = std.testing.io;

    var bound = try listenLoopback(io, 38674);
    defer bound.server.deinit(io);
    const thread = try std.Thread.spawn(.{}, serveScript, .{
        &bound.server, io,
        &[_]ScriptStep{
            // 1. The original call, with the stale access token -> ExpiredToken.
            .{
                .must_contain_head = "GET /xrpc/com.atproto.server.getSession",
                .must_contain_head_b = "authorization: Bearer access-old",
                .status = .bad_request,
                .body =
                \\{"error":"ExpiredToken","message":"Token has expired"}
                ,
            },
            // 2. The refresh, authenticated with the REFRESH token, no body.
            .{
                .must_contain_head = "POST /xrpc/com.atproto.server.refreshSession",
                .must_contain_head_b = "authorization: Bearer refresh-old",
                .status = .ok,
                .body =
                \\{"accessJwt":"access-new","refreshJwt":"refresh-new",
                \\ "handle":"alice.test","did":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"}
                ,
            },
            // 3. The retried call, now carrying the rotated access token.
            .{
                .must_contain_head = "GET /xrpc/com.atproto.server.getSession",
                .must_contain_head_b = "authorization: Bearer access-new",
                .status = .ok,
                .body =
                \\{"did":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","handle":"alice.test"}
                ,
            },
        },
    });
    defer thread.join();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var session = try testSession(gpa, bound.port);
    defer freeSession(gpa, session);

    const outcome = try query(gpa, arena, io, null, &session, lexicon.method.get_session, &.{}, lexicon.GetSessionResponse);

    try std.testing.expectEqualStrings("alice.test", outcome.ok.handle);
    try std.testing.expectEqualStrings("access-new", session.access_jwt);
    try std.testing.expectEqualStrings("refresh-new", session.refresh_jwt);
}

test "loopback round trip: a dead refresh token surfaces as a value; session is unchanged" {
    const gpa = std.testing.allocator; // C6
    const io = std.testing.io;

    var bound = try listenLoopback(io, 38696);
    defer bound.server.deinit(io);
    const thread = try std.Thread.spawn(.{}, serveScript, .{
        &bound.server, io,
        &[_]ScriptStep{
            .{
                .must_contain_head = "GET /xrpc/com.atproto.server.getSession",
                .must_contain_head_b = "authorization: Bearer access-old",
                .status = .bad_request,
                .body =
                \\{"error":"ExpiredToken","message":"Token has expired"}
                ,
            },
            .{
                .must_contain_head = "POST /xrpc/com.atproto.server.refreshSession",
                .must_contain_head_b = "authorization: Bearer refresh-old",
                .status = .bad_request,
                .body =
                \\{"error":"InvalidToken","message":"Refresh token revoked"}
                ,
            },
        },
    });
    defer thread.join();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var session = try testSession(gpa, bound.port);
    defer freeSession(gpa, session);

    const outcome = try query(gpa, arena, io, null, &session, lexicon.method.get_session, &.{}, lexicon.GetSessionResponse);

    try std.testing.expectEqualStrings("InvalidToken", outcome.failed.code);
    // The session was not corrupted by the failed rotation (E2).
    try std.testing.expectEqualStrings("access-old", session.access_jwt);
    try std.testing.expectEqualStrings("refresh-old", session.refresh_jwt);
}
