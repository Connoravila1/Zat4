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

//! B1 classification: SHELL. Public face of the **XRPC deep module** (D1).
//!
//! Interface, in full: `Param`, `Failure`, `Outcome`, `query`, `procedure`.
//! XRPC is atproto's RPC-over-HTTP — queries are GET, procedures are POST,
//! methods are NSIDs like `app.zat4.feed.getTimeline`. How URLs are spelled,
//! how values are escaped, how JSON becomes typed records, what an error
//! body looks like — all of that is the sealed wire-format decision living
//! in src/core/xrpc.zig, internal to this module (D2/D3). Callers hand in
//! plain values and a lexicon record type; they get plain values back (B5).
//! No std.json, no std.http, no URL string ever crosses this boundary.
//!
//! Failure model (E3/E4, the line drawn on purpose):
//!   * Zig errors  = our side broke: transport failure, budget exceeded,
//!     malformed response body, OOM. Explicit in the signature.
//!   * `Outcome.failed` = the SERVER refused: a routine protocol outcome
//!     carried as plain data (status + code + message) that callers branch
//!     on — Phase 3 will branch on `code == "ExpiredToken"` to refresh.

const std = @import("std");
const Allocator = std.mem.Allocator;
const http = @import("http.zig");
const core = @import("../core/xrpc.zig");

pub const Param = core.Param;
pub const Failure = core.Failure;

/// Per-call knobs the caller controls. The auth module supplies
/// `authorization`; unauthenticated callers pass `.{}`.
/// A7.2: cold struct (per-call configuration), size guard waived.
pub const CallOptions = struct {
    /// Full authorization header value (e.g. "Bearer <jwt>").
    authorization: ?[]const u8 = null,
};

/// Every call resolves to exactly one of these. A tagged union of plain
/// data — Zig will not let a caller forget to look (E3: no forgettable
/// sentinel).
pub fn Outcome(comptime Response: type) type {
    return union(enum) {
        ok: Response,
        failed: Failure,
    };
}

/// A typed outcome plus the raw 2xx response body (arena-owned) — what
/// `queryCapturingBody` returns. Named (not an anonymous literal) so the
/// internal engine and the public wrapper share ONE type.
pub fn Captured(comptime Response: type) type {
    return struct { outcome: Outcome(Response), body: []const u8 };
}

/// Call an XRPC query (GET). `Response` is the lexicon record type to decode
/// into (comptime — F2: reflection, not generated codecs).
///
/// C1/C3: `arena` is the single allocator and must be arena-like — the URL,
/// transport body, and every slice inside the returned outcome live in it
/// and are freed wholesale by the caller's `deinit`. One unit of work, one
/// arena.
pub fn query(
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    host: []const u8,
    nsid: []const u8,
    params: []const Param,
    comptime Response: type,
    call_options: CallOptions,
) !Outcome(Response) {
    const url = try core.buildQueryUrl(arena, host, nsid, params);
    return fetchWithRetry(Response, arena, io, environ, url, .{
        .accept = "application/json",
        .authorization = call_options.authorization,
    });
}

/// Call an XRPC procedure (POST). `input` is a plain record serialized as
/// the JSON body (null optionals omitted). Same arena contract as `query`.
pub fn procedure(
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    host: []const u8,
    nsid: []const u8,
    input: anytype,
    comptime Response: type,
    call_options: CallOptions,
) !Outcome(Response) {
    const url = try core.buildMethodUrl(arena, host, nsid);
    // Some procedures (refreshSession) take no input at all: pass `null` and
    // no body or content-type goes on the wire. Comptime branch — F2.
    const body: ?[]const u8 = if (@TypeOf(input) == @TypeOf(null))
        null
    else
        try core.encodeBody(arena, input);
    return fetchWithRetry(Response, arena, io, environ, url, .{
        .method = .POST,
        .body = body,
        .content_type = if (body != null) "application/json" else null,
        .accept = "application/json",
        .authorization = call_options.authorization,
    });
}

/// Issue the request, retrying a 429 on the pure schedule the core dictates
/// (the core decides, this shell owns the clock — B3). 2xx decodes into the
/// typed record; anything else — including a 429 that outlived the schedule
/// — is classified into a `Failure` value. All arms allocate only from the
/// arena (bounded: at most three attempts' bodies live in it).
fn fetchWithRetry(
    comptime Response: type,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    url: []const u8,
    request_options: http.RequestOptions,
) !Outcome(Response) {
    return (try fetchWithRetryBody(Response, arena, io, environ, url, request_options)).outcome;
}

/// The retry/classify engine, also surfacing the raw response body so the
/// capturing variant can hand it back. `query`/`procedure` discard the body.
fn fetchWithRetryBody(
    comptime Response: type,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    url: []const u8,
    request_options: http.RequestOptions,
) !Captured(Response) {
    var attempt: usize = 0;
    while (true) {
        const resp = try http.request(arena, io, environ, url, request_options);
        if (resp.status == 429) {
            if (core.rateLimitRetryDelayMs(attempt)) |delay_ms| {
                attempt += 1;
                try io.sleep(.fromMilliseconds(@intCast(delay_ms)), .awake);
                continue;
            }
        }
        if (resp.status < 200 or resp.status > 299) {
            return .{ .outcome = .{ .failed = try core.parseFailure(arena, resp.status, resp.body) }, .body = resp.body };
        }
        return .{ .outcome = .{ .ok = try core.decode(Response, arena, resp.body) }, .body = resp.body };
    }
}

/// Like `query`, but ALSO returns the raw 2xx response body (arena-owned). For
/// the one caller that must re-examine the wire bytes after the typed decode:
/// the AppView ingest re-hashes each record to verify its CID against the PDS's
/// claim (verify-don't-trust, the trust boundary). `body` carries the error
/// body on a refusal. Only OPAQUE bytes cross — no wire-format TYPE leaks, so
/// the D3 seal holds; the caller re-parses with the sanctioned dagjson path.
pub fn queryCapturingBody(
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    host: []const u8,
    nsid: []const u8,
    params: []const Param,
    comptime Response: type,
    call_options: CallOptions,
) !Captured(Response) {
    const url = try core.buildQueryUrl(arena, host, nsid, params);
    return fetchWithRetryBody(Response, arena, io, environ, url, .{
        .accept = "application/json",
        .authorization = call_options.authorization,
    });
}

// ---------------------------------------------------------------------------
// Loopback round trips — real sockets, real HTTP, no external network.
// A fixture server on 127.0.0.1 plays the AppView/PDS; the tests drive the
// module's actual build -> fetch -> classify -> decode path end to end,
// in the ordinary `zig build test` suite under the leak detector (C6).
// ---------------------------------------------------------------------------

const lexicon = @import("../core/lexicon.zig");

const profile_fixture =
    \\{"did":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","handle":"alice.test",
    \\ "displayName":"Alice","followersCount":12,"followsCount":34,"postsCount":56}
;

const fixture = @import("test_fixture.zig");
const listenLoopback = fixture.listenLoopback;
const serveScript = fixture.serveScript;

test "loopback round trip: query -> typed lexicon record (params escaped on the wire)" {
    const gpa = std.testing.allocator; // C6
    const io = std.testing.io;

    var bound = try listenLoopback(io, 38560);
    defer bound.server.deinit(io);
    const steps = [_]fixture.ScriptStep{.{
        .must_contain_head = "/xrpc/app.zat4.actor.getProfile?actor=alice.test",
        .status = .ok,
        .body = profile_fixture,
    }};
    const thread = try std.Thread.spawn(.{}, serveScript, .{ &bound.server, io, &steps });
    defer thread.join();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var host_buf: [48]u8 = undefined;
    const host = try std.fmt.bufPrint(&host_buf, "http://127.0.0.1:{d}", .{bound.port});

    const outcome = try query(arena, io, null, host, lexicon.method.get_profile, &.{
        .{ .name = "actor", .value = "alice.test" },
    }, lexicon.ProfileViewDetailed, .{});

    try std.testing.expectEqualStrings("alice.test", outcome.ok.handle);
    try std.testing.expectEqualStrings("Alice", outcome.ok.displayName.?);
    try std.testing.expectEqual(@as(u64, 56), outcome.ok.postsCount);
}

test "loopback round trip: server refusal becomes a Failure value, not a Zig error" {
    const gpa = std.testing.allocator; // C6
    const io = std.testing.io;

    var bound = try listenLoopback(io, 38582);
    defer bound.server.deinit(io);
    const steps = [_]fixture.ScriptStep{.{
        .must_contain_head = "/xrpc/app.zat4.actor.getProfile?actor=missing.test",
        .status = .bad_request,
        .body =
        \\{"error":"InvalidRequest","message":"Profile not found"}
        ,
    }};
    const thread = try std.Thread.spawn(.{}, serveScript, .{ &bound.server, io, &steps });
    defer thread.join();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var host_buf: [48]u8 = undefined;
    const host = try std.fmt.bufPrint(&host_buf, "http://127.0.0.1:{d}", .{bound.port});

    const outcome = try query(arena, io, null, host, lexicon.method.get_profile, &.{
        .{ .name = "actor", .value = "missing.test" },
    }, lexicon.ProfileViewDetailed, .{});

    try std.testing.expectEqual(@as(u16, 400), outcome.failed.status);
    try std.testing.expectEqualStrings("InvalidRequest", outcome.failed.code);
    try std.testing.expectEqualStrings("Profile not found", outcome.failed.message);
}

/// Procedure fixture: echoes what it observed (method, content-type, raw
/// body) back as JSON, so the CLIENT asserts on what actually crossed the
/// wire.
/// Kept bespoke on purpose (F4): echoing the request body back IS the
/// behavior under test, which the shared canned-script fixture cannot
/// express. Every other server in this file rides test_fixture now.
fn serveProcedureEchoOnce(server: *std.Io.net.Server, io: std.Io) void {
    const stream = server.accept(io) catch return;
    defer stream.close(io);
    var read_buf: [8192]u8 = undefined;
    var write_buf: [8192]u8 = undefined;
    var stream_reader = stream.reader(io, &read_buf);
    var stream_writer = stream.writer(io, &write_buf);
    var http_server: std.http.Server = .init(&stream_reader.interface, &stream_writer.interface);
    var request = http_server.receiveHead() catch return;

    // Head strings are invalidated by acquiring the body reader — copy first.
    var method_buf: [16]u8 = undefined;
    const method_name = std.fmt.bufPrint(&method_buf, "{t}", .{request.head.method}) catch return;
    var ct_buf: [64]u8 = undefined;
    const content_type = if (request.head.content_type) |ct|
        (std.fmt.bufPrint(&ct_buf, "{s}", .{ct}) catch return)
    else
        "";
    const body_len: usize = @intCast(request.head.content_length orelse 0);
    if (body_len > 4096) return;

    var reader_buf: [4096]u8 = undefined;
    const body_reader = request.readerExpectContinue(&reader_buf) catch return;
    var body_storage: [4096]u8 = undefined;
    body_reader.readSliceAll(body_storage[0..body_len]) catch return;

    var response_buf: [8192]u8 = undefined;
    const response = std.fmt.bufPrint(
        &response_buf,
        \\{{"sawMethod":"{s}","sawContentType":"{s}","echo":{s}}}
    ,
        .{ method_name, content_type, body_storage[0..body_len] },
    ) catch return;
    request.respond(response, .{
        .extra_headers = &.{.{ .name = "content-type", .value = "application/json" }},
    }) catch return;
}

test "loopback round trip: procedure POSTs the encoded input and decodes the response" {
    const gpa = std.testing.allocator; // C6
    const io = std.testing.io;

    var bound = try listenLoopback(io, 38604);
    defer bound.server.deinit(io);
    const thread = try std.Thread.spawn(.{}, serveProcedureEchoOnce, .{ &bound.server, io });
    defer thread.join();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var host_buf: [48]u8 = undefined;
    const host = try std.fmt.bufPrint(&host_buf, "http://127.0.0.1:{d}", .{bound.port});

    const Input = struct {
        identifier: []const u8,
        password: []const u8,
        authFactorToken: ?[]const u8 = null, // must be OMITTED on the wire
    };
    const EchoResponse = struct {
        // A7.2: cold struct, size guard waived — test-only parse target.
        sawMethod: []const u8 = "",
        sawContentType: []const u8 = "",
        echo: Input = .{ .identifier = "", .password = "" },
    };

    const outcome = try procedure(arena, io, null, host, "com.atproto.server.createSession", Input{
        .identifier = "alice.test",
        .password = "hunter2",
    }, EchoResponse, .{});

    try std.testing.expectEqualStrings("POST", outcome.ok.sawMethod);
    try std.testing.expectEqualStrings("application/json", outcome.ok.sawContentType);
    try std.testing.expectEqualStrings("alice.test", outcome.ok.echo.identifier);
    try std.testing.expectEqualStrings("hunter2", outcome.ok.echo.password);
    try std.testing.expectEqual(@as(?[]const u8, null), outcome.ok.echo.authFactorToken);
}

// Two connections: refuse the first with 429, answer the second. Reaching
// `ok` proves the retry loop walked the schedule.
test "loopback round trip: a 429 is retried on the schedule, then succeeds" {
    const gpa = std.testing.allocator; // C6
    const io = std.testing.io;

    var bound = try listenLoopback(io, 38618);
    defer bound.server.deinit(io);
    const steps = [_]fixture.ScriptStep{
        .{
            .must_contain_head = "/xrpc/",
            .status = .too_many_requests,
            .body =
            \\{"error":"RateLimitExceeded","message":"slow down"}
            ,
        },
        .{
            .must_contain_head = "/xrpc/",
            .status = .ok,
            .body = profile_fixture,
        },
    };
    const thread = try std.Thread.spawn(.{}, serveScript, .{ &bound.server, io, &steps });
    defer thread.join();

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var host_buf: [48]u8 = undefined;
    const host = try std.fmt.bufPrint(&host_buf, "http://127.0.0.1:{d}", .{bound.port});

    const outcome = try query(arena, io, null, host, lexicon.method.get_profile, &.{
        .{ .name = "actor", .value = "alice.test" },
    }, lexicon.ProfileViewDetailed, .{});

    try std.testing.expectEqualStrings("alice.test", outcome.ok.handle);
}
