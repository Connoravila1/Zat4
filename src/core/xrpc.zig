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

//! B1 classification: CORE (pure). The XRPC deep module's interior.
//!
//! INTERNAL FILE — the only permitted importer is src/shell/xrpc.zig, the
//! module's public face (D1/D3). This file is the **sealed wire-format
//! decision**: how method URLs are spelled, how query values are escaped,
//! how JSON becomes typed records and back, and what an XRPC error body
//! looks like. atproto is pre-1.0; when this churns, the blast radius is
//! the xrpc module and the lexicon shapes — nothing else (D1).
//!
//! Everything here is a deterministic transform over bytes (B2/B4): no
//! network, no clock, no globals. Allocating functions take the allocator
//! explicitly (C1); decode results are slices into the given arena, with
//! lifetimes documented per function.

const std = @import("std");
const jsonguard = @import("jsonguard.zig");
const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// Method URLs
// ---------------------------------------------------------------------------

/// One query parameter — a plain name/value pair (A1).
/// A7.2: cold struct, size guard waived — a handful exist per call, on the
/// caller's stack, never resident.
pub const Param = struct {
    name: []const u8,
    value: []const u8,
};

pub const UrlError = error{ InvalidNsid, OutOfMemory };

/// `{host}/xrpc/{nsid}` — the procedure (POST) form, no query string.
pub fn buildMethodUrl(alloc: Allocator, host: []const u8, nsid: []const u8) UrlError![]u8 {
    try validateNsid(nsid);
    return std.fmt.allocPrint(alloc, "{s}/xrpc/{s}", .{ host, nsid });
}

/// `{host}/xrpc/{nsid}?{params}` — the query (GET) form. Parameter names
/// and values are percent-encoded to the RFC 3986 unreserved set, so DIDs
/// (`did:plc:…`), handles, and cursors travel safely as values.
pub fn buildQueryUrl(
    alloc: Allocator,
    host: []const u8,
    nsid: []const u8,
    params: []const Param,
) UrlError![]u8 {
    try validateNsid(nsid);
    var out: std.Io.Writer.Allocating = .init(alloc);
    errdefer out.deinit(); // C5
    const w = &out.writer;
    w.print("{s}/xrpc/{s}", .{ host, nsid }) catch return error.OutOfMemory;
    for (params, 0..) |param, i| {
        w.writeByte(if (i == 0) '?' else '&') catch return error.OutOfMemory;
        std.Uri.Component.percentEncode(w, param.name, isUnreservedChar) catch return error.OutOfMemory;
        w.writeByte('=') catch return error.OutOfMemory;
        std.Uri.Component.percentEncode(w, param.value, isUnreservedChar) catch return error.OutOfMemory;
    }
    return out.toOwnedSlice() catch return error.OutOfMemory;
}

/// NSIDs are dot-separated reverse-DNS names (`app.zat4.actor.getProfile`):
/// ASCII letters, digits, dots, hyphens. Anything else does not belong in a
/// URL path we build.
fn validateNsid(nsid: []const u8) error{InvalidNsid}!void {
    if (nsid.len == 0) return error.InvalidNsid;
    for (nsid) |c| switch (c) {
        'a'...'z', 'A'...'Z', '0'...'9', '.', '-' => {},
        else => return error.InvalidNsid,
    };
}

/// RFC 3986 unreserved characters — everything else is %XX-escaped.
/// (std.Uri's own predicate is private; this five-liner is the F2 answer,
/// not a dependency.)
fn isUnreservedChar(c: u8) bool {
    return switch (c) {
        'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => true,
        else => false,
    };
}

// ---------------------------------------------------------------------------
// Codec — typed records in, typed records out (the JSON decision, sealed)
// ---------------------------------------------------------------------------

pub const DecodeError = error{ MalformedResponseBody, OutOfMemory };

/// Decode an XRPC response body straight into the given lexicon record type
/// — flat typed structs, never a dynamic tree we re-walk. Unknown fields are
/// ignored on purpose: lexicons evolve, and a new field must not break an
/// old client (E4). `arena` must be an arena (leaky parse); the returned
/// record's slices point into it and live exactly as long as it does.
pub fn decode(comptime T: type, arena: Allocator, body: []const u8) DecodeError!T {
    // Bound nesting BEFORE std.json (which recurses per level and can blow the
    // stack on `[[[[…]]]]`). Every other JSON-fed boundary guards depth first;
    // this is the primary timeline/profile/getRecord read path, so it must too
    // (Phase 2 — a depth bomb is a clean rejection, not a stack-overflow DoS).
    if (!jsonguard.depthWithinLimit(body, jsonguard.max_json_depth)) return error.MalformedResponseBody;
    return std.json.parseFromSliceLeaky(T, arena, body, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory, // never masked (C-discipline)
        else => error.MalformedResponseBody,
    };
}

/// Encode a procedure input record as the JSON request body. Optional fields
/// that are null are omitted entirely — XRPC servers want absent, not null.
pub fn encodeBody(arena: Allocator, input: anytype) error{OutOfMemory}![]u8 {
    return std.json.Stringify.valueAlloc(arena, input, .{
        .emit_null_optional_fields = false,
    });
}

// ---------------------------------------------------------------------------
// Rate-limit retry policy — the pure decision; the shell owns the clock (B3)
// ---------------------------------------------------------------------------

/// Schedule for retrying a 429: how long to wait before attempt N+1, or null
/// to give up. Two bounded retries — a transient limit clears; a real window
/// (atproto enforces multi-minute windows) will not, and hammering it makes
/// the standing worse. Honoring the server's `ratelimit-reset` header is
/// recorded in the roadmap: it needs response-header capture, which the
/// current transport (std fetch) does not surface.
pub fn rateLimitRetryDelayMs(attempt: usize) ?u64 {
    return switch (attempt) {
        0 => 1_000,
        1 => 2_000,
        else => null,
    };
}

// ---------------------------------------------------------------------------
// XRPC application errors — values, not Zig errors
// ---------------------------------------------------------------------------

/// What the server said when it refused: plain data the caller branches on
/// (Phase 3 will branch on `code == "ExpiredToken"`, for example). This is
/// E4 applied: a refused request is a routine protocol outcome, carried as
/// a value — Zig errors stay reserved for transport/codec failure (E3).
/// A7.2: cold struct, size guard waived — one per failed call.
pub const Failure = struct {
    status: u16,
    /// The server's error code string, "" when none was provided.
    code: []const u8,
    /// The server's human-readable message, "" when none was provided.
    message: []const u8,
};

/// The wire shape of an XRPC error body.
/// A7.2: cold struct, size guard waived — transient parse target.
const ErrorBodyJson = struct {
    @"error": []const u8 = "",
    message: []const u8 = "",
};

/// Classify a non-2xx response. Never fails: a body that is not the
/// documented error shape (HTML from a proxy, an empty body) still yields a
/// usable `Failure` with empty code/message — the status carries the truth.
/// OOM is the one real error and is never masked. Slices point into `arena`.
pub fn parseFailure(arena: Allocator, status: u16, body: []const u8) error{OutOfMemory}!Failure {
    const parsed = std.json.parseFromSliceLeaky(ErrorBodyJson, arena, body, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return .{ .status = status, .code = "", .message = "" },
    };
    return .{ .status = status, .code = parsed.@"error", .message = parsed.message };
}

// ---------------------------------------------------------------------------
// Tests — the wire-format decision exercised entirely offline (B2), under
// the leak-detecting allocator (C6).
// ---------------------------------------------------------------------------

const testing = std.testing;
const lexicon = @import("lexicon.zig");

test "query URL: NSID path, multiple params, reserved characters escaped" {
    const gpa = testing.allocator;
    const url = try buildQueryUrl(gpa, "https://public.api.bsky.app", "app.zat4.actor.getProfile", &.{
        .{ .name = "actor", .value = "did:plc:z72i7hdynmk6r22z27h6tvur" },
        .{ .name = "q", .value = "two words&more=trouble" },
    });
    defer gpa.free(url);
    try testing.expectEqualStrings(
        "https://public.api.bsky.app/xrpc/app.zat4.actor.getProfile" ++
            "?actor=did%3Aplc%3Az72i7hdynmk6r22z27h6tvur" ++
            "&q=two%20words%26more%3Dtrouble",
        url,
    );
}

test "query URL: no params means no question mark; method URL has no query" {
    const gpa = testing.allocator;
    const bare = try buildQueryUrl(gpa, "https://host.test", "com.example.query", &.{});
    defer gpa.free(bare);
    try testing.expectEqualStrings("https://host.test/xrpc/com.example.query", bare);

    const proc = try buildMethodUrl(gpa, "https://host.test", "com.atproto.server.createSession");
    defer gpa.free(proc);
    try testing.expectEqualStrings("https://host.test/xrpc/com.atproto.server.createSession", proc);
}

test "query URL: a malformed NSID never reaches the wire" {
    try testing.expectError(error.InvalidNsid, buildMethodUrl(testing.allocator, "https://h.test", "bad nsid"));
    try testing.expectError(error.InvalidNsid, buildQueryUrl(testing.allocator, "https://h.test", "../../etc", &.{}));
    try testing.expectError(error.InvalidNsid, buildMethodUrl(testing.allocator, "https://h.test", ""));
}

test "decode: realistic profile body into the lexicon record, unknown fields ignored" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const body =
        \\{
        \\  "did": "did:plc:z72i7hdynmk6r22z27h6tvur",
        \\  "handle": "bsky.app",
        \\  "displayName": "Bluesky",
        \\  "description": "official app account",
        \\  "avatar": "https://cdn.bsky.app/img/avatar.jpg",
        \\  "followersCount": 3400000,
        \\  "followsCount": 5,
        \\  "postsCount": 280,
        \\  "indexedAt": "2026-01-01T00:00:00.000Z",
        \\  "associated": {"lists": 0, "feedgens": 2},
        \\  "viewer": {"muted": false}
        \\}
    ;
    const profile = try decode(lexicon.ProfileViewDetailed, arena, body);
    try testing.expectEqualStrings("bsky.app", profile.handle);
    try testing.expectEqualStrings("Bluesky", profile.displayName.?);
    try testing.expectEqual(@as(u64, 3_400_000), profile.followersCount);
    try testing.expectEqual(@as(u64, 280), profile.postsCount);
}

test "decode: absent optional fields parse to defaults; garbage is an explicit error" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const minimal = try decode(lexicon.ProfileViewDetailed, arena,
        \\{"did":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","handle":"a.test"}
    );
    try testing.expectEqual(@as(?[]const u8, null), minimal.displayName);
    try testing.expectEqual(@as(u64, 0), minimal.followersCount);

    try testing.expectError(error.MalformedResponseBody, decode(lexicon.ProfileViewDetailed, arena, "<!doctype html>"));
}

test "encodeBody: null optionals are omitted, present fields serialize" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const Input = struct {
        identifier: []const u8,
        password: []const u8,
        authFactorToken: ?[]const u8 = null,
    };
    const body = try encodeBody(arena, Input{ .identifier = "alice.test", .password = "hunter2" });
    try testing.expectEqualStrings(
        \\{"identifier":"alice.test","password":"hunter2"}
    , body);
}

test "parseFailure: documented error shape, and graceful classification of garbage" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const documented = try parseFailure(arena, 400,
        \\{"error":"InvalidRequest","message":"actor must be a valid did or handle"}
    );
    try testing.expectEqual(@as(u16, 400), documented.status);
    try testing.expectEqualStrings("InvalidRequest", documented.code);
    try testing.expectEqualStrings("actor must be a valid did or handle", documented.message);

    const garbage = try parseFailure(arena, 502, "<html>bad gateway</html>");
    try testing.expectEqual(@as(u16, 502), garbage.status);
    try testing.expectEqualStrings("", garbage.code);
}

test "rate-limit retry policy: two bounded attempts, then give up" {
    try testing.expectEqual(@as(?u64, 1_000), rateLimitRetryDelayMs(0));
    try testing.expectEqual(@as(?u64, 2_000), rateLimitRetryDelayMs(1));
    try testing.expectEqual(@as(?u64, null), rateLimitRetryDelayMs(2));
}
