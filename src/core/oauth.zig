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

//! B1 classification: CORE (pure). Parses the two atproto OAuth discovery
//! documents into flat typed structs:
//!
//!   * `/.well-known/oauth-protected-resource` (RFC 9728) — the PDS as a
//!     resource server; we need its `authorization_servers[0]` (the issuer).
//!   * `/.well-known/oauth-authorization-server` (RFC 8414) — the issuer's
//!     endpoint set (authorize / token / PAR).
//!
//! Pure transforms over caller-supplied bytes: the shell does the (SSRF-guarded)
//! fetching and hands the JSON here. Every document is depth-bounded
//! (`jsonguard`) before parsing, so a hostile metadata document can't blow the
//! stack (the Phase-2 DoS guard, applied at this trust boundary too).
//!
//! Parsing also *validates the server is usable for our flow*: ES256 DPoP and
//! S256 PKCE must be advertised, and the PAR endpoint must exist (atproto
//! requires pushed authorization requests). A server missing any of these is an
//! explicit `UnsupportedServer` error, not a surprise three slices later.

const std = @import("std");
const Allocator = std.mem.Allocator;
const jsonguard = @import("jsonguard.zig");

/// The issuer's endpoint set, the fruit of discovery. Strings are owned by the
/// allocator passed to `parseAuthServer`; free with `freeAuthServer`.
/// A7.2: cold struct — one per login, never held in quantity. Waived.
pub const AuthServer = struct {
    issuer: []const u8,
    authorization_endpoint: []const u8,
    token_endpoint: []const u8,
    /// Pushed Authorization Request endpoint — required by the atproto profile.
    par_endpoint: []const u8,
};

pub const Error = error{
    /// JSON nesting exceeded the depth guard — refused before parsing.
    TooDeep,
    /// Not valid JSON, or a field had the wrong type.
    Malformed,
    /// A required field was absent.
    MissingField,
    /// The server doesn't advertise something our flow needs (ES256 DPoP,
    /// S256 PKCE, or a PAR endpoint).
    UnsupportedServer,
} || Allocator.Error;

/// From the protected-resource document, return the first authorization server
/// URL (the issuer to discover next). Owned by `gpa`.
pub fn parseAuthServerUrl(gpa: Allocator, json: []const u8) Error![]u8 {
    if (!jsonguard.depthWithinLimit(json, jsonguard.max_json_depth)) return error.TooDeep;
    var parsed = std.json.parseFromSlice(std.json.Value, gpa, json, .{}) catch return error.Malformed;
    defer parsed.deinit();
    const root = objectOf(parsed.value) orelse return error.Malformed;

    const servers = root.get("authorization_servers") orelse return error.MissingField;
    if (servers != .array or servers.array.items.len == 0) return error.MissingField;
    const first = servers.array.items[0];
    if (first != .string) return error.Malformed;
    return gpa.dupe(u8, first.string);
}

/// From the authorization-server document, extract the endpoint set and verify
/// the server supports our flow (ES256 DPoP, S256 PKCE, PAR). Owned by `gpa`.
pub fn parseAuthServer(gpa: Allocator, json: []const u8) Error!AuthServer {
    if (!jsonguard.depthWithinLimit(json, jsonguard.max_json_depth)) return error.TooDeep;
    var parsed = std.json.parseFromSlice(std.json.Value, gpa, json, .{}) catch return error.Malformed;
    defer parsed.deinit();
    const root = objectOf(parsed.value) orelse return error.Malformed;

    // Capability gates first — fail fast on an unusable server.
    if (!arrayHasString(root.get("dpop_signing_alg_values_supported"), "ES256")) return error.UnsupportedServer;
    if (!arrayHasString(root.get("code_challenge_methods_supported"), "S256")) return error.UnsupportedServer;

    const issuer = try stringField(root, "issuer");
    const authorize = try stringField(root, "authorization_endpoint");
    const token = try stringField(root, "token_endpoint");
    const par = try stringField(root, "pushed_authorization_request_endpoint");

    // Dupe into gpa with an errdefer chain so a mid-way OOM leaks nothing (C5).
    const issuer_owned = try gpa.dupe(u8, issuer);
    errdefer gpa.free(issuer_owned);
    const authorize_owned = try gpa.dupe(u8, authorize);
    errdefer gpa.free(authorize_owned);
    const token_owned = try gpa.dupe(u8, token);
    errdefer gpa.free(token_owned);
    const par_owned = try gpa.dupe(u8, par);

    return .{
        .issuer = issuer_owned,
        .authorization_endpoint = authorize_owned,
        .token_endpoint = token_owned,
        .par_endpoint = par_owned,
    };
}

pub fn freeAuthServer(gpa: Allocator, s: AuthServer) void {
    gpa.free(s.issuer);
    gpa.free(s.authorization_endpoint);
    gpa.free(s.token_endpoint);
    gpa.free(s.par_endpoint);
}

// --- small helpers (pure) ---

fn objectOf(v: std.json.Value) ?std.json.ObjectMap {
    return if (v == .object) v.object else null;
}

/// Required string field: present and of string type, else an explicit error.
fn stringField(root: std.json.ObjectMap, key: []const u8) Error![]const u8 {
    const v = root.get(key) orelse return error.MissingField;
    if (v != .string) return error.Malformed;
    return v.string;
}

/// True iff `value` is a JSON array containing the exact string `needle`.
fn arrayHasString(value: ?std.json.Value, needle: []const u8) bool {
    const v = value orelse return false;
    if (v != .array) return false;
    for (v.array.items) |item| {
        if (item == .string and std.mem.eql(u8, item.string, needle)) return true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// Tests (C6). Fixtures are the REAL documents served by pds.zat4.com
// (captured 2026-06-27), trimmed only of fields we don't read — so a green
// test proves we parse our own live auth server, not a hand-built guess.
// ---------------------------------------------------------------------------

const testing = std.testing;

const real_protected_resource =
    \\{"resource":"https://pds.zat4.com","authorization_servers":["https://pds.zat4.com"],
    \\"scopes_supported":[],"bearer_methods_supported":["header"],
    \\"resource_documentation":"https://atproto.com"}
;

const real_auth_server =
    \\{"issuer":"https://pds.zat4.com",
    \\"authorization_endpoint":"https://pds.zat4.com/oauth/authorize",
    \\"token_endpoint":"https://pds.zat4.com/oauth/token",
    \\"pushed_authorization_request_endpoint":"https://pds.zat4.com/oauth/par",
    \\"require_pushed_authorization_requests":true,
    \\"dpop_signing_alg_values_supported":["RS256","PS256","ES256","ES256K","ES384"],
    \\"scopes_supported":["atproto","transition:email","transition:generic"],
    \\"token_endpoint_auth_methods_supported":["none","private_key_jwt"],
    \\"response_types_supported":["code"],
    \\"grant_types_supported":["authorization_code","refresh_token"],
    \\"code_challenge_methods_supported":["S256"]}
;

test "oauth: protected-resource yields the first authorization server" {
    const url = try parseAuthServerUrl(testing.allocator, real_protected_resource);
    defer testing.allocator.free(url);
    try testing.expectEqualStrings("https://pds.zat4.com", url);
}

test "oauth: authorization-server parses the endpoint set (real pds.zat4.com doc)" {
    const s = try parseAuthServer(testing.allocator, real_auth_server);
    defer freeAuthServer(testing.allocator, s);
    try testing.expectEqualStrings("https://pds.zat4.com", s.issuer);
    try testing.expectEqualStrings("https://pds.zat4.com/oauth/authorize", s.authorization_endpoint);
    try testing.expectEqualStrings("https://pds.zat4.com/oauth/token", s.token_endpoint);
    try testing.expectEqualStrings("https://pds.zat4.com/oauth/par", s.par_endpoint);
}

test "oauth: a server without ES256 DPoP is rejected" {
    const no_es256 =
        \\{"issuer":"https://x","authorization_endpoint":"https://x/a","token_endpoint":"https://x/t",
        \\"pushed_authorization_request_endpoint":"https://x/par",
        \\"dpop_signing_alg_values_supported":["RS256"],"code_challenge_methods_supported":["S256"]}
    ;
    try testing.expectError(error.UnsupportedServer, parseAuthServer(testing.allocator, no_es256));
}

test "oauth: a server without S256 PKCE is rejected" {
    const no_s256 =
        \\{"issuer":"https://x","authorization_endpoint":"https://x/a","token_endpoint":"https://x/t",
        \\"pushed_authorization_request_endpoint":"https://x/par",
        \\"dpop_signing_alg_values_supported":["ES256"],"code_challenge_methods_supported":["plain"]}
    ;
    try testing.expectError(error.UnsupportedServer, parseAuthServer(testing.allocator, no_s256));
}

test "oauth: a server missing the PAR endpoint is rejected" {
    const no_par =
        \\{"issuer":"https://x","authorization_endpoint":"https://x/a","token_endpoint":"https://x/t",
        \\"dpop_signing_alg_values_supported":["ES256"],"code_challenge_methods_supported":["S256"]}
    ;
    try testing.expectError(error.MissingField, parseAuthServer(testing.allocator, no_par));
}

test "oauth: empty authorization_servers is a missing field" {
    const empty = "{\"authorization_servers\":[]}";
    try testing.expectError(error.MissingField, parseAuthServerUrl(testing.allocator, empty));
}

test "oauth: malformed JSON is rejected, not crashed" {
    try testing.expectError(error.Malformed, parseAuthServerUrl(testing.allocator, "{not json"));
    try testing.expectError(error.Malformed, parseAuthServer(testing.allocator, "[]"));
}
