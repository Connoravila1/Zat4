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

//! B1 classification: CORE (pure). The deterministic halves of the atproto
//! OAuth authorization-code flow: build the request bodies and the authorize
//! URL, and parse the responses and the browser callback. No I/O — the shell
//! (`shell/oauth.zig`) does the POSTs, opens the browser, and runs the loopback
//! server; it hands the bytes here.
//!
//! Flow shape (the shell drives it; these are its building blocks):
//!   1. `buildParBody`        → POST to the PAR endpoint
//!   2. `parseParResponse`    → `request_uri`
//!   3. `buildAuthorizeUrl`   → open in the browser
//!   4. `parseCallback` + `validateCallback` → the auth `code`
//!   5. `buildTokenBody`      → POST to the token endpoint
//!   6. `parseTokenResponse`  → the DPoP-bound token set
//!
//! Every response is depth-bounded (`jsonguard`) before parsing. `state` and
//! `iss` are validated on the callback (anti-forgery / anti-mixup, the Phase-10
//! "unvalidated redirect = auth interception" guard).

const std = @import("std");
const Allocator = std.mem.Allocator;
const jsonguard = @import("jsonguard.zig");

pub const Error = error{
    TooDeep,
    Malformed,
    MissingField,
    /// The authorization server returned an `error` on the callback (the user
    /// denied, or the request was rejected).
    AuthorizationDenied,
    /// The callback `state` didn't match the one we sent — a forged/replayed
    /// redirect. Refused.
    StateMismatch,
    /// The callback `iss` didn't match the issuer we started the flow with — an
    /// authorization-server mixup. Refused.
    IssuerMismatch,
    /// The token response wasn't DPoP-bound (`token_type` != "DPoP").
    NotDpopBound,
} || Allocator.Error;

// ---------------------------------------------------------------------------
// 1. Pushed Authorization Request (PAR) body.
// ---------------------------------------------------------------------------

/// A7.2: cold struct, size guard waived — per-login request parameters, one per
/// flow, never in a hot loop.
pub const ParParams = struct {
    client_id: []const u8,
    redirect_uri: []const u8,
    scope: []const u8,
    state: []const u8,
    /// The S256 PKCE challenge (from `core/pkce`).
    code_challenge: []const u8,
    /// Optional handle to pre-fill the login form.
    login_hint: ?[]const u8 = null,
};

/// Form-encode the PAR request body (application/x-www-form-urlencoded).
pub fn buildParBody(gpa: Allocator, p: ParParams) Allocator.Error![]u8 {
    var b: std.ArrayListUnmanaged(u8) = .empty;
    defer b.deinit(gpa);
    try appendForm(&b, gpa, "response_type", "code", true);
    try appendForm(&b, gpa, "code_challenge_method", "S256", false);
    try appendForm(&b, gpa, "client_id", p.client_id, false);
    try appendForm(&b, gpa, "redirect_uri", p.redirect_uri, false);
    try appendForm(&b, gpa, "scope", p.scope, false);
    try appendForm(&b, gpa, "state", p.state, false);
    try appendForm(&b, gpa, "code_challenge", p.code_challenge, false);
    if (p.login_hint) |h| try appendForm(&b, gpa, "login_hint", h, false);
    return b.toOwnedSlice(gpa);
}

/// A7.2: cold struct, size guard waived — one per login.
pub const ParResponse = struct {
    request_uri: []const u8,
    expires_in: i64,
};

/// Parse the PAR response: `{request_uri, expires_in}`. The `request_uri` is
/// owned by `gpa`.
pub fn parseParResponse(gpa: Allocator, json: []const u8) Error!ParResponse {
    if (!jsonguard.depthWithinLimit(json, jsonguard.max_json_depth)) return error.TooDeep;
    var parsed = std.json.parseFromSlice(std.json.Value, gpa, json, .{}) catch return error.Malformed;
    defer parsed.deinit();
    const root = if (parsed.value == .object) parsed.value.object else return error.Malformed;
    const uri = root.get("request_uri") orelse return error.MissingField;
    if (uri != .string) return error.Malformed;
    const expires = root.get("expires_in") orelse return error.MissingField;
    const expires_in: i64 = switch (expires) {
        .integer => |n| n,
        else => return error.Malformed,
    };
    return .{ .request_uri = try gpa.dupe(u8, uri.string), .expires_in = expires_in };
}

// ---------------------------------------------------------------------------
// 2. Authorize URL.
// ---------------------------------------------------------------------------

/// `<authorize_endpoint>?client_id=<enc>&request_uri=<enc>` — the URL the user
/// opens in the browser. Owned by `gpa`.
pub fn buildAuthorizeUrl(
    gpa: Allocator,
    authorize_endpoint: []const u8,
    client_id: []const u8,
    request_uri: []const u8,
) Allocator.Error![]u8 {
    var b: std.ArrayListUnmanaged(u8) = .empty;
    defer b.deinit(gpa);
    try b.appendSlice(gpa, authorize_endpoint);
    try b.append(gpa, '?');
    try appendForm(&b, gpa, "client_id", client_id, true);
    try appendForm(&b, gpa, "request_uri", request_uri, false);
    return b.toOwnedSlice(gpa);
}

// ---------------------------------------------------------------------------
// 3. The browser callback.
// ---------------------------------------------------------------------------

/// A7.2: cold struct, size guard waived — one per login callback.
pub const Callback = struct {
    code: []const u8,
    state: []const u8,
    /// The issuer the auth server reports (RFC 9207 `iss`), if present.
    iss: ?[]const u8,
};

/// Parse a callback query string (everything after `?`) into its fields, each
/// percent-decoded and owned by `gpa`. An `error=...` parameter becomes
/// `AuthorizationDenied` (the user said no, or the server refused).
pub fn parseCallback(gpa: Allocator, query: []const u8) Error!Callback {
    var code: ?[]u8 = null;
    var state: ?[]u8 = null;
    var iss: ?[]u8 = null;
    errdefer {
        if (code) |c| gpa.free(c);
        if (state) |s| gpa.free(s);
        if (iss) |i| gpa.free(i);
    }

    var it = std.mem.splitScalar(u8, query, '&');
    while (it.next()) |pair| {
        if (pair.len == 0) continue;
        const eq = std.mem.indexOfScalar(u8, pair, '=') orelse continue;
        const key = pair[0..eq];
        const val = pair[eq + 1 ..];
        if (std.mem.eql(u8, key, "error")) return error.AuthorizationDenied;
        if (std.mem.eql(u8, key, "code")) {
            code = try percentDecode(gpa, val);
        } else if (std.mem.eql(u8, key, "state")) {
            state = try percentDecode(gpa, val);
        } else if (std.mem.eql(u8, key, "iss")) {
            iss = try percentDecode(gpa, val);
        }
    }
    return .{
        .code = code orelse return error.MissingField,
        .state = state orelse return error.MissingField,
        .iss = iss,
    };
}

pub fn freeCallback(gpa: Allocator, cb: Callback) void {
    gpa.free(cb.code);
    gpa.free(cb.state);
    if (cb.iss) |i| gpa.free(i);
}

/// The two security checks on the callback: `state` must match what we sent,
/// and `iss` (if present) must be the issuer we began with. Either mismatch is
/// a refused authorization (Phase 10).
pub fn validateCallback(cb: Callback, expected_state: []const u8, expected_iss: []const u8) Error!void {
    if (!constEql(cb.state, expected_state)) return error.StateMismatch;
    if (cb.iss) |got| {
        if (!std.mem.eql(u8, got, expected_iss)) return error.IssuerMismatch;
    }
}

// ---------------------------------------------------------------------------
// 4. Token exchange.
// ---------------------------------------------------------------------------

/// A7.2: cold struct, size guard waived — one per login.
pub const TokenParams = struct {
    client_id: []const u8,
    redirect_uri: []const u8,
    code: []const u8,
    code_verifier: []const u8,
};

/// Form-encode the authorization-code token-exchange body.
pub fn buildTokenBody(gpa: Allocator, p: TokenParams) Allocator.Error![]u8 {
    var b: std.ArrayListUnmanaged(u8) = .empty;
    defer b.deinit(gpa);
    try appendForm(&b, gpa, "grant_type", "authorization_code", true);
    try appendForm(&b, gpa, "code", p.code, false);
    try appendForm(&b, gpa, "redirect_uri", p.redirect_uri, false);
    try appendForm(&b, gpa, "client_id", p.client_id, false);
    try appendForm(&b, gpa, "code_verifier", p.code_verifier, false);
    return b.toOwnedSlice(gpa);
}

/// Form-encode the refresh-token grant body. The same token endpoint and DPoP
/// machinery as the initial exchange; only the grant differs.
pub fn buildRefreshBody(gpa: Allocator, client_id: []const u8, refresh_token: []const u8) Allocator.Error![]u8 {
    var b: std.ArrayListUnmanaged(u8) = .empty;
    defer b.deinit(gpa);
    try appendForm(&b, gpa, "grant_type", "refresh_token", true);
    try appendForm(&b, gpa, "refresh_token", refresh_token, false);
    try appendForm(&b, gpa, "client_id", client_id, false);
    return b.toOwnedSlice(gpa);
}

/// The DPoP-bound token set from a successful exchange. Strings owned by `gpa`.
/// A7.2: cold struct — one per login. Waived.
pub const TokenSet = struct {
    access_token: []const u8,
    refresh_token: []const u8,
    /// The authenticated account DID (`sub`).
    sub: []const u8,
    scope: []const u8,
    expires_in: i64,
};

/// Parse the token response, requiring it be DPoP-bound (`token_type` "DPoP",
/// case-insensitive). Strings owned by `gpa`.
pub fn parseTokenResponse(gpa: Allocator, json: []const u8) Error!TokenSet {
    if (!jsonguard.depthWithinLimit(json, jsonguard.max_json_depth)) return error.TooDeep;
    var parsed = std.json.parseFromSlice(std.json.Value, gpa, json, .{}) catch return error.Malformed;
    defer parsed.deinit();
    const root = if (parsed.value == .object) parsed.value.object else return error.Malformed;

    const token_type = try strField(root, "token_type");
    if (!std.ascii.eqlIgnoreCase(token_type, "DPoP")) return error.NotDpopBound;

    const access = try strField(root, "access_token");
    const refresh = try strField(root, "refresh_token");
    const sub = try strField(root, "sub");
    const scope = try strField(root, "scope");
    const expires_in: i64 = if (root.get("expires_in")) |v| (switch (v) {
        .integer => |n| n,
        else => return error.Malformed,
    }) else 0;

    const access_owned = try gpa.dupe(u8, access);
    errdefer gpa.free(access_owned);
    const refresh_owned = try gpa.dupe(u8, refresh);
    errdefer gpa.free(refresh_owned);
    const sub_owned = try gpa.dupe(u8, sub);
    errdefer gpa.free(sub_owned);
    const scope_owned = try gpa.dupe(u8, scope);

    return .{
        .access_token = access_owned,
        .refresh_token = refresh_owned,
        .sub = sub_owned,
        .scope = scope_owned,
        .expires_in = expires_in,
    };
}

pub fn freeTokenSet(gpa: Allocator, t: TokenSet) void {
    gpa.free(t.access_token);
    gpa.free(t.refresh_token);
    gpa.free(t.sub);
    gpa.free(t.scope);
}

/// True iff the server's error body asks us to retry with a DPoP nonce — the
/// expected `use_dpop_nonce` handshake, not a failure (the shell pairs this
/// with the `DPoP-Nonce` response header to retry once).
pub fn isUseDpopNonce(gpa: Allocator, json: []const u8) bool {
    if (!jsonguard.depthWithinLimit(json, jsonguard.max_json_depth)) return false;
    var parsed = std.json.parseFromSlice(std.json.Value, gpa, json, .{}) catch return false;
    defer parsed.deinit();
    const root = if (parsed.value == .object) parsed.value.object else return false;
    const e = root.get("error") orelse return false;
    return e == .string and std.mem.eql(u8, e.string, "use_dpop_nonce");
}

// --- small pure helpers ---

fn strField(root: std.json.ObjectMap, key: []const u8) Error![]const u8 {
    const v = root.get(key) orelse return error.MissingField;
    if (v != .string) return error.Malformed;
    return v.string;
}

/// Append `key=value` (value percent-encoded) to a form body, with a leading
/// `&` unless this is the `first` field.
fn appendForm(b: *std.ArrayListUnmanaged(u8), gpa: Allocator, key: []const u8, value: []const u8, first: bool) Allocator.Error!void {
    if (!first) try b.append(gpa, '&');
    try b.appendSlice(gpa, key);
    try b.append(gpa, '=');
    try percentEncodeInto(b, gpa, value);
}

/// Percent-encode per RFC 3986: ALPHA / DIGIT / `-` `.` `_` `~` pass through,
/// everything else (space included, as %20 — valid in both query and form
/// bodies) becomes %XX. Uppercase hex.
fn percentEncodeInto(b: *std.ArrayListUnmanaged(u8), gpa: Allocator, s: []const u8) Allocator.Error!void {
    const hex = "0123456789ABCDEF";
    for (s) |c| {
        if (std.ascii.isAlphanumeric(c) or c == '-' or c == '.' or c == '_' or c == '~') {
            try b.append(gpa, c);
        } else {
            try b.appendSlice(gpa, &.{ '%', hex[c >> 4], hex[c & 0x0F] });
        }
    }
}

/// Percent-decode a query-string value into `gpa`-owned bytes. A malformed `%`
/// escape is treated literally (lenient — these come from our own auth server).
fn percentDecode(gpa: Allocator, s: []const u8) Allocator.Error![]u8 {
    var out: std.ArrayListUnmanaged(u8) = .empty;
    defer out.deinit(gpa);
    var i: usize = 0;
    while (i < s.len) : (i += 1) {
        if (s[i] == '%' and i + 2 < s.len) {
            const hi = std.fmt.charToDigit(s[i + 1], 16) catch {
                try out.append(gpa, s[i]);
                continue;
            };
            const lo = std.fmt.charToDigit(s[i + 2], 16) catch {
                try out.append(gpa, s[i]);
                continue;
            };
            try out.append(gpa, @as(u8, hi) << 4 | lo);
            i += 2;
        } else if (s[i] == '+') {
            try out.append(gpa, ' ');
        } else {
            try out.append(gpa, s[i]);
        }
    }
    return out.toOwnedSlice(gpa);
}

/// Constant-time-ish equality for the `state` check (length-independent leak is
/// acceptable here; the value is single-use and short-lived).
fn constEql(a: []const u8, b: []const u8) bool {
    if (a.len != b.len) return false;
    var diff: u8 = 0;
    for (a, b) |x, y| diff |= x ^ y;
    return diff == 0;
}

// ---------------------------------------------------------------------------
// Tests (C6).
// ---------------------------------------------------------------------------

const testing = std.testing;

test "oauth_flow: PAR body form-encodes and escapes the scope space and colon" {
    const body = try buildParBody(testing.allocator, .{
        .client_id = "https://pds.zat4.com/client-metadata.json",
        .redirect_uri = "http://127.0.0.1:54321/callback",
        .scope = "atproto transition:generic",
        .state = "xyz",
        .code_challenge = "abc123",
        .login_hint = "zat4.com",
    });
    defer testing.allocator.free(body);
    try testing.expect(std.mem.startsWith(u8, body, "response_type=code&code_challenge_method=S256&"));
    try testing.expect(std.mem.indexOf(u8, body, "scope=atproto%20transition%3Ageneric") != null);
    try testing.expect(std.mem.indexOf(u8, body, "client_id=https%3A%2F%2Fpds.zat4.com%2Fclient-metadata.json") != null);
    try testing.expect(std.mem.indexOf(u8, body, "login_hint=zat4.com") != null);
}

test "oauth_flow: authorize URL carries client_id and request_uri" {
    const url = try buildAuthorizeUrl(
        testing.allocator,
        "https://pds.zat4.com/oauth/authorize",
        "https://pds.zat4.com/client-metadata.json",
        "urn:ietf:params:oauth:request_uri:abc",
    );
    defer testing.allocator.free(url);
    try testing.expect(std.mem.startsWith(u8, url, "https://pds.zat4.com/oauth/authorize?client_id="));
    try testing.expect(std.mem.indexOf(u8, url, "&request_uri=urn%3Aietf%3Aparams%3Aoauth%3Arequest_uri%3Aabc") != null);
}

test "oauth_flow: PAR response parses request_uri + expires_in" {
    const json = "{\"request_uri\":\"urn:ietf:params:oauth:request_uri:xyz\",\"expires_in\":299}";
    const r = try parseParResponse(testing.allocator, json);
    defer testing.allocator.free(r.request_uri);
    try testing.expectEqualStrings("urn:ietf:params:oauth:request_uri:xyz", r.request_uri);
    try testing.expectEqual(@as(i64, 299), r.expires_in);
}

test "oauth_flow: callback parses + validates state and iss" {
    const cb = try parseCallback(testing.allocator, "code=abc%2Fdef&state=s123&iss=https%3A%2F%2Fpds.zat4.com");
    defer freeCallback(testing.allocator, cb);
    try testing.expectEqualStrings("abc/def", cb.code);
    try testing.expectEqualStrings("s123", cb.state);
    try testing.expectEqualStrings("https://pds.zat4.com", cb.iss.?);
    try validateCallback(cb, "s123", "https://pds.zat4.com");
    try testing.expectError(error.StateMismatch, validateCallback(cb, "WRONG", "https://pds.zat4.com"));
    try testing.expectError(error.IssuerMismatch, validateCallback(cb, "s123", "https://evil.example"));
}

test "oauth_flow: a callback error is AuthorizationDenied" {
    try testing.expectError(error.AuthorizationDenied, parseCallback(testing.allocator, "error=access_denied&state=s1"));
}

test "oauth_flow: token response requires DPoP binding" {
    const ok = "{\"token_type\":\"DPoP\",\"access_token\":\"at\",\"refresh_token\":\"rt\",\"sub\":\"did:plc:abc\",\"scope\":\"atproto transition:generic\",\"expires_in\":3600}";
    const t = try parseTokenResponse(testing.allocator, ok);
    defer freeTokenSet(testing.allocator, t);
    try testing.expectEqualStrings("at", t.access_token);
    try testing.expectEqualStrings("did:plc:abc", t.sub);
    try testing.expectEqual(@as(i64, 3600), t.expires_in);

    const bearer = "{\"token_type\":\"Bearer\",\"access_token\":\"at\",\"refresh_token\":\"rt\",\"sub\":\"x\",\"scope\":\"y\"}";
    try testing.expectError(error.NotDpopBound, parseTokenResponse(testing.allocator, bearer));
}

test "oauth_flow: refresh body carries the grant, token, and client_id" {
    const body = try buildRefreshBody(testing.allocator, "https://pds.zat4.com/client-metadata.json", "rt-value-123");
    defer testing.allocator.free(body);
    try testing.expect(std.mem.startsWith(u8, body, "grant_type=refresh_token&"));
    try testing.expect(std.mem.indexOf(u8, body, "refresh_token=rt-value-123") != null);
    try testing.expect(std.mem.indexOf(u8, body, "client_id=https%3A%2F%2Fpds.zat4.com%2Fclient-metadata.json") != null);
}

test "oauth_flow: use_dpop_nonce error is recognized" {
    try testing.expect(isUseDpopNonce(testing.allocator, "{\"error\":\"use_dpop_nonce\",\"error_description\":\"x\"}"));
    try testing.expect(!isUseDpopNonce(testing.allocator, "{\"error\":\"invalid_grant\"}"));
    try testing.expect(!isUseDpopNonce(testing.allocator, "not json"));
}
