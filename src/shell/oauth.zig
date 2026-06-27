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

//! B1 classification: SHELL (thin). OAuth authorization-server discovery: the
//! two networked `.well-known` fetches that turn a resolved PDS into the
//! issuer's endpoint set. The PARSING is pure (`core/oauth.zig`); this module
//! only does I/O — fetch, hand the bytes to the parser, and validate the issuer.
//!
//! Both fetches are `.untrusted` (the host is network-derived), so they inherit
//! `http`'s SSRF gate: https-only, blocked-range refusal, and no redirect
//! following (Phase 1). The caller resolves handle/DID → PDS via the existing
//! `identity` module and passes the PDS URL here; this is the OAuth-specific
//! leg of that chain (D6: one vertical slice, reusing identity as-is).

const std = @import("std");
const Allocator = std.mem.Allocator;
const http = @import("http.zig");
const clock = @import("clock.zig");
const config = @import("config.zig");
const oauth = @import("../core/oauth.zig");
const oauth_flow = @import("../core/oauth_flow.zig");
const pkce = @import("../core/pkce.zig");
const dpop = @import("../core/dpop.zig");
const Scheme = std.crypto.sign.ecdsa.EcdsaP256Sha256;

/// Metadata documents are small flat JSON; 256 KiB is luxurious headroom while
/// still bounding a hostile server (the transport also enforces its own cap).
const max_metadata_bytes: usize = 256 * 1024;

const protected_resource_path = "/.well-known/oauth-protected-resource";
const auth_server_path = "/.well-known/oauth-authorization-server";

pub const Error = error{
    /// A discovery fetch returned a non-2xx status.
    DiscoveryFailed,
    /// The auth-server document's `issuer` didn't match the URL it was fetched
    /// from — a metadata-substitution red flag, refused (RFC 8414 §3.3).
    IssuerMismatch,
} || oauth.Error || Allocator.Error;

/// Discover the issuer's OAuth endpoints for an account hosted at `pds_url`.
/// The returned `AuthServer`'s strings are owned by `gpa` (free with
/// `oauth.freeAuthServer`); every transient — URLs, response bodies, the
/// intermediate issuer URL — lives in `scratch` and is freed wholesale by the
/// caller (C3). `environ` honors proxy vars; pass null in tests.
pub fn discover(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    scratch: Allocator,
    pds_url: []const u8,
) !oauth.AuthServer {
    // 1. The PDS as a resource server → its authorization server (the issuer).
    const pr_url = try wellKnownUrl(scratch, pds_url, protected_resource_path);
    const pr_body = try fetchJson(scratch, io, environ, pr_url);
    const issuer_url = try oauth.parseAuthServerUrl(scratch, pr_body);

    // 2. The issuer's metadata → the endpoint set.
    const as_url = try wellKnownUrl(scratch, issuer_url, auth_server_path);
    const as_body = try fetchJson(scratch, io, environ, as_url);
    const server = try oauth.parseAuthServer(gpa, as_body);
    errdefer oauth.freeAuthServer(gpa, server);

    // 3. The issuer identifier MUST match where we fetched the metadata from
    // (RFC 8414 §3.3): a mismatch means the resource server pointed us at a
    // document that doesn't claim to be that issuer — reject it.
    if (!std.mem.eql(u8, server.issuer, issuer_url)) return error.IssuerMismatch;
    return server;
}

/// One `.untrusted` GET that must return 2xx, returning the body (scratch-owned).
fn fetchJson(
    scratch: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    url: []const u8,
) ![]u8 {
    const resp = try http.request(scratch, io, environ, url, .{
        .guard = .untrusted,
        .accept = "application/json",
        .max_response_bytes = max_metadata_bytes,
    });
    if (resp.status < 200 or resp.status >= 300) return error.DiscoveryFailed;
    return resp.body;
}

/// Join a base origin/URL with a `.well-known` path. Pure. Trims exactly one
/// trailing slash off `base` so `https://pds.zat4.com/` and `https://pds.zat4.com`
/// both yield `https://pds.zat4.com/.well-known/...`.
///
/// Note: per RFC 8414 a base with its OWN path component would insert the
/// well-known segment between host and path; atproto issuers are bare origins,
/// so the simple append is correct here. Extending to path-bearing issuers is a
/// localized change if a non-atproto server ever needs it.
fn wellKnownUrl(scratch: Allocator, base: []const u8, path: []const u8) Allocator.Error![]u8 {
    const trimmed = if (std.mem.endsWith(u8, base, "/")) base[0 .. base.len - 1] else base;
    return std.mem.concat(scratch, u8, &.{ trimmed, path });
}

// ---------------------------------------------------------------------------
// The authorization-code login flow (the Slice-3 choreography). Discovery →
// PKCE/DPoP prep → PAR → browser → loopback callback → token exchange, with the
// DPoP-nonce retry. The pure halves live in `core/oauth_flow`; this is the I/O.
// ---------------------------------------------------------------------------

/// The product of a successful login: the DPoP-bound token set plus the
/// material needed to keep using and refreshing it (Slice 4). The DPoP key is
/// ephemeral this slice (in-memory, regenerated per login); Slice 5 persists it.
/// Strings owned by `gpa`. A7.2: cold struct, size guard waived — one per login.
pub const LoginResult = struct {
    tokens: oauth_flow.TokenSet,
    /// The 32-byte P-256 DPoP private scalar bound to these tokens.
    dpop_secret: [32]u8,
    issuer: []const u8,
    /// The token endpoint, kept for the refresh grant (Slice 4).
    token_endpoint: []const u8,
    /// The most recent server DPoP nonce, to seed the next request (Slice 4).
    dpop_nonce: ?[]const u8,
};

pub fn freeLoginResult(gpa: Allocator, r: LoginResult) void {
    oauth_flow.freeTokenSet(gpa, r.tokens);
    gpa.free(r.issuer);
    gpa.free(r.token_endpoint);
    if (r.dpop_nonce) |n| gpa.free(n);
}

/// Run the full browser OAuth login for the account at `pds_url` (resolved by
/// the caller from a handle/DID via `identity`). `handle` seeds the login form.
/// Opens the system browser and blocks on the loopback callback until the user
/// completes (or denies). The result's strings are owned by `gpa`; every
/// transient lives in `scratch`.
pub fn login(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    scratch: Allocator,
    pds_url: []const u8,
    handle: ?[]const u8,
) !LoginResult {
    // 1. Discover the issuer's endpoints (scratch-owned for the flow).
    const server = try discover(scratch, io, environ, scratch, pds_url);

    // 2. Prep: an ephemeral DPoP key, PKCE, and an unguessable state (B3: the
    // key, the entropy, and the clock are all shell-sourced here).
    const dpop_kp = Scheme.KeyPair.generate(io);
    const secret = dpop_kp.secret_key.toBytes();
    var pkce_entropy: [32]u8 = undefined;
    std.crypto.random.bytes(&pkce_entropy);
    const verifier = pkce.verifierFromEntropy(pkce_entropy);
    const challenge = pkce.challengeS256(&verifier);
    const state = try randomToken(scratch, 24);

    // 3. The loopback catcher MUST be listening before we send its URL in PAR.
    var lb = try openLoopback(io);
    defer lb.server.deinit(io);
    const redirect_uri = try std.fmt.allocPrint(scratch, "http://127.0.0.1:{d}/callback", .{lb.port});

    // 4. Pushed Authorization Request → request_uri (DPoP, with nonce retry).
    const par_body = try oauth_flow.buildParBody(scratch, .{
        .client_id = config.oauth_client_id,
        .redirect_uri = redirect_uri,
        .scope = config.oauth_scope,
        .state = state,
        .code_challenge = &challenge,
        .login_hint = handle,
    });
    const par_post = try dpopPost(io, environ, scratch, server.par_endpoint, par_body, secret, null);
    const par = try oauth_flow.parseParResponse(scratch, par_post.body);

    // 5. Open the browser to the authorize endpoint.
    const authorize_url = try oauth_flow.buildAuthorizeUrl(scratch, server.authorization_endpoint, config.oauth_client_id, par.request_uri);
    // Dev affordance: echo the URL so a failed auto-open (headless/SSH) is
    // recoverable by pasting it. Not a secret. Removed when the GUI drives this.
    std.debug.print("[oauth] authorize URL (opens automatically): {s}\n", .{authorize_url});
    openBrowser(io, authorize_url) catch {};

    // 6. Block on the callback; validate state + iss.
    const query = try awaitCallback(scratch, io, &lb.server);
    const cb = try oauth_flow.parseCallback(scratch, query);
    try oauth_flow.validateCallback(cb, state, server.issuer);

    // 7. Token exchange (DPoP, seeded with the nonce PAR handed back).
    const token_body = try oauth_flow.buildTokenBody(scratch, .{
        .client_id = config.oauth_client_id,
        .redirect_uri = redirect_uri,
        .code = cb.code,
        .code_verifier = &verifier,
    });
    const tok_post = try dpopPost(io, environ, scratch, server.token_endpoint, token_body, secret, par_post.nonce);
    const tokens = try oauth_flow.parseTokenResponse(gpa, tok_post.body);
    errdefer oauth_flow.freeTokenSet(gpa, tokens);

    // 8. Assemble the gpa-owned result.
    const issuer = try gpa.dupe(u8, server.issuer);
    errdefer gpa.free(issuer);
    const token_endpoint = try gpa.dupe(u8, server.token_endpoint);
    errdefer gpa.free(token_endpoint);
    const nonce_owned: ?[]const u8 = if (tok_post.nonce) |n| try gpa.dupe(u8, n) else null;

    return .{
        .tokens = tokens,
        .dpop_secret = secret,
        .issuer = issuer,
        .token_endpoint = token_endpoint,
        .dpop_nonce = nonce_owned,
    };
}

/// One DPoP-signed POST with the expected nonce handshake: the first attempt
/// has no nonce; if the server answers `use_dpop_nonce` with a fresh
/// `DPoP-Nonce`, rebuild the proof with it and retry exactly once. Returns the
/// 2xx body and the latest nonce (both `scratch`-owned).
fn dpopPost(
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    scratch: Allocator,
    endpoint: []const u8,
    form_body: []const u8,
    secret: [32]u8,
    nonce_in: ?[]const u8,
) !struct { body: []u8, nonce: ?[]u8 } {
    var nonce = nonce_in;
    var attempt: u8 = 0;
    while (attempt < 2) : (attempt += 1) {
        const jti = try randomToken(scratch, 16);
        const proof = try dpop.buildProof(scratch, .{
            .secret_key = secret,
            .htm = "POST",
            .htu = endpoint,
            .iat = clock.unixSeconds(),
            .jti = jti,
            .nonce = nonce,
        });
        const resp = try http.requestCapturing(scratch, io, environ, endpoint, .{
            .method = .POST,
            .body = form_body,
            .content_type = "application/x-www-form-urlencoded",
            .accept = "application/json",
            .guard = .untrusted,
            .extra_headers = &.{.{ .name = "DPoP", .value = proof }},
        }, "DPoP-Nonce");

        if (resp.status >= 200 and resp.status < 300) {
            return .{ .body = resp.body, .nonce = resp.captured };
        }
        // The nonce handshake is expected on first contact — retry once.
        if (attempt == 0 and resp.captured != null and oauth_flow.isUseDpopNonce(scratch, resp.body)) {
            nonce = resp.captured;
            continue;
        }
        return error.OAuthRequestFailed;
    }
    unreachable;
}

/// A7.2: cold struct, size guard waived — one per login, held only during the flow.
const Loopback = struct { server: std.Io.net.Server, port: u16 };

/// Bind a loopback listener on a free port in the dynamic/ephemeral range,
/// probing upward until one is free (the bound socket doesn't report its port,
/// so we choose it). The port is not matched by the auth server (it ignores
/// loopback ports), so any free one works.
fn openLoopback(io: std.Io) !Loopback {
    var port: u16 = 49823;
    var i: u8 = 0;
    while (i < 32) : (i += 1) {
        var address: std.Io.net.IpAddress = .{ .ip4 = .loopback(port) };
        if (address.listen(io, .{ .reuse_address = true })) |server| {
            return .{ .server = server, .port = port };
        } else |_| {
            port +%= 1;
        }
    }
    return error.NoFreePort;
}

/// Accept one connection, read the callback request line, and answer the
/// browser with a small "you're signed in" page (which tries to close itself —
/// the max-smooth touch). Returns the callback query string (`scratch`-owned).
fn awaitCallback(scratch: Allocator, io: std.Io, server: *std.Io.net.Server) ![]u8 {
    const stream = try server.accept(io);
    defer stream.close(io);
    var read_buf: [16 * 1024]u8 = undefined;
    var write_buf: [4 * 1024]u8 = undefined;
    var stream_reader = stream.reader(io, &read_buf);
    var stream_writer = stream.writer(io, &write_buf);
    var hs: std.http.Server = .init(&stream_reader.interface, &stream_writer.interface);
    var req = hs.receiveHead() catch return error.CallbackFailed;
    const target = req.head.target; // e.g. "/callback?code=...&state=...&iss=..."
    const q = if (std.mem.indexOfScalar(u8, target, '?')) |idx| target[idx + 1 ..] else "";
    const query = try scratch.dupe(u8, q);
    req.respond(success_page, .{
        .extra_headers = &.{.{ .name = "content-type", .value = "text/html; charset=utf-8" }},
    }) catch {};
    return query;
}

const success_page =
    \\<!doctype html><html lang="en"><head><meta charset="utf-8">
    \\<meta name="viewport" content="width=device-width,initial-scale=1"><title>Zat4</title>
    \\<style>html,body{height:100%;margin:0}body{display:flex;align-items:center;justify-content:center;
    \\background:#181812;color:#e9e6df;font:500 16px/1.5 system-ui,sans-serif}
    \\.c{text-align:center;padding:2rem}.z{color:#F58C0F;font-weight:700;font-size:1.4rem}
    \\p{opacity:.7}</style></head><body><div class="c">
    \\<div class="z">Signed in to Zat4</div><p>You can close this tab and return to the app.</p>
    \\</div><script>setTimeout(function(){window.close();},800);</script></body></html>
;

/// Open `url` in the system browser. Linux: `xdg-open`. (mac `open` / win
/// `start` are the cross-platform follow-ups, like the GPU seam.)
fn openBrowser(io: std.Io, url: []const u8) !void {
    var child = try std.process.spawn(io, .{
        .argv = &.{ "xdg-open", url },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    _ = child.wait(io) catch {};
}

/// `n` CSPRNG bytes as base64url (unreserved, URL-safe) — for `state` and `jti`.
fn randomToken(scratch: Allocator, comptime n: usize) ![]u8 {
    var raw: [n]u8 = undefined;
    std.crypto.random.bytes(&raw);
    const enc_len = std.base64.url_safe_no_pad.Encoder.calcSize(n);
    const out = try scratch.alloc(u8, enc_len);
    _ = std.base64.url_safe_no_pad.Encoder.encode(out, &raw);
    return out;
}

// ---------------------------------------------------------------------------
// Tests (C6). The networked `discover`/`login` are exercised end-to-end when the
// flow runs (Slice 3 live test) and the parsers are golden-tested in
// core/oauth*.zig against real pds.zat4.com documents; here we pin pure helpers.
// ---------------------------------------------------------------------------

const testing = std.testing;

test "oauth shell: wellKnownUrl appends and de-duplicates the slash" {
    const a = try wellKnownUrl(testing.allocator, "https://pds.zat4.com", protected_resource_path);
    defer testing.allocator.free(a);
    try testing.expectEqualStrings("https://pds.zat4.com/.well-known/oauth-protected-resource", a);

    const b = try wellKnownUrl(testing.allocator, "https://pds.zat4.com/", auth_server_path);
    defer testing.allocator.free(b);
    try testing.expectEqualStrings("https://pds.zat4.com/.well-known/oauth-authorization-server", b);
}
