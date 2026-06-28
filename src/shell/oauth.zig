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

//! B1 classification: SHELL. OBTAINING an OAuth session — discovery and the
//! browser authorization-code flow. The counterpart, USING a session (the
//! DPoP-authenticated query/procedure and refresh), lives in `auth.zig`, which
//! `login` returns an `auth.Session` into; the split keeps the import acyclic
//! (`oauth` → `auth`, never back).
//!
//! Discovery: two networked `.well-known` fetches turn a resolved PDS into the
//! issuer's endpoint set. The parsing is pure (`core/oauth.zig`). Both fetches
//! are `.untrusted` (the host is network-derived), inheriting `http`'s SSRF
//! gate. Login: PKCE/DPoP prep → PAR → system browser → loopback callback →
//! token exchange (the pure builders/parsers are `core/oauth_flow.zig`; the DPoP
//! POST primitive is `auth.dpopPost`).

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const http = @import("http.zig");
const config = @import("config.zig");
const auth = @import("auth.zig");
const oauth = @import("../core/oauth.zig");
const oauth_flow = @import("../core/oauth_flow.zig");
const pkce = @import("../core/pkce.zig");
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
// The authorization-code login flow. Discovery → PKCE/DPoP prep → PAR → browser
// → loopback callback → token exchange. The result is an `auth.Session` (oauth
// mode); from there the app uses `auth.query`/`auth.procedure` like any session.
// ---------------------------------------------------------------------------

/// Run the full browser OAuth login for the account at `pds_url` (resolved by
/// the caller from a handle/DID via `identity`). `handle` seeds the login form.
/// Opens the system browser and blocks on the loopback callback until the user
/// completes (or denies). Returns a ready-to-use `auth.Session` (oauth mode),
/// its strings owned by `gpa`; every transient lives in `scratch`.
///
/// `cancel` (optional) lets a caller abort the wait from another thread: the GUI
/// runs this on a worker and sets the flag if the user closes the window while
/// the browser is still open, so the loopback wait stops instead of blocking
/// forever (returns `error.CallbackFailed`). Headless callers pass null.
pub fn login(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    scratch: Allocator,
    pds_url: []const u8,
    handle: ?[]const u8,
    cancel: ?*std.atomic.Value(bool),
) !auth.Session {
    // 1. Discover the issuer's endpoints (scratch-owned for the flow).
    const server = try discover(scratch, io, environ, scratch, pds_url);

    // 2. Prep: an ephemeral DPoP key, PKCE, and an unguessable state (B3: the
    // key, the entropy, and the clock are all shell-sourced here).
    const dpop_kp = Scheme.KeyPair.generate(io);
    const secret = dpop_kp.secret_key.toBytes();
    var pkce_entropy: [32]u8 = undefined;
    try io.randomSecure(&pkce_entropy);
    const verifier = pkce.verifierFromEntropy(pkce_entropy);
    const challenge = pkce.challengeS256(&verifier);
    const state = try randomToken(io, scratch, 24);

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
    const par_post = try auth.dpopPost(io, environ, scratch, server.par_endpoint, par_body, secret, null);
    const par = try oauth_flow.parseParResponse(scratch, par_post.body);

    // 5. Open the browser to the authorize endpoint.
    const authorize_url = try oauth_flow.buildAuthorizeUrl(scratch, server.authorization_endpoint, config.oauth_client_id, par.request_uri);
    // Dev affordance: echo the URL so a failed auto-open (headless/SSH) is
    // recoverable by pasting it. Not a secret. Removed when the GUI drives this.
    std.debug.print("[oauth] authorize URL (opens automatically): {s}\n", .{authorize_url});
    openBrowser(io, authorize_url) catch |err| {
        // Auto-open failed (headless / SSH / no xdg-open). NOT fatal: the URL was
        // printed above for manual paste, so the flow proceeds to await the
        // callback. Surfacing the reason instead of swallowing it (E3) keeps a
        // failed launch from looking like a silent hang. NOTE for slice 6.2: in
        // the GUI this message + the URL print become a proper surfaced state,
        // and the flow's overall lifetime (cancel if the browser never opens)
        // is owned by the worker-thread design that wires this in.
        std.debug.print("[oauth] could not launch a browser ({s}); open the URL above manually.\n", .{@errorName(err)});
    };

    // 6. Block on the callback; validate state + iss.
    const query = try awaitCallback(scratch, io, &lb.server, cancel);
    const cb = try oauth_flow.parseCallback(scratch, query);
    try oauth_flow.validateCallback(cb, state, server.issuer);

    // 7. Token exchange (DPoP, seeded with the nonce PAR handed back).
    const token_body = try oauth_flow.buildTokenBody(scratch, .{
        .client_id = config.oauth_client_id,
        .redirect_uri = redirect_uri,
        .code = cb.code,
        .code_verifier = &verifier,
    });
    const tok_post = try auth.dpopPost(io, environ, scratch, server.token_endpoint, token_body, secret, par_post.nonce);
    const tokens = try oauth_flow.parseTokenResponse(gpa, tok_post.body);
    errdefer oauth_flow.freeTokenSet(gpa, tokens);

    // 8. Assemble the gpa-owned session — the token strings transfer into it.
    const handle_owned = try gpa.dupe(u8, handle orelse "");
    errdefer gpa.free(handle_owned);
    const pds_owned = try gpa.dupe(u8, pds_url);
    errdefer gpa.free(pds_owned);
    const issuer = try gpa.dupe(u8, server.issuer);
    errdefer gpa.free(issuer);
    const token_endpoint = try gpa.dupe(u8, server.token_endpoint);
    errdefer gpa.free(token_endpoint);
    const nonce_owned: ?[]const u8 = if (tok_post.nonce) |n| try gpa.dupe(u8, n) else null;

    return .{
        .mode = .oauth,
        .did = tokens.sub,
        .handle = handle_owned,
        .pds_url = pds_owned,
        .access_jwt = tokens.access_token,
        .refresh_jwt = tokens.refresh_token,
        .scope = tokens.scope,
        .issuer = issuer,
        .token_endpoint = token_endpoint,
        .dpop_secret = secret,
        .nonce = nonce_owned,
    };
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

/// Wait for the real callback request and answer the browser with a small
/// "you're signed in" page. Returns the callback query string (`scratch`-owned).
///
/// Loops over connections rather than accepting just one: browsers (Firefox/
/// LibreWolf especially) open *speculative* preconnections that send no data,
/// and may also fetch `/favicon.ico`. A single-shot accept races those and can
/// close the listener before the genuine `GET /callback?...` arrives — exactly
/// the "Unable to connect" failure. So we ignore empty/non-callback connections
/// and keep listening until the callback (carrying a query) shows up.
fn awaitCallback(scratch: Allocator, io: std.Io, server: *std.Io.net.Server, cancel: ?*std.atomic.Value(bool)) ![]u8 {
    var seen: u32 = 0;
    while (seen < 64) : (seen += 1) {
        // Wait for an incoming connection by POLLING the listener with a short
        // timeout rather than blocking in `accept`, so we can observe `cancel`
        // (the GUI closed the window mid-flow) and bail promptly instead of
        // hanging a worker thread on `accept` forever. With no cancel flag this
        // is the same patient wait as a bare accept, just woken every 250 ms.
        // Windows has no browser flow yet, so it keeps the plain blocking accept.
        if (comptime builtin.os.tag != .windows) {
            while (true) {
                if (cancel) |c| if (c.load(.acquire)) return error.CallbackFailed;
                var lfds = [_]std.posix.pollfd{.{ .fd = server.socket.handle, .events = std.posix.POLL.IN, .revents = 0 }};
                const lready = std.posix.poll(&lfds, 250) catch return error.CallbackFailed;
                if (lready > 0) break;
            }
        }
        const stream = server.accept(io) catch return error.CallbackFailed;
        // One close for every exit of this iteration — continue, return, OR the
        // `try` below failing on OOM (the old per-branch closes leaked the fd on
        // that error path). `accept` blocks patiently between connections, so
        // the overall wait for the user is unbounded; only each individual
        // connection is bounded by the poll below (C5).
        defer stream.close(io);

        // A speculative preconnection (the comment above) can open the socket
        // and send NOTHING, which would block receiveHead forever and hang the
        // whole login. Bound each connection: if no request bytes arrive within
        // a few seconds, treat it as silent and move on — the browser opens a
        // fresh connection for the real GET /callback. Mirrors the raw-fd poll
        // in stream.zig; Windows v1 skips it (no browser flow there yet).
        if (comptime builtin.os.tag != .windows) {
            var pfds = [_]std.posix.pollfd{.{ .fd = stream.socket.handle, .events = std.posix.POLL.IN, .revents = 0 }};
            const ready = std.posix.poll(&pfds, 5_000) catch 0;
            if (ready == 0) continue;
        }

        var read_buf: [16 * 1024]u8 = undefined;
        var write_buf: [4 * 1024]u8 = undefined;
        var stream_reader = stream.reader(io, &read_buf);
        var stream_writer = stream.writer(io, &write_buf);
        var hs: std.http.Server = .init(&stream_reader.interface, &stream_writer.interface);
        // A speculative/empty connection (no complete request) — discard it and
        // wait for the next, keeping the listener open.
        var req = hs.receiveHead() catch continue;
        const target = req.head.target; // e.g. "/callback?code=...&state=...&iss=..."
        const qpos = std.mem.indexOfScalar(u8, target, '?');
        if (!std.mem.startsWith(u8, target, "/callback") or qpos == null) {
            // Not the callback (a preconnect GET /, /favicon.ico, etc.).
            req.respond("", .{ .status = .not_found }) catch {};
            continue;
        }
        const query = try scratch.dupe(u8, target[qpos.? + 1 ..]);
        req.respond(success_page, .{
            .extra_headers = &.{.{ .name = "content-type", .value = "text/html; charset=utf-8" }},
        }) catch {};
        return query;
    }
    return error.CallbackFailed;
}

const success_page =
    \\<!doctype html><html lang="en"><head><meta charset="utf-8">
    \\<meta name="viewport" content="width=device-width,initial-scale=1"><title>Zat4</title>
    \\<style>html,body{height:100%;margin:0}body{display:flex;align-items:center;justify-content:center;
    \\background:#181812;color:#e9e6df;font:500 16px/1.5 system-ui,sans-serif}
    \\.c{text-align:center;padding:2rem}.z{color:#F58C0F;font-weight:700;font-size:1.4rem;margin-bottom:.4rem}
    \\p{opacity:.7;margin:0}</style></head><body><div class="c">
    \\<div class="z">Signed in to Zat4</div><p>You're all set — you can close this tab and return to the app.</p>
    \\</div></body></html>
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

/// `n` CSPRNG bytes as base64url (unreserved, URL-safe) — for `state`.
/// Uses `io.randomSecure` (the same syscall CSPRNG the credential gen uses).
fn randomToken(io: std.Io, scratch: Allocator, comptime n: usize) ![]u8 {
    var raw: [n]u8 = undefined;
    try io.randomSecure(&raw);
    const enc_len = std.base64.url_safe_no_pad.Encoder.calcSize(n);
    const out = try scratch.alloc(u8, enc_len);
    _ = std.base64.url_safe_no_pad.Encoder.encode(out, &raw);
    return out;
}

// ---------------------------------------------------------------------------
// Tests (C6). The networked `discover`/`login` are exercised end-to-end when the
// flow runs (live test) and the parsers are golden-tested in core/oauth*.zig
// against real pds.zat4.com documents; here we pin the pure helper.
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
