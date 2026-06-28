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
const http = @import("http.zig");
const clock = @import("clock.zig");
const config = @import("config.zig");
const lexicon = @import("../core/lexicon.zig");
const xrpc_core = @import("../core/xrpc.zig");
const dpop = @import("../core/dpop.zig");
const oauth_flow = @import("../core/oauth_flow.zig");

/// How a session authenticates. `app_password` is the legacy/dev path (a Bearer
/// JWT, refreshed via `refreshSession`); `oauth` is the atproto OAuth + DPoP
/// path (a token bound to a device key, every request carrying a fresh proof,
/// refreshed via the OAuth token endpoint). The rest of the app calls
/// `query`/`procedure` and never branches on this — the dispatch is interior.
pub const AuthMode = enum(u8) { app_password, oauth };

/// Serializes the credential-mutating choreography (token refresh + DPoP nonce
/// rotation) when a `Session` is shared across threads: the write worker
/// (write_worker.zig) holds a `*Session` and rotates its tokens/nonce while the
/// UI thread may issue its own PDS calls on the same session. Without this, an
/// oauth `setNonce` (free+replace of `session.nonce`) on one thread races a
/// proof build reading `session.nonce` on the other — a use-after-free / double
/// free on essentially every overlapping write.
///
/// Unlike the Mailbox/IndexLock spinlocks (brief critical sections), this lock
/// is held across a network round-trip, so the waiter SLEEPS rather than
/// spinning a core. Built on `std.atomic` for the same reason the rest of the
/// codebase avoids `std.Thread.Mutex` (unstable across our 0.16 fork snapshots;
/// stream.zig records it). Uncontended acquire is a single atomic swap;
/// contention — rare, at human action rates — costs ~1ms sleeps. Holding it
/// also defines away the refresh-token-rotation race: the second caller wakes,
/// reads the freshly-rotated token, and never spends the spent (single-use)
/// refresh token. A7.2: cold lock type (one per session), size guard waived.
pub const SessionLock = struct {
    held: std.atomic.Value(bool) = .init(false),
    fn lock(self: *SessionLock) void {
        while (self.held.swap(true, .acquire)) clock.sleepMillis(1);
    }
    fn unlock(self: *SessionLock) void {
        self.held.store(false, .release);
    }
};

/// An authenticated session — plain values (A1), every string owned by the
/// `gpa` given to `login`. Free with `freeSession`. Callers read `did`,
/// `handle`, `pds_url`; the jwt fields are data like any other (D5:
/// records get no encapsulation — the SUBSYSTEM is the sealed thing), but
/// only this module has a reason to touch them.
/// A7.2: cold struct, size guard waived — one per logged-in account.
///
/// Dual-mode: `did`/`handle`/`pds_url` and the two token fields are common to
/// both. The DPoP fields below are meaningful only when `mode == .oauth`; for
/// `app_password` they are inert (zeroed key, empty strings, null nonce) and
/// never freed. `access_jwt`/`refresh_jwt` hold the OAuth access/refresh tokens
/// in oauth mode (same slots, different credential).
pub const Session = struct {
    did: []const u8,
    handle: []const u8,
    pds_url: []const u8,
    access_jwt: []const u8,
    refresh_jwt: []const u8,
    /// Defaults make the common app-password session a 5-field literal; the
    /// oauth fields below default inert and are filled only by the oauth path.
    mode: AuthMode = .app_password,
    // --- oauth/DPoP only (inert in app-password mode: never read or freed) ---
    /// The 32-byte P-256 DPoP private scalar the tokens are bound to.
    dpop_secret: [32]u8 = [_]u8{0} ** 32,
    scope: []const u8 = "",
    /// The OAuth issuer and its token endpoint (for the refresh grant).
    issuer: []const u8 = "",
    token_endpoint: []const u8 = "",
    /// The most recent server DPoP nonce; rotates per response.
    nonce: ?[]const u8 = null,
    /// Serializes credential mutation when this session is shared across threads
    /// (see SessionLock). Inert and uncontended for a single-threaded session.
    /// Not persisted (cache.zig serializes named fields, never the whole struct).
    cred_lock: SessionLock = .{},
};

/// Login resolves to a session or the server's stated refusal (wrong
/// password, 2FA required, rate limit) — a routine outcome carried as plain
/// data the caller can show or branch on (E4). Zig errors remain reserved
/// for transport/codec failure (E3). `refused` strings live in the arena
/// passed to `login`.
/// A7.2: cold union, size guard waived — one per login, returned and matched.
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

/// Create a NEW account on `pds_url` via `com.atproto.server.createAccount` and
/// return its session (same shape as login). The PDS gates on `inviteCode` while
/// invite-only; a refusal (taken handle, bad/again-used invite, missing email)
/// comes back as `refused` for the caller to surface (E4). `refused` strings live
/// in `arena`; the returned session is owned by `gpa`.
pub fn createAccount(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    pds_url: []const u8,
    input: lexicon.CreateAccountInput,
) !LoginOutcome {
    const outcome = try xrpc.procedure(
        arena,
        io,
        environ,
        pds_url,
        lexicon.method.create_account,
        input,
        lexicon.SessionResponse,
        .{},
    );
    switch (outcome) {
        .failed => |failure| return .{ .refused = failure },
        .ok => |resp| return .{ .ok = try dupeSession(gpa, pds_url, resp) },
    }
}

/// Scrub a secret token's bytes before returning them to the allocator, so a
/// freed JWT cannot linger in a crash dump or swapped-out page (SECURITY_ROADMAP
/// Phase 0). `secureZero` is the erase the optimizer will not drop. The bytes
/// were allocated by us (`gpa.dupe`), so casting away const to zero our own
/// buffer is sound — the scrub happens at the point of release (C5).
fn freeSecret(gpa: Allocator, secret: []const u8) void {
    std.crypto.secureZero(u8, @constCast(secret));
    gpa.free(secret);
}

/// Re-home a `Session`'s owned strings from `src` to `dst`, then free (scrubbing
/// the secrets of) the source — an ownership transfer across allocators.
///
/// Why this exists: the GUI runs the blocking OAuth login on a worker thread,
/// which (per the enroll-worker convention) allocates from a thread-safe
/// allocator rather than the single-threaded render allocator. The finished
/// session must then be handed to a caller that frees with the render allocator,
/// so its strings are duped into `dst` and the worker-owned originals released.
/// Called on the main thread AFTER the worker is joined — no concurrency here.
///
/// On success the returned `Session` is wholly owned by `dst` and `s` has been
/// freed (do not touch it again). On an allocation failure nothing leaks: the
/// partial `dst` copies unwind via `errdefer`, and `s` is left intact for the
/// caller to free with `src`.
pub fn reownSession(dst: Allocator, src: Allocator, s: Session) !Session {
    const did = try dst.dupe(u8, s.did);
    errdefer dst.free(did);
    const handle = try dst.dupe(u8, s.handle);
    errdefer dst.free(handle);
    const pds_url = try dst.dupe(u8, s.pds_url);
    errdefer dst.free(pds_url);
    const access = try dst.dupe(u8, s.access_jwt);
    errdefer freeSecret(dst, access);
    const refresh = try dst.dupe(u8, s.refresh_jwt);
    errdefer freeSecret(dst, refresh);

    var out: Session = .{
        .did = did,
        .handle = handle,
        .pds_url = pds_url,
        .access_jwt = access,
        .refresh_jwt = refresh,
        .mode = s.mode,
        .dpop_secret = s.dpop_secret,
    };
    if (s.mode == .oauth) {
        out.scope = try dst.dupe(u8, s.scope);
        errdefer dst.free(out.scope);
        out.issuer = try dst.dupe(u8, s.issuer);
        errdefer dst.free(out.issuer);
        out.token_endpoint = try dst.dupe(u8, s.token_endpoint);
        errdefer dst.free(out.token_endpoint);
        out.nonce = if (s.nonce) |n| try dst.dupe(u8, n) else null;
    }
    freeSession(src, s); // scrubs + releases the source copy (no concurrency: post-join)
    return out;
}

/// Free a `Session` produced by `login` (A1: behavior as a free function). The
/// JWTs are session secrets, so they are scrubbed before release.
pub fn freeSession(gpa: Allocator, session: Session) void {
    gpa.free(session.did);
    gpa.free(session.handle);
    gpa.free(session.pds_url);
    freeSecret(gpa, session.access_jwt);
    freeSecret(gpa, session.refresh_jwt);
    if (session.mode == .oauth) {
        gpa.free(session.scope);
        gpa.free(session.issuer);
        gpa.free(session.token_endpoint);
        if (session.nonce) |n| gpa.free(n);
    }
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

    // Past this point we read and may rotate the session's credential fields
    // (access token / DPoP nonce). Serialize against the write-worker thread
    // that shares this *Session; the appview-bearer path above touches no
    // mutable field and stays lock-free (the hot timeline read). D4: the
    // cross-thread coupling stays sealed inside this module.
    session.cred_lock.lock();
    defer session.cred_lock.unlock();

    // OAuth sessions authenticate to their own PDS with DPoP, not a Bearer JWT.
    if (session.mode == .oauth) {
        const url = try xrpc_core.buildQueryUrl(arena, host, nsid, params);
        return dpopOutcome(Response, gpa, arena, io, environ, session, .GET, url, null, null);
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
    // A write always targets the PDS session token, so the whole body reads/
    // rotates credential fields — serialize against the write-worker thread
    // that shares this *Session (see queryHost / SessionLock).
    session.cred_lock.lock();
    defer session.cred_lock.unlock();

    // OAuth sessions write to their PDS with DPoP.
    if (session.mode == .oauth) {
        const url = try xrpc_core.buildMethodUrl(arena, session.pds_url, nsid);
        const body: ?[]const u8 = if (@TypeOf(input) == @TypeOf(null)) null else try xrpc_core.encodeBody(arena, input);
        return dpopOutcome(Response, gpa, arena, io, environ, session, .POST, url, body, if (body != null) "application/json" else null);
    }
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
            // Scrub the rotated-out tokens — they are now spent secrets.
            freeSecret(gpa, session.access_jwt);
            freeSecret(gpa, session.refresh_jwt);
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
    return .{
        .mode = .app_password,
        .did = did,
        .handle = handle,
        .pds_url = pds,
        .access_jwt = access,
        .refresh_jwt = refresh,
        // Inert in app-password mode — never read, never freed.
        .dpop_secret = [_]u8{0} ** 32,
        .scope = "",
        .issuer = "",
        .token_endpoint = "",
        .nonce = null,
    };
}

// --- OAuth / DPoP request mechanics (the oauth-mode half of query/procedure) -
//
// `oauth.zig` obtains the session (the browser flow); this module USES it. A
// DPoP request carries a fresh proof bound to the access token (ath) and the
// request (htm/htu), plus `Authorization: DPoP <token>`. The server's nonce
// rotates per response (retried once); an expired token (401) triggers one
// refresh-and-retry. `dpopPost` is also the primitive the login flow's PAR and
// token exchange ride on (so it lives here, where both can reach it without an
// import cycle).

/// Send a DPoP-authenticated request, decode a 2xx into the typed record, and
/// classify anything else into a `Failure` value — the same `Outcome` contract
/// the Bearer path returns.
fn dpopOutcome(
    comptime Response: type,
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *Session,
    method: std.http.Method,
    url: []const u8,
    body: ?[]const u8,
    content_type: ?[]const u8,
) !xrpc.Outcome(Response) {
    const resp = try dpopSend(gpa, arena, io, environ, session, method, url, body, content_type);
    if (resp.status >= 200 and resp.status <= 299) {
        return .{ .ok = try xrpc_core.decode(Response, arena, resp.body) };
    }
    return .{ .failed = try xrpc_core.parseFailure(arena, resp.status, resp.body) };
}

/// The request engine: sign, send, handle the DPoP-nonce handshake and the
/// 401-refresh, retry. Returns the final status + body (`arena`-owned). `htu`
/// is the URL minus its query (RFC 9449). Mutates the session's nonce (and, on
/// refresh, the tokens) in place.
fn dpopSend(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *Session,
    method: std.http.Method,
    url: []const u8,
    body: ?[]const u8,
    content_type: ?[]const u8,
) !struct { status: u16, body: []u8 } {
    const htu = url[0 .. std.mem.indexOfScalar(u8, url, '?') orelse url.len];
    var refreshed = false;
    var attempt: u8 = 0;
    while (attempt < 4) : (attempt += 1) {
        const jti = try randomJti(io, arena);
        const proof = try dpop.buildProof(arena, .{
            .secret_key = session.dpop_secret,
            .htm = if (method == .POST) "POST" else "GET",
            .htu = htu,
            .iat = clock.unixSeconds(),
            .jti = jti,
            .nonce = session.nonce,
            .access_token = session.access_jwt, // ath: binds the proof to the token
        });
        const auth_header = try std.fmt.allocPrint(arena, "DPoP {s}", .{session.access_jwt});
        const resp = try http.requestCapturing(arena, io, environ, url, .{
            .method = method,
            .body = body,
            .content_type = content_type,
            .accept = "application/json",
            .authorization = auth_header,
            .extra_headers = &.{.{ .name = "DPoP", .value = proof }},
        }, "DPoP-Nonce");

        if (resp.captured) |n| try setNonce(gpa, session, n);
        if (resp.status >= 200 and resp.status <= 299) return .{ .status = resp.status, .body = resp.body };
        // Nonce handshake / rotation: retry once the nonce is in hand.
        if (resp.captured != null and oauth_flow.isUseDpopNonce(arena, resp.body)) continue;
        // Expired access token: refresh once, then retry. A failed refresh means
        // the session is dead — surface the 401 for the caller to re-auth on.
        if (resp.status == 401 and !refreshed) {
            refreshOAuth(gpa, arena, io, environ, session) catch {
                return .{ .status = resp.status, .body = resp.body };
            };
            refreshed = true;
            continue;
        }
        return .{ .status = resp.status, .body = resp.body };
    }
    return error.OAuthRetryExhausted;
}

/// Refresh-token grant (DPoP-bound) at the issuer's token endpoint; rotates the
/// access + refresh tokens (and scope, and nonce) in place.
fn refreshOAuth(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *Session,
) !void {
    const body = try oauth_flow.buildRefreshBody(arena, config.oauth_client_id, session.refresh_jwt);
    const post = try dpopPost(io, environ, arena, session.token_endpoint, body, session.dpop_secret, session.nonce);
    const fresh = try oauth_flow.parseTokenResponse(gpa, post.body);
    freeSecret(gpa, session.access_jwt);
    freeSecret(gpa, session.refresh_jwt);
    gpa.free(session.scope);
    gpa.free(fresh.sub); // unchanged; keep session.did
    session.access_jwt = fresh.access_token;
    session.refresh_jwt = fresh.refresh_token;
    session.scope = fresh.scope;
    // Do NOT stamp the token-endpoint's DPoP nonce onto session.nonce. Nonces
    // are per-server (RFC 9449); session.nonce belongs to the PDS resource
    // server, while post.nonce came from the issuer's token endpoint. Writing
    // it here would force a guaranteed `use_dpop_nonce` retry on the very next
    // PDS request (and can burn the dpopSend attempt budget → spurious
    // OAuthRetryExhausted). The PDS nonce already held stays; if stale, the
    // normal handshake refreshes it. (post.nonce is arena-owned; ignoring it
    // leaks nothing.)
}

/// A DPoP-signed form POST with the expected nonce handshake (retry once with
/// the server nonce). The login flow's PAR + token exchange and the refresh
/// grant all ride on this. `scratch`-owned body + nonce. Public so `oauth.zig`
/// can use it without an import cycle.
pub fn dpopPost(
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
        const jti = try randomJti(io, scratch);
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
        if (resp.status >= 200 and resp.status <= 299) return .{ .body = resp.body, .nonce = resp.captured };
        if (attempt == 0 and resp.captured != null and oauth_flow.isUseDpopNonce(scratch, resp.body)) {
            nonce = resp.captured;
            continue;
        }
        return error.OAuthRequestFailed;
    }
    unreachable;
}

/// Replace the session's nonce with a fresh `gpa`-owned copy, freeing the old.
fn setNonce(gpa: Allocator, session: *Session, new: []const u8) Allocator.Error!void {
    const owned = try gpa.dupe(u8, new);
    if (session.nonce) |old| gpa.free(old);
    session.nonce = owned;
}

/// 16 CSPRNG bytes as base64url — a unique DPoP proof id. `scratch`-owned.
fn randomJti(io: std.Io, scratch: Allocator) ![]u8 {
    var raw: [16]u8 = undefined;
    try io.randomSecure(&raw);
    const enc_len = std.base64.url_safe_no_pad.Encoder.calcSize(16);
    const out = try scratch.alloc(u8, enc_len);
    _ = std.base64.url_safe_no_pad.Encoder.encode(out, &raw);
    return out;
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

test "reownSession: oauth fields transfer to dst and the source is released (C6)" {
    const gpa = std.testing.allocator; // C6: a leak in either the dst copy or the
    // src free fails this test (src and dst are the same allocator, so the dupe
    // count and the free count must balance exactly).

    // A worker-owned oauth session (every owned string + the oauth-only fields).
    const src: Session = .{
        .mode = .oauth,
        .did = try gpa.dupe(u8, "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb"),
        .handle = try gpa.dupe(u8, "bob.test"),
        .pds_url = try gpa.dupe(u8, "https://pds.example"),
        .access_jwt = try gpa.dupe(u8, "access-secret"),
        .refresh_jwt = try gpa.dupe(u8, "refresh-secret"),
        .scope = try gpa.dupe(u8, "atproto transition:generic"),
        .issuer = try gpa.dupe(u8, "https://issuer.example"),
        .token_endpoint = try gpa.dupe(u8, "https://issuer.example/token"),
        .nonce = try gpa.dupe(u8, "nonce-xyz"),
        .dpop_secret = [_]u8{7} ** 32,
    };

    const out = try reownSession(gpa, gpa, src); // src is freed inside on success
    defer freeSession(gpa, out);

    try std.testing.expectEqual(AuthMode.oauth, out.mode);
    try std.testing.expectEqualStrings("did:plc:bbbbbbbbbbbbbbbbbbbbbbbb", out.did);
    try std.testing.expectEqualStrings("bob.test", out.handle);
    try std.testing.expectEqualStrings("access-secret", out.access_jwt);
    try std.testing.expectEqualStrings("https://issuer.example/token", out.token_endpoint);
    try std.testing.expectEqualStrings("nonce-xyz", out.nonce.?);
    try std.testing.expectEqualSlices(u8, &([_]u8{7} ** 32), &out.dpop_secret);
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

test "cred_lock serializes concurrent nonce rotation (the shared-Session race)" {
    // The bug: the write-worker thread and the UI thread share one *Session;
    // in oauth mode every request frees+replaces session.nonce (setNonce). Two
    // threads doing that unsynchronized double-free the old nonce / read a
    // dangling one. This test hammers the exact read-then-rotate sequence
    // dpopSend runs, from many threads, under the leak/double-free detector
    // (C6) — the allocator IS the oracle: without the lock it corrupts/aborts.
    const gpa = std.testing.allocator;
    var session = try testSession(gpa, 0);
    session.mode = .oauth; // scope/issuer/token_endpoint stay "" (free is a no-op on len 0)
    session.nonce = try gpa.dupe(u8, "nonce-seed");
    defer freeSession(gpa, session);

    const Hammer = struct {
        fn run(s: *Session, g: Allocator) void {
            var i: usize = 0;
            while (i < 3000) : (i += 1) {
                s.cred_lock.lock();
                defer s.cred_lock.unlock();
                // Read the nonce (as buildProof would) then rotate it (setNonce)
                // — the read-modify-write the lock must make atomic.
                if (s.nonce) |n| {
                    if (n.len == 0xDEAD) unreachable; // force the load, not elided
                }
                setNonce(g, s, "nonce-rotated") catch {};
            }
        }
    };

    var threads: [4]std.Thread = undefined;
    for (&threads) |*t| t.* = try std.Thread.spawn(.{}, Hammer.run, .{ &session, gpa });
    for (threads) |t| t.join();

    // Survived 12k concurrent rotations with no double-free/UAF; the nonce is
    // still exactly one owned allocation (freeSession will prove no leak).
    try std.testing.expect(session.nonce != null);
}
