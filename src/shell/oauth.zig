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
const oauth = @import("../core/oauth.zig");

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
// Tests (C6). The networked `discover` is exercised end-to-end when the flow
// runs (Slice 3) and its parser is golden-tested in core/oauth.zig against the
// real pds.zat4.com documents; here we pin the one pure helper.
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
