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

//! B1 classification: SHELL (reads the environment — an impure source).
//!
//! The endpoint configuration seat (STANDALONE_ROADMAP Phase B). ONE place
//! decides where AppView reads go, so dev/local/prod swap without a code
//! change to any other module (D6 — a deployment change is one edit here,
//! not a hunt through the read paths). The value is threaded from the shell
//! entry into the read paths; no module reaches for it implicitly.
//!
//! The read/write split this enables is the whole point of going standalone:
//!  - WRITES and AUTH go to the user's own PDS (`session.pds_url`) — a Zat4
//!    post lands in the user's own repo, signed by their own identity. That
//!    host is per-user, resolved at login, and is NOT configured here.
//!  - READS (timeline, profile) go to the ZAT4 APPVIEW — the indexing
//!    service that assembles feeds across many repos. That host is a single
//!    deployment value, and it lives here.
//!
//! The compiled-in default is the PRODUCTION endpoint (DISTRIBUTION_ROADMAP
//! T3): a double-clicked download must reach the live network with zero
//! environment setup, so the default is the shipping value and `ZAT4_APPVIEW`
//! is the dev/staging OVERRIDE (a local stub, the old SSH tunnel, a test
//! box) — never the other way around.

const std = @import("std");

/// The compiled-in default AppView base URL: the live deployment, served on
/// the already-trusted PDS host under a path (see DEPLOY_STATE — a separate
/// subdomain would fail the PDS's on-demand tls-check). The AppView's own
/// bearer gate does auth; TLS terminates at the edge.
pub const default_appview_url = "https://pds.zat4.com/appview";

/// The environment variable that overrides the default, so prod/staging
/// point at a real AppView without a recompile.
pub const appview_env_var = "ZAT4_APPVIEW";

/// The PDS that mints new `*.zat4.com` accounts (where enrollment's
/// `createAccount` is sent). `ZAT_PDS` overrides it without a recompile.
pub const default_pds_url = "https://pds.zat4.com";
pub const pds_env_var = "ZAT_PDS";

/// Zat4's OAuth client identity. `oauth_client_id` MUST equal the URL the
/// client metadata is hosted at (the spec requires it); it is served on the box
/// (see `deploy/zat4-client-metadata.json`). The scope is what the feature set
/// needs: identity plus full record read/write during the atproto transition.
pub const oauth_client_id = "https://pds.zat4.com/client-metadata.json";
pub const oauth_scope = "atproto transition:generic";

/// Endpoint configuration. A7.2: cold config — one per process, constructed
/// once at startup, never in a hot loop. Holds borrowed slices (either the
/// comptime default literal or a slice into the environment block); it owns
/// no memory and frees nothing (C4 — the environ block outlives it).
pub const Endpoints = struct {
    /// Where authenticated AppView reads (timeline, profile) are sent.
    appview_url: []const u8 = default_appview_url,
    /// The PDS new accounts are minted on (enrollment `createAccount`).
    pds_url: []const u8 = default_pds_url,
};

/// Build the endpoint config from the environment (B3 — reads an impure
/// source, so this is shell). A set, non-empty override wins; otherwise the
/// default holds. An absent variable is an ordinary state (E4), not an error.
pub fn fromEnv(environ: ?*const std.process.Environ.Map) Endpoints {
    var out: Endpoints = .{};
    if (environ) |env| {
        if (env.get(appview_env_var)) |val| {
            if (val.len > 0) out.appview_url = val;
        }
        if (env.get(pds_env_var)) |val| {
            if (val.len > 0) out.pds_url = val;
        }
    }
    return out;
}

// ---------------------------------------------------------------------------
// Tests (C6)
// ---------------------------------------------------------------------------

const testing = std.testing;

test "endpoints: default points at the live AppView when env is absent" {
    const cfg = fromEnv(null);
    try testing.expectEqualStrings(default_appview_url, cfg.appview_url);
    // The shipping default must be TLS and never loopback (T3: a bare
    // download reaches the network; loopback is the dev override's job).
    try testing.expect(std.mem.startsWith(u8, cfg.appview_url, "https://"));
}

test "endpoints: ZAT4_APPVIEW overrides the default; empty is ignored" {
    var env: std.process.Environ.Map = .init(testing.allocator);
    defer env.deinit();

    // Empty value falls back to the default (an empty override is no override).
    try env.put(appview_env_var, "");
    try testing.expectEqualStrings(default_appview_url, fromEnv(&env).appview_url);

    // A real value wins — the Hetzner-box case.
    try env.put(appview_env_var, "https://appview.zat4.example");
    try testing.expectEqualStrings("https://appview.zat4.example", fromEnv(&env).appview_url);
}
