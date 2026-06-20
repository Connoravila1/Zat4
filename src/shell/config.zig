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
//! Until the AppView exists (Phase C), the default points at a local stub on
//! loopback, so the client is exercisable end-to-end now. A real deployment
//! overrides it via the `ZAT4_APPVIEW` environment variable — so pointing at
//! a Hetzner box is an env change, never a recompile (the roadmap's
//! "swap without code change" requirement, met).

const std = @import("std");

/// The compiled-in default AppView base URL: a local stub on loopback. The
/// stub answers `app.zat4.feed.getTimeline` / `app.zat4.actor.getProfile`
/// for end-to-end testing before the real AppView is deployed.
pub const default_appview_url = "http://127.0.0.1:2584";

/// The environment variable that overrides the default, so prod/staging
/// point at a real AppView without a recompile.
pub const appview_env_var = "ZAT4_APPVIEW";

/// Endpoint configuration. A7.2: cold config — one per process, constructed
/// once at startup, never in a hot loop. Holds borrowed slices (either the
/// comptime default literal or a slice into the environment block); it owns
/// no memory and frees nothing (C4 — the environ block outlives it).
pub const Endpoints = struct {
    /// Where authenticated AppView reads (timeline, profile) are sent.
    appview_url: []const u8 = default_appview_url,
};

/// Build the endpoint config from the environment (B3 — reads an impure
/// source, so this is shell). `ZAT4_APPVIEW`, if set and non-empty, wins;
/// otherwise the loopback stub default holds. An absent variable is an
/// ordinary state (E4), not an error — the default is the answer.
pub fn fromEnv(environ: ?*const std.process.Environ.Map) Endpoints {
    if (environ) |env| {
        if (env.get(appview_env_var)) |val| {
            if (val.len > 0) return .{ .appview_url = val };
        }
    }
    return .{};
}

// ---------------------------------------------------------------------------
// Tests (C6)
// ---------------------------------------------------------------------------

const testing = std.testing;

test "endpoints: default points at the loopback stub when env is absent" {
    const cfg = fromEnv(null);
    try testing.expectEqualStrings(default_appview_url, cfg.appview_url);
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
