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

//! B1 classification: SHELL. Program entry — wires the process allocator and
//! Io capability, then runs the interactive client. Resolves a handle to an
//! identity, then (with credentials) logs in to the user's own PDS and runs
//! the timeline screen, which reads from the Zat4 AppView (ZAT4_APPVIEW).
//!
//! Usage:  zat [handle]        (default handle: bsky.app)
//!
//! Still no behavior in main beyond choreography: parsing, validation,
//! verification, and decoding live in the cores; fetching lives in the
//! shell modules.

const std = @import("std");
const identity = @import("shell/identity.zig");
const auth = @import("shell/auth.zig");
const feed_shell = @import("shell/feed.zig");
const feed_core = @import("core/feed.zig");
const shell_tui = @import("shell/tui.zig");
const enroll_run = @import("shell/enroll_run.zig");
const cache_shell = @import("shell/cache.zig");
const config = @import("shell/config.zig");
const window_shell = @import("shell/native.zig");
const lexicon = @import("core/lexicon.zig");
const write = @import("shell/write.zig");
const clock_shell = @import("shell/clock.zig");

/// Is there a usable cached session on disk? A cheap pre-auth probe: a new user
/// (no cache) is sent to enrollment; a returning user (cache present) falls
/// through to the normal cached-session run path. Loads and frees the tiny 0600
/// file once — negligible, and it runs at most once per launch.
fn hasCachedSession(gpa: std.mem.Allocator, env: ?*const std.process.Environ.Map) bool {
    var buf: [512]u8 = undefined;
    const sp = cache_shell.sessionPath(&buf, env) orelse return false;
    if (cache_shell.loadSessionAt(gpa, sp)) |cached| {
        var s = cached;
        cache_shell.freeSession(gpa, &s);
        return true;
    }
    return false;
}

/// Trim display text to `max` bytes without splitting a UTF-8 sequence.
fn truncate(text: []const u8, max: usize) []const u8 {
    if (text.len <= max) return text;
    var end = max;
    while (end > 0 and (text[end] & 0xC0) == 0x80) end -= 1;
    return text[0..end];
}

/// One backend for both session paths — was duplicated at each (the
/// recorded D6 smell, now extracted). The caller owns the close via the
/// returned handle.
fn openBackend(
    gpa: std.mem.Allocator,
    env: ?*const std.process.Environ.Map,
    out: *std.Io.Writer,
    window_mode: bool,
) !struct { backend: shell_tui.Backend, win: ?*window_shell.Window } {
    if (!window_mode) return .{ .backend = .terminal, .win = null };
    const win = window_shell.open(gpa, env, "zat", 110, 32) catch |err| {
        try out.print("--window could not open a native window ({s}); on X11, is DISPLAY set?\n", .{@errorName(err)});
        try out.flush();
        return err;
    };
    return .{ .backend = .{ .window = win }, .win = win };
}

pub fn main(init: std.process.Init) !void {
    // Debug builds wire this gpa for leak detection automatically; a leak at
    // exit is reported, in the spirit of C6 everywhere, not only in tests.
    const gpa = init.gpa;
    const io = init.io;

    // C3: one arena per unit of work — this resolve-and-fetch — freed
    // wholesale. Identity strings, URLs, bodies, and the decoded profile all
    // land here: nothing to free piecemeal.
    var request_arena = std.heap.ArenaAllocator.init(gpa);
    defer request_arena.deinit();
    const arena = request_arena.allocator();

    const args = try init.minimal.args.toSlice(arena);
    var handle: []const u8 = "bsky.app";
    var tui_mode = false;
    var window_mode = false;
    // Headless write-path test (STANDALONE write leg): `--post "text"` publishes
    // one app.zat4.feed.post and exits, bypassing the GUI composer. The value is
    // the next argument.
    var post_text: ?[]const u8 = null;
    // Headless graph-write leg: `--follow <handle-or-did>` publishes one
    // app.zat4.graph.follow from the logged-in account (the positional handle)
    // to the target and exits. The value is the next argument.
    var follow_target: ?[]const u8 = null;
    var ai: usize = 1;
    while (ai < args.len) : (ai += 1) {
        const arg = args[ai];
        if (std.mem.eql(u8, arg, "--tui")) {
            tui_mode = true;
        } else if (std.mem.eql(u8, arg, "--window")) {
            // The same screens in an X11 window; --window implies the
            // interactive run, so it sets tui_mode too.
            window_mode = true;
            tui_mode = true;
        } else if (std.mem.eql(u8, arg, "--post")) {
            if (ai + 1 < args.len) {
                ai += 1;
                post_text = args[ai];
            }
        } else if (std.mem.eql(u8, arg, "--follow")) {
            if (ai + 1 < args.len) {
                ai += 1;
                follow_target = args[ai];
            }
        } else {
            handle = arg;
        }
    }

    const env = init.environ_map;

    // Pre-auth front door: a window launch with NO credentials and NO cached
    // session is a new user — show the "Join Zat4" flow instead of resolving a
    // handle or demanding a password. A returning user (cache present, or a
    // password supplied) falls through to the normal login/run paths below.
    // Slice 3: this is the LOCAL enrollment surface in the live app; the
    // networked createAccount + hand-off-to-feed legs are a later slice.
    if (window_mode and env.get("ZAT_APP_PASSWORD") == null and !hasCachedSession(gpa, env)) {
        try enroll_run.run(gpa, io, env);
        return;
    }

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer: std.Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const out = &stdout_writer.interface;

    const id = try identity.resolve(arena, io, init.environ_map, .{}, handle);

    try out.print(
        \\identity (Phase 1)
        \\  handle:      {s}
        \\  did:         {s}
        \\  pds:         {s}
        \\  signing key: {s}
        \\
    , .{ id.handle, id.did, id.pds_url, id.signing_key_multibase });
    try out.flush();

    // Phase 3 demo, gated on credentials in the environment (capability-
    // passed — 0.16 has no global getenv, fittingly for this project):
    //   ZAT_APP_PASSWORD=xxxx-xxxx-xxxx-xxxx zat your.handle
    // ZAT_IDENTIFIER overrides the login identifier if it differs from the
    // resolved handle.

    // Phase B: the one endpoint-config seat. Reads (timeline, profile) go to
    // the Zat4 AppView at this URL; writes/auth stay on the user's own PDS.
    // Defaults to a loopback stub; ZAT4_APPVIEW overrides it (a Hetzner box
    // is an env change, never a recompile).
    const endpoints = config.fromEnv(env);

    // Phase 8: a cached session (a 0600 file) skips the login round-trip
    // for the screen — deleting the file IS the logout. The print demo
    // below still logs in fresh; it exists to exercise that path. Tokens
    // are re-persisted after the run: the refresh flow may have rotated
    // them mid-session.
    var session_path_buf: [512]u8 = undefined;
    const session_path = cache_shell.sessionPath(&session_path_buf, env);

    // Headless post: establish a session (a fresh ZAT_APP_PASSWORD login is
    // preferred for a one-shot write since a cached token may have expired;
    // otherwise reuse the cached session), publish the post, print the
    // resulting at-uri/cid, and exit. This is the write-leg test: the record
    // lands in the user's OWN PDS under app.zat4.feed.post, from where the
    // firehose carries it to the Zat4 AppView.
    if (post_text != null or follow_target != null) {
        var from_cache = false;
        var session: auth.Session = undefined;
        if (env.get("ZAT_APP_PASSWORD")) |password| {
            const identifier = env.get("ZAT_IDENTIFIER") orelse id.handle;
            switch (try auth.login(gpa, arena, io, env, id.pds_url, identifier, password)) {
                .refused => |f| {
                    try out.print("login refused: status {d} {s}: {s}\n", .{ f.status, f.code, f.message });
                    try out.flush();
                    return error.LoginFailed;
                },
                .ok => |established| session = established,
            }
        } else if (session_path) |sp| {
            session = cache_shell.loadSessionAt(gpa, sp) orelse {
                try out.print("--post/--follow needs credentials: set ZAT_APP_PASSWORD (or run the app once to cache a login)\n", .{});
                try out.flush();
                return error.LoginFailed;
            };
            from_cache = true;
        } else {
            try out.print("--post/--follow needs credentials: set ZAT_APP_PASSWORD\n", .{});
            try out.flush();
            return error.LoginFailed;
        }
        defer if (from_cache) cache_shell.freeSession(gpa, &session) else auth.freeSession(gpa, session);
        if (session_path) |sp| _ = cache_shell.saveSessionAt(gpa, sp, &session); // persist rotated tokens (E4)

        const now = clock_shell.unixSeconds();

        // The post leg: publish one app.zat4.feed.post into the user's own PDS,
        // from where the AppView's poll/firehose carries it into Zat4.
        if (post_text) |text| {
            const outcome = write.createPost(gpa, arena, io, env, &session, text, &[_]lexicon.Facet{}, null, now) catch |err| {
                try out.print("post failed: {s}\n", .{@errorName(err)});
                try out.flush();
                return err;
            };
            switch (outcome) {
                .ok => |ref| try out.print("posted app.zat4.feed.post\n  uri: {s}\n  cid: {s}\n", .{ ref.uri, ref.cid }),
                .failed => |f| try out.print("post refused: status {d} {s}: {s}\n", .{ f.status, f.code, f.message }),
            }
            try out.flush();
        }

        // The follow leg: resolve the target to a DID (a `did:` literal is used
        // as-is) and publish one app.zat4.graph.follow into the user's own PDS.
        if (follow_target) |target| {
            const subject_did = if (std.mem.startsWith(u8, target, "did:")) target else blk: {
                const resolved = identity.resolve(arena, io, env, .{}, target) catch |err| {
                    try out.print("--follow: could not resolve {s}: {s}\n", .{ target, @errorName(err) });
                    try out.flush();
                    return err;
                };
                break :blk resolved.did;
            };
            const outcome = write.followAccount(gpa, arena, io, env, &session, subject_did, now) catch |err| {
                try out.print("follow failed: {s}\n", .{@errorName(err)});
                try out.flush();
                return err;
            };
            switch (outcome) {
                .ok => |ref| try out.print("followed {s}\n  subject: {s}\n  uri: {s}\n", .{ target, subject_did, ref.uri }),
                .failed => |f| try out.print("follow refused: status {d} {s}: {s}\n", .{ f.status, f.code, f.message }),
            }
            try out.flush();
        }
        return;
    }

    // The cached session is only the NO-PASSWORD fallback. When ZAT_APP_PASSWORD
    // is given it must WIN — otherwise a stale cached session (expired/revoked
    // tokens) is used forever and every write fails `ExpiredToken`, even though
    // the user supplied fresh credentials. So skip the cache path when a
    // password is present and fall through to the fresh login below.
    if (tui_mode and env.get("ZAT_APP_PASSWORD") == null) {
        if (session_path) |sp| {
            if (cache_shell.loadSessionAt(gpa, sp)) |cached| {
                var session = cached;
                defer cache_shell.freeSession(gpa, &session);
                defer _ = cache_shell.saveSessionAt(gpa, sp, &session); // E4: failure = no cache
                var store = cache_shell.loadStore(gpa, env) orelse feed_core.Store{};
                defer feed_core.deinitStore(gpa, &store);
                defer _ = cache_shell.saveStore(gpa, env, &store); // E4
                const opened = try openBackend(gpa, env, out, window_mode);
                defer if (opened.win) |w| window_shell.close(w);
                shell_tui.run(gpa, io, env, &session, endpoints.appview_url, &store, opened.backend) catch |err| switch (err) {
                    error.NotATerminal => {
                        try out.print("--tui needs an interactive terminal (a real stdin/stdout tty)\n", .{});
                        try out.flush();
                        return err;
                    },
                    else => return err,
                };
                return;
            }
        }
    }

    if (env.get("ZAT_APP_PASSWORD")) |password| {
        const identifier = env.get("ZAT_IDENTIFIER") orelse id.handle;
        const login_outcome = try auth.login(gpa, arena, io, env, id.pds_url, identifier, password);
        switch (login_outcome) {
            .refused => |failure| {
                try out.print("login refused: status {d} {s}: {s}\n", .{
                    failure.status, failure.code, failure.message,
                });
                try out.flush();
                return error.LoginFailed;
            },
            .ok => |established| {
                var session = established;
                defer auth.freeSession(gpa, session);

                // Phase 5: the screen. --tui hands the session and an
                // empty store to the renderer; everything after this line
                // is the print demo for non-interactive runs.
                if (session_path) |sp| _ = cache_shell.saveSessionAt(gpa, sp, &session); // E4
                if (tui_mode) {
                    var store = cache_shell.loadStore(gpa, env) orelse feed_core.Store{};
                    defer feed_core.deinitStore(gpa, &store);
                    defer _ = cache_shell.saveStore(gpa, env, &store); // E4
                    defer if (session_path) |sp| {
                        _ = cache_shell.saveSessionAt(gpa, sp, &session); // rotated tokens
                    };
                    const opened = try openBackend(gpa, env, out, window_mode);
                    defer if (opened.win) |w| window_shell.close(w);
                    shell_tui.run(gpa, io, env, &session, endpoints.appview_url, &store, opened.backend) catch |err| switch (err) {
                        error.NotATerminal => {
                            try out.print("--tui needs an interactive terminal (a real stdin/stdout tty)\n", .{});
                            try out.flush();
                            return err;
                        },
                        else => return err,
                    };
                    return;
                }

                const who = try auth.query(gpa, arena, io, env, &session, lexicon.method.get_session, &.{}, lexicon.GetSessionResponse);
                switch (who) {
                    .ok => |confirmed| try out.print(
                        \\session via XRPC (Phase 3)
                        \\  authenticated as: {s} ({s}) -- server-confirmed
                        \\
                    , .{ confirmed.handle, confirmed.did }),
                    .failed => |failure| {
                        try out.print("getSession refused: status {d} {s}: {s}\n", .{
                            failure.status, failure.code, failure.message,
                        });
                        try out.flush();
                        return error.SessionCheckFailed;
                    },
                }
                try out.flush();

                // Phase 4: two pages of the real timeline into the SoA
                // store, then render-ready view-models.
                var store: feed_core.Store = .{};
                defer feed_core.deinitStore(gpa, &store);

                var pages_loaded: u32 = 0;
                var page: u32 = 0;
                while (page < 2) : (page += 1) {
                    if (page > 0 and feed_core.nextCursor(&store).len == 0) break;
                    const loaded = try feed_shell.loadTimelinePage(gpa, arena, io, env, &session, endpoints.appview_url, &store, 25);
                    switch (loaded) {
                        .failed => |failure| {
                            try out.print("getTimeline refused: status {d} {s}: {s}\n", .{
                                failure.status, failure.code, failure.message,
                            });
                            try out.flush();
                            return error.TimelineFetchFailed;
                        },
                        .ok => |stats| {
                            pages_loaded += 1;
                            try out.print("timeline page {d}: +{d} items, +{d} posts, {d} deduped, +{d} authors\n", .{
                                pages_loaded, stats.items_added, stats.posts_added, stats.posts_deduped, stats.authors_added,
                            });
                        },
                    }
                }

                const items = try feed_core.buildTimeline(arena, &store);
                try out.print(
                    \\timeline via the SoA store (Phase 4)
                    \\  resident: {d} posts, {d} authors, {d} feed items
                    \\
                , .{ store.posts.len, store.authors.len, store.feed.len });
                const shown = @min(items.len, 5);
                for (items[0..shown]) |item| {
                    if (item.reposted_by_handle.len > 0) {
                        try out.print("  [reposted by @{s}]\n", .{item.reposted_by_handle});
                    }
                    if (item.replying_to_handle.len > 0) {
                        try out.print("  @{s} -> @{s}: {s}\n", .{ item.author_handle, item.replying_to_handle, truncate(item.text, 60) });
                    } else {
                        try out.print("  @{s}: {s}\n", .{ item.author_handle, truncate(item.text, 60) });
                    }
                    try out.print("      {d} likes, {d} reposts, {d} replies\n", .{ item.like_count, item.repost_count, item.reply_count });
                }
            },
        }
    } else {
        if (tui_mode) {
            try out.print("--tui needs credentials: set ZAT_APP_PASSWORD (and optionally ZAT_IDENTIFIER)\n", .{});
        } else {
            try out.print("(set ZAT_APP_PASSWORD to demo authentication; add --tui for the timeline screen)\n", .{});
        }
    }
    try out.flush();
}

test {
    // Pull every source file into the test build so its tests run and its
    // comptime guards (A7) are semantically analyzed on every `zig build test`.
    _ = @import("core/identity.zig");
    _ = @import("core/sigverify.zig");
    _ = @import("core/dagcbor.zig");
    _ = @import("core/cid.zig");
    _ = @import("core/dagjson.zig");
    _ = @import("core/netguard.zig");
    _ = @import("core/jsonguard.zig");
    _ = @import("core/lexicon.zig");
    _ = @import("core/xrpc.zig");
    _ = @import("shell/http.zig");
    _ = @import("shell/identity.zig");
    _ = @import("shell/xrpc.zig");
    _ = @import("shell/auth.zig");
    _ = @import("core/feed.zig");
    _ = @import("core/feed_view.zig");
    _ = @import("core/lens_socket.zig");
    _ = @import("core/lens_catalog.zig");
    _ = @import("shell/loadout.zig");
    _ = @import("core/appview.zig");
    _ = @import("core/moderation.zig");
    _ = @import("core/tui.zig");
    _ = @import("core/timeline_ui.zig");
    _ = @import("core/field.zig");
    _ = @import("core/effect.zig");
    _ = @import("core/field_ui.zig");
    _ = @import("core/compose.zig");
    _ = @import("core/websocket.zig");
    _ = @import("core/jetstream.zig");
    _ = @import("core/snapshot.zig");
    _ = @import("core/layout.zig");
    _ = @import("core/raster.zig");
    _ = @import("core/text.zig");
    _ = @import("core/atlas.zig");
    _ = @import("core/glyph_field.zig");
    _ = @import("core/x11.zig");
    _ = @import("core/win32.zig");
    _ = @import("core/textinput.zig");
    _ = @import("core/textedit.zig");
    _ = @import("core/appkit.zig");
    _ = @import("shell/cache.zig");
    _ = @import("shell/config.zig");
    _ = @import("shell/appview_ingest.zig");
    _ = @import("shell/appview_serve.zig");
    _ = @import("shell/clock.zig");
    _ = @import("shell/window.zig");
    _ = @import("shell/stream.zig");
    _ = @import("shell/write.zig");
    _ = @import("shell/write_worker.zig");
    _ = @import("core/pow.zig");
    _ = @import("shell/pow.zig");
    _ = @import("core/credential.zig");
    _ = @import("shell/credential.zig");
    _ = @import("core/membership.zig");
    _ = @import("shell/membership.zig");
    _ = @import("core/enroll_view.zig");
    _ = @import("shell/enroll_run.zig");
    _ = @import("shell/feed.zig");
    _ = @import("shell/tui.zig");
}
