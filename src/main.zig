//! B1 classification: SHELL. Program entry — wires the process allocator and
//! Io capability, then runs the current-frontier demo. Phase 2: resolve a
//! handle, then fetch its profile over XRPC and decode into a typed lexicon
//! record.
//!
//! Usage:  zat [handle]        (default handle: bsky.app)
//!
//! Still no behavior in main beyond choreography: parsing, validation,
//! verification, and decoding live in the cores; fetching lives in the
//! shell modules.

const std = @import("std");
const identity = @import("shell/identity.zig");
const xrpc = @import("shell/xrpc.zig");
const auth = @import("shell/auth.zig");
const feed_shell = @import("shell/feed.zig");
const feed_core = @import("core/feed.zig");
const shell_tui = @import("shell/tui.zig");
const cache_shell = @import("shell/cache.zig");
const window_shell = @import("shell/native.zig");
const lexicon = @import("core/lexicon.zig");

/// The public AppView for unauthenticated reads. A demo choice made HERE,
/// by the caller — the xrpc module is host-agnostic, so the decentralized
/// "host is never hardcoded" property survives in every module below main.
const public_appview = "https://public.api.bsky.app";

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
    for (args[1..]) |arg| {
        if (std.mem.eql(u8, arg, "--tui")) {
            tui_mode = true;
        } else if (std.mem.eql(u8, arg, "--window")) {
            // The same screens in an X11 window; --window implies the
            // interactive run, so it sets tui_mode too.
            window_mode = true;
            tui_mode = true;
        } else {
            handle = arg;
        }
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

    const outcome = try xrpc.query(arena, io, init.environ_map, public_appview, lexicon.method.get_profile, &.{
        .{ .name = "actor", .value = id.did },
    }, lexicon.ProfileViewDetailed, .{});

    switch (outcome) {
        .ok => |profile| try out.print(
            \\profile via XRPC (Phase 2)
            \\  display name: {s}
            \\  followers:    {d}
            \\  following:    {d}
            \\  posts:        {d}
            \\
        , .{
            profile.displayName orelse "(none)",
            profile.followersCount,
            profile.followsCount,
            profile.postsCount,
        }),
        .failed => |failure| {
            try out.print("xrpc refused: status {d} {s}: {s}\n", .{
                failure.status, failure.code, failure.message,
            });
            try out.flush();
            return error.ProfileFetchFailed;
        },
    }
    try out.flush();

    // Phase 3 demo, gated on credentials in the environment (capability-
    // passed — 0.16 has no global getenv, fittingly for this project):
    //   ZAT_APP_PASSWORD=xxxx-xxxx-xxxx-xxxx zat your.handle
    // ZAT_IDENTIFIER overrides the login identifier if it differs from the
    // resolved handle.
    const env = init.environ_map;

    // Phase 8: a cached session (a 0600 file) skips the login round-trip
    // for the screen — deleting the file IS the logout. The print demo
    // below still logs in fresh; it exists to exercise that path. Tokens
    // are re-persisted after the run: the refresh flow may have rotated
    // them mid-session.
    var session_path_buf: [512]u8 = undefined;
    const session_path = cache_shell.sessionPath(&session_path_buf, env);
    if (tui_mode) {
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
                shell_tui.run(gpa, io, env, &session, &store, opened.backend) catch |err| switch (err) {
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
                    shell_tui.run(gpa, io, env, &session, &store, opened.backend) catch |err| switch (err) {
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
                    const loaded = try feed_shell.loadTimelinePage(gpa, arena, io, env, &session, &store, 25);
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
    _ = @import("core/lexicon.zig");
    _ = @import("core/xrpc.zig");
    _ = @import("shell/http.zig");
    _ = @import("shell/identity.zig");
    _ = @import("shell/xrpc.zig");
    _ = @import("shell/auth.zig");
    _ = @import("core/feed.zig");
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
    _ = @import("core/x11.zig");
    _ = @import("core/win32.zig");
    _ = @import("core/textinput.zig");
    _ = @import("core/appkit.zig");
    _ = @import("shell/cache.zig");
    _ = @import("shell/clock.zig");
    _ = @import("shell/window.zig");
    _ = @import("shell/stream.zig");
    _ = @import("shell/write.zig");
    _ = @import("shell/feed.zig");
    _ = @import("shell/tui.zig");
}
