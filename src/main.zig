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
const builtin = @import("builtin");
const dist_config = @import("dist_config");
const identity = @import("shell/identity.zig");
const auth = @import("shell/auth.zig");
const oauth_shell = @import("shell/oauth.zig");
const feed_shell = @import("shell/feed.zig");
const feed_core = @import("core/feed.zig");
const shell_tui = @import("shell/tui.zig");
const enroll_run = @import("shell/enroll_run.zig");
const credential_shell = @import("shell/credential.zig");
const cache_shell = @import("shell/cache.zig");
const config = @import("shell/config.zig");
const window_shell = @import("shell/native.zig");

/// The window title (X11 WM_NAME / the app's on-screen name). The standalone Zat
/// Chat flavor wears its own; the full client is "Zat4". Comptime build identity.
const win_title = if (dist_config.product == .chat) "Zat Chat" else "Zat4";
const lexicon = @import("core/lexicon.zig");
const anchor_core = @import("core/anchor.zig");
const write = @import("shell/write.zig");
const chat_keys = @import("shell/chat_keys.zig");
const pay_addr = @import("shell/pay_addr.zig");
const payuri = @import("core/payuri.zig");
const lnurl = @import("shell/lnurl.zig");
const wallet_caps = @import("core/wallet_caps.zig");
const chat_core = @import("core/chat.zig");
const launch = @import("shell/launch.zig");
const chainwatch_core = @import("core/chainwatch.zig");
const chainwatch_shell = @import("shell/chainwatch.zig");
const algorithm_shell = @import("shell/algorithm.zig");
const algo_gate = @import("core/algo_gate.zig");
const discover = @import("core/discover.zig");
const builder = @import("core/builder.zig");
const lens_catalog = @import("core/lens_catalog.zig");
const clock_shell = @import("shell/clock.zig");

/// The dev app-password, fenced (DISTRIBUTION_ROADMAP T4): a distribution
/// build never reads the credential env vars — in-app login (enrollment /
/// browser OAuth) is a tester's only path, so a tester machine's stray
/// environment can never steer authentication. Dev builds keep the
/// env-var workflow unchanged.
fn appPassword(env: ?*const std.process.Environ.Map) ?[]const u8 {
    if (comptime dist_config.dist) return null;
    const e = env orelse return null;
    return e.get("ZAT_APP_PASSWORD");
}

/// Is there a usable cached session on disk? A cheap pre-auth probe: a new user
/// (no cache) is sent to enrollment; a returning user (cache present) falls
/// through to the normal cached-session run path. Loads and frees the tiny 0600
/// file once — negligible, and it runs at most once per launch.
/// The pre-auth front door: the SHELL with no session. Returns the session
/// enrollment produced, or null if the person closed the window.
///
/// This replaces `enroll_run.run`, which owned a window — the thing a phone does
/// not have, and the reason a phone could not create an account at all. Same
/// flow, same card, one loop.
fn frontDoor(gpa: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map) !?auth.Session {
    var store = feed_core.Store{};
    defer feed_core.deinitStore(gpa, &store);
    const eps = config.fromEnv(env);
    const win = window_shell.open(gpa, env, win_title, 110, 32) catch |err| {
        std.debug.print("Zat4: could not open a native window ({s})\n", .{@errorName(err)});
        return null;
    };
    defer window_shell.close(win);
    var enrolled: ?auth.Session = null;
    _ = shell_tui.run(gpa, io, env, null, eps.appview_url, &store, .{ .window = win }, &enrolled) catch |err| {
        std.debug.print("Zat4: the front door ended on an error ({s})\n", .{@errorName(err)});
    };
    return enrolled;
}

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

/// The --export-session success message: where the file went and the exact
/// adb steps that provision it into the phone's files dir (MC.4d).
fn printExportRecipe(out: *std.Io.Writer, handle: []const u8, path: []const u8, target_name: []const u8) !void {
    try out.print(
        \\[export] {s} -> {s} (plain 0600 file, LIVE tokens — delete after the push)
        \\[export] provision:  adb push {s} /data/local/tmp/{s}
        \\[export]             adb shell run-as com.zat4.client sh -c 'mkdir -p files/.cache/zat && cp /data/local/tmp/{s} files/.cache/zat/'
        \\[export]             adb shell rm /data/local/tmp/{s} && rm {s}
        \\
    , .{ handle, path, path, target_name, target_name, target_name, path });
}

/// Print the publish gate's named refusals (algo_gate, Phase 5) — the
/// author-facing half of shell/algorithm.publish's fail-closed error.
fn printGateRefusals(out: *std.Io.Writer, cfg: discover.FeedConfig) !void {
    const v = algo_gate.gate(cfg);
    if (v.pass()) return;
    try out.print("publish gate refused ({d} reason(s)):\n", .{v.count});
    for (v.list()) |r| try out.print("  - {s}\n", .{algo_gate.label(r)});
    try out.flush();
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
    const win = window_shell.open(gpa, env, win_title, 110, 32) catch |err| {
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
    // Off-Linux the windowed GUI is the NO-ARGS default: a double-clicked
    // exe passes no flags, and there is no terminal story there anyway (the
    // terminal backend is compiled out on Windows). On Linux the terminal
    // default stays and --window opts in as before. (DISTRIBUTION_ROADMAP W2)
    const windowed_os = builtin.os.tag == .windows or builtin.os.tag.isDarwin();
    var tui_mode = windowed_os;
    var window_mode = windowed_os;
    var front_door = false;
    // Headless write-path test (STANDALONE write leg): `--post "text"` publishes
    // one app.zat4.feed.post and exits, bypassing the GUI composer. The value is
    // the next argument.
    var post_text: ?[]const u8 = null;
    // Headless graph-write leg: `--follow <handle-or-did>` publishes one
    // app.zat4.graph.follow from the logged-in account (the positional handle)
    // to the target and exits. The value is the next argument.
    var follow_target: ?[]const u8 = null;
    // Dev harness: `--publish-algo <name>` writes one app.zat4.feed.algorithm
    // record (the friendly-builder's default config) into the user's repo, so the
    // marketplace has content to index before the authoring UI exists.
    var publish_algo_name: ?[]const u8 = null;
    // Dev harness: `--publish-discover` publishes the house Zat4 Discover config
    // (L1 weights + L2 rules + L3 formula — the full-stack showcase) as a record.
    var publish_discover = false;
    // Headless sign-up test (enrollment 3b): `--create-account <username>` mints
    // <username>.zat4.com on the PDS with a fresh CSPRNG password and exits,
    // printing the handle/DID/password. No GUI, no display, no tunnel (the PDS is
    // a public HTTPS host). `--email` and `--invite` set those; the invite falls
    // back to ZAT_INVITE_CODE. This exercises the same `auth.createAccount` the
    // GUI flow uses, so the network leg can be verified in one command.
    var create_account_user: ?[]const u8 = null;
    var email_arg: ?[]const u8 = null;
    var invite_arg: ?[]const u8 = null;
    // Headless OAuth login test (OAuth slice 3): `--oauth-login <handle>` runs the
    // full browser authorization-code flow against the account's PDS and prints
    // the DPoP-bound result, then exits. Opens the system browser; needs one sign-in.
    var oauth_login_handle: ?[]const u8 = null;
    // OAuth persistence test (slice 5): `--oauth-resume` loads the saved DPoP
    // session and makes an authenticated call WITHOUT re-login, proving the key
    // and tokens survive across launches.
    var oauth_resume = false;
    // Dev provisioning target (MC.4d): `--export-session <path>` writes the
    // cached OAuth session to a plain file for the adb push to a phone.
    var export_session_path: ?[]const u8 = null;
    // Chat anchor test (Zat Chat slice C6): `--chat-anchor <did>` loads or
    // creates the device-bound anchor key for that DID, prints its public key,
    // and self-verifies the DID binding. Run twice: "created" then "loaded"
    // with the SAME public key proves persistence (keystore or 0600 file).
    var chat_anchor_did: ?[]const u8 = null;
    // Chat key-directory test (U6): `--chat-publish` (with a handle + password)
    // publishes THIS account's last-resort keyPackage record, then fetches it
    // back through the public directory path and validates the whole chain
    // (anchor binding, suite, expiry, signatures) — the full U6 loop, headless.
    var chat_publish = false;
    // THE REPAIR: `--chat-reclaim` makes THIS device the account's chat device
    // again — it removes every OTHER device record and re-asserts the singleton
    // from this device's stored key. It exists because a device that could not read
    // the directory once concluded it was the root and seized the account's chat
    // identity (2026-07-14); the honest way back is a person, at the keyboard,
    // saying which device is real. It never runs on the app's own initiative.
    var chat_reclaim = false;
    // Payment-address directory test (M5 A2): `--pay-publish <lightning|-> <bitcoin|->`
    // validates the addresses (full checksums), publishes the anchor-signed
    // app.zat4.pay.address record, then fetches it back the way a PAYER would
    // (public getRecord + the core gate against the anchor key) — the full A2
    // loop, headless. "-" leaves that rail unpublished.
    var pay_publish_ln: ?[]const u8 = null;
    var pay_publish_btc: ?[]const u8 = null;
    var pay_publish = false;
    // Payment hand-off test (M5 A3): `--pay-handoff <address> <sats> <note|->`
    // builds the standard wallet URI (BIP-21 for an on-chain address,
    // lightning: for a LUD-16 one — picked by shape), prints it, and hands it
    // to the OS default handler. Purely local — no network, no session. If no
    // wallet is registered for the scheme, the printed URI is the fallback.
    var pay_handoff_addr: ?[]const u8 = null;
    var pay_handoff_sats: ?[]const u8 = null;
    var pay_handoff_note: ?[]const u8 = null;
    // Confirmation-watcher test (M5 A5): `--watch-address <address> <sats>`
    // asks the configured chain source (ZAT_CHAIN_API, default mempool.space)
    // how the network sees that address+amount and prints the verdict the
    // six-block animation would draw. Purely read-only public data.
    var watch_addr: ?[]const u8 = null;
    var watch_sats: ?[]const u8 = null;
    // LNURL-pay exactness test: `--pay-invoice <lightning-address> <sats>` runs
    // the real LUD-06/16 leg against a live provider (resolve the address →
    // fetch a BOLT11 for exactly that amount) and prints the `lightning:`
    // hand-off URI the wallet would receive. Read-only, no session.
    var invoice_addr: ?[]const u8 = null;
    var invoice_sats: ?[]const u8 = null;
    var probe_addr: ?[]const u8 = null;
    var ai: usize = 1;
    while (ai < args.len) : (ai += 1) {
        const arg = args[ai];
        if (std.mem.eql(u8, arg, "--create-account")) {
            if (ai + 1 < args.len) {
                ai += 1;
                create_account_user = args[ai];
            }
        } else if (std.mem.eql(u8, arg, "--email")) {
            if (ai + 1 < args.len) {
                ai += 1;
                email_arg = args[ai];
            }
        } else if (std.mem.eql(u8, arg, "--invite")) {
            if (ai + 1 < args.len) {
                ai += 1;
                invite_arg = args[ai];
            }
        } else if (std.mem.eql(u8, arg, "--oauth-login")) {
            if (ai + 1 < args.len) {
                ai += 1;
                oauth_login_handle = args[ai];
            }
        } else if (std.mem.eql(u8, arg, "--oauth-resume")) {
            oauth_resume = true;
        } else if (std.mem.eql(u8, arg, "--export-session")) {
            if (ai + 1 < args.len) {
                ai += 1;
                export_session_path = args[ai];
            }
        } else if (std.mem.eql(u8, arg, "--chat-anchor")) {
            if (ai + 1 < args.len) {
                ai += 1;
                chat_anchor_did = args[ai];
            }
        } else if (std.mem.eql(u8, arg, "--chat-publish")) {
            chat_publish = true;
        } else if (std.mem.eql(u8, arg, "--chat-reclaim")) {
            chat_reclaim = true;
        } else if (std.mem.eql(u8, arg, "--pay-publish")) {
            if (ai + 2 < args.len) {
                pay_publish_ln = args[ai + 1];
                pay_publish_btc = args[ai + 2];
                ai += 2;
                pay_publish = true;
            }
        } else if (std.mem.eql(u8, arg, "--pay-handoff")) {
            if (ai + 3 < args.len) {
                pay_handoff_addr = args[ai + 1];
                pay_handoff_sats = args[ai + 2];
                pay_handoff_note = args[ai + 3];
                ai += 3;
            }
        } else if (std.mem.eql(u8, arg, "--wallet-probe")) {
            if (ai + 1 < args.len) {
                probe_addr = args[ai + 1];
                ai += 1;
            }
        } else if (std.mem.eql(u8, arg, "--pay-invoice")) {
            if (ai + 2 < args.len) {
                invoice_addr = args[ai + 1];
                invoice_sats = args[ai + 2];
                ai += 2;
            }
        } else if (std.mem.eql(u8, arg, "--watch-address")) {
            if (ai + 2 < args.len) {
                watch_addr = args[ai + 1];
                watch_sats = args[ai + 2];
                ai += 2;
            }
        } else if (std.mem.eql(u8, arg, "--tui")) {
            tui_mode = true;
        } else if (std.mem.eql(u8, arg, "--front-door")) {
            // FRONT_DOOR_ROADMAP phase 1: run the SHELL with no session, so the
            // pre-auth app can be exercised on the real run loop (the one a phone
            // also reaches) before the flow is wired and enroll_run's private
            // window is retired.
            front_door = true;
            tui_mode = true;
            window_mode = true;
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
        } else if (std.mem.eql(u8, arg, "--publish-algo")) {
            if (ai + 1 < args.len) {
                ai += 1;
                publish_algo_name = args[ai];
            }
        } else if (std.mem.eql(u8, arg, "--publish-discover")) {
            publish_discover = true;
        } else {
            handle = arg;
        }
    }

    const env = init.environ_map;

    // Pre-auth front door: a window launch with NO credentials and NO cached
    // session is a new user, so show the "Join Zat4" flow instead of resolving a
    // handle or demanding a password. A returning user (cache present, or a
    // password supplied) falls through to the normal login/run paths below.
    // On a completed sign-up, the flow hands back a session: cache it (so the
    // next launch goes straight to the feed) and drop into the feed now.
    // FRONT_DOOR_ROADMAP phase 1. Checked BEFORE the cached-session gate on
    // purpose: the whole point of the flag is to exercise the pre-auth app on a
    // machine that already HAS a session, without wiping it.
    if (front_door) {
        var store = feed_core.Store{};
        defer feed_core.deinitStore(gpa, &store);
        const eps = config.fromEnv(env);
        const win = window_shell.open(gpa, env, win_title, 110, 32) catch |err| {
            std.debug.print("Zat4: could not open a native window ({s})\n", .{@errorName(err)});
            return;
        };
        defer window_shell.close(win);
        std.debug.print("[front-door] running the shell with NO session — the pre-auth app.\n", .{});
        var enrolled: ?auth.Session = null;
        _ = shell_tui.run(gpa, io, env, null, eps.appview_url, &store, .{ .window = win }, &enrolled) catch |err| {
            std.debug.print("Zat4: the front door ended on an error ({s})\n", .{@errorName(err)});
        };
        // ENROLLED. Become that person: persist the session (so the next launch
        // goes straight to the feed) and run the app as them, on the same window.
        if (enrolled) |new_session| {
            var session = new_session;
            defer auth.freeSession(gpa, session);
            var sp_buf: [512]u8 = undefined;
            if (cache_shell.sessionPath(&sp_buf, env)) |sp| _ = cache_shell.saveSessionAt(gpa, sp, &session);
            std.debug.print("[front-door] enrolled as {s} — starting the app.\n", .{session.handle});
            _ = shell_tui.run(gpa, io, env, &session, eps.appview_url, &store, .{ .window = win }, null) catch |err| {
                std.debug.print("Zat4: the session ended on an error ({s})\n", .{@errorName(err)});
            };
        }
        return;
    }

    if (window_mode and appPassword(env) == null and !hasCachedSession(gpa, env)) {
        // Returning OAuth user (6.3): a persisted DPoP session means we skip the
        // Join flow and drop straight into the feed, exactly as a cached app-
        // password session does in the normal path below. Rotated tokens are
        // saved back on exit (E4). The app-password cache was already ruled out
        // by `hasCachedSession` above, so these two never collide.
        var oa_buf: [512]u8 = undefined;
        if (cache_shell.oauthSessionPath(&oa_buf, env)) |oa_sp| {
            if (cache_shell.loadOAuthSessionAt(gpa, oa_sp)) |loaded| {
                var session = loaded;
                var signed_out = false;
                defer auth.freeSession(gpa, session);
                // On a normal exit, persist rotated tokens (E4); on sign-out, wipe
                // the cached session so the next launch shows the Join/login flow.
                defer if (signed_out) cache_shell.clearSession(env) else {
                    _ = cache_shell.saveOAuthSessionAt(gpa, oa_sp, &session);
                };
                var store = cache_shell.loadStore(gpa, env) orelse feed_core.Store{};
                defer feed_core.deinitStore(gpa, &store);
                defer _ = cache_shell.saveStore(gpa, env, &store);
                const eps = config.fromEnv(env);
                const win = window_shell.open(gpa, env, win_title, 110, 32) catch |err| {
                    // A double-clicked exe has no visible terminal; still say
                    // WHY we exited for anyone running from one (E3).
                    std.debug.print("Zat4: could not open a native window ({s})\n", .{@errorName(err)});
                    return;
                };
                defer window_shell.close(win);
                signed_out = shell_tui.run(gpa, io, env, &session, eps.appview_url, &store, .{ .window = win }, null) catch |err| blk: {
                    std.debug.print("Zat4: the session ended on an error ({s})\n", .{@errorName(err)});
                    break :blk false;
                };
                return;
            }
        }

        // THE FRONT DOOR IS THE SHELL NOW (FRONT_DOOR_ROADMAP phase 4). `enroll_run`
        // opened its own X11 window, brought up its own GPU context and ran its own
        // input loop — which is exactly why a phone could never reach it. The flow
        // it drove is unchanged (same State, same steps, same card); only the loop
        // driving it is, and that loop is one both platforms have.
        if (try frontDoor(gpa, io, env)) |new_session| {
            var session = new_session;
            var signed_out = false;
            defer auth.freeSession(gpa, session);
            var sp_buf: [512]u8 = undefined;
            if (cache_shell.sessionPath(&sp_buf, env)) |sp| _ = cache_shell.saveSessionAt(gpa, sp, &session);
            // Sign-out from a freshly-enrolled session wipes the cache just saved.
            defer if (signed_out) cache_shell.clearSession(env);
            var store = cache_shell.loadStore(gpa, env) orelse feed_core.Store{};
            defer feed_core.deinitStore(gpa, &store);
            defer _ = cache_shell.saveStore(gpa, env, &store);
            const eps = config.fromEnv(env);
            const win = window_shell.open(gpa, env, win_title, 110, 32) catch |err| {
                    // A double-clicked exe has no visible terminal; still say
                    // WHY we exited for anyone running from one (E3).
                    std.debug.print("Zat4: could not open a native window ({s})\n", .{@errorName(err)});
                    return;
                };
            defer window_shell.close(win);
            signed_out = shell_tui.run(gpa, io, env, &session, eps.appview_url, &store, .{ .window = win }, null) catch |err| blk: {
                    std.debug.print("Zat4: the session ended on an error ({s})\n", .{@errorName(err)});
                    break :blk false;
                };
        }
        return;
    }

    var stdout_buffer: [1024]u8 = undefined;
    var stdout_writer: std.Io.File.Writer = .init(.stdout(), io, &stdout_buffer);
    const out = &stdout_writer.interface;

    // Headless sign-up: mint a new account and print its credentials, then exit.
    // The same `auth.createAccount` the Join flow uses, driven from the terminal.
    if (create_account_user) |uname| {
        var cred = credential_shell.generate(io, .super_secure) catch |err| {
            try out.print("--create-account: could not generate a password: {s}\n", .{@errorName(err)});
            try out.flush();
            return err;
        };
        defer credential_shell.wipe(&cred);
        const password = cred.bytes[0..cred.len];
        var hbuf: [128]u8 = undefined;
        const new_handle = try std.fmt.bufPrint(&hbuf, "{s}.zat4.com", .{uname});
        const invite = invite_arg orelse env.get("ZAT_INVITE_CODE");
        const pds = config.fromEnv(env).pds_url;
        const outcome = try auth.createAccount(gpa, arena, io, env, pds, .{
            .handle = new_handle,
            .password = password,
            .email = email_arg,
            .inviteCode = invite,
        });
        switch (outcome) {
            .ok => |session| {
                defer auth.freeSession(gpa, session);
                try out.print(
                    \\created account on {s}
                    \\  handle:   {s}
                    \\  did:      {s}
                    \\  password: {s}   (save it, this is the login)
                    \\
                , .{ pds, session.handle, session.did, password });
            },
            .refused => |f| try out.print("createAccount refused: status {d} {s}: {s}\n", .{ f.status, f.code, f.message }),
        }
        try out.flush();
        return;
    }

    // Headless OAuth login: resolve the handle to its PDS, run the full browser
    // flow, and print the DPoP-bound result. Only a prefix of the access token is
    // shown — it's a bearer secret.
    if (oauth_login_handle) |oh| {
        const oid = identity.resolve(arena, io, env, .{}, oh) catch |err| {
            try out.print("--oauth-login: could not resolve {s}: {s}\n", .{ oh, @errorName(err) });
            try out.flush();
            return err;
        };
        try out.print("[oauth] {s} -> {s}\n[oauth] opening browser to sign in...\n", .{ oid.handle, oid.pds_url });
        try out.flush();
        var sess = oauth_shell.login(gpa, io, env, arena, oid.pds_url, oid.handle, null) catch |err| {
            try out.print("--oauth-login failed: {s}\n", .{@errorName(err)});
            try out.flush();
            return err;
        };
        defer auth.freeSession(gpa, sess);
        const at = sess.access_jwt;
        try out.print(
            \\OAuth login complete — tokens are DPoP-bound.
            \\  did:        {s}
            \\  scope:      {s}
            \\  issuer:     {s}
            \\  access:     {s}... ({d} bytes)
            \\  refresh:    present ({d} bytes)
            \\
        , .{ sess.did, sess.scope, sess.issuer, at[0..@min(12, at.len)], at.len, sess.refresh_jwt.len });
        try out.flush();
        // Slice 6: the SAME auth.query the app uses — DPoP dispatched internally.
        const outcome = auth.query(gpa, arena, io, env, &sess, lexicon.method.get_session, &.{}, lexicon.GetSessionResponse) catch |err| {
            try out.print("[oauth] auth.query getSession FAILED: {s}\n", .{@errorName(err)});
            try out.flush();
            return err;
        };
        switch (outcome) {
            .ok => |r| try out.print("[oauth] auth.query getSession OK: did={s} handle={s}\n", .{ r.did, r.handle }),
            .failed => |f| try out.print("[oauth] getSession refused: {d} {s}\n", .{ f.status, f.code }),
        }
        // Slice 5: persist the session (key + tokens) so it survives a relaunch.
        var sp_buf: [512]u8 = undefined;
        if (cache_shell.oauthSessionPath(&sp_buf, env)) |sp| {
            if (cache_shell.saveOAuthSessionAt(gpa, sp, &sess))
                try out.print("[oauth] session saved — relaunch with --oauth-resume to reuse it (no re-login)\n", .{});
        }
        try out.flush();
        return;
    }

    // Slice 5 proof: resume the persisted DPoP session and make an authenticated
    // call without any re-login — the key and tokens came off disk.
    // Dev provisioning (M_CORE_INVERSION MC.4d): write the cached OAuth
    // session — keystore-resolved — to a plain file a phone's file-fallback
    // load can read (`adb push` + `run-as cp` into the app's files dir).
    // Fenced from dist builds: a shipped binary carries no secrets-export
    // flag. The file holds LIVE tokens + the DPoP key: push it, delete it.
    if (comptime !dist_config.dist) if (export_session_path) |xp| {
        var sp_buf: [512]u8 = undefined;
        // OAuth first, app-password second — the same precedence the phone's
        // zat_feed_start resumes with. The provisioned file must keep its
        // kind's own name (the two loaders read different blobs).
        var wrote = false;
        if (cache_shell.oauthSessionPath(&sp_buf, env)) |sp| {
            if (cache_shell.loadOAuthSessionAt(gpa, sp)) |sess| {
                defer auth.freeSession(gpa, sess);
                wrote = cache_shell.exportOAuthSessionTo(gpa, xp, &sess);
                if (wrote) try printExportRecipe(out, sess.handle, xp, "oauth_session.zat");
            }
        }
        if (!wrote) if (cache_shell.sessionPath(&sp_buf, env)) |sp| {
            if (cache_shell.loadSessionAt(gpa, sp)) |sess| {
                defer auth.freeSession(gpa, sess);
                wrote = cache_shell.exportSessionTo(gpa, xp, &sess);
                if (wrote) try printExportRecipe(out, sess.handle, xp, "session.zat");
            }
        };
        if (!wrote) try out.print("--export-session: no saved session on this machine (or the write failed)\n", .{});
        try out.flush();
        return;
    };

    if (oauth_resume) {
        var sp_buf: [512]u8 = undefined;
        const sp = cache_shell.oauthSessionPath(&sp_buf, env) orelse {
            try out.print("--oauth-resume: no cache directory available\n", .{});
            try out.flush();
            return;
        };
        var sess = cache_shell.loadOAuthSessionAt(gpa, sp) orelse {
            try out.print("--oauth-resume: no saved OAuth session (run --oauth-login first)\n", .{});
            try out.flush();
            return;
        };
        defer auth.freeSession(gpa, sess);
        try out.print("[oauth] resumed saved session for {s} — no re-login\n", .{sess.handle});
        try out.flush();
        const outcome = auth.query(gpa, arena, io, env, &sess, lexicon.method.get_session, &.{}, lexicon.GetSessionResponse) catch |err| {
            try out.print("[oauth] resumed getSession FAILED: {s}\n", .{@errorName(err)});
            try out.flush();
            return err;
        };
        switch (outcome) {
            .ok => |r| try out.print("[oauth] auth.query getSession with the PERSISTED key OK: did={s} handle={s}\n", .{ r.did, r.handle }),
            .failed => |f| try out.print("[oauth] resumed getSession refused: {d} {s}\n", .{ f.status, f.code }),
        }
        // Re-save: the nonce (and possibly tokens) rotated during the call.
        _ = cache_shell.saveOAuthSessionAt(gpa, sp, &sess);
        try out.flush();
        return;
    }

    // Zat Chat C6 proof: the device-bound anchor key survives relaunches and
    // its DID binding self-verifies. Purely local — no network, no session.
    if (chat_anchor_did) |did| {
        var res = cache_shell.loadOrCreateAnchorSeed(gpa, io, env, did) orelse {
            try out.print("--chat-anchor: could not create or persist an anchor (no keystore, no writable cache dir, or no entropy)\n", .{});
            try out.flush();
            return;
        };
        defer std.crypto.secureZero(u8, &res.seed);
        const anchor_pub = try anchor_core.publicKey(res.seed);
        const sig = try anchor_core.signDidBinding(res.seed, did);
        try anchor_core.verifyDidBinding(anchor_pub, did, &sig);
        const pub_hex = std.fmt.bytesToHex(anchor_pub, .lower);
        try out.print(
            \\[chat] anchor {s} for {s}
            \\[chat]   public key: {s}
            \\[chat]   DID binding signs and verifies (anchor <-> DID)
            \\
        , .{ if (res.created) @as([]const u8, "CREATED") else "LOADED", did, pub_hex });
        try out.flush();
        return;
    }

    // M5 A5 proof: the confirmation-watcher's whole read leg, live — tip
    // height, the address page, the pure conservative match, and the depth
    // the six-block animation would draw. Public data only; no session.
    if (watch_addr) |wa| {
        const sats = std.fmt.parseInt(u64, watch_sats.?, 10) catch {
            try out.print("--watch-address: sats must be a positive integer\n", .{});
            try out.flush();
            return;
        };
        const src = chainwatch_shell.source(env);
        try out.print("[watch] chain source: {s} ({s})\n", .{ src.base, if (src.guard == .trusted) @as([]const u8, "your endpoint") else "public, guarded" });
        try out.flush();
        const tip = chainwatch_shell.tipHeight(arena, io, env, src) catch |err| {
            try out.print("[watch] tip fetch failed: {s}\n", .{@errorName(err)});
            try out.flush();
            return;
        };
        const ob = chainwatch_shell.observe(arena, io, env, src, wa, sats) catch |err| {
            try out.print("[watch] address fetch failed: {s}\n", .{@errorName(err)});
            try out.flush();
            return;
        };
        const depth = chainwatch_core.depthOf(ob, tip);
        if (depth) |d| {
            if (d == 0) {
                try out.print("[watch] tip {d}: seen in the MEMPOOL (0 confirmations) — the card would read broadcast\n", .{tip});
            } else {
                try out.print("[watch] tip {d}: {d} confirmation(s) — the card would read {s}\n", .{ tip, d, if (d >= 6) @as([]const u8, "settled") else "confirming" });
            }
        } else {
            try out.print("[watch] tip {d}: no transaction paying exactly {d} sats to that address in the newest page\n", .{ tip, sats });
        }
        try out.flush();
        return;
    }

    // M5 A3 proof: the wallet hand-off, end to end minus the wallet itself.
    // Build the standard URI (validated address, exact BIP-21 amount, encoded
    // note) and give it to the OS. Purely local — no network, no session.
    if (pay_handoff_addr) |addr| {
        const sats = std.fmt.parseInt(u64, pay_handoff_sats.?, 10) catch {
            try out.print("--pay-handoff: sats must be a positive integer\n", .{});
            try out.flush();
            return;
        };
        if (sats == 0 or sats > chat_core.max_amount_sat) {
            try out.print("--pay-handoff: sats out of range\n", .{});
            try out.flush();
            return;
        }
        const note = if (std.mem.eql(u8, pay_handoff_note.?, "-")) "" else pay_handoff_note.?;
        var uri_buf: [payuri.max_uri_len]u8 = undefined;
        const is_ln = std.mem.indexOfScalar(u8, addr, '@') != null;
        const uri = (if (is_ln)
            payuri.buildLightningUri(&uri_buf, addr)
        else
            payuri.buildBitcoinUri(&uri_buf, addr, sats, "", note)) catch |err| {
            try out.print("--pay-handoff: {s}\n", .{@errorName(err)});
            try out.flush();
            return;
        };
        try out.print(
            \\[pay] {s} hand-off URI (amount {s}):
            \\[pay]   {s}
            \\
        , .{
            if (is_ln) @as([]const u8, "lightning") else "on-chain",
            if (is_ln) @as([]const u8, "chosen in the wallet — LUD-16") else pay_handoff_sats.?,
            uri,
        });
        try out.flush();
        launch.openUri(io, uri) catch |err| {
            try out.print("[pay] no handler opened ({s}) — use the URI above directly\n", .{@errorName(err)});
            try out.flush();
            return;
        };
        try out.print("[pay] handed to the OS default handler\n", .{});
        try out.flush();
        return;
    }

    // The capability probe, against a live provider: ask a wallet what it can do
    // and print the table the user will be shown. `--wallet-probe <address>`.
    if (probe_addr) |addr| {
        const caps = lnurl.probe(arena, io, init.environ_map, addr) catch |err| {
            try out.print("[wallet] {s} \u{2014} CANNOT be used: {s}\n", .{ addr, @errorName(err) });
            try out.flush();
            return;
        };
        var nbuf: [64]u8 = undefined;
        const name = wallet_caps.providerName(&nbuf, addr);
        try out.print(
            \\[wallet] {s} ({s})
            \\[wallet]   receive in chat      : {s}
            \\[wallet]   confirms automatically: {s}
            \\[wallet]   notes reach the wallet: {s} ({d} chars)
            \\[wallet]   amount range          : {d} - {d} sats
            \\
        , .{
            name,
            addr,
            if (caps.receivable) "yes" else "no",
            if (caps.auto_confirm) "yes (LUD-21)" else "NO - you'll mark payments received yourself",
            if (caps.comment_max > 0) "yes" else "no",
            caps.comment_max,
            caps.min_sat,
            caps.max_sat,
        });
        try out.flush();
        return;
    }

    // LNURL-pay exactness proof: the real LUD-06/16 leg against a live provider.
    if (invoice_addr) |addr| {
        const sats = std.fmt.parseInt(u64, invoice_sats.?, 10) catch {
            try out.print("--pay-invoice: sats must be a positive integer\n", .{});
            try out.flush();
            return;
        };
        if (sats == 0 or sats > chat_core.max_amount_sat) {
            try out.print("--pay-invoice: sats out of range\n", .{});
            try out.flush();
            return;
        }
        const resolved = lnurl.resolveInvoice(arena, io, init.environ_map, addr, sats) catch |err| {
            try out.print("[pay] LNURL resolve failed: {s}\n", .{@errorName(err)});
            try out.flush();
            return;
        };
        var uri_buf: [payuri.max_uri_len]u8 = undefined;
        const uri = payuri.buildLightningInvoiceUri(&uri_buf, resolved.bolt11) catch |err| {
            try out.print("[pay] invoice rejected by the URI gate: {s}\n", .{@errorName(err)});
            try out.flush();
            return;
        };
        try out.print(
            \\[pay] LNURL-pay invoice for {d} sats from {s}:
            \\[pay]   {s}
            \\
        , .{ sats, addr, uri });
        try out.flush();
        return;
    }

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
    if (post_text != null or follow_target != null or publish_algo_name != null or publish_discover or chat_publish or chat_reclaim or pay_publish) {
        var from_cache = false;
        var session: auth.Session = undefined;
        if (appPassword(env)) |password| {
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
                try out.print("--post/--follow/--publish-algo needs credentials: set ZAT_APP_PASSWORD (or run the app once to cache a login)\n", .{});
                try out.flush();
                return error.LoginFailed;
            };
            from_cache = true;
        } else {
            try out.print("--post/--follow/--publish-algo needs credentials: set ZAT_APP_PASSWORD\n", .{});
            try out.flush();
            return error.LoginFailed;
        }
        defer if (from_cache) cache_shell.freeSession(gpa, &session) else auth.freeSession(gpa, session);
        if (session_path) |sp| _ = cache_shell.saveSessionAt(gpa, sp, &session); // persist rotated tokens (E4)

        const now = clock_shell.unixSeconds();

        // The chat key-directory leg (U6): publish this account's last-resort
        // keyPackage, then fetch it back the way a COUNTERPARTY would (public
        // getRecord on the DID's own PDS) and validate the whole chain.
        if (chat_publish) {
            // replace_foreign = false (A3): even a dev tool does not get to
            // silently overwrite an account's chat identity. If the keys live on
            // another device this refuses and says so, which is the whole point.
            const pub_result = chat_keys.ensurePublished(gpa, arena, io, env, &session, false) catch |err| {
                if (err == error.IdentityElsewhere) {
                    try out.print("--chat-publish refused: this account's chat keys are published from ANOTHER device.\n" ++
                        "  Publishing here would replace them and orphan every conversation the account has.\n" ++
                        "  Do it from the app (Messages → \"Set up chat fresh on this device\") if that is really what you want.\n", .{});
                    try out.flush();
                    return err;
                }
                try out.print("--chat-publish failed: {s}\n", .{@errorName(err)});
                try out.flush();
                return err;
            };
            try out.print(
                \\[chat] keyPackage record {s}
                \\[chat]   uri: {s}
                \\[chat]   cid: {s}
                \\
            , .{ if (pub_result.minted) @as([]const u8, "PUBLISHED (fresh package minted)") else "REPUBLISHED (stored package)", pub_result.uri, pub_result.cid });
            try out.flush();
            const fetched = chat_keys.fetchPeer(gpa, arena, io, env, session.did) catch |err| {
                try out.print("[chat] fetch-back FAILED: {s}\n", .{@errorName(err)});
                try out.flush();
                return err;
            };
            if (fetched) |peer| {
                const pub_hex = std.fmt.bytesToHex(peer.anchor_pub, .lower);
                try out.print(
                    \\[chat] fetch-back VALID — the directory chain holds:
                    \\[chat]   anchor key: {s}
                    \\[chat]   keyPackage: {d} bytes, suite + signatures + DID binding verified
                    \\
                , .{ pub_hex, peer.kp_bytes.len });
            } else {
                try out.print("[chat] fetch-back found NO record — publish did not land\n", .{});
            }
            try out.flush();
        }

        // THE REPAIR (2026-07-14). Take chat back for THIS device: drop every other
        // device's record, then re-assert the account's singleton from the key this
        // device already holds. Nothing is minted, so peers see the key they have
        // always seen; a device removed here can simply ask again and be approved.
        if (chat_reclaim) {
            const rep = chat_keys.reclaim(gpa, arena, io, env, &session, "Desktop") catch |err| {
                try out.print("--chat-reclaim FAILED: {s}\n" ++
                    "  Nothing was changed that this message does not name.\n", .{@errorName(err)});
                try out.flush();
                return err;
            };
            try out.print(
                \\[chat] reclaimed — this device is the account's chat device again
                \\[chat]   other device records removed: {d}
                \\[chat]   this device now stands: {s}
                \\
            , .{ rep.devices_removed, @tagName(rep.status) });
            if (rep.status != .root) {
                // Say it plainly rather than reassure: the repair did not take, and
                // the operator needs to know that BEFORE they trust the account.
                try out.print("[chat] WARNING: expected 'root'. The directory did not end up where it should — do not assume chat is repaired.\n", .{});
            }
            try out.flush();
        }

        // The payment-address leg (M5 A2): publish this account's anchor-signed
        // payment addresses, then fetch them back the way a PAYER would (public
        // getRecord on the DID's own PDS + the core gate against the anchor key
        // — here our own, standing in for the one a payer's conversation pins).
        if (pay_publish) {
            const ln = if (std.mem.eql(u8, pay_publish_ln.?, "-")) "" else pay_publish_ln.?;
            const btc = if (std.mem.eql(u8, pay_publish_btc.?, "-")) "" else pay_publish_btc.?;
            const pub_result = pay_addr.publish(gpa, arena, io, env, &session, ln, btc) catch |err| {
                try out.print("--pay-publish failed: {s}\n", .{@errorName(err)});
                try out.flush();
                return err;
            };
            try out.print(
                \\[pay] address record PUBLISHED
                \\[pay]   uri: {s}
                \\[pay]   cid: {s}
                \\
            , .{ pub_result.uri, pub_result.cid });
            try out.flush();

            var own = cache_shell.loadOrCreateAnchorSeed(gpa, io, env, session.did) orelse {
                try out.print("[pay] fetch-back skipped: no anchor available\n", .{});
                try out.flush();
                return error.NoAnchor;
            };
            defer std.crypto.secureZero(u8, &own.seed);
            const own_pub = try anchor_core.publicKey(own.seed);
            const fetched = pay_addr.fetchPayee(gpa, arena, io, env, session.did, own_pub) catch |err| {
                try out.print("[pay] fetch-back FAILED: {s}\n", .{@errorName(err)});
                try out.flush();
                return err;
            };
            if (fetched) |payee| {
                try out.print(
                    \\[pay] fetch-back VALID — the address chain holds:
                    \\[pay]   lightning: {s}
                    \\[pay]   bitcoin:   {s}
                    \\
                , .{
                    if (payee.lightning.len > 0) payee.lightning else "(not offered)",
                    if (payee.bitcoin.len > 0) payee.bitcoin else "(not offered)",
                });
            } else {
                try out.print("[pay] fetch-back found NO record — publish did not land\n", .{});
            }
            try out.flush();
        }

        // The post leg: publish one app.zat4.feed.post into the user's own PDS,
        // from where the AppView's poll/firehose carries it into Zat4.
        if (post_text) |text| {
            const outcome = write.createPost(gpa, arena, io, env, &session, text, &[_]lexicon.Facet{}, null, null, &.{}, now) catch |err| {
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

        // The publish-algorithm leg: write one app.zat4.feed.algorithm record (the
        // friendly builder's calibrated default — an adaptive, on-device-learning
        // config) into the user's repo, keyed by a fixed dev rkey so re-running
        // republishes the same slot. From there the AppView's poll indexes it and
        // `getAlgorithms` lists it — the marketplace's content, before the UI.
        // Both publish legs run the Phase-5 gate first and print its named
        // refusals — the shell refuses fail-closed either way.
        if (publish_algo_name) |name| {
            const config_out = builder.build(.{});
            try printGateRefusals(out, config_out); // named reasons before the shell's fail-closed refusal
            const published = algorithm_shell.publish(gpa, arena, io, env, &session, name, config_out, "dev-algo", now, .{}) catch |err| {
                try out.print("publish-algo failed: {s}\n", .{@errorName(err)});
                try out.flush();
                return err;
            };
            try out.print("published app.zat4.feed.algorithm \"{s}\"\n  uri: {s}\n  cid: {s}\n", .{ name, published.uri, published.cid });
            try out.flush();
        }

        // The full-stack showcase: publish the house Zat4 Discover (L1 weights +
        // L2 rules + L3 formula) so the marketplace + transparency page have a
        // genuinely complex, behavioral algorithm to render.
        if (publish_discover) {
            const cfg = lens_catalog.scoringConfigForId("zat4:discover") orelse builder.build(.{});
            try printGateRefusals(out, cfg);
            const published = algorithm_shell.publish(gpa, arena, io, env, &session, "Zat4 Discover", cfg, "zat4-discover", now, .{}) catch |err| {
                try out.print("publish-discover failed: {s}\n", .{@errorName(err)});
                try out.flush();
                return err;
            };
            try out.print("published app.zat4.feed.algorithm \"Zat4 Discover\"\n  uri: {s}\n  cid: {s}\n", .{ published.uri, published.cid });
            try out.flush();
        }
        return;
    }

    // The cached session is only the NO-PASSWORD fallback. When ZAT_APP_PASSWORD
    // is given it must WIN — otherwise a stale cached session (expired/revoked
    // tokens) is used forever and every write fails `ExpiredToken`, even though
    // the user supplied fresh credentials. So skip the cache path when a
    // password is present and fall through to the fresh login below.
    if (tui_mode and appPassword(env) == null) {
        if (session_path) |sp| {
            if (cache_shell.loadSessionAt(gpa, sp)) |cached| {
                var session = cached;
                var signed_out = false;
                defer cache_shell.freeSession(gpa, &session);
                // Normal exit re-saves (rotated tokens, E4); sign-out wipes the cache.
                defer if (signed_out) cache_shell.clearSession(env) else {
                    _ = cache_shell.saveSessionAt(gpa, sp, &session);
                };
                var store = cache_shell.loadStore(gpa, env) orelse feed_core.Store{};
                defer feed_core.deinitStore(gpa, &store);
                defer _ = cache_shell.saveStore(gpa, env, &store); // E4
                const opened = try openBackend(gpa, env, out, window_mode);
                defer if (opened.win) |w| window_shell.close(w);
                signed_out = shell_tui.run(gpa, io, env, &session, endpoints.appview_url, &store, opened.backend, null) catch |err| switch (err) {
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

    if (appPassword(env)) |password| {
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
                    var signed_out = false;
                    var store = cache_shell.loadStore(gpa, env) orelse feed_core.Store{};
                    defer feed_core.deinitStore(gpa, &store);
                    defer _ = cache_shell.saveStore(gpa, env, &store); // E4
                    defer if (session_path) |sp| {
                        if (signed_out) cache_shell.clearSession(env) else _ = cache_shell.saveSessionAt(gpa, sp, &session); // rotated tokens
                    };
                    const opened = try openBackend(gpa, env, out, window_mode);
                    defer if (opened.win) |w| window_shell.close(w);
                    signed_out = shell_tui.run(gpa, io, env, &session, endpoints.appview_url, &store, opened.backend, null) catch |err| switch (err) {
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
    _ = @import("ui/reveal.zig"); // Rover: portable UI primitives (src/ui/README.md)
    _ = @import("ui/tokens.zig");
    _ = @import("ui/layout.zig");
    _ = @import("ui/insets.zig");
    _ = @import("ui/ease.zig");
    _ = @import("ui/scroll.zig");
    _ = @import("ui/anchor.zig");
    _ = @import("ui/timing.zig");
    _ = @import("ui/feedback.zig");
    // Pull every source file into the test build so its tests run and its
    // comptime guards (A7) are semantically analyzed on every `zig build test`.
    _ = @import("core/identity.zig");
    _ = @import("core/sigverify.zig");
    _ = @import("core/commit.zig");
    _ = @import("core/jws.zig");
    _ = @import("core/pkce.zig");
    _ = @import("core/dpop.zig");
    _ = @import("core/hpke.zig");
    _ = @import("core/xwing.zig");
    _ = @import("core/mls_wire.zig");
    _ = @import("core/mls_schedule.zig");
    _ = @import("core/mls.zig");
    _ = @import("core/kbd_lm.zig");
    _ = @import("core/anchor.zig");
    _ = @import("core/keydir.zig");
    _ = @import("shell/chat_relay.zig");
    _ = @import("shell/chat_keys.zig");
    _ = @import("shell/pay_addr.zig");
    _ = @import("core/wallet_caps.zig");
    _ = @import("shell/chat_e2ee.zig");
    _ = @import("core/oauth.zig");
    _ = @import("core/oauth_flow.zig");
    _ = @import("core/dagcbor.zig");
    _ = @import("core/cid.zig");
    _ = @import("core/dagjson.zig");
    _ = @import("core/record_check.zig");
    _ = @import("core/netguard.zig");
    _ = @import("core/jsonguard.zig");
    _ = @import("core/lexicon.zig");
    _ = @import("core/xrpc.zig");
    _ = @import("shell/http.zig");
    _ = @import("shell/identity.zig");
    _ = @import("shell/oauth.zig");
    _ = @import("shell/xrpc.zig");
    _ = @import("shell/auth.zig");
    _ = @import("shell/keystore.zig");
    _ = @import("core/feed.zig");
    _ = @import("core/chat.zig");
    _ = @import("core/chat_view.zig");
    _ = @import("core/payaddr.zig");
    _ = @import("core/payuri.zig");
    _ = @import("shell/launch.zig");
    _ = @import("core/chainwatch.zig");
    _ = @import("shell/chainwatch.zig");
    _ = @import("core/discover.zig");
    _ = @import("core/algorithm.zig");
    _ = @import("core/learner.zig");
    _ = @import("core/transparency.zig");
    _ = @import("core/builder.zig");
    _ = @import("core/rules.zig");
    _ = @import("core/algo_vm.zig");
    _ = @import("core/retrieval.zig");
    _ = @import("core/guest_abi.zig");
    _ = @import("core/guest_vm.zig");
    _ = @import("core/zal_lex.zig");
    _ = @import("core/zal_parse.zig");
    _ = @import("core/zal_compile.zig");
    _ = @import("core/zal_templates.zig");
    _ = @import("core/algo_gate.zig");
    _ = @import("shell/algorithm.zig");
    _ = @import("core/feed_view.zig");
    _ = @import("core/zone_pins.zig");
    _ = @import("core/settings_view.zig");
    _ = @import("core/prefs.zig");
    _ = @import("core/lens_socket.zig");
    _ = @import("core/lens_catalog.zig");
    _ = @import("core/algo_library.zig");
    _ = @import("core/create_flow.zig");
    _ = @import("core/dev_flow.zig");
    _ = @import("core/algo_docs.zig");
    _ = @import("shell/loadout.zig");
    _ = @import("core/appview.zig");
    _ = @import("core/moderation.zig");
    _ = @import("core/tui.zig");
    _ = @import("core/timeline_ui.zig");
    _ = @import("core/timefmt.zig");
    _ = @import("core/field.zig");
    _ = @import("core/effect.zig");
    _ = @import("core/chat_effects.zig");
    _ = @import("core/screen_fx.zig");
    _ = @import("core/chat_games.zig");
    _ = @import("core/field_ui.zig");
    _ = @import("core/compose.zig");
    _ = @import("core/websocket.zig");
    _ = @import("core/jetstream.zig");
    _ = @import("core/snapshot.zig");
    _ = @import("core/layout.zig");
    _ = @import("core/raster.zig");
    _ = @import("core/text.zig");
    _ = @import("core/text_select.zig");
    _ = @import("core/xcursor.zig");
    _ = @import("core/atlas.zig");
    _ = @import("core/glyph_field.zig");
    _ = @import("core/spring.zig");
    _ = @import("core/gravity.zig");
    _ = @import("core/shatter.zig");
    _ = @import("core/pet.zig");
    _ = @import("core/gesture.zig");
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
    _ = @import("shell/refresh_worker.zig");
    _ = @import("shell/view_worker.zig");
    _ = @import("shell/mobile_host.zig");
    _ = @import("core/pow.zig");
    _ = @import("shell/pow.zig");
    _ = @import("core/constellation.zig");
    _ = @import("core/pow_issue.zig");
    _ = @import("core/gate_wire.zig");
    _ = @import("core/gate_record.zig");
    _ = @import("shell/gate_store.zig");
    _ = @import("shell/gate_pool.zig");
    _ = @import("shell/gate_client.zig");
    _ = @import("shell/gate_serve.zig");
    _ = @import("core/credential.zig");
    _ = @import("shell/credential.zig");
    _ = @import("core/membership.zig");
    _ = @import("shell/membership.zig");
    _ = @import("shell/membership_record.zig");
    _ = @import("core/enroll_view.zig");
    _ = @import("core/boot_intro.zig");
    _ = @import("shell/enroll_run.zig");
    _ = @import("shell/feed.zig");
    _ = @import("shell/tui.zig");
}
