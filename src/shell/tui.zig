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

//! B1 classification: SHELL. The **renderer deep module**, file 3 of 3:
//! the terminal session — the ONLY file in the program where a tty, raw
//! mode, the wall clock, and stdin/stdout bytes exist (B3).
//!
//! The loop is the imperative-shell sandwich, once per frame:
//!   shell: read terminal size, read the clock, read input bytes
//!   core:  buildTimeline (feed) -> buildFrame (screen) -> encodeDiff (ANSI)
//!   shell: write the bytes
//! Per-frame work lives in one arena reset every iteration — C3's
//! "per-frame arena" taken literally.
//!
//! POSIX-only by recorded decision: terminal control IS a platform API,
//! and this is the renderer's shell — a Windows console or GPU renderer is
//! a future sibling behind the same view-model boundary (D1 contains the
//! swap to this module). There is no automated test in this file: it is
//! ~150 lines of choreography over a tty the test runner does not have;
//! every decision it choreographs is tested in the two core files. The
//! terminal is ALWAYS restored — raw mode and the alternate screen are
//! released by defers that run on success, error, and quit alike (C5).

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const Allocator = std.mem.Allocator;
const tui = @import("../core/tui.zig");
const timeline_ui = @import("../core/timeline_ui.zig");
const feed_core = @import("../core/feed.zig");
const chat_core = @import("../core/chat.zig");
const chat_view_core = @import("../core/chat_view.zig");
const chat_relay = @import("chat_relay.zig");
const chat_e2ee = @import("chat_e2ee.zig");
const feed_shell = @import("feed.zig");
const stream_shell = @import("stream.zig");
const cache_shell = @import("cache.zig");
const xrpc = @import("xrpc.zig");
const window_shell = @import("native.zig");
const gpu = @import("gpu.zig");
const glyph_field = @import("../core/glyph_field.zig");
const layout_core = @import("../core/layout.zig");
const raster_core = @import("../core/raster.zig");
const text_core = @import("../core/text.zig");
const field_core = @import("../core/field.zig");
const field_ui = @import("../core/field_ui.zig");
const feed_view = @import("../core/feed_view.zig");
const settings_view = @import("../core/settings_view.zig");
const text_select = @import("../core/text_select.zig");
const textedit = @import("../core/textedit.zig");
const lens_socket = @import("../core/lens_socket.zig");
const lens_catalog = @import("../core/lens_catalog.zig");
const discover = @import("../core/discover.zig");
const create_flow = @import("../core/create_flow.zig");
const builder = @import("../core/builder.zig");
const algo_library = @import("../core/algo_library.zig");
const transparency = @import("../core/transparency.zig");
const algorithm_core = @import("../core/algorithm.zig");
const algorithm_shell = @import("algorithm.zig");
const loadout_store = @import("loadout.zig");
const effect_core = @import("../core/effect.zig");
const clock_shell = @import("clock.zig");
const write = @import("write.zig");
const write_worker = @import("write_worker.zig");
const auth = @import("auth.zig");
const lexicon = @import("../core/lexicon.zig");
const moderation = @import("../core/moderation.zig");

/// DIAGNOSTIC flag (temporary): when true, `fireEngageEffect` prints one
/// stderr line per effect actually fired, so the fire count of a single click
/// can be read on the real machine (there is no live GUI to watch in the
/// build/test environment). Compile-time, so it is free when false and breaks
/// no rule — it is not a mutable global and not a getenv (which 0.16 lacks).
/// Set to false to silence once the question of "how many effects fire?" is
/// settled.
const debug_effects = true;
// G1/G2: flip to true to print per-phase wall-clock every frame — build
// (compose + content layout) vs present (raster.paint + blit) — so the
// burst cost is MEASURED on the real machine, not guessed, before any
// optimization. Zero cost when false (the branch folds away).
const debug_frame_timing = false;
/// Zat Chat (ZAT_CHAT_ROADMAP): route the Messages rail slot to the chat
/// surface. FEATURE GATE — the transport (relay), E2EE core (MLS), and
/// persistence are all real now (M1); this flag gates a still-maturing
/// feature (no compose-new-conversation UI yet — ZAT4_CHAT_PEER is the
/// entry point — and the iOS-grade motion of U6a is pending). Off ⇒
/// Messages stays the titled placeholder.
const dev_chat = true;

/// Run the timeline screen until the user quits. The store may arrive
/// empty; `r` loads pages. Network calls happen inline between frames —
/// the "loading" frame is painted first, so the wait is visible, not a
/// freeze without explanation. (A streaming/async loop is Phase 7's
/// firehose work.)
/// Open the live stream for the authors the store has met (capped at 64;
/// the follow-graph subscription is the recorded upgrade). Returns null on
/// any non-OOM failure — a stream that won't start is a status line, never
/// a dead screen (E2).
/// The subscription list: the session's OWN did first — your own posts
/// are the one live source you can summon on demand, and they were
/// structurally absent before — then the authors the store has met.
fn composeSubscription(
    arena: Allocator,
    session_did: []const u8,
    store: *feed_core.Store,
    max_authors: usize,
) error{OutOfMemory}![]const []const u8 {
    const authors = try feed_core.authorDids(arena, store, max_authors);
    var dids = try arena.alloc([]const u8, authors.len + 1);
    dids[0] = session_did;
    var count: usize = 1;
    for (authors) |did| {
        if (std.mem.eql(u8, did, session_did)) continue;
        dids[count] = did;
        count += 1;
    }
    return dids[0..count];
}

fn startLiveStream(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session_did: []const u8,
    store: *feed_core.Store,
    mailbox: *stream_shell.Mailbox,
    arena: Allocator,
) error{OutOfMemory}!?*stream_shell.Stream {
    const dids = try composeSubscription(arena, session_did, store, 255);
    const default_host = "jetstream2.us-east.bsky.network";
    const host = if (environ) |env|
        env.get("ZAT_JETSTREAM") orelse default_host
    else
        default_host;
    // Transcript DEFAULT ON (diagnostic phase, recorded): zat-stream.log
    // in the working directory; ZAT_STREAM_LOG overrides; "off" disables.
    const requested = if (environ) |env| env.get("ZAT_STREAM_LOG") else null;
    const chosen = requested orelse "zat-stream.log";
    const log_path: ?[]const u8 = if (std.mem.eql(u8, chosen, "off")) null else chosen;
    return stream_shell.start(gpa, io, mailbox, host, 443, true, dids, log_path) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => null,
    };
}

/// The rendering-backend decision (D1), sealed to a two-way switch: the
/// SAME loop, screens, and input decoder serve a tty or an X11 window.
/// The window pretends to be a terminal (cells out, key bytes in); the
/// loop never learns the difference.
/// A7.2: cold union, size guard waived — exactly one per app run.
pub const Backend = union(enum) {
    terminal,
    window: *window_shell.Window,
};

pub fn run(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    appview_url: []const u8,
    store: *feed_core.Store,
    backend: Backend,
) !bool {
    // Returns whether the user SIGNED OUT (vs a normal window close / quit): the
    // caller then clears the cached session instead of re-saving it on exit.
    var user_signed_out = false;
    const stdin_file: std.Io.File = .stdin();
    const stdout_file: std.Io.File = .stdout();
    if (backend == .terminal) {
        if (!(try stdin_file.isTty(io)) or !(try stdout_file.isTty(io))) {
            return error.NotATerminal;
        }
    }
    const stdin_fd = stdin_file.handle;

    // Raw mode (terminal backend only): no line buffering, no echo, no
    // signal keys (ctrl-c arrives as a byte and quits through the same
    // action path as q). The window backend has no tty to configure.
    // Windows v1 is window-only: the console needs SetConsoleMode, a
    // recorded follow-up — until then --tui there says so plainly.
    const has_termios = builtin.os.tag != .windows;
    var original_termios: ?(if (has_termios) posix.termios else void) = null;
    if (!has_termios and backend == .terminal) return error.NotATerminal;
    if (comptime has_termios) if (backend == .terminal) {
        const original = try posix.tcgetattr(stdin_fd);
        original_termios = original;
        var raw = original;
        raw.lflag.ICANON = false;
        raw.lflag.ECHO = false;
        raw.lflag.ISIG = false;
        raw.lflag.IEXTEN = false;
        raw.iflag.IXON = false;
        raw.iflag.ICRNL = false;
        raw.iflag.BRKINT = false;
        raw.iflag.ISTRIP = false;
        raw.iflag.INPCK = false;
        raw.oflag.OPOST = false;
        raw.cc[@intFromEnum(posix.V.MIN)] = 1;
        raw.cc[@intFromEnum(posix.V.TIME)] = 0;
        try posix.tcsetattr(stdin_fd, .FLUSH, raw);
    };
    defer if (original_termios) |original| {
        if (comptime has_termios) posix.tcsetattr(stdin_fd, .FLUSH, original) catch {}; // C5: always restored
    };

    var out_buffer: [32 * 1024]u8 = undefined;
    var out_writer: std.Io.File.Writer = .init(stdout_file, io, &out_buffer);
    const out = &out_writer.interface;

    // Alternate screen + hidden cursor; both released on every exit path.
    // (Terminal only — the window has no ANSI to speak.)
    if (backend == .terminal) {
        try out.writeAll("\x1b[?1049h\x1b[?25l");
        try out.flush();
    }
    defer if (backend == .terminal) {
        out.writeAll("\x1b[0m\x1b[?25h\x1b[?1049l") catch {};
        out.flush() catch {};
    };

    var prev: tui.Surface = .{};
    defer tui.deinitSurface(gpa, &prev);
    var next: tui.Surface = .{};
    defer tui.deinitSurface(gpa, &next);

    var state: timeline_ui.UiState = .{};
    var status_buf: [96]u8 = undefined;
    var status: []const u8 = "press r to load your timeline";

    var frame_arena = std.heap.ArenaAllocator.init(gpa);
    defer frame_arena.deinit();

    // Composer session: the draft buffer is gpa-owned (it outlives frames);
    // the reply target's strings are copied into their own arena, reset at
    // each composer open (C3: one composition, one unit of work).
    var mode: Mode = .timeline;
    // Composer text: a fixed backing buffer (the draft is capped at 300
    // codepoints — ≤1200 UTF-8 bytes) wrapped in the shared editable-text model,
    // so the composer gets caret-aware editing (click-to-place, ←/→, Home/End,
    // mid-text insert/delete) instead of append-only. Caller-owned: no deinit.
    var compose_store: [1200]u8 = undefined;
    var compose: textedit.Field = .{ .buf = &compose_store };
    // The caret blink anchor: reset on every edit/move so the caret stays solid
    // while the user is active, then blinks when idle (B3: the clock is shell).
    var caret_anchor_ns: u64 = 0;
    // True between a press and release in the composer text area — a drag extends
    // the selection (textedit anchor stays, caret follows the pointer).
    var compose_drag: bool = false;
    // Multi-click tracking (double = word, triple = line): consecutive presses
    // close in time and position step the count.
    var last_click_ns: u64 = 0;
    var last_click_x: i32 = -1000;
    var last_click_y: i32 = -1000;
    var click_count: u8 = 0;
    // Release-activation (the premium standard): a tap is ARMED on press and
    // FIRES on release only if the release lands on the same target (press then
    // slide off = cancel). The press records the target; the release re-hit-tests
    // and fires the feed switch / legacy cell / composer button if it matches.
    // (Caret placement + socket drag stay on press; the lens socket's own taps
    // are unchanged for now — its drag/drop model is separate.)
    var armed_kind: ?feed_view.Action = null;
    var armed_post: u16 = 0;
    var armed_legacy: bool = false;
    var armed_cx: u16 = 0;
    var armed_cy: u16 = 0;
    var armed_compose: ?feed_view.Action = null; // composer Send/Cancel armed on press
    var compose_arena_state = std.heap.ArenaAllocator.init(gpa);
    defer compose_arena_state.deinit();
    var reply_target: ?write.ReplyTarget = null;
    var reply_handle: []const u8 = "";
    // The compose flow is reused for the profile editor: .post writes a feed
    // post on send; .profile upserts the self profile record with the buffer as
    // the display name. Set when the editor / composer is opened.
    var compose_kind: ComposeKind = .post;
    // A post/reply optimistically shown, its create write queued for the loop to
    // run after the post is on screen (0ms posting). At most one in flight.
    var pending_send: ?SendJob = null;
    defer if (pending_send) |job| freeSendJob(gpa, job);
    // A queued profile-edit save (the display name to putProfile after it's
    // shown optimistically). gpa-owned; at most one in flight.
    var pending_profile_save: ?[]const u8 = null;
    defer if (pending_profile_save) |n| gpa.free(n);

    // Reveal toggles: cids the user has opened past a moderation collapse.
    // Plain values handed to the core each frame (B5); freed here (C4/C5).
    var revealed: std.ArrayList([]const u8) = .empty;
    defer {
        for (revealed.items) |cid| gpa.free(cid);
        revealed.deinit(gpa);
    }

    // The profile screen's strings live in their own arena, reset per
    // fetch (C3); the info struct is a view over it.
    var profile_arena_state = std.heap.ArenaAllocator.init(gpa);
    defer profile_arena_state.deinit();
    var profile_info: ?timeline_ui.ProfileInfo = null;

    // Live stream: spawned after the first page teaches us whose posts to
    // want; it speaks only through the mailbox (E1) and is joined before
    // the terminal defers above unwind. A dead stream is a status line,
    // never a dead screen (E2).
    var mailbox: stream_shell.Mailbox = .{};
    defer mailbox.deinit(gpa);
    var live_stream: ?*stream_shell.Stream = null;
    defer if (live_stream) |live| stream_shell.shutdown(live);
    var live_mail: std.ArrayList(stream_shell.Mail) = .empty;
    defer live_mail.deinit(gpa);
    var subscribed_authors: usize = 0;
    var live_start_attempted = false;

    // The WRITE WORKER (mirror of the firehose): like/unlike/repost network
    // calls run on this worker's own thread so the UI loop never blocks on
    // a write. The UI submits a plain-data request and returns immediately;
    // the worker posts a result back, drained each loop iteration below,
    // and only a server REFUSAL reverts the optimistic state. This is what
    // makes animations smooth — the main loop keeps running every frame
    // while the network call is in flight on another thread.
    var write_in: write_worker.RequestBox = .{};
    defer write_in.deinit(gpa);
    var write_out: write_worker.ResultBox = .{};
    defer write_out.deinit(gpa);
    const writer: ?*write_worker.Worker = write_worker.start(gpa, io, environ, session, &write_in, &write_out) catch null;
    defer if (writer) |w| write_worker.shutdown(w);
    var write_results: std.ArrayList(write_worker.Result) = .empty;
    defer write_results.deinit(gpa);
    // Deferred-undo intents: a post the user UN-engaged before its like/repost
    // create had returned a record uri. Keyed by a hash of the post cid; when
    // the create's result lands (with the uri), the drain fires the delete at
    // once — so undo is instant instead of waiting on the create round-trip.
    var deferred_unlike: std.AutoHashMapUnmanaged(u64, void) = .empty;
    defer deferred_unlike.deinit(gpa);
    var deferred_unrepost: std.AutoHashMapUnmanaged(u64, void) = .empty;
    defer deferred_unrepost.deinit(gpa);

    // Auto-refresh: the reliable live path. The Jetstream subsystem stays
    // wired (it proves the firehose engineering), but the VISIBLE feed is
    // kept current by re-running the same getTimeline refresh `r` does, on a
    // wall-clock interval. Polling the timeline endpoint is how most clients
    // actually keep the rendered feed fresh; the firehose shines for
    // notifications/counts, a later slice. Interval is overridable via
    // ZAT_REFRESH_SECS (0 disables auto-refresh, falling back to manual r).
    const refresh_interval: i64 = blk: {
        const secs = if (environ) |env| env.get("ZAT_REFRESH_SECS") else null;
        if (secs) |s| break :blk std.fmt.parseInt(i64, s, 10) catch 5;
        break :blk 5;
    };
    var last_auto_refresh: i64 = 0;

    // The jk-test fix: input must NEVER wait behind a blocking network
    // call. The auto-refresh below is a synchronous getTimeline round trip
    // on this thread; if it fires between keypresses, the keys queue in the
    // socket and the screen freezes, then catches up in a burst — exactly
    // the "tap j/k, lag, then it unsticks" symptom. So the refresh is gated
    // on input being IDLE: while the user is actively navigating, it is
    // suppressed entirely and movement stays instant. Liveness is unharmed
    // — the firehose thread keeps streaming new posts the whole time; the
    // poll is only a fallback and can wait the few hundred ms until the
    // user pauses. (G3/G4: responsiveness is the invariant; the network is
    // exiled off the input path, never allowed to leak inward.)
    const input_idle_gate_nanos: u64 = 600 * std.time.ns_per_ms;
    var last_input_nanos: u64 = 0;

    // ---- the modern window path (GUI roadmap 5.2/5.5/5.6, §7 amendment) --
    // The proportional engine and pixel view state exist only for the
    // window backend. A failed font init degrades to the cell renderer
    // (E2: a plainer window, never a dead one) — paintFrame() checks.
    var engine: ?text_core.Engine = null;
    defer if (engine) |*e| text_core.deinitEngine(gpa, e);
    if (backend == .window) engine = text_core.initEngine() catch null;
    // The glyph-field cutover (GLYPH_FIELD_SYSTEM_DESIGN G.0): the
    // window renders the feed as a live simulated mono grid. All of
    // this exists only when the font engine came up (E2: otherwise the
    // cell fallback still runs — a plainer window, never a dead one).
    var gfield: field_core.Field = .{};
    defer field_core.deinit(gpa, &gfield);
    var gparticles: field_core.ParticleList = .empty;
    defer gparticles.deinit(gpa);
    var gactive: effect_core.ActiveList = .empty;
    defer gactive.deinit(gpa);
    var gdraw: raster_core.DrawList = .empty;
    defer gdraw.deinit(gpa);
    var ghr: field_ui.HitList = .empty;
    defer ghr.deinit(gpa);
    var ghearts: field_ui.HeartList = .empty;
    defer ghearts.deinit(gpa);
    var gview: field_ui.ViewState = .{};
    var gspawn: std.ArrayList(field_core.SpawnEvent) = .empty;
    defer gspawn.deinit(gpa);
    var glast_nanos: u64 = 0;
    var gzoom: f32 = 1.0; // user text-scaling factor (+/- keys)
    // cut 5.6 premium feed: pixel scroll offset (≤0 scrolls the stack up),
    // its clamp bound (total content height), and the per-frame button hit
    // regions the pointer handler tests in pixels.
    var gscroll_px: i32 = 0;
    var gcontent_h: i32 = 0;
    // Pull-to-refresh: an upward wheel while already pinned at the top of Home
    // accumulates "overscroll"; crossing `pull_refresh_threshold` requests a
    // manual refresh (handled at the loop top with the auto-refresh). A
    // downward scroll or a fired refresh resets the accumulator.
    var overscroll_accum: i32 = 0;
    var pull_refresh_requested = false;
    const pull_refresh_threshold: i32 = 112; // ~four wheel notches of pull
    var gregions: feed_view.Regions = .empty;
    defer gregions.deinit(gpa);
    // THE LENS SOCKET loadouts — THREE surfaces (feed / reply / zone),
    // SOCKET_LOADOUT §10. The FEED surface is interactive in the home header;
    // reply/zone are held so a save writes the whole record without clobbering
    // them (the loadout PAGE makes them editable). Cards + blob are gpa-owned
    // so the CID slices the socket emits stay valid across frames (B-split).
    var empty_cards = [_]lens_socket.LensCard{};
    var socket_cards: []lens_socket.LensCard = &empty_cards;
    var socket_blob: []const u8 = "";
    var gseated: u32 = 0;
    var reply_cards: []lens_socket.LensCard = &empty_cards;
    var reply_blob: []const u8 = "";
    var reply_seated: u32 = 0;
    var zone_cards: []lens_socket.LensCard = &empty_cards;
    var zone_blob: []const u8 = "";
    var zone_seated: u32 = 0;
    // Restore the persisted loadouts from `app.zat4.socket.loadout`; absent
    // (first run) or a failed read falls back to the catalog defaults, which
    // we then write so the record exists going forward.
    {
        var load_arena = std.heap.ArenaAllocator.init(gpa);
        defer load_arena.deinit();
        const loaded: ?loadout_store.Loaded = loadout_store.load(gpa, load_arena.allocator(), io, environ, session) catch null;
        if (loaded) |ld| {
            buildSurfaceFromEntries(gpa, ld.feed, &socket_cards, &socket_blob, &gseated);
            buildSurfaceFromEntries(gpa, ld.reply, &reply_cards, &reply_blob, &reply_seated);
            buildSurfaceFromEntries(gpa, ld.zone, &zone_cards, &zone_blob, &zone_seated);
        }
        // Any surface that didn't resolve from the record → its catalog default.
        if (socket_cards.len == 0) if (lens_catalog.defaultFeedLoadout(gpa)) |t| {
            socket_cards = t[0];
            socket_blob = t[1];
            gseated = lens_catalog.default_feed_seated;
        } else |_| {};
        if (reply_cards.len == 0) if (lens_catalog.defaultReplyLoadout(gpa)) |t| {
            reply_cards = t[0];
            reply_blob = t[1];
            reply_seated = lens_catalog.default_reply_seated;
        } else |_| {};
        if (zone_cards.len == 0) if (lens_catalog.defaultZoneLoadout(gpa)) |t| {
            zone_cards = t[0];
            zone_blob = t[1];
            zone_seated = lens_catalog.default_zone_seated;
        } else |_| {};
        // First run (no record): persist the defaults once (synchronous here is
        // fine — it's startup, before the loop).
        if (loaded == null) {
            loadout_store.saveAll(
                gpa,
                load_arena.allocator(),
                io,
                environ,
                session,
                surfaceDataOf(load_arena.allocator(), socket_cards, socket_blob, gseated),
                surfaceDataOf(load_arena.allocator(), reply_cards, reply_blob, reply_seated),
                surfaceDataOf(load_arena.allocator(), zone_cards, zone_blob, zone_seated),
                clock_shell.unixSeconds(),
            ) catch {};
        }
    }
    if (socket_cards.len > 0) gseated = @min(gseated, @as(u32, @intCast(socket_cards.len - 1)));
    defer if (socket_cards.len > 0) gpa.free(socket_cards);
    defer if (socket_blob.len > 0) gpa.free(socket_blob);
    defer if (reply_cards.len > 0) gpa.free(reply_cards);
    defer if (reply_blob.len > 0) gpa.free(reply_blob);
    defer if (zone_cards.len > 0) gpa.free(zone_cards);
    defer if (zone_blob.len > 0) gpa.free(zone_blob);
    // Set when the loadout changes (recolor / reorder / seat); flushed to the
    // background worker when the tray closes (so editing never blocks).
    var loadout_dirty = false;
    var socket_was_open = false;
    var gsocket_ui: lens_socket.SocketUi = .{};
    var gsocket_hits: lens_socket.HitList = .empty;
    defer gsocket_hits.deinit(gpa);
    // The reply/zone sockets, shown on the loadout PAGE (the feed surface reuses
    // gsocket_ui/gsocket_hits above). Their transient UI + per-frame hit lists.
    var reply_ui: lens_socket.SocketUi = .{};
    var reply_hits: lens_socket.HitList = .empty;
    defer reply_hits.deinit(gpa);
    var zone_ui: lens_socket.SocketUi = .{};
    var zone_hits: lens_socket.HitList = .empty;
    defer zone_hits.deinit(gpa);
    // Drag on the loadout PAGE: each socket's on-page geometry (filled by
    // layoutLoadout), and which surface is mid-drag (0 feed / 1 reply / 2 zone).
    var page_geoms: [3]lens_socket.Geometry = .{ .{ .x = 0, .y = 0, .w = 0 }, .{ .x = 0, .y = 0, .w = 0 }, .{ .x = 0, .y = 0, .w = 0 } };
    var page_drag_surface: ?u8 = null;
    // Previous frame's screen — flush the loadout when LEAVING the page (the
    // page's sockets are always open, so there's no tray-close beat there).
    var prev_screen: u8 = 0;
    // The active sub-tab on the Algorithms page: 0 = Loadout, 1 = Marketplace,
    // 2 = Create (the latter two are placeholders for now).
    var gloadout_tab: u8 = 0;
    // The simple-Create flow's state (loadout tab 2): the current step, the
    // plain-language answers so far, the live config (rebuilt from the answers, then
    // nudged by the recap knobs), the chosen accent, and the name buffer. The user's
    // OWNED algorithms land in `algo_lib`; `algo_uid` mints their local ids.
    var gcreate_step: create_flow.Step = .landing;
    var gcreate_answers: builder.Answers = .{};
    var gcreate_config: discover.FeedConfig = builder.build(.{});
    var gcreate_color: u8 = 0;
    var gcreate_name_buf: [64]u8 = undefined;
    var gcreate_name_len: usize = 0;
    // Zat Chat (M1): the DM view store — a QUERY model over the real E2EE
    // session below (zat-view-model law). Messages are end-to-end encrypted
    // via MLS; this store holds only the plaintext the local user has typed
    // or the crypto core has decrypted for display.
    var gchat_store: chat_core.Store = .{};
    defer chat_core.deinitStore(gpa, &gchat_store);
    var gchat_sel: ?chat_core.ConvIndex = null;
    var gchat_draft_buf: [512]u8 = undefined;
    var gchat_draft_len: usize = 0;
    var gchat_input_focus: bool = false;
    // The new-conversation flow: the recipient draft (a handle or DID being
    // typed) and why the last attempt refused (static strings, "" = none).
    var gchat_composing: bool = false;
    var gchat_peer_buf: [254]u8 = undefined;
    var gchat_peer_len: usize = 0;
    var gchat_compose_status: []const u8 = "";
    // The peer-is-typing signal (U6a, real): an ENCRYPTED ping on the
    // reserved wire kind (chat.kind_typing_wire) — the relay sees one more
    // fixed-size bucket; only the peer can read it. Receiving one arms a
    // deadline; the indicator shows in the matching open thread until it
    // lapses (or the message itself arrives). The sender throttles to one
    // ping per 4s of active typing.
    var gchat_typing_deadline: i64 = 0;
    var gchat_typing_peer_buf: [256]u8 = undefined;
    var gchat_typing_peer_len: usize = 0;
    var gchat_typing_sent_at: i64 = 0;
    // Last chat keystroke (monotonic ns) — the caret's blink clock: lit
    // while typing, breathing when idle.
    var gchat_key_ns: u64 = 0;

    // The real E2EE session (M1): the crypto state (anchor, keyPackage,
    // per-conversation MLS groups) + the relay link that carries encrypted
    // buckets. Live only when the relay endpoint is configured
    // (ZAT4_RELAY=host:port + ZAT_RELAY_TOKEN); absent it, Messages shows an
    // empty, honest surface (no fake seeds). A dead relay is an empty drain,
    // never a dead screen (E2/E4). A short-lived arena serves the network
    // legs (publish/fetch); the resident state is gpa-owned.
    var gchat_arena_state = std.heap.ArenaAllocator.init(gpa);
    defer gchat_arena_state.deinit();
    var gchat_box: chat_relay.Mailbox = .{};
    defer gchat_box.deinit(gpa);
    var gchat_link: ?*chat_relay.ChatRelay = null;
    defer if (gchat_link) |link| chat_relay.shutdown(link);
    var gchat_e2ee: ?chat_e2ee.State = null;
    defer if (gchat_e2ee) |*st| chat_e2ee.deinit(gpa, st);
    var gchat_mail: std.ArrayList(chat_relay.Mail) = .empty;
    defer {
        for (gchat_mail.items) |m| chat_relay.freeMail(gpa, m);
        gchat_mail.deinit(gpa);
    }
    if (dev_chat) {
        if (environ) |env| {
            if (env.get("ZAT4_RELAY")) |hostport| {
                const token = env.get("ZAT_RELAY_TOKEN") orelse "";
                const colon = std.mem.lastIndexOfScalar(u8, hostport, ':');
                const rhost = if (colon) |c| hostport[0..c] else "";
                const rport = if (colon) |c| std.fmt.parseInt(u16, hostport[c + 1 ..], 10) catch 0 else 0;
                if (rport != 0 and token.len > 0 and rhost.len > 0) {
                    // Bring up the crypto (publishes our keyPackage, restores
                    // saved conversations), then the relay link subscribed to
                    // our own inbox mailbox.
                    _ = gchat_arena_state.reset(.retain_capacity);
                    if (chat_e2ee.init(gpa, gchat_arena_state.allocator(), io, env, session)) |st| {
                        gchat_e2ee = st;
                        gchat_link = chat_relay.start(gpa, io, &gchat_box, rhost, rport, token, st.inbox) catch null;
                        // Restore the displayed history (M2) first. A missing
                        // or corrupt blob is a cold start, never a half-restore
                        // (the codec is strict) — the mirror below still
                        // recovers the conversation LIST from the MLS groups;
                        // only the transcript would be gone.
                        var hist_path_buf: [512]u8 = undefined;
                        if (cache_shell.chatHistoryPath(&hist_path_buf, env, st.my_did)) |hist_path| {
                            if (cache_shell.loadChatHistoryAt(gpa, hist_path, st.my_did)) |blob| {
                                defer {
                                    std.crypto.secureZero(u8, blob);
                                    gpa.free(blob);
                                }
                                if (chat_core.deserializeStore(gpa, blob)) |restored| {
                                    chat_core.deinitStore(gpa, &gchat_store);
                                    gchat_store = restored;
                                } else |_| {}
                            }
                        }
                        // Mirror restored conversations into the view store so
                        // they show on launch (openConversation dedupes by DID,
                        // so ones already in the history blob are found, not
                        // doubled), then persist once to heal any divergence.
                        for (st.peer_dids.items) |did| {
                            _ = chat_core.openConversation(gpa, &gchat_store, did, "") catch {};
                        }
                        chatPersistHistory(gpa, io, env, &st, &gchat_store);
                        if (gchat_link != null) {
                            std.debug.print("[chat] E2EE up -> {s} ({d} conversation(s) restored)\n", .{ hostport, st.peer_dids.items.len });
                        } else {
                            std.debug.print("[chat] keyPackage published but the relay link did NOT start\n", .{});
                        }
                    } else |err| {
                        std.debug.print("[chat] E2EE init failed: {s}\n", .{@errorName(err)});
                    }
                } else {
                    std.debug.print("[chat] ZAT4_RELAY malformed (need host:port) or ZAT_RELAY_TOKEN unset\n", .{});
                }
                // Starting a conversation is a UI verb now — the "+ New"
                // pill on the Messages screen (the ZAT4_CHAT_PEER env
                // stopgap is deleted, not flagged off; same cut-over rule
                // as M1's plaintext path).
            }
        }
    }
    var gcreate_prepare_frames: u32 = 0; // the .preparing loading beat's progress (frames)
    // Load the user's saved library (created/downloaded feeds); empty on first run
    // or a corrupt file (deserialize is total). Saved after each create/adopt.
    var algo_lib: algo_library.Library = cache_shell.loadLibrary(gpa, environ) orelse .{};
    defer algo_lib.deinit(gpa);
    var algo_uid: u32 = 0;
    // Resume id minting past the highest persisted `user:N`, so a new create can't
    // collide with a saved one (add is idempotent by id → a collision drops the new).
    for (algo_lib.records.items) |rec| {
        const id = algo_lib.slice(rec.id);
        if (std.mem.startsWith(u8, id, "user:")) {
            const n = std.fmt.parseInt(u32, id["user:".len..], 10) catch continue;
            if (n >= algo_uid) algo_uid = n + 1;
        }
    }
    // The active top-level Screen (index into feed_view.nav_labels); the rail
    // sets it on a click. 0 = Home (the feed). Lives across frames in run().
    var gscreen: u8 = 0;
    // The premium Profile screen is a VIEW over the ONE shared `store`, not a
    // second store (ZONES invariant 4 — the post is the post). Entering it
    // fetches the viewed author's posts as CONTENT into `store`; the view's
    // ordering is a query (`feed_core.buildAuthorView`). The profile shows ANY
    // author: `profile_target_did` is whose profile (defaults to your own — the
    // rail "Profile"; set to a post author's DID when you tap their avatar).
    // `on_profile_prev` catches re-entry; `profile_dirty` catches a target
    // change (tapping a new author while already on the profile).
    var on_profile_prev = false;
    var profile_target_buf: [256]u8 = undefined;
    var profile_target_did: []const u8 = session.did;
    var profile_dirty = false;

    // The Thread screen (C4): tapping a post body opens its thread — also a VIEW
    // over the ONE shared store (the reply linkage rides on each post). Entering
    // fetches the thread (`feed_shell.loadThread`) as CONTENT; the ordering is a
    // query (`feed_core.buildThreadView`) keyed by the focused post's cid. The
    // uri is sent to the AppView's getPostThread; `thread_return_screen` is where
    // Back goes.
    var on_thread_prev = false;
    var thread_focus_cid_buf: [256]u8 = undefined;
    var thread_focus_uri_buf: [320]u8 = undefined;
    var thread_focus_cid: []const u8 = "";
    var thread_focus_uri: []const u8 = "";
    var thread_dirty = false;
    var thread_return_screen: u8 = 0;
    // ZONE page (a tag-scoped feed): tapping a `#tag` in a post's tray opens it.
    // On entry the shell fetches the zone (`feed_shell.loadZoneFeed`) as CONTENT;
    // the ordering is a query (`feed_core.buildTagView`) keyed by the tag. The
    // tag (display form) is sent to the AppView's getPostsForTag, which normalizes
    // it. `zone_return_screen` is where Back goes.
    var on_zone_prev = false;
    var zone_tag_buf: [256]u8 = undefined;
    var zone_tag: []const u8 = "";
    var zone_dirty = false;
    var zone_return_screen: u8 = 0;
    // Settings (`screen_settings`): the selected left-hand section (master–detail
    // state, like the return-screen vars above). A section tap sets it.
    var gsettings_section: u8 = 0;
    // Runtime on/off of every Settings toggle — a bitset indexed by GLOBAL row
    // index, seeded from each toggle's `flag_on` default. A toggle tap flips its
    // bit (so all Toy Box switches are live, even before their effects are wired).
    var toggle_bits: u64 = blk: {
        var b: u64 = 0;
        for (settings_view.rows, 0..) |r, i| {
            if (r.kind == .toggle and (r.flags & settings_view.flag_on) != 0) b |= @as(u64, 1) << @intCast(i);
        }
        break :blk b;
    };
    // Holds the "@handle" form for the Settings → Account info row (formatted
    // each frame from the session; the session handle has no leading @).
    var account_handle_buf: [128]u8 = undefined;
    // CHOICE selections: the live selected-option index per choice, seeded from
    // each choice's default. `gsettings_picking` = the open choice's action
    // (255 = no picker open). A tap on a choice opens its picker; an option tap
    // sets the index + closes.
    var choice_sel: [settings_view.choices.len]u8 = blk: {
        var s: [settings_view.choices.len]u8 = undefined;
        for (settings_view.choices, 0..) |c, i| s[i] = c.default;
        break :blk s;
    };
    var gsettings_picking: u8 = 255;
    // Zones BROWSE catalog (`screen_zones_browse`): gpa-owned zone cards (the
    // display tag duped + post count), (re)fetched from `listTags` on entering
    // the browse screen. Each card taps to its zone feed; freed on exit.
    var zone_catalog: std.ArrayList(feed_view.ZoneCard) = .empty;
    var on_browse_prev = false;
    defer {
        for (zone_catalog.items) |zc| gpa.free(zc.tag);
        zone_catalog.deinit(gpa);
    }
    // MARKETPLACE catalog (Algorithms → Marketplace tab): gpa-owned rows from the
    // AppView's `getAlgorithms`, (re)fetched on entering the tab. `market_catalog`
    // holds the full row (incl. the author DID + rkey the "View details" fetch
    // needs); `market_cards` is the display projection handed to the renderer.
    const MarketRow = struct {
        name: []const u8,
        author_disp: []const u8, // "@handle" or the DID
        author_did: []const u8,
        rkey: []const u8,
        cid: []const u8,
        learns: bool,
        uses_behavioral: bool,
        state_budget_bytes: u32,
    };
    var market_catalog: std.ArrayList(MarketRow) = .empty;
    var market_cards: std.ArrayList(feed_view.MarketAlgoCard) = .empty;
    var on_market_prev = false;
    defer {
        for (market_catalog.items) |r| {
            gpa.free(r.name);
            gpa.free(r.author_disp);
            gpa.free(r.author_did);
            gpa.free(r.rkey);
            gpa.free(r.cid);
        }
        market_catalog.deinit(gpa);
        market_cards.deinit(gpa);
    }
    // The algorithm being inspected on the transparency page (screen_transparency):
    // its fetched config + name + ref (CID), rebuilt into a page each frame. The
    // screen to return to on Back. Config null ⇒ not inspecting.
    // The inspected algorithm is held as its SERIALIZED bytes (gpa-owned, stable),
    // NOT a parsed FeedConfig: a parsed config's `rules`/`vm_program` slices point
    // into the per-frame arena, which is reset every frame — holding the struct
    // across frames dangles those slices (a use-after-free that crashes validated()
    // on any non-empty program). The render re-parses these bytes into the current
    // frame's arena, and the source view IS these bytes.
    var inspect_bytes: ?[]const u8 = null;
    var inspect_name: []const u8 = "";
    var inspect_ref: []const u8 = "";
    var transp_return_screen: u8 = feed_view.screen_loadout;
    // On the transparency page: false = the summary, true = the byte-exact source
    // (the "View the exact source" tap-through). Reset when a new algorithm opens.
    var gtransp_source = false;
    // The config fetch runs on a worker (no UI freeze); true while it's in flight.
    var inspect_loading = false;
    var inspectjob: InspectJob = .{};
    defer stopInspect(&inspectjob); // join any in-flight fetch before exit
    // CID-keyed config cache (A8): an algorithm's config is a content-addressed,
    // immutable record — same CID ⇒ same bytes ⇒ fetch ONCE, never again. Keyed by
    // the record CID (duped), value = the serialized config (owned). A re-view is a
    // local map hit (instant), only a never-seen algorithm pays the network fetch.
    // (A size cap / eviction is a later concern; the marketplace is small for now.)
    var config_cache: std.StringHashMapUnmanaged([]u8) = .empty;
    defer {
        var it = config_cache.iterator();
        while (it.next()) |kv| {
            gpa.free(kv.key_ptr.*);
            gpa.free(kv.value_ptr.*);
        }
        config_cache.deinit(gpa);
    }
    defer {
        if (inspect_bytes) |b| gpa.free(b);
        if (inspect_name.len > 0) gpa.free(inspect_name);
        if (inspect_ref.len > 0) gpa.free(inspect_ref);
    }
    // RE-ROOT mode: false when a thread is opened from the timeline (show the WHOLE
    // thread, scroll to the focus); true when a reply is tapped INSIDE the thread
    // (re-root on it: condensed ancestors above + the focus + its subtree).
    var thread_rerooted = false;
    // Collapsed reply CIDs (Reddit-style) — per-view state (ZONES inv. 4: never
    // on the post). gpa-owned dupes; cleared on exit. Passed to buildThreadView.
    var gcollapsed: std.ArrayList([]const u8) = .empty;
    defer {
        for (gcollapsed.items) |c| gpa.free(c);
        gcollapsed.deinit(gpa);
    }

    // The pointer's last position in LOGICAL coords (for the hover highlight),
    // updated on every motion event; <0 until the first move.
    var ghover_x: i32 = -1;
    var ghover_y: i32 = -1;

    // Phase 6.4: the GPU render path, brought up additively when the window is
    // open AND the font engine is live AND `gpu.init` succeeds. On any failure
    // it stays null and the SOFTWARE path renders (E2: a plainer window, never
    // a dead one). Created once here; the window is already open by the time
    // run() is called, so its XID is valid.
    var gpu_state: ?GpuState = null;
    defer if (gpu_state) |*gs| deinitGpuState(gpa, gs);
    if (backend == .window) if (engine) |*e| {
        gpu_state = initGpuState(gpa, e, backend.window) catch |err| blk: {
            std.debug.print("[gpu] init failed ({s}) — using the software path.\n", .{@errorName(err)});
            break :blk null;
        };
    };

    main_loop: while (true) {
        _ = frame_arena.reset(.retain_capacity); // C3: one arena per frame
        const arena = frame_arena.allocator();

        const size: WindowSize = switch (backend) {
            .terminal => readWindowSize(stdin_fd),
            .window => |win| .{ .cols = win.cols, .rows = win.rows },
        };
        if (size.cols != next.width or size.rows != next.height) {
            try tui.resizeSurface(gpa, &next, size.cols, size.rows);
            // prev keeps its old dimensions; encodeDiff sees the mismatch
            // and full-repaints — resize handling for free.
        }

        // Wall clock via the cross-OS clock shell (kernel-stable syscalls
        // on Linux, kernel32 on Windows — std.Io's clock API still drifts
        // between 0.16-dev snapshots). The clock stays in the shell (B3);
        // the core receives the epoch as plain data (B4).
        const now: i64 = clock_shell.unixSeconds();

        // Phase 8: a cache-warmed store gets live coverage and an honest
        // status from frame one — no fetch needed to learn whose posts to
        // want. One attempt; the fetch arms below retry on their own.
        if (!live_start_attempted and live_stream == null and store.authors.len > 0) {
            live_start_attempted = true;
            status = std.fmt.bufPrint(&status_buf, "cached: {d} posts (r refreshes)", .{store.feed.len}) catch "cached";
            live_stream = try startLiveStream(gpa, io, environ, session.did, store, &mailbox, arena);
            if (live_stream != null) subscribed_authors = store.authors.len;
        }

        // Drain the stream's mailbox on the UI thread: plain values in,
        // ingested here, so the store stays single-threaded. Post strings
        // are freed the moment they are ingested — and the unprocessed
        // tail is freed before any error bubbles (C5).
        live_mail.clearRetainingCapacity();
        try mailbox.drain(gpa, &live_mail);
        var mail_i: usize = 0;
        while (mail_i < live_mail.items.len) : (mail_i += 1) {
            switch (live_mail.items[mail_i]) {
                .status => |msg| status = msg,
                .failure => |err| status = std.fmt.bufPrint(
                    &status_buf,
                    "stream: {s}; retrying",
                    .{@errorName(err)},
                ) catch "stream: retrying",
                .post => |post| {
                    const ingested = feed_core.ingestLivePost(gpa, store, post);
                    stream_shell.freePost(gpa, post);
                    const outcome = ingested catch |err| {
                        var rest = mail_i + 1;
                        while (rest < live_mail.items.len) : (rest += 1) {
                            switch (live_mail.items[rest]) {
                                .post => |tail| stream_shell.freePost(gpa, tail),
                                .status, .failure => {},
                            }
                        }
                        return err;
                    };
                    if (outcome == .added) {
                        // A live post inserts at feed index 0. The render
                        // window starts at scroll_top and paints downward, so
                        // to SHOW the arrival we anchor the viewport and the
                        // cursor at the top. (The prior code did scroll_top +=1
                        // to "hold position," but that pushed the window one row
                        // BELOW the new post — rendering everything except the
                        // post that just arrived, the exact "live: new post but
                        // nothing appears" bug. For a firehose the right default
                        // is to surface the new post; hold-position can return
                        // later as a configurable behavior.)
                        state.selected = 0;
                        state.scroll_top = 0;
                        gview.scroll_rows = 0;
                        status = "live: new post";
                    }
                },
            }
        }

        // Drain the chat relay's mailbox (M1): each delivered bucket is an
        // MLS message the E2EE session routes — a decrypted application
        // message becomes a counterparty bubble in the one shared store; a
        // Welcome opens a new conversation (verified against the directory).
        // Damaged/foreign buckets are skipped values, never a dead screen
        // (E2/E4). The surface repaints via the chat signature exactly as a
        // local append does.
        if (gchat_link != null) if (gchat_e2ee) |*st| {
            gchat_mail.clearRetainingCapacity();
            try gchat_box.drain(gpa, &gchat_mail);
            var chat_mutated = false;
            for (gchat_mail.items) |m| {
                switch (m) {
                    .blob => |b| {
                        _ = gchat_arena_state.reset(.retain_capacity);
                        const inc = chat_e2ee.onBucket(gpa, gchat_arena_state.allocator(), io, environ, st, b) catch null;
                        if (inc) |ev| {
                            defer chat_e2ee.freeIncoming(gpa, ev);
                            switch (ev) {
                                .message => |msg| {
                                    if (chat_core.openConversation(gpa, &gchat_store, msg.peer_did, "") catch null) |c| {
                                        _ = chat_core.appendMessage(gpa, &gchat_store, c, msg.kind, msg.text, now, false) catch {};
                                        chat_mutated = true;
                                    }
                                    // The message supersedes its typing bubble.
                                    if (std.mem.eql(u8, msg.peer_did, gchat_typing_peer_buf[0..gchat_typing_peer_len]))
                                        gchat_typing_deadline = 0;
                                },
                                .started => |s| {
                                    _ = chat_core.openConversation(gpa, &gchat_store, s.peer_did, "") catch null;
                                    chat_mutated = true;
                                    status = "chat: new conversation";
                                },
                                // Ephemeral: arm the indicator's deadline;
                                // nothing enters the store (M2 never sees it).
                                .typing => |t| if (t.peer_did.len <= gchat_typing_peer_buf.len) {
                                    @memcpy(gchat_typing_peer_buf[0..t.peer_did.len], t.peer_did);
                                    gchat_typing_peer_len = t.peer_did.len;
                                    gchat_typing_deadline = now + 6;
                                },
                            }
                        }
                    },
                    .refused => status = "chat: relay refused the send",
                    .status => {},
                    .failure => {},
                }
                chat_relay.freeMail(gpa, m);
            }
            gchat_mail.clearRetainingCapacity();
            // M2: one history write per drain that changed the store. This
            // matters more than the send-side write — forward secrecy means a
            // decrypted message can NEVER be recovered from the wire again, so
            // it reaches disk before this frame ends.
            if (chat_mutated) chatPersistHistory(gpa, io, environ, st, &gchat_store);
        };

        // Drain write-worker results (the non-blocking like/unlike/repost
        // replies). On OK, nothing to do — the optimistic state already
        // shows the right thing. On a refusal or network error, REVERT the
        // optimism so the count returns to truth. This runs every loop
        // iteration, off the network thread, so the UI never blocked on the
        // write — the whole point of the worker.
        write_results.clearRetainingCapacity();
        try write_out.drain(gpa, &write_results);
        for (write_results.items) |res| {
            // Deferred-undo: if the user un-engaged this post WHILE its create
            // was in flight, the create's result is the first moment we can
            // delete the record. Fire the delete now (the optimistic hollow is
            // already shown); on a failed create there's nothing to delete.
            const deferred: ?*std.AutoHashMapUnmanaged(u64, void) = switch (res.kind) {
                .like => &deferred_unlike,
                .repost => &deferred_unrepost,
                .unlike, .unrepost => null,
                .loadout => null, // loadout writes post no result; defensive only
            };
            if (deferred) |set| {
                if (set.remove(std.hash.Wyhash.hash(0, res.cid))) {
                    if (res.outcome == .ok and res.outcome.ok.len > 0) {
                        if (writer) |w| _ = write_worker.submit(w, if (res.kind == .like) .unlike else .unrepost, res.cid, "", "", res.outcome.ok, now);
                    }
                    write_worker.freeResult(gpa, res);
                    continue;
                }
            }
            switch (res.outcome) {
                .ok => |uri| {
                    // Record OUR created like/repost uri so a later unlike/
                    // unrepost can delete that record — the AppView never sends
                    // viewer.like, so the optimistic path has no uri otherwise.
                    if (uri.len > 0) switch (res.kind) {
                        .like => feed_core.setLikeUri(gpa, store, res.cid, uri) catch {},
                        .repost => feed_core.setRepostUri(gpa, store, res.cid, uri) catch {},
                        .unlike, .unrepost, .loadout => {},
                    };
                },
                .refused => |f| {
                    revertWrite(res.kind, gpa, store, res.cid, res.revert_uri) catch {};
                    status = std.fmt.bufPrint(&status_buf, "refused: {d} {s}", .{ f.status, f.code }) catch "refused";
                },
                .net_error => |name| {
                    revertWrite(res.kind, gpa, store, res.cid, res.revert_uri) catch {};
                    status = std.fmt.bufPrint(&status_buf, "network error: {s}", .{name}) catch "network error";
                },
            }
            write_worker.freeResult(gpa, res);
        }

        // Auto-refresh tick: in timeline mode, once the interval has elapsed,
        // re-run the same getTimeline the `r` key runs. New posts slot in at
        // the top and the viewport jumps so they are seen — identical to a
        // manual refresh, just on a timer. This ALSO does the initial load: an
        // empty store (a cleared cache / first run) would otherwise never fetch
        // — the window path has no separate startup fetch, so the first tick is
        // the first load. Failure is contained to the status line (E2); only
        // OOM is fatal. Never fires mid-compose, so it cannot disturb a draft.
        if (refresh_interval > 0 and mode == .timeline and
            now - last_auto_refresh >= refresh_interval and
            clock_shell.monotonicNanos() -| last_input_nanos >= input_idle_gate_nanos)
        {
            last_auto_refresh = now;
            const was_empty = store.feed.len == 0;
            const outcome = feed_shell.refreshTimeline(gpa, arena, io, environ, session, appview_url, store, 30) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => blk: {
                    status = "auto-refresh: network error"; // contained
                    break :blk null;
                },
            };
            if (outcome) |result| switch (result) {
                // New posts are STAGED (refreshTimeline doesn't displace the
                // reader). Reveal them immediately ONLY on the first load (an
                // empty feed) or when the reader is at the very top of Home;
                // otherwise leave them behind the "N new posts" pill so the
                // reader's place is never yanked (the Twitter/Bluesky pattern).
                .ok => if (feed_core.pendingCount(store) > 0) {
                    const at_top_home = gscreen == feed_view.screen_home and gscroll_px == 0;
                    if (was_empty or at_top_home) {
                        _ = feed_core.revealPending(gpa, store) catch 0;
                        state.selected = 0;
                        state.scroll_top = 0;
                        gview.scroll_rows = 0;
                        gscroll_px = 0;
                    }
                    // else: the pill (feed_core.pendingCount) carries the count.
                },
                .failed => {}, // a refused poll is silent; the next tick retries
            };
            if (outcome != null and outcome.? == .ok) {
                _ = cache_shell.saveStore(gpa, environ, store); // E4: a failed save is simply no cache
            }
        }

        // Pull-to-refresh: the overscroll gesture asked for a refresh. Unlike the
        // passive auto-refresh, an EXPLICIT pull asks to SEE the new — so reveal
        // the staged posts and jump to the top. Failure stays on the status line
        // (E2); only OOM is fatal.
        if (pull_refresh_requested) {
            pull_refresh_requested = false;
            status = "refreshing...";
            if (feed_shell.refreshTimeline(gpa, arena, io, environ, session, appview_url, store, 30)) |outcome| {
                switch (outcome) {
                    .ok => |stats| {
                        const revealed_n = feed_core.revealPending(gpa, store) catch 0;
                        if (revealed_n > 0) {
                            state.selected = 0;
                            state.scroll_top = 0;
                            gview.scroll_rows = 0;
                            gscroll_px = 0;
                        }
                        status = if (stats.items_added == 0 and revealed_n == 0)
                            "no new posts"
                        else
                            std.fmt.bufPrint(&status_buf, "+{d} new at top", .{revealed_n}) catch "new posts";
                        _ = cache_shell.saveStore(gpa, environ, store);
                    },
                    .failed => |failure| status = std.fmt.bufPrint(&status_buf, "refused: {d} {s}", .{ failure.status, failure.code }) catch "refused",
                }
            } else |err| switch (err) {
                error.OutOfMemory => return err,
                else => status = "network error", // contained (E2)
            }
        }

        // Premium Profile screen: on ENTERING it (the rail click flips gscreen),
        // fetch the viewed account's posts as CONTENT into the SHARED store — a
        // fresh fetch each visit. Failure is contained to the status line (E2);
        // only OOM is fatal. Gated to the timeline mode + window path.
        const on_profile = mode == .timeline and gscreen == feed_view.screen_profile;
        if (on_profile and (!on_profile_prev or profile_dirty)) {
            const po = feed_shell.loadAuthorFeed(gpa, arena, io, environ, session, appview_url, store, profile_target_did, 30) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => blk: {
                    status = "profile: network error"; // contained
                    break :blk null;
                },
            };
            if (po) |result| switch (result) {
                .ok => {},
                .failed => status = "profile: unavailable",
            };
            profile_dirty = false;
        }
        on_profile_prev = on_profile;

        // Thread screen: on ENTERING (a post-body tap flips gscreen) or a target
        // change, fetch the focused post's thread as CONTENT into the SHARED
        // store. The view ordering is then a query (buildThreadView). Same E2
        // containment as the profile fetch.
        const on_thread = mode == .timeline and gscreen == feed_view.screen_thread;
        if (on_thread and (!on_thread_prev or thread_dirty)) {
            const to = feed_shell.loadThread(gpa, arena, io, environ, session, appview_url, store, thread_focus_uri, 50) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => blk: {
                    status = "thread: network error"; // contained
                    break :blk null;
                },
            };
            if (to) |result| switch (result) {
                .ok => {},
                .failed => status = "thread: unavailable",
            };
            thread_dirty = false;
        }
        on_thread_prev = on_thread;

        // Zone page: on ENTERING (a tag-pill tap flips gscreen) or a tag change,
        // fetch the zone's posts as CONTENT into the SHARED store. The view
        // ordering is then a query (buildTagView). Same E2 containment.
        const on_zone = mode == .timeline and gscreen == feed_view.screen_zones;
        if (on_zone and (!on_zone_prev or zone_dirty)) {
            const zo = feed_shell.loadZoneFeed(gpa, arena, io, environ, session, appview_url, store, zone_tag, 50) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => blk: {
                    status = "zone: network error"; // contained
                    break :blk null;
                },
            };
            if (zo) |result| switch (result) {
                .ok => {},
                .failed => status = "zone: unavailable",
            };
            zone_dirty = false;
        }
        on_zone_prev = on_zone;

        // Zones BROWSE: on ENTERING the catalog screen, fetch the zone set
        // (`listTags`) into the owned catalog. Metadata, not posts — it doesn't
        // touch the store. Contained failure (E2): the grid just stays as it was.
        const on_browse = mode == .timeline and gscreen == feed_view.screen_zones_browse;
        if (on_browse and !on_browse_prev) {
            const zo = feed_shell.loadZones(gpa, arena, io, environ, session, appview_url) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => blk: {
                    status = "zones: network error"; // contained
                    break :blk null;
                },
            };
            if (zo) |result| switch (result) {
                .ok => |tags| {
                    for (zone_catalog.items) |zc| gpa.free(zc.tag);
                    zone_catalog.clearRetainingCapacity();
                    for (tags) |t| {
                        const dup = try gpa.dupe(u8, t.tag);
                        try zone_catalog.append(gpa, .{ .tag = dup, .count = t.count });
                    }
                },
                .failed => status = "zones: unavailable",
            };
        }
        on_browse_prev = on_browse;

        // MARKETPLACE: on ENTERING the Algorithms → Marketplace tab, fetch the
        // published algorithms (`getAlgorithms`) into the owned catalog. Metadata,
        // not posts — it doesn't touch the store. Contained failure (E2).
        const on_market = mode == .timeline and gscreen == feed_view.screen_loadout and gloadout_tab == 1;
        if (on_market and !on_market_prev) {
            const mo = feed_shell.loadAlgorithms(gpa, arena, io, environ, session, appview_url, 50) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => blk: {
                    status = "marketplace: network error"; // contained
                    break :blk null;
                },
            };
            if (mo) |result| switch (result) {
                .ok => |algos| {
                    for (market_catalog.items) |r| {
                        gpa.free(r.name);
                        gpa.free(r.author_disp);
                        gpa.free(r.author_did);
                        gpa.free(r.rkey);
                        gpa.free(r.cid);
                    }
                    market_catalog.clearRetainingCapacity();
                    for (algos) |a| {
                        const author_disp = if (a.handle.len > 0)
                            try std.fmt.allocPrint(gpa, "@{s}", .{a.handle})
                        else
                            try gpa.dupe(u8, a.author);
                        try market_catalog.append(gpa, .{
                            .name = try gpa.dupe(u8, a.name),
                            .author_disp = author_disp,
                            .author_did = try gpa.dupe(u8, a.author),
                            .rkey = try gpa.dupe(u8, a.rkey),
                            .cid = try gpa.dupe(u8, a.cid),
                            .learns = a.learns,
                            .uses_behavioral = a.usesBehavioral,
                            .state_budget_bytes = a.stateBudgetBytes,
                        });
                    }
                    // Refill the display projection (strings point into the owned
                    // rows above, which are stable until the next fetch clears them).
                    market_cards.clearRetainingCapacity();
                    for (market_catalog.items) |r| try market_cards.append(gpa, .{
                        .name = r.name,
                        .author = r.author_disp,
                        .learns = r.learns,
                        .uses_behavioral = r.uses_behavioral,
                        .state_budget_bytes = r.state_budget_bytes,
                    });
                },
                .failed => status = "marketplace: unavailable",
            };
        }
        on_market_prev = on_market;

        // Consume a finished background config fetch (View details): after the
        // worker signals done, join it and copy its page_allocator result into the
        // render gpa (no concurrency past the join), then free the worker copy.
        if (inspectjob.active and inspectjob.done.load(.acquire)) {
            joinInspect(&inspectjob);
            if (inspectjob.ok) {
                if (inspectjob.bytes) |b| {
                    if (inspect_bytes) |old| gpa.free(old);
                    inspect_bytes = gpa.dupe(u8, b) catch null;
                    // Cache the config by CID (A8) so a re-view never re-fetches.
                    if (inspect_ref.len > 0 and !config_cache.contains(inspect_ref)) {
                        const k = gpa.dupe(u8, inspect_ref) catch null;
                        const v = gpa.dupe(u8, b) catch null;
                        if (k != null and v != null) {
                            config_cache.put(gpa, k.?, v.?) catch {
                                gpa.free(k.?);
                                gpa.free(v.?);
                            };
                        } else {
                            if (k) |kk| gpa.free(kk);
                            if (v) |vv| gpa.free(vv);
                        }
                    }
                    std.heap.page_allocator.free(b);
                    inspectjob.bytes = null;
                }
            } else status = "algorithm: unavailable";
            inspect_loading = false;
        }

        // The ACTIVE view: Home (one ordering over the store), the profile screen
        // (the TARGET author's posts), a post's THREAD, or a ZONE (a tag query) —
        // each a query over the SAME store. One list of view-models the render +
        // input + engagement paths all key off; the post records (and so
        // engagement + identity) are shared (ZONES invariant 4).
        // The seated lens per surface decides ordering: the FEED lens whether
        // Home is scored (and by which algorithm), the REPLY lens how a thread's
        // siblings order (null on either = the no-scoring path: feed order /
        // chronological threading). Resolved once per frame and reused by the
        // engagement repaints so they rebuild through the same algorithm.
        const feed_config = seatedLensConfig(socket_cards, socket_blob, gseated);
        const reply_config = seatedLensConfig(reply_cards, reply_blob, reply_seated);
        const view_items: []const feed_core.TimelineItem = if (on_thread)
            try feed_core.buildThreadView(arena, store, thread_focus_cid, thread_rerooted, gcollapsed.items, now, reply_config)
        else if (on_profile)
            try feed_core.buildAuthorView(arena, store, profile_target_did)
        else if (on_zone)
            try feed_core.buildTagView(arena, store, zone_tag)
        else if (feed_config) |cfg|
            try feed_core.buildDiscoverView(arena, store, cfg, now, null)
        else
            try feed_core.buildTimeline(arena, store);
        const profile_header = try profileHeaderFor(arena, session, gscreen, profile_target_did, view_items);
        // Advance the seat animation one step per painted frame, resetting at
        // the end of the swap (the field animates continuously, so frames
        // flow). The widget maps swap_phase→geometry purely (B4).
        if (gsocket_ui.swap_phase > 0) {
            gsocket_ui.swap_phase +|= 1;
            if (gsocket_ui.swap_phase > lens_socket.swap_total_frames) gsocket_ui.swap_phase = 0;
        }
        // Spring-open: ease each switcher socket's open progress toward its open
        // state. The widget sweeps the tray + reveals cards by this (page sockets
        // force open_t=1 in their render, so this is a no-op there).
        {
            const oe: f32 = 0.34;
            gsocket_ui.open_t += ((if (gsocket_ui.open) @as(f32, 1) else 0) - gsocket_ui.open_t) * oe;
            reply_ui.open_t += ((if (reply_ui.open) @as(f32, 1) else 0) - reply_ui.open_t) * oe;
            zone_ui.open_t += ((if (zone_ui.open) @as(f32, 1) else 0) - zone_ui.open_t) * oe;
        }
        const home_tray: lens_socket.TrayView = .{ .cards = socket_cards, .text = socket_blob, .seated = gseated };
        // Advance the drag's LIVE REFLOW + lift + settle one step per frame (the
        // iOS "pick up and the others fill in" feel). The targets are pure
        // integer slot math; positions are eased here, drawn by the widget.
        const socket_layout_w: i32 = if (gpu_state != null) @intCast(design_w) else switch (backend) {
            .window => |w| @intCast(w.fb.width),
            else => @intCast(design_w),
        };
        if (gscreen == feed_view.screen_loadout) {
            // On the page, advance whichever surface is mid-drag, using its
            // on-page geometry (from last frame's layoutLoadout). Clear the
            // drag once its settle finishes (drag_active goes null).
            if (page_drag_surface) |s| {
                switch (s) {
                    0 => advanceSocketDrag(&gsocket_ui, home_tray, page_geoms[0]),
                    1 => advanceSocketDrag(&reply_ui, .{ .cards = reply_cards, .text = reply_blob, .seated = reply_seated }, page_geoms[1]),
                    else => advanceSocketDrag(&zone_ui, .{ .cards = zone_cards, .text = zone_blob, .seated = zone_seated }, page_geoms[2]),
                }
                const ui_done = switch (s) {
                    1 => reply_ui.drag_active == null,
                    2 => zone_ui.drag_active == null,
                    else => gsocket_ui.drag_active == null,
                };
                if (ui_done) page_drag_surface = null;
            }
        } else {
            advanceSocketDrag(&gsocket_ui, home_tray, feed_view.homeSocketGeom(socket_layout_w));
        }
        // Persist the loadout when the tray CLOSES (the "done editing" beat).
        // Hand it to the BACKGROUND write worker (the same thread that does
        // likes/reposts) so the putRecord never blocks the UI loop — this is
        // the fix for the freeze on cartridge-switch (seating closes the tray,
        // which used to do a synchronous network write right here). The ids
        // are slices into socket_blob; submitLoadout dupes them.
        // Flush on the home tray CLOSING, or on LEAVING the loadout page (whose
        // sockets are always open, so there's no tray-close there).
        const left_loadout_page = prev_screen == feed_view.screen_loadout and gscreen != feed_view.screen_loadout;
        const left_thread = prev_screen == feed_view.screen_thread and gscreen != feed_view.screen_thread;
        const left_zone = prev_screen == feed_view.screen_zones and gscreen != feed_view.screen_zones;
        const tray_closed = socket_was_open and !gsocket_ui.open;
        if ((tray_closed or left_loadout_page or left_thread or left_zone) and loadout_dirty) {
            if (writer) |w| {
                // Write the WHOLE record (all three surfaces) so one surface's
                // edit doesn't clobber the others. ids slice into each surface's
                // blob; submitLoadout dupes them onto the worker.
                _ = write_worker.submitLoadout(
                    w,
                    surfaceDataOf(arena, socket_cards, socket_blob, gseated),
                    surfaceDataOf(arena, reply_cards, reply_blob, reply_seated),
                    surfaceDataOf(arena, zone_cards, zone_blob, zone_seated),
                    now,
                );
            }
            loadout_dirty = false;
        }
        socket_was_open = gsocket_ui.open;
        prev_screen = gscreen;
        // pix exists exactly when a window backend has a live engine; the
        // composer and profile screens stay on the cell path this cut
        // (their pixel port is the recorded next slice).
        // On the THREAD screen the socket-of-the-screen is the REPLY socket
        // (drawn inline after the root + author self-thread). Elsewhere (home
        // header, loadout page) it's the FEED socket. Accent stays feed-derived
        // — reply seating never retints (owner rule).
        // The socket-of-the-screen: REPLY socket on a thread, the ZONE socket on a
        // zone page, the FEED socket on Home. Each is a switcher over its own
        // surface's loadout (the three the Algorithms page edits).
        const on_thread_screen = gscreen == feed_view.screen_thread;
        const on_zone_screen = gscreen == feed_view.screen_zones;
        const cur_socket_tray: lens_socket.TrayView = if (on_thread_screen)
            .{ .cards = reply_cards, .text = reply_blob, .seated = reply_seated }
        else if (on_zone_screen)
            .{ .cards = zone_cards, .text = zone_blob, .seated = zone_seated }
        else
            home_tray;
        // Functional Toy Box / Appearance toggles — each reads its runtime bit
        // (the generalized Julia pattern) and gates its behaviour below.
        const julia_on = toggleOn(toggle_bits, settings_view.act_julia);
        const ripples_on = toggleOn(toggle_bits, settings_view.act_ripples);
        const field_on = toggleOn(toggle_bits, settings_view.act_field);
        const crt_on = toggleOn(toggle_bits, settings_view.act_crt);
        const frametiming_on = toggleOn(toggle_bits, settings_view.act_frametiming);
        const settings_account: feed_view.SettingsAccount = .{
            .handle = std.fmt.bufPrint(&account_handle_buf, "@{s}", .{session.handle}) catch session.handle,
            .did = session.did,
            .pds = session.pds_url,
        };
        // Choice selections → the effects (each frame, declarative like the toggles).
        const settings_choices_packed = packChoices(&choice_sel);
        const accent_override: ?u32 = accentChoiceColor(choiceSel(&choice_sel, settings_view.act_accent));
        const field_gain: f32 = fieldGainFor(choiceSel(&choice_sel, settings_view.act_field_intensity));
        switch (backend) { // heart cursor follows the Julia toggle
            .window => |w| window_shell.setJulia(w, julia_on),
            else => {},
        }
        var cur_socket_ui = if (on_thread_screen) reply_ui else if (on_zone_screen) zone_ui else gsocket_ui;
        cur_socket_ui.julia = julia_on;
        const cur_socket_hits = if (on_thread_screen) &reply_hits else if (on_zone_screen) &zone_hits else &gsocket_hits;
        // The Create "preparing" beat: a brief loading pause after the last question,
        // so it reads that the answers calibrated the numbers, then reveal the recap.
        // The living field repaints every frame, so a frame counter advances it.
        const create_prepare_len: u32 = 66; // ~1.1s at 60fps
        if (gscreen == feed_view.screen_loadout and gloadout_tab == 2 and gcreate_step == .preparing) {
            gcreate_prepare_frames += 1;
            if (gcreate_prepare_frames >= create_prepare_len) gcreate_step = .recap;
        }
        const create_prepare_t: f32 = @min(@as(f32, @floatFromInt(gcreate_prepare_frames)) / @as(f32, @floatFromInt(create_prepare_len)), 1.0);
        // The bench: the user's library algorithms as socket cards, built into the
        // frame arena (auto-freed). Only on the Loadout tab; empty otherwise.
        var bench_tray: lens_socket.TrayView = .{ .cards = &.{}, .text = "", .seated = 0 };
        if (gscreen == feed_view.screen_loadout and gloadout_tab == 0) {
            if (lens_catalog.benchCards(arena, arena, &algo_lib)) |res| {
                bench_tray = .{ .cards = res[0], .text = res[1], .seated = 0 };
            } else |_| {}
        }
        const pix: ?Grid = if (engine) |*e| .{ .engine = e, .field = &gfield, .particles = &gparticles, .active = &gactive, .draw = &gdraw, .hr = &ghr, .hearts = &ghearts, .view = &gview, .spawn_buf = &gspawn, .last_nanos = &glast_nanos, .zoom = &gzoom, .scroll = &gscroll_px, .content_h = &gcontent_h, .regions = &gregions, .screen = &gscreen, .gpu = if (gpu_state) |*gs| gs else null, .pending_new = feed_core.pendingCount(store), .hover_x = ghover_x, .hover_y = ghover_y, .socket_tray = cur_socket_tray, .socket_ui = cur_socket_ui, .socket_hits = cur_socket_hits, .accent = if (julia_on) lens_socket.julia_pink else (accent_override orelse lens_socket.seatedAccent(home_tray)), .reply_tray = .{ .cards = reply_cards, .text = reply_blob, .seated = reply_seated }, .reply_ui = reply_ui, .reply_hits = &reply_hits, .zone_tray = .{ .cards = zone_cards, .text = zone_blob, .seated = zone_seated }, .zone_ui = zone_ui, .zone_hits = &zone_hits, .loadout_tab = gloadout_tab, .market = if (gscreen == feed_view.screen_loadout and gloadout_tab == 1) market_cards.items else &.{}, .create = .{ .step = gcreate_step, .answers = gcreate_answers, .config = gcreate_config, .name = gcreate_name_buf[0..gcreate_name_len], .color = gcreate_color, .naming = gcreate_step == .name, .prepare_t = create_prepare_t }, .bench = bench_tray, .inspect_bytes = inspect_bytes orelse "", .inspect_name = inspect_name, .inspect_ref = inspect_ref, .inspect_source = gtransp_source, .inspect_loading = inspect_loading, .loadout_geoms = &page_geoms, .zone_title = if (on_zone_screen) zone_tag else "", .zones = if (gscreen == feed_view.screen_zones_browse) zone_catalog.items else &.{}, .settings_section = gsettings_section, .settings_toggles = toggle_bits, .settings_account = settings_account, .settings_choices = settings_choices_packed, .settings_picking = gsettings_picking, .chat_store = if (dev_chat) &gchat_store else null, .chat_sel = gchat_sel, .chat_draft = gchat_draft_buf[0..gchat_draft_len], .chat_input_focus = gchat_input_focus, .chat_composing = gchat_composing, .chat_compose = gchat_peer_buf[0..gchat_peer_len], .chat_compose_status = gchat_compose_status, .chat_typing = gscreen == feed_view.screen_messages and now < gchat_typing_deadline and gchat_sel != null and std.mem.eql(u8, chat_core.conversationDid(&gchat_store, gchat_sel.?), gchat_typing_peer_buf[0..gchat_typing_peer_len]), .chat_key_ns = gchat_key_ns, .field_gain = field_gain, .julia = julia_on, .ripples_on = ripples_on, .field_on = field_on, .crt_on = crt_on, .frametiming_on = frametiming_on } else null;
        switch (mode) {
            .timeline => try paintFrame(gpa, out, arena, &prev, &next, backend, pix, view_items, profile_header, &state, revealed.items, now, session.handle, status),
            .compose => {
                if (pix) |g| switch (backend) {
                    .window => |win| {
                        if (g.gpu) |gs| {
                            // Premium composer on the GPU (the living field behind
                            // the card). Reply is distinguished by a non-empty
                            // target handle; the profile editor reuses the same
                            // surface with its own context line + "Save" label.
                            const ctx: feed_view.ComposeContext = if (compose_kind == .profile)
                                .profile
                            else if (reply_handle.len > 0) .reply else .post;
                            paintComposeGpu(gpa, win, g, gs, ctx, reply_handle, textedit.view(&compose), compose.caret, textedit.selStart(&compose), textedit.selEnd(&compose), composeBlinkOn(caret_anchor_ns), status) catch {};
                        } else {
                            // Software fallback: the glyph-field cell composer.
                            const cell = cellSize(win.fb.width, gzoom);
                            const fgrid = softFieldGrid(win.fb.width, win.fb.height, cell.w, cell.h);
                            const cols = fgrid.cols;
                            const rows = fgrid.rows;
                            if (gfield.cols != cols or gfield.rows != rows) {
                                field_core.deinit(gpa, &gfield);
                                try field_core.init(gpa, &gfield, cols, rows);
                            }
                            const cc = timeline_ui.countCodepoints(textedit.view(&compose));
                            // Software fallback keeps an end-of-text cursor (the
                            // GPU path owns the caret-aware bar); the model still
                            // edits at the caret either way.
                            const cursor = field_ui.buildCompose(&gfield, textedit.view(&compose), reply_handle, cc, status);
                            try field_core.compose(gpa, &gfield, gparticles.slice(), .{ .x = @floatFromInt(cols / 2), .y = @floatFromInt(rows / 3), .radius = @floatFromInt(cols), .ambient = 0.7 }, cell.w, cell.h, &gdraw);
                            // The cursor: a filled block at the insertion cell,
                            // tinted with the app accent (alpha-blended).
                            try gdraw.append(gpa, .{ .rect = .{ .x = @intCast(@min(cursor.x * cell.w, 32767)), .y = @intCast(@min(cursor.y * cell.h, 32767)), .w = cell.w, .h = cell.h, .color = 0x88000000 | (field_core.palette[field_ui.col_accent] & 0x00FFFFFF), .radius = 0 } });
                            window_shell.presentDrawList(win, gpa, g.engine, gdraw.slice(), field_core.background) catch {};
                        }
                    },
                    .terminal => {
                        timeline_ui.buildComposeFrame(&next, textedit.view(&compose), reply_handle, status);
                        try present(gpa, out, arena, &prev, &next, backend);
                    },
                } else {
                    timeline_ui.buildComposeFrame(&next, textedit.view(&compose), reply_handle, status);
                    try present(gpa, out, arena, &prev, &next, backend);
                }
            },
            .profile => {
                if (pix) |g| switch (backend) {
                    .window => |win| {
                        const cell = cellSize(win.fb.width, gzoom);
                        const fgrid = softFieldGrid(win.fb.width, win.fb.height, cell.w, cell.h);
                        const cols = fgrid.cols;
                        const rows = fgrid.rows;
                        if (gfield.cols != cols or gfield.rows != rows) {
                            field_core.deinit(gpa, &gfield);
                            try field_core.init(gpa, &gfield, cols, rows);
                        }
                        field_ui.buildProfile(&gfield, profile_info orelse .{}, status);
                        try field_core.compose(gpa, &gfield, gparticles.slice(), .{ .x = @floatFromInt(cols / 2), .y = @floatFromInt(rows / 3), .radius = @floatFromInt(cols), .ambient = 0.7 }, cell.w, cell.h, &gdraw);
                        window_shell.presentDrawList(win, gpa, g.engine, gdraw.slice(), field_core.background) catch {};
                    },
                    .terminal => {
                        timeline_ui.buildProfileFrame(&next, profile_info orelse .{}, status);
                        try present(gpa, out, arena, &prev, &next, backend);
                    },
                } else {
                    timeline_ui.buildProfileFrame(&next, profile_info orelse .{}, status);
                    try present(gpa, out, arena, &prev, &next, backend);
                }
            },
        }

        // 0ms posting: a queued send was shown optimistically and PAINTED above
        // this frame; perform the actual create write now, then reconcile the
        // temp cid to the server's (keep the post) or drop it on failure. The
        // write blocks briefly, but the post is already on screen — it FELT
        // instant. Network failure is contained (E2); only OOM is fatal.
        if (pending_send) |job| {
            pending_send = null;
            defer freeSendJob(gpa, job);
            const facets = write.resolveFacets(arena, io, environ, session, job.text) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => &[_]lexicon.Facet{}, // post without facets rather than fail
            };
            const posted = write.createPost(gpa, arena, io, environ, session, job.text, facets, job.target, now) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => blk: {
                    feed_core.dropOptimisticPost(store, job.temp_cid);
                    status = "send failed";
                    break :blk null;
                },
            };
            if (posted) |result| switch (result) {
                .ok => |ref| feed_core.reconcileOptimisticPost(gpa, store, job.temp_cid, ref.cid, ref.uri) catch {},
                .failed => |f| {
                    feed_core.dropOptimisticPost(store, job.temp_cid);
                    status = std.fmt.bufPrint(&status_buf, "send refused: {d} {s}", .{ f.status, f.code }) catch "refused";
                },
            };
        }

        // 0ms profile-name save: the name is already shown optimistically (and
        // guarded); run the putProfile write now, reverting the guard on failure
        // so the next refresh restores the server name. On success the guard
        // releases when the AppView re-polls + serves the new name.
        if (pending_profile_save) |name| {
            pending_profile_save = null;
            defer gpa.free(name);
            const saved = write.putProfile(gpa, arena, io, environ, session, name, now) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => blk: {
                    feed_core.clearPendingDisplay(store);
                    status = "name save failed";
                    break :blk null;
                },
            };
            if (saved) |s| switch (s) {
                .ok => {},
                .failed => |f| {
                    feed_core.clearPendingDisplay(store);
                    status = std.fmt.bufPrint(&status_buf, "name refused: {d} {s}", .{ f.status, f.code }) catch "refused";
                },
            };
        }

        // Wait for input; the timeout re-renders so relative ages stay
        // honest on an idle screen. 500 ms: the mailbox drains and
        // relative ages tick at human latency; two wakeups a second is
        // beneath measurement (G3).
        var in_buf: [256]u8 = undefined;
        var n: usize = 0;
        switch (backend) {
            // On Windows the terminal backend returns NotATerminal at
            // startup (console raw mode is the recorded follow-up), so
            // this arm comptime-vanishes there — this std snapshot's
            // posix.pollfd does not even resolve on that target.
            .terminal => if (comptime builtin.os.tag == .windows) unreachable else {
                var fds = [_]posix.pollfd{.{ .fd = stdin_fd, .events = posix.POLL.IN, .revents = 0 }};
                const ready = posix.poll(&fds, 500) catch 0;
                if (ready == 0) continue;
                n = posix.read(stdin_fd, &in_buf) catch 0;
                if (n == 0) continue;
                last_input_nanos = clock_shell.monotonicNanos();
            },
            .window => |win| {
                // The pump translates X keys into the same bytes a tty
                // would deliver; close/resize fold into the loop's own
                // re-render lap (E2: a window hiccup is not a crash).
                var pumped_bytes: std.ArrayList(u8) = .empty;
                defer pumped_bytes.deinit(gpa);
                // Cut 5.1: the pointer channel arrives but is not yet
                // consumed — hit-testing lands in 5.2 (GUI roadmap §7).
                // Drained per lap so a motion flood never accumulates.
                var pointer_events: std.ArrayList(layout_core.InputEvent) = .empty;
                defer pointer_events.deinit(gpa);
                // The field animates only while it has live work — a
                // playing effect or particles in flight. When it does,
                // pump at frame cadence (~16 ms) so the loop ticks the
                // simulation forward each lap; when the screen is static,
                // block the full idle interval so a still timeline costs
                // ZERO CPU (the project's no-wasted-cycles ethos, and the
                // laptop's battery). The next lap's paintFrame is what
                // advances the sim — a short pump returning no input still
                // yields one animation frame.
                // The GPU field is ALIVE AT REST (ambient forcing drives it), so
                // when the GPU path is live we always pump at frame cadence to
                // keep the simulation ticking; otherwise only when a software
                // effect/particles are in flight, so a still timeline costs zero
                // CPU (the no-wasted-cycles ethos).
                const animating = gpu_state != null or (engine != null and (gactive.len > 0 or gparticles.len > 0));
                const pump_ms: i32 = if (animating) 16 else 500;
                const pumped = window_shell.pump(win, pump_ms, gpa, &pumped_bytes, &pointer_events) catch {
                    status = "window error";
                    continue;
                };
                if (pumped.closed) break :main_loop;
                if (pumped.dropped > 0) status = "input dropped (low memory)";
                if (pumped.x_error != 0) {
                    // The server refused a request (almost always a blit).
                    // Show the code so a black window names its own cause
                    // instead of staying mute. Codes: 1=Request 2=Value
                    // 3=Window 4=Pixmap 8=Match 9=Drawable 13=GContext
                    // 16=Length. (E3: no silent failure.)
                    status = std.fmt.bufPrint(&status_buf, "X error code {d}", .{pumped.x_error}) catch "X error";
                }
                // The window's FIRST valid drawable arrives with Expose, not
                // with map: a PutImage sent before the server has exposed the
                // window is discarded, which is exactly the "window opens
                // black and never paints" failure. The pump reports Expose
                // (and geometry changes) precisely so the loop can paint the
                // moment the surface becomes valid — honor it by re-presenting
                // the current frame at once instead of idling 500 ms with a
                // blit the server already threw away. (E2: a repaint request
                // is folded into the loop's own re-render lap.)
                if (pumped.exposed or pumped.resized) {
                    if (mode == .timeline) {
                        try paintFrame(gpa, out, arena, &prev, &next, backend, pix, view_items, profile_header, &state, revealed.items, now, session.handle, status);
                    } else {
                        try present(gpa, out, arena, &prev, &next, backend);
                    }
                }
                // ---- the mouse becomes the app (5.2): consume the channel.
                // Wheel scrolls the pixel viewport; motion drives hover;
                // a click selects its card, and an action zone injects the
                // SAME byte the bound key sends, so the dispatch below is
                // the one and only path (timeline_ui.keyFor — round-trip
                // tested against actionFor). Hit rects are last frame's:
                // immediate-mode's standard one-frame contract.
                if (mode == .timeline) if (pix) |g| {
                    // Pointer coords are PIXELS; the grid thinks in cells.
                    // Use the SAME zoom-derived cell size the renderer
                    // used, so clicks land on the cell under the cursor at
                    // any zoom. Convert once, then everything is cell-space.
                    const pcell = cellSize(win.fb.width, g.zoom.*);
                    // The GPU feed lays out in LOGICAL pixels (design_w, scaled
                    // to fill); the software feed in physical pixels. So the
                    // region hit-test and the scroll clamp work in whichever
                    // space the layout used — map the physical pointer back to
                    // logical for GPU (÷scale), pass it through for software.
                    const gpu_scale: f32 = if (g.gpu) |gs| gs.scale else 1.0;
                    for (pointer_events.items) |pev| {
                        const cx: u16 = pev.x / pcell.w;
                        const cy: u16 = pev.y / pcell.h;
                        const rx: i32 = if (g.gpu != null) @intFromFloat(@as(f32, @floatFromInt(pev.x)) / gpu_scale) else @intCast(pev.x);
                        const ry: i32 = if (g.gpu != null) @intFromFloat(@as(f32, @floatFromInt(pev.y)) / gpu_scale) else @intCast(pev.y);
                        switch (pev.kind) {
                            .wheel => {
                                if (g.gpu) |gs| gs.menu_open = false; // scrolling dismisses the menu
                                const delta: i32 = if (pev.button == 5) 3 else -3;
                                g.view.scroll_rows += delta;
                                // The premium feed scrolls in PIXELS. Wheel down
                                // (button 5) moves content up, so the offset goes
                                // more negative; clamp so you cannot scroll past
                                // the ends (top = 0, bottom exposes the last post
                                // + a little breathing room). content_h is in the
                                // layout's space, so the viewport height matches.
                                if (dev_chat and g.screen.* == feed_view.screen_messages) {
                                    // The chat thread is BOTTOM-anchored: wheel UP walks
                                    // back into history. The shared clamp keeps scroll in
                                    // [min_scroll, 0]; the dispatch passes -scroll to
                                    // layoutChat as its positive history offset.
                                    g.scroll.* += delta * 28;
                                } else {
                                    g.scroll.* -= delta * 28;
                                }
                                const view_h: i32 = if (g.gpu != null)
                                    @intFromFloat(@as(f32, @floatFromInt(win.fb.height)) / gpu_scale)
                                else
                                    @intCast(win.fb.height);
                                const min_scroll: i32 = @min(0, view_h - g.content_h.* - 24);
                                g.scroll.* = @max(min_scroll, @min(0, g.scroll.*));
                                effect_core.shiftY(g.active, -delta);
                                // Pull-to-refresh: a wheel-up (button 4 → delta < 0)
                                // that lands while already pinned at the top of Home
                                // builds overscroll; past the threshold it asks for a
                                // refresh. A wheel-down cancels the pull.
                                if (g.screen.* == feed_view.screen_home and pev.button != 5 and g.scroll.* == 0) {
                                    overscroll_accum += 28;
                                    if (overscroll_accum >= pull_refresh_threshold) {
                                        pull_refresh_requested = true;
                                        overscroll_accum = 0;
                                    } else {
                                        // Visible proof the pull is registering (the
                                        // animated indicator is the deferred polish).
                                        status = "↑ keep pulling to refresh";
                                    }
                                } else if (pev.button == 5) {
                                    overscroll_accum = 0;
                                }
                            },
                            .move => {
                                // Track the pointer in LOGICAL coords for the hover
                                // highlight (rx/ry are already mapped through scale).
                                ghover_x = rx;
                                ghover_y = ry;
                                // A live drag: the ghost card follows the pointer. On the
                                // loadout page the dragged surface may be reply/zone.
                                if (page_drag_surface) |s| {
                                    const ui = switch (s) {
                                        1 => &reply_ui,
                                        2 => &zone_ui,
                                        else => &gsocket_ui,
                                    };
                                    ui.drag_x = rx;
                                    ui.drag_y = ry;
                                } else if (gsocket_ui.drag_active != null) {
                                    gsocket_ui.drag_x = rx;
                                    gsocket_ui.drag_y = ry;
                                }
                                const field_hit = field_ui.hitTest(cx, cy, g.hr.slice());
                                g.view.hover = if (field_hit) |hit| hit.target else field_ui.no_target;
                                // Pointer affordance: the hand cursor over anything
                                // clickable, the arrow otherwise. The SAME hit-tests
                                // the click path below consults — feed regions, the
                                // lens socket, on the Algorithms page the reply/zone
                                // sockets too, and the legacy cell rects — so the
                                // cursor and the click always agree on what is tappable.
                                const over_clickable =
                                    feed_view.hitTest(g.regions.items, rx, ry) != null or
                                    lens_socket.hitTest(g.socket_hits.items, rx, ry) != null or
                                    (gscreen == feed_view.screen_loadout and
                                        (lens_socket.hitTest(reply_hits.items, rx, ry) != null or
                                            lens_socket.hitTest(zone_hits.items, rx, ry) != null)) or
                                    field_hit != null;
                                // A live text-selection drag over the rooted post:
                                // extend the selection to the caret under the pointer.
                                if (g.gpu) |gs| if (gs.sel_dragging) {
                                    gs.sel_focus = text_select.caretAtPoint(gs.sel_glyphs.items, rx, ry);
                                };
                                // Cursor shape, by priority: grab while dragging a lens
                                // card; the I-beam over the rooted post's selectable body
                                // (or mid text-drag); the hand over anything else
                                // clickable; the arrow otherwise.
                                const dragging_card = page_drag_surface != null or gsocket_ui.drag_active != null;
                                const over_focus_text = gscreen == feed_view.screen_thread and blk: {
                                    const h = feed_view.hitTest(g.regions.items, rx, ry) orelse break :blk false;
                                    break :blk h.kind == .post_body and h.post < view_items.len and view_items[h.post].is_focus;
                                };
                                const sel_dragging = if (g.gpu) |gs| gs.sel_dragging else false;
                                window_shell.setCursor(win, if (dragging_card)
                                    .grab
                                else if (over_focus_text or sel_dragging)
                                    .text
                                else if (over_clickable)
                                    .pointer
                                else
                                    .default);
                                // GPU: the cursor lights the field (drawFieldGrid
                                // halo) and leaves a gentle colourless wake.
                                if (g.gpu) |gs| {
                                    gs.mcx = @as(f32, @floatFromInt(pev.x)) / @as(f32, @floatFromInt(field_cell_w));
                                    gs.mcy = @as(f32, @floatFromInt(pev.y)) / @as(f32, @floatFromInt(field_cell_h));
                                    if (gs.cols > 0 and gs.rows > 0) {
                                        const sx: u32 = @min(@as(u32, @intFromFloat(@max(0.0, gs.mcx))), gs.cols - 1);
                                        const sy: u32 = @min(@as(u32, @intFromFloat(@max(0.0, gs.mcy))), gs.rows - 1);
                                        // hover wake: a gentle, colourless ripple at the pointer.
                                        gs.splashes.append(gpa, .{ .x = sx, .y = sy, .radius = 3, .amp = 0.4 }) catch {};
                                    }
                                }
                            },
                            .button_down => {
                                // Right-click → the context menu over the rooted
                                // post body. Left-click while the menu is open hits
                                // an item or dismisses it (never the feed beneath).
                                if (pev.button == 3) {
                                    if (g.gpu) |gs| openContextMenu(gs, gscreen, view_items, g.regions.items, rx, ry);
                                } else if (pev.button == 1) {
                                    if (g.gpu) |gs| if (gs.menu_open) {
                                        menuClick(gpa, gs, backend, rx, ry);
                                        continue;
                                    };
                                // Premium buttons are hit-tested against the
                                // regions the feed emitted this frame. A like/
                                // repost tap blooms the burst right at the icon:
                                // on the GPU it stamps the living field (a real
                                // dye splash); on the software path it triggers
                                // the legacy burst effect. (Persisting a MOUSE
                                // tap is still the deferred slice; the keyboard
                                // like persists and bursts via fireEngageEffect.)
                                // If nothing premium is hit, fall through to the
                                // legacy cell hit rects.
                                //
                                // THE LENS SOCKET is tested FIRST — it sits in the
                                // sticky header, on top of the feed (its hits live
                                // in their own space). Seating re-tints + animates
                                // the swap; re-ranking the feed awaits the discover
                                // engine (only Following exists today).
                                var socket_handled = false;
                                if (gscreen == feed_view.screen_loadout) {
                                    // Loadout page: edit the surface under the cursor (feed /
                                    // reply / zone). A handle press (.reorder) starts a drag for
                                    // that surface; everything else is a click edit.
                                    if (lens_socket.hitTest(g.socket_hits.items, rx, ry)) |sact| {
                                        switch (sact) {
                                            .reorder => |r| {
                                                page_drag_surface = 0;
                                                gsocket_ui.drag_active = trayIndexOfCid(socket_cards, socket_blob, r.lens);
                                                gsocket_ui.drag_x = rx;
                                                gsocket_ui.drag_y = ry;
                                            },
                                            else => applyLoadoutAction(sact, socket_cards, socket_blob, &gseated, &gsocket_ui, &loadout_dirty),
                                        }
                                        socket_handled = true;
                                    } else if (lens_socket.hitTest(reply_hits.items, rx, ry)) |sact| {
                                        switch (sact) {
                                            .reorder => |r| {
                                                page_drag_surface = 1;
                                                reply_ui.drag_active = trayIndexOfCid(reply_cards, reply_blob, r.lens);
                                                reply_ui.drag_x = rx;
                                                reply_ui.drag_y = ry;
                                            },
                                            else => applyLoadoutAction(sact, reply_cards, reply_blob, &reply_seated, &reply_ui, &loadout_dirty),
                                        }
                                        socket_handled = true;
                                    } else if (lens_socket.hitTest(zone_hits.items, rx, ry)) |sact| {
                                        switch (sact) {
                                            .reorder => |r| {
                                                page_drag_surface = 2;
                                                zone_ui.drag_active = trayIndexOfCid(zone_cards, zone_blob, r.lens);
                                                zone_ui.drag_x = rx;
                                                zone_ui.drag_y = ry;
                                            },
                                            else => applyLoadoutAction(sact, zone_cards, zone_blob, &zone_seated, &zone_ui, &loadout_dirty),
                                        }
                                        socket_handled = true;
                                    }
                                } else if (gscreen == feed_view.screen_thread) {
                                    // The inline REPLY socket on a thread: a switcher over the
                                    // reply loadout (shared with the Algorithms page). Order-only,
                                    // no view retint. Reorder lives on the Algorithms page.
                                    if (lens_socket.hitTest(g.socket_hits.items, rx, ry)) |sact| {
                                        socket_handled = true;
                                        switch (sact) {
                                            .toggle_tray => reply_ui.open = !reply_ui.open,
                                            .seat => |cid| {
                                                if (trayIndexOfCid(reply_cards, reply_blob, cid)) |idx| {
                                                    reply_seated = idx;
                                                    loadout_dirty = true;
                                                }
                                                reply_ui.open = false;
                                                reply_ui.expanded = null;
                                                reply_ui.picking = null;
                                            },
                                            .get_more => {
                                                reply_ui.open = false;
                                                gscreen = feed_view.screen_loadout;
                                                gscroll_px = 0;
                                            },
                                            else => applyLoadoutAction(sact, reply_cards, reply_blob, &reply_seated, &reply_ui, &loadout_dirty),
                                        }
                                    }
                                } else if (gscreen == feed_view.screen_zones) {
                                    // The zone page's socket: a switcher over the ZONE
                                    // loadout (shared with the Algorithms page). Order-only;
                                    // no real ranking power yet (the discover engine is
                                    // unbuilt). Reorder lives on the Algorithms page.
                                    if (lens_socket.hitTest(g.socket_hits.items, rx, ry)) |sact| {
                                        socket_handled = true;
                                        switch (sact) {
                                            .toggle_tray => zone_ui.open = !zone_ui.open,
                                            .seat => |cid| {
                                                if (trayIndexOfCid(zone_cards, zone_blob, cid)) |idx| {
                                                    zone_seated = idx;
                                                    loadout_dirty = true;
                                                }
                                                zone_ui.open = false;
                                                zone_ui.expanded = null;
                                                zone_ui.picking = null;
                                            },
                                            .get_more => {
                                                zone_ui.open = false;
                                                gscreen = feed_view.screen_loadout;
                                                gscroll_px = 0;
                                            },
                                            else => applyLoadoutAction(sact, zone_cards, zone_blob, &zone_seated, &zone_ui, &loadout_dirty),
                                        }
                                    }
                                } else if (lens_socket.hitTest(g.socket_hits.items, rx, ry)) |sact| {
                                    socket_handled = true;
                                    // Any socket action other than opening/using the picker
                                    // closes it (the open/set arms re-open or keep as needed).
                                    switch (sact) {
                                        .open_swatch, .set_color => {},
                                        else => gsocket_ui.picking = null,
                                    }
                                    switch (sact) {
                                        .toggle_tray => gsocket_ui.open = !gsocket_ui.open,
                                        .seat => |cid| {
                                            if (trayIndexOfCid(socket_cards, socket_blob, cid)) |ni| {
                                                if (ni != gseated) {
                                                    gsocket_ui.swap_from = gseated;
                                                    gsocket_ui.swap_to = ni;
                                                    gsocket_ui.swap_phase = 1;
                                                    gseated = ni;
                                                    // Seat = re-rank now, scroll to top (owner decision
                                                    // 2026-06-22). The visible gesture today; the actual
                                                    // lens re-ordering is the discover-engine track —
                                                    // THIS is the seam it plugs into (re-rank the feed by
                                                    // the seated lens here, then reset scroll).
                                                    gscroll_px = 0;
                                                }
                                            }
                                            gsocket_ui.expanded = null;
                                            gsocket_ui.open = false; // watch it plug in, then the tray retracts
                                            loadout_dirty = true;
                                        },
                                        // ⓘ → expand inline detail; tapping the open one collapses it.
                                        .expand => |cid| {
                                            if (trayIndexOfCid(socket_cards, socket_blob, cid)) |idx| {
                                                gsocket_ui.expanded = if (gsocket_ui.expanded == idx) null else idx;
                                            }
                                        },
                                        .collapse => gsocket_ui.expanded = null,
                                        // Press on a drag handle → start dragging that lens (the
                                        // seated one has no handle, §7.3). The ghost follows the
                                        // pointer; the drop lands on button_up.
                                        .reorder => |r| {
                                            gsocket_ui.picking = null;
                                            gsocket_ui.drag_active = trayIndexOfCid(socket_cards, socket_blob, r.lens);
                                            gsocket_ui.drag_x = rx;
                                            gsocket_ui.drag_y = ry;
                                        },
                                        // Tap a card's swatch → open/close its color picker (§11.5).
                                        .open_swatch => |cid| {
                                            const idx = trayIndexOfCid(socket_cards, socket_blob, cid);
                                            gsocket_ui.picking = if (gsocket_ui.picking == idx) null else idx;
                                        },
                                        // Pick a color → recolor that lens (totally the user's
                                        // call; duplicates allowed). If it's the seated lens, the
                                        // whole-UI accent follows next frame (seatedAccent).
                                        .set_color => |sc2| {
                                            if (trayIndexOfCid(socket_cards, socket_blob, sc2.lens)) |idx| {
                                                if (idx < socket_cards.len) socket_cards[idx].color = sc2.color;
                                                loadout_dirty = true;
                                            }
                                            gsocket_ui.picking = null;
                                        },
                                        // "get more" → the Algorithms (loadout) page.
                                        .get_more => {
                                            gsocket_ui.picking = null;
                                            gsocket_ui.open = false;
                                            gscreen = feed_view.screen_loadout;
                                        },
                                    }
                                }
                                if (!socket_handled) {
                                    // Release-activation: ARM the tap (don't fire). It
                                    // fires on button_up only if the release lands on
                                    // the same target — press-then-slide-off cancels.
                                    if (feed_view.hitTest(g.regions.items, rx, ry)) |hit| {
                                        gsocket_ui.picking = null; // a click off the socket closes the picker
                                        // The ROOTED post's body is selectable, not a
                                        // re-root target: a press there places the caret
                                        // and begins a text selection (web-style — a
                                        // release without a drag clears it). Don't arm a tap.
                                        const is_focus_body = gscreen == feed_view.screen_thread and hit.kind == .post_body and
                                            hit.post < view_items.len and view_items[hit.post].is_focus;
                                        if (is_focus_body) {
                                            if (g.gpu) |gs| selectPress(gs, rx, ry, &last_click_ns, &last_click_x, &last_click_y, &click_count, clock_shell.monotonicNanos());
                                        } else {
                                            armed_kind = hit.kind;
                                            armed_post = hit.post;
                                        }
                                    } else if (field_ui.hitTest(cx, cy, g.hr.slice())) |_| {
                                        armed_legacy = true;
                                        armed_cx = cx;
                                        armed_cy = cy;
                                    }
                                }
                                }
                            },
                            // Release-activation: the armed tap fires here (see the
                            // button_down arm). Placed after the drag-drop handling so
                            // a drag never also triggers a tap.
                            .button_up => if (pev.button == 1) {
                                // End a text-selection drag (the selection itself
                                // persists until the next press; a no-drag press left
                                // anchor==focus, i.e. an empty selection = cleared).
                                if (g.gpu) |gs| gs.sel_dragging = false;
                                // Finish any drag with a drop first (the press began it).
                                if (gscreen == feed_view.screen_loadout) {
                                    if (page_drag_surface) |s| switch (s) {
                                        0 => pageDragDrop(socket_cards, socket_blob, &gseated, &gsocket_ui, page_geoms[0], &loadout_dirty),
                                        1 => pageDragDrop(reply_cards, reply_blob, &reply_seated, &reply_ui, page_geoms[1], &loadout_dirty),
                                        else => pageDragDrop(zone_cards, zone_blob, &zone_seated, &zone_ui, page_geoms[2], &loadout_dirty),
                                    };
                                } else if (gsocket_ui.drag_active) |d| {
                                    const geom = feed_view.homeSocketGeom(if (gpu_state != null) @as(i32, @intCast(design_w)) else @as(i32, @intCast(win.fb.width)));
                                    const to: u32 = lens_socket.dropIndex(home_tray, gsocket_ui, geom) orelse d;
                                    const seated_off = if (gseated < socket_cards.len) socket_cards[gseated].cid.off else 0;
                                    reorderTray(socket_cards, d, to);
                                    for (socket_cards, 0..) |c, ix| {
                                        if (c.cid.off == seated_off) {
                                            gseated = @intCast(ix);
                                            break;
                                        }
                                    }
                                    gsocket_ui.drag_active = to; // the card now lives at `to`
                                    gsocket_ui.settle_phase = 1; // ghost eases from release point into its slot
                                    loadout_dirty = true;
                                }
                                // Release-activation: fire the armed feed tap ONLY if the
                                // release lands on the same target the press armed. A press
                                // that began a drag never armed a tap, so a drag never also
                                // fires one.
                                if (armed_kind) |ak| {
                                    if (feed_view.hitTest(g.regions.items, rx, ry)) |hit| {
                                        if (hit.kind == ak and hit.post == armed_post) {
                                            switch (hit.kind) {
                                        // Left-rail destination: switch the active screen
                                        // (post carries the Screen index). Selecting Profile
                                        // targets YOUR own profile; the next frame re-renders.
                                        .nav => {
                                            gscreen = @intCast(hit.post);
                                            if (gscreen == feed_view.screen_profile) {
                                                profile_target_did = session.did;
                                                profile_dirty = true;
                                            }
                                            // Each screen starts at the top (scroll is shared).
                                            gscroll_px = 0;
                                        },
                                        // Avatar tap → open THAT author's profile (any author;
                                        // the DID comes from the post's at-uri). A query over
                                        // the shared store — same engagement/identity truth.
                                        .author => if (hit.post < view_items.len) {
                                            const did = authorDidFromUri(view_items[hit.post].uri);
                                            if (did.len > 0 and did.len <= profile_target_buf.len) {
                                                @memcpy(profile_target_buf[0..did.len], did);
                                                profile_target_did = profile_target_buf[0..did.len];
                                                gscreen = feed_view.screen_profile;
                                                profile_dirty = true;
                                            }
                                        },
                                        // New-post button → the composer (cell path for now).
                                        .compose => {
                                            compose_kind = .post;
                                            mode = .compose;
                                        },
                                        // "Edit profile" → reuse the composer to set your
                                        // display name; prefill the current one (when it's a
                                        // real name, not the handle fallback). Saved via
                                        // putProfile on send (handleComposeInput).
                                        .edit_profile => {
                                            compose_kind = .profile;
                                            textedit.clear(&compose);
                                            if (profile_header) |ph| {
                                                const bare = if (ph.handle.len > 1) ph.handle[1..] else "";
                                                if (ph.display_name.len > 0 and !std.mem.eql(u8, ph.display_name, bare))
                                                    textedit.set(&compose, ph.display_name);
                                            }
                                            mode = .compose;
                                            status = "edit display name · Enter saves";
                                        },
                                        // Like / boost: the SAME path the keyboard uses —
                                        // optimistic toggle (heart fills red), persist via
                                        // the worker, and fire the splash + heart-pop.
                                        // Works in ANY view: engageSelected is CID-keyed on
                                        // the one shared store, so a like from the profile
                                        // updates the same record Home shows (ZONES inv. 4).
                                        .like, .repost => if (hit.post < view_items.len) {
                                            state.selected = hit.post;
                                            const ek: Engagement = if (hit.kind == .like) .like else .repost;
                                            const r = try engageSelected(ek, gpa, arena, session, store, view_items[hit.post], hit.post, gscreen, profile_target_did, thread_focus_cid, zone_tag, thread_rerooted, gcollapsed.items, feed_config, reply_config, &state, revealed.items, now, out, &prev, &next, backend, pix, writer, &deferred_unlike, &deferred_unrepost);
                                            if (r.status.len > 0) status = r.status;
                                        },
                                        // Reply → open the premium composer in reply
                                        // mode for the TAPPED post (C2). Same sequence
                                        // the cell-path keyboard reply proved: resolve
                                        // the root/parent refs, copy them out of the
                                        // store (the composer outlives this frame), set
                                        // the target + handle, open compose.
                                        .reply => if (hit.post < view_items.len) {
                                            const item = view_items[hit.post];
                                            if (feed_core.replyRefsForCid(store, item.cid)) |refs| {
                                                _ = compose_arena_state.reset(.retain_capacity);
                                                const compose_arena = compose_arena_state.allocator();
                                                reply_target = .{
                                                    .root_uri = try compose_arena.dupe(u8, refs.root_uri),
                                                    .root_cid = try compose_arena.dupe(u8, refs.root_cid),
                                                    .parent_uri = try compose_arena.dupe(u8, refs.parent_uri),
                                                    .parent_cid = try compose_arena.dupe(u8, refs.parent_cid),
                                                };
                                                reply_handle = try compose_arena.dupe(u8, item.author_handle);
                                                compose_kind = .post;
                                                textedit.clear(&compose);
                                                status = "";
                                                mode = .compose;
                                            }
                                        },
                                        // Post body tap → open this post's THREAD
                                        // (whole post minus the avatar/engagement
                                        // carve-outs). Remember the focus cid (for
                                        // the buildThreadView query) + the uri (for
                                        // the getPostThread fetch) and where Back
                                        // returns. Copy them out — the view list is
                                        // rebuilt next frame.
                                        .post_body => if (hit.post < view_items.len) {
                                            const item = view_items[hit.post];
                                            if (item.cid.len > 0 and item.cid.len <= thread_focus_cid_buf.len and item.uri.len <= thread_focus_uri_buf.len) {
                                                @memcpy(thread_focus_cid_buf[0..item.cid.len], item.cid);
                                                thread_focus_cid = thread_focus_cid_buf[0..item.cid.len];
                                                @memcpy(thread_focus_uri_buf[0..item.uri.len], item.uri);
                                                thread_focus_uri = thread_focus_uri_buf[0..item.uri.len];
                                                const was_in_thread = gscreen == feed_view.screen_thread;
                                                if (!was_in_thread) thread_return_screen = gscreen;
                                                gscreen = feed_view.screen_thread;
                                                thread_dirty = true;
                                                // First tap from the timeline = WHOLE thread; a tap
                                                // INSIDE the thread = RE-ROOT (condensed ancestors
                                                // above the focus). EITHER way, land ON the tapped
                                                // post (it's the new root) — ancestors sit above,
                                                // scrollable up — so a deep-chain tap doesn't dump
                                                // you at the top to scroll back down.
                                                thread_rerooted = was_in_thread;
                                                g.scroll.* = 0;
                                                if (g.gpu) |gs| {
                                                    gs.scroll_to_focus = true;
                                                    // The rooted post (and so the
                                                    // selectable body) changed — drop any
                                                    // stale selection.
                                                    gs.sel_anchor = 0;
                                                    gs.sel_focus = 0;
                                                    gs.sel_dragging = false;
                                                }
                                            }
                                        },
                                        // Back (thread top bar) → the prior screen.
                                        .back => {
                                            // The transparency page, zone page, and thread
                                            // share Back; each returns where it was entered.
                                            if (gscreen == feed_view.screen_transparency) {
                                                if (gtransp_source) {
                                                    // On the source sub-view → back to the summary.
                                                    gtransp_source = false;
                                                } else {
                                                    gscreen = transp_return_screen;
                                                    if (inspect_bytes) |b| gpa.free(b);
                                                    inspect_bytes = null;
                                                }
                                            } else {
                                                gscreen = if (gscreen == feed_view.screen_zones) zone_return_screen else thread_return_screen;
                                            }
                                            g.scroll.* = 0;
                                        },
                                        // "N new posts" pill → reveal the staged
                                        // posts + jump to the top (the reader opted
                                        // in, so displacing them now is wanted).
                                        .reveal_new => {
                                            _ = feed_core.revealPending(gpa, store) catch 0;
                                            g.scroll.* = 0;
                                            gview.scroll_rows = 0;
                                            state.selected = 0;
                                            status = "";
                                        },
                                        // The composer's footer buttons never appear
                                        // on the timeline; they are handled in compose
                                        // mode below.
                                        .compose_send, .compose_cancel => {},
                                        // Not wired yet — drawn for the fuller row /
                                        // profile tabs; their regions exist so hover
                                        // can highlight them and a later slice wires
                                        // them. A tap is a no-op for now.
                                        // Algorithms-page sub-tab (Loadout / Marketplace / Create).
                                        .loadout_tab => {
                                            gloadout_tab = @intCast(hit.post);
                                            if (hit.post == 2) gcreate_step = .landing; // Create opens on its landing page
                                            gscroll_px = 0; // top of the newly-selected tab
                                        },
                                        // ---- The simple-Create flow (loadout tab 2) ----
                                        // Pick a question option → record the answer, rebuild
                                        // the config from the answers, and advance a step
                                        // (privacy → the recap).
                                        .create_pick => {
                                            create_flow.applyAnswer(&gcreate_answers, gcreate_step, hit.post);
                                            gcreate_config = builder.build(gcreate_answers);
                                            gcreate_step = create_flow.nextStep(gcreate_step);
                                            if (gcreate_step == .preparing) gcreate_prepare_frames = 0; // start the beat
                                            gscroll_px = 0;
                                        },
                                        .create_back => {
                                            gcreate_step = create_flow.prevStep(gcreate_step);
                                            if (gcreate_step == .preparing) gcreate_step = .privacy; // skip the beat going back
                                            gscroll_px = 0;
                                        },
                                        .create_next => { // landing → questions, recap → name
                                            gcreate_step = create_flow.nextStep(gcreate_step);
                                            gscroll_px = 0;
                                        },
                                        .create_dev => status = "Developer submission is coming soon — write it in Zal and publish.",
                                        .create_knob_dec, .create_knob_inc => {
                                            const k: create_flow.Knob = @enumFromInt(@as(u8, @intCast(hit.post)));
                                            const step = create_flow.knobMeta(k).step;
                                            const cur = create_flow.knobValue(gcreate_config, k);
                                            create_flow.knobSet(&gcreate_config, k, if (hit.kind == .create_knob_inc) cur + step else cur - step);
                                        },
                                        .create_color => gcreate_color = @intCast(hit.post),
                                        // Finalize: serialize the config into a PRIVATE library
                                        // record (a minted local id), reset the flow, and drop
                                        // the user back on their loadout with it saved.
                                        .create_save => {
                                            var idbuf: [24]u8 = undefined;
                                            const id = std.fmt.bufPrint(&idbuf, "user:{d}", .{algo_uid}) catch "user:x";
                                            const nm = if (gcreate_name_len > 0) gcreate_name_buf[0..gcreate_name_len] else "My feed";
                                            if (create_flow.finalize(arena, gcreate_config, id, nm, gcreate_color)) |new| {
                                                if (algo_lib.add(gpa, new)) |_| {
                                                    algo_uid += 1;
                                                    _ = cache_shell.saveLibrary(gpa, environ, &algo_lib); // persist across launches
                                                    status = "Saved to your library.";
                                                    gcreate_step = .pace;
                                                    gcreate_answers = .{};
                                                    gcreate_config = builder.build(.{});
                                                    gcreate_name_len = 0;
                                                    gcreate_color = 0;
                                                    gloadout_tab = 0;
                                                    gscroll_px = 0;
                                                } else |_| status = "Couldn't save — out of memory.";
                                            } else |_| status = "Couldn't build that feed.";
                                        },
                                        // Reddit-style collapse: toggle this reply's CID in the
                                        // per-view collapsed set (no network — buildThreadView
                                        // re-derives the view next frame; ZONES inv. 4).
                                        .collapse => if (hit.post < view_items.len) {
                                            const cid = view_items[hit.post].cid;
                                            var found: ?usize = null;
                                            for (gcollapsed.items, 0..) |c, ix| if (std.mem.eql(u8, c, cid)) {
                                                found = ix;
                                                break;
                                            };
                                            if (found) |ix| {
                                                gpa.free(gcollapsed.items[ix]);
                                                _ = gcollapsed.swapRemove(ix);
                                            } else if (gpa.dupe(u8, cid)) |d| {
                                                gcollapsed.append(gpa, d) catch gpa.free(d);
                                            } else |_| {}
                                        },
                                        .bookmark, .share, .more, .profile_tab => {},
                                        // Zat Chat (U3): open the tapped conversation. The
                                        // region carries the LIST ORDINAL; map it back through
                                        // the same ordering query the list was built from (no
                                        // store index rides a region, A5).
                                        .chat_conv => if (dev_chat) {
                                            if (chat_core.conversationsByActivity(gpa, &gchat_store) catch null) |order| {
                                                defer gpa.free(order);
                                                if (hit.post < order.len) {
                                                    gchat_sel = order[hit.post];
                                                    chat_core.markRead(&gchat_store, order[hit.post]);
                                                    // M2: read-state survives a relaunch too.
                                                    chatPersistHistory(gpa, io, environ, if (gchat_e2ee) |*p| p else null, &gchat_store);
                                                    gchat_input_focus = true;
                                                    gchat_composing = false; // a row tap leaves the compose flow
                                                    gscroll_px = 0; // newest, bottom-anchored
                                                }
                                            }
                                        },
                                        .chat_input => if (dev_chat) {
                                            gchat_input_focus = true;
                                            gchat_composing = false;
                                        },
                                        // "+ New": open (or close) the recipient bar; it owns
                                        // the keyboard while open. Tapping the bar itself is
                                        // inert — being open IS its focus state.
                                        .chat_new => if (dev_chat) {
                                            gchat_composing = !gchat_composing;
                                            gchat_peer_len = 0;
                                            gchat_compose_status = "";
                                            gchat_input_focus = false;
                                        },
                                        .chat_compose_input => {},
                                        .chat_send => if (dev_chat) {
                                            const body = std.mem.trimEnd(u8, gchat_draft_buf[0..gchat_draft_len], " \n");
                                            if (body.len > 0) if (gchat_sel) |sc| {
                                                _ = chat_core.appendMessage(gpa, &gchat_store, sc, .text, body, now, true) catch {};
                                                chatSend(gpa, io, environ, if (gchat_e2ee) |*st| st else null, gchat_link, &gchat_store, sc, body);
                                                chatPersistHistory(gpa, io, environ, if (gchat_e2ee) |*p| p else null, &gchat_store);
                                                gchat_draft_len = 0;
                                                gchat_input_focus = true;
                                                gscroll_px = 0;
                                            };
                                        },
                                        // Tag pill (tray) OR an inline `#tag` in the prose →
                                        // ENTER its zone. Both regions carry the post index in
                                        // `post` and the tag's index in `_pad`; resolve the
                                        // display tag, open the zone page, and let the
                                        // fetch-on-enter pull the zone feed (buildTagView).
                                        .zone_jump, .tag_inline => if (hit.post < view_items.len) {
                                            const tags = view_items[hit.post].tags;
                                            if (hit._pad < tags.len) {
                                                const t = tags[hit._pad];
                                                if (t.len > 0 and t.len <= zone_tag_buf.len) {
                                                    @memcpy(zone_tag_buf[0..t.len], t);
                                                    // Back returns to where we came FROM (don't
                                                    // overwrite it on a zone→zone hop).
                                                    if (gscreen != feed_view.screen_zones) zone_return_screen = gscreen;
                                                    zone_tag = zone_tag_buf[0..t.len];
                                                    gscreen = feed_view.screen_zones;
                                                    zone_dirty = true;
                                                    gscroll_px = 0;
                                                    gsocket_ui.open = false; // tuck the home socket
                                                }
                                            }
                                        },
                                        // Zone card (browse grid) → ENTER its zone. The
                                        // region carries the catalog index in `post`; resolve
                                        // its display tag and open the zone page (the
                                        // fetch-on-enter pulls the feed, like a tag pill).
                                        .zone_open => if (hit.post < zone_catalog.items.len) {
                                            const t = zone_catalog.items[hit.post].tag;
                                            if (t.len > 0 and t.len <= zone_tag_buf.len) {
                                                @memcpy(zone_tag_buf[0..t.len], t);
                                                if (gscreen != feed_view.screen_zones) zone_return_screen = gscreen;
                                                zone_tag = zone_tag_buf[0..t.len];
                                                gscreen = feed_view.screen_zones;
                                                zone_dirty = true;
                                                gscroll_px = 0;
                                                gsocket_ui.open = false;
                                            }
                                        },
                                        // Marketplace "View details": fetch this
                                        // algorithm's full config by (author, rkey) and
                                        // open its transparency page. The fetched config
                                        // is validated in the shell leg (never trust the
                                        // wire); what the page shows is what would run.
                                        .algo_view => if (hit.post < market_catalog.items.len) {
                                            const r = market_catalog.items[hit.post];
                                            // Join any still-running fetch (rapid re-tap) before reusing
                                            // the job, so its thread can't outlive the reused fields.
                                            if (inspectjob.active) {
                                                joinInspect(&inspectjob);
                                                if (inspectjob.ok) if (inspectjob.bytes) |b| std.heap.page_allocator.free(b);
                                            }
                                            if (inspect_name.len > 0) gpa.free(inspect_name);
                                            if (inspect_ref.len > 0) gpa.free(inspect_ref);
                                            if (inspect_bytes) |b| gpa.free(b);
                                            inspect_bytes = null;
                                            inspect_name = try gpa.dupe(u8, r.name);
                                            inspect_ref = try gpa.dupe(u8, r.cid);
                                            transp_return_screen = gscreen;
                                            gscreen = feed_view.screen_transparency;
                                            gtransp_source = false; // open on the summary
                                            gscroll_px = 0;
                                            // A8: a config we've already retrieved is immutable (same
                                            // CID) — serve it from the cache, INSTANT, no network.
                                            if (config_cache.get(r.cid)) |cached| {
                                                inspect_bytes = gpa.dupe(u8, cached) catch null;
                                                inspect_loading = false;
                                            } else {
                                                // Never seen: fetch on a worker (public read, no shared
                                                // session), page opens in a loading state meanwhile.
                                                startInspect(&inspectjob, io, environ, session.pds_url, r.author_did, r.rkey);
                                                inspect_loading = true;
                                            }
                                        },
                                        // "View the exact source" on the transparency
                                        // page → the byte-exact serialized artifact.
                                        .algo_source => {
                                            gtransp_source = true;
                                            gscroll_px = 0;
                                        },
                                        // "Add to loadout" (adopt + score) is the next
                                        // slice — it needs the fetched config wired into
                                        // the scoring resolver. Honest until then.
                                        .algo_add => {
                                            status = "Add to loadout is coming next — view its details for now.";
                                        },
                                        // Settings → Sign out: flag it and leave the
                                        // run loop. The caller (main) clears the cached
                                        // session instead of re-saving it, so the next
                                        // launch shows the Join/login flow.
                                        .sign_out => {
                                            user_signed_out = true;
                                            break :main_loop;
                                        },
                                        // Settings master–detail: pick the section.
                                        .settings_section => {
                                            gsettings_section = @intCast(hit.post);
                                            gscroll_px = 0;
                                            gsettings_picking = 255; // close any open picker
                                        },
                                        // A detail-pane row. Toggles flip their
                                        // runtime bit (live — Julia mode reads its
                                        // bit; other toggles flip but do nothing
                                        // until wired). Non-toggle rows: inert.
                                        .settings_row => {
                                            if (hit.post < settings_view.rows.len and settings_view.rows[hit.post].kind == .toggle) {
                                                toggle_bits ^= @as(u64, 1) << @intCast(hit.post);
                                                // Julia mode flipped ON → sparks fly from the
                                                // SWITCH: a heart-shaped bloom of ripples out of
                                                // the toggle's spot in the field. Convert the
                                                // toggle pill (logical px, right end of the row)
                                                // to a field cell (window px / cell, via scale).
                                                if (settings_view.rows[hit.post].action == settings_view.act_julia and (toggle_bits >> @intCast(hit.post)) & 1 != 0) {
                                                    if (gpu_state) |*gs| {
                                                        const tx = (@as(f32, @floatFromInt(hit.x)) + @as(f32, @floatFromInt(hit.w)) - 36.0) * gs.scale;
                                                        const ty = (@as(f32, @floatFromInt(hit.y)) + @as(f32, @floatFromInt(hit.h)) * 0.5) * gs.scale;
                                                        pushJuliaBurst(gpa, gs, @intFromFloat(tx / @as(f32, @floatFromInt(field_cell_w))), @intFromFloat(ty / @as(f32, @floatFromInt(field_cell_h))));
                                                        // The visible spark: hearts fly from the switch, on top of everything.
                                                        gs.julia_burst_x = tx;
                                                        gs.julia_burst_y = ty;
                                                        gs.julia_burst_t = 1.0;
                                                    }
                                                }
                                            }
                                            gsettings_picking = 255; // a row tap closes the picker
                                        },
                                        // A wired CHOICE row: open (or re-close) its
                                        // picker popover.
                                        .settings_choice => {
                                            const act = settings_view.rows[hit.post].action;
                                            gsettings_picking = if (gsettings_picking == act) 255 else act;
                                        },
                                        // A picker option: post = choiceIndex*8 + optionIndex.
                                        .settings_choice_opt => {
                                            const ci = hit.post / 8;
                                            const oi: u8 = @intCast(hit.post % 8);
                                            if (ci < choice_sel.len) choice_sel[ci] = oi;
                                            gsettings_picking = 255; // selection closes the picker
                                        },
                                            }
                                        }
                                    }
                                } else if (armed_legacy and cx == armed_cx and cy == armed_cy) {
                                    // Legacy (software cell) tap: same target on release.
                                    if (field_ui.hitTest(cx, cy, g.hr.slice())) |hit| {
                                        if (hit.target != field_ui.no_target and hit.target < view_items.len) state.selected = hit.target;
                                        if (hit.action != .none) if (timeline_ui.keyFor(hit.action)) |byte| {
                                            try pumped_bytes.append(gpa, byte);
                                        };
                                    }
                                }
                                armed_kind = null;
                                armed_legacy = false;
                            },
                            else => {},
                        }
                    }
                    if (pointer_events.items.len > 0) last_input_nanos = clock_shell.monotonicNanos();
                };
                // Compose mode: the premium composer's footer buttons. A tap is
                // turned into the SAME control byte the keyboard sends — Ctrl-D
                // (send) / Ctrl-C (cancel) — so handleComposeInput stays the one
                // dispatch path (the timeline does the same trick for its rows).
                if (mode == .compose) if (pix) |g| {
                    const gpu_scale: f32 = if (g.gpu) |gs| gs.scale else 1.0;
                    for (pointer_events.items) |pev| {
                        const rx: i32 = if (g.gpu != null) @intFromFloat(@as(f32, @floatFromInt(pev.x)) / gpu_scale) else @intCast(pev.x);
                        const ry: i32 = if (g.gpu != null) @intFromFloat(@as(f32, @floatFromInt(pev.y)) / gpu_scale) else @intCast(pev.y);
                        switch (pev.kind) {
                            .button_down => {
                                if (pev.button != 1) continue;
                                if (feed_view.hitTest(g.regions.items, rx, ry)) |hit| switch (hit.kind) {
                                    // Release-activation: arm the footer button; it fires
                                    // on button_up if the release is still on it.
                                    .compose_send, .compose_cancel => armed_compose = hit.kind,
                                    else => {},
                                } else {
                                    // Press in the text area. Count consecutive
                                    // presses close in time + place: 1 = caret +
                                    // drag, 2 = select word, 3 = select line.
                                    const now_ns = clock_shell.monotonicNanos();
                                    const near = @abs(rx - last_click_x) <= 3 and @abs(ry - last_click_y) <= 3;
                                    click_count = if (now_ns -| last_click_ns < 400_000_000 and near) click_count + 1 else 1;
                                    last_click_ns = now_ns;
                                    last_click_x = rx;
                                    last_click_y = ry;
                                    const off = feed_view.composeCaretAtPoint(g.engine, @intCast(design_w), textedit.view(&compose), rx, ry);
                                    switch (@min(click_count, @as(u8, 3))) {
                                        1 => {
                                            textedit.setCaret(&compose, off);
                                            compose_drag = true; // single press → drag-select
                                        },
                                        2 => textedit.selectWord(&compose, off),
                                        else => textedit.selectLine(&compose, off),
                                    }
                                    caret_anchor_ns = now_ns;
                                }
                            },
                            .move => {
                                // Affordance: the hand over the composer's footer
                                // buttons (the only regions it emits), the I-beam over
                                // the editable text area otherwise — so a tap into the
                                // composer doesn't leave the hand from the button that
                                // opened it, and editable text reads as selectable.
                                window_shell.setCursor(win, if (feed_view.hitTest(g.regions.items, rx, ry) != null) .pointer else .text);
                                if (compose_drag) {
                                    // Drag extends the selection to the pointer.
                                    const off = feed_view.composeCaretAtPoint(g.engine, @intCast(design_w), textedit.view(&compose), rx, ry);
                                    textedit.extendTo(&compose, off);
                                    caret_anchor_ns = clock_shell.monotonicNanos();
                                }
                            },
                            .button_up => if (pev.button == 1) {
                                compose_drag = false;
                                // Fire the armed footer button only if the release is
                                // still over the same button (slide-off cancels).
                                if (armed_compose) |ac| {
                                    if (feed_view.hitTest(g.regions.items, rx, ry)) |hit| {
                                        if (hit.kind == ac) switch (ac) {
                                            .compose_send => try pumped_bytes.append(gpa, 4), // ctrl-D
                                            .compose_cancel => try pumped_bytes.append(gpa, 3), // ctrl-C
                                            else => {},
                                        };
                                    }
                                }
                                armed_compose = null;
                            },
                            else => {},
                        }
                    }
                    if (pointer_events.items.len > 0) last_input_nanos = clock_shell.monotonicNanos();
                };
                n = @min(pumped_bytes.items.len, in_buf.len);
                @memcpy(in_buf[0..n], pumped_bytes.items[0..n]);
                // No input this lap: idle back to the top. The top-of-loop
                // paintFrame is the ONE place the sim advances — it runs every
                // lap, and the dynamic pump above already set this lap's length
                // to the frame cadence while animating, so looping back yields
                // exactly one animation frame. (A second paint here was
                // redundant: it re-ran the whole pipeline with ~0 dt, doing the
                // CPU work of a frame the top-of-loop paint repeats next lap —
                // pure waste on the render thread. One paint per lap.)
                if (n == 0) continue;
                last_input_nanos = clock_shell.monotonicNanos();
            },
        }

        var offset: usize = 0;
        while (offset < n) {
            const decoded = tui.decodeInput(in_buf[offset..n]);
            if (decoded.consumed == 0) break;
            offset += decoded.consumed;

            if (mode == .profile) {
                try handleProfileInput(gpa, arena, io, environ, session, out, backend, &prev, &next, &status, &status_buf, &mode, &profile_info, decoded.event, now);
                continue;
            }

            // Timeline: Escape dismisses an open context menu; Ctrl+C copies the
            // rooted post's text selection. Both need the shell (menu state /
            // clipboard). Ctrl+C only CONSUMES the key when a selection exists, so
            // with none it still falls through to its normal handling.
            if (mode == .timeline) if (pix) |g| if (g.gpu) |gs| {
                if (decoded.event == .escape and gs.menu_open) {
                    gs.menu_open = false;
                    continue;
                }
                const ch: ?u21 = switch (decoded.event) {
                    .char => |c| c,
                    else => null,
                };
                if (ch == 3) {
                    const r = text_select.range(gs.sel_glyphs.items.len, gs.sel_anchor, gs.sel_focus);
                    if (r.hi > r.lo) {
                        copySelection(gpa, gs, backend);
                        status = "Copied";
                        continue;
                    }
                }
                // Tiling foundation: '/' toggles the content-driven SEARCH tile —
                // it grows + pushes the trending/follow tiles down (a cheap
                // reposition, no relayout). The shell springs `search_open`.
                if (ch == '/') {
                    gs.search_want = !gs.search_want;
                    continue;
                }
            };

            if (mode == .compose) {
                // Copy (Ctrl+C) / Cut (Ctrl+X) on a selection — handled here
                // because the clipboard write needs the window. With a selection,
                // Ctrl+C copies (not cancel); Ctrl+X copies then deletes.
                const ctrl_char: ?u21 = switch (decoded.event) {
                    .char => |c| c,
                    else => null,
                };
                if (ctrl_char) |c| if ((c == 3 or c == 24) and textedit.hasSelection(&compose)) {
                    switch (backend) {
                        .window => |w| window_shell.setClipboard(w, textedit.selView(&compose)),
                        .terminal => {},
                    }
                    if (c == 24) textedit.deleteSelection(&compose);
                    caret_anchor_ns = clock_shell.monotonicNanos();
                    continue;
                };
                try handleComposeInput(gpa, session, &status, &mode, store, &compose, &reply_target, &reply_handle, compose_kind, pix, &pending_send, &pending_profile_save, decoded.event, now);
                if (mode != .compose) compose_drag = false; // composer closed → end any drag
                caret_anchor_ns = clock_shell.monotonicNanos(); // keystroke/move → solid caret
                continue;
            }

            // Zoom (text scaling) is a window-render concern, so it is
            // handled here in the shell, before the core action dispatch
            // — the pure timeline_ui need not learn about pixel cells
            // (B2/D3), the same way wheel-scroll lives in the pointer
            // block, not the core Action enum. '+'/'=' grow the text,
            // '-'/'_' shrink it; only meaningful in the window (the
            // terminal has no pixel cells), so gated on an engine.
            // Zat Chat's structural keys arrive as decoded EVENTS, not chars
            // (the terminal decoder owns that mapping — checking for '\r' in
            // a .char is dead code). Enter SENDS the draft (trailing
            // whitespace trimmed; all-whitespace sends nothing) or submits
            // the recipient bar; Shift+Enter breaks the line in the draft;
            // Escape leaves the focused input. Consumes the key.
            if (engine != null and dev_chat and gscreen == feed_view.screen_messages and (gchat_composing or gchat_input_focus)) {
                var chat_key = true;
                switch (decoded.event) {
                    .enter => if (gchat_composing) {
                        if (gchat_peer_len > 0) {
                            _ = gchat_arena_state.reset(.retain_capacity);
                            var new_sel: ?chat_core.ConvIndex = null;
                            gchat_compose_status = chatStartCompose(gpa, gchat_arena_state.allocator(), io, environ, session, if (gchat_e2ee) |*p| p else null, gchat_link, &gchat_store, gchat_peer_buf[0..gchat_peer_len], &new_sel);
                            if (new_sel) |nc| {
                                gchat_sel = nc;
                                gchat_composing = false;
                                gchat_peer_len = 0;
                                gchat_compose_status = "";
                                gchat_input_focus = true; // straight into typing the first message
                                gscroll_px = 0;
                            }
                        }
                    } else {
                        const body = std.mem.trimEnd(u8, gchat_draft_buf[0..gchat_draft_len], " \n");
                        if (body.len > 0) if (gchat_sel) |sc| {
                            _ = chat_core.appendMessage(gpa, &gchat_store, sc, .text, body, now, true) catch {};
                            chatSend(gpa, io, environ, if (gchat_e2ee) |*st| st else null, gchat_link, &gchat_store, sc, body);
                            chatPersistHistory(gpa, io, environ, if (gchat_e2ee) |*p| p else null, &gchat_store);
                            gchat_draft_len = 0;
                            gscroll_px = 0; // re-anchor to the newest message
                        };
                    },
                    .shift_enter => if (!gchat_composing and gchat_draft_len < gchat_draft_buf.len) {
                        gchat_draft_buf[gchat_draft_len] = '\n';
                        gchat_draft_len += 1;
                        gchat_key_ns = clock_shell.monotonicNanos();
                    },
                    .escape => if (gchat_composing) {
                        gchat_composing = false;
                        gchat_compose_status = "";
                    } else {
                        gchat_input_focus = false;
                    },
                    else => chat_key = false,
                }
                if (chat_key) {
                    try paintFrame(gpa, out, arena, &prev, &next, backend, pix, view_items, profile_header, &state, revealed.items, now, session.handle, status);
                    continue;
                }
            }

            if (engine != null) if (decoded.event == .char) {
                const zc = decoded.event.char;
                // The Zat Chat composer strip: typing lands in the chat draft
                // while the field has focus (tap the input to focus). ASCII
                // for now, same as the Create name field; the full textedit
                // (caret, selection, UTF-8) is the recorded upgrade.
                // Consumes the key. The recipient bar (compose-new-
                // conversation) owns the keyboard while open. Every chat
                // keystroke stamps `gchat_key_ns` — the caret stays lit
                // while typing and breathes when idle.
                if (dev_chat and gscreen == feed_view.screen_messages and gchat_composing) {
                    if (zc == 8 or zc == 127) {
                        if (gchat_peer_len > 0) gchat_peer_len -= 1;
                        gchat_key_ns = clock_shell.monotonicNanos();
                    } else if (zc >= 0x20 and zc < 0x7f and gchat_peer_len < gchat_peer_buf.len) {
                        gchat_peer_buf[gchat_peer_len] = @intCast(zc);
                        gchat_peer_len += 1;
                        gchat_key_ns = clock_shell.monotonicNanos();
                    }
                } else if (dev_chat and gscreen == feed_view.screen_messages and gchat_input_focus) {
                    if (zc == 8 or zc == 127) {
                        if (gchat_draft_len > 0) gchat_draft_len -= 1;
                        gchat_key_ns = clock_shell.monotonicNanos();
                    } else if (zc >= 0x20 and zc < 0x7f and gchat_draft_len < gchat_draft_buf.len) {
                        gchat_draft_buf[gchat_draft_len] = @intCast(zc);
                        gchat_draft_len += 1;
                        gchat_key_ns = clock_shell.monotonicNanos();
                        // One encrypted typing ping per 4s of active typing.
                        // deposit is worker-queued (never blocks the frame);
                        // the ping's persist is the same nonce rule a send
                        // pays — one keystore write per ping, throttled.
                        if (now - gchat_typing_sent_at >= 4) if (gchat_sel) |sc| {
                            if (gchat_e2ee) |*st| if (gchat_link) |l| {
                                chat_e2ee.sendTyping(gpa, io, environ, st, l, chat_core.conversationDid(&gchat_store, sc)) catch {};
                                gchat_typing_sent_at = now;
                            };
                        };
                    }
                    try paintFrame(gpa, out, arena, &prev, &next, backend, pix, view_items, profile_header, &state, revealed.items, now, session.handle, status);
                    continue;
                }
                // The Create name field: route typing into the feed-name buffer (ASCII
                // for now — a zone/feed name is short). Backspace via BS/DEL. Consumes
                // the key so it never falls through to zoom or the feed shortcuts.
                if (gscreen == feed_view.screen_loadout and gloadout_tab == 2 and gcreate_step == .name) {
                    if ((zc == 8 or zc == 127)) {
                        if (gcreate_name_len > 0) gcreate_name_len -= 1;
                    } else if (zc >= 0x20 and zc < 0x7f and gcreate_name_len < gcreate_name_buf.len) {
                        gcreate_name_buf[gcreate_name_len] = @intCast(zc);
                        gcreate_name_len += 1;
                    }
                    try paintFrame(gpa, out, arena, &prev, &next, backend, pix, view_items, profile_header, &state, revealed.items, now, session.handle, status);
                    continue;
                }
                if (zc == '+' or zc == '=') {
                    gzoom = std.math.clamp(gzoom + 0.15, zoom_min, zoom_max);
                    status = "zoom in";
                    try paintFrame(gpa, out, arena, &prev, &next, backend, pix, view_items, profile_header, &state, revealed.items, now, session.handle, status);
                    continue;
                } else if (zc == '-' or zc == '_') {
                    gzoom = std.math.clamp(gzoom - 0.15, zoom_min, zoom_max);
                    status = "zoom out";
                    try paintFrame(gpa, out, arena, &prev, &next, backend, pix, view_items, profile_header, &state, revealed.items, now, session.handle, status);
                    continue;
                }
            };

            switch (timeline_ui.actionFor(decoded.event)) {
                .quit => break :main_loop,
                .refresh => {
                    status = "refreshing...";
                    try paintFrame(gpa, out, arena, &prev, &next, backend, pix, view_items, profile_header, &state, revealed.items, now, session.handle, status);

                    const outcome = feed_shell.refreshTimeline(gpa, arena, io, environ, session, appview_url, store, 30) catch |err| switch (err) {
                        error.OutOfMemory => return err,
                        else => {
                            status = "network error"; // contained (E2)
                            continue;
                        },
                    };
                    status = switch (outcome) {
                        .ok => |stats| blk: {
                            // An explicit refresh asks to SEE the new — REVEAL
                            // the staged posts and jump to the top. (The passive
                            // auto-refresh stages them behind the pill instead.)
                            const revealed_n = feed_core.revealPending(gpa, store) catch 0;
                            if (revealed_n > 0) {
                                state.selected = 0;
                                state.scroll_top = 0;
                                gview.scroll_rows = 0;
                                gscroll_px = 0;
                            }
                            break :blk if (stats.items_added == 0 and revealed_n == 0)
                                "no new posts"
                            else
                                std.fmt.bufPrint(&status_buf, "+{d} new at top", .{revealed_n}) catch "new posts";
                        },
                        .failed => |failure| std.fmt.bufPrint(&status_buf, "refused: {d} {s}", .{
                            failure.status, failure.code,
                        }) catch "refused",
                    };
                    if (outcome == .ok) _ = cache_shell.saveStore(gpa, environ, store); // E4
                    if (outcome == .ok and live_stream == null and store.authors.len > 0) {
                        live_stream = try startLiveStream(gpa, io, environ, session.did, store, &mailbox, arena);
                        if (live_stream == null) status = "live stream unavailable" else subscribed_authors = store.authors.len;
                    }
                },
                .load_more => {
                    if (store.feed.len > 0 and feed_core.nextCursor(store).len == 0) {
                        status = "end of feed";
                        continue;
                    }
                    // Paint the wait before paying it.
                    status = "loading...";
                    try paintFrame(gpa, out, arena, &prev, &next, backend, pix, view_items, profile_header, &state, revealed.items, now, session.handle, status);

                    const outcome = feed_shell.loadTimelinePage(gpa, arena, io, environ, session, appview_url, store, 30) catch |err| switch (err) {
                        error.OutOfMemory => return err,
                        else => {
                            // Contained: the feed fetch failing is a status
                            // line, not a dead screen (E2).
                            status = "network error";
                            continue;
                        },
                    };
                    status = switch (outcome) {
                        .ok => |stats| std.fmt.bufPrint(&status_buf, "+{d} older ({d} seen)", .{
                            stats.items_added, stats.posts_deduped,
                        }) catch "loaded",
                        .failed => |failure| std.fmt.bufPrint(&status_buf, "refused: {d} {s}", .{
                            failure.status, failure.code,
                        }) catch "refused",
                    };
                    if (outcome == .ok) _ = cache_shell.saveStore(gpa, environ, store); // E4
                    if (outcome == .ok and live_stream == null and store.authors.len > 0) {
                        live_stream = try startLiveStream(gpa, io, environ, session.did, store, &mailbox, arena);
                        if (live_stream == null) status = "live stream unavailable" else subscribed_authors = store.authors.len;
                    }
                },
                .like => if (view_items.len > 0) {
                    const r = try engageSelected(.like, gpa, arena, session, store, view_items[state.selected], state.selected, gscreen, profile_target_did, thread_focus_cid, zone_tag, thread_rerooted, gcollapsed.items, feed_config, reply_config, &state, revealed.items, now, out, &prev, &next, backend, pix, writer, &deferred_unlike, &deferred_unrepost);
                    if (r.status.len > 0) status = r.status;
                    if (r.skip_rest) continue;
                },
                .repost => if (view_items.len > 0) {
                    const r = try engageSelected(.repost, gpa, arena, session, store, view_items[state.selected], state.selected, gscreen, profile_target_did, thread_focus_cid, zone_tag, thread_rerooted, gcollapsed.items, feed_config, reply_config, &state, revealed.items, now, out, &prev, &next, backend, pix, writer, &deferred_unlike, &deferred_unrepost);
                    if (r.status.len > 0) status = r.status;
                    if (r.skip_rest) continue;
                },
                .profile => if (view_items.len > 0) {
                    const item = view_items[state.selected];
                    status = "loading profile...";
                    try paintFrame(gpa, out, arena, &prev, &next, backend, pix, view_items, profile_header, &state, revealed.items, now, session.handle, status);
                    const outcome = auth.queryHost(gpa, arena, io, environ, session, appview_url, lexicon.method.get_profile, &.{
                        .{ .name = "actor", .value = item.author_handle },
                    }, lexicon.ProfileViewDetailed) catch |err| switch (err) {
                        error.OutOfMemory => return err,
                        else => {
                            status = "network error"; // contained (E2)
                            continue;
                        },
                    };
                    switch (outcome) {
                        .ok => |wire| {
                            _ = profile_arena_state.reset(.retain_capacity);
                            const parena = profile_arena_state.allocator();
                            profile_info = .{
                                .did = try parena.dupe(u8, wire.did),
                                .handle = try parena.dupe(u8, wire.handle),
                                .display_name = try parena.dupe(u8, wire.displayName orelse ""),
                                .description = try parena.dupe(u8, wire.description orelse ""),
                                .followers = @intCast(@min(wire.followersCount, std.math.maxInt(u32))),
                                .follows = @intCast(@min(wire.followsCount, std.math.maxInt(u32))),
                                .posts = @intCast(@min(wire.postsCount, std.math.maxInt(u32))),
                                .following = wire.viewer != null and wire.viewer.?.following != null,
                            };
                            mode = .profile;
                            status = "";
                        },
                        .failed => |failure| status = std.fmt.bufPrint(&status_buf, "refused: {d} {s}", .{
                            failure.status, failure.code,
                        }) catch "refused",
                    }
                },
                .toggle_reveal => if (view_items.len > 0) {
                    const item = view_items[state.selected];
                    var found: ?usize = null;
                    for (revealed.items, 0..) |cid, i| {
                        if (std.mem.eql(u8, cid, item.cid)) {
                            found = i;
                            break;
                        }
                    }
                    if (found) |i| {
                        gpa.free(revealed.items[i]);
                        _ = revealed.swapRemove(i);
                        status = "hidden again";
                    } else if (moderation.verdictFor(item.label_flags) == .hide) {
                        try revealed.append(gpa, try gpa.dupe(u8, item.cid));
                        status = "shown (x re-hides)";
                    }
                },
                .follow => if (view_items.len > 0) {
                    const item = view_items[state.selected];
                    const did = feed_core.authorDidForCid(store, item.cid);
                    if (did.len > 0) {
                        status = "following...";
                        try paintFrame(gpa, out, arena, &prev, &next, backend, pix, view_items, profile_header, &state, revealed.items, now, session.handle, status);
                        const outcome = write.followAccount(gpa, arena, io, environ, session, did, now) catch |err| switch (err) {
                            error.OutOfMemory => return err,
                            else => {
                                status = "network error";
                                continue;
                            },
                        };
                        status = switch (outcome) {
                            .ok => std.fmt.bufPrint(&status_buf, "followed @{s}", .{item.author_handle}) catch "followed",
                            .failed => |failure| std.fmt.bufPrint(&status_buf, "refused: {d} {s}", .{
                                failure.status, failure.code,
                            }) catch "refused",
                        };
                    }
                },
                .reply => if (view_items.len > 0) {
                    const item = view_items[state.selected];
                    if (feed_core.replyRefsForCid(store, item.cid)) |refs| {
                        // Copy the refs out of the store before composing:
                        // the composer outlives this frame and the store may
                        // grow under it (the lifetime contract, honored).
                        _ = compose_arena_state.reset(.retain_capacity);
                        const compose_arena = compose_arena_state.allocator();
                        reply_target = .{
                            .root_uri = try compose_arena.dupe(u8, refs.root_uri),
                            .root_cid = try compose_arena.dupe(u8, refs.root_cid),
                            .parent_uri = try compose_arena.dupe(u8, refs.parent_uri),
                            .parent_cid = try compose_arena.dupe(u8, refs.parent_cid),
                        };
                        reply_handle = try compose_arena.dupe(u8, item.author_handle);
                        textedit.clear(&compose);
                        status = "";
                        mode = .compose;
                    }
                },
                .new_post => {
                    reply_target = null;
                    reply_handle = "";
                    textedit.clear(&compose);
                    status = "";
                    mode = .compose;
                },
                else => |action| {
                    timeline_ui.applyAction(&state, action, view_items.len);
                    switch (action) {
                        // Key navigation scrolls the pixel viewport to the
                        // cursor; wheel reading never does (one-shot flag,
                        // consumed by buildTimeline).
                        .move_up, .move_down, .page_up, .page_down, .go_top, .go_bottom => gview.ensure_selected = true,
                        else => {},
                    }
                },
            }
        }
    }
    return user_signed_out;
}

/// The caret blink phase: solid for the ~530 ms after the last edit/move
/// (anchor), then a 530 ms on/off cycle while idle. B3: the clock is the shell's.
fn composeBlinkOn(anchor_ns: u64) bool {
    return ((clock_shell.monotonicNanos() -| anchor_ns) / 530_000_000) % 2 == 0;
}

/// Diff, write, flush, and bring `prev` up to date with what is on screen.
const Mode = enum { timeline, compose, profile };

// ---------------------------------------------------------------------------
// Mode input handlers — the per-mode split that completes the recorded
// B3 thinning (deviation #1): run() keeps only dispatch; each mode's
// choreography lives in its own named function. Same parameter-passing
// house style as engageSelected: explicit values and pointers, no
// hidden context (D4: the coupling is loud and stays inside this file).
// ---------------------------------------------------------------------------

fn handleProfileInput(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    out: *std.Io.Writer,
    backend: Backend,
    prev: *tui.Surface,
    next: *tui.Surface,
    status: *[]const u8,
    status_buf: []u8,
    mode: *Mode,
    profile_info: *?timeline_ui.ProfileInfo,
    ev: tui.InputEvent,
    now: i64,
) !void {
    switch (timeline_ui.actionForProfile(ev)) {
        .close => {
            mode.* = .timeline;
            status.* = "";
        },
        .follow => if (profile_info.*) |info| {
            if (info.did.len > 0 and !info.following) {
                status.* = "following...";
                timeline_ui.buildProfileFrame(next, info, status.*);
                try present(gpa, out, arena, prev, next, backend);
                const outcome = write.followAccount(gpa, arena, io, environ, session, info.did, now) catch |err| switch (err) {
                    error.OutOfMemory => return err,
                    else => {
                        status.* = "network error"; // contained (E2)
                        return;
                    },
                };
                switch (outcome) {
                    .ok => {
                        profile_info.*.?.following = true;
                        status.* = "followed";
                    },
                    .failed => |failure| status.* = std.fmt.bufPrint(status_buf, "refused: {d} {s}", .{
                        failure.status, failure.code,
                    }) catch "refused",
                }
            }
        },
        .none => {},
    }
}

/// A queued create-write for a post/reply that was already shown OPTIMISTICALLY
/// (seated in the store under `temp_cid`). The loop performs the write AFTER the
/// optimistic post is on screen, then reconciles the temp cid to the server's
/// real one (or drops the post on failure). Owns its strings (gpa) — they
/// outlive the cleared compose draft. One in flight at a time.
/// A7.2: cold struct, size guard waived — at most one in flight, transient.
const SendJob = struct {
    temp_cid: []const u8,
    text: []const u8,
    target: ?write.ReplyTarget,
};

fn dupeTarget(gpa: Allocator, t: ?write.ReplyTarget) !?write.ReplyTarget {
    const tt = t orelse return null;
    return .{
        .root_uri = try gpa.dupe(u8, tt.root_uri),
        .root_cid = try gpa.dupe(u8, tt.root_cid),
        .parent_uri = try gpa.dupe(u8, tt.parent_uri),
        .parent_cid = try gpa.dupe(u8, tt.parent_cid),
    };
}

fn freeSendJob(gpa: Allocator, job: SendJob) void {
    gpa.free(job.temp_cid);
    if (job.text.len > 0) gpa.free(job.text);
    if (job.target) |t| {
        gpa.free(t.root_uri);
        gpa.free(t.root_cid);
        gpa.free(t.parent_uri);
        gpa.free(t.parent_cid);
    }
}

// Input handling only mutates draft/compose state and QUEUES network writes
// (pending_send / pending_profile_save) for the loop to run after the
// optimistic UI is on screen — so it takes no I/O args of its own.
fn handleComposeInput(
    gpa: Allocator,
    session: *auth.Session,
    status: *[]const u8,
    mode: *Mode,
    /// The shared store — a send is optimistically ingested into it so it shows
    /// INSTANTLY (the 5s refresh would otherwise gate it).
    store: *feed_core.Store,
    compose: *textedit.Field,
    reply_target: *?write.ReplyTarget,
    reply_handle: *[]const u8,
    compose_kind: ComposeKind,
    /// The live render grid (for the post-send scroll-to-top).
    pix: ?Grid,
    /// Set by a post/reply send: the queued create-write the loop performs AFTER
    /// the optimistic post is on screen (0ms). Null when nothing is queued.
    pending_send: *?SendJob,
    /// Set by a profile-edit save: the display name to putProfile, run by the
    /// loop after the name is optimistically shown. gpa-owned; null when idle.
    pending_profile_save: *?[]const u8,
    ev: tui.InputEvent,
    now: i64,
) !void {
    switch (timeline_ui.actionForCompose(ev)) {
        .cancel => {
            mode.* = .timeline;
            status.* = "cancelled";
        },
        .backspace => textedit.backspace(compose),
        .delete_fwd => textedit.deleteForward(compose),
        .left => textedit.left(compose),
        .right => textedit.right(compose),
        .home => textedit.home(compose),
        .end => textedit.end(compose),
        .insert => |cp| {
            if (timeline_ui.countCodepoints(textedit.view(compose)) >= 300) {
                status.* = "300 character limit";
            } else {
                var utf8_buf: [4]u8 = undefined;
                const len = std.unicode.utf8Encode(cp, &utf8_buf) catch 0;
                if (len > 0) textedit.insert(compose, utf8_buf[0..len]);
            }
        },
        .send => {
            if (compose.len == 0) {
                status.* = if (compose_kind == .profile) "name can't be empty" else "nothing to post";
                return;
            }
            // Profile editor: upsert the self profile record, then return to the
            // profile screen (mode→timeline re-enters it and re-fetches, so the
            // new name shows once the AppView re-polls the record).
            if (compose_kind == .profile) {
                // 0ms: set the display name locally NOW (guarded against a stale
                // refresh), close to the profile, and queue the putProfile write
                // for the loop to run after — the new name shows instantly.
                feed_core.setOwnDisplayName(gpa, store, session.did, textedit.view(compose)) catch {};
                pending_profile_save.* = gpa.dupe(u8, textedit.view(compose)) catch null;
                textedit.clear(compose);
                mode.* = .timeline;
                status.* = "name updated";
                return;
            }
            // TRULY 0ms: seat the post in the store under a TEMPORARY cid and
            // return to the feed immediately — it renders THIS frame. The actual
            // create write is queued (`pending_send`) and run by the loop AFTER
            // the optimistic post is on screen; it then reconciles the temp cid
            // to the server's real one, or drops the post on failure. The temp
            // cid is unique: `posts.len` only grows.
            const target = reply_target.*;
            const temp_cid = try std.fmt.allocPrint(gpa, "pending:{d}", .{store.posts.len});
            _ = feed_core.ingestLivePost(gpa, store, .{
                .did = session.did,
                .handle = session.handle,
                .uri = "",
                .cid = temp_cid,
                .text = textedit.view(compose),
                .reply_parent_cid = if (target) |t| t.parent_cid else "",
                .reply_root_cid = if (target) |t| t.root_cid else "",
                .created_at = now,
            }) catch {};
            if (target) |t| feed_core.bumpReplyCount(store, t.parent_cid);
            pending_send.* = .{
                .temp_cid = temp_cid,
                .text = try gpa.dupe(u8, textedit.view(compose)),
                .target = try dupeTarget(gpa, target),
            };
            textedit.clear(compose);
            reply_target.* = null;
            reply_handle.* = "";
            mode.* = .timeline;
            if (pix) |g| g.scroll.* = 0; // jump to top so you see your post land
            status.* = "";
        },
        .none => {},
    }
}

// ---------------------------------------------------------------------------
// Engagement — the like/boost twins, unified (the first cut of the
// recorded B3 thinning: one body, two verbs; the run loop keeps only
// control flow). Optimistic apply paints first; any refusal reverts.
// ---------------------------------------------------------------------------

const Engagement = enum { like, repost };

/// What the reused compose flow writes on send — a feed post, or the self
/// profile record (the in-app profile editor reuses the composer's input).
const ComposeKind = enum { post, profile };

/// The discover-engine config a surface's seated lens resolves to, or null when
/// that lens is the no-scoring path (Following / Most Recent) — then the surface
/// stays its plain builder (feed order, or chronological threading). Surface-
/// agnostic: the SAME resolver serves the feed tray and the reply tray, because
/// the tray is the user's and identical on every surface (DISCOVER invariant 12).
/// Empty tray ⇒ null (E4).
fn seatedLensConfig(cards: []const lens_socket.LensCard, blob: []const u8, seated: u32) ?discover.FeedConfig {
    if (cards.len == 0) return null;
    const idx = @min(seated, @as(u32, @intCast(cards.len - 1)));
    const span = cards[idx].cid;
    const cid = blob[span.off..][0..span.len];
    return lens_catalog.scoringConfigForId(cid);
}

/// Build the ACTIVE view's posts over the SHARED store — Home (scored by the
/// seated feed lens, or chronological), a post's thread (sibling order composed
/// onto threading by the seated reply lens), the profile author query, or a
/// zone. The single place "which view is showing" is decided, for both the main
/// loop and engageSelected's optimistic repaint. `now` is the shell's clock
/// reading, handed to the pure scorer (invariant 9).
/// Zat Chat (U3): the per-frame view bundle for the Messages surface. A7.2:
/// cold struct, size guard waived — one transient per frame, never collected.
const ChatFrame = struct {
    list: []const chat_view_core.ListRow = &.{},
    thread: []const chat_view_core.BubbleRow = &.{},
    sel: u16 = std.math.maxInt(u16),
    peer: []const u8 = "",
};

/// Resolve the Messages surface's view-models from the one chat store: the
/// conversation list, the open thread, the selected ordinal, and the peer
/// label. Pure queries into the frame arena (C3); the ordinal is the value
/// the surface's tap regions carry.
/// M1 send: encrypt the just-typed draft to the conversation's peer and
/// deposit it on the relay (chat_e2ee owns the crypto + persistence). A null
/// session/link (no ZAT4_RELAY) keeps the send local-only — the bubble still
/// shows, it just doesn't transmit. A crypto/relay error is a status line,
/// never a crash (E2). `env` feeds the persist-after-send.
fn chatSend(gpa: Allocator, io: std.Io, env: ?*const std.process.Environ.Map, st: ?*chat_e2ee.State, link: ?*chat_relay.ChatRelay, cs: *const chat_core.Store, conv: chat_core.ConvIndex, text: []const u8) void {
    const state = st orelse return;
    const l = link orelse return;
    const peer_did = chat_core.conversationDid(cs, conv);
    chat_e2ee.send(gpa, io, env, state, l, peer_did, .text, text) catch {};
}

/// The compose flow's one verb: resolve what the user typed (a handle via
/// the PDS, or a literal `did:`), start the E2EE conversation, and open it
/// in the view store — the typed handle becomes the list label. Returns a
/// static status line ("" = success) and reports the opened conversation
/// through `sel_out`. Runs on the caller's thread — the recorded v1
/// first-contact posture (chat_e2ee module header): rare events, a worker
/// is the recorded upgrade if they ever jank.
fn chatStartCompose(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    env: ?*const std.process.Environ.Map,
    session: *auth.Session,
    st: ?*chat_e2ee.State,
    link: ?*chat_relay.ChatRelay,
    cs: *chat_core.Store,
    typed_raw: []const u8,
    sel_out: *?chat_core.ConvIndex,
) []const u8 {
    const state = st orelse return "Chat is offline — no relay configured";
    const l = link orelse return "Chat is offline — no relay configured";
    var typed = std.mem.trim(u8, typed_raw, " ");
    if (typed.len > 0 and typed[0] == '@') typed = typed[1..]; // "@handle" reads naturally; accept it
    if (typed.len == 0) return "";

    var did: []const u8 = undefined;
    var handle: []const u8 = "";
    if (std.mem.startsWith(u8, typed, "did:")) {
        did = typed;
    } else {
        const outcome = xrpc.query(
            arena,
            io,
            env,
            session.pds_url,
            lexicon.method.resolve_handle,
            &.{.{ .name = "handle", .value = typed }},
            lexicon.ResolveHandleResponse,
            .{},
        ) catch return "Couldn't resolve that handle";
        switch (outcome) {
            .ok => |resolved| {
                if (resolved.did.len == 0) return "Couldn't resolve that handle";
                did = resolved.did;
            },
            .failed => return "Couldn't resolve that handle",
        }
        handle = typed;
    }
    if (std.mem.eql(u8, did, state.my_did)) return "That's you — pick someone else";

    if (!chat_e2ee.hasConversation(state, did)) {
        chat_e2ee.startConversation(gpa, arena, io, env, state, l, did) catch |err| switch (err) {
            error.AlreadyOpen => {}, // raced ourselves; the view opens below
            error.NoKeyPackage => return "No chat keys published for that account",
            error.RelayDown => return "Relay unreachable — try again",
            error.CryptoFailed, error.OutOfMemory => return "Couldn't start the conversation",
        };
    }
    const conv = chat_core.openConversation(gpa, cs, did, handle) catch return "Couldn't start the conversation";
    sel_out.* = conv;
    chatPersistHistory(gpa, io, env, state, cs);
    return "";
}

/// M2 persist: the displayed history survives a relaunch. Serialize the view
/// store (pure core codec) and hand cache the blob — sealed at rest under a
/// keystore-held key, per account. A quiet no-op without a live E2EE session
/// (no DID to key the file by, and nothing durable to show); a failed write
/// drops this snapshot, never the frame — the next mutation rewrites the
/// whole blob anyway.
fn chatPersistHistory(gpa: Allocator, io: std.Io, env: ?*const std.process.Environ.Map, st: ?*const chat_e2ee.State, cs: *const chat_core.Store) void {
    const state = st orelse return;
    const blob = chat_core.serializeStore(gpa, cs) catch return;
    defer {
        std.crypto.secureZero(u8, blob); // the transcript passes through
        gpa.free(blob);
    }
    var path_buf: [512]u8 = undefined;
    const path = cache_shell.chatHistoryPath(&path_buf, env, state.my_did) orelse return;
    _ = cache_shell.saveChatHistoryAt(gpa, io, path, state.my_did, blob);
}

fn buildChatFrame(arena: Allocator, cs: *const chat_core.Store, sel: ?chat_core.ConvIndex, now: i64) ChatFrame {
    const list = chat_view_core.buildList(arena, cs, now) catch return .{};
    var out: ChatFrame = .{ .list = list };
    const sc = sel orelse return out;
    const order = chat_core.conversationsByActivity(arena, cs) catch return out;
    for (order, 0..) |c, i| {
        if (c == sc) {
            out.sel = @intCast(i);
            break;
        }
    }
    if (out.sel != std.math.maxInt(u16) and out.sel < list.len) {
        out.peer = list[out.sel].name;
        out.thread = chat_view_core.buildThread(arena, cs, sc, now) catch &.{};
    }
    return out;
}

fn buildActiveView(arena: Allocator, store: *feed_core.Store, screen: u8, profile_did: []const u8, thread_cid: []const u8, zone_tag: []const u8, rerooted: bool, collapsed: []const []const u8, feed_config: ?discover.FeedConfig, reply_config: ?discover.FeedConfig, now: i64) error{OutOfMemory}![]feed_core.TimelineItem {
    if (screen == feed_view.screen_thread) return feed_core.buildThreadView(arena, store, thread_cid, rerooted, collapsed, now, reply_config);
    if (screen == feed_view.screen_profile) return feed_core.buildAuthorView(arena, store, profile_did);
    if (screen == feed_view.screen_zones) return feed_core.buildTagView(arena, store, zone_tag);
    if (feed_config) |cfg| return feed_core.buildDiscoverView(arena, store, cfg, now, null);
    return feed_core.buildTimeline(arena, store);
}

/// The profile header on the profile screen, else null. Derives the viewed
/// account's identity from its posts (the handle/display name the AppView
/// serves), falling back to your own session handle for an empty OWN profile,
/// else the target DID. Works for any author (tap-to-profile).
fn profileHeaderFor(arena: Allocator, session: *const auth.Session, screen: u8, target_did: []const u8, view_items: []const feed_core.TimelineItem) error{OutOfMemory}!?feed_view.ProfileHeader {
    if (screen != feed_view.screen_profile) return null;
    const first_handle = if (view_items.len > 0) view_items[0].author_handle else "";
    const first_name = if (view_items.len > 0) view_items[0].author_display_name else "";
    const is_self = std.mem.eql(u8, target_did, session.did);
    const handle_src = if (first_handle.len > 0) first_handle else if (is_self) session.handle else target_did;
    const name = if (first_name.len > 0) first_name else handle_src;
    return .{
        .display_name = name,
        .handle = try std.fmt.allocPrint(arena, "@{s}", .{handle_src}),
        .post_count = @intCast(view_items.len),
        .editable = is_self, // your own profile gets the "Edit profile" button
    };
}

/// Pull the author DID out of an at-uri (`at://{did}/{collection}/{rkey}`),
/// so a tap on a post's avatar can open that author's profile. "" if malformed.
fn authorDidFromUri(uri: []const u8) []const u8 {
    if (!std.mem.startsWith(u8, uri, "at://")) return "";
    const rest = uri["at://".len..];
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse return rest;
    return rest[0..slash];
}

const EngageResult = struct {
    // A7.2: cold struct, size guard waived — one per action, returned by value.

    /// Status to show ("" = leave the current status alone).
    status: []const u8,
    /// True on the network-error path: the caller skips the rest of this
    /// input batch, exactly as the inline arms did.
    skip_rest: bool = false,
};

fn engageSelected(
    kind: Engagement,
    gpa: Allocator,
    arena: Allocator,
    session: *auth.Session,
    store: *feed_core.Store,
    item: feed_core.TimelineItem,
    target: u32,
    /// The active Screen + the profile's author DID + the thread's focus cid, so
    /// the optimistic repaint rebuilds the SAME view the tap came from (Home,
    /// a profile, or a thread).
    screen: u8,
    profile_did: []const u8,
    thread_cid: []const u8,
    /// The open zone's tag, so a like on the zone page repaints the zone view.
    zone_tag: []const u8,
    thread_rerooted: bool,
    collapsed_cids: []const []const u8,
    /// The seated FEED and REPLY lens configs (null = the no-scoring path), so
    /// the optimistic repaint rebuilds the active surface through the SAME
    /// algorithm it's showing (Home scored / a thread's siblings ordered).
    feed_config: ?discover.FeedConfig,
    reply_config: ?discover.FeedConfig,
    state: *timeline_ui.UiState,
    revealed_cids: []const []const u8,
    now: i64,
    out: *std.Io.Writer,
    prev: *tui.Surface,
    next: *tui.Surface,
    backend: Backend,
    pix: ?Grid,
    writer: ?*write_worker.Worker,
    /// Deferred-undo intent sets (by post-cid hash) for the case where the user
    /// un-engages before the create's record uri is known — see the drain.
    def_unlike: *std.AutoHashMapUnmanaged(u64, void),
    def_unrepost: *std.AutoHashMapUnmanaged(u64, void),
) !EngageResult {
    const applied = switch (kind) {
        .like => feed_core.applyLike(store, item.cid),
        .repost => feed_core.applyRepost(store, item.cid),
    };
    switch (applied) {
        .already => {
            // Toggle: already engaged, so this press DISENGAGES. The
            // verdict's uri borrows the store's bytes — copy it out
            // before anything can append (the revert path appends).
            const dis = switch (kind) {
                .like => feed_core.applyUnlike(store, item.cid),
                .repost => feed_core.applyUnrepost(store, item.cid),
            };
            const borrowed = switch (dis) {
                .applied => |uri| uri,
                .not_engaged, .unknown => return .{ .status = "" },
                // The record uri isn't known yet (the create is still in
                // flight). Don't make the user wait: hollow the heart NOW and
                // remember to delete the record the instant the create returns
                // its uri (handled in the write-result drain). Undo is instant.
                .no_record_uri => {
                    const acted = switch (kind) {
                        .like => feed_core.applyUnlikeDeferred(store, item.cid),
                        .repost => feed_core.applyUnrepostDeferred(store, item.cid),
                    };
                    if (!acted) return .{ .status = "" };
                    const set = if (kind == .like) def_unlike else def_unrepost;
                    set.put(gpa, std.hash.Wyhash.hash(0, item.cid), {}) catch {};
                    const fresh = try buildActiveView(arena, store, screen, profile_did, thread_cid, zone_tag, thread_rerooted, collapsed_cids, feed_config, reply_config, now);
                    const fresh_header = try profileHeaderFor(arena, session, screen, profile_did, fresh);
                    try paintFrame(gpa, out, arena, prev, next, backend, pix, fresh, fresh_header, state, revealed_cids, now, session.handle, if (kind == .like) "unliking..." else "unboosting...");
                    if (pix) |g| fireEngageEffect(gpa, g, kind, target, false);
                    return .{ .status = if (kind == .like) "unliking..." else "unboosting..." };
                },
            };
            var uri_buf: [512]u8 = undefined;
            if (borrowed.len > uri_buf.len) {
                // Absurd uri: undo the optimistic state while the borrow
                // is still valid (nothing has appended yet) and refuse.
                try revertDisengage(kind, gpa, store, item.cid, borrowed);
                return .{ .status = "refused: bad record uri" };
            }
            const record_uri = uri_buf[0..borrowed.len];
            @memcpy(record_uri, borrowed);

            const fresh = try buildActiveView(arena, store, screen, profile_did, thread_cid, zone_tag, thread_rerooted, collapsed_cids, feed_config, reply_config, now);
            const fresh_header = try profileHeaderFor(arena, session, screen, profile_did, fresh);
            try paintFrame(gpa, out, arena, prev, next, backend, pix, fresh, fresh_header, state, revealed_cids, now, session.handle, if (kind == .like) "unliking..." else "unboosting...");
            // Fire the drain effect at the post's heart cell (state is now
            // DISENGAGED → the cooler recipe). One trigger, derived from the
            // actual transition — no click-path race.
            if (pix) |g| fireEngageEffect(gpa, g, kind, target, false);
            // SUBMIT the delete to the write worker and RETURN — the UI loop
            // keeps running, the drain animation plays smoothly every frame,
            // and the worker's result (drained later) reverts only on a
            // refusal. If the worker is unavailable (start failed) or its
            // queue is full, fall back to reverting now so state stays true.
            if (writer) |w| {
                if (!write_worker.submit(w, if (kind == .like) .unlike else .unrepost, item.cid, "", "", record_uri, now)) {
                    try revertDisengage(kind, gpa, store, item.cid, record_uri);
                    return .{ .status = "busy, try again" };
                }
                return .{ .status = if (kind == .like) "unliking..." else "unboosting..." };
            } else {
                try revertDisengage(kind, gpa, store, item.cid, record_uri);
                return .{ .status = "write unavailable" };
            }
        },
        .unknown => return .{ .status = "" },
        .applied => {},
    }

    // Optimistic first: the bumped count paints now; the worker call
    // follows on its own thread; a refusal reverts (drained in the loop).
    const fresh = try buildActiveView(arena, store, screen, profile_did, thread_cid, zone_tag, thread_rerooted, collapsed_cids, feed_config, reply_config, now);
    const fresh_header = try profileHeaderFor(arena, session, screen, profile_did, fresh);
    try paintFrame(gpa, out, arena, prev, next, backend, pix, fresh, fresh_header, state, revealed_cids, now, session.handle, if (kind == .like) "liking..." else "boosting...");
    // Fire the like/boost burst at the post's heart cell (state is now
    // ENGAGED). One trigger derived from the transition.
    if (pix) |g| fireEngageEffect(gpa, g, kind, target, true);
    // SUBMIT the create to the worker and RETURN immediately — no blocking
    // network call on the render thread, so the burst animation plays
    // smoothly in the main loop. The worker posts its result back; only a
    // refusal reverts the optimistic count.
    if (writer) |w| {
        if (!write_worker.submit(w, if (kind == .like) .like else .repost, item.cid, item.uri, item.cid, "", now)) {
            revertEngagement(kind, store, item.cid);
            return .{ .status = "busy, try again" };
        }
        return .{ .status = if (kind == .like) "liking..." else "boosting..." };
    } else {
        revertEngagement(kind, store, item.cid);
        return .{ .status = "write unavailable" };
    }
}

// (legacy synchronous engage path removed — the worker handles writes now)
fn revertDisengage(kind: Engagement, gpa: Allocator, store: *feed_core.Store, cid: []const u8, uri: []const u8) error{OutOfMemory}!void {
    switch (kind) {
        .like => try feed_core.revertUnlike(gpa, store, cid, uri),
        .repost => try feed_core.revertUnrepost(gpa, store, cid, uri),
    }
}

/// Undo the optimistic state for a write the worker reported as refused
/// or failed. A refused CREATE (like/repost) is undone by removing the
/// optimistic engagement (cid only). A refused DELETE (unlike/unrepost)
/// is undone by RESTORING the engagement, which needs the original record
/// uri the request carried back (revert_uri). Matches by CID; if the post
/// has scrolled out of the store, the revert is a no-op (the lookup
/// misses) — benign, the next refresh reconciles.
fn revertWrite(kind: write_worker.Request.Kind, gpa: Allocator, store: *feed_core.Store, cid: []const u8, revert_uri: []const u8) error{OutOfMemory}!void {
    switch (kind) {
        .like => feed_core.revertLike(store, cid),
        .repost => feed_core.revertRepost(store, cid),
        .unlike => try feed_core.revertUnlike(gpa, store, cid, revert_uri),
        .unrepost => try feed_core.revertUnrepost(gpa, store, cid, revert_uri),
        .loadout => {}, // loadout writes are not optimistic; nothing to revert
    }
}

/// Undo an optimistic like/repost (the CREATE direction) — used on the
/// submit-failure fallback in engageSelected when the worker queue is
/// full or unavailable. Removing the engagement needs only the CID.
fn revertEngagement(kind: Engagement, store: *feed_core.Store, cid: []const u8) void {
    switch (kind) {
        .like => feed_core.revertLike(store, cid),
        .repost => feed_core.revertRepost(store, cid),
    }
}


/// The pixel path's working set, threaded as one explicit handle
/// (house style: plain pointers, no hidden state). A7.2: cold struct,
/// size guard waived — one per run(), stack-only.
/// The live glyph-field state for the window — the cutover's working
/// set (GLYPH_FIELD_SYSTEM_DESIGN G.0), threaded as one handle (house
/// style: plain pointers, no hidden state). A7.2: cold struct, waived —
/// one per run(). The font engine renders the mono cells; the field IS
/// the UI (every glyph a physics cell); active are the playing effects;
/// particles the transient agents; hr the click map; view the
/// scroll/selection; spawn_buf scratch for the events effects emit.
/// Resolve a persisted surface (id/color entries → gpa-owned cards + blob) via
/// the catalog. No-op when the surface has no entries (caller then uses the
/// default). Sets `cards`/`blob`/`seated` on success.
fn buildSurfaceFromEntries(gpa: Allocator, se: loadout_store.SurfaceEntries, cards: *[]lens_socket.LensCard, blob: *[]const u8, seated: *u32) void {
    if (se.entries.len == 0) return;
    if (lens_catalog.loadoutFromEntries(gpa, se.entries)) |t| {
        cards.* = t[0];
        blob.* = t[1];
        seated.* = se.seated;
    } else |_| {}
}

/// Extract a surface's persist form (parallel id/color arrays + seated) from
/// its live cards + blob, into `arena`. The ids are slices into `blob`; the
/// caller (worker submit / saveAll) copies them as needed.
fn surfaceDataOf(arena: Allocator, cards: []const lens_socket.LensCard, blob: []const u8, seated: u32) loadout_store.SurfaceData {
    const ids = arena.alloc([]const u8, cards.len) catch return .{};
    const colors = arena.alloc(u8, cards.len) catch return .{};
    for (cards, 0..) |c, i| {
        const end = @min(blob.len, @as(usize, c.cid.off) + c.cid.len);
        ids[i] = if (c.cid.off <= blob.len) blob[@min(c.cid.off, blob.len)..end] else "";
        colors[i] = c.color;
    }
    return .{ .ids = ids, .colors = colors, .seated = seated };
}

/// Apply a socket action to a surface on the LOADOUT PAGE (click-only: seat,
/// recolor, expand — drag-reorder on the page is a later slice). Mutates the
/// surface's seated/color/ui and flags it dirty. Unlike the home feed handler
/// there is no scroll/close/plug-in animation — the page socket is always open.
fn applyLoadoutAction(sact: lens_socket.SocketAction, cards: []lens_socket.LensCard, blob: []const u8, seated: *u32, ui: *lens_socket.SocketUi, dirty: *bool) void {
    switch (sact) {
        .seat => |cid| {
            if (trayIndexOfCid(cards, blob, cid)) |idx| {
                seated.* = idx;
                dirty.* = true;
            }
            ui.expanded = null;
            ui.picking = null;
        },
        .expand => |cid| {
            if (trayIndexOfCid(cards, blob, cid)) |idx| {
                ui.expanded = if (ui.expanded == idx) null else idx;
            }
        },
        .collapse => ui.expanded = null,
        .open_swatch => |cid| {
            const idx = trayIndexOfCid(cards, blob, cid);
            ui.picking = if (ui.picking == idx) null else idx;
        },
        .set_color => |sc2| {
            if (trayIndexOfCid(cards, blob, sc2.lens)) |idx| {
                if (idx < cards.len) cards[idx].color = sc2.color;
                dirty.* = true;
            }
            ui.picking = null;
        },
        else => {}, // toggle_tray / reorder / get_more: not used on the page
    }
}

/// Drop a dragged page socket: reorder the surface's cards to the slot under
/// the pointer (using that socket's on-page geometry), keep the seated lens by
/// CID, and start the settle. Flags dirty. Mirrors the home-feed drop.
fn pageDragDrop(cards: []lens_socket.LensCard, blob: []const u8, seated: *u32, ui: *lens_socket.SocketUi, geom: lens_socket.Geometry, dirty: *bool) void {
    if (ui.drag_active) |d| {
        const tray: lens_socket.TrayView = .{ .cards = cards, .text = blob, .seated = seated.* };
        // Force open for the insertion math — the page socket renders open but
        // its stored `open` is false (which dropIndex would reject).
        var oui = ui.*;
        oui.open = true;
        const to: u32 = lens_socket.dropIndex(tray, oui, geom) orelse d;
        const seated_off = if (seated.* < cards.len) cards[seated.*].cid.off else 0;
        reorderTray(cards, d, to);
        for (cards, 0..) |c, ix| {
            if (c.cid.off == seated_off) {
                seated.* = @intCast(ix);
                break;
            }
        }
        ui.drag_active = to;
        ui.settle_phase = 1;
        dirty.* = true;
    }
}

/// Index of the card whose CID equals `cid` (a slice into `blob`), or null.
fn trayIndexOfCid(cards: []const lens_socket.LensCard, blob: []const u8, cid: []const u8) ?u32 {
    for (cards, 0..) |c, i| {
        const s = blob[c.cid.off..][0..c.cid.len];
        if (std.mem.eql(u8, s, cid)) return @intCast(i);
    }
    return null;
}

/// Advance the socket's drag animation one frame: lift, the per-card reflow
/// (others slide to open a gap at the insertion slot), and the drop-settle.
/// Pure easing over the persistent SocketUi state; the widget draws the result.
fn advanceSocketDrag(ui: *lens_socket.SocketUi, tray: lens_socket.TrayView, geom: lens_socket.Geometry) void {
    const ease = 0.30; // per-frame approach factor (~150ms feel at 60fps)
    const n: i32 = @intCast(tray.cards.len);
    if (ui.drag_active) |d| {
        if (ui.settle_phase == 0) {
            // Active drag: lift the ghost; reflow neighbours toward the gap.
            ui.lift += (1.0 - ui.lift) * ease;
            // dropIndex early-returns null unless the socket is open; the page
            // sockets are rendered open but their stored `open` is false, so
            // force it for the insertion math (home is already open here).
            var oui = ui.*;
            oui.open = true;
            const ins: i32 = if (lens_socket.dropIndex(tray, oui, geom)) |x| @intCast(x) else @as(i32, @intCast(d));
            var a: i32 = 0;
            while (a < n and a < @as(i32, @intCast(ui.slide.len))) : (a += 1) {
                if (a == d) continue;
                // target slot of card a when d is pulled out and re-inserted at ins
                const r = if (a < @as(i32, @intCast(d))) a else a - 1;
                const target = if (r < ins) r else r + 1;
                const desired: f32 = @floatFromInt(target - a); // -1, 0, or +1
                ui.slide[@intCast(a)] += (desired - ui.slide[@intCast(a)]) * ease;
            }
        } else {
            // Settling: drop the lift, glide the reflow back to home, finish.
            ui.lift += (0.0 - ui.lift) * ease;
            for (&ui.slide) |*s| s.* += (0.0 - s.*) * ease;
            ui.settle_phase +|= 1;
            if (ui.settle_phase > lens_socket.settle_total_frames) {
                ui.drag_active = null;
                ui.settle_phase = 0;
                ui.lift = 0;
                ui.slide = [_]f32{0} ** lens_socket.max_lenses;
            }
        }
    } else {
        // Not dragging: relax any residual offsets back to rest.
        ui.lift += (0.0 - ui.lift) * ease;
        for (&ui.slide) |*s| s.* += (0.0 - s.*) * ease;
    }
}

/// Move the card at `from` to rank `to`, sliding the rest — the L.4 reorder.
/// The CID spans travel with the moved structs (the blob is unchanged), so a
/// caller can re-find the seated card by its CID offset afterward.
fn reorderTray(cards: []lens_socket.LensCard, from: u32, to: u32) void {
    if (from == to or from >= cards.len or to >= cards.len) return;
    const moved = cards[from];
    if (from < to) {
        var k = from;
        while (k < to) : (k += 1) cards[k] = cards[k + 1];
    } else {
        var k = from;
        while (k > to) : (k -= 1) cards[k] = cards[k - 1];
    }
    cards[to] = moved;
}

/// The background config-fetch for the marketplace "View details" page. Fetching
/// an algorithm's config is a network round-trip; done on the UI thread it FREEZES
/// the app for the fetch (the "extreme lag going to the info page"). So it runs on
/// this worker — a public, unauthenticated `getRecord`, so the worker never touches
/// the shared mutable session. The run loop polls `done`, then copies the
/// page_allocator result into the render `gpa` after join (no concurrency).
/// A7.2: cold struct (one live instance, holds a thread), size guard waived.
const InspectJob = struct {
    thread: ?std.Thread = null,
    done: std.atomic.Value(bool) = .init(false),
    active: bool = false, // a fetch is running (or finished, not yet consumed)
    ok: bool = false, // a config was produced (read after done-acquire / join)
    bytes: ?[]u8 = null, // page_allocator-owned serialized config on success
    // Inputs, COPIED in so the worker never reads run-loop state (which the UI
    // thread mutates). io/env are shared but read-only / thread-safe.
    io: std.Io = undefined,
    env: ?*const std.process.Environ.Map = null,
    pds: [256]u8 = undefined,
    pds_len: usize = 0,
    repo: [128]u8 = undefined,
    repo_len: usize = 0,
    rkey: [128]u8 = undefined,
    rkey_len: usize = 0,
};

/// Worker body: a public getRecord + serialize, all off the `page_allocator` (a
/// private arena for the fetch, page_allocator for the surviving result), so the
/// render allocator is never touched. Publishes via `done` (release).
fn inspectWorker(job: *InspectJob) void {
    const a = std.heap.page_allocator;
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const scratch = arena_state.allocator();
    const cfg = algorithm_shell.fetchPublic(scratch, job.io, job.env, job.pds[0..job.pds_len], job.repo[0..job.repo_len], job.rkey[0..job.rkey_len]) catch null;
    if (cfg) |c| {
        // Serialize into page_allocator (survives the arena deinit); the main
        // thread copies it into gpa and frees this after join.
        if (algorithm_core.serialize(a, c)) |b| {
            job.bytes = b;
            job.ok = true;
        } else |_| job.ok = false;
    } else job.ok = false;
    job.done.store(true, .release);
}

/// Spawn a config fetch for (pds, repo, rkey). The strings are COPIED into the job
/// so the worker never reads run-loop state. A spawn failure completes the job as
/// a clean failure (done, ok=false) rather than hanging the loading state forever.
fn startInspect(job: *InspectJob, io: std.Io, env: ?*const std.process.Environ.Map, pds: []const u8, repo: []const u8, rkey: []const u8) void {
    const pn = @min(pds.len, job.pds.len);
    @memcpy(job.pds[0..pn], pds[0..pn]);
    job.pds_len = pn;
    const rn = @min(repo.len, job.repo.len);
    @memcpy(job.repo[0..rn], repo[0..rn]);
    job.repo_len = rn;
    const kn = @min(rkey.len, job.rkey.len);
    @memcpy(job.rkey[0..kn], rkey[0..kn]);
    job.rkey_len = kn;
    job.io = io;
    job.env = env;
    job.done.store(false, .monotonic);
    job.ok = false;
    job.bytes = null;
    job.active = true;
    job.thread = std.Thread.spawn(.{}, inspectWorker, .{job}) catch null;
    if (job.thread == null) job.done.store(true, .release); // spawn failed → done, ok=false
}

/// Join a finished fetch WITHOUT freeing its result — the caller is about to
/// CONSUME `bytes` (copy into gpa). Leaves `thread == null` so shutdown skips it.
fn joinInspect(job: *InspectJob) void {
    if (job.thread) |th| {
        th.join();
        job.thread = null;
    }
    job.active = false;
}

/// Shutdown cleanup (the defer): join any in-flight fetch and free a result the
/// loop never consumed (landed in the frame the app exits). A no-op if the loop
/// already took it (`thread == null`), so never a double-free.
fn stopInspect(job: *InspectJob) void {
    if (job.thread) |th| {
        th.join();
        job.thread = null;
        if (job.ok) if (job.bytes) |b| std.heap.page_allocator.free(b);
    }
    job.active = false;
}

/// A7.2: cold struct, waived — one per run(), the per-frame bundle of
/// shared pointers the paint path and input handler both read.
const Grid = struct {
    engine: *text_core.Engine,
    field: *field_core.Field,
    particles: *field_core.ParticleList,
    active: *effect_core.ActiveList,
    draw: *raster_core.DrawList,
    hr: *field_ui.HitList,
    hearts: *field_ui.HeartList,
    view: *field_ui.ViewState,
    spawn_buf: *std.ArrayList(field_core.SpawnEvent),
    /// Monotonic clock of the previous frame, for dt injection (B4 —
    /// the one time source). 0 until the first frame.
    last_nanos: *u64,
    /// User zoom factor for the glyph cell size (text scaling). 1.0 is
    /// the base size; '+'/'-' adjust it, clamped to [zoom_min, zoom_max].
    /// Shared so paintFrame and the pointer hit-test derive the SAME cell
    /// size from it.
    zoom: *f32,
    /// cut 5.6: premium feed pixel scroll, its content-height clamp bound,
    /// and the latest frame's button hit regions (pixel-space).
    scroll: *i32,
    content_h: *i32,
    regions: *feed_view.Regions,
    /// The active top-level Screen (index into feed_view.nav_labels): 0 = Home
    /// (the feed); the rail switches it on a click. Shared (a pointer to a run()
    /// local) so paint and the click handler agree on the same value.
    screen: *u8,
    /// THE LENS SOCKET (Home). The tray is the user's carried lens set
    /// (invariant 12); `socket_ui` is the transient open/swap state; the
    /// socket's tap targets land in `socket_hits` (its own space, tested
    /// before the feed regions). `accent` is the seated lens's palette
    /// color (§11.5), the app accent token this frame.
    socket_tray: ?lens_socket.TrayView = null,
    socket_ui: lens_socket.SocketUi = .{},
    socket_hits: *lens_socket.HitList,
    accent: u32 = feed_view.accent_house,
    /// The reply/zone sockets — only drawn on the loadout page (screen_loadout).
    reply_tray: lens_socket.TrayView = .{ .cards = &.{}, .text = "", .seated = 0 },
    reply_ui: lens_socket.SocketUi = .{},
    reply_hits: *lens_socket.HitList = undefined,
    zone_tray: lens_socket.TrayView = .{ .cards = &.{}, .text = "", .seated = 0 },
    zone_ui: lens_socket.SocketUi = .{},
    zone_hits: *lens_socket.HitList = undefined,
    /// The active Algorithms-page sub-tab (0 Loadout / 1 Marketplace / 2 Create).
    loadout_tab: u8 = 0,
    /// The Marketplace tab's browse cards (published algorithms, mapped from the
    /// AppView's rows). Empty on every other tab/screen. A value set per frame.
    market: []const feed_view.MarketAlgoCard = &.{},
    /// The simple-Create flow's state (loadout tab 2). A value set per frame.
    create: feed_view.CreateView = .{ .step = .landing, .answers = .{}, .config = discover.DEFAULT_CONFIG, .name = "", .color = 0 },
    /// The user's bench — library algorithms not in a socket (Loadout tab). A value
    /// set per frame (built from the library into the frame arena).
    bench: lens_socket.TrayView = .{ .cards = &.{}, .text = "", .seated = 0 },
    /// The transparency page's inspected algorithm (screen_transparency): its
    /// fetched config + name + ref (CID), rebuilt into a page each frame. Null
    /// config ⇒ not inspecting. Set per frame.
    /// The inspected algorithm's SERIALIZED bytes (stable; the render re-parses
    /// them into the frame arena — see the run-loop note). Empty = not inspecting.
    inspect_bytes: []const u8 = "",
    inspect_name: []const u8 = "",
    inspect_ref: []const u8 = "",
    /// On the transparency page: false = the summary, true = the byte-exact source.
    inspect_source: bool = false,
    /// True while the background config fetch is in flight (show a loading state).
    inspect_loading: bool = false,
    /// Out: layoutLoadout writes each page socket's geometry here for the
    /// shell's drag math (feed / reply / zone).
    loadout_geoms: *[3]lens_socket.Geometry = undefined,
    /// The GPU render path, present only when `gpu.init` succeeded on this
    /// window (else null → the software path renders, the rule's fallback).
    /// A pointer into run()'s `gpu_state` local; one-frame contract like the
    /// rest of Grid.
    gpu: ?*GpuState,
    /// Count of staged-but-unrevealed new posts this frame — drives the Home
    /// "N new posts" pill. A value (set per frame), not a pointer.
    pending_new: usize = 0,
    /// The pointer's position in LOGICAL layout coords (the space regions live
    /// in), or <0 when off-window — drives the hover highlight. Set per frame.
    hover_x: i32 = -1,
    hover_y: i32 = -1,
    /// The open zone's display tag (e.g. "water") when on the zone page — the
    /// "#name" title in its header. "" on every other screen.
    zone_title: []const u8 = "",
    /// The zone CATALOG for the browse screen (`screen_zones_browse`): the known
    /// zones with post counts. Empty on every other screen.
    zones: []const feed_view.ZoneCard = &.{},
    /// The selected SECTION on the Settings screen (master–detail state). Index
    /// into `settings_view.sections`; ignored off `screen_settings`.
    settings_section: u8 = 0,
    /// Runtime on/off of every Settings toggle (bitset by global row index).
    settings_toggles: u64 = 0,
    /// The viewer's real identity for the Settings → Account info rows.
    settings_account: feed_view.SettingsAccount = .{},
    /// Packed selected-option index per CHOICE (3 bits each); drives the choice
    /// values + picker checkmark. `settings_picking` = the open choice's action
    /// (255 = none). `field_gain` is the brightness the Field-intensity choice
    /// resolves to (applied to the GPU field each frame).
    settings_choices: u64 = 0,
    settings_picking: u8 = 255,
    /// Zat Chat (U3, dev-gated): the DM store (null = gate off), the selected
    /// conversation, and the composer strip's live draft. The view-models are
    /// built per frame in paintFrame from these (queries over the one store).
    chat_store: ?*const chat_core.Store = null,
    chat_sel: ?chat_core.ConvIndex = null,
    chat_draft: []const u8 = "",
    chat_input_focus: bool = false,
    chat_composing: bool = false,
    chat_compose: []const u8 = "",
    chat_compose_status: []const u8 = "",
    /// The typing-indicator SIGNAL (U6a): true = the counterparty is typing
    /// (an encrypted ping armed the deadline).
    chat_typing: bool = false,
    /// Last chat keystroke (monotonic ns) for the caret blink clock.
    chat_key_ns: u64 = 0,
    field_gain: f32 = 0.9,
    /// Toy Box "Julia mode" active — the field renderer pinks its glyph ink.
    julia: bool = false,
    /// "Ripples on like" — the like fires the field ripple + red dye.
    ripples_on: bool = true,
    /// "Living glyph field" — the field renders (off ⇒ flat background).
    field_on: bool = true,
    /// Toy Box "CRT scanlines" — a scanline overlay over the whole frame.
    crt_on: bool = false,
    /// Toy Box "Show frame timing" — an fps/ms overlay.
    frametiming_on: bool = false,
};

// ===========================================================================
// The GPU render path (Phase 6.4): the living glyph field (a pure CPU wave
// simulation, core/glyph_field.zig) rendered grid-intensity + the premium feed,
// both on the GPU via shell/gpu.zig. Brought up additively when the window
// opens and `gpu.init` succeeds; the SOFTWARE path stays the automatic fallback
// (E2: degrade to a plainer window, never a dead one). The reference pipeline is
// src/gpu_preview.zig; this is that pipeline, driven by the live app's input.
// ===========================================================================

/// Field glyph cell — big enough to read the symbols, still many of them
/// (matches the preview). The field grid is win/cell in physical pixels.
const field_cell_w: u16 = 13;
const field_cell_h: u16 = 17;
/// The feed is authored for a fixed LOGICAL width and scaled to FILL the
/// window (DPI): scale = window_width / design_w. So the three-pane keeps its
/// cohesion at any window size and the type lands at design size, crisp.
const design_w: u32 = 1340;
/// Ambient-forcing knobs: a slow drifting swell so the still field breathes.
const amb_amp: f32 = 0.010;
const amb_scale: f32 = 0.060;
const amb_drift: f32 = 0.10;
/// 0xFF181812 — the same background the software path clears to.
const gpu_clear_r: f32 = @as(f32, 0x18) / 255.0;
const gpu_clear_g: f32 = @as(f32, 0x18) / 255.0;
const gpu_clear_b: f32 = @as(f32, 0x12) / 255.0;
// Julia mode is a LIGHT theme: the field backdrop is a soft pink-white (not the
// dark room), so the field reads as pink symbols on white paper.
const julia_clear_r: f32 = @as(f32, 0xF7) / 255.0;
const julia_clear_g: f32 = @as(f32, 0xE9) / 255.0;
const julia_clear_b: f32 = @as(f32, 0xF1) / 255.0;

fn uiScale(physical_w: u32) f32 {
    return @as(f32, @floatFromInt(physical_w)) / @as(f32, @floatFromInt(design_w));
}
fn logicalH(physical_w: u32, physical_h: u32) u32 {
    return @max(1, @as(u32, @intFromFloat(@as(f32, @floatFromInt(physical_h)) / uiScale(physical_w))));
}

/// The GPU path's working set, one per run(). A7.2: cold struct, size guard
/// waived — stack-only, exactly one. The CPU sim (`field`) + shell-side
/// ambient `bias` + queued `splashes` feed the pure `glyph_field.step`; the
/// renderers (`grid`, `ramp`, `feed`) draw it. `t`/`mcx`/`mcy` are the animation
/// clock and the cursor-light cell (top-down; <0 = no cursor).
const GpuState = struct {
    g: gpu.Gpu,
    field: glyph_field.Field,
    grid: gpu.FieldGrid,
    ramp: gpu.FieldRenderer,
    feed: gpu.Feed,
    /// The PREVIOUS screen's feed verts, kept for the screen-switch CROSSFADE:
    /// on a screen change `feed`↔`feed_prev` swap, then `feed` rebuilds with the
    /// new content while `feed_prev` holds the old; we draw old at (1-fade) + new
    /// at fade. The nav rail is in BOTH so it stays solid; only content dissolves.
    feed_prev: gpu.Feed,
    fade_t: f32 = 1, // 1 = settled (no fade); 0 just after a screen switch
    fade_screen: u8 = 0, // the screen `feed` currently holds (edge-detects switches)
    /// The nav rail as its OWN tile (decomposition) — a separate vert buffer so
    /// it can slide/compress independently of the content. Built each rebuild.
    rail: gpu.Feed,
    /// A small overlay vert buffer for the HOVER highlight (post wash + button
    /// highlight), rebuilt each frame and drawn between the field and the feed so
    /// the highlights sit BEHIND the post content. Separate from `feed` so a
    /// pointer move never rebuilds the cached feed verts.
    hover: gpu.Feed,
    /// Eased hover opacity (0→1) so the highlight FADES in/out instead of
    /// snapping — the "hover animation" feel.
    hover_alpha: f32 = 0,
    /// Read-only text selection of the ROOTED post's body (thread screen). `sel`
    /// is its own overlay vert buffer (the highlight rects, drawn BEHIND the feed
    /// text like the hover wash); `sel_glyphs` is the rooted body's glyph geometry
    /// captured on each feed rebuild (feed_view.SelGlyphs — the one selectable
    /// post, ZONES inv. 4). `sel_anchor`/`sel_focus` are caret indices into it
    /// (0..len), equal = no selection; `sel_dragging` while the button is held.
    sel: gpu.Feed,
    sel_glyphs: feed_view.SelGlyphs = .empty,
    sel_anchor: u32 = 0,
    sel_focus: u32 = 0,
    sel_dragging: bool = false,
    /// The right-click context menu (Copy / Select all) over the rooted post.
    /// `menu` is its own overlay vert buffer (drawn last, on top of everything);
    /// `menu_x`/`menu_y` are its top-left in logical pixels. Closed by an item
    /// click, a click outside, Escape, or a scroll.
    menu: gpu.Feed,
    menu_open: bool = false,
    menu_x: i32 = 0,
    menu_y: i32 = 0,
    /// A like's red dye REVEALED gradually (synced to the spark animation) rather
    /// than blipping in: while frames>0, advanceField injects a fraction of the
    /// dye ring at (cx,cy) each step. Defaults so they ride the struct literal.
    dye_reveal_cx: u32 = 0,
    dye_reveal_cy: u32 = 0,
    dye_reveal_frames: u32 = 0,
    /// The animated like-heart pass (SDF fill + pop + star burst), drawn over
    /// the feed for each active like effect this frame.
    heart: gpu.HeartRenderer,
    /// Toy Box "CRT scanlines" — a full-screen post-process drawn last.
    scanlines: gpu.Scanlines,
    /// "Show frame timing" — smoothed frame period (ms) + the last frame's clock,
    /// for the fps/ms overlay. 0 until the first frame pair.
    frame_ms: f32 = 0,
    last_frame_nanos: u64 = 0,
    /// The SDF-icon pass (the heart's technique generalised) — crisp engagement /
    /// nav icons, one draw call each, replacing the aliased line-art.
    icon: gpu.IconRenderer,
    bias: []f32,
    splashes: std.ArrayList(glyph_field.Splash),
    cols: u32,
    rows: u32,
    t: f32,
    mcx: f32,
    mcy: f32,
    /// Toy Box "Julia mode" toggle-ON spark: a one-shot burst of SDF hearts that
    /// fly out from the switch, drawn ON TOP (so it isn't hidden behind a panel
    /// like the field ripple is). `t` runs 1→0 over the burst; x,y = origin in
    /// framebuffer px.
    julia_burst_t: f32 = 0,
    julia_burst_x: f32 = 0,
    julia_burst_y: f32 = 0,
    /// Last frame's DPI scale (physical_w / design_w) — the feed lays out in
    /// LOGICAL pixels, so the input handlers read this to map a click/region
    /// back to physical pixels and thence to a field cell. Refreshed each
    /// frame by paintFrameGpu.
    scale: f32,
    /// Dirty signature of the last-built feed (scroll + window size + each
    /// post's identity/counts/flags). The field animates every frame, but the
    /// feed — transform + per-post text measurement + vertex build — is rebuilt
    /// ONLY when this changes, so a large feed does not pay that cost 60×/sec.
    feed_sig: u64,
    /// Content-only signature (excludes scroll + window height): when it
    /// changes, the per-post `heights` cache is reset. So a pure SCROLL (which
    /// changes feed_sig but not this) keeps the cache and skips re-measuring
    /// every post — the scroll-lag fix.
    feed_content_sig: u64,
    /// Per-post measured-height cache handed to feed_view.layout. Scroll-
    /// invariant; sized to the post count, reset to -1 on content/width change.
    heights: []i32,
    /// Monotonic clock of the last simulation STEP. The field advances on a
    /// fixed wall-clock timestep (≈60 Hz) so it evolves at a constant real-time
    /// rate no matter how fast the loop spins — without this, a fast input
    /// stream (mouse motion floods events → the loop runs far above 60 fps)
    /// stepped the sim every lap and the WHOLE field's motion sped up while the
    /// pointer moved. 0 until the first frame.
    last_step_nanos: u64,
    /// Set when a thread is opened / re-focused: paintFrameGpu scrolls the
    /// focused post to the top (ancestors remain above, scrollable up) once the
    /// per-post heights are valid, then clears it. (Thread view only.)
    scroll_to_focus: bool = false,
    /// Sticky CHAIN header (thread "chain"): the extent + identity are captured on
    /// the feed rebuild (content-space offsets, scroll-independent); the per-frame
    /// overlay uses them + the live scroll to pin / catch-up / push-out. Identity
    /// is OWNED (copied) so it survives across non-rebuild frames.
    chain_present: bool = false,
    chain_top_off: i32 = 0,
    chain_bottom_off: i32 = 0,
    chain_pin_y: i32 = 0,
    chain_tint: u32 = 0,
    chain_initial: u21 = ' ',
    chain_name: [64]u8 = undefined,
    chain_name_len: u8 = 0,
    chain_handle: [80]u8 = undefined,
    chain_handle_len: u8 = 0,
    chain_catchup_t: f32 = 0, // 0 = above/hidden, 1 = settled at the pin
    chain_was_pinned: bool = false, // edge-detect the scroll-down pin to fire the catch-up
    /// Tiling foundation (S.2): the pane geometry as ANIMATED state. The live
    /// sub-pixel pane boundaries (`geom_*`) spring toward the current screen's
    /// target (feed_view.paneGeomFor), so switching screens GLIDES the panes
    /// instead of snapping. `gv_*` are the velocities; seeded on the first frame.
    /// Geometry is a SOLVED partition each frame — a blend of two valid layouts
    /// is itself valid, so the morph never overlaps.
    geom_init: bool = false,
    geom_rail_x: f32 = 0,
    geom_col_x: f32 = 0,
    geom_col_w: f32 = 0,
    geom_lx: f32 = 0,
    geom_cw: f32 = 0,
    geom_side_x: f32 = 0,
    gv_rail_x: f32 = 0,
    gv_col_x: f32 = 0,
    gv_col_w: f32 = 0,
    gv_lx: f32 = 0,
    gv_cw: f32 = 0,
    gv_side_x: f32 = 0,
    /// Content-driven SEARCH tile (sidebar): `search_open` springs 0..1 toward
    /// `search_want`; while it moves it pushes the trending/follow tiles down
    /// (a cheap reposition — no relayout). Toggled by '/'.
    search_open: f32 = 0,
    search_v: f32 = 0,
    search_want: bool = false,
    /// ZONES test: the nav rail relocates to the right on the Zones tab. Springs
    /// 0 (rail at home/left) → 1 (rail slid to the right). A revertable demo.
    zones_t: f32 = 0,
    zones_v: f32 = 0,
    /// Hover-expand of the condensed right rail: 0 = icons-only strip, 1 = full
    /// labelled rail. Springs toward 1 while the cursor is over the right strip.
    rail_hover_t: f32 = 0,
    rail_hover_v: f32 = 0,
    /// The LIVE content column (logical px) — set each rebuild from the animated
    /// geometry. The field's panel-softening ("distortion") reads THIS so it
    /// tracks the content as it widens/shifts, instead of the static metricsPage.
    content_x: i32 = 0,
    content_w: i32 = 0,
    /// ALGORITHMS test: the LEFT rail condenses in place (stays left) and the
    /// content expands. `algo_t` springs on the loadout screen; `left_hover_t`
    /// springs while the cursor is over the (left) rail, re-expanding it.
    algo_t: f32 = 0,
    algo_v: f32 = 0,
    left_hover_t: f32 = 0,
    left_hover_v: f32 = 0,
    /// Zat Chat motion (U6a): the newest bubble's send/arrival springs, the
    /// typing indicator's grow/melt spring + its pulse clock, and the store
    /// watermark the triggers derive from. ONE trigger site — the observed
    /// state transition (the store grew), per ANIMATION_SYSTEM_NOTES.
    chat_send_t: f32 = 1,
    chat_send_v: f32 = 0,
    chat_arrive_t: f32 = 1,
    chat_arrive_v: f32 = 0,
    chat_typing_t: f32 = 0,
    chat_typing_v: f32 = 0,
    chat_typing_phase: f32 = 0,
    chat_seen_msgs: usize = 0,
    /// False until the Messages screen has been seen once — the history
    /// restore and any pre-visit arrivals must NOT animate on first paint.
    chat_seen_valid: bool = false,
    /// The chat springs' frame-clock watermark (monotonic ns): motion
    /// advances by MEASURED time, not a fixed per-frame tick.
    chat_clock_ns: u64 = 0,
};

/// Spring one geometry boundary toward its target (S.2). Stiff + just over
/// critical damping → fast settle, no overshoot (overshoot would let a pane
/// boundary cross past its target mid-morph).
fn springGeom(cur: *f32, vel: *f32, target: f32, dt: f32) void {
    const k: f32 = 150.0;
    const c: f32 = 25.0;
    vel.* += (-k * (cur.* - target) - c * vel.*) * dt;
    cur.* += vel.* * dt;
}

/// The message-motion spring (U6a): stiff and mildly UNDER-damped
/// (damping ratio ≈ 0.77) — a sent bubble snaps into its seat in ~0.35s
/// with one small overshoot, the tuned response of a platform-native
/// message send. Geometry morphs keep springGeom (no overshoot — a pane
/// boundary must not cross its target); a bubble should breathe past its
/// seat and settle.
fn springPop(cur: *f32, vel: *f32, target: f32, dt: f32) void {
    const k: f32 = 380.0;
    const c: f32 = 30.0;
    vel.* += (-k * (cur.* - target) - c * vel.*) * dt;
    cur.* += vel.* * dt;
}

/// Step the WHOLE geometry toward the screen's target — content column AND
/// glass move together (no "finished content waiting for the glass"). A convex
/// blend of two valid layouts is itself valid, so it never overlaps. The text
/// width (cw) is folded into the height-cache key by the caller, so a morph that
/// changes cw re-measures — but those are the wide NON-post pages (nothing heavy
/// to measure), while the post pages share one reading width (cache stays warm).
fn stepGeomAnim(gs: *GpuState, target: feed_view.PaneGeom, dt: f32) bool {
    const tr: f32 = @floatFromInt(target.rail_x);
    const tcx: f32 = @floatFromInt(target.col_x);
    const tcw: f32 = @floatFromInt(target.col_w);
    const tlx: f32 = @floatFromInt(target.lx);
    const tcwd: f32 = @floatFromInt(target.cw);
    const tsx: f32 = @floatFromInt(target.side_x);
    if (!gs.geom_init) {
        gs.geom_init = true;
        gs.geom_rail_x = tr;
        gs.geom_col_x = tcx;
        gs.geom_col_w = tcw;
        gs.geom_lx = tlx;
        gs.geom_cw = tcwd;
        gs.geom_side_x = tsx;
        return false;
    }
    springGeom(&gs.geom_rail_x, &gs.gv_rail_x, tr, dt);
    springGeom(&gs.geom_col_x, &gs.gv_col_x, tcx, dt);
    springGeom(&gs.geom_col_w, &gs.gv_col_w, tcw, dt);
    springGeom(&gs.geom_lx, &gs.gv_lx, tlx, dt);
    springGeom(&gs.geom_cw, &gs.gv_cw, tcwd, dt);
    springGeom(&gs.geom_side_x, &gs.gv_side_x, tsx, dt);
    const far = @abs(gs.geom_rail_x - tr) + @abs(gs.geom_col_x - tcx) + @abs(gs.geom_col_w - tcw) +
        @abs(gs.geom_lx - tlx) + @abs(gs.geom_cw - tcwd) + @abs(gs.geom_side_x - tsx);
    return far > 0.75;
}

/// The live (animated) geometry as a PaneGeom to hand `layout()`. The glass
/// width is clamped to never be narrower than the text column, so the text
/// never overflows the panel mid-widen. `wide` snaps to the target's value.
fn liveGeom(gs: *const GpuState, target: feed_view.PaneGeom) feed_view.PaneGeom {
    const col_w: i32 = @intFromFloat(@round(@max(gs.geom_col_w, gs.geom_cw)));
    return .{
        .rail_x = @intFromFloat(@round(gs.geom_rail_x)),
        .col_x = @intFromFloat(@round(gs.geom_col_x)),
        .col_w = col_w,
        .lx = @intFromFloat(@round(gs.geom_lx)),
        .cw = @intFromFloat(@round(gs.geom_cw)),
        .side_x = @intFromFloat(@round(gs.geom_side_x)),
        .wide = target.wide,
    };
}

/// Bring up the GPU path on the live window. Any failure (no GL, shader/pack
/// error, OOM) propagates so the caller falls back to software (E2). Each
/// acquired resource has an errdefer so a mid-init failure frees cleanly (C5).
fn initGpuState(gpa: Allocator, engine: *text_core.Engine, win: *window_shell.Window) !GpuState {
    var g = try gpu.init(win.wid);
    errdefer gpu.deinit(&g);
    const w: u32 = win.fb.width;
    const h: u32 = win.fb.height;
    gpu.setViewport(@intCast(w), @intCast(h));

    var feed = try gpu.initFeed(gpa);
    errdefer gpu.feedDeinit(&feed, gpa);
    var feed_prev = try gpu.initFeed(gpa);
    errdefer gpu.feedDeinit(&feed_prev, gpa);
    var rail = try gpu.initFeed(gpa);
    errdefer gpu.feedDeinit(&rail, gpa);
    var hover = try gpu.initFeed(gpa);
    errdefer gpu.feedDeinit(&hover, gpa);
    var sel = try gpu.initFeed(gpa);
    errdefer gpu.feedDeinit(&sel, gpa);
    var menu = try gpu.initFeed(gpa);
    errdefer gpu.feedDeinit(&menu, gpa);
    const ramp = try gpu.initFieldRenderer(gpa, engine, field_cell_w, field_cell_h);
    const grid = try gpu.initFieldGrid();
    const heart = try gpu.initHeartRenderer();
    const scanlines = try gpu.initScanlines();
    const icon_r = try gpu.initIconRenderer();

    const fgrid = gpuFieldGrid(w, h);
    const cols = fgrid.cols;
    const rows = fgrid.rows;
    var field: glyph_field.Field = undefined;
    try glyph_field.init(gpa, &field, cols, rows);
    errdefer glyph_field.deinit(gpa, &field);
    const bias = try gpa.alloc(f32, cols * rows);
    errdefer gpa.free(bias);

    return .{
        .g = g,
        .field = field,
        .grid = grid,
        .ramp = ramp,
        .feed = feed,
        .feed_prev = feed_prev,
        .rail = rail,
        .hover = hover,
        .sel = sel,
        .menu = menu,
        .heart = heart,
        .scanlines = scanlines,
        .icon = icon_r,
        .bias = bias,
        .splashes = .empty,
        .cols = cols,
        .rows = rows,
        .t = 0,
        .mcx = -1,
        .mcy = -1,
        .scale = uiScale(w),
        .feed_sig = 0,
        .feed_content_sig = 0,
        .heights = &.{},
        .last_step_nanos = 0,
    };
}

/// A cheap dirty signature of the rendered feed: the scroll offset, the window
/// size, and each post's identity (cid) + the fields that affect its render
/// (engagement counts + viewer flags). Hashing the whole feed is far cheaper
/// (a few µs) than the layout it gates (per-post text measurement). Relative
/// age is intentionally excluded — it would force a rebuild every second; ages
/// refresh on the next scroll / new post / engagement instead.
fn feedSignature(items: []const feed_core.TimelineItem, scroll: i32, w: u32, h: u32) u64 {
    var hh = std.hash.Wyhash.init(0x7A74_F1E1);
    hh.update(std.mem.asBytes(&scroll));
    hh.update(std.mem.asBytes(&w));
    hh.update(std.mem.asBytes(&h));
    const n: u64 = items.len;
    hh.update(std.mem.asBytes(&n));
    for (items) |it| {
        hh.update(it.cid);
        hh.update(std.mem.asBytes(&it.like_count));
        hh.update(std.mem.asBytes(&it.repost_count));
        hh.update(std.mem.asBytes(&it.reply_count));
        hh.update(std.mem.asBytes(&it.item_flags));
        // Thread view-state: focus moving / collapse / stitch all change the
        // render, so fold them in (else tapping a different post in the same
        // thread wouldn't rebuild the cached feed verts).
        hh.update(std.mem.asBytes(&it.is_focus));
        hh.update(std.mem.asBytes(&it.depth));
        hh.update(std.mem.asBytes(&it.stitched));
        hh.update(std.mem.asBytes(&it.collapsed));
    }
    return hh.final();
}

fn deinitGpuState(gpa: Allocator, gs: *GpuState) void {
    gs.splashes.deinit(gpa);
    if (gs.heights.len > 0) gpa.free(gs.heights);
    gpa.free(gs.bias);
    glyph_field.deinit(gpa, &gs.field);
    gpu.feedDeinit(&gs.feed, gpa);
    gpu.feedDeinit(&gs.feed_prev, gpa);
    gpu.feedDeinit(&gs.rail, gpa);
    gpu.feedDeinit(&gs.hover, gpa);
    gpu.feedDeinit(&gs.sel, gpa);
    gpu.feedDeinit(&gs.menu, gpa);
    gs.sel_glyphs.deinit(gpa);
    gpu.deinit(&gs.g);
}

/// Refit the CPU field grid + ambient-bias buffer to a new window size. New
/// buffers allocated BEFORE the old are freed, so a failed alloc leaves the
/// existing state (and its deinit) valid (C5). The dye/height reset on resize
/// is accepted for v1 (the field re-seeds calm); reproject later if wanted.
fn resizeGpuField(gpa: Allocator, gs: *GpuState, w: u32, h: u32) !void {
    const fgrid = gpuFieldGrid(w, h);
    const cols = fgrid.cols;
    const rows = fgrid.rows;
    var newfield: glyph_field.Field = undefined;
    try glyph_field.init(gpa, &newfield, cols, rows);
    errdefer glyph_field.deinit(gpa, &newfield);
    const new_bias = try gpa.alloc(f32, cols * rows);
    glyph_field.deinit(gpa, &gs.field);
    gs.field = newfield;
    gpa.free(gs.bias);
    gs.bias = new_bias;
    gs.cols = cols;
    gs.rows = rows;
}

/// Append the LIKE burst — a splash RECIPE: a strong central kick plus a ring
/// of six satellites, all staining the medium red — at field cell (gx,gy).
/// This is the heart-burst as energy injected into the field (design §1). A
/// queue-full append is dropped silently (E4: a missed effect must never break
/// the action). Mirrors the preview's recipe + the spec's tuning.
/// Read a functional settings TOGGLE's runtime bit by its action — maps the
/// action → its global row index (`settings_view.rowOf`) → the `toggle_bits`
/// bit. False if the action isn't a toggle in the table. The generalized form
/// of the Julia-mode wiring: each functional toggle reads its bit this way.
fn toggleOn(bits: u64, action: u8) bool {
    return if (settings_view.rowOf(action)) |i| (bits >> i) & 1 != 0 else false;
}

/// Pack the per-choice selected indices into the 3-bits-each word `layout` reads.
fn packChoices(sel: []const u8) u64 {
    var p: u64 = 0;
    for (sel, 0..) |s, i| p |= @as(u64, s & 7) << @intCast(i * 3);
    return p;
}

/// The live selected option index for a choice action (0 if it isn't a choice).
fn choiceSel(sel: []const u8, action: u8) u8 {
    return if (settings_view.choiceIndex(action)) |i| sel[i] else 0;
}

/// "Accent" choice → an accent override, or null for "Auto" (follow the lens).
/// Option order matches settings_view.choices: Auto, Amber, Blue, Green, Violet,
/// Rose, Teal (the lens-socket palette colours).
fn accentChoiceColor(opt: u8) ?u32 {
    return switch (opt) {
        1 => feed_view.accent_house, // Amber (house)
        2 => 0xFF4A9EFF, // Blue
        3 => 0xFF3FC97E, // Green
        4 => 0xFF9B7BFF, // Violet
        5 => 0xFFFF5C8A, // Rose
        6 => 0xFF33C2C2, // Teal
        else => null, // 0 = Auto
    };
}

/// "Field intensity" choice → the field's uGain. Subtle / Normal / Vivid.
fn fieldGainFor(opt: u8) f32 {
    return switch (opt) {
        0 => 0.5, // Subtle
        2 => 1.5, // Vivid
        else => 0.9, // Normal (the default)
    };
}

fn pushLikeSplash(gpa: Allocator, gs: *GpuState, gx: u32, gy: u32, with_dye: bool) void {
    if (gs.cols == 0 or gs.rows == 0) return;
    const sx = @min(gx, gs.cols - 1);
    const sy = @min(gy, gs.rows - 1);
    // A strong central splash THROWS the wave; two concentric rings carry it
    // OUTWARD, so a like visibly shoots out and ripples. The WAVE fires once here
    // (dye = 0); the RED is faded in separately over the next ~18 steps (armed
    // below), synced to the spark — so the colour grows in instead of blipping.
    gs.splashes.append(gpa, .{ .x = sx, .y = sy, .radius = 6, .amp = 3.6, .dye = 0 }) catch {};
    const ring_dist = [_]f32{ 5.0, 9.0 };
    const ring_amp = [_]f32{ 1.8, 1.1 };
    for (ring_dist, ring_amp) |dist, amp| {
        var k: u32 = 0;
        while (k < 8) : (k += 1) {
            const ang = @as(f32, @floatFromInt(k)) * (6.2831853 / 8.0);
            const ox: i32 = @intFromFloat(@cos(ang) * dist);
            const oy: i32 = @intFromFloat(@sin(ang) * dist);
            const rx = std.math.clamp(@as(i32, @intCast(sx)) + ox, 0, @as(i32, @intCast(gs.cols - 1)));
            const ry = std.math.clamp(@as(i32, @intCast(sy)) + oy, 0, @as(i32, @intCast(gs.rows - 1)));
            gs.splashes.append(gpa, .{ .x = @intCast(rx), .y = @intCast(ry), .radius = 3, .amp = amp, .dye = 0 }) catch {};
        }
    }
    // Arm the gradual dye reveal at the centre — but ONLY for a like. The red
    // dye is the heart's alone (repost gets the colourless ripple above, no
    // stain; a boost-green dye is future per-effect work, GLYPH_FIELD spec).
    if (with_dye) {
        gs.dye_reveal_cx = sx;
        gs.dye_reveal_cy = sy;
        gs.dye_reveal_frames = dye_reveal_frames_total;
    }
}

/// Toy Box "Julia mode" — the over-the-top toggle-ON celebration: sparks fly out
/// of the SWITCH as a bloom of wave splashes, traced along a HEART curve so the
/// living field pulses a heart of ripples outward then relaxes. WAVE only
/// (dye = 0), so nothing accumulates across toggles. One call per ON-flip; ~17
/// one-shot splashes (the like burst is the same mechanism), negligible — the
/// splash buffer is cleared every field step. `(cx, cy)` is a field cell.
fn pushJuliaBurst(gpa: Allocator, gs: *GpuState, cx: i32, cy: i32) void {
    if (gs.cols == 0 or gs.rows == 0) return;
    const cols_i: i32 = @intCast(gs.cols);
    const rows_i: i32 = @intCast(gs.rows);
    const cl = struct {
        fn f(v: i32, hi: i32) u16 {
            return @intCast(std.math.clamp(v, 0, hi - 1));
        }
    }.f;
    // A bright central pulse at the switch.
    gs.splashes.append(gpa, .{ .x = cl(cx, cols_i), .y = cl(cy, rows_i), .radius = 7, .amp = 4.5, .dye = 0 }) catch {};
    // Splashes traced along the classic heart parametric curve (scaled to cells,
    // screen-y flipped so the point sits at the bottom): the ripples bloom a heart.
    const n: u32 = 16;
    const sscale: f32 = 0.9;
    var k: u32 = 0;
    while (k < n) : (k += 1) {
        const t = @as(f32, @floatFromInt(k)) * (6.2831853 / @as(f32, @floatFromInt(n)));
        const s = @sin(t);
        const hx = 16.0 * s * s * s;
        const hy = 13.0 * @cos(t) - 5.0 * @cos(2.0 * t) - 2.0 * @cos(3.0 * t) - @cos(4.0 * t);
        const ox: i32 = @intFromFloat(hx * sscale);
        const oy: i32 = @intFromFloat(-hy * sscale); // screen y is down
        gs.splashes.append(gpa, .{ .x = cl(cx + ox, cols_i), .y = cl(cy + oy, rows_i), .radius = 3, .amp = 1.8, .dye = 0 }) catch {};
    }
}

/// THE single source of truth for the glyph cell size for the CELL-PATH
/// fallback. Two facts drive it: (1) the cell HEIGHT is the pixel size the
/// font rasterizes at, and (2) the cell WIDTH is sized to a font advance at
/// that height. The UI face is now PROPORTIONAL (Inter), which has no single
/// advance; we size the cell to 'M' (~0.765× px, the wide reference) so the
/// widest glyph never overflows its cell on this fallback — proportional text
/// reads a little loose here, the accepted cost of the fallback (the premium
/// GPU path uses real per-glyph advances and is unaffected). A bigger window →
/// taller glyphs → larger text, at a roughly constant column count.
///
/// The ratio is a stable font constant, so the pure cellSize can hold it
/// without calling the engine (B2 preserved). It is asserted against the real
/// 'M' metric in a core test (text.zig) so it cannot silently drift.
const glyph_advance_ratio: f32 = 0.765; // measured: advance(M)/px for Inter
/// Target columns the window aims to show at zoom 1.0 — cells scale so
/// roughly this many fit, so widening the window scales text UP rather
/// than packing in more small cells. [TUNE].
const target_cols: f32 = 70;
/// Glyph-height bounds (px): legible when small, dense enough for the
/// physics when large. [TUNE].
const glyph_h_min: f32 = 14;
const glyph_h_max: f32 = 40;
/// Zoom multiplies the window-derived size. [TUNE].
const zoom_min: f32 = 0.6;
const zoom_max: f32 = 2.2;

/// The field grid never shrinks below this many cells, so even a tiny window
/// shows a coherent glyph field rather than a sparse smear. ONE floor for every
/// surface and both render paths (D6): the home/compose/profile software sites
/// had drifted to 24/8 vs 16/6 and the GPU path to 8/8 — same window, so that
/// was change-amplification drift, not intent. The floor binds only at
/// degenerate sizes; the field is a transient background (wiped on resize, §7).
const field_grid_min_cols: u32 = 24;
const field_grid_min_rows: u32 = 8;

/// SOFTWARE-path field grid: how many `cellSize` cells tile the framebuffer
/// (u16, as `field_core.init` wants). The single source for the home, compose,
/// and profile software paths — derive the grid here, never inline (D6).
fn softFieldGrid(fb_w: u32, fb_h: u32, cell_w: u16, cell_h: u16) struct { cols: u16, rows: u16 } {
    return .{
        .cols = @intCast(@max(field_grid_min_cols, fb_w / cell_w)),
        .rows = @intCast(@max(field_grid_min_rows, fb_h / cell_h)),
    };
}

/// GPU-path field grid: the fixed `field_cell_*` cells tile the window (u32, as
/// `glyph_field.init` wants). The single source for GPU init AND resize so the
/// two can never derive the grid differently (the CLAUDE.md §6 unify item).
fn gpuFieldGrid(w: u32, h: u32) struct { cols: u32, rows: u32 } {
    return .{
        .cols = @max(field_grid_min_cols, w / field_cell_w),
        .rows = @max(field_grid_min_rows, h / field_cell_h),
    };
}

/// Derive the integer cell size from the WINDOW width and the user zoom.
/// Pure; the single place the (window,zoom)→pixels mapping lives, so the
/// render path, the pointer hit-test, and the grid-dimension math can
/// never disagree (all call it with the same window width).
fn cellSize(win_w: u32, zoom: f32) struct { w: u16, h: u16 } {
    const z = std.math.clamp(zoom, zoom_min, zoom_max);
    // Width that fits target_cols across the window, zoomed. That width is
    // a glyph ADVANCE; convert it to the glyph HEIGHT the font needs, clamp
    // the height to legible bounds, then set width back to the true advance
    // at that height — so the cell and the glyph are exactly the same width.
    const fitted_w = (@as(f32, @floatFromInt(@max(1, win_w))) / target_cols) * z;
    const h = std.math.clamp(fitted_w / glyph_advance_ratio, glyph_h_min, glyph_h_max);
    const w = h * glyph_advance_ratio;
    return .{
        .w = @max(1, @as(u16, @intFromFloat(@round(w)))),
        .h = @max(1, @as(u16, @intFromFloat(@round(h)))),
    };
}

/// The simulation's injected RNG. Seeded once; the field's evolution is
/// deterministic given the seed + the dt sequence (B2). A process-
/// lifetime source is fine here — it is the SHELL's injected randomness,
/// not core state; the core never reaches for it, the shell hands it in
/// at the one call site below (B4).
var sim_rng = std.Random.DefaultPrng.init(0x7A74_2026);

/// Render the timeline. The window earns the LIVING GLYPH FIELD (G.0):
/// the feed is laid out into a mono grid, effects advance, particles
/// integrate, and compose maps the whole simulation to pixels — every
/// frame a pure transform with dt injected from the monotonic clock
/// (B4). Everything else (terminal, or a window whose font engine
/// failed) keeps the cell frame + diff/present pair. ONE funnel, so
/// interim status flashes render through the same path (D6).
fn paintFrame(
    gpa: Allocator,
    out: *std.Io.Writer,
    arena: Allocator,
    prev: *tui.Surface,
    next: *tui.Surface,
    backend: Backend,
    pix: ?Grid,
    /// The ACTIVE view's posts — Home's timeline, or a profile/zone query. ONE
    /// list of view-models over the shared store, chosen by the caller; the
    /// renderer and input paths key off it uniformly (ZONES invariant 4).
    view_items: []const feed_core.TimelineItem,
    /// The profile header band, non-null only on the profile screen.
    profile_header: ?feed_view.ProfileHeader,
    state: *timeline_ui.UiState,
    revealed: []const []const u8,
    now: i64,
    account_handle: []const u8,
    status: []const u8,
) !void {
    if (pix) |g| switch (backend) {
        .window => |win| {
            if (view_items.len > 0 and state.selected >= view_items.len) state.selected = @intCast(view_items.len - 1);
            // Phase 6.4: when the GPU path is live, render the field + feed on
            // the GPU and return; the software path below is the fallback.
            if (g.gpu) |gs| {
                try paintFrameGpu(gpa, arena, win, g, gs, view_items, profile_header, now);
                return;
            }
            // Cell size scales with the user zoom; the grid reflows to
            // fill the window at whatever size results. The font engine
            // rasterizes at the derived pixel height (cached per-size).
            const cell = cellSize(win.fb.width, g.zoom.*);
            const fgrid = softFieldGrid(win.fb.width, win.fb.height, cell.w, cell.h);
            const cols = fgrid.cols;
            const rows = fgrid.rows;
            // (Re)size the field to the window. Cheap; the perturb grid
            // is wiped on resize (transient by design, §7).
            if (g.field.cols != cols or g.field.rows != rows) {
                field_core.deinit(gpa, g.field);
                try field_core.init(gpa, g.field, cols, rows);
            }
            // dt from the monotonic clock — the one time source (B4).
            const t = clock_shell.monotonicNanos();
            var dt: f32 = if (g.last_nanos.* == 0) 1.0 / 60.0 else @as(f32, @floatFromInt(t -| g.last_nanos.*)) / 1_000_000_000.0;
            g.last_nanos.* = t;
            if (dt > 0.1) dt = 0.1; // a long stall integrates one capped step, not a leap
            if (dt <= 0) dt = 1.0 / 60.0;

            // The pipeline, in order: 1. layout writes the content grid
            // + hit rects (perturb persists). 2. effects paint their
            // current stage and emit any spawns. 3. physics integrates
            // particles + cells. 4. compose maps it all to pixels.
            //
            // Step 1 is now the three-column shell carve (nav · feed ·
            // sidebar), which delegates the centre band to the same feed
            // builder and collapses to the full-width feed when the window
            // is too narrow (SHELL_LAYOUT_ROADMAP). Pane widths are a cold
            // config value (A7.2) held here, the one seat a settings screen
            // will later write — no config plumbing built before it is used
            // (F4).
            const t_start = if (debug_frame_timing) clock_shell.monotonicNanos() else 0;
            const pane_cfg: field_ui.PaneConfig = .{};
            _ = try field_ui.layoutShell(g.field, pane_cfg, g.hr, g.hearts, view_items, state.selected, g.view, revealed, now, account_handle, status, gpa);
            // cut 5.6: replace the old cell-grid feed text with the static
            // ambient glyph texture — the premium feed_view layer draws the
            // real content on top. layoutShell still runs so the hit rects and
            // heart slots are ready for the input slice (buttons), but its
            // content is overwritten here.
            field_core.fillAmbient(g.field);
            try effect_core.advance(gpa, g.active, g.field, dt, g.spawn_buf);
            try field_core.step(gpa, g.field, g.particles, g.spawn_buf.items, dt, sim_rng.random());
            const light: field_core.Light = .{
                .x = @floatFromInt(cols / 2),
                .y = @floatFromInt(rows / 4),
                .radius = @floatFromInt(cols),
                .ambient = 0.30, // dim so the field recedes and pools at the light — dark cells
                // starve so the light pools through the material (mockup look)
            };
            try field_core.compose(gpa, g.field, g.particles.slice(), light, cell.w, cell.h, g.draw);
            // The animating heart burst still composes (when an effect is
            // live); the OLD resting heart sprites are gone — the premium
            // layer owns the heart icons now.
            try effect_core.composeEffects(gpa, g.active.slice(), cell.w, cell.h, g.draw);
            const t_built = if (debug_frame_timing) clock_shell.monotonicNanos() else 0;
            // The premium content layer (avatars, type hierarchy, engagement
            // row, dividers) painted OVER the field as proportional items, fed
            // by the REAL timeline via a pure transform (B5). An empty timeline
            // renders the chrome with no posts — no placeholder content.
            const feed_posts = feed_view.fromTimeline(arena, view_items, now) catch &[_]feed_view.PostView{};
            if (g.chat_store != null and g.screen.* == feed_view.screen_messages) {
                // Zat Chat (U3, dev-gated): the Messages surface. -scroll maps the
                // shared ≤0 scroll state onto layoutChat's positive history offset.
                const cf = buildChatFrame(arena, g.chat_store.?, g.chat_sel, now);
                g.content_h.* = feed_view.layoutChat(gpa, g.engine, @intCast(win.fb.width), @intCast(win.fb.height), g.draw, g.regions, g.accent, -g.scroll.*, false, false, null, cf.list, cf.thread, cf.sel, cf.peer, g.chat_draft, g.chat_input_focus, g.chat_composing, g.chat_compose, g.chat_compose_status, .{}) catch g.content_h.*;
            } else if (g.screen.* == feed_view.screen_loadout) {
                const ft = g.socket_tray orelse lens_socket.TrayView{ .cards = &.{}, .text = "", .seated = 0 };
                g.content_h.* = feed_view.layoutLoadout(gpa, g.engine, @intCast(win.fb.width), @intCast(win.fb.height), g.draw, g.regions, g.accent, g.scroll.*, g.loadout_tab, g.loadout_geoms, ft, g.socket_ui, g.socket_hits, g.reply_tray, g.reply_ui, g.reply_hits, g.zone_tray, g.zone_ui, g.zone_hits, false, false, null, g.market, g.create, g.bench) catch g.content_h.*; // software: draw line-art nav
            } else if (g.screen.* == feed_view.screen_transparency) {
                if (g.inspect_loading) {
                    g.content_h.* = feed_view.layoutAlgorithmLoading(gpa, g.engine, @intCast(win.fb.width), g.draw, g.regions, g.accent, g.inspect_name) catch g.content_h.*;
                } else if (g.inspect_bytes.len > 0) {
                    if (g.inspect_source) {
                        // The byte-exact source IS the stored serialized config.
                        g.content_h.* = feed_view.layoutAlgorithmSource(gpa, g.engine, @intCast(win.fb.width), @intCast(win.fb.height), g.draw, g.regions, g.accent, g.scroll.*, g.inspect_name, g.inspect_ref, g.inspect_bytes) catch g.content_h.*;
                    } else {
                        // Re-parse into THIS frame's arena (stable bytes → valid slices).
                        const cfg = algorithm_core.parse(arena, g.inspect_bytes) catch discover.DEFAULT_CONFIG;
                        if (transparency.buildPage(arena, g.inspect_name, g.inspect_ref, cfg) catch null) |pg|
                            g.content_h.* = feed_view.layoutTransparency(gpa, g.engine, @intCast(win.fb.width), @intCast(win.fb.height), g.draw, g.regions, g.accent, g.scroll.*, pg) catch g.content_h.*;
                    }
                }
            } else {
                // Tiling foundation (S.1): geometry comes through the partition
                // seam. Slice 1 hands back the screen's own geometry (identical
                // render); the animated morph springs this between screens.
                const sw_geom = feed_view.paneGeomFor(@intCast(win.fb.width), g.screen.*);
                g.content_h.* = feed_view.layout(gpa, g.engine, @intCast(win.fb.width), @intCast(win.fb.height), feed_posts, g.scroll.*, g.draw, g.regions, null, false, g.screen.*, profile_header, g.pending_new, g.accent, g.socket_tray, g.socket_ui, g.socket_hits, null, null, g.zone_title, g.zones, sw_geom, g.settings_section, g.settings_toggles, g.settings_account, g.settings_choices, g.settings_picking) catch g.content_h.*;
            }
            const t_layout = if (debug_frame_timing) clock_shell.monotonicNanos() else 0;
            window_shell.presentDrawList(win, gpa, g.engine, g.draw.slice(), field_core.background) catch {}; // E2: a lost blit is the next frame's problem
            if (debug_frame_timing) {
                const t_end = clock_shell.monotonicNanos();
                const us = struct {
                    fn d(a: i128, b: i128) i64 {
                        return @intCast(@divTrunc(b - a, 1000));
                    }
                };
                std.debug.print("[zat frame] field+effects {d}us · content {d}us · present(paint+blit) {d}us · items {d} · effects {d}\n", .{ us.d(t_start, t_built), us.d(t_built, t_layout), us.d(t_layout, t_end), g.draw.len, g.active.len });
            }
            return;
        },
        .terminal => {},
    };
    timeline_ui.buildFrame(next, view_items, state, revealed, now, account_handle, status);
    try present(gpa, out, arena, prev, next, backend);
}

/// The GPU render route (Phase 6.4), one frame: step the living field, render
/// Advance the glyph-field medium one fixed-timestep (≈60 Hz) tick, at most once
/// per frame, so it evolves at a constant real-time rate regardless of how fast
/// the loop spins. Stepping per loop-iteration coupled the sim to the INPUT rate
/// (a mouse-motion flood drove the loop far above 60 fps → the whole field sped
/// up while the pointer moved). With the clock gate, idle and active evolve
/// identically; only the pointer's local splash is injected. Shared by the feed
/// and composer paint paths so the field animates the same behind both.
/// How many sim steps the like's red dye fades in over — ~0.3s at 60 Hz, timed
/// to land with the heart's spark burst.
const dye_reveal_frames_total: u32 = 18;
/// Inject one increment (`frac` of the full charge) of a like's dye ring —
/// centre + two concentric rings — as DYE-ONLY splashes (amp 0), so the red
/// FADES in across the splat instead of blipping. Mirrors pushLikeSplash's
/// spatial pattern. A queue-full append is dropped (E4).
fn injectLikeDye(gpa: Allocator, gs: *GpuState, cx: u32, cy: u32, frac: f32) void {
    if (gs.cols == 0 or gs.rows == 0) return;
    gs.splashes.append(gpa, .{ .x = cx, .y = cy, .radius = 6, .amp = 0, .dye = 1.0 * frac }) catch {};
    const ring_dist = [_]f32{ 5.0, 9.0 };
    const ring_dye = [_]f32{ 0.9, 0.6 };
    for (ring_dist, ring_dye) |dist, dye| {
        var k: u32 = 0;
        while (k < 8) : (k += 1) {
            const ang = @as(f32, @floatFromInt(k)) * (6.2831853 / 8.0);
            const ox: i32 = @intFromFloat(@cos(ang) * dist);
            const oy: i32 = @intFromFloat(@sin(ang) * dist);
            const rx = std.math.clamp(@as(i32, @intCast(cx)) + ox, 0, @as(i32, @intCast(gs.cols - 1)));
            const ry = std.math.clamp(@as(i32, @intCast(cy)) + oy, 0, @as(i32, @intCast(gs.rows - 1)));
            gs.splashes.append(gpa, .{ .x = @intCast(rx), .y = @intCast(ry), .radius = 3, .amp = 0, .dye = dye * frac }) catch {};
        }
    }
}

fn advanceField(gpa: Allocator, gs: *GpuState, active: *effect_core.ActiveList) void {
    const dt_ns: u64 = 16_666_667; // 1/60 s
    const now_ns = clock_shell.monotonicNanos();
    const due = gs.last_step_nanos == 0 or (now_ns -| gs.last_step_nanos) >= dt_ns;
    if (!due) return;
    // Fill the time-driven ambient bias (shell side → the core stays pure, B3):
    // a slow drifting two-sine swell plus a finer term so the dense interior is
    // an ASSORTMENT of glyphs, not a wall of one symbol.
    //
    // Both terms are SEPARABLE products — sin(of x,t)·sin(of y,t) — so the value
    // factors into a per-COLUMN part and a per-ROW part. Precompute those 1D
    // tables once (≈2·(cols+rows) sins) and the inner loop is pure multiplies,
    // instead of 4 sins PER CELL (≈4·cols·rows). The arithmetic is the same
    // operands in the same order, so `bias` is bit-identical to the naive form;
    // this is a cost change only. Falls back to per-cell sins if the grid ever
    // exceeds the table cap (no realistic monitor does at a 13×17 px cell).
    const amb_cap = 2048;
    if (gs.cols <= amb_cap and gs.rows <= amb_cap) {
        var ax: [amb_cap]f32 = undefined; // base x-factor:  sin(fx·s + t·d)
        var cx: [amb_cap]f32 = undefined; // fine x-factor:  sin(fx·0.21 − t·0.07)
        var by: [amb_cap]f32 = undefined; // base y-factor:  sin(fy·s·1.3 − t·d·0.8)
        var dy: [amb_cap]f32 = undefined; // fine y-factor:  sin(fy·0.18 + t·0.06)
        var xx: u32 = 0;
        while (xx < gs.cols) : (xx += 1) {
            const fx: f32 = @floatFromInt(xx);
            ax[xx] = std.math.sin(fx * amb_scale + gs.t * amb_drift);
            cx[xx] = std.math.sin(fx * 0.21 - gs.t * 0.07);
        }
        var yy: u32 = 0;
        while (yy < gs.rows) : (yy += 1) {
            const fy: f32 = @floatFromInt(yy);
            by[yy] = std.math.sin(fy * amb_scale * 1.3 - gs.t * amb_drift * 0.8);
            dy[yy] = std.math.sin(fy * 0.18 + gs.t * 0.06);
        }
        yy = 0;
        while (yy < gs.rows) : (yy += 1) {
            const row = yy * gs.cols;
            const byy = by[yy];
            const dyy = dy[yy];
            xx = 0;
            while (xx < gs.cols) : (xx += 1) {
                const base = ax[xx] * byy;
                const fine = cx[xx] * dyy;
                gs.bias[row + xx] = amb_amp * (base + 0.5 * fine);
            }
        }
    } else {
        var yy: u32 = 0;
        while (yy < gs.rows) : (yy += 1) {
            const fy: f32 = @floatFromInt(yy);
            var xx: u32 = 0;
            while (xx < gs.cols) : (xx += 1) {
                const fx: f32 = @floatFromInt(xx);
                const base = std.math.sin(fx * amb_scale + gs.t * amb_drift) *
                    std.math.sin(fy * amb_scale * 1.3 - gs.t * amb_drift * 0.8);
                const fine = std.math.sin(fx * 0.21 - gs.t * 0.07) *
                    std.math.sin(fy * 0.18 + gs.t * 0.06);
                gs.bias[yy * gs.cols + xx] = amb_amp * (base + 0.5 * fine);
            }
        }
    }
    // A like's red DYE is revealed gradually (synced to the spark animation)
    // rather than blipping in: inject a fraction of the dye ring each step until
    // the window closes. The wave (the ripple) already fired once in
    // pushLikeSplash; this only fades the colour in.
    if (gs.dye_reveal_frames > 0) {
        injectLikeDye(gpa, gs, gs.dye_reveal_cx, gs.dye_reveal_cy, 1.0 / @as(f32, @floatFromInt(dye_reveal_frames_total)));
        gs.dye_reveal_frames -= 1;
    }
    // Advance the medium one step; queued splashes injected once.
    glyph_field.step(&gs.field, .{}, gs.splashes.items, gs.bias);
    gs.splashes.clearRetainingCapacity();
    // Tick the like-heart animation clocks on the same 60 Hz step.
    effect_core.advanceClocks(active, 1.0 / 60.0);
    gs.t += 1.0 / 60.0;
    // Advance the step clock by one tick; if we fell far behind (a stall), snap
    // to now and DROP the backlog rather than fast-forward the field.
    gs.last_step_nanos = if (gs.last_step_nanos == 0 or (now_ns -| gs.last_step_nanos) > dt_ns * 4)
        now_ns
    else
        gs.last_step_nanos + dt_ns;
}

/// Render the premium composer (PHASE C1) on the GPU: the living field behind,
/// the composer card on top, then swap — the same field-behind-content pipeline
/// the feed uses, so New-post / reply / profile-edit share the feed's look and
/// the field stays alive behind them. The composer verts are rebuilt every frame
/// (the draft changes per keystroke) into the SAME `gs.feed` buffer; `feed_sig`
/// is zeroed so the timeline rebuilds cleanly on return.
fn paintComposeGpu(
    gpa: Allocator,
    win: *window_shell.Window,
    g: Grid,
    gs: *GpuState,
    ctx: feed_view.ComposeContext,
    reply_handle: []const u8,
    draft: []const u8,
    caret: usize,
    sel_start: usize,
    sel_end: usize,
    blink_on: bool,
    status: []const u8,
) !void {
    const w: u32 = win.fb.width;
    const h: u32 = win.fb.height;
    gpu.setViewport(@intCast(w), @intCast(h));
    const want = gpuFieldGrid(w, h);
    if (want.cols != gs.cols or want.rows != gs.rows) {
        resizeGpuField(gpa, gs, w, h) catch {};
    }
    const scale = uiScale(w);
    gs.scale = scale;

    // Build the composer at the LOGICAL design width (scaled to fill), exactly as
    // the feed lays out — so the emitted button regions map back through gs.scale.
    const lh = logicalH(w, h);
    g.draw.len = 0;
    feed_view.layoutCompose(gpa, g.engine, @intCast(design_w), @intCast(lh), g.accent, ctx, reply_handle, draft, caret, sel_start, sel_end, blink_on, status, g.draw, g.regions) catch {};
    if (g.julia) feed_view.juliaRemapText(g.draw); // light theme: dark text
    gpu.feedBuild(&gs.feed, gpa, g.engine, g.draw.slice(), scale) catch {};
    gs.feed_sig = 0; // force a timeline rebuild when the composer closes

    advanceField(gpa, gs, g.active);

    gpu.uploadField(&gs.grid, gs.field.height, gs.field.dye, gs.field.cols, gs.field.rows);
    if (g.julia) gpu.clear(julia_clear_r, julia_clear_g, julia_clear_b) else gpu.clear(gpu_clear_r, gpu_clear_g, gpu_clear_b);
    // Field glyph ink: cool grey-white normally; pink under Julia mode (the glow
    // rides the ink, so it pinks too). 0xA6ACBA = the shader's original bright endpoint.
    const field_ink: u32 = if (g.julia) lens_socket.julia_field_ink else 0xFFA6ACBA;
    if (g.field_on) gpu.drawFieldGrid(&gs.grid, &gs.ramp, gs.mcx, gs.mcy, gs.t, @intCast(w), @intCast(h), 0, 0, field_ink, g.julia); // composer: no panel softening ("Living glyph field" off ⇒ flat)
    gpu.feedDraw(&gs.feed, @intCast(w), @intCast(h));
    gpu.swap(&gs.g);
}

/// it grid-intensity, then the premium feed on top, and swap. The feed is laid
/// out at the fixed LOGICAL design width and scaled to FILL the window (DPI),
/// exactly as the preview does. No per-frame pixel blit — render + swap.
fn paintFrameGpu(
    gpa: Allocator,
    arena: Allocator,
    win: *window_shell.Window,
    g: Grid,
    gs: *GpuState,
    items: []const feed_core.TimelineItem, // the ACTIVE view's posts
    /// The profile header band, non-null only on the profile screen.
    profile_header: ?feed_view.ProfileHeader,
    now: i64,
) !void {
    const w: u32 = win.fb.width;
    const h: u32 = win.fb.height;
    // Frame-period measurement for the "Show frame timing" overlay — a smoothed
    // ms between successive frames (cheap; the clock read is the only cost).
    {
        const now_ns = clock_shell.monotonicNanos();
        if (gs.last_frame_nanos != 0) {
            const ms = @as(f32, @floatFromInt(now_ns -| gs.last_frame_nanos)) / 1_000_000.0;
            gs.frame_ms = if (gs.frame_ms == 0) ms else gs.frame_ms * 0.9 + ms * 0.1;
        }
        gs.last_frame_nanos = now_ns;
    }
    gpu.setViewport(@intCast(w), @intCast(h));
    // Refit the field grid to the window when the cell count changes (cheap;
    // a few KB R32F). On a failed realloc keep the prior grid (E2).
    const want = gpuFieldGrid(w, h);
    if (want.cols != gs.cols or want.rows != gs.rows) {
        resizeGpuField(gpa, gs, w, h) catch {};
    }

    const scale = uiScale(w);
    gs.scale = scale;

    // Auto-scroll a freshly-opened/re-focused THREAD so the focused post lands at
    // the top (ancestors above, scrollable up — Bluesky parity). Uses the per-post
    // height cache from the prior layout (valid when its length matches this
    // view); done BEFORE the rebuild so the new scroll takes effect THIS frame.
    if (gs.scroll_to_focus and g.screen.* == feed_view.screen_thread and gs.heights.len == items.len) {
        var off: i32 = 0;
        var measured = true; // only apply once the preceding posts' heights exist
        for (items, 0..) |it, ix| {
            if (it.is_focus) break;
            if (gs.heights[ix] > 0) off += gs.heights[ix] else {
                measured = false;
                break;
            }
        }
        if (measured) {
            const lh_view = logicalH(w, h);
            const min_scroll: i32 = @min(0, @as(i32, @intCast(lh_view)) - g.content_h.* - 24);
            g.scroll.* = @max(min_scroll, @min(0, -off));
            gs.scroll_to_focus = false; // applied; wait for heights next frame otherwise
        }
    }

    // Rebuild the feed ONLY when it changed (scroll / window size / any post's
    // identity, counts, or flags). The field below animates every frame, but
    // this pipeline — fromTimeline + feed_view.layout (which MEASURES every
    // post, including off-screen ones) + buildVertices — is the one per-frame
    // cost worth avoiding (§5 gotcha): at 60 fps over a large feed it stutters.
    // A content hash is the dirty signal, far cheaper than the layout it gates.
    // The feed verts persist in gs.feed across frames; feedDraw below reuses
    // them. (G1/G3: this is the measured-cause fix for the live lag.)
    // Fold the active screen into the dirty signature: switching screens
    // changes the rendered body, so the cached feed verts must rebuild.
    // Fold the socket's live state into the dirty signature: opening the
    // tray, the seat animation advancing, or a re-seat all change what the
    // header draws, so the cached feed verts must rebuild those frames.
    var socket_sig: u64 = (@as(u64, @intFromBool(g.socket_ui.open)) << 40) |
        (@as(u64, g.socket_ui.swap_phase) << 32) | (@as(u64, g.socket_ui.swap_to) << 16) |
        (@as(u64, (g.socket_ui.expanded orelse 0xFFF) + 1) << 48) |
        (if (g.socket_tray) |t| @as(u64, t.seated) else 0);
    socket_sig ^= (@as(u64, (g.socket_ui.picking orelse 0xFF)) +% 1) *% 0xA24B_AED4_963E_E407;
    // While the tray springs open/closed, open_t changes each frame — quantize
    // it into the signature so the feed verts rebuild through the animation.
    socket_sig ^= (@as(u64, @intFromFloat(@max(0, @min(1.0, g.socket_ui.open_t)) * 64)) +% 1) *% 0xCA6B_9576_3F1D_2E11;
    // While dragging, the ghost follows the pointer — fold the drag pointer in
    // so each move rebuilds the socket (the one time a per-move rebuild is wanted).
    if (g.socket_ui.drag_active) |d| {
        socket_sig ^= (@as(u64, d) +% 1) *% 0x2545_F491_4F6C_DD1D;
        socket_sig ^= @as(u64, @bitCast(@as(i64, g.socket_ui.drag_x))) *% 0x9E37_79B1;
        socket_sig ^= @as(u64, @bitCast(@as(i64, g.socket_ui.drag_y))) *% 0x85EB_CA77;
    }
    // Screen-switch CROSSFADE: on a screen change, swap the feed buffers so the
    // OLD screen's verts survive in `feed_prev` (it fades OUT) while `feed`
    // rebuilds with the new content (it fades IN). The nav rail is identical in
    // both, so it stays solid; only the differing content dissolves. Cheap — no
    // relayout during the fade, just two cached draws at a uniform alpha.
    if (gs.fade_screen != g.screen.*) {
        const tmp = gs.feed;
        gs.feed = gs.feed_prev;
        gs.feed_prev = tmp;
        gs.fade_t = 0;
        gs.fade_screen = g.screen.*;
        gs.feed_sig = 0; // the swapped-in buffer is stale → force a rebuild below
    }
    gs.fade_t += (1.0 - gs.fade_t) * 0.16; // ease in (~0.25 s)

    // Content-driven SEARCH tile: spring it toward open/closed. While it moves
    // the sidebar repositions, so the feed rebuilds — but the feed's width is
    // unchanged, so its height cache stays warm (cheap, like a scroll).
    springGeom(&gs.search_open, &gs.search_v, if (gs.search_want) 1.0 else 0.0, 1.0 / 60.0);
    const search_animating = @abs(gs.search_open - (if (gs.search_want) @as(f32, 1.0) else 0.0)) > 0.004 or @abs(gs.search_v) > 0.004;

    // ZONES TEST: on the Zones tab the nav rail relocates to the RIGHT — a
    // custom per-page tile-move. `zones_t` springs 0→1 when on a zones screen;
    // while it animates the rail (and its regions/icons) follow, so we rebuild.
    const on_zones = g.screen.* == feed_view.screen_zones_browse or g.screen.* == feed_view.screen_zones;
    springGeom(&gs.zones_t, &gs.zones_v, if (on_zones) 1.0 else 0.0, 1.0 / 60.0);
    const zones_animating = @abs(gs.zones_t - (if (on_zones) @as(f32, 1.0) else 0.0)) > 0.003 or @abs(gs.zones_v) > 0.003;

    // Hover the RIGHT rail → it expands. The hit-band must track the rail's
    // CURRENT (animated) left edge — when expanded it reaches ~188px further
    // left, so a fixed collapsed-strip band would drop the hover as you move
    // onto the open panel and snap it shut. Use last frame's rail_hover_t.
    const dwf: f32 = @floatFromInt(design_w);
    const rail_left_now: f32 = (dwf - 76.0) - gs.rail_hover_t * 188.0;
    const over_right_rail = gs.zones_t > 0.5 and @as(f32, @floatFromInt(g.hover_x)) >= rail_left_now - 8.0 and g.hover_x < @as(i32, @intCast(design_w)) and g.hover_y >= 0;
    springGeom(&gs.rail_hover_t, &gs.rail_hover_v, if (over_right_rail) 1.0 else 0.0, 1.0 / 60.0);
    const rail_hover_animating = @abs(gs.rail_hover_t - (if (over_right_rail) @as(f32, 1.0) else 0.0)) > 0.004 or @abs(gs.rail_hover_v) > 0.004;

    // ALGORITHMS: the LEFT rail condenses in place (stays left). algo_t springs
    // on the loadout screen; hovering the left rail (its current right edge
    // tracks the expand) re-opens it.
    const on_algo = g.screen.* == feed_view.screen_loadout;
    springGeom(&gs.algo_t, &gs.algo_v, if (on_algo) 1.0 else 0.0, 1.0 / 60.0);
    const home_rail_left: f32 = @floatFromInt(feed_view.paneGeomFor(@intCast(design_w), feed_view.screen_loadout).rail_x);
    // The condensed rail hugs the left edge (shifted left by 60); the hover band
    // tracks that shifted position + the current expand width.
    const left_rail_right: f32 = (home_rail_left - 60.0) + 64.0 + gs.left_hover_t * 188.0;
    const over_left_rail = gs.algo_t > 0.5 and g.hover_x >= 0 and @as(f32, @floatFromInt(g.hover_x)) < left_rail_right + 8.0 and g.hover_y >= 0;
    springGeom(&gs.left_hover_t, &gs.left_hover_v, if (over_left_rail) 1.0 else 0.0, 1.0 / 60.0);
    const algo_animating = @abs(gs.algo_t - (if (on_algo) @as(f32, 1.0) else 0.0)) > 0.003 or @abs(gs.algo_v) > 0.003 or @abs(gs.left_hover_t - (if (over_left_rail) @as(f32, 1.0) else 0.0)) > 0.004 or @abs(gs.left_hover_v) > 0.004;
    // Zat Chat (U3): the Messages surface renders from the chat store +
    // selection + draft, none of which the feed signature below can see — a
    // conversation tap or a local send must invalidate the cached content
    // vertices or the screen only updates on re-entry (the caching bug the
    // first live test caught). Fold the chat state in when on the screen.
    var chat_sig: u64 = 0;
    if (g.screen.* == feed_view.screen_messages) if (g.chat_store) |cs| {
        chat_sig = (@as(u64, cs.msgs.len) *% 0x9E37_79B9_7F4A_7C15) ^
            ((if (g.chat_sel) |sc| @as(u64, @intFromEnum(sc)) +% 1 else 0) *% 0xC2B2_AE3D_27D4_EB4F) ^
            std.hash.Wyhash.hash(0x5A72_C4A7, g.chat_draft);
        var unread_sum: u64 = 0;
        for (cs.convs.items(.unread)) |u| unread_sum +%= u;
        chat_sig ^= unread_sum *% 0x2545_F491_4F6C_DD1D;
        // The composer focus ring must appear the frame the input is tapped.
        chat_sig ^= @as(u64, @intFromBool(g.chat_input_focus)) *% 0x8A91_7F2B_4D3E_61C7;
        // The recipient bar: open/close, every keystroke, and the status
        // line must each repaint the frame they change.
        chat_sig ^= @as(u64, @intFromBool(g.chat_composing)) *% 0xF29C_511C_8E3D_45A7;
        chat_sig ^= std.hash.Wyhash.hash(0x77E1_A2C9, g.chat_compose);
        chat_sig ^= std.hash.Wyhash.hash(0x3B8F_55D1, g.chat_compose_status);
    };

    // Zat Chat motion (U6a). The trigger is DERIVED, in this one place, from
    // the observed state transition — the store grew — and the newest
    // message's direction picks the animation (send pop vs arrival settle).
    // The springs then run in the one loop on the one clock; the surface
    // just draws whatever the values say (ANIMATION_SYSTEM_NOTES).
    var chat_animating = false;
    if (g.screen.* == feed_view.screen_messages) if (g.chat_store) |cs| {
        if (gs.chat_seen_valid and cs.msgs.len > gs.chat_seen_msgs) {
            if (cs.mine.isSet(cs.msgs.len - 1)) {
                gs.chat_send_t = 0;
                gs.chat_send_v = 0;
            } else {
                gs.chat_arrive_t = 0;
                gs.chat_arrive_v = 0;
            }
        }
        gs.chat_seen_msgs = cs.msgs.len;
        gs.chat_seen_valid = true;
        // MEASURED frame time, sub-stepped for stability: the motion is
        // identical at 60Hz, 144Hz, or across a dropped frame — smoothness
        // comes from advancing by real elapsed time, never a fixed tick.
        const spring_now = clock_shell.monotonicNanos();
        var dt: f32 = if (gs.chat_clock_ns == 0) 1.0 / 60.0 else @as(f32, @floatFromInt(spring_now -| gs.chat_clock_ns)) / 1_000_000_000.0;
        gs.chat_clock_ns = spring_now;
        dt = std.math.clamp(dt, 0.0, 0.05);
        var rem = dt;
        while (rem > 1e-6) {
            const step = @min(rem, 1.0 / 240.0);
            springPop(&gs.chat_send_t, &gs.chat_send_v, 1.0, step);
            springPop(&gs.chat_arrive_t, &gs.chat_arrive_v, 1.0, step);
            springPop(&gs.chat_typing_t, &gs.chat_typing_v, if (g.chat_typing) 1.0 else 0.0, step);
            rem -= step;
        }
        if (gs.chat_typing_t > 0.01) gs.chat_typing_phase += dt;
        // A focused input keeps frames coming for the caret's breath.
        chat_animating = @abs(gs.chat_send_t - 1.0) > 0.004 or @abs(gs.chat_send_v) > 0.004 or
            @abs(gs.chat_arrive_t - 1.0) > 0.004 or @abs(gs.chat_arrive_v) > 0.004 or
            gs.chat_typing_t > 0.01 or g.chat_typing or
            g.chat_input_focus or g.chat_composing;
    };
    const sig = feedSignature(items, g.scroll.*, w, h) ^ (@as(u64, g.screen.*) *% 0x9E37_79B9_7F4A_7C15) ^ (socket_sig *% 0xD1B5_4A32_D192_ED03) ^ (@as(u64, g.settings_section) *% 0xC2B2_AE3D_27D4_EB4F) ^ (g.settings_toggles *% 0x9E6C_63D0_676A_9A99) ^ (g.settings_choices *% 0x2545_F491_4F6C_DD1D) ^ (@as(u64, g.settings_picking) *% 0x8A91_7F2B_4D3E_61C7) ^ (@as(u64, @intFromBool(g.inspect_source)) *% 0xF29C_511C_8E3D_45A7) ^ (@as(u64, @intFromBool(g.inspect_loading)) *% 0xBF58_476D_1CE4_E5B9) ^ chat_sig;
    // A drag/settle animates the socket every frame (lift, reflow, ghost), so
    // bypass the feed cache while it runs — a brief interaction, and the field
    // already rebuilds every frame anyway.
    if (sig != gs.feed_sig or gs.feed.verts.items.len == 0 or g.socket_ui.drag_active != null or search_animating or zones_animating or rail_hover_animating or algo_animating or chat_animating or g.screen.* == feed_view.screen_loadout or g.frametiming_on) {
        gs.feed_sig = sig;
        // An empty timeline renders the chrome with no posts (no placeholders).
        const feed_posts = feed_view.fromTimeline(arena, items, now) catch &[_]feed_view.PostView{};
        // Per-post height cache: post heights are scroll-invariant, so only
        // reset the cache when the CONTENT or WIDTH changed (scroll/height
        // zeroed in this signature). A pure scroll then reuses every post's
        // measured height and skips the text-shaping pass — the scroll-lag fix.
        const content_sig = feedSignature(items, 0, w, 0);
        if (content_sig != gs.feed_content_sig or gs.heights.len != feed_posts.len) {
            gs.feed_content_sig = content_sig;
            if (gs.heights.len != feed_posts.len) {
                if (gpa.alloc(i32, feed_posts.len)) |buf| {
                    if (gs.heights.len > 0) gpa.free(gs.heights);
                    gs.heights = buf;
                } else |_| {} // keep the old buffer; layout guards on length
            }
            @memset(gs.heights, -1);
        }
        const lh = logicalH(w, h);
        g.draw.len = 0;
        var chain_info: feed_view.ChainSticky = .{};
        if (g.screen.* == feed_view.screen_loadout) {
            // The loadout page: three stacked sockets, its own render path.
            const ft = g.socket_tray orelse lens_socket.TrayView{ .cards = &.{}, .text = "", .seated = 0 };
            // ALGORITHMS: expand the loadout content into the space the condensed
            // left rail frees — shift the glass a bit LEFT toward the rail + widen
            // RIGHT, by algo_t. (The rail itself condenses in the rail-tile pass.)
            var lg = feed_view.paneGeomFor(@intCast(design_w), feed_view.screen_loadout);
            if (gs.algo_t > 0.01) {
                const at = gs.algo_t * gs.algo_t * (3.0 - 2.0 * gs.algo_t);
                const tcx: f32 = home_rail_left + 92.0;
                const tcw: f32 = @as(f32, @floatFromInt(design_w)) - tcx - 40.0;
                const lp2 = struct {
                    fn f(a: i32, b: f32, t: f32) i32 {
                        return @intFromFloat(@as(f32, @floatFromInt(a)) + (b - @as(f32, @floatFromInt(a))) * t);
                    }
                }.f;
                lg.col_x = lp2(lg.col_x, tcx, at);
                lg.col_w = lp2(lg.col_w, tcw, at);
                lg.lx = lp2(lg.lx, tcx + 22.0, at);
            }
            gs.content_x = lg.col_x;
            gs.content_w = lg.col_w;
            g.content_h.* = feed_view.layoutLoadout(gpa, g.engine, @intCast(design_w), @intCast(lh), g.draw, g.regions, g.accent, g.scroll.*, g.loadout_tab, g.loadout_geoms, ft, g.socket_ui, g.socket_hits, g.reply_tray, g.reply_ui, g.reply_hits, g.zone_tray, g.zone_ui, g.zone_hits, true, true, lg, g.market, g.create, g.bench) catch g.content_h.*; // GPU: SDF pass strikes the nav icons crisp
        } else if (g.chat_store != null and g.screen.* == feed_view.screen_messages) {
            // Zat Chat (U3, dev-gated): the Messages surface in the GPU's logical
            // design space; the rail is the shell's own tile (rail_external), and
            // -scroll maps the shared ≤0 scroll onto the positive history offset.
            const lg = feed_view.paneGeomFor(@intCast(design_w), feed_view.screen_messages);
            gs.content_x = lg.col_x;
            gs.content_w = lg.col_w;
            const cf = buildChatFrame(arena, g.chat_store.?, g.chat_sel, now);
            // Seconds since the last chat keystroke, wrapped onto one blink
            // period past the solid window — f32-precise forever, and a
            // never-touched input still breathes (clock-since-launch).
            const caret_raw_ns: u64 = if (g.chat_key_ns == 0) gs.chat_clock_ns else gs.chat_clock_ns -| g.chat_key_ns;
            var caret_ph: f64 = @as(f64, @floatFromInt(caret_raw_ns)) / 1_000_000_000.0;
            if (caret_ph > 0.55) caret_ph = 0.55 + @mod(caret_ph - 0.55, 1.1);
            const caret_phase: f32 = @floatCast(caret_ph);
            g.content_h.* = feed_view.layoutChat(gpa, g.engine, @intCast(design_w), @intCast(lh), g.draw, g.regions, g.accent, -g.scroll.*, true, true, lg, cf.list, cf.thread, cf.sel, cf.peer, g.chat_draft, g.chat_input_focus, g.chat_composing, g.chat_compose, g.chat_compose_status, .{ .send_t = gs.chat_send_t, .arrive_t = gs.chat_arrive_t, .typing_t = gs.chat_typing_t, .typing_phase = gs.chat_typing_phase, .caret_phase = caret_phase }) catch g.content_h.*;
        } else if (g.screen.* == feed_view.screen_transparency) {
            // The algorithm transparency page: a plain scrolling document (no rail),
            // rebuilt from the inspected config each entry (what you see = what runs).
            // Summary by default; the byte-exact serialized source on the tap-through.
            if (g.inspect_loading) {
                g.content_h.* = feed_view.layoutAlgorithmLoading(gpa, g.engine, @intCast(design_w), g.draw, g.regions, g.accent, g.inspect_name) catch g.content_h.*;
            } else if (g.inspect_bytes.len > 0) {
                if (g.inspect_source) {
                    g.content_h.* = feed_view.layoutAlgorithmSource(gpa, g.engine, @intCast(design_w), @intCast(lh), g.draw, g.regions, g.accent, g.scroll.*, g.inspect_name, g.inspect_ref, g.inspect_bytes) catch g.content_h.*;
                } else {
                    const cfg = algorithm_core.parse(arena, g.inspect_bytes) catch discover.DEFAULT_CONFIG;
                    if (transparency.buildPage(arena, g.inspect_name, g.inspect_ref, cfg) catch null) |pg|
                        g.content_h.* = feed_view.layoutTransparency(gpa, g.engine, @intCast(design_w), @intCast(lh), g.draw, g.regions, g.accent, g.scroll.*, pg) catch g.content_h.*;
                }
            }
        } else {
            // skip_heart=true on every screen: the SDF heart pass (drawEngagementHearts,
            // below) draws the heart in place for each visible like button of the
            // ACTIVE view, so layout never draws its own — one heart, one pipeline.
            // Tiling foundation (S.1): geometry through the partition seam. The
            // GPU path lays out at the logical design width, so the geom is
            // solved at design_w. Slice 1 = the screen's own geometry (identical).
            // Tiling foundation (S.1): geometry through the partition seam. The
            // GPU path lays out at the logical design width, so the geom is
            // solved at design_w. Geometry SNAPS to the screen's layout (smooth,
            // no per-frame relayout); a cross-screen MORPH is a separate, cheaper
            // mechanism (see the dormant geom_* spring state) — not a relayout.
            var gp_geom = feed_view.paneGeomFor(@intCast(design_w), g.screen.*);
            gp_geom.search_open = gs.search_open; // the content-driven sidebar push
            gp_geom.rail_external = true; // the rail is its own tile (decomposition)
            // ZONES: the rail moved to the right, so the content fills the freed
            // LEFT space — shift the glass left + widen as zones_t grows. (Zones
            // has no posts, so the per-frame relayout during the slide is cheap.)
            if (gs.zones_t > 0.01) {
                const zt2 = gs.zones_t * gs.zones_t * (3.0 - 2.0 * gs.zones_t);
                const tcx: f32 = 90.0;
                const tcw: f32 = @as(f32, @floatFromInt(design_w)) - 90.0 - 104.0; // stop before the right rail
                const lp = struct {
                    fn f(a: i32, b: f32, t: f32) i32 {
                        return @intFromFloat(@as(f32, @floatFromInt(a)) + (b - @as(f32, @floatFromInt(a))) * t);
                    }
                }.f;
                gp_geom.col_x = lp(gp_geom.col_x, tcx, zt2);
                gp_geom.col_w = lp(gp_geom.col_w, tcw, zt2);
                gp_geom.lx = lp(gp_geom.lx, tcx + 22.0, zt2);
            }
            gs.content_x = gp_geom.col_x; // for the field panel-softening (tracks the live content)
            gs.content_w = gp_geom.col_w;
            g.content_h.* = feed_view.layout(gpa, g.engine, @intCast(design_w), @intCast(lh), feed_posts, g.scroll.*, g.draw, g.regions, gs.heights, true, g.screen.*, profile_header, g.pending_new, g.accent, g.socket_tray, g.socket_ui, g.socket_hits, &chain_info, &gs.sel_glyphs, g.zone_title, g.zones, gp_geom, g.settings_section, g.settings_toggles, g.settings_account, g.settings_choices, g.settings_picking) catch g.content_h.*;
        }
        if (g.julia) feed_view.juliaRemapText(g.draw); // light theme: dark text
        // "Show frame timing": ride the fps/ms badge on the feed buffer. The gate
        // above forces a per-frame rebuild while this is on, so the number is live
        // (a debug mode — the rebuild cost is the thing you're measuring anyway).
        if (g.frametiming_on) {
            var fbuf: [48]u8 = undefined;
            const fps: f32 = if (gs.frame_ms > 0.05) 1000.0 / gs.frame_ms else 0;
            const fs = std.fmt.bufPrint(&fbuf, "{d:.1} ms   {d:.0} fps", .{ gs.frame_ms, fps }) catch "";
            if (fs.len > 0) feed_view.overlayBadge(gpa, g.draw, g.engine, 16, 26, fs) catch {};
        }
        gpu.feedBuild(&gs.feed, gpa, g.engine, g.draw.slice(), scale) catch {};

        // The nav rail as its OWN tile (the decomposition): render it into a
        // separate vertex buffer so it can slide/compress independently of the
        // content. It emits the nav hit regions (clicks + the SDF nav icons
        // follow). Because the rail is no longer in `gs.feed`, the screen-switch
        // crossfade no longer dissolves it — it stays solid, which is correct.
        // Built for EVERY screen (incl. the loadout/Algorithms page, which now
        // skips its own rail via rail_external) with the active nav = the screen.
        {
            const dw: f32 = @floatFromInt(design_w);
            const home_rail_x: f32 = @floatFromInt(feed_view.paneGeomFor(@intCast(design_w), g.screen.*).rail_x);
            const zt = gs.zones_t * gs.zones_t * (3.0 - 2.0 * gs.zones_t); // smoothstep
            g.draw.len = 0;
            // LEFT rail: slides off the left as zt→1 (Zones). On the Algorithms
            // page it CONDENSES and hugs the LEFT EDGE (shift left by algo_t);
            // hover re-expands it in place.
            const algo_shift: f32 = gs.algo_t * 60.0;
            const left_home: f32 = home_rail_x - algo_shift;
            const exit_x: i32 = @intFromFloat(left_home + (-260.0 - left_home) * zt);
            const left_expand: f32 = 1.0 - gs.algo_t * (1.0 - gs.left_hover_t);
            feed_view.renderRail(gpa, g.draw, g.engine, exit_x, @intCast(lh), g.screen.*, g.regions, g.accent, true, left_expand) catch {};
            // RIGHT rail (CONDENSED): slides IN from beyond the right edge as
            // zt→1, simultaneously. Hover expands it (rail_hover_t) and shifts it
            // LEFT so the full width fits on-screen (a flyout over the content).
            if (gs.zones_t > 0.01) {
                const compressed_x = dw - 76.0;
                const settled_x = compressed_x - gs.rail_hover_t * 188.0; // shift left when expanded
                const enter_x: i32 = @intFromFloat((dw + 20.0) + (settled_x - (dw + 20.0)) * zt);
                feed_view.renderRail(gpa, g.draw, g.engine, enter_x, @intCast(lh), g.screen.*, g.regions, g.accent, true, gs.rail_hover_t) catch {};
            }
            if (g.julia) feed_view.juliaRemapText(g.draw); // light theme: dark text
            gpu.feedBuild(&gs.rail, gpa, g.engine, g.draw.slice(), scale) catch {};
        }

        // Capture the chain extent + identity (OWNED copies) for the sticky chain
        // header overlay — valid across the non-rebuild frames until the next
        // content change (offsets are scroll-independent).
        gs.chain_present = chain_info.present and chain_info.head_index < feed_posts.len;
        if (gs.chain_present) {
            const head = feed_posts[chain_info.head_index];
            gs.chain_top_off = chain_info.top_off;
            gs.chain_bottom_off = chain_info.bottom_off;
            gs.chain_pin_y = chain_info.pin_y;
            gs.chain_tint = head.tint;
            gs.chain_initial = head.initial;
            const nl = @min(head.name.len, gs.chain_name.len);
            @memcpy(gs.chain_name[0..nl], head.name[0..nl]);
            gs.chain_name_len = @intCast(nl);
            const hl = @min(head.handle.len, gs.chain_handle.len);
            @memcpy(gs.chain_handle[0..hl], head.handle[0..hl]);
            gs.chain_handle_len = @intCast(hl);
        }
    }

    advanceField(gpa, gs, g.active);

    // Render: the living field behind, the feed on top, then swap.
    gpu.uploadField(&gs.grid, gs.field.height, gs.field.dye, gs.field.cols, gs.field.rows);
    if (g.julia) gpu.clear(julia_clear_r, julia_clear_g, julia_clear_b) else gpu.clear(gpu_clear_r, gpu_clear_g, gpu_clear_b);
    // Soften the field UNDER the content column (glass backdrop). The feed lays
    // out at the logical design width; map the column's x-range to physical px.
    // Panel softening tracks the LIVE (animated) content column, not the static
    // metricsPage one — so the "distortion" panel follows the widened Zones glass.
    const panel_l = @as(f32, @floatFromInt(gs.content_x)) * scale;
    const panel_r = @as(f32, @floatFromInt(gs.content_x + gs.content_w)) * scale;
    const field_ink: u32 = if (g.julia) lens_socket.julia_field_ink else 0xFFA6ACBA;
    gs.grid.gain = g.field_gain; // Appearance → "Field intensity" choice
    if (g.field_on) gpu.drawFieldGrid(&gs.grid, &gs.ramp, gs.mcx, gs.mcy, gs.t, @intCast(w), @intCast(h), panel_l, panel_r, field_ink, g.julia); // "Living glyph field" off ⇒ flat background
    // Hover highlight (post wash + button highlight), BEHIND the feed so the
    // content draws on top — the app feels alive under the cursor.
    drawHoverOverlay(gpa, g, gs, scale, @intCast(w), @intCast(h));
    // The feed verts persist across frames (rebuilt above only when the feed
    // changed); just draw them. During a screen-switch CROSSFADE, draw the old
    // screen (fading out) under the new (fading in) — the rail, in both, stays.
    if (gs.fade_t < 0.995) {
        gpu.feedDrawAlpha(&gs.feed_prev, @intCast(w), @intCast(h), 1.0 - gs.fade_t);
        gpu.feedDrawAlpha(&gs.feed, @intCast(w), @intCast(h), gs.fade_t);
    } else {
        gpu.feedDraw(&gs.feed, @intCast(w), @intCast(h));
    }
    // The nav rail tile draws ON TOP of the content and SOLID (no crossfade) —
    // it's constant across screens, so it stays put while content dissolves.
    gpu.feedDraw(&gs.rail, @intCast(w), @intCast(h));
    // The rooted post's read-only text selection — a translucent band drawn ON TOP
    // of the feed text (a highlighter, not an occluder). It must sit above the
    // post's glass fill, so it draws AFTER the feed, not behind it (behind, the
    // glass swallowed it — the "selection does nothing" report).
    drawSelectionOverlay(gpa, g, gs, scale, @intCast(w), @intCast(h));
    // The socket hover highlight rides ON TOP of the feed (its panels are
    // opaque, so it can't sit behind like the post wash does).
    drawSocketHoverTop(gpa, g, gs, scale, @intCast(w), @intCast(h));
    // The engagement hearts: one SDF heart per visible like button, drawn IN
    // PLACE (feed_view skips its own), so a like fills + pops the ACTUAL heart.
    drawEngagementHearts(g, gs, items, @intCast(w), @intCast(h));
    drawJuliaBurst(gs, @intCast(w), @intCast(h));
    // The SDF icons (repost, gear) — crisp, drawn in place of the line-art.
    drawSdfIcons(g, gs, items, @intCast(w), @intCast(h));
    // The sticky CHAIN header: pins while scrolling the chain, catches up on
    // scroll-down, pushed out at the chain's end. Drawn LAST (on top), per-frame.
    drawChainSticky(gpa, g, gs, scale, @intCast(w), @intCast(h));
    // The right-click context menu sits ABOVE everything else.
    drawContextMenu(gpa, g, gs, scale, @intCast(w), @intCast(h));
    // Toy Box: CRT scanlines — a post-process over the whole frame.
    if (g.crt_on) gpu.drawScanlines(&gs.scanlines);
    gpu.swap(&gs.g);
}

/// The sticky chain header overlay (thread "chain"). Pure-sticky base
/// (`y = min(max(inlineY, pinY), chainBottom − h)`) so the scroll-UP handoff to
/// the inline header is seamless by construction; a scroll-DOWN-only catch-up
/// (brief fade + slide-down) is layered on top and never affects the up seam.
fn drawChainSticky(gpa: Allocator, g: Grid, gs: *GpuState, scale: f32, vw: i32, vh: i32) void {
    if (!gs.chain_present or g.screen.* != feed_view.screen_thread) {
        gs.chain_catchup_t = 0;
        gs.chain_was_pinned = false;
        return;
    }
    const scroll = g.scroll.*;
    const pin_y = gs.chain_pin_y;
    const header_h: i32 = 46;
    const inline_y = gs.chain_top_off + scroll; // screen y of the inline header
    const bottom_y = gs.chain_bottom_off + scroll; // screen y of the chain end
    const pinned = inline_y < pin_y; // the inline header has scrolled above the pin
    // Catch-up edge: newly pinned (scrolled down past) → restart the entrance.
    if (pinned and !gs.chain_was_pinned) gs.chain_catchup_t = 0;
    gs.chain_was_pinned = pinned;
    if (!pinned) {
        gs.chain_catchup_t = 0; // inline header is in view; the feed draws it
        return;
    }
    gs.chain_catchup_t += (1.0 - gs.chain_catchup_t) * 0.16;
    const t = gs.chain_catchup_t;
    // Pure-sticky base, pushed up by the chain's end (continuous → seamless).
    var base_y = pin_y;
    const pushed = bottom_y - header_h;
    if (pushed < base_y) base_y = pushed;
    // Catch-up: a small downward slide settling to base_y + a fade.
    const slide: i32 = @intFromFloat((1.0 - t) * 16.0);
    const draw_y = base_y - slide;
    // Fully pushed out above the pin → nothing to show.
    if (base_y + header_h <= pin_y) return;
    const alpha: f32 = t * std.math.clamp(@as(f32, @floatFromInt(base_y + header_h - pin_y)) / @as(f32, @floatFromInt(header_h)), 0.0, 1.0);
    if (alpha <= 0.02) return;

    var hd: raster_core.DrawList = .{};
    defer hd.deinit(gpa);
    feed_view.buildChainHeaderBar(gpa, &hd, g.engine, @intCast(design_w), draw_y, header_h, pin_y, gs.chain_tint, gs.chain_initial, gs.chain_name[0..gs.chain_name_len], gs.chain_handle[0..gs.chain_handle_len], g.accent, alpha) catch return;
    if (hd.len == 0) return;
    gpu.feedBuild(&gs.hover, gpa, g.engine, hd.slice(), scale) catch return;
    gpu.feedDraw(&gs.hover, vw, vh);
}

/// Scan one socket HitList for the rect under the pointer, splitting it the
/// same way the feed does: a `.seat` (the whole lens card) is the wash; every
/// other control (toggle/expand/reorder/swatch/get_more…) is the brighter
/// button. Forward iteration means the last (topmost-drawn) match wins, so a
/// sub-control over its card highlights the control AND washes the card.
fn scanSocketHits(hits: []const lens_socket.HitRect, hx: i32, hy: i32, wash: *?lens_socket.HitRect, button: *?lens_socket.HitRect) void {
    for (hits) |r| {
        if (hx < r.x or hx >= @as(i32, r.x) + r.w or hy < r.y or hy >= @as(i32, r.y) + r.h) continue;
        switch (r.target) {
            .seat => wash.* = r, // the whole lens card
            // The whole-bar toggle is clickable but should NOT wash on hover —
            // only its chevron (the .caret sub-hit) lights up.
            .toggle => {},
            else => button.* = r, // caret, expand, reorder, swatch_open, get_more…
        }
    }
}

/// Build + draw the hover highlight: a subtle wash over the post under the
/// cursor and a brighter highlight behind the specific button under it. Driven
/// by g.hover_x/y (logical coords) hit-tested against THIS frame's regions, into
/// a small overlay vert buffer — so a pointer move never rebuilds the feed.
fn drawHoverOverlay(gpa: Allocator, g: Grid, gs: *GpuState, scale: f32, vw: i32, vh: i32) void {
    var wash: ?feed_view.Region = null; // the post under the cursor
    var button: ?feed_view.Region = null; // a button/control under the cursor
    // Socket tap targets live in their own HitLists (not g.regions), so scan
    // them too: a `.seat` (whole card) reads as the wash, sub-controls as the
    // brighter button — the same wash/button split the feed uses.
    var sock_wash: ?lens_socket.HitRect = null;
    var sock_button: ?lens_socket.HitRect = null;
    if (g.hover_x >= 0) {
        for (g.regions.items) |r| {
            if (g.hover_x < r.x or g.hover_x >= @as(i32, r.x) + r.w or g.hover_y < r.y or g.hover_y >= @as(i32, r.y) + r.h) continue;
            switch (r.kind) {
                .post_body => wash = r,
                .tag_inline => {}, // an inline hashtag underlines in drawSocketHoverTop (on TOP of the feed); the post wash here still fires via .post_body
                .compose_send, .compose_cancel => {},
                else => button = r, // engagement, avatar, nav, tabs, edit, pill, back…
            }
        }
        // The active socket (feed on home, reply on the thread, feed on the
        // loadout page) is always live; the reply/zone sockets are only laid
        // out by layoutLoadout, so scan them only on that screen.
        scanSocketHits(g.socket_hits.items, g.hover_x, g.hover_y, &sock_wash, &sock_button);
        if (g.screen.* == feed_view.screen_loadout) {
            scanSocketHits(g.reply_hits.items, g.hover_x, g.hover_y, &sock_wash, &sock_button);
            scanSocketHits(g.zone_hits.items, g.hover_x, g.hover_y, &sock_wash, &sock_button);
        }
    }
    // Ease toward present/absent so the highlight fades rather than snaps.
    const target: f32 = if (wash != null or button != null or sock_wash != null or sock_button != null) 1.0 else 0.0;
    gs.hover_alpha += (target - gs.hover_alpha) * 0.30;
    if (gs.hover_alpha < 0.02) return;

    // Scale each highlight's alpha byte by the eased opacity.
    // Post wash bumped 0x0E → 0x16 (~1.6×): the large post area read too faint at
    // 5.5% while the smaller icon/nav highlights (0x1C) looked right.
    const wash_a: u32 = @intFromFloat(@as(f32, 0x16) * gs.hover_alpha);
    const btn_a: u32 = @intFromFloat(@as(f32, 0x1C) * gs.hover_alpha);
    var hd: raster_core.DrawList = .{};
    defer hd.deinit(gpa);
    // The feed wash/button sit BEHIND the feed: posts are translucent glass over
    // the field, so the highlight shows through. The socket is NOT drawn here —
    // its panels are opaque, so a highlight behind them is occluded. It draws in
    // drawSocketHoverTop (after the feed) instead; the sock_* detection above
    // only feeds the easing target so the alpha rises while over the socket.
    if (wash) |r| hd.append(gpa, .{ .rect = .{ .x = r.x, .y = r.y, .w = r.w, .h = r.h, .color = (wash_a << 24) | 0x00FFFFFF, .radius = 0 } }) catch {};
    if (button) |r| hd.append(gpa, .{ .rect = .{ .x = @intCast(@as(i32, r.x) - 4), .y = r.y, .w = r.w + 8, .h = r.h, .color = (btn_a << 24) | 0x00FFFFFF, .radius = 12 } }) catch {};
    if (hd.len == 0) return;
    gpu.feedBuild(&gs.hover, gpa, g.engine, hd.slice(), scale) catch return;
    gpu.feedDraw(&gs.hover, vw, vh);
}

/// A press on the rooted post's body: place the caret + begin a drag (single
/// click), or select the word (double) / line (triple) under it — the standard
/// text affordances, counted by the same time+proximity rule the composer uses.
fn selectPress(gs: *GpuState, rx: i32, ry: i32, last_ns: *u64, last_x: *i32, last_y: *i32, count: *u8, now_ns: u64) void {
    const near = @abs(rx - last_x.*) <= 3 and @abs(ry - last_y.*) <= 3;
    count.* = if (now_ns -| last_ns.* < 400_000_000 and near) count.* + 1 else 1;
    last_ns.* = now_ns;
    last_x.* = rx;
    last_y.* = ry;
    const caret = text_select.caretAtPoint(gs.sel_glyphs.items, rx, ry);
    switch (@min(count.*, @as(u8, 3))) {
        1 => {
            gs.sel_anchor = caret;
            gs.sel_focus = caret;
            gs.sel_dragging = true; // single click → drag-extend
        },
        2 => {
            const s = text_select.wordAt(gs.sel_glyphs.items, caret);
            gs.sel_anchor = s.lo;
            gs.sel_focus = s.hi;
            gs.sel_dragging = false;
        },
        else => {
            // Triple click → the WHOLE post. A wrapped "line" is just a layout
            // break here, not a meaningful unit, so word → post is the ladder.
            gs.sel_anchor = 0;
            gs.sel_focus = @intCast(gs.sel_glyphs.items.len);
            gs.sel_dragging = false;
        },
    }
}

// The right-click context menu over a rooted post's selectable text.
const menu_w: i32 = 184;
const menu_row_h: i32 = 30;
const menu_pad_y: i32 = 6;
const menu_items = [_][]const u8{ "Copy", "Select all" };

fn clampI16(v: i32) i16 {
    return @intCast(std.math.clamp(v, -32768, 32767));
}
fn clampU16(v: i32) u16 {
    return @intCast(std.math.clamp(v, 0, 65535));
}

/// Right-click on the rooted post body opens the menu at the cursor. With no
/// selection yet, it first selects the word under the cursor so Copy has a
/// target (browser behaviour). A miss (not the rooted body) does nothing.
fn openContextMenu(gs: *GpuState, screen: u8, view_items: []const feed_core.TimelineItem, regions: []const feed_view.Region, rx: i32, ry: i32) void {
    if (screen != feed_view.screen_thread) return;
    const hit = feed_view.hitTest(regions, rx, ry) orelse return;
    if (hit.kind != .post_body or hit.post >= view_items.len or !view_items[hit.post].is_focus) return;
    const r = text_select.range(gs.sel_glyphs.items.len, gs.sel_anchor, gs.sel_focus);
    if (r.hi <= r.lo) {
        const caret = text_select.caretAtPoint(gs.sel_glyphs.items, rx, ry);
        const w = text_select.wordAt(gs.sel_glyphs.items, caret);
        gs.sel_anchor = w.lo;
        gs.sel_focus = w.hi;
    }
    gs.menu_open = true;
    gs.menu_x = std.math.clamp(rx, 0, @as(i32, @intCast(design_w)) - menu_w);
    gs.menu_y = @max(0, ry);
}

/// The menu item (0=Copy, 1=Select all) under the pointer, or null.
fn menuItemAt(gs: *const GpuState, rx: i32, ry: i32) ?u8 {
    if (rx < gs.menu_x or rx >= gs.menu_x + menu_w) return null;
    var i: u8 = 0;
    while (i < menu_items.len) : (i += 1) {
        const iy = gs.menu_y + menu_pad_y + @as(i32, i) * menu_row_h;
        if (ry >= iy and ry < iy + menu_row_h) return i;
    }
    return null;
}

/// A click while the menu is open: run the item under the pointer (or just close
/// on a click outside). Always closes the menu.
fn menuClick(gpa: Allocator, gs: *GpuState, backend: Backend, rx: i32, ry: i32) void {
    defer gs.menu_open = false;
    const item = menuItemAt(gs, rx, ry) orelse return;
    switch (item) {
        0 => copySelection(gpa, gs, backend),
        1 => {
            gs.sel_anchor = 0;
            gs.sel_focus = @intCast(gs.sel_glyphs.items.len);
        },
        else => {},
    }
}

/// Copy the current selection to the clipboard (no-op if empty). Shared by the
/// menu's Copy and the Ctrl+C key path.
fn copySelection(gpa: Allocator, gs: *GpuState, backend: Backend) void {
    const r = text_select.range(gs.sel_glyphs.items.len, gs.sel_anchor, gs.sel_focus);
    if (r.hi <= r.lo) return;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(gpa);
    text_select.copyInto(gpa, &buf, gs.sel_glyphs.items, gs.sel_anchor, gs.sel_focus) catch return;
    if (buf.items.len == 0) return;
    switch (backend) {
        .window => |w| window_shell.setClipboard(w, buf.items),
        .terminal => {},
    }
}

/// Append a UTF-8 run as proportional glyph items (the shell's own little text
/// emitter for the menu — feed_view owns the feed's text; this is just chrome).
fn menuText(dl: *raster_core.DrawList, gpa: Allocator, engine: *const text_core.Engine, x: i32, baseline: i32, color: u32, px: u16, s: []const u8) void {
    var pen = x;
    var it = (std.unicode.Utf8View.init(s) catch return).iterator();
    while (it.nextCodepoint()) |cp| {
        dl.append(gpa, .{ .text = .{ .x = clampI16(pen), .baseline = clampI16(baseline), .codepoint = cp, .color = color, .px = px, .weight = 0 } }) catch return;
        pen += @intCast(text_core.advance(engine, .regular, cp, px));
    }
}

/// Draw the context menu on top of everything: a rounded slab, a row hover
/// highlight, and the item labels (Copy dim when there's nothing selected).
fn drawContextMenu(gpa: Allocator, g: Grid, gs: *GpuState, scale: f32, vw: i32, vh: i32) void {
    if (!gs.menu_open) return;
    const x = gs.menu_x;
    const y = gs.menu_y;
    const h: i32 = menu_pad_y * 2 + menu_row_h * @as(i32, menu_items.len);
    var dl: raster_core.DrawList = .{};
    defer dl.deinit(gpa);
    dl.append(gpa, .{ .rect = .{ .x = clampI16(x), .y = clampI16(y), .w = clampU16(menu_w), .h = clampU16(h), .color = 0xF21C1E26, .radius = 10 } }) catch {};
    const has_sel = blk: {
        const r = text_select.range(gs.sel_glyphs.items.len, gs.sel_anchor, gs.sel_focus);
        break :blk r.hi > r.lo;
    };
    for (menu_items, 0..) |label, i| {
        const iy = y + menu_pad_y + @as(i32, @intCast(i)) * menu_row_h;
        const hovered = g.hover_x >= x and g.hover_x < x + menu_w and g.hover_y >= iy and g.hover_y < iy + menu_row_h;
        if (hovered) dl.append(gpa, .{ .rect = .{ .x = clampI16(x + 4), .y = clampI16(iy + 2), .w = clampU16(menu_w - 8), .h = clampU16(menu_row_h - 4), .color = 0x24FFFFFF, .radius = 6 } }) catch {};
        const dim = i == 0 and !has_sel; // Copy is dim with no selection
        const color: u32 = if (dim) 0x66E8EAED else 0xFFE8EAED;
        menuText(&dl, gpa, g.engine, x + 14, iy + 20, color, 15, label);
    }
    gpu.feedBuild(&gs.menu, gpa, g.engine, dl.slice(), scale) catch return;
    gpu.feedDraw(&gs.menu, vw, vh);
}

/// The rooted post's read-only text selection: one translucent accent band per
/// selected line, drawn BEHIND the feed text (the glyphs land on top, so it
/// reads as a highlight). The bands come from the pure `text_select` core over
/// the body glyphs captured this rebuild; the indices are clamped there, so a
/// just-shrunk glyph run can't read out of bounds. Thread screen only.
fn drawSelectionOverlay(gpa: Allocator, g: Grid, gs: *GpuState, scale: f32, vw: i32, vh: i32) void {
    if (g.screen.* != feed_view.screen_thread) return;
    const r = text_select.range(gs.sel_glyphs.items.len, gs.sel_anchor, gs.sel_focus);
    if (r.hi <= r.lo) return;
    var rects: std.ArrayListUnmanaged(text_select.Rect) = .empty;
    defer rects.deinit(gpa);
    // Body text is 16px: ~14px above the baseline, ~4px below, covers the band.
    text_select.highlightRects(gpa, &rects, gs.sel_glyphs.items, gs.sel_anchor, gs.sel_focus, 14, 4) catch return;
    if (rects.items.len == 0) return;
    var hd: raster_core.DrawList = .{};
    defer hd.deinit(gpa);
    const accent = g.accent & 0x00FFFFFF;
    // One CONTINUOUS selection: each wrapped line's band is extended down to the
    // next line's top so they abut (no gaps, no per-line pills), with only a
    // gentle uniform softening. A whole-selection breath on the fill keeps a bit
    // of life without the busy per-line glow that read as disjointed blobs.
    const pulse: f32 = 0.5 + 0.5 * @sin(gs.t * 1.8);
    const fill_a: u32 = @intFromFloat(@as(f32, 0x44) + pulse * @as(f32, 0x12)); // ~68..86
    for (rects.items, 0..) |rc, i| {
        // Abut: a non-last line fills the leading down to the next line's top.
        const h: i32 = if (i + 1 < rects.items.len) rects.items[i + 1].y - rc.y else rc.h;
        hd.append(gpa, .{ .rect = .{
            .x = clampI16(rc.x),
            .y = clampI16(rc.y),
            .w = clampU16(rc.w),
            .h = clampU16(h),
            .color = (fill_a << 24) | accent,
            .radius = 2,
        } }) catch {};
    }
    // Bracket beams: a crisp bright accent bar at the selection's exact start and
    // end (the | | the owner pictured) — drawn ON TOP of the fill so they read as
    // clean range markers. They sit at the first/last glyphs' edges and span the
    // text line height (not the abutted leading).
    if (rects.items.len > 0) {
        const first = rects.items[0];
        const last = rects.items[rects.items.len - 1];
        const beam: u32 = (@as(u32, 0xCC) << 24) | accent;
        hd.append(gpa, .{ .rect = .{ .x = clampI16(first.x - 1), .y = clampI16(first.y), .w = 2, .h = clampU16(first.h), .color = beam, .radius = 1 } }) catch {};
        hd.append(gpa, .{ .rect = .{ .x = clampI16(last.x + last.w - 1), .y = clampI16(last.y), .w = 2, .h = clampU16(last.h), .color = beam, .radius = 1 } }) catch {};
    }
    if (hd.len == 0) return;
    gpu.feedBuild(&gs.sel, gpa, g.engine, hd.slice(), scale) catch return;
    gpu.feedDraw(&gs.sel, vw, vh);
}

/// The socket half of the hover highlight, drawn AFTER the feed (on top): the
/// socket panels are opaque, so its wash/button can't go behind the feed like
/// the post highlight does. Reuses the eased `gs.hover_alpha` set this frame by
/// drawHoverOverlay (which already folded the socket into its target), and the
/// same gs.hover vert buffer — built+drawn after the feed so it lands on top.
fn drawSocketHoverTop(gpa: Allocator, g: Grid, gs: *GpuState, scale: f32, vw: i32, vh: i32) void {
    if (g.hover_x < 0 or gs.hover_alpha < 0.02) return;
    var sock_wash: ?lens_socket.HitRect = null;
    var sock_button: ?lens_socket.HitRect = null;
    scanSocketHits(g.socket_hits.items, g.hover_x, g.hover_y, &sock_wash, &sock_button);
    if (g.screen.* == feed_view.screen_loadout) {
        scanSocketHits(g.reply_hits.items, g.hover_x, g.hover_y, &sock_wash, &sock_button);
        scanSocketHits(g.zone_hits.items, g.hover_x, g.hover_y, &sock_wash, &sock_button);
    }
    // An inline `#tag` under the cursor gets an UNDERLINE — drawn HERE (after the
    // feed) so it lands on TOP of the prose, not behind the translucent post like
    // the wash. The "this is a link" affordance the user asked for.
    var tag_ul: ?feed_view.Region = null;
    for (g.regions.items) |r| {
        if (r.kind != .tag_inline) continue;
        if (g.hover_x < r.x or g.hover_x >= @as(i32, r.x) + r.w or g.hover_y < r.y or g.hover_y >= @as(i32, r.y) + r.h) continue;
        tag_ul = r;
    }
    if (sock_wash == null and sock_button == null and tag_ul == null) return;

    const wash_a: u32 = @intFromFloat(@as(f32, 0x0E) * gs.hover_alpha);
    const btn_a: u32 = @intFromFloat(@as(f32, 0x1C) * gs.hover_alpha);
    var hd: raster_core.DrawList = .{};
    defer hd.deinit(gpa);
    // Card wash is rounded to match the cards; the sub-control highlight is the
    // feed's pill. Both translucent white on top — a lift, not a veil.
    if (sock_wash) |r| hd.append(gpa, .{ .rect = .{ .x = r.x, .y = r.y, .w = r.w, .h = r.h, .color = (wash_a << 24) | 0x00FFFFFF, .radius = 10 } }) catch {};
    if (sock_button) |r| hd.append(gpa, .{ .rect = .{ .x = @intCast(@as(i32, r.x) - 4), .y = r.y, .w = r.w + 8, .h = r.h, .color = (btn_a << 24) | 0x00FFFFFF, .radius = 12 } }) catch {};
    if (tag_ul) |r| {
        const ul_a: u32 = @intFromFloat(@as(f32, 0xFF) * gs.hover_alpha);
        const uy: i32 = @as(i32, r.y) + @as(i32, r.h) - 1;
        hd.append(gpa, .{ .rect = .{ .x = r.x, .y = @intCast(uy), .w = r.w, .h = 2, .color = (ul_a << 24) | 0x004DA3FF, .radius = 0 } }) catch {}; // 0x4DA3FF = feed_view tag_blue
    }
    if (hd.len == 0) return;
    gpu.feedBuild(&gs.hover, gpa, g.engine, hd.slice(), scale) catch return;
    gpu.feedDraw(&gs.hover, vw, vh);
}

/// Draw the engagement heart for EVERY visible like button as an SDF heart, at
/// the heart's real place in the feed — the like region's LEFT edge (the region
/// also spans the count, so its CENTRE sits too far right; that mismatch was the
/// "offset overlay" bug). `fill` is the post's liked state; if a like effect is
/// live for that post it ANIMATES (bottom-up fill + scale pop + star burst) from
/// the pure, tested `effect.heartVisual`. This is the ONE heart on the GPU path
/// (feed_view skips its own), so the fill happens IN PLACE. No allocation.
/// The SDF-icon pass: crisp engagement / nav icons drawn in place (feed_view
/// skips the line-art for these on the GPU path). Prototype set — the repost
/// (per .repost region, green when the viewer reposted) and the gear (the
/// Settings rail slot). Positions mirror feed_view's icon offsets; the full
/// rollout will have feed_view emit exact placements.
fn drawSdfIcons(g: Grid, gs: *GpuState, items: []const feed_core.TimelineItem, vw: i32, vh: i32) void {
    const scale = gs.scale;
    const header_bottom: i32 = if (g.screen.* == feed_view.screen_home)
        feed_view.homeSocketBottom(g.socket_tray, g.socket_ui)
    else
        feed_view.headerBottom(g.screen.*);
    const grey: u32 = 0xFFB4B1A8; // feed_view.icon_grey (soft white)
    const muted: u32 = 0xFF9A968A; // feed_view.muted (inactive nav)
    const green: u32 = 0xFF8FD18F; // feed_view.boost_c (reposted)
    const eng: f32 = 9.5 * scale; // engagement icon half-extent
    const nav: f32 = 11.0 * scale; // rail icon half-extent (line-art was 22 box)
    // Engagement icons scroll under the sticky header; clip them there.
    const clipped = struct {
        fn f(r: feed_view.Region, hb: i32) bool {
            return @as(i32, r.y) + @divTrunc(@as(i32, r.h), 2) < hb;
        }
    }.f;
    for (g.regions.items) |r| {
        const cy = (@as(f32, @floatFromInt(r.y)) + @as(f32, @floatFromInt(r.h)) * 0.5) * scale;
        switch (r.kind) {
            // LEFT engagement group — the icon sits at region.x + is/2 (8.5).
            .reply => {
                if (clipped(r, header_bottom)) continue;
                gpu.drawIcon(&gs.icon, gpu.icon_reply, (@as(f32, @floatFromInt(r.x)) + 8.5) * scale, cy, eng, grey, vw, vh);
            },
            .repost => {
                if (clipped(r, header_bottom) or r.post >= items.len) continue;
                const col = if (items[r.post].item_flags.viewer_reposted) green else grey;
                gpu.drawIcon(&gs.icon, gpu.icon_repost, (@as(f32, @floatFromInt(r.x)) + 8.5) * scale, cy, eng, col, vw, vh);
            },
            // RIGHT engagement group — the icon centres in its (narrower) region.
            .bookmark, .share, .more => {
                if (clipped(r, header_bottom)) continue;
                const cx = (@as(f32, @floatFromInt(r.x)) + @as(f32, @floatFromInt(r.w)) * 0.5) * scale;
                const id: i32 = switch (r.kind) {
                    .bookmark => gpu.icon_bookmark,
                    .share => gpu.icon_share,
                    else => gpu.icon_more,
                };
                gpu.drawIcon(&gs.icon, id, cx, cy, eng, grey, vw, vh);
            },
            // The nav rail (mirrors drawRail's icon at region.x+10, size 22 →
            // centre +21 / +19). Drawn on EVERY screen incl. the loadout page, so
            // the Algorithms tab gets the same crisp SDF icons as the rest (it used
            // to be excluded here + line-art in layoutLoadout — which looked worse).
            .nav => {
                const id: i32 = switch (r.post) {
                    0 => gpu.icon_home,
                    1 => gpu.icon_hash, // Zones
                    2 => gpu.icon_heart, // Activity
                    3 => gpu.icon_reply, // Messages
                    4 => gpu.icon_sliders, // Algorithms
                    5 => gpu.icon_gear, // Settings
                    else => continue, // the "you" card (post 7) is an avatar, not an icon
                };
                const cx = (@as(f32, @floatFromInt(r.x)) + 21.0) * scale;
                const ncy = (@as(f32, @floatFromInt(r.y)) + 19.0) * scale;
                const col: u32 = if (@as(u16, g.screen.*) == r.post) g.accent else muted;
                gpu.drawIcon(&gs.icon, id, cx, ncy, nav, col, vw, vh);
            },
            else => {},
        }
    }
}

/// The Julia toggle-ON spark: a ring of SDF hearts flying out of the switch,
/// drawn over everything so it can't hide behind a panel. Procedural (no
/// per-heart storage) — positions derive from the burst clock + index; each
/// heart flies outward, arcs up a touch, and shrinks as it fades. ~14 hearts for
/// ~0.5s, one draw call each — negligible. Decrements the clock each frame.
fn drawJuliaBurst(gs: *GpuState, vw: i32, vh: i32) void {
    if (gs.julia_burst_t <= 0) return;
    const t = gs.julia_burst_t; // 1 → 0
    const prog = 1.0 - t; // 0 → 1
    const n: u32 = 10;
    const maxdist: f32 = 150.0 * gs.scale;
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        const ang = @as(f32, @floatFromInt(i)) * (6.2831853 / @as(f32, @floatFromInt(n))) + 0.3;
        const dist = prog * maxdist;
        const px = gs.julia_burst_x + @cos(ang) * dist;
        const py = gs.julia_burst_y + @sin(ang) * dist - prog * prog * 50.0 * gs.scale; // arc up
        const size = (9.0 + 7.0 * t) * gs.scale; // shrink as they fade
        // Each heart's SDF runs over a full-screen triangle — without a scissor,
        // N hearts = N full-screen fragment passes (the lag spike). Clip each to
        // its own small box so it only shades ~(box²) px. GL origin is bottom-left.
        const box = size * 3.0;
        gpu.pushScissor(@intFromFloat(px - box), @intFromFloat(@as(f32, @floatFromInt(vh)) - py - box), @intFromFloat(box * 2.0), @intFromFloat(box * 2.0));
        gpu.drawHeart(&gs.heart, px, py, size, 1.0, 1.0 + 0.4 * t, t, 0.0, vw, vh);
    }
    gpu.popScissor();
    gs.julia_burst_t = @max(0.0, t - 0.03); // ~33 frames ≈ 0.55s
}

fn drawEngagementHearts(g: Grid, gs: *GpuState, items: []const feed_core.TimelineItem, vw: i32, vh: i32) void {
    const scale = gs.scale;
    const s = g.active.slice();
    const recipes = s.items(.recipe);
    const axs = s.items(.x);
    const ays = s.items(.y);
    const stages = s.items(.stage);
    const stage_ts = s.items(.stage_t);
    // The sticky header occludes the post text (it's painted over it in the feed
    // draw list), but the heart is a SEPARATE pass on top — so it would bleed
    // over the frosted header as a post scrolls up. Clip it: skip any heart whose
    // row has crossed under the header band. feed_view owns the exact height so
    // this can't drift from it (the profile-tabs growth broke the old hardcode).
    // On Home, the OPEN lens-socket tray drops over the posts; clip hearts to
    // its bottom too, or they bleed over it (the socket only draws once, on
    // top, but the heart pass is separate).
    const header_bottom: i32 = if (g.screen.* == feed_view.screen_home)
        feed_view.homeSocketBottom(g.socket_tray, g.socket_ui)
    else
        feed_view.headerBottom(g.screen.*);
    for (g.regions.items) |r| {
        if (r.kind != .like or r.post >= items.len) continue;
        if (@as(i32, r.y) + @divTrunc(@as(i32, r.h), 2) < header_bottom) continue;
        const liked = items[r.post].item_flags.viewer_liked;
        // Heart centre: the region starts at the heart's left edge; the icon box
        // is 16 logical wide, so the heart centres 8 in. Vertical centre of the
        // region row. [TUNE] 8 = is/2; size 9 = half the icon box.
        const cx: f32 = (@as(f32, @floatFromInt(r.x)) + 8.5) * scale; // icon box is 17 wide
        const cy: f32 = (@as(f32, @floatFromInt(r.y)) + @as(f32, @floatFromInt(r.h)) * 0.5) * scale;
        const size: f32 = 11.0 * scale; // was 9 — the heart read small next to the line icons
        // Static fill from the liked state; overridden by the live animation if
        // a like effect for this post is playing (matched by its heart cell).
        var vis = effect_core.HeartVisual{ .fill = if (liked) 1.0 else 0.0, .scale = 1.0, .glow = 0.0, .burst = 0.0 };
        if (heartFieldCell(g, gs, r.post)) |cell| {
            const hx: u16 = @intCast(@min(cell.x, std.math.maxInt(u16)));
            const hy: u16 = @intCast(@min(cell.y, std.math.maxInt(u16)));
            var i: usize = 0;
            while (i < g.active.len) : (i += 1) {
                if (recipes[i] != &effect_core.like_heart and recipes[i] != &effect_core.unlike_heart) continue;
                if (axs[i] == hx and ays[i] == hy) {
                    vis = effect_core.heartVisual(recipes[i], stages[i], stage_ts[i]);
                    break;
                }
            }
        }
        gpu.drawHeart(&gs.heart, cx, cy, size, vis.fill, vis.scale, vis.glow, vis.burst, vw, vh);
    }
}

/// Fire the field effect for an engagement transition at the post's heart
/// cell — the ONE place an engagement maps to a recipe, derived from the
/// transition itself (liking vs unliking), not from a separate click
/// handler that could race the toggle. `now_liked` is the state AFTER the
/// toggle: true ⇒ a like burst, false ⇒ the unlike drain. The heart cell
/// is found from the frame's heart slots by the post's index. Errors are
/// swallowed: a missed effect must never break the action (E4).
fn fireEngageEffect(gpa: Allocator, g: Grid, kind: Engagement, target: u32, now_liked: bool) void {
    // GPU path: the living field IS the effect. Inject the like/boost burst as
    // a SPLASH (energy + red dye) into the medium at the post's heart cell;
    // the medium carries and keeps it. The software effect list is NOT advanced
    // on the GPU path, so firing it here would only accumulate — so we don't.
    // An unlike has no dye-removal in v1 (the stain persists by design).
    if (g.gpu) |gs| {
        if (heartFieldCell(g, gs, target)) |cell| {
            const hx: u16 = @intCast(@min(cell.x, std.math.maxInt(u16)));
            const hy: u16 = @intCast(@min(cell.y, std.math.maxInt(u16)));
            if (now_liked or kind == .repost) {
                // Like / boost: splash the field, and (for a like) pop the heart.
                // The RED dye is the like's alone — a repost gets only the
                // colourless ripple (no dye stain). The field ripple + dye are
                // gated by the "Ripples on like" toggle; the heart pop is not.
                if (g.ripples_on) pushLikeSplash(gpa, gs, cell.x, cell.y, now_liked and kind == .like);
                if (now_liked and kind == .like) {
                    effect_core.trigger(gpa, g.active, &effect_core.like_heart, hx, hy, 1.0) catch {};
                }
            } else if (kind == .like) {
                // Unlike: DRAIN the heart back to hollow (no field splash — the
                // dye is permanent ink in the medium by design).
                effect_core.trigger(gpa, g.active, &effect_core.unlike_heart, hx, hy, 1.0) catch {};
            }
        }
        if (debug_effects) {
            const name = switch (kind) {
                .like => if (now_liked) "like(fill)" else "unlike(drain)",
                .repost => "boost",
            };
            std.debug.print("[zat] gpu splash {s} for post {d}\n", .{ name, target });
        }
        return;
    }
    const recipe: *const effect_core.Recipe = switch (kind) {
        .like => if (now_liked) &effect_core.like_heart else &effect_core.unlike_heart,
        .repost => &effect_core.boost,
    };
    // Locate the heart cell for this post in the current frame's slots.
    const txs = g.hearts.slice().items(.target);
    const hxs = g.hearts.slice().items(.x);
    const hys = g.hearts.slice().items(.y);
    for (txs, hxs, hys) |tg, hx, hy| {
        if (tg == target) {
            effect_core.trigger(gpa, g.active, recipe, hx, hy, 1.0) catch {};
            // DIAGNOSTIC (temporary, shell-side I/O is allowed): when
            // `debug_effects` is true, every effect actually fired prints one
            // stderr line, so a single click that should fire ONE effect can
            // be checked against what really happens on the real machine —
            // there is no live GUI here to watch (G2: profile the affected
            // hardware, don't guess). A compile-time const, not a global var
            // and not a 0.16-absent getenv: zero cost when false, and it
            // obeys the project's no-globals/capability rules. One unlike
            // click should print exactly one `unlike(drain)`. Two lines — or
            // an `unlike` then a `like` — means the toggle is firing more than
            // once (a click-path bug); exactly one means the trigger is fine
            // and any visual doubling is in the renderer.
            if (debug_effects) {
                const name = switch (kind) {
                    .like => if (now_liked) "like(fill)" else "unlike(drain)",
                    .repost => "boost",
                };
                std.debug.print("[zat] fired {s} at cell ({d},{d}); active effects now = {d}\n", .{ name, hx, hy, g.active.len });
            }
            return;
        }
    }
}

/// Find the field grid cell under post `target`'s like button, for the GPU
/// burst. The feed regions are in LOGICAL pixels (the feed lays out at
/// design_w); map a region's centre through the frame's DPI scale to physical
/// pixels, then to a field cell. Returns null if the post has no like region
/// this frame (scrolled out) — the caller then fires nothing (E4).
fn heartFieldCell(g: Grid, gs: *GpuState, target: u32) ?struct { x: u32, y: u32 } {
    for (g.regions.items) |r| {
        if (r.post == target and r.kind == .like) {
            const cx_logical: f32 = @as(f32, @floatFromInt(r.x)) + @as(f32, @floatFromInt(r.w)) / 2.0;
            const cy_logical: f32 = @as(f32, @floatFromInt(r.y)) + @as(f32, @floatFromInt(r.h)) / 2.0;
            const px: f32 = cx_logical * gs.scale;
            const py: f32 = cy_logical * gs.scale;
            const gx: u32 = @intFromFloat(@max(0.0, px / @as(f32, field_cell_w)));
            const gy: u32 = @intFromFloat(@max(0.0, py / @as(f32, field_cell_h)));
            return .{ .x = gx, .y = gy };
        }
    }
    return null;
}

fn present(
    gpa: Allocator,
    out: *std.Io.Writer,
    arena: Allocator,
    prev: *tui.Surface,
    next: *const tui.Surface,
    backend: Backend,
) !void {
    switch (backend) {
        .window => |win| return window_shell.present(win, next) catch {}, // E2: a lost blit is the next frame's problem
        .terminal => {},
    }
    const bytes = try tui.encodeDiff(arena, prev, next);
    if (bytes.len > 0) {
        try out.writeAll(bytes);
        try out.flush();
    }
    if (prev.width != next.width or prev.height != next.height) {
        try tui.resizeSurface(gpa, prev, next.width, next.height);
    }
    @memcpy(prev.chars.items, next.chars.items);
    @memcpy(prev.styles.items, next.styles.items);
}

const WindowSize = struct {
    // A7.2: cold struct, size guard waived — one per frame, returned by value.
    cols: u16,
    rows: u16,
};

/// Ask the kernel for the terminal size; polled each frame, which also
/// handles resize without signal machinery. Off Linux (or on failure) the
/// classic 80×24 stands in — same fallback std.Progress uses.
fn readWindowSize(fd: posix.fd_t) WindowSize {
    if (builtin.os.tag == .linux) {
        var ws: posix.winsize = undefined;
        const rc = std.os.linux.ioctl(fd, std.os.linux.T.IOCGWINSZ, @intFromPtr(&ws));
        if (posix.errno(rc) == .SUCCESS and ws.col > 0 and ws.row > 0) {
            return .{ .cols = ws.col, .rows = ws.row };
        }
    }
    return .{ .cols = 80, .rows = 24 };
}
