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
const feed_shell = @import("feed.zig");
const stream_shell = @import("stream.zig");
const cache_shell = @import("cache.zig");
const window_shell = @import("native.zig");
const gpu = @import("gpu.zig");
const glyph_field = @import("../core/glyph_field.zig");
const layout_core = @import("../core/layout.zig");
const raster_core = @import("../core/raster.zig");
const text_core = @import("../core/text.zig");
const field_core = @import("../core/field.zig");
const field_ui = @import("../core/field_ui.zig");
const feed_view = @import("../core/feed_view.zig");
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
) !void {
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
    var compose_buf: std.ArrayList(u8) = .empty;
    defer compose_buf.deinit(gpa);
    var compose_arena_state = std.heap.ArenaAllocator.init(gpa);
    defer compose_arena_state.deinit();
    var reply_target: ?write.ReplyTarget = null;
    var reply_handle: []const u8 = "";

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
    var gregions: feed_view.Regions = .empty;
    defer gregions.deinit(gpa);
    // The active top-level Screen (index into feed_view.nav_labels); the rail
    // sets it on a click. 0 = Home (the feed). Lives across frames in run().
    var gscreen: u8 = 0;

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

        // Drain write-worker results (the non-blocking like/unlike/repost
        // replies). On OK, nothing to do — the optimistic state already
        // shows the right thing. On a refusal or network error, REVERT the
        // optimism so the count returns to truth. This runs every loop
        // iteration, off the network thread, so the UI never blocked on the
        // write — the whole point of the worker.
        write_results.clearRetainingCapacity();
        try write_out.drain(gpa, &write_results);
        for (write_results.items) |res| {
            switch (res.outcome) {
                .ok => |uri| {
                    // Record OUR created like/repost uri so a later unlike/
                    // unrepost can delete that record — the AppView never sends
                    // viewer.like, so the optimistic path has no uri otherwise.
                    if (uri.len > 0) switch (res.kind) {
                        .like => feed_core.setLikeUri(gpa, store, res.cid, uri) catch {},
                        .repost => feed_core.setRepostUri(gpa, store, res.cid, uri) catch {},
                        .unlike, .unrepost => {},
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
            const outcome = feed_shell.refreshTimeline(gpa, arena, io, environ, session, appview_url, store, 30) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => blk: {
                    status = "auto-refresh: network error"; // contained
                    break :blk null;
                },
            };
            if (outcome) |result| switch (result) {
                .ok => |stats| if (stats.items_added > 0) {
                    state.selected = 0;
                    state.scroll_top = 0;
                    gview.scroll_rows = 0;
                    status = std.fmt.bufPrint(&status_buf, "+{d} new", .{stats.items_added}) catch "new posts";
                },
                .failed => {}, // a refused poll is silent; the next tick retries
            };
            if (outcome != null and outcome.? == .ok) {
                _ = cache_shell.saveStore(gpa, environ, store); // E4: a failed save is simply no cache
            }
        }

        const items = try feed_core.buildTimeline(arena, store);
        // pix exists exactly when a window backend has a live engine; the
        // composer and profile screens stay on the cell path this cut
        // (their pixel port is the recorded next slice).
        const pix: ?Grid = if (engine) |*e| .{ .engine = e, .field = &gfield, .particles = &gparticles, .active = &gactive, .draw = &gdraw, .hr = &ghr, .hearts = &ghearts, .view = &gview, .spawn_buf = &gspawn, .last_nanos = &glast_nanos, .zoom = &gzoom, .scroll = &gscroll_px, .content_h = &gcontent_h, .regions = &gregions, .screen = &gscreen, .gpu = if (gpu_state) |*gs| gs else null } else null;
        switch (mode) {
            .timeline => try paintFrame(gpa, out, arena, &prev, &next, backend, pix, items, &state, revealed.items, now, session.handle, status),
            .compose => {
                if (pix) |g| switch (backend) {
                    .window => |win| {
                        // Glyph-field composer (matches the timeline look).
                        const cell = cellSize(win.fb.width, gzoom);
                        const cols: u16 = @intCast(@max(16, win.fb.width / cell.w));
                        const rows: u16 = @intCast(@max(6, win.fb.height / cell.h));
                        if (gfield.cols != cols or gfield.rows != rows) {
                            field_core.deinit(gpa, &gfield);
                            try field_core.init(gpa, &gfield, cols, rows);
                        }
                        const cc = timeline_ui.countCodepoints(compose_buf.items);
                        const cursor = field_ui.buildCompose(&gfield, compose_buf.items, reply_handle, cc, status);
                        try field_core.compose(gpa, &gfield, gparticles.slice(), .{ .x = @floatFromInt(cols / 2), .y = @floatFromInt(rows / 3), .radius = @floatFromInt(cols), .ambient = 0.7 }, cell.w, cell.h, &gdraw);
                        // The cursor: a filled block at the insertion cell,
                        // tinted with the app accent (alpha-blended) rather
                        // than a stray literal — one look, one source.
                        try gdraw.append(gpa, .{ .rect = .{ .x = @intCast(@min(cursor.x * cell.w, 32767)), .y = @intCast(@min(cursor.y * cell.h, 32767)), .w = cell.w, .h = cell.h, .color = 0x88000000 | (field_core.palette[field_ui.col_accent] & 0x00FFFFFF), .radius = 0 } });
                        window_shell.presentDrawList(win, gpa, g.engine, gdraw.slice(), field_core.background) catch {};
                    },
                    .terminal => {
                        timeline_ui.buildComposeFrame(&next, compose_buf.items, reply_handle, status);
                        try present(gpa, out, arena, &prev, &next, backend);
                    },
                } else {
                    timeline_ui.buildComposeFrame(&next, compose_buf.items, reply_handle, status);
                    try present(gpa, out, arena, &prev, &next, backend);
                }
            },
            .profile => {
                if (pix) |g| switch (backend) {
                    .window => |win| {
                        const cell = cellSize(win.fb.width, gzoom);
                        const cols: u16 = @intCast(@max(16, win.fb.width / cell.w));
                        const rows: u16 = @intCast(@max(6, win.fb.height / cell.h));
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
                        try paintFrame(gpa, out, arena, &prev, &next, backend, pix, items, &state, revealed.items, now, session.handle, status);
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
                                const delta: i32 = if (pev.button == 5) 3 else -3;
                                g.view.scroll_rows += delta;
                                // The premium feed scrolls in PIXELS. Wheel down
                                // (button 5) moves content up, so the offset goes
                                // more negative; clamp so you cannot scroll past
                                // the ends (top = 0, bottom exposes the last post
                                // + a little breathing room). content_h is in the
                                // layout's space, so the viewport height matches.
                                g.scroll.* -= delta * 28;
                                const view_h: i32 = if (g.gpu != null)
                                    @intFromFloat(@as(f32, @floatFromInt(win.fb.height)) / gpu_scale)
                                else
                                    @intCast(win.fb.height);
                                const min_scroll: i32 = @min(0, view_h - g.content_h.* - 24);
                                g.scroll.* = @max(min_scroll, @min(0, g.scroll.*));
                                effect_core.shiftY(g.active, -delta);
                            },
                            .move => {
                                g.view.hover = if (field_ui.hitTest(cx, cy, g.hr.slice())) |hit| hit.target else field_ui.no_target;
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
                            .button_down => if (pev.button == 1) {
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
                                if (feed_view.hitTest(g.regions.items, rx, ry)) |hit| {
                                    switch (hit.kind) {
                                        // Left-rail destination: switch the active screen
                                        // (post carries the Screen index). The next frame
                                        // re-renders the body (sig folds in the screen).
                                        .nav => gscreen = @intCast(hit.post),
                                        // New-post button → the composer (cell path for now).
                                        .compose => mode = .compose,
                                        // Like / boost: the SAME path the keyboard uses —
                                        // optimistic toggle (heart fills red), persist via
                                        // the worker, and fire the splash + heart-pop.
                                        .like, .repost => if (hit.post < items.len) {
                                            state.selected = hit.post;
                                            const ek: Engagement = if (hit.kind == .like) .like else .repost;
                                            const r = try engageSelected(ek, gpa, arena, session, store, items[hit.post], hit.post, &state, revealed.items, now, out, &prev, &next, backend, pix, writer);
                                            if (r.status.len > 0) status = r.status;
                                        },
                                        // Reply → the thread/reply view (a later screen).
                                        .reply => {},
                                    }
                                } else if (field_ui.hitTest(cx, cy, g.hr.slice())) |hit| {
                                    if (hit.target != field_ui.no_target and hit.target < items.len) state.selected = hit.target;
                                    if (hit.action != .none) if (timeline_ui.keyFor(hit.action)) |byte| {
                                        try pumped_bytes.append(gpa, byte);
                                    };
                                }
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

            if (mode == .compose) {
                try handleComposeInput(gpa, arena, io, environ, session, out, backend, &prev, &next, &status, &status_buf, &mode, &compose_buf, &reply_target, &reply_handle, decoded.event, now);
                continue;
            }

            // Zoom (text scaling) is a window-render concern, so it is
            // handled here in the shell, before the core action dispatch
            // — the pure timeline_ui need not learn about pixel cells
            // (B2/D3), the same way wheel-scroll lives in the pointer
            // block, not the core Action enum. '+'/'=' grow the text,
            // '-'/'_' shrink it; only meaningful in the window (the
            // terminal has no pixel cells), so gated on an engine.
            if (engine != null) if (decoded.event == .char) {
                const zc = decoded.event.char;
                if (zc == '+' or zc == '=') {
                    gzoom = std.math.clamp(gzoom + 0.15, zoom_min, zoom_max);
                    status = "zoom in";
                    try paintFrame(gpa, out, arena, &prev, &next, backend, pix, items, &state, revealed.items, now, session.handle, status);
                    continue;
                } else if (zc == '-' or zc == '_') {
                    gzoom = std.math.clamp(gzoom - 0.15, zoom_min, zoom_max);
                    status = "zoom out";
                    try paintFrame(gpa, out, arena, &prev, &next, backend, pix, items, &state, revealed.items, now, session.handle, status);
                    continue;
                }
            };

            switch (timeline_ui.actionFor(decoded.event)) {
                .quit => break :main_loop,
                .refresh => {
                    status = "refreshing...";
                    try paintFrame(gpa, out, arena, &prev, &next, backend, pix, items, &state, revealed.items, now, session.handle, status);

                    const outcome = feed_shell.refreshTimeline(gpa, arena, io, environ, session, appview_url, store, 30) catch |err| switch (err) {
                        error.OutOfMemory => return err,
                        else => {
                            status = "network error"; // contained (E2)
                            continue;
                        },
                    };
                    status = switch (outcome) {
                        .ok => |stats| blk: {
                            if (stats.items_added > 0) {
                                // An explicit refresh asks to SEE the new —
                                // jump to the top. (Passive live arrivals
                                // still preserve the reading position.)
                                state.selected = 0;
                                state.scroll_top = 0;
                                gview.scroll_rows = 0;
                            }
                            break :blk if (stats.items_added == 0)
                                "no new posts"
                            else
                                std.fmt.bufPrint(&status_buf, "+{d} new at top", .{stats.items_added}) catch "new posts";
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
                    try paintFrame(gpa, out, arena, &prev, &next, backend, pix, items, &state, revealed.items, now, session.handle, status);

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
                .like => if (items.len > 0) {
                    const r = try engageSelected(.like, gpa, arena, session, store, items[state.selected], state.selected, &state, revealed.items, now, out, &prev, &next, backend, pix, writer);
                    if (r.status.len > 0) status = r.status;
                    if (r.skip_rest) continue;
                },
                .repost => if (items.len > 0) {
                    const r = try engageSelected(.repost, gpa, arena, session, store, items[state.selected], state.selected, &state, revealed.items, now, out, &prev, &next, backend, pix, writer);
                    if (r.status.len > 0) status = r.status;
                    if (r.skip_rest) continue;
                },
                .profile => if (items.len > 0) {
                    const item = items[state.selected];
                    status = "loading profile...";
                    try paintFrame(gpa, out, arena, &prev, &next, backend, pix, items, &state, revealed.items, now, session.handle, status);
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
                .toggle_reveal => if (items.len > 0) {
                    const item = items[state.selected];
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
                .follow => if (items.len > 0) {
                    const item = items[state.selected];
                    const did = feed_core.authorDidForCid(store, item.cid);
                    if (did.len > 0) {
                        status = "following...";
                        try paintFrame(gpa, out, arena, &prev, &next, backend, pix, items, &state, revealed.items, now, session.handle, status);
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
                .reply => if (items.len > 0) {
                    const item = items[state.selected];
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
                        compose_buf.clearRetainingCapacity();
                        status = "";
                        mode = .compose;
                    }
                },
                .new_post => {
                    reply_target = null;
                    reply_handle = "";
                    compose_buf.clearRetainingCapacity();
                    status = "";
                    mode = .compose;
                },
                else => |action| {
                    timeline_ui.applyAction(&state, action, items.len);
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
}

/// Remove the last codepoint from the draft (UTF-8-aware backspace).
fn popCodepoint(buf: *std.ArrayList(u8)) void {
    if (buf.items.len == 0) return;
    var end = buf.items.len - 1;
    while (end > 0 and (buf.items[end] & 0xC0) == 0x80) end -= 1;
    buf.shrinkRetainingCapacity(end);
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

fn handleComposeInput(
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
    compose_buf: *std.ArrayList(u8),
    reply_target: *?write.ReplyTarget,
    reply_handle: *[]const u8,
    ev: tui.InputEvent,
    now: i64,
) !void {
    switch (timeline_ui.actionForCompose(ev)) {
        .cancel => {
            mode.* = .timeline;
            status.* = "cancelled";
        },
        .backspace => popCodepoint(compose_buf),
        .insert => |cp| {
            if (timeline_ui.countCodepoints(compose_buf.items) >= 300) {
                status.* = "300 character limit";
            } else {
                var utf8_buf: [4]u8 = undefined;
                const len = std.unicode.utf8Encode(cp, &utf8_buf) catch 0;
                if (len > 0) try compose_buf.appendSlice(gpa, utf8_buf[0..len]);
            }
        },
        .send => {
            if (compose_buf.items.len == 0) {
                status.* = "nothing to post";
                return;
            }
            status.* = "posting...";
            timeline_ui.buildComposeFrame(next, compose_buf.items, reply_handle.*, status.*);
            try present(gpa, out, arena, prev, next, backend);
            // Transport failure is contained to a status line —
            // a wifi blip must not take the screen down (E2).
            // Only OOM stays fatal.
            const facets = write.resolveFacets(arena, io, environ, session, compose_buf.items) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => {
                    status.* = "network error";
                    return;
                },
            };
            const posted = write.createPost(gpa, arena, io, environ, session, compose_buf.items, facets, reply_target.*, now) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => {
                    status.* = "network error";
                    return;
                },
            };
            switch (posted) {
                .ok => {
                    compose_buf.clearRetainingCapacity();
                    reply_target.* = null;
                    reply_handle.* = "";
                    mode.* = .timeline;
                    status.* = "posted";
                },
                .failed => |failure| {
                    // The draft survives a refusal.
                    status.* = std.fmt.bufPrint(status_buf, "refused: {d} {s}", .{
                        failure.status, failure.code,
                    }) catch "refused";
                },
            }
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
    state: *timeline_ui.UiState,
    revealed_cids: []const []const u8,
    now: i64,
    out: *std.Io.Writer,
    prev: *tui.Surface,
    next: *tui.Surface,
    backend: Backend,
    pix: ?Grid,
    writer: ?*write_worker.Worker,
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
                .no_record_uri => return .{ .status = if (kind == .like) "refresh to unlike" else "refresh to unboost" },
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

            const fresh = try feed_core.buildTimeline(arena, store);
            try paintFrame(gpa, out, arena, prev, next, backend, pix, fresh, state, revealed_cids, now, session.handle, if (kind == .like) "unliking..." else "unboosting...");
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
    const fresh = try feed_core.buildTimeline(arena, store);
    try paintFrame(gpa, out, arena, prev, next, backend, pix, fresh, state, revealed_cids, now, session.handle, if (kind == .like) "liking..." else "boosting...");
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
    /// The GPU render path, present only when `gpu.init` succeeded on this
    /// window (else null → the software path renders, the rule's fallback).
    /// A pointer into run()'s `gpu_state` local; one-frame contract like the
    /// rest of Grid.
    gpu: ?*GpuState,
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
    /// The animated like-heart pass (SDF fill + pop + star burst), drawn over
    /// the feed for each active like effect this frame.
    heart: gpu.HeartRenderer,
    bias: []f32,
    splashes: std.ArrayList(glyph_field.Splash),
    cols: u32,
    rows: u32,
    t: f32,
    mcx: f32,
    mcy: f32,
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
};

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
    const ramp = try gpu.initFieldRenderer(gpa, engine, field_cell_w, field_cell_h);
    const grid = try gpu.initFieldGrid();
    const heart = try gpu.initHeartRenderer();

    const cols: u32 = @max(8, w / field_cell_w);
    const rows: u32 = @max(8, h / field_cell_h);
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
        .heart = heart,
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
    }
    return hh.final();
}

fn deinitGpuState(gpa: Allocator, gs: *GpuState) void {
    gs.splashes.deinit(gpa);
    if (gs.heights.len > 0) gpa.free(gs.heights);
    gpa.free(gs.bias);
    glyph_field.deinit(gpa, &gs.field);
    gpu.feedDeinit(&gs.feed, gpa);
    gpu.deinit(&gs.g);
}

/// Refit the CPU field grid + ambient-bias buffer to a new window size. New
/// buffers allocated BEFORE the old are freed, so a failed alloc leaves the
/// existing state (and its deinit) valid (C5). The dye/height reset on resize
/// is accepted for v1 (the field re-seeds calm); reproject later if wanted.
fn resizeGpuField(gpa: Allocator, gs: *GpuState, w: u32, h: u32) !void {
    const cols: u32 = @max(8, w / field_cell_w);
    const rows: u32 = @max(8, h / field_cell_h);
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
fn pushLikeSplash(gpa: Allocator, gs: *GpuState, gx: u32, gy: u32) void {
    if (gs.cols == 0 or gs.rows == 0) return;
    const sx = @min(gx, gs.cols - 1);
    const sy = @min(gy, gs.rows - 1);
    // A strong central splash THROWS the wave; two concentric rings of dyed
    // splashes carry the red OUTWARD on it, so a like visibly shoots out and
    // ripples — not a faint local blush. [TUNE: amp = wave reach, dye = red.]
    gs.splashes.append(gpa, .{ .x = sx, .y = sy, .radius = 6, .amp = 3.6, .dye = 1.0 }) catch {};
    const ring_dist = [_]f32{ 5.0, 9.0 };
    const ring_amp = [_]f32{ 1.8, 1.1 };
    const ring_dye = [_]f32{ 0.9, 0.6 };
    for (ring_dist, ring_amp, ring_dye) |dist, amp, dye| {
        var k: u32 = 0;
        while (k < 8) : (k += 1) {
            const ang = @as(f32, @floatFromInt(k)) * (6.2831853 / 8.0);
            const ox: i32 = @intFromFloat(@cos(ang) * dist);
            const oy: i32 = @intFromFloat(@sin(ang) * dist);
            const rx = std.math.clamp(@as(i32, @intCast(sx)) + ox, 0, @as(i32, @intCast(gs.cols - 1)));
            const ry = std.math.clamp(@as(i32, @intCast(sy)) + oy, 0, @as(i32, @intCast(gs.rows - 1)));
            gs.splashes.append(gpa, .{ .x = @intCast(rx), .y = @intCast(ry), .radius = 3, .amp = amp, .dye = dye }) catch {};
        }
    }
}

/// THE single source of truth for the glyph cell size. Two facts drive
/// it: (1) the cell HEIGHT is the pixel size the font rasterizes at, and
/// (2) the cell WIDTH must equal the font's real glyph ADVANCE at that
/// height — JetBrains Mono advances ~0.46× its pixel height (measured),
/// so a cell any wider than that floats each glyph in empty space (the
/// "F e l i c i a" wide-spacing bug). We therefore pick a target glyph
/// HEIGHT from the window width and set the width to the true advance.
/// A bigger window → taller glyphs → larger text, at a roughly constant
/// column count. The engine caches per px (text.glyph keys on px).
///
/// The advance ratio is a stable font constant, so the pure cellSize can
/// hold it without calling the engine (B2 preserved). It is asserted
/// against the real metric in a shell test so it cannot silently drift.
const glyph_advance_ratio: f32 = 0.46; // measured: advance(M)/px for JetBrains Mono
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
    items: []const feed_core.TimelineItem,
    state: *timeline_ui.UiState,
    revealed: []const []const u8,
    now: i64,
    account_handle: []const u8,
    status: []const u8,
) !void {
    if (pix) |g| switch (backend) {
        .window => |win| {
            if (items.len > 0 and state.selected >= items.len) state.selected = @intCast(items.len - 1);
            // Phase 6.4: when the GPU path is live, render the field + feed on
            // the GPU and return; the software path below is the fallback.
            if (g.gpu) |gs| {
                try paintFrameGpu(gpa, arena, win, g, gs, items, now);
                return;
            }
            // Cell size scales with the user zoom; the grid reflows to
            // fill the window at whatever size results. The font engine
            // rasterizes at the derived pixel height (cached per-size).
            const cell = cellSize(win.fb.width, g.zoom.*);
            const cols: u16 = @intCast(@max(24, win.fb.width / cell.w));
            const rows: u16 = @intCast(@max(8, win.fb.height / cell.h));
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
            _ = try field_ui.layoutShell(g.field, pane_cfg, g.hr, g.hearts, items, state.selected, g.view, revealed, now, account_handle, status, gpa);
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
            const feed_posts = feed_view.fromTimeline(arena, items, now) catch &[_]feed_view.PostView{};
            g.content_h.* = feed_view.layout(gpa, g.engine, @intCast(win.fb.width), @intCast(win.fb.height), feed_posts, g.scroll.*, g.draw, g.regions, null, false, g.screen.*) catch g.content_h.*;
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
    timeline_ui.buildFrame(next, items, state, revealed, now, account_handle, status);
    try present(gpa, out, arena, prev, next, backend);
}

/// The GPU render route (Phase 6.4), one frame: step the living field, render
/// it grid-intensity, then the premium feed on top, and swap. The feed is laid
/// out at the fixed LOGICAL design width and scaled to FILL the window (DPI),
/// exactly as the preview does. No per-frame pixel blit — render + swap.
fn paintFrameGpu(
    gpa: Allocator,
    arena: Allocator,
    win: *window_shell.Window,
    g: Grid,
    gs: *GpuState,
    items: []const feed_core.TimelineItem,
    now: i64,
) !void {
    const w: u32 = win.fb.width;
    const h: u32 = win.fb.height;
    gpu.setViewport(@intCast(w), @intCast(h));
    // Refit the field grid to the window when the cell count changes (cheap;
    // a few KB R32F). On a failed realloc keep the prior grid (E2).
    const want_cols: u32 = @max(8, w / field_cell_w);
    const want_rows: u32 = @max(8, h / field_cell_h);
    if (want_cols != gs.cols or want_rows != gs.rows) {
        resizeGpuField(gpa, gs, w, h) catch {};
    }

    const scale = uiScale(w);
    gs.scale = scale;
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
    const sig = feedSignature(items, g.scroll.*, w, h) ^ (@as(u64, g.screen.*) *% 0x9E37_79B9_7F4A_7C15);
    if (sig != gs.feed_sig or gs.feed.verts.items.len == 0) {
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
        g.content_h.* = feed_view.layout(gpa, g.engine, @intCast(design_w), @intCast(lh), feed_posts, g.scroll.*, g.draw, g.regions, gs.heights, true, g.screen.*) catch g.content_h.*;
        gpu.feedBuild(&gs.feed, gpa, g.engine, g.draw.slice(), scale) catch {};
    }

    // Advance the medium on a FIXED WALL-CLOCK timestep (≈60 Hz), at most once
    // per frame, so the field evolves at a constant real-time rate regardless of
    // how fast this loop spins. Stepping once per loop iteration coupled the sim
    // to the INPUT rate: a stream of mouse-motion events drove the loop far above
    // 60 fps, so the whole field's animation sped up whenever the pointer moved
    // (every disturbance everywhere running fast in lockstep — the "far corners
    // react too" symptom). With the clock gate, idle and active evolve
    // identically; only the splash the pointer injects is local to it.
    const dt_ns: u64 = 16_666_667; // 1/60 s
    const now_ns = clock_shell.monotonicNanos();
    const due = gs.last_step_nanos == 0 or (now_ns -| gs.last_step_nanos) >= dt_ns;
    if (due) {
        // Fill the time-driven ambient bias (shell side → the core stays pure,
        // B3): a slow drifting two-sine swell plus a finer term so the dense
        // interior is an ASSORTMENT of glyphs, not a wall of one symbol.
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
        // Advance the medium one step; queued splashes injected once.
        glyph_field.step(&gs.field, .{}, gs.splashes.items, gs.bias);
        gs.splashes.clearRetainingCapacity();
        // Tick the like-heart animation clocks on the same 60 Hz step (no
        // field.zig coupling — the GPU heart pass draws them from this clock).
        effect_core.advanceClocks(g.active, 1.0 / 60.0);
        gs.t += 1.0 / 60.0;
        // Advance the step clock by one tick; if we fell far behind (a stall),
        // snap to now and DROP the backlog rather than fast-forward the field.
        gs.last_step_nanos = if (gs.last_step_nanos == 0 or (now_ns -| gs.last_step_nanos) > dt_ns * 4)
            now_ns
        else
            gs.last_step_nanos + dt_ns;
    }

    // Render: the living field behind, the feed on top, then swap.
    gpu.uploadField(&gs.grid, gs.field.height, gs.field.dye, gs.field.cols, gs.field.rows);
    gpu.clear(gpu_clear_r, gpu_clear_g, gpu_clear_b);
    gpu.drawFieldGrid(&gs.grid, &gs.ramp, gs.mcx, gs.mcy, gs.t, @intCast(w), @intCast(h));
    // The feed verts persist across frames (rebuilt above only when the feed
    // changed); just draw them.
    gpu.feedDraw(&gs.feed, @intCast(w), @intCast(h));
    // The engagement hearts: one SDF heart per visible like button, drawn IN
    // PLACE (feed_view skips its own), so a like fills + pops the ACTUAL heart.
    drawEngagementHearts(g, gs, items, @intCast(w), @intCast(h));
    gpu.swap(&gs.g);
}

/// Draw the engagement heart for EVERY visible like button as an SDF heart, at
/// the heart's real place in the feed — the like region's LEFT edge (the region
/// also spans the count, so its CENTRE sits too far right; that mismatch was the
/// "offset overlay" bug). `fill` is the post's liked state; if a like effect is
/// live for that post it ANIMATES (bottom-up fill + scale pop + star burst) from
/// the pure, tested `effect.heartVisual`. This is the ONE heart on the GPU path
/// (feed_view skips its own), so the fill happens IN PLACE. No allocation.
fn drawEngagementHearts(g: Grid, gs: *GpuState, items: []const feed_core.TimelineItem, vw: i32, vh: i32) void {
    const scale = gs.scale;
    const s = g.active.slice();
    const recipes = s.items(.recipe);
    const axs = s.items(.x);
    const ays = s.items(.y);
    const stages = s.items(.stage);
    const stage_ts = s.items(.stage_t);
    for (g.regions.items) |r| {
        if (r.kind != .like or r.post >= items.len) continue;
        const liked = items[r.post].item_flags.viewer_liked;
        // Heart centre: the region starts at the heart's left edge; the icon box
        // is 16 logical wide, so the heart centres 8 in. Vertical centre of the
        // region row. [TUNE] 8 = is/2; size 9 = half the icon box.
        const cx: f32 = (@as(f32, @floatFromInt(r.x)) + 8.0) * scale;
        const cy: f32 = (@as(f32, @floatFromInt(r.y)) + @as(f32, @floatFromInt(r.h)) * 0.5) * scale;
        const size: f32 = 9.0 * scale;
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
                // The pop/drain are drawn by the GPU heart pass in paintFrameGpu;
                // triggering here lets advanceClocks tick them.
                pushLikeSplash(gpa, gs, cell.x, cell.y);
                if (now_liked and kind == .like) {
                    effect_core.trigger(gpa, g.active, &effect_core.like_heart, hx, hy, 1.0) catch {};
                }
            } else if (kind == .like) {
                // Unlike: DRAIN the heart back to hollow (no field splash — the
                // red dye is permanent ink in the medium by design).
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
