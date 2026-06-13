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
const layout_core = @import("../core/layout.zig");
const raster_core = @import("../core/raster.zig");
const text_core = @import("../core/text.zig");
const field_core = @import("../core/field.zig");
const field_ui = @import("../core/field_ui.zig");
const effect_core = @import("../core/effect.zig");
const clock_shell = @import("clock.zig");
const write = @import("write.zig");
const auth = @import("auth.zig");
const lexicon = @import("../core/lexicon.zig");
const moderation = @import("../core/moderation.zig");

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

        // The author table grew (a fetch or a live reply taught us someone
        // new): widen the live subscription to match.
        if (live_stream) |live| {
            if (store.authors.len > subscribed_authors) {
                const fresh = try composeSubscription(arena, session.did, store, 255);
                try stream_shell.updateDids(live, fresh);
                subscribed_authors = store.authors.len;
            }
        }

        // Auto-refresh tick: in timeline mode, once the interval has elapsed
        // and we have an established feed, re-run the same getTimeline the
        // `r` key runs. New posts slot in at the top and the viewport jumps
        // so they are seen — identical to a manual refresh, just on a timer.
        // Failure is contained to the status line (E2); only OOM is fatal.
        // Never fires mid-compose, so it cannot disturb a draft.
        if (refresh_interval > 0 and mode == .timeline and store.feed.len > 0 and
            now - last_auto_refresh >= refresh_interval and
            clock_shell.monotonicNanos() -| last_input_nanos >= input_idle_gate_nanos)
        {
            last_auto_refresh = now;
            const outcome = feed_shell.refreshTimeline(gpa, arena, io, environ, session, store, 30) catch |err| switch (err) {
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
        const pix: ?Grid = if (engine) |*e| .{ .engine = e, .field = &gfield, .particles = &gparticles, .active = &gactive, .draw = &gdraw, .hr = &ghr, .hearts = &ghearts, .view = &gview, .spawn_buf = &gspawn, .last_nanos = &glast_nanos, .zoom = &gzoom } else null;
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
                        // The cursor: a filled block at the insertion cell.
                        try gdraw.append(gpa, .{ .rect = .{ .x = @intCast(@min(cursor.x * cell.w, 32767)), .y = @intCast(@min(cursor.y * cell.h, 32767)), .w = cell.w, .h = cell.h, .color = 0x886CA8FF, .radius = 0 } });
                        window_shell.presentDrawList(win, gpa, g.engine, gdraw.slice(), 0xFF0E1116) catch {};
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
                        window_shell.presentDrawList(win, gpa, g.engine, gdraw.slice(), 0xFF0E1116) catch {};
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
                const animating = engine != null and (gactive.len > 0 or gparticles.len > 0);
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
                    for (pointer_events.items) |pev| {
                        const cx: u16 = pev.x / pcell.w;
                        const cy: u16 = pev.y / pcell.h;
                        switch (pev.kind) {
                            .wheel => {
                                const delta: i32 = if (pev.button == 5) 3 else -3;
                                g.view.scroll_rows += delta;
                                // Keep any playing effect anchored to its
                                // post: scrolling moves content by `delta`
                                // rows, so shift active effect origins by
                                // the same amount and they ride the scroll
                                // instead of detaching. (The plan for
                                // animation-during-scroll: the heart burst
                                // is pinned to the post's cell, re-derived
                                // as the view moves — here via the scroll
                                // delta, the one scroll source.)
                                effect_core.shiftY(g.active, -delta);
                            },
                            .move => g.view.hover = if (field_ui.hitTest(cx, cy, g.hr.slice())) |hit| hit.target else field_ui.no_target,
                            .button_down => if (pev.button == 1) {
                                if (field_ui.hitTest(cx, cy, g.hr.slice())) |hit| {
                                    if (hit.target != field_ui.no_target and hit.target < items.len) state.selected = hit.target;
                                    // Fire the effect for this action AT
                                    // its origin (the like glyph), so the
                                    // heart blooms on the tapped counter.
                                    // The like recipe depends on whether
                                    // this is a like or an UNLIKE — read
                                    // the item's current state, the same
                                    // flag the toggle dispatch will flip.
                                    if (hit.target < items.len) fireEffect(gpa, g, hit, items[hit.target]);
                                    // The action byte runs the SAME key
                                    // dispatch (keyFor↔actionFor), which
                                    // already toggles like/unlike on the
                                    // viewer's current state — so a click
                                    // on a liked post unlikes it, exactly
                                    // as the 'l' key does.
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
                // No input this lap: normally idle back to the top. But
                // if the field is mid-animation, fall through to repaint
                // so the simulation advances a frame (the dynamic pump
                // above kept this lap short precisely for this). The
                // expose/resize repaint already ran above; this is the
                // steady animation tick.
                if (n == 0) {
                    if (mode == .timeline and engine != null and (gactive.len > 0 or gparticles.len > 0)) {
                        try paintFrame(gpa, out, arena, &prev, &next, backend, pix, items, &state, revealed.items, now, session.handle, status);
                    }
                    continue;
                }
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

                    const outcome = feed_shell.refreshTimeline(gpa, arena, io, environ, session, store, 30) catch |err| switch (err) {
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

                    const outcome = feed_shell.loadTimelinePage(gpa, arena, io, environ, session, store, 30) catch |err| switch (err) {
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
                    const r = try engageSelected(.like, gpa, arena, io, environ, session, store, items[state.selected], &state, revealed.items, now, out, &prev, &next, backend, pix, &status_buf);
                    if (r.status.len > 0) status = r.status;
                    if (r.skip_rest) continue;
                },
                .repost => if (items.len > 0) {
                    const r = try engageSelected(.repost, gpa, arena, io, environ, session, store, items[state.selected], &state, revealed.items, now, out, &prev, &next, backend, pix, &status_buf);
                    if (r.status.len > 0) status = r.status;
                    if (r.skip_rest) continue;
                },
                .profile => if (items.len > 0) {
                    const item = items[state.selected];
                    status = "loading profile...";
                    try paintFrame(gpa, out, arena, &prev, &next, backend, pix, items, &state, revealed.items, now, session.handle, status);
                    const outcome = auth.query(gpa, arena, io, environ, session, lexicon.method.get_profile, &.{
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

/// Pump a short, capped burst of glyph-field animation frames before a
/// blocking network call. THE FIX for the multi-second effect delay: a
/// like/unlike fires its effect instantly, but the engagement's network
/// write (write.likePost et al.) is SYNCHRONOUS on this thread — so
/// without this, the loop cannot render a single animation frame until
/// the round-trip returns, and the burst appears frozen mid-flight.
/// Here we drive the WHOLE animation to completion (the heart fills,
/// pops, sparks, and settles) BEFORE the network call, so the burst is
/// smooth and never pauses partway. The like count is already bumped
/// optimistically, so starting the network call ~0.8 s later is
/// invisible to the user. The network remains the conceded bottleneck;
/// the fully robust cure is threading the write off this thread (the
/// firehose mailbox pattern), but running the animation to completion
/// here removes the visible pause entirely. The resting hearts of OTHER
/// posts are redrawn each frame too, so the screen stays whole.
fn animateBeforeBlock(gpa: Allocator, win: anytype, g: Grid, zoom: f32) void {
    const cell = cellSize(win.fb.width, zoom);
    // Run to completion (cap is a safety bound, not the target): once the
    // effect and its particles have settled, stop.
    const max_frames: usize = 90; // ~1.5 s ceiling; the break ends it sooner
    var i: usize = 0;
    while (i < max_frames) : (i += 1) {
        if (g.active.len == 0 and g.particles.len == 0) break;
        effect_core.advance(gpa, g.active, g.field, 1.0 / 60.0, g.spawn_buf) catch break;
        field_core.step(gpa, g.field, g.particles, g.spawn_buf.items, 1.0 / 60.0, sim_rng.random()) catch break;
        const cols = g.field.cols;
        const rows = g.field.rows;
        const light: field_core.Light = .{ .x = @floatFromInt(cols / 2), .y = @floatFromInt(rows / 3), .radius = @floatFromInt(cols), .ambient = 0.64 };
        field_core.compose(gpa, g.field, g.particles.slice(), light, cell.w, cell.h, g.draw) catch break;
        // Redraw the OTHER posts' resting hearts (the animating one is
        // suppressed by cell match — composeEffects draws it). Without
        // this they would blink out for the animation's duration.
        const hxs = g.hearts.slice().items(.x);
        const hys = g.hearts.slice().items(.y);
        const hlk = g.hearts.slice().items(.liked);
        const axs = g.active.slice().items(.x);
        const ays = g.active.slice().items(.y);
        for (hxs, hys, hlk) |hxc, hyc, lk| {
            var animating = false;
            for (axs, ays) |axc, ayc| {
                if (axc == hxc and ayc == hyc) {
                    animating = true;
                    break;
                }
            }
            if (!animating) effect_core.composeStaticHeart(gpa, lk, hxc, hyc, cell.w, cell.h, g.draw) catch {};
        }
        effect_core.composeEffects(gpa, g.active.slice(), cell.w, cell.h, g.draw) catch break;
        window_shell.presentDrawList(win, gpa, g.engine, g.draw.slice(), 0xFF0E1116) catch break;
        // ~16 ms/frame so the animation plays at roughly 60fps wall-clock,
        // perceptible and smooth rather than a blur.
        clock_shell.sleepMillis(16);
    }
}

fn engageSelected(
    kind: Engagement,
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    store: *feed_core.Store,
    item: feed_core.TimelineItem,
    state: *timeline_ui.UiState,
    revealed_cids: []const []const u8,
    now: i64,
    out: *std.Io.Writer,
    prev: *tui.Surface,
    next: *tui.Surface,
    backend: Backend,
    pix: ?Grid,
    status_buf: []u8,
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
            // Show the effect's burst before the blocking network call
            // (else it appears frozen for the round-trip). Window only.
            if (pix) |g| switch (backend) {
                .window => |win| animateBeforeBlock(gpa, win, g, g.zoom.*),
                .terminal => {},
            };

            const undo_call = switch (kind) {
                .like => write.unlikePost(gpa, arena, io, environ, session, record_uri),
                .repost => write.unrepostPost(gpa, arena, io, environ, session, record_uri),
            };
            const undo = undo_call catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => {
                    try revertDisengage(kind, gpa, store, item.cid, record_uri);
                    return .{ .status = "network error", .skip_rest = true };
                },
            };
            switch (undo) {
                .ok => return .{ .status = if (kind == .like) "unliked" else "unboosted" },
                .failed => |failure| {
                    try revertDisengage(kind, gpa, store, item.cid, record_uri);
                    return .{ .status = std.fmt.bufPrint(status_buf, "refused: {d} {s}", .{
                        failure.status, failure.code,
                    }) catch "refused" };
                },
            }
        },
        .unknown => return .{ .status = "" },
        .applied => {},
    }

    // Optimistic first: the bumped count paints now; the server call
    // follows; a refusal reverts.
    const fresh = try feed_core.buildTimeline(arena, store);
    try paintFrame(gpa, out, arena, prev, next, backend, pix, fresh, state, revealed_cids, now, session.handle, if (kind == .like) "liking..." else "boosting...");
    // Show the effect's burst before the blocking network call (else it
    // appears frozen for the round-trip). Window only.
    if (pix) |g| switch (backend) {
        .window => |win| animateBeforeBlock(gpa, win, g, g.zoom.*),
        .terminal => {},
    };

    const call = switch (kind) {
        .like => write.likePost(gpa, arena, io, environ, session, item.uri, item.cid, now),
        .repost => write.repostPost(gpa, arena, io, environ, session, item.uri, item.cid, now),
    };
    const outcome = call catch |err| switch (err) {
        error.OutOfMemory => return err,
        else => {
            revertEngagement(kind, store, item.cid);
            return .{ .status = "network error", .skip_rest = true };
        },
    };
    switch (outcome) {
        .ok => return .{ .status = if (kind == .like) "liked" else "boosted" },
        .failed => |failure| {
            revertEngagement(kind, store, item.cid);
            return .{ .status = std.fmt.bufPrint(status_buf, "refused: {d} {s}", .{
                failure.status, failure.code,
            }) catch "refused" };
        },
    }
}

fn revertDisengage(kind: Engagement, gpa: Allocator, store: *feed_core.Store, cid: []const u8, uri: []const u8) error{OutOfMemory}!void {
    switch (kind) {
        .like => try feed_core.revertUnlike(gpa, store, cid, uri),
        .repost => try feed_core.revertUnrepost(gpa, store, cid, uri),
    }
}

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
};

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
            _ = try field_ui.build(g.field, g.hr, g.hearts, items, state.selected, g.view, revealed, now, account_handle, status, gpa);
            try effect_core.advance(gpa, g.active, g.field, dt, g.spawn_buf);
            try field_core.step(gpa, g.field, g.particles, g.spawn_buf.items, dt, sim_rng.random());
            const light: field_core.Light = .{
                .x = @floatFromInt(cols / 2),
                .y = @floatFromInt(rows / 3),
                .radius = @floatFromInt(cols),
                .ambient = 0.64,
            };
            try field_core.compose(gpa, g.field, g.particles.slice(), light, cell.w, cell.h, g.draw);
            // The resting like-button hearts: draw each post's heart sprite
            // at its reserved cell — EXCEPT any whose cell has a live effect
            // (that heart is being animated by composeEffects; drawing both
            // would double it). The button and its burst are one heart.
            {
                const hxs = g.hearts.slice().items(.x);
                const hys = g.hearts.slice().items(.y);
                const hliked = g.hearts.slice().items(.liked);
                const axs = g.active.slice().items(.x);
                const ays = g.active.slice().items(.y);
                for (hxs, hys, hliked) |hxc, hyc, lk| {
                    var animating = false;
                    for (axs, ays) |axc, ayc| {
                        if (axc == hxc and ayc == hyc) {
                            animating = true;
                            break;
                        }
                    }
                    if (!animating) try effect_core.composeStaticHeart(gpa, lk, hxc, hyc, cell.w, cell.h, g.draw);
                }
            }
            // Fine-resolution effect overlays (the animating heart) draw
            // on top at their own sub-cell pitch.
            try effect_core.composeEffects(gpa, g.active.slice(), cell.w, cell.h, g.draw);
            window_shell.presentDrawList(win, gpa, g.engine, g.draw.slice(), 0xFF0E1116) catch {}; // E2: a lost blit is the next frame's problem
            return;
        },
        .terminal => {},
    };
    timeline_ui.buildFrame(next, items, state, revealed, now, account_handle, status);
    try present(gpa, out, arena, prev, next, backend);
}

/// Choose and fire the glyph-field effect for a click, AT the hit's
/// recorded origin (the like glyph's centre), so the animation blooms
/// exactly where the eye is. This is the one place the app maps a
/// user action to a recipe — change a row here, or pass a different
/// `scale`, and the feel changes app-wide (the owner's context dial).
/// A like on an already-liked post is an UNLIKE: the cooler recipe.
fn fireEffect(gpa: Allocator, g: Grid, hit: field_ui.Hit, item: feed_core.TimelineItem) void {
    const recipe: *const effect_core.Recipe = switch (hit.action) {
        .like => if (item.item_flags.viewer_liked) &effect_core.unlike_heart else &effect_core.like_heart,
        .repost => &effect_core.boost,
        else => return, // other actions get no field effect (yet)
    };
    // scale = 1.0 is the recipe as authored; a louder milestone or a
    // quieter dense-feed pass is a different number here. errors are
    // swallowed: a missed effect must never break the click (E4).
    effect_core.trigger(gpa, g.active, recipe, hit.fx, hit.fy, 1.0) catch {};
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
