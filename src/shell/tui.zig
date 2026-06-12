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
                    status = std.fmt.bufPrint(&status_buf, "+{d} new", .{stats.items_added}) catch "new posts";
                },
                .failed => {}, // a refused poll is silent; the next tick retries
            };
            if (outcome != null and outcome.? == .ok) {
                _ = cache_shell.saveStore(gpa, environ, store); // E4: a failed save is simply no cache
            }
        }

        const items = try feed_core.buildTimeline(arena, store);
        switch (mode) {
            .timeline => timeline_ui.buildFrame(&next, items, &state, revealed.items, now, session.handle, status),
            .compose => timeline_ui.buildComposeFrame(&next, compose_buf.items, reply_handle, status),
            .profile => timeline_ui.buildProfileFrame(&next, profile_info orelse .{}, status),
        }
        try present(gpa, out, arena, &prev, &next, backend);

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
                const pumped = window_shell.pump(win, 500, gpa, &pumped_bytes) catch {
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
                    try present(gpa, out, arena, &prev, &next, backend);
                }
                n = @min(pumped_bytes.items.len, in_buf.len);
                @memcpy(in_buf[0..n], pumped_bytes.items[0..n]);
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

            switch (timeline_ui.actionFor(decoded.event)) {
                .quit => break :main_loop,
                .refresh => {
                    status = "refreshing...";
                    timeline_ui.buildFrame(&next, items, &state, revealed.items, now, session.handle, status);
                    try present(gpa, out, arena, &prev, &next, backend);

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
                    timeline_ui.buildFrame(&next, items, &state, revealed.items, now, session.handle, status);
                    try present(gpa, out, arena, &prev, &next, backend);

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
                    const r = try engageSelected(.like, gpa, arena, io, environ, session, store, items[state.selected], &state, revealed.items, now, out, &prev, &next, backend, &status_buf);
                    if (r.status.len > 0) status = r.status;
                    if (r.skip_rest) continue;
                },
                .repost => if (items.len > 0) {
                    const r = try engageSelected(.repost, gpa, arena, io, environ, session, store, items[state.selected], &state, revealed.items, now, out, &prev, &next, backend, &status_buf);
                    if (r.status.len > 0) status = r.status;
                    if (r.skip_rest) continue;
                },
                .profile => if (items.len > 0) {
                    const item = items[state.selected];
                    status = "loading profile...";
                    timeline_ui.buildFrame(&next, items, &state, revealed.items, now, session.handle, status);
                    try present(gpa, out, arena, &prev, &next, backend);
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
                        timeline_ui.buildFrame(&next, items, &state, revealed.items, now, session.handle, status);
                        try present(gpa, out, arena, &prev, &next, backend);
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
                else => |action| timeline_ui.applyAction(&state, action, items.len),
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
            timeline_ui.buildFrame(next, fresh, state, revealed_cids, now, session.handle, if (kind == .like) "unliking..." else "unboosting...");
            try present(gpa, out, arena, prev, next, backend);

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
    timeline_ui.buildFrame(next, fresh, state, revealed_cids, now, session.handle, if (kind == .like) "liking..." else "boosting...");
    try present(gpa, out, arena, prev, next, backend);

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
