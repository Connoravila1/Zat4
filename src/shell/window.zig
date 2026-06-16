//! B1 classification: SHELL. The window — a hand-rolled X11 client over
//! the Unix socket, zero dependencies (F1/F2: X11 is a socket protocol;
//! we speak it the way we speak WebSocket). Every byte's MEANING lives
//! in core/x11.zig and the layout/raster/text cores; this file owns the fd, the
//! Xauthority cookie, the open/reply choreography, the event pump, and
//! the PutImage blits — I/O and nothing else (B3, D1).
//!
//! The backend trick, stated once: the window translates X key events
//! into the SAME bytes a terminal would deliver ('q', '\r', ESC [ A …)
//! and rasterizes the SAME cell surface the terminal renders. The input
//! decoder and every screen the app draws never learn the difference.

const std = @import("std");
const Allocator = std.mem.Allocator;
const linux = std.os.linux;
const x11 = @import("../core/x11.zig");
const layout = @import("../core/layout.zig");
const raster = @import("../core/raster.zig");
const text_core = @import("../core/text.zig");
const text = text_core; // cell metrics alias (cols/rows derivation)
const tui = @import("../core/tui.zig");

pub const OpenError = error{
    UnsupportedDisplay,
    ConnectFailed,
    SetupRefused,
    ProtocolError,
    OutOfMemory,
};

/// A7.2: cold struct, size guard waived — one per session.
pub const Window = struct {
    gpa: Allocator,
    fd: i32,
    wid: u32,
    gc: u32,
    root_depth: u8,
    image_byte_order: u8,
    max_request_units: u32,
    wm_protocols: u32,
    wm_delete: u32,
    /// Keyboard geometry + the keysym table fetched at open (gpa-owned).
    min_keycode: u8,
    syms_per_keycode: u8,
    keysyms: []u32,
    /// The pixels (gpa-owned via raster.resize), the per-frame draw list
    /// (held as opaque transport between the layout and raster cores —
    /// never inspected here, B5/D3), and the cell geometry the surface
    /// should be built at.
    fb: raster.Framebuffer,
    draw_list: raster.DrawList,
    cols: u16,
    rows: u16,
    /// Partial-frame carry between pumps: X events are 32 bytes, reads
    /// are not obliged to align with them.
    carry: [32]u8,
    carry_len: usize,
    /// Bytes of a stray reply body still to be discarded.
    skip_bytes: usize,
    /// Scratch row for byte-swapped blits on MSBFirst servers (rare).
    swap_row: []u8,
    /// Damage tracking for the blit. `shadow` holds the pixels last sent to
    /// the server; blit() diffs the framebuffer against it (raster.damageBand)
    /// and PutImages only the rows that changed — the heart animation touches
    /// a few rows, not the whole frame, and a full-frame PutImage every frame
    /// was the render path's real cost (the CPU paint is ~1 ms; the megabyte
    /// socket write is what stalled and stuttered). `shadow_w`/`shadow_h` pin
    /// the geometry the shadow was taken at, so a resize that keeps the same
    /// pixel COUNT but different dimensions still forces a reseed. `dirty_all`
    /// forces the next blit to be full (and reseed the shadow): the first
    /// frame, a resize, or an Expose that may have discarded the server's
    /// copy. gpa-owned; freed in close (C5). B3: the blit is I/O; this is just
    /// shell bookkeeping about what the framebuffer holds — the core (which
    /// computes the band) never touches the socket.
    shadow: []u32,
    shadow_w: u32,
    shadow_h: u32,
    dirty_all: bool,
    /// Report the first X error to the terminal, then stay quiet: a
    /// rejected blit repeats every frame and would otherwise flood stderr
    /// with thousands of identical lines. One clear line is the diagnostic.
    x_error_reported: bool,
};

pub const PumpResult = struct {
    // A7.2: cold struct, size guard waived — one per pump, returned by value.

    /// The server asked us to repaint (Expose) — present the next frame
    /// even if nothing changed.
    exposed: bool = false,
    /// The window geometry changed; `cols`/`rows` are already updated.
    resized: bool = false,
    /// The close button: WM_DELETE_WINDOW arrived.
    closed: bool = false,
    /// Parity with the Win32 backend; this pump propagates allocation
    /// failure instead of dropping, so it is always zero here.
    dropped: u32 = 0,
    /// The X error code from the most recent error packet this pump saw, or
    /// 0 for none. The server reports these for rejected requests (a bad
    /// drawable, GC, depth, or length on a blit); swallowing them is what
    /// turns "the server refused our PutImage" into a silent black window.
    /// Surfacing the code (1=Request 2=Value 3=Window 4=Pixmap 5=Atom
    /// 8=Match 9=Drawable 11=Alloc 13=GContext 16=Length) makes the actual
    /// fault legible instead of a guess. (E3 in spirit: the failure is no
    /// longer silent.)
    x_error: u8 = 0,
};

// ---------------------------------------------------------------------------
// fd plumbing — the same kernel-stable surface the rest of the shell uses
// ---------------------------------------------------------------------------

fn writeAll(fd: i32, bytes: []const u8) error{ProtocolError}!void {
    var sent: usize = 0;
    while (sent < bytes.len) {
        const rc = linux.write(fd, bytes.ptr + sent, bytes.len - sent);
        const n: isize = @bitCast(rc);
        if (n <= 0) return error.ProtocolError;
        sent += @intCast(n);
    }
}

fn readExact(fd: i32, out: []u8) error{ProtocolError}!void {
    var got: usize = 0;
    while (got < out.len) {
        const rc = linux.read(fd, out.ptr + got, out.len - got);
        const n: isize = @bitCast(rc);
        if (n <= 0) return error.ProtocolError;
        got += @intCast(n);
    }
}

fn unixConnect(path: []const u8) ?i32 {
    if (path.len == 0 or path.len >= 108) return null;
    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM, 0);
    const fd_signed: isize = @bitCast(rc);
    if (fd_signed < 0) return null;
    const fd: i32 = @intCast(fd_signed);
    var addr: linux.sockaddr.un = .{ .path = [_]u8{0} ** 108 };
    @memcpy(addr.path[0..path.len], path);
    const conn_rc = linux.connect(fd, &addr, @sizeOf(linux.sockaddr.un));
    if (@as(isize, @bitCast(conn_rc)) != 0) {
        _ = linux.close(fd);
        return null;
    }
    return fd;
}

// ---------------------------------------------------------------------------
// DISPLAY and Xauthority
// ---------------------------------------------------------------------------

/// ":0", ":0.0", "unix:1" ⇒ "/tmp/.X11-unix/X<n>". TCP displays are out
/// of scope on purpose — local sockets are the case that exists.
fn displaySocketPath(buf: []u8, display: []const u8) ?[]const u8 {
    var rest = display;
    if (std.mem.startsWith(u8, rest, "unix")) rest = rest["unix".len..];
    if (rest.len < 2 or rest[0] != ':') return null;
    var digits = rest[1..];
    if (std.mem.indexOfScalar(u8, digits, '.')) |dot| digits = digits[0..dot];
    if (digits.len == 0) return null;
    for (digits) |c| if (!std.ascii.isDigit(c)) return null;
    return std.fmt.bufPrint(buf, "/tmp/.X11-unix/X{s}", .{digits}) catch null;
}

const Cookie = struct {
    // A7.2: cold struct, size guard waived — one per open; a parse result, never stored.

    name_buf: [64]u8 = undefined,
    name_len: usize = 0,
    data_buf: [64]u8 = undefined,
    data_len: usize = 0,

    fn name(c: *const Cookie) []const u8 {
        return c.name_buf[0..c.name_len];
    }
    fn data(c: *const Cookie) []const u8 {
        return c.data_buf[0..c.data_len];
    }
};

/// Walk ~/.Xauthority (all lengths big-endian u16) for an
/// MIT-MAGIC-COOKIE-1 entry matching the display number. Absence is not
/// an error — cookie-less local servers exist (E4).
fn loadCookie(gpa: Allocator, environ: ?*const std.process.Environ.Map, display_num: []const u8) Cookie {
    var cookie: Cookie = .{};
    const env = environ orelse return cookie;
    var path_buf: [512]u8 = undefined;
    const path = blk: {
        if (env.get("XAUTHORITY")) |explicit| break :blk explicit;
        const home = env.get("HOME") orelse return cookie;
        break :blk std.fmt.bufPrint(&path_buf, "{s}/.Xauthority", .{home}) catch return cookie;
    };
    const bytes = readSmallFile(gpa, path) orelse return cookie;
    defer gpa.free(bytes);

    var at: usize = 0;
    while (at + 2 <= bytes.len) {
        at += 2; // family — any local family is acceptable for our match
        const address = takeField(bytes, &at) orelse return cookie;
        _ = address;
        const number = takeField(bytes, &at) orelse return cookie;
        const auth_name = takeField(bytes, &at) orelse return cookie;
        const auth_data = takeField(bytes, &at) orelse return cookie;
        const number_matches = number.len == 0 or std.mem.eql(u8, number, display_num);
        if (number_matches and std.mem.eql(u8, auth_name, "MIT-MAGIC-COOKIE-1") and
            auth_name.len <= cookie.name_buf.len and auth_data.len <= cookie.data_buf.len)
        {
            @memcpy(cookie.name_buf[0..auth_name.len], auth_name);
            cookie.name_len = auth_name.len;
            @memcpy(cookie.data_buf[0..auth_data.len], auth_data);
            cookie.data_len = auth_data.len;
            return cookie;
        }
    }
    return cookie;
}

fn takeField(bytes: []const u8, at: *usize) ?[]const u8 {
    if (at.* + 2 > bytes.len) return null;
    const len = std.mem.readInt(u16, bytes[at.*..][0..2], .big);
    at.* += 2;
    if (at.* + len > bytes.len) return null;
    const field = bytes[at.* .. at.* + len];
    at.* += len;
    return field;
}

fn readSmallFile(gpa: Allocator, path: []const u8) ?[]u8 {
    var z: [512]u8 = undefined;
    if (path.len == 0 or path.len >= z.len) return null;
    @memcpy(z[0..path.len], path);
    z[path.len] = 0;
    const rc = linux.open(z[0..path.len :0].ptr, .{ .ACCMODE = .RDONLY }, 0);
    const fd_signed: isize = @bitCast(rc);
    if (fd_signed < 0) return null;
    const fd: i32 = @intCast(fd_signed);
    defer _ = linux.close(fd);
    var out: std.ArrayList(u8) = .empty;
    var chunk: [4096]u8 = undefined;
    while (out.items.len < 64 * 1024) {
        const n_rc = linux.read(fd, &chunk, chunk.len);
        const n: isize = @bitCast(n_rc);
        if (n < 0) {
            out.deinit(gpa);
            return null;
        }
        if (n == 0) break;
        out.appendSlice(gpa, chunk[0..@intCast(n)]) catch {
            out.deinit(gpa);
            return null;
        };
    }
    return out.toOwnedSlice(gpa) catch {
        out.deinit(gpa);
        return null;
    };
}

// ---------------------------------------------------------------------------
// Open / close
// ---------------------------------------------------------------------------

/// Resolve $DISPLAY + cookie and open. `cols`/`rows` set the initial cell
/// geometry; the window manager may resize us immediately after.
pub fn open(
    gpa: Allocator,
    environ: ?*const std.process.Environ.Map,
    title: []const u8,
    cols: u16,
    rows: u16,
) OpenError!*Window {
    const env = environ orelse return error.UnsupportedDisplay;
    const display = env.get("DISPLAY") orelse return error.UnsupportedDisplay;
    var path_buf: [128]u8 = undefined;
    const path = displaySocketPath(&path_buf, display) orelse return error.UnsupportedDisplay;
    var digits = display[std.mem.indexOfScalar(u8, display, ':').? + 1 ..];
    if (std.mem.indexOfScalar(u8, digits, '.')) |dot| digits = digits[0..dot];
    const cookie = loadCookie(gpa, environ, digits);
    return openAt(gpa, path, cookie.name(), cookie.data(), title, cols, rows);
}

pub fn openAt(
    gpa: Allocator,
    socket_path: []const u8,
    auth_name: []const u8,
    auth_data: []const u8,
    title: []const u8,
    cols: u16,
    rows: u16,
) OpenError!*Window {
    const fd = unixConnect(socket_path) orelse return error.ConnectFailed;
    errdefer _ = linux.close(fd);

    // --- connection setup ---
    var req_buf: [256]u8 = undefined;
    try writeAll(fd, x11.setupRequest(&req_buf, auth_name, auth_data));
    var head: [8]u8 = undefined;
    try readExact(fd, &head);
    const header = x11.setupHeader(&head);
    if (header.status != 1) return error.SetupRefused;
    const body = gpa.alloc(u8, header.body_len) catch return error.OutOfMemory;
    defer gpa.free(body);
    try readExact(fd, body);
    const setup = x11.parseSetup(body) catch return error.ProtocolError;

    const wid = setup.resource_id_base | 1;
    const gc = setup.resource_id_base | 2;

    // --- create, decorate, wire the close button, map ---
    const mask = x11.event_mask_key_press | x11.event_mask_key_release |
        x11.event_mask_button_press | x11.event_mask_button_release |
        x11.event_mask_pointer_motion |
        x11.event_mask_exposure | x11.event_mask_structure;
    const width = @as(u16, @intCast(@min(@as(u32, cols) * text.cell_w, 16380)));
    const height = @as(u16, @intCast(@min(@as(u32, rows) * text.cell_h, 16380)));
    try writeAll(fd, x11.createWindow(&req_buf, wid, setup.root_window, width, height, layout.palette_bg, mask));
    try writeAll(fd, x11.changePropertyString(&req_buf, wid, x11.atom_wm_name, title));

    try writeAll(fd, x11.internAtom(&req_buf, "WM_PROTOCOLS"));
    const wm_protocols = try awaitAtom(fd);
    try writeAll(fd, x11.internAtom(&req_buf, "WM_DELETE_WINDOW"));
    const wm_delete = try awaitAtom(fd);
    try writeAll(fd, x11.changePropertyAtom(&req_buf, wid, wm_protocols, wm_delete));
    try writeAll(fd, x11.createGC(&req_buf, gc, wid));

    // --- the keyboard table, fetched once ---
    const key_count: u8 = setup.max_keycode - setup.min_keycode + 1;
    try writeAll(fd, x11.getKeyboardMapping(&req_buf, setup.min_keycode, key_count));
    var reply: [32]u8 = undefined;
    try awaitReply(fd, &reply);
    const per = x11.keyboardMappingPer(&reply);
    const extra_len = x11.replyExtraBytes(&reply);
    const extra = gpa.alloc(u8, extra_len) catch return error.OutOfMemory;
    defer gpa.free(extra);
    try readExact(fd, extra);
    const keysyms = gpa.alloc(u32, extra_len / 4) catch return error.OutOfMemory;
    errdefer gpa.free(keysyms);
    _ = x11.keyboardMappingSyms(extra, keysyms);

    try writeAll(fd, x11.mapWindow(&req_buf, wid));

    const window = gpa.create(Window) catch return error.OutOfMemory;
    errdefer gpa.destroy(window);
    window.* = .{
        .gpa = gpa,
        .fd = fd,
        .wid = wid,
        .gc = gc,
        .root_depth = setup.root_depth,
        .image_byte_order = setup.image_byte_order,
        .max_request_units = setup.max_request_units,
        .wm_protocols = wm_protocols,
        .wm_delete = wm_delete,
        .min_keycode = setup.min_keycode,
        .syms_per_keycode = per,
        .keysyms = keysyms,
        .fb = .{},
        .draw_list = .empty,
        .cols = cols,
        .rows = rows,
        .carry = undefined,
        .carry_len = 0,
        .skip_bytes = 0,
        .swap_row = &.{},
        .x_error_reported = false,
        .shadow = &.{},
        .shadow_w = 0,
        .shadow_h = 0,
        .dirty_all = true, // first blit paints the whole window
    };
    raster.resize(gpa, &window.fb, width, height, layout.palette_bg) catch return error.OutOfMemory;
    return window;
}

/// During open, only replies and errors can arrive (the window is not
/// yet mapped); a reply is 32 bytes, an error is fatal here.
fn awaitReply(fd: i32, out: *[32]u8) error{ProtocolError}!void {
    try readExact(fd, out);
    if (out[0] != 1) return error.ProtocolError;
}

fn awaitAtom(fd: i32) error{ProtocolError}!u32 {
    var reply: [32]u8 = undefined;
    try awaitReply(fd, &reply);
    return x11.internAtomReply(&reply);
}

pub fn close(window: *Window) void {
    const gpa = window.gpa;
    _ = linux.close(window.fd);
    gpa.free(window.keysyms);
    if (window.swap_row.len > 0) gpa.free(window.swap_row);
    if (window.shadow.len > 0) gpa.free(window.shadow);
    window.draw_list.deinit(gpa);
    raster.deinit(gpa, &window.fb);
    gpa.destroy(window);
}

// ---------------------------------------------------------------------------
// The pump — X events in, terminal bytes out
// ---------------------------------------------------------------------------

/// Wait up to `timeout_ms` for activity, translate every key press into
/// terminal bytes appended to `out`, and fold geometry/lifecycle events
/// into the result. The poll is a bounded wait, not a gate: whatever is
/// readable gets read.
pub fn pump(
    window: *Window,
    timeout_ms: i32,
    gpa: Allocator,
    out: *std.ArrayList(u8),
    // A3 exception: a flat list of the 8-byte InputEvent, not SoA — the
    // consumer (layout's hit-testing) reads every field of each event
    // whole and in order, the record is one machine word, and a frame
    // carries tens of events; parallel field arrays would add growth
    // sites for no locality win. (GUI roadmap §3.1: "a flat slice".)
    events: *std.ArrayList(layout.InputEvent),
) error{ OutOfMemory, ProtocolError }!PumpResult {
    var result: PumpResult = .{};
    var fds = [_]linux.pollfd{.{ .fd = window.fd, .events = linux.POLL.IN, .revents = 0 }};
    const poll_rc = linux.poll(&fds, 1, timeout_ms);
    if (@as(isize, @bitCast(poll_rc)) <= 0) return result;

    var chunk: [2048]u8 = undefined;
    const read_rc = linux.read(window.fd, &chunk, chunk.len);
    const n: isize = @bitCast(read_rc);
    if (n == 0) {
        result.closed = true; // server hung up
        return result;
    }
    if (n < 0) return error.ProtocolError;

    var bytes: []const u8 = chunk[0..@intCast(n)];
    while (bytes.len > 0) {
        if (window.skip_bytes > 0) {
            const eat = @min(window.skip_bytes, bytes.len);
            window.skip_bytes -= eat;
            bytes = bytes[eat..];
            continue;
        }
        const want = 32 - window.carry_len;
        const take = @min(want, bytes.len);
        @memcpy(window.carry[window.carry_len..][0..take], bytes[0..take]);
        window.carry_len += take;
        bytes = bytes[take..];
        if (window.carry_len < 32) break;
        window.carry_len = 0;

        if (window.carry[0] == 1) {
            // A stray reply: discard its body and move on.
            window.skip_bytes = x11.replyExtraBytes(&window.carry);
            continue;
        }
        const event = x11.parseEvent(&window.carry, window.wm_protocols, window.wm_delete);
        switch (event.kind) {
            .key_press => {
                const shifted = event.state & x11.shift_mask != 0;
                const ctrl = event.state & x11.control_mask != 0;
                const sym = x11.keysymFor(window.keysyms, window.syms_per_keycode, window.min_keycode, event.detail, shifted);
                var key_buf: [8]u8 = undefined;
                const len = x11.keyBytes(sym, ctrl, &key_buf);
                if (len > 0) try out.appendSlice(gpa, key_buf[0..len]);
            },
            // Pointer events become the OS-agnostic InputEvent and ride
            // their own channel; key bytes keep the terminal channel.
            // Wheel arrives as X buttons 4/5 (press only — the paired
            // release carries nothing and is dropped, as are horizontal
            // wheel buttons 6/7 until a screen wants them).
            .button_press, .button_release => {
                const mods: u8 = @truncate(event.state);
                switch (event.detail) {
                    1, 2, 3 => try events.append(gpa, .{
                        .x = event.w,
                        .y = event.h,
                        .kind = if (event.kind == .button_press) .button_down else .button_up,
                        .button = event.detail,
                        .mods = mods,
                        ._pad = 0,
                    }),
                    4, 5 => if (event.kind == .button_press) try events.append(gpa, .{
                        .x = event.w,
                        .y = event.h,
                        .kind = .wheel,
                        .button = event.detail,
                        .mods = mods,
                        ._pad = 0,
                    }),
                    else => {},
                }
            },
            .motion => try events.append(gpa, .{
                .x = event.w,
                .y = event.h,
                .kind = .move,
                .button = 0,
                .mods = @truncate(event.state),
                ._pad = 0,
            }),
            .expose => {
                result.exposed = true;
                // The server can discard a window's contents before an
                // Expose; the shadow no longer reflects what is on screen, so
                // the next blit must repaint the whole window, not just the
                // band that changed in our framebuffer.
                window.dirty_all = true;
            },
            .configure => {
                if (event.w != window.fb.width or event.h != window.fb.height) {
                    raster.resize(window.gpa, &window.fb, event.w, event.h, layout.palette_bg) catch return error.OutOfMemory;
                    window.cols = @intCast(@max(20, event.w / text.cell_w));
                    window.rows = @intCast(@max(5, event.h / text.cell_h));
                    result.resized = true;
                    // New geometry: the framebuffer was reallocated/cleared,
                    // so the next blit is full and reseeds the shadow.
                    window.dirty_all = true;
                }
            },
            .client_delete => result.closed = true,
            .err => {
                result.x_error = event.detail;
                // Report the FIRST error only (a refused blit repeats every
                // frame — left unbounded it floods the terminal). `detail`
                // is the error code; `state` carries the major opcode of the
                // refused request, which names WHAT was rejected. The buffer
                // is generous and the message short so the print itself can
                // never overflow (the earlier flood printed the fallback
                // string because the message was longer than its buffer).
                if (!window.x_error_reported) {
                    window.x_error_reported = true;
                    var msg: [128]u8 = undefined;
                    const line = std.fmt.bufPrint(
                        &msg,
                        "zat: X error code {d}, opcode {d}, badid 0x{x}\n",
                        .{ event.detail, event.state, event.data },
                    ) catch "zat: X error (fmt)\n";
                    _ = linux.write(2, line.ptr, line.len);
                }
            },
            .key_release, .none => {},
        }
    }
    return result;
}

// ---------------------------------------------------------------------------
// Present — rasterize and blit, chunked under the request ceiling
// ---------------------------------------------------------------------------

pub fn present(window: *Window, surface: *const tui.Surface) error{ OutOfMemory, ProtocolError }!void {
    // The Phase-5 seam (GUI roadmap §2): pure layout builds the draw
    // list, pure raster paints it, and only the blit below is shell.
    try layout.fromSurface(window.gpa, &window.draw_list, surface);
    try raster.paint(window.gpa, null, window.draw_list.slice(), &window.fb, layout.palette_bg);
    try blit(window);
}

/// The modern pixel path (timeline): the caller laid out and owns the
/// list; this paints it with the proportional engine and blits — the
/// same boundary discipline as present(), one screen richer.
pub fn presentDrawList(
    window: *Window,
    gpa: Allocator,
    engine: *text_core.Engine,
    list: raster.DrawList.Slice,
    clear: u32,
) error{ OutOfMemory, ProtocolError }!void {
    try raster.paint(gpa, engine, list, &window.fb, clear);
    try blit(window);
}

/// PutImage only the rows that changed since the last blit. raster.paint
/// rewrites the whole framebuffer each frame, but the resulting PIXELS
/// barely move — only the animating region (the heart, a few rows) actually
/// changes. Diffing against the shadow (raster.damageBand) and sending just
/// that band turns a ~megabyte-per-frame socket write into a few KB, and
/// skips the write entirely when nothing changed. That is what made the
/// animation smooth and kept clicks from queueing behind a blocking write:
/// the CPU cost was never the problem (paint ~1 ms; the field sim ~44 µs) —
/// the full-frame PutImage was. A full blit (reseeding the shadow) is forced
/// on the first frame, on resize, and after an Expose — anything that may
/// have discarded the server's copy. (B3: blit is I/O; the band decision is
/// the pure core's, computed without touching the socket. G1: bench "blit
/// damage".)
pub fn blit(window: *Window) error{ OutOfMemory, ProtocolError }!void {
    const fb = &window.fb;
    if (fb.width == 0 or fb.height == 0) return;
    const count = fb.pixels.len;

    // Reseed-and-full-blit when the shadow cannot be trusted as the server's
    // current contents: first frame, geometry change, or a post-Expose
    // repaint. The shadow is (re)sized to match before it is filled.
    if (window.dirty_all or window.shadow.len != count or
        window.shadow_w != fb.width or window.shadow_h != fb.height)
    {
        if (window.shadow.len != count) {
            if (window.shadow.len > 0) window.gpa.free(window.shadow);
            window.shadow = window.gpa.alloc(u32, count) catch return error.OutOfMemory;
        }
        try blitBand(window, 0, @intCast(fb.height));
        @memcpy(window.shadow, fb.pixels);
        window.shadow_w = fb.width;
        window.shadow_h = fb.height;
        window.dirty_all = false;
        return;
    }

    // Steady state: send only the changed band, then bring the shadow up to
    // date over exactly those rows (the rest is already in sync).
    const band = raster.damageBand(window.shadow, fb.pixels, fb.width, fb.height) orelse return;
    const rows: u16 = @intCast(band.last - band.first + 1);
    try blitBand(window, @intCast(band.first), rows);
    const lo = band.first * fb.width;
    const hi = (band.last + 1) * fb.width;
    @memcpy(window.shadow[lo..hi], fb.pixels[lo..hi]);
}

/// Emit `rows_total` framebuffer rows starting at `dst_y` as one or more
/// PutImage requests, each kept under the server's max-request ceiling.
/// Shared by the full-frame reseed and the per-frame damaged band so the
/// chunking math and the rare MSBFirst byte-swap live in exactly one place.
fn blitBand(window: *Window, dst_y: u16, rows_total: u16) error{ OutOfMemory, ProtocolError }!void {
    const fb = &window.fb;
    if (rows_total == 0) return;
    const width: u16 = @intCast(fb.width);
    const rows_per = x11.putImageRowsPerChunk(width, window.max_request_units);
    var header: [24]u8 = undefined;
    var y: u32 = dst_y;
    const end: u32 = @as(u32, dst_y) + rows_total;
    while (y < end) {
        const rows: u16 = @intCast(@min(@as(u32, rows_per), end - y));
        try writeAll(window.fd, x11.putImageHeader(&header, window.wid, window.gc, width, rows, @intCast(y), window.root_depth));
        const slice = fb.pixels[y * fb.width .. (y + rows) * fb.width];
        if (window.image_byte_order == 0) {
            try writeAll(window.fd, std.mem.sliceAsBytes(slice));
        } else {
            try writeSwapped(window, slice);
        }
        y += rows;
    }
}

/// MSBFirst servers exist in theory; honor them rather than assume.
fn writeSwapped(window: *Window, pixels: []const u32) error{ OutOfMemory, ProtocolError }!void {
    const needed = @as(usize, window.fb.width) * 4;
    if (window.swap_row.len < needed) {
        if (window.swap_row.len > 0) window.gpa.free(window.swap_row);
        window.swap_row = window.gpa.alloc(u8, needed) catch return error.OutOfMemory;
    }
    var at: usize = 0;
    while (at < pixels.len) {
        const count = @min(window.fb.width, pixels.len - at);
        for (pixels[at .. at + count], 0..) |px, i| {
            std.mem.writeInt(u32, window.swap_row[i * 4 ..][0..4], px, .big);
        }
        try writeAll(window.fd, window.swap_row[0 .. count * 4]);
        at += count;
    }
}

// ---------------------------------------------------------------------------
// Tests (C6): a loopback FAKE X SERVER — the same playbook that pinned
// the Jetstream client. It speaks just enough of the protocol to prove
// the full round trip: setup, atoms, keyboard, map, a key press becoming
// the byte 'q', a PutImage carrying our pixels, and the close button.
// ---------------------------------------------------------------------------

const testing = std.testing;

const FakeResult = struct {
    /// Diagnostic checkpoint for flake hunts: 1 setup-sent, 2 map-seen,
    /// 3 events-sent, 4 blit-parsed, 5 close-sent.
    stage: u8 = 0,
    // A7.2: cold struct, size guard waived — test fixture, one per loopback run.

    ok_setup: bool = false,
    saw_create: bool = false,
    saw_title: bool = false,
    put_width: u16 = 0,
    first_pixel: u32 = 0,
    finished: bool = false,
};

fn put16(buf: []u8, at: usize, v: u16) void {
    std.mem.writeInt(u16, buf[at..][0..2], v, .little);
}
fn put32(buf: []u8, at: usize, v: u32) void {
    std.mem.writeInt(u32, buf[at..][0..4], v, .little);
}
fn get16(bytes: []const u8, at: usize) u16 {
    return std.mem.readInt(u16, bytes[at..][0..2], .little);
}

fn unixListen(path: []const u8) ?i32 {
    var z: [128]u8 = undefined;
    @memcpy(z[0..path.len], path);
    z[path.len] = 0;
    _ = linux.unlink(z[0..path.len :0].ptr);
    const rc = linux.socket(linux.AF.UNIX, linux.SOCK.STREAM, 0);
    const fd_signed: isize = @bitCast(rc);
    if (fd_signed < 0) return null;
    const fd: i32 = @intCast(fd_signed);
    var addr: linux.sockaddr.un = .{ .path = [_]u8{0} ** 108 };
    @memcpy(addr.path[0..path.len], path);
    if (@as(isize, @bitCast(linux.bind(fd, @ptrCast(&addr), @sizeOf(linux.sockaddr.un)))) != 0) {
        _ = linux.close(fd);
        return null;
    }
    if (@as(isize, @bitCast(linux.listen(fd, 1))) != 0) {
        _ = linux.close(fd);
        return null;
    }
    return fd;
}

fn serveFakeX(listen_fd: i32, result: *FakeResult) void {
    const accept_rc = linux.accept(listen_fd, null, null);
    const fd_signed: isize = @bitCast(accept_rc);
    if (fd_signed < 0) return;
    const fd: i32 = @intCast(fd_signed);
    defer _ = linux.close(fd);

    // --- setup ---
    var setup_req: [12]u8 = undefined;
    readExact(fd, &setup_req) catch return;
    if (setup_req[0] != 'l') return;

    var setup: [8 + 80]u8 = [_]u8{0} ** 88;
    setup[0] = 1; // success
    put16(&setup, 2, 11);
    put16(&setup, 6, 80 / 4);
    const body = setup[8..];
    put32(body, 4, 0x0200_0000); // id base
    put32(body, 8, 0x001F_FFFF); // id mask
    put16(body, 18, 0xFFFF); // max request units
    body[20] = 1; // screens
    body[21] = 1; // formats
    body[22] = 0; // LSBFirst
    body[26] = 8; // min keycode
    body[27] = 255; // max keycode
    // format entry occupies body[32..40]; screen follows.
    put32(body, 40, 0x0000_05A1); // root window
    put32(body, 40 + 32, 0x21); // root visual
    body[40 + 38] = 24; // root depth
    writeAll(fd, &setup) catch return;
    result.ok_setup = true;
    result.stage = 1;

    // --- request loop until MapWindow ---
    var seq: u16 = 0;
    var atom_next: u32 = 100;
    while (true) {
        var head: [4]u8 = undefined;
        readExact(fd, &head) catch return;
        seq +%= 1;
        const units = get16(&head, 2);
        const rest_len = @as(usize, units) * 4 - 4;
        var rest: [512]u8 = undefined;
        if (rest_len > rest.len) return;
        readExact(fd, rest[0..rest_len]) catch return;
        switch (head[0]) {
            1 => result.saw_create = true,
            18 => {
                // ChangeProperty: the STRING title is the first one sent.
                if (rest[12 - 4] == 8) result.saw_title = true;
            },
            16 => {
                var reply = [_]u8{0} ** 32;
                reply[0] = 1;
                put16(&reply, 2, seq);
                put32(&reply, 8, atom_next);
                atom_next += 1;
                writeAll(fd, &reply) catch return;
            },
            101 => {
                // Keyboard mapping: identity keysyms, one per keycode.
                const count: u32 = 248;
                var reply = [_]u8{0} ** 32;
                reply[0] = 1;
                reply[1] = 1; // keysyms per keycode
                put16(&reply, 2, seq);
                put32(&reply, 4, count);
                writeAll(fd, &reply) catch return;
                var sym_buf: [4]u8 = undefined;
                var keycode: u32 = 8;
                while (keycode < 8 + count) : (keycode += 1) {
                    put32(&sym_buf, 0, keycode); // keysym == keycode
                    writeAll(fd, &sym_buf) catch return;
                }
            },
            8 => {
                result.stage = 2;
                break; // MapWindow — the window is up
            },
            else => {},
        }
    }

    // --- the window lives: expose, then the letter q ---
    var event = [_]u8{0} ** 32;
    event[0] = 12; // Expose
    writeAll(fd, &event) catch return;
    @memset(&event, 0);
    event[0] = 2; // KeyPress
    event[1] = 'q'; // identity mapping makes keycode 'q' the keysym 'q'
    writeAll(fd, &event) catch return;

    // --- the pointer battery: spec-exact 32-byte events (strict double) ---
    @memset(&event, 0);
    event[0] = 6; // MotionNotify at (33, 17)
    put16(&event, 24, 33);
    put16(&event, 26, 17);
    writeAll(fd, &event) catch return;
    @memset(&event, 0);
    event[0] = 4; // ButtonPress: left at (40, 12), shift held
    event[1] = 1;
    put16(&event, 24, 40);
    put16(&event, 26, 12);
    put16(&event, 28, 0x0001); // shift
    writeAll(fd, &event) catch return;
    @memset(&event, 0);
    event[0] = 5; // ButtonRelease: left at (40, 12)
    event[1] = 1;
    put16(&event, 24, 40);
    put16(&event, 26, 12);
    writeAll(fd, &event) catch return;
    @memset(&event, 0);
    event[0] = 4; // ButtonPress: wheel-up (button 4) at (5, 6)
    event[1] = 4;
    put16(&event, 24, 5);
    put16(&event, 26, 6);
    writeAll(fd, &event) catch return;
    @memset(&event, 0);
    event[0] = 5; // ButtonRelease: wheel-up pair — must be DROPPED
    event[1] = 4;
    writeAll(fd, &event) catch return;
    result.stage = 3;

    // --- expect at least one PutImage and record its first pixel ---
    while (true) {
        var head: [4]u8 = undefined;
        readExact(fd, &head) catch return;
        const units: usize = get16(&head, 2);
        var rest_len = units * 4 - 4;
        if (head[0] == 72) {
            // PutImage: total request = units*4 bytes, header = 24 bytes
            // (6 units), rest is pixel data. 4 header bytes are already in
            // `head`; read the remaining 20 to complete the 24-byte header,
            // then the first pixel, then drain the rest of the data.
            var fixed: [20]u8 = undefined;
            readExact(fd, &fixed) catch return;
            // width is at absolute request offset 12 -> fixed offset 8.
            result.put_width = get16(&fixed, 8);
            const data_bytes = units * 4 - 24; // total minus the 24-byte header
            var first: [4]u8 = undefined;
            readExact(fd, &first) catch return;
            result.first_pixel = std.mem.readInt(u32, &first, .little);
            result.stage = 4;
            // Drain the remaining pixel data (first 4 already consumed).
            var remaining = data_bytes - 4;
            var sink: [4096]u8 = undefined;
            while (remaining > 0) {
                const take = @min(remaining, sink.len);
                readExact(fd, sink[0..take]) catch return;
                remaining -= take;
            }
            break;
        }
        var sink: [4096]u8 = undefined;
        while (rest_len > 0) {
            const take = @min(rest_len, sink.len);
            readExact(fd, sink[0..take]) catch return;
            rest_len -= take;
        }
    }

    // --- the close button ---
    @memset(&event, 0);
    event[0] = 33; // ClientMessage
    put32(&event, 8, 100); // WM_PROTOCOLS (first interned atom)
    put32(&event, 12, 101); // WM_DELETE_WINDOW (second)
    writeAll(fd, &event) catch return;
    result.stage = 5;
    result.finished = true;
}

test "window loopback: fake X server — open, a key becomes 'q', a blit lands, close button closes" {
    const gpa = testing.allocator; // C6
    var path_buf: [64]u8 = undefined;
    const path = std.fmt.bufPrint(&path_buf, "/tmp/zat-x11-{d}.sock", .{linux.getpid()}) catch unreachable;
    const listen_fd = unixListen(path) orelse return error.TestUnexpectedResult;
    defer _ = linux.close(listen_fd);
    defer {
        var z: [128]u8 = undefined;
        @memcpy(z[0..path.len], path);
        z[path.len] = 0;
        _ = linux.unlink(z[0..path.len :0].ptr);
    }

    var result: FakeResult = .{};
    const server = try std.Thread.spawn(.{}, serveFakeX, .{ listen_fd, &result });
    defer server.join();

    const window = try openAt(gpa, path, "", "", "zat-test", 8, 2);
    defer close(window);
    try testing.expectEqual(@as(u16, 8), window.cols);
    try testing.expectEqual(@as(u8, 24), window.root_depth);

    // Pump until the fake server's KeyPress arrives as the byte 'q'.
    var keys: std.ArrayList(u8) = .empty;
    defer keys.deinit(gpa);
    var pointer_events: std.ArrayList(layout.InputEvent) = .empty;
    defer pointer_events.deinit(gpa);
    var waited: u32 = 0;
    var exposed = false;
    while (waited < 8000 and std.mem.indexOfScalar(u8, keys.items, 'q') == null) {
        const pumped = try pump(window, 50, gpa, &keys, &pointer_events);
        exposed = exposed or pumped.exposed;
        waited += 50;
    }
    if (std.mem.indexOfScalar(u8, keys.items, 'q') == null) std.debug.print(
        "loopback diagnostic (key wait): stage={d} setup={} key_bytes={d} exposed={}\n",
        .{ result.stage, result.ok_setup, keys.items.len, exposed },
    );
    try testing.expect(std.mem.indexOfScalar(u8, keys.items, 'q') != null);
    try testing.expect(exposed);

    // Present a real surface; the fake server records the blit.
    var surface: tui.Surface = .{};
    defer tui.deinitSurface(gpa, &surface);
    try tui.resizeSurface(gpa, &surface, 8, 2);
    _ = tui.putText(&surface, 0, 0, .{}, "A");
    try present(window, &surface);

    // The close button arrives once the server has seen the blit.
    var closed = false;
    waited = 0;
    while (waited < 8000 and !closed) {
        const pumped = try pump(window, 50, gpa, &keys, &pointer_events);
        closed = pumped.closed;
        waited += 50;
    }
    if (!closed) std.debug.print(
        "loopback diagnostic: stage={d} setup={} create={} put_w={d} finished={} key_bytes={d}\n",
        .{ result.stage, result.ok_setup, result.saw_create, result.put_width, result.finished, keys.items.len },
    );
    try testing.expect(closed);

    // The pointer battery, translated: motion, left down (shifted),
    // left up, one wheel-up — and the wheel's release pair dropped.
    try testing.expectEqual(@as(usize, 4), pointer_events.items.len);
    const ev = pointer_events.items;
    try testing.expectEqual(layout.InputEvent.Kind.move, ev[0].kind);
    try testing.expectEqual(@as(u16, 33), ev[0].x);
    try testing.expectEqual(@as(u16, 17), ev[0].y);
    try testing.expectEqual(layout.InputEvent.Kind.button_down, ev[1].kind);
    try testing.expectEqual(@as(u8, 1), ev[1].button);
    try testing.expectEqual(@as(u16, 40), ev[1].x);
    try testing.expect(ev[1].mods & layout.InputEvent.mod_shift != 0);
    try testing.expectEqual(layout.InputEvent.Kind.button_up, ev[2].kind);
    try testing.expectEqual(layout.InputEvent.Kind.wheel, ev[3].kind);
    try testing.expectEqual(@as(u8, 4), ev[3].button);

    try testing.expect(result.ok_setup);
    try testing.expect(result.saw_create);
    try testing.expect(result.finished);
    try testing.expectEqual(@as(u16, 64), result.put_width); // 8 cols × 8 px
    // 'A' row 0 is blank in the font: the first blitted pixel is the
    // background — the palette, observed on the wire.
    try testing.expectEqual(layout.palette_bg, result.first_pixel);
}
