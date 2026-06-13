//! B1 classification: SHELL. The Windows window — Win32 spoken directly
//! as the OS ABI (`extern "user32"` / `"gdi32"` declarations), the same
//! doctrine as the Linux syscall surface: no third-party code, no
//! binding library, F1 never fires. The module exposes the SAME surface
//! as shell/window.zig (open / close / pump / present / PumpResult), so
//! shell/native.zig can select it by OS and nothing above notices (D1).
//!
//! Division of meaning: key semantics are pure tables in core/win32.zig
//! (tested on any host); the rasterizer is the shared layout/raster/text core stack;
//! this file owns only the OS choreography — class registration, the
//! window procedure, the message pump, and the DIB blit (B3).
//!
//! Status, recorded honestly: this MODULE is complete and cross-compile-
//! proven (`zig build-obj -target x86_64-windows src/shell/win32.zig`).
//! The full APP on Windows additionally needs the POSIX shell surfaces
//! ported (clock, cache files, stream sockets) — the checklist lives in
//! the roadmap's cross-platform section. Runtime verification happens on
//! a real Windows machine; this container has none.

const std = @import("std");
const Allocator = std.mem.Allocator;
const layout = @import("../core/layout.zig");
const raster = @import("../core/raster.zig");
const text_core = @import("../core/text.zig");
const text = text_core;
const keys = @import("../core/win32.zig");
const tui = @import("../core/tui.zig");

// ---------------------------------------------------------------------------
// The OS ABI, declared locally (D3: no other module sees these types)
// ---------------------------------------------------------------------------

const HWND = ?*opaque {};
const HINSTANCE = ?*opaque {};
const HDC = ?*opaque {};
const HICON = ?*opaque {};
const HCURSOR = ?*opaque {};
const HBRUSH = ?*opaque {};
const HMENU = ?*opaque {};
const WPARAM = usize;
const LPARAM = isize;
const LRESULT = isize;

const WndProc = *const fn (HWND, u32, WPARAM, LPARAM) callconv(.winapi) LRESULT;

const POINT = extern struct {
    // A7.2 (FFI): layout is the OS ABI's, not ours — an exact guard
    // would assert the foreign ABI, never zat's discipline; waived.
    x: i32,
    y: i32,
};
const RECT = extern struct {
    // A7.2 (FFI): layout is the OS ABI's, not ours — an exact guard
    // would assert the foreign ABI, never zat's discipline; waived.
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
};
const MSG = extern struct {
    // A7.2 (FFI): layout is the OS ABI's, not ours — an exact guard
    // would assert the foreign ABI, never zat's discipline; waived.

    hwnd: HWND,
    message: u32,
    wParam: WPARAM,
    lParam: LPARAM,
    time: u32,
    pt: POINT,
};
const WNDCLASSEXW = extern struct {
    // A7.2 (FFI): layout is the OS ABI's, not ours — an exact guard
    // would assert the foreign ABI, never zat's discipline; waived.

    cbSize: u32,
    style: u32,
    lpfnWndProc: WndProc,
    cbClsExtra: i32 = 0,
    cbWndExtra: i32 = 0,
    hInstance: HINSTANCE,
    hIcon: HICON = null,
    hCursor: HCURSOR,
    hbrBackground: HBRUSH = null,
    lpszMenuName: ?[*:0]const u16 = null,
    lpszClassName: [*:0]const u16,
    hIconSm: HICON = null,
};
const BITMAPINFOHEADER = extern struct {
    // A7.2 (FFI): layout is the OS ABI's, not ours — an exact guard
    // would assert the foreign ABI, never zat's discipline; waived.

    biSize: u32,
    biWidth: i32,
    biHeight: i32,
    biPlanes: u16,
    biBitCount: u16,
    biCompression: u32,
    biSizeImage: u32 = 0,
    biXPelsPerMeter: i32 = 0,
    biYPelsPerMeter: i32 = 0,
    biClrUsed: u32 = 0,
    biClrImportant: u32 = 0,
};
const BITMAPINFO = extern struct {
    // A7.2 (FFI): layout is the OS ABI's, not ours — an exact guard
    // would assert the foreign ABI, never zat's discipline; waived.

    bmiHeader: BITMAPINFOHEADER,
    bmiColors: [1]u32 = .{0},
};

extern "kernel32" fn GetModuleHandleW(lpModuleName: ?[*:0]const u16) callconv(.winapi) HINSTANCE;
extern "kernel32" fn GetLastError() callconv(.winapi) u32;
extern "user32" fn RegisterClassExW(class: *const WNDCLASSEXW) callconv(.winapi) u16;
extern "user32" fn LoadCursorW(hInstance: HINSTANCE, lpCursorName: usize) callconv(.winapi) HCURSOR;
extern "user32" fn AdjustWindowRect(lpRect: *RECT, dwStyle: u32, bMenu: i32) callconv(.winapi) i32;
extern "user32" fn CreateWindowExW(
    dwExStyle: u32,
    lpClassName: [*:0]const u16,
    lpWindowName: [*:0]const u16,
    dwStyle: u32,
    x: i32,
    y: i32,
    nWidth: i32,
    nHeight: i32,
    hWndParent: HWND,
    hMenu: HMENU,
    hInstance: HINSTANCE,
    lpParam: ?*anyopaque,
) callconv(.winapi) HWND;
extern "user32" fn DestroyWindow(hWnd: HWND) callconv(.winapi) i32;
extern "user32" fn DefWindowProcW(hWnd: HWND, msg: u32, wParam: WPARAM, lParam: LPARAM) callconv(.winapi) LRESULT;
extern "user32" fn SetWindowLongPtrW(hWnd: HWND, nIndex: i32, dwNewLong: isize) callconv(.winapi) isize;
extern "user32" fn GetWindowLongPtrW(hWnd: HWND, nIndex: i32) callconv(.winapi) isize;
extern "user32" fn PeekMessageW(lpMsg: *MSG, hWnd: HWND, wMsgFilterMin: u32, wMsgFilterMax: u32, wRemoveMsg: u32) callconv(.winapi) i32;
extern "user32" fn TranslateMessage(lpMsg: *const MSG) callconv(.winapi) i32;
extern "user32" fn DispatchMessageW(lpMsg: *const MSG) callconv(.winapi) LRESULT;
extern "user32" fn MsgWaitForMultipleObjects(nCount: u32, pHandles: ?*const anyopaque, fWaitAll: i32, dwMilliseconds: u32, dwWakeMask: u32) callconv(.winapi) u32;
extern "user32" fn ValidateRect(hWnd: HWND, lpRect: ?*const RECT) callconv(.winapi) i32;
extern "user32" fn GetDC(hWnd: HWND) callconv(.winapi) HDC;
extern "user32" fn ScreenToClient(hWnd: HWND, lpPoint: *POINT) callconv(.winapi) i32;
extern "user32" fn ReleaseDC(hWnd: HWND, hDC: HDC) callconv(.winapi) i32;
extern "gdi32" fn StretchDIBits(
    hdc: HDC,
    xDest: i32,
    yDest: i32,
    DestWidth: i32,
    DestHeight: i32,
    xSrc: i32,
    ySrc: i32,
    SrcWidth: i32,
    SrcHeight: i32,
    lpBits: *const anyopaque,
    lpbmi: *const BITMAPINFO,
    iUsage: u32,
    rop: u32,
) callconv(.winapi) i32;

const ws_overlappedwindow: u32 = 0x00CF_0000;
const ws_visible: u32 = 0x1000_0000;
const cw_usedefault: i32 = @bitCast(@as(u32, 0x8000_0000));
const gwlp_userdata: i32 = -21;
const pm_remove: u32 = 1;
const qs_allinput: u32 = 0x04FF;
const dib_rgb_colors: u32 = 0;
const srccopy: u32 = 0x00CC_0020;
const idc_arrow: usize = 32512;
const error_class_already_exists: u32 = 1410;

const wm_destroy: u32 = 0x0002;
const wm_size: u32 = 0x0005;
const wm_paint: u32 = 0x000F;
const wm_close: u32 = 0x0010;
const wm_erasebkgnd: u32 = 0x0014;
const wm_keydown: u32 = 0x0100;
const wm_char: u32 = 0x0102;
const wm_mousemove: u32 = 0x0200;
const wm_lbuttondown: u32 = 0x0201;
const wm_lbuttonup: u32 = 0x0202;
const wm_rbuttondown: u32 = 0x0204;
const wm_rbuttonup: u32 = 0x0205;
const wm_mbuttondown: u32 = 0x0207;
const wm_mbuttonup: u32 = 0x0208;
const wm_mousewheel: u32 = 0x020A;
/// Mouse-message modifier bits in wParam's low word (MK_*).
const mk_shift: usize = 0x0004;
const mk_control: usize = 0x0008;

// ---------------------------------------------------------------------------
// The window — same surface as shell/window.zig
// ---------------------------------------------------------------------------

pub const OpenError = error{
    UnsupportedDisplay, // kept for surface parity; never produced here
    ConnectFailed, // class registration or CreateWindowExW refused
    SetupRefused,
    ProtocolError,
    OutOfMemory,
};

/// A7.2: cold struct, size guard waived — one per session.
pub const Window = struct {
    gpa: Allocator,
    hwnd: HWND,
    fb: raster.Framebuffer,
    /// Per-frame draw list — opaque transport between the layout and
    /// raster cores; never inspected here (B5/D3).
    draw_list: raster.DrawList,
    cols: u16,
    rows: u16,
    /// Terminal bytes the window procedure has produced since the last
    /// pump; drained into the caller's buffer (the same hand-off shape
    /// as the X11 pump).
    queue: std.ArrayList(u8),
    /// Pointer events the procedure has produced since the last pump,
    /// drained the same way. A3 exception: flat 8-byte InputEvent
    /// records, consumed whole and in order by the core — see the X11
    /// pump's note for the full reasoning.
    pointer_queue: std.ArrayList(layout.InputEvent),
    closed: bool,
    resized: bool,
    exposed: bool,
    /// Surrogate-pair state for WM_CHAR (core/win32.utf16Step owns the
    /// semantics; this is just its caller-held u16).
    pending_high: u16,
    /// Keystroke bytes lost to allocation failure inside the procedure —
    /// counted here, surfaced by the pump, never silent (E3 honored as
    /// far as a Win32 callback allows).
    dropped: u32,
};

pub const PumpResult = struct {
    // A7.2: cold struct, size guard waived — one per pump, returned by value.

    exposed: bool = false,
    resized: bool = false,
    closed: bool = false,
    /// Input bytes lost since the last pump (allocation failure in the
    /// window procedure). Zero in healthy operation.
    dropped: u32 = 0,
    /// Parity with the X11 backend's error-packet report; there is no X
    /// server here, so it is always zero. Exists so the Backend seam in
    /// shell/tui.zig reads one shape on every OS (the native.zig
    /// same-surface contract).
    x_error: u8 = 0,
};

const class_name = std.unicode.utf8ToUtf16LeStringLiteral("zatWindow");

/// `environ` is accepted for surface parity with the X11 backend (which
/// needs DISPLAY/XAUTHORITY); Windows needs nothing from it.
pub fn open(
    gpa: Allocator,
    environ: anytype,
    title: []const u8,
    cols: u16,
    rows: u16,
) OpenError!*Window {
    _ = environ;
    const hinstance = GetModuleHandleW(null);

    const class: WNDCLASSEXW = .{
        .cbSize = @sizeOf(WNDCLASSEXW),
        .style = 0,
        .lpfnWndProc = wndProc,
        .hInstance = hinstance,
        .hCursor = LoadCursorW(null, idc_arrow),
        .lpszClassName = class_name,
    };
    if (RegisterClassExW(&class) == 0 and GetLastError() != error_class_already_exists) {
        return error.ConnectFailed;
    }

    const width: i32 = @as(i32, cols) * @as(i32, @intCast(text.cell_w));
    const height: i32 = @as(i32, rows) * @as(i32, @intCast(text.cell_h));
    var frame: RECT = .{ .left = 0, .top = 0, .right = width, .bottom = height };
    _ = AdjustWindowRect(&frame, ws_overlappedwindow, 0);

    var title_buf: [64]u16 = undefined;
    const title_len = std.unicode.utf8ToUtf16Le(title_buf[0 .. title_buf.len - 1], title) catch 0;
    title_buf[title_len] = 0;

    const hwnd = CreateWindowExW(
        0,
        class_name,
        title_buf[0..title_len :0],
        ws_overlappedwindow | ws_visible,
        cw_usedefault,
        cw_usedefault,
        frame.right - frame.left,
        frame.bottom - frame.top,
        null,
        null,
        hinstance,
        null,
    ) orelse return error.ConnectFailed;

    const window = gpa.create(Window) catch return error.OutOfMemory;
    errdefer gpa.destroy(window);
    window.* = .{
        .gpa = gpa,
        .hwnd = hwnd,
        .fb = .{},
        .draw_list = .empty,
        .pointer_queue = .empty,
        .cols = cols,
        .rows = rows,
        .queue = .empty,
        .closed = false,
        .resized = false,
        .exposed = false,
        .pending_high = 0,
        .dropped = 0,
    };
    // A burst of typing or dragging should never need the allocator
    // mid-callback.
    window.queue.ensureTotalCapacity(gpa, 256) catch return error.OutOfMemory;
    window.pointer_queue.ensureTotalCapacity(gpa, 256) catch return error.OutOfMemory;
    raster.resize(gpa, &window.fb, @intCast(width), @intCast(height), layout.palette_bg) catch return error.OutOfMemory;
    _ = SetWindowLongPtrW(hwnd, gwlp_userdata, @bitCast(@intFromPtr(window)));
    return window;
}

pub fn close(window: *Window) void {
    const gpa = window.gpa;
    _ = SetWindowLongPtrW(window.hwnd, gwlp_userdata, 0);
    _ = DestroyWindow(window.hwnd);
    window.queue.deinit(gpa);
    window.pointer_queue.deinit(gpa);
    window.draw_list.deinit(gpa);
    raster.deinit(gpa, &window.fb);
    gpa.destroy(window);
}

/// The window procedure: the OS's required callback shape. It does the
/// minimum — translate, flag, queue — and the pump (our code, our loop)
/// does everything else. State rides GWLP_USERDATA; messages arriving
/// before open() finishes fall through to DefWindowProc harmlessly.
fn wndProc(hwnd: HWND, msg: u32, wparam: WPARAM, lparam: LPARAM) callconv(.winapi) LRESULT {
    const raw = GetWindowLongPtrW(hwnd, gwlp_userdata);
    if (raw == 0) return DefWindowProcW(hwnd, msg, wparam, lparam);
    const window: *Window = @ptrFromInt(@as(usize, @bitCast(raw)));

    switch (msg) {
        wm_close => {
            window.closed = true;
            return 0;
        },
        wm_size => {
            const w: u16 = @truncate(@as(usize, @bitCast(lparam)));
            const h: u16 = @truncate(@as(usize, @bitCast(lparam)) >> 16);
            if (w > 0 and h > 0 and (w != window.fb.width or h != window.fb.height)) {
                // Allocation inside the procedure is same-thread (the pump
                // dispatches us); a failed resize keeps the old buffer and
                // the next WM_SIZE retries (E4).
                raster.resize(window.gpa, &window.fb, w, h, layout.palette_bg) catch return 0;
                window.cols = @intCast(@max(20, w / text.cell_w));
                window.rows = @intCast(@max(5, h / text.cell_h));
                window.resized = true;
            }
            return 0;
        },
        wm_paint => {
            _ = ValidateRect(hwnd, null); // or the OS repeats WM_PAINT forever
            window.exposed = true;
            return 0;
        },
        wm_erasebkgnd => return 1, // we paint every pixel; no flicker pass
        wm_char => {
            if (keys.utf16Step(&window.pending_high, @truncate(wparam))) |cp| {
                var buf: [8]u8 = undefined;
                const n = keys.codepointBytes(cp, &buf);
                if (n > 0) window.queue.appendSlice(window.gpa, buf[0..n]) catch {
                    window.dropped +%= @intCast(n); // counted, not silent
                };
            }
            return 0;
        },
        wm_keydown => {
            var buf: [8]u8 = undefined;
            const n = keys.keydownBytes(@truncate(wparam), &buf);
            if (n > 0) window.queue.appendSlice(window.gpa, buf[0..n]) catch {
                window.dropped +%= @intCast(n); // counted, not silent
            };
            return 0;
        },
        wm_mousemove, wm_lbuttondown, wm_lbuttonup, wm_rbuttondown, wm_rbuttonup, wm_mbuttondown, wm_mbuttonup => {
            // Client coordinates ride lParam as two signed shorts; clamp
            // negatives to the edge (capture can report outside the
            // client area), same policy as the X11 leg. Modifiers are
            // translated INTO the X11 mask positions the InputEvent
            // contract fixes (layout.InputEvent doc).
            const lx: i16 = @bitCast(@as(u16, @truncate(@as(usize, @bitCast(lparam)))));
            const ly: i16 = @bitCast(@as(u16, @truncate(@as(usize, @bitCast(lparam)) >> 16)));
            const kind: layout.InputEvent.Kind = switch (msg) {
                wm_mousemove => .move,
                wm_lbuttondown, wm_rbuttondown, wm_mbuttondown => .button_down,
                else => .button_up,
            };
            const button: u8 = switch (msg) {
                wm_lbuttondown, wm_lbuttonup => 1,
                wm_mbuttondown, wm_mbuttonup => 2,
                wm_rbuttondown, wm_rbuttonup => 3,
                else => 0,
            };
            window.pointer_queue.append(window.gpa, .{
                .x = if (lx < 0) 0 else @intCast(lx),
                .y = if (ly < 0) 0 else @intCast(ly),
                .kind = kind,
                .button = button,
                .mods = win32Mods(wparam),
                ._pad = 0,
            }) catch {
                window.dropped +%= 1; // counted, not silent
            };
            return 0;
        },
        wm_mousewheel => {
            // Wheel coordinates are SCREEN space (the one mouse message
            // that differs); convert to client space before queueing.
            // HIWORD(wParam) is a signed delta in multiples of 120:
            // positive = away from the user = wheel up = button 4.
            const delta: i16 = @bitCast(@as(u16, @truncate(wparam >> 16)));
            if (delta == 0) return 0;
            var pt: POINT = .{
                .x = @as(i16, @bitCast(@as(u16, @truncate(@as(usize, @bitCast(lparam)))))),
                .y = @as(i16, @bitCast(@as(u16, @truncate(@as(usize, @bitCast(lparam)) >> 16)))),
            };
            _ = ScreenToClient(hwnd, &pt);
            window.pointer_queue.append(window.gpa, .{
                .x = if (pt.x < 0) 0 else @intCast(@min(pt.x, std.math.maxInt(u16))),
                .y = if (pt.y < 0) 0 else @intCast(@min(pt.y, std.math.maxInt(u16))),
                .kind = .wheel,
                .button = if (delta > 0) 4 else 5,
                .mods = win32Mods(wparam),
                ._pad = 0,
            }) catch {
                window.dropped +%= 1; // counted, not silent
            };
            return 0;
        },
        wm_destroy => return 0,
        else => return DefWindowProcW(hwnd, msg, wparam, lparam),
    }
}

/// MK_* (mouse-message wParam bits) -> the X11 mask positions the
/// InputEvent contract fixes. Alt does not ride mouse wParams on Win32;
/// it would need GetKeyState — added when a screen actually wants
/// alt-click (F4: no speculative machinery).
fn win32Mods(wparam: WPARAM) u8 {
    var mods: u8 = 0;
    if (wparam & mk_shift != 0) mods |= layout.InputEvent.mod_shift;
    if (wparam & mk_control != 0) mods |= layout.InputEvent.mod_control;
    return mods;
}

/// Bounded wait, then drain the message queue; the procedure above fills
/// `window.queue` and the flags, and this hands them to the caller — the
/// same contract as the X11 pump.
pub fn pump(
    window: *Window,
    timeout_ms: i32,
    gpa: Allocator,
    out: *std.ArrayList(u8),
    events: *std.ArrayList(layout.InputEvent),
) error{ OutOfMemory, ProtocolError }!PumpResult {
    const wait: u32 = if (timeout_ms > 0) @intCast(timeout_ms) else 0;
    _ = MsgWaitForMultipleObjects(0, null, 0, wait, qs_allinput);

    var msg: MSG = undefined;
    while (PeekMessageW(&msg, null, 0, 0, pm_remove) != 0) {
        _ = TranslateMessage(&msg);
        _ = DispatchMessageW(&msg);
    }

    if (window.queue.items.len > 0) {
        try out.appendSlice(gpa, window.queue.items);
        window.queue.clearRetainingCapacity();
    }
    if (window.pointer_queue.items.len > 0) {
        try events.appendSlice(gpa, window.pointer_queue.items);
        window.pointer_queue.clearRetainingCapacity();
    }
    const result: PumpResult = .{
        .exposed = window.exposed,
        .resized = window.resized,
        .closed = window.closed,
        .dropped = window.dropped,
    };
    window.exposed = false;
    window.resized = false;
    window.dropped = 0;
    return result;
}

pub fn present(window: *Window, surface: *const tui.Surface) error{ OutOfMemory, ProtocolError }!void {
    // The Phase-5 seam (GUI roadmap §2): pure layout builds the draw
    // list, pure raster paints it, and only the blit below is shell.
    try layout.fromSurface(window.gpa, &window.draw_list, surface);
    try raster.paint(window.gpa, null, window.draw_list.slice(), &window.fb, layout.palette_bg);
    try blit(window);
}

/// The modern pixel path — paint the caller's list, then blit. Mirrors
/// the X11 backend's surface (native.zig same-shape contract).
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

pub fn blit(window: *Window) error{ OutOfMemory, ProtocolError }!void {
    const fb = &window.fb;
    if (fb.width == 0 or fb.height == 0) return;

    const hdc = GetDC(window.hwnd) orelse return error.ProtocolError;
    defer _ = ReleaseDC(window.hwnd, hdc);

    const bi: BITMAPINFO = .{
        .bmiHeader = .{
            .biSize = @sizeOf(BITMAPINFOHEADER),
            .biWidth = @intCast(fb.width),
            .biHeight = -@as(i32, @intCast(fb.height)), // negative: top-down rows
            .biPlanes = 1,
            .biBitCount = 32,
            .biCompression = 0, // BI_RGB; our 0xAARGGBB matches the DIB layout
        },
    };
    const w: i32 = @intCast(fb.width);
    const h: i32 = @intCast(fb.height);
    if (StretchDIBits(hdc, 0, 0, w, h, 0, 0, w, h, fb.pixels.ptr, &bi, dib_rgb_colors, srccopy) == 0) {
        return error.ProtocolError;
    }
}
