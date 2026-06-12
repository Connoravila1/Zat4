//! B1 classification: SHELL. The AppKit window backend — macOS native,
//! zero third-party code, RUNTIME-BOUND: every Objective-C, AppKit,
//! CoreGraphics, and CoreFoundation symbol is fetched with dlopen/dlsym
//! at open(), so the binary carries no framework link-time symbols and
//! cross-compiles from any host (the same doctrine as the raw-syscall
//! X11 backend and the kernel32/user32 Win32 backend: the OS ABI is the
//! dependency, nothing else). objc_msgSend is one untyped symbol cast to
//! a precise function type per call site; struct RETURNS are avoided
//! entirely (no CGRect-returning calls), which keeps x86_64 away from
//! objc_msgSend_stret — CGRect appears only as a BY-VALUE argument,
//! which both Mach-O ABIs pass plainly.
//!
//! v1 scope, recorded: the window is FIXED-SIZE (styleMask omits
//! Resizable — live resize needs an NSWindowDelegate or frame polling,
//! the recorded follow-up), so `resized` is always false; the close
//! button is detected by polling [window isVisible] each pump
//! (performClose: orders the window out — no delegate machinery needed);
//! `dropped` is always 0 here because this pump propagates OutOfMemory
//! instead of swallowing it. Exercised by compile/link proof from the
//! build container and by runtime use on real hardware — the pure key
//! semantics it rides (core/appkit.zig, core/textinput.zig) are unit-
//! tested on every platform.

const std = @import("std");
const Allocator = std.mem.Allocator;
const pixel = @import("../core/pixel.zig");
const font = @import("../core/font.zig");
const tui = @import("../core/tui.zig");
const keys = @import("../core/appkit.zig");
const textinput = @import("../core/textinput.zig");

pub const OpenError = error{
    UnsupportedDisplay, // kept for surface parity; never produced here
    ConnectFailed, // a framework failed to dlopen
    SetupRefused, // a required symbol, class, or object was absent
    ProtocolError,
    OutOfMemory,
};

/// A7.2: cold struct, size guard waived — one per pump, returned by value.
pub const PumpResult = struct {
    exposed: bool = false,
    resized: bool = false,
    closed: bool = false,
    /// Parity with the Win32 backend; this pump propagates allocation
    /// failure instead of dropping, so it is always zero here.
    dropped: u32 = 0,
};

const Id = ?*anyopaque;
const Sel = ?*anyopaque;

/// CGRect, flattened: { origin, size } is four contiguous CGFloats.
/// Passed BY VALUE only (initWithContentRect:...), never returned.
const CGRect = extern struct {
    // A7.2 (FFI): layout is the OS ABI's, not ours — an exact guard
    // would assert the foreign ABI, never zat's discipline; waived.
    x: f64,
    y: f64,
    w: f64,
    h: f64,
};

/// The dlsym'd surface: the three Objective-C runtime entry points plus
/// the handful of CoreGraphics/CoreFoundation functions the blit needs.
/// A7.2: cold struct, size guard waived — one per window, a fn-ptr table.
const Objc = struct {
    getClass: *const fn ([*:0]const u8) callconv(.c) Id,
    selReg: *const fn ([*:0]const u8) callconv(.c) Sel,
    /// Untyped on purpose: cast to the precise signature at each call.
    msgSend: *anyopaque,
    CFDataCreate: *const fn (Id, [*]const u8, isize) callconv(.c) Id,
    CFRelease: *const fn (Id) callconv(.c) void,
    CGColorSpaceCreateDeviceRGB: *const fn () callconv(.c) Id,
    CGColorSpaceRelease: *const fn (Id) callconv(.c) void,
    CGDataProviderCreateWithCFData: *const fn (Id) callconv(.c) Id,
    CGDataProviderRelease: *const fn (Id) callconv(.c) void,
    CGImageCreate: *const fn (usize, usize, usize, usize, usize, Id, u32, Id, ?*const f64, u8, u32) callconv(.c) Id,
    CGImageRelease: *const fn (Id) callconv(.c) void,
};

// --- typed objc_msgSend casts: one tiny helper per call shape ---------

fn send0(o: *const Objc, self: Id, sel: Sel) Id {
    const F = *const fn (Id, Sel) callconv(.c) Id;
    return @as(F, @ptrCast(@alignCast(o.msgSend)))(self, sel);
}

fn send1(o: *const Objc, self: Id, sel: Sel, a: Id) Id {
    const F = *const fn (Id, Sel, Id) callconv(.c) Id;
    return @as(F, @ptrCast(@alignCast(o.msgSend)))(self, sel, a);
}

fn sendStr(o: *const Objc, self: Id, sel: Sel, s: [*:0]const u8) Id {
    const F = *const fn (Id, Sel, [*:0]const u8) callconv(.c) Id;
    return @as(F, @ptrCast(@alignCast(o.msgSend)))(self, sel, s);
}

fn sendU64ret(o: *const Objc, self: Id, sel: Sel) u64 {
    const F = *const fn (Id, Sel) callconv(.c) u64;
    return @as(F, @ptrCast(@alignCast(o.msgSend)))(self, sel);
}

fn sendBool0(o: *const Objc, self: Id, sel: Sel) i8 {
    const F = *const fn (Id, Sel) callconv(.c) i8;
    return @as(F, @ptrCast(@alignCast(o.msgSend)))(self, sel);
}

fn sendBoolArg(o: *const Objc, self: Id, sel: Sel, b: i8) Id {
    const F = *const fn (Id, Sel, i8) callconv(.c) Id;
    return @as(F, @ptrCast(@alignCast(o.msgSend)))(self, sel, b);
}

fn sendI64Arg(o: *const Objc, self: Id, sel: Sel, v: i64) Id {
    const F = *const fn (Id, Sel, i64) callconv(.c) Id;
    return @as(F, @ptrCast(@alignCast(o.msgSend)))(self, sel, v);
}

fn sendF64Arg(o: *const Objc, self: Id, sel: Sel, v: f64) Id {
    const F = *const fn (Id, Sel, f64) callconv(.c) Id;
    return @as(F, @ptrCast(@alignCast(o.msgSend)))(self, sel, v);
}

fn sendU16At(o: *const Objc, self: Id, sel: Sel, i: u64) u16 {
    const F = *const fn (Id, Sel, u64) callconv(.c) u16;
    return @as(F, @ptrCast(@alignCast(o.msgSend)))(self, sel, i);
}

fn sendNext(o: *const Objc, self: Id, sel: Sel, mask: u64, date: Id, mode: Id, deq: i8) Id {
    const F = *const fn (Id, Sel, u64, Id, Id, i8) callconv(.c) Id;
    return @as(F, @ptrCast(@alignCast(o.msgSend)))(self, sel, mask, date, mode, deq);
}

fn sendInitRect(o: *const Objc, self: Id, sel: Sel, r: CGRect, style: u64, backing: u64, deferred: i8) Id {
    const F = *const fn (Id, Sel, CGRect, u64, u64, i8) callconv(.c) Id;
    return @as(F, @ptrCast(@alignCast(o.msgSend)))(self, sel, r, style, backing, deferred);
}

fn loadSym(comptime T: type, lib: *anyopaque, name: [*:0]const u8) OpenError!T {
    const raw = std.c.dlsym(lib, name) orelse return error.SetupRefused;
    return @ptrCast(@alignCast(raw));
}

/// A7.2: cold struct, size guard waived — exactly one per app run.
pub const Window = struct {
    gpa: Allocator,
    objc: Objc,
    app: Id,
    window: Id,
    layer: Id,
    colorspace: Id,
    ns_date_cls: Id,
    pool_cls: Id,
    mode_str: Id,
    sel_alloc: Sel,
    sel_init: Sel,
    sel_drain: Sel,
    sel_next_event: Sel,
    sel_send_event: Sel,
    sel_type: Sel,
    sel_chars_ig: Sel,
    sel_length: Sel,
    sel_char_at: Sel,
    sel_is_visible: Sel,
    sel_set_contents: Sel,
    sel_date_with: Sel,
    sel_distant_past: Sel,
    sel_close: Sel,
    fb: pixel.Framebuffer,
    /// Fixed at open (v1: no live resize) — the tui reads these for its
    /// surface size, same as the X11 and Win32 Windows.
    cols: u16,
    rows: u16,
    pending_high: u16,
    first_pump: bool,
};

pub fn open(
    gpa: Allocator,
    environ: anytype,
    title: []const u8,
    cols: u16,
    rows: u16,
) OpenError!*Window {
    _ = environ; // no DISPLAY equivalent: the window server is implicit

    const objc_lib = std.c.dlopen("/usr/lib/libobjc.A.dylib", .{ .NOW = true }) orelse return error.ConnectFailed;
    _ = std.c.dlopen("/System/Library/Frameworks/AppKit.framework/AppKit", .{ .NOW = true }) orelse return error.ConnectFailed;
    const cg_lib = std.c.dlopen("/System/Library/Frameworks/CoreGraphics.framework/CoreGraphics", .{ .NOW = true }) orelse return error.ConnectFailed;
    const cf_lib = std.c.dlopen("/System/Library/Frameworks/CoreFoundation.framework/CoreFoundation", .{ .NOW = true }) orelse return error.ConnectFailed;

    var o: Objc = undefined;
    o.getClass = try loadSym(@TypeOf(o.getClass), objc_lib, "objc_getClass");
    o.selReg = try loadSym(@TypeOf(o.selReg), objc_lib, "sel_registerName");
    o.msgSend = std.c.dlsym(objc_lib, "objc_msgSend") orelse return error.SetupRefused;
    o.CFDataCreate = try loadSym(@TypeOf(o.CFDataCreate), cf_lib, "CFDataCreate");
    o.CFRelease = try loadSym(@TypeOf(o.CFRelease), cf_lib, "CFRelease");
    o.CGColorSpaceCreateDeviceRGB = try loadSym(@TypeOf(o.CGColorSpaceCreateDeviceRGB), cg_lib, "CGColorSpaceCreateDeviceRGB");
    o.CGColorSpaceRelease = try loadSym(@TypeOf(o.CGColorSpaceRelease), cg_lib, "CGColorSpaceRelease");
    o.CGDataProviderCreateWithCFData = try loadSym(@TypeOf(o.CGDataProviderCreateWithCFData), cg_lib, "CGDataProviderCreateWithCFData");
    o.CGDataProviderRelease = try loadSym(@TypeOf(o.CGDataProviderRelease), cg_lib, "CGDataProviderRelease");
    o.CGImageCreate = try loadSym(@TypeOf(o.CGImageCreate), cg_lib, "CGImageCreate");
    o.CGImageRelease = try loadSym(@TypeOf(o.CGImageRelease), cg_lib, "CGImageRelease");

    // One autorelease pool around setup: NSEvent/NSString temporaries
    // need a pool on this thread or they leak with console noise.
    const pool_cls = o.getClass("NSAutoreleasePool") orelse return error.SetupRefused;
    const sel_alloc = o.selReg("alloc");
    const sel_init = o.selReg("init");
    const sel_drain = o.selReg("drain");
    const setup_pool = send0(&o, send0(&o, pool_cls, sel_alloc), sel_init);
    defer _ = send0(&o, setup_pool, sel_drain);

    const app_cls = o.getClass("NSApplication") orelse return error.SetupRefused;
    const app = send0(&o, app_cls, o.selReg("sharedApplication")) orelse return error.SetupRefused;
    _ = sendI64Arg(&o, app, o.selReg("setActivationPolicy:"), 0); // Regular: dock icon, key window
    _ = send0(&o, app, o.selReg("finishLaunching"));

    const w_px: f64 = @floatFromInt(@as(u32, cols) * font.glyph_w);
    const h_px: f64 = @floatFromInt(@as(u32, rows) * font.glyph_h);
    const win_cls = o.getClass("NSWindow") orelse return error.SetupRefused;
    const win_alloc = send0(&o, win_cls, sel_alloc) orelse return error.SetupRefused;
    // styleMask 1|2|4 = Titled|Closable|Miniaturizable — Resizable (8) is
    // deliberately absent in v1 (fixed-size; the recorded follow-up).
    const rect: CGRect = .{ .x = 0, .y = 0, .w = w_px, .h = h_px };
    const win = sendInitRect(&o, win_alloc, o.selReg("initWithContentRect:styleMask:backing:defer:"), rect, 1 | 2 | 4, 2, 0) orelse return error.SetupRefused;
    // The close button must not deallocate the window out from under us:
    // we poll isVisible and close deterministically in close() (C5).
    _ = sendBoolArg(&o, win, o.selReg("setReleasedWhenClosed:"), 0);

    const str_cls = o.getClass("NSString") orelse return error.SetupRefused;
    var title_z: [128]u8 = undefined;
    const t_len = @min(title.len, title_z.len - 1);
    @memcpy(title_z[0..t_len], title[0..t_len]);
    title_z[t_len] = 0;
    // alloc/initWithUTF8String: gives OWNED strings (not autoreleased) —
    // these two outlive the setup pool by design.
    const sel_init_utf8 = o.selReg("initWithUTF8String:");
    const title_ns = sendStr(&o, send0(&o, str_cls, sel_alloc), sel_init_utf8, title_z[0..t_len :0]);
    _ = send1(&o, win, o.selReg("setTitle:"), title_ns);
    const mode_str = sendStr(&o, send0(&o, str_cls, sel_alloc), sel_init_utf8, "kCFRunLoopDefaultMode") orelse return error.SetupRefused;

    _ = send1(&o, win, o.selReg("makeKeyAndOrderFront:"), null);
    _ = sendBoolArg(&o, app, o.selReg("activateIgnoringOtherApps:"), 1);

    const view = send0(&o, win, o.selReg("contentView")) orelse return error.SetupRefused;
    _ = sendBoolArg(&o, view, o.selReg("setWantsLayer:"), 1);
    const layer = send0(&o, view, o.selReg("layer")) orelse return error.SetupRefused;

    const colorspace = o.CGColorSpaceCreateDeviceRGB() orelse return error.SetupRefused;

    const window = gpa.create(Window) catch return error.OutOfMemory;
    errdefer gpa.destroy(window);
    window.* = .{
        .gpa = gpa,
        .objc = o,
        .app = app,
        .window = win,
        .layer = layer,
        .colorspace = colorspace,
        .ns_date_cls = o.getClass("NSDate") orelse return error.SetupRefused,
        .pool_cls = pool_cls,
        .mode_str = mode_str,
        .sel_alloc = sel_alloc,
        .sel_init = sel_init,
        .sel_drain = sel_drain,
        .sel_next_event = o.selReg("nextEventMatchingMask:untilDate:inMode:dequeue:"),
        .sel_send_event = o.selReg("sendEvent:"),
        .sel_type = o.selReg("type"),
        .sel_chars_ig = o.selReg("charactersIgnoringModifiers"),
        .sel_length = o.selReg("length"),
        .sel_char_at = o.selReg("characterAtIndex:"),
        .sel_is_visible = o.selReg("isVisible"),
        .sel_set_contents = o.selReg("setContents:"),
        .sel_date_with = o.selReg("dateWithTimeIntervalSinceNow:"),
        .sel_distant_past = o.selReg("distantPast"),
        .sel_close = o.selReg("close"),
        .fb = .{},
        .cols = cols,
        .rows = rows,
        .pending_high = 0,
        .first_pump = true,
    };
    pixel.resize(gpa, &window.fb, @as(u32, cols) * font.glyph_w, @as(u32, rows) * font.glyph_h) catch return error.OutOfMemory;
    return window;
}

pub fn close(window: *Window) void {
    const o = &window.objc;
    _ = send0(o, window.window, window.sel_close);
    o.CGColorSpaceRelease(window.colorspace);
    pixel.deinit(window.gpa, &window.fb);
    const gpa = window.gpa;
    gpa.destroy(window);
}

/// Drain the event queue: wait up to timeout_ms for the first event,
/// then take the rest non-blocking (distantPast). KeyDown text flows
/// through the shared UTF-16 cores; every event is then handed back to
/// the system (sendEvent:) so the close button, miniaturize, and window
/// dragging keep working without a delegate.
pub fn pump(
    window: *Window,
    timeout_ms: u32,
    gpa: Allocator,
    out: *std.ArrayList(u8),
) error{OutOfMemory}!PumpResult {
    const o = &window.objc;
    const pool = send0(o, send0(o, window.pool_cls, window.sel_alloc), window.sel_init);
    defer _ = send0(o, pool, window.sel_drain);

    var result: PumpResult = .{};
    if (window.first_pump) {
        window.first_pump = false;
        result.exposed = true; // first paint, same contract as Expose/WM_PAINT
    }

    const secs: f64 = @as(f64, @floatFromInt(timeout_ms)) / 1000.0;
    var date: Id = sendF64Arg(o, window.ns_date_cls, window.sel_date_with, secs);
    while (true) {
        const ev = sendNext(o, window.app, window.sel_next_event, std.math.maxInt(u64), date, window.mode_str, 1);
        if (ev == null) break;
        if (sendU64ret(o, ev, window.sel_type) == 10) { // NSEventTypeKeyDown
            const chars = send0(o, ev, window.sel_chars_ig);
            if (chars != null) {
                const len = sendU64ret(o, chars, window.sel_length);
                var i: u64 = 0;
                while (i < len) : (i += 1) {
                    const unit = sendU16At(o, chars, window.sel_char_at, i);
                    var buf: [8]u8 = undefined;
                    var n: usize = 0;
                    if (keys.isFunctionKey(unit)) {
                        window.pending_high = 0;
                        n = keys.functionKeyBytes(unit, &buf);
                    } else if (textinput.utf16Step(&window.pending_high, unit)) |cp| {
                        n = textinput.codepointBytes(cp, &buf);
                    }
                    if (n > 0) try out.appendSlice(gpa, buf[0..n]);
                }
            }
        }
        _ = send1(o, window.app, window.sel_send_event, ev);
        date = send0(o, window.ns_date_cls, window.sel_distant_past);
    }

    // No delegate: the close button orders the window out, and we read
    // that state here. Polling is one message per pump — beneath
    // measurement (G3) and far simpler than objc_allocateClassPair.
    if (sendBool0(o, window.window, window.sel_is_visible) == 0) result.closed = true;
    return result;
}

/// Rasterize and blit: pixels are COPIED into a CFData (the layer may
/// hold the image past this call), wrapped as a CGImage, and assigned to
/// the layer's contents. bitmapInfo 0x2006 = ByteOrder32Little |
/// AlphaNoneSkipFirst — exactly our 0xAARRGGBB words in memory.
pub fn present(window: *Window, surface: *const tui.Surface) error{ OutOfMemory, ProtocolError }!void {
    pixel.rasterize(surface, &window.fb);
    const o = &window.objc;
    const byte_len: isize = @intCast(window.fb.pixels.len * 4);
    const data = o.CFDataCreate(null, @ptrCast(window.fb.pixels.ptr), byte_len) orelse return error.OutOfMemory;
    const provider = o.CGDataProviderCreateWithCFData(data) orelse {
        o.CFRelease(data);
        return error.ProtocolError;
    };
    const img = o.CGImageCreate(
        window.fb.width,
        window.fb.height,
        8,
        32,
        @as(usize, window.fb.width) * 4,
        window.colorspace,
        0x2006,
        provider,
        null,
        0,
        0,
    ) orelse {
        o.CGDataProviderRelease(provider);
        o.CFRelease(data);
        return error.ProtocolError;
    };
    _ = send1(o, window.layer, window.sel_set_contents, img);
    o.CGImageRelease(img);
    o.CGDataProviderRelease(provider);
    o.CFRelease(data);
}
