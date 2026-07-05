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

//! B1 classification: SHELL (the FFI boundary). The mobile C-ABI seam —
//! MOBILE_ROADMAP §2 [REV 2026-07-04]: the native shim owns the OS window,
//! lifecycle, input, and browser tab; this file is the ONLY thing it calls.
//! Plain values cross; no Zig type, renderer primitive, or wire format leaks
//! through the ABI (D3/B5). Errors surface as null/false returns — the shim
//! degrades to a skipped frame or an ignored event, never a crash across the
//! boundary (E1–E3).
//!
//! Scope: M-And.0 (the seam + the pure sim, no libc) plus M-And.0b (the GPU
//! attach — zat_surface takes the ANativeWindow*, dlopens the system libEGL
//! through the same gpu.init seam as every desktop backend, and renders the
//! living field; available only in NDK-libc builds, see `mobile_config`).
//! Deliberately NOT here: the feed. The desktop run loop OWNS its loop
//! (shell/tui.zig); mobile inverts control, so the feed arrives with the
//! control-inversion slice (M-Core.1), not as a smuggled rewrite here.
//!
//! Threading contract (documented for the shim): all calls on one thread
//! (the render/choreographer thread), same as every OS window backend.

const std = @import("std");
const builtin = @import("builtin");
const glyph_field = @import("core/glyph_field.zig");
// Build-time capability switch (build.zig options module): `have_gpu` is
// true only for the NDK-libc build (-Dandroid-ndk=...), which is what makes
// bionic, the font engine, and dlopen(libEGL) available. The pure build
// comptime-gates every use below, so these imports cost it nothing.
const mobile_config = @import("mobile_config");
const gpu = @import("shell/gpu.zig");
const text = @import("core/text.zig");
const tui = @import("shell/tui.zig");
const auth = @import("shell/auth.zig");
const cache_shell = @import("shell/cache.zig");
const config = @import("shell/config.zig");
const feed_core = @import("core/feed.zig");
const layout_core = @import("core/layout.zig");
const android_dns = @import("shell/android_dns.zig");

/// The seam's context handle. The shim holds it as an opaque pointer.
/// A7.2: cold struct, size guard waived — exactly one per app process.
const Ctx = struct {
    gpa: std.mem.Allocator,
    field: glyph_field.Field,
    params: glyph_field.Params,
    bias: []f32,
    splashes: std.ArrayList(glyph_field.Splash),
    /// Pixel geometry: the field grid is derived from it (one cell per
    /// `cell_px` square), same derivation as the desktop shells.
    width_px: u32,
    height_px: u32,
    cell_px: u32,
    /// Sim clock: the shim passes wall dt; the sim steps on a fixed ~60 Hz
    /// grid exactly like the desktop loops (accumulated, clamped).
    acc_ns: u64,
    t: f32,
    /// The GPU attachment (EGL context on the shim's surface + the field
    /// renderer). Null until zat_surface; void in pure builds.
    gfx: ?Gfx,
    /// The feed leg. Null until zat_feed_start; void in pure builds.
    feed: ?Feed,
};

/// Everything the render leg owns once a surface is attached (M-And.0b).
/// A7.2: cold struct, size guard waived — at most one, lives in Ctx.
const Gfx = if (mobile_config.have_gpu) struct {
    g: gpu.Gpu,
    engine: text.Engine,
    ramp: gpu.FieldRenderer,
    grid: gpu.FieldGrid,
    width_px: u32,
    height_px: u32,
} else void;

/// The FEED leg (M_CORE_INVERSION MC.4c): everything zat_feed_start owns —
/// the process-lifetime plumbing main.zig gets for free (an Io instance, an
/// environ map rooted at the app's files dir so every cache path works
/// unchanged), the resumed session + store, and the driver handle. NDK
/// builds only, like Gfx.
/// A7.2: cold struct, size guard waived — at most one per app process.
const Feed = if (mobile_config.have_gpu) struct {
    io_backend: *std.Io.Threaded,
    env: *std.process.Environ.Map,
    session: auth.Session,
    store: feed_core.Store,
    run: *tui.MobileRun,
} else void;

// The one Android log line (liblog, linked by the NDK build): stderr goes
// nowhere in an APK, so the feed leg narrates its decisions here — `adb
// logcat -s zat4` is the whole debugging story for a phone that shows the
// field but no feed. No-op off Android.
extern "log" fn __android_log_write(prio: c_int, tag: [*:0]const u8, text: [*:0]const u8) c_int;
fn logcat(comptime fmt: []const u8, args: anytype) void {
    if (comptime !(mobile_config.have_gpu and builtin.abi.isAndroid())) return;
    var buf: [512]u8 = undefined;
    const msg = std.fmt.bufPrintZ(&buf, fmt, args) catch return;
    _ = __android_log_write(4, "zat4", msg); // 4 = ANDROID_LOG_INFO
}

// Bionic LP64 struct sigaction — sa_flags FIRST (kernel order is handler
// first; the two must never be conflated). Declared locally per the FFI
// doctrine; the extern binds libc's real symbol.
// A7.2 (FFI): layout is the OS ABI's, not ours; waived.
const BionicSigaction = extern struct {
    flags: c_int = 0,
    handler: ?*const fn (c_int) callconv(.c) void,
    mask: u64 = 0, // sigset_t: one unsigned long on LP64
    restorer: ?*const fn () callconv(.c) void = null,
};
extern "c" fn sigaction(sig: c_int, act: ?*const BionicSigaction, oact: ?*BionicSigaction) c_int;
const bionic_sigaction = sigaction;
const sig_pipe: c_int = 13;
const sig_io: c_int = 29;

fn sigNoop(_: c_int) callconv(.c) void {}

const step_ns: u64 = 16_666_667; // the fixed 60 Hz sim timestep
const amb_amp: f32 = 0.006;
const amb_scale: f32 = 0.055;
const amb_drift: f32 = 0.08;

fn gridDims(width_px: u32, height_px: u32, cell_px: u32) struct { cols: u32, rows: u32 } {
    const cp = @max(4, cell_px);
    return .{ .cols = @max(8, width_px / cp), .rows = @max(8, height_px / cp) };
}

fn create(gpa: std.mem.Allocator, width_px: u32, height_px: u32, cell_px: u32) !*Ctx {
    const ctx = try gpa.create(Ctx);
    errdefer gpa.destroy(ctx);
    const dims = gridDims(width_px, height_px, cell_px);
    var field: glyph_field.Field = undefined;
    try glyph_field.init(gpa, &field, dims.cols, dims.rows);
    errdefer glyph_field.deinit(gpa, &field);
    const bias = try gpa.alloc(f32, dims.cols * dims.rows);
    errdefer gpa.free(bias);
    @memset(bias, 0);
    ctx.* = .{
        .gpa = gpa,
        .field = field,
        .params = .{},
        .bias = bias,
        .splashes = .empty,
        .width_px = width_px,
        .height_px = height_px,
        .cell_px = @max(4, cell_px),
        .acc_ns = 0,
        .t = 0,
        .gfx = null,
        .feed = null,
    };
    return ctx;
}

fn destroy(ctx: *Ctx) void {
    feedEnd(ctx);
    detachSurface(ctx);
    const gpa = ctx.gpa;
    ctx.splashes.deinit(gpa);
    gpa.free(ctx.bias);
    glyph_field.deinit(gpa, &ctx.field);
    gpa.destroy(ctx);
}

fn resize(ctx: *Ctx, width_px: u32, height_px: u32) bool {
    const dims = gridDims(width_px, height_px, ctx.cell_px);
    var nf: glyph_field.Field = undefined;
    glyph_field.init(ctx.gpa, &nf, dims.cols, dims.rows) catch return false;
    const nb = ctx.gpa.alloc(f32, dims.cols * dims.rows) catch {
        glyph_field.deinit(ctx.gpa, &nf);
        return false;
    };
    @memset(nb, 0);
    glyph_field.deinit(ctx.gpa, &ctx.field);
    ctx.gpa.free(ctx.bias);
    ctx.field = nf;
    ctx.bias = nb;
    ctx.width_px = width_px;
    ctx.height_px = height_px;
    return true;
}

fn touch(ctx: *Ctx, kind: u32, x_px: f32, y_px: f32) void {
    // v0 vocabulary: 0 = down, 1 = move, 2 = up — the same three the desktop
    // pumps produce. With the FEED live, the event joins the frame step's
    // queue (the same InputEvents the X11 pump makes; dispatch = MC.4d).
    // Field-only mode keeps the splash.
    if (comptime mobile_config.have_gpu) {
        if (ctx.feed) |*f| {
            const ev: layout_core.InputEvent = .{
                .x = @intFromFloat(std.math.clamp(x_px, 0, 65535)),
                .y = @intFromFloat(std.math.clamp(y_px, 0, 65535)),
                .kind = switch (kind) {
                    0 => .button_down,
                    1 => .move,
                    2 => .button_up,
                    else => return,
                },
                .button = 1,
                .mods = 0,
                ._pad = 0,
            };
            _ = tui.mobilePush(f.run, ev); // a dropped tap is contained (E4)
            return;
        }
    }
    if (kind != 0) return;
    const fcell: f32 = @floatFromInt(ctx.cell_px);
    const cx: f32 = std.math.clamp(x_px / fcell, 0, @as(f32, @floatFromInt(ctx.field.cols - 1)));
    const cy: f32 = std.math.clamp(y_px / fcell, 0, @as(f32, @floatFromInt(ctx.field.rows - 1)));
    ctx.splashes.append(ctx.gpa, .{
        .x = @intFromFloat(cx),
        .y = @intFromFloat(cy),
        .radius = 3,
        .amp = 0.6,
    }) catch return; // a dropped splash is a skipped ripple, not an error (E4)
}

fn stepSim(ctx: *Ctx, dt_ns: u64) void {
    // Accumulate wall time onto the fixed sim grid; clamp a background-resume
    // burst to a few steps so a foregrounded app settles instead of fast-
    // forwarding minutes of physics.
    ctx.acc_ns += @min(dt_ns, step_ns * 8);
    while (ctx.acc_ns >= step_ns) : (ctx.acc_ns -= step_ns) {
        var yy: u32 = 0;
        while (yy < ctx.field.rows) : (yy += 1) {
            const fy: f32 = @floatFromInt(yy);
            var xx: u32 = 0;
            while (xx < ctx.field.cols) : (xx += 1) {
                const fx: f32 = @floatFromInt(xx);
                const base = std.math.sin(fx * amb_scale + ctx.t * amb_drift) *
                    std.math.sin(fy * amb_scale * 1.3 - ctx.t * amb_drift * 0.8);
                ctx.bias[yy * ctx.field.cols + xx] = amb_amp * base;
            }
        }
        glyph_field.step(&ctx.field, ctx.params, ctx.splashes.items, ctx.bias);
        ctx.splashes.clearRetainingCapacity();
        ctx.t += 1.0 / 60.0;
    }
}

/// Bring the FEED up on the attached surface (MC.4c): root the cache at the
/// app's files dir, resume the cached session, load the store, hand the
/// attach's GL context to the shared mobile driver (tui.mobileStart). False
/// = no attach yet, no cached session (sign-in on device is M-And.5; until
/// then MC.4d provisions the session file), or a failed bring-up — the shim
/// keeps the field-only render, never a dead screen (E2).
fn feedStart(ctx: *Ctx, files_dir: []const u8) bool {
    if (comptime !mobile_config.have_gpu) return false;
    if (ctx.feed != null) return true; // idempotent: already running
    const gpa = ctx.gpa;
    logcat("feed: start requested (files dir: {s})", .{files_dir});
    // The surface attach must exist — its context becomes the feed's.
    if (ctx.gfx == null) {
        logcat("feed: no surface attached yet — field-only", .{});
        return false;
    }

    const io_backend = gpa.create(std.Io.Threaded) catch return false;
    io_backend.* = std.Io.Threaded.init(gpa, .{});
    // Threaded interrupts blocked syscalls by sending SIGIO (its cancel
    // mechanism — the HTTP client's connect race cancels the loser), and an
    // unhandled SIGIO TERMINATES the process (the first on-device connect
    // died exactly there: "exited due to signal 29"). Threaded DOES install
    // a no-op handler — but every sigaction on this target is broken: bionic
    // LP64 puts sa_flags FIRST in struct sigaction, while std's layout is
    // the kernel/glibc handler-first order, so the struct arrives scrambled
    // and nothing installs. Declare bionic's true layout locally (the same
    // declare-the-ABI doctrine as android_activity's NDK surface) and
    // install the no-ops through it; SIGPIPE gets the same treatment (same
    // class of socket-lifetime signal, same default death).
    if (comptime builtin.abi.isAndroid()) {
        var act: BionicSigaction = .{ .handler = &sigNoop };
        const rio = bionic_sigaction(sig_io, &act, null);
        const rpipe = bionic_sigaction(sig_pipe, &act, null);
        logcat("feed: SIGIO/SIGPIPE no-op handlers installed (rc {d}/{d})", .{ rio, rpipe });
    }
    // Android has no /etc/resolv.conf — name lookups go through bionic's
    // getaddrinfo instead (the netLookup vtable slot; everything else stays
    // the Threaded implementation).
    const io = android_dns.wrap(io_backend.io());
    var ok_io = false;
    defer if (!ok_io) {
        io_backend.deinit();
        gpa.destroy(io_backend);
    };

    // The environ map IS the path root: HOME = the app's private files dir,
    // so every existing cache path derivation works unchanged.
    const env = gpa.create(std.process.Environ.Map) catch return false;
    env.* = std.process.Environ.Map.init(gpa);
    var ok_env = false;
    defer if (!ok_env) {
        env.deinit();
        gpa.destroy(env);
    };
    env.put("HOME", files_dir) catch return false;

    // Resume the cached session: OAuth (DPoP) first, the app-password
    // cache second — same precedence as main.zig's front door.
    var sp_buf: [512]u8 = undefined;
    const session: auth.Session = blk: {
        if (cache_shell.oauthSessionPath(&sp_buf, env)) |sp| {
            if (cache_shell.loadOAuthSessionAt(gpa, sp)) |s| {
                logcat("feed: resumed OAuth session ({s})", .{s.handle});
                break :blk s;
            }
        }
        if (cache_shell.sessionPath(&sp_buf, env)) |sp| {
            if (cache_shell.loadSessionAt(gpa, sp)) |s| {
                logcat("feed: resumed app-password session ({s})", .{s.handle});
                break :blk s;
            }
        }
        logcat("feed: NO cached session under {s}/.cache/zat — field-only (provision via --export-session)", .{files_dir});
        return false; // no session on this device yet
    };
    var ok_session = false;
    defer if (!ok_session) auth.freeSession(gpa, session);

    logcat("feed: session ok — loading store", .{});
    var store = cache_shell.loadStore(gpa, env) orelse feed_core.Store{};
    logcat("feed: store loaded ({d} posts) — dissolving field gfx", .{store.posts.len});
    var ok_store = false;
    defer if (!ok_store) feed_core.deinitStore(gpa, &store);

    const eps = config.fromEnv(env);

    // The feed leg takes over the render: dissolve the field-only Gfx —
    // steal its context (the driver owns it from here), end its private
    // font engine (the driver makes its own). The ramp/grid GL names die
    // with the context at feed end; no process memory is held.
    const stolen = ctx.gfx.?.g;
    const w = ctx.gfx.?.width_px;
    const h = ctx.gfx.?.height_px;
    text.deinitEngine(gpa, &ctx.gfx.?.engine);
    ctx.gfx = null;

    logcat("feed: gfx dissolved — starting the driver", .{});
    ctx.feed = .{
        .io_backend = io_backend,
        .env = env,
        .session = session,
        .store = store,
        .run = undefined,
    };
    const f = &ctx.feed.?;
    f.run = tui.mobileStart(gpa, io, env, &f.session, eps.appview_url, &f.store, stolen, w, h) catch |err| {
        // mobileStart owned the context from the call (deinits on its own
        // failure); unwind the rest through the flags above.
        logcat("feed: driver bring-up FAILED ({s}) — field lost too (context consumed); relaunch to retry", .{@errorName(err)});
        ctx.feed = null;
        return false;
    };
    logcat("feed: LIVE — appview {s}, {d} cached posts, {d}x{d}", .{ eps.appview_url, f.store.feed.len, w, h });
    ok_io = true;
    ok_env = true;
    ok_session = true;
    ok_store = true;
    return true;
}

/// Tear the feed down (app exit / explicit stop): persist the store and the
/// rotated session tokens (E4: a failed save is simply no cache), then the
/// driver (workers joined, GL context ends with the GPU state) and the
/// process-lifetime plumbing.
fn feedEnd(ctx: *Ctx) void {
    if (comptime !mobile_config.have_gpu) return;
    if (ctx.feed == null) return;
    logcat("feed: ending (persist store + session)", .{});
    const gpa = ctx.gpa;
    const f = &ctx.feed.?;
    _ = cache_shell.saveStore(gpa, f.env, &f.store);
    var sp_buf: [512]u8 = undefined;
    if (f.session.mode == .oauth) {
        if (cache_shell.oauthSessionPath(&sp_buf, f.env)) |sp| _ = cache_shell.saveOAuthSessionAt(gpa, sp, &f.session);
    } else if (cache_shell.sessionPath(&sp_buf, f.env)) |sp| {
        _ = cache_shell.saveSessionAt(gpa, sp, &f.session);
    }
    tui.mobileEnd(f.run);
    feed_core.deinitStore(gpa, &f.store);
    auth.freeSession(gpa, f.session);
    f.env.deinit();
    gpa.destroy(f.env);
    f.io_backend.deinit();
    gpa.destroy(f.io_backend);
    ctx.feed = null;
}

fn detachSurface(ctx: *Ctx) void {
    if (comptime !mobile_config.have_gpu) return;
    if (ctx.gfx) |*gfx| {
        // GL objects (textures, buffers, programs) die with the context;
        // only the context itself and the font engine need explicit ends.
        gpu.deinit(&gfx.g);
        text.deinitEngine(ctx.gpa, &gfx.engine);
        ctx.gfx = null;
    }
}

fn attachSurface(ctx: *Ctx, native_window: ?*anyopaque, width_px: u32, height_px: u32) bool {
    if (comptime !mobile_config.have_gpu) return false;
    detachSurface(ctx); // Android recreates surfaces freely; re-attach = replace
    var g = gpu.init(native_window) catch return false;
    gpu.setViewport(@intCast(width_px), @intCast(height_px));
    var engine = text.initEngine() catch {
        gpu.deinit(&g);
        return false;
    };
    const cell: u16 = @intCast(@min(ctx.cell_px, 256)); // renderer takes u16 cells
    const ramp = gpu.initFieldRenderer(ctx.gpa, &engine, cell, cell) catch {
        text.deinitEngine(ctx.gpa, &engine);
        gpu.deinit(&g);
        return false;
    };
    const grid = gpu.initFieldGrid() catch {
        text.deinitEngine(ctx.gpa, &engine);
        gpu.deinit(&g);
        return false;
    };
    ctx.gfx = .{
        .g = g,
        .engine = engine,
        .ramp = ramp,
        .grid = grid,
        .width_px = width_px,
        .height_px = height_px,
    };
    if (width_px != ctx.width_px or height_px != ctx.height_px) _ = resize(ctx, width_px, height_px);
    return true;
}

fn renderFrame(ctx: *Ctx) void {
    if (comptime !mobile_config.have_gpu) return;
    if (ctx.gfx) |*gfx| {
        gpu.uploadField(&gfx.grid, ctx.field.height, ctx.field.dye, ctx.field.cols, ctx.field.rows);
        gpu.clear(20.0 / 255.0, 20.0 / 255.0, 22.0 / 255.0);
        // Full-bleed field: no dimmed content pillar yet (that arrives with
        // the feed, M-Core.1) — the band is zero-width at the left edge.
        gpu.drawFieldGrid(&gfx.grid, &gfx.ramp, -100, -100, ctx.t, @intCast(gfx.width_px), @intCast(gfx.height_px), 0, 0, 0xFFA6ACBA, false);
        gpu.swap(&gfx.g);
    }
}

// ---------------------------------------------------------------------------
// The exported ABI. Names are the contract (MOBILE_ROADMAP §2); keep them
// stable — the Kotlin/Swift shims bind these strings.
// ---------------------------------------------------------------------------

/// Attach the OS surface (Android: the ANativeWindow* from the shim's
/// surfaceCreated). Brings up EGL/GLES + the field renderer on it. Pure
/// builds (no NDK libc) report false — the shim falls back to the
/// height-plane readback below.
pub export fn zat_surface(ctx_ptr: ?*anyopaque, native_window: ?*anyopaque, width_px: u32, height_px: u32) bool {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr orelse return false));
    return attachSurface(ctx, native_window, width_px, height_px);
}

/// The surface is gone (Android surfaceDestroyed / background). Safe to
/// call without an attach; rendering resumes on the next zat_surface.
pub export fn zat_surface_lost(ctx_ptr: ?*anyopaque) void {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr orelse return));
    detachSurface(ctx);
}

/// Render one frame of the field to the attached surface (call after
/// zat_step on the same thread). No surface → no-op.
pub export fn zat_render(ctx_ptr: ?*anyopaque) void {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr orelse return));
    renderFrame(ctx);
}

pub export fn zat_init(width_px: u32, height_px: u32, cell_px: u32) ?*anyopaque {
    // v0 allocator: the page allocator — pure Zig, no libc requirement, and
    // the sim's allocations are few and long-lived. The NDK build (fonts,
    // GPU, feed) revisits this deliberately (C1 — the choice is visible).
    const ctx = create(std.heap.page_allocator, width_px, height_px, cell_px) catch return null;
    return @ptrCast(ctx);
}

pub export fn zat_resize(ctx_ptr: ?*anyopaque, width_px: u32, height_px: u32) bool {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr orelse return false));
    return resize(ctx, width_px, height_px);
}

pub export fn zat_touch(ctx_ptr: ?*anyopaque, kind: u32, x_px: f32, y_px: f32) void {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr orelse return));
    touch(ctx, kind, x_px, y_px);
}

pub export fn zat_step(ctx_ptr: ?*anyopaque, dt_ns: u64) void {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr orelse return));
    stepSim(ctx, dt_ns);
}

/// Field readback for the shim's debug render (v0 only — the GPU attach
/// replaces this): the height plane as row-major f32, cols × rows. The
/// pointer stays valid until the next zat_resize/zat_shutdown.
pub export fn zat_field_cols(ctx_ptr: ?*anyopaque) u32 {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr orelse return 0));
    return ctx.field.cols;
}
pub export fn zat_field_rows(ctx_ptr: ?*anyopaque) u32 {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr orelse return 0));
    return ctx.field.rows;
}
pub export fn zat_field_height(ctx_ptr: ?*anyopaque) ?[*]const f32 {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr orelse return null));
    return ctx.field.height.ptr;
}

/// Bring the FEED up (MC.4c). `files_dir` = the app's private files
/// directory (NUL-terminated; Android: getFilesDir()), which roots every
/// cache path. Requires a prior zat_surface attach (the feed takes over its
/// GL context). False = not attached / no cached session / bring-up failed
/// — the shim keeps the field-only render (E2). Idempotent when running.
pub export fn zat_feed_start(ctx_ptr: ?*anyopaque, files_dir: ?[*:0]const u8) bool {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr orelse return false));
    const dir = files_dir orelse return false;
    return feedStart(ctx, std.mem.span(dir));
}

/// One FEED frame on the OS's clock (call instead of zat_step+zat_render
/// while the feed runs; wait budget 0 — the choreographer already waited).
/// Returns 0 = again, 1 = quit, 2 = signed out, 3 = not running / frame
/// error (the shim may retry next vsync; persistent 3s mean stop).
pub export fn zat_feed_step(ctx_ptr: ?*anyopaque) u32 {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr orelse return 3));
    if (comptime !mobile_config.have_gpu) return 3;
    if (ctx.feed) |*f| {
        const outcome = tui.mobileStep(f.run) catch |err| {
            logcat("feed: frame error {s}", .{@errorName(err)});
            return 3;
        };
        return switch (outcome) {
            .again => 0,
            .quit => 1,
            .signed_out => 2,
        };
    }
    return 3;
}

/// The surface changed size while the feed runs (rotation/fold).
pub export fn zat_feed_resize(ctx_ptr: ?*anyopaque, width_px: u32, height_px: u32) void {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr orelse return));
    if (comptime !mobile_config.have_gpu) return;
    if (ctx.feed) |*f| tui.mobileResize(f.run, width_px, height_px);
}

/// Stop the feed and persist (store + rotated tokens). Safe without a start.
pub export fn zat_feed_end(ctx_ptr: ?*anyopaque) void {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr orelse return));
    feedEnd(ctx);
}

pub export fn zat_shutdown(ctx_ptr: ?*anyopaque) void {
    const ctx: *Ctx = @ptrCast(@alignCast(ctx_ptr orelse return));
    destroy(ctx);
}

// ---------------------------------------------------------------------------
// Tests (C6) — the seam driven exactly as a shim would drive it, on the
// native target, under the leak-checking test allocator via the internal fns.
// ---------------------------------------------------------------------------

// The Android in-process host (the "shim" that needs no Kotlin): reference
// it so ANativeActivity_onCreate is analyzed + exported on android builds.
comptime {
    if (builtin.abi.isAndroid()) _ = @import("android_activity.zig");
}

const testing = std.testing;

test "seam: init → touch → step moves energy → resize survives → shutdown leaks nothing" {
    const ctx = try create(testing.allocator, 1080, 2400, 24);
    defer destroy(ctx);

    // A touch splashes; a step propagates. Energy must appear near the tap.
    touch(ctx, 0, 540, 1200);
    stepSim(ctx, step_ns * 3);
    var energy: f32 = 0;
    for (ctx.field.height) |h| energy += @abs(h);
    try testing.expect(energy > 0);

    // Rotation-shaped resize: new grid, sim keeps running.
    try testing.expect(resize(ctx, 2400, 1080));
    stepSim(ctx, step_ns);
    try testing.expectEqual(gridDims(2400, 1080, 24).cols, ctx.field.cols);
}

test "seam ABI: null context is a no-op on every export, never a crash" {
    try testing.expect(!zat_resize(null, 10, 10));
    zat_touch(null, 0, 1, 1);
    zat_step(null, step_ns);
    try testing.expectEqual(@as(u32, 0), zat_field_cols(null));
    try testing.expectEqual(@as(?[*]const f32, null), zat_field_height(null));
    try testing.expect(!zat_surface(null, null, 10, 10));
    zat_surface_lost(null);
    zat_render(null);
    try testing.expect(!zat_feed_start(null, null));
    try testing.expectEqual(@as(u32, 3), zat_feed_step(null));
    zat_feed_resize(null, 10, 10);
    zat_feed_end(null);
    zat_shutdown(null);
}

test "seam: a pure build refuses the surface attach honestly" {
    // The native test build has have_gpu=false — attach must report false
    // (the shim's cue to use the readback fallback), never pretend.
    if (comptime mobile_config.have_gpu) return error.SkipZigTest;
    const ctx = try create(testing.allocator, 320, 240, 16);
    defer destroy(ctx);
    try testing.expect(!attachSurface(ctx, null, 320, 240));
}
