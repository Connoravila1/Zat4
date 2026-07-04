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
    };
    return ctx;
}

fn destroy(ctx: *Ctx) void {
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
    // pumps produce. Only `down` splashes for now; move/up join with the
    // feed's hit-testing (M-Core.1).
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
