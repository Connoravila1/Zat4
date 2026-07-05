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

//! B1 classification: SHELL. The Android host — the "native shim" of
//! MOBILE_ROADMAP §2, which on Android needs no Kotlin at all: with
//! `android:hasCode="false"` the framework's NativeActivity loads libzat
//! and calls ANativeActivity_onCreate below. The NDK ABI is declared
//! locally (D3), the same doctrine as shell/win32.zig's Win32 surface.
//!
//! Threading (the one real contract here): the framework invokes every
//! callback on the process MAIN thread, which belongs to the OS — nothing
//! heavy may run there. All real work lives on ONE render thread that this
//! file owns: it attaches/detaches the EGL surface, drains the input
//! queue, steps the sim, renders. Callbacks only flip mutex-guarded state.
//! The single ordering rule Android enforces: after onNativeWindowDestroyed
//! RETURNS, the window pointer is dead — so that callback BLOCKS until the
//! render thread acknowledges the detach (the same handshake
//! android_native_app_glue implements; hand-rolled here per F1/F2 — the
//! glue is a convenience library, not a platform requirement).
//!
//! This file drives the same C-ABI seam a Kotlin shim would (mobile.zig's
//! zat_* exports) — the seam stays the contract; this is just its first
//! in-process consumer.

const std = @import("std");
const builtin = @import("builtin");
const seam = @import("mobile.zig");
const clock = @import("shell/clock.zig");

/// The house lock (see auth.SessionLock's note): std.Thread.Mutex is
/// unstable across this 0.16 fork's snapshots, so brief critical sections
/// ride an atomic with sleeping waiters. A7.2: cold, waived.
const Lock = struct {
    held: std.atomic.Value(bool) = .init(false),
    fn lock(self: *Lock) void {
        while (self.held.swap(true, .acquire)) clock.sleepMillis(1);
    }
    fn unlock(self: *Lock) void {
        self.held.store(false, .release);
    }
};

// ---------------------------------------------------------------------------
// The NDK ABI, declared locally (D3): android/native_activity.h,
// android/input.h, android/native_window.h. A7.2 (FFI): layouts are the
// OS ABI's, not ours — exact guards would assert the foreign ABI; waived.
// ---------------------------------------------------------------------------

const ANativeWindow = opaque {};
const AInputQueue = opaque {};
const AInputEvent = opaque {};
const ARect = extern struct {
    // A7.2 (FFI): layout is the OS ABI's, not ours — an exact guard
    // would assert the foreign ABI, never zat's discipline; waived.
    left: i32,
    top: i32,
    right: i32,
    bottom: i32,
};

const Callbacks = extern struct {
    // A7.2 (FFI): layout is the OS ABI's, not ours — an exact guard
    // would assert the foreign ABI, never zat's discipline; waived.
    onStart: ?*const fn (*Activity) callconv(.c) void = null,
    onResume: ?*const fn (*Activity) callconv(.c) void = null,
    onSaveInstanceState: ?*const fn (*Activity, *usize) callconv(.c) ?*anyopaque = null,
    onPause: ?*const fn (*Activity) callconv(.c) void = null,
    onStop: ?*const fn (*Activity) callconv(.c) void = null,
    onDestroy: ?*const fn (*Activity) callconv(.c) void = null,
    onWindowFocusChanged: ?*const fn (*Activity, c_int) callconv(.c) void = null,
    onNativeWindowCreated: ?*const fn (*Activity, *ANativeWindow) callconv(.c) void = null,
    onNativeWindowResized: ?*const fn (*Activity, *ANativeWindow) callconv(.c) void = null,
    onNativeWindowRedrawNeeded: ?*const fn (*Activity, *ANativeWindow) callconv(.c) void = null,
    onNativeWindowDestroyed: ?*const fn (*Activity, *ANativeWindow) callconv(.c) void = null,
    onInputQueueCreated: ?*const fn (*Activity, *AInputQueue) callconv(.c) void = null,
    onInputQueueDestroyed: ?*const fn (*Activity, *AInputQueue) callconv(.c) void = null,
    onContentRectChanged: ?*const fn (*Activity, *const ARect) callconv(.c) void = null,
    onConfigurationChanged: ?*const fn (*Activity) callconv(.c) void = null,
    onLowMemory: ?*const fn (*Activity) callconv(.c) void = null,
};

const Activity = extern struct {
    // A7.2 (FFI): layout is the OS ABI's, not ours — an exact guard
    // would assert the foreign ABI, never zat's discipline; waived.
    callbacks: *Callbacks,
    vm: *anyopaque,
    env: *anyopaque,
    clazz: *anyopaque,
    internalDataPath: [*:0]const u8,
    externalDataPath: [*:0]const u8,
    sdkVersion: i32,
    instance: ?*anyopaque,
    assetManager: *anyopaque,
    obbPath: [*:0]const u8,
};

// libandroid.so — in-process by construction (NativeActivity loaded us).
extern "android" fn ANativeWindow_getWidth(window: *ANativeWindow) callconv(.c) i32;
extern "android" fn ANativeWindow_getHeight(window: *ANativeWindow) callconv(.c) i32;
extern "android" fn AInputQueue_hasEvents(queue: *AInputQueue) callconv(.c) i32;
extern "android" fn AInputQueue_getEvent(queue: *AInputQueue, out: *?*AInputEvent) callconv(.c) i32;
extern "android" fn AInputQueue_preDispatchEvent(queue: *AInputQueue, event: *AInputEvent) callconv(.c) i32;
extern "android" fn AInputQueue_finishEvent(queue: *AInputQueue, event: *AInputEvent, handled: c_int) callconv(.c) void;
extern "android" fn AInputEvent_getType(event: *const AInputEvent) callconv(.c) i32;
extern "android" fn AMotionEvent_getAction(event: *const AInputEvent) callconv(.c) i32;
extern "android" fn AMotionEvent_getX(event: *const AInputEvent, pointer_index: usize) callconv(.c) f32;
extern "android" fn AMotionEvent_getY(event: *const AInputEvent, pointer_index: usize) callconv(.c) f32;

const input_event_type_motion: i32 = 2;
const action_mask: i32 = 0xff;
const action_down: i32 = 0;
const action_up: i32 = 1;
const action_move: i32 = 2;

/// One field cell ≈ 18 device px — the web reference's 9 CSS px at ~2×
/// density; an eyes-on-device [TUNE] (MOBILE_ROADMAP §8.3).
const cell_px: u32 = 18;

// ---------------------------------------------------------------------------
// The host state + render thread
// ---------------------------------------------------------------------------

/// A7.2: cold struct, size guard waived — one per activity instance.
const App = struct {
    mutex: Lock = .{},
    thread: ?std.Thread = null,
    running: std.atomic.Value(bool) = .init(true),
    /// Set by the UI-thread callbacks under the mutex; consumed by the
    /// render thread. `window_gen` bumps on every create/destroy so the
    /// render thread notices replacement (Android recreates freely).
    window: ?*ANativeWindow = null,
    window_gen: u32 = 0,
    queue: ?*AInputQueue = null,
    /// The detach handshake: onNativeWindowDestroyed blocks until the
    /// render thread has stopped touching the dying surface.
    detach_ack: std.atomic.Value(u32) = .init(0),
    /// The app's private files dir (activity.internalDataPath, copied in
    /// onCreate before the thread spawns) — the cache root zat_feed_start
    /// takes (M_CORE_INVERSION MC.4d).
    files_dir: [512:0]u8 = [_:0]u8{0} ** 512,
};

var app: App = .{};

fn renderThread() void {
    const ctx = seam.zat_init(1080, 2400, cell_px) orelse return;
    defer seam.zat_shutdown(ctx);

    var attached_gen: u32 = 0;
    // The FEED leg (MC.4d): attempted once per surface attach — a false
    // (no cached session / bring-up failure) leaves the field-only render
    // for that surface, never a dead screen (E2). While live, the loop is
    // zat_feed_step (one frame per vsync; the swap inside paces it) and
    // the field-only step/render pair rests.
    var feed_live = false;
    var feed_errs: u32 = 0;
    var last_ns: u64 = clock.monotonicNanos();

    while (app.running.load(.acquire)) {
        // Snapshot the UI-thread-owned state.
        app.mutex.lock();
        const win = app.window;
        const gen = app.window_gen;
        const queue = app.queue;
        app.mutex.unlock();

        // Surface choreography: attach on a new generation, detach + ack
        // when the window went away. A dying surface ENDS the feed first —
        // zat_feed_end persists the store + rotated tokens and closes the
        // GL context cleanly; the next attach restarts it from the cache
        // (v1 lifecycle: feed life = surface life; M-And.4 refines this).
        if (win == null and attached_gen != 0) {
            if (feed_live) {
                seam.zat_feed_end(ctx);
                feed_live = false;
            }
            seam.zat_surface_lost(ctx);
            attached_gen = 0;
            app.detach_ack.store(gen, .release);
        } else if (win != null and attached_gen != gen) {
            const w: u32 = @intCast(@max(1, ANativeWindow_getWidth(win.?)));
            const h: u32 = @intCast(@max(1, ANativeWindow_getHeight(win.?)));
            if (seam.zat_surface(ctx, @ptrCast(win.?), w, h)) {
                _ = seam.zat_resize(ctx, w, h);
                attached_gen = gen;
                feed_live = seam.zat_feed_start(ctx, &app.files_dir);
                feed_errs = 0;
            }
        }

        // Drain touches (queue polled, no looper — the render tick is the
        // only clock this app has, same single-loop doctrine as desktop).
        if (queue) |q| {
            while (AInputQueue_hasEvents(q) > 0) {
                var ev: ?*AInputEvent = null;
                if (AInputQueue_getEvent(q, &ev) < 0) break;
                const e = ev orelse break;
                if (AInputQueue_preDispatchEvent(q, e) != 0) continue; // IME took it
                var handled: c_int = 0;
                if (AInputEvent_getType(e) == input_event_type_motion) {
                    const action = AMotionEvent_getAction(e) & action_mask;
                    const kind: u32 = switch (action) {
                        action_down => 0,
                        action_move => 1,
                        action_up => 2,
                        else => 3,
                    };
                    if (kind != 3) {
                        seam.zat_touch(ctx, kind, AMotionEvent_getX(e, 0), AMotionEvent_getY(e, 0));
                        handled = 1;
                    }
                }
                AInputQueue_finishEvent(q, e, handled);
            }
        }

        if (feed_live) {
            // One feed frame; the swap inside vsync-paces the loop. 1/2
            // (quit/signed-out) and persistent 3s (frame errors, ~2s worth)
            // end the feed — the screen parks on its last frame; a surface
            // bounce (or app relaunch) starts fresh from the cache.
            const rc = seam.zat_feed_step(ctx);
            if (rc == 1 or rc == 2) {
                seam.zat_feed_end(ctx);
                feed_live = false;
            } else if (rc == 3) {
                feed_errs += 1;
                if (feed_errs > 120) {
                    seam.zat_feed_end(ctx);
                    feed_live = false;
                }
            } else feed_errs = 0;
            last_ns = clock.monotonicNanos();
            continue;
        }
        const now_ns = clock.monotonicNanos();
        seam.zat_step(ctx, now_ns -| last_ns);
        last_ns = now_ns;
        if (attached_gen != 0) {
            seam.zat_render(ctx); // eglSwapBuffers vsync-paces the loop
        } else {
            clock.sleepMillis(50); // parked: no surface
        }
    }
    if (feed_live) seam.zat_feed_end(ctx);
    seam.zat_surface_lost(ctx);
}

// ---------------------------------------------------------------------------
// Framework callbacks (UI thread: flip state, never work)
// ---------------------------------------------------------------------------

fn onNativeWindowCreated(_: *Activity, window: *ANativeWindow) callconv(.c) void {
    app.mutex.lock();
    defer app.mutex.unlock();
    app.window = window;
    app.window_gen +%= 1;
    if (app.window_gen == 0) app.window_gen = 1;
}

fn onNativeWindowDestroyed(_: *Activity, _: *ANativeWindow) callconv(.c) void {
    app.mutex.lock();
    const gen = app.window_gen;
    app.window = null;
    app.mutex.unlock();
    // Android's rule: the pointer dies when this returns. Hold the door
    // until the render thread has let go (it acks with the generation).
    while (app.running.load(.acquire) and app.detach_ack.load(.acquire) != gen) {
        clock.sleepMillis(1);
    }
}

fn onInputQueueCreated(_: *Activity, queue: *AInputQueue) callconv(.c) void {
    app.mutex.lock();
    defer app.mutex.unlock();
    app.queue = queue;
}

fn onInputQueueDestroyed(_: *Activity, queue: *AInputQueue) callconv(.c) void {
    app.mutex.lock();
    defer app.mutex.unlock();
    if (app.queue == queue) app.queue = null;
}

fn onDestroy(_: *Activity) callconv(.c) void {
    app.running.store(false, .release);
    if (app.thread) |t| t.join();
    app.thread = null;
}

/// The framework's entry point (looked up by name in the library that
/// android.app.lib_name names). Wire the callbacks, start the one thread.
export fn ANativeActivity_onCreate(activity: *Activity, saved: ?*anyopaque, saved_len: usize) void {
    _ = saved;
    _ = saved_len;
    activity.callbacks.onNativeWindowCreated = onNativeWindowCreated;
    activity.callbacks.onNativeWindowDestroyed = onNativeWindowDestroyed;
    activity.callbacks.onInputQueueCreated = onInputQueueCreated;
    activity.callbacks.onInputQueueDestroyed = onInputQueueDestroyed;
    activity.callbacks.onDestroy = onDestroy;
    app = .{};
    // The app's private files dir — the cache root the feed leg needs
    // (MC.4d). Copied before the thread spawns; the activity's own string
    // may not outlive us.
    const path = std.mem.span(activity.internalDataPath);
    const n = @min(path.len, app.files_dir.len);
    @memcpy(app.files_dir[0..n], path[0..n]);
    app.files_dir[n] = 0;
    app.thread = std.Thread.spawn(.{}, renderThread, .{}) catch null;
}
