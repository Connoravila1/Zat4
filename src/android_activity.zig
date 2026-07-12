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
const input_event_type_key: i32 = 1;
const action_mask: i32 = 0xff;
const action_down: i32 = 0;
const action_up: i32 = 1;
const action_move: i32 = 2;
const action_cancel: i32 = 3; // the system claimed the gesture (back edge, shade)
const action_pointer_down: i32 = 5; // a SECOND finger landed (two-thumb typing)
const action_pointer_up: i32 = 6; // a non-last finger lifted (identity renumbers after)
const action_pointer_index_shift: u5 = 8; // its index rides the action's high byte
const key_action_down: i32 = 0;
const akeycode_back: i32 = 4; // AKEYCODE_BACK — the system back gesture/button
const meta_shift_on: i32 = 0x1;

extern "android" fn AKeyEvent_getAction(event: *const AInputEvent) callconv(.c) i32;
extern "android" fn AKeyEvent_getKeyCode(event: *const AInputEvent) callconv(.c) i32;
extern "android" fn AKeyEvent_getMetaState(event: *const AInputEvent) callconv(.c) i32;

/// Map an Android keycode (+shift) to the codepoint the seam feeds the
/// composer. The soft keyboard reaches a no-text-widget app through its
/// KeyEvent FALLBACK (the game-engine path), which covers this basic Latin
/// set; rich IME text (autocorrect, emoji, CJK) needs an InputConnection —
/// the recorded follow-up. Unmapped keys return null and stay UNHANDLED so
/// the system keeps BACK/volume/etc.
fn keyCodepoint(kc: i32, meta: i32) ?u21 {
    const shift = (meta & meta_shift_on) != 0;
    return switch (kc) {
        7...16 => blk: { // KEYCODE_0..9
            const d: u21 = @intCast(kc - 7);
            if (!shift) break :blk '0' + d;
            const syms = [10]u21{ ')', '!', '@', '#', '$', '%', '^', '&', '*', '(' };
            break :blk syms[@intCast(kc - 7)];
        },
        29...54 => blk: { // KEYCODE_A..Z
            const c: u21 = 'a' + @as(u21, @intCast(kc - 29));
            break :blk if (shift) c - 32 else c;
        },
        62 => ' ',
        66 => 13, // enter
        67 => 8, // del -> backspace
        55 => if (shift) @as(u21, '<') else ',',
        56 => if (shift) @as(u21, '>') else '.',
        68 => if (shift) @as(u21, '~') else '`',
        69 => if (shift) @as(u21, '_') else '-',
        70 => if (shift) @as(u21, '+') else '=',
        71 => if (shift) @as(u21, '{') else '[',
        72 => if (shift) @as(u21, '}') else ']',
        73 => if (shift) @as(u21, '|') else '\\',
        74 => if (shift) @as(u21, ':') else ';',
        75 => if (shift) @as(u21, '"') else '\'',
        76 => if (shift) @as(u21, '?') else '/',
        77 => '@',
        else => null,
    };
}

// ---------------------------------------------------------------------------
// Minimal JNI, declared locally (D3) — the two OAuth hops (M-And.5) are the
// only Java the app speaks: startActivity(ACTION_VIEW url) to open the
// browser, and getIntent().getDataString() to read the redirect back. Only
// the dialed slots are typed; indices were read from the NDK's jni.h
// (233-slot JNINativeInterface, 8-slot JNIInvokeInterface). The A-variants
// (jvalue arrays) are used exclusively — no C varargs cross this boundary.
// A7.2 (FFI): layouts are the JVM ABI's, not ours; waived.
// ---------------------------------------------------------------------------

const jobject = ?*anyopaque;
const jclass = jobject;
const jstring = jobject;
const jmethodID = ?*anyopaque;
// A7.2 (FFI): layout is the JVM ABI's, not ours; waived.
const jvalue = extern union { l: jobject, z: u8, i: i32, j: i64 };

// A7.2 (FFI): layout is the JVM ABI's, not ours; waived.
const JniTable = extern struct { slots: [233]?*const anyopaque };
const JniEnv = *const *const JniTable;
// A7.2 (FFI): layout is the JVM ABI's, not ours; waived.
const VmTable = extern struct { slots: [8]?*const anyopaque };
const JavaVm = *const *const VmTable;

const jni_find_class = 6; // FindClass
const jni_exception_clear = 17; // ExceptionClear
const jni_new_object_a = 30; // NewObjectA
const jni_get_object_class = 31; // GetObjectClass
const jni_get_method_id = 33; // GetMethodID
const jni_call_object_method_a = 36; // CallObjectMethodA
const jni_call_void_method_a = 63; // CallVoidMethodA
const jni_call_boolean_method_a = 39; // CallBooleanMethodA
// CallIntMethodA. The table is triples (Call<T>Method / …V / …A) starting at
// Object=34; each group is +3, and the A-variant is base+2: Object(34/36),
// Boolean(37/39), Byte(40/42), Char(43/45), Short(46/48), Int(49/51). So
// CallIntMethodA = 51, NOT 49 (49 is the varargs CallIntMethod). Cross-checked
// against the constants above (36/39) and CallVoidMethodA=63 (Void base 61).
const jni_call_int_method_a = 51; // CallIntMethodA
const jni_get_field_id = 94; // GetFieldID
const jni_get_int_field = 100; // GetIntField
const jni_get_static_method_id = 113; // GetStaticMethodID
const jni_call_static_object_method_a = 116; // CallStaticObjectMethodA
const jni_call_static_int_method_a = 131; // CallStaticIntMethodA
const jni_new_string_utf = 167; // NewStringUTF
const jni_get_string_utf_chars = 169; // GetStringUTFChars
const jni_release_string_utf_chars = 170; // ReleaseStringUTFChars
const jni_exception_check = 228; // ExceptionCheck
const vm_attach_current_thread = 4; // AttachCurrentThread
const vm_detach_current_thread = 5; // DetachCurrentThread

const FindClassFn = *const fn (JniEnv, [*:0]const u8) callconv(.c) jclass;
const GetMethodIdFn = *const fn (JniEnv, jclass, [*:0]const u8, [*:0]const u8) callconv(.c) jmethodID;
const NewStringUtfFn = *const fn (JniEnv, [*:0]const u8) callconv(.c) jstring;
const NewObjectAFn = *const fn (JniEnv, jclass, jmethodID, [*]const jvalue) callconv(.c) jobject;
const GetObjectClassFn = *const fn (JniEnv, jobject) callconv(.c) jclass;
const CallObjectMethodAFn = *const fn (JniEnv, jobject, jmethodID, [*]const jvalue) callconv(.c) jobject;
const CallVoidMethodAFn = *const fn (JniEnv, jobject, jmethodID, [*]const jvalue) callconv(.c) void;
const CallBooleanMethodAFn = *const fn (JniEnv, jobject, jmethodID, [*]const jvalue) callconv(.c) u8;
const CallIntMethodAFn = *const fn (JniEnv, jobject, jmethodID, [*]const jvalue) callconv(.c) i32;
const CallStaticObjectMethodAFn = *const fn (JniEnv, jclass, jmethodID, [*]const jvalue) callconv(.c) jobject;
const CallStaticIntMethodAFn = *const fn (JniEnv, jclass, jmethodID, [*]const jvalue) callconv(.c) i32;
const jfieldID = ?*anyopaque;
const GetFieldIdFn = *const fn (JniEnv, jclass, [*:0]const u8, [*:0]const u8) callconv(.c) jfieldID;
const GetIntFieldFn = *const fn (JniEnv, jobject, jfieldID) callconv(.c) i32;
const GetStringUtfCharsFn = *const fn (JniEnv, jstring, ?*u8) callconv(.c) ?[*:0]const u8;
const ReleaseStringUtfCharsFn = *const fn (JniEnv, jstring, [*:0]const u8) callconv(.c) void;
const ExceptionCheckFn = *const fn (JniEnv) callconv(.c) u8;
const ExceptionClearFn = *const fn (JniEnv) callconv(.c) void;
const AttachFn = *const fn (JavaVm, *JniEnv, ?*anyopaque) callconv(.c) c_int;
const DetachFn = *const fn (JavaVm) callconv(.c) c_int;

fn jniFn(env: JniEnv, comptime idx: usize, comptime F: type) F {
    return @ptrCast(@alignCast(env.*.slots[idx].?));
}

/// True (and clears) if the last JNI call left an exception pending —
/// calling further JNI with one pending is undefined, so every hop checks.
fn jniFailed(env: JniEnv) bool {
    if (jniFn(env, jni_exception_check, ExceptionCheckFn)(env) == 0) return false;
    jniFn(env, jni_exception_clear, ExceptionClearFn)(env);
    return true;
}

/// Look up an instance method on `obj`'s class. Null on any failure.
fn jniMethod(env: JniEnv, obj: jobject, name: [*:0]const u8, sig: [*:0]const u8) jmethodID {
    const cls = jniFn(env, jni_get_object_class, GetObjectClassFn)(env, obj);
    if (jniFailed(env) or cls == null) return null;
    const mid = jniFn(env, jni_get_method_id, GetMethodIdFn)(env, cls, name, sig);
    if (jniFailed(env)) return null;
    return mid;
}

/// CallObjectMethodA with the exception check folded in (null on failure).
fn jniCallObj(env: JniEnv, obj: jobject, mid: jmethodID, args: [*]const jvalue) jobject {
    const r = jniFn(env, jni_call_object_method_a, CallObjectMethodAFn)(env, obj, mid, args);
    if (jniFailed(env)) return null;
    return r;
}

const no_args = [_]jvalue{};

/// Open `url` in the OS browser: startActivity(new Intent(ACTION_VIEW,
/// Uri.parse(url))). Runs on the render thread — attaches it to the JVM for
/// the calls and detaches before returning (an attached thread must never
/// exit attached). Any failure is a logcat line and a no-op: the login flow
/// keeps waiting and an app relaunch retries (E2/E4).
fn openUrlViaOs(activity: *Activity, url: [*:0]const u8) void {
    const vm: JavaVm = @ptrCast(@alignCast(activity.vm));
    var env: JniEnv = undefined;
    const attach: AttachFn = @ptrCast(@alignCast(vm.*.slots[vm_attach_current_thread].?));
    if (attach(vm, &env, null) != 0) {
        seam.logcat("login: JVM attach failed — cannot open the browser", .{});
        return;
    }
    defer _ = @as(DetachFn, @ptrCast(@alignCast(vm.*.slots[vm_detach_current_thread].?)))(vm);

    const find_class = jniFn(env, jni_find_class, FindClassFn);
    const new_string = jniFn(env, jni_new_string_utf, NewStringUtfFn);

    const uri_cls = find_class(env, "android/net/Uri");
    if (jniFailed(env) or uri_cls == null) return seam.logcat("login: Uri class lookup failed", .{});
    const parse_mid = jniFn(env, jni_get_static_method_id, GetMethodIdFn)(env, uri_cls, "parse", "(Ljava/lang/String;)Landroid/net/Uri;");
    if (jniFailed(env) or parse_mid == null) return seam.logcat("login: Uri.parse lookup failed", .{});
    const url_j = new_string(env, url);
    if (jniFailed(env) or url_j == null) return seam.logcat("login: url string failed", .{});
    const uri = jniFn(env, jni_call_static_object_method_a, CallStaticObjectMethodAFn)(env, uri_cls, parse_mid, &[_]jvalue{.{ .l = url_j }});
    if (jniFailed(env) or uri == null) return seam.logcat("login: Uri.parse failed", .{});

    const intent_cls = find_class(env, "android/content/Intent");
    if (jniFailed(env) or intent_cls == null) return seam.logcat("login: Intent class lookup failed", .{});
    const ctor = jniFn(env, jni_get_method_id, GetMethodIdFn)(env, intent_cls, "<init>", "(Ljava/lang/String;Landroid/net/Uri;)V");
    if (jniFailed(env) or ctor == null) return seam.logcat("login: Intent ctor lookup failed", .{});
    const action_j = new_string(env, "android.intent.action.VIEW");
    if (jniFailed(env) or action_j == null) return seam.logcat("login: action string failed", .{});
    const intent = jniFn(env, jni_new_object_a, NewObjectAFn)(env, intent_cls, ctor, &[_]jvalue{ .{ .l = action_j }, .{ .l = uri } });
    if (jniFailed(env) or intent == null) return seam.logcat("login: Intent construction failed", .{});

    const start_mid = jniMethod(env, activity.clazz, "startActivity", "(Landroid/content/Intent;)V");
    if (start_mid == null) return seam.logcat("login: startActivity lookup failed", .{});
    jniFn(env, jni_call_void_method_a, CallVoidMethodAFn)(env, activity.clazz, start_mid, &[_]jvalue{.{ .l = intent }});
    if (jniFailed(env)) return seam.logcat("login: startActivity threw", .{});
    seam.logcat("login: browser opened for the authorize URL", .{});
}

/// Read the launching intent's data URI and, when it is the OAuth scheme,
/// hand it to the seam's armed flow (which lives in the PROCESS-owned ctx,
/// so it survives the activity recreation Android uses to deliver the
/// intent — observed on-device). Main thread, the activity's own env.
fn deliverIntentRedirect(activity: *Activity) bool {
    const env: JniEnv = @ptrCast(@alignCast(activity.env));
    const get_intent = jniMethod(env, activity.clazz, "getIntent", "()Landroid/content/Intent;") orelse return false;
    const intent = jniCallObj(env, activity.clazz, get_intent, &no_args) orelse return false;
    const get_data = jniMethod(env, intent, "getDataString", "()Ljava/lang/String;") orelse return false;
    const data_j = jniCallObj(env, intent, get_data, &no_args) orelse return false;
    const chars = jniFn(env, jni_get_string_utf_chars, GetStringUtfCharsFn)(env, data_j, null) orelse return false;
    defer jniFn(env, jni_release_string_utf_chars, ReleaseStringUtfCharsFn)(env, data_j, chars);
    if (!std.mem.startsWith(u8, std.mem.span(chars), "com.zat4.pds:")) return false;
    if (seam.zat_oauth_redirect(chars)) {
        seam.logcat("login: redirect delivered to the waiting flow", .{});
        return true;
    }
    seam.logcat("login: redirect arrived with no armed flow — dropped", .{});
    return false;
}

/// Show or hide the soft keyboard (the M-UX keyboard leg). NativeActivity
/// has no text widget, so this is the game-engine recipe: ask the
/// InputMethodManager directly, with the decor view as the anchor
/// (SHOW_FORCED — the plain flag is a no-op without a focused editor).
/// Render thread; attach/detach like the browser hop. Failures log and
/// no-op — typing just needs a relaunch, never a crash (E2/E4).
fn imeSetVisible(activity: *Activity, show: bool) void {
    const vm: JavaVm = @ptrCast(@alignCast(activity.vm));
    var env: JniEnv = undefined;
    const attach: AttachFn = @ptrCast(@alignCast(vm.*.slots[vm_attach_current_thread].?));
    if (attach(vm, &env, null) != 0) return;
    defer _ = @as(DetachFn, @ptrCast(@alignCast(vm.*.slots[vm_detach_current_thread].?)))(vm);

    const new_string = jniFn(env, jni_new_string_utf, NewStringUtfFn);
    const call_bool = jniFn(env, jni_call_boolean_method_a, CallBooleanMethodAFn);

    const get_svc = jniMethod(env, activity.clazz, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;") orelse return;
    const svc_name = new_string(env, "input_method");
    if (jniFailed(env) or svc_name == null) return;
    const imm = jniCallObj(env, activity.clazz, get_svc, &[_]jvalue{.{ .l = svc_name }}) orelse return seam.logcat("ime: no InputMethodManager", .{});

    const get_window = jniMethod(env, activity.clazz, "getWindow", "()Landroid/view/Window;") orelse return;
    const window = jniCallObj(env, activity.clazz, get_window, &no_args) orelse return;
    const get_decor = jniMethod(env, window, "getDecorView", "()Landroid/view/View;") orelse return;
    const decor = jniCallObj(env, window, get_decor, &no_args) orelse return;

    if (show) {
        // MODERN PATH (API 30+): WindowInsetsController.show(ime()) — needs no
        // focused editor AND carries no FORCED semantics. The old SHOW_FORCED
        // show marked the IME "user-forced, don't auto-dismiss", which made the
        // system's back-GESTURE dismissal commit as a no-op — the on-device
        // "takes two swipes to close the keyboard" (2026-07-09; a back KEY
        // event still hid it, which is why the adb repro passed first try).
        modern: {
            const gic = jniMethod(env, decor, "getWindowInsetsController", "()Landroid/view/WindowInsetsController;") orelse break :modern;
            const ctrl = jniCallObj(env, decor, gic, &no_args) orelse break :modern;
            const type_cls = jniFn(env, jni_find_class, FindClassFn)(env, "android/view/WindowInsets$Type");
            if (jniFailed(env) or type_cls == null) break :modern;
            const ime_mid = jniFn(env, jni_get_static_method_id, GetMethodIdFn)(env, type_cls, "ime", "()I");
            if (jniFailed(env) or ime_mid == null) break :modern;
            const ime_mask = jniFn(env, jni_call_static_int_method_a, CallStaticIntMethodAFn)(env, type_cls, ime_mid, &no_args);
            if (jniFailed(env)) break :modern;
            const show_mid = jniMethod(env, ctrl, "show", "(I)V") orelse break :modern;
            jniFn(env, jni_call_void_method_a, CallVoidMethodAFn)(env, ctrl, show_mid, &[_]jvalue{.{ .i = ime_mask }});
            if (jniFailed(env)) break :modern;
            seam.logcat("ime: shown (insets controller)", .{});
            return;
        }
        // Fallback (pre-30): the old forced show — better than no keyboard.
        const show_mid = jniMethod(env, imm, "showSoftInput", "(Landroid/view/View;I)Z") orelse return;
        const shown = call_bool(env, imm, show_mid, &[_]jvalue{ .{ .l = decor }, .{ .i = 2 } }); // 2 = SHOW_FORCED
        if (jniFailed(env)) return seam.logcat("ime: showSoftInput threw", .{});
        seam.logcat("ime: show requested (accepted={d})", .{shown});
    } else {
        const get_token = jniMethod(env, decor, "getWindowToken", "()Landroid/os/IBinder;") orelse return;
        const token = jniCallObj(env, decor, get_token, &no_args) orelse return;
        const hide_mid = jniMethod(env, imm, "hideSoftInputFromWindow", "(Landroid/os/IBinder;I)Z") orelse return;
        _ = call_bool(env, imm, hide_mid, &[_]jvalue{ .{ .l = token }, .{ .i = 0 } });
        _ = jniFailed(env);
        seam.logcat("ime: hidden", .{});
    }
}

/// One crisp taptic on the decor view — the gesture system's threshold
/// ticks (pull-to-refresh arming, the drawer latch). performHapticFeedback
/// respects the user's system haptic setting, which is the polite default;
/// failures log and no-op (E2/E4 — a missed tick, never a crash). Render
/// thread; attach/detach like the IME hop.
/// Back at the app's root: Activity.moveTaskToBack(true) steps the task behind
/// the launcher WITHOUT finishing — the process, GL context, and feed stay hot,
/// so returning is instant (the same warm-resume path as Home). Render thread;
/// attach/detach like the other JNI hops; failures log and no-op (E2/E4).
fn moveTaskToBack(activity: *Activity) void {
    const vm: JavaVm = @ptrCast(@alignCast(activity.vm));
    var env: JniEnv = undefined;
    const attach: AttachFn = @ptrCast(@alignCast(vm.*.slots[vm_attach_current_thread].?));
    if (attach(vm, &env, null) != 0) return;
    defer _ = @as(DetachFn, @ptrCast(@alignCast(vm.*.slots[vm_detach_current_thread].?)))(vm);

    const call_bool = jniFn(env, jni_call_boolean_method_a, CallBooleanMethodAFn);
    const mid = jniMethod(env, activity.clazz, "moveTaskToBack", "(Z)Z") orelse return;
    _ = call_bool(env, activity.clazz, mid, &[_]jvalue{.{ .z = 1 }});
    if (jniFailed(env)) return seam.logcat("back: moveTaskToBack threw", .{});
}

/// The IME's current bottom inset in device px (0 = hidden / unavailable).
/// Polled per lap ONLY while the keyboard is up (no JNI hop when hidden), so
/// the chat composer rides above the keyboard as it opens and resizes.
/// Render thread; attach/detach like the other JNI hops; failures read as 0.
fn imeInsetPx(activity: *Activity) i32 {
    const vm: JavaVm = @ptrCast(@alignCast(activity.vm));
    var env: JniEnv = undefined;
    const attach: AttachFn = @ptrCast(@alignCast(vm.*.slots[vm_attach_current_thread].?));
    if (attach(vm, &env, null) != 0) return 0;
    defer _ = @as(DetachFn, @ptrCast(@alignCast(vm.*.slots[vm_detach_current_thread].?)))(vm);
    const get_window = jniMethod(env, activity.clazz, "getWindow", "()Landroid/view/Window;") orelse return 0;
    const window = jniCallObj(env, activity.clazz, get_window, &no_args) orelse return 0;
    const get_decor = jniMethod(env, window, "getDecorView", "()Landroid/view/View;") orelse return 0;
    const decor = jniCallObj(env, window, get_decor, &no_args) orelse return 0;
    const grwi = jniMethod(env, decor, "getRootWindowInsets", "()Landroid/view/WindowInsets;") orelse return 0;
    const wi = jniCallObj(env, decor, grwi, &no_args) orelse return 0;
    const type_cls = jniFn(env, jni_find_class, FindClassFn)(env, "android/view/WindowInsets$Type");
    if (jniFailed(env) or type_cls == null) return 0;
    const ime_mid = jniFn(env, jni_get_static_method_id, GetMethodIdFn)(env, type_cls, "ime", "()I");
    if (jniFailed(env) or ime_mid == null) return 0;
    const mask = jniFn(env, jni_call_static_int_method_a, CallStaticIntMethodAFn)(env, type_cls, ime_mid, &no_args);
    if (jniFailed(env)) return 0;
    const gi_mid = jniMethod(env, wi, "getInsets", "(I)Landroid/graphics/Insets;") orelse return 0;
    const ins = jniCallObj(env, wi, gi_mid, &[_]jvalue{.{ .i = mask }}) orelse return 0;
    const icls = jniFn(env, jni_get_object_class, GetObjectClassFn)(env, ins);
    if (jniFailed(env) or icls == null) return 0;
    const f_bot = jniFn(env, jni_get_field_id, GetFieldIdFn)(env, icls, "bottom", "I");
    if (jniFailed(env) or f_bot == null) return 0;
    const v = jniFn(env, jni_get_int_field, GetIntFieldFn)(env, ins, f_bot);
    if (jniFailed(env)) return 0;
    return v;
}

/// The activity's half of the clipboard seam: resolve the OS
/// ClipboardManager once per call (render-lap rate is copy/paste taps —
/// human-rare). `text` -> setPrimaryClip; read -> the primary clip's first
/// item as UTF-8 handed back through zat_clip_feed.
fn clipboardManager(env: JniEnv, activity: *Activity) jobject {
    const svc = jniFn(env, jni_new_string_utf, NewStringUtfFn)(env, "clipboard");
    if (jniFailed(env) or svc == null) return null;
    const get_svc = jniMethod(env, activity.clazz, "getSystemService", "(Ljava/lang/String;)Ljava/lang/Object;") orelse return null;
    return jniCallObj(env, activity.clazz, get_svc, &[_]jvalue{.{ .l = svc }});
}

fn clipboardSet(activity: *Activity, text: [*:0]const u8) void {
    const vm: JavaVm = @ptrCast(@alignCast(activity.vm));
    var env: JniEnv = undefined;
    const attach: AttachFn = @ptrCast(@alignCast(vm.*.slots[vm_attach_current_thread].?));
    if (attach(vm, &env, null) != 0) return;
    defer _ = @as(DetachFn, @ptrCast(@alignCast(vm.*.slots[vm_detach_current_thread].?)))(vm);
    const cm = clipboardManager(env, activity) orelse return;
    const new_string = jniFn(env, jni_new_string_utf, NewStringUtfFn);
    const label = new_string(env, "zat4");
    const txt = new_string(env, text);
    if (jniFailed(env) or label == null or txt == null) return;
    const clip_cls = jniFn(env, jni_find_class, FindClassFn)(env, "android/content/ClipData");
    if (jniFailed(env) or clip_cls == null) return;
    const new_plain = jniFn(env, jni_get_static_method_id, GetMethodIdFn)(env, clip_cls, "newPlainText", "(Ljava/lang/CharSequence;Ljava/lang/CharSequence;)Landroid/content/ClipData;");
    if (jniFailed(env) or new_plain == null) return;
    const clip = jniFn(env, jni_call_static_object_method_a, CallStaticObjectMethodAFn)(env, clip_cls, new_plain, &[_]jvalue{ .{ .l = label }, .{ .l = txt } });
    if (jniFailed(env) or clip == null) return;
    const set_prim = jniMethod(env, cm, "setPrimaryClip", "(Landroid/content/ClipData;)V") orelse return;
    jniFn(env, jni_call_void_method_a, CallVoidMethodAFn)(env, cm, set_prim, &[_]jvalue{.{ .l = clip }});
    if (jniFailed(env)) seam.logcat("clipboard: setPrimaryClip threw", .{});
}

fn clipboardRead(activity: *Activity, ctx: *anyopaque) void {
    const vm: JavaVm = @ptrCast(@alignCast(activity.vm));
    var env: JniEnv = undefined;
    const attach: AttachFn = @ptrCast(@alignCast(vm.*.slots[vm_attach_current_thread].?));
    if (attach(vm, &env, null) != 0) return;
    defer _ = @as(DetachFn, @ptrCast(@alignCast(vm.*.slots[vm_detach_current_thread].?)))(vm);
    const cm = clipboardManager(env, activity) orelse return;
    const get_clip = jniMethod(env, cm, "getPrimaryClip", "()Landroid/content/ClipData;") orelse return;
    const clip = jniCallObj(env, cm, get_clip, &no_args) orelse return;
    const get_item = jniMethod(env, clip, "getItemAt", "(I)Landroid/content/ClipData$Item;") orelse return;
    const item = jniCallObj(env, clip, get_item, &[_]jvalue{.{ .i = 0 }}) orelse return;
    const get_text = jniMethod(env, item, "getText", "()Ljava/lang/CharSequence;") orelse return;
    const cs = jniCallObj(env, item, get_text, &no_args) orelse return;
    const to_str = jniMethod(env, cs, "toString", "()Ljava/lang/String;") orelse return;
    const jstr = jniCallObj(env, cs, to_str, &no_args) orelse return;
    const chars = jniFn(env, jni_get_string_utf_chars, GetStringUtfCharsFn)(env, jstr, null) orelse return;
    defer jniFn(env, jni_release_string_utf_chars, ReleaseStringUtfCharsFn)(env, jstr, chars);
    seam.zat_clip_feed(ctx, chars, @intCast(std.mem.len(chars)));
}

fn hapticTick(activity: *Activity) void {
    const vm: JavaVm = @ptrCast(@alignCast(activity.vm));
    var env: JniEnv = undefined;
    const attach: AttachFn = @ptrCast(@alignCast(vm.*.slots[vm_attach_current_thread].?));
    if (attach(vm, &env, null) != 0) return;
    defer _ = @as(DetachFn, @ptrCast(@alignCast(vm.*.slots[vm_detach_current_thread].?)))(vm);

    const call_bool = jniFn(env, jni_call_boolean_method_a, CallBooleanMethodAFn);
    const get_window = jniMethod(env, activity.clazz, "getWindow", "()Landroid/view/Window;") orelse return;
    const window = jniCallObj(env, activity.clazz, get_window, &no_args) orelse return;
    const get_decor = jniMethod(env, window, "getDecorView", "()Landroid/view/View;") orelse return;
    const decor = jniCallObj(env, window, get_decor, &no_args) orelse return;
    const perform = jniMethod(env, decor, "performHapticFeedback", "(I)Z") orelse return;
    // 6 = HapticFeedbackConstants.CONTEXT_CLICK (the short, crisp tick).
    _ = call_bool(env, decor, perform, &[_]jvalue{.{ .i = 6 }});
    if (jniFailed(env)) return seam.logcat("haptic: performHapticFeedback threw", .{});
}

/// Read the OS safe-area insets (status bar, nav/home-pill, cutout) off the
/// decor view and hand them to the core via the seam. Also switches the window
/// to edge-to-edge with transparent system bars so the field draws full-bleed.
/// Render thread; attach/detach like the other JNI hops. getRootWindowInsets
/// can transiently return null before the first layout pass — guarded, so it
/// simply retries on the next surface (re)attach. Failures no-op (E2/E4).
fn applyWindowInsets(activity: *Activity, ctx: ?*anyopaque) void {
    const vm: JavaVm = @ptrCast(@alignCast(activity.vm));
    var env: JniEnv = undefined;
    const attach: AttachFn = @ptrCast(@alignCast(vm.*.slots[vm_attach_current_thread].?));
    if (attach(vm, &env, null) != 0) return;
    defer _ = @as(DetachFn, @ptrCast(@alignCast(vm.*.slots[vm_detach_current_thread].?)))(vm);

    const call_void = jniFn(env, jni_call_void_method_a, CallVoidMethodAFn);
    const call_int = jniFn(env, jni_call_int_method_a, CallIntMethodAFn);

    const get_window = jniMethod(env, activity.clazz, "getWindow", "()Landroid/view/Window;") orelse return;
    const window = jniCallObj(env, activity.clazz, get_window, &no_args) orelse return;
    const get_decor = jniMethod(env, window, "getDecorView", "()Landroid/view/View;") orelse return;
    const decor = jniCallObj(env, window, get_decor, &no_args) orelse return;

    // Edge-to-edge: draw behind the system bars, transparent status/nav bars.
    // Each lookup is guarded (API-gated methods no-op on older platforms).
    if (jniMethod(env, window, "setDecorFitsSystemWindows", "(Z)V")) |mid| {
        call_void(env, window, mid, &[_]jvalue{.{ .z = 0 }});
        _ = jniFailed(env);
    }
    if (jniMethod(env, window, "setStatusBarColor", "(I)V")) |mid| {
        call_void(env, window, mid, &[_]jvalue{.{ .i = 0 }}); // transparent
        _ = jniFailed(env);
    }
    if (jniMethod(env, window, "setNavigationBarColor", "(I)V")) |mid| {
        call_void(env, window, mid, &[_]jvalue{.{ .i = 0 }}); // transparent
        _ = jniFailed(env);
    }

    // Insets. MODERN PATH FIRST (API 30+): WindowInsets.getInsets(mask) with
    // statusBars|navigationBars|displayCutout — crucially EXCLUDING ime(). The
    // deprecated getSystemWindowInset* getters FOLD THE SOFT KEYBOARD IN, so a
    // resume that caught the IME (or its dismiss animation) stored a ~940px
    // "bottom inset" and shoved the tab bar to mid-screen (on-device,
    // 2026-07-09). Every JNI miss falls through to the deprecated path.
    const grwi = jniMethod(env, decor, "getRootWindowInsets", "()Landroid/view/WindowInsets;") orelse return;
    const wi = jniCallObj(env, decor, grwi, &no_args) orelse return; // null before first layout → retry next attach

    var top: i32 = -1;
    var bottom: i32 = -1;
    var left: i32 = -1;
    var right: i32 = -1;
    modern: {
        const type_cls = jniFn(env, jni_find_class, FindClassFn)(env, "android/view/WindowInsets$Type");
        if (jniFailed(env) or type_cls == null) break :modern;
        const gsm = jniFn(env, jni_get_static_method_id, GetMethodIdFn);
        const sint = jniFn(env, jni_call_static_int_method_a, CallStaticIntMethodAFn);
        var mask: i32 = 0;
        inline for (.{ "statusBars", "navigationBars", "displayCutout" }) |nm| {
            const mid = gsm(env, type_cls, nm, "()I");
            if (jniFailed(env) or mid == null) break :modern;
            mask |= sint(env, type_cls, mid, &no_args);
            if (jniFailed(env)) break :modern;
        }
        const gi_mid = jniMethod(env, wi, "getInsets", "(I)Landroid/graphics/Insets;") orelse break :modern;
        const ins = jniCallObj(env, wi, gi_mid, &[_]jvalue{.{ .i = mask }}) orelse break :modern;
        const icls = jniFn(env, jni_get_object_class, GetObjectClassFn)(env, ins);
        if (jniFailed(env) or icls == null) break :modern;
        const gfid = jniFn(env, jni_get_field_id, GetFieldIdFn);
        const gint = jniFn(env, jni_get_int_field, GetIntFieldFn);
        // android.graphics.Insets exposes its values as public final int FIELDS.
        const f_top = gfid(env, icls, "top", "I");
        if (jniFailed(env) or f_top == null) break :modern;
        const f_bot = gfid(env, icls, "bottom", "I");
        if (jniFailed(env) or f_bot == null) break :modern;
        const f_left = gfid(env, icls, "left", "I");
        if (jniFailed(env) or f_left == null) break :modern;
        const f_right = gfid(env, icls, "right", "I");
        if (jniFailed(env) or f_right == null) break :modern;
        top = gint(env, ins, f_top);
        bottom = gint(env, ins, f_bot);
        left = gint(env, ins, f_left);
        right = gint(env, ins, f_right);
        if (jniFailed(env)) {
            top = -1; // poisoned mid-read → the deprecated path below re-reads
            break :modern;
        }
    }
    if (top < 0) {
        // Deprecated fallback (pre-API-30): the per-side getters.
        const top_mid = jniMethod(env, wi, "getSystemWindowInsetTop", "()I") orelse return;
        const bot_mid = jniMethod(env, wi, "getSystemWindowInsetBottom", "()I") orelse return;
        const left_mid = jniMethod(env, wi, "getSystemWindowInsetLeft", "()I") orelse return;
        const right_mid = jniMethod(env, wi, "getSystemWindowInsetRight", "()I") orelse return;
        top = call_int(env, wi, top_mid, &no_args);
        bottom = call_int(env, wi, bot_mid, &no_args);
        left = call_int(env, wi, left_mid, &no_args);
        right = call_int(env, wi, right_mid, &no_args);
        if (jniFailed(env)) return;
    }
    // Sanity clamp (both paths): bars/pill/cutout insets are small (≲150 device
    // px on any sane phone). Anything bigger is a transient — an IME mid-dismiss,
    // an animation frame — so SKIP the update and keep the previous good values
    // rather than shoving the whole layout around.
    const inset_cap: i32 = 300;
    if (top > inset_cap or bottom > inset_cap or left > inset_cap or right > inset_cap)
        return seam.logcat("insets: transient skipped (top={d} bottom={d} left={d} right={d})", .{ top, bottom, left, right });
    seam.zat_set_insets(ctx, top, bottom, left, right);
    seam.logcat("insets: top={d} bottom={d} left={d} right={d}", .{ top, bottom, left, right });
}

/// The redirect trampoline (M-And.5). IF the OS ever stacks a fresh
/// activity instance for the VIEW intent while this process already runs a
/// live one, this create must not touch `app` — instead: ferry the intent's
/// data URI to the armed login flow, re-front the app's task (the launcher
/// intent brings the original activity forward), and finish this instance.
/// (On the test device the redirect arrives as a RECREATE — the normal
/// launch path below delivers it — but launch behavior varies by launcher/
/// OEM, so the duplicate-instance case stays handled.) Returns true when
/// this create was such a duplicate.
fn redirectTrampoline(activity: *Activity) bool {
    if (app.thread == null) return false; // no live instance: a normal launch
    const env: JniEnv = @ptrCast(@alignCast(activity.env));

    const delivered = deliverIntentRedirect(activity);

    // Re-front the original task ONLY when this create actually carried the
    // OAuth redirect (our task may sit behind the browser's, so the launcher
    // intent brings it forward). A duplicate MAIN/LAUNCHER create — the
    // launcher CAN stack a fresh instance on the live task (seen on the Pixel
    // right after an app-freezer unfreeze, 2026-07-09) — must NOT fire it:
    // launchMode is standard, so the launch intent stacks yet another
    // instance, every new create trampolines again, and ActivityManager kills
    // the app for rapidActivityLaunch (the on-device "zones crash"; the
    // stacked duplicates also ate taps — their input queues are never wired).
    // Finishing the duplicate is enough there: the original activity beneath
    // the same task resumes by itself.
    if (delivered) blk: {
        const get_pm = jniMethod(env, activity.clazz, "getPackageManager", "()Landroid/content/pm/PackageManager;") orelse break :blk;
        const pm = jniCallObj(env, activity.clazz, get_pm, &no_args) orelse break :blk;
        const get_pkg = jniMethod(env, activity.clazz, "getPackageName", "()Ljava/lang/String;") orelse break :blk;
        const pkg = jniCallObj(env, activity.clazz, get_pkg, &no_args) orelse break :blk;
        const get_launch = jniMethod(env, pm, "getLaunchIntentForPackage", "(Ljava/lang/String;)Landroid/content/Intent;") orelse break :blk;
        const launch_intent = jniCallObj(env, pm, get_launch, &[_]jvalue{.{ .l = pkg }}) orelse break :blk;
        const start_mid = jniMethod(env, activity.clazz, "startActivity", "(Landroid/content/Intent;)V") orelse break :blk;
        jniFn(env, jni_call_void_method_a, CallVoidMethodAFn)(env, activity.clazz, start_mid, &[_]jvalue{.{ .l = launch_intent }});
        _ = jniFailed(env);
    }
    seam.logcat("trampoline: duplicate create (redirect={}) — finishing it", .{delivered});

    // Dismiss the duplicate instance. Its callbacks were never wired, so
    // the teardown that follows touches nothing of ours.
    if (jniMethod(env, activity.clazz, "finish", "()V")) |fin| {
        jniFn(env, jni_call_void_method_a, CallVoidMethodAFn)(env, activity.clazz, fin, &no_args);
        _ = jniFailed(env);
    }
    return true;
}

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
    /// The live activity (M-And.5: the render thread's JNI door for the
    /// browser launch). Set in onCreate before the thread spawns; onDestroy
    /// JOINS the render thread before the pointer dies, so no use races
    /// the teardown.
    activity: ?*Activity = null,
    /// M-And.5: this create carried no redirect — if a login flow is still
    /// waiting, re-offer its authorize URL so this instance reopens the
    /// browser (set in onCreate; consumed once by the render thread).
    reoffer_login: bool = false,
};

var app: App = .{};

/// The seam context is PROCESS-owned, not activity-owned (created by the
/// first render thread, never shut down): Android freely DESTROYS and
/// RECREATES the activity — including to deliver the OAuth redirect intent
/// (observed on-device: the redirect arrives as a recreate, not as a second
/// instance) — and everything durable (the parked feed's RunState, the
/// armed login flow) must survive that. The activity is a surface pump; the
/// ctx is the app. The OS reclaims it at process death (suspend persists
/// the store + tokens at every surface loss, so nothing is lost).
var g_ctx: ?*anyopaque = null;

fn renderThread() void {
    const ctx = g_ctx orelse blk: {
        const c = seam.zat_init(1080, 2400, cell_px) orelse return;
        g_ctx = c;
        break :blk c;
    };

    var attached_gen: u32 = 0;
    // The FEED leg (MC.4d): attempted once per surface attach — a false
    // (no cached session / bring-up failure) leaves the field-only render
    // for that surface, never a dead screen (E2). While live, the loop is
    // zat_feed_step (one frame per vsync; the swap inside paces it) and
    // the field-only step/render pair rests.
    var feed_live = false;
    // M-And.4: a surface bounce PARKS the feed (store/session/workers/
    // scroll stay hot; only the GL leg is released) and the next surface
    // resumes it — lock/unlock and backgrounding no longer reset the feed.
    // A recreated ACTIVITY hands its ctx to a fresh render thread, so ask
    // the seam whether the previous thread left a parked feed behind.
    var feed_parked = seam.zat_feed_parked(ctx);
    var feed_errs: u32 = 0;
    var ime_shown = false;
    var last_ns: u64 = clock.monotonicNanos();
    if (app.reoffer_login) seam.zat_login_reoffer(ctx); // fresh instance, waiting flow → browser again

    while (app.running.load(.acquire)) {
        // Snapshot the UI-thread-owned state.
        app.mutex.lock();
        const win = app.window;
        const gen = app.window_gen;
        const queue = app.queue;
        app.mutex.unlock();

        // Surface choreography (M-And.4): attach on a new generation,
        // detach + ack when the window went away. A dying surface PARKS a
        // live feed — zat_feed_suspend persists (kill insurance) and
        // releases the GL leg while the RunState stays hot; the next
        // surface RESUMES it in place (scroll intact), falling back to the
        // full restart-from-cache path only if the resume refuses.
        if (win == null) {
            if (attached_gen != 0) {
                if (feed_live) {
                    seam.zat_feed_suspend(ctx);
                    feed_live = false;
                    feed_parked = true;
                }
                seam.zat_surface_lost(ctx);
                attached_gen = 0;
            }
            // ALWAYS ack a dead window, attached or not — a surface can be
            // created and destroyed before this thread ever attached (a
            // launch into a sleeping screen), and a gen-gated ack left the
            // main thread spinning in onNativeWindowDestroyed forever (the
            // exact ANR the first doze exposed). The ack is idempotent.
            app.detach_ack.store(gen, .release);
        } else if (win != null and attached_gen != gen) {
            const w: u32 = @intCast(@max(1, ANativeWindow_getWidth(win.?)));
            const h: u32 = @intCast(@max(1, ANativeWindow_getHeight(win.?)));
            if (feed_parked and seam.zat_feed_resume(ctx, @ptrCast(win.?), w, h)) {
                attached_gen = gen;
                feed_parked = false;
                feed_live = true;
                feed_errs = 0;
            } else {
                if (feed_parked) {
                    // The parked feed refused the new surface — tear down
                    // to the restart path (the suspend already persisted).
                    seam.zat_feed_end(ctx);
                    feed_parked = false;
                }
                if (seam.zat_surface(ctx, @ptrCast(win.?), w, h)) {
                    _ = seam.zat_resize(ctx, w, h);
                    attached_gen = gen;
                    feed_live = seam.zat_feed_start(ctx, &app.files_dir);
                    feed_errs = 0;
                }
            }
            // Edge-to-edge + safe-area insets: (re)read on every attach so a
            // rotation/fold (a fresh gen re-enters this branch) refreshes them.
            if (attached_gen == gen) {
                if (app.activity) |act| applyWindowInsets(act, ctx);
            }
        }

        // M-And.5: ferry the on-device sign-in. The seam surfaces the
        // authorize URL exactly once — open it in the OS browser; when the
        // flow lands a session (the trampoline delivered the redirect and
        // the token exchange finished), start the feed through the same
        // front door the cached-session path uses.
        if (!feed_live and !feed_parked) {
            if (app.activity) |act| {
                if (seam.zat_login_url(ctx)) |u| openUrlViaOs(act, u);
            }
            if (attached_gen != 0 and seam.zat_login_ready(ctx)) {
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
                    const action_raw = AMotionEvent_getAction(e);
                    const action = action_raw & action_mask;
                    // A SECOND finger landing (two-thumb typing): forward it
                    // as its own kind with ITS pointer's coordinates — the
                    // pump press-commits the key and otherwise ignores it.
                    if (action == action_pointer_down or action == action_pointer_up) {
                        const pidx: usize = @intCast((action_raw >> action_pointer_index_shift) & 0xff);
                        seam.zat_touch(ctx, if (action == action_pointer_down) 5 else 6, AMotionEvent_getX(e, pidx), AMotionEvent_getY(e, pidx));
                        AInputQueue_finishEvent(q, e, 1);
                        continue;
                    }
                    const kind: u32 = switch (action) {
                        action_down => 0,
                        action_move => 1,
                        action_up => 2,
                        // CANCEL is forwarded too: the system claims the touch
                        // stream mid-gesture (the back edge, the shade) and the
                        // machine must RESET — dropped, it left a phantom finger
                        // (down with no up) in the pump's state.
                        action_cancel => 3,
                        else => 4,
                    };
                    if (kind != 4) {
                        seam.zat_touch(ctx, kind, AMotionEvent_getX(e, 0), AMotionEvent_getY(e, 0));
                        handled = 1;
                    }
                } else if (AInputEvent_getType(e) == input_event_type_key) {
                    // BACK (the system edge swipe / back button — the manifest
                    // leaves enableOnBackInvokedCallback off, so it arrives as
                    // this key event): route it to the app's own navigation pop
                    // and CONSUME both halves — unhandled, the framework's
                    // default finishes the activity (the "back exits the app"
                    // complaint). Back-at-root minimizes via the poll below.
                    if (AKeyEvent_getKeyCode(e) == akeycode_back) {
                        if (AKeyEvent_getAction(e) == key_action_down) seam.zat_back(ctx);
                        handled = 1;
                    } else if (AKeyEvent_getAction(e) == key_action_down) {
                        // The soft keyboard's KeyEvent fallback (M-UX keyboard
                        // leg). Mapped keys feed the composer; other unmapped
                        // ones (volume, …) stay the system's.
                        if (keyCodepoint(AKeyEvent_getKeyCode(e), AKeyEvent_getMetaState(e))) |cp| {
                            seam.zat_key(ctx, cp);
                            handled = 1;
                        }
                    }
                }
                AInputQueue_finishEvent(q, e, handled);
            }
        }

        // The M-UX keyboard leg: summon/dismiss the IME on the frame's word
        // (the composer opening/closing flips it).
        if (feed_live) {
            const want_ime = seam.zat_ime_wanted(ctx);
            if (want_ime != ime_shown) {
                if (app.activity) |act| imeSetVisible(act, want_ime);
                ime_shown = want_ime;
            }
            // The gesture system's threshold ticks (drawer latch,
            // pull-to-refresh arm) land as one taptic each.
            {
                // The clipboard seam: copy/cut out, paste's read back in.
                var clen: u32 = 0;
                if (seam.zat_clip_take(ctx, &clen)) |cp| {
                    if (clen > 0 and clen < 1024) {
                        var zbuf: [1024]u8 = undefined;
                        @memcpy(zbuf[0..clen], cp[0..clen]);
                        zbuf[clen] = 0;
                        if (app.activity) |act| clipboardSet(act, zbuf[0..clen :0]);
                    }
                }
                if (seam.zat_clip_want(ctx) != 0) {
                    if (app.activity) |act| clipboardRead(act, ctx);
                }
            }
            if (seam.zat_haptic(ctx) != 0) {
                if (app.activity) |act| hapticTick(act);
            }
            // Back popped at the ROOT (Home, nothing open): step the task
            // back to the launcher — the Android convention. Never finish():
            // the process + feed stay hot for an instant return.
            if (seam.zat_minimize(ctx)) {
                if (app.activity) |act| moveTaskToBack(act);
            }
            // The keyboard's live inset: polled while it is up so the chat
            // composer rides ABOVE it (it used to be covered — typing blind).
            // No JNI hop while hidden; 0 clears the lift.
            if (app.activity) |act| {
                seam.zat_set_ime_inset(ctx, if (ime_shown) imeInsetPx(act) else 0);
            }
        } else if (ime_shown) {
            if (app.activity) |act| imeSetVisible(act, false);
            ime_shown = false;
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
        if (feed_parked) {
            // Backgrounded with a parked feed: fully idle — no sim, no
            // render — until a surface arrives or the activity ends.
            last_ns = clock.monotonicNanos();
            clock.sleepMillis(50);
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
    // Thread exit = the ACTIVITY died, not the app: PARK a live feed
    // (persist + release the GL leg; RunState and the login flow stay hot
    // in the process-owned ctx) — a recreated activity's thread resumes it.
    // Nothing is ended: at process death the OS reclaims, and the suspend
    // already persisted the store + rotated tokens.
    if (feed_live) seam.zat_feed_suspend(ctx);
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
    app.activity = null; // the pointer dies when this returns
}

// stderr → logcat: a Zig panic in this fork prints its message + trace to
// stderr and exits — which on Android is a SILENT death (fd 2 goes
// nowhere). Route fd 2 (and 1) through a pipe into the log so every panic
// names itself in `adb logcat -s zat4-stderr`.
extern "log" fn __android_log_write(prio: c_int, tag: [*:0]const u8, text: [*:0]const u8) c_int;

fn stderrPump(read_fd: std.c.fd_t) void {
    var buf: [512]u8 = undefined;
    var line: [512]u8 = undefined;
    var line_len: usize = 0;
    while (true) {
        const n = std.c.read(read_fd, &buf, buf.len);
        if (n <= 0) return;
        for (buf[0..@intCast(n)]) |c| {
            if (c == '\n' or line_len == line.len - 1) {
                line[line_len] = 0;
                _ = __android_log_write(6, "zat4-stderr", line[0..line_len :0]); // 6 = ERROR
                line_len = 0;
                if (c != '\n') {
                    line[0] = c;
                    line_len = 1;
                }
            } else {
                line[line_len] = c;
                line_len += 1;
            }
        }
    }
}

var stderr_routed = false; // once per PROCESS — a recreated activity reuses the pipe

fn routeStderrToLogcat() void {
    // libc-only plumbing: the pure (no-libc) build has neither pipe nor
    // liblog — and nothing prints there anyway (the feed leg is NDK-only).
    if (comptime !@import("mobile_config").have_gpu) return;
    if (stderr_routed) return;
    stderr_routed = true;
    var fds: [2]std.c.fd_t = undefined;
    if (std.c.pipe(&fds) != 0) return;
    if (std.c.dup2(fds[1], 2) < 0) return;
    if (std.c.dup2(fds[1], 1) < 0) return;
    const t = std.Thread.spawn(.{}, stderrPump, .{fds[0]}) catch return;
    t.detach();
}

/// The framework's entry point (looked up by name in the library that
/// android.app.lib_name names). Wire the callbacks, start the one thread.
/// A second create in a live process is the OAuth redirect trampoline
/// (M-And.5) — handled and dismissed before any of this state is touched.
export fn ANativeActivity_onCreate(activity: *Activity, saved: ?*anyopaque, saved_len: usize) void {
    _ = saved;
    _ = saved_len;
    if (redirectTrampoline(activity)) return;
    routeStderrToLogcat();
    activity.callbacks.onNativeWindowCreated = onNativeWindowCreated;
    activity.callbacks.onNativeWindowDestroyed = onNativeWindowDestroyed;
    activity.callbacks.onInputQueueCreated = onInputQueueCreated;
    activity.callbacks.onInputQueueDestroyed = onInputQueueDestroyed;
    activity.callbacks.onDestroy = onDestroy;
    app = .{};
    app.activity = activity;
    // A recreate can BE the redirect delivery (Android tears the activity
    // down and hands the VIEW intent to the new instance); the armed flow
    // survived in the process-owned ctx — feed it before the thread spins.
    // A recreate WITHOUT a redirect while a flow waits re-offers the
    // browser instead (the user gets the sign-in page back, not a dead
    // field); the render thread acts on the flag once the ctx exists.
    app.reoffer_login = !deliverIntentRedirect(activity);
    // The app's private files dir — the cache root the feed leg needs
    // (MC.4d). Copied before the thread spawns; the activity's own string
    // may not outlive us.
    const path = std.mem.span(activity.internalDataPath);
    const n = @min(path.len, app.files_dir.len);
    @memcpy(app.files_dir[0..n], path[0..n]);
    app.files_dir[n] = 0;
    app.thread = std.Thread.spawn(.{}, renderThread, .{}) catch null;
}
