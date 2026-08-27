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

//! B1 classification: SHELL. Decoding a photograph, through the platform.
//!
//! WHY THE PLATFORM AND NOT A VENDORED DECODER. The bytes are
//! ATTACKER-CONTROLLED: anybody who can message you can hand this device a
//! JPEG. `stb_image` is one public-domain file with no transitive dependencies —
//! the same bar `stb_truetype` was accepted on (F1) — but its own documentation
//! disclaims bounds-checking on untrusted input, and the justification written
//! for stb_truetype rests explicitly on the fact that this app SHIPS ITS OWN
//! FONTS and never loads a user's. A photo from a stranger is the exact opposite
//! case, and it is the shape image-decoder CVEs come in.
//!
//! So: `BitmapFactory.decodeByteArray` through JNI, then
//! `AndroidBitmap_lockPixels` (libjnigraphics) for the pixels. Hardened,
//! sandboxed, and maintained by people whose job it is.
//!
//! The whole thing is fail-closed: every step that can fail answers null, and a
//! null is an ordinary result (E4) meaning "this did not decode" — never a
//! partially-filled buffer, which is the one outcome a renderer must never see.

const std = @import("std");
const Allocator = std.mem.Allocator;
const builtin = @import("builtin");

/// The JavaVM, stashed by the activity at create. Decoding happens on the render
/// thread, which is not the UI thread, so every call attaches and detaches — the
/// same discipline every other JNI hop in this codebase follows.
pub var vm_handle: ?*anyopaque = null;

// --- JNI, the same hand-matched slots the activity uses ----------------------

// A7.2 (FFI): every layout below is the JNI ABI's, not zat's. An exact guard
// would assert a foreign contract we do not control and could not change if it
// failed — it would pin the JVM, not our discipline. Waived, as the same shapes
// are in android_activity.zig.
const VmTable = extern struct { slots: [8]?*anyopaque };
const JavaVm = *const *const VmTable;
// A7.2 (FFI): the JNI function table — size guard waived, see above.
const JniTable = extern struct { slots: [256]?*anyopaque };
const JniEnv = *const *const JniTable;
const jobject = ?*anyopaque;
const jclass = jobject;
const jmethodID = ?*anyopaque;
// A7.2 (FFI): the JNI argument union — size guard waived, see above.
const jvalue = extern union { z: u8, b: i8, c: u16, s: i16, i: i32, j: i64, f: f32, d: f64, l: jobject };

const vm_attach = 4;
const vm_detach = 5;

const jni_find_class = 6;
const jni_new_object_a = 30;
const jni_get_method_id = 33;
const jni_call_object_method_a = 36;
const jni_call_int_method_a = 51;
const jni_get_static_method_id = 113;
const jni_call_static_object_method_a = 116;
const jni_new_byte_array = 176;
const jni_set_byte_array_region = 208;
const jni_exception_check = 228;
const jni_exception_clear = 17;
const jni_delete_local_ref = 23;

const AttachFn = *const fn (JavaVm, *JniEnv, ?*anyopaque) callconv(.c) c_int;
const DetachFn = *const fn (JavaVm) callconv(.c) c_int;
const FindClassFn = *const fn (JniEnv, [*:0]const u8) callconv(.c) jclass;
const GetMethodIdFn = *const fn (JniEnv, jclass, [*:0]const u8, [*:0]const u8) callconv(.c) jmethodID;
const CallObjectAFn = *const fn (JniEnv, jobject, jmethodID, [*]const jvalue) callconv(.c) jobject;
const CallStaticObjectAFn = *const fn (JniEnv, jclass, jmethodID, [*]const jvalue) callconv(.c) jobject;
const CallIntAFn = *const fn (JniEnv, jobject, jmethodID, [*]const jvalue) callconv(.c) i32;
const NewByteArrayFn = *const fn (JniEnv, i32) callconv(.c) jobject;
const SetByteRegionFn = *const fn (JniEnv, jobject, i32, i32, [*]const i8) callconv(.c) void;
const ExceptionCheckFn = *const fn (JniEnv) callconv(.c) u8;
const ExceptionClearFn = *const fn (JniEnv) callconv(.c) void;
const DeleteLocalRefFn = *const fn (JniEnv, jobject) callconv(.c) void;

fn jniFn(env: JniEnv, slot: usize, comptime T: type) T {
    return @ptrCast(@alignCast(env.*.*.slots[slot].?));
}

fn threw(env: JniEnv) bool {
    const check = jniFn(env, jni_exception_check, ExceptionCheckFn);
    if (check(env) == 0) return false;
    jniFn(env, jni_exception_clear, ExceptionClearFn)(env);
    return true;
}

// --- libjnigraphics: the pixels, natively ------------------------------------

/// A7.2 (FFI): libjnigraphics' own struct — size guard waived, see above.
const AndroidBitmapInfo = extern struct {
    width: u32,
    height: u32,
    stride: u32,
    format: i32,
    flags: u32,
};

/// RGBA_8888. The only format asked for, so the only one handled — a decoder
/// that quietly accepts three layouts is three chances to read a picture wrong.
const android_bitmap_format_rgba_8888: i32 = 1;

extern fn AndroidBitmap_getInfo(env: JniEnv, bmp: jobject, info: *AndroidBitmapInfo) callconv(.c) c_int;
extern fn AndroidBitmap_lockPixels(env: JniEnv, bmp: jobject, addr: *?*anyopaque) callconv(.c) c_int;
extern fn AndroidBitmap_unlockPixels(env: JniEnv, bmp: jobject) callconv(.c) c_int;

/// A decoded picture. `rgba` is gpa-owned, tightly packed (no stride padding),
/// and exactly `width * height * 4` bytes.
/// A7.2: cold, one per picture decoded.
pub const Decoded = struct {
    rgba: []u8,
    width: u32,
    height: u32,

    pub fn deinit(d: *Decoded, gpa: Allocator) void {
        gpa.free(d.rgba);
        d.* = undefined;
    }
};

/// The largest picture we will hold decoded, in PIXELS. A 4000×3000 photo is 48
/// MB of RGBA — a phone will not thank us, and a sender who picked the dimensions
/// should not get to choose our allocation. Refused rather than clamped: a
/// silently downscaled picture is a picture that does not match what was sent.
pub const max_pixels: u64 = 4096 * 4096;

/// Decode `bytes` to RGBA, or null if anything at all goes wrong.
pub fn decode(gpa: Allocator, bytes: []const u8) ?Decoded {
    if (comptime builtin.os.tag != .linux) return null; // Android is a linux target
    if (bytes.len == 0 or bytes.len > std.math.maxInt(i32)) return null;
    const vm: JavaVm = @ptrCast(@alignCast(vm_handle orelse return null));

    var env: JniEnv = undefined;
    const attach: AttachFn = @ptrCast(@alignCast(vm.*.slots[vm_attach].?));
    if (attach(vm, &env, null) != 0) return null;
    defer _ = @as(DetachFn, @ptrCast(@alignCast(vm.*.slots[vm_detach].?)))(vm);

    const del = jniFn(env, jni_delete_local_ref, DeleteLocalRefFn);

    // The encoded bytes, into a Java byte[].
    const arr = jniFn(env, jni_new_byte_array, NewByteArrayFn)(env, @intCast(bytes.len));
    if (threw(env) or arr == null) return null;
    defer del(env, arr);
    jniFn(env, jni_set_byte_array_region, SetByteRegionFn)(env, arr, 0, @intCast(bytes.len), @ptrCast(bytes.ptr));
    if (threw(env)) return null;

    const bf_cls = jniFn(env, jni_find_class, FindClassFn)(env, "android/graphics/BitmapFactory");
    if (threw(env) or bf_cls == null) return null;
    defer del(env, bf_cls);
    const decode_mid = jniFn(env, jni_get_static_method_id, GetMethodIdFn)(
        env,
        bf_cls,
        "decodeByteArray",
        "([BII)Landroid/graphics/Bitmap;",
    );
    if (threw(env) or decode_mid == null) return null;

    // THE DECODE ITSELF, inside the platform. A malformed or hostile file comes
    // back as a null Bitmap rather than as our problem.
    const bmp = jniFn(env, jni_call_static_object_method_a, CallStaticObjectAFn)(env, bf_cls, decode_mid, &[_]jvalue{
        .{ .l = arr }, .{ .i = 0 }, .{ .i = @intCast(bytes.len) },
    });
    if (threw(env) or bmp == null) return null;
    defer del(env, bmp);

    var info: AndroidBitmapInfo = undefined;
    if (AndroidBitmap_getInfo(env, bmp, &info) != 0) return null;
    if (info.format != android_bitmap_format_rgba_8888) return null;
    if (info.width == 0 or info.height == 0) return null;
    if (@as(u64, info.width) * info.height > max_pixels) return null;

    var addr: ?*anyopaque = null;
    if (AndroidBitmap_lockPixels(env, bmp, &addr) != 0) return null;
    const src_ptr: [*]const u8 = @ptrCast(addr orelse return null);
    defer _ = AndroidBitmap_unlockPixels(env, bmp);

    const row_bytes = @as(usize, info.width) * 4;
    const out = gpa.alloc(u8, row_bytes * info.height) catch return null;
    // COPIED ROW BY ROW, because a Bitmap's stride is not its width: rows are
    // padded for alignment, and taking the buffer whole would shear the picture
    // by a few pixels more on every line.
    var y: usize = 0;
    while (y < info.height) : (y += 1) {
        const src = src_ptr[y * info.stride ..][0..row_bytes];
        @memcpy(out[y * row_bytes ..][0..row_bytes], src);
    }
    return .{ .rgba = out, .width = info.width, .height = info.height };
}
