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

//! B1 classification: SHELL. The OS keystore for secrets AT REST (Phase 4).
//!
//! Linux backend: the freedesktop Secret Service via `libsecret-1.so.0`, loaded
//! with `dlopen` — the same GL-loader doctrine the GPU backend uses (no `-dev`
//! package, only libc linked). When the keyring is absent or non-functional,
//! every call fails cleanly and `cache.zig` falls back to its 0600 file, so the
//! app still works; the keystore is a hardening, never a hard dependency. macOS
//! Keychain / Windows Credential Manager are the cross-platform follow-ups
//! behind this same `put`/`get`/`del` interface (F4: one backend until a second
//! platform needs it).
//!
//! The Secret Service stores a secret as a C STRING, so a binary session blob is
//! base64'd in and out (NUL-clean, text-safe). `put` STORES, then READS BACK and
//! compares before reporting success — so a loaded-but-broken keyring can never
//! trick the caller into deleting its plaintext fallback and losing the session.

const std = @import("std");
const Allocator = std.mem.Allocator;

extern fn dlopen(path: [*:0]const u8, mode: c_int) callconv(.c) ?*anyopaque;
extern fn dlsym(handle: ?*anyopaque, symbol: [*:0]const u8) callconv(.c) ?*anyopaque;
const RTLD_NOW: c_int = 2;

// --- libsecret ABI (matched by hand — no headers; see secret-schema.h) ------

/// `SecretSchemaAttribute`: a name + a type tag (STRING = 0). A7.2: cold,
/// size guard waived — ABI-fixed C struct, two per process.
const SchemaAttr = extern struct { name: ?[*:0]const u8, attr_type: c_int };

/// `SecretSchema`: name + flags + a NULL-name-terminated attribute array, then
/// libsecret's private reserved tail (included so the struct SIZE matches the
/// ABI; libsecret never reads these). A7.2: cold, size guard waived — one static
/// instance, never in a hot path.
const Schema = extern struct {
    name: [*:0]const u8,
    flags: c_int,
    attributes: [32]SchemaAttr,
    reserved: c_int = 0,
    reserved1: ?*anyopaque = null,
    reserved2: ?*anyopaque = null,
    reserved3: ?*anyopaque = null,
    reserved4: ?*anyopaque = null,
    reserved5: ?*anyopaque = null,
    reserved6: ?*anyopaque = null,
    reserved7: ?*anyopaque = null,
};

/// One schema, one string attribute "key" (the only thing we match on). Stores
/// and lookups use the same schema, so they pair up. flags = SECRET_SCHEMA_NONE.
const schema: Schema = blk: {
    var a = [_]SchemaAttr{.{ .name = null, .attr_type = 0 }} ** 32;
    a[0] = .{ .name = "key", .attr_type = 0 }; // SECRET_SCHEMA_ATTRIBUTE_STRING
    break :blk .{ .name = "com.zat4.Session", .flags = 0, .attributes = a };
};

// The four sync entry points (variadic: trailing attribute name/value pairs end
// with a NULL). gboolean == c_int; gchar* == [*:0]u8; GError** == *?*anyopaque.
const StoreFn = *const fn (*const Schema, ?[*:0]const u8, [*:0]const u8, [*:0]const u8, ?*anyopaque, *?*anyopaque, ...) callconv(.c) c_int;
const LookupFn = *const fn (*const Schema, ?*anyopaque, *?*anyopaque, ...) callconv(.c) ?[*:0]u8;
const ClearFn = *const fn (*const Schema, ?*anyopaque, *?*anyopaque, ...) callconv(.c) c_int;
const FreeFn = *const fn (?[*:0]u8) callconv(.c) void;
const ErrFreeFn = *const fn (?*anyopaque) callconv(.c) void;

/// Resolved entry points. A7.2: cold, size guard waived — one cached instance.
const Lib = struct {
    store: StoreFn,
    lookup: LookupFn,
    clear: ClearFn,
    free: FreeFn,
    err_free: ?ErrFreeFn, // g_error_free (best-effort; null → leak a GError on the rare error path)
};

// Lazily resolved once. Shell-local process state for a dlopen'd library — the
// standard loader pattern (the GPU backend caches its handles likewise); session
// save/load is main-thread and rare, so no synchronization is needed.
var cached: ?Lib = null;
var tried: bool = false;

fn load() ?Lib {
    if (cached) |l| return l;
    if (tried) return null;
    tried = true;
    const lib = dlopen("libsecret-1.so.0", RTLD_NOW) orelse return null;
    const store = dlsym(lib, "secret_password_store_sync") orelse return null;
    const lookup = dlsym(lib, "secret_password_lookup_sync") orelse return null;
    const clear = dlsym(lib, "secret_password_clear_sync") orelse return null;
    const free = dlsym(lib, "secret_password_free") orelse return null;
    var err_free: ?ErrFreeFn = null;
    if (dlopen("libglib-2.0.so.0", RTLD_NOW)) |glib| {
        if (dlsym(glib, "g_error_free")) |p| err_free = @ptrCast(@alignCast(p));
    }
    cached = .{
        .store = @ptrCast(@alignCast(store)),
        .lookup = @ptrCast(@alignCast(lookup)),
        .clear = @ptrCast(@alignCast(clear)),
        .free = @ptrCast(@alignCast(free)),
        .err_free = err_free,
    };
    return cached;
}

/// True if a Secret Service backend is loadable at all (the .so resolves). Does
/// not prove the keyring is unlocked/functional — `put`'s readback proves that.
pub fn available() bool {
    return load() != null;
}

/// Store `blob` under `key` (base64'd), then read it back and confirm it
/// round-trips. Returns true ONLY on a verified store — the caller may then
/// safely drop any plaintext fallback. Any failure (no keyring, locked, error)
/// → false, and the caller keeps its fallback.
pub fn put(gpa: Allocator, key: []const u8, blob: []const u8) bool {
    const lib = load() orelse return false;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const Enc = std.base64.standard.Encoder;
    const b64 = arena.allocSentinel(u8, Enc.calcSize(blob.len), 0) catch return false;
    _ = Enc.encode(b64, blob);
    const key_z = arena.dupeZ(u8, key) catch return false;

    var gerr: ?*anyopaque = null;
    const ok = lib.store(&schema, null, key_z.ptr, b64.ptr, null, &gerr, @as(?[*:0]const u8, "key"), @as(?[*:0]const u8, key_z.ptr), @as(?[*:0]const u8, null));
    if (gerr) |e| {
        if (lib.err_free) |f| f(e);
        return false;
    }
    if (ok == 0) return false;

    // Readback verification — the safety that lets the caller delete plaintext.
    const got = get(gpa, key) orelse return false;
    defer gpa.free(got);
    return std.mem.eql(u8, got, blob);
}

/// Fetch the blob stored under `key` (gpa-owned), or null if absent / no keyring.
pub fn get(gpa: Allocator, key: []const u8) ?[]u8 {
    const lib = load() orelse return null;
    var key_buf: [256]u8 = undefined;
    if (key.len >= key_buf.len) return null;
    @memcpy(key_buf[0..key.len], key);
    key_buf[key.len] = 0;
    const key_z: [*:0]const u8 = @ptrCast(&key_buf);

    var gerr: ?*anyopaque = null;
    const pw = lib.lookup(&schema, null, &gerr, @as(?[*:0]const u8, "key"), @as(?[*:0]const u8, key_z), @as(?[*:0]const u8, null));
    if (gerr) |e| {
        if (lib.err_free) |f| f(e);
        return null;
    }
    const pw_ptr = pw orelse return null; // not found
    defer lib.free(pw);

    const b64 = std.mem.span(pw_ptr);
    const Dec = std.base64.standard.Decoder;
    const dec_len = Dec.calcSizeForSlice(b64) catch return null;
    const out = gpa.alloc(u8, dec_len) catch return null;
    Dec.decode(out, b64) catch {
        gpa.free(out);
        return null;
    };
    return out;
}

/// Remove the secret stored under `key` (best-effort; a no-op if absent).
pub fn del(key: []const u8) void {
    const lib = load() orelse return;
    var key_buf: [256]u8 = undefined;
    if (key.len >= key_buf.len) return;
    @memcpy(key_buf[0..key.len], key);
    key_buf[key.len] = 0;
    const key_z: [*:0]const u8 = @ptrCast(&key_buf);

    var gerr: ?*anyopaque = null;
    _ = lib.clear(&schema, null, &gerr, @as(?[*:0]const u8, "key"), @as(?[*:0]const u8, key_z), @as(?[*:0]const u8, null));
    if (gerr) |e| {
        if (lib.err_free) |f| f(e);
    }
}

// ---------------------------------------------------------------------------
// Test — a real round trip through the Secret Service IF one is present. On a
// machine with no keyring (CI), `put` returns false and the test SKIPS, so the
// suite stays green everywhere; on a desktop with gnome-keyring it actually
// exercises store → readback → fetch → delete (C6, no leaks).
// ---------------------------------------------------------------------------

test "keystore: round trip through the live Secret Service, or skip if absent" {
    const gpa = std.testing.allocator;
    if (!available()) return; // no libsecret → fallback path is cache.zig's job

    const key = "zat4-keystore-selftest";
    const blob = [_]u8{ 0x00, 0x01, 0xFF, 0x0A, 0x7F, 'z', 'a', 't', 0x00 }; // NUL + newline = the binary case base64 must survive
    if (!put(gpa, key, &blob)) return; // keyring locked/unavailable → skip

    const got = get(gpa, key) orelse {
        del(key);
        return error.KeystoreReadbackMissing;
    };
    defer gpa.free(got);
    defer del(key); // never leave the self-test secret behind
    try std.testing.expectEqualSlices(u8, &blob, got);
}
