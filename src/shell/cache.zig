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

//! B1 classification: SHELL. Disk persistence — the store snapshot and
//! the auth session, across runs. This file resolves paths, opens fds,
//! and moves bytes ATOMICALLY (write-then-rename); what the bytes MEAN is
//! sealed inside core/snapshot.zig (D1/D3). All file I/O rides the
//! kernel-stable syscall surface (caution 1a).
//!
//! Failure doctrine (E4): a cache that is missing, stale, torn, or
//! corrupt is not an error — it is a cold start. Load returns null;
//! save returns false; the app proceeds either way.

const std = @import("std");
const Allocator = std.mem.Allocator;
const builtin = @import("builtin");
const linux = std.os.linux;
const is_windows = builtin.os.tag == .windows;
const is_darwin = builtin.os.tag.isDarwin();

/// Darwin file primitives, self-declared from libSystem (same doctrine
/// as k32 below). `open` is declared VARIADIC because it is variadic in
/// C — Apple's arm64 ABI passes variadic arguments on the stack, so a
/// flattened three-argument declaration would corrupt the mode.
const dc = struct {
    // Not a record: an extern-fn namespace (no fields). A1/A7 do not apply.
    extern "c" fn open(path: [*:0]const u8, flags: c_int, ...) c_int;
    extern "c" fn read(fd: c_int, buf: [*]u8, n: usize) isize;
    extern "c" fn write(fd: c_int, buf: [*]const u8, n: usize) isize;
    extern "c" fn close(fd: c_int) c_int;
    extern "c" fn rename(old: [*:0]const u8, new: [*:0]const u8) c_int;
    extern "c" fn mkdir(path: [*:0]const u8, mode: u16) c_int;
    const O_RDONLY: c_int = 0;
    const O_WRONLY: c_int = 1;
    const O_CREAT: c_int = 0x200;
    const O_TRUNC: c_int = 0x400;
};

/// Windows file primitives (kernel32) — the OS ABI, the same doctrine as
/// the Linux syscall surface below. Namespaced to keep symbols tidy.
const k32 = struct {
    // Not a record: an extern-fn namespace (no fields). A1/A7 do not apply.

    extern "kernel32" fn CreateFileW(name: [*:0]const u16, access: u32, share: u32, sec: ?*anyopaque, disp: u32, flags: u32, template: ?*anyopaque) callconv(.winapi) ?*anyopaque;
    extern "kernel32" fn ReadFile(h: *anyopaque, buf: [*]u8, n: u32, read: *u32, ov: ?*anyopaque) callconv(.winapi) i32;
    extern "kernel32" fn WriteFile(h: *anyopaque, buf: [*]const u8, n: u32, written: *u32, ov: ?*anyopaque) callconv(.winapi) i32;
    extern "kernel32" fn CloseHandle(h: *anyopaque) callconv(.winapi) i32;
    extern "kernel32" fn MoveFileExW(from: [*:0]const u16, to: [*:0]const u16, flags: u32) callconv(.winapi) i32;
    extern "kernel32" fn CreateDirectoryW(path: [*:0]const u16, sec: ?*anyopaque) callconv(.winapi) i32;
    const generic_read: u32 = 0x8000_0000;
    const generic_write: u32 = 0x4000_0000;
    const share_read: u32 = 1;
    const open_existing: u32 = 3;
    const create_always: u32 = 2;
    const attr_normal: u32 = 0x80;
    const movefile_replace: u32 = 1;
    const invalid_handle: usize = std.math.maxInt(usize);
};

fn utf16Path(buf: *[520]u16, path: []const u8) ?[:0]const u16 {
    if (path.len == 0) return null;
    const n = std.unicode.utf8ToUtf16Le(buf[0 .. buf.len - 1], path) catch return null;
    buf[n] = 0;
    return buf[0..n :0];
}

fn winOpen(path: []const u8, write: bool) ?*anyopaque {
    var w: [520]u16 = undefined;
    const wp = utf16Path(&w, path) orelse return null;
    const h = k32.CreateFileW(
        wp.ptr,
        if (write) k32.generic_write else k32.generic_read,
        k32.share_read,
        null,
        if (write) k32.create_always else k32.open_existing,
        k32.attr_normal,
        null,
    );
    if (h == null or @intFromPtr(h.?) == k32.invalid_handle) return null;
    return h.?;
}
const snapshot = @import("../core/snapshot.zig");
const feed = @import("../core/feed.zig");
const algo_library = @import("../core/algo_library.zig");
const auth = @import("auth.zig");
const keystore = @import("keystore.zig");

// Keystore keys (Phase 4): both session blobs live in the OS keystore when one
// is available, off the 0600 plaintext file (see saveSessionAt / the SECURITY
// NOTE on the oauth section). Keystore use is gated to Linux for now — libsecret
// is the only backend; macOS Keychain / Windows Credential Manager are the
// follow-ups behind keystore.zig's same interface, so those platforms keep the
// 0600 file until then.
const session_keystore_key = "app-password-session";
const oauth_keystore_key = "oauth-session";
// Linux only (libsecret is the sole backend) AND never in test builds — the
// cache tests must exercise the file path deterministically and must NEVER touch
// the developer's real keyring (a fixed production key would clobber a live
// saved session). `keystore.zig` has its own test for the FFI (dedicated key,
// self-cleaning); the cache↔keystore wiring is validated live (--oauth-resume).
const keystore_supported = builtin.os.tag == .linux and !builtin.is_test;

const store_file = "store.zat";
const session_file = "session.zat";
const library_file = "algorithms.zat";
const oauth_session_file = "oauth_session.zat";
const max_file_bytes = 64 * 1024 * 1024;

// ---------------------------------------------------------------------------
// Paths
// ---------------------------------------------------------------------------

/// Resolve (and create) the cache directory: ZAT_CACHE_DIR, else
/// $XDG_CACHE_HOME/zat, else $HOME/.cache/zat. Null when no home exists —
/// the app then simply runs cacheless.
pub fn cacheDir(buf: []u8, environ: ?*const std.process.Environ.Map) ?[]const u8 {
    const env = environ orelse return null;
    const dir: []const u8 = blk: {
        if (env.get("ZAT_CACHE_DIR")) |explicit| {
            break :blk std.fmt.bufPrint(buf, "{s}", .{explicit}) catch return null;
        }
        if (comptime is_darwin) {
            if (env.get("HOME")) |home| {
                break :blk std.fmt.bufPrint(buf, "{s}/Library/Caches/zat", .{home}) catch return null;
            }
            return null;
        }
        if (comptime is_windows) {
            if (env.get("LOCALAPPDATA")) |base| {
                break :blk std.fmt.bufPrint(buf, "{s}\\zat", .{base}) catch return null;
            }
            return null;
        }
        if (env.get("XDG_CACHE_HOME")) |xdg| {
            break :blk std.fmt.bufPrint(buf, "{s}/zat", .{xdg}) catch return null;
        }
        if (env.get("HOME")) |home| {
            const parent = std.fmt.bufPrint(buf, "{s}/.cache", .{home}) catch return null;
            mkdir(parent); // best effort; usually exists
            break :blk std.fmt.bufPrint(buf, "{s}/.cache/zat", .{home}) catch return null;
        }
        return null;
    };
    mkdir(dir);
    return dir;
}

fn mkdir(path: []const u8) void {
    if (comptime is_darwin) {
        var z: [512]u8 = undefined;
        const zp = zPath(&z, path) orelse return;
        _ = dc.mkdir(zp, 0o700); // EEXIST and friends are fine (E4)
        return;
    }
    if (comptime is_windows) {
        var w: [520]u16 = undefined;
        const wp = utf16Path(&w, path) orelse return;
        _ = k32.CreateDirectoryW(wp.ptr, null); // ALREADY_EXISTS is fine (E4)
        return;
    }
    var z: [512]u8 = undefined;
    const zp = zPath(&z, path) orelse return;
    _ = linux.mkdir(zp, 0o700); // EEXIST and friends are fine (E4)
}

fn zPath(buf: *[512]u8, path: []const u8) ?[*:0]const u8 {
    if (path.len == 0 or path.len >= buf.len) return null;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    return buf[0..path.len :0].ptr;
}

fn joinFile(buf: []u8, dir: []const u8, name: []const u8) ?[]const u8 {
    return std.fmt.bufPrint(buf, "{s}/{s}", .{ dir, name }) catch null;
}

// ---------------------------------------------------------------------------
// Kernel-surface file primitives
// ---------------------------------------------------------------------------

fn readFileAlloc(gpa: Allocator, path: []const u8) ?[]u8 {
    if (comptime is_darwin) {
        var z: [512]u8 = undefined;
        const zp = zPath(&z, path) orelse return null;
        const fd = dc.open(zp, dc.O_RDONLY);
        if (fd < 0) return null;
        defer _ = dc.close(fd);
        var out: std.ArrayList(u8) = .empty;
        var chunk: [64 * 1024]u8 = undefined;
        while (true) {
            const got = dc.read(fd, &chunk, chunk.len);
            if (got < 0) {
                out.deinit(gpa);
                return null;
            }
            if (got == 0) break;
            const g: usize = @intCast(got);
            if (out.items.len + g > max_file_bytes) {
                out.deinit(gpa);
                return null;
            }
            out.appendSlice(gpa, chunk[0..g]) catch {
                out.deinit(gpa);
                return null;
            };
        }
        return out.toOwnedSlice(gpa) catch {
            out.deinit(gpa);
            return null;
        };
    }
    if (comptime is_windows) {
        const h = winOpen(path, false) orelse return null;
        defer _ = k32.CloseHandle(h);
        var out: std.ArrayList(u8) = .empty;
        var chunk: [64 * 1024]u8 = undefined;
        while (true) {
            var got: u32 = 0;
            if (k32.ReadFile(h, &chunk, chunk.len, &got, null) == 0) {
                out.deinit(gpa);
                return null;
            }
            if (got == 0) break;
            if (out.items.len + got > max_file_bytes) {
                out.deinit(gpa);
                return null;
            }
            out.appendSlice(gpa, chunk[0..got]) catch {
                out.deinit(gpa);
                return null;
            };
        }
        return out.toOwnedSlice(gpa) catch {
            out.deinit(gpa);
            return null;
        };
    }
    var z: [512]u8 = undefined;
    const zp = zPath(&z, path) orelse return null;
    const open_rc = linux.open(zp, .{ .ACCMODE = .RDONLY }, 0);
    const fd_signed: isize = @bitCast(open_rc);
    if (fd_signed < 0) return null;
    const fd: i32 = @intCast(fd_signed);
    defer _ = linux.close(fd);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var chunk: [64 * 1024]u8 = undefined;
    while (true) {
        const n_rc = linux.read(fd, &chunk, chunk.len);
        const n_signed: isize = @bitCast(n_rc);
        if (n_signed < 0) {
            out.deinit(gpa);
            return null;
        }
        if (n_signed == 0) break;
        if (out.items.len + @as(usize, @intCast(n_signed)) > max_file_bytes) {
            out.deinit(gpa);
            return null;
        }
        out.appendSlice(gpa, chunk[0..@intCast(n_signed)]) catch {
            out.deinit(gpa);
            return null;
        };
    }
    // toOwnedSlice: the returned slice's length must equal the allocation
    // the caller will free — items.len under a larger capacity is a lie
    // the leak detector rightly aborts on.
    return out.toOwnedSlice(gpa) catch {
        out.deinit(gpa);
        return null;
    };
}

fn writeFileAtomic(path: []const u8, bytes: []const u8, mode: u32) bool {
    var tmp_buf: [512]u8 = undefined;
    const tmp = std.fmt.bufPrint(&tmp_buf, "{s}.tmp", .{path}) catch return false;
    if (comptime is_darwin) {
        var zt: [512]u8 = undefined;
        var zf: [512]u8 = undefined;
        const tmp_z = zPath(&zt, tmp) orelse return false;
        const final_z = zPath(&zf, path) orelse return false;
        const fd = dc.open(tmp_z, dc.O_WRONLY | dc.O_CREAT | dc.O_TRUNC, @as(c_int, @intCast(mode)));
        if (fd < 0) return false;
        var sent: usize = 0;
        while (sent < bytes.len) {
            const wrote = dc.write(fd, bytes.ptr + sent, bytes.len - sent);
            if (wrote <= 0) {
                _ = dc.close(fd);
                return false;
            }
            sent += @intCast(wrote);
        }
        if (dc.close(fd) != 0) return false;
        return dc.rename(tmp_z, final_z) == 0;
    }
    if (comptime is_windows) {
        // `mode` is POSIX semantics; Windows files inherit directory ACLs.
        // Tightening session.zat with an explicit ACL is the recorded
        // hardening follow-up for the Windows port.
        const h = winOpen(tmp, true) orelse return false;
        var sent: usize = 0;
        while (sent < bytes.len) {
            var wrote: u32 = 0;
            const n: u32 = @intCast(@min(bytes.len - sent, std.math.maxInt(u32)));
            if (k32.WriteFile(h, bytes.ptr + sent, n, &wrote, null) == 0 or wrote == 0) {
                _ = k32.CloseHandle(h);
                return false;
            }
            sent += wrote;
        }
        _ = k32.CloseHandle(h);
        var wt: [520]u16 = undefined;
        var wf: [520]u16 = undefined;
        const tmp_w = utf16Path(&wt, tmp) orelse return false;
        const final_w = utf16Path(&wf, path) orelse return false;
        return k32.MoveFileExW(tmp_w.ptr, final_w.ptr, k32.movefile_replace) != 0;
    }
    var z_tmp: [512]u8 = undefined;
    const zp_tmp = zPath(&z_tmp, tmp) orelse return false;

    const open_rc = linux.open(zp_tmp, .{ .ACCMODE = .WRONLY, .CREAT = true, .TRUNC = true }, mode);
    const fd_signed: isize = @bitCast(open_rc);
    if (fd_signed < 0) return false;
    const fd: i32 = @intCast(fd_signed);

    var written: usize = 0;
    while (written < bytes.len) {
        const n_rc = linux.write(fd, bytes.ptr + written, bytes.len - written);
        const n_signed: isize = @bitCast(n_rc);
        if (n_signed <= 0) {
            _ = linux.close(fd);
            return false;
        }
        written += @intCast(n_signed);
    }
    _ = linux.close(fd);

    var z_final: [512]u8 = undefined;
    const zp_final = zPath(&z_final, path) orelse return false;
    return linux.rename(zp_tmp, zp_final) == 0;
}

// ---------------------------------------------------------------------------
// The store snapshot
// ---------------------------------------------------------------------------

pub fn loadStoreAt(gpa: Allocator, path: []const u8) ?feed.Store {
    const bytes = readFileAlloc(gpa, path) orelse return null;
    defer gpa.free(bytes);
    return snapshot.decode(gpa, bytes) catch null;
}

pub fn saveStoreAt(gpa: Allocator, path: []const u8, store: *const feed.Store) bool {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const image = snapshot.encode(arena_state.allocator(), store) catch return false;
    return writeFileAtomic(path, image, 0o644);
}

pub fn loadStore(gpa: Allocator, environ: ?*const std.process.Environ.Map) ?feed.Store {
    var dir_buf: [512]u8 = undefined;
    var path_buf: [512]u8 = undefined;
    const dir = cacheDir(&dir_buf, environ) orelse return null;
    const path = joinFile(&path_buf, dir, store_file) orelse return null;
    return loadStoreAt(gpa, path);
}

pub fn saveStore(gpa: Allocator, environ: ?*const std.process.Environ.Map, store: *const feed.Store) bool {
    var dir_buf: [512]u8 = undefined;
    var path_buf: [512]u8 = undefined;
    const dir = cacheDir(&dir_buf, environ) orelse return false;
    const path = joinFile(&path_buf, dir, store_file) orelse return false;
    return saveStoreAt(gpa, path, store);
}

// ---------------------------------------------------------------------------
// The algorithm library — the user's created/downloaded feeds
// ---------------------------------------------------------------------------

pub fn loadLibraryAt(gpa: Allocator, path: []const u8) ?algo_library.Library {
    const bytes = readFileAlloc(gpa, path) orelse return null;
    defer gpa.free(bytes);
    return algo_library.deserialize(gpa, bytes) catch null;
}

pub fn saveLibraryAt(gpa: Allocator, path: []const u8, lib: *const algo_library.Library) bool {
    const bytes = algo_library.serialize(gpa, lib) catch return false;
    defer gpa.free(bytes);
    return writeFileAtomic(path, bytes, 0o644);
}

pub fn loadLibrary(gpa: Allocator, environ: ?*const std.process.Environ.Map) ?algo_library.Library {
    var dir_buf: [512]u8 = undefined;
    var path_buf: [512]u8 = undefined;
    const dir = cacheDir(&dir_buf, environ) orelse return null;
    const path = joinFile(&path_buf, dir, library_file) orelse return null;
    return loadLibraryAt(gpa, path);
}

pub fn saveLibrary(gpa: Allocator, environ: ?*const std.process.Environ.Map, lib: *const algo_library.Library) bool {
    var dir_buf: [512]u8 = undefined;
    var path_buf: [512]u8 = undefined;
    const dir = cacheDir(&dir_buf, environ) orelse return false;
    const path = joinFile(&path_buf, dir, library_file) orelse return false;
    return saveLibraryAt(gpa, path, lib);
}

// ---------------------------------------------------------------------------
// The session — five strings behind 0600
// ---------------------------------------------------------------------------

const session_magic = [4]u8{ 'Z', 'A', 'T', 'S' };
const session_version: u16 = 1;

pub fn saveSessionAt(gpa: Allocator, path: []const u8, session: *const auth.Session) bool {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var out: std.ArrayList(u8) = .empty;
    out.appendSlice(arena, &session_magic) catch return false;
    out.appendSlice(arena, std.mem.asBytes(&session_version)) catch return false;
    inline for (.{ session.did, session.handle, session.pds_url, session.access_jwt, session.refresh_jwt }) |field| {
        const len: u32 = @intCast(field.len);
        out.appendSlice(arena, std.mem.asBytes(&len)) catch return false;
        out.appendSlice(arena, field) catch return false;
    }
    // Phase 4: prefer the OS keystore (secrets off plaintext). On a VERIFIED
    // store (keystore.put reads back to confirm), drop any 0600 fallback so no
    // plaintext sibling lingers — the "encrypt one file, leave the other" theater
    // the SECURITY NOTE warns about. If the keystore is absent/locked, fall back
    // to the 0600 file unchanged.
    if (keystore_supported and keystore.put(gpa, session_keystore_key, out.items)) {
        unlink(path);
        return true;
    }
    return writeFileAtomic(path, out.items, 0o600);
}

/// Loaded strings are gpa-owned; release with `freeSession`. Reads the keystore
/// first (Phase 4), then the 0600 file (legacy / fallback / pre-migration — a
/// file hit migrates to the keystore on the next save).
pub fn loadSessionAt(gpa: Allocator, path: []const u8) ?auth.Session {
    if (keystore_supported) {
        if (keystore.get(gpa, session_keystore_key)) |blob| {
            defer gpa.free(blob);
            if (parseSession(gpa, blob)) |s| return s;
        }
    }
    const bytes = readFileAlloc(gpa, path) orelse return null;
    defer gpa.free(bytes);
    return parseSession(gpa, bytes);
}

/// Parse a session blob (keystore secret or file bytes) into an owned Session.
/// Borrows `bytes` (dupes every field into `gpa`); the caller frees `bytes`.
fn parseSession(gpa: Allocator, bytes: []const u8) ?auth.Session {
    if (bytes.len < 6 or !std.mem.eql(u8, bytes[0..4], &session_magic)) return null;
    if (std.mem.bytesToValue(u16, bytes[4..6]) != session_version) return null;

    var fields: [5][]const u8 = undefined;
    var at: usize = 6;
    var loaded: usize = 0;
    errdefer for (fields[0..loaded]) |f| gpa.free(f);
    for (&fields) |*field| {
        if (bytes.len - at < 4) {
            for (fields[0..loaded]) |f| gpa.free(f);
            return null;
        }
        const len = std.mem.bytesToValue(u32, bytes[at..][0..4]);
        at += 4;
        if (bytes.len - at < len) {
            for (fields[0..loaded]) |f| gpa.free(f);
            return null;
        }
        field.* = gpa.dupe(u8, bytes[at .. at + len]) catch {
            for (fields[0..loaded]) |f| gpa.free(f);
            return null;
        };
        loaded += 1;
        at += len;
    }
    if (at != bytes.len) {
        for (fields) |f| gpa.free(f);
        return null;
    }
    return .{
        .mode = .app_password,
        .did = fields[0],
        .handle = fields[1],
        .pds_url = fields[2],
        .access_jwt = fields[3],
        .refresh_jwt = fields[4],
        // Inert in app-password mode (never read or freed).
        .dpop_secret = [_]u8{0} ** 32,
        .scope = "",
        .issuer = "",
        .token_endpoint = "",
        .nonce = null,
    };
}

/// Free a session loaded from disk. Delegates to the auth module, which owns
/// the Session free contract (D5): ONE freer for the shared type, so a loaded
/// session and a logged-in one release identically. This also covers the oauth
/// fields (scope/issuer/token_endpoint/nonce) and scrubs the token secrets —
/// the hand-rolled version here did neither, so an oauth session freed through
/// this path leaked and left secrets in freed pages (C4/C5).
pub fn freeSession(gpa: Allocator, session: *const auth.Session) void {
    auth.freeSession(gpa, session.*);
}

/// Sign-out: remove every trace of the cached session — BOTH cache files AND the
/// keystore entries (app-password + oauth), so a relaunch finds nothing and shows
/// the Join/login flow. Best-effort and idempotent (E4): a missing file or an
/// absent keystore entry is success, not an error. Mirrors the two places a
/// session is persisted — `saveSessionAt` (keystore key `app-password-session` +
/// `session.zat`) and `saveOAuthSessionAt` (`oauth-session` + `oauth_session.zat`).
pub fn clearSession(environ: ?*const std.process.Environ.Map) void {
    if (keystore_supported) {
        keystore.del(session_keystore_key);
        keystore.del(oauth_keystore_key);
    }
    var buf: [512]u8 = undefined;
    if (sessionPath(&buf, environ)) |p| unlink(p);
    var buf2: [512]u8 = undefined;
    if (oauthSessionPath(&buf2, environ)) |p| unlink(p);
}

pub fn sessionPath(buf: []u8, environ: ?*const std.process.Environ.Map) ?[]const u8 {
    var dir_buf: [512]u8 = undefined;
    const dir = cacheDir(&dir_buf, environ) orelse return null;
    return joinFile(buf, dir, session_file);
}

// --- OAuth (DPoP) session persistence (OAuth slice 5) -----------------------
//
// Same on-disk posture as the app-password session above: a 0600 file in the
// cache dir. The format is magic + version + the raw 32-byte DPoP key + the
// length-prefixed strings. Persisting the key is what lets a DPoP login survive
// a relaunch (the binding is only useful if the key is stable).
//
// SECURITY (slice 5b — DONE on Linux): the DPoP key + refresh token go into the
// OS keystore (libsecret) when available; the 0600 file is the fallback only
// where no keystore exists, and a keystore store deletes any plaintext sibling
// (saveOAuthSessionAt below). BOTH session blobs are covered (app-password + this
// one), so there is no "encrypt one, leave the other" theater. macOS Keychain /
// Windows Credential Manager are the follow-ups behind keystore.zig's interface;
// those platforms keep the 0600 posture until then.
const oauth_session_magic = [4]u8{ 'Z', 'A', 'T', 'O' };
const oauth_session_version: u16 = 1;

pub fn saveOAuthSessionAt(gpa: Allocator, path: []const u8, sess: *const auth.Session) bool {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var out: std.ArrayList(u8) = .empty;
    out.appendSlice(arena, &oauth_session_magic) catch return false;
    out.appendSlice(arena, std.mem.asBytes(&oauth_session_version)) catch return false;
    out.appendSlice(arena, &sess.dpop_secret) catch return false;
    inline for (.{
        sess.did,         sess.handle,      sess.pds_url,
        sess.access_jwt,  sess.refresh_jwt, sess.scope,
        sess.issuer,      sess.token_endpoint,
    }) |field| {
        const len: u32 = @intCast(field.len);
        out.appendSlice(arena, std.mem.asBytes(&len)) catch return false;
        out.appendSlice(arena, field) catch return false;
    }
    // The nonce is optional; an empty string on disk means "none".
    const nonce = sess.nonce orelse "";
    const nlen: u32 = @intCast(nonce.len);
    out.appendSlice(arena, std.mem.asBytes(&nlen)) catch return false;
    out.appendSlice(arena, nonce) catch return false;
    // Phase 4: keystore-first (DPoP key + refresh token off plaintext), file
    // fallback. A verified store removes the plaintext sibling. See saveSessionAt.
    if (keystore_supported and keystore.put(gpa, oauth_keystore_key, out.items)) {
        unlink(path);
        return true;
    }
    return writeFileAtomic(path, out.items, 0o600);
}

/// Loaded strings are gpa-owned; release with `auth.freeSession`. Keystore first
/// (Phase 4), then the 0600 file (legacy / fallback / pre-migration).
pub fn loadOAuthSessionAt(gpa: Allocator, path: []const u8) ?auth.Session {
    if (keystore_supported) {
        if (keystore.get(gpa, oauth_keystore_key)) |blob| {
            defer gpa.free(blob);
            if (parseOAuthSession(gpa, blob)) |s| return s;
        }
    }
    const bytes = readFileAlloc(gpa, path) orelse return null;
    defer gpa.free(bytes);
    return parseOAuthSession(gpa, bytes);
}

/// Parse an oauth session blob (keystore secret or file bytes); borrows `bytes`
/// (dupes fields into `gpa`), the caller frees `bytes`.
fn parseOAuthSession(gpa: Allocator, bytes: []const u8) ?auth.Session {
    // 4 magic + 2 version + 32 key = 38 byte header minimum.
    if (bytes.len < 38 or !std.mem.eql(u8, bytes[0..4], &oauth_session_magic)) return null;
    if (std.mem.bytesToValue(u16, bytes[4..6]) != oauth_session_version) return null;
    const secret: [32]u8 = bytes[6..38].*;

    var fields: [9][]const u8 = undefined; // 8 strings + nonce
    var at: usize = 38;
    var loaded: usize = 0;
    for (&fields) |*field| {
        if (bytes.len - at < 4) {
            for (fields[0..loaded]) |f| gpa.free(f);
            return null;
        }
        const len = std.mem.bytesToValue(u32, bytes[at..][0..4]);
        at += 4;
        if (bytes.len - at < len) {
            for (fields[0..loaded]) |f| gpa.free(f);
            return null;
        }
        field.* = gpa.dupe(u8, bytes[at .. at + len]) catch {
            for (fields[0..loaded]) |f| gpa.free(f);
            return null;
        };
        loaded += 1;
        at += len;
    }
    if (at != bytes.len) {
        for (fields) |f| gpa.free(f);
        return null;
    }
    // Empty nonce string -> none.
    var nonce: ?[]const u8 = fields[8];
    if (fields[8].len == 0) {
        gpa.free(fields[8]);
        nonce = null;
    }
    return .{
        .mode = .oauth,
        .did = fields[0],
        .handle = fields[1],
        .pds_url = fields[2],
        .access_jwt = fields[3],
        .refresh_jwt = fields[4],
        .scope = fields[5],
        .issuer = fields[6],
        .token_endpoint = fields[7],
        .dpop_secret = secret,
        .nonce = nonce,
    };
}

pub fn oauthSessionPath(buf: []u8, environ: ?*const std.process.Environ.Map) ?[]const u8 {
    var dir_buf: [512]u8 = undefined;
    const dir = cacheDir(&dir_buf, environ) orelse return null;
    return joinFile(buf, dir, oauth_session_file);
}

// --- Chat anchor key persistence (Zat Chat slice C6) -------------------------
//
// The anchor key is the device-bound Ed25519 seed that IS the user's chat
// identity (core/anchor.zig) — never delegated to the PDS, never in the repo.
// Same storage posture as the sessions above: OS keystore preferred, 0600 file
// fallback, a verified keystore store deletes the plaintext sibling.
//
// Keyed PER DID: a device can host several accounts over time, and one
// account's anchor must never clobber another's (losing an anchor seed is an
// IDENTITY change — peers see a new key). For the same reason `clearSession`
// deliberately does NOT touch anchors: sign-out ends the session, not the
// device's chat identity; signing back into the same account finds the same
// anchor and the published keyPackage stays valid.
const anchor_magic = [4]u8{ 'Z', 'A', 'T', 'A' };
const anchor_version: u16 = 1;
const anchor_seed_len = 32;
const anchor_keystore_prefix = "chat-anchor:";

/// Cache-file path for a DID's anchor: `anchor-<16 hex of sha256(did)>.zat`.
/// Hashed because DIDs contain ':' (illegal in Windows filenames) and can be
/// long; the DID itself is stored inside the blob and checked on load.
pub fn anchorPath(buf: []u8, environ: ?*const std.process.Environ.Map, did: []const u8) ?[]const u8 {
    var dir_buf: [512]u8 = undefined;
    const dir = cacheDir(&dir_buf, environ) orelse return null;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(did, &digest, .{});
    const hex = std.fmt.bytesToHex(digest[0..8].*, .lower);
    var name_buf: [32]u8 = undefined;
    const name = std.fmt.bufPrint(&name_buf, "anchor-{s}.zat", .{hex}) catch return null;
    return joinFile(buf, dir, name);
}

/// The per-DID keystore key, or null when the DID is too long for the
/// keystore's key buffer (then the file is the only store).
fn anchorKeystoreKey(buf: *[255]u8, did: []const u8) ?[]const u8 {
    return std.fmt.bufPrint(buf, anchor_keystore_prefix ++ "{s}", .{did}) catch null;
}

pub fn saveAnchorSeedAt(gpa: Allocator, path: []const u8, did: []const u8, seed: [anchor_seed_len]u8) bool {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var out: std.ArrayList(u8) = .empty;
    out.appendSlice(arena, &anchor_magic) catch return false;
    out.appendSlice(arena, std.mem.asBytes(&anchor_version)) catch return false;
    const dlen: u32 = @intCast(did.len);
    out.appendSlice(arena, std.mem.asBytes(&dlen)) catch return false;
    out.appendSlice(arena, did) catch return false;
    out.appendSlice(arena, &seed) catch return false;
    if (keystore_supported) {
        var key_buf: [255]u8 = undefined;
        if (anchorKeystoreKey(&key_buf, did)) |key| {
            if (keystore.put(gpa, key, out.items)) {
                unlink(path);
                return true;
            }
        }
    }
    return writeFileAtomic(path, out.items, 0o600);
}

/// The anchor seed for `did`, or null if none is stored (first chat use) or
/// the stored blob is damaged / for a different DID. Keystore first, then the
/// 0600 file.
pub fn loadAnchorSeedAt(gpa: Allocator, path: []const u8, did: []const u8) ?[anchor_seed_len]u8 {
    if (keystore_supported) {
        var key_buf: [255]u8 = undefined;
        if (anchorKeystoreKey(&key_buf, did)) |key| {
            if (keystore.get(gpa, key)) |blob| {
                defer {
                    std.crypto.secureZero(u8, blob);
                    gpa.free(blob);
                }
                if (parseAnchorSeed(blob, did)) |seed| return seed;
            }
        }
    }
    const bytes = readFileAlloc(gpa, path) orelse return null;
    defer {
        std.crypto.secureZero(u8, bytes);
        gpa.free(bytes);
    }
    return parseAnchorSeed(bytes, did);
}

fn parseAnchorSeed(bytes: []const u8, did: []const u8) ?[anchor_seed_len]u8 {
    // 4 magic + 2 version + 4 did-len = 10 byte header minimum.
    if (bytes.len < 10 or !std.mem.eql(u8, bytes[0..4], &anchor_magic)) return null;
    if (std.mem.bytesToValue(u16, bytes[4..6]) != anchor_version) return null;
    const dlen = std.mem.bytesToValue(u32, bytes[6..10]);
    if (bytes.len != 10 + @as(usize, dlen) + anchor_seed_len) return null;
    if (!std.mem.eql(u8, bytes[10 .. 10 + dlen], did)) return null;
    return bytes[10 + dlen ..][0..anchor_seed_len].*;
}

// --- Chat last-resort KeyPackage persistence (Zat Chat slice U6) ------------
//
// The published keyPackage record is public; its PRIVATE halves (the init and
// encryption keys `mls.generateKeyPackage` returned, plus the exact published
// wire bytes they belong to) must survive relaunches — a Welcome addressed to
// this package can arrive weeks after it was minted. Same posture as the
// anchor: per-DID, keystore preferred, 0600 file fallback, never cleared by
// sign-out.
const chat_kp_magic = [4]u8{ 'Z', 'A', 'T', 'K' };
const chat_kp_version: u16 = 1;
const chat_kp_keystore_prefix = "chat-kp:";

/// A7.2: cold struct, size guard waived — one per chat identity, transient.
pub const ChatKeyPackage = struct {
    init_priv: [32]u8,
    enc_priv: [32]u8,
    /// The published MLSMessage(KeyPackage) bytes these keys belong to
    /// (gpa-owned; free with `freeChatKeyPackage`).
    kp_bytes: []u8,
};

pub fn freeChatKeyPackage(gpa: Allocator, kp: *ChatKeyPackage) void {
    std.crypto.secureZero(u8, &kp.init_priv);
    std.crypto.secureZero(u8, &kp.enc_priv);
    gpa.free(kp.kp_bytes);
    kp.kp_bytes = &.{};
}

pub fn chatKeyPackagePath(buf: []u8, environ: ?*const std.process.Environ.Map, did: []const u8) ?[]const u8 {
    var dir_buf: [512]u8 = undefined;
    const dir = cacheDir(&dir_buf, environ) orelse return null;
    var digest: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(did, &digest, .{});
    const hex = std.fmt.bytesToHex(digest[0..8].*, .lower);
    var name_buf: [32]u8 = undefined;
    const name = std.fmt.bufPrint(&name_buf, "chatkp-{s}.zat", .{hex}) catch return null;
    return joinFile(buf, dir, name);
}

fn chatKpKeystoreKey(buf: *[255]u8, did: []const u8) ?[]const u8 {
    return std.fmt.bufPrint(buf, chat_kp_keystore_prefix ++ "{s}", .{did}) catch null;
}

pub fn saveChatKeyPackageAt(gpa: Allocator, path: []const u8, did: []const u8, kp: *const ChatKeyPackage) bool {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var out: std.ArrayList(u8) = .empty;
    out.appendSlice(arena, &chat_kp_magic) catch return false;
    out.appendSlice(arena, std.mem.asBytes(&chat_kp_version)) catch return false;
    const dlen: u32 = @intCast(did.len);
    out.appendSlice(arena, std.mem.asBytes(&dlen)) catch return false;
    out.appendSlice(arena, did) catch return false;
    out.appendSlice(arena, &kp.init_priv) catch return false;
    out.appendSlice(arena, &kp.enc_priv) catch return false;
    const klen: u32 = @intCast(kp.kp_bytes.len);
    out.appendSlice(arena, std.mem.asBytes(&klen)) catch return false;
    out.appendSlice(arena, kp.kp_bytes) catch return false;
    if (keystore_supported) {
        var key_buf: [255]u8 = undefined;
        if (chatKpKeystoreKey(&key_buf, did)) |key| {
            if (keystore.put(gpa, key, out.items)) {
                unlink(path);
                return true;
            }
        }
    }
    return writeFileAtomic(path, out.items, 0o600);
}

/// The stored last-resort package for `did`, or null (none / damaged / a
/// different DID's blob). Keystore first, then the 0600 file.
pub fn loadChatKeyPackageAt(gpa: Allocator, path: []const u8, did: []const u8) ?ChatKeyPackage {
    if (keystore_supported) {
        var key_buf: [255]u8 = undefined;
        if (chatKpKeystoreKey(&key_buf, did)) |key| {
            if (keystore.get(gpa, key)) |blob| {
                defer {
                    std.crypto.secureZero(u8, blob);
                    gpa.free(blob);
                }
                if (parseChatKeyPackage(gpa, blob, did)) |kp| return kp;
            }
        }
    }
    const bytes = readFileAlloc(gpa, path) orelse return null;
    defer {
        std.crypto.secureZero(u8, bytes);
        gpa.free(bytes);
    }
    return parseChatKeyPackage(gpa, bytes, did);
}

fn parseChatKeyPackage(gpa: Allocator, bytes: []const u8, did: []const u8) ?ChatKeyPackage {
    // 4 magic + 2 version + 4 did-len = 10 byte header minimum.
    if (bytes.len < 10 or !std.mem.eql(u8, bytes[0..4], &chat_kp_magic)) return null;
    if (std.mem.bytesToValue(u16, bytes[4..6]) != chat_kp_version) return null;
    const dlen = std.mem.bytesToValue(u32, bytes[6..10]);
    var at: usize = 10;
    if (bytes.len - at < dlen) return null;
    if (!std.mem.eql(u8, bytes[at .. at + dlen], did)) return null;
    at += dlen;
    if (bytes.len - at < 64 + 4) return null;
    const init_priv: [32]u8 = bytes[at..][0..32].*;
    at += 32;
    const enc_priv: [32]u8 = bytes[at..][0..32].*;
    at += 32;
    const klen = std.mem.bytesToValue(u32, bytes[at..][0..4]);
    at += 4;
    if (bytes.len - at != klen) return null;
    const kp_bytes = gpa.dupe(u8, bytes[at..]) catch return null;
    return .{ .init_priv = init_priv, .enc_priv = enc_priv, .kp_bytes = kp_bytes };
}

/// A7.2: cold struct, size guard waived — one per chat startup, transient.
pub const AnchorLoad = struct {
    seed: [anchor_seed_len]u8,
    /// True when this call minted (and persisted) a fresh anchor.
    created: bool,
};

/// The one entry point chat uses: the stored anchor for `did`, or a freshly
/// generated one (CSPRNG) persisted before it is handed out. Null means no
/// anchor is possible right now (no cache dir AND no keystore, or no entropy)
/// — a caller must treat that as "chat identity unavailable", NEVER mint an
/// ephemeral key, because an unpersisted anchor would silently become a new
/// identity on every launch.
pub fn loadOrCreateAnchorSeed(gpa: Allocator, io: std.Io, environ: ?*const std.process.Environ.Map, did: []const u8) ?AnchorLoad {
    var path_buf: [512]u8 = undefined;
    const path = anchorPath(&path_buf, environ, did) orelse return null;
    if (loadAnchorSeedAt(gpa, path, did)) |seed| return .{ .seed = seed, .created = false };
    var seed: [anchor_seed_len]u8 = undefined;
    io.randomSecure(&seed) catch return null;
    if (!saveAnchorSeedAt(gpa, path, did, seed)) {
        std.crypto.secureZero(u8, &seed);
        return null;
    }
    return .{ .seed = seed, .created = true };
}

// ---------------------------------------------------------------------------
// Tests (C6) — real files under /tmp, cleaned up
// ---------------------------------------------------------------------------

const testing = std.testing;

fn tmpPath(buf: []u8, comptime name: []const u8) []const u8 {
    return std.fmt.bufPrint(buf, "/tmp/zat-test-{d}-" ++ name, .{linux.getpid()}) catch unreachable;
}

fn unlink(path: []const u8) void {
    var z: [512]u8 = undefined;
    const zp = zPath(&z, path) orelse return;
    _ = linux.unlink(zp);
}

test "cache: store snapshot survives the disk; corruption is a cold start" {
    const gpa = testing.allocator; // C6
    var path_buf: [128]u8 = undefined;
    const path = tmpPath(&path_buf, "store");
    defer unlink(path);

    var store: feed.Store = .{};
    defer feed.deinitStore(gpa, &store);
    _ = try feed.ingestPage(gpa, &store, feed.fixture_page);

    try testing.expect(saveStoreAt(gpa, path, &store));
    var loaded = loadStoreAt(gpa, path) orelse return error.TestUnexpectedResult;
    defer feed.deinitStore(gpa, &loaded);
    try testing.expectEqual(store.feed.len, loaded.feed.len);
    try testing.expectEqualStrings(feed.nextCursor(&store), feed.nextCursor(&loaded));

    // Corruption is refused quietly.
    try testing.expect(writeFileAtomic(path, "not a snapshot", 0o644));
    try testing.expectEqual(@as(?feed.Store, null), loadStoreAt(gpa, path));

    // Absence is a cold start.
    unlink(path);
    try testing.expectEqual(@as(?feed.Store, null), loadStoreAt(gpa, path));
}

test "cache: session round-trips behind 0600 and frees clean" {
    const gpa = testing.allocator; // C6
    var path_buf: [128]u8 = undefined;
    const path = tmpPath(&path_buf, "session");
    defer unlink(path);

    const session = auth.Session{
        .did = "did:plc:cccccccccccccccccccccccc",
        .handle = "carol.test",
        .pds_url = "https://pds.example",
        .access_jwt = "access-token",
        .refresh_jwt = "refresh-token",
    };
    try testing.expect(saveSessionAt(gpa, path, &session));

    const loaded = loadSessionAt(gpa, path) orelse return error.TestUnexpectedResult;
    defer freeSession(gpa, &loaded);
    try testing.expectEqualStrings(session.did, loaded.did);
    try testing.expectEqualStrings(session.refresh_jwt, loaded.refresh_jwt);

    // 0600: the kernel agrees (statx is this snapshot's stat surface).
    var z: [512]u8 = undefined;
    var stx: linux.Statx = undefined;
    const stat_rc = linux.statx(linux.AT.FDCWD, zPath(&z, path).?, 0, .{ .MODE = true }, &stx);
    try testing.expect(stat_rc == 0);
    try testing.expectEqual(@as(u16, 0o600), stx.mode & 0o777);
}

test "cache: OAuth session round-trips key, tokens, and nonce" {
    const gpa = testing.allocator; // C6
    var path_buf: [128]u8 = undefined;
    const path = tmpPath(&path_buf, "oauth");
    defer unlink(path);

    var secret: [32]u8 = undefined;
    for (&secret, 0..) |*b, i| b.* = @intCast(i);

    const sess = auth.Session{
        .mode = .oauth,
        .did = "did:plc:dddddddddddddddddddddddd",
        .handle = "dan.test",
        .pds_url = "https://pds.example",
        .access_jwt = "access-tok",
        .refresh_jwt = "refresh-tok",
        .scope = "atproto transition:generic",
        .issuer = "https://pds.example",
        .token_endpoint = "https://pds.example/oauth/token",
        .dpop_secret = secret,
        .nonce = "server-nonce-1",
    };
    try testing.expect(saveOAuthSessionAt(gpa, path, &sess));

    const loaded = loadOAuthSessionAt(gpa, path) orelse return error.TestUnexpectedResult;
    defer auth.freeSession(gpa, loaded);
    try testing.expectEqualStrings(sess.did, loaded.did);
    try testing.expectEqualStrings(sess.access_jwt, loaded.access_jwt);
    try testing.expectEqualStrings(sess.token_endpoint, loaded.token_endpoint);
    try testing.expectEqualSlices(u8, &secret, &loaded.dpop_secret);
    try testing.expectEqualStrings("server-nonce-1", loaded.nonce.?);

    // A null nonce round-trips as null (empty string on disk).
    var sess2 = sess;
    sess2.nonce = null;
    var path2_buf: [128]u8 = undefined;
    const path2 = tmpPath(&path2_buf, "oauth2");
    defer unlink(path2);
    try testing.expect(saveOAuthSessionAt(gpa, path2, &sess2));
    const loaded2 = loadOAuthSessionAt(gpa, path2) orelse return error.TestUnexpectedResult;
    defer auth.freeSession(gpa, loaded2);
    try testing.expectEqual(@as(?[]const u8, null), loaded2.nonce);
}

test "cache: anchor seed round-trips per DID behind 0600 and refuses mismatches" {
    const gpa = testing.allocator; // C6
    var path_buf: [128]u8 = undefined;
    const path = tmpPath(&path_buf, "anchor");
    defer unlink(path);

    const did = "did:plc:eeeeeeeeeeeeeeeeeeeeeeee";
    var seed: [anchor_seed_len]u8 = undefined;
    for (&seed, 0..) |*b, i| b.* = @intCast(i * 3 & 0xff);

    try testing.expect(saveAnchorSeedAt(gpa, path, did, seed));
    const loaded = loadAnchorSeedAt(gpa, path, did) orelse return error.TestUnexpectedResult;
    try testing.expectEqualSlices(u8, &seed, &loaded);

    // 0600: the anchor is a secret at rest.
    var z: [512]u8 = undefined;
    var stx: linux.Statx = undefined;
    const stat_rc = linux.statx(linux.AT.FDCWD, zPath(&z, path).?, 0, .{ .MODE = true }, &stx);
    try testing.expect(stat_rc == 0);
    try testing.expectEqual(@as(u16, 0o600), stx.mode & 0o777);

    // Another DID's lookup must NOT see this seed (the blob self-identifies).
    try testing.expectEqual(@as(?[anchor_seed_len]u8, null), loadAnchorSeedAt(gpa, path, "did:plc:ffffffffffffffffffffffff"));

    // Corruption is refused quietly (first chat use then regenerates).
    try testing.expect(writeFileAtomic(path, "not an anchor", 0o600));
    try testing.expectEqual(@as(?[anchor_seed_len]u8, null), loadAnchorSeedAt(gpa, path, did));

    // Absence means "no anchor yet".
    unlink(path);
    try testing.expectEqual(@as(?[anchor_seed_len]u8, null), loadAnchorSeedAt(gpa, path, did));
}

test "cache: chat keyPackage privates round-trip per DID and refuse mismatches" {
    const gpa = testing.allocator; // C6
    var path_buf: [128]u8 = undefined;
    const path = tmpPath(&path_buf, "chatkp");
    defer unlink(path);

    const did = "did:plc:kpkpkpkpkpkpkpkpkpkpkpkp";
    var kp: ChatKeyPackage = .{
        .init_priv = [_]u8{0xA1} ** 32,
        .enc_priv = [_]u8{0xB2} ** 32,
        .kp_bytes = try gpa.dupe(u8, "fake-key-package-wire-bytes"),
    };
    defer freeChatKeyPackage(gpa, &kp);

    try testing.expect(saveChatKeyPackageAt(gpa, path, did, &kp));
    var loaded = loadChatKeyPackageAt(gpa, path, did) orelse return error.TestUnexpectedResult;
    defer freeChatKeyPackage(gpa, &loaded);
    try testing.expectEqualSlices(u8, &kp.init_priv, &loaded.init_priv);
    try testing.expectEqualSlices(u8, &kp.enc_priv, &loaded.enc_priv);
    try testing.expectEqualStrings("fake-key-package-wire-bytes", loaded.kp_bytes);

    // Another DID sees nothing; corruption is null; absence is null.
    try testing.expect(loadChatKeyPackageAt(gpa, path, "did:plc:nnnnnnnnnnnnnnnnnnnnnnnn") == null);
    try testing.expect(writeFileAtomic(path, "garbage", 0o600));
    try testing.expect(loadChatKeyPackageAt(gpa, path, did) == null);
    unlink(path);
    try testing.expect(loadChatKeyPackageAt(gpa, path, did) == null);
}

test "cache: anchorPath keys files by DID" {
    // Two DIDs must land in two files; the same DID must be stable.
    var env = std.process.Environ.Map.init(testing.allocator);
    defer env.deinit();
    try env.put("ZAT_CACHE_DIR", "/tmp/zat-anchor-test");
    var b1: [512]u8 = undefined;
    var b2: [512]u8 = undefined;
    var b3: [512]u8 = undefined;
    const p1 = anchorPath(&b1, &env, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa") orelse return error.TestUnexpectedResult;
    const p2 = anchorPath(&b2, &env, "did:plc:bbbbbbbbbbbbbbbbbbbbbbbb") orelse return error.TestUnexpectedResult;
    const p3 = anchorPath(&b3, &env, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa") orelse return error.TestUnexpectedResult;
    try testing.expect(!std.mem.eql(u8, p1, p2));
    try testing.expectEqualStrings(p1, p3);
}
