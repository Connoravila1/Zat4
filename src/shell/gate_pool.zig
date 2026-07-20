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

//! B1 classification: SHELL (file I/O). The **invite-code pool** — how the gate
//! hands out the artifact that actually creates an account.
//!
//! ── The pool model, and why the gate has no admin credential (§9.5) ──
//! The owner pre-mints single-use codes with `pdsadmin create-invite-code` and
//! drops them in a file. The gate hands them out one at a time. It CANNOT mint
//! more, because it holds no PDS admin credential — and that is the point: a
//! fully compromised gate can exhaust a small pool, which the owner refills,
//! but it can never mint unlimited accounts, read a message, or impersonate
//! anyone. The accepted cost is that the gate also cannot revoke a code it has
//! already handed out.
//!
//! ── This file IS a bearer-token file ──
//! Anyone holding a line from it can create an account without passing the
//! gate. Mode is checked on load and a world-readable pool is refused, because
//! the §9.3 invariant ("no account exists without a gate-minted code") is only
//! as strong as this file's permissions.
//!
//! ── Consumption must survive a restart ──
//! A handed-out code must never be handed out twice. The PDS would reject the
//! second use (codes are `useCount=1`), so the failure mode is not a security
//! hole — it is an honest user who did all the work and gets a dud code at the
//! last step, which is arguably worse to debug. Consumption is therefore
//! recorded in its own append-only log of fixed-size records, replayed at
//! startup. Kept SEPARATE from the enrollment log (D1): pool mechanics and
//! coordination observation change for different reasons.
//!
//! Interface, in full: `Pool`, `load`, `unload`, `take`, `remaining`,
//! `consumed_record_bytes`, `low_water`.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

/// Warn below this many codes remaining. An empty pool is an enrollment
/// OUTAGE — nobody can join — so it must be visible well before it happens.
pub const low_water: usize = 20;

/// One consumed-log record: which slot was handed out, and when.
/// 4 (index) + 8 (when) + 4 (crc) = 16 bytes, fixed, so a torn tail is a short
/// remainder to drop rather than a misparse.
pub const consumed_record_bytes = 16;

/// The longest invite code accepted from the pool file. PDS codes look like
/// `pds-zat4-com-wtivz-mlqlc` (24 chars); 63 leaves generous headroom while
/// keeping every entry a fixed, bounded allocation.
const max_code_len = 63;

/// Hard cap on pool size. The enrollment record stores the slot as a `u16`
/// join key, so a pool larger than this could not be referenced.
const max_codes = 65534; // 0xFFFF is `gate_record.no_code`

/// A loaded pool. `codes` and its contents are owned by `gpa` (C4).
///
/// A7.2: cold struct — one per process, read on each enrollment but never held
/// in quantity.
pub const Pool = struct {
    codes: [][]const u8 = &.{},
    /// Slots below this are already handed out. Restored from the consumed log
    /// at startup.
    next: usize = 0,
    /// Append fd for the consumed log; < 0 means DISABLED.
    consumed_fd: i32 = -1,
    /// Set when the pool file was present but refused for its permissions.
    /// Distinguished from "absent" so the operator gets the right message.
    insecure_mode: bool = false,
};

pub fn remaining(p: Pool) usize {
    return if (p.next >= p.codes.len) 0 else p.codes.len - p.next;
}

/// SHELL (B3): load the pool file and replay the consumed log.
///
/// Missing files yield an EMPTY pool rather than an error (E4): a gate with no
/// pool still observes and scores, it simply cannot hand out a code. The caller
/// decides how loudly to complain — see `gate_main`.
///
/// Blank lines and `#` comments are skipped so the file can carry a note about
/// where the codes came from.
pub fn load(gpa: Allocator, pool_path: []const u8, consumed_path: []const u8) Pool {
    var p: Pool = .{};
    if (comptime builtin.os.tag != .linux) return p;

    const text = readAll(gpa, pool_path, 1 << 20) orelse return p;
    defer gpa.free(text);

    // A pool readable by anyone on the box is a pile of account credentials
    // sitting in the open. Refuse it rather than quietly serve from it.
    if (worldAccessible(pool_path)) {
        p.insecure_mode = true;
        return p;
    }

    var list: std.ArrayListUnmanaged([]const u8) = .empty;
    defer list.deinit(gpa);

    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0 or line[0] == '#') continue;
        if (line.len > max_code_len) continue; // malformed; skip, do not truncate
        if (list.items.len >= max_codes) break;
        const copy = gpa.dupe(u8, line) catch break;
        list.append(gpa, copy) catch {
            gpa.free(copy);
            break;
        };
    }
    p.codes = list.toOwnedSlice(gpa) catch &.{};

    p.next = replayConsumed(gpa, consumed_path);
    p.consumed_fd = openAppend(consumed_path);
    return p;
}

pub fn unload(gpa: Allocator, p: *Pool) void {
    for (p.codes) |c| gpa.free(c);
    if (p.codes.len > 0) gpa.free(p.codes);
    p.codes = &.{};
    if (p.consumed_fd >= 0 and comptime builtin.os.tag == .linux) _ = linux.close(p.consumed_fd);
    p.consumed_fd = -1;
}

/// SHELL (B3): hand out the next unconsumed code, returning it and its slot
/// index. Absent optional when the pool is exhausted (E4 — an empty pool is an
/// ordinary, if urgent, state).
///
/// ── The durable write happens BEFORE the code is returned ──
/// If the consumed log cannot be appended to, this refuses to hand out the code
/// at all. Handing one out without recording it would mean a restart re-issues
/// it, and the second recipient does all the enrollment work only to have the
/// PDS reject their code at the final step. Refusing costs one enrollment
/// attempt; the alternative costs a user's entire signup and looks like a bug in
/// the client.
pub fn take(p: *Pool, now: i64) ?struct { code: []const u8, index: u16 } {
    if (p.next >= p.codes.len) return null;
    const idx = p.next;
    if (idx > max_codes) return null;

    if (!appendConsumed(p.consumed_fd, @intCast(idx), now)) return null;

    p.next += 1;
    return .{ .code = p.codes[idx], .index = @intCast(idx) };
}

// ── consumed log: fixed 16-byte records ──

fn encodeConsumed(index: u32, when: i64) [consumed_record_bytes]u8 {
    var b: [consumed_record_bytes]u8 = undefined;
    std.mem.writeInt(u32, b[0..4], index, .little);
    std.mem.writeInt(i64, b[4..12], when, .little);
    std.mem.writeInt(u32, b[12..16], crc(b[0..12]), .little);
    return b;
}

fn decodeConsumed(b: []const u8) ?u32 {
    if (b.len != consumed_record_bytes) return null;
    if (std.mem.readInt(u32, b[12..16], .little) != crc(b[0..12])) return null;
    return std.mem.readInt(u32, b[0..4], .little);
}

/// Replay the consumed log to find where to resume.
///
/// Returns HIGHEST-CONSUMED + 1, not a count. Those differ if a record is ever
/// lost, and resuming from a count would re-issue an already-handed-out code —
/// the exact failure this log exists to prevent. Taking the maximum fails in
/// the safe direction: at worst a few codes are skipped and wasted, which costs
/// nothing but a refill.
fn replayConsumed(gpa: Allocator, path: []const u8) usize {
    const buf = readAll(gpa, path, 1 << 20) orelse return 0;
    defer gpa.free(buf);

    var highest: ?u32 = null;
    var at: usize = 0;
    while (at + consumed_record_bytes <= buf.len) : (at += consumed_record_bytes) {
        const idx = decodeConsumed(buf[at..][0..consumed_record_bytes]) orelse continue;
        if (highest == null or idx > highest.?) highest = idx;
    }
    return if (highest) |h| @as(usize, h) + 1 else 0;
}

fn appendConsumed(fd: i32, index: u32, when: i64) bool {
    if (fd < 0) return false;
    if (comptime builtin.os.tag != .linux) return false;
    const b = encodeConsumed(index, when);
    const rc = linux.write(fd, &b, b.len);
    const signed: isize = @bitCast(rc);
    return signed == @as(isize, b.len);
}

// ── small file helpers (same syscall posture as shell/gate_store.zig) ──

fn zpath(buf: *[256]u8, path: []const u8) ?[:0]const u8 {
    if (path.len == 0 or path.len >= 255) return null;
    @memcpy(buf[0..path.len], path);
    buf[path.len] = 0;
    return buf[0..path.len :0];
}

fn readAll(gpa: Allocator, path: []const u8, cap: usize) ?[]u8 {
    if (comptime builtin.os.tag != .linux) return null;
    var z: [256]u8 = undefined;
    const p = zpath(&z, path) orelse return null;
    const rc = linux.open(p.ptr, .{ .ACCMODE = .RDONLY }, 0);
    const signed: isize = @bitCast(rc);
    if (signed < 0) return null;
    const fd: i32 = @intCast(signed);
    defer _ = linux.close(fd);

    const buf = gpa.alloc(u8, cap) catch return null;
    var filled: usize = 0;
    while (filled < buf.len) {
        const n = linux.read(fd, buf[filled..].ptr, buf.len - filled);
        const sn: isize = @bitCast(n);
        if (sn <= 0) break;
        filled += @intCast(sn);
    }
    if (gpa.resize(buf, filled)) return buf[0..filled];
    const exact = gpa.alloc(u8, filled) catch {
        gpa.free(buf);
        return null;
    };
    @memcpy(exact, buf[0..filled]);
    gpa.free(buf);
    return exact;
}

fn openAppend(path: []const u8) i32 {
    if (comptime builtin.os.tag != .linux) return -1;
    var z: [256]u8 = undefined;
    const p = zpath(&z, path) orelse return -1;
    const rc = linux.open(p.ptr, .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true }, 0o600);
    const signed: isize = @bitCast(rc);
    return if (signed < 0) -1 else @intCast(signed);
}

/// True if the pool file is readable or writable by group or other. The gate's
/// core invariant is only as strong as this file's permissions.
fn worldAccessible(path: []const u8) bool {
    if (comptime builtin.os.tag != .linux) return false;
    var z: [256]u8 = undefined;
    const p = zpath(&z, path) orelse return false;
    // statx is this snapshot's stat surface (same as shell/cache.zig).
    var stx: linux.Statx = undefined;
    const rc = linux.statx(linux.AT.FDCWD, p.ptr, 0, .{ .MODE = true }, &stx);
    const signed: isize = @bitCast(rc);
    if (signed < 0) return false; // cannot tell; the read already succeeded
    return (stx.mode & 0o077) != 0;
}

fn crc(bytes: []const u8) u32 {
    var c = std.hash.Crc32.init();
    c.update(bytes);
    return c.final();
}

// ── Tests: the codec and the resume logic, which is where a double-issue bug
// would live. The file paths are exercised by running the binary.

const testing = std.testing;

test "a consumed record round-trips and rejects corruption" {
    const b = encodeConsumed(7, 1_767_323_045);
    try testing.expectEqual(@as(u32, 7), decodeConsumed(&b).?);

    var bad = b;
    bad[2] ^= 0xFF;
    try testing.expect(decodeConsumed(&bad) == null);
    try testing.expect(decodeConsumed(b[0 .. consumed_record_bytes - 1]) == null);
}

/// Mirror of `replayConsumed`'s scan over an in-memory buffer.
fn scanConsumed(buf: []const u8) usize {
    var highest: ?u32 = null;
    var at: usize = 0;
    while (at + consumed_record_bytes <= buf.len) : (at += consumed_record_bytes) {
        const idx = decodeConsumed(buf[at..][0..consumed_record_bytes]) orelse continue;
        if (highest == null or idx > highest.?) highest = idx;
    }
    return if (highest) |h| @as(usize, h) + 1 else 0;
}

test "replay resumes after the HIGHEST consumed index, not the count" {
    // These differ the moment a record is lost, and resuming from a count would
    // re-issue a code that was already handed out.
    var buf: [consumed_record_bytes * 3]u8 = undefined;
    for ([_]u32{ 0, 1, 2 }, 0..) |idx, i| {
        const b = encodeConsumed(idx, 1);
        @memcpy(buf[i * consumed_record_bytes ..][0..consumed_record_bytes], &b);
    }
    try testing.expectEqual(@as(usize, 3), scanConsumed(&buf));

    // Now corrupt the MIDDLE record: two survive, but the highest is still 2,
    // so we resume at 3 and skip nothing that was issued.
    buf[consumed_record_bytes + 1] ^= 0xFF;
    try testing.expectEqual(@as(usize, 3), scanConsumed(&buf));
}

test "an empty or torn consumed log resumes from the start safely" {
    try testing.expectEqual(@as(usize, 0), scanConsumed(&.{}));

    var partial: [consumed_record_bytes + 5]u8 = undefined;
    const b = encodeConsumed(4, 1);
    @memcpy(partial[0..consumed_record_bytes], &b);
    @memset(partial[consumed_record_bytes..], 0xAB);
    try testing.expectEqual(@as(usize, 5), scanConsumed(&partial)); // torn tail ignored
}

test "take refuses to issue when the consumed log cannot be written" {
    // Issuing without recording means a restart re-issues the same code, and
    // the second user does all the work only for the PDS to reject it.
    var codes = [_][]const u8{ "code-a", "code-b" };
    var p: Pool = .{ .codes = &codes, .next = 0, .consumed_fd = -1 };
    try testing.expect(take(&p, 1) == null);
    try testing.expectEqual(@as(usize, 0), p.next); // nothing was consumed
}

test "remaining reports the pool honestly, including exhausted" {
    var codes = [_][]const u8{ "a", "b", "c" };
    var p: Pool = .{ .codes = &codes, .next = 0 };
    try testing.expectEqual(@as(usize, 3), remaining(p));
    p.next = 2;
    try testing.expectEqual(@as(usize, 1), remaining(p));
    p.next = 3;
    try testing.expectEqual(@as(usize, 0), remaining(p));
    p.next = 99; // past the end: still zero, never an underflow
    try testing.expectEqual(@as(usize, 0), remaining(p));
}
