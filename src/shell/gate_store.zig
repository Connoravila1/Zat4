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

//! B1 classification: SHELL (file I/O). The Constellation Gate's **durable
//! store** — an append-only log of observed enrollments.
//!
//! Why this exists at all: shadow mode's entire purpose is accumulating the
//! data that turns every `[CALIBRATE]` placeholder into a number. An in-memory
//! store loses all of it on restart, which would look like a working gate while
//! quietly wasting the whole calibration period. That failure — healthy-looking
//! and silently useless — is the one this codebase keeps producing, so the
//! store is not an optimization; it is the point of running the gate at all.
//!
//! Kernel-surface file I/O (raw `std.os.linux`), matching `shell/cache.zig`,
//! `shell/stream.zig` and `shell/appview_store.zig`: the fork's `std.Io.Dir`
//! API drifts across snapshots, so the durable stores ride the stable syscall
//! boundary. Linux is the deployment target; anywhere else the store degrades
//! to DISABLED and the gate runs in memory exactly as before (E2: a missing
//! capability is a plainer service, never a dead one).
//!
//! Interface, in full: `Store`, `open`, `close`, `append`, `replay`,
//! `ReplayResult`, `enabled`.

const std = @import("std");
const builtin = @import("builtin");
const linux = std.os.linux;
const record = @import("../core/gate_record.zig");
const constellation = @import("../core/constellation.zig");

/// An open durable log. `fd < 0` means DISABLED — every operation is a no-op.
/// A7.2: cold struct, size guard waived — one per process.
pub const Store = struct {
    fd: i32 = -1,
};

pub fn enabled(s: Store) bool {
    return s.fd >= 0;
}

/// Replay cap. 512 MiB / 128 B = ~4 million enrollments, which is far past any
/// scale this gate will see before it is rearchitected. The cap is here so a
/// corrupt or hostile file cannot drive an unbounded read (C2: the cost is
/// visible at the call site).
const max_file_bytes: usize = 512 * 1024 * 1024;

/// What a replay found. Counts are surfaced rather than swallowed so a store
/// that is quietly shedding records shows up as a NUMBER at startup instead of
/// as an unexplained gap in the calibration data months later.
///
/// A7.2: cold struct, size guard waived — exactly one exists, produced once at
/// startup and printed. Never held in quantity, never in a hot loop.
pub const ReplayResult = struct {
    /// Records decoded and applied.
    applied: usize = 0,
    /// Records that failed `decode` — bad magic, bad checksum, bad field.
    /// Anything above zero means real corruption and is worth investigating.
    corrupt: usize = 0,
    /// Bytes left over after the last whole record: a torn final append,
    /// almost always a power loss mid-write. Expected to be 0 or one partial
    /// record; anything else means the file has been mangled.
    trailing_bytes: usize = 0,
    /// Records dropped because the caller's token buffer filled. Distinct from
    /// `corrupt`: the data was fine, we had nowhere to put it.
    dropped_full: usize = 0,
};

/// SHELL (B3): open (creating if absent) the log at `path` for append.
///
/// An empty path or a failed open yields a DISABLED store rather than an error
/// (E2) — the gate then runs in memory, as it did before this module. Mode
/// 0600, not 0644: the file is coordination structure about real people, and
/// while it holds no identities (§2), it is nobody else's business.
pub fn open(path: []const u8) Store {
    if (path.len == 0 or path.len >= 255) return .{};
    if (comptime builtin.os.tag != .linux) return .{};
    var z: [256]u8 = undefined;
    @memcpy(z[0..path.len], path);
    z[path.len] = 0;
    const rc = linux.open(
        z[0..path.len :0].ptr,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true },
        0o600,
    );
    const signed: isize = @bitCast(rc);
    if (signed < 0) return .{};
    return .{ .fd = @intCast(signed) };
}

pub fn close(store: *Store) void {
    if (store.fd >= 0 and comptime builtin.os.tag == .linux) _ = linux.close(store.fd);
    store.fd = -1;
}

/// SHELL (B3): append one enrollment. Returns false if it was not durably
/// handed to the kernel, so the caller can COUNT the loss rather than assume
/// success.
///
/// The file is opened O_APPEND, so the write is positioned atomically by the
/// kernel — concurrent writers cannot interleave into one another's records.
/// A short write is treated as a failure rather than retried: retrying from a
/// partial offset is what produces a garbled record, and a garbled record that
/// passes length checks is exactly what the checksum exists to catch. Better
/// to leave a torn tail that replay drops cleanly.
pub fn append(store: Store, e: record.Enrollment) bool {
    if (store.fd < 0) return false;
    if (comptime builtin.os.tag != .linux) return false;
    const block = record.encode(e);
    const rc = linux.write(store.fd, &block, block.len);
    const signed: isize = @bitCast(rc);
    return signed == @as(isize, block.len);
}

/// SHELL (B3): read the whole log and refill the caller's token buffer.
///
/// `tokens` is caller-owned and caller-sized (C1/C4) — this never allocates.
/// Returns the number of tokens written plus a `ReplayResult` describing what
/// was skipped and why.
///
/// A corrupt record is DROPPED, and the scan CONTINUES rather than stopping.
/// Stopping at the first bad record would silently discard every later
/// observation, turning one bad block into total data loss; and since signals
/// never decay, the store is append-only history that is worth salvaging around
/// a hole.
pub fn replay(
    gpa: std.mem.Allocator,
    path: []const u8,
    tokens: []constellation.Token,
) struct { len: usize, result: ReplayResult } {
    var out: ReplayResult = .{};
    if (path.len == 0 or path.len >= 255) return .{ .len = 0, .result = out };
    if (comptime builtin.os.tag != .linux) return .{ .len = 0, .result = out };

    var z: [256]u8 = undefined;
    @memcpy(z[0..path.len], path);
    z[path.len] = 0;
    const rc = linux.open(z[0..path.len :0].ptr, .{ .ACCMODE = .RDONLY }, 0);
    const signed: isize = @bitCast(rc);
    if (signed < 0) return .{ .len = 0, .result = out }; // absent file = empty store
    const fd: i32 = @intCast(signed);
    defer _ = linux.close(fd);

    const buf = gpa.alloc(u8, max_file_bytes) catch
        return .{ .len = 0, .result = out };
    defer gpa.free(buf);

    var filled: usize = 0;
    while (filled < buf.len) {
        const n = linux.read(fd, buf[filled..].ptr, buf.len - filled);
        const sn: isize = @bitCast(n);
        if (sn <= 0) break;
        filled += @intCast(sn);
    }

    var len: usize = 0;
    var at: usize = 0;
    while (at + record.record_bytes <= filled) : (at += record.record_bytes) {
        const e = record.decode(buf[at..][0..record.record_bytes]) orelse {
            out.corrupt += 1;
            continue;
        };
        const n = @min(e.token_len, record.max_tokens);
        if (len + n > tokens.len) {
            out.dropped_full += 1;
            continue;
        }
        for (e.tokens[0..n]) |t| {
            tokens[len] = t;
            len += 1;
        }
        out.applied += 1;
    }
    out.trailing_bytes = filled - at;

    return .{ .len = len, .result = out };
}

// ── Tests: the codec is covered in core/gate_record.zig; these cover the
// scan/skip logic, which is where the data-loss bugs would live.

const testing = std.testing;

fn testEnrollment(tag: u64, n: u8) record.Enrollment {
    var e: record.Enrollment = .{
        .subject_tag = tag,
        .observed_at = 1_767_323_045,
        .factor_x100 = 100,
        .token_len = n,
        .tokens = undefined,
    };
    for (0..record.max_tokens) |i| {
        e.tokens[i] = .{ .value = tag +% i, .kind = .timing };
    }
    return e;
}

/// Drive `replay`'s scan over an in-memory buffer, mirroring its loop exactly.
/// The file path is not exercised here (that needs a real fd); what is
/// exercised is the skip-and-continue behaviour, which is the part with teeth.
fn scan(buf: []const u8, tokens: []constellation.Token) struct { len: usize, result: ReplayResult } {
    var out: ReplayResult = .{};
    var len: usize = 0;
    var at: usize = 0;
    while (at + record.record_bytes <= buf.len) : (at += record.record_bytes) {
        const e = record.decode(buf[at..][0..record.record_bytes]) orelse {
            out.corrupt += 1;
            continue;
        };
        const n = @min(e.token_len, record.max_tokens);
        if (len + n > tokens.len) {
            out.dropped_full += 1;
            continue;
        }
        for (e.tokens[0..n]) |t| {
            tokens[len] = t;
            len += 1;
        }
        out.applied += 1;
    }
    out.trailing_bytes = buf.len - at;
    return .{ .len = len, .result = out };
}

test "replay reads back every appended record in order" {
    var buf: [record.record_bytes * 3]u8 = undefined;
    for (0..3) |i| {
        const b = record.encode(testEnrollment(@intCast(i + 1), 2));
        @memcpy(buf[i * record.record_bytes ..][0..record.record_bytes], &b);
    }
    var tokens: [16]constellation.Token = undefined;
    const r = scan(&buf, &tokens);
    try testing.expectEqual(@as(usize, 3), r.result.applied);
    try testing.expectEqual(@as(usize, 6), r.len); // 3 records x 2 tokens
    try testing.expectEqual(@as(usize, 0), r.result.corrupt);
    try testing.expectEqual(@as(usize, 0), r.result.trailing_bytes);
}

test "a corrupt record in the MIDDLE does not discard the ones after it" {
    // Stopping at the first bad block would turn one flipped bit into total
    // loss of every later observation. With no signal decay the log is
    // append-only history worth salvaging around a hole.
    var buf: [record.record_bytes * 3]u8 = undefined;
    for (0..3) |i| {
        const b = record.encode(testEnrollment(@intCast(i + 1), 2));
        @memcpy(buf[i * record.record_bytes ..][0..record.record_bytes], &b);
    }
    buf[record.record_bytes + 40] ^= 0xFF; // garble record 1

    var tokens: [16]constellation.Token = undefined;
    const r = scan(&buf, &tokens);
    try testing.expectEqual(@as(usize, 2), r.result.applied); // 0 and 2 survive
    try testing.expectEqual(@as(usize, 1), r.result.corrupt);
    try testing.expectEqual(@as(usize, 4), r.len);
}

test "a torn tail is counted, not misread" {
    var buf: [record.record_bytes + 40]u8 = undefined;
    const b = record.encode(testEnrollment(7, 3));
    @memcpy(buf[0..record.record_bytes], &b);
    @memset(buf[record.record_bytes..], 0xAB); // half-written append

    var tokens: [16]constellation.Token = undefined;
    const r = scan(&buf, &tokens);
    try testing.expectEqual(@as(usize, 1), r.result.applied);
    try testing.expectEqual(@as(usize, 40), r.result.trailing_bytes);
    try testing.expectEqual(@as(usize, 0), r.result.corrupt); // torn != corrupt
}

test "a full token buffer drops records and COUNTS them" {
    // Distinct from corruption: the data was fine, there was nowhere to put it.
    // Counting it is what stops a silently truncated store from reading as a
    // healthy one.
    var buf: [record.record_bytes * 4]u8 = undefined;
    for (0..4) |i| {
        const b = record.encode(testEnrollment(@intCast(i + 1), 3));
        @memcpy(buf[i * record.record_bytes ..][0..record.record_bytes], &b);
    }
    var tokens: [7]constellation.Token = undefined; // room for 2 records, not 4
    const r = scan(&buf, &tokens);
    try testing.expectEqual(@as(usize, 2), r.result.applied);
    try testing.expectEqual(@as(usize, 2), r.result.dropped_full);
    try testing.expectEqual(@as(usize, 6), r.len);
}

test "an empty log replays to an empty store" {
    var tokens: [4]constellation.Token = undefined;
    const r = scan(&.{}, &tokens);
    try testing.expectEqual(@as(usize, 0), r.result.applied);
    try testing.expectEqual(@as(usize, 0), r.len);
}

test "a disabled store accepts appends without pretending they landed" {
    const s: Store = .{}; // fd = -1
    try testing.expect(!enabled(s));
    try testing.expect(!append(s, testEnrollment(1, 2))); // false, not a silent true
}
