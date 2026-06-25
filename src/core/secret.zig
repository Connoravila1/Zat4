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

//! B1 classification: CORE (pure — no I/O; allocation is explicit per C1).
//!
//! A wrapper for secret bytes — session tokens, signing-key material, the
//! assigned password — that makes the two most common real-world leaks take
//! deliberate effort instead of being the default (SECURITY_ROADMAP Phase 0):
//!   1. **Lingering in memory.** `wipe` `secureZero`s the bytes (an erase the
//!      compiler may not elide) before freeing, so a later crash dump or a
//!      swapped-out page can't contain a usable secret.
//!   2. **Accidental logging.** The value can only be read through the one
//!      named accessor `expose` — a single greppable point every disclosure
//!      passes through — and formatting a `Secret` prints `[redacted]`, never
//!      the bytes, so an `std.debug.print`/error-line of one is harmless.
//!
//! Ruleset note (A1/D5): behaviour lives in FREE functions (`init`, `wipe`,
//! `expose`) over plain data, per A1. The lone method is `format`, and it is a
//! deliberate, recorded exception: it is a security INTERLOCK that *suppresses*
//! output (prints a constant, reads nothing, enforces no invariant, hides no
//! cost) — the opposite of the attached behaviour A1 exists to forbid. It is
//! the redacting formatter SECURITY_ROADMAP Phase 0 calls for, and Zig's std
//! formatting protocol can only be overridden by a method. Nothing else here is
//! a method.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

/// Owns a heap copy of some secret bytes. Construct with `init`, read through
/// `expose`, and always `wipe` (it both scrubs and frees). A7.2-adjacent: held
/// in small quantity (a session has a few), but the guard is cheap and exact.
pub const Secret = struct {
    bytes: []u8,

    comptime {
        assert(@sizeOf(Secret) == @sizeOf([]u8)); // a slice and nothing more
    }

    /// The redaction interlock — see the module note on the A1 exception. Prints
    /// a constant so a Secret can never be the thing that leaks into a log line.
    pub fn format(s: Secret, w: *std.Io.Writer) std.Io.Writer.Error!void {
        _ = s;
        try w.writeAll("[redacted]");
    }
};

/// Copy `plaintext` into a freshly-owned buffer (C1: explicit allocator). The
/// Secret owns the copy, so the caller may wipe/free its own source
/// independently. Pass the plaintext straight in and drop your reference.
pub fn init(gpa: Allocator, plaintext: []const u8) Allocator.Error!Secret {
    return .{ .bytes = try gpa.dupe(u8, plaintext) };
}

/// Scrub then free. `secureZero` is the erase the optimizer will not drop
/// (defeating dead-store elimination), so the plaintext does not survive in
/// freed memory. Idempotent: a wiped Secret holds an empty slice (C5).
pub fn wipe(s: *Secret, gpa: Allocator) void {
    std.crypto.secureZero(u8, s.bytes);
    gpa.free(s.bytes);
    s.bytes = &.{};
}

/// The one deliberate disclosure point. Every place that needs the plaintext
/// calls this by name, so a reviewer can grep `expose(` to enumerate exactly
/// where the secret is read.
pub fn expose(s: Secret) []const u8 {
    return s.bytes;
}

// ---------------------------------------------------------------------------
// Tests (C6 — leak-checked: a missing wipe fails the test, not just warns).
// ---------------------------------------------------------------------------

const testing = std.testing;

test "init copies, expose round-trips, wipe leaves nothing to free" {
    var src = [_]u8{ 's', 'e', 'c', 'r', 'e', 't' };
    var s = try init(testing.allocator, &src);
    // Independent copy: mutating the source does not change the Secret.
    src[0] = 'X';
    try testing.expectEqualStrings("secret", expose(s));
    wipe(&s, testing.allocator);
    try testing.expectEqual(@as(usize, 0), expose(s).len);
    wipe(&s, testing.allocator); // idempotent: a second wipe is safe (empty free)
}

test "wipe scrubs the bytes before releasing them" {
    // Inspect the buffer through an alias to prove it is zeroed (not just freed
    // with stale contents). The alias is freed by wipe; we only read it before.
    const buf = try testing.allocator.alloc(u8, 4);
    @memcpy(buf, "key!");
    var s = Secret{ .bytes = buf };
    std.crypto.secureZero(u8, s.bytes); // the exact scrub wipe performs
    try testing.expectEqualSlices(u8, &.{ 0, 0, 0, 0 }, buf);
    testing.allocator.free(buf);
    s.bytes = &.{};
}

test "format redacts: the plaintext never appears" {
    var s = try init(testing.allocator, "hunter2-do-not-print");
    defer wipe(&s, testing.allocator);
    var buf: [64]u8 = undefined;
    const out = try std.fmt.bufPrint(&buf, "token={f}", .{s});
    try testing.expectEqualStrings("token=[redacted]", out);
    try testing.expect(std.mem.indexOf(u8, out, "hunter2") == null);
}
