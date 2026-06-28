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

//! B1 classification: SHELL (build tooling). Mechanizes THE SIZE GUARD
//! audit (A7): every module-level struct in src/ must carry an exact
//! `comptime @sizeOf` guard, an `A7.2` waiver comment, an explicit
//! packed backing (`packed struct(uN)` — the type itself is the size
//! contract), or a "not a record" namespace note. A bare struct FAILS
//! THE BUILD: layout discipline enforced by a gate, not by review.
//! Wired into `zig build test`; runnable alone as `zig build guards`.
//!
//! Directory walking rides raw getdents64 over the FIXED two-level
//! layout B1 itself mandates (src/, src/core/, src/shell/) — the same
//! kernel-surface doctrine as the cache shell, immune to std.fs churn.
//! This file deliberately declares no module-level structs of its own.

const std = @import("std");
const linux = std.os.linux;
const Allocator = std.mem.Allocator;

const max_file_bytes = 1 << 20;
const body_cap_lines = 400;

pub fn main() !void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var failures: usize = 0;
    var checked: usize = 0;
    for ([_][:0]const u8{ "src", "src/core", "src/shell" }) |dir| {
        scanDir(arena, dir, &failures, &checked);
    }

    if (failures > 0) {
        std.debug.print("check_guards: {d} of {d} module-level structs lack a guard or waiver (A7).\n", .{ failures, checked });
        std.process.exit(1);
    }
    std.debug.print("check_guards: {d} module-level structs — all guarded, waived, or self-sizing.\n", .{checked});
}

fn scanDir(arena: Allocator, dir_path: [:0]const u8, failures: *usize, checked: *usize) void {
    const fd_rc = linux.open(dir_path.ptr, .{ .ACCMODE = .RDONLY, .DIRECTORY = true }, 0);
    const fd_s: isize = @bitCast(fd_rc);
    if (fd_s < 0) return;
    const fd: i32 = @intCast(fd_s);
    defer _ = linux.close(fd);

    var buf: [8192]u8 = undefined;
    while (true) {
        const n_rc = linux.getdents64(fd, &buf, buf.len);
        const n_s: isize = @bitCast(n_rc);
        if (n_s <= 0) break;
        const n: usize = @intCast(n_s);
        var off: usize = 0;
        while (off < n) {
            const reclen = std.mem.readInt(u16, buf[off + 16 ..][0..2], .little);
            const dtype = buf[off + 18];
            const name_z: [*:0]const u8 = @ptrCast(buf[off + 19 ..].ptr);
            const name = std.mem.span(name_z);
            if (dtype == 8 and std.mem.endsWith(u8, name, ".zig")) {
                const full = arena.allocSentinel(u8, dir_path.len + 1 + name.len, 0) catch return;
                @memcpy(full[0..dir_path.len], dir_path);
                full[dir_path.len] = '/';
                @memcpy(full[dir_path.len + 1 ..][0..name.len], name);
                scanFile(arena, full, failures, checked);
            }
            off += reclen;
        }
    }
}

fn scanFile(arena: Allocator, path: [:0]const u8, failures: *usize, checked: *usize) void {
    const text = readFile(arena, path) orelse return;

    var lines: std.ArrayList([]const u8) = .empty;
    var it = std.mem.splitScalar(u8, text, '\n');
    while (it.next()) |line| lines.append(arena, line) catch return;

    for (lines.items, 0..) |line, i| {
        if (!isStructDecl(line)) continue;
        checked.* += 1;
        if (std.mem.indexOf(u8, line, "packed struct(") != null) continue;
        if (accepted(lines.items, i)) continue;
        failures.* += 1;
        std.debug.print("A7 GUARD MISSING: {s}:{d}: {s}\n", .{
            path, i + 1, std.mem.trim(u8, line, " "),
        });
    }
}

fn readFile(arena: Allocator, path: [:0]const u8) ?[]const u8 {
    const fd_rc = linux.open(path.ptr, .{ .ACCMODE = .RDONLY }, 0);
    const fd_s: isize = @bitCast(fd_rc);
    if (fd_s < 0) return null;
    const fd: i32 = @intCast(fd_s);
    defer _ = linux.close(fd);
    var out: std.ArrayList(u8) = .empty;
    var chunk: [64 * 1024]u8 = undefined;
    while (true) {
        const got_rc = linux.read(fd, &chunk, chunk.len);
        const got_s: isize = @bitCast(got_rc);
        if (got_s < 0) return null;
        if (got_s == 0) break;
        const got: usize = @intCast(got_s);
        if (out.items.len + got > max_file_bytes) return null;
        out.appendSlice(arena, chunk[0..got]) catch return null;
    }
    return out.items;
}

/// Module-level record declaration: column 0, `const`/`pub const`, the
/// struct/union keyword on the same line. Tagged (and bare) UNIONS count too —
/// a `union(enum)` held in a collection (e.g. `DrawItem` in a MultiArrayList)
/// is as hot as any struct, so A7 governs it. Missing them was a real blind
/// spot. Indented (function- or test-local) declarations are out of scope on
/// purpose — A7 governs records, and records live at module level here.
fn isStructDecl(line: []const u8) bool {
    if (!std.mem.startsWith(u8, line, "pub const ") and !std.mem.startsWith(u8, line, "const "))
        return false;
    return std.mem.indexOf(u8, line, "= struct {") != null or
        std.mem.indexOf(u8, line, "= extern struct {") != null or
        std.mem.indexOf(u8, line, "= packed struct") != null or
        std.mem.indexOf(u8, line, "= union(") != null or
        std.mem.indexOf(u8, line, "= union {") != null or
        std.mem.indexOf(u8, line, "= extern union {") != null or
        std.mem.indexOf(u8, line, "= packed union") != null;
}

/// A struct passes if the contiguous comment block above it, or its body
/// (to the column-0 closing brace), carries the guard or a named waiver.
fn accepted(lines: []const []const u8, decl_idx: usize) bool {
    var j: usize = decl_idx;
    while (j > 0) {
        const prev = std.mem.trimStart(u8, lines[j - 1], " ");
        if (!std.mem.startsWith(u8, prev, "//")) break;
        j -= 1;
        if (hasToken(lines[j])) return true;
    }
    var has_comptime = false;
    var has_sizeof = false;
    var k = decl_idx + 1;
    const end = @min(lines.len, decl_idx + body_cap_lines);
    while (k < end) : (k += 1) {
        const l = lines[k];
        if (hasToken(l)) return true;
        if (std.mem.indexOf(u8, l, "comptime {") != null) has_comptime = true;
        if (std.mem.indexOf(u8, l, "@sizeOf(") != null) has_sizeof = true;
        if (has_comptime and has_sizeof) return true;
        if (std.mem.startsWith(u8, l, "};")) break;
    }
    return false;
}

fn hasToken(line: []const u8) bool {
    return std.mem.indexOf(u8, line, "A7.2") != null or
        std.mem.indexOf(u8, line, "A1/A7 do not apply") != null;
}
