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

//! B1 classification: SHELL (process spawn). Hand a URI to the OS default
//! handler — the ONE place Zat4 crosses into another application. Two
//! callers, one seam: the OAuth flow opens `https:` in the browser
//! (shell/oauth.zig), the payment hand-off opens `lightning:`/`bitcoin:`
//! in the user's wallet (M5 A3). Whatever app the user registered for the
//! scheme is the app that opens — no whitelist, no per-wallet integration
//! (PART II §2).
//!
//! Linux: `xdg-open`. macOS: `open`. Windows: ShellExecuteW — NOT `cmd /c
//! start`, which re-parses its command line and mangles the `&`s inside
//! OAuth/LNURL query strings. Failure is ordinary and surfaced to the
//! caller (headless box, no handler registered): callers show the URI so
//! the user can act on it themselves (E4).

const std = @import("std");
const builtin = @import("builtin");

// The Win32 ABI, declared locally (D3) — same doctrine as shell/win32.zig.
extern "shell32" fn ShellExecuteW(
    hwnd: ?*anyopaque,
    operation: ?[*:0]const u16,
    file: [*:0]const u16,
    parameters: ?[*:0]const u16,
    directory: ?[*:0]const u16,
    show_cmd: i32,
) callconv(.winapi) ?*anyopaque;

/// Open `uri` with the OS default handler for its scheme. Blocks only for
/// the handler dispatch, never for the target application.
pub fn openUri(io: std.Io, uri: []const u8) !void {
    if (comptime builtin.os.tag == .windows) {
        // UTF-16 for the OS ABI. A URI is ASCII by construction; the buffer
        // still covers the general case, and overflow is an ordinary launch
        // failure (the caller prints the URI), not a crash.
        var wbuf: [2048]u16 = undefined;
        const n = std.unicode.utf8ToUtf16Le(wbuf[0 .. wbuf.len - 1], uri) catch return error.LaunchFailed;
        if (n >= wbuf.len) return error.LaunchFailed;
        wbuf[n] = 0;
        const verb = std.unicode.utf8ToUtf16LeStringLiteral("open");
        // Per the ABI, the returned pseudo-HINSTANCE is > 32 on success.
        const r = ShellExecuteW(null, verb, wbuf[0..n :0], null, null, 1);
        if (@intFromPtr(r) <= 32) return error.LaunchFailed;
        return;
    }
    const argv: []const []const u8 = if (comptime builtin.os.tag.isDarwin())
        &.{ "open", uri }
    else
        &.{ "xdg-open", uri };
    var child = try std.process.spawn(io, .{
        .argv = argv,
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    _ = child.wait(io) catch {};
}
