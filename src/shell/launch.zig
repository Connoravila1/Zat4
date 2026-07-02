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
//! Linux: `xdg-open`. (mac `open` / win `start` are the cross-platform
//! follow-ups, same posture as the GPU seam.) Failure is ordinary and
//! surfaced to the caller (headless box, no handler registered): callers
//! show the URI so the user can act on it themselves (E4).

const std = @import("std");

/// Open `uri` with the OS default handler for its scheme. Blocks only for
/// the handler dispatch (xdg-open execs and exits), never for the target
/// application.
pub fn openUri(io: std.Io, uri: []const u8) !void {
    var child = try std.process.spawn(io, .{
        .argv = &.{ "xdg-open", uri },
        .stdin = .ignore,
        .stdout = .ignore,
        .stderr = .ignore,
    });
    _ = child.wait(io) catch {};
}
