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

//! B1 classification: CORE (pure). Relative-age formatting — the SINGLE source
//! for "now / 5m / 3h / 2d / 1w" so the premium feed view and the TUI cannot
//! drift apart (D6). It exists as its own one-function module precisely so a
//! caller can format an age WITHOUT pulling a whole UI module into its graph
//! (the reason feed_view used to keep a private copy). Pure arithmetic; `now`
//! always arrives as an argument (B2/B4 — no clock). Both times are unix
//! SECONDS, the project-wide unit for `created_at`.

const std = @import("std");

/// Format the age of `created` relative to `now` (both unix seconds) into
/// `buf`, returning the written slice. Coarsens by unit: under a minute reads
/// "now", then m / h / d / w. A non-positive delta (clock skew, or a record
/// stamped in the future) reads as "now" rather than a negative age.
pub fn format(buf: []u8, now: i64, created: i64) []const u8 {
    const d = if (now > created) now - created else 0;
    if (d < 60) return std.fmt.bufPrint(buf, "now", .{}) catch "";
    if (d < 3_600) return std.fmt.bufPrint(buf, "{d}m", .{@divFloor(d, 60)}) catch "";
    if (d < 86_400) return std.fmt.bufPrint(buf, "{d}h", .{@divFloor(d, 3_600)}) catch "";
    if (d < 604_800) return std.fmt.bufPrint(buf, "{d}d", .{@divFloor(d, 86_400)}) catch "";
    return std.fmt.bufPrint(buf, "{d}w", .{@divFloor(d, 604_800)}) catch "";
}

test "format coarsens by unit and floors negatives to now" {
    var b: [16]u8 = undefined;
    try std.testing.expectEqualStrings("now", format(&b, 1_000, 1_000));
    try std.testing.expectEqualStrings("now", format(&b, 1_000, 1_030)); // future -> now
    try std.testing.expectEqualStrings("5m", format(&b, 1_000, 1_000 - 5 * 60));
    try std.testing.expectEqualStrings("3h", format(&b, 100_000, 100_000 - 3 * 3_600));
    try std.testing.expectEqualStrings("2d", format(&b, 1_000_000, 1_000_000 - 2 * 86_400));
    try std.testing.expectEqualStrings("4w", format(&b, 10_000_000, 10_000_000 - 4 * 604_800));
}
