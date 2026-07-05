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

//! B1 classification: SHELL. The MOBILE host surface — the third `Backend`
//! arm's payload (M_CORE_INVERSION MC.4b). Where the X11 window pumps its
//! own socket, a phone's OS owns the loop and hands us input through the
//! C-ABI seam (src/mobile.zig): the shim pushes plain `InputEvent`s here
//! between frames, and stepFrame's mobile pump arm DRAINS them — no wait,
//! no OS call, no X11 anywhere in the arm (the driver waits in the
//! choreographer; stepFrame gets wait budget 0).
//!
//! Plain data on purpose (E1): the seam thread and the step run on the SAME
//! thread by the seam's documented contract (mobile.zig header), so this is
//! a queue in the shape sense only — no lock needed, and none is pretended.

const std = @import("std");
const Allocator = std.mem.Allocator;
const layout_core = @import("../core/layout.zig");

/// The OS-owned surface as the frame step sees it. One per app process,
/// owned by the seam's Ctx; the step reads dims and drains events.
/// A7.2: cold struct, size guard waived — exactly one per app process.
pub const MobileHost = struct {
    /// Surface pixel geometry — written by the seam on attach/resize,
    /// read by the step for layout + viewport.
    width_px: u32 = 0,
    height_px: u32 = 0,
    /// Input pushed across the seam since the last step; drained (moved
    /// out) by the pump arm each frame, so a motion flood never
    /// accumulates past one frame.
    events: std.ArrayList(layout_core.InputEvent) = .empty,
    /// The OS asked us to leave (activity finishing). The pump arm maps
    /// it to the same exit as a window close.
    closed: bool = false,
    /// The live drag's last pointer y in surface pixels, or -1 when no
    /// finger is down — the v1 touch-scroll anchor (the pump arm turns
    /// move deltas into pixel scroll; momentum/fling is the M-UX pass).
    drag_y: i32 = -1,
};

pub fn deinit(host: *MobileHost, gpa: Allocator) void {
    host.events.deinit(gpa);
}

/// Queue one event from the seam. A dropped event on OOM is a missed tap,
/// never a crash across the ABI (E2/E4) — false reports the drop.
pub fn push(host: *MobileHost, gpa: Allocator, ev: layout_core.InputEvent) bool {
    host.events.append(gpa, ev) catch return false;
    return true;
}

/// Move all pending events into `out` (the pump arm's per-frame list).
pub fn drain(host: *MobileHost, gpa: Allocator, out: *std.ArrayList(layout_core.InputEvent)) error{OutOfMemory}!void {
    try out.appendSlice(gpa, host.events.items);
    host.events.clearRetainingCapacity();
}

// ---------------------------------------------------------------------------
// Tests (C6)
// ---------------------------------------------------------------------------

const testing = std.testing;

test "host: push then drain moves events and empties the queue" {
    const gpa = testing.allocator;
    var host: MobileHost = .{ .width_px = 1080, .height_px = 2400 };
    defer deinit(&host, gpa);

    try testing.expect(push(&host, gpa, .{ .x = 10, .y = 20, .kind = .button_down, .button = 1, .mods = 0, ._pad = 0 }));
    try testing.expect(push(&host, gpa, .{ .x = 10, .y = 21, .kind = .button_up, .button = 1, .mods = 0, ._pad = 0 }));

    var out: std.ArrayList(layout_core.InputEvent) = .empty;
    defer out.deinit(gpa);
    try drain(&host, gpa, &out);
    try testing.expectEqual(@as(usize, 2), out.items.len);
    try testing.expectEqual(layout_core.InputEvent.Kind.button_down, out.items[0].kind);
    try testing.expectEqual(@as(usize, 0), host.events.items.len);
}
