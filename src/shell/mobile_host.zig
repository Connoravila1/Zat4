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
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const layout_core = @import("../core/layout.zig");
const gesture = @import("../core/gesture.zig");

// Android's log stream (liblog): the run loop's network outcomes narrate
// here on the phone — the status LINE is the desktop's surface, logcat is
// the phone's (`adb logcat -s zat4`). Comptime-pruned to a no-op (and the
// extern never referenced, so nothing links) off Android.
extern "log" fn __android_log_write(prio: c_int, tag: [*:0]const u8, text: [*:0]const u8) c_int;
pub fn logcat(comptime fmt: []const u8, args: anytype) void {
    if (comptime !builtin.abi.isAndroid()) return;
    var buf: [512]u8 = undefined;
    const msg = std.fmt.bufPrintZ(&buf, fmt, args) catch return;
    _ = __android_log_write(4, "zat4", msg); // 4 = ANDROID_LOG_INFO
}

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
    /// The touch-slop state machine's anchors (the pump arm's tap-vs-scroll
    /// disambiguation): the press origin in surface pixels (-1 = no finger
    /// down), whether this press committed to scrolling, and the last
    /// pointer y a scroll delta was taken from. Momentum/fling = M-UX.
    down_x: i32 = -1,
    down_y: i32 = -1,
    scrolling: bool = false,
    /// This press committed to a HORIZONTAL swipe (the phone nav drawer) —
    /// mutually exclusive with `scrolling`; the dominant axis at the slop
    /// threshold decides. The drawer TETHERS to the finger during the drag
    /// (`hswipe_base` = drawer_t at commit); release settles by the
    /// halfway rule.
    hswipe: bool = false,
    hswipe_base: f32 = 0,
    /// This press committed to a socket SWIPE (cycle the seated cartridge on the
    /// closed home socket) — mutually exclusive with hswipe/scrolling. It takes
    /// PRECEDENCE over the nav-drawer swipe: a horizontal drag that starts on the
    /// socket swaps cartridges and never opens the drawer (owner's rule).
    socket_swipe: bool = false,
    /// Which surface's socket the swipe started on, so release cycles the RIGHT
    /// seated cartridge: 0 = home feed, 1 = reply/thread, 2 = zone masthead.
    /// Only meaningful while `socket_swipe` is true.
    socket_swipe_surface: u8 = 0,
    drag_y: i32 = -1,
    /// Soft-keyboard bytes from the seam (the terminal vocabulary: UTF-8
    /// text, 0x08 backspace, '\r' enter) — drained into the pump's byte
    /// stream each frame, exactly like the window backend's key bytes.
    bytes: std.ArrayList(u8) = .empty,
    /// The fling: scroll velocity in LOGICAL px/frame, sampled (smoothed)
    /// while the finger drags and carried when it lifts; friction decays it,
    /// the scroll clamp kills it, and a new touch stops it instantly
    /// (interruptibility is the signature — same doctrine as the chat
    /// bubbles' springs).
    fling_v: f32 = 0,
    /// The active finger's recent samples (logical px, shell-stamped ms) —
    /// the gesture core's velocity estimate reads these at release, so the
    /// drawer settle and the edge bounce start from the finger's REAL speed
    /// (GESTURE_SYSTEM_ROADMAP §2.2/§2.3), not a single-frame delta.
    ring: gesture.SampleRing = .empty,
    /// Feed overscroll past the top/bottom edge, in RAW logical px of finger
    /// travel (the rubber-band curve maps it to displayed give). Nonzero only
    /// while a drag holds the feed past an edge; release hands it to the
    /// bounce spring.
    over_px: f32 = 0,
    /// Sub-pixel scroll carry: `gscroll_px` is an integer, so each move event
    /// would truncate the fractional part of the (physical/scale) logical delta
    /// and lose it — a slow drag (delta < 1 logical px/event) would then scroll
    /// far less than the finger. This holds the lost fraction across events so
    /// the feed tracks the finger 1:1 at every speed. Reset on touch-down.
    scroll_carry: f32 = 0,
    /// The edge-bounce spring channel: displayed overscroll offset + velocity
    /// (logical px, px/s). Active whenever the offset or velocity is nonzero;
    /// integrates toward zero (the edge) via spring.stepScalar.
    bounce_px: f32 = 0,
    bounce_v: f32 = 0,
    /// Press-and-hold to drag (the loadout library → socket, like holding a
    /// home-screen icon): `down_ms` is the shell-stamped ms the finger landed —
    /// the long-press clock — and `hold_fired` latches once a still press past the
    /// threshold has PICKED UP a draggable, which locks the gesture out of scroll/
    /// swipe for its lifetime. Both reset on the next touch-down. The continuous
    /// render loop ticks even on a motionless finger, so the timer fires.
    down_ms: u32 = 0,
    hold_fired: bool = false,
    /// The system BACK (edge swipe / back button), delivered by the activity's
    /// key drain: the pump pops one level of in-app navigation. When there is
    /// nothing left to pop (Home, no overlays), the pump sets `minimize_pending`
    /// and the activity steps the task back to the launcher (moveTaskToBack) —
    /// the Android convention; the process and feed stay hot for the return.
    back_pending: bool = false,
    minimize_pending: bool = false,
    /// The OS claimed the in-flight gesture (ACTION_CANCEL — back edge, shade):
    /// the pump resets its touch machine without firing a tap or a drop.
    touch_cancel: bool = false,
    /// One pending haptic tick, set by the pump the frame a threshold is
    /// CROSSED during a drag (GESTURE_SYSTEM_ROADMAP §3 — the tick lands
    /// under the finger, never on release) and taken (read-and-clear) by the
    /// activity's per-lap poll. 0 none; 1 pull-to-refresh armed; 2 drawer
    /// latch crossed.
    haptic_pending: u8 = 0,
};

pub fn deinit(host: *MobileHost, gpa: Allocator) void {
    host.events.deinit(gpa);
    host.bytes.deinit(gpa);
}

/// Queue one soft-keyboard byte. Dropped on OOM (a missed keystroke, E4).
pub fn pushByte(host: *MobileHost, gpa: Allocator, b: u8) bool {
    host.bytes.append(gpa, b) catch return false;
    return true;
}

/// Move the queued keyboard bytes into the pump's stream.
pub fn drainBytes(host: *MobileHost, gpa: Allocator, out: *std.ArrayList(u8)) !void {
    try out.appendSlice(gpa, host.bytes.items);
    host.bytes.clearRetainingCapacity();
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
