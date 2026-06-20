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

//! B1 classification: SHELL. GPU smoke test (`zig build gpu-smoke`).
//!
//! The foundation check for the GPU backend: open the real X11 window, bring
//! up an EGL/GLES2 context on it, and clear it to a slowly shifting colour so
//! motion is obvious. This isolates the one thing that cannot be verified in
//! the build sandbox — whether a GL context comes up on our hand-rolled X
//! window on real hardware — from all the renderer work that builds on it.
//!
//! What a successful run looks like: a window whose background pulses through
//! dark teal/violet, plus "[gpu] context is current" on stderr. If it stops,
//! the "[gpu] <step> FAILED" line names the exact EGL call and error code.

const std = @import("std");
const window_shell = @import("shell/native.zig");
const gpu = @import("shell/gpu.zig");
const layout = @import("core/layout.zig"); // InputEvent type for pump

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const env = init.environ_map;

    const win = window_shell.open(gpa, env, "zat-gpu-smoke", 110, 32) catch |err| {
        std.debug.print("window.open failed: {s} (on X11, is DISPLAY set?)\n", .{@errorName(err)});
        return;
    };
    defer window_shell.close(win);
    std.debug.print("window opened: wid=0x{x} fd={d} depth={d} fb={d}x{d}\n", .{ win.wid, win.fd, win.root_depth, win.fb.width, win.fb.height });

    var g = gpu.init(win.wid) catch {
        std.debug.print("GPU init failed — see [gpu] lines above for the exact step.\n", .{});
        return;
    };
    defer gpu.deinit(&g);
    gpu.setViewport(@intCast(win.fb.width), @intCast(win.fb.height));

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var events: std.ArrayList(layout.InputEvent) = .empty;
    defer events.deinit(gpa);

    var t: f32 = 0;
    var frames: u32 = 0;
    while (true) {
        const pr = window_shell.pump(win, 16, gpa, &out, &events) catch break;
        if (pr.closed) break;
        if (pr.resized) gpu.setViewport(@intCast(win.fb.width), @intCast(win.fb.height));

        const r = 0.10 + 0.10 * @sin(t);
        const gg = 0.12 + 0.10 * @sin(t + 2.094);
        const b = 0.14 + 0.12 * @sin(t + 4.188);
        gpu.clear(r, gg, b);
        gpu.swap(&g);

        t += 0.03;
        frames += 1;
        if (frames > 3600) break; // ~60s safety cap
    }
    std.debug.print("gpu smoke done ({d} frames). If you saw a pulsing window, the GPU path works.\n", .{frames});
}
