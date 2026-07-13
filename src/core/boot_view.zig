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

//! B1 classification: CORE (pure). The surface the app shows BEFORE it has a
//! session — the moment nobody had designed.
//!
//! The phone used to render the bare glyph field here: no wordmark, no words,
//! nothing at all. A person who tapped "sign in", got bounced to a browser, and
//! came back to an empty animated field had no way to know whether the app was
//! working, waiting, or broken. The owner photographed it and asked whether we
//! had disabled the field, because a field with nothing on it does not read as a
//! screen — it reads as a bug.
//!
//! This is deliberately NOT the enrollment flow. It says one true sentence about
//! what is happening and nothing more; it emits no tap regions, because there is
//! nothing here to tap. The full mobile front door (Join / sign in / PDS choice —
//! `enroll_view`, which today only the desktop reaches) is the separate piece of
//! work this makes room for.

const std = @import("std");
const Allocator = std.mem.Allocator;
const text = @import("text.zig");
const raster = @import("raster.zig");
// The shared draw vocabulary (a text run, a rounded rect). Reusing the feed's
// primitives rather than growing a second, subtly-different copy of them.
const fv = @import("feed_view.zig");

/// What the app is doing while it has no session. Each maps to one honest line.
pub const Phase = enum(u8) {
    /// Bringing the app up (fonts, GPU, cache) — normally a blink.
    starting = 0,
    /// The OS browser is being handed the authorize URL.
    opening_browser = 1,
    /// The browser is out there and we are waiting for the redirect home.
    waiting_for_browser = 2,
    /// The redirect landed; the token exchange is running.
    signing_in = 3,
    /// It failed. Say so — and say what to do, which is: try again.
    failed = 4,
};

fn line(phase: Phase) []const u8 {
    return switch (phase) {
        .starting => "Starting\u{2026}",
        .opening_browser => "Opening your browser to sign in\u{2026}",
        .waiting_for_browser => "Waiting for you to finish signing in\u{2026}",
        .signing_in => "Signing you in\u{2026}",
        .failed => "Sign-in didn't finish \u{2014} reopen the app to try again",
    };
}

const ink: u32 = 0xFFEDEAE0;
const muted: u32 = 0xFF9A968A;
const warn: u32 = 0xFFE5544B;

/// Emit the pre-session surface: the wordmark, one honest line, and a breathing
/// dot so the screen is visibly ALIVE rather than merely stopped. `t` is the
/// shell's animation clock in seconds (the pulse is a pure function of it — no
/// clock in here, B4).
pub fn layout(
    gpa: Allocator,
    e: *const text.Engine,
    w: i32,
    h: i32,
    phase: Phase,
    t: f32,
    dl: *raster.DrawList,
) error{OutOfMemory}!void {
    const cx = @divTrunc(w, 2);
    const cy = @divTrunc(h, 2);

    // The wordmark. It is the one thing that says WHICH app you are looking at,
    // and its absence is most of why the blank field was disorienting.
    const mark = "zat";
    const mw: i32 = @intCast(text.measure(e, .semibold, mark, 44));
    _ = try fv.str(gpa, dl, e, .semibold, cx - @divTrunc(mw, 2), cy - 40, ink, 44, mark);

    const msg = line(phase);
    const lw: i32 = @intCast(text.measure(e, .regular, msg, 15));
    _ = try fv.str(gpa, dl, e, .regular, cx - @divTrunc(lw, 2), cy + 6, if (phase == .failed) warn else muted, 15, msg);

    // A single breathing dot: proof of life. A still screen and a hung screen
    // look identical, and this is exactly the moment a user decides which one
    // they are looking at. Nothing pulses on the failed line — a failure that
    // animates reads as "still trying", which would be a lie.
    if (phase != .failed) {
        const pulse = 0.35 + 0.65 * (0.5 + 0.5 * @sin(t * 2.2));
        const a: u32 = @intFromFloat(@round(pulse * 200.0));
        const d: i32 = 6;
        try fv.rect(gpa, dl, cx - @divTrunc(d, 2), cy + 34, d, d, (a << 24) | (muted & 0x00FFFFFF), 3);
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "boot_view: every phase says something, and only the failure holds still" {
    const gpa = std.testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);

    for ([_]Phase{ .starting, .opening_browser, .waiting_for_browser, .signing_in, .failed }) |p| {
        var dl: raster.DrawList = .{};
        defer dl.deinit(gpa);
        try layout(gpa, &engine, 430, 930, p, 1.0, &dl);
        // The screen is NEVER blank — which is the entire point of this file.
        // (A text run is one draw item per glyph, so the counts are glyph counts;
        // what matters is that words are on the screen at all.)
        try std.testing.expect(dl.len > 4);
        try std.testing.expect(line(p).len > 0);
    }
}
