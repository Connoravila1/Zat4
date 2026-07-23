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

//! B1 classification: CORE (pure). Congestion control / bandwidth estimation
//! for Zat Chat calling — a Google-Congestion-Control-style controller that
//! turns transport feedback (delay trend + loss + measured throughput) into a
//! target send bitrate. Its output is exactly the
//! `call_decision.CallMetrics.network_bandwidth_estimate_kbps` the adaptive
//! brain (§4) clamps video against, so this closes the sender-rate loop the
//! "build it ourselves" ruling put in our hands (ZAT_CHAT_CALLING_ROADMAP.md
//! §3 #9, §6.2).
//!
//! PURE (B2/B3/B4): no clock, no RNG, no I/O. The shell measures each feedback
//! interval (RTT, loss fraction, the inter-arrival delay gradient, and the
//! acknowledged throughput — RTP timing the shell already has) and hands them
//! in as a `Feedback` value; the controller returns a new target and advances
//! its own small state. Deterministic, so it is golden-testable headlessly (see
//! the tests at the foot).
//!
//! The design combines two controllers and takes the minimum, per GCC:
//!  - delay-based: an over-use detector on the delay gradient drives AIMD —
//!    multiplicative decrease toward the measured throughput on over-use,
//!    increase when the path is normal, hold when it is draining (under-use);
//!  - loss-based: the classic WebRTC rule — cut on >10% loss, raise under 2%,
//!    hold between.
//! The adaptive over-use threshold is a v1 constant; making it self-tuning
//! (Kalman/trendline) is a named refinement, not required for a working loop.

const std = @import("std");
const assert = std.debug.assert;

/// The send-rate floor (kbps): the audio floor plus a minimal video sliver, so
/// the estimate never collapses to zero while a call is up.
pub const min_bitrate_kbps: u32 = 50;
/// The 1:1 send-rate ceiling (kbps). Group calling would raise this behind the
/// sealed transport interface.
pub const max_bitrate_kbps: u32 = 2500;

/// Default over-use threshold on the delay gradient (ms), GCC's `del_var_th`
/// starting point. v1 keeps it fixed; a self-tuning threshold is a refinement.
pub const default_threshold_ms: f32 = 12.5;

/// The delay-based over-use detector's verdict for the last interval.
pub const BandwidthUsage = enum(u8) { normal, overusing, underusing };

/// PLAIN DATA (A1). One feedback interval's measurements, from the shell. A7.2:
/// cold struct, size guard waived — a transient input, never held in bulk.
pub const Feedback = struct {
    rtt_ms: u16,
    loss_fraction: f32, // 0.0 .. 1.0 of packets lost this interval
    delay_gradient_ms: f32, // signed trend of inter-arrival delay (+ = queue building)
    acked_bitrate_kbps: u32, // throughput actually delivered this interval
};

/// PLAIN DATA (A1). The controller's state. One per sending stream — guarded
/// under the tie-break rule. Behaviour is in the free functions below (A1).
pub const Controller = struct {
    target_kbps: u32, // the current send-rate target (the estimate)
    threshold_ms: f32, // over-use threshold on the delay gradient
    delay_state: BandwidthUsage, // last delay-detector verdict
    _pad: [3]u8 = [_]u8{0} ** 3, // A6: explicit pad to the 4-byte boundary

    comptime {
        // Budget: u32 + f32 = 8, then enum(u8) + pad[3] = 4. 12 exact, align 4.
        assert(@sizeOf(Controller) == 12);
    }
};

/// Start a controller at an initial guess (clamped into range).
pub fn init(start_kbps: u32) Controller {
    return .{
        .target_kbps = std.math.clamp(start_kbps, min_bitrate_kbps, max_bitrate_kbps),
        .threshold_ms = default_threshold_ms,
        .delay_state = .normal,
    };
}

/// Apply one interval of feedback and return the new target bitrate (kbps).
/// The target is the minimum of the delay-based and loss-based controllers,
/// clamped to `[min_bitrate_kbps, max_bitrate_kbps]`.
pub fn update(c: *Controller, fb: Feedback) u32 {
    // --- delay-based over-use detector -> AIMD --------------------------------
    if (fb.delay_gradient_ms > c.threshold_ms) {
        c.delay_state = .overusing;
    } else if (fb.delay_gradient_ms < -c.threshold_ms) {
        c.delay_state = .underusing;
    } else {
        c.delay_state = .normal;
    }

    const delay_target: u32 = switch (c.delay_state) {
        // Decrease toward what actually got through (fall back to the target if
        // no throughput was measured), the GCC multiplicative-decrease rule.
        .overusing => blk: {
            const base = if (fb.acked_bitrate_kbps > 0) fb.acked_bitrate_kbps else c.target_kbps;
            break :blk scale(base, 0.85);
        },
        // Climb while the path is healthy (multiplicative increase).
        .normal => scale(c.target_kbps, 1.08),
        // Queue draining: hold and let it clear.
        .underusing => c.target_kbps,
    };

    // --- loss-based controller (classic WebRTC rule) --------------------------
    var loss_target: u32 = c.target_kbps;
    if (fb.loss_fraction > 0.10) {
        loss_target = scale(c.target_kbps, 1.0 - 0.5 * fb.loss_fraction);
    } else if (fb.loss_fraction < 0.02) {
        loss_target = scale(c.target_kbps, 1.05);
    }

    // --- combine: the more conservative of the two wins ----------------------
    const combined = @min(delay_target, loss_target);
    c.target_kbps = std.math.clamp(combined, min_bitrate_kbps, max_bitrate_kbps);
    return c.target_kbps;
}

fn scale(v: u32, factor: f32) u32 {
    const r = @as(f32, @floatFromInt(v)) * factor;
    if (r <= 0) return 0;
    return @intFromFloat(@round(r));
}

// ---------------------------------------------------------------------------
// Tests (B2/C6 — deterministic; no allocator needed)
// ---------------------------------------------------------------------------

const testing = std.testing;

fn clean(acked: u32) Feedback {
    return .{ .rtt_ms = 30, .loss_fraction = 0.0, .delay_gradient_ms = 0.0, .acked_bitrate_kbps = acked };
}

test "a clean path climbs toward the ceiling and clamps there" {
    var c = init(500);
    var prev = c.target_kbps;
    var i: usize = 0;
    while (i < 100) : (i += 1) {
        const now = update(&c, clean(c.target_kbps));
        try testing.expect(now >= prev); // never decreases on a clean path
        prev = now;
    }
    try testing.expectEqual(max_bitrate_kbps, c.target_kbps); // pinned at the ceiling
}

test "a rising delay gradient triggers over-use and cuts the rate below throughput" {
    var c = init(1500);
    const acked: u32 = 1400;
    const now = update(&c, .{ .rtt_ms = 80, .loss_fraction = 0.0, .delay_gradient_ms = 40.0, .acked_bitrate_kbps = acked });
    try testing.expectEqual(BandwidthUsage.overusing, c.delay_state);
    try testing.expect(now < acked); // decreased toward, then below, measured throughput
    try testing.expectEqual(@as(u32, @intFromFloat(@round(@as(f32, 1400) * 0.85))), now);
}

test "heavy loss cuts the rate even when delay looks fine" {
    var c = init(1000);
    const now = update(&c, .{ .rtt_ms = 40, .loss_fraction = 0.20, .delay_gradient_ms = 0.0, .acked_bitrate_kbps = 1000 });
    // loss rule: 1000 * (1 - 0.5*0.2) = 900; delay rule (normal) would raise to
    // 1080, so the loss controller wins via the min().
    try testing.expectEqual(@as(u32, 900), now);
}

test "the estimate recovers after congestion clears" {
    var c = init(1500);
    _ = update(&c, .{ .rtt_ms = 90, .loss_fraction = 0.0, .delay_gradient_ms = 50.0, .acked_bitrate_kbps = 1200 });
    const dropped = c.target_kbps;
    try testing.expect(dropped < 1500);
    // Several clean intervals bring it back up.
    var i: usize = 0;
    while (i < 5) : (i += 1) _ = update(&c, clean(c.target_kbps));
    try testing.expect(c.target_kbps > dropped);
}

test "the target never leaves [min, max]" {
    var c = init(min_bitrate_kbps);
    // Hammer with loss to try to drive it under the floor.
    var i: usize = 0;
    while (i < 50) : (i += 1) _ = update(&c, .{ .rtt_ms = 200, .loss_fraction = 0.9, .delay_gradient_ms = 100.0, .acked_bitrate_kbps = 10 });
    try testing.expect(c.target_kbps >= min_bitrate_kbps);
    try testing.expect(c.target_kbps <= max_bitrate_kbps);
}

test "update is deterministic (B2)" {
    var a = init(700);
    var b = init(700);
    const fb: Feedback = .{ .rtt_ms = 55, .loss_fraction = 0.05, .delay_gradient_ms = 3.0, .acked_bitrate_kbps = 680 };
    try testing.expectEqual(update(&a, fb), update(&b, fb));
    try testing.expectEqual(a.target_kbps, b.target_kbps);
}
