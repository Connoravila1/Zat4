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

//! B1 classification: CORE (pure). **The friendly builder's core — DISCOVER D7.**
//! The user-friendly algorithm creator is a short questionnaire; this is its
//! pure heart: a transform from a handful of plain-language ANSWERS (curated
//! 3-stop scales, never a raw weight) → a `discover.FeedConfig`.
//!
//! The whole point of the design holds here (invariant 1, D6): the friendly
//! builder emits the IDENTICAL `FeedConfig` the developer path and the engine
//! use — there is no second data model. A guided-built feed is just a config,
//! so it serializes, publishes, classifies, and runs exactly like any other.
//! Each answer nudges a small, named group of fields off the calibrated default;
//! the UI shows the question, never the number it moves.

const std = @import("std");
const discover = @import("discover.zig");

/// How fresh vs. settled the feed feels.
pub const Pace = enum { live, balanced, calm };
/// How far beyond your follows it reaches.
pub const Reach = enum { following, balanced, discover };
/// How much conversation (replies) it favors.
pub const Conversation = enum { heavy, balanced, quiet };
/// Whether the feed adapts to your on-device attention, or stays candidate-side.
/// This single answer is what the (system-derived) privacy label keys off
/// (transparency.classify), so the user's choice IS the provable classification.
pub const Privacy = enum { adaptive, private };

/// One filled-in questionnaire. Defaults reproduce the calibrated Discover-ish
/// feel, so an untouched builder yields a sensible feed. A7.2: cold — one per
/// builder session, never a hot loop. Size guard waived.
pub const Answers = struct {
    pace: Pace = .balanced,
    reach: Reach = .balanced,
    conversation: Conversation = .balanced,
    privacy: Privacy = .adaptive,
};

/// Map answers onto a config. PURE. Starts from the calibrated default and
/// applies each answer's small, legible edit — the only place the friendly
/// vocabulary becomes numbers. The result is an ordinary `FeedConfig`: it can be
/// explained, classified, serialized, published, and run with no special path.
pub fn build(answers: Answers) discover.FeedConfig {
    var c = discover.DEFAULT_CONFIG;

    switch (answers.pace) {
        .live => { // in-the-moment: fresh decays fast, early climbers boosted
            c.recency_half_life_hrs = 3.0;
            c.velocity_boost = true;
        },
        .balanced => {}, // the calibrated default
        .calm => { // settled: slow decay, no velocity spike
            c.recency_half_life_hrs = 24.0;
            c.velocity_boost = false;
        },
    }

    c.query.source_mix = switch (answers.reach) {
        .following => 1.0, // only accounts you follow
        .balanced => 0.5, // the calibrated mix
        .discover => 0.2, // mostly beyond your follows
    };

    switch (answers.conversation) {
        .heavy => { // surface threads people actually talk in
            c.w_reply = 40.0;
            c.w_reply_chain = 200.0;
        },
        .balanced => {}, // the calibrated weights (27 / 150)
        .quiet => { // de-emphasize reply pile-ons
            c.w_reply = 13.0;
            c.w_reply_chain = 75.0;
        },
    }

    switch (answers.privacy) {
        .adaptive => { // learn from on-device attention (clicks stay on too)
            c.behavioral_weight = 1.0;
        },
        .private => { // candidate-side ONLY — every behavioral door shut
            c.behavioral_weight = 0.0;
            c.w_profile_click = 0.0;
            c.w_link_click = 0.0;
            c.w_bookmark = 0.0;
        },
    }

    return c;
}

// ---------------------------------------------------------------------------
// Tests — pure (B2), leak-free (no allocation at all)
// ---------------------------------------------------------------------------

const transparency = @import("transparency.zig");

test "build: defaults yield the calibrated baseline" {
    const c = build(.{});
    try std.testing.expectEqual(discover.DEFAULT_CONFIG.w_reply, c.w_reply);
    try std.testing.expectEqual(@as(f32, 0.5), c.query.source_mix);
    // The default answer is adaptive → it learns.
    try std.testing.expect(transparency.classify(c).learns);
}

test "build: pace moves freshness + velocity, not engagement weights" {
    const live = build(.{ .pace = .live });
    try std.testing.expectEqual(@as(f32, 3.0), live.recency_half_life_hrs);
    try std.testing.expect(live.velocity_boost);

    const calm = build(.{ .pace = .calm });
    try std.testing.expectEqual(@as(f32, 24.0), calm.recency_half_life_hrs);
    try std.testing.expect(!calm.velocity_boost);
    // Engagement weights are untouched by pace.
    try std.testing.expectEqual(discover.DEFAULT_CONFIG.w_like, calm.w_like);
}

test "build: reach sets the source mix across its scale" {
    try std.testing.expectEqual(@as(f32, 1.0), build(.{ .reach = .following }).query.source_mix);
    try std.testing.expectEqual(@as(f32, 0.2), build(.{ .reach = .discover }).query.source_mix);
}

test "build: conversation raises or trims reply weighting" {
    const heavy = build(.{ .conversation = .heavy });
    const quiet = build(.{ .conversation = .quiet });
    try std.testing.expect(heavy.w_reply > quiet.w_reply);
    try std.testing.expect(heavy.w_reply_chain > quiet.w_reply_chain);
}

test "build: the privacy answer IS the provable classification (ties #3 to #2)" {
    // Private → classify proves no behavioral data; adaptive → it learns. The
    // user's plain choice becomes a system-PROVEN label, not a claim (invariant 6).
    const private = build(.{ .privacy = .private });
    const pc = transparency.classify(private);
    try std.testing.expect(!pc.uses_behavioral);
    try std.testing.expect(!pc.learns);

    const adaptive = build(.{ .privacy = .adaptive });
    const ac = transparency.classify(adaptive);
    try std.testing.expect(ac.uses_behavioral and ac.learns);
}

test "build: output is an ordinary config — sane under validation, no special path" {
    // A guided-built config survives the same validation any config does (E2/E4):
    // it is already in range, so validation is a no-op on the fields it sets.
    const c = build(.{ .pace = .calm, .reach = .discover, .conversation = .quiet, .privacy = .private });
    const v = discover.validated(c);
    try std.testing.expectEqual(c.w_reply, v.w_reply);
    try std.testing.expectEqual(c.query.source_mix, v.query.source_mix);
}
