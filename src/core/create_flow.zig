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

//! B1 classification: CORE (pure). **The simple-Create flow's heart.** The friendly
//! "make your own feed" path: a few plain-language questions, then a RECAP where the
//! numbers those questions moved are laid bare and freely tweakable — the Fallout
//! SPECIAL-setup feel. It produces a PRIVATE algorithm (just for you), never the
//! marketplace.
//!
//! This module is the pure model the renderer draws and the shell drives: the
//! ordered flow steps, the question catalog (titles + the 3-stop options with
//! plain-language blurbs, `builder.Answers` behind them), the tweakable RECAP knobs
//! (a curated set of real `FeedConfig` numbers, each with a range + step so the UI is
//! just sliders over `knobValue`/`knobSet`), and `finalize` — the config + a name +
//! an accent color → an `algo_library.NewAlgo` (private, its config serialized). The
//! answers still flow through `builder.build`, so a guided feed is the same ordinary
//! `FeedConfig` as any other (invariant 1) — the recap only nudges it further.

const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const discover = @import("discover.zig");
const builder = @import("builder.zig");
const algorithm = @import("algorithm.zig");
const algo_library = @import("algo_library.zig");

/// The ordered steps of the flow. The four questions, then the tweakable recap,
/// then naming + save. The renderer draws one at a time; the shell advances.
pub const Step = enum(u8) { pace, reach, conversation, privacy, recap, name };

/// One selectable option in a question: what the user reads, and a one-line blurb
/// under it. The option INDEX maps to the matching `builder` enum value (same order).
pub const Option = struct { label: []const u8, blurb: []const u8 };

/// One question: its heading, a short prompt, and the 3 (or 2) options. A7.2: cold —
/// a comptime catalog, never held in quantity. Waived.
pub const Question = struct { title: []const u8, prompt: []const u8, options: []const Option };

/// The four questions, in `Step` order (pace, reach, conversation, privacy). The
/// option order matches the `builder` enums exactly, so the chosen index IS the
/// answer. This is the single place the friendly wording for the questionnaire lives.
pub const questions = [_]Question{
    .{ .title = "Pace", .prompt = "How in-the-moment should it feel?", .options = &.{
        .{ .label = "Live", .blurb = "Fresh posts surface fast; early climbers get a lift." },
        .{ .label = "Balanced", .blurb = "The calibrated middle." },
        .{ .label = "Calm", .blurb = "Settled — slow to change, no pile-on spikes." },
    } },
    .{ .title = "Reach", .prompt = "How far beyond the people you follow?", .options = &.{
        .{ .label = "Following", .blurb = "Only accounts you follow." },
        .{ .label = "Balanced", .blurb = "A mix of your follows and discovery." },
        .{ .label = "Discover", .blurb = "Mostly posts from beyond your follows." },
    } },
    .{ .title = "Conversation", .prompt = "How much should replies matter?", .options = &.{
        .{ .label = "Heavy", .blurb = "Surface the threads people actually talk in." },
        .{ .label = "Balanced", .blurb = "The calibrated weighting." },
        .{ .label = "Quiet", .blurb = "Ease off reply pile-ons." },
    } },
    .{ .title = "Privacy", .prompt = "Should it learn from your attention?", .options = &.{
        .{ .label = "Adaptive", .blurb = "Adapts to what you linger on — on your device, never sent anywhere." },
        .{ .label = "Private", .blurb = "Candidate-side only — never looks at your attention." },
    } },
};

/// Set the answer for a question step from a chosen option index (clamped). PURE.
pub fn applyAnswer(answers: *builder.Answers, step: Step, option: usize) void {
    switch (step) {
        .pace => answers.pace = enumFromIndex(builder.Pace, option),
        .reach => answers.reach = enumFromIndex(builder.Reach, option),
        .conversation => answers.conversation = enumFromIndex(builder.Conversation, option),
        .privacy => answers.privacy = enumFromIndex(builder.Privacy, option),
        .recap, .name => {}, // not a question
    }
}

/// The current option index for a question step (so the UI can show the selection).
pub fn answerIndex(answers: builder.Answers, step: Step) usize {
    return switch (step) {
        .pace => @intFromEnum(answers.pace),
        .reach => @intFromEnum(answers.reach),
        .conversation => @intFromEnum(answers.conversation),
        .privacy => @intFromEnum(answers.privacy),
        .recap, .name => 0,
    };
}

fn enumFromIndex(comptime E: type, i: usize) E {
    const n = @typeInfo(E).@"enum".fields.len;
    return @enumFromInt(@as(u8, @intCast(@min(i, n - 1))));
}

/// A tweakable recap KNOB — a curated real `FeedConfig` number the user can nudge on
/// the recap screen, each with a plain label, a range, and a step (the UI is just a
/// slider over `knobValue`/`knobSet`). Deliberately a SMALL, legible set — the knobs
/// a feed's feel actually turns on — not every field.
pub const Knob = enum(u8) {
    like, // w_like
    repost, // w_repost
    reply, // w_reply
    freshness, // recency_half_life_hrs (lower = fresher)
    reach, // query.source_mix (1 = follows only … 0 = discovery)
    adaptive, // behavioral_weight (0 or 1 — learns from attention)
};

/// The display + range metadata for a knob. A7.2: cold — a comptime table. Waived.
pub const KnobMeta = struct { label: []const u8, hint: []const u8, min: f32, max: f32, step: f32 };

pub fn knobMeta(k: Knob) KnobMeta {
    return switch (k) {
        .like => .{ .label = "Likes", .hint = "how much a like counts", .min = 0, .max = 5, .step = 0.5 },
        .repost => .{ .label = "Reposts", .hint = "amplification / reach", .min = 0, .max = 10, .step = 0.5 },
        .reply => .{ .label = "Replies", .hint = "conversation depth", .min = 0, .max = 60, .step = 1 },
        .freshness => .{ .label = "Freshness", .hint = "hours to half-decay; lower is fresher", .min = 0, .max = 48, .step = 1 },
        .reach => .{ .label = "Reach", .hint = "1 = your follows … 0 = discovery", .min = 0, .max = 1, .step = 0.1 },
        .adaptive => .{ .label = "Adaptive", .hint = "learns from your on-device attention", .min = 0, .max = 1, .step = 1 },
    };
}

/// Read a knob's current value out of a config. PURE.
pub fn knobValue(cfg: discover.FeedConfig, k: Knob) f32 {
    return switch (k) {
        .like => cfg.w_like,
        .repost => cfg.w_repost,
        .reply => cfg.w_reply,
        .freshness => cfg.recency_half_life_hrs,
        .reach => cfg.query.source_mix,
        .adaptive => cfg.behavioral_weight,
    };
}

/// Set a knob's value on a config, clamped to its range. PURE. `adaptive` also shuts
/// the behavioral engagement doors when turned to 0, so the privacy label the recap
/// shows stays honest (mirrors `builder`'s `.private` branch).
pub fn knobSet(cfg: *discover.FeedConfig, k: Knob, value: f32) void {
    const m = knobMeta(k);
    const v = std.math.clamp(value, m.min, m.max);
    switch (k) {
        .like => cfg.w_like = v,
        .repost => cfg.w_repost = v,
        .reply => cfg.w_reply = v,
        .freshness => cfg.recency_half_life_hrs = v,
        .reach => cfg.query.source_mix = v,
        .adaptive => {
            cfg.behavioral_weight = v;
            if (v == 0) {
                cfg.w_profile_click = 0;
                cfg.w_link_click = 0;
                cfg.w_bookmark = 0;
            }
        },
    }
}

/// Turn a finished draft into a PRIVATE library algorithm: the config is serialized
/// (the same byte-exact form everything uses), the visibility is private, the creator
/// is you. `id` is the caller-minted local uid; `name`/`color` are the user's. The
/// `ranks` one-liner is derived from the config so the socket cartridge reads well.
/// Allocates in `arena` (the returned `NewAlgo` borrows it). PURE over its inputs.
pub fn finalize(arena: Allocator, cfg: discover.FeedConfig, id: []const u8, name: []const u8, color: u8) Allocator.Error!algo_library.NewAlgo {
    return .{
        .id = id,
        .name = name,
        .ranks = ranksLine(cfg),
        .desc = "",
        .creator = "you",
        .config = try algorithm.serialize(arena, cfg),
        .color = color,
        .visibility = .private,
    };
}

/// A short "what it ranks for" line derived from the config's shape (a static string,
/// no allocation) — enough for the cartridge until the user edits it.
fn ranksLine(cfg: discover.FeedConfig) []const u8 {
    if (cfg.behavioral_weight != 0) return "engagement, adaptive";
    if (cfg.w_reply >= 30) return "conversation-forward";
    return "engagement";
}

// ---------------------------------------------------------------------------
// Tests — pure, leak-checked.
// ---------------------------------------------------------------------------

const t = std.testing;

test "question catalog matches the builder answer enums (option index = answer)" {
    try t.expectEqual(@typeInfo(builder.Pace).@"enum".fields.len, questions[0].options.len);
    try t.expectEqual(@typeInfo(builder.Reach).@"enum".fields.len, questions[1].options.len);
    try t.expectEqual(@typeInfo(builder.Conversation).@"enum".fields.len, questions[2].options.len);
    try t.expectEqual(@typeInfo(builder.Privacy).@"enum".fields.len, questions[3].options.len);
    // Applying an option index sets the matching enum, round-trips through answerIndex.
    var a: builder.Answers = .{};
    applyAnswer(&a, .pace, 2); // Calm
    try t.expectEqual(builder.Pace.calm, a.pace);
    try t.expectEqual(@as(usize, 2), answerIndex(a, .pace));
    applyAnswer(&a, .pace, 99); // clamps to the last option
    try t.expectEqual(builder.Pace.calm, a.pace);
}

test "recap knobs read + write config numbers, clamped" {
    var cfg = builder.build(.{});
    try t.expectEqual(cfg.w_like, knobValue(cfg, .like));
    knobSet(&cfg, .reply, 1000); // clamps to the max (60)
    try t.expectEqual(@as(f32, 60), knobValue(cfg, .reply));
    knobSet(&cfg, .like, -5); // clamps to 0
    try t.expectEqual(@as(f32, 0), cfg.w_like);
    // Turning adaptive off shuts the behavioral doors (label stays honest).
    knobSet(&cfg, .adaptive, 0);
    const transparency = @import("transparency.zig");
    try t.expect(!transparency.classify(cfg).uses_behavioral);
}

test "finalize produces a private algorithm whose config round-trips" {
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var cfg = builder.build(.{ .conversation = .heavy });
    knobSet(&cfg, .like, 2.0);
    const new = try finalize(arena, cfg, "user:7", "My Feed", 5);
    try t.expectEqual(algo_library.Visibility.private, new.visibility);
    try t.expectEqualStrings("you", new.creator);
    try t.expectEqualStrings("My Feed", new.name);
    try t.expectEqual(@as(u8, 5), new.color);
    // The serialized config parses back to the tuned values.
    const back = try algorithm.parse(arena, new.config);
    try t.expectEqual(@as(f32, 2.0), back.w_like);
    try t.expect(back.w_reply >= 30); // conversation=heavy
}
