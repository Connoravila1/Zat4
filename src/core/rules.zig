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

//! B1 classification: CORE (pure). **The bounded rule-list — DISCOVER Level 2.**
//! The first step past flat weights into LOGIC a creator authors: a list of
//! `{predicate, action}` rules — *"if a post is out-of-network and has high
//! engagement, boost it; if it is link-only, drop it."* This is real per-creator
//! logic (two creators' rule-lists rank the same pool differently in ways flat
//! weights cannot express), and it is SAFE BY CONSTRUCTION: a predicate and an
//! action are each one value of a FIXED enum vocabulary the engine exposes, so a
//! rule can only compose primitives the engine already has — it can never do
//! anything arbitrary, reach off-device, or run code. That property (logic
//! without an interpreter) is exactly what makes the rule-list shippable long
//! before the executable sandbox (Level 3).
//!
//! This module is the data model + the pure evaluator only. It is decoupled from
//! the candidate store: a caller fills a plain `Facts` from whatever it holds and
//! asks `apply` to adjust a base score. Integration into the scorer, into the
//! serialized config record, and into the transparency page (rules rendered as
//! readable logic) are the following slices.

const std = @import("std");
const assert = std.debug.assert;

/// The condition a rule tests. A FIXED vocabulary — the engine's exposed
/// primitives, nothing more. Each kind reads facts the engine can supply about a
/// candidate; the `param` carries a threshold where one is meaningful (e.g.
/// `min_likes` ⇒ "likes ≥ param"), and is ignored otherwise.
pub const PredicateKind = enum(u8) {
    always, // matches every candidate (an unconditional rule)
    in_network, // the post is from an account you follow
    out_of_network, // the post is a discovery candidate
    min_likes, // like_count ≥ param
    min_reposts, // repost_count ≥ param
    min_replies, // reply_count ≥ param
    min_engagement, // likes + reposts + replies ≥ param
    newer_than_hrs, // age < param hours
    older_than_hrs, // age ≥ param hours
};

/// What a matching rule DOES. Also a fixed vocabulary. `boost`/`dampen` are the
/// same multiply, named for readable authoring intent (a creator writes "boost
/// 1.5" or "dampen 0.5"); `exclude` drops the candidate from the pool.
pub const ActionKind = enum(u8) {
    boost, // score ×= factor (factor > 1 to lift)
    dampen, // score ×= factor (factor < 1 to suppress)
    exclude, // remove the candidate entirely
};

/// A condition. `kind` + an optional numeric threshold.
pub const Predicate = struct {
    kind: PredicateKind,
    param: f32 = 0,

    comptime {
        // Budget 8: enum(u8) + f32, the f32's 4-byte alignment padding the tag.
        assert(@sizeOf(Predicate) == 8);
    }
};

/// An effect. `kind` + a multiply factor (unused for `exclude`).
pub const Action = struct {
    kind: ActionKind,
    factor: f32 = 1.0,

    comptime {
        assert(@sizeOf(Action) == 8);
    }
};

/// One authored rule: when `predicate` holds for a candidate, apply `action`.
/// Evaluated in a loop over candidates × rules, so it is hot — guarded (A7).
pub const Rule = struct {
    predicate: Predicate,
    action: Action,

    comptime {
        // Budget 16: two 8-byte halves, packed exactly.
        assert(@sizeOf(Rule) == 16);
    }
};

/// The candidate facts a predicate can read — a plain value the caller fills
/// from its own store (so this module stays decoupled from `discover.Candidate`
/// and the in-network bitset). `age_hrs` is precomputed by the caller from `now`
/// (the clock never enters here — B4).
/// A7.2: cold — one is built per candidate at the call site and passed by value,
/// never held in a collection here. Size guard waived.
pub const Facts = struct {
    in_network: bool,
    like_count: u32,
    repost_count: u32,
    reply_count: u32,
    age_hrs: f64,
};

/// Does this predicate hold for these facts? Pure, total.
pub fn matches(p: Predicate, f: Facts) bool {
    return switch (p.kind) {
        .always => true,
        .in_network => f.in_network,
        .out_of_network => !f.in_network,
        .min_likes => @as(f64, @floatFromInt(f.like_count)) >= p.param,
        .min_reposts => @as(f64, @floatFromInt(f.repost_count)) >= p.param,
        .min_replies => @as(f64, @floatFromInt(f.reply_count)) >= p.param,
        .min_engagement => @as(f64, @floatFromInt(f.like_count + f.repost_count + f.reply_count)) >= p.param,
        .newer_than_hrs => f.age_hrs < p.param,
        .older_than_hrs => f.age_hrs >= p.param,
    };
}

/// Apply a rule-list to one candidate's base score. Rules are evaluated IN ORDER
/// (later rules see earlier rules' effect on the score), so authoring order is
/// meaningful — the same composition logic the engine already uses. Returns the
/// adjusted score, or `null` when a matching `exclude` removes the candidate from
/// the pool. Pure; no allocation.
pub fn apply(rules: []const Rule, f: Facts, base_score: f64) ?f64 {
    var score = base_score;
    for (rules) |r| {
        if (!matches(r.predicate, f)) continue;
        switch (r.action.kind) {
            // Defensive: a non-finite factor from a hostile/malformed rule is a
            // no-op (it cannot poison the score with NaN/Inf), and the factor is
            // clamped to a sane range. So a shared rule-list is safe to run
            // without a separate validation pass (E2/E4).
            .boost, .dampen => {
                const fac: f64 = r.action.factor;
                if (std.math.isFinite(fac)) score *= std.math.clamp(fac, 0.0, 1_000_000.0);
            },
            .exclude => return null,
        }
    }
    return score;
}

// ---------------------------------------------------------------------------
// Tests — pure (B2), no allocation
// ---------------------------------------------------------------------------

const popular_oon: Facts = .{ .in_network = false, .like_count = 100, .repost_count = 10, .reply_count = 30, .age_hrs = 2.0 };
const quiet_in: Facts = .{ .in_network = true, .like_count = 2, .repost_count = 0, .reply_count = 0, .age_hrs = 1.0 };

test "matches: the predicate vocabulary reads candidate facts" {
    const t = std.testing;
    try t.expect(matches(.{ .kind = .always }, quiet_in));
    try t.expect(matches(.{ .kind = .out_of_network }, popular_oon));
    try t.expect(!matches(.{ .kind = .out_of_network }, quiet_in));
    try t.expect(matches(.{ .kind = .min_engagement, .param = 100 }, popular_oon)); // 140 ≥ 100
    try t.expect(!matches(.{ .kind = .min_engagement, .param = 100 }, quiet_in)); // 2 < 100
    try t.expect(matches(.{ .kind = .newer_than_hrs, .param = 6 }, popular_oon)); // 2h < 6h
}

test "apply: a boost rule lifts a matching candidate, leaves others untouched" {
    const t = std.testing;
    // "Boost strong discovery posts 1.5×."
    const rules = [_]Rule{.{
        .predicate = .{ .kind = .out_of_network },
        .action = .{ .kind = .boost, .factor = 1.5 },
    }};
    try t.expectEqual(@as(?f64, 150.0), apply(&rules, popular_oon, 100.0)); // boosted
    try t.expectEqual(@as(?f64, 100.0), apply(&rules, quiet_in, 100.0)); // in-network: untouched
}

test "apply: an exclude rule drops the candidate from the pool" {
    const t = std.testing;
    // "Hide low-engagement out-of-network noise."
    const rules = [_]Rule{.{
        .predicate = .{ .kind = .out_of_network },
        .action = .{ .kind = .exclude },
    }};
    try t.expectEqual(@as(?f64, null), apply(&rules, popular_oon, 100.0)); // excluded
    try t.expectEqual(@as(?f64, 50.0), apply(&rules, quiet_in, 50.0)); // kept
}

test "apply: rules compose in order — a later rule sees the earlier one's effect" {
    const t = std.testing;
    const rules = [_]Rule{
        .{ .predicate = .{ .kind = .always }, .action = .{ .kind = .boost, .factor = 2.0 } },
        .{ .predicate = .{ .kind = .min_replies, .param = 10 }, .action = .{ .kind = .dampen, .factor = 0.5 } },
    };
    // popular_oon (30 replies): ×2 then ×0.5 = ×1 → 100.
    try t.expectEqual(@as(?f64, 100.0), apply(&rules, popular_oon, 100.0));
    // quiet_in (0 replies): only the first rule → ×2 = 200.
    try t.expectEqual(@as(?f64, 200.0), apply(&rules, quiet_in, 100.0));
}

test "apply: an empty rule-list is the identity (a config with no rules is unchanged)" {
    const t = std.testing;
    try t.expectEqual(@as(?f64, 42.0), apply(&.{}, popular_oon, 42.0));
}
