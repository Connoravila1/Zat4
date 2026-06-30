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

//! B1 classification: CORE (pure). **The on-device learner — Phase D9, Tier 2.**
//! The engine-owned adaptive loop every config rides on: it turns a user's
//! BEHAVIORAL signal (dwell/attention — never published, invariant 3) into a
//! bounded per-user preference state, and reads that state back as the
//! per-candidate `behavioral` signal the scorer already reserves
//! (`discover.Candidate.behavioral`, multiplied through `FeedConfig.behavioral_
//! weight`). Authors compete on the starting policy; this ONE shared learner
//! adapts it to each person (the Tier-2 thesis).
//!
//! Everything here is PURE (B2/B4): no clock, no randomness, no I/O. The SHELL
//! owns the impure legs — capturing real dwell/scroll into `intensity` values,
//! choosing exploration draws from `explorationWeight`, and persisting the
//! vector to on-device storage within the algorithm's declared state budget.
//! The learner only ever produces NUMBERS; it has no primitive to move anything
//! off-device (invariant 4 — capability denial, not policy). That is what makes
//! "behavioral data never leaves the device" a structural fact here, not a
//! promise: the vector is bounded, on-device, and feeds a score, nothing else.
//!
//! Privacy, by construction:
//!   * **Bounded state.** The preference vector is a FIXED `[pref_dim]f32` —
//!     its exact byte size is guarded (A7), which IS the D9/D11 "bound the
//!     per-user state" side-channel mitigation made structural: per-refresh
//!     leakage is finite because the state is finite.
//!   * **Feature hashing.** Features (a post's zone tags, its author) hash into
//!     buckets, so the vector size is independent of how many topics/authors
//!     exist, and a bucket is a blurred mix — not a legible dossier.
//!   * **The doorway, not this module, enforces the tier.** A "no behavioral
//!     data" algorithm (Discover Private) is simply never handed a vector and
//!     its `behavioral_weight` is 0; it cannot consult what it was never given
//!     (invariant 6). This module makes the signal possible; the doorway decides
//!     who may see it.

const std = @import("std");
const assert = std.debug.assert;

/// Number of buckets in the preference vector. A power of two so a feature hash
/// maps with a mask. 256 × f32 = 1 KiB — negligible against the per-algorithm
/// state budget (`discover.state_budget_hard_cap`), and the exact size is the
/// bounded-state guarantee. Raising it trades a bigger (still tiny) state for
/// fewer feature collisions — a calibration knob, not a correctness one.
pub const pref_dim: usize = 256;

/// Per-user, per-algorithm affinity state: a bounded bag of feature weights.
/// PLAIN DATA (A1) — the free functions below are the behavior. On-device only;
/// the shell persists it within the algorithm's state budget and never sends it
/// anywhere (invariant 3/4).
pub const PrefVector = struct {
    buckets: [pref_dim]f32 = [_]f32{0} ** pref_dim,

    comptime {
        // Budget 1024: pref_dim × f32, exactly. This guard IS the "bound the
        // per-user state" side-channel mitigation (D9/D11) made structural — the
        // state cannot silently grow, so per-refresh leakage stays finite. (A7;
        // raising pref_dim is a deliberate, recorded calibration act — A7.1.)
        assert(@sizeOf(PrefVector) == 1024);
    }
};

/// Tuning constants for the update step. Cold (one set, comptime), not hot.
/// `decay` is the per-update relax-toward-zero factor (slow forgetting so stale
/// interests fade); `rate` is how strongly an attended feature is reinforced;
/// `ceiling` clamps a bucket so one obsession can't dominate. Priors (G1/G2),
/// tunable against real behavior.
pub const decay: f32 = 0.997;
pub const rate: f32 = 0.25;
pub const ceiling: f32 = 8.0;

/// The bucket a feature lands in. A stable content hash masked to `pref_dim`;
/// the same feature bytes always hash the same bucket, so a topic the user
/// engages with accumulates weight across sessions. Pure (no seed/clock).
pub fn bucketOf(feature: []const u8) usize {
    return std.hash.Wyhash.hash(0, feature) & (pref_dim - 1);
}

/// Fold one attention event into the vector: relax every bucket toward zero
/// (forgetting), then reinforce the attended post's feature buckets by
/// `intensity × rate`, clamped to the ceiling. `intensity` is the shell's
/// normalized dwell/attention in [0,1] (the shell computes it from timing
/// events; the core never sees a clock). `features` are the post's topic tags +
/// author — opaque byte-strings the learner hashes and never interprets. Pure,
/// in-place; no allocation (the state is fixed-size). An empty `features` (an
/// untagged post) just applies the decay — an ordinary result, not an error
/// (E4).
pub fn update(v: *PrefVector, features: []const []const u8, intensity: f32) void {
    const clamped_intensity = std.math.clamp(intensity, 0.0, 1.0);
    for (&v.buckets) |*b| b.* *= decay;
    for (features) |f| {
        const i = bucketOf(f);
        v.buckets[i] = @min(v.buckets[i] + clamped_intensity * rate, ceiling);
    }
}

/// The learned BEHAVIORAL signal for a candidate: how much the user's vector
/// aligns with this post's features, squashed to [0,1). This is exactly the
/// value the shell writes into `discover.Candidate.behavioral`, which the scorer
/// multiplies through `behavioral_weight`. A featureless post (or an empty
/// vector) is 0 — neutral, no behavioral lift (E4). Pure.
pub fn affinity(v: *const PrefVector, features: []const []const u8) f32 {
    if (features.len == 0) return 0;
    var sum: f32 = 0;
    for (features) |f| sum += v.buckets[bucketOf(f)];
    const avg = sum / @as(f32, @floatFromInt(features.len));
    // Saturating map avg∈[0,ceiling] → [0,1): strong but never runaway.
    return avg / (1.0 + avg);
}

/// How much to EXPLORE (surface outside known preference) given the vector's
/// maturity. Near-empty state ⇒ ~1.0 (cold-start: there is nothing to exploit,
/// so explore — this covers Phase D0 as a natural consequence); as signal
/// accrues the weight decays toward `explore_floor` (never zero — a good
/// adaptive feed never fully stops exploring). The CORE only reports the weight;
/// the SHELL owns the randomness that actually draws exploratory candidates
/// (B4). Pure.
pub const explore_floor: f32 = 0.1;
pub fn explorationWeight(v: *const PrefVector) f32 {
    var mass: f32 = 0;
    for (v.buckets) |b| mass += b;
    // Maturity rises with accumulated mass; exploration falls from 1 → floor.
    const maturity = mass / (mass + 16.0); // 0 when empty, →1 as mass grows
    return explore_floor + (1.0 - explore_floor) * (1.0 - maturity);
}

// ---------------------------------------------------------------------------
// Tests — pure, no allocation, no clock (B2/B4)
// ---------------------------------------------------------------------------

test "update then affinity: attention raises the signal for matching features" {
    const t = std.testing;
    var v: PrefVector = .{};

    // Cold: every candidate is neutral.
    try t.expectEqual(@as(f32, 0), affinity(&v, &.{"#dolphins"}));

    // The user dwells on dolphins posts a few times.
    for (0..5) |_| update(&v, &.{ "#dolphins", "did:plc:coach" }, 1.0);

    // A dolphins post now reads positive; an unrelated topic stays neutral.
    try t.expect(affinity(&v, &.{"#dolphins"}) > 0.3);
    try t.expectEqual(@as(f32, 0), affinity(&v, &.{"#knitting"}));
    // The author the user lingered on also gained affinity.
    try t.expect(affinity(&v, &.{"did:plc:coach"}) > 0.0);
}

test "affinity is bounded in [0,1) however much a feature is reinforced" {
    const t = std.testing;
    var v: PrefVector = .{};
    for (0..1000) |_| update(&v, &.{"#obsession"}, 1.0);
    const a = affinity(&v, &.{"#obsession"});
    try t.expect(a > 0.5 and a < 1.0); // strong but never reaches 1
}

test "decay: an interest fades when attention moves elsewhere" {
    const t = std.testing;
    var v: PrefVector = .{};
    for (0..5) |_| update(&v, &.{"#olds"}, 1.0);
    const before = affinity(&v, &.{"#olds"});
    // Many updates on something else apply decay to the stale bucket.
    for (0..400) |_| update(&v, &.{"#news"}, 1.0);
    const after = affinity(&v, &.{"#olds"});
    try t.expect(after < before); // the old interest faded
    try t.expect(affinity(&v, &.{"#news"}) > after); // the new one leads
}

test "exploration is high when cold and decays as signal accrues, never to zero" {
    const t = std.testing;
    var v: PrefVector = .{};
    const cold = explorationWeight(&v);
    try t.expect(cold > 0.9); // nothing to exploit yet → explore

    for (0..50) |_| update(&v, &.{ "#a", "#b", "#c" }, 1.0);
    const warm = explorationWeight(&v);
    try t.expect(warm < cold); // less exploration once it knows you
    try t.expect(warm >= explore_floor); // but never stops entirely
}

test "empty features: an untagged post is neutral and just applies decay" {
    const t = std.testing;
    var v: PrefVector = .{};
    for (0..5) |_| update(&v, &.{"#x"}, 1.0);
    const before = affinity(&v, &.{"#x"});
    update(&v, &.{}, 1.0); // an untagged post: no feature to reinforce
    try t.expectEqual(@as(f32, 0), affinity(&v, &.{})); // featureless → neutral
    try t.expect(affinity(&v, &.{"#x"}) < before); // decay still applied
}
