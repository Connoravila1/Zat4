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

//! B1 classification: CORE (pure). **The discover engine's model + scorer** —
//! Phase D1 (the candidate record) and D3 (the pure scoring core + the default
//! config), the foundation every feed in Zat4 rides on.
//!
//! The load-bearing idea of the whole feature, in one line:
//!
//!   A feed is a SCORING FUNCTION over candidate posts. The "algorithm" is the
//!   set of numbers (a `FeedConfig`) that scoring function uses. The first-party
//!   default feed and a user-built feed are the SAME engine called with a
//!   different config — there is no privileged path (DISCOVER invariant 2).
//!
//! This file is that engine's heart and nothing else: the plain-data candidate
//! the scorer consumes, the plain-data config that IS an algorithm, and the
//! pure transform from (candidates, config, now) → a ranked order. No I/O, no
//! clock, no randomness (B2/B4): `now` is handed in as a value. Sourcing (D2,
//! shell) fills the candidate pool; diversity + moderation (D4) filter the
//! ranked order afterwards; serialization into a shareable atproto record (D5)
//! turns a config into a marketplace artifact. Those are separate slices over
//! this one engine — never a second scoring path (D6, invariant 1).
//!
//! By the law:
//!   * A1/A3 — `Candidate` is plain data in a struct-of-arrays; scoring is a
//!     free function over the collection, never a method.
//!   * A4/A5 — a candidate references its post by an OPAQUE `Ref` handle the
//!     caller assigns meaning to; this module never dereferences it, so the
//!     post index never gains meaning here and never leaves its owning module.
//!   * A6 — the in/out-of-network flag rides out of band in a parallel bitset.
//!   * A7 — `Candidate` is hot (scored in bulk every refresh); it carries an
//!     exact-size guard. `FeedConfig` is cold (one per feed selection, never in
//!     a hot loop) and is A7.2-waived.
//!   * B4 — `now` is a parameter. Same candidates + same config + same `now` ⇒
//!     same ranking, which is exactly what makes a shared algorithm verifiable
//!     (invariant 5) and this file trivially testable.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const rules_mod = @import("rules.zig");
const algo_vm = @import("algo_vm.zig");
const retrieval = @import("retrieval.zig");
const guest_vm = @import("guest_vm.zig");
const guest_abi = @import("guest_abi.zig");

// ---------------------------------------------------------------------------
// The candidate — the hot record the scorer consumes (Phase D1)
// ---------------------------------------------------------------------------

/// An OPAQUE handle a candidate carries back to whoever sourced it. The caller
/// (the feed module, a zone query, a reply pool) packs its own post index in
/// and reads it back in ranked order; this module NEVER interprets it — it
/// sorts handles, it does not index an array it doesn't own. So A4/A5 hold:
/// the meaningful index stays inside its owning module, and what crosses this
/// boundary is a handle, not a bare index.
pub const Ref = enum(u32) {
    _,

    pub fn from(value: u32) Ref {
        return @enumFromInt(value);
    }
    pub fn raw(r: Ref) u32 {
        return @intFromEnum(r);
    }
};

/// One candidate post: its opaque ref plus every signal the scorer weighs.
/// The graph-dependent signals (`author_rep`, `relevance`) and the on-device
/// `behavioral` signal are COMPUTED IN THE SHELL and handed in as plain values
/// — the core never touches the follow graph, a clock, or the attention stream
/// directly (B2/B4, invariant 3). Signals Zat4 does not yet capture (the click
/// and bookmark and reply-chain counts) are modeled now so the config and the
/// scorer share one vocabulary (F5: get the model right early); until a source
/// populates them they are simply 0 (E4: absence is ordinary data).
pub const Candidate = struct {
    /// Caller's opaque handle (see `Ref`).
    ref: Ref,
    /// Unix seconds, same unit as the `now` passed to the scorer.
    created_at: i64,
    like_count: u32,
    repost_count: u32,
    reply_count: u32,
    /// The author replied back into the thread — the strongest positive.
    reply_chain_count: u32,
    bookmark_count: u32,
    profile_click_count: u32,
    link_click_count: u32,
    /// Block / mute / report / not-interested — the asymmetric punisher. A
    /// positive count; the config's weight for it is negative.
    negative_count: u32,
    /// Shell-supplied author credibility in [0,1] (B3 computes it off-graph).
    author_rep: f32,
    /// Shell-supplied topic-match-to-this-user in [0,1].
    relevance: f32,
    /// TIER-2 RESERVED (Phase D9): the on-device per-user attention/affinity
    /// signal (dwell, watch-through) folded to [0,1]. NEVER leaves the device
    /// (invariant 3); handed in exactly like `relevance`. The scorer already
    /// multiplies it through (default `behavioral_weight` 0 ⇒ inert), so the
    /// learner is reachable with no layout rework — and this slot costs ZERO
    /// bytes: without it the struct is 52 bytes, which i64 alignment pads to 56
    /// anyway, so the f32 rides in on padding that would otherwise be dead.
    behavioral: f32,

    comptime {
        // Budget 56: ref(4) + created_at(8) + 8×u32 counts(32) + author_rep,
        // relevance, behavioral (3×f32 = 12) = 56, an exact multiple of the
        // i64 alignment, no padding. In the SoA store every field is its own
        // column, so even this never materializes as one packed row in memory
        // — the guard pins the honest @sizeOf and forces a decision the instant
        // a signal is added. (A7; raising this requires A7.1 justification. The
        // behavioral slot did NOT raise it — see the field comment.)
        assert(@sizeOf(Candidate) == 56);
    }
};

/// The candidate pool for one refresh: the hot `Candidate` rows in SoA, plus
/// the in/out-of-network bit per row OUT OF BAND (A6) — sourcing (D2) sets it
/// and the source-mix uses it; the per-candidate SCORE does not depend on it,
/// so the scorer never reads this bitset.
/// A7.2: cold struct, size guard waived — one per refresh, transient; its
/// CONTENTS are the hot, guarded `Candidate` rows.
pub const Candidates = struct {
    list: std.MultiArrayList(Candidate) = .empty,
    in_network: std.DynamicBitSetUnmanaged = .{},
    /// Per-candidate PUBLIC signals the developer tier reads, kept OUT OF BAND (A6)
    /// like `in_network`: whether the viewer already liked/reposted the post, how
    /// many topic tags it carries, and its quote-repost count (a public engagement
    /// signal Zat4 ingests but the config path does not weight, so it rides here
    /// rather than growing the hot `Candidate`). The shell fills these from its
    /// store; a caller that doesn't (a config algorithm, a test) leaves them at the
    /// defaults (not-engaged, 0 tags, 0 quotes), so nothing else is affected.
    viewer_engaged: std.DynamicBitSetUnmanaged = .{},
    tag_count: std.ArrayListUnmanaged(u8) = .empty,
    quote_count: std.ArrayListUnmanaged(u32) = .empty,
    /// Per-candidate topic-tag strings (zones), for the `tag_scope` retrieval
    /// source (A6, out of band). Each element is the candidate's tags; the strings
    /// borrow the caller's store. Filled ONLY when the query references tag_scope
    /// (F5) — otherwise left empty, and the scorer reads it as "no tags" per row.
    cand_tags: std.ArrayListUnmanaged([]const []const u8) = .empty,

    /// Append one candidate, growing the parallel out-of-band signals (A6).
    pub fn append(self: *Candidates, gpa: Allocator, c: Candidate, in_network: bool) error{OutOfMemory}!void {
        try self.list.append(gpa, c);
        try self.in_network.resize(gpa, self.list.len, false);
        self.in_network.setValue(self.list.len - 1, in_network);
        try self.viewer_engaged.resize(gpa, self.list.len, false);
        try self.tag_count.append(gpa, 0);
        try self.quote_count.append(gpa, 0);
        try self.cand_tags.append(gpa, &.{});
    }

    pub fn deinit(self: *Candidates, gpa: Allocator) void {
        self.list.deinit(gpa);
        self.in_network.deinit(gpa);
        self.viewer_engaged.deinit(gpa);
        self.tag_count.deinit(gpa);
        self.quote_count.deinit(gpa);
        self.cand_tags.deinit(gpa);
        self.* = undefined;
    }
};

// ---------------------------------------------------------------------------
// The config — the algorithm as plain, cold data (Phase D3)
// ---------------------------------------------------------------------------

/// The author-controlled CANDIDATE QUERY: what the engine is asked to fetch,
/// not how the result is ranked. Modeling this as a structured sub-record now
/// — rather than baking a single source-mix scalar into the engine — keeps
/// RETRIEVAL a first-class creative surface: a future author shapes the POOL
/// (topic include-sets, similarity seeds, graph-walk hops, time windows), the
/// engine still owns the I/O and cost, and nothing invasive is expressible
/// (the author never touches the network — D2 runs the query in the shell).
/// v1 honors `source_mix` + `max_candidates`; the richer, variable-length
/// retrieval params attach here when D2's index becomes parameterizable. (F5:
/// get the model's SHAPE right early so widening retrieval later is not a
/// change-amplification defect; F4: build only the scalar knobs for now.)
/// A7.2: cold config sub-record, size guard waived.
pub const Query = struct {
    /// In-network vs out-of-network ratio in [0,1] (0.5 default). 1.0 = follows
    /// only; 0.0 = discovery only. A parameter, never a constant.
    source_mix: f32 = 0.5,
    /// The pool-size cap the sourcer honors for one refresh.
    max_candidates: u32 = 500,
    /// Hard recency window in hours; 0 = no window (E4).
    recency_window_hrs: u32 = 0,

    /// PHASE 0 — the creator's authored RETRIEVAL: a list of source operators
    /// (`core/retrieval.zig`) that shape the candidate POOL — which posts are in,
    /// and how strongly each source weights them. Empty by default (a config with
    /// no retrieval query pulls the whole available pool — backward compatible),
    /// so this is inert for every existing config. The host runs each source over
    /// its indexes; the author never touches the network (D2), so — like the L2
    /// rules and the L3 VM — nothing invasive is expressible. Travels with the
    /// config record (it IS part of the algorithm); borrows the caller's memory.
    sources: []const retrieval.Source = &.{},
};

/// The algorithm. Plain data (A1), loaded once per feed selection and never in
/// a hot loop, so it carries NO size guard. The default feed is just one VALUE
/// of this type; a marketplace algorithm is another. Every default below is a
/// CALIBRATION PRIOR (G1/G2), not a measured truth — `like = 1.0` is the
/// baseline everything else is relative to; the numbers get tuned against real
/// Zat4 data and are trivial to retune. Serializes into a shareable atproto
/// record in D5.
///
/// The defaults ARE the launch "Zat4 Discover" config, and they are CALIBRATED
/// against Twitter's open-sourced Heavy-Ranker output weights (2023), our
/// `like = 1.0` baseline = Twitter's raw weights ÷ its like of 0.5 (so the
/// ratios are Twitter's exactly). The load-bearing lesson, corroborated
/// independently by Bluesky's Discover ("40 replies beat 200 likes"): a REPLY is
/// the dominant public quality signal (~27× a like), an author replying back is
/// the strongest of all (~150×), and a repost is only ~2× a like — NOT the 20×
/// an earlier draft of this config guessed. Negative feedback is the asymmetric
/// punisher (~−148). The click/dwell weights are BEHAVIORAL — reserved priors
/// here (the counts are 0 until on-device capture exists, D9), and pinned to 0
/// in the Private config (the doorway never hands it the signal).
/// A7.2: cold config, size guard waived.
pub const FeedConfig = struct {
    // Engagement weights (multiplied by the per-candidate counts, summed).
    // Calibrated to Twitter Heavy-Ranker ratios (×2 so like = 1.0 baseline).
    w_like: f32 = 1.0, // baseline passive approval (Twitter 0.5)
    w_repost: f32 = 2.0, // amplification (Twitter retweet 1.0 = 2× a like)
    w_reply: f32 = 27.0, // conversation — the dominant public signal (Twitter 13.5)
    w_reply_chain: f32 = 150.0, // author replied back — strongest positive (Twitter 75)
    w_bookmark: f32 = 10.0, // high-intent private save (no Twitter equiv; reserved)
    w_profile_click: f32 = 24.0, // BEHAVIORAL — interest in the author (Twitter 12)
    w_link_click: f32 = 22.0, // BEHAVIORAL — followed the content out (Twitter 11)
    w_negative: f32 = -148.0, // block / mute / report — asymmetric punisher (Twitter −74)

    /// A baseline added to the engagement sum for EVERY candidate, so a post with
    /// no engagement yet still has a non-zero score that freshness can lift — the
    /// cold-start floor. Because the score is multiplicative, a zero-engagement
    /// post otherwise scores exactly 0 regardless of recency; this is the knob that
    /// gives brand-new posts a chance to surface (additive smoothing). **Default 0
    /// preserves the pure engagement-gated behavior** — the right value for a given
    /// feed is a measured calibration decision (G2), and an algorithm author can
    /// tune it, so it lives in the config rather than as a hardcoded constant.
    engagement_floor: f32 = 0,

    // Freshness + boosts (MULTIPLY the engagement sum — see `scoreRow`).
    recency_half_life_hrs: f32 = 6.0,
    velocity_boost: bool = true, // early-engagement (~first 30 min) multiplier
    author_rep_weight: f32 = 0.5, // "moderate" prior (Twitter leans on TweepCred)
    relevance_weight: f32 = 1.0, // "high" prior
    /// TIER-2 RESERVED (Phase D9): how much the on-device per-user preference
    /// vector multiplies into the score. Default 0 ⇒ the behavioral signal is
    /// inert, so the learner is opt-in per config and reachable with no rework.
    behavioral_weight: f32 = 0.0,

    // Diversity caps — DATA the engine carries; applied as a separate pass in
    // D4, never tangled into scoring here.
    max_per_author: u32 = 3,
    max_per_subtopic: u32 = 8,

    /// The candidate query (retrieval) this algorithm asks for.
    query: Query = .{},

    /// DECLARED per-algorithm on-device state budget, in bytes (Phase D9/D11
    /// foresight). The doorway enforces it and the marketplace shows it as a
    /// truthful, system-derived label ("stores up to X locally" — invariant 6);
    /// a stateless algorithm declares 0. Capped at `state_budget_hard_cap`.
    /// Modeled now so the label vocabulary and the box's scratch budget carry
    /// it without a retrofit; the learner that uses it is D9.
    state_budget_bytes: u32 = 1 << 20, // 1 MiB soft default (digest-class)

    /// LEVEL 2 — the creator's authored LOGIC: a list of `{predicate, action}`
    /// rules (`core/rules.zig`) applied to each candidate's base score in order,
    /// after `scoreRow`. Empty by default (a flat-weights config), so this field
    /// is inert for every Level-1 config. A rule can boost/dampen a score or
    /// exclude a candidate; it composes only the engine's fixed vocabulary, so it
    /// is safe to run a shared rule-list with no interpreter. The rules travel
    /// with the config record (they ARE part of the algorithm). The slice borrows
    /// the caller's memory; for a parsed/built config it lives in that arena.
    rules: []const rules_mod.Rule = &.{},

    /// LEVEL 3 — the creator's authored SCORING FORMULA: a bounded expression-VM
    /// program (`core/algo_vm.zig`) run per candidate, AFTER the rule-list, with
    /// the rule-adjusted score exposed as the program's `base_score` input. Empty
    /// by default (Level-1/2 configs never touch it). The VM is total and reads
    /// only the same public facts the rules do — a program can shape ranking
    /// arbitrarily but can neither read your attention nor do anything off-device
    /// (the capability is not in the opcode set). Travels with the record (it IS
    /// part of the algorithm); the load path rejects a malformed program to a
    /// no-op (`validated`). Borrows the caller's memory like `rules`.
    vm_program: []const algo_vm.Instr = &.{},

    /// THE DEVELOPER TIER — a compiled `guest_vm` program (authored in Zal). When
    /// present, it IS the ranking: the engine marshals each candidate's public
    /// features into a `guest_abi.CandidateView` and runs the program to get the
    /// score, INSTEAD of the L1 formula + L2 rules + L3 VM above. Retrieval still
    /// shapes the pool BEFORE it, and moderation/diversity (D4) still run AFTER it —
    /// a guest gets freedom over ranking, never over the pool (invariant 8). Empty
    /// by default, so every config/rule/L3 algorithm is unaffected. Run here with a
    /// NULL host (facts only, pure); the on-device attention + state capabilities
    /// are wired in the shell (they touch I/O — B3/B4). Borrows the caller's memory.
    guest_program: []const guest_vm.Instr = &.{},
    /// The guest program's per-candidate fuel budget (a CPU-DoS wall; the scorer
    /// runs `candidates × fuel`). Clamped to `guest_vm.max_fuel` by `validated`.
    guest_fuel: u32 = guest_vm.default_fuel,
    /// The guest program's read-only TAG-CONSTANT POOL: the tag names its
    /// `has_tag`/`source_tag_scope` calls reference by index (the host resolves the
    /// index against this pool). Travels with the program (part of the artifact),
    /// empty when the program uses no tag literal. PUBLIC data (zone names), no
    /// identity — a guest reads tag membership, never a handle. Borrows the caller's
    /// memory; clamped to `guest_vm.max_strings` by `validated`.
    guest_strings: []const []const u8 = &.{},
    /// THE DEVELOPER TIER — the guest's optional `retrieve()` program, compiled from
    /// the same Zal source as `guest_program` (its `score`). When present it composes
    /// the candidate QUERY: run ONCE per refresh, its `follows/discovery/trending/
    /// tag_scope` capability calls append retrieval sources, and those REPLACE
    /// `query.sources` for the run — the guest shapes its own pool (still host-run
    /// over indexes, still pre-moderation, invariant 8). Empty ⇒ the declarative
    /// `query.sources` are used, unchanged. Borrows the caller's memory; validated
    /// like `guest_program`.
    guest_retrieve: []const guest_vm.Instr = &.{},
};

/// The hard ceiling on a single algorithm's declared on-device state (10 MiB).
/// The cap is BOTH disk hygiene and a side-channel wall: it bounds how much an
/// algorithm could ever accumulate about a user locally (Phase D9/D11). Most
/// algorithms need far less than the soft default; this is the room an
/// ambitious author may declare into, shown to the user, never granted by
/// default.
pub const state_budget_hard_cap: u32 = 10 << 20;

/// The hard ceiling on how many Level-2 rules one algorithm may carry. The
/// scorer evaluates `candidates × rules` every refresh, so an unbounded rule-list
/// in a shared (untrusted) config is a CPU denial-of-service vector — `validated`
/// truncates to this cap, on both the publish and the load path. 64 is far more
/// than authored scoring logic needs (the built-ins use 1–3); a config asking for
/// more is malformed input, clipped to a safe length rather than rejected (E4).
pub const max_rules: usize = 64;

/// The hard ceiling on how many retrieval SOURCES one algorithm's query may carry.
/// The scorer tests `candidates × sources`, so an unbounded source-list in a shared
/// (untrusted) config is a CPU-DoS dial — `validated` clips it. 32 is far more than
/// a composed retrieval query needs (a handful of sources shapes any pool).
pub const max_sources: usize = 32;

/// The hard ceiling on how many candidates one refresh may pull in to rank. The
/// scorer runs `candidates × (rules + program ops)`, so an unbounded
/// `max_candidates` in a shared (untrusted) config is the one remaining CPU/
/// memory denial-of-service dial — `validated` clamps it. 5000 is 10× the
/// digest-class default: generous for any real feed, far below "hang the client."
pub const max_candidates_hard_cap: u32 = 5000;

/// The Twitter-like default — Discover. One value of `FeedConfig`, with no
/// special-casing anywhere: `score(candidates, DEFAULT_CONFIG, now)` IS the
/// default feed (invariant 2).
pub const DEFAULT_CONFIG: FeedConfig = .{};

/// The window (hours) over which the early-engagement velocity boost applies.
const velocity_window_hrs: f64 = 0.5;

// ---------------------------------------------------------------------------
// The scorer — the pure transform (Phase D3)
// ---------------------------------------------------------------------------

/// Exponential freshness decay: `0.5 ^ (age / half_life)`. A future timestamp
/// (clock skew) clamps to age 0 ⇒ decay 1, never a negative age. A non-positive
/// half-life disables decay (E4), so a "no recency" config is expressible.
/// Pure.
pub fn recencyDecay(now: i64, created_at: i64, half_life_hrs: f32) f64 {
    if (half_life_hrs <= 0) return 1.0;
    const d = now - created_at;
    const age_hrs: f64 = if (d <= 0) 0.0 else @as(f64, @floatFromInt(d)) / 3600.0;
    return std.math.pow(f64, 0.5, age_hrs / @as(f64, half_life_hrs));
}

/// Early-engagement velocity: a young post gets a boost that decays linearly
/// from 2× at age 0 to 1× at the window edge, then 1× thereafter. A calibration
/// prior (G2): the precise curve is a measure-and-tune question, not a truth.
/// Pure.
pub fn velocityFactor(config: FeedConfig, age_hrs: f64) f64 {
    if (!config.velocity_boost) return 1.0;
    if (age_hrs >= velocity_window_hrs) return 1.0;
    return 1.0 + (1.0 - age_hrs / velocity_window_hrs);
}

/// Score one candidate — the heart, the recorded MULTIPLICATIVE formula:
///
///   score = (Σ count[k] × w[k])          // weighted engagement sum
///         × recency_decay
///         × velocity_factor
///         × (1 + author_rep × author_rep_weight)
///         × (1 + relevance  × relevance_weight)
///         × (1 + behavioral × behavioral_weight)   // Tier 2; weight 0 ⇒ inert
///
/// Multiplicative (not an additive sum of all terms) is the recorded decision:
/// it produces the authentic Twitter-like behavior where a fresh, fast-climbing
/// post can outrank an older viral one — at the cost of being more volatile and
/// more gameable on a single term, which is a CALIBRATION question to settle
/// with measurement (G2), not a structural one. Note a consequence to calibrate:
/// a zero-engagement post scores 0 regardless of recency, so a brand-new post
/// with no signal does not surface on engagement alone — a base-recency floor is
/// the calibration knob if cold posts need a chance. Pure; takes a row by value
/// (56 bytes, trivial — G3) so a test can score a hand-built candidate directly.
pub fn scoreRow(c: Candidate, config: FeedConfig, now: i64) f64 {
    const eng =
        @as(f64, @floatFromInt(c.like_count)) * @as(f64, config.w_like) +
        @as(f64, @floatFromInt(c.repost_count)) * @as(f64, config.w_repost) +
        @as(f64, @floatFromInt(c.reply_count)) * @as(f64, config.w_reply) +
        @as(f64, @floatFromInt(c.reply_chain_count)) * @as(f64, config.w_reply_chain) +
        @as(f64, @floatFromInt(c.bookmark_count)) * @as(f64, config.w_bookmark) +
        @as(f64, @floatFromInt(c.profile_click_count)) * @as(f64, config.w_profile_click) +
        @as(f64, @floatFromInt(c.link_click_count)) * @as(f64, config.w_link_click) +
        @as(f64, @floatFromInt(c.negative_count)) * @as(f64, config.w_negative) +
        @as(f64, config.engagement_floor); // cold-start baseline (default 0)

    const d = now - c.created_at;
    const age_hrs: f64 = if (d <= 0) 0.0 else @as(f64, @floatFromInt(d)) / 3600.0;

    const rec = recencyDecay(now, c.created_at, config.recency_half_life_hrs);
    const vel = velocityFactor(config, age_hrs);
    const author = 1.0 + @as(f64, c.author_rep) * @as(f64, config.author_rep_weight);
    const rel = 1.0 + @as(f64, c.relevance) * @as(f64, config.relevance_weight);
    const behav = 1.0 + @as(f64, c.behavioral) * @as(f64, config.behavioral_weight);

    return eng * rec * vel * author * rel * behav;
}

/// The CONTENT host for a guest score run — the public, non-behavioral capabilities
/// that read a candidate's tags. `has_tag(idx)` resolves the pool index to a tag
/// name and reports whether THIS candidate carries it (1/0). PURE: a function of the
/// pool + the candidate's tags, no I/O, so `score` remains a pure transform. The
/// attention/state capabilities are NOT answered here (they touch I/O and are gated
/// in the shell) — an unhandled capability returns 0, exactly as a null host would.
/// A7.2: cold — one per candidate on the guest path, two borrowed slices. Waived.
const ScoreHost = struct {
    strings: []const []const u8, // the artifact's tag-constant pool
    tags: []const []const u8, // this candidate's public tags

    fn call(ctx: *anyopaque, cap: guest_abi.Capability, arg0: f64, arg1: f64) f64 {
        _ = arg1;
        const self: *const ScoreHost = @ptrCast(@alignCast(ctx));
        switch (cap) {
            .has_tag => {
                // Resolve arg0 → a pool index defensively: a NaN/negative/out-of-range
                // index (the VM sanitizes values but never proves them integral) is
                // "no such tag" → 0, never an out-of-bounds access.
                if (!(arg0 >= 0 and arg0 < @as(f64, @floatFromInt(self.strings.len)))) return 0;
                const want = self.strings[@intFromFloat(arg0)];
                // Case-insensitive: zones fold ASCII case (invariant 1), so a
                // guest's has_tag("Foo") matches a candidate tagged #foo.
                for (self.tags) |tg| if (std.ascii.eqlIgnoreCase(tg, want)) return 1;
                return 0;
            },
            else => return 0, // retrieval/state/behavioral are not answered on the score path
        }
    }
};

/// The query-builder host for a guest `retrieve()` run: each source capability the
/// guest calls APPENDS a `retrieval.Source` to a list the engine then executes. The
/// guest never traverses anything — it names + weights sources, exactly the config
/// tier's vocabulary, so no raw/network reach is expressible (D2). PURE (it grows an
/// arena list). Capped at `max_sources` (a runaway `retrieve()` can't build an
/// unbounded query; fuel bounds the loop too). A7.2: cold — one per refresh. Waived.
const RetrieveHost = struct {
    arena: Allocator,
    strings: []const []const u8, // the artifact's tag pool (for source_tag_scope)
    out: *std.ArrayListUnmanaged(retrieval.Source),
    oom: bool = false, // an append failed — surfaced after the run (the host fn can't error)

    fn call(ctx: *anyopaque, cap: guest_abi.Capability, arg0: f64, arg1: f64) f64 {
        const self: *RetrieveHost = @ptrCast(@alignCast(ctx));
        if (self.out.items.len >= max_sources) return 0; // the DoS wall — ignore further sources
        const src: ?retrieval.Source = switch (cap) {
            .source_follows => .{ .kind = .follows, .weight = clampWeight(arg0) },
            .source_discovery => .{ .kind = .discovery, .weight = clampWeight(arg0) },
            .source_trending => .{ .kind = .trending, .threshold = clampWeight(arg0), .weight = clampWeight(arg1) },
            .source_tag_scope => blk: {
                // arg0 = tag pool index (host-resolved), arg1 = weight.
                if (!(arg0 >= 0 and arg0 < @as(f64, @floatFromInt(self.strings.len)))) break :blk null;
                break :blk .{ .kind = .tag_scope, .tag = self.strings[@intFromFloat(arg0)], .weight = clampWeight(arg1) };
            },
            else => null, // content/state/behavioral are not query-composing
        };
        if (src) |s| self.out.append(self.arena, s) catch {
            self.oom = true;
        };
        return 0;
    }
};

/// Keep a guest-supplied weight/threshold finite (a source weight rides through
/// `retrieval.poolWeight`, which already ignores non-finite/negative, but clamping
/// here keeps the stored query clean). The VM already sanitizes values.
fn clampWeight(v: f64) f32 {
    if (!std.math.isFinite(v)) return 0;
    return @floatCast(v);
}

/// Run a guest `retrieve()` program once to compose its candidate query. The guest
/// has no candidate here (it names sources, not scores posts), so it runs over a
/// zeroed view; any fact it reads is 0 and any content/state call is inert. Returns
/// the composed sources (bounded by `max_sources`), or an empty query on OOM (E4:
/// the caller falls back to the whole pool). Allocates in `arena` (C3). PURE.
fn composeGuestQuery(arena: Allocator, config: FeedConfig) error{OutOfMemory}![]const retrieval.Source {
    var out: std.ArrayListUnmanaged(retrieval.Source) = .empty;
    var host_ctx = RetrieveHost{ .arena = arena, .strings = config.guest_strings, .out = &out };
    const host = guest_vm.Host{ .ctx = &host_ctx, .call = RetrieveHost.call };
    const zero_view: guest_abi.CandidateView = .{ .like_count = 0, .repost_count = 0, .reply_count = 0, .age_hrs = 0, .author_rep = 0, .in_network = false };
    _ = guest_vm.run(config.guest_retrieve, zero_view, 0, config.guest_fuel, &host);
    if (host_ctx.oom) return error.OutOfMemory;
    return out.toOwnedSlice(arena);
}

/// Rank a candidate pool: pure transform from (candidates, config, now) → the
/// candidates' refs in DESCENDING score order, allocated in `arena` (C1/C3).
/// Diversity caps and moderation are SEPARATE later passes (D4) — this returns
/// the pure scored order and nothing else. Ties break by recency then ref so
/// the order is total and deterministic (verifiability, invariant 5). The empty
/// pool is an empty order, not an error (E4).
pub fn score(arena: Allocator, cands: *const Candidates, config: FeedConfig, now: i64) error{OutOfMemory}![]Ref {
    const n = cands.list.len;
    if (n == 0) return arena.alloc(Ref, 0);

    // Base score per candidate, then the config's LEVEL-2 RULES (if any) adjust
    // it in order — a rule can boost/dampen the score or EXCLUDE the candidate
    // from the pool (the creator's authored logic). A rule-less config (every
    // Level-1 feed) skips this entirely. The non-bypassable moderation/diversity
    // pass (D4) still runs AFTER, on the result — a rule cannot resurface what
    // moderation hides.
    // The EFFECTIVE retrieval query: a guest `retrieve()` program composes its own
    // sources (run once here), otherwise the declarative `query.sources` are used.
    // Either way the host runs the query over the pool below — the guest names
    // sources, never traverses (D2). Composed once, before the per-candidate loop.
    const eff_sources: []const retrieval.Source = if (config.guest_retrieve.len > 0)
        try composeGuestQuery(arena, config)
    else
        config.query.sources;

    const scores = try arena.alloc(f64, n);
    var kept: std.ArrayListUnmanaged(u32) = .empty;
    try kept.ensureTotalCapacity(arena, n);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const c = cands.list.get(i);
        const in_net = cands.in_network.isSet(i);
        // RETRIEVAL (Phase 0): the config's candidate query shapes the POOL. Each
        // source pulls in matching candidates with a weight; a candidate matched by
        // NO source was never "retrieved" and is dropped here. An empty query pulls
        // the whole available pool at weight 1 (backward compatible). The scorer
        // then multiplies the base score by the retrieval weight, so a post pulled
        // by several sources surfaces stronger.
        const row_tags: []const []const u8 = if (i < cands.cand_tags.items.len) cands.cand_tags.items[i] else &.{};
        const pool_w: f32 = retrieval.poolWeight(eff_sources, .{
            .in_network = in_net,
            .engagement = c.like_count + c.repost_count + c.reply_count,
            .tags = row_tags,
        }) orelse continue; // matched no source ⇒ not in the pool

        // THE DEVELOPER TIER: a compiled guest program IS the ranking when present —
        // marshal the candidate's public features and run it (null host: facts only,
        // pure). It replaces the L1/L2/L3 path below; retrieval already shaped the
        // pool, and D4 moderation/diversity still runs after (invariant 8).
        if (config.guest_program.len > 0) {
            const engaged = i < cands.viewer_engaged.capacity() and cands.viewer_engaged.isSet(i);
            const tags: u8 = if (i < cands.tag_count.items.len) cands.tag_count.items[i] else 0;
            const quotes: u32 = if (i < cands.quote_count.items.len) cands.quote_count.items[i] else 0;
            const view = candidateView(c, in_net, engaged, tags, quotes, now);
            const base = scoreRow(c, config, now); // available to the guest as `base_score`
            // The score-side CONTENT host: answers `has_tag` for THIS candidate from
            // the artifact's tag pool + the candidate's public tags. PURE (no I/O), so
            // the scorer stays pure; attention/state capabilities are not answered
            // here (they touch I/O + are gated) — they return 0, exactly as a null host.
            var host_ctx = ScoreHost{ .strings = config.guest_strings, .tags = row_tags };
            const host = guest_vm.Host{ .ctx = &host_ctx, .call = ScoreHost.call };
            scores[i] = guest_vm.run(config.guest_program, view, base, config.guest_fuel, &host) * @as(f64, pool_w);
            kept.appendAssumeCapacity(@intCast(i));
            continue;
        }

        var s = scoreRow(c, config, now) * @as(f64, pool_w);
        // The creator's authored logic, in two composable layers over the same
        // public facts: the Level-2 rule-list (which may EXCLUDE a candidate),
        // then the Level-3 expression VM (an arbitrary scoring formula, fed the
        // rule-adjusted score as its `base_score`). Both are inert when empty, so
        // a Level-1 feed computes the facts only when a layer is present and pays
        // nothing otherwise. Moderation/diversity (D4) still run AFTER on the
        // result — no authored layer can resurface what moderation hides.
        if (config.rules.len > 0 or config.vm_program.len > 0) {
            const facts = factsOf(c, in_net, now);
            if (config.rules.len > 0) {
                s = rules_mod.apply(config.rules, facts, s) orelse continue; // a rule excluded it
            }
            if (config.vm_program.len > 0) {
                s = algo_vm.run(config.vm_program, facts, s);
            }
        }
        scores[i] = s;
        kept.appendAssumeCapacity(@intCast(i));
    }
    const order = kept.items;

    const refs = cands.list.items(.ref);
    const createds = cands.list.items(.created_at);
    const Ctx = struct {
        scores: []const f64,
        createds: []const i64,
        refs: []const Ref,
        pub fn lessThan(ctx: @This(), x: u32, y: u32) bool {
            if (ctx.scores[x] != ctx.scores[y]) return ctx.scores[x] > ctx.scores[y]; // higher first
            if (ctx.createds[x] != ctx.createds[y]) return ctx.createds[x] > ctx.createds[y]; // fresher first
            return ctx.refs[x].raw() < ctx.refs[y].raw(); // stable tiebreak
        }
    };
    std.sort.block(u32, order, Ctx{ .scores = scores, .createds = createds, .refs = refs }, Ctx.lessThan);

    const out = try arena.alloc(Ref, order.len); // ≤ n when rules excluded some
    for (out, order) |*o, idx| o.* = refs[idx];
    return out;
}

/// Marshal one candidate's PUBLIC features into a `guest_abi.CandidateView` for the
/// developer tier — the exact, no-identity feature set a guest program reads (a
/// guest sees no author DID / "is this me", so it cannot target an account). `now`
/// is the value the scorer was handed (B4); `age_hrs` is derived here.
fn candidateView(c: Candidate, in_network: bool, viewer_engaged: bool, tag_count: u8, quote_count: u32, now: i64) guest_abi.CandidateView {
    const d = now - c.created_at;
    const age_hrs: f32 = if (d <= 0) 0 else @floatCast(@as(f64, @floatFromInt(d)) / 3600.0);
    return .{
        .like_count = c.like_count,
        .repost_count = c.repost_count,
        .reply_count = c.reply_count,
        .reply_chain = c.reply_chain_count,
        .tag_count = tag_count,
        .quote_count = quote_count,
        .age_hrs = age_hrs,
        .author_rep = c.author_rep,
        .in_network = in_network,
        .viewer_engaged = viewer_engaged,
    };
}

/// The rule-evaluator facts for one candidate (in-network from the pool's
/// parallel bitset; age from `now` vs the post's `created_at`). Built only when
/// a config carries rules. Pure — `now` is the value the scorer was handed (B4).
fn factsOf(c: Candidate, in_network: bool, now: i64) rules_mod.Facts {
    const d = now - c.created_at;
    const age_hrs: f64 = if (d <= 0) 0.0 else @as(f64, @floatFromInt(d)) / 3600.0;
    return .{
        .in_network = in_network,
        .like_count = c.like_count,
        .repost_count = c.repost_count,
        .reply_count = c.reply_count,
        .age_hrs = age_hrs,
    };
}

// ---------------------------------------------------------------------------
// The post-scoring filters — diversity + non-bypassable moderation (Phase D4)
// ---------------------------------------------------------------------------

/// Apply the two post-scoring passes to a ranked order: **moderation removal**
/// (non-bypassable, invariant 8) and the **per-author diversity cap**. A pure
/// transform over the order — `author_key[i]` and `keep[i]` are PARALLEL to
/// `order` (one per ranked position), supplied by the caller from its own store;
/// the engine groups authors by key EQUALITY and never interprets the key as an
/// index (A5 — it's a grouping token, like a hash).
///
/// `keep[i] == false` is a moderation removal: applied regardless of `config`,
/// so no algorithm — first-party default or contributed — can rank around what
/// moderation hid (invariant 8, "freedom over ranking, never over the pool").
/// The diversity cap then keeps at most `config.max_per_author` survivors per
/// author so no one account dominates a refresh; `max_per_author == 0` means no
/// cap. (`max_per_subtopic` is modeled in the config but not enforced yet — it
/// needs the topic/entity index from D2; recorded, not silently dropped.)
///
/// Order: moderation-hidden posts are dropped FIRST so they never consume an
/// author's diversity slot (a lower-ranked visible post by that author can take
/// it instead). Moderation stays non-bypassable either way; this just doesn't
/// waste quota on removed posts. Returns survivors in rank order, in `arena`.
pub fn applyCaps(
    arena: Allocator,
    order: []const Ref,
    author_key: []const u32,
    keep: []const bool,
    config: FeedConfig,
) error{OutOfMemory}![]Ref {
    assert(order.len == author_key.len and order.len == keep.len);
    var out: std.ArrayListUnmanaged(Ref) = .empty;
    try out.ensureTotalCapacity(arena, order.len);

    var per_author: std.AutoHashMapUnmanaged(u32, u32) = .empty;
    defer per_author.deinit(arena);

    for (order, author_key, keep) |ref, akey, k| {
        if (!k) continue; // moderation removal — non-bypassable
        if (config.max_per_author != 0) {
            const gop = try per_author.getOrPut(arena, akey);
            if (!gop.found_existing) gop.value_ptr.* = 0;
            if (gop.value_ptr.* >= config.max_per_author) continue; // author cap hit
            gop.value_ptr.* += 1;
        }
        out.appendAssumeCapacity(ref);
    }
    return out.toOwnedSlice(arena);
}

// ---------------------------------------------------------------------------
// Validation — a shared/hostile config is just bad DATA, never a crash (D5)
// ---------------------------------------------------------------------------

/// Clamp one float into a finite range; a NaN/Inf (which would poison the
/// multiplicative score) falls back to `dflt`. Pure.
fn clampF(x: f32, lo: f32, hi: f32, dflt: f32) f32 {
    if (!std.math.isFinite(x)) return dflt;
    return std.math.clamp(x, lo, hi);
}

/// Sanitize a config loaded from anywhere (a shared record, a hand-edit, an
/// import) into one the engine can run safely (E2/E4): every weight is clamped
/// to a finite range so no value can produce a NaN/Inf or absurdly dominate,
/// the source-mix is pinned to [0,1], and the declared state budget is capped at
/// `state_budget_hard_cap` (DISCOVER D9/D11 — an imported algorithm cannot
/// declare itself more on-device room than the ceiling allows). Pure: the
/// engine never trusts a number it did not clamp. Generous bounds — these stop
/// abuse and accidents, not legitimate tuning (the priors sit well inside them).
pub fn validated(c: FeedConfig) FeedConfig {
    const d = DEFAULT_CONFIG;
    var v = c;
    const w_lo: f32 = -100_000;
    const w_hi: f32 = 100_000;
    v.w_like = clampF(c.w_like, w_lo, w_hi, d.w_like);
    v.w_repost = clampF(c.w_repost, w_lo, w_hi, d.w_repost);
    v.w_reply = clampF(c.w_reply, w_lo, w_hi, d.w_reply);
    v.w_reply_chain = clampF(c.w_reply_chain, w_lo, w_hi, d.w_reply_chain);
    v.w_bookmark = clampF(c.w_bookmark, w_lo, w_hi, d.w_bookmark);
    v.w_profile_click = clampF(c.w_profile_click, w_lo, w_hi, d.w_profile_click);
    v.w_link_click = clampF(c.w_link_click, w_lo, w_hi, d.w_link_click);
    v.w_negative = clampF(c.w_negative, w_lo, w_hi, d.w_negative);
    v.engagement_floor = clampF(c.engagement_floor, 0, w_hi, d.engagement_floor); // ≥ 0, bounded
    v.recency_half_life_hrs = clampF(c.recency_half_life_hrs, 0, 1_000_000, d.recency_half_life_hrs);
    v.author_rep_weight = clampF(c.author_rep_weight, -1000, 1000, d.author_rep_weight);
    v.relevance_weight = clampF(c.relevance_weight, -1000, 1000, d.relevance_weight);
    v.behavioral_weight = clampF(c.behavioral_weight, -1000, 1000, d.behavioral_weight);
    v.query.source_mix = clampF(c.query.source_mix, 0, 1, d.query.source_mix);
    if (v.query.max_candidates == 0) v.query.max_candidates = d.query.max_candidates;
    if (v.query.max_candidates > max_candidates_hard_cap) v.query.max_candidates = max_candidates_hard_cap;
    if (v.state_budget_bytes > state_budget_hard_cap) v.state_budget_bytes = state_budget_hard_cap;
    // Clip a hostile/oversized rule-list to the cap (CPU-DoS wall). Truncating a
    // const slice borrows the same memory — no allocation, so `validated` stays
    // pure and total. Extra rules never run and, because serialize() validates
    // first, never survive a round trip either.
    if (v.rules.len > max_rules) v.rules = v.rules[0..max_rules];
    // Clip a hostile/oversized retrieval source-list to its cap (the scorer runs
    // `candidates × sources`, so an unbounded list is a CPU-DoS dial). Per-source
    // weights/thresholds need no clamp — `retrieval.poolWeight` ignores non-finite
    // / negative weights defensively, so a bad value is already a safe no-op.
    if (v.query.sources.len > max_sources) v.query.sources = v.query.sources[0..max_sources];
    // Reject a malformed or oversized Level-3 program to a safe no-op (the
    // expression VM). `validatedProgram` keeps a well-formed, within-cap program
    // and discards the rest — fail-safe, never partially executed (E2/E4).
    v.vm_program = algo_vm.validatedProgram(v.vm_program);
    // The developer-tier guest program: reject a malformed one to a safe no-op (the
    // guest VM's own validator — the untrusted-compiler / trusted-validator split),
    // and clamp the fuel budget to the DoS ceiling.
    v.guest_program = guest_vm.validatedProgram(v.guest_program);
    // The guest's retrieve() program: reject a malformed one to a safe no-op (the
    // same untrusted-compiler / trusted-validator split as the score program). An
    // empty retrieve() ⇒ the declarative query.sources are used.
    v.guest_retrieve = guest_vm.validatedProgram(v.guest_retrieve);
    // Clip a hostile/oversized tag-constant pool to its cap (a `has_tag` lookup is
    // `candidates × pool` in the worst case). Truncating the const slice borrows the
    // same memory — no allocation, so `validated` stays pure. An index past the
    // clipped pool resolves to "no such tag" at runtime (the host bounds-checks), so
    // dropping entries can only make a match fail safe, never read out of bounds.
    if (v.guest_strings.len > guest_vm.max_strings) v.guest_strings = v.guest_strings[0..guest_vm.max_strings];
    if (v.guest_fuel == 0) v.guest_fuel = guest_vm.default_fuel;
    if (v.guest_fuel > guest_vm.max_fuel) v.guest_fuel = guest_vm.max_fuel;
    return v;
}

// ---------------------------------------------------------------------------
// Tests — leak-checked (C6), pure (no clock: `now` is a fixed literal)
// ---------------------------------------------------------------------------

const test_now: i64 = 1_700_000_000; // a fixed "now" — the clock never enters (B4)

/// Build a candidate with the given ref/age/likes, everything else zero — the
/// minimal hand-built input the pure scorer needs.
fn mk(ref: u32, age_secs: i64, likes: u32) Candidate {
    return .{
        .ref = Ref.from(ref),
        .created_at = test_now - age_secs,
        .like_count = likes,
        .repost_count = 0,
        .reply_count = 0,
        .reply_chain_count = 0,
        .bookmark_count = 0,
        .profile_click_count = 0,
        .link_click_count = 0,
        .negative_count = 0,
        .author_rep = 0,
        .relevance = 0,
        .behavioral = 0,
    };
}

test "score: more engagement ranks first at equal age" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var c: Candidates = .{};
    defer c.deinit(t.allocator);
    try c.append(t.allocator, mk(10, 3600, 5), true);
    try c.append(t.allocator, mk(20, 3600, 50), true); // more likes, same age
    try c.append(t.allocator, mk(30, 3600, 1), true);

    const order = try score(arena, &c, DEFAULT_CONFIG, test_now);
    try t.expectEqual(@as(usize, 3), order.len);
    try t.expectEqual(@as(u32, 20), order[0].raw());
    try t.expectEqual(@as(u32, 10), order[1].raw());
    try t.expectEqual(@as(u32, 30), order[2].raw());
}

test "score: fresher wins when engagement is equal" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var c: Candidates = .{};
    defer c.deinit(t.allocator);
    try c.append(t.allocator, mk(1, 12 * 3600, 100), true); // 12h old
    try c.append(t.allocator, mk(2, 1 * 3600, 100), true); //  1h old

    const order = try score(arena, &c, DEFAULT_CONFIG, test_now);
    try t.expectEqual(@as(u32, 2), order[0].raw()); // recency decay favors the fresh one
    try t.expectEqual(@as(u32, 1), order[1].raw());
}

test "score: calibrated ratios hold — a reply dominates, a repost is only ~2x a like" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const ten_likes = mk(1, 3600, 10); // 10 × 1 = 10
    var one_reply = mk(2, 3600, 0);
    one_reply.reply_count = 1; // 1 × 27 = 27 — the dominant public signal
    var one_repost = mk(3, 3600, 0);
    one_repost.repost_count = 1; // 1 × 2 = 2 — a repost is only ~2× a like
    const three_likes = mk(4, 3600, 3); // 3 × 1 = 3

    var c: Candidates = .{};
    defer c.deinit(t.allocator);
    try c.append(t.allocator, ten_likes, true);
    try c.append(t.allocator, one_reply, true);
    try c.append(t.allocator, one_repost, true);
    try c.append(t.allocator, three_likes, true);

    const order = try score(arena, &c, DEFAULT_CONFIG, test_now);
    // reply (27) > ten likes (10) > three likes (3) > one repost (2)
    try t.expectEqual(@as(u32, 2), order[0].raw());
    try t.expectEqual(@as(u32, 1), order[1].raw());
    try t.expectEqual(@as(u32, 4), order[2].raw());
    try t.expectEqual(@as(u32, 3), order[3].raw());
}

test "score: negative actions are an asymmetric punisher" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var reported = mk(1, 3600, 100); // 100 likes...
    reported.negative_count = 2; // ...but two reports: 100×1 + 2×(-74) = -48

    var c: Candidates = .{};
    defer c.deinit(t.allocator);
    try c.append(t.allocator, reported, true);
    try c.append(t.allocator, mk(2, 3600, 1), true); // a quiet positive post

    const order = try score(arena, &c, DEFAULT_CONFIG, test_now);
    try t.expectEqual(@as(u32, 2), order[0].raw()); // the punished post sinks below it
    try t.expect(scoreRow(reported, DEFAULT_CONFIG, test_now) < 0);
}

test "score: behavioral signal is inert under the default config (Tier-2 reserved)" {
    const t = std.testing;
    // Two identical posts; one carries a strong behavioral signal. With the
    // default behavioral_weight of 0 it must NOT change the score — the slot is
    // reserved, the learner (D9) is not built.
    const plain = mk(1, 3600, 10);
    var attended = mk(2, 3600, 10);
    attended.behavioral = 1.0;
    try t.expectEqual(scoreRow(plain, DEFAULT_CONFIG, test_now), scoreRow(attended, DEFAULT_CONFIG, test_now));

    // Turn the weight on and the same signal now lifts the score (the path works).
    var learns = DEFAULT_CONFIG;
    learns.behavioral_weight = 0.5;
    try t.expect(scoreRow(attended, learns, test_now) > scoreRow(plain, learns, test_now));
}

test "score: future timestamp (clock skew) clamps, does not explode" {
    const t = std.testing;
    const future = mk(1, -3600, 10); // created_at one hour in the FUTURE
    const s = scoreRow(future, DEFAULT_CONFIG, test_now);
    try t.expect(std.math.isFinite(s));
    // age clamps to 0 ⇒ decay 1, velocity at its max 2× ⇒ score = 10 × 1 × 2.
    try t.expectApproxEqAbs(@as(f64, 20.0), s, 1e-9);
}

test "score: deterministic — same inputs, same order (verifiability)" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var c: Candidates = .{};
    defer c.deinit(t.allocator);
    try c.append(t.allocator, mk(1, 3600, 7), true);
    try c.append(t.allocator, mk(2, 7200, 7), false);
    try c.append(t.allocator, mk(3, 1800, 7), true);

    const a = try score(arena, &c, DEFAULT_CONFIG, test_now);
    const b = try score(arena, &c, DEFAULT_CONFIG, test_now);
    try t.expectEqualSlices(Ref, a, b);
}

test "score: empty pool is an empty order, not an error" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var c: Candidates = .{};
    defer c.deinit(t.allocator);
    const order = try score(arena, &c, DEFAULT_CONFIG, test_now);
    try t.expectEqual(@as(usize, 0), order.len);
}

test "score: a config rule boosts a matching candidate above a higher-base one" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Two equal-age posts: ref 1 has more likes (higher base). A rule boosts
    // out-of-network posts 3×; ref 2 is out-of-network, ref 1 is in-network.
    var c: Candidates = .{};
    defer c.deinit(t.allocator);
    try c.append(t.allocator, mk(1, 3600, 20), true); // in-network, base 20
    try c.append(t.allocator, mk(2, 3600, 10), false); // out-of-network, base 10

    const cfg_rules = [_]rules_mod.Rule{.{
        .predicate = .{ .kind = .out_of_network },
        .action = .{ .kind = .boost, .factor = 3.0 },
    }};
    var cfg = DEFAULT_CONFIG;
    cfg.rules = &cfg_rules;

    const order = try score(arena, &c, cfg, test_now);
    try t.expectEqual(@as(usize, 2), order.len);
    try t.expectEqual(@as(u32, 2), order[0].raw()); // 10×3 = 30 > 20 — the rule lifted it
    try t.expectEqual(@as(u32, 1), order[1].raw());
}

test "score: an exclude rule removes candidates from the ranked pool" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var c: Candidates = .{};
    defer c.deinit(t.allocator);
    try c.append(t.allocator, mk(1, 3600, 50), false); // out-of-network
    try c.append(t.allocator, mk(2, 3600, 30), true); // in-network
    try c.append(t.allocator, mk(3, 3600, 10), false); // out-of-network

    // "Show me only the people I follow."
    const cfg_rules = [_]rules_mod.Rule{.{
        .predicate = .{ .kind = .out_of_network },
        .action = .{ .kind = .exclude },
    }};
    var cfg = DEFAULT_CONFIG;
    cfg.rules = &cfg_rules;

    const order = try score(arena, &c, cfg, test_now);
    try t.expectEqual(@as(usize, 1), order.len); // two excluded
    try t.expectEqual(@as(u32, 2), order[0].raw()); // only the in-network post survives
}

test "score: a retrieval query shapes the POOL — a `follows` source drops out-of-network posts" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var c: Candidates = .{};
    defer c.deinit(t.allocator);
    try c.append(t.allocator, mk(1, 3600, 50), false); // out-of-network
    try c.append(t.allocator, mk(2, 3600, 30), true); // in-network
    try c.append(t.allocator, mk(3, 3600, 10), false); // out-of-network

    // "Pull only from the people I follow" — a retrieval query, not a rule.
    const srcs = [_]retrieval.Source{.{ .kind = .follows }};
    var cfg = DEFAULT_CONFIG;
    cfg.query.sources = &srcs;

    const order = try score(arena, &c, cfg, test_now);
    try t.expectEqual(@as(usize, 1), order.len); // only the in-network post was retrieved
    try t.expectEqual(@as(u32, 2), order[0].raw());
}

test "score: a tag_scope query shapes the POOL — only posts in the named zone are retrieved" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var c: Candidates = .{};
    defer c.deinit(t.allocator);
    try c.append(t.allocator, mk(1, 3600, 50), true); // will carry #zig
    try c.append(t.allocator, mk(2, 3600, 90), true); // untagged (higher engagement)
    try c.append(t.allocator, mk(3, 3600, 10), true); // #cooking
    // Per-candidate tags, out of band (what buildDiscoverView materializes from the store).
    c.cand_tags.items[0] = &.{"zig"};
    c.cand_tags.items[1] = &.{};
    c.cand_tags.items[2] = &.{"cooking"};

    // "Pull from the zig zone" — a retrieval query over the resident tags.
    const srcs = [_]retrieval.Source{.{ .kind = .tag_scope, .tag = "zig" }};
    var cfg = DEFAULT_CONFIG;
    cfg.query.sources = &srcs;

    const order = try score(arena, &c, cfg, test_now);
    try t.expectEqual(@as(usize, 1), order.len); // only the #zig post survived retrieval
    try t.expectEqual(@as(u32, 1), order[0].raw()); // not the higher-engagement untagged post
}

test "developer tier: a guest ranks by TAG membership via has_tag (content capability, engine host)" {
    const t = std.testing;
    const zal_parse = @import("zal_parse.zig");
    const zal_compile = @import("zal_compile.zig");
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // "posts in the zig zone are worth a lot; otherwise rank by likes."
    const src = "fn score() num { if (has_tag(\"zig\")) { return 1000.0; } return like_count; }";
    const ast = try zal_parse.parse(arena, src);
    const res = try zal_compile.compile(arena, &ast, "score");
    try t.expect(res.ok());
    var cfg = DEFAULT_CONFIG;
    cfg.guest_program = res.program;
    cfg.guest_strings = res.strings; // the tag pool travels WITH the program
    cfg = validated(cfg);

    var c: Candidates = .{};
    defer c.deinit(t.allocator);
    try c.append(t.allocator, mk(1, 3600, 500), true); // high engagement, untagged
    try c.append(t.allocator, mk(2, 3600, 5), true); // low engagement, #zig
    c.cand_tags.items[0] = &.{};
    c.cand_tags.items[1] = &.{"zig"};

    // The engine built a per-candidate content host, the guest called has_tag("zig"),
    // and the tag boost carried the low-engagement #zig post above the popular one.
    const order = try score(arena, &c, cfg, test_now);
    try t.expectEqual(@as(usize, 2), order.len);
    try t.expectEqual(@as(u32, 2), order[0].raw()); // 1000 (tagged) > 500 (untagged likes)
}

test "developer tier: a guest retrieve() composes its own pool via tag_scope" {
    const t = std.testing;
    const zal_parse = @import("zal_parse.zig");
    const zal_compile = @import("zal_compile.zig");
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // score by likes; retrieve ONLY the zig zone — the guest shapes its own pool.
    const src =
        \\fn retrieve() num { tag_scope("zig", 1.0); return 0.0; }
        \\fn score() num { return like_count; }
    ;
    const ast = try zal_parse.parse(arena, src);
    const art = try zal_compile.compileArtifact(arena, &ast);
    try t.expect(art.ok());
    try t.expect(art.retrieve.len > 0);
    var cfg = DEFAULT_CONFIG;
    cfg.guest_program = art.score;
    cfg.guest_retrieve = art.retrieve;
    cfg.guest_strings = art.strings; // ONE shared pool for score + retrieve
    cfg = validated(cfg);

    var c: Candidates = .{};
    defer c.deinit(t.allocator);
    try c.append(t.allocator, mk(1, 3600, 500), true); // untagged, popular
    try c.append(t.allocator, mk(2, 3600, 5), true); // #zig, unpopular
    c.cand_tags.items[0] = &.{};
    c.cand_tags.items[1] = &.{"zig"};

    // The guest's retrieve() ran once, composed a tag_scope("zig") source, and the
    // engine kept ONLY the #zig post — the popular untagged one was never retrieved.
    const order = try score(arena, &c, cfg, test_now);
    try t.expectEqual(@as(usize, 1), order.len);
    try t.expectEqual(@as(u32, 2), order[0].raw());
}

test "score: a source WEIGHT lifts its pool — heavily-weighted follows beats a more-engaged discovery post" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var c: Candidates = .{};
    defer c.deinit(t.allocator);
    // Same age. By engagement alone the out-of-network post (100) beats the
    // in-network one (40).
    try c.append(t.allocator, mk(1, 3600, 100), false); // out-of-network, high engagement
    try c.append(t.allocator, mk(2, 3600, 40), true); // in-network, lower engagement

    // A query that heavily weights your follows pulls the in-network post above.
    const srcs = [_]retrieval.Source{
        .{ .kind = .follows, .weight = 10.0 },
        .{ .kind = .discovery, .weight = 1.0 },
    };
    var cfg = DEFAULT_CONFIG;
    cfg.query.sources = &srcs;

    const order = try score(arena, &c, cfg, test_now);
    try t.expectEqual(@as(usize, 2), order.len); // both retrieved (a source matches each)
    try t.expectEqual(@as(u32, 2), order[0].raw()); // the follows-weighted post now leads
}

test "developer tier: a compiled Zal program IS the ranking (Discover-in-Zal through the engine)" {
    const t = std.testing;
    const zal_parse = @import("zal_parse.zig");
    const zal_compile = @import("zal_compile.zig");
    const templates = @import("zal_templates.zig");
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Compile the REAL Zat4 Discover, written in Zal, down to guest bytecode.
    const ast = try zal_parse.parse(arena, templates.zat4_discover);
    const res = try zal_compile.compile(arena, &ast, "score");
    try t.expect(res.ok());

    var cfg = DEFAULT_CONFIG;
    cfg.guest_program = res.program;
    cfg = validated(cfg); // the guest VM's validator accepts it; survives the round
    try t.expect(cfg.guest_program.len > 0);

    var c: Candidates = .{};
    defer c.deinit(t.allocator);
    try c.append(t.allocator, mk(1, 3600, 10), true); // low engagement
    try c.append(t.allocator, mk(2, 3600, 200), true); // high engagement

    // The engine marshalled each candidate into a CandidateView and ran the Zal
    // program to rank them — the developer tier, end to end through the same
    // score() every config algorithm uses (one engine, no privileged path).
    const order = try score(arena, &c, cfg, test_now);
    try t.expectEqual(@as(usize, 2), order.len);
    try t.expectEqual(@as(u32, 2), order[0].raw()); // the high-engagement post ranks first
}

test "scoreRow: the cold-start floor lets a zero-engagement fresh post score above 0" {
    const t = std.testing;
    // Default config: a zero-engagement post scores exactly 0, regardless of age.
    const fresh_quiet = mk(1, 60, 0); // 1 minute old, no engagement
    try t.expectEqual(@as(f64, 0), scoreRow(fresh_quiet, DEFAULT_CONFIG, test_now));

    // With a floor, the same post scores > 0, and a fresher one outscores an older
    // one purely on recency (the cold-start behavior we wanted).
    var cfg = DEFAULT_CONFIG;
    cfg.engagement_floor = 10;
    const fresh = scoreRow(mk(1, 60, 0), cfg, test_now);
    const stale = scoreRow(mk(2, 3600 * 48, 0), cfg, test_now); // 48h old, no engagement
    try t.expect(fresh > 0);
    try t.expect(fresh > stale); // freshness now breaks the tie among quiet posts

    // The floor is additive smoothing: a high-engagement post is barely affected.
    const busy_default = scoreRow(mk(3, 60, 100), DEFAULT_CONFIG, test_now);
    const busy_floored = scoreRow(mk(3, 60, 100), cfg, test_now);
    try t.expect(busy_floored > busy_default); // floor added
    try t.expect((busy_floored - busy_default) / busy_default < 0.5); // but a small relative nudge
}

test "validated: a negative cold-start floor is clamped to 0" {
    const t = std.testing;
    var hostile = DEFAULT_CONFIG;
    hostile.engagement_floor = -5; // a negative floor would penalize, not seed
    try t.expectEqual(@as(f32, 0), validated(hostile).engagement_floor);
}

test "score: a Level-3 VM program reshapes the ranking via an authored formula" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Two equal-age posts: ref 1 has the higher base (more likes). A formula
    // multiplies the score by reposts, and ref 2 has far more reposts — so the
    // authored formula flips the order, something flat weights alone wouldn't do
    // here. score := base_score × reposts.
    var c: Candidates = .{};
    defer c.deinit(t.allocator);
    var hi = mk(1, 3600, 50); // higher base
    hi.repost_count = 1;
    var lo = mk(2, 3600, 40); // lower base
    lo.repost_count = 5; // but many more reposts
    try c.append(t.allocator, hi, true);
    try c.append(t.allocator, lo, true);

    const program = [_]algo_vm.Instr{
        .{ .op = .push_fact, .fact = .base_score },
        .{ .op = .push_fact, .fact = .repost_count },
        .{ .op = .mul },
    };
    var cfg = DEFAULT_CONFIG;
    cfg.vm_program = &program;

    const order = try score(arena, &c, cfg, test_now);
    try t.expectEqual(@as(usize, 2), order.len);
    try t.expectEqual(@as(u32, 2), order[0].raw()); // base40×5 = 200 > base50×1 = 50
    try t.expectEqual(@as(u32, 1), order[1].raw());
}

test "score: a malformed VM program is inert (validated to a no-op upstream)" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var c: Candidates = .{};
    defer c.deinit(t.allocator);
    try c.append(t.allocator, mk(1, 3600, 50), true);
    try c.append(t.allocator, mk(2, 3600, 10), true);

    // An underflowing program — the load path (`validated`) drops it to empty, so
    // the ranking is the plain base order. We validate, as the live path does.
    const bad = [_]algo_vm.Instr{.{ .op = .mul }};
    var cfg = DEFAULT_CONFIG;
    cfg.vm_program = &bad;

    const order = try score(arena, &c, validated(cfg), test_now);
    try t.expectEqual(@as(usize, 2), order.len);
    try t.expectEqual(@as(u32, 1), order[0].raw()); // base order, unchanged
    try t.expectEqual(@as(u32, 2), order[1].raw());
}

test "score: Level-2 rules and the Level-3 VM compose — exclude, then reshape survivors" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // refs 1,2 in-network; ref 3 out-of-network with the highest base. A rule
    // excludes out-of-network (drops ref 3); the VM then reshapes the survivors
    // by score = base × reposts, flipping 1 and 2.
    var c: Candidates = .{};
    defer c.deinit(t.allocator);
    var a = mk(1, 3600, 50);
    a.repost_count = 1; // higher base, few reposts
    var b = mk(2, 3600, 40);
    b.repost_count = 5; // lower base, many reposts
    try c.append(t.allocator, a, true);
    try c.append(t.allocator, b, true);
    try c.append(t.allocator, mk(3, 3600, 100), false); // out-of-network, top base — excluded

    const cfg_rules = [_]rules_mod.Rule{.{ .predicate = .{ .kind = .out_of_network }, .action = .{ .kind = .exclude } }};
    const program = [_]algo_vm.Instr{
        .{ .op = .push_fact, .fact = .base_score },
        .{ .op = .push_fact, .fact = .repost_count },
        .{ .op = .mul },
    };
    var cfg = DEFAULT_CONFIG;
    cfg.rules = &cfg_rules;
    cfg.vm_program = &program;

    const order = try score(arena, &c, cfg, test_now);
    try t.expectEqual(@as(usize, 2), order.len); // ref 3 excluded by the L2 rule
    try t.expectEqual(@as(u32, 2), order[0].raw()); // L3: base≈50×5 > base≈52×1
    try t.expectEqual(@as(u32, 1), order[1].raw());
}

test "applyCaps composes with a rule exclusion: a dropped post does not consume an author slot" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Author A owns refs 1, 2, 4; author B owns ref 3. A rule excludes the
    // out-of-network post (ref 2). With max_per_author = 1, A keeps only its top
    // SURVIVING post — the excluded one never claimed A's single slot.
    var c: Candidates = .{};
    defer c.deinit(t.allocator);
    try c.append(t.allocator, mk(1, 3600, 30), true); // A, in-network
    try c.append(t.allocator, mk(2, 3600, 99), false); // A, out-of-network → excluded (would be top)
    try c.append(t.allocator, mk(3, 3600, 20), true); // B, in-network
    try c.append(t.allocator, mk(4, 3600, 10), true); // A, in-network

    const cfg_rules = [_]rules_mod.Rule{.{ .predicate = .{ .kind = .out_of_network }, .action = .{ .kind = .exclude } }};
    var cfg = DEFAULT_CONFIG;
    cfg.rules = &cfg_rules;
    cfg.max_per_author = 1;

    const order = try score(arena, &c, cfg, test_now);
    try t.expectEqual(@as(usize, 3), order.len); // ref 2 excluded; survivors 1,3,4 by base

    // The shell builds author_key + keep parallel to the scored order, then caps.
    const akey = try arena.alloc(u32, order.len);
    const keep = try arena.alloc(bool, order.len);
    for (order, 0..) |ref, i| {
        akey[i] = switch (ref.raw()) {
            1, 2, 4 => 0, // author A
            else => 1, // author B
        };
        keep[i] = true; // no moderation removal in this case
    }

    const final = try applyCaps(arena, order, akey, keep, cfg);
    try t.expectEqual(@as(usize, 2), final.len); // A capped to 1, B has 1
    try t.expectEqual(@as(u32, 1), final[0].raw()); // A's top survivor (ref 1)
    try t.expectEqual(@as(u32, 3), final[1].raw()); // B (ref 3); ref 4 dropped by the cap
}

test "applyCaps: per-author diversity cap keeps at most N per author, in rank order" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Ranked order: five posts; author 7 owns three of them (refs 1,2,4).
    const order = [_]Ref{ Ref.from(1), Ref.from(2), Ref.from(3), Ref.from(4), Ref.from(5) };
    const author = [_]u32{ 7, 7, 9, 7, 9 };
    const keep = [_]bool{ true, true, true, true, true };

    var cfg = DEFAULT_CONFIG;
    cfg.max_per_author = 2;
    const out = try applyCaps(arena, &order, &author, &keep, cfg);
    // author 7 capped at its first two (1,2 — ref 4 dropped); author 9 keeps both.
    try t.expectEqual(@as(usize, 4), out.len);
    try t.expectEqual(@as(u32, 1), out[0].raw());
    try t.expectEqual(@as(u32, 2), out[1].raw());
    try t.expectEqual(@as(u32, 3), out[2].raw());
    try t.expectEqual(@as(u32, 5), out[3].raw()); // ref 4 (author 7's third) removed
}

test "applyCaps: moderation removal is non-bypassable and frees the author slot" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // All by author 7; cap 1. The top-ranked post is moderation-hidden, so the
    // cap must NOT be spent on it — the next visible post by 7 takes the slot.
    const order = [_]Ref{ Ref.from(1), Ref.from(2), Ref.from(3) };
    const author = [_]u32{ 7, 7, 7 };
    const keep = [_]bool{ false, true, true }; // ref 1 hidden by moderation

    var cfg = DEFAULT_CONFIG;
    cfg.max_per_author = 1;
    const out = try applyCaps(arena, &order, &author, &keep, cfg);
    try t.expectEqual(@as(usize, 1), out.len);
    try t.expectEqual(@as(u32, 2), out[0].raw()); // ref 1 removed, ref 2 takes the slot
}

test "validated: NaN/Inf and out-of-range fields are sanitized to safe data" {
    const t = std.testing;
    var hostile = DEFAULT_CONFIG;
    hostile.w_repost = std.math.nan(f32); // would poison every score
    hostile.w_like = 1e30; // absurd dominance
    hostile.query.source_mix = 5.0; // out of [0,1]
    hostile.state_budget_bytes = 1 << 30; // 1 GiB — above the hard cap
    hostile.query.max_candidates = 0;

    var greedy = DEFAULT_CONFIG;
    greedy.query.max_candidates = 4_000_000_000; // a DoS-sized retrieval request
    try t.expectEqual(max_candidates_hard_cap, validated(greedy).query.max_candidates); // clamped

    const v = validated(hostile);
    try t.expect(std.math.isFinite(v.w_repost));
    try t.expectEqual(DEFAULT_CONFIG.w_repost, v.w_repost); // NaN → default
    try t.expectEqual(@as(f32, 100_000), v.w_like); // clamped to the ceiling
    try t.expectEqual(@as(f32, 1.0), v.query.source_mix); // pinned to [0,1]
    try t.expectEqual(state_budget_hard_cap, v.state_budget_bytes); // capped
    try t.expectEqual(DEFAULT_CONFIG.query.max_candidates, v.query.max_candidates); // 0 → default

    // A valid config is unchanged.
    const ok = validated(DEFAULT_CONFIG);
    try t.expectEqual(DEFAULT_CONFIG.w_repost, ok.w_repost);
    try t.expectEqual(DEFAULT_CONFIG.recency_half_life_hrs, ok.recency_half_life_hrs);
}

test "validated: an oversized rule-list is clipped to the cap (CPU-DoS wall)" {
    const t = std.testing;
    // A hostile config asking for far more rules than the engine will run.
    const flood = [_]rules_mod.Rule{
        .{ .predicate = .{ .kind = .always }, .action = .{ .kind = .boost, .factor = 1.01 } },
    } ** (max_rules + 50);
    var hostile = DEFAULT_CONFIG;
    hostile.rules = &flood;

    const v = validated(hostile);
    try t.expectEqual(max_rules, v.rules.len); // clipped, not rejected (E4)

    // A within-budget rule-list is untouched (borrows the same memory).
    const small = [_]rules_mod.Rule{
        .{ .predicate = .{ .kind = .out_of_network }, .action = .{ .kind = .boost, .factor = 1.5 } },
    };
    var ok = DEFAULT_CONFIG;
    ok.rules = &small;
    try t.expectEqual(@as(usize, 1), validated(ok).rules.len);
}

test "applyCaps: max_per_author 0 means no cap; moderation still applies" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const order = [_]Ref{ Ref.from(1), Ref.from(2), Ref.from(3) };
    const author = [_]u32{ 7, 7, 7 };
    const keep = [_]bool{ true, false, true }; // ref 2 hidden

    var cfg = DEFAULT_CONFIG;
    cfg.max_per_author = 0; // unlimited
    const out = try applyCaps(arena, &order, &author, &keep, cfg);
    try t.expectEqual(@as(usize, 2), out.len); // all of author 7's VISIBLE posts kept
    try t.expectEqual(@as(u32, 1), out[0].raw());
    try t.expectEqual(@as(u32, 3), out[1].raw());
}
