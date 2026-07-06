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

//! B1 classification: CORE (pure data). **GUEST TIER — the Zal template library.**
//! See `GUEST_TIER_ROADMAP.md`.
//!
//! The flagship feeds, written as real Zal programs — both the proof that the
//! language can express a genuine algorithm and the starter models a creator forks.
//! Every source here COMPILES, VALIDATES, and RUNS (the tests do exactly that on
//! sample candidates); they are the canonical examples the reference documentation
//! is written against.
//!
//! The scoring facts a `score()` reads (public, per-candidate): `like_count`,
//! `repost_count`, `reply_count`, `age_hrs`, `author_rep` (0..1), `in_network`.
//! On-device attention is read through capability CALLS — `attention_dwell()`,
//! `attention_clicked()` — which never leave the device (a program that doesn't
//! call them provably uses no behavioral data). `base_score` (the engine's own
//! score) is also available, but these programs compute from raw facts so the
//! whole mechanism is visible.
//!
//! Recency uses a RATIONAL decay (`w / (age + w)`), not an exponential — Zal has no
//! `exp`/`pow`, and rational decay is deterministic and reproducible across
//! machines (the property the config-tier `pow` couldn't promise).

const std = @import("std");

/// **Zat4 Discover** — Twitter-Heavy-Ranker-flavoured, and it adapts to you
/// on-device. A reply is worth far more than a like (people invest effort in
/// replies); your own attention nudges what you see, read locally and never sent
/// anywhere; velocity surfaces posts climbing fast; strong out-of-network posts get
/// a discovery lift.
pub const zat4_discover: []const u8 =
    \\fn score() num {
    \\  // Public engagement, weighted like Twitter's ranker (a reply >> a like).
    \\  var eng = like_count + repost_count * 2.0 + reply_count * 27.0;
    \\  // On-device attention (adaptive): your dwell + clicks. Read locally; the
    \\  // sandbox has no way to send this anywhere.
    \\  eng = eng + attention_dwell() * 20.0 + attention_clicked() * 24.0;
    \\  // Cold-start floor: a brand-new post still gets a small chance.
    \\  eng = eng + 1.0;
    \\  // Freshness: a soft, deterministic ~6h decay (no exponential needed).
    \\  var s = eng * (6.0 / (age_hrs + 6.0));
    \\  // Velocity: reward fast-accruing amplification + conversation (trending).
    \\  s = s * (1.0 + (repost_count + reply_count) / (age_hrs + 2.0));
    \\  // A mild public author-reputation prior.
    \\  s = s * (1.0 + author_rep * 0.5);
    \\  // Out-of-network discovery: lift strong posts from beyond your follows.
    \\  if (!in_network && eng > 150.0) { s = s * 1.4; }
    \\  // Stale guard: push day-old+ content down.
    \\  if (age_hrs > 48.0) { s = s * 0.4; }
    \\  return s;
    \\}
;

/// **Zat4 Private Discover** — the best feed achievable with ZERO behavioral data.
/// The same spirit as Discover, but it NEVER reads your attention (no dwell, no
/// clicks): it leans on the public conversation graph, weighting replies even
/// harder (what your network finds worth discussing), with a fresher window.
pub const zat4_discover_private: []const u8 =
    \\fn score() num {
    \\  // Public engagement ONLY; replies weighted even harder (conversation-first).
    \\  var eng = like_count + repost_count * 2.0 + reply_count * 40.0;
    \\  eng = eng + 1.0; // cold-start floor
    \\  // A fresher ~4h window than Discover.
    \\  var s = eng * (4.0 / (age_hrs + 4.0));
    \\  s = s * (1.0 + (repost_count + reply_count) / (age_hrs + 2.0));
    \\  s = s * (1.0 + author_rep * 0.5);
    \\  if (!in_network && eng > 150.0) { s = s * 1.4; }
    \\  if (age_hrs > 48.0) { s = s * 0.4; }
    \\  return s;
    \\}
;

/// **Most Liked** — the simplest possible starter: rank by likes alone.
pub const most_liked: []const u8 =
    \\fn score() num { return like_count; }
;

/// **Most Recent** — reverse-chronological: the newer the post, the higher.
pub const most_recent: []const u8 =
    \\fn score() num { return 0.0 - age_hrs; }
;

/// **Calm** — down-ranks pile-ons: rewards a bit of conversation but divides by the
/// crowd size so a viral dogpile doesn't dominate. Candidate-side, no behavioral.
pub const calm: []const u8 =
    \\fn score() num {
    \\  var eng = like_count + reply_count * 4.0;
    \\  // Divide by a growing crowd factor so high-velocity pile-ons are tempered.
    \\  return eng / (1.0 + (repost_count + reply_count) / 20.0);
    \\}
;

/// **Fresh First** — the canonical POOL-VISIBLE starter (arrange(), cross-item):
/// rank by engagement, then PULL every post younger than an hour to the front.
/// Two passes over the ranked pool; the second emits everything — an already-
/// placed post is simply ignored (emit() is once-per-post), so nothing is lost.
/// This shape (walk the pool, place what matters, then place the rest) is the
/// skeleton of most arrangement algorithms.
pub const fresh_first: []const u8 =
    \\fn score() num { return like_count + repost_count * 2.0; }
    \\fn arrange() num {
    \\  var n = pool_len();
    \\  var i = 0.0;
    \\  while (i < n) {
    \\    if (pool_read(i, age_hrs) < 1.0) { emit(i); }
    \\    i = i + 1.0;
    \\  }
    \\  i = 0.0;
    \\  while (i < n) { emit(i); i = i + 1.0; }
    \\  return 0.0;
    \\}
;

/// One entry in the starter catalogue: a name + its Zal source. A7.2: cold table.
pub const Template = struct { name: []const u8, source: []const u8 };

/// Every starter, in one table — the seed of the marketplace's "start from a
/// template" list and the worked examples for the reference doc.
/// **Search Tiers** — the GOOGLE shape, fundamentally: the pool is an INDEX,
/// not your social graph (`retrieve()` never calls `follows()` — the whole
/// break from the timeline architecture), entered by relevance/authority the
/// way a query enters an index, and arranged in tiers the way a results page
/// is. The showcase that Zal changes retrieval's FUNDAMENTALS, not weights.
pub const search_tiers: []const u8 =
    \\fn retrieve() num {
    \\  // A search engine's pool is THE INDEX, not your timeline: everything
    \\  // beyond your follows, plus whatever is provably resonating.
    \\  discovery(1.0);
    \\  trending(50.0, 1.0);
    \\  return 0.0;
    \\}
    \\fn score() num {
    \\  // Relevance, not recency: all-time quality plus a small rate term, so
    \\  // a durably-good post outranks a briefly-hot one (a result, not news).
    \\  var quality = like_count + repost_count * 3.0 + reply_count * 9.0;
    \\  var rate = quality / (age_hrs + 1.0);
    \\  return quality * 0.7 + rate * 0.3 + author_rep * 50.0;
    \\}
    \\fn arrange() num {
    \\  // The results page: tier 1 = trusted author + real engagement;
    \\  // tier 2 = conversation-rich; then everything else in score order.
    \\  var n = pool_len();
    \\  var i = 0.0;
    \\  while (i < n) {
    \\    if (pool_read(i, author_rep) > 0.6 && pool_read(i, like_count) > 5.0) { emit(i); }
    \\    i = i + 1.0;
    \\  }
    \\  i = 0.0;
    \\  while (i < n) {
    \\    if (pool_read(i, reply_count) > 3.0) { emit(i); }
    \\    i = i + 1.0;
    \\  }
    \\  i = 0.0;
    \\  while (i < n) { emit(i); i = i + 1.0; }
    \\  return 0.0;
    \\}
;

/// **Catalog** — the AMAZON shape, fundamentally: the pool is a CATEGORY
/// INDEX (`retrieve()` scopes to one zone — the department you're browsing),
/// sorted by all-time quality the way a storefront sorts by rating — a
/// product's rating doesn't expire the way a post's novelty does. Swap the
/// tag and it's a different shop; the architecture is the template.
pub const catalog: []const u8 =
    \\fn retrieve() num {
    \\  // A storefront's pool is a department, not a timeline. The tag IS
    \\  // the department — change it to stand in a different aisle.
    \\  tag_scope("marketplace", 1.0);
    \\  return 0.0;
    \\}
    \\fn score() num {
    \\  // All-time quality, like a product rating; age barely matters.
    \\  var q = like_count * 2.0 + repost_count * 4.0 + reply_count * 3.0;
    \\  return q * (1.0 + author_rep) / (1.0 + age_hrs * 0.01);
    \\}
;

pub const all = [_]Template{
    .{ .name = "Zat4 Discover", .source = zat4_discover },
    .{ .name = "Zat4 Private Discover", .source = zat4_discover_private },
    .{ .name = "Most Liked", .source = most_liked },
    .{ .name = "Most Recent", .source = most_recent },
    .{ .name = "Calm", .source = calm },
    .{ .name = "Fresh First", .source = fresh_first },
    .{ .name = "Search Tiers", .source = search_tiers },
    .{ .name = "Catalog", .source = catalog },
};

// ---------------------------------------------------------------------------
// Tests — every template compiles, validates, and RUNS; the privacy claim of
// each is provable from its bytecode.
// ---------------------------------------------------------------------------

const t = std.testing;
const parse = @import("zal_parse.zig");
const compile = @import("zal_compile.zig");
const vm = @import("guest_vm.zig");
const guest_abi = @import("guest_abi.zig");

/// A live mock host so `attention_*` calls return something during the tests
/// (dwell 0.5, clicked from arg0). Real capabilities are Phase 4.
fn mockHostCall(ctx: *anyopaque, cap: guest_abi.Capability, a0: f64, a1: f64) f64 {
    _ = ctx;
    _ = a1;
    return switch (cap) {
        .attention_dwell => 0.5,
        .attention_clicked => if (a0 != 0) @as(f64, 1) else 0,
        else => 0,
    };
}

fn compileScore(arena: std.mem.Allocator, src: []const u8) !compile.Result {
    const ast = try parse.parse(arena, src);
    return compile.compile(arena, &ast, "score");
}

test "templates: every starter compiles, validates, and runs to a finite score" {
    var a = std.heap.ArenaAllocator.init(t.allocator);
    defer a.deinit();
    var ctx: u8 = 0;
    const host = vm.Host{ .ctx = &ctx, .call = mockHostCall };
    const sample: guest_abi.CandidateView = .{
        .like_count = 100, .repost_count = 10, .reply_count = 30,
        .age_hrs = 4.0, .author_rep = 0.5, .in_network = true,
    };
    for (all) |tmpl| {
        const res = try compileScore(a.allocator(), tmpl.source);
        try t.expect(res.ok()); // clean compile
        try t.expect(vm.validProgram(res.program)); // the trusted validator accepts it
        const s = vm.run(res.program, sample, 0, vm.default_fuel, &host);
        try t.expect(std.math.isFinite(s)); // it runs, totally
    }
}

test "Fresh First: the whole artifact compiles and its arrange() survives the validator + entry wall" {
    var a = std.heap.ArenaAllocator.init(t.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const ast = try parse.parse(arena, fresh_first);
    const art = try compile.compileArtifact(arena, &ast);
    try t.expect(art.ok());
    try t.expect(art.arrange.len > 0);
    try t.expect(vm.validProgram(art.arrange));
    try t.expect(vm.entryViolation(art.arrange, .arrange) == null); // pool + emit only
    try t.expect(!compile.usesBehavioral(art.arrange)); // pool reads are public
}

test "Search Tiers: the tiered arrange() compiles and survives the validator + entry wall" {
    var a = std.heap.ArenaAllocator.init(t.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const ast = try parse.parse(arena, search_tiers);
    const art = try compile.compileArtifact(arena, &ast);
    try t.expect(art.ok());
    try t.expect(art.arrange.len > 0);
    try t.expect(vm.validProgram(art.arrange));
    try t.expect(vm.entryViolation(art.arrange, .arrange) == null); // pool + emit only
    try t.expect(!compile.usesBehavioral(art.arrange)); // pool reads are public
    // The Google-shape point: the pool is composed by retrieve(), and it is
    // an index (discovery + trending), never the follow graph.
    try t.expect(art.retrieve.len > 0);
    try t.expect(vm.entryViolation(art.retrieve, .retrieve) == null);
    const caps = vm.usedCapabilities(art.retrieve);
    try t.expect(caps.contains(.source_discovery));
    try t.expect(caps.contains(.source_trending));
    try t.expect(!caps.contains(.source_follows));
}

test "the developer guide's worked examples compile whole (ZAL_DEVELOPER_GUIDE §12 stays honest)" {
    var a = std.heap.ArenaAllocator.init(t.allocator);
    defer a.deinit();
    const arena = a.allocator();
    // The examples that are NOT already templates above: the zone-first feed
    // (retrieve + has_tag together) and the pool-relative cap (a cross-item
    // score that aggregates the pool). If an engine change breaks either, the
    // guide is lying to developers — fix the doc in the same change.
    const zone_first =
        \\fn retrieve() num {
        \\  tag_scope("zig", 1.5);
        \\  follows(1.0);
        \\  return 0.0;
        \\}
        \\fn score() num {
        \\  var s = like_count + reply_count * 27.0;
        \\  if (has_tag("zig")) { s = s * 2.0; }
        \\  return s * (6.0 / (age_hrs + 6.0));
        \\}
    ;
    const pool_cap =
        \\fn score() num {
        \\  var n = pool_len();
        \\  var sum = 0.0;
        \\  var i = 0.0;
        \\  while (i < n) {
        \\    sum = sum + pool_read(i, base_score);
        \\    i = i + 1.0;
        \\  }
        \\  var avg = 1.0;
        \\  if (n > 0.0) { avg = sum / n; }
        \\  var s = like_count + reply_count * 27.0;
        \\  if (s > avg * 10.0) { s = avg * 10.0; }
        \\  return s;
        \\}
    ;
    inline for (.{ zone_first, pool_cap }) |src| {
        const ast = try parse.parse(arena, src);
        const art = try compile.compileArtifact(arena, &ast);
        try t.expect(art.ok());
        try t.expect(vm.validProgram(art.score));
    }
}

test "templates: the behavioral claim is PROVABLE from bytecode (invariant 6)" {
    var a = std.heap.ArenaAllocator.init(t.allocator);
    defer a.deinit();
    // Discover reads attention → provably behavioral. Private and the rest do not.
    const disc = try compileScore(a.allocator(), zat4_discover);
    try t.expect(compile.usesBehavioral(disc.program));
    const priv = try compileScore(a.allocator(), zat4_discover_private);
    try t.expect(!compile.usesBehavioral(priv.program));
    const calm_r = try compileScore(a.allocator(), calm);
    try t.expect(!compile.usesBehavioral(calm_r.program));
}

test "Zat4 Discover behaves: more engagement ranks higher; stale posts are damped" {
    var a = std.heap.ArenaAllocator.init(t.allocator);
    defer a.deinit();
    var ctx: u8 = 0;
    const host = vm.Host{ .ctx = &ctx, .call = mockHostCall };
    const res = try compileScore(a.allocator(), zat4_discover);
    try t.expect(res.ok());

    const base: guest_abi.CandidateView = .{
        .like_count = 50, .repost_count = 5, .reply_count = 10,
        .age_hrs = 2.0, .author_rep = 0.5, .in_network = true,
    };
    var more = base;
    more.reply_count = 40; // far more conversation → should rank higher
    var stale = base;
    stale.age_hrs = 100.0; // day-old+ → the stale guard damps it

    const s_base = vm.run(res.program, base, 0, vm.default_fuel, &host);
    const s_more = vm.run(res.program, more, 0, vm.default_fuel, &host);
    const s_stale = vm.run(res.program, stale, 0, vm.default_fuel, &host);
    try t.expect(s_more > s_base); // engagement lifts
    try t.expect(s_stale < s_base); // staleness damps
}

test "Zat4 Discover: a strong out-of-network post gets the discovery lift" {
    var a = std.heap.ArenaAllocator.init(t.allocator);
    defer a.deinit();
    var ctx: u8 = 0;
    const host = vm.Host{ .ctx = &ctx, .call = mockHostCall };
    const res = try compileScore(a.allocator(), zat4_discover);

    // A strong post (high engagement so eng > 150), in-network vs out-of-network.
    const inn: guest_abi.CandidateView = .{
        .like_count = 200, .repost_count = 20, .reply_count = 20,
        .age_hrs = 3.0, .author_rep = 0.5, .in_network = true,
    };
    var oon = inn;
    oon.in_network = false; // same post, but out of network → +40% discovery lift
    const s_in = vm.run(res.program, inn, 0, vm.default_fuel, &host);
    const s_oon = vm.run(res.program, oon, 0, vm.default_fuel, &host);
    try t.expect(s_oon > s_in); // discovery boost applied
}
