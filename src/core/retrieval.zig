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

//! B1 classification: CORE (pure). **DISCOVER Phase 0 — the retrieval query.**
//!
//! Feed quality lives in RETRIEVAL — *which* posts enter the candidate pool —
//! far more than in the ranking formula. The config tiers so far let a creator
//! re-rank an engine-chosen pool; this module lets them shape the POOL: a small,
//! composable set of SOURCE operators ("where do candidates come from") that the
//! creator picks and weights. The HOST runs each source over its indexes, so the
//! creator shapes the pool without ever touching the network (D2 discipline) —
//! nothing invasive is expressible, exactly like the L2 rule / L3 VM vocabularies.
//!
//! This is the shared foundation for two tiers at once: it IS the easy-tier menu
//! (a config field a friendly builder fills), AND it defines the exact retrieval
//! CAPABILITIES the future guest VM will call (`GUEST_TIER_ROADMAP.md`, Phase 0).
//!
//! Decoupling (the `rules.zig` pattern): this module knows nothing about
//! `discover.Candidate` or the store. The caller fills a plain `Facts` per
//! candidate from its own indexes and asks a pure question; the module answers
//! with a pool weight (or "not retrieved"). Same input ⇒ same output, no I/O.

const std = @import("std");
const assert = std.debug.assert;

/// The source-operator vocabulary — the composable "where do candidates come
/// from" ingredients a creator picks. FIXED, like the rule/VM vocabularies. The
/// host runs each source over its own indexes; the creator only names and weights
/// them, so nothing invasive (no network, no raw traversal) is expressible.
///
/// Slice-1 sources read only in-network + engagement facts (cheap, no index
/// plumbing). The index-backed sources — `tag_scope`, `graph_walk(hops)`,
/// `network_split`, `similar_to` — attach here as the AppView index becomes
/// parameterizable (each needs a new `Facts` field + host support); adding one is
/// a deliberate act, guarded below.
pub const SourceKind = enum(u8) {
    all, // every available candidate — the baseline pool
    follows, // in-network: from accounts the viewer follows
    discovery, // out-of-network: beyond the follow graph (the discovery pool)
    trending, // engagement ≥ threshold — viral, regardless of network
    tag_scope, // posts carrying a named topic tag (zone) — a zone-scoped pool

    comptime {
        // Vocabulary guard: five sources. Widening retrieval is a deliberate
        // decision (a new source usually needs a new Fact + a host index) — bump
        // this on purpose, mirroring `algo_vm.Fact`'s count guard. `tag_scope` is
        // the first index-backed source with a real on-device data source today
        // (the resident zone tags); the network-scale sources (`graph_walk`,
        // `network_split`, `similar_to`) attach the same way when the AppView
        // candidate-sourcing endpoint lands.
        assert(@typeInfo(SourceKind).@"enum".fields.len == 5);
    }
};

/// One source in a retrieval query: which operator, how strongly it weights the
/// candidates it pulls in, and a kind-specific numeric threshold. HOT — iterated
/// `candidates × sources` in the scorer — so it carries an exact size guard (A7).
pub const Source = struct {
    kind: SourceKind,
    weight: f32 = 1.0, // relative contribution of this source's posts to the pool
    threshold: f32 = 0, // kind-specific: `trending` = minimum engagement; else unused
    /// `tag_scope` only: the zone tag this source pulls (e.g. "zig"). Empty for
    /// every other source. Borrows the config record's bytes (it travels IN the
    /// serialized algorithm, exactly like the guest program / rule params), so a
    /// source's lifetime is its config's — never freed here (A1: plain data).
    tag: []const u8 = &.{},

    comptime {
        // Budget 32: the tag slice (ptr+len = 16, 8-byte aligned) + two f32 (8) +
        // the enum tag (1) = 25, padded to 32 at the slice's 8-byte alignment. A7.1:
        // the size grew from 12 to carry `tag_scope`'s one string parameter — the
        // minimal representation of a named-tag source (an index into a separate
        // table would cross a module boundary, A5); the slice keeps retrieval
        // decoupled from any store and lets std.json round-trip it as a plain string.
        assert(@sizeOf(Source) == 32);
    }
};

/// The per-candidate facts a source reads — a plain value the CALLER fills from
/// its own store (DECOUPLED from `discover.Candidate`, exactly like `rules.Facts`,
/// so this module never depends on the candidate layout or the index). Slice-1
/// sources need only these two; richer sources add facts when they land.
/// A7.2: cold — one is built per candidate at the call site and passed by value.
pub const Facts = struct {
    in_network: bool,
    engagement: u32, // like + repost + reply
    /// The candidate's topic tags (zones), each a plain string — filled by the
    /// caller from its own store, read only by `tag_scope`. Empty when the caller
    /// doesn't plumb tags (no `tag_scope` in the query) so nothing else pays for it.
    tags: []const []const u8 = &.{},
};

/// Does this source pull in the candidate? Pure, total.
pub fn includes(s: Source, f: Facts) bool {
    return switch (s.kind) {
        .all => true,
        .follows => f.in_network,
        .discovery => !f.in_network,
        .trending => @as(f64, @floatFromInt(f.engagement)) >= s.threshold,
        .tag_scope => for (f.tags) |tag| {
            if (std.mem.eql(u8, tag, s.tag)) break true;
        } else false,
    };
}

/// Does this query reference `tag_scope`? The caller uses this to decide whether to
/// pay for materializing per-candidate tags (F5: no tag_scope ⇒ no tag plumbing).
/// Pure, total.
pub fn needsTags(sources: []const Source) bool {
    for (sources) |s| if (s.kind == .tag_scope) return true;
    return false;
}

/// The retrieval weight for a candidate under a source list:
///   - `null`  → NOT retrieved (matched no source) — the caller drops it from the pool.
///   - `w`     → in the pool; `w` is the SUMMED weight of the matching sources, so a
///     post pulled by several sources (e.g. in-network AND trending) surfaces
///     stronger. The scorer multiplies the base score by this.
///
/// An EMPTY source list = the whole available pool at weight 1.0, so a config with
/// no retrieval query behaves exactly as before — backward compatible (F5). Pure,
/// total, no allocation. DEFENSIVE: a non-finite or non-positive weight is ignored
/// (it can never poison the pool weight with NaN/Inf or a negative), so a shared,
/// untrusted query is safe to run with no separate validation pass — same posture
/// as `rules.apply`.
pub fn poolWeight(sources: []const Source, f: Facts) ?f32 {
    if (sources.len == 0) return 1.0; // no query ⇒ include everything (identity)
    var w: f32 = 0;
    var matched = false;
    for (sources) |s| {
        if (!includes(s, f)) continue;
        matched = true;
        if (std.math.isFinite(s.weight) and s.weight > 0) w += s.weight;
    }
    return if (matched) w else null;
}

// ---------------------------------------------------------------------------
// Tests — pure (B2), no allocation, no I/O.
// ---------------------------------------------------------------------------

const t = std.testing;

test "guard: Source is exactly sized; the source vocabulary count" {
    try t.expectEqual(@as(usize, 32), @sizeOf(Source));
    try t.expectEqual(@as(usize, 5), @typeInfo(SourceKind).@"enum".fields.len);
}

test "empty query includes everything at weight 1 (backward compatible)" {
    try t.expectEqual(@as(?f32, 1.0), poolWeight(&.{}, .{ .in_network = true, .engagement = 0 }));
    try t.expectEqual(@as(?f32, 1.0), poolWeight(&.{}, .{ .in_network = false, .engagement = 999 }));
}

test "follows pulls in-network only; discovery pulls out-of-network only" {
    const follows = [_]Source{.{ .kind = .follows }};
    const discovery = [_]Source{.{ .kind = .discovery }};
    try t.expectEqual(@as(?f32, 1.0), poolWeight(&follows, .{ .in_network = true, .engagement = 0 }));
    try t.expectEqual(@as(?f32, null), poolWeight(&follows, .{ .in_network = false, .engagement = 0 })); // dropped
    try t.expectEqual(@as(?f32, 1.0), poolWeight(&discovery, .{ .in_network = false, .engagement = 0 }));
    try t.expectEqual(@as(?f32, null), poolWeight(&discovery, .{ .in_network = true, .engagement = 0 }));
}

test "trending pulls posts at or above the engagement threshold" {
    const q = [_]Source{.{ .kind = .trending, .threshold = 100 }};
    try t.expectEqual(@as(?f32, 1.0), poolWeight(&q, .{ .in_network = false, .engagement = 150 }));
    try t.expectEqual(@as(?f32, null), poolWeight(&q, .{ .in_network = false, .engagement = 99 })); // below → dropped
}

test "sources COMPOSE: a post matched by several sums their weights (multi-source surfaces stronger)" {
    // "my follows' posts + viral posts, viral-in-network boosted."
    const q = [_]Source{
        .{ .kind = .follows, .weight = 1.0 },
        .{ .kind = .trending, .weight = 0.5, .threshold = 100 },
    };
    // In-network AND trending → both match → 1.0 + 0.5 = 1.5 (boosted).
    try t.expectEqual(@as(?f32, 1.5), poolWeight(&q, .{ .in_network = true, .engagement = 200 }));
    // In-network, not trending → only follows → 1.0.
    try t.expectEqual(@as(?f32, 1.0), poolWeight(&q, .{ .in_network = true, .engagement = 10 }));
    // Out-of-network, trending → only trending → 0.5.
    try t.expectEqual(@as(?f32, 0.5), poolWeight(&q, .{ .in_network = false, .engagement = 200 }));
    // Out-of-network, not trending → matched nothing → dropped from the pool.
    try t.expectEqual(@as(?f32, null), poolWeight(&q, .{ .in_network = false, .engagement = 10 }));
}

test "tag_scope pulls posts carrying the named tag, drops the rest" {
    const q = [_]Source{.{ .kind = .tag_scope, .tag = "zig" }};
    const zig_post = Facts{ .in_network = false, .engagement = 0, .tags = &.{ "rust", "zig" } };
    const other_post = Facts{ .in_network = true, .engagement = 999, .tags = &.{"cooking"} };
    const untagged = Facts{ .in_network = true, .engagement = 999, .tags = &.{} };
    try t.expectEqual(@as(?f32, 1.0), poolWeight(&q, zig_post));
    try t.expectEqual(@as(?f32, null), poolWeight(&q, other_post)); // wrong tag → dropped
    try t.expectEqual(@as(?f32, null), poolWeight(&q, untagged)); // no tags → dropped
}

test "tag_scope COMPOSES with a network source (zone posts + your follows)" {
    // "posts in the zig zone, plus anything from my follows."
    const q = [_]Source{
        .{ .kind = .tag_scope, .tag = "zig", .weight = 1.0 },
        .{ .kind = .follows, .weight = 0.5 },
    };
    // In-network AND zig-tagged → both match → 1.5 (a followed zig post surfaces strongest).
    try t.expectEqual(@as(?f32, 1.5), poolWeight(&q, .{ .in_network = true, .engagement = 0, .tags = &.{"zig"} }));
    // Out-of-network zig post → only tag_scope → 1.0 (zone reaches beyond the follow graph).
    try t.expectEqual(@as(?f32, 1.0), poolWeight(&q, .{ .in_network = false, .engagement = 0, .tags = &.{"zig"} }));
    // In-network, untagged → only follows → 0.5.
    try t.expectEqual(@as(?f32, 0.5), poolWeight(&q, .{ .in_network = true, .engagement = 0, .tags = &.{} }));
    // Out-of-network, untagged → nothing → dropped.
    try t.expectEqual(@as(?f32, null), poolWeight(&q, .{ .in_network = false, .engagement = 0, .tags = &.{} }));
}

test "needsTags: only a query that references tag_scope asks for tags" {
    try t.expect(!needsTags(&.{}));
    try t.expect(!needsTags(&[_]Source{.{ .kind = .follows }}));
    try t.expect(needsTags(&[_]Source{ .{ .kind = .follows }, .{ .kind = .tag_scope, .tag = "zig" } }));
}

test "defensive: a hostile non-finite / negative weight can't poison the pool weight" {
    const q = [_]Source{
        .{ .kind = .all, .weight = std.math.nan(f32) },
        .{ .kind = .all, .weight = -5.0 },
        .{ .kind = .all, .weight = 2.0 },
    };
    // Only the finite, positive 2.0 contributes; the candidate is still in the pool.
    try t.expectEqual(@as(?f32, 2.0), poolWeight(&q, .{ .in_network = true, .engagement = 0 }));
}
