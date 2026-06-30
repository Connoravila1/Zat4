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

//! B1 classification: CORE (pure). **The transparency data model — DISCOVER D5
//! / invariant 5.** The pure transform behind every creator's transparency page:
//! a `discover.FeedConfig` → an ordered, per-field, plain-English explanation of
//! EXACTLY what the algorithm does. Not a summary — every knob the engine reads
//! is one row here, with its precise value and what it means.
//!
//! Paired with `core/algorithm.serialize` (which gives the byte-exact record the
//! CID addresses — the "file"), this gives the page both halves of the
//! transparency promise: what runs, byte-for-byte, AND what each line means in
//! human terms. The CID is the guarantee; this is the reading of it.
//!
//! **Completeness is enforced at COMPILE TIME.** `explain` iterates the config's
//! fields by reflection and looks each one up in `metaFor`, whose `else` branch
//! is a `@compileError`. So the instant a field is ADDED to `FeedConfig` (or
//! `Query`) without an explanation, the build fails — the transparency can never
//! silently drift behind what the engine actually reads. This is the A7-style
//! "the compiler enforces the discipline" pattern applied to honesty.

const std = @import("std");
const Allocator = std.mem.Allocator;
const discover = @import("discover.zig");

/// Which aspect of ranking a field governs — lets a page group the rows.
pub const Category = enum {
    engagement, // how much each public interaction counts
    freshness, // recency + early-velocity
    personalization, // author reputation, topic relevance, on-device learning
    diversity, // per-author / per-subtopic caps
    retrieval, // what pool is pulled in to rank
    privacy_state, // on-device memory budget
};

/// One explained field of an algorithm. The `field` is the EXACT serialized key
/// (so it maps 1:1 to the byte-exact record the CID addresses); `label` is its
/// human name; `value` is its precise current value; `meaning` is the plain
/// reading; `behavioral` marks a field that reads your on-device ATTENTION data
/// (the privacy story — pinned to 0 in the candidate-side-only feeds).
/// A7.2: cold view-model — a handful (one per config field) built once per
/// transparency-page open, never a hot loop. Size guard waived.
pub const FieldExplanation = struct {
    field: []const u8,
    label: []const u8,
    value: []const u8,
    meaning: []const u8,
    category: Category,
    behavioral: bool,
};

/// The human metadata for one field (everything but its runtime value).
/// A7.2: cold — comptime-only descriptors, never held in a collection. Waived.
const Meta = struct {
    label: []const u8,
    meaning: []const u8,
    category: Category,
    behavioral: bool = false,
};

/// The single source of per-field truth. A `comptime` switch over EVERY leaf
/// field name in `FeedConfig`/`Query`; the `else` is a hard compile error, so a
/// new field with no entry fails the build (the completeness guarantee). Plain,
/// honest wording — what the knob does, not why it's good.
fn metaFor(comptime name: []const u8) Meta {
    return if (comptime std.mem.eql(u8, name, "w_like")) .{
        .label = "Like weight",
        .meaning = "How much a like counts. This is the baseline (1.0) every other signal is measured against.",
        .category = .engagement,
    } else if (comptime std.mem.eql(u8, name, "w_repost")) .{
        .label = "Repost weight",
        .meaning = "How much a repost counts — amplification and reach.",
        .category = .engagement,
    } else if (comptime std.mem.eql(u8, name, "w_reply")) .{
        .label = "Reply weight",
        .meaning = "How much a reply counts. A reply costs effort, so it signals more than a like.",
        .category = .engagement,
    } else if (comptime std.mem.eql(u8, name, "w_reply_chain")) .{
        .label = "Author-replied-back weight",
        .meaning = "How much it counts when the author replies back into the thread — the strongest positive signal.",
        .category = .engagement,
    } else if (comptime std.mem.eql(u8, name, "w_bookmark")) .{
        .label = "Bookmark weight",
        .meaning = "How much a private save counts. Reads your saves, which never leave your device.",
        .category = .engagement,
        .behavioral = true,
    } else if (comptime std.mem.eql(u8, name, "w_profile_click")) .{
        .label = "Profile-click weight",
        .meaning = "How much it counts when you tap into the author's profile. Reads your taps, on your device only.",
        .category = .engagement,
        .behavioral = true,
    } else if (comptime std.mem.eql(u8, name, "w_link_click")) .{
        .label = "Link-click weight",
        .meaning = "How much it counts when you follow a link out of a post. Reads your taps, on your device only.",
        .category = .engagement,
        .behavioral = true,
    } else if (comptime std.mem.eql(u8, name, "w_negative")) .{
        .label = "Negative-feedback penalty",
        .meaning = "The penalty when you block, mute, or report. Negative, so it pushes a post down hard.",
        .category = .engagement,
    } else if (comptime std.mem.eql(u8, name, "recency_half_life_hrs")) .{
        .label = "Freshness half-life (hours)",
        .meaning = "How fast a post's freshness fades — after this many hours its freshness score halves. 0 means freshness never decays.",
        .category = .freshness,
    } else if (comptime std.mem.eql(u8, name, "velocity_boost")) .{
        .label = "Early-velocity boost",
        .meaning = "Whether a brand-new post that is climbing fast gets an early lift.",
        .category = .freshness,
    } else if (comptime std.mem.eql(u8, name, "author_rep_weight")) .{
        .label = "Author-reputation weight",
        .meaning = "How much the author's reputation counts. Computed from the public follow graph, not your behavior.",
        .category = .personalization,
    } else if (comptime std.mem.eql(u8, name, "relevance_weight")) .{
        .label = "Relevance weight",
        .meaning = "How much a post's relevance to you counts — derived from your public follows, not your attention.",
        .category = .personalization,
    } else if (comptime std.mem.eql(u8, name, "behavioral_weight")) .{
        .label = "On-device learning weight",
        .meaning = "How much your on-device attention (what you linger on) adjusts ranking. 0 means this feed never looks at your attention.",
        .category = .personalization,
        .behavioral = true,
    } else if (comptime std.mem.eql(u8, name, "max_per_author")) .{
        .label = "Max posts per author",
        .meaning = "The most posts from any single account per refresh, so no one voice dominates. 0 means no limit.",
        .category = .diversity,
    } else if (comptime std.mem.eql(u8, name, "max_per_subtopic")) .{
        .label = "Max posts per sub-topic",
        .meaning = "The most posts from any single sub-topic per refresh, so no one topic dominates.",
        .category = .diversity,
    } else if (comptime std.mem.eql(u8, name, "source_mix")) .{
        .label = "In-network vs discovery mix",
        .meaning = "The blend of accounts you follow vs discovery. 1.0 is follows only; 0.0 is discovery only.",
        .category = .retrieval,
    } else if (comptime std.mem.eql(u8, name, "max_candidates")) .{
        .label = "Candidates per refresh",
        .meaning = "How many posts are pulled in to be ranked each refresh.",
        .category = .retrieval,
    } else if (comptime std.mem.eql(u8, name, "recency_window_hrs")) .{
        .label = "Recency window (hours)",
        .meaning = "Only posts newer than this many hours are considered. 0 means no time window.",
        .category = .retrieval,
    } else if (comptime std.mem.eql(u8, name, "state_budget_bytes")) .{
        .label = "On-device memory budget (bytes)",
        .meaning = "The most this feed may remember about you, stored only on your device and never sent anywhere. Capped at 10 MiB.",
        .category = .privacy_state,
    } else @compileError("transparency: no explanation for FeedConfig field '" ++ name ++ "' — add one to metaFor (the completeness guarantee)");
}

/// Format one field's value exactly, in `arena`. Floats and ints print their
/// shortest faithful form; a toggle prints yes/no.
fn fmtValue(arena: Allocator, v: anytype) error{OutOfMemory}![]const u8 {
    return switch (@typeInfo(@TypeOf(v))) {
        .float => std.fmt.allocPrint(arena, "{d}", .{v}),
        .int => std.fmt.allocPrint(arena, "{d}", .{v}),
        .bool => arena.dupe(u8, if (v) "yes" else "no"),
        else => @compileError("transparency: unhandled value type " ++ @typeName(@TypeOf(v))),
    };
}

/// Explain a config: one `FieldExplanation` per leaf field, in declaration
/// order (which mirrors the serialized record), allocated in `arena`. PURE.
/// The compile-time completeness guarantee lives in `metaFor`.
pub fn explain(arena: Allocator, config: discover.FeedConfig) error{OutOfMemory}![]FieldExplanation {
    var list: std.ArrayListUnmanaged(FieldExplanation) = .empty;
    inline for (@typeInfo(discover.FeedConfig).@"struct".fields) |f| {
        if (comptime std.mem.eql(u8, f.name, "query")) {
            // Flatten the candidate-query sub-record into its own leaf rows.
            inline for (@typeInfo(discover.Query).@"struct".fields) |qf| {
                const m = metaFor(qf.name);
                try list.append(arena, .{
                    .field = "query." ++ qf.name,
                    .label = m.label,
                    .value = try fmtValue(arena, @field(config.query, qf.name)),
                    .meaning = m.meaning,
                    .category = m.category,
                    .behavioral = m.behavioral,
                });
            }
        } else {
            const m = metaFor(f.name);
            try list.append(arena, .{
                .field = f.name,
                .label = m.label,
                .value = try fmtValue(arena, @field(config, f.name)),
                .meaning = m.meaning,
                .category = m.category,
                .behavioral = m.behavioral,
            });
        }
    }
    return list.toOwnedSlice(arena);
}

// ---------------------------------------------------------------------------
// Classification — the PROVABLE privacy labels (DISCOVER invariant 6)
// ---------------------------------------------------------------------------

/// What the app can PROVE about an algorithm from its own config — not what the
/// author claims. Two orthogonal axes: whether it reads your attention data at
/// all, and whether it accumulates a model of you over time. Because the engine
/// gates behavioral access on these exact weights (the doorway), these labels
/// are facts about what the algorithm CAN reach, not promises.
/// A7.2: cold result — one per classification, transient. Size guard waived.
pub const Classification = struct {
    /// True iff the config reads ANY on-device attention signal. The four
    /// behavioral weights are the only doors to it; all zero ⇒ candidate-side
    /// only (the "uses no behavioral data" guarantee, system-proven).
    uses_behavioral: bool,
    /// True iff it maintains a per-user model across sessions (the on-device
    /// learner). `behavioral_weight` is the only path to that, so this is its
    /// non-zero-ness — momentary signals (clicks) read attention without learning.
    learns: bool,
    /// The on-device memory it may keep ABOUT YOU (0 when it doesn't learn — a
    /// non-learning feed accumulates nothing). Never leaves the device.
    state_budget_bytes: u32,
};

/// Derive the classification from the config's own numbers (pure). The behavioral
/// fields checked here are exactly the ones `metaFor` marks `.behavioral` — a
/// test cross-checks the two so they cannot drift apart.
pub fn classify(config: discover.FeedConfig) Classification {
    const learns = config.behavioral_weight != 0;
    const uses_behavioral = learns or
        config.w_bookmark != 0 or
        config.w_profile_click != 0 or
        config.w_link_click != 0;
    return .{
        .uses_behavioral = uses_behavioral,
        .learns = learns,
        .state_budget_bytes = if (learns) config.state_budget_bytes else 0,
    };
}

/// The plain behavioral-axis label for a transparency page / marketplace card.
pub fn behavioralLabel(c: Classification) []const u8 {
    return if (c.uses_behavioral)
        "Uses your attention data — on your device only, never sent anywhere"
    else
        "Uses no behavioral data — public signals only";
}

/// The plain stateful-axis label.
pub fn statefulLabel(c: Classification) []const u8 {
    return if (c.learns)
        "Learns from you over time, on-device"
    else
        "Stateless — ranks the same for everyone";
}

// ---------------------------------------------------------------------------
// Tests — pure, leak-checked (C6)
// ---------------------------------------------------------------------------

/// The leaf-field count, computed by reflection so the test can't go stale: all
/// of FeedConfig's fields, minus the nested `query`, plus Query's own fields.
fn leafFieldCount() usize {
    var n: usize = 0;
    inline for (@typeInfo(discover.FeedConfig).@"struct".fields) |f| {
        if (comptime std.mem.eql(u8, f.name, "query")) {
            n += @typeInfo(discover.Query).@"struct".fields.len;
        } else n += 1;
    }
    return n;
}

test "explain: one row per leaf field, every one labeled, valued, and explained" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const rows = try explain(arena, discover.DEFAULT_CONFIG);
    try t.expectEqual(leafFieldCount(), rows.len); // completeness: nothing omitted
    for (rows) |r| {
        try t.expect(r.field.len > 0);
        try t.expect(r.label.len > 0);
        try t.expect(r.value.len > 0);
        try t.expect(r.meaning.len > 0); // never a blank "see summary" row
    }
}

test "explain: values are exact and a field maps to its serialized key" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const rows = try explain(arena, discover.DEFAULT_CONFIG);
    var saw_reply = false;
    var saw_source_mix = false;
    for (rows) |r| {
        if (std.mem.eql(u8, r.field, "w_reply")) {
            saw_reply = true;
            try t.expectEqualStrings("27", r.value); // the calibrated default, exactly
        }
        if (std.mem.eql(u8, r.field, "query.source_mix")) {
            saw_source_mix = true;
            try t.expectEqualStrings("0.5", r.value);
        }
    }
    try t.expect(saw_reply and saw_source_mix);
}

test "explain: the behavioral fields are flagged, and they are all 0 in a candidate-side feed" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A candidate-side-only config (the Discover Private shape): every
    // behavioral field pinned to 0.
    var private = discover.DEFAULT_CONFIG;
    private.w_bookmark = 0;
    private.w_profile_click = 0;
    private.w_link_click = 0;
    private.behavioral_weight = 0;

    const rows = try explain(arena, private);
    var behavioral_count: usize = 0;
    for (rows) |r| {
        if (r.behavioral) {
            behavioral_count += 1;
            try t.expectEqualStrings("0", r.value); // proven candidate-side: every attention knob is 0
        }
    }
    try t.expectEqual(@as(usize, 4), behavioral_count); // bookmark, profile-click, link-click, learning
}

test "classify: candidate-side config proves no behavioral data, stateless" {
    const t = std.testing;
    var private = discover.DEFAULT_CONFIG;
    private.w_bookmark = 0;
    private.w_profile_click = 0;
    private.w_link_click = 0;
    private.behavioral_weight = 0;

    const c = classify(private);
    try t.expect(!c.uses_behavioral);
    try t.expect(!c.learns);
    try t.expectEqual(@as(u32, 0), c.state_budget_bytes); // no learning ⇒ no on-device state
    try t.expectEqualStrings("Uses no behavioral data — public signals only", behavioralLabel(c));
}

test "classify: each behavioral door independently proves behavioral; only learning weight learns" {
    const t = std.testing;
    const base = blk: {
        var b = discover.DEFAULT_CONFIG;
        b.w_bookmark = 0;
        b.w_profile_click = 0;
        b.w_link_click = 0;
        b.behavioral_weight = 0;
        break :blk b; // a clean candidate-side base
    };

    // A momentary attention signal (a click) → uses behavioral, but does NOT learn.
    var clicks = base;
    clicks.w_profile_click = 12;
    try t.expect(classify(clicks).uses_behavioral);
    try t.expect(!classify(clicks).learns);

    var links = base;
    links.w_link_click = 11;
    try t.expect(classify(links).uses_behavioral);

    var saves = base;
    saves.w_bookmark = 10;
    try t.expect(classify(saves).uses_behavioral);

    // The on-device learner → uses behavioral AND learns, and now keeps state.
    var learner_cfg = base;
    learner_cfg.behavioral_weight = 0.5;
    const lc = classify(learner_cfg);
    try t.expect(lc.uses_behavioral and lc.learns);
    try t.expect(lc.state_budget_bytes > 0);
}

test "classify agrees with explain on the behavioral verdict (no cross-module drift)" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // For any config, classify's verdict must equal "explain flagged a behavioral
    // field with a non-zero value" — the two views can never disagree.
    var private = discover.DEFAULT_CONFIG;
    private.w_bookmark = 0;
    private.w_profile_click = 0;
    private.w_link_click = 0;
    private.behavioral_weight = 0;
    var learns = discover.DEFAULT_CONFIG;
    learns.behavioral_weight = 0.5;

    for ([_]discover.FeedConfig{ discover.DEFAULT_CONFIG, private, learns }) |c| {
        const rows = try explain(arena, c);
        var explain_behavioral = false;
        for (rows) |r| {
            if (r.behavioral and !std.mem.eql(u8, r.value, "0")) explain_behavioral = true;
        }
        try t.expectEqual(classify(c).uses_behavioral, explain_behavioral);
    }
}
