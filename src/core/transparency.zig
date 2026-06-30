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
const rules = @import("rules.zig");
const algo_vm = @import("algo_vm.zig");

// **The behavioral-door wall — the label-honesty guarantee, made structural.**
// `classify` decides a feed's "uses behavioral data" verdict from its WEIGHTS
// alone; it never inspects the Level-2 rule-list. That is only honest if a rule
// CANNOT read attention data in the first place — and it can't, because a
// predicate reads only `rules.Facts`, which carries public, candidate-side facts
// and nothing else. This `comptime` block pins that: every field of `Facts` must
// be on the public allowlist below. Add a behavioral fact (dwell, bookmark, a
// click) to the predicate vocabulary and the build FAILS here, forcing a
// deliberate decision — teach `classify` to account for rules, and update the
// label — instead of a rule-list silently bypassing the "uses no behavioral
// data" claim. Capability denial by construction, not policy.
comptime {
    const public_facts = [_][]const u8{
        "in_network", "like_count", "repost_count", "reply_count", "age_hrs",
    };
    for (@typeInfo(rules.Facts).@"struct".fields) |f| {
        var allowed = false;
        for (public_facts) |name| {
            if (std.mem.eql(u8, f.name, name)) allowed = true;
        }
        if (!allowed) @compileError(
            "transparency: rule fact '" ++ f.name ++ "' is not on the public-fact allowlist. " ++
                "If it reads behavioral/attention data, `classify` must account for the rule-list " ++
                "(and the label must change) BEFORE this fact is exposed to predicates — the " ++
                "behavioral-door wall (label-honesty guarantee).",
        );
    }
    // The SAME wall for the Level-3 expression VM: every value a program can load
    // must be a public fact (or `base_score`, the engine's own output, whose
    // behavioral content is already governed by `behavioral_weight` and so already
    // reflected in `classify`). A new behavioral member on `algo_vm.Fact` would
    // let a program read attention without the label showing it — fail here first.
    for (@typeInfo(algo_vm.Fact).@"enum".fields) |vf| {
        var allowed = std.mem.eql(u8, vf.name, "base_score");
        for (public_facts) |name| {
            if (std.mem.eql(u8, vf.name, name)) allowed = true;
        }
        if (!allowed) @compileError(
            "transparency: VM fact '" ++ vf.name ++ "' is not on the public-fact allowlist " ++
                "(nor `base_score`). A Level-3 program must not be able to read behavioral data " ++
                "the label doesn't disclose — the behavioral-door wall extends to the VM.",
        );
    }
}

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
    /// False for a knob that is DECLARED in the config (and so carried in the
    /// record the CID addresses) but NOT YET enforced by the engine. The page
    /// marks such a row "not yet active" so it can never advertise a guarantee the
    /// scorer isn't delivering — honesty is the whole feature, so a modeled-but-
    /// inert field must say so rather than read as live.
    enforced: bool,
};

/// The human metadata for one field (everything but its runtime value).
/// A7.2: cold — comptime-only descriptors, never held in a collection. Waived.
const Meta = struct {
    label: []const u8,
    meaning: []const u8,
    category: Category,
    behavioral: bool = false,
    /// Default true; set false for a config knob the engine does not enforce yet
    /// (modeled in the record, inert at runtime). See `FieldExplanation.enforced`.
    enforced: bool = true,
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
        .meaning = "Intended to cap how many posts any single sub-topic can take per refresh. Not active yet: enforcement needs the sub-topic index, so this value is carried but does not affect ranking today.",
        .category = .diversity,
        .enforced = false, // applyCaps enforces per-author only; subtopic index is D2
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
        if (comptime std.mem.eql(u8, f.name, "rules") or std.mem.eql(u8, f.name, "vm_program")) {
            // The Level-2 rule-list and the Level-3 VM program are LOGIC, not
            // scalars — each renders as its own readable section (rules as
            // "if … then …" lines, the VM as a decompiled formula), so neither is
            // a per-field scalar row here. Skipped, not forgotten: this branch
            // keeps the comptime completeness guarantee honest.
        } else if (comptime std.mem.eql(u8, f.name, "query")) {
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
                    .enforced = m.enforced,
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
                .enforced = m.enforced,
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

/// Is a scalar field "in use" — a non-zero weight or an enabled toggle? The
/// behavioral fields are all f32 weights; this stays general so the derivation
/// below works for any field type.
fn isActive(v: anytype) bool {
    return switch (@typeInfo(@TypeOf(v))) {
        .float, .int => v != 0,
        .bool => v,
        else => false,
    };
}

/// Derive the classification from the config (pure). `uses_behavioral` is DERIVED
/// by reflection from `metaFor`'s per-field `.behavioral` flags — `metaFor` is the
/// SINGLE source of truth for what reads attention. So a new behavioral signal
/// added to the engine, which the `metaFor` completeness `@compileError` already
/// forces an author to describe, is AUTOMATICALLY reflected in the label: classify
/// cannot drift behind the engine, and a behavioral knob cannot be added while the
/// "uses no behavioral data" verdict silently stays clean. `learns` is the
/// narrower cross-session axis — only the on-device learner weight maintains a
/// model — so it stays keyed to `behavioral_weight`.
pub fn classify(config: discover.FeedConfig) Classification {
    const learns = config.behavioral_weight != 0;
    var uses_behavioral = learns;
    inline for (@typeInfo(discover.FeedConfig).@"struct".fields) |f| {
        if (comptime std.mem.eql(u8, f.name, "rules") or
            std.mem.eql(u8, f.name, "vm_program") or
            std.mem.eql(u8, f.name, "query"))
        {
            // Logic lists and the retrieval sub-record carry no behavioral SCALAR
            // weight: the door wall keeps rule/VM facts public, and Query holds
            // retrieval knobs only. (If a behavioral leaf is ever added to Query,
            // extend this to flatten it — the cross-drift test will catch it.)
        } else if (comptime metaFor(f.name).behavioral) {
            if (isActive(@field(config, f.name))) uses_behavioral = true;
        }
    }
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
// Level-2 rules as readable logic (the "resembles code" view, honestly)
// ---------------------------------------------------------------------------

/// One authored rule, rendered as a plain-English line of logic for the page.
/// `text` is the whole readable sentence ("If the post is from discovery, boost
/// its score 1.5×."); `excludes` flags a removal so the renderer can mark it.
/// A7.2: cold view-model — a handful per page, built once on open. Waived.
pub const RuleLine = struct {
    text: []const u8,
    excludes: bool,
};

/// The condition half of a rule, read straight from the fixed predicate
/// vocabulary — every kind is covered (the `else`-free switch is the completeness
/// guarantee, the same discipline `metaFor` uses for scalars).
fn predicateText(arena: Allocator, p: rules.Predicate) error{OutOfMemory}![]const u8 {
    return switch (p.kind) {
        .always => arena.dupe(u8, "every post"),
        .in_network => arena.dupe(u8, "the post is from someone you follow"),
        .out_of_network => arena.dupe(u8, "the post is from discovery (out-of-network)"),
        .min_likes => std.fmt.allocPrint(arena, "the post has at least {d} likes", .{p.param}),
        .min_reposts => std.fmt.allocPrint(arena, "the post has at least {d} reposts", .{p.param}),
        .min_replies => std.fmt.allocPrint(arena, "the post has at least {d} replies", .{p.param}),
        .min_engagement => std.fmt.allocPrint(arena, "the post has at least {d} total interactions", .{p.param}),
        .newer_than_hrs => std.fmt.allocPrint(arena, "the post is newer than {d} hours", .{p.param}),
        .older_than_hrs => std.fmt.allocPrint(arena, "the post is older than {d} hours", .{p.param}),
    };
}

/// The effect half of a rule. `boost`/`dampen` are the same multiply, named for
/// the authored intent; `exclude` drops the candidate.
fn actionText(arena: Allocator, a: rules.Action) error{OutOfMemory}![]const u8 {
    return switch (a.kind) {
        .boost => std.fmt.allocPrint(arena, "boost its score {d}×", .{a.factor}),
        .dampen => std.fmt.allocPrint(arena, "dampen its score to {d}×", .{a.factor}),
        .exclude => arena.dupe(u8, "remove it from the feed"),
    };
}

/// Render a rule-list as ordered readable logic (PURE), in `arena`. Authoring
/// order is meaningful (later rules see earlier effects), so the lines are in the
/// same order the scorer runs them — what you read is the order that runs.
pub fn ruleLines(arena: Allocator, rs: []const rules.Rule) error{OutOfMemory}![]RuleLine {
    var list: std.ArrayListUnmanaged(RuleLine) = .empty;
    for (rs) |r| {
        const cond = try predicateText(arena, r.predicate);
        const eff = try actionText(arena, r.action);
        // "For every post, …" reads better than "If every post, …".
        const sentence = if (r.predicate.kind == .always)
            try std.fmt.allocPrint(arena, "For {s}, {s}.", .{ cond, eff })
        else
            try std.fmt.allocPrint(arena, "If {s}, {s}.", .{ cond, eff });
        try list.append(arena, .{ .text = sentence, .excludes = r.action.kind == .exclude });
    }
    return list.toOwnedSlice(arena);
}

// ---------------------------------------------------------------------------
// Level-3 VM program as a readable formula (decompiled, honestly)
// ---------------------------------------------------------------------------

/// The human name of a VM input fact.
fn vmFactName(f: algo_vm.Fact) []const u8 {
    return switch (f) {
        .base_score => "base score",
        .in_network => "in-network",
        .like_count => "likes",
        .repost_count => "reposts",
        .reply_count => "replies",
        .age_hrs => "age (hrs)",
    };
}

/// Decompile a VM program into one readable infix formula (PURE), in `arena`, or
/// null if the program is empty or not well-formed — only a valid program is a
/// meaningful formula to show (`algo_vm.run` stays safe on the rest, but the page
/// renders nothing rather than a half-expression). The decompiler is the VM's own
/// straight-line evaluation done over STRING fragments instead of numbers, so the
/// rendered formula is exactly the computation that runs (transparency, not a
/// paraphrase). `validProgram` guarantees the stack indices below are in bounds.
pub fn formulaText(arena: Allocator, program: []const algo_vm.Instr) error{OutOfMemory}!?[]const u8 {
    // This is a SECOND interpreter of untrusted bytecode (the VM is the first),
    // reachable from any fetched algorithm's transparency page. So it is written
    // to be TOTAL on its own — every stack access is guarded and an imbalance
    // returns null — rather than trusting `algo_vm.run`'s validator. The two stay
    // in agreement by an explicit cross-check fuzz test: `validProgram(p)` iff
    // `formulaText(p) != null`. Safety is forced on as a final backstop against a
    // bug in these very guards, so a slip is a controlled panic and never silent
    // memory corruption, regardless of the build's optimization mode.
    @setRuntimeSafety(true);
    // Empty or over-cap programs are not meaningful formulas (and the latter is
    // also the DoS bound), matching `algo_vm.validProgram` exactly — a cross-check
    // fuzz test asserts the two agree on validity.
    if (program.len == 0 or program.len > algo_vm.max_program_len) return null;
    const cap = algo_vm.stack_cap;
    var stack: [cap][]const u8 = undefined;
    var sp: usize = 0;
    // EXHAUSTIVE — no `else`. A new opcode must be given a rendering here.
    for (program) |ins| {
        switch (ins.op) {
            .push_const => {
                if (sp >= cap) return null;
                stack[sp] = try std.fmt.allocPrint(arena, "{d}", .{ins.value});
                sp += 1;
            },
            .push_fact => {
                if (sp >= cap) return null;
                stack[sp] = vmFactName(ins.fact);
                sp += 1;
            },
            .neg => {
                if (sp < 1) return null;
                stack[sp - 1] = try std.fmt.allocPrint(arena, "(−{s})", .{stack[sp - 1]});
            },
            .abs => {
                if (sp < 1) return null;
                stack[sp - 1] = try std.fmt.allocPrint(arena, "|{s}|", .{stack[sp - 1]});
            },
            .add => {
                if (sp < 2) return null;
                const r = try std.fmt.allocPrint(arena, "({s} + {s})", .{ stack[sp - 2], stack[sp - 1] });
                sp -= 1;
                stack[sp - 1] = r;
            },
            .sub => {
                if (sp < 2) return null;
                const r = try std.fmt.allocPrint(arena, "({s} − {s})", .{ stack[sp - 2], stack[sp - 1] });
                sp -= 1;
                stack[sp - 1] = r;
            },
            .mul => {
                if (sp < 2) return null;
                const r = try std.fmt.allocPrint(arena, "({s} × {s})", .{ stack[sp - 2], stack[sp - 1] });
                sp -= 1;
                stack[sp - 1] = r;
            },
            .div => {
                if (sp < 2) return null;
                const r = try std.fmt.allocPrint(arena, "({s} ÷ {s})", .{ stack[sp - 2], stack[sp - 1] });
                sp -= 1;
                stack[sp - 1] = r;
            },
            .min => {
                if (sp < 2) return null;
                const r = try std.fmt.allocPrint(arena, "min({s}, {s})", .{ stack[sp - 2], stack[sp - 1] });
                sp -= 1;
                stack[sp - 1] = r;
            },
            .max => {
                if (sp < 2) return null;
                const r = try std.fmt.allocPrint(arena, "max({s}, {s})", .{ stack[sp - 2], stack[sp - 1] });
                sp -= 1;
                stack[sp - 1] = r;
            },
            .gt => {
                if (sp < 2) return null;
                const r = try std.fmt.allocPrint(arena, "({s} > {s})", .{ stack[sp - 2], stack[sp - 1] });
                sp -= 1;
                stack[sp - 1] = r;
            },
            .lt => {
                if (sp < 2) return null;
                const r = try std.fmt.allocPrint(arena, "({s} < {s})", .{ stack[sp - 2], stack[sp - 1] });
                sp -= 1;
                stack[sp - 1] = r;
            },
            .select => {
                if (sp < 3) return null;
                const r = try std.fmt.allocPrint(arena, "(if {s} then {s} else {s})", .{ stack[sp - 3], stack[sp - 2], stack[sp - 1] });
                sp -= 2;
                stack[sp - 1] = r;
            },
        }
    }
    if (sp != 1) return null; // a well-formed formula leaves exactly one expression
    return stack[sp - 1];
}

// ---------------------------------------------------------------------------
// The page model — what the transparency SCREEN renders (D5 / invariant 5)
// ---------------------------------------------------------------------------

/// Everything a transparency page shows about one algorithm, assembled from the
/// foundations: the title + its CID/ref (the artifact identity), the two
/// system-PROVEN classification labels, and the full per-field explanation. The
/// renderer (feed_view.layoutTransparency) draws this; the raw byte-exact "file"
/// it pairs with comes from `algorithm.serialize`. PLAIN DATA (A1).
/// A7.2: cold view-model — one per transparency-page open. Size guard waived.
pub const Page = struct {
    name: []const u8,
    /// The CID (or, for a built-in, its stable id) — the thing the page proves
    /// "is what runs" (invariant 5).
    ref: []const u8,
    behavioral_label: []const u8,
    stateful_label: []const u8,
    uses_behavioral: bool,
    learns: bool,
    rows: []const FieldExplanation,
    /// The creator's authored Level-2 logic, rendered as readable lines in run
    /// order. Empty for a flat-weights (Level-1) algorithm.
    rule_lines: []const RuleLine,
    /// The creator's authored Level-3 scoring formula, decompiled to one readable
    /// expression — or null when the algorithm carries no (valid) VM program.
    formula: ?[]const u8,
};

/// Assemble the transparency page for one algorithm (PURE): the classification
/// verdict + every explained field, in `arena`. The caller supplies the human
/// `name` and the `ref` (CID/id) it resolved the config from.
pub fn buildPage(arena: Allocator, name: []const u8, ref: []const u8, config: discover.FeedConfig) error{OutOfMemory}!Page {
    // Render the VALIDATED config — the exact form the engine runs (clamped
    // weights, capped/clipped rule-list, malformed VM program dropped to a
    // no-op). This makes "what you see is what runs" STRUCTURAL: the page cannot
    // display an un-clamped weight or a rejected program the scorer would never
    // execute, regardless of whether the caller validated first. The published
    // bytes a CID addresses are likewise `serialize(validated(config))`, so the
    // page and the hash agree by construction (invariant 5).
    const cfg = discover.validated(config);
    const c = classify(cfg);
    return .{
        .name = name,
        .ref = ref,
        .behavioral_label = behavioralLabel(c),
        .stateful_label = statefulLabel(c),
        .uses_behavioral = c.uses_behavioral,
        .learns = c.learns,
        .rows = try explain(arena, cfg),
        .rule_lines = try ruleLines(arena, cfg.rules),
        .formula = try formulaText(arena, cfg.vm_program),
    };
}

// ---------------------------------------------------------------------------
// Tests — pure, leak-checked (C6)
// ---------------------------------------------------------------------------

/// The leaf-field count, computed by reflection so the test can't go stale: all
/// of FeedConfig's fields, minus the nested `query`, plus Query's own fields.
fn leafFieldCount() usize {
    var n: usize = 0;
    inline for (@typeInfo(discover.FeedConfig).@"struct".fields) |f| {
        if (comptime std.mem.eql(u8, f.name, "rules") or std.mem.eql(u8, f.name, "vm_program")) {
            // not scalar leaves — rendered as their own logic sections (matches explain)
        } else if (comptime std.mem.eql(u8, f.name, "query")) {
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

test "explain: a declared-but-unenforced knob is flagged, never advertised as live" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // The transparency page must never present a guarantee the engine isn't
    // delivering. `max_per_subtopic` is modeled but not yet enforced (applyCaps
    // does per-author only), so it must come back flagged; everything else is live.
    const rows = try explain(arena, discover.DEFAULT_CONFIG);
    var found_subtopic = false;
    for (rows) |r| {
        if (std.mem.eql(u8, r.field, "max_per_subtopic")) {
            found_subtopic = true;
            try t.expect(!r.enforced); // honestly marked "not yet active"
        } else {
            try t.expect(r.enforced); // every other knob is actually enforced
        }
    }
    try t.expect(found_subtopic);
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

test "buildPage: assembles the verdict + every field for the renderer" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var private = discover.DEFAULT_CONFIG;
    private.w_bookmark = 0;
    private.w_profile_click = 0;
    private.w_link_click = 0;
    private.behavioral_weight = 0;

    const page = try buildPage(arena, "Zat4 Private Discover", "zat4:private-discover", private);
    try t.expectEqualStrings("Zat4 Private Discover", page.name);
    try t.expectEqualStrings("zat4:private-discover", page.ref);
    try t.expect(!page.uses_behavioral); // proven clean
    try t.expectEqual(leafFieldCount(), page.rows.len); // every line present
    try t.expectEqual(@as(usize, 0), page.rule_lines.len); // a flat-weights config has no logic lines
}

test "ruleLines: renders authored logic as ordered, readable sentences" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const rs = [_]rules.Rule{
        .{ .predicate = .{ .kind = .out_of_network }, .action = .{ .kind = .boost, .factor = 1.5 } },
        .{ .predicate = .{ .kind = .min_engagement, .param = 50 }, .action = .{ .kind = .exclude } },
    };
    const lines = try ruleLines(arena, &rs);
    try t.expectEqual(@as(usize, 2), lines.len);
    // Order preserved (run order == read order).
    try t.expectEqualStrings("If the post is from discovery (out-of-network), boost its score 1.5×.", lines[0].text);
    try t.expect(!lines[0].excludes);
    try t.expectEqualStrings("If the post has at least 50 total interactions, remove it from the feed.", lines[1].text);
    try t.expect(lines[1].excludes); // a removal is flagged for the renderer

    // The `always` predicate reads as "For every post, …".
    const uncond = [_]rules.Rule{.{ .predicate = .{ .kind = .always }, .action = .{ .kind = .dampen, .factor = 0.5 } }};
    const one = try ruleLines(arena, &uncond);
    try t.expectEqualStrings("For every post, dampen its score to 0.5×.", one[0].text);

    // An empty rule-list is an empty slice, not an error (E4).
    const none = try ruleLines(arena, &.{});
    try t.expectEqual(@as(usize, 0), none.len);
}

test "formulaText: decompiles a VM program to a readable infix expression" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // (base score × 1.5) + reposts
    const program = [_]algo_vm.Instr{
        .{ .op = .push_fact, .fact = .base_score },
        .{ .op = .push_const, .value = 1.5 },
        .{ .op = .mul },
        .{ .op = .push_fact, .fact = .repost_count },
        .{ .op = .add },
    };
    const f = (try formulaText(arena, &program)).?;
    try t.expectEqualStrings("((base score × 1.5) + reposts)", f);

    // An empty program has no formula to show.
    try t.expectEqual(@as(?[]const u8, null), try formulaText(arena, &.{}));

    // A malformed program (underflow) renders nothing rather than a fragment.
    const bad = [_]algo_vm.Instr{.{ .op = .add }};
    try t.expectEqual(@as(?[]const u8, null), try formulaText(arena, &bad));
}

test "fuzz: the decompiler is total and agrees with the VM validator" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var prng = std.Random.DefaultPrng.init(0xDEC0_FFEE);
    const rnd = prng.random();
    const ops = std.enums.values(algo_vm.Op);
    const facts = std.enums.values(algo_vm.Fact);

    var buf: [2 * algo_vm.max_program_len]algo_vm.Instr = undefined; // over-cap lengths too
    var iter: usize = 0;
    while (iter < 40_000) : (iter += 1) {
        const len = rnd.uintAtMost(usize, buf.len);
        for (buf[0..len]) |*ins| ins.* = .{
            .op = ops[rnd.uintLessThan(usize, ops.len)],
            .fact = facts[rnd.uintLessThan(usize, facts.len)],
            .value = @bitCast(rnd.int(u32)),
        };
        const prog = buf[0..len];
        // The decompiler must never crash, and must render a formula EXACTLY when
        // the VM considers the program valid — the two interpreters cannot drift.
        const rendered = (try formulaText(arena, prog)) != null;
        try t.expectEqual(algo_vm.validProgram(prog), rendered);
        // Reset the arena periodically so 40k iterations don't balloon memory.
        if (iter % 256 == 0) _ = arena_state.reset(.retain_capacity);
    }
}
