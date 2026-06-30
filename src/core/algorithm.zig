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

//! B1 classification: CORE (pure). **The algorithm RECORD — Phase D5.** The
//! serialization seam that turns a `discover.FeedConfig` (the engine's plain
//! config) into a portable, human-readable, shareable artifact and back.
//!
//! This is what makes "an algorithm is a config record" real (DISCOVER D5,
//! invariant 5): a config serializes to a self-describing JSON document a
//! developer can read, hand-edit, and share; parsing it back is
//! validation-gated, so a malformed or hostile shared config is just BAD DATA
//! that falls back to the default — never a crash (E2/E4). The published form
//! becomes an atproto record in the user's repo (collection
//! `lexicon.collection.algorithm`); the bytes serialized here ARE what a CID
//! addresses, so what a user inspects is byte-identical to what runs
//! (transparency = the hash, not a promised link — invariant 5). The byte-exact
//! round-trip is the testable core of that guarantee.
//!
//! D3 boundary: the PUBLIC interface is `bytes <-> FeedConfig` only — the JSON
//! record shape is a private detail of this module, so no wire type leaks into
//! anyone's signature. The transport (the XRPC write to publish, the fetch-by-
//! CID to import) is the thin SHELL leg, built when the marketplace UI needs it
//! (F4); it reuses the same authed put/getRecord path the loadout record uses.

const std = @import("std");
const Allocator = std.mem.Allocator;
const discover = @import("discover.zig");
const rules = @import("rules.zig");
const algo_vm = @import("algo_vm.zig");
const jsonguard = @import("jsonguard.zig");

/// Schema version of the serialized form. Bumped only on an incompatible
/// change; readers ignore unknown fields and default missing ones, so most
/// evolution needs no bump (forward- and backward-compatible by construction).
const schema_version: u32 = 1;

/// The on-the-wire document: a version envelope around the algorithm's config.
/// PRIVATE — callers see only bytes and `FeedConfig` (D3). Every field of
/// `FeedConfig` already defaults, so a record missing fields parses (older
/// writer → newer reader) and a record with extra fields parses (newer writer →
/// older reader, `ignore_unknown_fields`).
/// A7.2: cold struct, size guard waived — one transient per serialize/parse,
/// never held in a collection or a hot loop.
const Record = struct {
    version: u32 = schema_version,
    config: discover.FeedConfig = .{},
};

/// Serialize a config to its canonical, human-readable JSON form in `arena`.
/// The config is `validated` first, so the published bytes are always a sane
/// algorithm — you cannot publish a NaN. Indented because human-readability is
/// the priority (a developer hand-edits this); compactness does not matter (the
/// record is tiny and loaded once).
pub fn serialize(arena: Allocator, config: discover.FeedConfig) error{OutOfMemory}![]u8 {
    const rec = Record{ .config = discover.validated(config) };
    return std.json.Stringify.valueAlloc(arena, rec, .{ .whitespace = .indent_2 });
}

/// Parse a config from its serialized form. A malformed, hostile, or depth-bomb
/// document is ordinary bad data → the DEFAULT config (E2/E4), never an error
/// the caller must handle and never a crash; only genuine OOM propagates (the
/// C-discipline: allocation failure is never masked). The parsed config is
/// `validated`, so even a well-formed-but-abusive record (absurd weights) runs
/// safely. `arena` must be an arena — the parse is leaky.
pub fn parse(arena: Allocator, bytes: []const u8) error{OutOfMemory}!discover.FeedConfig {
    // Bound nesting before std.json recurses (Phase 2 discipline — a depth bomb
    // is a clean rejection, not a stack-overflow). A shared algorithm is
    // untrusted input on exactly the footing the timeline read path is.
    if (!jsonguard.depthWithinLimit(bytes, jsonguard.max_json_depth)) return discover.DEFAULT_CONFIG;
    const rec = std.json.parseFromSliceLeaky(Record, arena, bytes, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return discover.DEFAULT_CONFIG,
    };
    return discover.validated(rec.config);
}

// ---------------------------------------------------------------------------
// Tests — leak-checked (C6), pure
// ---------------------------------------------------------------------------

test "serialize → parse round-trips a config byte-for-byte (transparency core)" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A non-default config (the "Calm"-shaped one) survives the round trip.
    var cfg = discover.DEFAULT_CONFIG;
    cfg.velocity_boost = false;
    cfg.recency_half_life_hrs = 24.0;
    cfg.w_reply = 5.0;
    cfg.max_per_author = 2;
    cfg.query.source_mix = 0.25;

    const bytes = try serialize(arena, cfg);
    const back = try parse(arena, bytes);
    try t.expectEqual(cfg.velocity_boost, back.velocity_boost);
    try t.expectEqual(cfg.recency_half_life_hrs, back.recency_half_life_hrs);
    try t.expectEqual(cfg.w_reply, back.w_reply);
    try t.expectEqual(cfg.max_per_author, back.max_per_author);
    try t.expectEqual(cfg.query.source_mix, back.query.source_mix);

    // What you inspect IS what runs: serializing the parsed config reproduces
    // the same bytes (the CID-transparency property, locally checkable).
    const bytes2 = try serialize(arena, back);
    try t.expectEqualSlices(u8, bytes, bytes2);
}

test "parse: malformed / hostile / empty input falls back to the default (E2/E4)" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const garbage = try parse(arena, "this is not json {{{");
    try t.expectEqual(discover.DEFAULT_CONFIG.w_repost, garbage.w_repost);

    const empty = try parse(arena, "");
    try t.expectEqual(discover.DEFAULT_CONFIG.w_like, empty.w_like);

    // A depth bomb is rejected to the default, not a stack overflow.
    const bomb = "{\"config\":" ** 200 ++ "{}" ++ ("}" ** 200);
    const bombed = try parse(arena, bomb);
    try t.expectEqual(discover.DEFAULT_CONFIG.w_like, bombed.w_like);
}

test "parse: a well-formed but abusive record is sanitized, not trusted" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A hand-crafted record with an absurd weight and an over-budget state
    // declaration — well-formed JSON, but the engine must clamp it on load.
    const hostile =
        \\{ "version": 1, "config": { "w_like": 1e30, "state_budget_bytes": 1073741824 } }
    ;
    const cfg = try parse(arena, hostile);
    try t.expect(std.math.isFinite(cfg.w_like));
    try t.expect(cfg.w_like <= 100_000);
    try t.expect(cfg.state_budget_bytes <= discover.state_budget_hard_cap);
    // Fields the record omitted came back as the safe defaults.
    try t.expectEqual(discover.DEFAULT_CONFIG.w_repost, cfg.w_repost);
}

test "serialize/parse: a config's LEVEL-2 rules travel with the record" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // An algorithm with authored logic: boost strong discovery posts, drop noise.
    const rule_list = [_]rules.Rule{
        .{ .predicate = .{ .kind = .out_of_network }, .action = .{ .kind = .boost, .factor = 1.5 } },
        .{ .predicate = .{ .kind = .min_engagement, .param = 5 }, .action = .{ .kind = .exclude } },
    };
    var cfg = discover.DEFAULT_CONFIG;
    cfg.rules = &rule_list;

    const bytes = try serialize(arena, cfg);
    const back = try parse(arena, bytes);
    try t.expectEqual(@as(usize, 2), back.rules.len);
    try t.expectEqual(rules.PredicateKind.out_of_network, back.rules[0].predicate.kind);
    try t.expectEqual(@as(f32, 1.5), back.rules[0].action.factor);
    try t.expectEqual(rules.ActionKind.exclude, back.rules[1].action.kind);
    try t.expectEqual(@as(f32, 5), back.rules[1].predicate.param);
}

test "serialize/parse: a config's LEVEL-3 VM program travels with the record" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // An authored scoring formula: base_score * 1.5 + reposts.
    const program = [_]algo_vm.Instr{
        .{ .op = .push_fact, .fact = .base_score },
        .{ .op = .push_const, .value = 1.5 },
        .{ .op = .mul },
        .{ .op = .push_fact, .fact = .repost_count },
        .{ .op = .add },
    };
    var cfg = discover.DEFAULT_CONFIG;
    cfg.vm_program = &program;

    const bytes = try serialize(arena, cfg);
    const back = try parse(arena, bytes);
    try t.expectEqual(@as(usize, 5), back.vm_program.len);
    try t.expectEqual(algo_vm.Op.push_fact, back.vm_program[0].op);
    try t.expectEqual(algo_vm.Fact.base_score, back.vm_program[0].fact);
    try t.expectEqual(@as(f32, 1.5), back.vm_program[1].value);
    try t.expectEqual(algo_vm.Op.add, back.vm_program[4].op);

    // Byte-exact re-serialization (the CID-transparency property holds with a
    // program present, too).
    const bytes2 = try serialize(arena, back);
    try t.expectEqualSlices(u8, bytes, bytes2);
}

test "parse: a malformed VM program is rejected to a safe no-op on load" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A well-formed JSON record whose program underflows the stack (an `add`
    // with no operands) — valid to parse, but not a valid formula. `validated`
    // (run inside parse) must drop it to empty, so nothing untrusted runs.
    const hostile =
        \\{ "version": 1, "config": { "vm_program": [ { "op": "add", "fact": "base_score", "value": 0 } ] } }
    ;
    const cfg = try parse(arena, hostile);
    try t.expectEqual(@as(usize, 0), cfg.vm_program.len); // rejected to no-op
}

test "fuzz: parse tolerates arbitrary input and always yields a validated config" {
    const fuzzgen = @import("fuzzgen.zig");
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var g = fuzzgen.Gen.init(0xA1607A5E);
    var buf: [512]u8 = undefined;
    // Valid seeds (mutated by the generator to reach deep, post-parse paths) plus
    // pure-random and charset-random input.
    const seeds = [_][]const u8{
        \\{ "version": 1, "config": { "w_like": 2.0, "rules": [ { "predicate": { "kind": "always" }, "action": { "kind": "boost", "factor": 2 } } ] } }
        ,
        \\{ "config": { "vm_program": [ { "op": "push_fact", "fact": "like_count" }, { "op": "push_const", "value": 2 }, { "op": "mul" } ] } }
        ,
    };
    const charset = "{}[]\":,.- 0123456789truefalsenulopfactvaluekindrulesconfigvm_program";

    var i: usize = 0;
    while (i < 6000) : (i += 1) {
        const input = g.next(&buf, &seeds, charset, i);
        // No crash on ANY input; only OOM may propagate. Whatever parses is a sane,
        // VALIDATED config — every untrusted bound holds (the load-path guarantee).
        const cfg = parse(arena, input) catch continue;
        try t.expect(std.math.isFinite(cfg.w_like));
        try t.expect(std.math.isFinite(cfg.behavioral_weight));
        try t.expect(cfg.rules.len <= discover.max_rules);
        try t.expect(cfg.vm_program.len <= algo_vm.max_program_len);
        try t.expect(cfg.query.max_candidates <= discover.max_candidates_hard_cap);
        try t.expect(cfg.state_budget_bytes <= discover.state_budget_hard_cap);
        if (i % 128 == 0) _ = arena_state.reset(.retain_capacity);
    }
}

test "parse: forward-compatible — unknown fields are ignored (E4)" {
    const t = std.testing;
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A record from a FUTURE schema with a field this build doesn't know.
    const future =
        \\{ "version": 2, "config": { "w_like": 2.0, "some_future_knob": 99 } }
    ;
    const cfg = try parse(arena, future);
    try t.expectEqual(@as(f32, 2.0), cfg.w_like); // known field honored
}
