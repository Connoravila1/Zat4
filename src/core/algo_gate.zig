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

//! B1 classification: CORE (pure). **GUEST TIER — Phase 5: the publish gate.**
//! See `GUEST_TIER_ROADMAP.md` §Phase 5.
//!
//! The strict, fail-closed gate an algorithm passes BEFORE it is published.
//! The run path is deliberately forgiving — `discover.validated` repairs a
//! hostile or malformed config into something safe (clamp, clip, empty) so a
//! fetched record can never hurt the reader. Publishing is the opposite
//! posture: a config that would be REPAIRED at load is a config that would
//! run differently than authored, and shipping it means the CID commits to
//! bytes the engine won't honor. So the gate REFUSES, by name, everything
//! the load path would quietly fix, plus the checks only publish time can
//! afford: running the guest programs over a battery of edge-case candidates
//! to prove they finish inside their own declared fuel budget.
//!
//! One rule, three enforcers (the eBPF-verifier posture): the entry/
//! capability wall is `guest_abi.entryPermits`, applied by the compiler at
//! author time, HERE by name at publish time, and by `discover.validated`
//! as the load-time backstop for bytecode no compiler saw.
//!
//! Pure and allocation-free: refusals land in a bounded array (at most one
//! of each kind), so the gate itself can never be a resource problem.

const std = @import("std");
const discover = @import("discover.zig");
const rules = @import("rules.zig");
const algo_vm = @import("algo_vm.zig");
const guest_vm = @import("guest_vm.zig");
const guest_abi = @import("guest_abi.zig");

/// Every reason the gate can refuse a config, each a single honest sentence
/// via `label`. Exhaustive by construction: `gate` can emit at most one of
/// each, and the Verdict array is sized from this enum.
pub const Refusal = enum(u8) {
    guest_score_malformed,
    guest_retrieve_malformed,
    vm_program_malformed,
    entry_wall_score,
    entry_wall_retrieve,
    fuel_over_ceiling,
    state_budget_over_ceiling,
    strings_over_cap,
    string_too_long,
    rules_over_cap,
    sources_over_cap,
    candidates_over_cap,
    battery_score_exhausted,
    battery_retrieve_exhausted,
    guest_arrange_malformed,
    entry_wall_arrange,
    battery_arrange_exhausted,
    not_load_stable,
};

/// The human sentence for a refusal — what the author sees. Exhaustive (no
/// `else`): a new refusal cannot ship without its explanation.
pub fn label(r: Refusal) []const u8 {
    return switch (r) {
        .guest_score_malformed => "the score() bytecode is malformed (bad jump target or capability id, or over the length cap)",
        .guest_retrieve_malformed => "the retrieve() bytecode is malformed (bad jump target or capability id, or over the length cap)",
        .vm_program_malformed => "the formula program is malformed or over its length cap",
        .entry_wall_score => "score() calls a retrieval-source capability — sources belong to retrieve()",
        .entry_wall_retrieve => "retrieve() calls a candidate/state/attention capability — those belong to score()/learn()",
        .fuel_over_ceiling => "the declared fuel budget is over the engine ceiling",
        .state_budget_over_ceiling => "the declared on-device state budget is over the hard cap",
        .strings_over_cap => "the tag-constant pool has more entries than the cap",
        .string_too_long => "a tag constant is longer than the cap",
        .rules_over_cap => "the rule list is longer than the cap",
        .sources_over_cap => "the retrieval source list is longer than the cap",
        .candidates_over_cap => "max_candidates is over the hard cap",
        .battery_score_exhausted => "score() ran out of its own declared fuel on a test candidate — it cannot finish inside its budget",
        .battery_retrieve_exhausted => "retrieve() ran out of its own declared fuel — it cannot finish inside its budget",
        .guest_arrange_malformed => "the arrange() bytecode is malformed (bad jump target or capability id, or over the length cap)",
        .entry_wall_arrange => "arrange() calls a capability outside the pool/state set — sources and per-candidate reads don't belong there",
        .battery_arrange_exhausted => "arrange() ran out of its own declared fuel over a full-size pool — it cannot finish inside its budget",
        .not_load_stable => "a value the engine would repair or clip at load — what you publish must be exactly what runs",
    };
}

const refusal_count = @typeInfo(Refusal).@"enum".fields.len;

/// The gate's answer: pass, or every reason it refused. Bounded — at most
/// one of each refusal kind — so the gate allocates nothing.
/// A7.2: cold struct, size guard waived — one per publish attempt.
pub const Verdict = struct {
    refusals: [refusal_count]Refusal = undefined,
    count: u8 = 0,

    pub fn pass(v: *const Verdict) bool {
        return v.count == 0;
    }
    pub fn list(v: *const Verdict) []const Refusal {
        return v.refusals[0..v.count];
    }
    pub fn has(v: *const Verdict, r: Refusal) bool {
        for (v.list()) |x| if (x == r) return true;
        return false;
    }
    fn add(v: *Verdict, r: Refusal) void {
        if (v.has(r)) return;
        v.refusals[v.count] = r;
        v.count += 1;
    }
};

/// The battery's edge-case candidates: the calm case, the empty case, the
/// saturated case, and a hostile-floats case (our marshaling never produces
/// non-finite floats, but the gate assumes nothing about who built the view).
/// A guest must finish inside its declared fuel on EVERY one of these — a
/// loop bounded by a count that saturates, or one that spins on a weird
/// float, is exactly what this catches before a reader ever runs it.
const battery = [_]guest_abi.CandidateView{
    // typical
    .{ .like_count = 12, .repost_count = 3, .reply_count = 5, .reply_chain = 1, .tag_count = 2, .quote_count = 1, .age_hrs = 6.5, .author_rep = 0.5, .in_network = true, .viewer_engaged = false },
    // everything zero / brand new
    .{ .like_count = 0, .repost_count = 0, .reply_count = 0, .age_hrs = 0, .author_rep = 0, .in_network = false },
    // saturated counts, ancient post
    .{ .like_count = std.math.maxInt(u32), .repost_count = std.math.maxInt(u32), .reply_count = std.math.maxInt(u32), .reply_chain = std.math.maxInt(u32), .tag_count = std.math.maxInt(u32), .quote_count = std.math.maxInt(u32), .age_hrs = 1e9, .author_rep = 1.0, .in_network = true, .viewer_engaged = true },
    // hostile floats
    .{ .like_count = 1, .repost_count = 1, .reply_count = 1, .age_hrs = std.math.nan(f32), .author_rep = -std.math.inf(f32), .in_network = false },
};

/// The battery's deterministic mock host: every capability answers with a
/// small, capability-derived number (plus a whiff of its first argument), so
/// host-calling paths execute rather than short-circuit on 0. No I/O — the
/// gate stays pure (B2).
fn batteryHostCall(_: *anyopaque, cap: guest_abi.Capability, arg0: f64, _: f64) f64 {
    const id: f64 = @floatFromInt(@intFromEnum(cap));
    return (id + 1.0) * 0.125 + (if (std.math.isFinite(arg0)) arg0 else 0) * 0.001;
}

var battery_host_ctx: u8 = 0; // the mock needs an address, not state
const battery_host: guest_vm.Host = .{ .ctx = @ptrCast(&battery_host_ctx), .call = batteryHostCall };

/// The arrange() battery's mock host: `pool_len` answers a FULL visible pool
/// (`pool_size_cap`) — the worst case an arrange will ever face — so a program
/// whose loops scale with the pool is metered against the real ceiling, not a
/// toy. Reads answer varied finite values; emits acknowledge. Pure (B2).
fn arrangeBatteryHostCall(_: *anyopaque, cap: guest_abi.Capability, arg0: f64, arg1: f64) f64 {
    return switch (cap) {
        .pool_len => @floatFromInt(guest_abi.pool_size_cap),
        .pool_read => (if (std.math.isFinite(arg0)) arg0 else 0) * 0.5 + (if (std.math.isFinite(arg1)) arg1 else 0),
        .arrange_emit => 1,
        else => batteryHostCall(@ptrCast(&battery_host_ctx), cap, arg0, arg1),
    };
}

var arrange_battery_ctx: u8 = 0;
const arrange_battery_host: guest_vm.Host = .{ .ctx = @ptrCast(&arrange_battery_ctx), .call = arrangeBatteryHostCall };

/// Compare a config against its load-repaired self, field by field at
/// comptime — slices by identity (validated only ever borrows: a clip or an
/// empty changes ptr/len), scalars by value. A NaN scalar compares unequal
/// to itself, which is the right verdict: garbage in a published record is
/// a refusal even where the load path would tolerate it.
fn sameLoaded(comptime T: type, a: T, b: T) bool {
    return switch (@typeInfo(T)) {
        .@"struct" => |s| inline for (s.fields) |f| {
            if (!sameLoaded(f.type, @field(a, f.name), @field(b, f.name))) break false;
        } else true,
        .pointer => a.ptr == b.ptr and a.len == b.len,
        else => a == b,
    };
}

/// The gate. Pure, allocation-free, total. Every refusal it can emit is a
/// sentence via `label`; an empty verdict means `discover.validated` is a
/// NO-OP on this config — what the CID commits to is exactly what runs.
pub fn gate(c: discover.FeedConfig) Verdict {
    var v: Verdict = .{};

    // -- Structural: programs must be well-formed as authored, not repaired.
    if (c.guest_program.len > 0 and !guest_vm.validProgram(c.guest_program)) v.add(.guest_score_malformed);
    if (c.guest_retrieve.len > 0 and !guest_vm.validProgram(c.guest_retrieve)) v.add(.guest_retrieve_malformed);
    if (c.guest_arrange.len > 0 and !guest_vm.validProgram(c.guest_arrange)) v.add(.guest_arrange_malformed);
    if (c.vm_program.len > 0 and !algo_vm.validProgram(c.vm_program)) v.add(.vm_program_malformed);

    // -- The entry/capability wall, on the bytecode (guest_abi.entryPermits).
    if (guest_vm.entryViolation(c.guest_program, .score) != null) v.add(.entry_wall_score);
    if (guest_vm.entryViolation(c.guest_retrieve, .retrieve) != null) v.add(.entry_wall_retrieve);
    if (guest_vm.entryViolation(c.guest_arrange, .arrange) != null) v.add(.entry_wall_arrange);

    // -- Budgets: declared, not clamped. A budget past the ceiling would be
    //    silently cut at load — here it is a named refusal.
    if (c.guest_fuel > guest_vm.max_fuel) v.add(.fuel_over_ceiling);
    if (c.state_budget_bytes > discover.state_budget_hard_cap) v.add(.state_budget_over_ceiling);
    if (c.guest_strings.len > guest_vm.max_strings) v.add(.strings_over_cap);
    for (c.guest_strings) |s| {
        if (s.len > guest_vm.max_tag_len) v.add(.string_too_long);
    }
    if (c.rules.len > discover.max_rules) v.add(.rules_over_cap);
    if (c.query.sources.len > discover.max_sources) v.add(.sources_over_cap);
    if (c.query.max_candidates > discover.max_candidates_hard_cap) v.add(.candidates_over_cap);

    // -- The battery: a structurally-clean guest must FINISH, inside its own
    //    declared fuel, on every edge-case candidate. Run only what passed
    //    the checks above (a malformed program is already refused).
    const fuel = if (c.guest_fuel == 0) guest_vm.default_fuel else c.guest_fuel;
    if (c.guest_program.len > 0 and !v.has(.guest_score_malformed) and !v.has(.entry_wall_score) and !v.has(.fuel_over_ceiling)) {
        for (battery) |view| {
            if (guest_vm.runMetered(c.guest_program, view, 1.0, fuel, &battery_host).fuel_exhausted) {
                v.add(.battery_score_exhausted);
                break;
            }
        }
    }
    if (c.guest_retrieve.len > 0 and !v.has(.guest_retrieve_malformed) and !v.has(.entry_wall_retrieve) and !v.has(.fuel_over_ceiling)) {
        // retrieve() runs once per refresh with no candidate — a zeroed view.
        if (guest_vm.runMetered(c.guest_retrieve, battery[1], 0.0, fuel, &battery_host).fuel_exhausted) {
            v.add(.battery_retrieve_exhausted);
        }
    }
    if (c.guest_arrange.len > 0 and !v.has(.guest_arrange_malformed) and !v.has(.entry_wall_arrange) and !v.has(.fuel_over_ceiling)) {
        // arrange() runs once per refresh with no candidate (zeroed view), over
        // the pool host that reports a FULL visible window — the worst case its
        // pool-scaled loops will ever meet. Fuel exhaustion here is a fuel-cut
        // partial order at runtime (safe), but a named refusal at publish time:
        // an algorithm that cannot finish its own arrange doesn't ship.
        if (guest_vm.runMetered(c.guest_arrange, battery[1], 0.0, fuel, &arrange_battery_host).fuel_exhausted) {
            v.add(.battery_arrange_exhausted);
        }
    }

    // -- The net: if none of the named reasons fired but the load path would
    //    STILL alter something (a clamp this gate predates — e.g. a weight
    //    out of range or non-finite), refuse generically rather than let a
    //    repair slip through. This pairs the gate to validated() forever: a
    //    new load-time clamp automatically becomes a publish-time refusal.
    if (v.count == 0 and !sameLoaded(discover.FeedConfig, c, discover.validated(c))) {
        v.add(.not_load_stable);
    }

    return v;
}

// ---------------------------------------------------------------------------
// Tests — pure (B2), no allocation. Every refusal fires by name; a real
// compiled Zal artifact passes; the battery catches the loop the structural
// checks cannot.
// ---------------------------------------------------------------------------

const t = std.testing;
const zal_parse = @import("zal_parse.zig");
const zal_compile = @import("zal_compile.zig");

test "gate: the default config and a compiled Zal artifact both pass" {
    try t.expect(gate(discover.DEFAULT_CONFIG).pass());

    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const src =
        \\fn retrieve() num { tag_scope("zig", 1.0); return 0.0; }
        \\fn score() num { if (has_tag("zig")) { return base_score * 2.0; } return base_score; }
    ;
    const ast = try zal_parse.parse(arena, src);
    const art = try zal_compile.compileArtifact(arena, &ast);
    try t.expect(art.ok());
    var cfg = discover.DEFAULT_CONFIG;
    cfg.guest_program = art.score;
    cfg.guest_retrieve = art.retrieve;
    cfg.guest_strings = art.strings;
    const v = gate(cfg);
    try t.expect(v.pass());
}

test "gate: every budget refusal fires by name" {
    var cfg = discover.DEFAULT_CONFIG;
    cfg.guest_fuel = guest_vm.max_fuel + 1;
    cfg.state_budget_bytes = discover.state_budget_hard_cap + 1;
    cfg.query.max_candidates = discover.max_candidates_hard_cap + 1;
    const v = gate(cfg);
    try t.expect(!v.pass());
    try t.expect(v.has(.fuel_over_ceiling));
    try t.expect(v.has(.state_budget_over_ceiling));
    try t.expect(v.has(.candidates_over_cap));
    try t.expect(!v.has(.not_load_stable)); // named reasons, not the net
}

test "gate: the entry wall refuses wrong-side bytecode by name" {
    // score() calling a retrieval source — expressible only as hand-crafted
    // bytecode (the compiler refuses it), which is exactly the gap the gate
    // and the load backstop close.
    const bad_score = [_]guest_vm.Instr{
        .{ .op = .push_const, .value = 1 },
        .{ .op = .push_const, .value = 1 },
        .{ .op = .call_host, .arg = @intFromEnum(guest_abi.Capability.source_follows) },
        .{ .op = .halt },
    };
    var cfg = discover.DEFAULT_CONFIG;
    cfg.guest_program = &bad_score;
    try t.expect(gate(cfg).has(.entry_wall_score));

    const bad_retrieve = [_]guest_vm.Instr{
        .{ .op = .push_const, .value = 0 },
        .{ .op = .push_const, .value = 0 },
        .{ .op = .call_host, .arg = @intFromEnum(guest_abi.Capability.attention_dwell) },
        .{ .op = .halt },
    };
    cfg = discover.DEFAULT_CONFIG;
    cfg.guest_retrieve = &bad_retrieve;
    try t.expect(gate(cfg).has(.entry_wall_retrieve));

    // And the load backstop empties both — wrong-side reach never runs.
    cfg = discover.DEFAULT_CONFIG;
    cfg.guest_program = &bad_score;
    cfg.guest_retrieve = &bad_retrieve;
    const loaded = discover.validated(cfg);
    try t.expectEqual(@as(usize, 0), loaded.guest_program.len);
    try t.expectEqual(@as(usize, 0), loaded.guest_retrieve.len);
}

test "gate: the battery refuses a program that cannot finish inside its declared fuel" {
    // An infinite loop: jump to self. Structurally valid (the target is in
    // range), safe at run time (fuel cuts it) — but it can NEVER finish, and
    // only the battery can know that.
    const spinner = [_]guest_vm.Instr{
        .{ .op = .jump, .arg = 0 },
    };
    var cfg = discover.DEFAULT_CONFIG;
    cfg.guest_program = &spinner;
    const v = gate(cfg);
    try t.expect(v.has(.battery_score_exhausted));

    // The same loop as retrieve() is refused on its own name.
    cfg = discover.DEFAULT_CONFIG;
    cfg.guest_retrieve = &spinner;
    try t.expect(gate(cfg).has(.battery_retrieve_exhausted));

    // A bounded loop that fits its budget passes: count 100 down to zero.
    const counter = [_]guest_vm.Instr{
        .{ .op = .push_const, .value = 100 }, // 0: counter on the stack
        .{ .op = .push_const, .value = 1 }, // 1: loop: decrement
        .{ .op = .sub, .arg = 0 },
        .{ .op = .dup, .arg = 0 },
        .{ .op = .jump_if_zero, .arg = 6 }, // done -> 6
        .{ .op = .jump, .arg = 1 }, // again -> 1
        .{ .op = .halt },
    };
    cfg = discover.DEFAULT_CONFIG;
    cfg.guest_program = &counter;
    try t.expect(gate(cfg).pass());
}

test "gate: arrange() is walled, batteried against a FULL pool, and a real one passes" {
    // The wall: an arrange() reaching for a pointwise read is refused by name.
    const bad_arrange = [_]guest_vm.Instr{
        .{ .op = .push_const, .value = 0 },
        .{ .op = .push_const, .value = 0 },
        .{ .op = .call_host, .arg = @intFromEnum(guest_abi.Capability.has_tag) },
        .{ .op = .halt },
    };
    var cfg = discover.DEFAULT_CONFIG;
    cfg.guest_arrange = &bad_arrange;
    try t.expect(gate(cfg).has(.entry_wall_arrange));

    // The battery: a spinner as arrange() can never finish — refused by name.
    const spinner = [_]guest_vm.Instr{
        .{ .op = .jump, .arg = 0 },
    };
    cfg = discover.DEFAULT_CONFIG;
    cfg.guest_arrange = &spinner;
    try t.expect(gate(cfg).has(.battery_arrange_exhausted));

    // A real authored arrange — reverse the pool — finishes against the
    // battery's FULL visible window (pool_size_cap rows) and passes whole.
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const src =
        \\fn score() num { return like_count; }
        \\fn arrange() num {
        \\  var i = pool_len() - 1.0;
        \\  while (i >= 0.0) { emit(i); i = i - 1.0; }
        \\  return 0.0;
        \\}
    ;
    const ast = try zal_parse.parse(arena, src);
    const art = try zal_compile.compileArtifact(arena, &ast);
    try t.expect(art.ok());
    cfg = discover.DEFAULT_CONFIG;
    cfg.guest_program = art.score;
    cfg.guest_arrange = art.arrange;
    try t.expect(gate(cfg).pass());
}

test "gate: malformed programs and oversized pools are named, and the net catches load repairs" {
    // A jump past the end is malformed as authored.
    const bad = [_]guest_vm.Instr{
        .{ .op = .jump, .arg = 99 },
    };
    var cfg = discover.DEFAULT_CONFIG;
    cfg.guest_program = &bad;
    try t.expect(gate(cfg).has(.guest_score_malformed));

    // An over-long tag constant.
    const long = [_]u8{'a'} ** (guest_vm.max_tag_len + 1);
    cfg = discover.DEFAULT_CONFIG;
    cfg.guest_strings = &.{&long};
    try t.expect(gate(cfg).has(.string_too_long));

    // The net: a non-finite weight has no named refusal, but load would
    // repair it — the generic refusal holds the line.
    cfg = discover.DEFAULT_CONFIG;
    cfg.w_like = std.math.nan(f32);
    const v = gate(cfg);
    try t.expect(!v.pass());
    try t.expect(v.has(.not_load_stable));

    // Every refusal has a non-empty sentence.
    inline for (@typeInfo(Refusal).@"enum".fields) |f| {
        try t.expect(label(@field(Refusal, f.name)).len > 0);
    }
}
