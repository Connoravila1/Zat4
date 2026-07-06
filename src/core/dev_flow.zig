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

//! B1 classification: CORE (pure). **The developer submission flow's heart** —
//! the sibling of `create_flow.zig` for the marketplace path: real Zal code in,
//! a publishable public algorithm out (ALGO_SUBMISSION_ROADMAP slice 1).
//!
//! The pure model the renderer draws and the shell drives: the ordered steps
//! (source editor → details → the public-page review → publishing → done), and
//! the two transforms that carry the flow — `check` (Zal source → compile →
//! the fail-closed publish gate, exactly what the CLI publish path enforces,
//! surfaced by name while the author can still fix it) and `finalize` (the
//! checked config + the author's own words → an `algo_library.NewAlgo`,
//! visibility PUBLIC). The author writes their own name/ranks/description; what
//! the code CAN DO is never theirs to claim — the review step's disclosures
//! come from `transparency` over the compiled config, the same derived-labels
//! posture the AppView enforces at index time.

const std = @import("std");
const Allocator = std.mem.Allocator;
const assert = std.debug.assert;
const discover = @import("discover.zig");
const algorithm = @import("algorithm.zig");
const algo_gate = @import("algo_gate.zig");
const algo_library = @import("algo_library.zig");
const zal_parse = @import("zal_parse.zig");
const zal_compile = @import("zal_compile.zig");

/// The ordered steps: the SOURCE editor (write or paste Zal; the check verdict
/// renders here, and nothing advances until it passes), the DETAILS form (the
/// author's name/ranks/description/accent), the REVIEW (the public page as a
/// user will see it — author prose beside code-derived disclosures), then the
/// publish-in-flight beat and the landing. The `enum(u8)` order is load-bearing —
/// advancing is `+1` (the `create_flow` convention).
pub const Step = enum(u8) { source, details, review, publishing, done };

/// The step after `s`, clamped at `done`. PURE.
pub fn nextStep(s: Step) Step {
    const n = @typeInfo(Step).@"enum".fields.len;
    return @enumFromInt(@min(@intFromEnum(s) + 1, n - 1));
}

/// The step before `s`, clamped at `source`. PURE.
pub fn prevStep(s: Step) Step {
    const i = @intFromEnum(s);
    return @enumFromInt(if (i > 0) i - 1 else 0);
}

/// The outcome of checking a Zal source: compile diagnostics (parse errors ride
/// the same list, fail-closed like the compiler itself), or the compiled config
/// plus the publish gate's verdict over it. `config` is meaningful only when
/// `errors` is empty; it borrows the check's arena (the shell re-checks rather
/// than holding one across frames). A7.2: cold struct, size guard waived — one
/// per explicit check action, never held in quantity.
pub const Check = struct {
    config: discover.FeedConfig = .{},
    errors: []const zal_compile.Error = &.{},
    verdict: algo_gate.Verdict = .{},

    /// Publishable as checked: compiled clean AND the gate found nothing to
    /// refuse. The same bar `shell/algorithm.publish` re-applies fail-closed.
    pub fn ok(c: *const Check) bool {
        return c.errors.len == 0 and c.verdict.pass();
    }
};

/// Compile a Zal source and run the publish gate over the result — the whole
/// submit bar, as one pure call (PURE over `(arena, source)`; every slice in
/// the returned Check borrows `arena`). Compile errors return early (the gate
/// needs a program); a compiled artifact lands in a NEUTRAL default config —
/// a guest program IS the ranking, so the config tier it replaces stays at
/// its defaults, same as a fetched record with only guest fields.
pub fn check(arena: Allocator, source: []const u8) Allocator.Error!Check {
    const ast = try zal_parse.parse(arena, source);
    const art = try zal_compile.compileArtifact(arena, &ast);
    if (!art.ok()) return .{ .errors = art.errors };
    var cfg: discover.FeedConfig = .{};
    cfg.guest_program = art.score;
    cfg.guest_retrieve = art.retrieve;
    cfg.guest_arrange = art.arrange;
    cfg.guest_strings = art.strings;
    return .{ .config = cfg, .verdict = algo_gate.gate(cfg) };
}

/// The 1-based line a byte offset falls on — compile diagnostics carry byte
/// offsets (`Error.start`); the editor gutter speaks in lines. PURE, total:
/// an offset past the end reports the last line.
pub fn lineOf(source: []const u8, start: u32) u32 {
    var line: u32 = 1;
    const end = @min(start, source.len);
    for (source[0..end]) |b| {
        if (b == '\n') line += 1;
    }
    return line;
}

/// Turn a checked draft into a PUBLIC library algorithm: the config serialized
/// byte-exact (the same form the publish record carries), the author's own
/// name / ranks one-liner / description, visibility public. `id` is the
/// caller-minted local uid until the publish returns the record CID.
/// Allocates in `arena` (the returned `NewAlgo` borrows it). PURE.
pub fn finalize(
    arena: Allocator,
    cfg: discover.FeedConfig,
    id: []const u8,
    name: []const u8,
    ranks: []const u8,
    desc: []const u8,
    color: u8,
) Allocator.Error!algo_library.NewAlgo {
    return .{
        .id = id,
        .name = name,
        .ranks = ranks,
        .desc = desc,
        .creator = "you",
        .config = try algorithm.serialize(arena, cfg),
        .color = color,
        .visibility = .public,
    };
}

// ---------------------------------------------------------------------------
// Tests — pure, leak-checked.
// ---------------------------------------------------------------------------

const t = std.testing;

test "check: a real template compiles, passes the gate, and is publishable" {
    const templates = @import("zal_templates.zig");
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const c = try check(arena, templates.zat4_discover);
    try t.expectEqual(@as(usize, 0), c.errors.len);
    try t.expect(c.verdict.pass());
    try t.expect(c.ok());
    try t.expect(c.config.guest_program.len > 0);
}

test "check: broken source reports compile errors and is not publishable" {
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const c = try check(arena, "fn score() { return like_count + ; }");
    try t.expect(c.errors.len > 0);
    try t.expect(!c.ok());
    try t.expectEqual(@as(usize, 0), c.config.guest_program.len);
}

test "check: a program without score() is refused with a named diagnostic" {
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const c = try check(arena, "fn helper() { return 1; }");
    try t.expect(c.errors.len > 0);
    try t.expect(!c.ok());
}

test "lineOf maps byte offsets to 1-based lines, total past the end" {
    const src = "a\nbb\nccc";
    try t.expectEqual(@as(u32, 1), lineOf(src, 0));
    try t.expectEqual(@as(u32, 2), lineOf(src, 2));
    try t.expectEqual(@as(u32, 3), lineOf(src, 5));
    try t.expectEqual(@as(u32, 3), lineOf(src, 999));
}

test "finalize produces a public algorithm whose guest config round-trips" {
    const templates = @import("zal_templates.zig");
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const c = try check(arena, templates.zat4_discover_private);
    try t.expect(c.ok());
    const new = try finalize(arena, c.config, "user:9", "Quiet Signal", "calm, candidate-only", "Ranks without reading attention.", 3);
    try t.expectEqual(algo_library.Visibility.public, new.visibility);
    try t.expectEqualStrings("Quiet Signal", new.name);
    // The serialized config parses back with the guest program intact — the
    // byte form a publish record carries loses nothing.
    const back = try algorithm.parse(arena, new.config);
    try t.expectEqual(c.config.guest_program.len, back.guest_program.len);
}
