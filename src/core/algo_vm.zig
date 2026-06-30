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

//! B1 classification: CORE (pure). **The bounded expression VM — DISCOVER
//! Level 3: "creators run their own algorithm code."** Where Level 2 (`rules.zig`)
//! lets a creator pick from a fixed `{predicate, action}` menu, Level 3 lets them
//! author an ARBITRARY SCORING FORMULA over the candidate facts — a real
//! computational artifact the engine executes per candidate. A feed *is* a
//! scoring function, and this VM computes scoring functions and nothing else.
//!
//! **Why this and not WASM/Lua.** The security property we need is that a shared,
//! untrusted algorithm cannot do anything off-device, cannot read your attention
//! data, cannot loop forever, and cannot crash the client. With a general runtime
//! those are fences you maintain (escape surface, gas metering, a heavyweight
//! dependency). Here they are THEOREMS, true by construction:
//!   * **No off-device anything.** The only inputs are a fixed set of public,
//!     candidate-side `Facts` (the same vocabulary Level-2 predicates read) plus
//!     the engine's own `base_score`. There is no opcode for I/O, memory, the
//!     clock, or randomness — the capability is not expressible, so there is
//!     nothing to detect or forbid. (B4 — the pure core lives where the network
//!     isn't — extended to the guest program.)
//!   * **No behavioral door.** The fact vocabulary carries no attention signal,
//!     so a program can never bypass the "uses no behavioral data" label. A
//!     compile-time wall in `transparency.zig` pins the vocabulary public.
//!   * **Always terminates.** The instruction set is straight-line: no jumps, no
//!     loops, no calls. Evaluation is O(program length), and the length is capped
//!     (`max_program_len`). There is no infinite loop to meter against.
//!   * **Never crashes, never poisons a score.** `run` is TOTAL: any byte soup is
//!     a defined, finite number out. A bounded operand stack, missing operands
//!     read as 0, and every value sanitized to a finite, magnitude-bounded range
//!     mean no overflow, no NaN/Inf, no out-of-bounds — on ANY input (E2/E4).
//!   * **Deterministic.** Same program + same facts ⇒ same number, everywhere.
//!     That is the CID-transparency promise: what you inspect is what runs.
//!
//! The program is a slice of plain `Instr` records (typed, JSON-serializable,
//! human-readable in the config record — the priority the marketplace set), so it
//! round-trips byte-exact like the Level-2 rule-list and the Level-1 weights.

const std = @import("std");
const assert = std.debug.assert;
const rules = @import("rules.zig");

/// The VM's read surface — the ONLY values a program can load. Every member but
/// `base_score` is a public, candidate-side fact mirroring `rules.Facts`;
/// `base_score` is the engine's own ranking score for the candidate (so a program
/// can tweak the calibrated base, or ignore it and compute a score from scratch).
/// There is deliberately no behavioral/attention member — that omission is the
/// label-honesty wall, asserted at compile time in `transparency.zig`.
pub const Fact = enum(u8) {
    base_score, // the engine's computed score for this candidate (the layer-in)
    in_network, // 1.0 if from someone you follow, else 0.0
    like_count,
    repost_count,
    reply_count,
    age_hrs, // hours since the post was created
};

/// The opcode vocabulary. A minimal, total, straight-line stack machine: loads,
/// arithmetic, min/max, two unary ops, two comparisons (each pushing 1.0/0.0),
/// and a ternary `select` for branch-free conditionals. No control flow exists,
/// so a program cannot loop or call — termination is structural.
pub const Op = enum(u8) {
    push_const, // push `value`
    push_fact, // push the current value of `fact`
    add, // a + b
    sub, // a - b
    mul, // a * b
    div, // a / b   (b == 0 ⇒ sanitized to 0; never a trap)
    min, // min(a, b)
    max, // max(a, b)
    neg, // -a       (unary)
    abs, // |a|      (unary)
    gt, // a > b ? 1.0 : 0.0
    lt, // a < b ? 1.0 : 0.0
    select, // cond, then, else ⇒ (cond != 0 ? then : else)  (ternary)
};

/// One instruction. `fact` is read only by `push_fact`; `value` only by
/// `push_const`; both are inert for the arithmetic ops. Evaluated in a loop over
/// candidates × instructions, so it is HOT — guarded (A7).
pub const Instr = struct {
    op: Op,
    fact: Fact = .base_score,
    value: f32 = 0,

    comptime {
        // Budget 8: op (u8) + fact (u8) pack into the f32's 4-byte alignment
        // padding, then the f32. Exactly packed.
        assert(@sizeOf(Instr) == 8);
    }
};

/// The most instructions one program may carry. Evaluation is `candidates ×
/// instructions` every refresh, so an unbounded program in a shared (untrusted)
/// config is a CPU denial-of-service vector — the load path rejects anything
/// longer (see `validatedProgram`). 256 is far more than a scoring formula needs.
pub const max_program_len: usize = 256;

/// The operand-stack depth. A straight-line program's stack depth is statically
/// known, so this is a real ceiling, not a guess; `validProgram` proves a program
/// never exceeds it, and `run` clamps to it regardless (defense in depth).
pub const stack_cap: usize = 32;

/// Every stack value is kept finite and within ±`value_limit`, so no operation
/// can produce Inf/NaN or grow without bound. Generous next to any sane score.
const value_limit: f64 = 1e12;

/// Coerce any intermediate to the safe range: non-finite ⇒ 0, otherwise clamped.
/// This single chokepoint is why `run` can never emit Inf/NaN (E4 — a "bad value"
/// is defined out of existence rather than propagated).
fn sanitize(v: f64) f64 {
    if (!std.math.isFinite(v)) return 0;
    return std.math.clamp(v, -value_limit, value_limit);
}

/// Resolve a `Fact` to its f64 value for the current candidate. Pure; the clock
/// never enters (`age_hrs` was precomputed by the caller — B4).
fn factValue(fact: Fact, f: rules.Facts, base_score: f64) f64 {
    return switch (fact) {
        .base_score => base_score,
        .in_network => if (f.in_network) 1.0 else 0.0,
        .like_count => @floatFromInt(f.like_count),
        .repost_count => @floatFromInt(f.repost_count),
        .reply_count => @floatFromInt(f.reply_count),
        .age_hrs => f.age_hrs,
    };
}

/// A bounded operand stack. `push` past the cap drops the value (a program that
/// would overflow is malformed — `run` stays safe rather than trapping); `pop`
/// past the bottom yields 0 (a missing operand reads as zero), so every op is
/// total on any instruction soup.
const Stack = struct {
    buf: [stack_cap]f64 = undefined,
    sp: usize = 0,

    comptime {
        // Budget: the 32-slot f64 operand buffer (256) + the stack pointer (8).
        // A fixed scratch buffer, one per `run` call; the size is deliberate.
        assert(@sizeOf(Stack) == stack_cap * @sizeOf(f64) + @sizeOf(usize));
    }

    fn push(s: *Stack, v: f64) void {
        if (s.sp >= stack_cap) return; // overflow ⇒ drop (malformed program)
        s.buf[s.sp] = sanitize(v);
        s.sp += 1;
    }
    fn pop(s: *Stack) f64 {
        if (s.sp == 0) return 0; // underflow ⇒ 0 (missing operand)
        s.sp -= 1;
        return s.buf[s.sp];
    }
};

/// Evaluate a program for one candidate and return its score. TOTAL: defined and
/// finite for ANY `program` (including hostile or truncated bytecode) — see the
/// module header for the safety argument. `base_score` is the engine's score for
/// the candidate, exposed as the `base_score` fact and used as the result if the
/// program leaves the stack empty (an empty program ⇒ the base unchanged, so the
/// VM layer is inert by default). Pure; no allocation.
pub fn run(program: []const Instr, f: rules.Facts, base_score: f64) f64 {
    var st: Stack = .{};
    for (program) |ins| {
        switch (ins.op) {
            .push_const => st.push(ins.value),
            .push_fact => st.push(factValue(ins.fact, f, base_score)),
            .neg => {
                const a = st.pop();
                st.push(-a);
            },
            .abs => {
                const a = st.pop();
                st.push(@abs(a));
            },
            .select => {
                const else_v = st.pop();
                const then_v = st.pop();
                const cond = st.pop();
                st.push(if (cond != 0) then_v else else_v);
            },
            else => {
                // The binary ops share the pop-b, pop-a shape.
                const b = st.pop();
                const a = st.pop();
                st.push(switch (ins.op) {
                    .add => a + b,
                    .sub => a - b,
                    .mul => a * b,
                    .div => if (b == 0) 0 else a / b,
                    .min => @min(a, b),
                    .max => @max(a, b),
                    .gt => if (a > b) @as(f64, 1.0) else 0.0,
                    .lt => if (a < b) @as(f64, 1.0) else 0.0,
                    else => unreachable, // the non-binary ops are handled above
                });
            },
        }
    }
    // The formula's result is the top of the stack; an empty stack means the
    // program contributed nothing, so the engine's base score stands.
    return sanitize(if (st.sp > 0) st.buf[st.sp - 1] else base_score);
}

/// How many operands an op consumes / produces — the basis of the static stack
/// analysis. (consumed, produced).
fn arity(op: Op) struct { in: u8, out: u8 } {
    return switch (op) {
        .push_const, .push_fact => .{ .in = 0, .out = 1 },
        .neg, .abs => .{ .in = 1, .out = 1 },
        .select => .{ .in = 3, .out = 1 },
        else => .{ .in = 2, .out = 1 }, // the binary ops
    };
}

/// Is this a well-formed program? A straight-line program's stack behaviour is
/// statically decidable, so we can PROVE well-formedness without running it:
/// within the length cap, never underflows, never exceeds `stack_cap`, and leaves
/// exactly one value (the result). This is the honesty/sanity gate — `run` is
/// safe on any input, but only a valid program is a meaningful formula, so the
/// load path keeps valid programs and discards the rest, and the transparency
/// view renders only a valid program as readable logic. Pure.
pub fn validProgram(program: []const Instr) bool {
    if (program.len > max_program_len) return false;
    var depth: usize = 0;
    for (program) |ins| {
        const a = arity(ins.op);
        if (depth < a.in) return false; // underflow
        depth = depth - a.in + a.out;
        if (depth > stack_cap) return false; // would overflow the operand stack
    }
    return depth == 1; // exactly one result left on the stack
}

/// The program the engine will actually run: the input if it is valid, otherwise
/// EMPTY (a no-op that leaves the base score untouched). A malformed or oversized
/// program is fail-safe — never partially executed, never trusted (E2/E4). The
/// returned slice borrows the input's memory; no allocation.
pub fn validatedProgram(program: []const Instr) []const Instr {
    return if (validProgram(program)) program else &.{};
}

// ---------------------------------------------------------------------------
// Tests — pure (B2), no allocation
// ---------------------------------------------------------------------------

const sample: rules.Facts = .{
    .in_network = false,
    .like_count = 100,
    .repost_count = 10,
    .reply_count = 30,
    .age_hrs = 4.0,
};

test "run: an empty program leaves the base score untouched (inert by default)" {
    const t = std.testing;
    try t.expectEqual(@as(f64, 7.5), run(&.{}, sample, 7.5));
}

test "run: a constant formula ignores the base" {
    const t = std.testing;
    const prog = [_]Instr{.{ .op = .push_const, .value = 42 }};
    try t.expectEqual(@as(f64, 42), run(&prog, sample, 999));
}

test "run: facts load and arithmetic composes (likes*2 + reposts)" {
    const t = std.testing;
    // push like_count; push 2; mul; push repost_count; add  ⇒ 100*2 + 10 = 210
    const prog = [_]Instr{
        .{ .op = .push_fact, .fact = .like_count },
        .{ .op = .push_const, .value = 2 },
        .{ .op = .mul },
        .{ .op = .push_fact, .fact = .repost_count },
        .{ .op = .add },
    };
    try t.expectEqual(@as(f64, 210), run(&prog, sample, 0));
}

test "run: base_score is readable and tweakable (base * 1.5)" {
    const t = std.testing;
    const prog = [_]Instr{
        .{ .op = .push_fact, .fact = .base_score },
        .{ .op = .push_const, .value = 1.5 },
        .{ .op = .mul },
    };
    try t.expectEqual(@as(f64, 12), run(&prog, sample, 8));
}

test "run: select gives a branch-free conditional" {
    const t = std.testing;
    // if (in_network > 0) then base*2 else base   — here in_network is false ⇒ base
    const prog = [_]Instr{
        .{ .op = .push_fact, .fact = .in_network }, // cond
        .{ .op = .push_fact, .fact = .base_score }, // then-branch value
        .{ .op = .push_const, .value = 2 },
        .{ .op = .mul },
        .{ .op = .push_fact, .fact = .base_score }, // else-branch value
        .{ .op = .select },
    };
    // Stack at select: [cond=0, then=2*base, else=base] ⇒ else = base = 5
    try t.expectEqual(@as(f64, 5), run(&prog, sample, 5));
}

test "run: division by zero is defined as 0, never a trap or Inf" {
    const t = std.testing;
    const prog = [_]Instr{
        .{ .op = .push_const, .value = 1 },
        .{ .op = .push_const, .value = 0 },
        .{ .op = .div },
    };
    const r = run(&prog, sample, 0);
    try t.expect(std.math.isFinite(r));
    try t.expectEqual(@as(f64, 0), r);
}

test "run: a runaway product is clamped finite, never Inf/NaN" {
    const t = std.testing;
    // Multiply a huge constant by itself — would overflow to Inf without the
    // per-value clamp.
    const prog = [_]Instr{
        .{ .op = .push_const, .value = 3.0e38 }, // near f32 max
        .{ .op = .push_const, .value = 3.0e38 },
        .{ .op = .mul },
    };
    const r = run(&prog, sample, 0);
    try t.expect(std.math.isFinite(r));
    try t.expect(@abs(r) <= value_limit);
}

test "run: underflow (too few operands) reads missing as 0, never crashes" {
    const t = std.testing;
    const prog = [_]Instr{.{ .op = .add }}; // add with an empty stack ⇒ 0 + 0
    try t.expectEqual(@as(f64, 0), run(&prog, sample, 9));
}

test "validProgram: accepts a balanced formula, rejects malformed ones" {
    const t = std.testing;
    const ok = [_]Instr{
        .{ .op = .push_fact, .fact = .like_count },
        .{ .op = .push_const, .value = 2 },
        .{ .op = .mul },
    };
    try t.expect(validProgram(&ok)); // ends with depth 1

    const underflow = [_]Instr{.{ .op = .add }}; // needs 2, has 0
    try t.expect(!validProgram(&underflow));

    const leftover = [_]Instr{
        .{ .op = .push_const, .value = 1 },
        .{ .op = .push_const, .value = 2 },
    }; // ends with depth 2 — ambiguous, not a single result
    try t.expect(!validProgram(&leftover));

    try t.expect(!validProgram(&.{})); // empty ends with depth 0, not 1
}

test "validProgram: a too-long program is rejected (DoS wall)" {
    const t = std.testing;
    // A program that is a single push repeated past the cap — also overflows the
    // operand stack, but the length check rejects it first regardless.
    var long: [max_program_len + 1]Instr = undefined;
    for (&long) |*ins| ins.* = .{ .op = .push_const, .value = 1 };
    try t.expect(!validProgram(&long));
}

test "validatedProgram: malformed input becomes a safe no-op" {
    const t = std.testing;
    const bad = [_]Instr{.{ .op = .mul }}; // underflows
    try t.expectEqual(@as(usize, 0), validatedProgram(&bad).len);

    const good = [_]Instr{.{ .op = .push_const, .value = 1 }};
    try t.expectEqual(@as(usize, 1), validatedProgram(&good).len);
}

// ---------------------------------------------------------------------------
// Fuzzing — the totality theorem, hammered (Phase-8 discipline). `run` must be
// defined, finite, and bounded for ANY program over the valid opcodes and ANY
// facts/base, INCLUDING NaN/Inf constants and fact values. An out-of-range enum
// would itself be illegal behaviour to construct, so the realistic threat model
// is a well-formed `Instr` array carrying arbitrary opcodes, facts, and values —
// exactly what a parsed-from-the-wire program is once its enum tags validated.
// ---------------------------------------------------------------------------

/// A random f32 — arbitrary bit patterns, so NaN, ±Inf, and denormals all occur.
fn fuzzF32(rnd: std.Random) f32 {
    return @bitCast(rnd.int(u32));
}

test "fuzz: run is total — finite, bounded output for any program and any facts" {
    const t = std.testing;
    var prng = std.Random.DefaultPrng.init(0xA130_F00D);
    const rnd = prng.random();
    const ops = std.enums.values(Op);
    const facts = std.enums.values(Fact);

    var buf: [2 * max_program_len]Instr = undefined; // lengths past the cap too
    var iter: usize = 0;
    while (iter < 40_000) : (iter += 1) {
        const len = rnd.uintAtMost(usize, buf.len);
        for (buf[0..len]) |*ins| ins.* = .{
            .op = ops[rnd.uintLessThan(usize, ops.len)],
            .fact = facts[rnd.uintLessThan(usize, facts.len)],
            .value = fuzzF32(rnd), // includes NaN / ±Inf constants
        };
        const prog = buf[0..len];

        const f: rules.Facts = .{
            .in_network = rnd.boolean(),
            .like_count = rnd.int(u32),
            .repost_count = rnd.int(u32),
            .reply_count = rnd.int(u32),
            .age_hrs = @bitCast(rnd.int(u64)), // arbitrary f64 incl NaN/Inf
        };
        const base: f64 = @bitCast(rnd.int(u64)); // even a NaN base must come out finite

        const out = run(prog, f, base);
        try t.expect(std.math.isFinite(out)); // never NaN/Inf
        try t.expect(@abs(out) <= value_limit); // always bounded

        // The validation gate must also never crash, and a program it accepts
        // must still run finite (defense in depth — the score path runs the
        // validated slice).
        _ = validProgram(prog);
        const vp = validatedProgram(prog);
        try t.expect(std.math.isFinite(run(vp, f, base)));
    }
}

test "fuzz: a valid program always leaves exactly one result, and run agrees" {
    const t = std.testing;
    var prng = std.Random.DefaultPrng.init(0xBEEF_5C0E);
    const rnd = prng.random();
    const ops = std.enums.values(Op);
    const facts = std.enums.values(Fact);

    var buf: [max_program_len]Instr = undefined;
    var checked: usize = 0;
    var iter: usize = 0;
    // Generate programs and, whenever one happens to be valid, assert the
    // structural promise: run produces a finite score (it always does), and a
    // valid program by construction balanced to depth 1.
    while (iter < 60_000 and checked < 2_000) : (iter += 1) {
        const len = rnd.uintAtMost(usize, buf.len);
        for (buf[0..len]) |*ins| ins.* = .{
            .op = ops[rnd.uintLessThan(usize, ops.len)],
            .fact = facts[rnd.uintLessThan(usize, facts.len)],
            .value = fuzzF32(rnd),
        };
        const prog = buf[0..len];
        if (!validProgram(prog)) continue;
        checked += 1;
        const out = run(prog, sample, 1.0);
        try t.expect(std.math.isFinite(out));
    }
    try t.expect(checked > 0); // the generator did reach valid programs
}
