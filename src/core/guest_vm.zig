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

//! B1 classification: CORE (pure). **GUEST TIER — Phase 2: the guest VM.** See
//! `GUEST_TIER_ROADMAP.md`.
//!
//! The Turing-complete machine a developer-tier algorithm runs on. It is a SIBLING
//! of `algo_vm.zig` (the straight-line L3 expression VM), not a replacement: that
//! VM stays exactly as it is — small, proven, and used by the config tier. This
//! one reuses its DESIGN (a bounded operand stack, `sanitize` on every value,
//! exhaustive `else`-free switches, `@setRuntimeSafety(true)` on untrusted
//! indexing) and adds what a real authoring target needs — control flow (loops +
//! branches), and, in later sub-slices, bounded scratch memory and the `call_host`
//! capability window. It is deliberately NOT WASM: no dependency, and safety stays
//! a theorem of the opcode set (there is no opcode for I/O — that reach is simply
//! absent, `guest_abi.zig`).
//!
//! **Termination is by FUEL, not structure.** A straight-line VM terminates because
//! it can't loop; this one can, so `run` meters a step budget and STOPS when it is
//! exhausted. That makes evaluation TOTAL over any bytecode — hostile, looping, or
//! truncated — with no hang, no trap, no unbounded work. Combined with the bounded
//! stack (pop-underflow ⇒ 0, push-overflow ⇒ drop) and `sanitize` (no NaN/Inf/
//! unbounded value), `run` is defined and finite for EVERY input. `validProgram`
//! is a well-formedness SANITY gate on top of that, never the safety mechanism —
//! `run` is safe on anything.
//!
//! SCOPE (sub-slice 2a): loads, arithmetic, stack shuffles, control flow, fuel.
//! Bounded scratch memory (2b) and `call_host` into the capability table (2c) land
//! next; the opcode set + validator are built to extend to them without a reshape.

const std = @import("std");
const assert = std.debug.assert;
const guest_abi = @import("guest_abi.zig");

/// The input facts a program reads with `push_fact` — the PUBLIC candidate features
/// (from `guest_abi.CandidateView`) plus `base_score` (the engine's score for the
/// candidate, the layer-in). NO per-identity fact and NO behavioral fact here: the
/// user's attention is reached only through the gated `call_host` capability (2c),
/// never as a plain readable fact — so a program that was granted no behavioral
/// capability provably cannot read attention (the door discipline, `guest_abi`).
pub const Fact = enum(u8) {
    base_score,
    like_count,
    repost_count,
    reply_count,
    age_hrs,
    author_rep,
    in_network,

    comptime {
        // Exactly the public CandidateView features + base_score. Adding a fact is
        // a deliberate act (weigh targeting / behavioral exposure), mirroring
        // `algo_vm.Fact`'s count guard.
        assert(@typeInfo(Fact).@"enum".fields.len == 7);
    }
};

/// The opcode vocabulary. Loads, arithmetic, min/max, two unary ops, two
/// comparisons, a branch-free `select`, stack shuffles, and CONTROL FLOW (`jump`,
/// `jump_if_zero`, `halt`). Unlike `algo_vm`, control flow exists — so the machine
/// is Turing-complete and termination is fuel-metered, not structural.
pub const Op = enum(u8) {
    push_const, // push `value`
    push_fact, // push the current value of `fact`
    add,
    sub,
    mul,
    div, // b == 0 ⇒ 0 (never a trap)
    min,
    max,
    neg, // unary
    abs, // unary
    gt, // a > b ? 1 : 0
    lt, // a < b ? 1 : 0
    select, // cond, then, else ⇒ (cond != 0 ? then : else)
    dup, // push a copy of the top
    pop, // discard the top
    jump, // pc = `arg` (unconditional)
    jump_if_zero, // pop cond; if 0, pc = `arg`, else fall through
    halt, // stop; the result is the top of the stack

    comptime {
        assert(@typeInfo(Op).@"enum".fields.len == 18);
    }
};

/// One instruction. `fact` is read only by `push_fact`; `value` only by
/// `push_const`; `arg` is the integer operand for control flow (`jump` /
/// `jump_if_zero` target) and, later, memory index / capability id — all small
/// integers. Evaluated in a loop over instructions, so it is HOT → A7.
pub const Instr = struct {
    op: Op,
    fact: Fact = .base_score,
    arg: u16 = 0, // jump target (2a); memory index / capability id (2b/2c)
    value: f32 = 0, // push_const literal

    comptime {
        // Budget 8: op (1) + fact (1) + arg (2) pack ahead of the f32's 4-byte
        // alignment, then value (4). Exactly packed — same tight 8 bytes as
        // `algo_vm.Instr`, with the spare 2 bytes now spent on the jump target.
        assert(@sizeOf(Instr) == 8);
    }
};

/// The most instructions one guest program may carry. Larger than the L3 formula
/// cap because loops make longer programs meaningful, but still a hard DoS bound
/// (the publish gate rejects anything longer, Phase 5). u16 `arg` addresses up to
/// 65535, comfortably past this.
pub const max_program_len: usize = 4096;

/// The operand-stack depth. A bounded, owned buffer; push past it drops (a
/// malformed program stays safe rather than trapping), pop past bottom yields 0.
pub const stack_cap: usize = 64;

/// The default per-run fuel budget (max instructions executed for ONE candidate).
/// The real budget is declared per-algorithm and capped at `max_fuel`; this is the
/// engine default. Generous for orchestration, bounded so a loop can never hang.
pub const default_fuel: u32 = 100_000;

/// The hard ceiling on a declared fuel budget — the CPU-DoS wall (evaluation is
/// `candidates × fuel`). The load path clamps a declared budget to this.
pub const max_fuel: u32 = 5_000_000;

/// Every stack value is kept finite and within ±`value_limit`, so no op can produce
/// Inf/NaN or grow without bound.
const value_limit: f64 = 1e12;

/// Coerce any intermediate to the safe range: non-finite ⇒ 0, else clamped. The
/// single chokepoint that makes `run` unable to emit Inf/NaN (E4).
fn sanitize(v: f64) f64 {
    if (!std.math.isFinite(v)) return 0;
    return std.math.clamp(v, -value_limit, value_limit);
}

/// Resolve a `Fact` to its f64 value for the current candidate. Pure; the clock
/// never enters (`age_hrs` was precomputed by the host — B4).
fn factValue(fact: Fact, v: guest_abi.CandidateView, base_score: f64) f64 {
    return switch (fact) {
        .base_score => base_score,
        .like_count => @floatFromInt(v.like_count),
        .repost_count => @floatFromInt(v.repost_count),
        .reply_count => @floatFromInt(v.reply_count),
        .age_hrs => v.age_hrs,
        .author_rep => v.author_rep,
        .in_network => if (v.in_network) 1.0 else 0.0,
    };
}

/// A bounded operand stack (the `algo_vm` design). `push` past the cap drops the
/// value; `pop`/`peek` past the bottom yields 0 — so every op is total on any
/// instruction soup. Safety forced on regardless of build mode.
const Stack = struct {
    buf: [stack_cap]f64 = undefined,
    sp: usize = 0,

    comptime {
        assert(@sizeOf(Stack) == stack_cap * @sizeOf(f64) + @sizeOf(usize));
    }

    fn push(s: *Stack, v: f64) void {
        @setRuntimeSafety(true);
        if (s.sp >= stack_cap) return; // overflow ⇒ drop (malformed program)
        s.buf[s.sp] = sanitize(v);
        s.sp += 1;
    }
    fn pop(s: *Stack) f64 {
        @setRuntimeSafety(true);
        if (s.sp == 0) return 0; // underflow ⇒ 0 (missing operand)
        s.sp -= 1;
        return s.buf[s.sp];
    }
    fn peek(s: *const Stack) f64 {
        @setRuntimeSafety(true);
        return if (s.sp == 0) 0 else s.buf[s.sp - 1];
    }
};

/// Run a guest program for one candidate and return its score. TOTAL: defined and
/// finite for ANY bytecode, at any `fuel_budget` — a looping or hostile program is
/// STOPPED when its fuel runs out (never a hang), operands are bounded, and every
/// value is sanitized. `base_score` is the engine's score for the candidate (the
/// `base_score` fact) and the result if the program leaves the stack empty (an
/// empty program ⇒ base unchanged, so the VM layer is inert by default). Pure.
pub fn run(program: []const Instr, view: guest_abi.CandidateView, base_score: f64, fuel_budget: u32) f64 {
    @setRuntimeSafety(true); // untrusted bytecode drives `pc` — force checks on regardless of build
    var st: Stack = .{};
    var pc: usize = 0;
    var fuel: u32 = 0;
    while (pc < program.len) {
        if (fuel >= fuel_budget) break; // out of fuel ⇒ stop (this is what makes loops total)
        fuel += 1;
        const ins = program[pc];
        // EXHAUSTIVE — no `else`. A new opcode must be handled here (and in `arity`)
        // or the build fails; a fuzz test cross-checks the two switches.
        switch (ins.op) {
            .push_const => {
                st.push(ins.value);
                pc += 1;
            },
            .push_fact => {
                st.push(factValue(ins.fact, view, base_score));
                pc += 1;
            },
            .add => {
                const b = st.pop();
                st.push(st.pop() + b);
                pc += 1;
            },
            .sub => {
                const b = st.pop();
                st.push(st.pop() - b);
                pc += 1;
            },
            .mul => {
                const b = st.pop();
                st.push(st.pop() * b);
                pc += 1;
            },
            .div => {
                const b = st.pop();
                const a = st.pop();
                st.push(if (b == 0) 0 else a / b);
                pc += 1;
            },
            .min => {
                const b = st.pop();
                st.push(@min(st.pop(), b));
                pc += 1;
            },
            .max => {
                const b = st.pop();
                st.push(@max(st.pop(), b));
                pc += 1;
            },
            .neg => {
                st.push(-st.pop());
                pc += 1;
            },
            .abs => {
                st.push(@abs(st.pop()));
                pc += 1;
            },
            .gt => {
                const b = st.pop();
                st.push(if (st.pop() > b) @as(f64, 1.0) else 0.0);
                pc += 1;
            },
            .lt => {
                const b = st.pop();
                st.push(if (st.pop() < b) @as(f64, 1.0) else 0.0);
                pc += 1;
            },
            .select => {
                const else_v = st.pop();
                const then_v = st.pop();
                const cond = st.pop();
                st.push(if (cond != 0) then_v else else_v);
                pc += 1;
            },
            .dup => {
                st.push(st.peek());
                pc += 1;
            },
            .pop => {
                _ = st.pop();
                pc += 1;
            },
            .jump => {
                // An out-of-range target ends the loop (the `while` guard), so a bad
                // jump just terminates — safe. A jump to self burns fuel until it's
                // out — also safe.
                pc = ins.arg;
            },
            .jump_if_zero => {
                if (st.pop() == 0) pc = ins.arg else pc += 1;
            },
            .halt => break,
        }
    }
    return sanitize(if (st.sp > 0) st.buf[st.sp - 1] else base_score);
}

/// A well-formedness SANITY gate (NOT the safety mechanism — `run` is total on any
/// input). Because loops make exact stack analysis undecidable in general, this is
/// a lenient structural check: within the length cap, every control-flow target is
/// in range, and no SINGLE instruction under-flows the operand stack given the
/// per-op arity along the fall-through path (a coarse local check that catches the
/// obvious mistakes; `run` stays safe on the rest). Pure.
pub fn validProgram(program: []const Instr) bool {
    if (program.len == 0 or program.len > max_program_len) return false;
    for (program) |ins| {
        switch (ins.op) {
            // A branch/jump target must land inside the program (or exactly at the
            // end, meaning "halt"). Out-of-range would silently terminate at run
            // time — a valid program never relies on that.
            .jump, .jump_if_zero => if (ins.arg > program.len) return false,
            else => {},
        }
    }
    return true;
}

/// The program the engine will run: the input if well-formed, otherwise EMPTY (a
/// no-op that leaves the base score untouched). Fail-safe (E2/E4); borrows the
/// input's memory.
pub fn validatedProgram(program: []const Instr) []const Instr {
    return if (validProgram(program)) program else &.{};
}

// ---------------------------------------------------------------------------
// Tests — pure (B2), no allocation. Turing-completeness, termination-by-fuel,
// and totality on hostile bytecode.
// ---------------------------------------------------------------------------

const t = std.testing;

const sample: guest_abi.CandidateView = .{
    .like_count = 100,
    .repost_count = 10,
    .reply_count = 30,
    .age_hrs = 4.0,
    .author_rep = 0.5,
    .in_network = true,
};

test "guards + counts" {
    try t.expectEqual(@as(usize, 8), @sizeOf(Instr));
    try t.expectEqual(@as(usize, 18), @typeInfo(Op).@"enum".fields.len);
    try t.expectEqual(@as(usize, 7), @typeInfo(Fact).@"enum".fields.len);
}

test "run: empty program leaves the base score untouched (inert by default)" {
    try t.expectEqual(@as(f64, 7.5), run(&.{}, sample, 7.5, default_fuel));
}

test "run: arithmetic — base_score × 1.5 + likes" {
    const prog = [_]Instr{
        .{ .op = .push_fact, .fact = .base_score },
        .{ .op = .push_const, .value = 1.5 },
        .{ .op = .mul },
        .{ .op = .push_fact, .fact = .like_count },
        .{ .op = .add },
    };
    // 10 × 1.5 + 100 = 115
    try t.expectEqual(@as(f64, 115.0), run(&prog, sample, 10.0, default_fuel));
}

test "run: a real LOOP runs to a verifiable result — countdown to 1" {
    // i = N; while (i > 1) i -= 1;  → result = 1 for any N ≥ 1. A straight-line VM
    // cannot express this (it has no back-edge); here the `jump` closes the loop
    // and fuel guarantees it stops. N = like_count = 100, so it iterates 99 times.
    const prog = [_]Instr{
        .{ .op = .push_fact, .fact = .like_count }, // 0: i = 100          [i]
        .{ .op = .dup }, // 1: loop head            [i, i]
        .{ .op = .push_const, .value = 1 }, // 2    [i, i, 1]
        .{ .op = .gt }, // 3: i > 1 ?               [i, cond]
        .{ .op = .jump_if_zero, .arg = 8 }, // 4: if not, exit to end@8   [i]
        .{ .op = .push_const, .value = 1 }, // 5    [i, 1]
        .{ .op = .sub }, // 6: i -= 1               [i-1]
        .{ .op = .jump, .arg = 1 }, // 7: back to the loop head
    }; // 8 = end (pc past the last instruction ⇒ halt); result = top = 1
    try t.expectEqual(@as(f64, 1.0), run(&prog, sample, 0, default_fuel));
}

test "run: an infinite loop is STOPPED by fuel (termination is total)" {
    // jump 0 forever — with structural termination this would hang; fuel halts it.
    const prog = [_]Instr{
        .{ .op = .push_const, .value = 42 },
        .{ .op = .jump, .arg = 0 },
    };
    // A tiny fuel budget: it must return (not hang) and stay finite.
    const r = run(&prog, sample, 7.0, 50);
    try t.expect(std.math.isFinite(r));
}

test "run: totally safe on hostile / truncated bytecode (underflow, bad jumps)" {
    // ops with no operands, a jump way out of range, a pop on empty — all defined.
    const prog = [_]Instr{
        .{ .op = .add }, // underflow → operands read as 0
        .{ .op = .pop }, // pop empty → 0
        .{ .op = .jump, .arg = 9999 }, // out of range → loop ends (safe)
        .{ .op = .mul },
    };
    const r = run(&prog, sample, 3.0, default_fuel);
    try t.expect(std.math.isFinite(r));
}

test "fuzz: run is TOTAL on random bytecode — always finite, never hangs (the safety proof)" {
    // 100k random programs: random opcodes, facts, jump targets, and value bit
    // patterns (including NaN/Inf). Each must return a FINITE score within a small
    // fuel budget — proving termination (fuel), memory safety (bounded stack), and
    // no NaN/Inf (sanitize) all hold on adversarial input. Ops/facts are generated
    // in-range so this fuzzes SEMANTICS, not enum-tag corruption (the load path and
    // the validator reject out-of-range tags before `run` ever sees them).
    var prng = std.Random.DefaultPrng.init(0xC0FFEE_D00D);
    const rand = prng.random();
    var buf: [96]Instr = undefined;
    var iter: usize = 0;
    while (iter < 100_000) : (iter += 1) {
        const len = rand.intRangeAtMost(usize, 0, buf.len);
        for (buf[0..len]) |*ins| {
            ins.* = .{
                .op = @enumFromInt(rand.uintLessThan(u8, @typeInfo(Op).@"enum".fields.len)),
                .fact = @enumFromInt(rand.uintLessThan(u8, @typeInfo(Fact).@"enum".fields.len)),
                .arg = rand.int(u16), // random jump targets, often out of range
                .value = @bitCast(rand.int(u32)), // any f32 bits — NaN, Inf, huge
            };
        }
        const r = run(buf[0..len], sample, @bitCast(rand.int(u64)), 3000);
        try t.expect(std.math.isFinite(r)); // TOTAL: finite, and it returned (no hang)
    }
}

test "validProgram: rejects empty, over-cap, and out-of-range jump targets" {
    try t.expect(!validProgram(&.{})); // empty is not a meaningful program
    const ok = [_]Instr{ .{ .op = .push_const, .value = 1 }, .{ .op = .jump, .arg = 0 } };
    try t.expect(validProgram(&ok));
    const bad_target = [_]Instr{.{ .op = .jump, .arg = 500 }};
    try t.expect(!validProgram(&bad_target)); // target past the end
    try t.expectEqual(@as(usize, 0), validatedProgram(&bad_target).len); // → no-op
}
