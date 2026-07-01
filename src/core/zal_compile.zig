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

//! B1 classification: CORE (pure over `(arena, ast)`). **GUEST TIER — Phase 3:
//! Zal, codegen — the last mile that makes Zal source RUN.** See
//! `GUEST_TIER_ROADMAP.md`.
//!
//! Walks the parser's AST and emits `guest_vm` bytecode: expressions in postfix
//! (stack-machine) order, control flow via `jump`/`jump_if_zero` with back-patched
//! targets, locals in scratch-memory slots. It also does the little "type-check"
//! this language needs — with one numeric type there are no real type errors, so
//! checking IS name resolution + call arity: an identifier resolves to a VM FACT
//! (`base_score`, `like_count`, …), a declared LOCAL (a scratch slot), or, in a
//! call, a host CAPABILITY (`guest_abi.Capability`); an unknown name or a bad arity
//! is a clean error, and codegen REFUSES to emit anything for a program that had
//! parse errors or resolution errors.
//!
//! The eBPF trust posture: this compiler is UNTRUSTED. The real security boundary
//! is `guest_vm.validProgram` + the total `guest_vm.run` — the CALLER validates the
//! emitted bytecode, and even if this compiler had a bug (or were replaced by a
//! hostile one), the VM is safe on ANY bytecode. Pure over `(arena, ast)`; only OOM
//! propagates.

const std = @import("std");
const Allocator = std.mem.Allocator;
const parse = @import("zal_parse.zig");
const vm = @import("guest_vm.zig");
const guest_abi = @import("guest_abi.zig");

const Ast = parse.Ast;
const Tag = parse.Tag;
const NodeIndex = parse.NodeIndex;
const Instr = vm.Instr;

/// A compile diagnostic. A7.2: cold — a handful, author-facing.
pub const Error = struct {
    msg: []const u8,
    start: u32,
};

/// The compile result. `program` is empty when `errors` is non-empty — a program
/// with any error is never partially emitted (fail-closed). `strings` is the
/// read-only tag-constant pool the program's `has_tag`/`source_tag_scope` calls
/// index into (empty on error, or when the program uses no tag literal); it travels
/// WITH the program as part of the artifact. A7.2: cold, waived.
pub const Result = struct {
    program: []const Instr,
    strings: []const []const u8 = &.{},
    errors: []const Error,
    pub fn ok(self: Result) bool {
        return self.errors.len == 0;
    }
};

/// Map a Zal identifier to a VM input fact, or null if it is not a fact name.
fn factOf(name: []const u8) ?vm.Fact {
    const table = .{
        .{ "base_score", vm.Fact.base_score },
        .{ "like_count", vm.Fact.like_count },
        .{ "repost_count", vm.Fact.repost_count },
        .{ "reply_count", vm.Fact.reply_count },
        .{ "age_hrs", vm.Fact.age_hrs },
        .{ "author_rep", vm.Fact.author_rep },
        .{ "in_network", vm.Fact.in_network },
        .{ "viewer_engaged", vm.Fact.viewer_engaged },
        .{ "tag_count", vm.Fact.tag_count },
        .{ "reply_chain", vm.Fact.reply_chain },
        .{ "quote_count", vm.Fact.quote_count },
    };
    inline for (table) |e| if (std.mem.eql(u8, name, e[0])) return e[1];
    return null;
}

/// Map a Zal call name to a host capability, or null if it is not a capability.
/// These are the readable stdlib names a creator writes; they mirror the
/// `guest_abi.Capability` set one-to-one (one vocabulary, `guest_abi`).
fn capabilityOf(name: []const u8) ?guest_abi.Capability {
    const table = .{
        .{ "follows", guest_abi.Capability.source_follows },
        .{ "discovery", guest_abi.Capability.source_discovery },
        .{ "trending", guest_abi.Capability.source_trending },
        .{ "tag_scope", guest_abi.Capability.source_tag_scope },
        .{ "has_tag", guest_abi.Capability.has_tag },
        .{ "state_read", guest_abi.Capability.state_read },
        .{ "state_write", guest_abi.Capability.state_write },
        .{ "attention_dwell", guest_abi.Capability.attention_dwell },
        .{ "attention_clicked", guest_abi.Capability.attention_clicked },
    };
    inline for (table) |e| if (std.mem.eql(u8, name, e[0])) return e[1];
    return null;
}

/// Does this capability take a TAG-STRING literal as its first argument (resolved
/// from the artifact's string pool by the host)? These are the only calls where a
/// string literal is legal; a string anywhere else is a compile error. Exhaustive
/// (no `else`), so a new capability must decide here whether it is tag-taking.
fn capabilityTakesTag(cap: guest_abi.Capability) bool {
    return switch (cap) {
        .has_tag, .source_tag_scope => true,
        .source_follows, .source_discovery, .source_trending, .state_read, .state_write, .attention_dwell, .attention_clicked => false,
    };
}

/// Strip the surrounding quotes from a string token's text (`"zig"` → `zig`). The
/// lexer only emits a `.string` for a terminated `"..."`, so `len >= 2`.
fn stripQuotes(lit: []const u8) []const u8 {
    return if (lit.len >= 2) lit[1 .. lit.len - 1] else lit;
}

const Local = struct { name: []const u8, slot: u16 };

// A7.2: cold — one instance per compile; holds the emit state. Waived.
const Compiler = struct {
    arena: Allocator,
    ast: *const Ast,
    code: std.ArrayListUnmanaged(Instr) = .empty,
    errors: std.ArrayListUnmanaged(Error) = .empty,
    locals: std.ArrayListUnmanaged(Local) = .empty,
    strings: std.ArrayListUnmanaged([]const u8) = .empty,
    next_slot: u16 = 0,

    fn emit(c: *Compiler, ins: Instr) Allocator.Error!u32 {
        const idx: u32 = @intCast(c.code.items.len);
        try c.code.append(c.arena, ins);
        return idx;
    }

    /// Intern a tag literal into the read-only string pool, returning its index (a
    /// small number the guest pushes and the host resolves), or null on a bounds
    /// error (fail-closed). Deduplicated by value; bounded by the artifact caps.
    fn internString(c: *Compiler, s: []const u8) Allocator.Error!?u16 {
        for (c.strings.items, 0..) |existing, i| {
            if (std.mem.eql(u8, existing, s)) return @intCast(i);
        }
        if (s.len > vm.max_tag_len) {
            try c.err("tag name too long", 0);
            return null;
        }
        if (c.strings.items.len >= vm.max_strings) {
            try c.err("too many distinct tag names", 0);
            return null;
        }
        const idx: u16 = @intCast(c.strings.items.len);
        try c.strings.append(c.arena, s);
        return idx;
    }

    fn err(c: *Compiler, msg: []const u8, start: u32) Allocator.Error!void {
        if (c.errors.items.len < 64) try c.errors.append(c.arena, .{ .msg = msg, .start = start });
    }

    fn resolveLocal(c: *Compiler, name: []const u8) ?u16 {
        for (c.locals.items) |l| if (std.mem.eql(u8, l.name, name)) return l.slot;
        return null;
    }

    fn declareLocal(c: *Compiler, name: []const u8) Allocator.Error!?u16 {
        if (c.resolveLocal(name)) |s| return s; // redeclaration reuses the slot
        if (c.next_slot >= vm.mem_words) {
            try c.err("too many local variables", 0);
            return null;
        }
        const slot = c.next_slot;
        c.next_slot += 1;
        try c.locals.append(c.arena, .{ .name = name, .slot = slot });
        return slot;
    }

    /// Patch a previously-emitted branch's target to the current end of code.
    fn patchToHere(c: *Compiler, at: u32) void {
        c.code.items[at].arg = @intCast(c.code.items.len);
    }

    // --- expressions (postfix emit) --------------------------------------

    fn genExpr(c: *Compiler, n: NodeIndex) Allocator.Error!void {
        const node = c.ast.nodes[n];
        switch (node.tag) {
            .number => {
                const text = c.ast.tokenText(n);
                const v: f64 = if (std.mem.eql(u8, text, "true"))
                    1
                else if (std.mem.eql(u8, text, "false"))
                    0
                else
                    std.fmt.parseFloat(f64, text) catch blk: {
                        try c.err("invalid number literal", node.tok_start);
                        break :blk 0;
                    };
                _ = try c.emit(.{ .op = .push_const, .value = @floatCast(v) });
            },
            .ident => {
                const name = c.ast.tokenText(n);
                if (factOf(name)) |f| {
                    _ = try c.emit(.{ .op = .push_fact, .fact = f });
                } else if (c.resolveLocal(name)) |slot| {
                    _ = try c.emit(.{ .op = .push_const, .value = @floatFromInt(slot) });
                    _ = try c.emit(.{ .op = .load });
                } else {
                    try c.err("unknown name", node.tok_start);
                }
            },
            .neg => {
                try c.genExpr(node.a);
                _ = try c.emit(.{ .op = .neg });
            },
            .not => {
                try c.genExpr(node.a);
                _ = try c.emit(.{ .op = .not });
            },
            .add => try c.genBinary(node, .add),
            .sub => try c.genBinary(node, .sub),
            .mul => try c.genBinary(node, .mul),
            .div => try c.genBinary(node, .div),
            .lt => try c.genBinary(node, .lt),
            .gt => try c.genBinary(node, .gt),
            .eq => try c.genBinary(node, .eq),
            .le => { // a <= b  ⟺  !(a > b)
                try c.genExpr(node.a);
                try c.genExpr(node.b);
                _ = try c.emit(.{ .op = .gt });
                _ = try c.emit(.{ .op = .not });
            },
            .ge => { // a >= b  ⟺  !(a < b)
                try c.genExpr(node.a);
                try c.genExpr(node.b);
                _ = try c.emit(.{ .op = .lt });
                _ = try c.emit(.{ .op = .not });
            },
            .ne => { // a != b  ⟺  !(a == b)
                try c.genExpr(node.a);
                try c.genExpr(node.b);
                _ = try c.emit(.{ .op = .eq });
                _ = try c.emit(.{ .op = .not });
            },
            .logic_and => { // booleanize both, then min (both non-zero ⇒ 1)
                try c.genBool(node.a);
                try c.genBool(node.b);
                _ = try c.emit(.{ .op = .min });
            },
            .logic_or => {
                try c.genBool(node.a);
                try c.genBool(node.b);
                _ = try c.emit(.{ .op = .max });
            },
            .call => try c.genCall(n),
            // A string is not a value the VM computes on — it is only legal as a tag
            // argument, handled in `genCall`. Reaching it here (arithmetic, a
            // condition, a non-tag call arg) is a type error, caught for every such
            // misuse in one place.
            .string => try c.err("a text value is only valid as a tag name, e.g. has_tag(\"zig\")", node.tok_start),
            else => try c.err("cannot compile this expression", node.tok_start),
        }
    }

    fn genBinary(c: *Compiler, node: parse.Node, op: vm.Op) Allocator.Error!void {
        try c.genExpr(node.a);
        try c.genExpr(node.b);
        _ = try c.emit(.{ .op = op });
    }

    /// Emit an expression coerced to a boolean 0/1: `!!x` == `(x != 0)`.
    fn genBool(c: *Compiler, n: NodeIndex) Allocator.Error!void {
        try c.genExpr(n);
        _ = try c.emit(.{ .op = .not });
        _ = try c.emit(.{ .op = .not });
    }

    fn genCall(c: *Compiler, n: NodeIndex) Allocator.Error!void {
        const node = c.ast.nodes[n];
        const name = c.ast.tokenText(n);
        const cap = capabilityOf(name) orelse {
            try c.err("unknown function or capability", node.tok_start);
            return;
        };
        const args = c.ast.extra[node.a..node.b];
        if (args.len > 2) {
            try c.err("too many arguments (a capability takes at most 2)", node.tok_start);
            return;
        }
        // A tag-taking capability's FIRST argument is a string literal, compiled to a
        // pool index (arg0); the rest are numeric. Every other capability takes only
        // numbers, and a string among them falls through to `genExpr`'s `.string`
        // error. `call_host` always pops two operands, so pad unused slots to zero.
        if (capabilityTakesTag(cap)) {
            if (args.len == 0 or c.ast.nodes[args[0]].tag != .string) {
                try c.err("this capability needs a tag name in quotes, e.g. has_tag(\"zig\")", node.tok_start);
                return;
            }
            const idx = (try c.internString(stripQuotes(c.ast.tokenText(args[0])))) orelse return;
            _ = try c.emit(.{ .op = .push_const, .value = @floatFromInt(idx) }); // arg0 = pool index
            for (args[1..]) |arg| try c.genExpr(arg); // remaining args numeric (a string here → error)
        } else {
            for (args) |arg| try c.genExpr(arg);
        }
        var i = args.len;
        while (i < 2) : (i += 1) _ = try c.emit(.{ .op = .push_const, .value = 0 });
        _ = try c.emit(.{ .op = .call_host, .arg = @intFromEnum(cap) });
    }

    // --- statements ------------------------------------------------------

    fn genStmt(c: *Compiler, n: NodeIndex) Allocator.Error!void {
        const node = c.ast.nodes[n];
        switch (node.tag) {
            .var_decl => {
                const name = c.ast.tokenText(n);
                const slot = (try c.declareLocal(name)) orelse return;
                try c.genExpr(node.a); // init value on the stack
                _ = try c.emit(.{ .op = .push_const, .value = @floatFromInt(slot) });
                _ = try c.emit(.{ .op = .store }); // store pops idx (top) then value
            },
            .assign => {
                const name = c.ast.tokenText(n);
                const slot = c.resolveLocal(name) orelse {
                    try c.err("assignment to an undeclared variable", node.tok_start);
                    return;
                };
                try c.genExpr(node.a);
                _ = try c.emit(.{ .op = .push_const, .value = @floatFromInt(slot) });
                _ = try c.emit(.{ .op = .store });
            },
            .if_stmt => {
                try c.genExpr(node.a); // condition
                const jz = try c.emit(.{ .op = .jump_if_zero }); // skip THEN when 0
                try c.genBlockOrStmt(node.b);
                if (node.c != parse.none) {
                    const jend = try c.emit(.{ .op = .jump }); // skip ELSE after THEN
                    c.patchToHere(jz); // ELSE starts here
                    try c.genBlockOrStmt(node.c);
                    c.patchToHere(jend); // END here
                } else {
                    c.patchToHere(jz); // no ELSE: 0 lands past THEN
                }
            },
            .while_stmt => {
                const loop_head: u16 = @intCast(c.code.items.len);
                try c.genExpr(node.a); // condition
                const jz = try c.emit(.{ .op = .jump_if_zero }); // exit when 0
                try c.genBlockOrStmt(node.b);
                _ = try c.emit(.{ .op = .jump, .arg = loop_head }); // back to the head
                c.patchToHere(jz); // exit here
            },
            .return_stmt => {
                if (node.a != parse.none) {
                    try c.genExpr(node.a);
                } else {
                    _ = try c.emit(.{ .op = .push_fact, .fact = .base_score }); // bare return ⇒ base
                }
                _ = try c.emit(.{ .op = .halt });
            },
            .expr_stmt => {
                try c.genExpr(node.a);
                _ = try c.emit(.{ .op = .pop }); // a statement expression's value is discarded
            },
            .block => try c.genBlock(n),
            else => try c.err("cannot compile this statement", node.tok_start),
        }
    }

    fn genBlock(c: *Compiler, n: NodeIndex) Allocator.Error!void {
        const node = c.ast.nodes[n];
        for (c.ast.extra[node.a..node.b]) |s| try c.genStmt(s);
    }

    fn genBlockOrStmt(c: *Compiler, n: NodeIndex) Allocator.Error!void {
        if (n == parse.none) return;
        if (c.ast.nodes[n].tag == .block) return c.genBlock(n) else return c.genStmt(n);
    }

    /// Compile ONE named function's body into a fresh bytecode slice, or null if no
    /// such function exists. The code + locals reset per entry, but the STRING POOL
    /// persists across entries of the same program — so a program's `score()` and
    /// `retrieve()` share one tag-constant pool and their `push_const(index)` indices
    /// agree with it (`compileArtifact`). Errors accumulate on the shared list.
    fn compileEntry(c: *Compiler, entry_name: []const u8) Allocator.Error!?[]const Instr {
        var entry: ?NodeIndex = null;
        for (c.ast.top) |f| {
            if (std.mem.eql(u8, c.ast.tokenText(f), entry_name)) entry = f;
        }
        if (entry == null) return null;
        c.code.clearRetainingCapacity();
        c.locals.clearRetainingCapacity();
        c.next_slot = 0;
        try c.genBlock(c.ast.nodes[entry.?].c); // the function body block
        // Fall-off-the-end ⇒ the engine's base score, so a value is always defined.
        _ = try c.emit(.{ .op = .push_fact, .fact = .base_score });
        _ = try c.emit(.{ .op = .halt });
        return try c.code.toOwnedSlice(c.arena);
    }
};

/// Compile the `entry_name` function of a parsed program into `guest_vm` bytecode
/// (PURE over `(arena, ast)`). Returns the emitted program, or errors — a program
/// with ANY error (parse or compile) yields an empty program (fail-closed). The
/// CALLER validates the result with `guest_vm.validProgram` before running it (the
/// untrusted-compiler / trusted-validator split). Only OOM propagates.
pub fn compile(arena: Allocator, ast: *const Ast, entry_name: []const u8) Allocator.Error!Result {
    // Refuse to compile a program that did not parse cleanly.
    if (!ast.ok()) {
        const es = try arena.alloc(Error, ast.errors.len);
        for (es, ast.errors) |*d, s| d.* = .{ .msg = s.msg, .start = s.start };
        return .{ .program = &.{}, .errors = es };
    }

    var c: Compiler = .{ .arena = arena, .ast = ast };
    const prog = (try c.compileEntry(entry_name)) orelse {
        try c.err("no such function", 0);
        return .{ .program = &.{}, .errors = try c.errors.toOwnedSlice(arena) };
    };
    if (c.errors.items.len > 0) {
        return .{ .program = &.{}, .errors = try c.errors.toOwnedSlice(arena) };
    }
    return .{
        .program = prog,
        .strings = try c.strings.toOwnedSlice(arena),
        .errors = &.{},
    };
}

/// A whole guest ARTIFACT: a program's entry points compiled together, sharing ONE
/// tag-constant pool. `score` is required (a feed IS a scoring function); `retrieve`
/// is optional (empty when the program has no `retrieve()`). Fail-closed: any error
/// yields empty programs. A7.2: cold, waived.
pub const Artifact = struct {
    score: []const Instr,
    retrieve: []const Instr = &.{},
    strings: []const []const u8 = &.{},
    errors: []const Error,
    pub fn ok(self: Artifact) bool {
        return self.errors.len == 0;
    }
};

/// Compile a parsed program's `score()` (required) and `retrieve()` (optional) into
/// one artifact with a SHARED tag pool (PURE over `(arena, ast)`). This is the
/// artifact the developer tier publishes and runs: `score` ranks each candidate,
/// `retrieve` composes the pool, and both index the same `strings`. Fail-closed —
/// any parse or compile error yields empty programs (the caller re-validates each
/// with `guest_vm.validProgram`, the untrusted-compiler / trusted-validator split).
pub fn compileArtifact(arena: Allocator, ast: *const Ast) Allocator.Error!Artifact {
    if (!ast.ok()) {
        const es = try arena.alloc(Error, ast.errors.len);
        for (es, ast.errors) |*d, s| d.* = .{ .msg = s.msg, .start = s.start };
        return .{ .score = &.{}, .errors = es };
    }
    var c: Compiler = .{ .arena = arena, .ast = ast };
    const score_prog = (try c.compileEntry("score")) orelse {
        try c.err("a feed algorithm needs a score() function", 0);
        return .{ .score = &.{}, .errors = try c.errors.toOwnedSlice(arena) };
    };
    // retrieve() is optional; absent ⇒ the declarative query.sources are used.
    const retrieve_prog: []const Instr = (try c.compileEntry("retrieve")) orelse &.{};
    if (c.errors.items.len > 0) {
        return .{ .score = &.{}, .errors = try c.errors.toOwnedSlice(arena) };
    }
    return .{
        .score = score_prog,
        .retrieve = retrieve_prog,
        .strings = try c.strings.toOwnedSlice(arena),
        .errors = &.{},
    };
}

/// Does this compiled program read the user's PRIVATE attention data? The
/// capability-DERIVED privacy label for guest CODE (invariant 6). Delegates to
/// `guest_vm.usesBehavioral` — the single source of truth for scanning a program's
/// capability set — so the compiler and the transparency layer can never disagree.
pub fn usesBehavioral(program: []const Instr) bool {
    return vm.usesBehavioral(program);
}

// ---------------------------------------------------------------------------
// Tests — pure (B2), arena + leak-checked. The whole point: Zal source RUNS.
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

/// Compile a snippet's `score` fn and run it — the end-to-end path.
fn runSource(arena: Allocator, src: []const u8, base: f64) !f64 {
    const ast = try parse.parse(arena, src);
    const res = try compile(arena, &ast, "score");
    try t.expect(res.ok());
    try t.expect(vm.validProgram(res.program)); // the trusted validator accepts it
    return vm.run(res.program, sample, base, vm.default_fuel, null);
}

test "compile+run: arithmetic and facts — the loop closes" {
    var a = std.heap.ArenaAllocator.init(t.allocator);
    defer a.deinit();
    // base(10) × 1.5 + reply_count(30) × 2 = 15 + 60 = 75
    const r = try runSource(a.allocator(), "fn score() num { return base_score * 1.5 + reply_count * 2.0; }", 10.0);
    try t.expectEqual(@as(f64, 75.0), r);
}

test "compile+run: locals + an if branch" {
    var a = std.heap.ArenaAllocator.init(t.allocator);
    defer a.deinit();
    const src =
        \\fn score() num {
        \\  var s = base_score;
        \\  if (in_network) { s = s * 2.0; } else { s = s + 1.0; }
        \\  return s;
        \\}
    ;
    // in_network is true ⇒ 10 × 2 = 20
    try t.expectEqual(@as(f64, 20.0), try runSource(a.allocator(), src, 10.0));
}

test "compile+run: a while loop (halving) computes a real result" {
    var a = std.heap.ArenaAllocator.init(t.allocator);
    defer a.deinit();
    const src =
        \\fn score() num {
        \\  var s = base_score;
        \\  while (s > 100.0) { s = s / 2.0; }
        \\  return s;
        \\}
    ;
    // 800 → 400 → 200 → 100 (stops when not > 100). Result 100.
    try t.expectEqual(@as(f64, 100.0), try runSource(a.allocator(), src, 800.0));
}

test "compile+run: comparison + logical operators via the added eq/not ops" {
    var a = std.heap.ArenaAllocator.init(t.allocator);
    defer a.deinit();
    // (like_count == 100) && (age_hrs <= 5) → true && true → 1
    const r = try runSource(a.allocator(), "fn score() num { return (like_count == 100.0) && (age_hrs <= 5.0); }", 0);
    try t.expectEqual(@as(f64, 1.0), r);
}

test "compile+run: the new public signals (viewer_engaged, tag_count) are readable" {
    var a = std.heap.ArenaAllocator.init(t.allocator);
    defer a.deinit();
    const arena = a.allocator();
    // "reward tags; halve the score if you already engaged this post (freshness)."
    const src = "fn score() num { var s = like_count + tag_count * 5.0; if (viewer_engaged) { s = s / 2.0; } return s; }";
    const ast = try parse.parse(arena, src);
    const res = try compile(arena, &ast, "score");
    try t.expect(res.ok());

    var fresh = sample;
    fresh.viewer_engaged = false;
    fresh.tag_count = 2; // 100 + 2*5 = 110
    var seen = sample;
    seen.viewer_engaged = true;
    seen.tag_count = 2; // (100 + 10) / 2 = 55
    const s_fresh = vm.run(res.program, fresh, 0, vm.default_fuel, null);
    const s_seen = vm.run(res.program, seen, 0, vm.default_fuel, null);
    try t.expectEqual(@as(f64, 110.0), s_fresh);
    try t.expect(s_fresh > s_seen); // an already-engaged post is down-ranked
}

test "compile+run: has_tag compiles to a pooled tag index + a host call" {
    var a = std.heap.ArenaAllocator.init(t.allocator);
    defer a.deinit();
    const arena = a.allocator();
    // "double the score for posts in the zig zone."
    const src = "fn score() num { if (has_tag(\"zig\")) { return like_count * 2.0; } return like_count; }";
    const ast = try parse.parse(arena, src);
    const res = try compile(arena, &ast, "score");
    try t.expect(res.ok());
    // The literal was interned into the read-only pool (not a VM value).
    try t.expectEqual(@as(usize, 1), res.strings.len);
    try t.expectEqualStrings("zig", res.strings[0]);

    // A host that reports "this candidate carries pool tag #0" (the zig index).
    const H = struct {
        fn call(ctx: *anyopaque, cap: guest_abi.Capability, a0: f64, a1: f64) f64 {
            _ = ctx;
            _ = a1;
            return if (cap == .has_tag and a0 == 0) 1 else 0;
        }
    };
    var ctx: u8 = 0;
    const host = vm.Host{ .ctx = &ctx, .call = H.call };
    try t.expectEqual(@as(f64, 200.0), vm.run(res.program, sample, 0, vm.default_fuel, &host)); // tagged → doubled
    try t.expectEqual(@as(f64, 100.0), vm.run(res.program, sample, 0, vm.default_fuel, null)); // no host → untagged branch
}

test "compileArtifact: score and retrieve compile together, sharing one tag pool" {
    var a = std.heap.ArenaAllocator.init(t.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const src =
        \\fn score() num { if (has_tag("zig")) { return 2.0; } return 1.0; }
        \\fn retrieve() num { tag_scope("rust", 1.0); return 0.0; }
    ;
    const ast = try parse.parse(arena, src);
    const art = try compileArtifact(arena, &ast);
    try t.expect(art.ok());
    try t.expect(art.score.len > 0);
    try t.expect(art.retrieve.len > 0);
    // Both literals share ONE pool — score compiles first (zig → 0), then retrieve
    // (rust → 1) — so each program's push_const index agrees with `strings`.
    try t.expectEqual(@as(usize, 2), art.strings.len);
    try t.expectEqualStrings("zig", art.strings[0]);
    try t.expectEqualStrings("rust", art.strings[1]);
    // A program with no retrieve() is valid — score alone, empty retrieve.
    const ast2 = try parse.parse(arena, "fn score() num { return like_count; }");
    const art2 = try compileArtifact(arena, &ast2);
    try t.expect(art2.ok());
    try t.expectEqual(@as(usize, 0), art2.retrieve.len);
    // Missing score() is an error (a feed IS a scoring function).
    const ast3 = try parse.parse(arena, "fn retrieve() num { return 0.0; }");
    const art3 = try compileArtifact(arena, &ast3);
    try t.expect(!art3.ok());
}

test "compile: a text literal is rejected outside a tag argument (type discipline, fail-closed)" {
    var a = std.heap.ArenaAllocator.init(t.allocator);
    defer a.deinit();
    const arena = a.allocator();
    // A string in arithmetic.
    const r1 = try compile(arena, &(try parse.parse(arena, "fn score() num { return like_count + \"zig\"; }")), "score");
    try t.expect(!r1.ok());
    try t.expectEqual(@as(usize, 0), r1.program.len);
    // A string to a NON-tag capability.
    const r2 = try compile(arena, &(try parse.parse(arena, "fn score() num { follows(\"zig\"); return base_score; }")), "score");
    try t.expect(!r2.ok());
    // A number where a tag capability needs a tag name.
    const r3 = try compile(arena, &(try parse.parse(arena, "fn score() num { if (has_tag(5)) { return 1.0; } return base_score; }")), "score");
    try t.expect(!r3.ok());
}

test "compile+run: the thread-structure signals (reply_chain, quote_count) are readable" {
    var a = std.heap.ArenaAllocator.init(t.allocator);
    defer a.deinit();
    const arena = a.allocator();
    // "reward posts the author stayed in (self-replies) and posts others amplified."
    const src = "fn score() num { return like_count + reply_chain * 150.0 + quote_count * 3.0; }";
    const ast = try parse.parse(arena, src);
    const res = try compile(arena, &ast, "score");
    try t.expect(res.ok());

    const plain = sample; // 100 + 0 + 0 = 100
    var active = sample;
    active.reply_chain = 2; // author replied back twice
    active.quote_count = 4; // 100 + 2*150 + 4*3 = 412
    const s_plain = vm.run(res.program, plain, 0, vm.default_fuel, null);
    const s_active = vm.run(res.program, active, 0, vm.default_fuel, null);
    try t.expectEqual(@as(f64, 100.0), s_plain);
    try t.expectEqual(@as(f64, 412.0), s_active);
    try t.expect(s_active > s_plain); // author-active, amplified posts rank higher
}

test "compile: unknown name and undeclared assignment are clean errors, no bytecode" {
    var a = std.heap.ArenaAllocator.init(t.allocator);
    defer a.deinit();
    const arena = a.allocator();

    const ast1 = try parse.parse(arena, "fn score() num { return nonsense_name + 1.0; }");
    const r1 = try compile(arena, &ast1, "score");
    try t.expect(!r1.ok());
    try t.expectEqual(@as(usize, 0), r1.program.len); // fail-closed

    const ast2 = try parse.parse(arena, "fn score() num { undeclared = 5.0; return base_score; }");
    const r2 = try compile(arena, &ast2, "score");
    try t.expect(!r2.ok());

    // A missing entry function is an error, not a crash.
    const ast3 = try parse.parse(arena, "fn other() num { return 1.0; }");
    const r3 = try compile(arena, &ast3, "score");
    try t.expect(!r3.ok());
}

test "compile: a parse error refuses codegen (fail-closed)" {
    var a = std.heap.ArenaAllocator.init(t.allocator);
    defer a.deinit();
    const arena = a.allocator();
    const ast = try parse.parse(arena, "fn score( { return + ; ");
    const r = try compile(arena, &ast, "score");
    try t.expect(!r.ok());
    try t.expectEqual(@as(usize, 0), r.program.len);
}
