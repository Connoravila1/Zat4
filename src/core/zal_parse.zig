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

//! B1 classification: CORE (pure over `(arena, source)`). **GUEST TIER — Phase 3:
//! Zal, the parser.** See `GUEST_TIER_ROADMAP.md`.
//!
//! Turns the lexer's token stream into an ABSTRACT SYNTAX TREE, then type-check
//! (next slice) and codegen (after) turn the tree into `guest_vm` bytecode. The AST
//! is a FLAT node array with `u32` child INDEXES (A4 — no pointers between nodes;
//! index 0 is the reserved `none` sentinel), so it is plain data that lives in one
//! arena and is discarded after codegen.
//!
//! Recursive descent with precedence climbing (the standard, readable shape for a
//! C-like grammar). It is TOTAL and RECOVERING: malformed input never crashes and
//! never loops — every statement/toplevel loop is guaranteed to consume at least
//! one token per iteration, and recursion depth is capped (a `((((…` bomb is a
//! clean error, not a stack overflow). Errors are COLLECTED (not thrown), so one
//! mistake doesn't abort the parse; the compiler reports them and refuses to emit
//! bytecode. Only OOM propagates.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const lex = @import("zal_lex.zig");

/// A node index into `Ast.nodes`. Index 0 is the reserved NONE sentinel (an absent
/// child — e.g. a `return;` with no value, or an `if` with no `else`).
pub const NodeIndex = u32;
pub const none: NodeIndex = 0;

/// The AST node tags. Operators get one tag EACH (rather than a shared `binary`
/// tag + a stored operator) so codegen is a single flat switch straight to a
/// bytecode op — the same "exhaustive switch = completeness" discipline the VM and
/// transparency use. Per-tag child meaning is documented on `Node`.
pub const Tag = enum(u8) {
    none, // the index-0 sentinel; never a real node
    // --- expressions ---
    number, // literal; value parsed from the token span
    string, // "quoted" tag literal; only valid as a tag argument (compiler enforces)
    ident, // a name (fact / local / capability), resolved at type-check
    neg, // unary -a           (a = operand)
    not, // unary !a           (a = operand)
    add,
    sub,
    mul,
    div, // binary a?b         (a = lhs, b = rhs)
    lt,
    gt,
    le,
    ge,
    eq,
    ne,
    logic_and,
    logic_or,
    call, // f(args)            (name = tok span; a..b = arg node range in `extra`)
    // --- statements ---
    var_decl, // var name = e;   (name = tok span; a = init expr)
    assign, // name = e;         (name = tok span; a = value expr)
    if_stmt, // if(c){}else{}    (a = cond, b = then-block, c = else-block or none)
    while_stmt, // while(c){}    (a = cond, b = body-block)
    return_stmt, // return e?;   (a = expr or none)
    expr_stmt, // e;             (a = expr)
    block, // { stmts }          (a..b = statement node range in `extra`)
    // --- top level ---
    fn_decl, // fn name(params) ret { body }  (name = tok span; a..b = param range
    //                                          in `extra`; c = body-block)

    comptime {
        assert(@typeInfo(Tag).@"enum".fields.len == 27);
    }
};

/// One AST node. Up to three child indexes (`a`/`b`/`c`) plus a source-token SPAN
/// (`tok_start`/`tok_len`) for named/literal nodes. List-bearing nodes (`block`,
/// `call`, `fn_decl` params) store their children as a half-open range `[a, b)`
/// into `Ast.extra`. A7.2: transient compile-time structure — an AST exists per
/// compile and is discarded after codegen, never in a hot runtime loop. Size guard
/// kept anyway (cheap; catches field creep in the node the whole tree is made of).
pub const Node = struct {
    tag: Tag,
    a: NodeIndex = none,
    b: NodeIndex = none,
    c: NodeIndex = none,
    tok_start: u32 = 0,
    tok_len: u32 = 0,

    comptime {
        // tag (1) + 5×u32 (20) = 21, padded to 24 at the u32 alignment. Exact.
        assert(@sizeOf(Node) == 24);
    }
};

/// One parse diagnostic: a human message and where in the source it occurred.
/// A7.2: cold — collected in small numbers, shown to the author, never hot.
pub const Error = struct {
    msg: []const u8,
    start: u32,
};

/// The parsed program. `nodes[0]` is the NONE sentinel. `top` lists the top-level
/// `fn_decl` node indices in source order. `errors` is empty iff the parse was
/// clean; a program with errors must NOT be compiled (codegen refuses). All slices
/// live in the caller's arena. A7.2: cold result, size guard waived.
pub const Ast = struct {
    source: []const u8,
    nodes: []const Node,
    extra: []const NodeIndex,
    top: []const NodeIndex,
    errors: []const Error,

    pub fn ok(self: Ast) bool {
        return self.errors.len == 0;
    }
    /// The source text a node spans (for names / number literals).
    pub fn tokenText(self: Ast, n: NodeIndex) []const u8 {
        const node = self.nodes[n];
        return self.source[node.tok_start .. node.tok_start + node.tok_len];
    }
};

/// The recursion-depth ceiling — a hostile `((((((…` or deeply nested block must be
/// a clean error, not a stack overflow (totality on adversarial input).
const max_depth: u32 = 128;

// A7.2: cold — exactly one instance per compile, holds the parse state; waived.
const Parser = struct {
    arena: Allocator,
    src: []const u8,
    lx: lex.Lexer,
    tok: lex.Token, // one-token lookahead (the current token)
    nodes: std.ArrayListUnmanaged(Node) = .empty,
    extra: std.ArrayListUnmanaged(NodeIndex) = .empty,
    errors: std.ArrayListUnmanaged(Error) = .empty,
    depth: u32 = 0,

    fn advance(p: *Parser) void {
        p.tok = p.lx.next();
    }

    fn addNode(p: *Parser, node: Node) Allocator.Error!NodeIndex {
        const idx: NodeIndex = @intCast(p.nodes.items.len);
        try p.nodes.append(p.arena, node);
        return idx;
    }

    fn addError(p: *Parser, msg: []const u8) Allocator.Error!void {
        // Cap the error list so a pathological input can't grow it without bound.
        if (p.errors.items.len < 64) try p.errors.append(p.arena, .{ .msg = msg, .start = p.tok.start });
    }

    /// Consume the current token if it matches; otherwise record an error (no
    /// advance — the caller's recovery decides how to proceed).
    fn expect(p: *Parser, kind: lex.Kind, msg: []const u8) Allocator.Error!bool {
        if (p.tok.kind == kind) {
            p.advance();
            return true;
        }
        try p.addError(msg);
        return false;
    }

    fn span(tok: lex.Token) struct { start: u32, len: u32 } {
        return .{ .start = tok.start, .len = tok.len };
    }

    // --- top level -------------------------------------------------------

    fn parseProgram(p: *Parser) Allocator.Error![]const NodeIndex {
        var top: std.ArrayListUnmanaged(NodeIndex) = .empty;
        while (p.tok.kind != .eof) {
            const before = p.tok.start;
            if (p.tok.kind == .kw_fn) {
                const f = try p.parseFn();
                if (f != none) try top.append(p.arena, f);
            } else {
                try p.addError("expected a function declaration");
            }
            // GUARANTEE PROGRESS: if nothing consumed a token this round (an error
            // path), force one forward so the loop can never spin (totality).
            if (p.tok.start == before and p.tok.kind != .eof) p.advance();
        }
        return top.toOwnedSlice(p.arena);
    }

    fn parseFn(p: *Parser) Allocator.Error!NodeIndex {
        p.advance(); // 'fn'
        const name = p.tok;
        _ = try p.expect(.identifier, "expected a function name after 'fn'");
        _ = try p.expect(.lparen, "expected '(' after the function name");
        // Parameters: comma-separated identifiers until ')'.
        const params_start: NodeIndex = @intCast(p.extra.items.len);
        while (p.tok.kind != .rparen and p.tok.kind != .eof) {
            if (p.tok.kind == .identifier) {
                const pnode = try p.addNode(.{ .tag = .ident, .tok_start = p.tok.start, .tok_len = p.tok.len });
                try p.extra.append(p.arena, pnode);
                p.advance();
                if (p.tok.kind == .comma) p.advance() else break;
            } else break;
        }
        const params_end: NodeIndex = @intCast(p.extra.items.len);
        _ = try p.expect(.rparen, "expected ')' after the parameters");
        // Optional return type: a single identifier (one numeric type; ignored).
        if (p.tok.kind == .identifier) p.advance();
        const body = try p.parseBlock();
        return p.addNode(.{
            .tag = .fn_decl,
            .a = params_start,
            .b = params_end,
            .c = body,
            .tok_start = name.start,
            .tok_len = name.len,
        });
    }

    fn parseBlock(p: *Parser) Allocator.Error!NodeIndex {
        if (!try p.expect(.lbrace, "expected '{'")) {
            // No brace — return an empty block so the caller can continue.
            return p.addNode(.{ .tag = .block });
        }
        var stmts: std.ArrayListUnmanaged(NodeIndex) = .empty;
        while (p.tok.kind != .rbrace and p.tok.kind != .eof) {
            const before = p.tok.start;
            const s = try p.parseStmt();
            if (s != none) try stmts.append(p.arena, s);
            if (p.tok.start == before and p.tok.kind != .rbrace and p.tok.kind != .eof) p.advance(); // progress
        }
        _ = try p.expect(.rbrace, "expected '}' to close the block");
        const start: NodeIndex = @intCast(p.extra.items.len);
        try p.extra.appendSlice(p.arena, stmts.items);
        const end: NodeIndex = @intCast(p.extra.items.len);
        return p.addNode(.{ .tag = .block, .a = start, .b = end });
    }

    // --- statements ------------------------------------------------------

    fn parseStmt(p: *Parser) Allocator.Error!NodeIndex {
        switch (p.tok.kind) {
            .kw_var => return p.parseVarDecl(),
            .kw_if => return p.parseIf(),
            .kw_while => return p.parseWhile(),
            .kw_return => return p.parseReturn(),
            .lbrace => return p.parseBlock(),
            else => {
                // An expression statement OR an assignment. Parse an expression; if
                // it is a bare identifier followed by '=', it's an assignment (a
                // one-token lookahead suffices because '=' is not an expr operator).
                const e = try p.parseExpr();
                if (p.tok.kind == .assign and e != none and p.nodes.items[e].tag == .ident) {
                    const target = p.nodes.items[e];
                    p.advance(); // '='
                    const rhs = try p.parseExpr();
                    _ = try p.expect(.semicolon, "expected ';' after the assignment");
                    return p.addNode(.{ .tag = .assign, .a = rhs, .tok_start = target.tok_start, .tok_len = target.tok_len });
                }
                _ = try p.expect(.semicolon, "expected ';' after the expression");
                return p.addNode(.{ .tag = .expr_stmt, .a = e });
            },
        }
    }

    fn parseVarDecl(p: *Parser) Allocator.Error!NodeIndex {
        p.advance(); // 'var'
        const name = p.tok;
        _ = try p.expect(.identifier, "expected a variable name after 'var'");
        _ = try p.expect(.assign, "expected '=' in the variable declaration");
        const init_expr = try p.parseExpr();
        _ = try p.expect(.semicolon, "expected ';' after the declaration");
        return p.addNode(.{ .tag = .var_decl, .a = init_expr, .tok_start = name.start, .tok_len = name.len });
    }

    fn parseIf(p: *Parser) Allocator.Error!NodeIndex {
        p.advance(); // 'if'
        _ = try p.expect(.lparen, "expected '(' after 'if'");
        const cond = try p.parseExpr();
        _ = try p.expect(.rparen, "expected ')' after the condition");
        const then_block = try p.parseBlock();
        var else_block: NodeIndex = none;
        if (p.tok.kind == .kw_else) {
            p.advance();
            // `else if` chains as an else-block containing a single if.
            else_block = if (p.tok.kind == .kw_if) try p.parseIf() else try p.parseBlock();
        }
        return p.addNode(.{ .tag = .if_stmt, .a = cond, .b = then_block, .c = else_block });
    }

    fn parseWhile(p: *Parser) Allocator.Error!NodeIndex {
        p.advance(); // 'while'
        _ = try p.expect(.lparen, "expected '(' after 'while'");
        const cond = try p.parseExpr();
        _ = try p.expect(.rparen, "expected ')' after the condition");
        const body = try p.parseBlock();
        return p.addNode(.{ .tag = .while_stmt, .a = cond, .b = body });
    }

    fn parseReturn(p: *Parser) Allocator.Error!NodeIndex {
        p.advance(); // 'return'
        var e: NodeIndex = none;
        if (p.tok.kind != .semicolon) e = try p.parseExpr();
        _ = try p.expect(.semicolon, "expected ';' after 'return'");
        return p.addNode(.{ .tag = .return_stmt, .a = e });
    }

    // --- expressions (precedence climbing) -------------------------------
    // or < and < equality < comparison < additive < multiplicative < unary < primary

    fn parseExpr(p: *Parser) Allocator.Error!NodeIndex {
        if (p.depth >= max_depth) {
            try p.addError("expression nested too deeply");
            return none;
        }
        p.depth += 1;
        defer p.depth -= 1;
        return p.parseOr();
    }

    fn binaryLevel(
        p: *Parser,
        next: *const fn (*Parser) Allocator.Error!NodeIndex,
        comptime ops: []const struct { k: lex.Kind, tag: Tag },
    ) Allocator.Error!NodeIndex {
        var lhs = try next(p);
        outer: while (true) {
            inline for (ops) |o| {
                if (p.tok.kind == o.k) {
                    p.advance();
                    const rhs = try next(p);
                    lhs = try p.addNode(.{ .tag = o.tag, .a = lhs, .b = rhs });
                    continue :outer;
                }
            }
            break;
        }
        return lhs;
    }

    fn parseOr(p: *Parser) Allocator.Error!NodeIndex {
        return p.binaryLevel(parseAnd, &.{.{ .k = .or_or, .tag = .logic_or }});
    }
    fn parseAnd(p: *Parser) Allocator.Error!NodeIndex {
        return p.binaryLevel(parseEquality, &.{.{ .k = .and_and, .tag = .logic_and }});
    }
    fn parseEquality(p: *Parser) Allocator.Error!NodeIndex {
        return p.binaryLevel(parseComparison, &.{ .{ .k = .eq, .tag = .eq }, .{ .k = .ne, .tag = .ne } });
    }
    fn parseComparison(p: *Parser) Allocator.Error!NodeIndex {
        return p.binaryLevel(parseAdd, &.{
            .{ .k = .lt, .tag = .lt }, .{ .k = .gt, .tag = .gt },
            .{ .k = .le, .tag = .le }, .{ .k = .ge, .tag = .ge },
        });
    }
    fn parseAdd(p: *Parser) Allocator.Error!NodeIndex {
        return p.binaryLevel(parseMul, &.{ .{ .k = .plus, .tag = .add }, .{ .k = .minus, .tag = .sub } });
    }
    fn parseMul(p: *Parser) Allocator.Error!NodeIndex {
        return p.binaryLevel(parseUnary, &.{ .{ .k = .star, .tag = .mul }, .{ .k = .slash, .tag = .div } });
    }

    fn parseUnary(p: *Parser) Allocator.Error!NodeIndex {
        if (p.tok.kind == .minus or p.tok.kind == .bang) {
            const is_neg = p.tok.kind == .minus;
            p.advance();
            const operand = try p.parseUnary();
            return p.addNode(.{ .tag = if (is_neg) .neg else .not, .a = operand });
        }
        return p.parsePrimary();
    }

    fn parsePrimary(p: *Parser) Allocator.Error!NodeIndex {
        switch (p.tok.kind) {
            .number => {
                const n = try p.addNode(.{ .tag = .number, .tok_start = p.tok.start, .tok_len = p.tok.len });
                p.advance();
                return n;
            },
            .kw_true, .kw_false => {
                // true/false are the numbers 1/0; keep the token span for the value.
                const n = try p.addNode(.{ .tag = .number, .tok_start = p.tok.start, .tok_len = p.tok.len });
                p.advance();
                return n;
            },
            .string => {
                // A tag literal; the token span includes the quotes (the compiler
                // strips them). Only meaningful as a tag argument — the compiler
                // rejects it anywhere else, so no type is attached here.
                const n = try p.addNode(.{ .tag = .string, .tok_start = p.tok.start, .tok_len = p.tok.len });
                p.advance();
                return n;
            },
            .identifier => {
                const name = p.tok;
                p.advance();
                if (p.tok.kind == .lparen) return p.parseCall(name);
                return p.addNode(.{ .tag = .ident, .tok_start = name.start, .tok_len = name.len });
            },
            .lparen => {
                p.advance();
                const e = try p.parseExpr();
                _ = try p.expect(.rparen, "expected ')'");
                return e;
            },
            else => {
                try p.addError("expected an expression");
                return none;
            },
        }
    }

    fn parseCall(p: *Parser, name: lex.Token) Allocator.Error!NodeIndex {
        p.advance(); // '('
        const args_start: NodeIndex = @intCast(p.extra.items.len);
        while (p.tok.kind != .rparen and p.tok.kind != .eof) {
            const before = p.tok.start;
            const arg = try p.parseExpr();
            try p.extra.append(p.arena, arg);
            if (p.tok.kind == .comma) p.advance() else break;
            if (p.tok.start == before) p.advance(); // progress guard
        }
        const args_end: NodeIndex = @intCast(p.extra.items.len);
        _ = try p.expect(.rparen, "expected ')' to close the call");
        return p.addNode(.{ .tag = .call, .a = args_start, .b = args_end, .tok_start = name.start, .tok_len = name.len });
    }
};

/// Parse a Zal program into an `Ast` (PURE over `(arena, src)`). Never crashes and
/// never loops: errors are collected and the parse always terminates. Only OOM
/// propagates. Check `ast.ok()` before compiling.
pub fn parse(arena: Allocator, src: []const u8) Allocator.Error!Ast {
    var p: Parser = .{ .arena = arena, .src = src, .lx = lex.Lexer.init(src), .tok = undefined };
    try p.nodes.append(arena, .{ .tag = .none }); // index 0 = the NONE sentinel
    p.advance(); // prime the first token
    const top = try p.parseProgram();
    return .{
        .source = src,
        .nodes = p.nodes.items,
        .extra = p.extra.items,
        .top = top,
        .errors = p.errors.items,
    };
}

// ---------------------------------------------------------------------------
// Tests — pure (B2), arena-allocated, leak-checked. Structure + totality.
// ---------------------------------------------------------------------------

const t = std.testing;

test "guards + tag count" {
    try t.expectEqual(@as(usize, 24), @sizeOf(Node));
    try t.expectEqual(@as(usize, 27), @typeInfo(Tag).@"enum".fields.len);
}

test "parse: a whole function builds a clean AST" {
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const src =
        \\fn score() num {
        \\  var s = base_score;
        \\  if (in_network) { s = s * 1.5; } else { s = s + 1.0; }
        \\  while (s > 100.0) { s = s / 2.0; }
        \\  return s + reply_count * 2.0;
        \\}
    ;
    const ast = try parse(arena, src);
    try t.expect(ast.ok()); // no errors
    try t.expectEqual(@as(usize, 1), ast.top.len); // one function
    const fnode = ast.nodes[ast.top[0]];
    try t.expectEqual(Tag.fn_decl, fnode.tag);
    try t.expectEqualStrings("score", ast.tokenText(ast.top[0]));
    // Its body is a block with four statements (var, if, while, return).
    const body = ast.nodes[fnode.c];
    try t.expectEqual(Tag.block, body.tag);
    try t.expectEqual(@as(usize, 4), body.b - body.a);
    // The first statement is `var s = base_score;`.
    const first = ast.extra[body.a];
    try t.expectEqual(Tag.var_decl, ast.nodes[first].tag);
    try t.expectEqualStrings("s", ast.tokenText(first));
}

test "parse: operator precedence — a + b * c groups the multiply first" {
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const ast = try parse(arena, "fn f() num { return a + b * c; }");
    try t.expect(ast.ok());
    const body = ast.nodes[ast.nodes[ast.top[0]].c];
    const ret = ast.nodes[ast.extra[body.a]];
    try t.expectEqual(Tag.return_stmt, ret.tag);
    const sum = ast.nodes[ret.a];
    try t.expectEqual(Tag.add, sum.tag); // top is the add …
    try t.expectEqual(Tag.ident, ast.nodes[sum.a].tag); // lhs = a
    try t.expectEqual(Tag.mul, ast.nodes[sum.b].tag); // rhs = (b * c), the tighter bind
}

test "parse: a call with arguments" {
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const ast = try parse(arena, "fn f() num { return trending(100.0, 2.0); }");
    try t.expect(ast.ok());
    const body = ast.nodes[ast.nodes[ast.top[0]].c];
    const ret = ast.nodes[ast.extra[body.a]];
    const calln = ast.nodes[ret.a];
    try t.expectEqual(Tag.call, calln.tag);
    try t.expectEqualStrings("trending", ast.tokenText(ret.a));
    try t.expectEqual(@as(usize, 2), calln.b - calln.a); // two arguments
}

test "parse: malformed input yields errors, never a crash or hang" {
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Missing brace, stray operators, unterminated call — all recover to errors.
    const ast = try parse(arena, "fn f( { return + * ; trending(,,, ");
    try t.expect(!ast.ok()); // errors recorded
    try t.expect(ast.errors.len > 0);
}

test "parse: a deeply nested expression is a clean error, not a stack overflow" {
    var arena_state = std.heap.ArenaAllocator.init(t.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(t.allocator);
    try buf.appendSlice(t.allocator, "fn f() num { return ");
    for (0..1000) |_| try buf.append(t.allocator, '(');
    try buf.appendSlice(t.allocator, "1");
    const ast = try parse(arena, buf.items);
    try t.expect(!ast.ok()); // depth cap tripped → error, and it TERMINATED
}
