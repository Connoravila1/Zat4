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

//! B1 classification: CORE (pure). **GUEST TIER — Phase 3: Zal, the lexer.** See
//! `GUEST_TIER_ROADMAP.md`.
//!
//! Zal ("Zat4 Algorithm Language", working name) is the C-like language a
//! developer-tier creator authors in; the compiler (this slice: the lexer)
//! translates it to `guest_vm` bytecode. It LOOKS like C so anyone who knows C is
//! immediately productive, and it is NOT C — it has no pointers, no manual memory,
//! no undefined behaviour, and no I/O except the host capability calls. The eBPF
//! posture applies: this compiler is UNTRUSTED; the real security boundary is
//! `guest_vm.validProgram` + the total `guest_vm.run`, which are safe on ANY
//! bytecode this (or a hostile) compiler could emit.
//!
//! The language shape this lexer tokenizes (pinned here; parser/typecheck give it
//! meaning in later slices):
//!   - One numeric type, `num` (f64-backed, the VM's value type). `true`/`false`
//!     are the numbers 1 and 0.
//!   - Functions: `fn score() num { ... }` — the entry points (`score`, `retrieve`,
//!     `learn`) are functions with fixed names; helpers are ordinary functions.
//!   - Statements: `var x = e;`, assignment, `if (c) { } else { }`, `while (c) { }`,
//!     `return e;`, expression statements (mostly capability calls).
//!   - Expressions: arithmetic `+ - * /`, comparison `< > <= >= == !=`, logical
//!     `&& || !`, grouping `( )`, calls `f(a, b)`, identifiers (facts like
//!     `base_score`/`in_network`, locals, and capability names), number literals.
//!   - `//` line comments; whitespace insignificant.
//!
//! The lexer is TOTAL: any byte sequence produces a token stream ending in `eof`;
//! an unrecognised byte yields a single `invalid` token (the parser reports it) and
//! scanning continues — never a crash, never an infinite loop. Streaming (`next`),
//! so no allocation: the parser pulls tokens on demand.

const std = @import("std");
const assert = std.debug.assert;

/// A token kind. Keywords are distinguished from identifiers at lex time (a small
/// fixed set), so the parser branches on `kind` alone.
pub const Kind = enum(u8) {
    // literals + names
    number,
    identifier,
    // keywords
    kw_fn,
    kw_var,
    kw_if,
    kw_else,
    kw_while,
    kw_return,
    kw_true,
    kw_false,
    // grouping + punctuation
    lparen,
    rparen,
    lbrace,
    rbrace,
    semicolon,
    comma,
    // operators
    plus,
    minus,
    star,
    slash,
    assign, // =
    lt, // <
    gt, // >
    le, // <=
    ge, // >=
    eq, // ==
    ne, // !=
    and_and, // &&
    or_or, // ||
    bang, // !
    // terminals
    eof,
    invalid, // an unrecognised byte (the parser reports the diagnostic)

    comptime {
        // A fixed vocabulary; a new token kind is a deliberate language change.
        assert(@typeInfo(Kind).@"enum".fields.len == 32);
    }
};

/// One token: its kind and the half-open byte span `[start, start+len)` into the
/// source. The lexer does NOT parse number VALUES (the parser does, from the span),
/// so a token is a pure position record. HOT (one per lexeme, many per program) →
/// exact size guard (A7).
pub const Token = struct {
    kind: Kind,
    start: u32,
    len: u32,

    comptime {
        // Budget 12: kind (1) + start (4) + len (4) = 9, padded to 12 at the u32
        // alignment. Exact.
        assert(@sizeOf(Token) == 12);
    }

    /// The source text this token spans (a view into the lexer's source; borrows).
    pub fn text(self: Token, src: []const u8) []const u8 {
        return src[self.start .. self.start + self.len];
    }
};

/// Match an identifier against the keyword set. Returns the keyword kind, or
/// `.identifier` when it is an ordinary name. A small, exhaustive comparison — no
/// hash map (F2: `comptime`/std over a structure), and the set is tiny.
fn keywordKind(word: []const u8) Kind {
    const table = .{
        .{ "fn", Kind.kw_fn },
        .{ "var", Kind.kw_var },
        .{ "if", Kind.kw_if },
        .{ "else", Kind.kw_else },
        .{ "while", Kind.kw_while },
        .{ "return", Kind.kw_return },
        .{ "true", Kind.kw_true },
        .{ "false", Kind.kw_false },
    };
    inline for (table) |entry| {
        if (std.mem.eql(u8, word, entry[0])) return entry[1];
    }
    return .identifier;
}

fn isIdentStart(c: u8) bool {
    return (c >= 'a' and c <= 'z') or (c >= 'A' and c <= 'Z') or c == '_';
}
fn isIdentCont(c: u8) bool {
    return isIdentStart(c) or (c >= '0' and c <= '9');
}
fn isDigit(c: u8) bool {
    return c >= '0' and c <= '9';
}

/// The lexer. `src` is the whole program; `pos` is the scan cursor. Pure and
/// total: `next` always makes progress (or returns `eof`), so a token loop
/// terminates on any input. A7.2: cold — one per compile, holds two fields.
pub const Lexer = struct {
    src: []const u8,
    pos: u32 = 0,

    pub fn init(src: []const u8) Lexer {
        return .{ .src = src, .pos = 0 };
    }

    /// The next token. Skips whitespace and `//` line comments first, then reads one
    /// lexeme. At end of input (or forever after) returns `eof`.
    pub fn next(self: *Lexer) Token {
        self.skipTrivia();
        const start = self.pos;
        if (self.pos >= self.src.len) return .{ .kind = .eof, .start = start, .len = 0 };

        const c = self.src[self.pos];

        // Identifier or keyword.
        if (isIdentStart(c)) {
            while (self.pos < self.src.len and isIdentCont(self.src[self.pos])) self.pos += 1;
            const word = self.src[start..self.pos];
            return .{ .kind = keywordKind(word), .start = start, .len = self.pos - start };
        }

        // Number: digits, an optional single '.', more digits. (No exponents in the
        // first cut — F4; add if a real program needs them.)
        if (isDigit(c) or (c == '.' and self.pos + 1 < self.src.len and isDigit(self.src[self.pos + 1]))) {
            while (self.pos < self.src.len and isDigit(self.src[self.pos])) self.pos += 1;
            if (self.pos < self.src.len and self.src[self.pos] == '.') {
                self.pos += 1;
                while (self.pos < self.src.len and isDigit(self.src[self.pos])) self.pos += 1;
            }
            return .{ .kind = .number, .start = start, .len = self.pos - start };
        }

        // Punctuation + operators (multi-char forms checked first).
        return self.operator(start);
    }

    /// Read one operator/punctuation token starting at `start`, advancing `pos`.
    fn operator(self: *Lexer, start: u32) Token {
        const c = self.src[self.pos];
        const two: ?u8 = if (self.pos + 1 < self.src.len) self.src[self.pos + 1] else null;
        // Two-character operators.
        const kind2: ?Kind = switch (c) {
            '<' => if (two == '=') .le else null,
            '>' => if (two == '=') .ge else null,
            '=' => if (two == '=') .eq else null,
            '!' => if (two == '=') .ne else null,
            '&' => if (two == '&') .and_and else null,
            '|' => if (two == '|') .or_or else null,
            else => null,
        };
        if (kind2) |k| {
            self.pos += 2;
            return .{ .kind = k, .start = start, .len = 2 };
        }
        // Single-character tokens.
        const kind1: Kind = switch (c) {
            '(' => .lparen,
            ')' => .rparen,
            '{' => .lbrace,
            '}' => .rbrace,
            ';' => .semicolon,
            ',' => .comma,
            '+' => .plus,
            '-' => .minus,
            '*' => .star,
            '/' => .slash,
            '=' => .assign,
            '<' => .lt,
            '>' => .gt,
            '!' => .bang,
            else => .invalid,
        };
        self.pos += 1; // always advance one byte, even on `.invalid` — guarantees progress
        return .{ .kind = kind1, .start = start, .len = 1 };
    }

    /// Skip whitespace and `//` line comments (everything up to the next newline).
    fn skipTrivia(self: *Lexer) void {
        while (self.pos < self.src.len) {
            const c = self.src[self.pos];
            if (c == ' ' or c == '\t' or c == '\r' or c == '\n') {
                self.pos += 1;
            } else if (c == '/' and self.pos + 1 < self.src.len and self.src[self.pos + 1] == '/') {
                self.pos += 2;
                while (self.pos < self.src.len and self.src[self.pos] != '\n') self.pos += 1;
            } else break;
        }
    }
};

// ---------------------------------------------------------------------------
// Tests — pure (B2), no allocation. Totality + the token vocabulary.
// ---------------------------------------------------------------------------

const t = std.testing;

/// Collect kinds for a quick sequence assertion (test-only; bounded).
fn kinds(src: []const u8, out: []Kind) usize {
    var lx = Lexer.init(src);
    var n: usize = 0;
    while (n < out.len) {
        const tok = lx.next();
        out[n] = tok.kind;
        n += 1;
        if (tok.kind == .eof) break;
    }
    return n;
}

test "guards + vocabulary size" {
    try t.expectEqual(@as(usize, 12), @sizeOf(Token));
    try t.expectEqual(@as(usize, 32), @typeInfo(Kind).@"enum".fields.len);
}

test "lex: a small function tokenizes to the expected stream" {
    const src =
        \\fn score() num {
        \\  var s = base_score; // start from the base
        \\  if (in_network) { s = s * 1.5; }
        \\  return s + reply_count;
        \\}
    ;
    var buf: [64]Kind = undefined;
    const n = kinds(src, &buf);
    const got = buf[0..n];
    const expect = [_]Kind{
        .kw_fn,     .identifier, .lparen,   .rparen,     .identifier, .lbrace, // fn score() num {
        .kw_var,    .identifier, .assign,   .identifier, .semicolon, // var s = base_score;
        .kw_if,     .lparen,     .identifier, .rparen,   .lbrace, // if (in_network) {
        .identifier, .assign,    .identifier, .star,     .number,   .semicolon, .rbrace, // s = s * 1.5; }
        .kw_return, .identifier, .plus,      .identifier, .semicolon, // return s + reply_count;
        .rbrace, // }
        .eof,
    };
    try t.expectEqualSlices(Kind, &expect, got);
}

test "lex: number spans (int and decimal), keywords vs identifiers" {
    var lx = Lexer.init("42 3.14 truely true");
    const a = lx.next();
    try t.expectEqual(Kind.number, a.kind);
    try t.expectEqualStrings("42", a.text(lx.src));
    const b = lx.next();
    try t.expectEqualStrings("3.14", b.text(lx.src));
    const c = lx.next();
    try t.expectEqual(Kind.identifier, c.kind); // "truely" is NOT the keyword "true"
    try t.expectEqualStrings("truely", c.text(lx.src));
    try t.expectEqual(Kind.kw_true, lx.next().kind);
}

test "lex: two-char operators beat one-char; single-char forms too" {
    var buf: [16]Kind = undefined;
    const n = kinds("<= < >= == != && || ! = <", &buf);
    try t.expectEqualSlices(Kind, &[_]Kind{
        .le, .lt, .ge, .eq, .ne, .and_and, .or_or, .bang, .assign, .lt, .eof,
    }, buf[0..n]);
}

test "lex: TOTAL on hostile input — unknown bytes are `invalid`, scanning still terminates" {
    // Control bytes, unicode, unterminated comment — the loop must always end.
    const src = "\x00 @ #\xff  // unterminated comment to EOF";
    var lx = Lexer.init(src);
    var count: usize = 0;
    while (count < 1000) : (count += 1) {
        const tok = lx.next();
        if (tok.kind == .eof) break;
    }
    try t.expect(count < 1000); // it terminated (didn't spin), i.e. `next` always progresses
}
