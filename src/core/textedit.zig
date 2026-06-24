// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Zat4 — a social-media client built on the AT Protocol.
// Copyright (C) 2026  Connor Avila

//! B1 classification: CORE (pure). A single editable text field: a caller-owned
//! byte buffer plus a caret. Every editing operation is a free function over
//! plain data (A1), so every text surface in the app — the composer, the profile
//! editor, every enrollment field — shares ONE model instead of each
//! re-implementing append/backspace at the end (D5/D6: the reuse the per-field
//! drift was asking for).
//!
//! UTF-8 aware: motion and deletion step whole codepoints, never half of one.
//! There is no I/O and no allocation here — the buffer is fixed and caller-owned,
//! the caret blink clock and the clipboard live in the shell (B3). Selection is
//! deliberately NOT modeled yet (it needs a modifier-carrying key channel; F4 —
//! add the cut point when the real use arrives).

const std = @import("std");
const assert = std.debug.assert;

/// One editable text buffer. `buf` is caller-owned backing storage and its
/// length is the capacity; `len` bytes are live; `caret` is the byte offset of
/// the insertion point, always on a UTF-8 boundary in `[0, len]`. `anchor` is
/// the other end of the selection — `anchor == caret` means no selection; the
/// selected range is `[min(anchor,caret), max(anchor,caret))`.
pub const Field = struct {
    buf: []u8,
    len: u32 = 0,
    caret: u32 = 0,
    anchor: u32 = 0,

    comptime {
        // A7.1: budget raised 24 → 32 to add `anchor` (selection's second
        // endpoint, a u32 byte offset — flat, no pointer). []u8 (16) + three u32
        // (12) = 28 used; the slice forces 8-byte struct alignment, so there are
        // 4 bytes of tail padding → 32. The padding is fully explained by
        // alignment, not a layout defect; this is cold, low-quantity UI state.
        assert(@sizeOf(Field) == 32);
    }
};

fn isCont(b: u8) bool {
    return (b & 0xC0) == 0x80;
}

/// The byte offset of the codepoint boundary at or before `off-1` (the start of
/// the codepoint ending at `off`). Caller guarantees `off > 0`.
fn prevBoundary(bytes: []const u8, off: u32) u32 {
    var i: u32 = off - 1;
    while (i > 0 and isCont(bytes[i])) i -= 1;
    return i;
}

/// The byte offset of the next codepoint boundary after `off`. Caller guarantees
/// `off < bytes.len`.
fn nextBoundary(bytes: []const u8, off: u32) u32 {
    const l: u32 = std.unicode.utf8ByteSequenceLength(bytes[off]) catch 1;
    const n: u32 = off + l;
    return if (n > bytes.len) @intCast(bytes.len) else n;
}

/// The largest length `m <= min(cap, text.len)` that does not split a codepoint
/// in `text` — so a clamped copy never ends mid-sequence.
fn clampLen(cap: usize, text: []const u8) usize {
    var m: usize = @min(cap, text.len);
    while (m > 0 and m < text.len and isCont(text[m])) m -= 1;
    return m;
}

/// The live text (`buf[0..len]`).
pub fn view(f: *const Field) []const u8 {
    return f.buf[0..f.len];
}

/// Empty the field, keeping the backing buffer.
pub fn clear(f: *Field) void {
    f.len = 0;
    f.caret = 0;
    f.anchor = 0;
}

/// Replace all contents with `text` (clamped to capacity on a codepoint
/// boundary), caret to the end, no selection. Seeds a field — e.g. the profile
/// editor prefilling the current display name.
pub fn set(f: *Field, text: []const u8) void {
    const n = clampLen(f.buf.len, text);
    @memcpy(f.buf[0..n], text[0..n]);
    f.len = @intCast(n);
    f.caret = @intCast(n);
    f.anchor = f.caret;
}

// ── selection ───────────────────────────────────────────────────────────────

/// Is a (non-empty) range selected?
pub fn hasSelection(f: *const Field) bool {
    return f.anchor != f.caret;
}

/// The ordered selection-start byte offset.
pub fn selStart(f: *const Field) u32 {
    return @min(f.anchor, f.caret);
}
/// The ordered selection-end byte offset.
pub fn selEnd(f: *const Field) u32 {
    return @max(f.anchor, f.caret);
}

/// The selected text (empty when there is no selection) — what Copy/Cut emit.
pub fn selView(f: *const Field) []const u8 {
    return f.buf[selStart(f)..selEnd(f)];
}

/// Delete the selected range (if any); the caret collapses to its start.
pub fn deleteSelection(f: *Field) void {
    if (!hasSelection(f)) return;
    const s = selStart(f);
    const e = selEnd(f);
    const gap = e - s;
    std.mem.copyForwards(u8, f.buf[s .. f.len - gap], f.buf[e..f.len]);
    f.len -= gap;
    f.caret = s;
    f.anchor = s;
}

/// Snap `off` into `[0, len]` and back to the nearest codepoint boundary.
fn snap(f: *const Field, off: u32) u32 {
    var o: u32 = @min(off, f.len);
    while (o > 0 and o < f.len and isCont(f.buf[o])) o -= 1;
    return o;
}

// ── editing (selection-aware) ────────────────────────────────────────────────

/// Insert `text` at the caret (replacing the selection first, if any), advancing
/// the caret past it. A no-op if it would not fit (higher-level caps — e.g. the
/// composer's 300-codepoint limit — are enforced by the caller before calling).
pub fn insert(f: *Field, text: []const u8) void {
    if (text.len == 0) return;
    deleteSelection(f);
    if (@as(usize, f.len) + text.len > f.buf.len) return;
    const c = f.caret;
    const tlen: u32 = @intCast(text.len);
    // Shift [c, len) right by tlen, then drop `text` into the gap.
    std.mem.copyBackwards(u8, f.buf[c + tlen .. f.len + tlen], f.buf[c..f.len]);
    @memcpy(f.buf[c .. c + tlen], text);
    f.len += tlen;
    f.caret += tlen;
    f.anchor = f.caret;
}

/// Backspace: delete the selection if any, else the codepoint before the caret.
pub fn backspace(f: *Field) void {
    if (hasSelection(f)) {
        deleteSelection(f);
        return;
    }
    if (f.caret == 0) return;
    const p = prevBoundary(f.buf[0..f.len], f.caret);
    const gap = f.caret - p;
    std.mem.copyForwards(u8, f.buf[p .. f.len - gap], f.buf[f.caret..f.len]);
    f.len -= gap;
    f.caret = p;
    f.anchor = p;
}

/// Forward Delete: delete the selection if any, else the codepoint at the caret.
pub fn deleteForward(f: *Field) void {
    if (hasSelection(f)) {
        deleteSelection(f);
        return;
    }
    if (f.caret >= f.len) return;
    const n = nextBoundary(f.buf[0..f.len], f.caret);
    const gap = n - f.caret;
    std.mem.copyForwards(u8, f.buf[f.caret .. f.len - gap], f.buf[n..f.len]);
    f.len -= gap;
}

// ── caret motion (collapses any selection) ───────────────────────────────────

/// Move the caret one codepoint left (or to the selection start, if selected).
pub fn left(f: *Field) void {
    if (hasSelection(f)) {
        f.caret = selStart(f);
    } else if (f.caret > 0) {
        f.caret = prevBoundary(f.buf[0..f.len], f.caret);
    }
    f.anchor = f.caret;
}

/// Move the caret one codepoint right (or to the selection end, if selected).
pub fn right(f: *Field) void {
    if (hasSelection(f)) {
        f.caret = selEnd(f);
    } else if (f.caret < f.len) {
        f.caret = nextBoundary(f.buf[0..f.len], f.caret);
    }
    f.anchor = f.caret;
}

/// Move the caret to the start of the current line (after the previous '\n', or
/// the buffer start). For single-line fields this is the start.
pub fn home(f: *Field) void {
    var i = f.caret;
    while (i > 0 and f.buf[i - 1] != '\n') i -= 1;
    f.caret = i;
    f.anchor = i;
}

/// Move the caret to the end of the current line (before the next '\n', or the
/// buffer end). For single-line fields this is the end.
pub fn end(f: *Field) void {
    var i = f.caret;
    while (i < f.len and f.buf[i] != '\n') i += 1;
    f.caret = i;
    f.anchor = i;
}

/// Place the caret at byte offset `off` and collapse any selection — the entry
/// point for a plain click / the start of a drag (the shell maps a pixel to a
/// byte offset, then calls this).
pub fn setCaret(f: *Field, off: u32) void {
    f.caret = snap(f, off);
    f.anchor = f.caret;
}

/// Extend the selection to byte offset `off` (caret moves, anchor stays) — the
/// drag-to-select / Shift-move entry point.
pub fn extendTo(f: *Field, off: u32) void {
    f.caret = snap(f, off);
}

const CharClass = enum { word, space, other };
fn classOf(b: u8) CharClass {
    if (b >= 0x80) return .word; // any byte of a multibyte codepoint
    if (b == ' ' or b == '\t' or b == '\n' or b == '\r') return .space;
    if ((b >= 'a' and b <= 'z') or (b >= 'A' and b <= 'Z') or (b >= '0' and b <= '9') or b == '_') return .word;
    return .other;
}

/// Select the run of same-class characters around byte offset `at` (double-click):
/// a word, a whitespace run, or a punctuation run, whichever `at` lands on.
pub fn selectWord(f: *Field, at: u32) void {
    if (f.len == 0) {
        setCaret(f, 0);
        return;
    }
    const bytes = f.buf[0..f.len];
    var p = snap(f, @min(at, f.len));
    if (p >= f.len) p = prevBoundary(bytes, f.len); // at the end: use the char to the left
    const cls = classOf(bytes[p]);
    var s = p;
    while (s > 0) {
        const q = prevBoundary(bytes, s);
        if (classOf(bytes[q]) != cls) break;
        s = q;
    }
    var e = nextBoundary(bytes, p);
    while (e < f.len and classOf(bytes[e]) == cls) e = nextBoundary(bytes, e);
    f.anchor = s;
    f.caret = e;
}

/// Select the whole line/paragraph containing `at` (triple-click): from after the
/// previous '\n' to before the next '\n'.
pub fn selectLine(f: *Field, at: u32) void {
    const p = @min(at, f.len);
    var s = p;
    while (s > 0 and f.buf[s - 1] != '\n') s -= 1;
    var e = p;
    while (e < f.len and f.buf[e] != '\n') e += 1;
    f.anchor = s;
    f.caret = e;
}

// ── tests ───────────────────────────────────────────────────────────────────

test "insert at caret, mid-text, and capacity clamp" {
    var store: [8]u8 = undefined;
    var f: Field = .{ .buf = &store };
    insert(&f, "ac");
    try std.testing.expectEqualStrings("ac", view(&f));
    try std.testing.expectEqual(@as(u32, 2), f.caret);
    setCaret(&f, 1);
    insert(&f, "b");
    try std.testing.expectEqualStrings("abc", view(&f));
    try std.testing.expectEqual(@as(u32, 2), f.caret); // after the inserted 'b'
    insert(&f, "123456"); // len 3 + 6 > 8-byte buffer → no-op
    try std.testing.expectEqualStrings("abc", view(&f));
}

test "backspace and forward delete at the caret" {
    var store: [8]u8 = undefined;
    var f: Field = .{ .buf = &store };
    set(&f, "abcd");
    setCaret(&f, 2);
    backspace(&f); // removes 'b'
    try std.testing.expectEqualStrings("acd", view(&f));
    try std.testing.expectEqual(@as(u32, 1), f.caret);
    deleteForward(&f); // removes 'c'
    try std.testing.expectEqualStrings("ad", view(&f));
    try std.testing.expectEqual(@as(u32, 1), f.caret);
    setCaret(&f, 0);
    backspace(&f); // at start → no-op
    try std.testing.expectEqualStrings("ad", view(&f));
}

test "motion steps whole UTF-8 codepoints" {
    var store: [16]u8 = undefined;
    var f: Field = .{ .buf = &store };
    set(&f, "aébc"); // é = 0xC3 0xA9 (2 bytes); len = 5, caret = 5
    try std.testing.expectEqual(@as(u32, 5), f.caret);
    left(&f); // before 'c'
    try std.testing.expectEqual(@as(u32, 4), f.caret);
    left(&f); // before 'b'
    try std.testing.expectEqual(@as(u32, 3), f.caret);
    left(&f); // before 'é' — skips BOTH bytes of the codepoint
    try std.testing.expectEqual(@as(u32, 1), f.caret);
    right(&f); // past 'é'
    try std.testing.expectEqual(@as(u32, 3), f.caret);
    // backspace before 'b' removes 'é' wholesale
    backspace(&f);
    try std.testing.expectEqualStrings("abc", view(&f));
}

test "home and end are line-aware" {
    var store: [16]u8 = undefined;
    var f: Field = .{ .buf = &store };
    set(&f, "ab\ncd");
    setCaret(&f, 4); // between c and d on line 2
    home(&f);
    try std.testing.expectEqual(@as(u32, 3), f.caret); // start of line 2 (after '\n')
    end(&f);
    try std.testing.expectEqual(@as(u32, 5), f.caret); // end of line 2
    setCaret(&f, 1);
    home(&f);
    try std.testing.expectEqual(@as(u32, 0), f.caret);
    end(&f);
    try std.testing.expectEqual(@as(u32, 2), f.caret); // before the '\n'
}

test "selection: extend, selView, type-replaces, backspace-deletes, left collapses" {
    var store: [16]u8 = undefined;
    var f: Field = .{ .buf = &store };
    set(&f, "abcdef"); // caret 6, anchor 6
    setCaret(&f, 1); // collapse at 1
    extendTo(&f, 4); // select "bcd"
    try std.testing.expect(hasSelection(&f));
    try std.testing.expectEqualStrings("bcd", selView(&f));
    // Typing replaces the selection.
    insert(&f, "X");
    try std.testing.expectEqualStrings("aXef", view(&f));
    try std.testing.expect(!hasSelection(&f));
    try std.testing.expectEqual(@as(u32, 2), f.caret);
    // Re-select and Backspace deletes the whole range (not one char).
    setCaret(&f, 1);
    extendTo(&f, 3); // "Xe"
    backspace(&f);
    try std.testing.expectEqualStrings("af", view(&f));
    // left with a selection collapses to its start.
    set(&f, "hello");
    setCaret(&f, 1);
    extendTo(&f, 4);
    left(&f);
    try std.testing.expect(!hasSelection(&f));
    try std.testing.expectEqual(@as(u32, 1), f.caret);
}

test "selectWord and selectLine pick the right runs" {
    var store: [32]u8 = undefined;
    var f: Field = .{ .buf = &store };
    set(&f, "hello world foo");
    selectWord(&f, 2); // inside "hello"
    try std.testing.expectEqualStrings("hello", selView(&f));
    selectWord(&f, 5); // on the space between hello/world
    try std.testing.expectEqualStrings(" ", selView(&f));
    set(&f, "ab\ncd ef\ngh");
    selectLine(&f, 5); // inside the middle line "cd ef"
    try std.testing.expectEqualStrings("cd ef", selView(&f));
    try std.testing.expectEqual(@as(u32, 3), selStart(&f));
}

test "setCaret clamps and snaps to a codepoint boundary" {
    var store: [16]u8 = undefined;
    var f: Field = .{ .buf = &store };
    set(&f, "aé"); // bytes: a, C3, A9  (len 3)
    setCaret(&f, 99); // clamp to len
    try std.testing.expectEqual(@as(u32, 3), f.caret);
    setCaret(&f, 2); // mid-codepoint (the A9 continuation) → snaps back to 1
    try std.testing.expectEqual(@as(u32, 1), f.caret);
}
