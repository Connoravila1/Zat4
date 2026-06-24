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

//! B1 classification: CORE (pure). The **renderer deep module**, file 1 of
//! 3: the terminal substrate.
//!
//! DECISION RECORDED (Phase 5): the first renderer is a hand-built,
//! immediate-mode TERMINAL renderer. Zero dependencies — F1's default "no"
//! stands (an ImGui/SDL binding would mean a C++ toolchain and a
//! framework's opinions about structure); every line is ours to
//! restructure. The renderer is sealed behind D1: the rest of the app
//! hands plain view-model values to file 2 and never learns that ANSI
//! exists. A future GPU/native renderer is a SIBLING module behind the
//! same view-model boundary — swapping it in touches nothing above.
//!
//! The model is the doctrine's ideal frame: a `Surface` is a cell grid
//! stored as hand-rolled parallel arrays (A3 — codepoints in one array,
//! styles in another), rebuilt every frame by pure functions, and presented by
//! a pure DIFF: (previous grid, next grid) → the minimal ANSI byte string
//! that turns one into the other. Bytes are testable; nothing here touches
//! a tty (B2/B4) — file 3 (the shell) owns the terminal itself.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// Styles
// ---------------------------------------------------------------------------

/// The 16 ANSI colors plus the terminal default — the entire palette, on
/// purpose: it inherits the user's theme and keeps the style word small.
pub const Color = enum(u8) {
    default,
    black,
    red,
    green,
    yellow,
    blue,
    magenta,
    cyan,
    white,
    bright_black,
    bright_red,
    bright_green,
    bright_yellow,
    bright_blue,
    bright_magenta,
    bright_cyan,
    bright_white,
};

fn sgrForeground(color: Color) u8 {
    const i = @intFromEnum(color);
    return switch (color) {
        .default => 39,
        else => if (i <= 8) 30 + i - 1 else 90 + i - 9,
    };
}

/// One cell's appearance.
/// D5/A1 note: `eql` is a value-equality helper on a tiny value type —
/// not behavior attached to a stored record.
pub const Style = packed struct(u16) {
    fg: Color = .default,
    bold: bool = false,
    dim: bool = false,
    inverse: bool = false,
    _reserved: u5 = 0,

    comptime {
        // Budget 2: one per cell in the style array; a full 80×24 frame's
        // styles fit in two cache lines per row. (A7)
        assert(@sizeOf(Style) == 2);
    }

    fn eql(a: Style, b: Style) bool {
        return @as(u16, @bitCast(a)) == @as(u16, @bitCast(b));
    }
};

// ---------------------------------------------------------------------------
// The surface — a frame as data
// ---------------------------------------------------------------------------

/// A cell grid in struct-of-arrays form: `chars[i]` is the codepoint at
/// cell i (0 = continuation cell of a preceding wide glyph), `styles[i]`
/// its style; i = y * width + x. Rebuilt wholesale every frame.
/// A7.2: cold struct, size guard waived — two singletons per session
/// (previous/next frame); its CONTENTS are the parallel arrays. (A3: cells
/// are hand-rolled parallel arrays rather than a MultiArrayList because
/// the two columns are always resized and cleared in lockstep.)
pub const Surface = struct {
    width: u16 = 0,
    height: u16 = 0,
    chars: std.ArrayList(u32) = .empty,
    styles: std.ArrayList(Style) = .empty,
};

pub fn deinitSurface(gpa: Allocator, surface: *Surface) void {
    surface.chars.deinit(gpa);
    surface.styles.deinit(gpa);
    surface.* = undefined;
}

/// Size (or re-size) the grid and clear it to blank cells.
pub fn resizeSurface(gpa: Allocator, surface: *Surface, width: u16, height: u16) error{OutOfMemory}!void {
    const cells: usize = @as(usize, width) * height;
    try surface.chars.resize(gpa, cells);
    try surface.styles.resize(gpa, cells);
    surface.width = width;
    surface.height = height;
    clearSurface(surface);
}

pub fn clearSurface(surface: *Surface) void {
    @memset(surface.chars.items, ' ');
    @memset(surface.styles.items, Style{});
}

fn cellIndex(surface: *const Surface, x: u16, y: u16) usize {
    return @as(usize, y) * surface.width + x;
}

/// Place UTF-8 text at (x, y), clipping at the right edge. Returns the
/// number of columns consumed. Wide glyphs occupy two cells (head + a
/// 0-codepoint continuation); invalid bytes render as U+FFFD; control
/// characters render as spaces — the grid never holds anything a terminal
/// could misinterpret.
pub fn putText(surface: *Surface, x: u16, y: u16, style: Style, text: []const u8) u16 {
    if (y >= surface.height or x >= surface.width) return 0;
    var col: u16 = x;
    var i: usize = 0;
    while (i < text.len) {
        const decoded = nextCodepoint(text[i..]);
        i += decoded.len;
        var cp = decoded.cp;
        if (cp < 0x20 or cp == 0x7f) cp = ' ';
        const w = runeWidth(cp);
        if (w == 0) continue;
        if (@as(u32, col) + w > surface.width) break;
        const cell = cellIndex(surface, col, y);
        surface.chars.items[cell] = cp;
        surface.styles.items[cell] = style;
        if (w == 2) {
            surface.chars.items[cell + 1] = 0;
            surface.styles.items[cell + 1] = style;
        }
        col += w;
    }
    return col - x;
}

/// Fill an entire row with one styled codepoint (width-1 only).
pub fn fillRow(surface: *Surface, y: u16, style: Style, cp: u32) void {
    if (y >= surface.height) return;
    const start = cellIndex(surface, 0, y);
    @memset(surface.chars.items[start .. start + surface.width], cp);
    @memset(surface.styles.items[start .. start + surface.width], style);
}

const Decoded = struct {
    cp: u32,
    len: usize,

    comptime {
        // Ruled HOT (A7.2 tie-break: ambiguous goes hot): one Decoded per
        // codepoint, produced inside every putText/render loop. Budget:
        // u32 cp + usize len; 4 bytes of padding ride along on 64-bit.
        if (@sizeOf(usize) == 8) assert(@sizeOf(Decoded) == 16);
    }
};

/// Decode one codepoint, total over arbitrary bytes: invalid sequences
/// yield U+FFFD and advance one byte (E4 — bad bytes are ordinary data).
fn nextCodepoint(bytes: []const u8) Decoded {
    const len = std.unicode.utf8ByteSequenceLength(bytes[0]) catch return .{ .cp = 0xFFFD, .len = 1 };
    if (len > bytes.len) return .{ .cp = 0xFFFD, .len = 1 };
    const cp = std.unicode.utf8Decode(bytes[0..len]) catch return .{ .cp = 0xFFFD, .len = 1 };
    return .{ .cp = cp, .len = len };
}

/// Display width of a codepoint: 2 for East-Asian wide blocks and emoji,
/// else 1. A pragmatic table, not full Unicode — the recorded trade: a
/// terminal that disagrees mis-draws one line until the next diff repaints
/// it.
pub fn runeWidth(cp: u32) u2 {
    const wide_ranges = [_][2]u32{
        .{ 0x1100, 0x115F },   .{ 0x2329, 0x232A }, .{ 0x2E80, 0x303E },
        .{ 0x3041, 0x33FF },   .{ 0x3400, 0x4DBF }, .{ 0x4E00, 0x9FFF },
        .{ 0xA000, 0xA4CF },   .{ 0xA960, 0xA97F }, .{ 0xAC00, 0xD7A3 },
        .{ 0xF900, 0xFAFF },   .{ 0xFE10, 0xFE19 }, .{ 0xFE30, 0xFE6F },
        .{ 0xFF00, 0xFF60 },   .{ 0xFFE0, 0xFFE6 }, .{ 0x1F300, 0x1FAFF },
        .{ 0x20000, 0x3FFFD },
    };
    for (wide_ranges) |range| {
        if (cp >= range[0] and cp <= range[1]) return 2;
    }
    return 1;
}

// ---------------------------------------------------------------------------
// Presentation — the pure diff
// ---------------------------------------------------------------------------

/// Encode the ANSI byte string that turns `prev` into `next`. A size
/// change (or an empty prev) produces a full repaint; otherwise only
/// changed cells are emitted, with cursor moves and SGR sequences elided
/// while position/style continue runs. Returns an empty slice when nothing
/// changed. Deterministic — the golden tests below pin the exact bytes.
pub fn encodeDiff(arena: Allocator, prev: *const Surface, next: *const Surface) error{OutOfMemory}![]u8 {
    var out: std.Io.Writer.Allocating = .init(arena);
    defer out.deinit();
    const w = &out.writer;

    const full = prev.width != next.width or prev.height != next.height;
    var emitted = false;
    var cursor_x: u32 = std.math.maxInt(u32);
    var cursor_y: u32 = std.math.maxInt(u32);
    var current: ?Style = null;

    if (full) {
        w.writeAll("\x1b[2J") catch return error.OutOfMemory;
        emitted = true;
    }

    var y: u16 = 0;
    while (y < next.height) : (y += 1) {
        var x: u16 = 0;
        while (x < next.width) : (x += 1) {
            const cell = cellIndex(next, x, y);
            const cp = next.chars.items[cell];
            if (cp == 0) continue; // continuation of a wide glyph
            const style = next.styles.items[cell];
            if (!full) {
                const same = prev.chars.items[cell] == cp and prev.styles.items[cell].eql(style);
                if (same) continue;
            }
            if (cursor_x != x or cursor_y != y) {
                w.print("\x1b[{d};{d}H", .{ y + 1, x + 1 }) catch return error.OutOfMemory;
                cursor_x = x;
                cursor_y = y;
            }
            if (current == null or !current.?.eql(style)) {
                writeSgr(w, style) catch return error.OutOfMemory;
                current = style;
            }
            var utf8_buf: [4]u8 = undefined;
            const len = std.unicode.utf8Encode(@intCast(cp), &utf8_buf) catch blk: {
                utf8_buf[0] = '?';
                break :blk 1;
            };
            w.writeAll(utf8_buf[0..len]) catch return error.OutOfMemory;
            emitted = true;
            cursor_x += runeWidth(cp);
        }
    }

    if (emitted) w.writeAll("\x1b[0m") catch return error.OutOfMemory;
    return out.toOwnedSlice();
}

/// SGR in canonical form: always a reset, then attributes in fixed order,
/// then the foreground — deterministic so the goldens hold.
fn writeSgr(w: *std.Io.Writer, style: Style) !void {
    try w.writeAll("\x1b[0");
    if (style.bold) try w.writeAll(";1");
    if (style.dim) try w.writeAll(";2");
    if (style.inverse) try w.writeAll(";7");
    try w.print(";{d}m", .{sgrForeground(style.fg)});
}

// ---------------------------------------------------------------------------
// Input — terminal bytes to plain events
// ---------------------------------------------------------------------------

/// One decoded input. A7.2: cold struct, size guard waived — one exists at
/// a time, on the stack of the input loop.
pub const InputEvent = union(enum) {
    char: u21,
    up,
    down,
    left,
    right,
    page_up,
    page_down,
    home,
    end_key,
    delete,
    back_tab, // Shift+Tab (CSI Z) — reverse focus traversal
    enter,
    escape,
    none,
};

pub const DecodedInput = struct {
    event: InputEvent,
    consumed: usize,

    comptime {
        // Ruled HOT (A7.2 tie-break: ambiguous goes hot): one per input
        // event in the decode loop. Budget: InputEvent (tagged union, 8)
        // + usize length on 64-bit.
        if (@sizeOf(usize) == 8) assert(@sizeOf(DecodedInput) == 16);
    }
};

/// Decode the first event from a byte buffer. Pure and total: unknown
/// escape sequences are consumed as `.none`; a lone ESC is `.escape`.
/// (Sequences split across reads are consumed as ESC — terminals emit them
/// atomically in practice; the trade is recorded here.)
pub fn decodeInput(bytes: []const u8) DecodedInput {
    if (bytes.len == 0) return .{ .event = .none, .consumed = 0 };
    if (bytes[0] == 0x1b) {
        if (bytes.len >= 3 and bytes[1] == '[') {
            switch (bytes[2]) {
                'A' => return .{ .event = .up, .consumed = 3 },
                'B' => return .{ .event = .down, .consumed = 3 },
                'C' => return .{ .event = .right, .consumed = 3 },
                'D' => return .{ .event = .left, .consumed = 3 },
                'H' => return .{ .event = .home, .consumed = 3 },
                'F' => return .{ .event = .end_key, .consumed = 3 },
                'Z' => return .{ .event = .back_tab, .consumed = 3 }, // Shift+Tab
                '5', '6', '1', '3', '4' => if (bytes.len >= 4 and bytes[3] == '~') {
                    const event: InputEvent = switch (bytes[2]) {
                        '5' => .page_up,
                        '6' => .page_down,
                        '1' => .home,
                        '3' => .delete,
                        else => .end_key,
                    };
                    return .{ .event = event, .consumed = 4 };
                },
                else => return .{ .event = .none, .consumed = 3 },
            }
            return .{ .event = .none, .consumed = @min(bytes.len, 4) };
        }
        return .{ .event = .escape, .consumed = if (bytes.len >= 2 and bytes[1] == '[') 2 else 1 };
    }
    if (bytes[0] == '\r' or bytes[0] == '\n') return .{ .event = .enter, .consumed = 1 };
    const decoded = nextCodepoint(bytes);
    return .{ .event = .{ .char = @intCast(decoded.cp) }, .consumed = decoded.len };
}

// ---------------------------------------------------------------------------
// Tests — the renderer's behavior pinned as data, no terminal required
// (B2 pays the wildcard down: the risky phase tests like any other). C6.
// ---------------------------------------------------------------------------

const testing = std.testing;

test "surface: text placement, clipping, and wide-glyph continuation" {
    const gpa = testing.allocator;
    var s: Surface = .{};
    defer deinitSurface(gpa, &s);
    try resizeSurface(gpa, &s, 8, 2);

    const used = putText(&s, 1, 0, .{ .fg = .cyan }, "hi");
    try testing.expectEqual(@as(u16, 2), used);
    try testing.expectEqual(@as(u32, 'h'), s.chars.items[1]);
    try testing.expectEqual(@as(u32, 'i'), s.chars.items[2]);
    try testing.expectEqual(Color.cyan, s.styles.items[1].fg);

    // A CJK glyph is two columns: head + continuation cell.
    _ = putText(&s, 0, 1, .{}, "好x");
    try testing.expectEqual(@as(u32, 0x597D), s.chars.items[cellIndex(&s, 0, 1)]);
    try testing.expectEqual(@as(u32, 0), s.chars.items[cellIndex(&s, 1, 1)]);
    try testing.expectEqual(@as(u32, 'x'), s.chars.items[cellIndex(&s, 2, 1)]);

    // Clipping: never writes past the right edge.
    const clipped = putText(&s, 6, 0, .{}, "abcdef");
    try testing.expectEqual(@as(u16, 2), clipped);
}

test "diff: one changed cell emits exactly one move + one SGR + the glyph" {
    const gpa = testing.allocator;
    var prev: Surface = .{};
    var next: Surface = .{};
    defer deinitSurface(gpa, &prev);
    defer deinitSurface(gpa, &next);
    try resizeSurface(gpa, &prev, 4, 2);
    try resizeSurface(gpa, &next, 4, 2);

    _ = putText(&next, 1, 1, .{ .fg = .cyan, .bold = true }, "A");

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const bytes = try encodeDiff(arena_state.allocator(), &prev, &next);
    try testing.expectEqualStrings("\x1b[2;2H\x1b[0;1;36mA\x1b[0m", bytes);
}

test "diff: identical frames emit nothing; adjacent same-style cells share one SGR" {
    const gpa = testing.allocator;
    var prev: Surface = .{};
    var next: Surface = .{};
    defer deinitSurface(gpa, &prev);
    defer deinitSurface(gpa, &next);
    try resizeSurface(gpa, &prev, 6, 1);
    try resizeSurface(gpa, &next, 6, 1);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    try testing.expectEqualStrings("", try encodeDiff(arena_state.allocator(), &prev, &next));

    _ = putText(&next, 2, 0, .{ .dim = true }, "ab");
    const bytes = try encodeDiff(arena_state.allocator(), &prev, &next);
    // One cursor move, one SGR, two glyphs riding the same run.
    try testing.expectEqualStrings("\x1b[1;3H\x1b[0;2;39mab\x1b[0m", bytes);
}

test "diff: a size change forces a full repaint that starts with a clear" {
    const gpa = testing.allocator;
    var prev: Surface = .{};
    var next: Surface = .{};
    defer deinitSurface(gpa, &prev);
    defer deinitSurface(gpa, &next);
    try resizeSurface(gpa, &prev, 2, 1);
    try resizeSurface(gpa, &next, 3, 1);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const bytes = try encodeDiff(arena_state.allocator(), &prev, &next);
    try testing.expect(std.mem.startsWith(u8, bytes, "\x1b[2J"));
    try testing.expect(std.mem.endsWith(u8, bytes, "\x1b[0m"));
}

test "input: keys, arrows, paging, and utf-8 decode to plain events" {
    try testing.expectEqual(InputEvent.up, decodeInput("\x1b[A").event);
    try testing.expectEqual(@as(usize, 3), decodeInput("\x1b[A").consumed);
    try testing.expectEqual(InputEvent.page_down, decodeInput("\x1b[6~").event);
    try testing.expectEqual(InputEvent.escape, decodeInput("\x1b").event);
    try testing.expectEqual(InputEvent.enter, decodeInput("\r").event);

    const j = decodeInput("j");
    try testing.expectEqual(@as(u21, 'j'), j.event.char);

    const wide = decodeInput("好");
    try testing.expectEqual(@as(u21, 0x597D), wide.event.char);
    try testing.expectEqual(@as(usize, 3), wide.consumed);
}

test "rune width: ascii narrow, CJK and emoji wide" {
    try testing.expectEqual(@as(u2, 1), runeWidth('a'));
    try testing.expectEqual(@as(u2, 2), runeWidth(0x597D)); // 好
    try testing.expectEqual(@as(u2, 2), runeWidth(0x1F600)); // emoji
    try testing.expectEqual(@as(u2, 1), runeWidth(0xFFFD));
}
