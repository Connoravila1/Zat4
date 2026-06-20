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

//! B1 classification: CORE. UTF-16 input semantics shared by the Win32
//! and AppKit backends — both OSes deliver text as UTF-16 code units
//! (WM_CHAR messages; NSString contents), surrogate pairs split in two.
//! Pure: state in, state out, no globals (B2). core/win32.zig re-exports
//! these so its shell keeps one `keys` namespace; shell/appkit.zig
//! imports this file directly.

const std = @import("std");
const testing = std.testing;

/// Fold one UTF-16 code unit into a codepoint. High surrogates park in
/// `pending_high` (caller-owned, zero-initialized) and yield null; the
/// matching low surrogate completes the pair. A lone low surrogate is
/// dropped. Pure: state in, state out, no globals (B2).
pub fn utf16Step(pending_high: *u16, unit: u16) ?u21 {
    if (unit >= 0xD800 and unit <= 0xDBFF) {
        pending_high.* = unit;
        return null;
    }
    if (unit >= 0xDC00 and unit <= 0xDFFF) {
        const high = pending_high.*;
        pending_high.* = 0;
        if (high == 0) return null; // lone low surrogate: dropped
        return 0x10000 + ((@as(u21, high) - 0xD800) << 10) + (unit - 0xDC00);
    }
    pending_high.* = 0;
    return unit;
}

/// Translate a completed codepoint to terminal bytes: the control table
/// the decoder expects, plus real UTF-8 for everything printable.
/// Returns 0 for code units the UI has no meaning for — silence, not
/// noise (the same contract as x11.keyBytes).
pub fn codepointBytes(cp: u21, out: *[8]u8) usize {
    switch (cp) {
        0x0D => {
            out[0] = '\r';
            return 1;
        },
        0x1B => {
            out[0] = 0x1B;
            return 1;
        },
        0x08 => {
            out[0] = 0x7F; // BackSpace arrives as DEL, terminal-style
            return 1;
        },
        0x09 => {
            out[0] = '\t';
            return 1;
        },
        0x20...0x10FFFF => {
            return std.unicode.utf8Encode(cp, out) catch 0;
        },
        else => return 0,
    }
}

test "textinput: printables, control chars, and the DEL convention" {
    var out: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 1), codepointBytes('q', &out));
    try testing.expectEqual(@as(u8, 'q'), out[0]);
    try testing.expectEqual(@as(usize, 1), codepointBytes(0x0D, &out));
    try testing.expectEqual(@as(u8, '\r'), out[0]);
    try testing.expectEqual(@as(usize, 1), codepointBytes(0x08, &out));
    try testing.expectEqual(@as(u8, 0x7F), out[0]); // backspace = DEL
}

test "textinput: non-ASCII becomes real UTF-8, surrogate pairs included" {
    var out: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 2), codepointBytes(0x00E9, &out)); // é
    try testing.expectEqualSlices(u8, &.{ 0xC3, 0xA9 }, out[0..2]);
    try testing.expectEqual(@as(usize, 3), codepointBytes(0x20AC, &out)); // €
    var pending: u16 = 0;
    try testing.expectEqual(@as(?u21, null), utf16Step(&pending, 0xD83D));
    const cp = utf16Step(&pending, 0xDE00) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u21, 0x1F600), cp); // grinning face
    try testing.expectEqual(@as(usize, 4), codepointBytes(cp, &out));
    // A lone low surrogate is dropped, and state resets.
    try testing.expectEqual(@as(?u21, null), utf16Step(&pending, 0xDE00));
    try testing.expectEqual(@as(?u21, 'a'), utf16Step(&pending, 'a'));
}
