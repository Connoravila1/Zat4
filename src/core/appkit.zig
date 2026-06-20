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

//! B1 classification: CORE. AppKit key semantics — a pure table mapping
//! NSEvent's function-key code units (the reserved 0xF700 block:
//! NSUpArrowFunctionKey and friends) to the same terminal byte sequences
//! the input decoder already speaks. The shell feeds each NSString unit
//! here first; everything that is not a function key flows through
//! core/textinput.zig like any other UTF-16 input. Same contract as
//! x11.keyBytes / win32.keydownBytes: 0 bytes means silence, not noise.

const std = @import("std");
const testing = std.testing;

/// AppKit delivers arrows, F-keys, and navigation keys as code units in
/// the reserved 0xF700–0xF8FF range. These must be intercepted before
/// UTF-16 decoding — they are valid code units that mean keys, not text.
pub fn isFunctionKey(unit: u16) bool {
    return unit >= 0xF700 and unit <= 0xF8FF;
}

/// The four arrows map to the decoder's escape trio; every other
/// function key is unbound in this UI and yields silence.
pub fn functionKeyBytes(unit: u16, out: *[8]u8) usize {
    const final: u8 = switch (unit) {
        0xF700 => 'A', // NSUpArrowFunctionKey
        0xF701 => 'B', // NSDownArrowFunctionKey
        0xF702 => 'D', // NSLeftArrowFunctionKey
        0xF703 => 'C', // NSRightArrowFunctionKey
        else => return 0,
    };
    out[0] = 0x1B;
    out[1] = '[';
    out[2] = final;
    return 3;
}

test "appkit keys: arrows map to the terminal escape trio" {
    var out: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 3), functionKeyBytes(0xF700, &out));
    try testing.expectEqualSlices(u8, &.{ 0x1B, '[', 'A' }, out[0..3]);
    try testing.expectEqual(@as(usize, 3), functionKeyBytes(0xF701, &out));
    try testing.expectEqual(@as(u8, 'B'), out[2]);
    try testing.expectEqual(@as(usize, 3), functionKeyBytes(0xF702, &out));
    try testing.expectEqual(@as(u8, 'D'), out[2]);
    try testing.expectEqual(@as(usize, 3), functionKeyBytes(0xF703, &out));
    try testing.expectEqual(@as(u8, 'C'), out[2]);
}

test "appkit keys: unbound function keys are silence, and the range is tight" {
    var out: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 0), functionKeyBytes(0xF704, &out)); // F1: unbound
    try testing.expect(isFunctionKey(0xF700));
    try testing.expect(isFunctionKey(0xF8FF));
    try testing.expect(!isFunctionKey(0xF6FF));
    try testing.expect(!isFunctionKey('a'));
}
