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

//! B1 classification: CORE (pure data). The emoji atlas: 201 curated
//! single-codepoint emoji as one raw RGBA sprite sheet (768x624, 48px
//! cells, 16 columns), baked from Noto Color Emoji's published 72px PNGs
//! (SIL OFL 1.1 — googlefonts/noto-emoji; the Pixel's own set, the
//! owner's pick 2026-07-12). Data, not a dependency (F1): re-bake by
//! re-running the sheet script over any set with the same layout — a
//! future Toy Box "emoji skin" is exactly one more sheet. Codepoints are
//! SORTED for binary search; the cell index is the codepoint's rank.

pub const cell_px: u32 = 48;
pub const cols: u32 = 16;
pub const sheet_w: u32 = 768;
pub const sheet_h: u32 = 672;
pub const count: u32 = 209;

/// The sheet: row-major RGBA8, straight (non-premultiplied) alpha.
pub const sheet_rgba = @embedFile("emoji_atlas.rgba");

/// The inline BOX an emoji renders at for text size `px`, and the pen
/// advance — one definition, so draw and measure can never drift.
pub fn boxFor(px: u32) u32 {
    return px + px / 4;
}
pub fn advanceFor(px: u32) u32 {
    return boxFor(px) + 2;
}

/// Cell index for a codepoint (null = not an emoji we carry). Binary
/// search over the sorted table — the render path calls this per glyph
/// run, not per pixel.
pub fn cellOf(cp: u21) ?u32 {
    var lo: usize = 0;
    var hi: usize = cps.len;
    while (lo < hi) {
        const mid = (lo + hi) / 2;
        if (cps[mid] == cp) return @intCast(mid);
        if (cps[mid] < cp) lo = mid + 1 else hi = mid;
    }
    return null;
}

/// The cell's pixel origin in the sheet.
pub fn cellOrigin(cell: u32) struct { x: u32, y: u32 } {
    return .{ .x = (cell % cols) * cell_px, .y = (cell / cols) * cell_px };
}

pub const cps = [_]u21{
    0x2600, 0x261D, 0x2639, 0x26A1, 0x26BD, 0x26BE, 0x26C5, 0x26C8,
    0x2708, 0x270A, 0x270B, 0x270C, 0x270D, 0x2728, 0x2744, 0x2763,
    0x2764, 0x2B50, 0x1F308, 0x1F30A, 0x1F30D, 0x1F319, 0x1F31F, 0x1F327,
    0x1F32A, 0x1F381, 0x1F388, 0x1F389, 0x1F3A4, 0x1F3A7, 0x1F3AC, 0x1F3AE,
    0x1F3AF, 0x1F3B2, 0x1F3B5, 0x1F3B8, 0x1F3BE, 0x1F3C0, 0x1F3C6, 0x1F3C8,
    0x1F3CB, 0x1F3E0, 0x1F410, 0x1F437, 0x1F446, 0x1F447, 0x1F448, 0x1F449,
    0x1F44A, 0x1F44B, 0x1F44C, 0x1F44D, 0x1F44E, 0x1F44F, 0x1F450, 0x1F451,
    0x1F479, 0x1F47B, 0x1F47D, 0x1F47F, 0x1F480, 0x1F485, 0x1F48E, 0x1F493,
    0x1F494, 0x1F495, 0x1F496, 0x1F497, 0x1F498, 0x1F499, 0x1F49A, 0x1F49B,
    0x1F49C, 0x1F49D, 0x1F49E, 0x1F4A1, 0x1F4A9, 0x1F4AA, 0x1F4AF, 0x1F4B0,
    0x1F4B8, 0x1F4F7, 0x1F525, 0x1F590, 0x1F595, 0x1F596, 0x1F5A4, 0x1F600,
    0x1F601, 0x1F602, 0x1F603, 0x1F604, 0x1F605, 0x1F606, 0x1F607, 0x1F608,
    0x1F609, 0x1F60A, 0x1F60B, 0x1F60C, 0x1F60D, 0x1F60E, 0x1F60F, 0x1F610,
    0x1F611, 0x1F612, 0x1F613, 0x1F614, 0x1F615, 0x1F616, 0x1F617, 0x1F618,
    0x1F619, 0x1F61A, 0x1F61B, 0x1F61C, 0x1F61D, 0x1F61E, 0x1F61F, 0x1F620,
    0x1F621, 0x1F622, 0x1F623, 0x1F624, 0x1F625, 0x1F626, 0x1F627, 0x1F628,
    0x1F629, 0x1F62A, 0x1F62B, 0x1F62C, 0x1F62D, 0x1F62E, 0x1F62F, 0x1F630,
    0x1F631, 0x1F632, 0x1F633, 0x1F634, 0x1F635, 0x1F636, 0x1F637, 0x1F638,
    0x1F639, 0x1F63A, 0x1F63B, 0x1F63C, 0x1F63D, 0x1F63E, 0x1F63F, 0x1F640,
    0x1F641, 0x1F642, 0x1F643, 0x1F644, 0x1F64C, 0x1F64F, 0x1F680, 0x1F697,
    0x1F90C, 0x1F90D, 0x1F90E, 0x1F90F, 0x1F910, 0x1F911, 0x1F912, 0x1F913,
    0x1F914, 0x1F915, 0x1F916, 0x1F917, 0x1F918, 0x1F919, 0x1F91A, 0x1F91B,
    0x1F91C, 0x1F91D, 0x1F91E, 0x1F91F, 0x1F920, 0x1F921, 0x1F922, 0x1F923,
    0x1F924, 0x1F925, 0x1F927, 0x1F928, 0x1F929, 0x1F92A, 0x1F92B, 0x1F92C,
    0x1F92D, 0x1F92E, 0x1F92F, 0x1F932, 0x1F947, 0x1F948, 0x1F949, 0x1F94A,
    0x1F970, 0x1F971, 0x1F973, 0x1F974, 0x1F975, 0x1F976, 0x1F97A, 0x1F9D0,
    0x1F9E1,
};

/// The picker's CATEGORIES, in display order: faces, hands, hearts,
/// nature, activities, and everything else (objects/misc). Predicate
/// ranges may cover codepoints the sheet doesn't carry — the builders
/// only walk `cps`, so strangers cost nothing.
fn isFace(cp: u21) bool {
    return (cp >= 0x1F600 and cp <= 0x1F644) or // smileys + cat faces
        (cp >= 0x1F910 and cp <= 0x1F917) or // zipper→hug (hands start 1F918)
        (cp >= 0x1F920 and cp <= 0x1F92F) or // cowboy→exploding head
        (cp >= 0x1F970 and cp <= 0x1F97A) or // hearts-smile→pleading
        cp == 0x1F9D0; // monocle
}
fn isHand(cp: u21) bool {
    return cp == 0x261D or (cp >= 0x270A and cp <= 0x270D) or
        (cp >= 0x1F446 and cp <= 0x1F450) or cp == 0x1F4AA or
        cp == 0x1F590 or cp == 0x1F595 or cp == 0x1F596 or
        cp == 0x1F64C or cp == 0x1F64F or cp == 0x1F90C or cp == 0x1F90F or
        (cp >= 0x1F918 and cp <= 0x1F91F) or cp == 0x1F932;
}
fn isHeart(cp: u21) bool {
    return cp == 0x2763 or cp == 0x2764 or (cp >= 0x1F493 and cp <= 0x1F49E) or
        cp == 0x1F5A4 or cp == 0x1F90D or cp == 0x1F90E or cp == 0x1F9E1;
}
fn isNature(cp: u21) bool {
    return cp == 0x2600 or cp == 0x26A1 or cp == 0x26C5 or cp == 0x26C8 or
        cp == 0x2728 or cp == 0x2744 or cp == 0x1F308 or cp == 0x1F30D or
        cp == 0x1F319 or cp == 0x1F31F or cp == 0x1F327 or cp == 0x1F525;
}
fn isActivity(cp: u21) bool {
    return cp == 0x26BD or cp == 0x26BE or (cp >= 0x1F3A4 and cp <= 0x1F3C8) or
        cp == 0x1F388 or cp == 0x1F389 or (cp >= 0x1F947 and cp <= 0x1F949);
}

/// A codepoint's category — the FIRST matching predicate; anything
/// unmatched is objects/misc (the last tab).
fn catOf(cp: u21) u8 {
    if (isFace(cp)) return 0;
    if (isHand(cp)) return 1;
    if (isHeart(cp)) return 2;
    if (isNature(cp)) return 3;
    if (isActivity(cp)) return 4;
    return 5;
}

pub const category_count: usize = 6;
/// One representative codepoint per category — the nav rollout's icons.
/// Every entry is IN the sheet (pinned by the test below).
pub const cat_icons = [category_count]u21{ 0x1F600, 0x1F44D, 0x2764, 0x2600, 0x26BD, 0x1F48E };

/// The PICKER's display order: category-blocked (faces lead), codepoint
/// order within each block. `display[i]` is the atlas CELL at picker
/// slot `i`. The `cps` table itself stays sorted — `cellOf`'s binary
/// search and the render path never see this permutation.
pub const display: [count]u16 = blk: {
    @setEvalBranchQuota(20000);
    var out: [count]u16 = undefined;
    var n: usize = 0;
    var cat: u8 = 0;
    while (cat < category_count) : (cat += 1) {
        for (cps, 0..) |c, i| {
            if (catOf(c) == cat) {
                out[n] = i;
                n += 1;
            }
        }
    }
    break :blk out;
};

/// Where each category starts in `display` — the nav's jump targets.
pub const cat_starts: [category_count]u16 = blk: {
    @setEvalBranchQuota(20000);
    var out: [category_count]u16 = undefined;
    var n: u16 = 0;
    var cat: u8 = 0;
    while (cat < category_count) : (cat += 1) {
        out[cat] = n;
        for (cps) |c| {
            if (catOf(c) == cat) n += 1;
        }
    }
    break :blk out;
};

const std = @import("std");

test "emoji atlas: display order is a permutation, categories are blocks" {
    var seen = [_]bool{false} ** count;
    for (display) |cell| {
        try std.testing.expect(cell < count);
        try std.testing.expect(!seen[cell]);
        seen[cell] = true;
    }
    // The first slot is the grinning face, not the codepoint-order sun.
    try std.testing.expectEqual(@as(u21, 0x1F600), cps[display[0]]);
    // Categories never interleave: catOf is nondecreasing across display.
    var prev: u8 = 0;
    for (display) |cell| {
        const c = catOf(cps[cell]);
        try std.testing.expect(c >= prev);
        prev = c;
    }
    // cat_starts point at the first slot of each category (or the end of
    // the previous block when a category is empty), and every nav icon is
    // a codepoint the sheet actually carries.
    try std.testing.expectEqual(@as(u16, 0), cat_starts[0]);
    for (cat_starts, 0..) |s, cat| {
        try std.testing.expect(s <= count);
        if (s < count and catOf(cps[display[s]]) == cat)
            try std.testing.expect(s == 0 or catOf(cps[display[s - 1]]) < cat);
    }
    for (cat_icons) |ic| try std.testing.expect(cellOf(ic) != null);
}

test "emoji atlas: lookup finds every baked codepoint, misses strangers" {
    for (cps, 0..) |c, i| {
        try std.testing.expectEqual(@as(?u32, @intCast(i)), cellOf(c));
    }
    try std.testing.expectEqual(@as(?u32, null), cellOf('A'));
    try std.testing.expectEqual(@as(?u32, null), cellOf(0x10FFFF));
    try std.testing.expectEqual(@as(usize, count), cps.len);
    try std.testing.expectEqual(@as(usize, sheet_w * sheet_h * 4), sheet_rgba.len);
}
