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

//! B1 classification: CORE (pure). Parser for the Xcursor file format — the
//! on-disk shape of every cursor in a Linux cursor theme. The shell finds and
//! reads the file (filesystem I/O); this turns the bytes into the cursor image
//! the GPU/X-Render upload wants. No I/O, no allocation.
//!
//! Format (all integers little-endian): a 16-byte file header
//! (magic "Xcur", header-size, version, table-of-contents count), then a TOC of
//! {type, subtype, position} entries. Image entries (type 0xFFFD0002) carry the
//! nominal pixel size as `subtype`; each points at an image chunk: a 36-byte
//! header (header-size, type, subtype, version, width, height, xhot, yhot,
//! delay) followed by width·height ARGB32 pixels (premultiplied, little-endian
//! — i.e. B,G,R,A bytes, exactly what an X depth-32 ZPixmap wants).

const std = @import("std");

const image_type: u32 = 0xFFFD0002;

/// One decoded cursor image: its size, hotspot, and a slice of the source bytes
/// holding the ARGB32 pixels (premultiplied, LE). The slice borrows the caller's
/// buffer — no copy, no allocation. A7.2: cold — one transient per cursor load.
pub const Image = struct {
    width: u32,
    height: u32,
    xhot: u32,
    yhot: u32,
    pixels: []const u8, // width*height*4 bytes, ARGB32 LE premultiplied
};

fn rd32(bytes: []const u8, at: usize) u32 {
    return std.mem.readInt(u32, bytes[at..][0..4], .little);
}

/// The image whose nominal size is nearest `target` (ties break toward the
/// larger, for crispness). Returns null on a malformed or non-Xcursor file, or
/// if the chosen image runs past the end of `bytes` — every field is bounds-
/// checked, so a truncated/garbage file is an ordinary null, not a crash (E4).
/// First frame only: an animated cursor's extra frames (same size, a delay) are
/// ignored — a static pointer is all we need.
pub fn bestImage(bytes: []const u8, target: u32) ?Image {
    if (bytes.len < 16) return null;
    if (!std.mem.eql(u8, bytes[0..4], "Xcur")) return null;
    const ntoc = rd32(bytes, 12);
    if (ntoc > 4096) return null; // a sane ceiling on a local theme file

    var best_pos: ?u32 = null;
    var best_size: u32 = 0;
    var best_diff: u32 = std.math.maxInt(u32);
    var i: u32 = 0;
    var toc: usize = 16;
    while (i < ntoc) : (i += 1) {
        if (toc + 12 > bytes.len) return null;
        const ttype = rd32(bytes, toc);
        const subtype = rd32(bytes, toc + 4); // nominal size for images
        const position = rd32(bytes, toc + 8);
        toc += 12;
        if (ttype != image_type) continue;
        const diff = if (subtype > target) subtype - target else target - subtype;
        if (diff < best_diff or (diff == best_diff and subtype > best_size)) {
            best_diff = diff;
            best_size = subtype;
            best_pos = position;
        }
    }

    const pos = best_pos orelse return null;
    if (pos + 36 > bytes.len) return null;
    if (rd32(bytes, pos + 4) != image_type) return null; // chunk type
    const width = rd32(bytes, pos + 16);
    const height = rd32(bytes, pos + 20);
    const xhot = rd32(bytes, pos + 24);
    const yhot = rd32(bytes, pos + 28);
    if (width == 0 or height == 0 or width > 512 or height > 512) return null;
    const npix = @as(usize, width) * @as(usize, height);
    const data = pos + 36;
    if (data + npix * 4 > bytes.len) return null;
    return .{
        .width = width,
        .height = height,
        .xhot = @min(xhot, width),
        .yhot = @min(yhot, height),
        .pixels = bytes[data .. data + npix * 4],
    };
}

// ---------------------------------------------------------------------------
// Tests (C6)
// ---------------------------------------------------------------------------

const testing = std.testing;

fn wr32(buf: []u8, at: usize, v: u32) void {
    std.mem.writeInt(u32, buf[at..][0..4], v, .little);
}

/// Build a minimal one-image Xcursor file (size×size, ARGB) for the tests.
fn synth(buf: []u8, size: u32) []u8 {
    const npix = size * size;
    const total = 16 + 12 + 36 + npix * 4;
    @memset(buf[0..total], 0);
    @memcpy(buf[0..4], "Xcur");
    wr32(buf, 4, 16); // header size
    wr32(buf, 8, 0x10000); // version
    wr32(buf, 12, 1); // one TOC entry
    // TOC entry at 16: image, nominal size, position 28.
    wr32(buf, 16, image_type);
    wr32(buf, 20, size);
    wr32(buf, 24, 28);
    // image chunk at 28.
    wr32(buf, 28, 36); // chunk header size
    wr32(buf, 32, image_type);
    wr32(buf, 36, size); // subtype
    wr32(buf, 40, 1); // version
    wr32(buf, 44, size); // width
    wr32(buf, 48, size); // height
    wr32(buf, 52, 1); // xhot
    wr32(buf, 56, 2); // yhot
    wr32(buf, 60, 0); // delay
    // pixels start at 64; leave them zero except a marker.
    wr32(buf, 64, 0xAABBCCDD);
    return buf[0..total];
}

test "xcursor: parses a well-formed file and reads the image header" {
    var buf: [16 + 12 + 36 + 24 * 24 * 4]u8 = undefined;
    const file = synth(&buf, 24);
    const img = bestImage(file, 24) orelse return error.TestUnexpectedResult;
    try testing.expectEqual(@as(u32, 24), img.width);
    try testing.expectEqual(@as(u32, 24), img.height);
    try testing.expectEqual(@as(u32, 1), img.xhot);
    try testing.expectEqual(@as(u32, 2), img.yhot);
    try testing.expectEqual(@as(usize, 24 * 24 * 4), img.pixels.len);
    try testing.expectEqual(@as(u8, 0xDD), img.pixels[0]); // first pixel, LE byte 0
}

test "xcursor: rejects non-Xcursor and truncated files (ordinary null, no crash)" {
    try testing.expect(bestImage("not a cursor", 24) == null);
    try testing.expect(bestImage(&[_]u8{0} ** 8, 24) == null);
    // A header that claims an image at a position past EOF → null, not a read OOB.
    var buf: [16 + 12]u8 = undefined;
    @memset(&buf, 0);
    @memcpy(buf[0..4], "Xcur");
    wr32(&buf, 4, 16);
    wr32(&buf, 12, 1);
    wr32(&buf, 16, image_type);
    wr32(&buf, 20, 24);
    wr32(&buf, 24, 9999); // position past EOF
    try testing.expect(bestImage(&buf, 24) == null);
}
