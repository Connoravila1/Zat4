//! B1 classification: CORE (pure). The rasterizer — the same cell
//! Surface the terminal renders becomes ARGB pixels for the window
//! backend. This is the whole trick of the pixel path: every screen the
//! app already knows how to draw (timeline, composer, status, keybar)
//! arrives here as plain cells and leaves as one flat u32 array. No new
//! UI logic, no second draw path to drift (D6).
//!
//! The framebuffer is the hot data and it is already the ideal shape:
//! one contiguous []u32, row-major, no structs to guard — the array IS
//! the layout (A3 in spirit; there is nothing to SoA).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const tui = @import("tui.zig");
const font = @import("font.zig");

/// A7.2: cold struct, size guard waived — one per window, never in a
/// collection. Its CONTENTS (pixels) are the hot array.
pub const Framebuffer = struct {
    width: u32 = 0,
    height: u32 = 0,
    /// 0xAARRGGBB, row-major, length = width * height. Caller-owned (C1).
    pixels: []u32 = &.{},
};

pub fn resize(gpa: Allocator, fb: *Framebuffer, width: u32, height: u32) error{OutOfMemory}!void {
    const count: usize = @as(usize, width) * height;
    if (fb.pixels.len != count) {
        gpa.free(fb.pixels);
        fb.pixels = try gpa.alloc(u32, count);
    }
    fb.width = width;
    fb.height = height;
    @memset(fb.pixels, palette_bg);
}

pub fn deinit(gpa: Allocator, fb: *Framebuffer) void {
    gpa.free(fb.pixels);
    fb.* = undefined;
}

// ---------------------------------------------------------------------------
// Palette — the terminal's 16 colors, given concrete pixels.
// One dark theme, chosen once: the window inherits zat's taste the way
// the terminal inherits the user's.
// ---------------------------------------------------------------------------

pub const palette_bg: u32 = 0xFF101014; // near-black, slightly blue
pub const palette_fg: u32 = 0xFFC8C8C8; // the `.default` foreground

const palette = [17]u32{
    palette_fg, //  0 default
    0xFF15151A, //  1 black
    0xFFCC6666, //  2 red
    0xFF9CB876, //  3 green
    0xFFE0C285, //  4 yellow
    0xFF81A2BE, //  5 blue
    0xFFB294BB, //  6 magenta
    0xFF8ABEB7, //  7 cyan
    0xFFC8C8C8, //  8 white
    0xFF666666, //  9 bright_black
    0xFFE08C8C, // 10 bright_red
    0xFFB5D68A, // 11 bright_green
    0xFFF0D9A0, // 12 bright_yellow
    0xFFA3C4E0, // 13 bright_blue
    0xFFD0B0D8, // 14 bright_magenta
    0xFFA8DCD4, // 15 bright_cyan
    0xFFF2F2F2, // 16 bright_white
};

/// Resolve a cell style to (fg, bg) pixels: bold brightens the eight base
/// colors, dim halves the foreground, inverse swaps — the same semantics
/// the terminal encoder gives these bits, expressed in ARGB.
pub fn resolveStyle(style: tui.Style) struct { fg: u32, bg: u32 } {
    var fg_index: usize = @intFromEnum(style.fg);
    if (style.bold and fg_index >= 1 and fg_index <= 8) fg_index += 8;
    var fg = palette[fg_index];
    if (style.bold and fg_index == 0) fg = palette[16];
    if (style.dim) fg = halve(fg);
    var bg = palette_bg;
    if (style.inverse) {
        const swap = fg;
        fg = bg;
        bg = swap;
    }
    return .{ .fg = fg, .bg = bg };
}

fn halve(argb: u32) u32 {
    return (argb & 0xFF000000) | ((argb >> 1) & 0x007F7F7F);
}

// ---------------------------------------------------------------------------
// Rasterize
// ---------------------------------------------------------------------------

/// Paint the whole surface into the framebuffer: cell (cx, cy) occupies
/// the glyph_w × glyph_h pixel block at (cx * 8, cy * 16). The buffer is
/// expected to be at least cols*8 × rows*16; extra margin keeps the
/// background. Pure: same surface ⇒ same pixels.
pub fn rasterize(surface: *const tui.Surface, fb: *Framebuffer) void {
    @memset(fb.pixels, palette_bg);
    const cols = surface.width;
    const rows = surface.height;
    var cy: u16 = 0;
    while (cy < rows) : (cy += 1) {
        var cx: u16 = 0;
        while (cx < cols) : (cx += 1) {
            const cell = @as(usize, cy) * cols + cx;
            const codepoint = surface.chars.items[cell];
            if (codepoint == 0) continue; // continuation of a wide glyph
            const colors = resolveStyle(surface.styles.items[cell]);
            drawGlyph(fb, @as(u32, cx) * font.glyph_w, @as(u32, cy) * font.glyph_h, codepoint, colors.fg, colors.bg);
        }
    }
}

fn drawGlyph(fb: *Framebuffer, px: u32, py: u32, codepoint: u32, fg: u32, bg: u32) void {
    if (px + font.glyph_w > fb.width or py + font.glyph_h > fb.height) return;
    const rows = font.glyph(codepoint);
    var row: u32 = 0;
    while (row < font.glyph_h) : (row += 1) {
        const bits = rows[row];
        const base = @as(usize, py + row) * fb.width + px;
        var col: u32 = 0;
        while (col < font.glyph_w) : (col += 1) {
            const on = (bits >> @intCast(7 - col)) & 1 == 1;
            fb.pixels[base + col] = if (on) fg else bg;
        }
    }
}

// ---------------------------------------------------------------------------
// Tests (B2, C6)
// ---------------------------------------------------------------------------

const testing = std.testing;

test "rasterize: a glyph lands pixel-exact, styles resolve, inverse swaps" {
    const gpa = testing.allocator; // C6
    var surface: tui.Surface = .{};
    defer tui.deinitSurface(gpa, &surface);
    try tui.resizeSurface(gpa, &surface, 2, 1);
    _ = tui.putText(&surface, 0, 0, .{ .fg = .cyan }, "A");
    _ = tui.putText(&surface, 1, 0, .{ .fg = .red, .inverse = true }, "B");

    var fb: Framebuffer = .{};
    defer deinit(gpa, &fb);
    try resize(gpa, &fb, 16, 16);
    rasterize(&surface, &fb);

    // Every set bit of 'A' must be cyan, every clear bit background —
    // checked against the embedded bitmap itself, row by row.
    const a_rows = font.glyph('A');
    var row: u32 = 0;
    while (row < font.glyph_h) : (row += 1) {
        var col: u32 = 0;
        while (col < font.glyph_w) : (col += 1) {
            const on = (a_rows[row] >> @intCast(7 - col)) & 1 == 1;
            const pixel = fb.pixels[row * fb.width + col];
            try testing.expectEqual(if (on) palette[7] else palette_bg, pixel);
        }
    }

    // Inverse: 'B' cell's CLEAR bits carry the red foreground as bg.
    const b_rows = font.glyph('B');
    var found_bg_red = false;
    var col: u32 = 0;
    while (col < font.glyph_w) : (col += 1) {
        const on = (b_rows[0] >> @intCast(7 - col)) & 1 == 1;
        if (!on) {
            try testing.expectEqual(palette[2], fb.pixels[8 + col]);
            found_bg_red = true;
        }
    }
    try testing.expect(found_bg_red);
}

test "resolveStyle: bold brightens, dim halves" {
    try testing.expectEqual(palette[10], resolveStyle(.{ .fg = .red, .bold = true }).fg);
    try testing.expectEqual(palette[16], resolveStyle(.{ .fg = .default, .bold = true }).fg);
    const dimmed = resolveStyle(.{ .fg = .white, .dim = true }).fg;
    try testing.expectEqual(halve(palette[8]), dimmed);
}
