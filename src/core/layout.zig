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

//! B1 classification: CORE (pure). Layout — the module that hides the
//! decision "what the app looks like" (D1, PHASE5_GUI_ROADMAP §2). The
//! palette, the style semantics, and where every glyph sits on screen
//! are decided here and nowhere else; raster paints what it is told and
//! has no opinions.
//!
//! Cut 5.0 shape: the input is still the cell Surface the app already
//! builds (timeline_ui et al.) — this module turns it into the flat
//! draw list raster consumes. That keeps the carve a pure refactor:
//! same screens, same pixels, new seam. Later cuts move real layout
//! here (5.3: pixel dimensions + scale as inputs; 5.2: hit rectangles
//! alongside the draw list; 5.6: view-model layout, where the cell grid
//! finally dissolves). The interface that crosses out is plain values
//! only: a draw list in, nothing else (B5/D3).
//!
//! Pure in the B2 sense: same surface ⇒ same draw list. The one
//! allocation (growing the list) takes an explicit allocator and is
//! visible at the call site (C1/C2); steady-state frames reuse capacity
//! and allocate nothing.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const tui = @import("tui.zig");
const text = @import("text.zig");
const raster = @import("raster.zig");

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
// Input — the OS-agnostic event vocabulary (Phase 5.1, GUI roadmap §3.1)
// ---------------------------------------------------------------------------

/// One OS input event, OS-agnostic. The shells fill these from X11
/// Button/Motion events (or Win32/AppKit equivalents) and hand the core
/// a flat slice each frame (B5). Layout owns the type because layout is
/// the consumer that gives positions meaning — hit-testing (Cut 5.2) is
/// pure core here, never shell guesswork. HOT — arrives in quantity on
/// drag/scroll → A7.
///
/// Cut 5.1 produces mouse kinds only; `.key` exists so keyboard input
/// can ride this same channel when layout starts consuming input — the
/// terminal-byte path stays authoritative for keys until then.
pub const InputEvent = struct {
    x: u16, // pointer position in window pixels
    y: u16,
    kind: Kind,
    /// 1=left 2=middle 3=right; for `.wheel`, 4=up 5=down.
    button: u8,
    /// Modifier bitset, in X11 mask positions on every OS (the Win32
    /// and AppKit shells translate INTO these bits): shift=0x01,
    /// control=0x04, alt(Mod1)=0x08.
    mods: u8,
    _pad: u8, // A6: explicit, keeps the struct at a round 8

    pub const Kind = enum(u8) { move, button_down, button_up, key, wheel };

    pub const mod_shift: u8 = 0x01;
    pub const mod_control: u8 = 0x04;
    pub const mod_alt: u8 = 0x08; // X11 Mod1

    comptime {
        // Budget: 2+2+1+1+1+1 = 8 bytes, exact. Bumping needs A7.1.
        assert(@sizeOf(InputEvent) == 8);
    }
};

/// The pointer SHAPE a window backend should show. A plain-data affordance
/// decision — WHICH cursor — made in the shell from the frame's hit-tests and
/// mapped to a native OS cursor by each backend (the B-split: the decision is
/// data here; turning it into an X11 glyph / IDC_* / NSCursor is the backend's
/// I/O). One vocabulary on every OS, like InputEvent's modifier bits.
///   default = the arrow · pointer = the hand (over clickable links/buttons)
///   text    = the I-beam (over selectable/editable text)
///   grab    = the move/grab hand (while dragging, e.g. a lens card)
pub const Cursor = enum(u8) { default, pointer, text, grab, heart };

// ---------------------------------------------------------------------------
// Surface → draw list (the Cut 5.0 layout)
// ---------------------------------------------------------------------------

/// Rebuild the draw list from the cell surface: one GlyphItem per
/// non-empty cell, positioned at (cx·cell_w, cy·cell_h), colors
/// resolved. Codepoint 0 (continuation of a wide glyph) emits nothing,
/// exactly as the pre-carve renderer skipped it.
///
/// The list is cleared and refilled wholesale each frame (the immediate-
/// mode shape, §1 of the GUI roadmap); capacity is reserved once up
/// front so the fill loop never branches on growth. Pixel coordinates
/// fit u16 by protocol: X11/Win32 window dimensions are themselves u16,
/// so cx·cell_w ≤ window width ≤ 65535.
pub fn fromSurface(
    gpa: Allocator,
    list: *raster.DrawList,
    surface: *const tui.Surface,
) error{OutOfMemory}!void {
    list.clearRetainingCapacity();
    const cols = surface.width;
    const rows = surface.height;
    try list.ensureTotalCapacity(gpa, @as(usize, cols) * rows);
    const m = text.metrics(text.cell_h);
    var cy: u16 = 0;
    while (cy < rows) : (cy += 1) {
        var cx: u16 = 0;
        while (cx < cols) : (cx += 1) {
            const cell = @as(usize, cy) * cols + cx;
            const codepoint = surface.chars.items[cell];
            if (codepoint == 0) continue; // continuation of a wide glyph
            const colors = resolveStyle(surface.styles.items[cell]);
            list.appendAssumeCapacity(.{ .cell = .{
                .x = @intCast(@as(u32, cx) * m.cell_w),
                .y = @intCast(@as(u32, cy) * m.cell_h),
                .codepoint = codepoint,
                .fg = colors.fg,
                .bg = colors.bg,
            } });
        }
    }
}

// ---------------------------------------------------------------------------
// Tests (B2, C6)
// ---------------------------------------------------------------------------

const testing = std.testing;

// Test-only import: the golden reference below is rebuilt from the raw
// font asset so the double stays strict (SESSION_FINDINGS §3.2 — a fake
// that models reality loosely misdirects). Module code keeps going
// through text.zig; only the reference renderer may touch the asset (D3).
const font_asset = @import("font.zig");

test "seam end-to-end: a glyph lands pixel-exact, styles resolve, inverse swaps" {
    const gpa = testing.allocator; // C6
    var surface: tui.Surface = .{};
    defer tui.deinitSurface(gpa, &surface);
    try tui.resizeSurface(gpa, &surface, 2, 1);
    _ = tui.putText(&surface, 0, 0, .{ .fg = .cyan }, "A");
    _ = tui.putText(&surface, 1, 0, .{ .fg = .red, .inverse = true }, "B");

    var list: raster.DrawList = .empty;
    defer list.deinit(gpa);
    var fb: raster.Framebuffer = .{};
    defer raster.deinit(gpa, &fb);
    try raster.resize(gpa, &fb, 16, 16, palette_bg);

    try fromSurface(gpa, &list, &surface);
    try raster.paint(gpa, null, list.slice(), &fb, palette_bg);

    // Every set bit of 'A' must be cyan, every clear bit background —
    // checked against the embedded bitmap itself, row by row.
    const a_rows = font_asset.glyph('A');
    var row: u32 = 0;
    while (row < 16) : (row += 1) {
        var col: u32 = 0;
        while (col < 8) : (col += 1) {
            const on = (a_rows[row] >> @intCast(7 - col)) & 1 == 1;
            const pixel = fb.pixels[row * fb.width + col];
            try testing.expectEqual(if (on) palette[7] else palette_bg, pixel);
        }
    }

    // Inverse: 'B' cell's CLEAR bits carry the red foreground as bg.
    const b_rows = font_asset.glyph('B');
    var found_bg_red = false;
    var col: u32 = 0;
    while (col < 8) : (col += 1) {
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

test "golden equivalence: the new pipeline matches the pre-carve renderer byte for byte" {
    // The strongest "no behavior change" proof Cut 5.0 can offer: the
    // pre-carve algorithm, reimplemented here verbatim as the golden
    // reference, against the layout→raster pipeline over a surface that
    // exercises every style bit, the wide-glyph zero cell, and the
    // replacement fallback. Full-framebuffer comparison, every pixel.
    const gpa = testing.allocator;
    var surface: tui.Surface = .{};
    defer tui.deinitSurface(gpa, &surface);
    try tui.resizeSurface(gpa, &surface, 12, 3);
    _ = tui.putText(&surface, 0, 0, .{ .fg = .cyan }, "zat");
    _ = tui.putText(&surface, 4, 0, .{ .fg = .red, .bold = true }, "BOLD");
    _ = tui.putText(&surface, 0, 1, .{ .fg = .white, .dim = true }, "dim");
    _ = tui.putText(&surface, 4, 1, .{ .fg = .green, .inverse = true }, "inv");
    _ = tui.putText(&surface, 8, 1, .{ .fg = .default, .bold = true }, "W");
    _ = tui.putText(&surface, 0, 2, .{}, "\u{4E2D}"); // wide: glyph + zero cell

    const w: u32 = 12 * 8;
    const h: u32 = 3 * 16;

    // --- the new pipeline ---
    var list: raster.DrawList = .empty;
    defer list.deinit(gpa);
    var fb: raster.Framebuffer = .{};
    defer raster.deinit(gpa, &fb);
    try raster.resize(gpa, &fb, w, h, palette_bg);
    try fromSurface(gpa, &list, &surface);
    try raster.paint(gpa, null, list.slice(), &fb, palette_bg);

    // --- the pre-carve reference, verbatim ---
    const golden = try gpa.alloc(u32, w * h);
    defer gpa.free(golden);
    @memset(golden, palette_bg);
    var cy: u16 = 0;
    while (cy < surface.height) : (cy += 1) {
        var cx: u16 = 0;
        while (cx < surface.width) : (cx += 1) {
            const cell = @as(usize, cy) * surface.width + cx;
            const cp = surface.chars.items[cell];
            if (cp == 0) continue;
            const colors = resolveStyle(surface.styles.items[cell]);
            const px = @as(u32, cx) * 8;
            const py = @as(u32, cy) * 16;
            if (px + 8 > w or py + 16 > h) continue;
            const rows = font_asset.glyph(cp);
            var row: u32 = 0;
            while (row < 16) : (row += 1) {
                const bits = rows[row];
                const base = @as(usize, py + row) * w + px;
                var col: u32 = 0;
                while (col < 8) : (col += 1) {
                    const on = (bits >> @intCast(7 - col)) & 1 == 1;
                    golden[base + col] = if (on) colors.fg else colors.bg;
                }
            }
        }
    }

    try testing.expectEqualSlices(u32, golden, fb.pixels);
}

// ===========================================================================
// THE MODERN TIMELINE (pixel-space layout — GUI roadmap cuts 5.2/5.3/
// 5.5/5.6, landed together per the §7 amendment). This section is the
// look: theme, type scale, card geometry, hit zones. Raster paints what
// it is told; everything visual is decided here and only here (D1).
// ===========================================================================

const feed = @import("feed.zig");
const moderation = @import("moderation.zig");
const timeline_ui = @import("timeline_ui.zig");

/// The window theme: a named palette. A7.2: not a record — a namespace
/// of comptime constants; no instances ever exist, so there is no size
/// to guard.
pub const theme = struct {
    pub const bg: u32 = 0xFF0E1116;
    pub const surface: u32 = 0xFF161B22;
    pub const surface_hover: u32 = 0xFF1B212B;
    pub const surface_sel: u32 = 0xFF1E2733;
    pub const hairline: u32 = 0xFF232B36;
    pub const ink: u32 = 0xFFE7EAF0;
    pub const ink_dim: u32 = 0xFF8B94A3;
    pub const ink_faint: u32 = 0xFF5C6470;
    pub const accent: u32 = 0xFF6CA8FF;
    pub const like: u32 = 0xFFFF6B81;
    pub const boost: u32 = 0xFF7BD88F;
    pub const pill: u32 = 0xF01B212B; // translucent status pill
};

/// One clickable region produced by layout (GUI roadmap §3.2). HOT —
/// one per interactive element per frame, rebuilt wholesale → A7;
/// held as struct-of-arrays via HitList (A3). `target` is a row index
/// into THIS frame's items — it never crosses further than the shell's
/// dispatch, which immediately converts it to selection state (A5: the
/// CID remains the id that crosses module boundaries; the index dies
/// with the frame).
pub const HitRect = struct {
    x: u16,
    y: u16,
    w: u16,
    h: u16,
    action: u16, // @intFromEnum(timeline_ui.Action); .none = select only
    _pad: u16 = 0, // A6: explicit
    target: u32,

    comptime {
        // Budget: 4×2 + 2 + 2 + 4 = 16 bytes, exact (A7).
        assert(@sizeOf(HitRect) == 16);
    }
};

pub const HitList = std.MultiArrayList(HitRect);

pub const no_target: u32 = std.math.maxInt(u32);

/// A resolved click. A7.2: cold struct, size guard waived — returned by
/// value from hitTest, never held.
pub const Hit = struct {
    action: timeline_ui.Action,
    target: u32,
};

/// Pure (B2): point + this frame's rects ⇒ the topmost hit. Later rects
/// win (zones are pushed after their card), so the scan runs in reverse.
pub fn hitTest(x: u16, y: u16, rects: HitList.Slice) ?Hit {
    const xs = rects.items(.x);
    const ys = rects.items(.y);
    const ws = rects.items(.w);
    const hs = rects.items(.h);
    const actions = rects.items(.action);
    const targets = rects.items(.target);
    var i: usize = rects.len;
    while (i > 0) {
        i -= 1;
        if (x >= xs[i] and x < xs[i] + ws[i] and y >= ys[i] and y < ys[i] + hs[i]) {
            return .{ .action = @enumFromInt(actions[i]), .target = targets[i] };
        }
    }
    return null;
}

/// Pixel-path view state, owned by the shell's loop and consumed here.
/// A7.2: cold struct, size guard waived — one per running window.
pub const ViewState = struct {
    scroll_px: i32 = 0,
    hover: u32 = no_target,
    /// Set by key navigation; buildTimeline scrolls the selection into
    /// view exactly once and clears it. Wheel scrolling never sets it,
    /// so reading older posts is never yanked back to the cursor.
    ensure_selected: bool = false,
};

/// What one frame's layout learned. A7.2: cold struct, waived.
pub const TimelineMetrics = struct {
    content_h: u32,
};

/// The type scale, derived from window height (roadmap §5: scale is an
/// INPUT to pure layout; resize relayouts for free). A7.2: cold, waived.
const TypeScale = struct {
    body: u32,
    name: u32,
    small: u32,
};

fn typeScale(h: u32) TypeScale {
    const body: u32 = @max(15, @min(20, 13 + h / 160));
    return .{ .body = body, .name = body + 1, .small = body - 2 };
}

/// Per-frame measurement context: one (weight, size) pair with its
/// ASCII fast table. A7.2: cold struct, waived — three per frame, stack.
const Meas = struct {
    engine: *text.Engine,
    weight: text.Weight,
    px: u32,
    ascii: [128]u16,

    fn init(engine: *text.Engine, weight: text.Weight, px: u32) Meas {
        var m: Meas = .{ .engine = engine, .weight = weight, .px = px, .ascii = undefined };
        text.asciiAdvances(engine, weight, px, &m.ascii);
        return m;
    }

    fn cp(m: *const Meas, codepoint: u32) u32 {
        if (codepoint < 128) return m.ascii[codepoint];
        return text.advance(m.engine, m.weight, codepoint, m.px);
    }

    fn width(m: *const Meas, str: []const u8) u32 {
        var total: u32 = 0;
        var it = utf8Iter(str);
        while (it.next()) |c| total += m.cp(c);
        return total;
    }
};

/// Tolerant UTF-8 cursor (invalid bytes skipped, E4). A7.2: cold
/// struct, size guard waived — one per measured string, stack-only.
const Utf8 = struct {
    str: []const u8,
    i: usize = 0,
    fn next(self: *Utf8) ?u32 {
        while (self.i < self.str.len) {
            const n = std.unicode.utf8ByteSequenceLength(self.str[self.i]) catch {
                self.i += 1;
                continue;
            };
            if (self.i + n > self.str.len) {
                self.i = self.str.len;
                return null;
            }
            const c = std.unicode.utf8Decode(self.str[self.i..][0..n]) catch {
                self.i += 1;
                continue;
            };
            self.i += n;
            return c;
        }
        return null;
    }
};

fn utf8Iter(str: []const u8) Utf8 {
    return .{ .str = str };
}

/// Greedy word wrap at pixel widths; long words hard-split by advance.
/// Returns the byte length of the next line of `str` fitting `max_w`.
fn wrapLine(m: *const Meas, str: []const u8, max_w: u32) usize {
    if (str.len == 0) return 0;
    var w: u32 = 0;
    var last_space: usize = 0;
    var it = utf8Iter(str);
    var prev_i: usize = 0;
    while (true) {
        prev_i = it.i;
        const c = it.next() orelse return str.len;
        if (c == '\n') return prev_i + 1; // hard break; the \n is consumed
        w += m.cp(c);
        if (c == ' ') last_space = it.i;
        if (w > max_w and prev_i > 0) {
            return if (last_space > 0) last_space else prev_i;
        }
    }
}

fn pushText(
    gpa: Allocator,
    dl: *raster.DrawList,
    m: *const Meas,
    x: i32,
    baseline: i32,
    color: u32,
    str: []const u8,
) error{OutOfMemory}!u32 {
    var pen: i32 = x;
    var it = utf8Iter(str);
    while (it.next()) |c| {
        if (c != ' ' and c != '\n') try dl.append(gpa, .{ .text = .{
            .x = @intCast(@max(-32768, @min(32767, pen))),
            .baseline = @intCast(@max(-32768, @min(32767, baseline))),
            .codepoint = c,
            .color = color,
            .px = @intCast(m.px),
            .weight = @intFromEnum(m.weight),
        } });
        pen += @intCast(m.cp(c));
    }
    return @intCast(pen - x);
}

fn pushRect(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, w: u32, h: u32, color: u32, radius: u8) error{OutOfMemory}!void {
    if (w == 0 or h == 0) return;
    try dl.append(gpa, .{ .rect = .{
        .x = @intCast(@max(-32768, @min(32767, x))),
        .y = @intCast(@max(-32768, @min(32767, y))),
        .w = @intCast(@min(w, 65535)),
        .h = @intCast(@min(h, 65535)),
        .color = color,
        .radius = radius,
    } });
}

fn pushHit(gpa: Allocator, hr: *HitList, x: i32, y: i32, w: u32, h: u32, action: timeline_ui.Action, target: u32, view_w: u32, view_h: u32) error{OutOfMemory}!void {
    // Clip to the viewport: hit rects are unsigned screen-space.
    if (x >= view_w or y >= view_h) return;
    const cx: u32 = @intCast(@max(0, x));
    const cy: u32 = @intCast(@max(0, y));
    const x2: i64 = @as(i64, x) + w;
    const y2: i64 = @as(i64, y) + h;
    if (x2 <= 0 or y2 <= 0) return;
    const cw: u32 = @intCast(@min(@as(i64, view_w), x2) - cx);
    const ch: u32 = @intCast(@min(@as(i64, view_h), y2) - cy);
    if (cw == 0 or ch == 0) return;
    try hr.append(gpa, .{
        .x = @intCast(cx),
        .y = @intCast(cy),
        .w = @intCast(cw),
        .h = @intCast(ch),
        .action = @intFromEnum(action),
        .target = target,
    });
}

fn isRevealed(revealed: []const []const u8, cid: []const u8) bool {
    for (revealed) |r| if (std.mem.eql(u8, r, cid)) return true;
    return false;
}

/// Geometry of one frame. A7.2: cold, waived — stack scratch.
const Geo = struct {
    w: u32,
    h: u32,
    col_x: i32,
    col_w: u32,
    pad: u32,
    gap: u32,
    header_h: u32,
    body_line: u32,
    name_line: u32,
    small_line: u32,
    body_asc: i32,
    name_asc: i32,
    small_asc: i32,
};

/// One card's measured shape. A7.2: cold, waived — stack scratch.
const CardShape = struct {
    h: u32,
    hidden: bool,
};

fn measureCard(g: *const Geo, body: *const Meas, item: feed.TimelineItem, revealed: []const []const u8) CardShape {
    if (moderation.verdictFor(item.label_flags) == .hide and !isRevealed(revealed, item.cid)) {
        return .{ .h = g.pad * 2 + g.small_line, .hidden = true };
    }
    var h: u32 = g.pad; // top pad
    if (item.reposted_by_handle.len > 0) h += g.small_line;
    h += g.name_line;
    if (item.replying_to_handle.len > 0) h += g.small_line;
    h += 4; // name → body breath
    const max_w = g.col_w - 2 * g.pad;
    var rest = item.text;
    if (rest.len == 0) {
        // No body: collapse the breath, keep the counts row legible.
        h -= 4;
    } else while (rest.len > 0) {
        const n = wrapLine(body, rest, max_w);
        h += g.body_line;
        rest = rest[@max(n, 1)..];
    }
    h += 6 + g.small_line; // counts row
    h += g.pad; // bottom pad
    return .{ .h = h, .hidden = false };
}

/// Build the modern timeline frame: draw list + hit rects from plain
/// view-models, at pixel granularity, scaled from the window size.
/// Deterministic over its inputs; mutates only its out-params and the
/// view's scroll (clamped, plus the one-shot ensure_selected — the same
/// out-param posture timeline_ui.buildFrame already takes with UiState).
/// Two passes: measure everything, then emit only what intersects the
/// viewport (culling keeps the list proportional to the screen, not the
/// feed).
pub fn buildTimeline(
    gpa: Allocator,
    engine: *text.Engine,
    dl: *raster.DrawList,
    hr: *HitList,
    items: []const feed.TimelineItem,
    selected: u32,
    view: *ViewState,
    revealed: []const []const u8,
    now: i64,
    account_handle: []const u8,
    status: []const u8,
    width: u32,
    height: u32,
) error{OutOfMemory}!TimelineMetrics {
    dl.clearRetainingCapacity();
    hr.clearRetainingCapacity();
    if (width < 120 or height < 80) return .{ .content_h = 0 };

    const ts = typeScale(height);
    var body = Meas.init(engine, .regular, ts.body);
    var name = Meas.init(engine, .semibold, ts.name);
    var small = Meas.init(engine, .regular, ts.small);
    const body_lm = text.lineMetrics(engine, .regular, ts.body);
    const name_lm = text.lineMetrics(engine, .semibold, ts.name);
    const small_lm = text.lineMetrics(engine, .regular, ts.small);

    var g: Geo = .{
        .w = width,
        .h = height,
        .col_w = @min(width -| 32, 880),
        .col_x = 0,
        .pad = 14,
        .gap = 10,
        .header_h = name_lm.height + 20,
        .body_line = body_lm.height,
        .name_line = name_lm.height,
        .small_line = small_lm.height,
        .body_asc = body_lm.ascent,
        .name_asc = name_lm.ascent,
        .small_asc = small_lm.ascent,
    };
    g.col_x = @intCast((width - g.col_w) / 2);

    // ---- pass 1: heights, content extent, selection position ----
    var content_h: u32 = g.header_h + g.gap;
    var sel_top: u32 = content_h;
    var sel_h: u32 = 0;
    const footer_h: u32 = g.small_line + 2 * g.gap; // the load-older row
    for (items, 0..) |item, i| {
        const shape = measureCard(&g, &body, item, revealed);
        if (i == selected) {
            sel_top = content_h;
            sel_h = shape.h;
        }
        content_h += shape.h + g.gap;
    }
    if (items.len > 0) content_h += footer_h;

    // ---- scroll resolution: clamp, then honor ensure_selected once ----
    const max_scroll: i32 = @intCast(content_h -| height);
    if (view.ensure_selected and items.len > 0) {
        view.ensure_selected = false;
        const margin: i32 = @intCast(g.gap);
        const top: i32 = @intCast(sel_top);
        const bottom: i32 = top + @as(i32, @intCast(sel_h));
        if (top - margin < view.scroll_px) view.scroll_px = top - margin;
        if (bottom + margin > view.scroll_px + @as(i32, @intCast(height)))
            view.scroll_px = bottom + margin - @as(i32, @intCast(height));
    }
    view.scroll_px = @max(0, @min(view.scroll_px, @max(0, max_scroll)));

    // ---- pass 2: emit ----
    const scroll = view.scroll_px;

    // Header band (fixed — does not scroll): wordmark, account, tally.
    try pushRect(gpa, dl, 0, 0, width, g.header_h, theme.bg, 0);
    var hx: i32 = g.col_x;
    const head_base: i32 = @intCast((g.header_h - g.name_line) / 2 + @as(u32, @intCast(g.name_asc)));
    hx += @intCast(try pushText(gpa, dl, &name, hx, head_base, theme.accent, "Zat4"));
    if (account_handle.len > 0) {
        hx += 8; // breath after the wordmark
        hx += @intCast(try pushText(gpa, dl, &small, hx, head_base, theme.ink_dim, "@"));
        hx += @intCast(try pushText(gpa, dl, &small, hx, head_base, theme.ink_dim, account_handle));
    }
    var tally_buf: [32]u8 = undefined;
    const tally = std.fmt.bufPrint(&tally_buf, "{d} posts", .{items.len}) catch "";
    const tally_w = small.width(tally);
    _ = try pushText(gpa, dl, &small, g.col_x + @as(i32, @intCast(g.col_w - tally_w)), head_base, theme.ink_faint, tally);
    try pushRect(gpa, dl, 0, @intCast(g.header_h - 1), width, 1, theme.hairline, 0);

    if (items.len == 0) {
        const msg = "timeline is empty - press r to refresh";
        const mw = body.width(msg);
        _ = try pushText(gpa, dl, &body, @intCast((width - mw) / 2), @intCast(height / 2), theme.ink_dim, msg);
        return .{ .content_h = content_h };
    }

    var y: i32 = @as(i32, @intCast(g.header_h + g.gap)) - scroll;
    for (items, 0..) |item, idx| {
        const i: u32 = @intCast(idx);
        const shape = measureCard(&g, &body, item, revealed);
        const card_h = shape.h;
        defer y += @intCast(card_h + g.gap);
        if (y + @as(i32, @intCast(card_h)) <= @as(i32, @intCast(g.header_h)) or y >= @as(i32, @intCast(height))) continue; // culled

        const is_sel = i == selected;
        const surface_color: u32 = if (is_sel) theme.surface_sel else if (view.hover == i) theme.surface_hover else theme.surface;
        try pushRect(gpa, dl, g.col_x, y, g.col_w, card_h, surface_color, 10);
        if (is_sel) try pushRect(gpa, dl, g.col_x, y + 8, 3, card_h -| 16, theme.accent, 1);
        // Whole-card hit: select on click (action .none carries target).
        try pushHit(gpa, hr, g.col_x, y, g.col_w, card_h, .none, i, width, height);

        const tx: i32 = g.col_x + @as(i32, @intCast(g.pad));
        const inner_w: u32 = g.col_w - 2 * g.pad;
        var cy: i32 = y + @as(i32, @intCast(g.pad));

        if (shape.hidden) {
            var hid_buf: [128]u8 = undefined;
            const label = std.fmt.bufPrint(&hid_buf, "hidden: {s} - click to show", .{moderation.reasonFor(item.label_flags)}) catch "hidden - click to show";
            _ = try pushText(gpa, dl, &small, tx, cy + g.small_asc, theme.ink_faint, label);
            try pushHit(gpa, hr, g.col_x, y, g.col_w, card_h, .toggle_reveal, i, width, height);
            continue;
        }

        if (item.reposted_by_handle.len > 0) {
            var rb: [160]u8 = undefined;
            const line = std.fmt.bufPrint(&rb, "reposted by @{s}", .{item.reposted_by_handle}) catch "reposted";
            _ = try pushText(gpa, dl, &small, tx, cy + g.small_asc, theme.boost, line);
            cy += @intCast(g.small_line);
        }

        // Author row: name semibold, handle dim, age right-aligned.
        {
            var x = tx;
            const nb = cy + g.name_asc;
            if (item.author_display_name.len > 0) {
                x += @intCast(try pushText(gpa, dl, &name, x, nb, if (is_sel) theme.accent else theme.ink, item.author_display_name));
                x += 6;
            }
            var hb: [160]u8 = undefined;
            const handle = std.fmt.bufPrint(&hb, "@{s}", .{item.author_handle}) catch "@";
            if (item.author_display_name.len > 0) {
                x += @intCast(try pushText(gpa, dl, &small, x, nb, theme.ink_dim, handle));
            } else {
                x += @intCast(try pushText(gpa, dl, &name, x, nb, if (is_sel) theme.accent else theme.ink, handle));
            }
            var age_buf: [16]u8 = undefined;
            const age = timeline_ui.formatAge(&age_buf, now, item.created_at);
            const aw = small.width(age);
            _ = try pushText(gpa, dl, &small, tx + @as(i32, @intCast(inner_w - aw)), nb, theme.ink_faint, age);
            cy += @intCast(g.name_line);
        }

        if (item.replying_to_handle.len > 0) {
            var rb: [160]u8 = undefined;
            const line = std.fmt.bufPrint(&rb, "replying to @{s}", .{item.replying_to_handle}) catch "replying";
            _ = try pushText(gpa, dl, &small, tx, cy + g.small_asc, theme.ink_faint, line);
            cy += @intCast(g.small_line);
        }

        if (item.text.len > 0) {
            cy += 4;
            var rest = item.text;
            while (rest.len > 0) {
                const n = wrapLine(&body, rest, inner_w);
                const line = std.mem.trimEnd(u8, rest[0..n], "\n");
                _ = try pushText(gpa, dl, &body, tx, cy + g.body_asc, theme.ink, line);
                cy += @intCast(g.body_line);
                rest = rest[@max(n, 1)..];
            }
        }

        // Engagement row: three labeled zones, the SAME actions the keys run.
        {
            cy += 6;
            const zb = cy + g.small_asc;
            var x = tx;
            var buf: [48]u8 = undefined;
            const zone_pad: u32 = 10;

            const likes = std.fmt.bufPrint(&buf, "likes {d}", .{item.like_count}) catch "likes";
            const lw = small.width(likes);
            _ = try pushText(gpa, dl, &small, x, zb, if (item.item_flags.viewer_liked) theme.like else theme.ink_dim, likes);
            try pushHit(gpa, hr, x - 4, cy - 4, lw + 8, g.small_line + 8, .like, i, width, height);
            x += @intCast(lw + 3 * zone_pad);

            const reposts = std.fmt.bufPrint(&buf, "reposts {d}", .{item.repost_count}) catch "reposts";
            const rw = small.width(reposts);
            _ = try pushText(gpa, dl, &small, x, zb, if (item.item_flags.viewer_reposted) theme.boost else theme.ink_dim, reposts);
            try pushHit(gpa, hr, x - 4, cy - 4, rw + 8, g.small_line + 8, .repost, i, width, height);
            x += @intCast(rw + 3 * zone_pad);

            const replies = std.fmt.bufPrint(&buf, "replies {d}", .{item.reply_count}) catch "replies";
            const pw = small.width(replies);
            _ = try pushText(gpa, dl, &small, x, zb, theme.ink_dim, replies);
            try pushHit(gpa, hr, x - 4, cy - 4, pw + 8, g.small_line + 8, .reply, i, width, height);
        }
    }

    // Load-older row at the very bottom of the content.
    {
        const label = "load older posts";
        const lw2 = small.width(label);
        const ly: i32 = @as(i32, @intCast(content_h - footer_h + g.gap)) - scroll;
        if (ly < height and ly + @as(i32, @intCast(g.small_line)) > 0) {
            const lx: i32 = @intCast((width - lw2) / 2);
            _ = try pushText(gpa, dl, &small, lx, ly + g.small_asc, theme.ink_faint, label);
            try pushHit(gpa, hr, lx - 12, ly - 6, lw2 + 24, g.small_line + 12, .load_more, no_target, width, height);
        }
    }

    // Status pill, floating bottom-right.
    if (status.len > 0) {
        const sw = small.width(status);
        const ph: u32 = g.small_line + 12;
        const pw2: u32 = sw + 24;
        const px: i32 = @intCast(width -| (pw2 + 16));
        const py: i32 = @intCast(height -| (ph + 16));
        try pushRect(gpa, dl, px, py, pw2, ph, theme.pill, @intCast(ph / 2));
        _ = try pushText(gpa, dl, &small, px + 12, py + 6 + g.small_asc, theme.accent, status);
    }

    return .{ .content_h = content_h };
}

/// One wheel notch in pixels, scaled with the type (pure).
pub fn wheelStep(engine: *const text.Engine, height: u32) i32 {
    const ts = typeScale(height);
    return @intCast(text.lineMetrics(engine, .regular, ts.body).height * 3);
}

// ---------------------------------------------------------------------------
// Pixel-timeline tests (B2, C6)
// ---------------------------------------------------------------------------

test "hitTest: topmost wins, misses return null" {
    const gpa = testing.allocator;
    var hr: HitList = .empty;
    defer hr.deinit(gpa);
    try hr.append(gpa, .{ .x = 10, .y = 10, .w = 100, .h = 50, .action = @intFromEnum(timeline_ui.Action.none), .target = 7 });
    try hr.append(gpa, .{ .x = 20, .y = 20, .w = 30, .h = 10, .action = @intFromEnum(timeline_ui.Action.like), .target = 7 });

    const zone = hitTest(25, 25, hr.slice()).?;
    try testing.expectEqual(timeline_ui.Action.like, zone.action);
    const card = hitTest(15, 45, hr.slice()).?;
    try testing.expectEqual(timeline_ui.Action.none, card.action);
    try testing.expectEqual(@as(u32, 7), card.target);
    try testing.expect(hitTest(5, 5, hr.slice()) == null);
}

test "buildTimeline: cards, zones, scroll clamp, ensure-visible" {
    const gpa = testing.allocator; // C6
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    var dl: raster.DrawList = .empty;
    defer dl.deinit(gpa);
    var hr: HitList = .empty;
    defer hr.deinit(gpa);

    const items = [_]feed.TimelineItem{
        .{ .uri = "at://1", .cid = "c1", .author_handle = "alice.test", .author_display_name = "Alice", .reposted_by_handle = "", .replying_to_handle = "", .text = "the carve landed and the cards are real now", .created_at = 1_700_000_000, .like_count = 3, .repost_count = 1, .reply_count = 0, .quote_count = 0, .label_flags = .{}, .item_flags = .{ .viewer_liked = true } },
        .{ .uri = "at://2", .cid = "c2", .author_handle = "bob.test", .author_display_name = "", .reposted_by_handle = "alice.test", .replying_to_handle = "alice.test", .text = "a longer body that must wrap across several pixel lines once the column narrows enough to force the greedy breaker to do its actual job", .created_at = 1_700_000_100, .like_count = 0, .repost_count = 0, .reply_count = 2, .quote_count = 0, .label_flags = .{}, .item_flags = .{} },
    };

    var view: ViewState = .{};
    const m = try buildTimeline(gpa, &engine, &dl, &hr, &items, 0, &view, &.{}, 1_700_000_500, "me.test", "live", 640, 480);
    try testing.expect(m.content_h > 0);
    try testing.expect(dl.len > 20); // rects + many glyphs
    // Per visible card: 1 card hit + 3 zones (+ load-older).
    try testing.expect(hr.len >= 9);

    // Every zone's action round-trips to a key the dispatch understands.
    const actions = hr.slice().items(.action);
    var like_zones: usize = 0;
    for (actions) |a| {
        const action: timeline_ui.Action = @enumFromInt(a);
        if (action == .like) like_zones += 1;
        if (action != .none) try testing.expect(timeline_ui.keyFor(action) != null);
    }
    try testing.expectEqual(@as(usize, 2), like_zones);

    // Scroll clamps: a wild offset comes back into range.
    view.scroll_px = 1_000_000;
    _ = try buildTimeline(gpa, &engine, &dl, &hr, &items, 0, &view, &.{}, 1_700_000_500, "me.test", "", 640, 480);
    try testing.expect(view.scroll_px >= 0 and view.scroll_px <= @as(i32, @intCast(m.content_h)));

    // ensure_selected pulls the selection into view and clears itself.
    view.scroll_px = 0;
    view.ensure_selected = true;
    _ = try buildTimeline(gpa, &engine, &dl, &hr, &items, 1, &view, &.{}, 1_700_000_500, "me.test", "", 640, 200);
    try testing.expect(!view.ensure_selected);
    try testing.expect(view.scroll_px > 0); // card 1 was below the fold
}

test "buildTimeline: hidden cards collapse and expose only the reveal zone" {
    const gpa = testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    var dl: raster.DrawList = .empty;
    defer dl.deinit(gpa);
    var hr: HitList = .empty;
    defer hr.deinit(gpa);

    const flagged: moderation.LabelFlags = .{ .sexual = true };
    const items = [_]feed.TimelineItem{
        .{ .uri = "at://1", .cid = "c1", .author_handle = "x.test", .author_display_name = "", .reposted_by_handle = "", .replying_to_handle = "", .text = "should not appear", .created_at = 0, .like_count = 0, .repost_count = 0, .reply_count = 0, .quote_count = 0, .label_flags = flagged, .item_flags = .{} },
    };
    var view: ViewState = .{};
    _ = try buildTimeline(gpa, &engine, &dl, &hr, &items, 0, &view, &.{}, 100, "", "", 640, 480);
    const actions = hr.slice().items(.action);
    var reveal = false;
    var like = false;
    for (actions) |a| {
        const action: timeline_ui.Action = @enumFromInt(a);
        if (action == .toggle_reveal) reveal = true;
        if (action == .like) like = true;
    }
    try testing.expect(reveal);
    try testing.expect(!like); // a hidden card offers no engagement zones
}
