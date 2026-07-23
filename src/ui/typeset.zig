//! Rover · typeset — text placement math (baseline centering, alignment, ellipsis).
//!
//! PORTABLE (Rover rule): PURE, standalone, `std`-only. No renderer, no font engine,
//! no app types. The host measures glyphs with ITS OWN font engine and passes the
//! plain numbers in (a `Metrics` for the font, a slice of per-glyph advances for a
//! run); this returns where the BASELINE sits, where the run starts for an
//! alignment, and how to TRUNCATE with an ellipsis. The reusable artifact is the
//! typographic math — the browser's line-box baseline alignment and `text-overflow:
//! ellipsis`, expressed as free functions.
//!
//! Why this exists: "the text isn't vertically centered" is a recurring native-UI
//! bug because centering a text box by its pixel height ignores the font's ascent /
//! descent / cap-height. Metric-driven baselines fix it once, everywhere.
//!
//! All values are LOGICAL px; y grows downward; a baseline is the y the glyphs sit
//! ON (ascenders go up from it, descenders below).

const std = @import("std");
const assert = std.debug.assert;

/// PLAIN DATA (A1): a font's vertical metrics at a given size, as the host's font
/// engine reports them. Positive magnitudes: `ascent` above the baseline, `descent`
/// below, `cap_height` the height of a capital, `x_height` of lowercase, `line_gap`
/// the extra leading between lines.
pub const Metrics = struct {
    ascent: f32 = 0,
    descent: f32 = 0,
    cap_height: f32 = 0,
    x_height: f32 = 0,
    line_gap: f32 = 0,

    comptime {
        // Five f32, no padding.
        assert(@sizeOf(Metrics) == 20);
    }
};

/// The natural line height for this font: `ascent + descent + line_gap`.
pub fn lineHeight(m: Metrics) f32 {
    return m.ascent + m.descent + m.line_gap;
}

/// Baseline y that centers the font's EM BOX (ascent+descent) inside a box of height
/// `box_h` starting at `box_top`. Use when descenders should count toward centering
/// (e.g. a paragraph line).
pub fn baselineEmCentered(box_top: f32, box_h: f32, m: Metrics) f32 {
    const em = m.ascent + m.descent;
    return box_top + (box_h - em) / 2.0 + m.ascent;
}

/// Baseline y that OPTICALLY centers the CAP HEIGHT inside the box — the balanced
/// look for a button label, a chip, a single-line title, where you want the visible
/// letters centered regardless of descenders. This is the one most "not centered"
/// bugs actually want.
pub fn baselineCapCentered(box_top: f32, box_h: f32, m: Metrics) f32 {
    return box_top + box_h / 2.0 + m.cap_height / 2.0;
}

/// Horizontal alignment of a run of width `text_w` within `[box_x, box_x+box_w]`.
pub const Align = enum(u8) { left, center, right };

/// The run's start x for the given alignment. `center` rounds toward the left by
/// truncation of the half-gap (callers wanting pixel-crisp text can round).
pub fn alignX(box_x: f32, box_w: f32, text_w: f32, alignment: Align) f32 {
    return switch (alignment) {
        .left => box_x,
        .center => box_x + (box_w - text_w) / 2.0,
        .right => box_x + box_w - text_w,
    };
}

/// The total advance width of a run given its per-glyph advances.
pub fn runWidth(advances: []const f32) f32 {
    var w: f32 = 0;
    for (advances) |a| w += a;
    return w;
}

/// The count of leading glyphs whose cumulative advance fits within `max_w` (no
/// ellipsis). Stops at the first glyph that would overflow. `max_w <= 0` → 0.
pub fn fitPrefix(advances: []const f32, max_w: f32) u32 {
    if (max_w <= 0) return 0;
    var w: f32 = 0;
    var n: u32 = 0;
    for (advances) |a| {
        if (w + a > max_w) break;
        w += a;
        n += 1;
    }
    return n;
}

/// The result of an ellipsis fit: how many leading glyphs to draw, and whether an
/// ellipsis was needed (the run did not fit whole).
pub const Truncation = struct {
    count: u32 = 0,
    truncated: bool = false,
    // A7.2: cold — a per-call return value, never held in bulk.
};

/// Fit a run into `max_w`, appending an ellipsis (`ellipsis_w` wide) when it does
/// not fit whole. If the whole run fits, `truncated` is false and `count` is every
/// glyph. Otherwise `count` is the largest prefix whose width plus the ellipsis fits,
/// and `truncated` is true (the host draws `count` glyphs then the ellipsis). If not
/// even the ellipsis fits, `count` is 0 and `truncated` is true.
pub fn truncate(advances: []const f32, ellipsis_w: f32, max_w: f32) Truncation {
    if (runWidth(advances) <= max_w) {
        return .{ .count = @intCast(advances.len), .truncated = false };
    }
    // Does not fit whole: reserve room for the ellipsis, then fit the prefix.
    const budget = max_w - ellipsis_w;
    if (budget <= 0) return .{ .count = 0, .truncated = true };
    return .{ .count = fitPrefix(advances, budget), .truncated = true };
}

// ---------------------------------------------------------------------------

const expect = std.testing.expect;
const expectEq = std.testing.expectEqual;
const eps: f32 = 1.0e-4;

fn approx(a: f32, b: f32) bool {
    return @abs(a - b) < eps;
}

test "typeset: lineHeight sums ascent + descent + gap" {
    const m: Metrics = .{ .ascent = 18, .descent = 6, .line_gap = 4 };
    try expect(approx(lineHeight(m), 28));
}

test "typeset: em-centered baseline centers the ascent+descent box" {
    const m: Metrics = .{ .ascent = 18, .descent = 6, .cap_height = 14 };
    // box_top 100, box_h 50: (50 - 24)/2 + 18 = 13 + 18 = 31, + 100 = 131.
    try expect(approx(baselineEmCentered(100, 50, m), 131));
    // Symmetric sanity: the gap above the ascent equals the gap below the descent.
    const bl = baselineEmCentered(0, 40, m);
    const above = (bl - m.ascent) - 0; // top of glyph box to box top
    const below = 40 - (bl + m.descent); // bottom of glyph box to box bottom
    try expect(approx(above, below));
}

test "typeset: cap-centered baseline optically centers capitals" {
    const m: Metrics = .{ .ascent = 18, .descent = 6, .cap_height = 14 };
    // box_top 100, box_h 50: 100 + 25 + 7 = 132. Distinct from em-centered (131).
    try expect(approx(baselineCapCentered(100, 50, m), 132));
}

test "typeset: alignX places left/center/right" {
    try expect(approx(alignX(10, 100, 40, .left), 10));
    try expect(approx(alignX(10, 100, 40, .center), 40)); // 10 + (100-40)/2
    try expect(approx(alignX(10, 100, 40, .right), 70)); // 10 + 100 - 40
}

test "typeset: fitPrefix counts leading glyphs that fit" {
    const adv = [_]f32{ 10, 10, 10, 10 };
    try expectEq(@as(u32, 2), fitPrefix(&adv, 25)); // 10+10=20 fits, +10=30 doesn't
    try expectEq(@as(u32, 4), fitPrefix(&adv, 100)); // all fit
    try expectEq(@as(u32, 0), fitPrefix(&adv, 5)); // none fit
    try expectEq(@as(u32, 0), fitPrefix(&adv, -1)); // negative width
    try expectEq(@as(u32, 4), fitPrefix(&adv, 40)); // exact total fits
}

test "typeset: truncate keeps whole run when it fits, else ellipsizes" {
    const adv = [_]f32{ 10, 10, 10, 10 }; // total 40
    // Fits whole.
    const whole = truncate(&adv, 8, 100);
    try expectEq(@as(u32, 4), whole.count);
    try expect(!whole.truncated);
    // Needs ellipsis: budget 25 - 8 = 17 -> one glyph.
    const cut = truncate(&adv, 8, 25);
    try expectEq(@as(u32, 1), cut.count);
    try expect(cut.truncated);
    // Not even the ellipsis fits.
    const none = truncate(&adv, 8, 5);
    try expectEq(@as(u32, 0), none.count);
    try expect(none.truncated);
    // Exact fit is not truncated.
    const exact = truncate(&adv, 8, 40);
    try expectEq(@as(u32, 4), exact.count);
    try expect(!exact.truncated);
}

test "typeset: empty run is defined (no truncation, zero width)" {
    const empty = [_]f32{};
    try expect(approx(runWidth(&empty), 0));
    const t = truncate(&empty, 8, 100);
    try expectEq(@as(u32, 0), t.count);
    try expect(!t.truncated);
    try expectEq(@as(u32, 0), fitPrefix(&empty, 100));
}
