//! Rover · tokens — the semantic scales a UI is described in.
//!
//! PORTABLE (Rover rule): PURE, standalone, `std`-only. No renderer, no app types.
//! This is the CONSISTENCY layer — the half of "looks right on the first try" that
//! is not position but *coherence*. A screen references NAMED ROLES on a scale
//! (`space(.md)`, `radius(.lg)`, `text(.title)`, `color(theme, .ink)`) instead of
//! magic numbers, so nothing is ever "slightly off" and changing a role reflows the
//! whole look at once. Light and dark are two `Theme` tables of the same roles.
//!
//! The VALUES here are the reference theme (proven in the Zat client); another
//! project swaps the `Theme` tables and the scale steps for its own brand. The
//! reusable artifact is the SHAPE — a spacing/radius/type scale and a set of
//! semantic color roles — not these particular bytes.
//!
//! Colors are plain `u32` ARGB (0xAARRGGBB), the same value vocabulary the host's
//! rasterizer already speaks; the module never draws them.

const std = @import("std");
const assert = std.debug.assert;

// ---------------------------------------------------------------------------
// Spacing — one grid, named steps. `space(.md)` is 12px. Using the named step
// (not a raw number) is the consistency lever: every gap/pad on the scale.
// ---------------------------------------------------------------------------

/// The base grid unit (px). Every spacing step is a multiple of it.
pub const grid: i32 = 4;

/// Named spacing steps on the 4px grid. Values ARE the pixel amounts, so
/// `@intFromEnum` is the resolved size.
pub const Space = enum(i32) {
    none = 0,
    xs = 4, // 1×  — hairline gaps, icon-to-label
    sm = 8, // 2×  — inside a chip, tight rows
    md = 12, // 3× — default padding inside a card
    lg = 16, // 4× — card-to-edge, section padding
    xl = 24, // 6× — between sections
    xxl = 32, // 8× — page gutters
    huge = 48, // 12× — hero spacing
};

/// The pixel amount of a spacing step.
pub inline fn space(s: Space) i32 {
    return @intFromEnum(s);
}

// ---------------------------------------------------------------------------
// Corner radius — a matching named scale. `pill` is "fully rounded".
// ---------------------------------------------------------------------------

pub const Radius = enum(i32) {
    none = 0,
    sm = 4, // chips, small controls
    md = 8, // buttons, inputs
    lg = 12, // cards, menus (the app's default card radius)
    xl = 16, // sheets, large surfaces
    pill = 1000, // fully rounded — the host clamps to half the smaller side
};

pub inline fn radius(r: Radius) i32 {
    return @intFromEnum(r);
}

// ---------------------------------------------------------------------------
// Type scale — roles, not sizes. Each role fixes size + line height + weight so
// vertical rhythm is consistent. `line_px` is the line box the host centers text
// within (baseline math lives in the `type` primitive; this is the metric source).
// ---------------------------------------------------------------------------

pub const Weight = enum { regular, semibold };

/// A resolved text style. Returned by value on demand (not held in bulk), so it is
/// a cold struct — size guard waived per A7.2.
pub const TextStyle = struct {
    size_px: i32,
    line_px: i32,
    weight: Weight,
    // A7.2: cold struct — produced on demand, never stored in a collection.
};

pub const TypeRole = enum {
    caption, // 12 — timestamps, meta
    footnote, // 13 — secondary labels
    body, // 15 — post body, the reading size
    callout, // 16 — emphasized body, primary buttons
    subhead, // 18 — row titles, section heads
    title, // 22 — screen titles
    display, // 28 — hero / wordmark
};

/// The style for a text role. Line heights are ~1.3–1.4× the size, rounded to the
/// grid's feel; monotonic in size across the roles (asserted in tests).
pub fn text(role: TypeRole) TextStyle {
    return switch (role) {
        .caption => .{ .size_px = 12, .line_px = 16, .weight = .regular },
        .footnote => .{ .size_px = 13, .line_px = 18, .weight = .regular },
        .body => .{ .size_px = 15, .line_px = 21, .weight = .regular },
        .callout => .{ .size_px = 16, .line_px = 22, .weight = .semibold },
        .subhead => .{ .size_px = 18, .line_px = 24, .weight = .semibold },
        .title => .{ .size_px = 22, .line_px = 28, .weight = .semibold },
        .display => .{ .size_px = 28, .line_px = 34, .weight = .semibold },
    };
}

// ---------------------------------------------------------------------------
// Color — semantic ROLES, resolved against a Theme. Never a raw hex at a call
// site. Two Theme tables (dark/light) carry the same roles; the host picks one.
// ---------------------------------------------------------------------------

pub const ColorRole = enum {
    canvas, // app background behind everything
    surface, // cards, menus, sheets
    surface_hover, // a surface under the pointer
    surface_sel, // a selected/active surface
    ink, // primary text
    muted, // secondary text
    faint, // tertiary text, placeholders
    border, // hairline card/control outline
    divider, // separator line (carries its own alpha)
    scrim, // modal backdrop (carries its own alpha)
    accent, // brand / primary action (runtime lens may override; this is the house default)
    on_accent, // ink drawn on top of an accent fill
    disabled_fill, // an inert control's fill
    disabled_ink, // an inert control's label
};

const n_roles = @typeInfo(ColorRole).@"enum".fields.len;

/// A complete color table: one ARGB value per role. Named fields (not an array) so
/// adding a role is a compile error until both themes and the accessor cover it.
pub const Theme = struct {
    canvas: u32,
    surface: u32,
    surface_hover: u32,
    surface_sel: u32,
    ink: u32,
    muted: u32,
    faint: u32,
    border: u32,
    divider: u32,
    scrim: u32,
    accent: u32,
    on_accent: u32,
    disabled_fill: u32,
    disabled_ink: u32,

    comptime {
        // One u32 per role, no padding. Guards against a role being dropped or a
        // stray field creeping in — the table stays exactly the role set.
        assert(@sizeOf(Theme) == n_roles * 4);
    }
};

/// The shared house accent (site-default orange). Both themes reference it so a
/// change is one edit; the running app may still override accent per lens.
pub const accent_house: u32 = 0xFFF2762A;

/// Reference DARK theme — the Zat client's real values.
pub const dark: Theme = .{
    .canvas = 0xFF000000, // pure black — field backdrop + elevation base
    .surface = 0xFF1B1B1B, // the solid grey card
    .surface_hover = 0xFF242424, // a hair lighter under the pointer
    .surface_sel = 0xFF2A2A2A,
    .ink = 0xFFEDEAE0, // warm off-white
    .muted = 0xFF9A968A,
    .faint = 0xFF6A665C,
    .border = 0xFF2A2A2A, // 1px card outline
    .divider = 0x18EDEAE0, // ~9% ink hairline
    .scrim = 0xB0000000, // ~69% black modal backdrop
    .accent = accent_house,
    .on_accent = 0xFF0B0B0F, // near-black ink on an accent fill
    .disabled_fill = 0x2AEDEAE0, // ~16% ink wash
    .disabled_ink = 0xFF9A968A, // = muted
};

/// Reference LIGHT theme — the same roles, inverted for a light canvas. This is the
/// single place light-mode contrast is defined (no per-element remapping).
pub const light: Theme = .{
    .canvas = 0xFFF7F6F3, // warm off-white page
    .surface = 0xFFFFFFFF, // white cards
    .surface_hover = 0xFFF0EEE9,
    .surface_sel = 0xFFE9E6DF,
    .ink = 0xFF17150F, // near-black warm ink
    .muted = 0xFF6A665C,
    .faint = 0xFF9A968A,
    .border = 0xFFE2DED4, // light hairline
    .divider = 0x18000000, // ~9% black hairline
    .scrim = 0x66000000, // ~40% black backdrop (lighter over a light page)
    .accent = accent_house,
    .on_accent = 0xFFFFFFFF, // white ink on the accent fill
    .disabled_fill = 0x14000000, // ~8% black wash
    .disabled_ink = 0xFF9A968A,
};

/// Resolve a role against a theme. Exhaustive: adding a `ColorRole` without wiring
/// it here fails to compile — a role can never be silently unthemed.
pub fn color(t: Theme, role: ColorRole) u32 {
    return switch (role) {
        .canvas => t.canvas,
        .surface => t.surface,
        .surface_hover => t.surface_hover,
        .surface_sel => t.surface_sel,
        .ink => t.ink,
        .muted => t.muted,
        .faint => t.faint,
        .border => t.border,
        .divider => t.divider,
        .scrim => t.scrim,
        .accent => t.accent,
        .on_accent => t.on_accent,
        .disabled_fill => t.disabled_fill,
        .disabled_ink => t.disabled_ink,
    };
}

// ---------------------------------------------------------------------------
// Color transforms — pure ARGB math. Tint/alpha/mix without touching the host.
// ---------------------------------------------------------------------------

/// Replace the alpha channel, keeping RGB. `a` is 0..255.
pub inline fn withAlpha(argb: u32, a: u8) u32 {
    return (@as(u32, a) << 24) | (argb & 0x00FFFFFF);
}

/// Linear blend between two ARGB colors, per channel including alpha. `t` in [0,1]
/// (clamped): 0 → `a`, 1 → `b`.
pub fn mix(a: u32, b: u32, t: f32) u32 {
    const k = std.math.clamp(t, 0.0, 1.0);
    var out: u32 = 0;
    var shift: u5 = 0;
    while (true) {
        const ca: f32 = @floatFromInt((a >> shift) & 0xFF);
        const cb: f32 = @floatFromInt((b >> shift) & 0xFF);
        const cc: u32 = @intFromFloat(@round(ca + (cb - ca) * k));
        out |= (cc & 0xFF) << shift;
        if (shift == 24) break;
        shift += 8;
    }
    return out;
}

// ---------------------------------------------------------------------------
// Motion durations — reference timings (ms). The CURVES live in `ease`; tokens
// only names the durations so transitions across the app share a tempo.
// ---------------------------------------------------------------------------

pub const Dur = enum(i32) {
    fast = 120, // taps, small state flips
    base = 200, // most transitions
    slow = 320, // large surfaces, sheets
};

pub inline fn ms(d: Dur) i32 {
    return @intFromEnum(d);
}

// ---------------------------------------------------------------------------

test "tokens: spacing scale is monotonic and grid-aligned" {
    const steps = [_]Space{ .none, .xs, .sm, .md, .lg, .xl, .xxl, .huge };
    var prev: i32 = -1;
    for (steps) |s| {
        const v = space(s);
        try std.testing.expect(v > prev); // strictly increasing
        try std.testing.expect(@rem(v, grid) == 0); // on the grid
        prev = v;
    }
    try std.testing.expectEqual(@as(i32, 12), space(.md));
}

test "tokens: radius scale is monotonic" {
    const rs = [_]Radius{ .none, .sm, .md, .lg, .xl, .pill };
    var prev: i32 = -1;
    for (rs) |r| {
        const v = radius(r);
        try std.testing.expect(v > prev);
        prev = v;
    }
}

test "tokens: type scale is monotonic in size and every line box fits its glyphs" {
    const roles = [_]TypeRole{ .caption, .footnote, .body, .callout, .subhead, .title, .display };
    var prev: i32 = 0;
    for (roles) |role| {
        const ts = text(role);
        try std.testing.expect(ts.size_px > prev); // sizes strictly increase
        try std.testing.expect(ts.line_px >= ts.size_px); // line box never clips the glyph
        prev = ts.size_px;
    }
}

test "tokens: color roles resolve to the theme's exact value, both themes complete" {
    // Round-trip: the accessor returns the stored field.
    try std.testing.expectEqual(@as(u32, 0xFF000000), color(dark, .canvas));
    try std.testing.expectEqual(@as(u32, 0xFF1B1B1B), color(dark, .surface));
    try std.testing.expectEqual(@as(u32, 0xFFEDEAE0), color(dark, .ink));
    try std.testing.expectEqual(@as(u32, 0xFFF7F6F3), color(light, .canvas));
    // The house accent is shared across themes (one source of truth).
    try std.testing.expectEqual(accent_house, color(dark, .accent));
    try std.testing.expectEqual(accent_house, color(light, .accent));
    // Every role is defined in both themes (opaque roles opaque; alpha roles < FF).
    inline for (@typeInfo(ColorRole).@"enum".fields) |f| {
        const role: ColorRole = @enumFromInt(f.value);
        _ = color(dark, role);
        _ = color(light, role);
    }
    // Divider/scrim carry partial alpha by design; solid roles are fully opaque.
    try std.testing.expect((color(dark, .divider) >> 24) < 0xFF);
    try std.testing.expect((color(dark, .scrim) >> 24) < 0xFF);
    try std.testing.expect((color(dark, .surface) >> 24) == 0xFF);
}

test "tokens: withAlpha replaces alpha, keeps rgb" {
    try std.testing.expectEqual(@as(u32, 0x80EDEAE0), withAlpha(0xFFEDEAE0, 0x80));
    try std.testing.expectEqual(@as(u32, 0x00EDEAE0), withAlpha(0xFFEDEAE0, 0x00));
}

test "tokens: mix endpoints and midpoint blend every channel" {
    const a: u32 = 0x00000000;
    const b: u32 = 0xFFFFFFFF;
    try std.testing.expectEqual(a, mix(a, b, 0.0));
    try std.testing.expectEqual(b, mix(a, b, 1.0));
    try std.testing.expectEqual(@as(u32, 0x80808080), mix(a, b, 0.5)); // round(127.5)=128
    // Clamp: out-of-range t saturates, never wraps.
    try std.testing.expectEqual(a, mix(a, b, -1.0));
    try std.testing.expectEqual(b, mix(a, b, 2.0));
    // Per-channel independence: red-only to green-only midpoint.
    try std.testing.expectEqual(@as(u32, 0xFF808000), mix(0xFFFF0000, 0xFF00FF00, 0.5));
}

test "tokens: motion durations are ordered fast < base < slow" {
    try std.testing.expect(ms(.fast) < ms(.base));
    try std.testing.expect(ms(.base) < ms(.slow));
}
