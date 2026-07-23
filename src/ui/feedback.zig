//! Rover · feedback — interaction-state + press-feedback primitive.
//!
//! PORTABLE (Rover rule): PURE, standalone, `std`-only. No renderer, no window
//! backend, no app types cross this boundary. This is the browser's
//! `:hover` / `:active` / `:focus` / `:disabled` visual states plus a
//! material-style press flash / ripple, expressed as free functions over plain
//! data. The host reports what the pointer/keyboard are doing (hovered, pressed,
//! focused, disabled) and the real elapsed time; this hands back a resolved
//! visual STATE, a standard state-layer overlay alpha, and a decaying press-flash
//! alpha / ripple radius. The host binds those numbers to whatever it draws — a
//! tinted overlay, a highlight rect, an expanding circle. The reusable artifact
//! is the STATE + the animation curve, never the pixels.
//!
//! The press flash is FRAME-RATE INDEPENDENT: it decays by a documented
//! exponential time constant, and exponential decay composes exactly — one step
//! of `dt` and N steps summing to `dt` reach the same value (up to float slack),
//! so the same wall-clock produces the same fade at 60 Hz, 144 Hz, or across a
//! dropped frame.
//!
//! COMPOSITION (kept as documentation, not imports — both stay single-file liftable):
//!   · with `input`: for a control id, fill `Interaction` from an `input.Event`/State
//!     as `.{ .hovered = e.hover == id, .pressed = e.active == id, .focused =
//!     e.focus == id and st.focus_visible, .disabled = <host> }`. Note `pressed`
//!     maps to input's ACTIVE (pressed AND still over it), so dragging off releases
//!     the pushed-in look; and `focused` gates on `focus_visible`, so a ring shows
//!     only for keyboard focus — exactly the browser's `:focus-visible`.
//!   · with `tokens`: the alphas here are OVERLAY opacities. The host draws a wash
//!     of a token color at that alpha (e.g. `tokens.withAlpha(role_color, a)`); a
//!     disabled control additionally scales its content alpha by
//!     `disabled_content_alpha`. This module never names a color.

const std = @import("std");
const assert = std.debug.assert;

/// The resolved visual state a control is in, after precedence is applied. The
/// host maps this to a tint / border / opacity. `disabled` outranks everything
/// (an inert control shows no hover/press), then `pressed`, then `focused`, then
/// `hover`, then `rest`.
pub const State = enum {
    rest,
    hover,
    pressed,
    focused,
    disabled,
};

/// PLAIN DATA (A1): what the pointer/keyboard are doing to a control, as a tiny
/// packed flag set. Stored out-of-band-style in one byte so it costs nothing to
/// keep one per widget in a hot list (A6). The host sets the bits from its input
/// layer; `state()` derives the visual state from them.
pub const Interaction = packed struct(u8) {
    hovered: bool = false,
    pressed: bool = false,
    focused: bool = false,
    disabled: bool = false,
    _pad: u4 = 0,

    comptime {
        // One byte: four flags + padding, packed.
        assert(@sizeOf(Interaction) == 1);
    }
};

/// Resolve the interaction flags into a single visual state, applying the CSS /
/// material precedence: disabled > pressed > focused > hover > rest. A control
/// with several flags set shows only the highest-precedence one.
pub fn state(i: Interaction) State {
    if (i.disabled) return .disabled;
    if (i.pressed) return .pressed;
    if (i.focused) return .focused;
    if (i.hovered) return .hover;
    return .rest;
}

// --- state-layer opacities (material "state layer" convention) ---------------
//
// A translucent overlay of the control's foreground colour, its opacity keyed to
// the state. These are the standard material state-layer opacities, rounded to
// 8-bit alpha: hover ~0.08, focus ~0.11, pressed ~0.16. `rest` is 0 (no layer)
// and `disabled` is 0 (a disabled control is dimmed by reducing its CONTENT
// alpha elsewhere, not by adding a state layer — so its state layer is defined
// as empty).

pub const hover_alpha: u8 = 20; // ~0.08 * 255
pub const focus_alpha: u8 = 28; // ~0.11 * 255
pub const pressed_alpha: u8 = 40; // ~0.16 * 255

/// A disabled control is dimmed by scaling its CONTENT alpha (ink + fill) to this,
/// in addition to showing no state layer — material's ~38% disabled emphasis. This
/// is the one place "how dim is disabled" lives; the host multiplies the control's
/// content alpha by `disabled_content_alpha / 255` when the state is `.disabled`.
pub const disabled_content_alpha: u8 = 97; // ~0.38 * 255

/// The state-layer overlay alpha [0, 255] for a resolved state. Ordering holds:
/// pressed > focused > hover > rest == disabled == 0.
pub fn overlayAlpha(s: State) u8 {
    return switch (s) {
        .rest => 0,
        .hover => hover_alpha,
        .focused => focus_alpha,
        .pressed => pressed_alpha,
        .disabled => 0,
    };
}

/// Convenience: resolve the flags and return the overlay alpha in one call.
pub fn interactionAlpha(i: Interaction) u8 {
    return overlayAlpha(state(i));
}

// --- press flash / ripple ----------------------------------------------------

/// PLAIN DATA (A1): the transient press-feedback animation. `t` is the flash
/// energy, 1 at the moment of press-down, decaying toward 0; `active` is true
/// while the flash is still visible so the host knows to keep drawing (and
/// rebuilding) it. One per pressable surface that is currently animating.
pub const Press = struct {
    t: f32 = 0, // flash energy in [0, 1]; 1 = just pressed, 0 = faded out
    active: bool = false,

    comptime {
        // f32 + bool padded to the f32's alignment.
        assert(@sizeOf(Press) == 8);
    }
};

/// Exponential decay time constant (seconds): the flash energy falls to 1/e in
/// this time. ~0.20s reads as a quick, premium tap flash — visible but not
/// lingering.
pub const flash_tau: f32 = 0.20;

/// Peak overlay alpha [0, 255] of the press flash at the instant of press-down.
/// Sits a touch above the resting pressed state-layer so a real tap "pops".
pub const flash_peak_alpha: u8 = 48; // ~0.19 * 255

/// Below this energy the flash is imperceptible; snap it off so `active` goes
/// false and the host stops animating.
pub const rest_eps: f32 = 1.0e-3;

/// Begin (or restart) a press flash — call on pointer/key press-down. Resets the
/// energy to full and marks it active.
pub fn down(p: *Press) void {
    p.t = 1.0;
    p.active = true;
}

/// Advance the flash by real elapsed `dt` seconds. Exponential decay toward 0 by
/// `flash_tau`; because `exp(-a) * exp(-b) == exp(-(a+b))`, this is frame-rate
/// independent. Snaps off (and clears `active`) once imperceptible. A no-op once
/// inactive, so it is cheap to call every frame.
pub fn step(p: *Press, dt: f32) void {
    if (!p.active) return;
    const d = @max(dt, 0.0);
    p.t *= @exp(-d / flash_tau);
    if (p.t < rest_eps) {
        p.t = 0.0;
        p.active = false;
    }
}

/// True while the flash is still fading — the host keeps rendering it until this
/// goes false.
pub fn active(p: Press) bool {
    return p.active;
}

/// The press-flash overlay alpha [0, 255] for this frame — the flash energy
/// scaled by the peak. 0 when settled.
pub fn alpha(p: Press) u8 {
    const a = std.math.clamp(p.t, 0.0, 1.0) * @as(f32, @floatFromInt(flash_peak_alpha));
    return @intFromFloat(a);
}

/// Nice-to-have ripple: a normalized radius in [0, 1] that GROWS from the press
/// point as the flash ages. Since energy `t` falls 1 -> 0, the radius rises
/// 0 -> 1 as `1 - t`; the host multiplies by the control's reach to size the
/// expanding circle. 0 when no flash is active.
pub fn rippleRadius(p: Press) f32 {
    if (!p.active) return 0.0;
    return std.math.clamp(1.0 - p.t, 0.0, 1.0);
}

// ---------------------------------------------------------------------------

test "feedback: state precedence (disabled > pressed > focused > hover > rest)" {
    // Nothing set -> rest.
    try std.testing.expectEqual(State.rest, state(.{}));
    // Single flags.
    try std.testing.expectEqual(State.hover, state(.{ .hovered = true }));
    try std.testing.expectEqual(State.focused, state(.{ .focused = true }));
    try std.testing.expectEqual(State.pressed, state(.{ .pressed = true }));
    try std.testing.expectEqual(State.disabled, state(.{ .disabled = true }));
    // Disabled beats pressed (and everything else).
    try std.testing.expectEqual(State.disabled, state(.{
        .disabled = true,
        .pressed = true,
        .focused = true,
        .hovered = true,
    }));
    // Pressed beats focused and hover.
    try std.testing.expectEqual(State.pressed, state(.{ .pressed = true, .hovered = true }));
    try std.testing.expectEqual(State.pressed, state(.{ .pressed = true, .focused = true }));
    // Focused beats hover.
    try std.testing.expectEqual(State.focused, state(.{ .focused = true, .hovered = true }));
}

test "feedback: overlayAlpha ordering (pressed > focused > hover > rest, disabled defined)" {
    try std.testing.expectEqual(@as(u8, 0), overlayAlpha(.rest));
    try std.testing.expectEqual(@as(u8, 0), overlayAlpha(.disabled)); // defined: empty state layer
    try std.testing.expect(overlayAlpha(.pressed) > overlayAlpha(.focused));
    try std.testing.expect(overlayAlpha(.focused) > overlayAlpha(.hover));
    try std.testing.expect(overlayAlpha(.hover) > overlayAlpha(.rest));
    // interactionAlpha resolves flags then maps.
    try std.testing.expectEqual(pressed_alpha, interactionAlpha(.{ .pressed = true }));
    try std.testing.expectEqual(@as(u8, 0), interactionAlpha(.{ .disabled = true, .pressed = true }));
}

test "feedback: disabled dims content (inert + partial content alpha)" {
    // Disabled shows no state layer (inert) but is not invisible — it dims content.
    try std.testing.expectEqual(@as(u8, 0), overlayAlpha(.disabled));
    try std.testing.expect(disabled_content_alpha > 0 and disabled_content_alpha < 255);
    // Dimmer than a fully-opaque enabled control.
    try std.testing.expect(disabled_content_alpha < 255);
}

test "feedback: press starts full and decays to inactive with alpha 0" {
    var p: Press = .{};
    try std.testing.expect(!active(p));
    try std.testing.expectEqual(@as(u8, 0), alpha(p));

    down(&p);
    try std.testing.expect(active(p));
    try std.testing.expect(alpha(p) > 0);
    try std.testing.expectEqual(flash_peak_alpha, alpha(p)); // full at press-down

    // ~1.5s at 60fps is many time-constants past a 0.20s decay.
    var i: usize = 0;
    while (i < 90) : (i += 1) step(&p, 1.0 / 60.0);
    try std.testing.expect(!active(p));
    try std.testing.expectEqual(@as(u8, 0), alpha(p));
    try std.testing.expectEqual(@as(f32, 0), p.t);
    try std.testing.expectEqual(@as(f32, 0), rippleRadius(p));
}

test "feedback: press decay is frame-rate independent" {
    var a: Press = .{};
    var b: Press = .{};
    down(&a);
    down(&b);
    // 0.3s delivered as one step vs six equal steps (still active at 0.3s).
    step(&a, 0.3);
    var i: usize = 0;
    while (i < 6) : (i += 1) step(&b, 0.3 / 6.0);
    try std.testing.expect(a.active and b.active);
    try std.testing.expect(@abs(a.t - b.t) < 0.01);
}

test "feedback: ripple radius grows from 0 toward 1 as the flash ages" {
    var p: Press = .{};
    try std.testing.expectEqual(@as(f32, 0), rippleRadius(p)); // inactive -> 0
    down(&p);
    // Just pressed: energy ~1, radius ~0.
    try std.testing.expect(rippleRadius(p) < 0.01);
    const r0 = rippleRadius(p);
    step(&p, 0.1); // one half-ish time constant in
    const r1 = rippleRadius(p);
    try std.testing.expect(r1 > r0); // grew
    try std.testing.expect(r1 >= 0.0 and r1 <= 1.0);
}
