//! Rover · insets — safe-area + system-gesture inset math.
//!
//! PORTABLE (Rover rule): PURE, `std`-only, plain data in / plain data out. This is
//! the browser's `env(safe-area-inset-*)` and visual-viewport behavior, expressed
//! as free functions. The host reads the OS insets (status bar, nav bar, notch, the
//! swipe-up-home gesture strip) and passes them in; these return the reserves that
//! LAYOUT must honor. All values are LOGICAL (design) pixels.

const std = @import("std");

/// A conservative fallback for the bottom system-gesture strip (the swipe-up-home
/// zone), in logical px, used when the OS system-gesture inset is not yet known.
/// Android's gesture zone is ~48dp; at a typical phone's logical scale that is a
/// bit more than 48 LOGICAL px, so a 48-logical reserve fell just short and a
/// swipe still clipped the space bar. 64 clears it with margin. (The exact value
/// arrives when the real system-gesture inset is plumbed from the OS.)
pub const default_gesture_bottom: i32 = 64;

/// The bottom reserve a bottom-anchored INTERACTIVE control (a keyboard's space
/// row, a bottom action bar) must keep clear so the OS swipe-up-home gesture does
/// not steal its touch-down — the "swipe up to switch apps fires the spacebar" bug.
///
/// It is the larger of the system-bars bottom inset (the nav pill area) and the
/// system-gesture bottom inset; when the gesture inset is unknown (<= 0) we fall
/// back to `default_gesture_bottom` so the fix works before that value is plumbed.
pub fn safeBottom(system_bars_bottom: i32, system_gestures_bottom: i32) i32 {
    const g = if (system_gestures_bottom > 0) system_gestures_bottom else default_gesture_bottom;
    return @max(@max(system_bars_bottom, 0), g);
}

/// How far content must scroll UP so a focused field's bottom clears the top of the
/// keyboard (0 if it already clears). `field_bottom` and `keyboard_top` share one
/// coordinate space (logical px from the top); `margin` is breathing room above the
/// keyboard. This is the browser's "keep the focused input visible" behavior.
pub fn keyboardAvoid(field_bottom: i32, keyboard_top: i32, margin: i32) i32 {
    return @max(0, field_bottom + margin - keyboard_top);
}

// ---------------------------------------------------------------------------

test "insets: safeBottom takes the larger reserve, falls back when gesture unknown" {
    // Gesture inset unknown -> the default protects against the swipe-up strip.
    try std.testing.expectEqual(default_gesture_bottom, safeBottom(0, 0));
    try std.testing.expectEqual(default_gesture_bottom, safeBottom(24, 0)); // 24 < 48
    // A known, larger gesture inset wins.
    try std.testing.expectEqual(@as(i32, 60), safeBottom(24, 60));
    // A large system-bars inset wins over a small gesture inset.
    try std.testing.expectEqual(@as(i32, 70), safeBottom(70, 40));
}

test "insets: keyboardAvoid is 0 when clear, positive when overlapping" {
    // Field bottom at 400, keyboard top at 600 -> already clear.
    try std.testing.expectEqual(@as(i32, 0), keyboardAvoid(400, 600, 8));
    // Field bottom at 620, keyboard top at 600, 8px margin -> scroll up 28.
    try std.testing.expectEqual(@as(i32, 28), keyboardAvoid(620, 600, 8));
}
