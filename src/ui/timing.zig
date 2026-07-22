//! Rover · timing — event-timing predicates (debounce, throttle, double-tap,
//! long-press).
//!
//! PORTABLE (Rover rule): PURE, standalone, `std`-only. No renderer, no window
//! backend, no clock, no app types cross this boundary. These are the small
//! timing behaviors a browser smooths for free — collapsing a burst of events,
//! rate-limiting a stream, recognizing a double-tap, arming a long-press —
//! expressed as pure predicates over timestamps.
//!
//! THE CLOCK LIVES IN THE HOST. Nothing here reads a clock. The caller samples
//! the time ONCE per event (monotonic, milliseconds) and passes it in; each
//! function returns a decision and, where it has state, records the timestamp it
//! was given. Same inputs ⇒ same outputs ⇒ fully testable with synthetic time
//! (reveal.zig follows the same rule for its `dt`).
//!
//! All times are UNSIGNED MILLISECONDS from a monotonic source. `now_ms` must be
//! non-decreasing across calls on the same state; a clock that only moves forward
//! is the one invariant the host owns. Subtraction is done saturating so a stray
//! backward sample can never underflow into a huge elapsed value.

const std = @import("std");
const assert = std.debug.assert;

// ---------------------------------------------------------------------------
// Default windows (milliseconds). Documented, tunable by the host at the call
// site — nothing here reaches for these implicitly.
// ---------------------------------------------------------------------------

/// Double-tap recognition window: a second tap later than this reads as two
/// separate taps. ~300ms is the familiar platform default.
pub const default_double_tap_ms: u64 = 300;

/// Double-tap position tolerance (logical px): the second tap must land within
/// this of the first, or it is a new tap somewhere else, not a double-tap.
pub const default_double_tap_slop_px: i32 = 24;

/// Long-press arm time: how long a press must be held still before it counts as
/// a long-press (context menu / press-and-hold).
pub const default_long_press_ms: u64 = 380;

/// Held-key auto-repeat: the delay before the FIRST repeat, then the interval
/// between subsequent repeats — the classic keyboard-repeat curve.
pub const default_repeat_first_delay_ms: u64 = 400;
pub const default_repeat_interval_ms: u64 = 40;

/// A general-purpose debounce/throttle window for rapid UI callbacks (resize,
/// search-as-you-type, scroll-settle).
pub const default_debounce_ms: u64 = 150;
pub const default_throttle_ms: u64 = 100;

/// Saturating elapsed time: `now_ms - since_ms`, but 0 if `now_ms` ran backward.
/// Keeps a non-monotonic sample from wrapping into an enormous interval.
pub fn elapsed(now_ms: u64, since_ms: u64) u64 {
    return if (now_ms > since_ms) now_ms - since_ms else 0;
}

// ---------------------------------------------------------------------------
// Debounce — TRAILING-EDGE suppression of a rapid burst.
// ---------------------------------------------------------------------------

/// PLAIN DATA (A1): one debounce clock. `last_ms` is the timestamp of the last
/// accepted fire; the sentinel below marks "never fired" so the very first call
/// is always allowed (leading edge).
pub const Debounce = struct {
    /// Timestamp of the last accepted fire. `never` = has not fired yet.
    last_ms: u64 = never,

    /// Sentinel for "no fire yet". Using max means the first `shouldFire` sees a
    /// huge elapsed time and fires immediately, giving a clean LEADING edge.
    pub const never: u64 = std.math.maxInt(u64);

    comptime {
        // One u64, no padding.
        assert(@sizeOf(Debounce) == 8);
    }
};

/// Debounce with LEADING-EDGE semantics: fire immediately, then swallow every
/// call for `wait_ms` after an accepted fire. Returns true (and stamps `last_ms`)
/// only when at least `wait_ms` has elapsed since the last accepted fire — so a
/// storm of rapid calls collapses to one fire at the start of each quiet-spaced
/// window. The first call on a fresh `Debounce` always fires.
///
/// This is the "act now, then ignore the repeats" flavor (a button that must not
/// double-submit). For classic TRAILING-edge debounce (act once after the burst
/// STOPS), the host holds the pending call and asks `settled()` below.
pub fn shouldFire(d: *Debounce, now_ms: u64, wait_ms: u64) bool {
    if (d.last_ms != Debounce.never and elapsed(now_ms, d.last_ms) < wait_ms) {
        return false;
    }
    d.last_ms = now_ms;
    return true;
}

/// TRAILING-EDGE companion: record that an event happened (the burst is ongoing)
/// without deciding to fire. The host calls this on every raw event...
pub fn touch(d: *Debounce, now_ms: u64) void {
    d.last_ms = now_ms;
}

/// ...then, when it wants to know whether the burst has gone quiet long enough to
/// run the trailing action, asks this. True once `wait_ms` has passed since the
/// last `touch` (and something was actually touched). Does not mutate state, so
/// the host stays in control of when the pending action clears.
pub fn settled(d: Debounce, now_ms: u64, wait_ms: u64) bool {
    if (d.last_ms == Debounce.never) return false;
    return elapsed(now_ms, d.last_ms) >= wait_ms;
}

/// Reset a debounce clock to its never-fired state (e.g. on focus loss).
pub fn resetDebounce(d: *Debounce) void {
    d.last_ms = Debounce.never;
}

// ---------------------------------------------------------------------------
// Throttle — rate-limit a stream to at most once per interval.
// ---------------------------------------------------------------------------

/// PLAIN DATA (A1): one throttle clock. Same shape as `Debounce` but a distinct
/// type so intent is legible at the call site.
pub const Throttle = struct {
    /// Timestamp of the last allowed pass. `never` = none yet (first pass allowed).
    last_ms: u64 = never,

    pub const never: u64 = std.math.maxInt(u64);

    comptime {
        assert(@sizeOf(Throttle) == 8);
    }
};

/// Allow at most one pass per `interval_ms`. Returns true (and stamps `last_ms`)
/// when at least `interval_ms` has elapsed since the last allowed pass; false in
/// between. Leading-edge: the first call always passes. Unlike `shouldFire`, the
/// clock advances from the LAST ALLOWED time, so a steady stream passes at a
/// fixed cadence rather than being reset by each rejected call — which is the
/// difference between throttle (steady cadence) and debounce (quiet-gap gate).
pub fn allow(t: *Throttle, now_ms: u64, interval_ms: u64) bool {
    if (t.last_ms != Throttle.never and elapsed(now_ms, t.last_ms) < interval_ms) {
        return false;
    }
    t.last_ms = now_ms;
    return true;
}

/// Reset a throttle clock to its never-passed state.
pub fn resetThrottle(t: *Throttle) void {
    t.last_ms = Throttle.never;
}

// ---------------------------------------------------------------------------
// Double-tap — two taps close in time AND space.
// ---------------------------------------------------------------------------

/// PLAIN DATA (A1): the last tap, so the next one can be measured against it.
pub const DoubleTap = struct {
    /// Timestamp of the last recorded tap. `never` = none yet.
    last_down_ms: u64 = never,
    last_x: i32 = 0,
    last_y: i32 = 0,

    pub const never: u64 = std.math.maxInt(u64);

    comptime {
        // u64 + two i32 = 16, no padding.
        assert(@sizeOf(DoubleTap) == 16);
    }
};

/// Feed a tap. Returns true when THIS tap completes a double-tap — it landed
/// within `window_ms` and within `slop_px` (Chebyshev / max-axis distance) of the
/// previous recorded tap. Otherwise records this tap as the new "previous" and
/// returns false.
///
/// On a recognized double-tap the state is RESET (to `never`), so a third rapid
/// tap does not read as another double-tap off the second — a triple-tap is one
/// double-tap plus a fresh single, matching platform behavior.
pub fn tap(d: *DoubleTap, now_ms: u64, x: i32, y: i32, window_ms: u64, slop_px: i32) bool {
    if (d.last_down_ms != DoubleTap.never and
        elapsed(now_ms, d.last_down_ms) <= window_ms and
        withinSlop(x - d.last_x, y - d.last_y, slop_px))
    {
        // Recognized: consume the pair so the next tap starts fresh.
        d.last_down_ms = DoubleTap.never;
        return true;
    }
    d.last_down_ms = now_ms;
    d.last_x = x;
    d.last_y = y;
    return false;
}

/// Reset the double-tap state (e.g. when the pointer target changes).
pub fn resetDoubleTap(d: *DoubleTap) void {
    d.last_down_ms = DoubleTap.never;
}

/// True when a delta stays within `slop` on both axes (a square tolerance box —
/// cheaper and steadier than a Euclidean radius, and matches how touch slop is
/// usually specified per-axis). `abs` guards against i32 overflow on min-int.
fn withinSlop(dx: i32, dy: i32, slop: i32) bool {
    return absI32(dx) <= slop and absI32(dy) <= slop;
}

/// Absolute value that saturates instead of overflowing on `minInt(i32)`.
fn absI32(v: i32) i32 {
    if (v == std.math.minInt(i32)) return std.math.maxInt(i32);
    return if (v < 0) -v else v;
}

// ---------------------------------------------------------------------------
// Long-press — held past a threshold, plus held-key auto-repeat.
// ---------------------------------------------------------------------------

/// PURE PREDICATE: has a press that went down at `down_ms` been held long enough
/// (as of `now_ms`) to count as a long-press? No state — the host owns the
/// down-timestamp (it already tracks the active press) and just asks. The host is
/// responsible for confirming the pointer has not moved beyond its own slop; this
/// answers only the TIME question.
pub fn longPressReady(down_ms: u64, now_ms: u64, hold_ms: u64) bool {
    return elapsed(now_ms, down_ms) >= hold_ms;
}

/// Fraction in [0,1] of the way from press-down to the long-press threshold — for
/// a "hold to confirm" ring / fill that grows while the finger is down. Reaches
/// 1.0 exactly at the threshold and never exceeds it. `hold_ms == 0` reads as
/// instantly complete.
pub fn longPressProgress(down_ms: u64, now_ms: u64, hold_ms: u64) f32 {
    if (hold_ms == 0) return 1.0;
    const held: f32 = @floatFromInt(elapsed(now_ms, down_ms));
    const target: f32 = @floatFromInt(hold_ms);
    return std.math.clamp(held / target, 0.0, 1.0);
}

/// Held-key auto-repeat: how many repeat events SHOULD have fired by `now_ms` for
/// a key held since `down_ms`, given a `first_delay_ms` before repeat 1 and an
/// `interval_ms` between subsequent repeats. Returns a running total; the host
/// remembers how many it has already emitted and fires the difference. Before
/// `first_delay_ms` elapses the count is 0. `interval_ms == 0` is treated as 1ms
/// to avoid a divide-by-zero (a degenerate but harmless "as fast as possible").
pub fn repeatsDue(down_ms: u64, now_ms: u64, first_delay_ms: u64, interval_ms: u64) u32 {
    const held = elapsed(now_ms, down_ms);
    if (held < first_delay_ms) return 0;
    const step = if (interval_ms == 0) @as(u64, 1) else interval_ms;
    const after_first = held - first_delay_ms;
    const n = 1 + (after_first / step); // repeat 1 at first_delay, then every step
    return std.math.cast(u32, n) orelse std.math.maxInt(u32);
}

// ---------------------------------------------------------------------------
// Tests — synthetic timestamps only, no clock.
// ---------------------------------------------------------------------------

const testing = std.testing;

test "timing: elapsed is saturating (no backward underflow)" {
    try testing.expectEqual(@as(u64, 50), elapsed(150, 100));
    try testing.expectEqual(@as(u64, 0), elapsed(100, 150)); // backward → 0
    try testing.expectEqual(@as(u64, 0), elapsed(100, 100));
}

test "timing: debounce fires leading, suppresses inside wait, allows after" {
    var d: Debounce = .{};
    // First call always fires (leading edge).
    try testing.expect(shouldFire(&d, 1000, 150));
    // Inside the wait window: suppressed.
    try testing.expect(!shouldFire(&d, 1050, 150));
    try testing.expect(!shouldFire(&d, 1149, 150));
    // Exactly at the boundary: allowed (>= wait).
    try testing.expect(shouldFire(&d, 1150, 150));
    // A fresh burst right after is suppressed again.
    try testing.expect(!shouldFire(&d, 1200, 150));
}

test "timing: debounce trailing edge via touch + settled" {
    var d: Debounce = .{};
    // Nothing touched yet: never settled.
    try testing.expect(!settled(d, 5000, 150));
    // A burst of events keeps pushing the clock forward.
    touch(&d, 1000);
    try testing.expect(!settled(d, 1100, 150));
    touch(&d, 1100);
    try testing.expect(!settled(d, 1200, 150)); // only 100ms of quiet
    touch(&d, 1200);
    // Now go quiet: 150ms after the last touch it settles.
    try testing.expect(!settled(d, 1349, 150));
    try testing.expect(settled(d, 1350, 150));
}

test "timing: debounce reset returns to never-fired" {
    var d: Debounce = .{};
    try testing.expect(shouldFire(&d, 1000, 150));
    try testing.expect(!shouldFire(&d, 1050, 150));
    resetDebounce(&d);
    // After reset the next call fires immediately again.
    try testing.expect(shouldFire(&d, 1060, 150));
}

test "timing: throttle allows once per interval at a steady cadence" {
    var t: Throttle = .{};
    try testing.expect(allow(&t, 0, 100)); // leading pass
    try testing.expect(!allow(&t, 50, 100));
    try testing.expect(!allow(&t, 99, 100));
    try testing.expect(allow(&t, 100, 100)); // interval elapsed
    try testing.expect(!allow(&t, 150, 100));
    try testing.expect(allow(&t, 205, 100)); // next cadence pass
    resetThrottle(&t);
    try testing.expect(allow(&t, 210, 100)); // reset → passes again
}

test "timing: double-tap true only inside window and slop" {
    var d: DoubleTap = .{};
    // First tap: records, returns false.
    try testing.expect(!tap(&d, 1000, 10, 10, 300, 24));
    // Second tap inside window + slop: recognized.
    try testing.expect(tap(&d, 1200, 20, 15, 300, 24));
    // State was consumed: the next tap is a fresh single.
    try testing.expect(!tap(&d, 1300, 20, 15, 300, 24));
}

test "timing: double-tap false when too slow" {
    var d: DoubleTap = .{};
    try testing.expect(!tap(&d, 1000, 10, 10, 300, 24));
    // 400ms later: outside the 300ms window → treated as a new first tap.
    try testing.expect(!tap(&d, 1400, 10, 10, 300, 24));
    // But a quick one after THAT recognizes off the 1400 tap.
    try testing.expect(tap(&d, 1500, 10, 10, 300, 24));
}

test "timing: double-tap false when too far" {
    var d: DoubleTap = .{};
    try testing.expect(!tap(&d, 1000, 10, 10, 300, 24));
    // In time, but 100px away (> 24 slop) → new tap, not a double.
    try testing.expect(!tap(&d, 1100, 110, 10, 300, 24));
    // Exactly at slop on one axis, in time → recognized.
    try testing.expect(tap(&d, 1200, 110 + 24, 10, 300, 24));
}

test "timing: double-tap boundary is inclusive on window and slop" {
    var d: DoubleTap = .{};
    try testing.expect(!tap(&d, 0, 0, 0, 300, 24));
    // Exactly 300ms and exactly 24px on both axes: still a double-tap.
    try testing.expect(tap(&d, 300, 24, 24, 300, 24));
}

test "timing: longPressReady flips at the threshold" {
    try testing.expect(!longPressReady(1000, 1000, 380));
    try testing.expect(!longPressReady(1000, 1379, 380));
    try testing.expect(longPressReady(1000, 1380, 380)); // exactly at hold_ms
    try testing.expect(longPressReady(1000, 2000, 380));
}

test "timing: longPressProgress ramps 0→1 and clamps" {
    try testing.expectEqual(@as(f32, 0.0), longPressProgress(1000, 1000, 400));
    try testing.expectApproxEqAbs(@as(f32, 0.5), longPressProgress(1000, 1200, 400), 1.0e-6);
    try testing.expectEqual(@as(f32, 1.0), longPressProgress(1000, 1400, 400));
    try testing.expectEqual(@as(f32, 1.0), longPressProgress(1000, 9999, 400)); // clamped
    try testing.expectEqual(@as(f32, 1.0), longPressProgress(1000, 1000, 0)); // zero hold
}

test "timing: repeatsDue rises over time" {
    // Before the first delay: nothing.
    try testing.expectEqual(@as(u32, 0), repeatsDue(0, 100, 400, 40));
    try testing.expectEqual(@as(u32, 0), repeatsDue(0, 399, 400, 40));
    // At the first delay: exactly one repeat.
    try testing.expectEqual(@as(u32, 1), repeatsDue(0, 400, 400, 40));
    // Then one more every interval.
    try testing.expectEqual(@as(u32, 1), repeatsDue(0, 439, 400, 40));
    try testing.expectEqual(@as(u32, 2), repeatsDue(0, 440, 400, 40));
    try testing.expectEqual(@as(u32, 6), repeatsDue(0, 600, 400, 40)); // 1 + 200/40
    // Monotonic non-decreasing as now advances.
    var prev: u32 = 0;
    var now: u64 = 0;
    while (now <= 2000) : (now += 7) {
        const n = repeatsDue(0, now, 400, 40);
        try testing.expect(n >= prev);
        prev = n;
    }
}

test "timing: repeatsDue tolerates zero interval" {
    // interval 0 → treated as 1ms; still finite and non-crashing.
    const n = repeatsDue(0, 500, 400, 0);
    try testing.expectEqual(@as(u32, 1 + 100), n); // 1 + (500-400)/1
}
