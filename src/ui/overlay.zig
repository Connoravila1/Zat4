//! Rover · overlay — modal / popover stack (scrim, scroll-lock, outside-dismiss).
//!
//! PORTABLE (Rover rule): PURE, standalone, `std`-only. No renderer, no app types.
//! This is the browser's dialog / popover layer: a STACK of open surfaces, each with
//! a scrim, a z-order, focus containment, and background scroll-lock. It exists so a
//! new overlay is DECLARED (pushed onto the stack) instead of hand-wired through a
//! per-surface checklist — the recurring "the modal draws in the wrong buffer / lets
//! input bleed through / forgot the scrim" class of bugs.
//!
//! It OWNS only the logic unique to a stack of layers — push/pop, z assignment,
//! whether the background is scroll-locked, the scrim opacity, and outside-tap
//! dismissal. The pieces other primitives already provide are COMPOSED (documented,
//! not imported, so this file stays single-file liftable):
//!   · PRESENT/DISMISS motion — drive a `reveal.Reveal` per layer; the scrim uses
//!     `scrimAlpha(reveal.progress, max)` and the panel uses `reveal.slideUp`.
//!   · ANCHORED popovers — position the content with `anchor.place(...)`, then push
//!     that rect as the layer.
//!   · FOCUS TRAP — pass ONLY the top layer's regions to `input.focusNext` / hit-test;
//!     restricting the region set to the top layer IS the trap (`topZ` tells the host
//!     what to draw above; `activeId` tells it which layer owns input this frame).
//!
//! Coordinates are LOGICAL px (f32), matching `layout` — the usual source of a
//! layer's content rect.

const std = @import("std");
const assert = std.debug.assert;

/// Per-layer behavior. Out-of-band bits, not fat bools (Rover A6).
pub const LayerFlags = packed struct(u8) {
    /// Draws a scrim, locks background scroll, and owns focus (a dialog / sheet).
    /// A non-modal layer is a popover: no scrim, background stays live.
    modal: bool = false,
    /// A tap outside the content rect dismisses the layer (tap-scrim-to-close,
    /// click-away for a popover).
    dismiss_outside: bool = false,
    _pad: u6 = 0,
};

/// One open layer. Hot (held in the stack array): size-guarded. `id` is a
/// host-stable identifier for the surface; the rect is its content box.
pub const Layer = struct {
    id: u32,
    x: f32 = 0,
    y: f32 = 0,
    w: f32 = 0,
    h: f32 = 0,
    z: i16 = 0, // assigned by `push` from stack depth
    flags: LayerFlags = .{},

    comptime {
        // id(4) + rect(16) + z(2) + flags(1) + 1 pad = 24.
        assert(@sizeOf(Layer) == 24);
    }
};

/// Maximum simultaneously-open layers. Overlays rarely nest past a few (a sheet, a
/// menu on it, a confirm on that); a small fixed cap avoids any allocation.
pub const max_layers: usize = 8;

/// The z-order gap between stacked layers, leaving room for a scrim just under each
/// layer's content (`content z - 1`).
pub const z_step: i16 = 100;

/// The overlay stack — one per host. Cold (a single instance), so no size guard
/// (A7.2); the hot `Layer` it holds is guarded.
pub const Stack = struct {
    layers: [max_layers]Layer = undefined,
    len: u8 = 0,
};

inline fn contains(l: Layer, px: f32, py: f32) bool {
    return px >= l.x and px < l.x + l.w and py >= l.y and py < l.y + l.h;
}

/// Open a layer. Its z is assigned from the current depth so each new layer stacks
/// above the last. Returns false (a no-op) if the stack is full — the cap is never
/// silently exceeded.
pub fn push(s: *Stack, id: u32, x: f32, y: f32, w: f32, h: f32, flags: LayerFlags) bool {
    if (s.len >= max_layers) return false;
    const z: i16 = @intCast((@as(i32, s.len) + 1) * @as(i32, z_step));
    s.layers[s.len] = .{ .id = id, .x = x, .y = y, .w = w, .h = h, .z = z, .flags = flags };
    s.len += 1;
    return true;
}

/// Close the top layer (a no-op on an empty stack).
pub fn pop(s: *Stack) void {
    if (s.len > 0) s.len -= 1;
}

/// Close every layer.
pub fn clear(s: *Stack) void {
    s.len = 0;
}

/// The top (frontmost) layer, or null when nothing is open.
pub fn top(s: *const Stack) ?Layer {
    if (s.len == 0) return null;
    return s.layers[s.len - 1];
}

/// The id of the layer that owns input this frame — the top one — or 0 if none.
/// The host routes hit-testing / focus only to this layer's regions (the focus trap).
pub fn activeId(s: *const Stack) u32 {
    return if (top(s)) |l| l.id else 0;
}

/// True when anything is open.
pub fn isOpen(s: Stack) bool {
    return s.len > 0;
}

/// How many layers are open.
pub fn depth(s: Stack) usize {
    return s.len;
}

/// True when a layer with the given id is currently in the stack.
pub fn contains_id(s: Stack, id: u32) bool {
    for (s.layers[0..s.len]) |l| if (l.id == id) return true;
    return false;
}

/// Should the BACKGROUND (everything under the stack) be scroll-locked? True when
/// any open layer is modal — a scrim over live-scrolling content reads as broken.
pub fn scrollLocked(s: Stack) bool {
    for (s.layers[0..s.len]) |l| if (l.flags.modal) return true;
    return false;
}

/// The z at which to draw the top layer's CONTENT, and (content_z - 1) for its
/// scrim. 0 when nothing is open.
pub fn topZ(s: *const Stack) i16 {
    return if (top(s)) |l| l.z else 0;
}

/// The scrim (backdrop) alpha [0,255] for a modal, scaled by its present `progress`
/// (drive `progress` from a `reveal.Reveal`). `max` is the seated opacity — a
/// `tokens` scrim role's alpha is a good source.
pub fn scrimAlpha(progress: f32, max: u8) u8 {
    const a = std.math.clamp(progress, 0.0, 1.0) * @as(f32, @floatFromInt(max));
    return @intFromFloat(a);
}

/// Should a pointer press at (px,py) dismiss the top layer? True only when the top
/// layer opts into outside-dismissal AND the press is outside its content rect.
/// (The host still runs its present/dismiss transition; this just decides.)
pub fn dismissOnPress(s: *const Stack, px: f32, py: f32) bool {
    const t = top(s) orelse return false;
    if (!t.flags.dismiss_outside) return false;
    return !contains(t, px, py);
}

// ---------------------------------------------------------------------------

const expect = std.testing.expect;
const expectEq = std.testing.expectEqual;

test "overlay: push/top/pop maintain a LIFO stack with rising z" {
    var s: Stack = .{};
    try expect(!isOpen(s));
    try expect(push(&s, 1, 0, 0, 200, 300, .{ .modal = true }));
    try expect(push(&s, 2, 10, 10, 100, 80, .{ .dismiss_outside = true }));
    try expectEq(@as(usize, 2), depth(s));
    try expectEq(@as(u32, 2), activeId(&s)); // top owns input
    try expect(top(&s).?.z > s.layers[0].z); // stacked above
    pop(&s);
    try expectEq(@as(u32, 1), activeId(&s));
    pop(&s);
    try expect(!isOpen(s));
    try expectEq(@as(u32, 0), activeId(&s));
}

test "overlay: push respects the capacity cap without overflowing" {
    var s: Stack = .{};
    var i: u32 = 0;
    while (i < max_layers) : (i += 1) try expect(push(&s, i + 1, 0, 0, 10, 10, .{}));
    try expectEq(max_layers, depth(s)); // full
    try expect(!push(&s, 999, 0, 0, 10, 10, .{})); // refused, not silently dropped
    try expectEq(max_layers, depth(s));
}

test "overlay: background scroll-locks only while a modal is open" {
    var s: Stack = .{};
    try expect(!scrollLocked(s));
    _ = push(&s, 1, 0, 0, 10, 10, .{ .modal = false }); // a popover
    try expect(!scrollLocked(s)); // popover leaves the background live
    _ = push(&s, 2, 0, 0, 10, 10, .{ .modal = true }); // a modal on top
    try expect(scrollLocked(s));
    pop(&s);
    try expect(!scrollLocked(s));
}

test "overlay: outside-press dismisses only when the top layer opts in" {
    var s: Stack = .{};
    _ = push(&s, 1, 100, 100, 50, 40, .{ .dismiss_outside = true });
    try expect(!dismissOnPress(&s, 120, 120)); // inside content -> keep
    try expect(dismissOnPress(&s, 10, 10)); // outside -> dismiss
    // A layer that does not opt in never dismisses on outside press.
    pop(&s);
    _ = push(&s, 2, 100, 100, 50, 40, .{ .dismiss_outside = false });
    try expect(!dismissOnPress(&s, 10, 10));
    // Empty stack: nothing to dismiss.
    clear(&s);
    try expect(!dismissOnPress(&s, 10, 10));
}

test "overlay: scrimAlpha scales the seated opacity by present progress" {
    try expectEq(@as(u8, 0), scrimAlpha(0.0, 180));
    try expectEq(@as(u8, 180), scrimAlpha(1.0, 180));
    try expectEq(@as(u8, 90), scrimAlpha(0.5, 180));
    try expectEq(@as(u8, 180), scrimAlpha(2.0, 180)); // clamped
    try expectEq(@as(u8, 0), scrimAlpha(-1.0, 180)); // clamped
}

test "overlay: contains_id and clear" {
    var s: Stack = .{};
    _ = push(&s, 7, 0, 0, 10, 10, .{});
    _ = push(&s, 9, 0, 0, 10, 10, .{});
    try expect(contains_id(s, 7));
    try expect(contains_id(s, 9));
    try expect(!contains_id(s, 5));
    clear(&s);
    try expect(!contains_id(s, 7));
    try expect(!isOpen(s));
}
