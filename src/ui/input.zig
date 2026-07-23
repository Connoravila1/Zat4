//! Rover · input — hit-testing, pointer capture, and focus.
//!
//! PORTABLE (Rover rule): PURE, standalone, `std`-only. No renderer, no window
//! backend, no app types. This is the second SPINE primitive — the input model the
//! browser gives free. It ends a whole class of native-UI bugs: a control is
//! interactive because it registered a REGION, not because someone remembered to
//! wire it into a render signature or a "who owns the keyboard" predicate.
//!
//! The host, each frame, builds a flat list of `Region`s (a rect + a host-STABLE id
//! + a z-order + capability flags) in draw order, and feeds one `Pointer` sample.
//! `update` resolves:
//!   · HOVER   — the topmost region under the pointer (z-order, later-drawn wins ties).
//!   · CAPTURE — once pressed, the pointer stays bound to that control even if the
//!     finger leaves its rect (a real drag), until release.
//!   · PRESS / ACTIVE / CLICK — `active` is the pressed control while the pointer is
//!     still over it (the "pushed in" look); `clicked` fires on release over the same
//!     control the press began on (a real click/tap, not a drag-off cancel).
//!   · FOCUS — pressing a focusable control focuses it; pressing empty space blurs;
//!     `focusNext` walks the tab order. `ownsKeyboard` answers "should the soft
//!     keyboard be up" from the focused control's flag — no per-field predicate.
//!
//! Ids are host-stable values (a hash of the control's identity), so focus and
//! capture persist across frames. `0` is reserved as "no control" (`none`). The id
//! is the only thing that crosses the boundary (Rover A5: a stable id, not an index).

const std = @import("std");
const assert = std.debug.assert;

/// A host-stable control id. `none` (0) means "no control".
pub const Id = u32;
pub const none: Id = 0;

/// Per-region capabilities. Out-of-band bits, not fat bools (Rover A6).
pub const Flags = packed struct(u8) {
    /// Can receive focus and participate in tab traversal.
    focusable: bool = false,
    /// A text input: owns the soft keyboard while focused.
    keyboard: bool = false,
    /// Present but inert — never hit-tested, never focusable.
    disabled: bool = false,
    _pad: u5 = 0,
};

/// One interactive region for this frame. Hot (a list per frame): size-guarded.
pub const Region = struct {
    id: Id,
    x: f32,
    y: f32,
    w: f32,
    h: f32,
    z: i16 = 0, // higher is on top; ties broken by draw order (later wins)
    flags: Flags = .{},

    comptime {
        // id(4) + rect(16) + z(2) + flags(1) + 1 pad = 24.
        assert(@sizeOf(Region) == 24);
    }
};

/// A pointer sample for the frame.
pub const Pointer = struct {
    x: f32 = 0,
    y: f32 = 0,
    down: bool = false,
    // A7.2: cold — a per-frame parameter value, never stored in bulk.
};

/// Persistent interaction state — one per input surface, held by the host across
/// frames. Plain data (Rover A1); the host owns it, `update` transitions it.
pub const State = struct {
    focus: Id = none, // focused control
    capture: Id = none, // control the pointer is bound to during a drag
    hover: Id = none, // resolved hover target this frame
    pressed: Id = none, // control the current press began on
    focus_visible: bool = false, // show a focus ring (keyboard-driven focus)
    was_down: bool = false, // previous frame's pointer state (edge detection)
    // A7.2: cold — a single instance per surface, not held in a collection.
};

/// What happened this frame. Returned by value; the host reads it to drive actions
/// and visual states.
pub const Event = struct {
    hover: Id = none, // pointer is over this control
    active: Id = none, // pressed AND pointer still over it (the "pushed in" look)
    pressed: Id = none, // press is held on this control (even if dragged off)
    clicked: Id = none, // a completed click/tap fired on this control this frame
    focus: Id = none, // currently focused control
    // A7.2: cold — a per-frame return value.
};

inline fn contains(r: Region, px: f32, py: f32) bool {
    return px >= r.x and px < r.x + r.w and py >= r.y and py < r.y + r.h;
}

/// The topmost hittable region under the point, or `none`. Highest `z` wins; equal
/// `z` resolves to the region later in the list (drawn on top). Disabled regions and
/// zero-`id` regions are transparent to hit-testing.
pub fn hitTest(regions: []const Region, px: f32, py: f32) Id {
    var best: Id = none;
    var best_z: i16 = std.math.minInt(i16);
    var seen = false;
    for (regions) |r| {
        if (r.id == none or r.flags.disabled) continue;
        if (!contains(r, px, py)) continue;
        if (!seen or r.z >= best_z) {
            best_z = r.z;
            best = r.id;
            seen = true;
        }
    }
    return best;
}

fn regionById(regions: []const Region, id: Id) ?Region {
    if (id == none) return null;
    for (regions) |r| if (r.id == id) return r;
    return null;
}

fn isFocusable(regions: []const Region, id: Id) bool {
    if (regionById(regions, id)) |r| return r.flags.focusable and !r.flags.disabled;
    return false;
}

/// Advance the interaction state one frame and report what happened. Pure over
/// (state, regions, pointer): the same inputs always produce the same transition.
pub fn update(s: *State, regions: []const Region, p: Pointer) Event {
    const raw = hitTest(regions, p.x, p.y); // real control under the pointer
    // While captured, the target stays the captured control (pointer capture).
    const target: Id = if (s.capture != none) s.capture else raw;
    s.hover = target;

    var clicked: Id = none;
    const press_edge = p.down and !s.was_down;
    const release_edge = !p.down and s.was_down;

    if (press_edge) {
        s.pressed = target;
        if (target != none) s.capture = target;
        if (target == none) {
            // Pressed empty space: blur.
            s.focus = none;
            s.focus_visible = false;
        } else if (isFocusable(regions, target)) {
            // Pointer focus: focus the control, but no ring (ring is for keyboard nav).
            s.focus = target;
            s.focus_visible = false;
        }
        // Pressing a non-focusable interactive control leaves focus unchanged.
    }

    if (release_edge) {
        // A click completes only if the release is over the same control the press
        // began on — dragging off and releasing cancels it.
        if (s.pressed != none and raw == s.pressed) clicked = s.pressed;
        s.capture = none;
        s.pressed = none;
    }

    s.was_down = p.down;

    const active: Id = if (p.down and s.pressed != none and raw == s.pressed) s.pressed else none;
    return .{
        .hover = s.hover,
        .active = active,
        .pressed = if (p.down) s.pressed else none,
        .clicked = clicked,
        .focus = s.focus,
    };
}

/// Move focus to the next (or previous) focusable control in tab order (list order
/// for v1; explicit tabindex is deferred). Wraps around. Marks focus visible, since
/// keyboard-driven focus should show a ring. No-op if nothing is focusable.
pub fn focusNext(s: *State, regions: []const Region, forward: bool) void {
    // Index of the currently focused region within the list, if any.
    var cur: ?usize = null;
    for (regions, 0..) |r, i| {
        if (r.id == s.focus and r.flags.focusable and !r.flags.disabled) {
            cur = i;
            break;
        }
    }

    const n = regions.len;
    if (n == 0) return;
    // Walk the list starting after the current position, wrapping once.
    var step: usize = 0;
    while (step < n) : (step += 1) {
        const off = step + 1;
        const i: usize = if (cur) |c|
            (if (forward) (c + off) % n else (c + n * n - off) % n)
        else
            (if (forward) (off - 1) % n else (n - off) % n);
        const r = regions[i];
        if (r.flags.focusable and !r.flags.disabled and r.id != none) {
            s.focus = r.id;
            s.focus_visible = true;
            return;
        }
    }
    // Nothing focusable at all: leave focus as-is.
}

/// Should the soft keyboard be raised? True iff the focused control is a text input.
/// Replaces bespoke per-field "who owns the keyboard" predicates.
pub fn ownsKeyboard(s: State, regions: []const Region) bool {
    if (regionById(regions, s.focus)) |r| return r.flags.keyboard and !r.flags.disabled;
    return false;
}

/// Clear focus and any in-progress capture/press (e.g. on screen change).
pub fn blur(s: *State) void {
    s.focus = none;
    s.focus_visible = false;
    s.capture = none;
    s.pressed = none;
}

// ---------------------------------------------------------------------------

const expect = std.testing.expect;
const expectEq = std.testing.expectEqual;

test "input: hitTest picks the topmost by z, ties by draw order, skips disabled" {
    const regs = [_]Region{
        .{ .id = 1, .x = 0, .y = 0, .w = 100, .h = 100, .z = 0 },
        .{ .id = 2, .x = 10, .y = 10, .w = 20, .h = 20, .z = 5 }, // on top
        .{ .id = 3, .x = 10, .y = 10, .w = 20, .h = 20, .z = 5 }, // same z, later -> wins tie
        .{ .id = 4, .x = 50, .y = 50, .w = 20, .h = 20, .z = 9, .flags = .{ .disabled = true } },
    };
    try expectEq(@as(Id, 3), hitTest(&regs, 15, 15)); // overlap of 1/2/3 -> highest z, latest
    try expectEq(@as(Id, 1), hitTest(&regs, 80, 5)); // only region 1
    try expectEq(@as(Id, 1), hitTest(&regs, 55, 55)); // over disabled -> transparent, falls through to the panel beneath
    try expectEq(@as(Id, none), hitTest(&regs, 200, 200)); // miss -> none
}

test "input: a click fires only on release over the same control" {
    const regs = [_]Region{.{ .id = 7, .x = 0, .y = 0, .w = 50, .h = 50 }};
    var s: State = .{};
    _ = update(&s, &regs, .{ .x = 10, .y = 10, .down = false }); // hover, no press
    const press = update(&s, &regs, .{ .x = 10, .y = 10, .down = true });
    try expectEq(@as(Id, 7), press.active); // pushed in
    try expectEq(@as(Id, none), press.clicked); // not yet
    const release = update(&s, &regs, .{ .x = 10, .y = 10, .down = false });
    try expectEq(@as(Id, 7), release.clicked); // fired
}

test "input: pointer capture keeps the target when dragged off; release off cancels" {
    const regs = [_]Region{.{ .id = 7, .x = 0, .y = 0, .w = 50, .h = 50 }};
    var s: State = .{};
    _ = update(&s, &regs, .{ .x = 10, .y = 10, .down = false });
    _ = update(&s, &regs, .{ .x = 10, .y = 10, .down = true }); // press inside
    const dragged = update(&s, &regs, .{ .x = 200, .y = 200, .down = true }); // finger left the rect
    try expectEq(@as(Id, 7), dragged.pressed); // still captured/pressed
    try expectEq(@as(Id, none), dragged.active); // but not "pushed in" (pointer is off it)
    const release_off = update(&s, &regs, .{ .x = 200, .y = 200, .down = false });
    try expectEq(@as(Id, none), release_off.clicked); // released off target -> no click
    try expectEq(@as(Id, none), s.capture); // capture released
}

test "input: focus follows a press on a focusable control; empty space blurs" {
    const regs = [_]Region{
        .{ .id = 1, .x = 0, .y = 0, .w = 40, .h = 40, .flags = .{ .focusable = true } },
        .{ .id = 2, .x = 50, .y = 0, .w = 40, .h = 40 }, // not focusable
    };
    var s: State = .{};
    _ = update(&s, &regs, .{ .x = 10, .y = 10, .down = true });
    _ = update(&s, &regs, .{ .x = 10, .y = 10, .down = false });
    try expectEq(@as(Id, 1), s.focus); // pressed the focusable -> focused

    // Press the non-focusable control: focus unchanged.
    _ = update(&s, &regs, .{ .x = 60, .y = 10, .down = true });
    _ = update(&s, &regs, .{ .x = 60, .y = 10, .down = false });
    try expectEq(@as(Id, 1), s.focus);

    // Press empty space: blur.
    _ = update(&s, &regs, .{ .x = 300, .y = 300, .down = true });
    try expectEq(@as(Id, none), s.focus);
}

test "input: focusNext walks focusable controls in order and wraps, ring visible" {
    const regs = [_]Region{
        .{ .id = 1, .x = 0, .y = 0, .w = 10, .h = 10, .flags = .{ .focusable = true } },
        .{ .id = 2, .x = 0, .y = 0, .w = 10, .h = 10 }, // skipped (not focusable)
        .{ .id = 3, .x = 0, .y = 0, .w = 10, .h = 10, .flags = .{ .focusable = true } },
        .{ .id = 4, .x = 0, .y = 0, .w = 10, .h = 10, .flags = .{ .focusable = true, .disabled = true } }, // skipped
    };
    var s: State = .{};
    focusNext(&s, &regs, true);
    try expectEq(@as(Id, 1), s.focus);
    try expect(s.focus_visible);
    focusNext(&s, &regs, true);
    try expectEq(@as(Id, 3), s.focus); // 2 skipped
    focusNext(&s, &regs, true);
    try expectEq(@as(Id, 1), s.focus); // 4 disabled -> wrap to 1
    focusNext(&s, &regs, false);
    try expectEq(@as(Id, 3), s.focus); // backward wraps to last focusable
}

test "input: ownsKeyboard is true only when a text input is focused" {
    const regs = [_]Region{
        .{ .id = 1, .x = 0, .y = 0, .w = 10, .h = 10, .flags = .{ .focusable = true } }, // button
        .{ .id = 2, .x = 0, .y = 0, .w = 10, .h = 10, .flags = .{ .focusable = true, .keyboard = true } }, // field
    };
    var s: State = .{};
    s.focus = 1;
    try expect(!ownsKeyboard(s, &regs));
    s.focus = 2;
    try expect(ownsKeyboard(s, &regs));
    blur(&s);
    try expect(!ownsKeyboard(s, &regs));
}

test "input: a disabled control is never hit, focused, or keyboard-owning" {
    const regs = [_]Region{
        .{ .id = 1, .x = 0, .y = 0, .w = 40, .h = 40, .flags = .{ .focusable = true, .keyboard = true, .disabled = true } },
    };
    var s: State = .{};
    const e = update(&s, &regs, .{ .x = 10, .y = 10, .down = true });
    try expectEq(@as(Id, none), e.hover);
    try expectEq(@as(Id, none), s.focus);
    focusNext(&s, &regs, true);
    try expectEq(@as(Id, none), s.focus);
    s.focus = 1; // even if forced, a disabled field doesn't raise the keyboard
    try expect(!ownsKeyboard(s, &regs));
}
