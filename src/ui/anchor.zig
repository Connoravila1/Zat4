//! Rover · anchor — anchored / floating positioning.
//!
//! PORTABLE (Rover rule): PURE, `std`-only, plain data in / plain data out. This is
//! the web's floating-ui / CSS-anchor behavior expressed as free functions: given
//! an ANCHOR rect (the button/word the popover belongs to), the CONTENT size, and
//! the VIEWPORT, it returns the floating element's final rect — placed on a
//! preferred side, FLIPPED to the opposite side when the preferred one would clip,
//! and SHIFTED along the cross axis to stay on screen. One primitive for tooltips,
//! popovers, dropdown menus, context menus — anything that hangs off an anchor.
//!
//! The reusable artifact is the GEOMETRY, not the pixels: the host takes the
//! returned rect and draws its surface there however it draws. No renderer, no app
//! types, no clock — same input always yields the same rect. All values are LOGICAL
//! (design) pixels; this codebase lays out in integer logical px, so coordinates
//! are `i32` throughout (y grows downward, x grows rightward, top-left origin).

const std = @import("std");
const assert = std.debug.assert;

/// PLAIN DATA (A1): an axis-aligned rectangle in logical px. The anchor, the
/// viewport, and the returned floating box are all `Rect`s. Hot: rects are the
/// currency of layout and pass through this module in bulk.
pub const Rect = struct {
    x: i32 = 0,
    y: i32 = 0,
    w: i32 = 0,
    h: i32 = 0,

    comptime {
        // Four i32, no padding.
        assert(@sizeOf(Rect) == 16);
    }
};

/// Which side of the anchor the content is preferred to sit on. `bottom` means the
/// content hangs BELOW the anchor (a dropdown), `top` ABOVE it, etc.
pub const Side = enum(u8) { top, bottom, left, right };

/// Cross-axis alignment of the content against the anchor. For a top/bottom
/// placement this is horizontal (`start` = left edges flush); for a left/right
/// placement it is vertical (`start` = top edges flush).
pub const Align = enum(u8) { start, center, end };

/// PLAIN DATA (A1): the caller's PREFERRED placement. `place()` treats it as a hint
/// and may flip `side` to its opposite when the preferred side does not fit.
pub const Placement = struct {
    side: Side = .bottom,
    alignment: Align = .center,

    comptime {
        // Two u8-backed enums, no padding.
        assert(@sizeOf(Placement) == 2);
    }
};

/// The opposite side — used by the flip step.
fn opposite(side: Side) Side {
    return switch (side) {
        .top => .bottom,
        .bottom => .top,
        .left => .right,
        .right => .left,
    };
}

/// The free space (px) available for content on `side` of the anchor, after
/// reserving `gap`. May be negative when the anchor is flush against that edge.
fn spaceOnSide(side: Side, anchor: Rect, viewport: Rect, gap: i32) i32 {
    return switch (side) {
        .bottom => (viewport.y + viewport.h) - (anchor.y + anchor.h + gap),
        .top => (anchor.y - gap) - viewport.y,
        .right => (viewport.x + viewport.w) - (anchor.x + anchor.w + gap),
        .left => (anchor.x - gap) - viewport.x,
    };
}

/// The cross-axis start coordinate for the given alignment. `anchor_start` /
/// `anchor_size` describe the anchor along the cross axis; `content_size` is the
/// content's extent along that same axis.
fn alignCross(anchor_start: i32, anchor_size: i32, content_size: i32, alignment: Align) i32 {
    return switch (alignment) {
        .start => anchor_start,
        .center => anchor_start + @divTrunc(anchor_size - content_size, 2),
        .end => anchor_start + anchor_size - content_size,
    };
}

/// Position content of `cw`×`ch` on `side` of `anchor`, offset by `gap`, aligned per
/// `alignment` on the cross axis. Pure placement — no viewport clamping yet.
fn positionOnSide(side: Side, anchor: Rect, cw: i32, ch: i32, gap: i32, alignment: Align) Rect {
    return switch (side) {
        .top => .{
            .x = alignCross(anchor.x, anchor.w, cw, alignment),
            .y = anchor.y - gap - ch,
            .w = cw,
            .h = ch,
        },
        .bottom => .{
            .x = alignCross(anchor.x, anchor.w, cw, alignment),
            .y = anchor.y + anchor.h + gap,
            .w = cw,
            .h = ch,
        },
        .left => .{
            .x = anchor.x - gap - cw,
            .y = alignCross(anchor.y, anchor.h, ch, alignment),
            .w = cw,
            .h = ch,
        },
        .right => .{
            .x = anchor.x + anchor.w + gap,
            .y = alignCross(anchor.y, anchor.h, ch, alignment),
            .w = cw,
            .h = ch,
        },
    };
}

/// True when `r` lies wholly inside `viewport`.
pub fn fits(r: Rect, viewport: Rect) bool {
    return r.x >= viewport.x and
        r.y >= viewport.y and
        (r.x + r.w) <= (viewport.x + viewport.w) and
        (r.y + r.h) <= (viewport.y + viewport.h);
}

/// Nudge `r` so it sits inside `viewport`. When `r` fits, this returns it fully
/// on-screen; when `r` is LARGER than the viewport on an axis, that axis is pinned
/// to the top/left edge (over-hanging the far edge is unavoidable). The far-edge
/// clamp is applied first so the near-edge clamp wins for oversized content.
pub fn clampToViewport(r: Rect, viewport: Rect) Rect {
    var out = r;

    const max_x = (viewport.x + viewport.w) - r.w;
    if (out.x > max_x) out.x = max_x;
    if (out.x < viewport.x) out.x = viewport.x;

    const max_y = (viewport.y + viewport.h) - r.h;
    if (out.y > max_y) out.y = max_y;
    if (out.y < viewport.y) out.y = viewport.y;

    return out;
}

/// Place a `content_w`×`content_h` floating element next to `anchor`, preferring
/// `want`, keeping it inside `viewport`, with `gap` px between anchor and content.
///
/// Order of operations (floating-ui's model):
///   1. FLIP — if the preferred side lacks room for the content's main-axis extent
///      and the opposite side has more room, place on the opposite side instead.
///   2. Position on the chosen side, cross-aligned per `want.alignment`.
///   3. SHIFT + clamp — slide the content back inside the viewport. Along the cross
///      axis this is the shift that keeps it attached to the anchor; along the main
///      axis it is a safety clamp that only bites in the degenerate case where the
///      content fits on neither side.
///
/// Guarantee: if the content fits inside the viewport at all, the returned rect is
/// wholly inside it (`fits(place(...), viewport)` is true).
pub fn place(anchor: Rect, content_w: i32, content_h: i32, viewport: Rect, want: Placement, gap: i32) Rect {
    var side = want.side;

    // 1. FLIP. The main axis is the axis the side pushes along.
    const main_extent: i32 = switch (side) {
        .top, .bottom => content_h,
        .left, .right => content_w,
    };
    const space_pref = spaceOnSide(side, anchor, viewport, gap);
    const space_opp = spaceOnSide(opposite(side), anchor, viewport, gap);
    if (space_pref < main_extent and space_opp > space_pref) {
        side = opposite(side);
    }

    // 2. Position on the chosen side.
    const positioned = positionOnSide(side, anchor, content_w, content_h, gap, want.alignment);

    // 3. SHIFT (cross axis) + safety clamp (main axis).
    return clampToViewport(positioned, viewport);
}

// ---------------------------------------------------------------------------

const vp: Rect = .{ .x = 0, .y = 0, .w = 1000, .h = 800 };

test "anchor: bottom placement that fits stays on the bottom" {
    const anchor: Rect = .{ .x = 450, .y = 400, .w = 100, .h = 40 };
    const r = place(anchor, 200, 100, vp, .{ .side = .bottom, .alignment = .center }, 8);
    // Below the anchor: y = anchor.y + anchor.h + gap.
    try std.testing.expectEqual(@as(i32, 448), r.y);
    // Centered over the anchor: 450 + (100-200)/2 = 400.
    try std.testing.expectEqual(@as(i32, 400), r.x);
    try std.testing.expect(fits(r, vp));
}

test "anchor: bottom placement that would overflow the bottom flips to top" {
    const anchor: Rect = .{ .x = 450, .y = 740, .w = 100, .h = 40 };
    const r = place(anchor, 200, 100, vp, .{ .side = .bottom, .alignment = .center }, 8);
    // No room below (740+40+8+100 = 888 > 800), plenty above -> flip to top.
    // Top placement: y = anchor.y - gap - content_h = 740 - 8 - 100 = 632.
    try std.testing.expectEqual(@as(i32, 632), r.y);
    try std.testing.expect(r.y + r.h <= anchor.y); // sits entirely above the anchor
    try std.testing.expect(fits(r, vp));
}

test "anchor: right placement that would overflow the right flips to left" {
    const anchor: Rect = .{ .x = 900, .y = 400, .w = 60, .h = 40 };
    const r = place(anchor, 200, 100, vp, .{ .side = .right, .alignment = .center }, 8);
    // No room right (900+60+8+200 = 1168 > 1000) -> flip to left.
    // Left placement: x = anchor.x - gap - content_w = 900 - 8 - 200 = 692.
    try std.testing.expectEqual(@as(i32, 692), r.x);
    try std.testing.expect(r.x + r.w <= anchor.x);
    try std.testing.expect(fits(r, vp));
}

test "anchor: centered placement near a viewport edge shifts to stay visible" {
    // Anchor near the right edge; a wide centered popover would spill off the right.
    const anchor: Rect = .{ .x = 920, .y = 400, .w = 60, .h = 40 };
    const r = place(anchor, 200, 100, vp, .{ .side = .bottom, .alignment = .center }, 8);
    // Preferred bottom fits vertically (y = 448); horizontal center = 920+(60-200)/2 = 850,
    // which spills (850+200 = 1050 > 1000), so it SHIFTS left to max_x = 1000-200 = 800.
    try std.testing.expectEqual(@as(i32, 448), r.y); // still on the bottom, not flipped
    try std.testing.expectEqual(@as(i32, 800), r.x); // shifted flush to the right edge
    try std.testing.expect(fits(r, vp));
}

test "anchor: shift also protects the near (left/top) edges" {
    // Anchor near the left edge; centered content spills off the left -> shift to x=0.
    const anchor: Rect = .{ .x = 10, .y = 10, .w = 60, .h = 40 };
    const r = place(anchor, 200, 100, vp, .{ .side = .bottom, .alignment = .center }, 8);
    try std.testing.expectEqual(@as(i32, 0), r.x);
    try std.testing.expect(fits(r, vp));
}

test "anchor: start/end alignment place the cross edge flush with the anchor" {
    const anchor: Rect = .{ .x = 300, .y = 300, .w = 120, .h = 40 };
    const start = place(anchor, 80, 60, vp, .{ .side = .bottom, .alignment = .start }, 6);
    try std.testing.expectEqual(anchor.x, start.x); // left edges flush
    const end = place(anchor, 80, 60, vp, .{ .side = .bottom, .alignment = .end }, 6);
    try std.testing.expectEqual(anchor.x + anchor.w - 80, end.x); // right edges flush
}

test "anchor: content that fits is always fully within the viewport after place()" {
    const sides = [_]Side{ .top, .bottom, .left, .right };
    const aligns = [_]Align{ .start, .center, .end };
    // Sweep anchors across the whole viewport, including hard against every edge.
    var ax: i32 = -20;
    while (ax <= 1020) : (ax += 85) {
        var ay: i32 = -20;
        while (ay <= 820) : (ay += 85) {
            const anchor: Rect = .{ .x = ax, .y = ay, .w = 50, .h = 30 };
            for (sides) |s| {
                for (aligns) |a| {
                    // Content comfortably smaller than the viewport -> must always fit.
                    const r = place(anchor, 220, 140, vp, .{ .side = s, .alignment = a }, 10);
                    try std.testing.expect(fits(r, vp));
                }
            }
        }
    }
}

test "anchor: fits and clampToViewport behave on the boundary" {
    try std.testing.expect(fits(.{ .x = 0, .y = 0, .w = 1000, .h = 800 }, vp));
    try std.testing.expect(!fits(.{ .x = 1, .y = 0, .w = 1000, .h = 800 }, vp));
    // Oversized content pins to the top-left, overhanging the far edge.
    const big = clampToViewport(.{ .x = 500, .y = 500, .w = 1200, .h = 900 }, vp);
    try std.testing.expectEqual(@as(i32, 0), big.x);
    try std.testing.expectEqual(@as(i32, 0), big.y);
}
