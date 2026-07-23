//! Rover · layout — the flex/stack layout engine (two-pass measure → arrange).
//!
//! PORTABLE (Rover rule): PURE, standalone, `std`-only. No renderer, no app types.
//! This is the KEYSTONE — the reason an HTML mockup "just works": you describe
//! INTENT (a row, a column, gaps, alignment, which child grows) and the solver
//! computes every rect. Nothing at a call site is a hand-added pixel offset.
//!
//! The reusable artifact is the GEOMETRY. The host builds a tree of nodes, each a
//! `Spec` (row/col, gap, padding, sizing mode, alignment); for leaves it passes the
//! measured content size (text measured by the host's own font engine — the module
//! never measures pixels). `solve()` runs:
//!   · PASS 1 measure  (post-order): each node's INTRINSIC size — a container hugs
//!     its children + padding, a leaf hugs its content. This is what lets a button
//!     size to `label + padding` without a magic width.
//!   · PASS 2 arrange  (pre-order): each node's final rect — distribute leftover
//!     main-axis space to `grow` children, justify along the main axis, align on the
//!     cross axis, recurse.
//! The host then reads `rectOf(node)` per node and draws.
//!
//! Sizing modes per axis (`Fit`): `fixed` (exact px), `hug` (fit content/children),
//! `grow` (fill leftover main-axis space, weighted). Cross-axis `stretch` (an
//! alignment) makes children fill the cross axis.
//!
//! v1 scope: flex/stack (row & column). NOT yet: a full grid solver, absolutely
//! positioned/overlay children (that is the `overlay` + `anchor` primitives' job),
//! and wrap. Those are named as non-goals so nothing silently under-delivers.

const std = @import("std");
const assert = std.debug.assert;

/// A resolved rectangle in logical px — the module's output vocabulary.
pub const Rect = struct {
    x: f32 = 0,
    y: f32 = 0,
    w: f32 = 0,
    h: f32 = 0,

    comptime {
        assert(@sizeOf(Rect) == 16); // 4×f32, no padding
    }
};

/// Opaque node handle. The host receives one from `add`, links with `child`, and
/// reads its result with `rectOf` — it is used only with this module's API, never
/// as a bare index into another array (Rover A5).
pub const Node = enum(u32) { _ };

const nil: u32 = std.math.maxInt(u32);

pub const Axis = enum(u8) { row, col };

/// Main-axis distribution of the free space (CSS `justify-content`).
pub const Justify = enum(u8) { start, center, end, between, around, evenly };

/// Cross-axis placement of each child (CSS `align-items`); `stretch` fills the
/// cross axis.
pub const Cross = enum(u8) { start, center, end, stretch };

/// Per-axis sizing mode. `fixed`: exact `w`/`h`. `hug`: fit content (leaf) or
/// children (container). `grow`: take a weighted share of leftover main-axis space.
pub const Fit = enum(u8) { fixed, hug, grow };

/// One layout node. Hot (one per node, held in an array): kept tight, size-guarded.
/// For a leaf, `w`/`h` are the measured content size when the matching `*_fit` is
/// `hug` (or the exact size when `fixed`). Padding insets a container's content box.
pub const Spec = struct {
    axis: Axis = .row,
    justify: Justify = .start,
    cross: Cross = .start,
    w_fit: Fit = .hug,
    h_fit: Fit = .hug,

    w: f32 = 0, // fixed width, or leaf content width when w_fit == .hug
    h: f32 = 0, // fixed height, or leaf content height when h_fit == .hug
    grow: f32 = 1, // weight among grow siblings on the main axis
    gap: f32 = 0, // space between children (main axis)
    pad_l: f32 = 0,
    pad_t: f32 = 0,
    pad_r: f32 = 0,
    pad_b: f32 = 0,
    min_w: f32 = 0,
    min_h: f32 = 0,
    max_w: f32 = big,
    max_h: f32 = big,

    comptime {
        // A7.1: a layout node — 12 geometry f32 (size/grow/gap/4×pad/4×min-max) plus
        // 5 mode enums packed into the leading alignment pad. 56 bytes packed; this
        // is the whole per-node budget and it never grows in a loop beyond node count.
        assert(@sizeOf(Spec) == 56);
    }
};

/// A large finite sentinel for "no max" — avoids infinities leaking into arithmetic.
pub const big: f32 = 1_000_000_000;

/// The layout arena: parallel arrays (SoA) for specs, the child linked-list, the
/// measured intrinsic sizes, and the output rects. Cold (one per layout pass,
/// reused across frames via `reset`) — size guard waived per A7.2.
pub const Tree = struct {
    gpa: std.mem.Allocator,
    spec: std.ArrayListUnmanaged(Spec) = .empty,
    first: std.ArrayListUnmanaged(u32) = .empty, // first child, or nil
    last: std.ArrayListUnmanaged(u32) = .empty, // last child, or nil (O(1) append)
    next: std.ArrayListUnmanaged(u32) = .empty, // next sibling, or nil
    mw: std.ArrayListUnmanaged(f32) = .empty, // measured intrinsic width
    mh: std.ArrayListUnmanaged(f32) = .empty, // measured intrinsic height
    out: std.ArrayListUnmanaged(Rect) = .empty, // arranged rects

    pub fn init(gpa: std.mem.Allocator) Tree {
        return .{ .gpa = gpa };
    }

    pub fn deinit(t: *Tree) void {
        t.spec.deinit(t.gpa);
        t.first.deinit(t.gpa);
        t.last.deinit(t.gpa);
        t.next.deinit(t.gpa);
        t.mw.deinit(t.gpa);
        t.mh.deinit(t.gpa);
        t.out.deinit(t.gpa);
    }

    /// Clear for a fresh layout pass, keeping the allocated capacity.
    pub fn reset(t: *Tree) void {
        t.spec.clearRetainingCapacity();
        t.first.clearRetainingCapacity();
        t.last.clearRetainingCapacity();
        t.next.clearRetainingCapacity();
        t.mw.clearRetainingCapacity();
        t.mh.clearRetainingCapacity();
        t.out.clearRetainingCapacity();
    }

    /// Add a node (leaf or container) and return its handle. Link children onto it
    /// with `child`. Allocation is explicit here (Rover C1/C2).
    pub fn add(t: *Tree, s: Spec) !Node {
        const id: u32 = @intCast(t.spec.items.len);
        try t.spec.append(t.gpa, s);
        try t.first.append(t.gpa, nil);
        try t.last.append(t.gpa, nil);
        try t.next.append(t.gpa, nil);
        try t.mw.append(t.gpa, 0);
        try t.mh.append(t.gpa, 0);
        try t.out.append(t.gpa, .{});
        return @enumFromInt(id);
    }

    /// Append `kid` as the last child of `parent` (order preserved).
    pub fn child(t: *Tree, parent: Node, kid: Node) void {
        const p = @intFromEnum(parent);
        const k = @intFromEnum(kid);
        if (t.first.items[p] == nil) {
            t.first.items[p] = k;
        } else {
            t.next.items[t.last.items[p]] = k;
        }
        t.last.items[p] = k;
    }

    /// The arranged rect of a node. Valid after `solve`.
    pub fn rectOf(t: *const Tree, n: Node) Rect {
        return t.out.items[@intFromEnum(n)];
    }

    /// Run both passes. `root` fills a box sized from `avail_w`/`avail_h` (a `grow`
    /// root fills the available space; a `hug` root shrinks to its content; a `fixed`
    /// root uses its own size). After this, read results with `rectOf`.
    pub fn solve(t: *Tree, root: Node, avail_w: f32, avail_h: f32) void {
        measure(t, @intFromEnum(root));
        const r = @intFromEnum(root);
        const s = t.spec.items[r];
        const rw = clamp(switch (s.w_fit) {
            .fixed => s.w,
            .hug => t.mw.items[r],
            .grow => avail_w,
        }, s.min_w, s.max_w);
        const rh = clamp(switch (s.h_fit) {
            .fixed => s.h,
            .hug => t.mh.items[r],
            .grow => avail_h,
        }, s.min_h, s.max_h);
        arrange(t, r, .{ .x = 0, .y = 0, .w = rw, .h = rh });
    }
};

// --- pure helpers -----------------------------------------------------------

inline fn clamp(v: f32, lo: f32, hi: f32) f32 {
    return std.math.clamp(v, lo, @max(lo, hi));
}

inline fn mainOf(w: f32, h: f32, axis: Axis) f32 {
    return if (axis == .row) w else h;
}
inline fn crossOf(w: f32, h: f32, axis: Axis) f32 {
    return if (axis == .row) h else w;
}

/// A child's own sizing mode / size / bounds along the parent's MAIN axis.
inline fn childMainFit(s: Spec, axis: Axis) Fit {
    return if (axis == .row) s.w_fit else s.h_fit;
}
inline fn childCrossFit(s: Spec, axis: Axis) Fit {
    return if (axis == .row) s.h_fit else s.w_fit;
}

// --- pass 1: measure intrinsic sizes (post-order) ---------------------------

fn measure(t: *Tree, n: u32) void {
    const s = t.spec.items[n];
    const kids = t.first.items[n];

    if (kids == nil) {
        // Leaf: intrinsic = content size (hug/fixed), or the floor (grow).
        const iw = if (s.w_fit == .grow) s.min_w else s.w;
        const ih = if (s.h_fit == .grow) s.min_h else s.h;
        t.mw.items[n] = clamp(iw, s.min_w, s.max_w);
        t.mh.items[n] = clamp(ih, s.min_h, s.max_h);
        return;
    }

    // Container: measure children first, then sum along main / max along cross.
    var sum_main: f32 = 0;
    var max_cross: f32 = 0;
    var count: f32 = 0;
    var c = kids;
    while (c != nil) : (c = t.next.items[c]) {
        measure(t, c);
        sum_main += mainOf(t.mw.items[c], t.mh.items[c], s.axis);
        max_cross = @max(max_cross, crossOf(t.mw.items[c], t.mh.items[c], s.axis));
        count += 1;
    }
    const gaps = if (count > 1) s.gap * (count - 1) else 0;
    const content_main = sum_main + gaps;

    // Fold padding back into width/height space.
    const pad_main = if (s.axis == .row) s.pad_l + s.pad_r else s.pad_t + s.pad_b;
    const pad_cross = if (s.axis == .row) s.pad_t + s.pad_b else s.pad_l + s.pad_r;
    const intrinsic_main = content_main + pad_main;
    const intrinsic_cross = max_cross + pad_cross;

    const iw = if (s.axis == .row) intrinsic_main else intrinsic_cross;
    const ih = if (s.axis == .row) intrinsic_cross else intrinsic_main;

    // A fixed axis reports its fixed size; hug/grow report the intrinsic content.
    t.mw.items[n] = clamp(if (s.w_fit == .fixed) s.w else iw, s.min_w, s.max_w);
    t.mh.items[n] = clamp(if (s.h_fit == .fixed) s.h else ih, s.min_h, s.max_h);
}

// --- pass 2: arrange final rects (pre-order) --------------------------------

fn arrange(t: *Tree, n: u32, rect: Rect) void {
    t.out.items[n] = rect;
    const s = t.spec.items[n];
    const kids = t.first.items[n];
    if (kids == nil) return;

    // Content box (inside padding), never negative.
    const cx = rect.x + s.pad_l;
    const cy = rect.y + s.pad_t;
    const cw = @max(0.0, rect.w - s.pad_l - s.pad_r);
    const ch = @max(0.0, rect.h - s.pad_t - s.pad_b);
    const main = if (s.axis == .row) cw else ch;
    const cross = if (s.axis == .row) ch else cw;

    // Pass A: base main sizes, grow weights, count.
    var sum_base: f32 = 0;
    var total_weight: f32 = 0;
    var count: f32 = 0;
    var c = kids;
    while (c != nil) : (c = t.next.items[c]) {
        const cs = t.spec.items[c];
        sum_base += childBaseMain(t, c, cs, s.axis);
        if (childMainFit(cs, s.axis) == .grow) total_weight += cs.grow;
        count += 1;
    }
    const gaps = if (count > 1) s.gap * (count - 1) else 0;
    const extra = @max(0.0, main - sum_base - gaps);

    // Total of final main sizes (base + distributed grow), for justify spacing.
    const sum_final = sum_base + (if (total_weight > 0) extra else 0);
    const free = @max(0.0, main - sum_final - gaps);

    // Justify: starting cursor + spacing between children.
    var cursor: f32 = 0;
    var between = s.gap;
    switch (s.justify) {
        .start => {},
        .center => cursor = free / 2,
        .end => cursor = free,
        .between => between = s.gap + (if (count > 1) free / (count - 1) else 0),
        .around => {
            const unit = if (count > 0) free / count else 0;
            cursor = unit / 2;
            between = s.gap + unit;
        },
        .evenly => {
            const unit = free / (count + 1);
            cursor = unit;
            between = s.gap + unit;
        },
    }

    // Pass B: place each child (recompute its main size deterministically).
    c = kids;
    while (c != nil) : (c = t.next.items[c]) {
        const cs = t.spec.items[c];
        var cm = childBaseMain(t, c, cs, s.axis);
        if (childMainFit(cs, s.axis) == .grow and total_weight > 0) {
            const share = extra * (cs.grow / total_weight);
            const max_main = mainOf(cs.max_w, cs.max_h, s.axis);
            cm = clamp(cm + share, mainOf(cs.min_w, cs.min_h, s.axis), max_main);
        }

        // Cross size: container `stretch` (or a child `grow` on the cross axis)
        // fills the cross box; otherwise the child keeps its own cross size.
        const fills_cross = s.cross == .stretch or childCrossFit(cs, s.axis) == .grow;
        var ck = if (fills_cross)
            cross
        else switch (childCrossFit(cs, s.axis)) {
            .fixed => crossOf(cs.w, cs.h, s.axis),
            .hug => crossOf(t.mw.items[c], t.mh.items[c], s.axis),
            .grow => cross,
        };
        ck = clamp(ck, crossOf(cs.min_w, cs.min_h, s.axis), crossOf(cs.max_w, cs.max_h, s.axis));

        // Cross position: align the child within the cross box.
        const cpos: f32 = if (fills_cross) 0 else switch (s.cross) {
            .start, .stretch => 0,
            .center => (cross - ck) / 2,
            .end => cross - ck,
        };

        const child_rect: Rect = if (s.axis == .row) .{
            .x = cx + cursor,
            .y = cy + cpos,
            .w = cm,
            .h = ck,
        } else .{
            .x = cx + cpos,
            .y = cy + cursor,
            .w = ck,
            .h = cm,
        };
        arrange(t, c, child_rect);
        cursor += cm + between;
    }
}

/// A child's main-axis size BEFORE grow distribution: its fixed size, its measured
/// hug size, or (for a grow child) its main-axis floor. Clamped to the child's bounds.
fn childBaseMain(t: *const Tree, c: u32, cs: Spec, axis: Axis) f32 {
    const v = switch (childMainFit(cs, axis)) {
        .fixed => mainOf(cs.w, cs.h, axis),
        .hug => mainOf(t.mw.items[c], t.mh.items[c], axis),
        .grow => mainOf(cs.min_w, cs.min_h, axis),
    };
    return clamp(v, mainOf(cs.min_w, cs.min_h, axis), mainOf(cs.max_w, cs.max_h, axis));
}

// --- pixel snapping (host convenience) --------------------------------------

/// Snap a rect to integer pixels by its EDGES (left/right, top/bottom rounded
/// independently) so adjacent rects stay seamless — no sub-pixel gap or overlap.
pub fn snapped(r: Rect) Rect {
    const l = @round(r.x);
    const tp = @round(r.y);
    const rt = @round(r.x + r.w);
    const bt = @round(r.y + r.h);
    return .{ .x = l, .y = tp, .w = rt - l, .h = bt - tp };
}

// ---------------------------------------------------------------------------

const expect = std.testing.expect;
const expectEq = std.testing.expectEqual;

fn approx(a: f32, b: f32) bool {
    return @abs(a - b) < 0.001;
}

test "layout: a lone fixed node fills exactly its size" {
    var t = Tree.init(std.testing.allocator);
    defer t.deinit();
    const root = try t.add(.{ .w_fit = .fixed, .h_fit = .fixed, .w = 120, .h = 40 });
    t.solve(root, 500, 500);
    const r = t.rectOf(root);
    try expect(approx(r.x, 0) and approx(r.y, 0) and approx(r.w, 120) and approx(r.h, 40));
}

test "layout: a hug container wraps children plus padding and gap" {
    var t = Tree.init(std.testing.allocator);
    defer t.deinit();
    // row, pad 8 all sides, gap 10, two 30×20 leaves -> w = 8+30+10+30+8 = 86, h = 8+20+8 = 36
    const root = try t.add(.{ .axis = .row, .gap = 10, .pad_l = 8, .pad_t = 8, .pad_r = 8, .pad_b = 8 });
    const a = try t.add(.{ .w_fit = .fixed, .h_fit = .fixed, .w = 30, .h = 20 });
    const b = try t.add(.{ .w_fit = .fixed, .h_fit = .fixed, .w = 30, .h = 20 });
    t.child(root, a);
    t.child(root, b);
    t.solve(root, 1000, 1000);
    const r = t.rectOf(root);
    try expect(approx(r.w, 86) and approx(r.h, 36));
    try expect(approx(t.rectOf(a).x, 8) and approx(t.rectOf(a).y, 8));
    try expect(approx(t.rectOf(b).x, 48)); // 8 + 30 + 10
}

test "layout: grow children split the leftover main-axis space by weight" {
    var t = Tree.init(std.testing.allocator);
    defer t.deinit();
    // row width 100, gap 0: fixed 20, grow(1), grow(3). leftover 80 -> 20 and 60.
    const root = try t.add(.{ .axis = .row, .w_fit = .fixed, .h_fit = .fixed, .w = 100, .h = 10, .cross = .stretch });
    const fixed = try t.add(.{ .w_fit = .fixed, .h_fit = .grow, .w = 20 });
    const g1 = try t.add(.{ .w_fit = .grow, .h_fit = .grow, .grow = 1 });
    const g3 = try t.add(.{ .w_fit = .grow, .h_fit = .grow, .grow = 3 });
    t.child(root, fixed);
    t.child(root, g1);
    t.child(root, g3);
    t.solve(root, 200, 200);
    try expect(approx(t.rectOf(fixed).w, 20) and approx(t.rectOf(fixed).x, 0));
    try expect(approx(t.rectOf(g1).w, 20) and approx(t.rectOf(g1).x, 20));
    try expect(approx(t.rectOf(g3).w, 60) and approx(t.rectOf(g3).x, 40));
    // stretch made every child fill the 10px cross axis.
    try expect(approx(t.rectOf(g1).h, 10) and approx(t.rectOf(fixed).h, 10));
}

test "layout: justify distributes free space (center, end, between, around, evenly)" {
    const cases = [_]struct { j: Justify, ax: f32, bx: f32 }{
        // width 100, two 20-wide children, free = 60.
        .{ .j = .start, .ax = 0, .bx = 20 },
        .{ .j = .center, .ax = 30, .bx = 50 }, // offset free/2 = 30
        .{ .j = .end, .ax = 60, .bx = 80 }, // offset free = 60
        .{ .j = .between, .ax = 0, .bx = 80 }, // ends pinned, gap = 60
        .{ .j = .around, .ax = 15, .bx = 65 }, // unit 30 -> 15, then +20+30
        .{ .j = .evenly, .ax = 20, .bx = 60 }, // unit free/3 = 20
    };
    for (cases) |cse| {
        var t = Tree.init(std.testing.allocator);
        defer t.deinit();
        const root = try t.add(.{ .axis = .row, .justify = cse.j, .w_fit = .fixed, .h_fit = .fixed, .w = 100, .h = 10 });
        const a = try t.add(.{ .w_fit = .fixed, .h_fit = .fixed, .w = 20, .h = 10 });
        const b = try t.add(.{ .w_fit = .fixed, .h_fit = .fixed, .w = 20, .h = 10 });
        t.child(root, a);
        t.child(root, b);
        t.solve(root, 200, 200);
        try expect(approx(t.rectOf(a).x, cse.ax));
        try expect(approx(t.rectOf(b).x, cse.bx));
    }
}

test "layout: cross alignment places children start/center/end" {
    const cases = [_]struct { c: Cross, y: f32, h: f32 }{
        .{ .c = .start, .y = 0, .h = 20 },
        .{ .c = .center, .y = 40, .h = 20 }, // (100-20)/2
        .{ .c = .end, .y = 80, .h = 20 }, // 100-20
        .{ .c = .stretch, .y = 0, .h = 100 }, // fills
    };
    for (cases) |cse| {
        var t = Tree.init(std.testing.allocator);
        defer t.deinit();
        const root = try t.add(.{ .axis = .row, .cross = cse.c, .w_fit = .fixed, .h_fit = .fixed, .w = 50, .h = 100 });
        const a = try t.add(.{ .w_fit = .fixed, .h_fit = .fixed, .w = 30, .h = 20 });
        t.child(root, a);
        t.solve(root, 200, 200);
        try expect(approx(t.rectOf(a).y, cse.y));
        try expect(approx(t.rectOf(a).h, cse.h));
    }
}

test "layout: a column mirrors a row on the other axis" {
    var t = Tree.init(std.testing.allocator);
    defer t.deinit();
    const root = try t.add(.{ .axis = .col, .gap = 10, .w_fit = .fixed, .h_fit = .fixed, .w = 40, .h = 100 });
    const a = try t.add(.{ .w_fit = .fixed, .h_fit = .fixed, .w = 40, .h = 20 });
    const b = try t.add(.{ .w_fit = .fixed, .h_fit = .fixed, .w = 40, .h = 20 });
    t.child(root, a);
    t.child(root, b);
    t.solve(root, 200, 200);
    try expect(approx(t.rectOf(a).y, 0));
    try expect(approx(t.rectOf(b).y, 30)); // 20 + gap 10
}

test "layout: min/max clamp the resolved size" {
    var t = Tree.init(std.testing.allocator);
    defer t.deinit();
    // A grow child capped at 25 cannot take the whole 100px row.
    const root = try t.add(.{ .axis = .row, .w_fit = .fixed, .h_fit = .fixed, .w = 100, .h = 10 });
    const g = try t.add(.{ .w_fit = .grow, .h_fit = .fixed, .h = 10, .max_w = 25 });
    t.child(root, g);
    t.solve(root, 200, 200);
    try expect(approx(t.rectOf(g).w, 25));
}

test "layout: intrinsic sizing lets a button hug label + padding" {
    var t = Tree.init(std.testing.allocator);
    defer t.deinit();
    // A "button": hug both axes, pad 12/8, one leaf = the measured label (64×18).
    const btn = try t.add(.{ .axis = .row, .pad_l = 12, .pad_r = 12, .pad_t = 8, .pad_b = 8, .cross = .center });
    const label = try t.add(.{ .w_fit = .fixed, .h_fit = .fixed, .w = 64, .h = 18 });
    t.child(btn, label);
    t.solve(btn, 500, 500);
    const r = t.rectOf(btn);
    try expect(approx(r.w, 64 + 24)); // label + horizontal padding
    try expect(approx(r.h, 18 + 16)); // label + vertical padding
}

test "layout: nested containers place descendants in absolute coordinates" {
    var t = Tree.init(std.testing.allocator);
    defer t.deinit();
    const root = try t.add(.{ .axis = .col, .pad_l = 10, .pad_t = 10, .w_fit = .fixed, .h_fit = .fixed, .w = 200, .h = 200 });
    const rowc = try t.add(.{ .axis = .row, .gap = 5, .pad_l = 4, .pad_t = 4 });
    const leaf = try t.add(.{ .w_fit = .fixed, .h_fit = .fixed, .w = 10, .h = 10 });
    t.child(root, rowc);
    t.child(rowc, leaf);
    t.solve(root, 300, 300);
    // root pad(10,10) -> rowc at (10,10); rowc pad(4,4) -> leaf at (14,14).
    try expect(approx(t.rectOf(rowc).x, 10) and approx(t.rectOf(rowc).y, 10));
    try expect(approx(t.rectOf(leaf).x, 14) and approx(t.rectOf(leaf).y, 14));
}

test "layout: children never escape the parent content box (start/hug)" {
    var t = Tree.init(std.testing.allocator);
    defer t.deinit();
    const root = try t.add(.{ .axis = .row, .gap = 6, .pad_l = 5, .pad_r = 5, .pad_t = 5, .pad_b = 5, .cross = .stretch, .w_fit = .fixed, .h_fit = .fixed, .w = 300, .h = 60 });
    var prev_right: f32 = 5; // left content edge
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        const c = try t.add(.{ .w_fit = .fixed, .h_fit = .grow, .w = 40 });
        t.child(root, c);
    }
    t.solve(root, 400, 400);
    var c = t.first.items[@intFromEnum(root)];
    while (c != nil) : (c = t.next.items[c]) {
        const r = t.out.items[c];
        try expect(r.x >= prev_right - 0.001); // no overlap / left-escape
        try expect(r.x + r.w <= 295 + 0.001); // within right content edge (300-5)
        try expect(r.y >= 5 - 0.001 and r.y + r.h <= 55 + 0.001); // within vertical content box
        prev_right = r.x + r.w;
    }
}

test "layout: degenerate inputs stay finite (no children, zero size, overflow)" {
    var t = Tree.init(std.testing.allocator);
    defer t.deinit();
    const root = try t.add(.{ .axis = .row, .gap = 10, .w_fit = .fixed, .h_fit = .fixed, .w = 10, .h = 10 });
    // three 40-wide children in a 10-wide row (heavy overflow) + padding bigger than size.
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        const c = try t.add(.{ .w_fit = .fixed, .h_fit = .fixed, .w = 40, .h = 40 });
        t.child(root, c);
    }
    t.spec.items[@intFromEnum(root)].pad_l = 100; // padding exceeds width
    t.solve(root, 0, 0);
    var c = t.first.items[@intFromEnum(root)];
    while (c != nil) : (c = t.next.items[c]) {
        const r = t.out.items[c];
        try expect(std.math.isFinite(r.x) and std.math.isFinite(r.w));
        try expect(r.w >= 0 and r.h >= 0);
    }
}

test "layout: reset reuses the arena for a fresh pass" {
    var t = Tree.init(std.testing.allocator);
    defer t.deinit();
    const a = try t.add(.{ .w_fit = .fixed, .h_fit = .fixed, .w = 10, .h = 10 });
    t.solve(a, 100, 100);
    t.reset();
    try expectEq(@as(usize, 0), t.spec.items.len);
    const b = try t.add(.{ .w_fit = .fixed, .h_fit = .fixed, .w = 20, .h = 20 });
    t.solve(b, 100, 100);
    try expect(approx(t.rectOf(b).w, 20));
}

test "layout: snapped rounds by edges so neighbours stay seamless" {
    // Two abutting rects with fractional edges must share the boundary exactly.
    const a = snapped(.{ .x = 0, .y = 0, .w = 10.4, .h = 5 });
    const b = snapped(.{ .x = 10.4, .y = 0, .w = 9.6, .h = 5 });
    try expect(approx(a.x + a.w, b.x)); // no seam, no overlap
    try expect(approx(a.w, 10) and approx(b.x, 10) and approx(b.w, 10));
}
