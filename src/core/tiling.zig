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

//! TILING (design-spike core) — the carve only.
//!
//! Pure (B1/B2): `tile(tree, dims, cfg) ⇒ viewports + seams`, no clock, no
//! I/O. This is the §1 "tile" interface of TILING_LAYOUT_DESIGN.md, built as
//! a SANDBOX module so the approach can be judged before it supersedes the
//! per-screen metric ladder in feed_view. It is reachable ONLY from the
//! `tiling-spike` harness, never from main.zig — the live render path is
//! untouched.
//!
//! What it proves: a page is a split TREE of regions; width, arrangement, and
//! which regions survive a narrow window all FALL OUT of the tree (D6 — a
//! layout change is one transform over data, not a new `screen == x` branch).
//! Collapse below a leaf minimum is an ordinary result, not an error (E4),
//! exactly as today's `min_three_col_w` already behaves.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

/// Partition axis of a split.
pub const Dir = enum(u8) { h, v };

/// The closed set of region types (design §2.1). Closed on purpose: adding a
/// kind is a deliberate act, and it keeps the content-emitter switch
/// exhaustive (E3 — no silent default). The spike renders each as a labeled
/// block; the real build routes each to a `field_ui` emitter.
pub const RegionKind = enum(u8) {
    nav, // the fixed chrome rail — a region pinned constant across pages
    masthead,
    feed,
    profile_id,
    profile_feed,
    zone_masthead,
    zone_feed,
    conv_list,
    thread,
    widgets,
    activity,
    settings,
    composer,
};

/// A content region. `weight == 0` means SIZE-TO-CONTENT: the leaf takes a
/// fixed `min` extent along the parent's axis (a masthead's natural height),
/// and the remainder is shared among the weighted siblings. `min` doubles as
/// the collapse threshold for weighted leaves (design §2.1, §0.2).
pub const Leaf = struct { kind: RegionKind, weight: u16, min: u16 };

/// A split partitions its rectangle among `children` along `dir`.
pub const Split = struct { dir: Dir, children: []const Node };

/// A page is a tree of these. COLD (A7.2 waived): one small tree per page,
/// built at navigation, never scanned in bulk — the single array-of-structs
/// concession in this design, justified because the tree is tiny and not hot.
pub const Node = union(enum) {
    leaf: Leaf,
    split: Split,
};

/// The placed window the tree carves, plus the scroll into its surface — the
/// HOT output of `tile` (one per visible region per frame). A7 guarded.
pub const Viewport = struct {
    x: u16,
    y: u16,
    w: u16,
    h: u16,
    surface: u16, // index into the surface table (A4 — never leaves the module)
    scroll: u16, // rows scrolled into the surface
    kind: RegionKind,

    comptime {
        // Budget: 4×u16 (rect) + 2×u16 (surface,scroll) + u8 (kind) = 13,
        // padded to u16 alignment → 14. EXACT (A7). Raising is an A7.1 act.
        assert(@sizeOf(Viewport) == 14);
    }
};

/// A divider between two children of a split — HOT, A7 guarded. In the live
/// build these are `fixed` cells the field flows around; here they are thin
/// rects the harness draws.
pub const Seam = struct {
    x: u16,
    y: u16,
    len: u16,
    dir: Dir,

    comptime {
        // Budget: 3×u16 + u8 = 7, padded to u16 alignment → 8. EXACT (A7).
        assert(@sizeOf(Seam) == 8);
    }
};

/// Carve parameters — COLD config (A7.2), one per shell.
pub const Config = struct {
    /// Seam thickness in pixels.
    seam: u16 = 6,
};

/// The whole of what `tile` hands back across the boundary (plain values, B5).
pub const Carve = struct {
    // A7.2: cold struct, size guard waived — a return aggregate (two slices),
    // built once per `tile` call, never held in quantity or scanned in a loop.
    viewports: []Viewport,
    seams: []Seam,
};

/// THE CARVE (design §1). Pure: same (tree, dims, cfg) ⇒ same viewports +
/// seams. Allocates into the caller's allocator (C1) — the harness passes an
/// arena it frees wholesale (C3).
pub fn tile(arena: Allocator, root: *const Node, w: u16, h: u16, cfg: Config) error{OutOfMemory}!Carve {
    var vps: std.ArrayListUnmanaged(Viewport) = .empty;
    var seams: std.ArrayListUnmanaged(Seam) = .empty;
    var next_surface: u16 = 0;
    try carve(arena, root, 0, 0, w, h, cfg, &vps, &seams, &next_surface);
    return .{ .viewports = vps.items, .seams = seams.items };
}

/// The natural (collapse) extent of a child along the split axis: a
/// size-to-content leaf wants exactly `min`; a weighted leaf or a nested
/// split wants at least its `min` (0 for a split, which never self-collapses
/// — its own children collapse first).
fn childMin(node: *const Node) u16 {
    return switch (node.*) {
        .leaf => |lf| lf.min,
        .split => 0,
    };
}

fn carve(
    arena: Allocator,
    node: *const Node,
    x: u16,
    y: u16,
    w: u16,
    h: u16,
    cfg: Config,
    vps: *std.ArrayListUnmanaged(Viewport),
    seams: *std.ArrayListUnmanaged(Seam),
    next_surface: *u16,
) error{OutOfMemory}!void {
    switch (node.*) {
        .leaf => |lf| {
            try vps.append(arena, .{
                .x = x,
                .y = y,
                .w = w,
                .h = h,
                .surface = next_surface.*,
                .scroll = 0,
                .kind = lf.kind,
            });
            next_surface.* += 1;
        },
        .split => |sp| {
            const main: u16 = if (sp.dir == .v) h else w;

            // 1. COLLAPSE (E4). Drop children from the end (sidebars/widgets
            //    are placed last) until the survivors' minimums + seams fit
            //    the available extent. A narrow window simply shows fewer
            //    regions — an ordinary result, never an error. A lone child
            //    is never dropped.
            var n: usize = sp.children.len;
            while (n > 1 and required(sp.children[0..n], cfg.seam) > main) : (n -= 1) {}
            const kids = sp.children[0..n];

            // A single survivor means the split degenerated to its child —
            // recurse straight through with no seam (the collapse case where,
            // e.g., a feed|widgets split becomes feed-only on a phone width).
            if (kids.len == 1) {
                try carve(arena, &kids[0], x, y, w, h, cfg, vps, seams, next_surface);
                return;
            }

            // 2. DISTRIBUTE. Size-to-content children take their fixed `min`;
            //    the remainder is shared among the weighted children by
            //    weight. Round-off accrues to the last weighted child so the
            //    partition exactly fills `main` (no seam of dead pixels).
            const seam_total: u16 = @intCast((kids.len - 1) * cfg.seam);
            var fixed_total: u32 = 0;
            var weight_total: u32 = 0;
            for (kids) |*c| {
                switch (c.*) {
                    .leaf => |lf| if (lf.weight == 0) {
                        fixed_total += lf.min;
                    } else {
                        weight_total += lf.weight;
                    },
                    .split => weight_total += 1, // a nested split flexes weight 1
                }
            }
            const used: i64 = @as(i64, seam_total) + fixed_total;
            const flex_avail: u32 = @intCast(@max(@as(i64, 0), @as(i64, main) - used));

            var cursor: u16 = if (sp.dir == .v) y else x;
            var given: u32 = 0;
            var weight_seen: u32 = 0;
            for (kids, 0..) |*c, i| {
                const wgt: u32 = switch (c.*) {
                    .leaf => |lf| if (lf.weight == 0) 0 else lf.weight,
                    .split => 1,
                };
                const is_fixed = wgt == 0;

                var extent: u16 = undefined;
                if (is_fixed) {
                    extent = c.leaf.min;
                } else {
                    weight_seen += wgt;
                    const is_last_weighted = weight_seen == weight_total;
                    if (is_last_weighted) {
                        extent = @intCast(flex_avail - given); // soak up round-off
                    } else {
                        const e: u32 = flex_avail * wgt / weight_total;
                        extent = @intCast(e);
                        given += e;
                    }
                }

                // Place the child's sub-rectangle.
                if (sp.dir == .v) {
                    try carve(arena, c, x, cursor, w, extent, cfg, vps, seams, next_surface);
                } else {
                    try carve(arena, c, cursor, y, extent, h, cfg, vps, seams, next_surface);
                }
                cursor += extent;

                // Emit the seam BETWEEN this child and the next.
                if (i + 1 < kids.len) {
                    if (sp.dir == .v) {
                        try seams.append(arena, .{ .x = x, .y = cursor, .len = w, .dir = .v });
                    } else {
                        try seams.append(arena, .{ .x = cursor, .y = y, .len = h, .dir = .h });
                    }
                    cursor += cfg.seam;
                }
            }
        },
    }
}

/// The extent a set of children minimally needs along the split axis:
/// the sum of their collapse-minimums plus the seams between them.
fn required(kids: []const Node, seam: u16) u32 {
    var sum: u32 = 0;
    for (kids) |*c| sum += childMin(c);
    sum += @as(u32, @intCast(kids.len - 1)) * seam;
    return sum;
}

// ---------------------------------------------------------------------------
// Golden tests — pin the carve so a layout regression fails the build.
// ---------------------------------------------------------------------------

test "vertical split: masthead sizes to content, feed takes the rest" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // A page: masthead (natural 120) over a feed (flex), stacked vertically.
    const tree: Node = .{ .split = .{ .dir = .v, .children = &.{
        .{ .leaf = .{ .kind = .masthead, .weight = 0, .min = 120 } },
        .{ .leaf = .{ .kind = .feed, .weight = 1, .min = 200 } },
    } } };

    const out = try tile(arena, &tree, 1000, 800, .{ .seam = 6 });
    try std.testing.expectEqual(@as(usize, 2), out.viewports.len);
    try std.testing.expectEqual(@as(usize, 1), out.seams.len);

    // Masthead: full width, natural height, at the top.
    try std.testing.expectEqual(RegionKind.masthead, out.viewports[0].kind);
    try std.testing.expectEqual(@as(u16, 1000), out.viewports[0].w);
    try std.testing.expectEqual(@as(u16, 120), out.viewports[0].h);
    try std.testing.expectEqual(@as(u16, 0), out.viewports[0].y);

    // Feed: full width, remainder height (800 − 120 − 6 seam = 674), below the seam.
    try std.testing.expectEqual(RegionKind.feed, out.viewports[1].kind);
    try std.testing.expectEqual(@as(u16, 674), out.viewports[1].h);
    try std.testing.expectEqual(@as(u16, 126), out.viewports[1].y);

    // Surfaces are sequential, local indexes.
    try std.testing.expectEqual(@as(u16, 0), out.viewports[0].surface);
    try std.testing.expectEqual(@as(u16, 1), out.viewports[1].surface);
}

test "horizontal split partitions width by weight" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // feed (weight 2) beside widgets (weight 1) — a 2:1 split of (900 − 6).
    const tree: Node = .{ .split = .{ .dir = .h, .children = &.{
        .{ .leaf = .{ .kind = .profile_feed, .weight = 2, .min = 200 } },
        .{ .leaf = .{ .kind = .widgets, .weight = 1, .min = 160 } },
    } } };

    const out = try tile(arena, &tree, 900, 600, .{ .seam = 6 });
    try std.testing.expectEqual(@as(usize, 2), out.viewports.len);
    // 894 flex; 2/3 → 596, remainder 298 to the last child. They sum to 894.
    try std.testing.expectEqual(@as(u16, 596), out.viewports[0].w);
    try std.testing.expectEqual(@as(u16, 298), out.viewports[1].w);
    try std.testing.expectEqual(@as(u16, 0), out.viewports[0].x);
    try std.testing.expectEqual(@as(u16, 602), out.viewports[1].x); // 596 + 6 seam
}

test "narrow window collapses the side region (E4, not an error)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // feed (min 360) beside widgets (min 280): together they need 360+280+6 =
    // 646. A 600-wide window cannot honor both → widgets collapses, feed fills.
    const tree: Node = .{ .split = .{ .dir = .h, .children = &.{
        .{ .leaf = .{ .kind = .feed, .weight = 2, .min = 360 } },
        .{ .leaf = .{ .kind = .widgets, .weight = 1, .min = 280 } },
    } } };

    const wide = try tile(arena, &tree, 1000, 600, .{ .seam = 6 });
    try std.testing.expectEqual(@as(usize, 2), wide.viewports.len); // both fit

    const narrow = try tile(arena, &tree, 600, 600, .{ .seam = 6 });
    try std.testing.expectEqual(@as(usize, 1), narrow.viewports.len); // widgets dropped
    try std.testing.expectEqual(RegionKind.feed, narrow.viewports[0].kind);
    try std.testing.expectEqual(@as(u16, 600), narrow.viewports[0].w); // feed fills, no seam
    try std.testing.expectEqual(@as(usize, 0), narrow.seams.len);
}

test "nested tree: masthead over a feed|widgets split" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const tree: Node = .{ .split = .{ .dir = .v, .children = &.{
        .{ .leaf = .{ .kind = .profile_id, .weight = 0, .min = 150 } },
        .{ .split = .{ .dir = .h, .children = &.{
            .{ .leaf = .{ .kind = .profile_feed, .weight = 2, .min = 300 } },
            .{ .leaf = .{ .kind = .widgets, .weight = 1, .min = 240 } },
        } } },
    } } };

    const out = try tile(arena, &tree, 1200, 900, .{ .seam = 6 });
    // 3 leaves total → 3 viewports; 1 vertical seam + 1 horizontal seam.
    try std.testing.expectEqual(@as(usize, 3), out.viewports.len);
    try std.testing.expectEqual(@as(usize, 2), out.seams.len);
    // The id band spans full width at the top.
    try std.testing.expectEqual(RegionKind.profile_id, out.viewports[0].kind);
    try std.testing.expectEqual(@as(u16, 1200), out.viewports[0].w);
    // The feed + widgets sit below the band (y = 150 + 6 seam = 156).
    try std.testing.expectEqual(@as(u16, 156), out.viewports[1].y);
    try std.testing.expectEqual(@as(u16, 156), out.viewports[2].y);
}
