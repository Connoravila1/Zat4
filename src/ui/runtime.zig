//! Rover · runtime — one structural source of truth for native UI.
//!
//! PURE, renderer-independent composition over plain data. The host declares a
//! tree in logical pixels. `resolve` derives world rectangles, inherited clips,
//! visibility, hit eligibility, focus eligibility, and deterministic paint order
//! from that same tree. A host must use these results for both painting and input;
//! it must not reconstruct a second geometry list.
//!
//! Phase A deliberately accepts already-measured local rectangles. `layout.zig`
//! will produce those rectangles in Phase B. Keeping that seam explicit lets the
//! runtime contract be proven before expanding the layout solver.

const std = @import("std");
const assert = std.debug.assert;

const nil: u32 = std.math.maxInt(u32);

/// Stable host identity. Zero is reserved for "no control".
pub const Id = enum(u32) { none = 0, _ };

/// Opaque handle into one `Scene`. It never crosses into another Rover module as
/// a bare array index.
pub const Node = enum(u32) { _ };

/// Logical-pixel rectangle. Origins grow right/down.
pub const Rect = struct {
    x: f32 = 0,
    y: f32 = 0,
    w: f32 = 0,
    h: f32 = 0,

    comptime {
        assert(@sizeOf(Rect) == 16);
    }
};

/// Translation applied after layout and inherited by descendants.
pub const Translation = struct {
    x: f32 = 0,
    y: f32 = 0,

    comptime {
        assert(@sizeOf(Translation) == 8);
    }
};

/// How this node constrains descendant overflow.
pub const Overflow = enum(u8) {
    visible,
    clip,
    scroll,
};

/// Declared node capabilities. Stored as a hot SoA column.
pub const Flags = packed struct(u8) {
    visible: bool = true,
    hittable: bool = false,
    focusable: bool = false,
    keyboard: bool = false,
    disabled: bool = false,
    _pad: u3 = 0,

    comptime {
        assert(@sizeOf(Flags) == 1);
    }
};

/// Resolved capabilities after ancestor visibility, clipping, and disabled state.
pub const ResolvedFlags = packed struct(u8) {
    visible: bool = false,
    hittable: bool = false,
    focusable: bool = false,
    keyboard: bool = false,
    disabled: bool = false,
    _pad: u3 = 0,

    comptime {
        assert(@sizeOf(ResolvedFlags) == 1);
    }
};

/// Transient declaration passed to `addRoot` / `addChild`.
pub const Spec = struct {
    id: Id,
    rect: Rect,
    translation: Translation = .{},
    overflow: Overflow = .visible,
    flags: Flags = .{},
    z: i16 = 0,
    // A7.2: cold builder value, never stored as an AoS collection.
};

pub const AddError = error{
    DuplicateId,
    InvalidId,
    InvalidParent,
    OutOfMemory,
};

pub const ResolveError = error{
    DuplicateId,
    InvalidGeometry,
    InvalidParent,
    InvalidViewport,
};

/// Resolved output for one node. This is a transient boundary value; the hot
/// storage remains SoA inside `Scene`.
pub const Resolved = struct {
    id: Id,
    world: Rect,
    clip: Rect,
    paint_order: u32,
    z: i16,
    flags: ResolvedFlags,
    // A7.2: returned by value for inspection, never stored in bulk.
};

/// Declaration + resolution arena. One per surface, retained and reset each
/// frame. All per-node data is stored in parallel arrays.
pub const Scene = struct {
    gpa: std.mem.Allocator,

    ids: std.ArrayListUnmanaged(Id) = .empty,
    parents: std.ArrayListUnmanaged(u32) = .empty,
    local: std.ArrayListUnmanaged(Rect) = .empty,
    translations: std.ArrayListUnmanaged(Translation) = .empty,
    overflow: std.ArrayListUnmanaged(Overflow) = .empty,
    declared_flags: std.ArrayListUnmanaged(Flags) = .empty,
    zs: std.ArrayListUnmanaged(i16) = .empty,

    world: std.ArrayListUnmanaged(Rect) = .empty,
    clips: std.ArrayListUnmanaged(Rect) = .empty,
    paint_order: std.ArrayListUnmanaged(u32) = .empty,
    resolved_flags: std.ArrayListUnmanaged(ResolvedFlags) = .empty,

    resolved: bool = false,

    // A7.2: cold owner, one per UI surface.

    pub fn init(gpa: std.mem.Allocator) Scene {
        return .{ .gpa = gpa };
    }

    pub fn deinit(s: *Scene) void {
        s.ids.deinit(s.gpa);
        s.parents.deinit(s.gpa);
        s.local.deinit(s.gpa);
        s.translations.deinit(s.gpa);
        s.overflow.deinit(s.gpa);
        s.declared_flags.deinit(s.gpa);
        s.zs.deinit(s.gpa);
        s.world.deinit(s.gpa);
        s.clips.deinit(s.gpa);
        s.paint_order.deinit(s.gpa);
        s.resolved_flags.deinit(s.gpa);
        s.* = undefined;
    }

    /// Clear declarations and results while retaining capacity.
    pub fn reset(s: *Scene) void {
        s.ids.clearRetainingCapacity();
        s.parents.clearRetainingCapacity();
        s.local.clearRetainingCapacity();
        s.translations.clearRetainingCapacity();
        s.overflow.clearRetainingCapacity();
        s.declared_flags.clearRetainingCapacity();
        s.zs.clearRetainingCapacity();
        s.world.clearRetainingCapacity();
        s.clips.clearRetainingCapacity();
        s.paint_order.clearRetainingCapacity();
        s.resolved_flags.clearRetainingCapacity();
        s.resolved = false;
    }

    pub fn count(s: *const Scene) usize {
        return s.ids.items.len;
    }

    pub fn addRoot(s: *Scene, gpa: std.mem.Allocator, spec: Spec) AddError!Node {
        assert(gpa.ptr == s.gpa.ptr and gpa.vtable == s.gpa.vtable);
        return s.append(spec, nil);
    }

    pub fn addChild(s: *Scene, gpa: std.mem.Allocator, parent: Node, spec: Spec) AddError!Node {
        assert(gpa.ptr == s.gpa.ptr and gpa.vtable == s.gpa.vtable);
        const p = @intFromEnum(parent);
        if (p >= s.ids.items.len) return error.InvalidParent;
        return s.append(spec, p);
    }

    fn append(s: *Scene, spec: Spec, parent: u32) AddError!Node {
        if (spec.id == .none) return error.InvalidId;
        for (s.ids.items) |existing| {
            if (existing == spec.id) return error.DuplicateId;
        }

        // Reserve every column before changing any length, so allocation failure
        // cannot leave the SoA columns mismatched.
        try s.ids.ensureUnusedCapacity(s.gpa, 1);
        try s.parents.ensureUnusedCapacity(s.gpa, 1);
        try s.local.ensureUnusedCapacity(s.gpa, 1);
        try s.translations.ensureUnusedCapacity(s.gpa, 1);
        try s.overflow.ensureUnusedCapacity(s.gpa, 1);
        try s.declared_flags.ensureUnusedCapacity(s.gpa, 1);
        try s.zs.ensureUnusedCapacity(s.gpa, 1);
        try s.world.ensureUnusedCapacity(s.gpa, 1);
        try s.clips.ensureUnusedCapacity(s.gpa, 1);
        try s.paint_order.ensureUnusedCapacity(s.gpa, 1);
        try s.resolved_flags.ensureUnusedCapacity(s.gpa, 1);

        const index: u32 = @intCast(s.ids.items.len);
        s.ids.appendAssumeCapacity(spec.id);
        s.parents.appendAssumeCapacity(parent);
        s.local.appendAssumeCapacity(spec.rect);
        s.translations.appendAssumeCapacity(spec.translation);
        s.overflow.appendAssumeCapacity(spec.overflow);
        s.declared_flags.appendAssumeCapacity(spec.flags);
        s.zs.appendAssumeCapacity(spec.z);
        s.world.appendAssumeCapacity(.{});
        s.clips.appendAssumeCapacity(.{});
        s.paint_order.appendAssumeCapacity(0);
        s.resolved_flags.appendAssumeCapacity(.{});
        s.resolved = false;
        return @enumFromInt(index);
    }

    /// Resolve every node. Parents must precede children, which the builder API
    /// guarantees. Roots are relative to the viewport origin; children are
    /// relative to their parent's world origin.
    pub fn resolve(s: *Scene, viewport: Rect) ResolveError!void {
        if (!validRect(viewport)) return error.InvalidViewport;

        // Defend the contract even if future internal builders bypass `append`.
        for (s.ids.items, 0..) |id, i| {
            if (id == .none) return error.InvalidGeometry;
            for (s.ids.items[0..i]) |prior| {
                if (prior == id) return error.DuplicateId;
            }
        }

        for (s.ids.items, 0..) |_, i| {
            const local = s.local.items[i];
            const translation = s.translations.items[i];
            if (!validRect(local) or !validTranslation(translation)) {
                return error.InvalidGeometry;
            }

            const parent = s.parents.items[i];
            var inherited_clip = viewport;
            var inherited_visible = true;
            var origin_x = viewport.x;
            var origin_y = viewport.y;

            if (parent != nil) {
                if (parent >= i) return error.InvalidParent;
                const p = @as(usize, parent);
                origin_x = s.world.items[p].x;
                origin_y = s.world.items[p].y;
                inherited_visible = s.resolved_flags.items[p].visible;
                inherited_clip = s.clips.items[p];
                if (s.overflow.items[p] != .visible) {
                    inherited_clip = intersection(inherited_clip, s.world.items[p]);
                }
            }

            const world: Rect = .{
                .x = origin_x + local.x + translation.x,
                .y = origin_y + local.y + translation.y,
                .w = local.w,
                .h = local.h,
            };
            if (!validRect(world)) return error.InvalidGeometry;

            const declared = s.declared_flags.items[i];
            const visible_part = intersection(world, inherited_clip);
            const visible = inherited_visible and declared.visible and hasArea(visible_part);

            s.world.items[i] = world;
            s.clips.items[i] = inherited_clip;
            s.paint_order.items[i] = @intCast(i);
            s.resolved_flags.items[i] = .{
                .visible = visible,
                .hittable = visible and declared.hittable and !declared.disabled,
                .focusable = visible and declared.focusable and !declared.disabled,
                .keyboard = visible and declared.focusable and declared.keyboard and !declared.disabled,
                .disabled = declared.disabled,
            };
        }
        s.resolved = true;
    }

    pub fn result(s: *const Scene, node: Node) ?Resolved {
        if (!s.resolved) return null;
        const i = @intFromEnum(node);
        if (i >= s.ids.items.len) return null;
        return .{
            .id = s.ids.items[i],
            .world = s.world.items[i],
            .clip = s.clips.items[i],
            .paint_order = s.paint_order.items[i],
            .z = s.zs.items[i],
            .flags = s.resolved_flags.items[i],
        };
    }

    /// Topmost resolved control at a point. Effective clipping, inherited
    /// visibility, disabled state, z, and paint order all come from this scene;
    /// no caller-maintained hit rectangles participate.
    pub fn hitTest(s: *const Scene, x: f32, y: f32) Id {
        if (!s.resolved) return .none;
        var best: Id = .none;
        var best_z: i16 = std.math.minInt(i16);
        var best_order: u32 = 0;
        var seen = false;
        for (s.ids.items, 0..) |id, i| {
            if (!s.resolved_flags.items[i].hittable) continue;
            const visible_rect = intersection(s.world.items[i], s.clips.items[i]);
            if (!contains(visible_rect, x, y)) continue;
            const z = s.zs.items[i];
            const order = s.paint_order.items[i];
            if (!seen or z > best_z or (z == best_z and order >= best_order)) {
                best = id;
                best_z = z;
                best_order = order;
                seen = true;
            }
        }
        return best;
    }

    pub fn flagsForId(s: *const Scene, id: Id) ?ResolvedFlags {
        if (!s.resolved or id == .none) return null;
        for (s.ids.items, 0..) |candidate, i| {
            if (candidate == id) return s.resolved_flags.items[i];
        }
        return null;
    }

    /// Next focusable id in deterministic paint order, wrapping once.
    pub fn nextFocusable(s: *const Scene, current: Id, forward: bool) Id {
        if (!s.resolved or s.ids.items.len == 0) return .none;
        const n = s.ids.items.len;
        var current_index: ?usize = null;
        for (s.ids.items, 0..) |candidate, i| {
            if (candidate == current) {
                current_index = i;
                break;
            }
        }
        var step: usize = 0;
        while (step < n) : (step += 1) {
            const offset = step + 1;
            const i: usize = if (current_index) |at|
                (if (forward) (at + offset) % n else (at + n * n - offset) % n)
            else
                (if (forward) (offset - 1) % n else (n - offset) % n);
            if (s.resolved_flags.items[i].focusable) return s.ids.items[i];
        }
        return .none;
    }

    /// Deterministic structural diagnostics. One line per resolved node, in paint
    /// order. Intended for golden tests and the host's debug overlay/log.
    pub fn dump(s: *const Scene, out: *std.Io.Writer) !void {
        if (!s.resolved) return error.NotResolved;
        for (s.ids.items, 0..) |id, i| {
            const w = s.world.items[i];
            const c = s.clips.items[i];
            const f = s.resolved_flags.items[i];
            try out.print(
                "node id={d} parent={d} world=({d},{d},{d},{d}) clip=({d},{d},{d},{d}) order={d} z={d} visible={} hit={} focus={} keyboard={} disabled={}\n",
                .{
                    @intFromEnum(id),
                    s.parents.items[i],
                    w.x,
                    w.y,
                    w.w,
                    w.h,
                    c.x,
                    c.y,
                    c.w,
                    c.h,
                    s.paint_order.items[i],
                    s.zs.items[i],
                    f.visible,
                    f.hittable,
                    f.focusable,
                    f.keyboard,
                    f.disabled,
                },
            );
        }
    }
};

pub fn contains(r: Rect, x: f32, y: f32) bool {
    return hasArea(r) and x >= r.x and x < r.x + r.w and y >= r.y and y < r.y + r.h;
}

pub fn intersection(a: Rect, b: Rect) Rect {
    const left = @max(a.x, b.x);
    const top = @max(a.y, b.y);
    const right = @min(a.x + a.w, b.x + b.w);
    const bottom = @min(a.y + a.h, b.y + b.h);
    return .{
        .x = left,
        .y = top,
        .w = @max(0.0, right - left),
        .h = @max(0.0, bottom - top),
    };
}

pub fn hasArea(r: Rect) bool {
    return r.w > 0 and r.h > 0;
}

fn validRect(r: Rect) bool {
    return std.math.isFinite(r.x) and
        std.math.isFinite(r.y) and
        std.math.isFinite(r.w) and
        std.math.isFinite(r.h) and
        r.w >= 0 and
        r.h >= 0;
}

fn validTranslation(t: Translation) bool {
    return std.math.isFinite(t.x) and std.math.isFinite(t.y);
}

fn testId(n: u32) Id {
    return @enumFromInt(n);
}

fn approx(a: f32, b: f32) bool {
    return @abs(a - b) < 0.001;
}

test "runtime: nested transforms and clips resolve from one tree" {
    var scene = Scene.init(std.testing.allocator);
    defer scene.deinit();

    const root = try scene.addRoot(std.testing.allocator, .{
        .id = testId(1),
        .rect = .{ .x = 0, .y = 0, .w = 200, .h = 120 },
        .overflow = .clip,
    });
    const row = try scene.addChild(std.testing.allocator, root, .{
        .id = testId(2),
        .rect = .{ .x = 10, .y = 20, .w = 180, .h = 80 },
        .translation = .{ .y = -30 },
        .overflow = .clip,
    });
    const button = try scene.addChild(std.testing.allocator, row, .{
        .id = testId(3),
        .rect = .{ .x = 20, .y = 60, .w = 80, .h = 40 },
        .flags = .{ .hittable = true, .focusable = true },
    });

    try scene.resolve(.{ .x = 0, .y = 0, .w = 160, .h = 100 });
    const r = scene.result(button).?;
    try std.testing.expect(approx(r.world.x, 30));
    try std.testing.expect(approx(r.world.y, 50));
    try std.testing.expect(approx(r.clip.x, 10));
    try std.testing.expect(approx(r.clip.y, 0));
    try std.testing.expect(approx(r.clip.w, 150));
    try std.testing.expect(approx(r.clip.h, 70));
    try std.testing.expect(r.flags.visible and r.flags.hittable and r.flags.focusable);
}

test "runtime: clipped-off descendants neither show nor receive input" {
    var scene = Scene.init(std.testing.allocator);
    defer scene.deinit();

    const root = try scene.addRoot(std.testing.allocator, .{
        .id = testId(1),
        .rect = .{ .w = 100, .h = 100 },
        .overflow = .clip,
    });
    const child = try scene.addChild(std.testing.allocator, root, .{
        .id = testId(2),
        .rect = .{ .x = 120, .y = 20, .w = 30, .h = 30 },
        .flags = .{ .hittable = true, .focusable = true },
    });

    try scene.resolve(.{ .w = 500, .h = 500 });
    const r = scene.result(child).?;
    try std.testing.expect(!r.flags.visible);
    try std.testing.expect(!r.flags.hittable);
    try std.testing.expect(!r.flags.focusable);
}

test "runtime: visible overflow is not clipped by the parent" {
    var scene = Scene.init(std.testing.allocator);
    defer scene.deinit();

    const root = try scene.addRoot(std.testing.allocator, .{
        .id = testId(1),
        .rect = .{ .w = 100, .h = 100 },
        .overflow = .visible,
    });
    const child = try scene.addChild(std.testing.allocator, root, .{
        .id = testId(2),
        .rect = .{ .x = 120, .y = 20, .w = 30, .h = 30 },
        .flags = .{ .hittable = true },
    });

    try scene.resolve(.{ .w = 500, .h = 500 });
    const r = scene.result(child).?;
    try std.testing.expect(r.flags.visible and r.flags.hittable);
}

test "runtime: hidden ancestors and disabled nodes suppress interaction" {
    var scene = Scene.init(std.testing.allocator);
    defer scene.deinit();

    const hidden = try scene.addRoot(std.testing.allocator, .{
        .id = testId(1),
        .rect = .{ .w = 100, .h = 100 },
        .flags = .{ .visible = false },
    });
    const child = try scene.addChild(std.testing.allocator, hidden, .{
        .id = testId(2),
        .rect = .{ .w = 20, .h = 20 },
        .flags = .{ .hittable = true },
    });
    const disabled = try scene.addRoot(std.testing.allocator, .{
        .id = testId(3),
        .rect = .{ .w = 20, .h = 20 },
        .flags = .{ .hittable = true, .focusable = true, .disabled = true },
    });

    try scene.resolve(.{ .w = 500, .h = 500 });
    try std.testing.expect(!scene.result(child).?.flags.visible);
    const d = scene.result(disabled).?;
    try std.testing.expect(d.flags.visible and d.flags.disabled);
    try std.testing.expect(!d.flags.hittable and !d.flags.focusable);
}

test "runtime: invalid ids, duplicate ids, parents, and geometry fail explicitly" {
    var scene = Scene.init(std.testing.allocator);
    defer scene.deinit();

    try std.testing.expectError(error.InvalidId, scene.addRoot(std.testing.allocator, .{
        .id = .none,
        .rect = .{},
    }));
    _ = try scene.addRoot(std.testing.allocator, .{ .id = testId(1), .rect = .{ .w = 10, .h = 10 } });
    try std.testing.expectError(error.DuplicateId, scene.addRoot(std.testing.allocator, .{
        .id = testId(1),
        .rect = .{},
    }));
    try std.testing.expectError(error.InvalidParent, scene.addChild(std.testing.allocator, @enumFromInt(99), .{
        .id = testId(2),
        .rect = .{},
    }));

    scene.reset();
    _ = try scene.addRoot(std.testing.allocator, .{
        .id = testId(1),
        .rect = .{ .w = -1, .h = 10 },
    });
    try std.testing.expectError(error.InvalidGeometry, scene.resolve(.{ .w = 100, .h = 100 }));
    try std.testing.expectError(error.InvalidViewport, scene.resolve(.{ .w = -1, .h = 100 }));
}

test "runtime: diagnostic dump is deterministic and reset reuses the scene" {
    var scene = Scene.init(std.testing.allocator);
    defer scene.deinit();

    _ = try scene.addRoot(std.testing.allocator, .{
        .id = testId(7),
        .rect = .{ .x = 2, .y = 3, .w = 40, .h = 20 },
        .flags = .{ .hittable = true },
        .z = 4,
    });
    try scene.resolve(.{ .w = 100, .h = 100 });

    var bytes: [512]u8 = undefined;
    var writer: std.Io.Writer = .fixed(&bytes);
    try scene.dump(&writer);
    const first = writer.buffered();
    try std.testing.expect(std.mem.startsWith(u8, first, "node id=7 parent=4294967295"));
    try std.testing.expect(std.mem.indexOf(u8, first, "order=0 z=4 visible=true hit=true") != null);

    scene.reset();
    try std.testing.expectEqual(@as(usize, 0), scene.count());
    const root = try scene.addRoot(std.testing.allocator, .{ .id = testId(9), .rect = .{ .w = 10, .h = 10 } });
    try scene.resolve(.{ .w = 100, .h = 100 });
    try std.testing.expectEqual(@as(u32, 9), @intFromEnum(scene.result(root).?.id));
}

test "runtime: rectangle intersection and half-open containment" {
    const a: Rect = .{ .x = 0, .y = 0, .w = 20, .h = 20 };
    const b: Rect = .{ .x = 10, .y = 5, .w = 20, .h = 5 };
    const c = intersection(a, b);
    try std.testing.expect(approx(c.x, 10) and approx(c.y, 5));
    try std.testing.expect(approx(c.w, 10) and approx(c.h, 5));
    try std.testing.expect(contains(c, 10, 5));
    try std.testing.expect(!contains(c, 20, 5));
}

test "runtime: hit testing uses effective clips, z, and paint-order ties" {
    var scene = Scene.init(std.testing.allocator);
    defer scene.deinit();

    const root = try scene.addRoot(std.testing.allocator, .{
        .id = testId(1),
        .rect = .{ .w = 100, .h = 100 },
        .overflow = .clip,
    });
    _ = try scene.addChild(std.testing.allocator, root, .{
        .id = testId(2),
        .rect = .{ .x = 10, .y = 10, .w = 80, .h = 80 },
        .flags = .{ .hittable = true },
        .z = 2,
    });
    _ = try scene.addChild(std.testing.allocator, root, .{
        .id = testId(3),
        .rect = .{ .x = 10, .y = 10, .w = 80, .h = 80 },
        .flags = .{ .hittable = true },
        .z = 2,
    });
    _ = try scene.addChild(std.testing.allocator, root, .{
        .id = testId(4),
        .rect = .{ .x = 20, .y = 20, .w = 20, .h = 20 },
        .flags = .{ .hittable = true },
        .z = 3,
    });
    _ = try scene.addChild(std.testing.allocator, root, .{
        .id = testId(5),
        .rect = .{ .x = 120, .y = 10, .w = 20, .h = 20 },
        .flags = .{ .hittable = true },
        .z = 9,
    });
    try scene.resolve(.{ .w = 500, .h = 500 });

    try std.testing.expectEqual(testId(4), scene.hitTest(25, 25)); // higher z
    try std.testing.expectEqual(testId(3), scene.hitTest(60, 60)); // equal z, later paint
    try std.testing.expectEqual(Id.none, scene.hitTest(125, 15)); // clipped by root
}

test "runtime: focus and keyboard capabilities use resolved state" {
    var scene = Scene.init(std.testing.allocator);
    defer scene.deinit();

    _ = try scene.addRoot(std.testing.allocator, .{
        .id = testId(1),
        .rect = .{ .w = 20, .h = 20 },
        .flags = .{ .hittable = true, .focusable = true },
    });
    _ = try scene.addRoot(std.testing.allocator, .{
        .id = testId(2),
        .rect = .{ .x = 30, .w = 20, .h = 20 },
        .flags = .{ .hittable = true, .focusable = true, .keyboard = true },
    });
    _ = try scene.addRoot(std.testing.allocator, .{
        .id = testId(3),
        .rect = .{ .x = 60, .w = 20, .h = 20 },
        .flags = .{ .hittable = true, .focusable = true, .disabled = true },
    });
    try scene.resolve(.{ .w = 100, .h = 100 });

    try std.testing.expectEqual(testId(1), scene.nextFocusable(.none, true));
    try std.testing.expectEqual(testId(2), scene.nextFocusable(testId(1), true));
    try std.testing.expectEqual(testId(1), scene.nextFocusable(testId(2), true));
    try std.testing.expect(scene.flagsForId(testId(2)).?.keyboard);
    try std.testing.expect(!scene.flagsForId(testId(3)).?.focusable);
}
