//! B1 classification: CORE (pure). The EFFECT RECIPE layer — the
//! authoring surface over field.zig's physics (GLYPH_FIELD_SYSTEM_DESIGN
//! §5, the "parameterise, don't enumerate" promise made real).
//!
//! field.zig answers "how does one cell spring, how does one particle
//! fly." This module answers "what is a *like*, a *boost*, a *new-post
//! arrival*" — as DATA, never as bespoke code. The whole point of the
//! owner's ask: not one like-burst, but a workshop where any effect is
//! a tunable recipe you dial by context, and a new one costs a struct
//! literal, not a module.
//!
//! THE KEY IDEA — a stage is a rule change over time, not a keyframe.
//! The owner's heart example ("symbols redden from the bottom, then
//! burst, then shove the neighbours") is THREE stages:
//!   1. a `glow_ramp` that lights the stencil's cells bottom-up,
//!   2. a `burst` spawn fired at the stage edge,
//!   3. the perturbation that follows is just field.zig's physics.
//! None of it is animated frame-by-frame. Each stage is a parameter
//! set; `advance()` is a pure transform of (active effects, dt) into
//! (field writes + spawn events). Same inputs ⇒ same evolution (B2),
//! so the whole thing is golden-testable headless exactly like the sim.
//!
//! EVERYTHING IS TUNABLE. Every magnitude, duration, colour, count,
//! and glyph below is a field on a plain struct the caller owns — the
//! `recipes` table holds defaults, but a caller can clone a recipe,
//! change three numbers, and fire it. Context-sensitive intensity
//! (the owner's "more or less depending on what I'm going for") is a
//! `scale` multiplier passed at trigger time, applied to counts and
//! magnitudes uniformly (§4).
//!
//! Governing law: A1 (plain data), A3 (SoA for the active list), A7
//! (guards on every hot record), B2 (pure), C1/C2 (explicit alloc),
//! E4 (an exhausted effect is an ordinary cull, not an error),
//! F2 (comptime tables, no dependency).

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const field = @import("field.zig");
const raster = @import("raster.zig");

// ---------------------------------------------------------------------------
// Stencils — glyph-art shapes placed into the field (the heart, icons…)
// ---------------------------------------------------------------------------

/// A small glyph-art shape: rows of text with a transparent marker.
/// Comptime data (F2) — the same embedded-asset precedent the font
/// sets. The authoring pipeline (paint ASCII → const) drops shapes
/// here; nothing is hand-placed cell by cell at runtime.
///
/// VARIABLE RESOLUTION (the owner's idea): a shape may declare a `scale`
/// > 1, meaning its glyphs render at 1/scale the timeline's cell pitch —
/// so a heart can be built from many small characters for detail while
/// body text stays at the readable size. The shape still lives in the
/// ONE field (its cells are real field cells the physics acts on, D5's
/// one-grid thesis intact); only its PIXEL footprint shrinks. A
/// scale-1 shape is the ordinary same-size case. The field stores
/// shapes in a fine sub-grid; compose renders flagged cells at the
/// finer pitch. (Built when the detailed heart needed it, not
/// speculatively — F4.)
///
/// A7.2: not a hot record — a comptime descriptor, read to stamp cells
/// into the grid, never held in quantity.
pub const Stencil = struct {
    /// Rows of glyphs; ' ' (space) is transparent (no cell written).
    rows: []const []const u8,
    w: u8,
    h: u8,
    /// Render resolution: 1 = ordinary cell size; 2 = half-pitch (4× the
    /// glyph density); 3 = third-pitch. The shape's pixel size is
    /// (w/scale × h/scale) timeline cells.
    scale: u8 = 1,

    pub fn make(comptime rows: []const []const u8) Stencil {
        return makeScaled(rows, 1);
    }

    pub fn makeScaled(comptime rows: []const []const u8, comptime scale: u8) Stencil {
        comptime {
            var maxw: u8 = 0;
            for (rows) |r| maxw = @max(maxw, @as(u8, @intCast(r.len)));
            return .{ .rows = rows, .w = maxw, .h = @intCast(rows.len), .scale = scale };
        }
    }
};

/// The like-heart, rebuilt as an UPRIGHT, FILLED, high-detail silhouette
/// (the owner's HTML reference) at 2× resolution — many small glyphs
/// instead of a sparse outline. `#` is the body; the glow ramp reddens
/// it bottom-up, the burst throws sparks, the shockwave pops it. The
/// shape is solid so the fill reads as a heart filling, not an outline
/// lighting. Drawn ~26 wide × 22 tall in the fine sub-grid → ~13×11
/// timeline cells at scale 2.
pub const heart = Stencil.makeScaled(&.{
    "    ######      ######    ",
    "  ##########  ##########  ",
    " ############ ############ ",
    "###########################",
    "############################",
    "############################",
    "############################",
    " ########################## ",
    " ########################## ",
    "  ########################  ",
    "   ######################   ",
    "    ####################    ",
    "     ##################     ",
    "      ################      ",
    "       ##############       ",
    "        ############        ",
    "         ##########         ",
    "          ########          ",
    "           ######           ",
    "            ####            ",
    "             ##             ",
}, 2);

/// The INLINE like-button heart: the SAME concept (the button IS the
/// heart), compact enough to sit beside the other engagement buttons.
/// At scale 2 over a ~10-glyph-wide silhouette it renders ~5 cells wide
/// — bigger than a single char, but each glyph is large enough (~4-5px)
/// that the shape READS as a heart, where a denser scale-4 grid rendered
/// as illegible horizontal bands (the glyphs were too small to form the
/// outline). The font has no ♥ glyph (it returns notdef), so the heart
/// must be built from ASCII; scale 2 is the legibility floor for that.
/// Used for the resting button (composeStaticHeart) and the burst
/// (composeEffects) alike — one heart, both states.
pub const heart_inline = Stencil.makeScaled(&.{
    "## ##",
    "#####",
    " ### ",
    "  #  ",
}, 2);

/// A simple boost/repost arrow ring, to show a second shape rides the
/// same machinery with zero new code.
pub const boost_ring = Stencil.make(&.{
    " /^\\ ",
    "<   >",
    " \\v/ ",
});

// ---------------------------------------------------------------------------
// The recipe — a staged effect, entirely as tunable data
// ---------------------------------------------------------------------------

/// What a stage DOES to the stencil's cells while it runs. Each is a
/// pure per-cell rule evaluated against stage progress `t` in [0,1].
pub const StageKind = enum(u8) {
    /// Light the cells in, ordered by a sweep direction, so they ignite
    /// progressively (the heart "reddening from the bottom").
    glow_ramp,
    /// Hold the current look; a deliberate beat before the next stage.
    hold,
    /// Fire a single field.SpawnEvent from the stencil's centre at the
    /// moment this stage begins (the "burst"). The stage's own duration
    /// then lets the particles fly before the effect ends.
    emit,
    /// Shove every stencil cell outward from the centre (an expanding
    /// pop), magnitude eased over `t` — the shape itself flies apart,
    /// distinct from the particles `emit` throws.
    shockwave,
    /// Fade the cells' glow back out (the comedown).
    fade,
};

/// Direction a `glow_ramp` sweeps the shape.
pub const Sweep = enum(u8) { bottom_up, top_down, center_out, left_right, all_at_once };

/// One stage of an effect — a tunable parameter set, NOT a frame.
/// A7.2: cold struct (a handful per recipe, read at advance time);
/// waived. Every field here is a knob the owner can turn.
pub const Stage = struct {
    kind: StageKind,
    /// Seconds this stage runs. 0 = instantaneous (fire and move on).
    duration: f32 = 0.2,
    /// glow_ramp/fade: peak glow added to a cell (0..255).
    glow: u8 = 200,
    /// glow_ramp: which way the light sweeps.
    sweep: Sweep = .bottom_up,
    /// glow_ramp: palette index the lit cells take (the heart's red).
    color: u8 = 4,
    /// shockwave: outward speed in cells/sec at the cell edge.
    push: f32 = 4.0,
    /// emit: the spawn fired at this stage's start. count/energy here
    /// are pre-scale; the trigger-time `scale` multiplies them (§4).
    emit_kind: field.SpawnEvent.Kind = .burst,
    emit_count: u8 = 24,
    emit_energy: u8 = 70,
    emit_palette: u8 = 0,
};

/// A complete effect: a shape (optional — particle-only effects pass
/// none) plus an ordered list of stages. This is the entire authoring
/// unit. A new effect is one of these literals.
///
/// A7.2: cold — recipes are comptime/config, cloned and tweaked, never
/// held in a hot loop; their RUNTIME instances (Active, below) are the
/// hot population and are guarded.
pub const Recipe = struct {
    stencil: ?Stencil = null,
    stages: []const Stage,

    /// Total seconds the effect runs — the sum of its stages. Pure.
    pub fn lifetime(r: Recipe) f32 {
        var t: f32 = 0;
        for (r.stages) |s| t += s.duration;
        return t;
    }
};

// ---------------------------------------------------------------------------
// The default recipe library (every number a tunable default — §5 table)
// ---------------------------------------------------------------------------

/// The owner's heart, staged exactly as described: redden bottom-up,
/// a held beat, burst outward (shape pops AND particles fly), comedown.
/// Clone this and change numbers for a softer or louder like.
pub const like_heart = Recipe{
    .stencil = heart_inline,
    .stages = &.{
        .{ .kind = .glow_ramp, .duration = 0.22, .glow = 210, .sweep = .bottom_up, .color = 4 },
        .{ .kind = .hold, .duration = 0.04 },
        // Burst sized for an inline heart: fewer, gentler sparks so they
        // pop around the button, not across the whole post. [TUNE]
        .{ .kind = .emit, .duration = 0.0, .emit_kind = .burst, .emit_count = 14, .emit_energy = 34, .emit_palette = 0 },
        .{ .kind = .shockwave, .duration = 0.16, .push = 2.2, .color = 4 },
        .{ .kind = .fade, .duration = 0.40, .glow = 210 },
    },
};

/// A quieter unlike: the heart cools top-down and collapses inward, no
/// burst — the visual inverse of a like, same machinery.
pub const unlike_heart = Recipe{
    .stencil = heart_inline,
    .stages = &.{
        .{ .kind = .glow_ramp, .duration = 0.30, .glow = 90, .sweep = .top_down, .color = 5 },
        .{ .kind = .fade, .duration = 0.40, .glow = 90 },
    },
};

/// Boost: a green ring ignites center-out and throws a light ember
/// puff — shows force/colour/shape all swapped from like, no new code.
pub const boost = Recipe{
    .stencil = boost_ring,
    .stages = &.{
        .{ .kind = .glow_ramp, .duration = 0.25, .glow = 200, .sweep = .center_out, .color = 3 },
        .{ .kind = .emit, .duration = 0.0, .emit_kind = .burst, .emit_count = 16, .emit_energy = 55, .emit_palette = 1 },
        .{ .kind = .shockwave, .duration = 0.16, .push = 4.0, .color = 3 },
        .{ .kind = .fade, .duration = 0.45, .glow = 200 },
    },
};

/// A pure-particle effect (no stencil): a stream that nudges the feed
/// down when a new post arrives. Proves the layer handles shapeless
/// effects too.
pub const new_post = Recipe{
    .stencil = null,
    .stages = &.{
        .{ .kind = .emit, .duration = 0.0, .emit_kind = .stream, .emit_count = 14, .emit_energy = 40, .emit_palette = 0 },
        .{ .kind = .hold, .duration = 0.3 },
    },
};

// ---------------------------------------------------------------------------
// Runtime — the active effect population (HOT, guarded)
// ---------------------------------------------------------------------------

/// One playing effect instance. HOT — several can run at once (rapid
/// likes, a like over a boost) → A7. The recipe is referenced, not
/// copied (it is comptime/cold data); position, clock, scale and the
/// stage cursor are the per-instance state.
pub const Active = struct {
    /// A reference to a Recipe. The recipes the shell fires are this
    /// module's OWN module-level constants (`&effect.like_heart` etc.),
    /// so this pointer points back into the data's owning module — a
    /// stable reference to immutable module data, not a foreign-array
    /// index (A4/A5 are about indexes into another module's arrays; a
    /// pointer to our own `const` is the legitimate analogue of passing
    /// a CID). A caller MAY also pass a pointer to a Recipe it built and
    /// keeps alive for the effect's lifetime; either way the pointee
    /// must outlive the Active, which the comptime recipes trivially do.
    recipe: *const Recipe,
    /// Screen-cell origin the stencil is centred on.
    x: u16,
    y: u16,
    /// Trigger-time intensity multiplier (the owner's context dial):
    /// scales emit counts and shockwave push. 256 = ×1.0 (8.8 fixed).
    scale_q8: u16,
    /// Seconds elapsed inside the CURRENT stage.
    stage_t: f32,
    /// Index of the running stage.
    stage: u8,
    /// Set once when the current stage's one-shot work (emit) has fired.
    fired: bool,
    _pad: u8 = 0,

    comptime {
        // Budget: 8 (ptr) + 2+2 (xy) + 2 (scale) + 4 (stage_t) + 1+1+1
        // = 22 → 24 with 8-byte alignment of the pointer. Exact.
        assert(@sizeOf(Active) == 24);
    }
};

pub const ActiveList = std.MultiArrayList(Active);

/// Scale helper: 8.8 fixed multiply, saturating to u8 count range.
fn scaleCount(base: u8, scale_q8: u16) u8 {
    const v = (@as(u32, base) * scale_q8) >> 8;
    return @intCast(@min(v, 255));
}

fn scaleF(base: f32, scale_q8: u16) f32 {
    return base * (@as(f32, @floatFromInt(scale_q8)) / 256.0);
}

// ---------------------------------------------------------------------------
// trigger / advance — the pure authoring transform (B2)
// ---------------------------------------------------------------------------

/// Begin an effect at a screen cell with a context intensity. Pure
/// bookkeeping: appends one Active. `scale` is the owner's live dial
/// (1.0 = the recipe as written; 0.4 = a whisper; 2.0 = a shout).
/// C1: explicit allocator; C2: the only allocation, visible here.
pub fn trigger(
    gpa: Allocator,
    active: *ActiveList,
    recipe: *const Recipe,
    x: u16,
    y: u16,
    scale: f32,
) error{OutOfMemory}!void {
    const q8: u16 = @intFromFloat(std.math.clamp(scale * 256.0, 0.0, 65535.0));
    try active.append(gpa, .{
        .recipe = recipe,
        .x = x,
        .y = y,
        .scale_q8 = q8,
        .stage_t = 0,
        .stage = 0,
        .fired = false,
    });
}

/// PURE (B2): advance every active effect by `dt`, writing glow/colour
/// into the field's content+perturb grids and appending any spawn
/// events the effects fire this frame. Same (active, field, dt) ⇒ same
/// writes and same events. Exhausted effects are culled — an ordinary
/// result, not an error (E4).
///
/// The returned events are handed straight to field.step by the caller
/// in the SAME frame, so an effect's burst and the physics that answers
/// it are one tick apart at most. `out_events` is caller-owned scratch
/// (the per-frame arena, C3); cleared on entry.
pub fn advance(
    gpa: Allocator,
    active: *ActiveList,
    f: *field.Field,
    dt: f32,
    out_events: *std.ArrayList(field.SpawnEvent),
) error{OutOfMemory}!void {
    out_events.clearRetainingCapacity();

    var i: usize = 0;
    while (i < active.len) {
        var done = false;
        {
            const s = active.slice();
            const a_recipe = s.items(.recipe)[i];
            const a_x = s.items(.x)[i];
            const a_y = s.items(.y)[i];
            const a_scale = s.items(.scale_q8)[i];
            const stage_idx = &s.items(.stage)[i];
            const stage_t = &s.items(.stage_t)[i];
            const fired = &s.items(.fired)[i];

            const stages = a_recipe.stages;
            if (stage_idx.* >= stages.len) {
                done = true;
            } else {
                const stage = stages[stage_idx.*];

                // One-shot work at stage entry: fire the emit.
                if (!fired.*) {
                    fired.* = true;
                    if (stage.kind == .emit) {
                        try out_events.append(gpa, .{
                            .x = a_x,
                            .y = a_y,
                            .kind = stage.emit_kind,
                            .energy = stage.emit_energy,
                            .count = scaleCount(stage.emit_count, a_scale),
                            .palette = stage.emit_palette,
                        });
                    }
                }

                // Per-frame work: paint the stencil according to the
                // stage's rule, evaluated at progress t.
                const t: f32 = if (stage.duration > 0) @min(1.0, stage_t.* / stage.duration) else 1.0;
                if (a_recipe.stencil) |stencil| {
                    applyStage(f, stencil, a_x, a_y, stage, t, a_scale);
                }

                // Advance the clock; roll to the next stage at the edge.
                stage_t.* += dt;
                if (stage.duration <= 0 or stage_t.* >= stage.duration) {
                    stage_idx.* += 1;
                    stage_t.* = 0;
                    fired.* = false;
                    if (stage_idx.* >= stages.len) done = true;
                }
            }
        }
        if (done) {
            active.swapRemove(i);
        } else {
            i += 1;
        }
    }
}

/// Shift every active effect's Y origin by a signed cell `delta`. PURE
/// (B2): mutates only the passed list, no clock/IO. When the timeline
/// scrolls, content moves by some rows; calling this with the matching
/// delta keeps a playing effect (the like burst) anchored to the post it
/// belongs to, so it RIDES the scroll instead of detaching and floating
/// in place. Saturates into the u16 cell range — an effect scrolled off
/// the top clamps to 0 (and is drawn off-screen / culled by its own
/// lifetime), never wraps. The shell owns when to call this; the core
/// just performs the transform on plain data.
pub fn shiftY(active: *ActiveList, delta: i32) void {
    const ys = active.slice().items(.y);
    for (ys) |*y| {
        const shifted: i32 = @as(i32, y.*) + delta;
        y.* = @intCast(std.math.clamp(shifted, 0, std.math.maxInt(u16)));
    }
}
///
/// For a scale-1 shape this stamps every glyph as a coarse cell. For a
/// finer shape (scale > 1), it stamps a COARSE footprint of `interactive`
/// cells (so the burst still shoves neighbouring text and particles
/// collide), while the DETAILED visual is drawn separately by
/// composeEffects at the fine pitch — the field stays coarse (ContentCell
/// is 4 bytes, no sub-cell storage), the look gets the density.
pub fn stamp(f: *field.Field, stencil: Stencil, cx: u16, cy: u16, color: u8) void {
    if (stencil.scale > 1) {
        // Coarse physics footprint: a block of interactive cells the
        // size of the shape's cell footprint, centred on (cx,cy). The
        // fine glyphs are composeEffects' job.
        const fw: i32 = @max(1, @divTrunc(@as(i32, stencil.w), @as(i32, stencil.scale)));
        const fh: i32 = @max(1, @divTrunc(@as(i32, stencil.h), @as(i32, stencil.scale)));
        var ry: i32 = 0;
        while (ry < fh) : (ry += 1) {
            var rx: i32 = 0;
            while (rx < fw) : (rx += 1) {
                const gx = @as(i32, cx) - @divTrunc(fw, 2) + rx;
                const gy = @as(i32, cy) - @divTrunc(fh, 2) + ry;
                if (gx < 0 or gy < 0 or gx >= f.cols or gy >= f.rows) continue;
                // Mark interactive but DON'T draw a coarse glyph (glyph 0
                // = empty), so compose skips it and only the fine pass
                // shows. The cell still perturbs and collides.
                const at = field.index(f, @intCast(gx), @intCast(gy));
                f.content[at].flags.interactive = true;
            }
        }
        return;
    }
    const ox: i32 = @as(i32, cx) - stencil.w / 2;
    const oy: i32 = @as(i32, cy) - stencil.h / 2;
    for (stencil.rows, 0..) |row, ry| {
        for (row, 0..) |ch, rx| {
            if (ch == ' ') continue;
            const gx = ox + @as(i32, @intCast(rx));
            const gy = oy + @as(i32, @intCast(ry));
            if (gx < 0 or gy < 0 or gx >= f.cols or gy >= f.rows) continue;
            f.content[field.index(f, @intCast(gx), @intCast(gy))] = .{
                .glyph = ch,
                .fg = color,
                .flags = .{ .text = true, .interactive = true },
            };
        }
    }
}

/// Render every active effect's FINE-resolution stencil directly into
/// the draw list, at its own sub-cell pixel pitch — this is the
/// variable-resolution path (the detailed upright heart). Called after
/// field.compose, so fine glyphs draw ON TOP of the coarse grid.
///
/// PURE (B2): same (active, stage progress, cell metrics) ⇒ same draw
/// items. The bottom-up fill, the pop overshoot, and the colour ramp are
/// all computed here from the stage clock — no stored frames. Only
/// scale>1 stencils render here; scale-1 shapes go through stamp/compose
/// as before. Allocator is explicit (C1); the only growth is the draw
/// list, visible at the call site (C2).
pub fn composeEffects(
    gpa: Allocator,
    active: ActiveList.Slice,
    cell_w: u16,
    cell_h: u16,
    dl: *raster.DrawList,
) error{OutOfMemory}!void {
    const recipes = active.items(.recipe);
    const axs = active.items(.x);
    const ays = active.items(.y);
    const stages = active.items(.stage);
    const stage_ts = active.items(.stage_t);

    for (recipes, axs, ays, stages, stage_ts) |recipe, ax, ay, stage_idx, stage_t| {
        const stencil = recipe.stencil orelse continue;
        if (stencil.scale <= 1) continue; // coarse shapes: not our job
        if (stage_idx >= recipe.stages.len) continue;
        const stage = recipe.stages[stage_idx];

        // The inline heart is drawn as the SAME density-glyph heart as the
        // resting button (drawHeartGlyphs), animated by the stage clock —
        // so it never changes into blocks or jumps position. The fill and
        // settling glow follow the owner's HTML: liking fills bottom-up and
        // glows down; UNLIKING drains the fill back out (the power-down).
        const dur = if (stage.duration > 0) stage.duration else 0.0001;
        const t: f32 = @min(1.0, stage_t / dur);
        const draining = stage.sweep == .top_down; // unlike recipe uses top_down
        const fill: f32 = if (draining)
            (1.0 - t) // drain 1 → 0 over the stage (HTML unlike)
        else switch (stage.kind) {
            .glow_ramp => t, // fill 0 → 1 bottom-up
            .hold, .emit, .shockwave, .fade => 1.0,
        };
        // Settling glow: bright at the pop, easing to the resting level.
        const glow: f32 = switch (stage.kind) {
            .shockwave => 0.45,
            .glow_ramp => if (draining) 0.0 else (0.35 * t),
            .hold, .emit => 0.35,
            .fade => if (draining) 0.0 else 0.35 * (1.0 - t),
        };
        try drawHeartGlyphs(gpa, ax, ay, cell_w, cell_h, fill, glow, dl);

        // The radiating ring (HTML burst): during the shockwave stage a
        // ring of '.'/'o' glyphs expands outward from the heart and fades.
        // It is drawn as text glyphs (ASCII, like everything else), at the
        // bar's pixel scale, centred on the heart.
        if (stage.kind == .shockwave and !draining) {
            try drawRing(gpa, ax, ay, cell_w, cell_h, t, dl);
        }
    }
}

/// Draw one expanding ring of glyphs around the heart at progress `t`
/// (0→1 over the shockwave stage). The radius grows and the ring fades;
/// glyphs are placed on a circle, deduped to whole cells. ASCII, drawn as
/// engine text items at the bar pixel scale. PURE.
fn drawRing(
    gpa: Allocator,
    cx: u16,
    cy: u16,
    cell_w: u16,
    cell_h: u16,
    t: f32,
    dl: *raster.DrawList,
) error{OutOfMemory}!void {
    const tile: i32 = @max(3, @divTrunc(@as(i32, cell_h) * 28, 100)); // ~ a heart tile
    // Centre on the heart's middle (the heart spans ~4 tiles wide, ~1.4 rows).
    const center_x: f32 = @as(f32, @floatFromInt(@as(i32, cx) * cell_w)) + @as(f32, @floatFromInt(tile)) * 2.0;
    const center_y: f32 = @as(f32, @floatFromInt(@as(i32, cy) * cell_h)) + @as(f32, @floatFromInt(cell_h)) * 0.5;
    // Radius in pixels grows with t; fade out as it expands.
    const radius: f32 = (0.4 + t * 2.2) * @as(f32, @floatFromInt(tile));
    const life: f32 = 1.0 - t;
    if (life <= 0.05) return;
    const r: u32 = @intFromFloat(lerp(40, 200, life));
    const g: u32 = @intFromFloat(lerp(60, 230, life));
    const b: u32 = @intFromFloat(lerp(110, 220, life));
    const color: u32 = 0xFF000000 | (r << 16) | (g << 8) | b;
    const glyph: u8 = if (t < 0.5) '.' else ':';

    // 16 points around the circle, slightly wider than tall (HTML 1.8x).
    const n = 16;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const ang = (@as(f32, @floatFromInt(i)) / n) * std.math.tau;
        const px = center_x + @cos(ang) * radius * 1.4;
        const py = center_y + @sin(ang) * radius;
        try dl.append(gpa, .{ .text = .{
            .x = @intCast(std.math.clamp(@as(i32, @intFromFloat(px)), -32768, 32767)),
            .baseline = @intCast(std.math.clamp(@as(i32, @intFromFloat(py)) + tile, -32768, 32767)),
            .codepoint = glyph,
            .color = color,
            .px = @intCast(@max(1, tile)),
            .weight = 0,
        } });
    }
}

/// The heart silhouette: 1 = part of the heart. Shared by the resting
/// button and the burst so they are the SAME heart. It is drawn as
/// DENSITY GLYPHS (the owner's HTML spec): each cell picks a ramp
/// character by brightness — sparse '.' when dim, dense '@' when bright —
/// exactly the Ghostty-ghost language where the SYMBOLS change with the
/// animation. Rendered as engine text glyphs at a small px so the heart
/// is built of ASCII, not solid blocks.
const heart_bitmap = [5][7]u8{
    .{ 0, 1, 0, 0, 0, 1, 0 },
    .{ 1, 1, 1, 0, 1, 1, 1 },
    .{ 1, 1, 1, 1, 1, 1, 1 },
    .{ 0, 1, 1, 1, 1, 1, 0 },
    .{ 0, 0, 1, 1, 1, 0, 0 },
};
const heart_rows = heart_bitmap.len;
const heart_cols = heart_bitmap[0].len;

/// The density ramp from the owner's HTML: sparse → dense. A brighter
/// cell picks a later (denser) glyph; the floor is index 3 ('-') so the
/// unfilled outline still reads as a heart, never blank.
const heart_ramp = " .:-=+*#%@";

/// Brightness → warm heart colour (HTML: lerp red→pink as b rises).
fn heartColor(b_in: f32) u32 {
    const b = std.math.clamp(b_in, 0.0, 1.0);
    const r: u32 = @intFromFloat(lerp(200, 255, b));
    const g: u32 = @intFromFloat(lerp(40, 150, b));
    const bl: u32 = @intFromFloat(lerp(95, 160, b * 0.8));
    return 0xFF000000 | (r << 16) | (g << 8) | bl;
}
fn lerp(a: f32, b: f32, t: f32) f32 {
    return a + (b - a) * t;
}

/// Draw the heart at cell (cx,cy) as DENSITY GLYPHS, sized to the bar.
/// `fill` in [0,1] is the bottom-up fill fraction (HTML fillLevel):
/// cells at or below the fill line glow warm with a brightness-picked
/// ramp glyph; cells above show the dim slate outline ('-'). `glow` adds
/// the post-pop settling brightness. `scale` (1.0 = none) applies the
/// pop overshoot by nudging the per-cell brightness. One code path for
/// the resting button (fill given, glow 0) and the burst (animated).
fn drawHeartGlyphs(
    gpa: Allocator,
    cx: u16,
    cy: u16,
    cell_w: u16,
    cell_h: u16,
    fill: f32,
    glow: f32,
    dl: *raster.DrawList,
) error{OutOfMemory}!void {
    // The heart fits the bar: total height ~1.4 cell rows (so it reads as
    // a heart without spilling into the divider or the text above). With a
    // 5-row silhouette each tile is ~0.28·cell_h — big enough that the
    // ramp character in each tile is legible. Tile width follows the font
    // advance so the glyphs sit flush, like the body text.
    const rows_i: i32 = @intCast(heart_rows);
    const total_h: i32 = @max(rows_i, @divTrunc(@as(i32, cell_h) * 14, 10));
    const tile_h: i32 = @max(3, @divTrunc(total_h, rows_i));
    const tile_w: i32 = @max(3, @divTrunc(tile_h * 60, 100)); // a touch wider than advance for body
    const origin_x: i32 = @as(i32, cx) * cell_w;
    // Centre the heart vertically on the bar row.
    const origin_y: i32 = @as(i32, cy) * cell_h + @divTrunc(@as(i32, cell_h) - tile_h * rows_i, 2);

    // Fill line in ROW space (HTML: fillRow = max - (max-min)*fillLevel).
    const fill_row: f32 = @as(f32, heart_rows - 1) * (1.0 - fill);

    for (heart_bitmap, 0..) |brow, ry| {
        for (brow, 0..) |ink, rx| {
            if (ink == 0) continue;
            const lit = @as(f32, @floatFromInt(ry)) >= fill_row;
            var glyph: u8 = heart_ramp[3]; // dim outline default
            var color: u32 = 0xFF36406E; // cool slate (HTML rgb(54,64,110))
            if (lit) {
                // Brightness: base + settling glow + a subtle horizontal
                // shimmer so the filled body is not flat (HTML dEdge feel).
                const edge: f32 = @as(f32, @floatFromInt(@min(rx, heart_cols - rx))) / @as(f32, heart_cols);
                var b: f32 = 0.55 + glow + edge * 0.25;
                b = std.math.clamp(b, 0.0, 1.0);
                const idx: usize = @max(3, @as(usize, @intFromFloat(@round(b * @as(f32, heart_ramp.len - 1)))));
                glyph = heart_ramp[@min(idx, heart_ramp.len - 1)];
                color = heartColor(b);
            }
            const gx = origin_x + @as(i32, @intCast(rx)) * tile_w;
            const gy = origin_y + @as(i32, @intCast(ry)) * tile_h;
            try dl.append(gpa, .{ .text = .{
                .x = @intCast(std.math.clamp(gx, -32768, 32767)),
                .baseline = @intCast(std.math.clamp(gy + tile_h, -32768, 32767)),
                .codepoint = glyph,
                .color = color,
                .px = @intCast(@max(1, tile_h)),
                .weight = 0,
            } });
        }
    }
}

/// The number of timeline cells the inline heart reserves horizontally,
/// so layout can place the like count after it. The glyph heart is 12
/// ramp-tiles wide at ~0.46 advance and ~2 bar-rows tall; that is ≈3
/// cells wide. Fixed cell count (the heart sizes to pixels, not the cell
/// grid), so layout — which works in cells — has a stable reservation.
pub fn inlineHeartCellW() u16 {
    return 4;
}
pub fn inlineHeartCellH() u16 {
    return 1; // anchored on the single engagement-bar row
}

/// Draw the RESTING like-button heart at cell (cx, cy) — the static
/// sprite the owner wants AS the button: a filled red heart when liked,
/// a dim outline when not. Same stencil, same fine-glyph rendering as
/// the animation (composeEffects), so the button and its burst are
/// literally the same heart at the same size. PURE (B2): same (liked,
/// position, metrics) ⇒ same draw items. The heart is vertically
/// centred on the cell row so it sits on the engagement line. Returns
/// nothing; appends fine glyphs to the draw list (C1/C2 explicit).
///
/// `suppress` lets the caller hide the static heart for one post while
/// its animation is playing (the effect draws the heart then, so drawing
/// both would double it) — the shell passes the animating target.
pub fn composeStaticHeart(
    gpa: Allocator,
    liked: bool,
    cx: u16,
    cy: u16,
    cell_w: u16,
    cell_h: u16,
    dl: *raster.DrawList,
) error{OutOfMemory}!void {
    // Resting heart, drawn as density glyphs (the owner's HTML look).
    // Liked: fully filled (fill = 1) with a gentle resting glow. Unliked:
    // fill = 0 → the dim slate '-' outline. Same drawHeartGlyphs the burst
    // uses, so the button and its animation are the same ASCII heart.
    if (liked) {
        try drawHeartGlyphs(gpa, cx, cy, cell_w, cell_h, 1.0, 0.10, dl);
    } else {
        try drawHeartGlyphs(gpa, cx, cy, cell_w, cell_h, 0.0, 0.0, dl);
    }
}

/// The per-stage cell rule — pure, evaluated against progress `t`. This
/// is where "redden from the bottom" actually happens: each stencil
/// cell's lit-ness is a function of its position and `t`, so the light
/// sweeps as t grows. No frame is stored; the sweep EMERGES from the
/// rule meeting the clock.
fn applyStage(f: *field.Field, stencil: Stencil, cx: u16, cy: u16, stage: Stage, t: f32, scale_q8: u16) void {
    // Fine-resolution shapes (scale > 1) are drawn by composeEffects at
    // their own pitch; here we only drive the COARSE-footprint physics
    // so the burst still shoves neighbours and the cells still glow.
    if (stencil.scale > 1) {
        applyCoarseFootprint(f, stencil, cx, cy, stage, t, scale_q8);
        return;
    }
    const ox: i32 = @as(i32, cx) - stencil.w / 2;
    const oy: i32 = @as(i32, cy) - stencil.h / 2;
    for (stencil.rows, 0..) |row, ry| {
        for (row, 0..) |ch, rx| {
            if (ch == ' ') continue;
            const gx = ox + @as(i32, @intCast(rx));
            const gy = oy + @as(i32, @intCast(ry));
            if (gx < 0 or gy < 0 or gx >= f.cols or gy >= f.rows) continue;
            const at = field.index(f, @intCast(gx), @intCast(gy));

            // How "reached" is this cell by the sweep at progress t?
            // reach in [0,1]; a cell lights when t passes its position.
            const fy: f32 = @as(f32, @floatFromInt(ry)) / @max(1.0, @as(f32, @floatFromInt(stencil.h - 1)));
            const fx: f32 = @as(f32, @floatFromInt(rx)) / @max(1.0, @as(f32, @floatFromInt(stencil.w - 1)));
            const pos: f32 = switch (stage.sweep) {
                .bottom_up => 1.0 - fy, // bottom row reached first
                .top_down => fy,
                .left_right => fx,
                .center_out => @max(@abs(fx - 0.5), @abs(fy - 0.5)) * 2.0,
                .all_at_once => 0.0,
            };

            switch (stage.kind) {
                .glow_ramp => {
                    const lit = t >= pos;
                    if (lit) {
                        f.content[at].fg = stage.color;
                        const p = &f.perturb[at];
                        const g: u16 = @as(u16, p.glow) + stage.glow / 4;
                        p.glow = @intCast(@min(g, stage.glow));
                        p.flags |= field.Perturb.flag_active;
                    }
                },
                .hold => {},
                .emit => {},
                .shockwave => {
                    // Push this cell outward from centre, eased by t.
                    const dirx = fx - 0.5;
                    const diry = fy - 0.5;
                    const len = @max(0.001, @sqrt(dirx * dirx + diry * diry));
                    const mag = scaleF(stage.push, scale_q8) * (1.0 - t); // fades as it expands
                    const p = &f.perturb[at];
                    const nvx = (dirx / len) * mag;
                    const nvy = (diry / len) * mag;
                    p.vx = clampFp(@as(f32, @floatFromInt(p.vx)) / 16.0 + nvx);
                    p.vy = clampFp(@as(f32, @floatFromInt(p.vy)) / 16.0 + nvy);
                    p.flags |= field.Perturb.flag_active;
                },
                .fade => {
                    // Let field.zig's glow_decay do the work; nudge the
                    // colour back toward neutral as t completes.
                    if (t > 0.6) f.content[at].fg = if (t > 0.85) 1 else stage.color;
                },
            }
        }
    }
}

fn clampFp(v: f32) i8 {
    return @intFromFloat(std.math.clamp(@round(v * 16.0), -127.0, 127.0));
}

/// Coarse-footprint physics for a fine (scale>1) shape: glow and
/// shockwave applied to the block of cells the shape covers, so the
/// burst shoves neighbouring text and the cells light, while the
/// detailed glyphs are drawn by composeEffects. Mirrors applyStage's
/// per-cell rules but over the coarse footprint, using each cell's
/// position within the block for the sweep.
fn applyCoarseFootprint(f: *field.Field, stencil: Stencil, cx: u16, cy: u16, stage: Stage, t: f32, scale_q8: u16) void {
    const fw: i32 = @max(1, @divTrunc(@as(i32, stencil.w), @as(i32, stencil.scale)));
    const fh: i32 = @max(1, @divTrunc(@as(i32, stencil.h), @as(i32, stencil.scale)));
    var ry: i32 = 0;
    while (ry < fh) : (ry += 1) {
        var rx: i32 = 0;
        while (rx < fw) : (rx += 1) {
            const gx = @as(i32, cx) - @divTrunc(fw, 2) + rx;
            const gy = @as(i32, cy) - @divTrunc(fh, 2) + ry;
            if (gx < 0 or gy < 0 or gx >= f.cols or gy >= f.rows) continue;
            const at = field.index(f, @intCast(gx), @intCast(gy));
            const fyf: f32 = @as(f32, @floatFromInt(ry)) / @max(1.0, @as(f32, @floatFromInt(fh - 1)));
            const fxf: f32 = @as(f32, @floatFromInt(rx)) / @max(1.0, @as(f32, @floatFromInt(fw - 1)));
            const pos: f32 = switch (stage.sweep) {
                .bottom_up => 1.0 - fyf,
                .top_down => fyf,
                .left_right => fxf,
                .center_out => @max(@abs(fxf - 0.5), @abs(fyf - 0.5)) * 2.0,
                .all_at_once => 0.0,
            };
            const p = &f.perturb[at];
            switch (stage.kind) {
                .glow_ramp => if (t >= pos) {
                    const g: u16 = @as(u16, p.glow) + stage.glow / 6;
                    p.glow = @intCast(@min(g, stage.glow));
                    p.flags |= field.Perturb.flag_active;
                },
                .shockwave => {
                    const dirx = fxf - 0.5;
                    const diry = fyf - 0.5;
                    const len = @max(0.001, @sqrt(dirx * dirx + diry * diry));
                    const mag = scaleF(stage.push, scale_q8) * (1.0 - t);
                    p.vx = clampFp(@as(f32, @floatFromInt(p.vx)) / 16.0 + (dirx / len) * mag);
                    p.vy = clampFp(@as(f32, @floatFromInt(p.vy)) / 16.0 + (diry / len) * mag);
                    p.flags |= field.Perturb.flag_active;
                },
                else => {},
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Golden tests (design §8): staged behaviour pinned by numbers
// ---------------------------------------------------------------------------

test "guards and lifetimes: the authoring records are exactly sized" {
    try testing.expectEqual(@as(usize, 24), @sizeOf(Active));
    // The heart's staged lifetime is the sum of its stages — a pure fact.
    try testing.expectApproxEqAbs(@as(f32, 0.82), like_heart.lifetime(), 0.001);
    // The heart is now an upright, detailed, fine-resolution silhouette.
    try testing.expect(heart.scale == 2);
    try testing.expect(heart.w > 20 and heart.h > 15); // dense, not a sparse outline
    // The INLINE heart is the same shape but compact: a handful of cells
    // wide so it sits AS the like button beside rt/re. This is the owner's
    // point — the button is the heart. (Scale 2 is the legibility floor:
    // denser scales rendered as illegible bands.)
    // The INLINE heart is minimal: ~3 cells wide and ~2 tall so it sits
    // on the engagement line with the count without colliding with the
    // rows around it (the owner's constraint — at most slightly taller
    // than the numbers beside it). The font has no ♥ glyph, so it is an
    // ASCII silhouette; at this size the lobes are only suggested.
    try testing.expect(inlineHeartCellW() >= 2 and inlineHeartCellW() <= 4);
    try testing.expect(inlineHeartCellH() <= 2);
}

test "glow_ramp sweeps bottom-up: lower rows light before upper rows" {
    const gpa = testing.allocator; // C6
    var f: field.Field = .{};
    try field.init(gpa, &f, 40, 30);
    defer field.deinit(gpa, &f);

    var active: ActiveList = .empty;
    defer active.deinit(gpa);
    var events: std.ArrayList(field.SpawnEvent) = .empty;
    defer events.deinit(gpa);

    // A bottom-up ramp over the heart, centred at (20,15) in a field big
    // enough for its coarse footprint (~13×11 cells at scale 2).
    const ramp = Recipe{ .stencil = heart, .stages = &.{
        .{ .kind = .glow_ramp, .duration = 1.0, .glow = 200, .sweep = .bottom_up, .color = 4 },
    } };
    try trigger(gpa, &active, &ramp, 20, 15, 1.0);

    const dt: f32 = 1.0 / 60.0;
    // Step ~30% of the way: the lower band of the footprint should carry
    // more glow than the upper band — reddening from below.
    var n: usize = 0;
    while (n < 18) : (n += 1) try advance(gpa, &active, &f, dt, &events);

    // Compare the lower half of the field's rows to the upper half,
    // summing glow across all columns — geometry-agnostic, so it holds
    // regardless of the exact footprint size.
    var lower: u64 = 0;
    var upper: u64 = 0;
    for (0..30) |y| {
        var rowsum: u64 = 0;
        for (0..40) |x| rowsum += f.perturb[field.index(&f, @intCast(x), @intCast(y))].glow;
        if (y >= 15) lower += rowsum else upper += rowsum;
    }
    try testing.expect(lower > upper); // bottom reached first
}

test "emit stage fires exactly one spawn, scaled by context intensity" {
    const gpa = testing.allocator;
    var f: field.Field = .{};
    try field.init(gpa, &f, 24, 12);
    defer field.deinit(gpa, &f);
    var active: ActiveList = .empty;
    defer active.deinit(gpa);
    var events: std.ArrayList(field.SpawnEvent) = .empty;
    defer events.deinit(gpa);

    const pop = Recipe{ .stencil = null, .stages = &.{
        .{ .kind = .emit, .duration = 0.0, .emit_kind = .burst, .emit_count = 20, .emit_energy = 60, .emit_palette = 0 },
    } };
    // Fire at 2x intensity: the count should double, deterministically.
    try trigger(gpa, &active, &pop, 12, 6, 2.0);
    try advance(gpa, &active, &f, 1.0 / 60.0, &events);
    try testing.expectEqual(@as(usize, 1), events.items.len);
    try testing.expectEqual(@as(u8, 40), events.items[0].count); // 20 × 2.0
    // Instantaneous emit stage completes in one tick → effect is gone.
    try testing.expectEqual(@as(usize, 0), active.len);
}

test "the full like-heart runs through every stage and self-culls" {
    const gpa = testing.allocator;
    var f: field.Field = .{};
    try field.init(gpa, &f, 40, 16);
    defer field.deinit(gpa, &f);
    var active: ActiveList = .empty;
    defer active.deinit(gpa);
    var events: std.ArrayList(field.SpawnEvent) = .empty;
    defer events.deinit(gpa);
    var all_spawns: std.ArrayList(field.SpawnEvent) = .empty;
    defer all_spawns.deinit(gpa);

    try trigger(gpa, &active, &like_heart, 20, 8, 1.0);
    const dt: f32 = 1.0 / 60.0;
    // Run a hair past the heart's full lifetime; collect every spawn.
    var elapsed: f32 = 0;
    var saw_burst = false;
    while (elapsed < like_heart.lifetime() + 0.1) : (elapsed += dt) {
        try advance(gpa, &active, &f, dt, &events);
        for (events.items) |ev| {
            if (ev.kind == .burst) saw_burst = true;
        }
    }
    try testing.expect(saw_burst); // the burst stage fired
    try testing.expectEqual(@as(usize, 0), active.len); // and it cleaned up (E4)
}

test "many simultaneous effects coexist and each completes independently" {
    const gpa = testing.allocator;
    var f: field.Field = .{};
    try field.init(gpa, &f, 60, 30);
    defer field.deinit(gpa, &f);
    var active: ActiveList = .empty;
    defer active.deinit(gpa);
    var events: std.ArrayList(field.SpawnEvent) = .empty;
    defer events.deinit(gpa);

    // A rapid flurry: like, unlike, boost, new-post — all live at once.
    try trigger(gpa, &active, &like_heart, 10, 10, 1.0);
    try trigger(gpa, &active, &unlike_heart, 30, 10, 0.6);
    try trigger(gpa, &active, &boost, 20, 20, 1.5);
    try trigger(gpa, &active, &new_post, 40, 5, 1.0);
    try testing.expectEqual(@as(usize, 4), active.len);

    const dt: f32 = 1.0 / 60.0;
    var n: usize = 0;
    const longest = like_heart.lifetime();
    while (n < @as(usize, @intFromFloat(longest / dt)) + 4) : (n += 1) {
        try advance(gpa, &active, &f, dt, &events);
    }
    try testing.expectEqual(@as(usize, 0), active.len); // all settled, no leaks
}

test "shiftY moves every effect by the scroll delta and saturates at the top" {
    const gpa = testing.allocator;
    var active: ActiveList = .empty;
    defer active.deinit(gpa);

    // Three effects at different rows; a like burst is anchored to a post.
    try trigger(gpa, &active, &like_heart, 10, 20, 1.0);
    try trigger(gpa, &active, &boost, 5, 8, 1.0);
    try trigger(gpa, &active, &new_post, 40, 3, 1.0);

    // Scroll the content DOWN by 3 rows → effects ride along (+3).
    shiftY(&active, 3);
    {
        const ys = active.slice().items(.y);
        try testing.expectEqual(@as(u16, 23), ys[0]);
        try testing.expectEqual(@as(u16, 11), ys[1]);
        try testing.expectEqual(@as(u16, 6), ys[2]);
    }
    // Scroll UP hard enough that the top effect would go negative: it
    // clamps to 0, never wraps to a huge u16.
    shiftY(&active, -10);
    {
        const ys = active.slice().items(.y);
        try testing.expectEqual(@as(u16, 13), ys[0]);
        try testing.expectEqual(@as(u16, 1), ys[1]);
        try testing.expectEqual(@as(u16, 0), ys[2]); // 6 - 10 clamped to 0
    }
    // x is untouched by a Y shift.
    try testing.expectEqual(@as(u16, 10), active.slice().items(.x)[0]);
}
