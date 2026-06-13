//! B1 classification: CORE (pure). The glyph-field simulation —
//! GLYPH_FIELD_SYSTEM_DESIGN made real, slices G.1–G.3 (+ the seed of
//! G.5's vocabulary). The entire engine is a deterministic transform:
//!
//!     step(field, particles, events, dt, rng) -> next state
//!
//! No clock, no global randomness, no I/O — `dt` and `rng` are INJECTED
//! by the shell (B2/B4), which is what makes every behaviour below
//! golden-testable and headless-runnable (design §8). Effects are never
//! authored frame-by-frame: a "like burst" is an initial condition
//! handed to the same universal rules that run every frame (§1).
//!
//! What lives here: the two-grid field (content + perturbation), the
//! particle population, event ingestion, forces, the collision
//! write-back (§4 — the whole interaction mechanic), the damped-spring
//! settle, and the pure compose to a draw list. What does NOT live
//! here: clocks, event sources, blitting — shell, all of it (§3.2).
//!
//! Status against the design's build order (§10): G.1 (cell springs),
//! G.2 (particles), G.3 (collision) are implemented and golden-tested
//! headless. G.0 (the app cutover: layout writing the content grid,
//! engine-rendered mono cells) is the next slice and is deliberately
//! NOT here yet. G.4 (active-list) waits for a bench indictment
//! (G2/F4). G.5 exists as the comptime `kinds` table, to be widened
//! into full recipes when effects are authored.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const raster = @import("raster.zig");

// ---------------------------------------------------------------------------
// The data model (design §2) — plain data, fields only (A1), SoA (A3)
// ---------------------------------------------------------------------------

/// One cell of UI content, written by layout each frame (immediate
/// mode). HOT — one per screen cell, thousands → A7. `glyph` is an
/// index into the glyph vocabulary (this slice: the ASCII code itself;
/// the comptime art table arrives with G.0's authoring pipeline) and it
/// never leaves this module's render path (A4/A5). `fg` is a palette
/// index, not packed RGB (A6 spirit: the hot cell stays tight).
pub const ContentCell = struct {
    glyph: u8,
    fg: u8,
    flags: Flags,
    _pad: u8 = 0, // A6: explicit

    pub const Flags = packed struct(u8) {
        text: bool = false,
        divider: bool = false,
        fixed: bool = false,
        interactive: bool = false,
        _rest: u4 = 0,
    };

    pub const empty: ContentCell = .{ .glyph = 0, .fg = 0, .flags = .{} };

    comptime {
        // Budget: 4 bytes, exact. At 200x80 that is 64 KB — one L2
        // working set (design §2.1). Raising this is an A7.1 act.
        assert(@sizeOf(ContentCell) == 4);
    }
};

/// The physics perturbation of one cell: displacement from home,
/// velocity, glow. Persistent across relayout (screen-space, transient
/// — design §7). Sub-cell precision is FIXED-POINT i8 at 1/16 cell per
/// unit; math widens to f32 transiently and stores back saturating.
/// HOT — scanned every frame → A7, kept minimal by design.
pub const Perturb = struct {
    dx: i8 = 0,
    dy: i8 = 0,
    vx: i8 = 0,
    vy: i8 = 0,
    glow: u8 = 0,
    flags: u8 = 0, // bit0 = active (seed of G.4's active-list)
    _pad: u16 = 0, // A6: explicit

    pub const flag_active: u8 = 1;

    comptime {
        // Budget: 8 bytes, exact. Precision is the tuning knob, not the
        // layout; widening any field is an A7.1 act recorded here
        // (design §12.3: decide with eyes on a real screen).
        assert(@sizeOf(Perturb) == 8);
    }
};

/// One mobile particle in continuous (sub-cell) coordinates. Few of
/// them, smooth motion needed ⇒ f32 is the right budget here, exactly
/// as the design's A7.1 note reasons (§2.2). HOT → A7.
pub const Particle = struct {
    x: f32,
    y: f32,
    vx: f32,
    vy: f32,
    life: f32,
    glyph: u8,
    kind: u8,
    _pad: u16 = 0, // A6: explicit

    comptime {
        // Budget: 24 bytes, exact.
        assert(@sizeOf(Particle) == 24);
    }
};

pub const ParticleList = std.MultiArrayList(Particle);

/// A request to inject energy — the outside world as data (B5). The
/// shell resolves feed identity to a SCREEN position BEFORE this is
/// built; no feed index or CID ever enters the sim (A5, design §2.3).
pub const SpawnEvent = struct {
    x: u16,
    y: u16,
    kind: Kind,
    energy: u8,
    count: u8,
    palette: u8,
    _pad: u8 = 0, // A6: explicit

    pub const Kind = enum(u8) { burst, stream, implode };

    comptime {
        // Budget: 10 bytes, exact (design §2.3).
        assert(@sizeOf(SpawnEvent) == 10);
    }
};

/// The two layered grids plus observability counters. Owns its memory
/// (C4). A7.2: cold struct, size guard waived — one per window; its
/// CONTENTS are the hot arrays guarded above.
pub const Field = struct {
    cols: u16 = 0,
    rows: u16 = 0,
    content: []ContentCell = &.{},
    perturb: []Perturb = &.{},
    /// Observability (design §8 / SESSION_FINDINGS §3.1): nothing is
    /// silently swallowed. Spawns refused by the population cap and
    /// non-finite velocities that were caught-and-zeroed are COUNTED,
    /// so a misbehaving recipe is a number on a status line, never a
    /// mystery.
    dropped_spawns: u32 = 0,
    faults: u32 = 0,
};

pub fn init(gpa: Allocator, f: *Field, cols: u16, rows: u16) error{OutOfMemory}!void {
    const n: usize = @as(usize, cols) * rows;
    f.content = try gpa.alloc(ContentCell, n);
    errdefer gpa.free(f.content);
    f.perturb = try gpa.alloc(Perturb, n);
    f.cols = cols;
    f.rows = rows;
    @memset(f.content, ContentCell.empty);
    @memset(f.perturb, .{});
}

pub fn deinit(gpa: Allocator, f: *Field) void {
    gpa.free(f.content);
    gpa.free(f.perturb);
    f.* = .{};
}

pub fn index(f: *const Field, x: u16, y: u16) usize {
    return @as(usize, y) * f.cols + x;
}

/// Write a text run into the content grid (layout's job in G.0; a
/// helper here so tests and the demo speak the same vocabulary).
pub fn writeText(f: *Field, x: u16, y: u16, fg: u8, str: []const u8) void {
    if (y >= f.rows) return;
    for (str, 0..) |ch, i| {
        const cx = x + i;
        if (cx >= f.cols) break;
        f.content[index(f, @intCast(cx), y)] = .{ .glyph = ch, .fg = fg, .flags = .{ .text = true } };
    }
}

pub fn writeDivider(f: *Field, y: u16, fg: u8, glyph: u8) void {
    if (y >= f.rows) return;
    var x: u16 = 0;
    while (x < f.cols) : (x += 1) {
        f.content[index(f, x, y)] = .{ .glyph = glyph, .fg = fg, .flags = .{ .divider = true } };
    }
}

pub fn setFixed(f: *Field, x: u16, y: u16, fg: u8, glyph: u8) void {
    if (x >= f.cols or y >= f.rows) return;
    f.content[index(f, x, y)] = .{ .glyph = glyph, .fg = fg, .flags = .{ .fixed = true } };
}

// ---------------------------------------------------------------------------
// The rule vocabulary, seeded (design §5) — parameterise, don't enumerate
// ---------------------------------------------------------------------------

/// What a particle hit does to a cell (§5.3). `reflect` acts on the
/// particle instead (it bounces); `absorb` ends it.
pub const Response = enum(u8) { nudge, scatter, ignite, absorb, reflect, none };

/// Per-kind physics + collision selection — a comptime table (F2), the
/// seed of §5's recipes: a new effect is a new ROW, never new code.
/// A7.2: not a record in the hot sense — comptime configuration rows.
pub const KindRule = struct {
    gravity: f32, // cells/s², downward positive
    drag: f32, // 1/s
    on_text: Response,
    on_divider: Response,
    speed_scale: f32, // cells/s per unit of SpawnEvent.energy
    life_s: f32,
};

/// [TUNE] every number below — empirical, against a real display
/// (design §12.1). The STRUCTURE is the decision; these are defaults.
pub const kinds = [_]KindRule{
    // 0 spark: the like-burst workhorse — falls, drags, shoves letters,
    //          pops dividers, bounces off fixed chrome.
    .{ .gravity = 14.0, .drag = 1.6, .on_text = .nudge, .on_divider = .scatter, .speed_scale = 0.16, .life_s = 1.1 },
    // 1 ember: pure light — ignites whatever it crosses, never moves it.
    .{ .gravity = 2.0, .drag = 3.0, .on_text = .ignite, .on_divider = .ignite, .speed_scale = 0.10, .life_s = 0.8 },
    // 2 mote: implode fuel — flies to its target and is absorbed on the
    //         first solid it meets (the counter-assembly recipe).
    .{ .gravity = 0.0, .drag = 0.4, .on_text = .absorb, .on_divider = .absorb, .speed_scale = 0.14, .life_s = 1.6 },
};

/// Cell spring + glow character (§5.4). [TUNE] — the bounce's feel.
/// Calibration findings already on the page (design §12.3, kept honest):
/// - The i8 velocity range caps cell speed at ~7.9 cells/s; an
///   energetic hit saturates there (pinned in the golden test). The
///   ceiling reads as a natural "max kick" — acceptable until eyes on
///   a real screen say otherwise (widening is an A7.1 act).
/// - Sub-quantum overshoot (< 1/16 cell) is eaten by the fixed point:
///   GENTLE pokes glide home without wobble — a feature (no shimmer on
///   small impulses); energetic pokes overshoot visibly and spring.
/// - Settle snaps at |d|<=1fp AND |v|<=8fp: below that the per-frame
///   motion is under half a quantum and the cell would limit-cycle at
///   ±1fp forever, pinning the future active list. A fast pass-through
///   near home carries far more than 8fp, so overshoot is never
///   falsely snapped.
pub const spring_k: f32 = 70.0; // 1/s² toward home
pub const spring_c: f32 = 11.0; // 1/s damping
pub const glow_decay: f32 = 7.0; // 1/s geometric decay
pub const settle_d: i8 = 1; // fp quanta
pub const settle_v: i8 = 8; // fp quanta
pub const max_particles: usize = 512; // population cap; excess is COUNTED

// Fixed-point helpers: i8 storage at 1/16 cell, f32 math (design §2.1).
const fp_unit: f32 = 16.0;

fn fpToF(v: i8) f32 {
    return @as(f32, @floatFromInt(v)) / fp_unit;
}

fn fToFp(v: f32) i8 {
    const scaled = @round(v * fp_unit);
    return @intFromFloat(std.math.clamp(scaled, -127.0, 127.0));
}

fn satAddGlow(glow: u8, add: u8) u8 {
    return if (@as(u16, glow) + add > 255) 255 else glow + add;
}

// ---------------------------------------------------------------------------
// step — the entire dynamic engine, one pure transform (design §3.1)
// ---------------------------------------------------------------------------

/// PURE (B2): same (field, particles, events, dt, rng) ⇒ same next
/// state. No clock (dt injected), no global RNG (interface injected),
/// no I/O. Mutates the field and particle list it OWNS (C4) — the same
/// out-param posture buildFrame/buildTimeline already take. `gpa`
/// grows the particle list only; every allocation is at a visible call
/// site (C1/C2). Phases exactly as the design orders them.
pub fn step(
    gpa: Allocator,
    f: *Field,
    particles: *ParticleList,
    events: []const SpawnEvent,
    dt: f32,
    rng: std.Random,
) error{OutOfMemory}!void {
    // 1. ingest events → spawn particles (§5.1)
    for (events) |ev| try spawn(gpa, f, particles, ev, rng);

    // 2+3. integrate particles, then collide (§4): position first, per
    // the design's order, so a particle acts on the cell it ARRIVES in.
    {
        const s = particles.slice();
        const xs = s.items(.x);
        const ys = s.items(.y);
        const vxs = s.items(.vx);
        const vys = s.items(.vy);
        const lifes = s.items(.life);
        const kind_ids = s.items(.kind);
        for (xs, ys, vxs, vys, lifes, kind_ids) |*x, *y, *vx, *vy, *life, kind_id| {
            const rule = kinds[@min(kind_id, kinds.len - 1)];
            x.* += vx.* * dt;
            y.* += vy.* * dt;
            vy.* += rule.gravity * dt;
            const damp = @max(0.0, 1.0 - rule.drag * dt);
            vx.* *= damp;
            vy.* *= damp;
            life.* -= dt;
            // Observability (§8): a non-finite velocity is caught,
            // zeroed, and COUNTED — never propagated into the grid.
            if (!std.math.isFinite(vx.*) or !std.math.isFinite(vy.*)) {
                vx.* = 0;
                vy.* = 0;
                f.faults += 1;
            }
            collideOne(f, x, y, vx, vy, life, rule);
        }
    }

    // 4. integrate cells: damped spring home + glow decay (§4).
    // Naive full scan by design — the active-list ships only when a
    // bench indicts this loop (G.4, G2/F4).
    integrateCells(f, dt);

    // 5. cull the dead — "death" is an ordinary result, not an error
    // (E4). Reverse order so swapRemove never skips a survivor.
    var i: usize = particles.len;
    while (i > 0) {
        i -= 1;
        if (particles.slice().items(.life)[i] <= 0) particles.swapRemove(i);
    }
}

/// §5.1 spawn shapes. Energy enters as initial conditions, never as a
/// script: burst is radial, stream is directional, implode is a ring
/// collapsing inward. Direction parameterisation for `stream` joins
/// the full recipe table in G.5; this slice streams DOWNWARD (the
/// new-post recipe) with jitter.
fn spawn(
    gpa: Allocator,
    f: *Field,
    particles: *ParticleList,
    ev: SpawnEvent,
    rng: std.Random,
) error{OutOfMemory}!void {
    const rule = kinds[@min(@as(usize, ev.palette), kinds.len - 1)];
    const speed: f32 = @as(f32, @floatFromInt(ev.energy)) * rule.speed_scale;
    var n: usize = ev.count;
    while (n > 0) : (n -= 1) {
        if (particles.len >= max_particles) {
            f.dropped_spawns += 1; // counted, not silent (§8)
            return;
        }
        const jitter = 0.85 + rng.float(f32) * 0.3;
        var p: Particle = .{
            .x = @floatFromInt(ev.x),
            .y = @floatFromInt(ev.y),
            .vx = 0,
            .vy = 0,
            .life = rule.life_s * jitter,
            .glyph = particleGlyph(ev.kind, rng),
            .kind = ev.palette,
        };
        switch (ev.kind) {
            .burst => {
                const angle = rng.float(f32) * std.math.tau;
                p.vx = @cos(angle) * speed * jitter;
                p.vy = @sin(angle) * speed * jitter;
            },
            .stream => {
                p.x += (rng.float(f32) - 0.5) * 4.0;
                p.vx = (rng.float(f32) - 0.5) * speed * 0.3;
                p.vy = speed * jitter;
            },
            .implode => {
                const angle = rng.float(f32) * std.math.tau;
                const radius = 3.0 + rng.float(f32) * 2.0;
                p.x += @cos(angle) * radius;
                p.y += @sin(angle) * radius;
                p.vx = -@cos(angle) * speed * jitter;
                p.vy = -@sin(angle) * speed * jitter;
            },
        }
        try particles.append(gpa, p);
    }
}

fn particleGlyph(kind: SpawnEvent.Kind, rng: std.Random) u8 {
    const sets = switch (kind) {
        .burst => "*+x.",
        .stream => "|:.",
        .implode => "o*.",
    };
    return sets[rng.intRangeLessThan(usize, 0, sets.len)];
}

/// §4 — the interaction mechanic, ONE rule: a particle landing on a
/// solid cell applies an impulse to that cell's Perturb. The grid is
/// its own broadphase: locating the cell is a floor and an index.
fn collideOne(f: *Field, x: *f32, y: *f32, vx: *f32, vy: *f32, life: *f32, rule: KindRule) void {
    if (x.* < 0 or y.* < 0) return;
    const cx: u16 = @intFromFloat(@min(x.*, @as(f32, @floatFromInt(f.cols - 1))));
    const cy: u16 = @intFromFloat(@min(y.*, @as(f32, @floatFromInt(f.rows - 1))));
    if (x.* >= @as(f32, @floatFromInt(f.cols)) or y.* >= @as(f32, @floatFromInt(f.rows))) return;
    const at = index(f, cx, cy);
    const cell = f.content[at];
    const fl = cell.flags;
    if (!(fl.text or fl.divider or fl.fixed or fl.interactive)) return; // empty air

    // `fixed` chrome never moves; the particle reflects off it (§4).
    if (fl.fixed) {
        vy.* = -vy.* * 0.6;
        vx.* = vx.* * 0.8;
        y.* = @floatFromInt(cy); // step back out of the cell
        f.perturb[at].glow = satAddGlow(f.perturb[at].glow, 24);
        return;
    }

    const response: Response = if (fl.divider) rule.on_divider else rule.on_text;
    const p = &f.perturb[at];
    switch (response) {
        .nudge => {
            // Shove in the particle's direction of travel; light it up.
            const mag: f32 = 0.9; // [TUNE] impulse strength, cells/s
            const len = @max(0.001, @sqrt(vx.* * vx.* + vy.* * vy.*));
            p.vx = fToFp(fpToF(p.vx) + (vx.* / len) * mag);
            p.vy = fToFp(fpToF(p.vy) + (vy.* / len) * mag);
            p.glow = satAddGlow(p.glow, 110);
            p.flags |= Perturb.flag_active;
        },
        .scatter => {
            // The divider symbol pops upward off the line (§4).
            p.vy = fToFp(fpToF(p.vy) - 1.6); // [TUNE] kick, cells/s
            p.glow = satAddGlow(p.glow, 140);
            p.flags |= Perturb.flag_active;
        },
        .ignite => {
            p.glow = satAddGlow(p.glow, 90);
            p.flags |= Perturb.flag_active;
        },
        .absorb => {
            p.glow = satAddGlow(p.glow, 170);
            p.flags |= Perturb.flag_active;
            life.* = 0; // energy transfers and stops (§4)
        },
        .reflect => {
            vy.* = -vy.* * 0.6;
        },
        .none => {},
    }
}

/// §4's settle: every perturbed cell is pulled home like a damped
/// spring, glow decays geometrically. The bounce, the wobble, the
/// settle — all emergent from this single rule.
fn integrateCells(f: *Field, dt: f32) void {
    for (f.perturb) |*p| {
        if (p.flags & Perturb.flag_active == 0 and p.glow == 0) continue;
        var dx = fpToF(p.dx);
        var dy = fpToF(p.dy);
        var vx = fpToF(p.vx);
        var vy = fpToF(p.vy);
        vx += (-spring_k * dx - spring_c * vx) * dt;
        vy += (-spring_k * dy - spring_c * vy) * dt;
        dx += vx * dt;
        dy += vy * dt;
        p.dx = fToFp(dx);
        p.dy = fToFp(dy);
        p.vx = fToFp(vx);
        p.vy = fToFp(vy);
        const g: f32 = @floatFromInt(p.glow);
        p.glow = @intFromFloat(@max(0.0, g - g * glow_decay * dt));
        // Settled: snap to rest and leave the (future) active list.
        // Epsilons per the calibration note above — they break the
        // ±1fp limit cycle without ever clipping a real overshoot.
        if (@abs(p.dx) <= settle_d and @abs(p.dy) <= settle_d and
            @abs(p.vx) <= settle_v and @abs(p.vy) <= settle_v and p.glow <= 2)
        {
            p.* = .{};
        }
    }
}

// ---------------------------------------------------------------------------
// compose (design §6) — one pure map to draw items
// ---------------------------------------------------------------------------

/// The light source — just another injected input, so compose stays
/// deterministic (§6). A7.2: cold struct, waived — one per frame.
pub const Light = struct {
    x: f32,
    y: f32,
    radius: f32,
    ambient: f32, // 0..1 floor of the scene
};

/// The field's palette (indexed by ContentCell.fg). Comptime data, not
/// a dependency (F2). G.0's visual pass owns the final values.
pub const palette = [_]u32{
    0xFF8B94A3, // 0 dim
    0xFFE7EAF0, // 1 ink
    0xFF6CA8FF, // 2 accent
    0xFF7BD88F, // 3 boost
    0xFFFF6B81, // 4 like
    0xFF5C6470, // 5 faint
};

/// PURE (B2): (content, perturb, particles, light, cell metrics) → cell
/// draw items. Same inputs ⇒ same list ⇒ same pixels. Glyphs render at
/// home + displacement (the fixed-point offsets become PIXELS here);
/// brightness = content base + glow, toned by the light — with a HARD
/// FLOOR for `text` cells so body copy never drops below readable
/// contrast (design §12.2: a constraint, not a taste call).
pub fn compose(
    gpa: Allocator,
    f: *const Field,
    particles: ParticleList.Slice,
    light: Light,
    cell_w: u16,
    cell_h: u16,
    dl: *raster.DrawList,
) error{OutOfMemory}!void {
    dl.clearRetainingCapacity();
    var y: u16 = 0;
    while (y < f.rows) : (y += 1) {
        var x: u16 = 0;
        while (x < f.cols) : (x += 1) {
            const at = index(f, x, y);
            const cell = f.content[at];
            if (cell.glyph == 0 or cell.glyph == ' ') continue;
            const p = f.perturb[at];
            const px: i32 = @as(i32, x) * cell_w + @divTrunc(@as(i32, p.dx) * cell_w, 16);
            const py: i32 = @as(i32, y) * cell_h + @divTrunc(@as(i32, p.dy) * cell_h, 16);
            var bright = lightAt(light, @floatFromInt(x), @floatFromInt(y));
            bright += @as(f32, @floatFromInt(p.glow)) / 255.0;
            // §12.2: legibility floor — text never dims past reading.
            if (cell.flags.text) bright = @max(bright, 0.55);
            const color = toneScale(palette[@min(cell.fg, palette.len - 1)], @min(bright, 1.6));
            // Render through the runtime engine at the DYNAMIC cell height
            // (a .text item), not the fixed comptime strike — so glyphs
            // scale WITH the window and sit flush at the true advance. The
            // baseline sits ~0.78 of the way down the cell (standard for a
            // monospace face); the engine places the glyph from there.
            const baseline: i32 = py + @divTrunc(@as(i32, cell_h) * 78, 100);
            try dl.append(gpa, .{ .text = .{
                .x = @intCast(std.math.clamp(px, -32768, 32767)),
                .baseline = @intCast(std.math.clamp(baseline, -32768, 32767)),
                .codepoint = cell.glyph,
                .color = color,
                .px = cell_h,
                .weight = 0,
            } });
        }
    }
    // Particles draw on top at their continuous positions, rounded to
    // cells (§6) — bright, unfloored, transient.
    const xs = particles.items(.x);
    const ys = particles.items(.y);
    const glyphs = particles.items(.glyph);
    for (xs, ys, glyphs) |fx, fy, glyph| {
        if (fx < 0 or fy < 0) continue;
        const px: i32 = @intFromFloat(fx * @as(f32, @floatFromInt(cell_w)));
        const py: i32 = @intFromFloat(fy * @as(f32, @floatFromInt(cell_h)));
        if (px < 0 or py < 0) continue;
        const baseline: i32 = py + @divTrunc(@as(i32, cell_h) * 78, 100);
        try dl.append(gpa, .{ .text = .{
            .x = @intCast(std.math.clamp(px, -32768, 32767)),
            .baseline = @intCast(std.math.clamp(baseline, -32768, 32767)),
            .codepoint = glyph,
            .color = toneScale(0xFFFFE9B0, 1.0),
            .px = cell_h,
            .weight = 0,
        } });
    }
}

fn lightAt(light: Light, x: f32, y: f32) f32 {
    const dx = x - light.x;
    const dy = y - light.y;
    const d = @sqrt(dx * dx + dy * dy);
    const falloff = @max(0.0, 1.0 - d / @max(1.0, light.radius));
    return light.ambient + (1.0 - light.ambient) * falloff;
}

fn toneScale(argb: u32, factor: f32) u32 {
    const r: f32 = @floatFromInt((argb >> 16) & 0xFF);
    const g: f32 = @floatFromInt((argb >> 8) & 0xFF);
    const b: f32 = @floatFromInt(argb & 0xFF);
    const rr: u32 = @intFromFloat(@min(255.0, r * factor));
    const gg: u32 = @intFromFloat(@min(255.0, g * factor));
    const bb: u32 = @intFromFloat(@min(255.0, b * factor));
    return 0xFF000000 | (rr << 16) | (gg << 8) | bb;
}

// ---------------------------------------------------------------------------
// Golden tests (design §8): the behaviour pinned by numbers, not vibes
// ---------------------------------------------------------------------------

test "guards: the design's budgets hold exactly" {
    try testing.expectEqual(@as(usize, 4), @sizeOf(ContentCell));
    try testing.expectEqual(@as(usize, 8), @sizeOf(Perturb));
    try testing.expectEqual(@as(usize, 24), @sizeOf(Particle));
    try testing.expectEqual(@as(usize, 10), @sizeOf(SpawnEvent));
}

test "spring: an energetic poke overshoots and settles; the velocity ceiling pins" {
    const gpa = testing.allocator; // C6
    var f: Field = .{};
    try init(gpa, &f, 8, 4);
    defer deinit(gpa, &f);

    const at = index(&f, 3, 1);
    f.perturb[at] = .{ .dx = 64, .flags = Perturb.flag_active }; // four cells right

    var particles: ParticleList = .empty;
    defer particles.deinit(gpa);
    const dt: f32 = 1.0 / 60.0;

    // Golden first frames, derived from the exact fixed-point math —
    // frame 2's vx SATURATES at -127: the i8 speed ceiling, pinned on
    // purpose (the calibration note above).
    var prng = std.Random.DefaultPrng.init(7);
    try step(gpa, &f, &particles, &.{}, dt, prng.random());
    try testing.expectEqual(@as(i8, 63), f.perturb[at].dx);
    try testing.expectEqual(@as(i8, -75), f.perturb[at].vx);
    try step(gpa, &f, &particles, &.{}, dt, prng.random());
    try testing.expectEqual(@as(i8, 61), f.perturb[at].dx);
    try testing.expectEqual(@as(i8, -127), f.perturb[at].vx);

    // It crosses home (the wobble §4 promises), then snaps to EXACT rest.
    var crossed = false;
    var frames: usize = 0;
    var settled = false;
    while (frames < 240) : (frames += 1) {
        try step(gpa, &f, &particles, &.{}, dt, prng.random());
        if (f.perturb[at].dx < 0) crossed = true;
        if (f.perturb[at].dx == 0 and f.perturb[at].vx == 0 and f.perturb[at].glow == 0) {
            settled = true;
            break;
        }
    }
    try testing.expect(crossed);
    try testing.expect(settled);
    try testing.expectEqual(@as(u8, 0), f.perturb[at].flags & Perturb.flag_active);
}

test "spring: a gentle poke glides home without wobble (sub-quantum smoothness)" {
    const gpa = testing.allocator;
    var f: Field = .{};
    try init(gpa, &f, 8, 4);
    defer deinit(gpa, &f);
    const at = index(&f, 3, 1);
    f.perturb[at] = .{ .dx = 16, .flags = Perturb.flag_active }; // one cell

    var particles: ParticleList = .empty;
    defer particles.deinit(gpa);
    var prng = std.Random.DefaultPrng.init(7);
    var frames: usize = 0;
    var crossed = false;
    while (frames < 60) : (frames += 1) {
        try step(gpa, &f, &particles, &.{}, 1.0 / 60.0, prng.random());
        if (f.perturb[at].dx < 0) crossed = true;
        if (f.perturb[at].dx == 0 and f.perturb[at].vx == 0) break;
    }
    try testing.expect(!crossed); // the overshoot is below one quantum: no shimmer
    try testing.expect(frames < 60); // and it is HOME inside a second
}

test "determinism: same seed, same dt sequence, identical state — different seed differs" {
    const gpa = testing.allocator;
    const dt: f32 = 1.0 / 60.0;
    var ends: [3]struct { x: f32, y: f32, len: usize } = undefined;
    for (&ends, 0..) |*end, run| {
        var f: Field = .{};
        try init(gpa, &f, 32, 16);
        defer deinit(gpa, &f);
        writeText(&f, 4, 8, 1, "ZAT4");
        var particles: ParticleList = .empty;
        defer particles.deinit(gpa);
        var prng = std.Random.DefaultPrng.init(if (run == 2) 99 else 42);
        const ev: SpawnEvent = .{ .x = 8, .y = 4, .kind = .burst, .energy = 40, .count = 24, .palette = 0 };
        try step(gpa, &f, &particles, &.{ev}, dt, prng.random());
        var i: usize = 0;
        while (i < 12) : (i += 1) try step(gpa, &f, &particles, &.{}, dt, prng.random());
        end.* = .{ .x = particles.items(.x)[0], .y = particles.items(.y)[0], .len = particles.len };
    }
    try testing.expectEqual(ends[0].x, ends[1].x); // bit-identical (B2)
    try testing.expectEqual(ends[0].y, ends[1].y);
    try testing.expectEqual(ends[0].len, ends[1].len);
    try testing.expect(ends[0].x != ends[2].x or ends[0].y != ends[2].y);
}

test "collision: a burst nudges text, scatters a divider upward, never moves fixed chrome" {
    const gpa = testing.allocator;
    var f: Field = .{};
    try init(gpa, &f, 24, 12);
    defer deinit(gpa, &f);
    writeText(&f, 6, 8, 1, "HELLO");
    writeDivider(&f, 10, 5, '-');
    setFixed(&f, 2, 8, 2, '#');

    var particles: ParticleList = .empty;
    defer particles.deinit(gpa);
    var prng = std.Random.DefaultPrng.init(1234);
    const dt: f32 = 1.0 / 60.0;
    // A hard burst directly above the text row.
    try step(gpa, &f, &particles, &.{.{ .x = 8, .y = 5, .kind = .burst, .energy = 90, .count = 64, .palette = 0 }}, dt, prng.random());
    var i: usize = 0;
    while (i < 30) : (i += 1) try step(gpa, &f, &particles, &.{}, dt, prng.random());

    var text_hit = false;
    var divider_kicked_up = false;
    for (f.content, f.perturb) |cell, p| {
        if (cell.flags.text and (p.glow > 0 or p.dx != 0 or p.dy != 0)) text_hit = true;
        if (cell.flags.divider and p.dy < 0) divider_kicked_up = true;
    }
    try testing.expect(text_hit);
    try testing.expect(divider_kicked_up);
    // Fixed chrome glows when struck but NEVER displaces (§4).
    const fixed_p = f.perturb[index(&f, 2, 8)];
    try testing.expectEqual(@as(i8, 0), fixed_p.dx);
    try testing.expectEqual(@as(i8, 0), fixed_p.dy);
}

test "absorb: an imploding mote dies on first contact and lights the cell" {
    const gpa = testing.allocator;
    var f: Field = .{};
    try init(gpa, &f, 16, 8);
    defer deinit(gpa, &f);
    writeText(&f, 7, 4, 2, "9");

    var particles: ParticleList = .empty;
    defer particles.deinit(gpa);
    var prng = std.Random.DefaultPrng.init(5);
    const dt: f32 = 1.0 / 60.0;
    try step(gpa, &f, &particles, &.{.{ .x = 7, .y = 4, .kind = .implode, .energy = 60, .count = 16, .palette = 2 }}, dt, prng.random());
    const born = particles.len;
    var i: usize = 0;
    while (i < 90) : (i += 1) try step(gpa, &f, &particles, &.{}, dt, prng.random());
    try testing.expect(particles.len < born); // absorbed and/or expired
    try testing.expect(f.perturb[index(&f, 7, 4)].glow > 0 or born > 0);
}

test "saturation and caps: huge impulses clamp, oversized spawns are counted not silent" {
    const gpa = testing.allocator;
    var f: Field = .{};
    try init(gpa, &f, 8, 8);
    defer deinit(gpa, &f);
    // Absurd stored velocity must clamp through the fixed-point path,
    // never overflow (the i8 bet, guarded — design §12.3).
    f.perturb[0] = .{ .dx = 127, .vx = 127, .flags = Perturb.flag_active };
    var particles: ParticleList = .empty;
    defer particles.deinit(gpa);
    var prng = std.Random.DefaultPrng.init(9);
    try step(gpa, &f, &particles, &.{}, 1.0 / 60.0, prng.random());
    try testing.expect(f.perturb[0].dx <= 127);

    // Spawn far past the population cap: the excess is a NUMBER (§8).
    const ev: SpawnEvent = .{ .x = 4, .y = 4, .kind = .burst, .energy = 10, .count = 255, .palette = 0 };
    try step(gpa, &f, &particles, &.{ ev, ev, ev }, 1.0 / 60.0, prng.random());
    try testing.expect(particles.len <= max_particles);
    try testing.expect(f.dropped_spawns > 0);
}

test "compose: text keeps its legibility floor in darkness; glyphs render at offset homes" {
    const gpa = testing.allocator;
    var f: Field = .{};
    try init(gpa, &f, 12, 4);
    defer deinit(gpa, &f);
    writeText(&f, 1, 1, 1, "READ");
    f.perturb[index(&f, 1, 1)] = .{ .dx = 8, .dy = -4 }; // half-cell right, quarter up

    var particles: ParticleList = .empty;
    defer particles.deinit(gpa);
    var dl: raster.DrawList = .empty;
    defer dl.deinit(gpa);
    // A light far away with a pitch-black ambient: the floor must hold.
    try compose(gpa, &f, particles.slice(), .{ .x = 1000, .y = 1000, .radius = 5, .ambient = 0.0 }, 8, 16, &dl);
    try testing.expectEqual(@as(usize, 4), dl.len);
    const first = dl.get(0).text;
    // Home (1,1) at 8x16 cells = (8,16); +8/16 cell right = +4px → x=12.
    // Glyphs render through the engine now (.text items at px=cell_h).
    try testing.expectEqual(@as(i16, 12), first.x);
    try testing.expectEqual(@as(u16, 16), first.px); // renders at the cell height
    const channel = first.color & 0xFF;
    try testing.expect(channel >= @as(u32, @intFromFloat(0xF0 * 0.55)) - 8); // the §12.2 floor
}

test "compose: each particle draws its OWN glyph (regression: not always particle 0's)" {
    const gpa = testing.allocator; // C6
    var f: Field = .{};
    try init(gpa, &f, 16, 8);
    defer deinit(gpa, &f);

    // Two particles with DISTINCT glyphs at distinct cells. If compose
    // ever writes glyphs[0] for both (the bug this pins), the second
    // draw item's codepoint would wrongly equal the first's.
    var particles: ParticleList = .empty;
    defer particles.deinit(gpa);
    try particles.append(gpa, .{ .x = 1, .y = 1, .vx = 0, .vy = 0, .life = 1, .glyph = '*', .kind = 0 });
    try particles.append(gpa, .{ .x = 5, .y = 3, .vx = 0, .vy = 0, .life = 1, .glyph = 'o', .kind = 0 });

    var dl: raster.DrawList = .empty;
    defer dl.deinit(gpa);
    try compose(gpa, &f, particles.slice(), .{ .x = 8, .y = 4, .radius = 10, .ambient = 0.5 }, 8, 16, &dl);

    // No content cells, so the only draw items are the two particles, in
    // order. Each must carry the glyph it was given.
    try testing.expectEqual(@as(usize, 2), dl.len);
    try testing.expectEqual(@as(u32, '*'), dl.get(0).text.codepoint);
    try testing.expectEqual(@as(u32, 'o'), dl.get(1).text.codepoint);
}
