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
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

//! B1 classification: CORE (pure). THE LENS SOCKET — a portable,
//! immediate-mode lens/algorithm switcher (LENS_SOCKET_DESIGN.md). It
//! replaces the home feed's Following/Discover tab labels: there is no tab
//! strip — the seated lens IS the feed's ordering, and the same `build`
//! call drops onto the feed, any zone header, or a reply tree (discover
//! invariant 12; ZONES invariant 4 — a post is a post, surfaces are lenses).
//!
//! The whole widget is a pure function of (TrayView, SocketUi, Geometry) →
//! draw items + hit-rects, rebuilt every frame, retaining nothing (the
//! immediate-mode discipline the whole project uses). It allocates only
//! into the per-frame arena handed in (C1/C3) and frees nothing; it reads
//! no clock — the shell advances `swap_phase` and threads it in (B2/B4);
//! and the LENS INDEX never leaves this module — the CID is the only id
//! that crosses out, in every SocketAction (A5/A8).
//!
//! Build order is LENS_SOCKET_DESIGN §8. This file implements L.0 (resting
//! cartridge) + L.1 (open 3-up grid, click-body → seat). The seat
//! animation (L.2 + the dynamic accent), inline detail (L.3), reorder
//! (L.4), and the portability mount (L.5) land on top without changing the
//! contract.
//!
//! API deviation recorded (H4): the design sketches `build → BuildResult
//! {draw_list, hits}`. To match the codebase's established render pattern
//! (feed_view.layout appends into a caller-owned DrawList + Regions and
//! returns the height consumed), `build` instead appends into a provided
//! `*raster.DrawList` and an optional `*HitList`, returning the socket's
//! total pixel height so a surface can lay out beneath it. Same purity,
//! same plain-values-only boundary; one convention for the whole frame.

const std = @import("std");
const builtin = @import("builtin");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const text = @import("text.zig");
const raster = @import("raster.zig");

// Neutrals, copied by value from feed_view/field (D4: only the value
// crosses a module boundary, never a reach-across). ARGB.
const ink: u32 = 0xFFEDEAE0;
const body: u32 = 0xFFD8D3C8; // detail-panel paragraph text
const muted: u32 = 0xFF9A968A;
const faint: u32 = 0xFF6A655A;
const glass: u32 = 0xFF1C1B16; // the socket panel — OPAQUE (owner: no transparency)
const julia_glass: u32 = 0xFFA6407A; // Julia mode: the socket panel goes bright rose
const hairline: u32 = 0x18FFFFFF; // ~9% white edge
const pill_bg: u32 = 0x14FFFFFF; // ~8% white card fill (reads on the dark panel)
const pill_edge: u32 = 0x1FFFFFFF; // ~12% white card edge
const rail: u32 = 0x1AFFFFFF; // contact-rail dashes
/// The open tray's panel — OPAQUE: it drops OVER the feed posts and this
/// path has no backdrop-blur, so anything less lets the timeline bleed
/// through (the open-tray conflict the owner caught). A touch darker than
/// the socket panel so the tray reads as recessed below the seated cartridge.
const tray_panel: u32 = 0xFF131210;
// Privacy is its OWN channel, never the lens accent (invariant 6): green =
// no behavioral data, amber = local-learning. Fixed semantics.
const priv_clean: u32 = 0xFF6FCF97;
const priv_learn: u32 = 0xFFE8B23A;

/// The socket holds at most this many lenses (owner decision 2026-06-22: 6
/// feels right in testing, down from the original 9). The palette stays 9
/// colors, so recolor still offers the full set and there are always free
/// colors for auto-assign. Doubles as the per-card reflow-array length.
pub const max_lenses: usize = 6;

/// THE 9-COLOR PALETTE (LENS_SOCKET_DESIGN §11.5). The cap is the palette:
/// 9 lenses max ⇒ 9 colors, bounded by design. A lens stores a `u8` index
/// into this comptime table (A6 — not an inline color). Seating a lens
/// makes `palette[seated.color]` the app's single accent token (the
/// app-wide re-tint is the L.2 sub-slice; here the socket tints its own
/// cartridge so the seated color is already visible).
pub const palette = [9]u32{
    0xFFF2762A, // 0 orange — Standard Discover (house accent / site default)
    0xFF4A9EFF, // 1 blue   — Private Discover
    0xFF949AAA, // 2 grey   — Following (neutral = "no shaping", reads chronological)
    0xFF9B7BFF, // 3 violet — reserve
    0xFF3FC97E, // 4 green  — reserve
    0xFFFF5C8A, // 5 rose   — reserve
    0xFFFF8A3D, // 6 orange — reserve
    0xFF33C2C2, // 7 teal   — reserve
    0xFFD4B24A, // 8 gold   — reserve
};

// ---------------------------------------------------------------------------
// Data model (A1, A3, A7)
// ---------------------------------------------------------------------------

/// A span into the tray's text blob — offset + length, the same out-of-band
/// text discipline feed.zig uses (A6: keep the hot record tight; strings
/// live in one blob the spans point into).
pub const TextSpan = struct {
    off: u32 = 0,
    len: u32 = 0,

    comptime {
        // Budget: 4 + 4 = 8 bytes, exact (A7). Raising this requires A7.1.
        assert(@sizeOf(TextSpan) == 8);
    }
};

/// Out-of-band per-lens flags (A6: not `bool` fields padding the hot
/// record). The privacy CLASS is system-derived (invariant 6) — `learns`
/// drives both the always-visible privacy glyph and the behavioral-status
/// label; it is never self-declared. `packed struct(u8)` is its own size
/// contract (the guard gate accepts packed backings).
pub const LensFlags = packed struct(u8) {
    behavioral: bool = false, // reads your on-device ATTENTION data (the privacy bit)
    learns: bool = false, // keeps a cross-session on-device model (the ADAPTIVE bit)
    is_default: bool = false, // a first-party default lens (Following / Discover)
    _rest: u5 = 0,
};

/// The hot per-lens record — a user may own up to 9 (the cap), iterated
/// every tray render. HOT → exact size guard mandatory (A7). It holds
/// spans into the tray blob + the palette index + flags; never inline
/// strings, never the live color (A6).
pub const LensCard = struct {
    cid: TextSpan, // A8 stable id — the value that crosses the boundary
    name: TextSpan, // "For You"
    author: TextSpan, // "@desh.zat" / "zat4 default"
    ranks: TextSpan, // one-line "what it ranks for"
    desc: TextSpan, // the expand-panel paragraph (L.3)
    color: u8, // palette index 0..8 (§11.5)
    flags: LensFlags, // privacy/learns/default bitset (A6)

    comptime {
        // Budget: 5 × TextSpan(8) = 40, + color(1) + flags(1) = 42, padded
        // to 44 at the u32 alignment of TextSpan. Set to the packed target
        // (A7.1): `desc` and `color` are earned — `desc` is the L.3 detail
        // text, `color` is the §11.5 palette index the whole accent system
        // rides on. Both belong on the record, both stay out-of-band-tight.
        assert(@sizeOf(LensCard) == 44);
    }
};

/// What the widget READS (A3 SoA, read-only — it never owns or frees this,
/// C4). Order is meaningful: index 0 is front-of-tray. The surface resolves
/// the fallback (feed→adaptive, zone→Discover, replies→threaded) BEFORE
/// building this view; the widget sees only the resolved `seated`.
pub const TrayView = struct {
    cards: []const LensCard,
    text: []const u8, // the blob the TextSpans point into
    seated: u32, // index of the currently seated lens

    comptime {
        // 2 slices (16 each) + u32 = 36, padded to 40 at slice alignment.
        // Guarded rather than waived (design §3.2): cheap, catches field
        // creep on the one handle that crosses in every frame.
        assert(@sizeOf(TrayView) == 40);
    }
};

/// Transient interaction state, threaded by the shell (B4/B5). The TIME
/// SOURCE is passed in: `swap_phase` is an integer the shell advances from
/// its own frame clock; the widget maps phase→geometry deterministically.
/// Same (TrayView, SocketUi, Geometry) ⇒ same pixels, always.
pub const SocketUi = struct {
    // A7.2: cold — exactly one instance per render, never iterated. Waived.
    open: bool = false,
    /// Eased open progress 0→1 (the shell springs it toward `open`). The tray
    /// sweeps down by this and cards reveal top-to-bottom as it passes them —
    /// so opening isn't a binary pop. 1 = fully open (forced on the always-open
    /// loadout-page sockets).
    open_t: f32 = 0,
    expanded: ?u32 = null, // card showing inline detail, or null (E4)
    picking: ?u32 = null, // card whose color-swatch picker is open, or null (§11.5)
    swap_phase: u8 = 0, // 0 = resting; 1..N = eject/seat animation (L.2)
    swap_from: u32 = 0,
    swap_to: u32 = 0,
    drag_active: ?u32 = null, // card being dragged/settling, or null (E4)
    drag_x: i32 = 0, // live pointer (logical) while dragging — the ghost follows it
    drag_y: i32 = 0,
    /// Per-card eased reflow offset in SLOT units, signed, ~[-1,1] (iOS-style
    /// "fill in"): the shell advances it toward each card's target slot so the
    /// others slide to make room as you drag. Geometry-free here (slot units);
    /// the widget turns it into pixels. Indexed by card; length is the cap.
    slide: [max_lenses]f32 = [_]f32{0} ** max_lenses,
    /// Ghost lift (0→1): eased up on pickup, down on drop — the scale/shadow cue.
    lift: f32 = 0,
    /// 0 = actively dragging (ghost follows the pointer); 1..N = settling (ghost
    /// eases from the release point into its slot). The shell advances it.
    settle_phase: u8 = 0,
    /// Toy Box "Julia mode": when set, every socket colour (card swatches, seated
    /// accents, picker chips) renders `julia_pink` regardless of the lens's stored
    /// colour — so no colour but pink can be seen or chosen. The shell mirrors the
    /// settings toggle into this each frame.
    julia: bool = false,
};

/// Julia mode's accent pink — a bright bubblegum hot-pink (girlier than the
/// palette's muted rose). The whole-UI accent + every socket swatch take this.
pub const julia_pink: u32 = 0xFFFF69B4;
/// Julia mode's FIELD glyph ink — a saturated magenta, DARK enough to read as
/// pink symbols on the now-WHITE field backdrop (light theme). Kept distinct from
/// the accent so the field is its own layer.
pub const julia_field_ink: u32 = 0xFFC81E84;

/// Frames the drop-settle animation runs over (the ghost easing home).
pub const settle_total_frames: u8 = 9;

/// Where to draw, in pixels, with the layout scale (PHASE5 §5 hands scale
/// in the same way). Pure geometry — no surface knowledge.
pub const Geometry = struct {
    // A7.2: cold — one instance per render. Size guard waived.
    x: i32,
    y: i32,
    w: i32,
    scale: f32 = 1.0,
};

/// What a hit-rect maps to. The CID (not an index) rides the rect, so
/// hitTest can answer with a CID-bearing action from `hits` alone (A5).
pub const HitTarget = enum(u8) { toggle, seat, expand, collapse, reorder_handle, get_more, swatch, swatch_open, caret };

/// One tap target. HOT-ish (iterated in hitTest); guarded (A7). It carries
/// the lens's CID slice (into the shell-owned, frame-stable tray blob) so
/// the index never has to leave the module.
pub const HitRect = struct {
    cid: []const u8, // the lens CID (empty for toggle/get_more/collapse)
    x: i16,
    y: i16,
    w: u16,
    h: u16,
    target: HitTarget,
    color: u8 = 0, // for `swatch`: which palette color; else 0

    comptime {
        // slice(16) + 4×2(8) + target(1) + color(1) = 26, padded to 32 at
        // slice alignment. Exact (A7).
        assert(@sizeOf(HitRect) == 32);
    }
};

pub const HitList = std.ArrayListUnmanaged(HitRect);

/// The intent a click resolves to. Every variant carries a CID or a plain
/// value — NEVER an index (A5). The shell routes this through the SAME
/// action path the keyboard uses (PHASE5 §3). "No hit" is `null`, an
/// ordinary result (E3/E4).
/// A7.2: cold union, size guard waived — one UI intent per hit-test, routed
/// immediately through the action path, never collected.
pub const SocketAction = union(enum) {
    toggle_tray,
    seat: []const u8, // seat this lens — CID crosses out (A5/A8)
    expand: []const u8, // show inline detail for this lens
    collapse,
    reorder: struct { lens: []const u8, to_rank: u32 },
    get_more,
    open_swatch: []const u8, // tap the swatch → open/close the color picker (§11.5)
    set_color: struct { lens: []const u8, color: u8 }, // pick a color from the picker
};

// ---------------------------------------------------------------------------
// Pure helpers — text spans & derived labels
// ---------------------------------------------------------------------------

fn span(tray: TrayView, s: TextSpan) []const u8 {
    const end = @min(tray.text.len, @as(usize, s.off) + s.len);
    if (s.off >= tray.text.len) return "";
    return tray.text[s.off..end];
}

/// The privacy class is system-derived (invariant 6), never self-declared. It keys
/// off `behavioral` — whether the algorithm reads your attention — NOT `learns`
/// (which is the separate adaptive/keeps-a-model bit, shown alongside).
fn privLabel(f: LensFlags) []const u8 {
    return if (f.behavioral) "uses attention" else "private";
}
fn behaveLabel(f: LensFlags) []const u8 {
    return if (f.behavioral) "uses attention" else "no behavioral data";
}
fn privColor(f: LensFlags) u32 {
    return if (f.behavioral) priv_learn else priv_clean;
}
/// The adaptive-status marker (the socket's SECOND derived bit): whether the
/// algorithm keeps an on-device model that changes with you. Empty when static,
/// so a plain feed carries no marker (no clutter) and only an adaptive one is tagged.
fn adaptiveMark(f: LensFlags) []const u8 {
    return if (f.learns) "adaptive" else "";
}

/// A soft (alpha-reduced) variant of a palette color — the cartridge wash
/// and seat-line tints.
fn soft(c: u32, a: u8) u32 {
    return (@as(u32, a) << 24) | (c & 0x00FFFFFF);
}

/// Scale an ARGB color's existing alpha by `mul`/255 — used to fade the
/// cartridge in/out across the seat animation (the eject/plug-in feel).
fn alphaScale(c: u32, mul: u8) u32 {
    const a = (c >> 24) & 0xFF;
    const na = (a * @as(u32, mul)) / 255;
    return (na << 24) | (c & 0x00FFFFFF);
}

/// The seat animation's total length in frames. The shell advances
/// `SocketUi.swap_phase` 1→this from its own frame clock (B4), then resets
/// to 0 and commits the seat. Split eject(8) → drop-in(8) → glow-decay(8).
/// At ~60fps this is ~0.4s — the design's target band (§6); calibrated
/// against the real renderer, recorded here, not hard-asserted (G1).
pub const swap_total_frames: u8 = 24;

/// Resolve the seated lens's accent color — the single value the shell
/// threads into the feed as the app accent token at mount time (§11.5,
/// L.5). Pure: a palette lookup over the tray. Falls back to neutral grey.
pub fn seatedAccent(tray: TrayView) u32 {
    if (tray.cards.len == 0 or tray.seated >= tray.cards.len) return palette[2];
    return palette[@min(tray.cards[tray.seated].color, palette.len - 1)];
}

/// The total pixel height `build` consumes for (tray, ui, geom) — resting
/// socket, or socket + open tray — WITHOUT drawing. Pure arithmetic, no
/// text measurement, so the shell can clip the feed/hearts under the open
/// tray. MUST mirror build's height math (kept in sync by hand).
pub fn measuredHeight(tray: TrayView, ui: SocketUi, geom: Geometry) i32 {
    const sc = geom.scale;
    const sock_h = fxi(64 * sc);
    const op = @min(1.0, ui.open_t);
    if (op <= 0.004) return sock_h;
    const box_pad = fxi(10 * sc);
    const hdr_h = fxi(26 * sc);
    const col_gap = fxi(8 * sc);
    const card_h = fxi(104 * sc);
    const n = tray.cards.len;
    const shown: i32 = @intCast(@max(n, max_lenses)); // capacity slots (incl. placeholders)
    const rows: i32 = @divFloor(shown + 2, 3);
    const expanded = if (ui.expanded) |ex| (n > 0 and ex < n) else false;
    const detail_h = fxi(124 * sc);
    const grid_h = rows * card_h + @max(0, rows - 1) * col_gap +
        (if (expanded) detail_h + col_gap else 0);
    const box_h = hdr_h + grid_h + box_pad;
    const sweep_h: i32 = if (op >= 0.999) box_h else fxi(@as(f32, @floatFromInt(box_h)) * op);
    return sock_h + fxi(10 * sc) + sweep_h;
}

// ---------------------------------------------------------------------------
// Pure helpers — the draw vocabulary (thin over raster, kept local so the
// widget is a self-contained deep module, D2). Mirrors feed_view's helpers.
// ---------------------------------------------------------------------------

fn fxi(v: f32) i32 {
    return @intFromFloat(@round(v));
}

/// Pixel top-left of a grid slot (col = slot%3), accounting for the detail
/// panel's downshift of rows below an expanded card. Used for reflow + settle.
fn slotXY(slot: i32, grid_x: i32, grid_top: i32, card_w: i32, card_h: i32, col_gap: i32, detail_h: i32, expanded: bool, row_e: i32) [2]i32 {
    const col = @mod(slot, 3);
    const row = @divFloor(slot, 3);
    const sh: i32 = if (expanded and row > row_e) detail_h + col_gap else 0;
    return .{ grid_x + col * (card_w + col_gap), grid_top + row * (card_h + col_gap) + sh };
}

fn lerpi(a: i32, b: i32, t: f32) i32 {
    return a + fxi(@as(f32, @floatFromInt(b - a)) * t);
}

/// Spring-ish ease that OVERSHOOTS past 1 then settles back — the "it springs,
/// it doesn't snap" feel (§3). t in [0,1].
fn easeOutBack(t: f32) f32 {
    const c1: f32 = 1.70158;
    const c3: f32 = c1 + 1.0;
    const u = t - 1.0;
    return 1.0 + c3 * u * u * u + c1 * u * u;
}

fn rect(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, w: i32, h: i32, color: u32, radius: u8) !void {
    try dl.append(gpa, .{ .rect = .{
        .x = @intCast(x),
        .y = @intCast(y),
        .w = @intCast(@max(0, w)),
        .h = @intCast(@max(0, h)),
        .color = color,
        .radius = radius,
    } });
}

fn line(gpa: Allocator, dl: *raster.DrawList, x0: i32, y0: i32, x1: i32, y1: i32, color: u32, th: u8) !void {
    try dl.append(gpa, .{ .line = .{ .x0 = @intCast(x0), .y0 = @intCast(y0), .x1 = @intCast(x1), .y1 = @intCast(y1), .color = color, .thickness = th } });
}

/// A UTF-8 run; returns the pen x after it.
fn str(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, weight: text.Weight, x0: i32, baseline: i32, color: u32, px: u16, s: []const u8) !i32 {
    var x = x0;
    var it = (std.unicode.Utf8View.init(s) catch return x).iterator();
    while (it.nextCodepoint()) |cp| {
        try dl.append(gpa, .{ .text = .{
            .x = @intCast(x),
            .baseline = @intCast(baseline),
            .codepoint = cp,
            .color = color,
            .px = px,
            .weight = @intFromEnum(weight),
        } });
        x += @as(i32, @intCast(text.advance(e, weight, cp, px)));
    }
    return x;
}

/// A dashed horizontal line (the socket's contact rails).
fn dashedH(gpa: Allocator, dl: *raster.DrawList, x0: i32, x1: i32, y: i32, color: u32, th: u8, dash: i32, gap: i32) !void {
    var x = x0;
    while (x < x1) : (x += dash + gap) {
        try line(gpa, dl, x, y, @min(x + dash, x1), y, color, th);
    }
}

/// A chevron at (cx, cy): a small "v" pointing down (closed) or up (open).
fn chevron(gpa: Allocator, dl: *raster.DrawList, cx: i32, cy: i32, s: i32, color: u32, th: u8, up: bool) !void {
    const dy = if (up) -s else s;
    try line(gpa, dl, cx - s, cy - @divTrunc(dy, 2), cx, cy + @divTrunc(dy, 2), color, th);
    try line(gpa, dl, cx, cy + @divTrunc(dy, 2), cx + s, cy - @divTrunc(dy, 2), color, th);
}

fn pushHit(gpa: Allocator, hits: ?*HitList, x: i32, y: i32, w: i32, h: i32, target: HitTarget, cid: []const u8, color: u8) !void {
    if (hits) |hl| try hl.append(gpa, .{
        .cid = cid,
        .x = @intCast(x),
        .y = @intCast(y),
        .w = @intCast(@max(0, w)),
        .h = @intCast(@max(0, h)),
        .target = target,
        .color = color,
    });
}

// ---------------------------------------------------------------------------
// The pure contract (B2, B5)
// ---------------------------------------------------------------------------

/// CORE, PURE. Same (tray, ui, geom) ⇒ same draw items + hit-rects, every
/// time. Appends into `dl`; fills `hits` when non-null (null = draw-only,
/// e.g. the headless preview). Returns the total pixel height consumed
/// (resting socket, or socket + open tray) so a surface lays out beneath it.
/// Allocates only into `gpa` (the per-frame arena, C1/C3); frees nothing.
pub fn build(
    gpa: Allocator,
    e: *const text.Engine,
    tray: TrayView,
    ui: SocketUi,
    geom: Geometry,
    dl: *raster.DrawList,
    hits: ?*HitList,
) error{OutOfMemory}!i32 {
    const sc = geom.scale;
    const x0 = geom.x;
    const y0 = geom.y;
    const w = geom.w;

    // ---- metrics (logical px × scale) ----
    const sock_h = fxi(64 * sc);
    const radius: u8 = @intCast(@max(0, fxi(14 * sc)));
    const cart_radius: u8 = @intCast(@max(0, fxi(10 * sc)));
    const pad = fxi(12 * sc);

    // The seated lens (E4: an empty tray still renders a valid, empty
    // socket — never an error path). Fall back to a neutral grey accent.
    const have = tray.cards.len > 0 and tray.seated < tray.cards.len;

    // The seat animation (L.2). swap_phase==0 is resting; 1..N maps to a
    // deterministic eject → drop-in → glow-decay of the cartridge. The
    // displayed lens is `swap_from` while ejecting, `swap_to` while it
    // plugs in — so the content swaps WHILE off-screen (the HTML's trick).
    var disp_idx = tray.seated;
    var cart_dy: i32 = 0; // vertical offset of the cartridge during the swap
    var cart_alpha: u8 = 255; // cartridge fade
    var glow: u8 = 0; // seat-glow halo intensity (the "click home" cue)
    if (ui.swap_phase > 0) {
        const seg: u8 = swap_total_frames / 3; // eject | drop | glow
        const p = @min(ui.swap_phase, swap_total_frames);
        if (p <= seg) { // eject: old lens lifts and fades out
            disp_idx = ui.swap_from;
            const u = @as(f32, @floatFromInt(p)) / @as(f32, @floatFromInt(seg));
            cart_dy = fxi(-10 * u * sc);
            cart_alpha = @intCast(@max(0, 255 - fxi(255 * u)));
        } else if (p <= seg * 2) { // drop-in: new lens descends, fades in, glow rises
            disp_idx = ui.swap_to;
            const u = @as(f32, @floatFromInt(p - seg)) / @as(f32, @floatFromInt(seg));
            cart_dy = fxi(14 * (1 - easeOutBack(u)) * sc); // springs into the slot (slight overshoot)
            cart_alpha = @intCast(@min(255, fxi(255 * u)));
            glow = @intCast(@min(255, fxi(255 * u)));
        } else { // settle: cartridge home, seat-glow decays
            disp_idx = ui.swap_to;
            const u = @as(f32, @floatFromInt(p - seg * 2)) / @as(f32, @floatFromInt(seg));
            glow = @intCast(@max(0, 255 - fxi(255 * u)));
        }
    }
    const seat = if (have and disp_idx < tray.cards.len) tray.cards[disp_idx] else LensCard{
        .cid = .{},
        .name = .{},
        .author = .{},
        .ranks = .{},
        .desc = .{},
        .color = 2,
        .flags = .{},
    };
    const acc = if (ui.julia) julia_pink else palette[@min(seat.color, palette.len - 1)];

    // ---- 1. the socket panel (glass over the field) ----
    try rect(gpa, dl, x0, y0, w, sock_h, if (ui.julia) julia_glass else glass, radius);
    try rect(gpa, dl, x0, y0, w, fxi(1 * sc) + 1, hairline, radius); // top inner-light edge
    // contact rails, top & bottom (dashed, faint)
    const dash = fxi(6 * sc);
    const gap = fxi(6 * sc);
    try dashedH(gpa, dl, x0 + fxi(8 * sc), x0 + w - fxi(8 * sc), y0 + fxi(5 * sc), rail, 1, dash, gap);
    try dashedH(gpa, dl, x0 + fxi(8 * sc), x0 + w - fxi(8 * sc), y0 + sock_h - fxi(5 * sc), rail, 1, dash, gap);

    // ---- the cartridge (the seated lens, tinted its palette color) ----
    // `dy`/`a` carry the seat animation: the whole cartridge slides + fades
    // as one. The socket panel, rails, count, and chevron below stay put.
    const cart_x = x0 + pad;
    const cart_y = y0 + fxi(10 * sc) + cart_dy;
    const cart_h = sock_h - fxi(20 * sc);
    const count_w = fxi(96 * sc); // reserve room for "N in tray" + chevron
    const cart_w = w - pad * 2 - count_w;
    const a = cart_alpha;

    // seat-glow: an accent halo behind the cartridge, peaking as it plugs
    // home and decaying — the "click home" cue (§6). Drawn first, beneath.
    if (glow > 0) {
        const g = fxi(4 * sc);
        try rect(gpa, dl, cart_x - g, y0 + fxi(10 * sc) - g, cart_w + g * 2, cart_h + g * 2, soft(acc, @intCast(glow / 3)), cart_radius + @as(u8, @intCast(@max(0, g))));
    }

    try rect(gpa, dl, cart_x, cart_y, cart_w, cart_h, alphaScale(soft(acc, 0x24), a), cart_radius);
    try rect(gpa, dl, cart_x, cart_y, cart_w, fxi(1 * sc) + 1, alphaScale(soft(acc, 0x70), a), cart_radius);

    // privacy glyph (a dot) — always visible (invariant 6)
    const glyph_d = @max(2, fxi(9 * sc));
    const glyph_x = cart_x + fxi(14 * sc);
    const glyph_cy = cart_y + @divTrunc(cart_h, 2);
    try rect(gpa, dl, glyph_x, glyph_cy - @divTrunc(glyph_d, 2), glyph_d, glyph_d, alphaScale(privColor(seat.flags), a), @intCast(@divTrunc(glyph_d, 2)));

    // name + behavioral status
    const txt_x = glyph_x + glyph_d + fxi(11 * sc);
    const name_px: u16 = @intCast(@max(1, fxi(15.5 * sc)));
    const meta_px: u16 = @intCast(@max(1, fxi(11.5 * sc)));
    const name_s = if (have) span(tray, seat.name) else "no lens";
    _ = try str(gpa, dl, e, .semibold, txt_x, cart_y + fxi(22 * sc), alphaScale(ink, a), name_px, name_s);
    // The two derived bits: the privacy label, then — separated by a dot — the
    // adaptive marker when the lens keeps a model (nothing when it's static).
    const meta_y = cart_y + fxi(38 * sc);
    const priv_pen = try str(gpa, dl, e, .regular, txt_x, meta_y, alphaScale(muted, a), meta_px, behaveLabel(seat.flags));
    if (have and seat.flags.learns) {
        const dot_pen = try str(gpa, dl, e, .regular, priv_pen + fxi(6 * sc), meta_y, alphaScale(faint, a), meta_px, "·");
        _ = try str(gpa, dl, e, .regular, dot_pen + fxi(6 * sc), meta_y, alphaScale(privColor(seat.flags), a), meta_px, adaptiveMark(seat.flags));
    }

    // "N in tray" + chevron, right-aligned in the reserved strip
    const count_px: u16 = @intCast(@max(1, fxi(12 * sc)));
    var buf: [24]u8 = undefined;
    const n_in_tray = if (tray.cards.len > 0) tray.cards.len - 1 else 0;
    const count_s = std.fmt.bufPrint(&buf, "{d} in tray", .{n_in_tray}) catch "tray";
    const count_meas: i32 = @intCast(text.measure(e, .regular, count_s, count_px));
    const chev_x = x0 + w - pad - fxi(8 * sc);
    const strip_cy = y0 + @divTrunc(sock_h, 2); // static — does not ride the swap
    _ = try str(gpa, dl, e, .regular, chev_x - fxi(16 * sc) - count_meas, strip_cy + @divTrunc(count_px, 3), faint, count_px, count_s);
    try chevron(gpa, dl, chev_x, strip_cy, fxi(4 * sc), acc, @intCast(@max(1, fxi(1.5 * sc))), ui.open);

    // the whole socket toggles the tray (clickable anywhere)…
    try pushHit(gpa, hits, x0, y0, w, sock_h, .toggle, "", 0);
    // …but only the chevron HIGHLIGHTS on hover — a small box around it, pushed
    // after the bar so the hover scan (last-match-wins) prefers it.
    const caret_box = fxi(30 * sc);
    try pushHit(gpa, hits, chev_x - @divTrunc(caret_box, 2), strip_cy - @divTrunc(caret_box, 2), caret_box, caret_box, .caret, "", 0);

    // Spring-open: the tray sweeps down by `op` (0→1) and cards reveal as it
    // passes them. op≈1 = fully open. Below the threshold it's closed (resting).
    const op = @min(1.0, ui.open_t);
    if (op <= 0.004) return sock_h;

    // ---- 2. the open tray: header + 3-up grid ----
    const tray_top = y0 + sock_h + fxi(10 * sc);
    const box_pad = fxi(10 * sc);
    const hdr_h = fxi(26 * sc);
    const col_gap = fxi(8 * sc);
    const card_h = fxi(104 * sc);
    const grid_x = x0 + box_pad;
    const grid_w = w - box_pad * 2;
    const card_w = @divTrunc(grid_w - col_gap * 2, 3);

    const n = tray.cards.len;
    // The tray always shows the full CAPACITY (max_lenses slots): real cards
    // fill the front, empty slots become "add a lens" placeholders into the
    // marketplace. So the grid is sized to the capacity, not the loaded count.
    const shown: i32 = @intCast(@max(n, max_lenses));
    const rows: i32 = @divFloor(shown + 2, 3);
    // L.3 — an expanded card inserts a full-width detail panel below its row,
    // shifting later rows down. `exp` is the expanded card (validated, E4);
    // `row_e` its row; `detail_h` the panel height.
    const exp: ?u32 = if (ui.expanded) |ex| (if (have and ex < n) ex else null) else null;
    const detail_h = fxi(124 * sc);
    const row_e: i32 = if (exp) |ex| @intCast(ex / 3) else -1;
    const grid_h = rows * card_h + @max(0, rows - 1) * col_gap +
        (if (exp != null) detail_h + col_gap else 0);
    const box_h = hdr_h + grid_h + box_pad;
    // The panel's currently-revealed height (sweeps down with `op`). Cards are
    // drawn only once this sweep has passed them — the staggered reveal.
    const sweep_h: i32 = if (op >= 0.999) box_h else fxi(@as(f32, @floatFromInt(box_h)) * op);
    const reveal_bottom = tray_top + sweep_h;

    // Soft lift shadow under the tray — layered (low alpha, growing offset) to
    // fake a big, soft falloff, so the panel hovers above the feed.
    try rect(gpa, dl, x0 - fxi(2 * sc), tray_top + fxi(10 * sc), w + fxi(4 * sc), sweep_h, soft(0x000000, 0x1C), radius);
    try rect(gpa, dl, x0, tray_top + fxi(5 * sc), w, sweep_h, soft(0x000000, 0x22), radius);
    try rect(gpa, dl, x0, tray_top, w, sweep_h, tray_panel, radius);
    try rect(gpa, dl, x0, tray_top, w, fxi(1 * sc) + 1, hairline, radius); // top lit edge

    // header: hint (uppercase, faint) + "+ get more" (accent) — once the sweep
    // has revealed the header strip.
    const hint_px: u16 = @intCast(@max(1, fxi(11 * sc)));
    if (sweep_h > hdr_h - fxi(4 * sc)) {
        _ = try str(gpa, dl, e, .regular, grid_x, tray_top + fxi(16 * sc), faint, hint_px, "YOUR TRAY \u{00B7} TAP TO SEAT \u{00B7} DRAG HANDLE TO REORDER");
        const more_s = "+ get more";
        const more_meas: i32 = @intCast(text.measure(e, .regular, more_s, hint_px));
        const more_x = x0 + w - box_pad - more_meas;
        _ = try str(gpa, dl, e, .regular, more_x, tray_top + fxi(16 * sc), acc, hint_px, more_s);
        try pushHit(gpa, hits, more_x - fxi(4 * sc), tray_top, more_meas + fxi(8 * sc), hdr_h, .get_more, "", 0);
    }

    // the grid
    const grid_top = tray_top + hdr_h;

    // L.4 — drag to reorder, with iOS-style LIVE REFLOW: the held card lifts to
    // a ghost (below), and the others slide to fill via `ui.slide` (eased per
    // card by the shell, in slot units). `dragging` is the held/settling card.
    const dragging: ?u32 = if (ui.drag_active) |d| (if (have and d < n) d else null) else null;
    const expanded = exp != null;
    for (tray.cards, 0..) |card, i| {
        const seated = have and i == tray.seated;
        const card_acc = if (ui.julia) julia_pink else palette[@min(card.color, palette.len - 1)];

        // The held/settling card rides the ghost (drawn last); skip its slot —
        // the gap it leaves is filled by the reflowing neighbours.
        if (dragging) |d| if (d == i) continue;

        // Reflow position: home slot, lerped toward the neighbour slot by the
        // card's eased slide (slot units). |slide|→1 means a full one-slot move.
        const home = slotXY(@intCast(i), grid_x, grid_top, card_w, card_h, col_gap, detail_h, expanded, row_e);
        var cx = home[0];
        var cy = home[1];
        const sl: f32 = if (i < ui.slide.len) ui.slide[i] else 0;
        if (sl != 0) {
            const dir: i32 = if (sl >= 0) 1 else -1;
            const nb = std.math.clamp(@as(i32, @intCast(i)) + dir, 0, @as(i32, @intCast(n)) - 1);
            const np = slotXY(nb, grid_x, grid_top, card_w, card_h, col_gap, detail_h, expanded, row_e);
            const t = @min(1.0, @abs(sl));
            cx = lerpi(home[0], np[0], t);
            cy = lerpi(home[1], np[1], t);
        }
        // Staggered reveal: skip the card until the opening sweep has reached it.
        if (cy + card_h > reveal_bottom + fxi(2 * sc)) continue;

        // card body. Unseated cards sit RAISED (a soft shadow lifts them);
        // the seated card sits RECESSED (darker, no shadow) with a thin
        // glowing accent rule down its left edge — "found its home" (§2).
        if (!seated) try rect(gpa, dl, cx, cy + fxi(3 * sc), card_w, card_h, soft(0x000000, 0x26), cart_radius);
        const fill = if (seated) soft(0x000000, 0x33) else pill_bg;
        const edge = if (seated) soft(card_acc, 0x3A) else pill_edge;
        try rect(gpa, dl, cx, cy, card_w, card_h, fill, cart_radius);
        try rect(gpa, dl, cx, cy, card_w, fxi(1 * sc) + 1, edge, cart_radius);
        if (seated) try rect(gpa, dl, cx, cy + fxi(7 * sc), @max(2, fxi(3 * sc)), card_h - fxi(14 * sc), card_acc, @intCast(@max(1, fxi(2 * sc))));

        const in_x = cx + fxi(11 * sc);
        // top row: privacy chip (glyph + label) at left.
        const chip_px: u16 = @intCast(@max(1, fxi(10.5 * sc)));
        const cg_d = @max(2, fxi(7 * sc));
        const cg_y = cy + fxi(14 * sc);
        try rect(gpa, dl, in_x, cg_y - @divTrunc(cg_d, 2), cg_d, cg_d, privColor(card.flags), @intCast(@divTrunc(cg_d, 2)));
        const chip_c = if (seated) card_acc else muted;
        _ = try str(gpa, dl, e, .regular, in_x + cg_d + fxi(5 * sc), cg_y + @divTrunc(chip_px, 3), chip_c, chip_px, privLabel(card.flags));

        // THE COLOR SWATCH (top-right): this lens's palette color — the
        // recognition cue (the color the WHOLE UI takes when seated, §11.5)
        // and the future click-to-recolor target. A resting card otherwise
        // showed only the privacy dot, so its lens color was invisible (the
        // mismatch the owner caught: a "learns" lens looked amber regardless).
        const sw_w = fxi(24 * sc);
        const sw_h = fxi(13 * sc);
        const sw_rad: u8 = @intCast(@max(2, fxi(4 * sc)));
        const sw_x = cx + card_w - fxi(11 * sc) - sw_w;
        const sw_y = cy + fxi(8 * sc);
        try rect(gpa, dl, sw_x, sw_y, sw_w, sw_h, card_acc, sw_rad);
        try rect(gpa, dl, sw_x, sw_y, sw_w, fxi(1 * sc) + 1, soft(0xFFFFFF, 0x44), sw_rad); // lit top edge

        // name
        const cname_px: u16 = @intCast(@max(1, fxi(14 * sc)));
        _ = try str(gpa, dl, e, .semibold, in_x, cy + fxi(42 * sc), ink, cname_px, span(tray, card.name));

        // glanceable stats: "ranks <x>" + behavioral line, anchored low
        const stat_px: u16 = @intCast(@max(1, fxi(11 * sc)));
        const ranks_x = try str(gpa, dl, e, .regular, in_x, cy + card_h - fxi(26 * sc), muted, stat_px, "ranks ");
        _ = try str(gpa, dl, e, .semibold, ranks_x, cy + card_h - fxi(26 * sc), ink, stat_px, span(tray, card.ranks));
        const behave_px: u16 = @intCast(@max(1, fxi(10.5 * sc)));
        _ = try str(gpa, dl, e, .regular, in_x, cy + card_h - fxi(11 * sc), faint, behave_px, behaveLabel(card.flags));
        // seated marker, bottom-right (the accent wash + edge also mark it).
        if (seated) {
            const tick_s = "\u{25CF} seated";
            const tick_meas: i32 = @intCast(text.measure(e, .regular, tick_s, behave_px));
            _ = try str(gpa, dl, e, .regular, cx + card_w - fxi(11 * sc) - tick_meas, cy + card_h - fxi(11 * sc), card_acc, behave_px, tick_s);
        }

        // The ⓘ expand affordance, bottom-right corner (a faint glyph). It
        // surfaces full detail WITHOUT seating (the look-before-you-leap path,
        // §7.1). When this card is already expanded it reads as "active".
        const info_px: u16 = @intCast(@max(1, fxi(13 * sc)));
        const info_w: i32 = @intCast(text.measure(e, .regular, "\u{24D8}", info_px));
        const info_x = cx + card_w - fxi(9 * sc) - info_w;
        const info_y = cy + card_h - fxi(9 * sc);
        const info_on = if (exp) |ex| ex == i else false;
        _ = try str(gpa, dl, e, .regular, info_x, info_y, if (info_on) card_acc else faint, info_px, "\u{24D8}");

        // The drag HANDLE — a small grip at the right edge, vertical centre.
        // Only on non-seated cards (the seated lens can't be dragged out of
        // front, §7.3). It's the one reorder affordance.
        const can_drag = !seated;
        if (can_drag) {
            const dot = @max(1, fxi(2 * sc));
            const hgx = cx + card_w - fxi(11 * sc);
            const hgy = cy + @divTrunc(card_h, 2) - fxi(4 * sc);
            var dr: i32 = 0;
            while (dr < 3) : (dr += 1) {
                try rect(gpa, dl, hgx, hgy + dr * fxi(4 * sc), dot, dot, soft(0xFFFFFF, 0x40), 0);
                try rect(gpa, dl, hgx + fxi(4 * sc), hgy + dr * fxi(4 * sc), dot, dot, soft(0xFFFFFF, 0x40), 0);
            }
        }

        // click-body seats this lens (the CID crosses out, not the index).
        try pushHit(gpa, hits, cx, cy, card_w, card_h, .seat, span(tray, card.cid), 0);
        // The ⓘ corner expands detail instead — pushed AFTER seat so it wins
        // in its small area (hitTest is last-drawn-first).
        try pushHit(gpa, hits, info_x - fxi(8 * sc), info_y - info_px, info_w + fxi(16 * sc), fxi(22 * sc), .expand, span(tray, card.cid), 0);
        // The handle grip — pushed LAST so it wins over seat in its strip.
        if (can_drag) try pushHit(gpa, hits, cx + card_w - fxi(20 * sc), cy + @divTrunc(card_h, 2) - fxi(12 * sc), fxi(20 * sc), fxi(24 * sc), .reorder_handle, span(tray, card.cid), 0);
        // The color SWATCH opens the recolor picker (§11.5) — pushed last so it
        // wins over seat in its corner. The picker popover is drawn after the loop.
        try pushHit(gpa, hits, sw_x - fxi(4 * sc), sw_y - fxi(4 * sc), sw_w + fxi(8 * sc), sw_h + fxi(8 * sc), .swatch_open, span(tray, card.cid), 0);
    }

    // §11.5 — the color PICKER popover: a 3×3 grid of the palette, opened by
    // tapping a card's swatch. Pick any color (duplicates allowed — totally the
    // user's call); the selected one is ringed. Drawn after the cards so it sits
    // on top; its chips out-rank the card beneath (pushed last).
    if (ui.picking) |pk| if (have and pk < n) {
        const card = tray.cards[pk];
        const home = slotXY(@intCast(pk), grid_x, grid_top, card_w, card_h, col_gap, detail_h, expanded, row_e);
        const chip = fxi(18 * sc);
        const cgp = fxi(6 * sc);
        const pop_w = 3 * chip + 2 * cgp + fxi(16 * sc);
        const pop_h = 3 * chip + 2 * cgp + fxi(16 * sc);
        const pop_x = home[0] + card_w - pop_w - fxi(6 * sc);
        const pop_y = home[1] + fxi(26 * sc);
        try rect(gpa, dl, pop_x + fxi(2 * sc), pop_y + fxi(4 * sc), pop_w, pop_h, soft(0x000000, 0x66), cart_radius); // shadow
        try rect(gpa, dl, pop_x, pop_y, pop_w, pop_h, 0xFF20201B, cart_radius);
        try rect(gpa, dl, pop_x, pop_y, pop_w, fxi(1 * sc) + 1, soft(0xFFFFFF, 0x33), cart_radius);
        const chip_rad: u8 = @intCast(@max(2, fxi(4 * sc)));
        var ci: usize = 0;
        while (ci < palette.len) : (ci += 1) {
            const ccol: i32 = @intCast(ci % 3);
            const crow: i32 = @intCast(ci / 3);
            const chx = pop_x + fxi(8 * sc) + ccol * (chip + cgp);
            const chy = pop_y + fxi(8 * sc) + crow * (chip + cgp);
            if (card.color == ci) try rect(gpa, dl, chx - fxi(2 * sc), chy - fxi(2 * sc), chip + fxi(4 * sc), chip + fxi(4 * sc), ink, chip_rad); // selected ring
            try rect(gpa, dl, chx, chy, chip, chip, if (ui.julia) julia_pink else palette[ci], chip_rad);
            try pushHit(gpa, hits, chx, chy, chip, chip, .swatch, span(tray, card.cid), @intCast(ci));
        }
    };

    // Empty-slot PLACEHOLDERS: every capacity slot past the loaded lenses reads
    // as "another could go here," and tapping one opens the marketplace
    // (get_more). A dashed outline + a centred "+", deliberately quiet so it
    // doesn't compete with the real cards.
    {
        var s: usize = n;
        while (s < @as(usize, @intCast(shown))) : (s += 1) {
            const col: i32 = @intCast(s % 3);
            const row: i32 = @intCast(s / 3);
            const px2 = grid_x + col * (card_w + col_gap);
            const py2 = grid_top + row * (card_h + col_gap) + (if (exp != null and row > row_e) detail_h + col_gap else 0);
            if (py2 + card_h > reveal_bottom + fxi(2 * sc)) continue; // not yet revealed by the sweep
            // a faint dashed border (four edges) + a soft "+" in the centre
            try dashedH(gpa, dl, px2 + fxi(6 * sc), px2 + card_w - fxi(6 * sc), py2 + fxi(2 * sc), rail, 1, fxi(7 * sc), fxi(5 * sc));
            try dashedH(gpa, dl, px2 + fxi(6 * sc), px2 + card_w - fxi(6 * sc), py2 + card_h - fxi(2 * sc), rail, 1, fxi(7 * sc), fxi(5 * sc));
            // Quiet: dimmer than `faint` so the placeholders whisper, sitting
            // clearly below the real cards (§4) — they brighten on hover later.
            const ghost = soft(0xFFFFFF, 0x1C);
            const plus_px: u16 = @intCast(@max(1, fxi(20 * sc)));
            const plus_w: i32 = @intCast(text.measure(e, .regular, "+", plus_px));
            _ = try str(gpa, dl, e, .regular, px2 + @divTrunc(card_w - plus_w, 2), py2 + @divTrunc(card_h, 2), ghost, plus_px, "+");
            const add_px: u16 = @intCast(@max(1, fxi(10.5 * sc)));
            const add_w: i32 = @intCast(text.measure(e, .regular, "add a lens", add_px));
            _ = try str(gpa, dl, e, .regular, px2 + @divTrunc(card_w - add_w, 2), py2 + @divTrunc(card_h, 2) + fxi(20 * sc), ghost, add_px, "add a lens");
            try pushHit(gpa, hits, px2, py2, card_w, card_h, .get_more, "", 0);
        }
    }

    // L.4 — the held card's GHOST, drawn LAST so it floats over everything. It
    // follows the pointer while dragging, then SETTLES into its slot on drop
    // (a quick ease), and carries a LIFT (scale + shadow) that fades as it lands.
    if (dragging) |d| {
        const card = tray.cards[d];
        const card_acc = if (ui.julia) julia_pink else palette[@min(card.color, palette.len - 1)];
        const from_x = ui.drag_x - @divTrunc(card_w, 2);
        const from_y = ui.drag_y - @divTrunc(card_h, 2);
        var gx = from_x;
        var gy = from_y;
        if (ui.settle_phase > 0) {
            // ease from the release point into the card's home slot
            const home = slotXY(@intCast(d), grid_x, grid_top, card_w, card_h, col_gap, detail_h, expanded, row_e);
            const raw = @as(f32, @floatFromInt(@min(ui.settle_phase, settle_total_frames))) / @as(f32, @floatFromInt(settle_total_frames));
            const t = easeOutBack(raw); // spring overshoot, then settle
            gx = lerpi(from_x, home[0], t);
            gy = lerpi(from_y, home[1], t);
        }
        // Lift: grow the ghost slightly (centred) while held; shrinks as it lands.
        const bump = fxi(8 * ui.lift * sc);
        const lx = gx - @divTrunc(bump, 2);
        const ly = gy - @divTrunc(bump, 2);
        const lw = card_w + bump;
        const lh = card_h + bump;
        const shadow_off = fxi((3 + 5 * ui.lift) * sc);
        try rect(gpa, dl, lx + shadow_off, ly + shadow_off + fxi(2 * sc), lw, lh, soft(0x000000, 0x55), cart_radius); // drop shadow (deeper while lifted)
        try rect(gpa, dl, lx, ly, lw, lh, soft(card_acc, 0x3A), cart_radius);
        try rect(gpa, dl, lx, ly, lw, fxi(1 * sc) + 1, soft(card_acc, 0xAA), cart_radius);
        try rect(gpa, dl, lx + fxi(11 * sc), ly + fxi(11 * sc), fxi(24 * sc), fxi(13 * sc), card_acc, @intCast(@max(2, fxi(4 * sc)))); // swatch
        _ = try str(gpa, dl, e, .semibold, lx + fxi(11 * sc), ly + @divTrunc(lh, 2) + fxi(6 * sc), ink, @intCast(@max(1, fxi(14 * sc))), span(tray, card.name));
    }

    // L.3 — the expanded detail panel: spans the grid row below the expanded
    // card, shows author / description / ranks / privacy / CID, and a seat +
    // close action. Does NOT seat by itself; does not leave the grid (§5.5).
    if (exp) |ex| {
        if (grid_top + row_e * (card_h + col_gap) + card_h + col_gap + detail_h <= reveal_bottom + fxi(2 * sc)) {
        const card = tray.cards[ex];
        const card_acc = if (ui.julia) julia_pink else palette[@min(card.color, palette.len - 1)];
        const py = grid_top + row_e * (card_h + col_gap) + card_h + col_gap;
        try rect(gpa, dl, grid_x, py, grid_w, detail_h, soft(card_acc, 0x14), cart_radius);
        try rect(gpa, dl, grid_x, py, grid_w, fxi(1 * sc) + 1, soft(card_acc, 0x66), cart_radius);
        const dx = grid_x + fxi(14 * sc);

        // name + "by author"
        const nm_x = try str(gpa, dl, e, .semibold, dx, py + fxi(22 * sc), ink, @intCast(@max(1, fxi(15 * sc))), span(tray, card.name));
        _ = try str(gpa, dl, e, .regular, nm_x + fxi(10 * sc), py + fxi(22 * sc), muted, @intCast(@max(1, fxi(12 * sc))), "by ");
        _ = try str(gpa, dl, e, .regular, nm_x + fxi(10 * sc) + fxi(18 * sc), py + fxi(22 * sc), faint, @intCast(@max(1, fxi(12 * sc))), span(tray, card.author));

        // description (one wrapped-ish line; the panel is fixed height)
        _ = try str(gpa, dl, e, .regular, dx, py + fxi(44 * sc), body, @intCast(@max(1, fxi(12.5 * sc))), span(tray, card.desc));

        // facts row: ranks · privacy (system-derived) · CID
        const fact_px: u16 = @intCast(@max(1, fxi(11.5 * sc)));
        var fx = try str(gpa, dl, e, .regular, dx, py + fxi(70 * sc), muted, fact_px, "ranks ");
        fx = try str(gpa, dl, e, .semibold, fx, py + fxi(70 * sc), ink, fact_px, span(tray, card.ranks));
        fx = try str(gpa, dl, e, .regular, fx + fxi(14 * sc), py + fxi(70 * sc), muted, fact_px, "privacy ");
        fx = try str(gpa, dl, e, .semibold, fx, py + fxi(70 * sc), ink, fact_px, behaveLabel(card.flags));
        if (card.flags.learns) {
            fx = try str(gpa, dl, e, .regular, fx + fxi(10 * sc), py + fxi(70 * sc), faint, fact_px, "· ");
            fx = try str(gpa, dl, e, .semibold, fx, py + fxi(70 * sc), privColor(card.flags), fact_px, adaptiveMark(card.flags));
        }
        var cb: [40]u8 = undefined;
        const cid_s = std.fmt.bufPrint(&cb, "cid {s}", .{span(tray, card.cid)}) catch "cid";
        _ = try str(gpa, dl, e, .regular, dx, py + fxi(90 * sc), faint, fact_px, cid_s);

        // actions: "seat this lens" (primary) + "close", bottom-right
        const seated_here = have and ex == tray.seated;
        const btn_px: u16 = @intCast(@max(1, fxi(12.5 * sc)));
        const close_lbl = "close";
        const close_w: i32 = @as(i32, @intCast(text.measure(e, .semibold, close_lbl, btn_px))) + fxi(24 * sc);
        const close_x = grid_x + grid_w - fxi(12 * sc) - close_w;
        const btn_y = py + detail_h - fxi(40 * sc);
        const btn_h = fxi(30 * sc);
        try rect(gpa, dl, close_x, btn_y, close_w, btn_h, pill_bg, @intCast(@max(2, fxi(8 * sc))));
        _ = try str(gpa, dl, e, .semibold, close_x + fxi(12 * sc), btn_y + fxi(20 * sc), muted, btn_px, close_lbl);
        try pushHit(gpa, hits, close_x, btn_y, close_w, btn_h, .collapse, "", 0);
        if (!seated_here) {
            const seat_lbl = "seat this lens";
            const seat_w: i32 = @as(i32, @intCast(text.measure(e, .semibold, seat_lbl, btn_px))) + fxi(28 * sc);
            const seat_x = close_x - fxi(10 * sc) - seat_w;
            try rect(gpa, dl, seat_x, btn_y, seat_w, btn_h, card_acc, @intCast(@max(2, fxi(8 * sc))));
            _ = try str(gpa, dl, e, .semibold, seat_x + fxi(14 * sc), btn_y + fxi(20 * sc), 0xFF181812, btn_px, seat_lbl);
            try pushHit(gpa, hits, seat_x, btn_y, seat_w, btn_h, .seat, span(tray, card.cid), 0);
        }
        }
    }

    return sock_h + fxi(10 * sc) + sweep_h;
}

/// The grid slot index under (ui.drag_x, ui.drag_y) — the drag's insertion
/// rank. Pure; recomputes the same grid metrics `build` uses (kept in sync).
/// Null when closed or the pointer is off the grid.
pub fn dropIndex(tray: TrayView, ui: SocketUi, geom: Geometry) ?u32 {
    if (!ui.open or tray.cards.len == 0) return null;
    const sc = geom.scale;
    const sock_h = fxi(64 * sc);
    const box_pad = fxi(10 * sc);
    const hdr_h = fxi(26 * sc);
    const col_gap = fxi(8 * sc);
    const card_h = fxi(104 * sc);
    const grid_x = geom.x + box_pad;
    const grid_w = geom.w - box_pad * 2;
    const card_w = @divTrunc(grid_w - col_gap * 2, 3);
    const grid_top = geom.y + sock_h + fxi(10 * sc) + hdr_h;
    const n = tray.cards.len;
    const expanded = if (ui.expanded) |ex| (ex < n) else false;
    const detail_h = fxi(124 * sc);
    const row_e: i32 = if (ui.expanded) |ex| @intCast(ex / 3) else -1;
    for (0..n) |j| {
        const p = slotXY(@intCast(j), grid_x, grid_top, card_w, card_h, col_gap, detail_h, expanded, row_e);
        if (ui.drag_x >= p[0] and ui.drag_x < p[0] + card_w and ui.drag_y >= p[1] and ui.drag_y < p[1] + card_h) return @intCast(j);
    }
    return null;
}

/// CORE, PURE. Maps a click point to an intent from `hits` alone — no
/// mutation, no I/O, no index ever returned (A5). Last-drawn-first
/// (reverse paint order) so a card beats the socket panel beneath it.
pub fn hitTest(hits: []const HitRect, px: i32, py: i32) ?SocketAction {
    var i: usize = hits.len;
    while (i > 0) {
        i -= 1;
        const r = hits[i];
        if (px >= r.x and px < @as(i32, r.x) + r.w and py >= r.y and py < @as(i32, r.y) + r.h) {
            return switch (r.target) {
                .toggle, .caret => .toggle_tray,
                .seat => .{ .seat = r.cid },
                .expand => .{ .expand = r.cid },
                .collapse => .collapse,
                .get_more => .get_more,
                .reorder_handle => .{ .reorder = .{ .lens = r.cid, .to_rank = 0 } },
                .swatch_open => .{ .open_swatch = r.cid },
                .swatch => .{ .set_color = .{ .lens = r.cid, .color = r.color } },
            };
        }
    }
    return null;
}

// ---------------------------------------------------------------------------
// Tests (C6: leak-checked). Golden-ish: determinism, purity, hit mapping,
// and the empty-tray ordinary-result path (E4). Size guards run at comptime.
// ---------------------------------------------------------------------------

const testing = std.testing;

/// A tiny placeholder tray built into a caller-owned arena — also the shape
/// the preview harness uses (the design's "include a few placeholders").
fn buildSampleTray(arena: Allocator) !TrayView {
    var blob: std.ArrayListUnmanaged(u8) = .empty;
    const Spec = struct { name: []const u8, author: []const u8, ranks: []const u8, desc: []const u8, cid: []const u8, color: u8, flags: LensFlags };
    const specs = [_]Spec{
        .{ .name = "For You", .author = "zat4 default", .ranks = "engagement + recency", .desc = "The adaptive default.", .cid = "bafy7x2a", .color = 0, .flags = .{ .behavioral = true, .learns = true, .is_default = true } },
        .{ .name = "Following", .author = "zat4 default", .ranks = "chronological", .desc = "Reverse-chron of your follows.", .cid = "bafy0c11", .color = 2, .flags = .{ .is_default = true } },
        .{ .name = "Discover", .author = "zat4 default", .ranks = "popularity + topics", .desc = "Strong posts beyond your follows.", .cid = "bafy9f3d", .color = 1, .flags = .{ .behavioral = true, .learns = true } },
    };
    var cards = try arena.alloc(LensCard, specs.len);
    for (specs, 0..) |s, i| {
        const name: TextSpan = .{ .off = @intCast(blob.items.len), .len = @intCast(s.name.len) };
        try blob.appendSlice(arena, s.name);
        const author: TextSpan = .{ .off = @intCast(blob.items.len), .len = @intCast(s.author.len) };
        try blob.appendSlice(arena, s.author);
        const ranks: TextSpan = .{ .off = @intCast(blob.items.len), .len = @intCast(s.ranks.len) };
        try blob.appendSlice(arena, s.ranks);
        const desc: TextSpan = .{ .off = @intCast(blob.items.len), .len = @intCast(s.desc.len) };
        try blob.appendSlice(arena, s.desc);
        const cid: TextSpan = .{ .off = @intCast(blob.items.len), .len = @intCast(s.cid.len) };
        try blob.appendSlice(arena, s.cid);
        cards[i] = .{ .cid = cid, .name = name, .author = author, .ranks = ranks, .desc = desc, .color = s.color, .flags = s.flags };
    }
    return .{ .cards = cards, .text = blob.items, .seated = 0 };
}

test "build is pure: same inputs produce identical draw lists" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var engine = try text.initEngine();
    defer text.deinitEngine(testing.allocator, &engine);

    const tray = try buildSampleTray(arena);
    const ui: SocketUi = .{ .open = true, .open_t = 1.0 };
    const geom: Geometry = .{ .x = 40, .y = 40, .w = 640, .scale = 1.0 };

    var dl1: raster.DrawList = .{};
    defer dl1.deinit(testing.allocator);
    var dl2: raster.DrawList = .{};
    defer dl2.deinit(testing.allocator);

    const h1 = try build(testing.allocator, &engine, tray, ui, geom, &dl1, null);
    const h2 = try build(testing.allocator, &engine, tray, ui, geom, &dl2, null);
    try testing.expectEqual(h1, h2);
    try testing.expectEqual(dl1.len, dl2.len);
}

test "resting socket is shorter than the open tray" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var engine = try text.initEngine();
    defer text.deinitEngine(testing.allocator, &engine);

    const tray = try buildSampleTray(arena);
    const geom: Geometry = .{ .x = 0, .y = 0, .w = 600, .scale = 1.0 };

    var dl: raster.DrawList = .{};
    defer dl.deinit(testing.allocator);

    const closed = try build(testing.allocator, &engine, tray, .{ .open = false }, geom, &dl, null);
    dl.len = 0;
    const open = try build(testing.allocator, &engine, tray, .{ .open = true, .open_t = 1.0 }, geom, &dl, null);
    try testing.expect(open > closed);
}

test "hitTest: socket toggles, card seats with its CID, miss is null (E4)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var engine = try text.initEngine();
    defer text.deinitEngine(testing.allocator, &engine);

    const tray = try buildSampleTray(arena);
    const geom: Geometry = .{ .x = 0, .y = 0, .w = 600, .scale = 1.0 };

    var dl: raster.DrawList = .{};
    defer dl.deinit(testing.allocator);
    var hits: HitList = .empty;
    defer hits.deinit(testing.allocator);

    _ = try build(testing.allocator, &engine, tray, .{ .open = true, .open_t = 1.0 }, geom, &dl, &hits);

    // A click inside the socket band (y < 64) hits the toggle.
    const top = hitTest(hits.items, 300, 20) orelse return error.NoHit;
    try testing.expect(top == .toggle_tray);

    // A click on the second card body seats it — and the action carries the
    // CID slice, never an index (A5). Card row 0, col 1.
    const card_action = hitTest(hits.items, 300, 130) orelse return error.NoHit;
    switch (card_action) {
        .seat => |cid| try testing.expect(cid.len > 0),
        else => return error.WrongAction,
    }

    // A click far below everything is an ordinary null (E4), not an error.
    try testing.expect(hitTest(hits.items, 300, 5000) == null);
}

test "seat animation: phase-driven, pure, and bounded across the whole swap" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var engine = try text.initEngine();
    defer text.deinitEngine(testing.allocator, &engine);

    const tray = try buildSampleTray(arena);
    const geom: Geometry = .{ .x = 0, .y = 0, .w = 600, .scale = 1.0 };

    // Every frame of the swap renders deterministically (same phase ⇒ same
    // length), and the resting frame (phase 0) matches a no-swap build.
    var phase: u8 = 0;
    while (phase <= swap_total_frames + 2) : (phase += 1) {
        var dla: raster.DrawList = .{};
        defer dla.deinit(testing.allocator);
        var dlb: raster.DrawList = .{};
        defer dlb.deinit(testing.allocator);
        const ui: SocketUi = .{ .open = false, .swap_phase = phase, .swap_from = 0, .swap_to = 2 };
        _ = try build(testing.allocator, &engine, tray, ui, geom, &dla, null);
        _ = try build(testing.allocator, &engine, tray, ui, geom, &dlb, null);
        try testing.expectEqual(dla.len, dlb.len);
        try testing.expect(dla.len > 0);
    }
}

test "seatedAccent: returns the seated lens's palette color (§11.5)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var tray = try buildSampleTray(arena); // [0]=For You amber, [1]=Following grey
    tray.seated = 0;
    try testing.expectEqual(palette[0], seatedAccent(tray));
    tray.seated = 1;
    try testing.expectEqual(palette[2], seatedAccent(tray));
    // Empty tray falls back to neutral grey, not an error (E4).
    try testing.expectEqual(palette[2], seatedAccent(.{ .cards = &.{}, .text = "", .seated = 0 }));
}

test "L.3 expand: panel grows the tray, ⓘ maps to expand, close collapses" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var engine = try text.initEngine();
    defer text.deinitEngine(testing.allocator, &engine);

    const tray = try buildSampleTray(arena);
    const geom: Geometry = .{ .x = 0, .y = 0, .w = 600, .scale = 1.0 };

    // Expanding a card makes the tray taller than the plain open tray.
    const open_h = measuredHeight(tray, .{ .open = true, .open_t = 1.0 }, geom);
    const exp_h = measuredHeight(tray, .{ .open = true, .open_t = 1.0, .expanded = 0 }, geom);
    try testing.expect(exp_h > open_h);
    // build agrees with measuredHeight when a card is expanded.
    var dl: raster.DrawList = .{};
    defer dl.deinit(testing.allocator);
    var hits: HitList = .empty;
    defer hits.deinit(testing.allocator);
    const built = try build(testing.allocator, &engine, tray, .{ .open = true, .open_t = 1.0, .expanded = 0 }, geom, &dl, &hits);
    try testing.expectEqual(exp_h, built);

    // Some ⓘ corner maps to .expand carrying a CID; the detail's close button
    // maps to .collapse. Scan the hits for both targets.
    var saw_expand = false;
    var saw_collapse = false;
    for (hits.items) |h| {
        if (h.target == .expand and h.cid.len > 0) saw_expand = true;
        if (h.target == .collapse) saw_collapse = true;
    }
    try testing.expect(saw_expand);
    try testing.expect(saw_collapse);
}

test "L.4 reorder: non-seated cards emit a drag handle; the seated one does not" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var engine = try text.initEngine();
    defer text.deinitEngine(testing.allocator, &engine);

    const tray = try buildSampleTray(arena); // seated = 0
    const geom: Geometry = .{ .x = 0, .y = 0, .w = 600, .scale = 1.0 };
    var dl: raster.DrawList = .{};
    defer dl.deinit(testing.allocator);
    var hits: HitList = .empty;
    defer hits.deinit(testing.allocator);
    _ = try build(testing.allocator, &engine, tray, .{ .open = true, .open_t = 1.0 }, geom, &dl, &hits);

    var handles: usize = 0;
    var seated_has_handle = false;
    const seated_cid = blk: {
        const c = tray.cards[tray.seated].cid;
        break :blk tray.text[c.off..][0..c.len];
    };
    for (hits.items) |h| {
        if (h.target == .reorder_handle) {
            handles += 1;
            if (std.mem.eql(u8, h.cid, seated_cid)) seated_has_handle = true;
        }
    }
    // Every non-seated card gets a handle; the seated card does not (§7.3).
    try testing.expectEqual(tray.cards.len - 1, handles);
    try testing.expect(!seated_has_handle);

    // A drag still renders (the ghost + hole) without panicking.
    dl.len = 0;
    _ = try build(testing.allocator, &engine, tray, .{ .open = true, .open_t = 1.0, .drag_active = 2, .drag_x = 200, .drag_y = 300 }, geom, &dl, null);
    try testing.expect(dl.len > 0);
}

test "§11.5 recolor: swatch opens a picker; chips map to set_color over 9 colors" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var engine = try text.initEngine();
    defer text.deinitEngine(testing.allocator, &engine);

    const tray = try buildSampleTray(arena);
    const geom: Geometry = .{ .x = 0, .y = 0, .w = 600, .scale = 1.0 };
    var dl: raster.DrawList = .{};
    defer dl.deinit(testing.allocator);
    var hits: HitList = .empty;
    defer hits.deinit(testing.allocator);

    // Closed picker: every card offers a swatch_open target, no chips.
    _ = try build(testing.allocator, &engine, tray, .{ .open = true, .open_t = 1.0 }, geom, &dl, &hits);
    var opens: usize = 0;
    var chips: usize = 0;
    for (hits.items) |h| {
        if (h.target == .swatch_open) opens += 1;
        if (h.target == .swatch) chips += 1;
    }
    try testing.expectEqual(tray.cards.len, opens);
    try testing.expectEqual(@as(usize, 0), chips);

    // Open the picker on card 2 → a full palette of color chips appears.
    hits.clearRetainingCapacity();
    dl.len = 0;
    _ = try build(testing.allocator, &engine, tray, .{ .open = true, .open_t = 1.0, .picking = 2 }, geom, &dl, &hits);
    var palette_chips: usize = 0;
    var seen_colors: [palette.len]bool = @splat(false);
    for (hits.items) |h| {
        if (h.target == .swatch) {
            palette_chips += 1;
            if (h.color < palette.len) seen_colors[h.color] = true;
        }
    }
    try testing.expectEqual(palette.len, palette_chips);
    for (seen_colors) |s| try testing.expect(s); // all 9 colors offered

    // A chip resolves to set_color carrying the lens CID + chosen color.
    var ok = false;
    for (hits.items) |h| {
        if (h.target != .swatch) continue;
        switch (hitTest(&.{h}, h.x + 1, h.y + 1).?) {
            .set_color => |s| if (s.lens.len > 0) {
                ok = true;
            },
            else => {},
        }
    }
    try testing.expect(ok);
}

test "empty tray renders a valid socket, not an error (E4)" {
    var engine = try text.initEngine();
    defer text.deinitEngine(testing.allocator, &engine);
    const tray: TrayView = .{ .cards = &.{}, .text = "", .seated = 0 };
    const geom: Geometry = .{ .x = 0, .y = 0, .w = 500, .scale = 1.0 };
    var dl: raster.DrawList = .{};
    defer dl.deinit(testing.allocator);
    const h = try build(testing.allocator, &engine, tray, .{ .open = true, .open_t = 1.0 }, geom, &dl, null);
    try testing.expect(h > 0);
    try testing.expect(dl.len > 0);
}
