// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Zat4 — a social-media client built on the AT Protocol.
// Copyright (C) 2026  Connor Avila

//! B1: CORE (pure). THE BOOT ENTRANCE — the first thing anybody ever sees of
//! Zat4, and the last thing built (FRONT_DOOR_ROADMAP §5).
//!
//! Two movements, from the owner's design:
//!
//!   1. A boot log TYPES ITSELF, centred, growing outward from the middle. Each
//!      line is centred, so a half-typed line grows from its own centre while the
//!      stack grows downward — that is the whole trick, and it survives here for
//!      free because every line is centre-measured as it is drawn.
//!   2. The ZAT4 wordmark RESOLVES OUT OF NOISE. Every cell starts as a random
//!      junk glyph in dead grey and LOCKS to its true shape on a per-cell
//!      threshold, so the mark does not wipe in — it precipitates.
//!
//! THE COLOUR IS NOT DECORATION. The letters are Zig orange and the AT is
//! atproto blue: the app is a Zig program speaking AT Protocol, and the wordmark
//! says so without a word of prose.
//!
//! WHY THE MARK IS DRAWN AS RECTANGLES, not as text. The design's block art is
//! ANSI-shadow — `█ ╗ ╔ ╝ ╚ ║ ═` — and our embedded font (Inter) contains NONE of
//! those codepoints; every one of them would strike as .notdef. So the art GRID is
//! kept exactly as designed and each inked cell is rasterized from the shape it
//! names: a full block IS a rectangle, a double-line is a bar, a corner is two
//! bars meeting. No new font asset, crisp at any DPI, and the shape is the
//! designer's, not an approximation of it. The NOISE, by contrast, is plain ASCII
//! (`@#%&*+=…`) — which the font does have — so the resolve reads as junk text
//! condensing into solid matter.
//!
//! PURE: no clock, no RNG. Everything is a function of `t` (seconds since the
//! entrance began), and the noise is a hash of (row, col, frame) — deterministic,
//! and therefore testable.

const std = @import("std");
const Allocator = std.mem.Allocator;
const text = @import("text.zig");
const raster = @import("raster.zig");
const fv = @import("feed_view.zig");

// ── palette (the owner's, to the byte) ──
const zig_orange: u32 = 0xFFF7A41D;
const atproto_blue: u32 = 0xFF0A7AFF;
const log_dim: u32 = 0xFF6A6A6A; // the boot log's prose
const log_ok: u32 = 0xFFB0B0B0; // its [ok] / [found]
const noise_c: u32 = 0xFF3A3A3A; // dead grey — unresolved cells

// ── timing (the mockup's, to the millisecond) ──
const per_char_s: f32 = 0.018;
const per_line_s: f32 = 0.200;
const hold_after_log_s: f32 = 0.320;
const resolve_s: f32 = 0.700; // 42 frames at 60 Hz, as designed
/// The settled mark holds for a beat before the door opens, so the entrance ends
/// on the wordmark rather than snatching it away the instant it forms.
const hold_after_mark_s: f32 = 0.400;

const BootLine = struct {
    // A7.2: cold struct (a fixed 6-entry table, read once per frame), guard waived.
    text: []const u8,
    ok: []const u8,
};

const boot_log = [_]BootLine{
    .{ .text = "zat4 :: cold boot", .ok = "ok" },
    .{ .text = "mounting feed substrate", .ok = "ok" },
    .{ .text = "opening socket :: atproto", .ok = "ok" },
    .{ .text = "entropy pool primed", .ok = "ok" },
    .{ .text = "check for user awesomeness", .ok = "found" },
    .{ .text = "rendering surface", .ok = "ok" },
};

/// The wordmark, in the design's own grid — transcribed from the ANSI-shadow art
/// cell for cell. `#` full block · `=` double horizontal · `!` double vertical ·
/// `1 2 3 4` the four corners (top-left, top-right, bottom-left, bottom-right).
const mark = [_][]const u8{
    "#######2  #####2  ########2 ##2  ##2",
    "3==###14 ##1==##2 3==##1==4 ##!  ##!",
    "  ###14  #######!    ##!    #######!",
    " ###14   ##1==##!    ##!    3====##!",
    "#######2 ##!  ##!    ##!         ##!",
    "3======4 3=4  3=4    3=4         3=4",
};
const mark_rows: i32 = @intCast(mark.len);
const mark_cols: i32 = 36;

comptime {
    // A ragged row would shear the wordmark. The grid is the design; hold it.
    for (mark) |row| std.debug.assert(row.len == mark_cols);
}

/// The AT of ZAT4 — the columns the A and the T occupy in the grid above. Their
/// SHADOW (the line-and-corner cells, not the solid body) is struck in atproto
/// blue; the body stays Zig orange. That is the mockup's exact rule.
const at_col_lo: i32 = 9;
const at_col_hi: i32 = 26;

const noise_glyphs = "@#%&*+=:.-_/\\|<>!?01";

/// How long the whole entrance runs. The shell holds the door until then (or
/// until somebody skips, which they may always do).
pub fn duration() f32 {
    var total: f32 = 0;
    for (boot_log) |l| {
        const n: f32 = @floatFromInt(l.text.len + 4 + l.ok.len); // "text  [ok]"
        total += n * per_char_s + per_line_s;
    }
    return total + hold_after_log_s + resolve_s + hold_after_mark_s;
}

/// The moment a SKIP should jump to: the mark fully settled, with the closing beat
/// still to play. Skipping lands you on the finished wordmark — not on nothing,
/// which would read as a crash rather than an entrance.
pub fn skipTo() f32 {
    return duration() - hold_after_mark_s;
}

/// When the typing ends and the mark begins to precipitate.
fn resolveStart() f32 {
    var total: f32 = 0;
    for (boot_log) |l| {
        const n: f32 = @floatFromInt(l.text.len + 4 + l.ok.len);
        total += n * per_char_s + per_line_s;
    }
    return total + hold_after_log_s;
}

/// PURE: a cheap integer hash → the junk glyph an unresolved cell shows this
/// frame. A hash, not a random number: the entrance must be the same entrance
/// every time it plays, and a test must be able to assert what it drew.
fn noiseAt(r: i32, c: i32, frame: i32) u8 {
    var h: u32 = @bitCast(r *% 73_856_093 ^ c *% 19_349_663 ^ frame *% 83_492_791);
    h ^= h >> 13;
    h *%= 0x5BD1_E995;
    h ^= h >> 15;
    return noise_glyphs[h % noise_glyphs.len];
}

/// PURE: 0 → the cell is still noise, 1 → it has locked. The per-cell threshold is
/// a standing wave across the grid (`sin(r*7.1 + c*3.3)`), so cells lock in a
/// scattered order rather than sweeping left to right. That scatter IS the
/// precipitation.
fn locked(r: i32, c: i32, settle: f32) bool {
    const fr: f32 = @floatFromInt(r);
    const fc: f32 = @floatFromInt(c);
    const threshold = @sin(fr * 7.1 + fc * 3.3) * 0.5 + 0.5;
    return settle > threshold;
}

/// Emit the entrance at time `t` (seconds since it began) into `dl`. No hit
/// regions: there is nothing here to tap — a tap SKIPS, and the shell owns that.
pub fn layout(
    gpa: Allocator,
    e: *const text.Engine,
    w: i32,
    h: i32,
    t: f32,
    dl: *raster.DrawList,
) error{OutOfMemory}!void {
    const cx = @divTrunc(w, 2);
    const cy = @divTrunc(h, 2);
    const rs = resolveStart();

    if (t < rs) {
        try typeLog(gpa, e, cx, cy, t, dl);
        return;
    }
    const settle = @min(1.0, (t - rs) / resolve_s);
    try drawMark(gpa, e, w, cx, cy, settle, t, dl);
}

/// Movement 1 — the log types itself, every line centred on the middle of the
/// screen, so a half-typed line grows outward from its own centre.
fn typeLog(gpa: Allocator, e: *const text.Engine, cx: i32, cy: i32, t: f32, dl: *raster.DrawList) !void {
    const px: u16 = 14;
    const lh: i32 = 22;
    // The finished stack is centred vertically, and it is drawn at its FULL height
    // from the first frame — so the block does not creep upward as lines land.
    const top = cy - @divTrunc(@as(i32, @intCast(boot_log.len)) * lh, 2);

    var elapsed: f32 = 0;
    for (boot_log, 0..) |l, i| {
        const full_len: usize = l.text.len + 4 + l.ok.len; // "text" + "  [" + ok + "]"
        const line_s: f32 = @as(f32, @floatFromInt(full_len)) * per_char_s;
        if (t <= elapsed) break; // this line has not started
        const into = t - elapsed;
        const shown: usize = @min(full_len, @as(usize, @intFromFloat(into / per_char_s)));
        if (shown == 0) break;

        // Split what is currently visible back into the prose and the [ok] tail, so
        // the tail can be struck brighter — a line that has landed should LOOK like
        // it landed.
        var buf: [96]u8 = undefined;
        const composed = std.fmt.bufPrint(&buf, "{s}  [{s}]", .{ l.text, l.ok }) catch continue;
        const vis = composed[0..@min(shown, composed.len)];
        const prose_n = @min(vis.len, l.text.len);
        const prose = vis[0..prose_n];
        const tail = vis[prose_n..];

        const pw: i32 = @intCast(text.measure(e, .regular, prose, px));
        const tw: i32 = @intCast(text.measure(e, .regular, tail, px));
        const y = top + @as(i32, @intCast(i)) * lh;
        var x = cx - @divTrunc(pw + tw, 2);
        x = try fv.str(gpa, dl, e, .regular, x, y, log_dim, px, prose);
        if (tail.len > 0) _ = try fv.str(gpa, dl, e, .regular, x, y, log_ok, px, tail);

        elapsed += line_s + per_line_s;
    }
}

/// Movement 2 — the mark precipitates. Locked cells are struck as the SHAPE the
/// art names (rectangles); unlocked cells are junk glyphs in dead grey.
fn drawMark(gpa: Allocator, e: *const text.Engine, w: i32, cx: i32, cy: i32, settle: f32, t: f32, dl: *raster.DrawList) !void {
    // The mark fills a comfortable share of the width and never overflows a phone.
    const cell: i32 = @max(6, @min(14, @divTrunc(w - 48, mark_cols)));
    const grid_w = mark_cols * cell;
    const grid_h = mark_rows * cell;
    const x0 = cx - @divTrunc(grid_w, 2);
    const y0 = cy - @divTrunc(grid_h, 2);
    const frame: i32 = @intFromFloat(t * 60.0); // the noise churns on the frame clock

    var r: i32 = 0;
    while (r < mark_rows) : (r += 1) {
        const row = mark[@intCast(r)];
        var c: i32 = 0;
        while (c < mark_cols) : (c += 1) {
            const ch: u8 = if (@as(usize, @intCast(c)) < row.len) row[@intCast(c)] else ' ';
            if (ch == ' ') continue; // the negative space stays empty, always

            const x = x0 + c * cell;
            const y = y0 + r * cell;
            if (!locked(r, c, settle)) {
                // Junk text, dead grey, centred in the cell.
                var g: [1]u8 = .{noiseAt(r, c, frame)};
                const gw: i32 = @intCast(text.measure(e, .regular, &g, @intCast(cell)));
                _ = try fv.str(gpa, dl, e, .regular, x + @divTrunc(cell - gw, 2), y + cell - 2, noise_c, @intCast(cell), &g);
                continue;
            }
            try inkCell(gpa, dl, x, y, cell, ch, colourFor(c, ch));
        }
    }
}

/// The AT's shadow is blue; everything else is Zig orange. (The mockup's rule
/// exactly: within the A/T columns, the LINE cells — not the solid body — carry
/// the atproto colour, so the two letters are lit from the protocol side.)
fn colourFor(c: i32, ch: u8) u32 {
    const in_at = c >= at_col_lo and c <= at_col_hi;
    return if (in_at and ch != '#') atproto_blue else zig_orange;
}

/// One inked cell, rasterized from the shape its art character names. A block is a
/// rectangle; a double-line is a bar; a corner is the two bars that meet there.
fn inkCell(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, cell: i32, ch: u8, col: u32) !void {
    const bar = @max(2, @divTrunc(cell * 3, 10)); // the line weight
    const mid = @divTrunc(cell - bar, 2); // where a bar sits within the cell
    const half = mid + bar; // a corner's arm reaches past the middle

    switch (ch) {
        '#' => try fv.rect(gpa, dl, x, y, cell, cell, col, 0),
        '=' => try fv.rect(gpa, dl, x, y + mid, cell, bar, col, 0),
        '!' => try fv.rect(gpa, dl, x + mid, y, bar, cell, col, 0),
        // Corners: the horizontal arm runs to the cell's centre, the vertical arm
        // away from it — so adjacent cells join into one continuous outline.
        '1' => { // ╔ top-left
            try fv.rect(gpa, dl, x + mid, y + mid, cell - mid, bar, col, 0);
            try fv.rect(gpa, dl, x + mid, y + mid, bar, cell - mid, col, 0);
        },
        '2' => { // ╗ top-right
            try fv.rect(gpa, dl, x, y + mid, half, bar, col, 0);
            try fv.rect(gpa, dl, x + mid, y + mid, bar, cell - mid, col, 0);
        },
        '3' => { // ╚ bottom-left
            try fv.rect(gpa, dl, x + mid, y + mid, cell - mid, bar, col, 0);
            try fv.rect(gpa, dl, x + mid, y, bar, half, col, 0);
        },
        '4' => { // ╝ bottom-right
            try fv.rect(gpa, dl, x, y + mid, half, bar, col, 0);
            try fv.rect(gpa, dl, x + mid, y, bar, half, col, 0);
        },
        else => {},
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "boot_intro: the entrance is deterministic, and it ENDS" {
    const gpa = std.testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);

    // It has a finite length, and a skip lands ON the settled mark — never on a
    // blank screen, which would read as a crash rather than an entrance.
    try std.testing.expect(duration() > 1.0);
    try std.testing.expect(skipTo() < duration());
    try std.testing.expect(skipTo() > resolveStart());

    // Same t ⇒ same pixels (no clock, no RNG in here — B2/B4).
    var a: raster.DrawList = .{};
    defer a.deinit(gpa);
    var b: raster.DrawList = .{};
    defer b.deinit(gpa);
    try layout(gpa, &engine, 430, 930, 1.2, &a);
    try layout(gpa, &engine, 430, 930, 1.2, &b);
    try std.testing.expectEqual(a.len, b.len);

    // Every stage of the entrance draws SOMETHING. A frame of the boot animation
    // that emits nothing is a black screen somebody will read as a hang.
    for ([_]f32{ 0.05, 1.0, 2.5, resolveStart() + 0.01, resolveStart() + 0.35, duration() }) |t| {
        var dl: raster.DrawList = .{};
        defer dl.deinit(gpa);
        try layout(gpa, &engine, 430, 930, t, &dl);
        try std.testing.expect(dl.len > 0);
    }
}

test "boot_intro: the mark precipitates — scattered, not swept" {
    // At a mid settle, SOME cells have locked and some have not (a wipe would have
    // a clean boundary; this must not).
    var early: u32 = 0;
    var late: u32 = 0;
    var r: i32 = 0;
    while (r < mark_rows) : (r += 1) {
        var c: i32 = 0;
        while (c < mark_cols) : (c += 1) {
            if (locked(r, c, 0.5)) early += 1 else late += 1;
        }
    }
    try std.testing.expect(early > 0);
    try std.testing.expect(late > 0);

    // And by the end, everything is locked.
    r = 0;
    while (r < mark_rows) : (r += 1) {
        var c: i32 = 0;
        while (c < mark_cols) : (c += 1) {
            try std.testing.expect(locked(r, c, 1.001));
        }
    }
}

test "boot_intro: the AT is struck in atproto blue, the rest in Zig orange" {
    // The colour carries the sentence "a Zig program speaking AT Protocol". If this
    // ever silently becomes one colour, the wordmark has stopped saying anything.
    try std.testing.expectEqual(zig_orange, colourFor(0, '#')); // the Z's body
    try std.testing.expectEqual(zig_orange, colourFor(at_col_lo, '#')); // the A's body
    try std.testing.expectEqual(atproto_blue, colourFor(at_col_lo, '2')); // the A's shadow
    try std.testing.expectEqual(atproto_blue, colourFor(at_col_hi, '!')); // the T's shadow
    try std.testing.expectEqual(zig_orange, colourFor(at_col_hi + 1, '!')); // past it: the 4
}
