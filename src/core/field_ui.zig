//! B1 classification: CORE (pure). The glyph-grid timeline — the G.0
//! cutover (GLYPH_FIELD_SYSTEM_DESIGN §10): layout writing the feed into
//! field.zig's CONTENT grid as a monospace glyph surface, the form the
//! whole simulation acts on.
//!
//! This replaces the proportional card body (timeline_ui pixel path /
//! layout.buildTimeline) for the window. The trade is deliberate and
//! owner-approved: a monospace grid is what buys O(1) particle/cell
//! collision (a particle's cell is one floor + index), and it is the
//! literal thesis — "a single grid of glyph cells, all obeying the same
//! physics." Card chrome survives as `fixed`/divider cells the physics
//! treats as immovable scenery (§4).
//!
//! What this module decides (D1: the look): row layout, where the
//! handle/age/counts sit, the divider seams, which cells are
//! interactive, and — crucially — the SCREEN POSITION of each post's
//! like glyph, so the shell can fire an effect there (the heart blooms
//! exactly where the eye is). What it does NOT decide: pixels (compose
//! does that), physics (field.step), or what a "like" means (the shell).
//!
//! Pure (B2): same (items, selection, scroll, dims) ⇒ same grid + same
//! hit rects. Golden-testable headless, no window. The content grid is
//! rewritten wholesale each frame (immediate mode), so scroll/resize/
//! relayout are automatic — exactly as the pixel path already proved.

const std = @import("std");
const assert = std.debug.assert;
const testing = std.testing;
const Allocator = std.mem.Allocator;
const field = @import("field.zig");
const feed = @import("feed.zig");
const moderation = @import("moderation.zig");
const timeline_ui = @import("timeline_ui.zig");
const effect = @import("effect.zig");

/// Palette indices into field.palette (kept in lockstep with it).
pub const col_dim: u8 = 0;
pub const col_ink: u8 = 1;
pub const col_accent: u8 = 2;
pub const col_boost: u8 = 3;
pub const col_like: u8 = 4;
pub const col_faint: u8 = 5;

/// A clickable region in GRID cells (not pixels). HOT — one per
/// interactive element per frame, SoA via HitList → A7. `target` is the
/// row index into this frame's items; it dies with the frame (A5 — the
/// shell converts it to selection/CID immediately). `fx`/`fy` carry the
/// screen-cell ORIGIN an effect should fire from when this zone is hit
/// (e.g. the centre of the like glyph), so the heart blooms on the tap.
pub const HitRect = struct {
    x: u16,
    y: u16,
    w: u16,
    h: u16,
    fx: u16, // effect origin x (grid cell)
    fy: u16, // effect origin y (grid cell)
    action: u16, // @intFromEnum(timeline_ui.Action)
    target: u32,

    comptime {
        // Budget: 6×u16 (x,y,w,h,fx,fy) + 1×u16 (action) + 1×u32
        // (target) = 14 + 4 = 18 payload → 20 with u32 alignment. Exact.
        // Raising this requires an A7.1 justification here.
        assert(@sizeOf(HitRect) == 20);
    }
};

pub const HitList = std.MultiArrayList(HitRect);
pub const no_target: u32 = std.math.maxInt(u32);

/// One inline heart-button placement: the cell the heart sprite occupies
/// and whether the post is liked. The owner's model — the like button IS
/// the heart — so layout RESERVES the heart's cells and records this, and
/// the premium feed layer (feed_view) draws the heart icon at (x,y);
/// this slot records its cell so a like animation/burst can originate
/// there. HOT (one per visible post, scanned each frame) → A7 guard.
pub const HeartSlot = struct {
    x: u16, // grid cell of the heart's left edge
    y: u16, // grid cell row of the heart
    target: u32, // post index this heart belongs to
    liked: bool,

    comptime {
        // Budget: 2×u16 (x,y) + 1×u32 (target) + 1 bool = 4 + 4 + 1 = 9
        // → 12 with u32 alignment (3 bytes pad). Exact.
        assert(@sizeOf(HeartSlot) == 12);
    }
};
pub const HeartList = std.MultiArrayList(HeartSlot);

/// A resolved click. A7.2: cold, waived — returned by value.
pub const Hit = struct {
    action: timeline_ui.Action,
    target: u32,
    /// Where the effect for this hit should originate (grid cells).
    fx: u16,
    fy: u16,
};

/// Pure (B2): grid point + this frame's rects ⇒ topmost hit (zones are
/// pushed after their card, so the scan runs in reverse).
pub fn hitTest(x: u16, y: u16, rects: HitList.Slice) ?Hit {
    const xs = rects.items(.x);
    const ys = rects.items(.y);
    const ws = rects.items(.w);
    const hs = rects.items(.h);
    const fxs = rects.items(.fx);
    const fys = rects.items(.fy);
    const actions = rects.items(.action);
    const targets = rects.items(.target);
    var i: usize = rects.len;
    while (i > 0) {
        i -= 1;
        if (x >= xs[i] and x < xs[i] + ws[i] and y >= ys[i] and y < ys[i] + hs[i]) {
            return .{ .action = @enumFromInt(actions[i]), .target = targets[i], .fx = fxs[i], .fy = fys[i] };
        }
    }
    return null;
}

/// Scroll/selection state for the grid timeline. A7.2: cold, waived —
/// one per window. Scroll is in WHOLE ROWS (the grid is discrete).
pub const ViewState = struct {
    scroll_rows: i32 = 0,
    hover: u32 = no_target,
    ensure_selected: bool = false,
};

/// What one frame's layout learned. A7.2: cold, waived.
pub const Metrics = struct {
    content_rows: u32,
};

/// A horizontal column band: the left origin and width, in grid cells.
/// The center feed renders into one of these instead of assuming it owns
/// the whole field (SHELL_LAYOUT_ROADMAP S.0) — the seam that lets the
/// same `build` fill a sub-width column. A7.2: cold, passed by value, one
/// per pane per frame; never held in a hot loop.
pub const Band = struct {
    x0: u16,
    w: u16,
};

/// Pane widths for the three-column shell, as a config VALUE (the
/// roadmap's §0 commitment 1: layout is a pure function of data + dims,
/// pane widths as config, never cached). Center width is whatever is left
/// after the two rails and the two divider seams. A7.2: cold config, one
/// per shell, never in a hot loop — size guard waived by rule.
pub const PaneConfig = struct {
    nav_w: u16 = 22,
    sidebar_w: u16 = 28,
    /// Below this total width the shell collapses to center-only — an
    /// ordinary result (E4), not an error.
    min_three_col_w: u16 = 80,
};

const header_rows: u16 = 2;

/// How many grid rows one post occupies, given the wrap width. Pure;
/// shared by the measure pass and the emit pass so they never disagree.
fn cardRows(item: feed.TimelineItem, text_w: u16, revealed: []const []const u8) u16 {
    if (moderation.verdictFor(item.label_flags) == .hide and !isRevealed(revealed, item.cid))
        return 3; // collapsed: blank, "hidden…", blank
    var rows: u16 = 0;
    if (item.reposted_by_handle.len > 0) rows += 1; // repost line
    rows += 1; // author row
    if (item.replying_to_handle.len > 0) rows += 1; // reply context
    rows += wrapRows(item.text, text_w); // body
    rows += 1; // engagement row
    rows += 1; // seam divider
    return rows;
}

fn wrapRows(text: []const u8, width: u16) u16 {
    if (text.len == 0) return 1;
    if (width == 0) return 1;
    var rows: u16 = 0;
    var rest = text;
    while (rest.len > 0) {
        const n = wrapOne(rest, width);
        rows += 1;
        rest = rest[@max(n, 1)..];
    }
    return @max(rows, 1);
}

/// Greedy character wrap (monospace: one glyph = one cell). Returns the
/// byte length of the next line of `str` fitting `width` cells.
fn wrapOne(str: []const u8, width: u16) usize {
    if (str.len <= width) {
        // Still honour an embedded newline.
        if (std.mem.indexOfScalar(u8, str, '\n')) |nl| return nl + 1;
        return str.len;
    }
    if (std.mem.indexOfScalar(u8, str[0..width], '\n')) |nl| return nl + 1;
    var i: usize = width;
    while (i > 0) : (i -= 1) {
        if (str[i - 1] == ' ') return i;
    }
    return width; // a single long word: hard split
}

fn isRevealed(revealed: []const []const u8, cid: []const u8) bool {
    for (revealed) |r| if (std.mem.eql(u8, r, cid)) return true;
    return false;
}

/// Saturating left-pad for hit zones: widen a zone leftward without
/// underflowing u16 at the screen edge.
fn sub(x: u16, n: u16) u16 {
    return if (x > n) x - n else 0;
}

/// Build the timeline into the field's content grid and produce hit
/// rects. Pure over its inputs; mutates the field's content (rewritten
/// wholesale) and the view's scroll (clamped + one-shot ensure-visible).
/// The perturb grid is LEFT ALONE — physics persists across relayout by
/// living in screen space (design §7).
///
/// This is the full-field entry point: it clears the content grid and
/// renders the feed across the whole width, exactly as before. It now
/// delegates to `buildBand` (the seam, SHELL_LAYOUT_ROADMAP S.0) with a
/// band spanning the entire field, so every existing caller and golden
/// test is byte-for-byte unchanged.
pub fn build(
    f: *field.Field,
    hr: *HitList,
    hearts: *HeartList,
    items: []const feed.TimelineItem,
    selected: u32,
    view: *ViewState,
    revealed: []const []const u8,
    now: i64,
    account_handle: []const u8,
    status: []const u8,
    gpa: Allocator,
) error{OutOfMemory}!Metrics {
    // Clear content only (perturb persists — §7). The banded builder does
    // NOT clear, so the shell can paint multiple bands into one grid; the
    // full-field path clears here, once, then fills the whole width.
    @memset(f.content, field.ContentCell.empty);
    hr.clearRetainingCapacity();
    hearts.clearRetainingCapacity();
    return buildBand(f, .{ .x0 = 0, .w = f.cols }, hr, hearts, items, selected, view, revealed, now, account_handle, status, gpa);
}

/// Render the feed into one column `band` of the content grid. Pure (B2):
/// same (band, items, selection, scroll, dims) ⇒ same cells + same hit
/// rects within the band. Does NOT clear the grid or the hit list — the
/// caller owns that, so the shell can compose this band beside a nav rail
/// and a sidebar in the same frame (SHELL_LAYOUT_ROADMAP S.0/S.1). All
/// horizontal positions are derived from `band.x0`/`band.w`; the grid's
/// true stride (f.cols) is untouched, so cells land in the right column.
pub fn buildBand(
    f: *field.Field,
    band: Band,
    hr: *HitList,
    hearts: *HeartList,
    items: []const feed.TimelineItem,
    selected: u32,
    view: *ViewState,
    revealed: []const []const u8,
    now: i64,
    account_handle: []const u8,
    status: []const u8,
    gpa: Allocator,
) error{OutOfMemory}!Metrics {
    const rows = f.rows;
    if (band.w < 24 or rows < 6) return .{ .content_rows = 0 };

    const margin: u16 = 2;
    const left: u16 = band.x0 + margin; // content's left column in the band
    const right: u16 = band.x0 + band.w; // right clip / right-anchored origin
    const text_w: u16 = band.w - margin * 2;

    // ---- header (fixed; never scrolls, never moves under physics) ----
    writeFixed(f, left, 0, col_accent, "zat");
    if (account_handle.len > 0) {
        var hb: [96]u8 = undefined;
        const h = std.fmt.bufPrint(&hb, "@{s}", .{account_handle}) catch "@";
        writeFixed(f, left + 4, 0, col_dim, h);
    }
    var tally_buf: [24]u8 = undefined;
    const tally = std.fmt.bufPrint(&tally_buf, "{d} posts", .{items.len}) catch "";
    if (band.x0 + tally.len < right) writeFixed(f, right - margin - @as(u16, @intCast(tally.len)), 0, col_faint, tally);
    fixedDivider(f, 1, col_faint, '=');

    // ---- measure pass: heights, selection position, total extent ----
    var content_rows: u32 = header_rows;
    var sel_top: u32 = content_rows;
    var sel_h: u16 = 0;
    for (items, 0..) |item, i| {
        const ch = cardRows(item, text_w, revealed);
        if (i == selected) {
            sel_top = content_rows;
            sel_h = ch;
        }
        content_rows += ch;
    }
    content_rows += 1; // load-older row

    // ---- scroll resolution (whole rows) ----
    const max_scroll: i32 = @intCast(content_rows -| rows);
    if (view.ensure_selected and items.len > 0) {
        view.ensure_selected = false;
        const top: i32 = @intCast(sel_top);
        const bottom: i32 = top + sel_h;
        if (top - 1 < view.scroll_rows) view.scroll_rows = top - 1;
        if (bottom + 1 > view.scroll_rows + @as(i32, rows)) view.scroll_rows = bottom + 1 - @as(i32, rows);
    }
    view.scroll_rows = @max(0, @min(view.scroll_rows, @max(0, max_scroll)));
    const scroll = view.scroll_rows;

    if (items.len == 0) {
        writeText(f, left, rows / 2, col_dim, "timeline is empty - press r to refresh");
        return .{ .content_rows = content_rows };
    }

    // ---- emit pass: only rows intersecting the viewport ----
    var y: i32 = @as(i32, header_rows) - scroll;
    for (items, 0..) |item, idx| {
        const i: u32 = @intCast(idx);
        const ch = cardRows(item, text_w, revealed);
        const card_top = y;
        defer y += ch;
        if (card_top + @as(i32, ch) <= header_rows or card_top >= rows) continue; // culled

        const is_sel = i == selected;
        const body_col: u8 = if (is_sel) col_ink else col_dim;

        // Whole-card hit (select); its effect origin is the card centre.
        appendHit(gpa, hr, left, card_top, text_w, ch, .none, i, right, rows, header_rows, @intCast(left + text_w / 2), card_top + @divTrunc(ch, 2));

        var row = card_top;
        if (moderation.verdictFor(item.label_flags) == .hide and !isRevealed(revealed, item.cid)) {
            var hb: [128]u8 = undefined;
            const label = std.fmt.bufPrint(&hb, "hidden: {s} - click to show", .{moderation.reasonFor(item.label_flags)}) catch "hidden - click to show";
            putRow(f, left, row + 1, col_faint, label, right, rows);
            appendHit(gpa, hr, left, card_top, text_w, ch, .toggle_reveal, i, right, rows, header_rows, 0, 0);
            continue;
        }

        // Selection marker at the band's left edge.
        if (is_sel) {
            var r = card_top;
            while (r < card_top + ch - 1) : (r += 1) putCell(f, band.x0, r, col_accent, '|', right, rows, .{ .fixed = true });
        }

        if (item.reposted_by_handle.len > 0) {
            var rb: [128]u8 = undefined;
            const line = std.fmt.bufPrint(&rb, "reposted by @{s}", .{item.reposted_by_handle}) catch "reposted";
            putRow(f, left, row, col_boost, line, right, rows);
            row += 1;
        }

        // Author row: name + handle left, age right.
        {
            var nb: [192]u8 = undefined;
            const name = if (item.author_display_name.len > 0)
                std.fmt.bufPrint(&nb, "{s} @{s}", .{ item.author_display_name, item.author_handle }) catch item.author_handle
            else
                std.fmt.bufPrint(&nb, "@{s}", .{item.author_handle}) catch "@";
            putRow(f, left, row, if (is_sel) col_accent else col_ink, name, right, rows);
            var ab: [16]u8 = undefined;
            const age = timeline_ui.formatAge(&ab, now, item.created_at);
            if (band.x0 + age.len + margin < right) putRow(f, right - margin - @as(u16, @intCast(age.len)), row, col_faint, age, right, rows);
            row += 1;
        }

        if (item.replying_to_handle.len > 0) {
            var rb: [128]u8 = undefined;
            const line = std.fmt.bufPrint(&rb, "replying to @{s}", .{item.replying_to_handle}) catch "replying";
            putRow(f, left, row, col_faint, line, right, rows);
            row += 1;
        }

        // Body, wrapped.
        {
            var rest = item.text;
            if (rest.len == 0) {
                row += 1;
            } else while (rest.len > 0) {
                const n = wrapOne(rest, text_w);
                const line = std.mem.trimEnd(u8, rest[0..n], "\n");
                putRow(f, left, row, body_col, line, right, rows);
                row += 1;
                rest = rest[@max(n, 1)..];
            }
        }

        // Engagement row: like / boost / reply. The like button IS the
        // heart (the owner's model): layout RESERVES the inline heart's
        // cells and records a HeartSlot; the premium feed layer draws the
        // heart icon there. The SAME heart fills and bursts in place on
        // click, so the hit target and the effect origin both point at
        // the heart's own cell, not the card centre.
        {
            const zrow: i32 = row;
            var x = left;
            const liked = item.item_flags.viewer_liked;
            const heart_w = effect.inlineHeartCellW();

            // Record the heart placement; reserve its cells (leave them
            // blank — the sprite draws over them in the shell). Vertically
            // the heart centres on this single row.
            try hearts.append(gpa, .{ .x = x, .y = @intCast(@max(0, zrow)), .target = i, .liked = liked });
            const heart_cx = x; // effect origin = the heart's own cell
            const heart_cy: u16 = @intCast(@max(0, zrow));
            x += heart_w + 1; // heart, then a gap before the count

            // The like count, after the heart.
            var lb: [24]u8 = undefined;
            const like_s = std.fmt.bufPrint(&lb, "{d}", .{item.like_count}) catch "0";
            putRow(f, x, zrow, if (liked) col_like else col_dim, like_s, right, rows);
            // Hit target spans the heart AND its count, so the whole
            // affordance is clickable, but anchored on the heart. Effect
            // origin is the heart cell → the burst happens at the button.
            // Height is 2, not 1: the heart sprite is centred on this row but
            // drawn ~1.4 cell-rows tall, so its bottom spills ~0.4 of a row
            // into the cell below. With a 1-row target those clicks landed
            // just under the rect and silently missed ("sometimes a click
            // doesn't like"). The row directly below is the seam divider,
            // which carries no other affordance, so claiming it for the heart
            // costs nothing and makes the visible heart fully clickable.
            const target_w: u16 = heart_w + 1 + @as(u16, @intCast(like_s.len)) + 1;
            appendHit(gpa, hr, left, zrow, target_w, 2, .like, i, right, rows, header_rows, heart_cx, heart_cy);
            x += @intCast(like_s.len + 3);

            var bb: [32]u8 = undefined;
            const boost_s = std.fmt.bufPrint(&bb, "rt {d}", .{item.repost_count}) catch "rt";
            putRow(f, x, zrow, if (item.item_flags.viewer_reposted) col_boost else col_dim, boost_s, right, rows);
            appendHit(gpa, hr, sub(x, 2), zrow, @intCast(boost_s.len + 4), 1, .repost, i, right, rows, header_rows, x, zrow);
            x += @intCast(boost_s.len + 3);

            var pb: [32]u8 = undefined;
            const reply_s = std.fmt.bufPrint(&pb, "re {d}", .{item.reply_count}) catch "re";
            putRow(f, x, zrow, col_dim, reply_s, right, rows);
            appendHit(gpa, hr, sub(x, 2), zrow, @intCast(reply_s.len + 4), 1, .reply, i, right, rows, header_rows, x, zrow);
            row += 1;
        }

        // Seam divider between cards (scatter-able scenery).
        if (row >= header_rows and row < rows) {
            var dx: u16 = left;
            while (dx < right - margin) : (dx += 1) putCell(f, dx, row, col_faint, '-', right, rows, .{ .divider = true });
        }
    }

    // Load-older row at content bottom.
    {
        const ly: i32 = @as(i32, @intCast(content_rows - 1)) - scroll;
        if (ly >= header_rows and ly < rows) {
            const label = "load older posts";
            const lx: u16 = if (label.len < band.w) band.x0 + @as(u16, @intCast((band.w - label.len) / 2)) else left;
            putRow(f, lx, ly, col_faint, label, right, rows);
            appendHit(gpa, hr, left, ly, text_w, 1, .load_more, no_target, right, rows, header_rows, 0, 0);
        }
    }

    // Status pill text, bottom-right (chrome — fixed).
    if (status.len > 0 and band.x0 + status.len + margin < right) {
        writeFixed(f, right - margin - @as(u16, @intCast(status.len)), rows - 1, col_accent, status);
    }

    return .{ .content_rows = content_rows };
}

// ---------------------------------------------------------------------------
// The three-column shell (SHELL_LAYOUT_ROADMAP S.1–S.3). One pure carve
// over the field, plus two rail helpers. No new module (F4): this is the
// same kind of work `buildBand` does — a transform filling the grid. The
// look is the renderer's sealed decision (D1); a layout change is one
// vertical slice (D6).
// ---------------------------------------------------------------------------

/// Carve the field into nav rail · center feed · sidebar and fill each.
/// Pure (B2): same (items, selection, scroll, dims, config) ⇒ same grid +
/// same hit rects. Clears the grid and hit/heart lists once, writes the
/// two vertical divider seams as fixed scenery, delegates the center to
/// `buildBand`, and the rails to the helpers below. Below the config's
/// three-column threshold it collapses to the full-width feed — an
/// ordinary result (E4), not an error.
///
/// The seam columns are `fixed` (physics treats them as immovable
/// scenery, GLYPH_FIELD §4), so the rails read as separated panes that
/// the simulation still flows around.
pub fn layoutShell(
    f: *field.Field,
    cfg: PaneConfig,
    hr: *HitList,
    hearts: *HeartList,
    items: []const feed.TimelineItem,
    selected: u32,
    view: *ViewState,
    revealed: []const []const u8,
    now: i64,
    account_handle: []const u8,
    status: []const u8,
    gpa: Allocator,
) error{OutOfMemory}!Metrics {
    @memset(f.content, field.ContentCell.empty);
    hr.clearRetainingCapacity();
    hearts.clearRetainingCapacity();

    const cols = f.cols;

    // Collapse to center-only when too narrow to seat three columns plus
    // their seams and gutters (E4: an ordinary result, the narrow layout).
    if (cols < cfg.min_three_col_w) {
        return buildBand(f, .{ .x0 = 0, .w = cols }, hr, hearts, items, selected, view, revealed, now, account_handle, status, gpa);
    }

    // Three bands: [nav][seam][center][seam][sidebar]. The two seams take
    // one column each; the center is whatever remains.
    const nav_w = cfg.nav_w;
    const side_w = cfg.sidebar_w;
    const seam_l: u16 = nav_w; // first divider column
    const center_x: u16 = nav_w + 1;
    const center_w: u16 = cols - nav_w - side_w - 2; // minus two seam cols
    const seam_r: u16 = center_x + center_w; // second divider column
    const side_x: u16 = seam_r + 1;

    // The two vertical seams as fixed/divider scenery.
    seamColumn(f, seam_l, col_faint, '|');
    seamColumn(f, seam_r, col_faint, '|');

    // Left rail and right sidebar (static glyph panes for now).
    layoutNavRail(gpa, f, .{ .x0 = 0, .w = nav_w }, hr, account_handle);
    layoutSidebar(f, .{ .x0 = side_x, .w = side_w });

    // Center feed: the same `buildBand`, now inset between the seams.
    return buildBand(f, .{ .x0 = center_x, .w = center_w }, hr, hearts, items, selected, view, revealed, now, account_handle, status, gpa);
}

/// One full-height vertical divider seam at column `x` (fixed scenery).
fn seamColumn(f: *field.Field, x: u16, fg: u8, glyph: u8) void {
    if (x >= f.cols) return;
    var y: u16 = 0;
    while (y < f.rows) : (y += 1) {
        f.content[field.index(f, x, y)] = .{ .glyph = glyph, .fg = fg, .flags = .{ .fixed = true, .divider = true } };
    }
}

/// The left nav rail (S.2): wordmark, a column of destinations, and a
/// compose affordance — each interactive row pushes a `HitRect` carrying
/// a nav action, so the rail inherits hit-testing and the simulation for
/// free. Destinations with no screen yet emit a nav action that resolves
/// to a no-op click until Phase D wires it (timeline_ui.keyFor returns
/// null for those); Home/Profile/Compose emit the real refresh/profile/
/// new_post verbs and work today.
fn layoutNavRail(
    gpa: Allocator,
    f: *field.Field,
    band: Band,
    hr: *HitList,
    account_handle: []const u8,
) void {
    const margin: u16 = 2;
    const left: u16 = band.x0 + margin;
    const right: u16 = band.x0 + band.w;
    const rows = f.rows;

    // Wordmark header, aligned with the feed's (fixed chrome).
    writeFixed(f, left, 0, col_accent, "zat4");

    // The destination list. Each row is (glyph label, action). Real verbs
    // (refresh/profile/new_post) work now; nav_* are stubs until Phase D.
    const Dest = struct { label: []const u8, action: timeline_ui.Action };
    const dests = [_]Dest{
        .{ .label = "home", .action = .refresh },
        .{ .label = "explore", .action = .nav_explore },
        .{ .label = "notifications", .action = .nav_notifications },
        .{ .label = "chat", .action = .nav_chat },
        .{ .label = "feeds", .action = .nav_feeds },
        .{ .label = "lists", .action = .nav_lists },
        .{ .label = "profile", .action = .profile },
        .{ .label = "settings", .action = .nav_settings },
    };

    var y: u16 = 3;
    for (dests) |d| {
        if (y >= rows - 2) break; // keep clear of the compose row + footer
        // Inactive destinations sit at `dim`, not `ink`: in a minimal dark
        // shell the rail recedes so the centre feed carries the eye. The
        // accent is reserved for the compose affordance below.
        putRow(f, left, y, col_dim, d.label, right, rows);
        appendHit(gpa, hr, band.x0, y, band.w, 1, d.action, no_target, right, rows, header_rows, left, y);
        y += 1;
    }

    // Compose affordance, pinned near the bottom of the rail.
    if (rows >= 4) {
        const cy: u16 = rows - 2;
        putRow(f, left, cy, col_accent, "+ new post", right, rows);
        appendHit(gpa, hr, band.x0, cy, band.w, 1, .new_post, no_target, right, rows, header_rows, left, cy);
    }

    // Signed-in handle at the very bottom (fixed chrome), if known.
    if (account_handle.len > 0 and rows >= 2) {
        var hb: [96]u8 = undefined;
        const h = std.fmt.bufPrint(&hb, "@{s}", .{account_handle}) catch "@";
        writeFixed(f, left, rows - 1, col_faint, h);
    }
}

/// The right sidebar (S.3): a search row, a stubbed feed list, and a
/// stubbed trending block. Deliberately static and data-free (F4) —
/// trending has no clean data source decided yet, so it is placeholder
/// glyphs until a real source emerges. No hit rects: nothing here is
/// wired to act on yet.
fn layoutSidebar(f: *field.Field, band: Band) void {
    const margin: u16 = 2;
    const left: u16 = band.x0 + margin;
    const right: u16 = band.x0 + band.w;
    const rows = f.rows;
    if (band.w < 8 or rows < 6) return;

    // Search sits in the reserved header band as fixed chrome (putRow
    // declines rows 0–1 by design, so the search label uses writeFixed).
    writeFixed(f, left, 0, col_dim, "search");

    var y: u16 = 3;
    if (y < rows) {
        putRow(f, left, y, col_faint, "your feeds", right, rows);
        y += 1;
    }
    const feeds = [_][]const u8{ "- discover", "- following", "- science" };
    for (feeds) |label| {
        if (y >= rows - 1) break;
        putRow(f, left, y, col_dim, label, right, rows);
        y += 1;
    }

    y += 1;
    if (y < rows) {
        putRow(f, left, y, col_faint, "trending", right, rows);
        y += 1;
    }
    const trends = [_][]const u8{ "#zig", "#atproto", "#zat4" };
    for (trends) |label| {
        if (y >= rows - 1) break;
        putRow(f, left, y, col_dim, label, right, rows);
        y += 1;
    }
}


/// Where the text cursor sits, in grid cells — returned by buildCompose
/// so the shell can draw the blinking block at the insertion point.
/// A7.2: cold, returned by value.
pub const Cursor = struct { x: u16, y: u16 };

/// Build the COMPOSER into the field's content grid — the glyph-field
/// counterpart to the timeline's build(), so writing a post looks like
/// the rest of the app instead of the retired cell surface. Pure (B2):
/// same (text, reply target, dims) ⇒ same grid + same cursor. The
/// composer's characters are real field cells, so the same physics/
/// effects could later play here (a post "landing" with a ripple) — the
/// one-grid thesis pays off again. Returns the cursor cell for the shell
/// to render. The perturb grid is left alone (transient, §7).
pub fn buildCompose(
    f: *field.Field,
    text: []const u8,
    reply_to_handle: []const u8,
    char_count: usize,
    status: []const u8,
) Cursor {
    @memset(f.content, field.ContentCell.empty);
    const cols = f.cols;
    const rows = f.rows;
    if (cols < 16 or rows < 6) return .{ .x = 0, .y = 0 };

    const margin: u16 = 2;

    // Header: "zat — new post" or "zat — reply to @handle" (fixed chrome).
    writeFixed(f, margin, 0, col_accent, "zat");
    if (reply_to_handle.len > 0) {
        var hb: [128]u8 = undefined;
        const h = std.fmt.bufPrint(&hb, "- reply to @{s}", .{reply_to_handle}) catch "- reply";
        writeFixed(f, margin + 4, 0, col_dim, h);
    } else {
        writeFixed(f, margin + 4, 0, col_dim, "- new post");
    }
    fixedDivider(f, 1, col_faint, '=');

    // Body: the draft text, wrapped, starting at row 3. Track the cursor
    // as the end of the last laid-out line (or the placeholder origin).
    const text_x: u16 = margin;
    const text_w: u16 = if (cols > text_x + margin) cols - text_x - margin else 1;
    const body_top: u16 = 3;
    var cursor: Cursor = .{ .x = text_x, .y = body_top };

    if (text.len == 0) {
        putRow(f, text_x, body_top, col_faint, "say something...", cols, rows);
        // cursor sits at the start, before the placeholder.
    } else {
        var y: i32 = body_top;
        var rest = text;
        var last_w: u16 = 0;
        const footer_guard: i32 = @as(i32, rows) - 3; // keep clear of counter/footer
        while (rest.len > 0 and y < footer_guard) {
            const n = wrapOne(rest, text_w);
            const line = std.mem.trimEnd(u8, rest[0..n], "\n");
            putRow(f, text_x, y, col_ink, line, cols, rows);
            cursor.y = @intCast(y);
            last_w = dispWidth(line);
            y += 1;
            rest = rest[@max(n, 1)..];
        }
        cursor.x = text_x + last_w;
        // A trailing newline drops the cursor to a fresh line.
        if (text[text.len - 1] == '\n' and y < footer_guard) {
            cursor.y = @intCast(y);
            cursor.x = text_x;
        }
    }

    // Character counter, bottom-right above the footer (fixed chrome).
    var cb: [24]u8 = undefined;
    const counter = std.fmt.bufPrint(&cb, "{d}/300", .{char_count}) catch "";
    const over = char_count > 300;
    if (counter.len + margin < cols) {
        writeFixed(f, cols - margin - @as(u16, @intCast(counter.len)), rows - 2, if (over) col_like else col_faint, counter);
    }

    // Footer: key hints, plus any status (fixed chrome).
    fixedDivider(f, rows - 1, col_faint, ' ');
    writeFixed(f, margin, rows - 1, col_dim, "ctrl-d send   esc cancel");
    if (status.len > 0 and status.len + margin < cols) {
        writeFixed(f, cols - margin - @as(u16, @intCast(status.len)), rows - 1, col_accent, status);
    }

    return cursor;
}

/// Monospace display width: one cell per byte is wrong for UTF-8, so
/// count codepoints (the grid advances one cell per codepoint). ASCII
/// fast path dominates; this only matters for multi-byte runs.
fn dispWidth(line: []const u8) u16 {
    var w: u16 = 0;
    var i: usize = 0;
    while (i < line.len) {
        const len = std.unicode.utf8ByteSequenceLength(line[i]) catch 1;
        i += len;
        w += 1;
    }
    return w;
}

/// Build the PROFILE view into the field's content grid — the
/// glyph-field counterpart to buildProfileFrame, so a profile looks like
/// the rest of the app. Pure (B2): same (info, dims) ⇒ same grid. Header,
/// display name, @handle (+ "following" marker), the counts line, the
/// wrapped bio, and a footer — all field cells via the shared writers.
pub fn buildProfile(
    f: *field.Field,
    info: timeline_ui.ProfileInfo,
    status: []const u8,
) void {
    @memset(f.content, field.ContentCell.empty);
    const cols = f.cols;
    const rows = f.rows;
    if (cols < 16 or rows < 6) return;
    const margin: u16 = 2;

    writeFixed(f, margin, 0, col_accent, "zat");
    writeFixed(f, margin + 4, 0, col_dim, "- profile");
    if (status.len > 0 and status.len + margin < cols) {
        writeFixed(f, cols - margin - @as(u16, @intCast(status.len)), 0, col_accent, status);
    }
    fixedDivider(f, 1, col_faint, '=');

    var y: u16 = 3;
    if (info.display_name.len > 0) {
        putRow(f, margin, y, col_ink, info.display_name, cols, rows);
        y += 1;
    }
    // @handle in accent, optional "· following".
    {
        var hb: [128]u8 = undefined;
        const h = std.fmt.bufPrint(&hb, "@{s}", .{info.handle}) catch "@";
        putRow(f, margin, y, col_accent, h, cols, rows);
        if (info.following) {
            const hw = dispWidth(h);
            putRow(f, margin + hw + 1, y, col_dim, "- following", cols, rows);
        }
        y += 2;
    }

    var cb: [128]u8 = undefined;
    const counts = std.fmt.bufPrint(&cb, "{d} followers - {d} following - {d} posts", .{ info.followers, info.follows, info.posts }) catch "";
    putRow(f, margin, y, col_dim, counts, cols, rows);
    y += 2;

    // Bio, wrapped, stopping clear of the footer.
    const text_w: u16 = if (cols > margin * 2) cols - margin * 2 else 1;
    if (info.description.len > 0) {
        var rest = info.description;
        while (rest.len > 0 and y < rows - 2) {
            const n = wrapOne(rest, text_w);
            const line = std.mem.trimEnd(u8, rest[0..n], "\n");
            putRow(f, margin, y, col_ink, line, cols, rows);
            y += 1;
            rest = rest[@max(n, 1)..];
        }
    }

    fixedDivider(f, rows - 1, col_faint, ' ');
    writeFixed(f, margin, rows - 1, col_dim, "f follow   p close");
}

// ---- cell writers -------------------------------------------------------

fn writeText(f: *field.Field, x: u16, y: u16, fg: u8, str: []const u8) void {
    field.writeText(f, x, y, fg, str);
}

fn writeFixed(f: *field.Field, x: u16, y: u16, fg: u8, str: []const u8) void {
    if (y >= f.rows) return;
    for (str, 0..) |ch, i| {
        const cx = x + i;
        if (cx >= f.cols) break;
        f.content[field.index(f, @intCast(cx), y)] = .{ .glyph = ch, .fg = fg, .flags = .{ .fixed = true } };
    }
}

fn fixedDivider(f: *field.Field, y: u16, fg: u8, glyph: u8) void {
    if (y >= f.rows) return;
    var x: u16 = 0;
    while (x < f.cols) : (x += 1) f.content[field.index(f, x, y)] = .{ .glyph = glyph, .fg = fg, .flags = .{ .fixed = true } };
}

/// A clipped text row (skips off-screen rows; clips at the right edge).
fn putRow(f: *field.Field, x: u16, y: i32, fg: u8, str: []const u8, cols: u16, rows: u16) void {
    if (y < header_rows or y >= rows) return;
    const yy: u16 = @intCast(y);
    for (str, 0..) |ch, i| {
        const cx = x + i;
        if (cx >= cols) break;
        f.content[field.index(f, @intCast(cx), yy)] = .{ .glyph = ch, .fg = fg, .flags = .{ .text = true, .interactive = true } };
    }
}

fn putCell(f: *field.Field, x: u16, y: i32, fg: u8, glyph: u8, cols: u16, rows: u16, flags: field.ContentCell.Flags) void {
    if (y < 0 or y >= rows or x >= cols) return;
    f.content[field.index(f, x, @intCast(y))] = .{ .glyph = glyph, .fg = fg, .flags = flags };
}

fn appendHit(gpa: Allocator, hr: *HitList, x: u16, y: i32, w: u16, h: u16, action: timeline_ui.Action, target: u32, cols: u16, rows: u16, header: u16, fx: u16, fy: i32) void {
    // Clip to the scrollable region (below the fixed header).
    var top = y;
    var height: i32 = h;
    if (top < header) {
        height -= (header - top);
        top = header;
    }
    if (top >= rows or height <= 0) return;
    if (top + height > rows) height = rows - top;
    const cw: u16 = if (x + w > cols) cols - x else w;
    hr.append(gpa, .{
        .x = x,
        .y = @intCast(top),
        .w = cw,
        .h = @intCast(height),
        .fx = fx,
        .fy = @intCast(@max(0, @min(fy, rows - 1))),
        .action = @intFromEnum(action),
        .target = target,
    }) catch {};
}

// ---------------------------------------------------------------------------
// Tests (B2, C6)
// ---------------------------------------------------------------------------

test "guard: HitRect is exactly sized" {
    try testing.expectEqual(@as(usize, 20), @sizeOf(HitRect));
}

test "build: writes a header, cards, and a like zone carrying its effect origin" {
    const gpa = testing.allocator; // C6
    var f: field.Field = .{};
    try field.init(gpa, &f, 60, 30);
    defer field.deinit(gpa, &f);
    var hr: HitList = .empty;
    defer hr.deinit(gpa);
    var hearts: HeartList = .empty;
    defer hearts.deinit(gpa);

    const items = [_]feed.TimelineItem{
        .{ .uri = "at://1", .cid = "c1", .author_handle = "alice.test", .author_display_name = "Alice", .reposted_by_handle = "", .replying_to_handle = "", .text = "the grid is alive and the heart will bloom right here", .created_at = 1_700_000_000, .like_count = 3, .repost_count = 1, .reply_count = 0, .quote_count = 0, .label_flags = .{}, .item_flags = .{ .viewer_liked = false } },
        .{ .uri = "at://2", .cid = "c2", .author_handle = "bob.test", .author_display_name = "", .reposted_by_handle = "alice.test", .replying_to_handle = "alice.test", .text = "second", .created_at = 1_700_000_100, .like_count = 9, .repost_count = 0, .reply_count = 2, .quote_count = 0, .label_flags = .{}, .item_flags = .{ .viewer_liked = true } },
    };
    var view: ViewState = .{};
    const m = try build(&f, &hr, &hearts, &items, 0, &view, &.{}, 1_700_000_500, "me.test", "live", gpa);
    try testing.expect(m.content_rows > 4);

    // The header wordmark landed as fixed chrome.
    try testing.expectEqual(@as(u8, 'z'), f.content[field.index(&f, 2, 0)].glyph);
    try testing.expect(f.content[field.index(&f, 2, 0)].flags.fixed);

    // There is at least one like zone, and it carries a usable origin.
    var like_zones: usize = 0;
    var any_origin = false;
    const acts = hr.slice().items(.action);
    const fxs = hr.slice().items(.fx);
    const fys = hr.slice().items(.fy);
    for (acts, fxs, fys) |a, fx, fy| {
        if (@as(timeline_ui.Action, @enumFromInt(a)) == .like) {
            like_zones += 1;
            if (fx > 0 and fy > 0) any_origin = true;
        }
    }
    try testing.expectEqual(@as(usize, 2), like_zones);
    try testing.expect(any_origin);
    // Every non-select zone maps to a key (one dispatch path).
    for (acts) |a| {
        const action: timeline_ui.Action = @enumFromInt(a);
        if (action != .none) try testing.expect(timeline_ui.keyFor(action) != null);
    }
}

test "click on a like zone resolves to .like on THAT post (the unlike-by-click path)" {
    const gpa = testing.allocator; // C6
    var f: field.Field = .{};
    try field.init(gpa, &f, 60, 30);
    defer field.deinit(gpa, &f);
    var hr: HitList = .empty;
    defer hr.deinit(gpa);
    var hearts: HeartList = .empty;
    defer hearts.deinit(gpa);

    // Two posts; the SECOND is already liked. A click on its like zone
    // must resolve to .like targeting post 1 — the loop then injects the
    // toggle byte, which unlikes. If the zone is too small or shadowed
    // by the card-select zone, this resolves to .none and the post is
    // only selected — exactly the reported "can't unlike with the mouse"
    // symptom. This test fails in that case.
    const items = [_]feed.TimelineItem{
        .{ .uri = "at://1", .cid = "c1", .author_handle = "alice.test", .author_display_name = "Alice", .reposted_by_handle = "", .replying_to_handle = "", .text = "first post here", .created_at = 1_700_000_000, .like_count = 3, .repost_count = 1, .reply_count = 0, .quote_count = 0, .label_flags = .{}, .item_flags = .{} },
        .{ .uri = "at://2", .cid = "c2", .author_handle = "bob.test", .author_display_name = "Bob", .reposted_by_handle = "", .replying_to_handle = "", .text = "second post here", .created_at = 1_700_000_100, .like_count = 9, .repost_count = 0, .reply_count = 2, .quote_count = 0, .label_flags = .{}, .item_flags = .{ .viewer_liked = true } },
    };
    var view: ViewState = .{};
    _ = try build(&f, &hr, &hearts, &items, 0, &view, &.{}, 1_700_000_500, "me.test", "", gpa);

    // Find post 1's like zone and click its DEAD CENTRE — the worst case
    // for a small target is the user aiming at the middle.
    const xs = hr.slice().items(.x);
    const ys = hr.slice().items(.y);
    const ws = hr.slice().items(.w);
    const hs = hr.slice().items(.h);
    const acts = hr.slice().items(.action);
    const tgs = hr.slice().items(.target);
    var found = false;
    for (xs, ys, ws, hs, acts, tgs) |zx, zy, zw, zh, a, tg| {
        if (@as(timeline_ui.Action, @enumFromInt(a)) == .like and tg == 1) {
            const mid_x = zx + zw / 2;
            const mid_y = zy + zh / 2;
            const hit = hitTest(mid_x, mid_y, hr.slice()).?;
            // The centre of the like zone resolves to .like on post 1,
            // NOT to the card-select zone behind it.
            try testing.expectEqual(timeline_ui.Action.like, hit.action);
            try testing.expectEqual(@as(u32, 1), hit.target);
            // And it maps to a key, so the loop can inject the toggle.
            try testing.expect(timeline_ui.keyFor(hit.action) != null);
            found = true;
        }
    }
    try testing.expect(found);
}

test "build: hidden cards collapse and expose only the reveal zone" {
    const gpa = testing.allocator;
    var f: field.Field = .{};
    try field.init(gpa, &f, 60, 30);
    defer field.deinit(gpa, &f);
    var hr: HitList = .empty;
    defer hr.deinit(gpa);
    var hearts: HeartList = .empty;
    defer hearts.deinit(gpa);

    const items = [_]feed.TimelineItem{
        .{ .uri = "at://1", .cid = "c1", .author_handle = "x.test", .author_display_name = "", .reposted_by_handle = "", .replying_to_handle = "", .text = "hidden body", .created_at = 0, .like_count = 0, .repost_count = 0, .reply_count = 0, .quote_count = 0, .label_flags = .{ .sexual = true }, .item_flags = .{} },
    };
    var view: ViewState = .{};
    _ = try build(&f, &hr, &hearts, &items, 0, &view, &.{}, 100, "", "", gpa);
    var reveal = false;
    var like = false;
    for (hr.slice().items(.action)) |a| {
        const action: timeline_ui.Action = @enumFromInt(a);
        if (action == .toggle_reveal) reveal = true;
        if (action == .like) like = true;
    }
    try testing.expect(reveal);
    try testing.expect(!like);
}

test "build: scroll clamps and ensure-visible pulls a low selection up" {
    const gpa = testing.allocator;
    var f: field.Field = .{};
    try field.init(gpa, &f, 50, 12);
    defer field.deinit(gpa, &f);
    var hr: HitList = .empty;
    defer hr.deinit(gpa);
    var hearts: HeartList = .empty;
    defer hearts.deinit(gpa);

    var items: [12]feed.TimelineItem = undefined;
    for (&items, 0..) |*it, k| it.* = .{ .uri = "u", .cid = "c", .author_handle = "a.test", .author_display_name = "", .reposted_by_handle = "", .replying_to_handle = "", .text = "row", .created_at = 0, .like_count = @intCast(k), .repost_count = 0, .reply_count = 0, .quote_count = 0, .label_flags = .{}, .item_flags = .{} };

    var view: ViewState = .{ .scroll_rows = 99999 };
    const m = try build(&f, &hr, &hearts, &items, 0, &view, &.{}, 100, "", "", gpa);
    try testing.expect(view.scroll_rows >= 0 and view.scroll_rows <= @as(i32, @intCast(m.content_rows)));

    view.scroll_rows = 0;
    view.ensure_selected = true;
    _ = try build(&f, &hr, &hearts, &items, 11, &view, &.{}, 100, "", "", gpa);
    try testing.expect(view.scroll_rows > 0); // the last post was below the fold
}

test "buildCompose: empty draft shows placeholder, cursor at body origin" {
    const gpa = testing.allocator; // C6
    var f: field.Field = .{};
    try field.init(gpa, &f, 50, 12);
    defer field.deinit(gpa, &f);

    const cur = buildCompose(&f, "", "", 0, "draft");
    // Header wordmark is fixed chrome at the top-left margin.
    try testing.expectEqual(@as(u8, 'z'), f.content[field.index(&f, 2, 0)].glyph);
    try testing.expect(f.content[field.index(&f, 2, 0)].flags.fixed);
    // The placeholder is present on the body row.
    try testing.expectEqual(@as(u8, 's'), f.content[field.index(&f, 2, 3)].glyph);
    // Cursor sits at the body origin when empty.
    try testing.expectEqual(@as(u16, 2), cur.x);
    try testing.expectEqual(@as(u16, 3), cur.y);
}

test "buildCompose: text wraps and the cursor follows the last line's end" {
    const gpa = testing.allocator;
    var f: field.Field = .{};
    try field.init(gpa, &f, 24, 14);
    defer field.deinit(gpa, &f);

    // Wider than the ~20-cell text column, so it must wrap to >1 line.
    const draft = "the quick brown fox jumps over the lazy dog again";
    const cur = buildCompose(&f, draft, "", countCodepointsLocal(draft), "");
    // The cursor's row advanced past the first body row (wrapping
    // happened), and its column is the width of the final line.
    try testing.expect(cur.y > 3);
    try testing.expect(cur.x >= 2);
    // Reply mode changes the header.
    _ = buildCompose(&f, "hi", "alice.test", 2, "");
    // "- reply to @" begins right after "zat " at the margin+4 column.
    try testing.expectEqual(@as(u8, '-'), f.content[field.index(&f, 6, 0)].glyph);
}

test "buildCompose: over-limit counter renders in the like/warn colour" {
    const gpa = testing.allocator;
    var f: field.Field = .{};
    try field.init(gpa, &f, 40, 10);
    defer field.deinit(gpa, &f);

    _ = buildCompose(&f, "x", "", 305, ""); // 305 > 300
    // Find the counter row (rows-2 = 8) and confirm a digit cell carries
    // the warn colour (col_like), not the normal faint.
    var warn = false;
    var x: u16 = 0;
    while (x < 40) : (x += 1) {
        const c = f.content[field.index(&f, x, 8)];
        if (c.glyph != 0 and c.fg == col_like) warn = true;
    }
    try testing.expect(warn);
}

// Local codepoint count for tests (mirrors timeline_ui.countCodepoints
// without importing it into the test — ASCII drafts count as bytes).
fn countCodepointsLocal(s: []const u8) usize {
    var n: usize = 0;
    var i: usize = 0;
    while (i < s.len) {
        i += std.unicode.utf8ByteSequenceLength(s[i]) catch 1;
        n += 1;
    }
    return n;
}

test "buildProfile: header, handle, following marker, and counts render" {
    const gpa = testing.allocator; // C6
    var f: field.Field = .{};
    try field.init(gpa, &f, 60, 16);
    defer field.deinit(gpa, &f);

    buildProfile(&f, .{
        .handle = "alice.bsky.social",
        .display_name = "Alice",
        .description = "building things in zig and posting about it on the glyph field",
        .followers = 1234,
        .follows = 321,
        .posts = 5678,
        .following = true,
    }, "live");

    // Header wordmark, fixed.
    try testing.expectEqual(@as(u8, 'z'), f.content[field.index(&f, 2, 0)].glyph);
    try testing.expect(f.content[field.index(&f, 2, 0)].flags.fixed);
    // Display name on row 3, handle on row 4 starting with '@' in accent.
    try testing.expectEqual(@as(u8, 'A'), f.content[field.index(&f, 2, 3)].glyph);
    try testing.expectEqual(@as(u8, '@'), f.content[field.index(&f, 2, 4)].glyph);
    try testing.expectEqual(col_accent, f.content[field.index(&f, 2, 4)].fg);
    // Somewhere on the handle row, the "following" marker's 'f' appears.
    var following_marker = false;
    var x: u16 = 0;
    while (x < 60) : (x += 1) {
        if (f.content[field.index(&f, x, 4)].glyph == 'f' and f.content[field.index(&f, x, 4)].fg == col_dim) following_marker = true;
    }
    try testing.expect(following_marker);
    // The counts line (row 6) contains digits.
    var has_digit = false;
    x = 0;
    while (x < 60) : (x += 1) {
        const c = f.content[field.index(&f, x, 6)].glyph;
        if (c >= '0' and c <= '9') has_digit = true;
    }
    try testing.expect(has_digit);
}

// ---------------------------------------------------------------------------
// Shell carve golden tests (SHELL_LAYOUT_ROADMAP S.4). Pin the three-band
// structure for a known (items, dims, config): the seams land where the
// config says, the nav rail is present and clickable with the right
// actions, the sidebar stubs render, and the feed is inset — not at
// column 0. Consistent with the headless field tests above (no window).
// ---------------------------------------------------------------------------

test "layoutShell: three bands, fixed seams, inset feed, clickable nav rail" {
    const gpa = testing.allocator; // C6
    var f: field.Field = .{};
    try field.init(gpa, &f, 120, 30);
    defer field.deinit(gpa, &f);
    var hr: HitList = .empty;
    defer hr.deinit(gpa);
    var hearts: HeartList = .empty;
    defer hearts.deinit(gpa);

    const items = [_]feed.TimelineItem{
        .{ .uri = "at://1", .cid = "c1", .author_handle = "alice.test", .author_display_name = "Alice", .reposted_by_handle = "", .replying_to_handle = "", .text = "a post in the centre column", .created_at = 1_700_000_000, .like_count = 3, .repost_count = 1, .reply_count = 0, .quote_count = 0, .label_flags = .{}, .item_flags = .{} },
    };
    const cfg: PaneConfig = .{};
    var view: ViewState = .{};
    _ = try layoutShell(&f, cfg, &hr, &hearts, &items, 0, &view, &.{}, 1_700_000_500, "me.test", "live", gpa);

    // Seam columns: nav_w and nav_w+1+center_w, both fixed dividers.
    const center_w: u16 = 120 - cfg.nav_w - cfg.sidebar_w - 2;
    const seam_l: u16 = cfg.nav_w;
    const seam_r: u16 = cfg.nav_w + 1 + center_w;
    try testing.expect(f.content[field.index(&f, seam_l, 5)].flags.fixed);
    try testing.expect(f.content[field.index(&f, seam_l, 5)].flags.divider);
    try testing.expect(f.content[field.index(&f, seam_r, 5)].flags.fixed);

    // The nav rail wordmark sits at the rail's left inset (col 2), fixed.
    try testing.expectEqual(@as(u8, 'z'), f.content[field.index(&f, 2, 0)].glyph);
    try testing.expect(f.content[field.index(&f, 2, 0)].flags.fixed);

    // The centre feed is INSET: column 0 of the feed body is past the
    // left seam, so the feed's first body glyph is not in the nav band.
    // The feed header wordmark now lives at center_x + margin, not col 2.
    const center_x: u16 = cfg.nav_w + 1;
    try testing.expectEqual(@as(u8, 'z'), f.content[field.index(&f, center_x + 2, 0)].glyph);

    // The rail pushed clickable destination zones: at least the real
    // verbs (refresh = home, profile, new_post = compose) are present,
    // and every rail zone targets no_target (nav is not a per-post act).
    var saw_home = false;
    var saw_profile = false;
    var saw_compose = false;
    var saw_stub = false;
    const acts = hr.slice().items(.action);
    const xs = hr.slice().items(.x);
    const tgs = hr.slice().items(.target);
    for (acts, xs, tgs) |a, zx, tg| {
        // Rail zones live in the nav band (x < seam_l).
        if (zx >= seam_l) continue;
        const action: timeline_ui.Action = @enumFromInt(a);
        switch (action) {
            .refresh => saw_home = true,
            .profile => saw_profile = true,
            .new_post => saw_compose = true,
            .nav_explore, .nav_notifications, .nav_chat, .nav_feeds, .nav_lists, .nav_settings => saw_stub = true,
            else => {},
        }
        // No rail destination is a per-post target.
        try testing.expectEqual(no_target, tg);
    }
    try testing.expect(saw_home);
    try testing.expect(saw_profile);
    try testing.expect(saw_compose);
    try testing.expect(saw_stub);

    // The sidebar rendered a stub: the "trending" label appears somewhere
    // in the right band.
    const side_x: u16 = seam_r + 1;
    var saw_trending = false;
    var ry: u16 = 0;
    while (ry < 30) : (ry += 1) {
        if (f.content[field.index(&f, side_x + 2, ry)].glyph == 't') {
            // Cheap check: a 't' starting a band-local row; the full word
            // is asserted by reading the run.
            var word: [8]u8 = undefined;
            var k: u16 = 0;
            while (k < 8 and side_x + 2 + k < 120) : (k += 1) word[k] = f.content[field.index(&f, side_x + 2 + k, ry)].glyph;
            if (std.mem.eql(u8, word[0..8], "trending")) saw_trending = true;
        }
    }
    try testing.expect(saw_trending);
}

test "layoutShell: collapses to a full-width feed below the threshold (E4)" {
    const gpa = testing.allocator; // C6
    var f: field.Field = .{};
    try field.init(gpa, &f, 60, 20); // < min_three_col_w
    defer field.deinit(gpa, &f);
    var hr: HitList = .empty;
    defer hr.deinit(gpa);
    var hearts: HeartList = .empty;
    defer hearts.deinit(gpa);

    const items = [_]feed.TimelineItem{
        .{ .uri = "at://1", .cid = "c1", .author_handle = "alice.test", .author_display_name = "", .reposted_by_handle = "", .replying_to_handle = "", .text = "narrow", .created_at = 0, .like_count = 0, .repost_count = 0, .reply_count = 0, .quote_count = 0, .label_flags = .{}, .item_flags = .{} },
    };
    var view: ViewState = .{};
    _ = try layoutShell(&f, .{}, &hr, &hearts, &items, 0, &view, &.{}, 100, "me.test", "", gpa);

    // No left seam: there is no fixed divider sitting at the nav_w column,
    // because the narrow layout is the full-width feed (an ordinary
    // result, E4). The feed wordmark is at the usual col 2.
    try testing.expectEqual(@as(u8, 'z'), f.content[field.index(&f, 2, 0)].glyph);
    var any_vertical_seam = false;
    var ry: u16 = 3;
    while (ry < 20) : (ry += 1) {
        const c = f.content[field.index(&f, 22, ry)]; // default nav_w
        if (c.flags.fixed and c.flags.divider and c.glyph == '|') any_vertical_seam = true;
    }
    try testing.expect(!any_vertical_seam);
}
