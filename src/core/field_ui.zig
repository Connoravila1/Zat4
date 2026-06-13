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
/// the shell draws the heart sprite (effect.composeStaticHeart) at (x,y)
/// after field.compose, suppressing the one currently animating (the
/// effect draws that one). HOT (one per visible post, scanned each
/// frame) → A7 guard.
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
    // Clear content only (perturb persists — §7).
    @memset(f.content, field.ContentCell.empty);
    hr.clearRetainingCapacity();
    hearts.clearRetainingCapacity();

    const cols = f.cols;
    const rows = f.rows;
    if (cols < 24 or rows < 6) return .{ .content_rows = 0 };

    const margin: u16 = 2;
    const text_w: u16 = cols - margin * 2;

    // ---- header (fixed; never scrolls, never moves under physics) ----
    writeFixed(f, margin, 0, col_accent, "zat");
    if (account_handle.len > 0) {
        var hb: [96]u8 = undefined;
        const h = std.fmt.bufPrint(&hb, "@{s}", .{account_handle}) catch "@";
        writeFixed(f, margin + 4, 0, col_dim, h);
    }
    var tally_buf: [24]u8 = undefined;
    const tally = std.fmt.bufPrint(&tally_buf, "{d} posts", .{items.len}) catch "";
    if (tally.len < cols) writeFixed(f, cols - margin - @as(u16, @intCast(tally.len)), 0, col_faint, tally);
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
        writeText(f, margin, rows / 2, col_dim, "timeline is empty - press r to refresh");
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
        appendHit(gpa, hr, margin, card_top, text_w, ch, .none, i, cols, rows, header_rows, @intCast(margin + text_w / 2), card_top + @divTrunc(ch, 2));

        var row = card_top;
        if (moderation.verdictFor(item.label_flags) == .hide and !isRevealed(revealed, item.cid)) {
            var hb: [128]u8 = undefined;
            const label = std.fmt.bufPrint(&hb, "hidden: {s} - click to show", .{moderation.reasonFor(item.label_flags)}) catch "hidden - click to show";
            putRow(f, margin, row + 1, col_faint, label, cols, rows);
            appendHit(gpa, hr, margin, card_top, text_w, ch, .toggle_reveal, i, cols, rows, header_rows, 0, 0);
            continue;
        }

        // Selection marker in the left margin.
        if (is_sel) {
            var r = card_top;
            while (r < card_top + ch - 1) : (r += 1) putCell(f, 0, r, col_accent, '|', cols, rows, .{ .fixed = true });
        }

        if (item.reposted_by_handle.len > 0) {
            var rb: [128]u8 = undefined;
            const line = std.fmt.bufPrint(&rb, "reposted by @{s}", .{item.reposted_by_handle}) catch "reposted";
            putRow(f, margin, row, col_boost, line, cols, rows);
            row += 1;
        }

        // Author row: name + handle left, age right.
        {
            var nb: [192]u8 = undefined;
            const name = if (item.author_display_name.len > 0)
                std.fmt.bufPrint(&nb, "{s} @{s}", .{ item.author_display_name, item.author_handle }) catch item.author_handle
            else
                std.fmt.bufPrint(&nb, "@{s}", .{item.author_handle}) catch "@";
            putRow(f, margin, row, if (is_sel) col_accent else col_ink, name, cols, rows);
            var ab: [16]u8 = undefined;
            const age = timeline_ui.formatAge(&ab, now, item.created_at);
            if (age.len + margin < cols) putRow(f, cols - margin - @as(u16, @intCast(age.len)), row, col_faint, age, cols, rows);
            row += 1;
        }

        if (item.replying_to_handle.len > 0) {
            var rb: [128]u8 = undefined;
            const line = std.fmt.bufPrint(&rb, "replying to @{s}", .{item.replying_to_handle}) catch "replying";
            putRow(f, margin, row, col_faint, line, cols, rows);
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
                putRow(f, margin, row, body_col, line, cols, rows);
                row += 1;
                rest = rest[@max(n, 1)..];
            }
        }

        // Engagement row: like / boost / reply. The like button IS the
        // heart (the owner's model): layout RESERVES the inline heart's
        // cells and records a HeartSlot; the shell draws the heart sprite
        // there (effect.composeStaticHeart) — filled red if liked, dim
        // outline if not. The SAME heart fills and bursts in place on
        // click, so the hit target and the effect origin both point at
        // the heart's own cell, not the card centre.
        {
            const zrow: i32 = row;
            var x = margin;
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
            putRow(f, x, zrow, if (liked) col_like else col_dim, like_s, cols, rows);
            // Hit target spans the heart AND its count, so the whole
            // affordance is clickable, but anchored on the heart. Effect
            // origin is the heart cell → the burst happens at the button.
            const target_w: u16 = heart_w + 1 + @as(u16, @intCast(like_s.len)) + 1;
            appendHit(gpa, hr, margin, zrow, target_w, 1, .like, i, cols, rows, header_rows, heart_cx, heart_cy);
            x += @intCast(like_s.len + 3);

            var bb: [32]u8 = undefined;
            const boost_s = std.fmt.bufPrint(&bb, "rt {d}", .{item.repost_count}) catch "rt";
            putRow(f, x, zrow, if (item.item_flags.viewer_reposted) col_boost else col_dim, boost_s, cols, rows);
            appendHit(gpa, hr, sub(x, 2), zrow, @intCast(boost_s.len + 4), 1, .repost, i, cols, rows, header_rows, x, zrow);
            x += @intCast(boost_s.len + 3);

            var pb: [32]u8 = undefined;
            const reply_s = std.fmt.bufPrint(&pb, "re {d}", .{item.reply_count}) catch "re";
            putRow(f, x, zrow, col_dim, reply_s, cols, rows);
            appendHit(gpa, hr, sub(x, 2), zrow, @intCast(reply_s.len + 4), 1, .reply, i, cols, rows, header_rows, x, zrow);
            row += 1;
        }

        // Seam divider between cards (scatter-able scenery).
        if (row >= header_rows and row < rows) {
            var dx: u16 = margin;
            while (dx < cols - margin) : (dx += 1) putCell(f, dx, row, col_faint, '-', cols, rows, .{ .divider = true });
        }
    }

    // Load-older row at content bottom.
    {
        const ly: i32 = @as(i32, @intCast(content_rows - 1)) - scroll;
        if (ly >= header_rows and ly < rows) {
            const label = "load older posts";
            const lx: u16 = if (label.len < cols) @intCast((cols - label.len) / 2) else margin;
            putRow(f, lx, ly, col_faint, label, cols, rows);
            appendHit(gpa, hr, margin, ly, text_w, 1, .load_more, no_target, cols, rows, header_rows, 0, 0);
        }
    }

    // Status pill text, bottom-right (chrome — fixed).
    if (status.len > 0 and status.len + margin < cols) {
        writeFixed(f, cols - margin - @as(u16, @intCast(status.len)), rows - 1, col_accent, status);
    }

    return .{ .content_rows = content_rows };
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
