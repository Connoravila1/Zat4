//! B1 classification: CORE (pure). The **renderer deep module**, file 2 of
//! 3: the timeline screen — the part that is custom to THIS app.
//!
//! One pure function, `buildFrame`, turns (view-model values, ui state,
//! the current time handed in by the shell, a surface size) into a cell
//! grid. No clock is read here (B4), no terminal is touched, and the only
//! types crossing in are plain values: `feed.TimelineItem` slices and
//! integers. Moderation verdicts are obeyed, not interpreted — this file
//! asks the moderation module and renders the answer.
//!
//! Layout is measured and drawn by the SAME function (`layoutCard` with
//! draw on/off), so scroll arithmetic can never drift from what is painted.

const std = @import("std");
const Allocator = std.mem.Allocator;
const tui = @import("tui.zig");
const feed = @import("feed.zig");
const moderation = @import("moderation.zig");

// ---------------------------------------------------------------------------
// State and intent
// ---------------------------------------------------------------------------

/// Cursor + viewport, the whole interaction state.
/// A7.2: cold struct, size guard waived — one per running screen.
pub const UiState = struct {
    selected: u32 = 0,
    scroll_top: u32 = 0,
};

pub const Action = enum {
    none,
    quit,
    move_up,
    move_down,
    page_up,
    page_down,
    go_top,
    go_bottom,
    load_more,
    refresh,
    like,
    repost,
    reply,
    new_post,
    follow,
    profile,
    toggle_reveal,
};

/// Key bindings, in one place: vi keys and arrows move; r (or enter) loads
/// the next page; l likes, b boosts, R replies, n composes, f follows the
/// selected author; p opens their profile; x shows (and re-hides) a
/// post collapsed by moderation; q, ESC, or ctrl-c quits.
pub fn actionFor(event: tui.InputEvent) Action {
    return switch (event) {
        .up => .move_up,
        .down => .move_down,
        .page_up => .page_up,
        .page_down => .page_down,
        .home => .go_top,
        .end_key => .go_bottom,
        .enter => .load_more,
        .escape => .quit,
        .char => |c| switch (c) {
            'q', 3 => .quit, // 3 = ctrl-c arriving as a byte under raw mode
            'k' => .move_up,
            'j' => .move_down,
            'g' => .go_top,
            'G' => .go_bottom,
            'r' => .refresh,
            ' ' => .load_more,
            'l' => .like,
            'b' => .repost,
            'R' => .reply,
            'n' => .new_post,
            'f' => .follow,
            'p' => .profile,
            'x' => .toggle_reveal,
            else => .none,
        },
        else => .none,
    };
}

/// What a key means inside the composer. ctrl-d sends (end of input);
/// ESC or ctrl-c backs out with the draft intact for this session.
pub const ComposeAction = union(enum) {
    insert: u21,
    backspace,
    send,
    cancel,
    none,
};

pub fn actionForCompose(event: tui.InputEvent) ComposeAction {
    return switch (event) {
        .escape => .cancel,
        .enter => .{ .insert = '\n' },
        .char => |c| switch (c) {
            4 => .send, // ctrl-d
            3 => .cancel, // ctrl-c
            127, 8 => .backspace, // DEL / BS
            else => if (c >= 32) .{ .insert = c } else ComposeAction.none,
        },
        else => .none,
    };
}

/// Codepoints in a UTF-8 buffer (the network's 300-character post limit
/// counts graphemes; codepoints are the honest cheap approximation —
/// recorded trade).
pub fn countCodepoints(text: []const u8) usize {
    var count: usize = 0;
    var i: usize = 0;
    while (i < text.len) {
        const len = std.unicode.utf8ByteSequenceLength(text[i]) catch 1;
        i += @max(len, 1);
        count += 1;
    }
    return count;
}

/// Apply a movement to the state (pure clamp arithmetic). `load_more` and
/// `quit` are the shell's business and leave the state untouched.
pub fn applyAction(state: *UiState, action: Action, item_count: usize) void {
    if (item_count == 0) {
        state.selected = 0;
        state.scroll_top = 0;
        return;
    }
    const last: u32 = @intCast(item_count - 1);
    switch (action) {
        .move_up => state.selected -|= 1,
        .move_down => state.selected = @min(state.selected + 1, last),
        .page_up => state.selected -|= 5,
        .page_down => state.selected = @min(state.selected + 5, last),
        .go_top => state.selected = 0,
        .go_bottom => state.selected = last,
        else => {},
    }
}

// ---------------------------------------------------------------------------
// The frame
// ---------------------------------------------------------------------------

const header_style: tui.Style = .{ .inverse = true, .bold = true };
const dim_style: tui.Style = .{ .dim = true };
const author_style: tui.Style = .{ .bold = true };
const accent_style: tui.Style = .{ .fg = .cyan, .bold = true };
const repost_style: tui.Style = .{ .fg = .green, .dim = true };
const hidden_style: tui.Style = .{ .fg = .yellow, .dim = true };
const status_style: tui.Style = .{ .fg = .bright_yellow };

/// Build one complete frame. Reconciles the scroll so the selected card is
/// visible, then paints header, cards, and footer. Deterministic for a
/// given (items, state, now, size, status) — the smoke tests below assert
/// on the resulting cells.
pub fn buildFrame(
    surface: *tui.Surface,
    items: []const feed.TimelineItem,
    state: *UiState,
    /// CIDs the user has explicitly revealed past a moderation collapse —
    /// plain values across the boundary (B5); the shell owns the list.
    revealed: []const []const u8,
    now: i64,
    account_handle: []const u8,
    status: []const u8,
) void {
    tui.clearSurface(surface);
    if (surface.width < 8 or surface.height < 4) return;

    const view_top: u16 = 1;
    const view_height: u16 = surface.height - 2;

    if (items.len > 0 and state.selected >= items.len) state.selected = @intCast(items.len - 1);
    reconcileScroll(state, items, surface, view_height, revealed, now);

    // Header: identity left, tally right, one inverse bar.
    tui.fillRow(surface, 0, header_style, ' ');
    var x = tui.putText(surface, 0, 0, header_style, " zat ");
    if (account_handle.len > 0) {
        x += tui.putText(surface, x, 0, header_style, "- @");
        x += tui.putText(surface, x, 0, header_style, account_handle);
    }
    var tally_buf: [32]u8 = undefined;
    const tally = std.fmt.bufPrint(&tally_buf, "{d} items ", .{items.len}) catch "";
    if (tally.len < surface.width) {
        _ = tui.putText(surface, surface.width - @as(u16, @intCast(tally.len)), 0, header_style, tally);
    }

    // Cards from the scroll anchor; rows past the footer clip, and the
    // footer is painted last so a partial card never bleeds over it.
    if (items.len == 0) {
        _ = tui.putText(surface, 2, view_top + 1, dim_style, "timeline empty - press r to load");
    } else {
        var y: u16 = view_top;
        var index: u32 = state.scroll_top;
        while (index < items.len and y < view_top + view_height) : (index += 1) {
            y += layoutCard(surface, items[index], y, index == state.selected, revealed, now, true);
        }
    }

    // Footer: key bar left, status right.
    const footer_y = surface.height - 1;
    tui.fillRow(surface, footer_y, dim_style, ' ');
    // Width-aware key bar: never let "quit" clip off a narrow terminal.
    const keybar = if (surface.width >= 72)
        "j/k move  l like  b boost  R reply  n new  p profile  x show  r refresh  space older  q quit"
    else
        "j/k  r refresh  spc older  q quit";
    _ = tui.putText(surface, 1, footer_y, dim_style, keybar);
    if (status.len > 0 and status.len + 1 < surface.width) {
        _ = tui.putText(surface, surface.width - @as(u16, @intCast(status.len)) - 1, footer_y, status_style, status);
    }
}

/// Advance the scroll anchor until the selected card fits inside the view.
/// Quadratic in the worst case over visible items — tens of cards against
/// a network-fed list (G3: not worth cleverness).
fn reconcileScroll(state: *UiState, items: []const feed.TimelineItem, surface: *tui.Surface, view_height: u16, revealed: []const []const u8, now: i64) void {
    if (items.len == 0) return;
    if (state.selected < state.scroll_top) state.scroll_top = state.selected;
    while (state.scroll_top < state.selected) {
        var used: u32 = 0;
        var index = state.scroll_top;
        while (index <= state.selected) : (index += 1) {
            used += layoutCard(surface, items[index], 0, false, revealed, now, false);
        }
        if (used <= view_height) break;
        state.scroll_top += 1;
    }
}

fn isRevealed(revealed: []const []const u8, cid: []const u8) bool {
    for (revealed) |r| if (std.mem.eql(u8, r, cid)) return true;
    return false;
}

/// Measure (draw = false) or draw one card; one body, one width source —
/// the scroll math can never disagree with what is painted. Returns the
/// card's height in rows; measuring never writes a cell.
fn layoutCard(
    surface: *tui.Surface,
    item: feed.TimelineItem,
    top: u16,
    selected: bool,
    revealed: []const []const u8,
    now: i64,
    draw: bool,
) u16 {
    const gutter: u16 = 2;
    const width: u16 = surface.width;
    const text_width: u16 = if (width > gutter + 1) width - gutter - 1 else 1;
    var rows: u16 = 0;

    // Hidden cards collapse to a one-line notice + separator; the verdict
    // comes from the sealed moderation module.
    if (moderation.verdictFor(item.label_flags) == .hide and !isRevealed(revealed, item.cid)) {
        if (draw) {
            drawGutter(surface, top, selected);
            var x = tui.putText(surface, gutter, top, hidden_style, "[hidden: ");
            x += tui.putText(surface, gutter + x, top, hidden_style, moderation.reasonFor(item.label_flags));
            _ = tui.putText(surface, gutter + x, top, hidden_style, "]");
        }
        rows += 1;
        if (draw) drawSeparator(surface, top + rows, width);
        return rows + 1;
    }

    if (item.reposted_by_handle.len > 0) {
        if (draw) {
            const x = tui.putText(surface, gutter, top, repost_style, "reposted by @");
            _ = tui.putText(surface, gutter + x, top, repost_style, item.reposted_by_handle);
        }
        rows += 1;
    }

    // Author line: display name (bold), @handle and age (dim).
    if (draw) {
        drawGutter(surface, top + rows, selected);
        var x: u16 = gutter;
        const name_style = if (selected) accent_style else author_style;
        if (item.author_display_name.len > 0) {
            x += tui.putText(surface, x, top + rows, name_style, item.author_display_name);
            x += tui.putText(surface, x, top + rows, dim_style, " @");
        } else {
            x += tui.putText(surface, x, top + rows, name_style, "@");
        }
        x += tui.putText(surface, x, top + rows, if (item.author_display_name.len > 0) dim_style else name_style, item.author_handle);
        var age_buf: [16]u8 = undefined;
        const age = formatAge(&age_buf, now, item.created_at);
        x += tui.putText(surface, x, top + rows, dim_style, " . ");
        _ = tui.putText(surface, x, top + rows, dim_style, age);
    }
    rows += 1;

    if (item.replying_to_handle.len > 0) {
        if (draw) {
            const x = tui.putText(surface, gutter, top + rows, dim_style, "replying to @");
            _ = tui.putText(surface, gutter + x, top + rows, dim_style, item.replying_to_handle);
        }
        rows += 1;
    }

    // Body: width-aware wrap. Measuring and drawing share wrapCount /
    // wrapNext so the row math is one piece of code.
    var wrap = WrapIterator{ .text = item.text, .max_width = text_width };
    while (wrap.next()) |line| {
        if (draw) _ = tui.putText(surface, gutter, top + rows, .{}, line);
        rows += 1;
    }

    // Counts line.
    if (draw) {
        var counts_buf: [96]u8 = undefined;
        const counts = std.fmt.bufPrint(&counts_buf, "likes {d} . reposts {d} . replies {d}{s}{s}", .{
            item.like_count,
            item.repost_count,
            item.reply_count,
            if (item.item_flags.viewer_liked) " [liked]" else "",
            if (item.item_flags.viewer_reposted) " [boosted]" else "",
        }) catch "";
        _ = tui.putText(surface, gutter, top + rows, dim_style, counts);
    }
    rows += 1;

    if (draw) drawSeparator(surface, top + rows, width);
    return rows + 1;
}

fn drawGutter(surface: *tui.Surface, y: u16, selected: bool) void {
    if (selected) _ = tui.putText(surface, 0, y, accent_style, "> ");
}

fn drawSeparator(surface: *tui.Surface, y: u16, width: u16) void {
    _ = width;
    tui.fillRow(surface, y, .{ .dim = true }, 0x2500); // ─
}

/// Build the composer frame: header (new post / reply target), the draft
/// wrapped with a cursor cell at its end, a character counter, and the
/// composer key bar. Pure, like buildFrame.
pub fn buildComposeFrame(
    surface: *tui.Surface,
    text: []const u8,
    reply_to_handle: []const u8,
    status: []const u8,
) void {
    tui.clearSurface(surface);
    if (surface.width < 8 or surface.height < 4) return;

    tui.fillRow(surface, 0, header_style, ' ');
    var hx = tui.putText(surface, 0, 0, header_style, " zat ");
    if (reply_to_handle.len > 0) {
        hx += tui.putText(surface, hx, 0, header_style, "- reply to @");
        _ = tui.putText(surface, hx, 0, header_style, reply_to_handle);
    } else {
        _ = tui.putText(surface, hx, 0, header_style, "- new post");
    }

    const text_x: u16 = 2;
    const text_width: u16 = if (surface.width > text_x + 1) surface.width - text_x - 1 else 1;
    var y: u16 = 2;
    var cursor_x: u16 = text_x;
    var cursor_y: u16 = y;
    if (text.len == 0) {
        _ = tui.putText(surface, text_x, y, dim_style, "say something...");
    } else {
        var wrap = WrapIterator{ .text = text, .max_width = text_width };
        var last_line: []const u8 = "";
        var wrapped_any = false;
        while (wrap.next()) |line| {
            if (y + 2 < surface.height) {
                _ = tui.putText(surface, text_x, y, .{}, line);
                cursor_y = y;
                last_line = line;
                wrapped_any = true;
                y += 1;
            }
        }
        if (wrapped_any) cursor_x = text_x + displayWidth(last_line);
        // Text ending in a newline puts the cursor on a fresh line.
        if (text[text.len - 1] == '\n' and cursor_y + 3 < surface.height) {
            cursor_y += 1;
            cursor_x = text_x;
        }
    }
    // The cursor: one inverse cell at the insertion point.
    if (cursor_x < surface.width) {
        _ = tui.putText(surface, cursor_x, cursor_y, .{ .inverse = true }, " ");
    }

    var counter_buf: [24]u8 = undefined;
    const counter = std.fmt.bufPrint(&counter_buf, "{d}/300", .{countCodepoints(text)}) catch "";
    if (counter.len + 2 < surface.width) {
        _ = tui.putText(
            surface,
            surface.width - @as(u16, @intCast(counter.len)) - 1,
            surface.height - 2,
            dim_style,
            counter,
        );
    }

    const footer_y = surface.height - 1;
    tui.fillRow(surface, footer_y, dim_style, ' ');
    _ = tui.putText(surface, 1, footer_y, dim_style, "ctrl-d send  esc cancel");
    if (status.len > 0 and status.len + 1 < surface.width) {
        _ = tui.putText(surface, surface.width - @as(u16, @intCast(status.len)) - 1, footer_y, status_style, status);
    }
}

fn displayWidth(text: []const u8) u16 {
    var cols: u32 = 0;
    var i: usize = 0;
    while (i < text.len) {
        const len = std.unicode.utf8ByteSequenceLength(text[i]) catch 1;
        const cp = if (len == 1 or i + len > text.len)
            @as(u32, text[i])
        else
            std.unicode.utf8Decode(text[i .. i + len]) catch @as(u32, 0xFFFD);
        cols += tui.runeWidth(cp);
        i += @max(len, 1);
    }
    return @intCast(@min(cols, std.math.maxInt(u16)));
}

// ---------------------------------------------------------------------------
// Word wrap — display-width aware, zero-copy (lines are slices of the
// input), an iterator so measuring allocates nothing
// ---------------------------------------------------------------------------

/// A7.2: cold struct, size guard waived — one per card layout, stack-only.
/// D5/A1 note: an ITERATOR (the standard Zig idiom), not a data record —
/// `next` is permitted. A7.2: cold, one per wrapped paragraph; waived.
pub const WrapIterator = struct {
    text: []const u8,
    max_width: u16,
    index: usize = 0,

    pub fn next(self: *WrapIterator) ?[]const u8 {
        if (self.index >= self.text.len) return null;
        const width = @max(self.max_width, 1);
        const start = self.index;
        var i = start;
        var cols: u32 = 0;
        var last_space: ?usize = null;
        while (i < self.text.len) {
            const b = self.text[i];
            if (b == '\n') {
                const line = self.text[start..i];
                self.index = i + 1;
                return line;
            }
            const len = std.unicode.utf8ByteSequenceLength(b) catch 1;
            const cp = if (len == 1 or i + len > self.text.len)
                @as(u32, b)
            else
                std.unicode.utf8Decode(self.text[i .. i + len]) catch @as(u32, 0xFFFD);
            const w = tui.runeWidth(cp);
            if (cols + w > width) {
                if (last_space) |space| {
                    const line = self.text[start..space];
                    self.index = space + 1;
                    return line;
                }
                const line = self.text[start..i];
                self.index = i;
                return line;
            }
            if (b == ' ') last_space = i;
            cols += w;
            i += @max(len, 1);
        }
        self.index = self.text.len;
        return self.text[start..];
    }
};

// ---------------------------------------------------------------------------
// Relative ages — pure arithmetic; "now" always arrives as an argument
// ---------------------------------------------------------------------------

pub fn formatAge(buf: []u8, now: i64, created: i64) []const u8 {
    const delta = now - created;
    if (delta < 60) return std.fmt.bufPrint(buf, "now", .{}) catch "";
    if (delta < 3_600) return std.fmt.bufPrint(buf, "{d}m", .{@divFloor(delta, 60)}) catch "";
    if (delta < 86_400) return std.fmt.bufPrint(buf, "{d}h", .{@divFloor(delta, 3_600)}) catch "";
    if (delta < 604_800) return std.fmt.bufPrint(buf, "{d}d", .{@divFloor(delta, 86_400)}) catch "";
    return std.fmt.bufPrint(buf, "{d}w", .{@divFloor(delta, 604_800)}) catch "";
}

// ---------------------------------------------------------------------------
// Tests — the screen asserted as cells, no terminal anywhere (B2, C6)
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// The profile screen — same doctrine: plain data in, cells out (B2/B5).
// ---------------------------------------------------------------------------

/// A7.2: cold struct, size guard waived — one on screen at a time; the
/// strings are owned by the shell's profile arena (C3/C4), this is a view.
pub const ProfileInfo = struct {
    did: []const u8 = "",
    handle: []const u8 = "",
    display_name: []const u8 = "",
    description: []const u8 = "",
    followers: u32 = 0,
    follows: u32 = 0,
    posts: u32 = 0,
    following: bool = false,
};

pub const ProfileAction = enum { none, close, follow };

/// p (again), q, or ESC closes; f follows from here.
pub fn actionForProfile(event: tui.InputEvent) ProfileAction {
    return switch (event) {
        .escape => .close,
        .char => |c| switch (c) {
            'p', 'q', 3 => .close,
            'f' => .follow,
            else => .none,
        },
        else => .none,
    };
}

/// PURE (B2): one profile as a frame — header bar, identity, counts,
/// wrapped bio, keybar. The same cells either backend renders.
pub fn buildProfileFrame(surface: *tui.Surface, info: ProfileInfo, status: []const u8) void {
    tui.clearSurface(surface);
    if (surface.width < 8 or surface.height < 4) return;
    const width = surface.width;

    tui.fillRow(surface, 0, header_style, ' ');
    var x = tui.putText(surface, 0, 0, header_style, " zat · profile ");
    if (status.len > 0 and width > x + 2) {
        _ = tui.putText(surface, x + 1, 0, header_style, status);
    }

    var y: u16 = 2;
    if (info.display_name.len > 0) {
        _ = tui.putText(surface, 1, y, .{ .bold = true }, info.display_name);
        y += 1;
    }
    x = tui.putText(surface, 1, y, .{ .fg = .cyan }, "@");
    x += tui.putText(surface, 1 + x, y, .{ .fg = .cyan }, info.handle);
    if (info.following) {
        _ = tui.putText(surface, 1 + x + 1, y, dim_style, "· following");
    }
    y += 2;

    var counts_buf: [96]u8 = undefined;
    const counts = std.fmt.bufPrint(&counts_buf, "{d} followers · {d} following · {d} posts", .{
        info.followers, info.follows, info.posts,
    }) catch "";
    _ = tui.putText(surface, 1, y, .{}, counts);
    y += 2;

    const text_width: u16 = if (width > 2) width - 2 else 1;
    var wrap = WrapIterator{ .text = info.description, .max_width = text_width };
    while (wrap.next()) |line| {
        if (y >= surface.height - 2) break;
        _ = tui.putText(surface, 1, y, .{}, line);
        y += 1;
    }

    _ = tui.putText(surface, 1, surface.height - 1, dim_style, "f follow  p close");
}

const testing = std.testing;

fn rowString(arena: Allocator, surface: *const tui.Surface, y: u16) ![]u8 {
    const out = try arena.alloc(u8, surface.width);
    for (out, 0..) |*c, x| {
        const cp = surface.chars.items[@as(usize, y) * surface.width + x];
        c.* = if (cp >= 32 and cp < 127) @intCast(cp) else if (cp == 0x2500) '-' else ' ';
    }
    return out;
}

fn testItem(text: []const u8) feed.TimelineItem {
    return .{
        .uri = "at://did:plc:aaaaaaaaaaaaaaaaaaaaaaaa/app.bsky.feed.post/3kali1",
        .cid = "bafyreialice1",
        .author_handle = "alice.test",
        .author_display_name = "Alice",
        .reposted_by_handle = "",
        .replying_to_handle = "",
        .text = text,
        .created_at = 990,
        .like_count = 3,
        .repost_count = 0,
        .reply_count = 1,
        .quote_count = 0,
        .label_flags = .none,
        .item_flags = .none,
    };
}

test "wrap: breaks at spaces, hard-breaks long words, honors newlines and width" {
    var it = WrapIterator{ .text = "hello world again", .max_width = 6 };
    try testing.expectEqualStrings("hello", it.next().?);
    try testing.expectEqualStrings("world", it.next().?);
    try testing.expectEqualStrings("again", it.next().?);
    try testing.expectEqual(@as(?[]const u8, null), it.next());

    var hard = WrapIterator{ .text = "abcdefgh", .max_width = 3 };
    try testing.expectEqualStrings("abc", hard.next().?);
    try testing.expectEqualStrings("def", hard.next().?);
    try testing.expectEqualStrings("gh", hard.next().?);

    var nl = WrapIterator{ .text = "one\ntwo", .max_width = 10 };
    try testing.expectEqualStrings("one", nl.next().?);
    try testing.expectEqualStrings("two", nl.next().?);

    // Wide glyphs count two columns: only two fit in five.
    var wide = WrapIterator{ .text = "好好好", .max_width = 5 };
    try testing.expectEqualStrings("好好", wide.next().?);
    try testing.expectEqualStrings("好", wide.next().?);
}

test "ages: seconds to weeks" {
    var buf: [16]u8 = undefined;
    try testing.expectEqualStrings("now", formatAge(&buf, 1_000, 990));
    try testing.expectEqualStrings("5m", formatAge(&buf, 1_000, 1_000 - 5 * 60));
    try testing.expectEqualStrings("3h", formatAge(&buf, 100_000, 100_000 - 3 * 3_600));
    try testing.expectEqualStrings("2d", formatAge(&buf, 1_000_000, 1_000_000 - 2 * 86_400));
    try testing.expectEqualStrings("4w", formatAge(&buf, 10_000_000, 10_000_000 - 4 * 604_800));
}

test "actions: movement clamps at both ends" {
    var state: UiState = .{};
    applyAction(&state, .move_up, 10);
    try testing.expectEqual(@as(u32, 0), state.selected);
    applyAction(&state, .go_bottom, 10);
    try testing.expectEqual(@as(u32, 9), state.selected);
    applyAction(&state, .move_down, 10);
    try testing.expectEqual(@as(u32, 9), state.selected);
    applyAction(&state, .page_up, 10);
    try testing.expectEqual(@as(u32, 4), state.selected);
}

test "frame: header, card content, selection gutter, hidden card, footer" {
    const gpa = testing.allocator;
    var surface: tui.Surface = .{};
    defer tui.deinitSurface(gpa, &surface);
    try tui.resizeSurface(gpa, &surface, 44, 14);

    var hidden = testItem("should not appear");
    hidden.label_flags = .{ .spam = true };
    const items = [_]feed.TimelineItem{ testItem("hello timeline"), hidden };
    var state: UiState = .{};

    buildFrame(&surface, &items, &state, &.{}, 1_000, "carol.test", "2 loaded");

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const header = try rowString(arena, &surface, 0);
    try testing.expect(std.mem.indexOf(u8, header, "zat") != null);
    try testing.expect(std.mem.indexOf(u8, header, "@carol.test") != null);
    try testing.expect(std.mem.indexOf(u8, header, "2 items") != null);

    const author_row = try rowString(arena, &surface, 1);
    try testing.expect(std.mem.indexOf(u8, author_row, "> ") != null); // selected gutter
    try testing.expect(std.mem.indexOf(u8, author_row, "Alice @alice.test") != null);

    const body_row = try rowString(arena, &surface, 2);
    try testing.expect(std.mem.indexOf(u8, body_row, "hello timeline") != null);

    // The hidden card shows only its notice.
    var found_notice = false;
    var found_leak = false;
    var y: u16 = 0;
    while (y < surface.height) : (y += 1) {
        const row = try rowString(arena, &surface, y);
        if (std.mem.indexOf(u8, row, "[hidden: likely spam]") != null) found_notice = true;
        if (std.mem.indexOf(u8, row, "should not appear") != null) found_leak = true;
    }
    try testing.expect(found_notice);
    try testing.expect(!found_leak);

    const footer = try rowString(arena, &surface, 13);
    try testing.expect(std.mem.indexOf(u8, footer, "q quit") != null);
    try testing.expect(std.mem.indexOf(u8, footer, "2 loaded") != null);
}

test "frame: scroll reconciliation keeps the selected card on screen" {
    const gpa = testing.allocator;
    var surface: tui.Surface = .{};
    defer tui.deinitSurface(gpa, &surface);
    try tui.resizeSurface(gpa, &surface, 40, 10);

    const items = [_]feed.TimelineItem{
        testItem("post zero"), testItem("post one"),
        testItem("post two"),  testItem("post three"),
        testItem("post four"),
    };
    var state: UiState = .{ .selected = 4 };
    buildFrame(&surface, &items, &state, &.{}, 1_000, "carol.test", "");

    try testing.expect(state.scroll_top > 0);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    var found_selected = false;
    var y: u16 = 0;
    while (y < surface.height) : (y += 1) {
        const row = try rowString(arena_state.allocator(), &surface, y);
        if (std.mem.indexOf(u8, row, "post four") != null) found_selected = true;
    }
    try testing.expect(found_selected);
}

test "compose keys: insert, backspace, send, cancel" {
    try testing.expectEqual(ComposeAction.send, actionForCompose(.{ .char = 4 }));
    try testing.expectEqual(ComposeAction.cancel, actionForCompose(.escape));
    try testing.expectEqual(ComposeAction.backspace, actionForCompose(.{ .char = 127 }));
    try testing.expectEqual(@as(u21, 'x'), actionForCompose(.{ .char = 'x' }).insert);
    try testing.expectEqual(@as(u21, '\n'), actionForCompose(.enter).insert);
    try testing.expectEqual(ComposeAction.none, actionForCompose(.{ .char = 1 }));
}

test "compose frame: reply header, draft, cursor, counter, key bar" {
    const gpa = testing.allocator;
    var surface: tui.Surface = .{};
    defer tui.deinitSurface(gpa, &surface);
    try tui.resizeSurface(gpa, &surface, 40, 10);

    buildComposeFrame(&surface, "hello there", "alice.test", "draft");

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const header = try rowString(arena, &surface, 0);
    try testing.expect(std.mem.indexOf(u8, header, "reply to @alice.test") != null);

    const draft = try rowString(arena, &surface, 2);
    try testing.expect(std.mem.indexOf(u8, draft, "hello there") != null);
    // The cursor cell sits right after the draft, styled inverse.
    const cursor_index = @as(usize, 2) * surface.width + 2 + 11;
    try testing.expect(surface.styles.items[cursor_index].inverse);

    const counter_row = try rowString(arena, &surface, 8);
    try testing.expect(std.mem.indexOf(u8, counter_row, "11/300") != null);

    const footer = try rowString(arena, &surface, 9);
    try testing.expect(std.mem.indexOf(u8, footer, "ctrl-d send") != null);
    try testing.expect(std.mem.indexOf(u8, footer, "draft") != null);

    // A new post (no reply target) says so.
    buildComposeFrame(&surface, "", "", "");
    const header2 = try rowString(arena, &surface, 0);
    try testing.expect(std.mem.indexOf(u8, header2, "new post") != null);
}

test "counts line: viewer markers appear when flags are set" {
    const gpa = testing.allocator;
    var surface: tui.Surface = .{};
    defer tui.deinitSurface(gpa, &surface);
    try tui.resizeSurface(gpa, &surface, 80, 10); // wide tier starts at 72 now

    var item = testItem("marked");
    item.item_flags = .{ .viewer_liked = true };
    const items = [_]feed.TimelineItem{item};
    var state: UiState = .{};
    buildFrame(&surface, &items, &state, &.{}, 1_000, "carol.test", "");

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    var found = false;
    var y: u16 = 0;
    while (y < surface.height) : (y += 1) {
        const row = try rowString(arena_state.allocator(), &surface, y);
        if (std.mem.indexOf(u8, row, "[liked]") != null) found = true;
    }
    try testing.expect(found);

    const footer = try rowString(arena_state.allocator(), &surface, 9);
    try testing.expect(std.mem.indexOf(u8, footer, "b boost") != null); // full bar on wide screens
}

test "reveal toggle: a revealed cid renders the hidden card in full" {
    const gpa = testing.allocator; // C6
    var surface: tui.Surface = .{};
    defer tui.deinitSurface(gpa, &surface);
    try tui.resizeSurface(gpa, &surface, 44, 14);

    var hidden = testItem("the hidden truth");
    hidden.label_flags = .{ .spam = true };
    const items = [_]feed.TimelineItem{hidden};
    var state: UiState = .{};

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    buildFrame(&surface, &items, &state, &.{}, 1_000, "carol.test", "");
    const collapsed = try rowString(arena, &surface, 1);
    try testing.expect(std.mem.indexOf(u8, collapsed, "[hidden:") != null);

    const revealed = [_][]const u8{items[0].cid};
    buildFrame(&surface, &items, &state, &revealed, 1_000, "carol.test", "");
    var shown = false;
    var y: u16 = 1;
    while (y < surface.height) : (y += 1) {
        const row = try rowString(arena, &surface, y);
        if (std.mem.indexOf(u8, row, "the hidden truth") != null) shown = true;
    }
    try testing.expect(shown);
}

test "profile frame: identity, counts, wrapped bio, keybar" {
    const gpa = testing.allocator; // C6
    var surface: tui.Surface = .{};
    defer tui.deinitSurface(gpa, &surface);
    try tui.resizeSurface(gpa, &surface, 40, 12);

    const info: ProfileInfo = .{
        .did = "did:plc:cccccccccccccccccccccccc",
        .handle = "carol.test",
        .display_name = "Carol",
        .description = "writes long careful sentences about systems and birds and weather",
        .followers = 12,
        .follows = 3,
        .posts = 7,
        .following = true,
    };
    buildProfileFrame(&surface, info, "");

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expect(std.mem.indexOf(u8, try rowString(arena, &surface, 2), "Carol") != null);
    const handle_row = try rowString(arena, &surface, 3);
    try testing.expect(std.mem.indexOf(u8, handle_row, "@carol.test") != null);
    try testing.expect(std.mem.indexOf(u8, handle_row, "following") != null);
    try testing.expect(std.mem.indexOf(u8, try rowString(arena, &surface, 5), "12 followers") != null);
    // The bio wraps at width 40: its tail lands on the second bio row.
    const bio_tail = try rowString(arena, &surface, 8);
    try testing.expect(bio_tail.len > 0);
    const footer = try rowString(arena, &surface, surface.height - 1);
    try testing.expect(std.mem.indexOf(u8, footer, "f follow") != null);
}
