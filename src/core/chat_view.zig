//! B1 classification: CORE (pure). Zat Chat view-models (ZAT_CHAT_ROADMAP
//! slice U2): the chat store's records become render-ready rows — the
//! conversation list and the open thread — the exact analogue of
//! `feed_view.fromTimeline`. Same store + same `now` ⇒ same rows (B2). No
//! clock, no I/O (B4); `now` is handed in by the shell.
//!
//! The RENDERER for these rows is `feed_view.layoutChat` (the settings /
//! loadout precedent: view-model data here, drawing in the premium-UI
//! module). Rows carry borrowed slices — store text lives as long as the
//! store, formatted strings live in the frame arena (C3).

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const chat = @import("chat.zig");
const timefmt = @import("timefmt.zig");

/// One conversation-list entry, resolved for drawing. Built fresh per frame
/// for the visible rows — but it rides a per-frame loop, so it carries the
/// guard (A7).
pub const ListRow = struct {
    /// Display label: the handle when known, else the DID.
    name: []const u8,
    /// The newest message, one line ("You: " prefixed when it is ours);
    /// empty for a conversation with no messages yet.
    preview: []const u8,
    /// Relative age of the last activity; empty when there is none.
    age: []const u8,
    unread: u32,

    comptime {
        // Budget 56: 3 slices (48) + u32 (4) = 52, padded to pointer
        // alignment. (A7; raising this requires A7.1 justification.)
        assert(@sizeOf(ListRow) == 56);
    }
};

/// One thread bubble, resolved for drawing. Per-frame loop ⇒ guarded (A7).
pub const BubbleRow = struct {
    body: []const u8,
    /// Relative age at `now` — drawn only where `stamp` asks for it.
    age: []const u8,
    mine: bool,
    /// True when a time divider should render above this bubble (first
    /// message, or a gap of `stamp_gap` seconds since the previous one).
    stamp: bool,
    kind: chat.Kind,

    comptime {
        // Budget 40: 2 slices (32) + 3 bytes = 35, padded to pointer
        // alignment. (A7)
        assert(@sizeOf(BubbleRow) == 40);
    }
};

/// A gap this long between consecutive messages earns a time divider.
pub const stamp_gap: i64 = 15 * 60;

/// Arena-owned relative age via the shared `timefmt` (the single source).
fn ageStr(arena: Allocator, now: i64, created: i64) error{OutOfMemory}![]const u8 {
    var buf: [16]u8 = undefined;
    return arena.dupe(u8, timefmt.format(&buf, now, created));
}

/// The conversation list, newest activity first — one row per conversation,
/// in the same order `chat.conversationsByActivity` reports. The row
/// ordinal is what a tap region carries; the shell maps it back through its
/// own copy of the ordering query.
pub fn buildList(
    arena: Allocator,
    store: *const chat.Store,
    now: i64,
) error{OutOfMemory}![]ListRow {
    const order = try chat.conversationsByActivity(arena, store);

    // Newest message per conversation, one pass (ties to the later row —
    // matching threadSlice's arrival-order tie-break, whose LAST element is
    // what a preview shows).
    const none = std.math.maxInt(u32);
    const newest = try arena.alloc(u32, store.convs.len);
    @memset(newest, none);
    const conv_col = store.msgs.items(.conv);
    const created_col = store.msgs.items(.created_at);
    for (conv_col, 0..) |c, i| {
        const ci: u32 = @intFromEnum(c);
        if (newest[ci] == none or created_col[i] >= created_col[newest[ci]])
            newest[ci] = @intCast(i);
    }

    const convs = store.convs.slice();
    const out = try arena.alloc(ListRow, order.len);
    for (order, out) |conv, *row| {
        const ci: u32 = @intFromEnum(conv);
        const handle = chat.sliceSpan(store, convs.items(.handle)[ci]);
        const did = chat.sliceSpan(store, convs.items(.did)[ci]);
        const last = convs.items(.last_activity)[ci];

        var preview: []const u8 = "";
        if (newest[ci] != none) {
            const mi = newest[ci];
            const body = chat.sliceSpan(store, store.msgs.items(.text)[mi]);
            preview = if (store.mine.isSet(mi))
                try std.fmt.allocPrint(arena, "You: {s}", .{body})
            else
                body;
        }

        row.* = .{
            .name = if (handle.len > 0) handle else did,
            .preview = preview,
            .age = if (last > 0) try ageStr(arena, now, last) else "",
            .unread = convs.items(.unread)[ci],
        };
    }
    return out;
}

/// One conversation's bubbles, oldest first, with time dividers computed
/// (first message, and any `stamp_gap` silence).
pub fn buildThread(
    arena: Allocator,
    store: *const chat.Store,
    conv: chat.ConvIndex,
    now: i64,
) error{OutOfMemory}![]BubbleRow {
    const order = try chat.threadSlice(arena, store, conv);
    const created_col = store.msgs.items(.created_at);
    const out = try arena.alloc(BubbleRow, order.len);
    var prev_at: i64 = 0;
    for (order, out, 0..) |msg, *row, i| {
        const mi: u32 = @intFromEnum(msg);
        const at = created_col[mi];
        row.* = .{
            .body = chat.sliceSpan(store, store.msgs.items(.text)[mi]),
            .age = try ageStr(arena, now, at),
            .mine = chat.isMine(store, msg),
            .stamp = i == 0 or at - prev_at >= stamp_gap,
            .kind = store.msgs.items(.kind)[mi],
        };
        prev_at = at;
    }
    return out;
}

// ---------------------------------------------------------------------------
// Tests (C6: leak-checked by std.testing.allocator)
// ---------------------------------------------------------------------------

test "buildList resolves order, previews, ages, and DID fallback" {
    const gpa = std.testing.allocator;
    var store: chat.Store = .{};
    defer chat.deinitStore(gpa, &store);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const a = try chat.openConversation(gpa, &store, "did:plc:aaa", "maya.zat4.com");
    const b = try chat.openConversation(gpa, &store, "did:plc:bbb", "");
    _ = try chat.openConversation(gpa, &store, "did:plc:ccc", "quiet.zat4.com");

    _ = try chat.appendMessage(gpa, &store, a, .text, "first", 1000, false);
    _ = try chat.appendMessage(gpa, &store, a, .text, "newest in a", 2000, true);
    _ = try chat.appendMessage(gpa, &store, b, .text, "hello from b", 3000, false);

    const rows = try buildList(arena, &store, 3000 + 120);

    try std.testing.expectEqual(@as(usize, 3), rows.len);
    // b has the newest activity; its handle is unknown so the DID shows.
    try std.testing.expectEqualStrings("did:plc:bbb", rows[0].name);
    try std.testing.expectEqualStrings("hello from b", rows[0].preview);
    try std.testing.expectEqual(@as(u32, 1), rows[0].unread);
    // a's newest message is ours: "You: " prefix.
    try std.testing.expectEqualStrings("maya.zat4.com", rows[1].name);
    try std.testing.expectEqualStrings("You: newest in a", rows[1].preview);
    try std.testing.expect(rows[1].age.len > 0);
    // The empty conversation: no preview, no age.
    try std.testing.expectEqualStrings("quiet.zat4.com", rows[2].name);
    try std.testing.expectEqualStrings("", rows[2].preview);
    try std.testing.expectEqualStrings("", rows[2].age);
}

test "buildThread orders bubbles and computes stamps at silences" {
    const gpa = std.testing.allocator;
    var store: chat.Store = .{};
    defer chat.deinitStore(gpa, &store);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const a = try chat.openConversation(gpa, &store, "did:plc:aaa", "maya.zat4.com");
    _ = try chat.appendMessage(gpa, &store, a, .text, "hi", 1000, true);
    _ = try chat.appendMessage(gpa, &store, a, .text, "quick reply", 1030, false);
    _ = try chat.appendMessage(gpa, &store, a, .text, "much later", 1030 + stamp_gap, false);

    const rows = try buildThread(arena, &store, a, 10_000);

    try std.testing.expectEqual(@as(usize, 3), rows.len);
    try std.testing.expectEqualStrings("hi", rows[0].body);
    try std.testing.expect(rows[0].mine);
    try std.testing.expect(rows[0].stamp); // first message always stamps
    try std.testing.expect(!rows[1].mine);
    try std.testing.expect(!rows[1].stamp); // 30s gap: no divider
    try std.testing.expect(rows[2].stamp); // the silence earns one
    try std.testing.expectEqual(chat.Kind.text, rows[2].kind);
}
