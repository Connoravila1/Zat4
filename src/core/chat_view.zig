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
    /// CHAT_FEATURES: a pin and a mute that the list does not SHOW are a pin and a
    /// mute the person cannot trust.
    pinned: bool = false,
    muted: bool = false,

    comptime {
        // Budget 56: 3 slices (48) + u32 (4) = 52, padded to pointer
        // alignment. (A7; raising this requires A7.1 justification.)
        // A7: still 56 — the two flags land in padding the three slices already
        // owned. A pin and a mute the list does not SHOW are ones a person cannot
        // trust, so they have to reach the view; happily they cost nothing to carry.
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
    /// True on the LAST bubble of a consecutive same-sender run (a
    /// different sender, a time-divider gap, or the thread's end closes a
    /// run) — the speech-bubble TAIL draws only there; stacked bubbles
    /// above it stay plain (the grouped-messenger grammar).
    tail: bool = false,
    /// Payment cards only (M5 A4): ordinal into the thread's parallel
    /// `PayCard` slice; `no_pay` for every other kind. For a card, `body`
    /// is the NOTE — the renderer draws amount/rail/status itself.
    pay: u32 = no_pay,
    /// WHICH MESSAGE this row is, in the store (CHAT_FEATURES slice 2). A row IS a
    /// message; it simply never had to say which one until something could be DONE
    /// to it. The context menu acts on the store, so the identity has to survive the
    /// trip out to the view and back.
    msg: u32 = 0,
    /// A tombstone: the text is gone and the bubble says so. Rendered rather than
    /// removed — removing the row would renumber every index above it.
    deleted: bool = false,
    /// The words changed after they were sent. The bubble SAYS so — a message that
    /// was quietly rewritten after you read it is how somebody edits the past.
    edited: bool = false,

    comptime {
        // A7.1 — budget raised 40 → 48. `msg` (u32) is the row's identity in the
        // store and `deleted` is one bit that lands in existing padding; the u32
        // pushes the struct past 40 and alignment rounds to 48. Paid deliberately:
        // without the id, no message action (delete, reply, react) can name the
        // message it is acting on, and the alternative — re-deriving the mapping in
        // the shell from a parallel query — is the kind of implicit coupling that
        // breaks the first time the two orderings disagree.
        assert(@sizeOf(BubbleRow) == 48);
    }
};

pub const no_pay: u32 = std.math.maxInt(u32);

/// A payment card's display facts, parallel to the thread rows (M5 A4).
/// `payment_id` is the wire correlation key — the value a tap hands back
/// to the shell, which resolves it through `chat.findPayment` (no store
/// index crosses here, A5). Per-frame loop ⇒ guarded (A7).
pub const PayCard = struct {
    payment_id: u64,
    amount_sat: u64,
    rail: chat.Rail,
    status: chat.PayStatus,
    confirmations: u8,
    /// The shell is WATCHING this payment settle (LUD-21): the payee's provider
    /// gave us a URL that answers "has it landed?", and we are asking. The card
    /// says so, and pulses, instead of sitting at "approve in your wallet" with
    /// no sign that anything is happening.
    ///
    /// Shell-supplied, not derived from the store — whether a payment can be
    /// watched depends on the payee's provider, which is a network fact, not a
    /// stored one. Defaults false, so previews and the software path are honest.
    watching: bool = false,

    comptime {
        // Budget 24 (unchanged): 2×8 (u64) + 3×1 + the `watching` bool = 20,
        // padded to u64 alignment. It landed in existing padding — no A7.1 bump.
        assert(@sizeOf(PayCard) == 24);
    }
};

/// `buildThread`'s result: the rows plus the payment cards they point at.
/// A7.2: cold struct, size guard waived — one transient per frame.
pub const Thread = struct {
    rows: []BubbleRow = &.{},
    cards: []PayCard = &.{},
};

/// A gap this long between consecutive messages earns a time divider.
pub const stamp_gap: i64 = 15 * 60;

/// Arena-owned relative age via the shared `timefmt` (the single source).
fn ageStr(arena: Allocator, now: i64, created: i64) error{OutOfMemory}![]const u8 {
    var buf: [16]u8 = undefined;
    return arena.dupe(u8, timefmt.format(&buf, now, created));
}

/// A payment card's one-line body (M5 A1 interim — the rich card with the
/// six-block animation is slice A4; until then the bubble states the facts
/// in words, honestly: amount, rail, live status, note). Arena-owned.
fn paymentLine(
    arena: Allocator,
    store: *const chat.Store,
    msg: chat.MsgIndex,
    kind: chat.Kind,
    note: []const u8,
) error{OutOfMemory}![]const u8 {
    // A card without its row is impossible by store invariant; degrade to
    // the note rather than crash if it ever happens (E4).
    const pay = chat.paymentByMsg(store, msg) orelse return note;
    const p = @intFromEnum(pay);
    const amount = store.payments.items(.amount_sat)[p];
    const status = store.payments.items(.status)[p];
    const verb: []const u8 = if (kind == .payment_request) "Payment request" else "Payment";
    const rail: []const u8 = switch (store.payments.items(.rail)[p]) {
        .lightning => "lightning",
        .onchain => "on-chain",
    };
    var status_buf: [24]u8 = undefined;
    const state: []const u8 = if (status == .confirming)
        std.fmt.bufPrint(&status_buf, "{d}/{d} confirmations", .{
            store.payments.items(.confirmations)[p],
            chat.settle_depth,
        }) catch "confirming"
    else
        @tagName(status);
    return if (note.len > 0)
        std.fmt.allocPrint(arena, "{s} · {d} sats · {s} · {s} — {s}", .{ verb, amount, rail, state, note })
    else
        std.fmt.allocPrint(arena, "{s} · {d} sats · {s} · {s}", .{ verb, amount, rail, state });
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
            const mkind = store.msgs.items(.kind)[mi];
            var body = chat.sliceSpan(store, store.msgs.items(.text)[mi]);
            if (chat.isPaymentKind(mkind))
                body = try paymentLine(arena, store, @enumFromInt(mi), mkind, body);
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
            .pinned = convs.items(.pinned)[ci],
            .muted = convs.items(.muted)[ci],
        };
    }
    return out;
}

/// One conversation's bubbles, oldest first, with time dividers computed
/// (first message, and any `stamp_gap` silence). Payment cards ride as
/// rows whose `pay` points into the parallel `cards` slice; their `body`
/// is the note.
pub fn buildThread(
    arena: Allocator,
    store: *const chat.Store,
    conv: chat.ConvIndex,
    now: i64,
) error{OutOfMemory}!Thread {
    const order = try chat.threadSlice(arena, store, conv);
    const created_col = store.msgs.items(.created_at);
    const out = try arena.alloc(BubbleRow, order.len);
    var n_pay: usize = 0;
    for (order) |msg| {
        if (chat.isPaymentKind(store.msgs.items(.kind)[@intFromEnum(msg)])) n_pay += 1;
    }
    const cards = try arena.alloc(PayCard, n_pay);
    var next_card: u32 = 0;
    var prev_at: i64 = 0;
    for (order, out, 0..) |msg, *row, i| {
        const mi: u32 = @intFromEnum(msg);
        const at = created_col[mi];
        const kind = store.msgs.items(.kind)[mi];
        var pay: u32 = no_pay;
        if (chat.isPaymentKind(kind)) {
            // A card without its row is impossible by store invariant;
            // degrade to a plain note bubble rather than crash (E4).
            if (chat.paymentByMsg(store, msg)) |p| {
                const pi = @intFromEnum(p);
                cards[next_card] = .{
                    .payment_id = store.payments.items(.payment_id)[pi],
                    .amount_sat = store.payments.items(.amount_sat)[pi],
                    .rail = store.payments.items(.rail)[pi],
                    .status = store.payments.items(.status)[pi],
                    .confirmations = store.payments.items(.confirmations)[pi],
                };
                pay = next_card;
                next_card += 1;
            }
        }
        const gone = chat.isDeleted(store, mi);
        row.* = .{
            // A deleted message says SO. Leaving the bubble blank would read as a
            // rendering bug; leaving it out would renumber every row above it.
            .body = if (gone) "Message deleted" else chat.sliceSpan(store, store.msgs.items(.text)[mi]),
            .age = try ageStr(arena, now, at),
            .mine = chat.isMine(store, msg),
            .stamp = i == 0 or at - prev_at >= stamp_gap,
            .kind = kind,
            .pay = pay,
            .msg = mi,
            .deleted = gone,
            .edited = chat.isEdited(store, mi),
        };
        prev_at = at;
    }
    // Close each same-sender run: the tail goes on its last bubble (a sender
    // change, a time-divider gap, or the end of the thread ends a run).
    for (out, 0..) |*row, i| {
        row.tail = i + 1 == out.len or out[i + 1].mine != row.mine or out[i + 1].stamp;
    }
    return .{ .rows = out, .cards = cards[0..next_card] };
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

    const rows = (try buildThread(arena, &store, a, 10_000)).rows;

    try std.testing.expectEqual(@as(usize, 3), rows.len);
    try std.testing.expectEqualStrings("hi", rows[0].body);
    try std.testing.expect(rows[0].mine);
    try std.testing.expect(rows[0].stamp); // first message always stamps
    try std.testing.expect(!rows[1].mine);
    try std.testing.expect(!rows[1].stamp); // 30s gap: no divider
    try std.testing.expect(rows[2].stamp); // the silence earns one
    try std.testing.expectEqual(chat.Kind.text, rows[2].kind);
    // Tails close the runs: [0] ends its run (sender change), [1] ends its
    // run too (the divider after it breaks the group even though [2] is the
    // same sender), [2] is the thread's end.
    try std.testing.expect(rows[0].tail);
    try std.testing.expect(rows[1].tail);
    try std.testing.expect(rows[2].tail);
}

test "buildThread: a same-sender run keeps its tail only on the last bubble" {
    const gpa = std.testing.allocator;
    var store: chat.Store = .{};
    defer chat.deinitStore(gpa, &store);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const a = try chat.openConversation(gpa, &store, "did:plc:aaa", "maya.zat4.com");
    _ = try chat.appendMessage(gpa, &store, a, .text, "one", 1000, true);
    _ = try chat.appendMessage(gpa, &store, a, .text, "two", 1010, true);
    _ = try chat.appendMessage(gpa, &store, a, .text, "three", 1020, true);
    _ = try chat.appendMessage(gpa, &store, a, .text, "reply", 1030, false);

    const rows = (try buildThread(arena, &store, a, 2000)).rows;
    try std.testing.expect(!rows[0].tail); // stacked
    try std.testing.expect(!rows[1].tail); // stacked
    try std.testing.expect(rows[2].tail); // the run's last
    try std.testing.expect(rows[3].tail); // thread end
}

test "payment cards ride rows with parallel card facts; list previews summarize" {
    const gpa = std.testing.allocator;
    var store: chat.Store = .{};
    defer chat.deinitStore(gpa, &store);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const a = try chat.openConversation(gpa, &store, "did:plc:aaa", "maya.zat4.com");
    _ = try chat.appendMessage(gpa, &store, a, .text, "hi", 1000, true);
    const req = try chat.appendPayment(gpa, &store, a, .payment_request, 0xCAFE, .lightning, 5000, "dinner", 1010, false);
    const sent = try chat.appendPayment(gpa, &store, a, .payment_sent, 0xBEEF, .onchain, 250_000, "", 1020, true);
    _ = chat.setConfirmations(&store, sent, 3);

    const th = try buildThread(arena, &store, a, 2000);
    try std.testing.expectEqual(@as(usize, 3), th.rows.len);
    try std.testing.expectEqual(@as(usize, 2), th.cards.len);
    // The text bubble points at no card; the cards point in thread order.
    try std.testing.expectEqual(no_pay, th.rows[0].pay);
    try std.testing.expectEqual(chat.Kind.payment_request, th.rows[1].kind);
    try std.testing.expectEqual(@as(u32, 0), th.rows[1].pay);
    try std.testing.expectEqualStrings("dinner", th.rows[1].body); // body = the NOTE
    try std.testing.expectEqual(@as(u64, 0xCAFE), th.cards[0].payment_id);
    try std.testing.expectEqual(@as(u64, 5000), th.cards[0].amount_sat);
    try std.testing.expectEqual(chat.Rail.lightning, th.cards[0].rail);
    try std.testing.expectEqual(chat.PayStatus.requested, th.cards[0].status);
    try std.testing.expectEqual(@as(u32, 1), th.rows[2].pay);
    try std.testing.expectEqual(chat.PayStatus.confirming, th.cards[1].status);
    try std.testing.expectEqual(@as(u8, 3), th.cards[1].confirmations);

    // The list preview keeps the one-line summary ("You: " prefixed — ours).
    const list = try buildList(arena, &store, 2000);
    try std.testing.expectEqualStrings(
        "You: Payment · 250000 sats · on-chain · 3/6 confirmations",
        list[0].preview,
    );

    // A settled card reads settled in the card facts.
    _ = try chat.advancePayment(gpa, &store, req, .settled, null);
    const th2 = try buildThread(arena, &store, a, 2000);
    try std.testing.expectEqual(chat.PayStatus.settled, th2.cards[0].status);
}
