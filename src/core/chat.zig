//! Zat Chat — the conversation store (ZAT_CHAT_ROADMAP slice U1).
//!
//! One resident store for direct messages: a conversation table, a message
//! table, and a string arena, struct-of-arrays throughout (A3). The thread
//! view and the conversation list are QUERIES over this one store, never
//! copies — the same one-store law the feed obeys.
//!
//! PURE CORE (B1/B2): no I/O, no clock — `created_at` and `now` arrive as
//! values. Until milestone M1 this store carries dev-gated plaintext; the
//! encrypted transport hands it decrypted plain text and it neither knows
//! nor cares (B4: nothing crypto-shaped or relay-shaped appears here).
//!
//! Identity: a conversation's counterparty is its DID — the stable id that
//! crosses module boundaries (A5). Handles are display labels that can
//! change; they are reconciled, never trusted as identity.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// The resident records — hot, guarded, integer-only
// ---------------------------------------------------------------------------

/// Offset + length into `Store.string_bytes`.
pub const TextSpan = struct {
    offset: u32,
    len: u32,

    pub const empty: TextSpan = .{ .offset = 0, .len = 0 };

    comptime {
        // Budget: lives inside every hot record below. (A7)
        assert(@sizeOf(TextSpan) == 8);
    }
};

/// Index into `Store.convs`. Typed (the Ast.Node pattern) so a conversation
/// index cannot be handed where a message index belongs.
pub const ConvIndex = enum(u32) { _ };

/// Index into `Store.msgs`.
pub const MsgIndex = enum(u32) { _ };

/// The message-kind vocabulary, defined ONCE and in full so later features
/// land as one more kind with zero schema migration (D6). Reserved values
/// (ZAT_CHAT_ROADMAP §5): 2..15 chat extensions (attachments, reactions,
/// replies), 16..19 the payment card (ZAT5_PAYMENTS §8, milestone M5).
/// Until those slices exist, `parseKind` rejects their bytes (E3).
pub const Kind = enum(u8) {
    text = 0,
    system = 1,
};

pub const KindError = error{UnknownKind};

/// Wire byte -> kind. Reserved and unknown bytes are explicit errors, not
/// silently coerced (E3) — an unrecognized kind is a message this build
/// cannot faithfully render, and pretending it is text would misrepresent it.
pub fn parseKind(byte: u8) KindError!Kind {
    return switch (byte) {
        0 => .text,
        1 => .system,
        else => error.UnknownKind,
    };
}

/// One message. Direction (mine vs. counterparty's) is a single bit stored
/// out of band in `Store.mine` (A6), parallel to `msgs`.
pub const ChatMsg = struct {
    /// Unix seconds — the codebase-wide unit; relative ages and ordering
    /// are integer work.
    created_at: i64,
    text: TextSpan,
    conv: ConvIndex,
    kind: Kind,

    comptime {
        // Budget 24: 8 (i64) + 8 (span) + 4 (conv) + 1 (kind) = 21 bytes of
        // payload; @sizeOf reports 24 because i64 alignment pads the tail.
        // In the SoA store each field lives in its own array, so the pad
        // never materializes — the guard pins the honest @sizeOf and forces
        // a decision the moment any field grows. (A7; raising this number
        // requires A7.1 justification.)
        assert(@sizeOf(ChatMsg) == 24);
    }
};

/// One conversation, deduplicated by counterparty DID. A zero-length handle
/// span encodes "not yet resolved" — no booleans (A6).
pub const Conversation = struct {
    /// Counterparty DID — the identity this conversation is bound to (A5).
    did: TextSpan,
    /// Display handle; reconciled on change, empty until known.
    handle: TextSpan,
    /// Unix seconds of the newest message; drives list ordering. Zero for a
    /// conversation with no messages yet.
    last_activity: i64,
    /// Counterparty messages not yet seen; cleared by `markRead`.
    unread: u32,

    comptime {
        // Budget 32: 2×8 (spans) + 8 (i64) + 4 (u32) = 28 bytes of payload;
        // i64 alignment pads to 32. Same SoA note as ChatMsg. (A7)
        assert(@sizeOf(Conversation) == 32);
    }
};

// ---------------------------------------------------------------------------
// The store — the chat subsystem's resident state
// ---------------------------------------------------------------------------

/// Offset-keyed interning map: keys are u32 offsets of NUL-terminated
/// strings inside `string_bytes`; values are record indexes. std's
/// StringIndex machinery (the compiler's own interning pattern — F2).
const SpanIndexMap = std.HashMapUnmanaged(
    u32,
    u32,
    std.hash_map.StringIndexContext,
    std.hash_map.default_max_load_percentage,
);

/// The chat subsystem's state: one string buffer, two SoA collections, one
/// interning map, one out-of-band direction bitset. Owned by the caller,
/// operated on exclusively through the free functions in this file (D3 by
/// convention).
/// A7.2: cold struct, size guard waived — a singleton, never in a
/// collection; its CONTENTS are the hot, guarded records above.
pub const Store = struct {
    string_bytes: std.ArrayList(u8) = .empty,
    convs: std.MultiArrayList(Conversation) = .empty,
    msgs: std.MultiArrayList(ChatMsg) = .empty,
    conv_by_did: SpanIndexMap = .empty,
    /// Direction bit, parallel to `msgs` (A6): set = authored by THIS
    /// account, clear = authored by the counterparty.
    mine: std.DynamicBitSetUnmanaged = .{},
};

/// Release everything the store owns (C4: this subsystem frees its own
/// memory and nobody else's).
pub fn deinitStore(gpa: Allocator, store: *Store) void {
    store.string_bytes.deinit(gpa);
    store.convs.deinit(gpa);
    store.msgs.deinit(gpa);
    store.conv_by_did.deinit(gpa);
    store.mine.deinit(gpa);
    store.* = undefined;
}

pub fn sliceSpan(store: *const Store, span: TextSpan) []const u8 {
    return store.string_bytes.items[span.offset..][0..span.len];
}

/// Whether this message was authored by the session account (the out-of-band
/// direction bit, A6).
pub fn isMine(store: *const Store, msg: MsgIndex) bool {
    return store.mine.isSet(@intFromEnum(msg));
}

/// The counterparty DID of a conversation — identity crosses module
/// boundaries as the DID (A5); the shell addresses transport with it.
pub fn conversationDid(store: *const Store, conv: ConvIndex) []const u8 {
    return sliceSpan(store, store.convs.items(.did)[@intFromEnum(conv)]);
}

/// Append a string (plus a NUL so the span can serve as an interning key)
/// and return its span.
fn appendString(gpa: Allocator, store: *Store, s: []const u8) error{OutOfMemory}!TextSpan {
    const offset: u32 = @intCast(store.string_bytes.items.len);
    try store.string_bytes.ensureUnusedCapacity(gpa, s.len + 1);
    store.string_bytes.appendSliceAssumeCapacity(s);
    store.string_bytes.appendAssumeCapacity(0);
    return .{ .offset = offset, .len = @intCast(s.len) };
}

// ---------------------------------------------------------------------------
// Mutation — open, append, mark read
// ---------------------------------------------------------------------------

/// Find or create the conversation with `did`, interning by DID. A fresh,
/// non-empty `handle` is reconciled on an actual change (a handle is a
/// mutable label, not identity — same rule as the feed's authors).
pub fn openConversation(
    gpa: Allocator,
    store: *Store,
    did: []const u8,
    handle: []const u8,
) error{OutOfMemory}!ConvIndex {
    const gop = try store.conv_by_did.getOrPutContextAdapted(
        gpa,
        did,
        std.hash_map.StringIndexAdapter{ .bytes = &store.string_bytes },
        std.hash_map.StringIndexContext{ .bytes = &store.string_bytes },
    );
    if (gop.found_existing) {
        const ci: u32 = gop.value_ptr.*;
        const convs = store.convs.slice();
        if (handle.len > 0 and
            !std.mem.eql(u8, sliceSpan(store, convs.items(.handle)[ci]), handle))
        {
            convs.items(.handle)[ci] = try appendString(gpa, store, handle);
        }
        return @enumFromInt(ci);
    }

    const did_span = try appendString(gpa, store, did);
    const handle_span = if (handle.len > 0)
        try appendString(gpa, store, handle)
    else
        TextSpan.empty;

    const index: u32 = @intCast(store.convs.len);
    try store.convs.append(gpa, .{
        .did = did_span,
        .handle = handle_span,
        .last_activity = 0,
        .unread = 0,
    });
    gop.key_ptr.* = did_span.offset;
    gop.value_ptr.* = index;
    return @enumFromInt(index);
}

/// Append one message to a conversation. Bumps the conversation's activity
/// clock and, for a counterparty message, its unread count. `mine` is a
/// parameter, not a stored bool field — it lands in the out-of-band bitset
/// (A6).
pub fn appendMessage(
    gpa: Allocator,
    store: *Store,
    conv: ConvIndex,
    kind: Kind,
    text: []const u8,
    created_at: i64,
    mine: bool,
) error{OutOfMemory}!MsgIndex {
    const span = try appendString(gpa, store, text);
    const index: u32 = @intCast(store.msgs.len);
    try store.msgs.append(gpa, .{
        .created_at = created_at,
        .text = span,
        .conv = conv,
        .kind = kind,
    });
    try store.mine.resize(gpa, store.msgs.len, false);
    store.mine.setValue(index, mine);

    const ci: u32 = @intFromEnum(conv);
    const convs = store.convs.slice();
    // Relay drains and disk resume can deliver out of order; the activity
    // clock only moves forward.
    convs.items(.last_activity)[ci] = @max(convs.items(.last_activity)[ci], created_at);
    if (!mine) convs.items(.unread)[ci] += 1;
    return @enumFromInt(index);
}

/// The reader has seen this conversation; its unread count returns to zero.
pub fn markRead(store: *Store, conv: ConvIndex) void {
    store.convs.slice().items(.unread)[@intFromEnum(conv)] = 0;
}

// ---------------------------------------------------------------------------
// Queries — views over the one store (B5: plain arrays out)
// ---------------------------------------------------------------------------

/// The conversation list, newest activity first. Arena-allocated result
/// (C3); ties break by table order so the output is deterministic.
pub fn conversationsByActivity(
    arena: Allocator,
    store: *const Store,
) error{OutOfMemory}![]ConvIndex {
    const out = try arena.alloc(ConvIndex, store.convs.len);
    for (out, 0..) |*slot, i| slot.* = @enumFromInt(i);
    const activity = store.convs.items(.last_activity);
    const Ctx = struct {
        activity: []const i64,
        pub fn lessThan(ctx: @This(), x: ConvIndex, y: ConvIndex) bool {
            const ax = ctx.activity[@intFromEnum(x)];
            const ay = ctx.activity[@intFromEnum(y)];
            if (ax != ay) return ax > ay;
            return @intFromEnum(x) < @intFromEnum(y);
        }
    };
    std.mem.sort(ConvIndex, out, Ctx{ .activity = activity }, Ctx.lessThan);
    return out;
}

/// One conversation's messages, oldest first. Arena-allocated result (C3);
/// equal timestamps keep arrival order, so the thread never reshuffles under
/// the reader.
pub fn threadSlice(
    arena: Allocator,
    store: *const Store,
    conv: ConvIndex,
) error{OutOfMemory}![]MsgIndex {
    const conv_col = store.msgs.items(.conv);
    var count: usize = 0;
    for (conv_col) |c| {
        if (c == conv) count += 1;
    }
    const out = try arena.alloc(MsgIndex, count);
    var n: usize = 0;
    for (conv_col, 0..) |c, i| {
        if (c == conv) {
            out[n] = @enumFromInt(i);
            n += 1;
        }
    }
    const created = store.msgs.items(.created_at);
    const Ctx = struct {
        created: []const i64,
        pub fn lessThan(ctx: @This(), x: MsgIndex, y: MsgIndex) bool {
            const cx = ctx.created[@intFromEnum(x)];
            const cy = ctx.created[@intFromEnum(y)];
            if (cx != cy) return cx < cy;
            return @intFromEnum(x) < @intFromEnum(y);
        }
    };
    std.mem.sort(MsgIndex, out, Ctx{ .created = created }, Ctx.lessThan);
    return out;
}

// ---------------------------------------------------------------------------
// Tests (C6: leak-checked by std.testing.allocator)
// ---------------------------------------------------------------------------

test "openConversation dedupes by DID and reconciles the handle" {
    const gpa = std.testing.allocator;
    var store: Store = .{};
    defer deinitStore(gpa, &store);

    const a = try openConversation(gpa, &store, "did:plc:aaa", "maya.zat4.com");
    const b = try openConversation(gpa, &store, "did:plc:bbb", "");
    const a2 = try openConversation(gpa, &store, "did:plc:aaa", "maya-moved.zat4.com");

    try std.testing.expectEqual(a, a2);
    try std.testing.expect(a != b);
    try std.testing.expectEqual(@as(usize, 2), store.convs.len);

    const convs = store.convs.slice();
    try std.testing.expectEqualStrings(
        "maya-moved.zat4.com",
        sliceSpan(&store, convs.items(.handle)[@intFromEnum(a)]),
    );
    // The unresolved handle stays an empty span, not a placeholder string.
    try std.testing.expectEqual(@as(u32, 0), convs.items(.handle)[@intFromEnum(b)].len);
}

test "threadSlice orders by time, keeps arrival order on ties, filters by conversation" {
    const gpa = std.testing.allocator;
    var store: Store = .{};
    defer deinitStore(gpa, &store);

    const a = try openConversation(gpa, &store, "did:plc:aaa", "a");
    const b = try openConversation(gpa, &store, "did:plc:bbb", "b");

    const m_late = try appendMessage(gpa, &store, a, .text, "late", 300, true);
    const m_early = try appendMessage(gpa, &store, a, .text, "early", 100, false);
    _ = try appendMessage(gpa, &store, b, .text, "other thread", 200, false);
    const m_tie1 = try appendMessage(gpa, &store, a, .text, "tie first", 200, false);
    const m_tie2 = try appendMessage(gpa, &store, a, .text, "tie second", 200, true);

    const thread = try threadSlice(gpa, &store, a);
    defer gpa.free(thread);

    try std.testing.expectEqual(@as(usize, 4), thread.len);
    try std.testing.expectEqual(m_early, thread[0]);
    try std.testing.expectEqual(m_tie1, thread[1]);
    try std.testing.expectEqual(m_tie2, thread[2]);
    try std.testing.expectEqual(m_late, thread[3]);
    try std.testing.expectEqualStrings(
        "early",
        sliceSpan(&store, store.msgs.items(.text)[@intFromEnum(thread[0])]),
    );
}

test "direction bit, unread accounting, and markRead" {
    const gpa = std.testing.allocator;
    var store: Store = .{};
    defer deinitStore(gpa, &store);

    const a = try openConversation(gpa, &store, "did:plc:aaa", "a");
    const sent = try appendMessage(gpa, &store, a, .text, "hi", 100, true);
    const got1 = try appendMessage(gpa, &store, a, .text, "hey", 110, false);
    const got2 = try appendMessage(gpa, &store, a, .text, "you there?", 120, false);

    try std.testing.expect(isMine(&store, sent));
    try std.testing.expect(!isMine(&store, got1));
    try std.testing.expect(!isMine(&store, got2));

    const unread = store.convs.items(.unread);
    try std.testing.expectEqual(@as(u32, 2), unread[@intFromEnum(a)]);
    markRead(&store, a);
    try std.testing.expectEqual(@as(u32, 0), unread[@intFromEnum(a)]);
}

test "conversation list orders by activity and only moves forward" {
    const gpa = std.testing.allocator;
    var store: Store = .{};
    defer deinitStore(gpa, &store);

    const a = try openConversation(gpa, &store, "did:plc:aaa", "a");
    const b = try openConversation(gpa, &store, "did:plc:bbb", "b");
    const c = try openConversation(gpa, &store, "did:plc:ccc", "c");

    _ = try appendMessage(gpa, &store, a, .text, "1", 100, true);
    _ = try appendMessage(gpa, &store, b, .text, "2", 300, false);
    // An out-of-order (older) arrival must not drag b's activity backward.
    _ = try appendMessage(gpa, &store, b, .text, "old", 50, false);

    const list = try conversationsByActivity(gpa, &store);
    defer gpa.free(list);

    try std.testing.expectEqual(@as(usize, 3), list.len);
    try std.testing.expectEqual(b, list[0]);
    try std.testing.expectEqual(a, list[1]);
    // c has no messages: activity 0, sorted last.
    try std.testing.expectEqual(c, list[2]);
}

test "parseKind accepts the built vocabulary and rejects reserved bytes" {
    try std.testing.expectEqual(Kind.text, try parseKind(0));
    try std.testing.expectEqual(Kind.system, try parseKind(1));
    // Reserved chat extension range.
    try std.testing.expectError(error.UnknownKind, parseKind(7));
    // Reserved payment kinds stay rejected until milestone M5.
    try std.testing.expectError(error.UnknownKind, parseKind(16));
    try std.testing.expectError(error.UnknownKind, parseKind(19));
    try std.testing.expectError(error.UnknownKind, parseKind(255));
}
