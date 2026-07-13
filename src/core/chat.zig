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
/// replies). 16/17 are the payment CARD kinds (M5 slice A1): one card per
/// payment that morphs in place — its live state is the payment row's
/// `status`, never a second bubble. The settlement wire bytes 18/19 flip an
/// existing card and are never stored (see `kind_pay_settled_wire`).
/// Unbuilt bytes stay rejected by `parseKind` (E3).
pub const Kind = enum(u8) {
    text = 0,
    system = 1,
    /// A payment card asking the counterparty for an amount (starts
    /// `requested`; its ChatMsg text is the optional note).
    payment_request = 16,
    /// A payment card announcing an initiated payment (starts `broadcast`).
    payment_sent = 17,
};

/// True for the kinds that carry a parallel payment row (card ⇔ row, A1).
pub fn isPaymentKind(kind: Kind) bool {
    return kind == .payment_request or kind == .payment_sent;
}

/// The typing-indicator ping's WIRE kind byte (from the reserved chat-
/// extension range 2..15). Ephemeral by construction: it rides the same
/// E2EE channel as a message ([kind][…] → mls.encrypt → bucket — the relay
/// sees one more fixed-size opaque blob), but it is consumed at the session
/// layer and NEVER enters the store, so `parseKind` keeps rejecting it —
/// a typing ping that somehow reached a history blob is damage, not data.
pub const kind_typing_wire: u8 = 2;

/// The group-ACK's WIRE kind byte (also from the reserved 2..15 range). The
/// joiner sends one the moment it accepts a Welcome, over the group it just
/// joined — so the ack is MLS-authenticated end to end, not a relay receipt
/// (the relay never learns that a delivery happened, which is what the
/// standing no-auto-receipt rule requires). Wire-only, like the typing ping:
/// it is consumed at the session layer and never enters the store, so
/// `parseKind` keeps rejecting it.
///
/// Why it exists: a Welcome used to be a single unacknowledged shot. Lose it
/// — a relay restart (the store is in-memory by design), a momentary
/// disconnect, a recipient offline past the TTL — and the STARTER still
/// believes a group exists while every message after it vanishes silently.
/// The ack is the one bit that tells the starter the conversation is real.
pub const kind_group_ack_wire: u8 = 3;

/// How many times an unacknowledged Welcome is re-sent before the client
/// stops and says so. With the ladder below this is ~1 hour of trying; a
/// relaunch starts the ladder over (`restoreGroups`), so a peer who comes
/// back tomorrow still gets the Welcome without anyone touching a button.
pub const welcome_retry_max: u8 = 12;

/// The floor between two acks for the SAME conversation. A Welcome bucket is
/// public bytes on a public mailbox, so anyone can replay one at us; without
/// this floor each replay would make us encrypt + deposit another ack.
pub const welcome_ack_min_gap_s: i64 = 5;

/// Seconds to wait after `attempts` sends before trying again: 5s, 10, 20,
/// 40 … capped at 10 minutes. Fast enough that a peer who opens the app a
/// few seconds later gets the Welcome immediately; slow enough that an
/// offline peer costs a handful of deposits an hour.
pub fn welcomeRetryDelay(attempts: u8) i64 {
    if (attempts == 0) return 0; // never sent: send now
    const shift: u6 = @intCast(@min(attempts - 1, 8));
    return @min(@as(i64, 5) << shift, 600);
}

/// Whether an unacknowledged Welcome is due for another send. Pure policy —
/// the shell supplies the clock (B3).
pub fn welcomeRetryDue(attempts: u8, last_sent: i64, now: i64) bool {
    if (attempts >= welcome_retry_max) return false;
    return now - last_sent >= welcomeRetryDelay(attempts);
}

/// What the OTHER side knows about this conversation, as the thread must say
/// it. `confirmed` = they acked; the channel is real. `waiting` = the Welcome
/// is out and unanswered (we are still retrying) — an honest "waiting for
/// them to receive this", never a dead thread that looks alive. `undelivered`
/// = the retries are spent; the repair is one tap away.
///
/// `needs_reconnect` (A2) is the other way a conversation dies: the two halves
/// DRIFTED — a Commit one side never saw — and their messages no longer open
/// under our ratchet. Until now the only signal was "replies stopped," because
/// the failed message was dropped and the thread went on looking perfectly
/// healthy. It takes precedence over the Welcome states: a channel that cannot
/// decrypt is broken now, whatever it was doing before.
pub const Delivery = enum(u8) { confirmed = 0, waiting = 1, undelivered = 2, needs_reconnect = 3 };

/// The settlement-event WIRE bytes (the reserved 18/19). Like the typing
/// ping they never enter the store as messages — `parseKind` keeps
/// rejecting them — but unlike it they are not ephemeral: the session layer
/// correlates the frame's payment_id to an existing card and advances that
/// card's `status` (settled/failed), which M2 then persists. One card per
/// payment, morphing in place; never a fifth bubble.
pub const kind_pay_settled_wire: u8 = 18;
pub const kind_pay_failed_wire: u8 = 19;

/// The send-to-a-walletless-recipient LIFECYCLE wire bytes (S2,
/// PAYMENT_UX_SPEC §11). Same posture as the settlement bytes above —
/// wire-only, `parseKind` keeps rejecting them, correlate by payment_id —
/// but they drive the pre-money offer handshake, never a transfer:
///   20 offer   — payer → recipient: "I want to pay you, but you have no
///                wallet." The recipient's drain CREATES a card at
///                `pending_setup` (never inferred from setup state — that is
///                a race that would imply money is coming when none is, §11.1).
///   21 ready   — recipient → payer: "I set up a wallet." Advances to `ready`.
///   22 cancel  — the initiator withdrew → `cancelled`.
///   23 decline — the other side declined → `declined`.
pub const kind_pay_offer_wire: u8 = 20;
pub const kind_pay_ready_wire: u8 = 21;
pub const kind_pay_cancel_wire: u8 = 22;
pub const kind_pay_decline_wire: u8 = 23;

/// True for a lifecycle wire byte that FLIPS an existing card to a known
/// terminal-or-forward status (21/22/23 and the settlement 18/19) — as
/// opposed to the offer byte 20, which CREATES one. The mapped status is the
/// receiver's target (`advancePayment`); an unmapped byte returns null.
pub fn payEventStatus(byte: u8) ?PayStatus {
    return switch (byte) {
        kind_pay_settled_wire => .settled,
        kind_pay_failed_wire => .failed,
        kind_pay_ready_wire => .ready,
        kind_pay_cancel_wire => .cancelled,
        kind_pay_decline_wire => .declined,
        else => null,
    };
}

pub const KindError = error{UnknownKind};

/// Wire byte -> kind. Reserved and unknown bytes are explicit errors, not
/// silently coerced (E3) — an unrecognized kind is a message this build
/// cannot faithfully render, and pretending it is text would misrepresent it.
pub fn parseKind(byte: u8) KindError!Kind {
    return switch (byte) {
        0 => .text,
        1 => .system,
        16 => .payment_request,
        17 => .payment_sent,
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
// Payments (M5 slice A1) — plain-data rows parallel to the message array.
// A payment is one ChatMsg (kind payment_request/payment_sent; created_at,
// the note as its text span, the conversation, and the direction bit all
// live THERE and are never duplicated) plus one PaymentRow carrying what a
// text bubble lacks. The txid / payment hash is colder still and lives out
// of band in `SettlementRef` (A6). ZAT_CHAT_ROADMAP PART II §8.
// ---------------------------------------------------------------------------

/// Index into `Store.payments`.
pub const PayIndex = enum(u32) { _ };

/// The two co-equal rails (PART II §1). They differ only in how settlement
/// is proven — a preimage (lightning) vs. watched confirmation depth
/// (onchain); the rail is one field on the card and nothing else forks.
pub const Rail = enum(u8) { lightning = 0, onchain = 1 };

/// A card's live state. `requested`/`pending` are pre-money, `broadcast`/
/// `confirming` are in flight, `settled`/`failed` are terminal. Transitions
/// are monotonic (`advancePayment`) — a card never un-settles.
/// The card lifecycle (PAYMENT_UX_SPEC §4). Values 0–5 are the original set and
/// are FROZEN (the history codec persists this byte); 6+ were appended for the
/// full flow, so old history still reads. `pending` is the "awaiting_wallet"
/// state (handed to the payer's wallet, not yet on the wire). `pending_setup`,
/// `ready`, `cancelled`, `declined`, `expired` are reached by the send-to-a-
/// walletless-recipient and cancel/decline/expire flows (later slices); the
/// state + its per-side honest copy exist now.
pub const PayStatus = enum(u8) {
    requested = 0,
    pending = 1, // == awaiting_wallet: handed to the payer's wallet
    broadcast = 2,
    confirming = 3,
    settled = 4,
    failed = 5,
    pending_setup = 6, // send offered to someone with no wallet yet
    ready = 7, // that someone set up; the payer must re-confirm
    cancelled = 8, // the initiator withdrew it
    declined = 9, // the other side declined
    expired = 10, // the offer/request lapsed unanswered
};

pub fn isTerminalStatus(s: PayStatus) bool {
    return switch (s) {
        .settled, .failed, .cancelled, .declined, .expired => true,
        else => false,
    };
}

/// True once a card has NETWORK evidence behind it — seen in a mempool or
/// deeper (`broadcast`/`confirming`/`settled`). Money is (or may be) in
/// motion. A peer's withdrawal event (cancel/decline) must never retire such
/// a card: doing so would hide a real transfer, the worst golden-rule
/// violation. The shell gates remote withdrawals on this at the wire boundary.
pub fn hasNetworkEvidence(s: PayStatus) bool {
    return switch (s) {
        .broadcast, .confirming, .settled => true,
        else => false,
    };
}

/// Forward-only ordering for `advancePayment`; every terminal ranks last.
fn statusRank(s: PayStatus) u8 {
    return switch (s) {
        .pending_setup, .requested => 0,
        .ready => 1,
        .pending => 2,
        .broadcast => 3,
        .confirming => 4,
        .settled, .failed, .cancelled, .declined, .expired => 5,
    };
}

/// Every sat that will ever exist (21e6 BTC × 1e8). An amount of zero or
/// above this is malformed on its face — rejected at the wire (E3).
pub const max_amount_sat: u64 = 2_100_000_000_000_000;

/// The on-chain depth at which a card settles (the six-block animation's
/// last block; PART II §4).
pub const settle_depth: u8 = 6;

/// The hot payment row, parallel to a payment-kind ChatMsg (card ⇔ row is a
/// store invariant, enforced at append and at restore).
pub const PaymentRow = struct {
    /// Wire correlation id, minted nonzero by the initiating side (the
    /// shell's randomness — a value here, so this stays pure, B4). Trusted
    /// only within its conversation (`findPayment`).
    payment_id: u64,
    /// Sats on both rails (msat precision deliberately not modeled: the
    /// card's unit is the sat; a wallet may settle finer, we display sats).
    amount_sat: u64,
    /// The card this row details — a within-module back-ref (A4); it never
    /// crosses out of chat.zig (A5).
    msg: MsgIndex,
    rail: Rail,
    status: PayStatus,
    /// Watched on-chain depth (drives the six-block animation); 0 for
    /// lightning, saturating at 255.
    confirmations: u8,

    comptime {
        // Budget 24: 2×8 (u64) + 4 (msg) + 3×1 = 23 bytes of payload,
        // padded to u64 alignment. Same SoA note as ChatMsg. (A7; raising
        // this requires A7.1 justification.)
        assert(@sizeOf(PaymentRow) == 24);
    }
};

/// Settlement detail, out of band from the hot card (A6): the on-chain txid
/// or the lightning payment hash — both exactly 32 bytes, so one fixed
/// field serves both rails. Consulted when a card is watched or tapped,
/// never in the per-frame render scan.
pub const SettlementRef = struct {
    /// The payment row this belongs to. The roadmap sketch keyed this by
    /// payment_id ("a stable id, not a bare index across modules") — that
    /// concern is CROSS-module; both tables live here, so the within-module
    /// index is lawful (A4) and immune to a peer replaying someone else's
    /// id. The wire still correlates by payment_id.
    pay: PayIndex,
    /// txid (onchain) / payment hash (lightning). Never all-zero — zero
    /// means "none yet", and "none yet" is the absence of a row.
    ref: [32]u8,

    comptime {
        // Budget 36: 4 + 32, u32 alignment, no padding. (A7)
        assert(@sizeOf(SettlementRef) == 36);
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
    /// One row per payment card (card ⇔ row; M5 A1).
    payments: std.MultiArrayList(PaymentRow) = .empty,
    /// Cold settlement detail, at most one row per payment (A6).
    settlements: std.MultiArrayList(SettlementRef) = .empty,
};

/// Release everything the store owns (C4: this subsystem frees its own
/// memory and nobody else's).
pub fn deinitStore(gpa: Allocator, store: *Store) void {
    store.string_bytes.deinit(gpa);
    store.convs.deinit(gpa);
    store.msgs.deinit(gpa);
    store.conv_by_did.deinit(gpa);
    store.mine.deinit(gpa);
    store.payments.deinit(gpa);
    store.settlements.deinit(gpa);
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

/// The counterparty's display handle ("" until known) — a label, not an
/// identity (the DID above is the identity).
pub fn conversationHandle(store: *const Store, conv: ConvIndex) []const u8 {
    return sliceSpan(store, store.convs.items(.handle)[@intFromEnum(conv)]);
}

/// The DIDs of every conversation still wearing no handle — the shell's work
/// list for handle resolution (a conversation opened by an INBOUND message
/// knows only the DID, so it would otherwise render as `did:plc:…` forever).
///
/// Pure: a query over the store, no clock, no network (B2). The shell resolves
/// these off-thread and hands each answer back through `openConversation`,
/// which reconciles the handle in place. `arena` owns the returned slice; the
/// DIDs inside it borrow the store's text (they outlive the call only as long
/// as the store does — the shell copies them before crossing the thread seam).
pub fn unresolvedDids(arena: Allocator, store: *const Store) error{OutOfMemory}![][]const u8 {
    var out: std.ArrayListUnmanaged([]const u8) = .empty;
    const convs = store.convs.slice();
    var i: u32 = 0;
    while (i < store.convs.len) : (i += 1) {
        if (convs.items(.handle)[i].len != 0) continue;
        try out.append(arena, sliceSpan(store, convs.items(.did)[i]));
    }
    return out.toOwnedSlice(arena);
}

/// One payment row, by value — the shell reads facts through this, never
/// the arrays (D3 by convention, same as the accessors above).
pub fn paymentRow(store: *const Store, pay: PayIndex) PaymentRow {
    return store.payments.get(@intFromEnum(pay));
}

/// How many payment rows the store holds — the sweep/announce loops walk
/// `0..paymentCount` (the index never leaves this module, A5).
pub fn paymentCount(store: *const Store) u32 {
    return @intCast(store.payments.len);
}

/// The conversation a payment belongs to — resolved through its card's
/// ChatMsg, the single source of the conv/direction facts (A1).
pub fn paymentConv(store: *const Store, pay: PayIndex) ConvIndex {
    const msg = store.payments.items(.msg)[@intFromEnum(pay)];
    return store.msgs.items(.conv)[@intFromEnum(msg)];
}

/// Whether the session account authored this payment card (the offer/send
/// initiator vs. the counterparty), via the same out-of-band direction bit.
pub fn paymentMine(store: *const Store, pay: PayIndex) bool {
    return isMine(store, store.payments.items(.msg)[@intFromEnum(pay)]);
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
/// (A6). Payment kinds must go through `appendPayment` so the card ⇔ row
/// invariant can never break.
pub fn appendMessage(
    gpa: Allocator,
    store: *Store,
    conv: ConvIndex,
    kind: Kind,
    text: []const u8,
    created_at: i64,
    mine: bool,
) error{OutOfMemory}!MsgIndex {
    assert(!isPaymentKind(kind));
    return appendRecord(gpa, store, conv, kind, text, created_at, mine);
}

fn appendRecord(
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
// Payment mutation — the card ⇔ row pair, and the monotonic state machine
// ---------------------------------------------------------------------------

/// Append one payment CARD: a ChatMsg (its text is the optional note) plus
/// its parallel payment row, created together so card ⇔ row never breaks —
/// the row's capacity is reserved BEFORE the message lands, so an OOM can
/// never leave a card without its row. Initial status comes from the kind:
/// a request starts `requested`, a sent card starts `pending` — initiated
/// but UNOBSERVED. `broadcast`/`confirming` are network-evidence states
/// (the A5 watcher's), and a card never claims evidence nobody has (§6
/// honesty). The caller guarantees `payment_id` is
/// nonzero, unique in the conversation, and the amount is in range — wire
/// input satisfies this via `parsePaymentFrame` (E3); local input by
/// construction.
pub fn appendPayment(
    gpa: Allocator,
    store: *Store,
    conv: ConvIndex,
    kind: Kind,
    payment_id: u64,
    rail: Rail,
    amount_sat: u64,
    note: []const u8,
    created_at: i64,
    mine: bool,
) error{OutOfMemory}!PayIndex {
    assert(isPaymentKind(kind));
    assert(payment_id != 0);
    assert(amount_sat >= 1 and amount_sat <= max_amount_sat);
    assert(findPayment(store, conv, payment_id) == null);
    try store.payments.ensureUnusedCapacity(gpa, 1);
    const msg = try appendRecord(gpa, store, conv, kind, note, created_at, mine);
    const index: u32 = @intCast(store.payments.len);
    store.payments.appendAssumeCapacity(.{
        .payment_id = payment_id,
        .amount_sat = amount_sat,
        .msg = msg,
        .rail = rail,
        .status = if (kind == .payment_request) .requested else .pending,
        .confirmations = 0,
    });
    return @enumFromInt(index);
}

/// Set a FRESHLY-appended card's status directly, before it has begun its
/// lifecycle. This is the one legitimate bypass of the monotonic gate: a
/// `payment_sent` OFFERED to a walletless recipient must start at
/// `pending_setup` (rank 0), which `advancePayment` cannot reach from the
/// kind's default `pending` (rank 2) — the ranks only climb. Never call on a
/// card that has already advanced; the offer create-path (S2) is the sole
/// caller on both sides.
pub fn initPaymentStatus(store: *Store, pay: PayIndex, status: PayStatus) void {
    store.payments.items(.status)[@intFromEnum(pay)] = status;
}

/// The payment row a wire event addresses, matched by (conversation,
/// payment_id) — an id is trusted only within its own conversation, so a
/// peer replaying an id seen elsewhere reaches nothing. Linear scan:
/// payments per store are few, and this runs per event, not per frame (G3).
pub fn findPayment(store: *const Store, conv: ConvIndex, payment_id: u64) ?PayIndex {
    const ids = store.payments.items(.payment_id);
    const msg_col = store.payments.items(.msg);
    const conv_col = store.msgs.items(.conv);
    for (ids, msg_col, 0..) |id, mi, i| {
        if (id == payment_id and conv_col[@intFromEnum(mi)] == conv)
            return @enumFromInt(i);
    }
    return null;
}

/// The payment row behind a card's ChatMsg (the view resolves bubbles this
/// way). Same linear-scan posture as `findPayment`.
pub fn paymentByMsg(store: *const Store, msg: MsgIndex) ?PayIndex {
    for (store.payments.items(.msg), 0..) |mi, i| {
        if (mi == msg) return @enumFromInt(i);
    }
    return null;
}

/// Advance a card's status — from a wire event or a local hand-off result.
/// Monotonic and terminal-absorbing (E4): a terminal card ignores
/// everything (duplicates and stragglers are no-ops, never corruption); a
/// non-terminal card accepts either terminal at any time and a forward step
/// otherwise. A provided `ref` attaches first-wins — a wire event can never
/// rewrite an already-recorded txid/hash (local re-broadcast goes through
/// `setSettlementRef` directly, which replaces). Returns whether anything
/// changed, so the shell persists only on change.
pub fn advancePayment(
    gpa: Allocator,
    store: *Store,
    pay: PayIndex,
    to: PayStatus,
    ref: ?[32]u8,
) error{OutOfMemory}!bool {
    const p = @intFromEnum(pay);
    const status_col = store.payments.items(.status);
    if (isTerminalStatus(status_col[p])) return false;
    var changed = false;
    if (isTerminalStatus(to) or statusRank(to) > statusRank(status_col[p])) {
        status_col[p] = to;
        changed = true;
    }
    if (ref) |r| {
        if (settlementRef(store, pay) == null) {
            try setSettlementRef(gpa, store, pay, r);
            changed = true;
        }
    }
    return changed;
}

/// Record the watched on-chain depth (slice A5 feeds this; the view maps
/// depth → filled blocks). Depth only moves forward; `settle_depth` settles
/// the card, anything shallower marks it confirming. Terminal cards absorb
/// (E4). On-chain only — a lightning card has no depth to watch.
pub fn setConfirmations(store: *Store, pay: PayIndex, depth: u8) bool {
    const p = @intFromEnum(pay);
    assert(store.payments.items(.rail)[p] == .onchain);
    const status_col = store.payments.items(.status);
    const conf_col = store.payments.items(.confirmations);
    if (isTerminalStatus(status_col[p])) return false;
    var changed = false;
    if (depth > conf_col[p]) {
        conf_col[p] = depth;
        changed = true;
    }
    const next: PayStatus = if (depth >= settle_depth)
        .settled
    else if (depth >= 1)
        .confirming
    else
        status_col[p];
    if (next != status_col[p] and statusRank(next) > statusRank(status_col[p])) {
        status_col[p] = next;
        changed = true;
    }
    return changed;
}

/// How long an unanswered OFFER or REQUEST stands before it lapses (§6). 24h
/// survives an overnight so nobody misses it, then clears — we custody
/// nothing, so a stale offer is only thread clutter, and the initiator
/// re-sends in one tap. One tunable constant.
pub const payment_offer_ttl_s: i64 = 24 * 3600;

/// Retire every unanswered offer/request older than the TTL to `expired`,
/// pure and local — both sides run it against the same immutable `created_at`
/// and reach the same terminal, no wire needed (§11.3). ONLY the pre-commit
/// states lapse: `pending_setup`/`ready`/`requested` moved no money, so
/// expiring them is honest; a `pending`/`broadcast`/`confirming` card has a
/// hand-off or a mempool sighting behind it and must NEVER be silently
/// retired (that would hide a possible transfer — the golden rule). Returns
/// whether anything changed, so the shell persists only on change.
pub fn sweepExpired(store: *Store, now: i64, ttl_s: i64) bool {
    const status_col = store.payments.items(.status);
    const msg_col = store.payments.items(.msg);
    const created_col = store.msgs.items(.created_at);
    var changed = false;
    for (status_col, msg_col) |*s, mi| {
        switch (s.*) {
            .pending_setup, .ready, .requested => {},
            else => continue,
        }
        if (now - created_col[@intFromEnum(mi)] >= ttl_s) {
            s.* = .expired;
            changed = true;
        }
    }
    return changed;
}

/// Attach (or replace) a card's settlement detail — the upsert primitive;
/// wire-event policy (first-wins) lives in `advancePayment`. A ref is never
/// all-zero (zero means "none yet", and that is the absence of a row).
pub fn setSettlementRef(
    gpa: Allocator,
    store: *Store,
    pay: PayIndex,
    ref: [32]u8,
) error{OutOfMemory}!void {
    assert(!std.mem.allEqual(u8, &ref, 0));
    for (store.settlements.items(.pay), 0..) |p, i| {
        if (p == pay) {
            store.settlements.items(.ref)[i] = ref;
            return;
        }
    }
    try store.settlements.append(gpa, .{ .pay = pay, .ref = ref });
}

/// The card's txid / payment hash, when one has been recorded.
pub fn settlementRef(store: *const Store, pay: PayIndex) ?[32]u8 {
    for (store.settlements.items(.pay), 0..) |p, i| {
        if (p == pay) return store.settlements.items(.ref)[i];
    }
    return null;
}

/// One on-chain card the watcher should ask the chain about (M5 A5): the
/// correlation key, the amount, the conversation, and WHOSE published
/// address receives the money — a request pays its AUTHOR; a sent card
/// pays the author's counterparty. Plain values out (B5); the shell
/// resolves DIDs to addresses and anchors.
/// A7.2: cold struct, size guard waived — a poll-cycle snapshot, few.
pub const WatchEntry = struct {
    payment_id: u64,
    amount_sat: u64,
    conv: ConvIndex,
    /// True: the money lands at MY published address; false: at the
    /// counterparty's.
    mine_address: bool,
};

/// Every live on-chain card, as watch entries (arena-owned, C3). Lightning
/// cards have nothing to watch (preimage settles them); terminal cards are
/// done.
pub fn watchList(arena: Allocator, store: *const Store) error{OutOfMemory}![]WatchEntry {
    const pays = store.payments.slice();
    var n: usize = 0;
    for (pays.items(.rail), pays.items(.status)) |r, s| {
        if (r == .onchain and !isTerminalStatus(s)) n += 1;
    }
    const out = try arena.alloc(WatchEntry, n);
    var i: usize = 0;
    for (0..store.payments.len) |p| {
        if (pays.items(.rail)[p] != .onchain or isTerminalStatus(pays.items(.status)[p])) continue;
        const mi = @intFromEnum(pays.items(.msg)[p]);
        const mine = store.mine.isSet(mi);
        out[i] = .{
            .payment_id = pays.items(.payment_id)[p],
            .amount_sat = pays.items(.amount_sat)[p],
            .conv = store.msgs.items(.conv)[mi],
            .mine_address = if (store.msgs.items(.kind)[mi] == .payment_request) mine else !mine,
        };
        i += 1;
    }
    return out;
}

// ---------------------------------------------------------------------------
// The payment wire frame (pure) — what rides after the kind byte for every
// payment wire byte (16..19). One fixed shape for all four: the card kinds
// (16/17) create or advance a card; the event bytes (18/19) correlate by
// payment_id and settle/fail it. Strict little-endian, exact header,
// explicit errors on parse (E3).
//
//   [payment_id u64][amount_sat u64][ref 32B, all-zero = absent][rail u8][note …]
// ---------------------------------------------------------------------------

/// Frame bytes before the note (the note is everything after).
pub const payment_frame_min: usize = 49;

pub const zero_ref: [32]u8 = @splat(0);

/// A parsed (or to-build) frame. The note is borrowed from the parse buffer
/// / the caller (C3-style: the receiver copies what it keeps).
pub const PaymentFrame = struct {
    payment_id: u64,
    amount_sat: u64,
    /// Borrowed; empty is legal (the note is optional).
    note: []const u8,
    /// txid (onchain) / payment hash (lightning); all-zero = none.
    ref: [32]u8,
    rail: Rail,

    comptime {
        // Budget 72: 2×8 + 16 (slice) + 32 + 1 = 65 bytes of payload,
        // padded to pointer alignment. Transient, but it rides the receive
        // path — guarded (A7).
        assert(@sizeOf(PaymentFrame) == 72);
    }
};

pub const FrameError = error{Malformed};

/// Serialize a frame into `buf` (no allocation — the shell composes it
/// straight into the plaintext it encrypts). Asserts validity: the builder
/// is ours; hostile bytes exist only on parse.
pub fn buildPaymentFrame(buf: []u8, frame: PaymentFrame) []const u8 {
    assert(frame.payment_id != 0);
    assert(frame.amount_sat >= 1 and frame.amount_sat <= max_amount_sat);
    assert(buf.len >= payment_frame_min + frame.note.len);
    std.mem.writeInt(u64, buf[0..8], frame.payment_id, .little);
    std.mem.writeInt(u64, buf[8..16], frame.amount_sat, .little);
    @memcpy(buf[16..48], &frame.ref);
    buf[48] = @intFromEnum(frame.rail);
    @memcpy(buf[payment_frame_min..][0..frame.note.len], frame.note);
    return buf[0 .. payment_frame_min + frame.note.len];
}

/// Parse a wire frame — hostile input; every violation is an explicit
/// error, never a coerced value (E3).
pub fn parsePaymentFrame(bytes: []const u8) FrameError!PaymentFrame {
    if (bytes.len < payment_frame_min) return error.Malformed;
    const id = std.mem.readInt(u64, bytes[0..8], .little);
    const amount = std.mem.readInt(u64, bytes[8..16], .little);
    if (id == 0 or amount == 0 or amount > max_amount_sat) return error.Malformed;
    const rail: Rail = switch (bytes[48]) {
        0 => .lightning,
        1 => .onchain,
        else => return error.Malformed,
    };
    var ref: [32]u8 = undefined;
    @memcpy(&ref, bytes[16..48]);
    return .{
        .payment_id = id,
        .amount_sat = amount,
        .note = bytes[payment_frame_min..],
        .ref = ref,
        .rail = rail,
    };
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
// Persistence codec (pure) — the store's byte round-trip (Zat Chat M2).
// The shell owns WHERE the bytes live (cache, sealed at rest); this layer
// owns only WHAT they are. Explicit little-endian, exact lengths, and a
// malformed blob is an error, never a half-restored store — the same
// posture as mls.serializeGroup (E3).
// ---------------------------------------------------------------------------

const codec_magic = [4]u8{ 'Z', 'A', 'T', 'H' };
/// Version 2 (M5 A1) appends the payments + settlements sections. Version-1
/// blobs (pre-payments history) are still READ — their sections are simply
/// empty — so an existing transcript survives the upgrade; writes are
/// always version 2.
const codec_version: u16 = 2;
const conv_rec_len = 28; // did span 8 + handle span 8 + i64 8 + u32 4
const msg_rec_len = 21; // i64 8 + text span 8 + conv 4 + kind 1
const pay_rec_len = 23; // id 8 + amount 8 + msg 4 + rail 1 + status 1 + conf 1
const ref_rec_len = 36; // pay 4 + ref 32

pub const DeserializeError = error{ Malformed, OutOfMemory };

/// The store as one canonical byte blob (gpa-owned). The `conv_by_did`
/// interning map is derived state and is not written — restore rebuilds it.
pub fn serializeStore(gpa: Allocator, store: *const Store) error{OutOfMemory}![]u8 {
    const s_len = store.string_bytes.items.len;
    const c_count = store.convs.len;
    const m_count = store.msgs.len;
    const p_count = store.payments.len;
    const r_count = store.settlements.len;
    const total = 4 + 2 + 4 + s_len +
        4 + c_count * conv_rec_len +
        4 + m_count * msg_rec_len +
        (m_count + 7) / 8 +
        4 + p_count * pay_rec_len +
        4 + r_count * ref_rec_len;
    const out = try gpa.alloc(u8, total);
    errdefer gpa.free(out);

    var at: usize = 0;
    @memcpy(out[at..][0..4], &codec_magic);
    at += 4;
    std.mem.writeInt(u16, out[at..][0..2], codec_version, .little);
    at += 2;
    std.mem.writeInt(u32, out[at..][0..4], @intCast(s_len), .little);
    at += 4;
    @memcpy(out[at..][0..s_len], store.string_bytes.items);
    at += s_len;

    std.mem.writeInt(u32, out[at..][0..4], @intCast(c_count), .little);
    at += 4;
    const convs = store.convs.slice();
    for (0..c_count) |i| {
        const spans = [2]TextSpan{ convs.items(.did)[i], convs.items(.handle)[i] };
        for (spans) |span| {
            std.mem.writeInt(u32, out[at..][0..4], span.offset, .little);
            at += 4;
            std.mem.writeInt(u32, out[at..][0..4], span.len, .little);
            at += 4;
        }
        std.mem.writeInt(i64, out[at..][0..8], convs.items(.last_activity)[i], .little);
        at += 8;
        std.mem.writeInt(u32, out[at..][0..4], convs.items(.unread)[i], .little);
        at += 4;
    }

    std.mem.writeInt(u32, out[at..][0..4], @intCast(m_count), .little);
    at += 4;
    const msgs = store.msgs.slice();
    for (0..m_count) |i| {
        std.mem.writeInt(i64, out[at..][0..8], msgs.items(.created_at)[i], .little);
        at += 8;
        const span = msgs.items(.text)[i];
        std.mem.writeInt(u32, out[at..][0..4], span.offset, .little);
        at += 4;
        std.mem.writeInt(u32, out[at..][0..4], span.len, .little);
        at += 4;
        std.mem.writeInt(u32, out[at..][0..4], @intFromEnum(msgs.items(.conv)[i]), .little);
        at += 4;
        out[at] = @intFromEnum(msgs.items(.kind)[i]);
        at += 1;
    }

    // Direction bits, LSB-first within each byte; unused high bits stay zero
    // so the encoding is canonical.
    const mine_bytes = out[at..][0 .. (m_count + 7) / 8];
    @memset(mine_bytes, 0);
    for (0..m_count) |i| {
        if (store.mine.isSet(i)) mine_bytes[i / 8] |= @as(u8, 1) << @intCast(i % 8);
    }
    at += (m_count + 7) / 8;

    // Payments + settlements (v2 sections).
    std.mem.writeInt(u32, out[at..][0..4], @intCast(p_count), .little);
    at += 4;
    const pays = store.payments.slice();
    for (0..p_count) |i| {
        std.mem.writeInt(u64, out[at..][0..8], pays.items(.payment_id)[i], .little);
        std.mem.writeInt(u64, out[at + 8 ..][0..8], pays.items(.amount_sat)[i], .little);
        std.mem.writeInt(u32, out[at + 16 ..][0..4], @intFromEnum(pays.items(.msg)[i]), .little);
        out[at + 20] = @intFromEnum(pays.items(.rail)[i]);
        out[at + 21] = @intFromEnum(pays.items(.status)[i]);
        out[at + 22] = pays.items(.confirmations)[i];
        at += pay_rec_len;
    }

    std.mem.writeInt(u32, out[at..][0..4], @intCast(r_count), .little);
    at += 4;
    const refs = store.settlements.slice();
    for (0..r_count) |i| {
        std.mem.writeInt(u32, out[at..][0..4], @intFromEnum(refs.items(.pay)[i]), .little);
        @memcpy(out[at + 4 ..][0..32], &refs.items(.ref)[i]);
        at += ref_rec_len;
    }
    assert(at == total);
    return out;
}

/// True when `span` names a real NUL-terminated string inside `bytes` (the
/// appendString invariant every restored span must satisfy). The empty span
/// is TextSpan.empty exactly.
fn spanOk(bytes: []const u8, span: TextSpan) bool {
    if (span.len == 0) return span.offset == 0;
    const end = @as(u64, span.offset) + span.len; // u64: no overflow on hostile input
    if (end + 1 > bytes.len) return false;
    return bytes[@intCast(end)] == 0;
}

/// Rebuild a store from `serializeStore` bytes. Strict: every span is
/// bounds-checked and NUL-terminated, every message's conversation exists,
/// every kind byte is in the built vocabulary, DIDs are unique, and the blob
/// length is exact. Any violation is `error.Malformed` and the partial store
/// is fully released — the caller never sees half a restore.
pub fn deserializeStore(gpa: Allocator, bytes: []const u8) DeserializeError!Store {
    var store: Store = .{};
    errdefer deinitStore(gpa, &store);

    if (bytes.len < 10 or !std.mem.eql(u8, bytes[0..4], &codec_magic)) return error.Malformed;
    const version = std.mem.readInt(u16, bytes[4..6], .little);
    if (version != 1 and version != 2) return error.Malformed;
    const s_len = std.mem.readInt(u32, bytes[6..10], .little);
    var at: usize = 10;
    if (bytes.len - at < s_len) return error.Malformed;
    try store.string_bytes.appendSlice(gpa, bytes[at .. at + s_len]);
    at += s_len;

    if (bytes.len - at < 4) return error.Malformed;
    const c_count = std.mem.readInt(u32, bytes[at..][0..4], .little);
    at += 4;
    if (@as(u64, c_count) * conv_rec_len > bytes.len - at) return error.Malformed;
    try store.convs.setCapacity(gpa, c_count);
    for (0..c_count) |i| {
        var conv: Conversation = undefined;
        conv.did = .{
            .offset = std.mem.readInt(u32, bytes[at..][0..4], .little),
            .len = std.mem.readInt(u32, bytes[at + 4 ..][0..4], .little),
        };
        conv.handle = .{
            .offset = std.mem.readInt(u32, bytes[at + 8 ..][0..4], .little),
            .len = std.mem.readInt(u32, bytes[at + 12 ..][0..4], .little),
        };
        conv.last_activity = std.mem.readInt(i64, bytes[at + 16 ..][0..8], .little);
        conv.unread = std.mem.readInt(u32, bytes[at + 24 ..][0..4], .little);
        at += conv_rec_len;

        // A conversation IS its counterparty DID: non-empty, clean for the
        // interning map (no interior NUL), and unique.
        if (conv.did.len == 0 or !spanOk(store.string_bytes.items, conv.did)) return error.Malformed;
        const did = sliceSpan(&store, conv.did);
        if (std.mem.indexOfScalar(u8, did, 0) != null) return error.Malformed;
        if (!spanOk(store.string_bytes.items, conv.handle)) return error.Malformed;
        store.convs.appendAssumeCapacity(conv);

        const gop = try store.conv_by_did.getOrPutContextAdapted(
            gpa,
            did,
            std.hash_map.StringIndexAdapter{ .bytes = &store.string_bytes },
            std.hash_map.StringIndexContext{ .bytes = &store.string_bytes },
        );
        if (gop.found_existing) return error.Malformed;
        gop.key_ptr.* = conv.did.offset;
        gop.value_ptr.* = @intCast(i);
    }

    if (bytes.len - at < 4) return error.Malformed;
    const m_count = std.mem.readInt(u32, bytes[at..][0..4], .little);
    at += 4;
    if (@as(u64, m_count) * msg_rec_len > bytes.len - at) return error.Malformed;
    try store.msgs.setCapacity(gpa, m_count);
    for (0..m_count) |_| {
        var msg: ChatMsg = undefined;
        msg.created_at = std.mem.readInt(i64, bytes[at..][0..8], .little);
        msg.text = .{
            .offset = std.mem.readInt(u32, bytes[at + 8 ..][0..4], .little),
            .len = std.mem.readInt(u32, bytes[at + 12 ..][0..4], .little),
        };
        const conv_raw = std.mem.readInt(u32, bytes[at + 16 ..][0..4], .little);
        msg.kind = parseKind(bytes[at + 20]) catch return error.Malformed;
        at += msg_rec_len;
        if (conv_raw >= c_count) return error.Malformed;
        msg.conv = @enumFromInt(conv_raw);
        if (!spanOk(store.string_bytes.items, msg.text)) return error.Malformed;
        store.msgs.appendAssumeCapacity(msg);
    }

    const mine_len = (@as(usize, m_count) + 7) / 8;
    if (bytes.len - at < mine_len) return error.Malformed;
    try store.mine.resize(gpa, m_count, false);
    for (0..m_count) |i| {
        const bit = (bytes[at + i / 8] >> @intCast(i % 8)) & 1;
        store.mine.setValue(i, bit == 1);
    }
    if (m_count % 8 != 0) {
        // Canonical encoding: the last byte's unused high bits must be zero.
        const used: u3 = @intCast(m_count % 8);
        if ((bytes[at + mine_len - 1] >> used) != 0) return error.Malformed;
    }
    at += mine_len;

    // Payments + settlements (v2 sections; a v1 blob simply has none).
    // Card ⇔ row is validated as a bijection: every row names a payment
    // card, no card is named twice, and — checked below for BOTH versions —
    // no payment card is left without its row (a v1 blob can therefore
    // never smuggle a payment kind in).
    var claimed: std.DynamicBitSetUnmanaged = .{};
    defer claimed.deinit(gpa);
    try claimed.resize(gpa, m_count, false);
    if (version >= 2) {
        if (bytes.len - at < 4) return error.Malformed;
        const p_count = std.mem.readInt(u32, bytes[at..][0..4], .little);
        at += 4;
        if (@as(u64, p_count) * pay_rec_len > bytes.len - at) return error.Malformed;
        try store.payments.setCapacity(gpa, p_count);
        for (0..p_count) |_| {
            var row: PaymentRow = undefined;
            row.payment_id = std.mem.readInt(u64, bytes[at..][0..8], .little);
            row.amount_sat = std.mem.readInt(u64, bytes[at + 8 ..][0..8], .little);
            const msg_raw = std.mem.readInt(u32, bytes[at + 16 ..][0..4], .little);
            row.rail = switch (bytes[at + 20]) {
                0 => .lightning,
                1 => .onchain,
                else => return error.Malformed,
            };
            row.status = switch (bytes[at + 21]) {
                0 => .requested,
                1 => .pending,
                2 => .broadcast,
                3 => .confirming,
                4 => .settled,
                5 => .failed,
                6 => .pending_setup,
                7 => .ready,
                8 => .cancelled,
                9 => .declined,
                10 => .expired,
                else => return error.Malformed,
            };
            row.confirmations = bytes[at + 22];
            at += pay_rec_len;
            if (row.payment_id == 0) return error.Malformed;
            if (row.amount_sat == 0 or row.amount_sat > max_amount_sat) return error.Malformed;
            if (msg_raw >= m_count) return error.Malformed;
            if (!isPaymentKind(store.msgs.items(.kind)[msg_raw])) return error.Malformed;
            if (claimed.isSet(msg_raw)) return error.Malformed;
            claimed.set(msg_raw);
            row.msg = @enumFromInt(msg_raw);
            // (conversation, payment_id) is the correlation key findPayment
            // trusts — it must be unique.
            const conv_of = store.msgs.items(.conv)[msg_raw];
            for (store.payments.items(.payment_id), store.payments.items(.msg)) |other_id, other_msg| {
                if (other_id == row.payment_id and
                    store.msgs.items(.conv)[@intFromEnum(other_msg)] == conv_of)
                    return error.Malformed;
            }
            store.payments.appendAssumeCapacity(row);
        }
    }
    for (0..m_count) |i| {
        if (isPaymentKind(store.msgs.items(.kind)[i]) and !claimed.isSet(i)) return error.Malformed;
    }

    if (version >= 2) {
        if (bytes.len - at < 4) return error.Malformed;
        const r_count = std.mem.readInt(u32, bytes[at..][0..4], .little);
        at += 4;
        if (@as(u64, r_count) * ref_rec_len > bytes.len - at) return error.Malformed;
        try store.settlements.setCapacity(gpa, r_count);
        for (0..r_count) |_| {
            const pay_raw = std.mem.readInt(u32, bytes[at..][0..4], .little);
            var ref: [32]u8 = undefined;
            @memcpy(&ref, bytes[at + 4 ..][0..32]);
            at += ref_rec_len;
            if (pay_raw >= store.payments.len) return error.Malformed;
            if (std.mem.allEqual(u8, &ref, 0)) return error.Malformed; // zero = absent = no row
            // At most one ref per payment.
            for (store.settlements.items(.pay)) |p| {
                if (@intFromEnum(p) == pay_raw) return error.Malformed;
            }
            store.settlements.appendAssumeCapacity(.{ .pay = @enumFromInt(pay_raw), .ref = ref });
        }
    }

    if (at != bytes.len) return error.Malformed; // exact tail — no trailing bytes
    return store;
}

// ---------------------------------------------------------------------------
// Tests (C6: leak-checked by std.testing.allocator)
// ---------------------------------------------------------------------------

test "unresolvedDids lists exactly the conversations still wearing no name" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var store: Store = .{};
    defer deinitStore(gpa, &store);

    _ = try openConversation(gpa, &store, "did:plc:named", "maya.zat4.com");
    _ = try openConversation(gpa, &store, "did:plc:nameless", ""); // inbound: DID only
    _ = try openConversation(gpa, &store, "did:plc:alsonameless", "");

    const todo = try unresolvedDids(arena, &store);
    try std.testing.expectEqual(@as(usize, 2), todo.len);
    try std.testing.expectEqualStrings("did:plc:nameless", todo[0]);
    try std.testing.expectEqualStrings("did:plc:alsonameless", todo[1]);

    // Once the shell hands a resolved handle back, the conversation drops off
    // the work list — this is what stops the sweep re-asking forever.
    _ = try openConversation(gpa, &store, "did:plc:nameless", "oko.zat4.com");
    const todo2 = try unresolvedDids(arena, &store);
    try std.testing.expectEqual(@as(usize, 1), todo2.len);
    try std.testing.expectEqualStrings("did:plc:alsonameless", todo2[0]);
}

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

test "store codec: full round-trip, and the restored store keeps working" {
    const gpa = std.testing.allocator;
    var store: Store = .{};
    defer deinitStore(gpa, &store);

    const a = try openConversation(gpa, &store, "did:plc:aaa", "maya.zat4.com");
    const b = try openConversation(gpa, &store, "did:plc:bbb", "");
    _ = try appendMessage(gpa, &store, a, .text, "hello", 100, true);
    _ = try appendMessage(gpa, &store, a, .text, "hey back", 110, false);
    _ = try appendMessage(gpa, &store, b, .system, "conversation started", 120, false);
    markRead(&store, b);

    const blob = try serializeStore(gpa, &store);
    defer gpa.free(blob);

    var restored = try deserializeStore(gpa, blob);
    defer deinitStore(gpa, &restored);

    try std.testing.expectEqual(store.convs.len, restored.convs.len);
    try std.testing.expectEqual(store.msgs.len, restored.msgs.len);
    try std.testing.expectEqualStrings("did:plc:aaa", conversationDid(&restored, a));
    try std.testing.expectEqualStrings(
        "maya.zat4.com",
        sliceSpan(&restored, restored.convs.items(.handle)[@intFromEnum(a)]),
    );
    // Unread survives: a still carries its counterparty message, b was read.
    try std.testing.expectEqual(@as(u32, 1), restored.convs.items(.unread)[@intFromEnum(a)]);
    try std.testing.expectEqual(@as(u32, 0), restored.convs.items(.unread)[@intFromEnum(b)]);
    // Direction bits and text survive, oldest-first through the same query.
    const thread = try threadSlice(gpa, &restored, a);
    defer gpa.free(thread);
    try std.testing.expectEqual(@as(usize, 2), thread.len);
    try std.testing.expect(isMine(&restored, thread[0]));
    try std.testing.expect(!isMine(&restored, thread[1]));
    try std.testing.expectEqualStrings(
        "hey back",
        sliceSpan(&restored, restored.msgs.items(.text)[@intFromEnum(thread[1])]),
    );
    // The interning map was REBUILT, not just the arrays: an existing DID
    // dedupes and a fresh append lands in the restored world.
    const a2 = try openConversation(gpa, &restored, "did:plc:aaa", "");
    try std.testing.expectEqual(a, a2);
    _ = try appendMessage(gpa, &restored, a2, .text, "post-restore", 200, true);
    try std.testing.expectEqual(@as(usize, 4), restored.msgs.len);
}

test "store codec: the empty store round-trips" {
    const gpa = std.testing.allocator;
    var store: Store = .{};
    defer deinitStore(gpa, &store);
    const blob = try serializeStore(gpa, &store);
    defer gpa.free(blob);
    var restored = try deserializeStore(gpa, blob);
    defer deinitStore(gpa, &restored);
    try std.testing.expectEqual(@as(usize, 0), restored.convs.len);
    try std.testing.expectEqual(@as(usize, 0), restored.msgs.len);
}

test "store codec: every class of damage is refused, never half-restored" {
    const gpa = std.testing.allocator;
    var store: Store = .{};
    defer deinitStore(gpa, &store);
    const a = try openConversation(gpa, &store, "did:plc:aaa", "maya");
    const b = try openConversation(gpa, &store, "did:plc:bbb", "");
    _ = try appendMessage(gpa, &store, a, .text, "one", 100, true);
    _ = try appendMessage(gpa, &store, b, .text, "two", 110, false);
    _ = try appendMessage(gpa, &store, a, .text, "three", 120, false);
    const good = try serializeStore(gpa, &store);
    defer gpa.free(good);
    const s_len = store.string_bytes.items.len;
    const convs_at = 10 + s_len + 4; // header + strings + conv count

    // The good blob restores (the baseline for every mutation below).
    {
        var ok = try deserializeStore(gpa, good);
        deinitStore(gpa, &ok);
    }
    const expectBad = struct {
        fn check(alloc: Allocator, blob: []const u8) !void {
            try std.testing.expectError(error.Malformed, deserializeStore(alloc, blob));
        }
    }.check;

    var bad = try gpa.dupe(u8, good);
    defer gpa.free(bad);

    bad[0] ^= 1; // magic
    try expectBad(gpa, bad);
    bad[0] ^= 1;

    std.mem.writeInt(u16, bad[4..6], codec_version + 1, .little); // version
    try expectBad(gpa, bad);
    std.mem.writeInt(u16, bad[4..6], codec_version, .little);

    // Truncation at every byte boundary.
    var cut: usize = 0;
    while (cut < good.len) : (cut += 1) try expectBad(gpa, good[0..cut]);

    // A trailing byte (the tail must be exact).
    const longer = try std.mem.concat(gpa, u8, &.{ good, &.{0} });
    defer gpa.free(longer);
    try expectBad(gpa, longer);

    // An out-of-bounds handle span on conversation 0.
    std.mem.writeInt(u32, bad[convs_at + 12 ..][0..4], 0xFFFF, .little);
    try expectBad(gpa, bad);
    @memcpy(bad, good);

    // A duplicate DID: conversation 1's did span redirected onto 0's.
    @memcpy(bad[convs_at + conv_rec_len ..][0..8], bad[convs_at..][0..8]);
    try expectBad(gpa, bad);
    @memcpy(bad, good);

    // A reserved kind byte on message 0.
    const msgs_at = convs_at + 2 * conv_rec_len + 4;
    bad[msgs_at + 20] = 7;
    try expectBad(gpa, bad);
    @memcpy(bad, good);

    // A message pointing at a conversation that does not exist.
    std.mem.writeInt(u32, bad[msgs_at + 16 ..][0..4], 99, .little);
    try expectBad(gpa, bad);
    @memcpy(bad, good);

    // A non-canonical direction byte (unused high bit set; 3 messages, so
    // the direction byte sits before the two empty v2 section counts).
    bad[good.len - 9] |= 0x80;
    try expectBad(gpa, bad);
    @memcpy(bad, good);

    // A payment-kind byte on a message with no payment row (the card ⇔ row
    // bijection refuses a rowless card).
    bad[msgs_at + 20] = 16;
    try expectBad(gpa, bad);
}

test "parseKind accepts the built vocabulary and rejects reserved bytes" {
    try std.testing.expectEqual(Kind.text, try parseKind(0));
    try std.testing.expectEqual(Kind.system, try parseKind(1));
    // Reserved chat extension range.
    try std.testing.expectError(error.UnknownKind, parseKind(7));
    // The payment CARD kinds are built (M5 A1)…
    try std.testing.expectEqual(Kind.payment_request, try parseKind(16));
    try std.testing.expectEqual(Kind.payment_sent, try parseKind(17));
    // …but the settlement EVENT bytes are wire-only, never stored kinds.
    try std.testing.expectError(error.UnknownKind, parseKind(kind_pay_settled_wire));
    try std.testing.expectError(error.UnknownKind, parseKind(kind_pay_failed_wire));
    // The S2 lifecycle bytes (offer/ready/cancel/decline) are wire-only too.
    try std.testing.expectError(error.UnknownKind, parseKind(kind_pay_offer_wire));
    try std.testing.expectError(error.UnknownKind, parseKind(kind_pay_ready_wire));
    try std.testing.expectError(error.UnknownKind, parseKind(kind_pay_cancel_wire));
    try std.testing.expectError(error.UnknownKind, parseKind(kind_pay_decline_wire));
    try std.testing.expectError(error.UnknownKind, parseKind(255));
    // payEventStatus maps the flip bytes and only those.
    try std.testing.expectEqual(PayStatus.settled, payEventStatus(kind_pay_settled_wire).?);
    try std.testing.expectEqual(PayStatus.ready, payEventStatus(kind_pay_ready_wire).?);
    try std.testing.expectEqual(PayStatus.cancelled, payEventStatus(kind_pay_cancel_wire).?);
    try std.testing.expectEqual(PayStatus.declined, payEventStatus(kind_pay_decline_wire).?);
    try std.testing.expect(payEventStatus(kind_pay_offer_wire) == null); // create, not flip
    try std.testing.expect(payEventStatus(0) == null);
}

test "S2 offer: create at pending_setup, ready advances, expiry only lapses pre-commit" {
    const gpa = std.testing.allocator;
    var store: Store = .{};
    defer deinitStore(gpa, &store);
    const a = try openConversation(gpa, &store, "did:plc:payee", "");

    // A walletless-recipient offer starts BELOW the kind default and needs
    // the direct create-path (advancePayment could never reach rank 0).
    const offer = try appendPayment(gpa, &store, a, .payment_sent, 0x501, .onchain, 7000, "coffee", 100, false);
    initPaymentStatus(&store, offer, .pending_setup);
    try std.testing.expectEqual(PayStatus.pending_setup, store.payments.items(.status)[@intFromEnum(offer)]);

    // Recipient sets up → ready (rank 0 → 1, a legal forward step).
    try std.testing.expect(try advancePayment(gpa, &store, offer, .ready, null));
    try std.testing.expectEqual(PayStatus.ready, store.payments.items(.status)[@intFromEnum(offer)]);

    // A second, in-flight card must be immune to the expiry sweep.
    const live = try appendPayment(gpa, &store, a, .payment_sent, 0x502, .onchain, 9000, "", 100, true);
    _ = try advancePayment(gpa, &store, live, .broadcast, null);

    // Well before the TTL: nothing lapses.
    try std.testing.expect(!sweepExpired(&store, 100, payment_offer_ttl_s));
    // Past the TTL: the ready offer lapses; the broadcast card does NOT
    // (money may be in motion behind it — the golden rule).
    try std.testing.expect(sweepExpired(&store, 100 + payment_offer_ttl_s, payment_offer_ttl_s));
    try std.testing.expectEqual(PayStatus.expired, store.payments.items(.status)[@intFromEnum(offer)]);
    try std.testing.expectEqual(PayStatus.broadcast, store.payments.items(.status)[@intFromEnum(live)]);
    // Idempotent: a second sweep changes nothing (expired is terminal).
    try std.testing.expect(!sweepExpired(&store, 100 + 2 * payment_offer_ttl_s, payment_offer_ttl_s));

    // Accessors resolve the card's conv and direction.
    try std.testing.expectEqual(a, paymentConv(&store, offer));
    try std.testing.expect(!paymentMine(&store, offer));
    try std.testing.expect(paymentMine(&store, live));
    try std.testing.expectEqual(@as(u32, 2), paymentCount(&store));

    // The trust gate: a card with network evidence is a withdrawal's floor —
    // the shell drops a remote cancel/decline on it (checked here as the
    // pure predicate the gate consults).
    try std.testing.expect(hasNetworkEvidence(.broadcast));
    try std.testing.expect(hasNetworkEvidence(.confirming));
    try std.testing.expect(hasNetworkEvidence(.settled));
    try std.testing.expect(!hasNetworkEvidence(.pending_setup));
    try std.testing.expect(!hasNetworkEvidence(.ready));
    try std.testing.expect(!hasNetworkEvidence(.pending));
}

test "appendPayment creates the card + row pair with kind-derived status" {
    const gpa = std.testing.allocator;
    var store: Store = .{};
    defer deinitStore(gpa, &store);

    const a = try openConversation(gpa, &store, "did:plc:aaa", "maya.zat4.com");
    const req = try appendPayment(gpa, &store, a, .payment_request, 0xCAFE, .lightning, 5000, "dinner", 100, false);
    const sent = try appendPayment(gpa, &store, a, .payment_sent, 0xBEEF, .onchain, 250_000, "", 200, true);

    try std.testing.expectEqual(@as(usize, 2), store.msgs.len);
    try std.testing.expectEqual(@as(usize, 2), store.payments.len);
    try std.testing.expectEqual(PayStatus.requested, store.payments.items(.status)[@intFromEnum(req)]);
    try std.testing.expectEqual(PayStatus.pending, store.payments.items(.status)[@intFromEnum(sent)]);
    // The card is a real message: note text, direction, unread accounting.
    const req_msg = store.payments.items(.msg)[@intFromEnum(req)];
    try std.testing.expectEqual(Kind.payment_request, store.msgs.items(.kind)[@intFromEnum(req_msg)]);
    try std.testing.expectEqualStrings("dinner", sliceSpan(&store, store.msgs.items(.text)[@intFromEnum(req_msg)]));
    try std.testing.expect(!isMine(&store, req_msg));
    try std.testing.expectEqual(@as(u32, 1), store.convs.items(.unread)[@intFromEnum(a)]);
    // Correlation: found in its conversation, invisible from another.
    try std.testing.expectEqual(req, findPayment(&store, a, 0xCAFE).?);
    const b = try openConversation(gpa, &store, "did:plc:bbb", "");
    try std.testing.expect(findPayment(&store, b, 0xCAFE) == null);
    try std.testing.expectEqual(req, paymentByMsg(&store, req_msg).?);
}

test "advancePayment is monotonic, terminal-absorbing, and first-wins on refs" {
    const gpa = std.testing.allocator;
    var store: Store = .{};
    defer deinitStore(gpa, &store);
    const a = try openConversation(gpa, &store, "did:plc:aaa", "");
    const pay = try appendPayment(gpa, &store, a, .payment_request, 1, .lightning, 100, "", 10, false);

    // Forward: requested → broadcast. Backward: broadcast → pending is a no-op.
    try std.testing.expect(try advancePayment(gpa, &store, pay, .broadcast, null));
    try std.testing.expect(!(try advancePayment(gpa, &store, pay, .pending, null)));
    try std.testing.expectEqual(PayStatus.broadcast, store.payments.items(.status)[@intFromEnum(pay)]);

    // A ref attaches once; a later wire ref cannot rewrite it.
    const hash: [32]u8 = @splat(0x11);
    const other: [32]u8 = @splat(0x22);
    try std.testing.expect(try advancePayment(gpa, &store, pay, .broadcast, hash));
    try std.testing.expect(!(try advancePayment(gpa, &store, pay, .broadcast, other)));
    try std.testing.expectEqualSlices(u8, &hash, &settlementRef(&store, pay).?);
    // The local upsert primitive DOES replace (re-broadcast).
    try setSettlementRef(gpa, &store, pay, other);
    try std.testing.expectEqualSlices(u8, &other, &settlementRef(&store, pay).?);
    try std.testing.expectEqual(@as(usize, 1), store.settlements.len);

    // Terminal absorbs everything after.
    try std.testing.expect(try advancePayment(gpa, &store, pay, .settled, null));
    try std.testing.expect(!(try advancePayment(gpa, &store, pay, .failed, null)));
    try std.testing.expect(!(try advancePayment(gpa, &store, pay, .broadcast, hash)));
    try std.testing.expectEqual(PayStatus.settled, store.payments.items(.status)[@intFromEnum(pay)]);
}

test "setConfirmations walks depth forward and settles at six" {
    const gpa = std.testing.allocator;
    var store: Store = .{};
    defer deinitStore(gpa, &store);
    const a = try openConversation(gpa, &store, "did:plc:aaa", "");
    const pay = try appendPayment(gpa, &store, a, .payment_sent, 2, .onchain, 9000, "", 10, true);

    try std.testing.expect(setConfirmations(&store, pay, 1));
    try std.testing.expectEqual(PayStatus.confirming, store.payments.items(.status)[@intFromEnum(pay)]);
    try std.testing.expect(setConfirmations(&store, pay, 3));
    try std.testing.expect(!setConfirmations(&store, pay, 3)); // no change twice
    try std.testing.expect(!setConfirmations(&store, pay, 2)); // depth never regresses
    try std.testing.expectEqual(@as(u8, 3), store.payments.items(.confirmations)[@intFromEnum(pay)]);
    try std.testing.expect(setConfirmations(&store, pay, settle_depth));
    try std.testing.expectEqual(PayStatus.settled, store.payments.items(.status)[@intFromEnum(pay)]);
    try std.testing.expect(!setConfirmations(&store, pay, 7)); // terminal absorbs
}

test "payment frame round-trips and rejects malformed wire bytes" {
    var buf: [128]u8 = undefined;
    const hash: [32]u8 = @splat(0xAB);
    const frame = PaymentFrame{
        .payment_id = 0x1122334455667788,
        .amount_sat = 21_000,
        .note = "split the fare",
        .ref = hash,
        .rail = .onchain,
    };
    const wire = buildPaymentFrame(&buf, frame);
    try std.testing.expectEqual(payment_frame_min + frame.note.len, wire.len);
    const back = try parsePaymentFrame(wire);
    try std.testing.expectEqual(frame.payment_id, back.payment_id);
    try std.testing.expectEqual(frame.amount_sat, back.amount_sat);
    try std.testing.expectEqual(Rail.onchain, back.rail);
    try std.testing.expectEqualSlices(u8, &hash, &back.ref);
    try std.testing.expectEqualStrings("split the fare", back.note);

    // An empty note and an absent ref are legal.
    const bare = buildPaymentFrame(&buf, .{
        .payment_id = 7,
        .amount_sat = 1,
        .note = "",
        .ref = zero_ref,
        .rail = .lightning,
    });
    const bare_back = try parsePaymentFrame(bare);
    try std.testing.expectEqual(@as(usize, 0), bare_back.note.len);
    try std.testing.expect(std.mem.allEqual(u8, &bare_back.ref, 0));

    // Malformed: short, zero id, zero amount, over-max amount, bad rail.
    try std.testing.expectError(error.Malformed, parsePaymentFrame(wire[0 .. payment_frame_min - 1]));
    var bad: [payment_frame_min]u8 = undefined;
    @memcpy(&bad, wire[0..payment_frame_min]);
    std.mem.writeInt(u64, bad[0..8], 0, .little);
    try std.testing.expectError(error.Malformed, parsePaymentFrame(&bad));
    @memcpy(&bad, wire[0..payment_frame_min]);
    std.mem.writeInt(u64, bad[8..16], 0, .little);
    try std.testing.expectError(error.Malformed, parsePaymentFrame(&bad));
    std.mem.writeInt(u64, bad[8..16], max_amount_sat + 1, .little);
    try std.testing.expectError(error.Malformed, parsePaymentFrame(&bad));
    @memcpy(&bad, wire[0..payment_frame_min]);
    bad[48] = 2;
    try std.testing.expectError(error.Malformed, parsePaymentFrame(&bad));
}

test "store codec v2: payments and settlements round-trip" {
    const gpa = std.testing.allocator;
    var store: Store = .{};
    defer deinitStore(gpa, &store);

    const a = try openConversation(gpa, &store, "did:plc:aaa", "maya.zat4.com");
    _ = try appendMessage(gpa, &store, a, .text, "hello", 100, true);
    const req = try appendPayment(gpa, &store, a, .payment_request, 0xCAFE, .lightning, 5000, "dinner", 200, false);
    const sent = try appendPayment(gpa, &store, a, .payment_sent, 0xBEEF, .onchain, 250_000, "rent", 300, true);
    _ = try advancePayment(gpa, &store, req, .settled, @as([32]u8, @splat(0x33)));
    try std.testing.expect(setConfirmations(&store, sent, 2));

    const blob = try serializeStore(gpa, &store);
    defer gpa.free(blob);
    var restored = try deserializeStore(gpa, blob);
    defer deinitStore(gpa, &restored);

    try std.testing.expectEqual(@as(usize, 2), restored.payments.len);
    try std.testing.expectEqual(@as(usize, 1), restored.settlements.len);
    const r_req = findPayment(&restored, a, 0xCAFE).?;
    const r_sent = findPayment(&restored, a, 0xBEEF).?;
    try std.testing.expectEqual(PayStatus.settled, restored.payments.items(.status)[@intFromEnum(r_req)]);
    try std.testing.expectEqual(@as(u64, 5000), restored.payments.items(.amount_sat)[@intFromEnum(r_req)]);
    try std.testing.expectEqual(Rail.onchain, restored.payments.items(.rail)[@intFromEnum(r_sent)]);
    try std.testing.expectEqual(PayStatus.confirming, restored.payments.items(.status)[@intFromEnum(r_sent)]);
    try std.testing.expectEqual(@as(u8, 2), restored.payments.items(.confirmations)[@intFromEnum(r_sent)]);
    try std.testing.expectEqualSlices(u8, &@as([32]u8, @splat(0x33)), &settlementRef(&restored, r_req).?);
    try std.testing.expect(settlementRef(&restored, r_sent) == null);
    // The note rides the card's message text.
    const req_msg = restored.payments.items(.msg)[@intFromEnum(r_req)];
    try std.testing.expectEqualStrings("dinner", sliceSpan(&restored, restored.msgs.items(.text)[@intFromEnum(req_msg)]));
}

test "store codec: a version-1 blob (pre-payments) still restores" {
    const gpa = std.testing.allocator;
    var store: Store = .{};
    defer deinitStore(gpa, &store);
    const a = try openConversation(gpa, &store, "did:plc:aaa", "maya.zat4.com");
    _ = try appendMessage(gpa, &store, a, .text, "old world", 100, true);

    // A v2 blob with no payments is exactly a v1 blob plus two zero counts:
    // strip them and stamp version 1 — byte-identical to what M2 wrote.
    const v2 = try serializeStore(gpa, &store);
    defer gpa.free(v2);
    const v1 = try gpa.dupe(u8, v2[0 .. v2.len - 8]);
    defer gpa.free(v1);
    std.mem.writeInt(u16, v1[4..6], 1, .little);

    var restored = try deserializeStore(gpa, v1);
    defer deinitStore(gpa, &restored);
    try std.testing.expectEqual(@as(usize, 1), restored.msgs.len);
    try std.testing.expectEqual(@as(usize, 0), restored.payments.len);
    try std.testing.expectEqualStrings("did:plc:aaa", conversationDid(&restored, a));

    // A v1 blob cannot smuggle a payment kind (it has no rows to pair).
    const bad = try gpa.dupe(u8, v1);
    defer gpa.free(bad);
    const msgs_at = 10 + store.string_bytes.items.len + 4 + conv_rec_len + 4;
    bad[msgs_at + 20] = 16;
    try std.testing.expectError(error.Malformed, deserializeStore(gpa, bad));
}

test "store codec v2: every class of payment-section damage is refused" {
    const gpa = std.testing.allocator;
    var store: Store = .{};
    defer deinitStore(gpa, &store);
    const a = try openConversation(gpa, &store, "did:plc:aaa", "");
    _ = try appendMessage(gpa, &store, a, .text, "text", 100, true);
    const pay = try appendPayment(gpa, &store, a, .payment_request, 0xCAFE, .lightning, 5000, "n", 200, false);
    try setSettlementRef(gpa, &store, pay, @splat(0x44));

    const good = try serializeStore(gpa, &store);
    defer gpa.free(good);
    {
        var ok = try deserializeStore(gpa, good);
        deinitStore(gpa, &ok);
    }
    var bad = try gpa.dupe(u8, good);
    defer gpa.free(bad);
    const expectBad = struct {
        fn check(alloc: Allocator, blob: []const u8) !void {
            try std.testing.expectError(error.Malformed, deserializeStore(alloc, blob));
        }
    }.check;
    // Layout: refs section = last 4 + 36 bytes; payments = the 4 + 23
    // bytes before it.
    const ref_at = good.len - ref_rec_len;
    const pay_at = good.len - ref_rec_len - 4 - pay_rec_len;

    // Row → a non-payment message (message 0 is text).
    std.mem.writeInt(u32, bad[pay_at + 16 ..][0..4], 0, .little);
    try expectBad(gpa, bad);
    // Row → out-of-range message.
    std.mem.writeInt(u32, bad[pay_at + 16 ..][0..4], 99, .little);
    try expectBad(gpa, bad);
    @memcpy(bad, good);
    // Zero payment id / zero amount / bad rail / bad status byte.
    std.mem.writeInt(u64, bad[pay_at..][0..8], 0, .little);
    try expectBad(gpa, bad);
    @memcpy(bad, good);
    std.mem.writeInt(u64, bad[pay_at + 8 ..][0..8], 0, .little);
    try expectBad(gpa, bad);
    @memcpy(bad, good);
    bad[pay_at + 20] = 2;
    try expectBad(gpa, bad);
    @memcpy(bad, good);
    bad[pay_at + 21] = 11; // first value past the PayStatus set (0..10)
    try expectBad(gpa, bad);
    @memcpy(bad, good);
    // Ref → out-of-range payment row; all-zero ref.
    std.mem.writeInt(u32, bad[ref_at..][0..4], 9, .little);
    try expectBad(gpa, bad);
    @memcpy(bad, good);
    @memset(bad[ref_at + 4 ..][0..32], 0);
    try expectBad(gpa, bad);
    @memcpy(bad, good);
    // Truncation at every byte boundary still refuses cleanly.
    var cut: usize = 0;
    while (cut < good.len) : (cut += 1) try expectBad(gpa, good[0..cut]);
}

test "watchList: live on-chain cards only, with the right address owner" {
    const gpa = std.testing.allocator;
    var store: Store = .{};
    defer deinitStore(gpa, &store);
    const a = try openConversation(gpa, &store, "did:plc:aaa", "");

    // MY request (money to MY address), THEIR request (to THEIRS), MY sent
    // (to THEIRS), a lightning card (not watched), a settled one (done).
    _ = try appendPayment(gpa, &store, a, .payment_request, 1, .onchain, 100, "", 10, true);
    _ = try appendPayment(gpa, &store, a, .payment_request, 2, .onchain, 200, "", 20, false);
    _ = try appendPayment(gpa, &store, a, .payment_sent, 3, .onchain, 300, "", 30, true);
    _ = try appendPayment(gpa, &store, a, .payment_request, 4, .lightning, 400, "", 40, false);
    const done = try appendPayment(gpa, &store, a, .payment_sent, 5, .onchain, 500, "", 50, true);
    _ = try advancePayment(gpa, &store, done, .settled, null);

    const list = try watchList(gpa, &store);
    defer gpa.free(list);
    try std.testing.expectEqual(@as(usize, 3), list.len);
    try std.testing.expectEqual(@as(u64, 1), list[0].payment_id);
    try std.testing.expect(list[0].mine_address); // my request → my address
    try std.testing.expectEqual(@as(u64, 2), list[1].payment_id);
    try std.testing.expect(!list[1].mine_address); // their request → theirs
    try std.testing.expectEqual(@as(u64, 3), list[2].payment_id);
    try std.testing.expect(!list[2].mine_address); // my send → theirs
}

test "store codec v2: duplicate rows and duplicate correlation keys are refused" {
    const gpa = std.testing.allocator;
    var store: Store = .{};
    defer deinitStore(gpa, &store);
    const a = try openConversation(gpa, &store, "did:plc:aaa", "");
    _ = try appendPayment(gpa, &store, a, .payment_request, 0x0AAA, .lightning, 100, "", 100, false);
    _ = try appendPayment(gpa, &store, a, .payment_sent, 0x0BBB, .lightning, 200, "", 200, true);

    const good = try serializeStore(gpa, &store);
    defer gpa.free(good);
    var bad = try gpa.dupe(u8, good);
    defer gpa.free(bad);
    // Layout tail: [p_count=2][row0][row1][r_count=0]; rows are 23 bytes.
    const row1_at = good.len - 4 - pay_rec_len;
    const row0_at = row1_at - pay_rec_len;

    // Two rows claiming the same card (row1's msg → row0's msg).
    @memcpy(bad[row1_at + 16 ..][0..4], bad[row0_at + 16 ..][0..4]);
    try std.testing.expectError(error.Malformed, deserializeStore(gpa, bad));
    @memcpy(bad, good);
    // Two cards sharing (conversation, payment_id) — the correlation key.
    @memcpy(bad[row1_at..][0..8], bad[row0_at..][0..8]);
    try std.testing.expectError(error.Malformed, deserializeStore(gpa, bad));
}

test "welcome retry: the ladder climbs, caps, and gives up" {
    const t = std.testing;
    // Never sent → due immediately, whatever the clock says.
    try t.expect(welcomeRetryDue(0, 0, 0));
    try t.expectEqual(@as(i64, 0), welcomeRetryDelay(0));

    // 5s, 10, 20, 40 … doubling.
    try t.expectEqual(@as(i64, 5), welcomeRetryDelay(1));
    try t.expectEqual(@as(i64, 10), welcomeRetryDelay(2));
    try t.expectEqual(@as(i64, 40), welcomeRetryDelay(4));
    // …then flat at the 10-minute cap, and it never overflows the shift.
    try t.expectEqual(@as(i64, 600), welcomeRetryDelay(8));
    try t.expectEqual(@as(i64, 600), welcomeRetryDelay(welcome_retry_max));
    try t.expectEqual(@as(i64, 600), welcomeRetryDelay(255));

    // One attempt at t=1000: not due at t=1004, due at t=1005.
    try t.expect(!welcomeRetryDue(1, 1000, 1004));
    try t.expect(welcomeRetryDue(1, 1000, 1005));

    // The ceiling is a real stop — the thread says "undelivered" instead of
    // retrying forever behind the user's back.
    try t.expect(!welcomeRetryDue(welcome_retry_max, 0, std.math.maxInt(i32)));

    // The ack byte stays wire-only: it must never parse as a stored kind.
    try t.expectError(error.UnknownKind, parseKind(kind_group_ack_wire));
}
