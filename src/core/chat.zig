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
/// Bytes 24..31 are RESERVED for the call signaling wire vocabulary, which the
/// call module owns (see `core/call.zig`'s `kind_call_*_wire`): they ride this
/// same E2EE channel but are consumed at the call layer and never stored, so
/// `parseKind` keeps rejecting them.
/// Unbuilt bytes stay rejected by `parseKind` (E3).
pub const Kind = enum(u8) {
    text = 0,
    system = 1,
    /// A payment card asking the counterparty for an amount (starts
    /// `requested`; its ChatMsg text is the optional note).
    payment_request = 16,
    /// A payment card announcing an initiated payment (starts `broadcast`).
    payment_sent = 17,
    /// ONE MOVE of an in-thread game. Stored like a payment card rather than
    /// consumed at the session layer, because the thread IS the game: the board
    /// is derived by replaying these in order (`chat_games.replaySent`), exactly
    /// as the payment card's state is derived from its row. The move byte itself
    /// lives in `ChatMsg.game`; the text span is empty.
    game_move = 12,
};

/// True for the kinds that carry a game move (there is one today; the shape
/// generalizes when connect-four lands).
pub fn isGameKind(kind: Kind) bool {
    return kind == .game_move;
}

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

/// THE ROSTER's WIRE kind byte (reserved 2..15 range) — CHAT_MULTIDEVICE slice 3.
///
/// Sent only between YOUR OWN devices, over the pairwise session they share, and
/// it carries exactly one thing: the DIDs of the people you talk to. No messages,
/// no history, no names — the list, and nothing else.
///
/// Why it has to exist. In the pairwise model your desktop CANNOT create a session
/// between your phone and your friend's laptop: a session is between two
/// key-holding endpoints, and your desktop does not hold your phone's keys. That is
/// not a defect, it is what "nothing is copied" MEANS. So a newly-approved phone can
/// only join your conversations by opening them ITSELF — and to do that it needs
/// the one fact it cannot discover alone: who they are. This is that fact.
///
/// Without it the phone sits empty until somebody happens to message you, which is
/// not what we told the user ("your conversation list appears — the people, not the
/// history").
///
/// Wire-only, like the typing ping and the ack: consumed at the session layer,
/// never stored, so `parseKind` keeps rejecting it. A roster that reached a history
/// blob is damage, not data.
pub const kind_roster_wire: u8 = 4;

/// HISTORY TRANSFER (CHAT_MULTIDEVICE slice 5), both halves. Also wire-only, also
/// only ever between YOUR OWN devices.
///
/// `req`: a newly-added device asking its older sibling for the backlog.
/// `chunk`: [kind][u16 seq][u16 total][bytes] — the serialized store, cut up,
/// because a history is far bigger than one bucket and a bucket is a fixed size on
/// purpose (a variable one would leak the length of what you said).
///
/// DELIBERATELY OPT-IN AND SEPARATE from adding a device. Bringing your messages
/// across is a choice with a cost (they leave the one device that held them), and
/// bundling it invisibly into "add this phone" would be making that choice FOR
/// somebody. Adding a device gets you the people; this gets you the past, and only
/// if you ask.
pub const kind_history_req_wire: u8 = 5;
pub const kind_history_chunk_wire: u8 = 6;

/// DELETE FOR EVERYONE (CHAT_FEATURES slice 3). [kind][i64 created_at] — the
/// timestamp of the message the sender wants gone. We carry no message ids on the
/// wire (there are none in the store), and the stamp is enough: it is scoped to the
/// session it arrives on, so it can only ever name a message in THAT conversation,
/// from THAT person.
///
/// AND IT IS A REQUEST, NOT A DELETION. We cannot reach into somebody else's phone.
/// Their client honours it because it chooses to; a modified client simply would
/// not. Every messenger works this way and most of them let people believe
/// otherwise — the UI here does not, because that is the kind of lie that gets
/// somebody hurt.
pub const kind_unsend_wire: u8 = 7;

/// EDIT (CHAT_FEATURES). [kind][i64 created_at][the new text] — the same shape as
/// the unsend, and the same honesty: their client applies it because it chooses to.
/// The message keeps its timestamp (it is the same message, said better) and the
/// bubble wears an "Edited" mark, because words that changed after you read them and
/// said nothing about it is how somebody rewrites the past quietly.
pub const kind_edit_wire: u8 = 8;

/// REPLY (CHAT_FEATURES). [kind][i64 target_at][u8 target_was_mine][text] — the
/// message being answered, named the same way an unsend names one: by its timestamp
/// and who sent it. `target_was_mine` is from the SENDER's point of view, so the
/// receiver flips it (their "mine" is our "theirs").
///
/// A reply that arrives as a plain message is not a reply — it is a message that
/// happened to come after another one, and the whole point of the feature is to say
/// WHICH one, in a thread where four things are being discussed at once.
pub const kind_reply_wire: u8 = 9;

/// REACT (CHAT_FEATURES). [kind][i64 target_at][u8 target_mine][emoji utf-8]. Same
/// naming as an unsend; toggling is implied — the same emoji from the same person
/// twice takes it back, which is what everybody expects and nobody writes down.
pub const kind_react_wire: u8 = 10;

/// TEXT SENT WITH AN EFFECT. [kind][u8 effect][utf-8 text] — an ordinary text
/// message that also names the screen effect it was sent with, so the recipient
/// plays the one the SENDER chose.
///
/// This kind exists because a manually-picked effect cannot be re-derived. The
/// automatic phrase effects need no wire field at all: both ends run the same
/// pure `chat_effects.detectAuto` over the same text and reach the same answer.
/// But "hi" sent with lasers is indistinguishable from "hi" — the intent lives
/// only in the sender's tap, so it has to travel.
///
/// A message with NO effect is still encoded as a plain `[0][text]`, byte for
/// byte what it was before this kind existed. Only an effect-carrying message
/// takes this path, so ordinary delivery is untouched.
///
/// The id rides INSIDE the E2EE payload, so it is exactly as private as the
/// words it decorates — the relay sees one more opaque blob of the same shape.
/// ⚠️ MOVED 11 → 13, 2026-08-26, because 11 WAS ALREADY TAKEN by
/// `kind_read_wire` and the receive path dispatches both off the same byte in
/// the same if-chain — with the read receipt checked first.
///
/// The effect was total: every message sent with an effect was LOST. Short ones
/// hit the read receipt's `if (data.len < 9) return null` and were dropped
/// silently; longer ones were decoded AS a read receipt, so the words vanished
/// and eight bytes of (effect, bubble, text) were stamped in as an i64 read
/// watermark. The feature looked fine to the sender, whose own echo is local.
///
/// Moving THIS one rather than the receipt is the lesser break: effects have
/// never once arrived, so new↔new starts working and new↔old is no worse than
/// the nothing it already was, while read receipts — which won the collision and
/// therefore do work — keep their byte and keep working.
pub const kind_text_fx_wire: u8 = 13;

/// A GROUP MESSAGE, riding a PAIRWISE session.
///
/// `[14][group_id: 16][inner kind][inner payload…]` — the inner bytes are exactly
/// what the same message would have been in a direct chat, so every kind that
/// works in a DM works in a group without a second encoding of itself.
///
/// It has to say which group because of what a group IS here: N−1 of the ordinary
/// two-member sessions, fanned out. A message physically arrives over the pairwise
/// channel with ONE person, and without this byte the receiver would file it as a
/// DM from them — the group would look like a series of private conversations
/// that happen to say the same thing.
///
/// The id is opaque: 16 bytes the creator minted (the shell owns randomness, B3).
/// It is not secret and not a capability — knowing it does not admit you, because
/// nobody encrypts to a non-member. What keeps a stranger out is that no member's
/// client ever fans out to them.
pub const kind_group_msg_wire: u8 = 14;

/// THE ROSTER OF A GROUP: `[15][group_id: 16][title len u8][title][count u8][(did
/// len u8, did)…]`.
///
/// Sent to every member over their pairwise session when a group is created and
/// whenever its membership or title changes. This is the whole of "who is in this
/// group" — there is no cryptographic membership in the pairwise model, so
/// agreement is an application fact, and the honest thing is to say so rather than
/// to imply the maths is enforcing it.
///
/// THE TRUST RULE, and it is the same one the device directory uses: a roster is
/// believed only from somebody ALREADY in the group. The first one is the
/// invitation, and it can come from anybody — exactly like a first message from a
/// stranger, and it belongs behind the same guardrail rather than a new one.
pub const kind_group_meta_wire: u8 = 15;

/// Length of a group id, in bytes. 16 is the same width as a UUID and far past
/// what a birthday collision needs at any believable number of groups.
pub const group_id_len = 16;

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
/// EVERY BYTE THAT CAN APPEAR FIRST IN A DECRYPTED PAYLOAD, in one place, with a
/// comptime proof that no two of them are the same.
///
/// This exists because two of them WERE the same. `kind_text_fx_wire` and
/// `kind_read_wire` both claimed 11, sat in the same dispatch chain, and the
/// receipt won — so the effects feature never delivered a single message and
/// nothing anywhere said so. The constants were declared 1000 lines apart, which
/// is exactly how far apart two things have to be before nobody notices they
/// collide.
///
/// A new wire kind goes in this list. If it duplicates one, the build stops.
const wire_kinds = [_]u8{
    @intFromEnum(Kind.text),
    @intFromEnum(Kind.system),
    kind_typing_wire,
    kind_group_ack_wire,
    kind_roster_wire,
    kind_history_req_wire,
    kind_history_chunk_wire,
    kind_unsend_wire,
    kind_edit_wire,
    kind_reply_wire,
    kind_react_wire,
    @intFromEnum(Kind.game_move),
    kind_text_fx_wire,
    kind_group_msg_wire,
    kind_group_meta_wire,
    kind_read_wire,
    @intFromEnum(Kind.payment_request),
    @intFromEnum(Kind.payment_sent),
    kind_pay_settled_wire,
    kind_pay_failed_wire,
    kind_pay_offer_wire,
    kind_pay_ready_wire,
    kind_pay_cancel_wire,
    kind_pay_decline_wire,
};

comptime {
    for (wire_kinds, 0..) |a, i| {
        for (wire_kinds[i + 1 ..]) |b| {
            if (a == b) @compileError(
                "two wire kinds share a byte — the receive path dispatches on it, " ++
                    "so one of them would silently swallow the other (see kind_text_fx_wire)",
            );
        }
    }
}

pub fn parseKind(byte: u8) KindError!Kind {
    return switch (byte) {
        0 => .text,
        1 => .system,
        12 => .game_move,
        16 => .payment_request,
        17 => .payment_sent,
        else => error.UnknownKind,
    };
}

/// One message. Direction (mine vs. counterparty's) is a single bit stored
/// out of band in `Store.mine` (A6), parallel to `msgs`.
/// No message is being answered.
pub const no_reply: u32 = std.math.maxInt(u32);

/// One reaction: WHO (only "me" vs "them" — a 1:1 conversation has nobody else in
/// it), on WHICH message, with WHAT. The emoji is stored inline as UTF-8 bytes:
/// they are 4 bytes at most and a span into the string arena would cost more than
/// the thing it points at.
pub const Reaction = struct {
    msg: u32,
    /// UTF-8, NUL-padded. One codepoint — a reaction is a reaction, not a message.
    emoji: [8]u8,
    mine: bool,

    comptime {
        // Budget 16: 4 (u32) + 8 (bytes) + 1 (bool) = 13, padded to 16 by the u32's
        // alignment. Held in quantity, so it is guarded. (A7)
        assert(@sizeOf(Reaction) == 16);
    }
};

pub const ChatMsg = struct {
    /// Unix seconds — the codebase-wide unit; relative ages and ordering
    /// are integer work.
    created_at: i64,
    text: TextSpan,
    conv: ConvIndex,
    kind: Kind,
    /// CHAT_FEATURES: the message this one ANSWERS (a store index), or `no_reply`.
    reply_to: u32 = no_reply,
    /// The screen effect this message was SENT WITH (a `chat_effects.ScreenEffect`
    /// ordinal; 0 = none). Only a manually-picked effect is carried — the phrase
    /// -triggered ones are re-derived from the text on both ends, so storing them
    /// would be storing a duplicate of something already known.
    effect: u8 = 0,
    /// For a `.game_move`, the encoded `chat_games.Move` byte. Meaningless (and
    /// zero) for every other kind — the KIND is what says whether to read it.
    game: u8 = 0,
    /// The BUBBLE effect this message arrived with (a `chat_effects.BubbleEffect`
    /// ordinal; 0 = none). TRANSIENT: set from the wire on arrival, played once by
    /// the spawn animation, and deliberately NOT serialized — a bubble effect is a
    /// moment, not a property, so re-opening history must not re-slam every bubble.
    bubble: u8 = 0,

    comptime {
        // A7.1 — budget raised 24 → 32 for `reply_to` (u32), which is what makes a
        // reply a reply: without it the answer and the thing it answers are two
        // unrelated messages that merely arrived in order. In the SoA store each
        // field lives in its OWN array, so the real cost is 4 bytes per message and
        // the 8-byte tail padding this guard reports never materializes — the guard
        // pins the honest @sizeOf of the declared struct, which is what forces this
        // decision to be made on purpose.
        //
        // `effect`, `game` and `bubble` (u8 each) were then added for FREE: they
        // land in that existing tail padding, so the budget is unchanged at 32 and
        // the SoA cost is one byte per message each. Had any not fit, it would have
        // been a real decision rather than a free one.
        assert(@sizeOf(ChatMsg) == 32);
    }
};

/// Index into `Store.members`.
pub const MemberIndex = enum(u32) { _ };

/// ONE PARTICIPANT of a conversation.
///
/// A direct chat has exactly one member — the counterparty — and a group has
/// several. There is deliberately no separate one-person path (A2): the direct
/// chat is the degenerate case of the same array, walked by the same code, so a
/// group feature cannot work "except in DMs" and a DM fix cannot miss groups.
///
/// `did`/`handle` here are the SAME SPANS the conversation's dedup key holds for
/// a direct chat — the same offset into `string_bytes`, not a second copy of the
/// bytes. One string, two references to it.
pub const Member = struct {
    /// Identity. Crosses module boundaries as the DID (A5).
    did: TextSpan,
    /// Display handle; empty until resolved, exactly as on a conversation.
    handle: TextSpan,
    /// LEFT the conversation. Kept rather than removed, and this is load-bearing:
    /// a message attributes to a member by its OFFSET in the conversation's span,
    /// so removing a row would renumber the ones above it and silently re-attribute
    /// history to the wrong person. The same reason `deleted` is a tombstone.
    left: bool = false,

    comptime {
        // Budget: two spans (16) + the flag, padded. Members are held in the
        // dozens per account, but they are walked per conversation row and per
        // message attribution, so the guard stays (A7).
        assert(@sizeOf(Member) == 20);
    }
};

/// WHAT KIND OF CONVERSATION. A group with one member left is still a group, and
/// a direct chat is not a group of one — which is why this is a stated kind and
/// not "member_count > 1" inferred at the call site. Values are FROZEN: the
/// history codec persists this byte.
pub const ConvKind = enum(u8) { direct = 0, group = 1 };

/// Sentinel `sender` for a message this account wrote. The direction bitset
/// already says so; this keeps the sender column total rather than meaningless
/// on half its rows.
pub const sender_me: u16 = std.math.maxInt(u16);

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
    /// CHAT_FEATURES: what the person has DONE to this conversation.
    /// `pinned` floats it to the top; `muted` silences it (a mute is a promise about
    /// notifications, so it must exist BEFORE notifications do, or the first thing
    /// they ever do is wake somebody who asked not to be woken); `hidden` is the
    /// tombstone left by Delete — the row survives because indexes above it would
    /// otherwise renumber, and half this codebase holds conversation indexes.
    pinned: bool = false,
    muted: bool = false,
    hidden: bool = false,
    /// CHAT_FEATURES: the newest message of OURS they have told us they read (unix
    /// seconds; 0 = they have never said, which is also what somebody with receipts
    /// turned OFF looks like — and those two must be indistinguishable, or the
    /// setting would leak the fact that you turned it off).
    read_up_to: i64 = 0,
    /// GROUPS. The participants, as a span into `Store.members`. Every
    /// conversation has one — a direct chat's is length 1 — so nothing downstream
    /// has to ask which sort it is before it can list who is in it.
    member_first: u32 = 0,
    member_count: u16 = 0,
    /// Direct or group. Stated, never inferred from `member_count`: a group
    /// everyone but you has left still is one.
    kind: ConvKind = .direct,
    /// The group's name. Empty for a direct chat, which is named by its
    /// counterparty and has nothing to store here.
    title: TextSpan = TextSpan.empty,
    /// THE GROUP'S IDENTITY ON THE WIRE. Zero for a direct chat, which is
    /// addressed by its counterparty and needs none.
    ///
    /// Held as bytes rather than a span into `string_bytes`, because that blob's
    /// invariant is NUL-terminated strings with no interior NUL and a random 16
    /// bytes respects neither. A span would have meant either a second blob or a
    /// hex encoding, and both are more moving parts than sixteen bytes.
    group_id: [group_id_len]u8 = [_]u8{0} ** group_id_len,

    comptime {
        // A7.1 — budget raised 40 → 56 for GROUPS. `member_first`+`member_count`
        // +`kind` (7 bytes) land in the tail padding and cost nothing; `title` is a
        // real span and does not. Paid deliberately, and the alternative was worse:
        // a parallel side-table keyed by conversation, which is the same bytes plus
        // a lookup plus a way for the two to disagree. Conversations are held in the
        // dozens, and in the SoA store each field is its own array, so a column
        // nobody reads is a column nobody pays to touch.
        //
        // A7.1 — 56 → 72 for `group_id`. Sixteen bytes on every conversation
        // including the direct ones that do not use them, and paid anyway: a group
        // with no stable id cannot be addressed on the wire at all, and the
        // alternative (a side table keyed by conversation) is the same bytes plus
        // a lookup plus a way for the two to disagree — the same trade already
        // refused for the member span, refused again for the same reason.
        assert(@sizeOf(Conversation) == 72);
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
    /// DELETED, parallel to `msgs` (A6, same reason as `mine` — a bool on the hot
    /// record would cost 8 bytes of padding to carry one bit).
    ///
    /// A TOMBSTONE, not a hole. The row stays: removing it would renumber every
    /// index above it, and half this codebase holds message indexes. The bubble
    /// renders as "Message deleted" and its text is scrubbed from the string bytes
    /// on the next save — a deletion that leaves the words on disk is not a
    /// deletion, and the person who tapped it believes it was.
    deleted: std.DynamicBitSetUnmanaged = .{},
    /// EDITED, parallel to `msgs` (A6). The bubble wears an "Edited" mark: a message
    /// whose words changed and said nothing about it would let somebody rewrite what
    /// they said after you read it, and quietly.
    edited: std.DynamicBitSetUnmanaged = .{},
    /// CHAT_FEATURES: reactions. SPARSE by nature — most messages have none — so
    /// they are their own rows rather than a column on every message (A3/A6: you do
    /// not pay for a thing on the messages that do not have it).
    /// GROUPS: every conversation's participants, contiguous per conversation
    /// (`Conversation.member_first`/`member_count`). One flat array rather than a
    /// list per conversation — the same reason messages are one array (A3).
    members: std.MultiArrayList(Member) = .empty,
    /// WHO SENT IT, parallel to `msgs` (A6): the sender's OFFSET within its
    /// conversation's member span, or `sender_me`. In a direct chat it is always
    /// 0, and that is not a special case — it is the same lookup against a
    /// one-element list.
    ///
    /// The direction bitset alone was enough while every conversation had exactly
    /// one counterparty; in a group "not mine" names no one.
    senders: std.ArrayListUnmanaged(u16) = .empty,
    reactions: std.MultiArrayList(Reaction) = .empty,
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
    store.members.deinit(gpa);
    store.senders.deinit(gpa);
    store.mine.deinit(gpa);
    store.reactions.deinit(gpa);
    store.deleted.deinit(gpa);
    store.edited.deinit(gpa);
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
    // An EMPTY string is `TextSpan.empty`, canonically — offset 0, not "wherever
    // the arena happened to end". `spanOk` requires exactly that of any
    // zero-length span, so returning a non-canonical one made the message
    // unrestorable; and because `deserializeStore` rejects the WHOLE blob on a
    // bad span, a single empty text cost the ENTIRE history rather than itself.
    //
    // This was reachable in shipping code: the note on a payment is optional, so
    // sending money without a note wrote a history that would not load again.
    // Against the durability law directly, and silent — the save succeeded, and
    // only the next launch found out.
    if (s.len == 0) return .empty;
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
    // The counterparty is seated as member 0 — the SAME spans the dedup key
    // holds, not a second copy of the bytes. One creation path for both sorts of
    // conversation, so nothing downstream has to ask which it is (A2).
    const member_first: u32 = @intCast(store.members.len);
    try store.members.append(gpa, .{ .did = did_span, .handle = handle_span });
    try store.convs.append(gpa, .{
        .did = did_span,
        .handle = handle_span,
        .last_activity = 0,
        .unread = 0,
        .kind = .direct,
        .member_first = member_first,
        .member_count = 1,
    });
    gop.key_ptr.* = did_span.offset;
    gop.value_ptr.* = index;
    return @enumFromInt(index);
}

// ---------------------------------------------------------------------------
// GROUPS. A group is the same conversation with more than one member, walked by
// the same code — see `Member` for why there is no separate one-person path.
// ---------------------------------------------------------------------------

/// The members table is STRUCT-OF-ARRAYS (A3), so there is no contiguous
/// `[]Member` to hand back and this is deliberately not that shape. Callers walk
/// `0..memberCount(conv)` and ask for the field they need — which also keeps the
/// store's indexes inside this module (A5): what crosses the boundary is a DID,
/// a handle, a count.
///
/// Resolve one member's row, or null when the conversation or the seat does not
/// exist — including a store restored from a blob written before groups, whose
/// member table is empty. Absence is an ordinary answer here (E4).
fn memberRow(store: *const Store, conv: ConvIndex, seat: u16) ?u32 {
    const ci = @intFromEnum(conv);
    if (ci >= store.convs.len) return null;
    if (seat >= store.convs.items(.member_count)[ci]) return null;
    const row = store.convs.items(.member_first)[ci] + @as(u32, seat);
    if (row >= store.members.len) return null;
    return row;
}

/// The DID of the participant in `seat` (seating order). "" if there is none.
pub fn memberDid(store: *const Store, conv: ConvIndex, seat: u16) []const u8 {
    const row = memberRow(store, conv, seat) orelse return "";
    return sliceSpan(store, store.members.items(.did)[row]);
}

/// Their display handle, "" until it is known — same convention as a
/// conversation's.
pub fn memberHandle(store: *const Store, conv: ConvIndex, seat: u16) []const u8 {
    const row = memberRow(store, conv, seat) orelse return "";
    return sliceSpan(store, store.members.items(.handle)[row]);
}

/// Have they left? Their seat stays either way — see `Member.left`.
pub fn memberLeft(store: *const Store, conv: ConvIndex, seat: u16) bool {
    const row = memberRow(store, conv, seat) orelse return false;
    return store.members.items(.left)[row];
}

/// A hard ceiling on group size, mirroring the device-set cap's reasoning: an
/// unbounded member list is a fan-out bomb aimed at other people's clients, and
/// every member multiplies the MLS tree work on every send.
pub const max_members: u16 = 256;

pub const GroupError = error{ OutOfMemory, GroupFull, NotAGroup, NoSuchConversation };

/// ADD a participant, and hand back the seat they took.
///
/// Members are contiguous per conversation in one flat array, so this INSERTS at
/// the end of this conversation's span and slides everything after it along —
/// including the `member_first` of every conversation seated above. That is O(n)
/// over a table held in the dozens, and it keeps the array dense: the cheaper
/// "append at the tail and relocate the span" leaves dead rows behind that then
/// travel to disk and back forever.
///
/// Seats are append-only for the life of the conversation, which is what lets a
/// message store its sender as a seat number (see `Store.senders`).
pub fn addMember(
    gpa: Allocator,
    store: *Store,
    conv: ConvIndex,
    did: []const u8,
    handle: []const u8,
) GroupError!u16 {
    const ci = @intFromEnum(conv);
    if (ci >= store.convs.len) return error.NoSuchConversation;
    const seat = store.convs.items(.member_count)[ci];
    if (seat >= max_members) return error.GroupFull;

    const did_span = try appendString(gpa, store, did);
    const handle_span = if (handle.len > 0) try appendString(gpa, store, handle) else TextSpan.empty;

    const row = store.convs.items(.member_first)[ci] + @as(u32, seat);
    try store.members.insert(gpa, row, .{ .did = did_span, .handle = handle_span });

    // Everyone seated above this row shifted along by one.
    const firsts = store.convs.items(.member_first);
    for (firsts, 0..) |*f, i| {
        if (i != ci and f.* >= row) f.* += 1;
    }
    store.convs.items(.member_count)[ci] = seat + 1;
    return seat;
}

/// They LEFT. The seat is marked, never removed — message attribution is by seat
/// number, and renumbering would quietly re-attribute history to whoever slid
/// into the gap.
pub fn setMemberLeft(store: *Store, conv: ConvIndex, seat: u16, left: bool) void {
    const row = memberRow(store, conv, seat) orelse return;
    store.members.items(.left)[row] = left;
}

/// The seat this DID sits in, or null if they are not in this conversation.
pub fn seatOf(store: *const Store, conv: ConvIndex, did: []const u8) ?u16 {
    const n = memberCount(store, conv);
    var seat: u16 = 0;
    while (seat < n) : (seat += 1) {
        if (std.mem.eql(u8, memberDid(store, conv, seat), did)) return seat;
    }
    return null;
}

/// START A GROUP: a conversation that is a group from birth, named, with its
/// founding members seated in the order given.
///
/// It is NOT deduplicated by counterparty — that key means nothing here, and two
/// groups with the same people are two different groups, which is exactly how
/// people use them.
pub fn startGroup(
    gpa: Allocator,
    store: *Store,
    id: [group_id_len]u8,
    title: []const u8,
    dids: []const []const u8,
    handles: []const []const u8,
) GroupError!ConvIndex {
    if (dids.len > max_members) return error.GroupFull;
    const title_span = if (title.len > 0) try appendString(gpa, store, title) else TextSpan.empty;

    const index: u32 = @intCast(store.convs.len);
    const member_first: u32 = @intCast(store.members.len);
    try store.convs.append(gpa, .{
        .did = TextSpan.empty, // a group has no single counterparty to be keyed by
        .handle = TextSpan.empty,
        .last_activity = 0,
        .unread = 0,
        .kind = .group,
        .member_first = member_first,
        .member_count = 0,
        .title = title_span,
        .group_id = id,
    });
    const conv: ConvIndex = @enumFromInt(index);
    for (dids, 0..) |did, i| {
        const handle = if (i < handles.len) handles[i] else "";
        _ = try addMember(gpa, store, conv, did, handle);
    }
    return conv;
}

/// WHO SENT IT: the seat, or `sender_me`. A message of ours answers `sender_me`
/// whatever the column holds — the direction bit is the older, stronger fact.
pub fn senderSeat(store: *const Store, msg: MsgIndex) u16 {
    const mi = @intFromEnum(msg);
    if (mi >= store.msgs.len) return sender_me;
    if (isMine(store, msg)) return sender_me;
    if (mi >= store.senders.items.len) return 0; // pre-groups history: one counterparty
    return store.senders.items[mi];
}

/// The DID of whoever sent `msg`, or "" for our own. In a direct chat this is
/// the counterparty every time, by the same lookup a group uses.
pub fn senderDid(store: *const Store, msg: MsgIndex) []const u8 {
    const seat = senderSeat(store, msg);
    if (seat == sender_me) return "";
    const mi = @intFromEnum(msg);
    if (mi >= store.msgs.len) return "";
    return memberDid(store, store.msgs.items(.conv)[mi], seat);
}

/// Their display handle, "" until known.
pub fn senderHandle(store: *const Store, msg: MsgIndex) []const u8 {
    const seat = senderSeat(store, msg);
    if (seat == sender_me) return "";
    const mi = @intFromEnum(msg);
    if (mi >= store.msgs.len) return "";
    return memberHandle(store, store.msgs.items(.conv)[mi], seat);
}

/// Is this conversation a group?
pub fn isGroup(store: *const Store, conv: ConvIndex) bool {
    const ci = @intFromEnum(conv);
    return ci < store.convs.len and store.convs.items(.kind)[ci] == .group;
}

/// The group's name, or "" for a direct chat (which is named by its
/// counterparty and stores nothing).
pub fn groupTitle(store: *const Store, conv: ConvIndex) []const u8 {
    const ci = @intFromEnum(conv);
    if (ci >= store.convs.len) return "";
    return sliceSpan(store, store.convs.items(.title)[ci]);
}

/// How many participants, counting those who have left (their rows stay so
/// message attribution does not shift under history).
pub fn memberCount(store: *const Store, conv: ConvIndex) u16 {
    const ci = @intFromEnum(conv);
    return if (ci < store.convs.len) store.convs.items(.member_count)[ci] else 0;
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
        .reply_to = no_reply, // set by `setReplyTo` when this message answers one
        .effect = 0, // set by `setEffect` when this message was sent with one
        .game = 0, // set by `setGameMove` for a `.game_move`
        .bubble = 0, // set by `setBubbleFx` on arrival (transient)
    });
    try store.mine.resize(gpa, store.msgs.len, false);
    store.mine.setValue(index, mine);
    try store.deleted.resize(gpa, store.msgs.len, false);
    try store.edited.resize(gpa, store.msgs.len, false);
    // The sender column grows in lockstep with the messages, exactly as the
    // direction bitset does. Seat 0 is the default and it is the right answer for
    // every direct chat — the one-member case of the same lookup. A group send
    // overwrites it through `setSenderSeat`, which is the only way it differs.
    try store.senders.resize(gpa, store.msgs.len);
    store.senders.items[index] = if (mine) sender_me else 0;

    const ci: u32 = @intFromEnum(conv);
    const convs = store.convs.slice();
    // Relay drains and disk resume can deliver out of order; the activity
    // clock only moves forward.
    convs.items(.last_activity)[ci] = @max(convs.items(.last_activity)[ci], created_at);
    if (!mine) convs.items(.unread)[ci] += 1;
    return @enumFromInt(index);
}

/// The reader has seen this conversation; its unread count returns to zero.
/// WHO in a group sent it. Called by the receive path once it knows; a direct
/// chat never needs it, because seat 0 is already the only counterparty there is.
pub fn setSenderSeat(store: *Store, msg: MsgIndex, seat: u16) void {
    const mi = @intFromEnum(msg);
    if (mi >= store.senders.items.len) return;
    store.senders.items[mi] = seat;
}

/// Is this message a tombstone? (PURE.)
pub fn isDeleted(store: *const Store, msg: u32) bool {
    if (msg >= store.deleted.bit_length) return false;
    return store.deleted.isSet(msg);
}

/// DELETE a message from THIS device's history. The row survives as a tombstone —
/// removing it would renumber every index above it, and half the codebase holds
/// message indexes — but its TEXT is scrubbed to nothing here and its bytes stop
/// being written on the next save. A deletion that leaves the words on disk is not
/// a deletion, and the person who tapped it believes that it was.
pub fn deleteMessage(store: *Store, msg: u32) void {
    if (msg >= store.msgs.len) return;
    if (msg >= store.deleted.bit_length) return;
    store.deleted.set(msg);
    const msgs = store.msgs.slice();
    const span = msgs.items(.text)[msg];
    // Scrub the bytes in place: the string arena is shared, so this cannot free
    // them, but it CAN make them nothing.
    const bytes = store.string_bytes.items;
    const end = @as(usize, span.offset) + span.len;
    if (end <= bytes.len) @memset(bytes[span.offset..end], 0);
    msgs.items(.text)[msg] = TextSpan.empty;
}

pub fn isEdited(store: *const Store, msg: u32) bool {
    if (msg >= store.edited.bit_length) return false;
    return store.edited.isSet(msg);
}

/// HOW LONG a message stays editable / unsendable. 24 hours, which is where every
/// messenger landed: long enough for the typo you notice tomorrow morning, short
/// enough that a client which pruned the message cannot be asked to change a past
/// nobody can still see.
pub const edit_window_s: i64 = 24 * 60 * 60;

/// PURE: may this message still be edited or unsent? Only ours, only if it is not
/// already a tombstone, and only inside the window.
pub fn canRevise(store: *const Store, msg: u32, now: i64) bool {
    if (msg >= store.msgs.len) return false;
    if (isDeleted(store, msg)) return false;
    if (!isMine(store, @enumFromInt(msg))) return false;
    return now - store.msgs.items(.created_at)[msg] <= edit_window_s;
}

/// EDIT a message's text in place (ours, or an accepted edit of theirs). The new
/// text is appended to the string arena and the span re-pointed; the old bytes are
/// SCRUBBED, so the words somebody replaced do not survive on disk. The message
/// keeps its timestamp — it is the same message, said better — and wears the mark.
pub fn editMessage(gpa: Allocator, store: *Store, msg: u32, text: []const u8) error{OutOfMemory}!void {
    if (msg >= store.msgs.len) return;
    const msgs = store.msgs.slice();
    const old = msgs.items(.text)[msg];
    const span = try appendString(gpa, store, text);
    const bytes = store.string_bytes.items;
    const end = @as(usize, old.offset) + old.len;
    if (end <= bytes.len) @memset(bytes[old.offset..end], 0);
    msgs.items(.text)[msg] = span;
    if (msg < store.edited.bit_length) store.edited.set(msg);
}

/// Find a message by its conversation + timestamp + direction — how a DELETE
/// REQUEST from the other side names the message it wants gone. We do not send
/// message ids on the wire (there are none), and inventing one would mean a schema
/// change in a store that is already deployed. A collision would need two messages
/// from the same person in the same conversation in the same SECOND; if it ever
/// happens, the oldest matching one goes, which is the one they meant.
pub fn findByStamp(store: *const Store, conv: ConvIndex, created_at: i64, mine_bit: bool) ?u32 {
    const msgs = store.msgs.slice();
    var i: u32 = 0;
    while (i < store.msgs.len) : (i += 1) {
        if (msgs.items(.conv)[i] != conv) continue;
        if (msgs.items(.created_at)[i] != created_at) continue;
        if (isMine(store, @enumFromInt(i)) != mine_bit) continue;
        if (isDeleted(store, i)) continue;
        return i;
    }
    return null;
}

/// DELETE a conversation from this device: hide it, and scrub every message in it.
/// The row survives as a tombstone (indexes above it would renumber otherwise), but
/// nothing of what was said does — a "deleted" conversation whose words sit on disk
/// is not deleted, and the person who tapped it believes that it is.
///
/// It is not sent anywhere: deleting a conversation is a statement about YOUR copy.
/// (Deleting THEIR copy is what Delete-for-everyone does, message by message, and it
/// is a different sentence entirely.)
pub fn deleteConversation(store: *Store, conv: ConvIndex) void {
    const ci: u32 = @intFromEnum(conv);
    if (ci >= store.convs.len) return;
    var i: u32 = 0;
    while (i < store.msgs.len) : (i += 1) {
        if (store.msgs.items(.conv)[i] != conv) continue;
        deleteMessage(store, i);
    }
    store.convs.items(.hidden)[ci] = true;
    store.convs.items(.unread)[ci] = 0;
}

pub fn setPinned(store: *Store, conv: ConvIndex, on: bool) void {
    const ci: u32 = @intFromEnum(conv);
    if (ci < store.convs.len) store.convs.items(.pinned)[ci] = on;
}

pub fn setMuted(store: *Store, conv: ConvIndex, on: bool) void {
    const ci: u32 = @intFromEnum(conv);
    if (ci < store.convs.len) store.convs.items(.muted)[ci] = on;
}

pub fn isPinned(store: *const Store, conv: ConvIndex) bool {
    const ci: u32 = @intFromEnum(conv);
    return ci < store.convs.len and store.convs.items(.pinned)[ci];
}

pub fn isMuted(store: *const Store, conv: ConvIndex) bool {
    const ci: u32 = @intFromEnum(conv);
    return ci < store.convs.len and store.convs.items(.muted)[ci];
}

/// Mark it UNREAD again — "I saw it, I cannot deal with it now, do not let me
/// forget." One of the most-used features in every messenger and one of the least
/// celebrated.
/// This message ANSWERS that one. Set right after the append, by whoever knows.
pub fn setReplyTo(store: *Store, msg: u32, target: u32) void {
    if (msg >= store.msgs.len) return;
    if (target != no_reply and target >= store.msgs.len) return;
    store.msgs.items(.reply_to)[msg] = target;
}

pub fn replyTo(store: *const Store, msg: u32) u32 {
    if (msg >= store.msgs.len) return no_reply;
    return store.msgs.items(.reply_to)[msg];
}

/// Record the screen effect a message was sent with (`setReplyTo`'s shape: the
/// append stays one function, the decoration is applied after).
pub fn setEffect(store: *Store, msg: u32, effect: u8) void {
    if (msg >= store.msgs.len) return;
    store.msgs.items(.effect)[msg] = effect;
}

pub fn effectOf(store: *const Store, msg: u32) u8 {
    if (msg >= store.msgs.len) return 0;
    return store.msgs.items(.effect)[msg];
}

/// The BUBBLE effect a message arrived with (transient; see the field note).
pub fn setBubbleFx(store: *Store, msg: u32, bubble: u8) void {
    if (msg >= store.msgs.len) return;
    store.msgs.items(.bubble)[msg] = bubble;
}

pub fn bubbleFxOf(store: *const Store, msg: u32) u8 {
    if (msg >= store.msgs.len) return 0;
    return store.msgs.items(.bubble)[msg];
}

/// Record the encoded move byte on a `.game_move` message.
pub fn setGameMove(store: *Store, msg: u32, encoded: u8) void {
    if (msg >= store.msgs.len) return;
    store.msgs.items(.game)[msg] = encoded;
}

pub fn gameMoveOf(store: *const Store, msg: u32) u8 {
    if (msg >= store.msgs.len) return 0;
    return store.msgs.items(.game)[msg];
}

/// They have read everything of ours up to `at`. The watermark only ever moves
/// FORWARD: an out-of-order receipt must not un-read a message somebody has read.
pub fn setReadUpTo(store: *Store, conv: ConvIndex, at: i64) void {
    const ci: u32 = @intFromEnum(conv);
    if (ci >= store.convs.len) return;
    const cur = store.convs.items(.read_up_to)[ci];
    if (at > cur) store.convs.items(.read_up_to)[ci] = at;
}

pub fn readUpTo(store: *const Store, conv: ConvIndex) i64 {
    const ci: u32 = @intFromEnum(conv);
    return if (ci < store.convs.len) store.convs.items(.read_up_to)[ci] else 0;
}

/// READ (CHAT_FEATURES). [kind][i64 up_to] — "everything you sent me up to here, I
/// have seen". A watermark, not a per-message flag: it is one deposit instead of
/// one per message, which matters when every deposit is a fact the relay can time.
pub const kind_read_wire: u8 = 11;

/// TOGGLE a reaction: the same emoji from the same person twice is a person taking
/// it back, which is what everybody expects and nobody writes down.
pub fn react(gpa: Allocator, store: *Store, msg: u32, emoji: []const u8, mine: bool) error{OutOfMemory}!void {
    if (msg >= store.msgs.len or emoji.len == 0 or emoji.len > 8) return;
    var e8: [8]u8 = @splat(0);
    @memcpy(e8[0..emoji.len], emoji);

    const rs = store.reactions.slice();
    var i: usize = 0;
    while (i < store.reactions.len) : (i += 1) {
        if (rs.items(.msg)[i] != msg) continue;
        if (rs.items(.mine)[i] != mine) continue;
        if (!std.mem.eql(u8, &rs.items(.emoji)[i], &e8)) continue;
        _ = store.reactions.orderedRemove(i); // the same one again = take it back
        return;
    }
    // One reaction per person per message: a new one REPLACES theirs.
    i = 0;
    while (i < store.reactions.len) : (i += 1) {
        if (store.reactions.items(.msg)[i] == msg and store.reactions.items(.mine)[i] == mine) {
            _ = store.reactions.orderedRemove(i);
            break;
        }
    }
    try store.reactions.append(gpa, .{ .msg = msg, .emoji = e8, .mine = mine });
}

/// The reactions on a message, written into `out` (at most 2 in a 1:1 conversation:
/// theirs and yours). Returns how many.
pub fn reactionsOf(store: *const Store, msg: u32, out: *[4]Reaction) usize {
    var n: usize = 0;
    const rs = store.reactions.slice();
    for (0..store.reactions.len) |i| {
        if (rs.items(.msg)[i] != msg) continue;
        if (n == out.len) break;
        out[n] = .{ .msg = msg, .emoji = rs.items(.emoji)[i], .mine = rs.items(.mine)[i] };
        n += 1;
    }
    return n;
}

pub fn markUnread(store: *Store, conv: ConvIndex) void {
    const ci: u32 = @intFromEnum(conv);
    if (ci < store.convs.len and store.convs.items(.unread)[ci] == 0) store.convs.items(.unread)[ci] = 1;
}

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
// GROUP FRAMES (pure). Encode and decode only — who may SEND one is the shell's
// business, and what to believe about it is stated at the wire kinds above.
// ---------------------------------------------------------------------------

/// A group message, unwrapped: which group, and the bytes that would have been
/// the whole payload in a direct chat.
/// A7.2: cold, transient — one per delivered message.
pub const GroupFrame = struct {
    id: [group_id_len]u8,
    /// `[inner kind][inner payload…]` — handed straight to the same decoder a
    /// direct message goes through.
    inner: []const u8,
};

/// Parse `[group_id][inner…]` (the leading kind byte already consumed).
///
/// An EMPTY inner is refused: a group frame that carries nothing is not a message
/// with no text, it is a frame that lost its kind byte, and guessing which kind it
/// meant is how a parser starts inventing messages.
pub fn parseGroupFrame(bytes: []const u8) FrameError!GroupFrame {
    if (bytes.len < group_id_len + 1) return error.Malformed;
    var id: [group_id_len]u8 = undefined;
    @memcpy(&id, bytes[0..group_id_len]);
    return .{ .id = id, .inner = bytes[group_id_len..] };
}

/// Write one. `out` must hold `group_id_len + inner.len` bytes; returns the
/// written slice.
pub fn writeGroupFrame(out: []u8, id: [group_id_len]u8, inner: []const u8) FrameError![]u8 {
    if (inner.len == 0) return error.Malformed; // see `parseGroupFrame`
    if (out.len < group_id_len + inner.len) return error.Malformed;
    @memcpy(out[0..group_id_len], &id);
    @memcpy(out[group_id_len..][0..inner.len], inner);
    return out[0 .. group_id_len + inner.len];
}

/// A roster, unwrapped. The DIDs are walked with `next` rather than collected,
/// so parsing allocates nothing and a hostile count cannot make us reserve for it.
/// A7.2: cold, transient.
pub const GroupMeta = struct {
    id: [group_id_len]u8,
    title: []const u8,
    /// How many DIDs the frame CLAIMS. Believe the iterator, not this — a frame
    /// can say twelve and carry three, and `next` simply runs out.
    claimed: u8,
    rest: []const u8,

    /// The next DID, or null at the end. Total on hostile input: a length that
    /// overruns ends the walk rather than reading past the frame.
    pub fn next(m: *GroupMeta) ?[]const u8 {
        if (m.rest.len < 1) return null;
        const n = m.rest[0];
        if (n == 0 or m.rest.len < 1 + @as(usize, n)) {
            m.rest = m.rest[0..0];
            return null;
        }
        const did = m.rest[1..][0..n];
        m.rest = m.rest[1 + @as(usize, n) ..];
        return did;
    }
};

/// Parse `[group_id][title len][title][count][(did len, did)…]`.
pub fn parseGroupMeta(bytes: []const u8) FrameError!GroupMeta {
    if (bytes.len < group_id_len + 2) return error.Malformed;
    var id: [group_id_len]u8 = undefined;
    @memcpy(&id, bytes[0..group_id_len]);
    var at: usize = group_id_len;
    const tlen = bytes[at];
    at += 1;
    if (bytes.len < at + tlen + 1) return error.Malformed;
    const title = bytes[at..][0..tlen];
    at += tlen;
    const count = bytes[at];
    at += 1;
    return .{ .id = id, .title = title, .claimed = count, .rest = bytes[at..] };
}

/// Write one. Returns the written slice, or `Malformed` when it will not fit or a
/// field is too long to describe in its one length byte.
pub fn writeGroupMeta(
    out: []u8,
    id: [group_id_len]u8,
    title: []const u8,
    dids: []const []const u8,
) FrameError![]u8 {
    if (title.len > 255 or dids.len > 255) return error.Malformed;
    var need: usize = group_id_len + 1 + title.len + 1;
    for (dids) |d| {
        if (d.len == 0 or d.len > 255) return error.Malformed;
        need += 1 + d.len;
    }
    if (out.len < need) return error.Malformed;

    var at: usize = 0;
    @memcpy(out[0..group_id_len], &id);
    at += group_id_len;
    out[at] = @intCast(title.len);
    at += 1;
    @memcpy(out[at..][0..title.len], title);
    at += title.len;
    out[at] = @intCast(dids.len);
    at += 1;
    for (dids) |d| {
        out[at] = @intCast(d.len);
        at += 1;
        @memcpy(out[at..][0..d.len], d);
        at += d.len;
    }
    return out[0..at];
}

/// The group's id on the wire, or all-zero for a direct chat (which is addressed
/// by its counterparty and has none).
pub fn groupId(store: *const Store, conv: ConvIndex) [group_id_len]u8 {
    const ci = @intFromEnum(conv);
    if (ci >= store.convs.len) return [_]u8{0} ** group_id_len;
    return store.convs.items(.group_id)[ci];
}

/// Find the conversation carrying this group id, or null. Linear over the
/// conversations, which are held in dozens — and it is the ONE place a wire id
/// becomes a local conversation, so a group that arrives twice cannot become two.
pub fn conversationByGroupId(store: *const Store, id: [group_id_len]u8) ?ConvIndex {
    const kinds = store.convs.items(.kind);
    const ids = store.convs.items(.group_id);
    for (kinds, ids, 0..) |k, gid, i| {
        if (k != .group) continue;
        if (std.mem.eql(u8, &gid, &id)) return @enumFromInt(i);
    }
    return null;
}

// ---------------------------------------------------------------------------
// Queries — views over the one store (B5: plain arrays out)
// ---------------------------------------------------------------------------

/// The conversation list, newest activity first. Arena-allocated result
/// (C3); ties break by table order so the output is deterministic.
/// PINNED FIRST, then by activity — and DELETED conversations are not in the list at
/// all. (The row still exists in the store; it is simply not something the person is
/// looking at any more, which is what they asked for when they tapped Delete.)
pub fn conversationsByActivity(
    arena: Allocator,
    store: *const Store,
) error{OutOfMemory}![]ConvIndex {
    var keep = try std.ArrayListUnmanaged(ConvIndex).initCapacity(arena, store.convs.len);
    const hidden = store.convs.items(.hidden);
    for (0..store.convs.len) |i| {
        if (hidden[i]) continue;
        keep.appendAssumeCapacity(@enumFromInt(i));
    }
    const out = keep.items;
    const activity = store.convs.items(.last_activity);
    const pinned = store.convs.items(.pinned);
    const Ctx = struct {
        activity: []const i64,
        pinned: []const bool,
        pub fn lessThan(ctx: @This(), x: ConvIndex, y: ConvIndex) bool {
            // A PIN OUTRANKS RECENCY. That is the entire point of a pin: the person
            // has said "this one stays where I can see it", and a newer message from
            // somebody else must not be allowed to overrule them.
            const px = ctx.pinned[@intFromEnum(x)];
            const py = ctx.pinned[@intFromEnum(y)];
            if (px != py) return px;
            const ax = ctx.activity[@intFromEnum(x)];
            const ay = ctx.activity[@intFromEnum(y)];
            if (ax != ay) return ax > ay;
            return @intFromEnum(x) < @intFromEnum(y);
        }
    };
    std.mem.sort(ConvIndex, out, Ctx{ .activity = activity, .pinned = pinned }, Ctx.lessThan);
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
/// v3 (CHAT_FEATURES): the DELETED bitset, appended after the payments/settlements
/// sections so every v2 blob still reads (a version gate is a compatibility
/// contract and is written as a RANGE — the day we wrote it as a LIST, a v3 bump
/// orphaned every conversation on the owner's phone).
const codec_version: u16 = 11; // v11: groups — the member table, the conversation's kind/title/span, the sender column
const conv_rec_len = 28; // did span 8 + handle span 8 + i64 8 + u32 4
const member_rec_len = 17; // did span 8 + handle span 8 + left u8 1
/// The v11 per-conversation block: kind 1 + title span 8 + member span (4 + 2) +
/// group id. NAMED because the same sum is needed by the serializer, the reader,
/// `versionTailLen` and the round-trip test — and the last codec bump broke two
/// damage tests precisely by leaving that arithmetic written out four times.
const conv_v11_rec_len = 1 + 8 + 4 + 2 + group_id_len;
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
        4 + r_count * ref_rec_len +
        (m_count + 7) / 8 + // v3: the deleted bitset
        (m_count + 7) / 8 + // v4: the edited bitset
        c_count + // v5: one flags byte per conversation
        4 * m_count + // v6: reply_to, one u32 per message
        4 + store.reactions.len * 13 + // v7: reactions (u32 msg + 8 emoji + 1 mine)
        8 * c_count + // v8: read_up_to, one i64 per conversation
        m_count + // v9: effect, one u8 per message
        m_count + // v10: game move, one u8 per message
        // v11: GROUPS.
        4 + store.members.len * member_rec_len + // the member table
        c_count * conv_v11_rec_len + // per conversation: kind, title span, member span, group id
        2 * m_count; // per message: the sender's seat
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

    // v3: the tombstones. A deletion that a relaunch undoes is not a deletion.
    const del_bytes = out[at..][0 .. (m_count + 7) / 8];
    @memset(del_bytes, 0);
    for (0..m_count) |i| {
        if (i < store.deleted.bit_length and store.deleted.isSet(i)) del_bytes[i / 8] |= @as(u8, 1) << @intCast(i % 8);
    }
    at += (m_count + 7) / 8;

    // v4: the edit marks.
    const ed_bytes = out[at..][0 .. (m_count + 7) / 8];
    @memset(ed_bytes, 0);
    for (0..m_count) |i| {
        if (i < store.edited.bit_length and store.edited.isSet(i)) ed_bytes[i / 8] |= @as(u8, 1) << @intCast(i % 8);
    }
    at += (m_count + 7) / 8;

    // v5: what the person has done to each conversation. A pin that a relaunch
    // forgets is not a pin, and a mute that a relaunch forgets will wake somebody at
    // 3am who asked not to be woken.
    for (0..c_count) |i| {
        var f: u8 = 0;
        if (convs.items(.pinned)[i]) f |= 1;
        if (convs.items(.muted)[i]) f |= 2;
        if (convs.items(.hidden)[i]) f |= 4;
        out[at] = f;
        at += 1;
    }

    // v6: what each message answers. A reply that a relaunch forgets is just a
    // message that happened to arrive after another one.
    for (0..m_count) |i| {
        std.mem.writeInt(u32, out[at..][0..4], msgs.items(.reply_to)[i], .little);
        at += 4;
    }

    // v7: reactions.
    const rx_count: u32 = @intCast(store.reactions.len);
    std.mem.writeInt(u32, out[at..][0..4], rx_count, .little);
    at += 4;
    const rxs = store.reactions.slice();
    for (0..rx_count) |i| {
        std.mem.writeInt(u32, out[at..][0..4], rxs.items(.msg)[i], .little);
        @memcpy(out[at + 4 ..][0..8], &rxs.items(.emoji)[i]);
        out[at + 12] = @intFromBool(rxs.items(.mine)[i]);
        at += 13;
    }

    // v8: their read watermark.
    for (0..c_count) |i| {
        std.mem.writeInt(i64, out[at..][0..8], convs.items(.read_up_to)[i], .little);
        at += 8;
    }

    // v9: what each message was SENT WITH. Same reasoning as the reply column: a
    // message sent with lasers that a relaunch forgets is just a message.
    for (0..m_count) |i| {
        out[at] = msgs.items(.effect)[i];
        at += 1;
    }

    // v10: the game moves. THE BOARD IS THESE BYTES — the game has no stored
    // state of its own, so a relaunch that forgot this column would not forget a
    // detail of the game, it would forget the game.
    for (0..m_count) |i| {
        out[at] = msgs.items(.game)[i];
        at += 1;
    }

    // v11: GROUPS. The member table first (the conversations' spans point into
    // it), then each conversation's kind/title/span, then who sent each message.
    std.mem.writeInt(u32, out[at..][0..4], @intCast(store.members.len), .little);
    at += 4;
    const mems = store.members.slice();
    for (0..store.members.len) |i| {
        const spans = [2]TextSpan{ mems.items(.did)[i], mems.items(.handle)[i] };
        for (spans) |span| {
            std.mem.writeInt(u32, out[at..][0..4], span.offset, .little);
            at += 4;
            std.mem.writeInt(u32, out[at..][0..4], span.len, .little);
            at += 4;
        }
        out[at] = @intFromBool(mems.items(.left)[i]);
        at += 1;
    }
    for (0..c_count) |i| {
        out[at] = @intFromEnum(convs.items(.kind)[i]);
        at += 1;
        const t = convs.items(.title)[i];
        std.mem.writeInt(u32, out[at..][0..4], t.offset, .little);
        at += 4;
        std.mem.writeInt(u32, out[at..][0..4], t.len, .little);
        at += 4;
        std.mem.writeInt(u32, out[at..][0..4], convs.items(.member_first)[i], .little);
        at += 4;
        std.mem.writeInt(u16, out[at..][0..2], convs.items(.member_count)[i], .little);
        at += 2;
        @memcpy(out[at..][0..group_id_len], &convs.items(.group_id)[i]);
        at += group_id_len;
    }
    for (0..m_count) |i| {
        const seat: u16 = if (i < store.senders.items.len) store.senders.items[i] else 0;
        std.mem.writeInt(u16, out[at..][0..2], seat, .little);
        at += 2;
    }

    assert(at == total);
    return out;
}

/// The byte length of the v3..v11 per-record tail — everything appended AFTER the
/// settlement section by a codec version bump.
///
/// This exists because the arithmetic was written out by hand in two damage
/// tests, and the v9 bump broke BOTH: one started failing for the wrong reason
/// and the other stopped failing cleanly at all (a stale offset landed in a
/// length field and the deserializer tried to allocate it, so the test OOM'd
/// instead of reporting `Malformed`). Those tests locate the older sections by
/// stepping back over this tail, so every future version must extend it HERE,
/// once, rather than in each copy.
fn versionTailLen(store: *const Store) usize {
    const m = store.msgs.len;
    const c = store.convs.len;
    return 2 * ((m + 7) / 8) + // v3 tombstones + v4 edit marks
        c + // v5 conversation flags
        4 * m + // v6 reply_to
        4 + store.reactions.len * 13 + // v7 reactions (count + rows)
        8 * c + // v8 read_up_to
        m + // v9 effect
        m + // v10 game move
        // v11 GROUPS: the member table, then per conversation kind + title span +
        // member span, then the sender's seat per message.
        4 + store.members.len * member_rec_len +
        c * conv_v11_rec_len +
        2 * m;
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
    // A RANGE, NOT A LIST. This line read `version != 1 and version != 2`, which was
    // correct only while there were exactly two versions — and the LAST time a gate
    // like it was bumped, it silently orphaned every conversation on the owner's
    // phone (the groups blob, 2026-07-12). Every version we have ever written still
    // reads; only a version from the FUTURE is refused.
    if (version < 1 or version > codec_version) return error.Malformed;
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

        // A DIRECT conversation IS its counterparty DID: non-empty, clean for the
        // interning map (no interior NUL), and unique. A GROUP has no single
        // counterparty and carries the empty span instead — so emptiness is a
        // legal answer here, and it is the ONLY thing that distinguishes the two
        // at this point in the read (the kind byte lives in the v11 section, which
        // has not been reached yet).
        //
        // Whatever is present must still hold up: a span that is not empty is
        // checked exactly as strictly as before, and only non-empty DIDs enter the
        // interning map — a group is not addressable by counterparty and must
        // never collide with one that is.
        if (!spanOk(store.string_bytes.items, conv.did)) return error.Malformed;
        if (!spanOk(store.string_bytes.items, conv.handle)) return error.Malformed;
        const did = sliceSpan(&store, conv.did);
        if (did.len > 0 and std.mem.indexOfScalar(u8, did, 0) != null) return error.Malformed;
        store.convs.appendAssumeCapacity(conv);

        if (did.len > 0) {
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
    try store.deleted.resize(gpa, m_count, false);
    try store.edited.resize(gpa, m_count, false);
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

    // v3: the tombstones. A v2 blob has none, and that is not damage — nothing had
    // been deleted before the feature existed. (RANGE, not a list: the day this gate
    // was written as a list, a version bump silently orphaned every conversation on
    // the owner's phone.)
    if (version >= 3) {
        const del_len = (@as(usize, m_count) + 7) / 8;
        if (bytes.len - at < del_len) return error.Malformed;
        for (0..m_count) |i| {
            const bit = (bytes[at + i / 8] >> @intCast(i % 8)) & 1;
            store.deleted.setValue(i, bit == 1);
        }
        if (m_count % 8 != 0) {
            const used: u3 = @intCast(m_count % 8);
            const mask: u8 = @as(u8, 0xFF) << used;
            if (bytes[at + del_len - 1] & mask != 0) return error.Malformed; // canonical
        }
        at += del_len;
    }

    // v4: the edit marks. A v3 blob has none, which is not damage.
    if (version >= 4) {
        const ed_len = (@as(usize, m_count) + 7) / 8;
        if (bytes.len - at < ed_len) return error.Malformed;
        for (0..m_count) |i| {
            const bit = (bytes[at + i / 8] >> @intCast(i % 8)) & 1;
            store.edited.setValue(i, bit == 1);
        }
        if (m_count % 8 != 0) {
            const used: u3 = @intCast(m_count % 8);
            const mask: u8 = @as(u8, 0xFF) << used;
            if (bytes[at + ed_len - 1] & mask != 0) return error.Malformed;
        }
        at += ed_len;
    }

    // v5: the conversation flags. A v4 blob has none — nothing had been pinned,
    // muted or deleted before those existed.
    if (version >= 5) {
        if (bytes.len - at < c_count) return error.Malformed;
        const cs = store.convs.slice();
        for (0..c_count) |i| {
            const f = bytes[at + i];
            if (f & ~@as(u8, 7) != 0) return error.Malformed; // canonical: no unknown bits
            cs.items(.pinned)[i] = (f & 1) != 0;
            cs.items(.muted)[i] = (f & 2) != 0;
            cs.items(.hidden)[i] = (f & 4) != 0;
        }
        at += c_count;
    }

    // v6: the reply column. A v5 blob has none — nothing answered anything before
    // replies existed.
    if (version >= 6) {
        if (bytes.len - at < 4 * @as(usize, m_count)) return error.Malformed;
        const ms = store.msgs.slice();
        for (0..m_count) |i| {
            const r = std.mem.readInt(u32, bytes[at..][0..4], .little);
            // A reply must name a message that EXISTS (and never itself): a corrupt
            // index here would have the renderer chasing a bubble that is not there.
            if (r != no_reply and (r >= m_count or r == i)) return error.Malformed;
            ms.items(.reply_to)[i] = r;
            at += 4;
        }
    }

    // v7: reactions. A v6 blob has none.
    if (version >= 7) {
        if (bytes.len - at < 4) return error.Malformed;
        const rx_count = std.mem.readInt(u32, bytes[at..][0..4], .little);
        at += 4;
        if (bytes.len - at < @as(usize, rx_count) * 13) return error.Malformed;
        for (0..rx_count) |_| {
            const m = std.mem.readInt(u32, bytes[at..][0..4], .little);
            if (m >= m_count) return error.Malformed; // a reaction on nothing
            var e8: [8]u8 = undefined;
            @memcpy(&e8, bytes[at + 4 ..][0..8]);
            const mb = bytes[at + 12];
            if (mb > 1) return error.Malformed; // canonical
            try store.reactions.append(gpa, .{ .msg = m, .emoji = e8, .mine = mb == 1 });
            at += 13;
        }
    }

    // v8: the read watermark. A v7 blob has none.
    if (version >= 8) {
        if (bytes.len - at < 8 * @as(usize, c_count)) return error.Malformed;
        const cs2 = store.convs.slice();
        for (0..c_count) |i| {
            cs2.items(.read_up_to)[i] = std.mem.readInt(i64, bytes[at..][0..8], .little);
            at += 8;
        }
    }

    // v9: the effect column. A v8 blob has none — nothing was sent with an
    // effect before the picker could attach one.
    if (version >= 9) {
        if (bytes.len - at < m_count) return error.Malformed;
        const ms2 = store.msgs.slice();
        for (0..m_count) |i| {
            ms2.items(.effect)[i] = bytes[at];
            at += 1;
        }
    }

    // v10: the game-move column. A v9 blob has none — no game had been played.
    if (version >= 10) {
        if (bytes.len - at < m_count) return error.Malformed;
        const ms3 = store.msgs.slice();
        for (0..m_count) |i| {
            ms3.items(.game)[i] = bytes[at];
            at += 1;
        }
    }

    // v11: GROUPS.
    //
    // A blob written before groups existed has no member table — and that is a
    // MIGRATION, not an absence to shrug at: every conversation in it is a direct
    // chat with exactly one counterparty, so seating that counterparty as member 0
    // is what makes the old history speak the new model. Skip it and every
    // restored conversation would have no participants at all, which is a
    // different and much worse kind of wrong than a missing column.
    if (version >= 11) {
        if (bytes.len - at < 4) return error.Malformed;
        const mem_count = std.mem.readInt(u32, bytes[at..][0..4], .little);
        at += 4;
        if (@as(u64, mem_count) * member_rec_len > bytes.len - at) return error.Malformed;
        try store.members.ensureTotalCapacity(gpa, mem_count);
        for (0..mem_count) |_| {
            var spans: [2]TextSpan = undefined;
            for (&spans) |*span| {
                const off = std.mem.readInt(u32, bytes[at..][0..4], .little);
                at += 4;
                const len = std.mem.readInt(u32, bytes[at..][0..4], .little);
                at += 4;
                if (@as(u64, off) + len > store.string_bytes.items.len) return error.Malformed;
                span.* = .{ .offset = off, .len = len };
            }
            const left = bytes[at] != 0;
            at += 1;
            store.members.appendAssumeCapacity(.{ .did = spans[0], .handle = spans[1], .left = left });
        }

        if (bytes.len - at < c_count * conv_v11_rec_len) return error.Malformed;
        const cs2 = store.convs.slice();
        for (0..c_count) |i| {
            const kind_raw = bytes[at];
            at += 1;
            cs2.items(.kind)[i] = std.enums.fromInt(ConvKind, kind_raw) orelse return error.Malformed;
            const off = std.mem.readInt(u32, bytes[at..][0..4], .little);
            at += 4;
            const len = std.mem.readInt(u32, bytes[at..][0..4], .little);
            at += 4;
            if (@as(u64, off) + len > store.string_bytes.items.len) return error.Malformed;
            cs2.items(.title)[i] = .{ .offset = off, .len = len };
            const first = std.mem.readInt(u32, bytes[at..][0..4], .little);
            at += 4;
            const count = std.mem.readInt(u16, bytes[at..][0..2], .little);
            at += 2;
            // A span that leaves the table is a corrupt blob, not a survivable
            // one: every member lookup and every sender attribution reads through
            // it (E3 — named, never half-restored).
            if (@as(u64, first) + count > store.members.len) return error.Malformed;
            cs2.items(.member_first)[i] = first;
            cs2.items(.member_count)[i] = count;
            @memcpy(&cs2.items(.group_id)[i], bytes[at..][0..group_id_len]);
            at += group_id_len;

            // NOW the kind is known, so each sort answers for itself: a direct
            // conversation must have the counterparty DID it is addressed by, and
            // a group must not pretend to have one. Checked here rather than
            // above because above there was nothing to tell them apart.
            const has_did = cs2.items(.did)[i].len > 0;
            const zero_id = [_]u8{0} ** group_id_len;
            const has_id = !std.mem.eql(u8, &cs2.items(.group_id)[i], &zero_id);
            switch (cs2.items(.kind)[i]) {
                .direct => if (!has_did or has_id) return error.Malformed,
                // A group with no id could never be addressed on the wire again:
                // every message for it arrives over a pairwise session naming an
                // id, and there would be nothing to match. Restoring it would be
                // restoring a conversation that can only ever be read, never
                // continued — so it is damage, and damage is named (E3).
                .group => if (has_did or !has_id) return error.Malformed,
            }
        }

        if (bytes.len - at < 2 * m_count) return error.Malformed;
        try store.senders.resize(gpa, m_count);
        for (0..m_count) |i| {
            store.senders.items[i] = std.mem.readInt(u16, bytes[at..][0..2], .little);
            at += 2;
        }
    } else {
        // THE MIGRATION. Seat each old conversation's counterparty as its member 0,
        // reusing the very spans the conversation already holds — the same bytes,
        // referenced twice, never copied.
        const cs2 = store.convs.slice();
        try store.members.ensureTotalCapacity(gpa, c_count);
        for (0..c_count) |i| {
            // Written before groups existed ⇒ every conversation is direct ⇒ the
            // counterparty DID is still mandatory, exactly as it always was.
            if (cs2.items(.did)[i].len == 0) return error.Malformed;
            const first: u32 = @intCast(store.members.len);
            store.members.appendAssumeCapacity(.{
                .did = cs2.items(.did)[i],
                .handle = cs2.items(.handle)[i],
            });
            cs2.items(.kind)[i] = .direct;
            cs2.items(.title)[i] = TextSpan.empty;
            cs2.items(.group_id)[i] = [_]u8{0} ** group_id_len;
            cs2.items(.member_first)[i] = first;
            cs2.items(.member_count)[i] = 1;
        }
        // One counterparty means seat 0 for everything they said.
        try store.senders.resize(gpa, m_count);
        for (0..m_count) |i| store.senders.items[i] = 0;
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

test "store codec v9: the effect column survives a relaunch" {
    const gpa = std.testing.allocator;
    var store: Store = .{};
    defer deinitStore(gpa, &store);

    const a = try openConversation(gpa, &store, "did:plc:aaa", "amy.zat4.com");
    const plain = try appendMessage(gpa, &store, a, .text, "hi", 100, true);
    const withfx = try appendMessage(gpa, &store, a, .text, "hi", 101, true);
    setEffect(&store, @intFromEnum(withfx), 5); // lasers

    const blob = try serializeStore(gpa, &store);
    defer gpa.free(blob);
    var restored = try deserializeStore(gpa, blob);
    defer deinitStore(gpa, &restored);

    // A message sent with lasers that a relaunch forgets is just a message.
    try std.testing.expectEqual(@as(u8, 5), effectOf(&restored, @intFromEnum(withfx)));
    try std.testing.expectEqual(@as(u8, 0), effectOf(&restored, @intFromEnum(plain)));
}

test "store codec v10: the game moves survive a relaunch — they ARE the board" {
    const gpa = std.testing.allocator;
    var store: Store = .{};
    defer deinitStore(gpa, &store);

    const a = try openConversation(gpa, &store, "did:plc:aaa", "amy.zat4.com");
    // Two moves and an ordinary message between them, as a real thread would be.
    const m0 = try appendMessage(gpa, &store, a, .game_move, "", 100, true);
    setGameMove(&store, @intFromEnum(m0), 0x00); // cell 0
    _ = try appendMessage(gpa, &store, a, .text, "your go", 101, true);
    const m1 = try appendMessage(gpa, &store, a, .game_move, "", 102, false);
    setGameMove(&store, @intFromEnum(m1), 0x04); // cell 4

    const blob = try serializeStore(gpa, &store);
    defer gpa.free(blob);
    var restored = try deserializeStore(gpa, blob);
    defer deinitStore(gpa, &restored);

    // The game has no stored state of its own — losing this column would not
    // lose a detail of the game, it would lose the game.
    try std.testing.expectEqual(@as(u8, 0x00), gameMoveOf(&restored, @intFromEnum(m0)));
    try std.testing.expectEqual(@as(u8, 0x04), gameMoveOf(&restored, @intFromEnum(m1)));
    try std.testing.expectEqual(Kind.game_move, restored.msgs.items(.kind)[@intFromEnum(m1)]);
    // A non-game message carries a zero move byte, and its kind says to ignore it.
    try std.testing.expectEqual(@as(u8, 0), gameMoveOf(&restored, 1));
    try std.testing.expect(!isGameKind(restored.msgs.items(.kind)[1]));
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

    // A non-canonical direction byte (unused high bit set). Addressed by POSITION,
    // not by counting back from the end: the tail has grown four times (v3 tombstones,
    // v4 edit marks, v5 conversation flags, v6 the reply column) and every one of
    // those bumps would have silently moved a magic offset onto the wrong byte —
    // where, as it happens, the test would have kept passing for the wrong reason.
    const mine_at = msgs_at + 3 * msg_rec_len; // 3 messages
    bad[mine_at] |= 0x80;
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

    // A v1 blob is a v3 blob minus the v3 tombstone bitset (one byte per 8 msgs)
    // and minus v2's two zero payment counts: strip both and stamp version 1 —
    // byte-identical to what M2 wrote.
    const v3 = try serializeStore(gpa, &store);
    defer gpa.free(v3);
    const v5_tail = versionTailLen(&store); // v3..v10 — see versionTailLen
    const v1 = try gpa.dupe(u8, v3[0 .. v3.len - v5_tail - 8]);
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
    // v3 appends the tombstone bitset AFTER the settlement section, so the
    // payment/settlement records are no longer the tail: step back over it.
    const del_tail = versionTailLen(&store); // v3..v10 — see versionTailLen
    const ref_at = good.len - del_tail - ref_rec_len;
    const pay_at = good.len - del_tail - ref_rec_len - 4 - pay_rec_len;

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
    // Layout after the payment rows: [r_count=0] then the v3..v10 per-record
    // tail. This offset USED TO ignore the tail entirely, so it corrupted tail
    // bytes rather than payment rows and only reached `Malformed` by accident —
    // the test passed without testing what it claimed. Step back over both.
    const row1_at = good.len - versionTailLen(&store) - 4 - pay_rec_len;
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

test "store codec: a message with EMPTY text still restores (a payment with no note)" {
    // The note on a payment is optional, so an empty one is an ordinary thing to
    // send — and an empty text span must round-trip like any other. It is worth a
    // test of its own because the failure is not local: `deserializeStore`
    // rejects the WHOLE blob, so one note-less payment would cost the entire
    // history, which is exactly what must never happen.
    const gpa = std.testing.allocator;
    var store: Store = .{};
    defer deinitStore(gpa, &store);

    const a = try openConversation(gpa, &store, "did:plc:aaa", "amy.zat4.com");
    _ = try appendMessage(gpa, &store, a, .text, "hello", 100, true);
    _ = try appendPayment(gpa, &store, a, .payment_request, 0xCAFE, .lightning, 5000, "", 200, true);

    const blob = try serializeStore(gpa, &store);
    defer gpa.free(blob);
    var restored = try deserializeStore(gpa, blob);
    defer deinitStore(gpa, &restored);

    try std.testing.expectEqual(@as(usize, 2), restored.msgs.len);
    try std.testing.expectEqualStrings("hello", sliceSpan(&restored, restored.msgs.items(.text)[0]));
    try std.testing.expectEqualStrings("", sliceSpan(&restored, restored.msgs.items(.text)[1]));
}

test "groups: a direct chat is the one-member case of the same array" {
    // A2, made checkable. If a direct chat did not carry a member list, every
    // group feature would have to ask which sort of conversation it was looking
    // at before it could do anything — and that question is where the bugs live.
    const gpa = std.testing.allocator;
    var store: Store = .{};
    defer deinitStore(gpa, &store);

    const conv = try openConversation(gpa, &store, "did:plc:alice", "alice.zat4.com");
    try std.testing.expectEqual(@as(u16, 1), memberCount(&store, conv));
    try std.testing.expectEqualStrings("did:plc:alice", memberDid(&store, conv, 0));
    try std.testing.expectEqualStrings("alice.zat4.com", memberHandle(&store, conv, 0));
    try std.testing.expect(!isGroup(&store, conv));
    try std.testing.expectEqualStrings("", groupTitle(&store, conv));

    // The counterparty's message attributes to seat 0 — the same lookup a group
    // uses, against a list with one seat in it.
    const m = try appendMessage(gpa, &store, conv, .text, "hello", 1000, false);
    try std.testing.expectEqual(@as(u16, 0), senderSeat(&store, m));
    try std.testing.expectEqualStrings("did:plc:alice", senderDid(&store, m));

    // And ours attributes to nobody, because the direction bit already said so.
    const mine_msg = try appendMessage(gpa, &store, conv, .text, "hi", 1001, true);
    try std.testing.expectEqual(sender_me, senderSeat(&store, mine_msg));
    try std.testing.expectEqualStrings("", senderDid(&store, mine_msg));
}

test "groups: members are seated, attributed, and survive somebody leaving" {
    const gpa = std.testing.allocator;
    var store: Store = .{};
    defer deinitStore(gpa, &store);

    const conv = try startGroup(
        gpa,
        &store,
        [_]u8{0xA1} ** group_id_len,
        "Weekend",
        &.{ "did:plc:alice", "did:plc:bob" },
        &.{ "alice.zat4.com", "bob.zat4.com" },
    );
    try std.testing.expect(isGroup(&store, conv));
    try std.testing.expectEqualStrings("Weekend", groupTitle(&store, conv));
    try std.testing.expectEqual(@as(u16, 2), memberCount(&store, conv));
    try std.testing.expectEqual(@as(?u16, 0), seatOf(&store, conv, "did:plc:alice"));
    try std.testing.expectEqual(@as(?u16, 1), seatOf(&store, conv, "did:plc:bob"));
    try std.testing.expectEqual(@as(?u16, null), seatOf(&store, conv, "did:plc:nobody"));

    const from_bob = try appendMessage(gpa, &store, conv, .text, "on my way", 2000, false);
    setSenderSeat(&store, from_bob, 1);
    try std.testing.expectEqualStrings("did:plc:bob", senderDid(&store, from_bob));
    try std.testing.expectEqualStrings("bob.zat4.com", senderHandle(&store, from_bob));

    // ALICE LEAVES. Her seat stays, so Bob's message still says Bob. Compacting
    // the list here would slide Bob into seat 0 and quietly re-attribute every
    // word he ever said to her.
    setMemberLeft(&store, conv, 0, true);
    try std.testing.expect(memberLeft(&store, conv, 0));
    try std.testing.expectEqual(@as(u16, 2), memberCount(&store, conv));
    try std.testing.expectEqualStrings("did:plc:bob", senderDid(&store, from_bob));

    // A late joiner takes the next seat, and disturbs nobody.
    const seat = try addMember(gpa, &store, conv, "did:plc:carol", "carol.zat4.com");
    try std.testing.expectEqual(@as(u16, 2), seat);
    try std.testing.expectEqualStrings("did:plc:bob", senderDid(&store, from_bob));
}

test "groups: adding a member does not disturb another conversation's seats" {
    // Members live contiguously per conversation in ONE flat array, so an insert
    // slides every row above it — including other conversations' spans. Get that
    // wrong and a group quietly starts listing somebody else's people.
    const gpa = std.testing.allocator;
    var store: Store = .{};
    defer deinitStore(gpa, &store);

    const first = try startGroup(gpa, &store, [_]u8{0x01} ** group_id_len, "First", &.{"did:plc:alice"}, &.{"alice.zat4.com"});
    const second = try startGroup(gpa, &store, [_]u8{0x02} ** group_id_len, "Second", &.{"did:plc:bob"}, &.{"bob.zat4.com"});
    const direct = try openConversation(gpa, &store, "did:plc:dave", "dave.zat4.com");

    // Insert into the FIRST group, whose span sits below both of the others.
    _ = try addMember(gpa, &store, first, "did:plc:carol", "carol.zat4.com");

    try std.testing.expectEqualStrings("did:plc:alice", memberDid(&store, first, 0));
    try std.testing.expectEqualStrings("did:plc:carol", memberDid(&store, first, 1));
    try std.testing.expectEqualStrings("did:plc:bob", memberDid(&store, second, 0));
    try std.testing.expectEqualStrings("did:plc:dave", memberDid(&store, direct, 0));
    try std.testing.expectEqual(@as(u16, 1), memberCount(&store, second));
    try std.testing.expectEqual(@as(u16, 1), memberCount(&store, direct));
}

test "store codec v11: groups round-trip, and pre-group history is MIGRATED" {
    const gpa = std.testing.allocator;

    // A store with both sorts of conversation in it.
    var store: Store = .{};
    defer deinitStore(gpa, &store);
    const direct = try openConversation(gpa, &store, "did:plc:alice", "alice.zat4.com");
    _ = try appendMessage(gpa, &store, direct, .text, "just us", 100, false);
    const group = try startGroup(gpa, &store, [_]u8{0xB2} ** group_id_len, "Weekend", &.{ "did:plc:bob", "did:plc:carol" }, &.{ "bob.zat4.com", "" });
    const gm = try appendMessage(gpa, &store, group, .text, "all of us", 200, false);
    setSenderSeat(&store, gm, 1);
    setMemberLeft(&store, group, 0, true);

    const blob = try serializeStore(gpa, &store);
    defer gpa.free(blob);
    var back = try deserializeStore(gpa, blob);
    defer deinitStore(gpa, &back);

    try std.testing.expect(!isGroup(&back, direct));
    try std.testing.expectEqualStrings("did:plc:alice", memberDid(&back, direct, 0));
    try std.testing.expect(isGroup(&back, group));
    try std.testing.expectEqualStrings("Weekend", groupTitle(&back, group));
    try std.testing.expectEqual(@as(u16, 2), memberCount(&back, group));
    try std.testing.expect(memberLeft(&back, group, 0));
    try std.testing.expectEqualStrings("did:plc:carol", senderDid(&back, gm));

    // THE MIGRATION. A blob from before groups existed carries no member table,
    // and a restore that shrugged at that would hand back conversations with no
    // participants — worse than a missing column, because every attribution then
    // resolves to nothing.
    //
    // It is forged from a DIRECT-ONLY store, because that is the only thing a v10
    // blob could ever have held: groups did not exist to be written. (Forging it
    // from the store above instead was the first attempt, and the reader rightly
    // refused it — a v10 blob containing a group is not old history, it is a lie
    // about old history, and the pre-v11 path is entitled to assume otherwise.)
    var legacy_src: Store = .{};
    defer deinitStore(gpa, &legacy_src);
    const only = try openConversation(gpa, &legacy_src, "did:plc:alice", "alice.zat4.com");
    _ = try appendMessage(gpa, &legacy_src, only, .text, "just us", 100, false);

    const legacy_blob = try serializeStore(gpa, &legacy_src);
    defer gpa.free(legacy_blob);
    // The v11 tail is: member table + per-conversation block + sender column.
    const v11_tail = 4 + legacy_src.members.len * member_rec_len +
        legacy_src.convs.len * conv_v11_rec_len + 2 * legacy_src.msgs.len;
    std.mem.writeInt(u16, legacy_blob[4..6], 10, .little);
    var legacy = try deserializeStore(gpa, legacy_blob[0 .. legacy_blob.len - v11_tail]);
    defer deinitStore(gpa, &legacy);

    // Every restored conversation has its counterparty seated, and every
    // counterparty message attributes to them.
    try std.testing.expectEqual(@as(u16, 1), memberCount(&legacy, only));
    try std.testing.expectEqualStrings("did:plc:alice", memberDid(&legacy, only, 0));
    try std.testing.expect(!isGroup(&legacy, only));
    try std.testing.expectEqualStrings("did:plc:alice", senderDid(&legacy, @enumFromInt(0)));

    // And a v10 blob whose conversation has no counterparty is still refused —
    // the old invariant did not get weaker, it got scoped to the sort of
    // conversation it was always about.
    var forged = try gpa.dupe(u8, blob);
    defer gpa.free(forged);
    std.mem.writeInt(u16, forged[4..6], 10, .little);
    const forged_tail = 4 + back.members.len * member_rec_len +
        back.convs.len * conv_v11_rec_len + 2 * back.msgs.len;
    try std.testing.expectError(
        error.Malformed,
        deserializeStore(gpa, forged[0 .. forged.len - forged_tail]),
    );
}

test "wire: no two kinds share a first byte" {
    // The comptime block above already fails the BUILD on a duplicate, so this is
    // the record of why it is there rather than the enforcement.
    //
    // `kind_text_fx_wire` and `kind_read_wire` both claimed 11. They are declared
    // a thousand lines apart, they are dispatched off `data[0]` in the same
    // if-chain in `chat_e2ee.zig`, and the receipt is checked first — so EVERY
    // message sent with an effect was lost. Short ones tripped the receipt's
    // `data.len < 9` guard and were dropped without a word; longer ones decoded AS
    // a receipt, so the words vanished and eight bytes of (effect, bubble, text)
    // were stamped in as an i64 read watermark. The sender saw their own local
    // echo and had no way to know.
    var seen = [_]bool{false} ** 256;
    for (wire_kinds) |k| {
        try std.testing.expect(!seen[k]); // a duplicate would have swallowed a feature
        seen[k] = true;
    }

    // The two that collided, named explicitly: a test that only walks the table
    // would still pass if somebody quietly dropped one of them from it.
    try std.testing.expect(kind_text_fx_wire != kind_read_wire);
}

test "group frames: a message says which group it belongs to" {
    // WHY THIS BYTE EXISTS. A group here is N−1 ordinary pairwise sessions, so a
    // group message physically arrives over the private channel with ONE person.
    // Without the id the receiver files it as a DM from them, and the group looks
    // like several private conversations that happen to say the same thing.
    const id = [_]u8{0x7F} ** group_id_len;
    var buf: [64]u8 = undefined;
    const inner = [_]u8{ @intFromEnum(Kind.text), 'h', 'i' };
    const framed = try writeGroupFrame(&buf, id, &inner);

    const back = try parseGroupFrame(framed);
    try std.testing.expectEqualSlices(u8, &id, &back.id);
    try std.testing.expectEqualSlices(u8, &inner, back.inner);

    // The inner bytes are EXACTLY what the same message is in a DM, so every kind
    // that works in a direct chat works in a group with no second encoding.
    try std.testing.expectEqual(Kind.text, try parseKind(back.inner[0]));

    // An empty inner is refused: that is not a message with no text, it is a frame
    // that lost its kind byte, and guessing which kind it meant is how a parser
    // starts inventing messages.
    try std.testing.expectError(error.Malformed, writeGroupFrame(&buf, id, ""));
    try std.testing.expectError(error.Malformed, parseGroupFrame(&id)); // id, nothing after
    try std.testing.expectError(error.Malformed, parseGroupFrame(id[0 .. group_id_len - 1]));
    var tiny: [4]u8 = undefined;
    try std.testing.expectError(error.Malformed, writeGroupFrame(&tiny, id, &inner));
}

test "group frames: a roster survives the wire, and hostile ones do not read past it" {
    const id = [_]u8{0x11} ** group_id_len;
    var buf: [256]u8 = undefined;
    const dids = [_][]const u8{ "did:plc:alice", "did:plc:bob", "did:plc:carol" };
    const framed = try writeGroupMeta(&buf, id, "Weekend", &dids);

    var m = try parseGroupMeta(framed);
    try std.testing.expectEqualSlices(u8, &id, &m.id);
    try std.testing.expectEqualStrings("Weekend", m.title);
    try std.testing.expectEqual(@as(u8, 3), m.claimed);
    for (dids) |want| try std.testing.expectEqualStrings(want, m.next().?);
    try std.testing.expectEqual(@as(?[]const u8, null), m.next());

    // A frame that CLAIMS more than it carries. Believe the walk, not the count —
    // and the walk simply runs out rather than reading past the frame.
    var lying = try gpaLessCopy(&buf, framed.len);
    lying[group_id_len + 1 + "Weekend".len] = 200; // count says 200
    var m2 = try parseGroupMeta(lying);
    try std.testing.expectEqual(@as(u8, 200), m2.claimed);
    var seen: usize = 0;
    while (m2.next() != null) seen += 1;
    try std.testing.expectEqual(@as(usize, 3), seen);

    // A DID length that overruns the frame ends the walk instead of reading past.
    var overrun = try gpaLessCopy(&buf, framed.len);
    overrun[group_id_len + 1 + "Weekend".len + 1] = 255; // first did claims 255 bytes
    var m3 = try parseGroupMeta(overrun);
    try std.testing.expectEqual(@as(?[]const u8, null), m3.next());

    // Truncations are refused rather than half-read.
    try std.testing.expectError(error.Malformed, parseGroupMeta(framed[0 .. group_id_len + 1]));
    try std.testing.expectError(error.Malformed, parseGroupMeta(framed[0..3]));

    // A title or roster too long to describe in one length byte is refused at the
    // WRITE, so a truncated field can never reach the wire in the first place.
    const long_title = [_]u8{'x'} ** 300;
    try std.testing.expectError(error.Malformed, writeGroupMeta(&buf, id, &long_title, &dids));
    const empty_did = [_][]const u8{""};
    try std.testing.expectError(error.Malformed, writeGroupMeta(&buf, id, "t", &empty_did));
}

/// A stack copy of the first `n` bytes of `src`, for tamper tests that must not
/// disturb the original frame.
fn gpaLessCopy(src: []const u8, n: usize) ![]u8 {
    const S = struct {
        var scratch: [256]u8 = undefined;
    };
    if (n > S.scratch.len) return error.Malformed;
    @memcpy(S.scratch[0..n], src[0..n]);
    return S.scratch[0..n];
}

test "groups: a group id resolves to exactly one conversation" {
    const gpa = std.testing.allocator;
    var store: Store = .{};
    defer deinitStore(gpa, &store);

    const id_a = [_]u8{0xA0} ** group_id_len;
    const id_b = [_]u8{0xB0} ** group_id_len;
    const a = try startGroup(gpa, &store, id_a, "A", &.{"did:plc:x"}, &.{""});
    const b = try startGroup(gpa, &store, id_b, "B", &.{"did:plc:y"}, &.{""});
    _ = try openConversation(gpa, &store, "did:plc:z", "z.zat4.com");

    try std.testing.expectEqual(@as(?ConvIndex, a), conversationByGroupId(&store, id_a));
    try std.testing.expectEqual(@as(?ConvIndex, b), conversationByGroupId(&store, id_b));
    // An id nobody has is nobody's — an ordinary answer, not an error (E4). It is
    // what tells the receive path this is an INVITATION rather than a message for
    // a group it already knows.
    try std.testing.expectEqual(@as(?ConvIndex, null), conversationByGroupId(&store, [_]u8{0xCC} ** group_id_len));
    // And a direct chat is never matched, whatever its zeroed id looks like.
    try std.testing.expectEqual(@as(?ConvIndex, null), conversationByGroupId(&store, [_]u8{0} ** group_id_len));
}
