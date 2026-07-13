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

//! B1 classification: CORE (pure — bytes in, facts out; the shell does the
//! fetching). What a wallet can actually DO.
//!
//! Zat4 does not hold your money, and it does not tell you which wallet to use.
//! The consequence is that different wallets support different things, and the
//! app's behaviour silently changes depending on a choice the user made once and
//! has forgotten. That is the confusion this module exists to end.
//!
//! We ASK the wallet what it can do, at the moment it is added, and we render
//! the answer as a plain table the user signs off on. Afterwards, a feature that
//! is unavailable is drawn as unavailable — attributably, naming the wallet —
//! rather than as a missing or broken part of Zat4.
//!
//! Everything here is derived from the provider's own LNURL-pay document
//! (LUD-06/LUD-16) and its invoice response (LUD-21). No guessing, no
//! hard-coded allow-list of "good" wallets: a wallet nobody has ever heard of
//! gets the same honest interrogation as the three we happen to recommend.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

/// What a Lightning wallet can do for Zat Chat, as its own provider reports it.
///
/// A7: this rides in the store and in per-frame view params; guarded.
pub const Caps = struct {
    /// The smallest / largest a payer may send, in SATS (the provider speaks
    /// millisats; we convert once, here, so nothing downstream has to remember).
    min_sat: u64 = 0,
    max_sat: u64 = 0,
    /// The provider returned a LUD-21 `verify` URL with its invoice, so the
    /// PAYER's client can poll and learn the moment the payment actually
    /// settles. Without it nobody outside the payee's own wallet can observe a
    /// Lightning receipt — which is the entire reason the "Mark received" button
    /// exists, and why it must NAME the wallet rather than sit there unexplained.
    auto_confirm: bool = false,
    /// How many characters of a note the provider will carry INTO the payer's
    /// receipt at the wallet (LUD-12 `commentAllowed`; 0 = none). The note always
    /// shows inside Zat Chat regardless — this is only about whether it also
    /// reaches your wallet's own history.
    comment_max: u16 = 0,
    /// The endpoint answered, is a payRequest, and is willing to receive. False
    /// means the address does not work and must not be published — the case that
    /// used to sail straight through (`connor@strike.me` instead of
    /// `connoravila@strike.me`: a real, valid-LOOKING address that no one owns).
    receivable: bool = false,

    comptime {
        // Budget 24: 2×u64 (16) + u16 + 2 bools, padded to 8-alignment.
        assert(@sizeOf(Caps) == 24);
    }
};

/// The fields we consume from a LUD-06 payRequest document. Everything else the
/// provider sends is ignored.
/// A7.2: cold struct, size guard waived — one per probe, JSON-parse target only.
const PayDoc = struct {
    tag: []const u8 = "",
    callback: []const u8 = "",
    minSendable: u64 = 0,
    maxSendable: u64 = 0,
    commentAllowed: u32 = 0,
    /// LUD-06 error signalling. THE TRAP: a refusal arrives as HTTP **200** with
    /// `{"status":"ERROR","reason":...}` in the BODY. A check that trusts the
    /// status code alone declares a dead address healthy — which is precisely
    /// how a typo'd address got saved and reported as good.
    status: []const u8 = "",
    reason: []const u8 = "",
};

/// The fields we consume from the invoice response.
/// A7.2: cold struct, size guard waived.
const InvoiceDoc = struct {
    pr: []const u8 = "",
    /// LUD-21. Present ⇒ the payer can watch this invoice settle.
    verify: []const u8 = "",
};

pub const ParseError = error{
    /// The body is not JSON we can read.
    Malformed,
    /// The document is not an LNURL-pay endpoint at all.
    NotPayEndpoint,
    /// The provider explicitly refused (`status: ERROR`) — the address does not
    /// resolve to someone who can be paid.
    CannotReceive,
    OutOfMemory,
};

/// Read a provider's payRequest document. `arena` must be an arena (leaky JSON
/// parse). Returns the capabilities it implies, minus `auto_confirm` — that is
/// only knowable from an invoice response (`readInvoice`), because `verify`
/// rides with the invoice and not with the parameters.
///
/// `callback_out` receives the provider's callback URL (arena-owned) so the
/// shell can take the second leg without re-parsing.
pub fn readPayDoc(
    arena: Allocator,
    body: []const u8,
    callback_out: *[]const u8,
) ParseError!Caps {
    const doc = std.json.parseFromSliceLeaky(PayDoc, arena, body, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Malformed,
    };

    // The body-borne refusal, checked BEFORE anything else is believed.
    if (std.ascii.eqlIgnoreCase(doc.status, "ERROR")) return error.CannotReceive;
    if (!std.mem.eql(u8, doc.tag, "payRequest") or doc.callback.len == 0)
        return error.NotPayEndpoint;
    // A provider that will not accept any amount cannot receive, whatever it
    // says about itself.
    if (doc.maxSendable == 0 or doc.maxSendable < doc.minSendable) return error.CannotReceive;

    callback_out.* = doc.callback;
    return .{
        // Millisats → sats, once. A sub-1-sat minimum floors to 1: you cannot
        // send less than a satoshi, and reporting "0" would be a lie.
        .min_sat = @max(1, doc.minSendable / 1000),
        .max_sat = doc.maxSendable / 1000,
        .comment_max = @intCast(@min(doc.commentAllowed, std.math.maxInt(u16))),
        .auto_confirm = false, // decided by readInvoice
        .receivable = true,
    };
}

/// Read an invoice response and fold what it reveals into `caps`. The only fact
/// we want from it is whether the provider offered a LUD-21 `verify` URL — i.e.
/// whether a payment to this wallet can be CONFIRMED by anyone but its owner.
pub fn readInvoice(arena: Allocator, body: []const u8, caps: *Caps) ParseError!void {
    const doc = std.json.parseFromSliceLeaky(InvoiceDoc, arena, body, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        else => return error.Malformed,
    };
    // A provider may refuse at this leg too (same body-borne convention).
    if (doc.pr.len == 0) return error.CannotReceive;
    caps.auto_confirm = doc.verify.len > 0;
}

/// The provider's NAME, for a Lightning address — derived from its domain, so a
/// wallet we have never heard of still gets named rather than reduced to a URL.
/// `connoravila@strike.me` → "Strike". Falls back to the bare domain.
///
/// This exists because the user should be looking at "Strike", not at a string
/// they have to proofread. Writes into `buf`; the result borrows it or `addr`.
pub fn providerName(buf: []u8, addr: []const u8) []const u8 {
    const at = std.mem.indexOfScalar(u8, addr, '@') orelse return addr;
    var domain = addr[at + 1 ..];
    if (domain.len == 0) return addr;
    // Drop a leading "www." and take the registrable label ("strike" of
    // "strike.me", "getalby" of "getalby.com").
    if (std.mem.startsWith(u8, domain, "www.")) domain = domain[4..];
    const dot = std.mem.indexOfScalar(u8, domain, '.') orelse domain.len;
    const label = domain[0..dot];
    if (label.len == 0 or label.len > buf.len) return domain;
    // A few providers whose registrable label is not their name.
    if (std.ascii.eqlIgnoreCase(label, "getalby")) return "Alby";
    if (std.ascii.eqlIgnoreCase(label, "walletofsatoshi")) return "Wallet of Satoshi";
    if (std.ascii.eqlIgnoreCase(label, "livingroomofsatoshi")) return "Wallet of Satoshi";
    // Otherwise: title-case the label. "strike" → "Strike", "coinos" → "Coinos".
    buf[0] = std.ascii.toUpper(label[0]);
    @memcpy(buf[1..label.len], label[1..]);
    return buf[0..label.len];
}

// ---------------------------------------------------------------------------
// Tests — every one of these is a real provider's real answer, captured from
// the live endpoints on 2026-07-12. The point of the module is that we believe
// providers rather than guessing about them, so the fixtures are their words.
// ---------------------------------------------------------------------------

test "Strike: receivable, but CANNOT auto-confirm (no LUD-21 verify)" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const pay_doc =
        \\{"tag":"payRequest","status":"OK","callback":"https://strike.me/api/lnurlp/connoravila/",
        \\"minSendable":1000,"maxSendable":16000000000,"commentAllowed":200}
    ;
    var callback: []const u8 = "";
    var caps = try readPayDoc(arena, pay_doc, &callback);
    try std.testing.expect(caps.receivable);
    try std.testing.expectEqualStrings("https://strike.me/api/lnurlp/connoravila/", callback);
    try std.testing.expectEqual(@as(u64, 1), caps.min_sat);
    try std.testing.expectEqual(@as(u64, 16_000_000), caps.max_sat);
    try std.testing.expectEqual(@as(u16, 200), caps.comment_max);

    // Strike's invoice reply carries `pr` and `routes` — and no `verify`. So a
    // payment to Strike cannot be observed settling by anyone but its owner.
    const inv = "{\"pr\":\"lnbc10u1p49gvll...\",\"routes\":[]}";
    try readInvoice(arena, inv, &caps);
    try std.testing.expect(!caps.auto_confirm);
}

test "Alby: receivable AND auto-confirms (LUD-21 verify present)" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const pay_doc =
        \\{"status":"OK","tag":"payRequest","commentAllowed":255,
        \\"callback":"https://getalby.com/lnurlp/hello/callback",
        \\"minSendable":1000,"maxSendable":100000000000}
    ;
    var callback: []const u8 = "";
    var caps = try readPayDoc(arena, pay_doc, &callback);
    try std.testing.expect(caps.receivable);

    const inv =
        \\{"status":"OK","pr":"lnbc10u1p49gdp9...","routes":[],
        \\"verify":"https://getalby.com/lnurlp/hello/verify/5Km9cgPrHktKFrA6FU8PiZjq"}
    ;
    try readInvoice(arena, inv, &caps);
    try std.testing.expect(caps.auto_confirm);
}

test "the typo trap: a refusal arrives as HTTP 200 with the error in the BODY" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // This is verbatim what strike.me returns for `connor@strike.me` — a
    // plausible, well-formed address that simply belongs to nobody. It comes
    // back 200 OK. Any check that reads the status CODE calls this healthy, and
    // that is exactly how a bad address got saved and reported as good.
    const refusal = "{\"status\":\"ERROR\",\"reason\":\"User can't receive\"}";
    var callback: []const u8 = "";
    try std.testing.expectError(error.CannotReceive, readPayDoc(arena, refusal, &callback));
}

test "a non-payRequest document is refused, not half-believed" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    var callback: []const u8 = "";
    try std.testing.expectError(
        error.NotPayEndpoint,
        readPayDoc(arena, "{\"tag\":\"withdrawRequest\",\"callback\":\"https://x/y\"}", &callback),
    );
    // A provider that accepts no amount cannot receive, whatever it claims.
    try std.testing.expectError(
        error.CannotReceive,
        readPayDoc(arena, "{\"tag\":\"payRequest\",\"callback\":\"https://x/y\",\"maxSendable\":0}", &callback),
    );
    try std.testing.expectError(error.Malformed, readPayDoc(arena, "not json", &callback));
}

test "providerName: the user reads a NAME, never a URL" {
    var buf: [64]u8 = undefined;
    try std.testing.expectEqualStrings("Strike", providerName(&buf, "connoravila@strike.me"));
    try std.testing.expectEqualStrings("Alby", providerName(&buf, "hello@getalby.com"));
    try std.testing.expectEqualStrings("Coinos", providerName(&buf, "coinos@coinos.io"));
    try std.testing.expectEqualStrings("Wallet of Satoshi", providerName(&buf, "x@walletofsatoshi.com"));
    // A wallet nobody has heard of is still NAMED, not reduced to a string —
    // the point of the module is that we do not keep an allow-list of the
    // wallets we approve of.
    try std.testing.expectEqualStrings("Somenewwallet", providerName(&buf, "me@somenewwallet.xyz"));
}
