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

//! B1 classification: CORE (pure). The payment hand-off URIs (ZAT_CHAT_
//! ROADMAP PART II §0/§9, slice A3): the standard strings that carry a
//! payment from a Zat4 card into the user's OWN wallet —
//!
//!   on-chain    BIP-21   bitcoin:<address>?amount=<btc>[&label=…][&message=…]
//!   lightning   LUD-16   lightning:<local@domain>
//!
//! Handling these URIs is table stakes for every Bitcoin and Lightning
//! wallet, so this one seam supports essentially all of them with no
//! per-wallet integration (§2). The shell (`shell/launch.zig`) opens the
//! URI; this module only builds bytes — same inputs, same string (B2).
//!
//! Addresses are re-validated here through `core/payaddr.zig` before they
//! enter a URI (one rule source, D3): a malformed address can never reach
//! a wallet, no matter which caller built the card.
//!
//! HONESTY NOTE, recorded (amends the A3 sketch): neither URI scheme
//! defines a RETURN channel — no callback hands back a preimage or txid,
//! on any platform. Settlement is observed elsewhere by design: on-chain
//! by the confirmation-watcher (A5) watching the ADDRESS for the expected
//! amount, lightning by the payee's client sending the settled event (the
//! wire byte 18) when their wallet shows receipt. The `lightning:` URI
//! carries no amount either — a LUD-16 address lets the PAYER's wallet
//! pick the amount, so the wallet prompts and the payer confirms the sum
//! there (one more reason the approval genuinely happens in the wallet).
//! An exact-amount BOLT11 invoice flow is a recorded later enhancement.

const std = @import("std");
const assert = std.debug.assert;
const payaddr = @import("payaddr.zig");

pub const UriError = error{ TooLong, BadAddress, NoteTooLong };

/// Pre-encoding cap on label/message text (percent-encoding can triple it;
/// wallets truncate long URIs unpredictably, so we bound our side).
pub const max_text_len = 512;

/// A comfortable caller buffer: address + amount + two encoded texts.
pub const max_uri_len = 8 + payaddr.max_bitcoin_len + 8 + 24 +
    2 * (9 + 3 * max_text_len);

/// Append-only cursor over a caller buffer — the allocation-free builder.
const Cursor = struct {
    buf: []u8,
    len: usize = 0,

    comptime {
        // Budget 24: slice (16) + usize (8). Transient, but guarded — the
        // ambiguity rule says a struct is hot until proven cold. (A7)
        assert(@sizeOf(Cursor) == 24);
    }

    fn put(c: *Cursor, s: []const u8) UriError!void {
        if (c.len + s.len > c.buf.len) return error.TooLong;
        @memcpy(c.buf[c.len..][0..s.len], s);
        c.len += s.len;
    }

    /// RFC 3986 percent-encoding: unreserved bytes pass, everything else
    /// (including UTF-8 continuation bytes) becomes %XX uppercase.
    fn putEncoded(c: *Cursor, s: []const u8) UriError!void {
        for (s) |b| switch (b) {
            'A'...'Z', 'a'...'z', '0'...'9', '-', '.', '_', '~' => {
                if (c.len + 1 > c.buf.len) return error.TooLong;
                c.buf[c.len] = b;
                c.len += 1;
            },
            else => {
                if (c.len + 3 > c.buf.len) return error.TooLong;
                c.buf[c.len] = '%';
                const hex = "0123456789ABCDEF";
                c.buf[c.len + 1] = hex[b >> 4];
                c.buf[c.len + 2] = hex[b & 0xF];
                c.len += 3;
            },
        };
    }

    fn slice(c: *const Cursor) []const u8 {
        return c.buf[0..c.len];
    }
};

/// Sats → the BIP-21 decimal BTC string: integer math only, trailing
/// zeros trimmed, no fraction dot when whole ("21000000", "1.5",
/// "0.00000001"). `buf` needs at most 17 bytes (8 whole + '.' + 8 frac).
pub fn formatBtcAmount(buf: *[17]u8, amount_sat: u64) []const u8 {
    const whole = amount_sat / 100_000_000;
    const frac = amount_sat % 100_000_000;
    if (frac == 0)
        return std.fmt.bufPrint(buf, "{d}", .{whole}) catch unreachable;
    const s = std.fmt.bufPrint(buf, "{d}.{d:0>8}", .{ whole, frac }) catch unreachable;
    var end = s.len;
    while (buf[end - 1] == '0') end -= 1; // frac was nonzero: never eats the dot
    return s[0..end];
}

/// The on-chain hand-off: `bitcoin:<address>?amount=<btc>` with optional
/// `label` (who) and `message` (the note), both percent-encoded. The
/// address is checksum-validated before it enters the string (E3).
pub fn buildBitcoinUri(
    buf: []u8,
    address: []const u8,
    amount_sat: u64,
    label: []const u8,
    message: []const u8,
) UriError![]const u8 {
    payaddr.validateBitcoin(address) catch return error.BadAddress;
    if (label.len > max_text_len or message.len > max_text_len) return error.NoteTooLong;
    assert(amount_sat >= 1);
    var c = Cursor{ .buf = buf };
    try c.put("bitcoin:");
    try c.put(address);
    try c.put("?amount=");
    var amt_buf: [17]u8 = undefined;
    try c.put(formatBtcAmount(&amt_buf, amount_sat));
    if (label.len > 0) {
        try c.put("&label=");
        try c.putEncoded(label);
    }
    if (message.len > 0) {
        try c.put("&message=");
        try c.putEncoded(message);
    }
    return c.slice();
}

/// The lightning hand-off: `lightning:<local@domain>` (LUD-16). The
/// address charset is already URI-safe once validated; no params ride
/// along — the payer's wallet resolves LNURL-pay and prompts for the
/// amount (module header's honesty note).
pub fn buildLightningUri(buf: []u8, address: []const u8) UriError![]const u8 {
    payaddr.validateLightning(address) catch return error.BadAddress;
    var c = Cursor{ .buf = buf };
    try c.put("lightning:");
    try c.put(address);
    return c.slice();
}

// ---------------------------------------------------------------------------
// Tests (B2, C6: nothing here allocates)
// ---------------------------------------------------------------------------

const testing = std.testing;

test "formatBtcAmount: integer math, trimmed, dot only when needed" {
    var buf: [17]u8 = undefined;
    try testing.expectEqualStrings("0.00000001", formatBtcAmount(&buf, 1));
    try testing.expectEqualStrings("0.00021", formatBtcAmount(&buf, 21_000));
    try testing.expectEqualStrings("1", formatBtcAmount(&buf, 100_000_000));
    try testing.expectEqualStrings("1.5", formatBtcAmount(&buf, 150_000_000));
    try testing.expectEqualStrings("0.1", formatBtcAmount(&buf, 10_000_000));
    try testing.expectEqualStrings("21000000", formatBtcAmount(&buf, 2_100_000_000_000_000));
    try testing.expectEqualStrings("0", formatBtcAmount(&buf, 0)); // callers assert ≥1; the formatter is total
}

test "buildBitcoinUri: golden strings, encoding, and refusals" {
    var buf: [max_uri_len]u8 = undefined;
    const addr = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

    try testing.expectEqualStrings(
        "bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4?amount=0.00021",
        try buildBitcoinUri(&buf, addr, 21_000, "", ""),
    );
    try testing.expectEqualStrings(
        "bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4?amount=0.00005" ++
            "&label=maya.zat4.com&message=dinner%20split%20%F0%9F%8D%9C",
        try buildBitcoinUri(&buf, addr, 5_000, "maya.zat4.com", "dinner split 🍜"),
    );
    // Reserved characters in the note are neutralized, not passed through.
    const tricky = try buildBitcoinUri(&buf, addr, 1, "", "a&b=c?d#e");
    try testing.expectEqualStrings(
        "bitcoin:bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4?amount=0.00000001" ++
            "&message=a%26b%3Dc%3Fd%23e",
        tricky,
    );
    // A bad address never reaches a URI, whatever the caller believed.
    try testing.expectError(error.BadAddress, buildBitcoinUri(&buf, "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", 1, "", ""));
    // Over-cap text and an under-sized buffer are named errors, not cuts.
    const long = [_]u8{'x'} ** (max_text_len + 1);
    try testing.expectError(error.NoteTooLong, buildBitcoinUri(&buf, addr, 1, "", &long));
    var tiny: [16]u8 = undefined;
    try testing.expectError(error.TooLong, buildBitcoinUri(&tiny, addr, 1, "", ""));
}

test "buildLightningUri: golden string and refusal" {
    var buf: [max_uri_len]u8 = undefined;
    try testing.expectEqualStrings(
        "lightning:maya@wallet.example",
        try buildLightningUri(&buf, "maya@wallet.example"),
    );
    try testing.expectError(error.BadAddress, buildLightningUri(&buf, "not-an-address"));
}
