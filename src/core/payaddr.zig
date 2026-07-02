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

//! B1 classification: CORE (pure). The payment-address directory's record
//! semantics (ZAT_CHAT_ROADMAP PART II §3, slice A2): what an
//! `app.zat4.pay.address` record MEANS and when it is believed — the
//! record_check idiom, exactly `core/keydir.zig`'s shape. The shell
//! (`shell/pay_addr.zig`) owns JSON and base64; only decoded values cross
//! into here (D3).
//!
//! The record publishes, under the user's DID, where they accept Bitcoin:
//! a Lightning address (LUD-16 `local@domain`) and/or a static on-chain
//! address. v1 addressing decision (§3, recorded): STATIC on-chain address;
//! fresh-per-request (xpub/descriptor) is slice B2 and will ride the same
//! record as a new field — the reuse disclosure is a UI obligation (§6).
//!
//! What `validate` proves before an address may be paid:
//!   1. the record's `did` IS the repo it came from;
//!   2. at least one address is present, and every present address passes
//!      REAL format validation (full bech32/bech32m and base58check
//!      checksums on-chain, LUD-16 shape for lightning) — a typo'd address
//!      is refused at publish AND at fetch, because a typo here is money;
//!   3. the anchor-key binding over (did, createdAt, addresses) verifies
//!      against the EXPECTED anchor — the one the payer's E2EE conversation
//!      already PINS. Payments are in-thread, so the pin always exists: a
//!      compromised PDS can swap the record, but it cannot re-sign it, so
//!      it can never redirect a payment inside an established conversation.
//!      (First-contact trust remains the directory's recorded caveat; a
//!      REPLAYED old record re-signs nothing and can only yield the same
//!      user's earlier addresses — recorded bound, revisited with rotation.)
//! A record that fails ANY check proves nothing and must not be paid (E3).
//!
//! Address validation is mainnet-only by decision (hrp "bc", version bytes
//! 0x00/0x05): Zat4 addresses real value; a test rail would be a deliberate
//! config, not a silent acceptance.

const std = @import("std");
const assert = std.debug.assert;
const Ed25519 = std.crypto.sign.Ed25519;
const Sha256 = std.crypto.hash.sha2.Sha256;
const anchor = @import("anchor.zig");

// ---------------------------------------------------------------------------
// Caps (what keeps signing allocation-free) and the binding label
// ---------------------------------------------------------------------------

/// LUD-16 rides email shape: 64 local + 1 + 253 domain.
pub const max_lightning_len = 318;
/// BIP-173 caps a bech32 string at 90 chars; legacy base58 is shorter.
pub const max_bitcoin_len = 90;
/// RFC3339 UTC seconds ("2026-07-02T00:00:00Z") — the shell stamps it.
pub const max_created_len = 32;

/// Domain separation for the anchor→addresses signature, in the codebase's
/// labeled-signature idiom (anchor.zig's binding_label). Changing this
/// string is a BREAKING change — every published payment record stops
/// verifying — so the pinned-vector test below freezes it.
const binding_label = "Zat4 Pay 1.0 AddressBinding";

const max_msg_len = binding_label.len + 4 * 4 +
    anchor.max_did_len + max_created_len + max_lightning_len + max_bitcoin_len;

pub const BindingError = error{ BadKey, BadSignature, FieldTooLong };

/// The canonical signed message: label ++ len-prefixed(did, createdAt,
/// lightning, bitcoin). Length prefixes (u32 LE) keep multi-field messages
/// unambiguous — "a@b" + "c" can never collide with "a@" + "bc". Absent
/// addresses sign as empty fields, so presence is part of the statement.
fn bindingMessage(
    buf: *[max_msg_len]u8,
    did: []const u8,
    created_at: []const u8,
    lightning: []const u8,
    bitcoin: []const u8,
) BindingError![]const u8 {
    if (did.len > anchor.max_did_len or created_at.len > max_created_len or
        lightning.len > max_lightning_len or bitcoin.len > max_bitcoin_len)
        return error.FieldTooLong;
    var at: usize = 0;
    @memcpy(buf[at..][0..binding_label.len], binding_label);
    at += binding_label.len;
    for ([_][]const u8{ did, created_at, lightning, bitcoin }) |field| {
        std.mem.writeInt(u32, buf[at..][0..4], @intCast(field.len), .little);
        at += 4;
        @memcpy(buf[at..][0..field.len], field);
        at += field.len;
    }
    return buf[0..at];
}

/// anchor → addresses: the `anchorKeySig` the payment record carries. The
/// seed is handed in by the shell (which owns the keystore); the signature
/// itself is deterministic — pure (B2).
pub fn signBinding(
    seed: [anchor.seed_len]u8,
    did: []const u8,
    created_at: []const u8,
    lightning: []const u8,
    bitcoin: []const u8,
) BindingError![anchor.sig_len]u8 {
    var buf: [max_msg_len]u8 = undefined;
    const msg = try bindingMessage(&buf, did, created_at, lightning, bitcoin);
    const kp = Ed25519.KeyPair.generateDeterministic(seed) catch return error.BadKey;
    const sig = kp.sign(msg, null) catch return error.BadKey;
    return sig.toBytes();
}

/// Verify a record's binding against the anchor key the payer already pins.
pub fn verifyBinding(
    anchor_pub: [anchor.pk_len]u8,
    did: []const u8,
    created_at: []const u8,
    lightning: []const u8,
    bitcoin: []const u8,
    sig: []const u8,
) BindingError!void {
    if (sig.len != anchor.sig_len) return error.BadSignature;
    var buf: [max_msg_len]u8 = undefined;
    const msg = try bindingMessage(&buf, did, created_at, lightning, bitcoin);
    const pk = Ed25519.PublicKey.fromBytes(anchor_pub) catch return error.BadKey;
    Ed25519.Signature.fromBytes(sig[0..anchor.sig_len].*).verify(msg, pk) catch
        return error.BadSignature;
}

// ---------------------------------------------------------------------------
// Lightning address (LUD-16): local@domain, the shape wallets resolve to
// an LNURL-pay endpoint. Strict lowercase per the spec.
// ---------------------------------------------------------------------------

pub const AddressError = error{BadAddress};

pub fn validateLightning(addr: []const u8) AddressError!void {
    if (addr.len == 0 or addr.len > max_lightning_len) return error.BadAddress;
    const at = std.mem.indexOfScalar(u8, addr, '@') orelse return error.BadAddress;
    const local = addr[0..at];
    const domain = addr[at + 1 ..];
    if (local.len == 0 or local.len > 64) return error.BadAddress;
    if (std.mem.indexOfScalar(u8, domain, '@') != null) return error.BadAddress;
    for (local) |c| switch (c) {
        'a'...'z', '0'...'9', '-', '_', '.' => {},
        else => return error.BadAddress,
    };
    // Domain: dot-separated LDH labels, at least two (a public host).
    if (domain.len == 0 or domain.len > 253) return error.BadAddress;
    var labels: usize = 0;
    var it = std.mem.splitScalar(u8, domain, '.');
    while (it.next()) |label| {
        if (label.len == 0 or label.len > 63) return error.BadAddress;
        if (label[0] == '-' or label[label.len - 1] == '-') return error.BadAddress;
        for (label) |c| switch (c) {
            'a'...'z', '0'...'9', '-' => {},
            else => return error.BadAddress,
        };
        labels += 1;
    }
    if (labels < 2) return error.BadAddress;
}

// ---------------------------------------------------------------------------
// Bitcoin address — REAL validation, both encodings, mainnet only.
// bech32/bech32m per BIP-173/BIP-350 (segwit v0 and v1+/taproot);
// base58check for legacy P2PKH ("1…") and P2SH ("3…").
// ---------------------------------------------------------------------------

const bech32_charset = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const bech32m_const: u32 = 0x2bc830a3;

fn bech32Polymod(hrp: []const u8, data: []const u8) u32 {
    const gen = [5]u32{ 0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3 };
    var chk: u32 = 1;
    // hrp expansion: high bits, 0, low bits.
    for (hrp) |c| {
        const top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ (c >> 5);
        for (gen, 0..) |g, i| {
            if ((top >> @intCast(i)) & 1 == 1) chk ^= g;
        }
    }
    {
        const top = chk >> 25;
        chk = (chk & 0x1ffffff) << 5;
        for (gen, 0..) |g, i| {
            if ((top >> @intCast(i)) & 1 == 1) chk ^= g;
        }
    }
    for (hrp) |c| {
        const top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ (c & 0x1f);
        for (gen, 0..) |g, i| {
            if ((top >> @intCast(i)) & 1 == 1) chk ^= g;
        }
    }
    for (data) |v| {
        const top = chk >> 25;
        chk = ((chk & 0x1ffffff) << 5) ^ v;
        for (gen, 0..) |g, i| {
            if ((top >> @intCast(i)) & 1 == 1) chk ^= g;
        }
    }
    return chk;
}

/// Validate a segwit address for hrp "bc" (BIP-173 §segwit + BIP-350):
/// charset, case discipline, checksum (bech32 for v0, bech32m for v1+),
/// witness program regrouping and length rules.
fn validateSegwit(addr: []const u8) AddressError!void {
    if (addr.len < 8 or addr.len > 90) return error.BadAddress;
    // All-lower or all-upper, never mixed; decode in lower.
    var has_lower = false;
    var has_upper = false;
    var lower_buf: [90]u8 = undefined;
    for (addr, 0..) |c, i| {
        if (c < 33 or c > 126) return error.BadAddress;
        if (c >= 'a' and c <= 'z') has_lower = true;
        if (c >= 'A' and c <= 'Z') has_upper = true;
        lower_buf[i] = std.ascii.toLower(c);
    }
    if (has_lower and has_upper) return error.BadAddress;
    const s = lower_buf[0..addr.len];

    const sep = std.mem.lastIndexOfScalar(u8, s, '1') orelse return error.BadAddress;
    const hrp = s[0..sep];
    const data_part = s[sep + 1 ..];
    if (!std.mem.eql(u8, hrp, "bc")) return error.BadAddress; // mainnet only (recorded)
    if (data_part.len < 7) return error.BadAddress; // ≥ 1 version + 6 checksum

    var data_buf: [88]u8 = undefined;
    for (data_part, 0..) |c, i| {
        data_buf[i] = @intCast(std.mem.indexOfScalar(u8, bech32_charset, c) orelse
            return error.BadAddress);
    }
    const data = data_buf[0..data_part.len];

    const version = data[0];
    if (version > 16) return error.BadAddress;
    const chk = bech32Polymod(hrp, data);
    const want: u32 = if (version == 0) 1 else bech32m_const; // BIP-350
    if (chk != want) return error.BadAddress;

    // Regroup the program 5→8 bits, strict padding (BIP-173).
    const payload = data[1 .. data.len - 6];
    var acc: u32 = 0;
    var bits: u5 = 0;
    var prog_len: usize = 0;
    for (payload) |v| {
        acc = (acc << 5) | v;
        bits += 5;
        while (bits >= 8) {
            bits -= 8;
            prog_len += 1;
        }
    }
    if (bits >= 5) return error.BadAddress; // over-long padding
    if (acc & (@as(u32, 1) << bits) - 1 != 0) return error.BadAddress; // nonzero padding
    if (prog_len < 2 or prog_len > 40) return error.BadAddress;
    if (version == 0 and prog_len != 20 and prog_len != 32) return error.BadAddress;
}

const base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Validate a legacy address: base58 big-int decode to exactly 25 bytes,
/// double-SHA256 checksum, mainnet version byte 0x00 (P2PKH) / 0x05 (P2SH).
fn validateBase58Check(addr: []const u8) AddressError!void {
    if (addr.len < 26 or addr.len > 35) return error.BadAddress;
    var payload = [_]u8{0} ** 25;
    for (addr) |c| {
        const digit_idx = std.mem.indexOfScalar(u8, base58_alphabet, c) orelse
            return error.BadAddress;
        var carry: u32 = @intCast(digit_idx);
        var i: usize = 25;
        while (i > 0) {
            i -= 1;
            carry += @as(u32, payload[i]) * 58;
            payload[i] = @truncate(carry);
            carry >>= 8;
        }
        if (carry != 0) return error.BadAddress; // longer than 25 bytes
    }
    // Canonical form (what bitcoin-core enforces): leading '1' characters
    // map one-to-one to leading zero BYTES — a padded re-encoding of the
    // same value is refused, not silently accepted.
    var ones: usize = 0;
    while (ones < addr.len and addr[ones] == '1') ones += 1;
    var zeros: usize = 0;
    while (zeros < 25 and payload[zeros] == 0) zeros += 1;
    if (ones != zeros) return error.BadAddress;
    var first = Sha256.init(.{});
    first.update(payload[0..21]);
    var h1: [32]u8 = undefined;
    first.final(&h1);
    var second = Sha256.init(.{});
    second.update(&h1);
    var h2: [32]u8 = undefined;
    second.final(&h2);
    if (!std.mem.eql(u8, payload[21..25], h2[0..4])) return error.BadAddress;
    if (payload[0] != 0x00 and payload[0] != 0x05) return error.BadAddress; // mainnet only
}

/// One entry: any mainnet Bitcoin address a wallet would accept — segwit
/// (bech32/bech32m) or legacy (base58check). Everything else is refused.
pub fn validateBitcoin(addr: []const u8) AddressError!void {
    if (addr.len == 0 or addr.len > max_bitcoin_len) return error.BadAddress;
    const c0 = std.ascii.toLower(addr[0]);
    if (c0 == 'b' and addr.len >= 3 and std.ascii.toLower(addr[1]) == 'c' and addr[2] == '1')
        return validateSegwit(addr);
    return validateBase58Check(addr);
}

// ---------------------------------------------------------------------------
// The record gate (record_check idiom)
// ---------------------------------------------------------------------------

/// The decoded record values, as the shell hands them over (D3: no JSON,
/// no base64 here). A7.2: cold struct, size guard waived — transient
/// parameter carrier, one per fetch.
pub const Record = struct {
    /// The record's own `did` field.
    did: []const u8,
    /// LUD-16 lightning address; empty = the user takes no lightning.
    lightning: []const u8,
    /// Static mainnet address; empty = the user takes no on-chain.
    bitcoin: []const u8,
    /// RFC3339 stamp, part of the signed statement (freshness policy is a
    /// recorded follow-up; v1 verifies, does not enforce age).
    created_at: []const u8,
    /// The anchor-key signature over the binding (decoded).
    anchor_sig: []const u8,
};

pub const ValidateError = error{
    DidMismatch,
    NoAddresses,
    BadLightning,
    BadBitcoin,
    BadBinding,
};

/// The facts a valid record establishes: where this DID accepts payment,
/// as slices borrowed from the record. A7.2: cold struct, size guard
/// waived — transient result.
pub const Payee = struct {
    /// Empty = rail not offered.
    lightning: []const u8,
    bitcoin: []const u8,
};

/// The fetch-side gate (checks 1–3 in the module header). `repo_did` is the
/// repo the record was actually read from; `expected_anchor` is the anchor
/// key the payer's conversation PINS — never one read from the same repo
/// (that would let a PDS vouch for itself).
pub fn validate(
    repo_did: []const u8,
    rec: Record,
    expected_anchor: [anchor.pk_len]u8,
) ValidateError!Payee {
    if (!std.mem.eql(u8, rec.did, repo_did)) return error.DidMismatch;
    if (rec.lightning.len == 0 and rec.bitcoin.len == 0) return error.NoAddresses;
    if (rec.lightning.len > 0)
        validateLightning(rec.lightning) catch return error.BadLightning;
    if (rec.bitcoin.len > 0)
        validateBitcoin(rec.bitcoin) catch return error.BadBitcoin;
    verifyBinding(
        expected_anchor,
        rec.did,
        rec.created_at,
        rec.lightning,
        rec.bitcoin,
        rec.anchor_sig,
    ) catch return error.BadBinding;
    return .{ .lightning = rec.lightning, .bitcoin = rec.bitcoin };
}

// ---------------------------------------------------------------------------
// Tests (B2, C6: nothing here allocates)
// ---------------------------------------------------------------------------

const testing = std.testing;

test "lightning address: LUD-16 shapes pass, junk is refused" {
    try validateLightning("maya@wallet.example");
    try validateLightning("m.aya_2-x@ln.zat4.com");
    const bad = [_][]const u8{
        "", "maya", "@wallet.example", "maya@", "maya@localhost",
        "Maya@wallet.example", // uppercase local (LUD-16 is lowercase)
        "maya@wallet_example.com", // underscore in a hostname
        "maya@-bad.example", "maya@bad-.example", "ma ya@wallet.example",
        "maya@wallet.example@twice",
    };
    for (bad) |b| try testing.expectError(error.BadAddress, validateLightning(b));
}

test "bitcoin address: BIP-173/350 and base58check vectors pass" {
    // Segwit v0 P2WPKH + P2WSH (BIP-173 test vectors), both cases.
    try validateBitcoin("BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4");
    try validateBitcoin("bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4");
    try validateBitcoin("bc1qrp33g0q5c5txsp9arysrx4k6zdkfs4nce4xj0gdcccefvpysxf3qccfmv3");
    // Segwit v1 taproot (BIP-350 test vector, bech32m).
    try validateBitcoin("bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqzk5jj0");
    // Legacy P2PKH (the genesis address) and P2SH.
    try validateBitcoin("1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa");
    try validateBitcoin("3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy");
}

test "bitcoin address: every damage class is refused" {
    const bad = [_][]const u8{
        "",
        // BIP-173 invalid vectors (checksum, mixed case, padding, version).
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5", // bad checksum
        "BC1QW508d6QEJxTDG4y5R3ZArVARY0C5XW7KV8F3t4", // mixed case
        "bc1rw5uspcuh", // short program
        "bc10w508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4w508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4", // version > 16
        "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4x", // over-long
        // A v1 address with the OLD bech32 checksum (BIP-350 must refuse).
        "bc1p0xlxvlhemja6c4dqv22uapctqupfhlxm9h8z3k2e72q4k9hcz7vqh2y7hd",
        // Testnet hrp (mainnet-only decision).
        "tb1qw508d6qejxtdg4y5r3zarvary0c5xw7kxpjzsx",
        // Legacy: flipped char breaks the double-SHA checksum; testnet
        // version byte; base58 forbidden chars.
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNb",
        "mipcBbFg9gMiCh81Kj8tqqdgoZub1ZJRfn",
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7D0vfNa",
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DlvfNa",
    };
    for (bad) |b| testing.expectError(error.BadAddress, validateBitcoin(b)) catch |err| {
        std.debug.print("accepted: {s}\n", .{b});
        return err;
    };
}

const test_seed: [anchor.seed_len]u8 = [_]u8{0x61} ** 32;
const test_did = "did:plc:payaddrtestaaaaaaaaaaaa";
const test_created = "2026-07-02T00:00:00Z";
const test_ln = "maya@wallet.example";
const test_btc = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t4";

fn testRecord() !Record {
    const sig = try signBinding(test_seed, test_did, test_created, test_ln, test_btc);
    // The sig array is copied into a static so the record can borrow it.
    const S = struct {
        var sig_store: [anchor.sig_len]u8 = undefined;
    };
    S.sig_store = sig;
    return .{
        .did = test_did,
        .lightning = test_ln,
        .bitcoin = test_btc,
        .created_at = test_created,
        .anchor_sig = &S.sig_store,
    };
}

test "payaddr: a genuine record passes and yields both rails" {
    const rec = try testRecord();
    const payee = try validate(test_did, rec, try anchor.publicKey(test_seed));
    try testing.expectEqualStrings(test_ln, payee.lightning);
    try testing.expectEqualStrings(test_btc, payee.bitcoin);
}

test "payaddr: every tamper is refused by name" {
    const rec = try testRecord();
    const pk = try anchor.publicKey(test_seed);

    // 1. A record copied into someone else's repo.
    try testing.expectError(error.DidMismatch, validate("did:plc:someoneelse", rec, pk));

    // 2. No addresses at all (signature is irrelevant; nothing to pay).
    var r = rec;
    r.lightning = "";
    r.bitcoin = "";
    try testing.expectError(error.NoAddresses, validate(test_did, r, pk));

    // 3. A malformed address is refused before any crypto.
    r = rec;
    r.lightning = "not-an-address";
    try testing.expectError(error.BadLightning, validate(test_did, r, pk));
    r = rec;
    r.bitcoin = "bc1qw508d6qejxtdg4y5r3zarvary0c5xw7kv8f3t5";
    try testing.expectError(error.BadBitcoin, validate(test_did, r, pk));

    // 4. THE money check — a swapped address breaks the binding: same DID,
    //    valid alternative address, original signature.
    r = rec;
    r.bitcoin = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa";
    try testing.expectError(error.BadBinding, validate(test_did, r, pk));

    // 5. A dropped rail breaks it too (presence is part of the statement).
    r = rec;
    r.lightning = "";
    try testing.expectError(error.BadBinding, validate(test_did, r, pk));

    // 6. A re-stamped createdAt breaks it (the stamp is signed).
    r = rec;
    r.created_at = "2027-01-01T00:00:00Z";
    try testing.expectError(error.BadBinding, validate(test_did, r, pk));

    // 7. A different anchor key (an impostor's record) is refused.
    var wrong = pk;
    wrong[0] ^= 1;
    try testing.expectError(error.BadBinding, validate(test_did, rec, wrong));
}

test "payaddr: the binding label is frozen (pinned vector)" {
    // Deterministic Ed25519 over a fixed statement — if this vector moves,
    // the domain separation or canonical message changed, and every
    // published record just broke. Do not update casually (H3).
    const sig = try signBinding(test_seed, test_did, test_created, test_ln, test_btc);
    const hex = std.fmt.bytesToHex(sig, .lower);
    try testing.expectEqualStrings(
        "01f18844a4e89f5c12771516ddcf021e7d4810d331c1dd7b2f807513203d19a3" ++
            "d08378451e54442d6525f7751b7ed7f400d65d5c5f25b56c12b6d0713ab3d30f",
        &hex,
    );
}

test "payaddr: a one-rail record signs and validates" {
    const sig = try signBinding(test_seed, test_did, test_created, test_ln, "");
    const payee = try validate(test_did, .{
        .did = test_did,
        .lightning = test_ln,
        .bitcoin = "",
        .created_at = test_created,
        .anchor_sig = &sig,
    }, try anchor.publicKey(test_seed));
    try testing.expectEqualStrings(test_ln, payee.lightning);
    try testing.expectEqual(@as(usize, 0), payee.bitcoin.len);
}
