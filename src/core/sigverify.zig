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

//! B1 classification: CORE (pure). Signature verification — the trust math.
//!
//! The sealed crypto-identity module (SECURITY_ROADMAP Phase 3, D1/D2/D3).
//! "Verify, don't trust": given a record's claimed author public key and a
//! signature, decide — by the math, never by a server's word — whether the
//! signature is authentic. Everything wire-format about atproto signatures
//! (curve choice, multikey/multicodec encoding, the low-S malleability rule)
//! is hidden behind this boundary; the rest of the app asks one yes/no
//! question and gets a plain bool back (D3, E4).
//!
//! Pure (B2/B4): deterministic transforms over bytes handed in by the shell.
//! No network, no clock, no allocation — the decoder writes into a stack
//! buffer and the verifier is value-only. The shell resolves a DID document
//! (an SSRF surface — Phase 1, elsewhere) and hands the extracted
//! `publicKeyMultibase` string here; this module never fetches anything.
//!
//! Zero crypto dependencies (F1/F2): both atproto curves —
//!   - secp256k1 (k256): `std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256`
//!   - secp256r1 (p256): `std.crypto.sign.ecdsa.EcdsaP256Sha256`
//! ship in the Zig standard library. The ONE thing std does not give us is the
//! atproto-mandated **low-S** check (its verifier rejects only r/s == 0, not
//! the malleable high-S twin) — so we add it here. That is the single most
//! important atproto-specific crypto rule, and it is on us (Phase 3).

const std = @import("std");
const assert = std.debug.assert;

const Secp256k1Scheme = std.crypto.sign.ecdsa.EcdsaSecp256k1Sha256;
const P256Scheme = std.crypto.sign.ecdsa.EcdsaP256Sha256;
const Secp256k1 = std.crypto.ecc.Secp256k1;
const P256 = std.crypto.ecc.P256;

/// The two ECDSA curves atproto uses for signing keys.
pub const Curve = enum(u8) { k256, p256 };

/// A decoded atproto signing public key: the curve plus its 33-byte compressed
/// SEC1 point (a 0x02/0x03 parity byte followed by the 32-byte x coordinate).
/// Held by value and passed across the module boundary as plain data (A5) —
/// it carries no index and owns no memory.
pub const PublicKey = struct {
    curve: Curve,
    point: [33]u8,

    comptime {
        // Budget: 1-byte curve tag + 33-byte point, alignment 1. This is the
        // per-author key processed once per verified record; keep it tight.
        assert(@sizeOf(PublicKey) == 34);
    }
};

/// Why a `publicKeyMultibase` string could not be turned into a key. These are
/// genuine malformations — a well-formed atproto DID document never produces
/// them; a server that does is lying or corrupted (reject, do not trust).
pub const DecodeError = error{
    NotMultibase, // missing the 'z' base58btc multibase prefix
    BadBase58, // not valid base58btc (or longer than any real key)
    UnsupportedKeyType, // multicodec prefix isn't one of the two atproto curves
    BadKeyLength, // decoded bytes aren't multicodec(2) + compressed point(33)
};

/// An optional `did:key:` scheme prefix we tolerate on the front of a key
/// string, so callers may pass either the bare multibase (`z…`) the DID
/// document's verification method carries, or the full `did:key:z…` form.
const did_key_prefix = "did:key:";

/// Unsigned-varint multicodec prefixes identifying the public-key type, as they
/// appear after base58btc decoding of an atproto multikey.
///   secp256k1-pub = 0xe7  -> varint bytes { 0xe7, 0x01 }
///   p256-pub      = 0x1200 -> varint bytes { 0x80, 0x24 }
const mc_secp256k1_pub = [2]u8{ 0xe7, 0x01 };
const mc_p256_pub = [2]u8{ 0x80, 0x24 };

/// Multicodec prefix (2) + compressed SEC1 point (33).
const multikey_raw_len = 2 + 33;

/// Decode an atproto signing key from its multibase form — the
/// `publicKeyMultibase` value a `Multikey` verification method carries in a DID
/// document (e.g. `zQ3sh…` for k256, `zDna…` for p256), with or without a
/// leading `did:key:`. The encoding is: 'z' (base58btc multibase tag), then
/// base58btc of [multicodec-prefix ++ 33-byte compressed point].
pub fn decodeMultikey(multibase_in: []const u8) DecodeError!PublicKey {
    var s = multibase_in;
    if (std.mem.startsWith(u8, s, did_key_prefix)) s = s[did_key_prefix.len..];
    if (s.len == 0 or s[0] != 'z') return error.NotMultibase;

    // A real atproto multikey decodes to 35 bytes; size the scratch a little
    // larger and let an over-long input fall out as BadBase58 (Overflow).
    var raw: [48]u8 = undefined;
    const n = base58Decode(s[1..], &raw) catch return error.BadBase58;
    if (n != multikey_raw_len) return error.BadKeyLength;

    const prefix = raw[0..2];
    const curve: Curve = if (std.mem.eql(u8, prefix, &mc_secp256k1_pub))
        .k256
    else if (std.mem.eql(u8, prefix, &mc_p256_pub))
        .p256
    else
        return error.UnsupportedKeyType;

    return .{ .curve = curve, .point = raw[2..multikey_raw_len].* };
}

/// Verify an atproto signature. Returns true iff `sig` is a 64-byte raw r‖s
/// ECDSA signature over `message` under `key`, **and** it is low-S — atproto
/// rejects high-S (malleable) signatures, so we do too. A wrong-length sig (a
/// DER encoding is variable-length and never 64), a non-low-S sig, or a sig
/// that simply doesn't verify all return false (E4: a bad signature is an
/// ordinary negative result, not an error to propagate).
///
/// `message` is the original signed bytes (for atproto repo commits, the
/// DAG-CBOR of the unsigned commit node); the scheme hashes it with SHA-256
/// internally, matching atproto's "sign over sha256(bytes)".
pub fn verify(key: PublicKey, message: []const u8, sig: []const u8) bool {
    if (sig.len != 64) return false;
    const sig64: [64]u8 = sig[0..64].*;
    return switch (key.curve) {
        .k256 => verifyScheme(Secp256k1Scheme, Secp256k1, &key.point, message, sig64),
        .p256 => verifyScheme(P256Scheme, P256, &key.point, message, sig64),
    };
}

fn verifyScheme(
    comptime Scheme: type,
    comptime CurveT: type,
    point: []const u8,
    message: []const u8,
    sig64: [64]u8,
) bool {
    const pk = Scheme.PublicKey.fromSec1(point) catch return false;
    const signature = Scheme.Signature.fromBytes(sig64);
    if (!isLowS(CurveT, signature.s)) return false;
    signature.verify(message, pk) catch return false;
    return true;
}

/// The atproto low-S rule, checked order-agnostically: a signature's S value
/// is "low" iff S <= n - S (n = the curve order). Comparing S against its own
/// negation mod n decides this without hardcoding (and risking a typo in) the
/// 32-byte order constant for each curve. A non-canonical S (>= n) can't be
/// reduced to a scalar and is rejected outright.
fn isLowS(comptime CurveT: type, s_bytes: CurveT.scalar.CompressedScalar) bool {
    const s = CurveT.scalar.Scalar.fromBytes(s_bytes, .big) catch return false;
    const s_be = s.toBytes(.big);
    const neg_be = s.neg().toBytes(.big);
    return std.mem.order(u8, &s_be, &neg_be) != .gt;
}

// ---------------------------------------------------------------------------
// base58btc — the Bitcoin alphabet, big-number base conversion. Pure, writes
// into a caller buffer (C1/C2: no hidden allocation). Returns the decoded
// length, or an error if a non-alphabet byte appears or the result would not
// fit the buffer.
// ---------------------------------------------------------------------------

fn base58Decode(input: []const u8, out: []u8) error{ BadBase58, Overflow }!usize {
    var length: usize = 0;
    for (input) |c| {
        var carry: u32 = digitValue(c) orelse return error.BadBase58;
        var i: usize = 0;
        while (i < length) : (i += 1) {
            carry += 58 * @as(u32, out[i]);
            out[i] = @intCast(carry & 0xff);
            carry >>= 8;
        }
        while (carry != 0) {
            if (length >= out.len) return error.Overflow;
            out[length] = @intCast(carry & 0xff);
            length += 1;
            carry >>= 8;
        }
    }
    // Each leading '1' encodes one leading zero byte.
    for (input) |c| {
        if (c != '1') break;
        if (length >= out.len) return error.Overflow;
        out[length] = 0;
        length += 1;
    }
    // The accumulator built the value little-endian; flip to big-endian.
    std.mem.reverse(u8, out[0..length]);
    return length;
}

/// Map a base58btc character to its 0..57 digit value (the Bitcoin alphabet
/// omits 0, O, I and lowercase l). Returns null for any other byte.
fn digitValue(c: u8) ?u8 {
    return switch (c) {
        '1'...'9' => c - '1', //        0..8
        'A'...'H' => c - 'A' + 9, //    9..16   (I omitted)
        'J'...'N' => c - 'J' + 17, //  17..21
        'P'...'Z' => c - 'P' + 22, //  22..32   (O omitted)
        'a'...'k' => c - 'a' + 33, //  33..43   (l omitted)
        'm'...'z' => c - 'm' + 44, //  44..57
        else => null,
    };
}

// ---------------------------------------------------------------------------
// Tests (C6) — the differential test the roadmap calls for: the OFFICIAL
// atproto interop signature vectors, plus self-contained malleability tests.
// ---------------------------------------------------------------------------

const testing = std.testing;

/// One atproto interop vector, from
/// bluesky-social/atproto interop-test-files/crypto/signature-fixtures.json.
/// We feed `did` (the did:key form, which equals the live `Multikey`
/// publicKeyMultibase encoding) through `decodeMultikey`, then `verify`.
const Vector = struct {
    // A7.2: cold struct — a comptime test fixture, never in a hot loop. Waived.
    comment: []const u8,
    did: []const u8,
    msg_b64: []const u8,
    sig_b64: []const u8,
    expect_valid: bool,
};

const interop_vectors = [_]Vector{
    .{
        .comment = "valid P-256, low-S",
        .did = "did:key:zDnaembgSGUhZULN2Caob4HLJPaxBh92N7rtH21TErzqf8HQo",
        .msg_b64 = "oWVoZWxsb2V3b3JsZA",
        .sig_b64 = "2vZNsG3UKvvO/CDlrdvyZRISOFylinBh0Jupc6KcWoJWExHptCfduPleDbG3rko3YZnn9Lw0IjpixVmexJDegg",
        .expect_valid = true,
    },
    .{
        .comment = "valid K-256, low-S",
        .did = "did:key:zQ3shqwJEJyMBsBXCWyCBpUBMqxcon9oHB7mCvx4sSpMdLJwc",
        .msg_b64 = "oWVoZWxsb2V3b3JsZA",
        .sig_b64 = "5WpdIuEUUfVUYaozsi8G0B3cWO09cgZbIIwg1t2YKdUn/FEznOndsz/qgiYb89zwxYCbB71f7yQK5Lr7NasfoA",
        .expect_valid = true,
    },
    .{
        .comment = "P-256 high-S, invalid in atproto",
        .did = "did:key:zDnaembgSGUhZULN2Caob4HLJPaxBh92N7rtH21TErzqf8HQo",
        .msg_b64 = "oWVoZWxsb2V3b3JsZA",
        .sig_b64 = "2vZNsG3UKvvO/CDlrdvyZRISOFylinBh0Jupc6KcWoKp7O4VS9giSAah8k5IUbXIW00SuOrjfEqQ9HEkN9JGzw",
        .expect_valid = false,
    },
    .{
        .comment = "K-256 high-S, invalid in atproto",
        .did = "did:key:zQ3shqwJEJyMBsBXCWyCBpUBMqxcon9oHB7mCvx4sSpMdLJwc",
        .msg_b64 = "oWVoZWxsb2V3b3JsZA",
        .sig_b64 = "5WpdIuEUUfVUYaozsi8G0B3cWO09cgZbIIwg1t2YKdXYA67MYxYiTMAVfdnkDCMN9S5B3vHosRe07aORmoshoQ",
        .expect_valid = false,
    },
    .{
        .comment = "P-256 DER-encoded, invalid in atproto",
        .did = "did:key:zDnaeT6hL2RnTdUhAPLij1QBkhYZnmuKyM7puQLW1tkF4Zkt8",
        .msg_b64 = "oWVoZWxsb2V3b3JsZA",
        .sig_b64 = "MEQCIFxYelWJ9lNcAVt+jK0y/T+DC/X4ohFZ+m8f9SEItkY1AiACX7eXz5sgtaRrz/SdPR8kprnbHMQVde0T2R8yOTBweA",
        .expect_valid = false,
    },
    .{
        .comment = "K-256 DER-encoded, invalid in atproto",
        .did = "did:key:zQ3shnriYMXc8wvkbJqfNWh5GXn2bVAeqTC92YuNbek4npqGF",
        .msg_b64 = "oWVoZWxsb2V3b3JsZA",
        .sig_b64 = "MEUCIQCWumUqJqOCqInXF7AzhIRg2MhwRz2rWZcOEsOjPmNItgIgXJH7RnqfYY6M0eg33wU0sFYDlprwdOcpRn78Sz5ePgk",
        .expect_valid = false,
    },
};

test "interop: atproto signature fixtures (both curves; low-S/high-S/DER)" {
    const dec = std.base64.standard_no_pad.Decoder;
    for (interop_vectors) |v| {
        const key = try decodeMultikey(v.did);

        var msg: [64]u8 = undefined;
        const msg_len = try dec.calcSizeForSlice(v.msg_b64);
        try dec.decode(msg[0..msg_len], v.msg_b64);

        var sig: [80]u8 = undefined; // 64 raw, up to ~72 for the DER cases
        const sig_len = try dec.calcSizeForSlice(v.sig_b64);
        try dec.decode(sig[0..sig_len], v.sig_b64);

        const got = verify(key, msg[0..msg_len], sig[0..sig_len]);
        try testing.expectEqual(v.expect_valid, got);
    }
}

test "decodeMultikey: curve detection + compressed-point shape" {
    const k = try decodeMultikey("did:key:zQ3shqwJEJyMBsBXCWyCBpUBMqxcon9oHB7mCvx4sSpMdLJwc");
    try testing.expectEqual(Curve.k256, k.curve);
    try testing.expect(k.point[0] == 0x02 or k.point[0] == 0x03);

    // Bare multibase (no did:key: prefix) decodes identically.
    const bare = try decodeMultikey("zQ3shqwJEJyMBsBXCWyCBpUBMqxcon9oHB7mCvx4sSpMdLJwc");
    try testing.expectEqualSlices(u8, &k.point, &bare.point);

    const p = try decodeMultikey("did:key:zDnaembgSGUhZULN2Caob4HLJPaxBh92N7rtH21TErzqf8HQo");
    try testing.expectEqual(Curve.p256, p.curve);
    try testing.expect(p.point[0] == 0x02 or p.point[0] == 0x03);
}

test "decodeMultikey: malformed inputs are rejected, not trusted" {
    try testing.expectError(error.NotMultibase, decodeMultikey(""));
    try testing.expectError(error.NotMultibase, decodeMultikey("Q3shqwJ")); // no 'z'
    try testing.expectError(error.BadBase58, decodeMultikey("z0OIl")); // alphabet holes
    // A 'z' + valid base58 that decodes to the wrong length / unknown codec.
    try testing.expectError(error.BadKeyLength, decodeMultikey("zabc"));
}

// Self-contained malleability proof: sign a message, then derive the two S
// values (s and n-s). Exactly one is low-S. Our verify must ACCEPT the low-S
// signature and REJECT its high-S twin — while std's own verifier accepts
// BOTH, proving the rejection is purely our added low-S policy.
fn malleabilityCase(comptime Scheme: type, comptime CurveT: type) !void {
    const seed = [_]u8{7} ** Scheme.KeyPair.seed_length;
    const kp = try Scheme.KeyPair.generateDeterministic(seed);
    const msg = "zat4 signature malleability vector";
    const sig = try kp.sign(msg, null);

    const key = PublicKey{ .curve = curveTag(CurveT), .point = kp.public_key.toCompressedSec1() };

    // The malleable twin: same r, negated s.
    const neg_s = try CurveT.scalar.neg(sig.s, .big);
    var twin = sig;
    twin.s = neg_s;

    const a = verify(key, msg, &sig.toBytes());
    const b = verify(key, msg, &twin.toBytes());
    // Exactly one of the twins is accepted (the low-S one), never both/neither.
    try testing.expect(a != b);

    // Sanity: std accepts both encodings — only our low-S gate separates them.
    try testing.expectEqual({}, try sig.verify(msg, kp.public_key));
    try testing.expectEqual({}, try twin.verify(msg, kp.public_key));

    // A flipped message verifies under neither.
    try testing.expect(!verify(key, "tampered", &sig.toBytes()));
    try testing.expect(!verify(key, "tampered", &twin.toBytes()));
}

fn curveTag(comptime CurveT: type) Curve {
    return if (CurveT == Secp256k1) .k256 else .p256;
}

test "low-S: high-S twin rejected though std accepts it (both curves)" {
    try malleabilityCase(Secp256k1Scheme, Secp256k1);
    try malleabilityCase(P256Scheme, P256);
}

test "verify: wrong key rejects a good signature" {
    const seedA = [_]u8{3} ** P256Scheme.KeyPair.seed_length;
    const seedB = [_]u8{9} ** P256Scheme.KeyPair.seed_length;
    const kpA = try P256Scheme.KeyPair.generateDeterministic(seedA);
    const kpB = try P256Scheme.KeyPair.generateDeterministic(seedB);
    const msg = "authentic under A only";
    const sig = try kpA.sign(msg, null);

    const keyB = PublicKey{ .curve = .p256, .point = kpB.public_key.toCompressedSec1() };
    try testing.expect(!verify(keyB, msg, &sig.toBytes()));
}

test "fuzz: decodeMultikey + verify tolerate arbitrary bytes (no crash)" {
    const fuzzgen = @import("fuzzgen.zig");
    var g = fuzzgen.Gen.init(0x51A);
    var buf: [256]u8 = undefined;
    const seeds = [_][]const u8{
        "did:key:zQ3shqwJEJyMBsBXCWyCBpUBMqxcon9oHB7mCvx4sSpMdLJwc", "zDnaem", "z", "did:key:z",
    };
    const fixed_key = decodeMultikey("did:key:zQ3shqwJEJyMBsBXCWyCBpUBMqxcon9oHB7mCvx4sSpMdLJwc") catch unreachable;
    var i: usize = 0;
    while (i < 4000) : (i += 1) {
        const input = g.next(&buf, &seeds, "did:key:zQ3shDna234567ABCabc", i);
        _ = decodeMultikey(input) catch {};
        // arbitrary bytes as both message and signature — must never crash.
        _ = verify(fixed_key, input, input);
    }
}
