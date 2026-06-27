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

//! B1 classification: CORE (pure). Compact JWS (RFC 7515) over ES256/P-256 —
//! the signing primitive the DPoP proofs and the OAuth flow are built from.
//! Produces `base64url(header) "." base64url(payload) "." base64url(sig)` and
//! parses one back into its three segments.
//!
//! The signature is **deterministic** (RFC 6979 nonce, no `noise`), so the same
//! key + bytes yield the same token — which makes the whole flow golden-testable
//! and keeps this a pure function (B2/B3: no clock, no randomness of its own;
//! the caller supplies the key and the already-serialized JSON).
//!
//! ⚠️ **Low-S is enforced on the signature.** atproto's verifier rejects high-S
//! signatures (the malleability rule, `core/sigverify.isLowS`). std's ECDSA
//! sign does not canonicalize, so we fold a high-S `s` to `n - s` before
//! encoding — otherwise our own `sigverify`, and the atproto auth server, would
//! reject every proof we mint. This is the inverse of `sigverify`'s check.

const std = @import("std");
const Allocator = std.mem.Allocator;
const b64url = std.base64.url_safe_no_pad;

const P256 = std.crypto.ecc.P256;
const Scheme = std.crypto.sign.ecdsa.EcdsaP256Sha256;

/// The raw size of a P-256 ECDSA signature: r||s, 32 bytes each.
pub const sig_raw_len = 64;

pub const SignError = error{Sign} || Allocator.Error;

/// Sign `header_json` + `payload_json` (already-serialized JSON, caller-owned)
/// into a compact JWS string. `secret_key` is the 32-byte P-256 private scalar
/// (the form `EcdsaP256Sha256.SecretKey.toBytes()` yields). The returned slice
/// is owned by `gpa`. Deterministic: no clock, no randomness.
pub fn signCompact(
    gpa: Allocator,
    header_json: []const u8,
    payload_json: []const u8,
    secret_key: [32]u8,
) SignError![]u8 {
    // 1. The JWS signing input: base64url(header) "." base64url(payload).
    const h_len = b64url.Encoder.calcSize(header_json.len);
    const p_len = b64url.Encoder.calcSize(payload_json.len);
    const s_len = b64url.Encoder.calcSize(sig_raw_len);

    // header "." payload "." sig — two dots between three segments.
    var out = try gpa.alloc(u8, h_len + 1 + p_len + 1 + s_len);
    errdefer gpa.free(out);

    _ = b64url.Encoder.encode(out[0..h_len], header_json);
    out[h_len] = '.';
    _ = b64url.Encoder.encode(out[h_len + 1 ..][0..p_len], payload_json);

    const signing_input = out[0 .. h_len + 1 + p_len];

    // 2. ES256 sign the input, then canonicalize to low-S.
    const sk = Scheme.SecretKey.fromBytes(secret_key) catch return error.Sign;
    const kp = Scheme.KeyPair.fromSecretKey(sk) catch return error.Sign;
    const sig = kp.sign(signing_input, null) catch return error.Sign;
    const raw = lowSCanonical(sig.toBytes());

    // 3. Append "." base64url(sig).
    out[h_len + 1 + p_len] = '.';
    _ = b64url.Encoder.encode(out[h_len + 1 + p_len + 1 ..][0..s_len], &raw);
    return out;
}

/// Fold a P-256 signature's `s` to the low half of the order if it is high-S.
/// `raw` is r||s (64 bytes, big-endian). Mirrors `sigverify.isLowS`: `s` is low
/// iff `s <= n - s`; if not, replace it with `n - s` (same `r`, valid, low-S).
fn lowSCanonical(raw: [sig_raw_len]u8) [sig_raw_len]u8 {
    var out = raw;
    const s_bytes: P256.scalar.CompressedScalar = raw[32..64].*;
    const s = P256.scalar.Scalar.fromBytes(s_bytes, .big) catch return out;
    const s_be = s.toBytes(.big);
    const neg_be = s.neg().toBytes(.big);
    if (std.mem.order(u8, &s_be, &neg_be) == .gt) {
        @memcpy(out[32..64], &neg_be);
    }
    return out;
}

/// The three base64url segments of a compact JWS, still encoded. A view into
/// the caller's token bytes — no copy, no allocation.
/// A7.2: cold struct — one per token parse, never held in quantity. Waived.
pub const Segments = struct {
    header_b64: []const u8,
    payload_b64: []const u8,
    sig_b64: []const u8,
};

pub const ParseError = error{Malformed};

/// Split a compact JWS into its three encoded segments. Validates the shape
/// (exactly two dots, three non-empty parts) but does not decode or verify.
pub fn parse(token: []const u8) ParseError!Segments {
    const d1 = std.mem.indexOfScalar(u8, token, '.') orelse return error.Malformed;
    const rest = token[d1 + 1 ..];
    const d2_rel = std.mem.indexOfScalar(u8, rest, '.') orelse return error.Malformed;
    const header_b64 = token[0..d1];
    const payload_b64 = rest[0..d2_rel];
    const sig_b64 = rest[d2_rel + 1 ..];
    // A JWS must have three parts; a third dot would make the signature segment
    // itself contain a dot, which base64url never does.
    if (header_b64.len == 0 or payload_b64.len == 0 or sig_b64.len == 0) return error.Malformed;
    if (std.mem.indexOfScalar(u8, sig_b64, '.') != null) return error.Malformed;
    return .{ .header_b64 = header_b64, .payload_b64 = payload_b64, .sig_b64 = sig_b64 };
}

/// Decode a base64url segment into `gpa`-owned bytes (header/payload JSON, or
/// the raw signature). Caller frees.
pub fn decodeSegment(gpa: Allocator, segment: []const u8) (ParseError || Allocator.Error)![]u8 {
    const n = b64url.Decoder.calcSizeForSlice(segment) catch return error.Malformed;
    const buf = try gpa.alloc(u8, n);
    errdefer gpa.free(buf);
    b64url.Decoder.decode(buf, segment) catch return error.Malformed;
    return buf;
}

// ---------------------------------------------------------------------------
// Tests (C6). The signature is verified through our own `sigverify.verify`,
// which independently enforces low-S — so a green test proves both that the
// JWS is well-formed AND that the low-S canonicalization is correct (a high-S
// signature would be rejected by sigverify, failing the test).
// ---------------------------------------------------------------------------

const testing = std.testing;
const sigverify = @import("sigverify.zig");

// A deterministic test key (never used for anything real).
fn testKey() Scheme.KeyPair {
    const seed = [_]u8{0x11} ** Scheme.KeyPair.seed_length;
    return Scheme.KeyPair.generateDeterministic(seed) catch unreachable;
}

test "jws: signCompact produces a 3-segment token sigverify accepts (low-S proven)" {
    const kp = testKey();
    const header = "{\"alg\":\"ES256\",\"typ\":\"dpop+jwt\"}";
    const payload = "{\"htm\":\"POST\",\"htu\":\"https://pds.zat4.com/oauth/token\"}";

    const token = try signCompact(testing.allocator, header, payload, kp.secret_key.toBytes());
    defer testing.allocator.free(token);

    const seg = try parse(token);
    // Header / payload round-trip back to the exact JSON we signed.
    const h = try decodeSegment(testing.allocator, seg.header_b64);
    defer testing.allocator.free(h);
    const p = try decodeSegment(testing.allocator, seg.payload_b64);
    defer testing.allocator.free(p);
    try testing.expectEqualStrings(header, h);
    try testing.expectEqualStrings(payload, p);

    // The signature verifies over the signing input under our P-256 verifier,
    // which rejects high-S — so this passing means we emitted low-S.
    const sig = try decodeSegment(testing.allocator, seg.sig_b64);
    defer testing.allocator.free(sig);
    const signing_input = token[0 .. seg.header_b64.len + 1 + seg.payload_b64.len];
    const pub_key = sigverify.PublicKey{
        .curve = .p256,
        .point = kp.public_key.toCompressedSec1(),
    };
    try testing.expect(sigverify.verify(pub_key, signing_input, sig));
}

test "jws: signing is deterministic (same key + bytes → identical token)" {
    const kp = testKey();
    const a = try signCompact(testing.allocator, "{\"a\":1}", "{\"b\":2}", kp.secret_key.toBytes());
    defer testing.allocator.free(a);
    const b = try signCompact(testing.allocator, "{\"a\":1}", "{\"b\":2}", kp.secret_key.toBytes());
    defer testing.allocator.free(b);
    try testing.expectEqualStrings(a, b);
}

test "jws: a tampered payload fails verification" {
    const kp = testKey();
    const token = try signCompact(testing.allocator, "{\"alg\":\"ES256\"}", "{\"sub\":\"a\"}", kp.secret_key.toBytes());
    defer testing.allocator.free(token);
    const seg = try parse(token);
    const sig = try decodeSegment(testing.allocator, seg.sig_b64);
    defer testing.allocator.free(sig);
    const pub_key = sigverify.PublicKey{ .curve = .p256, .point = kp.public_key.toCompressedSec1() };
    // Verify against a DIFFERENT signing input → must be rejected.
    try testing.expect(!sigverify.verify(pub_key, "tampered.input", sig));
}

test "jws: parse rejects malformed tokens" {
    try testing.expectError(error.Malformed, parse("onlyonepart"));
    try testing.expectError(error.Malformed, parse("two.parts"));
    try testing.expectError(error.Malformed, parse("a..c"));
    try testing.expectError(error.Malformed, parse("a.b.c.d"));
}
