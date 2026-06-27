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

//! B1 classification: CORE (pure). PKCE (RFC 7636) for the atproto OAuth flow:
//! turn 32 bytes of shell-supplied CSPRNG entropy into a `code_verifier`, and
//! derive the S256 `code_challenge = base64url(sha256(verifier))`. No I/O, no
//! clock, no randomness of its own — the entropy is an input (B3). Pure
//! transforms over fixed-size buffers; nothing here allocates (C2).
//!
//! The atproto OAuth profile requires PKCE with method S256 (plain is
//! forbidden). We mint the verifier as base64url of 32 random bytes: 43 ASCII
//! characters, every one in the unreserved set, comfortably inside RFC 7636's
//! 43..128 length window.

const std = @import("std");
const Sha256 = std.crypto.hash.sha2.Sha256;
const b64url = std.base64.url_safe_no_pad;

/// A 32-byte CSPRNG draw encodes to exactly 43 base64url characters with no
/// padding (ceil(32*4/3) = 43). That is both the verifier length and, since
/// sha256 is also 32 bytes, the challenge length.
pub const verifier_len = b64url.Encoder.calcSize(32);
pub const challenge_len = b64url.Encoder.calcSize(Sha256.digest_length);

comptime {
    // The whole design rests on these being 43 (RFC 7636 floor) — assert it so
    // a std base64 change can't silently shift the buffers.
    std.debug.assert(verifier_len == 43);
    std.debug.assert(challenge_len == 43);
}

/// `code_verifier` = base64url(entropy). The caller supplies 32 bytes from the
/// shell CSPRNG; we only encode. Result is unreserved-charset ASCII.
pub fn verifierFromEntropy(entropy: [32]u8) [verifier_len]u8 {
    var out: [verifier_len]u8 = undefined;
    _ = b64url.Encoder.encode(&out, &entropy);
    return out;
}

/// `code_challenge` = base64url(sha256(verifier)), the S256 method. Takes the
/// verifier as bytes (it is ASCII) and returns the 43-char challenge.
pub fn challengeS256(verifier: []const u8) [challenge_len]u8 {
    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(verifier, &digest, .{});
    var out: [challenge_len]u8 = undefined;
    _ = b64url.Encoder.encode(&out, &digest);
    return out;
}

// ---------------------------------------------------------------------------
// Tests (C6) — the RFC 7636 Appendix B golden vector pins both halves: the
// exact octet sequence the RFC encodes into its sample verifier, and the
// S256 challenge that verifier derives. If std base64 or sha256 ever drift,
// this fails immediately.
// ---------------------------------------------------------------------------

const testing = std.testing;

// RFC 7636 Appendix B: the 32 octets of the sample code_verifier.
const rfc_octets = [32]u8{
    116, 24,  223, 180, 151, 153, 224, 37,
    79,  250, 96,  125, 216, 173, 187, 186,
    22,  212, 37,  77,  105, 214, 191, 240,
    91,  88,  5,   88,  83,  132, 141, 121,
};
const rfc_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
const rfc_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

test "pkce: verifierFromEntropy matches the RFC 7636 sample verifier" {
    const v = verifierFromEntropy(rfc_octets);
    try testing.expectEqualStrings(rfc_verifier, &v);
}

test "pkce: challengeS256 matches the RFC 7636 sample challenge" {
    const c = challengeS256(rfc_verifier);
    try testing.expectEqualStrings(rfc_challenge, &c);
}

test "pkce: the challenge of a freshly minted verifier round-trips its own hash" {
    // A non-RFC entropy block: prove the two helpers compose (mint → challenge)
    // and that the challenge equals an independently computed S256 digest.
    const entropy = [_]u8{0xA5} ** 32;
    const v = verifierFromEntropy(entropy);
    const c = challengeS256(&v);

    var digest: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(&v, &digest, .{});
    var expect: [challenge_len]u8 = undefined;
    _ = b64url.Encoder.encode(&expect, &digest);
    try testing.expectEqualStrings(&expect, &c);
    // Every verifier character is in the PKCE unreserved set.
    for (v) |ch| try testing.expect(std.ascii.isAlphanumeric(ch) or ch == '-' or ch == '_');
}
