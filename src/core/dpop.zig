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

//! B1 classification: CORE (pure). Builds a DPoP proof JWT (RFC 9449) for the
//! atproto OAuth flow: a compact JWS whose header carries the device's public
//! key as a JWK and whose claims bind the proof to one request.
//!
//!   header: {"typ":"dpop+jwt","alg":"ES256","jwk":{EC P-256 public key}}
//!   claims: {jti, htm, htu, iat[, nonce][, ath]}
//!
//! Pure: the clock (`iat`), the unique id (`jti`), and the server `nonce` are
//! all shell inputs (B3) — this module only serializes and signs. The signing
//! key is the 32-byte P-256 private scalar; the public JWK coordinates are
//! derived from it here, so the caller passes only the secret. `ath` (when an
//! access token is supplied) is `base64url(sha256(token))`, binding the proof
//! to that token. Signing (and its low-S canonicalization) lives in `jws`.

const std = @import("std");
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const b64url = std.base64.url_safe_no_pad;
const jws = @import("jws.zig");

const Scheme = std.crypto.sign.ecdsa.EcdsaP256Sha256;

/// The per-request inputs to a DPoP proof. Plain data (A1); the clock/id/nonce
/// come from the shell. A7.2: cold struct — one per outgoing request, built and
/// consumed immediately, never held in quantity. Waived.
pub const Params = struct {
    /// The 32-byte P-256 private scalar (the device's DPoP key).
    secret_key: [32]u8,
    /// The HTTP method of the request this proof authorizes, e.g. "POST".
    htm: []const u8,
    /// The HTTP target URI, without query or fragment (RFC 9449 §4.2).
    htu: []const u8,
    /// Issued-at, unix seconds — from the shell clock (B3).
    iat: i64,
    /// A unique, unguessable id for this proof — from the shell CSPRNG (B3).
    jti: []const u8,
    /// The server-issued DPoP nonce, once we have one (omitted on first contact).
    nonce: ?[]const u8 = null,
    /// The access token this proof is bound to; present → adds the `ath` claim.
    access_token: ?[]const u8 = null,
};

pub const BuildError = jws.SignError;

/// Build and sign a DPoP proof. Returns the compact JWS, owned by `gpa`.
pub fn buildProof(gpa: Allocator, p: Params) BuildError![]u8 {
    // Derive the public JWK coordinates from the secret key. Uncompressed SEC1
    // is 0x04 || x(32) || y(32); the JWK wants x and y base64url-encoded.
    const sk = Scheme.SecretKey.fromBytes(p.secret_key) catch return error.Sign;
    const kp = Scheme.KeyPair.fromSecretKey(sk) catch return error.Sign;
    const sec1 = kp.public_key.toUncompressedSec1(); // [65]u8
    var x_b64: [43]u8 = undefined;
    var y_b64: [43]u8 = undefined;
    _ = b64url.Encoder.encode(&x_b64, sec1[1..33]);
    _ = b64url.Encoder.encode(&y_b64, sec1[33..65]);

    // Header: typ/alg then the embedded JWK (members in RFC 7638 lexicographic
    // order — harmless, and matches how a thumbprint would canonicalize it).
    var header: std.ArrayListUnmanaged(u8) = .empty;
    defer header.deinit(gpa);
    try header.appendSlice(gpa, "{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"");
    try header.appendSlice(gpa, &x_b64);
    try header.appendSlice(gpa, "\",\"y\":\"");
    try header.appendSlice(gpa, &y_b64);
    try header.appendSlice(gpa, "\"}}");

    // Claims.
    var claims: std.ArrayListUnmanaged(u8) = .empty;
    defer claims.deinit(gpa);
    try claims.appendSlice(gpa, "{\"htm\":");
    try appendJsonString(&claims, gpa, p.htm);
    try claims.appendSlice(gpa, ",\"htu\":");
    try appendJsonString(&claims, gpa, p.htu);
    try claims.appendSlice(gpa, ",\"iat\":");
    try claims.print(gpa, "{d}", .{p.iat});
    try claims.appendSlice(gpa, ",\"jti\":");
    try appendJsonString(&claims, gpa, p.jti);
    if (p.nonce) |n| {
        try claims.appendSlice(gpa, ",\"nonce\":");
        try appendJsonString(&claims, gpa, n);
    }
    if (p.access_token) |tok| {
        var digest: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(tok, &digest, .{});
        var ath: [43]u8 = undefined;
        _ = b64url.Encoder.encode(&ath, &digest);
        try claims.appendSlice(gpa, ",\"ath\":");
        try appendJsonString(&claims, gpa, &ath);
    }
    try claims.append(gpa, '}');

    return jws.signCompact(gpa, header.items, claims.items, p.secret_key);
}

/// Append a JSON string literal (quoted, with the mandatory escapes). The DPoP
/// values are URLs/ids/methods — rarely needing escapes — but correctness is
/// cheap and a stray quote must never break the JSON.
fn appendJsonString(list: *std.ArrayListUnmanaged(u8), gpa: Allocator, s: []const u8) Allocator.Error!void {
    try list.append(gpa, '"');
    for (s) |c| switch (c) {
        '"' => try list.appendSlice(gpa, "\\\""),
        '\\' => try list.appendSlice(gpa, "\\\\"),
        0x08 => try list.appendSlice(gpa, "\\b"),
        0x0C => try list.appendSlice(gpa, "\\f"),
        '\n' => try list.appendSlice(gpa, "\\n"),
        '\r' => try list.appendSlice(gpa, "\\r"),
        '\t' => try list.appendSlice(gpa, "\\t"),
        else => if (c < 0x20) {
            try list.print(gpa, "\\u{x:0>4}", .{c});
        } else {
            try list.append(gpa, c);
        },
    };
    try list.append(gpa, '"');
}

// ---------------------------------------------------------------------------
// Tests (C6). Build a proof with a deterministic key + fixed shell inputs,
// then: parse the JWS, reconstruct the public key FROM the embedded JWK, and
// verify the signature through `sigverify` (which enforces low-S). A green run
// proves the proof is well-formed, the JWK matches the signing key, and the
// signature is valid + low-S — the full DPoP contract.
// ---------------------------------------------------------------------------

const testing = std.testing;
const sigverify = @import("sigverify.zig");

fn testSecret() [32]u8 {
    const seed = [_]u8{0x22} ** Scheme.KeyPair.seed_length;
    const kp = Scheme.KeyPair.generateDeterministic(seed) catch unreachable;
    return kp.secret_key.toBytes();
}

test "dpop: proof is a valid JWS whose embedded JWK verifies the signature" {
    const secret = testSecret();
    const token = try buildProof(testing.allocator, .{
        .secret_key = secret,
        .htm = "POST",
        .htu = "https://pds.zat4.com/oauth/token",
        .iat = 1_750_000_000,
        .jti = "abc123-unique",
    });
    defer testing.allocator.free(token);

    const seg = try jws.parse(token);
    const header = try jws.decodeSegment(testing.allocator, seg.header_b64);
    defer testing.allocator.free(header);

    // Reconstruct the public key from the header JWK's x/y.
    const parsed = try std.json.parseFromSlice(std.json.Value, testing.allocator, header, .{});
    defer parsed.deinit();
    const jwk = parsed.value.object.get("jwk").?.object;
    try testing.expectEqualStrings("dpop+jwt", parsed.value.object.get("typ").?.string);
    try testing.expectEqualStrings("ES256", parsed.value.object.get("alg").?.string);
    try testing.expectEqualStrings("EC", jwk.get("kty").?.string);
    try testing.expectEqualStrings("P-256", jwk.get("crv").?.string);

    var xy: [65]u8 = undefined;
    xy[0] = 0x04;
    try b64url.Decoder.decode(xy[1..33], jwk.get("x").?.string);
    try b64url.Decoder.decode(xy[33..65], jwk.get("y").?.string);
    const pk = try Scheme.PublicKey.fromSec1(&xy);
    const pub_key = sigverify.PublicKey{ .curve = .p256, .point = pk.toCompressedSec1() };

    const sig = try jws.decodeSegment(testing.allocator, seg.sig_b64);
    defer testing.allocator.free(sig);
    const signing_input = token[0 .. seg.header_b64.len + 1 + seg.payload_b64.len];
    try testing.expect(sigverify.verify(pub_key, signing_input, sig));
}

test "dpop: claims carry htm/htu/iat/jti, and nonce/ath only when supplied" {
    const secret = testSecret();

    // Minimal proof: no nonce, no ath.
    const bare = try buildProof(testing.allocator, .{
        .secret_key = secret,
        .htm = "GET",
        .htu = "https://pds.zat4.com/xrpc/app.bsky.feed.getTimeline",
        .iat = 1_750_000_123,
        .jti = "id-1",
    });
    defer testing.allocator.free(bare);
    {
        const seg = try jws.parse(bare);
        const claims = try jws.decodeSegment(testing.allocator, seg.payload_b64);
        defer testing.allocator.free(claims);
        const p = try std.json.parseFromSlice(std.json.Value, testing.allocator, claims, .{});
        defer p.deinit();
        try testing.expectEqualStrings("GET", p.value.object.get("htm").?.string);
        try testing.expectEqual(@as(i64, 1_750_000_123), p.value.object.get("iat").?.integer);
        try testing.expectEqualStrings("id-1", p.value.object.get("jti").?.string);
        try testing.expect(p.value.object.get("nonce") == null);
        try testing.expect(p.value.object.get("ath") == null);
    }

    // Bound proof: nonce + ath present, ath = base64url(sha256(token)).
    const access = "an-access-token-value";
    const bound = try buildProof(testing.allocator, .{
        .secret_key = secret,
        .htm = "POST",
        .htu = "https://pds.zat4.com/xrpc/com.atproto.repo.createRecord",
        .iat = 1_750_000_200,
        .jti = "id-2",
        .nonce = "server-nonce-xyz",
        .access_token = access,
    });
    defer testing.allocator.free(bound);
    {
        const seg = try jws.parse(bound);
        const claims = try jws.decodeSegment(testing.allocator, seg.payload_b64);
        defer testing.allocator.free(claims);
        const p = try std.json.parseFromSlice(std.json.Value, testing.allocator, claims, .{});
        defer p.deinit();
        try testing.expectEqualStrings("server-nonce-xyz", p.value.object.get("nonce").?.string);

        var digest: [Sha256.digest_length]u8 = undefined;
        Sha256.hash(access, &digest, .{});
        var expect_ath: [43]u8 = undefined;
        _ = b64url.Encoder.encode(&expect_ath, &digest);
        try testing.expectEqualStrings(&expect_ath, p.value.object.get("ath").?.string);
    }
}
