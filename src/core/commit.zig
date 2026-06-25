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

//! B1 classification: CORE (pure). Repo-commit signature verification — the
//! capstone of "verify, don't trust" (SECURITY_ROADMAP Phase 3).
//!
//! A repo commit is the signed root of a user's repository. Every record they
//! publish is reachable from it, so a commit signature we verify *ourselves* is
//! what makes a server unable to forge a user's posts — "trust the math, not the
//! messenger." atproto signs a commit over the SHA-256 of the DAG-CBOR of the
//! commit node WITHOUT its `sig` field. So verification is a pure composition of
//! the pieces already built: decode the commit block (`dagcbor.decode`),
//! reconstruct the unsigned node (every field except `sig`), re-encode it
//! canonically (`dagcbor.encode`), and verify the signature against the author's
//! resolved signing key (`sigverify.verify`, which enforces low-S).
//!
//! Pure (B2/B4): bytes + key in, a yes/no out. The shell fetches the commit
//! block (from the firehose, or a CAR via `com.atproto.sync.getRepo`) and
//! resolves the key (a DID-document parse — itself a hostile-input boundary);
//! this module never touches the network.

const std = @import("std");
const dagcbor = @import("dagcbor.zig");
const sigverify = @import("sigverify.zig");

pub const VerifyError = error{
    NotACommit, // the block didn't decode to a map (not a commit node)
    NoSignature, // no `sig` byte-string field present
} || dagcbor.DecodeError || dagcbor.EncodeError;

/// Verify a repo commit's signature. `commit_block` is the raw DAG-CBOR of the
/// commit node (the block its CID addresses); `key` is the author's signing key
/// (resolve it from their DID document, then `sigverify.decodeMultikey`).
/// Returns true iff the signature is authentic AND low-S. A block that doesn't
/// decode or carries no signature is an explicit error (E3); an authentic-no is
/// an ordinary `false` (E4). `arena` holds the decode + re-encode scratch and is
/// freed wholesale by the caller (C3).
pub fn verifyCommit(
    arena: std.mem.Allocator,
    commit_block: []const u8,
    key: sigverify.PublicKey,
) VerifyError!bool {
    const decoded = try dagcbor.decode(arena, commit_block);
    const fields = switch (decoded) {
        .map => |m| m,
        else => return error.NotACommit,
    };

    // Split off the signature; everything else IS the unsigned commit. The
    // remaining fields keep their (already canonical) order, and `encode` sorts
    // again regardless, so the bytes match exactly what the author signed.
    var sig: ?[]const u8 = null;
    const unsigned = try arena.alloc(dagcbor.Entry, fields.len);
    var n: usize = 0;
    for (fields) |field| {
        if (std.mem.eql(u8, field.key, "sig")) {
            sig = switch (field.value) {
                .bytes => |b| b,
                else => return error.NoSignature,
            };
        } else {
            unsigned[n] = field;
            n += 1;
        }
    }
    const sig_bytes = sig orelse return error.NoSignature;

    const signed_bytes = try dagcbor.encode(arena, .{ .map = unsigned[0..n] });
    return sigverify.verify(key, signed_bytes, sig_bytes);
}

// ---------------------------------------------------------------------------
// Tests (C6)
// ---------------------------------------------------------------------------

const testing = std.testing;
const P256 = std.crypto.ecc.P256;
const P256Scheme = std.crypto.sign.ecdsa.EcdsaP256Sha256;

/// Build a commit block: the unsigned fields plus a `sig` entry, encoded. Keeps
/// the test honest about the wire shape (a CBOR map of the six commit fields).
fn buildCommit(arena: std.mem.Allocator, unsigned: []const dagcbor.Entry, sig64: []const u8) ![]u8 {
    const all = try arena.alloc(dagcbor.Entry, unsigned.len + 1);
    @memcpy(all[0..unsigned.len], unsigned);
    all[unsigned.len] = .{ .key = "sig", .value = .{ .bytes = sig64 } };
    return dagcbor.encode(arena, .{ .map = all });
}

test "verifyCommit: an authentic low-S commit verifies; its high-S twin does not" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const kp = try P256Scheme.KeyPair.generateDeterministic([_]u8{42} ** P256Scheme.KeyPair.seed_length);
    const key = sigverify.PublicKey{ .curve = .p256, .point = kp.public_key.toCompressedSec1() };

    // A representative unsigned commit node (the real six-field shape).
    const data_cid = [_]u8{ 0x01, 0x71, 0x12, 0x20 } ++ [_]u8{0xab} ** 32;
    const unsigned = [_]dagcbor.Entry{
        .{ .key = "data", .value = .{ .link = &data_cid } },
        .{ .key = "did", .value = .{ .string = "did:plc:examplecommitsubject" } },
        .{ .key = "prev", .value = .null },
        .{ .key = "rev", .value = .{ .string = "3krev0commit0" } },
        .{ .key = "version", .value = .{ .int = 3 } },
    };
    const signed_bytes = try dagcbor.encode(arena, .{ .map = &unsigned });

    // Sign over the canonical unsigned bytes; the scheme hashes with SHA-256,
    // matching atproto's "sign over sha256(dag-cbor(unsigned commit))".
    const sig = try kp.sign(signed_bytes, null);
    const neg_s = try P256.scalar.neg(sig.s, .big);
    var twin = sig;
    twin.s = neg_s;

    const block_a = try buildCommit(arena, &unsigned, &sig.toBytes());
    const block_b = try buildCommit(arena, &unsigned, &twin.toBytes());

    const va = try verifyCommit(arena, block_a, key);
    const vb = try verifyCommit(arena, block_b, key);
    // Exactly one of the malleable twins is low-S, and only it verifies.
    try testing.expect(va != vb);

    // A different key never verifies the commit.
    const other = try P256Scheme.KeyPair.generateDeterministic([_]u8{99} ** P256Scheme.KeyPair.seed_length);
    const wrong = sigverify.PublicKey{ .curve = .p256, .point = other.public_key.toCompressedSec1() };
    try testing.expect(!try verifyCommit(arena, block_a, wrong));
    try testing.expect(!try verifyCommit(arena, block_b, wrong));
}

test "verifyCommit: a block with no signature is an explicit error" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const dummy_key = try sigverify.decodeMultikey("did:key:zDnaembgSGUhZULN2Caob4HLJPaxBh92N7rtH21TErzqf8HQo");

    const no_sig = [_]dagcbor.Entry{.{ .key = "did", .value = .{ .string = "did:plc:x" } }};
    const block = try dagcbor.encode(arena, .{ .map = &no_sig });
    try testing.expectError(error.NoSignature, verifyCommit(arena, block, dummy_key));

    // A non-map block is not a commit.
    const not_map = try dagcbor.encode(arena, .{ .int = 7 });
    try testing.expectError(error.NotACommit, verifyCommit(arena, not_map, dummy_key));
}

test "verifyCommit: a REAL signed repo commit verifies (cross-implementation vector)" {
    // A real commit node from connor.zat4.com's repo (public metadata + signature
    // only — no post content), fetched via com.atproto.sync.getBlocks; sha256 of
    // these exact bytes equals the commit's CID. It was signed by the upstream
    // (TypeScript) PDS, so a pass proves our whole decode -> reconstruct-unsigned
    // -> re-encode -> verify chain against a foreign signer, with low-S.
    const commit_hex = "a66364696478206469643a706c633a32356962756437737261706b676173616a6c726e70786d33637265766d336d703332756e336d67353235637369675840f66883ab04e6cfa49fcd2c9872c89313cadf203b7d2e14433964c6518877597d347c9def8b4d0c2fde76e33e65249445c819409213450e98890b97df7fa025146464617461d82a582500017112201e80b11d4860a5460e376dd438c3ff68960568271e28684d33a839e5a0ef1b8f6470726576f66776657273696f6e03";
    var block: [256]u8 = undefined;
    const block_bytes = try std.fmt.hexToBytes(&block, commit_hex);
    const key = try sigverify.decodeMultikey("did:key:zQ3shvSkuLTuA7yeHLNDUzY1AaKzYQLehG3TA38fT5vr51grk");

    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    try testing.expect(try verifyCommit(arena, block_bytes, key));

    // Tamper with the signed body (flip the `version` value) → must not verify.
    var tampered: [256]u8 = undefined;
    @memcpy(tampered[0..block_bytes.len], block_bytes);
    tampered[block_bytes.len - 1] ^= 0x01;
    const tampered_ok = verifyCommit(arena, tampered[0..block_bytes.len], key) catch false;
    try testing.expect(!tampered_ok);
}
