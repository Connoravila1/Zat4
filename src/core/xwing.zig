//! B1 classification: CORE (pure). X-Wing — the hybrid post-quantum KEM
//! (ML-KEM-768 + X25519, draft-connolly-cfrg-xwing) as an HPKE KEM
//! (ZAT_CHAT_ROADMAP slice C2).
//!
//! std already ships the construction: `std.crypto.kem.hybrid.MlKem768X25519`
//! is the SHA3-256 combiner over (ss_pq ‖ ss_x25519 ‖ ct_x25519 ‖ pk_x25519 ‖
//! label) with the X-Wing label `\.//^\`, keys expanded from a 32-byte seed
//! via SHAKE256 — the spec's construction, not merely a lookalike. This
//! module's job is (1) to PROVE that byte-for-byte against the spec's
//! published test vectors (the comment in std is a claim; the vectors are
//! the fact), and (2) to wrap it in the `hpke.Suite` KEM interface so
//! `Suite(XWingKem, aead)` is post-quantum HPKE with no caller changes —
//! the C2 seam doing its job.
//!
//! Per the spec's HPKE section, X-Wing's shared secret is used DIRECTLY as
//! the KEM shared secret (it is already uniform — no DHKEM-style
//! extract/expand), which is exactly how `hpke.Suite` consumes a KEM.
//!
//! Harvest-now-decrypt-later is the property bought here: a recorded
//! exchange stays confidential unless BOTH X25519 and ML-KEM-768 fall.

const std = @import("std");
const assert = std.debug.assert;
const hpke = @import("hpke.zig");

const H = std.crypto.kem.hybrid.MlKem768X25519;

/// X-Wing in the `hpke.Suite` KEM shape. The secret key is the 32-byte seed
/// (everything expands from it, per the spec); the encap seed is 64 bytes —
/// 32 for the ML-KEM message, 32 for the ephemeral X25519 secret.
pub const XWingKem = struct {
    /// The registered HPKE KEM id for X-Wing (IANA, from the draft).
    pub const kem_id: u16 = 0x647a;
    pub const Nsecret = 32;
    pub const Nenc = 1120; // ML-KEM-768 ct (1088) + X25519 ephemeral pk (32)
    pub const Npk = 1216; // ML-KEM-768 ek (1184) + X25519 pk (32)
    pub const Nsk = 32; // the seed IS the secret key
    pub const Nes = 64; // encap randomness: ML-KEM m (32) + X25519 sk (32)

    /// One encapsulation. PQ sizes are large ON PURPOSE — the guard pins
    /// them so a suite change is a recorded decision (A7/A7.1).
    pub const Encapped = struct {
        shared: [Nsecret]u8,
        enc: [Nenc]u8,

        comptime {
            // 32 + 1120 bytes, align 1 — exact. (A7)
            assert(@sizeOf(@This()) == 1152);
        }
    };

    /// A keypair expanded from the 32-byte seed. A7.2: cold struct, size
    /// guard waived — transient, one per key generation.
    pub const KeyPairBytes = struct {
        sk: [Nsk]u8,
        pk: [Npk]u8,
    };

    /// GenerateKeyPairDerand: seed → (sk = seed, pk). Deterministic — a
    /// stored seed is the same identity on every launch.
    pub fn keyPairFromSeed(seed: [Nsk]u8) hpke.KemError!KeyPairBytes {
        const kp = H.KeyPair.generateDeterministic(seed) catch return error.InvalidPublicKey;
        return .{ .sk = seed, .pk = kp.public_key.toBytes() };
    }

    pub fn encapDeterministic(es: [Nes]u8, pk_r: [Npk]u8) hpke.KemError!Encapped {
        const pk = H.PublicKey.fromBytes(&pk_r);
        const e = pk.encapsDeterministic(&es) catch return error.InvalidPublicKey;
        return .{ .shared = e.shared_secret, .enc = e.ciphertext };
    }

    pub fn decap(enc: [Nenc]u8, sk_r: [Nsk]u8) hpke.KemError![Nsecret]u8 {
        const sk = H.SecretKey.fromBytes(&sk_r);
        return sk.decaps(&enc) catch error.InvalidPublicKey;
    }
};

// ---------------------------------------------------------------------------
// Golden tests — the X-Wing spec's published vectors (spec/test-vectors.json
// in the draft repo). seed/eseed/ss are embedded whole; the large pk/ct are
// pinned by SHA-256 digest (collision resistance makes the digest as binding
// as the bytes). All three vectors drive keygen, encaps, and decaps.
// ---------------------------------------------------------------------------

fn hx(comptime s: []const u8) [s.len / 2]u8 {
    @setEvalBranchQuota(20_000);
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

fn sha256(bytes: []const u8) [32]u8 {
    var out: [32]u8 = undefined;
    std.crypto.hash.sha2.Sha256.hash(bytes, &out, .{});
    return out;
}

const Vec = struct {
    // A7.2: cold struct, size guard waived — three comptime test vectors.
    seed: [32]u8,
    eseed: [64]u8,
    ss: [32]u8,
    pk_digest: [32]u8,
    ct_digest: [32]u8,
};

const vectors = [_]Vec{
    .{
        .seed = hx("7f9c2ba4e88f827d616045507605853ed73b8093f6efbc88eb1a6eacfa66ef26"),
        .eseed = hx("3cb1eea988004b93103cfb0aeefd2a686e01fa4a58e8a3639ca8a1e3f9ae57e235b8cc873c23dc62b8d260169afa2f75ab916a58d974918835d25e6a435085b2"),
        .ss = hx("d2df0522128f09dd8e2c92b1e905c793d8f57a54c3da25861f10bf4ca613e384"),
        .pk_digest = hx("2e816deebcd76c5c80d0cd2d174478871658e8e2ff42bc9d4a6e486372e856bb"),
        .ct_digest = hx("17cd532d657e44c897ca6583e548a5424fc70bf54f99515a4d2bcf99e3469f33"),
    },
    .{
        .seed = hx("badfd6dfaac359a5efbb7bcc4b59d538df9a04302e10c8bc1cbf1a0b3a5120ea"),
        .eseed = hx("17cda7cfad765f5623474d368ccca8af0007cd9f5e4c849f167a580b14aabdefaee7eef47cb0fca9767be1fda69419dfb927e9df07348b196691abaeb580b32d"),
        .ss = hx("f2e86241c64d60f6649fbc6c5b7d17180b780a3f34355e64a85749949c45f150"),
        .pk_digest = hx("c42ba5f8430d7d2c83739338203819f090e8303ce9c8b02107c272bfa5376916"),
        .ct_digest = hx("1661ea86d608a1924ba30840cb0a65f13ae051e3aec9cf0f064efc0bc92f2154"),
    },
    .{
        .seed = hx("ef58538b8d23f87732ea63b02b4fa0f4873360e2841928cd60dd4cee8cc0d4c9"),
        .eseed = hx("22a96188d032675c8ac850933c7aff1533b94c834adbb69c6115bad4692d8619f90b0cdf8a7b9c264029ac185b70b83f2801f2f4b3f70c593ea3aeeb613a7f1b"),
        .ss = hx("953f7f4e8c5b5049bdc771d1dffada0dd961477d1a2ae0988baa7ea6898d893f"),
        .pk_digest = hx("6b080d6b84f095342092fa7a22423e58bd681397ad0ef00eac92bd254db4fa95"),
        .ct_digest = hx("d3ca5578500344b5896cffc4fd740c9311946b82951df155e6fd86a7966b43c6"),
    },
};

test "X-Wing spec vectors: std's MlKem768X25519 IS X-Wing, byte for byte" {
    for (vectors) |v| {
        // GenerateKeyPairDerand: seed -> the spec's encapsulation key.
        const kp = try XWingKem.keyPairFromSeed(v.seed);
        try std.testing.expectEqualSlices(u8, &v.pk_digest, &sha256(&kp.pk));

        // Encapsulate with the spec's randomness: the spec's ct and ss.
        const e = try XWingKem.encapDeterministic(v.eseed, kp.pk);
        try std.testing.expectEqualSlices(u8, &v.ct_digest, &sha256(&e.enc));
        try std.testing.expectEqualSlices(u8, &v.ss, &e.shared);

        // Decapsulate our (digest-proven identical) ct: the same ss.
        const ss = try XWingKem.decap(e.enc, kp.sk);
        try std.testing.expectEqualSlices(u8, &v.ss, &ss);
    }
}

test "post-quantum HPKE: Suite(XWingKem) seals and opens end to end" {
    const S = hpke.Suite(XWingKem, hpke.AeadChaCha20Poly1305);

    // Recipient identity from a seed; sender entropy passed in (B3).
    const rkp = try XWingKem.keyPairFromSeed(vectors[0].seed);
    var s = try S.setupBaseS(vectors[1].eseed, rkp.pk, "zat chat pq");
    var r = try S.setupBaseR(s.enc, rkp.sk, "zat chat pq");
    try std.testing.expectEqualSlices(u8, &s.ctx.key, &r.key);

    var ct: [11 + S.tag_length]u8 = undefined;
    try S.seal(&s.ctx, &ct, "hello field", "aad");
    var pt: [11]u8 = undefined;
    try S.open(&r, &pt, &ct, "aad");
    try std.testing.expectEqualSlices(u8, "hello field", &pt);

    // Tamper: explicit failure, sequence unmoved.
    ct[3] ^= 1;
    try std.testing.expectError(error.AuthenticationFailed, S.open(&r, &pt, &ct, "aad"));

    // Both sides export the same bound secret (what MLS will consume).
    var ex_s: [32]u8 = undefined;
    var ex_r: [32]u8 = undefined;
    S.exportSecret(&s.ctx, &ex_s, "test export");
    S.exportSecret(&r, &ex_r, "test export");
    try std.testing.expectEqualSlices(u8, &ex_s, &ex_r);
}
