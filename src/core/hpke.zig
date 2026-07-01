//! B1 classification: CORE (pure). HPKE — Hybrid Public Key Encryption,
//! RFC 9180, base mode (ZAT_CHAT_ROADMAP slice C1). The construction std
//! doesn't ship, built from the components it does (F2: HMAC/HKDF-SHA256,
//! X25519, the AEADs — no dependency).
//!
//! Everything here is a pure function over fixed-size byte arrays: no
//! allocator (nothing allocates, C2 trivially), no clock, no RNG — the
//! ephemeral KEM secret is PASSED IN (B2/B3: the shell owns entropy;
//! `io.randomSecure` at the call site). That is also what makes the module
//! golden-testable: the RFC's deterministic test vectors drive the exact
//! seal path the app will use.
//!
//! Shape: `Suite(Kem, Aead)` is comptime — the KEM is the sealed seam where
//! X-Wing (std's MlKem768X25519, slice C2) slots in without touching
//! callers; the KDF is fixed HKDF-SHA256 with the suite (D1: no cipher
//! IDs cross this module's boundary). Golden vectors: RFC 9180 Appendix A
//! (the CFRG published set), A.1 and A.2 base mode.

const std = @import("std");
const assert = std.debug.assert;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const X25519 = std.crypto.dh.X25519;

pub const mode_base: u8 = 0x00;

pub const KemError = error{InvalidPublicKey};
pub const SealError = error{MessageLimitReached};
pub const OpenError = error{ MessageLimitReached, AuthenticationFailed };

fn i2osp2(comptime v: u16) [2]u8 {
    return .{ @intCast(v >> 8), @intCast(v & 0xff) };
}

/// HKDF-Extract with the RFC 9180 labeling, streamed through HMAC so the
/// variable-length ikm never needs a concat buffer.
fn labeledExtract(salt: []const u8, comptime sid: []const u8, comptime label: []const u8, ikm: []const u8) [32]u8 {
    var h = HmacSha256.init(salt);
    h.update("HPKE-v1");
    h.update(sid);
    h.update(label);
    h.update(ikm);
    var prk: [32]u8 = undefined;
    h.final(&prk);
    return prk;
}

/// HKDF-Expand with the RFC 9180 labeling, the T(i) chain streamed through
/// HMAC (RFC 5869) — no concat buffer, any context length.
fn labeledExpand(prk: [32]u8, comptime sid: []const u8, comptime label: []const u8, context: []const u8, out: []u8) void {
    assert(out.len > 0 and out.len <= 255 * 32);
    const l2 = [2]u8{ @intCast(out.len >> 8), @intCast(out.len & 0xff) };
    var t: [32]u8 = undefined;
    var i: u8 = 1;
    var off: usize = 0;
    while (off < out.len) : (i += 1) {
        var h = HmacSha256.init(&prk);
        if (off > 0) h.update(&t);
        h.update(&l2);
        h.update("HPKE-v1");
        h.update(sid);
        h.update(label);
        h.update(context);
        h.update(&[1]u8{i});
        h.final(&t);
        const n = @min(32, out.len - off);
        @memcpy(out[off..][0..n], t[0..n]);
        off += n;
    }
}

/// DHKEM(X25519, HKDF-SHA256) — RFC 9180 §4.1, KEM id 0x0020.
pub const DhKemX25519 = struct {
    pub const kem_id: u16 = 0x0020;
    pub const Nsecret = 32;
    pub const Nenc = 32;
    pub const Npk = 32;
    pub const Nsk = 32;
    const sid: []const u8 = &("KEM".* ++ i2osp2(kem_id));

    /// One encapsulation: the shared secret and the enc to send.
    /// A7.2: cold struct, size guard waived — transient, never collected.
    pub const Encapped = struct {
        shared: [Nsecret]u8,
        enc: [Nenc]u8,
    };

    /// RFC 9180 DeriveKeyPair: seed bytes → (sk, pk). Deterministic — this
    /// is how a stored seed becomes the same key on every launch.
    pub fn deriveKeyPair(ikm: []const u8) KemError!struct { sk: [Nsk]u8, pk: [Npk]u8 } {
        const dkp_prk = labeledExtract("", sid, "dkp_prk", ikm);
        var sk: [Nsk]u8 = undefined;
        labeledExpand(dkp_prk, sid, "sk", "", &sk);
        const pk = X25519.recoverPublicKey(sk) catch return error.InvalidPublicKey;
        return .{ .sk = sk, .pk = pk };
    }

    pub fn derivePublic(sk: [Nsk]u8) KemError![Npk]u8 {
        return X25519.recoverPublicKey(sk) catch error.InvalidPublicKey;
    }

    fn extractAndExpand(dh: [32]u8, kem_context: []const u8) [Nsecret]u8 {
        const eae_prk = labeledExtract("", sid, "eae_prk", &dh);
        var out: [Nsecret]u8 = undefined;
        labeledExpand(eae_prk, sid, "shared_secret", kem_context, &out);
        return out;
    }

    /// Encap with the ephemeral secret PASSED IN (entropy is the caller's,
    /// B3) — deterministic, which is exactly what the golden vectors need.
    pub fn encapDeterministic(sk_e: [Nsk]u8, pk_r: [Npk]u8) KemError!Encapped {
        const dh = X25519.scalarmult(sk_e, pk_r) catch return error.InvalidPublicKey;
        const enc = X25519.recoverPublicKey(sk_e) catch return error.InvalidPublicKey;
        const kem_context: [64]u8 = enc ++ pk_r;
        return .{ .shared = extractAndExpand(dh, &kem_context), .enc = enc };
    }

    pub fn decap(enc: [Nenc]u8, sk_r: [Nsk]u8) KemError![Nsecret]u8 {
        const dh = X25519.scalarmult(sk_r, enc) catch return error.InvalidPublicKey;
        const pk_r = X25519.recoverPublicKey(sk_r) catch return error.InvalidPublicKey;
        const kem_context: [64]u8 = enc ++ pk_r;
        return extractAndExpand(dh, &kem_context);
    }
};

/// AEAD descriptors — the RFC id welded to the std implementation.
pub const AeadAes128Gcm = struct {
    // A7.2: cold struct, size guard waived — a zero-field comptime namespace.
    pub const aead_id: u16 = 0x0001;
    pub const A = std.crypto.aead.aes_gcm.Aes128Gcm;
};
pub const AeadChaCha20Poly1305 = struct {
    // A7.2: cold struct, size guard waived — a zero-field comptime namespace.
    pub const aead_id: u16 = 0x0003;
    pub const A = std.crypto.aead.chacha_poly.ChaCha20Poly1305;
};

/// An HPKE ciphersuite, fixed at comptime (D1: the IDs live here and only
/// here). KDF is HKDF-SHA256 (0x0001) with the suite.
pub fn Suite(comptime Kem: type, comptime Aead: type) type {
    return struct {
        pub const kdf_id: u16 = 0x0001;
        const A = Aead.A;
        const sid: []const u8 = &("HPKE".* ++ i2osp2(Kem.kem_id) ++ i2osp2(kdf_id) ++ i2osp2(Aead.aead_id));
        pub const tag_length = A.tag_length;
        pub const enc_length = Kem.Nenc;

        /// One direction's sealed state: the AEAD key, the nonce base, the
        /// exporter secret, and the message counter. Hot by the ruleset's
        /// tie-break (one per open conversation, ambiguous ⇒ guarded); the
        /// exact size is computed per instantiation (key/nonce widths are
        /// suite facts). The caller wipes it at end of life (the C4/C5
        /// scrub-on-free convention).
        pub const Context = struct {
            key: [A.key_length]u8,
            base_nonce: [A.nonce_length]u8,
            exporter: [32]u8,
            seq: u64,

            comptime {
                // key + nonce + exporter + seq, padded to u64 alignment. (A7)
                assert(@sizeOf(@This()) == std.mem.alignForward(usize, A.key_length + A.nonce_length + 32 + 8, 8));
            }
        };

        /// A sender setup: the enc to transmit and the sealed context.
        /// A7.2: cold struct, size guard waived — transient, never collected.
        pub const Sender = struct {
            enc: [Kem.Nenc]u8,
            ctx: Context,
        };

        fn keySchedule(shared: [Kem.Nsecret]u8, info: []const u8) Context {
            // Base mode: psk and psk_id are both empty (RFC 9180 §5.1).
            const psk_id_hash = labeledExtract("", sid, "psk_id_hash", "");
            const info_hash = labeledExtract("", sid, "info_hash", info);
            const ksc: [65]u8 = [1]u8{mode_base} ++ psk_id_hash ++ info_hash;
            const secret = labeledExtract(&shared, sid, "secret", "");
            var ctx: Context = .{ .key = undefined, .base_nonce = undefined, .exporter = undefined, .seq = 0 };
            labeledExpand(secret, sid, "key", &ksc, &ctx.key);
            labeledExpand(secret, sid, "base_nonce", &ksc, &ctx.base_nonce);
            labeledExpand(secret, sid, "exp", &ksc, &ctx.exporter);
            return ctx;
        }

        /// Sender side, deterministic: the ephemeral KEM secret is passed in
        /// (the shell rolls it fresh per setup and never reuses it).
        pub fn setupBaseS(sk_e: [Kem.Nsk]u8, pk_r: [Kem.Npk]u8, info: []const u8) KemError!Sender {
            const e = try Kem.encapDeterministic(sk_e, pk_r);
            return .{ .enc = e.enc, .ctx = keySchedule(e.shared, info) };
        }

        /// Recipient side: the received enc + the recipient's KEM secret.
        pub fn setupBaseR(enc: [Kem.Nenc]u8, sk_r: [Kem.Nsk]u8, info: []const u8) KemError!Context {
            const shared = try Kem.decap(enc, sk_r);
            return keySchedule(shared, info);
        }

        fn nonceFor(ctx: *const Context, seq: u64) [A.nonce_length]u8 {
            var n = ctx.base_nonce;
            var seq_bytes: [8]u8 = undefined;
            std.mem.writeInt(u64, &seq_bytes, seq, .big);
            for (n[A.nonce_length - 8 ..], seq_bytes) |*b, s| b.* ^= s;
            return n;
        }

        /// Seal one message; `out` is ciphertext||tag (msg.len + tag_length).
        /// The sequence number advances — nonce reuse is structurally
        /// impossible short of copying the context, which the caller must
        /// never do.
        pub fn seal(ctx: *Context, out: []u8, msg: []const u8, aad: []const u8) SealError!void {
            assert(out.len == msg.len + tag_length);
            if (ctx.seq == std.math.maxInt(u64)) return error.MessageLimitReached;
            const nonce = nonceFor(ctx, ctx.seq);
            A.encrypt(out[0..msg.len], out[msg.len..][0..tag_length], msg, aad, nonce, ctx.key);
            ctx.seq += 1;
        }

        /// Open one message; `ct` is ciphertext||tag, `out` is msg
        /// (ct.len - tag_length). A failed tag leaves the sequence number
        /// unmoved (the message is rejected, not consumed).
        pub fn open(ctx: *Context, out: []u8, ct: []const u8, aad: []const u8) OpenError!void {
            assert(ct.len >= tag_length and out.len == ct.len - tag_length);
            if (ctx.seq == std.math.maxInt(u64)) return error.MessageLimitReached;
            const nonce = nonceFor(ctx, ctx.seq);
            const msg_len = ct.len - tag_length;
            A.decrypt(out, ct[0..msg_len], ct[msg_len..][0..tag_length].*, aad, nonce, ctx.key) catch
                return error.AuthenticationFailed;
            ctx.seq += 1;
        }

        /// The exporter interface (RFC 9180 §5.3) — deriving further secrets
        /// bound to this context (MLS leans on this).
        pub fn exportSecret(ctx: *const Context, out: []u8, exporter_context: []const u8) void {
            labeledExpand(ctx.exporter, sid, "sec", exporter_context, out);
        }

        /// Scrub the context's secrets (the scrub-on-free convention).
        pub fn wipe(ctx: *Context) void {
            std.crypto.secureZero(u8, &ctx.key);
            std.crypto.secureZero(u8, &ctx.base_nonce);
            std.crypto.secureZero(u8, &ctx.exporter);
            ctx.seq = 0;
        }
    };
}

// ---------------------------------------------------------------------------
// Golden tests — RFC 9180 Appendix A (the CFRG published vector set), base
// mode, DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256. A.1 = AES-128-GCM,
// A.2 = ChaCha20-Poly1305. Both sides (S and R) are driven and must agree.
// ---------------------------------------------------------------------------

fn hx(comptime s: []const u8) [s.len / 2]u8 {
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

const test_info = hx("4f6465206f6e2061204772656369616e2055726e"); // "Ode on a Grecian Urn"
const test_pt = hx("4265617574792069732074727574682c20747275746820626561757479");

test "RFC 9180 A.1: base X25519 / HKDF-SHA256 / AES-128-GCM" {
    const S = Suite(DhKemX25519, AeadAes128Gcm);

    // DeriveKeyPair: ikmE -> skEm/pkEm, ikmR -> skRm/pkRm.
    const ekp = try DhKemX25519.deriveKeyPair(&hx("7268600d403fce431561aef583ee1613527cff655c1343f29812e66706df3234"));
    try std.testing.expectEqualSlices(u8, &hx("52c4a758a802cd8b936eceea314432798d5baf2d7e9235dc084ab1b9cfa2f736"), &ekp.sk);
    try std.testing.expectEqualSlices(u8, &hx("37fda3567bdbd628e88668c3c8d7e97d1d1253b6d4ea6d44c150f741f1bf4431"), &ekp.pk);
    const rkp = try DhKemX25519.deriveKeyPair(&hx("6db9df30aa07dd42ee5e8181afdb977e538f5e1fec8a06223f33f7013e525037"));
    try std.testing.expectEqualSlices(u8, &hx("4612c550263fc8ad58375df3f557aac531d26850903e55a9f23f21d8534e8ac8"), &rkp.sk);

    // Encap is deterministic given skE; enc and the shared secret match.
    const e = try DhKemX25519.encapDeterministic(ekp.sk, rkp.pk);
    try std.testing.expectEqualSlices(u8, &ekp.pk, &e.enc);
    try std.testing.expectEqualSlices(u8, &hx("fe0e18c9f024ce43799ae393c7e8fe8fce9d218875e8227b0187c04e7d2ea1fc"), &e.shared);

    // The key schedule lands on the vector's key / base_nonce / exporter.
    var s = try S.setupBaseS(ekp.sk, rkp.pk, &test_info);
    try std.testing.expectEqualSlices(u8, &hx("4531685d41d65f03dc48f6b8302c05b0"), &s.ctx.key);
    try std.testing.expectEqualSlices(u8, &hx("56d890e5accaaf011cff4b7d"), &s.ctx.base_nonce);
    try std.testing.expectEqualSlices(u8, &hx("45ff1c2e220db587171952c0592d5f5ebe103f1561a2614e38f2ffd47e99e3f8"), &s.ctx.exporter);

    // Seal the first three vector messages (seq 0, 1, 2 — nonce XOR path).
    const cts = [_][45]u8{
        hx("f938558b5d72f1a23810b4be2ab4f84331acc02fc97babc53a52ae8218a355a96d8770ac83d07bea87e13c512a"),
        hx("af2d7e9ac9ae7e270f46ba1f975be53c09f8d875bdc8535458c2494e8a6eab251c03d0c22a56b8ca42c2063b84"),
        hx("498dfcabd92e8acedc281e85af1cb4e3e31c7dc394a1ca20e173cb72516491588d96a19ad4a683518973dcc180"),
    };
    const aads = [_][7]u8{ hx("436f756e742d30"), hx("436f756e742d31"), hx("436f756e742d32") };
    for (cts, aads) |want, aad| {
        var got: [45]u8 = undefined;
        try S.seal(&s.ctx, &got, &test_pt, &aad);
        try std.testing.expectEqualSlices(u8, &want, &got);
    }

    // The recipient derives the SAME context from enc + skR and opens seq 0.
    var r = try S.setupBaseR(e.enc, rkp.sk, &test_info);
    try std.testing.expectEqualSlices(u8, &s.ctx.key, &r.key);
    var pt: [29]u8 = undefined;
    try S.open(&r, &pt, &cts[0], &aads[0]);
    try std.testing.expectEqualSlices(u8, &test_pt, &pt);

    // Exporter vectors ("" and 0x00 contexts).
    var ex: [32]u8 = undefined;
    S.exportSecret(&r, &ex, "");
    try std.testing.expectEqualSlices(u8, &hx("3853fe2b4035195a573ffc53856e77058e15d9ea064de3e59f4961d0095250ee"), &ex);
    S.exportSecret(&r, &ex, &[1]u8{0});
    try std.testing.expectEqualSlices(u8, &hx("2e8f0b54673c7029649d4eb9d5e33bf1872cf76d623ff164ac185da9e88c21a5"), &ex);
}

test "RFC 9180 A.2: base X25519 / HKDF-SHA256 / ChaCha20-Poly1305" {
    const S = Suite(DhKemX25519, AeadChaCha20Poly1305);

    const ekp = try DhKemX25519.deriveKeyPair(&hx("909a9b35d3dc4713a5e72a4da274b55d3d3821a37e5d099e74a647db583a904b"));
    try std.testing.expectEqualSlices(u8, &hx("f4ec9b33b792c372c1d2c2063507b684ef925b8c75a42dbcbf57d63ccd381600"), &ekp.sk);
    const rkp = try DhKemX25519.deriveKeyPair(&hx("1ac01f181fdf9f352797655161c58b75c656a6cc2716dcb66372da835542e1df"));
    try std.testing.expectEqualSlices(u8, &hx("4310ee97d88cc1f088a5576c77ab0cf5c3ac797f3d95139c6c84b5429c59662a"), &(try DhKemX25519.derivePublic(rkp.sk)));

    var s = try S.setupBaseS(ekp.sk, rkp.pk, &test_info);
    try std.testing.expectEqualSlices(u8, &hx("ad2744de8e17f4ebba575b3f5f5a8fa1f69c2a07f6e7500bc60ca6e3e3ec1c91"), &s.ctx.key);
    try std.testing.expectEqualSlices(u8, &hx("5c4d98150661b848853b547f"), &s.ctx.base_nonce);

    var ct: [45]u8 = undefined;
    try S.seal(&s.ctx, &ct, &test_pt, &hx("436f756e742d30"));
    try std.testing.expectEqualSlices(u8, &hx("1c5250d8034ec2b784ba2cfd69dbdb8af406cfe3ff938e131f0def8c8b60b4db21993c62ce81883d2dd1b51a28"), &ct);

    var r = try S.setupBaseR(s.enc, rkp.sk, &test_info);
    var ex: [32]u8 = undefined;
    S.exportSecret(&r, &ex, "");
    try std.testing.expectEqualSlices(u8, &hx("4bbd6243b8bb54cec311fac9df81841b6fd61f56538a775e7c80a9f40160606e"), &ex);
}

test "tampering and AAD mismatch are explicit failures; wipe scrubs" {
    const S = Suite(DhKemX25519, AeadAes128Gcm);
    const ekp = try DhKemX25519.deriveKeyPair("an ephemeral seed for this test");
    const rkp = try DhKemX25519.deriveKeyPair("a recipient seed for this test!");

    var s = try S.setupBaseS(ekp.sk, rkp.pk, "test");
    var ct: [5 + S.tag_length]u8 = undefined;
    try S.seal(&s.ctx, &ct, "hello", "aad");

    var r = try S.setupBaseR(s.enc, rkp.sk, "test");
    var pt: [5]u8 = undefined;

    // Wrong AAD: rejected, and the sequence number does not advance.
    try std.testing.expectError(error.AuthenticationFailed, S.open(&r, &pt, &ct, "bad"));
    try std.testing.expectEqual(@as(u64, 0), r.seq);
    // Flipped ciphertext bit: rejected.
    ct[0] ^= 1;
    try std.testing.expectError(error.AuthenticationFailed, S.open(&r, &pt, &ct, "aad"));
    ct[0] ^= 1;
    // Intact: opens.
    try S.open(&r, &pt, &ct, "aad");
    try std.testing.expectEqualSlices(u8, "hello", &pt);

    S.wipe(&r);
    try std.testing.expectEqualSlices(u8, &[_]u8{0} ** 16, &r.key);
}
