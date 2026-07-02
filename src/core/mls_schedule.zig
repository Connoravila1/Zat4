//! B1 classification: CORE (pure). The MLS key schedule and secret tree —
//! RFC 9420 §8 and §9 (ZAT_CHAT_ROADMAP slice C4). Allocation-free, no
//! clock, no RNG: secrets in, secrets out, deterministic under the MLS
//! working group's published interop vectors (which drive every test).
//!
//! The KDF is HKDF-SHA256 — the hash is a suite fact sealed with this
//! module for v1 (D1); the ExpandWithLabel construction streams its
//! KDFLabel through HMAC so a full GroupContext as context never needs a
//! concat buffer.
//!
//! Forward secrecy lives in DELETION: `EpochSecrets.wipe` and
//! `RatchetSecret` advancing in place are the wipe points the shell must
//! honor (C5's state machine calls them; the convention is scrub-at-
//! release, established project-wide).

const std = @import("std");
const assert = std.debug.assert;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Sha256 = std.crypto.hash.sha2.Sha256;
const wire = @import("mls_wire.zig");

/// KDF.Nh for this suite family (SHA-256).
pub const secret_len = 32;

pub const Secret = [secret_len]u8;

fn hkdfExtract(salt: []const u8, ikm: []const u8) Secret {
    var h = HmacSha256.init(salt);
    h.update(ikm);
    var prk: Secret = undefined;
    h.final(&prk);
    return prk;
}

/// HKDF-Expand with the info supplied as parts (RFC 5869's T(i) chain
/// streamed through HMAC) — no concat buffer, any context size.
fn expandParts(prk: Secret, parts: []const []const u8, out: []u8) void {
    assert(out.len > 0 and out.len <= 255 * secret_len);
    var t: Secret = undefined;
    var i: u8 = 1;
    var off: usize = 0;
    while (off < out.len) : (i += 1) {
        var h = HmacSha256.init(&prk);
        if (off > 0) h.update(&t);
        for (parts) |p| h.update(p);
        h.update(&[1]u8{i});
        h.final(&t);
        const n = @min(secret_len, out.len - off);
        @memcpy(out[off..][0..n], t[0..n]);
        off += n;
    }
}

/// RFC 9420 §8: ExpandWithLabel(Secret, Label, Context, Length) —
/// KDF.Expand over the serialized KDFLabel { uint16 length;
/// opaque label<V> = "MLS 1.0 " + Label; opaque context<V> }.
pub fn expandWithLabel(secret: Secret, label: []const u8, context: []const u8, out: []u8) void {
    var len2: [2]u8 = undefined;
    std.mem.writeInt(u16, &len2, @intCast(out.len), .big);
    var lb: [4]u8 = undefined;
    const lv = wire.varintBytes(&lb, @intCast(8 + label.len)) catch unreachable; // labels are short
    var cb: [4]u8 = undefined;
    const cv = wire.varintBytes(&cb, @intCast(context.len)) catch unreachable; // ≤ one wire object
    expandParts(secret, &.{ &len2, lv, "MLS 1.0 ", label, cv, context }, out);
}

/// RFC 9420 §8: DeriveSecret(Secret, Label) — ExpandWithLabel with an
/// empty context at the KDF's own width.
pub fn deriveSecret(secret: Secret, label: []const u8) Secret {
    var out: Secret = undefined;
    expandWithLabel(secret, label, "", &out);
    return out;
}

/// RFC 9420 §9: DeriveTreeSecret — the context is the generation counter
/// as a big-endian uint32.
pub fn deriveTreeSecret(secret: Secret, label: []const u8, generation: u32, out: []u8) void {
    var g: [4]u8 = undefined;
    std.mem.writeInt(u32, &g, generation, .big);
    expandWithLabel(secret, label, &g, out);
}

// ---------------------------------------------------------------------------
// The epoch key schedule (§8) — one chain per epoch, everything derived
// from it named and typed.
// ---------------------------------------------------------------------------

/// Every secret one epoch yields (§8, Table 4). One live instance per open
/// conversation — hot by the tie-break rule, so it carries the guard.
pub const EpochSecrets = struct {
    joiner: Secret,
    welcome: Secret,
    sender_data: Secret,
    encryption: Secret,
    exporter: Secret,
    external: Secret,
    confirmation_key: Secret,
    membership_key: Secret,
    resumption_psk: Secret,
    epoch_authenticator: Secret,
    init: Secret,

    comptime {
        // 11 × 32-byte secrets, packed exactly. (A7)
        assert(@sizeOf(EpochSecrets) == 11 * secret_len);
    }

    /// The wipe point (forward secrecy = these bytes actually dying).
    pub fn wipe(e: *EpochSecrets) void {
        std.crypto.secureZero(u8, std.mem.asBytes(e));
    }
};

/// Advance the schedule across a Commit: the previous epoch's init secret
/// + the commit secret + the NEW epoch's serialized GroupContext (and the
/// PSK secret — all-zero when no PSKs are in play, which is v1 always).
pub fn epochFromCommit(
    init_prev: Secret,
    commit_secret: Secret,
    psk_secret: Secret,
    group_context: []const u8,
) EpochSecrets {
    const pre = hkdfExtract(&init_prev, &commit_secret);
    var joiner: Secret = undefined;
    expandWithLabel(pre, "joiner", group_context, &joiner);
    return epochFromJoiner(joiner, psk_secret, group_context);
}

/// The Welcome receiver's entry point: the joiner secret (decrypted from
/// the Welcome) + the GroupContext it was told about.
pub fn epochFromJoiner(
    joiner: Secret,
    psk_secret: Secret,
    group_context: []const u8,
) EpochSecrets {
    const member = hkdfExtract(&joiner, &psk_secret);
    var epoch: Secret = undefined;
    expandWithLabel(member, "epoch", group_context, &epoch);
    return tableFrom(epoch, joiner, deriveSecret(member, "welcome"));
}

/// Group creation (RFC 9420 §11): epoch 0 starts from a FRESH RANDOM epoch
/// secret (the shell's entropy, passed in). No joiner/welcome exist for
/// epoch 0 — nobody joins an epoch that predates its group's first commit —
/// so those two table slots are zero.
pub fn epochFromRaw(epoch_secret: Secret) EpochSecrets {
    const zero: Secret = @splat(0);
    return tableFrom(epoch_secret, zero, zero);
}

/// The §8 Table 4 derivations, shared by every epoch entry point.
fn tableFrom(epoch: Secret, joiner: Secret, welcome: Secret) EpochSecrets {
    return .{
        .joiner = joiner,
        .welcome = welcome,
        .sender_data = deriveSecret(epoch, "sender data"),
        .encryption = deriveSecret(epoch, "encryption"),
        .exporter = deriveSecret(epoch, "exporter"),
        .external = deriveSecret(epoch, "external"),
        .confirmation_key = deriveSecret(epoch, "confirm"),
        .membership_key = deriveSecret(epoch, "membership"),
        .resumption_psk = deriveSecret(epoch, "resumption"),
        .epoch_authenticator = deriveSecret(epoch, "authentication"),
        .init = deriveSecret(epoch, "init"),
    };
}

/// The welcome secret (§8): derived from the joiner secret + PSK input
/// BEFORE the GroupContext enters the chain — which is what lets a joiner
/// decrypt the GroupInfo that CONTAINS the context.
pub fn welcomeSecretFromJoiner(joiner: Secret, psk_secret: Secret) Secret {
    return deriveSecret(hkdfExtract(&joiner, &psk_secret), "welcome");
}

/// RFC 9420 §8.5: MLS-Exporter(Label, Context, Length).
pub fn mlsExporter(exporter_secret: Secret, label: []const u8, context: []const u8, out: []u8) void {
    var ctx_hash: [Sha256.digest_length]u8 = undefined;
    Sha256.hash(context, &ctx_hash, .{});
    expandWithLabel(deriveSecret(exporter_secret, label), "exported", &ctx_hash, out);
}

// ---------------------------------------------------------------------------
// The secret tree (§9) — per-leaf handshake/application ratchets derived
// from the epoch's encryption secret down a left-balanced binary tree.
// ---------------------------------------------------------------------------

fn level(x: u32) u5 {
    return @intCast(@ctz(~x)); // consecutive low 1-bits
}

/// Walk root → leaf, expanding "tree"/"left"/"right" at each step
/// (Appendix C tree math over 2N-1 nodes; a leaf's node index is 2·leaf).
fn leafTreeSecret(encryption_secret: Secret, leaf: u32, n_leaves: u32) Secret {
    assert(leaf < n_leaves);
    const width: u32 = 2 * n_leaves - 1;
    const k: u5 = @intCast(31 - @clz(width));
    var node: u32 = (@as(u32, 1) << k) - 1; // root
    const target: u32 = 2 * leaf;
    var secret = encryption_secret;
    while (node != target) {
        const step = @as(u32, 1) << (level(node) - 1);
        if (target < node) {
            expandWithLabel(secret, "tree", "left", &secret);
            node ^= step;
        } else {
            expandWithLabel(secret, "tree", "right", &secret);
            node ^= step * 3;
        }
    }
    return secret;
}

pub const RatchetKind = enum { handshake, application };

/// One sender ratchet: the current chain secret + its generation. Hot (one
/// pair per member per epoch, stepped per message) — guarded.
pub const RatchetSecret = struct {
    secret: Secret,
    generation: u32,

    comptime {
        // 32 + 4, packed exactly. (A7)
        assert(@sizeOf(RatchetSecret) == 36);
    }

    pub fn wipe(r: *RatchetSecret) void {
        std.crypto.secureZero(u8, &r.secret);
        r.generation = 0;
    }
};

/// A leaf's ratchet at generation 0 for one kind.
pub fn ratchetInit(encryption_secret: Secret, leaf: u32, n_leaves: u32, kind: RatchetKind) RatchetSecret {
    const leaf_secret = leafTreeSecret(encryption_secret, leaf, n_leaves);
    var out: RatchetSecret = .{ .secret = undefined, .generation = 0 };
    expandWithLabel(leaf_secret, switch (kind) {
        .handshake => "handshake",
        .application => "application",
    }, "", &out.secret);
    return out;
}

/// Emit this generation's AEAD key + nonce and step the chain — the old
/// chain secret is overwritten in place (its forward-secrecy deletion).
pub fn ratchetAdvance(r: *RatchetSecret, key_out: []u8, nonce_out: []u8) void {
    deriveTreeSecret(r.secret, "key", r.generation, key_out);
    deriveTreeSecret(r.secret, "nonce", r.generation, nonce_out);
    var next: Secret = undefined;
    deriveTreeSecret(r.secret, "secret", r.generation, &next);
    r.secret = next;
    r.generation += 1;
}

/// RFC 9420 §6.3.2: the sender-data key/nonce, bound to a sample of the
/// message ciphertext.
pub fn senderDataKeyNonce(sender_data_secret: Secret, ciphertext: []const u8, key_out: []u8, nonce_out: []u8) void {
    const sample = ciphertext[0..@min(ciphertext.len, secret_len)];
    expandWithLabel(sender_data_secret, "key", sample, key_out);
    expandWithLabel(sender_data_secret, "nonce", sample, nonce_out);
}

// ---------------------------------------------------------------------------
// Golden tests — the MLS interop vectors (mlswg/mls-implementations),
// cipher suite 1 (SHA-256 KDF, AES-128 widths: Nk=16, Nn=12).
// ---------------------------------------------------------------------------

fn hx(comptime s: []const u8) [s.len / 2]u8 {
    @setEvalBranchQuota(20_000);
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "interop crypto-basics: ExpandWithLabel / DeriveSecret / DeriveTreeSecret" {
    var out16: [16]u8 = undefined;
    expandWithLabel(
        hx("1499360a561335f4ef51d0a1b0d586900dc8007ae405b1ab79bf4207bb3d67e4"),
        "ExpandWithLabel",
        &hx("2ff8c1f9d9c1248f82e372ddb5791c771695e01882abca6a64097bd2f04c971f"),
        &out16,
    );
    try std.testing.expectEqualSlices(u8, &hx("c1e8eb360391526c0c64039f13e0c5b1"), &out16);

    const ds = deriveSecret(hx("1a9ce178a53f8752d2513c27efe9c85133f6c0a97f7b35ac200695024a77228e"), "DeriveSecret");
    try std.testing.expectEqualSlices(u8, &hx("3b08c195a246c4ad469c1d11c10e62890d8fa6b684494ff925409efdb1ff0464"), &ds);

    var out32: [32]u8 = undefined;
    deriveTreeSecret(
        hx("5133c6f8bad297f5d3beacdf477f0c45ec51b02de659d305220c5f9385c6eb43"),
        "DeriveTreeSecret",
        2694881440,
        &out32,
    );
    try std.testing.expectEqualSlices(u8, &hx("8461f3ccc603eae52149a23a4134d29c880a1ad1ba70441e5d586e3521ec7b25"), &out32);
}

test "interop key-schedule: the full epoch chain, two epochs linked" {
    const gc0 = hx("0001000120a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e0000000000000000209769e302a99c457350a8e636009b12a2fee068664004606d6318eb3a1977d818205e57c9364dc71f0f71b19ffe561ab77257c490708a47e29f8f73f2b318201d2f00");

    var e0 = epochFromCommit(
        hx("a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e"), // initial init secret
        hx("a22606222e350fd7f0937168fe7548fb06626ab143cba7611d641693b1447509"), // commit secret
        hx("e871b247379522395689182736cb3d1e7b108d6ae934b802223975de8dc3f80b"), // psk secret
        &gc0,
    );
    try std.testing.expectEqualSlices(u8, &hx("4fb996ba26b29a70f3ce6c310151ce8701cb812d027f4d4bbf5cc4e9f884638d"), &e0.joiner);
    try std.testing.expectEqualSlices(u8, &hx("ddcd9ced2d264798f876cbd00a200cdc4d77311dfef96975257efb66b0ef2c4d"), &e0.welcome);
    try std.testing.expectEqualSlices(u8, &hx("9b3995e08589548b75e149190060cf35228df0eefe3527ea2fb39e49a84125b4"), &e0.sender_data);
    try std.testing.expectEqualSlices(u8, &hx("01588615c93d02c83bda0b587473303b1637a92bf80783206d963f9197c40a13"), &e0.encryption);
    try std.testing.expectEqualSlices(u8, &hx("5a097e149f2a375d0b9e1d1f4dc3a9c6c1788df888e5441f41a8791f4dc56cea"), &e0.exporter);
    try std.testing.expectEqualSlices(u8, &hx("b5cb5666cfb9c501ed76715c6ed1cafbed5061cd6b86898ae5d3fd4cb05abb26"), &e0.external);
    try std.testing.expectEqualSlices(u8, &hx("feabd690de3b4ce985a3dfad86a4c4e6a0be9b84e7cc764842784f2a6b938b75"), &e0.confirmation_key);
    try std.testing.expectEqualSlices(u8, &hx("970744ba7edd21700a3e106cb4e2b4c657cef6b41a1fe5b5a1418f86e76e037e"), &e0.membership_key);
    try std.testing.expectEqualSlices(u8, &hx("d78ca815e192823f5c7c94b0156bdc7af4791cfb3f240fff613c0c03c01dabd5"), &e0.resumption_psk);
    try std.testing.expectEqualSlices(u8, &hx("7375d449cde2c5a856c13c8eb52c16bf9ef29eceef59b09d1f946bd1bac24643"), &e0.epoch_authenticator);
    try std.testing.expectEqualSlices(u8, &hx("505be2ce2ff922aa11e0a03d76346dda2981f1d9edf5cf98ecfc8757f69b00c9"), &e0.init);

    // The exporter interface, against the vector's random label/context.
    // NOTE: the interop spec types `label` as a plain STRING — the hex
    // characters ARE the label; only the context is decoded binary.
    var exported: [32]u8 = undefined;
    mlsExporter(
        e0.exporter,
        "9ba13d54ecdec7cbefcb47b4268d7b1990fabc6d6e67681e167959389d84e4e4",
        &hx("884f1af892ab002f5be4c5d5081ade9e0e6418c6ea7a9a92e90534f19dcef785"),
        &exported,
    );
    try std.testing.expectEqualSlices(u8, &hx("dbce4e25e59ab4dfa6f6200f113ed08393cf6e7286d024811141c6a4dd11c0cb"), &exported);

    // Epoch 1 chains from epoch 0's init secret — the schedule is a chain,
    // not a set of one-shots. (The epoch-1 GroupContext from the vector.)
    const gc1 = hx("0001000120a897b53575b4dd35fed4466e4e714bfa949eaa72e616a9c68a47b39cb7a60d2e000000000000000120826a4d3b0956277ce5e272e4d18fdca023ffb63ea4cea636e34cc837ae7c5c5d2014a2985ea47db0685924a74d47ac8a08ec241f843b536dd1348e3ffb2d78184e00");
    var e1 = epochFromCommit(
        e0.init,
        hx("7b3027aa5d2224aab7e2a18660bbf57930e2e21d95e02b849c704d970e3e28c5"),
        hx("ca7a68f2a8a52147d70f1eb7195de968d2e182b93596bc5a61393861e91180e4"),
        &gc1,
    );
    try std.testing.expectEqualSlices(u8, &hx("7ba2c5eed466d6fa8de0b0f33553c7b336a2580c03820e79f22e9416efc5b9f9"), &e1.joiner);
    try std.testing.expectEqualSlices(u8, &hx("88586b2252f06838106a97f5ad1f3357d99d718be8f44f61ab103be653fc608a"), &e1.init);

    // Wipe scrubs (the forward-secrecy deletion point).
    e0.wipe();
    e1.wipe();
    try std.testing.expectEqualSlices(u8, &([_]u8{0} ** 32), &e0.init);
}

test "interop secret-tree: leaf walk + ratchet generations (8 leaves)" {
    const enc = hx("9d4ecb550dc4fbcbaae66d120a2215cbeca20d45d66791df5b4349eace30fd3f");

    const Case = struct { leaf: u32, gen: u32, hk: [16]u8, hn: [12]u8, ak: [16]u8, an: [12]u8 };
    const cases = [_]Case{
        .{ .leaf = 0, .gen = 0, .hk = hx("199d6d2b8810a8f6e81e80e49e6a29ce"), .hn = hx("18f6c449223678070da1a24b"), .ak = hx("dd3fbd3f880af22368f4232e7518d93b"), .an = hx("969933769978098b3eb6324a") },
        .{ .leaf = 0, .gen = 15, .hk = hx("e6c01a531c31e31faa37eaa6ec405cbd"), .hn = hx("579ee05a5d60db32f9c8aef0"), .ak = hx("3eddbdfcea44bf06aab8145c90e4e699"), .an = hx("4a12f22d9328a723cec85b8c") },
        .{ .leaf = 5, .gen = 0, .hk = hx("579d500a6e78803ffd6187c1e4a3448d"), .hn = hx("8bdceebc9e6f8838c93ebe06"), .ak = hx("87dd6efd2ac7e13e0e477a72cfea0c85"), .an = hx("c3f031d03cd30def2b14ac8d") },
        .{ .leaf = 5, .gen = 15, .hk = hx("9a494c83e2d9dfab6008d8df9ba63aab"), .hn = hx("95edab0a7777e09c30514561"), .ak = hx("66992f2f134e10095469e656dd7117e0"), .an = hx("a5efd9b2edf31ce95eab1e18") },
    };
    for (cases) |c| {
        inline for (.{ RatchetKind.handshake, RatchetKind.application }) |kind| {
            var r = ratchetInit(enc, c.leaf, 8, kind);
            var key: [16]u8 = undefined;
            var nonce: [12]u8 = undefined;
            var g: u32 = 0;
            while (g <= c.gen) : (g += 1) ratchetAdvance(&r, &key, &nonce);
            try std.testing.expectEqual(c.gen + 1, r.generation);
            const want_key = if (kind == .handshake) c.hk else c.ak;
            const want_nonce = if (kind == .handshake) c.hn else c.an;
            try std.testing.expectEqualSlices(u8, &want_key, &key);
            try std.testing.expectEqualSlices(u8, &want_nonce, &nonce);
            r.wipe();
        }
    }
}

test "interop secret-tree: the single-leaf tree and sender-data keys" {
    // One leaf: the root IS the leaf; no tree expansion happens.
    const enc = hx("d69fcc35969e94680461974bd26c7cda7594cbf45985c4bf668c3b3118b765ab");
    var r = ratchetInit(enc, 0, 1, .handshake);
    var key: [16]u8 = undefined;
    var nonce: [12]u8 = undefined;
    ratchetAdvance(&r, &key, &nonce);
    try std.testing.expectEqualSlices(u8, &hx("a2d6b8a9255478e9b79a076872ae3563"), &key);
    try std.testing.expectEqualSlices(u8, &hx("8e8fc08a4eb5189b7b558527"), &nonce);

    // Sender-data key/nonce, bound to the ciphertext sample.
    const ct = hx("156f2eb3fa482cff20e3a090c267ce6481d4a0976aee2adb921d70ae8a04a6494339462ac049f185e7184d8245270e54e68b72bd5df66800367c50e423cafec0260ac4dc743c24cabfc6060fc5");
    var sd_key: [16]u8 = undefined;
    var sd_nonce: [12]u8 = undefined;
    senderDataKeyNonce(
        hx("95684b805e1bbd9c71d1abaf8a1930c12112b9a06c12db937970be5bbb916573"),
        &ct,
        &sd_key,
        &sd_nonce,
    );
    try std.testing.expectEqualSlices(u8, &hx("92667d9c889a6b768c157538c0a79fed"), &sd_key);
    try std.testing.expectEqualSlices(u8, &hx("362785b1cc8bc775fcc216e7"), &sd_nonce);
}
