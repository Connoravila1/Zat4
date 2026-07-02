//! B1 classification: CORE (pure). MLS for two — RFC 9420 restricted to the
//! two-member case (ZAT_CHAT_ROADMAP slice C5). This is the deep module
//! (D2): a small interface — `createGroup / generateKeyPackage / addPeer /
//! join / encrypt / receive / commit` — over plain byte slices, with every
//! byte of entropy passed in as a parameter (B3: the shell owns randomness
//! and the clock; that is also what makes the interop vectors runnable).
//!
//! The cipher suite is SEALED here (D1): suite 0x0001 (X25519 / AES-128-GCM
//! / SHA-256 / Ed25519) — every component is in std and every published
//! interop vector applies. The HPKE layer is comptime (`hpke.Suite`), so
//! flipping the production default to the X-Wing PQ suite (proven in
//! core/xwing.zig) is a contained change once vectors exist for it.
//!
//! Scope guard (F4): the tree is the N-leaf tree's two-leaf degenerate case
//! ONLY where that costs nothing (tree hashing is generic over the array
//! representation because it is just hashing); everything stateful — the
//! ratchet tree, UpdatePath creation/processing, parent-hash validation —
//! is built for exactly two leaves. Group machinery (proposals by
//! reference, removes, PSKs, external commits) is REFUSED at parse, not
//! half-honored. v1 also assumes in-order delivery per sender (the relay's
//! mailboxes are FIFO): a skipped generation's keys are derived and
//! discarded, never stored.
//!
//! Forward secrecy is deletion actually happening: every epoch advance
//! wipes the old EpochSecrets and both members' ratchets in place before
//! the new ones are installed (the C4 wipe points), and transient key
//! material is secureZero'd at release (the project convention).
//!
//! Lifetime NOT checked here: validating a KeyPackage's notBefore/notAfter
//! needs a clock, which the core must not read (B4) — `addPeer` takes
//! `now` as a parameter and checks it there.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const Sha256 = std.crypto.hash.sha2.Sha256;
const HmacSha256 = std.crypto.auth.hmac.sha2.HmacSha256;
const Ed25519 = std.crypto.sign.Ed25519;
const wire = @import("mls_wire.zig");
const schedule = @import("mls_schedule.zig");
const hpke = @import("hpke.zig");

/// The sealed suite: MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519.
pub const cipher_suite_id: u16 = 0x0001;
const HpkeSuite = hpke.Suite(hpke.DhKemX25519, hpke.AeadAes128Gcm);
const Kem = hpke.DhKemX25519;
const Aead = std.crypto.aead.aes_gcm.Aes128Gcm;
const Secret = schedule.Secret;
const hash_len = schedule.secret_len; // 32
const key_len = Aead.key_length; // 16
const nonce_len = Aead.nonce_length; // 12
const tag_len = Aead.tag_length; // 16
const pk_len = 32; // X25519 and Ed25519 public keys
const sig_len = 64; // Ed25519 signature

/// How far ahead of the local ratchet a received generation may run. In-
/// order delivery makes >0 rare (a lost message); the cap bounds the work
/// a hostile generation number can demand (E2).
const max_generation_skip: u32 = 1024;

pub const MlsError = wire.ParseError || wire.WriteError || error{
    /// A persisted group blob that is not a group blob (M1 restore).
    BadMessage,
    UnsupportedPsk,
    MissingGroupBinding,
    BadKey,
    BadSignature,
    BadKeyPackage,
    WrongSuite,
    Expired,
    UnknownKeyPackage,
    UnsupportedGroupSize,
    MissingRatchetTree,
    TreeHashMismatch,
    ParentHashMismatch,
    PathKeyMismatch,
    BadConfirmationTag,
    WrongGroup,
    WrongEpoch,
    BadSenderData,
    StaleGeneration,
    GenerationTooFar,
    DecryptFailed,
    UnexpectedMessage,
    UnsupportedCommit,
    WrongState,
    MessageLimitReached,
};

// ---------------------------------------------------------------------------
// Labeled crypto primitives (§5.1–§5.2): SignWithLabel, EncryptWithLabel,
// RefHash. Each prefixes "MLS 1.0 " so a signature or ciphertext made for
// one purpose can never be replayed as another.
// ---------------------------------------------------------------------------

/// SignContent/EncryptContext share one shape: vector("MLS 1.0 "+Label)
/// followed by vector(Content).
fn appendLabeled(gpa: Allocator, out: *std.ArrayList(u8), label: []const u8, content: []const u8) MlsError!void {
    var lb: [4]u8 = undefined;
    try out.appendSlice(gpa, wire.varintBytes(&lb, @intCast(8 + label.len)) catch return error.ValueTooLarge);
    try out.appendSlice(gpa, "MLS 1.0 ");
    try out.appendSlice(gpa, label);
    try wire.writeVector(gpa, out, content);
}

fn signWithLabel(gpa: Allocator, sig_seed: [32]u8, label: []const u8, content: []const u8) MlsError![sig_len]u8 {
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try appendLabeled(gpa, &buf, label, content);
    const kp = Ed25519.KeyPair.generateDeterministic(sig_seed) catch return error.BadKey;
    const sig = kp.sign(buf.items, null) catch return error.BadKey;
    return sig.toBytes();
}

fn verifyWithLabel(gpa: Allocator, pub_key: [pk_len]u8, label: []const u8, content: []const u8, sig: []const u8) MlsError!void {
    if (sig.len != sig_len) return error.BadSignature;
    var buf: std.ArrayList(u8) = .empty;
    defer buf.deinit(gpa);
    try appendLabeled(gpa, &buf, label, content);
    const pk = Ed25519.PublicKey.fromBytes(pub_key) catch return error.BadKey;
    Ed25519.Signature.fromBytes(sig[0..sig_len].*).verify(buf.items, pk) catch return error.BadSignature;
}

/// RefHash (§5.2) — streaming, allocation-free.
fn refHash(label: []const u8, value: []const u8) [hash_len]u8 {
    var h = Sha256.init(.{});
    var b: [4]u8 = undefined;
    h.update(wire.varintBytes(&b, @intCast(label.len)) catch unreachable); // labels are short
    h.update(label);
    h.update(wire.varintBytes(&b, @intCast(@min(value.len, wire.varint_max))) catch unreachable);
    h.update(value);
    var out: [hash_len]u8 = undefined;
    h.final(&out);
    return out;
}

/// MakeKeyPackageRef (§5.2) over the encoded KeyPackage.
pub fn keyPackageRef(key_package_bytes: []const u8) [hash_len]u8 {
    return refHash("MLS 1.0 KeyPackage Reference", key_package_bytes);
}

/// EncryptWithLabel (§5.1.3): HPKE base-mode seal with the labeled context
/// as info. Appends kem_output nothing — returns enc; ciphertext lands in
/// `out_ct` (plaintext.len + tag).
fn encryptWithLabel(
    gpa: Allocator,
    pub_key: [pk_len]u8,
    label: []const u8,
    context: []const u8,
    plaintext: []const u8,
    encap_seed: [Kem.Nes]u8,
    out_ct: *std.ArrayList(u8),
) MlsError![pk_len]u8 {
    var info: std.ArrayList(u8) = .empty;
    defer info.deinit(gpa);
    try appendLabeled(gpa, &info, label, context);
    var snd = HpkeSuite.setupBaseS(encap_seed, pub_key, info.items) catch return error.BadKey;
    defer HpkeSuite.wipe(&snd.ctx);
    const start = out_ct.items.len;
    try out_ct.resize(gpa, start + plaintext.len + tag_len);
    HpkeSuite.seal(&snd.ctx, out_ct.items[start..], plaintext, "") catch return error.MessageLimitReached;
    return snd.enc;
}

/// DecryptWithLabel (§5.1.3). `out` must be ciphertext.len - tag.
fn decryptWithLabel(
    gpa: Allocator,
    priv_key: [pk_len]u8,
    label: []const u8,
    context: []const u8,
    kem_output: []const u8,
    ciphertext: []const u8,
    out: []u8,
) MlsError!void {
    if (kem_output.len != Kem.Nenc) return error.BadKey;
    if (ciphertext.len < tag_len or out.len != ciphertext.len - tag_len) return error.DecryptFailed;
    var info: std.ArrayList(u8) = .empty;
    defer info.deinit(gpa);
    try appendLabeled(gpa, &info, label, context);
    var ctx = HpkeSuite.setupBaseR(kem_output[0..Kem.Nenc].*, priv_key, info.items) catch return error.BadKey;
    defer HpkeSuite.wipe(&ctx);
    HpkeSuite.open(&ctx, out, ciphertext, "") catch return error.DecryptFailed;
}

// ---------------------------------------------------------------------------
// Tree hashing (§7.8) — generic over the array representation, because a
// tree hash is just hashing; and parent hashes (§7.9) for the two-leaf
// shape, which is the only tree this module ever holds.
// ---------------------------------------------------------------------------

/// One slot of the array-representation tree: the node's serialized body
/// (LeafNode or ParentNode wire bytes) or blank.
/// A7.2: cold struct, size guard waived — scratch view, per-parse arena.
const TreeSlot = struct {
    kind: u8, // wire.node_type_leaf / node_type_parent
    bytes: []const u8,
};

fn treeLevel(x: u32) u5 {
    return @intCast(@ctz(~x));
}

fn treeRootIndex(n_nodes: u32) u32 {
    assert(n_nodes > 0 and n_nodes % 2 == 1);
    return (@as(u32, 1) << @intCast(31 - @clz(n_nodes))) - 1;
}

/// LeafNodeHashInput under TreeHashInput (§7.8), streaming.
fn leafHash(leaf_index: u32, leaf_bytes: ?[]const u8) [hash_len]u8 {
    var h = Sha256.init(.{});
    h.update(&[1]u8{wire.node_type_leaf});
    var idx: [4]u8 = undefined;
    std.mem.writeInt(u32, &idx, leaf_index, .big);
    h.update(&idx);
    if (leaf_bytes) |lb| {
        h.update(&[1]u8{1});
        h.update(lb);
    } else {
        h.update(&[1]u8{0});
    }
    var out: [hash_len]u8 = undefined;
    h.final(&out);
    return out;
}

/// ParentNodeHashInput under TreeHashInput (§7.8), streaming.
fn parentHashNode(parent_bytes: ?[]const u8, left: [hash_len]u8, right: [hash_len]u8) [hash_len]u8 {
    var h = Sha256.init(.{});
    h.update(&[1]u8{wire.node_type_parent});
    if (parent_bytes) |pb| {
        h.update(&[1]u8{1});
        h.update(pb);
    } else {
        h.update(&[1]u8{0});
    }
    const vec32 = [1]u8{hash_len}; // varint(32) is a single byte
    h.update(&vec32);
    h.update(&left);
    h.update(&vec32);
    h.update(&right);
    var out: [hash_len]u8 = undefined;
    h.final(&out);
    return out;
}

/// The tree hash of node `x` over the array representation (recursive; the
/// depth is bounded by the 32-bit index space).
fn treeNodeHash(slots: []const ?TreeSlot, x: u32) [hash_len]u8 {
    if (x % 2 == 0) {
        const bytes: ?[]const u8 = if (slots[x]) |s| s.bytes else null;
        return leafHash(x / 2, bytes);
    }
    const step = @as(u32, 1) << (treeLevel(x) - 1);
    const left = treeNodeHash(slots, x ^ step);
    const right = treeNodeHash(slots, x ^ (step * 3));
    const bytes: ?[]const u8 = if (slots[x]) |s| s.bytes else null;
    return parentHashNode(bytes, left, right);
}

/// Parse a serialized `optional<Node> ratchet_tree<V>` into slots (arena-
/// allocated), extended with trailing blanks to full 2^(d+1)-1 width per
/// §12.4.3.3 (which also forbids a trailing blank on the wire).
fn parseTreeSlots(arena: Allocator, extension_data: []const u8) MlsError![]?TreeSlot {
    var it = try wire.ratchetTreeIter(extension_data);
    var list: std.ArrayList(?TreeSlot) = .empty;
    while (true) {
        const start = it.r.pos;
        const slot = (try it.next()) orelse break;
        if (slot) |node| {
            // Skip the presence byte + node_type byte; keep the node body.
            try list.append(arena, .{
                .kind = switch (node) {
                    .leaf => wire.node_type_leaf,
                    .parent => wire.node_type_parent,
                },
                .bytes = it.r.bytes[start + 2 .. it.r.pos],
            });
        } else {
            try list.append(arena, null);
        }
    }
    if (list.items.len == 0) return error.MalformedVector;
    if (list.items[list.items.len - 1] == null) return error.MalformedVector;
    // Extend to the next 2^(d+1)-1 width with blanks.
    while (!std.math.isPowerOfTwo(list.items.len + 1)) try list.append(arena, null);
    return list.items;
}

/// The root ParentNode of OUR two-leaf tree, serialized: a fresh path-set
/// root has an empty parent hash and no unmerged leaves.
fn rootParentBytes(root_pub: [pk_len]u8) [pk_len + 3]u8 {
    return [1]u8{pk_len} ++ root_pub ++ [2]u8{ 0, 0 };
}

/// ParentHashInput (§7.9) for the two-leaf tree's root: parent_hash is
/// empty (the root has no parent) and the original sibling tree hash is
/// the non-committing leaf's hash.
fn parentHashRoot2(root_pub: [pk_len]u8, sibling_leaf_hash: [hash_len]u8) [hash_len]u8 {
    var h = Sha256.init(.{});
    const vec32 = [1]u8{pk_len};
    h.update(&vec32);
    h.update(&root_pub);
    h.update(&[1]u8{0}); // parent_hash: zero-length vector
    h.update(&vec32);
    h.update(&sibling_leaf_hash);
    var out: [hash_len]u8 = undefined;
    h.final(&out);
    return out;
}

/// The two-leaf tree hash: root parent over both leaf hashes.
fn treeHash2(root_pub: [pk_len]u8, leaf0_hash: [hash_len]u8, leaf1_hash: [hash_len]u8) [hash_len]u8 {
    const pb = rootParentBytes(root_pub);
    return parentHashNode(&pb, leaf0_hash, leaf1_hash);
}

// ---------------------------------------------------------------------------
// Transcript hashes (§8.2) and the confirmation tag (§8.1).
// ---------------------------------------------------------------------------

fn transcriptConfirmed(interim_prev: []const u8, confirmed_input: []const u8) [hash_len]u8 {
    var h = Sha256.init(.{});
    h.update(interim_prev);
    h.update(confirmed_input);
    var out: [hash_len]u8 = undefined;
    h.final(&out);
    return out;
}

/// interim = Hash(confirmed || InterimTranscriptHashInput{MAC tag}) — the
/// MAC is a wire vector, so its one-byte length prefix is included.
fn transcriptInterim(confirmed: []const u8, confirmation_tag: []const u8) [hash_len]u8 {
    var h = Sha256.init(.{});
    h.update(confirmed);
    var b: [4]u8 = undefined;
    h.update(wire.varintBytes(&b, @intCast(confirmation_tag.len)) catch unreachable);
    h.update(confirmation_tag);
    var out: [hash_len]u8 = undefined;
    h.final(&out);
    return out;
}

fn confirmTag(confirmation_key: Secret, confirmed_transcript_hash: []const u8) [hash_len]u8 {
    var out: [hash_len]u8 = undefined;
    var h = HmacSha256.init(&confirmation_key);
    h.update(confirmed_transcript_hash);
    h.final(&out);
    return out;
}

fn tagEql(want: [hash_len]u8, got: []const u8) bool {
    if (got.len != hash_len) return false;
    return std.crypto.timing_safe.eql([hash_len]u8, want, got[0..hash_len].*);
}

// ---------------------------------------------------------------------------
// Message protection (§6.3): PrivateMessage protect/unprotect, plus the
// PublicMessage pair (§6.2) the interop vectors also pin. These are free
// functions over plain facts so the vectors can drive them without a Group.
// ---------------------------------------------------------------------------

/// What protection needs to know about the group at one instant.
/// A7.2: cold struct, size guard waived — transient view.
const GroupFacts = struct {
    group_id: []const u8,
    epoch: u64,
    /// The serialized current GroupContext (what signatures bind).
    gc_bytes: []const u8,
};

fn protectPrivate(
    gpa: Allocator,
    f: GroupFacts,
    my_leaf: u32,
    sig_seed: [32]u8,
    body: wire.FramedBody,
    confirmation_tag: ?[]const u8,
    ratchet: *schedule.RatchetSecret,
    sender_data_secret: Secret,
    reuse_guard: [4]u8,
    pad_len: usize,
) MlsError![]u8 {
    const content_type: wire.ContentType = body;
    assert((content_type == .commit) == (confirmation_tag != null));

    const fc: wire.FramedContent = .{
        .group_id = f.group_id,
        .epoch = f.epoch,
        .sender = .{ .member = my_leaf },
        .authenticated_data = "",
        .body = body,
    };

    // Sign the TBS (bound to the current GroupContext).
    var tbs: std.ArrayList(u8) = .empty;
    defer tbs.deinit(gpa);
    try wire.serializeFramedContentTBS(gpa, &tbs, wire.wire_private_message, fc, f.gc_bytes);
    const sig = try signWithLabel(gpa, sig_seed, "FramedContentTBS", tbs.items);

    // PrivateMessageContent: body + auth + zero padding.
    var pt: std.ArrayList(u8) = .empty;
    defer {
        std.crypto.secureZero(u8, pt.items);
        pt.deinit(gpa);
    }
    const pc: wire.PrivateContent = .{
        .body = body,
        .auth = .{ .signature = &sig, .confirmation_tag = confirmation_tag },
    };
    try pc.write(gpa, &pt, pad_len);

    // This generation's key + nonce; the chain steps forward in place.
    const generation = ratchet.generation;
    var key: [key_len]u8 = undefined;
    var nonce: [nonce_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &key);
    defer std.crypto.secureZero(u8, &nonce);
    schedule.ratchetAdvance(ratchet, &key, &nonce);
    for (nonce[0..4], reuse_guard) |*n, g| n.* ^= g;

    var aad: std.ArrayList(u8) = .empty;
    defer aad.deinit(gpa);
    try wire.serializePrivateContentAAD(gpa, &aad, f.group_id, f.epoch, content_type, "");

    const ct = try gpa.alloc(u8, pt.items.len + tag_len);
    defer gpa.free(ct);
    Aead.encrypt(ct[0..pt.items.len], ct[pt.items.len..][0..tag_len], pt.items, aad.items, nonce, key);

    // SenderData, sealed under a key bound to the ciphertext sample.
    const sd: wire.SenderData = .{ .leaf_index = my_leaf, .generation = generation, .reuse_guard = reuse_guard };
    const sd_pt = sd.encode();
    var sd_key: [key_len]u8 = undefined;
    var sd_nonce: [nonce_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &sd_key);
    defer std.crypto.secureZero(u8, &sd_nonce);
    schedule.senderDataKeyNonce(sender_data_secret, ct, &sd_key, &sd_nonce);
    var sd_aad: std.ArrayList(u8) = .empty;
    defer sd_aad.deinit(gpa);
    try wire.serializeSenderDataAAD(gpa, &sd_aad, f.group_id, f.epoch, content_type);
    var esd: [wire.SenderData.encoded_length + tag_len]u8 = undefined;
    Aead.encrypt(esd[0..sd_pt.len], esd[sd_pt.len..][0..tag_len], &sd_pt, sd_aad.items, sd_nonce, sd_key);

    const pm: wire.PrivateMessage = .{
        .group_id = f.group_id,
        .epoch = f.epoch,
        .content_type = content_type,
        .authenticated_data = "",
        .encrypted_sender_data = &esd,
        .ciphertext = ct,
    };
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try (wire.MlsMessage{ .private_message = pm }).write(gpa, &out);
    return try out.toOwnedSlice(gpa);
}

/// A decrypted PrivateMessage: the plaintext buffer plus views into it.
/// A7.2: cold struct, size guard waived — transient, consumed immediately.
const Opened = struct {
    plaintext: []u8,
    body: wire.FramedBody,
    auth: wire.FramedContentAuthData,
    sender_leaf: u32,

    fn deinit(o: *Opened, gpa: Allocator) void {
        std.crypto.secureZero(u8, o.plaintext);
        gpa.free(o.plaintext);
    }
};

fn unprotectPrivate(
    gpa: Allocator,
    f: GroupFacts,
    pm: wire.PrivateMessage,
    expected_sender: u32,
    sender_sig_pub: [pk_len]u8,
    handshake_ratchet: *schedule.RatchetSecret,
    application_ratchet: *schedule.RatchetSecret,
    sender_data_secret: Secret,
) MlsError!Opened {
    if (!std.mem.eql(u8, pm.group_id, f.group_id)) return error.WrongGroup;
    if (pm.epoch != f.epoch) return error.WrongEpoch;
    if (pm.encrypted_sender_data.len != wire.SenderData.encoded_length + tag_len) return error.BadSenderData;

    // Open the sender data first — it names the ratchet and generation.
    var sd_key: [key_len]u8 = undefined;
    var sd_nonce: [nonce_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &sd_key);
    defer std.crypto.secureZero(u8, &sd_nonce);
    schedule.senderDataKeyNonce(sender_data_secret, pm.ciphertext, &sd_key, &sd_nonce);
    var sd_aad: std.ArrayList(u8) = .empty;
    defer sd_aad.deinit(gpa);
    try wire.serializeSenderDataAAD(gpa, &sd_aad, pm.group_id, pm.epoch, pm.content_type);
    var sd_pt: [wire.SenderData.encoded_length]u8 = undefined;
    Aead.decrypt(
        &sd_pt,
        pm.encrypted_sender_data[0..wire.SenderData.encoded_length],
        pm.encrypted_sender_data[wire.SenderData.encoded_length..][0..tag_len].*,
        sd_aad.items,
        sd_nonce,
        sd_key,
    ) catch return error.BadSenderData;
    const sd = wire.SenderData.parse(&sd_pt) catch return error.BadSenderData;
    if (sd.leaf_index != expected_sender) return error.BadSenderData;

    const ratchet = if (pm.content_type == .application) application_ratchet else handshake_ratchet;
    if (sd.generation < ratchet.generation) return error.StaleGeneration;
    if (sd.generation - ratchet.generation > max_generation_skip) return error.GenerationTooFar;

    // Walk the chain to the named generation. Skipped generations' keys are
    // derived and immediately destroyed — v1 stores no out-of-order keys.
    var key: [key_len]u8 = undefined;
    var nonce: [nonce_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &key);
    defer std.crypto.secureZero(u8, &nonce);
    while (ratchet.generation <= sd.generation) {
        schedule.ratchetAdvance(ratchet, &key, &nonce);
    }
    for (nonce[0..4], sd.reuse_guard) |*n, g| n.* ^= g;

    var aad: std.ArrayList(u8) = .empty;
    defer aad.deinit(gpa);
    try wire.serializePrivateContentAAD(gpa, &aad, pm.group_id, pm.epoch, pm.content_type, pm.authenticated_data);

    if (pm.ciphertext.len < tag_len) return error.DecryptFailed;
    const pt = try gpa.alloc(u8, pm.ciphertext.len - tag_len);
    errdefer {
        std.crypto.secureZero(u8, pt);
        gpa.free(pt);
    }
    Aead.decrypt(
        pt,
        pm.ciphertext[0..pt.len],
        pm.ciphertext[pt.len..][0..tag_len].*,
        aad.items,
        nonce,
        key,
    ) catch return error.DecryptFailed;

    const pc = try wire.PrivateContent.parse(pt, pm.content_type);

    // Verify the content signature against the sender's leaf key.
    const fc: wire.FramedContent = .{
        .group_id = pm.group_id,
        .epoch = pm.epoch,
        .sender = .{ .member = sd.leaf_index },
        .authenticated_data = pm.authenticated_data,
        .body = pc.body,
    };
    var tbs: std.ArrayList(u8) = .empty;
    defer tbs.deinit(gpa);
    try wire.serializeFramedContentTBS(gpa, &tbs, wire.wire_private_message, fc, f.gc_bytes);
    try verifyWithLabel(gpa, sender_sig_pub, "FramedContentTBS", tbs.items, pc.auth.signature);

    return .{ .plaintext = pt, .body = pc.body, .auth = pc.auth, .sender_leaf = sd.leaf_index };
}

fn protectPublic(
    gpa: Allocator,
    f: GroupFacts,
    my_leaf: u32,
    sig_seed: [32]u8,
    membership_key: Secret,
    body: wire.FramedBody,
    confirmation_tag: ?[]const u8,
) MlsError![]u8 {
    // Application data MUST be sent as PrivateMessage (§15.2).
    if (body == .application) return error.UnexpectedMessage;
    assert((body == .commit) == (confirmation_tag != null));

    const fc: wire.FramedContent = .{
        .group_id = f.group_id,
        .epoch = f.epoch,
        .sender = .{ .member = my_leaf },
        .authenticated_data = "",
        .body = body,
    };
    var tbs: std.ArrayList(u8) = .empty;
    defer tbs.deinit(gpa);
    try wire.serializeFramedContentTBS(gpa, &tbs, wire.wire_public_message, fc, f.gc_bytes);
    const sig = try signWithLabel(gpa, sig_seed, "FramedContentTBS", tbs.items);

    // membership_tag = MAC(membership_key, AuthenticatedContentTBM) —
    // the TBS followed by the auth data (§6.2).
    const auth: wire.FramedContentAuthData = .{ .signature = &sig, .confirmation_tag = confirmation_tag };
    var auth_bytes: std.ArrayList(u8) = .empty;
    defer auth_bytes.deinit(gpa);
    try auth.write(gpa, &auth_bytes);
    var mtag: [hash_len]u8 = undefined;
    var h = HmacSha256.init(&membership_key);
    h.update(tbs.items);
    h.update(auth_bytes.items);
    h.final(&mtag);

    const pm: wire.PublicMessage = .{
        .content = fc,
        .auth = auth,
        .membership_tag = &mtag,
    };
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try (wire.MlsMessage{ .public_message = pm }).write(gpa, &out);
    return try out.toOwnedSlice(gpa);
}

/// Verify a PublicMessage's signature + membership tag. The content is in
/// the clear on the wire; this only authenticates it.
fn unprotectPublic(
    gpa: Allocator,
    f: GroupFacts,
    pm: wire.PublicMessage,
    sender_sig_pub: [pk_len]u8,
    membership_key: Secret,
) MlsError!void {
    if (!std.mem.eql(u8, pm.content.group_id, f.group_id)) return error.WrongGroup;
    if (pm.content.epoch != f.epoch) return error.WrongEpoch;
    if (pm.content.sender != .member) return error.UnexpectedMessage;

    var tbs: std.ArrayList(u8) = .empty;
    defer tbs.deinit(gpa);
    try wire.serializeFramedContentTBS(gpa, &tbs, wire.wire_public_message, pm.content, f.gc_bytes);
    try verifyWithLabel(gpa, sender_sig_pub, "FramedContentTBS", tbs.items, pm.auth.signature);

    var auth_bytes: std.ArrayList(u8) = .empty;
    defer auth_bytes.deinit(gpa);
    try pm.auth.write(gpa, &auth_bytes);
    var want: [hash_len]u8 = undefined;
    var h = HmacSha256.init(&membership_key);
    h.update(tbs.items);
    h.update(auth_bytes.items);
    h.final(&want);
    if (!tagEql(want, pm.membership_tag orelse return error.BadSignature)) return error.BadSignature;
}

// ---------------------------------------------------------------------------
// Leaf building. The v1 capabilities: mls10, this suite, basic credentials,
// nothing else.
// ---------------------------------------------------------------------------

const own_capabilities: wire.Capabilities = .{
    .versions = .{ .raw = "\x00\x01" }, // mls10
    .cipher_suites = .{ .raw = "\x00\x01" }, // this suite (sealed above)
    .credentials = .{ .raw = "\x00\x01" }, // basic
};

/// Serialize + sign a LeafNode (any source; commit/update sources carry the
/// group binding in their TBS).
fn buildLeaf(
    gpa: Allocator,
    ln_unsigned: wire.LeafNode,
    sig_seed: [32]u8,
    group: ?wire.GroupBinding,
) MlsError![]u8 {
    var ln = ln_unsigned;
    ln.signature = "";
    var tbs: std.ArrayList(u8) = .empty;
    defer tbs.deinit(gpa);
    try wire.serializeLeafNodeTBS(gpa, &tbs, ln, group);
    const sig = try signWithLabel(gpa, sig_seed, "LeafNodeTBS", tbs.items);
    ln.signature = &sig;
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try ln.write(gpa, &out);
    return try out.toOwnedSlice(gpa);
}

/// A commit rebuilds the committer's own leaf: same credential and signature
/// key, fresh encryption key, source=commit with the new parent hash, re-
/// signed under the group binding (§7.5).
fn rebuildCommitLeaf(
    gpa: Allocator,
    old_leaf_bytes: []const u8,
    new_enc_pub: [pk_len]u8,
    parent_hash: [hash_len]u8,
    group_id: []const u8,
    leaf_index: u32,
    sig_seed: [32]u8,
) MlsError![]u8 {
    var r = wire.Reader.init(old_leaf_bytes);
    var ln = try wire.LeafNode.parse(&r);
    try r.finish();
    ln.encryption_key = &new_enc_pub;
    ln.source = .{ .commit = &parent_hash };
    return buildLeaf(gpa, ln, sig_seed, .{ .group_id = group_id, .leaf_index = leaf_index });
}

/// Validate one leaf as §7.3 requires of a joiner: basic credential (the
/// parser enforces), sane key widths, and the signature under the right TBS.
fn validateLeaf(
    gpa: Allocator,
    ln: wire.LeafNode,
    leaf_index: u32,
    group_id: []const u8,
) MlsError!void {
    if (ln.encryption_key.len != pk_len or ln.signature_key.len != pk_len) return error.BadKeyPackage;
    var lv = ln;
    lv.signature = "";
    var tbs: std.ArrayList(u8) = .empty;
    defer tbs.deinit(gpa);
    try wire.serializeLeafNodeTBS(gpa, &tbs, lv, switch (ln.source) {
        .key_package => null,
        .update, .commit => .{ .group_id = group_id, .leaf_index = leaf_index },
    });
    try verifyWithLabel(gpa, ln.signature_key[0..pk_len].*, "LeafNodeTBS", tbs.items, ln.signature);
}

// ---------------------------------------------------------------------------
// KeyPackage generation (what U6 publishes) and validation.
// ---------------------------------------------------------------------------

/// A7.2: cold struct, size guard waived — one per enrollment, transient.
pub const KeyPackageBundle = struct {
    /// MLSMessage(KeyPackage) wire bytes — the publishable object.
    bytes: []u8,
    init_priv: [pk_len]u8,
    enc_priv: [pk_len]u8,

    pub fn deinit(b: *KeyPackageBundle, gpa: Allocator) void {
        std.crypto.secureZero(u8, &b.init_priv);
        std.crypto.secureZero(u8, &b.enc_priv);
        gpa.free(b.bytes);
        b.bytes = &.{};
    }
};

/// A7.2: cold struct, size guard waived — entropy carrier, transient.
pub const KeyPackageEntropy = struct {
    init_seed: [32]u8,
    enc_seed: [32]u8,
};

pub fn generateKeyPackage(
    gpa: Allocator,
    identity: []const u8,
    sig_seed: [32]u8,
    not_before: u64,
    not_after: u64,
    ep: KeyPackageEntropy,
) MlsError!KeyPackageBundle {
    const init_kp = Kem.deriveKeyPair(&ep.init_seed) catch return error.BadKey;
    const enc_kp = Kem.deriveKeyPair(&ep.enc_seed) catch return error.BadKey;
    const sig_kp = Ed25519.KeyPair.generateDeterministic(sig_seed) catch return error.BadKey;
    const sig_pub = sig_kp.public_key.toBytes();

    const leaf_bytes = try buildLeaf(gpa, .{
        .encryption_key = &enc_kp.pk,
        .signature_key = &sig_pub,
        .credential = .{ .identity = identity },
        .capabilities = own_capabilities,
        .source = .{ .key_package = .{ .not_before = not_before, .not_after = not_after } },
        .extensions_raw = "",
        .signature = "",
    }, sig_seed, null);
    defer gpa.free(leaf_bytes);

    var lr = wire.Reader.init(leaf_bytes);
    var kp: wire.KeyPackage = .{
        .version = wire.protocol_version_mls10,
        .cipher_suite = cipher_suite_id,
        .init_key = &init_kp.pk,
        .leaf_node = try wire.LeafNode.parse(&lr),
        .extensions_raw = "",
        .signature = "",
    };
    var tbs: std.ArrayList(u8) = .empty;
    defer tbs.deinit(gpa);
    try wire.serializeKeyPackageTBS(gpa, &tbs, kp);
    const sig = try signWithLabel(gpa, sig_seed, "KeyPackageTBS", tbs.items);
    kp.signature = &sig;

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try (wire.MlsMessage{ .key_package = kp }).write(gpa, &out);
    return .{
        .bytes = try out.toOwnedSlice(gpa),
        .init_priv = init_kp.sk,
        .enc_priv = enc_kp.sk,
    };
}

/// Validate a counterparty's MLSMessage(KeyPackage) per §10.1: suite,
/// version, both signatures, key widths, init/encryption distinctness, and
/// the lifetime against the caller-supplied clock.
fn validateKeyPackage(gpa: Allocator, kp: wire.KeyPackage, kp_body: []const u8, now: u64) MlsError!void {
    if (kp.version != wire.protocol_version_mls10) return error.BadKeyPackage;
    if (kp.cipher_suite != cipher_suite_id) return error.WrongSuite;
    if (kp.init_key.len != pk_len) return error.BadKeyPackage;
    if (std.mem.eql(u8, kp.init_key, kp.leaf_node.encryption_key)) return error.BadKeyPackage;
    if (kp.leaf_node.source != .key_package) return error.BadKeyPackage;
    const lt = kp.leaf_node.source.key_package;
    if (now < lt.not_before or now > lt.not_after) return error.Expired;
    try validateLeaf(gpa, kp.leaf_node, 1, "");
    // KeyPackageTBS = the body minus the trailing signature vector.
    var sig_wire: [4]u8 = undefined;
    const sv = wire.varintBytes(&sig_wire, @intCast(kp.signature.len)) catch return error.BadKeyPackage;
    const tbs_len = kp_body.len - sv.len - kp.signature.len;
    if (kp.leaf_node.signature_key.len != pk_len) return error.BadKeyPackage;
    try verifyWithLabel(gpa, kp.leaf_node.signature_key[0..pk_len].*, "KeyPackageTBS", kp_body[0..tbs_len], kp.signature);
}

/// A7.2: cold struct, size guard waived — transient fetch-validation view.
pub const KeyPackageInfo = struct {
    /// The leaf's signature key — the ANCHOR public key (C6): what the
    /// keyPackage record's DID binding verifies against.
    signature_key: [pk_len]u8,
    /// The leaf credential's identity (borrows `msg_bytes`) — the DID.
    identity: []const u8,
    /// The KeyPackage's own lifetime end (seconds).
    not_after: u64,
};

/// Full structural + signature validation of an MLSMessage(KeyPackage) for
/// the key directory (U6 fetch): everything `addPeer` checks, without a
/// group. Returns the plain facts the record layer binds against — no wire
/// types cross this boundary (D3).
pub fn checkKeyPackage(gpa: Allocator, msg_bytes: []const u8, now: u64) MlsError!KeyPackageInfo {
    var kr = wire.Reader.init(msg_bytes);
    if (try kr.readU16() != wire.protocol_version_mls10) return error.UnsupportedVersion;
    if (try kr.readU16() != wire.wire_key_package) return error.UnexpectedMessage;
    const kp_body = msg_bytes[4..];
    const kp = try wire.KeyPackage.parseFrom(&kr);
    try kr.finish();
    try validateKeyPackage(gpa, kp, kp_body, now);
    if (kp.leaf_node.signature_key.len != pk_len) return error.BadKeyPackage;
    return .{
        .signature_key = kp.leaf_node.signature_key[0..pk_len].*,
        .identity = kp.leaf_node.credential.identity,
        .not_after = kp.leaf_node.source.key_package.not_after,
    };
}

// ---------------------------------------------------------------------------
// The group state. One instance per open conversation — hot by the tie-
// break rule, so it carries the guard.
// ---------------------------------------------------------------------------

const ratchet_handshake = 0;
const ratchet_application = 1;

pub const Group = struct {
    /// Owned copies (allocated): the group id, GroupContext extensions, and
    /// each leaf's serialized LeafNode (index 1 empty while still alone).
    group_id: []u8,
    gc_extensions: []u8,
    leaf_bytes: [2][]u8,
    /// The epoch secret table + both members' ratchets ([leaf][kind]).
    secrets: schedule.EpochSecrets,
    ratchets: [2][2]schedule.RatchetSecret,
    /// Hashes: confirmed transcript (empty at epoch 0 — see cth_len),
    /// interim transcript, and the current tree hash.
    confirmed_transcript_hash: [hash_len]u8,
    interim_hash: [hash_len]u8,
    tree_hash: [hash_len]u8,
    /// The two-leaf tree's root key pair and my private material.
    root_pub: [pk_len]u8,
    root_priv: [pk_len]u8,
    my_enc_priv: [pk_len]u8,
    sig_seed: [32]u8,
    /// Cached per-leaf public keys (parsed once at install time).
    leaf_sig_pub: [2][pk_len]u8,
    leaf_enc_pub: [2][pk_len]u8,
    epoch: u64,
    my_leaf: u32,
    cth_len: u8,
    root_present: bool,
    root_priv_present: bool,
    ratchets_live: bool,

    comptime {
        // 4 slices (64) + secrets (352) + 4 ratchets (144) + 3 hashes (96)
        // + 4 keys (128) + 4 cached pubs (128) + epoch (8) + my_leaf (4)
        // + 4 byte-flags, padded to pointer alignment. (A7)
        assert(@sizeOf(Group) == 928);
    }

    fn cthSlice(g: *const Group) []const u8 {
        return g.confirmed_transcript_hash[0..g.cth_len];
    }

    /// The current serialized GroupContext.
    fn writeGroupContext(g: *const Group, gpa: Allocator, out: *std.ArrayList(u8)) MlsError!void {
        try (wire.GroupContext{
            .version = wire.protocol_version_mls10,
            .cipher_suite = cipher_suite_id,
            .group_id = g.group_id,
            .epoch = g.epoch,
            .tree_hash = &g.tree_hash,
            .confirmed_transcript_hash = g.cthSlice(),
            .extensions_raw = g.gc_extensions,
        }).write(gpa, out);
    }

    /// Wipe the current epoch's secrets in place — forward secrecy is this
    /// deletion actually happening before the new epoch is installed.
    fn wipeEpoch(g: *Group) void {
        g.secrets.wipe();
        for (&g.ratchets) |*pair| for (pair) |*r| r.wipe();
    }

    fn installRatchets(g: *Group) void {
        for (0..2) |leaf| {
            g.ratchets[leaf][ratchet_handshake] = schedule.ratchetInit(g.secrets.encryption, @intCast(leaf), 2, .handshake);
            g.ratchets[leaf][ratchet_application] = schedule.ratchetInit(g.secrets.encryption, @intCast(leaf), 2, .application);
        }
        g.ratchets_live = true;
    }

    pub fn deinit(g: *Group, gpa: Allocator) void {
        g.wipeEpoch();
        std.crypto.secureZero(u8, &g.root_priv);
        std.crypto.secureZero(u8, &g.my_enc_priv);
        std.crypto.secureZero(u8, &g.sig_seed);
        gpa.free(g.group_id);
        gpa.free(g.gc_extensions);
        for (g.leaf_bytes) |lb| gpa.free(lb);
        g.* = undefined;
    }
};

/// A7.2: cold structs, size guards waived — entropy carriers, transient.
pub const CreateEntropy = struct {
    // A7.2: cold struct, size guard waived — entropy carrier, transient.
    group_id: [32]u8,
    enc_seed: [32]u8,
    epoch_secret: [32]u8,
};
pub const AddEntropy = struct {
    // A7.2: cold struct, size guard waived — entropy carrier, transient.
    enc_seed: [32]u8,
    path_secret: [32]u8,
    welcome_seed: [32]u8,
};
pub const CommitEntropy = struct {
    // A7.2: cold struct, size guard waived — entropy carrier, transient.
    enc_seed: [32]u8,
    path_secret: [32]u8,
    seal_seed: [32]u8,
    reuse_guard: [4]u8,
};
pub const JoinKeys = struct {
    // A7.2: cold struct, size guard waived — key carrier, transient.
    init_priv: [pk_len]u8,
    enc_priv: [pk_len]u8,
    sig_seed: [32]u8,
};

/// What `receive` yields. A7.2: cold union, size guard waived — transient.
pub const Received = union(enum) {
    /// A decrypted application message (allocated; caller owns).
    application: []u8,
    /// The peer's commit was applied; the group is in a new epoch.
    epoch_advanced,
};

// ---------------------------------------------------------------------------
// Group creation (§11): a one-member group at epoch 0 with a fresh random
// epoch secret. The interim transcript hash is seeded from a confirmation
// tag over the empty confirmed hash, as §11 instructs.
// ---------------------------------------------------------------------------

pub fn createGroup(gpa: Allocator, identity: []const u8, sig_seed: [32]u8, ep: CreateEntropy) MlsError!Group {
    const enc_kp = Kem.deriveKeyPair(&ep.enc_seed) catch return error.BadKey;
    const sig_kp = Ed25519.KeyPair.generateDeterministic(sig_seed) catch return error.BadKey;
    const sig_pub = sig_kp.public_key.toBytes();

    const leaf0 = try buildLeaf(gpa, .{
        .encryption_key = &enc_kp.pk,
        .signature_key = &sig_pub,
        .credential = .{ .identity = identity },
        .capabilities = own_capabilities,
        .source = .{ .key_package = .{ .not_before = 0, .not_after = std.math.maxInt(u64) } },
        .extensions_raw = "",
        .signature = "",
    }, sig_seed, null);
    errdefer gpa.free(leaf0);

    const group_id = try gpa.dupe(u8, &ep.group_id);
    errdefer gpa.free(group_id);
    const gc_extensions = try gpa.dupe(u8, "");
    errdefer gpa.free(gc_extensions);
    const leaf1_empty = try gpa.dupe(u8, "");

    const secrets = schedule.epochFromRaw(ep.epoch_secret);
    const tag = confirmTag(secrets.confirmation_key, "");

    var g: Group = .{
        .group_id = group_id,
        .gc_extensions = gc_extensions,
        .leaf_bytes = .{ leaf0, leaf1_empty },
        .secrets = secrets,
        .ratchets = undefined,
        .confirmed_transcript_hash = @splat(0),
        .interim_hash = transcriptInterim("", &tag),
        .tree_hash = leafHash(0, leaf0),
        .root_pub = @splat(0),
        .root_priv = @splat(0),
        .my_enc_priv = enc_kp.sk,
        .sig_seed = sig_seed,
        .leaf_sig_pub = .{ sig_pub, @splat(0) },
        .leaf_enc_pub = .{ enc_kp.pk, @splat(0) },
        .epoch = 0,
        .my_leaf = 0,
        .cth_len = 0,
        .root_present = false,
        .root_priv_present = false,
        .ratchets_live = false,
    };
    for (&g.ratchets) |*pair| for (pair) |*r| r.wipe();
    return g;
}

// ---------------------------------------------------------------------------
// Adding the second member (§12.4): an Add+path commit built and applied
// locally (there is nobody else to send it to), and the Welcome that
// carries the new epoch to the peer.
// ---------------------------------------------------------------------------

/// Add the peer's MLSMessage(KeyPackage) to the one-member group. Returns
/// the MLSMessage(Welcome) to deliver to them; the group advances to epoch
/// 1 with two leaves.
pub fn addPeer(gpa: Allocator, g: *Group, key_package_msg: []const u8, now: u64, ep: AddEntropy) MlsError![]u8 {
    if (g.ratchets_live or g.epoch != 0) return error.WrongState;

    // Parse + validate the peer's KeyPackage.
    var kr = wire.Reader.init(key_package_msg);
    if (try kr.readU16() != wire.protocol_version_mls10) return error.UnsupportedVersion;
    if (try kr.readU16() != wire.wire_key_package) return error.UnexpectedMessage;
    const kp_body = key_package_msg[4..];
    const kp = try wire.KeyPackage.parseFrom(&kr);
    try kr.finish();
    try validateKeyPackage(gpa, kp, kp_body, now);

    // The peer's leaf, serialized (canonical writers: byte-identical).
    var leaf1: std.ArrayList(u8) = .empty;
    defer leaf1.deinit(gpa);
    try kp.leaf_node.write(gpa, &leaf1);
    const leaf1_hash = leafHash(1, leaf1.items);

    // My path update: fresh leaf key pair, one path secret at the root.
    const enc_kp = Kem.deriveKeyPair(&ep.enc_seed) catch return error.BadKey;
    var node_secret = schedule.deriveSecret(ep.path_secret, "node");
    defer std.crypto.secureZero(u8, &node_secret);
    const root_kp = Kem.deriveKeyPair(&node_secret) catch return error.BadKey;
    var commit_secret = schedule.deriveSecret(ep.path_secret, "path");
    defer std.crypto.secureZero(u8, &commit_secret);

    const ph_root = parentHashRoot2(root_kp.pk, leaf1_hash);
    const my_leaf_new = try rebuildCommitLeaf(gpa, g.leaf_bytes[0], enc_kp.pk, ph_root, g.group_id, 0, g.sig_seed);
    errdefer gpa.free(my_leaf_new);
    const tree_hash_new = treeHash2(root_kp.pk, leafHash(0, my_leaf_new), leaf1_hash);

    // The Commit: Add(peer) by value + my UpdatePath. The root's copath
    // resolution excludes the member being added, so the path secret rides
    // ONLY in the Welcome — the UpdatePathNode carries zero ciphertexts.
    var proposals: std.ArrayList(u8) = .empty;
    defer proposals.deinit(gpa);
    try wire.ProposalOrRef.write(.{ .proposal = .{ .add = kp } }, gpa, &proposals);
    var path_nodes: std.ArrayList(u8) = .empty;
    defer path_nodes.deinit(gpa);
    try wire.UpdatePathNode.write(.{ .encryption_key = &root_kp.pk, .encrypted_path_secrets_raw = "" }, gpa, &path_nodes);
    var mlr = wire.Reader.init(my_leaf_new);
    const commit_obj: wire.Commit = .{
        .proposals_raw = proposals.items,
        .path = .{ .leaf_node = try wire.LeafNode.parse(&mlr), .nodes_raw = path_nodes.items },
    };

    // Frame + sign in the OLD epoch. This commit is never transmitted (the
    // group has one member); it exists to drive the transcript hash.
    const fc: wire.FramedContent = .{
        .group_id = g.group_id,
        .epoch = 0,
        .sender = .{ .member = 0 },
        .authenticated_data = "",
        .body = .{ .commit = commit_obj },
    };
    var gc_old: std.ArrayList(u8) = .empty;
    defer gc_old.deinit(gpa);
    try g.writeGroupContext(gpa, &gc_old);
    var tbs: std.ArrayList(u8) = .empty;
    defer tbs.deinit(gpa);
    try wire.serializeFramedContentTBS(gpa, &tbs, wire.wire_public_message, fc, gc_old.items);
    const sig = try signWithLabel(gpa, g.sig_seed, "FramedContentTBS", tbs.items);

    // Transcript + the new epoch's schedule.
    var cti: std.ArrayList(u8) = .empty;
    defer cti.deinit(gpa);
    try wire.serializeConfirmedTranscriptHashInput(gpa, &cti, wire.wire_public_message, fc, &sig);
    const cth_new = transcriptConfirmed(g.interim_hash[0..], cti.items);

    var gc_new: std.ArrayList(u8) = .empty;
    defer gc_new.deinit(gpa);
    try (wire.GroupContext{
        .version = wire.protocol_version_mls10,
        .cipher_suite = cipher_suite_id,
        .group_id = g.group_id,
        .epoch = 1,
        .tree_hash = &tree_hash_new,
        .confirmed_transcript_hash = &cth_new,
        .extensions_raw = g.gc_extensions,
    }).write(gpa, &gc_new);

    var secrets_new = schedule.epochFromCommit(g.secrets.init, commit_secret, @splat(0), gc_new.items);
    errdefer secrets_new.wipe();
    const tag_new = confirmTag(secrets_new.confirmation_key, &cth_new);

    // GroupInfo with the full ratchet tree embedded, signed by me.
    var tree_body: std.ArrayList(u8) = .empty;
    defer tree_body.deinit(gpa);
    const root_parent = rootParentBytes(root_kp.pk);
    for ([_][]const u8{ my_leaf_new, &root_parent, leaf1.items }, 0..) |node_bytes, i| {
        try wire.writeU8(gpa, &tree_body, 1);
        try wire.writeU8(gpa, &tree_body, if (i == 1) wire.node_type_parent else wire.node_type_leaf);
        try tree_body.appendSlice(gpa, node_bytes);
    }
    var tree_ext: std.ArrayList(u8) = .empty;
    defer tree_ext.deinit(gpa);
    try wire.writeVector(gpa, &tree_ext, tree_body.items);
    var extensions: std.ArrayList(u8) = .empty;
    defer extensions.deinit(gpa);
    try wire.writeExtension(gpa, &extensions, wire.extension_ratchet_tree, tree_ext.items);

    var gcr = wire.Reader.init(gc_new.items);
    var gi: wire.GroupInfo = .{
        .group_context = try wire.GroupContext.parseFrom(&gcr),
        .group_context_raw = gc_new.items,
        .extensions_raw = extensions.items,
        .confirmation_tag = &tag_new,
        .signer = 0,
        .signature = "",
    };
    var gi_tbs: std.ArrayList(u8) = .empty;
    defer gi_tbs.deinit(gpa);
    try gi.writeUnsigned(gpa, &gi_tbs);
    const gi_sig = try signWithLabel(gpa, g.sig_seed, "GroupInfoTBS", gi_tbs.items);
    gi.signature = &gi_sig;
    var gi_bytes: std.ArrayList(u8) = .empty;
    defer gi_bytes.deinit(gpa);
    try gi.write(gpa, &gi_bytes);

    // Seal the GroupInfo under the welcome key/nonce.
    var welcome_key: [key_len]u8 = undefined;
    var welcome_nonce: [nonce_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &welcome_key);
    defer std.crypto.secureZero(u8, &welcome_nonce);
    schedule.expandWithLabel(secrets_new.welcome, "key", "", &welcome_key);
    schedule.expandWithLabel(secrets_new.welcome, "nonce", "", &welcome_nonce);
    const egi = try gpa.alloc(u8, gi_bytes.items.len + tag_len);
    defer gpa.free(egi);
    Aead.encrypt(egi[0..gi_bytes.items.len], egi[gi_bytes.items.len..][0..tag_len], gi_bytes.items, "", welcome_nonce, welcome_key);

    // GroupSecrets (joiner + the path secret) sealed to the peer's init key.
    var gs_bytes: std.ArrayList(u8) = .empty;
    defer {
        std.crypto.secureZero(u8, gs_bytes.items);
        gs_bytes.deinit(gpa);
    }
    try (wire.GroupSecrets{ .joiner_secret = &secrets_new.joiner, .path_secret = &ep.path_secret }).write(gpa, &gs_bytes);
    var gs_ct: std.ArrayList(u8) = .empty;
    defer gs_ct.deinit(gpa);
    const enc = try encryptWithLabel(gpa, kp.init_key[0..pk_len].*, "Welcome", egi, gs_bytes.items, ep.welcome_seed, &gs_ct);

    const ref = keyPackageRef(kp_body);
    var secrets_raw: std.ArrayList(u8) = .empty;
    defer secrets_raw.deinit(gpa);
    try (wire.EncryptedGroupSecrets{
        .new_member = &ref,
        .encrypted_group_secrets = .{ .kem_output = &enc, .ciphertext = gs_ct.items },
    }).write(gpa, &secrets_raw);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try (wire.MlsMessage{ .welcome = .{
        .cipher_suite = cipher_suite_id,
        .secrets_raw = secrets_raw.items,
        .encrypted_group_info = egi,
    } }).write(gpa, &out);
    const welcome_out = try out.toOwnedSlice(gpa);

    // Install the new epoch (wiping the old one first) — after this point
    // nothing can fail, so the Welcome and the state can't diverge.
    const leaf1_owned = leaf1.toOwnedSlice(gpa) catch |e| {
        gpa.free(welcome_out);
        gpa.free(my_leaf_new);
        secrets_new.wipe();
        return e;
    };
    gpa.free(g.leaf_bytes[0]);
    gpa.free(g.leaf_bytes[1]);
    g.leaf_bytes = .{ my_leaf_new, leaf1_owned };
    g.leaf_sig_pub[1] = kp.leaf_node.signature_key[0..pk_len].*;
    g.leaf_enc_pub[0] = enc_kp.pk;
    g.leaf_enc_pub[1] = kp.leaf_node.encryption_key[0..pk_len].*;
    g.my_enc_priv = enc_kp.sk;
    g.root_pub = root_kp.pk;
    g.root_priv = root_kp.sk;
    g.root_present = true;
    g.root_priv_present = true;
    g.epoch = 1;
    g.tree_hash = tree_hash_new;
    g.confirmed_transcript_hash = cth_new;
    g.cth_len = hash_len;
    g.interim_hash = transcriptInterim(&cth_new, &tag_new);
    g.wipeEpoch();
    g.secrets = secrets_new;
    g.installRatchets();
    return welcome_out;
}

// ---------------------------------------------------------------------------
// Joining via Welcome (§12.4.3.1).
// ---------------------------------------------------------------------------

/// The Welcome's decrypted payload, before any tree processing. Exposed
/// separately so the schedule-level checks are testable against Welcomes
/// for groups this module refuses to hold (anything not two-member).
/// A7.2: cold struct, size guard waived — transient.
pub const OpenedWelcome = struct {
    joiner_secret: Secret,
    path_secret: ?Secret,
    /// The decrypted GroupInfo wire bytes (allocated; deinit frees).
    group_info: []u8,

    pub fn deinit(ow: *OpenedWelcome, gpa: Allocator) void {
        std.crypto.secureZero(u8, std.mem.asBytes(&ow.joiner_secret));
        if (ow.path_secret) |*ps| std.crypto.secureZero(u8, ps);
        gpa.free(ow.group_info);
        ow.group_info = &.{};
    }
};

/// Decrypt a Welcome: find our KeyPackage's entry, open the GroupSecrets
/// with our init key, derive the welcome key/nonce, open the GroupInfo.
pub fn openWelcome(
    gpa: Allocator,
    welcome_msg: []const u8,
    key_package_msg: []const u8,
    init_priv: [pk_len]u8,
) MlsError!OpenedWelcome {
    const wm = try wire.MlsMessage.parse(welcome_msg);
    if (wm != .welcome) return error.UnexpectedMessage;
    const w = wm.welcome;
    if (w.cipher_suite != cipher_suite_id) return error.WrongSuite;

    const km = try wire.MlsMessage.parse(key_package_msg);
    if (km != .key_package) return error.UnexpectedMessage;
    const ref = keyPackageRef(key_package_msg[4..]);

    var it = w.secretsIter();
    const egs = blk: {
        while (try it.next()) |egs| {
            if (std.mem.eql(u8, egs.new_member, &ref)) break :blk egs;
        }
        return error.UnknownKeyPackage;
    };

    // Open the GroupSecrets (context = the encrypted GroupInfo bytes).
    const ct = egs.encrypted_group_secrets.ciphertext;
    if (ct.len < tag_len) return error.DecryptFailed;
    const gs_pt = try gpa.alloc(u8, ct.len - tag_len);
    defer {
        std.crypto.secureZero(u8, gs_pt);
        gpa.free(gs_pt);
    }
    try decryptWithLabel(gpa, init_priv, "Welcome", w.encrypted_group_info, egs.encrypted_group_secrets.kem_output, ct, gs_pt);
    const gs = try wire.GroupSecrets.parse(gs_pt);
    if (gs.joiner_secret.len != hash_len) return error.MalformedVector;
    if (gs.path_secret) |ps| if (ps.len != hash_len) return error.MalformedVector;

    // welcome_secret depends only on the joiner secret (no PSKs in v1);
    // then key/nonce open the GroupInfo.
    const joiner: Secret = gs.joiner_secret[0..hash_len].*;
    var welcome_secret = schedule.welcomeSecretFromJoiner(joiner, @splat(0));
    defer std.crypto.secureZero(u8, &welcome_secret);
    var welcome_key: [key_len]u8 = undefined;
    var welcome_nonce: [nonce_len]u8 = undefined;
    defer std.crypto.secureZero(u8, &welcome_key);
    defer std.crypto.secureZero(u8, &welcome_nonce);
    schedule.expandWithLabel(welcome_secret, "key", "", &welcome_key);
    schedule.expandWithLabel(welcome_secret, "nonce", "", &welcome_nonce);

    if (w.encrypted_group_info.len < tag_len) return error.DecryptFailed;
    const gi = try gpa.alloc(u8, w.encrypted_group_info.len - tag_len);
    errdefer gpa.free(gi);
    Aead.decrypt(
        gi,
        w.encrypted_group_info[0..gi.len],
        w.encrypted_group_info[gi.len..][0..tag_len].*,
        "",
        welcome_nonce,
        welcome_key,
    ) catch return error.DecryptFailed;

    return .{
        .joiner_secret = joiner,
        .path_secret = if (gs.path_secret) |ps| ps[0..hash_len].* else null,
        .group_info = gi,
    };
}

/// Join a two-member group from a Welcome. `key_package_msg` is our own
/// published KeyPackage; `keys` are its private halves plus our signing
/// seed. Verifies everything §12.4.3.1 lists: GroupInfo signature, tree
/// hash, parent-hash validity, leaf validity, and the confirmation tag.
pub fn join(gpa: Allocator, welcome_msg: []const u8, key_package_msg: []const u8, keys: JoinKeys) MlsError!Group {
    var ow = try openWelcome(gpa, welcome_msg, key_package_msg, keys.init_priv);
    defer ow.deinit(gpa);
    const gi = try wire.GroupInfo.parse(ow.group_info);
    const gc = gi.group_context;
    if (gc.version != wire.protocol_version_mls10) return error.UnsupportedVersion;
    if (gc.cipher_suite != cipher_suite_id) return error.WrongSuite;
    if (gc.confirmed_transcript_hash.len != hash_len) return error.MalformedVector;
    if (gc.tree_hash.len != hash_len) return error.MalformedVector;

    // The ratchet tree rides in the GroupInfo extension (our Welcomes
    // always embed it; an external-tree deployment is out of scope).
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const tree_data = blk: {
        var eit = wire.extensionsIter(gi.extensions_raw);
        while (try eit.next()) |ext| {
            if (ext.extension_type == wire.extension_ratchet_tree) break :blk ext.data;
        }
        return error.MissingRatchetTree;
    };
    const slots = try parseTreeSlots(arena, tree_data);
    if (slots.len != 3) return error.UnsupportedGroupSize;

    // Both leaves must be present; the root may be blank (a pathless add).
    const leaves: [2]wire.LeafNode = blk: {
        var out: [2]wire.LeafNode = undefined;
        for ([_]u32{ 0, 2 }, 0..) |slot_idx, i| {
            const s = slots[slot_idx] orelse return error.UnsupportedGroupSize;
            if (s.kind != wire.node_type_leaf) return error.MalformedVector;
            var r = wire.Reader.init(s.bytes);
            out[i] = try wire.LeafNode.parse(&r);
            try r.finish();
        }
        break :blk out;
    };

    // Which leaf is me? Match my KeyPackage's encryption key.
    const km = try wire.MlsMessage.parse(key_package_msg);
    const my_kp = km.key_package;
    const my_leaf: u32 = blk: {
        for (leaves, 0..) |ln, i| {
            if (std.mem.eql(u8, ln.encryption_key, my_kp.leaf_node.encryption_key)) break :blk @intCast(i);
        }
        return error.UnknownKeyPackage;
    };

    // My private halves must actually match my published leaf (E3: fail
    // here, not at first decrypt).
    const my_enc_pub = Kem.derivePublic(keys.enc_priv) catch return error.BadKey;
    if (!std.mem.eql(u8, leaves[my_leaf].encryption_key, &my_enc_pub)) return error.BadKey;
    const sig_kp = Ed25519.KeyPair.generateDeterministic(keys.sig_seed) catch return error.BadKey;
    if (!std.mem.eql(u8, leaves[my_leaf].signature_key, &sig_kp.public_key.toBytes())) return error.BadKey;

    // Validate both leaves' signatures; verify the GroupInfo signature
    // under the signer leaf's key.
    for (leaves, 0..) |ln, i| try validateLeaf(gpa, ln, @intCast(i), gc.group_id);
    if (gi.signer >= 2) return error.UnsupportedGroupSize;
    const signer_pub = leaves[gi.signer].signature_key[0..pk_len].*;
    {
        var gi_tbs: std.ArrayList(u8) = .empty;
        defer gi_tbs.deinit(gpa);
        try gi.writeUnsigned(gpa, &gi_tbs);
        try verifyWithLabel(gpa, signer_pub, "GroupInfoTBS", gi_tbs.items, gi.signature);
    }

    // Tree integrity: the tree hash, and parent-hash validity for any
    // commit-sourced leaf under a present root.
    const th = treeNodeHash(slots, treeRootIndex(@intCast(slots.len)));
    if (!std.mem.eql(u8, &th, gc.tree_hash)) return error.TreeHashMismatch;
    var root_pub: [pk_len]u8 = @splat(0);
    const root_present = slots[1] != null;
    if (slots[1]) |root_slot| {
        if (root_slot.kind != wire.node_type_parent) return error.MalformedVector;
        var rr = wire.Reader.init(root_slot.bytes);
        const root_node = try wire.ParentNode.parseFrom(&rr);
        try rr.finish();
        if (root_node.encryption_key.len != pk_len) return error.BadKey;
        root_pub = root_node.encryption_key[0..pk_len].*;
        for (leaves, 0..) |ln, i| {
            if (ln.source != .commit) continue;
            const sibling = slots[(1 - i) * 2];
            const sib_hash = leafHash(@intCast(1 - i), if (sibling) |s| s.bytes else null);
            const want = parentHashRoot2(root_pub, sib_hash);
            if (!std.mem.eql(u8, ln.source.commit, &want)) return error.ParentHashMismatch;
        }
    }

    // The epoch schedule from the joiner secret, then the confirmation tag.
    const secrets = schedule.epochFromJoiner(ow.joiner_secret, @splat(0), gi.group_context_raw);
    const want_tag = confirmTag(secrets.confirmation_key, gc.confirmed_transcript_hash);
    if (!tagEql(want_tag, gi.confirmation_tag)) return error.BadConfirmationTag;

    // The root private key, if the committer sent us the path secret.
    var root_priv: [pk_len]u8 = @splat(0);
    var root_priv_present = false;
    if (ow.path_secret) |ps| {
        if (root_present) {
            var node_secret = schedule.deriveSecret(ps, "node");
            defer std.crypto.secureZero(u8, &node_secret);
            const rkp = Kem.deriveKeyPair(&node_secret) catch return error.BadKey;
            if (!std.mem.eql(u8, &rkp.pk, &root_pub)) return error.PathKeyMismatch;
            root_priv = rkp.sk;
            root_priv_present = true;
        }
    }

    const group_id = try gpa.dupe(u8, gc.group_id);
    errdefer gpa.free(group_id);
    const gc_extensions = try gpa.dupe(u8, gc.extensions_raw);
    errdefer gpa.free(gc_extensions);
    const leaf0_bytes = try gpa.dupe(u8, slots[0].?.bytes);
    errdefer gpa.free(leaf0_bytes);
    const leaf1_bytes = try gpa.dupe(u8, slots[2].?.bytes);
    errdefer gpa.free(leaf1_bytes);

    var g: Group = .{
        .group_id = group_id,
        .gc_extensions = gc_extensions,
        .leaf_bytes = .{ leaf0_bytes, leaf1_bytes },
        .secrets = secrets,
        .ratchets = undefined,
        .confirmed_transcript_hash = gc.confirmed_transcript_hash[0..hash_len].*,
        .interim_hash = transcriptInterim(gc.confirmed_transcript_hash, gi.confirmation_tag),
        .tree_hash = th,
        .root_pub = root_pub,
        .root_priv = root_priv,
        .my_enc_priv = keys.enc_priv,
        .sig_seed = keys.sig_seed,
        .leaf_sig_pub = .{ leaves[0].signature_key[0..pk_len].*, leaves[1].signature_key[0..pk_len].* },
        .leaf_enc_pub = .{ leaves[0].encryption_key[0..pk_len].*, leaves[1].encryption_key[0..pk_len].* },
        .epoch = gc.epoch,
        .my_leaf = my_leaf,
        .cth_len = hash_len,
        .root_present = root_present,
        .root_priv_present = root_priv_present,
        .ratchets_live = false,
    };
    g.installRatchets();
    return g;
}

// ---------------------------------------------------------------------------
// Application messages.
// ---------------------------------------------------------------------------

/// Encrypt one application message. `pad_len` appends that many zero bytes
/// inside the AEAD (the traffic-shape knob U4's bucket sizes will drive);
/// `reuse_guard` is four bytes of fresh entropy (§6.3.1).
pub fn encrypt(gpa: Allocator, g: *Group, plaintext: []const u8, pad_len: usize, reuse_guard: [4]u8) MlsError![]u8 {
    if (!g.ratchets_live) return error.WrongState;
    var gc: std.ArrayList(u8) = .empty;
    defer gc.deinit(gpa);
    try g.writeGroupContext(gpa, &gc);
    return protectPrivate(
        gpa,
        .{ .group_id = g.group_id, .epoch = g.epoch, .gc_bytes = gc.items },
        g.my_leaf,
        g.sig_seed,
        .{ .application = plaintext },
        null,
        &g.ratchets[g.my_leaf][ratchet_application],
        g.secrets.sender_data,
        reuse_guard,
        pad_len,
    );
}

/// Decrypt one incoming MLSMessage from the peer: an application message
/// yields its plaintext; a commit advances the epoch (PCS).
pub fn receive(gpa: Allocator, g: *Group, msg_bytes: []const u8) MlsError!Received {
    if (!g.ratchets_live) return error.WrongState;
    const m = try wire.MlsMessage.parse(msg_bytes);
    if (m != .private_message) return error.UnexpectedMessage;
    const pm = m.private_message;
    const peer = 1 - g.my_leaf;

    var gc: std.ArrayList(u8) = .empty;
    defer gc.deinit(gpa);
    try g.writeGroupContext(gpa, &gc);
    var opened = try unprotectPrivate(
        gpa,
        .{ .group_id = g.group_id, .epoch = g.epoch, .gc_bytes = gc.items },
        pm,
        peer,
        g.leaf_sig_pub[peer],
        &g.ratchets[peer][ratchet_handshake],
        &g.ratchets[peer][ratchet_application],
        g.secrets.sender_data,
    );
    defer opened.deinit(gpa);

    switch (opened.body) {
        .application => |data| return .{ .application = try gpa.dupe(u8, data) },
        .commit => |commit_obj| {
            try processCommit(gpa, g, pm, commit_obj, opened.auth);
            return .epoch_advanced;
        },
        .proposal => return error.UnexpectedMessage,
    }
}

// ---------------------------------------------------------------------------
// Key rotation (§12.4): the empty commit with a full path — post-compromise
// security for the pair.
// ---------------------------------------------------------------------------

/// Rotate my leaf and the root: build an empty commit with an UpdatePath,
/// protect it in the CURRENT epoch, then advance to the new one. Returns
/// the MLSMessage(PrivateMessage) to deliver to the peer.
pub fn commit(gpa: Allocator, g: *Group, pad_len: usize, ep: CommitEntropy) MlsError![]u8 {
    if (!g.ratchets_live) return error.WrongState;
    const peer = 1 - g.my_leaf;

    // Fresh leaf key pair + the path secret chain.
    const enc_kp = Kem.deriveKeyPair(&ep.enc_seed) catch return error.BadKey;
    var node_secret = schedule.deriveSecret(ep.path_secret, "node");
    defer std.crypto.secureZero(u8, &node_secret);
    const root_kp = Kem.deriveKeyPair(&node_secret) catch return error.BadKey;
    var commit_secret = schedule.deriveSecret(ep.path_secret, "path");
    defer std.crypto.secureZero(u8, &commit_secret);

    const peer_leaf_hash = leafHash(peer, g.leaf_bytes[peer]);
    const ph_root = parentHashRoot2(root_kp.pk, peer_leaf_hash);
    const my_leaf_new = try rebuildCommitLeaf(gpa, g.leaf_bytes[g.my_leaf], enc_kp.pk, ph_root, g.group_id, g.my_leaf, g.sig_seed);
    errdefer gpa.free(my_leaf_new);
    const my_leaf_hash = leafHash(g.my_leaf, my_leaf_new);
    const tree_hash_new = if (g.my_leaf == 0)
        treeHash2(root_kp.pk, my_leaf_hash, peer_leaf_hash)
    else
        treeHash2(root_kp.pk, peer_leaf_hash, my_leaf_hash);

    // Provisional GroupContext (§12.4.1): new epoch + tree hash, OLD
    // confirmed transcript hash — the context the path secret seals under.
    var gc_prov: std.ArrayList(u8) = .empty;
    defer gc_prov.deinit(gpa);
    try (wire.GroupContext{
        .version = wire.protocol_version_mls10,
        .cipher_suite = cipher_suite_id,
        .group_id = g.group_id,
        .epoch = g.epoch + 1,
        .tree_hash = &tree_hash_new,
        .confirmed_transcript_hash = g.cthSlice(),
        .extensions_raw = g.gc_extensions,
    }).write(gpa, &gc_prov);

    // Encrypt the path secret to the peer's leaf key (the root's copath
    // resolution in a two-leaf tree is exactly the other leaf).
    var ps_ct: std.ArrayList(u8) = .empty;
    defer ps_ct.deinit(gpa);
    const ps_enc = try encryptWithLabel(gpa, g.leaf_enc_pub[peer], "UpdatePathNode", gc_prov.items, &ep.path_secret, ep.seal_seed, &ps_ct);

    var cts: std.ArrayList(u8) = .empty;
    defer cts.deinit(gpa);
    try (wire.HpkeCiphertext{ .kem_output = &ps_enc, .ciphertext = ps_ct.items }).write(gpa, &cts);
    var path_nodes: std.ArrayList(u8) = .empty;
    defer path_nodes.deinit(gpa);
    try wire.UpdatePathNode.write(.{ .encryption_key = &root_kp.pk, .encrypted_path_secrets_raw = cts.items }, gpa, &path_nodes);

    var mlr = wire.Reader.init(my_leaf_new);
    const commit_obj: wire.Commit = .{
        .proposals_raw = "",
        .path = .{ .leaf_node = try wire.LeafNode.parse(&mlr), .nodes_raw = path_nodes.items },
    };

    // Sign in the old epoch; derive the new one.
    const fc: wire.FramedContent = .{
        .group_id = g.group_id,
        .epoch = g.epoch,
        .sender = .{ .member = g.my_leaf },
        .authenticated_data = "",
        .body = .{ .commit = commit_obj },
    };
    var gc_old: std.ArrayList(u8) = .empty;
    defer gc_old.deinit(gpa);
    try g.writeGroupContext(gpa, &gc_old);
    var tbs: std.ArrayList(u8) = .empty;
    defer tbs.deinit(gpa);
    try wire.serializeFramedContentTBS(gpa, &tbs, wire.wire_private_message, fc, gc_old.items);
    const sig = try signWithLabel(gpa, g.sig_seed, "FramedContentTBS", tbs.items);

    var cti: std.ArrayList(u8) = .empty;
    defer cti.deinit(gpa);
    try wire.serializeConfirmedTranscriptHashInput(gpa, &cti, wire.wire_private_message, fc, &sig);
    const cth_new = transcriptConfirmed(g.interim_hash[0..], cti.items);

    var gc_new: std.ArrayList(u8) = .empty;
    defer gc_new.deinit(gpa);
    try (wire.GroupContext{
        .version = wire.protocol_version_mls10,
        .cipher_suite = cipher_suite_id,
        .group_id = g.group_id,
        .epoch = g.epoch + 1,
        .tree_hash = &tree_hash_new,
        .confirmed_transcript_hash = &cth_new,
        .extensions_raw = g.gc_extensions,
    }).write(gpa, &gc_new);
    var secrets_new = schedule.epochFromCommit(g.secrets.init, commit_secret, @splat(0), gc_new.items);
    errdefer secrets_new.wipe();
    const tag_new = confirmTag(secrets_new.confirmation_key, &cth_new);

    // Protect the commit with the OLD epoch's keys, then advance.
    const msg = try protectPrivate(
        gpa,
        .{ .group_id = g.group_id, .epoch = g.epoch, .gc_bytes = gc_old.items },
        g.my_leaf,
        g.sig_seed,
        .{ .commit = commit_obj },
        &tag_new,
        &g.ratchets[g.my_leaf][ratchet_handshake],
        g.secrets.sender_data,
        ep.reuse_guard,
        pad_len,
    );

    gpa.free(g.leaf_bytes[g.my_leaf]);
    g.leaf_bytes[g.my_leaf] = my_leaf_new;
    g.leaf_enc_pub[g.my_leaf] = enc_kp.pk;
    g.my_enc_priv = enc_kp.sk;
    g.root_pub = root_kp.pk;
    g.root_priv = root_kp.sk;
    g.root_present = true;
    g.root_priv_present = true;
    g.epoch += 1;
    g.tree_hash = tree_hash_new;
    g.confirmed_transcript_hash = cth_new;
    g.cth_len = hash_len;
    g.interim_hash = transcriptInterim(&cth_new, &tag_new);
    g.wipeEpoch();
    g.secrets = secrets_new;
    g.installRatchets();
    return msg;
}

/// Apply the peer's empty-with-path commit (already decrypted and its
/// signature verified by `unprotectPrivate`).
fn processCommit(
    gpa: Allocator,
    g: *Group,
    pm: wire.PrivateMessage,
    commit_obj: wire.Commit,
    auth: wire.FramedContentAuthData,
) MlsError!void {
    const peer = 1 - g.my_leaf;
    // v1 refuses everything but the empty rotation commit (F4).
    if (commit_obj.proposals_raw.len != 0) return error.UnsupportedCommit;
    const path = commit_obj.path orelse return error.UnsupportedCommit;
    const confirmation_tag = auth.confirmation_tag orelse return error.BadConfirmationTag;

    // The peer's new leaf: commit-sourced, same signature key (identity
    // continuity for the pair), valid under the group binding.
    const new_leaf = path.leaf_node;
    if (new_leaf.source != .commit) return error.UnsupportedCommit;
    if (!std.mem.eql(u8, new_leaf.signature_key, &g.leaf_sig_pub[peer])) return error.BadSignature;
    try validateLeaf(gpa, new_leaf, peer, g.group_id);
    if (new_leaf.encryption_key.len != pk_len) return error.BadKey;

    var nit = path.nodesIter();
    const node = (try nit.next()) orelse return error.UnsupportedCommit;
    if ((try nit.next()) != null) return error.UnsupportedCommit;
    if (node.encryption_key.len != pk_len) return error.BadKey;
    const root_pub_new = node.encryption_key[0..pk_len].*;
    var cit = node.ciphertextsIter();
    const ct = (try cit.next()) orelse return error.UnsupportedCommit;
    if ((try cit.next()) != null) return error.UnsupportedCommit;

    // Serialize the peer's new leaf (canonical) for hashing + storage.
    var peer_leaf_new: std.ArrayList(u8) = .empty;
    errdefer peer_leaf_new.deinit(gpa);
    try new_leaf.write(gpa, &peer_leaf_new);

    // Parent-hash validity for the new root.
    const my_leaf_hash = leafHash(g.my_leaf, g.leaf_bytes[g.my_leaf]);
    const want_ph = parentHashRoot2(root_pub_new, my_leaf_hash);
    if (!std.mem.eql(u8, new_leaf.source.commit, &want_ph)) return error.ParentHashMismatch;

    const peer_leaf_hash = leafHash(peer, peer_leaf_new.items);
    const tree_hash_new = if (g.my_leaf == 0)
        treeHash2(root_pub_new, my_leaf_hash, peer_leaf_hash)
    else
        treeHash2(root_pub_new, peer_leaf_hash, my_leaf_hash);

    // Decrypt the path secret under the provisional GroupContext.
    var gc_prov: std.ArrayList(u8) = .empty;
    defer gc_prov.deinit(gpa);
    try (wire.GroupContext{
        .version = wire.protocol_version_mls10,
        .cipher_suite = cipher_suite_id,
        .group_id = g.group_id,
        .epoch = g.epoch + 1,
        .tree_hash = &tree_hash_new,
        .confirmed_transcript_hash = g.cthSlice(),
        .extensions_raw = g.gc_extensions,
    }).write(gpa, &gc_prov);
    if (ct.ciphertext.len != hash_len + tag_len) return error.DecryptFailed;
    var path_secret: Secret = undefined;
    defer std.crypto.secureZero(u8, &path_secret);
    try decryptWithLabel(gpa, g.my_enc_priv, "UpdatePathNode", gc_prov.items, ct.kem_output, ct.ciphertext, &path_secret);

    // The derived root key pair must match the advertised public key.
    var node_secret = schedule.deriveSecret(path_secret, "node");
    defer std.crypto.secureZero(u8, &node_secret);
    const root_kp = Kem.deriveKeyPair(&node_secret) catch return error.BadKey;
    if (!std.mem.eql(u8, &root_kp.pk, &root_pub_new)) return error.PathKeyMismatch;
    var commit_secret = schedule.deriveSecret(path_secret, "path");
    defer std.crypto.secureZero(u8, &commit_secret);

    // Transcript + new epoch, then the confirmation tag gate.
    const fc: wire.FramedContent = .{
        .group_id = pm.group_id,
        .epoch = pm.epoch,
        .sender = .{ .member = peer },
        .authenticated_data = pm.authenticated_data,
        .body = .{ .commit = commit_obj },
    };
    var cti: std.ArrayList(u8) = .empty;
    defer cti.deinit(gpa);
    try wire.serializeConfirmedTranscriptHashInput(gpa, &cti, wire.wire_private_message, fc, auth.signature);
    const cth_new = transcriptConfirmed(g.interim_hash[0..], cti.items);

    var gc_new: std.ArrayList(u8) = .empty;
    defer gc_new.deinit(gpa);
    try (wire.GroupContext{
        .version = wire.protocol_version_mls10,
        .cipher_suite = cipher_suite_id,
        .group_id = g.group_id,
        .epoch = g.epoch + 1,
        .tree_hash = &tree_hash_new,
        .confirmed_transcript_hash = &cth_new,
        .extensions_raw = g.gc_extensions,
    }).write(gpa, &gc_new);
    var secrets_new = schedule.epochFromCommit(g.secrets.init, commit_secret, @splat(0), gc_new.items);
    errdefer secrets_new.wipe();
    const want_tag = confirmTag(secrets_new.confirmation_key, &cth_new);
    if (!tagEql(want_tag, confirmation_tag)) return error.BadConfirmationTag;

    gpa.free(g.leaf_bytes[peer]);
    g.leaf_bytes[peer] = try peer_leaf_new.toOwnedSlice(gpa);
    g.leaf_enc_pub[peer] = new_leaf.encryption_key[0..pk_len].*;
    g.root_pub = root_pub_new;
    g.root_priv = root_kp.sk;
    g.root_present = true;
    g.root_priv_present = true;
    g.epoch += 1;
    g.tree_hash = tree_hash_new;
    g.confirmed_transcript_hash = cth_new;
    g.cth_len = hash_len;
    g.interim_hash = transcriptInterim(&cth_new, confirmation_tag);
    g.wipeEpoch();
    g.secrets = secrets_new;
    g.installRatchets();
}

// ---------------------------------------------------------------------------
// Group persistence + inbox routing (ZAT_CHAT_ROADMAP M1). A conversation
// must survive a relaunch, so the whole Group round-trips through plain
// bytes; the caller (shell/cache) owns where those bytes rest — keystore or
// 0600 file, the session posture. Serializing LIVE ratchet state is the
// standard messenger trade (Signal does the same): forward secrecy is
// preserved because advanced generations are already gone from the state
// serialized — the wipe points fire BEFORE persistence ever sees the bytes.
// ---------------------------------------------------------------------------

const group_blob_magic = [4]u8{ 'Z', 'A', 'T', 'G' };
const group_blob_version: u16 = 1;

/// Serialize the whole group state (gpa-owned; the caller should scrub the
/// returned bytes after storing them — they contain live key material).
pub fn serializeGroup(gpa: Allocator, g: *const Group) error{OutOfMemory}![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    try out.appendSlice(gpa, &group_blob_magic);
    try out.appendSlice(gpa, std.mem.asBytes(&group_blob_version));
    inline for (.{ g.group_id, g.gc_extensions, g.leaf_bytes[0], g.leaf_bytes[1] }) |slice| {
        var len4: [4]u8 = undefined;
        std.mem.writeInt(u32, &len4, @intCast(slice.len), .little);
        try out.appendSlice(gpa, &len4);
        try out.appendSlice(gpa, slice);
    }
    // EpochSecrets is packed exactly (its guard proves 11×32 with no holes),
    // so its bytes are its serialization.
    try out.appendSlice(gpa, std.mem.asBytes(&g.secrets));
    for (g.ratchets) |pair| for (pair) |r| {
        try out.appendSlice(gpa, &r.secret);
        var gen4: [4]u8 = undefined;
        std.mem.writeInt(u32, &gen4, r.generation, .little);
        try out.appendSlice(gpa, &gen4);
    };
    try out.appendSlice(gpa, &g.confirmed_transcript_hash);
    try out.appendSlice(gpa, &g.interim_hash);
    try out.appendSlice(gpa, &g.tree_hash);
    try out.appendSlice(gpa, &g.root_pub);
    try out.appendSlice(gpa, &g.root_priv);
    try out.appendSlice(gpa, &g.my_enc_priv);
    try out.appendSlice(gpa, &g.sig_seed);
    for (g.leaf_sig_pub) |k| try out.appendSlice(gpa, &k);
    for (g.leaf_enc_pub) |k| try out.appendSlice(gpa, &k);
    var tail: [16]u8 = undefined;
    std.mem.writeInt(u64, tail[0..8], g.epoch, .little);
    std.mem.writeInt(u32, tail[8..12], g.my_leaf, .little);
    tail[12] = g.cth_len;
    tail[13] = @as(u8, @intFromBool(g.root_present)) |
        (@as(u8, @intFromBool(g.root_priv_present)) << 1) |
        (@as(u8, @intFromBool(g.ratchets_live)) << 2);
    tail[14] = 0;
    tail[15] = 0;
    try out.appendSlice(gpa, &tail);
    return out.toOwnedSlice(gpa);
}

/// Restore a group from `serializeGroup`'s bytes. Strict: any malformed
/// length is an error, never a half-restored group (E3).
pub fn deserializeGroup(gpa: Allocator, bytes: []const u8) MlsError!Group {
    var g: Group = undefined;
    if (bytes.len < 6 or !std.mem.eql(u8, bytes[0..4], &group_blob_magic)) return error.BadMessage;
    if (std.mem.bytesToValue(u16, bytes[4..6]) != group_blob_version) return error.BadMessage;
    var at: usize = 6;

    var slices: [4][]u8 = undefined;
    var filled: usize = 0;
    errdefer for (slices[0..filled]) |s| gpa.free(s);
    for (&slices) |*slot| {
        if (bytes.len - at < 4) return error.BadMessage;
        const len = std.mem.readInt(u32, bytes[at..][0..4], .little);
        at += 4;
        if (bytes.len - at < len) return error.BadMessage;
        slot.* = try gpa.dupe(u8, bytes[at .. at + len]);
        filled += 1;
        at += len;
    }

    const fixed_len = @sizeOf(schedule.EpochSecrets) + 4 * 36 + 3 * hash_len + 4 * pk_len + 4 * pk_len + 16;
    if (bytes.len - at != fixed_len) return error.BadMessage;
    g.group_id = slices[0];
    g.gc_extensions = slices[1];
    g.leaf_bytes = .{ slices[2], slices[3] };
    g.secrets = std.mem.bytesToValue(schedule.EpochSecrets, bytes[at..][0..@sizeOf(schedule.EpochSecrets)]);
    at += @sizeOf(schedule.EpochSecrets);
    for (&g.ratchets) |*pair| for (pair) |*r| {
        r.secret = bytes[at..][0..32].*;
        r.generation = std.mem.readInt(u32, bytes[at..][32..36], .little);
        at += 36;
    };
    g.confirmed_transcript_hash = bytes[at..][0..hash_len].*;
    at += hash_len;
    g.interim_hash = bytes[at..][0..hash_len].*;
    at += hash_len;
    g.tree_hash = bytes[at..][0..hash_len].*;
    at += hash_len;
    g.root_pub = bytes[at..][0..pk_len].*;
    at += pk_len;
    g.root_priv = bytes[at..][0..pk_len].*;
    at += pk_len;
    g.my_enc_priv = bytes[at..][0..pk_len].*;
    at += pk_len;
    g.sig_seed = bytes[at..][0..32].*;
    at += 32;
    for (&g.leaf_sig_pub) |*k| {
        k.* = bytes[at..][0..pk_len].*;
        at += pk_len;
    }
    for (&g.leaf_enc_pub) |*k| {
        k.* = bytes[at..][0..pk_len].*;
        at += pk_len;
    }
    g.epoch = std.mem.readInt(u64, bytes[at..][0..8], .little);
    g.my_leaf = std.mem.readInt(u32, bytes[at..][8..12], .little);
    if (g.my_leaf > 1) return error.BadMessage;
    g.cth_len = bytes[at..][12];
    if (g.cth_len != 0 and g.cth_len != hash_len) return error.BadMessage;
    const flags = bytes[at..][13];
    g.root_present = flags & 1 != 0;
    g.root_priv_present = flags & 2 != 0;
    g.ratchets_live = flags & 4 != 0;
    return g;
}

/// The counterparty's credential identity (their DID). BORROWS the group's
/// leaf bytes — copy it out before any group mutation (a commit rebuilds
/// leaves). Empty while the group is still one member.
pub fn peerIdentity(g: *const Group) []const u8 {
    const peer = 1 - g.my_leaf;
    if (g.leaf_bytes[peer].len == 0) return "";
    var r = wire.Reader.init(g.leaf_bytes[peer]);
    const ln = wire.LeafNode.parse(&r) catch return "";
    return ln.credential.identity;
}

/// What kind of MLS message a padded inbox bucket carries — the shell's
/// routing switch (welcome → join path; private_message → an open group).
pub const MessageKind = enum { welcome, private_message, other };

pub fn messageKind(msg_bytes: []const u8) MessageKind {
    var r = wire.Reader.init(msg_bytes);
    const version = r.readU16() catch return .other;
    if (version != wire.protocol_version_mls10) return .other;
    const kind = r.readU16() catch return .other;
    return switch (kind) {
        wire.wire_welcome => .welcome,
        wire.wire_private_message => .private_message,
        else => .other,
    };
}

/// A private message's group id (BORROWS `msg_bytes`) — how the shell finds
/// which conversation's group should `receive` it.
pub fn privateMessageGroupId(msg_bytes: []const u8) MlsError![]const u8 {
    var r = wire.Reader.init(msg_bytes);
    if (try r.readU16() != wire.protocol_version_mls10) return error.UnsupportedVersion;
    if (try r.readU16() != wire.wire_private_message) return error.UnexpectedMessage;
    const pm = try wire.PrivateMessage.parseFrom(&r);
    return pm.group_id;
}

// ---------------------------------------------------------------------------
// Tests (C6: leak-checked) — every layer that has a published interop
// vector is pinned to it (mlswg/mls-implementations, cipher suite 1; the
// hex lives in mls_vectors.zig), then the end-to-end two-member exchange.
// ---------------------------------------------------------------------------

const testing = std.testing;
const vec = @import("mls_vectors.zig");

fn hx(comptime s: []const u8) [s.len / 2]u8 {
    @setEvalBranchQuota(1_000_000);
    var out: [s.len / 2]u8 = undefined;
    _ = std.fmt.hexToBytes(&out, s) catch unreachable;
    return out;
}

test "interop crypto-basics: SignWithLabel is byte-exact; VerifyWithLabel accepts" {
    const gpa = testing.allocator;
    const seed = hx(vec.crypto_basics.sign.priv);
    const pub_key = hx(vec.crypto_basics.sign.pub_key);
    const content = hx(vec.crypto_basics.sign.content);
    const want_sig = hx(vec.crypto_basics.sign.signature);

    const kp = try Ed25519.KeyPair.generateDeterministic(seed);
    try testing.expectEqualSlices(u8, &pub_key, &kp.public_key.toBytes());

    // Ed25519 with no added noise is RFC 8032 deterministic — byte-exact.
    const sig = try signWithLabel(gpa, seed, vec.crypto_basics.sign.label, &content);
    try testing.expectEqualSlices(u8, &want_sig, &sig);
    try verifyWithLabel(gpa, pub_key, vec.crypto_basics.sign.label, &content, &want_sig);
    var bad = want_sig;
    bad[0] ^= 1;
    try testing.expectError(error.BadSignature, verifyWithLabel(gpa, pub_key, vec.crypto_basics.sign.label, &content, &bad));
}

test "interop crypto-basics: DecryptWithLabel opens the vector; seal round-trips" {
    const gpa = testing.allocator;
    const priv = hx(vec.crypto_basics.encrypt.priv);
    const pub_key = hx(vec.crypto_basics.encrypt.pub_key);
    const kem_output = hx(vec.crypto_basics.encrypt.kem_output);
    const ciphertext = hx(vec.crypto_basics.encrypt.ciphertext);
    const context = hx(vec.crypto_basics.encrypt.context);
    const plaintext = hx(vec.crypto_basics.encrypt.plaintext);
    const label = vec.crypto_basics.encrypt.label;

    var out: [plaintext.len]u8 = undefined;
    try decryptWithLabel(gpa, priv, label, &context, &kem_output, &ciphertext, &out);
    try testing.expectEqualSlices(u8, &plaintext, &out);

    // Our own seal (fresh encap entropy) opens with the same private key.
    var ct: std.ArrayList(u8) = .empty;
    defer ct.deinit(gpa);
    const enc = try encryptWithLabel(gpa, pub_key, label, &context, &plaintext, [_]u8{0x42} ** 32, &ct);
    var back: [plaintext.len]u8 = undefined;
    try decryptWithLabel(gpa, priv, label, &context, &enc, ct.items, &back);
    try testing.expectEqualSlices(u8, &plaintext, &back);
}

test "interop crypto-basics: RefHash" {
    const value = hx(vec.crypto_basics.ref.value);
    const want = hx(vec.crypto_basics.ref.out);
    const got = refHash(vec.crypto_basics.ref.label, &value);
    try testing.expectEqualSlices(u8, &want, &got);
}

test "interop tree-validation: tree hashes over the array representation" {
    const gpa = testing.allocator;
    inline for (.{
        .{ vec.tree_validation.tree0, vec.tree_validation.tree0_hashes },
        .{ vec.tree_validation.tree1, vec.tree_validation.tree1_hashes },
        .{ vec.tree_validation.tree2, vec.tree_validation.tree2_hashes },
    }) |case| {
        const tree_bytes = hx(case[0]);
        const hashes = hx(case[1]);
        var arena_state = std.heap.ArenaAllocator.init(gpa);
        defer arena_state.deinit();
        const slots = try parseTreeSlots(arena_state.allocator(), &tree_bytes);
        try testing.expectEqual(hashes.len / hash_len, slots.len);
        for (0..slots.len) |i| {
            const got = treeNodeHash(slots, @intCast(i));
            try testing.expectEqualSlices(u8, hashes[i * hash_len ..][0..hash_len], &got);
        }
    }
}

test "interop transcript-hashes: confirmed/interim chain + confirmation tag" {
    const gpa = testing.allocator;
    const confirmation_key = hx(vec.transcript.confirmation_key);
    const ac_bytes = hx(vec.transcript.authenticated_content);
    const interim_before = hx(vec.transcript.interim_transcript_hash_before);
    const want_confirmed = hx(vec.transcript.confirmed_transcript_hash_after);
    const want_interim = hx(vec.transcript.interim_transcript_hash_after);

    const ac = try wire.AuthenticatedContent.parse(&ac_bytes);
    var cti: std.ArrayList(u8) = .empty;
    defer cti.deinit(gpa);
    try wire.serializeConfirmedTranscriptHashInput(gpa, &cti, ac.wire_format, ac.content, ac.auth.signature);
    const confirmed = transcriptConfirmed(&interim_before, cti.items);
    try testing.expectEqualSlices(u8, &want_confirmed, &confirmed);

    const tag = confirmTag(confirmation_key, &confirmed);
    try testing.expect(tagEql(tag, ac.auth.confirmation_tag.?));
    const interim = transcriptInterim(&confirmed, &tag);
    try testing.expectEqualSlices(u8, &want_interim, &interim);
}

test "interop welcome: decrypt, verify GroupInfo signature + confirmation tag" {
    const gpa = testing.allocator;
    const welcome_msg = hx(vec.welcome.welcome_msg);
    const key_package_msg = hx(vec.welcome.key_package);
    const init_priv = hx(vec.welcome.init_priv);
    const signer_pub = hx(vec.welcome.signer_pub);

    var ow = try openWelcome(gpa, &welcome_msg, &key_package_msg, init_priv);
    defer ow.deinit(gpa);

    const gi = try wire.GroupInfo.parse(ow.group_info);
    var gi_tbs: std.ArrayList(u8) = .empty;
    defer gi_tbs.deinit(gpa);
    try gi.writeUnsigned(gpa, &gi_tbs);
    try verifyWithLabel(gpa, signer_pub, "GroupInfoTBS", gi_tbs.items, gi.signature);

    const secrets = schedule.epochFromJoiner(ow.joiner_secret, @splat(0), gi.group_context_raw);
    const tag = confirmTag(secrets.confirmation_key, gi.group_context.confirmed_transcript_hash);
    try testing.expect(tagEql(tag, gi.confirmation_tag));
}

test "interop message-protection: public + private messages, both directions" {
    const gpa = testing.allocator;
    const mp = vec.message_protection;
    const group_id = hx(mp.group_id);
    const tree_hash = hx(mp.tree_hash);
    const cth = hx(mp.confirmed_transcript_hash);
    const sig_seed = hx(mp.signature_priv);
    const sig_pub = hx(mp.signature_pub);
    const encryption_secret = hx(mp.encryption_secret);
    const sender_data_secret = hx(mp.sender_data_secret);
    const membership_key = hx(mp.membership_key);

    var gc: std.ArrayList(u8) = .empty;
    defer gc.deinit(gpa);
    try (wire.GroupContext{
        .version = wire.protocol_version_mls10,
        .cipher_suite = cipher_suite_id,
        .group_id = &group_id,
        .epoch = mp.epoch,
        .tree_hash = &tree_hash,
        .confirmed_transcript_hash = &cth,
        .extensions_raw = "",
    }).write(gpa, &gc);
    const facts: GroupFacts = .{ .group_id = &group_id, .epoch = mp.epoch, .gc_bytes = gc.items };

    // --- PublicMessage: the vector's proposal_pub and commit_pub verify,
    // and our own protection round-trips.
    const proposal_raw = hx(mp.proposal);
    const commit_raw = hx(mp.commit);
    inline for (.{ .{ mp.proposal_pub, proposal_raw }, .{ mp.commit_pub, commit_raw } }) |case| {
        const msg_bytes = hx(case[0]);
        const m = try wire.MlsMessage.parse(&msg_bytes);
        try unprotectPublic(gpa, facts, m.public_message, sig_pub, membership_key);
        try testing.expectEqual(@as(u32, 1), m.public_message.content.sender.member);

        // The framed body re-serializes to exactly the raw value.
        var body_bytes: std.ArrayList(u8) = .empty;
        defer body_bytes.deinit(gpa);
        try m.public_message.content.body.write(gpa, &body_bytes);
        try testing.expectEqualSlices(u8, &case[1], body_bytes.items);

        // Our own protection of the same body verifies too.
        const ours = try protectPublic(gpa, facts, 1, sig_seed, membership_key, m.public_message.content.body, m.public_message.auth.confirmation_tag);
        defer gpa.free(ours);
        const mo = try wire.MlsMessage.parse(ours);
        try unprotectPublic(gpa, facts, mo.public_message, sig_pub, membership_key);
    }

    // Application data refuses the public path (§15.2).
    const app_raw = hx(mp.application);
    try testing.expectError(error.UnexpectedMessage, protectPublic(gpa, facts, 1, sig_seed, membership_key, .{ .application = &app_raw }, null));

    // --- PrivateMessage: the vector's three messages open; our own
    // protection opens with an independently initialized secret tree.
    inline for (.{ mp.proposal_priv, mp.commit_priv, mp.application_priv }) |msg_hex| {
        const msg_bytes = hx(msg_hex);
        const m = try wire.MlsMessage.parse(&msg_bytes);
        var hs = schedule.ratchetInit(encryption_secret, 1, 2, .handshake);
        var app = schedule.ratchetInit(encryption_secret, 1, 2, .application);
        defer hs.wipe();
        defer app.wipe();
        var opened = try unprotectPrivate(gpa, facts, m.private_message, 1, sig_pub, &hs, &app, sender_data_secret);
        defer opened.deinit(gpa);

        var body_bytes: std.ArrayList(u8) = .empty;
        defer body_bytes.deinit(gpa);
        try opened.body.write(gpa, &body_bytes);
        switch (opened.body) {
            .application => try testing.expectEqualSlices(u8, &app_raw, opened.body.application),
            .proposal => try testing.expectEqualSlices(u8, &proposal_raw, body_bytes.items),
            .commit => try testing.expectEqualSlices(u8, &commit_raw, body_bytes.items),
        }

        // Round-trip our own protection of the same body.
        var send_ratchet = schedule.ratchetInit(encryption_secret, 1, 2, if (opened.body == .application) .application else .handshake);
        defer send_ratchet.wipe();
        const ours = try protectPrivate(gpa, facts, 1, sig_seed, opened.body, opened.auth.confirmation_tag, &send_ratchet, sender_data_secret, .{ 1, 2, 3, 4 }, 13);
        defer gpa.free(ours);
        var hs2 = schedule.ratchetInit(encryption_secret, 1, 2, .handshake);
        var app2 = schedule.ratchetInit(encryption_secret, 1, 2, .application);
        defer hs2.wipe();
        defer app2.wipe();
        const mo = try wire.MlsMessage.parse(ours);
        var opened2 = try unprotectPrivate(gpa, facts, mo.private_message, 1, sig_pub, &hs2, &app2, sender_data_secret);
        defer opened2.deinit(gpa);
        var body2: std.ArrayList(u8) = .empty;
        defer body2.deinit(gpa);
        try opened2.body.write(gpa, &body2);
        try testing.expectEqualSlices(u8, body_bytes.items, body2.items);
    }
}

test "interop treekem (two leaves): process the vector's paths, then our own" {
    const gpa = testing.allocator;
    const tk = vec.treekem2;
    const group_id = hx(tk.group_id);
    const cth = hx(tk.confirmed_transcript_hash);
    const tree_bytes = hx(tk.ratchet_tree);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const slots = try parseTreeSlots(arena_state.allocator(), &tree_bytes);
    try testing.expectEqual(@as(usize, 3), slots.len);

    const enc_privs = [2][32]u8{ hx(tk.leaf0_encryption_priv), hx(tk.leaf1_encryption_priv) };
    const sig_privs = [2][32]u8{ hx(tk.leaf0_signature_priv), hx(tk.leaf1_signature_priv) };

    inline for (.{
        .{ 0, tk.up0_update_path, tk.up0_peer_path_secret, tk.up0_commit_secret, tk.up0_tree_hash_after },
        .{ 1, tk.up1_update_path, tk.up1_peer_path_secret, tk.up1_commit_secret, tk.up1_tree_hash_after },
    }) |case| {
        const sender: u32 = case[0];
        const receiver: u32 = 1 - sender;
        const up_bytes = hx(case[1]);
        const want_path_secret = hx(case[2]);
        const want_commit_secret = hx(case[3]);
        const want_tree_hash = hx(case[4]);

        var upr = wire.Reader.init(&up_bytes);
        const up = try wire.UpdatePath.parseFrom(&upr);
        try upr.finish();
        var nit = up.nodesIter();
        const node = (try nit.next()).?;
        try testing.expectEqual(@as(?wire.UpdatePathNode, null), try nit.next());
        const root_pub = node.encryption_key[0..pk_len].*;

        // Parent-hash validity: the sender's new leaf commits to the new
        // root over the receiver's (unchanged) leaf.
        const receiver_leaf_hash = leafHash(receiver, slots[receiver * 2].?.bytes);
        const want_ph = parentHashRoot2(root_pub, receiver_leaf_hash);
        try testing.expectEqualSlices(u8, &want_ph, up.leaf_node.source.commit);

        // The merged tree hash.
        var sender_leaf: std.ArrayList(u8) = .empty;
        defer sender_leaf.deinit(gpa);
        try up.leaf_node.write(gpa, &sender_leaf);
        const sender_leaf_hash = leafHash(sender, sender_leaf.items);
        const merged = if (sender == 0)
            treeHash2(root_pub, sender_leaf_hash, receiver_leaf_hash)
        else
            treeHash2(root_pub, receiver_leaf_hash, sender_leaf_hash);
        try testing.expectEqualSlices(u8, &want_tree_hash, &merged);

        // Decrypt the path secret as the receiver (context: the provisional
        // GroupContext with the vector's epoch and the merged tree hash).
        var gc: std.ArrayList(u8) = .empty;
        defer gc.deinit(gpa);
        try (wire.GroupContext{
            .version = wire.protocol_version_mls10,
            .cipher_suite = cipher_suite_id,
            .group_id = &group_id,
            .epoch = tk.epoch,
            .tree_hash = &merged,
            .confirmed_transcript_hash = &cth,
            .extensions_raw = "",
        }).write(gpa, &gc);
        var cit = node.ciphertextsIter();
        const ct = (try cit.next()).?;
        try testing.expectEqual(@as(?wire.HpkeCiphertext, null), try cit.next());
        var path_secret: Secret = undefined;
        try decryptWithLabel(gpa, enc_privs[receiver], "UpdatePathNode", gc.items, ct.kem_output, ct.ciphertext, &path_secret);
        try testing.expectEqualSlices(u8, &want_path_secret, &path_secret);
        const commit_secret = schedule.deriveSecret(path_secret, "path");
        try testing.expectEqualSlices(u8, &want_commit_secret, &commit_secret);

        // Now create our OWN update path as the receiver and process it
        // from the other side: same commit secret on both ends.
        const my_path_secret: Secret = [_]u8{0x5a} ** 32;
        var node_secret = schedule.deriveSecret(my_path_secret, "node");
        const my_root_kp = try Kem.deriveKeyPair(&node_secret);
        const enc_kp = try Kem.deriveKeyPair("a fresh leaf encryption seed for treekem!");
        const other_leaf_hash = leafHash(sender, slots[sender * 2].?.bytes);
        const my_ph = parentHashRoot2(my_root_kp.pk, other_leaf_hash);
        const my_leaf_new = try rebuildCommitLeaf(gpa, slots[receiver * 2].?.bytes, enc_kp.pk, my_ph, &group_id, receiver, sig_privs[receiver]);
        defer gpa.free(my_leaf_new);
        const my_merged = if (receiver == 0)
            treeHash2(my_root_kp.pk, leafHash(0, my_leaf_new), other_leaf_hash)
        else
            treeHash2(my_root_kp.pk, other_leaf_hash, leafHash(1, my_leaf_new));
        var gc2: std.ArrayList(u8) = .empty;
        defer gc2.deinit(gpa);
        try (wire.GroupContext{
            .version = wire.protocol_version_mls10,
            .cipher_suite = cipher_suite_id,
            .group_id = &group_id,
            .epoch = tk.epoch,
            .tree_hash = &my_merged,
            .confirmed_transcript_hash = &cth,
            .extensions_raw = "",
        }).write(gpa, &gc2);

        // Seal to the OTHER leaf's public key; open with its private key.
        var lr = wire.Reader.init(slots[sender * 2].?.bytes);
        const other_leaf = try wire.LeafNode.parse(&lr);
        var ps_ct: std.ArrayList(u8) = .empty;
        defer ps_ct.deinit(gpa);
        const ps_enc = try encryptWithLabel(gpa, other_leaf.encryption_key[0..pk_len].*, "UpdatePathNode", gc2.items, &my_path_secret, [_]u8{0x77} ** 32, &ps_ct);
        var back: Secret = undefined;
        try decryptWithLabel(gpa, enc_privs[sender], "UpdatePathNode", gc2.items, &ps_enc, ps_ct.items, &back);
        try testing.expectEqualSlices(u8, &my_path_secret, &back);

        // And our rebuilt leaf is parent-hash valid + signature valid.
        var mlr = wire.Reader.init(my_leaf_new);
        const my_ln = try wire.LeafNode.parse(&mlr);
        try testing.expectEqualSlices(u8, &my_ph, my_ln.source.commit);
        try validateLeaf(gpa, my_ln, receiver, &group_id);
    }
}

test "interop passive-client-welcome: joins and honest refusals" {
    const gpa = testing.allocator;

    // Entries 0 and 1: no PSKs, tree embedded in the Welcome. The
    // schedule-level check (epoch authenticator) must pass; the full join
    // additionally passes whenever the group is our two-member shape.
    inline for (.{ vec.passive.e0, vec.passive.e1 }) |e| {
        const welcome_msg = hx(e.welcome_msg);
        const kp_msg = hx(e.key_package);
        const init_priv = hx(e.init_priv);
        const want_auth = hx(e.initial_epoch_authenticator);

        var ow = try openWelcome(gpa, &welcome_msg, &kp_msg, init_priv);
        defer ow.deinit(gpa);
        const gi = try wire.GroupInfo.parse(ow.group_info);
        const secrets = schedule.epochFromJoiner(ow.joiner_secret, @splat(0), gi.group_context_raw);
        try testing.expectEqualSlices(u8, &want_auth, &secrets.epoch_authenticator);

        if (join(gpa, &welcome_msg, &kp_msg, .{
            .init_priv = init_priv,
            .enc_priv = hx(e.encryption_priv),
            .sig_seed = hx(e.signature_priv),
        })) |g| {
            var group = g;
            defer group.deinit(gpa);
            try testing.expectEqualSlices(u8, &want_auth, &group.secrets.epoch_authenticator);
            try testing.expect(group.ratchets_live);
        } else |err| {
            // Anything but our recorded scope limit is a real failure.
            try testing.expectEqual(@as(MlsError, error.UnsupportedGroupSize), err);
        }
    }

    // Entry 2 carries PSKs: refused outright (v1 speaks no PSKs), never
    // half-honored.
    {
        const welcome_msg = hx(vec.passive.e2.welcome_msg);
        const kp_msg = hx(vec.passive.e2.key_package);
        try testing.expectError(error.UnsupportedPsk, openWelcome(gpa, &welcome_msg, &kp_msg, hx(vec.passive.e2.init_priv)));
    }

    // Entry 4: the tree is provided out of band, not in the GroupInfo —
    // the schedule still proves out; the full join names the missing tree.
    {
        const welcome_msg = hx(vec.passive.e4.welcome_msg);
        const kp_msg = hx(vec.passive.e4.key_package);
        const init_priv = hx(vec.passive.e4.init_priv);
        var ow = try openWelcome(gpa, &welcome_msg, &kp_msg, init_priv);
        defer ow.deinit(gpa);
        const gi = try wire.GroupInfo.parse(ow.group_info);
        const secrets = schedule.epochFromJoiner(ow.joiner_secret, @splat(0), gi.group_context_raw);
        try testing.expectEqualSlices(u8, &hx(vec.passive.e4.initial_epoch_authenticator), &secrets.epoch_authenticator);
        try testing.expectError(error.MissingRatchetTree, join(gpa, &welcome_msg, &kp_msg, .{
            .init_priv = init_priv,
            .enc_priv = hx(vec.passive.e4.encryption_priv),
            .sig_seed = hx(vec.passive.e4.signature_priv),
        }));
    }
}

test "end to end: create, add via Welcome, exchange, rotate (PCS), forward secrecy" {
    const gpa = testing.allocator;
    const seed_a = [_]u8{0xa1} ** 32;
    const seed_b = [_]u8{0xb2} ** 32;

    // A creates the group alone; application traffic is refused until the
    // peer exists.
    var a = try createGroup(gpa, "did:plc:alice", seed_a, .{
        .group_id = [_]u8{0x61} ** 32,
        .enc_seed = [_]u8{0x11} ** 32,
        .epoch_secret = [_]u8{0x22} ** 32,
    });
    defer a.deinit(gpa);
    try testing.expectError(error.WrongState, encrypt(gpa, &a, "too early", 0, .{ 0, 0, 0, 0 }));

    // B publishes a KeyPackage; A adds B and builds the Welcome.
    var bkp = try generateKeyPackage(gpa, "did:plc:bob", seed_b, 0, std.math.maxInt(u64), .{
        .init_seed = [_]u8{0x33} ** 32,
        .enc_seed = [_]u8{0x44} ** 32,
    });
    defer bkp.deinit(gpa);
    const welcome_msg = try addPeer(gpa, &a, bkp.bytes, 1_000_000, .{
        .enc_seed = [_]u8{0x55} ** 32,
        .path_secret = [_]u8{0x66} ** 32,
        .welcome_seed = [_]u8{0x77} ** 32,
    });
    defer gpa.free(welcome_msg);
    try testing.expectEqual(@as(u64, 1), a.epoch);

    // B joins from the Welcome: same epoch, same secrets, mirrored roles.
    var b = try join(gpa, welcome_msg, bkp.bytes, .{
        .init_priv = bkp.init_priv,
        .enc_priv = bkp.enc_priv,
        .sig_seed = seed_b,
    });
    defer b.deinit(gpa);
    try testing.expectEqual(@as(u64, 1), b.epoch);
    try testing.expectEqual(@as(u32, 1), b.my_leaf);
    try testing.expectEqualSlices(u8, &a.secrets.epoch_authenticator, &b.secrets.epoch_authenticator);
    try testing.expect(b.root_priv_present);

    // Both directions, multiple generations, padding on.
    const m1 = try encrypt(gpa, &a, "hello bob", 0, .{ 1, 2, 3, 4 });
    defer gpa.free(m1);
    const r1 = try receive(gpa, &b, m1);
    try testing.expectEqualSlices(u8, "hello bob", r1.application);
    gpa.free(r1.application);

    const m2 = try encrypt(gpa, &a, "second message", 64, .{ 5, 6, 7, 8 });
    defer gpa.free(m2);
    const r2 = try receive(gpa, &b, m2);
    try testing.expectEqualSlices(u8, "second message", r2.application);
    gpa.free(r2.application);

    const m3 = try encrypt(gpa, &b, "hi alice", 0, .{ 9, 9, 9, 9 });
    defer gpa.free(m3);
    const r3 = try receive(gpa, &a, m3);
    try testing.expectEqualSlices(u8, "hi alice", r3.application);
    gpa.free(r3.application);

    // Replay is rejected (the generation was consumed), and tampering is
    // rejected without corrupting the state (E2).
    try testing.expectError(error.StaleGeneration, receive(gpa, &b, m1));
    {
        const m4 = try encrypt(gpa, &a, "will be tampered", 0, .{ 2, 2, 2, 2 });
        defer gpa.free(m4);
        m4[m4.len - 1] ^= 1;
        try testing.expectError(error.DecryptFailed, receive(gpa, &b, m4));
    }
    // The tampered message burned its generation (keys are never reused);
    // the next fresh message still flows.
    const m5 = try encrypt(gpa, &a, "after the storm", 0, .{ 3, 3, 3, 3 });
    defer gpa.free(m5);
    const r5 = try receive(gpa, &b, m5);
    try testing.expectEqualSlices(u8, "after the storm", r5.application);
    gpa.free(r5.application);

    // A rotates (PCS): empty commit with a full path, protected in the old
    // epoch; B processes it and both land in epoch 2 with fresh secrets.
    const old_auth = a.secrets.epoch_authenticator;
    const c1 = try commit(gpa, &a, 0, .{
        .enc_seed = [_]u8{0x88} ** 32,
        .path_secret = [_]u8{0x99} ** 32,
        .seal_seed = [_]u8{0xaa} ** 32,
        .reuse_guard = .{ 4, 4, 4, 4 },
    });
    defer gpa.free(c1);
    try testing.expectEqual(@as(u64, 2), a.epoch);
    try testing.expectEqual(Received.epoch_advanced, try receive(gpa, &b, c1));
    try testing.expectEqual(@as(u64, 2), b.epoch);
    try testing.expectEqualSlices(u8, &a.secrets.epoch_authenticator, &b.secrets.epoch_authenticator);
    try testing.expect(!std.mem.eql(u8, &old_auth, &a.secrets.epoch_authenticator));

    // Forward secrecy, behaviorally: an old-epoch message can no longer
    // enter (the epoch is gone), and replaying the commit is refused.
    try testing.expectError(error.WrongEpoch, receive(gpa, &b, m5));
    try testing.expectError(error.WrongEpoch, receive(gpa, &b, c1));

    // Fresh epoch, both directions still converse.
    const m6 = try encrypt(gpa, &b, "post-rotation", 0, .{ 6, 6, 6, 6 });
    defer gpa.free(m6);
    const r6 = try receive(gpa, &a, m6);
    try testing.expectEqualSlices(u8, "post-rotation", r6.application);
    gpa.free(r6.application);

    // And B can rotate too — the roles are symmetric.
    const c2 = try commit(gpa, &b, 32, .{
        .enc_seed = [_]u8{0xbb} ** 32,
        .path_secret = [_]u8{0xcc} ** 32,
        .seal_seed = [_]u8{0xdd} ** 32,
        .reuse_guard = .{ 5, 5, 5, 5 },
    });
    defer gpa.free(c2);
    try testing.expectEqual(Received.epoch_advanced, try receive(gpa, &a, c2));
    try testing.expectEqual(@as(u64, 3), a.epoch);
    try testing.expectEqualSlices(u8, &a.secrets.epoch_authenticator, &b.secrets.epoch_authenticator);

    const m7 = try encrypt(gpa, &a, "third epoch", 0, .{ 7, 7, 7, 7 });
    defer gpa.free(m7);
    const r7 = try receive(gpa, &b, m7);
    try testing.expectEqualSlices(u8, "third epoch", r7.application);
    gpa.free(r7.application);
}

test "wipeEpoch zeroes the schedule and both ratchets in place" {
    const gpa = testing.allocator;
    var g = try createGroup(gpa, "did:plc:wipe", [_]u8{0xee} ** 32, .{
        .group_id = [_]u8{0x01} ** 32,
        .enc_seed = [_]u8{0x02} ** 32,
        .epoch_secret = [_]u8{0x03} ** 32,
    });
    defer g.deinit(gpa);
    try testing.expect(!std.mem.allEqual(u8, &g.secrets.init, 0));
    g.wipeEpoch();
    try testing.expect(std.mem.allEqual(u8, std.mem.asBytes(&g.secrets), 0));
    for (g.ratchets) |pair| for (pair) |r| {
        try testing.expect(std.mem.allEqual(u8, &r.secret, 0));
    };
}

test "persistence: a serialized group resumes the conversation exactly (M1)" {
    const gpa = testing.allocator;
    const seed_a = [_]u8{0xa1} ** 32;
    const seed_b = [_]u8{0xb2} ** 32;

    var a = try createGroup(gpa, "did:plc:alice", seed_a, .{
        .group_id = [_]u8{0x71} ** 32,
        .enc_seed = [_]u8{0x11} ** 32,
        .epoch_secret = [_]u8{0x22} ** 32,
    });
    defer a.deinit(gpa);
    var bkp = try generateKeyPackage(gpa, "did:plc:bob", seed_b, 0, std.math.maxInt(u64), .{
        .init_seed = [_]u8{0x33} ** 32,
        .enc_seed = [_]u8{0x44} ** 32,
    });
    defer bkp.deinit(gpa);
    const welcome_msg = try addPeer(gpa, &a, bkp.bytes, 1_000_000, .{
        .enc_seed = [_]u8{0x55} ** 32,
        .path_secret = [_]u8{0x66} ** 32,
        .welcome_seed = [_]u8{0x77} ** 32,
    });
    defer gpa.free(welcome_msg);
    var b = try join(gpa, welcome_msg, bkp.bytes, .{
        .init_priv = bkp.init_priv,
        .enc_priv = bkp.enc_priv,
        .sig_seed = seed_b,
    });
    defer b.deinit(gpa);

    // Some traffic advances the ratchets, then B "relaunches": serialize,
    // destroy, restore.
    const m1 = try encrypt(gpa, &a, "before the restart", 0, .{ 1, 2, 3, 4 });
    defer gpa.free(m1);
    const r1 = try receive(gpa, &b, m1);
    gpa.free(r1.application);

    // The peer identity reads back from the live group (both sides).
    try testing.expectEqualStrings("did:plc:bob", peerIdentity(&a));
    try testing.expectEqualStrings("did:plc:alice", peerIdentity(&b));

    const blob = try serializeGroup(gpa, &b);
    defer {
        std.crypto.secureZero(u8, blob);
        gpa.free(blob);
    }
    b.deinit(gpa);
    b = try deserializeGroup(gpa, blob);

    // The restored group continues BOTH directions, then survives a full
    // rotation (commit) from either side.
    const m2 = try encrypt(gpa, &a, "after the restart", 0, .{ 5, 6, 7, 8 });
    defer gpa.free(m2);
    const r2 = try receive(gpa, &b, m2);
    try testing.expectEqualSlices(u8, "after the restart", r2.application);
    gpa.free(r2.application);
    const m3 = try encrypt(gpa, &b, "resumed and replying", 0, .{ 9, 8, 7, 6 });
    defer gpa.free(m3);
    const r3 = try receive(gpa, &a, m3);
    try testing.expectEqualSlices(u8, "resumed and replying", r3.application);
    gpa.free(r3.application);

    const rot = try commit(gpa, &b, 0, .{
        .enc_seed = [_]u8{0x88} ** 32,
        .path_secret = [_]u8{0x99} ** 32,
        .seal_seed = [_]u8{0xAA} ** 32,
        .reuse_guard = .{ 1, 1, 1, 1 },
    });
    defer gpa.free(rot);
    const ra = try receive(gpa, &a, rot);
    try testing.expectEqual(Received.epoch_advanced, ra);
    try testing.expectEqual(a.epoch, b.epoch);
    const m4 = try encrypt(gpa, &a, "new epoch still speaks", 0, .{ 2, 2, 2, 2 });
    defer gpa.free(m4);
    const r4 = try receive(gpa, &b, m4);
    try testing.expectEqualSlices(u8, "new epoch still speaks", r4.application);
    gpa.free(r4.application);

    // Damage is refused, never half-restored.
    try testing.expectError(error.BadMessage, deserializeGroup(gpa, blob[0 .. blob.len - 1]));
    try testing.expectError(error.BadMessage, deserializeGroup(gpa, "not a group"));

    // Routing accessors: a private message routes by group id; a welcome is
    // recognized by kind.
    try testing.expectEqual(MessageKind.private_message, messageKind(m4));
    try testing.expectEqual(MessageKind.welcome, messageKind(welcome_msg));
    try testing.expectEqualSlices(u8, b.group_id, try privateMessageGroupId(m4));
    try testing.expectEqual(MessageKind.other, messageKind("zz"));
}
