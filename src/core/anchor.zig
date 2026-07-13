//! B1 classification: CORE (pure). The Zat Chat anchor key's DID binding
//! (ZAT_CHAT_ROADMAP slice C6).
//!
//! The anchor key is the device-bound Ed25519 identity for chat. It is
//! generated in the shell (`io.randomSecure`), persisted by `shell/cache.zig`
//! (OS keystore preferred, 0600 file fallback), and NEVER delegated to the
//! PDS — the repo signing key IS PDS-delegated, which is fine for public
//! posts and fatal for E2EE (ZAT5_MESSAGING §5). The 32-byte anchor seed is
//! exactly the `sig_seed` parameter `core/mls.zig` signs with, so the MLS
//! leaf's `signature_key` IS the anchor public key.
//!
//! This module is the BIDIRECTIONAL DID↔anchor bind the keyPackage record
//! publishes (U6):
//!   - repo → anchor: the record lives in the DID's own repo and its signed
//!     KeyPackage leaf carries the anchor public key;
//!   - anchor → DID: `signDidBinding` signs the DID under a domain-separated
//!     label (the record's `anchorKeySig`), and `verifyDidBinding` checks it
//!     against the leaf's signature key.
//! A record that fails the bind proves nothing about anchor-key custody for
//! that DID, and the conversation must not start.
//!
//! Pure (B2/B4): no clock, no RNG, no allocation — signing is deterministic
//! Ed25519 over a bounded stack buffer, which is what makes every test below
//! a fixed-vector test. Identity crosses this boundary as the DID (A5).

const std = @import("std");
const Ed25519 = std.crypto.sign.Ed25519;

pub const seed_len = 32;
pub const pk_len = 32;
pub const sig_len = 64;

/// atproto caps DIDs at 2 KB; the cap is what keeps signing allocation-free.
pub const max_did_len = 2048;

/// Domain separation for the anchor→DID signature, in the codebase's labeled-
/// signature idiom (mls.zig's "MLS 1.0 " prefixing). Changing this string is
/// a BREAKING identity change — every published binding stops verifying — so
/// the pinned-vector test below freezes it.
const binding_label = "Zat4 Chat 1.0 AnchorDidBinding";

pub const AnchorError = error{ BadKey, BadSignature, DidTooLong };

fn bindingMessage(buf: *[binding_label.len + max_did_len]u8, did: []const u8) AnchorError![]const u8 {
    if (did.len > max_did_len) return error.DidTooLong;
    @memcpy(buf[0..binding_label.len], binding_label);
    @memcpy(buf[binding_label.len..][0..did.len], did);
    return buf[0 .. binding_label.len + did.len];
}

/// The anchor public key for a seed — what the keyPackage leaf publishes.
pub fn publicKey(seed: [seed_len]u8) AnchorError![pk_len]u8 {
    const kp = Ed25519.KeyPair.generateDeterministic(seed) catch return error.BadKey;
    return kp.public_key.toBytes();
}

/// anchor → DID: the `anchorKeySig` the keyPackage record carries.
pub fn signDidBinding(seed: [seed_len]u8, did: []const u8) AnchorError![sig_len]u8 {
    var buf: [binding_label.len + max_did_len]u8 = undefined;
    const msg = try bindingMessage(&buf, did);
    const kp = Ed25519.KeyPair.generateDeterministic(seed) catch return error.BadKey;
    const sig = kp.sign(msg, null) catch return error.BadKey;
    return sig.toBytes();
}

/// Verify a counterparty's binding against the anchor key their keyPackage
/// publishes. `sig` is untrusted wire bytes, so it arrives as a slice.
pub fn verifyDidBinding(anchor_pub: [pk_len]u8, did: []const u8, sig: []const u8) AnchorError!void {
    if (sig.len != sig_len) return error.BadSignature;
    var buf: [binding_label.len + max_did_len]u8 = undefined;
    const msg = try bindingMessage(&buf, did);
    const pk = Ed25519.PublicKey.fromBytes(anchor_pub) catch return error.BadKey;
    Ed25519.Signature.fromBytes(sig[0..sig_len].*).verify(msg, pk) catch return error.BadSignature;
}

// ---------------------------------------------------------------------------
// Relay auth (CHAT_HARDENING A4 slice 2). The relay used to know no one: one
// shared bearer token, baked into every client, and any connection could
// deposit anything anywhere. Identity is what makes abuse ATTRIBUTABLE and
// scarce, and the anchor key is the identity we already have — the directory
// binds it to the DID, and the peer's bootstrap mailbox is derived from it.
//
// The proof is a signature over a nonce the SERVER chose, so it cannot be
// replayed onto another connection; and it is domain-separated from the DID
// binding above, so neither signature can ever be presented as the other.
// ---------------------------------------------------------------------------

pub const challenge_len = 32;

/// A distinct label — the whole point of domain separation. A published
/// `anchorKeySig` must not be replayable as a relay login, and a relay login
/// must not be replayable as a published binding.
const relay_auth_label = "Zat4 Chat 1.0 RelayAuth";

fn relayAuthMessage(
    buf: *[relay_auth_label.len + challenge_len + max_did_len]u8,
    challenge: [challenge_len]u8,
    did: []const u8,
) AnchorError![]const u8 {
    if (did.len > max_did_len) return error.DidTooLong;
    @memcpy(buf[0..relay_auth_label.len], relay_auth_label);
    @memcpy(buf[relay_auth_label.len..][0..challenge_len], &challenge);
    @memcpy(buf[relay_auth_label.len + challenge_len ..][0..did.len], did);
    return buf[0 .. relay_auth_label.len + challenge_len + did.len];
}

/// Sign the relay's connect challenge: "I hold the anchor key that the
/// directory binds to this DID."
pub fn signRelayAuth(seed: [seed_len]u8, challenge: [challenge_len]u8, did: []const u8) AnchorError![sig_len]u8 {
    var buf: [relay_auth_label.len + challenge_len + max_did_len]u8 = undefined;
    const msg = try relayAuthMessage(&buf, challenge, did);
    const kp = Ed25519.KeyPair.generateDeterministic(seed) catch return error.BadKey;
    const sig = kp.sign(msg, null) catch return error.BadKey;
    return sig.toBytes();
}

/// The relay's half: the signature must be over THIS connection's challenge
/// and the claimed DID, under the anchor key the caller resolved from the
/// directory. Untrusted wire bytes throughout (E3).
pub fn verifyRelayAuth(
    anchor_pub: [pk_len]u8,
    challenge: [challenge_len]u8,
    did: []const u8,
    sig: []const u8,
) AnchorError!void {
    if (sig.len != sig_len) return error.BadSignature;
    var buf: [relay_auth_label.len + challenge_len + max_did_len]u8 = undefined;
    const msg = try relayAuthMessage(&buf, challenge, did);
    const pk = Ed25519.PublicKey.fromBytes(anchor_pub) catch return error.BadKey;
    Ed25519.Signature.fromBytes(sig[0..sig_len].*).verify(msg, pk) catch return error.BadSignature;
}

// ---------------------------------------------------------------------------
// DEVICE APPROVAL (CHAT_MULTIDEVICE slice 0). An account may hold several
// devices, and each keeps its OWN keys — nothing is ever copied. So a second
// device is not admitted by possessing a secret; it is admitted by an EXISTING
// device SAYING SO, in a signature.
//
// This is the whole security of the feature. Anyone holding the account's
// credentials can write records into its repo (that is what a password IS), so
// repo-write authority cannot be what gates a new device — a credential thief
// would simply publish themselves and be fanned into every future conversation.
// What a thief does NOT have is an approved device's anchor PRIVATE key, and
// that is what signs this. A device nobody approved is a device peers ignore.
//
// (What a thief CAN still do is a loud "start fresh" — mint a new root and take
// chat over. That is visible by construction — the peer sees the root change and
// SAYS SO — and it is bounded by the credential layer, not by this one. The line
// this draws is the one that matters: no SILENT join.)
//
// Domain-separated, like every other signature here: an approval must never be
// replayable as a DID binding or a relay login, nor either of those as an
// approval.
// ---------------------------------------------------------------------------

const approval_label = "Zat4 Chat 1.0 DeviceApproval";

fn approvalMessage(
    buf: *[approval_label.len + pk_len + max_did_len]u8,
    did: []const u8,
    device_pub: [pk_len]u8,
) AnchorError![]const u8 {
    if (did.len > max_did_len) return error.DidTooLong;
    @memcpy(buf[0..approval_label.len], approval_label);
    @memcpy(buf[approval_label.len..][0..pk_len], &device_pub);
    @memcpy(buf[approval_label.len + pk_len ..][0..did.len], did);
    return buf[0 .. approval_label.len + pk_len + did.len];
}

/// An approved device says: "this other device belongs to this account too."
/// The DID is signed alongside the key, so an approval minted for one account
/// cannot be lifted onto another.
pub fn signDeviceApproval(seed: [seed_len]u8, did: []const u8, device_pub: [pk_len]u8) AnchorError![sig_len]u8 {
    var buf: [approval_label.len + pk_len + max_did_len]u8 = undefined;
    const msg = try approvalMessage(&buf, did, device_pub);
    const kp = Ed25519.KeyPair.generateDeterministic(seed) catch return error.BadKey;
    const sig = kp.sign(msg, null) catch return error.BadKey;
    return sig.toBytes();
}

/// The peer's half: does an ALREADY-TRUSTED device of this account vouch for
/// this one? Untrusted wire bytes throughout (E3).
pub fn verifyDeviceApproval(
    approver_pub: [pk_len]u8,
    did: []const u8,
    device_pub: [pk_len]u8,
    sig: []const u8,
) AnchorError!void {
    if (sig.len != sig_len) return error.BadSignature;
    var buf: [approval_label.len + pk_len + max_did_len]u8 = undefined;
    const msg = try approvalMessage(&buf, did, device_pub);
    const pk = Ed25519.PublicKey.fromBytes(approver_pub) catch return error.BadKey;
    Ed25519.Signature.fromBytes(sig[0..sig_len].*).verify(msg, pk) catch return error.BadSignature;
}

// ---------------------------------------------------------------------------
// Tests. Deterministic Ed25519 means these are all fixed-vector tests (C6:
// nothing allocates, so the leak allocator has nothing to see).
// ---------------------------------------------------------------------------

const testing = std.testing;

const test_seed: [seed_len]u8 = .{
    0x0b, 0x1f, 0x2e, 0x3d, 0x4c, 0x5b, 0x6a, 0x79,
    0x88, 0x97, 0xa6, 0xb5, 0xc4, 0xd3, 0xe2, 0xf1,
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
    0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xf0,
};
const test_did = "did:plc:ewvi7nxzyoun6zhxrhs64oiz";

test "anchor: the bind round-trips and rejects every tamper" {
    const pub_key = try publicKey(test_seed);
    const sig = try signDidBinding(test_seed, test_did);
    try verifyDidBinding(pub_key, test_did, &sig);

    // A different DID under the same signature: refused.
    try testing.expectError(error.BadSignature, verifyDidBinding(pub_key, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", &sig));

    // A different anchor key: refused.
    var other_seed = test_seed;
    other_seed[0] ^= 1;
    const other_pub = try publicKey(other_seed);
    try testing.expectError(error.BadSignature, verifyDidBinding(other_pub, test_did, &sig));

    // A flipped signature byte: refused.
    var bad_sig = sig;
    bad_sig[17] ^= 1;
    try testing.expectError(error.BadSignature, verifyDidBinding(pub_key, test_did, &bad_sig));

    // A truncated signature: refused before any crypto runs.
    try testing.expectError(error.BadSignature, verifyDidBinding(pub_key, test_did, sig[0..32]));
}

test "anchor: a DID over the atproto cap is refused" {
    const long = [_]u8{'x'} ** (max_did_len + 1);
    try testing.expectError(error.DidTooLong, signDidBinding(test_seed, &long));
    const pub_key = try publicKey(test_seed);
    try testing.expectError(error.DidTooLong, verifyDidBinding(pub_key, &long, &[_]u8{0} ** sig_len));
}

test "anchor: pinned vector freezes the domain label" {
    // Generated once from this module and pinned; a mismatch means the
    // binding label or construction CHANGED, which breaks every published
    // binding in the field. That must be a deliberate, versioned act.
    const sig = try signDidBinding(test_seed, test_did);
    var pinned: [sig_len]u8 = undefined;
    _ = try std.fmt.hexToBytes(&pinned, "d49eec5d331a86cc548ea13d69e178b3aa03b91fdc16eb5037a65645571585b4" ++
        "124c980e00b96ef8e8233eb2697c9e1011d17a78debbee55e49a21fb3b485904");
    try testing.expectEqualSlices(u8, &pinned, &sig);
}

test "anchor: the MLS keyPackage publishes this anchor key (the C6 chain)" {
    // The full identity chain U6 will rely on: the anchor seed drives
    // mls.generateKeyPackage as its sig_seed, the resulting leaf's
    // signature_key must BE the anchor public key, the credential identity
    // must BE the DID, and the DID binding must verify against that
    // published key.
    const gpa = testing.allocator;
    const mls = @import("mls.zig");
    const wire = @import("mls_wire.zig");

    var bundle = try mls.generateKeyPackage(gpa, test_did, test_seed, 0, 4102444800, .{
        .init_seed = [_]u8{0x11} ** 32,
        .enc_seed = [_]u8{0x22} ** 32,
    });
    defer bundle.deinit(gpa);

    const msg = try wire.MlsMessage.parse(bundle.bytes);
    const leaf = msg.key_package.leaf_node;
    const anchor_pub = try publicKey(test_seed);
    try testing.expectEqualSlices(u8, &anchor_pub, leaf.signature_key);
    try testing.expectEqualStrings(test_did, leaf.credential.identity);

    const sig = try signDidBinding(test_seed, test_did);
    try verifyDidBinding(leaf.signature_key[0..pk_len].*, test_did, &sig);
}

test "anchor: relay auth binds the challenge, the DID, and the key — and nothing else" {
    const anchor_pub = try publicKey(test_seed);
    const challenge: [challenge_len]u8 = @splat(0x5C);
    const sig = try signRelayAuth(test_seed, challenge, test_did);
    try verifyRelayAuth(anchor_pub, challenge, test_did, &sig);

    // A DIFFERENT challenge does not verify — this is the whole point: a
    // signature lifted off one connection cannot log in on another.
    var other = challenge;
    other[0] ^= 1;
    try testing.expectError(error.BadSignature, verifyRelayAuth(anchor_pub, other, test_did, &sig));

    // A different DID, and a different key, are both refused.
    try testing.expectError(error.BadSignature, verifyRelayAuth(anchor_pub, challenge, "did:plc:someoneelse", &sig));
    var wrong_key = anchor_pub;
    wrong_key[0] ^= 1;
    try testing.expect(std.meta.isError(verifyRelayAuth(wrong_key, challenge, test_did, &sig)));

    // DOMAIN SEPARATION. The published anchorKeySig (a DID binding) must not
    // be usable as a relay login, and a relay login must not be publishable as
    // a binding. Two labels, two message shapes — neither verifies as the
    // other, and that is enforced here so no refactor can quietly merge them.
    const binding = try signDidBinding(test_seed, test_did);
    try testing.expectError(error.BadSignature, verifyRelayAuth(anchor_pub, challenge, test_did, &binding));
    try testing.expectError(error.BadSignature, verifyDidBinding(anchor_pub, test_did, &sig));

    // A truncated signature is an explicit error, not a panic (E3).
    try testing.expectError(error.BadSignature, verifyRelayAuth(anchor_pub, challenge, test_did, sig[0 .. sig_len - 1]));
}

test "anchor: a device approval verifies, and every substitution fails" {
    const approver_seed = test_seed;
    const approver_pub = try publicKey(approver_seed);

    // The device being approved (its own keys — nothing is copied to it).
    const device_seed: [seed_len]u8 = [_]u8{0x5c} ** 32;
    const device_pub = try publicKey(device_seed);

    const sig = try signDeviceApproval(approver_seed, test_did, device_pub);
    try verifyDeviceApproval(approver_pub, test_did, device_pub, &sig);

    // A DIFFERENT device key: this is the attack the signature exists to stop —
    // a thief who can write to the repo swapping their own key into an approval
    // an honest device made for a device the owner actually approved.
    const thief_pub = try publicKey([_]u8{0x9e} ** 32);
    try testing.expectError(error.BadSignature, verifyDeviceApproval(approver_pub, test_did, thief_pub, &sig));

    // Another account's DID: an approval cannot be lifted between accounts.
    try testing.expectError(error.BadSignature, verifyDeviceApproval(approver_pub, "did:plc:someoneelseaaaaaaaaaaaaaaaa", device_pub, &sig));

    // A key nobody approved with: an unapproved device is simply not approved.
    try testing.expectError(error.BadSignature, verifyDeviceApproval(thief_pub, test_did, device_pub, &sig));

    // A tampered signature.
    var bad = sig;
    bad[0] ^= 0x01;
    try testing.expectError(error.BadSignature, verifyDeviceApproval(approver_pub, test_did, device_pub, &bad));
    try testing.expectError(error.BadSignature, verifyDeviceApproval(approver_pub, test_did, device_pub, sig[0 .. sig_len - 1]));
}

test "anchor: the three signatures are domain-separated — none is replayable as another" {
    // The security of every one of them rests on this. An approval presented as a
    // relay login, or a published DID binding presented as an approval, must not
    // verify — which is what the distinct labels buy.
    const seed = test_seed;
    const pub_key = try publicKey(seed);
    const device_pub = try publicKey([_]u8{0x33} ** 32);
    const challenge: [challenge_len]u8 = [_]u8{0x44} ** challenge_len;

    const binding = try signDidBinding(seed, test_did);
    const relay = try signRelayAuth(seed, challenge, test_did);
    const approval = try signDeviceApproval(seed, test_did, device_pub);

    try testing.expectError(error.BadSignature, verifyDeviceApproval(pub_key, test_did, device_pub, &binding));
    try testing.expectError(error.BadSignature, verifyDeviceApproval(pub_key, test_did, device_pub, &relay));
    try testing.expectError(error.BadSignature, verifyDidBinding(pub_key, test_did, &approval));
    try testing.expectError(error.BadSignature, verifyRelayAuth(pub_key, challenge, test_did, &approval));
}
