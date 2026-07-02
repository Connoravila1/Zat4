//! B1 classification: CORE (pure). The chat key directory's record
//! semantics (ZAT_CHAT_ROADMAP slice U6): what an `app.zat4.chat.keyPackage`
//! record MEANS and when it is believed.
//!
//! The user's PDS is the decentralized key directory (vision doc §5): the
//! repo holds ONE long-lived, explicitly-marked last-resort KeyPackage for
//! bootstrapping. This module is the fetch-side gate — the record_check
//! idiom: plain values in, an explicit verdict out, no I/O, `now` passed in
//! (B4). The shell's record module (`shell/chat_keys.zig`) owns the JSON
//! wire shape and base64; only decoded values cross into here (D3).
//!
//! What `validate` proves before a conversation may start:
//!   1. the record's `did` IS the repo it came from (a record copied into
//!      another repo proves nothing — the fetch side must pass the repo DID
//!      it actually read from);
//!   2. the cipher suite is the one we speak (the value is compared here;
//!      every suite DECISION stays inside core/mls.zig — D1);
//!   3. the record-level `notAfter` has not lapsed (the KeyPackage's own
//!      internal lifetime is checked by mls with the same clock);
//!   4. the KeyPackage itself is structurally valid and BOTH its signatures
//!      verify (mls.checkKeyPackage);
//!   5. the leaf's credential identity IS the record's DID;
//!   6. the anchor→DID binding verifies against the leaf's signature key —
//!      the bidirectional bind (C6): the repo publishes the anchor key, the
//!      anchor key signs the DID.
//! A record that fails ANY check proves nothing about anchor-key custody
//! for that DID, and the conversation must not start (E3: every failure is
//! named).

const std = @import("std");
const Allocator = std.mem.Allocator;
const mls = @import("mls.zig");
const anchor = @import("anchor.zig");

/// The decoded record values, as the shell hands them over (D3: no JSON,
/// no base64 here). A7.2: cold struct, size guard waived — transient
/// parameter carrier, one per fetch.
pub const Record = struct {
    /// The record's own `did` field.
    did: []const u8,
    /// The record's `cipherSuite`.
    cipher_suite: u16,
    /// MLSMessage(KeyPackage) wire bytes (decoded from the record).
    key_package: []const u8,
    /// The anchor-key signature over the DID (`anchorKeySig`, decoded).
    anchor_sig: []const u8,
    /// Record-level expiry, unix seconds (parsed from `notAfter`).
    not_after: i64,
};

pub const ValidateError = error{
    DidMismatch,
    WrongSuite,
    Expired,
    IdentityMismatch,
    BadBinding,
    BadKeyPackage,
    OutOfMemory,
};

/// The facts a valid record establishes. `anchor_pub` is what a client may
/// pin/display; A7.2: cold struct, size guard waived — transient result.
pub const Peer = struct {
    anchor_pub: [anchor.pk_len]u8,
};

/// The fetch-side gate (checks 1–6 above). `repo_did` is the repo the
/// record was actually read from; `now` is the caller's clock (B4).
pub fn validate(gpa: Allocator, repo_did: []const u8, rec: Record, now: i64) ValidateError!Peer {
    if (!std.mem.eql(u8, rec.did, repo_did)) return error.DidMismatch;
    if (rec.cipher_suite != mls.cipher_suite_id) return error.WrongSuite;
    if (now > rec.not_after) return error.Expired;

    const info = mls.checkKeyPackage(gpa, rec.key_package, @intCast(@max(0, now))) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory,
        error.Expired => return error.Expired,
        error.WrongSuite => return error.WrongSuite,
        else => return error.BadKeyPackage,
    };
    if (!std.mem.eql(u8, info.identity, rec.did)) return error.IdentityMismatch;

    anchor.verifyDidBinding(info.signature_key, rec.did, rec.anchor_sig) catch return error.BadBinding;
    return .{ .anchor_pub = info.signature_key };
}

// ---------------------------------------------------------------------------
// Tests (B2, C6) — a real generated KeyPackage through the gate, then every
// tamper the gate exists to refuse.
// ---------------------------------------------------------------------------

const testing = std.testing;

const test_did = "did:plc:keydirtestaaaaaaaaaaaaaa";
const test_seed: [anchor.seed_len]u8 = [_]u8{0x51} ** 32;

fn testRecord(gpa: Allocator) !struct { bytes: []u8, sig: [anchor.sig_len]u8 } {
    var bundle = try mls.generateKeyPackage(gpa, test_did, test_seed, 0, 4102444800, .{
        .init_seed = [_]u8{0x33} ** 32,
        .enc_seed = [_]u8{0x44} ** 32,
    });
    defer bundle.deinit(gpa);
    const bytes = try gpa.dupe(u8, bundle.bytes);
    return .{ .bytes = bytes, .sig = try anchor.signDidBinding(test_seed, test_did) };
}

test "keydir: a genuine record passes and yields the anchor key" {
    const gpa = testing.allocator;
    const tr = try testRecord(gpa);
    defer gpa.free(tr.bytes);

    const peer = try validate(gpa, test_did, .{
        .did = test_did,
        .cipher_suite = mls.cipher_suite_id,
        .key_package = tr.bytes,
        .anchor_sig = &tr.sig,
        .not_after = 2_000_000_000,
    }, 1_751_400_000);
    try testing.expectEqualSlices(u8, &(try anchor.publicKey(test_seed)), &peer.anchor_pub);
}

test "keydir: every tamper is refused by name" {
    const gpa = testing.allocator;
    const tr = try testRecord(gpa);
    defer gpa.free(tr.bytes);
    const good: Record = .{
        .did = test_did,
        .cipher_suite = mls.cipher_suite_id,
        .key_package = tr.bytes,
        .anchor_sig = &tr.sig,
        .not_after = 2_000_000_000,
    };
    const now: i64 = 1_751_400_000;

    // 1. A record copied into someone else's repo.
    try testing.expectError(error.DidMismatch, validate(gpa, "did:plc:someoneelse", good, now));

    // 2. A suite we do not speak.
    var r = good;
    r.cipher_suite = 0x0002;
    try testing.expectError(error.WrongSuite, validate(gpa, test_did, r, now));

    // 3. A lapsed record.
    r = good;
    r.not_after = now - 1;
    try testing.expectError(error.Expired, validate(gpa, test_did, r, now));

    // 4. A damaged KeyPackage (one flipped byte breaks a signature).
    const damaged = try gpa.dupe(u8, tr.bytes);
    defer gpa.free(damaged);
    damaged[damaged.len - 10] ^= 1;
    r = good;
    r.key_package = damaged;
    try testing.expectError(error.BadKeyPackage, validate(gpa, test_did, r, now));

    // 5. A record whose did is not the leaf's credential identity: the
    //    caller passes the record's did as repo too (they match each other),
    //    but the KeyPackage inside was minted for someone else.
    var other = try mls.generateKeyPackage(gpa, "did:plc:otheridentity", test_seed, 0, 4102444800, .{
        .init_seed = [_]u8{0x55} ** 32,
        .enc_seed = [_]u8{0x66} ** 32,
    });
    defer other.deinit(gpa);
    r = good;
    r.key_package = other.bytes;
    try testing.expectError(error.IdentityMismatch, validate(gpa, test_did, r, now));

    // 6. A binding signed by a DIFFERENT anchor key.
    var wrong_seed = test_seed;
    wrong_seed[0] ^= 1;
    const wrong_sig = try anchor.signDidBinding(wrong_seed, test_did);
    r = good;
    r.anchor_sig = &wrong_sig;
    try testing.expectError(error.BadBinding, validate(gpa, test_did, r, now));

    // The KeyPackage's own internal lifetime is enforced too (mls, same clock).
    try testing.expectError(error.Expired, validate(gpa, test_did, good, 4102444801));
}
