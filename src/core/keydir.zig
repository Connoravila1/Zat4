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

/// The BOOTSTRAP mailbox for an anchor key: where first contact (the
/// Welcome) and v1 traffic land. Derived from the anchor PUBLIC key, so
/// anyone holding the published record can address it — which is exactly
/// the recorded caveat (a relay operator who also scrapes repos could link
/// this mailbox to a DID); per-epoch mailboxes out of the MLS secret tree
/// are the recorded follow-up. Stable across keyPackage refreshes (the
/// anchor outlives packages).
pub fn bootstrapMailbox(anchor_pub: [anchor.pk_len]u8) [32]u8 {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update("Zat4 Chat 1.0 BootstrapMailbox");
    h.update(&anchor_pub);
    var out: [32]u8 = undefined;
    h.final(&out);
    return out;
}

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
// THE DEVICE SET (CHAT_MULTIDEVICE slice 0). An account is one identity with
// SEVERAL devices, and we used to model it as one identity with exactly one —
// which is why a phone could only ever take chat away from a desktop.
//
// Each device publishes its OWN record, under its own rkey, holding its own
// keys. Nothing is copied and no device can overwrite another's record. But a
// record's mere EXISTENCE proves nothing: anyone with the account's credentials
// can write records into its repo. What makes a device real is that an
// already-trusted device SIGNED FOR IT (anchor.verifyDeviceApproval).
//
// So the account's device set is a chain of vouching, rooted at the first device
// ever to use chat:
//
//   root (self-attested)  →  approves phone  →  phone may approve a third
//
// A record nobody vouched for is ignored — which is precisely why a credential
// thief cannot SILENTLY join your conversations. What they can do is publish a
// NEW ROOT ("start fresh"), and that is loud by construction: the root key
// changes, and every peer that had you pinned sees it and says so.
// ---------------------------------------------------------------------------

/// A device's decoded record (the shell owns JSON/base64; D3). A7.2: cold
/// parameter carrier, size guard waived.
pub const DeviceRecord = struct {
    did: []const u8,
    cipher_suite: u16,
    key_package: []const u8,
    /// The per-device anchor→DID binding — every device signs the DID itself.
    anchor_sig: []const u8,
    not_after: i64,
    /// The first device of the account self-attests; it has no approval to show.
    root: bool,
    /// An approved device's signature over (this device's key + the DID). Empty
    /// on the root. We do NOT record WHO signed — we simply test it against every
    /// device already trusted, which means the record carries no claim it could
    /// lie about.
    approval_sig: []const u8,
    /// Record timestamp (unix seconds) — only ever used to pick the NEWEST root.
    created_at: i64,
};

/// A device that is genuinely part of the account. `key_package` borrows the
/// caller's bytes. A7.2: cold, transient.
pub const Device = struct {
    anchor_pub: [anchor.pk_len]u8,
    key_package: []const u8,
    root: bool,
};

/// The account's chat identity as it stands right now. A7.2: cold, transient.
pub const DeviceSet = struct {
    /// Approved devices, root first, then by key — a stable order, so two peers
    /// resolving the same records agree on what they see.
    devices: []Device,
    /// The CURRENT root's key. This is the account's chat identity: if a peer
    /// pinned one root and now resolves a different one, the account started
    /// chat on a new device, and the peer must SAY SO rather than quietly carry
    /// on (which is what a successful impersonation would look like).
    root_pub: [anchor.pk_len]u8,
};

/// A hard ceiling on devices. Without it, anybody who can write to a repo could
/// publish a thousand device records and have every peer try to add a thousand
/// members to every group — a fan-out bomb aimed at other people's clients. Eight
/// is far past what a person owns and far short of what hurts.
pub const max_devices = 8;

/// PURE: decide which of these records are real devices of `repo_did`.
///
/// A record that fails validation is DROPPED, not fatal: one corrupt device
/// record must not take an account's whole chat identity offline (E4 — the
/// ordinary result is "these are the devices we can prove", not an error).
/// Returns an empty set (and a zero root) when the account has no valid root:
/// that is simply "this account has not used chat", not a failure.
pub fn resolveDevices(
    gpa: Allocator,
    repo_did: []const u8,
    recs: []const DeviceRecord,
    now: i64,
) error{OutOfMemory}!DeviceSet {
    // 1. Every record faces the SAME six checks a single-device record faces.
    //    A device that cannot prove custody of its own key is not a device.
    var valid = try std.ArrayListUnmanaged(struct { rec: DeviceRecord, pub_key: [anchor.pk_len]u8 }).initCapacity(gpa, recs.len);
    defer valid.deinit(gpa);
    for (recs) |r| {
        const peer = validate(gpa, repo_did, .{
            .did = r.did,
            .cipher_suite = r.cipher_suite,
            .key_package = r.key_package,
            .anchor_sig = r.anchor_sig,
            .not_after = r.not_after,
        }, now) catch continue;
        valid.appendAssumeCapacity(.{ .rec = r, .pub_key = peer.anchor_pub });
    }

    // 2. THE ROOT. Several can exist only when the account has started chat over
    //    (an old root's record still lying in the repo); the NEWEST wins, and the
    //    tie-break is the key itself so that every peer picks the same one.
    var root_idx: ?usize = null;
    for (valid.items, 0..) |v, i| {
        if (!v.rec.root) continue;
        const best = root_idx orelse {
            root_idx = i;
            continue;
        };
        const b = valid.items[best];
        const newer = v.rec.created_at > b.rec.created_at;
        const tied = v.rec.created_at == b.rec.created_at and std.mem.order(u8, &v.pub_key, &b.pub_key) == .gt;
        if (newer or tied) root_idx = i;
    }
    const root = root_idx orelse return .{ .devices = &.{}, .root_pub = [_]u8{0} ** anchor.pk_len };

    // 3. THE CHAIN OF VOUCHING. Start with the root; grow the trusted set by any
    //    record an already-trusted device has signed for. Iterate to a fixpoint,
    //    so the root may approve the phone and the phone a third device — but a
    //    record NOBODY vouched for never enters the set, no matter who wrote it.
    var out = try std.ArrayListUnmanaged(Device).initCapacity(gpa, @min(valid.items.len, max_devices));
    errdefer out.deinit(gpa);
    const rv = valid.items[root];
    out.appendAssumeCapacity(.{ .anchor_pub = rv.pub_key, .key_package = rv.rec.key_package, .root = true });

    var added = true;
    while (added and out.items.len < max_devices) {
        added = false;
        for (valid.items, 0..) |v, i| {
            if (i == root or v.rec.root) continue; // roots other than the winner are stale
            if (v.rec.approval_sig.len == 0) continue; // a claim with no proof is not a claim
            var already = false;
            for (out.items) |d| {
                if (std.mem.eql(u8, &d.anchor_pub, &v.pub_key)) already = true;
            }
            if (already) continue;

            // Vouched for by ANY device already trusted? We do not take the
            // record's word for who signed it — we check them all.
            for (out.items) |d| {
                anchor.verifyDeviceApproval(d.anchor_pub, repo_did, v.pub_key, v.rec.approval_sig) catch continue;
                out.appendAssumeCapacity(.{ .anchor_pub = v.pub_key, .key_package = v.rec.key_package, .root = false });
                added = true;
                break;
            }
            if (out.items.len >= max_devices) break;
        }
    }

    // 4. A stable order: root first, the rest by key. Two peers resolving the same
    //    repo must see the same set in the same order, or they will disagree about
    //    a group's membership.
    std.mem.sort(Device, out.items[1..], {}, struct {
        fn lt(_: void, a: Device, b: Device) bool {
            return std.mem.order(u8, &a.anchor_pub, &b.anchor_pub) == .lt;
        }
    }.lt);

    return .{ .devices = try out.toOwnedSlice(gpa), .root_pub = rv.pub_key };
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

// ---------------------------------------------------------------------------
// Device-set tests (CHAT_MULTIDEVICE slice 0). These are the claims the feature
// makes to a user, written as code: a second device joins only if an existing
// one vouched for it; a credential thief cannot silently join; starting fresh is
// visible.
// ---------------------------------------------------------------------------

const DevFixture = struct {
    // A7.2: cold struct (a test fixture, never in a hot loop), size guard waived.
    seed: [anchor.seed_len]u8,
    pub_key: [anchor.pk_len]u8,
    kp: []u8,
    binding: [anchor.sig_len]u8,
};

fn makeDevice(gpa: Allocator, seed_byte: u8, init_byte: u8) !DevFixture {
    const seed: [anchor.seed_len]u8 = [_]u8{seed_byte} ** 32;
    var bundle = try mls.generateKeyPackage(gpa, test_did, seed, 0, 4102444800, .{
        .init_seed = [_]u8{init_byte} ** 32,
        .enc_seed = [_]u8{init_byte +% 1} ** 32,
    });
    defer bundle.deinit(gpa);
    return .{
        .seed = seed,
        .pub_key = try anchor.publicKey(seed),
        .kp = try gpa.dupe(u8, bundle.bytes),
        .binding = try anchor.signDidBinding(seed, test_did),
    };
}

/// BY POINTER, deliberately: the record borrows `&d.binding`, and a by-value
/// parameter dies at the end of this function — which would hand every caller a
/// dangling signature slice.
fn deviceRec(d: *const DevFixture, is_root: bool, approval: []const u8, created: i64) DeviceRecord {
    return .{
        .did = test_did,
        .cipher_suite = mls.cipher_suite_id,
        .key_package = d.kp,
        .anchor_sig = &d.binding,
        .not_after = 2_000_000_000,
        .root = is_root,
        .approval_sig = approval,
        .created_at = created,
    };
}

const now_s: i64 = 1_751_400_000;

test "devices: the root alone, then a phone the root vouched for" {
    const gpa = testing.allocator;
    const desktop = try makeDevice(gpa, 0x51, 0x33);
    defer gpa.free(desktop.kp);
    const phone = try makeDevice(gpa, 0x62, 0x44);
    defer gpa.free(phone.kp);

    // Just the desktop: one device, and it is the root — the account's identity.
    {
        const set = try resolveDevices(gpa, test_did, &.{deviceRec(&desktop, true, "", 100)}, now_s);
        defer gpa.free(set.devices);
        try testing.expectEqual(@as(usize, 1), set.devices.len);
        try testing.expect(set.devices[0].root);
        try testing.expectEqualSlices(u8, &desktop.pub_key, &set.root_pub);
    }

    // The desktop approves the phone: BOTH are now the account, and the root did
    // not change — nobody started over, somebody added a device.
    {
        const approval = try anchor.signDeviceApproval(desktop.seed, test_did, phone.pub_key);
        const set = try resolveDevices(gpa, test_did, &.{
            deviceRec(&desktop, true, "", 100),
            deviceRec(&phone, false, &approval, 200),
        }, now_s);
        defer gpa.free(set.devices);
        try testing.expectEqual(@as(usize, 2), set.devices.len);
        try testing.expectEqualSlices(u8, &desktop.pub_key, &set.root_pub);
        var saw_phone = false;
        for (set.devices) |d| {
            if (std.mem.eql(u8, &d.anchor_pub, &phone.pub_key)) saw_phone = true;
        }
        try testing.expect(saw_phone);
    }
}

test "devices: A CREDENTIAL THIEF CANNOT SILENTLY JOIN" {
    // The attack the whole design exists to stop. The thief has the password, so
    // they can write whatever they like into the repo — including a perfectly
    // well-formed device record for a device they hold, with a valid DID binding
    // of their own. What they do NOT have is the desktop's anchor private key, so
    // they cannot produce an approval. Peers must ignore them.
    const gpa = testing.allocator;
    const desktop = try makeDevice(gpa, 0x51, 0x33);
    defer gpa.free(desktop.kp);
    const thief = try makeDevice(gpa, 0x9e, 0x77);
    defer gpa.free(thief.kp);

    // No approval at all.
    {
        const set = try resolveDevices(gpa, test_did, &.{
            deviceRec(&desktop, true, "", 100),
            deviceRec(&thief, false, "", 200),
        }, now_s);
        defer gpa.free(set.devices);
        try testing.expectEqual(@as(usize, 1), set.devices.len);
        try testing.expectEqualSlices(u8, &desktop.pub_key, &set.devices[0].anchor_pub);
    }

    // An approval the thief signed FOR THEMSELVES — the obvious forgery, and the
    // one a lesser design (trusting an `approvedBy` field) would have swallowed.
    {
        const self_signed = try anchor.signDeviceApproval(thief.seed, test_did, thief.pub_key);
        const set = try resolveDevices(gpa, test_did, &.{
            deviceRec(&desktop, true, "", 100),
            deviceRec(&thief, false, &self_signed, 200),
        }, now_s);
        defer gpa.free(set.devices);
        try testing.expectEqual(@as(usize, 1), set.devices.len);
    }

    // An approval LIFTED from an honest one: the desktop approved the phone, and
    // the thief pastes that signature onto their own record. It is a signature
    // over the PHONE's key, so it says nothing about the thief's.
    {
        const phone = try makeDevice(gpa, 0x62, 0x44);
        defer gpa.free(phone.kp);
        const for_phone = try anchor.signDeviceApproval(desktop.seed, test_did, phone.pub_key);
        const set = try resolveDevices(gpa, test_did, &.{
            deviceRec(&desktop, true, "", 100),
            deviceRec(&thief, false, &for_phone, 300),
        }, now_s);
        defer gpa.free(set.devices);
        try testing.expectEqual(@as(usize, 1), set.devices.len);
    }
}

test "devices: a device the phone vouched for is trusted (the chain, to a fixpoint)" {
    const gpa = testing.allocator;
    const desktop = try makeDevice(gpa, 0x51, 0x33);
    defer gpa.free(desktop.kp);
    const phone = try makeDevice(gpa, 0x62, 0x44);
    defer gpa.free(phone.kp);
    const laptop = try makeDevice(gpa, 0x73, 0x55);
    defer gpa.free(laptop.kp);

    const a_phone = try anchor.signDeviceApproval(desktop.seed, test_did, phone.pub_key);
    const a_laptop = try anchor.signDeviceApproval(phone.seed, test_did, laptop.pub_key);

    // Deliberately out of order: the laptop's voucher appears BEFORE the voucher
    // itself is trusted, so a single pass would have dropped it.
    const set = try resolveDevices(gpa, test_did, &.{
        deviceRec(&laptop, false, &a_laptop, 300),
        deviceRec(&desktop, true, "", 100),
        deviceRec(&phone, false, &a_phone, 200),
    }, now_s);
    defer gpa.free(set.devices);
    try testing.expectEqual(@as(usize, 3), set.devices.len);
    try testing.expect(set.devices[0].root); // root always first
}

test "devices: STARTING FRESH IS VISIBLE — a new root wins and orphans the old set" {
    // The lost-device path. A new device mints a new root; the old root's record
    // may well still be sitting in the repo. The newest root wins, everything the
    // OLD root vouched for is dropped, and `root_pub` CHANGES — which is the
    // signal a peer needs in order to say "connor started chat on a new device"
    // instead of silently carrying on, which is what impersonation looks like.
    const gpa = testing.allocator;
    const old_root = try makeDevice(gpa, 0x51, 0x33);
    defer gpa.free(old_root.kp);
    const old_phone = try makeDevice(gpa, 0x62, 0x44);
    defer gpa.free(old_phone.kp);
    const new_root = try makeDevice(gpa, 0x84, 0x66);
    defer gpa.free(new_root.kp);

    const approval = try anchor.signDeviceApproval(old_root.seed, test_did, old_phone.pub_key);
    const set = try resolveDevices(gpa, test_did, &.{
        deviceRec(&old_root, true, "", 100),
        deviceRec(&old_phone, false, &approval, 150),
        deviceRec(&new_root, true, "", 900), // the replacement device
    }, now_s);
    defer gpa.free(set.devices);

    try testing.expectEqualSlices(u8, &new_root.pub_key, &set.root_pub);
    try testing.expectEqual(@as(usize, 1), set.devices.len); // the old set is gone
    try testing.expectEqualSlices(u8, &new_root.pub_key, &set.devices[0].anchor_pub);
}

test "devices: an account with no valid root is simply not on chat (E4)" {
    const gpa = testing.allocator;
    const orphan = try makeDevice(gpa, 0x62, 0x44);
    defer gpa.free(orphan.kp);
    // A device record with no root anywhere: not an error, just nobody to talk to.
    const set = try resolveDevices(gpa, test_did, &.{deviceRec(&orphan, false, "", 200)}, now_s);
    defer gpa.free(set.devices);
    try testing.expectEqual(@as(usize, 0), set.devices.len);
    try testing.expectEqualSlices(u8, &([_]u8{0} ** anchor.pk_len), &set.root_pub);

    // And an empty repo likewise.
    const none = try resolveDevices(gpa, test_did, &.{}, now_s);
    defer gpa.free(none.devices);
    try testing.expectEqual(@as(usize, 0), none.devices.len);
}

test "devices: a broken record is dropped, not fatal — and the fan-out is capped" {
    const gpa = testing.allocator;
    const desktop = try makeDevice(gpa, 0x51, 0x33);
    defer gpa.free(desktop.kp);
    const phone = try makeDevice(gpa, 0x62, 0x44);
    defer gpa.free(phone.kp);
    const approval = try anchor.signDeviceApproval(desktop.seed, test_did, phone.pub_key);

    // One corrupt record must not take the account's whole chat identity offline.
    var junk = deviceRec(&phone, false, &approval, 200);
    junk.key_package = "not a key package at all";
    const set = try resolveDevices(gpa, test_did, &.{
        deviceRec(&desktop, true, "", 100),
        junk,
        deviceRec(&phone, false, &approval, 200),
    }, now_s);
    defer gpa.free(set.devices);
    try testing.expectEqual(@as(usize, 2), set.devices.len);

    // The cap holds: nobody can make a peer fan a group out to a thousand leaves.
    try testing.expect(set.devices.len <= max_devices);
}
