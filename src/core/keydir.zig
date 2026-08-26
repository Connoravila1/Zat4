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

pub const Claim = anchor.Claim;
pub const Generation = anchor.Generation;

/// A device's decoded record (the shell owns JSON/base64; D3). A7.2: cold
/// parameter carrier, size guard waived.
pub const DeviceRecord = struct {
    did: []const u8,
    cipher_suite: u16,
    key_package: []const u8,
    /// The per-device anchor→DID binding — every device signs the DID itself.
    anchor_sig: []const u8,
    not_after: i64,
    /// WHICH DEVICE-SET GENERATION this record claims. Highest generation wins.
    /// This replaced `root: bool` + newest-`createdAt`-wins: one bit could not
    /// carry both "the first device this account ever had" and "I am
    /// deliberately starting over", and an identity should not change hands on a
    /// clock (CHAT_DEVICE_MODEL_REDESIGN D1/D2).
    generation: Generation,
    /// `anchor.Claim` as it arrived on the wire. Kept raw so a value we do not
    /// recognize is REPORTED as an invalid record rather than silently dropped —
    /// the whole point of this module's rework is that nothing disappears
    /// without a reason attached.
    claim_raw: u8,
    /// For `.recovery`: the root key this generation supersedes. Zero otherwise.
    superseded_root: [anchor.pk_len]u8,
    /// This device's OWN signature over (generation, claim, superseded_root).
    /// Without it, `generation` would be unsigned metadata and anyone with the
    /// account's password could promote a device's record into a higher
    /// generation and evict every other device — see `anchor.signDeviceClaim`.
    claim_sig: []const u8,
    /// WHO approved this device. Named — and named inside the approval's signed
    /// message, so it is proved rather than believed. Zero when there is none.
    approval_by: [anchor.pk_len]u8,
    /// The approver's signature over (generation, approver, this device, DID).
    /// Empty on a record that roots a generation.
    approval_sig: []const u8,
    /// Audit and display ONLY. This decided who owned the account's chat
    /// identity until 2026-08-26; `generation` decides now.
    created_at: i64,
};

/// WHAT TO DO ABOUT A DEVICE — one value per distinct remedy, and no more. The
/// old model answered this with a bare in-set/not-in-set bool, which is why a
/// screen could not tell "nobody has approved you yet" from "you belong to a
/// device set that was replaced", and told the person the wrong thing.
pub const Standing = enum(u8) {
    /// Part of the account's chat identity right now.
    active,
    /// Well-formed and published; nobody has vouched for it yet. Remedy:
    /// another device approves it.
    awaiting_approval,
    /// Not part of the current device set, and no approval can make it one —
    /// it must re-join. Remedy: re-join at the current generation.
    orphaned,
    /// The record itself does not hold up. Remedy: republish it.
    invalid,
};

/// WHY — the explanation, kept separate from the remedy on purpose. `Standing`
/// decides what to do; `Reason` is what a person or a log gets told. Diagnosing
/// the 2026-08-26 prompt took a live PDS read plus a full code read precisely
/// because this did not exist.
pub const Reason = enum(u8) {
    /// `.active` / `.awaiting_approval`: there is nothing to explain.
    none,
    /// Belongs to a generation that is not the current one.
    superseded_generation,
    /// Another record won the current generation's root (decided by key order,
    /// so every peer picks the same winner).
    conflicting_root,
    /// Vouched for by a key that is not in the current set.
    approver_not_trusted,
    /// The account has no device set at all — nothing roots any generation.
    no_current_root,
    /// Failed the six record checks.
    failed_validation,
    /// A `claim` byte this version does not know.
    unrecognized_claim,
    /// The generation it asserts is not one its own key signed for.
    claim_not_signed,
};

/// One device's answer, parallel to the records it was computed from. A7 — this
/// IS held in a collection and looped over, so it carries an exact size guard.
pub const DeviceStanding = struct {
    standing: Standing,
    reason: Reason,

    comptime {
        // Budget: two u8-backed enums, nothing else. Raising this means a field
        // was added, which needs a recorded justification (A7.1).
        std.debug.assert(@sizeOf(DeviceStanding) == 2);
    }
};

/// A device that is genuinely part of the account. `key_package` borrows the
/// caller's bytes. A7.2: cold, transient.
pub const Device = struct {
    anchor_pub: [anchor.pk_len]u8,
    key_package: []const u8,
    root: bool,
    /// The device that vouched for this one — zero for the root. The audit
    /// trail the old shape could not produce: it is now possible to say
    /// "approved by your desktop" instead of merely "approved".
    approved_by: [anchor.pk_len]u8,
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
    /// The generation those devices belong to. A peer that sees this go up knows
    /// a fresh start happened — and, unlike before, knows it happened because
    /// somebody chose it.
    generation: Generation,
};

/// A hard ceiling on devices. Without it, anybody who can write to a repo could
/// publish a thousand device records and have every peer try to add a thousand
/// members to every group — a fan-out bomb aimed at other people's clients. Eight
/// is far past what a person owns and far short of what hurts.
pub const max_devices = 8;

/// Everything one pass over the records establishes. A7.2: cold, transient —
/// one per resolution, freed by the caller.
const Classified = struct {
    /// Parallel to `recs` (A3): index i is the answer for record i.
    standings: []DeviceStanding,
    /// Parallel to `recs`; meaningless where the standing is `.invalid`.
    pub_keys: [][anchor.pk_len]u8,
    /// The generation in force, and which record roots it. Null root means the
    /// account has no device set at all.
    generation: Generation,
    root: ?usize,
};

fn classify(
    gpa: Allocator,
    repo_did: []const u8,
    recs: []const DeviceRecord,
    now: i64,
) error{OutOfMemory}!Classified {
    const standings = try gpa.alloc(DeviceStanding, recs.len);
    errdefer gpa.free(standings);
    const pub_keys = try gpa.alloc([anchor.pk_len]u8, recs.len);
    errdefer gpa.free(pub_keys);
    const claims = try gpa.alloc(?Claim, recs.len);
    defer gpa.free(claims);
    @memset(standings, .{ .standing = .invalid, .reason = .failed_validation });
    @memset(pub_keys, [_]u8{0} ** anchor.pk_len);
    @memset(claims, null);

    // 1. Every record faces the SAME six checks a single-device record faces,
    //    and then must prove it signed its own claim. A record that fails is
    //    NAMED invalid, not silently dropped (E4 — one corrupt record must not
    //    take an account's chat offline, but it must not vanish either).
    for (recs, 0..) |r, i| {
        const peer = validate(gpa, repo_did, .{
            .did = r.did,
            .cipher_suite = r.cipher_suite,
            .key_package = r.key_package,
            .anchor_sig = r.anchor_sig,
            .not_after = r.not_after,
        }, now) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory,
            else => continue, // stays .invalid / .failed_validation
        };
        const claim = std.enums.fromInt(Claim, r.claim_raw) orelse {
            standings[i] = .{ .standing = .invalid, .reason = .unrecognized_claim };
            continue;
        };
        anchor.verifyDeviceClaim(
            peer.anchor_pub,
            repo_did,
            r.generation,
            claim,
            r.superseded_root,
            r.claim_sig,
        ) catch {
            standings[i] = .{ .standing = .invalid, .reason = .claim_not_signed };
            continue;
        };
        pub_keys[i] = peer.anchor_pub;
        claims[i] = claim;
    }

    // 2. THE CURRENT GENERATION. Only a record that can ROOT a generation counts
    //    toward it — otherwise anyone could publish a `joined` record claiming
    //    generation 99 and strand the account in a generation with no root.
    //    Founding is generation 1 by definition; anything later is a recovery,
    //    and a recovery is a deliberate signed act (never an inference).
    var cur_gen: ?Generation = null;
    for (claims, 0..) |c, i| {
        const claim = c orelse continue;
        if (claim == .joined) continue;
        if (claim == .founding and recs[i].generation != 1) continue;
        if (cur_gen == null or recs[i].generation > cur_gen.?) cur_gen = recs[i].generation;
    }
    const gen = cur_gen orelse {
        for (claims, 0..) |c, i| {
            if (c == null) continue;
            standings[i] = .{ .standing = .orphaned, .reason = .no_current_root };
        }
        return .{ .standings = standings, .pub_keys = pub_keys, .generation = 0, .root = null };
    };

    // 3. THE ROOT of that generation. Two records can claim one generation (a
    //    race, or a thief's fresh start); the winner is decided by KEY ORDER so
    //    that every peer resolving the same repo picks the same one, and the
    //    loser is told why rather than silently skipped — which is exactly the
    //    trap the old `root: bool` created.
    var root_idx: usize = undefined;
    var have_root = false;
    for (claims, 0..) |c, i| {
        const claim = c orelse continue;
        if (claim == .joined or recs[i].generation != gen) continue;
        if (claim == .founding and gen != 1) continue;
        if (!have_root or std.mem.order(u8, &pub_keys[i], &pub_keys[root_idx]) == .lt) {
            root_idx = i;
            have_root = true;
        }
    }
    std.debug.assert(have_root); // `gen` came from such a record

    // 4. THE CHAIN OF VOUCHING, to a fixpoint. The root may approve the phone and
    //    the phone a third device — but a record nobody vouched for never enters
    //    the set, no matter who wrote it. The approval NAMES its approver, so
    //    this is a lookup rather than the old trial-verification against every
    //    trusted key; a forged name simply fails to verify.
    var trusted = try std.ArrayListUnmanaged([anchor.pk_len]u8).initCapacity(gpa, @min(recs.len, max_devices));
    defer trusted.deinit(gpa);
    trusted.appendAssumeCapacity(pub_keys[root_idx]);
    standings[root_idx] = .{ .standing = .active, .reason = .none };

    var added = true;
    while (added and trusted.items.len < max_devices) {
        added = false;
        for (claims, 0..) |c, i| {
            const claim = c orelse continue;
            if (standings[i].standing == .active) continue;
            if (claim != .joined or recs[i].generation != gen) continue;
            if (recs[i].approval_sig.len == 0) continue;

            var approver_trusted = false;
            for (trusted.items) |t| {
                if (std.mem.eql(u8, &t, &recs[i].approval_by)) {
                    approver_trusted = true;
                    break;
                }
            }
            if (!approver_trusted) continue;
            anchor.verifyDeviceApproval(
                recs[i].approval_by,
                repo_did,
                gen,
                pub_keys[i],
                recs[i].approval_sig,
            ) catch continue;

            trusted.appendAssumeCapacity(pub_keys[i]);
            standings[i] = .{ .standing = .active, .reason = .none };
            added = true;
            if (trusted.items.len >= max_devices) break;
        }
    }

    // 5. EVERY REMAINING VALID RECORD GETS A REASON. This loop is the point of
    //    the rework: before it, "not in the set" was one silent answer covering
    //    four situations with four different remedies.
    for (claims, 0..) |c, i| {
        const claim = c orelse continue;
        if (standings[i].standing == .active) continue;
        if (recs[i].generation != gen) {
            standings[i] = .{ .standing = .orphaned, .reason = .superseded_generation };
        } else if (claim != .joined) {
            standings[i] = .{ .standing = .orphaned, .reason = .conflicting_root };
        } else if (recs[i].approval_sig.len == 0) {
            standings[i] = .{ .standing = .awaiting_approval, .reason = .none };
        } else {
            standings[i] = .{ .standing = .orphaned, .reason = .approver_not_trusted };
        }
    }

    return .{ .standings = standings, .pub_keys = pub_keys, .generation = gen, .root = root_idx };
}

/// What one pass over an account's device records established. The arrays are
/// PARALLEL TO `recs` (A3) and owned by the caller — `freeClassification`.
/// No index crosses this boundary (A5): the root is named by its key.
/// A7.2: cold, one per resolution.
pub const Classification = struct {
    /// Index i is the verdict on record i.
    standings: []DeviceStanding,
    /// Index i is record i's anchor key; zero where the standing is `.invalid`.
    pub_keys: [][anchor.pk_len]u8,
    /// The generation in force; 0 when the account has no device set at all.
    generation: Generation,
    /// The current root's key; zero when there is no device set.
    root_pub: [anchor.pk_len]u8,
};

pub fn freeClassification(gpa: Allocator, c: *Classification) void {
    gpa.free(c.standings);
    gpa.free(c.pub_keys);
    c.* = undefined;
}

/// PURE: where every one of these records stands, and why.
///
/// THE single source of truth for membership — the client gate, the relay's
/// verifier and the UI all read this one answer, because two of the six bugs
/// this subsystem has produced were two consumers deriving membership with
/// their own subtly different rules (REDESIGN D5).
pub fn classifyDevices(
    gpa: Allocator,
    repo_did: []const u8,
    recs: []const DeviceRecord,
    now: i64,
) error{OutOfMemory}!Classification {
    const c = try classify(gpa, repo_did, recs, now);
    return .{
        .standings = c.standings,
        .pub_keys = c.pub_keys,
        .generation = c.generation,
        .root_pub = if (c.root) |r| c.pub_keys[r] else [_]u8{0} ** anchor.pk_len,
    };
}

/// PURE: decide which of these records are real devices of `repo_did` — the
/// `.active` ones, in an order two peers will agree on.
///
/// Returns an empty set (and a zero root) when the account has no valid root:
/// that is simply "this account has not used chat", not a failure (E4).
pub fn resolveDevices(
    gpa: Allocator,
    repo_did: []const u8,
    recs: []const DeviceRecord,
    now: i64,
) error{OutOfMemory}!DeviceSet {
    const c = try classify(gpa, repo_did, recs, now);
    defer gpa.free(c.standings);
    defer gpa.free(c.pub_keys);

    const root = c.root orelse return .{
        .devices = &.{},
        .root_pub = [_]u8{0} ** anchor.pk_len,
        .generation = 0,
    };

    var out = try std.ArrayListUnmanaged(Device).initCapacity(gpa, @min(recs.len, max_devices));
    errdefer out.deinit(gpa);
    out.appendAssumeCapacity(.{
        .anchor_pub = c.pub_keys[root],
        .key_package = recs[root].key_package,
        .root = true,
        .approved_by = [_]u8{0} ** anchor.pk_len,
    });
    for (c.standings, 0..) |s, i| {
        if (i == root or s.standing != .active) continue;
        out.appendAssumeCapacity(.{
            .anchor_pub = c.pub_keys[i],
            .key_package = recs[i].key_package,
            .root = false,
            .approved_by = recs[i].approval_by,
        });
    }

    // A stable order: root first, the rest by key. Two peers resolving the same
    // repo must see the same set in the same order, or they will disagree about
    // a group's membership.
    std.mem.sort(Device, out.items[1..], {}, struct {
        fn lt(_: void, a: Device, b: Device) bool {
            return std.mem.order(u8, &a.anchor_pub, &b.anchor_pub) == .lt;
        }
    }.lt);

    return .{
        .devices = try out.toOwnedSlice(gpa),
        .root_pub = c.pub_keys[root],
        .generation = c.generation,
    };
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

const no_key = [_]u8{0} ** anchor.pk_len;

/// BY POINTER, deliberately: the record borrows `&d.binding`, and a by-value
/// parameter dies at the end of this function — which would hand every caller a
/// dangling signature slice. The same goes for every signature passed in here:
/// declare it as a `const` in the test's own scope.
fn deviceRec(
    d: *const DevFixture,
    generation: Generation,
    claim: Claim,
    superseded_root: [anchor.pk_len]u8,
    claim_sig: []const u8,
    approval_by: [anchor.pk_len]u8,
    approval_sig: []const u8,
    created: i64,
) DeviceRecord {
    return .{
        .did = test_did,
        .cipher_suite = mls.cipher_suite_id,
        .key_package = d.kp,
        .anchor_sig = &d.binding,
        .not_after = 2_000_000_000,
        .generation = generation,
        .claim_raw = @intFromEnum(claim),
        .superseded_root = superseded_root,
        .claim_sig = claim_sig,
        .approval_by = approval_by,
        .approval_sig = approval_sig,
        .created_at = created,
    };
}

/// Generation 1, self-attested: the first device the account ever had.
fn founding(d: *const DevFixture, claim_sig: []const u8, created: i64) DeviceRecord {
    return deviceRec(d, 1, .founding, no_key, claim_sig, no_key, "", created);
}

/// Vouched into `generation` by `by`.
fn joined(
    d: *const DevFixture,
    generation: Generation,
    claim_sig: []const u8,
    by: [anchor.pk_len]u8,
    approval: []const u8,
    created: i64,
) DeviceRecord {
    return deviceRec(d, generation, .joined, no_key, claim_sig, by, approval, created);
}

/// A DELIBERATE fresh start into `generation`, naming the root it supersedes.
fn recovery(
    d: *const DevFixture,
    generation: Generation,
    superseded_root: [anchor.pk_len]u8,
    claim_sig: []const u8,
    created: i64,
) DeviceRecord {
    return deviceRec(d, generation, .recovery, superseded_root, claim_sig, no_key, "", created);
}

fn signFounding(d: *const DevFixture) ![anchor.sig_len]u8 {
    return anchor.signDeviceClaim(d.seed, test_did, 1, .founding, no_key);
}

fn signJoined(d: *const DevFixture, generation: Generation) ![anchor.sig_len]u8 {
    return anchor.signDeviceClaim(d.seed, test_did, generation, .joined, no_key);
}

const now_s: i64 = 1_751_400_000;

fn standingOf(gpa: Allocator, recs: []const DeviceRecord, i: usize) !DeviceStanding {
    var c = try classifyDevices(gpa, test_did, recs, now_s);
    defer freeClassification(gpa, &c);
    return c.standings[i];
}

test "devices: the root alone, then a phone the root vouched for" {
    const gpa = testing.allocator;
    const desktop = try makeDevice(gpa, 0x51, 0x33);
    defer gpa.free(desktop.kp);
    const phone = try makeDevice(gpa, 0x62, 0x44);
    defer gpa.free(phone.kp);
    const d_claim = try signFounding(&desktop);
    const p_claim = try signJoined(&phone, 1);

    // Just the desktop: one device, it roots generation 1, and it is the
    // account's identity.
    {
        const recs = [_]DeviceRecord{founding(&desktop, &d_claim, 100)};
        const set = try resolveDevices(gpa, test_did, &recs, now_s);
        defer gpa.free(set.devices);
        try testing.expectEqual(@as(usize, 1), set.devices.len);
        try testing.expect(set.devices[0].root);
        try testing.expectEqual(@as(Generation, 1), set.generation);
        try testing.expectEqualSlices(u8, &desktop.pub_key, &set.root_pub);
    }

    // The desktop approves the phone: BOTH are now the account, the generation
    // did NOT change — nobody started over, somebody added a device — and the
    // phone's record records who vouched for it.
    {
        const approval = try anchor.signDeviceApproval(desktop.seed, test_did, 1, phone.pub_key);
        const recs = [_]DeviceRecord{
            founding(&desktop, &d_claim, 100),
            joined(&phone, 1, &p_claim, desktop.pub_key, &approval, 200),
        };
        const set = try resolveDevices(gpa, test_did, &recs, now_s);
        defer gpa.free(set.devices);
        try testing.expectEqual(@as(usize, 2), set.devices.len);
        try testing.expectEqual(@as(Generation, 1), set.generation);
        try testing.expectEqualSlices(u8, &desktop.pub_key, &set.root_pub);

        var saw_phone = false;
        for (set.devices) |d| {
            if (!std.mem.eql(u8, &d.anchor_pub, &phone.pub_key)) continue;
            saw_phone = true;
            // The audit trail the old shape could not produce.
            try testing.expectEqualSlices(u8, &desktop.pub_key, &d.approved_by);
        }
        try testing.expect(saw_phone);

        try testing.expectEqual(Standing.active, (try standingOf(gpa, &recs, 1)).standing);
    }
}

test "devices: A CREDENTIAL THIEF CANNOT SILENTLY JOIN" {
    // The attack the whole design exists to stop. The thief has the password, so
    // they can write whatever they like into the repo — including a perfectly
    // well-formed device record for a device they hold, with a valid DID binding
    // AND a valid claim signature of their own. What they do NOT have is an
    // approved device's anchor private key, so they cannot produce an approval.
    // Peers must ignore them.
    const gpa = testing.allocator;
    const desktop = try makeDevice(gpa, 0x51, 0x33);
    defer gpa.free(desktop.kp);
    const thief = try makeDevice(gpa, 0x9e, 0x77);
    defer gpa.free(thief.kp);
    const d_claim = try signFounding(&desktop);
    const t_claim = try signJoined(&thief, 1);

    // No approval at all.
    {
        const recs = [_]DeviceRecord{
            founding(&desktop, &d_claim, 100),
            joined(&thief, 1, &t_claim, no_key, "", 200),
        };
        const set = try resolveDevices(gpa, test_did, &recs, now_s);
        defer gpa.free(set.devices);
        try testing.expectEqual(@as(usize, 1), set.devices.len);
        try testing.expectEqualSlices(u8, &desktop.pub_key, &set.devices[0].anchor_pub);
        // And it is AWAITING APPROVAL, not orphaned: the remedy is that somebody
        // says yes, and the screen must be able to say so.
        try testing.expectEqual(Standing.awaiting_approval, (try standingOf(gpa, &recs, 1)).standing);
    }

    // An approval the thief signed FOR THEMSELVES — the obvious forgery.
    {
        const self_signed = try anchor.signDeviceApproval(thief.seed, test_did, 1, thief.pub_key);
        const recs = [_]DeviceRecord{
            founding(&desktop, &d_claim, 100),
            joined(&thief, 1, &t_claim, thief.pub_key, &self_signed, 200),
        };
        const set = try resolveDevices(gpa, test_did, &recs, now_s);
        defer gpa.free(set.devices);
        try testing.expectEqual(@as(usize, 1), set.devices.len);
        // The signature is real; the SIGNER is not trusted. That is the reason,
        // and it is now a thing the system can say out loud.
        const st = try standingOf(gpa, &recs, 1);
        try testing.expectEqual(Standing.orphaned, st.standing);
        try testing.expectEqual(Reason.approver_not_trusted, st.reason);
    }

    // An approval LIFTED from an honest one: the desktop approved the phone, and
    // the thief pastes that signature onto their own record. It is a signature
    // over the PHONE's key, so it says nothing about the thief's.
    {
        const phone = try makeDevice(gpa, 0x62, 0x44);
        defer gpa.free(phone.kp);
        const for_phone = try anchor.signDeviceApproval(desktop.seed, test_did, 1, phone.pub_key);
        const recs = [_]DeviceRecord{
            founding(&desktop, &d_claim, 100),
            joined(&thief, 1, &t_claim, desktop.pub_key, &for_phone, 300),
        };
        const set = try resolveDevices(gpa, test_did, &recs, now_s);
        defer gpa.free(set.devices);
        try testing.expectEqual(@as(usize, 1), set.devices.len);
    }

    // A FORGED `approval_by`: the thief names the desktop as their approver,
    // hoping the name is believed. It is not — the name is inside the signed
    // message, so a signature made by anyone else fails against it. This is the
    // test that makes recording the approver SAFE (REDESIGN §4.2), and it is the
    // reason the old "we do NOT say WHO signed" comment no longer applies.
    {
        const self_signed = try anchor.signDeviceApproval(thief.seed, test_did, 1, thief.pub_key);
        const recs = [_]DeviceRecord{
            founding(&desktop, &d_claim, 100),
            joined(&thief, 1, &t_claim, desktop.pub_key, &self_signed, 400),
        };
        const set = try resolveDevices(gpa, test_did, &recs, now_s);
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

    const d_claim = try signFounding(&desktop);
    const p_claim = try signJoined(&phone, 1);
    const l_claim = try signJoined(&laptop, 1);
    const a_phone = try anchor.signDeviceApproval(desktop.seed, test_did, 1, phone.pub_key);
    const a_laptop = try anchor.signDeviceApproval(phone.seed, test_did, 1, laptop.pub_key);

    // Deliberately out of order: the laptop's voucher appears BEFORE the voucher
    // itself is trusted, so a single pass would have dropped it.
    const recs = [_]DeviceRecord{
        joined(&laptop, 1, &l_claim, phone.pub_key, &a_laptop, 300),
        founding(&desktop, &d_claim, 100),
        joined(&phone, 1, &p_claim, desktop.pub_key, &a_phone, 200),
    };
    const set = try resolveDevices(gpa, test_did, &recs, now_s);
    defer gpa.free(set.devices);
    try testing.expectEqual(@as(usize, 3), set.devices.len);
    try testing.expect(set.devices[0].root); // root always first
}

test "devices: STARTING FRESH IS A SIGNED ACT — and the old set is told why it is out" {
    // The lost-device path. A device deliberately starts a new generation, and
    // the old generation's records may well still be sitting in the repo.
    //
    // What is UNCHANGED from the old model: the new root wins, everything the old
    // root vouched for drops out, and `root_pub` changes — the signal a peer needs
    // in order to say "they started chat on a new device" instead of silently
    // carrying on, which is what impersonation looks like.
    //
    // What is NEW, and is the whole point: this happens because a device SIGNED a
    // recovery saying so — never because a read came back empty — and every record
    // that falls out is told, in a value, exactly why and what to do about it.
    const gpa = testing.allocator;
    const old_root = try makeDevice(gpa, 0x51, 0x33);
    defer gpa.free(old_root.kp);
    const old_phone = try makeDevice(gpa, 0x62, 0x44);
    defer gpa.free(old_phone.kp);
    const new_root = try makeDevice(gpa, 0x84, 0x66);
    defer gpa.free(new_root.kp);

    const o_claim = try signFounding(&old_root);
    const p_claim = try signJoined(&old_phone, 1);
    const approval = try anchor.signDeviceApproval(old_root.seed, test_did, 1, old_phone.pub_key);
    const r_claim = try anchor.signDeviceClaim(new_root.seed, test_did, 2, .recovery, old_root.pub_key);

    const recs = [_]DeviceRecord{
        founding(&old_root, &o_claim, 100),
        joined(&old_phone, 1, &p_claim, old_root.pub_key, &approval, 150),
        recovery(&new_root, 2, old_root.pub_key, &r_claim, 900),
    };
    const set = try resolveDevices(gpa, test_did, &recs, now_s);
    defer gpa.free(set.devices);

    try testing.expectEqualSlices(u8, &new_root.pub_key, &set.root_pub);
    try testing.expectEqual(@as(usize, 1), set.devices.len); // the old set is gone
    try testing.expectEqual(@as(Generation, 2), set.generation);

    var c = try classifyDevices(gpa, test_did, &recs, now_s);
    defer freeClassification(gpa, &c);
    const s = c.standings;
    try testing.expectEqual(Standing.orphaned, s[0].standing);
    try testing.expectEqual(Reason.superseded_generation, s[0].reason);
    try testing.expectEqual(Standing.orphaned, s[1].standing);
    try testing.expectEqual(Reason.superseded_generation, s[1].reason);
    try testing.expectEqual(Standing.active, s[2].standing);
}

test "devices: THE TRAP — a superseded root cannot be approved back in, and says re-join" {
    // THE 2026-08-26 BUG, as a test.
    //
    // Under the old model a device holding a stale `root: true` record was skipped
    // by the vouching loop outright ("roots other than the winner are stale"), so
    // approving it from another device could not work — the approval landed in a
    // record the resolver refused to look at — and NOTHING anywhere could say so.
    // The device sat in a loop, and the person was shown a screen that offered a
    // choice it could not deliver.
    //
    // Now: the record is `orphaned` for a stated reason, and the remedy that
    // reason implies (re-join at the current generation) is the one that works.
    const gpa = testing.allocator;
    const old_root = try makeDevice(gpa, 0x51, 0x33);
    defer gpa.free(old_root.kp);
    const new_root = try makeDevice(gpa, 0x84, 0x66);
    defer gpa.free(new_root.kp);

    const o_claim = try signFounding(&old_root);
    const r_claim = try anchor.signDeviceClaim(new_root.seed, test_did, 2, .recovery, old_root.pub_key);

    // The new root approves the old one — in the CURRENT generation, correctly
    // signed. It still does not come back, because its own record claims to root
    // generation 1: an approval cannot change what a record says it is.
    const approval = try anchor.signDeviceApproval(new_root.seed, test_did, 2, old_root.pub_key);
    var stale = founding(&old_root, &o_claim, 100);
    stale.approval_by = new_root.pub_key;
    stale.approval_sig = &approval;

    const recs = [_]DeviceRecord{ stale, recovery(&new_root, 2, old_root.pub_key, &r_claim, 900) };
    var c = try classifyDevices(gpa, test_did, &recs, now_s);
    defer freeClassification(gpa, &c);
    const s = c.standings;
    try testing.expectEqual(Standing.orphaned, s[0].standing);
    try testing.expectEqual(Reason.superseded_generation, s[0].reason);

    // And the way OUT is the one the standing points at: republish as a joined
    // device of the current generation. Then the same approval works.
    const rejoin_claim = try signJoined(&old_root, 2);
    const rejoined = [_]DeviceRecord{
        joined(&old_root, 2, &rejoin_claim, new_root.pub_key, &approval, 950),
        recovery(&new_root, 2, old_root.pub_key, &r_claim, 900),
    };
    const set = try resolveDevices(gpa, test_did, &rejoined, now_s);
    defer gpa.free(set.devices);
    try testing.expectEqual(@as(usize, 2), set.devices.len);
}

test "devices: an approval does not survive the generation it was made in" {
    // The orphaning property, enforced by the signature rather than by the order
    // the resolver happens to walk the chain in. A phone approved in generation 1
    // cannot ride that approval into generation 2 by editing its own record.
    const gpa = testing.allocator;
    const root1 = try makeDevice(gpa, 0x51, 0x33);
    defer gpa.free(root1.kp);
    const phone = try makeDevice(gpa, 0x62, 0x44);
    defer gpa.free(phone.kp);
    const root2 = try makeDevice(gpa, 0x84, 0x66);
    defer gpa.free(root2.kp);

    const c1 = try signFounding(&root1);
    const c2 = try anchor.signDeviceClaim(root2.seed, test_did, 2, .recovery, root1.pub_key);
    const old_approval = try anchor.signDeviceApproval(root1.seed, test_did, 1, phone.pub_key);
    const p_claim2 = try signJoined(&phone, 2);

    const recs = [_]DeviceRecord{
        founding(&root1, &c1, 100),
        recovery(&root2, 2, root1.pub_key, &c2, 900),
        // The phone re-signs its own claim for generation 2 (it can — it is its
        // own key) but presents the OLD generation's approval.
        joined(&phone, 2, &p_claim2, root1.pub_key, &old_approval, 950),
    };
    const set = try resolveDevices(gpa, test_did, &recs, now_s);
    defer gpa.free(set.devices);
    try testing.expectEqual(@as(usize, 1), set.devices.len);

    var c = try classifyDevices(gpa, test_did, &recs, now_s);
    defer freeClassification(gpa, &c);
    const s = c.standings;
    try testing.expectEqual(Standing.orphaned, s[2].standing);
    try testing.expectEqual(Reason.approver_not_trusted, s[2].reason);
}

test "devices: A RECORD CANNOT BE PROMOTED INTO A GENERATION IT DID NOT CLAIM" {
    // Whoever holds the account's password can rewrite any record in the repo.
    // The generation decides who owns the identity, so if it were unsigned they
    // could take an honest device's own record — every cryptographic piece of it
    // genuine — republish it verbatim at a higher generation, and evict everyone.
    // (That hole is open today behind the unsigned `createdAt` tie-break.)
    const gpa = testing.allocator;
    const desktop = try makeDevice(gpa, 0x51, 0x33);
    defer gpa.free(desktop.kp);
    const d_claim = try signFounding(&desktop);

    // The honest record, promoted to generation 7 by an attacker with repo write.
    var promoted = founding(&desktop, &d_claim, 100);
    promoted.generation = 7;

    const recs = [_]DeviceRecord{promoted};
    var c = try classifyDevices(gpa, test_did, &recs, now_s);
    defer freeClassification(gpa, &c);
    const s = c.standings;
    try testing.expectEqual(Standing.invalid, s[0].standing);
    try testing.expectEqual(Reason.claim_not_signed, s[0].reason);

    // With no provable root, the account simply has no chat identity — it does
    // NOT fall into the attacker's hands.
    const set = try resolveDevices(gpa, test_did, &recs, now_s);
    defer gpa.free(set.devices);
    try testing.expectEqual(@as(usize, 0), set.devices.len);
}

test "devices: two roots in one generation resolve the same way for every peer" {
    // A race, or a thief's fresh start. Peers MUST agree, so the winner is decided
    // by key order and never by a clock — and the loser is told it conflicted
    // rather than silently skipped.
    const gpa = testing.allocator;
    const a = try makeDevice(gpa, 0x51, 0x33);
    defer gpa.free(a.kp);
    const b = try makeDevice(gpa, 0x62, 0x44);
    defer gpa.free(b.kp);
    const ca = try signFounding(&a);
    const cb = try signFounding(&b);

    const forward = [_]DeviceRecord{ founding(&a, &ca, 100), founding(&b, &cb, 200) };
    const backward = [_]DeviceRecord{ founding(&b, &cb, 200), founding(&a, &ca, 100) };

    const set1 = try resolveDevices(gpa, test_did, &forward, now_s);
    defer gpa.free(set1.devices);
    const set2 = try resolveDevices(gpa, test_did, &backward, now_s);
    defer gpa.free(set2.devices);

    // Same winner regardless of the order the records arrived in, and regardless
    // of which was written first.
    try testing.expectEqualSlices(u8, &set1.root_pub, &set2.root_pub);
    const lower = if (std.mem.order(u8, &a.pub_key, &b.pub_key) == .lt) a.pub_key else b.pub_key;
    try testing.expectEqualSlices(u8, &lower, &set1.root_pub);

    var c = try classifyDevices(gpa, test_did, &forward, now_s);
    defer freeClassification(gpa, &c);
    const s = c.standings;
    const loser: usize = if (std.mem.eql(u8, &set1.root_pub, &a.pub_key)) 1 else 0;
    try testing.expectEqual(Standing.orphaned, s[loser].standing);
    try testing.expectEqual(Reason.conflicting_root, s[loser].reason);
}

test "devices: an account with no valid root is simply not on chat (E4)" {
    const gpa = testing.allocator;
    const orphan = try makeDevice(gpa, 0x62, 0x44);
    defer gpa.free(orphan.kp);
    const o_claim = try signJoined(&orphan, 1);

    // A device record with no root anywhere: not an error, just nobody to talk to
    // — and the record is told which of the four situations it is in.
    const recs = [_]DeviceRecord{joined(&orphan, 1, &o_claim, no_key, "", 200)};
    const set = try resolveDevices(gpa, test_did, &recs, now_s);
    defer gpa.free(set.devices);
    try testing.expectEqual(@as(usize, 0), set.devices.len);
    try testing.expectEqualSlices(u8, &([_]u8{0} ** anchor.pk_len), &set.root_pub);

    const st = try standingOf(gpa, &recs, 0);
    try testing.expectEqual(Standing.orphaned, st.standing);
    try testing.expectEqual(Reason.no_current_root, st.reason);

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
    const d_claim = try signFounding(&desktop);
    const p_claim = try signJoined(&phone, 1);
    const approval = try anchor.signDeviceApproval(desktop.seed, test_did, 1, phone.pub_key);

    // One corrupt record must not take the account's whole chat identity offline.
    var junk = joined(&phone, 1, &p_claim, desktop.pub_key, &approval, 200);
    junk.key_package = "not a key package at all";
    const recs = [_]DeviceRecord{
        founding(&desktop, &d_claim, 100),
        junk,
        joined(&phone, 1, &p_claim, desktop.pub_key, &approval, 200),
    };
    const set = try resolveDevices(gpa, test_did, &recs, now_s);
    defer gpa.free(set.devices);
    try testing.expectEqual(@as(usize, 2), set.devices.len);

    // Dropped, but NOT vanished: it has a standing and a reason.
    const st = try standingOf(gpa, &recs, 1);
    try testing.expectEqual(Standing.invalid, st.standing);
    try testing.expectEqual(Reason.failed_validation, st.reason);

    // The cap holds: nobody can make a peer fan a group out to a thousand leaves.
    try testing.expect(set.devices.len <= max_devices);
}

test "devices: an unrecognized claim is named, not silently ignored" {
    // Forward compatibility with a reason attached: a future claim kind this
    // build does not know must not read as "no claim at all".
    const gpa = testing.allocator;
    const desktop = try makeDevice(gpa, 0x51, 0x33);
    defer gpa.free(desktop.kp);
    const d_claim = try signFounding(&desktop);

    var odd = founding(&desktop, &d_claim, 100);
    odd.claim_raw = 200;

    const recs = [_]DeviceRecord{odd};
    const st = try standingOf(gpa, &recs, 0);
    try testing.expectEqual(Standing.invalid, st.standing);
    try testing.expectEqual(Reason.unrecognized_claim, st.reason);
}
