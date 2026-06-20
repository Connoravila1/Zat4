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

//! B1 classification: SHELL (impure). The **membership store** — the one place
//! the password verifier is computed and checked (Argon2id is memory-hard work
//! over an `Io` capability), and the only holder of membership state. Keyed by
//! DID (A5/D4: the DID string is the sole identifier crossing in or out; the
//! verifier and the records never leave).
//!
//! Interface, in full: `Error`, `BreachChecker`, `Store`, `init`, `deinit`,
//! `enroll`, `activate`, `verifyLogin`, `changePassword`, `stateOf`,
//! `localBreachCheck`.
//!
//! ── Reconciliation with the design (recorded per H3) ──
//! Password STORAGE uses Argon2 `strHash`/`strVerify` — random salt, PHC
//! bundling, stored-hash compare — the very wrappers the PoW module deliberately
//! REJECTS, because PoW needs deterministic `kdf` recompute, not stored-hash
//! comparison (IDENTITY_ENROLLMENT §6: same primitive, two jobs, two APIs). Both
//! calls take an allocator (via options) and an `Io`, verified against 0.16.0.
//! A wrong password is an ordinary "no", not an error (E4): `strVerify`'s
//! `PasswordVerificationFailed` maps to `false`.
//!
//! The breach floor (§12.2) is split correctly across the B-line: the lookup is
//! I/O behind the `BreachChecker` seam (production: a Have-I-Been-Pwned
//! k-anonymity query — only a hash prefix leaves the device); the keep/reject
//! decision is the pure `membership.passwordChangeAllowed`. The local checker
//! here is a minimal embedded set so the slice runs offline; swapping in the
//! network version touches nothing but the function passed in (D1/F1).

const std = @import("std");
const membership = @import("../core/membership.zig");
const cred = @import("../core/credential.zig");
const argon2 = std.crypto.pwhash.argon2;

/// What the store can surface (E3). A wrong password is NOT here — it is a `false`
/// return (E4). `DuplicateMember` / `UnknownMember` are the store's own conditions.
pub const Error = error{
    OutOfMemory,
    Backend, // unexpected hashing-backend failure
    DuplicateMember, // this DID is already enrolled
    UnknownMember, // no membership for this DID
};

/// The breach-corpus check seam. The slice ships `localBreachCheck`; production
/// swaps a network k-anonymity checker behind this same type (the password never
/// leaves the device — only a hash prefix is queried).
pub const BreachChecker = *const fn (password: []const u8) bool;

/// Argon2id storage-hardening parameters. Independent of the PoW tax — these make
/// an OFFLINE crack of a leaked verifier slow. `[TUNE]` to the deployment's
/// per-login verify budget (G1: measure the real cost before settling).
const hash_params: argon2.Params = .{ .t = 3, .m = 65536, .p = 1 };

/// The in-memory membership store. Struct-of-arrays: a DID key column parallel to
/// the records (A3). Lookup is a linear scan — correct and simple for the first
/// slice; a DID→index map is the optimisation once volume warrants it (F4/F5).
pub const Store = struct {
    // A1/A7 do not apply — this is a stateful container/service, not a plain-data
    // record. The plain-data record it holds (membership.Membership) carries the
    // size discipline; this owns memory and has a lifecycle instead.
    gpa: std.mem.Allocator,
    dids: std.ArrayList([]u8), // owned DID copies (the key column)
    members: std.ArrayList(membership.Membership), // parallel records
};

/// SHELL: stand up an empty store. Allocations are explicit and owned here (C1/C4).
pub fn init(gpa: std.mem.Allocator) Store {
    return .{ .gpa = gpa, .dids = .empty, .members = .empty };
}

/// SHELL: release every owned DID copy and the backing arrays (C4/C5).
pub fn deinit(store: *Store) void {
    for (store.dids.items) |d| store.gpa.free(d);
    store.dids.deinit(store.gpa);
    store.members.deinit(store.gpa);
}

fn indexOf(store: *Store, did: []const u8) ?usize {
    for (store.dids.items, 0..) |d, i| {
        if (std.mem.eql(u8, d, did)) return i;
    }
    return null;
}

fn hashInto(store: *Store, io: std.Io, password: []const u8, out: *[membership.phc_cap]u8) Error!u8 {
    const phc = argon2.strHash(
        password,
        .{ .allocator = store.gpa, .params = hash_params, .mode = .argon2id, .encoding = .phc },
        out,
        io,
    ) catch |e| switch (e) {
        error.OutOfMemory => return Error.OutOfMemory,
        else => return Error.Backend,
    };
    return @intCast(phc.len);
}

/// SHELL: enroll a DID with its assigned password, at the chosen tier. Lands in
/// `pending_confirm` — the segmented confirmation (`activate`) makes it `active`.
/// The plaintext `password` is the caller's to wipe afterwards (credential `wipe`);
/// only the verifier is retained.
pub fn enroll(
    store: *Store,
    io: std.Io,
    did: []const u8,
    tier: cred.Tier,
    password: []const u8,
    now: i64,
) Error!void {
    if (indexOf(store, did) != null) return Error.DuplicateMember;

    var rec: membership.Membership = .{
        .verifier = undefined,
        .verifier_len = 0,
        .tier = tier,
        .state = .pending_confirm,
        .created_at = now,
    };
    rec.verifier_len = try hashInto(store, io, password, &rec.verifier);

    // Keep the two columns in lockstep: copy the DID, append both, and unwind the
    // first append if the second fails (no orphaned key, no leak).
    const did_copy = try store.gpa.dupe(u8, did);
    errdefer store.gpa.free(did_copy);
    try store.dids.append(store.gpa, did_copy);
    errdefer _ = store.dids.pop();
    try store.members.append(store.gpa, rec);
}

/// SHELL: flip a confirmed membership to active (after segmented confirmation).
pub fn activate(store: *Store, did: []const u8) Error!void {
    const i = indexOf(store, did) orelse return Error.UnknownMember;
    store.members.items[i].state = .active;
}

/// SHELL: does `password` match this DID's verifier? Returns `false` for a wrong
/// password (E4), an error only for genuinely exceptional conditions. Membership
/// STATE is a separate question — the caller pairs this with `stateOf`/`isActive`,
/// since proving the password and being an active member are distinct facts.
pub fn verifyLogin(store: *Store, io: std.Io, did: []const u8, password: []const u8) Error!bool {
    const i = indexOf(store, did) orelse return Error.UnknownMember;
    const rec = store.members.items[i];
    argon2.strVerify(
        rec.verifier[0..rec.verifier_len],
        password,
        .{ .allocator = store.gpa },
        io,
    ) catch |e| switch (e) {
        error.PasswordVerificationFailed => return false,
        error.OutOfMemory => return Error.OutOfMemory,
        else => return Error.Backend,
    };
    return true;
}

/// SHELL: change a member's password, subject to the §12.2 breach floor. Returns
/// `false` if the new password is rejected by the floor (the pure
/// `passwordChangeAllowed` decision over the `breach` lookup); `true` once stored.
pub fn changePassword(
    store: *Store,
    io: std.Io,
    did: []const u8,
    new_password: []const u8,
    breach: BreachChecker,
) Error!bool {
    const i = indexOf(store, did) orelse return Error.UnknownMember;
    if (!membership.passwordChangeAllowed(breach(new_password))) return false;

    var buf: [membership.phc_cap]u8 = undefined;
    const len = try hashInto(store, io, new_password, &buf);
    store.members.items[i].verifier = buf;
    store.members.items[i].verifier_len = len;
    return true;
}

/// SHELL: the membership state for a DID, or null if unknown.
pub fn stateOf(store: *Store, did: []const u8) ?membership.MembershipState {
    const i = indexOf(store, did) orelse return null;
    return store.members.items[i].state;
}

/// A minimal offline stand-in for the production breach corpus — enough common
/// leaked passwords to exercise the floor in tests. Production replaces this with
/// a k-anonymity query behind `BreachChecker` (F1: no network dependency pulled
/// into the build for a first slice).
pub fn localBreachCheck(password: []const u8) bool {
    const common = [_][]const u8{
        "password",  "123456",   "123456789", "qwerty",  "111111",
        "abc123",    "password1", "letmein",  "iloveyou", "admin",
        "welcome",   "monkey",   "dragon",    "000000",  "qwerty123",
    };
    for (common) |c| {
        if (std.ascii.eqlIgnoreCase(password, c)) return true;
    }
    return false;
}

// ── tests: real Argon2id via std.testing.io, leak-checked (C6) ──

test "enroll then login: right and wrong password" {
    var store = init(std.testing.allocator);
    defer deinit(&store);

    const did = "did:plc:alice000000000000000000";
    const pw = "Region-Chaps-Spinach-Garnet-Could-Maker";
    try enroll(&store, std.testing.io, did, .secure, pw, 1_700_000_000);

    try std.testing.expect(try verifyLogin(&store, std.testing.io, did, pw));
    try std.testing.expect(!try verifyLogin(&store, std.testing.io, did, "Region-Chaps-Spinach-Garnet-Could-Baker"));
    try std.testing.expectEqual(membership.MembershipState.pending_confirm, stateOf(&store, did).?);
}

test "activation gates membership" {
    var store = init(std.testing.allocator);
    defer deinit(&store);
    const did = "did:plc:bob0000000000000000000000";
    try enroll(&store, std.testing.io, did, .super_secure, "Astride-Stout-Obvious-Legend-Scorn-Unsworn-Ounce", 0);
    try std.testing.expect(!membership.isActive(.{ .verifier = undefined, .verifier_len = 0, .tier = .secure, .state = stateOf(&store, did).?, .created_at = 0 }));
    try activate(&store, did);
    try std.testing.expectEqual(membership.MembershipState.active, stateOf(&store, did).?);
}

test "duplicate enrollment is refused" {
    var store = init(std.testing.allocator);
    defer deinit(&store);
    const did = "did:plc:carol00000000000000000000";
    try enroll(&store, std.testing.io, did, .secure, "Jolt-Rimmed-Mammary-Jugular-Nanny-Reload", 0);
    try std.testing.expectError(Error.DuplicateMember, enroll(&store, std.testing.io, did, .secure, "Other-Words-Here-That-Are-Different", 0));
}

test "changePassword honors the breach floor" {
    var store = init(std.testing.allocator);
    defer deinit(&store);
    const did = "did:plc:dave00000000000000000000";
    try enroll(&store, std.testing.io, did, .secure, "Payroll-Ought-Hubcap-Delete-Angular-Molar", 0);

    // A known-breached password is rejected; the old one still works.
    try std.testing.expect(!try changePassword(&store, std.testing.io, did, "password1", localBreachCheck));
    try std.testing.expect(try verifyLogin(&store, std.testing.io, did, "Payroll-Ought-Hubcap-Delete-Angular-Molar"));

    // A strong unique password is accepted and becomes the new login.
    const fresh = "Powwow-Chaos-Widen-Lumpish-Junkie-Cause";
    try std.testing.expect(try changePassword(&store, std.testing.io, did, fresh, localBreachCheck));
    try std.testing.expect(try verifyLogin(&store, std.testing.io, did, fresh));
    try std.testing.expect(!try verifyLogin(&store, std.testing.io, did, "Payroll-Ought-Hubcap-Delete-Angular-Molar"));
}

test "unknown member surfaces as an error" {
    var store = init(std.testing.allocator);
    defer deinit(&store);
    try std.testing.expectError(Error.UnknownMember, verifyLogin(&store, std.testing.io, "did:plc:ghost0000000000000000000", "anything-at-all-here-friend"));
    try std.testing.expect(stateOf(&store, "did:plc:ghost0000000000000000000") == null);
}
