//! B1 classification: CORE (pure). The **membership** record, its state model,
//! and the pure policy decisions over results computed in the shell. This is the
//! MEMBERSHIP layer of IDENTITY_ENROLLMENT_DESIGN.md §1 — the Zat4-owned account
//! keyed to a DID. No I/O here: the Argon2 verifier is produced and checked in
//! shell/membership.zig (hashing is memory-hard work over an `Io`); password
//! breach lookups are the shell's (network). The core only holds plain data and
//! decides policy over the booleans the shell hands back.
//!
//! Interface, in full: `phc_cap`, `MembershipState`, `Membership`, `isActive`,
//! `passwordChangeAllowed`.

const std = @import("std");
const cred = @import("credential.zig");

/// Max length of the Argon2id PHC verifier we store. Measured ~120 bytes at the
/// storage params (m=65536, t=3, p=1; 32-byte salt + 32-byte hash, base64);
/// 160 leaves margin for larger parameter digits, and fits a `u8` length.
pub const phc_cap: usize = 160;

/// The enrollment lifecycle (IDENTITY_ENROLLMENT §3). A membership is not usable
/// until it reaches `active`.
pub const MembershipState = enum(u8) {
    pending_payment, // deposit / PoW not yet cleared
    pending_confirm, // password assigned, segmented confirmation outstanding
    active, // full member
    suspended, // revoked or paused
};

/// One member's Zat4 account. The DID is NOT a field — it is the store's KEY
/// (A5/D4: only the DID crosses the module boundary; the verifier and internals
/// never leave). The verifier is the Argon2id PHC string, a one-way hash — safe
/// to store, not a plaintext secret to wipe (the plaintext lives only in the
/// credential module's `Credential`, which is wiped after this verifier is made).
pub const Membership = struct {
    // A7.2 — COLD record: one per member, looked up by DID, never iterated on a
    // hot path, so an exact size guard would only pin a large churning number.
    // The ~160-byte verifier dominates; if the store is ever shown to be
    // hot-iterated, the verifier moves to a side array and this slims down (F5).
    verifier: [phc_cap]u8, // Argon2id PHC string (a hash, not a wipe-secret)
    verifier_len: u8,
    tier: cred.Tier, // the strength the member chose at enrollment
    state: MembershipState,
    created_at: i64, // unix seconds, supplied by the shell clock (B3)
};

// ── pure helpers (A1: behaviour in free functions, records stay plain) ──

/// PURE (B2): may this member act? Only an active membership may log in or post.
pub fn isActive(m: Membership) bool {
    return m.state == .active;
}

/// PURE (B2): the §12.2 change-password decision, taken over a breach-check
/// RESULT. The lookup itself is I/O (shell, B3); the keep/reject rule is pure and
/// lives here. A new password is allowed iff it is NOT found in the breach corpus.
/// Any future length/shape floors compose into this one decision.
pub fn passwordChangeAllowed(found_in_breach_corpus: bool) bool {
    return !found_in_breach_corpus;
}

// ── tests: pure, no Io ──

test "state gates activity" {
    const base = Membership{ .verifier = undefined, .verifier_len = 0, .tier = .secure, .state = .active, .created_at = 0 };
    try std.testing.expect(isActive(base));
    var pending = base;
    pending.state = .pending_confirm;
    try std.testing.expect(!isActive(pending));
}

test "breach floor decides password change" {
    try std.testing.expect(passwordChangeAllowed(false)); // not breached → allowed
    try std.testing.expect(!passwordChangeAllowed(true)); // breached → rejected
}
