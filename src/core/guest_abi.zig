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

//! B1 classification: CORE (pure data + pure helpers). **GUEST TIER — Phase 1:
//! the capability contract.** See `GUEST_TIER_ROADMAP.md`.
//!
//! This module is the SECURITY BOUNDARY of the developer tier, written as pinned
//! types BEFORE any runtime exists. A guest algorithm (Phase 2's extended VM,
//! authored in Phase 3's "Zal" language) can COMPUTE anything — it is a
//! Turing-complete, fuel-metered machine — but its ONLY window outward is the
//! fixed `Capability` set below. There is deliberately NO capability for the
//! network, the filesystem, the clock/RNG (except host-seeded), another user's
//! private data, or any per-identity input. So a guest cannot exfiltrate the
//! user's behavior, cannot target a specific account, and cannot call out — not
//! because it is forbidden, but because the primitive is not in this table.
//! **Privacy and no-targeting are THEOREMS of this file's contents.**
//!
//! Nothing here runs guest code; it defines the contract the VM (Phase 2), the
//! marshaling (Phase 4), and the transparency labels (Phase 6) all build against.
//! The comptime guards make the invariants structural: adding a capability, a
//! candidate field, or a behavioral door FAILS THE BUILD until its classification
//! is handled — the same "compiler enforces honesty" discipline as the config
//! tiers' `metaFor` completeness wall and `algo_vm.Fact`'s count guard.

const std = @import("std");
const assert = std.debug.assert;
const discover = @import("discover.zig");

/// The entry points the host calls on a guest program — the fixed interface a
/// guest implements. The host calls `score` per candidate to rank the pool,
/// `retrieve` once per refresh to compose the candidate query (by calling the
/// retrieval capabilities), and `learn` per on-device attention event to adapt
/// (adaptive-mode algorithms only). A guest need not implement all three; an
/// absent entry point means "engine default for that stage."
///
/// Calling convention (the actual stack/register marshaling is Phase 4):
///   retrieve() -> void         // side effect: calls `source_*` to build the query
///   score(CandidateView) -> f64
///   learn(AttentionEvent) -> void  // side effect: writes `state_*`
pub const EntryPoint = enum(u8) {
    retrieve,
    score,
    learn,

    comptime {
        assert(@typeInfo(EntryPoint).@"enum".fields.len == 3);
    }
};

/// The capability functions a guest may call — the ONLY reach outward, invoked
/// through the VM's `call_host` opcode with one of these ids. A guest is GRANTED a
/// subset at load time; a call to an ungranted capability is a validation failure
/// (never a silent no-op — the publish gate rejects it, Phase 5). The set is
/// deliberately tiny and auditable, and it is CATEGORIZED (`isBehavioral`) so the
/// transparency label is DERIVED from the granted set (invariant 6), never from
/// reading the guest's code.
///
/// Adding a capability is a deliberate security act: the exhaustive switches below
/// force its behavioral classification, and the count guard forces a human to look
/// at whether the new primitive opens a targeting, exfiltration, or side-channel
/// door. Do NOT add one to "make something work" without that review.
pub const Capability = enum(u8) {
    // --- Retrieval: compose the candidate query. The host runs each source over
    //     its own indexes (public data); the guest only names + weights them, so
    //     no raw traversal or network reach is expressible. (These MIRROR the
    //     `retrieval.SourceKind` operators — the guest tier calls what the config
    //     tier declares, one vocabulary.) ---
    source_follows, // add "accounts you follow" to the pool
    source_discovery, // add "beyond your follows (discovery)" to the pool
    source_trending, // add "trending (engagement ≥ threshold)" to the pool

    // --- State: the guest's OWN bounded on-device memory (its learned model),
    //     read at a run's start, written at its end. Bounded by the algorithm's
    //     declared state budget; never leaves the device (no capability could send
    //     it). This is what lets a guest implement any on-device learning method. ---
    state_read, // read a word from the persistent state blob at an index
    state_write, // write a word to the persistent state blob at an index

    // --- Behavioral (GATED): the user's on-device ATTENTION signal. Granted ONLY
    //     to an adaptive-mode algorithm, and shown on the label. It ENTERS the
    //     guest (so real per-person adaptation is possible — the fuller fork we
    //     chose) but has no exit: there is no capability that could move it off the
    //     device. Reading it is safe precisely because leaving with it is not
    //     expressible (the reader-path break, GUEST_TIER_ROADMAP §7). ---
    attention_dwell, // the viewer's normalized dwell on a candidate, in [0,1]
    attention_clicked, // whether the viewer clicked into a candidate

    comptime {
        // The whole capability surface, in one number (3 retrieval + 2 state + 2
        // behavioral). Bumping it is the deliberate review point for every new door
        // (targeting / exfiltration / side channel).
        assert(@typeInfo(Capability).@"enum".fields.len == 7);
    }
};

/// Does this capability read the user's PRIVATE attention (behavioral) data? The
/// transparency label ("uses your attention data") is derived from whether a guest
/// was granted ANY behavioral capability — the same door-wall discipline the config
/// `classify` uses. Exhaustive (no `else`), so adding a capability cannot compile
/// until its behavioral status is decided here on purpose.
pub fn isBehavioral(cap: Capability) bool {
    return switch (cap) {
        .source_follows, .source_discovery, .source_trending, .state_read, .state_write => false,
        .attention_dwell, .attention_clicked => true,
    };
}

/// The PUBLIC features of one candidate, handed to the guest's `score` entry point.
/// PUBLIC-ONLY BY CONSTRUCTION: there is NO per-identity field here (no author DID,
/// no handle, no "is this me") — so a guest cannot single out or target a specific
/// account. That absence is the no-targeting invariant, enforced structurally by
/// the size guard: adding an identity field changes the size and fails the build,
/// forcing a deliberate security decision (mirrors `algo_vm.Fact`'s count guard).
/// HOT — one per candidate, marshaled across the VM boundary every refresh → A7.
pub const CandidateView = struct {
    like_count: u32,
    repost_count: u32,
    reply_count: u32,
    tag_count: u32 = 0, // how many topic tags (zones) this post carries
    age_hrs: f32, // hours since the post was created (host computes; the clock never enters the guest)
    author_rep: f32, // public author-reputation prior, in [0,1]
    in_network: bool, // from an account the viewer follows
    viewer_engaged: bool = false, // the viewer already liked or reposted this post

    comptime {
        // Budget 28: 4×u32 (16) + 2×f32 (8) + 2×bool (2) = 26, padded to 28 at the
        // 4-byte alignment. Exact. The field SET is the no-targeting boundary — any
        // change is a deliberate widening of what a guest can see. These additions
        // are PUBLIC content signals (tag count, your own public engagement), no
        // per-identity input, so they open no targeting channel.
        assert(@sizeOf(CandidateView) == 28);
    }
};

/// One on-device attention event handed to the guest's `learn` entry point (only
/// when the guest is granted the behavioral capabilities). This is the user's
/// PRIVATE behavior: it enters the guest so the guest can adapt, and it is walled
/// on-device by the ABSENCE of any capability that could carry it out (there is no
/// network/emit-off-device primitive). HOT-ish (one per captured event) → A7.
pub const AttentionEvent = struct {
    candidate: CandidateView, // which post the attention was on
    dwell: f32, // normalized dwell on it, in [0,1]
    clicked: bool, // did the viewer click into it

    comptime {
        // Budget 36: CandidateView (28) + f32 (4) + bool (1) = 33, padded to 36.
        assert(@sizeOf(AttentionEvent) == 36);
    }
};

/// The hard ceiling on a guest's persistent on-device state — reused from the
/// config tier's declared-state cap, so the guest tier and the config tier bound
/// per-user accumulation by the SAME wall (a side-channel + disk limit). A guest
/// declares a budget ≤ this; the host allocates exactly that and no more.
pub const max_state_bytes: u32 = discover.state_budget_hard_cap;

/// The provable privacy verdict for a guest, DERIVED from the capabilities it was
/// granted — NOT from reading its (unauditable) code. This is how invariant 6
/// survives arbitrary code: "uses no behavioral data" is provable as "was granted
/// no behavioral capability." Plain data (A1); the transparency page renders it.
pub const GuestClassification = struct {
    // A7.2: cold struct — one per classify call, never held in quantity. Waived.
    uses_behavioral: bool, // was granted any behavioral capability
    can_learn: bool, // was granted state_write (keeps an on-device model)
};

/// Derive the label from a granted capability set (PURE). The single source of the
/// guest tier's privacy claim — same posture as `transparency.classify` for configs.
pub fn classifyGrant(granted: []const Capability) GuestClassification {
    var c: GuestClassification = .{ .uses_behavioral = false, .can_learn = false };
    for (granted) |cap| {
        if (isBehavioral(cap)) c.uses_behavioral = true;
        if (cap == .state_write) c.can_learn = true;
    }
    return c;
}

// ---------------------------------------------------------------------------
// Tests — pure (B2), no allocation, no I/O. The contract's invariants, pinned.
// ---------------------------------------------------------------------------

const t = std.testing;

test "guards: the ABI types are exactly sized (the no-targeting / feature boundary)" {
    try t.expectEqual(@as(usize, 28), @sizeOf(CandidateView));
    try t.expectEqual(@as(usize, 36), @sizeOf(AttentionEvent));
    try t.expectEqual(@as(usize, 7), @typeInfo(Capability).@"enum".fields.len);
    try t.expectEqual(@as(usize, 3), @typeInfo(EntryPoint).@"enum".fields.len);
}

test "the behavioral door: exactly the attention capabilities read private data" {
    // Retrieval + state are public/own-memory; only attention_* is behavioral.
    try t.expect(!isBehavioral(.source_follows));
    try t.expect(!isBehavioral(.source_discovery));
    try t.expect(!isBehavioral(.source_trending));
    try t.expect(!isBehavioral(.state_read));
    try t.expect(!isBehavioral(.state_write));
    try t.expect(isBehavioral(.attention_dwell));
    try t.expect(isBehavioral(.attention_clicked));
}

test "classifyGrant: the privacy label is PROVEN from the granted capabilities (invariant 6)" {
    // A candidate-side guest (retrieval only) provably uses no behavioral data.
    const candidate_side = [_]Capability{ .source_follows, .source_trending };
    const cs = classifyGrant(&candidate_side);
    try t.expect(!cs.uses_behavioral);
    try t.expect(!cs.can_learn);

    // An adaptive guest granted attention + state provably learns from attention.
    const adaptive = [_]Capability{ .source_follows, .attention_dwell, .state_read, .state_write };
    const ac = classifyGrant(&adaptive);
    try t.expect(ac.uses_behavioral);
    try t.expect(ac.can_learn);

    // State without attention = keeps a model, but NOT from behavioral data.
    const stateful_only = [_]Capability{ .state_read, .state_write };
    const so = classifyGrant(&stateful_only);
    try t.expect(!so.uses_behavioral);
    try t.expect(so.can_learn);
}
