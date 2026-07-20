// SPDX-License-Identifier: MIT
//
// The Constellation Gate — same-operator detection for Sybil-resistant
// enrollment.
// Copyright (c) 2026  Connor Avila
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
// FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
// DEALINGS IN THE SOFTWARE.
//
// ── LICENSE NOTE (deliberate divergence from the surrounding tree) ──
// The rest of Zat4 is AGPL-3.0-or-later. This module is MIT on purpose:
// CONSTELLATION_GATE_DESIGN.md §"Intended scope" commits it as a standalone,
// adoptable component. It is developed here but is designed to be LIFTED into
// its own repository verbatim, so it imports NOTHING from Zat4 — no DID, no
// handle, no atproto type, no sibling module, only `std`. Adding a Zat4
// import to this file breaks that contract; put the translation in the shell
// adapter instead.

//! B1 classification: CORE (pure). Phase **G1** of the Constellation Gate —
//! *signal derivation*. Specced in CONSTELLATION_GATE_DESIGN.md §1, §2, §5.
//!
//! The Gate answers one question: "is this new account controlled by the same
//! operator as existing accounts?" — and prices the refundable enrollment
//! deposit accordingly. It never asks whether anyone is human. It observes
//! six weak coordination signals, each a property of the *relationship*
//! between accounts, and derives a non-reversible token from each.
//!
//! This file is the derive half. It turns one enrollment's `Observation`
//! into `Derived` tokens. It does not score, cluster, or price — those are
//! G2/G3 and land beside this as separate free functions.
//!
//! ── The privacy doctrine, and why it is enforceable HERE (§2) ──
//! Observe → derive → discard → store-only-the-token. This module is the
//! *derive* step, and it is pure by construction, which is what makes the
//! doctrine checkable rather than aspirational: raw data enters as a value
//! and only tokens leave. The shell observes at the trust boundary, calls
//! `derive`, stores the tokens, and drops the `Observation` on the floor.
//! A breach of the token store reveals coordination STRUCTURE ("these N
//! accounts share token X"), never identity ("account A came from 1.2.3.4").
//!
//! Interface, in full: `SignalKind`, `Weight`, `IpClass`, `PlatformClass`,
//! `Observation`, `Token`, `Derived`, `classifyPlatform`, `powBand`,
//! `derive`, `weightOf`, `tierOf`, `SignalTier`, `signal_count`.

const std = @import("std");
const assert = std.debug.assert;

/// How many distinct signals the constellation carries (§1). Six is the
/// designed set; the count is named so callers size their buffers off the
/// module rather than a literal.
pub const signal_count = 6;

// ── Data model (A1: plain data, fields only; behavior is free functions) ──

/// The six signals (§1), in the document's order. Encoded into every token's
/// hash so the same underlying value under two different signals can never
/// collide into a false match.
///
/// An enum, not a record — A7 governs structs (see `pow.zig`'s precedent).
pub const SignalKind = enum(u8) {
    /// §1.1 STRONG — enrollment-timing burst. Real signups arrive with the
    /// entropy of independent human decisions; farms arrive in bursts.
    timing = 0,
    /// §1.2 STRONG — public graph shape. Structural, and the only signal
    /// that keeps evolving after enrollment. See the `graph` note on
    /// `Observation`: it is PROSPECTIVE, never retroactive.
    graph = 1,
    /// §1.3 MODERATE — proof-of-work solve-time residual. The hardware echo:
    /// physics the client cannot forge downward, only pad upward.
    pow_class = 2,
    /// §1.4 WEAK — datacenter vs. residential vs. proxy.
    ip_type = 3,
    /// §1.5 WEAK — multiple accounts, one address. "Multiple keys, same door."
    ip_shared = 4,
    /// §1.6 WEAK — coarse client/OS bucket. Trivially spoofed; included
    /// because it is free and costs the adversary one more thing to vary.
    platform = 5,
};

/// The reliability tier a signal belongs to (§1's strong / moderate / weak
/// grouping). The tier is not decoration: the G2 scorer applies a CAP such
/// that the weak tier alone can never cross the escalation threshold — see
/// `tierOf` and the doctrine note below.
pub const SignalTier = enum(u8) {
    weak = 0,
    moderate = 1,
    strong = 2,
};

/// A signal's vote weight in the G2 scoring sum (§3 Phase 1).
///
/// ⚠️ PLACEHOLDER VALUES — NOT YET CALIBRATED. ⚠️
/// §6 Open Problem 6 states it plainly: every weight here is a guess until
/// tested against observed abuse. The STRUCTURE (six signals, tiered,
/// weighted, capped) is the decision; the numbers are not. Per G1 these do
/// not get called "tuned" without a measurement behind them.
pub const Weight = u16;

/// Coarse IP classification (§1.4). Derived by the shell — which owns the
/// datacenter-range catalogue and any network lookup — and handed in as a
/// plain enum so this module stays free of I/O (B4).
///
/// `unknown` exists so a failed lookup is an ordinary result, not an error
/// (E4): an unclassifiable address simply emits no `ip_type` token.
pub const IpClass = enum(u8) {
    unknown = 0,
    residential = 1,
    datacenter = 2,
    proxy = 3,
};

/// Coarse client/OS bucket (§1.6). Deliberately BROAD — this is not a browser
/// fingerprint. The design rejects precise fingerprinting as invasive and
/// spoofable; what is wanted is a correlation input with a domain small
/// enough that it identifies nobody on its own.
pub const PlatformClass = enum(u8) {
    unknown = 0,
    desktop_windows = 1,
    desktop_macos = 2,
    desktop_linux = 3,
    mobile_android = 4,
    mobile_ios = 5,
    other = 6,
};

/// One enrollment's raw observations, as gathered at the trust boundary.
///
/// This struct is the ONLY place raw-ish data appears, it lives for the
/// duration of one `derive` call, and the shell discards it immediately
/// after (§2 step 3). It deliberately holds NO slices and NO pointers: the
/// two variable-length inputs (the User-Agent string and the raw IP bytes)
/// are reduced to fixed-size values *before* they get here — the UA by
/// `classifyPlatform`, the address by the shell's normalization to 16 bytes.
/// That keeps the struct plain, copyable, and size-guardable (A4/A6).
///
/// A7: one of these exists per in-flight enrollment. Guarded rather than
/// waived — when it is ambiguous whether a struct is hot, the ruleset says
/// treat it as hot.
pub const Observation = struct {
    /// Server-side enrollment completion time, in SECONDS. Server clock, never
    /// client-reported (§1.1) — a client-supplied timestamp is an input the
    /// adversary controls, which would make signal 1 worthless.
    enrolled_at: i64,

    /// The source address, normalized by the shell to 16 bytes (IPv4 is
    /// v6-mapped). Never stored: it is hashed into the `ip_shared` token here
    /// and the caller drops it.
    ip: [16]u8,

    /// Server-measured solve-time residual in MILLISECONDS: total round-trip
    /// minus the estimated network baseline (§1.3). Zero means "not measured"
    /// — absent, not suspicious — and emits no `pow_class` token.
    ///
    /// PREREQUISITE, recorded honestly: this requires a SERVER-ISSUED PoW
    /// challenge and a server-measured round-trip. Zat4's PoW is presently
    /// client-derived and client-verified (`shell/write.zig` says so in its
    /// own comment), so nothing produces this value yet. The field is defined
    /// because the derivation is specified; it will read 0 until the PoW
    /// becomes an enforced, server-issued control.
    pow_solve_ms: u32,

    /// Which difficulty tier produced `pow_solve_ms`. Folded into the token
    /// so bands never collide ACROSS tiers — a 900ms solve at an easy tier and
    /// a 900ms solve at a hard tier describe very different machines. This is
    /// §6 Open Problem 4's "will likely need per-difficulty-tier bucketing",
    /// taken care of structurally rather than left to calibration.
    pow_tier: u8,

    /// Coarse graph-shape score, 0–255, supplied post-enrollment (§1.2).
    /// 0 means "no graph observed yet", which is the state at enrollment time
    /// for every account — signal 2 contributes NOTHING at the gate and
    /// accrues over weeks.
    ///
    /// PROSPECTIVE, NEVER RETROACTIVE (this resolves §6 Open Problem 2): a
    /// graph token derived for account A does not re-price A. It enters the
    /// store and raises the score of the NEXT account that shares it. That
    /// is what lets the retroactive-adjustment answer be "no" without
    /// nullifying the highest-weight signal.
    graph_shape: u8,

    /// §1.4 classification, or `.unknown` if the shell could not classify.
    ip_class: IpClass,

    /// §1.6 bucket, from `classifyPlatform`.
    platform: PlatformClass,

    /// Nonzero when `ip` holds a real observed address.
    ///
    /// ⚠️ This exists because an all-zero `ip` would otherwise be a SENTINEL,
    /// and a sentinel for absence is exactly what this module refuses to do.
    /// Without the flag, every enrollment whose address could not be read —
    /// a missing `X-Forwarded-For`, or any IPv6 client while only v4 is parsed
    /// — would derive the SAME `ip_shared` token and cluster together on their
    /// shared absence. That is the "a missing signal must never look like a
    /// shared one" rule, and it is easy to reintroduce at the shell seam even
    /// when the core is careful.
    ip_known: u8 = 0,

    /// A6: explicit, named padding rather than compiler-chosen. Room for a
    /// future flag byte without moving anything.
    _reserved: [4]u8 = .{0} ** 4,

    comptime {
        // Budget: 8 (enrolled_at) + 16 (ip) + 4 (pow_solve_ms) + 1 (pow_tier)
        // + 1 (graph_shape) + 1 (ip_class) + 1 (platform) + 1 (ip_known)
        // + 4 (reserved) = 37 payload, rounded to 40 by the i64's 8-byte
        // alignment.
        // Raising this requires an A7.1 justification recorded HERE.
        assert(@sizeOf(Observation) == 40);
    }
};

/// One derived coordination token — the ONLY thing that reaches the store.
///
/// `value` is a truncated keyed hash: two accounts sharing a token shared the
/// underlying observation, and the token cannot be walked back to it without
/// the server's secret salt.
///
/// ── An honest limit on "non-reversible" (do not overstate this) ──
/// For `ip_shared` the salt genuinely protects the input: the address space is
/// far too large to enumerate blind. For `ip_type` and `platform` it does NOT
/// — those domains have four and seven members, so anyone holding the salt's
/// output alongside a guess can enumerate them trivially. The salt gives those
/// tokens a uniform SHAPE, not secrecy. That is acceptable because neither
/// value is sensitive on its own ("this account is on Android") and because
/// the store is meant to reveal structure. Said plainly so no one later
/// mistakes the hash for a privacy guarantee it does not provide.
///
/// A7: held in quantity — six per account, across every account in the store.
/// Hot by definition.
pub const Token = struct {
    /// Truncated keyed hash of (salt ‖ kind ‖ observation-value).
    value: u64,
    /// Which signal produced it. Mixed into the hash AND kept in the clear so
    /// the scorer can weight without rehashing.
    kind: SignalKind,
    /// A6: explicit padding to a round 16 bytes.
    _reserved: [7]u8 = .{0} ** 7,

    comptime {
        // Budget: 8 (value) + 1 (kind) + 7 (reserved) = 16 bytes, exact.
        assert(@sizeOf(Token) == 16);
    }
};

/// The result of deriving one enrollment: up to `signal_count` tokens.
///
/// Fewer than six is NORMAL, not a failure. At the moment of account creation
/// the graph signal is always absent, and the PoW signal is absent until a
/// server issues challenges. An unobserved signal emits no token rather than
/// a sentinel one — a missing signal must never look like a shared one.
///
/// A7: one per in-flight enrollment, and the array is walked in the scorer's
/// inner loop. Guarded.
pub const Derived = struct {
    tokens: [signal_count]Token,
    /// How many entries of `tokens` are populated. The rest are undefined.
    len: u8,
    _reserved: [7]u8 = .{0} ** 7,

    comptime {
        // Budget: 6 × 16 (tokens) + 1 (len) + 7 (reserved) = 104 bytes,
        // exact; the Token's 8-byte alignment is already satisfied.
        assert(@sizeOf(Derived) == 104);
    }
};

// ── Calibration constants ──

/// The bucket width for signal 1, in seconds (§1.1).
///
/// ⚠️ PLACEHOLDER — NOT CALIBRATED. ⚠️ §1.1 names the trade directly: tight
/// enough to catch farms, wide enough to absorb an organic spike from a
/// launch or a viral moment. Five minutes is the document's own example.
const timing_window_secs: i64 = 300;

/// Solve-time band edges in milliseconds for signal 3 (§1.3). Roughly
/// geometric, because hardware performance differences are multiplicative,
/// not additive — a flat 200ms band is meaningless at 4000ms and absurdly
/// fine at 100ms.
///
/// ⚠️ PLACEHOLDER — NOT CALIBRATED. ⚠️ §6 Open Problem 4 is explicit that the
/// right granularity is empirical: too coarse and millions share a band (no
/// signal), too fine and network jitter manufactures false distinctions.
/// These edges give a working derivation to calibrate AGAINST; they are not
/// a tuned result.
const pow_band_edges_ms = [_]u32{ 200, 400, 800, 1200, 2000, 4000 };

/// The per-signal vote weights (§1's tiering, §3's scoring sum).
///
/// ⚠️ PLACEHOLDER VALUES — NOT YET CALIBRATED (§6 Open Problem 6). ⚠️
/// The ordering encodes the document's tiers and is the part that is
/// actually decided: graph and timing dominate, PoW class is a real but
/// secondary vote, and the three weak signals are individually near-noise.
///
/// A1/A7 do not apply: this is a namespace of compile-time constants, not a
/// record held in quantity — no instances, no hot loop, nothing to size-guard.
const weights = struct {
    const graph: Weight = 100; // strong  — hardest to fake, slowest to accrue
    const timing: Weight = 80; // strong  — taxes farm deployment SPEED
    const pow_class: Weight = 40; // moderate — physics, but coarse buckets
    const ip_shared: Weight = 15; // weak    — families, campuses, carrier NAT
    const ip_type: Weight = 10; // weak    — VPN users are wrongly caught
    const platform: Weight = 5; // weak    — millions share a bucket
};

// ── Free functions (A1: behavior lives here, not on the records) ──

/// PURE (B2): a signal's vote weight.
pub fn weightOf(kind: SignalKind) Weight {
    return switch (kind) {
        .timing => weights.timing,
        .graph => weights.graph,
        .pow_class => weights.pow_class,
        .ip_type => weights.ip_type,
        .ip_shared => weights.ip_shared,
        .platform => weights.platform,
    };
}

/// PURE (B2): a signal's reliability tier (§1).
///
/// This exists to make the G2 weak-tier CAP expressible: signals 4, 5 and 6
/// together must not be able to cross the escalation threshold on their own —
/// it takes at least one moderate or strong carrier. That rule is what keeps
/// the honest first-time enrollee (a real person on a VPN, behind carrier
/// NAT, signing up during a launch spike) from being escalated by three
/// near-noise votes, and it is the same bound §6 Open Problem 5 asks for
/// against deliberate cluster poisoning. One rule, two threats.
pub fn tierOf(kind: SignalKind) SignalTier {
    return switch (kind) {
        .graph, .timing => .strong,
        .pow_class => .moderate,
        .ip_type, .ip_shared, .platform => .weak,
    };
}

/// PURE (B2): reduce a User-Agent string to a coarse platform bucket (§1.6).
///
/// Substring matching in a deliberate order — the specific before the general,
/// because real UA strings nest their claims (an Android UA also says "Linux";
/// an iOS UA also says "Mac OS X"). Getting that order wrong silently merges
/// two buckets, so the order IS the logic here.
///
/// Takes the string by slice and returns an enum: the raw text never enters
/// `Observation` and never reaches the store (§2).
pub fn classifyPlatform(ua: []const u8) PlatformClass {
    if (ua.len == 0) return .unknown;

    // Mobile first: both mobile UAs also carry a desktop-looking token.
    if (containsFold(ua, "android")) return .mobile_android;
    if (containsFold(ua, "iphone") or containsFold(ua, "ipad") or
        containsFold(ua, "ios"))
    {
        return .mobile_ios;
    }

    // Then desktop, most-specific first.
    if (containsFold(ua, "windows")) return .desktop_windows;
    if (containsFold(ua, "mac os") or containsFold(ua, "macintosh")) {
        return .desktop_macos;
    }
    if (containsFold(ua, "linux") or containsFold(ua, "x11")) return .desktop_linux;

    return .other;
}

/// PURE: ASCII case-insensitive substring test. Hand-rolled rather than
/// lowercasing a copy, because lowercasing would need an allocator (C1/C2)
/// for what is a read-only scan.
fn containsFold(haystack: []const u8, needle: []const u8) bool {
    if (needle.len == 0 or needle.len > haystack.len) return false;
    var i: usize = 0;
    outer: while (i + needle.len <= haystack.len) : (i += 1) {
        for (needle, 0..) |n, j| {
            if (std.ascii.toLower(haystack[i + j]) != n) continue :outer;
        }
        return true;
    }
    return false;
}

/// PURE (B2): map a measured solve time to its band index (§1.3).
///
/// Returns the number of edges the time exceeds, so band `0` is the fastest
/// and `pow_band_edges_ms.len` the slowest. Monotonic by construction.
pub fn powBand(solve_ms: u32) u8 {
    var band: u8 = 0;
    for (pow_band_edges_ms) |edge| {
        if (solve_ms < edge) break;
        band += 1;
    }
    return band;
}

/// PURE (B2): derive the coordination tokens for one enrollment. This is
/// Phase G1 in full — §5's exit criterion is that every enrollment produces
/// its derived tokens with no raw data retained, and this is the function
/// that makes the second half of that sentence structurally true.
///
/// `salt` is a long-lived server secret. It is a PARAMETER, not a constant,
/// because a secret is I/O-shaped state and belongs to the shell (B3) — this
/// module must stay a pure function of its inputs.
///
/// ⚠️ The salt must NOT be rotated casually: every stored token is keyed to
/// it, so rotating invalidates the entire store and every account's
/// coordination history resets to zero. That is a full amnesty for existing
/// clusters. Treat rotation as a deliberate, recorded migration.
///
/// Same inputs ⇒ same tokens, always: matching is equality on `value`, so a
/// non-deterministic derivation would silently break every comparison.
pub fn derive(obs: Observation, salt: [32]u8) Derived {
    var out: Derived = .{ .tokens = undefined, .len = 0 };

    // Signal 1 — timing window. Floored division must round toward negative
    // infinity so pre-epoch timestamps bucket consistently; Zig's `@divFloor`
    // does that, plain `/` truncates toward zero and would fold two windows
    // into one across the epoch boundary.
    const window = @divFloor(obs.enrolled_at, timing_window_secs);
    var window_bytes: [8]u8 = undefined;
    std.mem.writeInt(i64, &window_bytes, window, .little);
    out = push(out, token(salt, .timing, &window_bytes));

    // Signal 2 — graph shape. Absent (0) at enrollment for every account;
    // present only once a separate post-enrollment path has observed it.
    if (obs.graph_shape != 0) {
        out = push(out, token(salt, .graph, &[_]u8{obs.graph_shape}));
    }

    // Signal 3 — PoW solve-time residual, banded, bound to its difficulty
    // tier. Zero means not measured, which is absence, not a fast machine.
    if (obs.pow_solve_ms != 0) {
        const band = powBand(obs.pow_solve_ms);
        out = push(out, token(salt, .pow_class, &[_]u8{ obs.pow_tier, band }));
    }

    // Signal 4 — IP type. `.unknown` is a failed lookup, not a class.
    if (obs.ip_class != .unknown) {
        out = push(out, token(salt, .ip_type, &[_]u8{@intFromEnum(obs.ip_class)}));
    }

    // Signal 5 — shared address. Emitted ONLY when an address was actually
    // observed: see `Observation.ip_known`. An unreadable address is absence,
    // and absence must never derive a token that others share.
    if (obs.ip_known != 0) {
        out = push(out, token(salt, .ip_shared, &obs.ip));
    }

    // Signal 6 — platform bucket. `.unknown` means no UA was presented.
    if (obs.platform != .unknown) {
        out = push(out, token(salt, .platform, &[_]u8{@intFromEnum(obs.platform)}));
    }

    return out;
}

/// PURE: append a token. `derive` emits at most `signal_count`, so the bound
/// holds by construction — asserted rather than handled, because overflowing
/// it would mean this file grew a seventh emit site without growing the array.
fn push(d: Derived, t: Token) Derived {
    assert(d.len < signal_count);
    var out = d;
    out.tokens[d.len] = t;
    out.len = d.len + 1;
    return out;
}

/// PURE: the keyed one-way step every token goes through.
///
/// SHA-256 over (salt ‖ kind ‖ value), truncated to 64 bits. The salt goes
/// FIRST so the construction is prefix-keyed, and the kind is mixed in so the
/// same bytes under two different signals cannot collide into a false match.
///
/// 64 bits is a deliberate truncation. At store sizes the constellation cares
/// about, accidental collisions are negligible (a million tokens gives a
/// ~3-in-100,000,000,000 chance of any pair colliding), and a collision's
/// consequence is bounded anyway: it adds one spurious weak vote, which the
/// weak-tier cap already prevents from escalating anything on its own.
fn token(salt: [32]u8, kind: SignalKind, value: []const u8) Token {
    var h = std.crypto.hash.sha2.Sha256.init(.{});
    h.update(&salt);
    h.update(&[_]u8{@intFromEnum(kind)});
    h.update(value);
    var digest: [32]u8 = undefined;
    h.final(&digest);
    return .{ .value = std.mem.readInt(u64, digest[0..8], .little), .kind = kind };
}

// ══ Phase G2 — score-and-threshold (§3 Phase 1) ══
//
// The first operational Gate. A candidate enrollment's tokens are compared
// against the store; each overlap is a weighted vote; the weighted sum decides
// the deposit multiplier. This is a RUNG, not the destination — a score says
// "this looks coordinated" but not "this is the 14th account from this
// operator". The exponential curve needs cluster SIZE, which needs G3.

/// How many stored accounts share each signal's token with the candidate.
/// Indexed by `@intFromEnum(SignalKind)`.
///
/// A7: one per in-flight assessment, walked in the scoring loop. Guarded.
pub const MatchCounts = struct {
    per_signal: [signal_count]u32,

    comptime {
        // Budget: 6 × 4 = 24 bytes, exact.
        assert(@sizeOf(MatchCounts) == 24);
    }
};

/// The weighted outcome of one assessment.
///
/// `carrier_total` is tracked SEPARATELY from `total` rather than recomputed,
/// because the weak-tier cap needs to know how much of the score came from
/// signals that can actually carry an escalation. Folding them into one number
/// would lose exactly the distinction the cap depends on.
///
/// A7: held per assessment; guarded.
pub const Score = struct {
    /// Weighted sum across all six signals.
    total: u32,
    /// Weighted sum across the moderate and strong tiers only.
    carrier_total: u32,

    comptime {
        // Budget: 4 + 4 = 8 bytes, exact.
        assert(@sizeOf(Score) == 8);
    }
};

/// The escalation threshold: below this, the deposit stays at base rate.
///
/// ⚠️ PLACEHOLDER — NOT CALIBRATED (§6 Open Problem 6). ⚠️ For scale, one shared
/// timing token is 80 and one shared graph token is 100, so this sits just above
/// "a single strong signal matched one other account" — deliberately, because a
/// single overlap with one other account is not coordination, it is coincidence.
const escalation_threshold: u32 = 100;

/// The stepped escalation curve for G2 — deposit multiplier in hundredths
/// (100 = 1.0×, base rate).
///
/// ⚠️ PLACEHOLDER — NOT CALIBRATED. ⚠️ §3 says only that the shape is
/// "monotonically increasing"; whether it is linear, stepped, or continuous is
/// explicitly empirical. Steps are used here because they are legible in logs
/// during shadow mode, which is what this phase is actually for. Note this is
/// NOT the exponential curve from §0 — that one is keyed to cluster size and
/// arrives with G3. A score-based curve cannot express "the 14th account".
const escalation_steps = [_]struct { at: u32, factor_x100: u32 }{
    .{ .at = 100, .factor_x100 = 150 },
    .{ .at = 250, .factor_x100 = 200 },
    .{ .at = 500, .factor_x100 = 400 },
    .{ .at = 1000, .factor_x100 = 800 },
};

/// PURE (B2): count, per signal, how many stored tokens the candidate shares.
///
/// A token matches only within its own signal — `kind` is compared as well as
/// `value`, so a coincidental 64-bit collision across two different signals
/// cannot manufacture a match (the kind is already mixed into the hash, so this
/// is belt-and-braces, and it is free).
///
/// This is the pure DEFINITION of the matching semantics and the oracle the
/// tests check against. It is deliberately a linear scan: a real store will
/// index by token value, but there is no store yet, and building the index
/// before the store exists would be abstracting ahead of use (F4). The shell
/// owns that optimization when it owns the store.
pub fn countMatches(candidate: Derived, stored: []const Token) MatchCounts {
    var counts: MatchCounts = .{ .per_signal = .{0} ** signal_count };
    for (candidate.tokens[0..candidate.len]) |c| {
        var n: u32 = 0;
        for (stored) |s| {
            if (s.kind == c.kind and s.value == c.value) {
                // Saturate rather than wrap: the store is adversarial input
                // (§6 Open Problem 5), and a wrapped count would read as ZERO
                // matches — turning a colossal cluster into a clean account.
                n +|= 1;
            }
        }
        counts.per_signal[@intFromEnum(c.kind)] = n;
    }
    return counts;
}

/// PURE (B2): the weighted scoring sum of §3 Phase 1.
///
/// ```
/// score = Σ (signal_weight[i] × signal_match_count[i])
/// ```
///
/// Arithmetic saturates throughout. Every input here is attacker-influenced —
/// an adversary who can inflate a match count controls one multiplicand — and a
/// wrapped sum would silently produce a LOW score from an extreme cluster,
/// which is precisely the failure an attacker would want.
pub fn scoreOf(counts: MatchCounts) Score {
    var total: u32 = 0;
    var carrier_total: u32 = 0;
    for (counts.per_signal, 0..) |n, i| {
        const kind: SignalKind = @enumFromInt(i);
        const contribution: u32 = @as(u32, weightOf(kind)) *| n;
        total +|= contribution;
        if (tierOf(kind) != .weak) carrier_total +|= contribution;
    }
    return .{ .total = total, .carrier_total = carrier_total };
}

/// PURE (B2): the deposit multiplier in hundredths (100 = base rate).
///
/// ── THE WEAK-TIER CAP (§3, decided 2026-07-19) ──
/// If NO moderate or strong signal matched, the deposit stays at base rate no
/// matter how large the weak-tier score grows. Signals 4, 5 and 6 — IP type,
/// shared IP, and platform bucket — cannot escalate anyone on their own.
///
/// This is the single most important line in the scoring path, and it answers
/// two separate threats with one rule:
///
///   1. The honest FIRST-time enrollee. A real person on a VPN, behind carrier
///      NAT, signing up during a launch spike matches all three weak signals
///      against thousands of strangers. For a first account the "refundable
///      deposit" ethic offers them nothing — they never pay it, they are simply
///      priced out of joining. Weak signals must never be able to do that.
///   2. Cluster poisoning (§6 Open Problem 5). An adversary inducing false
///      clustering will reach for the cheap signals, because those are the ones
///      they can manufacture. Capping them bounds the whole attack.
///
/// The cap also gets stronger over time, which is the point: with no signal
/// decay (§2) match counts only ever grow, so a carrier-NAT or university IP
/// token accumulates accounts forever. Without this rule those users would
/// drift into permanent escalation purely for sharing an address.
pub fn escalationFactor(s: Score) u32 {
    if (s.carrier_total == 0) return 100; // the cap — base rate, full stop
    if (s.total < escalation_threshold) return 100;

    var factor: u32 = 100;
    for (escalation_steps) |step| {
        if (s.total >= step.at) factor = step.factor_x100;
    }
    return factor;
}

/// PURE (B2): the whole G2 assessment in one call — the shell's entry point.
/// Returns the deposit multiplier in hundredths for a candidate enrollment
/// against the current store.
///
/// ⚠️ SHADOW MODE: during bootstrap this result is LOGGED, not charged (§9.10).
/// It cannot harm an honest user until the deposit spine exists and someone
/// deliberately switches it from observed to enforced.
pub fn assess(candidate: Derived, stored: []const Token) u32 {
    return escalationFactor(scoreOf(countMatches(candidate, stored)));
}

// ── Tests: the pure core, no Io, no allocator ──

const test_salt = [_]u8{0x5A} ** 32;

/// A baseline enrollment: everything observed, so all six signals fire.
fn testObservation() Observation {
    return .{
        .enrolled_at = 1_767_323_045,
        .ip = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xFF, 0xFF, 203, 0, 113, 7 },
        .pow_solve_ms = 950,
        .pow_tier = 2,
        .graph_shape = 40,
        .ip_class = .residential,
        .platform = .desktop_linux,
        .ip_known = 1,
    };
}

test "derive is deterministic" {
    const obs = testObservation();
    const a = derive(obs, test_salt);
    const b = derive(obs, test_salt);
    try std.testing.expectEqual(a.len, b.len);
    for (a.tokens[0..a.len], b.tokens[0..b.len]) |ta, tb| {
        try std.testing.expectEqual(ta.value, tb.value);
        try std.testing.expectEqual(ta.kind, tb.kind);
    }
}

test "a fully-observed enrollment emits all six signals, exactly once each" {
    const d = derive(testObservation(), test_salt);
    try std.testing.expectEqual(@as(u8, signal_count), d.len);

    var seen = [_]bool{false} ** signal_count;
    for (d.tokens[0..d.len]) |t| {
        const i = @intFromEnum(t.kind);
        try std.testing.expect(!seen[i]); // no signal emits twice
        seen[i] = true;
    }
    for (seen) |s| try std.testing.expect(s);
}

test "an unobserved signal emits NO token rather than a sentinel one" {
    // This is the load-bearing property: a missing signal must never look
    // like a SHARED one, or every account lacking a graph would cluster
    // together on their shared absence.
    var obs = testObservation();
    obs.graph_shape = 0; // no graph yet — the state of every new account
    obs.pow_solve_ms = 0; // no server-issued PoW measurement
    obs.ip_class = .unknown; // classification failed
    obs.platform = .unknown; // no UA presented

    const d = derive(obs, test_salt);
    try std.testing.expectEqual(@as(u8, 2), d.len); // timing + ip_shared only
    for (d.tokens[0..d.len]) |t| {
        try std.testing.expect(t.kind == .timing or t.kind == .ip_shared);
    }
}

test "an UNREADABLE address emits no ip_shared token" {
    // Regression: the shell seam once passed an all-zero ip for "not observed",
    // which made every client with an unreadable address (a missing
    // X-Forwarded-For, or any IPv6 client while only v4 is parsed) share one
    // token and cluster on their shared absence. The core must not be able to
    // express that.
    var obs = testObservation();
    obs.ip_known = 0;
    const d = derive(obs, test_salt);
    try std.testing.expect(tokenOf(d, .ip_shared) == null);

    // And two such enrollments still share NOTHING via the address.
    var other = testObservation();
    other.ip_known = 0;
    other.ip = [_]u8{0xAB} ** 16; // different bytes, both unknown
    const e = derive(other, test_salt);
    try std.testing.expect(tokenOf(e, .ip_shared) == null);
}

test "two accounts in the same window share a timing token; a later one does not" {
    const base = testObservation();
    var near = base;
    near.enrolled_at = base.enrolled_at + 30; // same 5-minute bucket
    var far = base;
    far.enrolled_at = base.enrolled_at + timing_window_secs * 3; // a later bucket

    const t_base = tokenOf(derive(base, test_salt), .timing).?;
    const t_near = tokenOf(derive(near, test_salt), .timing).?;
    const t_far = tokenOf(derive(far, test_salt), .timing).?;

    try std.testing.expectEqual(t_base, t_near);
    try std.testing.expect(t_base != t_far);
}

test "the same address yields the same shared-IP token across enrollments" {
    const a = testObservation();
    var b = testObservation();
    b.enrolled_at = a.enrolled_at + 86_400; // a day apart, same door
    b.platform = .mobile_android;

    try std.testing.expectEqual(
        tokenOf(derive(a, test_salt), .ip_shared).?,
        tokenOf(derive(b, test_salt), .ip_shared).?,
    );

    var c = testObservation();
    c.ip[15] = 8; // one octet different
    try std.testing.expect(
        tokenOf(derive(a, test_salt), .ip_shared).? !=
            tokenOf(derive(c, test_salt), .ip_shared).?,
    );
}

test "tokens are salt-keyed: a different salt shares nothing" {
    const obs = testObservation();
    const a = derive(obs, test_salt);
    const b = derive(obs, [_]u8{0xA5} ** 32);
    for (a.tokens[0..a.len], b.tokens[0..b.len]) |ta, tb| {
        try std.testing.expectEqual(ta.kind, tb.kind);
        try std.testing.expect(ta.value != tb.value);
    }
}

test "the kind is mixed in: identical bytes under two signals do not collide" {
    // Both carry the single byte 2 (IpClass.datacenter / PlatformClass.macos).
    var obs = testObservation();
    obs.ip_class = .datacenter;
    obs.platform = .desktop_macos;
    const d = derive(obs, test_salt);
    try std.testing.expect(
        tokenOf(d, .ip_type).? != tokenOf(d, .platform).?,
    );
}

test "powBand is monotonic and binds its difficulty tier" {
    try std.testing.expectEqual(@as(u8, 0), powBand(0));
    try std.testing.expectEqual(@as(u8, 0), powBand(199));
    try std.testing.expectEqual(@as(u8, 1), powBand(200)); // edges are inclusive-low
    try std.testing.expectEqual(@as(u8, 3), powBand(950));
    try std.testing.expectEqual(@as(u8, 6), powBand(999_999)); // saturates

    var last: u8 = 0;
    var ms: u32 = 0;
    while (ms < 6000) : (ms += 37) {
        const b = powBand(ms);
        try std.testing.expect(b >= last);
        last = b;
    }

    // The same solve time at a different difficulty tier is a different token
    // (§6 Open Problem 4 — per-tier bucketing, handled structurally).
    var easy = testObservation();
    easy.pow_tier = 1;
    var hard = testObservation();
    hard.pow_tier = 2;
    try std.testing.expect(
        tokenOf(derive(easy, test_salt), .pow_class).? !=
            tokenOf(derive(hard, test_salt), .pow_class).?,
    );
}

test "classifyPlatform resolves the nested cases in the right order" {
    // Android UAs also say "Linux"; iOS UAs also say "Mac OS X". Order is the
    // logic — getting it wrong silently merges buckets.
    try std.testing.expectEqual(PlatformClass.mobile_android, classifyPlatform(
        "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36",
    ));
    try std.testing.expectEqual(PlatformClass.mobile_ios, classifyPlatform(
        "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1",
    ));
    try std.testing.expectEqual(PlatformClass.desktop_windows, classifyPlatform(
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) Gecko/20100101 Firefox/130.0",
    ));
    try std.testing.expectEqual(PlatformClass.desktop_macos, classifyPlatform(
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    ));
    try std.testing.expectEqual(PlatformClass.desktop_linux, classifyPlatform(
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:130.0) Gecko/20100101",
    ));
    try std.testing.expectEqual(PlatformClass.unknown, classifyPlatform(""));
    try std.testing.expectEqual(PlatformClass.other, classifyPlatform("curl/8.5.0"));
    // Case-insensitive.
    try std.testing.expectEqual(PlatformClass.desktop_windows, classifyPlatform("WINDOWS NT"));
}

test "weights and tiers encode the documented ordering" {
    // The relative ordering is the decided part (§7); the numbers are not.
    try std.testing.expect(weightOf(.graph) > weightOf(.timing));
    try std.testing.expect(weightOf(.timing) > weightOf(.pow_class));
    try std.testing.expect(weightOf(.pow_class) > weightOf(.ip_shared));
    try std.testing.expect(weightOf(.ip_shared) > weightOf(.ip_type));
    try std.testing.expect(weightOf(.ip_type) > weightOf(.platform));

    try std.testing.expectEqual(SignalTier.strong, tierOf(.graph));
    try std.testing.expectEqual(SignalTier.strong, tierOf(.timing));
    try std.testing.expectEqual(SignalTier.moderate, tierOf(.pow_class));
    try std.testing.expectEqual(SignalTier.weak, tierOf(.ip_type));
    try std.testing.expectEqual(SignalTier.weak, tierOf(.ip_shared));
    try std.testing.expectEqual(SignalTier.weak, tierOf(.platform));
}

/// Test helper: pull one signal's token value out of a `Derived`.
fn tokenOf(d: Derived, kind: SignalKind) ?u64 {
    for (d.tokens[0..d.len]) |t| {
        if (t.kind == kind) return t.value;
    }
    return null;
}

/// Test helper: flatten N derived enrollments into one store-shaped slice.
fn storeOf(buf: []Token, derived: []const Derived) []Token {
    var n: usize = 0;
    for (derived) |d| {
        for (d.tokens[0..d.len]) |t| {
            buf[n] = t;
            n += 1;
        }
    }
    return buf[0..n];
}

// ── G2 tests ──

test "a lone first enrollment matches nothing and pays base rate" {
    const d = derive(testObservation(), test_salt);
    const counts = countMatches(d, &[_]Token{});
    for (counts.per_signal) |n| try std.testing.expectEqual(@as(u32, 0), n);

    const s = scoreOf(counts);
    try std.testing.expectEqual(@as(u32, 0), s.total);
    try std.testing.expectEqual(@as(u32, 100), escalationFactor(s));
}

test "countMatches counts per signal and never across signals" {
    const a = derive(testObservation(), test_salt);

    // Three more enrollments from the same address, all in different windows
    // and on different platforms: only ip_shared should accumulate.
    var others: [3]Derived = undefined;
    for (&others, 0..) |*o, i| {
        var obs = testObservation();
        obs.enrolled_at += timing_window_secs * @as(i64, @intCast(i + 5));
        obs.platform = .desktop_windows;
        obs.graph_shape = 0;
        obs.pow_solve_ms = 0;
        o.* = derive(obs, test_salt);
    }
    var buf: [signal_count * 3]Token = undefined;
    const counts = countMatches(a, storeOf(&buf, &others));

    try std.testing.expectEqual(@as(u32, 3), counts.per_signal[@intFromEnum(SignalKind.ip_shared)]);
    try std.testing.expectEqual(@as(u32, 3), counts.per_signal[@intFromEnum(SignalKind.ip_type)]);
    try std.testing.expectEqual(@as(u32, 0), counts.per_signal[@intFromEnum(SignalKind.timing)]);
    try std.testing.expectEqual(@as(u32, 0), counts.per_signal[@intFromEnum(SignalKind.platform)]);
    try std.testing.expectEqual(@as(u32, 0), counts.per_signal[@intFromEnum(SignalKind.graph)]);
}

test "THE WEAK-TIER CAP: weak signals alone never escalate, at any scale" {
    // The honest first-timer: a real person on a VPN, behind carrier NAT,
    // signing up during a launch spike. They share IP type, shared IP, and
    // platform with an enormous number of strangers — and nothing else.
    // This must cost them exactly the base rate.
    var counts: MatchCounts = .{ .per_signal = .{0} ** signal_count };
    counts.per_signal[@intFromEnum(SignalKind.ip_type)] = 50_000;
    counts.per_signal[@intFromEnum(SignalKind.ip_shared)] = 50_000;
    counts.per_signal[@intFromEnum(SignalKind.platform)] = 50_000;

    const s = scoreOf(counts);
    try std.testing.expect(s.total > escalation_threshold); // enormous...
    try std.testing.expectEqual(@as(u32, 0), s.carrier_total); // ...but no carrier
    try std.testing.expectEqual(@as(u32, 100), escalationFactor(s)); // base rate

    // One carrier match flips it: the weak votes now count as support.
    counts.per_signal[@intFromEnum(SignalKind.timing)] = 1;
    const with_carrier = scoreOf(counts);
    try std.testing.expect(with_carrier.carrier_total > 0);
    try std.testing.expect(escalationFactor(with_carrier) > 100);
}

test "a single strong overlap with one account is coincidence, not coordination" {
    var counts: MatchCounts = .{ .per_signal = .{0} ** signal_count };
    counts.per_signal[@intFromEnum(SignalKind.timing)] = 1; // 80 < threshold 100
    try std.testing.expectEqual(@as(u32, 100), escalationFactor(scoreOf(counts)));

    counts.per_signal[@intFromEnum(SignalKind.graph)] = 1; // +100 → 180
    try std.testing.expect(escalationFactor(scoreOf(counts)) > 100);
}

test "escalation is monotonic in match count" {
    var last: u32 = 0;
    var n: u32 = 0;
    while (n < 40) : (n += 1) {
        var counts: MatchCounts = .{ .per_signal = .{0} ** signal_count };
        counts.per_signal[@intFromEnum(SignalKind.timing)] = n;
        counts.per_signal[@intFromEnum(SignalKind.pow_class)] = n;
        const f = escalationFactor(scoreOf(counts));
        try std.testing.expect(f >= last);
        last = f;
    }
    try std.testing.expect(last > 100); // it did actually climb
}

test "scoring saturates rather than wrapping on adversarial counts" {
    // A wrapped sum would turn a colossal cluster into a LOW score — exactly
    // the failure an attacker would engineer for. Saturation makes the worst
    // case "maximally escalated", never "clean".
    const counts: MatchCounts = .{ .per_signal = .{std.math.maxInt(u32)} ** signal_count };
    const s = scoreOf(counts);
    try std.testing.expectEqual(std.math.maxInt(u32), s.total);
    try std.testing.expect(s.carrier_total > 0);
    try std.testing.expect(escalationFactor(s) > 100);

    // And countMatches saturates too, rather than wrapping to zero matches.
    const d = derive(testObservation(), test_salt);
    const one = tokenOf(d, .ip_shared).?;
    var many: [8]Token = undefined;
    for (&many) |*t| t.* = .{ .value = one, .kind = .ip_shared };
    const c = countMatches(d, &many);
    try std.testing.expectEqual(@as(u32, 8), c.per_signal[@intFromEnum(SignalKind.ip_shared)]);
}

test "assess: a farm bursting from one machine escalates; a stranger does not" {
    // Ten accounts, same window, same address, same platform, same PoW band.
    var farm: [10]Derived = undefined;
    for (&farm, 0..) |*f, i| {
        var obs = testObservation();
        obs.enrolled_at += @intCast(i * 3); // seconds apart — same bucket
        f.* = derive(obs, test_salt);
    }
    var buf: [signal_count * 10]Token = undefined;
    const store = storeOf(&buf, &farm);

    // The eleventh account from that same machine.
    var next_obs = testObservation();
    next_obs.enrolled_at += 40;
    try std.testing.expect(assess(derive(next_obs, test_salt), store) > 100);

    // An unrelated person: different address, different window, different
    // hardware, different platform. They share only the IP *type* (both
    // residential) — a weak signal, so the cap holds them at base rate.
    var stranger = testObservation();
    stranger.enrolled_at += timing_window_secs * 900;
    stranger.ip = [_]u8{ 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
    stranger.pow_solve_ms = 180;
    stranger.platform = .mobile_ios;
    stranger.graph_shape = 0;
    try std.testing.expectEqual(@as(u32, 100), assess(derive(stranger, test_salt), store));
}
