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

//! B1 classification: SHELL (impure). The **credential generator's** impure
//! half — the one place cryptographic randomness enters. It draws fresh
//! entropy per credential via `std.Io.randomSecure` (0.16: randomness is a
//! capability on `Io`, not a global — B3), reduces it to unbiased pool
//! indices (the pure `pickIndex`), and hands the pure core the indices to
//! assemble. The plaintext crosses out as a `Credential` value (B5); no
//! index, no raw-entropy buffer leaks past this interface (D3).
//!
//! Interface, in full: `Error`, `generate`, `wipe`.
//!
//! ── Reconciliation with CREDENTIAL_GEN_DESIGN.md (recorded per H3) ──
//! The design assumed it could obtain a `std.Random` interface from `Io` and
//! call `intRangeLessThan`. Under 0.16.0, `Io.randomSecure(io, buffer)` fills
//! RAW BYTES — it does not yield a `std.Random` (that wraps a PRNG, which
//! would keep CSPRNG state in process memory, the very thing the design chose
//! `randomSecure` to avoid). So the unbiased pick is done directly on the raw
//! bytes: because the pool is a power of two, a 12-bit MASK is exactly uniform
//! (no rejection sampling). `secureZero` is `std.crypto.secureZero` (not the
//! `crypto.utils` path the design guessed). Both verified against 0.16.0 std.

const std = @import("std");
const cred = @import("../core/credential.zig");

/// What generation can surface (E3). These are exactly `Io.randomSecure`'s
/// errors, surfaced by name so a caller cannot forget the entropy-source
/// failure path. There is NO `EntropyFloorNotMet`: every tier clears the
/// floor as a compile-time fact (core comptime assert), so the case is
/// defined out of existence (E4).
pub const Error = error{
    /// The system entropy source is unavailable. Rare and exceptional; the
    /// caller should refuse to mint a credential rather than fall back to a
    /// weaker source.
    EntropyUnavailable,
    /// The Io operation was canceled.
    Canceled,
};

/// SHELL (B3): mint one credential at the chosen tier. Allocates NOTHING —
/// it writes into the inline `Credential` and reads the comptime pool, so per
/// C1/C2 it correctly takes no `Allocator`; its only resource is entropy,
/// which arrives via `io`.
///
/// UNIFORMITY (load-bearing, DESIGN §0): each index is `pickIndex(raw16)`, an
/// unbiased mask valid because the pool is a power of two. INDEPENDENCE: every
/// word uses its own fresh 16 bits from a single `randomSecure` draw. CSPRNG:
/// `randomSecure` is a syscall with no stored state. These three are the only
/// things that could erode the stated bits; all three are honored here.
///
/// SECRET HYGIENE (C5): the raw entropy and the picked indices are secret-
/// derived and are scrubbed before return via `defer`. The plaintext lives in
/// the returned `Credential` (one wipe site — see `wipe`).
pub fn generate(io: std.Io, tier: cred.Tier) Error!cred.Credential {
    const n = cred.wordCount(tier);

    // One syscall: 2 bytes of entropy per word (16 bits, of which 12 are used).
    var raw: [cred.max_words * 2]u8 = undefined;
    defer std.crypto.secureZero(u8, &raw); // scrub secret-derived bytes (C5)
    io.randomSecure(raw[0 .. @as(usize, n) * 2]) catch |e| switch (e) {
        error.EntropyUnavailable => return Error.EntropyUnavailable,
        error.Canceled => return Error.Canceled,
    };

    var indices: [cred.max_words]u16 = undefined;
    defer std.crypto.secureZero(u16, &indices); // scrub the picks (C5)
    var w: usize = 0;
    while (w < n) : (w += 1) {
        const raw16 = std.mem.readInt(u16, raw[w * 2 ..][0..2], .little);
        indices[w] = cred.pickIndex(raw16); // unbiased (power-of-two mask)
    }

    var c: cred.Credential = undefined;
    c.len = cred.assemble(indices[0..n], &c.bytes);
    return c;
}

/// Scrub a credential's plaintext after the caller is done with it. The
/// inline buffer means ONE deterministic wipe site (C5), not heap copies to
/// chase. `secureZero` defeats dead-store elimination.
pub fn wipe(c: *cred.Credential) void {
    std.crypto.secureZero(u8, &c.bytes);
    c.len = 0;
}

// ── Tests: real CSPRNG via std.testing.io, leak-checked (C6) ──

test "generate produces the right shape per tier" {
    inline for (.{
        .{ cred.Tier.secure, 6 },
        .{ cred.Tier.super_secure, 7 },
        .{ cred.Tier.ultra_secure, 9 },
    }) |pair| {
        const tier = pair[0];
        const words = pair[1];
        var c = try generate(std.testing.io, tier);
        defer wipe(&c);
        // word count = (dash count) + 1
        var dashes: usize = 0;
        for (c.bytes[0..c.len]) |ch| {
            if (ch == '-') dashes += 1;
        }
        try std.testing.expectEqual(@as(usize, words), dashes + 1);
        // every word is Title-Case (first char of each segment is A–Z, rest a–z)
        var at_word_start = true;
        for (c.bytes[0..c.len]) |ch| {
            if (ch == '-') {
                at_word_start = true;
                continue;
            }
            if (at_word_start) {
                try std.testing.expect(ch >= 'A' and ch <= 'Z');
                at_word_start = false;
            } else {
                try std.testing.expect(ch >= 'a' and ch <= 'z');
            }
        }
    }
}

test "generate is non-degenerate: draws vary across credentials" {
    // A broken or constant RNG would repeat. 50 draws from 4096 first-words
    // give ~50 distinct; assert a very safe lower bound so the test never flaps.
    var first_words: [50][]const u8 = undefined;
    var i: usize = 0;
    while (i < 50) : (i += 1) {
        var c = try generate(std.testing.io, .secure);
        defer wipe(&c);
        const dash = std.mem.indexOfScalar(u8, c.bytes[0..c.len], '-').?;
        first_words[i] = try std.testing.allocator.dupe(u8, c.bytes[0..dash]);
    }
    defer for (first_words) |fw| std.testing.allocator.free(fw);

    var distinct: usize = 0;
    for (first_words, 0..) |fw, idx| {
        var seen = false;
        for (first_words[0..idx]) |prev| {
            if (std.mem.eql(u8, fw, prev)) {
                seen = true;
                break;
            }
        }
        if (!seen) distinct += 1;
    }
    try std.testing.expect(distinct >= 10); // overwhelmingly ~50; 10 is a safe floor
}

test "wipe zeroes the plaintext and length" {
    var c = try generate(std.testing.io, .ultra_secure);
    try std.testing.expect(c.len > 0);
    wipe(&c);
    try std.testing.expectEqual(@as(u8, 0), c.len);
    for (c.bytes) |b| try std.testing.expectEqual(@as(u8, 0), b);
}
