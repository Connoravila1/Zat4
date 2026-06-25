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

//! TEST-ONLY utility (compiled solely into the test build; no caller in the
//! shipping graph). Deterministic adversarial-input generation for the
//! trust-boundary parser fuzz tests (SECURITY_ROADMAP Phase 8: "the core is
//! pure, so it is trivially fuzzable — feed bytes, assert no crash, no leak,
//! no hang"). The PRNG is seeded with a FIXED seed so runs are reproducible:
//! this is test randomness, not security randomness, so a plain PRNG is correct
//! here (it is never on a security path).

const std = @import("std");

pub const Gen = struct {
    // A7.2: cold struct — a test-only generator (one per fuzz test), not a hot
    // record; size guard waived.
    prng: std.Random.DefaultPrng,

    pub fn init(seed: u64) Gen {
        return .{ .prng = std.Random.DefaultPrng.init(seed) };
    }

    fn r(g: *Gen) std.Random {
        return g.prng.random();
    }

    /// A random-length (0..buf.len) run of fully random bytes.
    pub fn randomBytes(g: *Gen, buf: []u8) []u8 {
        const n = g.r().uintAtMost(usize, buf.len);
        g.r().bytes(buf[0..n]);
        return buf[0..n];
    }

    /// A random-length run drawn from `charset` — structure-aware fuzzing that
    /// reaches deeper into a parser than uniform random bytes (which almost
    /// always reject at the first byte).
    pub fn randomFromSet(g: *Gen, buf: []u8, charset: []const u8) []u8 {
        const n = g.r().uintAtMost(usize, buf.len);
        for (buf[0..n]) |*b| b.* = charset[g.r().uintLessThan(usize, charset.len)];
        return buf[0..n];
    }

    /// Copy `seed` into `buf`, then apply `k` random mutations (bit-flip,
    /// byte-replace, or truncate). Mutating a VALID seed is the most effective
    /// way to reach a parser's deep, post-validation code paths.
    pub fn mutate(g: *Gen, buf: []u8, seed: []const u8, k: usize) []u8 {
        var len = @min(seed.len, buf.len);
        @memcpy(buf[0..len], seed[0..len]);
        var i: usize = 0;
        while (i < k and len > 0) : (i += 1) {
            switch (g.r().uintLessThan(u8, 3)) {
                0 => buf[g.r().uintLessThan(usize, len)] ^= g.r().int(u8),
                1 => buf[g.r().uintLessThan(usize, len)] = g.r().int(u8),
                else => len = g.r().uintLessThan(usize, len),
            }
        }
        return buf[0..len];
    }

    /// One of three input flavours, chosen by `i % 3`, mixing a seed corpus with
    /// pure-random and charset-random bytes. The common driver for a fuzz loop.
    pub fn next(g: *Gen, buf: []u8, seeds: []const []const u8, charset: []const u8, i: usize) []u8 {
        return switch (i % 3) {
            0 => g.randomBytes(buf),
            1 => g.randomFromSet(buf, charset),
            else => g.mutate(buf, seeds[i % seeds.len], 5),
        };
    }
};
