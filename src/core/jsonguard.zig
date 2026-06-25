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

//! B1 classification: CORE (pure). A pre-parse nesting-depth bound on hostile
//! JSON (SECURITY_ROADMAP Phase 2: "bound recursion / nesting depth").
//!
//! `std.json`'s `parseFromSlice*` builds a value by recursing once per nesting
//! level (`internalParse` is "called recursively"), so a deeply-nested payload
//! — `[[[[[...]]]]]` — is a crash from data alone: it blows the stack before any
//! field is ever inspected. The HTTP response cap (4 MiB) does not save us; a
//! few megabytes of `[` is millions of levels deep. The defence is to reject
//! over-deep input BEFORE handing it to the parser.
//!
//! Pure (B2): a single linear scan over the bytes, no allocation, no I/O. The
//! shell hands network bytes to a core parser; that parser calls this first.

const std = @import("std");

/// Maximum JSON nesting depth accepted from the network. atproto records and
/// DID documents are shallow (a reply or an embed is a handful of levels); 32
/// is far above any legitimate document while still a hard ceiling on the
/// parser's recursion.
pub const max_json_depth: usize = 32;

/// True iff the bracket nesting in `json` never exceeds `max`. A linear scan
/// that counts `{`/`[` depth, ignoring brackets that appear inside string
/// literals (honouring backslash escapes). It does NOT validate JSON — it only
/// bounds depth, cheaply, so the recursive parser that runs next cannot be
/// driven to a stack overflow.
pub fn depthWithinLimit(json: []const u8, max: usize) bool {
    var depth: usize = 0;
    var in_string = false;
    var escaped = false;
    for (json) |c| {
        if (in_string) {
            if (escaped) {
                escaped = false;
            } else switch (c) {
                '\\' => escaped = true,
                '"' => in_string = false,
                else => {},
            }
            continue;
        }
        switch (c) {
            '"' => in_string = true,
            '{', '[' => {
                depth += 1;
                if (depth > max) return false;
            },
            '}', ']' => if (depth > 0) {
                depth -= 1;
            },
            else => {},
        }
    }
    return true;
}

// ---------------------------------------------------------------------------
// Tests (C6)
// ---------------------------------------------------------------------------

const testing = std.testing;

test "depth: shallow documents pass, deeper-than-max is rejected" {
    try testing.expect(depthWithinLimit("{\"a\":[1,2,{\"b\":3}]}", 8));
    try testing.expect(depthWithinLimit("", 8));
    try testing.expect(depthWithinLimit("\"just a string\"", 8));

    // Exactly `max` passes; max+1 fails.
    try testing.expect(depthWithinLimit("[[[]]]", 3));
    try testing.expect(!depthWithinLimit("[[[[]]]]", 3));

    // A pathological run is rejected long before it could blow the parser stack.
    var buf: [4096]u8 = undefined;
    @memset(&buf, '[');
    try testing.expect(!depthWithinLimit(&buf, max_json_depth));
}

test "depth: brackets inside strings (incl. escaped quotes) do not count" {
    // The brackets here live inside a string value and must be ignored.
    try testing.expect(depthWithinLimit("{\"k\":\"[[[[[[[[[[\"}", 2));
    // An escaped quote must not end the string early, so its brackets stay inert.
    try testing.expect(depthWithinLimit("{\"k\":\"a\\\"[[[[[[\"}", 2));
}
