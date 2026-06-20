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

//! B1 classification: CORE (pure). The **moderation deep module** (D1 —
//! one of the four sealed decisions, split out during Phase 4 and landing
//! here, before a visible timeline ships).
//!
//! Interface, in full: `LabelFlags`, `Verdict`, `flagsFromLabels`,
//! `verdictFor`, `reasonFor`. The label vocabulary, the wire-string
//! mapping, and the policy hide in this file. The feed stores `LabelFlags`
//! as plain data (it knows nothing of what the bits mean); the renderer
//! obeys a `Verdict` (it knows nothing of labels). When labeler logic
//! changes — subscriptions, per-user preferences, new vocabularies — the
//! blast radius is this module.
//!
//! v1 policy is deliberately conservative: anything flagged is hidden
//! behind a one-line notice. Per-label preferences and a reveal toggle are
//! the recorded next step (roadmap, Phase 5 remainder).

const std = @import("std");
const assert = std.debug.assert;
const lexicon = @import("lexicon.zig");

/// Out-of-band flags (A6 made structural: the post record carries these
/// 16 bits, never bool fields). One bit per label category this client
/// recognizes; `other` catches any label outside the vocabulary so an
/// unknown labeler still gets a conservative verdict (E4: unknown is an
/// ordinary state, handled as data).
pub const LabelFlags = packed struct(u16) {
    porn: bool = false,
    sexual: bool = false,
    nudity: bool = false,
    graphic_media: bool = false,
    spam: bool = false,
    system_hide: bool = false, // "!hide" — moderation authority says remove
    system_warn: bool = false, // "!warn"
    other: bool = false,
    _reserved: u8 = 0,

    pub const none: LabelFlags = .{};

    comptime {
        // Budget 2: sixteen bits, packed exactly; rides inside the
        // 64-byte Post budget without raising it. (A7)
        assert(@sizeOf(LabelFlags) == 2);
    }
};

/// What the renderer is told to do. The policy produces this; nothing
/// downstream sees a label string.
pub const Verdict = enum { show, hide };

/// Map wire label values onto flags. Pure, total: unknown values set
/// `other` rather than being dropped on the floor.
pub fn flagsFromLabels(labels: []const lexicon.Label) LabelFlags {
    var flags: LabelFlags = .{};
    for (labels) |label| {
        if (std.mem.eql(u8, label.val, "porn")) {
            flags.porn = true;
        } else if (std.mem.eql(u8, label.val, "sexual")) {
            flags.sexual = true;
        } else if (std.mem.eql(u8, label.val, "nudity")) {
            flags.nudity = true;
        } else if (std.mem.eql(u8, label.val, "graphic-media") or std.mem.eql(u8, label.val, "gore")) {
            flags.graphic_media = true;
        } else if (std.mem.eql(u8, label.val, "spam")) {
            flags.spam = true;
        } else if (std.mem.eql(u8, label.val, "!hide")) {
            flags.system_hide = true;
        } else if (std.mem.eql(u8, label.val, "!warn")) {
            flags.system_warn = true;
        } else if (label.val.len > 0) {
            flags.other = true;
        }
    }
    return flags;
}

/// The v1 policy: any recognized flag (or any unknown label) hides the
/// post behind a notice.
pub fn verdictFor(flags: LabelFlags) Verdict {
    return if (@as(u16, @bitCast(flags)) == 0) .show else .hide;
}

/// A static, human-readable reason for a hidden post (first matching
/// category wins). "" when nothing is flagged.
pub fn reasonFor(flags: LabelFlags) []const u8 {
    if (flags.system_hide) return "removed by moderation";
    if (flags.porn or flags.sexual or flags.nudity) return "adult content";
    if (flags.graphic_media) return "graphic content";
    if (flags.spam) return "likely spam";
    if (flags.system_warn) return "content warning";
    if (flags.other) return "labeled content";
    return "";
}

// ---------------------------------------------------------------------------
// Tests (B2: pure policy, exercised entirely offline; C6 throughout)
// ---------------------------------------------------------------------------

const testing = std.testing;

test "label mapping: known vocabulary, aliases, and the unknown catch-all" {
    const flags = flagsFromLabels(&.{
        .{ .val = "porn" },
        .{ .val = "gore" },
        .{ .val = "from-some-new-labeler" },
    });
    try testing.expect(flags.porn);
    try testing.expect(flags.graphic_media);
    try testing.expect(flags.other);
    try testing.expect(!flags.spam);
}

test "policy: clean posts show; anything flagged hides, with a reason" {
    try testing.expectEqual(Verdict.show, verdictFor(.none));
    try testing.expectEqualStrings("", reasonFor(.none));

    const adult = flagsFromLabels(&.{.{ .val = "sexual" }});
    try testing.expectEqual(Verdict.hide, verdictFor(adult));
    try testing.expectEqualStrings("adult content", reasonFor(adult));

    const removed = flagsFromLabels(&.{ .{ .val = "spam" }, .{ .val = "!hide" } });
    try testing.expectEqualStrings("removed by moderation", reasonFor(removed));
}
