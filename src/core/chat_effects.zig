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

//! B1 classification: CORE (pure). The EXPRESSIVE-MESSAGING vocabulary — the
//! iMessage-and-beyond effect taxonomy plus the phrase→effect auto-detector
//! (ZAT_CHAT_STANDALONE_ROADMAP §2). This module owns only the DECISION of which
//! effect a message carries; the LOOK (particles, the full-thread celebration
//! pass) is drawn by the effect/field layer and the shell, not here.
//!
//! A message can carry two independent effects: a BUBBLE effect (how the one
//! bubble arrives — slam / loud / gentle / invisible ink) and a SCREEN effect (a
//! full-thread celebration — balloons / confetti / lasers …). The chosen effect
//! ids ride WITH the message so the recipient sees exactly what the sender sent;
//! the sender picks them manually, OR `detectAuto` proposes one from the text
//! (the "Happy Birthday → balloons" behaviour).
//!
//! PURITY + PRIVACY (B2/B4, and the local-ephemeral principle the pet's reaction
//! set): `detectAuto` is a pure, LOCAL scan of the message body — same text ⇒ same
//! effect, no clock, no I/O. Nothing about the scan is stored or transmitted; only
//! the resulting effect id travels, and only because the sender is sending it.
//! Given the same inputs it is fully unit-testable headless (tests at the foot).

const std = @import("std");
const testing = std.testing;

/// How the single message bubble ARRIVES. Orthogonal to the screen effect — a
/// message can slam AND throw confetti. `none` is the ordinary send (the composer
/// morph). A7.2 does not apply (an enum is not a hot struct).
pub const BubbleEffect = enum(u8) {
    none,
    slam, // lands hard and shakes, oversized then settling
    loud, // arrives huge, booming
    gentle, // arrives tiny, whispered
    invisible, // "invisible ink": blurred until the reader swipes to reveal
};

/// A full-thread SCREEN effect — the celebration that takes over the conversation
/// for a beat. The set mirrors iMessage's and leaves room for our field-native
/// ones (the glyph field is a real medium — a laser can cut a wake through it, a
/// balloon can displace it; that "exceed" step is a later slice). Serialized as
/// this `u8` on the wire, so ordinals are STABLE — append, never reorder.
pub const ScreenEffect = enum(u8) {
    none = 0,
    balloons = 1,
    confetti = 2,
    fireworks = 3,
    hearts = 4, // "love"
    lasers = 5,
    celebration = 6,
    spotlight = 7,
    echo = 8,
    shooting_star = 9,
    _, // forward-compat: an unknown id from a newer peer degrades to "no effect"
};

/// A WIRE byte → an effect this build can actually play.
///
/// The effect id arrives from another device, so it is untrusted input like any
/// other: a newer peer may name an effect that did not exist when this build
/// shipped, and a hostile one may name something that never will. The enum is
/// non-exhaustive precisely so those values are representable, but a tag nothing
/// switches on must not reach the renderer — it degrades to `.none` here, once,
/// at the boundary.
///
/// Written exhaustively over the NAMED tags on purpose: adding an effect forces
/// a decision at this line rather than silently defaulting.
pub fn fromWire(b: u8) ScreenEffect {
    const fx: ScreenEffect = @enumFromInt(b);
    return switch (fx) {
        .none,
        .balloons,
        .confetti,
        .fireworks,
        .hearts,
        .lasers,
        .celebration,
        .spotlight,
        .echo,
        .shooting_star,
        => fx,
        _ => .none,
    };
}

/// A human label for an effect — for the send-effect picker UI (and tests). Pure.
pub fn screenName(fx: ScreenEffect) []const u8 {
    return switch (fx) {
        .none => "None",
        .balloons => "Balloons",
        .confetti => "Confetti",
        .fireworks => "Fireworks",
        .hearts => "Hearts",
        .lasers => "Lasers",
        .celebration => "Celebration",
        .spotlight => "Spotlight",
        .echo => "Echo",
        .shooting_star => "Shooting Star",
        _ => "None",
    };
}

/// A phrase that auto-proposes a screen effect. A7.2: cold config — a small
/// comptime table, read on send, never held in a hot loop; size guard waived.
const PhraseRule = struct { needle: []const u8, effect: ScreenEffect };

/// The auto-trigger table. `needle` is matched case-insensitively as a substring
/// of the message, so "Happy Birthday!!" and "happy birthday to you" both fire.
/// ORDER MATTERS: the first matching rule wins, so more specific phrases come
/// before the words they contain ("happy new year" before a bare "year" rule, if
/// one were ever added). Extend by adding a row — that is the whole cost.
const auto_rules = [_]PhraseRule{
    .{ .needle = "happy birthday", .effect = .balloons },
    .{ .needle = "happy new year", .effect = .fireworks },
    .{ .needle = "congratulations", .effect = .confetti },
    .{ .needle = "congrats", .effect = .confetti },
    .{ .needle = "pew pew", .effect = .lasers },
    .{ .needle = "i love you", .effect = .hearts },
};

/// ASCII lowercase fold of one byte (leaves non-letters, incl. UTF-8 bytes and
/// emoji, untouched). The auto phrases are ASCII, so an ASCII fold is exact for
/// them and never mangles the rest of the message.
fn lowerAscii(c: u8) u8 {
    return if (c >= 'A' and c <= 'Z') c + 32 else c;
}

/// Case-insensitive (ASCII-fold) substring test: is `needle` contained in `hay`?
/// Pure; O(len·needle) with no allocation — the messages are short and this runs
/// once per send. An empty needle never matches (it would match everything).
fn containsFold(hay: []const u8, needle: []const u8) bool {
    if (needle.len == 0 or needle.len > hay.len) return false;
    var i: usize = 0;
    while (i + needle.len <= hay.len) : (i += 1) {
        var j: usize = 0;
        while (j < needle.len) : (j += 1) {
            if (lowerAscii(hay[i + j]) != lowerAscii(needle[j])) break;
        } else return true; // the inner loop completed without a mismatch
    }
    return false;
}

/// Propose an auto SCREEN effect for an outgoing message body, or `.none` if no
/// phrase matches. PURE + LOCAL (see the module note): the sender may accept the
/// proposal, override it, or pick manually; whatever is chosen rides the message.
pub fn detectAuto(body: []const u8) ScreenEffect {
    for (auto_rules) |rule| {
        if (containsFold(body, rule.needle)) return rule.effect;
    }
    return .none;
}

// ---------------------------------------------------------------------------
// Golden tests (C6: leak-checked allocator; here purely value assertions).
// ---------------------------------------------------------------------------

test "detectAuto: the named phrases fire their effects, case-insensitively" {
    try testing.expectEqual(ScreenEffect.balloons, detectAuto("Happy Birthday!!"));
    try testing.expectEqual(ScreenEffect.balloons, detectAuto("happy birthday to you"));
    try testing.expectEqual(ScreenEffect.balloons, detectAuto("HAPPY BIRTHDAY"));
    try testing.expectEqual(ScreenEffect.confetti, detectAuto("Congratulations!"));
    try testing.expectEqual(ScreenEffect.confetti, detectAuto("congrats 🎉"));
    try testing.expectEqual(ScreenEffect.fireworks, detectAuto("Happy New Year everyone"));
    try testing.expectEqual(ScreenEffect.lasers, detectAuto("pew pew"));
    try testing.expectEqual(ScreenEffect.hearts, detectAuto("i love you"));
}

test "detectAuto: no false positives on unrelated or partial text" {
    try testing.expectEqual(ScreenEffect.none, detectAuto("just chatting"));
    try testing.expectEqual(ScreenEffect.none, detectAuto("")); // empty body
    // A bare word that is only PART of a trigger phrase must not fire.
    try testing.expectEqual(ScreenEffect.none, detectAuto("birthday"));
    try testing.expectEqual(ScreenEffect.none, detectAuto("new year"));
}

test "detectAuto: order — a more specific phrase wins where they could overlap" {
    // "happy new year" must fire fireworks even though it also contains "year";
    // and "happy birthday" balloons, not anything containing "happy".
    try testing.expectEqual(ScreenEffect.fireworks, detectAuto("wishing you a happy new year"));
    try testing.expectEqual(ScreenEffect.balloons, detectAuto("a very happy birthday"));
}

test "screen effect ordinals are stable (wire contract) and labels are total" {
    // These are the SERIALIZED values — append-only. If this fails, a reorder has
    // silently changed what a peer on the old ordinal will render.
    try testing.expectEqual(@as(u8, 0), @intFromEnum(ScreenEffect.none));
    try testing.expectEqual(@as(u8, 1), @intFromEnum(ScreenEffect.balloons));
    try testing.expectEqual(@as(u8, 2), @intFromEnum(ScreenEffect.confetti));
    try testing.expectEqual(@as(u8, 5), @intFromEnum(ScreenEffect.lasers));
    // An unknown id from a newer peer degrades gracefully.
    const future: ScreenEffect = @enumFromInt(200);
    try testing.expectEqualStrings("None", screenName(future));
    try testing.expectEqualStrings("Balloons", screenName(.balloons));
}

test "screen effects: a wire byte only becomes an effect this build can play" {
    // Every named id survives the boundary.
    try std.testing.expectEqual(ScreenEffect.balloons, fromWire(1));
    try std.testing.expectEqual(ScreenEffect.lasers, fromWire(5));
    try std.testing.expectEqual(ScreenEffect.shooting_star, fromWire(9));
    // An id from a newer peer, and a hostile one, both degrade to nothing
    // rather than reaching the renderer as a tag nothing switches on.
    try std.testing.expectEqual(ScreenEffect.none, fromWire(10));
    try std.testing.expectEqual(ScreenEffect.none, fromWire(200));
    try std.testing.expectEqual(ScreenEffect.none, fromWire(255));
}
