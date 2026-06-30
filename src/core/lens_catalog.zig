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

//! B1 classification: CORE (pure). The built-in Zat4 algorithm CATALOG and
//! the default per-surface loadouts. These are the first-party algorithms
//! the app ships with — named in the Fidelity "index fund" spirit (clear,
//! branded): "Following", "Zat4 Discover", "Zat4 Private Discover".
//!
//! This module is deliberately SEPARATE from `lens_socket.zig`: the socket
//! is the pure, content-free, portable widget; THIS is the Zat4-specific
//! content it renders. Marketplace algorithms are content-addressed records
//! (a later track) that resolve to the same `lens_socket.LensCard` shape;
//! a built-in's stable string `id` doubles as its `cid` until those records
//! exist, so the loadout (SOCKET_LOADOUT_AND_MARKETPLACE_DESIGN §10) can
//! reference built-ins today and upgrade the refs to strong refs later.
//!
//! Each algorithm carries an author-assigned DEFAULT color (the dev/Zat4
//! sets what it looks like when first loaded); the user is then free to
//! recolor it, and that override lives on the loadout entry (§11.5).
//!
//! The privacy glyph is derived from `flags.learns` here as a stand-in;
//! when the DISCOVER engine exists it becomes capability-PROVEN, never a
//! declared flag (DISCOVER invariant 6).

const std = @import("std");
const Allocator = std.mem.Allocator;
const lens_socket = @import("lens_socket.zig");
const discover = @import("discover.zig");

/// One first-party algorithm. A cold, comptime configuration table — low
/// cardinality, never iterated in a hot loop.
const Builtin = struct {
    // A7.2: cold catalog entry (a handful, comptime), size guard waived.
    id: []const u8, // stable id; doubles as the lens CID until algo records exist
    name: []const u8,
    ranks: []const u8, // one-line "what it ranks for"
    desc: []const u8, // the expand-panel paragraph
    color: u8, // author-assigned DEFAULT palette index (user may override)
    flags: lens_socket.LensFlags,
    /// The discover-engine algorithm this lens IS (DISCOVER D3): a built-in is
    /// just a named `FeedConfig`. `null` = the no-scoring chronological path
    /// (Following / Most Recent) — invariant 7's "nothing shaping you", which
    /// the multiplicative engine cannot express as a config (0 engagement ⇒ 0
    /// score), so it stays the plain feed-order/recency builder, not a config.
    config: ?discover.FeedConfig = null,
};

// The first-party algorithms, named once so the per-surface default loadouts
// below can compose them. Most Recent / Most Liked / Calm are the simplest
// configs in the one config space (SOCKET_LOADOUT §2), not a separate tier.
const b_discover = Builtin{
    .id = "zat4:discover",
    .name = "Zat4 Discover",
    .ranks = "engagement + topics",
    .desc = "The well-rounded default: a strong, Twitter-style feed that learns what you engage with — on your device, never sent anywhere.",
    .color = 0, // amber (house accent)
    .flags = .{ .learns = true, .is_default = true },
    .config = discover.DEFAULT_CONFIG, // the house algorithm = one config value (invariant 2)
};
const b_following = Builtin{
    .id = "zat4:following",
    .name = "Following",
    .ranks = "chronological",
    .desc = "Plain reverse-chronological of the accounts you follow. No scoring, no suggestions — nothing shaping you.",
    .color = 2, // grey (neutral = no shaping)
    .flags = .{ .is_default = true },
};
const b_private = Builtin{
    .id = "zat4:private-discover",
    .name = "Zat4 Private Discover",
    .ranks = "popularity + topics",
    .desc = "Surfaces strong posts beyond your follows, well-rounded — with ZERO behavioral data. Candidate-side only.",
    .color = 1, // blue (the calm/private tier)
    .flags = .{},
    // Bluesky-like, CANDIDATE-SIDE ONLY — the best feed achievable with ZERO
    // behavioral data. Every attention-derived weight is pinned to 0 (the
    // doorway also never hands it the signal — invariant 6), so it leans on the
    // public engagement graph the way Bluesky's Discover does: conversation
    // depth above all (replies weighted even harder than Discover — Bluesky's
    // "40 replies beat 200 likes"), amplification, a fresher recency window, and
    // network-proximity relevance computed from the PUBLIC follow graph. What it
    // gives up is the per-person "knows what you linger on" magic; what it keeps
    // is "what your network finds worth discussing." behavioral_weight 0 forever.
    .config = .{
        .w_like = 1.0,
        .w_repost = 2.0,
        .w_reply = 40.0, // conversation is the private feed's strength — lean in
        .w_reply_chain = 150.0,
        .w_bookmark = 0.0, // private data, never captured
        .w_profile_click = 0.0, // BEHAVIORAL — the wall
        .w_link_click = 0.0, // BEHAVIORAL — the wall
        .w_negative = -148.0, // block/mute/report are DELIBERATE public actions — allowed
        .recency_half_life_hrs = 4.0, // fresher / more "now"
        .author_rep_weight = 0.5, // from the public graph
        .relevance_weight = 1.0, // network proximity, from the PUBLIC follow graph
        .behavioral_weight = 0.0, // never — and never even handed the signal
    },
};
const b_most_recent = Builtin{
    .id = "zat4:most-recent",
    .name = "Most Recent",
    .ranks = "newest first",
    .desc = "Chronological — the latest replies first. No scoring, no behavioral data.",
    .color = 2, // grey
    .flags = .{ .is_default = true },
};
const b_most_liked = Builtin{
    .id = "zat4:most-liked",
    .name = "Most Liked",
    .ranks = "by likes",
    .desc = "The most-liked replies first. A simple popularity sort; no behavioral data.",
    .color = 5, // rose
    .flags = .{},
    // Pure popularity: likes only, decay + velocity + boosts off.
    .config = .{
        .w_repost = 0,
        .w_reply = 0,
        .w_reply_chain = 0,
        .w_bookmark = 0,
        .w_profile_click = 0,
        .w_link_click = 0,
        .recency_half_life_hrs = 0, // no decay
        .velocity_boost = false,
        .author_rep_weight = 0,
        .relevance_weight = 0,
    },
};
const b_calm = Builtin{
    .id = "zat4:calm",
    .name = "Calm",
    .ranks = "low-velocity first",
    .desc = "Down-ranks pile-ons and high-velocity threads. Candidate-side only; no behavioral data.",
    .color = 7, // teal
    .flags = .{},
    // Calmer than Discover: no early-velocity spike, slower freshness decay,
    // conversation weighted lower so pile-ons don't dominate.
    .config = .{
        .velocity_boost = false,
        .recency_half_life_hrs = 24.0,
        .w_reply = 5.0,
        .w_reply_chain = 20.0,
    },
};

/// Every distinct built-in — what `findById` resolves a persisted ref against.
const all_builtins = [_]Builtin{ b_discover, b_following, b_private, b_most_recent, b_most_liked, b_calm };

/// The default FEED loadout (onboarding-equipped, editable after): the
/// adaptive Zat4 Discover (seated), honest Following, and the zero-behavioral
/// Zat4 Private Discover.
pub const feed_builtins = [_]Builtin{ b_discover, b_following, b_private };
pub const default_feed_seated: u32 = 0;

/// Default REPLY loadout: Most Recent (seated) + Most Liked. Threading
/// (structure) is a SEPARATE adjacent control, never a tray lens (invariants
/// 13/14), so it is not in this list.
pub const reply_builtins = [_]Builtin{ b_most_recent, b_most_liked };
pub const default_reply_seated: u32 = 0;

/// Default ZONE loadout: Zat4 Discover (seated) + Calm.
pub const zone_builtins = [_]Builtin{ b_discover, b_calm };
pub const default_zone_seated: u32 = 0;

/// Build a `TrayView` (mutable cards + the text blob their spans point into)
/// from a built-in catalog slice, into `gpa` (caller owns and frees both).
/// Pure: same catalog ⇒ same data. Each card's CID is the built-in's stable
/// id; its color starts at the author default (the user may recolor later).
pub fn loadoutFrom(gpa: Allocator, builtins: []const Builtin) !struct { []lens_socket.LensCard, []const u8 } {
    var blob: std.ArrayListUnmanaged(u8) = .empty;
    errdefer blob.deinit(gpa);
    const cards = try gpa.alloc(lens_socket.LensCard, builtins.len);
    errdefer gpa.free(cards);
    for (builtins, 0..) |b, i| {
        const name: lens_socket.TextSpan = .{ .off = @intCast(blob.items.len), .len = @intCast(b.name.len) };
        try blob.appendSlice(gpa, b.name);
        const ranks: lens_socket.TextSpan = .{ .off = @intCast(blob.items.len), .len = @intCast(b.ranks.len) };
        try blob.appendSlice(gpa, b.ranks);
        const desc: lens_socket.TextSpan = .{ .off = @intCast(blob.items.len), .len = @intCast(b.desc.len) };
        try blob.appendSlice(gpa, b.desc);
        const author: lens_socket.TextSpan = .{ .off = @intCast(blob.items.len), .len = @intCast("zat4 default".len) };
        try blob.appendSlice(gpa, "zat4 default");
        const cid: lens_socket.TextSpan = .{ .off = @intCast(blob.items.len), .len = @intCast(b.id.len) };
        try blob.appendSlice(gpa, b.id);
        cards[i] = .{ .cid = cid, .name = name, .author = author, .ranks = ranks, .desc = desc, .color = b.color, .flags = b.flags };
    }
    return .{ cards, try blob.toOwnedSlice(gpa) };
}

/// The default per-surface loadouts (the first-party lenses for each).
pub fn defaultFeedLoadout(gpa: Allocator) !struct { []lens_socket.LensCard, []const u8 } {
    return loadoutFrom(gpa, &feed_builtins);
}
pub fn defaultReplyLoadout(gpa: Allocator) !struct { []lens_socket.LensCard, []const u8 } {
    return loadoutFrom(gpa, &reply_builtins);
}
pub fn defaultZoneLoadout(gpa: Allocator) !struct { []lens_socket.LensCard, []const u8 } {
    return loadoutFrom(gpa, &zone_builtins);
}

/// The built-in catalog entry for a stable id (e.g. "zat4:discover"), or null.
pub fn findById(id: []const u8) ?Builtin {
    for (all_builtins) |b| {
        if (std.mem.eql(u8, b.id, id)) return b;
    }
    return null;
}

/// The discover-engine `FeedConfig` a lens id resolves to, or null when the
/// lens is the NO-SCORING chronological path (Following / Most Recent) or the
/// id is unknown (E4). The caller scores with the config when present, and
/// falls back to the plain feed-order/recency builder when null — so "Following"
/// genuinely means nothing is shaping the order. A marketplace algo (a future
/// CID-addressed config record, D5) resolves here too once those records exist;
/// today only the built-ins do.
pub fn scoringConfigForId(id: []const u8) ?discover.FeedConfig {
    const b = findById(id) orelse return null;
    return b.config;
}

test "scoringConfigForId: Discover scores, Following is the no-scoring path" {
    const t = std.testing;
    try t.expect(scoringConfigForId("zat4:discover") != null);
    try t.expect(scoringConfigForId("zat4:following") == null); // chronological, no config
    try t.expect(scoringConfigForId("zat4:unknown-marketplace-algo") == null);
    // Most Liked is a real config: likes weighted, recency decay disabled.
    const ml = scoringConfigForId("zat4:most-liked").?;
    try t.expectEqual(@as(f32, 0), ml.recency_half_life_hrs);
    try t.expectEqual(@as(f32, 1.0), ml.w_like);
}

/// A persisted loadout entry, resolved from the user's record (§10): which
/// algorithm + the user's color override.
// A7.2: cold transient (one per persisted lens at load), size guard waived.
pub const Entry = struct { id: []const u8, color: u8 };

/// Build a `TrayView`'s cards + blob from PERSISTED entries (the user's saved
/// order, with their color overrides). Each entry's id is resolved against the
/// catalog for the lens's text + flags; the entry's color wins (the override).
/// Unknown ids (e.g. a marketplace algo not yet modelled) are skipped — an
/// ordinary result, not an error (E4). Pure; caller owns/frees both slices.
pub fn loadoutFromEntries(gpa: Allocator, entries: []const Entry) !struct { []lens_socket.LensCard, []const u8 } {
    var blob: std.ArrayListUnmanaged(u8) = .empty;
    errdefer blob.deinit(gpa);
    var cards: std.ArrayListUnmanaged(lens_socket.LensCard) = .empty;
    errdefer cards.deinit(gpa);
    for (entries) |entry| {
        const b = findById(entry.id) orelse continue;
        const name: lens_socket.TextSpan = .{ .off = @intCast(blob.items.len), .len = @intCast(b.name.len) };
        try blob.appendSlice(gpa, b.name);
        const ranks: lens_socket.TextSpan = .{ .off = @intCast(blob.items.len), .len = @intCast(b.ranks.len) };
        try blob.appendSlice(gpa, b.ranks);
        const desc: lens_socket.TextSpan = .{ .off = @intCast(blob.items.len), .len = @intCast(b.desc.len) };
        try blob.appendSlice(gpa, b.desc);
        const author: lens_socket.TextSpan = .{ .off = @intCast(blob.items.len), .len = @intCast("zat4 default".len) };
        try blob.appendSlice(gpa, "zat4 default");
        const cid: lens_socket.TextSpan = .{ .off = @intCast(blob.items.len), .len = @intCast(b.id.len) };
        try blob.appendSlice(gpa, b.id);
        try cards.append(gpa, .{ .cid = cid, .name = name, .author = author, .ranks = ranks, .desc = desc, .color = entry.color, .flags = b.flags });
    }
    return .{ try cards.toOwnedSlice(gpa), try blob.toOwnedSlice(gpa) };
}

test "loadoutFromEntries: resolves built-ins, applies the user's color override, skips unknowns" {
    const t = std.testing;
    const entries = [_]Entry{
        .{ .id = "zat4:following", .color = 5 }, // user recolored Following to rose
        .{ .id = "zat4:marketplace-not-yet", .color = 3 }, // unknown → skipped
        .{ .id = "zat4:discover", .color = 0 },
    };
    const cards, const blob = try loadoutFromEntries(t.allocator, &entries);
    defer t.allocator.free(cards);
    defer t.allocator.free(blob);
    try t.expectEqual(@as(usize, 2), cards.len); // the unknown was skipped
    try t.expectEqualStrings("Following", blob[cards[0].name.off..][0..cards[0].name.len]);
    try t.expectEqual(@as(u8, 5), cards[0].color); // override applied, not the grey default
    try t.expectEqualStrings("zat4:discover", blob[cards[1].cid.off..][0..cards[1].cid.len]);
}

test "default feed loadout: three named lenses, seated id resolves, colors are the author defaults" {
    const t = std.testing;
    const cards, const blob = try defaultFeedLoadout(t.allocator);
    defer t.allocator.free(cards);
    defer t.allocator.free(blob);
    try t.expectEqual(@as(usize, 3), cards.len);
    // The seated default is Zat4 Discover, amber, learns-on-device.
    const seat = cards[default_feed_seated];
    try t.expectEqualStrings("Zat4 Discover", blob[seat.name.off..][0..seat.name.len]);
    try t.expectEqualStrings("zat4:discover", blob[seat.cid.off..][0..seat.cid.len]);
    try t.expectEqual(@as(u8, 0), seat.color);
    try t.expect(seat.flags.learns);
    // Following is grey + not learning (nothing shaping you).
    try t.expectEqualStrings("Following", blob[cards[1].name.off..][0..cards[1].name.len]);
    try t.expectEqual(@as(u8, 2), cards[1].color);
    try t.expect(!cards[1].flags.learns);
    // Private Discover is blue + no behavioral data.
    try t.expectEqual(@as(u8, 1), cards[2].color);
    try t.expect(!cards[2].flags.learns);
}
