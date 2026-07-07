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

//! B1 classification: CORE (pure). The **write deep module's** pure half.
//!
//! The write module spans two files: this one — rich-text facet detection,
//! a single left-to-right scan that turns composed text into byte-range
//! annotations (the roadmap's "clean DOD structure": spans over bytes,
//! exactly like the feed's TextSpans) — and src/shell/write.zig, which
//! resolves mentions over the network and submits records.
//!
//! Detection is deliberately conservative: a span that does not validate
//! is simply not a facet — the text still posts, just unlinked (E4:
//! "not a mention" is an ordinary result, not an error).

const std = @import("std");
const Allocator = std.mem.Allocator;
const identity = @import("identity.zig");

pub const SpanKind = enum { mention, link, tag };

/// One detected span: UTF-8 byte offsets into the composed text, the
/// currency the wire's `byteSlice` wants verbatim.
/// A7.2: cold struct, size guard waived — a handful exist per composed
/// post, transient in the request arena.
pub const FacetSpan = struct {
    kind: SpanKind,
    byte_start: u32,
    byte_end: u32,
};

/// Scan text for mention, link and tag spans, in order, non-overlapping.
/// Mentions include the leading '@' in their range (the wire convention);
/// the handle inside must validate. Links are http(s) runs with trailing
/// punctuation trimmed. Tags include the leading '#'; the run of tag bytes
/// after it must be non-empty (a bare '#' stays prose).
pub fn detectFacetSpans(arena: Allocator, text: []const u8) error{OutOfMemory}![]FacetSpan {
    var spans: std.ArrayList(FacetSpan) = .empty;
    var i: usize = 0;
    while (i < text.len) {
        if (text[i] == '@' and atWordStart(text, i)) {
            const start = i;
            var end = i + 1;
            while (end < text.len and isHandleByte(text[end])) end += 1;
            // Trailing sentence punctuation is prose, not handle.
            while (end > start + 1 and (text[end - 1] == '.' or text[end - 1] == '-')) end -= 1;
            const handle = text[start + 1 .. end];
            if (identity.validateHandle(handle)) {
                try spans.append(arena, .{
                    .kind = .mention,
                    .byte_start = @intCast(start),
                    .byte_end = @intCast(end),
                });
                i = end;
                continue;
            } else |_| {
                // Not a valid handle — it stays prose (E4).
            }
        } else if (atWordStart(text, i) and startsLink(text[i..])) {
            const start = i;
            var end = i;
            while (end < text.len and text[end] != ' ' and text[end] != '\n' and text[end] != '\t') end += 1;
            while (end > start and std.mem.indexOfScalar(u8, ".,;:!?)\"'", text[end - 1]) != null) end -= 1;
            if (end > start + 8) { // longer than the bare scheme
                try spans.append(arena, .{
                    .kind = .link,
                    .byte_start = @intCast(start),
                    .byte_end = @intCast(end),
                });
                i = end;
                continue;
            }
        } else if (text[i] == '#' and atWordStart(text, i)) {
            const start = i;
            var end = i + 1;
            while (end < text.len and isTagByte(text[end])) end += 1;
            // Tag bytes never include sentence punctuation, so the run stops
            // itself — no trailing trim needed. A bare '#' is just prose.
            if (end > start + 1) {
                try spans.append(arena, .{
                    .kind = .tag,
                    .byte_start = @intCast(start),
                    .byte_end = @intCast(end),
                });
                i = end;
                continue;
            }
        }
        i += 1;
    }
    return spans.toOwnedSlice(arena);
}

fn atWordStart(text: []const u8, i: usize) bool {
    if (i == 0) return true;
    const prev = text[i - 1];
    return prev == ' ' or prev == '\n' or prev == '\t' or prev == '(';
}

fn isHandleByte(b: u8) bool {
    return std.ascii.isAlphanumeric(b) or b == '.' or b == '-';
}

fn startsLink(rest: []const u8) bool {
    return std.mem.startsWith(u8, rest, "https://") or std.mem.startsWith(u8, rest, "http://");
}

/// Valid inside a `#tag` run: ASCII alphanumerics and underscore. Conservative
/// on purpose — punctuation ends the tag, so trimming is unnecessary. (Unicode
/// tag bytes can broaden this later; the wire is ready for it.)
fn isTagByte(b: u8) bool {
    return std.ascii.isAlphanumeric(b) or b == '_';
}

/// If a `#tag` begins exactly at byte `i` — a word-start '#' followed by at least
/// one tag byte — return the exclusive end index (past the last tag byte); else
/// null. The single pure rule shared by the composer's facet detection (what gets
/// WRITTEN as a tag facet) and the renderer's inline highlighting (what gets lit
/// blue + made tappable), so the two can never diverge.
pub fn tagSpanAt(text: []const u8, i: usize) ?usize {
    if (i >= text.len or text[i] != '#' or !atWordStart(text, i)) return null;
    var end = i + 1;
    while (end < text.len and isTagByte(text[end])) end += 1;
    return if (end > i + 1) end else null;
}

/// The draft's INLINE #tags, in order of first appearance, '#'-stripped and
/// deduped case-insensitively — the composer tag bar's live source, cut by
/// the SAME spans `resolveFacets` writes so the bar and the record can't
/// disagree. Slices point INTO `text`; the list rides `arena`. PURE.
pub fn inlineTags(arena: Allocator, text: []const u8) error{OutOfMemory}![]const []const u8 {
    const spans = try detectFacetSpans(arena, text);
    var out: std.ArrayList([]const u8) = .empty;
    for (spans) |s| {
        if (s.kind != .tag) continue;
        const word = text[s.byte_start + 1 .. s.byte_end]; // past the '#'
        if (word.len == 0) continue;
        var seen = false;
        for (out.items) |t| {
            if (std.ascii.eqlIgnoreCase(t, word)) {
                seen = true;
                break;
            }
        }
        if (!seen) try out.append(arena, word);
    }
    return out.toOwnedSlice(arena);
}

// ---------------------------------------------------------------------------
// Tests (B2, C6) — byte offsets asserted exactly, including past multibyte
// text, because the wire takes these numbers verbatim
// ---------------------------------------------------------------------------

const testing = std.testing;

test "facets: mention and link spans with exact byte offsets" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const text = "hi @alice.test see https://example.com/x.";
    const spans = try detectFacetSpans(arena, text);
    try testing.expectEqual(@as(usize, 2), spans.len);

    try testing.expectEqual(SpanKind.mention, spans[0].kind);
    try testing.expectEqualStrings("@alice.test", text[spans[0].byte_start..spans[0].byte_end]);

    try testing.expectEqual(SpanKind.link, spans[1].kind);
    // The sentence-final '.' is prose, not URL.
    try testing.expectEqualStrings("https://example.com/x", text[spans[1].byte_start..spans[1].byte_end]);
}

test "facets: offsets are UTF-8 bytes, counted past multibyte text" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    const text = "héllo @bob.test"; // é is two bytes: '@' sits at byte 7
    const spans = try detectFacetSpans(arena_state.allocator(), text);
    try testing.expectEqual(@as(usize, 1), spans.len);
    try testing.expectEqual(@as(u32, 7), spans[0].byte_start);
    try testing.expectEqualStrings("@bob.test", text[spans[0].byte_start..spans[0].byte_end]);
}

test "facets: non-facets stay prose — mid-word @, bad handles, bare schemes" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectEqual(@as(usize, 0), (try detectFacetSpans(arena, "mail me a@b")).len);
    try testing.expectEqual(@as(usize, 0), (try detectFacetSpans(arena, "name@nodots")).len);
    try testing.expectEqual(@as(usize, 0), (try detectFacetSpans(arena, "see https:// nothing")).len);
    try testing.expectEqual(@as(usize, 0), (try detectFacetSpans(arena, "plain text only")).len);
}

test "facets: parenthesized mention, trailing punctuation trimmed from handle" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    const text = "(@alice.test).";
    const spans = try detectFacetSpans(arena_state.allocator(), text);
    try testing.expectEqual(@as(usize, 1), spans.len);
    try testing.expectEqualStrings("@alice.test", text[spans[0].byte_start..spans[0].byte_end]);
}

test "facets: tag spans include the '#', stop at punctuation, exact byte offsets" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const text = "love #water and #nba4real!";
    const spans = try detectFacetSpans(arena, text);
    try testing.expectEqual(@as(usize, 2), spans.len);

    try testing.expectEqual(SpanKind.tag, spans[0].kind);
    try testing.expectEqualStrings("#water", text[spans[0].byte_start..spans[0].byte_end]);

    try testing.expectEqual(SpanKind.tag, spans[1].kind);
    // The trailing '!' is prose, not part of the tag.
    try testing.expectEqualStrings("#nba4real", text[spans[1].byte_start..spans[1].byte_end]);
}

test "facets: tag offsets are UTF-8 bytes, counted past multibyte text" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();

    const text = "héllo #zat4"; // é is two bytes: '#' sits at byte 7
    const spans = try detectFacetSpans(arena_state.allocator(), text);
    try testing.expectEqual(@as(usize, 1), spans.len);
    try testing.expectEqual(SpanKind.tag, spans[0].kind);
    try testing.expectEqual(@as(u32, 7), spans[0].byte_start);
    try testing.expectEqualStrings("#zat4", text[spans[0].byte_start..spans[0].byte_end]);
}

test "facets: non-tags stay prose — mid-word #, bare '#', '#' before punctuation" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Mid-word '#' (e.g. a language name) is not a word-start tag.
    try testing.expectEqual(@as(usize, 0), (try detectFacetSpans(arena, "wrote some C# today")).len);
    // A bare '#' with no tag bytes is prose.
    try testing.expectEqual(@as(usize, 0), (try detectFacetSpans(arena, "the # symbol")).len);
    try testing.expectEqual(@as(usize, 0), (try detectFacetSpans(arena, "ends here #")).len);
    try testing.expectEqual(@as(usize, 0), (try detectFacetSpans(arena, "#! shebang-ish")).len);
}

test "facets: a tag, a mention and a link coexist in one post" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const text = "@alice.test re #zig see https://ziglang.org";
    const spans = try detectFacetSpans(arena, text);
    try testing.expectEqual(@as(usize, 3), spans.len);
    try testing.expectEqual(SpanKind.mention, spans[0].kind);
    try testing.expectEqual(SpanKind.tag, spans[1].kind);
    try testing.expectEqualStrings("#zig", text[spans[1].byte_start..spans[1].byte_end]);
    try testing.expectEqual(SpanKind.link, spans[2].kind);
}

test "inlineTags: order of first appearance, '#'-stripped, case-insensitive dedup" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const tags = try inlineTags(arena, "on #water and #Zig — more #WATER, mid#word stays prose");
    try testing.expectEqual(@as(usize, 2), tags.len);
    try testing.expectEqualStrings("water", tags[0]); // #WATER folded into the first sighting
    try testing.expectEqualStrings("Zig", tags[1]); // display casing preserved
    try testing.expectEqual(@as(usize, 0), (try inlineTags(arena, "no tags here")).len);
}
