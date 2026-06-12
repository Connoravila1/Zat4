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

pub const SpanKind = enum { mention, link };

/// One detected span: UTF-8 byte offsets into the composed text, the
/// currency the wire's `byteSlice` wants verbatim.
/// A7.2: cold struct, size guard waived — a handful exist per composed
/// post, transient in the request arena.
pub const FacetSpan = struct {
    kind: SpanKind,
    byte_start: u32,
    byte_end: u32,
};

/// Scan text for mention and link spans, in order, non-overlapping.
/// Mentions include the leading '@' in their range (the wire convention);
/// the handle inside must validate. Links are http(s) runs with trailing
/// punctuation trimmed.
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
