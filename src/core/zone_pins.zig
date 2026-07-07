//! Zone PINS — the viewer's kept zones ("pin the ones you return to").
//!
//! Plain data + free functions (A1): a flat list of canonical-lowercase tag
//! names the viewer pinned, owned by the caller's allocator. PURE (B1/B2) —
//! no I/O; the shell persists the serialized form in the client cache and
//! hands the bytes back at startup. Tags are stored normalized (lowercase,
//! no leading '#') so `has`/`toggle` match the zone key invariant (ZONES
//! inv. 1: one casing, one zone). A pinned tag the catalog no longer lists
//! is kept — pins are the user's, not the index's (E4: absence is ordinary).

const std = @import("std");
const Allocator = std.mem.Allocator;

/// The pin set. A7.2: cold struct, size guard waived — one per session,
/// a handful of entries, never in a hot loop.
pub const Pins = struct {
    /// Canonical-lowercase tag names, first-pinned order. Each slice is
    /// owned by the allocator handed to `toggle`/`deserialize` (C4).
    tags: std.ArrayList([]const u8) = .empty,
};

pub fn deinit(gpa: Allocator, p: *Pins) void {
    for (p.tags.items) |t| gpa.free(t);
    p.tags.deinit(gpa);
}

/// Normalize a raw tag into `buf` for pin matching: trim, strip one leading
/// '#', ASCII-lowercase. Null when empty or too long (E4).
fn normalize(raw: []const u8, buf: []u8) ?[]const u8 {
    var trimmed = std.mem.trim(u8, raw, " \t\r\n");
    if (trimmed.len > 0 and trimmed[0] == '#') trimmed = trimmed[1..];
    if (trimmed.len == 0 or trimmed.len > buf.len) return null;
    for (trimmed, 0..) |c, i| buf[i] = std.ascii.toLower(c);
    return buf[0..trimmed.len];
}

/// Whether `tag` (any casing, '#' optional) is pinned.
pub fn has(p: *const Pins, tag: []const u8) bool {
    var buf: [128]u8 = undefined;
    const norm = normalize(tag, &buf) orelse return false;
    for (p.tags.items) |t| if (std.mem.eql(u8, t, norm)) return true;
    return false;
}

/// Pin an unpinned tag / unpin a pinned one. Returns the NEW state (true =
/// now pinned), or null when the tag is empty/oversized (E4, not an error).
pub fn toggle(gpa: Allocator, p: *Pins, tag: []const u8) Allocator.Error!?bool {
    var buf: [128]u8 = undefined;
    const norm = normalize(tag, &buf) orelse return null;
    for (p.tags.items, 0..) |t, i| {
        if (std.mem.eql(u8, t, norm)) {
            gpa.free(t);
            _ = p.tags.orderedRemove(i); // keep first-pinned order stable
            return false;
        }
    }
    const dup = try gpa.dupe(u8, norm);
    errdefer gpa.free(dup);
    try p.tags.append(gpa, dup);
    return true;
}

/// One tag per line — the cache-file form. Deterministic (same pins ⇒ same
/// bytes); allocated with `gpa`, caller frees.
pub fn serialize(gpa: Allocator, p: *const Pins) Allocator.Error![]u8 {
    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    for (p.tags.items) |t| {
        try out.appendSlice(gpa, t);
        try out.append(gpa, '\n');
    }
    return out.toOwnedSlice(gpa);
}

/// Parse the cache-file form. Unparseable lines are skipped, never fatal
/// (E4) — a damaged cache degrades to fewer pins, not a dead screen.
pub fn deserialize(gpa: Allocator, bytes: []const u8) Allocator.Error!Pins {
    var p: Pins = .{};
    errdefer deinit(gpa, &p);
    var it = std.mem.splitScalar(u8, bytes, '\n');
    while (it.next()) |line| {
        var buf: [128]u8 = undefined;
        const norm = normalize(line, &buf) orelse continue;
        if (hasExact(&p, norm)) continue; // dedup a hand-edited file
        const dup = try gpa.dupe(u8, norm);
        errdefer gpa.free(dup);
        try p.tags.append(gpa, dup);
    }
    return p;
}

fn hasExact(p: *const Pins, norm: []const u8) bool {
    for (p.tags.items) |t| if (std.mem.eql(u8, t, norm)) return true;
    return false;
}

// ---------------------------------------------------------------------------
// Tests (C6)
// ---------------------------------------------------------------------------

const testing = std.testing;

test "pins: toggle pins then unpins; has matches any casing and a leading '#'" {
    const gpa = testing.allocator;
    var p: Pins = .{};
    defer deinit(gpa, &p);

    try testing.expectEqual(@as(?bool, true), try toggle(gpa, &p, "Water"));
    try testing.expect(has(&p, "water"));
    try testing.expect(has(&p, "#WATER")); // casing + '#' both fold away
    try testing.expect(!has(&p, "rivers"));

    try testing.expectEqual(@as(?bool, false), try toggle(gpa, &p, "#water"));
    try testing.expect(!has(&p, "water"));
    try testing.expectEqual(@as(usize, 0), p.tags.items.len);

    // Empty input is refused as an ordinary null, not an error (E4).
    try testing.expectEqual(@as(?bool, null), try toggle(gpa, &p, "  "));
}

test "pins: serialize/deserialize round-trips, dedups, and skips junk lines" {
    const gpa = testing.allocator;
    var p: Pins = .{};
    defer deinit(gpa, &p);
    _ = try toggle(gpa, &p, "water");
    _ = try toggle(gpa, &p, "zig");

    const bytes = try serialize(gpa, &p);
    defer gpa.free(bytes);
    try testing.expectEqualStrings("water\nzig\n", bytes);

    var q = try deserialize(gpa, "water\nzig\n\nWATER\n");
    defer deinit(gpa, &q);
    try testing.expectEqual(@as(usize, 2), q.tags.items.len); // blank + dup dropped
    try testing.expect(has(&q, "water"));
    try testing.expect(has(&q, "zig"));
}
