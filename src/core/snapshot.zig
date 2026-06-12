//! B1 classification: CORE (pure). The sealed **snapshot module** — the
//! cache-strategy decision (D1) in one place: how the feed store becomes
//! bytes and comes back. Nothing else in the tree knows this layout; the
//! shell hands `decode` a byte slice it read from somewhere and hands
//! `encode`'s result to somewhere — disk is the shell's business (B3).
//!
//! Format v1, recorded:
//! - Native-endian, native-layout: this is a LOCAL cache, written and read
//!   by the same build on the same machine. A version bump is the upgrade
//!   path; a mismatch is a cold start, never a migration.
//! - Every field is written and read EXPLICITLY, by name, in a fixed
//!   order — the format is sealed against struct-declaration reshuffles.
//! - Decode trusts nothing (E4 at the boundary): magic, version, every
//!   length, every span, every index is validated; any lie is
//!   `error.InvalidSnapshot` and the caller starts cold.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const feed = @import("feed.zig");

pub const magic = [4]u8{ 'Z', 'A', 'T', 'C' };
pub const version: u16 = 1;

/// A7.2: cold struct, size guard waived — one per encode/decode.
const Header = struct {
    string_len: u64,
    authors_len: u32,
    posts_len: u32,
    feed_len: u32,
    cursor: feed.TextSpan,
};

pub const DecodeError = error{ OutOfMemory, InvalidSnapshot };

// ---------------------------------------------------------------------------
// Encode
// ---------------------------------------------------------------------------

pub fn encode(arena: Allocator, store: *const feed.Store) error{OutOfMemory}![]u8 {
    var out: std.ArrayList(u8) = .empty;

    try out.appendSlice(arena, &magic);
    try appendInt(arena, &out, u16, version);
    try appendInt(arena, &out, u16, 0); // reserved
    try appendInt(arena, &out, u64, store.string_bytes.items.len);
    try appendInt(arena, &out, u32, @intCast(store.authors.len));
    try appendInt(arena, &out, u32, @intCast(store.posts.len));
    try appendInt(arena, &out, u32, @intCast(store.feed.len));
    try appendInt(arena, &out, u32, store.next_cursor.offset);
    try appendInt(arena, &out, u32, store.next_cursor.len);

    try out.appendSlice(arena, store.string_bytes.items);

    const authors = store.authors.slice();
    try appendField(arena, &out, authors.items(.did));
    try appendField(arena, &out, authors.items(.handle));
    try appendField(arena, &out, authors.items(.display_name));
    try appendField(arena, &out, authors.items(.avatar_url));

    const posts = store.posts.slice();
    try appendField(arena, &out, posts.items(.created_at));
    try appendField(arena, &out, posts.items(.text));
    try appendField(arena, &out, posts.items(.cid));
    try appendField(arena, &out, posts.items(.uri));
    try appendField(arena, &out, posts.items(.author));
    try appendField(arena, &out, posts.items(.reply_parent));
    try appendField(arena, &out, posts.items(.reply_root));
    try appendField(arena, &out, posts.items(.like_count));
    try appendField(arena, &out, posts.items(.repost_count));
    try appendField(arena, &out, posts.items(.reply_count));
    try appendField(arena, &out, posts.items(.quote_count));
    try appendField(arena, &out, posts.items(.label_flags));

    const items = store.feed.slice();
    try appendField(arena, &out, items.items(.post));
    try appendField(arena, &out, items.items(.reposted_by));

    try appendBitset(arena, &out, store.liked, store.posts.len);
    try appendBitset(arena, &out, store.reposted, store.posts.len);

    return out.items;
}

fn appendInt(arena: Allocator, out: *std.ArrayList(u8), comptime T: type, value: T) error{OutOfMemory}!void {
    try out.appendSlice(arena, std.mem.asBytes(&value));
}

fn appendField(arena: Allocator, out: *std.ArrayList(u8), field_slice: anytype) error{OutOfMemory}!void {
    try out.appendSlice(arena, std.mem.sliceAsBytes(field_slice));
}

fn appendBitset(
    arena: Allocator,
    out: *std.ArrayList(u8),
    bits: std.DynamicBitSetUnmanaged,
    len: usize,
) error{OutOfMemory}!void {
    var packed_byte: u8 = 0;
    var i: usize = 0;
    while (i < len) : (i += 1) {
        if (bits.isSet(i)) packed_byte |= @as(u8, 1) << @intCast(i % 8);
        if (i % 8 == 7) {
            try out.append(arena, packed_byte);
            packed_byte = 0;
        }
    }
    if (len % 8 != 0) try out.append(arena, packed_byte);
}

// ---------------------------------------------------------------------------
// Decode
// ---------------------------------------------------------------------------

const Cursor = struct {
    // D5/A1 note: a parse-state HANDLE, not a record held in quantity —
    // methods are permitted here. A7.2: cold, one per decode; waived.

    bytes: []const u8,
    at: usize = 0,

    fn take(c: *Cursor, n: usize) error{InvalidSnapshot}![]const u8 {
        if (c.bytes.len - c.at < n) return error.InvalidSnapshot;
        const slice = c.bytes[c.at .. c.at + n];
        c.at += n;
        return slice;
    }

    fn takeInt(c: *Cursor, comptime T: type) error{InvalidSnapshot}!T {
        const raw = try c.take(@sizeOf(T));
        return std.mem.bytesToValue(T, raw[0..@sizeOf(T)]);
    }
};

pub fn decode(gpa: Allocator, bytes: []const u8) DecodeError!feed.Store {
    var c: Cursor = .{ .bytes = bytes };

    const magic_read = try c.take(4);
    if (!std.mem.eql(u8, magic_read, &magic)) return error.InvalidSnapshot;
    if (try c.takeInt(u16) != version) return error.InvalidSnapshot;
    _ = try c.takeInt(u16); // reserved
    const header: Header = .{
        .string_len = try c.takeInt(u64),
        .authors_len = try c.takeInt(u32),
        .posts_len = try c.takeInt(u32),
        .feed_len = try c.takeInt(u32),
        .cursor = .{ .offset = try c.takeInt(u32), .len = try c.takeInt(u32) },
    };
    // A sanity ceiling: a local cache is megabytes, not gigabytes.
    if (header.string_len > 256 * 1024 * 1024) return error.InvalidSnapshot;

    var store: feed.Store = .{};
    errdefer feed.deinitStore(gpa, &store);

    try store.string_bytes.appendSlice(gpa, try c.take(@intCast(header.string_len)));

    try store.authors.resize(gpa, header.authors_len);
    const authors = store.authors.slice();
    try takeField(&c, authors.items(.did));
    try takeField(&c, authors.items(.handle));
    try takeField(&c, authors.items(.display_name));
    try takeField(&c, authors.items(.avatar_url));

    try store.posts.resize(gpa, header.posts_len);
    const posts = store.posts.slice();
    try takeField(&c, posts.items(.created_at));
    try takeField(&c, posts.items(.text));
    try takeField(&c, posts.items(.cid));
    try takeField(&c, posts.items(.uri));
    try takeField(&c, posts.items(.author));
    try takeField(&c, posts.items(.reply_parent));
    try takeField(&c, posts.items(.reply_root));
    try takeField(&c, posts.items(.like_count));
    try takeField(&c, posts.items(.repost_count));
    try takeField(&c, posts.items(.reply_count));
    try takeField(&c, posts.items(.quote_count));
    try takeField(&c, posts.items(.label_flags));

    try store.feed.resize(gpa, header.feed_len);
    const items = store.feed.slice();
    try takeField(&c, items.items(.post));
    try takeField(&c, items.items(.reposted_by));

    try takeBitset(gpa, &c, &store.liked, header.posts_len);
    try takeBitset(gpa, &c, &store.reposted, header.posts_len);
    // The record-uri arrays are wire-derived and deliberately NOT in the
    // snapshot: size them empty so indexing is safe; a refresh fills them.
    try store.like_uris.resize(gpa, store.posts.len);
    try store.repost_uris.resize(gpa, store.posts.len);
    @memset(store.like_uris.items, .empty);
    @memset(store.repost_uris.items, .empty);

    if (c.at != bytes.len) return error.InvalidSnapshot;

    store.next_cursor = header.cursor;

    // Trust nothing that points anywhere (the file may be stale, torn, or
    // hostile): every span inside the string buffer, every index inside
    // its array.
    try validateSpan(&store, store.next_cursor);
    for (authors.items(.did)) |span| try validateSpan(&store, span);
    for (authors.items(.handle)) |span| try validateSpan(&store, span);
    for (authors.items(.display_name)) |span| try validateSpan(&store, span);
    for (authors.items(.avatar_url)) |span| try validateSpan(&store, span);
    for (posts.items(.text)) |span| try validateSpan(&store, span);
    for (posts.items(.cid)) |span| try validateSpan(&store, span);
    for (posts.items(.uri)) |span| try validateSpan(&store, span);
    for (posts.items(.author)) |author| {
        if (@intFromEnum(author) >= header.authors_len) return error.InvalidSnapshot;
    }
    for (posts.items(.reply_parent)) |opt| try validateOptionalPost(opt, header.posts_len);
    for (posts.items(.reply_root)) |opt| try validateOptionalPost(opt, header.posts_len);
    for (items.items(.post)) |post| {
        if (@intFromEnum(post) >= header.posts_len) return error.InvalidSnapshot;
    }
    for (items.items(.reposted_by)) |opt| {
        if (opt.unwrap()) |author| {
            if (@intFromEnum(author) >= header.authors_len) return error.InvalidSnapshot;
        }
    }

    // Rebuild the identity maps from the verified spans (A8: the CID is
    // the key; the maps are derived state, never persisted).
    var i: u32 = 0;
    while (i < header.posts_len) : (i += 1) {
        const span = posts.items(.cid)[i];
        const gop = try store.post_by_cid.getOrPutContextAdapted(
            gpa,
            feed.sliceSpan(&store, span),
            std.hash_map.StringIndexAdapter{ .bytes = &store.string_bytes },
            std.hash_map.StringIndexContext{ .bytes = &store.string_bytes },
        );
        gop.key_ptr.* = span.offset;
        gop.value_ptr.* = i;
    }
    i = 0;
    while (i < header.authors_len) : (i += 1) {
        const span = authors.items(.did)[i];
        const gop = try store.author_by_did.getOrPutContextAdapted(
            gpa,
            feed.sliceSpan(&store, span),
            std.hash_map.StringIndexAdapter{ .bytes = &store.string_bytes },
            std.hash_map.StringIndexContext{ .bytes = &store.string_bytes },
        );
        gop.key_ptr.* = span.offset;
        gop.value_ptr.* = i;
    }

    return store;
}

fn takeField(c: *Cursor, field_slice: anytype) error{InvalidSnapshot}!void {
    const dst = std.mem.sliceAsBytes(field_slice);
    const src = try c.take(dst.len);
    @memcpy(dst, src);
}

fn takeBitset(
    gpa: Allocator,
    c: *Cursor,
    bits: *std.DynamicBitSetUnmanaged,
    len: usize,
) DecodeError!void {
    const packed_bytes = try c.take((len + 7) / 8);
    try bits.resize(gpa, len, false);
    var i: usize = 0;
    while (i < len) : (i += 1) {
        const bit = packed_bytes[i / 8] >> @intCast(i % 8) & 1;
        if (bit == 1) bits.set(i);
    }
}

fn validateSpan(store: *const feed.Store, span: feed.TextSpan) error{InvalidSnapshot}!void {
    const total = store.string_bytes.items.len;
    if (span.offset > total or total - span.offset < span.len) return error.InvalidSnapshot;
}

fn validateOptionalPost(opt: feed.OptionalPostIndex, posts_len: u32) error{InvalidSnapshot}!void {
    if (opt.unwrap()) |index| {
        if (@intFromEnum(index) >= posts_len) return error.InvalidSnapshot;
    }
}

// ---------------------------------------------------------------------------
// Tests (B2, C6)
// ---------------------------------------------------------------------------

const testing = std.testing;

fn populatedStore(gpa: Allocator) !feed.Store {
    var store: feed.Store = .{};
    errdefer feed.deinitStore(gpa, &store);
    _ = try feed.ingestPage(gpa, &store, feed.fixture_page);
    _ = try feed.ingestLivePost(gpa, &store, .{
        .did = "did:plc:nnnnnnnnnnnnnnnnnnnnnnnn",
        .handle = "",
        .uri = "at://did:plc:nnnnnnnnnnnnnnnnnnnnnnnn/app.bsky.feed.post/3snap",
        .cid = "bafyreisnaplive",
        .text = "survives the disk",
        .reply_parent_cid = "bafyreialice1",
        .reply_root_cid = "bafyreialice1",
        .created_at = 1_767_323_111,
    });
    _ = feed.applyLike(&store, "bafyreialice1");
    return store;
}

test "snapshot: a populated store round-trips exactly" {
    const gpa = testing.allocator; // C6
    var store = try populatedStore(gpa);
    defer feed.deinitStore(gpa, &store);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const image = try encode(arena_state.allocator(), &store);

    var loaded = try decode(gpa, image);
    defer feed.deinitStore(gpa, &loaded);

    try testing.expectEqualStrings(feed.nextCursor(&store), feed.nextCursor(&loaded));

    const before = try feed.buildTimeline(arena_state.allocator(), &store);
    const after = try feed.buildTimeline(arena_state.allocator(), &loaded);
    try testing.expectEqual(before.len, after.len);
    for (before, after) |a, b| {
        try testing.expectEqualStrings(a.text, b.text);
        try testing.expectEqualStrings(a.cid, b.cid);
        try testing.expectEqualStrings(a.uri, b.uri);
        try testing.expectEqualStrings(a.author_handle, b.author_handle);
        try testing.expectEqualStrings(a.replying_to_handle, b.replying_to_handle);
        try testing.expectEqual(a.created_at, b.created_at);
        try testing.expectEqual(a.like_count, b.like_count);
        try testing.expectEqual(a.item_flags.viewer_liked, b.item_flags.viewer_liked);
    }

    // The identity maps were rebuilt: dedup still works on the loaded store.
    const dup = try feed.ingestLivePost(gpa, &loaded, .{
        .did = "did:plc:nnnnnnnnnnnnnnnnnnnnnnnn",
        .handle = "",
        .uri = "at://did:plc:nnnnnnnnnnnnnnnnnnnnnnnn/app.bsky.feed.post/3snap",
        .cid = "bafyreisnaplive",
        .text = "survives the disk",
        .reply_parent_cid = "",
        .reply_root_cid = "",
        .created_at = 1_767_323_111,
    });
    try testing.expectEqual(feed.LiveIngest.duplicate, dup);
}

test "snapshot: lies are refused — magic, truncation, poisoned span, trailing bytes" {
    const gpa = testing.allocator; // C6
    var store = try populatedStore(gpa);
    defer feed.deinitStore(gpa, &store);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const image = try encode(arena, &store);

    var bad_magic = try arena.dupe(u8, image);
    bad_magic[0] = 'X';
    try testing.expectError(error.InvalidSnapshot, decode(gpa, bad_magic));

    try testing.expectError(error.InvalidSnapshot, decode(gpa, image[0 .. image.len / 2]));

    // Poison one span length deep inside the author section.
    var poisoned = try arena.dupe(u8, image);
    const span_section = 4 + 2 + 2 + 8 + 4 + 4 + 4 + 8 + store.string_bytes.items.len;
    std.mem.writeInt(u32, poisoned[span_section + 4 ..][0..4], 0xFFFF_FFFF, .little);
    try testing.expectError(error.InvalidSnapshot, decode(gpa, poisoned));

    var padded = try arena.alloc(u8, image.len + 1);
    @memcpy(padded[0..image.len], image);
    padded[image.len] = 0;
    try testing.expectError(error.InvalidSnapshot, decode(gpa, padded));
}
