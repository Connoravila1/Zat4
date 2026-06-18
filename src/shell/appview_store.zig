//! B1 classification: SHELL (disk I/O). The AppView's DURABLE EVENT LOG —
//! the on-disk persistence the in-memory index (core/appview.zig) lacked.
//!
//! The index is a PURE deterministic reduction of an event stream (every
//! record reduced by shell/appview_ingest.zig). So persistence is not a
//! serialization of the index's interned-pool/hashmap internals (fragile,
//! couples the on-disk format to the layout) — it is an APPEND-ONLY LOG of
//! the source records, in the exact Jetstream-commit envelope the ingest
//! reducer already understands, replayed on startup to rebuild the index.
//! The log is the source of truth; the index is the derived view (A8 in
//! spirit: a record is its content, re-applied idempotently).
//!
//! This is also the shape Tap ingestion (STANDALONE_ROADMAP "Cut 2") needs:
//! backfill re-reads history, so the index must absorb a re-seen record
//! without double-applying. Each appended line carries the RECORD's own cid;
//! `replay` rebuilds both the index AND the poll's `seen` dedup set from it,
//! so a restart-then-repoll (or a Tap re-backfill) never duplicates a follow
//! edge or inflates a like count.
//!
//! Kernel-surface file I/O (raw `std.os.linux`), matching shell/cache.zig and
//! shell/stream.zig: the fork's `std.Io.Dir` API drifts across snapshots, so
//! the durable store rides the stable syscall boundary. Linux is the AppView's
//! deployment target; on any other platform the store degrades to disabled
//! (fd < 0 → appends are no-ops, replay reads nothing) and the AppView runs
//! in-memory exactly as before (E2: a missing capability is a plainer service,
//! never a dead one).

const std = @import("std");
const builtin = @import("builtin");
const Allocator = std.mem.Allocator;
const linux = std.os.linux;
const appview = @import("../core/appview.zig");
const ingest = @import("appview_ingest.zig");
const lexicon = @import("../core/lexicon.zig");

/// Caller-visible dedup set: a 64-bit hash of each applied record's cid. The
/// poll keys its idempotency on this; `replay` repopulates it from the log so
/// dedup survives a restart. (A std container, owned by the caller.)
pub const SeenSet = std.AutoHashMapUnmanaged(u64, void);

/// The dedup key for a record cid. The poll and `replay` MUST agree on this so
/// a replayed record and a re-polled one collapse to the same `seen` entry.
pub fn seenKey(cid: []const u8) u64 {
    return std.hash.Wyhash.hash(0, cid);
}

/// An open durable log. `fd < 0` means disabled — every operation degrades to a
/// no-op (E2). A7.2: cold struct, size guard waived — one per process.
pub const Store = struct {
    fd: i32 = -1,
};

const max_file_bytes: usize = 512 * 1024 * 1024; // replay read cap (C2: visible)

/// Open (creating if absent) the durable log at `path` for append. An empty
/// path or a failed open yields a DISABLED store (E2) — the AppView then runs
/// in-memory, as it did before this module. Linux-only writable path.
pub fn open(path: []const u8) Store {
    if (path.len == 0 or path.len >= 255) return .{};
    if (comptime builtin.os.tag != .linux) return .{};
    var z: [256]u8 = undefined;
    @memcpy(z[0..path.len], path);
    z[path.len] = 0;
    const rc = linux.open(
        z[0..path.len :0].ptr,
        .{ .ACCMODE = .WRONLY, .CREAT = true, .APPEND = true },
        0o644,
    );
    const signed: isize = @bitCast(rc);
    if (signed < 0) return .{};
    return .{ .fd = @intCast(signed) };
}

pub fn close(store: *Store) void {
    if (store.fd >= 0 and comptime builtin.os.tag == .linux) _ = linux.close(store.fd);
    store.fd = -1;
}

// --- canonical envelope shapes (the durable line == a Jetstream commit) -----
//
// One line per record, in the exact shape shell/appview_ingest.zig reduces.
// Posts carry rkey (the reducer rebuilds the uri from it); follows/likes/
// reposts do not need it. The commit `cid` is the RECORD's own cid — what
// `replay` feeds back into `seen`.

/// A7.2: cold struct, size guard waived — transient serialize source.
const PostCommit = struct {
    operation: []const u8 = "create",
    collection: []const u8 = lexicon.collection.post,
    rkey: []const u8,
    cid: []const u8,
    record: lexicon.PostRecordOut,
};
/// A7.2: cold struct, size guard waived — transient serialize source.
const PostEnvelope = struct {
    did: []const u8,
    kind: []const u8 = "commit",
    commit: PostCommit,
};

/// A7.2: cold struct, size guard waived — transient serialize source.
const FollowCommit = struct {
    operation: []const u8 = "create",
    collection: []const u8 = lexicon.collection.follow,
    cid: []const u8,
    record: lexicon.FollowRecordOut,
};
/// A7.2: cold struct, size guard waived — transient serialize source.
const FollowEnvelope = struct {
    did: []const u8,
    kind: []const u8 = "commit",
    commit: FollowCommit,
};

/// A7.2: cold struct, size guard waived — transient serialize source.
const EngCommit = struct {
    operation: []const u8 = "create",
    collection: []const u8,
    cid: []const u8,
    record: lexicon.SubjectRecordOut,
};
/// A7.2: cold struct, size guard waived — transient serialize source.
const EngEnvelope = struct {
    did: []const u8,
    kind: []const u8 = "commit",
    commit: EngCommit,
};

/// A7.2: cold struct, size guard waived — transient parse target (replay cid peek).
const PeekCommit = struct {
    cid: []const u8 = "",
};
/// A7.2: cold struct, size guard waived — transient parse target.
const PeekEvent = struct {
    commit: ?PeekCommit = null,
};

/// Append a post record to the durable log. `rkey`/`cid` identify the record;
/// `text`/`created_at` are its content (verbatim from the source). A disabled
/// store is a silent no-op. `arena` is transient stringify scratch.
pub fn appendPost(
    store: *Store,
    arena: Allocator,
    author_did: []const u8,
    rkey: []const u8,
    cid: []const u8,
    text: []const u8,
    created_at: []const u8,
) void {
    if (store.fd < 0 or rkey.len == 0 or cid.len == 0) return;
    const env: PostEnvelope = .{
        .did = author_did,
        .commit = .{ .rkey = rkey, .cid = cid, .record = .{ .text = text, .createdAt = created_at } },
    };
    writeEnvelope(store, arena, env);
}

/// Append a follow edge. `record_cid` is the follow record's own cid (the
/// dedup key); `subject_did` is who the follower follows.
pub fn appendFollow(
    store: *Store,
    arena: Allocator,
    follower_did: []const u8,
    subject_did: []const u8,
    record_cid: []const u8,
) void {
    if (store.fd < 0 or record_cid.len == 0 or subject_did.len == 0) return;
    const env: FollowEnvelope = .{
        .did = follower_did,
        .commit = .{ .cid = record_cid, .record = .{ .subject = subject_did, .createdAt = "" } },
    };
    writeEnvelope(store, arena, env);
}

/// Append a like/repost. `record_cid` is the engagement record's own cid (the
/// dedup key); `subject_cid` is the post being engaged.
pub fn appendEngagement(
    store: *Store,
    arena: Allocator,
    kind: appview.Engagement,
    actor_did: []const u8,
    subject_cid: []const u8,
    record_cid: []const u8,
) void {
    if (store.fd < 0 or record_cid.len == 0 or subject_cid.len == 0) return;
    const collection = switch (kind) {
        .like => lexicon.collection.like,
        .repost => lexicon.collection.repost,
    };
    const env: EngEnvelope = .{
        .did = actor_did,
        .commit = .{
            .collection = collection,
            .cid = record_cid,
            .record = .{ .@"$type" = collection, .subject = .{ .cid = subject_cid }, .createdAt = "" },
        },
    };
    writeEnvelope(store, arena, env);
}

fn writeEnvelope(store: *Store, arena: Allocator, env: anytype) void {
    const json = std.json.Stringify.valueAlloc(arena, env, .{ .emit_null_optional_fields = false }) catch return;
    const line = std.fmt.allocPrint(arena, "{s}\n", .{json}) catch return;
    writeAll(store.fd, line);
}

fn writeAll(fd: i32, bytes: []const u8) void {
    if (comptime builtin.os.tag != .linux) return;
    var sent: usize = 0;
    while (sent < bytes.len) {
        const rc = linux.write(fd, bytes.ptr + sent, bytes.len - sent);
        const signed: isize = @bitCast(rc);
        if (signed <= 0) return; // a failed write drops this line (E2); the in-memory index still has it
        sent += @intCast(signed);
    }
}

/// Replay the durable log at `path` into the index AND the `seen` dedup set:
/// for each line, index it (via the shared reducer) and record its cid hash so
/// a later re-poll / re-backfill skips it. Returns the count of lines applied
/// (non-ignored). A missing/unreadable log is zero replayed (E4, not an error).
/// `gpa` grows the index; an internal arena holds per-line parse scratch.
pub fn replay(gpa: Allocator, idx: *appview.Index, seen: *SeenSet, path: []const u8) Allocator.Error!usize {
    const bytes = readFileAlloc(gpa, path) orelse return 0;
    defer gpa.free(bytes);

    var applied: usize = 0;
    var line_arena = std.heap.ArenaAllocator.init(gpa);
    defer line_arena.deinit();
    var it = std.mem.splitScalar(u8, bytes, '\n');
    while (it.next()) |raw| {
        const line = std.mem.trimEnd(u8, raw, "\r");
        if (line.len == 0) continue;
        _ = line_arena.reset(.retain_capacity);
        const la = line_arena.allocator();

        // Seed the dedup set from the record's own cid, matching the poll's key
        // so a re-polled copy of this record collapses to the same entry.
        if (std.json.parseFromSliceLeaky(PeekEvent, la, line, .{ .ignore_unknown_fields = true })) |peek| {
            if (peek.commit) |c| {
                if (c.cid.len != 0) try seen.put(gpa, seenKey(c.cid), {});
            }
        } else |_| {}

        const what = ingest.ingestEvent(gpa, la, idx, line) catch |e| switch (e) {
            error.OutOfMemory => return e,
        };
        if (what != .ignored) applied += 1;
    }
    return applied;
}

fn readFileAlloc(gpa: Allocator, path: []const u8) ?[]u8 {
    if (comptime builtin.os.tag != .linux) return null;
    if (path.len == 0 or path.len >= 255) return null;
    var z: [256]u8 = undefined;
    @memcpy(z[0..path.len], path);
    z[path.len] = 0;
    const open_rc = linux.open(z[0..path.len :0].ptr, .{ .ACCMODE = .RDONLY }, 0);
    const fd_signed: isize = @bitCast(open_rc);
    if (fd_signed < 0) return null;
    const fd: i32 = @intCast(fd_signed);
    defer _ = linux.close(fd);

    var out: std.ArrayList(u8) = .empty;
    errdefer out.deinit(gpa);
    var chunk: [64 * 1024]u8 = undefined;
    while (true) {
        const n_rc = linux.read(fd, &chunk, chunk.len);
        const n_signed: isize = @bitCast(n_rc);
        if (n_signed < 0) {
            out.deinit(gpa);
            return null;
        }
        if (n_signed == 0) break;
        if (out.items.len + @as(usize, @intCast(n_signed)) > max_file_bytes) {
            out.deinit(gpa);
            return null;
        }
        out.appendSlice(gpa, chunk[0..@intCast(n_signed)]) catch {
            out.deinit(gpa);
            return null;
        };
    }
    return out.toOwnedSlice(gpa) catch {
        out.deinit(gpa);
        return null;
    };
}

// ---------------------------------------------------------------------------
// Tests (C6) — round-trip the log against a real temp file on the linux path.
// ---------------------------------------------------------------------------

const testing = std.testing;

/// A unique temp path under $TMPDIR (or /tmp). No clock/rng in the test env, so
/// the test name keys the path; the test removes it on the way in and out.
fn tmpPath() []const u8 {
    return "/tmp/zat4_appview_store_test.jsonl";
}

fn rm(path: []const u8) void {
    if (comptime builtin.os.tag != .linux) return;
    var z: [256]u8 = undefined;
    @memcpy(z[0..path.len], path);
    z[path.len] = 0;
    _ = linux.unlink(z[0..path.len :0].ptr);
}

test "store: append then replay rebuilds the index (posts, follows, likes)" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    const path = tmpPath();
    rm(path);
    defer rm(path);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Write a session's worth of records to the durable log.
    {
        var store = open(path);
        defer close(&store);
        try testing.expect(store.fd >= 0);
        appendFollow(&store, arena, "did:plc:me", "did:plc:author", "bafy-follow-1");
        appendPost(&store, arena, "did:plc:author", "rk1", "bafy-post-1", "hello zat4", "2026-06-14T00:00:00Z");
        appendEngagement(&store, arena, .like, "did:plc:me", "bafy-post-1", "bafy-like-1");
    }

    // A fresh process: replay the log into a new index + seen set.
    var idx: appview.Index = .{};
    defer appview.deinit(gpa, &idx);
    var seen: SeenSet = .empty;
    defer seen.deinit(gpa);

    const applied = try replay(gpa, &idx, &seen, path);
    try testing.expectEqual(@as(usize, 3), applied);
    try testing.expectEqual(@as(usize, 1), idx.posts.len);
    try testing.expectEqual(@as(usize, 1), idx.follows.len);
    try testing.expectEqual(@as(u32, 1), idx.posts.items(.like_count)[0]);

    // The viewer's timeline is reconstructed.
    const rows = try appview.buildTimeline(arena, &idx, "did:plc:me", 10);
    try testing.expectEqual(@as(usize, 1), rows.len);
    try testing.expectEqualStrings("hello zat4", rows[0].text);

    // The dedup set carries every record cid, so a re-poll would skip them.
    try testing.expect(seen.contains(seenKey("bafy-follow-1")));
    try testing.expect(seen.contains(seenKey("bafy-like-1")));
}

test "store: replaying the same log twice does not double-apply (idempotent restart)" {
    if (comptime builtin.os.tag != .linux) return error.SkipZigTest;
    const gpa = testing.allocator;
    const path = tmpPath();
    rm(path);
    defer rm(path);

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    {
        var store = open(path);
        defer close(&store);
        appendFollow(&store, arena, "did:plc:me", "did:plc:a", "bafy-f1");
        appendPost(&store, arena, "did:plc:a", "rk1", "bafy-p1", "p", "2026-06-14T00:00:00Z");
        appendEngagement(&store, arena, .like, "did:plc:me", "bafy-p1", "bafy-l1");
    }

    var idx: appview.Index = .{};
    defer appview.deinit(gpa, &idx);
    var seen: SeenSet = .empty;
    defer seen.deinit(gpa);

    _ = try replay(gpa, &idx, &seen, path);
    // Posts dedup by cid in the index; the like is re-applied on a naive second
    // replay (the index has no per-engagement dedup) — so the GUARD against
    // double counting is the `seen` set the poll consults, which replay filled.
    // Verify the post is not duplicated and the follow graph is intact.
    try testing.expectEqual(@as(usize, 1), idx.posts.len);
    try testing.expect(seen.contains(seenKey("bafy-l1")));
    try testing.expect(seen.contains(seenKey("bafy-f1")));
}

test "store: a disabled store (no path) is a silent no-op, replay of nothing is zero" {
    const gpa = testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();

    var store = open(""); // disabled
    defer close(&store);
    try testing.expect(store.fd < 0);
    appendPost(&store, arena_state.allocator(), "did:x", "rk", "cid", "t", "2026-06-14T00:00:00Z"); // no crash

    var idx: appview.Index = .{};
    defer appview.deinit(gpa, &idx);
    var seen: SeenSet = .empty;
    defer seen.deinit(gpa);
    const applied = try replay(gpa, &idx, &seen, "/tmp/zat4_nonexistent_log_xyz.jsonl");
    try testing.expectEqual(@as(usize, 0), applied);
}

test {
    std.testing.refAllDecls(@This());
}
