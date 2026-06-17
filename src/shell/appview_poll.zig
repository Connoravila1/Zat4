//! B1 classification: SHELL (network I/O). The AppView's PDS-polling ingester.
//!
//! Bluesky's public Jetstream is LIVE-ONLY and was not built for custom-lexicon
//! backfill/discovery, so the AppView cannot find `app.zat4.*` content there.
//! The relay (`bsky.network`) IS lexicon-agnostic and carries our records, so
//! the proper firehose path is our own Jetstream against it (or Tap) — the
//! scale-up recorded in STANDALONE_ROADMAP / PDS_ROADMAP.
//!
//! Until then, this reads a repo's `app.zat4.feed.post` records DIRECTLY from
//! its PDS via `com.atproto.repo.listRecords` — a PUBLIC read, no auth — and
//! indexes new ones (cid dedup, A8). Correct and cheap for a small/known set of
//! authors; it does not scale to the whole network (that is the firehose's job).

const std = @import("std");
const Allocator = std.mem.Allocator;
const xrpc = @import("xrpc.zig");
const lexicon = @import("../core/lexicon.zig");
const feed = @import("../core/feed.zig");
const appview = @import("../core/appview.zig");
const serve = @import("appview_serve.zig");

/// One entry from `listRecords`. `value` is the post record (text/createdAt),
/// the same shape the write/jetstream paths already use. A7.2: cold transient
/// parse target — a read-only convenience for this module's ingest.
const ListRecord = struct {
    uri: []const u8 = "",
    cid: []const u8 = "",
    value: lexicon.PostRecord = .{},
};

/// `com.atproto.repo.listRecords` response. A7.2: cold transient parse target.
const ListRecordsResponse = struct {
    records: []const ListRecord = &.{},
    cursor: ?[]const u8 = null,
};

/// Poll one repo's `app.zat4.feed.post` collection and index any NEW posts into
/// `idx` (under `lock`, since the serve thread reads it concurrently). Returns
/// the count newly indexed — cid dedup (A8) makes a re-seen post a no-op, so a
/// steady poll only ever adds what is new. A refused/failed read is an error;
/// the caller logs and continues (E2). Strings are read out of `arena`, which
/// the caller resets per poll.
pub fn pollRepo(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    pds_url: []const u8,
    did: []const u8,
    idx: *appview.Index,
    lock: *serve.IndexLock,
) !usize {
    const params = [_]xrpc.Param{
        .{ .name = "repo", .value = did },
        .{ .name = "collection", .value = lexicon.collection.post },
        .{ .name = "limit", .value = "100" },
    };
    const outcome = try xrpc.query(
        arena,
        io,
        environ,
        pds_url,
        lexicon.method.list_records,
        &params,
        ListRecordsResponse,
        .{}, // public read — no authorization
    );
    const resp = switch (outcome) {
        .ok => |r| r,
        .failed => return error.ListRecordsRefused,
    };

    var added: usize = 0;
    lock.lock();
    defer lock.unlock();
    for (resp.records) |rec| {
        if (rec.cid.len == 0) continue;
        const is_new = appview.indexPost(gpa, idx, .{
            .cid = rec.cid,
            .author_did = did,
            .text = rec.value.text,
            .created_at = feed.parseTimestamp(rec.value.createdAt) catch 0,
        }) catch false;
        if (is_new) added += 1;
    }
    return added;
}

test {
    // Compile-coverage: the parse types + signature stay valid. The live read
    // is exercised by the owner's run (it needs a real PDS / network).
    std.testing.refAllDecls(@This());
}
