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

//! B1 classification: SHELL. The **write worker** — the same actor pattern
//! the firehose (stream.zig) already proves: it runs on its OWN thread,
//! owns its own arena (C4), and talks to the UI ONLY by plain-data
//! messages through two mailboxes (E1) — a REQUEST inbox (UI → worker)
//! and a RESULT outbox (worker → UI). It fails alone (E2): a network
//! error becomes a result message, never a crash, never a blocked UI.
//!
//! WHY THIS EXISTS: a like/unlike/repost is a network round-trip. Done
//! inline on the render thread it FREEZES the whole UI — scrolling, the
//! firehose, and any animation — for the server's reply (100–500ms). That
//! freeze is the mid-animation lag. Moving the write here means the UI
//! thread only drops a request and returns; the main loop keeps running,
//! so animations play smoothly as the pure per-frame transform the
//! glyph-field design intends, and the optimistic count is reverted later
//! (by a result message) only if the server refuses.
//!
//! Wire/HTTP knowledge stays in write.zig and auth.zig (D3); this file
//! only moves request/result VALUES across the thread boundary and calls
//! the existing write functions.

const std = @import("std");
const Allocator = std.mem.Allocator;
const auth = @import("auth.zig");
const write = @import("write.zig");
const clock = @import("clock.zig");
const loadout_store = @import("loadout.zig");
const algorithm_shell = @import("algorithm.zig");
const algorithm_core = @import("../core/algorithm.zig");

// ---------------------------------------------------------------------------
// The messages — plain data, the only thing that crosses the boundary (E1)
// ---------------------------------------------------------------------------

/// What kind of write the UI is asking for. The strings each request
/// carries are gpa-owned COPIES made at enqueue time (the call site's
/// arena does not outlive the request), freed by the worker after use.
pub const Request = struct {
    // A7.2: cold struct, size guard waived — write requests exist at human
    // action rates (a few in flight at most), carry slices (variable size,
    // not a packable hot record), and are drained in a short batch, never
    // a hot loop. The exact-byte guard is for tightly-packed hot structs.
    kind: Kind,
    /// The post's CID — carried through untouched so the RESULT can be
    /// matched back to the right post for an optimistic revert. Owned copy.
    cid: []const u8,
    /// For a create (like/repost): the subject post uri + cid. For a
    /// delete (unlike/unrepost): `record_uri` holds the like/repost record
    /// to remove and the subject fields are empty. Owned copies.
    subject_uri: []const u8,
    subject_cid: []const u8,
    record_uri: []const u8,
    /// Creation time for the record (createdAt). Captured on the UI thread
    /// so the worker reads no clock of its own for this value.
    now: i64,

    /// For a `.loadout` write only: the three per-surface loadouts to persist
    /// (feed, reply, zone), as owned id/color arrays. Empty otherwise. This is
    /// why the freeze went away: the loadout `putRecord` runs HERE, off the UI
    /// loop, instead of blocking it on tray-close. Indices: 0=feed,1=reply,2=zone.
    loadout: [3]loadout_store.SurfaceData = .{ .{}, .{}, .{} },

    /// For a `.publish_algo` write only: the record's display name and the
    /// serialized FeedConfig bytes (byte-exact, the form the record carries).
    /// The rkey rides in `record_uri`; the library's local id in `cid` (so the
    /// result can be matched back). Owned copies, empty otherwise.
    algo_name: []const u8 = "",
    algo_config: []const u8 = "",

    pub const Kind = enum(u8) { like, unlike, repost, unrepost, loadout, publish_algo };
};

/// What the worker reports back. `cid` matches the request's post so the
/// UI can find it; `outcome` says whether to keep or revert the optimism.
pub const Result = struct {
    // A7.2: cold struct, size guard waived — same as Request: human-rate
    // volume, slice-carrying, short-batch drained, not a hot record.
    kind: Request.Kind,
    cid: []const u8, // owned copy; the UI frees after handling
    /// The record uri this request acted on — carried back so a REFUSED
    /// unlike/unrepost can restore the like/repost record (revertUnlike
    /// needs it). Empty for create kinds, whose revert needs only the cid.
    /// Owned copy.
    revert_uri: []const u8,
    outcome: Outcome,

    pub const Outcome = union(enum) {
        /// On a CREATE (like/repost), the created record's uri (owned copy) —
        /// the UI records it so a later unlike/unrepost can delete that record.
        /// Empty for delete kinds and on OOM. Freed by freeResult.
        ok: []const u8,
        /// The server refused (e.g. auth/validation). status+code are owned.
        refused: struct { status: u16, code: []const u8 },
        /// A transport/local failure (the error name, owned copy).
        net_error: []const u8,
    };
};

fn freeRequest(gpa: Allocator, r: Request) void {
    gpa.free(r.cid);
    gpa.free(r.subject_uri);
    gpa.free(r.subject_cid);
    gpa.free(r.record_uri);
    gpa.free(r.algo_name);
    gpa.free(r.algo_config);
    for (r.loadout) |surf| {
        for (surf.ids) |id| gpa.free(id);
        gpa.free(surf.ids);
        gpa.free(surf.colors);
    }
}

pub fn freeResult(gpa: Allocator, r: Result) void {
    gpa.free(r.cid);
    gpa.free(r.revert_uri);
    freeOutcome(gpa, r.outcome);
}

/// Free an Outcome's owned bytes (the .ok uri, the .refused code, the
/// .net_error name). Empty slices (literals on OOM) are a no-op free.
fn freeOutcome(gpa: Allocator, o: Result.Outcome) void {
    switch (o) {
        .ok => |uri| if (uri.len > 0) gpa.free(uri),
        .refused => |f| gpa.free(f.code),
        .net_error => |name| gpa.free(name),
    }
}

// ---------------------------------------------------------------------------
// A mailbox of T — the spinlock-guarded hand-off, same shape as stream.zig
// ---------------------------------------------------------------------------

/// A7.2: cold struct, size guard waived — two per worker, the cross-thread seam.
/// Pub: refresh_worker.zig reuses this same hand-off rather than growing a
/// third copy of the pattern (stream.zig owns the original reasoning).
pub fn Mailbox(comptime T: type) type {
    return struct {
        const Self = @This();
        // Spinlock not mutex, deliberately (stream.zig's reasoning): two
        // threads, tiny critical sections, human-rate contention, and
        // std.atomic is stable across 0.16-dev snapshots.
        locked: std.atomic.Value(bool) = .init(false),
        items: std.ArrayList(T) = .empty,

        fn acquire(b: *Self) void {
            while (b.locked.swap(true, .acquire)) std.atomic.spinLoopHint();
        }
        fn release(b: *Self) void {
            b.locked.store(false, .release);
        }
        pub fn push(b: *Self, gpa: Allocator, item: T) bool {
            b.acquire();
            defer b.release();
            b.items.append(gpa, item) catch return false;
            return true;
        }
        /// Move all pending items into `out`; caller owns them now.
        pub fn drain(b: *Self, gpa: Allocator, out: *std.ArrayList(T)) error{OutOfMemory}!void {
            b.acquire();
            defer b.release();
            try out.appendSlice(gpa, b.items.items);
            b.items.clearRetainingCapacity();
        }
        fn count(b: *Self) usize {
            b.acquire();
            defer b.release();
            return b.items.items.len;
        }
        /// Free the backing array. The OWNER of the mailbox calls this
        /// (the run loop declares them on its stack); the worker only
        /// pushes/drains. Any items still queued are the caller's to free
        /// first (the worker's shutdown drains+frees them before this).
        pub fn deinit(b: *Self, gpa: Allocator) void {
            b.items.deinit(gpa);
        }
    };
}

pub const RequestBox = Mailbox(Request);
pub const ResultBox = Mailbox(Result);

// ---------------------------------------------------------------------------
// The worker
// ---------------------------------------------------------------------------

pub const Worker = struct {
    // A7.2: cold struct, size guard waived — exactly one per session.
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    inbox: *RequestBox,
    outbox: *ResultBox,
    thread: std.Thread,
    stop: std.atomic.Value(bool),
};

/// Enqueue a write request from the UI thread. Copies every string into
/// gpa (the worker outlives the caller's arena), so the caller may free
/// its originals immediately. Returns false only on OOM (the optimistic
/// state then simply never reconciles — the next manual action will).
pub fn submit(
    worker: *Worker,
    kind: Request.Kind,
    cid: []const u8,
    subject_uri: []const u8,
    subject_cid: []const u8,
    record_uri: []const u8,
    now: i64,
) bool {
    const gpa = worker.gpa;
    const cid_c = gpa.dupe(u8, cid) catch return false;
    const su_c = gpa.dupe(u8, subject_uri) catch {
        gpa.free(cid_c);
        return false;
    };
    const sc_c = gpa.dupe(u8, subject_cid) catch {
        gpa.free(cid_c);
        gpa.free(su_c);
        return false;
    };
    const ru_c = gpa.dupe(u8, record_uri) catch {
        gpa.free(cid_c);
        gpa.free(su_c);
        gpa.free(sc_c);
        return false;
    };
    const req: Request = .{
        .kind = kind,
        .cid = cid_c,
        .subject_uri = su_c,
        .subject_cid = sc_c,
        .record_uri = ru_c,
        .now = now,
    };
    if (!worker.inbox.push(gpa, req)) {
        freeRequest(gpa, req);
        return false;
    }
    return true;
}

/// Deep-copy a surface's id/color arrays into gpa (owned by the request).
/// Returns the owned copy, or null on OOM (caller aborts + cleans up).
fn dupeSurface(gpa: Allocator, s: loadout_store.SurfaceData) ?loadout_store.SurfaceData {
    const n = @min(s.ids.len, s.colors.len);
    const ids_c = gpa.alloc([]const u8, n) catch return null;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        ids_c[i] = gpa.dupe(u8, s.ids[i]) catch {
            for (ids_c[0..i]) |x| gpa.free(x);
            gpa.free(ids_c);
            return null;
        };
    }
    const colors_c = gpa.dupe(u8, s.colors[0..n]) catch {
        for (ids_c[0..n]) |x| gpa.free(x);
        gpa.free(ids_c);
        return null;
    };
    return .{ .ids = ids_c, .colors = colors_c, .seated = s.seated };
}

fn freeSurface(gpa: Allocator, s: loadout_store.SurfaceData) void {
    for (s.ids) |id| gpa.free(id);
    gpa.free(s.ids);
    gpa.free(s.colors);
}

/// Enqueue a loadout persist — all three per-surface loadouts at once (the
/// record is one document). Copies the ids/colors into gpa, so the caller may
/// free its originals immediately. Fire-and-forget (E2). False only on OOM.
pub fn submitLoadout(worker: *Worker, feed: loadout_store.SurfaceData, reply: loadout_store.SurfaceData, zone: loadout_store.SurfaceData, now: i64) bool {
    const gpa = worker.gpa;
    const f = dupeSurface(gpa, feed) orelse return false;
    const r = dupeSurface(gpa, reply) orelse {
        freeSurface(gpa, f);
        return false;
    };
    const z = dupeSurface(gpa, zone) orelse {
        freeSurface(gpa, f);
        freeSurface(gpa, r);
        return false;
    };
    // The post fields are unused for a loadout write; empty slices free as a
    // no-op in freeRequest (Allocator.free returns early on len 0).
    const req: Request = .{
        .kind = .loadout,
        .cid = "",
        .subject_uri = "",
        .subject_cid = "",
        .record_uri = "",
        .now = now,
        .loadout = .{ f, r, z },
    };
    if (!worker.inbox.push(gpa, req)) {
        freeRequest(gpa, req);
        return false;
    }
    return true;
}

/// Enqueue an algorithm publish (ALGO_SUBMISSION slice 1): the marketplace
/// record write, off the UI thread like every other write. `local_id` rides
/// back on the result's `cid` so the UI can finish its flow; `config` is the
/// serialized FeedConfig the check produced (the worker re-parses and the
/// publish gate re-verifies, fail-closed). False only on OOM.
pub fn submitPublishAlgo(worker: *Worker, local_id: []const u8, name: []const u8, config: []const u8, rkey: []const u8, now: i64) bool {
    const gpa = worker.gpa;
    const cid_c = gpa.dupe(u8, local_id) catch return false;
    const name_c = gpa.dupe(u8, name) catch {
        gpa.free(cid_c);
        return false;
    };
    const cfg_c = gpa.dupe(u8, config) catch {
        gpa.free(cid_c);
        gpa.free(name_c);
        return false;
    };
    const rkey_c = gpa.dupe(u8, rkey) catch {
        gpa.free(cid_c);
        gpa.free(name_c);
        gpa.free(cfg_c);
        return false;
    };
    const req: Request = .{
        .kind = .publish_algo,
        .cid = cid_c,
        .subject_uri = "",
        .subject_cid = "",
        .record_uri = rkey_c,
        .now = now,
        .algo_name = name_c,
        .algo_config = cfg_c,
    };
    if (!worker.inbox.push(gpa, req)) {
        freeRequest(gpa, req);
        return false;
    }
    return true;
}

pub fn start(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    inbox: *RequestBox,
    outbox: *ResultBox,
) !*Worker {
    const worker = try gpa.create(Worker);
    worker.* = .{
        .gpa = gpa,
        .io = io,
        .environ = environ,
        .session = session,
        .inbox = inbox,
        .outbox = outbox,
        .thread = undefined,
        .stop = .init(false),
    };
    worker.thread = try std.Thread.spawn(.{}, threadMain, .{worker});
    return worker;
}

/// Signal stop and join. The thread checks `stop` between requests and on
/// its idle wakeups, so it exits within one poll interval. Deterministic
/// teardown (C5): any requests still queued are drained and freed.
pub fn shutdown(worker: *Worker) void {
    worker.stop.store(true, .release);
    worker.thread.join();
    const gpa = worker.gpa;
    // Drain any leftovers in both boxes so nothing leaks (C6).
    var pending: std.ArrayList(Request) = .empty;
    defer pending.deinit(gpa);
    worker.inbox.drain(gpa, &pending) catch {};
    for (pending.items) |req| freeRequest(gpa, req);
    var done: std.ArrayList(Result) = .empty;
    defer done.deinit(gpa);
    worker.outbox.drain(gpa, &done) catch {};
    for (done.items) |res| freeResult(gpa, res);
    gpa.destroy(worker);
}

fn threadMain(worker: *Worker) void {
    const gpa = worker.gpa;
    var batch: std.ArrayList(Request) = .empty;
    defer batch.deinit(gpa);
    while (!worker.stop.load(.acquire)) {
        batch.clearRetainingCapacity();
        worker.inbox.drain(gpa, &batch) catch {
            // OOM draining: back off and retry; nothing is lost (the items
            // remain in the inbox).
            clock.sleepMillis(20);
            continue;
        };
        if (batch.items.len == 0) {
            // Idle: poll. Human action rates make a short poll plenty
            // responsive while costing nothing measurable.
            clock.sleepMillis(15);
            continue;
        }
        for (batch.items, 0..) |req, i| {
            if (worker.stop.load(.acquire)) {
                // Stop was signalled mid-batch: free THIS and every
                // remaining unprocessed request (their strings are owned),
                // then exit. Without this the tail of the batch would leak,
                // since these were already drained out of the inbox and so
                // shutdown's inbox-drain will not see them.
                for (batch.items[i..]) |leftover| freeRequest(gpa, leftover);
                return;
            }
            processOne(worker, req);
            freeRequest(gpa, req);
        }
    }
}

fn processOne(worker: *Worker, req: Request) void {
    const gpa = worker.gpa;
    // Per-request arena (C3): the write call allocates request/response
    // bodies; we free them wholesale here.
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Loadout persist: fire-and-forget, no result to match back (it has no
    // optimistic UI state to reconcile). Done here so the UI never blocks.
    if (req.kind == .loadout) {
        loadout_store.saveAll(gpa, arena, worker.io, worker.environ, worker.session, req.loadout[0], req.loadout[1], req.loadout[2], req.now) catch {};
        return;
    }

    // Algorithm publish: parse the serialized config back to a FeedConfig and
    // run the gated record write. The result's `.ok` carries the record uri;
    // `revert_uri` carries the record CID (the transparency anchor) — reusing
    // the existing seat rather than growing the Result for one kind.
    if (req.kind == .publish_algo) {
        var record_cid: []const u8 = "";
        const outcome: Result.Outcome = blk: {
            const cfg = algorithm_core.parse(arena, req.algo_config) catch {
                break :blk .{ .net_error = gpa.dupe(u8, "BadConfig") catch "error" };
            };
            const published = algorithm_shell.publish(gpa, arena, worker.io, worker.environ, worker.session, req.algo_name, cfg, req.record_uri, req.now) catch |err| {
                break :blk .{ .net_error = gpa.dupe(u8, @errorName(err)) catch "error" };
            };
            record_cid = gpa.dupe(u8, published.cid) catch "";
            break :blk .{ .ok = gpa.dupe(u8, published.uri) catch "" };
        };
        const cid_copy = gpa.dupe(u8, req.cid) catch {
            if (record_cid.len > 0) gpa.free(record_cid);
            freeOutcome(gpa, outcome);
            return;
        };
        const result: Result = .{ .kind = .publish_algo, .cid = cid_copy, .revert_uri = record_cid, .outcome = outcome };
        if (!worker.outbox.push(gpa, result)) freeResult(gpa, result);
        return;
    }

    const call = switch (req.kind) {
        .like => write.likePost(gpa, arena, worker.io, worker.environ, worker.session, req.subject_uri, req.subject_cid, req.now),
        .repost => write.repostPost(gpa, arena, worker.io, worker.environ, worker.session, req.subject_uri, req.subject_cid, req.now),
        .unlike => write.unlikePost(gpa, arena, worker.io, worker.environ, worker.session, req.record_uri),
        .unrepost => write.unrepostPost(gpa, arena, worker.io, worker.environ, worker.session, req.record_uri),
        .loadout, .publish_algo => unreachable, // handled above
    };

    const outcome: Result.Outcome = if (call) |wo| switch (wo) {
        .ok => |ref| .{ .ok = gpa.dupe(u8, ref.uri) catch "" },
        .failed => |f| .{ .refused = .{
            .status = f.status,
            .code = gpa.dupe(u8, f.code) catch "",
        } },
    } else |err| .{ .net_error = gpa.dupe(u8, @errorName(err)) catch "error" };

    const cid_copy = gpa.dupe(u8, req.cid) catch {
        // If even the cid copy fails, drop the result; the optimistic
        // state stays (a benign over-count until the next refresh).
        freeOutcome(gpa, outcome);
        return;
    };
    const revert_copy = gpa.dupe(u8, req.record_uri) catch {
        gpa.free(cid_copy);
        freeOutcome(gpa, outcome);
        return;
    };
    const result: Result = .{ .kind = req.kind, .cid = cid_copy, .revert_uri = revert_copy, .outcome = outcome };
    if (!worker.outbox.push(gpa, result)) freeResult(gpa, result);
}

// ---------------------------------------------------------------------------
// Tests (C6) — the mailbox hand-off and message hygiene, no network
// ---------------------------------------------------------------------------

const testing = std.testing;

test "mailbox: push then drain moves every item and clears" {
    const gpa = testing.allocator;
    var box: RequestBox = .{};
    defer box.items.deinit(gpa);

    var i: usize = 0;
    while (i < 3) : (i += 1) {
        const req: Request = .{
            .kind = .like,
            .cid = try gpa.dupe(u8, "cidX"),
            .subject_uri = try gpa.dupe(u8, "at://uri"),
            .subject_cid = try gpa.dupe(u8, "scid"),
            .record_uri = try gpa.dupe(u8, ""),
            .now = 0,
        };
        try testing.expect(box.push(gpa, req));
    }
    try testing.expectEqual(@as(usize, 3), box.count());

    var out: std.ArrayList(Request) = .empty;
    defer out.deinit(gpa);
    try box.drain(gpa, &out);
    try testing.expectEqual(@as(usize, 3), out.items.len);
    try testing.expectEqual(@as(usize, 0), box.count()); // drained
    for (out.items) |req| freeRequest(gpa, req);
}

test "mailbox deinit frees the backing array (the leak the smoke test caught)" {
    const gpa = testing.allocator;
    // Push items, drain some, leave some — then deinit must free the
    // backing ArrayList itself, not just the items. The leak detector
    // (C6) fails this test if deinit forgets the backing store.
    var box: ResultBox = .{};
    var i: usize = 0;
    while (i < 5) : (i += 1) {
        const r: Result = .{ .kind = .like, .cid = try gpa.dupe(u8, "c"), .revert_uri = try gpa.dupe(u8, ""), .outcome = .{ .ok = "" } };
        try testing.expect(box.push(gpa, r));
    }
    // Drain three (caller frees them), leaving two in the box.
    var out: std.ArrayList(Result) = .empty;
    defer out.deinit(gpa);
    try box.drain(gpa, &out);
    for (out.items) |r| freeResult(gpa, r);
    // The box is now empty of items but its backing array is still
    // allocated; free the two we left by re-pushing then draining is not
    // needed — drain already emptied it. deinit frees the backing store.
    box.deinit(gpa);
}

test "result hygiene: every outcome variant frees without leak" {
    const gpa = testing.allocator;
    // ok
    {
        const r: Result = .{ .kind = .like, .cid = try gpa.dupe(u8, "c"), .revert_uri = try gpa.dupe(u8, ""), .outcome = .{ .ok = "" } };
        freeResult(gpa, r);
    }
    // refused
    {
        const r: Result = .{ .kind = .unlike, .cid = try gpa.dupe(u8, "c"), .revert_uri = try gpa.dupe(u8, "at://like"), .outcome = .{ .refused = .{ .status = 400, .code = try gpa.dupe(u8, "BadRequest") } } };
        freeResult(gpa, r);
    }
    // net_error
    {
        const r: Result = .{ .kind = .repost, .cid = try gpa.dupe(u8, "c"), .revert_uri = try gpa.dupe(u8, ""), .outcome = .{ .net_error = try gpa.dupe(u8, "ConnectionRefused") } };
        freeResult(gpa, r);
    }
}
