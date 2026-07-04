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

//! B1 classification: SHELL. The **view-load worker** — the same actor
//! pattern as refresh_worker.zig (whose shape it mirrors and whose Mailbox
//! source, write_worker.zig, it reuses): its own thread, a per-request arena
//! (C4), plain-data messages through two mailboxes (E1), failure contained
//! to a result message (E2).
//!
//! WHY THIS EXISTS: entering a view (profile/thread/zone/…) used to run its
//! fetch INLINE on the render thread — a frozen frame per entry on desktop,
//! and a guaranteed ANR once the OS owns the loop on a phone
//! (M_CORE_INVERSION MC.3). Now entry submits a request and returns to the
//! frame; the screen shows the store's resident content (every view is a
//! query over the shared store) until the drained result fills it.
//!
//! Split of labour, same as the refresh worker: this thread runs ONLY the
//! network half (the store-free fetches in feed.zig) — the store is owned by
//! the UI thread, so the ingest half (`feed_core.ingestPosts`) runs there,
//! on the drained page. Wire/HTTP knowledge stays in feed.zig/auth.zig (D3);
//! this file only moves request/result VALUES across the thread boundary.
//! Sharing the *auth.Session with the UI and the other worker threads is
//! safe by design: credential mutation is serialized by Session.cred_lock
//! (auth.zig).

const std = @import("std");
const Allocator = std.mem.Allocator;
const auth = @import("auth.zig");
const feed_shell = @import("feed.zig");
const lexicon = @import("../core/lexicon.zig");
const clock = @import("clock.zig");
const write_worker = @import("write_worker.zig");

// ---------------------------------------------------------------------------
// The messages — plain data, the only thing that crosses the boundary (E1)
// ---------------------------------------------------------------------------

/// Which view asked. Carried through to the Result so the drain knows which
/// ingest to run and which status line owns a failure.
pub const Kind = enum(u8) {
    /// The profile screen's body: one author's posts (getAuthorFeed).
    profile,
    /// The thread screen's body: the focused post's flat thread
    /// (getPostThread), reshaped here into a page for the same ingest.
    thread,
    /// The zone screen's body: one tag's posts (getPostsForTag).
    zone,
    /// The zones BROWSE catalog (listTags) — metadata, not posts; takes no
    /// target.
    zones,
    /// The marketplace browse page (getAlgorithms) — metadata + fetch refs,
    /// not configs; takes no target.
    algorithms,
};

/// A view-load ask. Everything the fetch needs (session, appview_url, io) is
/// captured once in the Worker at start; the request additionally OWNS its
/// target copy (gpa bytes — the UI's target lives in a mutable buffer the
/// user's next tap rewrites, so the UI copies it out at submit time). Freed
/// by processOne on every path, or by shutdown's pending-drain.
/// A7.2: cold struct, size guard waived — one per view entry (human rate),
/// never held in quantity or walked in a hot loop.
pub const Request = struct {
    kind: Kind,
    /// The view's target parameter (actor DID / post uri / tag); null for
    /// kinds that take none.
    target: ?[]u8 = null,
    limit: u32,
};

/// What the worker reports back: the fetched value (or the failure), plus
/// the arena that owns every byte the outcome references. The UI ingests
/// the value, THEN frees the result — the arena crosses the boundary as an
/// owned value, exactly like the refresh worker's pages.
/// A7.2: cold struct, size guard waived — same human-rate volume as Request.
pub const Result = struct {
    kind: Kind,
    /// Owns the parsed value / failure strings. Heap-allocated so ownership
    /// can cross the thread boundary; destroyed by freeResult.
    arena: *std.heap.ArenaAllocator,
    outcome: Outcome,

    pub const Outcome = union(enum) {
        /// Posts for a content screen (profile/thread/zone) — the UI ingests
        /// them as CONTENT (`feed_core.ingestPosts`, no Home ordering rows);
        /// the view's ordering stays a pure query over the store.
        page: lexicon.TimelinePage,
        /// The zone catalog (listTags) for the browse screen — the UI merges
        /// it over the locally-derived set it built at view entry.
        zones: []const lexicon.TagView,
        /// The marketplace browse page (getAlgorithms) — the UI copies the
        /// rows it keeps into its own catalog.
        algorithms: []const lexicon.AlgorithmView,
        /// The server refused. Strings live in `arena` — copy (e.g. into a
        /// status buffer) before freeing the result.
        refused: struct { status: u16, code: []const u8 },
        /// Transport/local failure: the error name (@errorName — static
        /// storage, never freed).
        net_error: []const u8,
    };
};

pub fn freeResult(gpa: Allocator, r: Result) void {
    r.arena.deinit();
    gpa.destroy(r.arena);
}

pub const RequestBox = write_worker.Mailbox(Request);
pub const ResultBox = write_worker.Mailbox(Result);

// ---------------------------------------------------------------------------
// The worker
// ---------------------------------------------------------------------------

pub const Worker = struct {
    // A7.2: cold struct, size guard waived — exactly one per session.
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    appview_url: []const u8,
    inbox: *RequestBox,
    outbox: *ResultBox,
    thread: std.Thread,
    stop: std.atomic.Value(bool),
};

/// Enqueue a view load from the UI thread — returns immediately. On true the
/// worker OWNS `target` (the caller's gpa copy of the view's target param);
/// on false (mailbox OOM — the load is simply dropped; re-entering the view
/// retries) the caller keeps it.
pub fn submit(worker: *Worker, kind: Kind, target: ?[]u8, limit: u32) bool {
    return worker.inbox.push(worker.gpa, .{ .kind = kind, .target = target, .limit = limit });
}

pub fn start(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    appview_url: []const u8,
    inbox: *RequestBox,
    outbox: *ResultBox,
) !*Worker {
    const worker = try gpa.create(Worker);
    worker.* = .{
        .gpa = gpa,
        .io = io,
        .environ = environ,
        .session = session,
        .appview_url = appview_url,
        .inbox = inbox,
        .outbox = outbox,
        .thread = undefined,
        .stop = .init(false),
    };
    worker.thread = try std.Thread.spawn(.{}, threadMain, .{worker});
    return worker;
}

/// Signal stop and join; drain and free anything still queued (C5/C6).
pub fn shutdown(worker: *Worker) void {
    worker.stop.store(true, .release);
    worker.thread.join();
    const gpa = worker.gpa;
    var pending: std.ArrayList(Request) = .empty;
    defer pending.deinit(gpa);
    worker.inbox.drain(gpa, &pending) catch {};
    for (pending.items) |req| if (req.target) |t| gpa.free(t);
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
            clock.sleepMillis(20);
            continue;
        };
        if (batch.items.len == 0) {
            // Idle: poll. View entries arrive at tap rate; a 15ms poll is
            // invisible latency against the fetch's own round trip.
            clock.sleepMillis(15);
            continue;
        }
        for (batch.items) |req| {
            if (worker.stop.load(.acquire)) {
                // Unprocessed requests still own their target copies (C5).
                if (req.target) |t| gpa.free(t);
                continue;
            }
            processOne(worker, req);
        }
    }
}

fn processOne(worker: *Worker, req: Request) void {
    const gpa = worker.gpa;
    // The request owns its target copy — freed here on every path (C5).
    defer if (req.target) |t| gpa.free(t);
    // The result's arena: it must OUTLIVE this call (the UI ingests from it
    // later), so it is heap-created and travels inside the Result (C5: freed
    // by exactly one owner, freeResult, on every path).
    const arena_ptr = gpa.create(std.heap.ArenaAllocator) catch return; // load dropped; re-entering the view retries
    arena_ptr.* = std.heap.ArenaAllocator.init(gpa);

    const result: Result = .{
        .kind = req.kind,
        .arena = arena_ptr,
        .outcome = fetchOutcome(worker, arena_ptr.allocator(), req),
    };
    if (!worker.outbox.push(gpa, result)) freeResult(gpa, result);
}

/// Run the request's network half and shape the answer. Everything
/// (including OOM inside the fetch) is contained to this request (E2): a
/// status line on the UI, retried on the next view entry.
fn fetchOutcome(worker: *Worker, arena: Allocator, req: Request) Result.Outcome {
    const target = req.target orelse "";
    switch (req.kind) {
        .profile => {
            const fetched = feed_shell.fetchAuthorPage(
                worker.gpa,
                arena,
                worker.io,
                worker.environ,
                worker.session,
                worker.appview_url,
                target,
                req.limit,
            ) catch |err| return .{ .net_error = @errorName(err) };
            return switch (fetched) {
                .ok => |page| .{ .page = page },
                .failed => |f| .{ .refused = .{ .status = f.status, .code = f.code } },
            };
        },
        .thread => {
            const fetched = feed_shell.fetchThreadPage(
                worker.gpa,
                arena,
                worker.io,
                worker.environ,
                worker.session,
                worker.appview_url,
                target,
                req.limit,
            ) catch |err| return .{ .net_error = @errorName(err) };
            return switch (fetched) {
                // The thread arrives flat; hand it on as a page (plain
                // reshaping — the arena owns the posts either way) so the
                // UI runs the one content ingest for every post screen.
                .ok => |thread| .{ .page = .{ .feed = thread.posts } },
                .failed => |f| .{ .refused = .{ .status = f.status, .code = f.code } },
            };
        },
        .zone => {
            const fetched = feed_shell.fetchZonePage(
                worker.gpa,
                arena,
                worker.io,
                worker.environ,
                worker.session,
                worker.appview_url,
                target,
                req.limit,
            ) catch |err| return .{ .net_error = @errorName(err) };
            return switch (fetched) {
                .ok => |page| .{ .page = page },
                .failed => |f| .{ .refused = .{ .status = f.status, .code = f.code } },
            };
        },
        .zones => {
            const fetched = feed_shell.loadZones(
                worker.gpa,
                arena,
                worker.io,
                worker.environ,
                worker.session,
                worker.appview_url,
            ) catch |err| return .{ .net_error = @errorName(err) };
            return switch (fetched) {
                .ok => |tags| .{ .zones = tags },
                .failed => |f| .{ .refused = .{ .status = f.status, .code = f.code } },
            };
        },
        .algorithms => {
            const fetched = feed_shell.loadAlgorithms(
                worker.gpa,
                arena,
                worker.io,
                worker.environ,
                worker.session,
                worker.appview_url,
                req.limit,
            ) catch |err| return .{ .net_error = @errorName(err) };
            return switch (fetched) {
                .ok => |algos| .{ .algorithms = algos },
                .failed => |f| .{ .refused = .{ .status = f.status, .code = f.code } },
            };
        },
    }
}

// ---------------------------------------------------------------------------
// Tests (C6) — the mailbox hand-off and result hygiene, no network
// ---------------------------------------------------------------------------

const testing = std.testing;

test "mailbox: requests push and drain; target ownership is per-request" {
    const gpa = testing.allocator;
    var box: RequestBox = .{};
    defer box.deinit(gpa);

    const actor = try gpa.dupe(u8, "did:plc:someone");
    try testing.expect(box.push(gpa, .{ .kind = .profile, .target = actor, .limit = 30 }));

    var out: std.ArrayList(Request) = .empty;
    defer out.deinit(gpa);
    try box.drain(gpa, &out);
    try testing.expectEqual(@as(usize, 1), out.items.len);
    try testing.expectEqual(Kind.profile, out.items[0].kind);
    try testing.expectEqualStrings("did:plc:someone", out.items[0].target.?);
    // The drain hands ownership onward — freed the way processOne does (C6
    // fails this test if the copy leaks).
    for (out.items) |req| if (req.target) |t| gpa.free(t);
}

test "result hygiene: the arena crosses the boundary and frees without leak" {
    const gpa = testing.allocator;
    // Build a result the way processOne does: page bytes in a heap arena.
    const arena_ptr = try gpa.create(std.heap.ArenaAllocator);
    arena_ptr.* = std.heap.ArenaAllocator.init(gpa);
    const cursor = try arena_ptr.allocator().dupe(u8, "cursor-token");

    var box: ResultBox = .{};
    defer box.deinit(gpa);
    try testing.expect(box.push(gpa, .{
        .kind = .profile,
        .arena = arena_ptr,
        .outcome = .{ .page = .{ .cursor = cursor } },
    }));

    var out: std.ArrayList(Result) = .empty;
    defer out.deinit(gpa);
    try box.drain(gpa, &out);
    try testing.expectEqual(@as(usize, 1), out.items.len);
    const res = out.items[0];
    try testing.expectEqualStrings("cursor-token", res.outcome.page.cursor.?);
    freeResult(gpa, res); // the leak detector (C6) fails this test if the arena leaks
}
