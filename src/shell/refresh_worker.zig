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

//! B1 classification: SHELL. The **refresh worker** — the same actor pattern
//! as write_worker.zig (whose Mailbox it reuses): its own thread, its own
//! per-request arena (C4), plain-data messages through two mailboxes (E1),
//! failure contained to a result message (E2).
//!
//! WHY THIS EXISTS: the auto-refresh is a getTimeline round trip (100–500ms).
//! Done inline on the render thread it froze EVERYTHING that frame — the
//! living glyph field visibly hitched on every tick (the periodic split-second
//! freeze). The old input-idle gate only protected keystrokes; the field
//! animates precisely when the user is idle, so the gate guaranteed the fetch
//! landed mid-animation. Moving the fetch here means the render loop only
//! drops a request and drains a result: the network is fully exiled off the
//! frame path (G4: responsiveness is the invariant).
//!
//! Split of labour: this worker runs ONLY the network half
//! (`feed.fetchRefreshPage`) — the store is owned by the UI thread, so the
//! ingest half (`feed_core.ingestPageRefresh`) runs there, on the drained
//! page. Wire/HTTP knowledge stays in feed.zig/auth.zig (D3); this file only
//! moves request/result VALUES across the thread boundary. Sharing the
//! *auth.Session with the UI and write-worker threads is safe by design:
//! credential mutation is serialized by Session.cred_lock (auth.zig).

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

/// Who asked for the refresh. Carried through to the Result because the UI
/// treats them differently: an AUTO tick stages new posts behind the pill
/// (revealing only at top-of-Home or on the first load), while an explicit
/// PULL reveals and jumps — the reader asked to SEE the new.
pub const Trigger = enum(u8) { auto, pull };

/// A refresh ask. No owned bytes — everything the fetch needs (session,
/// appview_url, io) is captured once in the Worker at start.
/// A7.2: cold struct, size guard waived — one every few seconds at most,
/// never held in quantity or walked in a hot loop.
pub const Request = struct {
    trigger: Trigger,
    limit: u32,
};

/// What the worker reports back: the fetched page (or the failure), plus the
/// arena that owns every byte the outcome references. The UI ingests the page
/// into the store, THEN frees the result — the arena crosses the boundary as
/// an owned value, exactly like the write worker's owned strings.
/// A7.2: cold struct, size guard waived — same human-rate volume as Request.
pub const Result = struct {
    trigger: Trigger,
    /// Owns the parsed page / failure strings. Heap-allocated so ownership
    /// can cross the thread boundary; destroyed by freeResult.
    arena: *std.heap.ArenaAllocator,
    outcome: Outcome,

    pub const Outcome = union(enum) {
        /// The newest timeline page; every slice lives in `arena`.
        ok: lexicon.TimelinePage,
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

/// Enqueue a refresh from the UI thread — returns immediately. False only
/// on OOM (that tick is simply skipped; the next interval retries).
pub fn submit(worker: *Worker, trigger: Trigger, limit: u32) bool {
    return worker.inbox.push(worker.gpa, .{ .trigger = trigger, .limit = limit });
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
    // Requests own no bytes; nothing further to free.
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
            // Idle: poll. Refresh ticks arrive every few seconds; a 15ms
            // poll is invisible latency at that rate.
            clock.sleepMillis(15);
            continue;
        }
        for (batch.items) |req| {
            if (worker.stop.load(.acquire)) return; // requests own no bytes
            processOne(worker, req);
        }
    }
}

fn processOne(worker: *Worker, req: Request) void {
    const gpa = worker.gpa;
    // The result's arena: it must OUTLIVE this call (the UI ingests from it
    // later), so it is heap-created and travels inside the Result (C5: freed
    // by exactly one owner, freeResult, on every path).
    const arena_ptr = gpa.create(std.heap.ArenaAllocator) catch return; // tick skipped; next interval retries
    arena_ptr.* = std.heap.ArenaAllocator.init(gpa);
    const arena = arena_ptr.allocator();

    const outcome: Result.Outcome = if (feed_shell.fetchRefreshPage(
        gpa,
        arena,
        worker.io,
        worker.environ,
        worker.session,
        worker.appview_url,
        req.limit,
    )) |fetched| switch (fetched) {
        .ok => |page| .{ .ok = page },
        .failed => |f| .{ .refused = .{ .status = f.status, .code = f.code } },
    } else |err|
        // Everything (including OOM inside the fetch) is contained to this
        // request (E2): a status line on the UI, retried next tick.
        .{ .net_error = @errorName(err) };

    const result: Result = .{ .trigger = req.trigger, .arena = arena_ptr, .outcome = outcome };
    if (!worker.outbox.push(gpa, result)) freeResult(gpa, result);
}

// ---------------------------------------------------------------------------
// Tests (C6) — the mailbox hand-off and result hygiene, no network
// ---------------------------------------------------------------------------

const testing = std.testing;

test "mailbox: requests push and drain; deinit frees the backing array" {
    const gpa = testing.allocator;
    var box: RequestBox = .{};
    defer box.deinit(gpa);

    try testing.expect(box.push(gpa, .{ .trigger = .auto, .limit = 30 }));
    try testing.expect(box.push(gpa, .{ .trigger = .pull, .limit = 30 }));

    var out: std.ArrayList(Request) = .empty;
    defer out.deinit(gpa);
    try box.drain(gpa, &out);
    try testing.expectEqual(@as(usize, 2), out.items.len);
    try testing.expectEqual(Trigger.auto, out.items[0].trigger);
    try testing.expectEqual(Trigger.pull, out.items[1].trigger);
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
        .trigger = .auto,
        .arena = arena_ptr,
        .outcome = .{ .ok = .{ .cursor = cursor } },
    }));

    var out: std.ArrayList(Result) = .empty;
    defer out.deinit(gpa);
    try box.drain(gpa, &out);
    try testing.expectEqual(@as(usize, 1), out.items.len);
    const res = out.items[0];
    try testing.expectEqualStrings("cursor-token", res.outcome.ok.cursor.?);
    freeResult(gpa, res); // the leak detector (C6) fails this test if the arena leaks
}
