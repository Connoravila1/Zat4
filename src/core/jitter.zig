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

//! B1 classification: CORE (pure). The jitter buffer — reorders RTP packets
//! arriving out of order into a clean playout sequence, surfaces loss gaps for
//! NACK, and bounds its own memory. Plus `shouldDecode`, the receiver-side
//! decode-skip predicate (ZAT_CHAT_CALLING_ROADMAP.md §9.1), and `depthForJitter`,
//! the adaptive-depth policy (§7.6). This is the media-transport playout layer
//! the "build it ourselves" ruling unlocks.
//!
//! PURE (B2/B3/B4): no clock, no RNG, no I/O. The buffer takes an `Allocator`
//! (C1) for its fixed ring and copies payloads in on insert (it owns its bytes,
//! C4). Adaptive depth is a pure function of a jitter estimate the shell hands
//! in — the core never reads a clock (B4). Opus's own in-band FEC/PLC carries
//! concealment, so this stays a plain reorder+loss buffer rather than a NetEq
//! reimplementation (settled decision, roadmap §3). Fully unit-testable
//! headlessly and leak-checked (C6) — see the tests at the foot.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

/// PLAIN DATA (A1). One buffered packet's metadata — HOT (the buffer holds many
/// and scans them). Payload bytes live in a parallel arena keyed by physical
/// slot id; this record is only the metadata (A6).
pub const Slot = struct {
    timestamp: u32, // media-clock timestamp
    len: u32, // payload length in the arena
    seq: u16, // RTP sequence number
    _pad: u16 = 0, // A6: explicit pad to the u32 alignment boundary

    comptime {
        // Budget: u32+u32 = 8, then u16+u16 = 4. 12 exact, align 4, no tail pad.
        assert(@sizeOf(Slot) == 12);
    }
};

/// The outcome of an insert. Errors defined out of existence (E4): a duplicate,
/// a too-late, or an oversize packet is an ordinary result, not an error path.
pub const InsertResult = enum { accepted, duplicate, too_late, too_large };

/// A popped packet ready for playout. A7.2: cold struct, size guard waived — a
/// transient return value. `gap_skipped` is true when the buffer gave up
/// waiting for a lost packet and advanced past the gap.
pub const Popped = struct {
    seq: u16,
    timestamp: u32,
    payload: []const u8,
    gap_skipped: bool,
};

/// PLAIN DATA (A1). The jitter buffer's storage and cursors. A7.2: cold struct,
/// size guard waived — exactly one per receiving stream, never held in a
/// collection or scanned in bulk. Its hot data is the SoA slices below.
pub const JitterBuffer = struct {
    // Physical storage, indexed by slot id (A3 — struct-of-arrays).
    seqs: []u16,
    tss: []u32,
    lens: []u32,
    payloads: []u8, // capacity * max_payload, slot id i at [i*max_payload..]
    // `order` holds the physical slot ids of the buffered packets, kept sorted
    // ascending in serial-number order; `count` is how many are live.
    order: []u16,
    free_ids: []u16, // a free-slot stack
    free_top: usize,
    count: usize,
    capacity: u16,
    max_payload: u32,
    next_seq: u16, // the sequence expected next at playout
    target_depth: u16, // packets to buffer before forcing playout past a gap
    started: bool, // has playout begun (is next_seq valid)?
};

pub fn init(gpa: Allocator, jb: *JitterBuffer, capacity: u16, max_payload: u32, target_depth: u16) Allocator.Error!void {
    assert(capacity > 0 and max_payload > 0);
    const cap: usize = capacity;
    const seqs = try gpa.alloc(u16, cap);
    errdefer gpa.free(seqs);
    const tss = try gpa.alloc(u32, cap);
    errdefer gpa.free(tss);
    const lens = try gpa.alloc(u32, cap);
    errdefer gpa.free(lens);
    const payloads = try gpa.alloc(u8, cap * max_payload);
    errdefer gpa.free(payloads);
    const order = try gpa.alloc(u16, cap);
    errdefer gpa.free(order);
    const free_ids = try gpa.alloc(u16, cap);
    errdefer gpa.free(free_ids);

    for (free_ids, 0..) |*f, i| f.* = @intCast(cap - 1 - i); // fill the free stack
    jb.* = .{
        .seqs = seqs,
        .tss = tss,
        .lens = lens,
        .payloads = payloads,
        .order = order,
        .free_ids = free_ids,
        .free_top = cap,
        .count = 0,
        .capacity = capacity,
        .max_payload = max_payload,
        .next_seq = 0,
        .target_depth = @min(target_depth, capacity),
        .started = false,
    };
}

pub fn deinit(gpa: Allocator, jb: *JitterBuffer) void {
    gpa.free(jb.seqs);
    gpa.free(jb.tss);
    gpa.free(jb.lens);
    gpa.free(jb.payloads);
    gpa.free(jb.order);
    gpa.free(jb.free_ids);
    jb.* = undefined;
}

/// Serial-number "less than" (RFC 1982): true when `a` precedes `b` within the
/// half-space window, so wraparound orders correctly inside a jitter window.
fn serialLess(a: u16, b: u16) bool {
    return a != b and (b -% a) < 0x8000;
}

fn slotPayload(jb: *JitterBuffer, id: u16) []u8 {
    const base = @as(usize, id) * jb.max_payload;
    return jb.payloads[base..][0..jb.lens[id]];
}

fn popFree(jb: *JitterBuffer) u16 {
    jb.free_top -= 1;
    return jb.free_ids[jb.free_top];
}

fn pushFree(jb: *JitterBuffer, id: u16) void {
    jb.free_ids[jb.free_top] = id;
    jb.free_top += 1;
}

/// Insert a received packet. Deduplicates, drops packets already played out,
/// and evicts the oldest buffered packet when full so memory stays bounded.
pub fn insert(jb: *JitterBuffer, seq: u16, timestamp: u32, payload: []const u8) InsertResult {
    if (payload.len > jb.max_payload) return .too_large;
    if (jb.started and serialLess(seq, jb.next_seq)) return .too_late;

    // Find the sorted insertion position; detect duplicates along the way.
    var pos: usize = 0;
    while (pos < jb.count) : (pos += 1) {
        const s = jb.seqs[jb.order[pos]];
        if (s == seq) return .duplicate;
        if (serialLess(seq, s)) break;
    }

    // Full: evict the oldest (order[0]) to admit the newcomer, unless the
    // newcomer IS the oldest, in which case there is no room — drop it.
    if (jb.count == jb.capacity) {
        if (pos == 0) return .too_late;
        const evicted = jb.order[0];
        std.mem.copyForwards(u16, jb.order[0 .. jb.count - 1], jb.order[1..jb.count]);
        jb.count -= 1;
        pushFree(jb, evicted);
        pos -= 1; // positions shifted left by the eviction
    }

    const id = popFree(jb);
    jb.seqs[id] = seq;
    jb.tss[id] = timestamp;
    jb.lens[id] = @intCast(payload.len);
    @memcpy(jb.payloads[@as(usize, id) * jb.max_payload ..][0..payload.len], payload);

    // Open a hole at `pos` in `order` and drop the id in.
    var k: usize = jb.count;
    while (k > pos) : (k -= 1) jb.order[k] = jb.order[k - 1];
    jb.order[pos] = id;
    jb.count += 1;
    return .accepted;
}

/// Pop the next packet for playout, or null if we should keep waiting. On the
/// first pop, playout begins at the earliest buffered sequence. When the head
/// is the expected next sequence, it is returned in order. When a gap sits at
/// the head, we wait until the buffer has reached `target_depth`, then declare
/// the gap lost and advance past it (`gap_skipped = true`).
pub fn pop(jb: *JitterBuffer) ?Popped {
    if (jb.count == 0) return null;
    if (!jb.started) {
        jb.started = true;
        jb.next_seq = jb.seqs[jb.order[0]];
    }
    const head_seq = jb.seqs[jb.order[0]];
    var gap_skipped = false;
    if (head_seq != jb.next_seq) {
        // A gap at the head: hold until we've buffered enough, then skip it.
        if (jb.count < jb.target_depth) return null;
        jb.next_seq = head_seq;
        gap_skipped = true;
    }
    const id = jb.order[0];
    std.mem.copyForwards(u16, jb.order[0 .. jb.count - 1], jb.order[1..jb.count]);
    jb.count -= 1;
    jb.next_seq = head_seq +% 1;
    const out: Popped = .{
        .seq = jb.seqs[id],
        .timestamp = jb.tss[id],
        .payload = slotPayload(jb, id),
        .gap_skipped = gap_skipped,
    };
    pushFree(jb, id);
    return out;
}

/// The sequence number the playout is currently missing (present as a gap
/// before buffered packets) — the candidate to NACK. Null when the head is in
/// order or playout hasn't begun.
pub fn nextGap(jb: *const JitterBuffer) ?u16 {
    if (!jb.started or jb.count == 0) return null;
    const head_seq = jb.seqs[jb.order[0]];
    return if (head_seq != jb.next_seq) jb.next_seq else null;
}

// ---------------------------------------------------------------------------
// Pure policy helpers
// ---------------------------------------------------------------------------

pub const FrameType = enum(u8) { key, delta };

/// Receiver-side decode-skip predicate (roadmap §9.1). Always decode keyframes;
/// always decode after `max_skips` consecutive skips (prevents drift); always
/// decode when the payload jumps back above `motion_threshold` (motion
/// resumed); otherwise skip a small delta frame (the remote party is still).
pub fn shouldDecode(payload_size: u32, frame_type: FrameType, consecutive_skips: u32, motion_threshold: u32, max_skips: u32) bool {
    if (frame_type == .key) return true;
    if (consecutive_skips >= max_skips) return true;
    if (payload_size >= motion_threshold) return true;
    return false;
}

/// Adaptive target depth (in packets) for a measured network jitter. Buffer
/// roughly two jitters' worth of frames, clamped to a sane range. Pure function
/// of the shell-supplied estimate (§7.6) — the core never reads a clock.
pub fn depthForJitter(jitter_ms: u32, frame_ms: u32, min_depth: u16, max_depth: u16) u16 {
    const fm = @max(frame_ms, 1);
    const frames = (jitter_ms * 2 + fm - 1) / fm; // ceil(2*jitter / frame)
    const clamped = std.math.clamp(frames, @as(u32, min_depth), @as(u32, max_depth));
    return @intCast(clamped);
}

// ---------------------------------------------------------------------------
// Tests (B2/C6 — leak-checked, deterministic)
// ---------------------------------------------------------------------------

const testing = std.testing;

test "reorders out-of-order arrivals into a clean playout sequence" {
    const gpa = testing.allocator; // C6
    var jb: JitterBuffer = undefined;
    try init(gpa, &jb, 16, 64, 3);
    defer deinit(gpa, &jb);

    // Arrive 10, 12, 11, 13 (11 and 12 swapped).
    try testing.expectEqual(InsertResult.accepted, insert(&jb, 10, 100, "a"));
    try testing.expectEqual(InsertResult.accepted, insert(&jb, 12, 120, "c"));
    try testing.expectEqual(InsertResult.accepted, insert(&jb, 11, 110, "b"));
    try testing.expectEqual(InsertResult.accepted, insert(&jb, 13, 130, "d"));

    // Playout is in ascending sequence order.
    var seqs: [4]u16 = undefined;
    for (&seqs) |*s| s.* = pop(&jb).?.seq;
    try testing.expectEqualSlices(u16, &.{ 10, 11, 12, 13 }, &seqs);
}

test "duplicates and already-played packets are dropped" {
    const gpa = testing.allocator;
    var jb: JitterBuffer = undefined;
    try init(gpa, &jb, 8, 32, 1);
    defer deinit(gpa, &jb);

    try testing.expectEqual(InsertResult.accepted, insert(&jb, 5, 50, "x"));
    try testing.expectEqual(InsertResult.duplicate, insert(&jb, 5, 50, "x"));
    _ = pop(&jb); // plays seq 5, next_seq becomes 6
    try testing.expectEqual(InsertResult.too_late, insert(&jb, 5, 50, "x"));
    try testing.expectEqual(InsertResult.too_large, insert(&jb, 6, 60, "this-payload-is-definitely-longer-than-32-bytes"));
}

test "a loss gap is held until target depth, then skipped" {
    const gpa = testing.allocator;
    var jb: JitterBuffer = undefined;
    try init(gpa, &jb, 16, 32, 3);
    defer deinit(gpa, &jb);

    // seq 20 lost; 21, 22, 23 arrive.
    _ = insert(&jb, 21, 210, "b");
    // First pop starts playout at 21 (earliest available) and returns it.
    try testing.expectEqual(@as(u16, 21), pop(&jb).?.seq);
    // Now expecting 22; only 21 was seen. Insert 23, 25 — a gap at 22.
    _ = insert(&jb, 23, 230, "d");
    _ = insert(&jb, 25, 250, "f");
    // Head is 23, expected 22 → gap. Depth (2) < target (3): wait.
    try testing.expect(pop(&jb) == null);
    try testing.expectEqual(@as(u16, 22), nextGap(&jb).?); // NACK candidate
    // Buffer reaches depth 3.
    _ = insert(&jb, 27, 270, "h");
    const p = pop(&jb).?;
    try testing.expectEqual(@as(u16, 23), p.seq);
    try testing.expect(p.gap_skipped); // gave up on 22
}

test "full buffer evicts the oldest to admit newer packets (bounded memory)" {
    const gpa = testing.allocator;
    var jb: JitterBuffer = undefined;
    try init(gpa, &jb, 3, 16, 3);
    defer deinit(gpa, &jb);

    _ = insert(&jb, 100, 0, "a");
    _ = insert(&jb, 101, 0, "b");
    _ = insert(&jb, 102, 0, "c");
    // Full (3). Admitting 103 evicts 100.
    try testing.expectEqual(InsertResult.accepted, insert(&jb, 103, 0, "d"));
    // Admitting something older than everything buffered is dropped.
    try testing.expectEqual(InsertResult.too_late, insert(&jb, 100, 0, "a"));
    // Playout now starts at 101 (100 was evicted).
    try testing.expectEqual(@as(u16, 101), pop(&jb).?.seq);
}

test "shouldDecode: keyframes and motion always decode; small still deltas skip" {
    // Keyframe always decodes.
    try testing.expect(shouldDecode(50, .key, 0, 500, 10));
    // Small delta while still → skip.
    try testing.expect(!shouldDecode(50, .delta, 0, 500, 10));
    // Payload jumps back up → motion resumed → decode.
    try testing.expect(shouldDecode(900, .delta, 3, 500, 10));
    // Too many consecutive skips → force a decode to prevent drift.
    try testing.expect(shouldDecode(50, .delta, 10, 500, 10));
}

test "depthForJitter buffers ~2 jitters of frames, clamped" {
    // 60ms jitter, 20ms frames → ceil(120/20)=6 packets.
    try testing.expectEqual(@as(u16, 6), depthForJitter(60, 20, 2, 20));
    // Tiny jitter clamps to the floor.
    try testing.expectEqual(@as(u16, 2), depthForJitter(1, 20, 2, 20));
    // Huge jitter clamps to the ceiling.
    try testing.expectEqual(@as(u16, 20), depthForJitter(10_000, 20, 2, 20));
}

test "playout is deterministic for the same arrival order (B2)" {
    const gpa = testing.allocator;
    var a: JitterBuffer = undefined;
    var b: JitterBuffer = undefined;
    try init(gpa, &a, 16, 16, 2);
    defer deinit(gpa, &a);
    try init(gpa, &b, 16, 16, 2);
    defer deinit(gpa, &b);

    const arrivals = [_]u16{ 4, 2, 3, 7, 5 };
    for (arrivals) |s| {
        _ = insert(&a, s, s, "p");
        _ = insert(&b, s, s, "p");
    }
    var i: usize = 0;
    while (i < 3) : (i += 1) {
        const pa = pop(&a);
        const pb = pop(&b);
        try testing.expectEqual(pa.?.seq, pb.?.seq);
        try testing.expectEqual(pa.?.gap_skipped, pb.?.gap_skipped);
    }
}
