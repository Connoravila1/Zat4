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

//! B1 classification: CORE (pure). The JSON → IPLD bridge that makes CID
//! recompute work on real wire records.
//!
//! atproto records reach the client as JSON (an AppView `listRecords` /
//! timeline response), but a record's CID is the hash of its *DAG-CBOR* bytes.
//! To recompute a CID and check it (SECURITY_ROADMAP Phase 2 / A8) we must turn
//! the JSON value back into the IPLD data model, re-encode it canonically
//! (`core/dagcbor.zig`), hash, and compare (`core/cid.zig`).
//!
//! The conversion honours atproto's data-model JSON conventions:
//!   - `{"$link": "<cid>"}`  → an IPLD link (CBOR tag 42);
//!   - `{"$bytes": "<b64>"}` → a byte string (standard base64, no padding);
//!   - objects → maps, arrays → lists, integers → ints, and floats are
//!     **rejected** (the atproto data model has no float type — a record that
//!     carries one is not one we will vouch for).
//!
//! Pure (B2/B4): JSON parsing and re-encoding are deterministic computation,
//! not I/O. All scratch lives in an arena freed wholesale (C3); the shell hands
//! in the record bytes and the claimed CID and gets a yes/no back.

const std = @import("std");
const dagcbor = @import("dagcbor.zig");
const cid = @import("cid.zig");

/// Recursion bound for the conversion, matching the encoder's, so adversarial
/// nesting is a clean error rather than a stack overflow (Phase 2).
const max_depth = dagcbor.max_depth;

pub const ConvertError = error{
    UnsupportedNumber, // a float or an out-of-int64-range number — not in the atproto model
    MalformedLink, // a `$link` whose value isn't a parseable CID string
    MalformedBytes, // a `$bytes` whose value isn't valid base64
    TooDeep, // nesting past max_depth
} || std.mem.Allocator.Error;

/// Everything `verifyRecordCid` can report. A record that won't parse, won't
/// convert, or won't canonically encode cannot be vouched for (E3 — explicit,
/// never a silent false).
pub const VerifyError = error{MalformedJson} || ConvertError || dagcbor.EncodeError;

/// Recompute the CID of an atproto record (given as its JSON bytes) and confirm
/// it matches `claimed_cid`. True only when the record's canonical DAG-CBOR
/// hashes to exactly the claimed CID — the server's bytes are checked against
/// its own claim, never trusted (Phase 2).
pub fn verifyRecordCid(
    gpa: std.mem.Allocator,
    record_json: []const u8,
    claimed_cid: []const u8,
) VerifyError!bool {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const parsed = std.json.parseFromSliceLeaky(std.json.Value, arena, record_json, .{}) catch
        return error.MalformedJson;
    const value = try convert(arena, parsed, 0);
    return cid.verifyValue(gpa, value, claimed_cid);
}

/// Convert a parsed JSON value into the IPLD `dagcbor.Value` model. Allocates
/// the converted tree in `arena`; returned slices borrow from `arena` and the
/// parsed JSON (both outlive the caller's use within `verifyRecordCid`).
fn convert(arena: std.mem.Allocator, jv: std.json.Value, depth: usize) ConvertError!dagcbor.Value {
    if (depth >= max_depth) return error.TooDeep;
    return switch (jv) {
        .null => .null,
        .bool => |b| .{ .bool = b },
        .integer => |n| .{ .int = n },
        .float, .number_string => error.UnsupportedNumber,
        .string => |s| .{ .string = s },
        .array => |arr| blk: {
            const items = try arena.alloc(dagcbor.Value, arr.items.len);
            for (arr.items, items) |src, *dst| dst.* = try convert(arena, src, depth + 1);
            break :blk .{ .list = items };
        },
        .object => |obj| try convertObject(arena, obj, depth),
    };
}

fn convertObject(arena: std.mem.Allocator, obj: std.json.ObjectMap, depth: usize) ConvertError!dagcbor.Value {
    // The two atproto data-model escapes are single-key objects.
    if (obj.count() == 1) {
        if (obj.get("$link")) |lv| {
            const s = switch (lv) {
                .string => |x| x,
                else => return error.MalformedLink,
            };
            var bin: [cid.binary_len]u8 = undefined;
            cid.parse(s, &bin) catch return error.MalformedLink;
            return .{ .link = try arena.dupe(u8, &bin) };
        }
        if (obj.get("$bytes")) |bv| {
            const s = switch (bv) {
                .string => |x| x,
                else => return error.MalformedBytes,
            };
            const dec = std.base64.standard_no_pad.Decoder;
            const n = dec.calcSizeForSlice(s) catch return error.MalformedBytes;
            const buf = try arena.alloc(u8, n);
            dec.decode(buf, s) catch return error.MalformedBytes;
            return .{ .bytes = buf };
        }
    }

    const entries = try arena.alloc(dagcbor.Entry, obj.count());
    var it = obj.iterator();
    var i: usize = 0;
    while (it.next()) |e| : (i += 1) {
        entries[i] = .{ .key = e.key_ptr.*, .value = try convert(arena, e.value_ptr.*, depth + 1) };
    }
    return .{ .map = entries };
}

// ---------------------------------------------------------------------------
// Tests (C6). The record CIDs were computed independently (Python hashlib +
// stdlib base32 over hand-built DAG-CBOR), so a match proves the whole
// JSON → IPLD → DAG-CBOR → CID pipeline, not mere self-consistency.
// ---------------------------------------------------------------------------

const testing = std.testing;

// CID of the dag-cbor block {"hello":"world"} (also used as a $link value).
const hello_cid = "bafyreidykglsfhoixmivffc5uwhcgshx4j465xwqntbmu43nb2dzqwfvae";

test "verifyRecordCid: a record verifies against its true CID" {
    try testing.expect(try verifyRecordCid(testing.allocator, "{\"hello\":\"world\"}", hello_cid));
}

test "verifyRecordCid: integers + list, with JSON keys OUT of canonical order" {
    // {"a":1,"bb":[2,3]} canonicalizes regardless of the JSON key order.
    const rec = "{\"bb\":[2,3],\"a\":1}";
    const want = "bafyreihseod2drnfyknrg77oquxpf74wdko7hk6ksgcrksts6vq2i5kwn4";
    try testing.expect(try verifyRecordCid(testing.allocator, rec, want));
}

test "verifyRecordCid: $bytes decodes to a CBOR byte string" {
    // {"d": bytes(01020304)} via base64 "AQIDBA".
    const rec = "{\"d\":{\"$bytes\":\"AQIDBA\"}}";
    const want = "bafyreiaump5lrzw53b5wethn74ps6i4r6tghvix2iarqtdje2kjf4jeuba";
    try testing.expect(try verifyRecordCid(testing.allocator, rec, want));
}

test "verifyRecordCid: $link becomes a CBOR tag-42 CID link" {
    const rec = "{\"r\":{\"$link\":\"" ++ hello_cid ++ "\"}}";
    const want = "bafyreihnw2dj7d7mavbl5wxi3liobj2tohyj6gmznsuc7lqbvlucx5wfdy";
    try testing.expect(try verifyRecordCid(testing.allocator, rec, want));
}

test "verifyRecordCid: a CID for different content does not match" {
    const rec1 = "bafyreihseod2drnfyknrg77oquxpf74wdko7hk6ksgcrksts6vq2i5kwn4";
    try testing.expect(!try verifyRecordCid(testing.allocator, "{\"hello\":\"world\"}", rec1));
}

test "verifyRecordCid: malformed input is an explicit error, never a false-positive" {
    try testing.expectError(error.MalformedJson, verifyRecordCid(testing.allocator, "{not json", hello_cid));
    try testing.expectError(error.UnsupportedNumber, verifyRecordCid(testing.allocator, "{\"x\":1.5}", hello_cid));
    try testing.expectError(error.MalformedLink, verifyRecordCid(testing.allocator, "{\"$link\":\"not-a-cid\"}", hello_cid));
    try testing.expectError(error.MalformedBytes, verifyRecordCid(testing.allocator, "{\"$bytes\":\"!!!!\"}", hello_cid));
}
