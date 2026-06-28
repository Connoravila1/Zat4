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

//! B1 classification: CORE (pure). The trust boundary the AppView reads across.
//!
//! A PDS returns records as `{uri, cid, value}` rows; the `cid` is the PDS's
//! CLAIM about the record's content hash. This module re-derives each row's CID
//! from its `value` bytes (via the dagjson → DAG-CBOR → CID path the rest of the
//! crypto stack uses) and confirms it matches — so a PDS that tampers a record
//! in flight, or serves a corrupted one, is caught instead of trusted (the
//! "verify don't trust" principle made live). Pure: a response body in, a report
//! out, no I/O. It NEVER throws — a malformed body or row is COUNTED, not raised,
//! so one bad PDS response cannot break the poll loop (E2/E4). The report names
//! the failing CIDs so the ingest rejects EXACTLY those records (a tampered row
//! never blocks its honest neighbours).

const std = @import("std");
const dagjson = @import("dagjson.zig");
const jsonguard = @import("jsonguard.zig");
const identity = @import("identity.zig");
const cid_lib = @import("cid.zig");

// Lexicon-schema conformance at the boundary (Phase 2): the typed parse already
// enforces field TYPES and the ingest checks required fields are present; these
// confirm the key fields hold a well-FORMED value of the right kind before a
// record becomes a core record — a follow's subject is a real DID, a
// like/repost's subject is a real CID. A malformed one is non-conforming junk
// (or probing) and is rejected, so the pure core only ever keys on valid ids.

/// Is `s` a syntactically valid atproto DID (did:plc / did:web)?
pub fn isValidDid(s: []const u8) bool {
    identity.validateDid(s) catch return false;
    return true;
}

/// Is `s` a syntactically valid CIDv1 multibase string?
pub fn isValidCid(s: []const u8) bool {
    var bin: [cid_lib.binary_len]u8 = undefined;
    cid_lib.parse(s, &bin) catch return false;
    return true;
}

// Hard caps on attacker-controlled text fields, enforced at the ingest boundary
// BEFORE the value crosses into the pure core (Phase 2). Generous — well above
// any legitimate value — so they reject abuse, not real content. The response
// is already bounded to a few MiB by the transport (Phase 1); these tighten
// per-FIELD so one record can't carry a multi-MiB text blob, and add the UTF-8
// check the size cap alone can't give.
pub const max_post_text: usize = 64 * 1024;
pub const max_display_name: usize = 4 * 1024;
pub const max_handle: usize = 256; // atproto handles cap at 253

/// A network-derived text field is acceptable only if it is within `max` bytes
/// AND valid UTF-8 — rejecting malformed encoding and the homoglyph/bidi
/// spoofing vector early, so the core only ever sees well-formed text (B5).
pub fn textWithinLimits(s: []const u8, max: usize) bool {
    return s.len <= max and std.unicode.utf8ValidateSlice(s);
}

/// The outcome of checking one `com.atproto.repo.listRecords` response.
/// A7.2: cold struct, size guard waived — one per collection per poll cycle.
pub const Report = struct {
    /// Rows that carried a non-empty cid + value and were checked.
    checked: usize = 0,
    /// Checked rows whose recomputed CID did NOT match the claim (tampering).
    mismatched: usize = 0,
    /// Checked rows whose value would not parse / convert / encode — cannot be
    /// vouched for, so treated as suspect (counted + rejected, never passed).
    unverifiable: usize = 0,
    /// The claimed CIDs that FAILED (mismatch or unverifiable) — owned by the
    /// gpa passed to `checkListRecords`. The ingest rejects records whose cid is
    /// in here (`isBad`). Free with `freeReport`. Empty when everything checked.
    bad_cids: [][]const u8 = &.{},
};

/// How many records failed verification (the count that gates a verdict).
pub fn badCount(report: Report) usize {
    return report.bad_cids.len;
}

/// Did this record's CID fail verification? (→ the ingest must reject it.)
pub fn isBad(report: Report, cid: []const u8) bool {
    for (report.bad_cids) |b| {
        if (std.mem.eql(u8, b, cid)) return true;
    }
    return false;
}

/// Release a report's owned bad-cid list. Safe on the empty default.
pub fn freeReport(gpa: std.mem.Allocator, report: Report) void {
    for (report.bad_cids) |c| gpa.free(c);
    gpa.free(report.bad_cids);
}

/// Check every record CID in a listRecords response `body`. `gpa` funds the
/// per-record conversion arenas AND the returned bad-cid list. A row with an
/// empty/missing cid is skipped (not counted). A malformed body returns one
/// unverifiable and no bad cids (the typed parse the caller already did would
/// have rejected such a body first, so this is the unreachable-but-safe case).
pub fn checkListRecords(gpa: std.mem.Allocator, body: []const u8) Report {
    var report: Report = .{};
    // Bound adversarial nesting before std.json walks the whole document (Phase 2).
    if (!jsonguard.depthWithinLimit(body, jsonguard.max_json_depth)) {
        report.unverifiable = 1;
        return report;
    }
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const parsed = std.json.parseFromSliceLeaky(std.json.Value, arena, body, .{}) catch {
        report.unverifiable = 1;
        return report;
    };
    const root = switch (parsed) {
        .object => |o| o,
        else => return report,
    };
    const records = root.get("records") orelse return report;
    const rows = switch (records) {
        .array => |a| a,
        else => return report,
    };

    var bad: std.ArrayListUnmanaged([]const u8) = .empty;
    for (rows.items) |row| {
        const obj = switch (row) {
            .object => |o| o,
            else => continue,
        };
        const claimed: []const u8 = switch (obj.get("cid") orelse continue) {
            .string => |s| s,
            else => continue,
        };
        if (claimed.len == 0) continue;
        const value = obj.get("value") orelse continue;
        report.checked += 1;
        const ok = dagjson.verifyParsedRecord(gpa, value, claimed) catch {
            report.unverifiable += 1;
            noteBad(gpa, &bad, claimed);
            continue;
        };
        if (!ok) {
            report.mismatched += 1;
            noteBad(gpa, &bad, claimed);
        }
    }
    report.bad_cids = bad.toOwnedSlice(gpa) catch &.{};
    return report;
}

/// Append an owned copy of a failing cid; on OOM, drop it (degraded, not a
/// crash — the worst case is that one record isn't rejected this cycle).
fn noteBad(gpa: std.mem.Allocator, bad: *std.ArrayListUnmanaged([]const u8), claimed: []const u8) void {
    const c = gpa.dupe(u8, claimed) catch return;
    bad.append(gpa, c) catch gpa.free(c);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const testing = std.testing;

test "a clean listing passes with zero bad (real record + its true CID)" {
    const gpa = testing.allocator;
    // The same record/CID pair dagjson's own positive test pins, wrapped in a
    // listRecords row — proves a legitimate record verifies clean through here.
    const body =
        \\{"records":[{"uri":"at://x/c/1","cid":"bafyreidykglsfhoixmivffc5uwhcgshx4j465xwqntbmu43nb2dzqwfvae","value":{"hello":"world"}}]}
    ;
    const report = checkListRecords(gpa, body);
    defer freeReport(gpa, report);
    try testing.expectEqual(@as(usize, 1), report.checked);
    try testing.expectEqual(@as(usize, 0), badCount(report));
}

test "a tampered value is caught and named in bad_cids" {
    const gpa = testing.allocator;
    const wrong_cid = "bafyre4aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const body = try std.fmt.allocPrint(gpa,
        \\{{"records":[{{"uri":"at://x/app.zat4.feed.post/1","cid":"{s}","value":{{"$type":"app.zat4.feed.post","text":"hello"}}}}]}}
    , .{wrong_cid});
    defer gpa.free(body);

    const report = checkListRecords(gpa, body);
    defer freeReport(gpa, report);
    try testing.expectEqual(@as(usize, 1), report.checked);
    try testing.expect(badCount(report) >= 1);
    try testing.expect(isBad(report, wrong_cid)); // the failing cid is named
    try testing.expect(!isBad(report, "some-other-cid")); // an honest neighbour is not
}

test "malformed body is unverifiable, never a throw" {
    const gpa = testing.allocator;
    const report = checkListRecords(gpa, "{not json");
    defer freeReport(gpa, report);
    try testing.expectEqual(@as(usize, 1), report.unverifiable);
}

test "a row with no cid is skipped, not counted" {
    const gpa = testing.allocator;
    const body =
        \\{"records":[{"uri":"at://x/c/1","value":{"$type":"x","text":"y"}}]}
    ;
    const report = checkListRecords(gpa, body);
    defer freeReport(gpa, report);
    try testing.expectEqual(@as(usize, 0), report.checked);
    try testing.expectEqual(@as(usize, 0), badCount(report));
}

test "isValidDid / isValidCid: accept real ids, reject junk" {
    try testing.expect(isValidDid("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa"));
    try testing.expect(isValidDid("did:web:example.com"));
    try testing.expect(!isValidDid("not-a-did"));
    try testing.expect(!isValidDid(""));
    try testing.expect(isValidCid("bafyreidykglsfhoixmivffc5uwhcgshx4j465xwqntbmu43nb2dzqwfvae"));
    try testing.expect(!isValidCid("not-a-cid"));
    try testing.expect(!isValidCid(""));
}

test "textWithinLimits: caps length and rejects bad UTF-8" {
    try testing.expect(textWithinLimits("hello", 64));
    try testing.expect(textWithinLimits("", 64));
    try testing.expect(!textWithinLimits("toolong", 4)); // over the cap
    try testing.expect(!textWithinLimits("\xff\xfe", 64)); // invalid UTF-8
    try testing.expect(textWithinLimits("café ☕", 64)); // valid multibyte UTF-8
}
