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
//! "verify don't trust" principle made live). Pure: a response body in, a tally
//! out, no I/O. It NEVER throws — a malformed body or row is COUNTED, not
//! raised, so one bad PDS response cannot break the poll loop (E2/E4).

const std = @import("std");
const dagjson = @import("dagjson.zig");
const jsonguard = @import("jsonguard.zig");

/// The outcome of checking one `com.atproto.repo.listRecords` response.
/// A7.2: cold struct, size guard waived — one per collection per poll cycle.
pub const Report = struct {
    /// Rows that carried a non-empty cid + value and were checked.
    checked: usize = 0,
    /// Checked rows whose recomputed CID did NOT match the claim (tampering).
    mismatched: usize = 0,
    /// Checked rows whose value would not parse / convert / encode — cannot be
    /// vouched for, so treated as suspect (counted, never silently passed).
    unverifiable: usize = 0,
    /// The first claimed CID that failed (mismatch or unverifiable), copied in
    /// for a log line — `firstBad()` reads it. Empty when everything checked out.
    first_bad_buf: [96]u8 = undefined,
    first_bad_len: usize = 0,
};

/// Bad rows (mismatch + unverifiable) — the count that matters for a verdict.
pub fn badCount(report: Report) usize {
    return report.mismatched + report.unverifiable;
}

/// The first failing CID (borrows `report`); "" if all clean.
pub fn firstBad(report: *const Report) []const u8 {
    return report.first_bad_buf[0..report.first_bad_len];
}

fn noteBad(report: *Report, claimed: []const u8) void {
    if (report.first_bad_len != 0) return;
    const n = @min(claimed.len, report.first_bad_buf.len);
    @memcpy(report.first_bad_buf[0..n], claimed[0..n]);
    report.first_bad_len = n;
}

/// Check every record CID in a listRecords response `body`. `gpa` funds the
/// per-record conversion arenas. A row with an empty/missing cid is skipped
/// (not counted). A malformed body returns a report with one unverifiable.
pub fn checkListRecords(gpa: std.mem.Allocator, body: []const u8) Report {
    var report: Report = .{};
    // Bound adversarial nesting before std.json walks the whole document (Phase 2).
    if (!jsonguard.depthWithinLimit(body, jsonguard.max_json_depth)) {
        report.unverifiable = 1;
        noteBad(&report, "<malformed-body>");
        return report;
    }
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const parsed = std.json.parseFromSliceLeaky(std.json.Value, arena, body, .{}) catch {
        report.unverifiable = 1;
        noteBad(&report, "<malformed-body>");
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
            noteBad(&report, claimed);
            continue;
        };
        if (!ok) {
            report.mismatched += 1;
            noteBad(&report, claimed);
        }
    }
    return report;
}

// ---------------------------------------------------------------------------
// Tests — a tiny real record + its real CID, plus a tampered one.
// ---------------------------------------------------------------------------

const testing = std.testing;

test "clean listing verifies; a tampered value is caught" {
    const gpa = testing.allocator;
    // A record value and the CID of its canonical DAG-CBOR. Reuse dagjson's own
    // verified path to derive the truth, so this test pins the listing wrapper,
    // not the (separately golden-tested) CID math.
    const value =
        \\{"$type":"app.zat4.feed.post","text":"hello","createdAt":"2026-01-01T00:00:00Z"}
    ;
    // Find the true CID via a self-check: any string that verifyRecordCid
    // accepts. We instead assert behavior at the listing level with a KNOWN
    // mismatch (a syntactically valid but wrong CID) and a malformed row.
    const wrong_cid = "bafyre4aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";
    const body = try std.fmt.allocPrint(gpa,
        \\{{"records":[{{"uri":"at://x/app.zat4.feed.post/1","cid":"{s}","value":{s}}}],"cursor":null}}
    , .{ wrong_cid, value });
    defer gpa.free(body);

    const report = checkListRecords(gpa, body);
    try testing.expectEqual(@as(usize, 1), report.checked);
    // The claimed CID is wrong, so it is either a mismatch (parsed fine, hash
    // differs) — never a silent pass.
    try testing.expect(badCount(report) >= 1);
    try testing.expectEqualStrings(wrong_cid, firstBad(&report));
}

test "a clean listing passes with zero bad (real record + its true CID)" {
    const gpa = testing.allocator;
    // The same record/CID pair dagjson's own positive test pins, wrapped in a
    // listRecords row — proves a legitimate record verifies clean through here.
    const body =
        \\{"records":[{"uri":"at://x/c/1","cid":"bafyreidykglsfhoixmivffc5uwhcgshx4j465xwqntbmu43nb2dzqwfvae","value":{"hello":"world"}}]}
    ;
    const report = checkListRecords(gpa, body);
    try testing.expectEqual(@as(usize, 1), report.checked);
    try testing.expectEqual(@as(usize, 0), badCount(report));
    try testing.expectEqualStrings("", firstBad(&report));
}

test "malformed body is unverifiable, never a throw" {
    const gpa = testing.allocator;
    const report = checkListRecords(gpa, "{not json");
    try testing.expectEqual(@as(usize, 1), report.unverifiable);
    try testing.expect(badCount(report) >= 1);
}

test "a row with no cid is skipped, not counted" {
    const gpa = testing.allocator;
    const body =
        \\{"records":[{"uri":"at://x/c/1","value":{"$type":"x","text":"y"}}]}
    ;
    const report = checkListRecords(gpa, body);
    try testing.expectEqual(@as(usize, 0), report.checked);
    try testing.expectEqual(@as(usize, 0), badCount(report));
}
