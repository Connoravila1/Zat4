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

//! B1 classification: CORE (pure). SETTINGS PERSISTENCE — what the viewer's
//! Settings choices mean on disk. The shell owns the path and the fd work
//! (`shell/cache.zig` load/savePrefs); this module owns only the BYTES.
//!
//! Until now nothing in Settings survived a launch: `tui` seeded every toggle
//! and choice from the row table's defaults on every start, so "Light mode" and
//! "Accent" reset each time. This is the format that fixes that.
//!
//! **Keyed by ACTION, never by row index.** The live toggle word is indexed by
//! row POSITION (bit i = `rows[i]`), which is correct in RAM but wrong on disk:
//! inserting one row would silently reinterpret every stored bit. Actions
//! (`settings_view.act_*`) are stable and append-only, so they are the on-disk
//! key — the same reasoning that put `settings_view.rowOf` in the table module
//! ("so rows can be rearranged freely"). `rowOf` maps back on load.
//!
//! **Text, line-oriented, forward-compatible.** An unreadable, torn, truncated
//! or foreign file yields the DEFAULTS, never an error (E4 — absence is an
//! ordinary result): a corrupt prefs file must not be able to stop the app from
//! starting. Unknown lines and unknown actions are skipped, so an older build
//! reading a newer file keeps what it understands.
//!
//! PURE (B2): no clock, no I/O, no allocator — `serialize` writes into a caller
//! buffer and `parse` returns a plain value, so both are golden-tested headless.

const std = @import("std");
const assert = std.debug.assert;
const settings_view = @import("settings_view.zig");

/// File header. A file that does not start with this is not ours — treat it as
/// absent rather than guessing at its bytes.
pub const magic = "zatprefs";

/// Format version. Bump only for a change the parser cannot absorb by skipping;
/// additive entry kinds do not need it (unknown kinds are already skipped).
pub const version: u8 = 1;

pub const kind_toggle: u8 = 0;
pub const kind_choice: u8 = 1;

/// One persisted setting: which knob (`action`), whether it is a switch or a
/// pick (`kind`), and its stored state (`value` — 0/1 for a toggle, the option
/// index for a choice).
pub const Entry = struct {
    action: u8,
    kind: u8,
    value: u8,

    comptime {
        // Budget: three bytes, no padding — a plain triple of u8 held in a
        // fixed array and walked in a loop on every save.
        assert(@sizeOf(Entry) == 3);
    }
};

/// Capacity: every toggle row plus every choice could persist at once, with
/// headroom so adding settings does not silently start dropping them. The
/// comptime check below is what actually enforces that.
pub const max_entries: usize = 128;

comptime {
    assert(max_entries >= settings_view.rows.len + settings_view.choices.len);
}

/// The persisted set. A7.2: cold struct, size guard waived — exactly one per
/// session, read once at startup and rewritten when a setting changes.
pub const Set = struct {
    items: [max_entries]Entry = undefined,
    len: u8 = 0,
};

/// Whether `action` is allowed to survive a restart.
///
/// This is a DENY list, and deliberately so: the failure mode of an allow list
/// is that a newly-added setting silently does not stick (a real bug the user
/// sees and we do not), whereas the deny list's failure mode is a specific,
/// named toy persisting — which is exactly what we enumerate here.
///
/// GRAVITY is denied because it re-layouts the whole feed and is BROKEN ON
/// MOBILE (owner, 2026-07-18). Were it persisted, a phone that switched it on
/// would come back broken on every subsequent launch with no obvious way out —
/// a setting that can wedge a cold start must not be able to reach the disk.
/// Anything with that property belongs here.
///
/// Checked on BOTH write and read, so a prefs file written before an action was
/// denied cannot resurrect it.
pub fn persists(action: u8) bool {
    if (action == settings_view.act_none) return false; // a decorative/WIP row
    return switch (action) {
        settings_view.act_gravity => false,
        else => true,
    };
}

/// Append one setting to `set`, honouring `persists` and the capacity. Silently
/// drops what does not fit — a full set means a table far larger than the
/// comptime check above allows, so this cannot happen without a build failure
/// first.
pub fn put(set: *Set, kind: u8, action: u8, value: u8) void {
    if (!persists(action)) return;
    if (set.len >= max_entries) return;
    set.items[set.len] = .{ .action = action, .kind = kind, .value = value };
    set.len += 1;
}

/// The stored value for `action` of `kind`, or null when this file did not
/// carry it (E4 — the caller keeps its default).
pub fn get(set: *const Set, kind: u8, action: u8) ?u8 {
    for (set.items[0..set.len]) |e| {
        if (e.action == action and e.kind == kind) return e.value;
    }
    return null;
}

/// Write `set` into `buf` as the on-disk form. Null when `buf` is too small —
/// the caller then simply does not persist this round (E4).
pub fn serialize(buf: []u8, set: *const Set) ?[]const u8 {
    var w: usize = 0;
    const head = std.fmt.bufPrint(buf, "{s} {d}\n", .{ magic, version }) catch return null;
    w += head.len;
    for (set.items[0..set.len]) |e| {
        const tag: u8 = if (e.kind == kind_choice) 'c' else 't';
        const line = std.fmt.bufPrint(buf[w..], "{c} {d} {d}\n", .{ tag, e.action, e.value }) catch return null;
        w += line.len;
    }
    return buf[0..w];
}

/// Read the on-disk form. TOTAL — every malformed input maps to a set, never an
/// error: a bad header yields an empty set (i.e. all defaults), and individual
/// unparseable or denied lines are skipped while the rest are kept.
pub fn parse(bytes: []const u8) Set {
    var set: Set = .{};
    var lines = std.mem.splitScalar(u8, bytes, '\n');
    const header = lines.next() orelse return set;
    if (!std.mem.startsWith(u8, std.mem.trim(u8, header, " \t\r"), magic)) return set;
    while (lines.next()) |raw| {
        const line = std.mem.trim(u8, raw, " \t\r");
        if (line.len == 0) continue;
        const kind: u8 = switch (line[0]) {
            't' => kind_toggle,
            'c' => kind_choice,
            else => continue, // an entry kind this build does not know
        };
        var fields = std.mem.tokenizeScalar(u8, line[1..], ' ');
        const action_s = fields.next() orelse continue;
        const value_s = fields.next() orelse continue;
        const action = std.fmt.parseInt(u8, action_s, 10) catch continue;
        const value = std.fmt.parseInt(u8, value_s, 10) catch continue;
        put(&set, kind, action, value);
    }
    return set;
}

// ── mapping to and from the live settings state ────────────────────────────
//
// The shell holds two words: a toggle BIT PER ROW INDEX and a selected option
// index per choice. Converting those to and from the action-keyed disk form is
// pure table work, so it lives here and is golden-tested — the shell is left
// with nothing but the fd calls.

/// Fold a loaded set into the live toggle word. Rows the file did not carry keep
/// whatever `base` had (their table default), so a partial file is not a reset.
pub fn applyToggles(set: *const Set, base: u64) u64 {
    var bits = base;
    for (settings_view.rows, 0..) |r, i| {
        if (r.kind != .toggle) continue;
        const stored = get(set, kind_toggle, r.action) orelse continue;
        const bit = @as(u64, 1) << @intCast(i);
        if (stored != 0) bits |= bit else bits &= ~bit;
    }
    return bits;
}

/// Fold a loaded set into the live choice selections, in `settings_view.choices`
/// order. An out-of-range option index (an edited or stale file naming an option
/// that no longer exists) is DROPPED rather than clamped — landing on a
/// neighbouring option the viewer never picked would be a silent lie; the
/// default is the honest answer.
pub fn applyChoices(set: *const Set, sel: []u8) void {
    for (settings_view.choices, 0..) |c, i| {
        if (i >= sel.len) break;
        const stored = get(set, kind_choice, c.action) orelse continue;
        if (stored >= c.options.len) continue;
        sel[i] = stored;
    }
}

/// Build the persistable set from the live state. `persists` filtering happens
/// inside `put`, so a denied toggle never reaches the returned set.
pub fn collect(bits: u64, sel: []const u8) Set {
    var set: Set = .{};
    for (settings_view.rows, 0..) |r, i| {
        if (r.kind != .toggle) continue;
        const on: u8 = if (bits & (@as(u64, 1) << @intCast(i)) != 0) 1 else 0;
        put(&set, kind_toggle, r.action, on);
    }
    for (settings_view.choices, 0..) |c, i| {
        if (i >= sel.len) break;
        put(&set, kind_choice, c.action, sel[i]);
    }
    return set;
}

// ── tests ──────────────────────────────────────────────────────────────────

test "prefs: a toggle and a choice round-trip by action" {
    var set: Set = .{};
    put(&set, kind_toggle, settings_view.act_light, 1);
    put(&set, kind_choice, settings_view.act_accent, 2);

    var buf: [1024]u8 = undefined;
    const bytes = serialize(&buf, &set).?;
    const back = parse(bytes);

    try std.testing.expectEqual(@as(u8, 2), back.len);
    try std.testing.expectEqual(@as(?u8, 1), get(&back, kind_toggle, settings_view.act_light));
    try std.testing.expectEqual(@as(?u8, 2), get(&back, kind_choice, settings_view.act_accent));
}

test "prefs: a toggle and a choice sharing an action id do not collide" {
    // The two namespaces are independent — a toggle's action number and a
    // choice's action number are unrelated, so `get` must match on both.
    var set: Set = .{};
    put(&set, kind_toggle, settings_view.act_light, 1);
    try std.testing.expectEqual(@as(?u8, null), get(&set, kind_choice, settings_view.act_light));
}

test "prefs: gravity never reaches the disk" {
    var set: Set = .{};
    put(&set, kind_toggle, settings_view.act_gravity, 1);
    try std.testing.expectEqual(@as(u8, 0), set.len);

    var buf: [1024]u8 = undefined;
    const bytes = serialize(&buf, &set).?;
    try std.testing.expect(std.mem.indexOf(u8, bytes, "t 14 ") == null);
}

test "prefs: gravity in an OLD file is ignored on load" {
    // A prefs file written before the denial (or hand-edited) must not be able
    // to bring a wedging toy back.
    const old = "zatprefs 1\nt 14 1\nt 22 1\n";
    const back = parse(old);
    try std.testing.expectEqual(@as(?u8, null), get(&back, kind_toggle, settings_view.act_gravity));
    try std.testing.expectEqual(@as(?u8, 1), get(&back, kind_toggle, settings_view.act_light));
}

test "prefs: a corrupt or foreign file yields defaults, not an error" {
    try std.testing.expectEqual(@as(u8, 0), parse("").len);
    try std.testing.expectEqual(@as(u8, 0), parse("\x00\x01\x02").len);
    try std.testing.expectEqual(@as(u8, 0), parse("some other file\nt 22 1\n").len);
    // Truncated mid-write: the header survived, so keep the whole lines we got.
    const torn = "zatprefs 1\nt 22 1\nc 10 ";
    try std.testing.expectEqual(@as(?u8, 1), get(&parse(torn), kind_toggle, settings_view.act_light));
    try std.testing.expectEqual(@as(?u8, null), get(&parse(torn), kind_choice, settings_view.act_accent));
}

test "prefs: unknown entry kinds and unknown actions are skipped, known ones kept" {
    // An older build reading a newer file keeps what it understands.
    const newer = "zatprefs 1\nx 99 1\nt 22 1\nt 250 1\n";
    const back = parse(newer);
    try std.testing.expectEqual(@as(?u8, 1), get(&back, kind_toggle, settings_view.act_light));
    // The unknown action is stored (it is not denied) but means nothing to the
    // shell, which looks settings up by the actions it knows.
    try std.testing.expectEqual(@as(?u8, 1), get(&back, kind_toggle, 250));
}

test "prefs: every persisted action maps back to a real settings row" {
    // The on-disk key must resolve through the table, or a load is a no-op.
    for (settings_view.rows) |r| {
        if (r.kind != .toggle or !persists(r.action)) continue;
        try std.testing.expect(settings_view.rowOf(r.action) != null);
    }
}

test "prefs: live toggle state round-trips through the disk form" {
    const light_row = settings_view.rowOf(settings_view.act_light).?;
    var sel = [_]u8{0} ** settings_view.choices.len;
    sel[0] = 2; // accent -> "Blue"

    const bits: u64 = @as(u64, 1) << light_row;
    const set = collect(bits, &sel);

    var buf: [2048]u8 = undefined;
    const back = parse(serialize(&buf, &set).?);

    try std.testing.expectEqual(bits, applyToggles(&back, 0) & (@as(u64, 1) << light_row));
    var out = [_]u8{0} ** settings_view.choices.len;
    applyChoices(&back, &out);
    try std.testing.expectEqual(@as(u8, 2), out[0]);
}

test "prefs: rows the file did not carry keep their default" {
    // A partial file is not a reset — this is why entries are looked up by
    // action rather than the whole word being overwritten.
    const set = parse("zatprefs 1\n");
    try std.testing.expectEqual(@as(u64, 0b1011), applyToggles(&set, 0b1011));
}

test "prefs: inserting a settings row does not corrupt stored state" {
    // The regression the action-keyed format exists to prevent. Simulated by
    // reading a value back through `rowOf` rather than a hardcoded bit index:
    // if the on-disk key were positional, this would silently drift.
    var sel = [_]u8{0} ** settings_view.choices.len;
    const xp_row = settings_view.rowOf(settings_view.act_xp).?;
    const set = collect(@as(u64, 1) << xp_row, &sel);
    var buf: [2048]u8 = undefined;
    const back = parse(serialize(&buf, &set).?);

    const bits = applyToggles(&back, 0);
    try std.testing.expect(bits & (@as(u64, 1) << settings_view.rowOf(settings_view.act_xp).?) != 0);
    try std.testing.expect(bits & (@as(u64, 1) << settings_view.rowOf(settings_view.act_light).?) == 0);
}

test "prefs: an out-of-range choice index falls back to the default" {
    const c0 = settings_view.choices[0];
    var line_buf: [64]u8 = undefined;
    const line = try std.fmt.bufPrint(&line_buf, "zatprefs 1\nc {d} {d}\n", .{ c0.action, c0.options.len + 3 });
    const set = parse(line);
    var sel = [_]u8{1} ** settings_view.choices.len;
    applyChoices(&set, &sel);
    try std.testing.expectEqual(@as(u8, 1), sel[0]); // untouched, not clamped to a neighbour
}

test "prefs: a gravity bit that is somehow live is not collected" {
    var sel = [_]u8{0} ** settings_view.choices.len;
    const grow = settings_view.rowOf(settings_view.act_gravity).?;
    const set = collect(@as(u64, 1) << grow, &sel);
    try std.testing.expectEqual(@as(?u8, null), get(&set, kind_toggle, settings_view.act_gravity));
}

test "prefs: a serialize buffer too small refuses rather than truncating" {
    var set: Set = .{};
    put(&set, kind_toggle, settings_view.act_light, 1);
    var tiny: [4]u8 = undefined;
    try std.testing.expectEqual(@as(?[]const u8, null), serialize(&tiny, &set));
}
