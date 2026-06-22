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

//! B1 classification: SHELL (network I/O). Persistence for the lens-socket
//! loadout (SOCKET_LOADOUT_AND_MARKETPLACE §10, Phase 1b): read and write the
//! singleton `app.zat4.socket.loadout` record in the user's own repo, so the
//! tray (order, per-lens color, which is seated) is REMEMBERED and travels
//! with the account (invariant 12). The pure record↔cards transform lives in
//! the core (lens_catalog); this module is the thin I/O leg over the same
//! authed XRPC path the rest of the writes use.

const std = @import("std");
const Allocator = std.mem.Allocator;
const auth = @import("auth.zig");
const lexicon = @import("../core/lexicon.zig");
const lens_socket = @import("../core/lens_socket.zig");
const lens_catalog = @import("../core/lens_catalog.zig");
const feed_core = @import("../core/feed.zig");

/// A7.2: cold — one per surface per login. The resolved entries (id + color,
/// in saved order) + the seated index. Slices live in the caller's arena.
pub const SurfaceEntries = struct {
    entries: []const lens_catalog.Entry = &.{},
    seated: u32 = 0,
};

/// A7.2: cold — the three per-surface loadouts read from the record.
pub const Loaded = struct {
    feed: SurfaceEntries = .{},
    reply: SurfaceEntries = .{},
    zone: SurfaceEntries = .{},
};

/// A surface's loadout as parallel id/color arrays + seated — the form the
/// background write worker carries (no `LensCard`s). A7.2: cold.
pub const SurfaceData = struct {
    ids: []const []const u8 = &.{},
    colors: []const u8 = &.{},
    seated: u32 = 0,
};

fn parseSurface(arena: Allocator, s: lexicon.LoadoutSurface) !SurfaceEntries {
    const entries = try arena.alloc(lens_catalog.Entry, s.lenses.len);
    for (s.lenses, 0..) |l, i| entries[i] = .{ .id = l.algo, .color = l.color };
    return .{ .entries = entries, .seated = s.seated };
}

/// Read the user's persisted loadout (all three surfaces) from their repo.
/// Returns null when there is no record yet (first run) or the read fails —
/// an ordinary result, so the caller falls back to the catalog defaults (E4).
/// Entries point into `arena`.
pub fn load(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
) !?Loaded {
    const params = [_]@import("../core/xrpc.zig").Param{
        .{ .name = "repo", .value = session.did },
        .{ .name = "collection", .value = lexicon.collection.loadout },
        .{ .name = "rkey", .value = "self" },
    };
    const outcome = try auth.query(
        gpa,
        arena,
        io,
        environ,
        session,
        lexicon.method.get_record,
        &params,
        lexicon.GetRecordResponse(lexicon.LoadoutRecord),
    );
    const v = switch (outcome) {
        .ok => |r| r.value,
        .failed => return null, // 404 (no record) or any read failure → use the defaults
    };
    if (v.feed.lenses.len == 0 and v.reply.lenses.len == 0 and v.zone.lenses.len == 0) return null;
    return .{
        .feed = try parseSurface(arena, v.feed),
        .reply = try parseSurface(arena, v.reply),
        .zone = try parseSurface(arena, v.zone),
    };
}

fn surfaceOut(arena: Allocator, s: SurfaceData) !lexicon.LoadoutSurfaceOut {
    const n = @min(s.ids.len, s.colors.len);
    const lenses = try arena.alloc(lexicon.LoadoutLensOut, n);
    for (0..n) |i| lenses[i] = .{ .algo = s.ids[i], .color = s.colors[i] };
    return .{ .lenses = lenses, .seated = s.seated };
}

/// Write all three surface loadouts to the user's repo, upserting the
/// singleton record. Always writes the full record (the three surfaces are
/// one document — a partial write would clobber the others). Best-effort:
/// the caller swallows failures (a lost save is the next save's problem, E2).
pub fn saveAll(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    feed: SurfaceData,
    reply: SurfaceData,
    zone: SurfaceData,
    now_epoch: i64,
) !void {
    var ts_buf: [24]u8 = undefined;
    const record = lexicon.LoadoutRecordOut{
        .feed = try surfaceOut(arena, feed),
        .reply = try surfaceOut(arena, reply),
        .zone = try surfaceOut(arena, zone),
        .createdAt = feed_core.formatTimestamp(&ts_buf, now_epoch),
    };
    const input = lexicon.PutRecordInput(@TypeOf(record)){
        .repo = session.did,
        .collection = lexicon.collection.loadout,
        .rkey = "self",
        .record = record,
    };
    const outcome = try auth.procedure(
        gpa,
        arena,
        io,
        environ,
        session,
        lexicon.method.put_record,
        input,
        lexicon.RecordRef,
    );
    switch (outcome) {
        .ok => {},
        .failed => return error.SaveFailed,
    }
}
