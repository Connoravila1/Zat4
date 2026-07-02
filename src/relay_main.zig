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

//! B1 classification: SHELL (the relay process entry — argv, env, the serve
//! loop). The Zat Chat thin relay binary (ZAT_CHAT_ROADMAP slice U4): a
//! store-and-forward service for fixed-size padded ciphertext blobs, keyed
//! by opaque mailbox IDs. It knows no DIDs, no handles, no message sizes —
//! see `core/relay.zig` for what it refuses to know, `shell/relay_serve.zig`
//! for the wire.
//!
//! Usage:
//!   zat4-relay                 serve on 127.0.0.1:2589 until killed
//!   zat4-relay --port 2589     pick the port
//!
//! ZAT_RELAY_TOKEN gates the upgrade (a service gate, not identity; empty ⇒
//! fail closed, every connection refused). Deploys behind Caddy per
//! DEPLOY_STATE, same posture as the AppView: TLS at the proxy, loopback
//! here. State is in-memory ON PURPOSE (M3 — delivered means deleted,
//! undelivered means expired; a relay restart forfeits queued blobs and
//! that is the retention promise, not a defect).

const std = @import("std");
const relay = @import("core/relay.zig");
const serve = @import("shell/relay_serve.zig");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const io = init.io;
    const env = init.environ_map;

    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const args = try init.minimal.args.toSlice(arena_state.allocator());

    var port: u16 = 2589;
    var i: usize = 1;
    while (i < args.len) : (i += 1) {
        if (std.mem.eql(u8, args[i], "--port") and i + 1 < args.len) {
            i += 1;
            port = std.fmt.parseInt(u16, args[i], 10) catch 2589;
        }
    }

    var out_buf: [512]u8 = undefined;
    var out_writer: std.Io.File.Writer = .init(.stdout(), io, &out_buf);
    const out = &out_writer.interface;

    const token = env.get("ZAT_RELAY_TOKEN") orelse "";
    if (token.len == 0) {
        try out.print("zat4-relay: WARNING — ZAT_RELAY_TOKEN unset; the gate is fail-closed, ALL connections will be refused. Set it to serve.\n", .{});
    }
    try out.print("zat4-relay: serving ws on http://127.0.0.1:{d}/relay  (ctrl-c to stop)\n", .{port});
    try out.flush();

    var store: relay.Store = .{};
    defer relay.deinit(gpa, &store);
    var lock: serve.StoreLock = .{};

    try serve.run(gpa, io, &store, .{ .port = port, .token = token }, &lock);
}

test {
    // The relay's test manifest (the zat-test-manifest rule): these run via
    // `zig build test-relay`, which rides the default `zig build test`.
    _ = relay;
    _ = serve;
}
