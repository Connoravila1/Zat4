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
const chat_keys = @import("shell/chat_keys.zig");

/// The directory leg of per-DID auth (CHAT_HARDENING A4 slice 2): what anchor
/// key does this DID PUBLISH? Resolves the DID to its own PDS (never a guessed
/// host — `identity.pdsForDid`, SSRF-guarded) and reads the public keyPackage
/// record through the same validation gate the client uses for a counterparty.
/// The network lives HERE, in the binary; the serve loop takes this as a
/// function pointer and stays offline and testable (B3).
///
/// False = we do not know this DID, so the relay will not admit it. An
/// unreachable PDS reads the same as a missing account, deliberately: an
/// identity we cannot check is one we cannot enforce a limit against.
fn verifyDid(gpa: std.mem.Allocator, io: std.Io, did: []const u8, out: *[relay.anchor_pub_len]u8) bool {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const peer = (chat_keys.fetchPeer(gpa, arena_state.allocator(), io, null, did) catch return false) orelse return false;
    out.* = peer.anchor_pub;
    return true;
}

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

    // THE FLIP (A4 slice 2). Unset/0 = the transition window: clients that
    // speak auth are challenged and verified; clients that don't are served as
    // they always were. Set it to 1 ONLY once every client in the wild speaks
    // auth — it locks the rest out, which is the point, but on purpose.
    const require_auth = blk: {
        const v = env.get("ZAT_RELAY_REQUIRE_AUTH") orelse break :blk false;
        break :blk std.mem.eql(u8, v, "1") or std.mem.eql(u8, v, "true");
    };

    try out.print("zat4-relay: serving ws on http://127.0.0.1:{d}/relay  (ctrl-c to stop)\n", .{port});
    if (require_auth)
        try out.print("zat4-relay: per-DID auth REQUIRED — an unauthenticated connection deposits nothing.\n", .{})
    else
        try out.print("zat4-relay: per-DID auth OFFERED (transition window) — clients that speak it are verified; the rest are served as before. Set ZAT_RELAY_REQUIRE_AUTH=1 to enforce.\n", .{});
    try out.flush();

    var store: relay.Store = .{};
    defer relay.deinit(gpa, &store);
    var lock: serve.StoreLock = .{};
    var auth_cache: serve.AuthCache = .{};
    defer auth_cache.deinit(gpa);

    try serve.run(gpa, io, &store, .{
        .port = port,
        .token = token,
        .require_auth = require_auth,
        .verify_did = verifyDid,
        .auth_cache = &auth_cache,
    }, &lock);
}

test {
    // The relay's test manifest (the zat-test-manifest rule): these run via
    // `zig build test-relay`, which rides the default `zig build test`.
    _ = relay;
    _ = serve;
}
