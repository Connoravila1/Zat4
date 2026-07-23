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

//! B3 classification: SHELL. ICE loopback smoke test (`zig build call-ice-smoke`).
//!
//! The foundation check for the ICE agent: open two UDP agents on 127.0.0.1 and
//! run one STUN Binding connectivity check between them — a MESSAGE-INTEGRITY
//! authenticated request, an auto-reply, and validation of the response. This
//! isolates the one thing the offline unit test cannot cover (real datagram
//! send/recv through `call_ice.zig`) from the pure codec, which is already
//! RFC-vector-tested in `core/ice.zig`.
//!
//! A successful run prints "[call-ice] PASS ..." and exits 0; any failed step
//! prints where it stopped and exits non-zero.

const std = @import("std");
const call_ice = @import("shell/call_ice.zig");
const ice = @import("core/ice.zig");

pub fn main(init: std.process.Init) !void {
    const loop: [4]u8 = .{ 127, 0, 0, 1 };
    const pwd = "smoke-ice-credential";

    var a = try call_ice.open(0); // ephemeral ports
    defer call_ice.close(&a);
    var b = try call_ice.open(0);
    defer call_ice.close(&b);
    std.debug.print("[call-ice] agent A on 127.0.0.1:{d}, agent B on 127.0.0.1:{d}\n", .{ a.bound_port, b.bound_port });

    if (call_ice.localCandidate(&a, loop)) |cand| {
        std.debug.print("[call-ice] A host candidate: {d}.{d}.{d}.{d}:{d}\n", .{ cand.addr[0], cand.addr[1], cand.addr[2], cand.addr[3], cand.port });
    }

    var txid: [ice.txid_len]u8 = undefined;
    try init.io.randomSecure(&txid);

    // A → B: a Binding connectivity check.
    try call_ice.sendCheck(&a, loop, b.bound_port, txid, pwd);

    // B receives the request and auto-replies with a success response.
    var peer: ice.Address = undefined;
    const rb = call_ice.poll(&b, 500, pwd, &peer);
    std.debug.print("[call-ice] B poll = {s} (from :{d})\n", .{ @tagName(rb), peer.port });
    if (rb != .got_request) {
        std.debug.print("[call-ice] FAIL: B did not receive an authenticated Binding request\n", .{});
        return error.SmokeFailed;
    }

    // A receives B's success response — the pair is validated.
    const ra = call_ice.poll(&a, 500, pwd, &peer);
    std.debug.print("[call-ice] A poll = {s}; reflexive addr {d}.{d}.{d}.{d}:{d}\n", .{ @tagName(ra), peer.addr[0], peer.addr[1], peer.addr[2], peer.addr[3], peer.port });
    if (ra != .got_response) {
        std.debug.print("[call-ice] FAIL: A did not receive the authenticated success response\n", .{});
        return error.SmokeFailed;
    }

    // Negative check: a response signed with the wrong password must be ignored.
    try call_ice.sendCheck(&a, loop, b.bound_port, txid, "the-wrong-password");
    const rbad = call_ice.poll(&b, 200, pwd, &peer);
    std.debug.print("[call-ice] B poll (bad credential) = {s}\n", .{@tagName(rbad)});
    if (rbad != .ignored) {
        std.debug.print("[call-ice] FAIL: a mis-authenticated check was not rejected\n", .{});
        return error.SmokeFailed;
    }

    std.debug.print("[call-ice] PASS: authenticated Binding check connected A↔B on loopback; forged credential rejected.\n", .{});
}
