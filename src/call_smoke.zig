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

//! B3 classification: SHELL. Media loopback smoke (`zig build call-smoke`).
//!
//! The end-to-end proof of the media pipeline: two call engines on 127.0.0.1
//! ICE-connect, then one sends a run of synthetic tone frames and the other
//! receives them through the REAL path — RTP packetization, SRTP AES-256-GCM
//! encryption keyed from a shared exporter, UDP transport, rollover recovery,
//! replay check, and jitter-buffer playout. It verifies every frame arrives
//! decrypted and in order. This is the honest "encrypted media flows between
//! two endpoints" proof that the offline unit tests cannot give, with a
//! synthetic tone standing in for the (not-yet-built) audio-device shims.
//!
//! PASS → exit 0; any failed step names where it stopped and exits non-zero.

const std = @import("std");
const call_ice = @import("shell/call_ice.zig");
const call_engine = @import("shell/call_engine.zig");
const media_keys = @import("core/media_keys.zig");
const ice = @import("core/ice.zig");

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const loop: [4]u8 = .{ 127, 0, 0, 1 };
    const pwd = "smoke-ice-credential";
    const frames: u8 = 8;

    var a = try call_ice.open(0);
    defer call_ice.close(&a);
    var b = try call_ice.open(0);
    defer call_ice.close(&b);
    std.debug.print("[call] ICE: A@:{d}  B@:{d}\n", .{ a.bound_port, b.bound_port });

    // 1) ICE connectivity check (proven path): A → B, B replies, A validates.
    var txid: [ice.txid_len]u8 = undefined;
    try init.io.randomSecure(&txid);
    try call_ice.sendCheck(&a, loop, b.bound_port, txid, pwd);
    var peer: ice.Address = undefined;
    if (call_ice.poll(&b, 500, pwd, &peer) != .got_request) {
        std.debug.print("[call] FAIL: ICE check did not reach B\n", .{});
        return error.SmokeFailed;
    }
    if (call_ice.poll(&a, 500, pwd, &peer) != .got_response) {
        std.debug.print("[call] FAIL: ICE response did not reach A\n", .{});
        return error.SmokeFailed;
    }
    std.debug.print("[call] ICE connected.\n", .{});

    // 2) Bring up media on both ends from a SHARED exporter (stands in for the
    //    MLS epoch exporter). A sends (.send), B decrypts A's stream (.recv side
    //    resolves to the same .send key internally).
    var exporter: [media_keys.key_len]u8 = undefined;
    for (&exporter, 0..) |*x, i| x.* = @intCast((i * 11 + 5) & 0xff);
    const call_id: u64 = 0xC0FFEE_1234;

    var ea: call_engine.Engine = undefined;
    try call_engine.init(gpa, &ea, &a, loop, b.bound_port, exporter, call_id, 0x0A0A0A0A, .send);
    defer call_engine.deinit(gpa, &ea);
    var eb: call_engine.Engine = undefined;
    try call_engine.init(gpa, &eb, &b, loop, a.bound_port, exporter, call_id, 0x0B0B0B0B, .recv);
    defer call_engine.deinit(gpa, &eb);

    // 3) A sends `frames` tone frames (frame i is 20 bytes all == i).
    var i: u8 = 0;
    while (i < frames) : (i += 1) {
        var payload: [20]u8 = undefined;
        @memset(&payload, i);
        try call_engine.sendFrame(&ea, &payload);
    }
    std.debug.print("[call] A sent {d} encrypted frames.\n", .{frames});

    // 4) B receives them through the full decrypt + de-jitter path.
    var received: usize = 0;
    var guard: usize = 0;
    while (received < frames and guard < frames * 4) : (guard += 1) {
        if (call_engine.pump(&eb, 200) == .media) received += 1;
    }
    std.debug.print("[call] B decrypted {d}/{d} frames.\n", .{ received, frames });
    if (received != frames) {
        std.debug.print("[call] FAIL: not all frames arrived decrypted\n", .{});
        return error.SmokeFailed;
    }

    // 5) Playout must be in order with intact payloads.
    var got: usize = 0;
    var pbuf: [64]u8 = undefined;
    while (call_engine.playout(&eb, &pbuf)) |frame| : (got += 1) {
        if (frame.len != 20 or frame[0] != @as(u8, @intCast(got)) or frame[19] != @as(u8, @intCast(got))) {
            std.debug.print("[call] FAIL: frame {d} corrupt or out of order\n", .{got});
            return error.SmokeFailed;
        }
    }
    if (got != frames) {
        std.debug.print("[call] FAIL: played {d} of {d} frames\n", .{ got, frames });
        return error.SmokeFailed;
    }

    std.debug.print("[call] PASS: {d} tone frames flowed A→B — RTP+SRTP(AES-256-GCM)+jitter, in order, decrypted.\n", .{frames});
}
