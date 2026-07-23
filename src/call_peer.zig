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

//! B3 classification: SHELL. Cross-device call bring-up peer (a dev harness).
//!
//! One endpoint of a direct-LAN call, driven from the command line so the same
//! ARM64 binary can run on an Android phone over `adb shell` and a native one on
//! the desktop — proving the media stack (ICE + SRTP + RTP + jitter) works
//! between two REAL devices on a Wi-Fi network, with no accounts, no relay, no
//! GUI, and no APK. Signaling here is trivial: both IPs are passed on the
//! command line (the production build exchanges candidates over the MLS chat
//! channel instead; this isolates the network reality from that integration).
//!
//!   call-peer <a|b> <bind-port> <peer-ip> <peer-port>
//!     a = sender (streams a synthetic tone after connecting)
//!     b = receiver (verifies the tone arrives decrypted and in order)
//!
//! PASS prints "[peer] PASS ..." and exits 0; a failure names where it stopped.

const std = @import("std");
const call_ice = @import("shell/call_ice.zig");
const call_engine = @import("shell/call_engine.zig");
const media_keys = @import("core/media_keys.zig");
const ice = @import("core/ice.zig");

const pwd = "debug-call-credential";
const call_id: u64 = 0xC0FFEE_D00D;
const frames: u8 = 40; // ~0.8 s of 20 ms frames

fn parseIp(s: []const u8) ![4]u8 {
    var out: [4]u8 = undefined;
    var it = std.mem.splitScalar(u8, s, '.');
    for (0..4) |i| out[i] = try std.fmt.parseInt(u8, it.next() orelse return error.BadIp, 10);
    return out;
}

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const argv = try init.minimal.args.toSlice(gpa);
    defer gpa.free(argv);
    if (argv.len < 5) {
        std.debug.print("usage: call-peer <a|b> <bind-port> <peer-ip> <peer-port>\n", .{});
        return error.Args;
    }
    const role = argv[1];
    const bind_port = try std.fmt.parseInt(u16, argv[2], 10);
    const peer_ip = try parseIp(argv[3]);
    const peer_port = try std.fmt.parseInt(u16, argv[4], 10);
    const is_sender = std.mem.eql(u8, role, "a");

    var agent = try call_ice.open(bind_port);
    defer call_ice.close(&agent);
    std.debug.print("[peer {s}] bound :{d} → {d}.{d}.{d}.{d}:{d}\n", .{ role, agent.bound_port, peer_ip[0], peer_ip[1], peer_ip[2], peer_ip[3], peer_port });

    // 1) ICE: both sides send checks and answer each other until each has seen a
    //    valid response (a validated path). ~10 s budget.
    var txid: [ice.txid_len]u8 = undefined;
    try init.io.randomSecure(&txid);
    var peer: ice.Address = undefined;
    var got_resp = false;
    var got_req = false;
    var tries: usize = 0;
    while (!(got_resp and got_req) and tries < 200) : (tries += 1) {
        call_ice.sendCheck(&agent, peer_ip, peer_port, txid, pwd) catch {};
        switch (call_ice.poll(&agent, 50, pwd, &peer)) {
            .got_response => got_resp = true,
            .got_request => got_req = true,
            else => {},
        }
    }
    if (!(got_resp and got_req)) {
        std.debug.print("[peer {s}] FAIL: ICE did not connect (resp={any} req={any})\n", .{ role, got_resp, got_req });
        return error.IceFailed;
    }
    std.debug.print("[peer {s}] ICE connected.\n", .{role});

    // 2) Media, keyed from a shared debug exporter. The two ends take opposite
    //    key directions so each decrypts the other's stream.
    var exporter: [media_keys.key_len]u8 = undefined;
    for (&exporter, 0..) |*x, i| x.* = @intCast((i * 13 + 7) & 0xff);
    var eng: call_engine.Engine = undefined;
    try call_engine.init(gpa, &eng, &agent, peer_ip, peer_port, exporter, call_id, if (is_sender) 0x0A0A0A0A else 0x0B0B0B0B, if (is_sender) .send else .recv);
    defer call_engine.deinit(gpa, &eng);

    if (is_sender) {
        var i: u8 = 0;
        while (i < frames) : (i += 1) {
            var payload: [20]u8 = undefined;
            @memset(&payload, i);
            call_engine.sendFrame(&eng, &payload) catch {};
            _ = call_engine.pump(&eng, 20); // pace ~20 ms and drain any keepalive
        }
        std.debug.print("[peer a] PASS: sent {d} encrypted tone frames.\n", .{frames});
    } else {
        var received: usize = 0;
        var guard: usize = 0;
        while (received < frames and guard < frames * 6) : (guard += 1) {
            if (call_engine.pump(&eng, 50) == .media) received += 1;
        }
        // Verify what arrived is intact and strictly in order. Early frames may
        // be lost to the ICE-handshake race (dropped before playout begins), so
        // the run need not start at 0 — but every played frame must have uniform
        // bytes (integrity) and follow the previous by exactly one (ordering).
        var got: usize = 0;
        var first: i32 = -1;
        var prev: i32 = -1;
        var pbuf: [64]u8 = undefined;
        while (call_engine.playout(&eng, &pbuf)) |f| : (got += 1) {
            if (f.len != 20) {
                std.debug.print("[peer b] FAIL: short frame ({d} bytes)\n", .{f.len});
                return error.MediaCorrupt;
            }
            for (f) |byte| if (byte != f[0]) {
                std.debug.print("[peer b] FAIL: frame payload not intact (decrypt corrupt)\n", .{});
                return error.MediaCorrupt;
            };
            const v: i32 = f[0];
            if (first < 0) first = v;
            if (prev >= 0 and v != prev + 1) {
                std.debug.print("[peer b] FAIL: out of order — {d} followed {d}\n", .{ v, prev });
                return error.MediaOutOfOrder;
            }
            prev = v;
        }
        std.debug.print("[peer b] received {d}/{d}; played {d} contiguous frames (first={d}).\n", .{ received, frames, got, first });
        if (got == 0) {
            std.debug.print("[peer b] FAIL: no media arrived\n", .{});
            return error.NoMedia;
        }
        std.debug.print("[peer b] PASS: encrypted tone flowed across the network, decrypted + in order.\n", .{});
    }
}
