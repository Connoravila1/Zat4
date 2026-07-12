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

//! B1 classification: SHELL (test-only). The shared loopback fixture: a
//! scripted HTTP server on 127.0.0.1 that asserts each request's head (and
//! optionally body) contains expected substrings, then answers from the
//! script. Consolidates what were four per-file copies (F4: the cut point
//! emerged from real, repeated use — and was overdue); identity and xrpc
//! joined during the Phase 5 cleanup, leaving exactly one bespoke server
//! (xrpc's body-echo, whose semantics ARE the test).
//!
//! Only test builds reference this file, so it never reaches the binary.

const std = @import("std");

pub const ScriptStep = struct {
    // A7.2: cold struct, size guard waived — test scaffolding.
    must_contain_head: []const u8,
    must_contain_head_b: []const u8 = "", // optional second head substring
    must_contain_body: []const u8 = "",
    status: std.http.Status,
    body: []const u8,
};

pub fn serveScript(server: *std.Io.net.Server, io: std.Io, steps: []const ScriptStep) void {
    for (steps) |step| {
        const stream = server.accept(io) catch return;
        defer stream.close(io);
        var read_buf: [16384]u8 = undefined;
        var write_buf: [8192]u8 = undefined;
        var stream_reader = stream.reader(io, &read_buf);
        var stream_writer = stream.writer(io, &write_buf);
        var http_server: std.http.Server = .init(&stream_reader.interface, &stream_writer.interface);
        var req = http_server.receiveHead() catch return;

        // The body read invalidates head strings — copy the head first.
        var head_copy: [4096]u8 = undefined;
        const head_len = @min(req.head_buffer.len, head_copy.len);
        @memcpy(head_copy[0..head_len], req.head_buffer[0..head_len]);
        const head = head_copy[0..head_len];

        const body_len: usize = @intCast(req.head.content_length orelse 0);
        var reader_buf: [16384]u8 = undefined;
        var body_storage: [8192]u8 = undefined;
        if (body_len > 0) {
            const body_reader = req.readerExpectContinue(&reader_buf) catch return;
            body_reader.readSliceAll(body_storage[0..body_len]) catch return;
        }
        const request_body = body_storage[0..body_len];

        const matched = std.ascii.indexOfIgnoreCase(head, step.must_contain_head) != null and
            (step.must_contain_head_b.len == 0 or
                std.ascii.indexOfIgnoreCase(head, step.must_contain_head_b) != null) and
            (step.must_contain_body.len == 0 or
                std.mem.indexOf(u8, request_body, step.must_contain_body) != null);
        if (!matched) {
            req.respond("script expectation not met", .{ .status = .expectation_failed }) catch return;
            return;
        }
        req.respond(step.body, .{
            .status = step.status,
            .extra_headers = &.{.{ .name = "content-type", .value = "application/json" }},
        }) catch return;
    }
}

pub fn listenLoopback(io: std.Io, base_port: u16) !struct { server: std.Io.net.Server, port: u16 } {
    // NO reuse_address here, ever: on Linux it grants port SHARING
    // (REUSEPORT), so the probe "succeeds" on a taken port and the kernel
    // then load-balances client connections BETWEEN the parallel test
    // binaries — a wrong-process accept queue, a listener that never
    // wakes, an hour-long join (three listeners on one port, observed
    // 2026-07-11). Without it a taken port honestly refuses and the probe
    // walks on; TIME_WAIT collisions also walk on — right for tests.
    var port = base_port;
    var tries: u8 = 0;
    while (true) {
        var address: std.Io.net.IpAddress = .{ .ip4 = .loopback(port) };
        const server = address.listen(io, .{ .reuse_address = false }) catch {
            tries += 1;
            if (tries >= 8) return error.NoFreePort;
            port += 11;
            continue;
        };
        return .{ .server = server, .port = port };
    }
}
