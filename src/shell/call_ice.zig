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

//! B3 classification: SHELL (impure). The ICE agent's I/O half — a UDP socket,
//! host-candidate discovery, and STUN connectivity checks — driving the pure
//! `core/ice.zig` codec. This is the thin, impure layer the calling core needs
//! to actually reach the network; all message framing, HMAC, and
//! address/candidate logic lives in the pure core, verified there against RFC
//! vectors.
//!
//! Portability: this fork's `std.posix` no longer exposes the datagram calls
//! (socket/sendto/recvfrom/close moved under the `std.Io` reorg, and `std.Io.net`
//! is TCP-only), so UDP goes straight to `std.os.linux` — the same raw-syscall
//! idiom `window.zig` uses for the X11 socket (`@bitCast` the `usize` return to
//! detect the negative-errno case). That is Linux/Android-only, which is exactly
//! calling's target set today; a Windows/macOS variant is a later concern and
//! this module is not yet in the desktop client's non-Linux graph.
//!
//! v1 scope (voice-first, LAN-first): one UDP socket, one host candidate found
//! via the connect-getsockname trick, and a STUN Binding check with
//! MESSAGE-INTEGRITY so two agents can prove a path. Trickle from multiple
//! interfaces, srflx/relay candidates (STUN/TURN servers), and the full
//! check-list priority ladder are follow-ups; on a shared LAN a direct host
//! pair connects without any of them. The connectivity-check scheduling that
//! runs this on a worker thread lives in `call_engine.zig`.

const std = @import("std");
const linux = std.os.linux;
const ice = @import("../core/ice.zig");

pub const IoError = error{Syscall};
pub const OpenError = error{ SocketFailed, BindFailed };

/// PLAIN DATA (A1). The agent's socket state. A7.2: cold struct, size guard
/// waived — one instance per call, holds an OS handle, never in a collection.
pub const Agent = struct {
    fd: i32,
    bound_port: u16,
};

/// The result of polling for one datagram. The peer/observed address is written
/// to the caller's out-param on `got_request`/`got_response`.
pub const PollResult = enum { idle, got_request, got_response, ignored };

/// A raw syscall returns a `usize` that is `-errno` when negative. Turn that
/// into a checked fd or an error (the `window.zig` idiom).
fn fdOf(rc: usize) IoError!i32 {
    const s: isize = @bitCast(rc);
    if (s < 0) return error.Syscall;
    return @intCast(s);
}
fn checkRc(rc: usize) IoError!usize {
    const s: isize = @bitCast(rc);
    if (s < 0) return error.Syscall;
    return rc;
}

fn sockaddrV4(ip: [4]u8, port: u16) linux.sockaddr.in {
    return .{
        // .addr is in network byte order == the address bytes as laid out, so a
        // bitcast (memory-preserving) is correct on either host endianness.
        .port = std.mem.nativeToBig(u16, port),
        .addr = @bitCast(ip),
    };
}

fn ipOf(sa: linux.sockaddr.in) [4]u8 {
    return @bitCast(sa.addr);
}

const addr_len: linux.socklen_t = @sizeOf(linux.sockaddr.in);

/// Open a UDP socket bound to `0.0.0.0:port` (port 0 = ephemeral). The actual
/// bound port is read back into `Agent.bound_port`.
pub fn open(port: u16) OpenError!Agent {
    const fd = fdOf(linux.socket(linux.AF.INET, linux.SOCK.DGRAM, 0)) catch return error.SocketFailed;
    errdefer _ = linux.close(fd);
    var addr = sockaddrV4(.{ 0, 0, 0, 0 }, port);
    _ = checkRc(linux.bind(fd, @ptrCast(&addr), addr_len)) catch return error.BindFailed;

    var bound: linux.sockaddr.in = undefined;
    var blen: linux.socklen_t = addr_len;
    _ = checkRc(linux.getsockname(fd, @ptrCast(&bound), &blen)) catch return error.BindFailed;
    return .{ .fd = fd, .bound_port = std.mem.bigToNative(u16, bound.port) };
}

pub fn close(a: *Agent) void {
    _ = linux.close(a.fd);
    a.* = undefined;
}

/// Discover the local IPv4 address the kernel would use to reach `route_target`
/// (the classic connect-a-UDP-socket-then-getsockname trick — no interface
/// enumeration, no packets sent). Returns the host candidate `ip:bound_port`.
pub fn localCandidate(a: *Agent, route_target: [4]u8) ?ice.Address {
    const probe = fdOf(linux.socket(linux.AF.INET, linux.SOCK.DGRAM, 0)) catch return null;
    defer _ = linux.close(probe);
    var dst = sockaddrV4(route_target, 9); // discard port; no datagram is sent
    _ = checkRc(linux.connect(probe, @ptrCast(&dst), addr_len)) catch return null;
    var local: linux.sockaddr.in = undefined;
    var llen: linux.socklen_t = addr_len;
    _ = checkRc(linux.getsockname(probe, @ptrCast(&local), &llen)) catch return null;
    var out: ice.Address = .{ .port = a.bound_port, .is_ipv6 = false, .addr = [_]u8{0} ** 16 };
    @memcpy(out.addr[0..4], &ipOf(local));
    return out;
}

/// Send a STUN Binding connectivity check to `peer_ip:peer_port`, authenticated
/// with MESSAGE-INTEGRITY under `pwd` (the peer's ICE password, exchanged in
/// signaling). `txid` should be freshly random per check (shell-supplied).
pub fn sendCheck(a: *Agent, peer_ip: [4]u8, peer_port: u16, txid: [ice.txid_len]u8, pwd: []const u8) !void {
    var buf: [128]u8 = undefined;
    var n = try ice.buildBindingRequest(txid, &buf);
    n = try ice.appendMessageIntegrity(&buf, n, pwd);
    var dst = sockaddrV4(peer_ip, peer_port);
    _ = try checkRc(linux.sendto(a.fd, &buf, n, 0, @ptrCast(&dst), addr_len));
}

/// Poll for one datagram (up to `timeout_ms`). On a valid Binding REQUEST it
/// replies with a success response (XOR-MAPPED-ADDRESS of the sender +
/// MESSAGE-INTEGRITY) and returns `got_request`; on a valid success RESPONSE it
/// returns `got_response`. Messages failing integrity are `ignored` (never
/// trusted — E3). `peer_out` receives the sender's address.
pub fn poll(a: *Agent, timeout_ms: i32, pwd: []const u8, peer_out: *ice.Address) PollResult {
    var pfd = [_]linux.pollfd{.{ .fd = a.fd, .events = linux.POLL.IN, .revents = 0 }};
    const ready = checkRc(linux.poll(&pfd, 1, timeout_ms)) catch return .idle;
    if (ready == 0) return .idle;

    var buf: [1500]u8 = undefined;
    var from: linux.sockaddr.in = undefined;
    var flen: linux.socklen_t = addr_len;
    const rc = checkRc(linux.recvfrom(a.fd, &buf, buf.len, 0, @ptrCast(&from), &flen)) catch return .idle;
    const msg = buf[0..rc];

    const hdr = ice.parseHeader(msg) catch return .ignored;
    if (!ice.verifyMessageIntegrity(msg, pwd)) return .ignored;

    const from_ip = ipOf(from);
    const from_port = std.mem.bigToNative(u16, from.port);
    peer_out.* = .{ .port = from_port, .is_ipv6 = false, .addr = [_]u8{0} ** 16 };
    @memcpy(peer_out.addr[0..4], &from_ip);

    if (hdr.class == .request) {
        replySuccess(a, from, hdr.txid, from_ip, from_port, pwd) catch {};
        return .got_request;
    }
    if (hdr.class == .success) return .got_response;
    return .ignored;
}

/// A received datagram's length and source address. A7.2: cold struct, size
/// guard waived — a transient return value.
pub const Datagram = struct {
    len: usize,
    ip: [4]u8,
    port: u16,
};

/// Send raw bytes to `ip:port` on the agent's socket (used for media once ICE
/// has validated a path — RTP/SRTP shares the same port as STUN, demuxed by the
/// first byte at the receiver).
pub fn sendRaw(a: *Agent, ip: [4]u8, port: u16, data: []const u8) IoError!void {
    var dst = sockaddrV4(ip, port);
    _ = try checkRc(linux.sendto(a.fd, data.ptr, data.len, 0, @ptrCast(&dst), addr_len));
}

/// Receive one datagram (up to `timeout_ms`) into `buf`. Returns null on
/// timeout. The caller demuxes STUN vs RTP/SRTP by the first byte.
pub fn recvRaw(a: *Agent, timeout_ms: i32, buf: []u8) ?Datagram {
    var pfd = [_]linux.pollfd{.{ .fd = a.fd, .events = linux.POLL.IN, .revents = 0 }};
    const ready = checkRc(linux.poll(&pfd, 1, timeout_ms)) catch return null;
    if (ready == 0) return null;
    var from: linux.sockaddr.in = undefined;
    var flen: linux.socklen_t = addr_len;
    const rc = checkRc(linux.recvfrom(a.fd, buf.ptr, buf.len, 0, @ptrCast(&from), &flen)) catch return null;
    return .{ .len = rc, .ip = ipOf(from), .port = std.mem.bigToNative(u16, from.port) };
}

/// True if the first byte marks an RTP/SRTP packet (version 2, top bits 10)
/// rather than a STUN message (top bits 00) — RFC 5761 multiplexing demux.
pub fn isRtp(first_byte: u8) bool {
    return (first_byte & 0xC0) == 0x80;
}

fn replySuccess(a: *Agent, to: linux.sockaddr.in, txid: [ice.txid_len]u8, peer_ip: [4]u8, peer_port: u16, pwd: []const u8) !void {
    var buf: [128]u8 = undefined;
    // header (success response) + XOR-MAPPED-ADDRESS(peer) + MESSAGE-INTEGRITY
    std.mem.writeInt(u16, buf[0..2], ice.encodeType(ice.method_binding, .success), .big);
    std.mem.writeInt(u16, buf[2..4], 0, .big);
    std.mem.writeInt(u32, buf[4..8], ice.magic_cookie, .big);
    @memcpy(buf[8..20], &txid);
    var n = try ice.appendXorMappedV4(&buf, ice.header_len, @bitCast(peer_ip), peer_port);
    n = try ice.appendMessageIntegrity(&buf, n, pwd);
    var dst = to;
    _ = try checkRc(linux.sendto(a.fd, &buf, n, 0, @ptrCast(&dst), addr_len));
}

// ---------------------------------------------------------------------------
// Tests (pure helpers only — real socket I/O is proven by the call-ice-smoke
// harness, `zig build call-ice-smoke`, which cannot run in the offline test).
// ---------------------------------------------------------------------------

const testing = std.testing;

test "sockaddr round-trips the IPv4 bytes and port regardless of host endianness" {
    const sa = sockaddrV4(.{ 192, 168, 1, 10 }, 54321);
    try testing.expectEqualSlices(u8, &[_]u8{ 192, 168, 1, 10 }, &ipOf(sa));
    try testing.expectEqual(@as(u16, 54321), std.mem.bigToNative(u16, sa.port));
}
