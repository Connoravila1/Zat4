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

//! B1 classification: SHELL. Android name resolution — bionic's
//! `getaddrinfo` behind the Io vtable's `netLookup` slot.
//!
//! WHY: std's own resolver reads `/etc/resolv.conf`, a file Android does
//! not have — DNS there belongs to netd, reached only through bionic's
//! `getaddrinfo` (the first on-device feed run died with NameServerFailure
//! on exactly this). `wrap` returns an Io identical to the given one except
//! that single vtable slot, so every host lookup in the client (the HTTP
//! stack, the stream, the relay) resolves the platform's way while ALL
//! other Io behavior stays the Threaded implementation's. Off Android,
//! `wrap` is the identity — this file costs the desktop nothing.
//!
//! F1 note: no new dependency — bionic is already the linked libc on this
//! target, and getaddrinfo is its supported resolution API.
//!
//! Contract: `wrap` is called ONCE per process (the seam's feed bring-up),
//! before any lookup through the returned Io. The two globals hold the
//! wrapped Io and the patched vtable — one Io per app process by the
//! seam's own design (A7.2-shaped: cold, single).

const std = @import("std");
const builtin = @import("builtin");

extern "log" fn __android_log_write(prio: c_int, tag: [*:0]const u8, text: [*:0]const u8) c_int;
fn trace(comptime fmt: []const u8, args: anytype) void {
    if (comptime !builtin.abi.isAndroid()) return;
    var buf: [256]u8 = undefined;
    const msg = std.fmt.bufPrintZ(&buf, fmt, args) catch return;
    _ = __android_log_write(4, "zat4", msg);
}
const HostName = std.Io.net.HostName;
const IpAddress = std.Io.net.IpAddress;

var base: std.Io = undefined;
var patched: std.Io.VTable = undefined;

pub fn wrap(io: std.Io) std.Io {
    if (comptime !builtin.abi.isAndroid()) return io;
    base = io;
    patched = io.vtable.*;
    patched.netLookup = netLookup;
    return .{ .userdata = io.userdata, .vtable = &patched };
}

fn netLookup(
    userdata: ?*anyopaque,
    host_name: HostName,
    resolved: *std.Io.Queue(HostName.LookupResult),
    options: HostName.LookupOptions,
) HostName.LookupError!void {
    _ = userdata;
    trace("dns: lookup {s}", .{host_name.bytes});
    defer resolved.close(base);
    lookupFallible(host_name, resolved, options) catch |err| switch (err) {
        error.Closed => unreachable, // contract: the queue outlives the call
        else => |e| return e,
    };
}

fn lookupFallible(
    host_name: HostName,
    resolved: *std.Io.Queue(HostName.LookupResult),
    options: HostName.LookupOptions,
) (HostName.LookupError || std.Io.QueueClosedError || std.Io.Cancelable)!void {
    if (comptime !builtin.abi.isAndroid()) unreachable; // installed by wrap on Android only
    const name = host_name.bytes;

    // Literal addresses resolve locally, same as the std resolver.
    if (IpAddress.parseIp6(name, options.port)) |addr| {
        if (options.family == .ip4) return error.UnknownHostName;
        try putWithCanon(resolved, addr, name, options);
        return;
    } else |_| {}
    if (IpAddress.parseIp4(name, options.port)) |addr| {
        if (options.family == .ip6) return error.UnknownHostName;
        try putWithCanon(resolved, addr, name, options);
        return;
    } else |_| {}

    var name_buf: [HostName.max_len + 1]u8 = undefined;
    const name_z = std.fmt.bufPrintZ(&name_buf, "{s}", .{name}) catch return error.UnknownHostName;

    var hints = std.mem.zeroes(std.c.addrinfo);
    hints.family = switch (options.family orelse .ip6) {
        .ip4 => std.c.AF.INET,
        .ip6 => if (options.family == null) std.c.AF.UNSPEC else std.c.AF.INET6,
    };
    hints.socktype = std.c.SOCK.STREAM;

    var list: ?*std.c.addrinfo = null;
    trace("dns: calling getaddrinfo", .{});
    const rc = std.c.getaddrinfo(name_z.ptr, null, &hints, &list);
    trace("dns: getaddrinfo rc={d}", .{@intFromEnum(rc)});
    if (@intFromEnum(rc) != 0) return switch (rc) {
        .NONAME, .NODATA, .ADDRFAMILY => error.UnknownHostName,
        .AGAIN => error.NameServerFailure,
        else => error.NameServerFailure,
    };
    const head = list orelse return error.NoAddressReturned;
    defer std.c.freeaddrinfo(head);

    var put_any = false;
    var it: ?*std.c.addrinfo = head;
    while (it) |info| : (it = info.next) {
        const sa = info.addr orelse continue;
        switch (info.family) {
            std.c.AF.INET => {
                if (options.family == .ip6) continue;
                const sin: *const std.c.sockaddr.in = @ptrCast(@alignCast(sa));
                try resolved.putOne(base, .{ .address = .{ .ip4 = .{
                    .bytes = @bitCast(sin.addr),
                    .port = options.port,
                } } });
                put_any = true;
            },
            std.c.AF.INET6 => {
                if (options.family == .ip4) continue;
                const sin6: *const std.c.sockaddr.in6 = @ptrCast(@alignCast(sa));
                try resolved.putOne(base, .{ .address = .{ .ip6 = .{
                    .bytes = sin6.addr,
                    .port = options.port,
                } } });
                put_any = true;
            },
            else => continue,
        }
    }
    trace("dns: addresses queued (any={})", .{put_any});
    if (!put_any) return error.NoAddressReturned;
    if (copyCanon(options.canonical_name_buffer, name)) |canon| {
        try resolved.putOne(base, .{ .canonical_name = canon });
    }
}

fn putWithCanon(
    resolved: *std.Io.Queue(HostName.LookupResult),
    addr: IpAddress,
    name: []const u8,
    options: HostName.LookupOptions,
) (HostName.LookupError || std.Io.QueueClosedError || std.Io.Cancelable)!void {
    try resolved.putOne(base, .{ .address = addr });
    if (copyCanon(options.canonical_name_buffer, name)) |canon| {
        try resolved.putOne(base, .{ .canonical_name = canon });
    }
}

/// The queried name IS the canonical name we report (bionic can return a
/// CNAME target, but nothing in the client consumes it — the TLS SNI and
/// certificate checks use the queried host, correctly).
fn copyCanon(buffer: ?*[HostName.max_len]u8, name: []const u8) ?HostName {
    const buf = buffer orelse return null;
    @memcpy(buf[0..name.len], name);
    return .{ .bytes = buf[0..name.len] };
}
