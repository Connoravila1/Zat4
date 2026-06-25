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

//! B1 classification: SHELL. This file is impure by design.
//!
//! The transport module — the single place in the program where HTTP and TLS
//! exist (B3). Everything above this boundary speaks plain values: a URL,
//! a method, optional header values and a payload go in; a status + body
//! come out (B5). No std.http type, TLS detail, connection state, or
//! redirect mechanics appears in any caller's code (D3).
//!
//! D1/D2 — deep module rationale: the interface is one function and two
//! plain records; the implementation hides connection setup, certificate
//! loading, TLS, proxy discovery, redirect policy, decompression, header
//! policy, and the response-size budget. When the transport changes
//! (std.http API churn, connection pooling, an eventual swap), the blast
//! radius is this file alone.
//!
//! F1 — dependency justification (TLS): transport security comes from Zig's
//! own std.crypto / std.http — in-tree standard library, zero third-party
//! packages. What it does: TLS client + HTTP/1.1. Why we do not write it
//! ourselves: implementing TLS by hand is the canonical "do not roll your
//! own crypto" failure mode. Cost to remove: reimplement `request` over
//! another transport; this interface and every caller stay untouched.
//!
//! Note on connection reuse: a fresh client (and therefore a fresh TLS
//! handshake) per call remains deliberate — ownership stays trivially
//! correct. Pooling happens only if measurement demands it (G1/G3: the
//! network dominates regardless).

const std = @import("std");
const netguard = @import("../core/netguard.zig");

/// SSRF trust posture for a request (Phase 1). `.trusted` is for
/// operator-configured endpoints (the AppView, the DoH resolver, the PLC
/// directory — any of which may legitimately be loopback in dev). `.untrusted`
/// is for a fetch whose host is network-derived / attacker-influenced (a
/// handle's `.well-known`, a `did:web` document, a DID-document
/// `serviceEndpoint`): the scheme must be https, an IP-literal host in a
/// private / loopback / link-local / reserved range is refused before any
/// connection is attempted, AND redirects are not followed (so a public host
/// can't 302 to an internal one and slip past that gate).
pub const Guard = enum { trusted, untrusted };

/// Plain-data result of a request (A1: fields only; behavior lives in free
/// functions). `body` is owned by the caller's allocator — the caller frees
/// it, or hands in an arena and frees wholesale (C3).
/// A7.2: cold struct, size guard waived — one per request, never held in
/// quantity, never in a hot loop.
pub const Response = struct {
    status: u16,
    body: []u8,
};

/// Per-call knobs. Defaults make a plain GET: `request(gpa, io, env, url, .{})`.
/// A7.2: cold struct (per-request configuration), size guard waived.
pub const RequestOptions = struct {
    method: std.http.Method = .GET,
    /// Request payload (procedures POST JSON bodies through here).
    body: ?[]const u8 = null,
    /// Sent as the content-type header when present.
    content_type: ?[]const u8 = null,
    /// Full authorization header value (e.g. "Bearer <jwt>") — Phase 3's
    /// session module supplies this; the transport just carries it.
    authorization: ?[]const u8 = null,
    /// Sent as the accept header when present (some DoH resolvers and
    /// XRPC endpoints negotiate on it).
    accept: ?[]const u8 = null,
    /// Hard budget on the buffered response body. A body that exceeds it is
    /// `error.ResponseTooLarge`, not an unbounded allocation: a misbehaving
    /// or hostile server cannot balloon our memory (E2 at the process edge).
    max_response_bytes: usize = default_max_response_bytes,
    /// SSRF posture (Phase 1). Defaults to `.trusted` so operator-configured
    /// callers (incl. the dev loopback AppView) are unaffected; a caller
    /// fetching a network-derived host passes `.untrusted` to enable the guard.
    guard: Guard = .trusted,
};

/// XRPC JSON pages with embeds run tens-to-hundreds of KB; 4 MiB is generous
/// headroom while still being a real ceiling.
pub const default_max_response_bytes: usize = 4 * 1024 * 1024;

const user_agent = "zat/0.0.1 (atproto client)";

/// Perform one HTTP(S) request, following redirects. If `environ` is
/// provided, the standard proxy variables (http_proxy / https_proxy /
/// no_proxy) are honored; pass null where no environment exists (tests).
///
/// C1/C2 — allocation policy, visible here at the boundary:
///   * `gpa` pays for exactly one escaping allocation: the returned body.
///   * All transport scratch (proxy config, connection buffers, TLS state,
///     and the budget-sized response staging buffer) lives in an internal
///     per-request arena freed before return (C3), so this module owns and
///     releases its own memory (C4). The staging buffer is capacity, not
///     cost: the OS commits its pages lazily, and the arena releases them
///     wholesale before this function returns.
///
/// E3/E4 — failure policy: a non-2xx status is an ordinary result the caller
/// inspects, not an error. The error set is reserved for real transport
/// failure (DNS, TLS, connect, budget exceeded, OOM) and is explicit in the
/// signature.
pub fn request(
    gpa: std.mem.Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    url: []const u8,
    options: RequestOptions,
) !Response {
    // SSRF gate (Phase 1): for an untrusted (network-derived) host, refuse a
    // non-https scheme or an IP-literal host in a blocked range BEFORE opening
    // any connection. The classification is pure (`core/netguard.zig`); a host
    // *name* (verdict null) is left to the connection's own DNS — resolving the
    // name and classifying every returned address is the next hardening step.
    if (options.guard == .untrusted) {
        if (!netguard.isAllowedScheme(url)) return error.BlockedScheme;
        const host = netguard.hostOf(url) orelse return error.BlockedAddress;
        if (netguard.ipLiteralVerdict(host)) |blocked| {
            if (blocked) return error.BlockedAddress;
        }
    }

    var scratch_state = std.heap.ArenaAllocator.init(gpa); // C5: cleanup at acquisition
    defer scratch_state.deinit();
    const scratch = scratch_state.allocator();

    var client: std.http.Client = .{ .allocator = scratch, .io = io };
    defer client.deinit();

    if (environ) |env| try client.initDefaultProxies(scratch, env);

    // The response stages into a fixed, budget-sized buffer: overflowing it
    // is the budget enforcement. Simplest mechanism that is actually a hard
    // cap — no custom writer machinery for a path the network dominates (G3).
    const staging = try scratch.alloc(u8, options.max_response_bytes);
    var body_writer: std.Io.Writer = .fixed(staging);

    var extra_headers_buf: [1]std.http.Header = undefined;
    var extra_headers_len: usize = 0;
    if (options.accept) |accept| {
        extra_headers_buf[extra_headers_len] = .{ .name = "accept", .value = accept };
        extra_headers_len += 1;
    }

    // std's fetch routes a null payload through its bodiless send path,
    // which asserts the method carries no body — so a body-bearing method
    // (POST) with nothing to say sends the canonical empty body
    // (content-length: 0) instead. The wire result matches what every
    // mainstream client does for a bodiless POST.
    const payload: ?[]const u8 = if (options.body) |b|
        b
    else if (options.method.requestHasBody())
        ""
    else
        null;

    const result = client.fetch(.{
        .location = .{ .url = url },
        .method = options.method,
        .payload = payload,
        .response_writer = &body_writer,
        .headers = .{
            .user_agent = .{ .override = user_agent },
            .content_type = if (options.content_type) |ct| .{ .override = ct } else .default,
            .authorization = if (options.authorization) |auth| .{ .override = auth } else .default,
        },
        .extra_headers = extra_headers_buf[0..extra_headers_len],
        // SSRF (Phase 1), the redirect half: the up-front IP/scheme gate above
        // only sees the FIRST URL — std follows redirects internally, so a
        // public attacker host could 302 to `http://169.254.169.254/` and slip
        // past it. For an `.untrusted` fetch we therefore DON'T follow redirects
        // (`.unhandled` returns the 3xx as-is); the caller's non-2xx check
        // rejects it. Trusted/operator-configured fetches keep the default
        // follow behavior.
        .redirect_behavior = if (options.guard == .untrusted) .unhandled else null,
    }) catch |err| switch (err) {
        // With a fixed response writer, a write failure / overlong stream
        // during the body phase means the body blew the budget (request-side
        // and redirect plumbing have their own buffers). Mapped to the
        // module's own explicit error so callers see policy, not plumbing.
        error.WriteFailed, error.StreamTooLong => return error.ResponseTooLarge,
        else => return err,
    };

    return .{
        .status = @intFromEnum(result.status),
        .body = try gpa.dupe(u8, body_writer.buffered()),
    };
}

// ---------------------------------------------------------------------------
// Loopback tests — real sockets pin the transport's new behavior: header
// pass-through and the response budget. Client-side assertions are the
// oracle; the fixture answers 200 only when the wire looked right.
// ---------------------------------------------------------------------------

fn serveCheckingHeadersOnce(server: *std.Io.net.Server, io: std.Io) void {
    const stream = server.accept(io) catch return;
    defer stream.close(io);
    var read_buf: [8192]u8 = undefined;
    var write_buf: [8192]u8 = undefined;
    var stream_reader = stream.reader(io, &read_buf);
    var stream_writer = stream.writer(io, &write_buf);
    var http_server: std.http.Server = .init(&stream_reader.interface, &stream_writer.interface);
    var req = http_server.receiveHead() catch return;
    const head = req.head_buffer;
    const ok = std.ascii.indexOfIgnoreCase(head, "authorization: Bearer fixture-token") != null and
        std.ascii.indexOfIgnoreCase(head, "accept: application/json") != null;
    req.respond("", .{ .status = if (ok) .ok else .bad_request }) catch return;
}

test "loopback: authorization and accept reach the wire verbatim" {
    const gpa = std.testing.allocator; // C6
    const io = std.testing.io;

    var port: u16 = 38530;
    var address: std.Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    var server = address.listen(io, .{ .reuse_address = true }) catch blk: {
        port += 11;
        address = .{ .ip4 = .loopback(port) };
        break :blk try address.listen(io, .{ .reuse_address = true });
    };
    defer server.deinit(io);
    const thread = try std.Thread.spawn(.{}, serveCheckingHeadersOnce, .{ &server, io });
    defer thread.join();

    var url_buf: [48]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/check", .{port});

    const resp = try request(gpa, io, null, url, .{
        .authorization = "Bearer fixture-token",
        .accept = "application/json",
    });
    defer gpa.free(resp.body); // C5
    try std.testing.expectEqual(@as(u16, 200), resp.status);
}

fn serveOversizedOnce(server: *std.Io.net.Server, io: std.Io) void {
    const stream = server.accept(io) catch return;
    defer stream.close(io);
    var read_buf: [8192]u8 = undefined;
    var write_buf: [8192]u8 = undefined;
    var stream_reader = stream.reader(io, &read_buf);
    var stream_writer = stream.writer(io, &write_buf);
    var http_server: std.http.Server = .init(&stream_reader.interface, &stream_writer.interface);
    var req = http_server.receiveHead() catch return;
    const oversized = "x" ** (64 * 1024);
    req.respond(oversized, .{}) catch return;
}

test "loopback: the response budget is a hard cap, surfaced as the module's own error" {
    const gpa = std.testing.allocator; // C6
    const io = std.testing.io;

    var port: u16 = 38552;
    var address: std.Io.net.IpAddress = .{ .ip4 = .loopback(port) };
    var server = address.listen(io, .{ .reuse_address = true }) catch blk: {
        port += 11;
        address = .{ .ip4 = .loopback(port) };
        break :blk try address.listen(io, .{ .reuse_address = true });
    };
    defer server.deinit(io);
    const thread = try std.Thread.spawn(.{}, serveOversizedOnce, .{ &server, io });
    defer thread.join();

    var url_buf: [48]u8 = undefined;
    const url = try std.fmt.bufPrint(&url_buf, "http://127.0.0.1:{d}/big", .{port});

    const result = request(gpa, io, null, url, .{ .max_response_bytes = 1024 });
    try std.testing.expectError(error.ResponseTooLarge, result);
}

test "ssrf guard: an untrusted IP-literal host in a blocked range is refused before connecting" {
    const gpa = std.testing.allocator; // C6
    const io = std.testing.io;
    // No server is started: the guard must fire before any connection attempt.
    try std.testing.expectError(error.BlockedAddress, request(gpa, io, null, "https://127.0.0.1:9/x", .{ .guard = .untrusted }));
    try std.testing.expectError(error.BlockedAddress, request(gpa, io, null, "https://169.254.169.254/latest/meta-data", .{ .guard = .untrusted }));
    try std.testing.expectError(error.BlockedAddress, request(gpa, io, null, "https://[::1]/x", .{ .guard = .untrusted }));
    try std.testing.expectError(error.BlockedAddress, request(gpa, io, null, "https://10.0.0.5/x", .{ .guard = .untrusted }));
}

test "ssrf guard: an untrusted request must be https" {
    const gpa = std.testing.allocator; // C6
    const io = std.testing.io;
    try std.testing.expectError(error.BlockedScheme, request(gpa, io, null, "http://example.com/x", .{ .guard = .untrusted }));
    try std.testing.expectError(error.BlockedScheme, request(gpa, io, null, "file:///etc/passwd", .{ .guard = .untrusted }));
}
