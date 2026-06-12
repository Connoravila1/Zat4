//! B1 classification: SHELL (test root). Live network smoke tests.
//!
//! These hit the real network, so they live behind their own build step —
//! `zig build test-live` — keeping `zig build test` offline, fast, and
//! deterministic. Run them on a machine with unrestricted egress: sandboxes
//! that allowlist outbound domains will fail the identity tests at the
//! proxy (plc.directory / dns.google blocked), which is an environment
//! limitation, not a defect. All suites run under the leak-detecting test
//! allocator; a leak fails the test (C6).

const std = @import("std");
const http = @import("shell/http.zig");
const identity = @import("shell/identity.zig");
const stream_shell = @import("shell/stream.zig");

test "live: HTTPS GET returns 200 and a JSON body (transport smoke)" {
    const gpa = std.testing.allocator; // C6
    const resp = try http.request(gpa, std.testing.io, null, "https://pypi.org/pypi/ziglang/json", .{});
    defer gpa.free(resp.body); // C5: body ownership is the caller's, freed here
    try std.testing.expectEqual(@as(u16, 200), resp.status);
    try std.testing.expect(resp.body.len > 0);
    try std.testing.expectEqual(@as(u8, '{'), resp.body[0]);
}

test "live: a non-2xx status is a value, not an error (E4)" {
    const gpa = std.testing.allocator; // C6
    const resp = try http.request(gpa, std.testing.io, null, "https://pypi.org/pypi/this-package-does-not-exist-zat/json", .{});
    defer gpa.free(resp.body);
    try std.testing.expectEqual(@as(u16, 404), resp.status);
}

test "live: resolve bsky.app end to end (Phase 1 exit criterion, real network)" {
    const gpa = std.testing.allocator; // C6
    const id = try identity.resolve(gpa, std.testing.io, null, .{}, "bsky.app");
    defer identity.freeIdentity(gpa, id);
    try std.testing.expectEqualStrings("bsky.app", id.handle);
    try std.testing.expect(std.mem.startsWith(u8, id.did, "did:plc:"));
    try std.testing.expect(std.mem.startsWith(u8, id.pds_url, "https://"));
    try std.testing.expect(id.signing_key_multibase.len > 0);
}

test "live: a domain with no atproto record fails resolution explicitly (E3)" {
    const gpa = std.testing.allocator; // C6
    // pypi.org exists but is not an atproto handle: the DNS strategy misses
    // and its well-known returns 404 -> the module's own explicit error.
    // (A *nonexistent* domain instead surfaces the transport's DNS error.)
    const result = identity.resolve(gpa, std.testing.io, null, .{}, "pypi.org");
    try std.testing.expectError(error.HandleResolutionFailed, result);
}

const xrpc = @import("shell/xrpc.zig");
const lexicon = @import("core/lexicon.zig");

test "live: unauthenticated XRPC query decodes a real profile (Phase 2 exit criterion)" {
    var arena_state = std.heap.ArenaAllocator.init(std.testing.allocator); // C6
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const outcome = try xrpc.query(arena, std.testing.io, null, "https://public.api.bsky.app", lexicon.method.get_profile, &.{
        .{ .name = "actor", .value = "bsky.app" },
    }, lexicon.ProfileViewDetailed, .{});

    switch (outcome) {
        .ok => |profile| {
            try std.testing.expectEqualStrings("bsky.app", profile.handle);
            try std.testing.expect(std.mem.startsWith(u8, profile.did, "did:plc:"));
            try std.testing.expect(profile.followersCount > 0);
        },
        .failed => |failure| {
            std.debug.print("xrpc refused: {d} {s}: {s}\n", .{ failure.status, failure.code, failure.message });
            return error.TestUnexpectedXrpcFailure;
        },
    }
}

// Live authentication note: the 0.16 test runner has no environment
// capability (no global getenv exists), so credentialed login is demoed
// through the binary instead, where the environment is capability-passed:
//   ZAT_APP_PASSWORD=xxxx-xxxx-xxxx-xxxx zig build run -- your.handle
// The full refresh/rotation choreography is proven offline by the scripted
// loopback tests in src/shell/auth.zig.

test "live: stream TLS leg — handshake with a real endpoint, first bytes read" {
    const gpa = std.testing.allocator; // C6
    var buf: [256]u8 = undefined;
    const n = try stream_shell.tlsSmoke(gpa, std.testing.io, "pypi.org", &buf);
    try std.testing.expect(n > 0);
    try std.testing.expect(std.mem.startsWith(u8, buf[0..n], "HTTP/1.1"));
}
