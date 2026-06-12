//! B1 classification: SHELL. Public face of the **identity deep module** (D1).
//!
//! Interface, in full: `Identity`, `Endpoints`, `resolve`, `freeIdentity`.
//! Everything else — the dual resolution strategy (DNS TXT via DoH first,
//! HTTPS well-known fallback), DID-document wire shapes, the bidirectional
//! handle verification — is hidden interior (D2/D3). The pure logic lives in
//! src/core/identity.zig, which is internal to this module; the only thing
//! this file adds is the I/O choreography, and it is kept thin (B3).
//!
//! atproto's identity layer is the network's indirection: a person is a DID,
//! logs in with a handle, and their PDS host is *discovered*, never
//! hardcoded. When the resolution mechanics shift (they will; atproto is
//! pre-1.0), the blast radius is this module.

const std = @import("std");
const Allocator = std.mem.Allocator;
const http = @import("http.zig");
const core = @import("../core/identity.zig");

/// What the rest of the app knows about a resolved identity — plain values
/// (A1/B5), every string owned by the caller's allocator. Free with
/// `freeIdentity`, or pass an arena and free wholesale (C3).
/// A7.2: cold struct, size guard waived — one per resolution, never in bulk.
pub const Identity = struct {
    /// Normalized (lowercase) handle, verified bidirectionally against the
    /// DID document. If you hold an `Identity`, the handle is confirmed.
    handle: []const u8,
    did: []const u8,
    /// PDS base URL, no trailing slash — ready for XRPC (Phase 2).
    pds_url: []const u8,
    /// The account's atproto signing key (multibase), for repo/commit
    /// signature verification later.
    signing_key_multibase: []const u8,
};

/// Deployment configuration. Defaults target the live network; sandboxed PDS
/// environments and tests point these elsewhere.
/// A7.2: cold struct (configuration), size guard waived.
pub const Endpoints = struct {
    /// Google-style JSON DNS-over-HTTPS resolver (plain GET, no extra
    /// headers required — which is why it is the default over resolvers
    /// that demand an Accept header).
    doh: []const u8 = "https://dns.google/resolve",
    /// PLC directory base.
    plc: []const u8 = "https://plc.directory",
};

/// Resolve a handle to its verified Identity:
///
///   handle ──(DNS TXT via DoH, else HTTPS well-known)──> DID
///   DID ──(PLC directory / did:web well-known)──> DID document
///   document ──(verify id + alsoKnownAs, extract)──> { PDS, signing key }
///
/// C1/C2: `gpa` pays for exactly the four strings inside the returned
/// `Identity`. All transient work — request bodies, JSON parses, URL
/// strings — lives in one internal scratch arena freed before return
/// (C3/C4). E3: every failure is an explicit error; a handle the DID
/// document does not claim is `error.HandleNotVerified`, because an
/// unverified resolution is worse than none.
pub fn resolve(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    endpoints: Endpoints,
    raw_handle: []const u8,
) !Identity {
    var scratch_state = std.heap.ArenaAllocator.init(gpa); // C5: freed at scope end
    defer scratch_state.deinit();
    const scratch = scratch_state.allocator();

    const handle = try core.normalizeHandle(scratch, raw_handle);
    const did = try didForHandle(scratch, io, environ, endpoints, handle);
    const doc = try verifiedDocForDid(scratch, io, environ, endpoints, did, handle);

    return dupeIdentity(gpa, handle, did, doc);
}

/// Free an `Identity` produced by `resolve` (A1: behavior as a free
/// function, never a method on the record).
pub fn freeIdentity(gpa: Allocator, id: Identity) void {
    gpa.free(id.handle);
    gpa.free(id.did);
    gpa.free(id.pds_url);
    gpa.free(id.signing_key_multibase);
}

/// Strategy 1: DNS TXT record via DoH. Strategy 2: HTTPS well-known.
/// A DNS miss — or an unreachable/garbage resolver — is an ordinary,
/// *expected* condition handled by falling through to the second strategy
/// (E4); the fallthroughs below are that deliberate policy, not swallowed
/// errors. The well-known attempt is the last strategy, so its failures
/// propagate as the real errors of the resolution (E3).
fn didForHandle(
    scratch: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    endpoints: Endpoints,
    handle: []const u8,
) ![]const u8 {
    dns: {
        const url = try core.buildDohTxtUrl(scratch, endpoints.doh, handle);
        const resp = http.request(scratch, io, environ, url, .{}) catch break :dns; // resolver unreachable -> strategy 2
        if (resp.status != 200) break :dns;
        const found = core.didFromDohJson(scratch, resp.body) catch |err| switch (err) {
            error.OutOfMemory => return error.OutOfMemory, // never masked as a miss
            else => break :dns, // resolver served garbage -> strategy 2
        };
        if (found) |did| return did;
    }

    const url = try core.buildWellKnownUrl(scratch, handle);
    const resp = try http.request(scratch, io, environ, url, .{});
    if (resp.status != 200) return error.HandleResolutionFailed;
    return core.didFromWellKnown(resp.body);
}

/// Fetch the DID document and run the full verification + extraction.
fn verifiedDocForDid(
    scratch: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    endpoints: Endpoints,
    did: []const u8,
    expected_handle: ?[]const u8,
) !core.ParsedDoc {
    const url = try core.buildDidDocUrl(scratch, endpoints.plc, did);
    const resp = try http.request(scratch, io, environ, url, .{});
    if (resp.status != 200) return error.DidDocumentFetchFailed;
    return core.parseDidDocument(scratch, resp.body, did, expected_handle);
}

/// Copy the four result strings out of scratch into the caller's allocator.
/// C5: errdefer chain releases partial work on a mid-sequence OOM.
fn dupeIdentity(gpa: Allocator, handle: []const u8, did: []const u8, doc: core.ParsedDoc) Allocator.Error!Identity {
    const h = try gpa.dupe(u8, handle);
    errdefer gpa.free(h);
    const d = try gpa.dupe(u8, did);
    errdefer gpa.free(d);
    const p = try gpa.dupe(u8, doc.pds_url);
    errdefer gpa.free(p);
    const k = try gpa.dupe(u8, doc.signing_key_multibase);
    return .{ .handle = h, .did = d, .pds_url = p, .signing_key_multibase = k };
}

// ---------------------------------------------------------------------------
// Loopback round trip — real sockets, real HTTP, no external network.
// A fixture server on 127.0.0.1 plays the PLC directory; the test drives the
// module's actual fetch -> verify -> extract path end to end. Runs in the
// ordinary `zig build test` suite under the leak-detecting allocator (C6).
// ---------------------------------------------------------------------------

const test_doc =
    \\{
    \\  "id": "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
    \\  "alsoKnownAs": ["at://alice.test"],
    \\  "verificationMethod": [{
    \\    "id": "#atproto",
    \\    "type": "Multikey",
    \\    "publicKeyMultibase": "zQ3shLoopbackFixtureKey"
    \\  }],
    \\  "service": [{
    \\    "id": "#atproto_pds",
    \\    "type": "AtprotoPersonalDataServer",
    \\    "serviceEndpoint": "https://pds.alice.test"
    \\  }]
    \\}
;

/// Serve exactly one canned HTTP response, then exit. Test scaffolding only:
/// errors here surface as assertion failures on the client side of the test,
/// which is the oracle — hence the deliberate `catch return`s.
const fixture = @import("test_fixture.zig");

test "loopback round trip: DID -> document fetch -> verification -> identity fields" {
    const gpa = std.testing.allocator; // C6
    const io = std.testing.io;

    var bound = try fixture.listenLoopback(io, 38473);
    defer bound.server.deinit(io);

    const steps = [_]fixture.ScriptStep{.{
        .must_contain_head = "/did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
        .status = .ok,
        .body = test_doc,
    }};
    const server_thread = try std.Thread.spawn(.{}, fixture.serveScript, .{ &bound.server, io, &steps });
    defer server_thread.join();

    var plc_buf: [48]u8 = undefined;
    const plc_base = try std.fmt.bufPrint(&plc_buf, "http://127.0.0.1:{d}", .{bound.port});

    var scratch_state = std.heap.ArenaAllocator.init(gpa);
    defer scratch_state.deinit();
    const scratch = scratch_state.allocator();

    const doc = try verifiedDocForDid(
        scratch,
        io,
        null,
        .{ .plc = plc_base },
        "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa",
        "alice.test",
    );
    try std.testing.expectEqualStrings("https://pds.alice.test", doc.pds_url);
    try std.testing.expectEqualStrings("zQ3shLoopbackFixtureKey", doc.signing_key_multibase);
}

test "dupeIdentity ownership: every string freed by freeIdentity, no leaks" {
    const gpa = std.testing.allocator; // C6: a leak here fails the test
    const id = try dupeIdentity(gpa, "alice.test", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", .{
        .signing_key_multibase = "zQ3shKey",
        .pds_url = "https://pds.alice.test",
    });
    defer freeIdentity(gpa, id);
    try std.testing.expectEqualStrings("alice.test", id.handle);
    try std.testing.expectEqualStrings("did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", id.did);
}
