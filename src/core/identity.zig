//! B1 classification: CORE (pure). The identity deep module's interior.
//!
//! INTERNAL FILE — the only permitted importer is src/shell/identity.zig,
//! the module's public face (D1/D3). Nothing here reaches the network, the
//! clock, or any global (B2/B4): every function is a deterministic transform
//! over bytes handed in by the shell, returning plain values (B5). Functions
//! that allocate take the allocator explicitly (C1); several return slices
//! *into their input or into the given arena* — lifetimes are documented per
//! function, and the shell copies what must outlive its scratch arena.
//!
//! What lives here, in resolution order:
//!   1. Handle syntax validation + normalization (atproto handle spec).
//!   2. DID syntax validation (did:plc and did:web, the two atproto methods).
//!   3. URL construction for the three fetches the shell may perform.
//!   4. Parsers for the three wire payloads: DNS-over-HTTPS JSON, the
//!      well-known plain-text body, and the DID document JSON — each parsed
//!      straight into flat typed structs, never a dynamic tree we re-walk.
//!   5. DID-document verification: id match, *bidirectional* handle
//!      verification via alsoKnownAs (the spec's anti-impersonation check),
//!      signing-key and PDS-endpoint extraction.

const std = @import("std");
const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// Handles
// ---------------------------------------------------------------------------

/// Max total handle length per the atproto handle syntax (DNS rules).
pub const max_handle_len = 253;

pub const HandleError = error{InvalidHandle};

/// TLDs the atproto spec requires implementations to reject outright.
/// `.test` is deliberately absent: it is valid syntax, reserved for
/// development environments — exactly what our fixtures use.
const banned_tlds = [_][]const u8{
    "alt", "arpa", "example", "internal", "invalid", "local", "localhost", "onion",
};

/// Validate handle syntax: 2+ dot-separated labels, each 1–63 chars of
/// [A-Za-z0-9-] with no leading/trailing hyphen, total <= 253, TLD not
/// starting with a digit and not on the banned list. Case-insensitive.
pub fn validateHandle(raw: []const u8) HandleError!void {
    if (raw.len == 0 or raw.len > max_handle_len) return error.InvalidHandle;
    var labels = std.mem.splitScalar(u8, raw, '.');
    var label_count: usize = 0;
    var last_label: []const u8 = "";
    while (labels.next()) |label| {
        label_count += 1;
        last_label = label;
        if (label.len == 0 or label.len > 63) return error.InvalidHandle;
        if (label[0] == '-' or label[label.len - 1] == '-') return error.InvalidHandle;
        for (label) |c| switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9', '-' => {},
            else => return error.InvalidHandle,
        };
    }
    if (label_count < 2) return error.InvalidHandle;
    if (std.ascii.isDigit(last_label[0])) return error.InvalidHandle;
    for (banned_tlds) |tld| {
        if (std.ascii.eqlIgnoreCase(last_label, tld)) return error.InvalidHandle;
    }
}

/// Validate and lowercase a handle. Returns a fresh allocation owned by the
/// caller (handles are case-insensitive; the canonical form is lowercase).
pub fn normalizeHandle(alloc: Allocator, raw: []const u8) (HandleError || Allocator.Error)![]u8 {
    try validateHandle(raw);
    const out = try alloc.dupe(u8, raw);
    for (out) |*c| c.* = std.ascii.toLower(c.*);
    return out;
}

// ---------------------------------------------------------------------------
// DIDs
// ---------------------------------------------------------------------------

pub const DidError = error{ InvalidDid, UnsupportedDidMethod };

/// Validate DID syntax for the two methods atproto blesses.
///   did:plc:<24 chars of base32 [a-z2-7]>
///   did:web:<bare hostname>   (atproto restricts did:web to hostname-level
///                              identities — no ports, no path segments)
pub fn validateDid(did: []const u8) DidError!void {
    const prefix = "did:";
    if (!std.mem.startsWith(u8, did, prefix)) return error.InvalidDid;
    const rest = did[prefix.len..];

    if (std.mem.startsWith(u8, rest, "plc:")) {
        const id = rest["plc:".len..];
        if (id.len != 24) return error.InvalidDid;
        for (id) |c| switch (c) {
            'a'...'z', '2'...'7' => {},
            else => return error.InvalidDid,
        };
        return;
    }

    if (std.mem.startsWith(u8, rest, "web:")) {
        const host = rest["web:".len..];
        if (host.len == 0 or host.len > max_handle_len) return error.InvalidDid;
        if (host[0] == '.' or host[host.len - 1] == '.') return error.InvalidDid;
        if (std.mem.indexOfScalar(u8, host, '.') == null) return error.InvalidDid;
        if (std.mem.indexOf(u8, host, "..") != null) return error.InvalidDid;
        for (host) |c| switch (c) {
            'a'...'z', 'A'...'Z', '0'...'9', '-', '.' => {},
            // ':' (port) and '%' (encoded port/path) are valid generic
            // did:web but outside what atproto permits — rejected on purpose.
            else => return error.InvalidDid,
        };
        return;
    }

    return error.UnsupportedDidMethod;
}

// ---------------------------------------------------------------------------
// URL construction (pure string building; the shell performs the fetches)
// ---------------------------------------------------------------------------

/// `https://<handle>/.well-known/atproto-did` — handle must be normalized.
pub fn buildWellKnownUrl(alloc: Allocator, handle: []const u8) Allocator.Error![]u8 {
    return std.fmt.allocPrint(alloc, "https://{s}/.well-known/atproto-did", .{handle});
}

/// Google-style DNS-over-HTTPS JSON query for the `_atproto.` TXT record.
pub fn buildDohTxtUrl(alloc: Allocator, doh_base: []const u8, handle: []const u8) Allocator.Error![]u8 {
    return std.fmt.allocPrint(alloc, "{s}?name=_atproto.{s}&type=TXT", .{ doh_base, handle });
}

/// DID-document URL: PLC directory lookup for did:plc, the well-known
/// document for did:web. Assumes `validateDid` already passed.
pub fn buildDidDocUrl(alloc: Allocator, plc_base: []const u8, did: []const u8) Allocator.Error![]u8 {
    if (std.mem.startsWith(u8, did, "did:plc:")) {
        return std.fmt.allocPrint(alloc, "{s}/{s}", .{ plc_base, did });
    }
    const host = did["did:web:".len..];
    return std.fmt.allocPrint(alloc, "https://{s}/.well-known/did.json", .{host});
}

// ---------------------------------------------------------------------------
// Wire payload: /.well-known/atproto-did (plain text)
// ---------------------------------------------------------------------------

/// The well-known body is the DID and nothing else (whitespace tolerated).
/// Returns a slice INTO `body` — valid only as long as `body` is.
pub fn didFromWellKnown(body: []const u8) DidError![]const u8 {
    const trimmed = std.mem.trim(u8, body, " \t\r\n");
    if (std.mem.indexOfAny(u8, trimmed, " \t\r\n") != null) return error.InvalidDid;
    try validateDid(trimmed);
    return trimmed;
}

// ---------------------------------------------------------------------------
// Wire payload: DNS-over-HTTPS JSON (Google `resolve` response shape)
// ---------------------------------------------------------------------------

/// A7.2: cold struct, size guard waived — transient parse shape; a handful
/// of answers exist for one lookup, then the arena reclaims them.
const DohAnswer = struct {
    name: []const u8 = "",
    type: u32 = 0,
    data: []const u8 = "",
};

/// A7.2: cold struct, size guard waived — one per lookup.
const DohResponse = struct {
    Status: i64 = -1,
    Answer: []const DohAnswer = &.{},
};

pub const DohError = error{ MalformedDohResponse, OutOfMemory } || DidError;

/// Extract the DID from a DoH TXT answer for `_atproto.<handle>`.
///
/// Returns null for an ordinary miss — NXDOMAIN, no TXT answers, no `did=`
/// payload (E4: an absent record is a result, not an error). Errors are
/// reserved for a malformed response or a present-but-garbage DID.
/// `arena` must be an arena (leaky JSON parse); the returned slice points
/// into it.
pub fn didFromDohJson(arena: Allocator, body: []const u8) DohError!?[]const u8 {
    const resp = std.json.parseFromSliceLeaky(DohResponse, arena, body, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory, // never masked (C-discipline)
        else => return error.MalformedDohResponse,
    };
    if (resp.Status != 0) return null;
    for (resp.Answer) |answer| {
        if (answer.type != 16) continue; // TXT records only
        const payload = stripTxtQuotes(answer.data);
        if (!std.mem.startsWith(u8, payload, "did=")) continue;
        const did = payload["did=".len..];
        try validateDid(did); // a present record with a garbage DID is an error
        return did;
    }
    return null;
}

/// DoH JSON carries TXT character-strings wrapped in literal quotes
/// (`"did=did:plc:..."`). `_atproto.` payloads are short, single-chunk
/// strings, so stripping one outer pair is sufficient.
fn stripTxtQuotes(data: []const u8) []const u8 {
    if (data.len >= 2 and data[0] == '"' and data[data.len - 1] == '"') {
        return data[1 .. data.len - 1];
    }
    return data;
}

// ---------------------------------------------------------------------------
// Wire payload: the DID document
// ---------------------------------------------------------------------------

/// A7.2: cold struct, size guard waived — transient parse shape, 1–3 entries
/// per document, one document per resolution.
const VerificationMethodJson = struct {
    id: []const u8 = "",
    type: []const u8 = "",
    controller: []const u8 = "",
    publicKeyMultibase: ?[]const u8 = null,
};

/// A7.2: cold struct, size guard waived — same lifetime as above.
const ServiceJson = struct {
    id: []const u8 = "",
    type: []const u8 = "",
    serviceEndpoint: []const u8 = "",
};

/// A7.2: cold struct, size guard waived — one per resolution.
const DidDocJson = struct {
    id: []const u8 = "",
    alsoKnownAs: []const []const u8 = &.{},
    verificationMethod: []const VerificationMethodJson = &.{},
    service: []const ServiceJson = &.{},
};

/// What resolution actually needs from a DID document — plain values (B5).
/// A7.2: cold struct, size guard waived — one per resolution.
pub const ParsedDoc = struct {
    signing_key_multibase: []const u8,
    pds_url: []const u8,
};

pub const DocError = error{
    MalformedDidDocument,
    DidDocumentMismatch,
    HandleNotVerified,
    NoAtprotoSigningKey,
    NoPdsEndpoint,
    OutOfMemory,
};

/// Parse and verify a DID document.
///
///   * `expected_did` must equal the document's `id` — the doc must be about
///     the DID we asked for.
///   * If `expected_handle` is given, `alsoKnownAs` must list
///     `at://<handle>`. This is the bidirectional check that stops a DID from
///     claiming a handle it does not control; without it, handle resolution
///     is forgeable.
///   * The signing key is the `verificationMethod` whose id ends `#atproto`
///     (ids may be document-relative or absolute; suffix matching covers
///     both) and which carries `publicKeyMultibase`.
///   * The PDS is the `service` whose id ends `#atproto_pds` with type
///     `AtprotoPersonalDataServer`; its endpoint must be http(s) and is
///     returned without a trailing slash.
///
/// `arena` must be an arena (leaky JSON parse); returned slices point into
/// it and live exactly as long as it does.
pub fn parseDidDocument(
    arena: Allocator,
    body: []const u8,
    expected_did: []const u8,
    expected_handle: ?[]const u8,
) DocError!ParsedDoc {
    const doc = std.json.parseFromSliceLeaky(DidDocJson, arena, body, .{
        .ignore_unknown_fields = true,
    }) catch |err| switch (err) {
        error.OutOfMemory => return error.OutOfMemory, // never masked
        else => return error.MalformedDidDocument,
    };

    if (!std.mem.eql(u8, doc.id, expected_did)) return error.DidDocumentMismatch;

    if (expected_handle) |handle| {
        const verified = for (doc.alsoKnownAs) |aka| {
            if (!std.ascii.startsWithIgnoreCase(aka, "at://")) continue;
            if (std.ascii.eqlIgnoreCase(aka["at://".len..], handle)) break true;
        } else false;
        if (!verified) return error.HandleNotVerified;
    }

    const key = for (doc.verificationMethod) |vm| {
        if (std.mem.endsWith(u8, vm.id, "#atproto")) {
            if (vm.publicKeyMultibase) |k| break k;
        }
    } else return error.NoAtprotoSigningKey;

    const pds = for (doc.service) |svc| {
        if (std.mem.endsWith(u8, svc.id, "#atproto_pds") and
            std.mem.eql(u8, svc.type, "AtprotoPersonalDataServer"))
        {
            break std.mem.trimEnd(u8, svc.serviceEndpoint, "/");
        }
    } else return error.NoPdsEndpoint;

    if (!std.mem.startsWith(u8, pds, "https://") and !std.mem.startsWith(u8, pds, "http://")) {
        return error.MalformedDidDocument;
    }

    return .{ .signing_key_multibase = key, .pds_url = pds };
}

// ---------------------------------------------------------------------------
// Tests — the pure core is exercised entirely offline (B2 pays rent here).
// All allocation flows through the leak-detecting test allocator (C6).
// ---------------------------------------------------------------------------

const testing = std.testing;

test "handle validation: accepts well-formed handles" {
    try validateHandle("bsky.app");
    try validateHandle("alice.bsky.social");
    try validateHandle("XN--ALICE.example-domain.com");
    try validateHandle("a-b.test"); // .test is valid: reserved for dev envs
    try validateHandle("8.is.fine.in.middle.labels.org");
}

test "handle validation: rejects malformed handles" {
    try testing.expectError(error.InvalidHandle, validateHandle(""));
    try testing.expectError(error.InvalidHandle, validateHandle("no-dot"));
    try testing.expectError(error.InvalidHandle, validateHandle("a..b"));
    try testing.expectError(error.InvalidHandle, validateHandle(".leading.dot"));
    try testing.expectError(error.InvalidHandle, validateHandle("trailing.dot."));
    try testing.expectError(error.InvalidHandle, validateHandle("-bad.example.com"));
    try testing.expectError(error.InvalidHandle, validateHandle("bad-.example.com"));
    try testing.expectError(error.InvalidHandle, validateHandle("under_score.com"));
    try testing.expectError(error.InvalidHandle, validateHandle("alice.2tld")); // TLD starts with digit
    try testing.expectError(error.InvalidHandle, validateHandle("alice.local")); // banned TLD
    try testing.expectError(error.InvalidHandle, validateHandle("alice.onion"));
    // label longer than 63
    const long_label = "a" ** 64 ++ ".com";
    try testing.expectError(error.InvalidHandle, validateHandle(long_label));
    // total longer than 253
    const long_handle = ("a" ** 63 ++ ".") ** 4 ++ "com";
    try testing.expectError(error.InvalidHandle, validateHandle(long_handle));
}

test "handle normalization lowercases" {
    const gpa = testing.allocator;
    const h = try normalizeHandle(gpa, "Alice.Bsky.Social");
    defer gpa.free(h);
    try testing.expectEqualStrings("alice.bsky.social", h);
}

test "DID validation: did:plc and did:web accepted, others rejected" {
    try validateDid("did:plc:z72i7hdynmk6r22z27h6tvur");
    try validateDid("did:web:example.com");
    try validateDid("did:web:sub.example-host.com");

    try testing.expectError(error.InvalidDid, validateDid("did:plc:tooshort"));
    try testing.expectError(error.InvalidDid, validateDid("did:plc:Z72I7HDYNMK6R22Z27H6TVUR")); // base32 is lowercase
    try testing.expectError(error.InvalidDid, validateDid("did:plc:z72i7hdynmk6r22z27h6tv18")); // 0,1,8,9 not in base32
    try testing.expectError(error.InvalidDid, validateDid("did:web:no-tld"));
    try testing.expectError(error.InvalidDid, validateDid("did:web:host.com:8080")); // ports excluded by atproto
    try testing.expectError(error.InvalidDid, validateDid("did:web:host.com%3A8080"));
    try testing.expectError(error.UnsupportedDidMethod, validateDid("did:key:zQ3shabc"));
    try testing.expectError(error.InvalidDid, validateDid("not-a-did"));
}

test "well-known body parses with surrounding whitespace, rejects extra tokens" {
    const did = try didFromWellKnown("  did:plc:z72i7hdynmk6r22z27h6tvur\n");
    try testing.expectEqualStrings("did:plc:z72i7hdynmk6r22z27h6tvur", did);
    try testing.expectError(error.InvalidDid, didFromWellKnown("did:plc:z72i7hdynmk6r22z27h6tvur trailing"));
    try testing.expectError(error.InvalidDid, didFromWellKnown("<html>not a did</html>"));
}

test "URL builders produce the three resolution URLs" {
    const gpa = testing.allocator;

    const wk = try buildWellKnownUrl(gpa, "alice.test");
    defer gpa.free(wk);
    try testing.expectEqualStrings("https://alice.test/.well-known/atproto-did", wk);

    const doh = try buildDohTxtUrl(gpa, "https://dns.google/resolve", "alice.test");
    defer gpa.free(doh);
    try testing.expectEqualStrings("https://dns.google/resolve?name=_atproto.alice.test&type=TXT", doh);

    const plc = try buildDidDocUrl(gpa, "https://plc.directory", "did:plc:z72i7hdynmk6r22z27h6tvur");
    defer gpa.free(plc);
    try testing.expectEqualStrings("https://plc.directory/did:plc:z72i7hdynmk6r22z27h6tvur", plc);

    const web = try buildDidDocUrl(gpa, "https://plc.directory", "did:web:example.com");
    defer gpa.free(web);
    try testing.expectEqualStrings("https://example.com/.well-known/did.json", web);
}

test "DoH JSON: extracts the did= TXT record, skipping non-TXT and unrelated answers" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const body =
        \\{"Status":0,"TC":false,"AD":false,
        \\ "Question":[{"name":"_atproto.bsky.app.","type":16}],
        \\ "Answer":[
        \\   {"name":"_atproto.bsky.app.","type":5,"TTL":300,"data":"alias.example.com."},
        \\   {"name":"_atproto.bsky.app.","type":16,"TTL":300,"data":"\"v=spf1 ignore-me\""},
        \\   {"name":"_atproto.bsky.app.","type":16,"TTL":300,"data":"\"did=did:plc:z72i7hdynmk6r22z27h6tvur\""}
        \\ ]}
    ;
    const did = try didFromDohJson(arena, body);
    try testing.expectEqualStrings("did:plc:z72i7hdynmk6r22z27h6tvur", did.?);
}

test "DoH JSON: NXDOMAIN and empty answers are ordinary misses (null), not errors" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectEqual(@as(?[]const u8, null), try didFromDohJson(arena,
        \\{"Status":3,"Comment":"NXDOMAIN"}
    ));
    try testing.expectEqual(@as(?[]const u8, null), try didFromDohJson(arena,
        \\{"Status":0,"Answer":[]}
    ));
}

test "DoH JSON: malformed body and garbage DID are errors, not misses" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectError(error.MalformedDohResponse, didFromDohJson(arena, "<!doctype html>"));
    try testing.expectError(error.InvalidDid, didFromDohJson(arena,
        \\{"Status":0,"Answer":[{"type":16,"data":"\"did=did:plc:short\""}]}
    ));
}

/// A realistic PLC-shaped document used across the doc tests.
const fixture_doc =
    \\{
    \\  "@context": ["https://www.w3.org/ns/did/v1","https://w3id.org/security/multikey/v1"],
    \\  "id": "did:plc:z72i7hdynmk6r22z27h6tvur",
    \\  "alsoKnownAs": ["at://bsky.app"],
    \\  "verificationMethod": [{
    \\    "id": "did:plc:z72i7hdynmk6r22z27h6tvur#atproto",
    \\    "type": "Multikey",
    \\    "controller": "did:plc:z72i7hdynmk6r22z27h6tvur",
    \\    "publicKeyMultibase": "zQ3shXjHeiBuRCKmM36cuYnm7YEMzhGnCmCyW92sRJ9pribSF"
    \\  }],
    \\  "service": [{
    \\    "id": "#atproto_pds",
    \\    "type": "AtprotoPersonalDataServer",
    \\    "serviceEndpoint": "https://puffball.us-east.host.bsky.network/"
    \\  }]
    \\}
;

test "DID document: verifies and extracts key + PDS (trailing slash trimmed)" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const doc = try parseDidDocument(arena, fixture_doc, "did:plc:z72i7hdynmk6r22z27h6tvur", "bsky.app");
    try testing.expectEqualStrings("zQ3shXjHeiBuRCKmM36cuYnm7YEMzhGnCmCyW92sRJ9pribSF", doc.signing_key_multibase);
    try testing.expectEqualStrings("https://puffball.us-east.host.bsky.network", doc.pds_url);
}

test "DID document: handle check is case-insensitive and skippable" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    _ = try parseDidDocument(arena, fixture_doc, "did:plc:z72i7hdynmk6r22z27h6tvur", "BSKY.APP");
    _ = try parseDidDocument(arena, fixture_doc, "did:plc:z72i7hdynmk6r22z27h6tvur", null);
}

test "DID document: impersonation and mismatch are hard errors" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // Bidirectional verification: the doc does not claim this handle.
    try testing.expectError(
        error.HandleNotVerified,
        parseDidDocument(arena, fixture_doc, "did:plc:z72i7hdynmk6r22z27h6tvur", "evil.example.com"),
    );
    // The doc is about a different DID than the one we resolved.
    try testing.expectError(
        error.DidDocumentMismatch,
        parseDidDocument(arena, fixture_doc, "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", "bsky.app"),
    );
}

test "DID document: missing pieces produce specific errors" {
    var arena_state = std.heap.ArenaAllocator.init(testing.allocator);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    try testing.expectError(error.NoAtprotoSigningKey, parseDidDocument(arena,
        \\{"id":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","alsoKnownAs":["at://a.test"],
        \\ "service":[{"id":"#atproto_pds","type":"AtprotoPersonalDataServer","serviceEndpoint":"https://pds.test"}]}
    , "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", "a.test"));

    try testing.expectError(error.NoPdsEndpoint, parseDidDocument(arena,
        \\{"id":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","alsoKnownAs":["at://a.test"],
        \\ "verificationMethod":[{"id":"#atproto","publicKeyMultibase":"zQ3sh"}],
        \\ "service":[{"id":"#wrong_service","type":"AtprotoPersonalDataServer","serviceEndpoint":"https://pds.test"}]}
    , "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", "a.test"));

    try testing.expectError(error.MalformedDidDocument, parseDidDocument(arena,
        \\{"id":"did:plc:aaaaaaaaaaaaaaaaaaaaaaaa","alsoKnownAs":["at://a.test"],
        \\ "verificationMethod":[{"id":"#atproto","publicKeyMultibase":"zQ3sh"}],
        \\ "service":[{"id":"#atproto_pds","type":"AtprotoPersonalDataServer","serviceEndpoint":"ftp://pds.test"}]}
    , "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", "a.test"));

    try testing.expectError(error.MalformedDidDocument, parseDidDocument(arena, "not json", "did:plc:aaaaaaaaaaaaaaaaaaaaaaaa", null));
}
