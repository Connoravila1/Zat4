//! B1 classification: CORE (pure). The MLS wire codec — RFC 9420's TLS
//! presentation-language encoding (ZAT_CHAT_ROADMAP slice C3, part 1 of 2:
//! the CODEC; the KeyPackage/LeafNode/Welcome/Commit framing structs build
//! on it next).
//!
//! This is the attacker-facing byte boundary of the whole chat system:
//! everything a counterparty (or the relay) hands us parses through here
//! first. So the posture is parse-don't-trust: every read is bounds-checked,
//! every error is explicit in the signature (E3), varints MUST be minimally
//! encoded (the RFC's rule — a non-minimal length is rejected, not
//! normalized), and reading allocates NOTHING (vectors are borrowed slices
//! of the input, so a hostile length can never size an allocation).
//!
//! Encoding (RFC 9420 §2.1.2, the QUIC scheme capped at 4 bytes): the top
//! two bits of the first byte pick the width — 00 = 1 byte (6-bit value),
//! 01 = 2 bytes (14-bit), 10 = 4 bytes (30-bit), 11 = invalid.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;

pub const ReadError = error{
    Truncated,
    NonMinimalEncoding,
    InvalidVarintPrefix,
    TrailingBytes,
};

pub const WriteError = error{ OutOfMemory, ValueTooLarge };

/// The largest value (and vector length) the varint can carry.
pub const varint_max: u32 = (1 << 30) - 1;

/// A bounds-checked cursor over untrusted bytes. Reads BORROW from the
/// input — the caller owns the buffer, nothing is copied or allocated.
/// A7.2: cold struct, size guard waived — one transient per parse.
pub const Reader = struct {
    bytes: []const u8,
    pos: usize = 0,

    pub fn init(bytes: []const u8) Reader {
        return .{ .bytes = bytes };
    }

    pub fn remaining(r: *const Reader) usize {
        return r.bytes.len - r.pos;
    }

    /// The parse consumed everything — anything left over is an error, not
    /// slack (a trailing-garbage smuggling channel otherwise).
    pub fn finish(r: *const Reader) ReadError!void {
        if (r.pos != r.bytes.len) return error.TrailingBytes;
    }

    pub fn readBytes(r: *Reader, n: usize) ReadError![]const u8 {
        if (r.remaining() < n) return error.Truncated;
        const out = r.bytes[r.pos..][0..n];
        r.pos += n;
        return out;
    }

    pub fn readU8(r: *Reader) ReadError!u8 {
        const b = try r.readBytes(1);
        return b[0];
    }

    pub fn readU16(r: *Reader) ReadError!u16 {
        const b = try r.readBytes(2);
        return std.mem.readInt(u16, b[0..2], .big);
    }

    pub fn readU32(r: *Reader) ReadError!u32 {
        const b = try r.readBytes(4);
        return std.mem.readInt(u32, b[0..4], .big);
    }

    pub fn readU64(r: *Reader) ReadError!u64 {
        const b = try r.readBytes(8);
        return std.mem.readInt(u64, b[0..8], .big);
    }

    /// RFC 9420 §2.1.2 varint. Non-minimal encodings are REJECTED (the
    /// RFC's MUST — otherwise one value has many encodings and anything
    /// hashed over the wire form stops being canonical).
    pub fn readVarint(r: *Reader) ReadError!u32 {
        const b0 = try r.readU8();
        switch (b0 >> 6) {
            0 => return b0,
            1 => {
                const b1 = try r.readU8();
                const v = (@as(u32, b0 & 0x3f) << 8) | b1;
                if (v < 64) return error.NonMinimalEncoding;
                return v;
            },
            2 => {
                const rest = try r.readBytes(3);
                const v = (@as(u32, b0 & 0x3f) << 24) |
                    (@as(u32, rest[0]) << 16) |
                    (@as(u32, rest[1]) << 8) |
                    rest[2];
                if (v < 16384) return error.NonMinimalEncoding;
                return v;
            },
            else => return error.InvalidVarintPrefix,
        }
    }

    /// A variable-length vector: varint length, then that many bytes,
    /// returned as a BORROWED slice. The length is checked against what is
    /// actually present before anything is trusted.
    pub fn readVector(r: *Reader) ReadError![]const u8 {
        const len = try r.readVarint();
        return r.readBytes(len);
    }
};

// ---------------------------------------------------------------------------
// Writing — free functions appending to a caller-owned list (C1: the
// allocator is explicit at every call site).
// ---------------------------------------------------------------------------

pub fn writeU8(gpa: Allocator, out: *std.ArrayList(u8), v: u8) error{OutOfMemory}!void {
    try out.append(gpa, v);
}

pub fn writeU16(gpa: Allocator, out: *std.ArrayList(u8), v: u16) error{OutOfMemory}!void {
    var b: [2]u8 = undefined;
    std.mem.writeInt(u16, &b, v, .big);
    try out.appendSlice(gpa, &b);
}

pub fn writeU32(gpa: Allocator, out: *std.ArrayList(u8), v: u32) error{OutOfMemory}!void {
    var b: [4]u8 = undefined;
    std.mem.writeInt(u32, &b, v, .big);
    try out.appendSlice(gpa, &b);
}

pub fn writeU64(gpa: Allocator, out: *std.ArrayList(u8), v: u64) error{OutOfMemory}!void {
    var b: [8]u8 = undefined;
    std.mem.writeInt(u64, &b, v, .big);
    try out.appendSlice(gpa, &b);
}

/// Minimal-width varint — the only encoding the reader accepts.
pub fn writeVarint(gpa: Allocator, out: *std.ArrayList(u8), v: u32) WriteError!void {
    if (v < 64) {
        try out.append(gpa, @intCast(v));
    } else if (v < 16384) {
        try out.appendSlice(gpa, &.{ @intCast(0x40 | (v >> 8)), @intCast(v & 0xff) });
    } else if (v <= varint_max) {
        try out.appendSlice(gpa, &.{
            @intCast(0x80 | (v >> 24)),
            @intCast((v >> 16) & 0xff),
            @intCast((v >> 8) & 0xff),
            @intCast(v & 0xff),
        });
    } else {
        return error.ValueTooLarge;
    }
}

pub fn writeVector(gpa: Allocator, out: *std.ArrayList(u8), bytes: []const u8) WriteError!void {
    if (bytes.len > varint_max) return error.ValueTooLarge;
    try writeVarint(gpa, out, @intCast(bytes.len));
    try out.appendSlice(gpa, bytes);
}

// ---------------------------------------------------------------------------
// The JOIN objects (C3 part 2) — KeyPackage, LeafNode, Welcome and their
// pieces, field-for-field from RFC 9420's presentation definitions (§7.2,
// §10, §12.4.3.1; layouts taken from the spec text, not memory). These are
// PARSE VIEWS: plain data (A1), every byte slice BORROWS from the input
// buffer, nothing is copied. The signature math (SignWithLabel) is the
// crypto core's job — this module only produces the exact TBS bytes.
// ---------------------------------------------------------------------------

pub const ParseError = ReadError || error{
    UnsupportedCredential,
    InvalidEnum,
    MalformedVector,
};

/// ProtocolVersion mls10 (the only registered version).
pub const protocol_version_mls10: u16 = 1;
/// CredentialType basic (an application-asserted identity — the DID here).
pub const credential_basic: u16 = 1;

/// A wire vector of uint16s (the Capabilities fields), kept as the raw
/// bytes it arrived in — reads never allocate. Validated even-length once.
/// A7.2: cold struct, size guard waived — a borrowed view, transient.
pub const U16Vec = struct {
    raw: []const u8,

    pub const empty: U16Vec = .{ .raw = "" };

    pub fn fromRaw(raw: []const u8) ParseError!U16Vec {
        if (raw.len % 2 != 0) return error.MalformedVector;
        return .{ .raw = raw };
    }

    pub fn count(v: U16Vec) usize {
        return v.raw.len / 2;
    }

    pub fn at(v: U16Vec, i: usize) u16 {
        return std.mem.readInt(u16, v.raw[i * 2 ..][0..2], .big);
    }

    pub fn contains(v: U16Vec, needle: u16) bool {
        var i: usize = 0;
        while (i < v.count()) : (i += 1) if (v.at(i) == needle) return true;
        return false;
    }
};

fn writeU16Vec(gpa: Allocator, out: *std.ArrayList(u8), vals: []const u16) WriteError!void {
    if (vals.len * 2 > varint_max) return error.ValueTooLarge;
    try writeVarint(gpa, out, @intCast(vals.len * 2));
    for (vals) |v| try writeU16(gpa, out, v);
}

/// RFC 9420 §7.2. A7.2: cold struct, size guard waived — parse view.
pub const Capabilities = struct {
    versions: U16Vec = .empty,
    cipher_suites: U16Vec = .empty,
    extensions: U16Vec = .empty,
    proposals: U16Vec = .empty,
    credentials: U16Vec = .empty,

    fn parse(r: *Reader) ParseError!Capabilities {
        return .{
            .versions = try U16Vec.fromRaw(try r.readVector()),
            .cipher_suites = try U16Vec.fromRaw(try r.readVector()),
            .extensions = try U16Vec.fromRaw(try r.readVector()),
            .proposals = try U16Vec.fromRaw(try r.readVector()),
            .credentials = try U16Vec.fromRaw(try r.readVector()),
        };
    }

    fn write(c: Capabilities, gpa: Allocator, out: *std.ArrayList(u8)) WriteError!void {
        for ([_]U16Vec{ c.versions, c.cipher_suites, c.extensions, c.proposals, c.credentials }) |v|
            try writeVector(gpa, out, v.raw);
    }
};

/// RFC 9420 §7.2. A7.2: cold struct, size guard waived — two u64s, transient.
pub const Lifetime = struct {
    not_before: u64,
    not_after: u64,
};

/// RFC 9420 §5.3 — v1 speaks the `basic` credential only (the identity is
/// the DID; x509 is explicitly rejected, not silently skipped).
/// A7.2: cold struct, size guard waived — parse view.
pub const Credential = struct {
    identity: []const u8,

    fn parse(r: *Reader) ParseError!Credential {
        const ctype = try r.readU16();
        if (ctype != credential_basic) return error.UnsupportedCredential;
        return .{ .identity = try r.readVector() };
    }

    fn write(c: Credential, gpa: Allocator, out: *std.ArrayList(u8)) WriteError!void {
        try writeU16(gpa, out, credential_basic);
        try writeVector(gpa, out, c.identity);
    }
};

pub const LeafNodeSource = enum(u8) { key_package = 1, update = 2, commit = 3 };

/// The source-dependent select arm of a LeafNode (§7.2).
/// A7.2: cold union, size guard waived — parse view.
pub const SourceInfo = union(LeafNodeSource) {
    key_package: Lifetime,
    update: void,
    commit: []const u8, // parent_hash
};

/// RFC 9420 §7.2. A7.2: cold struct, size guard waived — parse view; the
/// HOT collections (the ratchet tree's rows) live in the MLS core with
/// their own guards.
pub const LeafNode = struct {
    encryption_key: []const u8,
    signature_key: []const u8,
    credential: Credential,
    capabilities: Capabilities,
    source: SourceInfo,
    /// The raw `Extension extensions<V>` bytes — v1 carries none of its own
    /// and interprets none; the bytes round-trip untouched.
    extensions_raw: []const u8,
    signature: []const u8,

    pub fn parse(r: *Reader) ParseError!LeafNode {
        var ln: LeafNode = undefined;
        ln.encryption_key = try r.readVector();
        ln.signature_key = try r.readVector();
        ln.credential = try Credential.parse(r);
        ln.capabilities = try Capabilities.parse(r);
        ln.source = switch (try r.readU8()) {
            1 => .{ .key_package = .{ .not_before = try r.readU64(), .not_after = try r.readU64() } },
            2 => .update,
            3 => .{ .commit = try r.readVector() },
            else => return error.InvalidEnum,
        };
        ln.extensions_raw = try r.readVector();
        ln.signature = try r.readVector();
        return ln;
    }

    /// Everything except the trailing signature — shared by the full
    /// serialization and the TBS builder so the two can never drift.
    fn writeUnsigned(ln: LeafNode, gpa: Allocator, out: *std.ArrayList(u8)) WriteError!void {
        try writeVector(gpa, out, ln.encryption_key);
        try writeVector(gpa, out, ln.signature_key);
        try ln.credential.write(gpa, out);
        try ln.capabilities.write(gpa, out);
        try writeU8(gpa, out, @intFromEnum(ln.source));
        switch (ln.source) {
            .key_package => |lt| {
                try writeU64(gpa, out, lt.not_before);
                try writeU64(gpa, out, lt.not_after);
            },
            .update => {},
            .commit => |ph| try writeVector(gpa, out, ph),
        }
        try writeVector(gpa, out, ln.extensions_raw);
    }

    pub fn write(ln: LeafNode, gpa: Allocator, out: *std.ArrayList(u8)) WriteError!void {
        try ln.writeUnsigned(gpa, out);
        try writeVector(gpa, out, ln.signature);
    }
};

/// LeafNodeTBS (§7.2): the signed content. For `update`/`commit` sources
/// the RFC appends the group binding; `key_package` appends nothing, and
/// v1 (KeyPackages only) passes null.
pub fn serializeLeafNodeTBS(
    gpa: Allocator,
    out: *std.ArrayList(u8),
    ln: LeafNode,
    group: ?struct { group_id: []const u8, leaf_index: u32 },
) (WriteError || error{MissingGroupBinding})!void {
    try ln.writeUnsigned(gpa, out);
    switch (ln.source) {
        .key_package => {},
        .update, .commit => {
            const g = group orelse return error.MissingGroupBinding;
            try writeVector(gpa, out, g.group_id);
            try writeU32(gpa, out, g.leaf_index);
        },
    }
}

/// RFC 9420 §10. A7.2: cold struct, size guard waived — parse view.
pub const KeyPackage = struct {
    version: u16,
    cipher_suite: u16,
    init_key: []const u8,
    leaf_node: LeafNode,
    extensions_raw: []const u8,
    signature: []const u8,

    pub fn parse(bytes: []const u8) ParseError!KeyPackage {
        var r = Reader.init(bytes);
        const kp = try parseFrom(&r);
        try r.finish();
        return kp;
    }

    pub fn parseFrom(r: *Reader) ParseError!KeyPackage {
        var kp: KeyPackage = undefined;
        kp.version = try r.readU16();
        kp.cipher_suite = try r.readU16();
        kp.init_key = try r.readVector();
        kp.leaf_node = try LeafNode.parse(r);
        kp.extensions_raw = try r.readVector();
        kp.signature = try r.readVector();
        return kp;
    }

    fn writeUnsigned(kp: KeyPackage, gpa: Allocator, out: *std.ArrayList(u8)) WriteError!void {
        try writeU16(gpa, out, kp.version);
        try writeU16(gpa, out, kp.cipher_suite);
        try writeVector(gpa, out, kp.init_key);
        try kp.leaf_node.write(gpa, out);
        try writeVector(gpa, out, kp.extensions_raw);
    }

    pub fn write(kp: KeyPackage, gpa: Allocator, out: *std.ArrayList(u8)) WriteError!void {
        try kp.writeUnsigned(gpa, out);
        try writeVector(gpa, out, kp.signature);
    }
};

/// KeyPackageTBS (§10) — the KeyPackage minus its trailing signature.
pub fn serializeKeyPackageTBS(gpa: Allocator, out: *std.ArrayList(u8), kp: KeyPackage) WriteError!void {
    try kp.writeUnsigned(gpa, out);
}

/// RFC 9420 §12.4.3.1. A7.2: cold structs, size guards waived — parse views.
pub const HpkeCiphertext = struct {
    kem_output: []const u8,
    ciphertext: []const u8,

    fn parse(r: *Reader) ParseError!HpkeCiphertext {
        return .{ .kem_output = try r.readVector(), .ciphertext = try r.readVector() };
    }

    fn write(h: HpkeCiphertext, gpa: Allocator, out: *std.ArrayList(u8)) WriteError!void {
        try writeVector(gpa, out, h.kem_output);
        try writeVector(gpa, out, h.ciphertext);
    }
};

/// A7.2: cold struct, size guard waived — parse view.
pub const EncryptedGroupSecrets = struct {
    /// KeyPackageRef — the hash reference naming which new member this is for.
    new_member: []const u8,
    encrypted_group_secrets: HpkeCiphertext,

    fn parse(r: *Reader) ParseError!EncryptedGroupSecrets {
        return .{ .new_member = try r.readVector(), .encrypted_group_secrets = try HpkeCiphertext.parse(r) };
    }

    pub fn write(e: EncryptedGroupSecrets, gpa: Allocator, out: *std.ArrayList(u8)) WriteError!void {
        try writeVector(gpa, out, e.new_member);
        try e.encrypted_group_secrets.write(gpa, out);
    }
};

/// A7.2: cold struct, size guard waived — parse view. `secrets` stays raw;
/// iterate with `secretsIter` (a 1:1 Welcome carries exactly one entry, but
/// the wire shape is the RFC's).
pub const Welcome = struct {
    cipher_suite: u16,
    secrets_raw: []const u8,
    encrypted_group_info: []const u8,

    pub fn parse(bytes: []const u8) ParseError!Welcome {
        var r = Reader.init(bytes);
        const w: Welcome = .{
            .cipher_suite = try r.readU16(),
            .secrets_raw = try r.readVector(),
            .encrypted_group_info = try r.readVector(),
        };
        try r.finish();
        return w;
    }

    pub fn write(w: Welcome, gpa: Allocator, out: *std.ArrayList(u8)) WriteError!void {
        try writeU16(gpa, out, w.cipher_suite);
        try writeVector(gpa, out, w.secrets_raw);
        try writeVector(gpa, out, w.encrypted_group_info);
    }

    pub fn secretsIter(w: Welcome) SecretsIter {
        return .{ .r = Reader.init(w.secrets_raw) };
    }
};

/// A7.2: cold struct, size guard waived — transient iterator.
pub const SecretsIter = struct {
    r: Reader,

    pub fn next(it: *SecretsIter) ParseError!?EncryptedGroupSecrets {
        if (it.r.remaining() == 0) return null;
        return try EncryptedGroupSecrets.parse(&it.r);
    }
};

/// GroupSecrets (§12.4.3.1) — the plaintext INSIDE the Welcome's HPKE
/// envelope. `optional<PathSecret>` is a presence byte then the struct.
/// v1 supports no PSKs: a non-empty psks vector is rejected outright
/// rather than half-honored (E3 — refusing beats misdecrypting).
/// A7.2: cold struct, size guard waived — parse view.
pub const GroupSecrets = struct {
    joiner_secret: []const u8,
    path_secret: ?[]const u8,

    pub fn parse(bytes: []const u8) (ParseError || error{UnsupportedPsk})!GroupSecrets {
        var r = Reader.init(bytes);
        const joiner = try r.readVector();
        const path: ?[]const u8 = switch (try r.readU8()) {
            0 => null,
            1 => try r.readVector(),
            else => return error.InvalidEnum,
        };
        const psks = try r.readVector();
        if (psks.len != 0) return error.UnsupportedPsk;
        try r.finish();
        return .{ .joiner_secret = joiner, .path_secret = path };
    }

    pub fn write(g: GroupSecrets, gpa: Allocator, out: *std.ArrayList(u8)) WriteError!void {
        try writeVector(gpa, out, g.joiner_secret);
        if (g.path_secret) |ps| {
            try writeU8(gpa, out, 1);
            try writeVector(gpa, out, ps);
        } else {
            try writeU8(gpa, out, 0);
        }
        try writeVarint(gpa, out, 0); // psks<V>: empty (no PSKs in v1)
    }
};

/// Build a Capabilities advertising exactly what v1 speaks — mls10, one
/// cipher suite, the basic credential, no extensions or proposals.
pub fn writeOwnCapabilities(gpa: Allocator, out: *std.ArrayList(u8), cipher_suite: u16) WriteError!void {
    const caps_versions = [_]u16{protocol_version_mls10};
    const caps_suites = [_]u16{cipher_suite};
    const caps_creds = [_]u16{credential_basic};
    try writeU16Vec(gpa, out, &caps_versions);
    try writeU16Vec(gpa, out, &caps_suites);
    try writeU16Vec(gpa, out, &.{});
    try writeU16Vec(gpa, out, &.{});
    try writeU16Vec(gpa, out, &caps_creds);
}

// ---------------------------------------------------------------------------
// Tests (C6: leak-checked). The boundary values are the RFC's width
// breakpoints; the rejections are the rules a hostile peer will probe.
// ---------------------------------------------------------------------------

const testing = std.testing;

test "varint: boundary values round-trip in minimal width" {
    const gpa = testing.allocator;
    const cases = [_]struct { v: u32, bytes: []const u8 }{
        .{ .v = 0, .bytes = &.{0x00} },
        .{ .v = 37, .bytes = &.{0x25} },
        .{ .v = 63, .bytes = &.{0x3f} },
        .{ .v = 64, .bytes = &.{ 0x40, 0x40 } },
        .{ .v = 16383, .bytes = &.{ 0x7f, 0xff } },
        .{ .v = 16384, .bytes = &.{ 0x80, 0x00, 0x40, 0x00 } },
        .{ .v = varint_max, .bytes = &.{ 0xbf, 0xff, 0xff, 0xff } },
    };
    for (cases) |c| {
        var out: std.ArrayList(u8) = .empty;
        defer out.deinit(gpa);
        try writeVarint(gpa, &out, c.v);
        try testing.expectEqualSlices(u8, c.bytes, out.items);
        var r = Reader.init(out.items);
        try testing.expectEqual(c.v, try r.readVarint());
        try r.finish();
    }
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try testing.expectError(error.ValueTooLarge, writeVarint(gpa, &out, varint_max + 1));
}

test "varint: non-minimal and invalid prefixes are rejected" {
    // 37 padded into two bytes: one value, two encodings — forbidden.
    var r1 = Reader.init(&.{ 0x40, 0x25 });
    try testing.expectError(error.NonMinimalEncoding, r1.readVarint());
    // 37 padded into four bytes.
    var r2 = Reader.init(&.{ 0x80, 0x00, 0x00, 0x25 });
    try testing.expectError(error.NonMinimalEncoding, r2.readVarint());
    // The 11 prefix has no meaning in MLS.
    var r3 = Reader.init(&.{0xc0});
    try testing.expectError(error.InvalidVarintPrefix, r3.readVarint());
    // A width promise the input can't keep.
    var r4 = Reader.init(&.{0x80});
    try testing.expectError(error.Truncated, r4.readVarint());
}

test "vectors: round-trip, nesting, hostile lengths, trailing bytes" {
    const gpa = testing.allocator;

    // A vector of two inner vectors — the nesting every MLS struct uses.
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var inner: std.ArrayList(u8) = .empty;
    defer inner.deinit(gpa);
    try writeVector(gpa, &inner, "hello");
    try writeVector(gpa, &inner, "");
    try writeVector(gpa, &out, inner.items);

    var r = Reader.init(out.items);
    var body = Reader.init(try r.readVector());
    try r.finish();
    try testing.expectEqualSlices(u8, "hello", try body.readVector());
    try testing.expectEqualSlices(u8, "", try body.readVector());
    try body.finish();

    // A length that promises more than the input holds: rejected before
    // anything downstream sees it (and nothing was allocated to size it).
    var hostile = Reader.init(&.{ 0xbf, 0xff, 0xff, 0xff, 'x' });
    try testing.expectError(error.Truncated, hostile.readVector());

    // Trailing garbage after a complete parse is an error, not slack.
    var trailing = Reader.init(&.{ 0x01, 'a', 'z' });
    _ = try trailing.readVector();
    try testing.expectError(error.TrailingBytes, trailing.finish());
}

test "fixed-width integers round-trip big-endian" {
    const gpa = testing.allocator;
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try writeU8(gpa, &out, 0xab);
    try writeU16(gpa, &out, 0x0102);
    try writeU32(gpa, &out, 0xdeadbeef);
    try writeU64(gpa, &out, 0x0123456789abcdef);
    var r = Reader.init(out.items);
    try testing.expectEqual(@as(u8, 0xab), try r.readU8());
    try testing.expectEqual(@as(u16, 0x0102), try r.readU16());
    try testing.expectEqual(@as(u32, 0xdeadbeef), try r.readU32());
    try testing.expectEqual(@as(u64, 0x0123456789abcdef), try r.readU64());
    try r.finish();
}

fn sampleLeafNode() LeafNode {
    return .{
        .encryption_key = "\x01\x02\x03\x04",
        .signature_key = "\xaa\xbb\xcc",
        .credential = .{ .identity = "did:plc:maya" },
        .capabilities = .{
            .versions = .{ .raw = "\x00\x01" },
            .cipher_suites = .{ .raw = "\x64\x7a" },
            .credentials = .{ .raw = "\x00\x01" },
        },
        .source = .{ .key_package = .{ .not_before = 1000, .not_after = 9999 } },
        .extensions_raw = "",
        .signature = "\xd0\x0d",
    };
}

test "KeyPackage: round-trip, and TBS is the serialization minus the signature" {
    const gpa = testing.allocator;
    const kp: KeyPackage = .{
        .version = protocol_version_mls10,
        .cipher_suite = 0x647a,
        .init_key = "\x11\x22\x33",
        .leaf_node = sampleLeafNode(),
        .extensions_raw = "",
        .signature = "\xfe\xed\xfa\xce",
    };
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try kp.write(gpa, &out);

    const back = try KeyPackage.parse(out.items);
    try testing.expectEqual(kp.version, back.version);
    try testing.expectEqual(kp.cipher_suite, back.cipher_suite);
    try testing.expectEqualSlices(u8, kp.init_key, back.init_key);
    try testing.expectEqualSlices(u8, "did:plc:maya", back.leaf_node.credential.identity);
    try testing.expectEqual(@as(u64, 9999), back.leaf_node.source.key_package.not_after);
    try testing.expect(back.leaf_node.capabilities.cipher_suites.contains(0x647a));
    try testing.expectEqualSlices(u8, kp.signature, back.signature);

    // The TBS bytes are exactly the serialization with the trailing
    // signature vector removed — the signed content can never drift from
    // the transmitted content.
    var tbs: std.ArrayList(u8) = .empty;
    defer tbs.deinit(gpa);
    try serializeKeyPackageTBS(gpa, &tbs, kp);
    const sig_wire_len = 1 + kp.signature.len; // varint(4) is one byte
    try testing.expectEqualSlices(u8, out.items[0 .. out.items.len - sig_wire_len], tbs.items);

    // A truncated KeyPackage is an explicit error at every cut point.
    var cut: usize = 0;
    while (cut < out.items.len) : (cut += 7) {
        try testing.expectError(error.Truncated, KeyPackage.parse(out.items[0..cut]));
    }
}

test "LeafNode: source arms round-trip; TBS group binding is enforced" {
    const gpa = testing.allocator;
    var ln = sampleLeafNode();
    ln.source = .{ .commit = "\x99\x88" };
    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    try ln.write(gpa, &out);
    var r = Reader.init(out.items);
    const back = try LeafNode.parse(&r);
    try r.finish();
    try testing.expectEqualSlices(u8, "\x99\x88", back.source.commit);

    // A commit/update-sourced TBS without its group binding is an error,
    // not a silently-shorter signed blob.
    var tbs: std.ArrayList(u8) = .empty;
    defer tbs.deinit(gpa);
    try testing.expectError(error.MissingGroupBinding, serializeLeafNodeTBS(gpa, &tbs, ln, null));
    try serializeLeafNodeTBS(gpa, &tbs, ln, .{ .group_id = "g1", .leaf_index = 1 });
    try testing.expect(tbs.items.len > 0);

    // An x509 credential is rejected, not skipped.
    var bad: std.ArrayList(u8) = .empty;
    defer bad.deinit(gpa);
    try writeVector(gpa, &bad, ln.encryption_key);
    try writeVector(gpa, &bad, ln.signature_key);
    try writeU16(gpa, &bad, 2); // x509
    var br = Reader.init(bad.items);
    try testing.expectError(error.UnsupportedCredential, LeafNode.parse(&br));
}

test "Welcome + GroupSecrets: round-trip, iterator, PSK refusal" {
    const gpa = testing.allocator;

    var egs_bytes: std.ArrayList(u8) = .empty;
    defer egs_bytes.deinit(gpa);
    const egs: EncryptedGroupSecrets = .{
        .new_member = "ref-hash-bytes",
        .encrypted_group_secrets = .{ .kem_output = "\x01\x02", .ciphertext = "\x03\x04\x05" },
    };
    try egs.write(gpa, &egs_bytes);

    const w: Welcome = .{ .cipher_suite = 0x647a, .secrets_raw = egs_bytes.items, .encrypted_group_info = "gi" };
    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    try w.write(gpa, &wire);

    const back = try Welcome.parse(wire.items);
    var it = back.secretsIter();
    const first = (try it.next()).?;
    try testing.expectEqualSlices(u8, "ref-hash-bytes", first.new_member);
    try testing.expectEqualSlices(u8, "\x03\x04\x05", first.encrypted_group_secrets.ciphertext);
    try testing.expectEqual(@as(?EncryptedGroupSecrets, null), try it.next());

    // GroupSecrets: both optional arms round-trip; a PSK list is refused.
    for ([_]?[]const u8{ null, "path-secret" }) |ps| {
        var gsb: std.ArrayList(u8) = .empty;
        defer gsb.deinit(gpa);
        const gsec: GroupSecrets = .{ .joiner_secret = "joiner", .path_secret = ps };
        try gsec.write(gpa, &gsb);
        const gback = try GroupSecrets.parse(gsb.items);
        try testing.expectEqualSlices(u8, "joiner", gback.joiner_secret);
        try testing.expectEqual(ps == null, gback.path_secret == null);
    }
    var with_psk: std.ArrayList(u8) = .empty;
    defer with_psk.deinit(gpa);
    try writeVector(gpa, &with_psk, "joiner");
    try writeU8(gpa, &with_psk, 0);
    try writeVector(gpa, &with_psk, "\x01"); // a non-empty psks vector
    try testing.expectError(error.UnsupportedPsk, GroupSecrets.parse(with_psk.items));
}

test "fuzz: KeyPackage.parse tolerates mutated wire bytes" {
    const gpa = testing.allocator;
    const fuzzgen = @import("fuzzgen.zig");

    var wire: std.ArrayList(u8) = .empty;
    defer wire.deinit(gpa);
    const kp: KeyPackage = .{
        .version = protocol_version_mls10,
        .cipher_suite = 0x647a,
        .init_key = "\x11\x22\x33",
        .leaf_node = sampleLeafNode(),
        .extensions_raw = "",
        .signature = "\xfe\xed",
    };
    try kp.write(gpa, &wire);

    var g = fuzzgen.Gen.init(0x94202);
    var buf: [256]u8 = undefined;
    const seeds = [_][]const u8{wire.items};
    const heads = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x3f, 0x40, 0x7f, 0x80, 0xbf, 0xc0, 0xff };
    var i: usize = 0;
    while (i < 4000) : (i += 1) {
        const input = g.next(&buf, &seeds, &heads, i);
        // Any outcome is fine; a crash or OOB read is the failure.
        _ = KeyPackage.parse(input) catch continue;
    }
}

test "fuzz: the reader tolerates arbitrary bytes (no crash, no allocation)" {
    const fuzzgen = @import("fuzzgen.zig");
    var g = fuzzgen.Gen.init(0x9420);
    var buf: [256]u8 = undefined;
    // Seeds shaped like real framing: nested vectors, fixed ints, varints.
    const seeds = [_][]const u8{
        &.{ 0x08, 0x01, 0x00, 0x01, 0x05, 'h', 'e', 'l', 'l', 'o' },
        &.{ 0x7f, 0xff, 0x00 },
        &.{ 0xbf, 0xff, 0xff, 0xff },
        &.{0x00},
    };
    // Width-prefix bytes reach every varint branch; the rest is noise.
    const heads = [_]u8{ 0x00, 0x3f, 0x40, 0x7f, 0x80, 0xbf, 0xc0, 0xff, 0x01, 0x05 };
    var i: usize = 0;
    while (i < 4000) : (i += 1) {
        const input = g.next(&buf, &seeds, &heads, i);
        // Drive a plausible parse shape over hostile bytes: any error is
        // fine; a crash, hang, or out-of-bounds read is the failure.
        var r = Reader.init(input);
        _ = r.readU16() catch continue;
        var depth: usize = 0;
        while (depth < 8) : (depth += 1) {
            const vec = r.readVector() catch break;
            var innr = Reader.init(vec);
            _ = innr.readVarint() catch {};
            _ = r.readU64() catch break;
        }
        r.finish() catch continue;
    }
}
