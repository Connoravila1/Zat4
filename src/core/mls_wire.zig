//! B1 classification: CORE (pure). The MLS wire codec — RFC 9420's TLS
//! presentation-language encoding (ZAT_CHAT_ROADMAP slice C3, all three
//! parts: the codec, the join objects, and the handshake/message framing).
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

/// Minimal-width varint into a caller stack buffer — for allocation-free
/// callers (the key schedule's label encoding).
pub fn varintBytes(buf: *[4]u8, v: u32) error{ValueTooLarge}![]const u8 {
    if (v < 64) {
        buf[0] = @intCast(v);
        return buf[0..1];
    } else if (v < 16384) {
        buf[0] = @intCast(0x40 | (v >> 8));
        buf[1] = @intCast(v & 0xff);
        return buf[0..2];
    } else if (v <= varint_max) {
        buf[0] = @intCast(0x80 | (v >> 24));
        buf[1] = @intCast((v >> 16) & 0xff);
        buf[2] = @intCast((v >> 8) & 0xff);
        buf[3] = @intCast(v & 0xff);
        return buf[0..4];
    }
    return error.ValueTooLarge;
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
    UnsupportedProposal,
    UnsupportedVersion,
    InvalidEnum,
    MalformedVector,
    NonZeroPadding,
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

/// The group binding an update/commit-sourced LeafNodeTBS carries (§7.2).
/// A7.2: cold struct, size guard waived — transient parameter.
pub const GroupBinding = struct { group_id: []const u8, leaf_index: u32 };

/// LeafNodeTBS (§7.2): the signed content. For `update`/`commit` sources
/// the RFC appends the group binding; `key_package` appends nothing, and
/// v1 (KeyPackages only) passes null.
pub fn serializeLeafNodeTBS(
    gpa: Allocator,
    out: *std.ArrayList(u8),
    ln: LeafNode,
    group: ?GroupBinding,
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

    pub fn parse(r: *Reader) ParseError!HpkeCiphertext {
        return .{ .kem_output = try r.readVector(), .ciphertext = try r.readVector() };
    }

    pub fn write(h: HpkeCiphertext, gpa: Allocator, out: *std.ArrayList(u8)) WriteError!void {
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
        const w = try parseFrom(&r);
        try r.finish();
        return w;
    }

    pub fn parseFrom(r: *Reader) ParseError!Welcome {
        return .{
            .cipher_suite = try r.readU16(),
            .secrets_raw = try r.readVector(),
            .encrypted_group_info = try r.readVector(),
        };
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
// The HANDSHAKE + MESSAGE framing (C3 part 3) — GroupContext/GroupInfo,
// Proposal/Commit/UpdatePath, FramedContent/PublicMessage/PrivateMessage and
// their TBS/AAD companions, field-for-field from RFC 9420 §6, §7.1, §8.1,
// §12.1–§12.4. Same posture as the join objects: borrowed-slice parse views,
// TBS bytes produced by the same writer minus the signature, vectors of
// structs kept raw with explicit iterators (a hostile count never sizes an
// allocation).
// ---------------------------------------------------------------------------

/// WireFormat registry values (§17.2).
pub const wire_public_message: u16 = 1;
pub const wire_private_message: u16 = 2;
pub const wire_welcome: u16 = 3;
pub const wire_group_info: u16 = 4;
pub const wire_key_package: u16 = 5;

/// ExtensionType ratchet_tree (§17.3) — the one extension v1 emits/reads.
pub const extension_ratchet_tree: u16 = 2;

pub const ContentType = enum(u8) { application = 1, proposal = 2, commit = 3 };

fn contentTypeFrom(b: u8) ParseError!ContentType {
    return switch (b) {
        1 => .application,
        2 => .proposal,
        3 => .commit,
        else => error.InvalidEnum,
    };
}

/// RFC 9420 §8.1. A7.2: cold struct, size guard waived — parse view.
pub const GroupContext = struct {
    version: u16,
    cipher_suite: u16,
    group_id: []const u8,
    epoch: u64,
    tree_hash: []const u8,
    confirmed_transcript_hash: []const u8,
    extensions_raw: []const u8,

    pub fn parse(bytes: []const u8) ParseError!GroupContext {
        var r = Reader.init(bytes);
        const gc = try parseFrom(&r);
        try r.finish();
        return gc;
    }

    pub fn parseFrom(r: *Reader) ParseError!GroupContext {
        return .{
            .version = try r.readU16(),
            .cipher_suite = try r.readU16(),
            .group_id = try r.readVector(),
            .epoch = try r.readU64(),
            .tree_hash = try r.readVector(),
            .confirmed_transcript_hash = try r.readVector(),
            .extensions_raw = try r.readVector(),
        };
    }

    pub fn write(gc: GroupContext, gpa: Allocator, out: *std.ArrayList(u8)) WriteError!void {
        try writeU16(gpa, out, gc.version);
        try writeU16(gpa, out, gc.cipher_suite);
        try writeVector(gpa, out, gc.group_id);
        try writeU64(gpa, out, gc.epoch);
        try writeVector(gpa, out, gc.tree_hash);
        try writeVector(gpa, out, gc.confirmed_transcript_hash);
        try writeVector(gpa, out, gc.extensions_raw);
    }
};

/// One `Extension` (§13.4) as a borrowed view.
/// A7.2: cold struct, size guard waived — parse view.
pub const Extension = struct {
    extension_type: u16,
    data: []const u8,
};

/// A7.2: cold struct, size guard waived — transient iterator.
pub const ExtensionIter = struct {
    r: Reader,

    pub fn next(it: *ExtensionIter) ParseError!?Extension {
        if (it.r.remaining() == 0) return null;
        return .{ .extension_type = try it.r.readU16(), .data = try it.r.readVector() };
    }
};

/// Iterate the body of an `Extension extensions<V>` vector (the raw bytes a
/// parse view carries in `extensions_raw`).
pub fn extensionsIter(raw: []const u8) ExtensionIter {
    return .{ .r = Reader.init(raw) };
}

pub fn writeExtension(gpa: Allocator, out: *std.ArrayList(u8), extension_type: u16, data: []const u8) WriteError!void {
    try writeU16(gpa, out, extension_type);
    try writeVector(gpa, out, data);
}

/// RFC 9420 §7.1. A7.2: cold struct, size guard waived — parse view.
pub const ParentNode = struct {
    encryption_key: []const u8,
    parent_hash: []const u8,
    /// The raw `uint32 unmerged_leaves<V>` bytes (validated multiple-of-4).
    unmerged_leaves_raw: []const u8,

    pub fn parseFrom(r: *Reader) ParseError!ParentNode {
        const pn: ParentNode = .{
            .encryption_key = try r.readVector(),
            .parent_hash = try r.readVector(),
            .unmerged_leaves_raw = try r.readVector(),
        };
        if (pn.unmerged_leaves_raw.len % 4 != 0) return error.MalformedVector;
        return pn;
    }

    pub fn write(pn: ParentNode, gpa: Allocator, out: *std.ArrayList(u8)) WriteError!void {
        try writeVector(gpa, out, pn.encryption_key);
        try writeVector(gpa, out, pn.parent_hash);
        try writeVector(gpa, out, pn.unmerged_leaves_raw);
    }

    pub fn unmergedCount(pn: ParentNode) usize {
        return pn.unmerged_leaves_raw.len / 4;
    }

    pub fn unmergedAt(pn: ParentNode, i: usize) u32 {
        return std.mem.readInt(u32, pn.unmerged_leaves_raw[i * 4 ..][0..4], .big);
    }
};

pub const node_type_leaf: u8 = 1;
pub const node_type_parent: u8 = 2;

/// One ratchet-tree slot (§12.4.3.3): a leaf, a parent, or blank.
/// A7.2: cold union, size guard waived — parse view.
pub const Node = union(enum) {
    leaf: LeafNode,
    parent: ParentNode,
};

/// A7.2: cold struct, size guard waived — transient iterator.
pub const RatchetTreeIter = struct {
    r: Reader,

    /// Yields one `optional<Node>` per call: null at end of tree, `.blank`
    /// distinguished from a present node by the outer optional.
    pub fn next(it: *RatchetTreeIter) ParseError!?(?Node) {
        if (it.r.remaining() == 0) return null;
        switch (try it.r.readU8()) {
            0 => return @as(?Node, null),
            1 => switch (try it.r.readU8()) {
                node_type_leaf => return @as(?Node, .{ .leaf = try LeafNode.parse(&it.r) }),
                node_type_parent => return @as(?Node, .{ .parent = try ParentNode.parseFrom(&it.r) }),
                else => return error.InvalidEnum,
            },
            else => return error.InvalidEnum,
        }
    }
};

/// Iterate a serialized `optional<Node> ratchet_tree<V>` (an extension body).
pub fn ratchetTreeIter(extension_data: []const u8) ParseError!RatchetTreeIter {
    var r = Reader.init(extension_data);
    const body = try r.readVector();
    try r.finish();
    return .{ .r = Reader.init(body) };
}

/// RFC 9420 §12.4.3. A7.2: cold struct, size guard waived — parse view.
pub const GroupInfo = struct {
    group_context: GroupContext,
    /// The GroupContext's EXACT wire bytes as parsed — the key schedule
    /// hashes these; keeping the original span beats re-serialization.
    group_context_raw: []const u8,
    extensions_raw: []const u8,
    confirmation_tag: []const u8,
    signer: u32,
    signature: []const u8,

    pub fn parse(bytes: []const u8) ParseError!GroupInfo {
        var r = Reader.init(bytes);
        const gi = try parseFrom(&r);
        try r.finish();
        return gi;
    }

    pub fn parseFrom(r: *Reader) ParseError!GroupInfo {
        const gc_start = r.pos;
        const group_context = try GroupContext.parseFrom(r);
        const group_context_raw = r.bytes[gc_start..r.pos];
        return .{
            .group_context = group_context,
            .group_context_raw = group_context_raw,
            .extensions_raw = try r.readVector(),
            .confirmation_tag = try r.readVector(),
            .signer = try r.readU32(),
            .signature = try r.readVector(),
        };
    }

    /// GroupInfoTBS (§12.4.3) — everything above the signature.
    pub fn writeUnsigned(gi: GroupInfo, gpa: Allocator, out: *std.ArrayList(u8)) WriteError!void {
        try gi.group_context.write(gpa, out);
        try writeVector(gpa, out, gi.extensions_raw);
        try writeVector(gpa, out, gi.confirmation_tag);
        try writeU32(gpa, out, gi.signer);
    }

    pub fn write(gi: GroupInfo, gpa: Allocator, out: *std.ArrayList(u8)) WriteError!void {
        try gi.writeUnsigned(gpa, out);
        try writeVector(gpa, out, gi.signature);
    }
};

/// ProposalType registry values (§17.4) — v1 speaks add/update/remove; the
/// rest are refused at parse (E3), not skipped.
pub const proposal_add: u16 = 1;
pub const proposal_update: u16 = 2;
pub const proposal_remove: u16 = 3;

/// RFC 9420 §12.1. A7.2: cold union, size guard waived — parse view.
pub const Proposal = union(enum) {
    add: KeyPackage,
    update: LeafNode,
    remove: u32,

    pub fn parseFrom(r: *Reader) ParseError!Proposal {
        return switch (try r.readU16()) {
            proposal_add => .{ .add = try KeyPackage.parseFrom(r) },
            proposal_update => .{ .update = try LeafNode.parse(r) },
            proposal_remove => .{ .remove = try r.readU32() },
            4...7 => error.UnsupportedProposal, // psk/reinit/external_init/gce
            else => error.InvalidEnum,
        };
    }

    pub fn write(p: Proposal, gpa: Allocator, out: *std.ArrayList(u8)) WriteError!void {
        switch (p) {
            .add => |kp| {
                try writeU16(gpa, out, proposal_add);
                try kp.write(gpa, out);
            },
            .update => |ln| {
                try writeU16(gpa, out, proposal_update);
                try ln.write(gpa, out);
            },
            .remove => |idx| {
                try writeU16(gpa, out, proposal_remove);
                try writeU32(gpa, out, idx);
            },
        }
    }
};

/// RFC 9420 §12.4. A7.2: cold union, size guard waived — parse view.
pub const ProposalOrRef = union(enum) {
    proposal: Proposal,
    reference: []const u8,

    pub fn parseFrom(r: *Reader) ParseError!ProposalOrRef {
        return switch (try r.readU8()) {
            1 => .{ .proposal = try Proposal.parseFrom(r) },
            2 => .{ .reference = try r.readVector() },
            else => error.InvalidEnum,
        };
    }

    pub fn write(p: ProposalOrRef, gpa: Allocator, out: *std.ArrayList(u8)) WriteError!void {
        switch (p) {
            .proposal => |prop| {
                try writeU8(gpa, out, 1);
                try prop.write(gpa, out);
            },
            .reference => |ref| {
                try writeU8(gpa, out, 2);
                try writeVector(gpa, out, ref);
            },
        }
    }
};

/// A7.2: cold struct, size guard waived — transient iterator.
pub const ProposalOrRefIter = struct {
    r: Reader,

    pub fn next(it: *ProposalOrRefIter) ParseError!?ProposalOrRef {
        if (it.r.remaining() == 0) return null;
        return try ProposalOrRef.parseFrom(&it.r);
    }
};

/// RFC 9420 §7.6. A7.2: cold struct, size guard waived — parse view.
/// `encrypted_path_secrets_raw` is the `HPKECiphertext encrypted_path_secret<V>`
/// body: one ciphertext per node in the copath resolution.
pub const UpdatePathNode = struct {
    encryption_key: []const u8,
    encrypted_path_secrets_raw: []const u8,

    pub fn parseFrom(r: *Reader) ParseError!UpdatePathNode {
        return .{
            .encryption_key = try r.readVector(),
            .encrypted_path_secrets_raw = try r.readVector(),
        };
    }

    pub fn write(n: UpdatePathNode, gpa: Allocator, out: *std.ArrayList(u8)) WriteError!void {
        try writeVector(gpa, out, n.encryption_key);
        try writeVector(gpa, out, n.encrypted_path_secrets_raw);
    }

    pub fn ciphertextsIter(n: UpdatePathNode) HpkeCiphertextIter {
        return .{ .r = Reader.init(n.encrypted_path_secrets_raw) };
    }
};

/// A7.2: cold struct, size guard waived — transient iterator.
pub const HpkeCiphertextIter = struct {
    r: Reader,

    pub fn next(it: *HpkeCiphertextIter) ParseError!?HpkeCiphertext {
        if (it.r.remaining() == 0) return null;
        return try HpkeCiphertext.parse(&it.r);
    }
};

/// RFC 9420 §7.6. A7.2: cold struct, size guard waived — parse view.
pub const UpdatePath = struct {
    leaf_node: LeafNode,
    /// The `UpdatePathNode nodes<V>` body, kept raw.
    nodes_raw: []const u8,

    pub fn parseFrom(r: *Reader) ParseError!UpdatePath {
        return .{
            .leaf_node = try LeafNode.parse(r),
            .nodes_raw = try r.readVector(),
        };
    }

    pub fn write(up: UpdatePath, gpa: Allocator, out: *std.ArrayList(u8)) WriteError!void {
        try up.leaf_node.write(gpa, out);
        try writeVector(gpa, out, up.nodes_raw);
    }

    pub fn nodesIter(up: UpdatePath) UpdatePathNodeIter {
        return .{ .r = Reader.init(up.nodes_raw) };
    }
};

/// A7.2: cold struct, size guard waived — transient iterator.
pub const UpdatePathNodeIter = struct {
    r: Reader,

    pub fn next(it: *UpdatePathNodeIter) ParseError!?UpdatePathNode {
        if (it.r.remaining() == 0) return null;
        return try UpdatePathNode.parseFrom(&it.r);
    }
};

/// RFC 9420 §12.4. A7.2: cold struct, size guard waived — parse view.
pub const Commit = struct {
    /// The `ProposalOrRef proposals<V>` body, kept raw.
    proposals_raw: []const u8,
    path: ?UpdatePath,

    pub fn parseFrom(r: *Reader) ParseError!Commit {
        const proposals_raw = try r.readVector();
        const path: ?UpdatePath = switch (try r.readU8()) {
            0 => null,
            1 => try UpdatePath.parseFrom(r),
            else => return error.InvalidEnum,
        };
        return .{ .proposals_raw = proposals_raw, .path = path };
    }

    pub fn write(c: Commit, gpa: Allocator, out: *std.ArrayList(u8)) WriteError!void {
        try writeVector(gpa, out, c.proposals_raw);
        if (c.path) |up| {
            try writeU8(gpa, out, 1);
            try up.write(gpa, out);
        } else {
            try writeU8(gpa, out, 0);
        }
    }

    pub fn proposalsIter(c: Commit) ProposalOrRefIter {
        return .{ .r = Reader.init(c.proposals_raw) };
    }
};

/// RFC 9420 §6. A7.2: cold union, size guard waived — parse view.
pub const Sender = union(enum) {
    member: u32, // leaf_index
    external: u32, // sender_index
    new_member_proposal,
    new_member_commit,

    pub fn parseFrom(r: *Reader) ParseError!Sender {
        return switch (try r.readU8()) {
            1 => .{ .member = try r.readU32() },
            2 => .{ .external = try r.readU32() },
            3 => .new_member_proposal,
            4 => .new_member_commit,
            else => error.InvalidEnum,
        };
    }

    pub fn write(s: Sender, gpa: Allocator, out: *std.ArrayList(u8)) WriteError!void {
        switch (s) {
            .member => |i| {
                try writeU8(gpa, out, 1);
                try writeU32(gpa, out, i);
            },
            .external => |i| {
                try writeU8(gpa, out, 2);
                try writeU32(gpa, out, i);
            },
            .new_member_proposal => try writeU8(gpa, out, 3),
            .new_member_commit => try writeU8(gpa, out, 4),
        }
    }
};

/// The content_type select arm of FramedContent (§6).
/// A7.2: cold union, size guard waived — parse view.
pub const FramedBody = union(ContentType) {
    application: []const u8,
    proposal: Proposal,
    commit: Commit,

    pub fn parseFrom(r: *Reader, content_type: ContentType) ParseError!FramedBody {
        return switch (content_type) {
            .application => .{ .application = try r.readVector() },
            .proposal => .{ .proposal = try Proposal.parseFrom(r) },
            .commit => .{ .commit = try Commit.parseFrom(r) },
        };
    }

    pub fn write(b: FramedBody, gpa: Allocator, out: *std.ArrayList(u8)) WriteError!void {
        switch (b) {
            .application => |data| try writeVector(gpa, out, data),
            .proposal => |p| try p.write(gpa, out),
            .commit => |c| try c.write(gpa, out),
        }
    }
};

/// RFC 9420 §6. A7.2: cold struct, size guard waived — parse view.
pub const FramedContent = struct {
    group_id: []const u8,
    epoch: u64,
    sender: Sender,
    authenticated_data: []const u8,
    body: FramedBody,

    pub fn parseFrom(r: *Reader) ParseError!FramedContent {
        const group_id = try r.readVector();
        const epoch = try r.readU64();
        const sender = try Sender.parseFrom(r);
        const authenticated_data = try r.readVector();
        const content_type = try contentTypeFrom(try r.readU8());
        return .{
            .group_id = group_id,
            .epoch = epoch,
            .sender = sender,
            .authenticated_data = authenticated_data,
            .body = try FramedBody.parseFrom(r, content_type),
        };
    }

    pub fn write(fc: FramedContent, gpa: Allocator, out: *std.ArrayList(u8)) WriteError!void {
        try writeVector(gpa, out, fc.group_id);
        try writeU64(gpa, out, fc.epoch);
        try fc.sender.write(gpa, out);
        try writeVector(gpa, out, fc.authenticated_data);
        try writeU8(gpa, out, @intFromEnum(fc.body));
        try fc.body.write(gpa, out);
    }
};

/// FramedContentTBS (§6.1): what the content signature covers. For member /
/// new_member_commit senders the RFC binds the GroupContext — passing null
/// for those senders is an error, never a silently-shorter signed blob.
pub fn serializeFramedContentTBS(
    gpa: Allocator,
    out: *std.ArrayList(u8),
    wire_format: u16,
    fc: FramedContent,
    group_context_bytes: ?[]const u8,
) (WriteError || error{MissingGroupBinding})!void {
    try writeU16(gpa, out, protocol_version_mls10);
    try writeU16(gpa, out, wire_format);
    try fc.write(gpa, out);
    switch (fc.sender) {
        .member, .new_member_commit => {
            const gc = group_context_bytes orelse return error.MissingGroupBinding;
            try out.appendSlice(gpa, gc);
        },
        .external, .new_member_proposal => {},
    }
}

/// RFC 9420 §6.1. A7.2: cold struct, size guard waived — parse view.
/// `confirmation_tag` is present exactly when the content is a commit.
pub const FramedContentAuthData = struct {
    signature: []const u8,
    confirmation_tag: ?[]const u8,

    pub fn parseFrom(r: *Reader, content_type: ContentType) ParseError!FramedContentAuthData {
        return .{
            .signature = try r.readVector(),
            .confirmation_tag = if (content_type == .commit) try r.readVector() else null,
        };
    }

    pub fn write(a: FramedContentAuthData, gpa: Allocator, out: *std.ArrayList(u8)) WriteError!void {
        try writeVector(gpa, out, a.signature);
        if (a.confirmation_tag) |tag| try writeVector(gpa, out, tag);
    }
};

/// RFC 9420 §6.1 — the transcript-hash unit (also §8.2's hash input).
/// A7.2: cold struct, size guard waived — parse view.
pub const AuthenticatedContent = struct {
    wire_format: u16,
    content: FramedContent,
    auth: FramedContentAuthData,

    pub fn parse(bytes: []const u8) ParseError!AuthenticatedContent {
        var r = Reader.init(bytes);
        const wire_format = try r.readU16();
        const content = try FramedContent.parseFrom(&r);
        const auth = try FramedContentAuthData.parseFrom(&r, content.body);
        try r.finish();
        return .{ .wire_format = wire_format, .content = content, .auth = auth };
    }
};

/// ConfirmedTranscriptHashInput (§8.2): the commit's AuthenticatedContent up
/// to and including its signature (the confirmation_tag is the interim
/// input's job).
pub fn serializeConfirmedTranscriptHashInput(
    gpa: Allocator,
    out: *std.ArrayList(u8),
    wire_format: u16,
    fc: FramedContent,
    signature: []const u8,
) WriteError!void {
    assert(fc.body == .commit);
    try writeU16(gpa, out, wire_format);
    try fc.write(gpa, out);
    try writeVector(gpa, out, signature);
}

/// RFC 9420 §6.2. A7.2: cold struct, size guard waived — parse view.
/// `membership_tag` is present exactly when the sender is a member.
pub const PublicMessage = struct {
    content: FramedContent,
    auth: FramedContentAuthData,
    membership_tag: ?[]const u8,

    pub fn parseFrom(r: *Reader) ParseError!PublicMessage {
        const content = try FramedContent.parseFrom(r);
        const auth = try FramedContentAuthData.parseFrom(r, content.body);
        const tag: ?[]const u8 = if (content.sender == .member) try r.readVector() else null;
        return .{ .content = content, .auth = auth, .membership_tag = tag };
    }

    pub fn write(pm: PublicMessage, gpa: Allocator, out: *std.ArrayList(u8)) WriteError!void {
        try pm.content.write(gpa, out);
        try pm.auth.write(gpa, out);
        if (pm.membership_tag) |tag| try writeVector(gpa, out, tag);
    }
};

/// RFC 9420 §6.3. A7.2: cold struct, size guard waived — parse view.
pub const PrivateMessage = struct {
    group_id: []const u8,
    epoch: u64,
    content_type: ContentType,
    authenticated_data: []const u8,
    encrypted_sender_data: []const u8,
    ciphertext: []const u8,

    pub fn parseFrom(r: *Reader) ParseError!PrivateMessage {
        return .{
            .group_id = try r.readVector(),
            .epoch = try r.readU64(),
            .content_type = try contentTypeFrom(try r.readU8()),
            .authenticated_data = try r.readVector(),
            .encrypted_sender_data = try r.readVector(),
            .ciphertext = try r.readVector(),
        };
    }

    pub fn write(pm: PrivateMessage, gpa: Allocator, out: *std.ArrayList(u8)) WriteError!void {
        try writeVector(gpa, out, pm.group_id);
        try writeU64(gpa, out, pm.epoch);
        try writeU8(gpa, out, @intFromEnum(pm.content_type));
        try writeVector(gpa, out, pm.authenticated_data);
        try writeVector(gpa, out, pm.encrypted_sender_data);
        try writeVector(gpa, out, pm.ciphertext);
    }
};

/// SenderData (§6.3.2) — the 12-byte plaintext inside the sender-data AEAD.
/// Hot by the tie-break (one per message received); guarded.
pub const SenderData = struct {
    leaf_index: u32,
    generation: u32,
    reuse_guard: [4]u8,

    comptime {
        // Two u32s + the 4-byte guard, packed exactly. (A7)
        assert(@sizeOf(SenderData) == 12);
    }

    pub const encoded_length = 12;

    pub fn parse(bytes: []const u8) ParseError!SenderData {
        var r = Reader.init(bytes);
        const sd: SenderData = .{
            .leaf_index = try r.readU32(),
            .generation = try r.readU32(),
            .reuse_guard = (try r.readBytes(4))[0..4].*,
        };
        try r.finish();
        return sd;
    }

    pub fn encode(sd: SenderData) [encoded_length]u8 {
        var out: [encoded_length]u8 = undefined;
        std.mem.writeInt(u32, out[0..4], sd.leaf_index, .big);
        std.mem.writeInt(u32, out[4..8], sd.generation, .big);
        out[8..12].* = sd.reuse_guard;
        return out;
    }
};

/// SenderDataAAD (§6.3.2).
pub fn serializeSenderDataAAD(
    gpa: Allocator,
    out: *std.ArrayList(u8),
    group_id: []const u8,
    epoch: u64,
    content_type: ContentType,
) WriteError!void {
    try writeVector(gpa, out, group_id);
    try writeU64(gpa, out, epoch);
    try writeU8(gpa, out, @intFromEnum(content_type));
}

/// PrivateContentAAD (§6.3.1).
pub fn serializePrivateContentAAD(
    gpa: Allocator,
    out: *std.ArrayList(u8),
    group_id: []const u8,
    epoch: u64,
    content_type: ContentType,
    authenticated_data: []const u8,
) WriteError!void {
    try writeVector(gpa, out, group_id);
    try writeU64(gpa, out, epoch);
    try writeU8(gpa, out, @intFromEnum(content_type));
    try writeVector(gpa, out, authenticated_data);
}

/// PrivateMessageContent (§6.3.1), decrypted side: the content select, the
/// auth data, then padding that MUST be all zero bytes (the RFC's covert-
/// channel rule — a non-zero pad rejects the whole message).
/// A7.2: cold struct, size guard waived — parse view.
pub const PrivateContent = struct {
    body: FramedBody,
    auth: FramedContentAuthData,

    pub fn parse(bytes: []const u8, content_type: ContentType) ParseError!PrivateContent {
        var r = Reader.init(bytes);
        const body = try FramedBody.parseFrom(&r, content_type);
        const auth = try FramedContentAuthData.parseFrom(&r, content_type);
        for (r.bytes[r.pos..]) |b| if (b != 0) return error.NonZeroPadding;
        return .{ .body = body, .auth = auth };
    }

    /// The sender side: content + auth + `pad_len` zero bytes.
    pub fn write(pc: PrivateContent, gpa: Allocator, out: *std.ArrayList(u8), pad_len: usize) WriteError!void {
        try pc.body.write(gpa, out);
        try pc.auth.write(gpa, out);
        try out.appendNTimes(gpa, 0, pad_len);
    }
};

/// MLSMessage (§6) — the outermost framing. A7.2: cold union, waived.
pub const MlsMessage = union(enum) {
    public_message: PublicMessage,
    private_message: PrivateMessage,
    welcome: Welcome,
    group_info: GroupInfo,
    key_package: KeyPackage,

    pub fn parse(bytes: []const u8) ParseError!MlsMessage {
        var r = Reader.init(bytes);
        if (try r.readU16() != protocol_version_mls10) return error.UnsupportedVersion;
        const msg: MlsMessage = switch (try r.readU16()) {
            wire_public_message => .{ .public_message = try PublicMessage.parseFrom(&r) },
            wire_private_message => .{ .private_message = try PrivateMessage.parseFrom(&r) },
            wire_welcome => .{ .welcome = try Welcome.parseFrom(&r) },
            wire_group_info => .{ .group_info = try GroupInfo.parseFrom(&r) },
            wire_key_package => .{ .key_package = try KeyPackage.parseFrom(&r) },
            else => return error.InvalidEnum,
        };
        try r.finish();
        return msg;
    }

    pub fn wireFormat(m: MlsMessage) u16 {
        return switch (m) {
            .public_message => wire_public_message,
            .private_message => wire_private_message,
            .welcome => wire_welcome,
            .group_info => wire_group_info,
            .key_package => wire_key_package,
        };
    }

    pub fn write(m: MlsMessage, gpa: Allocator, out: *std.ArrayList(u8)) WriteError!void {
        try writeU16(gpa, out, protocol_version_mls10);
        try writeU16(gpa, out, m.wireFormat());
        switch (m) {
            .public_message => |pm| try pm.write(gpa, out),
            .private_message => |pm| try pm.write(gpa, out),
            .welcome => |w| try w.write(gpa, out),
            .group_info => |gi| try gi.write(gpa, out),
            .key_package => |kp| try kp.write(gpa, out),
        }
    }
};

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

// ---------------------------------------------------------------------------
// Tests — C3 part 3 (framing). Round-trips, the TBS-minus-signature proofs,
// the padding rule, and fuzz over the two attacker-facing parsers.
// ---------------------------------------------------------------------------

fn sampleGroupContext() GroupContext {
    return .{
        .version = protocol_version_mls10,
        .cipher_suite = 1,
        .group_id = "a group id",
        .epoch = 7,
        .tree_hash = "\x01\x02\x03",
        .confirmed_transcript_hash = "\x04\x05",
        .extensions_raw = "",
    };
}

test "GroupContext + GroupInfo: round-trip; GroupInfoTBS = wire minus signature" {
    const gpa = testing.allocator;
    const gi: GroupInfo = .{
        .group_context = sampleGroupContext(),
        .group_context_raw = "",
        .extensions_raw = "",
        .confirmation_tag = "\xaa\xbb\xcc\xdd",
        .signer = 0,
        .signature = "\xd0\x0d\xfe\xed",
    };
    var wire_bytes: std.ArrayList(u8) = .empty;
    defer wire_bytes.deinit(gpa);
    try gi.write(gpa, &wire_bytes);

    const back = try GroupInfo.parse(wire_bytes.items);
    try testing.expectEqual(@as(u64, 7), back.group_context.epoch);
    try testing.expectEqualSlices(u8, "a group id", back.group_context.group_id);
    try testing.expectEqualSlices(u8, "\xaa\xbb\xcc\xdd", back.confirmation_tag);
    try testing.expectEqual(@as(u32, 0), back.signer);

    var tbs: std.ArrayList(u8) = .empty;
    defer tbs.deinit(gpa);
    try gi.writeUnsigned(gpa, &tbs);
    const sig_wire_len = 1 + gi.signature.len;
    try testing.expectEqualSlices(u8, wire_bytes.items[0 .. wire_bytes.items.len - sig_wire_len], tbs.items);
}

test "Proposal/ProposalOrRef: arms round-trip; unsupported types are refused" {
    const gpa = testing.allocator;

    // remove by value, then a reference — iterated back out of a raw body.
    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(gpa);
    try ProposalOrRef.write(.{ .proposal = .{ .remove = 1 } }, gpa, &body);
    try ProposalOrRef.write(.{ .reference = "ref-hash" }, gpa, &body);

    var it: ProposalOrRefIter = .{ .r = Reader.init(body.items) };
    const first = (try it.next()).?;
    try testing.expectEqual(@as(u32, 1), first.proposal.remove);
    const second = (try it.next()).?;
    try testing.expectEqualSlices(u8, "ref-hash", second.reference);
    try testing.expectEqual(@as(?ProposalOrRef, null), try it.next());

    // A psk proposal (type 4) is refused, not skipped.
    var psk: std.ArrayList(u8) = .empty;
    defer psk.deinit(gpa);
    try writeU16(gpa, &psk, 4);
    var r = Reader.init(psk.items);
    try testing.expectError(error.UnsupportedProposal, Proposal.parseFrom(&r));
}

test "Commit + UpdatePath: optional path, node iteration, ciphertext iteration" {
    const gpa = testing.allocator;

    var cts: std.ArrayList(u8) = .empty;
    defer cts.deinit(gpa);
    try HpkeCiphertext.write(.{ .kem_output = "\x01\x02", .ciphertext = "\x03\x04\x05" }, gpa, &cts);

    var nodes: std.ArrayList(u8) = .empty;
    defer nodes.deinit(gpa);
    try UpdatePathNode.write(.{ .encryption_key = "root-pub", .encrypted_path_secrets_raw = cts.items }, gpa, &nodes);

    const commit: Commit = .{
        .proposals_raw = "",
        .path = .{ .leaf_node = sampleLeafNode(), .nodes_raw = nodes.items },
    };
    var wire_bytes: std.ArrayList(u8) = .empty;
    defer wire_bytes.deinit(gpa);
    try commit.write(gpa, &wire_bytes);

    var r = Reader.init(wire_bytes.items);
    const back = try Commit.parseFrom(&r);
    try r.finish();
    try testing.expectEqual(@as(usize, 0), back.proposals_raw.len);
    var nit = back.path.?.nodesIter();
    const node = (try nit.next()).?;
    try testing.expectEqualSlices(u8, "root-pub", node.encryption_key);
    var cit = node.ciphertextsIter();
    const ct = (try cit.next()).?;
    try testing.expectEqualSlices(u8, "\x03\x04\x05", ct.ciphertext);
    try testing.expectEqual(@as(?HpkeCiphertext, null), try cit.next());
    try testing.expectEqual(@as(?UpdatePathNode, null), try nit.next());

    // No path: the null optional round-trips.
    const empty: Commit = .{ .proposals_raw = "", .path = null };
    var wire2: std.ArrayList(u8) = .empty;
    defer wire2.deinit(gpa);
    try empty.write(gpa, &wire2);
    var r2 = Reader.init(wire2.items);
    try testing.expectEqual(@as(?UpdatePath, null), (try Commit.parseFrom(&r2)).path);
}

test "FramedContent: TBS carries the group binding for member senders only" {
    const gpa = testing.allocator;
    const fc: FramedContent = .{
        .group_id = "gid",
        .epoch = 3,
        .sender = .{ .member = 1 },
        .authenticated_data = "",
        .body = .{ .application = "hello" },
    };

    var wire_bytes: std.ArrayList(u8) = .empty;
    defer wire_bytes.deinit(gpa);
    try fc.write(gpa, &wire_bytes);
    var r = Reader.init(wire_bytes.items);
    const back = try FramedContent.parseFrom(&r);
    try r.finish();
    try testing.expectEqualSlices(u8, "hello", back.body.application);
    try testing.expectEqual(@as(u32, 1), back.sender.member);

    // Member sender without a GroupContext: error, not a shorter signing
    // blob. (A failed TBS call leaves partial bytes — callers discard the
    // list on error, so the test uses a separate one.)
    var rejected: std.ArrayList(u8) = .empty;
    defer rejected.deinit(gpa);
    try testing.expectError(error.MissingGroupBinding, serializeFramedContentTBS(gpa, &rejected, wire_private_message, fc, null));
    var tbs: std.ArrayList(u8) = .empty;
    defer tbs.deinit(gpa);
    try serializeFramedContentTBS(gpa, &tbs, wire_private_message, fc, "gc-bytes");
    try testing.expect(std.mem.endsWith(u8, tbs.items, "gc-bytes"));

    // The TBS prefix is version + wire_format + the FramedContent wire bytes.
    try testing.expectEqualSlices(u8, wire_bytes.items, tbs.items[4 .. tbs.items.len - "gc-bytes".len]);
}

test "PrivateMessage + PrivateContent: round-trip; non-zero padding rejected" {
    const gpa = testing.allocator;
    const pm: PrivateMessage = .{
        .group_id = "gid",
        .epoch = 9,
        .content_type = .application,
        .authenticated_data = "ad",
        .encrypted_sender_data = "esd0123456789",
        .ciphertext = "ct",
    };
    var wire_bytes: std.ArrayList(u8) = .empty;
    defer wire_bytes.deinit(gpa);
    try pm.write(gpa, &wire_bytes);
    var r = Reader.init(wire_bytes.items);
    const back = try PrivateMessage.parseFrom(&r);
    try r.finish();
    try testing.expectEqual(ContentType.application, back.content_type);
    try testing.expectEqualSlices(u8, "esd0123456789", back.encrypted_sender_data);

    // PrivateMessageContent: padded write parses; a non-zero pad byte rejects.
    const pc: PrivateContent = .{
        .body = .{ .application = "msg" },
        .auth = .{ .signature = "sig", .confirmation_tag = null },
    };
    var content: std.ArrayList(u8) = .empty;
    defer content.deinit(gpa);
    try pc.write(gpa, &content, 16);
    const cback = try PrivateContent.parse(content.items, .application);
    try testing.expectEqualSlices(u8, "msg", cback.body.application);
    try testing.expectEqualSlices(u8, "sig", cback.auth.signature);
    content.items[content.items.len - 1] = 1;
    try testing.expectError(error.NonZeroPadding, PrivateContent.parse(content.items, .application));
}

test "SenderData: 12-byte encode/parse; trailing bytes rejected" {
    const sd: SenderData = .{ .leaf_index = 1, .generation = 42, .reuse_guard = .{ 9, 8, 7, 6 } };
    const enc = sd.encode();
    const back = try SenderData.parse(&enc);
    try testing.expectEqual(sd.leaf_index, back.leaf_index);
    try testing.expectEqual(sd.generation, back.generation);
    try testing.expectEqualSlices(u8, &sd.reuse_guard, &back.reuse_guard);
    const long = enc ++ [1]u8{0};
    try testing.expectError(error.TrailingBytes, SenderData.parse(&long));
}

test "MLSMessage: dispatch by wire format; bad version/format rejected" {
    const gpa = testing.allocator;
    const msg: MlsMessage = .{ .private_message = .{
        .group_id = "gid",
        .epoch = 1,
        .content_type = .commit,
        .authenticated_data = "",
        .encrypted_sender_data = "esd",
        .ciphertext = "ct",
    } };
    var wire_bytes: std.ArrayList(u8) = .empty;
    defer wire_bytes.deinit(gpa);
    try msg.write(gpa, &wire_bytes);
    const back = try MlsMessage.parse(wire_bytes.items);
    try testing.expectEqual(ContentType.commit, back.private_message.content_type);

    // Wrong protocol version.
    var v = try gpa.dupe(u8, wire_bytes.items);
    defer gpa.free(v);
    v[1] = 2;
    try testing.expectError(error.UnsupportedVersion, MlsMessage.parse(v));
    v[1] = 1;
    // Unknown wire format.
    v[3] = 9;
    try testing.expectError(error.InvalidEnum, MlsMessage.parse(v));
}

test "ratchet tree extension: blank/leaf/parent slots iterate" {
    const gpa = testing.allocator;

    var body: std.ArrayList(u8) = .empty;
    defer body.deinit(gpa);
    // leaf 0 present, root parent present, leaf 1 blank.
    try writeU8(gpa, &body, 1);
    try writeU8(gpa, &body, node_type_leaf);
    try sampleLeafNode().write(gpa, &body);
    try writeU8(gpa, &body, 1);
    try writeU8(gpa, &body, node_type_parent);
    try ParentNode.write(.{ .encryption_key = "rk", .parent_hash = "", .unmerged_leaves_raw = "\x00\x00\x00\x01" }, gpa, &body);
    try writeU8(gpa, &body, 0);

    var ext: std.ArrayList(u8) = .empty;
    defer ext.deinit(gpa);
    try writeVector(gpa, &ext, body.items);

    var it = try ratchetTreeIter(ext.items);
    const slot0 = (try it.next()).?;
    try testing.expectEqualSlices(u8, "did:plc:maya", slot0.?.leaf.credential.identity);
    const slot1 = (try it.next()).?;
    try testing.expectEqual(@as(usize, 1), slot1.?.parent.unmergedCount());
    try testing.expectEqual(@as(u32, 1), slot1.?.parent.unmergedAt(0));
    const slot2 = (try it.next()).?;
    try testing.expectEqual(@as(?Node, null), slot2);
    try testing.expectEqual(@as(??Node, null), try it.next());
}

test "fuzz: MLSMessage.parse and PrivateContent.parse tolerate mutated bytes" {
    const gpa = testing.allocator;
    const fuzzgen = @import("fuzzgen.zig");

    // Seed with a real private message and a real padded content.
    var wire_bytes: std.ArrayList(u8) = .empty;
    defer wire_bytes.deinit(gpa);
    const msg: MlsMessage = .{ .private_message = .{
        .group_id = "gid",
        .epoch = 1,
        .content_type = .application,
        .authenticated_data = "ad",
        .encrypted_sender_data = "esd",
        .ciphertext = "ciphertext",
    } };
    try msg.write(gpa, &wire_bytes);

    var content: std.ArrayList(u8) = .empty;
    defer content.deinit(gpa);
    const pc: PrivateContent = .{
        .body = .{ .application = "msg" },
        .auth = .{ .signature = "sig", .confirmation_tag = null },
    };
    try pc.write(gpa, &content, 8);

    var g = fuzzgen.Gen.init(0x94203);
    var buf: [256]u8 = undefined;
    const seeds = [_][]const u8{ wire_bytes.items, content.items };
    const heads = [_]u8{ 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x3f, 0x40, 0x7f, 0x80, 0xbf, 0xc0, 0xff };
    var i: usize = 0;
    while (i < 4000) : (i += 1) {
        const input = g.next(&buf, &seeds, &heads, i);
        // Any error is fine; a crash, hang, or OOB read is the failure.
        _ = MlsMessage.parse(input) catch {};
        _ = PrivateContent.parse(input, .commit) catch {};
        _ = PrivateContent.parse(input, .application) catch {};
    }
}
