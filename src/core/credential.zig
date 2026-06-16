//! B1 classification: CORE (pure). The **credential generator's** pure
//! half — the public word pool, the exact entropy accounting, the tier
//! model, and the deterministic assembly of a credential from a set of
//! picked indices. Specced in CREDENTIAL_GEN_DESIGN.md (the §7 tier model:
//! bare roots, word-count × 12 bits, fixed dashes and Title-Case).
//!
//! Interface, in full: `Tier`, `Credential`, `roots`, `root_count`,
//! `bits_per_word`, `max_root_len`, `max_words`, `max_credential_len`,
//! `index_mask`, `wordCount`, `entropyBits`, `pickIndex`, `assemble`.
//! Randomness is NOT here — it is the shell's (B3); see shell/credential.zig.
//!
//! ── THE LOAD-BEARING INVARIANT (DESIGN §0) ──
//! All security comes from the uniform random pick; NONE from the wordlist
//! being secret. The list is PUBLIC and that is fine — entropy is computed
//! assuming the attacker has the whole list in front of them (Kerckhoffs).
//! The only things that can lower real entropy below the stated number are
//! (1) a non-uniform pick, (2) non-independent picks, (3) a non-crypto RNG.
//! This file guards (1) structurally: `root_count` is a power of two, so a
//! pick is an unbiased mask (`pickIndex`), no rejection sampling needed and
//! no modulo bias. (2) and (3) are the shell's to honor.

const std = @import("std");
const assert = std.debug.assert;

/// The root pool as a comptime byte blob (PUBLIC by design — DESIGN §0).
/// Embedded the same way the UI fonts are (build.zig), so the wordlist
/// stays an editable asset and the pool is comptime-known (F2: data, not a
/// dependency; no allocation).
const roots_blob = @embedFile("roots_4096_txt");

/// Power-of-two pool size: load-bearing for the bit count AND for unbiased
/// masking. 4096 = 2^12 ⇒ exactly 12 bits per pick.
pub const root_count: usize = 4096;

/// The pool, split from the embedded blob at comptime into exactly
/// `root_count` slices into static data. A line-count mismatch fails the
/// BUILD (the entropy-guard spirit applied to the wordlist): the math can
/// never silently drift when the list is edited.
pub const roots: [root_count][]const u8 = blk: {
    @setEvalBranchQuota(400_000);
    var arr: [root_count][]const u8 = undefined;
    var idx: usize = 0;
    var start: usize = 0;
    var i: usize = 0;
    while (i < roots_blob.len) : (i += 1) {
        if (roots_blob[i] == '\n') {
            if (idx >= root_count) @compileError("roots_4096.txt has more than 4096 lines");
            arr[idx] = roots_blob[start..i];
            idx += 1;
            start = i + 1;
        }
    }
    // A final line without a trailing newline (ours ends in \n, so normally none).
    if (start < roots_blob.len) {
        if (idx >= root_count) @compileError("roots_4096.txt has more than 4096 lines");
        arr[idx] = roots_blob[start..roots_blob.len];
        idx += 1;
    }
    if (idx != root_count) @compileError("roots_4096.txt did not yield exactly 4096 words");
    break :blk arr;
};

comptime {
    // ENTROPY GUARD: the pool size is the bit count's foundation. A power of
    // two makes log2 exact AND makes the index pick an unbiased mask. If a
    // list edit changes the count, the build fails here and the math must be
    // re-derived (A7 spirit, applied to entropy rather than struct bytes).
    assert(root_count == 4096);
    assert(@popCount(root_count) == 1); // power of two ⇒ exact log2, unbiased mask
}

comptime {
    // Every root is non-empty and within the expected length band; an out-of-
    // band word would break the buffer sizing below. A build-time scan.
    @setEvalBranchQuota(400_000);
    for (roots) |w| {
        if (w.len == 0) @compileError("empty root word in pool");
        if (w.len > 31) @compileError("root word unexpectedly long (>31)");
    }
}

/// Bits contributed by one uniform pick = log2(root_count) = 12, EXACT
/// because the pool is a power of two (no rounding, the full 12 bits real).
pub const bits_per_word: u16 = std.math.log2_int(usize, root_count);

/// Longest root, computed from the actual pool at comptime. Sizes the
/// credential buffer; a longer wordlist changes this and trips the size
/// guard, forcing a deliberate decision (A7.1).
pub const max_root_len: usize = blk: {
    @setEvalBranchQuota(400_000);
    var m: usize = 0;
    for (roots) |w| if (w.len > m) {
        m = w.len;
    };
    break :blk m;
};

/// Mask for an unbiased index pick. `raw & index_mask` is uniform over
/// [0, root_count) ONLY because root_count is 2^k (so the mask is all-ones
/// over exactly the pool range). A non-power-of-two pool would require
/// rejection sampling instead — this is the structural guard on uniformity.
pub const index_mask: u16 = @intCast(root_count - 1);

comptime {
    assert((root_count & index_mask) == 0); // mask covers exactly the pool
    assert(index_mask == 0x0FFF);
}

/// The strength tiers a user selects at enrollment (DESIGN §7). The enum
/// value IS the word count, so there is one generator with one parameter.
/// All three are unbreakable in practice; higher tiers add LENGTH, not a
/// different mechanism — the UI must not frame the short one as unsafe
/// (DESIGN §7 honesty requirement).
pub const Tier = enum(u8) {
    secure = 6, // 72 bits
    super_secure = 7, // 84 bits
    ultra_secure = 9, // 108 bits
};

/// Word count for a tier (a free function, not a method — A1).
pub fn wordCount(tier: Tier) u8 {
    return @intFromEnum(tier);
}

/// The longest credential the worst-case tier can produce, computed from
/// the pool: max_words roots at max length, joined by (max_words - 1) dashes.
pub const max_words: usize = @intFromEnum(Tier.ultra_secure); // 9
pub const max_credential_len: usize = max_words * max_root_len + (max_words - 1);

comptime {
    // The entry tier must clear the practical floor. 72 bits is already
    // physically unbreakable against a rate-limited online login (DESIGN §6.3);
    // we assert it as a compile-time fact rather than a runtime check (E4).
    assert(@as(u16, wordCount(.secure)) * bits_per_word >= 72);
}

/// The generated plaintext, assembled into ONE inline buffer (DESIGN §2.3).
/// Held briefly and in small quantity, but treated HOT so the guard pins
/// its footprint and keeps a slice/pointer from creeping in (A4/A6). A fixed
/// buffer also gives the secret ONE location to wipe deterministically (C5;
/// the shell's `wipe`), not a heap string aliased around.
pub const Credential = struct {
    bytes: [max_credential_len]u8, // inline plaintext; never a heap slice (A4/A6)
    len: u8, // live length (≤ max_credential_len, which fits a u8)

    comptime {
        // Budget: max_credential_len (71 for this pool: 9×7 + 8) + 1 (len)
        // = 72 bytes, align 1, exact, no hidden padding. The buffer is sized
        // FROM the pool's max_root_len, so a longer wordlist changes this size
        // and trips the guard — a deliberate decision then, not a silent
        // overflow (A7.1).
        assert(@sizeOf(Credential) == 72);
        assert(max_credential_len <= std.math.maxInt(u8)); // len fits
    }
};

// ── Free functions (A1: behavior lives here, not on the records) ──

/// PURE (B2): the guaranteed entropy for a tier, in bits. Exact integer
/// because root_count is a power of two: word_count × 12. This is what makes
/// "72/84/108 bits" a fact, not a comment.
pub fn entropyBits(tier: Tier) u16 {
    return @as(u16, wordCount(tier)) * bits_per_word;
}

/// PURE (B2): reduce a raw 16-bit draw to a uniform pool index. Unbiased by
/// construction (mask of a power-of-two pool). The shell feeds this fresh
/// CSPRNG bytes; the masking adds no bias and the full 12 bits survive.
pub fn pickIndex(raw: u16) u16 {
    return raw & index_mask;
}

/// PURE (B2): assemble the credential plaintext from already-picked indices.
/// Title-Case each root, join with a fixed '-' (both are fixed rules ⇒ 0
/// entropy, pure readability — DESIGN §7). Deterministic: same indices ⇒
/// same bytes. The indices are the credential module's own (A5: an index
/// never leaves the module that owns the array it indexes — `assemble` and
/// the shell that calls it are both that module). Only the assembled
/// `Credential` (plain bytes) crosses out.
pub fn assemble(indices: []const u16, out: *[max_credential_len]u8) u8 {
    assert(indices.len >= 1 and indices.len <= max_words);
    var pos: usize = 0;
    for (indices, 0..) |ix, w| {
        assert(ix < root_count);
        if (w != 0) {
            out[pos] = '-';
            pos += 1;
        }
        const word = roots[ix];
        out[pos] = std.ascii.toUpper(word[0]); // Title-Case (fixed, 0 bits)
        pos += 1;
        for (word[1..]) |c| {
            out[pos] = c;
            pos += 1;
        }
    }
    assert(pos <= max_credential_len);
    return @intCast(pos);
}

// ── Tests: the pure core, no Io, no randomness ──

test "pool is exactly 4096 unique-sized words and 12 bits each" {
    try std.testing.expectEqual(@as(usize, 4096), root_count);
    try std.testing.expectEqual(@as(u16, 12), bits_per_word);
    try std.testing.expectEqual(@as(usize, 7), max_root_len);
    try std.testing.expectEqual(@as(usize, 71), max_credential_len);
}

test "entropy per tier is exact: 72 / 84 / 108 bits" {
    try std.testing.expectEqual(@as(u16, 72), entropyBits(.secure));
    try std.testing.expectEqual(@as(u16, 84), entropyBits(.super_secure));
    try std.testing.expectEqual(@as(u16, 108), entropyBits(.ultra_secure));
}

test "pickIndex is the unbiased mask over a power-of-two pool" {
    try std.testing.expectEqual(@as(u16, 0), pickIndex(0));
    try std.testing.expectEqual(@as(u16, 1), pickIndex(1));
    try std.testing.expectEqual(@as(u16, 0), pickIndex(4096)); // wraps to 0
    try std.testing.expectEqual(@as(u16, 5), pickIndex(4096 + 5));
    try std.testing.expectEqual(@as(u16, 4095), pickIndex(0xFFFF)); // top bits dropped
    // Every residue is reached by exactly 16 of the 65536 raw values ⇒ uniform.
    var counts = [_]u8{0} ** 16;
    var raw: u32 = 7; // arbitrary residue
    while (raw < 0x1_0000) : (raw += 4096) {
        counts[raw / 4096] += 1;
    }
    for (counts) |c| try std.testing.expectEqual(@as(u8, 1), c); // 16 distinct preimages
}

test "assemble Title-Cases and dash-joins, length matches" {
    // Use the first three known words: abacus, abide, abiding.
    var buf: [max_credential_len]u8 = undefined;
    const indices = [_]u16{ 0, 1, 2 };
    const len = assemble(&indices, &buf);
    try std.testing.expectEqualStrings("Abacus-Abide-Abiding", buf[0..len]);
}
