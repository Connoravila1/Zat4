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

//! B1 classification: CORE (pure). Per-call, per-direction media keys for
//! Zat Chat calling, derived from the MLS epoch exporter — the exact mechanism
//! `mls.mailboxId` already uses (CALLING_ARCHITECTURE.md §5). This is the single
//! most important reuse in the calling stack: the MLS group is already the
//! call's key authority, so 1:1 media is end-to-end encrypted and rotates on
//! every epoch/membership change with no new key infrastructure.
//!
//! PURE (B2/B3/B4): no clock, no RNG, no I/O. The exporter secret is handed in
//! by the shell as a plain value (never the `Group` — this module stays
//! decoupled from MLS internals and no index crosses the boundary, A5). Given
//! the same exporter + call id + direction the derivation is deterministic, so
//! it is fully unit-testable headlessly (see the tests at the foot).
//!
//! Crypto note: the derived material sizes an SRTP AES-256-GCM key + salt
//! (RFC 7714, the AEAD SRTP profile). The fork's `std.crypto` provides AES-GCM
//! but not the classic AES-CM/HMAC-SHA1 SRTP profile, so the AEAD profile is
//! the natural target; the actual SRTP protect/unprotect lives in a (deferred)
//! core module, this one only derives the keys.

const std = @import("std");
const assert = std.debug.assert;
const schedule = @import("mls_schedule.zig");

/// The exporter-derivation label for all call media keys — the sibling of
/// `mls.mailboxId`'s `"zat4 mailbox"`. Distinct label ⇒ distinct key space, so
/// a media key can never collide with a mailbox id even at the same epoch.
pub const media_label = "zat4 media";

/// SRTP AES-256-GCM master key length (RFC 7714 §12).
pub const key_len = 32;
/// SRTP AES-GCM master salt length (RFC 7714 §8.1).
pub const salt_len = 12;

/// Which end of the call a key protects. The two directions derive from
/// independent contexts so the send and receive keys are never equal — each
/// side encrypts under its `send` key and decrypts the peer's stream under its
/// `recv` key (the peer's `send`).
pub const Direction = enum(u8) { send = 0, recv = 1 };

/// PLAIN DATA (A1). One direction's SRTP-AEAD key material. At most two live
/// per call (send + recv); guarded under the tie-break rule.
pub const MediaKeys = struct {
    key: [key_len]u8, // AES-256-GCM master key
    salt: [salt_len]u8, // AES-GCM master salt

    comptime {
        // Budget: 32 + 12 = 44, both byte arrays (alignment 1), no padding.
        // Raising this requires a recorded justification per A7.1.
        assert(@sizeOf(MediaKeys) == 44);
    }
};

const derived_len = key_len + salt_len; // 44

/// Derive the media key material for one direction of one call from an MLS
/// epoch exporter secret. Mirrors `mls.mailboxId`: the context is the call id
/// (8 bytes, big-endian) followed by the direction byte, hashed and expanded
/// under the `"zat4 media"` label by the MLS exporter (RFC 9420 §8.5).
///
/// Because the material derives from the epoch exporter, it inherits MLS's
/// forward secrecy and post-compromise security: a new epoch (any join/leave,
/// or a routine rekey) yields entirely new media keys for free.
pub fn derive(exporter: schedule.Secret, call_id: u64, dir: Direction) MediaKeys {
    var ctx: [9]u8 = undefined;
    std.mem.writeInt(u64, ctx[0..8], call_id, .big);
    ctx[8] = @intFromEnum(dir);

    var out: [derived_len]u8 = undefined;
    schedule.mlsExporter(exporter, media_label, &ctx, &out);

    var mk: MediaKeys = undefined;
    @memcpy(&mk.key, out[0..key_len]);
    @memcpy(&mk.salt, out[key_len..derived_len]);
    std.crypto.secureZero(u8, &out); // scrub the transient buffer (C5 spirit)
    return mk;
}

// ---------------------------------------------------------------------------
// Tests (B2/C6 — deterministic; no allocator needed)
// ---------------------------------------------------------------------------

const testing = std.testing;

fn sampleExporter() schedule.Secret {
    var s: schedule.Secret = undefined;
    for (&s, 0..) |*b, i| b.* = @intCast((i * 7 + 3) & 0xff);
    return s;
}

test "derivation is deterministic — same inputs, same key material (B2)" {
    const exp = sampleExporter();
    const a = derive(exp, 0x1122_3344_5566_7788, .send);
    const b = derive(exp, 0x1122_3344_5566_7788, .send);
    try testing.expectEqualSlices(u8, &a.key, &b.key);
    try testing.expectEqualSlices(u8, &a.salt, &b.salt);
}

test "send and recv keys of the same call differ" {
    const exp = sampleExporter();
    const s = derive(exp, 42, .send);
    const r = derive(exp, 42, .recv);
    try testing.expect(!std.mem.eql(u8, &s.key, &r.key));
    try testing.expect(!std.mem.eql(u8, &s.salt, &r.salt));
}

test "different calls under the same epoch get independent keys" {
    const exp = sampleExporter();
    const c1 = derive(exp, 1, .send);
    const c2 = derive(exp, 2, .send);
    try testing.expect(!std.mem.eql(u8, &c1.key, &c2.key));
}

test "a different exporter (new epoch) yields entirely new keys — FS/PCS" {
    var exp2 = sampleExporter();
    exp2[0] ^= 0x01; // one bit of a fresh epoch's exporter
    const a = derive(sampleExporter(), 7, .send);
    const b = derive(exp2, 7, .send);
    try testing.expect(!std.mem.eql(u8, &a.key, &b.key));
}

test "media keys do not collide with the mailbox key space (label separation)" {
    // Reconstruct the mailbox derivation for the same exporter/context and
    // confirm it differs from the media key — the labels genuinely separate.
    const exp = sampleExporter();
    const mk = derive(exp, 0, .send);
    var mailbox: [derived_len]u8 = undefined;
    schedule.mlsExporter(exp, "zat4 mailbox", &[_]u8{0} ** 9, &mailbox);
    try testing.expect(!std.mem.eql(u8, &mk.key, mailbox[0..key_len]));
}
