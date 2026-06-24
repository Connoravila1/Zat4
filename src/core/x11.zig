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

//! B1 classification: CORE (pure). The X11 wire protocol — the subset a
//! window needs, hand-rolled the way the WebSocket layer was: byte
//! builders in, flat records out, golden-byte tested. X11 is a SOCKET
//! protocol; no Xlib, no XCB, no dependency (F1/F2 honored by
//! construction). The shell (shell/window.zig) owns the socket and the
//! choreography; this module owns every byte's meaning (D1/D3 — the
//! rendering-backend decision seals here and in pixel.zig).
//!
//! Wire facts this module encodes (X11 core protocol, v11.0):
//! - The client declares byte order; we declare 'l' (little-endian).
//! - Requests are 4-byte units; the length field counts units.
//! - Every reply is 32 bytes plus `reply_len` extra 4-byte units.
//! - Every event is exactly 32 bytes.

const std = @import("std");
const assert = std.debug.assert;

// ---------------------------------------------------------------------------
// Predefined atoms (X11 appendix) and protocol constants
// ---------------------------------------------------------------------------

pub const atom_atom: u32 = 4;
pub const atom_string: u32 = 31;
pub const atom_wm_name: u32 = 39;

pub const event_mask_key_press: u32 = 0x0000_0001;
pub const event_mask_key_release: u32 = 0x0000_0002;
pub const event_mask_button_press: u32 = 0x0000_0004;
pub const event_mask_button_release: u32 = 0x0000_0008;
pub const event_mask_pointer_motion: u32 = 0x0000_0040;
pub const event_mask_exposure: u32 = 0x0000_8000;
pub const event_mask_structure: u32 = 0x0002_0000;

const opcode_create_window: u8 = 1;
const opcode_map_window: u8 = 8;
const opcode_intern_atom: u8 = 16;
const opcode_change_property: u8 = 18;
const opcode_set_selection_owner: u8 = 22;
const opcode_send_event: u8 = 25;
const opcode_create_gc: u8 = 55;
const opcode_put_image: u8 = 72;
const opcode_get_keyboard_mapping: u8 = 101;

/// Event codes we send/parse beyond input (clipboard = the selection dance).
pub const event_selection_request: u8 = 30;
const event_selection_notify: u8 = 31;

// ---------------------------------------------------------------------------
// Little-endian byte plumbing
// ---------------------------------------------------------------------------

fn put16(buf: []u8, at: usize, value: u16) void {
    std.mem.writeInt(u16, buf[at..][0..2], value, .little);
}
fn put32(buf: []u8, at: usize, value: u32) void {
    std.mem.writeInt(u32, buf[at..][0..4], value, .little);
}
fn get16(bytes: []const u8, at: usize) u16 {
    return std.mem.readInt(u16, bytes[at..][0..2], .little);
}
fn get32(bytes: []const u8, at: usize) u32 {
    return std.mem.readInt(u32, bytes[at..][0..4], .little);
}

fn padded4(n: usize) usize {
    return (n + 3) & ~@as(usize, 3);
}

// ---------------------------------------------------------------------------
// Connection setup
// ---------------------------------------------------------------------------

/// Build the connection setup request. Auth is MIT-MAGIC-COOKIE-1 from
/// the Xauthority file, or empty strings for cookie-less local servers.
pub fn setupRequest(buf: []u8, auth_name: []const u8, auth_data: []const u8) []const u8 {
    const total = 12 + padded4(auth_name.len) + padded4(auth_data.len);
    assert(buf.len >= total);
    @memset(buf[0..total], 0);
    buf[0] = 'l';
    put16(buf, 2, 11); // protocol major
    put16(buf, 4, 0); // protocol minor
    put16(buf, 6, @intCast(auth_name.len));
    put16(buf, 8, @intCast(auth_data.len));
    @memcpy(buf[12..][0..auth_name.len], auth_name);
    @memcpy(buf[12 + padded4(auth_name.len) ..][0..auth_data.len], auth_data);
    return buf[0..total];
}

/// The 8-byte setup response header: status and how much body follows.
pub fn setupHeader(bytes: *const [8]u8) struct { status: u8, body_len: usize } {
    return .{ .status = bytes[0], .body_len = @as(usize, get16(bytes, 6)) * 4 };
}

/// Everything the shell needs from a successful setup body.
/// A7.2: cold struct, size guard waived — one per connection.
pub const Setup = struct {
    resource_id_base: u32,
    resource_id_mask: u32,
    /// Maximum request length in 4-byte units — PutImage chunks under it.
    max_request_units: u32,
    /// 0 = LSBFirst, 1 = MSBFirst — pixel bytes must match the SERVER's
    /// image order, not the client's declared request order.
    image_byte_order: u8,
    min_keycode: u8,
    max_keycode: u8,
    root_window: u32,
    root_visual: u32,
    root_depth: u8,
};

pub fn parseSetup(body: []const u8) error{InvalidSetup}!Setup {
    if (body.len < 40) return error.InvalidSetup;
    const vendor_len: usize = get16(body, 16);
    const formats: usize = body[21];
    const screen_at = 32 + padded4(vendor_len) + formats * 8;
    if (body.len < screen_at + 40) return error.InvalidSetup;
    return .{
        .resource_id_base = get32(body, 4),
        .resource_id_mask = get32(body, 8),
        .max_request_units = get16(body, 18),
        .image_byte_order = body[22],
        .min_keycode = body[26],
        .max_keycode = body[27],
        .root_window = get32(body, screen_at),
        .root_visual = get32(body, screen_at + 32),
        .root_depth = body[screen_at + 38],
    };
}

// ---------------------------------------------------------------------------
// Requests — builders return the exact wire slice
// ---------------------------------------------------------------------------

pub fn createWindow(
    buf: []u8,
    wid: u32,
    parent: u32,
    width: u16,
    height: u16,
    background: u32,
    event_mask: u32,
) []const u8 {
    // A client that paints every pixel itself (we PutImage the whole
    // surface each frame) must NOT let the server own the background.
    // With CWBackPixel the server repaints the window with that solid
    // color on every Expose — landing AFTER our blit and erasing it to a
    // flat fill: the "window maps, then goes black and never shows
    // content" failure. CWBackPixmap = None (0) tells the server to leave
    // the contents alone; we own every pixel via PutImage, repainting on
    // the Expose the pump now reports. `background` is unused on this
    // path by design — the first frame's rasterize fills the same palette
    // color, so nothing is lost visually.
    const value_mask = 0x0000_0001 | 0x0000_0800; // CWBackPixmap | CWEventMask
    _ = background;
    const total = 32 + 8; // fixed + two value-list entries
    assert(buf.len >= total);
    @memset(buf[0..total], 0);
    buf[0] = opcode_create_window;
    buf[1] = 0; // depth: CopyFromParent
    put16(buf, 2, total / 4);
    put32(buf, 4, wid);
    put32(buf, 8, parent);
    // x, y stay 0; the window manager places us.
    put16(buf, 16, width);
    put16(buf, 18, height);
    put16(buf, 20, 0); // border
    put16(buf, 22, 1); // class: InputOutput
    put32(buf, 24, 0); // visual: CopyFromParent
    put32(buf, 28, value_mask);
    put32(buf, 32, 0); // CWBackPixmap value: None — server never auto-fills
    put32(buf, 36, event_mask);
    return buf[0..total];
}

pub fn mapWindow(buf: []u8, wid: u32) []const u8 {
    assert(buf.len >= 8);
    buf[0] = opcode_map_window;
    buf[1] = 0;
    put16(buf, 2, 2);
    put32(buf, 4, wid);
    return buf[0..8];
}

pub fn internAtom(buf: []u8, name: []const u8) []const u8 {
    const total = 8 + padded4(name.len);
    assert(buf.len >= total);
    @memset(buf[0..total], 0);
    buf[0] = opcode_intern_atom;
    buf[1] = 0; // only_if_exists: false — create if missing
    put16(buf, 2, @intCast(total / 4));
    put16(buf, 4, @intCast(name.len));
    @memcpy(buf[8..][0..name.len], name);
    return buf[0..total];
}

/// Replace a 32-format property with a single u32 (WM_PROTOCOLS ⇒
/// WM_DELETE_WINDOW is the one use).
pub fn changePropertyAtom(buf: []u8, wid: u32, property: u32, value: u32) []const u8 {
    const total = 24 + 4;
    assert(buf.len >= total);
    buf[0] = opcode_change_property;
    buf[1] = 0; // mode: Replace
    put16(buf, 2, total / 4);
    put32(buf, 4, wid);
    put32(buf, 8, property);
    put32(buf, 12, atom_atom);
    buf[16] = 32; // format
    buf[17] = 0;
    buf[18] = 0;
    buf[19] = 0;
    put32(buf, 20, 1); // length in format units
    put32(buf, 24, value);
    return buf[0..total];
}

/// Replace an 8-format STRING property (the window title).
pub fn changePropertyString(buf: []u8, wid: u32, property: u32, value: []const u8) []const u8 {
    const total = 24 + padded4(value.len);
    assert(buf.len >= total);
    @memset(buf[0..total], 0);
    buf[0] = opcode_change_property;
    buf[1] = 0;
    put16(buf, 2, @intCast(total / 4));
    put32(buf, 4, wid);
    put32(buf, 8, property);
    put32(buf, 12, atom_string);
    buf[16] = 8;
    put32(buf, 20, @intCast(value.len));
    @memcpy(buf[24..][0..value.len], value);
    return buf[0..total];
}

pub fn createGC(buf: []u8, gc: u32, drawable: u32) []const u8 {
    assert(buf.len >= 16);
    @memset(buf[0..16], 0);
    buf[0] = opcode_create_gc;
    put16(buf, 2, 4);
    put32(buf, 4, gc);
    put32(buf, 8, drawable);
    return buf[0..16];
}

// ---------------------------------------------------------------------------
// Selections (the clipboard) — own CLIPBOARD, then serve paste requests.
// ---------------------------------------------------------------------------

/// Claim ownership of a selection (e.g. CLIPBOARD) for `owner`. After this the
/// server routes paste requests to `owner` as SelectionRequest events. `time`
/// of 0 is CurrentTime (accepted for SetSelectionOwner).
pub fn setSelectionOwner(buf: []u8, selection: u32, owner: u32, time: u32) []const u8 {
    const total = 16;
    assert(buf.len >= total);
    @memset(buf[0..total], 0);
    buf[0] = opcode_set_selection_owner;
    put16(buf, 2, total / 4);
    put32(buf, 4, owner);
    put32(buf, 8, selection);
    put32(buf, 12, time);
    return buf[0..total];
}

/// ChangeProperty in full generality: write `data` (raw bytes) as `count`
/// units of `format` bits, typed `type_atom`, onto ANY window `wid` (the paste
/// requestor, not necessarily ours). `changePropertyString`/`...Atom` are the
/// fixed-shape conveniences; this serves the clipboard's UTF8_STRING + TARGETS.
pub fn changePropertyData(buf: []u8, wid: u32, property: u32, type_atom: u32, format: u8, data: []const u8, count: u32) []const u8 {
    const total = 24 + padded4(data.len);
    assert(buf.len >= total);
    @memset(buf[0..total], 0);
    buf[0] = opcode_change_property;
    buf[1] = 0; // mode: Replace
    put16(buf, 2, @intCast(total / 4));
    put32(buf, 4, wid);
    put32(buf, 8, property);
    put32(buf, 12, type_atom);
    buf[16] = format;
    put32(buf, 20, count);
    @memcpy(buf[24..][0..data.len], data);
    return buf[0..total];
}

/// SendEvent a SelectionNotify back to a paste `requestor` — telling it the
/// data has been written to `property` (or `property` = 0 to refuse). This is
/// the reply that completes the selection transfer handshake.
pub fn sendSelectionNotify(buf: []u8, requestor: u32, selection: u32, target: u32, property: u32, time: u32) []const u8 {
    const total = 44; // 12-byte SendEvent header + the 32-byte event
    assert(buf.len >= total);
    @memset(buf[0..total], 0);
    buf[0] = opcode_send_event;
    buf[1] = 0; // propagate = false
    put16(buf, 2, total / 4); // 11 units
    put32(buf, 4, requestor); // destination window
    put32(buf, 8, 0); // event-mask 0 → deliver to the requestor's client
    // the 32-byte SelectionNotify event begins at offset 12
    buf[12] = event_selection_notify;
    put32(buf, 16, time);
    put32(buf, 20, requestor);
    put32(buf, 24, selection);
    put32(buf, 28, target);
    put32(buf, 32, property);
    return buf[0..total];
}

/// A paste request from another app (decoded from a SelectionRequest event).
/// COLD: one transient per paste, handled immediately — never held or iterated.
/// Its six 32-bit fields don't fit the hot 12-byte `Event`, so it has its own
/// parse path; the size guard keeps the wire layout honest (A7).
pub const SelectionRequest = struct {
    time: u32,
    owner: u32,
    requestor: u32,
    selection: u32,
    target: u32,
    property: u32,

    comptime {
        assert(@sizeOf(SelectionRequest) == 24); // 6 × u32, exact
    }
};

pub fn parseSelectionRequest(bytes: *const [32]u8) SelectionRequest {
    return .{
        .time = get32(bytes, 4),
        .owner = get32(bytes, 8),
        .requestor = get32(bytes, 12),
        .selection = get32(bytes, 16),
        .target = get32(bytes, 20),
        .property = get32(bytes, 24),
    };
}

/// The 24-byte PutImage header; the caller streams `width * rows * 4`
/// pixel bytes straight after it. ZPixmap, x = 0 always (we paint full-
/// width row bands and chunk on rows to stay within the request limit).
///
/// The X11 PutImage request header is EXACTLY 24 bytes = 6 units:
/// opcode, format, length, drawable, gc, width, height, dst-x, dst-y,
/// left-pad, depth, and 2 unused bytes — ending at offset 24. An earlier
/// version wrote 28 bytes (a phantom 4-byte trailing word) and declared 7
/// header units; the server then saw the request length disagree with the
/// data it received and refused EVERY blit with BadLength (error 16,
/// opcode 72) — the real cause of the black window, independent of chunk
/// size. The length field counts the whole request: 6 header units + the
/// pixel data in units.
pub fn putImageHeader(buf: []u8, drawable: u32, gc: u32, width: u16, rows: u16, dst_y: i16, depth: u8) []const u8 {
    assert(buf.len >= 24);
    const data_bytes = @as(u32, width) * rows * 4;
    buf[0] = opcode_put_image;
    buf[1] = 2; // format: ZPixmap
    put16(buf, 2, @intCast(6 + data_bytes / 4)); // 6 header units + data units
    put32(buf, 4, drawable);
    put32(buf, 8, gc);
    put16(buf, 12, width);
    put16(buf, 14, rows);
    put16(buf, 16, 0); // dst x
    put16(buf, 18, @bitCast(dst_y));
    buf[20] = 0; // left pad
    buf[21] = depth;
    put16(buf, 22, 0); // 2 unused bytes — header ends here, at offset 24
    return buf[0..24];
}

/// How many full pixel rows fit in one PutImage request.
///
/// The advertised `max_request_units` cannot be trusted as the real
/// ceiling: a server reports a CARD16 here, but the value 0xFFFF is the
/// big-requests sentinel ("the true limit is learned via an extension"),
/// and many servers accept far less than they advertise. Sending a request
/// sized to the advertised max then gets refused with BadLength (error 16
/// on opcode 72) — the blit silently fails and the window stays black.
///
/// So we clamp to a conservative, universally-safe request size. 16384
/// units (64 KiB) is below every X server's real per-request floor and is
/// what well-behaved clients use for incremental PutImage. The cost is more
/// requests per frame, which is nothing against network wait (G3) — and a
/// blit that actually lands beats a tuned one the server throws away (G4:
/// correctness is not traded for a micro-optimization).
pub const safe_request_units: u32 = 16384;

pub fn putImageRowsPerChunk(width: u16, max_request_units: u32) u16 {
    // Honor the advertised max only when it is smaller than our safe cap;
    // never exceed the safe cap even if the server claims it could.
    const budget = @min(max_request_units, safe_request_units);
    const data_units = budget -| 6; // 6-unit PutImage header overhead
    const units_per_row = (@as(u32, width) * 4) / 4;
    if (units_per_row == 0) return 1;
    const rows = data_units / units_per_row;
    return @intCast(@max(1, @min(rows, std.math.maxInt(u16))));
}

pub fn getKeyboardMapping(buf: []u8, first_keycode: u8, count: u8) []const u8 {
    assert(buf.len >= 8);
    buf[0] = opcode_get_keyboard_mapping;
    buf[1] = 0;
    put16(buf, 2, 2);
    buf[4] = first_keycode;
    buf[5] = count;
    buf[6] = 0;
    buf[7] = 0;
    return buf[0..8];
}

// ---------------------------------------------------------------------------
// Replies — every reply is 32 bytes + extra units
// ---------------------------------------------------------------------------

pub fn replyExtraBytes(header: *const [32]u8) usize {
    return @as(usize, get32(header, 4)) * 4;
}

pub fn internAtomReply(header: *const [32]u8) u32 {
    return get32(header, 8);
}

/// keysyms_per_keycode lives in the reply header; the keysyms themselves
/// are the extra body, one u32 each, little-endian as negotiated.
pub fn keyboardMappingPer(header: *const [32]u8) u8 {
    return header[1];
}

pub fn keyboardMappingSyms(extra: []const u8, out: []u32) usize {
    const count = @min(extra.len / 4, out.len);
    var i: usize = 0;
    while (i < count) : (i += 1) out[i] = get32(extra, i * 4);
    return count;
}

// ---------------------------------------------------------------------------
// Events — 32 bytes on the wire, one flat record here
// ---------------------------------------------------------------------------

pub const EventKind = enum(u8) {
    none,
    err,
    key_press,
    key_release,
    button_press,
    button_release,
    motion,
    expose,
    configure,
    client_delete,
};

/// The parsed event as plain data (A1): `detail`/`state` carry keycode
/// and modifier mask for keys, `w`/`h` the new size for configure,
/// `data` the error code for errors. Pointer events (Phase 5.1) reuse
/// the same seats: `detail` = button (1 left, 2 middle, 3 right,
/// 4/5 wheel), `state` = the KEYBUTMASK, `w`/`h` = event-x/event-y in
/// window pixels — the 12-byte budget holds with zero growth. Hot —
/// events arrive in quantity (drags especially) and are decoded in a
/// loop.
pub const Event = struct {
    kind: EventKind,
    detail: u8,
    state: u16,
    w: u16,
    h: u16,
    data: u32,

    comptime {
        // Budget: 1 + 1 + 2 + 2 + 2 + 4 = 12 bytes, exact — one u32-
        // aligned flat record per wire event, no padding. (A7)
        assert(@sizeOf(Event) == 12);
    }
};

pub const shift_mask: u16 = 0x0001;
pub const control_mask: u16 = 0x0004;

/// `wm_protocols` and `wm_delete` are the interned atoms; a ClientMessage
/// carrying them becomes `.client_delete` — the close button, as data.
pub fn parseEvent(bytes: *const [32]u8, wm_protocols: u32, wm_delete: u32) Event {
    const none: Event = .{ .kind = .none, .detail = 0, .state = 0, .w = 0, .h = 0, .data = 0 };
    const code = bytes[0] & 0x7F;
    switch (code) {
        // X error packet: [0]=0, [1]=error code, [2..4]=sequence,
        // [4..8]=bad resource id, [8..10]=minor opcode, [10]=major opcode.
        // The major opcode names WHICH request was refused (72=PutImage,
        // 55=CreateGC, 1=CreateWindow…) — the single most diagnostic byte.
        // Packed into `state` so the Event struct keeps its 12-byte guard.
        0 => return .{ .kind = .err, .detail = bytes[1], .state = bytes[10], .w = get16(bytes, 8), .h = 0, .data = get32(bytes, 4) },
        2, 3 => return .{
            .kind = if (code == 2) .key_press else .key_release,
            .detail = bytes[1],
            .state = get16(bytes, 28),
            .w = 0,
            .h = 0,
            .data = 0,
        },
        // Pointer events share the key-event layout (X11 §events):
        // [1]=detail(button), [24..26]=event-x INT16, [26..28]=event-y
        // INT16, [28..30]=state. Coordinates are SIGNED on the wire (a
        // grab can report the pointer outside the window); zat clamps
        // negatives to the window edge — off-window positions carry no
        // meaning for hit-testing, and the clamp keeps the Event record
        // unsigned and 12 bytes (E4: the odd case defined out of
        // existence, not an error path).
        4, 5 => return .{
            .kind = if (code == 4) .button_press else .button_release,
            .detail = bytes[1],
            .state = get16(bytes, 28),
            .w = eventCoord(bytes, 24),
            .h = eventCoord(bytes, 26),
            .data = 0,
        },
        6 => return .{
            .kind = .motion,
            .detail = 0,
            .state = get16(bytes, 28),
            .w = eventCoord(bytes, 24),
            .h = eventCoord(bytes, 26),
            .data = 0,
        },
        12 => return .{ .kind = .expose, .detail = 0, .state = 0, .w = 0, .h = 0, .data = 0 },
        22 => return .{ .kind = .configure, .detail = 0, .state = 0, .w = get16(bytes, 20), .h = get16(bytes, 22), .data = 0 },
        33 => {
            if (get32(bytes, 8) == wm_protocols and get32(bytes, 12) == wm_delete) {
                return .{ .kind = .client_delete, .detail = 0, .state = 0, .w = 0, .h = 0, .data = 0 };
            }
            return none;
        },
        else => return none,
    }
}

/// event-x/event-y are INT16 on the wire; negative means "outside the
/// window" (pointer grabs). Clamp to 0 — see the parseEvent note.
fn eventCoord(bytes: *const [32]u8, at: usize) u16 {
    const v: i16 = @bitCast(get16(bytes, at));
    return if (v < 0) 0 else @intCast(v);
}

// ---------------------------------------------------------------------------
// Keys — keycode ⇒ keysym ⇒ the SAME bytes a terminal would send.
// This is the whole backend trick: the window pretends to be a keyboard
// on a tty, and the existing input decoder never learns the difference.
// ---------------------------------------------------------------------------

pub fn keysymFor(syms: []const u32, per: u8, min_keycode: u8, keycode: u8, shifted: bool) u32 {
    if (per == 0 or keycode < min_keycode) return 0;
    const base = @as(usize, keycode - min_keycode) * per;
    if (base >= syms.len) return 0;
    var sym = syms[base];
    if (shifted) {
        const alt = if (per > 1 and base + 1 < syms.len) syms[base + 1] else 0;
        if (alt != 0) {
            sym = alt;
        } else if (sym >= 'a' and sym <= 'z') {
            sym = sym - 'a' + 'A';
        }
    }
    return sym;
}

/// Translate a keysym to terminal bytes. Returns 0 for keys the UI has
/// no meaning for (modifiers, function keys) — silence, not noise.
///
/// `ctrl` is the Control modifier: a tty delivers Ctrl+letter as the
/// control code letter & 0x1F (Ctrl-D = 0x04, Ctrl-C = 0x03, …), and the
/// input decoder upstream expects exactly those bytes. Without this the
/// window emitted the bare letter, so Ctrl-D (post/submit) typed a literal
/// "D" and posting was impossible in the window. The control code is the
/// same whether the letter arrives upper or lower case.
pub fn keyBytes(keysym: u32, ctrl: bool, out: *[8]u8) usize {
    if (ctrl) {
        // Map Ctrl + an ASCII letter to its control code, matching the tty.
        const letter: ?u8 = switch (keysym) {
            'a'...'z' => @as(u8, @intCast(keysym - 'a' + 'A')),
            'A'...'Z' => @intCast(keysym),
            else => null,
        };
        if (letter) |l| {
            out[0] = l & 0x1F; // 'A'->0x01 … 'D'->0x04 … 'Z'->0x1A
            return 1;
        }
        // Ctrl with a non-letter: fall through to the normal mapping.
    }
    switch (keysym) {
        0x20...0x7E => {
            out[0] = @intCast(keysym);
            return 1;
        },
        0xFF0D, 0xFF8D => {
            out[0] = '\r';
            return 1;
        },
        0xFF1B => {
            out[0] = 0x1B;
            return 1;
        },
        0xFF08 => {
            out[0] = 0x7F; // BackSpace arrives as DEL, terminal-style
            return 1;
        },
        0xFF09 => {
            out[0] = '\t';
            return 1;
        },
        0xFF52, 0xFF54, 0xFF53, 0xFF51 => {
            out[0] = 0x1B;
            out[1] = '[';
            out[2] = switch (keysym) {
                0xFF52 => 'A', // Up
                0xFF54 => 'B', // Down
                0xFF53 => 'C', // Right
                else => 'D', // Left
            };
            return 3;
        },
        else => return 0,
    }
}

// ---------------------------------------------------------------------------
// Tests (B2) — golden bytes, the same regime as the WebSocket layer
// ---------------------------------------------------------------------------

const testing = std.testing;

test "x11: setup request golden bytes (no auth)" {
    var buf: [64]u8 = undefined;
    const wire = setupRequest(&buf, "", "");
    try testing.expectEqualSlices(u8, &.{ 'l', 0, 11, 0, 0, 0, 0, 0, 0, 0, 0, 0 }, wire);
}

test "x11: setup request pads auth to 4-byte units" {
    var buf: [64]u8 = undefined;
    const wire = setupRequest(&buf, "MIT-MAGIC-COOKIE-1", "0123456789abcdef");
    try testing.expectEqual(@as(usize, 12 + 20 + 16), wire.len);
    try testing.expectEqual(@as(u8, 18), wire[6]); // name length
    try testing.expectEqualStrings("MIT-MAGIC-COOKIE-1", wire[12..30]);
    try testing.expectEqualStrings("0123456789abcdef", wire[32..48]);
}

test "x11: createWindow golden header" {
    var buf: [64]u8 = undefined;
    const wire = createWindow(&buf, 0x0200_0001, 0x0000_05A1, 800, 480, 0xFF101014, event_mask_exposure);
    try testing.expectEqual(@as(usize, 40), wire.len);
    try testing.expectEqual(@as(u8, 1), wire[0]);
    try testing.expectEqual(@as(u16, 10), get16(wire, 2)); // 40 / 4 units
    try testing.expectEqual(@as(u32, 0x0200_0001), get32(wire, 4));
    try testing.expectEqual(@as(u16, 800), get16(wire, 16));
    try testing.expectEqual(@as(u16, 1), get16(wire, 22)); // InputOutput
    // Value mask must be CWBackPixmap(0x1) | CWEventMask(0x800), NOT
    // CWBackPixel: a server-owned background erases our blit (the black-
    // window bug). The first value is the background-pixmap = None (0).
    try testing.expectEqual(@as(u32, 0x0000_0801), get32(wire, 28));
    try testing.expectEqual(@as(u32, 0), get32(wire, 32)); // None
    try testing.expectEqual(@as(u32, event_mask_exposure), get32(wire, 36));
}

test "x11: putImage header units and row chunking" {
    var buf: [32]u8 = undefined;
    const wire = putImageHeader(&buf, 1, 2, 640, 4, 32, 24);
    // The header is EXACTLY 24 bytes (6 units); the length field counts
    // 6 header units + the pixel data units. A 28-byte/7-unit header was
    // the BadLength black-window bug — pin the correct size here.
    try testing.expectEqual(@as(usize, 24), wire.len);
    try testing.expectEqual(@as(u16, 6 + 640 * 4), get16(wire, 2));
    try testing.expectEqual(@as(u16, 4), get16(wire, 14));
    // A 64 KiB request budget on a 640-wide image: (16384 - 6) / 640 rows.
    try testing.expectEqual(@as(u16, 25), putImageRowsPerChunk(640, 16384));

    // Regression (the BadLength black-window bug): a server advertising a
    // huge max must NOT make us build a request whose length overflows the
    // u16 length field. Clamp to the safe cap, and verify the resulting
    // request total stays within what the u16 field can encode for several
    // realistic widths.
    const huge: u32 = 262144;
    inline for (.{ 320, 640, 880, 1920, 4096 }) |w| {
        const rows = putImageRowsPerChunk(w, huge);
        try testing.expect(rows >= 1);
        const total_units: u32 = 6 + (@as(u32, w) * rows * 4) / 4;
        try testing.expect(total_units <= std.math.maxInt(u16));
    }
}

test "x11: setup body offsets pinned by golden bytes" {
    // A minimal body: 32 fixed + 0 vendor + 1 format (8) + 40 screen.
    var body = [_]u8{0} ** 80;
    put32(&body, 4, 0x0200_0000); // resource id base
    put32(&body, 8, 0x001F_FFFF); // resource id mask
    put16(&body, 16, 0); // vendor length
    put16(&body, 18, 0xFFFF); // max request units
    body[20] = 1; // screens
    body[21] = 1; // formats
    body[22] = 0; // image byte order: LSBFirst
    body[26] = 8; // min keycode
    body[27] = 255; // max keycode
    put32(&body, 40, 0x0000_05A1); // screen: root window
    put32(&body, 40 + 32, 0x0000_0021); // root visual
    body[40 + 38] = 24; // root depth
    const setup = try parseSetup(&body);
    try testing.expectEqual(@as(u32, 0x0200_0000), setup.resource_id_base);
    try testing.expectEqual(@as(u32, 0xFFFF), setup.max_request_units);
    try testing.expectEqual(@as(u8, 8), setup.min_keycode);
    try testing.expectEqual(@as(u8, 255), setup.max_keycode);
    try testing.expectEqual(@as(u32, 0x0000_05A1), setup.root_window);
    try testing.expectEqual(@as(u8, 24), setup.root_depth);
}

test "x11: events parse to flat records" {
    var raw = [_]u8{0} ** 32;
    raw[0] = 2; // KeyPress
    raw[1] = 38; // keycode
    put16(&raw, 28, shift_mask);
    const key = parseEvent(&raw, 100, 101);
    try testing.expectEqual(EventKind.key_press, key.kind);
    try testing.expectEqual(@as(u8, 38), key.detail);
    try testing.expect(key.state & shift_mask != 0);

    @memset(&raw, 0);
    raw[0] = 22; // ConfigureNotify
    put16(&raw, 20, 1024);
    put16(&raw, 22, 600);
    const conf = parseEvent(&raw, 100, 101);
    try testing.expectEqual(EventKind.configure, conf.kind);
    try testing.expectEqual(@as(u16, 1024), conf.w);

    @memset(&raw, 0);
    raw[0] = 33; // ClientMessage
    put32(&raw, 8, 100);
    put32(&raw, 12, 101);
    try testing.expectEqual(EventKind.client_delete, parseEvent(&raw, 100, 101).kind);
}

test "x11: pointer events parse with pinned offsets (golden bytes)" {
    // SESSION_FINDINGS §3.5: wire parsers get golden-byte tests with
    // pinned offsets from day one. Every offset below is the X11
    // protocol's, written as a literal — if the parser drifts from the
    // spec, this fails, not a real server at runtime.
    var raw = [_]u8{0} ** 32;

    // ButtonPress: left button at (300, 142), shift held.
    raw[0] = 4;
    raw[1] = 1; // detail = button 1 (left)
    put16(&raw, 24, 300); // event-x
    put16(&raw, 26, 142); // event-y
    put16(&raw, 28, shift_mask); // state
    const press = parseEvent(&raw, 100, 101);
    try testing.expectEqual(EventKind.button_press, press.kind);
    try testing.expectEqual(@as(u8, 1), press.detail);
    try testing.expectEqual(@as(u16, 300), press.w);
    try testing.expectEqual(@as(u16, 142), press.h);
    try testing.expect(press.state & shift_mask != 0);

    // ButtonRelease: wheel-down (button 5) — same layout, code 5.
    @memset(&raw, 0);
    raw[0] = 5;
    raw[1] = 5;
    put16(&raw, 24, 8);
    put16(&raw, 26, 16);
    const release = parseEvent(&raw, 100, 101);
    try testing.expectEqual(EventKind.button_release, release.kind);
    try testing.expectEqual(@as(u8, 5), release.detail);

    // MotionNotify with control held.
    @memset(&raw, 0);
    raw[0] = 6;
    put16(&raw, 24, 511);
    put16(&raw, 26, 0);
    put16(&raw, 28, control_mask);
    const move = parseEvent(&raw, 100, 101);
    try testing.expectEqual(EventKind.motion, move.kind);
    try testing.expectEqual(@as(u16, 511), move.w);
    try testing.expectEqual(@as(u16, 0), move.h);
    try testing.expect(move.state & control_mask != 0);

    // Negative event-x (pointer dragged outside the window during a
    // grab): INT16 on the wire, clamped to the edge, never wrapped.
    @memset(&raw, 0);
    raw[0] = 6;
    put16(&raw, 24, @bitCast(@as(i16, -7)));
    put16(&raw, 26, 9);
    const outside = parseEvent(&raw, 100, 101);
    try testing.expectEqual(@as(u16, 0), outside.w);
    try testing.expectEqual(@as(u16, 9), outside.h);

    // The send-event flag (top bit of the code) must not change parsing.
    @memset(&raw, 0);
    raw[0] = 4 | 0x80;
    raw[1] = 3;
    put16(&raw, 24, 10);
    try testing.expectEqual(EventKind.button_press, parseEvent(&raw, 100, 101).kind);
}

test "x11: keysym resolution and terminal bytes" {
    // Two columns per keycode, min_keycode 8: keycode 9 ⇒ ('a', 'A').
    const syms = [_]u32{ 'q', 'Q', 'a', 'A', '1', '!' };
    try testing.expectEqual(@as(u32, 'a'), keysymFor(&syms, 2, 8, 9, false));
    try testing.expectEqual(@as(u32, 'A'), keysymFor(&syms, 2, 8, 9, true));
    try testing.expectEqual(@as(u32, '!'), keysymFor(&syms, 2, 8, 10, true));

    var out: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 1), keyBytes('q', false, &out));
    try testing.expectEqual(@as(u8, 'q'), out[0]);
    try testing.expectEqual(@as(usize, 3), keyBytes(0xFF52, false, &out));
    try testing.expectEqualSlices(u8, &.{ 0x1B, '[', 'A' }, out[0..3]);
    try testing.expectEqual(@as(usize, 0), keyBytes(0xFFE1, false, &out)); // Shift itself: silence

    // Control modifier: Ctrl+letter becomes the tty control code, so the
    // window submits a post (Ctrl-D = 0x04) exactly like the terminal.
    try testing.expectEqual(@as(usize, 1), keyBytes('d', true, &out));
    try testing.expectEqual(@as(u8, 0x04), out[0]); // Ctrl-D
    _ = keyBytes('D', true, &out); // upper-case keysym
    try testing.expectEqual(@as(u8, 0x04), out[0]); // same control code
    _ = keyBytes('c', true, &out);
    try testing.expectEqual(@as(u8, 0x03), out[0]); // Ctrl-C
    // Ctrl with a non-letter falls through to the normal mapping.
    try testing.expectEqual(@as(usize, 1), keyBytes('1', true, &out));
    try testing.expectEqual(@as(u8, '1'), out[0]);
}

test "x11: clipboard encoders pinned by golden bytes" {
    var buf: [128]u8 = undefined;

    // SetSelectionOwner(selection=0xAA, owner=0xBB, time=0): 16 bytes, opcode 22.
    {
        const r = setSelectionOwner(&buf, 0xAA, 0xBB, 0);
        try testing.expectEqual(@as(usize, 16), r.len);
        try testing.expectEqual(@as(u8, 22), r[0]);
        try testing.expectEqual(@as(u16, 4), get16(r, 2)); // length in units
        try testing.expectEqual(@as(u32, 0xBB), get32(r, 4)); // owner
        try testing.expectEqual(@as(u32, 0xAA), get32(r, 8)); // selection
        try testing.expectEqual(@as(u32, 0), get32(r, 12)); // time
    }

    // ChangeProperty (UTF8_STRING text "abc"): header 24 + padded("abc")=4 → 28.
    {
        const r = changePropertyData(&buf, 0x10, 0x20, 0x30, 8, "abc", 3);
        try testing.expectEqual(@as(usize, 28), r.len);
        try testing.expectEqual(@as(u8, 18), r[0]); // ChangeProperty
        try testing.expectEqual(@as(u32, 0x10), get32(r, 4)); // requestor window
        try testing.expectEqual(@as(u32, 0x20), get32(r, 8)); // property
        try testing.expectEqual(@as(u32, 0x30), get32(r, 12)); // type atom
        try testing.expectEqual(@as(u8, 8), r[16]); // format
        try testing.expectEqual(@as(u32, 3), get32(r, 20)); // length in units
        try testing.expectEqualSlices(u8, "abc", r[24..27]);
    }

    // SendEvent(SelectionNotify): 44 bytes; the inner event begins at offset 12.
    {
        const r = sendSelectionNotify(&buf, 0x11, 0x22, 0x33, 0x44, 0x55);
        try testing.expectEqual(@as(usize, 44), r.len);
        try testing.expectEqual(@as(u8, 25), r[0]); // SendEvent
        try testing.expectEqual(@as(u16, 11), get16(r, 2)); // 44/4 units
        try testing.expectEqual(@as(u32, 0x11), get32(r, 4)); // destination
        try testing.expectEqual(@as(u8, 31), r[12]); // SelectionNotify code
        try testing.expectEqual(@as(u32, 0x55), get32(r, 16)); // time
        try testing.expectEqual(@as(u32, 0x11), get32(r, 20)); // requestor
        try testing.expectEqual(@as(u32, 0x22), get32(r, 24)); // selection
        try testing.expectEqual(@as(u32, 0x33), get32(r, 28)); // target
        try testing.expectEqual(@as(u32, 0x44), get32(r, 32)); // property
    }

    // SelectionRequest round-trips through the parser at the pinned offsets.
    {
        var ev = [_]u8{0} ** 32;
        ev[0] = 30;
        std.mem.writeInt(u32, ev[4..8], 0x1234, .little); // time
        std.mem.writeInt(u32, ev[8..12], 0xAAAA, .little); // owner
        std.mem.writeInt(u32, ev[12..16], 0xBBBB, .little); // requestor
        std.mem.writeInt(u32, ev[16..20], 0xCCCC, .little); // selection
        std.mem.writeInt(u32, ev[20..24], 0xDDDD, .little); // target
        std.mem.writeInt(u32, ev[24..28], 0xEEEE, .little); // property
        const sr = parseSelectionRequest(&ev);
        try testing.expectEqual(@as(u32, 0x1234), sr.time);
        try testing.expectEqual(@as(u32, 0xBBBB), sr.requestor);
        try testing.expectEqual(@as(u32, 0xCCCC), sr.selection);
        try testing.expectEqual(@as(u32, 0xDDDD), sr.target);
        try testing.expectEqual(@as(u32, 0xEEEE), sr.property);
    }
}
