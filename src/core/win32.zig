//! B1 classification: CORE (pure). Win32 key semantics — the WM_CHAR /
//! WM_KEYDOWN stream becomes the SAME terminal bytes the X11 backend and
//! a raw tty deliver ('q', '\r', 0x7F, ESC [ A …). This is the Windows
//! half of the backend trick: the input decoder never learns which OS
//! produced the bytes. Pure tables — testable on any host, which is how
//! the Windows leg earns coverage from a Linux container.
//!
//! WM_CHAR text input flows through core/textinput.zig (UTF-16 pairing
//! and UTF-8 emission, shared with the AppKit backend); this file keeps
//! what is Windows-only: the virtual-key table for non-character keys.

const std = @import("std");

const textinput = @import("textinput.zig");

/// UTF-16 semantics live in core/textinput.zig now (shared with the
/// AppKit backend — macOS delivers NSString code units, Windows delivers
/// WM_CHAR code units; one meaning, one home, per D). Re-exported so
/// shell/win32.zig keeps its single `keys` namespace.
pub const utf16Step = textinput.utf16Step;
pub const codepointBytes = textinput.codepointBytes;

/// Virtual-key codes that never produce WM_CHAR — the arrows. Everything
/// printable rides charBytes via TranslateMessage; answering arrows here
/// and printables there means no key is ever delivered twice.
pub fn keydownBytes(vk: u16, out: *[8]u8) usize {
    const third: u8 = switch (vk) {
        0x26 => 'A', // VK_UP
        0x28 => 'B', // VK_DOWN
        0x27 => 'C', // VK_RIGHT
        0x25 => 'D', // VK_LEFT
        else => return 0,
    };
    out[0] = 0x1B;
    out[1] = '[';
    out[2] = third;
    return 3;
}

// ---------------------------------------------------------------------------
// Tests (B2) — golden bytes, same regime as core/x11.zig
// ---------------------------------------------------------------------------

const testing = std.testing;

test "win32 keys: arrows become the same escape sequences" {
    var out: [8]u8 = undefined;
    try testing.expectEqual(@as(usize, 3), keydownBytes(0x26, &out));
    try testing.expectEqualSlices(u8, &.{ 0x1B, '[', 'A' }, out[0..3]);
    try testing.expectEqual(@as(usize, 3), keydownBytes(0x25, &out));
    try testing.expectEqualSlices(u8, &.{ 0x1B, '[', 'D' }, out[0..3]);
    try testing.expectEqual(@as(usize, 0), keydownBytes(0x41, &out)); // 'A' key: WM_CHAR's job
}
