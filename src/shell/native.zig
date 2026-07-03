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

//! B1 classification: SHELL. The OS-selected native window backend —
//! the portability hinge of the rendering-backend decision (D1). One
//! comptime switch; everything above (the Backend seam in shell/tui.zig,
//! the --window flag in main.zig) imports THIS file and never learns
//! which OS is underneath. Each implementation exposes the same surface:
//! `Window`, `OpenError`, `PumpResult`, `open`, `close`, `pump`,
//! `present` — names and plain values only across the boundary (D3/B5).
//!
//! Route A (approved): hand-rolled OS-ABI backends, zero third-party
//! code. Linux/X11 shipped; Windows/Win32 shipped; macOS/AppKit shipped
//! (all three cross-compile-proven from the build container; the AppKit
//! leg is runtime-bound through dlopen, so no SDK is needed to link).
//! Route B (SDL behind this same facade) is retired to the archive — it
//! returns only if runtime testing on real hardware demands it.

const builtin = @import("builtin");

const impl = switch (builtin.os.tag) {
    .windows => @import("win32.zig"),
    .macos => @import("appkit.zig"),
    else => @import("window.zig"),
};

pub const Window = impl.Window;
pub const NativeHandle = impl.NativeHandle;
pub const nativeHandle = impl.nativeHandle;
pub const OpenError = impl.OpenError;
pub const PumpResult = impl.PumpResult;
pub const open = impl.open;
pub const close = impl.close;
pub const pump = impl.pump;
pub const setClipboard = impl.setClipboard;
pub const setCursor = impl.setCursor;
pub const setJulia = impl.setJulia;
pub const present = impl.present;
pub const presentDrawList = impl.presentDrawList;
