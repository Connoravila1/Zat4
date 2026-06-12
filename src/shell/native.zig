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
pub const OpenError = impl.OpenError;
pub const PumpResult = impl.PumpResult;
pub const open = impl.open;
pub const close = impl.close;
pub const pump = impl.pump;
pub const present = impl.present;
