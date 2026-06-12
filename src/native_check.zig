//! Cross-compile proof root (never linked into the app): pulls the OS-
//! selected window backend's full closure for a foreign target, forcing
//! analysis of every entry point — the compiler is the test bench the
//! container can offer for OSes it cannot run.
const native = @import("shell/native.zig");

comptime {
    _ = native.open;
    _ = native.close;
    _ = native.pump;
    _ = native.present;
    _ = native.Window;
}
