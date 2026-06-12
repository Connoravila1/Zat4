//! B1 classification: SHELL. The wall clock and bounded sleep, on each
//! OS's stable surface — Linux rides the raw syscalls (caution 1a:
//! std.Io's clock API drifts between snapshots), Windows rides kernel32.
//! Cores never see this file (B4); shells receive plain i64s.

const std = @import("std");
const builtin = @import("builtin");

const is_windows = builtin.os.tag == .windows;
const is_darwin = builtin.os.tag.isDarwin();

/// Darwin rides libSystem, self-declared (the same doctrine as the
/// kernel32 externs below: the OS ABI is the dependency, not a header).
const dc = struct {
    // Not a record: an extern-fn namespace (no fields). A1/A7 do not apply.
    const timespec = extern struct {
        // A7.2 (FFI): layout is the OS ABI's, not ours; waived.
        sec: i64,
        nsec: i64,
    };
    extern "c" fn clock_gettime(clk: c_int, ts: *timespec) c_int;
    extern "c" fn nanosleep(req: *const timespec, rem: ?*timespec) c_int;
    const REALTIME: c_int = 0;
    const MONOTONIC: c_int = 6;
};

extern "kernel32" fn GetSystemTimeAsFileTime(out: *u64) callconv(.winapi) void;
extern "kernel32" fn Sleep(ms: u32) callconv(.winapi) void;
extern "kernel32" fn QueryPerformanceCounter(out: *i64) callconv(.winapi) i32;
extern "kernel32" fn QueryPerformanceFrequency(out: *i64) callconv(.winapi) i32;

/// FILETIME epoch (1601) to Unix epoch (1970), in 100 ns units.
const filetime_unix_offset: u64 = 116_444_736_000_000_000;

pub fn unixSeconds() i64 {
    if (comptime is_windows) {
        var ft: u64 = undefined;
        GetSystemTimeAsFileTime(&ft);
        return @intCast((ft - filetime_unix_offset) / 10_000_000);
    }
    if (comptime is_darwin) {
        var ts: dc.timespec = undefined;
        const rc = dc.clock_gettime(dc.REALTIME, &ts);
        return if (rc == 0) @intCast(ts.sec) else 0;
    }
    var ts: std.os.linux.timespec = undefined;
    const rc = std.os.linux.clock_gettime(.REALTIME, &ts);
    return if (rc == 0) @intCast(ts.sec) else 0;
}

pub fn unixMicros() i64 {
    if (comptime is_windows) {
        var ft: u64 = undefined;
        GetSystemTimeAsFileTime(&ft);
        return @intCast((ft - filetime_unix_offset) / 10);
    }
    if (comptime is_darwin) {
        var ts: dc.timespec = undefined;
        if (dc.clock_gettime(dc.REALTIME, &ts) != 0) return 0;
        return @as(i64, @intCast(ts.sec)) * 1_000_000 + @divTrunc(@as(i64, @intCast(ts.nsec)), 1_000);
    }
    var ts: std.os.linux.timespec = undefined;
    const rc = std.os.linux.clock_gettime(.REALTIME, &ts);
    if (rc != 0) return 0;
    return @as(i64, @intCast(ts.sec)) * 1_000_000 + @divTrunc(@as(i64, @intCast(ts.nsec)), 1_000);
}

/// Monotonic nanoseconds — the bench's stopwatch (G1). Never wall time:
/// NTP steps must not forge a measurement.
pub fn monotonicNanos() u64 {
    if (comptime is_windows) {
        var freq: i64 = 0;
        var count: i64 = 0;
        _ = QueryPerformanceFrequency(&freq);
        _ = QueryPerformanceCounter(&count);
        if (freq <= 0) return 0;
        return @intCast(@as(u128, @intCast(count)) * 1_000_000_000 / @as(u128, @intCast(freq)));
    }
    if (comptime is_darwin) {
        var ts: dc.timespec = undefined;
        if (dc.clock_gettime(dc.MONOTONIC, &ts) != 0) return 0;
        return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
    }
    var ts: std.os.linux.timespec = undefined;
    const rc = std.os.linux.clock_gettime(.MONOTONIC, &ts);
    if (rc != 0) return 0;
    return @as(u64, @intCast(ts.sec)) * 1_000_000_000 + @as(u64, @intCast(ts.nsec));
}

pub fn sleepMillis(ms: u64) void {
    if (comptime is_windows) {
        Sleep(@intCast(@min(ms, std.math.maxInt(u32))));
        return;
    }
    if (comptime is_darwin) {
        var ts: dc.timespec = .{
            .sec = @intCast(ms / 1_000),
            .nsec = @intCast((ms % 1_000) * 1_000_000),
        };
        _ = dc.nanosleep(&ts, null);
        return;
    }
    var ts: std.os.linux.timespec = .{
        .sec = @intCast(ms / 1_000),
        .nsec = @intCast((ms % 1_000) * 1_000_000),
    };
    _ = std.os.linux.nanosleep(&ts, null);
}

test "clock: monotonic never runs backwards" {
    const a = monotonicNanos();
    const b = monotonicNanos();
    try std.testing.expect(b >= a);
    try std.testing.expect(a > 0);
}

test "clock: seconds and micros agree and move forward" {
    const s = unixSeconds();
    const us = unixMicros();
    try std.testing.expect(s > 1_700_000_000); // after Nov 2023: sane wall time
    try std.testing.expect(@divTrunc(us, 1_000_000) - s <= 1);
}
