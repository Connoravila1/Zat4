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

//! B3 classification: SHELL (impure). The DEVICE-STATE sensors the adaptive
//! brain runs on — battery charge and thermal headroom. Two numbers, read from
//! the kernel, handed to `core/call_decision.zig` as plain data. The core never
//! learns where they came from.
//!
//! WHY SYSFS RATHER THAN A PLATFORM API: Android is Linux, and both publish the
//! same `/sys/class/power_supply` and `/sys/class/thermal` interfaces. One
//! implementation serves the desktop and the phone, with no JNI, no NDK header
//! and no second code path to keep in step. Android's `PowerManager` thermal
//! API is richer, and if measurement ever shows sysfs is unreadable or wrong on
//! a real handset that is the fallback — behind this same two-function
//! interface (D2/D3), with nothing above it changing.
//!
//! EVERY READ IS OPTIONAL. A desktop has no battery; a container may hide the
//! thermal zones. Absence is an ordinary result, not an error (E4): the caller
//! substitutes a neutral value and the call proceeds exactly as it would on a
//! device that never throttles.
//!
//! Raw `std.os.linux` syscalls, matching `shell/cache.zig`'s file primitives.
//! These files are tens of bytes, so there is nothing to buffer and nothing to
//! allocate — every read here works out of a stack array.

const std = @import("std");
const linux = std.os.linux;

/// Candidate battery nodes. The kernel names them differently by form factor —
/// `battery` on phones, `BAT0`/`BAT1` on laptops — and the directory also holds
/// AC adapters and USB ports, which are NOT batteries. Probing this fixed list
/// for a `capacity` file is both simpler than walking the directory and immune
/// to mistaking a charger for a cell.
const battery_nodes = [_][]const u8{
    "/sys/class/power_supply/battery/capacity",
    "/sys/class/power_supply/BAT0/capacity",
    "/sys/class/power_supply/BAT1/capacity",
    "/sys/class/power_supply/BAT2/capacity",
};

/// How many `/sys/class/thermal/thermal_zoneN/temp` nodes to probe. Phones
/// expose a lot of zones; 24 covers every device we have seen and costs 24
/// failed `open` calls per sample on a machine with fewer, which is nothing
/// next to the once-per-second sampling interval.
const thermal_zone_probe = 24;

/// Above `thermal_hot_c` the SoC is throttling in earnest; at or below
/// `thermal_cool_c` there is nothing to worry about. Headroom interpolates.
///
/// These are deliberately generic. The device-exact trip point lives in each
/// zone's `trip_point_*_temp`, which is the refinement to make once there is a
/// measurement to justify it (G1/G2) — reading it costs another file open per
/// zone per sample, and the linear ramp below already produces the right SHAPE
/// of response, just not a device-exact one.
const thermal_cool_c: f32 = 45.0;
const thermal_hot_c: f32 = 85.0;

/// Battery charge, 0..100. Null when the machine has no battery or the kernel
/// does not publish one.
pub fn batteryPercent() ?u8 {
    var buf: [32]u8 = undefined;
    for (battery_nodes) |path| {
        const text = readSmall(path, &buf) orelse continue;
        const pct = std.fmt.parseInt(u16, text, 10) catch continue;
        return @intCast(@min(pct, 100));
    }
    return null;
}

/// Thermal headroom, 1.0 (cool) .. 0.0 (throttle imminent), taken from the
/// HOTTEST zone the kernel reports — one overheating component throttles the
/// whole package, so the maximum is the honest reading, not the average.
///
/// Null when no thermal zone is readable.
pub fn thermalHeadroom() ?f32 {
    var path_buf: [64]u8 = undefined;
    var buf: [32]u8 = undefined;
    var hottest_c: f32 = 0;
    var found = false;

    for (0..thermal_zone_probe) |i| {
        const path = std.fmt.bufPrint(&path_buf, "/sys/class/thermal/thermal_zone{d}/temp", .{i}) catch break;
        const text = readSmall(path, &buf) orelse continue;
        // Reported in millidegrees Celsius. Some zones report 0 or a negative
        // sentinel when their sensor is unpowered; skip those rather than let
        // them drag the maximum around.
        const milli = std.fmt.parseInt(i32, text, 10) catch continue;
        if (milli <= 0) continue;
        const c = @as(f32, @floatFromInt(milli)) / 1000.0;
        if (!found or c > hottest_c) hottest_c = c;
        found = true;
    }
    if (!found) return null;

    if (hottest_c <= thermal_cool_c) return 1.0;
    if (hottest_c >= thermal_hot_c) return 0.0;
    return 1.0 - (hottest_c - thermal_cool_c) / (thermal_hot_c - thermal_cool_c);
}

/// Read a small sysfs file into `buf` and return it without surrounding
/// whitespace. Null on any failure — these nodes vanish when hardware is
/// hot-unplugged, and a live call must not care.
fn readSmall(path: []const u8, buf: []u8) ?[]const u8 {
    var z: [128]u8 = undefined;
    if (path.len + 1 > z.len) return null;
    @memcpy(z[0..path.len], path);
    z[path.len] = 0;

    const open_rc = linux.open(@ptrCast(&z), .{ .ACCMODE = .RDONLY }, 0);
    const fd_signed: isize = @bitCast(open_rc);
    if (fd_signed < 0) return null;
    const fd: i32 = @intCast(fd_signed);
    defer _ = linux.close(fd);

    const n_rc = linux.read(fd, buf.ptr, buf.len);
    const n_signed: isize = @bitCast(n_rc);
    if (n_signed <= 0) return null;
    return std.mem.trim(u8, buf[0..@intCast(n_signed)], " \t\r\n");
}

// ---------------------------------------------------------------------------
// Tests. These read the REAL machine, so they assert on the CONTRACT — the
// shape and range of what comes back — never on a particular value, which
// differs between the dev laptop, the build box and the phone. A desktop with
// no battery exercises the absent path; a laptop exercises the present one.
// ---------------------------------------------------------------------------

const testing = std.testing;

test "battery reads in range, or is absent" {
    if (batteryPercent()) |pct| try testing.expect(pct <= 100);
}

test "thermal headroom is a fraction, or is absent" {
    if (thermalHeadroom()) |h| {
        try testing.expect(h >= 0.0);
        try testing.expect(h <= 1.0);
    }
}

test "repeated reads agree — the sensors are stable, not garbage" {
    // Two samples taken back to back must be close. A wildly different second
    // read would mean we are parsing the wrong field or reading uninitialized
    // buffer tail, which is exactly the failure a range check alone misses.
    if (thermalHeadroom()) |a| {
        const b = thermalHeadroom() orelse return error.SensorVanished;
        try testing.expect(@abs(a - b) < 0.2);
    }
    if (batteryPercent()) |a| {
        const b = batteryPercent() orelse return error.SensorVanished;
        try testing.expect(@max(a, b) - @min(a, b) <= 1);
    }
}
