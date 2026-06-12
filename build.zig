//! Build graph for zat (Zig + atproto client), Phase 0.
//!
//! Steps:
//!   zig build run        — Phase-0 demo: live HTTPS GET -> typed struct
//!   zig build test       — offline unit tests (leak-checked, C6)
//!   zig build test-live  — network smoke tests, deliberately separate so
//!                          the default test step stays deterministic
//!
//! F1 standing record: this project has zero third-party dependencies.
//! Everything is Zig std. Any future import must carry a written
//! justification at its site before it passes review.

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });

    const exe = b.addExecutable(.{
        .name = "zat",
        .root_module = exe_mod,
    });
    b.installArtifact(exe);

    const run_cmd = b.addRunArtifact(exe);
    run_cmd.step.dependOn(b.getInstallStep());
    if (b.args) |args| run_cmd.addArgs(args);
    const run_step = b.step("run", "Run the Phase-0 demo (live HTTPS GET -> typed struct)");
    run_step.dependOn(&run_cmd.step);

    const unit_tests = b.addTest(.{ .root_module = exe_mod });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run offline unit tests (leak-checked)");
    test_step.dependOn(&run_unit_tests.step);

    const live_mod = b.createModule(.{
        .root_source_file = b.path("src/live_tests.zig"),
        .target = target,
        .optimize = optimize,
    });
    const live_tests = b.addTest(.{ .root_module = live_mod });
    const run_live_tests = b.addRunArtifact(live_tests);
    const test_live_step = b.step("test-live", "Run network smoke tests (hits the real network)");
    test_live_step.dependOn(&run_live_tests.step);

    // A7 mechanized (the boss audit's item 5, upgraded from optional):
    // every module-level struct must carry a size guard or a named
    // waiver — checked on every `zig build test`, so the audit is now a
    // standing build gate, not a periodic sweep.
    const guards_mod = b.createModule(.{
        .root_source_file = b.path("src/check_guards.zig"),
        .target = b.resolveTargetQuery(.{}),
        .optimize = .Debug,
    });
    const guards_exe = b.addExecutable(.{ .name = "check-guards", .root_module = guards_mod });
    const run_guards = b.addRunArtifact(guards_exe);
    run_guards.setCwd(b.path("."));
    run_guards.has_side_effects = true;
    const guards_step = b.step("guards", "A7: fail if any module-level struct lacks a size guard or waiver");
    guards_step.dependOn(&run_guards.step);
    test_step.dependOn(&run_guards.step);

    // The G1 performance ledger: wall-clock of core transforms and
    // bytes-per-record, measured — never claimed. ReleaseFast on purpose:
    // we measure what ships, not what the debug allocator costs.
    const bench_mod = b.createModule(.{
        .root_source_file = b.path("src/bench.zig"),
        .target = target,
        .optimize = .ReleaseFast,
    });
    const bench_exe = b.addExecutable(.{ .name = "zat-bench", .root_module = bench_mod });
    const run_bench = b.addRunArtifact(bench_exe);
    const bench_step = b.step("bench", "Run the G1 performance ledger (core transforms: wall-clock + bytes-per-record)");
    bench_step.dependOn(&run_bench.step);
}
