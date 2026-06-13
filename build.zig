//! Build graph for zat (Zig + atproto client), Phase 0.
//!
//! Steps:
//!   zig build run        — Phase-0 demo: live HTTPS GET -> typed struct
//!   zig build test       — offline unit tests (leak-checked, C6)
//!   zig build test-live  — network smoke tests, deliberately separate so
//!                          the default test step stays deterministic
//!
//! F1 standing record: this project carries exactly ONE third-party
//! import — vendor/stb_truetype.h (public domain, single file, zero
//! transitive deps), the glyph rasterizer the GUI roadmap §4 pre-
//! justified for Option C. The full F1 note lives at the import site
//! (vendor/stb_impl.c). Everything else is Zig std; any further import
//! must carry its own written justification before it passes review.

const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    addFontEngine(b, exe_mod);

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
    addFontEngine(b, live_mod);
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
    addFontEngine(b, bench_mod);
    const bench_exe = b.addExecutable(.{ .name = "zat-bench", .root_module = bench_mod });
    const run_bench = b.addRunArtifact(bench_exe);
    const bench_step = b.step("bench", "Run the G1 performance ledger (core transforms: wall-clock + bytes-per-record)");
    bench_step.dependOn(&run_bench.step);

    // Convenience: wipe the local build cache. The cache GROWING is
    // correct, not a bug — Zig keeps content-hashed artifacts so
    // incremental rebuilds are fast, and it cannot auto-delete old
    // variants because it has no way to know you won't switch back to
    // that target/mode. But after a session of heavy testing across
    // several cross-compile targets it accumulates, and the embedded
    // fonts make each artifact chunky. This step is just a tidy,
    // explicit `rm -rf .zig-cache zig-out` so it need not be retyped.
    // This Zig snapshot has no RemoveDir build step, so the clean step
    // shells out. `rm -rf` is POSIX; the Windows arm uses cmd's rmdir so
    // the step is not silently Unix-only. Missing dirs are not an error
    // (rm -f / rmdir-guarded), so `zig build clean` is always safe to run.
    const clean_step = b.step("clean", "Remove the local build cache (.zig-cache) and zig-out");
    if (b.graph.host.result.os.tag == .windows) {
        const rm = b.addSystemCommand(&.{ "cmd", "/c", "if exist .zig-cache rmdir /s /q .zig-cache & if exist zig-out rmdir /s /q zig-out" });
        clean_step.dependOn(&rm.step);
    } else {
        const rm = b.addSystemCommand(&.{ "rm", "-rf", ".zig-cache", "zig-out" });
        clean_step.dependOn(&rm.step);
    }
}

/// Wire the vendored stb_truetype TU + libc onto a module whose import
/// graph reaches core/text.zig. One place, three users (app, bench,
/// live tests) — the C surface cannot drift between them.
fn addFontEngine(b: *std.Build, mod: *std.Build.Module) void {
    // The embedded UI fonts ride as byte modules so core/text.zig can
    // The window timeline is a GLYPH GRID, so it wants a font designed
    // for the grid: JetBrains Mono (OFL, license beside the assets) —
    // every glyph the same advance, which is what the fixed cell expects.
    // (IBM Plex Sans, the prior proportional face, looked subtly off
    // because its varied advances were forced into uniform cells.) This
    // is a one-file swap behind text.zig's unchanged coverage interface,
    // exactly the ringfenced font decision the GUI roadmap §4 promised.
    mod.addImport("font_regular_ttf", b.createModule(.{ .root_source_file = b.path("assets/JetBrainsMono-Regular.ttf") }));
    mod.addImport("font_semibold_ttf", b.createModule(.{ .root_source_file = b.path("assets/JetBrainsMono-SemiBold.ttf") }));
    mod.addIncludePath(b.path("vendor"));
    mod.addCSourceFile(.{
        .file = b.path("vendor/stb_impl.c"),
        // stb's intentional UB tricks trip the sanitizer; upstream's
        // recommended posture — see the note in stb_impl.c.
        .flags = &.{"-fno-sanitize=undefined"},
    });
    mod.link_libc = true;
}
