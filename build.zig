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

    // The standalone Zat4 AppView (STANDALONE_ROADMAP Phase C). A separate,
    // headless binary — no font engine, no window — so it cross-compiles
    // cleanly to the deployment box (e.g. aarch64-linux for a Hetzner CAX
    // ARM box): `zig build -Dtarget=aarch64-linux appview`.
    const appview_mod = b.createModule(.{
        .root_source_file = b.path("src/appview_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    const appview_exe = b.addExecutable(.{
        .name = "zat4-appview",
        .root_module = appview_mod,
    });
    b.installArtifact(appview_exe);
    const appview_run = b.addRunArtifact(appview_exe);
    appview_run.step.dependOn(b.getInstallStep());
    if (b.args) |args| appview_run.addArgs(args);
    const appview_step = b.step("appview", "Run the Zat4 AppView (ingest stdin -> serve)");
    appview_step.dependOn(&appview_run.step);

    // The AppView's own offline test target, leak-checked (C6).
    const appview_tests = b.addTest(.{ .root_module = appview_mod });
    const run_appview_tests = b.addRunArtifact(appview_tests);
    const appview_test_step = b.step("test-appview", "Run the AppView's offline unit tests (leak-checked)");
    appview_test_step.dependOn(&run_appview_tests.step);

    const unit_tests = b.addTest(.{ .root_module = exe_mod });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run offline unit tests (leak-checked)");
    test_step.dependOn(&run_unit_tests.step);
    // The AppView's tests ride the default test step too, so `zig build test`
    // covers the whole project including Phase C.
    test_step.dependOn(&run_appview_tests.step);

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

    // Headless visual preview of the premium feed (cut 5.6): render the
    // real core path into a framebuffer and dump a PPM. A picture is the
    // only honest review of a visual pass, and the loopback tests cannot
    // provide one. Font engine wired; no window, no socket.
    const preview_mod = b.createModule(.{
        .root_source_file = b.path("src/preview.zig"),
        .target = target,
        .optimize = optimize,
    });
    addFontEngine(b, preview_mod);
    const preview_exe = b.addExecutable(.{ .name = "zat-preview", .root_module = preview_mod });
    const run_preview = b.addRunArtifact(preview_exe);
    if (b.args) |args| run_preview.addArgs(args);
    const preview_step = b.step("preview", "Render the premium feed to /tmp/zat_preview.ppm (headless)");
    preview_step.dependOn(&run_preview.step);

    // GPU smoke test (Phase 6 foundation): bring up an EGL/GLES2 context on
    // the real X11 window and clear it. EGL/GLESv2 are dlopen'd at RUNTIME, so
    // the build links only libc (via the font engine) — no -dev packages, no
    // vendored package. Cannot run in CI/sandbox (needs a display+GPU).
    const gpu_mod = b.createModule(.{
        .root_source_file = b.path("src/gpu_smoke.zig"),
        .target = target,
        .optimize = optimize,
    });
    addFontEngine(b, gpu_mod);
    const gpu_exe = b.addExecutable(.{ .name = "zat-gpu-smoke", .root_module = gpu_mod });
    const run_gpu = b.addRunArtifact(gpu_exe);
    if (b.args) |args| run_gpu.addArgs(args);
    const gpu_step = b.step("gpu-smoke", "Bring up an EGL/GLES context on the window and clear it (GPU smoke test)");
    gpu_step.dependOn(&run_gpu.step);

    // GPU preview (Phase 6.1): render the SAME draw list as `zig build
    // preview` — static ambient field + premium feed — through the GPU
    // renderer on the real window, to confirm parity with the software path.
    // Same dependency posture as gpu-smoke (EGL/GLESv2 dlopen'd; links libc
    // via the font engine). Needs a display+GPU.
    const gpu_preview_mod = b.createModule(.{
        .root_source_file = b.path("src/gpu_preview.zig"),
        .target = target,
        .optimize = optimize,
    });
    addFontEngine(b, gpu_preview_mod);
    const gpu_preview_exe = b.addExecutable(.{ .name = "zat-gpu-preview", .root_module = gpu_preview_mod });
    const run_gpu_preview = b.addRunArtifact(gpu_preview_exe);
    if (b.args) |args| run_gpu_preview.addArgs(args);
    const gpu_preview_step = b.step("gpu-preview", "Render the premium feed through the GPU on the real window (Phase 6.1 parity)");
    gpu_preview_step.dependOn(&run_gpu_preview.step);

    // ENROLLMENT harness (`zig build enroll`): the interactive "Join Zat4" flow
    // on the real window — clickable steps, real CSPRNG password mint, calm
    // field — with NO session / network, so the feel can be tested in isolation.
    // Same GPU dependency posture (EGL/GLESv2 dlopen'd; libc via the font
    // engine). Needs a display+GPU.
    const enroll_mod = b.createModule(.{
        .root_source_file = b.path("src/enroll_harness.zig"),
        .target = target,
        .optimize = optimize,
    });
    addFontEngine(b, enroll_mod);
    const enroll_exe = b.addExecutable(.{ .name = "zat-enroll", .root_module = enroll_mod });
    const run_enroll = b.addRunArtifact(enroll_exe);
    if (b.args) |args| run_enroll.addArgs(args);
    const enroll_step = b.step("enroll", "Drive the interactive enrollment flow on the real window (no session/network)");
    enroll_step.dependOn(&run_enroll.step);

    // TILING SPIKE (`zig build tiling-spike [-- <out_dir>]`): a SANDBOX that
    // renders the page-as-split-tree carve (core/tiling.zig) to PPMs —  static
    // wide/narrow proofs + a Home→Profile flow flipbook — to judge the modular
    // tiling approach BEFORE it supersedes feed_view's per-screen metric
    // ladder. Headless (raster path, no window/GPU); links libc via the font
    // engine for the proportional labels. Touches no live render code.
    const tiling_mod = b.createModule(.{
        .root_source_file = b.path("src/tiling_spike.zig"),
        .target = target,
        .optimize = optimize,
    });
    addFontEngine(b, tiling_mod);
    const tiling_exe = b.addExecutable(.{ .name = "zat-tiling-spike", .root_module = tiling_mod });
    const run_tiling = b.addRunArtifact(tiling_exe);
    if (b.args) |args| run_tiling.addArgs(args);
    const tiling_step = b.step("tiling-spike", "Render the tiling-layout carve + flow flipbook to PPMs (headless sandbox)");
    tiling_step.dependOn(&run_tiling.step);

    // TILING LIVE (`zig build tiling-live`): the INTERACTIVE sandbox — opens a
    // real X11 window (software present path, no GPU) and lets you navigate the
    // page-as-tree layouts live to feel the re-target/settle. Same dependency
    // posture as the other harnesses (libc via the font engine; X11 spoken raw
    // over the socket). Needs a display. Touches no live render code.
    const tiling_live_mod = b.createModule(.{
        .root_source_file = b.path("src/tiling_live.zig"),
        .target = target,
        .optimize = optimize,
    });
    addFontEngine(b, tiling_live_mod);
    const tiling_live_exe = b.addExecutable(.{ .name = "zat-tiling-live", .root_module = tiling_live_mod });
    const run_tiling_live = b.addRunArtifact(tiling_live_exe);
    if (b.args) |args| run_tiling_live.addArgs(args);
    const tiling_live_step = b.step("tiling-live", "Interactive windowed tiling-layout demo (navigate pages, feel the settle)");
    tiling_live_step.dependOn(&run_tiling_live.step);

    // TILING-REAL (`zig build tiling-real`): the REAL feed (feed_view) rendered
    // through the partition geometry on the GPU + living field — interactive
    // (space morphs the feed wider, resize re-solves live). Isolated harness.
    const tiling_real_mod = b.createModule(.{
        .root_source_file = b.path("src/tiling_real.zig"),
        .target = target,
        .optimize = optimize,
    });
    addFontEngine(b, tiling_real_mod);
    const tiling_real_exe = b.addExecutable(.{ .name = "zat-tiling-real", .root_module = tiling_real_mod });
    const run_tiling_real = b.addRunArtifact(tiling_real_exe);
    if (b.args) |args| run_tiling_real.addArgs(args);
    const tiling_real_step = b.step("tiling-real", "Run the REAL feed on the partition foundation (GPU, interactive)");
    tiling_real_step.dependOn(&run_tiling_real.step);

    // Isolated tests for the pure carve (the spike module is exe-only, so its
    // tests would otherwise be dormant). Kept off the default `test` step so
    // the sandbox never gates the real suite; run with `zig build tiling-test`.
    const tiling_test_mod = b.createModule(.{
        .root_source_file = b.path("src/core/tiling.zig"),
        .target = target,
        .optimize = optimize,
    });
    const tiling_tests = b.addTest(.{ .root_module = tiling_test_mod });
    const run_tiling_tests = b.addRunArtifact(tiling_tests);
    const tiling_test_step = b.step("tiling-test", "Run the tiling-spike carve's golden tests (leak-checked)");
    tiling_test_step.dependOn(&run_tiling_tests.step);

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
    // @embedFile them. The premium feed lays out PROPORTIONALLY (real per-
    // glyph advances, not a fixed cell), so it carries a proportional UI face:
    // Inter (OFL, license beside the assets). This is a one-file swap behind
    // text.zig's unchanged coverage interface — the ringfenced font decision
    // the GUI roadmap §4 promised; not a dependency (bundled data, like the
    // other faces in assets/). The legacy cell-path timeline + the glyph field
    // are fixed-cell grids that historically preferred a mono face (JetBrains
    // Mono is kept in assets/ for that); a follow-up can give the field its
    // own mono source if Inter reads off there.
    mod.addImport("font_regular_ttf", b.createModule(.{ .root_source_file = b.path("assets/Inter-Regular.ttf") }));
    mod.addImport("font_semibold_ttf", b.createModule(.{ .root_source_file = b.path("assets/Inter-SemiBold.ttf") }));
    // The credential generator's root word list rides as a byte module the
    // same way the fonts do, so core/credential.zig can @embedFile it and
    // split it into the comptime pool. PUBLIC by design (entropy is in the
    // pick, not the list — CREDENTIAL_GEN_DESIGN §0).
    mod.addImport("roots_4096_txt", b.createModule(.{ .root_source_file = b.path("assets/roots_4096.txt") }));
    mod.addIncludePath(b.path("vendor"));
    mod.addCSourceFile(.{
        .file = b.path("vendor/stb_impl.c"),
        // stb's intentional UB tricks trip the sanitizer; upstream's
        // recommended posture — see the note in stb_impl.c.
        .flags = &.{"-fno-sanitize=undefined"},
    });
    mod.link_libc = true;
}
