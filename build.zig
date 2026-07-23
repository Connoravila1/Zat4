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

/// The product flavor a build produces. `.zat4` is the full social client; `.chat`
/// is the standalone Zat Chat app — the SAME codebase (same account, relay, MLS),
/// booted into Messages with a chat-only rail and its own name. A build-time
/// identity, surfaced to the code as `dist_config.product` (read at comptime).
const Product = enum { zat4, chat };

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    const exe_mod = b.createModule(.{
        .root_source_file = b.path("src/main.zig"),
        .target = target,
        .optimize = optimize,
    });
    addFontEngine(b, exe_mod);

    // Closed-wave AppView token, baked at BUILD time into distributed builds
    // (`-Dappview-token=...`). Never committed: the default is empty, which
    // leaves the ZAT_APPVIEW_TOKEN env var as the only source (dev builds).
    // Wave-scoped by design — rotating it is a box-env edit plus a rebuild;
    // per-user atproto service auth is the recorded end state
    // (DISTRIBUTION_ROADMAP T2, SECURITY_ROADMAP).
    const appview_token = b.option([]const u8, "appview-token", "Compiled-in AppView bearer token for distributed builds (default: empty = env-only)") orelse "";
    // Distribution fence (T4): a dist build never reads the dev credential
    // env vars — in-app login (enrollment / browser OAuth) is a tester's
    // only path. The dist scripts pass -Ddist.
    const dist = b.option(bool, "dist", "Distribution build: fence dev credential env vars (in-app login only)") orelse false;
    const dist_opts = b.addOptions();
    dist_opts.addOption([]const u8, "appview_token", appview_token);
    // The chat relay endpoint + token for distributed builds (a phone has no
    // env vars). Same posture as the AppView token: default empty = env-only;
    // the env always wins when present. "wss://host[/…]" = TLS via the public
    // Caddy route; "host:port" = the plaintext SSH-tunnel dev posture.
    // A6: the DEFAULT is the public relay. Chat should work out of the box —
    // the phone already got this via the baked dist value, while a desktop
    // build pointed at nothing and needed a script to hand it an endpoint.
    // The URL is public infrastructure, not a secret; the TOKEN below stays
    // empty by default and is no longer needed at all now that a client can
    // prove WHO it is (CHAT_HARDENING A4 slice 2 + A6). `ZAT4_RELAY` still
    // wins when set — that is how chat-test.sh points at a local loopback relay.
    const relay_url = b.option([]const u8, "relay-url", "Compiled-in chat relay endpoint (default: the public relay)") orelse "wss://pds.zat4.com/relay";
    const relay_token = b.option([]const u8, "relay-token", "Compiled-in chat relay service token (default: empty = env-only)") orelse "";
    dist_opts.addOption([]const u8, "relay_url", relay_url);
    dist_opts.addOption([]const u8, "relay_token", relay_token);
    // REHEARSAL (front door). Walk the whole enrollment flow — every screen, the
    // REAL proof-of-work — without minting an account, and with the password
    // confirm gates pre-filled. Those gates exist to make a person prove they
    // saved their password; re-typing them on every test run is friction with no
    // signal. Dev builds only: a rehearsal that could mint nothing is the point.
    //   zig build -Denroll-rehearsal ...
    const enroll_rehearsal = b.option(bool, "enroll-rehearsal", "Front door: walk the flow without minting an account (dev)") orelse false;
    dist_opts.addOption(bool, "enroll_rehearsal", enroll_rehearsal);
    dist_opts.addOption(bool, "dist", dist);
    // The product flavor (default .zat4). `-Dproduct=chat` builds the standalone
    // Zat Chat app from this same tree. Read at comptime as `dist_config.product`.
    const product = b.option(Product, "product", "Product flavor: zat4 (full client) or chat (standalone Zat Chat)") orelse .zat4;
    dist_opts.addOption(Product, "product", product);
    exe_mod.addOptions("dist_config", dist_opts);

    // The product a tester downloads is called Zat4 (the exe name IS the app
    // name on Windows/macOS); the Linux binary stays `zat` so the dev scripts
    // and the box deploy keep their paths. (DISTRIBUTION_ROADMAP P phase)
    const client_name = switch (target.result.os.tag) {
        // The exe name IS the app name on Windows/macOS; the chat flavor wears its
        // own. The Linux binary stays `zat` either way so the dev scripts + box
        // deploy keep their paths (the flavor there differs by title/boot, not path).
        .windows, .macos => if (product == .chat) "Zat Chat" else "Zat4",
        else => "zat",
    };
    const exe = b.addExecutable(.{
        .name = client_name,
        .root_module = exe_mod,
    });
    if (target.result.os.tag == .windows) {
        // The taskbar/Explorer icon rides a compiled resource (the .ico is
        // generated from the repo logo — see assets/icon/).
        exe_mod.addWin32ResourceFile(.{ .file = b.path("assets/icon/zat4.rc") });
        // Dist builds are GUI-subsystem (no console window). Default stays
        // console: the [gpu]/[oauth] diagnostics are the W2/W5 bring-up tool.
        if (b.option(bool, "windows-gui", "Windows client as a GUI-subsystem app (no console; dist builds)") orelse false) {
            exe.subsystem = .Windows;
        }
    }
    b.installArtifact(exe);

    // Client-only build+install: the dist scripts use this because the full
    // install step also builds the servers, which fail on the Windows target
    // by design (pollfd; they are Linux-only) and would abort the script.
    const client_step = b.step("client", "Build + install only the client executable");
    client_step.dependOn(&b.addInstallArtifact(exe, .{}).step);

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

    // The Zat Chat thin relay (ZAT_CHAT_ROADMAP U4) — like the AppView, a
    // separate headless binary that cross-compiles to the box:
    // `zig build -Dtarget=x86_64-linux relay`.
    const relay_mod = b.createModule(.{
        .root_source_file = b.path("src/relay_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    const relay_exe = b.addExecutable(.{
        .name = "zat4-relay",
        .root_module = relay_mod,
    });
    b.installArtifact(relay_exe);
    const relay_run = b.addRunArtifact(relay_exe);
    relay_run.step.dependOn(b.getInstallStep());
    if (b.args) |args| relay_run.addArgs(args);
    const relay_step = b.step("relay", "Run the Zat Chat relay (store-and-forward for E2EE blobs)");
    relay_step.dependOn(&relay_run.step);

    const relay_tests = b.addTest(.{ .root_module = relay_mod });
    const run_relay_tests = b.addRunArtifact(relay_tests);
    const relay_test_step = b.step("test-relay", "Run the relay's offline unit tests (leak-checked)");
    relay_test_step.dependOn(&run_relay_tests.step);

    // The Constellation Gate — the enrollment trust boundary
    // (CONSTELLATION_GATE_DESIGN.md §9). Like the AppView and relay, a separate
    // headless binary that binds LOOPBACK only and cross-compiles to the box:
    // `zig build -Dtarget=x86_64-linux gate`.
    const gate_mod = b.createModule(.{
        .root_source_file = b.path("src/gate_main.zig"),
        .target = target,
        .optimize = optimize,
    });
    const gate_exe = b.addExecutable(.{
        .name = "zat4-gate",
        .root_module = gate_mod,
    });
    b.installArtifact(gate_exe);
    const gate_run = b.addRunArtifact(gate_exe);
    gate_run.step.dependOn(b.getInstallStep());
    if (b.args) |args| gate_run.addArgs(args);
    const gate_step = b.step("gate", "Run the Constellation Gate (enrollment trust boundary)");
    gate_step.dependOn(&gate_run.step);

    const gate_tests = b.addTest(.{ .root_module = gate_mod });
    const run_gate_tests = b.addRunArtifact(gate_tests);
    const gate_test_step = b.step("test-gate", "Run the Constellation Gate's offline unit tests (leak-checked)");
    gate_test_step.dependOn(&run_gate_tests.step);

    const unit_tests = b.addTest(.{ .root_module = exe_mod });
    const run_unit_tests = b.addRunArtifact(unit_tests);
    const test_step = b.step("test", "Run offline unit tests (leak-checked)");
    test_step.dependOn(&run_unit_tests.step);
    // The AppView's and relay's tests ride the default test step too, so
    // `zig build test` covers the whole project including the servers.
    test_step.dependOn(&run_appview_tests.step);
    test_step.dependOn(&run_relay_tests.step);
    test_step.dependOn(&run_gate_tests.step);

    // Mobile (MOBILE_ROADMAP M-And.0): the C-ABI seam as an Android shared
    // library. v0 is pure Zig — no libc, hence no fonts/EGL yet; the
    // NDK-libc build (M-And.0b) unlocks those. The seam's unit tests run on
    // the NATIVE target under the leak-checked allocator and ride the
    // default test step.
    const android_target = b.resolveTargetQuery(.{
        .cpu_arch = .aarch64,
        .os_tag = .linux,
        .abi = .android,
    });
    const libzat_mod = b.createModule(.{
        .root_source_file = b.path("src/mobile.zig"),
        .target = android_target,
        .optimize = optimize,
    });
    const libzat = b.addLibrary(.{
        .name = "zat",
        .root_module = libzat_mod,
        .linkage = .dynamic,
    });
    // M-And.0b: `-Dandroid-ndk=<path>` links bionic via the NDK sysroot,
    // which unlocks the font engine (stb) and dlopen — i.e. the GPU attach
    // (zat_surface → the system libEGL). Without it the library builds pure
    // (the seam + the sim; zat_surface reports false). The capability rides
    // an options module so src/mobile.zig comptime-gates its GPU leg.
    const ndk_path = b.option([]const u8, "android-ndk", "Android NDK path — bionic libc build of libzat: fonts + EGL (M-And.0b)");
    const libzat_opts = b.addOptions();
    libzat_opts.addOption(bool, "have_gpu", ndk_path != null);
    libzat_mod.addOptions("mobile_config", libzat_opts);
    // The feed leg (M-Core.1 MC.4c) pulls auth/cache/tui into libzat, and
    // auth reads the same baked dist config (AppView token, credential
    // fence) as the desktop client.
    libzat_mod.addOptions("dist_config", dist_opts);
    if (ndk_path) |ndk| {
        addFontEngine(b, libzat_mod); // also sets link_libc
        const sysroot = b.fmt("{s}/toolchains/llvm/prebuilt/linux-x86_64/sysroot", .{ndk});
        // libandroid.so: the NativeActivity host's window/input calls. The
        // NDK stub resolves the link; the device provides the real one.
        libzat_mod.linkSystemLibrary("android", .{});
        libzat_mod.linkSystemLibrary("log", .{}); // logcat: the feed leg narrates its bring-up (stderr goes nowhere in an APK)
        libzat_mod.addLibraryPath(.{ .cwd_relative = b.fmt("{s}/usr/lib/aarch64-linux-android/29", .{sysroot}) });
        const wf = b.addWriteFiles();
        // API 29 = this Zig's default android target version; present in r27c.
        const libc_txt = wf.add("android-libc.txt", b.fmt(
            "include_dir={s}/usr/include\n" ++
                "sys_include_dir={s}/usr/include/aarch64-linux-android\n" ++
                "crt_dir={s}/usr/lib/aarch64-linux-android/29\n" ++
                "msvc_lib_dir=\n" ++
                "kernel32_lib_dir=\n" ++
                "gcc_dir=\n", .{ sysroot, sysroot, sysroot }));
        libzat.setLibCFile(libc_txt);
        libzat.step.dependOn(&wf.step);
    }
    const libzat_step = b.step("libzat", "Build the Android C-ABI shared library (MOBILE_ROADMAP M-And.0/0b)");
    libzat_step.dependOn(&b.addInstallArtifact(libzat, .{}).step);

    // The seam's unit tests run NATIVE (pure build: have_gpu=false — the GPU
    // leg needs a device; its refusal path is what the tests pin).
    const mobile_test_mod = b.createModule(.{
        .root_source_file = b.path("src/mobile.zig"),
        .target = target,
        .optimize = optimize,
    });
    const mobile_test_opts = b.addOptions();
    mobile_test_opts.addOption(bool, "have_gpu", false);
    mobile_test_mod.addOptions("mobile_config", mobile_test_opts);
    mobile_test_mod.addOptions("dist_config", dist_opts); // feed_view (via the seam) reads product at comptime
    const mobile_tests = b.addTest(.{ .root_module = mobile_test_mod });
    const run_mobile_tests = b.addRunArtifact(mobile_tests);
    test_step.dependOn(&run_mobile_tests.step);

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
    preview_mod.addOptions("dist_config", dist_opts); // feed_view reads product at comptime
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

    // ICE loopback smoke (calling): two UDP agents run a STUN Binding check on
    // 127.0.0.1 over shell/call_ice.zig — proves the datagram send/recv +
    // MESSAGE-INTEGRITY path the offline test can't. No display, no GPU; posix
    // UDP only, so it runs anywhere (unlike gpu-smoke).
    const call_ice_mod = b.createModule(.{
        .root_source_file = b.path("src/call_ice_smoke.zig"),
        .target = target,
        .optimize = optimize,
    });
    const call_ice_exe = b.addExecutable(.{ .name = "zat-call-ice-smoke", .root_module = call_ice_mod });
    const run_call_ice = b.addRunArtifact(call_ice_exe);
    const call_ice_step = b.step("call-ice-smoke", "ICE loopback smoke: two UDP agents run an authenticated STUN Binding check");
    call_ice_step.dependOn(&run_call_ice.step);

    // Media loopback smoke (calling): two engines ICE-connect on 127.0.0.1 then
    // flow synthetic tone frames through RTP + SRTP(AES-256-GCM) + jitter, and
    // verify in-order decrypted playout. The end-to-end media-path proof.
    const call_mod = b.createModule(.{
        .root_source_file = b.path("src/call_smoke.zig"),
        .target = target,
        .optimize = optimize,
    });
    const call_exe = b.addExecutable(.{ .name = "zat-call-smoke", .root_module = call_mod });
    const run_call = b.addRunArtifact(call_exe);
    const call_step = b.step("call-smoke", "Media loopback smoke: encrypted tone frames flow A→B through the full pipeline");
    call_step.dependOn(&run_call.step);

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
    gpu_preview_mod.addOptions("dist_config", dist_opts); // feed_view reads product at comptime
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
    tiling_mod.addOptions("dist_config", dist_opts); // feed_view reads product at comptime
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
    tiling_live_mod.addOptions("dist_config", dist_opts); // feed_view reads product at comptime
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
    tiling_real_mod.addOptions("dist_config", dist_opts); // feed_view reads product at comptime
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
