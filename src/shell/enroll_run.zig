// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Zat4 — a social-media client built on the AT Protocol.
// Copyright (C) 2026  Connor Avila

//! B1 classification: SHELL. The "Join Zat4" enrollment run loop.
//!
//! Drives the REAL enrollment surface — `core/enroll_view.zig` — on a live
//! window: click the steps, type into the fields, pick a tier, mint a real
//! (CSPRNG) password, reroll, confirm, finish, then the proof-of-work gate.
//! Every LOCAL part is genuine (CSPRNG password, real Argon2id membership, real
//! PoW on a worker thread, a real P-256 recovery keypair, the X11 clipboard).
//! There is NO session and NO network here — this is the pre-auth front door
//! rendered in isolation; the networked `createAccount` legs are a later slice.
//!
//! ONE implementation, two callers (D6, no change amplification): the live app
//! reaches it pre-auth from `main.zig` (a credential-less window launch with no
//! cached session), and the dev `zig build enroll` step (`enroll_harness.zig`)
//! drives the same loop for fast iteration. The module owns its own window, so
//! a caller just asks it to run.
//!
//! The calm glyph field behind is the same pure wave medium the live app uses,
//! detuned (bigger cells, low ambient) so it stays wispy.

const std = @import("std");
const dist_config = @import("dist_config");
const window_shell = @import("native.zig");
const gpu = @import("gpu.zig");
const layout_core = @import("../core/layout.zig"); // pointer InputEvent
const tui = @import("../core/tui.zig"); // key decode (decodeInput) + key InputEvent
const textedit = @import("../core/textedit.zig"); // the shared editable-text model
const text = @import("../core/text.zig");
const raster = @import("../core/raster.zig");
const enroll_view = @import("../core/enroll_view.zig");
const credential_core = @import("../core/credential.zig");
const credential_shell = @import("credential.zig");
const membership_shell = @import("membership.zig");
const auth = @import("auth.zig"); // createAccount + Session (the network hand-off)
const oauth = @import("oauth.zig"); // existing-account browser sign-in (OAuth/DPoP)
const identity = @import("identity.zig"); // handle → PDS resolution for the OAuth flow
const membership_record = @import("membership_record.zig"); // the on-network Zat4 membership record
const config = @import("config.zig"); // the PDS host new accounts are minted on
const netguard = @import("../core/netguard.zig"); // pure hostOf() — is this PDS ours?
const lexicon = @import("../core/lexicon.zig");
const pow = @import("../core/pow.zig");
const pow_shell = @import("pow.zig");
const glyph_field = @import("../core/glyph_field.zig");
const clock_shell = @import("clock.zig");

// Calm field: bigger cells (wider glyph spacing) than the feed's 13×17.
const cell_w: u16 = 20;
const cell_h: u16 = 28;

// The card is laid out at a fixed LOGICAL width and the whole canvas is scaled
// to fill the window (same responsive model as the feed).
const design_w: u32 = 1280;
fn uiScale(physical_w: u32) f32 {
    return @as(f32, @floatFromInt(physical_w)) / @as(f32, @floatFromInt(design_w));
}
fn logicalH(pw: u32, ph: u32) u32 {
    return @max(1, @as(u32, @intFromFloat(@as(f32, @floatFromInt(ph)) / uiScale(pw))));
}

const clear_r: f32 = @as(f32, 0x14) / 255.0;
const clear_g: f32 = @as(f32, 0x14) / 255.0;
const clear_b: f32 = @as(f32, 0x16) / 255.0;

/// An editable single-line text buffer (one per field). Small, fixed; sized to
/// hold the longest password (71 bytes for the 9-word tier) for stage B of the
/// confirmation, with slack. Plain data (A1) — all editing goes through the
/// shared `textedit` model via the helpers below, so the fields get caret-aware
/// editing (←/→, Home/End, mid-text insert/delete) for free.
pub const TextField = struct {
    // A7.2: cold struct (a few single-instance enrollment fields), size guard waived.
    buf: [80]u8 = undefined,
    len: u32 = 0,
    caret: u32 = 0,
};

/// The live text of a field.
fn tfView(tf: *const TextField) []const u8 {
    return tf.buf[0..tf.len];
}

/// A `textedit.Field` view aliasing the field's inline buffer; edit through it,
/// then `tfApply` writes the new len/caret back. `anchor == caret` (no selection:
/// enrollment fields don't track one yet) — otherwise `insert` would treat
/// `[0, caret)` as a selection and delete it.
fn tfField(tf: *TextField) textedit.Field {
    return .{ .buf = &tf.buf, .len = tf.len, .caret = tf.caret, .anchor = tf.caret };
}
fn tfApply(tf: *TextField, f: textedit.Field) void {
    tf.len = f.len;
    tf.caret = f.caret;
}

/// The mutable shell-side state the pure view is a snapshot of.
pub const State = struct {
    // A7.2: cold struct (the single enrollment state instance), size guard waived.
    step: enroll_view.Step = .provenance,
    branch: enroll_view.Branch = .undecided,
    use_email: bool = true,
    age_ok: bool = false, // identity-step consent: 18+
    tos_ok: bool = false, // identity-step consent: Terms + Privacy
    tier: credential_core.Tier = .super_secure,
    saved: bool = false,
    // Recovery-key step (new + no-email): the REAL P-256 private key, grouped hex.
    recovery_key: [96]u8 = undefined,
    recovery_len: usize = 0,
    rec_saved: bool = false,
    focus: enroll_view.Focus = .none,
    handle: TextField = .{},
    username: TextField = .{},
    email: TextField = .{},
    // Confirm step. Stage A: three spot-check fields + the CSPRNG-chosen 1-based
    // positions they challenge (regenerated each mint). Stage B: the full entry.
    confirm_stage: enroll_view.ConfirmStage = .spot,
    spot_positions: [3]u8 = .{ 2, 4, 6 },
    spot: [3]TextField = .{ .{}, .{}, .{} },
    full: TextField = .{},
    confirm_error: bool = false,
    mem_verifying: bool = false, // Stage B: the off-thread Argon2id verify is in flight
    prev_confirm_stage: enroll_view.ConfirmStage = .spot,
    cred: credential_core.Credential = undefined,
    has_pw: bool = false,
    craft_t: f32 = 1.0, // password decode progress (driven below)
    craft_start_ns: u64 = 0, // when the current mint's decode began
    hover: enroll_view.HitTarget = .primary,
    hover_on: bool = false,
    hover_t: f32 = 0.0,
    tier_chosen: bool = false,
    bar_t: f32 = 0.0, // 0→1 fill progress since a tier was picked
    bar_sel_ns: u64 = 0, // when the current tier was selected
    bar_phase: f32 = 0.0, // free-running clock for the Overkill rainbow
    pow_t: f32 = 0.0, // proof-of-work progress on the verifying step
    seal_t: f32 = 0.0, // completion seal/star-burst progress
    pow_start_ns: u64 = 0,
    seal_start_ns: u64 = 0, // when the ring actually completed (max(floor, real solve))
    copied_ns: u64 = 0, // when Copy was last clicked (drives the "Copied" toast)
    copied_t: f32 = 0.0, // toast strength 0→1 (computed in the loop from copied_ns)
    final_handle: [80]u8 = undefined,
    final_handle_len: usize = 0,
    // Transition: ease the card height + slide the body in on a step change.
    prev_step: enroll_view.Step = .provenance,
    trans_t: f32 = 1.0, // 0 right after a step change → 1 settled
    trans_start_ns: u64 = 0, // when the current transition began (0 = none yet)
    /// WHICH WAY we just went: +1 deeper into the flow, −1 back out of it. The
    /// content slides in from the side you came from, so the motion is an answer
    /// to "where am I going", not decoration.
    trans_dir: i8 = 1,
    /// The card height the current transition STARTED from, so the growth is a
    /// pure function of the transition clock rather than a per-frame chase of a
    /// moving target (which runs at a different speed on a 120 Hz screen).
    trans_from_h: f32 = 0.0,
    card_h: f32 = 0.0, // eased card height (0 = not yet initialised)
    info: enroll_view.Info = .none, // which info bubble is open
    connect_failed: bool = false, // .connecting: the browser OAuth flow failed → retry card
    // ── the existing-account fork: WHO HOSTS THIS HANDLE? (FRONT_DOOR_ROADMAP §2b) ──
    /// The handle→PDS lookup is in flight. Until it lands we do not know whether
    /// this person types a password here or goes to their provider's website.
    resolving: bool = false,
    /// The lookup has ANSWERED (this attempt): the fork below is decided, and the
    /// run loop must not resolve again — it is what stops the browser road from
    /// re-asking the network every frame while it waits.
    resolved: bool = false,
    /// The resolved PDS: its host (named on the browser card) and its full URL
    /// (what `createSession` is aimed at). Written on the main thread from the
    /// resolve worker's result, so the worker never touches this struct.
    host: [96]u8 = undefined,
    host_len: u8 = 0,
    pds: [160]u8 = undefined,
    pds_len: u8 = 0,
    host_ours: bool = false, // the PDS is the one WE run → the in-app password road
    /// `.signin`: the typed password for an account we host, and its reveal toggle.
    /// Scrubbed the moment the step is left (`wipePw`) — a password has no business
    /// outliving the screen that asked for it.
    pw: TextField = .{},
    pw_show: bool = false,
    /// `.signin`: the `createSession` round-trip is in flight. `apply` raises it on
    /// the tap; the run loop is what actually starts the worker (C1/B3 — `apply`
    /// has no allocator and no business doing I/O).
    signin_busy: bool = false,
    sign_error: enroll_view.SignInError = .none,
    /// Enter means "done, hide the keyboard" (a phone) rather than "next field"
    /// (a mouse). Set by the driver each time it hands over keys.
    phone_enter: bool = false,
};

// How long the password "crafting" decode plays (≈1.9 s — long enough to enjoy).
const craft_dur_ns: f32 = 1_900_000_000;

/// Open a window and run the enrollment flow to exit (window close / Esc). The
/// module owns the window lifecycle so callers (the live app pre-auth front door
/// and the dev `enroll` step) just ask it to run. No session, no network.
/// Run the Join flow. Returns the new account's `Session` when sign-up completes
/// (the caller drops into the feed), or null when the window is closed / Esc.
pub fn run(gpa: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map) !?auth.Session {
    const win = window_shell.open(gpa, env, if (dist_config.product == .chat) "Zat Chat - join" else "Zat4 - join", 150, 52) catch |err| {
        std.debug.print("window.open failed: {s} (on X11, is DISPLAY set?)\n", .{@errorName(err)});
        return err;
    };
    defer window_shell.close(win);
    var W: u32 = win.fb.width;
    var H: u32 = win.fb.height;

    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);

    // The GPU is the premium path; without it (no driver, or an OS whose GPU
    // backend isn't built yet — DISTRIBUTION_ROADMAP W5/M4) the Join flow
    // still runs on the software rasterizer + the backend's blit, the same
    // fallback doctrine as the feed (E2). Software mode lays out at
    // window-pixel scale (scale = 1) and skips the living-field background.
    var g_opt: ?gpu.Gpu = gpu.init(window_shell.nativeHandle(win)) catch null;
    defer if (g_opt) |*gg| gpu.deinit(gg);
    const use_gpu = g_opt != null;

    var feed_path: gpu.Feed = undefined;
    var field_renderer: gpu.FieldRenderer = undefined;
    var field_grid: gpu.FieldGrid = undefined;
    if (use_gpu) {
        gpu.setViewport(@intCast(W), @intCast(H));
        feed_path = try gpu.initFeed(gpa);
        field_renderer = try gpu.initFieldRenderer(gpa, &engine, cell_w, cell_h);
        field_grid = try gpu.initFieldGrid();
    } else {
        std.debug.print("enrollment: GPU unavailable — using the software renderer.\n", .{});
    }
    defer if (use_gpu) gpu.feedDeinit(&feed_path, gpa);

    var gcols: u32 = @max(8, W / cell_w);
    var grows: u32 = @max(8, H / cell_h);
    var field: glyph_field.Field = undefined;
    try glyph_field.init(gpa, &field, gcols, grows);
    defer glyph_field.deinit(gpa, &field);
    var bias: []f32 = try gpa.alloc(f32, gcols * grows);
    defer gpa.free(bias);
    var splashes: std.ArrayList(glyph_field.Splash) = .empty;
    defer splashes.deinit(gpa);
    const fparams: glyph_field.Params = .{};

    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);
    var hits: enroll_view.HitList = .empty;
    defer hits.deinit(gpa);

    var out: std.ArrayList(u8) = .empty;
    defer out.deinit(gpa);
    var events: std.ArrayList(layout_core.InputEvent) = .empty;
    defer events.deinit(gpa);

    var state: State = .{};

    // REAL membership store (Argon2id). The minted password's verifier is
    // enrolled here on each mint; the confirm step's full-entry stage verifies
    // against it (the actual login path) — the password lifecycle is genuine,
    // not a text compare. The store uses a THREAD-SAFE allocator because the
    // enroll/verify hashing runs on the background worker (`memjob`), not the UI
    // thread — the main render allocator never touches it concurrently.
    var mstore = membership_shell.init(std.heap.page_allocator);
    defer membership_shell.deinit(&mstore);

    // REAL proof-of-work, run on a background thread so the proof-ring stays
    // smooth (and, on mobile, so the OS doesn't kill a UI-blocking app). The
    // ring tracks max(animation floor, real solve time).
    var powjob: PowJob = .{};
    defer stopPow(&powjob); // join any in-flight solve before exit

    // The membership Argon2id hash (enroll at mint, verify at confirm) also runs
    // off the UI thread on this worker — no Generate/Confirm hitch. The enroll
    // finishes during the ~1.9s password decode; the verify behind "Checking…".
    var memjob: MemJob = .{};
    defer joinMem(&memjob); // join any in-flight hash before exit (runs before mstore deinit)

    // The EXISTING-account browser OAuth sign-in runs on its own worker (the flow
    // BLOCKS on the loopback callback while the user is in the browser, so it must
    // not sit on the UI thread). The spinner stays live; the loop polls `done`.
    // `defer` cancels + joins any in-flight flow on exit (Esc / window close) —
    // the cancel unblocks the loopback wait so we never hang on shutdown.
    var oauthjob: OAuthJob = .{};
    defer stopOAuth(&oauthjob);

    // A first-time imported DID's OAuth session is held here while they finish the
    // membership-minting step (PoW), then handed to the caller. Freed on exit if
    // the window closes mid-mint (set to null before any return that consumes it,
    // so this never double-frees).
    var pending_oauth_session: ?auth.Session = null;
    defer if (pending_oauth_session) |ps| auth.freeSession(gpa, ps);

    var t: f32 = 0;
    var last_step_ns: u64 = 0;
    var caret_anchor_ns: u64 = 0; // reset on edit/click so the caret blink reads solid while active
    // Release-activation: a control is ARMED on press and FIRES on release only if
    // the release lands on the same target (press-then-slide-off cancels). The
    // press gives an immediate ripple; the action commits on release.
    var armed_target: ?enroll_view.HitTarget = null;
    // Guards the one-shot account creation when the proof seals (reset whenever we
    // leave the verifying step, so a failed attempt can be retried).
    var signup_attempted = false;
    var mcx: f32 = -1;
    var mcy: f32 = -1;
    const amb_amp: f32 = 0.006; // calmer than the feed (0.010)
    const amb_scale: f32 = 0.055;
    const amb_drift: f32 = 0.08;

    var cur_lx: i32 = -1; // cursor in logical coords (for hover hit-testing)
    var cur_ly: i32 = -1;

    std.debug.print("enrollment: click through the flow; type into focused fields; Esc or close to quit.\n", .{});

    while (true) {
        const pr = window_shell.pump(win, 16, gpa, &out, &events) catch break;
        if (pr.closed) break;

        // Resize: refit viewport + field grid.
        if (win.fb.width != W or win.fb.height != H) {
            W = win.fb.width;
            H = win.fb.height;
            if (use_gpu) gpu.setViewport(@intCast(W), @intCast(H));
            gcols = @max(8, W / cell_w);
            grows = @max(8, H / cell_h);
            var nf: glyph_field.Field = undefined;
            glyph_field.init(gpa, &nf, gcols, grows) catch break;
            glyph_field.deinit(gpa, &field);
            field = nf;
            const nb = gpa.alloc(f32, gcols * grows) catch break;
            gpa.free(bias);
            bias = nb;
        }

        // Typed bytes → the focused field (decoded keys: text, caret motion,
        // Home/End/Delete, Tab/Shift+Tab traversal). Esc quits.
        const had_input = out.items.len > 0;
        if (handleText(&state, out.items)) break;
        if (had_input) caret_anchor_ns = clock_shell.monotonicNanos(); // keep the caret solid while active
        out.clearRetainingCapacity();

        // Software mode renders the draw list 1:1 in window pixels, so its
        // layout width IS the window width and the pointer needs no rescale.
        const scale: f32 = if (use_gpu) uiScale(W) else 1.0;
        const frame_ns = clock_shell.monotonicNanos();

        // Pointer MOVES first (before layout): update the cursor + field light.
        for (events.items) |ev| {
            if (ev.kind == .move) {
                mcx = @as(f32, @floatFromInt(ev.x)) / @as(f32, @floatFromInt(cell_w));
                mcy = @as(f32, @floatFromInt(ev.y)) / @as(f32, @floatFromInt(cell_h));
                cur_lx = @intFromFloat(@as(f32, @floatFromInt(ev.x)) / scale);
                cur_ly = @intFromFloat(@as(f32, @floatFromInt(ev.y)) / scale);
            }
        }
        // Hover against the PREVIOUS frame's hits (1-frame lag, imperceptible).
        // Ease the lift in/out so it fades rather than snaps.
        const hovered = enroll_view.hitTest(hits.items, cur_lx, cur_ly);
        state.hover_on = hovered != null;
        if (hovered) |hv| state.hover = hv;
        state.hover_t += ((if (state.hover_on) @as(f32, 1.0) else 0.0) - state.hover_t) * 0.28;

        // Password decode: craft_t eases 0→1 over craft_dur (easeOutCubic for a
        // gentle settle), then sits at 1. Only on the password step.
        if (state.step == .password and state.has_pw and state.craft_start_ns != 0) {
            const el: f32 = @floatFromInt(frame_ns -| state.craft_start_ns);
            const lin = @min(1.0, el / craft_dur_ns);
            const inv = 1.0 - lin;
            state.craft_t = 1.0 - inv * inv * inv; // easeOutCubic
        } else {
            state.craft_t = 1.0;
        }

        // Strength bar: ease the fill in over ~0.6 s after a tier is picked;
        // bar_phase free-runs (the field clock) for the rainbow shimmer.
        if (state.tier_chosen) {
            const el: f32 = @floatFromInt(frame_ns -| state.bar_sel_ns);
            state.bar_t = @min(1.0, el / 600_000_000.0);
        } else {
            state.bar_t = 0.0;
        }
        state.bar_phase = t;

        // The step transition (slide + card growth) — the SAME routine the live run
        // loop drives it with, so the two cannot drift apart.
        stepMotion(&state, frame_ns);

        // Proof-of-work gate (REAL): a background worker runs pow.solve. The ring
        // CREEPS (a decelerating exponential of elapsed time) the whole way — the
        // motion is spread across the entire unknown solve, slowing as it climbs,
        // never quite reaching the top — so it always reads as "working," not a
        // fast fill then a dead stall near the end. It honors a min floor and only
        // finishes + seals when the genuine solution actually lands.
        if (state.step == .verifying) {
            if (!powjob.active) startPow(&powjob, &state, io);
            const el: f32 = @floatFromInt(frame_ns -| state.pow_start_ns);
            const floor_ns: f32 = 3_200_000_000.0;
            const solved = powjob.done.load(.acquire);
            const complete = solved and el >= floor_ns;

            if (complete) {
                // Finish home: ease the ring from wherever the creep left it up
                // to 1.0 (a smooth snap, not a jump), then the seal fires.
                state.pow_t += (1.0 - state.pow_t) * 0.16;
                if (state.pow_t > 0.999) state.pow_t = 1.0;
            } else {
                // DECELERATING CREEP tied to elapsed time: always moving, the
                // climb spread across the WHOLE (unknown) solve, slowing as it
                // rises, never reaching 1 until the real solution lands. The
                // motion IS the work — no fill-fast-then-stall-at-the-end. The
                // floor (min duration) is honored because `complete` can't be
                // true before it. tau ≈ a typical few-second solve.
                const tau: f32 = 2_800_000_000.0;
                const creep = 1.0 - @exp(-el / tau);
                state.pow_t = @min(0.97, creep);
            }

            // The seal fires only once the ring is genuinely FULL (work done +
            // finished home), so the bright sweep + burst land on completion.
            const prev_seal = state.seal_t;
            if (state.pow_t >= 0.999) {
                if (state.seal_start_ns == 0) state.seal_start_ns = frame_ns;
                const sel: f32 = @floatFromInt(frame_ns -| state.seal_start_ns);
                state.seal_t = @min(1.0, sel / 800_000_000.0);
            } else {
                state.seal_t = 0.0;
                state.seal_start_ns = 0;
            }

            const fcx = @as(f32, @floatFromInt(gcols)) * 0.5;
            const fcy = @as(f32, @floatFromInt(grows)) * 0.5;
            if (state.pow_t < 1.0) {
                // ripple at the sweeping comet frontier
                const ang = -1.5707963 + state.pow_t * 6.2831853;
                const sx: u32 = @intFromFloat(std.math.clamp(fcx + @cos(ang) * fcx * 0.22, 0, @as(f32, @floatFromInt(gcols - 1))));
                const sy: u32 = @intFromFloat(std.math.clamp(fcy + @sin(ang) * fcy * 0.30, 0, @as(f32, @floatFromInt(grows - 1))));
                splashes.append(gpa, .{ .x = sx, .y = sy, .radius = 2, .amp = 0.5 }) catch {};
            }
            if (prev_seal < 0.62 and state.seal_t >= 0.62) {
                // the click: a burst into the field as the seal snaps shut
                var k: u32 = 0;
                while (k < 8) : (k += 1) {
                    const a = @as(f32, @floatFromInt(k)) * (6.2831853 / 8.0);
                    const bx: u32 = @intFromFloat(std.math.clamp(fcx + @cos(a) * 6.0, 0, @as(f32, @floatFromInt(gcols - 1))));
                    const by: u32 = @intFromFloat(std.math.clamp(fcy + @sin(a) * 6.0, 0, @as(f32, @floatFromInt(grows - 1))));
                    // No dye — dye is the red "like" stain; the proof burst is
                    // just energy, it must not colour the field.
                    splashes.append(gpa, .{ .x = bx, .y = by, .radius = 4, .amp = 1.6 }) catch {};
                }
            }
            // Proof sealed → mint membership, once. NEW branch: create the account
            // on the PDS (which also writes its membership record) → feed, or the
            // done screen on failure. EXISTING branch: a first-time imported DID
            // (carrying its OAuth session) — write the membership record
            // (via=imported, no password) → feed.
            if (state.branch == .new) {
                if (state.seal_t >= 1.0 and !signup_attempted) {
                    signup_attempted = true;
                    if (createZatAccount(gpa, io, env, &state)) |sess| {
                        stopPow(&powjob);
                        return sess; // signed up → drop into the feed
                    }
                    state.step = .done; // failed (printed); let them retry
                }
            } else if (state.seal_t >= 1.0 and !signup_attempted) {
                signup_attempted = true;
                if (pending_oauth_session) |ps| {
                    var session = ps;
                    var aa = std.heap.ArenaAllocator.init(gpa);
                    defer aa.deinit();
                    _ = membership_record.put(gpa, aa.allocator(), io, env, &session, lexicon.membership_via.imported, tos_version_placeholder, state.age_ok, clock_shell.unixSeconds()) catch |err| {
                        std.debug.print("[enroll] membership write error: {s}\n", .{@errorName(err)});
                    };
                    pending_oauth_session = null; // ownership transfers to the return
                    stopPow(&powjob);
                    return session; // membership minted → drop into the feed
                }
                reset(&state); // no carried session (shouldn't happen) — fail safe
            }
        } else {
            if (powjob.active) stopPow(&powjob);
            state.pow_t = 0.0;
            state.seal_t = 0.0;
            signup_attempted = false; // left verifying → allow a fresh attempt
        }

        // EXISTING-account browser sign-in: while on the connecting step, run the
        // blocking OAuth flow on the worker and poll for it. On success we re-home
        // the worker-owned session into `gpa` (no concurrency: the worker is
        // joined first) and drop into the feed; on failure the spinner becomes a
        // retry card. The worker isn't (re)started while a failure is showing —
        // "Try again" clears `connect_failed`, which re-arms the start below.
        if (state.step == .connecting) {
            if (!oauthjob.active and !state.connect_failed) startOAuth(&oauthjob, &state, io, env);
            if (oauthjob.active and oauthjob.done.load(.acquire)) {
                joinOAuth(&oauthjob); // join the finished worker; we consume its result below
                if (oauthjob.ok) {
                    if (auth.reownSession(gpa, std.heap.page_allocator, oauthjob.session)) |sess| {
                        if (oauthjob.is_member) {
                            return sess; // returning member → straight to the feed (§13.1)
                        }
                        // First-time imported DID → mint Zat4 membership: through
                        // the PoW gate, then write the record (via=imported), no
                        // password. Carry the OAuth session through the PoW step.
                        pending_oauth_session = sess;
                        signup_attempted = false;
                        state.step = .verifying;
                        state.pow_start_ns = frame_ns;
                    } else |_| {
                        // OOM re-homing the session — release the worker copy and
                        // let the user retry (a transient, not a dead end).
                        auth.freeSession(std.heap.page_allocator, oauthjob.session);
                        state.connect_failed = true;
                    }
                } else {
                    state.connect_failed = true;
                }
            }
        }

        // "Copied" toast: hold ~1.1 s after a copy, then fade over ~0.35 s.
        if (state.copied_ns != 0) {
            const cel: f32 = @floatFromInt(frame_ns -| state.copied_ns);
            state.copied_t = if (cel < 1_100_000_000.0) 1.0 else @max(0.0, 1.0 - (cel - 1_100_000_000.0) / 350_000_000.0);
        } else {
            state.copied_t = 0.0;
        }

        // Off-thread membership verify (Stage B): when the worker lands, advance
        // (or flag the mismatch). The UI stayed live + animating the whole time.
        if (state.step == .confirm and state.mem_verifying and memjob.done.load(.acquire)) {
            joinMem(&memjob);
            state.mem_verifying = false;
            if (memjob.verify_ok) {
                confirmSucceed(&state, io, &mstore);
            } else {
                state.confirm_error = true;
            }
        }

        // Lay out the current state → draw list + hit rects.
        const blink_on = ((frame_ns -| caret_anchor_ns) / 530_000_000) % 2 == 0;
        dl.len = 0;
        const layout_w: u32 = if (use_gpu) design_w else @max(1, W);
        const layout_h: u32 = if (use_gpu) logicalH(W, H) else @max(1, H);
        try enroll_view.layout(gpa, &engine, @intCast(layout_w), @intCast(layout_h), snapshot(&state, blink_on), &dl, &hits);

        // Pointer CLICKS (after layout): release-activation — arm on press (with a
        // soft ripple), commit the action on release over the same target.
        for (events.items) |ev| {
            if (ev.button != 1) continue;
            const lx: i32 = @intFromFloat(@as(f32, @floatFromInt(ev.x)) / scale);
            const ly: i32 = @intFromFloat(@as(f32, @floatFromInt(ev.y)) / scale);
            if (ev.kind == .button_down) {
                armed_target = enroll_view.hitTest(hits.items, lx, ly);
                // Press ripple: immediate tactile feedback at the press point.
                const sx: u32 = @intFromFloat(std.math.clamp(@as(f32, @floatFromInt(ev.x)) / @as(f32, @floatFromInt(cell_w)), 0, @as(f32, @floatFromInt(gcols - 1))));
                const sy: u32 = @intFromFloat(std.math.clamp(@as(f32, @floatFromInt(ev.y)) / @as(f32, @floatFromInt(cell_h)), 0, @as(f32, @floatFromInt(grows - 1))));
                splashes.append(gpa, .{ .x = sx, .y = sy, .radius = 3, .amp = 0.6 }) catch {};
            } else if (ev.kind == .button_up) {
                if (armed_target) |at| if (enroll_view.hitTest(hits.items, lx, ly)) |rel| if (rel == at) {
                    // Copy → real X11 clipboard (the password on the password step,
                    // the private key on the recovery step) + the toast.
                    if (at == .copy) {
                        const clip_text: []const u8 = if (state.step == .recovery)
                            state.recovery_key[0..state.recovery_len]
                        else if (state.has_pw)
                            state.cred.bytes[0..state.cred.len]
                        else
                            "";
                        if (clip_text.len > 0) {
                            window_shell.setClipboard(win, clip_text);
                            state.copied_ns = frame_ns;
                        }
                    }
                    apply(&state, at, io, frame_ns, &mstore, &memjob);
                    caret_anchor_ns = frame_ns; // a click (focus/edit) → solid caret
                };
                armed_target = null;
            }
        }
        events.clearRetainingCapacity();

        // Advance the calm medium on a fixed ~60 Hz timestep.
        const dt_ns: u64 = 16_666_667;
        const now_ns = frame_ns;
        if (last_step_ns == 0 or (now_ns -| last_step_ns) >= dt_ns) {
            var yy: u32 = 0;
            while (yy < grows) : (yy += 1) {
                const fy: f32 = @floatFromInt(yy);
                var xx: u32 = 0;
                while (xx < gcols) : (xx += 1) {
                    const fx: f32 = @floatFromInt(xx);
                    const base = std.math.sin(fx * amb_scale + t * amb_drift) *
                        std.math.sin(fy * amb_scale * 1.3 - t * amb_drift * 0.8);
                    bias[yy * gcols + xx] = amb_amp * base;
                }
            }
            glyph_field.step(&field, fparams, splashes.items, bias);
            splashes.clearRetainingCapacity();
            t += 1.0 / 60.0;
            last_step_ns = if (last_step_ns == 0 or (now_ns -| last_step_ns) > dt_ns * 4) now_ns else last_step_ns + dt_ns;
        }

        // Render: calm field behind, the card on top.
        if (g_opt) |*gg| {
            gpu.feedBuild(&feed_path, gpa, &engine, dl.slice(), scale) catch {};
            gpu.uploadField(&field_grid, field.height, field.dye, field.cols, field.rows);
            gpu.clear(clear_r, clear_g, clear_b);
            // The dimmed field "pillar" sits behind the card and is intentionally
            // WIDER than it (margin each side), so the card rests in a calm band
            // rather than the band hugging its edges.
            const card_left: f32 = @floatFromInt((@as(i32, @intCast(design_w)) - 460) / 2);
            const margin: f32 = 52;
            const panel_l: f32 = (card_left - margin) * scale;
            const panel_r: f32 = (card_left + 460.0 + margin) * scale;
            gpu.drawFieldGrid(&field_grid, &field_renderer, mcx, mcy, t, @intCast(W), @intCast(H), panel_l, panel_r, 0xFFA6ACBA, false, false); // enroll is pre-auth: default grey-white ink, no hearts, no light mode
            gpu.feedDraw(&feed_path, @intCast(W), @intCast(H));
            gpu.swap(gg);
        } else {
            // Software funnel: rasterize the same draw list into the backend
            // framebuffer and blit — no field background (its grid render is
            // GPU-only; the sim still steps so a later GPU attach is seamless).
            const clear_px: u32 = 0xFF141416; // clear_r/g/b as a packed pixel
            window_shell.presentDrawList(win, gpa, &engine, dl.slice(), clear_px) catch break;
        }
    }
    return null; // window closed / Esc without signing up
}

/// Build the pure snapshot the view renders from the mutable state.
pub fn snapshot(s: *const State, blink_on: bool) enroll_view.EnrollView {
    return .{
        .step = s.step,
        .branch = s.branch,
        .handle = tfView(&s.handle),
        .username = tfView(&s.username),
        .email = tfView(&s.email),
        .use_email = s.use_email,
        .age_ok = s.age_ok,
        .tos_ok = s.tos_ok,
        .tier = s.tier,
        .password = if (s.has_pw) s.cred.bytes[0..s.cred.len] else "",
        .saved = s.saved,
        .recovery_key = s.recovery_key[0..s.recovery_len],
        .rec_saved = s.rec_saved,
        .copied_t = s.copied_t,
        .confirm_stage = s.confirm_stage,
        .spot_positions = s.spot_positions,
        .spot = .{ tfView(&s.spot[0]), tfView(&s.spot[1]), tfView(&s.spot[2]) },
        .full = tfView(&s.full),
        .confirm_error = s.confirm_error,
        .confirm_checking = s.mem_verifying,
        .focus = s.focus,
        .caret = focusedCaret(s),
        .blink_on = blink_on,
        .craft_t = s.craft_t,
        .hover = s.hover,
        .hover_on = s.hover_on,
        .hover_t = s.hover_t,
        .tier_chosen = s.tier_chosen,
        .bar_t = s.bar_t,
        .bar_phase = s.bar_phase,
        .pow_t = s.pow_t,
        .seal_t = s.seal_t,
        .did = if (s.step == .done) "did:plc:7mock4example" else "",
        .final_handle = s.final_handle[0..s.final_handle_len],
        .card_h = @intFromFloat(s.card_h),
        // The incoming body starts one slide-length to the side you came FROM and
        // settles to 0: forward from the right, Back from the left.
        .body_dx = @intFromFloat((1.0 - s.trans_t) * trans_slide_px * @as(f32, @floatFromInt(s.trans_dir))),
        .info = s.info,
        .connect_failed = s.connect_failed,
        .rehearsal = dist_config.enroll_rehearsal,
        // The card asks "do we KNOW yet?", not "is a worker running?" — the gap
        // between the two (a stale lookup still being reaped) must not flash the
        // browser copy at somebody we have not looked up.
        .resolving = !s.resolved,
        .host = s.host[0..s.host_len],
        .pw = tfView(&s.pw),
        .pw_show = s.pw_show,
        .signin_busy = s.signin_busy,
        .sign_error = s.sign_error,
    };
}

// How long a step transition takes, and how far the incoming body travels. Short
// enough that it never stands between a person and the next field; long enough to
// be read as motion rather than a jump.
const trans_dur_ns: f32 = 260_000_000;
/// STRICTLY LESS THAN THE CARD'S INNER PADDING (28). The draw list is not clipped
/// to the card — nothing clips it but the framebuffer — so a body offset larger
/// than the padding would push the incoming content out THROUGH the card's edge
/// and onto the field for the first frames of every forward step. Travel far
/// enough to be read as motion, never far enough to escape the card.
const trans_slide_px: f32 = 26.0;

/// The natural height of the card the state is currently showing.
fn cardTargetH(s: *const State) f32 {
    return @floatFromInt(if (s.step == .confirm)
        enroll_view.confirmHeight(s.confirm_stage)
    else
        enroll_view.cardHeight(s.step, s.branch));
}

/// THE STEP TRANSITION — one clock, driving both halves of it, shared by both
/// drivers (the live run loop and the dev harness) so the flow cannot animate two
/// different ways depending on who is running it.
///
/// The content SLIDES IN FROM THE SIDE YOU CAME FROM (forward → from the right,
/// Back → from the left) while the card GROWS UNDER IT toward the new step's
/// height. The two share `trans_t`, so the card is still settling as the content
/// arrives on top of it — the card reads as the thing the content lives in, not as
/// a second animation that happens to run alongside.
///
/// Time-based, not a per-frame lerp: `t += (1-t) * 0.22` settles in half the time
/// on a 120 Hz screen as on a 60 Hz one, which means the phone and the laptop were
/// running different animations. Elapsed nanoseconds, eased out cubic — fast off
/// the mark, gently arriving — is the same motion everywhere.
pub fn stepMotion(s: *State, frame_ns: u64) void {
    if (s.step != s.prev_step or s.confirm_stage != s.prev_confirm_stage) {
        const from = enroll_view.depth(s.prev_step, s.prev_confirm_stage);
        const to = enroll_view.depth(s.step, s.confirm_stage);
        s.trans_dir = if (to >= from) 1 else -1;
        s.trans_from_h = if (s.card_h < 1.0) cardTargetH(s) else s.card_h;
        s.trans_start_ns = frame_ns;
        s.prev_step = s.step;
        s.prev_confirm_stage = s.confirm_stage;
        s.info = .none; // a step change closes any open bubble
    }

    const lin: f32 = if (s.trans_start_ns == 0)
        1.0
    else
        @min(1.0, @as(f32, @floatFromInt(frame_ns -| s.trans_start_ns)) / trans_dur_ns);
    const inv = 1.0 - lin;
    s.trans_t = 1.0 - inv * inv * inv; // easeOutCubic

    const target = cardTargetH(s);
    if (s.card_h < 1.0) {
        s.card_h = target; // first frame: no growth from nothing
        s.trans_from_h = target;
    } else {
        s.card_h = s.trans_from_h + (target - s.trans_from_h) * s.trans_t;
    }
}

/// Scrub the typed sign-in password and forget it was ever typed. Called whenever
/// the `.signin` step is left, by any road (Back, a landed session, a reset) — the
/// bytes are erased with `secureZero`, which the optimizer is not allowed to drop.
pub fn wipePw(s: *State) void {
    std.crypto.secureZero(u8, &s.pw.buf);
    s.pw.len = 0;
    s.pw.caret = 0;
    s.pw_show = false;
    s.signin_busy = false;
}

/// Route decoded keys into the focused field: text insert, Backspace/Delete,
/// caret motion (←/→, Home/End), and Tab/Shift+Tab/Enter focus traversal. All
/// editing runs through the shared `textedit` model (caret-aware). Returns true
/// to quit (bare Esc).
/// `phone` = Enter DISMISSES the keyboard instead of hopping to the next field.
/// With a mouse, Enter-advances-focus is a convenience; with a thumb, the keyboard
/// is covering half the screen and "done" is what the key means — you press it to
/// get the keyboard OUT OF THE WAY so you can see what you typed and reach the
/// button underneath. Tab still traverses (a phone has no Tab).
pub fn handleTextFor(s: *State, bytes: []const u8, phone: bool) bool {
    s.phone_enter = phone;
    return handleText(s, bytes);
}

pub fn handleText(s: *State, bytes: []const u8) bool {
    var off: usize = 0;
    while (off < bytes.len) {
        const d = tui.decodeInput(bytes[off..]);
        if (d.consumed == 0) break;
        off += d.consumed;
        switch (d.event) {
            .escape => return true, // bare Esc quits
            .enter => if (s.phone_enter) {
                s.focus = .none; // phone: Enter means "done" — put the keyboard away
            } else if (s.step == .signin and s.pw.len > 0 and !s.signin_busy) {
                // A SIGN-IN FORM SUBMITS ON ENTER. Everywhere else in the flow Enter
                // means "next field"; on a one-field password card the next field is
                // itself, so the key would do nothing at all — and every person alive
                // types a password and presses Enter. (Same effect as tapping the
                // button: raise the flag, let the run loop do the network.)
                s.sign_error = .none;
                s.signin_busy = true;
                s.focus = .none;
            } else focusStep(s, false), // desktop: advance to the next field
            .back_tab => focusStep(s, true), // Shift+Tab → previous field
            .char => |c| {
                if (c == '\t') {
                    focusStep(s, false); // Tab → next field
                    continue;
                }
                const fld = focusedField(s) orelse continue;
                var f = tfField(fld);
                if (c == 127 or c == 8) {
                    textedit.backspace(&f);
                } else if (c >= 0x20) {
                    var u: [4]u8 = undefined;
                    const n = std.unicode.utf8Encode(c, &u) catch 0;
                    if (n > 0) textedit.insert(&f, u[0..n]);
                } else continue;
                tfApply(fld, f);
            },
            .left, .right, .home, .end_key, .delete => {
                const fld = focusedField(s) orelse continue;
                var f = tfField(fld);
                switch (d.event) {
                    .left => textedit.left(&f),
                    .right => textedit.right(&f),
                    .home => textedit.home(&f),
                    .end_key => textedit.end(&f),
                    .delete => textedit.deleteForward(&f),
                    else => unreachable,
                }
                tfApply(fld, f);
            },
            else => {},
        }
    }
    return false;
}

fn focusedField(s: *State) ?*TextField {
    return switch (s.focus) {
        .handle => &s.handle,
        .username => &s.username,
        .email => &s.email,
        .spot0 => &s.spot[0],
        .spot1 => &s.spot[1],
        .spot2 => &s.spot[2],
        .full => &s.full,
        .pw => &s.pw,
        .none => null,
    };
}

/// The caret offset of the focused field (0 when nothing is focused) — fed to the
/// view so it paints the caret in the right field at the right column.
fn focusedCaret(s: *const State) u32 {
    return switch (s.focus) {
        .handle => s.handle.caret,
        .username => s.username.caret,
        .email => s.email.caret,
        .spot0 => s.spot[0].caret,
        .spot1 => s.spot[1].caret,
        .spot2 => s.spot[2].caret,
        .full => s.full.caret,
        .pw => s.pw.caret,
        .none => 0,
    };
}

/// The ordered, tabbable fields for the current step/stage (written into `out`,
/// count returned). Tab cycles within this set; steps with no fields return 0.
fn focusOrder(s: *const State, out: *[4]enroll_view.Focus) usize {
    return switch (s.step) {
        .identity => switch (s.branch) {
            .existing => blk: {
                out[0] = .handle;
                break :blk 1;
            },
            else => blk: {
                out[0] = .username;
                if (s.use_email) {
                    out[1] = .email;
                    break :blk 2;
                }
                break :blk 1;
            },
        },
        .confirm => switch (s.confirm_stage) {
            .spot => blk: {
                out[0] = .spot0;
                out[1] = .spot1;
                out[2] = .spot2;
                break :blk 3;
            },
            else => blk: {
                out[0] = .full;
                break :blk 1;
            },
        },
        .signin => blk: {
            out[0] = .pw;
            break :blk 1;
        },
        else => 0,
    };
}

/// Move focus to the next (or previous) field in the current step, wrapping. A
/// no-op on steps without fields.
fn focusStep(s: *State, backward: bool) void {
    var order: [4]enroll_view.Focus = undefined;
    const n = focusOrder(s, &order);
    if (n == 0) return;
    var idx: usize = 0;
    var found = false;
    for (order[0..n], 0..) |f, i| if (f == s.focus) {
        idx = i;
        found = true;
    };
    if (!found) {
        s.focus = order[0];
    } else {
        idx = if (backward) (idx + n - 1) % n else (idx + 1) % n;
        s.focus = order[idx];
    }
    // Land the caret at the end of the newly-focused field.
    if (focusedField(s)) |fld| fld.caret = fld.len;
}

pub fn apply(s: *State, target: enroll_view.HitTarget, io: std.Io, now_ns: u64, mstore: *membership_shell.Store, memjob: *MemJob) void {
    switch (target) {
        .choose_existing => {
            s.branch = .existing;
            s.step = .identity;
            s.focus = .handle;
        },
        .choose_new => {
            s.branch = .new;
            s.step = .identity;
            s.focus = .username;
        },
        .back => {
            wipePw(s);
            forgetHost(s);
            s.step = .provenance;
            s.branch = .undecided;
            s.focus = .none;
        },
        .primary => switch (s.step) {
            .provenance => {},
            .identity => {
                // EXISTING identity → find out WHO HOSTS IT first (the run loop
                // starts the resolve worker on this step). Ours ⇒ an in-app
                // password; anyone else's ⇒ their browser. NEW identity continues
                // the create-account ritual through membership.
                if (s.branch == .existing) {
                    s.connect_failed = false;
                    forgetHost(s);
                    s.step = .connecting;
                } else {
                    s.step = .membership;
                }
                s.focus = .none;
            },
            .membership => {
                mint(s, io, mstore, memjob);
                s.craft_start_ns = now_ns; // begin the decode
                s.saved = false;
                s.step = .password;
                s.focus = .none;
            },
            .password => {
                // Enter the confirmation at stage A with empty inputs.
                s.step = .confirm;
                s.confirm_stage = .spot;
                s.spot = .{ .{}, .{}, .{} };
                s.full = .{};
                s.confirm_error = false;
                s.focus = .spot0;
            },
            .confirm => confirmSubmit(s, io, mstore, memjob),
            .recovery => {
                s.step = .done;
                s.focus = .none;
            },
            .done => {
                // "Enter Zat4" → the proof-of-work gate (verifying you're human).
                s.step = .verifying;
                s.pow_start_ns = now_ns;
            },
            .verifying => {},
            .connecting => {
                if (s.sign_error == .not_found) {
                    // "Edit handle" — a handle that resolves to nothing is a TYPO,
                    // not a failed sign-in. Retrying the same bytes would fail the
                    // same way; the only useful move is back to the field.
                    forgetHost(s);
                    s.step = .identity;
                    s.focus = .handle;
                } else {
                    // "Try again" after a failed browser sign-in: clear the failure
                    // so the run loop re-launches the OAuth worker.
                    s.connect_failed = false;
                }
            },
            // "Sign in" on an account WE host. The tap only raises the flag; the run
            // loop owns the network (B3) and starts the createSession worker.
            .signin => {
                if (s.pw.len > 0 and !s.signin_busy) {
                    s.sign_error = .none;
                    s.signin_busy = true;
                    s.focus = .none;
                }
            },
        },
        .tier_secure => selectTier(s, .secure, now_ns),
        .tier_super => selectTier(s, .super_secure, now_ns),
        .tier_overkill => selectTier(s, .ultra_secure, now_ns),
        .copy => {}, // clipboard handled at the click site (needs the window)
        .reroll => {
            mint(s, io, mstore, memjob);
            s.craft_start_ns = now_ns; // re-run the decode
            s.saved = false;
        },
        .toggle_saved => s.saved = !s.saved,
        .toggle_rec_saved => s.rec_saved = !s.rec_saved,
        .toggle_email => s.use_email = !s.use_email,
        .toggle_age => s.age_ok = !s.age_ok,
        .toggle_tos => s.tos_ok = !s.tos_ok,
        .link_tos => s.info = if (s.info == .tos) .none else .tos,
        .link_privacy => s.info = if (s.info == .privacy) .none else .privacy,
        // Clicking a field focuses it and lands the caret at its end (full
        // click-to-place within a field is a small follow-up).
        .field_handle => {
            s.focus = .handle;
            s.handle.caret = s.handle.len;
        },
        .field_username => {
            s.focus = .username;
            s.username.caret = s.username.len;
        },
        .field_email => {
            s.focus = .email;
            s.email.caret = s.email.len;
        },
        .field_spot0 => {
            s.focus = .spot0;
            s.spot[0].caret = s.spot[0].len;
        },
        .field_spot1 => {
            s.focus = .spot1;
            s.spot[1].caret = s.spot[1].len;
        },
        .field_spot2 => {
            s.focus = .spot2;
            s.spot[2].caret = s.spot[2].len;
        },
        .field_full => {
            s.focus = .full;
            s.full.caret = s.full.len;
        },
        .field_pw => {
            s.focus = .pw;
            s.pw.caret = s.pw.len;
        },
        .toggle_pw_show => s.pw_show = !s.pw_show,
        .regen_password => {
            // Didn't save it → mint a fresh password and go back to copy it.
            mint(s, io, mstore, memjob);
            s.craft_start_ns = now_ns;
            s.saved = false;
            s.confirm_stage = .spot;
            s.spot = .{ .{}, .{}, .{} };
            s.full = .{};
            s.confirm_error = false;
            s.mem_verifying = false; // abandon any in-flight verify; the new mint re-enrolls
            s.step = .password;
            s.focus = .none;
        },
        .info_membership => s.info = if (s.info == .membership) .none else .membership,
        .info_password => s.info = if (s.info == .password) .none else .password,
        .deposit => {}, // hover-only (rationale popup); no click action
        .restart => reset(s),
    }
}

/// Forget everything the lookup told us, so the next attempt asks the network
/// again rather than acting on a stale answer about a handle that has since been
/// retyped.
fn forgetHost(s: *State) void {
    s.resolving = false;
    s.resolved = false;
    s.host_len = 0;
    s.pds_len = 0;
    s.host_ours = false;
    s.sign_error = .none;
}

/// Pick a tier: mark it chosen and (re)start the strength-bar fill animation.
fn selectTier(s: *State, tier: credential_core.Tier, now_ns: u64) void {
    s.tier = tier;
    s.tier_chosen = true;
    s.bar_sel_ns = now_ns; // restart the fill from 0 → re-springs the bar
}

/// The DID enrollment registers its membership under. No network in this slice,
/// so a stable synthetic id is enough — verifyLogin keys off the same one. The
/// networked slice replaces it with the account's real `did:plc`.
const local_did = "did:zat4:local-enroll";

/// Mint a real password at the chosen tier (the one place randomness enters —
/// shell-side, as the rules require), then kick off the REAL Argon2id enroll on
/// the background worker. On failure leave the old one.
fn mint(s: *State, io: std.Io, mstore: *membership_shell.Store, memjob: *MemJob) void {
    if (credential_shell.generate(io, s.tier)) |c| {
        s.cred = c;
        s.has_pw = true;
        // Fresh spot-check positions for this password (per-enrollment random).
        s.spot_positions = pickSpotPositions(io, credential_core.wordCount(s.tier));
        startEnroll(memjob, s, io, mstore); // off-thread; finishes during the decode
    } else |_| {}
}

/// Pick three DISTINCT 1-based word positions to spot-check, drawn fresh from
/// the CSPRNG each mint so the challenge isn't a static form a bot can pre-fill.
/// Sorted ascending for a tidy presentation. On entropy failure, falls back to
/// a fixed valid spread (first / middle / last).
fn pickSpotPositions(io: std.Io, word_count: u8) [3]u8 {
    var pool: [credential_core.max_words]u8 = undefined;
    var i: u8 = 0;
    while (i < word_count) : (i += 1) pool[i] = i + 1; // 1-based positions
    var rnd: [3]u8 = undefined;
    io.randomSecure(&rnd) catch {
        return .{ 1, @max(2, word_count / 2), word_count };
    };
    // Partial Fisher–Yates over the first three slots of the position pool.
    var k: usize = 0;
    while (k < 3) : (k += 1) {
        const remaining: u8 = word_count - @as(u8, @intCast(k));
        const j: usize = k + @as(usize, rnd[k] % remaining);
        const tmp = pool[k];
        pool[k] = pool[j];
        pool[j] = tmp;
    }
    var out = [3]u8{ pool[0], pool[1], pool[2] };
    std.mem.sort(u8, &out, {}, std.sort.asc(u8));
    return out;
}

/// Validate the current confirm stage. Stage A spot-check: every answer must
/// match the word at its position (a partial check against the in-memory
/// plaintext — you can't Argon2-verify a single word against the whole-password
/// hash). Stage B: kick off the REAL Argon2id verify (`membership.verifyLogin`)
/// on the background worker; the render loop calls `confirmSucceed` (or flags the
/// error) when it lands. A spot mismatch raises the inline hint and stays put.
fn confirmSubmit(s: *State, io: std.Io, mstore: *membership_shell.Store, memjob: *MemJob) void {
    if (!s.has_pw or s.mem_verifying) return; // nothing to check / already verifying
    const pw = s.cred.bytes[0..s.cred.len];
    if (s.confirm_stage == .spot) {
        var i: usize = 0;
        while (i < 3) : (i += 1) {
            const want = enroll_view.wordAt(pw, s.spot_positions[i]);
            if (!enroll_view.confirmMatch(tfView(&s.spot[i]), want)) {
                s.confirm_error = true;
                return;
            }
        }
        s.confirm_stage = .full;
        s.confirm_error = false;
        s.focus = .full;
    } else {
        // Stage B: the full-password verify runs off-thread (the UI stays live,
        // the button shows "Checking…"); the render loop picks up the result.
        startVerify(memjob, s, io, mstore);
        s.confirm_error = false;
        s.mem_verifying = true;
    }
}

/// Called from the render loop when the off-thread Stage-B verify PASSES:
/// activate the membership (fast, main-thread) and advance the flow.
pub fn confirmSucceed(s: *State, io: std.Io, mstore: *membership_shell.Store) void {
    membership_shell.activate(mstore, local_did) catch {}; // real → active member
    finalize(s);
    // A new, no-email account gets its recovery key revealed before finishing.
    if (s.branch == .new and !s.use_email) {
        genRecoveryKey(s, io);
        s.rec_saved = false;
        s.step = .recovery;
    } else {
        s.step = .done;
    }
    s.focus = .none;
}

/// The recovery keypair scheme: P-256, an atproto `did:key` key type. The PUBLIC
/// key would register as the user's `did:plc` ROTATION key; the PRIVATE key
/// (shown, grouped hex) is the secret they must save.
const RecoveryScheme = std.crypto.sign.ecdsa.EcdsaP256Sha256;

/// Generate a REAL account recovery keypair (not a stand-in). `generate(io)`
/// draws its seed from the shell's CSPRNG (B3) and returns a valid P-256
/// keypair; we display the 32-byte PRIVATE scalar as grouped uppercase hex — the
/// genuine secret a user keeps. In the live app the matching PUBLIC key is
/// written into the DID document as the rotation key, completing the recovery
/// primitive; here there is no network, so only the key material is real.
fn genRecoveryKey(s: *State, io: std.Io) void {
    const kp = RecoveryScheme.KeyPair.generate(io);
    const priv = kp.secret_key.toBytes(); // the real private scalar (32 bytes)
    const hexd = "0123456789ABCDEF";
    var n: usize = 0;
    for (priv, 0..) |b, i| {
        if (i != 0 and i % 2 == 0) {
            s.recovery_key[n] = ' '; // space every 4 hex chars (wraps to 2 lines)
            n += 1;
        }
        s.recovery_key[n] = hexd[b >> 4];
        n += 1;
        s.recovery_key[n] = hexd[b & 0x0F];
        n += 1;
    }
    s.recovery_len = n;
}

// ── REAL proof-of-work (background worker) ──────────────────────────────────
//
// [CALIBRATE] enrollment difficulty: memory is FIXED + phone-safe (the one knob
// that can OOM a device — never adaptive, per ANTIBOT_DESIGN); only the attempt
// target (leading_zero_bits) would adapt in production. Here, tuned for a few
// visible seconds on a dev box. No-email pays more (the design's invisible tax).
// Production swaps these for a SERVER-ISSUED, risk-adaptive difficulty.
const enroll_pow: pow.Difficulty = .{ .mem_kib = 32 * 1024, .iters = 1, .lanes = 1, .leading_zero_bits = 6 };
const enroll_pow_hard: pow.Difficulty = .{ .mem_kib = 32 * 1024, .iters = 1, .lanes = 1, .leading_zero_bits = 7 };

/// The background PoW job. Lives in `run` (NOT in `State`, which gets reset),
/// so the worker thread + its atomics outlive a state reset cleanly.
pub const PowJob = struct {
    // A7.2: cold struct (one live instance, holds a thread + lifecycle), size guard waived.
    thread: ?std.Thread = null,
    cancel: std.atomic.Value(bool) = .init(false),
    done: std.atomic.Value(bool) = .init(false),
    ok: bool = false, // solution verified (informational; completion gates on `done`)
    solution: pow.Solution = .{ .nonce = 0 },
    challenge: pow.Challenge = undefined,
    difficulty: pow.Difficulty = enroll_pow,
    active: bool = false, // a job is running for this verifying session
};

/// Worker body: the genuine memory-hard solve, off the UI thread. Uses the
/// thread-safe page allocator for Argon2's buffers (no contention with the main
/// render allocator). Publishes the result via `done` (release/acquire fences
/// the plain `solution`/`ok` writes).
fn powWorker(job: *PowJob, io: std.Io) void {
    const a = std.heap.page_allocator;
    if (pow_shell.solve(a, io, job.challenge, job.difficulty, &job.cancel)) |sol| {
        job.solution = sol;
        job.ok = pow_shell.verify(a, io, job.challenge, sol, job.difficulty) catch false;
    } else |_| {
        job.ok = false; // canceled or errored — don't hang the UI
    }
    job.done.store(true, .release);
}

/// Spawn the solve for this verifying session. The challenge seed binds to the
/// account (the would-be handle) so the work proves effort for THIS entry.
pub fn startPow(job: *PowJob, s: *State, io: std.Io) void {
    const who = if (s.final_handle_len > 0) s.final_handle[0..s.final_handle_len] else "zat4-enroll";
    const seed = pow.seedForPost(who, 0);
    job.challenge = pow.challengeFor(seed, .heavy);
    job.difficulty = if (s.branch == .new and !s.use_email) enroll_pow_hard else enroll_pow;
    job.cancel.store(false, .monotonic);
    job.done.store(false, .monotonic);
    job.ok = false;
    job.active = true;
    job.thread = std.Thread.spawn(.{}, powWorker, .{ job, io }) catch null;
    if (job.thread == null) job.done.store(true, .release); // spawn failed → complete anyway
}

/// Cancel + join any in-flight solve (cooperative; the worker checks `cancel`
/// each attempt). Safe to call when idle.
pub fn stopPow(job: *PowJob) void {
    if (job.thread) |th| {
        job.cancel.store(true, .release);
        th.join();
        job.thread = null;
    }
    job.active = false;
}

// ── REAL membership hashing (background worker) ─────────────────────────────
//
// The Argon2id enroll/verify (64 MiB hashes, ~hundreds of ms) run here, off the
// UI thread, so Generate/Confirm never freeze. enroll and verify never overlap
// in time (different steps), so one worker serializes both; `startVerify` joins
// any in-flight enroll first, guaranteeing the verifier is stored before it's read.

/// The background membership job (one live instance — A7.2 cold, guard waived).
pub const MemJob = struct {
    // A7.2: cold struct (one live instance, holds a thread + lifecycle), size guard waived.
    thread: ?std.Thread = null,
    done: std.atomic.Value(bool) = .init(false),
    kind: Kind = .enroll,
    verify_ok: bool = false, // verify result (read after join / done-acquire)
    store: *membership_shell.Store = undefined,
    io: std.Io = undefined,
    tier: credential_core.Tier = .super_secure,
    pw: [80]u8 = undefined, // copied input (≤ max credential / TextField length)
    pw_len: u8 = 0,
    const Kind = enum { enroll, verify };
};

/// Worker body, off the UI thread. enroll resets the single-member store then
/// stores the genuine Argon2id verifier; verify checks the typed password against
/// it. Argon2's buffers come from the store's (thread-safe page) allocator.
fn memWorker(job: *MemJob) void {
    const pwd = job.pw[0..job.pw_len];
    switch (job.kind) {
        .enroll => {
            membership_shell.deinit(job.store);
            job.store.* = membership_shell.init(job.store.gpa);
            membership_shell.enroll(job.store, job.io, local_did, job.tier, pwd, 0) catch {};
        },
        .verify => {
            job.verify_ok = membership_shell.verifyLogin(job.store, job.io, local_did, pwd) catch false;
        },
    }
    job.done.store(true, .release);
}

/// Join any in-flight membership job (cooperative end — these are short hashes,
/// not a cancellable loop, so we just wait). Safe to call when idle.
pub fn joinMem(job: *MemJob) void {
    if (job.thread) |th| {
        th.join();
        job.thread = null;
    }
}

fn spawnMem(job: *MemJob, kind: MemJob.Kind, store: *membership_shell.Store, io: std.Io) void {
    job.kind = kind;
    job.store = store;
    job.io = io;
    job.verify_ok = false;
    job.done.store(false, .monotonic);
    job.thread = std.Thread.spawn(.{}, memWorker, .{job}) catch null;
    if (job.thread == null) job.done.store(true, .release); // spawn failed → "done" (no hang)
}

/// Kick off the REAL enroll of the freshly-minted password (off-thread). Joins
/// any prior op first so a reroll/regen replaces the verifier without a race.
fn startEnroll(job: *MemJob, s: *State, io: std.Io, mstore: *membership_shell.Store) void {
    if (!s.has_pw) return;
    joinMem(job);
    const pwd = s.cred.bytes[0..s.cred.len];
    @memcpy(job.pw[0..pwd.len], pwd);
    job.pw_len = @intCast(pwd.len);
    job.tier = s.tier;
    spawnMem(job, .enroll, mstore, io);
}

/// Kick off the REAL Stage-B verify (off-thread). Joins any in-flight enroll
/// first so the verifier is guaranteed stored before it's read.
fn startVerify(job: *MemJob, s: *State, io: std.Io, mstore: *membership_shell.Store) void {
    joinMem(job);
    const typed = tfView(&s.full);
    const n = @min(typed.len, job.pw.len);
    @memcpy(job.pw[0..n], typed[0..n]);
    job.pw_len = @intCast(n);
    spawnMem(job, .verify, mstore, io);
}

// ── EXISTING-account browser OAuth sign-in (background worker) ──────────────
//
// "I already have an account" hands off to the atproto OAuth/DPoP flow: resolve
// the typed handle to its PDS, open the system browser, and exchange the
// callback for a DPoP-bound session. That flow BLOCKS on the loopback callback
// for as long as the human takes, so it runs here, off the UI thread, exactly
// like the PoW + membership workers. The render loop spins the connecting
// spinner and polls `done`.
//
// Allocator discipline (the one subtlety): the worker builds the session with
// the thread-safe `page_allocator` — never the single-threaded render `gpa`,
// which the UI thread is using every frame. After the loop JOINS the worker, it
// re-homes the session into `gpa` via `auth.reownSession` (no concurrency at
// that point) so the caller frees it like any other session.

/// The background OAuth job (one live instance — A7.2 cold, guard waived).
pub const OAuthJob = struct {
    // A7.2: cold struct (one live instance, holds a thread + lifecycle), size guard waived.
    thread: ?std.Thread = null,
    /// Set by the main thread to abort the loopback wait (window closed mid-flow);
    /// `oauth.login` polls it so a shutdown never hangs on `accept`.
    cancel: std.atomic.Value(bool) = .init(false),
    done: std.atomic.Value(bool) = .init(false),
    active: bool = false, // a flow is running (or finished and not yet consumed)
    ok: bool = false, // a session was produced (read after done-acquire / join)
    /// Whether the signed-in DID already has a Zat4 membership record (§13.1): the
    /// fork — true → returning member (→ feed), false → first-timer (→ enrollment).
    /// Determined on the worker right after login so the result lands with the
    /// session, no UI-thread network call.
    is_member: bool = false,
    session: auth.Session = undefined, // page_allocator-owned on success
    handle: [256]u8 = undefined, // copied would-be handle (worker reads this, not State)
    handle_len: u16 = 0,
    io: std.Io = undefined,
    env: ?*const std.process.Environ.Map = null,
};

/// Worker body: resolve the handle → PDS, then run the browser OAuth flow. Both
/// legs are networked shell ops; everything is allocated from the thread-safe
/// `page_allocator` (the session) and a private arena over it (transients), so
/// the worker never touches the render allocator. Publishes via `done` (release).
fn oauthWorker(job: *OAuthJob) void {
    const a = std.heap.page_allocator;
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const scratch = arena_state.allocator();
    const handle = job.handle[0..job.handle_len];
    if (runOAuth(a, scratch, job, handle)) |sess| {
        job.session = sess;
        job.ok = true;
        // The fork (§13.1): does this DID already hold a Zat4 membership? A read
        // failure is treated as "not a member" (the safe default — a first-timer
        // path can always re-mint; idempotent at rkey "self"). Strings live in the
        // arena (discarded); we only need existence.
        const m = membership_record.fetch(a, scratch, job.io, job.env, &job.session, job.session.did) catch null;
        job.is_member = (m != null);
    } else |err| {
        std.debug.print("[enroll] oauth sign-in failed: {s}\n", .{@errorName(err)});
        job.ok = false;
    }
    job.done.store(true, .release);
}

/// Resolve the handle and run the login. The resolved `Identity` lives in
/// `scratch` (freed with the arena); the returned session is `gpa`-owned
/// (page_allocator here), re-homed by the caller after join.
fn runOAuth(gpa: std.mem.Allocator, scratch: std.mem.Allocator, job: *OAuthJob, handle: []const u8) !auth.Session {
    const id = try identity.resolve(scratch, job.io, job.env, .{}, handle);
    return oauth.login(gpa, job.io, job.env, scratch, id.pds_url, id.handle, &job.cancel);
}

/// Spawn the OAuth flow for the handle currently typed into the existing-branch
/// field. The handle is COPIED into the job so the worker never reads `State`
/// (which the UI thread mutates). A spawn failure completes the job as a clean
/// failure rather than hanging.
pub fn startOAuth(job: *OAuthJob, s: *State, io: std.Io, env: ?*const std.process.Environ.Map) void {
    const h = tfView(&s.handle);
    const n = @min(h.len, job.handle.len);
    @memcpy(job.handle[0..n], h[0..n]);
    job.handle_len = @intCast(n);
    job.io = io;
    job.env = env;
    job.cancel.store(false, .monotonic);
    job.done.store(false, .monotonic);
    job.ok = false;
    job.active = true;
    job.thread = std.Thread.spawn(.{}, oauthWorker, .{job}) catch null;
    if (job.thread == null) job.done.store(true, .release); // spawn failed → "done" (ok=false)
}

/// Join a finished worker WITHOUT freeing its result — the render loop calls this
/// once it sees `done`, because it's about to CONSUME `session` (re-home it into
/// `gpa`). Leaves `thread == null`, which tells the shutdown `stopOAuth` the
/// result was already taken.
pub fn joinOAuth(job: *OAuthJob) void {
    if (job.thread) |th| {
        th.join();
        job.thread = null;
    }
    job.active = false;
}

/// Shutdown cleanup (the `defer`): cancel + join any in-flight sign-in (the
/// cancel unblocks the loopback wait so this returns promptly even mid-browser),
/// AND release a SUCCESSFUL result that was never consumed — the case where the
/// flow lands in the very frame the window closes, so the loop breaks before
/// taking it. If the loop already consumed the result it called `joinOAuth`
/// first (`thread == null`), so this is then a no-op and never double-frees.
fn stopOAuth(job: *OAuthJob) void {
    if (job.thread) |th| {
        job.cancel.store(true, .release);
        th.join();
        job.thread = null;
        if (job.ok) auth.freeSession(std.heap.page_allocator, job.session);
    }
    job.active = false;
}

// ─────────────── the existing-account fork: resolve, then sign in ───────────────
//
// A returning person types a handle. WHO HOSTS IT decides the whole road:
//
//   pds.zat4.com  → an in-app password field + `com.atproto.server.createSession`.
//                   We run that server and already hold the Argon2id hash of that
//                   password; typing it into our app crosses no boundary that
//                   typing it into our website would not.
//   anywhere else → the browser (OAuth). Collecting another provider's password
//                   in our app is exactly what OAuth exists to prevent, and no
//                   promise on a screen makes it acceptable.
//
// Both legs are network, so both are workers: the render thread never blocks
// (UI-thread law), and neither worker ever reads `State` — the inputs are COPIED
// in, the answers are copied out.

/// The handle → PDS lookup. Answers with plain bytes in the job (the worker's
/// arena dies with it, so nothing it allocated escapes).
pub const ResolveJob = struct {
    // A7.2: cold struct (one live instance, holds a thread + lifecycle), size guard waived.
    thread: ?std.Thread = null,
    done: std.atomic.Value(bool) = .init(false),
    ok: bool = false, // the handle resolved (read after done-acquire / join)
    ours: bool = false, // …to the PDS we run
    handle: [256]u8 = undefined, // in: the typed handle, copied
    handle_len: u16 = 0,
    host: [96]u8 = undefined, // out: the PDS host ("bsky.network")
    host_len: u8 = 0,
    pds: [160]u8 = undefined, // out: the PDS URL (the createSession target)
    pds_len: u8 = 0,
    io: std.Io = undefined,
    env: ?*const std.process.Environ.Map = null,
};

fn resolveWorker(job: *ResolveJob) void {
    var arena_state = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena_state.deinit();
    const scratch = arena_state.allocator();
    const id = identity.resolve(scratch, job.io, job.env, .{}, job.handle[0..job.handle_len]) catch |err| {
        std.debug.print("[enroll] handle didn't resolve: {s}\n", .{@errorName(err)});
        job.done.store(true, .release);
        return;
    };
    const their_host = netguard.hostOf(id.pds_url) orelse "";
    const our_host = netguard.hostOf(config.fromEnv(job.env).pds_url) orelse "";
    const hn = @min(their_host.len, job.host.len);
    @memcpy(job.host[0..hn], their_host[0..hn]);
    job.host_len = @intCast(hn);
    const pn = @min(id.pds_url.len, job.pds.len);
    @memcpy(job.pds[0..pn], id.pds_url[0..pn]);
    job.pds_len = @intCast(pn);
    // Host equality, not URL equality: the same server reached as `https://x/` and
    // `https://x` is the same server, and case never was significant in a hostname.
    job.ours = their_host.len > 0 and our_host.len > 0 and std.ascii.eqlIgnoreCase(their_host, our_host);
    job.ok = true;
    job.done.store(true, .release);
}

/// Start the lookup for the handle currently typed into the existing-branch field
/// (COPIED in, so the worker never reads `State`). A spawn failure completes the
/// job as a clean failure rather than hanging.
pub fn startResolve(job: *ResolveJob, s: *State, io: std.Io, env: ?*const std.process.Environ.Map) void {
    const h = tfView(&s.handle);
    const n = @min(h.len, job.handle.len);
    @memcpy(job.handle[0..n], h[0..n]);
    job.handle_len = @intCast(n);
    job.io = io;
    job.env = env;
    job.done.store(false, .monotonic);
    job.ok = false;
    job.ours = false;
    job.host_len = 0;
    job.pds_len = 0;
    job.thread = std.Thread.spawn(.{}, resolveWorker, .{job}) catch null;
    if (job.thread == null) job.done.store(true, .release); // couldn't even start → "done" (ok=false)
}

/// Join a finished lookup and COPY its answer into `s` (main thread; the worker is
/// joined first, so there is no concurrency here). Returns true if the handle
/// resolved. Nothing here allocates: the answer is bytes in fixed buffers.
pub fn takeResolve(job: *ResolveJob, s: *State) bool {
    if (job.thread) |th| {
        th.join();
        job.thread = null;
    }
    s.resolving = false;
    s.resolved = true;
    if (!job.ok) {
        s.sign_error = .not_found;
        return false;
    }
    @memcpy(s.host[0..job.host_len], job.host[0..job.host_len]);
    s.host_len = job.host_len;
    @memcpy(s.pds[0..job.pds_len], job.pds[0..job.pds_len]);
    s.pds_len = job.pds_len;
    s.host_ours = job.ours;
    return true;
}

/// Shutdown / walked-away cleanup: join an in-flight lookup (it is a short HTTPS
/// round-trip, so it is waited out rather than cancelled) and drop its answer.
pub fn stopResolve(job: *ResolveJob) void {
    if (job.thread) |th| {
        th.join();
        job.thread = null;
    }
}

/// The in-app sign-in: `createSession` against OUR PDS with the typed password,
/// then the same membership fork the OAuth leg makes (§13.1) — a returning MEMBER
/// drops into the feed; a DID that is on our PDS but has no Zat4 membership record
/// still goes through the proof-of-work gate.
pub const PwLoginJob = struct {
    // A7.2: cold struct (one live instance, holds a thread + lifecycle), size guard waived.
    thread: ?std.Thread = null,
    done: std.atomic.Value(bool) = .init(false),
    ok: bool = false, // a session was produced
    refused: bool = false, // the SERVER said no (wrong password) — not a transport failure
    is_member: bool = false, // the DID already holds a Zat4 membership record
    session: auth.Session = undefined, // page_allocator-owned on success
    handle: [256]u8 = undefined,
    handle_len: u16 = 0,
    pds: [160]u8 = undefined,
    pds_len: u8 = 0,
    /// The secret, copied in and scrubbed the moment the job is joined.
    pw: [96]u8 = undefined,
    pw_len: u8 = 0,
    io: std.Io = undefined,
    env: ?*const std.process.Environ.Map = null,
};

fn pwLoginWorker(job: *PwLoginJob) void {
    const a = std.heap.page_allocator;
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const scratch = arena_state.allocator();
    const outcome = auth.login(a, scratch, job.io, job.env, job.pds[0..job.pds_len], job.handle[0..job.handle_len], job.pw[0..job.pw_len]) catch |err| {
        // Transport: we could not reach the server at all. That is NOT "wrong
        // password", and telling somebody their password is wrong when the truth is
        // that their train went into a tunnel is how you get them to change it.
        std.debug.print("[enroll] sign-in transport error: {s}\n", .{@errorName(err)});
        job.done.store(true, .release);
        return;
    };
    switch (outcome) {
        .refused => |f| {
            std.debug.print("[enroll] sign-in refused: {d} {s}\n", .{ f.status, f.code });
            job.refused = true;
        },
        .ok => |sess| {
            job.session = sess;
            job.ok = true;
            const m = membership_record.fetch(a, scratch, job.io, job.env, &job.session, job.session.did) catch null;
            job.is_member = (m != null);
        },
    }
    job.done.store(true, .release);
}

/// Start the sign-in with what is on the `.signin` card (handle + PDS from the
/// lookup, password from the field) — all COPIED into the job.
pub fn startPwLogin(job: *PwLoginJob, s: *State, io: std.Io, env: ?*const std.process.Environ.Map) void {
    const h = tfView(&s.handle);
    const hn = @min(h.len, job.handle.len);
    @memcpy(job.handle[0..hn], h[0..hn]);
    job.handle_len = @intCast(hn);
    const pn = @min(@as(usize, s.pds_len), job.pds.len);
    @memcpy(job.pds[0..pn], s.pds[0..pn]);
    job.pds_len = @intCast(pn);
    const pw = tfView(&s.pw);
    const wn = @min(pw.len, job.pw.len);
    @memcpy(job.pw[0..wn], pw[0..wn]);
    job.pw_len = @intCast(wn);
    job.io = io;
    job.env = env;
    job.done.store(false, .monotonic);
    job.ok = false;
    job.refused = false;
    job.is_member = false;
    job.thread = std.Thread.spawn(.{}, pwLoginWorker, .{job}) catch null;
    if (job.thread == null) job.done.store(true, .release); // couldn't start → "done" (ok=false)
}

/// Join a finished sign-in WITHOUT freeing its result — the caller is about to
/// consume `session`. The copied password is scrubbed here, at the point the job
/// stops needing it (C5).
pub fn joinPwLogin(job: *PwLoginJob) void {
    if (job.thread) |th| {
        th.join();
        job.thread = null;
    }
    std.crypto.secureZero(u8, &job.pw);
    job.pw_len = 0;
}

/// Shutdown cleanup: join an in-flight sign-in AND release a successful result
/// nobody consumed (the flow landing in the very frame the app is torn down). If
/// the loop already took it, `joinPwLogin` left `thread == null` and this is a
/// no-op — so it never double-frees.
pub fn stopPwLogin(job: *PwLoginJob) void {
    if (job.thread) |th| {
        th.join();
        job.thread = null;
        if (job.ok) auth.freeSession(std.heap.page_allocator, job.session);
    }
    std.crypto.secureZero(u8, &job.pw);
    job.pw_len = 0;
}

/// Compose the final handle for the done screen from the branch + inputs.
fn finalize(s: *State) void {
    var n: usize = 0;
    const put = struct {
        fn f(dst: []u8, at: *usize, src: []const u8) void {
            const room = dst.len - at.*;
            const k = @min(room, src.len);
            @memcpy(dst[at.* .. at.* + k], src[0..k]);
            at.* += k;
        }
    }.f;
    if (s.branch == .new) {
        put(&s.final_handle, &n, if (s.username.len > 0) tfView(&s.username) else "you");
        put(&s.final_handle, &n, ".zat4.com");
    } else {
        put(&s.final_handle, &n, if (s.handle.len > 0) tfView(&s.handle) else "you.bsky.social");
    }
    s.final_handle_len = n;
}

fn reset(s: *State) void {
    if (s.has_pw) credential_shell.wipe(&s.cred);
    wipePw(s); // the typed sign-in password never survives a restart of the flow
    s.* = .{};
}

/// Mint the NEW `.zat4.com` account on the PDS (slice 3b-#1). The minted
/// credential is the account password; the handle is `<username>.zat4.com`; the
/// invite code comes from `ZAT_INVITE_CODE` (the PDS is invite-gated while
/// bootstrapping). Returns the gpa-owned session on success, or null on a refusal
/// / transport error (printed). Email path for now; the no-email / recovery-DID
/// binding is a later sub-slice. A transient arena holds the request strings.
/// The Terms-of-Service version recorded in the consent at enrollment. PLACEHOLDER
/// until real Terms exist (ENROLLMENT_BUILD §9 A) — it just needs to be a stable
/// string so the membership record can pin which version was agreed to.
pub const tos_version_placeholder = "draft-2026-06";

pub fn createZatAccount(gpa: std.mem.Allocator, io: std.Io, env: ?*const std.process.Environ.Map, s: *State) ?auth.Session {
    if (!s.has_pw) return null;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    var hbuf: [128]u8 = undefined;
    const uname = tfView(&s.username);
    if (uname.len == 0) return null;
    const handle = std.fmt.bufPrint(&hbuf, "{s}.zat4.com", .{uname}) catch return null;
    const email: ?[]const u8 = if (s.use_email and s.email.len > 0) tfView(&s.email) else null;
    const invite: ?[]const u8 = if (env) |e| e.get("ZAT_INVITE_CODE") else null;
    const pds = config.fromEnv(env).pds_url;

    const outcome = auth.createAccount(gpa, arena, io, env, pds, lexicon.CreateAccountInput{
        .handle = handle,
        .password = s.cred.bytes[0..s.cred.len],
        .email = email,
        .inviteCode = invite,
    }) catch |err| {
        std.debug.print("[enroll] createAccount error: {s}\n", .{@errorName(err)});
        return null;
    };
    switch (outcome) {
        .ok => |sess| {
            var session = sess;
            // Record Zat4 membership in the brand-new repo (§13.2): its existence
            // makes the next sign-in a returning-member fast path. Best-effort —
            // the account already exists, so a failed write is logged, not fatal;
            // re-enrollment re-attempts it (putRecord at rkey "self" is idempotent).
            _ = membership_record.put(gpa, arena, io, env, &session, lexicon.membership_via.created, tos_version_placeholder, s.age_ok, clock_shell.unixSeconds()) catch |err| {
                std.debug.print("[enroll] membership write error: {s}\n", .{@errorName(err)});
            };
            return session;
        },
        .refused => |f| {
            std.debug.print("[enroll] createAccount refused: {d} {s}: {s}\n", .{ f.status, f.code, f.message });
            return null;
        },
    }
}
