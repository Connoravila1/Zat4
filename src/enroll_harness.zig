// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Zat4 — a social-media client built on the AT Protocol.
// Copyright (C) 2026  Connor Avila

//! B1 classification: SHELL. Interactive enrollment harness (`zig build
//! enroll`).
//!
//! Drives the REAL enrollment surface — `core/enroll_view.zig` — on a live
//! window so the FEEL can be tested: click the steps, type into the fields,
//! pick a tier, mint a real (CSPRNG) password, reroll, confirm, finish. There
//! is NO session and NO network here — this is the front door rendered in
//! isolation, exactly the way the pre-auth app will eventually show it. The
//! calm glyph field behind is the same pure wave medium the live app uses,
//! detuned (bigger cells, low ambient) so it stays wispy.
//!
//! This is a dev harness, the sibling of `gpu_preview.zig`. The shell state
//! machine here is a stand-in for the real run-loop wiring (slice 3); it lets
//! us iterate on the surface long before the network legs land.

const std = @import("std");
const window_shell = @import("shell/native.zig");
const gpu = @import("shell/gpu.zig");
const layout_core = @import("core/layout.zig"); // InputEvent
const text = @import("core/text.zig");
const raster = @import("core/raster.zig");
const enroll_view = @import("core/enroll_view.zig");
const credential_core = @import("core/credential.zig");
const credential_shell = @import("shell/credential.zig");
const glyph_field = @import("core/glyph_field.zig");
const clock_shell = @import("shell/clock.zig");

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

/// An editable single-line text buffer (one per field). Small, fixed. Sized
/// to hold the longest password (71 bytes for the 9-word tier) for stage B of
/// the confirmation, with slack.
const TextField = struct {
    // A7.2: cold struct (a few single-instance harness fields), size guard waived.
    buf: [80]u8 = undefined,
    len: usize = 0,
    fn slice(self: *const TextField) []const u8 {
        return self.buf[0..self.len];
    }
    fn push(self: *TextField, c: u8) void {
        if (self.len < self.buf.len) {
            self.buf[self.len] = c;
            self.len += 1;
        }
    }
    fn backspace(self: *TextField) void {
        if (self.len > 0) self.len -= 1;
    }
};

/// The mutable shell-side state the pure view is a snapshot of.
const State = struct {
    // A7.2: cold struct (the single harness state instance), size guard waived.
    step: enroll_view.Step = .provenance,
    branch: enroll_view.Branch = .undecided,
    use_email: bool = true,
    age_ok: bool = false, // identity-step consent: 18+
    tos_ok: bool = false, // identity-step consent: Terms + Privacy
    tier: credential_core.Tier = .super_secure,
    saved: bool = false,
    // Recovery-key step (new + no-email). Stand-in for the did:plc rotation key.
    recovery_key: [48]u8 = undefined,
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
    final_handle: [80]u8 = undefined,
    final_handle_len: usize = 0,
    // Transition (A): ease the card height + slide the body in on step change.
    prev_step: enroll_view.Step = .provenance,
    trans_t: f32 = 1.0, // 0 right after a step change → 1 settled
    card_h: f32 = 0.0, // eased card height (0 = not yet initialised)
    info: enroll_view.Info = .none, // which info bubble is open
};

// How long the password "crafting" decode plays (≈1.9 s — long enough to enjoy).
const craft_dur_ns: f32 = 1_900_000_000;

pub fn main(init: std.process.Init) !void {
    const gpa = init.gpa;
    const env = init.environ_map;
    const io = init.io;

    const win = window_shell.open(gpa, env, "zat - join", 150, 52) catch |err| {
        std.debug.print("window.open failed: {s} (on X11, is DISPLAY set?)\n", .{@errorName(err)});
        return;
    };
    defer window_shell.close(win);
    var W: u32 = win.fb.width;
    var H: u32 = win.fb.height;

    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);

    var g = gpu.init(win.wid) catch {
        std.debug.print("GPU init failed — see [gpu] lines above.\n", .{});
        return;
    };
    defer gpu.deinit(&g);
    gpu.setViewport(@intCast(W), @intCast(H));

    var feed_path = gpu.initFeed(gpa) catch return;
    defer gpu.feedDeinit(&feed_path, gpa);
    var field_renderer = gpu.initFieldRenderer(gpa, &engine, cell_w, cell_h) catch return;
    var field_grid = gpu.initFieldGrid() catch return;

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

    var t: f32 = 0;
    var last_step_ns: u64 = 0;
    var mcx: f32 = -1;
    var mcy: f32 = -1;
    const amb_amp: f32 = 0.006; // calmer than the feed (0.010)
    const amb_scale: f32 = 0.055;
    const amb_drift: f32 = 0.08;

    var cur_lx: i32 = -1; // cursor in logical coords (for hover hit-testing)
    var cur_ly: i32 = -1;

    std.debug.print("enrollment harness: click through the flow; type into focused fields; Esc or close to quit.\n", .{});

    while (true) {
        const pr = window_shell.pump(win, 16, gpa, &out, &events) catch break;
        if (pr.closed) break;

        // Resize: refit viewport + field grid.
        if (win.fb.width != W or win.fb.height != H) {
            W = win.fb.width;
            H = win.fb.height;
            gpu.setViewport(@intCast(W), @intCast(H));
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

        // Typed bytes → the focused field (terminal-style key input).
        if (handleText(&state, out.items)) break; // Esc quits
        out.clearRetainingCapacity();

        const scale = uiScale(W);
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

        // Transition (A): on a step change, restart the slide; ease the card
        // height + body offset toward rest every frame.
        if (state.step != state.prev_step or state.confirm_stage != state.prev_confirm_stage) {
            state.trans_t = 0.0;
            state.prev_step = state.step;
            state.prev_confirm_stage = state.confirm_stage; // a confirm sub-stage slide counts too
            state.info = .none; // close any open bubble when the step changes
        }
        state.trans_t += (1.0 - state.trans_t) * 0.22;
        const target_h: f32 = @floatFromInt(if (state.step == .confirm)
            enroll_view.confirmHeight(state.confirm_stage)
        else
            enroll_view.cardHeight(state.step, state.branch));
        state.card_h = if (state.card_h < 1.0) target_h else state.card_h + (target_h - state.card_h) * 0.28;

        // Proof-of-work gate: pow_t eases 0→1 (easeOutCubic so the last bit
        // grinds), holds ~1.5 s on "Verified", then the demo loops to the start.
        if (state.step == .verifying) {
            const el: f32 = @floatFromInt(frame_ns -| state.pow_start_ns);
            const lin = @min(1.0, el / 3_200_000_000.0);
            const inv = 1.0 - lin;
            state.pow_t = 1.0 - inv * inv * inv;
            const prev_seal = state.seal_t;
            state.seal_t = if (lin >= 1.0) @min(1.0, (el - 3_200_000_000.0) / 800_000_000.0) else 0.0;

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
            if (el > 5_200_000_000.0) reset(&state); // welcome beat, then loop
        } else {
            state.pow_t = 0.0;
            state.seal_t = 0.0;
        }

        // Lay out the current state → draw list + hit rects.
        dl.len = 0;
        try enroll_view.layout(gpa, &engine, @intCast(design_w), @intCast(logicalH(W, H)), snapshot(&state), &dl, &hits);

        // Pointer CLICKS (after layout): drive the state machine + a soft ripple.
        for (events.items) |ev| {
            if (ev.kind == .button_down and ev.button == 1) {
                const lx: i32 = @intFromFloat(@as(f32, @floatFromInt(ev.x)) / scale);
                const ly: i32 = @intFromFloat(@as(f32, @floatFromInt(ev.y)) / scale);
                if (enroll_view.hitTest(hits.items, lx, ly)) |target| {
                    apply(&state, target, io, frame_ns);
                    const sx: u32 = @intFromFloat(std.math.clamp(@as(f32, @floatFromInt(ev.x)) / @as(f32, @floatFromInt(cell_w)), 0, @as(f32, @floatFromInt(gcols - 1))));
                    const sy: u32 = @intFromFloat(std.math.clamp(@as(f32, @floatFromInt(ev.y)) / @as(f32, @floatFromInt(cell_h)), 0, @as(f32, @floatFromInt(grows - 1))));
                    splashes.append(gpa, .{ .x = sx, .y = sy, .radius = 3, .amp = 0.6 }) catch {};
                }
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
        gpu.drawFieldGrid(&field_grid, &field_renderer, mcx, mcy, t, @intCast(W), @intCast(H), panel_l, panel_r);
        gpu.feedDraw(&feed_path, @intCast(W), @intCast(H));
        gpu.swap(&g);
    }
}

/// Build the pure snapshot the view renders from the mutable state.
fn snapshot(s: *const State) enroll_view.EnrollView {
    return .{
        .step = s.step,
        .branch = s.branch,
        .handle = s.handle.slice(),
        .username = s.username.slice(),
        .email = s.email.slice(),
        .use_email = s.use_email,
        .age_ok = s.age_ok,
        .tos_ok = s.tos_ok,
        .tier = s.tier,
        .password = if (s.has_pw) s.cred.bytes[0..s.cred.len] else "",
        .saved = s.saved,
        .recovery_key = s.recovery_key[0..s.recovery_len],
        .rec_saved = s.rec_saved,
        .confirm_stage = s.confirm_stage,
        .spot_positions = s.spot_positions,
        .spot = .{ s.spot[0].slice(), s.spot[1].slice(), s.spot[2].slice() },
        .full = s.full.slice(),
        .confirm_error = s.confirm_error,
        .focus = s.focus,
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
        .body_dy = @intFromFloat((1.0 - s.trans_t) * 30.0),
        .info = s.info,
    };
}

/// Route typed bytes into the focused field. Returns true to quit (bare Esc).
fn handleText(s: *State, bytes: []const u8) bool {
    var i: usize = 0;
    while (i < bytes.len) : (i += 1) {
        const b = bytes[i];
        if (b == 0x1b) {
            // Esc alone quits; an escape SEQUENCE (arrows etc.) is skipped.
            if (i + 1 < bytes.len and bytes[i + 1] == '[') {
                i += 2; // skip '[' and the final byte
                continue;
            }
            return true;
        }
        const fld = focusedField(s) orelse continue;
        if (b == 0x7f or b == 0x08) {
            fld.backspace();
        } else if (b >= 0x20 and b < 0x7f) {
            fld.push(b);
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
        .none => null,
    };
}

fn apply(s: *State, target: enroll_view.HitTarget, io: std.Io, now_ns: u64) void {
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
            s.step = .provenance;
            s.branch = .undecided;
            s.focus = .none;
        },
        .primary => switch (s.step) {
            .provenance => {},
            .identity => {
                s.step = .membership;
                s.focus = .none;
            },
            .membership => {
                mint(s, io);
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
            .confirm => confirmSubmit(s, io),
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
        },
        .tier_secure => selectTier(s, .secure, now_ns),
        .tier_super => selectTier(s, .super_secure, now_ns),
        .tier_overkill => selectTier(s, .ultra_secure, now_ns),
        .copy => {}, // no clipboard in the harness
        .reroll => {
            mint(s, io);
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
        .field_handle => s.focus = .handle,
        .field_username => s.focus = .username,
        .field_email => s.focus = .email,
        .field_spot0 => s.focus = .spot0,
        .field_spot1 => s.focus = .spot1,
        .field_spot2 => s.focus = .spot2,
        .field_full => s.focus = .full,
        .regen_password => {
            // Didn't save it → mint a fresh password and go back to copy it.
            mint(s, io);
            s.craft_start_ns = now_ns;
            s.saved = false;
            s.confirm_stage = .spot;
            s.spot = .{ .{}, .{}, .{} };
            s.full = .{};
            s.confirm_error = false;
            s.step = .password;
            s.focus = .none;
        },
        .info_membership => s.info = if (s.info == .membership) .none else .membership,
        .info_password => s.info = if (s.info == .password) .none else .password,
        .deposit => {}, // hover-only (rationale popup); no click action
        .restart => reset(s),
    }
}

/// Pick a tier: mark it chosen and (re)start the strength-bar fill animation.
fn selectTier(s: *State, tier: credential_core.Tier, now_ns: u64) void {
    s.tier = tier;
    s.tier_chosen = true;
    s.bar_sel_ns = now_ns; // restart the fill from 0 → re-springs the bar
}

/// Mint a real password at the chosen tier (the one place randomness enters —
/// shell-side, as the rules require). On failure leave the old one.
fn mint(s: *State, io: std.Io) void {
    if (credential_shell.generate(io, s.tier)) |c| {
        s.cred = c;
        s.has_pw = true;
        // Fresh spot-check positions for this password (per-enrollment random).
        s.spot_positions = pickSpotPositions(io, credential_core.wordCount(s.tier));
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

/// Validate the current confirm stage. Stage A: every spot-check answer must
/// match the word at its position → advance to stage B. Stage B: the full
/// entry must match the whole password (normalized) → finalize. A mismatch
/// raises the inline hint and stays put.
fn confirmSubmit(s: *State, io: std.Io) void {
    if (!s.has_pw) return; // nothing to check against
    const pw = s.cred.bytes[0..s.cred.len];
    if (s.confirm_stage == .spot) {
        var i: usize = 0;
        while (i < 3) : (i += 1) {
            const want = enroll_view.wordAt(pw, s.spot_positions[i]);
            if (!enroll_view.confirmMatch(s.spot[i].slice(), want)) {
                s.confirm_error = true;
                return;
            }
        }
        s.confirm_stage = .full;
        s.confirm_error = false;
        s.focus = .full;
    } else if (enroll_view.confirmMatch(s.full.slice(), pw)) {
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
    } else {
        s.confirm_error = true;
    }
}

/// Generate a representative account recovery key: 16 CSPRNG bytes → grouped
/// uppercase hex ("XXXX-XXXX-…"). In the live app this is the user's `did:plc`
/// ROTATION key (the real atproto recovery primitive); the harness mints a
/// real-looking stand-in so the reveal screen has a secret to show + save.
fn genRecoveryKey(s: *State, io: std.Io) void {
    var raw: [16]u8 = undefined;
    io.randomSecure(&raw) catch {
        s.recovery_len = 0;
        return;
    };
    const hexd = "0123456789ABCDEF";
    var n: usize = 0;
    for (raw, 0..) |b, i| {
        if (i != 0 and i % 2 == 0) {
            s.recovery_key[n] = '-';
            n += 1;
        }
        s.recovery_key[n] = hexd[b >> 4];
        n += 1;
        s.recovery_key[n] = hexd[b & 0x0F];
        n += 1;
    }
    s.recovery_len = n;
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
        put(&s.final_handle, &n, if (s.username.len > 0) s.username.slice() else "you");
        put(&s.final_handle, &n, ".zat4.com");
    } else {
        put(&s.final_handle, &n, if (s.handle.len > 0) s.handle.slice() else "you.bsky.social");
    }
    s.final_handle_len = n;
}

fn reset(s: *State) void {
    if (s.has_pw) credential_shell.wipe(&s.cred);
    s.* = .{};
}
