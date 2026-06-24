// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Zat4 — a social-media client built on the AT Protocol.
// Copyright (C) 2026  Connor Avila

//! THE ENROLLMENT SURFACE — the "Join Zat4" front door. PURE (B1/B2): a
//! plain `EnrollView` snapshot in, a draw list + hit-rects out. Same input ⇒
//! same pixels, every time; no clock, no network, no allocation beyond the
//! per-frame arena (C1/C3). The shell (tui) owns the mutable step state and
//! the I/O (credential mint, PoW, the createAccount XRPC); this module only
//! lays out the calm card over the (detuned) glyph field.
//!
//! Deliberately NOT the feed's material: a single centred card on a quiet
//! field, conventional and trustworthy — onboarding should feel safe, not
//! flashy. It branches by identity PROVENANCE, then converges to one
//! membership ritual (see the flow doc), and it never says "passphrase": the
//! word-joined credential is the user's PASSWORD.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const text = @import("text.zig");
const raster = @import("raster.zig");
const credential = @import("credential.zig");

// ── palette (calm; the app's warm-neutral family, near-opaque card) ──
const ink: u32 = 0xFFEDEAE0;
const body_c: u32 = 0xFFC9C4B8;
const muted: u32 = 0xFF9A968A;
const faint: u32 = 0xFF6A655A;
const card_fill: u32 = 0xF21D1D1F; // ~95% — opaque enough that the field doesn't bleed through copy
const card_edge: u32 = 0x16FFFFFF; // top inner-light hairline
const line_c: u32 = 0x1AEDEAE0; // ~10% ink — dividers / field borders
const field_fill: u32 = 0xFF141416;
/// The onboarding accent. The house amber keeps it unmistakably Zat (pre-lens,
/// so there is no seated-lens accent yet). One token; flip here to retune.
pub const accent: u32 = 0xFFE8B84B;
const accent_soft: u32 = 0x24E8B84B;
const ok_c: u32 = 0xFF6FCF97; // success green (the "you're in" check)
const warn_c: u32 = 0xFFE0705C; // soft warm red — a confirm mismatch hint
const shadow_c: u32 = 0x33000000;

const membership_info =
    "Strength comes from entropy — how unpredictable the password is — not from looking like nonsense. Each word is one of 4,096, picked at random (12 bits). A few such words are millions of times stronger than a short random string, and you can actually remember it. We store only an Argon2id hash, never the password itself.";
const password_info =
    "Every word is drawn from a 4,096-word list by a cryptographic random generator independently, each time. The real words and dashes are just for your eyes. All the strength is in the random picks. Hit Reroll for a different set you like better.";
// PLACEHOLDER legal copy. The real Terms / Privacy Policy land before launch;
// these stand in so the flow, the links, and the consent record are all in
// place now. (ENROLLMENT_BUILD §7: A — consent gate.)
const tos_placeholder =
    "Terms of Service — placeholder. The full terms arrive before launch. In short: be a good neighbour, follow the community rules and acceptable-use policy, and understand the membership-deposit terms. Joining records that you accepted this version.";
const privacy_placeholder =
    "Privacy Policy — placeholder. The full policy arrives before launch. In short: Zat4 stores your DID, a one-way hash of your password, and your Zat4 posts. It never sees your provider password, and your Zat4 content stays in the Zat4 namespace.";

/// Which step of the funnel the surface is showing. `recovery` only appears for
/// a NEW, no-email identity (it reveals the account recovery key) — it sits
/// after `confirm` so the progress dots stay clean and both "save this secret"
/// moments (password, recovery key) sit together.
pub const Step = enum(u8) { provenance, identity, membership, password, confirm, recovery, done, verifying };

/// How the person is coming in (the top-level branch). `undecided` only before
/// step 0 is answered; the identity step renders differently per branch.
pub const Branch = enum(u8) { undecided, existing, new };

/// The currently-focused text field (caret + focus ring). `none` = no field.
pub const Focus = enum(u8) { none, handle, username, email, spot0, spot1, spot2, full };

/// The confirm step runs in two stages: a random spot-check (type a few words
/// at CSPRNG-chosen positions — minor anti-form-fill friction), then a full
/// entry (type the whole password, normalized compare). Both are a human
/// "did you actually save it" gate; the regen link is the escape hatch.
pub const ConfirmStage = enum(u8) { spot, full };

/// Which info bubble is open (toggled by an "i" dot or a legal link). `none` =
/// closed. `tos`/`privacy` are the identity-step consent placeholders.
pub const Info = enum(u8) { none, membership, password, tos, privacy };

/// The pure snapshot the shell hands in each frame. COLD: one instance, never
/// in a hot loop — A7.2 size-guard waiver. Slices point at shell-owned, frame-
/// stable buffers (the editable inputs, the minted password); they never
/// outlive the frame.
pub const EnrollView = struct {
    // A7.2: cold struct (single live instance, config-shaped), size guard waived.
    step: Step = .provenance,
    branch: Branch = .undecided,
    handle: []const u8 = "", // existing-path input
    username: []const u8 = "", // new-path input (before ".zat4.com")
    email: []const u8 = "", // new-path, when use_email
    use_email: bool = true, // new-path: email vs recovery key
    // Consent gate on the identity step (both branches). Both must be true for
    // the step's primary button to enable. The shell records WHICH ToS version
    // + a timestamp at account creation (slice 3) — these bools are just the UI
    // state. (ENROLLMENT_BUILD §7: A.)
    age_ok: bool = false, // "I'm 18 or older"
    tos_ok: bool = false, // "I agree to the Terms and Privacy Policy"
    tier: credential.Tier = .super_secure, // "Super Secure" is the default pick
    password: []const u8 = "", // the minted, word-joined password (display as-is)
    saved: bool = false, // step 3 "I've saved my password" gate
    // Recovery-key step (new + no-email only). The account recovery key — in the
    // live app this is the user's `did:plc` ROTATION key (the real atproto
    // primitive, ~72h override window); here the harness mints a representative
    // CSPRNG key. `rec_saved` is its save-gate. (ENROLLMENT_BUILD §9 B.)
    recovery_key: []const u8 = "",
    rec_saved: bool = false,
    /// "Copied" toast strength 0→1 by the Copy button (shell-driven, fades out).
    copied_t: f32 = 0.0,
    // step 4 confirmation. STAGE A spot-check: three CSPRNG-chosen 1-based word
    // positions and the three typed answers. STAGE B: the whole password typed
    // back. `confirm_error` flips on a failed submit to show the hint.
    confirm_stage: ConfirmStage = .spot,
    spot_positions: [3]u8 = .{ 2, 4, 6 },
    spot: [3][]const u8 = .{ "", "", "" },
    full: []const u8 = "",
    confirm_error: bool = false,
    confirm_checking: bool = false, // Stage B: the real Argon2id verify is in flight (off-thread)
    focus: Focus = .none,
    /// PoW progress 0→1 (the proof ring); the shell drives it from real work.
    /// Slice 1 leaves it static; the ring animation is slice 2.
    pow_t: f32 = 0.0,
    /// The completion seal: 0→1 AFTER pow_t hits 1. A bright line sweeps the
    /// ring closed and snaps shut with a star burst (like the like-heart pop).
    seal_t: f32 = 0.0,
    /// Password "crafting" progress 0→1. <1 ⇒ the words are still resolving
    /// (a left-to-right decode that settles word by word); 1 ⇒ fully shown.
    /// The mint is instant; this is pure theatre, driven by the shell's clock.
    craft_t: f32 = 1.0,
    /// Hover: which control the cursor is over (gated by `hover_on`) and the
    /// eased strength of the lift (0→1). Drawn as a single overlay pass so the
    /// surface feels alive under the cursor — same model as the feed.
    hover: HitTarget = .primary,
    hover_on: bool = false,
    hover_t: f32 = 0.0,
    /// Tier selection is NOT pre-made — you must pick a password length, which
    /// fills the strength bar. `bar_t` (0→1) eases the fill on select; the view
    /// springs it. `bar_phase` is a free-running clock for the Overkill rainbow.
    tier_chosen: bool = false,
    bar_t: f32 = 0.0,
    bar_phase: f32 = 0.0,
    did: []const u8 = "", // done-screen pills
    final_handle: []const u8 = "",
    /// Transition (A): the shell eases the card height between steps (`card_h`,
    /// 0 = use the step's natural height) and slides the step BODY in by
    /// `body_dy` (settles to 0). Pure — just an override + an offset.
    card_h: i32 = 0,
    body_dy: i32 = 0,
    info: Info = .none, // which info bubble is open
};

/// One tap target. HOT (iterated in `hitTest`); guarded (A7). No payload — the
/// target enum alone tells the shell what was hit (the step disambiguates).
pub const HitTarget = enum(u8) {
    choose_existing,
    choose_new,
    back,
    primary, // the step's main action button (Verify / Create / Generate / Continue / Confirm)
    tier_secure,
    tier_super,
    tier_overkill,
    copy,
    reroll,
    toggle_saved,
    toggle_rec_saved, // recovery-key step: "I've saved my recovery key" gate
    toggle_email, // new-path: switch email ⇄ recovery key
    toggle_age, // identity-step consent: "I'm 18 or older"
    toggle_tos, // identity-step consent: agree to Terms + Privacy
    link_tos, // open the Terms placeholder bubble
    link_privacy, // open the Privacy placeholder bubble
    field_handle,
    field_username,
    field_email,
    field_spot0,
    field_spot1,
    field_spot2,
    field_full,
    regen_password, // "didn't save it? get a new one" — back to the password step
    info_membership, // "i" dot → why-this-is-secure bubble
    info_password, // "i" dot → how-it's-generated bubble
    deposit, // hover → the deposit-rationale popup
    restart,
};

pub const Hit = struct {
    x: i16,
    y: i16,
    w: u16,
    h: u16,
    target: HitTarget,
    _pad: u8 = 0, // A6: explicit

    comptime {
        assert(@sizeOf(Hit) == 10); // 2+2+2+2+1+1, exact (A7)
    }
};

pub const HitList = std.ArrayListUnmanaged(Hit);

// Card geometry (logical px; the GPU scales the whole canvas to the window).
const card_w: i32 = 460;
const pad: i32 = 28; // inner padding
const radius: u8 = 16;

/// CORE, PURE. Lay the enrollment card for `view` into `dl`, filling `hits`
/// when non-null. Centres a fixed-width card in (w, h). Returns nothing — the
/// surface owns the whole frame (the field is composed behind it by the shell).
pub fn layout(
    gpa: Allocator,
    e: *const text.Engine,
    w: i32,
    h: i32,
    view: EnrollView,
    dl: *raster.DrawList,
    hits: ?*HitList,
) !void {
    if (hits) |hl| hl.clearRetainingCapacity();

    const card_h = if (view.card_h > 0) view.card_h else cardHeight(view.step, view.branch);
    const cx = @divTrunc(w - card_w, 2);
    const cy = @divTrunc(h - card_h, 2);

    // ── the card: layered soft shadow, fill, top lit edge ──
    try rect(gpa, dl, cx - 2, cy + 14, card_w + 4, card_h, soft(0x000000, 0x18), radius);
    try rect(gpa, dl, cx, cy + 7, card_w, card_h, soft(0x000000, 0x22), radius);
    try rect(gpa, dl, cx, cy, card_w, card_h, card_fill, radius);
    try rect(gpa, dl, cx, cy, card_w, 2, card_edge, radius);

    const ix = cx + pad; // inner left
    const iw = card_w - pad * 2; // inner width
    var y = cy + pad;

    // ── brand row (accent mark + wordmark) ──
    try rect(gpa, dl, ix, y, 26, 26, accent, 7);
    try rect(gpa, dl, ix, y, 26, 2, soft(0xFFFFFF, 0x40), 7); // a lit top edge on the mark
    _ = try str(gpa, dl, e, .semibold, ix + 36, y + 19, ink, 18, "Zat4");
    y += 26 + 18;

    // ── step progress dots (5 bars; on = accent, off = faint) ──
    try stepDots(gpa, dl, ix, y, iw, view.step);
    y += 4 + 22;

    // ── the step body (slides in by body_dy during a transition) ──
    const by = y + view.body_dy;
    switch (view.step) {
        .provenance => try stepProvenance(gpa, dl, e, ix, iw, by, hits),
        .identity => try stepIdentity(gpa, dl, e, ix, iw, by, view, hits),
        .membership => try stepMembership(gpa, dl, e, ix, iw, by, view, hits),
        .password => try stepPassword(gpa, dl, e, ix, iw, by, view, hits),
        .confirm => try stepConfirm(gpa, dl, e, ix, iw, by, view, hits),
        .recovery => try stepRecovery(gpa, dl, e, ix, iw, by, view, hits),
        .done => try stepDone(gpa, dl, e, ix, iw, by, view, hits),
        .verifying => try stepVerifying(gpa, dl, e, ix, iw, by, view),
    }

    // Hover lift: one overlay over whatever control the cursor is on, eased so
    // it fades rather than snaps. Drawn last so it sits over that control.
    if (hits) |hl| {
        if (view.hover_on and view.hover_t > 0.01) {
            const a: u32 = @intFromFloat(@as(f32, 0x16) * view.hover_t);
            for (hl.items) |hh| {
                if (hh.target != view.hover) continue;
                try rect(gpa, dl, hh.x, hh.y, hh.w, hh.h, soft(0xFFFFFF, @intCast(a)), 10);
                break;
            }
        }
    }

    // Info bubble (topmost): toggled by the "i" dots, anchored below the heading.
    if (view.info == .membership and view.step == .membership) {
        try infoBubble(gpa, dl, e, ix, cy + 150, iw, "Why this is secure", membership_info);
    } else if (view.info == .password and view.step == .password) {
        try infoBubble(gpa, dl, e, ix, cy + 150, iw, "How it's generated", password_info);
    } else if (view.info == .tos and view.step == .identity) {
        try infoBubble(gpa, dl, e, ix, cy + 200, iw, "Terms of Service", tos_placeholder);
    } else if (view.info == .privacy and view.step == .identity) {
        try infoBubble(gpa, dl, e, ix, cy + 200, iw, "Privacy Policy", privacy_placeholder);
    }
}

/// Resolve a tap to a target (reverse order: the topmost-pushed wins). PURE.
pub fn hitTest(hits: []const Hit, px: i32, py: i32) ?HitTarget {
    var i: usize = hits.len;
    while (i > 0) {
        i -= 1;
        const r = hits[i];
        if (px >= r.x and px < @as(i32, r.x) + r.w and py >= r.y and py < @as(i32, r.y) + r.h) return r.target;
    }
    return null;
}

/// PURE (B2): the word at 1-based position `pos` in a dash-joined password —
/// the confirm spot-check challenges these. Empty slice if `pos` is 0 or out
/// of range.
pub fn wordAt(password: []const u8, pos: u8) []const u8 {
    if (pos == 0) return "";
    var idx: u8 = 1;
    var start: usize = 0;
    var i: usize = 0;
    while (i <= password.len) : (i += 1) {
        if (i == password.len or password[i] == '-') {
            if (idx == pos) return password[start..i];
            idx += 1;
            start = i + 1;
        }
    }
    return "";
}

/// PURE (B2): the confirmation compare — EXACT, byte for byte. The password is
/// `Word-Word-Word` (Title-Case, dash-joined) and the real login hashes those
/// exact bytes (Argon2id, no normalization), so the confirmation must require
/// the literal form: same case, real dashes — spaces or lowercase are NOT the
/// password and must fail, otherwise we'd teach a form that can't log in. The
/// realistic path is Copy → paste, which reproduces the bytes exactly. An empty
/// input never matches (an untyped field must not pass the gate).
pub fn confirmMatch(typed: []const u8, password: []const u8) bool {
    if (typed.len == 0) return false;
    return std.mem.eql(u8, typed, password);
}

// ───────────────────────────── steps ─────────────────────────────

fn stepProvenance(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, ix: i32, iw: i32, y0: i32, hits: ?*HitList) !void {
    var y = y0;
    _ = try str(gpa, dl, e, .semibold, ix, y + 16, ink, 21, "Join Zat4");
    y += 36;
    y = try wrap(gpa, dl, e, ix, y, iw, muted, 14, "Zat4 is its own space on the AT Protocol. Pick how you're coming in.");
    y += 16;

    y = try choice(gpa, dl, e, ix, iw, y, "I already have an account",
        "You're on the network already. Bring that identity. Your handle stays the same everywhere.", hits, .choose_existing);
    y += 12;
    _ = try choice(gpa, dl, e, ix, iw, y, "I'm new to the network",
        "We'll create your identity and give you a .zat4.com handle, right here.", hits, .choose_new);
}

fn stepIdentity(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, ix: i32, iw: i32, y0: i32, view: EnrollView, hits: ?*HitList) !void {
    var y = y0;
    var label: []const u8 = "Continue";
    if (view.branch == .existing) {
        _ = try str(gpa, dl, e, .semibold, ix, y + 16, ink, 21, "Bring your identity");
        y += 36;
        y = try wrap(gpa, dl, e, ix, y, iw, muted, 14, "Enter your handle. We verify you control it. We never see your password.");
        y += 14;
        y = try field(gpa, dl, e, ix, iw, y, "Your handle", view.handle, "connor.bsky.social", "", view.focus == .handle, hits, .field_handle);
        y += 14;
        y = try note(gpa, dl, e, ix, iw, y, "You'll confirm on your own provider, then come straight back. Zat4 only learns your DID — a scoped, revocable token, never your password.");
        label = "Verify & continue";
    } else {
        _ = try str(gpa, dl, e, .semibold, ix, y + 16, ink, 21, "Create your identity");
        y += 36;
        y = try wrap(gpa, dl, e, ix, y, iw, muted, 14, "Pick a name. This becomes your handle across the whole network.");
        y += 14;
        y = try field(gpa, dl, e, ix, iw, y, "Username", view.username, "connor", ".zat4.com", view.focus == .username, hits, .field_username);
        y += 12;
        // Email OR recovery key — a small two-way toggle. No-email costs more
        // proof-of-work, invisibly; the user only chooses how to recover.
        y = try recoveryToggle(gpa, dl, e, ix, iw, y, view.use_email, hits);
        y += 10;
        if (view.use_email) {
            y = try field(gpa, dl, e, ix, iw, y, "Email", view.email, "you@example.com", "", view.focus == .email, hits, .field_email);
        } else {
            y = try note(gpa, dl, e, ix, iw, y, "No email — so we'll give you a recovery key before you finish. It's the only way back into your account if you forget your password, so keep it somewhere safe.");
        }
        label = "Create & continue";
    }

    // ── consent gate (both branches): age + Terms/Privacy, gates the button ──
    y += 16;
    y = try checkbox(gpa, dl, e, ix, y, "I'm 18 or older", view.age_ok, hits, .toggle_age);
    y += 14;
    y = try consentAgreeRow(gpa, dl, e, ix, y, view.tos_ok, hits);
    y += 20;
    const consent_ok = view.age_ok and view.tos_ok;
    try primaryButton(gpa, dl, e, ix, iw, y, label, consent_ok, hits);
    try ghostButton(gpa, dl, e, ix, iw, y + 52, "Back", hits);
}

fn stepMembership(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, ix: i32, iw: i32, y0: i32, view: EnrollView, hits: ?*HitList) !void {
    var y = y0;
    _ = try str(gpa, dl, e, .semibold, ix, y + 16, ink, 21, "Set up your membership");
    y += 42;
    // Password-generation explainer: a bold sub-heading + an "i" dot (deeper
    // detail in the bubble), then the why-words-not-gibberish pitch.
    const head_x = try str(gpa, dl, e, .semibold, ix, y + 13, ink, 15, "Password generation");
    try infoDot(gpa, dl, e, head_x + 9, y + 1, hits, .info_membership);
    y += 36;
    y = try wrap(gpa, dl, e, ix, y, iw, muted, 13, "We make it for you, from real everyday words. You get the same true randomness, but far easier to remember/input, and stored only as a hash.");
    y += 20;

    // Deposit — waived for now, shown struck-through so it's expected later.
    // Hover it for the rationale (popup drawn at the end, on top).
    const deposit_y = y;
    {
        const bx = ix;
        const bw = iw;
        const bh: i32 = 46;
        try rect(gpa, dl, bx, y, bw, bh, field_fill, 10);
        try rect(gpa, dl, bx, y, bw, bh, line_c, 10);
        _ = try str(gpa, dl, e, .regular, bx + 14, y + 28, body_c, 14, "Membership deposit");
        const price = "$10";
        const px2 = bx + bw - 14 - @as(i32, @intCast(text.measure(e, .semibold, price, 15)));
        _ = try str(gpa, dl, e, .semibold, px2, y + 28, faint, 15, price);
        try line(gpa, dl, px2 - 1, y + 23, px2 + @as(i32, @intCast(text.measure(e, .semibold, price, 15))) + 1, y + 23, muted, 2); // strike-through
        _ = try str(gpa, dl, e, .semibold, px2 - 10 - @as(i32, @intCast(text.measure(e, .semibold, "Waived", 13))), y + 27, ok_c, 13, "Waived");
        try pushHit(hits, gpa, bx, y, bw, bh, .deposit);
        y += bh + 18;
    }

    y += 4;

    // The tier cells: the LABEL is the hero; "N words" the descriptor. The bit
    // count + crack math live in the hover popover, not the cell.
    const gap: i32 = 8;
    const bw = @divTrunc(iw - gap * 2, 3);
    const bh: i32 = 64;
    const row_y = y;
    const Spec = struct { t: credential.Tier, label: []const u8, target: HitTarget };
    const specs = [_]Spec{
        .{ .t = .secure, .label = "Secure", .target = .tier_secure },
        .{ .t = .super_secure, .label = "Super Secure", .target = .tier_super },
        .{ .t = .ultra_secure, .label = "Overkill", .target = .tier_overkill },
    };
    for (specs, 0..) |s, i| {
        const bx = ix + @as(i32, @intCast(i)) * (bw + gap);
        const on = view.tier_chosen and view.tier == s.t;
        try rect(gpa, dl, bx - 1, row_y - 1, bw + 2, bh + 2, if (on) accent else line_c, 11);
        try rect(gpa, dl, bx, row_y, bw, bh, if (on) accent_soft else field_fill, 10);
        // Selected = amber fill, so the text flips to BLACK to stay legible.
        try centerStr(gpa, dl, e, bx, bw, row_y + 30, if (on) 0xFF161616 else body_c, 16, s.label);
        var wb: [12]u8 = undefined;
        const ws = std.fmt.bufPrint(&wb, "{d} words", .{credential.wordCount(s.t)}) catch "words";
        try centerStr(gpa, dl, e, bx, bw, row_y + 48, if (on) soft(0x161616, 0xC8) else muted, 12, ws);
        try pushHit(hits, gpa, bx, row_y, bw, bh, s.target);
    }
    y = row_y + bh + 18;

    // The strength bar — escalates absurdly with the tier (the joke).
    y = try strengthBar(gpa, dl, ix, iw, y, view);
    y += 16;

    // Alongside it: the live crack-time + a grounded strength pill.
    if (view.tier_chosen) {
        const bits = credential.entropyBits(view.tier);
        _ = try str(gpa, dl, e, .regular, ix, y + 11, faint, 11, "ESTIMATED TIME TO CRACK");
        const lvl = levelStr(bits);
        const lw: i32 = @intCast(text.measure(e, .semibold, lvl, 12));
        try rect(gpa, dl, ix + iw - lw - 22, y, lw + 22, 22, accent_soft, 11);
        _ = try str(gpa, dl, e, .semibold, ix + iw - lw - 11, y + 15, accent, 12, lvl);
        var cb: [64]u8 = undefined;
        _ = try str(gpa, dl, e, .semibold, ix, y + 38, ink, 16, crackTime(bits, &cb));
        y += 52;
    } else {
        _ = try str(gpa, dl, e, .regular, ix, y + 12, faint, 13, "Pick a length to see how strong it is.");
        y += 30;
    }
    y += 8;
    try primaryButton(gpa, dl, e, ix, iw, y, "Generate my password", view.tier_chosen, hits);

    // Hover popovers (drawn last → on top): tier entropy details, and the
    // deposit rationale.
    try entropyPopover(gpa, dl, e, view, ix, bw, gap, row_y);
    if (view.hover_on and view.hover == .deposit) {
        try hoverNote(gpa, dl, e, ix, iw, deposit_y + 46 + 8, "A small refundable deposit makes each account cost real money \u{2014} you get it back for good standing after enough time. We do this because it forces bot farm capital to become tied up across thousands and pays again for every burned one. For now, due to the small size of the network, this deposit is waived. If/when it turns on, it's only for new sign-ups. You're in for good.");
    }
}

/// A succinct hover note panel of width `w` at `y` (multi-line, opaque, on top).
fn hoverNote(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, x: i32, w: i32, y: i32, body: []const u8) !void {
    const inner = w - 28;
    const body_end = try wrap(gpa, dl, e, x + 14, y + 22, inner, muted, 13, body); // measure (covered below)
    const h = (body_end - y) + 12;
    try rect(gpa, dl, x, y + 5, w, h, soft(0x000000, 0x2E), 10); // shadow
    try rect(gpa, dl, x, y, w, h, 0xFF26262A, 10); // panel
    try rect(gpa, dl, x, y, w, 2, card_edge, 10);
    _ = try wrap(gpa, dl, e, x + 14, y + 22, inner, body_c, 13, body);
}

fn stepPassword(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, ix: i32, iw: i32, y0: i32, view: EnrollView, hits: ?*HitList) !void {
    var y = y0;
    const hx = try str(gpa, dl, e, .semibold, ix, y + 16, ink, 21, "Here's your password");
    try infoDot(gpa, dl, e, hx + 9, y + 4, hits, .info_password);
    y += 36;
    y = try wrap(gpa, dl, e, ix, y, iw, muted, 14, "We made it for you. Save it now. This is the only time we show it.");
    y += 14;

    // The password in a dashed-accent box — wraps to two lines for long
    // (Overkill) passwords, and DECODES word-by-word while craft_t < 1.
    {
        const pw = if (view.password.len > 0) view.password else "River-Anchor-Velvet-Tide";
        y = try passwordBox(gpa, dl, e, ix, iw, y, pw, view.craft_t);
        y += 10;
    }
    // Keep-it-safe guidance (Copy is the realistic path to a password manager).
    y = try wrapCenter(gpa, dl, e, ix, y + 4, iw, faint, 12, "Save it to your password manager, or write it down and keep it somewhere safe.");
    y += 10;

    // Copy + Reroll, side by side.
    {
        const gap: i32 = 8;
        const bw = @divTrunc(iw - gap, 2);
        try labelButton(gpa, dl, e, ix, bw, y, "Copy", true, hits, .copy);
        try labelButton(gpa, dl, e, ix + bw + gap, bw, y, "Reroll", false, hits, .reroll);
        try copiedToast(gpa, dl, e, ix + @divTrunc(iw, 2), y - 34, view.copied_t);
        y += 44 + 6;
    }

    // "I've saved my password" — the gate.
    y = try checkbox(gpa, dl, e, ix, y, "I've saved my password", view.saved, hits, .toggle_saved);
    y += 18;
    try primaryButton(gpa, dl, e, ix, iw, y, "Continue", view.saved, hits);
}

fn stepConfirm(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, ix: i32, iw: i32, y0: i32, view: EnrollView, hits: ?*HitList) !void {
    var y = y0;
    if (view.confirm_stage == .spot) {
        // STAGE A — spot-check three random word positions (anti-form-fill).
        _ = try str(gpa, dl, e, .semibold, ix, y + 16, ink, 21, "Quick check");
        y += 36;
        y = try wrap(gpa, dl, e, ix, y, iw, muted, 14, "Type these words from the password you just saved. We picked the positions at random.");
        y += 14;
        const focuses = [3]Focus{ .spot0, .spot1, .spot2 };
        const targets = [3]HitTarget{ .field_spot0, .field_spot1, .field_spot2 };
        var i: usize = 0;
        while (i < 3) : (i += 1) {
            var lb: [16]u8 = undefined;
            const label = std.fmt.bufPrint(&lb, "Word {d}", .{view.spot_positions[i]}) catch "Word";
            y = try field(gpa, dl, e, ix, iw, y, label, view.spot[i], "", "", view.focus == focuses[i], hits, targets[i]);
            y += 14;
        }
    } else {
        // STAGE B — type the whole password back (normalized compare; a PM
        // paste with spaces or the dashed form both pass).
        _ = try str(gpa, dl, e, .semibold, ix, y + 16, ink, 21, "Confirm your password");
        y += 36;
        y = try wrap(gpa, dl, e, ix, y, iw, muted, 14, "Now type the whole password, exactly as shown with the dashes. Pasting from your password manager is easiest.");
        y += 14;
        y = try field(gpa, dl, e, ix, iw, y, "Full password", view.full, "Your full password", "", view.focus == .full, hits, .field_full);
        y += 14;
    }
    if (view.confirm_error) {
        y = try wrap(gpa, dl, e, ix, y, iw, warn_c, 13, "That doesn't match. Check the words from the password you saved. Make sure the first letter of each word is capitalized.");
        y += 4;
    }
    y += 6;
    // Stage B disables + relabels the button while the real Argon2id verify runs
    // off-thread (so the UI never freezes and you can't double-submit).
    const checking = view.confirm_stage == .full and view.confirm_checking;
    const blabel = if (view.confirm_stage == .spot) "Continue" else if (checking) "Checking\u{2026}" else "Confirm";
    try primaryButton(gpa, dl, e, ix, iw, y, blabel, !checking, hits);

    // Escape hatch: didn't save the password (so can't reproduce it)? Mint a
    // fresh one and go back a step to copy it again.
    const link = "Didn't save it? Get a new password";
    const link_y = y + 46 + 24;
    const lw: i32 = @intCast(text.measure(e, .regular, link, 13));
    const lx = ix + @divTrunc(iw - lw, 2);
    _ = try str(gpa, dl, e, .regular, lx, link_y, accent, 13, link);
    try pushHit(hits, gpa, lx - 8, link_y - 16, lw + 16, 26, .regen_password);
}

fn stepRecovery(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, ix: i32, iw: i32, y0: i32, view: EnrollView, hits: ?*HitList) !void {
    var y = y0;
    _ = try str(gpa, dl, e, .semibold, ix, y + 16, ink, 21, "Save your recovery key");
    y += 36;
    y = try wrap(gpa, dl, e, ix, y, iw, muted, 14, "You chose no email, so this key is your ONLY way back into your account if you ever lose your password. There's no reset without it.");
    y += 14;

    // The real P-256 private key in an accent-ringed box (ring behind the fill,
    // per the rect()-fills gotcha). Grouped hex, wrapped to two centred lines
    // (it's 64 hex chars). Visually DISTINCT from the word-password so the two
    // secrets don't blur together.
    {
        const bh: i32 = 70;
        try rect(gpa, dl, ix - 1, y - 1, iw + 2, bh + 2, soft(accentRGB(), 0x55), 11);
        try rect(gpa, dl, ix, y, iw, bh, field_fill, 10);
        const key = if (view.recovery_key.len > 0) view.recovery_key else "A1B2 C3D4 E5F6 7890 A1B2 C3D4 E5F6 7890 A1B2 C3D4 E5F6 7890 A1B2 C3D4 E5F6 7890";
        // split at the space nearest the middle → two balanced lines
        var sp = key.len / 2;
        while (sp < key.len and key[sp] != ' ') sp += 1;
        const line1 = key[0..@min(sp, key.len)]; // sp lands on the space → no trailing space
        const line2 = if (sp + 1 < key.len) key[sp + 1 ..] else "";
        if (line2.len == 0) {
            try centerStr(gpa, dl, e, ix, iw, y + 42, ink, 15, line1);
        } else {
            try centerStr(gpa, dl, e, ix, iw, y + 30, ink, 15, line1);
            try centerStr(gpa, dl, e, ix, iw, y + 52, ink, 15, line2);
        }
        y += bh + 12;
    }
    y = try wrapCenter(gpa, dl, e, ix, y, iw, faint, 12, "Tied to your account's recovery (rotation) key. Save it to your password manager or write it down somewhere safe.");
    y += 12;

    try labelButton(gpa, dl, e, ix, iw, y, "Copy recovery key", true, hits, .copy);
    try copiedToast(gpa, dl, e, ix + @divTrunc(iw, 2), y - 34, view.copied_t);
    y += 44 + 8;
    y = try checkbox(gpa, dl, e, ix, y, "I've saved my recovery key", view.rec_saved, hits, .toggle_rec_saved);
    y += 18;
    try primaryButton(gpa, dl, e, ix, iw, y, "Continue", view.rec_saved, hits);
}

fn stepDone(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, ix: i32, iw: i32, y0: i32, view: EnrollView, hits: ?*HitList) !void {
    var y = y0 + 6;
    // a soft check medallion, centred
    const d: i32 = 56;
    const mx = ix + @divTrunc(iw - d, 2);
    try rect(gpa, dl, mx, y, d, d, soft(0x6FCF97, 0x26), @intCast(d / 2));
    try centerStr(gpa, dl, e, ix, iw, y + 38, ok_c, 30, "✓");
    y += d + 18;
    try centerStr(gpa, dl, e, ix, iw, y, ink, 21, "You're in");
    y += 28;
    const sub = if (view.branch == .existing)
        "Your existing identity now has a Zat4 membership."
    else
        "Your new identity and Zat4 membership are ready.";
    y = try wrapCenter(gpa, dl, e, ix, y, iw, muted, 14, sub);
    y += 16;
    // DID + handle pills, centred
    const did = if (view.did.len > 0) view.did else "did:plc:…";
    const hh = if (view.final_handle.len > 0) view.final_handle else "connor.zat4.com";
    try pillRow(gpa, dl, e, ix, iw, y, did, hh);
    y += 34 + 18;
    try primaryButton(gpa, dl, e, ix, iw, y, "Enter Zat4", true, hits);
}

/// THE PROOF-OF-WORK GATE — shown after "Enter Zat4." A clockwise-filling ring
/// of radial ticks (the proof): ticks behind the progress lock bright, the
/// frontier tick churns (the live search), pending ticks sit dim. Driven by
/// `pow_t` (the real proof progress); the churn flickers via `bar_phase`. On
/// completion the centre flips to a check. Pure.
fn stepVerifying(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, ix: i32, iw: i32, y0: i32, view: EnrollView) !void {
    const done = view.pow_t >= 0.999;
    var y = y0 + 4;
    try centerStr(gpa, dl, e, ix, iw, y + 16, ink, 21, if (done) "You're human" else "Verifying you're human");
    y += 36;
    y = try wrapCenter(gpa, dl, e, ix, y, iw, muted, 14, "A quick proof of work — it's what keeps the bots out. One moment.");
    y += 22;

    const cx = ix + @divTrunc(iw, 2);
    const r: i32 = 64;
    const cy = y + r + 8;
    try drawRing(gpa, dl, cx, cy, r, view.pow_t, view.bar_phase);
    if (done) try drawSeal(gpa, dl, cx, cy, r, view.seal_t);

    // Centre readout: live percent + a cycling nonce (the search made visible)
    // → a check on completion.
    if (done) {
        try centerStr(gpa, dl, e, cx - 40, 80, cy + 11, ok_c, 30, "\u{2713}");
    } else {
        var pb: [8]u8 = undefined;
        const ps = std.fmt.bufPrint(&pb, "{d}%", .{@as(u32, @intFromFloat(view.pow_t * 100.0))}) catch "";
        try centerStr(gpa, dl, e, cx - 40, 80, cy - 2, ink, 22, ps);
        var hb: [16]u8 = undefined;
        try centerStr(gpa, dl, e, cx - 50, 100, cy + 18, faint, 11, hexSpin(view.bar_phase, &hb));
    }
    const status = if (done) "Verified — welcome to Zat4." else "Running proof of work\u{2026}";
    try centerStr(gpa, dl, e, ix, iw, cy + r + 30, if (done) ok_c else faint, 13, status);
}

/// A rapidly-cycling 24-bit hex value (a stand-in nonce) derived from the
/// animation clock — pure, but reads as a live search churning.
fn hexSpin(phase: f32, buf: []u8) []const u8 {
    const v: u32 = @intFromFloat(@mod(@abs(phase) * 99991.0, 16777216.0));
    return std.fmt.bufPrint(buf, "0x{X:0>6}", .{v}) catch "0x000000";
}

/// The proof ring: N radial ticks around (cx, cy), filled clockwise from the
/// top by `pow_t`. The leading edge is a COMET — the frontier tick is brightest
/// and longest (churning via `phase`), with a tail that fades back to the steady
/// amber trail; pending ticks sit dim. Done = a full bright bloom.
fn drawRing(gpa: Allocator, dl: *raster.DrawList, cx: i32, cy: i32, r: i32, pow_t: f32, phase: f32) !void {
    const N: i32 = 48;
    const base_out: f32 = @floatFromInt(r);
    const r_in: f32 = base_out - 11.0;
    const cxf: f32 = @floatFromInt(cx);
    const cyf: f32 = @floatFromInt(cy);
    const step: f32 = 1.0 / @as(f32, @floatFromInt(N));
    const done = pow_t >= 0.999;
    var i: i32 = 0;
    while (i < N) : (i += 1) {
        const fi: f32 = @floatFromInt(i);
        const frac = fi * step;
        const ang = -1.5707963 + frac * 6.2831853; // top, clockwise
        const c = @cos(ang);
        const s = @sin(ang);
        var col: u32 = soft(accentRGB(), 0x2C); // pending (dim)
        var th: u8 = 3;
        var ext: f32 = 0; // outward extension (the comet's length)
        if (done) {
            const bloom = 0.5 + 0.5 * @sin(phase * 4.0 + fi * 0.5);
            col = mixToWhite(accent, 0.25 * bloom);
            th = 4;
            ext = 3.0;
        } else if (pow_t >= frac + step) {
            const behind = pow_t - frac; // distance behind the leading edge
            if (behind < 0.12) {
                const k = 1.0 - behind / 0.12; // 1 at the edge → 0 at the tail
                col = mixToWhite(accent, k * 0.85);
                th = 4;
                ext = k * 5.0;
            } else {
                col = accent; // steady trail
            }
        } else if (pow_t >= frac) {
            const fl = 0.6 + 0.4 * @sin(phase * 10.0 + fi * 1.3); // churn
            col = mixToWhite(accent, std.math.clamp(0.7 + 0.3 * fl, 0.0, 1.0));
            th = 5;
            ext = 7.0; // the comet head, longest
        }
        const r_out = base_out + ext;
        try line(gpa, dl, @intFromFloat(cxf + r_in * c), @intFromFloat(cyf + r_in * s), @intFromFloat(cxf + r_out * c), @intFromFloat(cyf + r_out * s), col, th);
    }
}

/// The completion seal: a bright line sweeps clockwise just outside the ring
/// and snaps shut (~seal_t 0.62), at which point a star burst pops from the
/// centre and fades — the satisfying "click," cousin of the like-heart pop.
fn drawSeal(gpa: Allocator, dl: *raster.DrawList, cx: i32, cy: i32, r: i32, seal_t: f32) !void {
    if (seal_t <= 0.001) return;
    const cxf: f32 = @floatFromInt(cx);
    const cyf: f32 = @floatFromInt(cy);
    const outer: f32 = @as(f32, @floatFromInt(r)) + 6.0;
    const close_at: f32 = 0.62;
    const sweep_lin = @min(1.0, seal_t / close_at);
    const sweep = 1.0 - (1.0 - sweep_lin) * (1.0 - sweep_lin); // easeOutQuad

    const N: i32 = 80;
    const stepf: f32 = 1.0 / @as(f32, @floatFromInt(N));
    var i: i32 = 0;
    while (i < N) : (i += 1) {
        const frac = @as(f32, @floatFromInt(i)) * stepf;
        if (frac > sweep) break;
        const ang = -1.5707963 + frac * 6.2831853;
        const c = @cos(ang);
        const s = @sin(ang);
        try line(gpa, dl, @intFromFloat(cxf + (outer - 2.5) * c), @intFromFloat(cyf + (outer - 2.5) * s), @intFromFloat(cxf + (outer + 2.5) * c), @intFromFloat(cyf + (outer + 2.5) * s), mixToWhite(accent, 0.7), 2);
    }

    // The click: a star burst from the centre once the seal closes.
    if (seal_t >= close_at) {
        const ft = std.math.clamp((seal_t - close_at) / (1.0 - close_at), 0.0, 1.0); // 0→1
        const M: i32 = 9;
        var k: i32 = 0;
        while (k < M) : (k += 1) {
            const a = @as(f32, @floatFromInt(k)) * (6.2831853 / @as(f32, @floatFromInt(M))) - 1.5707963;
            const dist = 10.0 + ft * 32.0;
            const sz = 5.0 * (1.0 - ft) + 1.5;
            const al: u8 = @intFromFloat((1.0 - ft) * 255.0);
            try drawStar(gpa, dl, cxf + @cos(a) * dist, cyf + @sin(a) * dist, sz, soft(0xFFFFFF, al));
        }
    }
}

/// A small 8-point sparkle (four lines through a point).
fn drawStar(gpa: Allocator, dl: *raster.DrawList, x: f32, y: f32, s: f32, col: u32) !void {
    const xi: i32 = @intFromFloat(x);
    const yi: i32 = @intFromFloat(y);
    const si: i32 = @intFromFloat(s);
    const di: i32 = @intFromFloat(s * 0.7);
    try line(gpa, dl, xi - si, yi, xi + si, yi, col, 1);
    try line(gpa, dl, xi, yi - si, xi, yi + si, col, 1);
    try line(gpa, dl, xi - di, yi - di, xi + di, yi + di, col, 1);
    try line(gpa, dl, xi - di, yi + di, xi + di, yi - di, col, 1);
}

fn mixToWhite(c: u32, f: f32) u32 {
    const r: f32 = @floatFromInt((c >> 16) & 0xFF);
    const g: f32 = @floatFromInt((c >> 8) & 0xFF);
    const b: f32 = @floatFromInt(c & 0xFF);
    const R: u32 = @intFromFloat(r + (255.0 - r) * f);
    const G: u32 = @intFromFloat(g + (255.0 - g) * f);
    const B: u32 = @intFromFloat(b + (255.0 - b) * f);
    return 0xFF000000 | (R << 16) | (G << 8) | B;
}

// ───────────────────────── component helpers ─────────────────────────

fn stepDots(gpa: Allocator, dl: *raster.DrawList, ix: i32, y: i32, iw: i32, step: Step) !void {
    const n: i32 = 5;
    const gap: i32 = 6;
    const bw = @divTrunc(iw - gap * (n - 1), n);
    const on: i32 = @intFromEnum(step);
    var i: i32 = 0;
    while (i < n) : (i += 1) {
        const c = if (i <= on) accent else line_c;
        try rect(gpa, dl, ix + i * (bw + gap), y, bw, 4, c, 2);
    }
}

fn choice(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, ix: i32, iw: i32, y: i32, title: []const u8, sub: []const u8, hits: ?*HitList, target: HitTarget) !i32 {
    const bh: i32 = 94;
    try rect(gpa, dl, ix, y, iw, bh, soft(0xFFFFFF, 0x05), 12);
    try rect(gpa, dl, ix, y, iw, bh, line_c, 12);
    _ = try str(gpa, dl, e, .semibold, ix + 18, y + 28, ink, 15, title);
    _ = try wrap(gpa, dl, e, ix + 18, y + 50, iw - 36, muted, 13, sub);
    try pushHit(hits, gpa, ix, y, iw, bh, target);
    return y + bh;
}

fn field(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, ix: i32, iw: i32, y: i32, label: []const u8, value: []const u8, placeholder: []const u8, suffix: []const u8, focused: bool, hits: ?*HitList, target: HitTarget) !i32 {
    var yy = y;
    if (label.len > 0) {
        _ = try str(gpa, dl, e, .regular, ix, yy + 12, muted, 13, label);
        yy += 20;
    }
    const fh: i32 = 44;
    // Border = a ring drawn BEHIND the fill (rect() fills, so an opaque accent
    // used "as a border" would flood the field). Focused → 2px accent ring.
    const off: i32 = if (focused) 2 else 1;
    try rect(gpa, dl, ix - off, yy - off, iw + off * 2, fh + off * 2, if (focused) accent else line_c, @intCast(10 + off));
    try rect(gpa, dl, ix, yy, iw, fh, field_fill, 10);
    const show = if (value.len > 0) value else placeholder;
    const col = if (value.len > 0) ink else faint;
    const tx = ix + 14;
    const end = try str(gpa, dl, e, .regular, tx, yy + 28, col, 15, show);
    if (focused) try line(gpa, dl, end + 1, yy + 13, end + 1, yy + 31, accent, 2); // caret
    if (suffix.len > 0) {
        const sw: i32 = @intCast(text.measure(e, .regular, suffix, 15));
        _ = try str(gpa, dl, e, .regular, ix + iw - 14 - sw, yy + 28, muted, 15, suffix);
    }
    try pushHit(hits, gpa, ix, yy, iw, fh, target);
    return yy + fh;
}

fn recoveryToggle(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, ix: i32, iw: i32, y: i32, use_email: bool, hits: ?*HitList) !i32 {
    const h: i32 = 34;
    const gap: i32 = 4;
    const half = @divTrunc(iw - gap, 2);
    try rect(gpa, dl, ix, y, iw, h, field_fill, 9);
    try rect(gpa, dl, ix, y, iw, h, line_c, 9);
    // the selected pill
    const sel_x = if (use_email) ix + 2 else ix + 2 + half;
    try rect(gpa, dl, sel_x, y + 2, half - 2, h - 4, accent_soft, 7);
    try rect(gpa, dl, sel_x, y + 2, half - 2, h - 4, soft(accentRGB(), 0x60), 7);
    try centerStr(gpa, dl, e, ix, half, y + 22, if (use_email) ink else muted, 13, "Use email");
    try centerStr(gpa, dl, e, ix + half + gap, half, y + 22, if (use_email) muted else ink, 13, "Recovery key");
    try pushHit(hits, gpa, ix, y, iw, h, .toggle_email);
    return y + h;
}

/// The strength bar. Calm-but-overflowing by tier — the gag: Secure fills a
/// normal amount, Super Secure overshoots past the cells, Overkill blasts off
/// the screen as a thick pulsing rainbow. The length springs in on select
/// (easeOutBack), then sits; the rainbow shimmers via bar_phase. Runs PAST the
/// card on purpose (the draw list isn't card-clipped); the framebuffer clips.
fn strengthBar(gpa: Allocator, dl: *raster.DrawList, ix: i32, iw: i32, y: i32, view: EnrollView) !i32 {
    const th: i32 = 12;
    try rect(gpa, dl, ix, y, iw, th, soft(0xFFFFFF, 0x0A), 6); // track
    if (!view.tier_chosen) return y + th;
    const factor: f32 = switch (view.tier) {
        .secure => 1.0, // fills the whole track — "already plenty"
        .super_secure => 1.45, // overshoots past the card, not off the page
        .ultra_secure => 7.0, // off the screen entirely
    };
    const len_f = @as(f32, @floatFromInt(iw)) * factor * @max(0.0, easeOutBack(@min(1.0, view.bar_t)));
    const len: i32 = @intFromFloat(len_f);
    if (len <= 0) return y + th;
    if (view.tier == .ultra_secure) {
        const segs: i32 = 72;
        var i: i32 = 0;
        while (i < segs) : (i += 1) {
            const fx = @as(f32, @floatFromInt(i)) / @as(f32, @floatFromInt(segs));
            const hue = @mod(fx * 0.95 + view.bar_phase * 0.12, 1.0);
            const pulse = 0.78 + 0.22 * @sin(view.bar_phase * 3.0 + fx * 8.0);
            const sx0 = ix + @divTrunc(len * i, segs);
            const sx1 = ix + @divTrunc(len * (i + 1), segs);
            try rect(gpa, dl, sx0, y, sx1 - sx0 + 1, th, 0xFF000000 | hsv(hue, 0.9, pulse), 0);
        }
    } else {
        try rect(gpa, dl, ix, y, len, th, accent, 6);
        try rect(gpa, dl, ix + len - 8, y, 10, th, soft(0xFFFFFF, 0x55), 6); // leading glow
    }
    return y + th;
}

/// The entropy popover above the hovered tier cell — the math, on demand.
fn entropyPopover(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, view: EnrollView, ix: i32, bw: i32, gap: i32, row_y: i32) !void {
    if (!view.hover_on) return;
    const idx: usize = switch (view.hover) {
        .tier_secure => 0,
        .tier_super => 1,
        .tier_overkill => 2,
        else => return,
    };
    const t: credential.Tier = switch (idx) {
        0 => .secure,
        1 => .super_secure,
        else => .ultra_secure,
    };
    var b1: [48]u8 = undefined;
    const l1 = std.fmt.bufPrint(&b1, "{d} bits of entropy", .{credential.entropyBits(t)}) catch "entropy";
    var b2: [48]u8 = undefined;
    const l2 = std.fmt.bufPrint(&b2, "{d} words \u{00D7} 12 bits each", .{credential.wordCount(t)}) catch "";
    const w1: i32 = @intCast(text.measure(e, .semibold, l1, 13));
    const w2: i32 = @intCast(text.measure(e, .regular, l2, 12));
    const pw = @max(w1, w2) + 28;
    const ph: i32 = 50;
    const cx = ix + @as(i32, @intCast(idx)) * (bw + gap) + @divTrunc(bw, 2);
    const px = cx - @divTrunc(pw, 2);
    const py = row_y - ph - 10;
    try rect(gpa, dl, px, py + 4, pw, ph, soft(0x000000, 0x24), 10); // shadow
    try rect(gpa, dl, px, py, pw, ph, 0xFF26262A, 10); // panel (floats above)
    try rect(gpa, dl, px, py, pw, 2, card_edge, 10);
    try centerStr(gpa, dl, e, px, pw, py + 22, ink, 13, l1);
    try centerStr(gpa, dl, e, px, pw, py + 39, muted, 12, l2);
}

/// Estimated time to crack: the EXACT keyspace ÷ (rate × seconds/year), shown
/// as the full comma-grouped figure (the big unclean number reads cooler — and
/// it's honest: ~1e6 guesses/sec is conservative against our Argon2id store).
/// Exact u128 integer math; the answer fits u64 even at 108 bits. Pure.
fn crackTime(bits: u16, buf: []u8) []const u8 {
    const divisor: u128 = 1_000_000 * 31_557_600; // guesses/sec × seconds/year
    const years: u128 = (@as(u128, 1) << @intCast(bits)) / divisor;
    return groupedYears(years, buf);
}

/// Write `n` with thousands separators, suffixed " years", into buf.
fn groupedYears(n: u128, buf: []u8) []const u8 {
    var rev: [40]u8 = undefined;
    var len: usize = 0;
    var v = n;
    if (v == 0) {
        rev[0] = '0';
        len = 1;
    }
    while (v > 0) : (v /= 10) {
        rev[len] = '0' + @as(u8, @intCast(v % 10));
        len += 1;
    }
    var bi: usize = 0;
    var p: usize = 0;
    while (p < len and bi < buf.len) : (p += 1) {
        if (p > 0 and (len - p) % 3 == 0 and bi < buf.len) {
            buf[bi] = ',';
            bi += 1;
        }
        if (bi < buf.len) {
            buf[bi] = rev[len - 1 - p];
            bi += 1;
        }
    }
    for (" years") |ch| {
        if (bi < buf.len) {
            buf[bi] = ch;
            bi += 1;
        }
    }
    return buf[0..bi];
}

/// The strength pill — the institutional password-entropy tier our level maps
/// to (grounded in NIST/industry research: ~50-65 bits = a strong consumer
/// password, ~70-85 bits = enterprise/high-assurance policy, ~100+ bits past
/// the memorable ceiling). 72→enterprise, 84→government; top stays bonkers.
fn levelStr(bits: u16) []const u8 {
    return switch (bits) {
        72 => "Enterprise-grade",
        84 => "Government-grade",
        else => "Cosmic",
    };
}

/// HSV→RGB (h,s,v in [0,1]) → 0xRRGGBB. For the Overkill rainbow.
fn hsv(h: f32, s: f32, v: f32) u32 {
    const ii = @floor(h * 6.0);
    const f = h * 6.0 - ii;
    const p = v * (1.0 - s);
    const q = v * (1.0 - f * s);
    const w = v * (1.0 - (1.0 - f) * s);
    var r: f32 = 0;
    var g: f32 = 0;
    var b: f32 = 0;
    switch (@as(u32, @intFromFloat(ii)) % 6) {
        0 => {
            r = v;
            g = w;
            b = p;
        },
        1 => {
            r = q;
            g = v;
            b = p;
        },
        2 => {
            r = p;
            g = v;
            b = w;
        },
        3 => {
            r = p;
            g = q;
            b = v;
        },
        4 => {
            r = w;
            g = p;
            b = v;
        },
        else => {
            r = v;
            g = p;
            b = q;
        },
    }
    const R: u32 = @intFromFloat(std.math.clamp(r, 0, 1) * 255.0);
    const G: u32 = @intFromFloat(std.math.clamp(g, 0, 1) * 255.0);
    const B: u32 = @intFromFloat(std.math.clamp(b, 0, 1) * 255.0);
    return (R << 16) | (G << 8) | B;
}

fn easeOutBack(t: f32) f32 {
    const c1: f32 = 1.70158;
    const c3: f32 = c1 + 1.0;
    const u = t - 1.0;
    return 1.0 + c3 * u * u * u + c1 * u * u;
}

fn checkbox(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, ix: i32, y: i32, label: []const u8, on: bool, hits: ?*HitList, target: HitTarget) !i32 {
    const s: i32 = 18;
    try rect(gpa, dl, ix, y, s, s, if (on) accent else field_fill, 5);
    try rect(gpa, dl, ix, y, s, s, if (on) accent else line_c, 5);
    if (on) {
        // a small check (two strokes)
        try line(gpa, dl, ix + 4, y + 9, ix + 8, y + 13, 0xFF1A1A1A, 2);
        try line(gpa, dl, ix + 8, y + 13, ix + 14, y + 5, 0xFF1A1A1A, 2);
    }
    _ = try str(gpa, dl, e, .regular, ix + s + 10, y + 14, body_c, 14, label);
    const lw: i32 = @intCast(text.measure(e, .regular, label, 14));
    try pushHit(hits, gpa, ix - 4, y - 5, s + 18 + lw, s + 10, target);
    return y + s;
}

/// The Terms/Privacy consent row: a checkbox (toggles `.toggle_tos`) with an
/// inline label whose "Terms" and "Privacy Policy" are tappable accent links
/// (`.link_tos` / `.link_privacy` — open the placeholder bubbles). The checkbox
/// hit covers the box + leading text only, so the links stay independently
/// tappable. Mirrors `checkbox`'s geometry.
fn consentAgreeRow(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, ix: i32, y: i32, on: bool, hits: ?*HitList) !i32 {
    const s: i32 = 18;
    try rect(gpa, dl, ix, y, s, s, if (on) accent else field_fill, 5);
    try rect(gpa, dl, ix, y, s, s, if (on) accent else line_c, 5);
    if (on) {
        try line(gpa, dl, ix + 4, y + 9, ix + 8, y + 13, 0xFF1A1A1A, 2);
        try line(gpa, dl, ix + 8, y + 13, ix + 14, y + 5, 0xFF1A1A1A, 2);
    }
    const ty = y + 14;
    var x = ix + s + 10;
    x = try str(gpa, dl, e, .regular, x, ty, body_c, 14, "I agree to the ");
    const t0 = x; // box + leading text toggles the checkbox
    try pushHit(hits, gpa, ix - 4, y - 5, (t0 - ix) + 4, s + 10, .toggle_tos);
    x = try str(gpa, dl, e, .regular, x, ty, accent, 14, "Terms");
    try pushHit(hits, gpa, t0, y - 4, x - t0, s + 8, .link_tos);
    x = try str(gpa, dl, e, .regular, x, ty, body_c, 14, " and ");
    const p0 = x;
    x = try str(gpa, dl, e, .regular, x, ty, accent, 14, "Privacy Policy");
    try pushHit(hits, gpa, p0, y - 4, x - p0, s + 8, .link_privacy);
    return y + s;
}

/// A small "✓ Copied" pill, centred on `cx`, sitting at `y` — pops above the
/// Copy button after a successful clipboard copy and fades (shell drives `t`).
fn copiedToast(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, cx: i32, y: i32, t: f32) !void {
    if (t <= 0.01) return;
    const label = "\u{2713} Copied";
    const tw: i32 = @intCast(text.measure(e, .semibold, label, 13));
    const pw = tw + 26;
    const px = cx - @divTrunc(pw, 2);
    const fa: u8 = @intFromFloat(@min(255.0, 235.0 * t));
    try rect(gpa, dl, px, y, pw, 28, soft(accentRGB(), fa), 14);
    const ta: u32 = @intFromFloat(@min(255.0, 255.0 * t));
    try centerStr(gpa, dl, e, px, pw, y + 19, (ta << 24) | 0x1A1A1A, 13, label);
}

fn primaryButton(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, ix: i32, iw: i32, y: i32, label: []const u8, enabled: bool, hits: ?*HitList) !void {
    const bh: i32 = 46;
    const fill = if (enabled) accent else soft(accentRGB(), 0x55);
    try rect(gpa, dl, ix, y, iw, bh, fill, 10);
    if (enabled) try rect(gpa, dl, ix, y, iw, 2, soft(0xFFFFFF, 0x33), 10);
    const tcol: u32 = if (enabled) 0xFF1A1A1A else soft(0x000000, 0x80);
    try centerStr(gpa, dl, e, ix, iw, y + 29, tcol, 15, label);
    if (enabled) try pushHit(hits, gpa, ix, y, iw, bh, .primary);
}

fn ghostButton(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, ix: i32, iw: i32, y: i32, label: []const u8, hits: ?*HitList) !void {
    const bh: i32 = 44;
    try rect(gpa, dl, ix, y, iw, bh, line_c, 10);
    try centerStr(gpa, dl, e, ix, iw, y + 28, muted, 14, label);
    try pushHit(hits, gpa, ix, y, iw, bh, .back);
}

fn labelButton(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, ix: i32, iw: i32, y: i32, label: []const u8, filled: bool, hits: ?*HitList, target: HitTarget) !void {
    const bh: i32 = 44;
    if (filled) {
        try rect(gpa, dl, ix, y, iw, bh, accent, 10);
        try centerStr(gpa, dl, e, ix, iw, y + 28, 0xFF1A1A1A, 14, label);
    } else {
        try rect(gpa, dl, ix, y, iw, bh, line_c, 10);
        try centerStr(gpa, dl, e, ix, iw, y + 28, body_c, 14, label);
    }
    try pushHit(hits, gpa, ix, y, iw, bh, target);
}

fn note(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, ix: i32, iw: i32, y: i32, body: []const u8) !i32 {
    const top = y;
    const inner = iw - 26;
    const ytext = try wrap(gpa, dl, e, ix + 13, y + 16, inner, muted, 13, body);
    const h = (ytext - y) + 14;
    try rect(gpa, dl, ix, top, iw, h, field_fill, 10);
    try rect(gpa, dl, ix, top, iw, h, line_c, 10);
    // re-draw the text over the box (the box was appended after, so it covers it)
    _ = try wrap(gpa, dl, e, ix + 13, top + 16, inner, muted, 13, body);
    return top + h;
}

fn pillRow(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, ix: i32, iw: i32, y: i32, a: []const u8, b: []const u8) !void {
    const h: i32 = 30;
    const aw: i32 = @as(i32, @intCast(text.measure(e, .regular, a, 13))) + 24;
    const bw: i32 = @as(i32, @intCast(text.measure(e, .regular, b, 13))) + 24;
    const gap: i32 = 8;
    const total = aw + gap + bw;
    var x = ix + @divTrunc(iw - total, 2);
    try rect(gpa, dl, x, y, aw, h, field_fill, 15);
    try rect(gpa, dl, x, y, aw, h, line_c, 15);
    _ = try str(gpa, dl, e, .regular, x + 12, y + 20, muted, 13, a);
    x += aw + gap;
    try rect(gpa, dl, x, y, bw, h, field_fill, 15);
    try rect(gpa, dl, x, y, bw, h, line_c, 15);
    _ = try str(gpa, dl, e, .regular, x + 12, y + 20, ink, 13, b);
}

/// The password box: a dashed-accent panel holding the word-joined password,
/// packed into 1–2 centred lines (so the 9-word Overkill tier fits), with a
/// left-to-right DECODE while `craft_t` < 1 — each word resolves from a scramble
/// to its real letters in turn, so the password reads as being "crafted." Pure:
/// the scramble is derived only from craft_t + the word index. Returns the y
/// after the box.
fn passwordBox(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, ix: i32, iw: i32, y: i32, password: []const u8, craft_t: f32) !i32 {
    const box_h: i32 = 84;
    const inset: i32 = 16;
    const px: u16 = 18;
    const maxw: i32 = iw - inset * 2;
    try rect(gpa, dl, ix, y, iw, box_h, accent_soft, 12);
    try dashedRect(gpa, dl, ix, y, iw, box_h, accent, 12);

    // split into words (Overkill = 9; cap generously)
    var words: [12][]const u8 = undefined;
    var nw: usize = 0;
    var it = std.mem.splitScalar(u8, password, '-');
    while (it.next()) |wd| {
        if (nw < words.len) {
            words[nw] = wd;
            nw += 1;
        }
    }
    if (nw == 0) return y + box_h;

    const dash_w: i32 = @intCast(text.measure(e, .semibold, "-", px));
    // greedy line-pack by REAL word widths (≤ 3 lines, always ≥1 word/line)
    var ls: [3]usize = undefined;
    var le: [3]usize = undefined;
    var nlines: usize = 0;
    var i: usize = 0;
    while (i < nw and nlines < ls.len) {
        var acc: i32 = 0;
        var j = i;
        while (j < nw) : (j += 1) {
            const ww: i32 = @intCast(text.measure(e, .semibold, words[j], px));
            const add = ww + (if (j > i) dash_w else 0);
            if (j > i and acc + add > maxw) break;
            acc += add;
        }
        if (j == i) j = i + 1;
        ls[nlines] = i;
        le[nlines] = j;
        nlines += 1;
        i = j;
    }

    const lh: i32 = 26;
    const total_h: i32 = @as(i32, @intCast(nlines)) * lh;
    var ly = y + @divTrunc(box_h - total_h, 2) + 18; // first baseline
    const fnw: f32 = @floatFromInt(nw);
    var tmp: [40]u8 = undefined;

    var li: usize = 0;
    while (li < nlines) : (li += 1) {
        // line width (real), centred
        var lw: i32 = 0;
        var w = ls[li];
        while (w < le[li]) : (w += 1) {
            lw += @intCast(text.measure(e, .semibold, words[w], px));
            if (w > ls[li]) lw += dash_w;
        }
        var x = ix + @divTrunc(iw - lw, 2);
        w = ls[li];
        while (w < le[li]) : (w += 1) {
            if (w > ls[li]) {
                // Dashes are part of the literal password — make them notable
                // (amber), so the structure reads and is easy to reproduce.
                _ = try str(gpa, dl, e, .semibold, x, ly, soft(accentRGB(), 0xDD), px, "-");
                x += dash_w;
            }
            const ww: i32 = @intCast(text.measure(e, .semibold, words[w], px));
            const lock = @as(f32, @floatFromInt(w + 1)) / fnw;
            const start = @as(f32, @floatFromInt(w)) / fnw;
            if (craft_t >= lock) {
                _ = try str(gpa, dl, e, .semibold, x, ly, ink, px, words[w]); // settled (already Title-Case)
            } else if (craft_t >= start) {
                _ = try str(gpa, dl, e, .semibold, x, ly, accent, px, scramble(words[w], craft_t, w, &tmp)); // resolving
            } else {
                _ = try str(gpa, dl, e, .regular, x, ly, faint, px, scramble(words[w], craft_t, w, &tmp)); // pending
            }
            x += ww;
        }
        ly += lh;
    }
    return y + box_h;
}

/// A same-length letter scramble for a word, derived purely from craft_t (so it
/// flickers as the clock advances) and the word index. First letter upper-case
/// to match the Title-Case real word — keeps the width ≈ stable as it resolves.
fn scramble(word: []const u8, craft_t: f32, k: usize, buf: *[40]u8) []const u8 {
    const n = @min(word.len, buf.len);
    const phase: u32 = @intFromFloat(craft_t * 150.0); // calmer shuffle over the (longer) decode
    var p: usize = 0;
    while (p < n) : (p += 1) {
        const h = (@as(u32, @intCast(k)) *% 2654435761) +% (@as(u32, @intCast(p)) *% 40503) +% (phase *% 2246822519);
        buf[p] = (if (p == 0) @as(u8, 'A') else @as(u8, 'a')) + @as(u8, @intCast(h % 26));
    }
    return buf[0..n];
}

/// A small "i" info dot (toggles a bubble). Soft amber disc + amber "i".
fn infoDot(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, x: i32, y: i32, hits: ?*HitList, target: HitTarget) !void {
    const d: i32 = 16;
    try rect(gpa, dl, x, y, d, d, soft(accentRGB(), 0x26), @intCast(@divTrunc(d, 2)));
    try centerStr(gpa, dl, e, x, d, y + 12, accent, 12, "i");
    try pushHit(hits, gpa, x - 3, y - 3, d + 6, d + 6, target);
}

/// A floating info bubble: a title + wrapped body in an opaque panel. Drawn on
/// top of the card (toggled by an info dot). Height sized to the body (drawn
/// once under the panel, then over it — the note() trick).
fn infoBubble(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, x: i32, y: i32, w: i32, title: []const u8, body: []const u8) !void {
    const inner = w - 28;
    const body_top = y + 44;
    const body_end = try wrap(gpa, dl, e, x + 14, body_top, inner, muted, 13, body); // measure pass (covered below)
    const h = (body_end - y) + 12;
    try rect(gpa, dl, x, y + 5, w, h, soft(0x000000, 0x2E), 12); // shadow
    try rect(gpa, dl, x, y, w, h, 0xFF26262A, 12); // panel
    try rect(gpa, dl, x, y, w, 2, card_edge, 12);
    _ = try str(gpa, dl, e, .semibold, x + 14, y + 26, ink, 14, title);
    _ = try wrap(gpa, dl, e, x + 14, body_top, inner, body_c, 13, body);
}

// ───────────────────────── primitive helpers ─────────────────────────

pub fn cardHeight(step: Step, branch: Branch) i32 {
    return switch (step) {
        .provenance => 402,
        .identity => if (branch == .existing) 558 else 582, // +consent gate
        .membership => 582,
        .password => 466,
        .confirm => confirmHeight(.spot), // fallback (card_h==0): the taller stage
        .recovery => 484,
        .done => 380,
        .verifying => 402,
    };
}

/// The confirm card's height per sub-stage. Stage A stacks three spot-check
/// fields (tall); stage B is one full-password field (short). The shell eases
/// `card_h` toward this so the card grows/shrinks between the two stages.
pub fn confirmHeight(stage: ConfirmStage) i32 {
    return switch (stage) {
        .spot => 560,
        .full => 432,
    };
}

fn accentRGB() u32 {
    return accent & 0x00FFFFFF;
}

fn soft(rgb: u32, a: u8) u32 {
    return (@as(u32, a) << 24) | (rgb & 0x00FFFFFF);
}

fn fxi(v: f32) i32 {
    return @intFromFloat(@round(v));
}

fn rect(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, w: i32, h: i32, color: u32, rad: u8) !void {
    try dl.append(gpa, .{ .rect = .{ .x = @intCast(x), .y = @intCast(y), .w = @intCast(@max(0, w)), .h = @intCast(@max(0, h)), .color = color, .radius = rad } });
}

fn line(gpa: Allocator, dl: *raster.DrawList, x0: i32, y0: i32, x1: i32, y1: i32, color: u32, th: u8) !void {
    try dl.append(gpa, .{ .line = .{ .x0 = @intCast(x0), .y0 = @intCast(y0), .x1 = @intCast(x1), .y1 = @intCast(y1), .color = color, .thickness = th } });
}

/// Four dashed edges of a rounded-ish rect (the password box outline).
fn dashedRect(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, w: i32, h: i32, color: u32, rad: u8) !void {
    _ = rad;
    const dash: i32 = 7;
    const gap: i32 = 5;
    var px = x + 6;
    while (px < x + w - 6) : (px += dash + gap) {
        try line(gpa, dl, px, y, @min(px + dash, x + w - 6), y, color, 1);
        try line(gpa, dl, px, y + h, @min(px + dash, x + w - 6), y + h, color, 1);
    }
    var py = y + 6;
    while (py < y + h - 6) : (py += dash + gap) {
        try line(gpa, dl, x, py, x, @min(py + dash, y + h - 6), color, 1);
        try line(gpa, dl, x + w, py, x + w, @min(py + dash, y + h - 6), color, 1);
    }
}

fn str(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, weight: text.Weight, x0: i32, baseline: i32, color: u32, px: u16, s: []const u8) !i32 {
    var x = x0;
    var it = (std.unicode.Utf8View.init(s) catch return x).iterator();
    while (it.nextCodepoint()) |cp| {
        try dl.append(gpa, .{ .text = .{ .x = @intCast(x), .baseline = @intCast(baseline), .codepoint = cp, .color = color, .px = px, .weight = @intFromEnum(weight) } });
        x += @as(i32, @intCast(text.advance(e, weight, cp, px)));
    }
    return x;
}

fn centerStr(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, ix: i32, iw: i32, baseline: i32, color: u32, px: u16, s: []const u8) !void {
    const sw: i32 = @intCast(text.measure(e, .semibold, s, px));
    _ = try str(gpa, dl, e, .semibold, ix + @divTrunc(iw - sw, 2), baseline, color, px, s);
}

/// Word-wrap `s` into `iw`, drawing left-aligned. Returns the baseline after
/// the last line. Line height ≈ px * 1.6 (roomy — the premium spacing pass).
fn wrap(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, ix: i32, y0: i32, iw: i32, color: u32, px: u16, s: []const u8) !i32 {
    const lh: i32 = fxi(@as(f32, @floatFromInt(px)) * 1.6);
    var y = y0;
    var it = std.mem.splitScalar(u8, s, ' ');
    var linebuf: [256]u8 = undefined;
    var ll: usize = 0;
    while (it.next()) |word| {
        const tentative_len = if (ll == 0) word.len else ll + 1 + word.len;
        if (tentative_len <= linebuf.len) {
            const candidate = if (ll == 0) blk: {
                @memcpy(linebuf[0..word.len], word);
                break :blk linebuf[0..word.len];
            } else blk: {
                linebuf[ll] = ' ';
                @memcpy(linebuf[ll + 1 .. ll + 1 + word.len], word);
                break :blk linebuf[0 .. ll + 1 + word.len];
            };
            if (@as(i32, @intCast(text.measure(e, .regular, candidate, px))) <= iw) {
                ll = candidate.len;
                continue;
            }
        }
        // overflow: flush current line, start a new one with `word`
        if (ll > 0) {
            _ = try str(gpa, dl, e, .regular, ix, y, color, px, linebuf[0..ll]);
            y += lh;
        }
        @memcpy(linebuf[0..word.len], word);
        ll = word.len;
    }
    if (ll > 0) {
        _ = try str(gpa, dl, e, .regular, ix, y, color, px, linebuf[0..ll]);
        y += lh;
    }
    return y;
}

/// Centred word-wrap (the done-screen subtitle).
fn wrapCenter(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, ix: i32, y0: i32, iw: i32, color: u32, px: u16, s: []const u8) !i32 {
    const lh: i32 = fxi(@as(f32, @floatFromInt(px)) * 1.6);
    var y = y0;
    var it = std.mem.splitScalar(u8, s, ' ');
    var linebuf: [256]u8 = undefined;
    var ll: usize = 0;
    while (it.next()) |word| {
        const candidate_len = if (ll == 0) word.len else ll + 1 + word.len;
        if (candidate_len <= linebuf.len) {
            var tmp: [256]u8 = undefined;
            const cand = if (ll == 0) blk: {
                @memcpy(tmp[0..word.len], word);
                break :blk tmp[0..word.len];
            } else blk: {
                @memcpy(tmp[0..ll], linebuf[0..ll]);
                tmp[ll] = ' ';
                @memcpy(tmp[ll + 1 .. ll + 1 + word.len], word);
                break :blk tmp[0 .. ll + 1 + word.len];
            };
            if (@as(i32, @intCast(text.measure(e, .regular, cand, px))) <= iw) {
                @memcpy(linebuf[0..cand.len], cand);
                ll = cand.len;
                continue;
            }
        }
        if (ll > 0) {
            const sw: i32 = @intCast(text.measure(e, .regular, linebuf[0..ll], px));
            _ = try str(gpa, dl, e, .regular, ix + @divTrunc(iw - sw, 2), y, color, px, linebuf[0..ll]);
            y += lh;
        }
        @memcpy(linebuf[0..word.len], word);
        ll = word.len;
    }
    if (ll > 0) {
        const sw: i32 = @intCast(text.measure(e, .regular, linebuf[0..ll], px));
        _ = try str(gpa, dl, e, .regular, ix + @divTrunc(iw - sw, 2), y, color, px, linebuf[0..ll]);
        y += lh;
    }
    return y;
}

fn pushHit(hits: ?*HitList, gpa: Allocator, x: i32, y: i32, w: i32, h: i32, target: HitTarget) !void {
    if (hits) |hl| try hl.append(gpa, .{ .x = @intCast(x), .y = @intCast(y), .w = @intCast(@max(0, w)), .h = @intCast(@max(0, h)), .target = target });
}

test "hitTest resolves the provenance choices" {
    const gpa = std.testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);
    var hits: HitList = .empty;
    defer hits.deinit(gpa);

    try layout(gpa, &engine, 1280, 880, .{ .step = .provenance }, &dl, &hits);
    // both choices must be hittable
    var saw_existing = false;
    var saw_new = false;
    for (hits.items) |hh| {
        if (hh.target == .choose_existing) saw_existing = true;
        if (hh.target == .choose_new) saw_new = true;
    }
    try std.testing.expect(saw_existing and saw_new);
}

test "password step gates Continue on saved" {
    const gpa = std.testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);
    var hits: HitList = .empty;
    defer hits.deinit(gpa);

    // unsaved → no .primary hit (Continue disabled)
    try layout(gpa, &engine, 1280, 880, .{ .step = .password, .saved = false, .password = "River-Anchor-Velvet-Tide" }, &dl, &hits);
    for (hits.items) |hh| try std.testing.expect(hh.target != .primary);

    // saved → Continue becomes hittable
    hits.clearRetainingCapacity();
    dl.len = 0;
    try layout(gpa, &engine, 1280, 880, .{ .step = .password, .saved = true, .password = "River-Anchor-Velvet-Tide" }, &dl, &hits);
    var saw_primary = false;
    for (hits.items) |hh| {
        if (hh.target == .primary) saw_primary = true;
    }
    try std.testing.expect(saw_primary);
}

test "recovery step gates Continue on rec_saved" {
    const gpa = std.testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);
    var hits: HitList = .empty;
    defer hits.deinit(gpa);

    const key = "8F2A-1C9B-44D7-E013-A6B5-2F8C-90D1-7E4A";
    // not saved → no primary; the save-gate is hittable
    try layout(gpa, &engine, 1280, 880, .{ .step = .recovery, .branch = .new, .use_email = false, .recovery_key = key, .rec_saved = false }, &dl, &hits);
    var saw_primary = false;
    var saw_gate = false;
    for (hits.items) |hh| {
        if (hh.target == .primary) saw_primary = true;
        if (hh.target == .toggle_rec_saved) saw_gate = true;
    }
    try std.testing.expect(!saw_primary and saw_gate);

    // saved → Continue becomes hittable
    hits.clearRetainingCapacity();
    dl.len = 0;
    try layout(gpa, &engine, 1280, 880, .{ .step = .recovery, .branch = .new, .use_email = false, .recovery_key = key, .rec_saved = true }, &dl, &hits);
    saw_primary = false;
    for (hits.items) |hh| {
        if (hh.target == .primary) saw_primary = true;
    }
    try std.testing.expect(saw_primary);
}

test "identity step gates the primary on age + consent" {
    const gpa = std.testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);
    var hits: HitList = .empty;
    defer hits.deinit(gpa);

    const hasPrimary = struct {
        fn f(hl: HitList) bool {
            for (hl.items) |hh| if (hh.target == .primary) return true;
            return false;
        }
    }.f;

    // Neither box checked → no primary hit (button disabled).
    try layout(gpa, &engine, 1280, 880, .{ .step = .identity, .branch = .new, .age_ok = false, .tos_ok = false }, &dl, &hits);
    try std.testing.expect(!hasPrimary(hits));

    // Only one checked → still disabled.
    hits.clearRetainingCapacity();
    dl.len = 0;
    try layout(gpa, &engine, 1280, 880, .{ .step = .identity, .branch = .new, .age_ok = true, .tos_ok = false }, &dl, &hits);
    try std.testing.expect(!hasPrimary(hits));

    // Both checked → primary is hittable; the legal links are always present.
    hits.clearRetainingCapacity();
    dl.len = 0;
    try layout(gpa, &engine, 1280, 880, .{ .step = .identity, .branch = .new, .age_ok = true, .tos_ok = true }, &dl, &hits);
    var saw_tos = false;
    var saw_privacy = false;
    for (hits.items) |hh| {
        if (hh.target == .link_tos) saw_tos = true;
        if (hh.target == .link_privacy) saw_privacy = true;
    }
    try std.testing.expect(hasPrimary(hits));
    try std.testing.expect(saw_tos and saw_privacy);
}

test "wordAt extracts 1-based dash-joined words" {
    const pw = "River-Anchor-Velvet-Tide";
    try std.testing.expectEqualStrings("River", wordAt(pw, 1));
    try std.testing.expectEqualStrings("Anchor", wordAt(pw, 2));
    try std.testing.expectEqualStrings("Tide", wordAt(pw, 4));
    try std.testing.expectEqualStrings("", wordAt(pw, 0)); // out of range
    try std.testing.expectEqualStrings("", wordAt(pw, 5)); // past the end
}

test "confirmMatch is exact: the literal password only" {
    const pw = "River-Anchor-Velvet-Tide";
    try std.testing.expect(confirmMatch(pw, pw)); // exact bytes (a paste)
    try std.testing.expect(confirmMatch("Anchor", wordAt(pw, 2))); // single spot word, exact
    // The password has dashes and is case-sensitive — these are NOT it.
    try std.testing.expect(!confirmMatch("river anchor velvet tide", pw)); // spaces + lowercase
    try std.testing.expect(!confirmMatch("river-anchor-velvet-tide", pw)); // lowercase
    try std.testing.expect(!confirmMatch("River Anchor Velvet Tide", pw)); // spaces not dashes
    try std.testing.expect(!confirmMatch("anchor", wordAt(pw, 2))); // wrong case
    try std.testing.expect(!confirmMatch("Anvil", wordAt(pw, 2))); // wrong word
    try std.testing.expect(!confirmMatch("", pw)); // empty never matches
}

test "confirm step: spot stage shows three positioned fields, full stage one" {
    const gpa = std.testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);
    var hits: HitList = .empty;
    defer hits.deinit(gpa);

    // Stage A: the three spot-check fields are present, the full field is not.
    try layout(gpa, &engine, 1280, 880, .{
        .step = .confirm,
        .confirm_stage = .spot,
        .spot_positions = .{ 1, 3, 5 },
    }, &dl, &hits);
    var spots: usize = 0;
    var saw_full = false;
    for (hits.items) |hh| {
        if (hh.target == .field_spot0 or hh.target == .field_spot1 or hh.target == .field_spot2) spots += 1;
        if (hh.target == .field_full) saw_full = true;
    }
    try std.testing.expectEqual(@as(usize, 3), spots);
    try std.testing.expect(!saw_full);

    // Stage B: one full-password field, no spot fields.
    hits.clearRetainingCapacity();
    dl.len = 0;
    try layout(gpa, &engine, 1280, 880, .{ .step = .confirm, .confirm_stage = .full }, &dl, &hits);
    spots = 0;
    saw_full = false;
    for (hits.items) |hh| {
        if (hh.target == .field_spot0 or hh.target == .field_spot1 or hh.target == .field_spot2) spots += 1;
        if (hh.target == .field_full) saw_full = true;
    }
    try std.testing.expectEqual(@as(usize, 0), spots);
    try std.testing.expect(saw_full);
}
