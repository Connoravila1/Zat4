//! The Settings SCHEMA — the whole settings tree as one flat table of plain
//! data (A1/A3). This file is the thing you edit to rearrange settings: a row
//! is a struct literal, a section is a struct literal, and reordering either is
//! reordering lines in an array. Nothing here draws — the renderer
//! (`feed_view.drawSettings`) walks these arrays and paints them, so a new
//! toggle, a moved row, or a regrouped card never touches draw code.
//!
//! The model is iOS-shaped: a small set of top-level SECTIONS, each opening a
//! DETAIL pane of grouped ROWS. Rows within a section share a `group` index so
//! consecutive same-group rows render as one rounded card (the grouped-list
//! look). Two levels only — no row drills into a third level.
//!
//! PURE (B1/B2): static `comptime` tables, no I/O, no clock, no allocation. The
//! shell owns "which section is selected" and "what a tap does"; this file only
//! describes the tree.

const std = @import("std");
const assert = std.debug.assert;

/// The closed set of row archetypes. Every settings row is one of these — a
/// small vocabulary keeps every screen built from the same bricks (the reason
/// iOS settings stay navigable). Behaviour for each lives in a free function in
/// the shell that switches on `Row.kind` + `Row.action`; rows carry no methods.
pub const RowKind = enum(u8) {
    /// Label + chevron; navigates deeper (for now, inert scaffold).
    disclosure,
    /// Label + on/off pill. The Toy Box's staple.
    toggle,
    /// Label + current value on the right + chevron; opens a picker (later).
    choice,
    /// A tappable command (Sign out, Clear cache). May be destructive (red).
    action,
    /// Read-only label + value (Version, your handle).
    info,
    /// Label + a range track (later; field intensity, text size).
    slider,
};

/// Section identity. The list order in `sections` is the on-screen order; these
/// constants are what a `Row.section` points at, so moving a section in the
/// array does NOT require renumbering rows.
// INVARIANT: each constant's value is that section's POSITION in `sections`
// below (the renderer uses the array index as the section id). To reorder a
// section, move its line in BOTH this block and `sections` together; rows need
// no edit (they reference these names). Toy Box sits second by request.
pub const sec_account: u8 = 0;
pub const sec_toybox: u8 = 1;
pub const sec_appearance: u8 = 2;
pub const sec_feed: u8 = 3;
pub const sec_notifications: u8 = 4;
pub const sec_privacy: u8 = 5;
pub const sec_about: u8 = 6;

/// A leading icon for a section row, kept as a small tag the renderer maps to a
/// line-art drawer (so the schema stays free of draw concerns).
pub const Icon = enum(u8) { account, appearance, feed, notifications, privacy, toybox, about };

/// An action tag a row carries, switched on by the shell when the row is tapped.
/// `none` is the inert skeleton default; `sign_out` routes to the existing
/// sign-out handler so that one wired control keeps working through the new
/// table. New live actions append here as the app grows.
pub const act_none: u8 = 0;
pub const act_sign_out: u8 = 1;
/// Toy Box: "Julia mode" — forces the whole UI pink (accent, field glyphs +
/// glow, and the socket colour swatches, so no colour but pink can be chosen).
/// The shell reads this row's toggle bit and substitutes pink at the colour
/// sources. A live effect, not just a display toggle.
pub const act_julia: u8 = 2;
// Functional toggles — the shell reads each row's bit (via `rowOf`) into a flag
// and gates the matching behaviour, the same pattern as Julia mode.
pub const act_ripples: u8 = 3; // Toy Box: the field ripple + red dye on a like
pub const act_crt: u8 = 4; // Toy Box: CRT scanline overlay
pub const act_frametiming: u8 = 5; // Toy Box: fps/frame-time overlay
pub const act_field: u8 = 6; // Appearance: the living glyph field on/off
// Account info rows whose value is the REAL session identity (not the table's
// placeholder); the renderer substitutes the live value for these.
pub const act_show_handle: u8 = 7;
pub const act_show_did: u8 = 8;
pub const act_show_pds: u8 = 9;
// CHOICE rows wired to a live knob (open a picker; selection drives the effect).
pub const act_accent: u8 = 10; // Appearance: the UI accent colour
pub const act_field_intensity: u8 = 11; // Appearance: the field's brightness (uGain)
pub const act_depth: u8 = 12; // Toy Box: Depth feed — posts loom/recede by engagement
pub const act_tectonic: u8 = 13; // Toy Box: Tectonic timeline — horizontal filmstrip feed
pub const act_gravity: u8 = 14; // Toy Box: Gravity — posts fall and pile at the bottom

/// Optional one-line explainer shown as a HOVER TOOLTIP over a row — opt-in per
/// action, empty for the rest. Kept out of band (a switch, not a `Row` field) so
/// `Row` stays 40 bytes and only the handful of rows that want a tooltip carry
/// the text (A6 spirit: sparse data off the hot/cold table). Comptime .rodata.
pub fn helpText(action: u8) []const u8 {
    return switch (action) {
        act_depth => "Posts scale by engagement — the liveliest posts loom nearest while quiet ones recede. Purely cosmetic; changes nothing about the feed itself.",
        act_tectonic => "The feed becomes a horizontal filmstrip — posts lay out left to right as cards, and scrolling pans sideways through them. Purely cosmetic.",
        act_gravity => "Posts get weight and fall — they drop and pile up at the bottom of the feed, with the most-liked posts falling hardest. Purely cosmetic.",
        else => "",
    };
}

/// The GLOBAL row index of the (first) row carrying `action`, or null. Lets the
/// shell map a functional `act_*` to its runtime toggle bit without hardcoding
/// an index (so rows can be rearranged freely). Linear scan over a tiny table.
pub fn rowOf(action: u8) ?u6 {
    for (rows, 0..) |r, i| if (r.action == action) return @intCast(i);
    return null;
}

/// A CHOICE row's options + default selection, looked up by the row's action.
/// The shell owns the live selected index; the picker renders these. A7.2: cold
/// config — a handful, comptime-constant, never in a hot loop.
pub const Choice = struct {
    action: u8,
    default: u8, // default selected option index
    options: []const []const u8,
};

/// The choices wired to a live effect (option index → a knob in the shell). Each
/// `choice` ROW must carry the matching `action`. ≤ 8 options each (packed 3 bits
/// per choice in the shell's selection word).
pub const choices = [_]Choice{
    .{ .action = act_accent, .default = 0, .options = &.{ "Auto", "Amber", "Blue", "Green", "Violet", "Rose", "Teal" } },
    .{ .action = act_field_intensity, .default = 1, .options = &.{ "Subtle", "Normal", "Vivid" } },
};

/// The Choice for `action`, or null if it isn't a wired choice.
pub fn choiceOf(action: u8) ?*const Choice {
    for (&choices) |*c| if (c.action == action) return c;
    return null;
}

/// The position of `action` within `choices` (its slot in the packed selection
/// word), or null.
pub fn choiceIndex(action: u8) ?u8 {
    for (choices, 0..) |c, i| if (c.action == action) return @intCast(i);
    return null;
}

comptime {
    // The shell packs each choice's selected index into 3 bits (act_* word), so a
    // choice may have at most 8 options, and the table at most 21 choices (63 bits).
    assert(choices.len <= 21);
    for (choices) |c| assert(c.options.len <= 8);
}

/// Row flag bits (A6: sparse booleans packed into one byte, not bloating the
/// struct with `bool` fields).
pub const flag_destructive: u8 = 1 << 0; // render the label in the warning red
pub const flag_on: u8 = 1 << 1; // a toggle's displayed state (skeleton: static)
pub const flag_wip: u8 = 1 << 2; // not yet implemented — rendered dimmed + a "Soon"
//                                  tag, and non-interactive (no tap region). Clear
//                                  the flag when the row's behaviour is wired.

/// One section: a leading icon + a label. Cold-ish (seven of them) but drawn in
/// the per-frame section-list loop, so treat as hot and guard (A7).
pub const Section = struct {
    icon: Icon,
    label: []const u8,

    comptime {
        // 16 (slice) + 1 (icon) → 24 with alignment padding. The label is a
        // comptime literal in .rodata (zero-alloc); a handful of these.
        assert(@sizeOf(Section) == 24);
    }
};

/// One row in the settings tree. Plain data (A1): the tags say WHAT it is, the
/// shell decides what a tap DOES. Rides the per-section render loop → guarded.
pub const Row = struct {
    section: u8, // which section owns it — regrouping = change this one number
    group: u8, // group index within the section (the grouped-card boundary)
    kind: RowKind,
    action: u8, // act_* — switched on at tap time; act_none = inert
    flags: u8, // flag_* bits
    label: []const u8, // left-hand text (comptime literal, zero-alloc)
    value: []const u8, // right-hand value for choice/info; "" otherwise

    comptime {
        // 2 slices (2×16=32) + 5 single-byte tags = 37 → 40 with alignment.
        // Both slices point at comptime .rodata, so there is no per-row alloc;
        // this is a small static table walked once per settings frame.
        assert(@sizeOf(Row) == 40);
    }
};

/// The top-level sections, in display order. Reorder these lines to reorder the
/// left-hand list — the row table is unaffected (rows point at `sec_*`).
pub const sections = [_]Section{
    .{ .icon = .account, .label = "Account" },
    .{ .icon = .toybox, .label = "Toy Box" },
    .{ .icon = .appearance, .label = "Appearance" },
    .{ .icon = .feed, .label = "Feed & Content" },
    .{ .icon = .notifications, .label = "Notifications" },
    .{ .icon = .privacy, .label = "Privacy & Safety" },
    .{ .icon = .about, .label = "About" },
};

/// The whole settings tree, top to bottom. To rearrange: move a line. To regroup
/// a row into a different card: change its `.group`. To move it to another
/// section: change its `.section`. To add a Toy Box toggle: drop one `.toggle`
/// line with `.section = sec_toybox`. The renderer follows this array verbatim.
///
/// Skeleton note: every row except Sign out is inert — `.action = act_none`,
/// toggles display a static state, choices show a placeholder value. This is the
/// navigable shell; the actions get wired one slice at a time later.
pub const rows = [_]Row{
    // ── Account ──────────────────────────────────────────────────────────
    .{ .section = sec_account, .group = 0, .kind = .info, .action = act_show_handle, .flags = 0, .label = "Handle", .value = "@you.zat4.com" },
    .{ .section = sec_account, .group = 0, .kind = .info, .action = act_show_did, .flags = 0, .label = "DID", .value = "did:plc:…" },
    .{ .section = sec_account, .group = 0, .kind = .disclosure, .action = act_none, .flags = flag_wip, .label = "Edit profile", .value = "" },
    .{ .section = sec_account, .group = 1, .kind = .info, .action = act_show_pds, .flags = 0, .label = "Home server (PDS)", .value = "pds.zat4.com" },
    .{ .section = sec_account, .group = 1, .kind = .disclosure, .action = act_none, .flags = flag_wip, .label = "App passwords", .value = "" },
    .{ .section = sec_account, .group = 2, .kind = .action, .action = act_sign_out, .flags = flag_destructive, .label = "Sign out", .value = "" },

    // ── Appearance ───────────────────────────────────────────────────────
    .{ .section = sec_appearance, .group = 0, .kind = .choice, .action = act_none, .flags = flag_wip, .label = "Theme", .value = "Dark" },
    .{ .section = sec_appearance, .group = 0, .kind = .choice, .action = act_accent, .flags = 0, .label = "Accent", .value = "Auto" },
    .{ .section = sec_appearance, .group = 0, .kind = .choice, .action = act_none, .flags = flag_wip, .label = "Text size", .value = "Medium" },
    .{ .section = sec_appearance, .group = 1, .kind = .toggle, .action = act_field, .flags = flag_on, .label = "Living glyph field", .value = "" },
    .{ .section = sec_appearance, .group = 1, .kind = .choice, .action = act_field_intensity, .flags = 0, .label = "Field intensity", .value = "Normal" },
    .{ .section = sec_appearance, .group = 1, .kind = .choice, .action = act_none, .flags = flag_wip, .label = "Density", .value = "Cozy" },

    // ── Feed & Content ───────────────────────────────────────────────────
    .{ .section = sec_feed, .group = 0, .kind = .choice, .action = act_none, .flags = flag_wip, .label = "Default feed", .value = "Following" },
    .{ .section = sec_feed, .group = 0, .kind = .toggle, .action = act_none, .flags = flag_wip, .label = "Show reposts", .value = "" },
    .{ .section = sec_feed, .group = 0, .kind = .toggle, .action = act_none, .flags = flag_wip, .label = "Autoplay media", .value = "" },
    .{ .section = sec_feed, .group = 1, .kind = .disclosure, .action = act_none, .flags = flag_wip, .label = "Muted words", .value = "" },
    .{ .section = sec_feed, .group = 1, .kind = .disclosure, .action = act_none, .flags = flag_wip, .label = "Muted zones", .value = "" },
    .{ .section = sec_feed, .group = 1, .kind = .choice, .action = act_none, .flags = flag_wip, .label = "Sensitive content", .value = "Warn" },

    // ── Notifications ────────────────────────────────────────────────────
    .{ .section = sec_notifications, .group = 0, .kind = .toggle, .action = act_none, .flags = flag_wip, .label = "Likes", .value = "" },
    .{ .section = sec_notifications, .group = 0, .kind = .toggle, .action = act_none, .flags = flag_wip, .label = "Replies", .value = "" },
    .{ .section = sec_notifications, .group = 0, .kind = .toggle, .action = act_none, .flags = flag_wip, .label = "Reposts", .value = "" },
    .{ .section = sec_notifications, .group = 0, .kind = .toggle, .action = act_none, .flags = flag_wip, .label = "New followers", .value = "" },
    .{ .section = sec_notifications, .group = 1, .kind = .toggle, .action = act_none, .flags = flag_wip, .label = "Zone activity", .value = "" },

    // ── Privacy & Safety ─────────────────────────────────────────────────
    .{ .section = sec_privacy, .group = 0, .kind = .choice, .action = act_none, .flags = flag_wip, .label = "Who can reply", .value = "Everyone" },
    .{ .section = sec_privacy, .group = 0, .kind = .toggle, .action = act_none, .flags = flag_wip, .label = "Discoverable", .value = "" },
    .{ .section = sec_privacy, .group = 1, .kind = .disclosure, .action = act_none, .flags = flag_wip, .label = "Blocked accounts", .value = "" },
    .{ .section = sec_privacy, .group = 1, .kind = .disclosure, .action = act_none, .flags = flag_wip, .label = "Muted accounts", .value = "" },
    .{ .section = sec_privacy, .group = 2, .kind = .toggle, .action = act_none, .flags = flag_wip, .label = "Privacy labels on lenses", .value = "" },

    // ── Toy Box ──────────────────────────────────────────────────────────
    // Your playground. Append experimental toggles here freely — clearly fenced
    // off from the polished sections so a half-baked switch never lands in
    // Account by accident.
    .{ .section = sec_toybox, .group = 0, .kind = .toggle, .action = act_julia, .flags = 0, .label = "Julia mode", .value = "" },
    .{ .section = sec_toybox, .group = 0, .kind = .toggle, .action = act_ripples, .flags = flag_on, .label = "Ripples on like", .value = "" },
    .{ .section = sec_toybox, .group = 1, .kind = .toggle, .action = act_crt, .flags = 0, .label = "CRT scanlines", .value = "" },
    .{ .section = sec_toybox, .group = 1, .kind = .toggle, .action = act_frametiming, .flags = 0, .label = "Show frame timing", .value = "" },
    // Feed-layout toys (they resolve each post's on-screen position). Depth is the
    // FIRST, so a single toggle is honest. F4: when the 2nd layout toy (tectonic)
    // lands, convert these into ONE exclusive selection — two can't co-own layout.
    .{ .section = sec_toybox, .group = 2, .kind = .toggle, .action = act_depth, .flags = 0, .label = "Depth feed", .value = "" },
    .{ .section = sec_toybox, .group = 2, .kind = .toggle, .action = act_tectonic, .flags = 0, .label = "Tectonic timeline", .value = "" },
    .{ .section = sec_toybox, .group = 2, .kind = .toggle, .action = act_gravity, .flags = 0, .label = "Gravity", .value = "" },

    // ── About ────────────────────────────────────────────────────────────
    .{ .section = sec_about, .group = 0, .kind = .info, .action = act_none, .flags = 0, .label = "Version", .value = "0.1.0-dev" },
    .{ .section = sec_about, .group = 0, .kind = .info, .action = act_none, .flags = 0, .label = "Build", .value = "main" },
    .{ .section = sec_about, .group = 1, .kind = .disclosure, .action = act_none, .flags = flag_wip, .label = "Open-source licenses", .value = "" },
    .{ .section = sec_about, .group = 1, .kind = .disclosure, .action = act_none, .flags = flag_wip, .label = "Acknowledgements", .value = "" },
};

comptime {
    // The shell tracks each toggle's runtime on/off in a `u64` bitset indexed by
    // GLOBAL row index (see tui.zig `toggle_bits`). Keep the table within 64 rows
    // until that store is widened, or a toggle past index 63 would silently lose
    // its state. Raising this means widening the bitset, not bumping the number.
    assert(rows.len <= 64);
}

test "every row points at a real section" {
    for (rows) |r| {
        try std.testing.expect(r.section < sections.len);
    }
}

test "every section has at least one row" {
    for (0..sections.len) |s| {
        var found = false;
        for (rows) |r| {
            if (r.section == s) {
                found = true;
                break;
            }
        }
        try std.testing.expect(found);
    }
}

test "groups within a section are contiguous (no interleaving)" {
    // The renderer draws a new card each time (section, group) changes, so a
    // group must not reappear after a different group of the same section —
    // otherwise one logical group would split into two cards. This guards the
    // table against an accidental mis-ordering when rows get rearranged.
    for (0..sections.len) |s| {
        var seen = [_]bool{false} ** 256;
        var prev_group: i32 = -1;
        for (rows) |r| {
            if (r.section != s) continue;
            if (r.group != prev_group) {
                try std.testing.expect(!seen[r.group]); // group not seen before
                seen[r.group] = true;
                prev_group = r.group;
            }
        }
    }
}
