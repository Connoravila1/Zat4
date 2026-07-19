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

/// The product flavor, read at COMPTIME (the same way core reads `builtin`) so
/// the flavor-specific defaults below fold out entirely in the other build.
/// B4 note: this is a build-time identity, not I/O — the module stays pure.
const chat_app = @import("dist_config").product == .chat;
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
    /// Label + an editable one-line TEXT field (the pet's name). Tapping focuses
    /// it; the shell routes keystrokes into a buffer and hands the live value back.
    textfield,
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

/// Does this SECTION exist in this product? "Feed & Content" is a timeline
/// concept, and the messenger has no timeline.
pub fn sectionInProduct(section: u8) bool {
    if (!chat_app) return true;
    return section != sec_feed;
}

/// Does this ROW exist in this product? Zat4 is the full client, so everything
/// shows there and this folds to `true`.
///
/// The distinction the owner drew (2026-07-18) is between toys that RE-THEME the
/// app and toys that RE-LAYOUT the feed. The pet, Julia mode, the CRT overlay and
/// the XP skin all dress the whole app and carry over to the messenger happily.
/// The feed-motion toys do not: Depth looms posts by engagement, Tectonic makes
/// the timeline a filmstrip, Zero-G and Liquid drift and slosh it, Gravity piles
/// it up. With no timeline these are not "off" in Zat Chat — they are meaningless,
/// and a settings row that cannot do anything is worse than an absent one.
pub fn rowInProduct(r: Row) bool {
    if (!chat_app) return true;
    if (!sectionInProduct(r.section)) return false;
    return (r.flags & flag_zat4_only) == 0;
}

/// Rows that DO NOTHING on the phone (the glyph field is compiled off
/// mobile for battery, and the like-ripple rides it): the phone's list
/// hides them; desktop keeps them. Pure table logic, used by the renderer.
pub fn rowOnPhone(r: Row) bool {
    return switch (r.action) {
        act_field, act_field_intensity, act_ripples => false,
        else => true,
    };
}
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
pub const act_pet: u8 = 15; // Toy Box: Pet — a companion in the corner
pub const act_pet_color: u8 = 16; // Toy Box: Pet colour (choice)
pub const act_pet_size: u8 = 17; // Toy Box: Pet size (choice)
pub const act_pet_name: u8 = 18; // Toy Box: Pet name (text field)
pub const act_xp: u8 = 19; // Toy Box: XP skin — a retro-OS desktop frame over the app
pub const act_zero_g: u8 = 20; // Toy Box: Zero-G — posts drift weightlessly
pub const act_liquid: u8 = 21; // Toy Box: Liquid — posts slosh with scroll inertia
pub const act_light: u8 = 22; // Appearance: light mode — the whole app on a light canvas
pub const act_zat_kbd: u8 = 23; // Input: the Zat4 keyboard (phone) — in-app keys, no system IME
pub const act_kbd_pulses: u8 = 24; // Keyboard: the circuit-lattice glints
pub const act_kbd_haptic: u8 = 25; // Keyboard: a soft tick per keystroke
pub const act_kbd_pop: u8 = 26; // Keyboard: the key-preview pop above the finger
pub const act_kbd_lm: u8 = 27; // Keyboard: smart tap targeting (the letter-trigram prior)
// MESSAGING privacy. These two are NOT ordinary settings bits: their authoritative
// state lives in the chat session (`gchat_receipts` / `gchat_typing_on`, persisted
// with the chat history), and until now the ONLY way to reach them was the consent
// screen shown once during chat onboarding — so a person who chose in a hurry could
// never change their mind. The Settings rows mirror that state; they do not own it.
pub const act_chat_receipts: u8 = 28; // send read receipts
pub const act_chat_typing: u8 = 29; // send typing indicators
pub const act_chat_disappearing: u8 = 30; // disappearing messages (M3 — not built yet)

/// Optional one-line explainer shown as a HOVER TOOLTIP over a row — opt-in per
/// action, empty for the rest. Kept out of band (a switch, not a `Row` field) so
/// `Row` stays 40 bytes and only the handful of rows that want a tooltip carry
/// the text (A6 spirit: sparse data off the hot/cold table). Comptime .rodata.
pub fn helpText(action: u8) []const u8 {
    return switch (action) {
        act_depth => "Posts scale by engagement — the liveliest posts loom nearest while quiet ones recede. Purely cosmetic; changes nothing about the feed itself.",
        act_tectonic => "The feed becomes a horizontal filmstrip — posts lay out left to right as cards, and scrolling pans sideways through them. Purely cosmetic.",
        act_gravity => "Posts get weight and fall — they drop and pile up at the bottom of the feed, with the most-liked posts falling hardest. Purely cosmetic.",
        act_pet => "A little companion lives in the corner. It gets hungry and sleepy over time, sulks if you doom-scroll, and cheers up when you click to pet it.",
        act_xp => "Wraps the app in a retro-desktop frame — a gradient title bar up top, a beveled window edge, and a taskbar with a Start button and a live clock along the bottom. Purely cosmetic chrome.",
        act_zero_g => "Cuts the gravity — posts drift weightlessly, each floating on its own slow path. Purely cosmetic; the feed order and scroll are untouched.",
        act_liquid => "The feed behaves like water — scrolling sends a slosh rippling down the column that sways and then settles. Purely cosmetic.",
        else => "",
    };
}

/// The Toy Box category title for a group index (the detail pane draws these as
/// section headers over each tile grid). Empty for an unknown group. Comptime
/// .rodata; the display ORDER is the group numbering in the row table above.
pub fn toyCategoryTitle(group: u8) []const u8 {
    return switch (group) {
        0 => "Effects",
        1 => "Companion",
        2 => "Theme",
        3 => "Feed motion",
        else => "",
    };
}

/// The Toy Box "feed motion" category — its toys are mutually exclusive (only one
/// owns the feed), so the detail pane renders them as a pick-one card grid rather
/// than independent switches. Kept as data here so the renderer stays generic.
pub const toy_motion_group: u8 = 3;

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

/// One entry in the UI accent palette: the name the picker shows and the colour
/// it means, as ONE table.
///
/// These used to be two parallel lists — the option STRINGS here and a colour
/// switch in the shell — agreeing only by index, with nothing enforcing it.
/// Filtering an option out for one product would have silently shifted every
/// colour after it. Both now derive from this, so they cannot drift.
///
/// A7.2: cold config — a handful of comptime rows, read when the picker opens.
pub const AccentOption = struct {
    label: []const u8,
    /// null = "Auto": follow the seated lens.
    color: ?u32,
};

/// PRODUCT-SPLIT. In Zat4 the accent follows the seated feed-socket lens, so
/// "Auto" leads and is the default. Zat Chat has no feed and no socket to
/// follow, so the accent is simply a choice — "Auto" would name a mechanism
/// that does not exist there — and it defaults to Blue, the messenger's colour
/// (owner, 2026-07-18).
pub const accent_options = if (chat_app) [_]AccentOption{
    .{ .label = "Blue", .color = 0xFF4A9EFF },
    .{ .label = "Amber", .color = 0xFFF2762A },
    .{ .label = "Green", .color = 0xFF3FC97E },
    .{ .label = "Violet", .color = 0xFF9B7BFF },
    .{ .label = "Rose", .color = 0xFFFF5C8A },
    .{ .label = "Teal", .color = 0xFF33C2C2 },
} else [_]AccentOption{
    .{ .label = "Auto", .color = null },
    .{ .label = "Amber", .color = 0xFFF2762A }, // feed_view.accent_house
    .{ .label = "Blue", .color = 0xFF4A9EFF },
    .{ .label = "Green", .color = 0xFF3FC97E },
    .{ .label = "Violet", .color = 0xFF9B7BFF },
    .{ .label = "Rose", .color = 0xFFFF5C8A },
    .{ .label = "Teal", .color = 0xFF33C2C2 },
};

/// The accent picker's option labels, derived from the palette above so the two
/// can never disagree.
const accent_labels = blk: {
    var l: [accent_options.len][]const u8 = undefined;
    for (accent_options, 0..) |o, i| l[i] = o.label;
    break :blk l;
};

/// The colour an accent option index means, or null for "Auto" (follow the
/// lens). Out of range is treated as Auto — a stale persisted index from an
/// older option list must not index off the end.
pub fn accentColor(opt: u8) ?u32 {
    if (opt >= accent_options.len) return null;
    return accent_options[opt].color;
}

/// The choices wired to a live effect (option index → a knob in the shell). Each
/// `choice` ROW must carry the matching `action`. ≤ 8 options each (packed 3 bits
/// per choice in the shell's selection word).
pub const choices = [_]Choice{
    .{ .action = act_accent, .default = 0, .options = &accent_labels },
    .{ .action = act_field_intensity, .default = 1, .options = &.{ "Subtle", "Normal", "Vivid" } },
    .{ .action = act_pet_color, .default = 0, .options = &.{ "Blue", "Mint", "Rose", "Amber", "Violet", "Grey" } },
    .{ .action = act_pet_size, .default = 1, .options = &.{ "Small", "Medium", "Large" } },
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
/// This row belongs to ZAT4 ONLY — it governs something the standalone Zat Chat
/// build has no surface for. Carried as a table BIT rather than switched on by
/// action, because several placeholder rows share `act_none` and cannot be told
/// apart by action at all. Editing the table is how you change what a product
/// shows, which is the point of a schema-driven settings tree.
pub const flag_zat4_only: u8 = 1 << 3;
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
    // Zat Chat is a LIGHT app by default (owner, 2026-07-18); Zat4 stays dark.
    .{ .section = sec_appearance, .group = 0, .kind = .toggle, .action = act_light, .flags = if (chat_app) flag_on else 0, .label = "Light mode", .value = "" },
    .{ .section = sec_appearance, .group = 0, .kind = .toggle, .action = act_zat_kbd, .flags = flag_on, .label = "Zat4 keyboard", .value = "" },
    .{ .section = sec_appearance, .group = 0, .kind = .toggle, .action = act_kbd_pulses, .flags = flag_on, .label = "Keyboard circuit pulses", .value = "" },
    .{ .section = sec_appearance, .group = 0, .kind = .toggle, .action = act_kbd_haptic, .flags = flag_on, .label = "Keyboard haptics", .value = "" },
    .{ .section = sec_appearance, .group = 0, .kind = .toggle, .action = act_kbd_pop, .flags = flag_on, .label = "Key preview pop", .value = "" },
    .{ .section = sec_appearance, .group = 0, .kind = .toggle, .action = act_kbd_lm, .flags = flag_on, .label = "Smart tap targeting", .value = "" },
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
    // MESSAGE notifications lead: they are the only ones the standalone app has,
    // and a messenger that cannot tell you a message arrived is not a messenger.
    // Still `flag_wip` — push notifications are genuinely unbuilt, and a switch
    // that silently governs nothing is worse than one marked "Soon".
    .{ .section = sec_notifications, .group = 0, .kind = .toggle, .action = act_none, .flags = flag_wip, .label = "New messages", .value = "" },
    .{ .section = sec_notifications, .group = 0, .kind = .toggle, .action = act_none, .flags = flag_wip, .label = "Reactions", .value = "" },
    .{ .section = sec_notifications, .group = 0, .kind = .toggle, .action = act_none, .flags = flag_wip, .label = "Show message previews", .value = "" },
    .{ .section = sec_notifications, .group = 1, .kind = .toggle, .action = act_none, .flags = flag_wip | flag_zat4_only, .label = "Likes", .value = "" },
    .{ .section = sec_notifications, .group = 1, .kind = .toggle, .action = act_none, .flags = flag_wip | flag_zat4_only, .label = "Replies", .value = "" },
    .{ .section = sec_notifications, .group = 1, .kind = .toggle, .action = act_none, .flags = flag_wip | flag_zat4_only, .label = "Reposts", .value = "" },
    .{ .section = sec_notifications, .group = 1, .kind = .toggle, .action = act_none, .flags = flag_wip | flag_zat4_only, .label = "New followers", .value = "" },
    .{ .section = sec_notifications, .group = 2, .kind = .toggle, .action = act_none, .flags = flag_wip | flag_zat4_only, .label = "Zone activity", .value = "" },

    // ── Privacy & Safety ─────────────────────────────────────────────────
    // MESSAGING privacy, group 0 — the first thing in Privacy, because for a
    // messenger it is the whole of it. Both default OFF: a receipt or a typing
    // dot is a disclosure about you, so it is opted INTO, never out of.
    .{ .section = sec_privacy, .group = 0, .kind = .toggle, .action = act_chat_receipts, .flags = 0, .label = "Send read receipts", .value = "" },
    .{ .section = sec_privacy, .group = 0, .kind = .toggle, .action = act_chat_typing, .flags = 0, .label = "Send typing indicators", .value = "" },
    .{ .section = sec_privacy, .group = 0, .kind = .toggle, .action = act_chat_disappearing, .flags = flag_wip, .label = "Disappearing messages", .value = "" },
    .{ .section = sec_privacy, .group = 1, .kind = .choice, .action = act_none, .flags = flag_wip | flag_zat4_only, .label = "Who can reply", .value = "Everyone" },
    .{ .section = sec_privacy, .group = 1, .kind = .toggle, .action = act_none, .flags = flag_wip, .label = "Discoverable", .value = "" },
    .{ .section = sec_privacy, .group = 2, .kind = .disclosure, .action = act_none, .flags = flag_wip, .label = "Blocked accounts", .value = "" },
    .{ .section = sec_privacy, .group = 2, .kind = .disclosure, .action = act_none, .flags = flag_wip, .label = "Muted accounts", .value = "" },
    .{ .section = sec_privacy, .group = 3, .kind = .toggle, .action = act_none, .flags = flag_wip | flag_zat4_only, .label = "Privacy labels on lenses", .value = "" },

    // ── Toy Box ──────────────────────────────────────────────────────────
    // Your playground. Grouped into CATEGORIES (the group index is the category,
    // in display order); the Toy Box detail pane renders each group as a titled
    // grid of tiles (see `toyCategoryTitle` + `drawToyBoxDetail`). Feed-motion is
    // deliberately LAST, with Companion + Theme above it. Append a toggle by
    // dropping a line into the right group — the grid follows this table verbatim.
    //
    // Group 0 — Effects: independent decorative overlays (stack with anything).
    .{ .section = sec_toybox, .group = 0, .kind = .toggle, .action = act_julia, .flags = 0, .label = "Julia mode", .value = "" },
    .{ .section = sec_toybox, .group = 0, .kind = .toggle, .action = act_ripples, .flags = flag_on | flag_zat4_only, .label = "Ripples on like", .value = "" },
    .{ .section = sec_toybox, .group = 0, .kind = .toggle, .action = act_crt, .flags = 0, .label = "CRT scanlines", .value = "" },
    .{ .section = sec_toybox, .group = 0, .kind = .toggle, .action = act_frametiming, .flags = 0, .label = "Show frame timing", .value = "" },
    // Group 1 — Companion: the Pet toggle + its colour / size / name options.
    .{ .section = sec_toybox, .group = 1, .kind = .toggle, .action = act_pet, .flags = 0, .label = "Pet", .value = "" },
    .{ .section = sec_toybox, .group = 1, .kind = .choice, .action = act_pet_color, .flags = 0, .label = "Pet colour", .value = "Blue" },
    .{ .section = sec_toybox, .group = 1, .kind = .choice, .action = act_pet_size, .flags = 0, .label = "Pet size", .value = "Medium" },
    .{ .section = sec_toybox, .group = 1, .kind = .textfield, .action = act_pet_name, .flags = 0, .label = "Pet name", .value = "" },
    // Group 2 — Theme: the retro-desktop chrome + full re-theme.
    .{ .section = sec_toybox, .group = 2, .kind = .toggle, .action = act_xp, .flags = 0, .label = "XP skin", .value = "" },
    // Group 3 — Feed motion: mutually-exclusive layout toys (only one owns the
    // feed at a time), rendered as a "pick one" selectable card grid.
    .{ .section = sec_toybox, .group = 3, .kind = .toggle, .action = act_depth, .flags = flag_zat4_only, .label = "Depth feed", .value = "" },
    .{ .section = sec_toybox, .group = 3, .kind = .toggle, .action = act_tectonic, .flags = flag_zat4_only, .label = "Tectonic timeline", .value = "" },
    .{ .section = sec_toybox, .group = 3, .kind = .toggle, .action = act_gravity, .flags = flag_zat4_only, .label = "Gravity", .value = "" },
    .{ .section = sec_toybox, .group = 3, .kind = .toggle, .action = act_zero_g, .flags = flag_zat4_only, .label = "Zero-G", .value = "" },
    .{ .section = sec_toybox, .group = 3, .kind = .toggle, .action = act_liquid, .flags = flag_zat4_only, .label = "Liquid", .value = "" },

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

test "accent palette: labels and colours are one table, not two that agree by luck" {
    const c = choiceOf(act_accent).?;
    try std.testing.expectEqual(accent_options.len, c.options.len);
    for (accent_options, 0..) |o, i| {
        try std.testing.expectEqualStrings(o.label, c.options[i]);
        try std.testing.expectEqual(o.color, accentColor(@intCast(i)));
    }
    // The picker packs its selection into 3 bits per choice in the shell.
    try std.testing.expect(accent_options.len <= 8);
}

test "accent palette: the default option matches the product" {
    const c = choiceOf(act_accent).?;
    const label = c.options[c.default];
    if (chat_app) {
        // Zat Chat has no feed socket to follow, so no "Auto" is offered and
        // the accent is simply a choice, defaulting to Blue.
        try std.testing.expectEqualStrings("Blue", label);
        for (accent_options) |o| try std.testing.expect(o.color != null);
    } else {
        try std.testing.expectEqualStrings("Auto", label);
        try std.testing.expectEqual(@as(?u32, null), accent_options[0].color);
    }
}

test "accent palette: an out-of-range index is Auto, never off the end" {
    try std.testing.expectEqual(@as(?u32, null), accentColor(@intCast(accent_options.len)));
    try std.testing.expectEqual(@as(?u32, null), accentColor(255));
}

test "light mode: Zat Chat starts light, Zat4 starts dark" {
    const row = rows[rowOf(act_light).?];
    try std.testing.expectEqual(chat_app, (row.flags & flag_on) != 0);
}

test "product filter: the feed-motion toys are absent from the messenger" {
    // They re-layout a timeline Zat Chat does not have — not "off", meaningless.
    for ([_]u8{ act_depth, act_tectonic, act_gravity, act_zero_g, act_liquid }) |a| {
        const r = rows[rowOf(a).?];
        try std.testing.expectEqual(!chat_app, rowInProduct(r));
    }
}

test "product filter: the whole-app toys carry over to the messenger" {
    // The owner's distinction: toys that RE-THEME travel, toys that RE-LAYOUT
    // the feed do not.
    for ([_]u8{ act_pet, act_julia, act_crt, act_xp }) |a| {
        try std.testing.expect(rowInProduct(rows[rowOf(a).?]));
    }
}

test "product filter: Feed & Content is a Zat4 section only" {
    try std.testing.expectEqual(!chat_app, sectionInProduct(sec_feed));
    // Every other section survives in both products.
    for ([_]u8{ sec_account, sec_toybox, sec_appearance, sec_notifications, sec_privacy, sec_about }) |sc| {
        try std.testing.expect(sectionInProduct(sc));
    }
}

test "product filter: no section is left with nothing in it" {
    // A section header opening an empty pane is a dead end; if a product ever
    // filters out every row of a section, that section must go too.
    for (sections, 0..) |_, si| {
        const sc: u8 = @intCast(si);
        if (!sectionInProduct(sc)) continue;
        var any = false;
        for (rows) |r| {
            if (r.section == sc and rowInProduct(r)) any = true;
        }
        try std.testing.expect(any);
    }
}

test "messaging privacy: receipts and typing are present in BOTH products" {
    // Chat exists in Zat4 too, so these are not chat-flavor-only rows.
    for ([_]u8{ act_chat_receipts, act_chat_typing }) |a| {
        const r = rows[rowOf(a).?];
        try std.testing.expect(rowInProduct(r));
        // Both OFF by default: a receipt is a disclosure about you, opted INTO.
        try std.testing.expectEqual(@as(u8, 0), r.flags & flag_on);
    }
}
