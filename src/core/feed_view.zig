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

//! B1 classification: CORE (pure). The premium feed view — a slice of
//! plain post records becomes proportional draw items (avatars, names,
//! body, an engagement row, dividers) layered OVER the living field
//! (PHASE5_GUI_ROADMAP cut 5.6, the deferred visual pass). It speaks the
//! raster draw-list vocabulary and nothing else: same posts + same engine
//! ⇒ same items (B2). No I/O, no clock, no network. Positioning is
//! measured through the font engine (a pure advance lookup), so the layout
//! is proportional, not locked to the field's cell grid — the decoupling
//! the mockups proved out.
//!
//! D6: this is one vertical slice. The field stays exactly as it was; this
//! module only appends a content layer on top. Wiring it in is a single
//! call in the shell's paint path after the field composes.

const std = @import("std");
const assert = std.debug.assert;
const Allocator = std.mem.Allocator;
const text = @import("text.zig");
const raster = @import("raster.zig");
const lens_socket = @import("lens_socket.zig");
const kbd_lm = @import("kbd_lm.zig");
const create_flow = @import("create_flow.zig");
const dev_flow = @import("dev_flow.zig");
const zal_templates = @import("zal_templates.zig");
const builder = @import("builder.zig");
const discover = @import("discover.zig");
const text_select = @import("text_select.zig");
const timefmt = @import("timefmt.zig");
const compose = @import("compose.zig");
const settings_view = @import("settings_view.zig");
const transp = @import("transparency.zig");
const algo_docs = @import("algo_docs.zig");
const chat_view = @import("chat_view.zig");
const chat_msg = @import("chat.zig");

/// Safe-area insets in LOGICAL (design-space) pixels — the shell converts the
/// OS's physical-px insets by the ui scale before handing them in (B5). Zero on
/// desktop/preview. Cold value (one per layout call), guarded for discipline.
pub const EdgeInsets = struct {
    top: i32 = 0,
    bottom: i32 = 0,
    left: i32 = 0,
    right: i32 = 0,
    comptime {
        assert(@sizeOf(EdgeInsets) == 16);
    }
};

// Palette, copied from field.zig so the view never reaches across a module
// for a constant (D4: only the value crosses, by copy). ARGB.
const bg: u32 = 0xFF000000; // app canvas — pure black (field backdrop + card elevation base)
const ink: u32 = 0xFFEDEAE0;
const body_c: u32 = 0xFFD8D3C8;
const muted: u32 = 0xFF9A968A;
const faint: u32 = 0xFF6A655A;

/// Relative luminance of an opaque RGB colour, 0..255 (integer Rec.601-ish
/// weights). The one input to the contrast rule below.
inline fn luma(c: u32) u32 {
    const r = (c >> 16) & 0xFF;
    const g = (c >> 8) & 0xFF;
    const b = c & 0xFF;
    return (r * 77 + g * 150 + b * 29) >> 8;
}

/// True when a fill is light enough that text on it must go DARK. The bubble
/// fill shifts with the user's ambient lens (any hue, any lightness), so card
/// text can never be hardcoded — it is derived from the fill it sits on.
inline fn fillIsBright(c: u32) bool {
    return luma(c) > 140;
}

/// The "colour proof" pair: a legible primary and a muted-companion text
/// colour for content drawn ON `fill` — dark ink on a bright fill, light ink
/// on a dark one. Used for every string on a payment card so it stays
/// readable whatever palette the reader has chosen.
inline fn onFill(fill: u32) u32 {
    return if (fillIsBright(fill)) 0xFF1A1712 else 0xFFF4F1EA;
}
inline fn onFillMuted(fill: u32) u32 {
    return if (fillIsBright(fill)) 0xFF4C463C else 0xFFD6D2C7;
}
/// The HOUSE accent (amber) — the default and the composer's fixed accent.
/// On Home the live accent is the SEATED LENS's palette color (§11.5),
/// threaded into `layout` as `accent` and passed down to the chrome; this
/// const is the fallback for surfaces with no seated lens.
pub const accent_house: u32 = 0xFFF2762A; // site default accent (orange)
/// Text-selection highlight (translucent steel, drawn behind selected glyphs).
const sel_fill: u32 = 0x553A6EA5;
const like_c: u32 = 0xFFF0617A;
const boost_c: u32 = 0xFF8FD18F;
/// Inline `#hashtag` colour in prose — a clear, calm blue that reads as a link
/// without going neon. Same hue as the Discover lens accent.
const tag_blue: u32 = 0xFF4DA3FF;
/// Resting engagement-icon colour — a soft neutral grey-white (no blue cast),
/// so the reply, repost, and hollow-heart icons read as one calm set without
/// pulling cool/blue or going bright white.
const icon_grey: u32 = 0xFFB4B1A8;
const veil: u32 = 0xD4181812; // ~83% over the field — texture glows faintly through
const header_veil: u32 = 0xF2181812; // ~95%: the sticky top bar, drawn OVER the posts so
// Julia mode: the menu surfaces go DIFFERENT shades of pink instead of near-black
// (the glass column, the sticky bars, and the cards each a distinct plum-pink).
// Chosen via `juliaSkin(accent)` so no new param threads through layout.
const veil_julia: u32 = 0xEAA83870; // glass column — saturated rose, high opacity
const header_veil_julia: u32 = 0xF49A305F; // sticky bars — deeper rose, near-opaque
const panel_julia: u32 = 0xF0C24E86; // cards / rail — bright bubblegum

// Julia mode is detected from the accent token (already threaded everywhere), so
// the menu skinning needs no extra parameter on layout()/the draw functions.
inline fn skinVeil(accent: u32) u32 {
    return if (accent == lens_socket.julia_pink) veil_julia else veil;
}
inline fn skinHeaderVeil(accent: u32) u32 {
    return if (accent == lens_socket.julia_pink) header_veil_julia else header_veil;
}
inline fn skinPanel(accent: u32) u32 {
    return if (accent == lens_socket.julia_pink) panel_julia else panel;
}

/// Website palette (index.html): the low-contrast border that DEFINES a card
/// against the background — ~15 levels lighter than the `#1b1b1b` fill, so it
/// reads as a soft edge, not a hard outline. The single origin for the future
/// light mode to swap.
const card_line: u32 = 0xFF2A2A2A;

/// Draw a CONTAINER panel: a subtle 1px border with `fill` on top. The border is
/// a slightly-larger rounded rect UNDERNEATH — the "ring" trick, since the rect
/// vocabulary can't stroke a rounded outline directly. Use for surfaces that HOLD
/// content (cards, menus, the composer); controls (pills/toggles) stay borderless
/// so the app doesn't read busy. Solid fill + this edge is the cure for the drab
/// translucent-over-field mush.
fn cardBox(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, w: i32, h: i32, radius: u8, fill: u32) error{OutOfMemory}!void {
    const r2: u8 = if (radius >= 255) 255 else radius + 1;
    try rect(gpa, dl, x - 1, y - 1, w + 2, h + 2, card_line, r2);
    try rect(gpa, dl, x, y, w, h, fill, radius);
}

/// A chat bubble's fill — FULLY OPAQUE, so a message reads as a solid bubble,
/// not a tint you can see the field through. Mine = the accent at full opacity
/// (the "sent" bubble); theirs = the opaque panel skin (the "received" bubble).
/// The panel/accent RGB is kept; only the alpha is forced to 0xFF.
inline fn bubbleFill(accent: u32, mine: bool) u32 {
    return if (mine)
        0xFF000000 | (accent & 0x00FFFFFF)
    else
        0xFF000000 | (skinPanel(accent) & 0x00FFFFFF);
}

// Julia mode is a LIGHT theme (white field, bright pink panels), so the text must
// go DARK to read. Rather than thread a flag through ~120 text-draw sites, the
// shell calls `juliaRemapText` over the finished draw list: the three text inks
// are known constants, so they're remapped by value in one pass. (lens_socket
// shares the same ink/muted/faint values, so the socket text is remapped too.)
// Light theme on deep-pink panels → WHITE text reads best. Primary pure white;
// secondary/tertiary a soft pink-white so the hierarchy survives.
const ink_julia: u32 = 0xFFFFFFFF; // names, body, titles
const muted_julia: u32 = 0xFFF4E2EC; // handles, secondary
const faint_julia: u32 = 0xFFE6C6D8; // tertiary (TRENDING sub-lines, etc.)

/// A small read-anywhere overlay badge — a dark pill behind light text, so it
/// reads over any background. Used by the shell's debug overlays (the
/// frame-timing readout). Positioned in logical px; fixed colours (NOT the text
/// inks, so `juliaRemapText` leaves it alone).
pub fn overlayBadge(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, x: i32, baseline: i32, s: []const u8) error{OutOfMemory}!void {
    const tw: i32 = @intCast(text.measure(e, .regular, s, 13));
    try rect(gpa, dl, x - 8, baseline - 17, tw + 16, 25, 0xD2101014, 7);
    _ = try str(gpa, dl, e, .regular, x, baseline, 0xFFE8EAF0, 13, s);
}

/// Remap the three UI text inks to their dark Julia-mode variants, in place, over
/// the finished draw list (TextItems only — rects/lit-edges that reuse the ink
/// value as a tint are untouched). Idempotent-ish: only the three exact colours
/// move. The shell calls this when Julia mode is on, before the GPU upload.
pub fn juliaRemapText(dl: *raster.DrawList) void {
    var i: usize = 0;
    while (i < dl.len) : (i += 1) {
        var item = dl.get(i);
        switch (item) {
            .text => |*t| {
                const nc: ?u32 = switch (t.color) {
                    ink => ink_julia,
                    muted => muted_julia,
                    faint => faint_julia,
                    else => null,
                };
                if (nc) |c| {
                    t.color = c;
                    dl.set(i, item);
                }
            },
            else => {},
        }
    }
}
// they scroll BEHIND it (firmly dimmed), the title/tabs crisp on top — a frosted header
// ambient-texture slice will lower this so the living field glows through.
const divider: u32 = 0x18EDEAE0; // ~9% ink hairline

/// Which control a hit region belongs to. The button slice maps these to
/// effects/writes; the view only reports geometry (B5). `nav` (a left-rail
/// destination; the region's `post` field carries the Screen index) and
/// `compose` (the New-post button) route navigation rather than engagement.
/// `compose_send` / `compose_cancel` are the premium composer's footer buttons
/// (the shell turns a tap into the same control byte the keyboard sends).
/// `settings_section` selects the left-hand settings section (carries the
/// section index in `post`); `settings_row` is a detail-pane row tap (carries
/// the global row index — inert scaffold today, except `act_sign_out` rows which
/// the renderer emits as `.sign_out` so that one wired control keeps working).
pub const Action = enum(u8) { reply, repost, like, nav, compose, author, edit_profile, compose_send, compose_cancel, post_body, back, reveal_new, bookmark, share, more, profile_tab, loadout_tab, collapse, sign_out, zone_jump, zone_open, tag_inline, zone_tab, zone_search, zone_pin, zone_compose, compose_tag_add, compose_tag_remove, settings_section, settings_row, settings_choice, settings_choice_opt, algo_view, algo_add, algo_source, create_pick, create_back, create_next, create_knob_dec, create_knob_inc, create_color, create_save, create_dev, chat_conv, chat_input, chat_send, chat_new, chat_compose_input, pay_open, pay_rail, pay_chip, pay_amount, pay_note, pay_unit, pay_request, pay_send, pay_cancel, pay_card_pay, pay_card_cancel, pay_card_received, pay_card_setup, pay_card_decline, pay_card_send, expand, compose_add, compose_remove, quote_open, quote_new, repost_do, recv_open, recv_ln, recv_btc, recv_save, recv_cancel, recv_have, recv_need, recv_wallet, recv_paste, recv_remove, pay_arm, pay_confirm_back, drawer_close, dev_template, dev_check, dev_next, dev_back, dev_publish, dev_src, dev_field, dev_color, dev_surface, algo_open, algo_install, market_search, chat_search, kbd_key, kbd_shift, kbd_page, kbd_backspace, chat_copy, chat_cut, chat_paste, chat_selall, bench_seat, bench_confirm, bench_cancel, pub_delete, docs_user, docs_dev, drawer_open, search, blocker };

/// Main-feed Read-more: a post whose body wraps to more than this many visual
/// lines is clamped to it (with a "Read more" doorway) until the reader expands
/// it. Home feed only — threads and detail views always render in full.
pub const feed_clamp_lines: u32 = 10;

/// The six top-level rail destinations, in order. The `Screen` index a nav
/// region carries is an index into this. Shared by the rail (draw + hit) and
/// the body (the screen title), so the two never drift.
/// Rail destinations. Slot 4 is "Algorithms" (the loadout page) — it took the
/// old Profile slot, since the bottom-left "you" card already opens Profile.
pub const nav_labels = [_][]const u8{ "Home", "Zones", "Activity", "Zat Chat", "Algorithms", "Settings" };

/// Named screen indices. The rail nav posts its index as the screen; slots
/// rendered as real surfaces (home, loadout) have their own branch, the rest
/// fall through to a placeholder.
pub const screen_home: u8 = 0;
/// The Zones BROWSE catalog — the rail's "Zones" slot (index 1, the old Explore
/// slot). The catalog of zones (tag → place): sub-tabs, a search/jump field, the
/// category row, and the manifest-zone grid. Tapping a card opens that zone's
/// feed (`screen_zones`). The sub-tabs/categories are present-but-inert scaffold
/// (like the lens socket) until the standing/manifest/catalog engines land.
pub const screen_zones_browse: u8 = 1;
/// The rail's "Messages" slot (index 3) — the Zat Chat surface, a
/// master–detail page (conversation list + the open thread), rendered by
/// `layoutChat`. Dev-gated in the shell until the E2EE core lands
/// (ZAT_CHAT_ROADMAP U3/M1); the surface itself draws the honesty banner.
pub const screen_messages: u8 = 3;
/// The loadout page — the rail's "Algorithms" slot (index 4). Renders the
/// three per-surface sockets (feed / replies / zones) stacked for editing.
pub const screen_loadout: u8 = 4;
/// The rail's "Settings" slot (index 5) — the gear nav icon.
pub const screen_settings: u8 = 5;
/// A transient sub-screen (not a rail destination): a post's thread, shown when
/// a post body is tapped. Past the nav labels, so the rail highlights none.
pub const screen_thread: u8 = 6;
/// Profile is no longer a rail slot; reached via the bottom-left "you" card
/// and avatar taps (which set this screen explicitly). Off the rail range.
pub const screen_profile: u8 = 7;
/// A ZONE page (a tag-scoped feed) — transient, reached by tapping a `#tag` in a
/// post's tray. Off the rail; renders like Home (title + header socket + feed)
/// with the zone's name as the title and a back button. (Zat Zones slice 4.)
pub const screen_zones: u8 = 8;
/// An algorithm's TRANSPARENCY page (DISCOVER invariant 5) — a wide document
/// page showing every field of a feed algorithm, its plain meaning, and the
/// system-proven privacy verdict. Reached from a lens card; renders
/// `transparency.Page` via `layoutTransparency`. Off the rail, with a back button.
pub const screen_transparency: u8 = 9;
pub const screen_algo_detail: u8 = 10; // one marketplace algorithm, full page
pub const screen_algo_docs: u8 = 11; // the explainer / writing-guide documents

/// The profile screen's header band — the viewed account's identity over its
/// post list. Plain data handed in by the shell (B5); the post count is the
/// number of posts fetched for the profile. A7.2: cold struct — one per frame,
/// never held in a collection, so no size guard.
pub const ProfileHeader = struct {
    display_name: []const u8,
    handle: []const u8, // already "@handle" form, as the post rows carry it
    post_count: u32,
    /// True when this is the viewer's OWN profile — draws an "Edit profile"
    /// button (a `.edit_profile` tap region) so they can set their display name.
    editable: bool = false,
};

/// One zone in the browse catalog (the manifest grid). Plain value handed in by
/// the shell (B5). Every field is REAL, computed from the tag index: `tag`
/// (display casing, no leading `#`), `count` (posts bearing it), `authors`
/// (distinct posters — the zone's people), `recent` (posts in the shell's
/// recency window, the trending velocity), `last_at` (newest post, unix secs),
/// and `pinned` (the viewer pinned this zone). Editorial copy (description,
/// category, official badge) stays a later-engine concern (Z2/Z3/Z7).
/// A7.2: cold — a handful per frame, never hot.
pub const ZoneCard = struct {
    tag: []const u8,
    count: usize,
    authors: usize = 0,
    recent: usize = 0,
    last_at: i64 = 0,
    pinned: bool = false,
};

/// EVERYTHING the zones surfaces need for one frame, as one plain value (B5) —
/// the hub catalog + its UI state (tab, search, pointer), the shell-driven
/// motion scalars, and the open zone page's own stats. Grouped so new zone
/// data never widens `layout`'s parameter list again.
/// A7.2: cold struct, size guard waived — one per frame, never collected.
pub const ZonesView = struct {
    /// The catalog, activity-sorted by the shell (`sortZonesByActivity`).
    /// A `.zone_open`/`.zone_pin` region's idx indexes THIS slice.
    cards: []const ZoneCard = &.{},
    /// Hub sub-tab: 0 Browse · 1 Pinned · 2 Trending.
    tab: u8 = 0,
    /// Live search text (the shell owns the buffer) + its focus/caret state.
    query: []const u8 = "",
    q_focus: bool = false,
    caret_on: bool = false,
    /// Pointer position in layout coords for hover states; -1 = no pointer.
    hover_x: i32 = -1,
    hover_y: i32 = -1,
    /// Unix seconds — relative "active …" labels (the clock stays in the
    /// shell, B3/B4; this is plain data).
    now: i64 = 0,
    /// Animated tab position: the shell lerps this toward `tab`; the
    /// underline draws at the interpolated rect (fractional = mid-flight).
    tab_t: f32 = 0,
    /// Tab-switch settle, 0→1: the incoming list slides up + fades in.
    /// (Page ENTRY needs no state here — the GPU path's screen-switch
    /// crossfade already dissolves between screens.)
    enter_t: f32 = 1,
    /// The OPEN zone page's stats (screen_zones): distinct posters, whether
    /// the viewer pinned it, and its newest post (0 = unknown → omitted).
    people: usize = 0,
    pinned: bool = false,
    last_at: i64 = 0,
};

/// Order the catalog like a LIVING directory: most 24h activity first, then
/// total size, then recency, then name (a stable, deterministic ordering —
/// same catalog ⇒ same shelf). In-place, no allocation. PURE.
pub fn sortZonesByActivity(cards: []ZoneCard) void {
    const S = struct {
        fn lessThan(_: void, a: ZoneCard, b: ZoneCard) bool {
            if (a.recent != b.recent) return a.recent > b.recent;
            if (a.count != b.count) return a.count > b.count;
            if (a.last_at != b.last_at) return a.last_at > b.last_at;
            return std.ascii.lessThanIgnoreCase(a.tag, b.tag);
        }
    };
    std.sort.block(ZoneCard, cards, {}, S.lessThan);
}

/// Human "when was this place last alive" label into `buf`: "active just now"
/// through "quiet for 3w", "" when unknown (last_at 0 or in the future). PURE.
pub fn activityLabel(buf: []u8, now: i64, last_at: i64) []const u8 {
    if (last_at <= 0 or now < last_at) return "";
    const dt = now - last_at;
    if (dt < 90) return "active just now";
    if (dt < 3600) return std.fmt.bufPrint(buf, "active {d}m ago", .{@divTrunc(dt, 60)}) catch "";
    if (dt < 86400) return std.fmt.bufPrint(buf, "active {d}h ago", .{@divTrunc(dt, 3600)}) catch "";
    if (dt < 7 * 86400) return std.fmt.bufPrint(buf, "active {d}d ago", .{@divTrunc(dt, 86400)}) catch "";
    return std.fmt.bufPrint(buf, "quiet for {d}w", .{@divTrunc(dt, 7 * 86400)}) catch "";
}

/// Scale a colour's alpha by `t` (0..1) — the tab-switch fade-in.
fn fadeColor(c: u32, t: f32) u32 {
    const a: u32 = c >> 24;
    const tc = @max(0.0, @min(1.0, t));
    const na: u32 = @intFromFloat(@as(f32, @floatFromInt(a)) * tc);
    return (na << 24) | (c & 0x00FFFFFF);
}

/// Scale the alpha of every draw item from `from` to the list's current end
/// by `t` — the collapse fade for a range a widget draws without an alpha
/// input (the zone masthead's tucking lens socket). PURE.
fn fadeItems(dl: *raster.DrawList, from: usize, t: f32) void {
    var i: usize = from;
    while (i < dl.len) : (i += 1) {
        var item = dl.get(i);
        switch (item) {
            .cell => |*c| c.fg = fadeColor(c.fg, t),
            .text => |*x| x.color = fadeColor(x.color, t),
            .rect => |*r| r.color = fadeColor(r.color, t),
            .line => |*l| l.color = fadeColor(l.color, t),
            .tri => |*tr| tr.color = fadeColor(tr.color, t),
        }
        dl.set(i, item);
    }
}

/// The kind of composition the premium composer is hosting — sets the context
/// line, the placeholder, and the send-button label. Reply is distinguished
/// from a fresh post by a non-empty target handle (the shell already tracks the
/// reply target separately; this only drives the look).
pub const ComposeContext = enum(u8) { post, reply, profile };

/// The composer TAG BAR for one frame, as plain values (B5): the live INLINE
/// #tags mirrored out of the draft, the manual "+ tag" chips, the LOCKED tag
/// (composing from a zone page — drawn solid, no ×, cannot be removed), and
/// the add-tag input's text/focus/caret. A7.2: cold — one per frame.
pub const ComposeTagBarView = struct {
    inline_tags: []const []const u8 = &.{},
    manual: []const []const u8 = &.{},
    locked: []const u8 = "",
    input: []const u8 = "",
    input_focus: bool = false,
    caret_on: bool = false,
};

/// The viewer's real identity for the Settings → Account info rows. Plain values
/// handed in by the shell (B5); empty ⇒ the table's placeholder shows instead.
/// A7.2: cold — one per frame, never collected.
pub const SettingsAccount = struct {
    handle: []const u8 = "", // already "@handle" form
    did: []const u8 = "",
    pds: []const u8 = "",
    pet_name: []const u8 = "", // the pet's name (editable text field)
    pet_name_focus: bool = false, // draw the caret when the field is focused
};

/// A pen position (where the next glyph — and so the text cursor — would land)
/// returned by the draft wrapper. A7.2: cold — a single transient value per
/// compose frame, never held in a collection.
const Pen = struct { x: i32, baseline: i32 };

/// One tappable button region in window pixels, tagged with the post it
/// belongs to and the control. Emitted alongside the draw items so a click
/// can be resolved without re-deriving the layout. HOT (a few per screen,
/// scanned per click) → A7.
pub const Region = struct {
    x: i16,
    y: i16,
    w: u16,
    h: u16,
    post: u16,
    kind: Action,
    _pad: u8 = 0, // A6: explicit

    comptime {
        assert(@sizeOf(Region) == 12); // 2+2+2+2+2+1+1, exact (A7)
    }
};

pub const Regions = std.ArrayListUnmanaged(Region);

/// The rooted post's body glyphs, for read-only text selection, are produced
/// here and consumed by `text_select` (the deep module that owns the selection
/// math); the glyph vocabulary lives there, aliased here for the producers.
pub const SelGlyph = text_select.Glyph;
pub const SelGlyphs = text_select.Glyphs;

/// The chain (OP stitched self-thread) extent, reported by `layout` so the shell
/// can draw the sticky "chain header" that pins while you scroll the chain and is
/// pushed out at its end. Offsets are CONTENT-space (scroll-independent): the
/// shell computes screen-y as `off + scroll`. A7.2: cold — one transient per
/// layout call, never collected.
pub const ChainSticky = struct {
    present: bool = false,
    head_index: u32 = 0, // index into `posts` for the chain header's identity
    top_off: i32 = 0, // chain header content top
    bottom_off: i32 = 0, // chain end content top (first non-chain post, or thread end)
    pin_y: i32 = 0, // where the sticky pins (the feed origin, below the top bar)
};

/// First region (in reverse paint order) containing the pixel, or null.
pub fn hitTest(regions: []const Region, px: i32, py: i32) ?Region {
    var i: usize = regions.len;
    while (i > 0) {
        i -= 1;
        const r = regions[i];
        if (px >= r.x and px < @as(i32, r.x) + r.w and py >= r.y and py < @as(i32, r.y) + r.h) return r;
    }
    return null;
}

/// One visible post, as the view needs it — plain display data, already
/// resolved by whatever produced it (sample content today; a transform
/// over real timeline items tomorrow, B5). Built fresh each frame for the
/// handful of on-screen rows, never the bulk store — but it rides a
/// per-frame loop, so it carries the guard.
pub const PostView = struct {
    name: []const u8,
    handle: []const u8,
    age: []const u8,
    body: []const u8,
    /// "@handle" of the post this replies to, or "" — drives the feed's
    /// "Replying to @x" context line so a reply doesn't read as a standalone
    /// post (Twitter/Bluesky parity).
    replying_to: []const u8 = "",
    tint: u32, // avatar fill (ARGB)
    reply: u32,
    boost: u32,
    like: u32,
    initial: u8, // avatar letter (ASCII)
    liked: bool,
    boosted: bool,
    /// Thread nesting depth (0 = root) + whether this is the focused post —
    /// VIEW-DERIVED (the reader's lens), 0/false outside the thread view. Both
    /// ride the tail padding, so the size is unchanged.
    depth: u8 = 0,
    is_focus: bool = false,
    /// The root author's self-reply continuation — render STITCHED (no header,
    /// flush, thin separator) into one continuous post. Rides the tail padding.
    stitched: bool = false,
    /// Thread lens: this post has replies, and the reader has collapsed it.
    has_kids: bool = false,
    collapsed: bool = false,
    /// Main-feed "Read more": the reader has expanded this post, so its body is
    /// laid out in FULL rather than clamped to `feed_clamp_lines`. View-derived
    /// (a per-reader lens, never on the record); false everywhere but Home.
    expanded: bool = false,
    /// The post's zone tags (display casing) — the tray of tappable zone-doorways
    /// the renderer paints below the post. A slice like the other variable-length
    /// view fields; empty ⇒ untagged.
    tags: []const []const u8 = &.{},
    /// Quote-post: the quoted post's DISPLAY snapshot for the quote card (name +
    /// @handle + text). The tap target's uri/cid ride the shell's parallel
    /// TimelineItem, so the view needs only what it draws. `quote_text` empty ⇒
    /// not a quote.
    quote_author_name: []const u8 = "",
    quote_author_handle: []const u8 = "",
    quote_text: []const u8 = "",

    comptime {
        // Budget: 9 slices (9×16=144) + 4 u32 (16) + 9 flag bytes = 169, rounded
        // to the 8-byte slice alignment = 176.
        // (A7.1 raise 128 → 176: three quote-card display slices — the same kind of
        // variable-length view data as `tags`/`replying_to`, empty on non-quotes.
        // This struct is built for a handful of VISIBLE rows, never the bulk store,
        // so the absolute cost is a few dozen bytes per frame.)
        assert(@sizeOf(PostView) == 176);
    }
};

const rail_w: i32 = 248;
const feed_w: i32 = 604;
const side_w: i32 = 352;
/// Height of the sticky PROFILE identity header: the compact horizontal identity
/// band (avatar + name + handle·count + Edit profile) PLUS a profile-nav tab row
/// (Posts · Replies · Media · Likes) below it. Both stay pinned so identity AND
/// the tabs remain visible while posts scroll under them.
const profile_header_h_wide: i32 = 152;
const profile_header_h_narrow: i32 = 134;
/// Home's sticky header grew to seat the LENS SOCKET (it replaces the old
/// Following/Discover tab labels). Title on top, the resting socket below,
/// then the divider — posts start beneath it (feed_y0).
const home_header_h_wide: i32 = 140;
const home_header_h_narrow: i32 = 122;
const socket_y_wide: i32 = 66; // socket top, under the "Home" title
const socket_y_narrow: i32 = 52; // socket top, under the wordmark
/// A ZONE page wears a richer MASTHEAD than Home — an identity band (icon tile +
/// big #name + face chip + Pin + description + stats) above the lens socket, so a
/// zone reads as a distinct PLACE, not the home feed with a different title. The
/// socket seats lower (under the band), and the caption sits beneath it.
const zone_header_h_wide: i32 = 250;
const zone_header_h_narrow: i32 = 214;
const zone_socket_y_wide: i32 = 166; // socket top, under the identity band
const zone_socket_y_narrow: i32 = 150;
/// Profile-nav tabs (visual for now — the regions carry the tab index for a
/// later slice; "Posts" is active). The Links page attaches as another tab.
const profile_tabs = [_][]const u8{ "Posts", "Replies", "Media", "Likes" };

/// The bottom edge (logical y) of the sticky header for a screen — the single
/// source of truth so other passes (e.g. the GPU heart clip) can't drift from
/// the header heights. The GPU feed lays out at the WIDE design width, so these
/// are the wide values; the plain top bar is 111.
pub fn headerBottom(active_screen: u8) i32 {
    if (active_screen == screen_profile) return profile_header_h_wide;
    // The zone page wears a tall identity masthead above its socket (distinct
    // from Home, which is just title + socket). NOTE: the zone masthead
    // COLLAPSES with scroll — scroll-aware callers use zoneHeaderH instead.
    if (active_screen == screen_zones) return zone_header_h_wide;
    if (active_screen == screen_home) return home_header_h_wide;
    return 111;
}

/// The zone masthead's collapsed-bar height.
pub const zone_thin_h_wide: i32 = 64;
pub const zone_thin_h_narrow: i32 = 52;

/// The zone page's band geometry (the Reddit shape): a reading column and,
/// when the glass is wide enough for both, the About sidebar beside it.
const zone_read_w: i32 = 720;
const zone_side_w: i32 = 340;
const zone_side_gap: i32 = 28;
/// The hub's grid band: two comfortable cards, centred in the glass.
const zones_hub_band_max: i32 = 1080;

/// How far the zone masthead has collapsed, 0 (at rest, tall) → 1 (fully
/// the thin bar). A pure function of the feed scroll, so leaving and
/// returning to the top restores the tall masthead PIXEL-PERFECT — the same
/// contract as the thread chain's sticky header. PURE.
pub fn zoneCollapseT(scroll: i32, wide: bool) f32 {
    const tall: i32 = if (wide) zone_header_h_wide else zone_header_h_narrow;
    const thin: i32 = if (wide) zone_thin_h_wide else zone_thin_h_narrow;
    const d: f32 = @floatFromInt(tall - thin);
    return std.math.clamp(@as(f32, @floatFromInt(-scroll)) / d, 0.0, 1.0);
}

/// The zone masthead's CURRENT height at this scroll — tall at the top,
/// shrinking to the thin bar as the reader scrolls in. Drives both the drawn
/// masthead and the shell's occlusion clip (they must agree or hearts/posts
/// pop behind the wrong edge). PURE.
pub fn zoneHeaderH(scroll: i32, wide: bool) i32 {
    const tall: i32 = if (wide) zone_header_h_wide else zone_header_h_narrow;
    const thin: i32 = if (wide) zone_thin_h_wide else zone_thin_h_narrow;
    const ct = zoneCollapseT(scroll, wide);
    return tall - @as(i32, @intFromFloat(@as(f32, @floatFromInt(tall - thin)) * ct));
}

/// The logical y the HOME header occludes down to, accounting for the lens
/// socket's OPEN tray (which drops over the posts). The shell clips the
/// separate GPU heart pass to this so hearts behind the open tray don't
/// bleed over it. Resting → the plain home header height. (Wide layout —
/// the GPU path lays out at the design width.)
pub fn homeSocketBottom(socket_tray: ?lens_socket.TrayView, socket_ui: lens_socket.SocketUi) i32 {
    const base = home_header_h_wide;
    const tray = socket_tray orelse return base;
    if (!socket_ui.open) return base;
    return @max(base, socket_y_wide + lens_socket.measuredHeight(tray, socket_ui, homeSocketGeom(wide_min)));
}

/// The ZONE page's occlusion bottom: the collapsing masthead's CURRENT height,
/// extended over the zone socket's OPEN tray (which drops over the posts,
/// exactly like Home's) — the same clip contract as homeSocketBottom, at the
/// live scroll. PURE.
pub fn zoneSocketBottom(socket_tray: ?lens_socket.TrayView, socket_ui: lens_socket.SocketUi, scroll: i32, wide: bool) i32 {
    const base = zoneHeaderH(scroll, wide);
    const tray = socket_tray orelse return base;
    if (!socket_ui.open) return base;
    const off: i32 = if (wide) zone_header_h_wide - zone_socket_y_wide else zone_header_h_narrow - zone_socket_y_narrow;
    const geom: lens_socket.Geometry = .{ .x = 0, .y = base - off, .w = zone_read_w, .scale = 1.0 };
    return @max(base, (base - off) + lens_socket.measuredHeight(tray, socket_ui, geom));
}

/// The exact geometry the Home header lays the socket out at, for a given
/// layout width — so the shell can run `lens_socket.dropIndex` (the drag
/// insertion math) against the same grid the widget drew.
pub fn homeSocketGeom(width: i32) lens_socket.Geometry {
    const m = metricsFor(width);
    return .{ .x = m.lx, .y = if (m.wide) socket_y_wide else socket_y_narrow, .w = m.cw, .scale = 1.0 };
}

/// Does the LOGICAL point (x, y) land on the CLOSED home socket bar? Phone only;
/// `inset_top` is the safe-area shift the header rides (the socket draws shifted
/// with it). The shell uses this to give a swipe that starts on the socket
/// precedence over the nav-drawer swipe.
pub fn homeSocketHit(width: i32, tray: ?lens_socket.TrayView, ui: lens_socket.SocketUi, inset_top: i32, x: i32, y: i32) bool {
    if (width > phone_max) return false;
    const geom = homeSocketGeom(width);
    const y0 = geom.y + inset_top;
    const y1 = homeSocketBottom(tray, ui) + inset_top;
    return x >= geom.x and x < geom.x + geom.w and y >= y0 and y < y1;
}
const wide_min: i32 = rail_w + feed_w + side_w + 40; // ~1244

const panel: u32 = 0xFF1B1B1B; // cards/menus: the website's solid grey (#1b1b1b),
//                                opaque now — a crisp surface, not a translucent tint
const panel_hover: u32 = 0xFF242424; // a card under the pointer — a hair lighter

const Metrics = struct {
    col_x: i32, // feed column
    col_w: i32,
    lx: i32,
    cw: i32,
    rail_x: i32,
    side_x: i32,
    wide: bool,
    _pad: [3]u8 = .{ 0, 0, 0 }, // A6

    comptime {
        assert(@sizeOf(Metrics) == 28); // 6×i32 + bool + 3 pad
    }
};

/// Externally-supplied pane geometry (the tiling foundation, S.1). When the
/// shell solves the layout as a space partition, it hands `layout()` the placed
/// pane rects through this; `layout()` then renders the real UI into them
/// instead of computing its own `metricsPage` geometry. Absent (null) ⇒ the
/// original self-computed three-pane (every existing caller, unchanged).
/// A7.2: cold — one per frame, passed by value across the boundary (B5).
pub const PaneGeom = struct {
    rail_x: i32,
    col_x: i32,
    col_w: i32,
    lx: i32,
    cw: i32,
    side_x: i32,
    wide: bool,
    /// Content-driven tile demo: how open the sidebar SEARCH tile is (0..1). At
    /// >0 the search-results tile grows and PUSHES the trending + follow tiles
    /// down — a pure reposition (no relayout), the cheap within-screen movement.
    /// The shell animates this; null geom ⇒ 0 (closed).
    search_open: f32 = 0,
    /// When true, `layout()` does NOT draw the nav rail — the shell renders it
    /// as its own movable TILE (`renderRail`) so it can slide/compress
    /// independently of the content (the decomposition that makes per-tile
    /// movement real). The rail's hit regions are still emitted by `renderRail`.
    rail_external: bool = false,
};

/// Toy Box — which LAYOUT-OWNING toy is active this frame. They are mutually
/// exclusive by construction (each resolves a post's on-screen position), so a
/// single selection, not one bit per toy. Only `.depth` is wired today; the rest
/// are reserved (stable enum values) per TOY_BOX_ROADMAP.md §8 so later slices
/// slot in without renumbering. An enum, not a struct → no A7 guard.
pub const ToyKind = enum(u8) { none, gravity, zero_g, liquid, tectonic, depth, lava, magnify };

/// The Toy Box selection handed into `layout()` as one plain value — the same
/// idiom as the `zones`/`geom` bundles (call sites pass `.{}` for "no toy").
/// A7.2: cold struct — exactly one per frame, never held in a collection. Guard
/// waived. (It carries only cold selection/tuning fields as more toys land.)
/// NOTE: Gravity is NOT a feed transform — it is the full-page SHATTER effect on
/// the Settings screen, driven entirely by the shell (see `shatter`), so it does
/// not appear in this feed-facing selection's draw path.
pub const ToyView = struct {
    feed_toy: ToyKind = .none,
    /// Animation time in seconds (the shell's clock, handed in as a plain value
    /// per B3/B4) — drives the Zero-G drift and the Liquid ripple phase.
    t: f32 = 0,
    /// Liquid slosh amplitude in px — a scroll-velocity-kicked spring the shell
    /// steps and settles to 0 (plain value; the core never reads the scroll state).
    flow: f32 = 0,
};

/// The geometry `layout()` would compute for a given window width + screen,
/// exposed so the shell can hold it as ANIMATED state (spring one frame's geom
/// toward the next screen's target and pass it back via `geom`) — the tiling
/// foundation's morph. A convex blend of two of these is itself a valid layout
/// (every boundary interpolates monotonically), so animating between screens
/// never overlaps. Returns the live per-screen geometry unchanged.
pub fn paneGeomFor(width: i32, active_screen: u8) PaneGeom {
    const m = metricsPage(width, active_screen);
    return .{ .rail_x = m.rail_x, .col_x = m.col_x, .col_w = m.col_w, .lx = m.lx, .cw = m.cw, .side_x = m.side_x, .wide = m.wide };
}

fn metricsFor(width: i32) Metrics {
    if (width >= wide_min) {
        const bx = @divTrunc(width - (rail_w + feed_w + side_w), 2);
        return .{ .rail_x = bx, .col_x = bx + rail_w, .col_w = feed_w, .lx = bx + rail_w + 22, .cw = feed_w - 44, .side_x = bx + rail_w + feed_w, .wide = true };
    }
    const col_w = @min(width, 600);
    const col_x = @divTrunc(width - col_w, 2);
    return .{ .rail_x = 0, .col_x = col_x, .col_w = col_w, .lx = col_x + 18, .cw = col_w - 36, .side_x = 0, .wide = false };
}

/// Home (and the focused thread) keep the NARROW reading column; every other
/// top-level page reads as a WIDE horizontal page. The right "column" stops being
/// a separate floating sidebar and becomes an EXTENSION attached to the content.
fn isWidePage(active_screen: u8) bool {
    return active_screen != screen_home and active_screen != screen_thread;
}

/// Page-aware metrics. On a wide page the glass spans the feed AND the old
/// sidebar span as ONE horizontal rectangle (`col_w` grows by `side_w`), with
/// `side_x` repurposed as the EXTENSION (widgets) start INSIDE the panel. `lx`/
/// `cw` stay the readable MAIN region, so post text never stretches — the extra
/// width is the extension. Home/thread (and any narrow window) are unchanged.
fn metricsPage(width: i32, active_screen: u8) Metrics {
    const m = metricsFor(width);
    if (!m.wide or !isWidePage(active_screen)) return m;
    const wide_w = m.col_w + side_w; // the glass spans the feed + the old sidebar span
    // PROFILE is the one wide page with a widget EXTENSION on the right: the main
    // region stays on the left (lx/cw unchanged), `side_x` = the extension start.
    if (active_screen == screen_profile) {
        return .{ .rail_x = m.rail_x, .col_x = m.col_x, .col_w = wide_w, .lx = m.lx, .cw = m.cw, .side_x = m.side_x, .wide = true };
    }
    // SETTINGS and MESSAGES are master–detail surfaces (a list + a detail
    // pane), so they want the FULL wide column with a modest gutter — not the
    // narrow centred reading column the other wide pages use. This sits the
    // title + panes left, toward the rail, so the two panes balance instead of
    // leaving a big left gap.
    if (active_screen == screen_settings or active_screen == screen_messages) {
        const gut: i32 = 34;
        return .{ .rail_x = m.rail_x, .col_x = m.col_x, .col_w = wide_w, .lx = m.col_x + gut, .cw = wide_w - 2 * gut, .side_x = m.col_x + wide_w, .wide = true };
    }
    // Every OTHER wide page (zone, browse, settings, Algorithms) centres a
    // comfortable content column in the wide glass — no side panel; the freed
    // sidebar space becomes breathing room (and a 2-up catalog on browse), not
    // an empty column. `side_x` parks at the right edge (no extension drawn).
    const cwid: i32 = 760;
    const left = @divTrunc(wide_w - cwid, 2);
    return .{ .rail_x = m.rail_x, .col_x = m.col_x, .col_w = wide_w, .lx = m.col_x + left + 22, .cw = cwid - 44, .side_x = m.col_x + wide_w, .wide = true };
}

/// The content column's x-range (logical px) for a given window width AND screen
/// — the panel the GPU field softens beneath (the glass backdrop blur). Mirrors
/// `metricsPage`, so the blur widens with the wide pages.
pub fn contentColumn(width: i32, active_screen: u8) struct { x: i32, w: i32 } {
    const m = metricsPage(width, active_screen);
    return .{ .x = m.col_x, .w = m.col_w };
}

fn rect(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, w: i32, h: i32, color: u32, radius: u8) !void {
    try dl.append(gpa, .{ .rect = .{
        .x = @intCast(x),
        .y = @intCast(y),
        .w = @intCast(@max(0, w)),
        .h = @intCast(@max(0, h)),
        .color = color,
        .radius = radius,
    } });
}

fn tri(gpa: Allocator, dl: *raster.DrawList, x0: i32, y0: i32, x1: i32, y1: i32, x2: i32, y2: i32, color: u32) !void {
    try dl.append(gpa, .{ .tri = .{
        .x0 = @intCast(x0),
        .y0 = @intCast(y0),
        .x1 = @intCast(x1),
        .y1 = @intCast(y1),
        .x2 = @intCast(x2),
        .y2 = @intCast(y2),
        .color = color,
    } });
}

/// The speech-bubble tail: a small triangle hugging the bubble's bottom
/// composer-side corner, pointing back at its sender — sent bubbles point
/// bottom-right, received bottom-left. It covers the corner's rounding and
/// pokes just past the edge, so the corner reads as the classic messenger
/// point. Drawn only where `BubbleRow.tail` says a same-sender run ends.
/// Draw it BEFORE the bubble rect: the triangle is hard-edged while the rect
/// is an antialiased SDF, so the rect on top buries the triangle's interior
/// edges and only the point past the corner shows. The point sits flush with
/// the bottom edge (collinear — any dip below reads as a ledge).
fn bubbleTail(gpa: Allocator, dl: *raster.DrawList, mine: bool, bx: i32, by: i32, bw: i32, hh: i32, color: u32) !void {
    const bot = by + hh;
    const nib = @min(14, @max(0, hh - 4)); // stay inside a mid-growth bubble
    if (mine) {
        const cx = bx + bw;
        try tri(gpa, dl, cx - nib, bot, cx, bot - nib, cx + 6, bot, color);
    } else {
        try tri(gpa, dl, bx + nib, bot, bx, bot - nib, bx - 6, bot, color);
    }
}

/// One proportional glyph; returns the pen x after it.
fn glyph1(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, weight: text.Weight, x: i32, baseline: i32, color: u32, px: u16, cp: u32) !i32 {
    try dl.append(gpa, .{ .text = .{
        .x = @intCast(x),
        .baseline = @intCast(baseline),
        .codepoint = cp,
        .color = color,
        .px = px,
        .weight = @intFromEnum(weight),
    } });
    return x + @as(i32, @intCast(text.advance(e, weight, cp, px)));
}

/// A UTF-8 run; returns the pen x after it.
fn str(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, weight: text.Weight, x0: i32, baseline: i32, color: u32, px: u16, s: []const u8) !i32 {
    var x = x0;
    var it = (std.unicode.Utf8View.init(s) catch return x).iterator();
    while (it.nextCodepoint()) |cp| x = try glyph1(gpa, dl, e, weight, x, baseline, color, px, cp);
    return x;
}

/// Word-wrap `body` to `maxw`, honouring explicit '\n' HARD breaks; returns the
/// baseline after the last line. When `draw_it` is false it only measures
/// (advances the baseline) without emitting glyphs — used to size off-screen
/// posts without painting them. A post authored with line breaks (the composer
/// inserts real '\n's) keeps them in the feed/thread, matching what the composer
/// shows (`wrapDraft` already honours '\n'). A body with NO '\n' is a single
/// segment, so it wraps byte-for-byte as before — the height cache and the
/// long-feed coordinate accounting (the 800-post regression) depend on that.
/// A quote-post's embedded card: a bordered mini-post (quoted name · @handle,
/// then the quoted text) drawn between the body and the engagement row. Dual-use
/// like `trayLayout` — returns the card height for the measure pass; when
/// `draw_it`, also paints it and emits a `.quote_open` tap region carrying the
/// QUOTING post index `pi` (the shell opens the quoted thread from that item's
/// quote_uri/cid). The quoted text is clamped to a few lines so a card stays
/// compact. Pure.
fn quoteCard(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, x0: i32, y0: i32, w: i32, name: []const u8, handle: []const u8, body: []const u8, draw_it: bool, regions: ?*Regions, pi: usize) error{OutOfMemory}!i32 {
    const qpad: i32 = 12;
    const qline: i32 = 19;
    const inner = w - qpad * 2;
    const head_base = y0 + qpad + 13;
    const text_top = head_base + 7 + qline;
    // Measure the (clamped) quoted text to size the border, then draw border →
    // header → text so the text lands on top of the fill.
    const text_end = try wrapBodyLimited(gpa, dl, e, x0 + qpad, text_top, inner, muted, 14, body, qline, false, null, 4, null);
    const h = (text_end - qline) - y0 + qpad + 8;
    if (draw_it) {
        try rect(gpa, dl, x0, y0, w, h, (0x10 << 24) | 0x00FFFFFF, 12); // faint inset fill = the card
        const nm = if (name.len > 0) name else handle;
        var hx = try str(gpa, dl, e, .semibold, x0 + qpad, head_base, ink, 14, nm);
        if (name.len > 0) {
            hx = try str(gpa, dl, e, .regular, hx + 6, head_base, faint, 13, "@");
            _ = try str(gpa, dl, e, .regular, hx, head_base, faint, 13, handle);
        }
        _ = try wrapBodyLimited(gpa, dl, e, x0 + qpad, text_top, inner, muted, 14, body, qline, true, null, 4, null);
        try emitRegion(gpa, regions, x0, y0, w, @intCast(@max(0, @min(32767, h))), @intCast(pi), .quote_open);
    }
    return h;
}

fn wrapBody(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, x0: i32, first_baseline: i32, maxw: i32, color: u32, px: u16, body: []const u8, line_h: i32, draw_it: bool, style: ?*const BodyTags) !i32 {
    return wrapBodyPen(gpa, dl, e, x0, first_baseline, maxw, color, px, body, line_h, draw_it, style, null, null, null);
}

/// `wrapBody` clamped to at most `max_lines` visual lines (main-feed Read-more).
/// Sets `overflow.*` = true when the body had more than fit, so the caller can
/// draw the "Read more" doorway. `max_lines` null ⇒ unclamped (identical to
/// `wrapBody`). The measure and paint passes call this with the SAME max_lines,
/// so their geometry agrees.
fn wrapBodyLimited(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, x0: i32, first_baseline: i32, maxw: i32, color: u32, px: u16, body: []const u8, line_h: i32, draw_it: bool, style: ?*const BodyTags, max_lines: ?u32, overflow: ?*bool) !i32 {
    return wrapBodyPen(gpa, dl, e, x0, first_baseline, maxw, color, px, body, line_h, draw_it, style, null, max_lines, overflow);
}

/// `wrapBody` that also reports the final pen x (the caret seat after the
/// last drawn glyph) — the editor-shaped surfaces need it; everyone else
/// calls `wrapBody` and never sees the parameter. `max_lines`/`overflow` drive
/// the main-feed Read-more clamp (null ⇒ unclamped, the original behaviour).
fn wrapBodyPen(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, x0: i32, first_baseline: i32, maxw: i32, color: u32, px: u16, body: []const u8, line_h: i32, draw_it: bool, style: ?*const BodyTags, end_x: ?*i32, max_lines: ?u32, overflow: ?*bool) !i32 {
    var baseline = first_baseline;
    var seg_start: usize = 0;
    // The line budget shared across paragraphs; unclamped calls get a budget so
    // large no real body reaches it (std.math.maxInt keeps the arithmetic total).
    var budget: i32 = if (max_lines) |m| @intCast(m) else std.math.maxInt(i32);
    while (true) {
        const nl = std.mem.indexOfScalarPos(u8, body, seg_start, '\n') orelse body.len;
        baseline = try wrapLine(gpa, dl, e, x0, baseline, maxw, color, px, body[seg_start..nl], line_h, draw_it, style, end_x, &budget, overflow);
        if (nl == body.len) break;
        seg_start = nl + 1; // step past the '\n' — the next paragraph starts a fresh line
        if (budget <= 0) { // more paragraphs remain but the clamp is spent
            if (overflow) |o| o.* = true;
            break;
        }
    }
    return baseline;
}

/// Word-wrap one paragraph segment (no '\n') to `maxw`; greedy break at the
/// last space before overflow. A single RUN longer than the whole line (a
/// long word, a URL, "hmmm…") HARD-BREAKS at the last codepoint that fits —
/// text never escapes its pane. The per-line worker behind `wrapBody`.
fn wrapLine(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, x0: i32, first_baseline: i32, maxw: i32, color: u32, px: u16, body: []const u8, line_h: i32, draw_it: bool, style: ?*const BodyTags, end_x: ?*i32, budget: *i32, overflow: ?*bool) !i32 {
    const maxw_u: u32 = @intCast(@max(0, maxw));
    var baseline = first_baseline;
    var line_start: usize = 0;
    var last_space: usize = 0;
    var have_space = false;
    var i: usize = 0;
    // The main-feed Read-more clamp: `budget` counts the visual lines this post
    // may still commit. When it runs out with content left, stop and flag the
    // overflow — the caller draws a "Read more" doorway and expands on tap. An
    // unclamped call passes a huge budget, so every commit is unblocked.
    while (i <= body.len) : (i += 1) {
        const at_end = i == body.len;
        if (!at_end and body[i] != ' ') continue;
        const candidate = body[line_start..i];
        if (text.measure(e, .regular, candidate, px) > maxw_u) {
            if (have_space) {
                if (budget.* <= 0) {
                    if (overflow) |o| o.* = true;
                    return baseline;
                }
                if (draw_it) try drawBodyRun(gpa, dl, e, x0, baseline, color, px, body, line_start, last_space, style);
                baseline += line_h;
                budget.* -= 1;
                line_start = last_space + 1;
                have_space = false;
                i = line_start;
                continue;
            }
            // No space to break at: hard-break the run mid-word — the
            // longest codepoint prefix that fits, and always at least one
            // codepoint so a too-narrow pane still makes progress.
            var fit = line_start;
            var probe = line_start;
            while (probe < i) {
                const cp_len = std.unicode.utf8ByteSequenceLength(body[probe]) catch 1;
                const next = @min(probe + cp_len, i);
                if (fit > line_start and
                    text.measure(e, .regular, body[line_start..next], px) > maxw_u) break;
                probe = next;
                fit = next;
            }
            if (budget.* <= 0) {
                if (overflow) |o| o.* = true;
                return baseline;
            }
            if (draw_it) try drawBodyRun(gpa, dl, e, x0, baseline, color, px, body, line_start, fit, style);
            baseline += line_h;
            budget.* -= 1;
            line_start = fit;
            i = line_start;
            continue;
        }
        if (at_end) {
            if (budget.* <= 0) {
                if (overflow) |o| o.* = true;
                return baseline;
            }
            if (draw_it) try drawBodyRun(gpa, dl, e, x0, baseline, color, px, body, line_start, i, style);
            if (end_x) |ex| ex.* = x0 + @as(i32, @intCast(text.measure(e, .regular, body[line_start..i], px)));
            baseline += line_h;
            budget.* -= 1;
            break;
        }
        last_space = i;
        have_space = true;
    }
    return baseline;
}

/// Inline-hashtag styling for a post body: the colour to light `#tags`, plus the
/// region sink + post identity needed to make each tag tappable. Each lit tag
/// emits a `.tag_inline` region carrying (post index, the tag's index within
/// `tags`) — the same (post, tag) pair the tray pills carry, so the shell opens
/// the zone the same way. Null when the body is drawn plain (measure passes and
/// the condensed thread ancestors). A7.2: cold — one transient per drawn post.
const BodyTags = struct {
    color: u32,
    regions: ?*Regions,
    pi: usize,
    tags: []const []const u8,
};

/// Index of `name` (a bare tag, no '#') in `tags`, case-insensitive — the served
/// display casing may differ from how the author typed it. Null if absent.
fn tagIndexOf(tags: []const []const u8, name: []const u8) ?usize {
    for (tags, 0..) |t, i| if (std.ascii.eqlIgnoreCase(t, name)) return i;
    return null;
}

/// Draw one wrapped line `body[a..b)` at (x0, baseline) in `color`. With a
/// `style`, any `#tag` run (same word-start rule the composer wrote facets with —
/// `compose.tagSpanAt`) is lit in `style.color` and gets a `.tag_inline` tap
/// region; without one it's a single plain `str`, byte-for-byte the old draw.
/// The wrap geometry is unaffected: only the DRAW is split into runs, and glyph
/// advance is per-glyph (no kerning), so split runs land exactly where one `str`
/// would have — wrap points and width are identical whether or not tags are lit.
fn drawBodyRun(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, x0: i32, baseline: i32, color: u32, px: u16, body: []const u8, a: usize, b: usize, style: ?*const BodyTags) error{OutOfMemory}!void {
    const st = style orelse {
        _ = try str(gpa, dl, e, .regular, x0, baseline, color, px, body[a..b]);
        return;
    };
    var x = x0;
    var i = a;
    while (i < b) {
        if (compose.tagSpanAt(body, i)) |raw_end| {
            const end = @min(raw_end, b); // a tag never spans a wrapped line; clamp defensively
            const startx = x;
            x = try str(gpa, dl, e, .regular, startx, baseline, st.color, px, body[i..end]);
            if (st.regions) |rg| if (tagIndexOf(st.tags, body[i + 1 .. end])) |ti| {
                try rg.append(gpa, .{
                    .x = @intCast(std.math.clamp(startx, -32768, 32767)),
                    .y = @intCast(std.math.clamp(baseline - @as(i32, @intCast(px)) + 4, -32768, 32767)),
                    .w = @intCast(@max(0, @min(32767, x - startx))),
                    .h = @intCast(@max(0, @min(32767, @as(i32, @intCast(px))))),
                    .post = @intCast(st.pi),
                    .kind = .tag_inline,
                    ._pad = @intCast(@min(ti, 255)),
                });
            };
            i = end;
            continue;
        }
        var j = i + 1;
        while (j < b and compose.tagSpanAt(body, j) == null) j += 1;
        x = try str(gpa, dl, e, .regular, x, baseline, color, px, body[i..j]);
        i = j;
    }
}

/// The tag tray: a wrapping row of tappable "#tag" pills below a post — each a
/// doorway into its zone (the feed↔zone stitch). Measures (`draw_it = false`) or
/// paints + emits regions (`draw_it = true`) and returns the tray's pixel height,
/// 0 when the post has no tags. The pill set + column width determine the height,
/// so it is SCROLL-INVARIANT. Each pill emits a `.zone_jump` region carrying the
/// post index and, in `_pad`, the tag's index — the shell resolves (post, tag) →
/// zone. `y` is the tray's top; the first pill row sits there.
fn trayLayout(
    gpa: Allocator,
    dl: *raster.DrawList,
    e: *const text.Engine,
    x: i32,
    y: i32,
    w: i32,
    tags: []const []const u8,
    accent: u32,
    draw_it: bool,
    regions: ?*Regions,
    pi: usize,
) error{OutOfMemory}!i32 {
    if (tags.len == 0) return 0;
    const pad_x: i32 = 11;
    const pill_h: i32 = 26;
    const row_gap: i32 = 8;
    const pill_gap: i32 = 8;
    const size: u16 = 13;
    const pill_bg: u32 = 0x16EDEAE0; // a faint ink wash — reads as a chip, not a button
    var cx = x;
    var cy = y;
    var buf: [160]u8 = undefined;
    for (tags, 0..) |tag, ti| {
        const label = std.fmt.bufPrint(&buf, "#{s}", .{tag}) catch continue;
        const tw: i32 = @intCast(text.measure(e, .regular, label, size));
        const pw = tw + 2 * pad_x;
        // Wrap to the next row when this pill would overflow the column (but keep
        // at least one pill per row, however narrow the column).
        if (cx + pw > x + w and cx > x) {
            cx = x;
            cy += pill_h + row_gap;
        }
        if (draw_it) {
            try rect(gpa, dl, cx, cy, pw, pill_h, pill_bg, @intCast(pill_h >> 1));
            _ = try str(gpa, dl, e, .regular, cx + pad_x, cy + 18, accent, size, label);
            if (regions) |rg| try rg.append(gpa, .{
                .x = @intCast(std.math.clamp(cx, -32768, 32767)),
                .y = @intCast(std.math.clamp(cy, -32768, 32767)),
                .w = @intCast(@max(0, @min(32767, pw))),
                .h = @intCast(pill_h),
                .post = @intCast(pi),
                .kind = .zone_jump,
                ._pad = @intCast(@min(ti, 255)), // the tag index, for the shell to resolve
            });
        }
        cx += pw + pill_gap;
    }
    return (cy + pill_h) - y;
}

/// Record the body glyphs just appended to `dl` (the range [from, dl.len)) into
/// `out`: the `.text` items only, each with its advance width and a line index
/// that rises on every baseline jump (so copy can reinsert the line breaks).
/// Pure — called for the rooted post's body alone. Replaces whatever `out` held.
fn captureBody(out: *SelGlyphs, gpa: Allocator, e: *const text.Engine, dl: *const raster.DrawList, from: usize) !void {
    out.clearRetainingCapacity();
    var lineno: u16 = 0;
    var prev_baseline: ?i16 = null;
    var i: usize = from;
    while (i < dl.len) : (i += 1) {
        switch (dl.get(i)) {
            .text => |t| {
                if (prev_baseline) |pb| {
                    if (t.baseline != pb) lineno += 1;
                }
                prev_baseline = t.baseline;
                const adv = text.advance(e, @enumFromInt(t.weight), t.codepoint, t.px);
                try out.append(gpa, .{
                    .cp = t.codepoint,
                    .x = t.x,
                    .baseline = t.baseline,
                    .w = @intCast(@min(@as(u32, std.math.maxInt(u16)), adv)),
                    .line = lineno,
                });
            },
            else => {},
        }
    }
}

// ---------------------------------------------------------------------------
// Toy Box: Depth feed — the draw-range affine transform (re-layout family)
//
// A layout-owning cosmetic toy decorates a post by SCALING the draw items it
// already emitted, in place — not by re-measuring. The natural monotonic stack
// runs first (so `y`, the scroll cursor, and the `heights` cache stay exact);
// then, per visible post, we scale its emitted `[start, dl.len)` slice about a
// pivot. Because both the software `raster.paint` and the GPU `buildVertices`
// consume the SAME DrawList, one pure transform decorates BOTH renderers. This
// primitive is the shared mechanism the re-layout family (depth, tectonic) uses;
// extract to a `core/toy.zig` at the real cut point, when tectonic needs it (F4).

fn clampI16(v: f32) i16 {
    return @intFromFloat(std.math.clamp(@round(v), -32768, 32767));
}
fn clampU16(v: f32) u16 {
    return @intFromFloat(std.math.clamp(@round(v), 0, 65535));
}
fn clampU8(v: f32) u8 {
    return @intFromFloat(std.math.clamp(@round(v), 0, 255));
}

/// Scale every draw item in `dl[start..end)` by `s` about pivot (cx, cy), then
/// translate by (dx, dy) — mutating coordinates in place. Positions move with the
/// pivot; sizes/font-px/stroke/radius scale by magnitude only (they don't
/// translate). Affine ⇒ each endpoint transforms independently under the one
/// shared pivot. The clamps make a pathological scale degrade to a clipped edge
/// rather than a wrapped i16. `.cell` never appears in a feed post's range (the
/// feed emits text/rect/line/tri), but it is handled so the primitive is
/// reusable by any surface. PURE (B2) — plain data in, plain data out.
pub fn transformDlRange(dl: *raster.DrawList, start: usize, end: usize, s: f32, cx: f32, cy: f32, dx: f32, dy: f32) void {
    var sl = dl.slice();
    const tags = sl.items(.tags);
    const data = sl.items(.data);
    var i: usize = start;
    while (i < end) : (i += 1) {
        switch (tags[i]) {
            .text => {
                const t = &data[i].text;
                t.x = clampI16(cx + (@as(f32, @floatFromInt(t.x)) - cx) * s + dx);
                t.baseline = clampI16(cy + (@as(f32, @floatFromInt(t.baseline)) - cy) * s + dy);
                t.px = @intFromFloat(std.math.clamp(@round(@as(f32, @floatFromInt(t.px)) * s), 4, 200));
            },
            .rect => {
                const r = &data[i].rect;
                r.x = clampI16(cx + (@as(f32, @floatFromInt(r.x)) - cx) * s + dx);
                r.y = clampI16(cy + (@as(f32, @floatFromInt(r.y)) - cy) * s + dy);
                r.w = clampU16(@as(f32, @floatFromInt(r.w)) * s);
                r.h = clampU16(@as(f32, @floatFromInt(r.h)) * s);
                r.radius = clampU8(@as(f32, @floatFromInt(r.radius)) * s);
            },
            .line => {
                const l = &data[i].line;
                l.x0 = clampI16(cx + (@as(f32, @floatFromInt(l.x0)) - cx) * s + dx);
                l.x1 = clampI16(cx + (@as(f32, @floatFromInt(l.x1)) - cx) * s + dx);
                l.y0 = clampI16(cy + (@as(f32, @floatFromInt(l.y0)) - cy) * s + dy);
                l.y1 = clampI16(cy + (@as(f32, @floatFromInt(l.y1)) - cy) * s + dy);
                l.thickness = clampU8(@as(f32, @floatFromInt(l.thickness)) * s);
            },
            .tri => {
                const t = &data[i].tri;
                t.x0 = clampI16(cx + (@as(f32, @floatFromInt(t.x0)) - cx) * s + dx);
                t.x1 = clampI16(cx + (@as(f32, @floatFromInt(t.x1)) - cx) * s + dx);
                t.x2 = clampI16(cx + (@as(f32, @floatFromInt(t.x2)) - cx) * s + dx);
                t.y0 = clampI16(cy + (@as(f32, @floatFromInt(t.y0)) - cy) * s + dy);
                t.y1 = clampI16(cy + (@as(f32, @floatFromInt(t.y1)) - cy) * s + dy);
                t.y2 = clampI16(cy + (@as(f32, @floatFromInt(t.y2)) - cy) * s + dy);
            },
            .cell => {
                const c = &data[i].cell;
                c.x = clampU16(cx + (@as(f32, @floatFromInt(c.x)) - cx) * s + dx);
                c.y = clampU16(cy + (@as(f32, @floatFromInt(c.y)) - cy) * s + dy);
            },
        }
    }
}

/// The same affine on the per-post hit `Region`s emitted in `[start, end)`, so a
/// scaled post is TAPPABLE where it is drawn (and — on the live GPU path — the SDF
/// engagement icons, which position off `regions` rects, follow the loom for
/// free). Icon SIZE is a global uniform on the GPU pass, so icons track position
/// but keep natural size in v1 (Region has no spare byte to carry a scale; A7).
pub fn transformRegionsRange(regions: *Regions, start: usize, end: usize, s: f32, cx: f32, cy: f32, dx: f32, dy: f32) void {
    var i: usize = start;
    while (i < end) : (i += 1) {
        const r = &regions.items[i];
        r.x = clampI16(cx + (@as(f32, @floatFromInt(r.x)) - cx) * s + dx);
        r.y = clampI16(cy + (@as(f32, @floatFromInt(r.y)) - cy) * s + dy);
        r.w = clampU16(@as(f32, @floatFromInt(r.w)) * s);
        r.h = clampU16(@as(f32, @floatFromInt(r.h)) * s);
    }
}

/// A post's engagement, widened so like+reply+boost cannot overflow. PURE.
fn engagementOf(p: PostView) u64 {
    return @as(u64, p.like) + @as(u64, p.reply) + @as(u64, p.boost);
}

/// Depth-feed "loom" scale for one post, given the visible slice's engagement
/// range: quiet posts recede (~0.80), the loudest looms (~1.12). Neutral 1.0-ish
/// at the midpoint; a flat slice (all equal) maps to 0.5 → no div-by-zero. PURE.
fn loomScale(p: PostView, eng_min: u64, eng_max: u64) f32 {
    const norm: f32 = if (eng_max == eng_min)
        0.5
    else
        @as(f32, @floatFromInt(engagementOf(p) - eng_min)) / @as(f32, @floatFromInt(eng_max - eng_min));
    return 0.8 + norm * 0.32;
}

fn fxi(v: f32) i32 {
    return @intFromFloat(@round(v));
}

fn line(gpa: Allocator, dl: *raster.DrawList, x0: i32, y0: i32, x1: i32, y1: i32, color: u32, th: u8) !void {
    try dl.append(gpa, .{ .line = .{ .x0 = @intCast(x0), .y0 = @intCast(y0), .x1 = @intCast(x1), .y1 = @intCast(y1), .color = color, .thickness = th } });
}

// Minimalist line-art icons in an s×s box at (x,y). Reply and repost are
// outlines; the heart is filled (its colour carries the liked state).
fn iconReply(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, color: u32) !void {
    const f: f32 = @floatFromInt(s);
    const bh = fxi(f * 0.64);
    try line(gpa, dl, x, y, x + s, y, color, 2); // top
    try line(gpa, dl, x, y, x, y + bh, color, 2); // left
    try line(gpa, dl, x + s, y, x + s, y + bh, color, 2); // right
    try line(gpa, dl, x, y + bh, x + fxi(f * 0.40), y + bh, color, 2); // bottom-left
    try line(gpa, dl, x + fxi(f * 0.64), y + bh, x + s, y + bh, color, 2); // bottom-right
    try line(gpa, dl, x + fxi(f * 0.40), y + bh, x + fxi(f * 0.26), y + s, color, 2); // tail down
    try line(gpa, dl, x + fxi(f * 0.26), y + s, x + fxi(f * 0.64), y + bh, color, 2); // tail back
}

fn iconRepost(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, color: u32) !void {
    const f: f32 = @floatFromInt(s);
    // top arrow → right
    try line(gpa, dl, x + fxi(f * 0.06), y + fxi(f * 0.34), x + fxi(f * 0.82), y + fxi(f * 0.34), color, 2);
    try line(gpa, dl, x + fxi(f * 0.82), y + fxi(f * 0.34), x + fxi(f * 0.62), y + fxi(f * 0.16), color, 2);
    try line(gpa, dl, x + fxi(f * 0.82), y + fxi(f * 0.34), x + fxi(f * 0.62), y + fxi(f * 0.52), color, 2);
    // bottom arrow ← left
    try line(gpa, dl, x + fxi(f * 0.18), y + fxi(f * 0.70), x + fxi(f * 0.94), y + fxi(f * 0.70), color, 2);
    try line(gpa, dl, x + fxi(f * 0.18), y + fxi(f * 0.70), x + fxi(f * 0.38), y + fxi(f * 0.52), color, 2);
    try line(gpa, dl, x + fxi(f * 0.18), y + fxi(f * 0.70), x + fxi(f * 0.38), y + fxi(f * 0.88), color, 2);
}

/// Bookmark: an outline tag with a V-notch at the bottom.
fn iconBookmark(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, c: u32) !void {
    const f: f32 = @floatFromInt(s);
    const left = x + fxi(f * 0.24);
    const right = x + fxi(f * 0.76);
    const top = y + fxi(f * 0.08);
    const bot = y + fxi(f * 0.92);
    const mid = x + fxi(f * 0.5);
    const notch = y + fxi(f * 0.64);
    try line(gpa, dl, left, top, right, top, c, 2);
    try line(gpa, dl, left, top, left, bot, c, 2);
    try line(gpa, dl, right, top, right, bot, c, 2);
    try line(gpa, dl, left, bot, mid, notch, c, 2);
    try line(gpa, dl, right, bot, mid, notch, c, 2);
}

/// Share: an up-arrow rising out of an open tray (the familiar share glyph).
fn iconShare(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, c: u32) !void {
    const f: f32 = @floatFromInt(s);
    const cx = x + fxi(f * 0.5);
    try line(gpa, dl, cx, y + fxi(f * 0.06), cx, y + fxi(f * 0.62), c, 2); // shaft
    try line(gpa, dl, cx, y + fxi(f * 0.06), x + fxi(f * 0.28), y + fxi(f * 0.30), c, 2); // left head
    try line(gpa, dl, cx, y + fxi(f * 0.06), x + fxi(f * 0.72), y + fxi(f * 0.30), c, 2); // right head
    const left = x + fxi(f * 0.20);
    const right = x + fxi(f * 0.80);
    const ttop = y + fxi(f * 0.46);
    const bot = y + fxi(f * 0.92);
    try line(gpa, dl, left, ttop, left, bot, c, 2);
    try line(gpa, dl, right, ttop, right, bot, c, 2);
    try line(gpa, dl, left, bot, right, bot, c, 2);
}

/// More: three dots (⋯).
fn iconMore(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, c: u32) !void {
    const f: f32 = @floatFromInt(s);
    const r = @max(1, fxi(f * 0.09));
    const cy = y + fxi(f * 0.5);
    for ([_]f32{ 0.16, 0.5, 0.84 }) |px| {
        try rect(gpa, dl, x + fxi(f * px) - r, cy - r, r * 2, r * 2, c, @intCast(r));
    }
}

fn iconHeart(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, color: u32) !void {
    const f: f32 = @floatFromInt(s);
    const rr = f * 0.27;
    const cyb = f * 0.32;
    try rect(gpa, dl, x + fxi(f * 0.30 - rr), y + fxi(cyb - rr), fxi(rr * 2), fxi(rr * 2), color, @intCast(fxi(rr)));
    try rect(gpa, dl, x + fxi(f * 0.70 - rr), y + fxi(cyb - rr), fxi(rr * 2), fxi(rr * 2), color, @intCast(fxi(rr)));
    const top = f * 0.22;
    const bot = f * 0.96;
    const cxh = f * 0.5;
    const half_top = f * 0.47;
    var ry: i32 = fxi(top);
    const ry_bot: i32 = fxi(bot);
    while (ry <= ry_bot) : (ry += 1) {
        const tp = (@as(f32, @floatFromInt(ry)) - top) / (bot - top);
        const hw = half_top * (1.0 - tp);
        const lx_ = if (hw <= 0) fxi(cxh) else fxi(cxh - hw);
        const rx_ = if (hw <= 0) fxi(cxh) else fxi(cxh + hw);
        try line(gpa, dl, x + lx_, y + ry, x + rx_, y + ry, color, 1);
    }
}

/// The UNLIKED like button: a HOLLOW heart OUTLINE, so a tap can visibly fill
/// it with red. Traced as the parametric heart curve (x=16sin³t, y=13cos t −
/// 5cos2t − 2cos3t − cos4t) — one clean closed stroke, normalized into the s×s
/// icon box — rather than a scanline fill, which is solid and cannot read as
/// empty. The filled `iconHeart` above is the LIKED state.
fn iconHeartHollow(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, color: u32) !void {
    const f: f32 = @floatFromInt(s);
    const segs: usize = 28;
    var prev_x: i32 = 0;
    var prev_y: i32 = 0;
    var i: usize = 0;
    while (i <= segs) : (i += 1) {
        const t = (@as(f32, @floatFromInt(i)) / @as(f32, @floatFromInt(segs))) * 6.2831853;
        const st = @sin(t);
        const hx = 16.0 * st * st * st;
        const hy = 13.0 * @cos(t) - 5.0 * @cos(2.0 * t) - 2.0 * @cos(3.0 * t) - @cos(4.0 * t);
        // Normalize: hx∈[-16,16] → centred horizontally; hy∈[-17,12], flipped to
        // screen-y-down and centred so the lobes sit high and the point at ~0.96.
        const nx = 0.5 + (hx / 16.0) * 0.46;
        const ny = 0.52 - (hy / 17.0) * 0.44;
        const px = x + fxi(nx * f);
        const py = y + fxi(ny * f);
        if (i > 0) try line(gpa, dl, prev_x, prev_y, px, py, color, 1);
        prev_x = px;
        prev_y = py;
    }
}

fn ring(gpa: Allocator, dl: *raster.DrawList, cx: i32, cy: i32, r: f32, color: u32, th: u8, segs: usize) !void {
    var i: usize = 0;
    while (i < segs) : (i += 1) {
        const a0 = @as(f32, @floatFromInt(i)) / @as(f32, @floatFromInt(segs)) * std.math.tau;
        const a1 = @as(f32, @floatFromInt(i + 1)) / @as(f32, @floatFromInt(segs)) * std.math.tau;
        try line(gpa, dl, cx + fxi(std.math.cos(a0) * r), cy + fxi(std.math.sin(a0) * r), cx + fxi(std.math.cos(a1) * r), cy + fxi(std.math.sin(a1) * r), color, th);
    }
}

fn iconHome(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, c: u32) !void {
    const f: f32 = @floatFromInt(s);
    try line(gpa, dl, x + fxi(f * 0.5), y, x + s, y + fxi(f * 0.46), c, 2);
    try line(gpa, dl, x + fxi(f * 0.5), y, x, y + fxi(f * 0.46), c, 2);
    try line(gpa, dl, x + fxi(f * 0.16), y + fxi(f * 0.42), x + fxi(f * 0.16), y + s, c, 2);
    try line(gpa, dl, x + fxi(f * 0.84), y + fxi(f * 0.42), x + fxi(f * 0.84), y + s, c, 2);
    try line(gpa, dl, x + fxi(f * 0.16), y + s, x + fxi(f * 0.84), y + s, c, 2);
}

fn iconSearch(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, c: u32) !void {
    const f: f32 = @floatFromInt(s);
    try ring(gpa, dl, x + fxi(f * 0.42), y + fxi(f * 0.42), f * 0.34, c, 2, 10);
    try line(gpa, dl, x + fxi(f * 0.66), y + fxi(f * 0.66), x + s, y + s, c, 2);
}

fn iconPerson(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, c: u32) !void {
    const f: f32 = @floatFromInt(s);
    const hr = f * 0.20;
    try rect(gpa, dl, x + fxi(f * 0.5 - hr), y + fxi(f * 0.04), fxi(hr * 2), fxi(hr * 2), c, @intCast(fxi(hr)));
    try line(gpa, dl, x + fxi(f * 0.16), y + s, x + fxi(f * 0.30), y + fxi(f * 0.58), c, 2);
    try line(gpa, dl, x + fxi(f * 0.84), y + s, x + fxi(f * 0.70), y + fxi(f * 0.58), c, 2);
    try line(gpa, dl, x + fxi(f * 0.30), y + fxi(f * 0.58), x + fxi(f * 0.70), y + fxi(f * 0.58), c, 2);
    try line(gpa, dl, x + fxi(f * 0.16), y + s, x + fxi(f * 0.84), y + s, c, 2);
}

fn iconGear(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, c: u32) !void {
    const f: f32 = @floatFromInt(s);
    const cx = x + fxi(f * 0.5);
    const cy = y + fxi(f * 0.5);
    try ring(gpa, dl, cx, cy, f * 0.32, c, 2, 8);
    try rect(gpa, dl, cx - fxi(f * 0.09), cy - fxi(f * 0.09), fxi(f * 0.18), fxi(f * 0.18), c, @intCast(fxi(f * 0.09)));
}

/// Sliders / equalizer — "Algorithms" (tuning your lenses). Three rails, each
/// with a knob at a different position, so it reads as adjustable controls.
fn iconAlgorithms(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, c: u32) !void {
    const f: f32 = @floatFromInt(s);
    const x0 = x + fxi(f * 0.10);
    const x1 = x + fxi(f * 0.90);
    const kr = @max(3, fxi(f * 0.16));
    const rows = [_]f32{ 0.24, 0.5, 0.76 };
    const knobs = [_]f32{ 0.66, 0.34, 0.58 };
    for (rows, knobs) |ry, kx| {
        const yy = y + fxi(f * ry);
        try line(gpa, dl, x0, yy, x1, yy, c, 2);
        const cx = x + fxi(f * kx);
        try rect(gpa, dl, cx - @divTrunc(kr, 2), yy - @divTrunc(kr, 2), kr, kr, c, @intCast(@divTrunc(kr, 2)));
    }
}

/// Zones — a hash (#), since a zone IS a hashtag-become-place. Two verticals
/// slightly splayed and two horizontals, the way a drawn `#` leans.
fn iconZones(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, c: u32) !void {
    const f: f32 = @floatFromInt(s);
    try line(gpa, dl, x + fxi(f * 0.34), y + fxi(f * 0.08), x + fxi(f * 0.24), y + fxi(f * 0.92), c, 2);
    try line(gpa, dl, x + fxi(f * 0.72), y + fxi(f * 0.08), x + fxi(f * 0.62), y + fxi(f * 0.92), c, 2);
    try line(gpa, dl, x + fxi(f * 0.12), y + fxi(f * 0.36), x + fxi(f * 0.86), y + fxi(f * 0.36), c, 2);
    try line(gpa, dl, x + fxi(f * 0.08), y + fxi(f * 0.64), x + fxi(f * 0.82), y + fxi(f * 0.64), c, 2);
}

/// A right-pointing disclosure chevron (the iOS ">"). Two strokes meeting at a
/// point, drawn within an `s`×`s` box.
fn iconChevron(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, c: u32) !void {
    const f: f32 = @floatFromInt(s);
    const tipx = x + fxi(f * 0.62);
    try line(gpa, dl, x + fxi(f * 0.40), y + fxi(f * 0.24), tipx, y + fxi(f * 0.5), c, 2);
    try line(gpa, dl, tipx, y + fxi(f * 0.5), x + fxi(f * 0.40), y + fxi(f * 0.76), c, 2);
}

/// A notification bell — a dome on a base with a clapper dot.
fn iconBell(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, c: u32) !void {
    const f: f32 = @floatFromInt(s);
    try line(gpa, dl, x + fxi(f * 0.5), y + fxi(f * 0.08), x + fxi(f * 0.5), y + fxi(f * 0.16), c, 2); // top stem
    try line(gpa, dl, x + fxi(f * 0.24), y + fxi(f * 0.70), x + fxi(f * 0.30), y + fxi(f * 0.30), c, 2); // left wall
    try line(gpa, dl, x + fxi(f * 0.76), y + fxi(f * 0.70), x + fxi(f * 0.70), y + fxi(f * 0.30), c, 2); // right wall
    try line(gpa, dl, x + fxi(f * 0.30), y + fxi(f * 0.30), x + fxi(f * 0.70), y + fxi(f * 0.30), c, 2); // shoulder
    try line(gpa, dl, x + fxi(f * 0.18), y + fxi(f * 0.70), x + fxi(f * 0.82), y + fxi(f * 0.70), c, 2); // rim
    try rect(gpa, dl, x + fxi(f * 0.44), y + fxi(f * 0.78), fxi(f * 0.12), fxi(f * 0.12), c, @intCast(fxi(f * 0.06))); // clapper
}

/// A safety shield — a crest outline narrowing to a point.
fn iconShield(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, c: u32) !void {
    const f: f32 = @floatFromInt(s);
    const tipx = x + fxi(f * 0.5);
    try line(gpa, dl, x + fxi(f * 0.18), y + fxi(f * 0.16), tipx, y + fxi(f * 0.08), c, 2); // top-left
    try line(gpa, dl, x + fxi(f * 0.82), y + fxi(f * 0.16), tipx, y + fxi(f * 0.08), c, 2); // top-right
    try line(gpa, dl, x + fxi(f * 0.18), y + fxi(f * 0.16), x + fxi(f * 0.20), y + fxi(f * 0.56), c, 2); // left wall
    try line(gpa, dl, x + fxi(f * 0.82), y + fxi(f * 0.16), x + fxi(f * 0.80), y + fxi(f * 0.56), c, 2); // right wall
    try line(gpa, dl, x + fxi(f * 0.20), y + fxi(f * 0.56), tipx, y + fxi(f * 0.92), c, 2); // left to point
    try line(gpa, dl, x + fxi(f * 0.80), y + fxi(f * 0.56), tipx, y + fxi(f * 0.92), c, 2); // right to point
}

/// A lab flask — the Toy Box mark (experimental). Neck, flared body, a hint of
/// fill.
fn iconFlask(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, c: u32) !void {
    const f: f32 = @floatFromInt(s);
    try line(gpa, dl, x + fxi(f * 0.40), y + fxi(f * 0.10), x + fxi(f * 0.40), y + fxi(f * 0.40), c, 2); // neck left
    try line(gpa, dl, x + fxi(f * 0.60), y + fxi(f * 0.10), x + fxi(f * 0.60), y + fxi(f * 0.40), c, 2); // neck right
    try line(gpa, dl, x + fxi(f * 0.34), y + fxi(f * 0.10), x + fxi(f * 0.66), y + fxi(f * 0.10), c, 2); // mouth
    try line(gpa, dl, x + fxi(f * 0.40), y + fxi(f * 0.40), x + fxi(f * 0.18), y + fxi(f * 0.86), c, 2); // body left
    try line(gpa, dl, x + fxi(f * 0.60), y + fxi(f * 0.40), x + fxi(f * 0.82), y + fxi(f * 0.86), c, 2); // body right
    try line(gpa, dl, x + fxi(f * 0.18), y + fxi(f * 0.86), x + fxi(f * 0.82), y + fxi(f * 0.86), c, 2); // base
    try rect(gpa, dl, x + fxi(f * 0.30), y + fxi(f * 0.66), fxi(f * 0.40), fxi(f * 0.18), c, 2); // liquid
}

/// An info mark — a circle with an "i" (a dot over a stem).
fn iconInfo(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, c: u32) !void {
    const f: f32 = @floatFromInt(s);
    const cx = x + fxi(f * 0.5);
    const cy = y + fxi(f * 0.5);
    try ring(gpa, dl, cx, cy, f * 0.42, c, 2, 12);
    try rect(gpa, dl, cx - fxi(f * 0.05), y + fxi(f * 0.24), fxi(f * 0.10), fxi(f * 0.10), c, @intCast(fxi(f * 0.05))); // dot
    try rect(gpa, dl, cx - fxi(f * 0.05), y + fxi(f * 0.44), fxi(f * 0.10), fxi(f * 0.30), c, 1); // stem
}

/// Map a settings SECTION icon tag to its line-art drawer (keeping the schema
/// free of draw concerns). Reuses the existing nav vocabulary where it fits.
fn settingsIcon(icon: settings_view.Icon, gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, c: u32) !void {
    switch (icon) {
        .account => try iconPerson(gpa, dl, x, y, s, c),
        .appearance => try iconAlgorithms(gpa, dl, x, y, s, c),
        .feed => try iconHome(gpa, dl, x, y, s, c),
        .notifications => try iconBell(gpa, dl, x, y, s, c),
        .privacy => try iconShield(gpa, dl, x, y, s, c),
        .toybox => try iconFlask(gpa, dl, x, y, s, c),
        .about => try iconInfo(gpa, dl, x, y, s, c),
    }
}

fn navIcon(idx: usize, gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, c: u32) !void {
    switch (idx) {
        0 => try iconHome(gpa, dl, x, y, s, c),
        1 => try iconZones(gpa, dl, x, y, s, c),
        2 => try iconHeartHollow(gpa, dl, x, y, s, c),
        3 => try iconReply(gpa, dl, x, y, s, c),
        4 => try iconAlgorithms(gpa, dl, x, y, s, c), // the "Algorithms" loadout page
        else => try iconGear(gpa, dl, x, y, s, c),
    }
}

/// Render the nav rail as a STANDALONE tile (the decomposition): the shell
/// calls this into its own draw list so the rail can slide/compress on its own.
/// Emits the rail's hit regions too (so clicks + the GPU SDF nav icons follow).
pub fn renderRail(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, rail_x: i32, height: i32, active: usize, regions: ?*Regions, accent: u32, skip_nav: bool, expand: f32) !void {
    return drawRail(gpa, dl, e, rail_x, height, active, regions, accent, skip_nav, expand);
}

fn drawRail(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, rx: i32, height: i32, active: usize, regions: ?*Regions, accent: u32, skip_nav: bool, expand: f32) !void {
    const x0 = rx + 14;
    // `expand` (0 = a tight ICONS-ONLY column, 1 = the full labelled rail) is the
    // condense/hover-expand control. The panel stays visible but narrows; the
    // labels + wordmark + New-post + "you" card FADE by `expand`. Nav icons stay
    // (drawn full, by the SDF pass / line-art) so the column always reads.
    const ex = std.math.clamp(expand, 0, 1);
    const ea: u32 = @as(u32, @intFromFloat(ex * 255.0)) << 24; // text/extras alpha
    const box_w: i32 = @intFromFloat(52.0 + @as(f32, @floatFromInt(rail_w - 24 - 52)) * ex);
    const pill_w: i32 = @intFromFloat(44.0 + @as(f32, @floatFromInt(rail_w - 32 - 44)) * ex);

    const wm = try str(gpa, dl, e, .semibold, x0 + 8, 58, (accent & 0x00FFFFFF) | ea, 26, "Zat4");
    _ = try str(gpa, dl, e, .semibold, wm, 58, (ink & 0x00FFFFFF) | ea, 26, ".");

    // The nav GROUP box (visible always; just narrower when condensed).
    try rect(gpa, dl, x0 - 2, 94, box_w, 304, skinPanel(accent), 18);

    // Visual ORDER of the nav rows (each row's `idx` is still its Screen — the
    // region/icon/active mapping is unchanged; only the on-screen order differs).
    // Algorithms (4) sits under Zones (1); Zat Chat (3) above Activity (2).
    const nav_order = [_]usize{ 0, 1, 4, 3, 2, 5 };
    var ny: i32 = 108;
    for (nav_order) |idx| {
        const label = nav_labels[idx];
        const on = idx == active;
        const col = if (on) ink else muted;
        if (on) try rect(gpa, dl, x0 + 2, ny - 8, pill_w, 42, (0x1F << 24) | (accent & 0x00FFFFFF), 12);
        if (!skip_nav) try navIcon(idx, gpa, dl, x0 + 10, ny, 22, if (on) accent else muted);
        _ = try str(gpa, dl, e, if (on) .semibold else .regular, x0 + 48, ny + 17, (col & 0x00FFFFFF) | ea, 16, label);
        // Tap target spans the (condensed) column width so the icon is clickable.
        try emitRegion(gpa, regions, rx + 14, ny - 8, box_w, 42, @intCast(idx), .nav);
        ny += 50;
    }

    ny += 16;
    // New-post + "you" card FADE out when condensed (they don't fit a tight
    // column); their regions are emitted only while visible so a hidden control
    // can't be clicked.
    if (ex > 0.05) {
        try rect(gpa, dl, x0 + 6, ny, rail_w - 44, 50, (accent & 0x00FFFFFF) | ea, 14);
        const npw: i32 = @intCast(text.measure(e, .semibold, "New post", 16));
        _ = try str(gpa, dl, e, .semibold, x0 + 6 + @divTrunc(rail_w - 44 - npw, 2), ny + 32, (bg & 0x00FFFFFF) | ea, 16, "New post");
        try emitRegion(gpa, regions, x0 + 6, ny, rail_w - 44, 50, 0, .compose);

        const by = height - 60;
        try rect(gpa, dl, x0 - 2, by - 10, rail_w - 24, 58, (skinPanel(accent) & 0x00FFFFFF) | ea, 16);
        try rect(gpa, dl, x0 + 6, by, 38, 38, (0x00FF3F3B2D & 0x00FFFFFF) | ea, 19);
        _ = try str(gpa, dl, e, .semibold, x0 + 54, by + 16, (ink & 0x00FFFFFF) | ea, 14, "you");
        _ = try str(gpa, dl, e, .regular, x0 + 54, by + 33, (faint & 0x00FFFFFF) | ea, 12, "@you.zat");
        try emitRegion(gpa, regions, x0 + 6, by - 4, rail_w - 40, 46, screen_profile, .nav);
    }
}

/// PHONE layouts (the locked mobile shape) at or below this logical width:
/// the narrow single column plus the bottom tab bar. The shell picks the
/// shape by choosing the surface's design width (tui.design_w_phone).
pub const phone_max: i32 = 500;
/// The tab bar's height — layout() adds it to content height on phone
/// widths so the last post scrolls clear of the bar.
pub const tab_bar_h: i32 = 76;

/// The PHONE tab bar (the locked mobile shape): home · zones · ＋compose ·
/// activity · you, pinned to the bottom edge over a scrim. Emits the SAME
/// region kinds as the desktop rail (.nav by screen index, .compose), so
/// the shell dispatch works unchanged — and each nav region is the 42×42
/// box whose (x+21, y+19) is the icon centre, the exact placement math the
/// GPU SDF-icon pass already applies to rail regions. The shell calls this
/// after ANY screen's layout on a phone-width surface (B5: plain values in,
/// draw list + regions out). `skip_nav` mirrors drawRail: the GPU draws the
/// nav icons itself; the software path gets the line-art.
/// The floating compose FAB's on-screen box (phone only) in LOGICAL px — the
/// ONE source of truth for its geometry, shared by drawTabBar (which paints it)
/// and the GPU engagement passes (which must skip any icon that scrolls behind
/// it, since it sits ABOVE the tab bar and the bottom clip doesn't catch it).
pub fn composeFabBox(width: i32, height: i32, bottom_inset: i32) struct { x0: i32, y0: i32, x1: i32, y1: i32 } {
    const fab_r: i32 = 27;
    const by = height - tab_bar_h - bottom_inset;
    const fab_cx = width - 26 - fab_r;
    const fab_cy = by - 22 - fab_r;
    return .{ .x0 = fab_cx - fab_r, .y0 = fab_cy - fab_r, .x1 = fab_cx + fab_r, .y1 = fab_cy + fab_r };
}

pub fn drawTabBar(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, width: i32, height: i32, bottom_inset: i32, active: u8, regions: ?*Regions, accent: u32, skip_nav: bool) error{OutOfMemory}!void {
    const by = height - tab_bar_h - bottom_inset;
    // The frosted veil the sticky top bar wears, and a hairline lid. (A 16px
    // dark "die-out" strip used to sit above the bar — it read as a stray black
    // band, worst in light mode; owner removed it 2026-07-09. The blocker below
    // still covers that band so near-miss taps stay swallowed.)
    // OPAQUE backing first, spanning the bar AND the home-pill strip: the veil
    // alone is translucent, so posts scrolling beneath ghosted faintly through
    // the very bottom of the screen (owner, 2026-07-09). The veil tints on top.
    try rect(gpa, dl, 0, by, width, tab_bar_h + @max(0, bottom_inset) + 12, bg, 0);
    try rect(gpa, dl, 0, by, width, tab_bar_h, skinHeaderVeil(accent), 0);
    // Fill behind the home pill so the veil reaches the screen edge (no gap).
    if (bottom_inset > 0) try rect(gpa, dl, 0, by + tab_bar_h, width, bottom_inset, skinHeaderVeil(accent), 0);
    try rect(gpa, dl, 0, by, width, 1, divider, 0);
    // The bar SWALLOWS taps: a full-width blocker over the whole bar (emitted
    // BEFORE the buttons, so hitTest — which prefers the last-emitted match —
    // still lets the buttons win, but a miss between them hits this no-op
    // instead of the post scrolling behind the bar).
    try emitRegion(gpa, regions, 0, by - 16, width, @intCast(@min(height - (by - 16), 65535)), 0, .blocker);

    const Slot = union(enum) { nav: u8, you };
    // The locked FIVE nav tabs (Bluesky pattern): home · zones(search) · Zat
    // Chat (centre) · activity · you. Composing is NOT a tab — it is the
    // floating FAB below. Everything else (Algorithms, Settings) lives in the
    // swipe-right nav DRAWER (drawDrawer).
    const slots = [_]Slot{ .{ .nav = screen_home }, .{ .nav = screen_zones_browse }, .{ .nav = screen_messages }, .{ .nav = 2 }, .you };
    const slot_w = @divTrunc(width, @as(i32, @intCast(slots.len)));
    const icon_cy = by + 36;
    for (slots, 0..) |slot, i| {
        const cx = slot_w * @as(i32, @intCast(i)) + @divTrunc(slot_w, 2);
        switch (slot) {
            .nav => |idx| {
                const on = idx == active;
                // The icon keeps its 28px box, but the tap target is the WHOLE
                // SLOT, bar-top to screen-bottom — a miss between buttons used
                // to select nothing (owner, 2026-07-11); now the nearest button
                // owns its full fifth. The GPU SDF nav pass (drawSdfIcons)
                // re-derives the icon centre from THIS geometry (r.x + r.w/2,
                // r.y + 36) — keep them in sync.
                if (on) try rect(gpa, dl, cx - 28, icon_cy - 26, 56, 52, (0x22 << 24) | (accent & 0x00FFFFFF), 15);
                if (!skip_nav) try navIcon(idx, gpa, dl, cx - 14, icon_cy - 14, 28, if (on) accent else muted);
                try emitRegion(gpa, regions, slot_w * @as(i32, @intCast(i)), by, slot_w, @intCast(@min(tab_bar_h + @max(0, bottom_inset), 32767)), idx, .nav);
            },
            .you => {
                const on = active == screen_profile;
                if (on) try rect(gpa, dl, cx - 28, icon_cy - 26, 56, 52, (0x22 << 24) | (accent & 0x00FFFFFF), 15);
                try rect(gpa, dl, cx - 22, icon_cy - 22, 44, 44, 0xFF3F3B2D, 22);
                _ = try str(gpa, dl, e, .semibold, cx - 6, icon_cy + 7, if (on) accent else ink, 16, "y");
                try emitRegion(gpa, regions, slot_w * @as(i32, @intCast(i)), by, slot_w, @intCast(@min(tab_bar_h + @max(0, bottom_inset), 32767)), screen_profile, .nav);
            },
        }
    }
    // The floating COMPOSE button (Bluesky pattern): a raised accent circle
    // above the bar at the right, distinct from the five nav tabs — posting
    // lives here now that the centre tab is Zat Chat.
    const fab_r: i32 = 27;
    const fab_box = composeFabBox(width, height, bottom_inset);
    const fab_cx = fab_box.x0 + fab_r;
    const fab_cy = fab_box.y0 + fab_r;
    try rect(gpa, dl, fab_cx - fab_r, fab_cy - fab_r + 3, fab_r * 2, fab_r * 2, 0x38000000, @intCast(fab_r)); // soft drop shadow so it lifts off the feed
    try rect(gpa, dl, fab_cx - fab_r, fab_cy - fab_r, fab_r * 2, fab_r * 2, accent, @intCast(fab_r));
    try rect(gpa, dl, fab_cx - 12, fab_cy - 2, 24, 4, bg, 2);
    try rect(gpa, dl, fab_cx - 2, fab_cy - 12, 4, 24, bg, 2);
    try emitRegion(gpa, regions, fab_cx - fab_r - 2, fab_cy - fab_r - 2, fab_r * 2 + 4, fab_r * 2 + 4, 0, .compose);
}

/// The double-back heads-up (the TikTok pattern, owner-requested): a centred
/// pill above the tab bar — the first system-back at the root arms it, and only
/// a second back inside the window minimizes the app. Drawn by the phone nav
/// tile while armed; expiry drops it via the rebuild signature.
pub fn drawBackHint(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, width: i32, height: i32, bottom_inset: i32) error{OutOfMemory}!void {
    const msg = "Swipe back again to exit";
    const px: u16 = 14;
    const tw: i32 = @intCast(text.measure(e, .semibold, msg, px));
    const pw = tw + 44;
    const ph: i32 = 40;
    const x = @divTrunc(width - pw, 2);
    const y = height - tab_bar_h - bottom_inset - ph - 18;
    try rect(gpa, dl, x, y, pw, ph, 0xF2262620, 20);
    _ = try str(gpa, dl, e, .semibold, x + 22, y + 26, ink, px, msg);
}

// ---------------------------------------------------------------------------
// THE ZAT4 KEYBOARD (phone; owner-designed): the app draws its own keys, so
// typing never touches a third-party IME — keystrokes stay in-process (the
// privacy story), the composer never fights the system keyboard for space,
// and the keys wear the house accent (they re-tint with the seated socket).
// Taps feed the SAME byte stream the system keyboard's fallback feeds; the
// settings toggle (act_zat_kbd, default ON) swaps back to the system IME.
// ---------------------------------------------------------------------------

/// Total height of the keyboard panel (logical px), excluding the safe-area
/// bottom inset it also paints over. The chat composer lifts by this.
/// FIVE rows since the owner's pass 2 (2026-07-11): a number row (1–9 +
/// emoji) rides on top of the letters, and keys grew a touch taller.
/// The 8 is the top pad; the 24 is BOTTOM pad — the key block floats a
/// few notches above the inset like the platform keyboard's (the owner's
/// side-by-side, 2026-07-12: ours ran nearly flush to the screen bottom,
/// which also parks the bottom row under the thumb's least accurate zone).
pub const keyboard_h: i32 = 5 * (kbd_key_h + kbd_gap) + 8 + 24;
const kbd_key_h: i32 = 52;
const kbd_gap: i32 = 7;

/// One key of a row: the unshifted/shifted codepoints (equal when shift is
/// meaningless) and a width in flex units. `cp == 0` marks a CONTROL key
/// named by `ctrl`. Comptime layout data — iterated per rebuild, tiny.
const KbdKey = struct {
    lo: u16,
    hi: u16 = 0,
    w: u8 = 2, // flex units (2 = a letter key)
    ctrl: u8 = 0, // 1 shift, 2 backspace, 3 page, 4 enter, 5 emoji (dead — the emoji story is queued)

    comptime {
        // Budget: 2+2+1+1 = 6, padded to 6 at u16 alignment (A7).
        assert(@sizeOf(KbdKey) == 6);
    }
};

fn kbdChar(lo: u16, hi: u16) KbdKey {
    return .{ .lo = lo, .hi = hi };
}
fn kbdRowStr(comptime low: []const u8, comptime high: []const u8) [low.len]KbdKey {
    var out: [low.len]KbdKey = undefined;
    for (low, high, 0..) |l, h, i| out[i] = kbdChar(l, h);
    return out;
}
const kbd_r0 = kbdRowStr("qwertyuiop", "QWERTYUIOP");
const kbd_r1 = kbdRowStr("asdfghjkl", "ASDFGHJKL");
const kbd_r2_mid = kbdRowStr("zxcvbnm", "ZXCVBNM");
const kbd_s0 = kbdRowStr("1234567890", "1234567890");
const kbd_s1 = kbdRowStr("@#$%&-+()", "@#$%&-+()");
const kbd_s2_mid = kbdRowStr("*\"':;!?/", "*\"':;!?/");
// The SECOND symbols page (the standard keyboard's "=\\<" layer): the
// less-common set, ASCII-safe — the embedded face is curated, so exotic
// glyphs stay out until they're proven in.
const kbd_x0 = kbdRowStr("[]{}<>^_~|", "[]{}<>^_~|");
const kbd_x1 = kbdRowStr("`\\=*#%+&@", "`\\=*#%+&@");
const kbd_x2_mid = kbdRowStr("$-'\"/:;!", "$-'\"/:;!");
// The standing number row (every page): 1–9 + the emoji key — the owner
// wants numbers one tap away while the symbols pages keep their own runs.
const kbd_num = kbdRowStr("123456789", "123456789");

/// The chat draft's edit state as the view needs it: caret + selection
/// byte offsets (sel_a == sel_b = no selection) + whether the Copy/Cut/
/// Paste bar is up. A7.2: cold view struct, transient per frame.
pub const ChatEdit = struct {
    caret: usize = std.math.maxInt(usize), // clamped to draft.len (= end)
    sel_a: usize = 0,
    sel_b: usize = 0,
    bar: bool = false,
};

/// Map a point (logical px, relative to the INPUT REGION's box) to the
/// nearest byte offset in the draft — replays wrapDraft's wrap rule (break
/// before a word that overflows; '\n' explicit) with the same text origin
/// the input draws at (region + 14, baseline +31, width -28). The shell
/// calls this on a long-press to plant the selection.
pub fn chatDraftOffsetAt(e: *const text.Engine, draft: []const u8, region_w: i32, hx: i32, hy: i32) u32 {
    const maxw = region_w - 28;
    const x0: i32 = 14;
    var baseline: i32 = 31;
    var x = x0;
    var best: u32 = @intCast(draft.len);
    var best_score: i64 = std.math.maxInt(i64);
    var word_start: usize = 0;
    var i: usize = 0;
    while (i <= draft.len) : (i += 1) {
        const at_end = i == draft.len;
        const ch: u8 = if (at_end) 0 else draft[i];
        if (!at_end and ch != ' ' and ch != '\n') continue;
        const word = draft[word_start..i];
        if (word.len > 0) {
            const ww: i32 = @intCast(text.measure(e, .regular, word, chat_px));
            if (x > x0 and x + ww > x0 + maxw) {
                baseline += chat_line_h;
                x = x0;
            }
            // every byte boundary inside the word is a caret candidate
            var k: usize = 0;
            while (k <= word.len) : (k += 1) {
                const sw: i32 = @intCast(text.measure(e, .regular, word[0..k], chat_px));
                nearerBoundary(@intCast(word_start + k), x + sw, baseline, hx, hy, &best, &best_score);
            }
            x += ww;
        } else {
            nearerBoundary(@intCast(word_start), x, baseline, hx, hy, &best, &best_score);
        }
        if (at_end) break;
        if (ch == ' ') {
            if (x > x0) x += @intCast(text.advance(e, .regular, ' ', chat_px));
        } else {
            baseline += chat_line_h;
            x = x0;
        }
        word_start = i + 1;
    }
    return best;
}

/// Expand a byte offset to the word around it (non-space run); a space
/// under the finger selects the gap's neighbouring word to the left.
pub fn wordAround(draft: []const u8, off: usize) struct { a: usize, b: usize } {
    if (draft.len == 0) return .{ .a = 0, .b = 0 };
    var o = @min(off, draft.len - 1);
    if (draft[o] == ' ' or draft[o] == '\n') {
        while (o > 0 and (draft[o] == ' ' or draft[o] == '\n')) o -= 1;
    }
    var a = o;
    while (a > 0 and draft[a - 1] != ' ' and draft[a - 1] != '\n') a -= 1;
    var b = o;
    while (b < draft.len and draft[b] != ' ' and draft[b] != '\n') b += 1;
    return .{ .a = a, .b = b };
}

/// TAP-MODEL v1 (the forgiveness layer, measured 2026-07-12): a touch is
/// scored against every key's CENTRE, normalised by that key's extents —
/// not clipped by hard rectangles. A press near a boundary resolves to the
/// key the finger was closest to at that key's own scale (wide keys are
/// proportionally tolerant, so space keeps its edges). Pure; the pump
/// calls this instead of raw hitTest for keyboard presses.
/// TAP-MODEL v2: the spatial score blends with a letter-trigram prior —
/// P(this key's letter | the last two typed) from kbd_lm — so a
/// boundary-ambiguous press resolves to the letter that CONTINUES what the
/// fingers were typing ("th" + a press between e/w -> e). The weight is
/// sized so the prior decides ties and near-ties ONLY: a clean press's
/// spatial margin (>= ~1.5 key-radii²) always beats the maximum prior
/// swing (~0.7). ctx = the last two typed classes (kbd_lm.classOf);
/// ctx[0] == 255 disables the prior (the settings toggle / desktop mouse).
pub fn kbdResolve(regions: []const Region, px: i32, py: i32, ctx: [2]u8) ?Region {
    const lm_on = ctx[0] != 255;
    const lam: f32 = 0.0055; // key-radii² per 1/16 nat
    var best: ?Region = null;
    var best_score: f32 = 2.6 + 0.35; // reach bound, prior-inclusive
    for (regions) |r| {
        switch (r.kind) {
            .kbd_key, .kbd_shift, .kbd_page, .kbd_backspace => {},
            else => continue,
        }
        const cx = @as(f32, @floatFromInt(r.x)) + @as(f32, @floatFromInt(r.w)) * 0.5;
        const cy = @as(f32, @floatFromInt(r.y)) + @as(f32, @floatFromInt(r.h)) * 0.5;
        const hw = @max(1.0, @as(f32, @floatFromInt(r.w)) * 0.5);
        const hh = @max(1.0, @as(f32, @floatFromInt(r.h)) * 0.5);
        const dx = (@as(f32, @floatFromInt(px)) - cx) / hw;
        // Vertical leniency 1.35x: measured finger scatter is ~1.8x taller
        // than wide (250 presses, 2026-07-12) — row-neighbour misses were
        // the dominant typo, so crossing a row needs more evidence than
        // crossing a column. (The platform keyboards weight it the same
        // way.)
        const dy = (@as(f32, @floatFromInt(py)) - cy) / (hh * 1.35);
        var score = dx * dx + dy * dy;
        if (score > 2.6) continue; // out of this key's reach
        if (lm_on) {
            // Letter and boundary keys carry their trigram cost; keys the
            // model doesn't speak for (digits, symbols, controls) carry the
            // average-ish flat cost so the prior never crowds them out.
            const nll: u8 = if (r.kind == .kbd_key and r.post != 0) blk: {
                const c3 = kbd_lm.classOf(@intCast(@min(r.post, 255)));
                const modeled = c3 != 26 or r.post == ' ' or r.post == ',' or r.post == '.';
                break :blk if (modeled) @min(kbd_lm.nll(ctx[0], ctx[1], c3), 128) else 55;
            } else 55;
            score += lam * @as(f32, @floatFromInt(nll));
        }
        if (score < best_score) {
            best_score = score;
            best = r;
        }
    }
    return best;
}

/// The Zat4 keyboard's LONG-PRESS popup: an option strip riding above its
/// anchor key (₿ acts directly; @ offers recent conversation handles, #
/// offers pinned zones — the keyboard IS the app, so app-aware alternates
/// cost no privacy). The SHELL owns the state (options, finger-tracked
/// selection); this module owns geometry + pixels, and `kbdPopupCellAt`
/// answers "which cell is the finger over" with the same math the draw
/// uses — the two can never drift. A7.2: cold view struct, transient.
pub const KbdPopup = struct {
    opts: []const []const u8 = &.{},
    anchor_x: i32 = 0,
    anchor_y: i32 = 0,
    anchor_w: i32 = 0,
    sel: i32 = -1,
};

const kbd_popup_px: u16 = 17;
const kbd_popup_cell_h: i32 = 46;
const kbd_popup_gap: i32 = 4;

fn kbdPopupCellW(e: *const text.Engine, opt: []const u8) i32 {
    return @as(i32, @intCast(text.measure(e, .regular, opt, kbd_popup_px))) + 26;
}

fn kbdPopupX0(e: *const text.Engine, width: i32, p: KbdPopup) i32 {
    var total: i32 = 0;
    for (p.opts) |o| total += kbdPopupCellW(e, o) + kbd_popup_gap;
    if (total > 0) total -= kbd_popup_gap;
    return std.math.clamp(p.anchor_x + @divTrunc(p.anchor_w, 2) - @divTrunc(total, 2), 4, @max(4, width - 4 - total));
}

/// Which option cell logical x `fx` is over (-1 = none). The shell calls
/// this per move to track the finger; release commits the answer.
pub fn kbdPopupCellAt(e: *const text.Engine, width: i32, p: KbdPopup, fx: i32) i32 {
    var x = kbdPopupX0(e, width, p);
    for (p.opts, 0..) |o, i| {
        const cw = kbdPopupCellW(e, o);
        if (fx >= x and fx < x + cw) return @intCast(i);
        x += cw + kbd_popup_gap;
    }
    return -1;
}

/// The Zat4 keyboard: an opaque panel over the very bottom (it paints the
/// safe-area inset too), the accent "circuit" lines across its top and
/// between rows, and one region per key. Shifted codepoints are emitted at
/// DRAW time, so the dispatch is a dumb byte writer. Pure (B2).
/// `caps` is the double-tap shift lock (letters stay shifted; the shift key
/// wears a lock bar). `flash_key`/`flash_a` are the shell's press feedback:
/// the identity of the last-pressed key (its codepoint; 0xE001 shift /
/// 0xE002 backspace / 0xE003 page / '\r' enter) and the flash's current
/// alpha — the key glows accent and fades as the shell decays it.
pub fn drawKeyboard(
    gpa: Allocator,
    dl: *raster.DrawList,
    e: *const text.Engine,
    regions: ?*Regions,
    width: i32,
    view_h: i32,
    bottom_inset: i32,
    accent: u32,
    shift: bool,
    page: u8,
    caps: bool,
    flash_key: u16,
    flash_a: u8,
    /// The shell's running clock (seconds) — drives the lattice pulses.
    t: f32,
    /// Settings: the traveling lattice glints, and the key-preview pop.
    pulses_on: bool,
    pop_on: bool,
    /// The open long-press popup (empty opts = closed).
    popup: KbdPopup,
) error{OutOfMemory}!void {
    const top = view_h - keyboard_h - bottom_inset;
    // The panel: opaque (nothing ghosts through chrome) with a faint wash.
    try rect(gpa, dl, 0, top, width, keyboard_h + bottom_inset, bg, 0);
    try rect(gpa, dl, 0, top, width, keyboard_h + bottom_inset, 0x14FFFFFF, 0);
    // The lit top edge — the circuit's supply rail.
    try rect(gpa, dl, 0, top, width, 2, (0xC8 << 24) | (accent & 0x00FFFFFF), 0);
    // Swallow every tap on the panel (the bar-blocker pattern): keys win by
    // being emitted after.
    try emitRegion(gpa, regions, 0, top, width, @intCast(@min(keyboard_h + bottom_inset, 32767)), 0, .blocker);

    const m: i32 = 6; // outer margin
    const row_w = width - 2 * m;
    const n_rows: usize = 5;

    // THE CIRCUIT LATTICE (the owner's tron lines, done as a board, not as
    // dashes on keys — the pass-1 miss): the accent runs through the GUTTERS
    // between rows and keys, a soft wide trace with a bright 1px core, so the
    // whole panel reads as one lit board the keys sit on. Horizontal traces
    // here; vertical traces per key boundary inside the loop below.
    var gr: usize = 1;
    while (gr < n_rows) : (gr += 1) {
        const gy = top + 8 + @as(i32, @intCast(gr)) * (kbd_key_h + kbd_gap) - @divTrunc(kbd_gap + 1, 2);
        try rect(gpa, dl, m, gy, row_w, 1, (0x1E << 24) | (accent & 0x00FFFFFF), 0);
    }

    // THE PULSES (owner: whispy glints riding the lines): two travel row
    // gutters in opposite directions, one rides the lit top rail — each a
    // bright head trailing two fading glints. Speeds are unequal so the
    // pattern never visibly repeats; subtle by alpha, not size.
    const rw_f: f32 = @floatFromInt(row_w);
    const Pulse = struct { row: i32, speed: f32, phase: f32, dirn: f32 };
    const pulses = [_]Pulse{
        .{ .row = 1, .speed = 0.071, .phase = 0.00, .dirn = 1 },
        .{ .row = 3, .speed = 0.047, .phase = 0.45, .dirn = -1 },
        .{ .row = -1, .speed = 0.113, .phase = 0.20, .dirn = 1 }, // the top rail
    };
    for (pulses) |p| if (pulses_on) {
        const gy = if (p.row < 0)
            top + 1
        else
            top + 8 + p.row * (kbd_key_h + kbd_gap) - @divTrunc(kbd_gap + 1, 2);
        const u = @mod(t * p.speed + p.phase, 1.0);
        const ux = if (p.dirn > 0) u else 1.0 - u;
        const hx: i32 = m + @as(i32, @intFromFloat(ux * rw_f));
        const tail: i32 = @intFromFloat(8.0 * p.dirn);
        try rect(gpa, dl, hx - 2, gy - 2, 5, 5, (0x6E << 24) | (accent & 0x00FFFFFF), 2);
        try rect(gpa, dl, hx - 1 - tail, gy - 1, 3, 3, (0x3A << 24) | (accent & 0x00FFFFFF), 1);
        try rect(gpa, dl, hx - 1 - 2 * tail, gy - 1, 3, 3, (0x1C << 24) | (accent & 0x00FFFFFF), 1);
    };

    var pop_x: i32 = std.math.minInt(i32);
    var pop_w: i32 = 0;
    var pop_y: i32 = 0;
    var pop_cp: u16 = 0;
    var y = top + 8;
    var row_i: usize = 0;
    while (row_i < n_rows) : (row_i += 1) {
        // Assemble the row: the number row (1–9 + emoji) rides both pages;
        // pages 0/1 share the frame below it — mids swap, the bottom row is
        // common ([?123/abc][bitcoin][space][enter]).
        var keys_buf: [12]KbdKey = undefined;
        var nk: usize = 0;
        switch (row_i) {
            0 => {
                for (kbd_num) |k| {
                    keys_buf[nk] = k;
                    nk += 1;
                }
                keys_buf[nk] = .{ .lo = 0, .ctrl = 5, .w = 2 }; // emoji (dead for now)
                nk += 1;
            },
            1 => {
                const src = switch (page) {
                    0 => kbd_r0[0..],
                    1 => kbd_s0[0..],
                    else => kbd_x0[0..],
                };
                for (src) |k| {
                    keys_buf[nk] = k;
                    nk += 1;
                }
            },
            2 => {
                const src = switch (page) {
                    0 => kbd_r1[0..],
                    1 => kbd_s1[0..],
                    else => kbd_x1[0..],
                };
                for (src) |k| {
                    keys_buf[nk] = k;
                    nk += 1;
                }
            },
            3 => {
                // Page 0 keeps shift here; the symbols pages use the slot the
                // standard way — a layer hop ("=\\<" deeper, "?123" back).
                // A ctrl-3 key carries its TARGET page in `lo`.
                keys_buf[nk] = if (page == 0)
                    .{ .lo = 0, .ctrl = 1, .w = 3 } // shift
                else if (page == 1)
                    .{ .lo = 2, .ctrl = 3, .w = 3 } // "=\\<" -> symbols 2
                else
                    .{ .lo = 1, .ctrl = 3, .w = 3 }; // "?123" -> symbols 1
                nk += 1;
                const src = switch (page) {
                    0 => kbd_r2_mid[0..],
                    1 => kbd_s2_mid[0..],
                    else => kbd_x2_mid[0..],
                };
                for (src) |k| {
                    keys_buf[nk] = k;
                    nk += 1;
                }
                keys_buf[nk] = .{ .lo = 0, .ctrl = 2, .w = 3 }; // backspace
                nk += 1;
            },
            else => {
                // Every page: [layer][₿][,][space][.][enter] — comma and
                // period flank the space bar, the standard seats (they were
                // simply MISSING in v1; owner, 2026-07-11).
                keys_buf[nk] = .{ .lo = if (page == 0) 1 else 0, .ctrl = 3, .w = 3 }; // ?123 / abc
                nk += 1;
                keys_buf[nk] = .{ .lo = ',', .hi = ',', .w = 2 };
                nk += 1;
                keys_buf[nk] = .{ .lo = 0x20BF, .hi = 0x20BF, .w = 2 }; // ₿ — the emoji's Gboard seat, ours
                nk += 1;
                keys_buf[nk] = .{ .lo = ' ', .hi = ' ', .w = 7 }; // space
                nk += 1;
                keys_buf[nk] = .{ .lo = '.', .hi = '.', .w = 2 };
                nk += 1;
                keys_buf[nk] = .{ .lo = 0, .ctrl = 4, .w = 3 }; // enter
                nk += 1;
            },
        }
        const keys = keys_buf[0..nk];
        // UNIFORM LETTER WIDTH (the muscle-memory fix, owner 2026-07-11):
        // every char key on rows 0–3 is exactly one tenth of the row — the
        // 9-key home row and shorter mids INSET and centre instead of
        // stretching, so each key's centre sits where a standard keyboard
        // put it. Shift/backspace absorb the row-3 margins; the bottom row
        // keeps its flex layout.
        const unit_kw = @divTrunc(row_w - 9 * kbd_gap, 10);
        var kx_buf: [12]i32 = undefined;
        var kww_buf: [12]i32 = undefined;
        if (row_i == 4) {
            var units: i32 = 0;
            for (keys) |k| units += k.w;
            const kw_num = row_w - @as(i32, @intCast(nk - 1)) * kbd_gap;
            var xx = m;
            for (keys, 0..) |k, kidx| {
                kx_buf[kidx] = xx;
                kww_buf[kidx] = @divTrunc(kw_num * k.w, units);
                xx += kww_buf[kidx] + kbd_gap;
            }
        } else if (row_i == 3) {
            const n_mid: i32 = @intCast(nk - 2);
            const mid_total = n_mid * unit_kw + (n_mid - 1) * kbd_gap;
            const mid_x0 = m + @divTrunc(row_w - mid_total, 2);
            kx_buf[0] = m;
            kww_buf[0] = mid_x0 - kbd_gap - m;
            var xx = mid_x0;
            var kidx: usize = 1;
            while (kidx < nk - 1) : (kidx += 1) {
                kx_buf[kidx] = xx;
                kww_buf[kidx] = unit_kw;
                xx += unit_kw + kbd_gap;
            }
            kx_buf[nk - 1] = xx;
            kww_buf[nk - 1] = m + row_w - xx;
        } else {
            const nk_i: i32 = @intCast(nk);
            const total = nk_i * unit_kw + (nk_i - 1) * kbd_gap;
            var xx = m + @divTrunc(row_w - total, 2);
            for (0..nk) |kidx| {
                kx_buf[kidx] = xx;
                kww_buf[kidx] = unit_kw;
                xx += unit_kw + kbd_gap;
            }
        }
        const hg = @divTrunc(kbd_gap, 2);
        for (keys, 0..) |k, ki| {
            const x = kx_buf[ki];
            const kw = kww_buf[ki];
            // Vertical circuit trace in the gutter left of this key.
            if (ki > 0) {
                const gx = x - @divTrunc(kbd_gap + 1, 2);
                try rect(gpa, dl, gx, y, 1, kbd_key_h, (0x1E << 24) | (accent & 0x00FFFFFF), 0);
            }
            const active_ctrl = (k.ctrl == 1 and (shift or caps)) or (k.ctrl == 3 and k.lo == 0 and page != 0);
            // The iOS lesson (owner's reference, 2026-07-11): the premium
            // read is CONTRAST + DEPTH, not size — a lighter key face over
            // the dark board, seated on a darker under-edge.
            const fill: u32 = if (active_ctrl) (0x50 << 24) | (accent & 0x00FFFFFF) else 0x26FFFFFF;
            try rect(gpa, dl, x, y, kw, kbd_key_h + 2, 0x66000000, 9); // the seat: a 2px lip below the face
            try rect(gpa, dl, x, y, kw, kbd_key_h, fill, 9);
            // Press feedback: the last-tapped key glows accent and fades
            // (the shell decays flash_a). Char keys match either case —
            // shift may have cleared between press and draw.
            const flashed = flash_a != 0 and switch (k.ctrl) {
                1 => flash_key == 0xE001,
                2 => flash_key == 0xE002,
                3 => flash_key == 0xE003,
                4 => flash_key == '\r',
                5 => flash_key == 0xE005,
                else => flash_key == k.lo or (k.hi != 0 and flash_key == k.hi),
            };
            if (flashed) try rect(gpa, dl, x, y, kw, kbd_key_h, (@as(u32, flash_a) << 24) | (accent & 0x00FFFFFF), 9);
            // The key-preview POP (iOS's signature, ours): the pressed CHAR
            // key's glyph rises above the finger while the flash is young —
            // the fingertip occludes the key; the confirmation lives above
            // it. Captured here, drawn after the rows (topmost).
            if (flashed and pop_on and k.ctrl == 0 and k.lo != ' ') {
                pop_x = x;
                pop_w = kw;
                pop_y = y;
                pop_cp = if ((shift or caps) and k.hi != 0) k.hi else k.lo;
            }
            // Caps lock: the shift key carries a solid accent lock bar.
            if (k.ctrl == 1 and caps)
                try rect(gpa, dl, x + @divTrunc(kw, 2) - 8, y + kbd_key_h - 9, 16, 3, (0xFF << 24) | (accent & 0x00FFFFFF), 1);
            // THE TAP TARGET TILES THE GUTTER (owner: misses between keys
            // typed nothing) — regions abut edge-to-edge and reach the panel
            // and screen edges; the visual key keeps its gap. The nearest key
            // owns the miss.
            const rx0: i32 = if (ki == 0) 0 else x - hg;
            const rx1: i32 = if (ki == nk - 1) width else x + kw + hg;
            const ry0: i32 = if (row_i == 0) top + 2 else y - hg;
            const ry1: i32 = if (row_i == n_rows - 1) view_h else y + kbd_key_h + hg;
            if (k.ctrl != 0) {
                if (k.ctrl == 5) {
                    // The emoji key: a drawn face (the embedded font carries
                    // no emoji; the story is queued — this key is DEAD, it
                    // only flashes). Disc + eyes + smile from primitives.
                    const ecx = x + @divTrunc(kw, 2);
                    const ecy = y + @divTrunc(kbd_key_h, 2);
                    try rect(gpa, dl, ecx - 10, ecy - 10, 20, 20, 0x30EDEAE0, 10);
                    try rect(gpa, dl, ecx - 8, ecy - 8, 16, 16, 0xE0212019, 8);
                    try rect(gpa, dl, ecx - 4, ecy - 4, 2, 4, ink, 1);
                    try rect(gpa, dl, ecx + 2, ecy - 4, 2, 4, ink, 1);
                    try rect(gpa, dl, ecx - 4, ecy + 4, 8, 2, ink, 1);
                } else {
                    const glyph: []const u8 = switch (k.ctrl) {
                        1 => "\u{21E7}", // shift
                        2 => "\u{232B}", // backspace
                        3 => switch (k.lo) { // the layer key names its TARGET
                            0 => "abc",
                            1 => "?123",
                            else => "=\\<",
                        },
                        else => "\u{23CE}", // enter
                    };
                    const gpx: u16 = if (k.ctrl == 3) 13 else 18;
                    const gw: i32 = @intCast(text.measure(e, .regular, glyph, gpx));
                    _ = try str(gpa, dl, e, .regular, x + @divTrunc(kw - gw, 2), y + 33, ink, gpx, glyph);
                }
                const kind: Action = switch (k.ctrl) {
                    1 => .kbd_shift,
                    2 => .kbd_backspace,
                    3 => .kbd_page,
                    else => .kbd_key, // enter emits '\r'; the dead emoji key emits 0
                };
                try emitRegion(gpa, regions, rx0, ry0, rx1 - rx0, @intCast(@min(ry1 - ry0, 32767)), switch (k.ctrl) {
                    4 => '\r',
                    3 => k.lo, // the layer key's target page
                    else => 0,
                }, kind);
            } else {
                const cp: u16 = if ((shift or caps) and k.hi != 0) k.hi else k.lo;
                var gb: [4]u8 = undefined;
                const gn = std.unicode.utf8Encode(@intCast(cp), &gb) catch 1;
                const gw: i32 = @intCast(text.measure(e, .regular, gb[0..gn], 19));
                _ = try str(gpa, dl, e, .regular, x + @divTrunc(kw - gw, 2), y + 34, ink, 19, gb[0..gn]);
                try emitRegion(gpa, regions, rx0, ry0, rx1 - rx0, @intCast(@min(ry1 - ry0, 32767)), cp, .kbd_key);
            }
        }
        y += kbd_key_h + kbd_gap;
    }
    // The pop cap: a raised key face just above the pressed key, accent
    // edge, big glyph — alpha rides the press flash (snaps in, fades fast).
    if (pop_x != std.math.minInt(i32) and flash_a > 40) {
        // ENLARGED, the platform way (owner, 2026-07-12): the pop is the
        // magnifier — a wider cap, a higher rise, and a 34px glyph vs the
        // key's 19 — not a copy of the key.
        const pw = @max(pop_w + 16, 54);
        const px0 = std.math.clamp(pop_x - @divTrunc(pw - pop_w, 2), 2, width - pw - 2);
        const py0 = pop_y - 68;
        const pa: u32 = @min(255, @as(u32, flash_a) * 3);
        try rect(gpa, dl, px0 - 1, py0 - 1, pw + 2, 60, ((pa * 0x70 / 255) << 24) | (accent & 0x00FFFFFF), 12);
        try rect(gpa, dl, px0, py0, pw, 58, (pa << 24) | 0x212019, 11);
        var pgb: [4]u8 = undefined;
        const pgn = std.unicode.utf8Encode(@intCast(pop_cp), &pgb) catch 1;
        const pgw: i32 = @intCast(text.measure(e, .regular, pgb[0..pgn], 34));
        _ = try str(gpa, dl, e, .regular, px0 + @divTrunc(pw - pgw, 2), py0 + 42, scaleAlpha(ink, @as(f32, @floatFromInt(pa)) / 255.0), 34, pgb[0..pgn]);
    }
    // The long-press popup strip: opaque cells above the anchor key, the
    // finger-tracked cell accent-filled. Selection is the shell's; release
    // commits it.
    if (popup.opts.len > 0) {
        const sy0 = popup.anchor_y - kbd_popup_cell_h - 10;
        var sx = kbdPopupX0(e, width, popup);
        for (popup.opts, 0..) |o, i| {
            const cw = kbdPopupCellW(e, o);
            const on = popup.sel == @as(i32, @intCast(i));
            try rect(gpa, dl, sx - 1, sy0 - 1, cw + 2, kbd_popup_cell_h + 2, (0x86 << 24) | (accent & 0x00FFFFFF), 11);
            try rect(gpa, dl, sx, sy0, cw, kbd_popup_cell_h, if (on) (0xFF << 24) | (accent & 0x00FFFFFF) else 0xFF23221B, 10);
            _ = try str(gpa, dl, e, .regular, sx + 13, sy0 + 30, if (on) 0xFF20201A else ink, kbd_popup_px, o);
            sx += cw + kbd_popup_gap;
        }
    }
}

/// The PHONE nav DRAWER (the Bluesky-pattern reference, owner-chosen): a
/// rightward swipe on the content slides it in from the left over a scrim.
/// It carries the profile card plus EVERY top-level screen — including the
/// ones the five-slot bar doesn't (Zat Chat, Algorithms, Settings — the
/// phone's only door to Sign out). Rows speak the same `.nav` vocabulary as
/// the rail/bar; the scrim emits `.drawer_close`. Regions land only once
/// the panel is essentially open (honest targets, no mid-flight taps).
/// `t` is the shell's spring (0 closed -> 1 open); `skip_nav` mirrors
/// drawRail — nav regions are sized so the GPU SDF pass's (x+21, y+19)
/// placement lands each icon on the row's icon slot.
pub const drawer_w: i32 = 300;
pub fn drawDrawer(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, width: i32, height: i32, t: f32, active: u8, regions: ?*Regions, accent: u32, you_handle: []const u8, skip_nav: bool) error{OutOfMemory}!void {
    const tt = std.math.clamp(t, 0, 1);
    if (tt <= 0.01) return;
    const open = tt > 0.6;

    // The scrim: the content dims as the panel arrives; a tap on it closes.
    const sa: u32 = @intFromFloat(150.0 * tt);
    try rect(gpa, dl, 0, 0, width, height, sa << 24, 0);
    if (open) try emitRegion(gpa, regions, 0, 0, width, @intCast(@min(height, 65535)), 0, .drawer_close);

    // The panel: OPAQUE (navigation must read over anything) with a lit edge.
    const px = -drawer_w + @as(i32, @intFromFloat(@as(f32, @floatFromInt(drawer_w)) * tt));
    try rect(gpa, dl, px, 0, drawer_w, height, 0xFF201F18, 0);
    try rect(gpa, dl, px + drawer_w - 1, 0, 1, height, divider, 0);

    // The profile card: avatar disc + handle -> your profile.
    try rect(gpa, dl, px + 20, 40, 46, 46, 0xFF3F3B2D, 23);
    _ = try str(gpa, dl, e, .semibold, px + 34, 70, ink, 16, "y");
    _ = try str(gpa, dl, e, .semibold, px + 20, 116, ink, 17, "you");
    const shown = if (you_handle.len > 0) you_handle else "not signed in";
    _ = try str(gpa, dl, e, .regular, px + 20, 138, faint, 13, shown);
    if (open) try emitRegion(gpa, regions, px + 12, 32, drawer_w - 24, 114, screen_profile, .nav);
    try rect(gpa, dl, px + 20, 156, drawer_w - 40, 1, divider, 0);

    // Every top-level screen, the rail's own order (nav_order).
    const rows = [_]u8{ 0, 1, 4, 3, 2, 5 };
    var ry: i32 = 182;
    for (rows) |idx| {
        const on = idx == active;
        if (on) try rect(gpa, dl, px + 12, ry - 8, drawer_w - 24, 42, (0x1F << 24) | (accent & 0x00FFFFFF), 12);
        if (!skip_nav) try navIcon(idx, gpa, dl, px + 24, ry, 22, if (on) accent else muted);
        _ = try str(gpa, dl, e, if (on) .semibold else .regular, px + 62, ry + 17, if (on) ink else muted, 16, nav_labels[idx]);
        // Region x sits so the SDF pass's x+21 = the icon centre (px+35).
        if (open) try emitRegion(gpa, regions, px + 14, ry - 8, drawer_w - 28, 42, idx, .nav);
        ry += 54;
    }
}

fn drawSidebar(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, sx: i32, height: i32, search_open: f32, accent: u32) !void {
    const x0 = sx + 16;
    const w = side_w - 32;
    const so = std.math.clamp(search_open, 0, 1);
    const searching = so > 0.02;

    // search field (lights up while open)
    try cardBox(gpa, dl, x0, 28, w, 46, 13, skinPanel(accent));
    if (searching) {
        try rect(gpa, dl, x0, 28, w, 2, accent_house, 0);
        try rect(gpa, dl, x0, 72, w, 2, accent_house, 0);
        try rect(gpa, dl, x0, 28, 2, 46, accent_house, 0);
        try rect(gpa, dl, x0 + w - 2, 28, 2, 46, accent_house, 0);
    }
    try iconSearch(gpa, dl, x0 + 14, 41, 20, if (searching) accent_house else faint);
    _ = try str(gpa, dl, e, .regular, x0 + 46, 57, if (searching) ink else faint, 14, if (searching) "small" else "Search zat4");

    // SEARCH RESULTS — content-driven height that PUSHES everything below it.
    // Rows clip to the live height so they reveal as the tile grows. Pure
    // reposition: nothing is re-laid-out (the cheap within-screen movement).
    const results_full: i32 = 196;
    const push: i32 = @intFromFloat(@as(f32, @floatFromInt(results_full)) * so);
    if (searching) {
        const ry: i32 = 82;
        try rect(gpa, dl, x0, ry, w, push, 0xFF26241B, 14);
        const results = [_][2][]const u8{
            .{ "#smallweb", "zone · 412 posts" },
            .{ "#small-net", "zone · 2,481 posts" },
            .{ "@mara.zat", "Mara Vesper" },
            .{ "smallweb manifesto", "post · 2d" },
        };
        var sy: i32 = ry + 18;
        for (results) |res| {
            if (sy + 30 > ry + push) break; // clip to the live height
            try rect(gpa, dl, x0 + 12, sy, 26, 26, accent_house, 13);
            _ = try str(gpa, dl, e, .semibold, x0 + 48, sy + 13, ink, 14, res[0]);
            _ = try str(gpa, dl, e, .regular, x0 + 48, sy + 30, faint, 12, res[1]);
            sy += 44;
        }
    }

    // trending — pushed down by the open search tile
    const ty: i32 = 92 + push;
    const th: i32 = 234;
    try cardBox(gpa, dl, x0, ty, w, th, 15, skinPanel(accent));
    _ = try str(gpa, dl, e, .semibold, x0 + 18, ty + 28, faint, 12, "TRENDING");
    const trends = [_][3][]const u8{
        .{ "protocol", "at://small-net", "2,481 posts" },
        .{ "design", "glyph fields", "913 posts" },
        .{ "zig", "0.16 release", "1,204 posts" },
        .{ "monospace", "one column", "640 posts" },
    };
    var yy: i32 = ty + 54;
    for (trends) |t| {
        _ = try str(gpa, dl, e, .regular, x0 + 18, yy, faint, 12, t[0]);
        _ = try str(gpa, dl, e, .semibold, x0 + 18, yy + 19, ink, 15, t[1]);
        _ = try str(gpa, dl, e, .regular, x0 + 18, yy + 35, faint, 12, t[2]);
        yy += 48;
    }

    // who to follow
    const wy: i32 = ty + th + 18;
    const wh: i32 = 196;
    try cardBox(gpa, dl, x0, wy, w, wh, 15, skinPanel(accent));
    _ = try str(gpa, dl, e, .semibold, x0 + 18, wy + 28, faint, 12, "WHO TO FOLLOW");
    const who = [_][2][]const u8{ .{ "Desh", "@desh.zat" }, .{ "atlas", "@atlas.zat" }, .{ "rune", "@rune.zat" } };
    const tints = [_]u32{ 0xFF9FB0C7, 0xFFC9A87A, 0xFFB59EC9 };
    var py: i32 = wy + 46;
    for (who, tints) |p, tint| {
        try rect(gpa, dl, x0 + 16, py, 38, 38, tint, 19);
        const iadv: i32 = @intCast(text.advance(e, .semibold, p[0][0], 18));
        _ = try glyph1(gpa, dl, e, .semibold, x0 + 16 + @divTrunc(38 - iadv, 2), py + 25, bg, 18, p[0][0]);
        _ = try str(gpa, dl, e, .semibold, x0 + 62, py + 16, ink, 14, p[0]);
        _ = try str(gpa, dl, e, .regular, x0 + 62, py + 33, faint, 12, p[1]);
        const fbw: i32 = 76;
        const fbx = x0 + w - fbw - 12;
        try rect(gpa, dl, fbx, py + 5, fbw, 29, ink, 14);
        const flw: i32 = @intCast(text.measure(e, .semibold, "Follow", 13));
        _ = try str(gpa, dl, e, .semibold, fbx + @divTrunc(fbw - flw, 2), py + 24, bg, 13, "Follow");
        py += 48;
    }

    // §13 (AGPL): Zat4 is served over a network, so every interacting user must
    // be OFFERED the Corresponding Source. This persistent footer is that offer —
    // a visible pointer to the canonical repository, pinned to the sidebar bottom.
    // Putting the licence in the repo alone does not satisfy §13; the offer has to
    // reach network users of the running instance. Keep this visible.
    try drawAgpl(gpa, dl, e, x0, @max(py + 8, height - 40));
}

/// The AGPL §13 source offer — pinned wherever it lands (home sidebar, the profile
/// extension, or the bottom of a centred wide page). Network-served software MUST
/// keep this visible; do not drop it.
fn drawAgpl(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, x0: i32, fy: i32) error{OutOfMemory}!void {
    _ = try str(gpa, dl, e, .regular, x0, fy, faint, 12, "Zat4 — free software, GNU AGPL-3.0");
    _ = try str(gpa, dl, e, .regular, x0, fy + 18, muted, 12, "source: codeberg.org/connoravila/zat4");
}

/// The PROFILE widget EXTENSION: the right portion of the wide PROFILE panel (from
/// `m.side_x` to the panel's right edge), drawn as part of the SAME glass — a
/// fold, not a floating sidebar. Widgets are PROFILE-ONLY (the other wide pages
/// recentre their content instead). A column of customisable WIDGET slots
/// (placeholders for now — the user furnishes them; eventually the public,
/// owner-arranged profile, see LINK_PAGE_ROADMAP §11) over the AGPL source offer.
fn drawExtension(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, m: Metrics, height: i32, regions: ?*Regions) !void {
    _ = regions;
    const ex0 = m.side_x;
    const ew = (m.col_x + m.col_w) - m.side_x; // = side_w
    const x0 = ex0 + 20;
    const w = ew - 40;
    // Start BELOW the profile identity header (it spans the full wide panel and is
    // drawn on top, so content above its bottom would be occluded).
    const top: i32 = headerBottom(screen_profile) + 16;

    // The seam where the main region meets the extension — a fold in one panel.
    try rect(gpa, dl, ex0, top - 16, 1, height - (top - 16), 0x14EDEAE0, 0);

    // Customisable widget slots — placeholders for now. Faint "add a widget" cards
    // so the extension reads as a surface you furnish, not a fixed sidebar.
    _ = try str(gpa, dl, e, .semibold, x0, top + 8, faint, 11, "WIDGETS");
    var wy: i32 = top + 20;
    const slot_h: i32 = 138;
    var i: usize = 0;
    while (i < 2) : (i += 1) {
        try rect(gpa, dl, x0, wy, w, slot_h, 0x0CEDEAE0, 15);
        try rect(gpa, dl, x0, wy, w, 1, 0x1AEDEAE0, 15); // lit top edge
        const label = "+  Add a widget";
        const lw: i32 = @intCast(text.measure(e, .regular, label, 14));
        _ = try str(gpa, dl, e, .regular, x0 + @divTrunc(w - lw, 2), wy + @divTrunc(slot_h, 2) + 5, faint, 14, label);
        wy += slot_h + 16;
    }

    try drawAgpl(gpa, dl, e, x0, @max(wy + 8, height - 40));
}

/// Shift a just-emitted sticky top-bar batch DOWN by `dy` logical px so its
/// chrome clears the status bar: the draw items (dl[dl0..]), the feed regions
/// (regions[rg0..]), AND the socket's own hit-list (socket_hits[sh0..]). The
/// socket hits are a SEPARATE tap space from `regions`, so they MUST move too —
/// otherwise the socket looks shifted but its targets stay put ("touch higher
/// than it looks"). No-op when dy == 0 (desktop/preview).
fn shiftTopBar(dl: *raster.DrawList, regions: ?*Regions, socket_hits: ?*lens_socket.HitList, dl0: usize, rg0: usize, sh0: usize, dy: i32) void {
    if (dy == 0) return;
    transformDlRange(dl, dl0, dl.len, 1.0, 0, 0, 0, @floatFromInt(dy));
    if (regions) |rg| {
        var i = rg0;
        while (i < rg.items.len) : (i += 1) rg.items[i].y += @intCast(dy);
    }
    if (socket_hits) |sh| {
        var i = sh0;
        while (i < sh.items.len) : (i += 1) sh.items[i].y += @intCast(dy);
    }
}

/// Emit the whole premium feed for `posts` into `dl`, OVER whatever the
/// field already composed. `scroll` shifts the post stack (≤0 scrolls up);
/// the top bar stays pinned. Appends only — the caller cleared the list.
pub fn layout(
    gpa: Allocator,
    e: *const text.Engine,
    width: i32,
    height: i32,
    posts: []const PostView,
    scroll: i32,
    dl: *raster.DrawList,
    regions: ?*Regions,
    /// Optional per-post height cache (advance from post_top to the next post),
    /// indexed by post. A post's height is SCROLL-INVARIANT — it depends only on
    /// the body text + column width — so the caller may keep this filled across
    /// scrolls and reset it only when the feed content or width changes, turning
    /// the costly per-post text-measure pass into a one-time cost. A slot < 0 (or
    /// a too-short cache) means "not measured yet": layout measures and fills it.
    /// Pass null to always measure (the original behaviour).
    heights: ?[]i32,
    /// When true, the per-post engagement HEART icon is NOT drawn — the GPU path
    /// draws it as an SDF heart instead, so it fills + pops IN PLACE. The like
    /// region, count, and reserved space are still emitted. False (software /
    /// preview) draws the heart here as before.
    skip_heart: bool,
    /// The active top-level Screen (index into `nav_labels`). 0 = Home renders
    /// the feed; any other index renders that screen's body (a titled premium
    /// placeholder for now) while the rail + sidebar chrome stay put. The rail
    /// highlights this index.
    active_screen: u8,
    /// The profile header to draw when `active_screen == screen_profile`. The
    /// posts in `posts` are then that account's own posts (read-only Cut 1).
    /// Null on every other screen (Home draws the feed; the rest are
    /// placeholders).
    profile: ?ProfileHeader,
    /// Count of staged-but-unrevealed new posts. When > 0 on Home, a pinned
    /// "N new posts" pill is drawn below the header (a `.reveal_new` tap region).
    pending_new: usize,
    /// The app accent token — the SEATED LENS's palette color on Home
    /// (§11.5), else the house amber. Threaded down to all the chrome that
    /// re-tints (wordmark, active-nav pill + icon, New-post, tab underline,
    /// the socket cartridge). Neutrals (glass, ink, field) ignore it.
    accent: u32,
    /// The home feed's lens tray (the user's carried set, invariant 12);
    /// null = no socket on this surface. On Home it is drawn in the header
    /// — it REPLACES the Following/Discover tab labels (there is no tab
    /// strip; the seated lens is the feed's order).
    socket_tray: ?lens_socket.TrayView,
    socket_ui: lens_socket.SocketUi,
    /// The socket's tap targets for this frame (its own hit space, distinct
    /// from the feed `regions`); the shell tests these first. Null = draw-only.
    socket_hits: ?*lens_socket.HitList,
    /// Out: the chain (OP self-thread) extent for the sticky chain header (thread
    /// screen). Null = don't report.
    chain_out: ?*ChainSticky,
    /// Out: the ROOTED post's body glyphs, for read-only text selection (thread
    /// screen only — the rooted post is the one selectable post, ZONES inv. 4).
    /// Filled when the focused post is laid out; cleared otherwise. Null = the
    /// caller doesn't support selection (software path / preview / tests).
    sel_out: ?*SelGlyphs,
    /// The zone's display name (e.g. "water") when `active_screen == screen_zones`
    /// — shown as the "#name" title in the zone page's header. "" otherwise.
    zone_title: []const u8,
    /// The zones view-state bundle: the hub's catalog/tab/search/motion for
    /// `screen_zones_browse`, plus the open zone page's stats for
    /// `screen_zones` (see `ZonesView`). `.{}` on every other screen.
    zones: ZonesView,
    /// The tiling foundation (S.1): when present, the pane geometry is SOLVED by
    /// the shell's partition and handed in, so the real UI renders into those
    /// rects (and morphs as they animate). Null ⇒ self-computed `metricsPage`.
    geom: ?PaneGeom,
    /// The selected left-hand SECTION on the Settings screen (`screen_settings`)
    /// — index into `settings_view.sections`. The shell owns this selection (it
    /// is master–detail state, like the zone/thread return-screen vars); ignored
    /// on every other screen. 0 = the first section (Account).
    settings_section: u8,
    /// Runtime on/off state of the Settings toggles — a bitset indexed by GLOBAL
    /// row index (the shell owns it; seeded from each toggle's `flag_on` default).
    /// A toggle row renders on iff its bit is set. Ignored off `screen_settings`.
    settings_toggles: u64,
    /// The viewer's real identity, shown in the Account section's info rows (the
    /// table holds placeholders; the shell hands the live values). Empty fields
    /// fall back to the placeholder. Ignored off `screen_settings`.
    settings_account: SettingsAccount,
    /// Packed selected-option index per CHOICE (3 bits each, by `choiceIndex`).
    /// Drives what each wired choice row displays + the picker's checkmark.
    settings_choices: u64,
    /// The action of the choice whose picker popover is OPEN, or 255 = none.
    settings_picking: u8,
    /// The VIEW index of the post whose repost/quote menu is OPEN, or null. The
    /// menu (Repost · Quote post) is drawn AFTER the post loop so it floats on top.
    repost_menu: ?usize,
    /// Toy Box: the active layout-owning toy (`.none` = natural layout). On Home,
    /// `.depth` scales each emitted post by engagement (the "loom"); every other
    /// screen and toy value lays out unchanged.
    toys: ToyView,
    /// The device's safe-area insets in LOGICAL px (status bar top, home-pill
    /// bottom, cutout left/right). Zero on desktop/preview. The content origin
    /// drops by `top`, the bottom scroll clearance grows by `bottom`, and the
    /// sticky top bar shifts down by `top` so chrome clears the status bar.
    insets: EdgeInsets,
) error{OutOfMemory}!i32 {
    var m: Metrics = if (geom) |g|
        .{ .rail_x = g.rail_x, .col_x = g.col_x, .col_w = g.col_w, .lx = g.lx, .cw = g.cw, .side_x = g.side_x, .wide = g.wide }
    else
        metricsPage(width, active_screen);
    // ZONES read as a community surface inside the wide glass (the Reddit
    // shape), never content hugging the left of a huge panel:
    // - the HUB centres its grid band in the glass;
    // - a ZONE page centres a band of reading column + About sidebar (the
    //   sidebar drops away when the glass is too narrow for both). The
    //   masthead's coloured banner still spans the glass (col_x/col_w);
    //   its contents, the socket, and the posts align on the band (lx/cw).
    if (active_screen == screen_zones_browse and m.wide) {
        m.cw = @min(m.col_w - 96, zones_hub_band_max);
        m.lx = m.col_x + @divTrunc(m.col_w - m.cw, 2);
    }
    if (active_screen == screen_zones and m.wide) {
        const full = zone_read_w + zone_side_gap + zone_side_w;
        if (m.col_w - 48 >= full) {
            m.lx = m.col_x + @divTrunc(m.col_w - full, 2);
            m.cw = zone_read_w;
        } else if (m.cw > zone_read_w) {
            m.lx = m.col_x + @divTrunc(m.col_w - zone_read_w, 2);
            m.cw = zone_read_w;
        }
    }
    // Toy Box: Tectonic — the feed becomes a horizontal FILMSTRIP of postcards
    // that float over the living glyph field. FULL COMMIT: the glass column and
    // the floating sidebar are suppressed so the strip owns the whole width; the
    // nav rail stays as the app's spine. Each post is a fixed-height postcard laid
    // at its natural column position, then TRANSLATED into its horizontal slot
    // (with a gentle zigzag stagger). Vertical OR horizontal wheel pans it.
    const tect = toys.feed_toy == .tectonic and active_screen == screen_home;
    // Toy Box: Gravity — the same postcard TILE as tectonic, but positioned by the
    // shell's physics sim (each card falls and piles at the bottom of the column)
    // instead of a horizontal slot. Shorter tiles so several stack in view; the
    // body clamps tighter to fit. Both toys are "tile" toys — they share the card.
    const tile = tect; // (Gravity's shatter is a shell effect, not a feed tile toy.)
    const tcard_h: i32 = 392; // uniform postcard height (logical)
    const tect_pitch: i32 = m.col_w + 40; // one card + a gutter (tectonic only)

    if (regions) |rg| rg.clearRetainingCapacity();
    if (socket_hits) |sh| sh.clearRetainingCapacity();
    // No focused post laid out this frame ⇒ no selectable body. Cleared up front;
    // refilled only if the rooted post's body is drawn below.
    if (sel_out) |so| so.clearRetainingCapacity();

    // 1. The content column as GLASS floating over the field (P.0, layout layer).
    //    A soft slab shadow falls off both gutter edges so the column reads as a
    //    raised plane (the figure/ground fix), then the glass fill, then a 1px lit
    //    inner edge — the universal "raised surface" cue. (The GPU backdrop blur
    //    of the field UNDER the glass is the finishing layer on the GPU path.)
    // Tectonic suppresses the glass column entirely — the postcards float over the
    // raw field across the full width (its signature "toy" look).
    if (m.wide and !tect) {
        const sw: i32 = 20;
        const steps: i32 = 5;
        const step = @divTrunc(sw, steps);
        var k: i32 = 0;
        while (k < steps) : (k += 1) {
            const t = @as(f32, @floatFromInt(steps - k)) / @as(f32, @floatFromInt(steps));
            const shade: u32 = @as(u32, @intFromFloat(74.0 * t)) << 24; // black, fading out
            try rect(gpa, dl, m.col_x - (k + 1) * step, 0, step, height, shade, 0); // left gutter
            try rect(gpa, dl, m.col_x + m.col_w + k * step, 0, step, height, shade, 0); // right gutter
        }
    }
    if (!tect) try rect(gpa, dl, m.col_x, 0, m.col_w, height, skinVeil(accent), 0); // glass fill
    if (m.wide and !tect) {
        try rect(gpa, dl, m.col_x, 0, 1, height, 0x24EDEAE0, 0); // left lit edge
        try rect(gpa, dl, m.col_x + m.col_w - 1, 0, 1, height, 0x24EDEAE0, 0); // right lit edge
    }

    // The feed-column TOP BAR (title, tabs, divider, and its frosted box) is
    // drawn LAST — see drawTopBar at the end — so the posts scroll BEHIND it.
    // Here we only place the rail/sidebar (their own columns, nothing scrolls
    // under them) and fix where the post stack begins.
    var feed_y0: i32 = 112;
    if (m.wide) {
        // 2a. Desktop chrome: the nav rail always flanks the content. Home (and the
        // focused thread) keep the floating 3-pane SIDEBAR — separate cards with
        // the field showing between. Every other page is WIDE: the glass already
        // spans the old sidebar area as one rectangle, so the right side is an
        // EXTENSION drawn INSIDE that panel (widgets), not a separate column.
        // The rail is drawn here UNLESS the shell renders it as its own tile
        // (rail_external) so it can slide/compress independently of the content.
        if (!(geom != null and geom.?.rail_external))
            try drawRail(gpa, dl, e, m.rail_x, height, active_screen, regions, accent, skip_heart, 1.0);
        if (!isWidePage(active_screen)) {
            // Tectonic reclaims the sidebar's space for the filmstrip.
            if (!tect) try drawSidebar(gpa, dl, e, m.side_x, height, if (geom) |gg| gg.search_open else 0, accent); // home/thread: floating 3-pane sidebar
        } else if (active_screen == screen_profile) {
            try drawExtension(gpa, dl, e, m, height, regions); // profile: customisable widgets
        } else {
            // Other wide pages centre their content in the wide glass — no side
            // panel; only the AGPL offer is pinned to the content column's bottom.
            try drawAgpl(gpa, dl, e, m.lx, height - 40);
        }
        feed_y0 = 126;
    } else {
        feed_y0 = 112;
    }
    // Home (and a zone page) seat the socket in the header, so the post stack
    // starts below it.
    if (active_screen == screen_home and socket_tray != null) {
        feed_y0 = if (m.wide) home_header_h_wide + 14 else home_header_h_narrow + 12;
    }

    // The Profile screen draws an identity header band, then falls through to
    // the SAME post loop below (the posts handed in are this account's own —
    // read-only in Cut 1). Every OTHER non-Home screen is still a titled
    // placeholder until it is built.
    if (active_screen == screen_profile) {
        // The identity band is now the STICKY header (drawn pinned in
        // drawProfileHeader, called from drawTopBar) — posts scroll UNDER it, so
        // the handle/name (and, later, profile-level nav like Links) stay visible
        // without scrolling back up. Here we only fix where the post stack begins
        // — just below the header's height.
        feed_y0 = if (m.wide) profile_header_h_wide + 14 else profile_header_h_narrow + 12;
    } else if (active_screen == screen_thread) {
        // A post's thread: the `posts` handed in ARE the thread (ancestors, the
        // focused post, then replies, in that order) — fall through to the post
        // loop. The top bar shows "Thread" + a back button (drawTopBar).
    } else if (active_screen == screen_zones) {
        // A zone page: the `posts` handed in ARE the zone's feed (a tag query over
        // the store). Falls through to the post loop; the top bar is a tall zone
        // MASTHEAD (identity band + #name + Pin + description + stats + the zone
        // socket + caption), so the post stack begins below it.
        feed_y0 = if (m.wide) zone_header_h_wide + 14 else zone_header_h_narrow + 12;
    } else if (active_screen == screen_zones_browse) {
        // The Zones hub draws its own full body (title, live sub-tabs, the
        // search-or-jump field, the tab's grid/list) and owns its scroll, so
        // it returns its content height directly — no post loop, no top bar.
        // These own-body screens skip the sticky-bar path, so apply the safe-area
        // top inset here too (else the title collides with the status bar).
        const _z0 = dl.len;
        const _zr0: usize = if (regions) |rg| rg.items.len else 0;
        const _zs0: usize = if (socket_hits) |sh| sh.items.len else 0;
        const _zh = try drawZonesBrowse(gpa, dl, e, m, height, scroll, regions, accent, zones);
        shiftTopBar(dl, regions, socket_hits, _z0, _zr0, _zs0, insets.top);
        if (insets.top > 0) try rect(gpa, dl, 0, 0, width, insets.top, skinHeaderVeil(accent), 0);
        return _zh;
    } else if (active_screen == screen_settings) {
        // Settings draws its own master–detail body (a left section list + the
        // selected section's grouped rows) and owns its scroll, returning content
        // height directly — no post loop, no top bar (it draws its own title).
        const _s0 = dl.len;
        const _sr0: usize = if (regions) |rg| rg.items.len else 0;
        const _ss0: usize = if (socket_hits) |sh| sh.items.len else 0;
        const _sh = try drawSettings(gpa, dl, e, m, height, scroll, regions, accent, settings_section, settings_toggles, settings_account, settings_choices, settings_picking);
        shiftTopBar(dl, regions, socket_hits, _s0, _sr0, _ss0, insets.top);
        if (insets.top > 0) try rect(gpa, dl, 0, 0, width, insets.top, skinHeaderVeil(accent), 0);
        return _sh;
    } else if (active_screen != 0) {
        const msg = "Coming soon";
        const tw: i32 = @intCast(text.measure(e, .regular, msg, 16));
        _ = try str(gpa, dl, e, .regular, m.col_x + @divTrunc(m.col_w - tw, 2), @divTrunc(height, 2), muted, 16, msg);
        const _ptb_dl0 = dl.len;
        const _ptb_rg0: usize = if (regions) |rg| rg.items.len else 0;
        const _ptb_sh0: usize = if (socket_hits) |sh| sh.items.len else 0;
        try drawTopBar(gpa, dl, e, m, active_screen, regions, profile, accent, socket_tray, socket_ui, socket_hits, zone_title, 0, zones, scroll); // no posts scroll here, but keep the title consistent
        shiftTopBar(dl, regions, socket_hits, _ptb_dl0, _ptb_rg0, _ptb_sh0, insets.top);
        if (insets.top > 0) try rect(gpa, dl, 0, 0, width, insets.top, skinHeaderVeil(accent), 0);
        return height;
    }

    // 3. Posts. On the THREAD screen the view nests: each post is indented by its
    // (view-derived) depth and gets vertical guide rails for its ancestor levels,
    // with a smaller avatar so the staircase fits the column. Depth is 0 on every
    // other screen, so this collapses to the flat feed there.
    const is_thread = active_screen == screen_thread;
    const av: i32 = if (is_thread) 32 else 46;
    const gap: i32 = 13;
    const indent_step: i32 = 30;
    const max_levels: i32 = 7; // cap the indent so a deep thread can't run off-column
    const init_px: u16 = if (is_thread) 17 else 22;
    const av_base: i32 = @divTrunc(av * 2, 3) + 1; // avatar-initial baseline within the disc
    // Main post body at px 17 (one notch up from 16); line height scaled with it
    // (~px*1.4). Measure + paint pass MUST pass the identical px + body_line below.
    const body_line: i32 = @max(24, @as(i32, @intCast(text.lineMetrics(e, .regular, 17).height)));

    // THE REPLY SOCKET (thread screen). It sits after the root + the author's
    // leading self-thread run (consecutive posts by the root author), before
    // everyone else's replies. All-same-author → end of the thread. `*_at` is
    // the post index it precedes; == posts.len means "after the last post".
    const reply_socket_at: usize = blk: {
        if (!is_thread or socket_tray == null or posts.len == 0) break :blk std.math.maxInt(usize);
        var i: usize = 1;
        while (i < posts.len) : (i += 1) {
            if (!std.mem.eql(u8, posts[i].handle, posts[0].handle)) break :blk i;
        }
        break :blk posts.len; // all the same author → end of thread
    };
    // Narrower than the feed socket, inset to sit within the reply column.
    const reply_inset: i32 = 26;

    // Chain (OP self-thread) extent tracking for the sticky chain header.
    var chain_seen_head = false;
    var chain_ended = false;
    var chain_top_off: i32 = 0;
    var chain_bottom_off: i32 = 0;
    var chain_head_idx: u32 = 0;

    // The repost/quote menu's anchor (the repost button of the open-menu post),
    // captured during the loop and drawn AFTER it so the menu floats on top.
    var menu_anchor: ?struct { x: i32, y: i32, boosted: bool } = null;

    // Toy Box: Depth feed. Home-gated — a Home cosmetic, and gating here keeps it
    // off the thread screen, so the depth transform never touches a post whose
    // body glyphs were captured for text selection (`sel_out`, thread-only). One
    // O(n) scan resolves the visible slice's engagement range for the loom mapping.
    const depth_active = toys.feed_toy == .depth and active_screen == screen_home;
    var eng_min: u64 = std.math.maxInt(u64);
    var eng_max: u64 = 0;
    if (depth_active) {
        for (posts) |p| {
            const eng = engagementOf(p);
            eng_min = @min(eng_min, eng);
            eng_max = @max(eng_max, eng);
        }
    }

    // Tectonic: a faint horizontal "timeline track" behind the cards (drawn before
    // the loop, so the postcards land on top) — the platformer ground line.
    if (tect) {
        const track_y = feed_y0 + @divTrunc(tcard_h, 2);
        try rect(gpa, dl, m.rail_x + rail_w, track_y, width - (m.rail_x + rail_w), 2, 0x1CEDEAE0, 0);
    }

    feed_y0 += insets.top; // content clears the status bar in every branch
    var y: i32 = feed_y0 + scroll;
    for (posts, 0..) |p, pi| {
        // The reply socket precedes this post (its seam in the thread).
        if (pi == reply_socket_at) if (socket_tray) |st| {
            const sg: lens_socket.Geometry = .{ .x = m.lx + reply_inset, .y = y, .w = m.cw - reply_inset * 2, .scale = 1.0 };
            const sh = lens_socket.measuredHeight(st, socket_ui, sg);
            if (y + sh > 0 and y < height) _ = try lens_socket.build(gpa, e, st, socket_ui, sg, dl, socket_hits);
            y += sh + 18;
        };
        var nb: [12]u8 = undefined;
        // Tile toys (tectonic/gravity) emit every card at the SAME fixed top, then
        // translate it into place, so there is no natural vertical stacking here —
        // `post_top` is constant and the position comes from the transform below.
        const post_top = if (tile) feed_y0 else y;
        // Tectonic horizontal cull: skip off-strip cards BEFORE the costly text
        // measure (the vertical cull's role, moved to the X axis). The strip spans
        // the whole width now (sidebar gone), from the rail edge to the window edge.
        if (tect) {
            const sx = m.col_x + @as(i32, @intCast(pi)) * tect_pitch + scroll;
            if (sx + m.col_w <= m.rail_x + rail_w or sx >= width) continue;
        }

        // Re-root ANCESTOR (condensed context above the re-rooted post): a smaller
        // avatar + dimmed name/body, tappable to re-root on it, linked by a thin
        // connector down the chain. Drawn compact; skips the full post render.
        if (is_thread and p.depth == feed.thread_ancestor_depth) {
            const aav: i32 = 22;
            const agap: i32 = 10;
            const aax = m.lx;
            const acx = aax + aav + agap;
            const acw = m.cw - aav - agap;
            const aline: i32 = @max(19, @as(i32, @intCast(text.lineMetrics(e, .regular, 13).height)));
            const abody_top: i32 = post_top + 14 + aline;
            const acached: ?i32 = if (heights) |hh| (if (pi < hh.len and hh[pi] >= 0) hh[pi] else null) else null;
            var anext_y: i32 = undefined;
            if (acached) |adv| {
                anext_y = post_top + adv;
            } else {
                const abe = try wrapBody(gpa, dl, e, acx, abody_top, acw, muted, 13, p.body, aline, false, null);
                anext_y = abe + 16;
                if (heights) |hh| if (pi < hh.len) {
                    hh[pi] = anext_y - post_top;
                };
            }
            if (anext_y > 0 and post_top < height) {
                try emitRegion(gpa, regions, m.col_x, post_top, m.col_w, @intCast(@max(0, @min(32767, anext_y - post_top))), @intCast(pi), .post_body);
                try rect(gpa, dl, aax, post_top, aav, aav, p.tint, @intCast(aav >> 1));
                const aiadv: i32 = @intCast(text.advance(e, .semibold, p.initial, 13));
                _ = try glyph1(gpa, dl, e, .semibold, aax + @divTrunc(aav - aiadv, 2), post_top + 16, bg, 13, p.initial);
                try emitRegion(gpa, regions, aax, post_top, aav, @intCast(aav), @intCast(pi), .author);
                const abx = try str(gpa, dl, e, .semibold, acx, post_top + 13, muted, 14, p.name);
                _ = try str(gpa, dl, e, .regular, abx + 7, post_top + 13, faint, 11, p.handle);
                _ = try wrapBody(gpa, dl, e, acx, abody_top, acw, muted, 13, p.body, aline, true, null);
                // Connector down the avatar column linking the chain to the focus.
                try rect(gpa, dl, aax + @divTrunc(aav, 2) - 1, post_top + aav, 2, anext_y - (post_top + aav), 0x44B7B3A8, 0);
            }
            y = anext_y;
            continue;
        }

        // Chain extent: the first non-ancestor post is the chain HEAD; the chain
        // runs through its stitched continuation; the first non-stitched post
        // after it ends the chain (where the regular replies begin).
        if (is_thread) {
            if (!chain_seen_head) {
                chain_seen_head = true;
                chain_head_idx = @intCast(pi);
                chain_top_off = post_top - scroll;
            } else if (!p.stitched and !chain_ended) {
                chain_bottom_off = post_top - scroll;
                chain_ended = true;
            }
        }

        // View-derived nesting geometry (thread screen only).
        const dep: i32 = if (is_thread) @min(@as(i32, p.depth), max_levels) else 0;
        const indent: i32 = dep * indent_step;
        const ax = m.lx + indent; // avatar left
        const cx = ax + av + gap; // text/body left
        const content_w = m.cw - indent - av - gap;
        // A reply reserves a row for its "Replying to @x" context line above the
        // body — but ONLY on the flat feed; in a thread the rails already convey
        // the relationship. Stable per post, so the height cache stays valid.
        const show_reply_to = !is_thread and p.replying_to.len > 0;
        const reply_h: i32 = if (show_reply_to) 19 else 0;
        // A stitched segment (the root author continuing their own thread) drops
        // the header — no avatar, no name row — and starts the body near the top,
        // joined to the post above by a thin separator. Non-stitched posts keep
        // the name row above the body.
        const stitch = is_thread and p.stitched;
        const body_top_off: i32 = if (stitch) (14 + body_line) else (18 + reply_h + body_line);
        // "Chain" = the OP's stitched self-thread. A post is in the chain if it is
        // a stitched segment OR the header immediately above one. Chain posts use
        // the vertical stem + per-post elbow instead of a horizontal divider.
        const next_stitched = is_thread and pi + 1 < posts.len and posts[pi + 1].stitched;
        const in_chain = is_thread and (p.stitched or next_stitched);

        // Measure the post's height WITHOUT drawing (no i16 casts), so we can
        // both advance the scroll accounting and decide visibility. Only posts
        // that actually intersect the viewport get painted — otherwise a long
        // timeline pushes y past the 16-bit draw coordinates and overflows.
        //
        // The body wrap (text shaping) is the costly step and it is SCROLL-
        // INVARIANT. When the caller supplies a `heights` cache, reuse a filled
        // slot and skip the measure entirely — this is what keeps SCROLLING
        // cheap over a long feed (otherwise every post re-shapes every scroll
        // frame). Geometry: next_y = body_end + 48 (erow +16, row +20, gap +12),
        // so body_end = next_y - 48 reconstructs it from a cached advance.
        // The cache holds the BODY advance only (post_top → body_end) — that is
        // the costly, scroll-invariant text-shaping result. The tray height is
        // cheap and recomputed every frame (and a future per-reader fold then
        // stays cache-free), so it is added on top, not stored.
        // Main-feed Read-more: clamp a long body to `feed_clamp_lines` on Home
        // (never in a thread/detail view, and never once the reader expanded it).
        // The clamp height (body + the "Read more" line) is baked into the cached
        // advance; the paint pass below re-derives the overflow to draw the doorway.
        const clamp_lines: ?u32 = if (!is_thread and active_screen == screen_home and !p.expanded) feed_clamp_lines else null;
        const more_line_h: i32 = body_line + 6; // the "Read more" doorway's own line
        const cached: ?i32 = if (heights) |hh| (if (pi < hh.len and hh[pi] >= 0) hh[pi] else null) else null;
        var body_end: i32 = undefined;
        if (cached) |adv| {
            body_end = post_top + adv;
        } else {
            var body_ovf = false;
            const raw = try wrapBodyLimited(gpa, dl, e, cx, post_top + body_top_off, content_w, body_c, 17, p.body, body_line, false, null, clamp_lines, &body_ovf);
            body_end = raw + (if (body_ovf) more_line_h else 0);
            if (heights) |hh| if (pi < hh.len) {
                hh[pi] = body_end - post_top;
            };
        }
        // Quote-post card: a bordered mini-post below the body, before the
        // engagement row. Measured here (cheap, recomputed each frame like the
        // tray) so the row + next post drop by its height; empty ⇒ no card, and
        // an unquoted post lays out byte-for-byte as before.
        const quote_extra: i32 = if (p.quote_text.len > 0)
            (try quoteCard(gpa, dl, e, cx, 0, content_w, p.quote_author_name, p.quote_author_handle, p.quote_text, false, null, pi)) + 12
        else
            0;
        // Roomier vertical rhythm: body_end + 60 = erow(+22) + row(+22) + gap(+16).
        const erow = body_end + quote_extra + 22;
        // The tag tray sits below the engagement row; measure it now so the
        // divider + next post drop by its height (0 when the post is untagged, so
        // an untagged post lays out byte-for-byte as before).
        const tray_h = try trayLayout(gpa, dl, e, cx, 0, content_w, p.tags, accent, false, null, pi);
        const tray_extra: i32 = if (tray_h > 0) tray_h + 12 else 0;
        const bottom = erow + 22 + tray_extra;
        const next_y = body_end + quote_extra + 60 + tray_extra;
        // Tectonic cards that survived the horizontal cull are always drawn.
        const visible = if (tect) true else (next_y > 0 and post_top < height);

        // Toy Box: Depth feed captures this post's draw + region ranges so the
        // whole card (wash, avatar, name, body, engagement row/icons, tags,
        // divider) can be scaled as one unit after it is emitted.
        const dl_start = dl.len;
        const rg_start: usize = if (regions) |rg| rg.items.len else 0;

        if (visible) {
            // Tectonic: a proper POSTCARD tile behind the whole post — a solid
            // rounded panel over the field, an author-tint spine along the top, and
            // a lit edge. Emitted first (behind the content) and inside the captured
            // range, so it travels with the card when it is translated into its slot.
            if (tile) {
                try rect(gpa, dl, m.col_x, post_top - 16, m.col_w, tcard_h, 0xF01F1D17, 22); // card body
                try rect(gpa, dl, m.col_x, post_top - 16, m.col_w, 5, p.tint, 22); // author-tint spine
                try rect(gpa, dl, m.col_x, post_top - 16, m.col_w, 1, 0x22EDEAE0, 22); // lit top edge
            }
            if (tect) {
                // A big, faint FRAME NUMBER anchors the tectonic card as a filmstrip
                // frame and fills the postcard's lower body. The tinted rule above it
                // ties the number to the author's colour. (Gravity's tiles are short.)
                var frbuf: [8]u8 = undefined;
                const frn = std.fmt.bufPrint(&frbuf, "{d:0>2}", .{pi + 1}) catch "";
                try rect(gpa, dl, m.col_x + 24, post_top + tcard_h - 96, 40, 3, p.tint, 2);
                _ = try str(gpa, dl, e, .semibold, m.col_x + 22, post_top + tcard_h - 44, 0x1EEDEAE0, 52, frn);
            }

            // The focused post (thread screen): a neutral light-grey wash behind
            // it (NOT the accent — that clashed with the socket colour and muddied
            // the accent selection drawn on top). A touch stronger than the hover
            // wash (~0x16 white) so the focus still reads. Drawn first; everything
            // else sits on top.
            if (p.is_focus) try rect(gpa, dl, m.col_x, post_top - 6, m.col_w, (next_y - post_top), (0x1A << 24) | 0x00FFFFFF, 8);

            // Chain stem + elbow: a continuous vertical line at the OP avatar
            // column runs down through the headerless continuation segments
            // (tying them into one post), and turns with a SHARP right-angle
            // elbow into each segment. The header (avatar present) anchors the top
            // of the stem; segments branch off it. No horizontal divider in the
            // chain (handled below) — the stem + elbow are the structure.
            if (in_chain) {
                const sx = m.lx + @divTrunc(av, 2) - 1;
                const top = if (p.stitched) post_top else post_top + av; // stitched: row top; header: avatar bottom
                try rect(gpa, dl, sx, top, 2, next_y - top, 0x44B7B3A8, 0); // vertical spine
                if (p.stitched) {
                    // Elbow: turn right from the spine into this segment's body
                    // (sharp corner — two rects meeting, no curve).
                    const ey = post_top + body_top_off - body_line + 4; // ~first body line
                    try rect(gpa, dl, sx, ey, (cx - 10) - sx, 2, 0x44B7B3A8, 0);
                }
            }

            // Whole-post tap target → open this post's thread. Emitted FIRST so
            // the avatar + engagement regions (emitted after, found first in the
            // reverse hit-test) punch through it — "whole post minus carve-outs".
            try emitRegion(gpa, regions, m.col_x, post_top, m.col_w, @intCast(@max(0, @min(32767, bottom - post_top))), @intCast(pi), .post_body);

            // Nesting rails: a thin vertical guide at each ancestor level's avatar
            // column, spanning the row. DFS order keeps a subtree contiguous, so
            // consecutive rows form one continuous line per level (the Reddit rail).
            if (is_thread and dep > 0) {
                var l: i32 = 0;
                while (l < dep) : (l += 1) {
                    const rx = m.lx + l * indent_step + @divTrunc(av, 2);
                    try rect(gpa, dl, rx, post_top - 6, 2, (next_y - post_top), 0x33B7B3A8, 0);
                }
            }

            // Stitched continuation (root author's own chain): NO header — no
            // avatar, no name row — so the body flows directly under the previous
            // segment in the OP's column (the avatar gutter stays empty, reading as
            // one continuous post). The thin separator between segments is the
            // per-post bottom divider below (each segment sits at depth 0).
            if (!stitch) {
                // avatar disc + initial — tapping it opens that author's profile.
                try rect(gpa, dl, ax, post_top, av, av, p.tint, @intCast(av >> 1));
                const iadv: i32 = @intCast(text.advance(e, .semibold, p.initial, init_px));
                _ = try glyph1(gpa, dl, e, .semibold, ax + @divTrunc(av - iadv, 2), post_top + av_base, bg, init_px, p.initial);
                try emitRegion(gpa, regions, ax, post_top, av, @intCast(av), @intCast(pi), .author);

                // name · handle · age — three weight TIERS, baseline-aligned (P.1):
                // the name is STRONG (heaviest, brightest, biggest 18px) so the eye
                // lands there first; handle + · + age are MUTED metadata (faint,
                // smaller 13px) that recede. Body is the PRIMARY tier below.
                var bx = try str(gpa, dl, e, .semibold, cx, post_top + 18, ink, 18, p.name);
                bx = try str(gpa, dl, e, .regular, bx + 9, post_top + 18, faint, 13, p.handle);
                bx = try str(gpa, dl, e, .regular, bx + 7, post_top + 18, faint, 13, "·");
                _ = try str(gpa, dl, e, .regular, bx + 7, post_top + 18, faint, 13, p.age);

                // "Replying to @x" with a subtle ↳ hook — reads as a threaded reply
                // rather than a standalone post (Twitter/Bluesky parity).
                if (show_reply_to) {
                    const hk = try str(gpa, dl, e, .regular, cx, post_top + 36, faint, 13, "\xE2\x86\xB3 ");
                    const rl = try str(gpa, dl, e, .regular, hk, post_top + 36, muted, 13, "Replying to ");
                    _ = try str(gpa, dl, e, .regular, rl, post_top + 36, accent, 13, p.replying_to);
                }
            }

            // Collapse toggle (Reddit-style): a nested reply WITH replies gets a
            // small −/+ on its thread-line column; tapping it hides/shows the
            // subtree (per-view state, never on the post). Stitched OP segments
            // are one continuous post, so they have no toggle.
            if (is_thread and !stitch and dep > 0 and p.has_kids) {
                const tgx = ax + @divTrunc(av, 2);
                const sym: u21 = if (p.collapsed) '+' else '-';
                const sadv: i32 = @intCast(text.advance(e, .semibold, sym, 15));
                _ = try glyph1(gpa, dl, e, .semibold, tgx - @divTrunc(sadv, 2), post_top + av + 16, muted, 15, sym);
                try emitRegion(gpa, regions, tgx - 12, post_top + av + 2, 24, 24, @intCast(pi), .collapse);
            }

            // body (draw) — inline `#tags` are lit blue + made tappable (a
            // `.tag_inline` region per tag → its zone), resolved against this
            // post's served tags. Works on every post in the loop, so the feed AND
            // the thread's rooted post both get clickable hashtags.
            const body_from = dl.len;
            const body_style: BodyTags = .{ .color = tag_blue, .regions = regions, .pi = pi, .tags = p.tags };
            var paint_ovf = false;
            const paint_baseline = try wrapBodyLimited(gpa, dl, e, cx, post_top + body_top_off, content_w, body_c, 17, p.body, body_line, true, &body_style, clamp_lines, &paint_ovf);
            // "Read more" doorway (main feed, clamped body): an accent line under
            // the clamped text; its `.expand` region is emitted AFTER the whole-post
            // `.post_body` region, so the reverse hit-test lets it win — a tap
            // expands the post in place rather than opening the thread.
            if (paint_ovf) {
                const mw = try str(gpa, dl, e, .semibold, cx, paint_baseline, accent, 15, "Read more");
                try emitRegion(gpa, regions, cx, paint_baseline - 15, mw - cx, 22, @intCast(pi), .expand);
            }
            // Quote-post card (paint) — anchored at body_end (which already folds in
            // any Read-more line), so it sits below the doorway and above the row.
            if (p.quote_text.len > 0) {
                _ = try quoteCard(gpa, dl, e, cx, body_end + 6, content_w, p.quote_author_name, p.quote_author_handle, p.quote_text, true, regions, pi);
            }
            // The rooted post (thread screen) is the one selectable post: capture
            // its body glyphs for the read-only selection layer (ZONES inv. 4 —
            // selection is a query over this transient map, never a stored copy).
            if (is_thread and p.is_focus) if (sel_out) |so| try captureBody(so, gpa, e, dl, body_from);

            // Engagement row — roomier spacing + a fuller action set. LEFT group:
            // reply · repost · like (icon + count); RIGHT group: bookmark · share ·
            // more, right-aligned (decorative for now — the regions carry the post
            // so hover can highlight them and a later slice can wire them).
            const is: i32 = 17;
            const iy = erow - 13;
            const tap_h: u16 = 32;
            const tap_y: i32 = erow - 21;
            const cgap: i32 = 9; // icon → count
            const ggap: i32 = 36; // count → next group's icon (the "less cramped" gap)
            const slot_w: i32 = is + cgap + 18; // generous tap target per item
            var ex = cx;
            const reply_x = ex;
            // GPU path: the SDF-icon pass draws all these crisply in place; only
            // the software path strokes the line-art. Counts + regions still emit.
            if (!skip_heart) try iconReply(gpa, dl, ex, iy, is, icon_grey);
            ex += is + cgap;
            ex = try str(gpa, dl, e, .regular, ex, erow, muted, 13, std.fmt.bufPrint(&nb, "{d}", .{p.reply}) catch "0");
            try emitRegion(gpa, regions, reply_x, tap_y, slot_w, tap_h, @intCast(pi), .reply);
            ex = reply_x + slot_w + ggap;
            const rt_x = ex;
            // On the GPU path (skip_heart) the SDF-icon pass draws the repost
            // crisply in place — like the heart; here only the software path
            // strokes the line-art version. The count + region still emit below.
            if (!skip_heart) try iconRepost(gpa, dl, ex, iy, is, if (p.boosted) boost_c else icon_grey);
            ex += is + cgap;
            _ = try str(gpa, dl, e, .regular, ex, erow, if (p.boosted) boost_c else muted, 13, std.fmt.bufPrint(&nb, "{d}", .{p.boost}) catch "0");
            try emitRegion(gpa, regions, rt_x, tap_y, slot_w, tap_h, @intCast(pi), .repost);
            if (repost_menu == pi) menu_anchor = .{ .x = rt_x, .y = tap_y, .boosted = p.boosted };
            const like_x = rt_x + slot_w + ggap;
            // Liked → FILLED red heart; unliked → HOLLOW outline. On the GPU path
            // this is SKIPPED — the SDF heart pass draws it in place.
            if (!skip_heart) {
                if (p.liked) {
                    try iconHeart(gpa, dl, like_x, iy, is, like_c);
                } else {
                    try iconHeartHollow(gpa, dl, like_x, iy, is, icon_grey);
                }
            }
            _ = try str(gpa, dl, e, .regular, like_x + is + cgap, erow, if (p.liked) like_c else muted, 13, std.fmt.bufPrint(&nb, "{d}", .{p.like}) catch "0");
            try emitRegion(gpa, regions, like_x, tap_y, slot_w, tap_h, @intCast(pi), .like);

            // RIGHT group: bookmark · share · more, right-aligned at the content
            // edge. A stitched segment shows the COMPACT row (reply/repost/like
            // only — image #2), so the right group is omitted there.
            if (!stitch) {
                const rgap: i32 = 32;
                var rxp = cx + content_w - is;
                if (!skip_heart) try iconMore(gpa, dl, rxp, iy, is, icon_grey);
                try emitRegion(gpa, regions, rxp - 7, tap_y, is + 14, tap_h, @intCast(pi), .more);
                rxp -= rgap;
                if (!skip_heart) try iconShare(gpa, dl, rxp, iy, is, icon_grey);
                try emitRegion(gpa, regions, rxp - 7, tap_y, is + 14, tap_h, @intCast(pi), .share);
                rxp -= rgap;
                if (!skip_heart) try iconBookmark(gpa, dl, rxp, iy, is, icon_grey);
                try emitRegion(gpa, regions, rxp - 7, tap_y, is + 14, tap_h, @intCast(pi), .bookmark);
            }

            // Tag tray — the row of tappable zone-doorways below the actions.
            // Drawn for any post that carries tags (the feed↔zone stitch).
            if (p.tags.len > 0) {
                _ = try trayLayout(gpa, dl, e, cx, erow + 26, content_w, p.tags, accent, true, regions, pi);
            }

            // divider — full-width on the flat feed; the thread uses a short
            // divider under the indented content. CHAIN posts get NO horizontal
            // divider — the vertical stem + elbow are their separation instead.
            if (is_thread) {
                if (!in_chain) try rect(gpa, dl, ax, bottom, m.col_x + m.col_w - ax - 4, 1, divider, 0);
            } else if (!tile) { // tile toys separate cards by the tile, not a line
                try rect(gpa, dl, m.col_x, bottom, m.col_w, 1, divider, 0);
            }
        }

        // Toy Box: Depth feed. Scale the post's emitted range about its own centre
        // — nearer (louder) looms, quieter recedes. v1 is scale-only (dx=dy=0); the
        // pivot at the column centre + post mid keeps the scaled box within ~6% of
        // the natural edges, so the untransformed cull above stays safe. `y`/`next_y`
        // (scroll + height accounting) are left untouched, so the `heights` cache and
        // all scroll math remain exact. Regions transform too, so taps land on the
        // loomed card and the GPU SDF icons (positioned off regions) follow it.
        if (visible and active_screen == screen_home) switch (toys.feed_toy) {
            .depth => {
                const s = loomScale(p, eng_min, eng_max);
                const pcx = @as(f32, @floatFromInt(m.col_x)) + @as(f32, @floatFromInt(m.col_w)) * 0.5;
                const pcy = (@as(f32, @floatFromInt(post_top)) + @as(f32, @floatFromInt(next_y))) * 0.5;
                transformDlRange(dl, dl_start, dl.len, s, pcx, pcy, 0, 0);
                if (regions) |rg| transformRegionsRange(rg, rg_start, rg.items.len, s, pcx, pcy, 0, 0);
            },
            .tectonic => {
                // Translate the full-size postcard (no scaling — text stays crisp)
                // to its horizontal slot. The X offset carries `scroll`, so a
                // vertical OR horizontal wheel pans the strip; odd cards drop by a
                // stagger for a playful platformer zigzag.
                const screen_x = m.col_x + @as(i32, @intCast(pi)) * tect_pitch + scroll;
                const stagger: i32 = if (pi % 2 == 1) 54 else 0;
                const dx = @as(f32, @floatFromInt(screen_x - m.col_x));
                const dy = @as(f32, @floatFromInt(stagger));
                transformDlRange(dl, dl_start, dl.len, 1.0, 0, 0, dx, dy);
                if (regions) |rg| transformRegionsRange(rg, rg_start, rg.items.len, 1.0, 0, 0, dx, dy);
            },
            .zero_g => {
                // Weightless drift: each post floats on a slow 2-D Lissajous, its
                // phase seeded by index so they wander independently. A pure
                // function of (time, index) — no persistent state, no scroll.
                const ph = @as(f32, @floatFromInt(pi)) * 1.7;
                const dx = @sin(toys.t * 0.55 + ph) * 15.0 + @sin(toys.t * 0.21 + ph * 2.3) * 6.0;
                const dy = @sin(toys.t * 0.73 + ph * 1.3) * 11.0 + @cos(toys.t * 0.29 + ph) * 5.0;
                transformDlRange(dl, dl_start, dl.len, 1.0, 0, 0, dx, dy);
                if (regions) |rg| transformRegionsRange(rg, rg_start, rg.items.len, 1.0, 0, 0, dx, dy);
            },
            .liquid => {
                // Sloshing: a horizontal wave whose amplitude is the shell's
                // scroll-kicked `flow` spring; the per-post phase makes the column
                // ripple like water and settle when flow decays to 0.
                const ph = @as(f32, @floatFromInt(pi)) * 0.6;
                const amp = toys.flow;
                const dx = @sin(toys.t * 5.0 - ph) * amp;
                const dy = @cos(toys.t * 4.2 - ph) * amp * 0.3;
                transformDlRange(dl, dl_start, dl.len, 1.0, 0, 0, dx, dy);
                if (regions) |rg| transformRegionsRange(rg, rg_start, rg.items.len, 1.0, 0, 0, dx, dy);
            },
            else => {},
        };
        y = next_y;
    }
    // All-same-author thread: the reply socket lands at the very end.
    if (is_thread and reply_socket_at == posts.len) if (socket_tray) |st| {
        const sg: lens_socket.Geometry = .{ .x = m.lx + reply_inset, .y = y, .w = m.cw - reply_inset * 2, .scale = 1.0 };
        const sh = lens_socket.measuredHeight(st, socket_ui, sg);
        if (y + sh > 0 and y < height) _ = try lens_socket.build(gpa, e, st, socket_ui, sg, dl, socket_hits);
        y += sh + 18;
    };
    // The sticky top bar, drawn LAST so the posts above scroll BEHIND its
    // frosted box with the title/tabs crisp on top. `posts.len` feeds the zone
    // masthead's stats line (on the zone screen `posts` IS the zone feed).
    // Its emitted items, regions AND socket hits are shifted DOWN by insets.top
    // so the wordmark/socket clear the status bar (only when there is a top
    // inset). Then a veil strip covers the gap ABOVE the shifted header so posts
    // scrolling up don't show through between the screen top and the header.
    const _tb_dl0 = dl.len;
    const _tb_rg0: usize = if (regions) |rg| rg.items.len else 0;
    const _tb_sh0: usize = if (socket_hits) |sh| sh.items.len else 0;
    try drawTopBar(gpa, dl, e, m, active_screen, regions, profile, accent, socket_tray, socket_ui, socket_hits, zone_title, posts.len, zones, scroll);
    shiftTopBar(dl, regions, socket_hits, _tb_dl0, _tb_rg0, _tb_sh0, insets.top);
    if (insets.top > 0) try rect(gpa, dl, 0, 0, width, insets.top, skinHeaderVeil(accent), 0);

    // The zone page's About sidebar (drawn after the masthead so its top
    // tracks the collapsing band's live bottom edge).
    if (active_screen == screen_zones and m.wide and m.col_w - 48 >= zone_read_w + zone_side_gap + zone_side_w)
        try drawZoneSidebar(gpa, dl, e, m, regions, accent, zone_title, posts.len, zones, scroll);

    // The "N new posts" pill (Home only): staged arrivals waiting to be revealed.
    // Pinned just below the header, centered; tapping it reveals + scrolls to top
    // — the reader is never displaced involuntarily (Twitter/Bluesky pattern).
    if (active_screen == screen_home and pending_new > 0) {
        var pb: [40]u8 = undefined;
        const label = std.fmt.bufPrint(&pb, "\xE2\x86\x91 {d} new post{s}", .{ pending_new, if (pending_new == 1) "" else "s" }) catch "new posts";
        const lw: i32 = @intCast(text.measure(e, .semibold, label, 14));
        const pw = lw + 40;
        const pill_h: i32 = 38;
        const px = m.col_x + @divTrunc(m.col_w - pw, 2);
        const py: i32 = if (m.wide) 120 else 104;
        try rect(gpa, dl, px, py, pw, pill_h, accent, 19);
        _ = try str(gpa, dl, e, .semibold, px + 20, py + 25, bg, 14, label);
        try emitRegion(gpa, regions, px, py, pw, pill_h, 0, .reveal_new);
    }
    // The repost/quote menu — a small floating panel below the tapped repost
    // button (the middle action doubles as Repost + Quote, the universal pattern).
    // Drawn LAST so it lands on top of the posts and the top bar; its rows carry
    // the menu post's index. Only drawn when that post was visible this frame.
    if (menu_anchor) |ma| if (repost_menu) |mp| {
        const menu_w: i32 = 196;
        const row_h: i32 = 46;
        const menu_h: i32 = row_h * 2 + 12;
        var mx = ma.x - 12;
        if (mx + menu_w > width - 10) mx = width - 10 - menu_w;
        if (mx < 10) mx = 10;
        // Below the button, unless that runs off the bottom → flip above.
        var my = ma.y + 40;
        if (my + menu_h > height - 10) my = ma.y - menu_h - 8;
        try rect(gpa, dl, mx, my, menu_w, menu_h, 0xF61E1E18, 14); // opaque panel
        try rect(gpa, dl, mx, my, menu_w, menu_h, 0x22000000, 14); // subtle edge darken
        const r1y = my + 6;
        const r2y = r1y + row_h;
        _ = try str(gpa, dl, e, .semibold, mx + 18, r1y + 29, if (ma.boosted) boost_c else ink, 15, if (ma.boosted) "Undo repost" else "Repost");
        try emitRegion(gpa, regions, mx, r1y, menu_w, @intCast(row_h), @intCast(mp), .repost_do);
        try rect(gpa, dl, mx + 14, r2y, menu_w - 28, 1, divider, 0); // row divider
        _ = try str(gpa, dl, e, .semibold, mx + 18, r2y + 29, ink, 15, "Quote post");
        try emitRegion(gpa, regions, mx, r2y, menu_w, @intCast(row_h), @intCast(mp), .quote_new);
    };

    if (chain_out) |co| co.* = .{
        .present = is_thread and chain_seen_head,
        .head_index = chain_head_idx,
        .top_off = chain_top_off,
        .bottom_off = if (chain_ended) chain_bottom_off else (y - scroll), // all-chain → thread end
        .pin_y = feed_y0,
    };
    // Tectonic maps vertical scroll → horizontal pan, so the "content extent" the
    // shell clamps scroll against is the STRIP WIDTH (the total run of cards).
    if (tect) return m.col_x + @as(i32, @intCast(posts.len)) * tect_pitch + 60;
    // Pure content height (scroll-independent), for the shell's scroll clamp. The
    // phone bottom-chrome clearance (tab bar + home-pill inset) that lifts the last
    // row clear of the tab bar is added ONCE in the shell for EVERY screen (see the
    // render funnel), not baked in here — every own-body screen gets it uniformly,
    // and the pure layout stays device-agnostic (B3/B4: the shell owns chrome).
    return y - scroll;
}

/// Scale a color's alpha by `al` (0..1), keeping its RGB — for fading an overlay.
fn aScale(c: u32, al: f32) u32 {
    const a8: u32 = @intFromFloat(@as(f32, @floatFromInt(c >> 24)) * std.math.clamp(al, 0.0, 1.0));
    return (a8 << 24) | (c & 0x00FFFFFF);
}

/// Draw the sticky CHAIN header bar into `dl` (a shell overlay): a frosted band
/// across the feed column with the chain author's avatar + display name + @handle,
/// faded by `alpha`. The bar is clamped to start at `pin_y` (so it grows out from
/// under the top bar during the catch-up rather than covering it); the avatar +
/// text center vertically in the visible band. The shell positions `draw_y` (the
/// pure-sticky + catch-up math) and animates `alpha`.
pub fn buildChainHeaderBar(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, width: i32, draw_y: i32, header_h: i32, pin_y: i32, tint: u32, initial: u21, name: []const u8, handle: []const u8, accent: u32, alpha: f32, band_top_override: ?i32) error{OutOfMemory}!void {
    _ = pin_y;
    const m = metricsFor(width);
    // The frosted band fills from the thread top bar's BOTTOM (drawTopBar box_h:
    // 111 wide / 96 narrow) down to the header — so it CONNECTS to the "Thread"
    // bar with no gap (the content still rides at `draw_y` for the seamless seam).
    // PHONE passes an override of 0: the fixed 96 misses the safe-area inset
    // shift, and the frosted veil alone let the "Thread" title ghost through at
    // the top (owner, 2026-07-09) — the override band also gets an OPAQUE
    // backing so nothing shows through it.
    const band_top: i32 = band_top_override orelse (if (m.wide) 111 else 96);
    const band_bottom = draw_y + header_h;
    if (band_bottom > band_top) {
        if (band_top_override != null)
            try rect(gpa, dl, m.col_x, band_top, m.col_w, band_bottom - band_top, aScale(bg, alpha), 0);
        try rect(gpa, dl, m.col_x, band_top, m.col_w, band_bottom - band_top, aScale(skinHeaderVeil(accent), alpha), 0);
        try rect(gpa, dl, m.col_x, band_bottom - 1, m.col_w, 1, aScale((0x66 << 24) | (divider & 0x00FFFFFF), alpha), 0);
    }
    // Avatar + name + @handle drawn at the EXACT geometry of the inline thread
    // header (av=32, gap=13, avatar initial baseline +22 @17px, name +18 @18px ink,
    // handle @13px faint) so when `draw_y` == the inline post_top the pinned bar is
    // pixel-identical to the original — the scroll-up handoff has no seam.
    const av: i32 = 32;
    const gap: i32 = 13;
    const ax = m.lx;
    try rect(gpa, dl, ax, draw_y, av, av, aScale(tint, alpha), @intCast(av >> 1));
    const iadv: i32 = @intCast(text.advance(e, .semibold, initial, 17));
    _ = try glyph1(gpa, dl, e, .semibold, ax + @divTrunc(av - iadv, 2), draw_y + 22, aScale(bg, alpha), 17, initial);
    const cx = ax + av + gap;
    const nx = try str(gpa, dl, e, .semibold, cx, draw_y + 18, aScale(ink, alpha), 18, name);
    _ = try str(gpa, dl, e, .regular, nx + 9, draw_y + 18, aScale(faint, alpha), 13, handle);
}

/// The end pen and the caret pen returned by the draft wrapper.
/// A7.2: cold — a single transient value per compose frame, never collected.
const DraftPens = struct { end: Pen, caret: Pen };

/// Word-wrap `draft` into `maxw`, honouring explicit '\n' line breaks, drawing
/// as it goes. Returns the pen after the last glyph AND the pen at byte offset
/// `caret_at` — the composer now supports mid-text editing, so the caret can sit
/// anywhere, not only at the end. A word longer than the column is not split
/// mid-word (it overhangs) — drafts are short and this keeps the wrapper a single
/// honest pass. The inverse query (a click → byte offset) is `composeCaretAtPoint`
/// below; the two share the wrap rule and must stay in step.
fn wrapDraft(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, x0: i32, first_baseline: i32, maxw: i32, color: u32, px: u16, draft: []const u8, line_h: i32, caret_at: usize, sel_start: usize, sel_end: usize) !DraftPens {
    var baseline = first_baseline;
    var x = x0;
    var caret_pen: Pen = .{ .x = x0, .baseline = first_baseline };
    var word_start: usize = 0;
    var i: usize = 0;
    while (i <= draft.len) : (i += 1) {
        const at_end = i == draft.len;
        const ch: u8 = if (at_end) 0 else draft[i];
        if (!at_end and ch != ' ' and ch != '\n') continue;
        const word = draft[word_start..i];
        if (word.len > 0) {
            const ww: i32 = @intCast(text.measure(e, .regular, word, px));
            if (x > x0 and x + ww > x0 + maxw) { // wrap BEFORE this word
                baseline += line_h;
                x = x0;
            }
            // Selection highlight behind the selected sub-run of this word.
            if (sel_end > sel_start) {
                const ss = @max(sel_start, word_start);
                const se = @min(sel_end, i);
                if (se > ss) {
                    const hx0 = x + @as(i32, @intCast(text.measure(e, .regular, draft[word_start..ss], px)));
                    const hx1 = x + @as(i32, @intCast(text.measure(e, .regular, draft[word_start..se], px)));
                    try rect(gpa, dl, hx0, baseline - 15, hx1 - hx0, 20, sel_fill, 2);
                }
            }
            // Caret inside this word (or at its edges): measure the sub-run.
            if (caret_at >= word_start and caret_at <= i) {
                const sw: i32 = @intCast(text.measure(e, .regular, draft[word_start..caret_at], px));
                caret_pen = .{ .x = x + sw, .baseline = baseline };
            }
            x = try str(gpa, dl, e, .regular, x, baseline, color, px, word);
        } else if (caret_at == word_start) {
            // Empty segment (leading/again-consecutive separator): caret here.
            caret_pen = .{ .x = x, .baseline = baseline };
        }
        if (at_end) break;
        if (ch == ' ') {
            if (x > x0) {
                // A selected space gets its own highlight cell.
                if (sel_end > sel_start and i >= sel_start and i < sel_end)
                    try rect(gpa, dl, x, baseline - 15, @intCast(text.advance(e, .regular, ' ', px)), 20, sel_fill, 2);
                x += @intCast(text.advance(e, .regular, ' ', px)); // no leading space
            }
        } else { // '\n' — explicit break
            baseline += line_h;
            x = x0;
        }
        word_start = i + 1;
    }
    return .{ .end = .{ .x = x, .baseline = baseline }, .caret = caret_pen };
}

/// The composer text-box geometry, shared by `layoutCompose` (drawing + caret)
/// and `composeCaretAtPoint` (click → offset) so the two never drift.
/// A7.2: cold — a single transient value computed per compose frame.
const ComposeGeom = struct { lx: i32, text_top: i32, inner_w: i32, line_h: i32 };
fn composeGeom(e: *const text.Engine, width: i32) ComposeGeom {
    const m = metricsFor(width);
    const cx0 = m.col_x + 16;
    const cw = m.col_w - 32;
    const card_y: i32 = 92;
    const pad: i32 = 24;
    const body_line: i32 = @max(24, @as(i32, @intCast(text.lineMetrics(e, .regular, 17).height)));
    return .{ .lx = cx0 + pad, .text_top = card_y + 50 + 14 + body_line, .inner_w = cw - pad * 2, .line_h = body_line };
}

/// Keep the candidate boundary nearest the hit point — line distance dominates
/// (scaled), then horizontal distance breaks ties within the line.
fn nearerBoundary(off: u32, bx: i32, bbaseline: i32, hx: i32, hy: i32, best_off: *u32, best_score: *i64) void {
    const dy: i64 = @intCast(@abs(@as(i64, bbaseline) - hy));
    const dx: i64 = @intCast(@abs(@as(i64, bx) - hx));
    const score = dy * 4096 + dx;
    if (score < best_score.*) {
        best_score.* = score;
        best_off.* = off;
    }
}

/// Map a click at logical (`hx`,`hy`) to the nearest caret byte offset in
/// `draft`, replaying the same wrap as `wrapDraft`/`layoutCompose`. Pure: the
/// shell calls it on a composer click, then `textedit.setCaret`.
pub fn composeCaretAtPoint(e: *const text.Engine, width: i32, draft: []const u8, hx: i32, hy: i32) u32 {
    if (draft.len == 0) return 0;
    const px: u16 = 17;
    const g = composeGeom(e, width);
    var baseline = g.text_top;
    var x = g.lx;
    var best_off: u32 = 0;
    var best_score: i64 = std.math.maxInt(i64);
    var word_start: usize = 0;
    var i: usize = 0;
    while (i <= draft.len) : (i += 1) {
        const at_end = i == draft.len;
        const ch: u8 = if (at_end) 0 else draft[i];
        if (!at_end and ch != ' ' and ch != '\n') continue;
        const word = draft[word_start..i];
        if (word.len > 0) {
            const ww: i32 = @intCast(text.measure(e, .regular, word, px));
            if (x > g.lx and x + ww > g.lx + g.inner_w) {
                baseline += g.line_h;
                x = g.lx;
            }
            // Boundary before the word, then after each codepoint within it.
            nearerBoundary(@intCast(word_start), x, baseline, hx, hy, &best_off, &best_score);
            var k: usize = word_start;
            var wx = x;
            while (k < i) {
                const clen: usize = std.unicode.utf8ByteSequenceLength(draft[k]) catch 1;
                const adv: i32 = @intCast(text.measure(e, .regular, draft[k .. k + clen], px));
                wx += adv;
                k += clen;
                nearerBoundary(@intCast(k), wx, baseline, hx, hy, &best_off, &best_score);
            }
            x += ww;
        } else {
            nearerBoundary(@intCast(word_start), x, baseline, hx, hy, &best_off, &best_score);
        }
        if (at_end) break;
        if (ch == ' ') {
            if (x > g.lx) x += @intCast(text.advance(e, .regular, ' ', px));
        } else {
            baseline += g.line_h;
            x = g.lx;
        }
        nearerBoundary(@intCast(i + 1), x, baseline, hx, hy, &best_off, &best_score);
        word_start = i + 1;
    }
    return best_off;
}

/// The premium composer (PHASE C1): the New-post / reply / profile-editor input
/// surface, rendered in the feed_view vocabulary over the living field instead
/// of the cell-grid composer. Pure (B2): same draft + engine ⇒ same draw list.
/// The shell keeps the draft buffer and the keyboard input path unchanged; this
/// only renders it and emits the footer button regions (`compose_send` /
/// `compose_cancel`) so a mouse can drive what Ctrl-D / Esc already do.
pub fn layoutCompose(
    gpa: Allocator,
    e: *const text.Engine,
    width: i32,
    height: i32,
    /// The app's live accent (the seated lens's color) — so the composer matches
    /// the rest of the site, not the static house amber.
    accent: u32,
    ctx: ComposeContext,
    /// "@handle" of the post being replied to, when `ctx == .reply`; else "".
    reply_handle: []const u8,
    /// The quoted post's author handle (no '@') when composing a quote-post; ""
    /// otherwise. Draws a "Quoting @x" line so the composer shows what it embeds.
    quoting: []const u8,
    draft: []const u8,
    /// Byte offset of the insertion point in `draft` (the textedit caret).
    caret: usize,
    /// Selected byte range `[sel_start, sel_end)` (equal ⇒ no selection).
    sel_start: usize,
    sel_end: usize,
    /// Whether to paint the caret this frame (the shell's blink clock).
    blink_on: bool,
    /// A status / hint line shown in the footer (the shell's compose status).
    status: []const u8,
    /// Finalized thread segments stacked above the active box (empty ⇒ a lone
    /// post). Each renders as a compact preview with an ✕ (`.compose_remove`,
    /// carrying its index); the "Add" button (`.compose_add`) appends the active
    /// box here, and Send publishes them all as one self-reply chain.
    segments: []const []const u8,
    /// The TAG BAR's state — see `ComposeTagBarView`.
    tag_bar: ComposeTagBarView,
    dl: *raster.DrawList,
    regions: ?*Regions,
) error{OutOfMemory}!void {
    const m = metricsFor(width);
    if (regions) |rg| rg.clearRetainingCapacity();

    // A heavy veil over the WHOLE surface dims the feed/field uniformly so the
    // composer reads as a focused overlay; the field still glows faintly through.
    try rect(gpa, dl, 0, 0, width, height, header_veil, 0);

    // The card: centred in the feed column. It grows to fit any finalized thread
    // segments (each a compact row), capped by the window; a lone post keeps the
    // comfortable fixed height.
    const cx0 = m.col_x + 16;
    const cw = m.col_w - 32;
    const card_y: i32 = 92;
    const body_line: i32 = @max(24, @as(i32, @intCast(text.lineMetrics(e, .regular, 17).height)));
    const seg_row: i32 = body_line + 10;
    const stack_h: i32 = if (segments.len > 0) @as(i32, @intCast(segments.len)) * seg_row + 14 else 0;
    const has_tag_bar = ctx != .profile;
    const bar_h: i32 = if (has_tag_bar) 48 else 0;
    const card_h: i32 = @min(height - card_y - 40, 380 + stack_h + bar_h);
    // Soft shadow so the card lifts off the dimmed backdrop — bracketed by the
    // theme-lock so the light remap keeps it a dark shadow (not inverted to white).
    try rect(gpa, dl, 0, 0, 0, 0, lens_socket.theme_keep_begin, 0);
    try rect(gpa, dl, cx0 - 1, card_y + 8, cw + 2, card_h + 2, 0x18000000, 22);
    try rect(gpa, dl, cx0, card_y + 4, cw, card_h, 0x20000000, 18);
    try rect(gpa, dl, 0, 0, 0, 0, lens_socket.theme_keep_end, 0);
    // The card: a BORDERED panel. The hairline is what defines it against the
    // backdrop in light mode, where the fill and the veil are both near-white.
    try cardBox(gpa, dl, cx0, card_y, cw, card_h, 18, skinPanel(accent));

    const pad: i32 = 24;
    const lx = cx0 + pad;
    const inner_w = cw - pad * 2;

    // Context line: who/what this is.
    const send_label: []const u8 = switch (ctx) {
        .reply => "Reply",
        .post => if (segments.len > 0) "Post all" else "Post",
        .profile => "Save",
    };
    const hx = try str(gpa, dl, e, .semibold, lx, card_y + 34, ink, 18, switch (ctx) {
        .reply => "Replying to ",
        .post => "New post",
        .profile => "Edit your display name",
    });
    if (ctx == .reply and reply_handle.len > 0) _ = try str(gpa, dl, e, .semibold, hx, card_y + 34, accent, 18, reply_handle);
    try rect(gpa, dl, cx0, card_y + 50, cw, 1, divider, 0);

    // Quote-post: a "Quoting @x" line under the header so the composer shows what
    // it will embed (the quoted post's full card renders in the feed after send).
    var stack_y = card_y + 50 + 10;
    if (quoting.len > 0) {
        const qx = try str(gpa, dl, e, .regular, lx, stack_y + 14, muted, 13, "Quoting @");
        _ = try str(gpa, dl, e, .semibold, qx, stack_y + 14, accent, 13, quoting);
        stack_y += 26;
    }

    // The finalized thread segments: compact previews under the header, tied by a
    // thin rail into one thread, each with a ✕ to drop it. Only posts chain.
    if (segments.len > 0) {
        const rail_x = lx + 3;
        const n: i32 = @intCast(segments.len);
        try rect(gpa, dl, rail_x, stack_y + 6, 2, n * seg_row - 10, scaleAlpha(accent, 0.5), 0);
        for (segments, 0..) |seg, si| {
            const ry = stack_y + @as(i32, @intCast(si)) * seg_row;
            const baseline = ry + body_line - 6;
            try rect(gpa, dl, rail_x - 2, baseline - 9, 6, 6, accent, 3); // node dot
            const rmw: i32 = 22; // reserved for the ✕
            try strEllipsis(gpa, dl, e, .regular, lx + 18, baseline, muted, 15, seg, inner_w - 18 - rmw - 8);
            _ = try str(gpa, dl, e, .semibold, cx0 + cw - pad - rmw, baseline, faint, 15, "\xC3\x97"); // ×
            try emitRegion(gpa, regions, cx0 + cw - pad - rmw - 6, ry, rmw + 12, @intCast(seg_row), @intCast(si), .compose_remove);
        }
        stack_y += n * seg_row;
        try rect(gpa, dl, cx0, stack_y + 4, cw, 1, divider, 0);
        stack_y += 4;
    }

    // The input WELL: a bordered box around the text-entry area, so the composer
    // reads as a real field instead of floating text on the card.
    const fy_well = card_y + card_h - 46;
    const well_top = stack_y + 6;
    const well_bottom = if (has_tag_bar) fy_well - 64 - 10 else fy_well - 12;
    if (well_bottom - well_top > 40)
        try cardBox(gpa, dl, lx - 10, well_top, inner_w + 20, well_bottom - well_top, 12, panel_hover);

    // The draft (or a faint placeholder), wrapped from just under the stack.
    const text_top = stack_y + 14 + body_line;
    const cursor: Pen = if (draft.len == 0) blk: {
        const ph: []const u8 = switch (ctx) {
            .reply => "Write your reply…",
            .post => if (segments.len > 0) "Add another post…" else "What's on the field?",
            .profile => "Your display name",
        };
        _ = try str(gpa, dl, e, .regular, lx, text_top, faint, 17, ph);
        break :blk .{ .x = lx, .baseline = text_top };
    } else (try wrapDraft(gpa, dl, e, lx, text_top, inner_w, body_c, 17, draft, body_line, caret, sel_start, sel_end)).caret;

    // The text cursor: a thin accent bar at the caret, one cap-height tall —
    // painted only on the "on" half of the shell's blink cycle.
    if (blink_on) try rect(gpa, dl, cursor.x + 1, cursor.baseline - 15, 2, 19, accent, 1);

    // Footer: Cancel (left, text) · char count · Send pill (right).
    const fy = card_y + card_h - 46;

    // ── THE TAG BAR — the post's zones, gathered in one place while you
    // write: the LOCKED chip (composing from a zone page — solid, no ×),
    // the "+ tag" chips (removable), and the live INLINE #tags mirrored out
    // of the prose (dim — they live in the text; edit the text to drop
    // them). Duplicates fold left-to-right: locked > manual > inline.
    if (has_tag_bar) {
        const bar_y = fy - 64;
        var chx = lx;
        const chip_h: i32 = 30;
        const right_stop = cx0 + cw - pad;
        // Locked (the zone you're posting into).
        if (tag_bar.locked.len > 0) {
            const w2: i32 = @intCast(text.measure(e, .semibold, tag_bar.locked, 13) + 34);
            if (chx + w2 <= right_stop) {
                try rect(gpa, dl, chx, bar_y, w2, chip_h, accent, 15);
                const hx2 = try str(gpa, dl, e, .semibold, chx + 12, bar_y + 20, bg, 13, "#");
                _ = try str(gpa, dl, e, .semibold, hx2, bar_y + 20, bg, 13, tag_bar.locked);
                chx += w2 + 8;
            }
        }
        // Manual chips, each with an × (the × is the tap target).
        for (tag_bar.manual, 0..) |t, ti| {
            if (std.ascii.eqlIgnoreCase(t, tag_bar.locked)) continue;
            const tw2: i32 = @intCast(text.measure(e, .semibold, t, 13));
            const w2 = tw2 + 52;
            if (chx + w2 > right_stop) break;
            try rect(gpa, dl, chx, bar_y, w2, chip_h, 0x33000000, 15);
            const hx2 = try str(gpa, dl, e, .semibold, chx + 12, bar_y + 20, ink, 13, "#");
            _ = try str(gpa, dl, e, .semibold, hx2, bar_y + 20, ink, 13, t);
            _ = try str(gpa, dl, e, .semibold, chx + w2 - 22, bar_y + 20, faint, 13, "\xC3\x97");
            try emitRegion(gpa, regions, chx + w2 - 30, bar_y, 30, @intCast(chip_h), @intCast(ti), .compose_tag_remove);
            chx += w2 + 8;
        }
        // Inline mirrors (already in the prose) — dim, not removable here.
        inline_loop: for (tag_bar.inline_tags) |t| {
            if (std.ascii.eqlIgnoreCase(t, tag_bar.locked)) continue;
            for (tag_bar.manual) |mt| if (std.ascii.eqlIgnoreCase(mt, t)) continue :inline_loop;
            const w2: i32 = @intCast(text.measure(e, .semibold, t, 13) + 34);
            if (chx + w2 > right_stop) break;
            try rect(gpa, dl, chx, bar_y, w2, chip_h, 0x1AEDEAE0, 15);
            const hx2 = try str(gpa, dl, e, .semibold, chx + 12, bar_y + 20, muted, 13, "#");
            _ = try str(gpa, dl, e, .semibold, hx2, bar_y + 20, muted, 13, t);
            chx += w2 + 8;
        }
        // The "+ tag" doorway / the live tag input.
        if (tag_bar.input_focus) {
            const iw: i32 = 130;
            if (chx + iw <= right_stop) {
                try rect(gpa, dl, chx, bar_y, iw, chip_h, 0x33000000, 15);
                try rect(gpa, dl, chx, bar_y + chip_h - 2, iw, 2, accent, 1);
                const hx2 = try str(gpa, dl, e, .semibold, chx + 12, bar_y + 20, muted, 13, "#");
                const tend = try str(gpa, dl, e, .semibold, hx2, bar_y + 20, ink, 13, tag_bar.input);
                if (tag_bar.caret_on) try rect(gpa, dl, tend + 1, bar_y + 7, 2, 16, accent, 1);
                try emitRegion(gpa, regions, chx, bar_y, iw, @intCast(chip_h), 0, .compose_tag_add);
            }
        } else if (chx + 70 <= right_stop) {
            try rect(gpa, dl, chx, bar_y, 66, chip_h, 0x22000000, 15);
            _ = try str(gpa, dl, e, .semibold, chx + 12, bar_y + 20, faint, 13, "+ tag");
            try emitRegion(gpa, regions, chx, bar_y, 66, @intCast(chip_h), 0, .compose_tag_add);
        }
    }
    // Cancel
    const cancel_w: i32 = @intCast(text.measure(e, .semibold, "Cancel", 14) + 28);
    try rect(gpa, dl, lx, fy, cancel_w, 34, 0x33000000, 14);
    _ = try str(gpa, dl, e, .semibold, lx + 14, fy + 22, muted, 14, "Cancel");
    try emitRegion(gpa, regions, lx, fy, cancel_w, 34, 0, .compose_cancel);
    // Send pill (accent, dark label).
    const sw: i32 = @intCast(text.measure(e, .semibold, send_label, 14) + 40);
    const sx = cx0 + cw - pad - sw;
    try rect(gpa, dl, sx, fy, sw, 34, accent, 16);
    _ = try str(gpa, dl, e, .semibold, sx + 20, fy + 22, bg, 14, send_label);
    try emitRegion(gpa, regions, sx, fy, sw, 34, 0, .compose_send);
    // "+ Add" — finalize the active draft as a thread segment (posts only). A
    // subtle outlined pill left of Send, so Send stays the primary action; the
    // handler no-ops on an empty box, so it can always show as an affordance.
    if (ctx == .post) {
        const add_label = "+ Add";
        const add_w: i32 = @intCast(text.measure(e, .semibold, add_label, 14) + 32);
        const add_x = sx - add_w - 12;
        try rect(gpa, dl, add_x, fy, add_w, 34, 0x33000000, 14);
        _ = try str(gpa, dl, e, .semibold, add_x + 16, fy + 22, muted, 14, add_label);
        try emitRegion(gpa, regions, add_x, fy, add_w, 34, 0, .compose_add);
    }
    // Char count (posts/replies only) between the two buttons.
    if (ctx != .profile) {
        var cb: [16]u8 = undefined;
        const n = std.unicode.utf8CountCodepoints(draft) catch draft.len;
        const cc = std.fmt.bufPrint(&cb, "{d}/300", .{n}) catch "";
        const over = n > 300;
        _ = try str(gpa, dl, e, .regular, lx + cancel_w + 16, fy + 22, if (over) like_c else faint, 13, cc);
    }
    // Status / hint, just above the footer.
    if (status.len > 0) {
        _ = try str(gpa, dl, e, .regular, lx, fy - 14, muted, 13, status);
    } else {
        _ = try str(gpa, dl, e, .regular, lx, fy - 14, faint, 13, "Ctrl+D to send · Esc to cancel");
    }
}

/// THE LOADOUT PAGE (screen_loadout / the rail's "Algorithms"). Renders the
/// three per-surface sockets — Feed, Replies, Zones — stacked and OPEN for
/// editing, over the same glass column + rail + sidebar chrome. Each socket
/// is the SAME portable widget; only the tray/ui/hits differ per surface
/// (invariant 12). A separate entry point (like layoutCompose) so `layout`'s
/// signature stays lean. Each surface's tap targets go to its own hit list.
/// Loadout-page sub-tabs (the row under the title). Loadout is built; the
/// other two are placeholders for later tracks.
pub const loadout_tabs = [_][]const u8{ "Loadout", "Marketplace", "Create", "Published" };

/// One marketplace browse card, as the Marketplace tab needs it — the shell fills
/// it from the AppView's `AlgorithmView` rows (D3: the wire type stays in the
/// shell; the pure renderer sees only these plain values). `learns` /
/// `uses_behavioral` are the AppView's config-DERIVED privacy verdict (invariant
/// 6), so the card's label is proven, never the author's claim.
/// A7.2: cold — a short browse list, never a hot per-frame loop over quantity.
pub const MarketAlgoCard = struct {
    name: []const u8,
    author: []const u8, // "@handle" or the DID when the handle is unresolved
    ranks: []const u8 = "", // the author's one-liner (schema rev)
    designed: u8 = 0, // declared-surface bitmask (1 feed / 2 replies / 4 zones)
    learns: bool,
    uses_behavioral: bool,
    state_budget_bytes: u32,
};

/// A category's screen heading.
fn transpCategory(c: transp.Category) []const u8 {
    return switch (c) {
        .engagement => "ENGAGEMENT",
        .freshness => "FRESHNESS",
        .personalization => "PERSONALIZATION",
        .diversity => "DIVERSITY",
        .retrieval => "WHAT IT PULLS IN",
        .privacy_state => "ON-DEVICE MEMORY",
    };
}

/// One classification line: a colored dot (the privacy glyph vocabulary) + label.
fn transpClassLine(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, x: i32, y: i32, label: []const u8, dot: u32) !i32 {
    try rect(gpa, dl, x, y + 3, 9, 9, dot, 4);
    _ = try str(gpa, dl, e, .semibold, x + 18, y + 14, ink, 16, label);
    return y + 30;
}

/// Render an algorithm's TRANSPARENCY page (DISCOVER invariant 5): the title +
/// its CID/ref, the two system-proven classification lines, then EVERY field —
/// label, exact value, and plain meaning — grouped by category, with a marker on
/// the fields that read your attention. Pure draw over `page` (built by
/// `transparency.buildPage`); returns the content height for scroll clamping.
/// No in-page hit regions in this cut — `back` (the nav) returns to the feed.
pub fn layoutTransparency(
    gpa: Allocator,
    e: *const text.Engine,
    width: i32,
    height: i32,
    dl: *raster.DrawList,
    regions: ?*Regions,
    accent: u32,
    scroll: i32,
    page: transp.Page,
) error{OutOfMemory}!i32 {
    _ = height;
    const m = metricsPage(width, screen_transparency);
    const lx = m.lx;
    const cw = m.cw;
    if (regions) |rg| rg.clearRetainingCapacity();
    var y = 80 + scroll;

    // A back affordance (the page draws no nav rail): "‹ Back" returns to wherever
    // the page was entered from (the shell resolves the return screen).
    {
        const back_w: i32 = 78;
        try rect(gpa, dl, lx, y - 34, back_w, 30, 0x14EDEAE0, 9);
        _ = try str(gpa, dl, e, .semibold, lx + 16, y - 13, ink, 14, "‹ Back");
        try emitRegion(gpa, regions, lx, y - 34, back_w, 30, 0, .back);
    }

    // Header: the algorithm's name + the ref it is proven to be (invariant 5).
    _ = try str(gpa, dl, e, .semibold, lx, y + 36, ink, 38, page.name);
    y += 56;
    _ = try str(gpa, dl, e, .regular, lx, y + 16, faint, 16, page.ref);
    y += 34;
    // A tap-through to the EXACT serialized source — the byte-for-byte artifact the
    // CID above commits to (what actually runs), not this hand-written summary. The
    // summary explains; the source proves. Placed at the top so "show me exactly
    // what runs" is one tap from the title.
    {
        const link = "⟨⟩  View the exact source";
        const lw: i32 = @intCast(text.measure(e, .semibold, link, 15));
        _ = try str(gpa, dl, e, .semibold, lx, y + 16, accent, 15, link);
        try emitRegion(gpa, regions, lx - 6, y - 2, lw + 16, 30, 0, .algo_source);
    }
    y += 40;

    // The system-PROVEN classification — green dot for the privacy win, accent
    // for "uses attention" / "learns".
    y = try transpClassLine(gpa, dl, e, lx, y, page.behavioral_label, if (page.uses_behavioral) accent else boost_c);
    y = try transpClassLine(gpa, dl, e, lx, y, page.stateful_label, if (page.learns) accent else muted);
    y += 16;

    try rect(gpa, dl, lx, y, cw, 1, 0x22FFFFFF, 0); // divider
    y += 30;

    // Every field, grouped by category — the "exactly what every line is" body.
    var cur_cat: ?transp.Category = null;
    for (page.rows) |r| {
        if (cur_cat == null or cur_cat.? != r.category) {
            cur_cat = r.category;
            _ = try str(gpa, dl, e, .semibold, lx, y + 13, muted, 13, transpCategory(r.category));
            y += 30;
        }
        // A field that reads your attention gets the accent marker (the privacy
        // story, per-line); candidate-side fields have no marker.
        if (r.behavioral) try rect(gpa, dl, lx, y + 5, 7, 7, accent, 3);
        const row_x = lx + 18;
        const pen = try str(gpa, dl, e, .semibold, row_x, y + 17, ink, 18, r.label);
        const after_val = try str(gpa, dl, e, .semibold, pen + 14, y + 17, accent, 18, r.value);
        // A declared-but-not-yet-enforced knob is tagged so it never reads as a
        // live guarantee (the honesty rule — modeled is not the same as active).
        if (!r.enforced) _ = try str(gpa, dl, e, .semibold, after_val + 12, y + 17, faint, 13, "· not yet active");
        y += 26;
        y = try wrapBody(gpa, dl, e, row_x, y + 15, cw - 18, body_c, 15, r.meaning, 21, true, null);
        y += 18;
    }

    // The creator's authored RETRIEVAL query — WHERE candidates are pulled from,
    // the pool-shaping half of the algorithm (Phase 0). Public-data sourcing only
    // (the author never touches the network), so no behavioral marker.
    if (page.source_lines.len > 0) {
        y += 12;
        try rect(gpa, dl, lx, y, cw, 1, 0x22FFFFFF, 0); // divider
        y += 30;
        _ = try str(gpa, dl, e, .semibold, lx, y + 13, muted, 13, "PULLS FROM");
        y += 30;
        for (page.source_lines) |sl| {
            try rect(gpa, dl, lx, y + 6, 7, 7, accent, 3);
            y = try wrapBody(gpa, dl, e, lx + 18, y + 17, cw - 18, ink, 16, sl.text, 22, true, null);
            y += 20;
        }
    }

    // The creator's authored Level-2 logic, in the order the scorer runs it —
    // readable as plain "if … then …" sentences. No row carries a behavioral
    // marker: a rule structurally cannot read your attention (the predicate
    // vocabulary is public-facts-only), so the logic can never widen the privacy
    // surface beyond what the field rows above already disclose.
    if (page.rule_lines.len > 0) {
        y += 12;
        try rect(gpa, dl, lx, y, cw, 1, 0x22FFFFFF, 0); // divider
        y += 30;
        _ = try str(gpa, dl, e, .semibold, lx, y + 13, muted, 13, "AUTHORED RULES");
        y += 30;
        for (page.rule_lines) |rl| {
            // A small leading dot: rose for a removal, green for a reweight, so the
            // shape of the logic reads at a glance.
            try rect(gpa, dl, lx, y + 6, 7, 7, if (rl.excludes) like_c else boost_c, 3);
            y = try wrapBody(gpa, dl, e, lx + 18, y + 17, cw - 18, ink, 16, rl.text, 22, true, null);
            y += 20;
        }
    }

    // The creator's authored Level-3 scoring formula, decompiled to one readable
    // expression — exactly the computation the VM runs per post (no behavioral
    // marker, for the same reason: the formula reads only public signals).
    if (page.formula) |formula| {
        y += 12;
        try rect(gpa, dl, lx, y, cw, 1, 0x22FFFFFF, 0); // divider
        y += 30;
        _ = try str(gpa, dl, e, .semibold, lx, y + 13, muted, 13, "SCORING FORMULA");
        y += 26;
        y = try wrapBody(gpa, dl, e, lx, y + 14, cw, faint, 13, "The score each post is ranked by, computed from public signals only.", 19, true, null);
        y += 10;
        _ = try str(gpa, dl, e, .semibold, lx, y + 15, muted, 14, "score =");
        y += 24;
        y = try wrapBody(gpa, dl, e, lx, y + 17, cw, ink, 18, formula, 25, true, null);
        y += 8;
    }

    y += 48;
    return y - scroll;
}

/// The EXACT SOURCE view — the "show me the code" counterpart to the summary. It
/// renders the byte-for-byte serialized algorithm (`core/algorithm.serialize`,
/// passed in as `source`): the exact configuration/logic the engine runs and the
/// `ref` (CID) commits to, verbatim, with no interpretation. Reached from the
/// summary's "View the exact source" link; its Back returns to the summary. Pure
/// draw; returns content height. Only source lines intersecting the viewport are
/// painted (i16 coord safety on a long program).
pub fn layoutAlgorithmSource(
    gpa: Allocator,
    e: *const text.Engine,
    width: i32,
    height: i32,
    dl: *raster.DrawList,
    regions: ?*Regions,
    accent: u32,
    scroll: i32,
    name: []const u8,
    ref: []const u8,
    source: []const u8,
) error{OutOfMemory}!i32 {
    const m = metricsPage(width, screen_transparency);
    const lx = m.lx;
    const cw = m.cw;
    if (regions) |rg| rg.clearRetainingCapacity();
    var y = 80 + scroll;

    // Back → the summary (not the marketplace; the shell resolves that).
    {
        const back_w: i32 = 78;
        try rect(gpa, dl, lx, y - 34, back_w, 30, 0x14EDEAE0, 9);
        _ = try str(gpa, dl, e, .semibold, lx + 16, y - 13, ink, 14, "‹ Back");
        try emitRegion(gpa, regions, lx, y - 34, back_w, 30, 0, .back);
    }

    _ = try str(gpa, dl, e, .semibold, lx, y + 32, ink, 32, name);
    y += 48;
    _ = try str(gpa, dl, e, .regular, lx, y + 14, faint, 15, ref);
    y += 28;
    y = try wrapBody(gpa, dl, e, lx, y + 14, cw, muted, 13, "The exact configuration the engine runs — byte-for-byte what the reference above commits to. No interpretation, just the source.", 19, true, null);
    y += 20;

    // The serialized source in a panel, line by line. ASCII JSON — the
    // proportional font reads it fine (a monospace face is a later nicety).
    const pad: i32 = 18;
    const line_h: i32 = 22;
    var lines: usize = 1;
    for (source) |c| {
        if (c == '\n') lines += 1;
    }
    const panel_top = y;
    const panel_h: i32 = @as(i32, @intCast(lines)) * line_h + pad * 2;
    try rect(gpa, dl, lx, panel_top, cw, panel_h, skinPanel(accent), 12);
    var ty = panel_top + pad + 14;
    var it = std.mem.splitScalar(u8, source, '\n');
    while (it.next()) |ln| {
        if (ty > scroll_guard_min and ty < height + 40) // paint only visible lines (i16 safety)
            _ = try str(gpa, dl, e, .regular, lx + pad, ty, body_c, 14, ln);
        ty += line_h;
    }
    return (panel_top + panel_h + 48) - scroll;
}

/// Lines above this y are off the top of the window — never paint them (their
/// i16 draw coords could otherwise wrap on a long source). A small negative slack.
const scroll_guard_min: i32 = -64;

/// The transparency page's LOADING state — shown while the config fetch runs on a
/// worker thread, so the page opens instantly instead of freezing the UI on the
/// network round-trip. Just the Back affordance + the algorithm's name + a quiet
/// "Loading…" line. Pure; emits the `.back` region so a mistap can escape.
pub fn layoutAlgorithmLoading(
    gpa: Allocator,
    e: *const text.Engine,
    width: i32,
    dl: *raster.DrawList,
    regions: ?*Regions,
    accent: u32,
    name: []const u8,
    /// True when the fetch already FAILED: draw an honest error line instead of
    /// "Loading...". Before this, the failed state drew NOTHING — a black page
    /// with no way back (the on-device transparency bug, 2026-07-09).
    failed: bool,
) error{OutOfMemory}!i32 {
    _ = accent;
    const m = metricsPage(width, screen_transparency);
    const lx = m.lx;
    if (regions) |rg| rg.clearRetainingCapacity();
    const y: i32 = 80;
    const back_w: i32 = 78;
    try rect(gpa, dl, lx, y - 34, back_w, 30, 0x14EDEAE0, 9);
    _ = try str(gpa, dl, e, .semibold, lx + 16, y - 13, ink, 14, "‹ Back");
    try emitRegion(gpa, regions, lx, y - 34, back_w, 30, 0, .back);
    _ = try str(gpa, dl, e, .semibold, lx, y + 36, ink, 38, name);
    if (failed) {
        _ = try str(gpa, dl, e, .regular, lx, y + 78, muted, 16, "Couldn't load this algorithm.");
        _ = try str(gpa, dl, e, .regular, lx, y + 104, faint, 14, "Check your connection, go back, and tap it again.");
    } else {
        _ = try str(gpa, dl, e, .regular, lx, y + 78, muted, 16, "Loading...");
    }
    return 0;
}

pub fn layoutLoadout(
    gpa: Allocator,
    e: *const text.Engine,
    width: i32,
    height: i32,
    dl: *raster.DrawList,
    regions: ?*Regions,
    accent: u32,
    scroll: i32, // pixel scroll (≤ 0); the socket stack rides under the sticky header
    tab: u8, // 0 = Loadout, 1 = Marketplace, 2 = Create
    /// Out: each surface socket's on-page geometry (feed/reply/zone), so the
    /// shell can run the drag math (dropIndex / reflow) at the right position.
    /// Zeroed for surfaces not drawn (non-Loadout tab).
    out_geoms: ?*[3]lens_socket.Geometry,
    feed_tray: lens_socket.TrayView,
    feed_ui: lens_socket.SocketUi,
    feed_hits: *lens_socket.HitList,
    reply_tray: lens_socket.TrayView,
    reply_ui: lens_socket.SocketUi,
    reply_hits: *lens_socket.HitList,
    zone_tray: lens_socket.TrayView,
    zone_ui: lens_socket.SocketUi,
    zone_hits: *lens_socket.HitList,
    /// GPU path: skip the rail's software line-art nav icons — the SDF-icon pass
    /// strikes them crisp (the same as `layout`'s `skip_heart`). Software: false,
    /// so the rail draws its own line-art. (Was hardcoded false, which forced the
    /// worse line-art on the Algorithms page even on the GPU.)
    skip_nav: bool,
    /// When true, the shell renders the nav rail as its own tile (decomposition),
    /// so layoutLoadout does NOT draw it here. Software path: false.
    rail_external: bool,
    /// Optional partition geometry (the shell expands the loadout content into
    /// the freed space when the left rail condenses). Null ⇒ self-computed.
    pane_geom: ?PaneGeom,
    /// The Marketplace tab's browse list (the AppView's published algorithms,
    /// already mapped from the wire). Empty ⇒ the "nothing published yet" state.
    /// Only read on tab 1; ignored on the others.
    market: []const MarketAlgoCard,
    /// The marketplace search draft + whether the box owns the keyboard.
    market_q: []const u8,
    market_q_focus: bool,
    /// A marketplace fetch is in flight (the empty state says "loading", not
    /// "nothing published" — the first fetch rides a cold connection).
    market_loading: bool,
    /// The designed-for heads-up modal (a mismatched drop) — null = closed.
    bench_pick: ?BenchPickView,
    /// A live bench drag (a shelf card riding the pointer) — null = none.
    bench_drag: ?BenchDragView,
    /// The Published tab's rows (the creator dashboard) — read on tab 3 only.
    published: []const PublishedRow,
    /// The simple-Create flow's state — read only on tab 2 (Create).
    create: CreateView,
    /// The developer submission flow's state — when `dev.active`, tab 2 hosts
    /// it instead of the guided builder (the landing's second button).
    dev: DevView,
    /// The user's BENCH — library algorithms (created/downloaded) not plugged into a
    /// socket. Rendered as a right-hand shelf on the Loadout tab; drag one into a
    /// socket to load it. Empty ⇒ the empty-state prompt.
    bench: lens_socket.TrayView,
    /// Safe-area insets (logical px). On phone the header + scroll body shift down
    /// by `top` so the "Algorithms" title clears the status bar; desktop passes
    /// zero. (The bottom clearance is added uniformly by the shell — see the funnel.)
    insets: EdgeInsets,
    /// Out: the PHONE library band's top edge in screen px (maxInt when the wide
    /// right-hand shelf is used instead) — the shell's touch drop test reads it:
    /// a card dragged out of a socket and released over the library unequips.
    out_lib_y: ?*i32,
) error{OutOfMemory}!i32 {
    if (out_lib_y) |p| p.* = std.math.maxInt(i32);
    // Algorithms is a WIDE page like the others: the glass spans the full
    // rectangle and the content centres in it — NO floating main-feed sidebar.
    const m: Metrics = if (pane_geom) |g|
        .{ .rail_x = g.rail_x, .col_x = g.col_x, .col_w = g.col_w, .lx = g.lx, .cw = g.cw, .side_x = g.side_x, .wide = g.wide }
    else
        metricsPage(width, screen_loadout);
    if (regions) |rg| rg.clearRetainingCapacity();
    // Sockets are only built (and so only hit-testable) on the Loadout tab.
    feed_hits.clearRetainingCapacity();
    reply_hits.clearRetainingCapacity();
    zone_hits.clearRetainingCapacity();
    if (out_geoms) |g| g.* = .{ .{ .x = 0, .y = 0, .w = 0 }, .{ .x = 0, .y = 0, .w = 0 }, .{ .x = 0, .y = 0, .w = 0 } };

    // Glass column over the field + the rail. Content centres in the wide glass.
    try rect(gpa, dl, m.col_x, 0, m.col_w, height, skinVeil(accent), 0);
    if (m.wide) {
        try rect(gpa, dl, m.col_x, 0, 1, height, 0x24EDEAE0, 0);
        try rect(gpa, dl, m.col_x + m.col_w - 1, 0, 1, height, 0x24EDEAE0, 0);
        if (!rail_external) try drawRail(gpa, dl, e, m.rail_x, height, screen_loadout, regions, accent, skip_nav, 1.0);
        try drawAgpl(gpa, dl, e, m.lx, height - 40);
    }

    // The sticky header grows by the top safe-area inset so the title + tabs sit
    // BELOW the status bar on phone (the same early-page inset fix the other
    // own-body screens got); desktop insets are zero, so nothing moves there.
    const top = insets.top;
    const header_h: i32 = 130 + top;
    const content_top: i32 = header_h + 10;
    var content_h: i32 = content_top;

    // The active sub-view, drawn FIRST + scrolled so it passes under the sticky
    // header (drawn last). Only the Loadout tab scrolls / has sockets.
    if (tab == 0) {
        const Surface = struct { label: []const u8, tray: lens_socket.TrayView, ui: lens_socket.SocketUi, hits: *lens_socket.HitList };
        const surfaces = [_]Surface{
            .{ .label = "FEED", .tray = feed_tray, .ui = feed_ui, .hits = feed_hits },
            .{ .label = "REPLIES", .tray = reply_tray, .ui = reply_ui, .hits = reply_hits },
            .{ .label = "ZONES", .tray = zone_tray, .ui = zone_ui, .hits = zone_hits },
        };
        var y: i32 = content_top + scroll;
        for (surfaces, 0..) |s, i| {
            _ = try str(gpa, dl, e, .semibold, m.lx, y + 4, faint, 12, s.label);
            y += 18;
            var ui = s.ui;
            ui.open = true; // always open on this page
            ui.open_t = 1.0; // fully revealed (no spring-open on the page)
            const geom: lens_socket.Geometry = .{ .x = m.lx, .y = y, .w = m.cw, .scale = 1.0 };
            if (out_geoms) |g| g[i] = geom;
            const sh = try lens_socket.build(gpa, e, s.tray, ui, geom, dl, s.hits);
            y += sh + 28;
        }
        content_h = (y - scroll) + 20; // total (unscrolled) height for scroll clamping

        // THE LIBRARY — algorithms you've created or downloaded that aren't socketed.
        // Drag one into a socket to load it. On the WIDE page it's a FIXED right-hand
        // shelf in the freed space beside the column (it doesn't scroll). On PHONE
        // there is no room beside the narrow column, so it FLOWS in the scroll body
        // BELOW the three sockets as a full-width list — otherwise the library is
        // off-screen and unreachable (the owner's "can't see my loadout").
        if (m.wide) {
            const shelf_x = m.lx + m.cw + 40;
            const shelf_w = m.side_x - shelf_x - 20;
            if (shelf_w >= 220) {
                var sy: i32 = content_top;
                _ = try str(gpa, dl, e, .semibold, shelf_x, sy + 12, muted, 12, "YOUR LIBRARY");
                sy += 30;
                if (bench.cards.len == 0) {
                    _ = try wrapBody(gpa, dl, e, shelf_x, sy + 12, shelf_w, faint, 13, "Algorithms you create or download park here. Drag one into a socket to use it.", 19, true, null);
                } else {
                    for (bench.cards, 0..) |card, bi| {
                        const ch: i32 = 72;
                        const card_acc = lens_socket.palette[@min(card.color, lens_socket.palette.len - 1)];
                        try rect(gpa, dl, shelf_x, sy, shelf_w, ch, skinPanel(accent), 12);
                        try rect(gpa, dl, shelf_x, sy, 4, ch, card_acc, 2); // accent spine
                        const dot: u32 = if (card.flags.behavioral) accent else boost_c;
                        try rect(gpa, dl, shelf_x + 18, sy + 20, 8, 8, dot, 4);
                        _ = try str(gpa, dl, e, .semibold, shelf_x + 34, sy + 28, ink, 15, bench.text[card.name.off..][0..card.name.len]);
                        _ = try str(gpa, dl, e, .regular, shelf_x + 18, sy + 52, muted, 12, bench.text[card.ranks.off..][0..card.ranks.len]);
                        _ = try str(gpa, dl, e, .semibold, shelf_x + shelf_w - 26, sy + 44, faint, 15, "\u{22EE}"); // ⋮ (drag lands later; tap = the socket chooser)
                        try emitRegion(gpa, regions, shelf_x, sy, shelf_w, @intCast(ch), @intCast(bi), .bench_seat);
                        sy += ch + 12;
                    }
                }
            }
        } else {
            // Phone: the library flows in-body, full width, beneath the sockets.
            var ly = y + 6;
            if (out_lib_y) |p| p.* = ly; // the unequip drop band starts here
            _ = try str(gpa, dl, e, .semibold, m.lx, ly + 14, muted, 13, "YOUR LIBRARY");
            ly += 34;
            if (bench.cards.len == 0) {
                ly = try wrapBody(gpa, dl, e, m.lx, ly + 12, m.cw, faint, 14, "Algorithms you create or download park here. Press and hold one to drag it into a socket.", 21, true, null);
                ly += 20;
            } else {
                for (bench.cards, 0..) |card, bi| {
                    const ch: i32 = 78;
                    const card_acc = lens_socket.palette[@min(card.color, lens_socket.palette.len - 1)];
                    try rect(gpa, dl, m.lx, ly, m.cw, ch, skinPanel(accent), 13);
                    try rect(gpa, dl, m.lx, ly, 4, ch, card_acc, 2); // accent spine
                    const dot: u32 = if (card.flags.behavioral) accent else boost_c;
                    try rect(gpa, dl, m.lx + 20, ly + 24, 9, 9, dot, 4);
                    _ = try str(gpa, dl, e, .semibold, m.lx + 40, ly + 32, ink, 16, bench.text[card.name.off..][0..card.name.len]);
                    _ = try str(gpa, dl, e, .regular, m.lx + 20, ly + 58, muted, 13, bench.text[card.ranks.off..][0..card.ranks.len]);
                    _ = try str(gpa, dl, e, .semibold, m.lx + m.cw - 28, ly + 48, faint, 17, "\u{22EE}"); // ⋮ — press-hold to drag
                    try emitRegion(gpa, regions, m.lx, ly, m.cw, @intCast(ch), @intCast(bi), .bench_seat);
                    ly += ch + 12;
                }
            }
            content_h = (ly - scroll) + 20;
        }
    } else if (tab == 1) {
        content_h = try drawMarketplace(gpa, dl, e, m, height, scroll, regions, accent, content_top, market, market_q, market_q_focus, market_loading);
    } else if (tab == 3) {
        content_h = try drawPublished(gpa, dl, e, m, height, scroll, regions, accent, content_top, published);
    } else if (dev.active) {
        content_h = try layoutDevSubmit(gpa, e, dl, m, height, scroll, regions, accent, dev);
    } else {
        content_h = try layoutCreate(gpa, e, dl, m, height, scroll, regions, accent, content_top, create);
    }

    // Sticky header: frosted box, title, the tab row, divider — drawn LAST. The
    // veil spans the full header_h (which already includes the top inset), so it
    // paints under the status bar; the title + tabs ride the inset down.
    try rect(gpa, dl, m.col_x, 0, m.col_w, header_h, skinHeaderVeil(accent), 0);
    _ = try str(gpa, dl, e, .semibold, m.lx, 50 + top, ink, 27, "Algorithms");
    var tx = m.lx;
    const tab_baseline: i32 = 96 + top;
    for (loadout_tabs, 0..) |label, i| {
        const on = i == tab;
        const tw: i32 = @intCast(text.measure(e, .semibold, label, 15));
        _ = try str(gpa, dl, e, .semibold, tx, tab_baseline, if (on) ink else muted, 15, label);
        if (on) try rect(gpa, dl, tx, tab_baseline + 9, tw, 3, accent, 2);
        try emitRegion(gpa, regions, tx - 8, tab_baseline - 19, tw + 16, 32, @intCast(i), .loadout_tab);
        tx += tw + 28;
    }
    try rect(gpa, dl, m.col_x, header_h - 1, m.col_w, 1, divider, 0);
    if (bench_pick) |bp| {
        // The designed-for HEADS-UP, topmost — the one modal left on this
        // page (the socket chooser became direct drag). The dimmed backdrop
        // is itself the cancel target; the buttons emitted after win their
        // overlaps (hitTest is last-in).
        const target = bp.warn orelse 0;
        try rect(gpa, dl, m.col_x, 0, m.col_w, height, 0x99101010, 0);
        try emitRegion(gpa, regions, m.col_x, 0, m.col_w, @intCast(@min(height, 32767)), 0, .bench_cancel);
        const pw: i32 = @min(460, m.cw - 24);
        const px = m.col_x + @divTrunc(m.col_w - pw, 2);
        const py: i32 = 170 + top;
        const ph: i32 = 240;
        try rect(gpa, dl, px, py, pw, ph, 0xFF23221A, 16);
        try rect(gpa, dl, px, py, pw, 4, accent, 2);
        _ = try str(gpa, dl, e, .semibold, px + 26, py + 44, ink, 20, "A heads-up");
        var wb: [192]u8 = undefined;
        var dl2: [64]u8 = undefined;
        var dw: usize = 0;
        for (dev_surfaces, 0..) |surf, si| {
            if (bp.designed & (@as(u8, 1) << @intCast(si)) == 0) continue;
            const sep: []const u8 = if (dw == 0) "" else " and ";
            @memcpy(dl2[dw..][0..sep.len], sep);
            dw += sep.len;
            @memcpy(dl2[dw..][0..surf.len], surf);
            dw += surf.len;
        }
        const wt = std.fmt.bufPrint(&wb, "{s} was designed for {s}. It runs anywhere — but its creator built it for that surface.", .{ bp.name, dl2[0..dw] }) catch "";
        const wy = try wrapBody(gpa, dl, e, px + 26, py + 76, pw - 52, muted, 15, wt, 21, true, null);
        var bb: [64]u8 = undefined;
        const bt = std.fmt.bufPrint(&bb, "Socket into {s} anyway", .{dev_surfaces[@min(target, dev_surfaces.len - 1)]}) catch "Socket it anyway";
        const by = wy + 22;
        const btw: i32 = @as(i32, @intCast(text.measure(e, .semibold, bt, 15))) + 48;
        try rect(gpa, dl, px + 26, by, btw, 44, accent, 11);
        _ = try str(gpa, dl, e, .semibold, px + 50, by + 28, 0xFF0B0B0F, 15, bt);
        try emitRegion(gpa, regions, px + 26, by, btw, 44, target, .bench_confirm);
        try rect(gpa, dl, px + 26 + btw + 12, by, 110, 44, 0x14EDEAE0, 11);
        _ = try str(gpa, dl, e, .semibold, px + 26 + btw + 40, by + 28, ink, 15, "Cancel");
        try emitRegion(gpa, regions, px + 26 + btw + 12, by, 110, 44, 0, .bench_cancel);
    }
    if (bench_drag) |bd| {
        // The bench drag GHOST: a mini card riding the pointer, topmost.
        // Drop on a socket to equip it; released anywhere else it fizzles.
        const gw: i32 = 210;
        const gx = bd.x - 40;
        const gy = bd.y - 20;
        try rect(gpa, dl, gx, gy, gw, 56, 0xF423221A, 12);
        try rect(gpa, dl, gx, gy, 4, 56, lens_socket.palette[@min(bd.color, lens_socket.palette.len - 1)], 2);
        _ = try str(gpa, dl, e, .semibold, gx + 16, gy + 33, ink, 15, bd.name);
    }
    return content_h;
}

/// The MARKETPLACE tab: browse published algorithms. Each card shows the name,
/// the author, the config-DERIVED privacy verdict (a coloured dot + label —
/// proven, never the author's claim, invariant 6), the declared on-device state
/// ceiling, and two affordances: "Details" (its transparency page) and "Add"
/// (drop it into the feed loadout). Emits `.algo_view` / `.algo_add` regions
/// carrying the card index. Empty list ⇒ a calm "nothing here yet" state. Only
/// cards intersecting the viewport are painted (i16 coord safety). PURE.
fn drawMarketplace(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, m: Metrics, height: i32, scroll: i32, regions: ?*Regions, accent: u32, y0: i32, market: []const MarketAlgoCard, query: []const u8, q_focus: bool, loading: bool) error{OutOfMemory}!i32 {
    // The sticky header's REAL bottom, passed in: it grows by the safe-area top
    // inset on phone, and the old hardcoded 140 left this tab's content starting
    // under the translucent veil — the "Your feed, your rules" ghost (2026-07-09).
    const content_top: i32 = y0;
    const x0 = m.lx;
    const w = m.cw;

    // The search box: name / author / one-liner / tags, filtered live by the
    // shell (the card list arriving here is already the filtered set).
    {
        const sh: i32 = 44;
        const sy = content_top + scroll;
        try rect(gpa, dl, x0, sy, w, sh, 0x12EDEAE0, 12);
        if (q_focus) try rect(gpa, dl, x0, sy, 3, sh, accent, 2);
        const shown = if (query.len > 0) query else "Search algorithms — name, creator, tags";
        const qc: u32 = if (query.len > 0) ink else faint;
        const pen = try str(gpa, dl, e, .regular, x0 + 16, sy + 28, qc, 15, shown);
        if (q_focus) try rect(gpa, dl, (if (query.len > 0) pen else x0 + 16) + 2, sy + 12, 2, 20, accent, 0);
        try emitRegion(gpa, regions, x0, sy, w, @intCast(sh), 0, .market_search);
        // The user explainer's front door, beside the search box.
        const lt: []const u8 = "How does this work?";
        const ltw: i32 = @intCast(text.measure(e, .regular, lt, 13));
        _ = try str(gpa, dl, e, .regular, x0 + w - ltw, sy + sh + 22, faint, 13, lt);
        try emitRegion(gpa, regions, x0 + w - ltw - 8, sy + sh + 4, ltw + 16, 28, 0, .docs_user);
    }
    const list_top = content_top + 92;

    if (market.len == 0) {
        const msg: []const u8 = if (loading and query.len == 0) "Loading the marketplace…" else if (query.len > 0) "Nothing matches that search" else "No algorithms published yet";
        const sub: []const u8 = if (loading and query.len == 0) "One moment — fetching the published algorithms." else if (query.len > 0) "Try fewer words — it matches names, creators, one-liners, and tags." else "Publish one and it shows up here to browse and adopt.";
        _ = try str(gpa, dl, e, .semibold, x0, list_top + scroll + 70, ink, 19, msg);
        _ = try str(gpa, dl, e, .regular, x0, list_top + scroll + 98, muted, 14, sub);
        return height; // nothing to scroll
    }

    var y: i32 = list_top + scroll;
    // Narrow (phone) cards grow a row: the privacy/meta line and the button
    // shared a band and collided at 430 (on-device finding) — the button
    // drops below the meta instead.
    const narrow = w < 520;
    const card_h: i32 = if (narrow) 162 else 128;
    const gap: i32 = 16;
    for (market, 0..) |a, i| {
        if (y + card_h > 0 and y < height) {
            try rect(gpa, dl, x0, y, w, card_h, skinPanel(accent), 16);
            try rect(gpa, dl, x0, y, w, 1, 0x14EDEAE0, 16); // lit top edge
            // The whole card opens the algorithm's PAGE (emitted first — the
            // View-details button below wins the overlap, hitTest is last-in).
            try emitRegion(gpa, regions, x0, y, w, @intCast(card_h), @intCast(i), .algo_open);

            _ = try str(gpa, dl, e, .semibold, x0 + 22, y + 34, ink, 20, a.name);
            var apen = try str(gpa, dl, e, .regular, x0 + 22, y + 58, muted, 14, a.author);
            if (a.ranks.len > 0) {
                apen = try str(gpa, dl, e, .regular, apen + 8, y + 58, faint, 13, "·");
                _ = try str(gpa, dl, e, .regular, apen + 8, y + 58, body_c, 13, a.ranks);
            }
            // Designed-for badges, top-right: the author's declaration of which
            // sockets this was built for (right-to-left so FEED lands leftmost).
            if (a.designed != 0) {
                var bx = x0 + w - 20;
                var si: usize = dev_surfaces.len;
                while (si > 0) {
                    si -= 1;
                    if (a.designed & (@as(u8, 1) << @intCast(si)) == 0) continue;
                    const btw: i32 = @intCast(text.measure(e, .semibold, dev_surfaces[si], 11));
                    bx -= btw + 18;
                    try rect(gpa, dl, bx, y + 22, btw + 14, 20, 0x14EDEAE0, 6);
                    _ = try str(gpa, dl, e, .semibold, bx + 7, y + 36, muted, 11, dev_surfaces[si]);
                    bx -= 6;
                }
            }

            // The proven privacy line: green when candidate-side (a privacy win),
            // accent when it reads or learns from your attention.
            const dot: u32 = if (a.uses_behavioral) accent else boost_c;
            const label: []const u8 = if (a.learns)
                "Learns on-device"
            else if (a.uses_behavioral)
                "Uses attention signals"
            else
                "No behavioral data";
            try rect(gpa, dl, x0 + 22, y + 78, 9, 9, dot, 4);
            const after = try str(gpa, dl, e, .semibold, x0 + 40, y + 89, body_c, 14, label);
            if (a.learns and a.state_budget_bytes > 0) {
                var buf: [48]u8 = undefined;
                const kib = (a.state_budget_bytes + 1023) / 1024;
                const s = std.fmt.bufPrint(&buf, "· up to {d} KB on device", .{kib}) catch "";
                _ = try str(gpa, dl, e, .regular, after + 12, y + 89, faint, 13, s);
            }

            // The primary affordance, right-aligned: open this algorithm's
            // transparency page (browse → inspect exactly what it does). "Add to
            // loadout" (adopt + score) is the next slice — it needs the fetched
            // config wired into the scoring resolver.
            const btn_h: i32 = 34;
            const btn_y = if (narrow) y + 108 else y + card_h - btn_h - 18;
            const view_w: i32 = 128;
            const view_x = x0 + w - view_w - 20;
            try rect(gpa, dl, view_x, btn_y, view_w, btn_h, 0x14EDEAE0, 10); // ghost
            _ = try str(gpa, dl, e, .semibold, view_x + 42, btn_y + 22, ink, 14, "Open");
            // ONE destination: the card and its button both open the
            // algorithm's page (two different pages confused the owner);
            // transparency lives inside that page.
            try emitRegion(gpa, regions, view_x, btn_y, view_w, btn_h, @intCast(i), .algo_open);
        }
        y += card_h + gap;
    }
    return (y - scroll) + 20;
}

/// The bench socket-chooser's render state: which shelf algorithm was tapped
/// (name + its declared surfaces) and, when set, the mismatch heads-up's
/// pending target. A7.2: cold — one per frame while the overlay is open.
/// One row of the creator DASHBOARD (the Published tab): a marketplace
/// submission of YOURS, with its live-on-the-marketplace status. The shell
/// builds these per frame from the library (visibility public) crossed with
/// the fetched marketplace catalog. A7.2: cold struct, size guard waived.
pub const PublishedRow = struct {
    name: []const u8 = "",
    ranks: []const u8 = "",
    designed: u8 = 0,
    live: bool = false, // present in the marketplace catalog (indexed + served)
    confirm: bool = false, // this row's Delete is armed (tap again to fire)
    lib_idx: u16 = 0, // the library record index — the action payload
};

/// The creator dashboard: your published algorithms, their marketplace
/// status, and the retraction. Download counts await an install-signal
/// design (installs are local-only today) — absent, never faked.
fn drawPublished(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, m: Metrics, height: i32, scroll: i32, regions: ?*Regions, accent: u32, y0: i32, rows: []const PublishedRow) error{OutOfMemory}!i32 {
    _ = height;
    const x0 = m.lx;
    const w = m.cw;
    var y: i32 = y0 + scroll;

    if (rows.len == 0) {
        _ = try str(gpa, dl, e, .semibold, x0, y + 70, ink, 19, "Nothing published yet");
        _ = try str(gpa, dl, e, .regular, x0, y + 98, muted, 14, "Write one under Create — everything you publish is managed from here.");
        return (y - scroll) + 160;
    }
    _ = try str(gpa, dl, e, .regular, x0, y + 16, muted, 14, "Everything you've published to the marketplace. Deleting retracts the record — installed copies on other devices keep working.");
    y += 44;
    for (rows) |row| {
        const ch: i32 = 108;
        try rect(gpa, dl, x0, y, w, ch, skinPanel(accent), 16);
        try rect(gpa, dl, x0, y, w, 1, 0x14EDEAE0, 16);
        _ = try str(gpa, dl, e, .semibold, x0 + 22, y + 34, ink, 19, row.name);
        if (row.ranks.len > 0) _ = try str(gpa, dl, e, .regular, x0 + 22, y + 58, muted, 14, row.ranks);
        // Live status: proven by presence in the fetched marketplace, not assumed.
        const dot: u32 = if (row.live) boost_c else faint;
        try rect(gpa, dl, x0 + 22, y + 76, 8, 8, dot, 4);
        _ = try str(gpa, dl, e, .regular, x0 + 38, y + 86, if (row.live) body_c else faint, 13, if (row.live) "Live on the marketplace" else "Syncing — not in the marketplace listing yet");
        // Designed-for badges, top-right of the card.
        var bx = x0 + w - 150;
        var si: usize = dev_surfaces.len;
        while (si > 0) {
            si -= 1;
            if (row.designed & (@as(u8, 1) << @intCast(si)) == 0) continue;
            const btw: i32 = @intCast(text.measure(e, .semibold, dev_surfaces[si], 11));
            bx -= btw + 18;
            try rect(gpa, dl, bx, y + 22, btw + 14, 20, 0x14EDEAE0, 6);
            _ = try str(gpa, dl, e, .semibold, bx + 7, y + 36, muted, 11, dev_surfaces[si]);
            bx -= 6;
        }
        // Delete: two-tap (armed reads differently and in the warning color).
        const bw: i32 = 128;
        const bx2 = x0 + w - bw - 20;
        const by2 = y + ch - 34 - 16;
        if (row.confirm) {
            try rect(gpa, dl, bx2, by2, bw, 34, like_c, 10);
            _ = try str(gpa, dl, e, .semibold, bx2 + 14, by2 + 22, 0xFF0B0B0F, 13, "Really delete?");
        } else {
            try rect(gpa, dl, bx2, by2, bw, 34, 0x14EDEAE0, 10);
            _ = try str(gpa, dl, e, .semibold, bx2 + 38, by2 + 22, if (row.live) ink else faint, 13, "Delete");
        }
        try emitRegion(gpa, regions, bx2, by2, bw, 34, row.lib_idx, .pub_delete);
        y += ch + 14;
    }
    return (y - scroll) + 40;
}

/// A dragged shelf card's ghost: what rides the pointer.
/// A7.2: cold struct, size guard waived — one per frame while a drag lives.
pub const BenchDragView = struct {
    name: []const u8 = "",
    color: u8 = 0,
    x: i32 = 0,
    y: i32 = 0,
};

/// The designed-for heads-up's render state (a mismatched drop's pending
/// target). A7.2: cold struct, size guard waived — one per frame while open.
pub const BenchPickView = struct {
    name: []const u8 = "",
    designed: u8 = 0,
    warn: ?u8 = null, // pending target surface awaiting the "anyway" confirm
};

/// Render a documentation page (screen_algo_docs): the user explainer or the
/// developer writing guide — one generic document renderer over `algo_docs`
/// data, the same plain-scrolling-document treatment as transparency. Pure.
pub fn layoutAlgoDocs(gpa: Allocator, e: *const text.Engine, width: i32, height: i32, dl: *raster.DrawList, regions: ?*Regions, accent: u32, scroll: i32, doc: algo_docs.Doc) error{OutOfMemory}!i32 {
    const m = metricsPage(width, screen_transparency);
    if (regions) |rg| rg.clearRetainingCapacity();
    try rect(gpa, dl, 0, 0, width, @intCast(std.math.clamp(height, 0, 32767)), bg, 0);
    const x0 = m.lx;
    const w = m.cw;
    var y: i32 = 96 + scroll;

    try rect(gpa, dl, x0, y, 96, 40, 0x12EDEAE0, 11);
    _ = try str(gpa, dl, e, .semibold, x0 + 22, y + 26, ink, 15, "‹ Back");
    try emitRegion(gpa, regions, x0, y, 96, 40, 0, .back);
    y += 72;
    _ = try str(gpa, dl, e, .semibold, x0, y + 32, ink, 30, doc.title);
    y += 48;
    y = try wrapBody(gpa, dl, e, x0, y + 18, w, muted, 16, doc.deck, 24, true, null);
    y += 26;
    for (doc.sections) |sec| {
        try rect(gpa, dl, x0, y + 6, 22, 3, accent, 1);
        _ = try str(gpa, dl, e, .semibold, x0, y + 40, ink, 19, sec.heading);
        y += 56;
        y = try wrapBody(gpa, dl, e, x0, y + 16, w, body_c, 15, sec.body, 23, true, null);
        y += 30;
    }
    return (y - scroll) + 40;
}

/// One marketplace algorithm as its FULL PAGE needs it (screen_algo_detail) —
/// the browse card's big sibling: the author's prose beside the proven label,
/// the declaration badges, the rating seat, and the working Install. The shell
/// fills it from the selected catalog row. A7.2: cold — one per frame. Waived.
pub const AlgoDetailView = struct {
    name: []const u8 = "",
    author: []const u8 = "",
    ranks: []const u8 = "",
    desc: []const u8 = "",
    tags: []const u8 = "",
    designed: u8 = 0,
    learns: bool = false,
    uses_behavioral: bool = false,
    state_budget_bytes: u32 = 0,
    installed: bool = false,
    rating_avg: f32 = 0,
    rating_count: u32 = 0,
    idx: u16 = 0, // filtered browse index — payload for install/transparency
};

/// The algorithm's public page: everything a user reads before trying it.
/// Pure draw over `view`; Back rides the global nav. Returns content height.
pub fn layoutAlgoDetail(gpa: Allocator, e: *const text.Engine, width: i32, height: i32, dl: *raster.DrawList, regions: ?*Regions, accent: u32, scroll: i32, view: AlgoDetailView) error{OutOfMemory}!i32 {
    // A plain scrolling DOCUMENT like the transparency page: same reading
    // column, regions cleared here, and an OPAQUE page ground first — without
    // it the living field bleeds through at full strength (owner-hit bug).
    const m = metricsPage(width, screen_transparency);
    if (regions) |rg| rg.clearRetainingCapacity();
    try rect(gpa, dl, 0, 0, width, @intCast(std.math.clamp(height, 0, 32767)), bg, 0);
    const x0 = m.lx;
    const w = m.cw;
    var y: i32 = 96 + scroll;

    // Back, then the masthead: name, creator, the declaration badges.
    try rect(gpa, dl, x0, y, 96, 40, 0x12EDEAE0, 11);
    _ = try str(gpa, dl, e, .semibold, x0 + 22, y + 26, ink, 15, "‹ Back");
    try emitRegion(gpa, regions, x0, y, 96, 40, 0, .back);
    y += 72;
    _ = try str(gpa, dl, e, .semibold, x0, y + 32, ink, 32, if (view.name.len > 0) view.name else "Algorithm");
    y += 46;
    var apen = try str(gpa, dl, e, .regular, x0, y + 18, muted, 16, view.author);
    if (view.designed != 0) {
        apen += 14;
        for (dev_surfaces, 0..) |surf, si| {
            if (view.designed & (@as(u8, 1) << @intCast(si)) == 0) continue;
            const btw: i32 = @intCast(text.measure(e, .semibold, surf, 12));
            try rect(gpa, dl, apen, y + 2, btw + 16, 22, 0x14EDEAE0, 7);
            _ = try str(gpa, dl, e, .semibold, apen + 8, y + 17, muted, 12, surf);
            apen += btw + 24;
        }
    }
    y += 34;
    // The rating seat: stars earn their ink only once real ratings exist.
    if (view.rating_count > 0) {
        var stars_buf: [24]u8 = undefined;
        var sw2: usize = 0;
        const filled: u32 = @intFromFloat(@round(view.rating_avg));
        for (0..5) |si| {
            const g: []const u8 = if (si < filled) "\u{2605}" else "\u{2606}";
            @memcpy(stars_buf[sw2..][0..g.len], g);
            sw2 += g.len;
        }
        var rb: [32]u8 = undefined;
        const rt = std.fmt.bufPrint(&rb, "{d} rating{s}", .{ view.rating_count, if (view.rating_count == 1) "" else "s" }) catch "";
        const spen = try str(gpa, dl, e, .semibold, x0, y + 16, accent, 16, stars_buf[0..sw2]);
        _ = try str(gpa, dl, e, .regular, spen + 12, y + 16, faint, 13, rt);
    } else {
        _ = try str(gpa, dl, e, .regular, x0, y + 16, faint, 13, "No ratings yet — be the first to try it.");
    }
    y += 42;
    if (view.ranks.len > 0) {
        _ = try str(gpa, dl, e, .semibold, x0, y + 18, body_c, 17, view.ranks);
        y += 34;
    }
    if (view.desc.len > 0) {
        y = try wrapBody(gpa, dl, e, x0, y + 18, w, muted, 16, view.desc, 24, true, null);
        y += 16;
    }
    if (view.tags.len > 0) {
        _ = try str(gpa, dl, e, .regular, x0, y + 14, faint, 14, view.tags);
        y += 28;
    }
    y += 12;

    // What the code proves — the derived line, never the author's claim.
    _ = try str(gpa, dl, e, .semibold, x0, y + 14, faint, 12, "WHAT THE CODE PROVES");
    y += 28;
    const dot: u32 = if (view.uses_behavioral) accent else boost_c;
    const label: []const u8 = if (view.learns)
        "Learns on-device — your attention never leaves this device"
    else if (view.uses_behavioral)
        "Uses attention signals — on your device only"
    else
        "No behavioral data — candidate-side only";
    try rect(gpa, dl, x0, y + 4, 9, 9, dot, 4);
    var ppen = try str(gpa, dl, e, .semibold, x0 + 18, y + 14, ink, 15, label);
    if (view.state_budget_bytes > 0) {
        var bb: [48]u8 = undefined;
        const kib = (view.state_budget_bytes + 1023) / 1024;
        const bt = std.fmt.bufPrint(&bb, "· up to {d} KB on device", .{kib}) catch "";
        _ = try str(gpa, dl, e, .regular, ppen + 12, y + 14, faint, 13, bt);
    }
    _ = &ppen;
    y += 34;
    _ = try str(gpa, dl, e, .regular, x0, y + 12, faint, 13, "Every fact above is derived from the compiled code by the engine.");
    y += 40;

    // The actions: Install (the primary), then the transparency deep-dive.
    const bh: i32 = 46;
    if (view.installed) {
        try rect(gpa, dl, x0, y, 220, bh, 0x14EDEAE0, 12);
        _ = try str(gpa, dl, e, .semibold, x0 + 24, y + 29, muted, 15, "In your library \u{2713}");
        try emitRegion(gpa, regions, x0, y, 220, @intCast(bh), view.idx, .algo_install);
    } else {
        try rect(gpa, dl, x0, y, 220, bh, accent, 12);
        _ = try str(gpa, dl, e, .semibold, x0 + 24, y + 29, 0xFF0B0B0F, 15, "Install to your library");
        try emitRegion(gpa, regions, x0, y, 220, @intCast(bh), view.idx, .algo_install);
    }
    const tx2 = x0 + 236;
    try rect(gpa, dl, tx2, y, 214, bh, 0x12EDEAE0, 12);
    _ = try str(gpa, dl, e, .semibold, tx2 + 22, y + 29, ink, 15, "\u{27E8}\u{27E9} Full transparency");
    try emitRegion(gpa, regions, tx2, y, 214, @intCast(bh), view.idx, .algo_view);
    y += bh + 40;
    return (y - scroll) + 40;
}

/// The state the Create flow renderer reads (the shell owns + drives it). Plain
/// values; the config carries the live recap numbers. A7.2: cold — one per frame on
/// the Create tab, never held in quantity. Waived.
pub const CreateView = struct {
    step: create_flow.Step,
    answers: builder.Answers,
    config: discover.FeedConfig,
    name: []const u8,
    color: u8, // chosen accent palette index (0..8)
    naming: bool = false, // the name field has focus (draw a caret)
    prepare_t: f32 = 0, // the .preparing beat's progress, 0..1 (the shell's timer)
};

/// Render the simple-Create flow's CURRENT step into the Create tab (PURE draw over
/// `view`; the shell owns the state + input). Emits a region for every tap target —
/// option pick, knob steppers, colour swatches, back / continue / create — so the
/// shell drives the flow entirely through `Action`s. Returns content height.
pub fn layoutCreate(gpa: Allocator, e: *const text.Engine, dl: *raster.DrawList, m: Metrics, height: i32, scroll: i32, regions: ?*Regions, accent: u32, y0: i32, view: CreateView) error{OutOfMemory}!i32 {
    _ = height;
    const x0 = m.lx;
    const w = m.cw;
    var y: i32 = y0 + scroll;

    switch (view.step) {
        .landing => {
            _ = try str(gpa, dl, e, .semibold, x0, y + 30, ink, 30, "Your feed, your rules");
            y += 52;
            y = try wrapBody(gpa, dl, e, x0, y + 18, w, muted, 16, "An algorithm decides which posts you see and in what order. On Zat4 it's yours to shape — everything runs on your device, and what it can and can't touch is provable, never a black box.", 24, true, null);
            y += 34;
            // Primary: the five-minute guided builder (→ the questions).
            const bh: i32 = 56;
            try rect(gpa, dl, x0, y, w, bh, accent, 14);
            _ = try str(gpa, dl, e, .semibold, x0 + 26, y + 30, 0xFF0B0B0F, 17, "Create your own in five minutes");
            _ = try str(gpa, dl, e, .regular, x0 + 26, y + 46, 0xCC0B0B0F, 13, "A few questions, then fine-tune — saved privately, just for you.");
            try emitRegion(gpa, regions, x0, y, @intCast(w), @intCast(bh), 0, .create_next);
            y += bh + 16;
            // Secondary: the developer submission path (a later slice; honest for now).
            try rect(gpa, dl, x0, y, w, bh, 0x12EDEAE0, 14);
            _ = try str(gpa, dl, e, .semibold, x0 + 26, y + 30, ink, 17, "Submit an algorithm you wrote");
            _ = try str(gpa, dl, e, .regular, x0 + 26, y + 46, muted, 13, "For developers — publish real code to the marketplace.");
            try emitRegion(gpa, regions, x0, y, @intCast(w), @intCast(bh), 0, .create_dev);
            y += bh + 24;
            // The two documents, as quiet text doors under the big buttons.
            const l1: []const u8 = "How algorithms work here";
            const l1w: i32 = @intCast(text.measure(e, .regular, l1, 14));
            _ = try str(gpa, dl, e, .regular, x0, y + 14, muted, 14, l1);
            try emitRegion(gpa, regions, x0 - 4, y, l1w + 12, 26, 0, .docs_user);
            const l2: []const u8 = "The writing guide, for developers";
            const l2w: i32 = @intCast(text.measure(e, .regular, l2, 14));
            _ = try str(gpa, dl, e, .regular, x0 + l1w + 34, y + 14, muted, 14, l2);
            try emitRegion(gpa, regions, x0 + l1w + 30, y, l2w + 12, 26, 0, .docs_dev);
            y += 34;
        },
        .preparing => {
            y += 120;
            _ = try str(gpa, dl, e, .semibold, x0, y + 30, ink, 26, "Preparing your custom algorithm");
            y += 52;
            _ = try str(gpa, dl, e, .regular, x0, y + 16, muted, 15, "Calibrating the numbers from your answers…");
            y += 44;
            // A determinate progress bar the shell fills over the beat, then advances.
            const bar_w = w - 40;
            try rect(gpa, dl, x0, y, bar_w, 6, 0x18EDEAE0, 3);
            const fill: i32 = @intFromFloat(@as(f32, @floatFromInt(bar_w)) * std.math.clamp(view.prepare_t, 0, 1));
            try rect(gpa, dl, x0, y, fill, 6, accent, 3);
            y += 40;
        },
        .pace, .reach, .conversation, .privacy => {
            const qi = @intFromEnum(view.step) - 1; // .pace is step 1 (landing is 0) → question 0
            const q = create_flow.questions[qi];
            var buf: [24]u8 = undefined;
            const step_lbl = std.fmt.bufPrint(&buf, "STEP {d} OF 4", .{qi + 1}) catch "";
            _ = try str(gpa, dl, e, .semibold, x0, y + 14, faint, 12, step_lbl);
            y += 34;
            _ = try str(gpa, dl, e, .semibold, x0, y + 30, ink, 30, q.title);
            y += 46;
            _ = try str(gpa, dl, e, .regular, x0, y + 16, muted, 15, q.prompt);
            y += 40;
            const sel = create_flow.answerIndex(view.answers, view.step);
            for (q.options, 0..) |opt, oi| {
                const oh: i32 = 76;
                const chosen = oi == sel;
                try rect(gpa, dl, x0, y, w, oh, if (chosen) skinPanel(accent) else 0x0EEDEAE0, 14);
                if (chosen) try rect(gpa, dl, x0, y, 4, oh, accent, 2); // accent spine
                _ = try str(gpa, dl, e, .semibold, x0 + 22, y + 30, ink, 18, opt.label);
                _ = try str(gpa, dl, e, .regular, x0 + 22, y + 54, muted, 14, opt.blurb);
                try emitRegion(gpa, regions, x0, y, @intCast(w), @intCast(oh), @intCast(oi), .create_pick);
                y += oh + 12;
            }
        },
        .recap => {
            _ = try str(gpa, dl, e, .semibold, x0, y + 30, ink, 30, "Fine-tune");
            y += 44;
            _ = try str(gpa, dl, e, .regular, x0, y + 16, muted, 15, "Adjust anything you like — this feed is just for you.");
            y += 44;
            for (std.enums.values(create_flow.Knob)) |k| {
                const meta = create_flow.knobMeta(k);
                const val = create_flow.knobValue(view.config, k);
                _ = try str(gpa, dl, e, .semibold, x0, y + 14, ink, 16, meta.label);
                // − and + steppers, then the value to the RIGHT of the +.
                const sb: i32 = 30;
                const minus_x = x0 + w - 118;
                const plus_x = minus_x + sb + 8;
                try rect(gpa, dl, minus_x, y - 6, sb, sb, 0x14EDEAE0, 8);
                _ = try str(gpa, dl, e, .semibold, minus_x + 11, y + 13, ink, 18, "-");
                try emitRegion(gpa, regions, minus_x, y - 6, sb, sb, @intCast(@intFromEnum(k)), .create_knob_dec);
                try rect(gpa, dl, plus_x, y - 6, sb, sb, 0x14EDEAE0, 8);
                _ = try str(gpa, dl, e, .semibold, plus_x + 10, y + 13, ink, 18, "+");
                try emitRegion(gpa, regions, plus_x, y - 6, sb, sb, @intCast(@intFromEnum(k)), .create_knob_inc);
                var vb: [24]u8 = undefined;
                const vs = std.fmt.bufPrint(&vb, "{d}", .{val}) catch "";
                _ = try str(gpa, dl, e, .semibold, plus_x + sb + 14, y + 14, accent, 16, vs);
                y += 26;
                _ = try str(gpa, dl, e, .regular, x0, y + 12, faint, 13, meta.hint);
                y += 22;
                // A slider bar showing the value's position in its range.
                const bar_w = w - 80;
                try rect(gpa, dl, x0, y, bar_w, 5, 0x18EDEAE0, 2);
                const frac = if (meta.max > meta.min) (val - meta.min) / (meta.max - meta.min) else 0;
                const fill: i32 = @intFromFloat(@as(f32, @floatFromInt(bar_w)) * std.math.clamp(frac, 0, 1));
                try rect(gpa, dl, x0, y, fill, 5, accent, 2);
                y += 26;
            }
            y += 8;
            y = try createNav(gpa, e, dl, x0, y, w, regions, accent, "Continue", .create_next);
        },
        .name => {
            _ = try str(gpa, dl, e, .semibold, x0, y + 30, ink, 30, "Name it");
            y += 52;
            // The name field (the shell owns the text edit; here we draw the box +
            // the current text, and a caret when focused).
            const fh: i32 = 48;
            try rect(gpa, dl, x0, y, w, fh, 0x12EDEAE0, 12);
            if (view.naming) try rect(gpa, dl, x0, y, w, fh, 0x00000000, 12);
            const shown = if (view.name.len > 0) view.name else "My feed";
            const nc = if (view.name.len > 0) ink else faint;
            const pen = try str(gpa, dl, e, .semibold, x0 + 18, y + 31, nc, 18, shown);
            if (view.naming) try rect(gpa, dl, pen + 2, y + 14, 2, 22, accent, 0);
            // The field is implicitly focused on the name step (the shell routes
            // keystrokes here), so there is no separate focus region to emit.
            y += fh + 30;
            // Accent picker: the 9 palette swatches; the chosen one ringed.
            _ = try str(gpa, dl, e, .semibold, x0, y + 12, muted, 13, "ACCENT");
            y += 28;
            const sw: i32 = 34;
            const sgap: i32 = 12;
            for (lens_socket.palette, 0..) |col, ci| {
                const cx = x0 + @as(i32, @intCast(ci)) * (sw + sgap);
                if (ci == view.color) try rect(gpa, dl, cx - 3, y - 3, sw + 6, sw + 6, 0x40FFFFFF, 11);
                try rect(gpa, dl, cx, y, sw, sw, col, 9);
                try emitRegion(gpa, regions, cx, y, @intCast(sw), @intCast(sw), @intCast(ci), .create_color);
            }
            y += sw + 34;
            y = try createNav(gpa, e, dl, x0, y, w, regions, accent, "Create feed", .create_save);
        },
    }
    return (y - scroll) + 40;
}

/// The bottom nav row of a Create step: a "‹ Back" ghost + a filled primary button.
fn createNav(gpa: Allocator, e: *const text.Engine, dl: *raster.DrawList, x0: i32, y: i32, w: i32, regions: ?*Regions, accent: u32, primary: []const u8, primary_action: Action) error{OutOfMemory}!i32 {
    const bh: i32 = 44;
    const back_w: i32 = 96;
    try rect(gpa, dl, x0, y, back_w, bh, 0x12EDEAE0, 11);
    _ = try str(gpa, dl, e, .semibold, x0 + 24, y + 28, ink, 15, "‹ Back");
    try emitRegion(gpa, regions, x0, y, @intCast(back_w), @intCast(bh), 0, .create_back);
    const pw: i32 = 168;
    const px = x0 + w - pw;
    try rect(gpa, dl, px, y, pw, bh, accent, 11);
    const tw: i32 = @intCast(text.measure(e, .semibold, primary, 15));
    _ = try str(gpa, dl, e, .semibold, px + @divTrunc(pw - tw, 2), y + 28, 0xFF0B0B0F, 15, primary);
    try emitRegion(gpa, regions, px, y, @intCast(pw), @intCast(bh), 0, primary_action);
    return y + bh + 20;
}

/// The developer-submission flow's render state (ALGO_SUBMISSION slice 1) —
/// the shell owns + drives it; this is what the renderer reads. Diagnostics
/// and disclosures arrive as pre-formatted sentences (the shell formats once
/// per check, never per frame). A7.2: cold — one per frame on the Create tab,
/// never held in quantity. Waived.
pub const DevView = struct {
    active: bool = false, // the Create tab is hosting the dev flow
    step: dev_flow.Step = .source,
    src: []const u8 = "",
    caret: u32 = 0,
    checked: bool = false, // a check has run since the last edit
    check_ok: bool = false,
    diags: []const []const u8 = &.{}, // compile errors / gate refusals, one sentence each
    disclosures: []const []const u8 = &.{}, // code-derived facts (the review step)
    name: []const u8 = "",
    ranks: []const u8 = "",
    desc: []const u8 = "",
    focus: u8 = 0, // details step: which field owns keys (0 name, 1 ranks, 2 desc, 3 tags)
    color: u8 = 0, // accent palette index (0..8)
    designed: u8 = 1, // declared-surface bitmask: 1 feed / 2 replies / 4 zones
    tags: []const u8 = "", // raw comma-separated tag draft
    status: []const u8 = "", // publish progress / error / the live record uri
};

/// The declared-surface catalog (bit order = the loadout page's socket order).
pub const dev_surfaces = [_][]const u8{ "Feed", "Replies", "Zones" };

/// The source-editor geometry, shared by the draw (`devSource`) and the click →
/// caret inverse (`devSrcCaretAtPoint`) so the two never drift. Code renders as
/// LITERAL lines (no word-wrap — it is code, not prose), with a line-number
/// gutter. A7.2: cold — one transient per frame/click.
const DevEditorGeom = struct { panel_x: i32, panel_y: i32, panel_w: i32, tx: i32, ty0: i32, line_h: i32 };

/// The editor geometry at a given panel top — the draw derives `panel_y` from
/// its running y (template chips may wrap to any number of rows); the caret
/// inverse recomputes the same y for the source-present case (no chips shown).
fn devEditorGeomAt(m: Metrics, panel_y: i32) DevEditorGeom {
    // ty0 clears the panel's header strip (34) plus the first line's ascent.
    return .{ .panel_x = m.lx, .panel_y = panel_y, .panel_w = m.cw, .tx = m.lx + 56, .ty0 = panel_y + 34 + 28, .line_h = 21 };
}

fn devEditorGeom(m: Metrics, scroll: i32) DevEditorGeom {
    var y: i32 = 140 + scroll;
    y += 24; // the step label
    y += 52; // title
    y += 34; // the sub line
    // No chips block: with source present the START FROM row is hidden, and
    // the caret inverse is only ever asked about a non-empty source.
    return devEditorGeomAt(m, y);
}

fn devLineCount(src: []const u8) u32 {
    var n: u32 = 1;
    for (src) |b| {
        if (b == '\n') n += 1;
    }
    return n;
}

/// Map a click at logical (`hx`,`hy`) to the nearest caret byte offset in the
/// dev editor's source, replaying `devSource`'s literal-line layout. Pure: the
/// shell calls it on a `.dev_src` hit, then `textedit.setCaret`. Metrics come
/// from the page width (`composeCaretAtPoint`'s convention) — under a condensed
/// rail's pane geometry the x mapping can drift a few px; the nearest-boundary
/// pick keeps that a one-column miss at worst.
pub fn devSrcCaretAtPoint(e: *const text.Engine, width: i32, src: []const u8, scroll: i32, hx: i32, hy: i32) u32 {
    if (src.len == 0) return 0;
    const m = metricsFor(width);
    const g = devEditorGeom(m, scroll);
    const nlines: i32 = @intCast(devLineCount(src));
    const li: i32 = std.math.clamp(@divFloor(hy - (g.ty0 - 16), g.line_h), 0, nlines - 1);
    // Walk to the target line's byte range.
    var line_start: usize = 0;
    var seen: i32 = 0;
    while (seen < li) {
        const nl = std.mem.indexOfScalarPos(u8, src, line_start, '\n') orelse break;
        line_start = nl + 1;
        seen += 1;
    }
    const line_end = std.mem.indexOfScalarPos(u8, src, line_start, '\n') orelse src.len;
    // Nearest inter-character boundary within the line.
    var best: u32 = @intCast(line_start);
    var best_dx: i32 = std.math.maxInt(i32);
    var x = g.tx;
    var k = line_start;
    while (true) {
        const dx: i32 = @intCast(@abs(@as(i64, x) - hx));
        if (dx < best_dx) {
            best_dx = dx;
            best = @intCast(k);
        }
        if (k >= line_end) break;
        const clen: usize = std.unicode.utf8ByteSequenceLength(src[k]) catch 1;
        x += @intCast(text.measure(e, .regular, src[k..@min(k + clen, line_end)], 15));
        k = @min(k + clen, line_end);
    }
    return best;
}

/// The dev flow's step marker — the hierarchy anchor above each step title
/// (the create flow's "STEP n OF 4" convention).
fn devStepLabel(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, x0: i32, y: i32, accent: u32, label: []const u8) !i32 {
    try rect(gpa, dl, x0, y + 4, 22, 3, accent, 1);
    _ = try str(gpa, dl, e, .semibold, x0 + 32, y + 10, faint, 12, label);
    return y + 24;
}

/// One labeled single-line text field of the details form: the box, the current
/// text (or placeholder), a caret when focused, and its tap region. Returns y
/// below the field.
fn devField(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, x0: i32, y_in: i32, w: i32, regions: ?*Regions, accent: u32, label: []const u8, value: []const u8, placeholder: []const u8, focused: bool, payload: u16) !i32 {
    var y = y_in;
    _ = try str(gpa, dl, e, .semibold, x0, y + 12, faint, 12, label);
    y += 22;
    const fh: i32 = 46;
    try rect(gpa, dl, x0, y, w, fh, 0x12EDEAE0, 12);
    if (focused) try rect(gpa, dl, x0, y, 3, fh, accent, 2);
    const shown = if (value.len > 0) value else placeholder;
    const vc: u32 = if (value.len > 0) ink else faint;
    const pen = try str(gpa, dl, e, .regular, x0 + 16, y + 29, vc, 16, shown);
    if (focused) try rect(gpa, dl, (if (value.len > 0) pen else x0 + 16) + 2, y + 13, 2, 20, accent, 0);
    try emitRegion(gpa, regions, x0, y, w, @intCast(fh), payload, .dev_field);
    return y + fh + 18;
}

/// The dev flow's bottom nav: "‹ Back" ghost, an optional mid ghost button, and
/// a primary (drawn dim when `enabled` is false — the region still emits, so
/// the shell can answer a tap with WHY it is disabled instead of dead pixels).
fn devNav(gpa: Allocator, e: *const text.Engine, dl: *raster.DrawList, x0: i32, y: i32, w: i32, regions: ?*Regions, accent: u32, mid: ?[]const u8, mid_action: Action, primary: []const u8, primary_action: Action, enabled: bool) !i32 {
    const bh: i32 = 44;
    const back_w: i32 = 96;
    try rect(gpa, dl, x0, y, back_w, bh, 0x12EDEAE0, 11);
    _ = try str(gpa, dl, e, .semibold, x0 + 24, y + 28, ink, 15, "‹ Back");
    try emitRegion(gpa, regions, x0, y, back_w, @intCast(bh), 0, .dev_back);
    const pw: i32 = @max(168, @as(i32, @intCast(text.measure(e, .semibold, primary, 15))) + 48);
    const px = x0 + w - pw;
    try rect(gpa, dl, px, y, pw, bh, if (enabled) accent else 0x2AEDEAE0, 11);
    const tw: i32 = @intCast(text.measure(e, .semibold, primary, 15));
    _ = try str(gpa, dl, e, .semibold, px + @divTrunc(pw - tw, 2), y + 28, if (enabled) 0xFF0B0B0F else muted, 15, primary);
    try emitRegion(gpa, regions, px, y, pw, @intCast(bh), 0, primary_action);
    if (mid) |label| {
        const mw: i32 = @as(i32, @intCast(text.measure(e, .semibold, label, 15))) + 44;
        const mx = px - mw - 12;
        try rect(gpa, dl, mx, y, mw, bh, 0x12EDEAE0, 11);
        _ = try str(gpa, dl, e, .semibold, mx + 22, y + 28, ink, 15, label);
        try emitRegion(gpa, regions, mx, y, mw, @intCast(bh), 0, mid_action);
    }
    return y + bh + 20;
}

/// Render the DEVELOPER submission flow (ALGO_SUBMISSION slice 1) into the
/// Create tab — the real-code path beside `layoutCreate`'s guided one. PURE
/// draw over `view`; the shell owns the state, the text buffers, and the
/// check/publish machinery. Returns content height.
pub fn layoutDevSubmit(gpa: Allocator, e: *const text.Engine, dl: *raster.DrawList, m: Metrics, height: i32, scroll: i32, regions: ?*Regions, accent: u32, view: DevView) error{OutOfMemory}!i32 {
    _ = height;
    const x0 = m.lx;
    const w = m.cw;
    var y: i32 = 140 + scroll;

    switch (view.step) {
        .source => {
            y = try devStepLabel(gpa, dl, e, x0, y, accent, "STEP 1 OF 3 — THE CODE");
            _ = try str(gpa, dl, e, .semibold, x0, y + 30, ink, 30, "Submit an algorithm");
            y += 52;
            _ = try str(gpa, dl, e, .regular, x0, y + 16, muted, 14, "Real Zal code — write it here or paste with Ctrl+V. Checked by the gate every published algorithm passes.");
            y += 34;
            if (view.src.len == 0) {
                _ = try str(gpa, dl, e, .semibold, x0, y + 14, faint, 12, "START FROM");
                y += 24;
                var cx = x0;
                for (zal_templates.all, 0..) |tpl, ti| {
                    const tw: i32 = @intCast(text.measure(e, .semibold, tpl.name, 13));
                    const cw2 = tw + 26;
                    if (cx + cw2 > x0 + w and cx > x0) { // wrap: the catalog outgrew one row
                        cx = x0;
                        y += 40;
                    }
                    try rect(gpa, dl, cx, y, cw2, 30, 0x14EDEAE0, 9);
                    _ = try str(gpa, dl, e, .semibold, cx + 13, y + 20, ink, 13, tpl.name);
                    try emitRegion(gpa, regions, cx, y, cw2, 30, @intCast(ti), .dev_template);
                    cx += cw2 + 10;
                }
                y += 44;
            }
            // The editor panel: literal lines over a line-number gutter. Geometry
            // follows the running y (chips may wrap), matching the caret inverse
            // for the source-present case where no chips are drawn.
            const g = devEditorGeomAt(m, y);
            const nlines = devLineCount(view.src);
            const eh: i32 = @max(340, @as(i32, @intCast(nlines)) * g.line_h + 78);
            // OPAQUE panel (owner call, 2026-07-06): the code sits on solid
            // ground, not glass — a slightly lifted plate over the page bg,
            // with a header strip and a darker gutter column giving it a
            // tool's anatomy instead of a floating rectangle.
            try rect(gpa, dl, g.panel_x, g.panel_y, g.panel_w, eh, 0xFF201F17, 14);
            try rect(gpa, dl, g.panel_x, g.panel_y, g.panel_w, 34, 0xFF262419, 14);
            try rect(gpa, dl, g.panel_x, g.panel_y + 30, g.panel_w, 4, 0xFF262419, 0); // square off the strip's bottom
            _ = try str(gpa, dl, e, .semibold, g.panel_x + 16, g.panel_y + 22, faint, 11, "ZAL SOURCE");
            var lcb: [24]u8 = undefined;
            const lct = std.fmt.bufPrint(&lcb, "{d} lines", .{if (view.src.len == 0) 0 else nlines}) catch "";
            const lcw: i32 = @intCast(text.measure(e, .regular, lct, 11));
            _ = try str(gpa, dl, e, .regular, g.panel_x + g.panel_w - lcw - 16, g.panel_y + 22, faint, 11, lct);
            try rect(gpa, dl, g.panel_x, g.panel_y + 34, 44, eh - 34 - 14, 0xFF1B1A13, 0); // the gutter column
            try emitRegion(gpa, regions, g.panel_x, g.panel_y, g.panel_w, @intCast(@min(eh, 32767)), 0, .dev_src);
            if (view.src.len == 0) {
                _ = try str(gpa, dl, e, .regular, g.tx, g.ty0, faint, 15, "fn score() {");
                _ = try str(gpa, dl, e, .regular, g.tx + 24, g.ty0 + g.line_h, faint, 15, "return like_count + reply_count * 27;");
                _ = try str(gpa, dl, e, .regular, g.tx, g.ty0 + g.line_h * 2, faint, 15, "}");
                try rect(gpa, dl, g.tx, g.ty0 - 15, 2, 19, accent, 0); // caret at the start
            } else {
                var baseline = g.ty0;
                var ln: u32 = 1;
                var it = std.mem.splitScalar(u8, view.src, '\n');
                var lnbuf: [8]u8 = undefined;
                var caret_drawn = false;
                var line_start: usize = 0;
                while (it.next()) |src_line| {
                    const lns = std.fmt.bufPrint(&lnbuf, "{d}", .{ln}) catch "";
                    _ = try str(gpa, dl, e, .regular, g.panel_x + 14, baseline, faint, 11, lns);
                    _ = try str(gpa, dl, e, .regular, g.tx, baseline, body_c, 15, src_line);
                    // The caret, when it sits on this line.
                    const line_end = line_start + src_line.len;
                    if (!caret_drawn and view.caret >= line_start and view.caret <= line_end) {
                        const cw3: i32 = @intCast(text.measure(e, .regular, view.src[line_start..view.caret], 15));
                        try rect(gpa, dl, g.tx + cw3, baseline - 15, 2, 19, accent, 0);
                        caret_drawn = true;
                    }
                    line_start = line_end + 1;
                    baseline += g.line_h;
                    ln += 1;
                }
            }
            y = g.panel_y + eh + 18;
            // Check feedback: named refusals/errors, the pass line, or the hint.
            if (view.diags.len > 0) {
                for (view.diags) |d| {
                    try rect(gpa, dl, x0, y + 4, 8, 8, like_c, 4);
                    y = try wrapBody(gpa, dl, e, x0 + 18, y + 12, w - 18, body_c, 14, d, 20, true, null);
                    y += 10;
                }
            } else if (view.checked) {
                try rect(gpa, dl, x0, y + 4, 8, 8, boost_c, 4);
                _ = try str(gpa, dl, e, .semibold, x0 + 18, y + 12, ink, 15, "Compiles clean — and passes the publish gate.");
                y += 28;
            } else {
                _ = try str(gpa, dl, e, .regular, x0, y + 12, faint, 13, "Check compiles your code and runs the publish gate — every refusal is named, never silent.");
                const gl: []const u8 = "Open the writing guide";
                const glw: i32 = @intCast(text.measure(e, .semibold, gl, 13));
                _ = try str(gpa, dl, e, .semibold, x0 + w - glw, y + 12, muted, 13, gl);
                try emitRegion(gpa, regions, x0 + w - glw - 8, y - 4, glw + 16, 28, 0, .docs_dev);
                y += 28;
            }
            y += 10;
            y = try devNav(gpa, e, dl, x0, y, w, regions, accent, "Check", .dev_check, "Continue", .dev_next, view.check_ok);
        },
        .details => {
            y = try devStepLabel(gpa, dl, e, x0, y, accent, "STEP 2 OF 3 — YOUR WORDS");
            _ = try str(gpa, dl, e, .semibold, x0, y + 30, ink, 30, "Describe it");
            y += 52;
            _ = try str(gpa, dl, e, .regular, x0, y + 16, muted, 14, "Your words — shown on the public page beside the facts derived from your code.");
            y += 36;
            y = try devField(gpa, dl, e, x0, y, w, regions, accent, "NAME", view.name, "Untitled algorithm", view.focus == 0, 0);
            y = try devField(gpa, dl, e, x0, y, w, regions, accent, "WHAT IT RANKS FOR — ONE LINE", view.ranks, "e.g. slow-burn threads, no pile-ons", view.focus == 1, 1);
            _ = try str(gpa, dl, e, .semibold, x0, y + 12, faint, 12, "DESCRIPTION");
            y += 22;
            const dh: i32 = 140;
            try rect(gpa, dl, x0, y, w, dh, 0x12EDEAE0, 12);
            if (view.focus == 2) try rect(gpa, dl, x0, y, 3, dh, accent, 2);
            if (view.desc.len > 0) {
                const end_y = try wrapBody(gpa, dl, e, x0 + 16, y + 26, w - 32, ink, 15, view.desc, 21, true, null);
                _ = end_y;
            } else {
                _ = try str(gpa, dl, e, .regular, x0 + 16, y + 26, faint, 15, "What does it surface, and for whom? Enter breaks the line.");
            }
            try emitRegion(gpa, regions, x0, y, w, @intCast(dh), 2, .dev_field);
            y += dh + 18;
            y = try devField(gpa, dl, e, x0, y, w, regions, accent, "TAGS — COMMA-SEPARATED, FOR SEARCH", view.tags, "e.g. calm, chronological, search", view.focus == 3, 3);
            y += 6;
            // DESIGNED FOR: the author's declaration of which sockets this was
            // built for (multi-select; declaration, never enforcement — a
            // mismatched seat later just gets a heads-up).
            _ = try str(gpa, dl, e, .semibold, x0, y + 12, faint, 12, "DESIGNED FOR — WHICH SOCKETS IS THIS BUILT FOR?");
            y += 24;
            var sx = x0;
            for (dev_surfaces, 0..) |surf, si| {
                const on = view.designed & (@as(u8, 1) << @intCast(si)) != 0;
                const tw2: i32 = @intCast(text.measure(e, .semibold, surf, 14));
                const cw4 = tw2 + 48;
                try rect(gpa, dl, sx, y, cw4, 34, if (on) skinPanel(accent) else 0x14EDEAE0, 10);
                if (on) try rect(gpa, dl, sx, y, 3, 34, accent, 2);
                if (on) _ = try str(gpa, dl, e, .semibold, sx + 14, y + 22, accent, 14, "\u{2713}");
                _ = try str(gpa, dl, e, .semibold, sx + 30, y + 22, ink, 14, surf);
                try emitRegion(gpa, regions, sx, y, cw4, 34, @intCast(si), .dev_surface);
                sx += cw4 + 10;
            }
            y += 34 + 24;
            _ = try str(gpa, dl, e, .semibold, x0, y + 12, faint, 12, "ACCENT");
            y += 28;
            const sw: i32 = 34;
            for (lens_socket.palette, 0..) |col, ci| {
                const cx = x0 + @as(i32, @intCast(ci)) * (sw + 12);
                if (ci == view.color) try rect(gpa, dl, cx - 3, y - 3, sw + 6, sw + 6, 0x40FFFFFF, 11);
                try rect(gpa, dl, cx, y, sw, sw, col, 9);
                try emitRegion(gpa, regions, cx, y, sw, @intCast(sw), @intCast(ci), .dev_color);
            }
            y += sw + 34;
            y = try devNav(gpa, e, dl, x0, y, w, regions, accent, null, .dev_check, "Review", .dev_next, view.name.len > 0);
        },
        .review => {
            y = try devStepLabel(gpa, dl, e, x0, y, accent, "STEP 3 OF 3 — THE PUBLIC PAGE");
            _ = try str(gpa, dl, e, .semibold, x0, y + 30, ink, 30, "The public page");
            y += 52;
            _ = try str(gpa, dl, e, .regular, x0, y + 16, muted, 14, "Exactly what a user reads before trying it.");
            y += 36;
            // The card: the author's words, under their chosen accent.
            const card_top = y;
            const card_acc = lens_socket.palette[@min(view.color, lens_socket.palette.len - 1)];
            _ = try str(gpa, dl, e, .semibold, x0 + 24, y + 40, ink, 22, if (view.name.len > 0) view.name else "Untitled algorithm");
            _ = try str(gpa, dl, e, .regular, x0 + 24, y + 62, muted, 13, "by you");
            y += 76;
            if (view.ranks.len > 0) {
                _ = try str(gpa, dl, e, .regular, x0 + 24, y + 8, body_c, 15, view.ranks);
                y += 26;
            }
            if (view.designed != 0) {
                var px2 = try str(gpa, dl, e, .semibold, x0 + 24, y + 10, faint, 12, "DESIGNED FOR");
                px2 += 10;
                for (dev_surfaces, 0..) |surf, si| {
                    if (view.designed & (@as(u8, 1) << @intCast(si)) == 0) continue;
                    const tw3: i32 = @intCast(text.measure(e, .semibold, surf, 12));
                    try rect(gpa, dl, px2, y - 4, tw3 + 20, 22, 0x14EDEAE0, 7);
                    _ = try str(gpa, dl, e, .semibold, px2 + 10, y + 11, ink, 12, surf);
                    px2 += tw3 + 28;
                }
                y += 28;
            }
            if (view.tags.len > 0) {
                _ = try str(gpa, dl, e, .regular, x0 + 24, y + 8, faint, 13, view.tags);
                y += 24;
            }
            if (view.desc.len > 0) {
                y = try wrapBody(gpa, dl, e, x0 + 24, y + 12, w - 48, muted, 15, view.desc, 21, true, null);
            }
            y += 20;
            const card_h = y - card_top;
            // Behind-the-text card chrome drawn as an underlay would need a second
            // pass; the spine alone carries the accent, over the page glass.
            try rect(gpa, dl, x0, card_top, 4, card_h, card_acc, 2);
            y += 8;
            _ = try str(gpa, dl, e, .semibold, x0, y + 14, faint, 12, "WHAT THE CODE PROVES");
            y += 30;
            for (view.disclosures) |fact| {
                try rect(gpa, dl, x0, y + 4, 8, 8, accent, 4);
                _ = try str(gpa, dl, e, .semibold, x0 + 18, y + 12, ink, 15, fact);
                y += 26;
            }
            y += 6;
            y = try wrapBody(gpa, dl, e, x0, y + 12, w, faint, 13, "Derived from the compiled code by the engine — a description never overrides these, here or anywhere an algorithm is shown.", 19, true, null);
            y += 20;
            if (view.status.len > 0) {
                y = try wrapBody(gpa, dl, e, x0, y + 8, w, like_c, 14, view.status, 20, true, null);
                y += 16;
            }
            y = try devNav(gpa, e, dl, x0, y, w, regions, accent, null, .dev_check, "Publish to the marketplace", .dev_publish, true);
        },
        .publishing => {
            y += 120;
            _ = try str(gpa, dl, e, .semibold, x0, y + 30, ink, 26, "Publishing");
            y += 52;
            _ = try str(gpa, dl, e, .regular, x0, y + 16, muted, 15, "Writing the signed record to your repo…");
            y += 40;
        },
        .done => {
            y += 80;
            _ = try str(gpa, dl, e, .semibold, x0, y + 30, ink, 30, "It's live");
            y += 52;
            y = try wrapBody(gpa, dl, e, x0, y + 16, w, muted, 15, "Your algorithm is published under your handle and lands in the marketplace as the network indexes it. It is also on your bench, ready to socket.", 22, true, null);
            y += 24;
            if (view.status.len > 0) {
                y = try wrapBody(gpa, dl, e, x0, y + 8, w, faint, 13, view.status, 19, true, null);
                y += 20;
            }
            const bh: i32 = 44;
            const pw: i32 = 128;
            try rect(gpa, dl, x0, y, pw, bh, accent, 11);
            _ = try str(gpa, dl, e, .semibold, x0 + 44, y + 28, 0xFF0B0B0F, 15, "Done");
            try emitRegion(gpa, regions, x0, y, pw, @intCast(bh), 0, .dev_next);
            y += bh + 20;
        },
    }
    return (y - scroll) + 40;
}

/// A zone's icon-tile colour, derived deterministically from its tag so a zone
/// always wears the same hue (pure — no per-zone metadata exists yet; the real
/// face/colour is a later-engine concern, Z4). A small warm-leaning palette.
fn tilePalette(tag: []const u8) u32 {
    const palette = [_]u32{
        0xFF2FA37A, // green
        0xFF7C6CF0, // violet
        0xFF3B82E0, // blue
        0xFFD08648, // amber-clay
        0xFFC0566F, // rose
        0xFF5BA3C9, // steel
    };
    var h: u32 = 2166136261; // FNV-1a, just to spread tags across the palette
    for (tag) |c| {
        h ^= c;
        h *%= 16777619;
    }
    return palette[h % palette.len];
}

/// One zone card in the browse grid: an icon tile, the `#name`, the post count,
/// and a bookmark affordance. Emits a `.zone_open` region carrying the catalog
/// index (the shell resolves it to the tag and opens the zone feed). Only the
/// name + count are real today; the tile colour is derived, the bookmark is
/// present-but-inert scaffold. PURE.
/// The warning red — destructive labels (Sign out). Local to the settings
/// surface for now; promote to the shared palette when a second site needs it.
const warn: u32 = 0xFFE5544B;

/// The SETTINGS screen (`screen_settings`) — a master–detail layout: a left
/// SECTION list and, on the right, the selected section's rows grouped into
/// rounded cards (the iOS grouped-list look). The whole tree is plain data in
/// `settings_view` (sections + rows); this walks it and paints. Reordering or
/// adding settings is editing that table, never this function. Returns total
/// content height for the scroll clamp. PURE.
///
/// v1 limits (skeleton): both panes scroll together (sections fit a screen, so
/// this rarely shows); every control except Sign out is inert display — taps on
/// other rows emit a `.settings_row` no-op. On a NARROW window the two panes get
/// cramped (settings is normally a wide page); a stacked narrow mode is later.
fn drawSettings(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, m: Metrics, height: i32, scroll: i32, regions: ?*Regions, accent: u32, sel_section: u8, toggles: u64, account: SettingsAccount, choices: u64, picking: u8) error{OutOfMemory}!i32 {
    const x0 = m.lx;
    const w = m.cw;
    // Defensive clamp — the shell owns the selection, but never trust an index
    // at a boundary (it indexes a fixed array).
    const ss: usize = if (sel_section < settings_view.sections.len) sel_section else 0;

    const top: i32 = if (m.wide) 40 else 30;
    const title_y = top + scroll;
    _ = try str(gpa, dl, e, .semibold, x0, title_y + 30, ink, 30, "Settings");
    const body_y = title_y + 70; // both panes begin below the page title

    // Pane split. On PHONE widths the master-detail STACKS instead — the
    // squeezed side-by-side collided labels with values at 430 (on-device
    // finding): the section list runs full width, the detail below it.
    const phone = m.col_w <= phone_max;
    const list_w: i32 = if (phone) w else std.math.clamp(@divTrunc(w * 36, 100), 180, 260);
    const split_gap: i32 = 28;
    const detail_x = if (phone) x0 else x0 + list_w + split_gap;
    const detail_w = if (phone) w else w - list_w - split_gap;

    // ── Left: the section list (icon + label + chevron + active pill). ──
    const sec_row_h: i32 = 50;
    var ly = body_y;
    for (settings_view.sections, 0..) |sec, si| {
        const on = si == ss;
        if (on) try rect(gpa, dl, x0, ly, list_w, sec_row_h - 6, (0x1F << 24) | (accent & 0x00FFFFFF), 12);
        try settingsIcon(sec.icon, gpa, dl, x0 + 14, ly + 11, 22, if (on) accent else muted);
        _ = try str(gpa, dl, e, if (on) .semibold else .regular, x0 + 48, ly + 29, if (on) ink else muted, 16, sec.label);
        try iconChevron(gpa, dl, x0 + list_w - 26, ly + 13, 18, if (on) accent else faint);
        try emitRegion(gpa, regions, x0, ly, list_w, sec_row_h - 6, @intCast(si), .settings_section);
        ly += sec_row_h;
    }

    // ── Right (phone: BELOW the list): the selected section's detail. ──
    const sec = settings_view.sections[ss];
    const detail_y0 = if (phone) body_y + @as(i32, @intCast(settings_view.sections.len)) * sec_row_h + 20 else body_y;
    _ = try str(gpa, dl, e, .semibold, detail_x, detail_y0 + 24, ink, 22, sec.label);
    var dy = detail_y0 + 50;

    // The Toy Box gets a bespoke DETAIL layout: category headers over a grid of
    // tiles (the flat single column was overwhelming). Every other section keeps
    // the generic grouped-card list below. Same rows table, same tap handling.
    if (ss == settings_view.sec_toybox and !phone) {
        const bottom = try drawToyBoxDetail(gpa, dl, e, regions, detail_x, dy, detail_w, height, accent, toggles, account, choices, picking);
        return @max(ly, bottom) - scroll + 40;
    }

    // Precompute the contiguous groups of this section, in order, with counts —
    // so each card's background can be drawn at its full height behind its rows.
    var group_ids: [32]u8 = undefined;
    var group_cnt: [32]i32 = undefined;
    var ng: usize = 0;
    for (settings_view.rows) |r| {
        if (r.section != ss) continue;
        if (phone and !settings_view.rowOnPhone(r)) continue; // dead on mobile
        if (ng == 0 or group_ids[ng - 1] != r.group) {
            if (ng == group_ids.len) break; // table guard (more than 32 groups: unreached)
            group_ids[ng] = r.group;
            group_cnt[ng] = 0;
            ng += 1;
        }
        group_cnt[ng - 1] += 1;
    }

    const row_h: i32 = 52;
    const group_gap: i32 = 22;
    // The open picker's anchor (recorded when its choice row is drawn; the popover
    // is drawn AFTER the loop so it overlays the rows below it).
    var pick_act: u8 = 255;
    var pick_x: i32 = 0;
    var pick_y: i32 = 0;
    var pick_w: i32 = 0;
    var pick_row_top: i32 = 0;
    for (0..ng) |g| {
        const gid = group_ids[g];
        const card_h = group_cnt[g] * row_h;
        if (dy + card_h > 0 and dy < height) {
            try cardBox(gpa, dl, detail_x, dy, detail_w, card_h, 14, skinPanel(accent));
            var k: i32 = 0;
            for (settings_view.rows, 0..) |r, ridx| {
                if (r.section != ss or r.group != gid) continue;
                if (phone and !settings_view.rowOnPhone(r)) continue; // dead on mobile

                const ry = dy + k * row_h;
                if (k > 0) try rect(gpa, dl, detail_x + 18, ry, detail_w - 36, 1, divider, 0);
                try drawSettingsRow(gpa, dl, e, regions, r, @intCast(ridx), detail_x, ry, detail_w, row_h, accent, toggles, account, choices);
                if (r.kind == .choice and r.action == picking) {
                    pick_x = detail_x;
                    pick_y = ry + row_h;
                    pick_row_top = ry;
                    pick_w = detail_w;
                    pick_act = r.action;
                }
                k += 1;
            }
        }
        dy += card_h + group_gap;
    }

    // The open choice's picker popover, drawn last so it overlays the rows below.
    // Flip it ABOVE the row when opening below would run off the bottom (the pet
    // colour/size sit low in the Toy Box list, so their pickers must open upward).
    if (pick_act != 255) if (settings_view.choiceOf(pick_act)) |ch| {
        const th = @as(i32, @intCast(ch.options.len)) * 38 + 20;
        const py2 = if (pick_y + th > height) pick_row_top - th else pick_y;
        try drawChoicePopover(gpa, dl, e, regions, ch, pick_x, py2, pick_w, choices);
    };

    return @max(ly, dy) - scroll + 40;
}

/// The Toy Box detail pane: each category (a row group) becomes a titled GRID of
/// tiles instead of one long single-column list. Toggles / choices / the pet-name
/// field reuse `drawSettingsRow` inside a tile box, so tap handling, the choice
/// popover, and live state are all unchanged (the shell sees the same `.settings_
/// row` / `.settings_choice` regions). The "feed motion" category renders as a
/// pick-one selectable-card grid, since those toys are mutually exclusive. Returns
/// the bottom Y (scrolled coords). PURE — walks the `settings_view` table.
fn drawToyBoxDetail(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, regions: ?*Regions, x: i32, y0: i32, w: i32, height: i32, accent: u32, toggles: u64, account: SettingsAccount, choices: u64, picking: u8) error{OutOfMemory}!i32 {
    const col_gap: i32 = 14;
    const tile_w = @divTrunc(w - col_gap, 2); // two columns
    const tile_h: i32 = 60;
    const tile_gap: i32 = 12;

    // Distinct groups (categories) of the Toy Box section, in table order.
    var groups: [16]u8 = undefined;
    var ng: usize = 0;
    for (settings_view.rows) |r| {
        if (r.section != settings_view.sec_toybox) continue;
        if (ng == 0 or groups[ng - 1] != r.group) {
            if (ng == groups.len) break;
            groups[ng] = r.group;
            ng += 1;
        }
    }

    // The open choice's picker anchor (a Companion tile), drawn after the grid so
    // it overlays the tiles beneath it.
    var pick_act: u8 = 255;
    var pick_x: i32 = 0;
    var pick_y: i32 = 0;
    var pick_w: i32 = 0;
    var pick_top: i32 = 0;

    var dy = y0;
    for (0..ng) |gi| {
        const gid = groups[gi];
        const motion = gid == settings_view.toy_motion_group;

        // Category header (+ a "pick one" hint over the mutually-exclusive group).
        dy += if (gi == 0) 6 else 20;
        _ = try str(gpa, dl, e, .semibold, x, dy + 14, muted, 13, settings_view.toyCategoryTitle(gid));
        if (motion) {
            const hint = "pick one";
            const hw: i32 = @intCast(text.measure(e, .regular, hint, 12));
            _ = try str(gpa, dl, e, .regular, x + w - hw, dy + 14, faint, 12, hint);
        }
        dy += 26;

        // Tiles in two columns, wrapping.
        var col: i32 = 0;
        var row_top = dy;
        for (settings_view.rows, 0..) |r, ridx| {
            if (r.section != settings_view.sec_toybox or r.group != gid) continue;
            const tx = x + col * (tile_w + col_gap);
            const ty = row_top;
            const on = (toggles >> @as(u6, @intCast(ridx))) & 1 != 0;
            if (motion) {
                // Pick-one card: the active toy fills with the accent, the rest sit
                // as quiet panels. Tapping emits the same toggle region — the shell's
                // mutual-exclusion clears the others (re-tapping the active = off).
                const fill: u32 = if (on) (accent & 0x00FFFFFF) | 0xFF000000 else skinPanel(accent);
                try cardBox(gpa, dl, tx, ty, tile_w, tile_h, 12, fill);
                if (on) try rect(gpa, dl, tx, ty, tile_w, 2, 0x40FFFFFF, 12);
                const lw: i32 = @intCast(text.measure(e, .semibold, r.label, 15));
                _ = try str(gpa, dl, e, .semibold, tx + @divTrunc(tile_w - lw, 2), ty + @divTrunc(tile_h, 2) + 5, if (on) bg else ink, 15, r.label);
                try emitRegion(gpa, regions, tx, ty, tile_w, tile_h, @intCast(ridx), .settings_row);
            } else {
                // A standard tile: a bordered panel + the shared row renderer inside.
                try cardBox(gpa, dl, tx, ty, tile_w, tile_h, 12, skinPanel(accent));
                try drawSettingsRow(gpa, dl, e, regions, r, @intCast(ridx), tx, ty, tile_w, tile_h, accent, toggles, account, choices);
                // Anchor the choice popover under the open picker's tile.
                if (r.kind == .choice and r.action == picking) {
                    pick_act = r.action;
                    pick_x = tx;
                    pick_y = ty + tile_h;
                    pick_top = ty;
                    pick_w = tile_w;
                }
            }
            col += 1;
            if (col >= 2) {
                col = 0;
                row_top += tile_h + tile_gap;
            }
        }
        if (col != 0) row_top += tile_h + tile_gap; // close a half-filled final row
        dy = row_top;
    }

    // The open picker popover — flip ABOVE its tile if opening below runs off-screen.
    if (pick_act != 255) if (settings_view.choiceOf(pick_act)) |ch| {
        const th = @as(i32, @intCast(ch.options.len)) * 38 + 20;
        const py2 = if (pick_y + th > height) pick_top - th else pick_y;
        try drawChoicePopover(gpa, dl, e, regions, ch, pick_x, py2, pick_w, choices);
    };

    return dy;
}

/// Toy Box: Pet — the companion's base footprint (logical px, before size scale),
/// so the shell places it and hit-tests taps against the same box.
pub const pet_w: i32 = 66;
pub const pet_h: i32 = 66;

/// The pet body colour for a "Pet colour" choice index.
pub fn petColor(idx: u8) u32 {
    return switch (idx) {
        1 => 0xFFB8E6C8, // mint
        2 => 0xFFF2B6C6, // rose
        3 => 0xFFF1D89C, // amber
        4 => 0xFFD3BCEC, // violet
        5 => 0xFFC6CCD6, // grey
        else => 0xFFCBD6EE, // blue
    };
}

/// The "Pet size" choice index → a draw scale.
pub fn petScale(idx: u8) f32 {
    return switch (idx) {
        0 => 0.75, // small
        2 => 1.45, // large
        else => 1.0, // medium
    };
}

fn petRot(fx: f32, fy: f32, cr: f32, sr: f32, cx: f32, cy: f32) [2]i32 {
    return .{ @intFromFloat(cx + fx * cr - fy * sr), @intFromFloat(cy + fx * sr + fy * cr) };
}

/// Draw the Pet: a hand-rolled blob at (ox, oy) top-left of its `scale`d box. Its
/// face is chosen by `anim` (0 idle, 1 happy, 2 sulk, 3 sleep, 4 excited-when-
/// thrown); `roll` spins the features around the round body so a flung pet tumbles
/// like a ball; `body` is its colour; `name` (if any) floats over its head. Bobs on
/// `phase`. No sprite asset — pure vector vocabulary. PURE.
pub fn drawPet(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, ox: i32, oy: i32, anim: u8, phase: f32, roll: f32, scale: f32, body: u32, accent: u32, name: []const u8) error{OutOfMemory}!void {
    const dark: u32 = 0xFF262A36;
    const s = scale;
    const R: f32 = 28.0 * s; // body radius
    const bob: f32 = @sin(phase) * 3.0 * s;
    const halfw = @as(f32, @floatFromInt(pet_w)) * s * 0.5;
    const halfh = @as(f32, @floatFromInt(pet_h)) * s * 0.5;
    const cx = @as(f32, @floatFromInt(ox)) + halfw;
    const cy = @as(f32, @floatFromInt(oy)) + halfh + bob;
    const cr = @cos(roll);
    const sr = @sin(roll);
    const rad: u8 = @intFromFloat(@min(255.0, R));
    const dot: i32 = @intFromFloat(@max(3.0, 6.0 * s));
    // Ground shadow (fixed to the box bottom, doesn't bob).
    try rect(gpa, dl, ox + @as(i32, @intFromFloat(6.0 * s)), oy + @as(i32, @intFromFloat(@as(f32, @floatFromInt(pet_h)) * s - 4.0)), @intFromFloat(@as(f32, @floatFromInt(pet_w)) * s - 12.0), @intFromFloat(@max(4.0, 7.0 * s)), 0x40000000, 4);
    // Ears + feet at rotated offsets (they orbit as it rolls), then the round body.
    const ear = petRot(R * 0.55, -R * 0.9, cr, sr, cx, cy);
    const ear2 = petRot(-R * 0.55, -R * 0.9, cr, sr, cx, cy);
    const foot = petRot(R * 0.42, R * 0.82, cr, sr, cx, cy);
    const foot2 = petRot(-R * 0.42, R * 0.82, cr, sr, cx, cy);
    const es: i32 = @intFromFloat(@max(6.0, 13.0 * s));
    try rect(gpa, dl, ear[0] - @divTrunc(es, 2), ear[1] - es, es, @intFromFloat(15.0 * s), body, @intFromFloat(6.0 * s));
    try rect(gpa, dl, ear2[0] - @divTrunc(es, 2), ear2[1] - es, es, @intFromFloat(15.0 * s), body, @intFromFloat(6.0 * s));
    try rect(gpa, dl, foot[0] - @divTrunc(es, 2), foot[1], es, @intFromFloat(10.0 * s), body, @intFromFloat(5.0 * s));
    try rect(gpa, dl, foot2[0] - @divTrunc(es, 2), foot2[1], es, @intFromFloat(10.0 * s), body, @intFromFloat(5.0 * s));
    try rect(gpa, dl, @intFromFloat(cx - R), @intFromFloat(cy - R * 0.92), @intFromFloat(R * 2.0), @intFromFloat(R * 1.84), body, rad);
    // Face — feature centres rotate with the roll; expressions drawn at them.
    const le = petRot(-R * 0.4, -R * 0.08, cr, sr, cx, cy);
    const re = petRot(R * 0.4, -R * 0.08, cr, sr, cx, cy);
    const mo = petRot(0, R * 0.42, cr, sr, cx, cy);
    switch (anim) {
        1 => { // HAPPY: closed ^_^ eyes, a curved SMILE, blush + a floating heart
            const ew: i32 = @intFromFloat(5.0 * s);
            try line(gpa, dl, le[0] - ew, le[1] + 2, le[0], le[1] - 3, dark, 2); // left ^
            try line(gpa, dl, le[0], le[1] - 3, le[0] + ew, le[1] + 2, dark, 2);
            try line(gpa, dl, re[0] - ew, re[1] + 2, re[0], re[1] - 3, dark, 2); // right ^
            try line(gpa, dl, re[0], re[1] - 3, re[0] + ew, re[1] + 2, dark, 2);
            const mw2: i32 = @intFromFloat(8.0 * s);
            const md: i32 = @intFromFloat(5.0 * s);
            try line(gpa, dl, mo[0] - mw2, mo[1] - 1, mo[0], mo[1] + md, dark, 2); // smile (U)
            try line(gpa, dl, mo[0], mo[1] + md, mo[0] + mw2, mo[1] - 1, dark, 2);
            const blush = (accent & 0x00FFFFFF) | 0x55000000;
            try rect(gpa, dl, le[0] - @as(i32, @intFromFloat(9.0 * s)), le[1] + @as(i32, @intFromFloat(6.0 * s)), @intFromFloat(7.0 * s), @intFromFloat(5.0 * s), blush, 3);
            try rect(gpa, dl, re[0] + @as(i32, @intFromFloat(2.0 * s)), re[1] + @as(i32, @intFromFloat(6.0 * s)), @intFromFloat(7.0 * s), @intFromFloat(5.0 * s), blush, 3);
            // a little heart bobbing over the head
            const heart: u32 = 0xFFF06B8A;
            const hx2 = @as(i32, @intFromFloat(cx + R * 0.5));
            const hy2 = @as(i32, @intFromFloat(cy - R - 6.0 * s)) - @as(i32, @intFromFloat(@sin(phase) * 2.0));
            const hb: i32 = @intFromFloat(@max(3.0, 5.0 * s));
            try rect(gpa, dl, hx2 - hb, hy2, hb, hb, heart, @intCast(@divTrunc(hb, 2)));
            try rect(gpa, dl, hx2, hy2, hb, hb, heart, @intCast(@divTrunc(hb, 2)));
            try tri(gpa, dl, hx2 - hb, hy2 + hb - 1, hx2 + hb, hy2 + hb - 1, hx2, hy2 + hb + hb, heart);
        },
        4 => { // EXCITED "whee": wide-open round eyes + an open O mouth
            const big: i32 = dot + 4;
            try rect(gpa, dl, le[0] - @divTrunc(big, 2), le[1] - @divTrunc(big, 2), big, big, dark, @intCast(@divTrunc(big, 2)));
            try rect(gpa, dl, re[0] - @divTrunc(big, 2), re[1] - @divTrunc(big, 2), big, big, dark, @intCast(@divTrunc(big, 2)));
            const ms2: i32 = @intFromFloat(@max(6.0, 10.0 * s));
            try rect(gpa, dl, mo[0] - @divTrunc(ms2, 2), mo[1] - 1, ms2, ms2, dark, @intCast(@divTrunc(ms2, 2)));
        },
        2 => { // sulk: dot eyes, a frown (inverted line pair)
            try rect(gpa, dl, le[0] - @divTrunc(dot, 2), le[1] - @divTrunc(dot, 2), dot, dot, dark, @intCast(@divTrunc(dot, 2)));
            try rect(gpa, dl, re[0] - @divTrunc(dot, 2), re[1] - @divTrunc(dot, 2), dot, dot, dark, @intCast(@divTrunc(dot, 2)));
            const fw: i32 = @intFromFloat(7.0 * s);
            try line(gpa, dl, mo[0] - fw, mo[1] + fw, mo[0], mo[1], dark, 2);
            try line(gpa, dl, mo[0], mo[1], mo[0] + fw, mo[1] + fw, dark, 2);
        },
        3 => { // sleep: closed eyes, a little o, rising z's
            const lw: i32 = @intFromFloat(9.0 * s);
            try rect(gpa, dl, le[0] - @divTrunc(lw, 2), le[1], lw, 2, dark, 1);
            try rect(gpa, dl, re[0] - @divTrunc(lw, 2), re[1], lw, 2, dark, 1);
            try rect(gpa, dl, mo[0] - @divTrunc(dot, 2), mo[1] - @divTrunc(dot, 2), dot, dot, dark, @intCast(@divTrunc(dot, 2)));
            const zt: i32 = @intFromFloat(@sin(phase) * 3.0);
            _ = try str(gpa, dl, e, .semibold, @as(i32, @intFromFloat(cx + R)), @as(i32, @intFromFloat(cy - R)) + zt, dark, 13, "z");
            _ = try str(gpa, dl, e, .semibold, @as(i32, @intFromFloat(cx + R + 10.0)), @as(i32, @intFromFloat(cy - R - 14.0)), dark, 16, "z");
        },
        else => { // idle: dot eyes (occasional blink), neutral mouth line
            if (@sin(phase * 0.8) > 0.94) {
                const lw: i32 = @intFromFloat(8.0 * s);
                try rect(gpa, dl, le[0] - @divTrunc(lw, 2), le[1], lw, 2, dark, 1);
                try rect(gpa, dl, re[0] - @divTrunc(lw, 2), re[1], lw, 2, dark, 1);
            } else {
                try rect(gpa, dl, le[0] - @divTrunc(dot, 2), le[1] - @divTrunc(dot, 2), dot, dot, dark, @intCast(@divTrunc(dot, 2)));
                try rect(gpa, dl, re[0] - @divTrunc(dot, 2), re[1] - @divTrunc(dot, 2), dot, dot, dark, @intCast(@divTrunc(dot, 2)));
            }
            const mw: i32 = @intFromFloat(11.0 * s);
            try rect(gpa, dl, mo[0] - @divTrunc(mw, 2), mo[1], mw, @intFromFloat(@max(2.0, 3.0 * s)), dark, 1);
        },
    }
    // The pet's NAME floats over its head.
    if (name.len > 0) {
        const npx: u16 = 14;
        const nw: i32 = @intCast(text.measure(e, .semibold, name, npx));
        const ny = @as(i32, @intFromFloat(cy - R - 12.0 * s)) - 8;
        try rect(gpa, dl, @intFromFloat(cx - @as(f32, @floatFromInt(nw)) * 0.5 - 7.0), ny - 14, nw + 14, 20, 0xCC1E1C16, 9);
        _ = try str(gpa, dl, e, .semibold, @intFromFloat(cx - @as(f32, @floatFromInt(nw)) * 0.5), ny, 0xFFF2EEE4, npx, name);
    }
}

/// Toy Box: Pet — dim the spot a profile picture was plucked from (a dark disc
/// over the original avatar), so the post reads as having lost it while you drag.
pub fn dimAvatar(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, w: i32, hh: i32) error{OutOfMemory}!void {
    try rect(gpa, dl, x, y, w, hh, 0xC0141210, @intCast(@min(255, @divTrunc(w, 2))));
}

/// Toy Box: Pet — a floating avatar "token" (a coloured disc + the author's
/// initial) at centre (cx, cy), drawn while you drag a profile picture out of the
/// feed toward the pet to feed it. PURE.
pub fn drawAvatarToken(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, cx: i32, cy: i32, size: i32, tint: u32, initial: u8) error{OutOfMemory}!void {
    const r = @divTrunc(size, 2);
    const px: u16 = @intCast(@divTrunc(size * 3, 5));
    try rect(gpa, dl, cx - r, cy - r + 3, size, size, 0x55000000, @intCast(r)); // shadow
    try rect(gpa, dl, cx - r, cy - r, size, size, tint, @intCast(r));
    const iadv: i32 = @intCast(text.advance(e, .semibold, initial, px));
    _ = try glyph1(gpa, dl, e, .semibold, cx - @divTrunc(iadv, 2), cy + @divTrunc(size, 4), 0xFF1A1712, px, initial);
}

// ── Toy Box: the XP skin — a retro-desktop chrome overlay ──────────────────
// Built ENTIRELY from the existing rect/line/text vocabulary: the glossy
// gradients are stacks of interpolated horizontal strips, the 3-D bevels are
// light/dark line pairs. No new DrawItem variant, so it renders identically on
// the software and GPU paths with zero backend change (D1/D3). PURE (B2): the
// shell reads the wall clock and hands `hour`/`minute` in as plain values
// (B3/B4). Drawn in LOGICAL coordinates; the renderer scales it to the window.

/// The retro chrome's fixed bar heights (logical px). Public so the shell and
/// tests can reason about the frame without duplicating the constants.
pub const xp_title_h: i32 = 30;
pub const xp_task_h: i32 = 34;

/// Blend two 0xAARRGGBB colours, `t` in [0,1] (0 = a, 1 = b). Opaque result —
/// the chrome is solid. Local to the skin.
fn xpLerp(a: u32, b: u32, t: f32) u32 {
    const tt = std.math.clamp(t, 0.0, 1.0);
    const af = struct {
        fn ch(c: u32, sh: u5) f32 {
            return @floatFromInt((c >> sh) & 0xFF);
        }
    };
    const r: u32 = @intFromFloat(af.ch(a, 16) + (af.ch(b, 16) - af.ch(a, 16)) * tt);
    const g: u32 = @intFromFloat(af.ch(a, 8) + (af.ch(b, 8) - af.ch(a, 8)) * tt);
    const bl: u32 = @intFromFloat(af.ch(a, 0) + (af.ch(b, 0) - af.ch(a, 0)) * tt);
    return 0xFF000000 | (r << 16) | (g << 8) | bl;
}

/// A vertical two-stop gradient as a stack of horizontal strips (the glossy
/// bar). Chrome-only, so a coarse strip count still reads as smooth.
fn xpGradientV(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, w: i32, h: i32, top: u32, bot: u32) !void {
    if (h <= 0 or w <= 0) return;
    const n: i32 = @min(h, 24);
    var i: i32 = 0;
    while (i < n) : (i += 1) {
        const t: f32 = if (n <= 1) 0.0 else @as(f32, @floatFromInt(i)) / @as(f32, @floatFromInt(n - 1));
        const sy = y + @divTrunc(i * h, n);
        const sy2 = y + @divTrunc((i + 1) * h, n);
        try rect(gpa, dl, x, sy, w, @max(1, sy2 - sy), xpLerp(top, bot, t), 0);
    }
}

/// A 3-D bevel border around a box: two light edges + two dark edges. `raised`
/// lights the top-left (a button popping out); otherwise it lights the
/// bottom-right (a sunken well). The classic Win9x/XP button relief.
fn xpBevel(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, w: i32, h: i32, raised: bool, light: u32, dark: u32) !void {
    if (w <= 0 or h <= 0) return;
    const tl = if (raised) light else dark;
    const br = if (raised) dark else light;
    try rect(gpa, dl, x, y, w, 1, tl, 0); // top
    try rect(gpa, dl, x, y, 1, h, tl, 0); // left
    try rect(gpa, dl, x, y + h - 1, w, 1, br, 0); // bottom
    try rect(gpa, dl, x + w - 1, y, 1, h, br, 0); // right
}

/// Draw the whole retro-desktop chrome: a glossy Luna title bar (window mark +
/// "zat" + minimize/maximize/close buttons), the sunken window-edge relief down
/// the sides, and a taskbar (green Start button + a live clock well). Appended
/// AFTER the feed content, so it frames whatever is on screen. PURE.
pub fn drawXpSkin(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, w: i32, h: i32, hour: u8, minute: u8) error{OutOfMemory}!void {
    const white: u32 = 0xFFFFFFFF;
    const luna_top: u32 = 0xFF3C8CE8;
    const luna_bot: u32 = 0xFF0A50C0;
    const luna_gloss: u32 = 0xFF9CC8F7;
    const luna_shadow: u32 = 0xFF063A8C;

    // ── Title bar ──────────────────────────────────────────────────────────
    try xpGradientV(gpa, dl, 0, 0, w, xp_title_h, luna_top, luna_bot);
    try rect(gpa, dl, 0, 1, w, 1, luna_gloss, 0); // bright gloss under the top edge
    try rect(gpa, dl, 0, xp_title_h - 1, w, 1, luna_shadow, 0); // dark seam at the base

    // Window mark — an ORIGINAL generic "application window" glyph (deliberately
    // NOT a vendor logo): a white pane with a blue title strip and content lines.
    const ix: i32 = 8;
    const iy: i32 = 7;
    const isz: i32 = 16;
    try rect(gpa, dl, ix, iy, isz, isz, 0xFF3E3B33, 0); // dark frame
    try rect(gpa, dl, ix + 1, iy + 1, isz - 2, isz - 2, white, 0); // pane
    try rect(gpa, dl, ix + 1, iy + 1, isz - 2, 4, 0xFF1E63C8, 0); // title strip
    try rect(gpa, dl, ix + 3, iy + 8, isz - 6, 1, 0xFF9A968A, 0); // content lines
    try rect(gpa, dl, ix + 3, iy + 11, isz - 8, 1, 0xFF9A968A, 0);

    // Title text, with a soft one-px shadow for legibility on the gradient.
    const tx = ix + isz + 8;
    _ = try str(gpa, dl, e, .semibold, tx + 1, 22, luna_shadow, 16, "zat");
    _ = try str(gpa, dl, e, .semibold, tx, 21, white, 16, "zat");

    // Window buttons — minimize, maximize, close — right-aligned.
    const btn: i32 = 20;
    const gap: i32 = 4;
    const bt_y: i32 = 5;
    const close_x = w - 8 - btn;
    const max_x = close_x - gap - btn;
    const min_x = max_x - gap - btn;
    const btn_lo: u32 = 0xFF1E63C8;
    const btn_hi: u32 = 0xFF6FB0F2;
    // minimize
    try xpGradientV(gpa, dl, min_x, bt_y, btn, btn, btn_hi, btn_lo);
    try xpBevel(gpa, dl, min_x, bt_y, btn, btn, true, 0xFFCFE4FB, luna_shadow);
    try rect(gpa, dl, min_x + 5, bt_y + btn - 7, btn - 10, 2, white, 0);
    // maximize (a small window outline)
    try xpGradientV(gpa, dl, max_x, bt_y, btn, btn, btn_hi, btn_lo);
    try xpBevel(gpa, dl, max_x, bt_y, btn, btn, true, 0xFFCFE4FB, luna_shadow);
    try xpBevel(gpa, dl, max_x + 5, bt_y + 5, btn - 10, btn - 10, false, white, white);
    try rect(gpa, dl, max_x + 5, bt_y + 5, btn - 10, 2, white, 0);
    // close (red) with an X
    try xpGradientV(gpa, dl, close_x, bt_y, btn, btn, 0xFFF08A6E, 0xFFD23B22);
    try xpBevel(gpa, dl, close_x, bt_y, btn, btn, true, 0xFFF9C9BC, 0xFF9A2414);
    try line(gpa, dl, close_x + 6, bt_y + 6, close_x + btn - 6, bt_y + btn - 6, white, 2);
    try line(gpa, dl, close_x + btn - 6, bt_y + 6, close_x + 6, bt_y + btn - 6, white, 2);

    // ── Window-edge relief — a thin sunken frame down the left and right, so
    // the feed reads as the client area of a desktop window.
    const tb_y = h - xp_task_h;
    try rect(gpa, dl, 0, xp_title_h, 2, tb_y - xp_title_h, luna_shadow, 0);
    try rect(gpa, dl, w - 2, xp_title_h, 2, tb_y - xp_title_h, luna_shadow, 0);

    // ── Taskbar ────────────────────────────────────────────────────────────
    try xpGradientV(gpa, dl, 0, tb_y, w, xp_task_h, 0xFF3A86E4, 0xFF0B44B4);
    try rect(gpa, dl, 0, tb_y, w, 1, luna_gloss, 0);
    try rect(gpa, dl, 0, tb_y + 1, w, 1, 0xFF6FB0F2, 0);

    // Start button — the glossy green pill, bottom-left.
    const st_x: i32 = 6;
    const st_h: i32 = xp_task_h - 8;
    const st_y = tb_y + 4;
    const st_rad: u8 = @intCast(@divTrunc(st_h, 2));
    const flag_x = st_x + 10;
    const flag_y = st_y + @divTrunc(st_h - 12, 2);
    const start_lbl = "start";
    const lbl_w: i32 = @intCast(text.measure(e, .semibold, start_lbl, 15));
    const st_w = flag_x + 14 + lbl_w + 12 - st_x;
    try rect(gpa, dl, st_x + 1, st_y + 2, st_w, st_h, 0x40000000, st_rad); // drop shadow
    try rect(gpa, dl, st_x, st_y, st_w, st_h, 0xFF2E7A26, st_rad); // base green
    try rect(gpa, dl, st_x + 1, st_y + 1, st_w - 2, @divTrunc(st_h, 2), 0x45FFFFFF, st_rad); // top gloss
    // Original "application window" glyph (NOT a vendor logo).
    const fsz: i32 = 12;
    try rect(gpa, dl, flag_x, flag_y, fsz, fsz, 0xFF1A3308, 0);
    try rect(gpa, dl, flag_x + 1, flag_y + 1, fsz - 2, fsz - 2, white, 0);
    try rect(gpa, dl, flag_x + 1, flag_y + 1, fsz - 2, 3, 0xFF1E63C8, 0);
    try rect(gpa, dl, flag_x + 3, flag_y + 7, fsz - 6, 1, 0xFF6A655A, 0);
    _ = try str(gpa, dl, e, .semibold, flag_x + 15, st_y + @divTrunc(st_h, 2) + 5, luna_shadow, 15, start_lbl);
    _ = try str(gpa, dl, e, .semibold, flag_x + 14, st_y + @divTrunc(st_h, 2) + 4, white, 15, start_lbl);

    // Clock well — a sunken panel, bottom-right, showing local 12-hour time.
    var buf: [12]u8 = undefined;
    const pm = hour >= 12;
    var h12: u8 = hour % 12;
    if (h12 == 0) h12 = 12;
    const clock = std.fmt.bufPrint(&buf, "{d}:{d:0>2} {s}", .{ h12, minute, if (pm) "PM" else "AM" }) catch "--:--";
    const cw: i32 = @intCast(text.measure(e, .semibold, clock, 14) + 20);
    const ch: i32 = st_h;
    const cx0 = w - 8 - cw;
    const cy0 = st_y;
    try rect(gpa, dl, cx0, cy0, cw, ch, 0xFF0E4EBE, 4);
    try xpBevel(gpa, dl, cx0, cy0, cw, ch, false, 0xFF5B97E8, 0xFF07347F);
    const clw: i32 = @intCast(text.measure(e, .semibold, clock, 14));
    _ = try str(gpa, dl, e, .semibold, cx0 + @divTrunc(cw - clw, 2), cy0 + @divTrunc(ch, 2) + 5, white, 14, clock);
}

// ── Toy Box: the XP skin — the retro RE-THEME of the whole content area ──────
// A pure draw-list transform (the SAME shape as the Gravity shatter): it takes
// the finished draw list for ANY screen and rewrites every item into an
// old-software look — square corners, a classic grey window face, black text,
// and 3-D beveled widgets. Because every screen renders through the one draw
// list, this single pass re-skins the entire app (feed, settings, zones, chat)
// at once (D6: one slice, not a per-screen fork). PURE (B2).

pub const retro_desktop: u32 = 0xFF0E7C74; // the classic teal desktop (gpu clear)
const retro_win: u32 = 0xFFECE9D8; // window client / large panels
const retro_face: u32 = 0xFFD8D4C8; // button / card face
const retro_text: u32 = 0xFF1B1B17; // near-black body text
const retro_muted: u32 = 0xFF57544B; // secondary text
const retro_faint: u32 = 0xFF7C786C; // tertiary text
const retro_hi: u32 = 0xFFFFFFFF; // bevel highlight (top-left)
const retro_sh: u32 = 0xFF8C897C; // bevel inner shadow (bottom-right)
const retro_dk: u32 = 0xFF3E3B33; // bevel outer line (deeper shadow)
const retro_navy: u32 = 0xFF0A3D91; // links / coloured labels

fn retroLuma(c: u32) f32 {
    const r: f32 = @floatFromInt((c >> 16) & 0xFF);
    const g: f32 = @floatFromInt((c >> 8) & 0xFF);
    const b: f32 = @floatFromInt(c & 0xFF);
    return (0.299 * r + 0.587 * g + 0.114 * b) / 255.0;
}
fn retroSat(c: u32) f32 {
    const r: i32 = @intCast((c >> 16) & 0xFF);
    const g: i32 = @intCast((c >> 8) & 0xFF);
    const b: i32 = @intCast(c & 0xFF);
    const mx = @max(r, @max(g, b));
    const mn = @min(r, @min(g, b));
    if (mx == 0) return 0;
    return @as(f32, @floatFromInt(mx - mn)) / @as(f32, @floatFromInt(mx));
}

/// Remap a FILL colour (rects). Faint overlays become subtle grooves; opaque
/// saturated fills (avatars, like/boost accents) keep their hue so meaning
/// survives; everything else becomes the classic window/button grey.
fn retroFill(c: u32, is_widget: bool) u32 {
    const a = (c >> 24) & 0xFF;
    if (a < 0x30) return (a << 24) | 0x00201E18; // faint divider/hover → dark groove, alpha kept
    if (retroSat(c) > 0.32 and a >= 0x80) return (c & 0x00FFFFFF) | 0xFF000000; // accent keeps hue, opaque
    const base = if (retroLuma(c) > 0.80) retro_hi else if (is_widget) retro_face else retro_win;
    return (base & 0x00FFFFFF) | 0xFF000000; // solid grey
}

/// Remap a TEXT colour: the warm inks map to a black/grey scale; coloured labels
/// become the classic navy link; other light text goes black.
fn retroInk(c: u32) u32 {
    switch (c) {
        ink => return retro_text,
        muted => return retro_muted,
        faint => return retro_faint,
        else => {},
    }
    if (retroSat(c) > 0.35) return retro_navy;
    if (retroLuma(c) > 0.45) return retro_text;
    return c;
}

/// Remap a STROKE colour (line/tri icons): saturated strokes (the red like heart,
/// etc.) keep their hue; light icon strokes go black so they read on the grey.
fn retroStroke(c: u32) u32 {
    if (retroSat(c) > 0.32) return c;
    const a = c & 0xFF000000;
    if ((c >> 24) & 0xFF < 0x30) return a | 0x00201E18;
    if (retroLuma(c) > 0.45) return a | (retro_text & 0x00FFFFFF);
    return c;
}

/// Rewrite `dl` in place into the retro look. `add_client_bg` prepends the grey
/// window client rect (the main content tile wants it; the nav-rail tile, which
/// draws OVER the content, must not — it would cover the feed). PURE.
pub fn rethemeRetro(gpa: Allocator, dl: *raster.DrawList, w: i32, h: i32, add_client_bg: bool) error{OutOfMemory}!void {
    if (dl.len == 0 and !add_client_bg) return;
    var src = try dl.clone(gpa);
    defer src.deinit(gpa);
    dl.len = 0;

    // The grey window client area, floating on the teal desktop — a thin teal
    // frame shows around it and behind the title bar / taskbar chrome.
    if (add_client_bg) {
        const b: i32 = 3;
        try rect(gpa, dl, b, xp_title_h, w - 2 * b, h - xp_title_h - xp_task_h, retro_win, 0);
    }

    var i: usize = 0;
    while (i < src.len) : (i += 1) {
        const item = src.get(i);
        switch (item) {
            .rect => |r| {
                const rw: i32 = r.w;
                const rh: i32 = r.h;
                const a = (r.color >> 24) & 0xFF;
                // A "widget" (button/pill/card) vs a big background slab: opaque,
                // in a button/card size band, and not a full-bleed bar.
                const widget = a >= 0x80 and rw >= 26 and rh >= 14 and rh <= 200 and rw < w - 8;
                const nc = retroFill(r.color, widget);
                try rect(gpa, dl, r.x, r.y, rw, rh, nc, 0); // square corners
                if (widget and (nc & 0xFF000000) == 0xFF000000) {
                    // Raised 3-D relief: light top-left, shadow bottom-right, a
                    // deeper outer line under it — the classic beveled button.
                    try xpBevel(gpa, dl, r.x, r.y, rw, rh, true, retro_hi, retro_sh);
                    try rect(gpa, dl, r.x, r.y + rh - 1, rw, 1, retro_dk, 0);
                    try rect(gpa, dl, r.x + rw - 1, r.y, 1, rh, retro_dk, 0);
                }
            },
            .text => |t| {
                var nt = t;
                nt.color = retroInk(t.color);
                try dl.append(gpa, .{ .text = nt });
            },
            .line => |ln| {
                var nl = ln;
                nl.color = retroStroke(ln.color);
                try dl.append(gpa, .{ .line = nl });
            },
            .tri => |tr| {
                var ntr = tr;
                ntr.color = retroStroke(tr.color);
                try dl.append(gpa, .{ .tri = ntr });
            },
            .cell => try dl.append(gpa, item),
        }
    }
}

// ── LIGHT MODE ─────────────────────────────────────────────────────────────
// A real light theme, built to the rethemeRetro standard (classify EVERY draw
// item by luminance + saturation) — NOT the shallow juliaRemapText (3 named
// constants). It keeps the modern rounded styling; only the value scale flips.
const light_ink: u32 = 0xFF1B1B17; // body text / titles (near-black, warm)
const light_muted: u32 = 0xFF63605A; // handles, secondary
const light_faint: u32 = 0xFF8C887E; // tertiary
const light_card: u32 = 0xFFFFFFFF; // card/menu face — pure white, so it lifts off the canvas
const light_card_hover: u32 = 0xFFF1EFE9; // a card under the pointer — a hair grey
const light_border: u32 = 0xFFDBD8CF; // the card hairline, visible on white
const light_col: u32 = 0xF6FFFFFF; // the content column — bright white, a whisper of field through
const light_header: u32 = 0xFAFFFFFF; // sticky bars over the column — nearly solid white
const light_socket_glass: u32 = 0xFF2B2A24; // the dark socket panel, softened off pure-black on the light page
const light_socket_tray: u32 = 0xFF201E19; // the open-tray panel, likewise softened
pub const light_field_ink: u32 = 0xFF1B1B17; // the field's dark glyphs on the light canvas

/// Invert a neutral's luminance into a warm light neutral: dark card -> near-
/// white, its slightly-lighter border -> a light grey (the ordering is kept, so
/// fills and borders stay distinct). Returns 0x00RRGGBB (alpha added by caller).
fn lightNeutral(c: u32) u32 {
    const outl = std.math.clamp(1.0 - retroLuma(c), 0.0, 1.0);
    const r: u32 = @intFromFloat(std.math.clamp(outl * 255.0, 0.0, 255.0));
    const g: u32 = @intFromFloat(std.math.clamp(outl * 253.0, 0.0, 255.0));
    const b: u32 = @intFromFloat(std.math.clamp(outl * 247.0, 0.0, 255.0));
    return (r << 16) | (g << 8) | b;
}

/// Remap a FILL. The known SURFACE constants get a real light elevation — a pure
/// luma inversion would flip it (canvas ending up whiter than the cards, so they
/// recede). Cards -> white, the card outline -> a visible hairline. Saturated
/// opaque fills (avatars, like/boost, the accent button) keep their hue; every
/// other neutral inverts dark<->light with its alpha preserved (canvas slabs,
/// faint dividers/hovers become faint dark ones).
fn lightFill(c: u32) u32 {
    switch (c) {
        panel => return light_card,
        panel_hover => return light_card_hover,
        card_line => return light_border,
        veil => return light_col, // the content column reads bright white, not a dull grey
        header_veil => return light_header,
        icon_grey => return light_ink, // engagement icons (incl. the rect "more" dots) go near-black
        else => {},
    }
    const a = (c >> 24) & 0xFF;
    if (retroSat(c) > 0.32 and a >= 0x80) return c; // accent / avatar / like: keep
    return (a << 24) | lightNeutral(c);
}

/// Remap a TEXT colour: the warm inks map to the dark scale; coloured labels keep
/// their hue; any other light text goes near-black; already-dark text is kept.
/// The SOURCE ALPHA is preserved throughout — a rail label fading out on collapse
/// must stay faded, not snap back to solid (the light-mode collapse glitch).
fn lightInk(c: u32) u32 {
    const a = c & 0xFF000000;
    const rgb = c & 0x00FFFFFF;
    if (rgb == (ink & 0x00FFFFFF)) return a | (light_ink & 0x00FFFFFF);
    if (rgb == (muted & 0x00FFFFFF)) return a | (light_muted & 0x00FFFFFF);
    if (rgb == (faint & 0x00FFFFFF)) return a | (light_faint & 0x00FFFFFF);
    if (retroSat(c) > 0.35) return c; // accent-coloured label: hue + alpha kept
    if (retroLuma(c) > 0.45) return a | (light_ink & 0x00FFFFFF); // light text -> dark
    return c; // already dark (e.g. label on an accent button)
}

/// Remap a STROKE (line/tri icons): saturated strokes (the like heart) keep hue;
/// faint strokes become faint dark; light icon strokes go near-black.
fn lightStroke(c: u32) u32 {
    if (retroSat(c) > 0.32) return c;
    const a = c & 0xFF000000;
    if (retroLuma(c) > 0.45) return a | (light_ink & 0x00FFFFFF);
    return c;
}

/// Rewrite `dl` in place into the light theme. Unlike rethemeRetro this keeps
/// rounded corners and adds no window chrome — only the colours flip, item by
/// item, so nothing renders in a dark-mode colour. The field (a separate GPU
/// pass) handles its own light-mode inversion. PURE.
pub fn rethemeLight(gpa: Allocator, dl: *raster.DrawList) error{OutOfMemory}!void {
    if (dl.len == 0) return;
    var src = try dl.clone(gpa);
    defer src.deinit(gpa);
    dl.len = 0;
    // While `keep` is set (between a socket's theme_keep sentinels) items pass
    // through UNCHANGED — the socket keeps its dark identity in light mode.
    var keep = false;
    var i: usize = 0;
    while (i < src.len) : (i += 1) {
        const item = src.get(i);
        switch (item) {
            .rect => |r| {
                if (r.color == lens_socket.theme_keep_begin) {
                    keep = true; // drop the marker itself
                } else if (r.color == lens_socket.theme_keep_end) {
                    keep = false;
                } else if (keep) {
                    // Socket stays dark, but soften its near-black panel to a
                    // charcoal so it reads as a surface, not a hole, on the page.
                    const c = if (r.color == lens_socket.glass)
                        light_socket_glass
                    else if (r.color == lens_socket.tray_panel)
                        light_socket_tray
                    else
                        r.color;
                    try rect(gpa, dl, r.x, r.y, r.w, r.h, c, r.radius);
                } else try rect(gpa, dl, r.x, r.y, r.w, r.h, lightFill(r.color), r.radius);
            },
            .text => |t| {
                if (keep) {
                    try dl.append(gpa, item);
                } else {
                    var nt = t;
                    nt.color = lightInk(t.color);
                    try dl.append(gpa, .{ .text = nt });
                }
            },
            .line => |ln| {
                if (keep) {
                    try dl.append(gpa, item);
                } else {
                    var nl = ln;
                    if (ln.color == icon_grey) {
                        // Engagement icons: near-black AND a touch heavier — a thin
                        // (1px) dark stroke antialiases to grey on white, so bump it.
                        nl.color = light_ink;
                        nl.thickness +|= 1;
                    } else nl.color = lightStroke(ln.color);
                    try dl.append(gpa, .{ .line = nl });
                }
            },
            .tri => |tr| {
                if (keep) {
                    try dl.append(gpa, item);
                } else {
                    var ntr = tr;
                    ntr.color = lightStroke(tr.color);
                    try dl.append(gpa, .{ .tri = ntr });
                }
            },
            .cell => try dl.append(gpa, item),
        }
    }
}

/// Toy Box: Gravity SHATTER — the fixed EXIT box geometry (top-right corner), so
/// the drawer and the input hit-test agree. Logical px.
pub const shatter_exit_w: i32 = 88;
pub const shatter_exit_h: i32 = 38;
pub const shatter_exit_margin: i32 = 16;
pub fn shatterExitX(design_w: i32) i32 {
    return design_w - shatter_exit_w - shatter_exit_margin;
}

/// Draw the always-on-top EXIT box (top-right) — a bright accent chip that ends the
/// shatter no matter where the pile lands. Appended LAST so it rides over the debris.
pub fn shatterExitBox(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, design_w: i32, accent: u32) error{OutOfMemory}!void {
    const x = shatterExitX(design_w);
    const y = shatter_exit_margin;
    try rect(gpa, dl, x - 3, y + 4, shatter_exit_w + 6, shatter_exit_h, 0x66000000, 12); // shadow
    try rect(gpa, dl, x, y, shatter_exit_w, shatter_exit_h, (accent & 0x00FFFFFF) | 0xFF000000, 12);
    const lbl = "exit";
    const lw: i32 = @intCast(text.measure(e, .semibold, lbl, 16));
    _ = try str(gpa, dl, e, .semibold, x + @divTrunc(shatter_exit_w - lw, 2), y + 25, 0xFF17130E, 16, lbl);
}

/// Toy Box: Gravity SHATTER — thin out the big dark BACKGROUND rects (glass column,
/// card panels) so the pile isn't dominated by giant slabs: a rect bigger than
/// `drop_dim` on its long side is removed entirely, a mid-sized one is cut into
/// `square`-ish pieces, and small rects (toggles, pills) plus text/line/tri pass
/// through whole (a word/icon/toggle is an asset and stays intact). Rebuilds `dl`.
pub fn shatterCullBig(alloc: Allocator, dl: *raster.DrawList, square: i32, drop_dim: i32) error{OutOfMemory}!void {
    if (square <= 0 or dl.len == 0) return;
    var src = try dl.clone(alloc);
    defer src.deinit(alloc);
    dl.len = 0;
    var i: usize = 0;
    while (i < src.len) : (i += 1) {
        const item = src.get(i);
        switch (item) {
            .rect => |r| {
                const rw: i32 = r.w;
                const rh: i32 = r.h;
                const long = @max(rw, rh);
                if (long > drop_dim) continue; // huge background slab — cut it out
                if (long <= square * 2) { // small enough — keep whole
                    try dl.append(alloc, item);
                    continue;
                }
                var gy: i32 = 0;
                while (gy < rh) : (gy += square) {
                    var gx: i32 = 0;
                    while (gx < rw) : (gx += square) {
                        const pw = @min(square, rw - gx);
                        const ph = @min(square, rh - gy);
                        try dl.append(alloc, .{ .rect = .{
                            .x = clampI16(@as(f32, @floatFromInt(@as(i32, r.x) + gx))),
                            .y = clampI16(@as(f32, @floatFromInt(@as(i32, r.y) + gy))),
                            .w = @intCast(std.math.clamp(pw, 0, 65535)),
                            .h = @intCast(std.math.clamp(ph, 0, 65535)),
                            .color = r.color,
                            .radius = 0,
                        } });
                    }
                }
            },
            else => try dl.append(alloc, item),
        }
    }
}

/// Toy Box: Gravity SHATTER — assign a GROUP ID to each draw item so runs of
/// adjacent text (a word / label) share one id and fall together as a readable
/// unit. `gid[i]` = 0 means ungrouped (falls alone). A run is consecutive text
/// items on the same baseline with a small x-gap; a non-text item breaks the run.
/// Returns the next free group id (the caller uses it for its own groups). PURE.
pub fn shatterWordGroups(dl: *const raster.DrawList, gid: []u32) u32 {
    const n = @min(dl.len, gid.len);
    for (0..n) |i| gid[i] = 0;
    var next: u32 = 1;
    var cur: u32 = 0;
    var have_prev = false;
    var prev_x: i32 = 0;
    var prev_base: i32 = 0;
    var prev_px: i32 = 0;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        switch (dl.get(i)) {
            .text => |t| {
                const gap = @as(i32, t.x) - prev_x;
                const adjacent = have_prev and t.baseline == prev_base and gap >= 0 and gap < @as(i32, prev_px) * 3 + 6;
                if (adjacent) {
                    gid[i] = cur;
                } else {
                    cur = next;
                    next += 1;
                    gid[i] = cur;
                }
                have_prev = true;
                prev_x = @as(i32, t.x) + @divTrunc(@as(i32, t.px) * 6, 10); // rough advance
                prev_base = t.baseline;
                prev_px = t.px;
            },
            else => have_prev = false,
        }
    }
    return next;
}

/// Toy Box: Gravity SHATTER — capture each draw item's HOME top-left anchor and
/// SIZE into parallel arrays (one entry per item), so the shell can seed a physics
/// body per INDIVIDUAL element (each word/glyph, icon stroke, toggle, panel falls
/// as itself). Called once on entry — the settings page is static, so draw item i
/// is the same element every frame. PURE.
pub fn shatterCaptureHomes(dl: *const raster.DrawList, hx: []f32, hy: []f32, bw: []f32, bh: []f32) void {
    const n = @min(dl.len, hx.len);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        var ax: f32 = 0;
        var ay: f32 = 0;
        var aw: f32 = 8;
        var ah: f32 = 8;
        switch (dl.get(i)) {
            .text => |t| {
                const pf: f32 = @floatFromInt(t.px);
                ax = @floatFromInt(t.x);
                ay = @as(f32, @floatFromInt(t.baseline)) - pf; // top ≈ baseline − px
                aw = pf * 0.72;
                ah = pf;
            },
            .rect => |r| {
                ax = @floatFromInt(r.x);
                ay = @floatFromInt(r.y);
                aw = @floatFromInt(r.w);
                ah = @floatFromInt(r.h);
            },
            .line => |l| {
                ax = @floatFromInt(@min(l.x0, l.x1));
                ay = @floatFromInt(@min(l.y0, l.y1));
                aw = @floatFromInt(@abs(@as(i32, l.x1) - @as(i32, l.x0)) + @as(u32, l.thickness));
                ah = @floatFromInt(@abs(@as(i32, l.y1) - @as(i32, l.y0)) + @as(u32, l.thickness));
            },
            .tri => |t| {
                const xmin = @min(t.x0, @min(t.x1, t.x2));
                const xmax = @max(t.x0, @max(t.x1, t.x2));
                const ymin = @min(t.y0, @min(t.y1, t.y2));
                const ymax = @max(t.y0, @max(t.y1, t.y2));
                ax = @floatFromInt(xmin);
                ay = @floatFromInt(ymin);
                aw = @floatFromInt(xmax - xmin);
                ah = @floatFromInt(ymax - ymin);
            },
            .cell => |c| {
                ax = @floatFromInt(c.x);
                ay = @floatFromInt(c.y);
                aw = 10;
                ah = 14;
            },
        }
        hx[i] = ax;
        hy[i] = ay;
        bw[i] = @max(aw, 2);
        bh[i] = @max(ah, 2);
    }
}

/// Toy Box: Gravity SHATTER — translate each draw item by ITS body's displacement
/// from home (`bx[i]-hx[i]`, `by[i]-hy[i]`), a rigid move applied to every coord of
/// the item. One body per item, so each element (word, icon, toggle, panel) moves
/// as itself. Translate-only. PURE — mutates `dl` in place.
pub fn applyShatterItems(dl: *raster.DrawList, bx: []const f32, by: []const f32, hx: []const f32, hy: []const f32) void {
    var sl = dl.slice();
    const tags = sl.items(.tags);
    const data = sl.items(.data);
    const n = @min(tags.len, bx.len);
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const dx = bx[i] - hx[i];
        const dy = by[i] - hy[i];
        switch (tags[i]) {
            .text => {
                const t = &data[i].text;
                t.x = clampI16(@as(f32, @floatFromInt(t.x)) + dx);
                t.baseline = clampI16(@as(f32, @floatFromInt(t.baseline)) + dy);
            },
            .rect => {
                const r = &data[i].rect;
                r.x = clampI16(@as(f32, @floatFromInt(r.x)) + dx);
                r.y = clampI16(@as(f32, @floatFromInt(r.y)) + dy);
            },
            .line => {
                const l = &data[i].line;
                l.x0 = clampI16(@as(f32, @floatFromInt(l.x0)) + dx);
                l.x1 = clampI16(@as(f32, @floatFromInt(l.x1)) + dx);
                l.y0 = clampI16(@as(f32, @floatFromInt(l.y0)) + dy);
                l.y1 = clampI16(@as(f32, @floatFromInt(l.y1)) + dy);
            },
            .tri => {
                const t = &data[i].tri;
                t.x0 = clampI16(@as(f32, @floatFromInt(t.x0)) + dx);
                t.x1 = clampI16(@as(f32, @floatFromInt(t.x1)) + dx);
                t.x2 = clampI16(@as(f32, @floatFromInt(t.x2)) + dx);
                t.y0 = clampI16(@as(f32, @floatFromInt(t.y0)) + dy);
                t.y1 = clampI16(@as(f32, @floatFromInt(t.y1)) + dy);
                t.y2 = clampI16(@as(f32, @floatFromInt(t.y2)) + dy);
            },
            .cell => {
                const cc = &data[i].cell;
                cc.x = clampU16(@as(f32, @floatFromInt(cc.x)) + dx);
                cc.y = clampU16(@as(f32, @floatFromInt(cc.y)) + dy);
            },
        }
    }
}


/// A floating hover TOOLTIP: a rounded panel with wrapped help text, anchored
/// below-right of the pointer and clamped into `[view_x0, view_x0+view_w]`. The
/// caller decides WHEN to show it (pointer over a row that opted into a help
/// string) and appends it LAST so it overlays everything. PURE — appends to `dl`.
pub fn drawTooltip(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, px: i32, py: i32, view_x0: i32, view_w: i32, help: []const u8) error{OutOfMemory}!void {
    if (help.len == 0) return;
    const pad: i32 = 12;
    const line_h: i32 = 19;
    const font_px: u16 = 13;
    const pw: i32 = 300;
    const inner: i32 = pw - pad * 2;
    // Anchor a touch below-right of the pointer, then clamp horizontally so the
    // panel never runs off the viewport edge.
    var tx = px + 16;
    if (tx + pw > view_x0 + view_w - 8) tx = view_x0 + view_w - 8 - pw;
    if (tx < view_x0 + 8) tx = view_x0 + 8;
    const ty = py + 20;
    const first_baseline = ty + pad + 13;
    // Measure the wrapped height (draw_it = false appends nothing to dl).
    var ovf = false;
    const y_after = try wrapBodyLimited(gpa, dl, e, tx + pad, first_baseline, inner, 0, font_px, help, line_h, false, null, null, &ovf);
    const panel_h = (y_after - ty) + pad;
    // Shadow, panel fill, and a lit top edge — the app's standard raised surface.
    try rect(gpa, dl, tx, ty + 3, pw, panel_h, 0x66000000, 12);
    try rect(gpa, dl, tx, ty, pw, panel_h, 0xF61E1C16, 12);
    try rect(gpa, dl, tx, ty, pw, 1, 0x24EDEAE0, 12);
    _ = try wrapBodyLimited(gpa, dl, e, tx + pad, first_baseline, inner, 0xFFD8D4CA, font_px, help, line_h, true, null, null, &ovf);
}

/// The dropdown popover for an open CHOICE: a panel below the row listing the
/// options, the selected one checked. Each option emits a `.settings_choice_opt`
/// region carrying `choiceIndex*8 + optionIndex` so the shell can apply it.
fn drawChoicePopover(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, regions: ?*Regions, ch: *const settings_view.Choice, x: i32, y: i32, w: i32, choices: u64) error{OutOfMemory}!void {
    const ci = settings_view.choiceIndex(ch.action) orelse return;
    const sel: u8 = @intCast((choices >> @intCast(@as(u32, ci) * 3)) & 7);
    const opt_h: i32 = 38;
    const pad: i32 = 8;
    const pw: i32 = @min(w, 260);
    const px = x + w - pw; // right-aligned under the value
    const total_h = @as(i32, @intCast(ch.options.len)) * opt_h + pad * 2;
    // Shadow + panel.
    try rect(gpa, dl, px, y + 4, pw, total_h, 0x55000000, 14);
    try rect(gpa, dl, px, y + 2, pw, total_h, 0xF61E1C16, 14);
    try rect(gpa, dl, px, y + 2, pw, 1, 0x24EDEAE0, 14);
    for (ch.options, 0..) |opt, oi| {
        const oy = y + 2 + pad + @as(i32, @intCast(oi)) * opt_h;
        const on = oi == sel;
        if (on) try rect(gpa, dl, px + 6, oy, pw - 12, opt_h, 0x18EDEAE0, 9);
        _ = try str(gpa, dl, e, if (on) .semibold else .regular, px + 18, oy + 24, if (on) ink else muted, 14, opt);
        if (on) { // a check mark on the selected option (two strokes)
            const cx = px + pw - 26;
            const cy = oy + @divTrunc(opt_h, 2);
            try line(gpa, dl, cx, cy + 2, cx + 4, cy + 6, ink, 2);
            try line(gpa, dl, cx + 4, cy + 6, cx + 11, cy - 4, ink, 2);
        }
        try emitRegion(gpa, regions, px, oy, pw, opt_h, @intCast(@as(u32, ci) * 8 + @as(u32, @intCast(oi))), .settings_choice_opt);
    }
}

/// One detail-pane row, dispatched on its archetype. Info rows aren't tappable;
/// every other row emits a region — `act_sign_out` routes to the live `.sign_out`
/// handler, the rest to the inert `.settings_row` (skeleton).
fn drawSettingsRow(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, regions: ?*Regions, r: settings_view.Row, ridx: u16, x: i32, y: i32, w: i32, h: i32, accent: u32, toggles: u64, account: SettingsAccount, choices: u64) error{OutOfMemory}!void {
    const pad: i32 = 18;
    const label_y = y + @divTrunc(h, 2) + 5;
    const destructive = (r.flags & settings_view.flag_destructive) != 0;
    const label_col = if (destructive) warn else ink;
    const right = x + w - pad;
    const chev_y = y + @divTrunc(h - 18, 2);

    // Not-yet-implemented rows: dim the label, tag it "Soon", draw no control and
    // emit NO region (so they don't look clickable). Honest scaffolding.
    if ((r.flags & settings_view.flag_wip) != 0) {
        _ = try str(gpa, dl, e, .regular, x + pad, label_y, aScale(ink, 0.30), 15, r.label);
        const tag = "Soon";
        const tw: i32 = @intCast(text.measure(e, .regular, tag, 12));
        _ = try str(gpa, dl, e, .regular, right - tw, label_y, aScale(muted, 0.55), 12, tag);
        return;
    }

    // The right-hand VALUE: a wired choice shows its live selected option; account
    // info rows show the real identity; everything else the table placeholder.
    const val: []const u8 = blk: {
        if (settings_view.choiceOf(r.action)) |ch| {
            const ci = settings_view.choiceIndex(r.action).?;
            const sel: u8 = @intCast((choices >> @intCast(@as(u32, ci) * 3)) & 7);
            break :blk ch.options[@min(sel, ch.options.len - 1)];
        }
        break :blk switch (r.action) {
            settings_view.act_show_handle => if (account.handle.len > 0) account.handle else r.value,
            settings_view.act_show_did => if (account.did.len > 0) account.did else r.value,
            settings_view.act_show_pds => if (account.pds.len > 0) account.pds else r.value,
            else => r.value,
        };
    };

    if (r.kind == .action) {
        // A standalone command — centred (iOS-style), in accent or destructive red.
        const col = if (destructive) warn else accent;
        const lw: i32 = @intCast(text.measure(e, .semibold, r.label, 15));
        _ = try str(gpa, dl, e, .semibold, x + @divTrunc(w - lw, 2), label_y, col, 15, r.label);
    } else {
        _ = try str(gpa, dl, e, .regular, x + pad, label_y, label_col, 15, r.label);
    }

    switch (r.kind) {
        .disclosure => try iconChevron(gpa, dl, right - 16, chev_y, 18, faint),
        .choice => {
            const vw: i32 = @intCast(text.measure(e, .regular, val, 14));
            _ = try str(gpa, dl, e, .regular, right - 22 - vw, label_y, muted, 14, val);
            try iconChevron(gpa, dl, right - 16, chev_y, 18, faint);
        },
        .info => {
            const vw: i32 = @intCast(text.measure(e, .regular, val, 14));
            _ = try str(gpa, dl, e, .regular, right - vw, label_y, muted, 14, val);
        },
        .toggle => {
            const pw: i32 = 42;
            const ph: i32 = 24;
            const px = right - pw;
            const py = y + @divTrunc(h - ph, 2);
            // The toggle's LIVE state is the shell's runtime bit, not the table's
            // default flag (which only seeds the initial bitset).
            const on = (toggles >> @as(u6, @intCast(ridx))) & 1 != 0;
            const track: u32 = if (on) (accent & 0x00FFFFFF) | 0xFF000000 else 0x33EDEAE0;
            try rect(gpa, dl, px, py, pw, ph, track, @intCast(@divTrunc(ph, 2)));
            const knob: i32 = ph - 6;
            const kx = if (on) px + pw - knob - 3 else px + 3;
            try rect(gpa, dl, kx, py + 3, knob, knob, 0xFFF5F2EA, @intCast(@divTrunc(knob, 2)));
        },
        .slider => {
            const tw: i32 = 96;
            const tx = right - tw;
            const ty = y + @divTrunc(h, 2);
            try rect(gpa, dl, tx, ty - 1, tw, 2, 0x33EDEAE0, 1);
            try rect(gpa, dl, tx + @divTrunc(tw, 2) - 6, ty - 7, 12, 14, accent, 6);
        },
        .textfield => { // the pet name — an editable one-line box
            const fw: i32 = 156;
            const fx = right - fw;
            const fy = y + @divTrunc(h - 30, 2);
            const focused = account.pet_name_focus;
            try rect(gpa, dl, fx, fy, fw, 30, if (focused) 0x26EDEAE0 else 0x14EDEAE0, 8);
            if (focused) try rect(gpa, dl, fx, fy + 28, fw, 2, (accent & 0x00FFFFFF) | 0xFF000000, 1);
            const nm = account.pet_name;
            if (nm.len > 0) {
                _ = try str(gpa, dl, e, .regular, fx + 11, fy + 20, ink, 14, nm);
            } else if (!focused) {
                _ = try str(gpa, dl, e, .regular, fx + 11, fy + 20, faint, 14, "unnamed");
            }
            if (focused) {
                const cw2: i32 = if (nm.len > 0) @intCast(text.measure(e, .regular, nm, 14)) else 0;
                try rect(gpa, dl, fx + 11 + cw2 + 1, fy + 7, 2, 16, (accent & 0x00FFFFFF) | 0xFF000000, 1);
            }
        },
        .action => {}, // label already drawn centred above
    }

    if (r.kind != .info) {
        const kind: Action = if (r.action == settings_view.act_sign_out)
            .sign_out
        else if (settings_view.choiceOf(r.action) != null)
            .settings_choice
        else
            .settings_row;
        try emitRegion(gpa, regions, x, y, w, @intCast(@max(0, @min(32767, h))), ridx, kind);
    }
}

/// A solid (pinned) bookmark: the body as one rounded rect, the bottom notch
/// as stepped shrinking rows — filled, unmistakably "kept".
fn iconBookmarkFill(gpa: Allocator, dl: *raster.DrawList, x: i32, y: i32, s: i32, c: u32) error{OutOfMemory}!void {
    const f: f32 = @floatFromInt(s);
    const left = x + fxi(f * 0.24);
    const right = x + fxi(f * 0.76);
    const top = y + fxi(f * 0.08);
    const notch = y + fxi(f * 0.64);
    const bot = y + fxi(f * 0.92);
    try rect(gpa, dl, left, top, right - left, notch - top, c, 2);
    // The notch: rows narrowing toward the middle as they descend.
    const steps: i32 = @max(1, bot - notch);
    var k: i32 = 0;
    const half: f32 = @as(f32, @floatFromInt(right - left)) / 2.0;
    while (k < steps) : (k += 1) {
        const t = @as(f32, @floatFromInt(k)) / @as(f32, @floatFromInt(steps));
        const inset: i32 = @intFromFloat(half * t);
        if (right - inset > left + inset) try rect(gpa, dl, left + inset, notch + k, (right - inset) - (left + inset), 1, c, 0);
    }
}

/// The live-community pulse: a small filled dot, green when the zone moved
/// within the last hour.
const live_green: u32 = 0xFF6CE0B2;

/// One catalog card — a zone as a PLACE: hue tile + initial, #name, the real
/// community stats ("N posts · N people"), the last-activity line with a live
/// pulse, and the pin bookmark (filled accent = pinned; a `.zone_pin` region
/// over it, emitted after the card's `.zone_open` so the pin wins the tap).
/// Hover lifts the fill and reveals an "open →" hint. `t` fades the whole card
/// in during a tab-switch settle. PURE.
fn drawZoneCard(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, regions: ?*Regions, x: i32, y: i32, w: i32, h: i32, z: ZoneCard, idx: u16, zv: ZonesView, accent: u32, t: f32) error{OutOfMemory}!void {
    const hover = zv.hover_x >= x and zv.hover_x < x + w and zv.hover_y >= y and zv.hover_y < y + h;
    try rect(gpa, dl, x, y, w, h, fadeColor(if (hover) panel_hover else panel, t), 14);
    try rect(gpa, dl, x, y, w, 1, fadeColor(if (hover) 0x2AEDEAE0 else 0x14EDEAE0, t), 14); // lit top edge

    // Icon tile, with the tag's leading letter struck in the background ink.
    const tile: i32 = 46;
    const tlx = x + 16;
    const tly = y + @divTrunc(h - tile, 2);
    try rect(gpa, dl, tlx, tly, tile, tile, fadeColor(tilePalette(z.tag), t), 12);
    if (z.tag.len > 0) {
        var g0: u8 = z.tag[0];
        if (g0 >= 'a' and g0 <= 'z') g0 -= 32; // uppercase the initial
        const gadv: i32 = @intCast(text.advance(e, .semibold, g0, 22));
        _ = try glyph1(gpa, dl, e, .semibold, tlx + @divTrunc(tile - gadv, 2), tly + 31, fadeColor(bg, t), 22, g0);
    }

    // #name (the '#' and the tag share the ink, drawn as two runs).
    const txx = tlx + tile + 14;
    const hx = try str(gpa, dl, e, .semibold, txx, y + 34, fadeColor(ink, t), 17, "#");
    _ = try str(gpa, dl, e, .semibold, hx, y + 34, fadeColor(ink, t), 17, z.tag);

    // The community line — every number real: posts + distinct posters.
    var cb: [64]u8 = undefined;
    const stats = if (z.authors > 0)
        std.fmt.bufPrint(&cb, "{d} {s} · {d} {s}", .{ z.count, if (z.count == 1) "post" else "posts", z.authors, if (z.authors == 1) "person" else "people" }) catch "posts"
    else
        std.fmt.bufPrint(&cb, "{d} {s}", .{ z.count, if (z.count == 1) "post" else "posts" }) catch "posts";
    _ = try str(gpa, dl, e, .regular, txx, y + 56, fadeColor(muted, t), 13, stats);

    // Last-activity line, with a live pulse when the zone moved this hour.
    var ab: [40]u8 = undefined;
    const act = activityLabel(&ab, zv.now, z.last_at);
    if (act.len > 0) {
        var ax = txx;
        if (zv.now - z.last_at < 3600) {
            try rect(gpa, dl, ax, y + 69, 6, 6, fadeColor(live_green, t), 3);
            ax += 12;
        }
        _ = try str(gpa, dl, e, .regular, ax, y + 77, fadeColor(faint, t), 12, act);
    }

    // Pin bookmark (top-right): filled accent when pinned, faint outline not.
    if (z.pinned)
        try iconBookmarkFill(gpa, dl, x + w - 38, y + 14, 18, fadeColor(accent, t))
    else
        try iconBookmark(gpa, dl, x + w - 38, y + 14, 18, fadeColor(if (hover) muted else faint, t));

    // Hover hint: the doorway reads as enterable.
    if (hover) _ = try str(gpa, dl, e, .semibold, x + w - 74, y + h - 14, fadeColor(accent, t), 12, "open \xE2\x86\x92");

    try emitRegion(gpa, regions, x, y, w, @intCast(@max(0, @min(32767, h))), idx, .zone_open);
    try emitRegion(gpa, regions, x + w - 48, y + 6, 44, 36, idx, .zone_pin); // after → wins the overlap
}

/// One TRENDING row — the Twitter-style ranked entry: rank number, big #name,
/// the velocity line ("N posts today · N people"), a live pulse when moving
/// this hour. The whole row opens the zone. PURE.
fn drawTrendRow(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, regions: ?*Regions, x: i32, y: i32, w: i32, h: i32, rank: usize, z: ZoneCard, idx: u16, zv: ZonesView, accent: u32, t: f32) error{OutOfMemory}!void {
    const hover = zv.hover_x >= x and zv.hover_x < x + w and zv.hover_y >= y and zv.hover_y < y + h;
    if (hover) try rect(gpa, dl, x - 10, y, w + 20, h - 1, fadeColor(0x10EDEAE0, t), 12);

    var rb: [24]u8 = undefined;
    const rank_str = std.fmt.bufPrint(&rb, "{d}", .{rank}) catch "·";
    _ = try str(gpa, dl, e, .regular, x + 2, y + 24, fadeColor(faint, t), 13, rank_str);
    _ = try str(gpa, dl, e, .regular, x + 2 + @as(i32, @intCast(text.measure(e, .regular, rank_str, 13))) + 8, y + 24, fadeColor(faint, t), 13, "· trending");

    // The term: '#' struck in the accent, the name big beside it.
    const hx = try str(gpa, dl, e, .semibold, x, y + 52, fadeColor(accent, t), 21, "#");
    _ = try str(gpa, dl, e, .semibold, hx + 1, y + 52, fadeColor(ink, t), 21, z.tag);

    // The velocity line — the ranking, said out loud, every number real.
    var vb: [80]u8 = undefined;
    const vel = std.fmt.bufPrint(&vb, "{d} {s} today · {d} {s}", .{ z.recent, if (z.recent == 1) "post" else "posts", z.authors, if (z.authors == 1) "person" else "people" }) catch "";
    var vx = x + 2;
    if (zv.now - z.last_at < 3600) {
        try rect(gpa, dl, vx, y + 66, 6, 6, fadeColor(live_green, t), 3);
        vx += 12;
    }
    _ = try str(gpa, dl, e, .regular, vx, y + 74, fadeColor(muted, t), 13, vel);
    if (hover) _ = try str(gpa, dl, e, .semibold, x + w - 64, y + 52, fadeColor(accent, t), 13, "open \xE2\x86\x92");

    try rect(gpa, dl, x, y + h - 1, w, 1, divider, 0);
    try emitRegion(gpa, regions, x - 10, y, w + 20, @intCast(@max(0, @min(32767, h))), idx, .zone_open);
}

/// A centred hub EMPTY STATE: a large dim glyph, a title, and a hint line.
fn drawZonesEmpty(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, x0: i32, w: i32, y: i32, glyph: []const u8, title: []const u8, hint: []const u8, t: f32) error{OutOfMemory}!i32 {
    const gw: i32 = @intCast(text.measure(e, .semibold, glyph, 44));
    _ = try str(gpa, dl, e, .semibold, x0 + @divTrunc(w - gw, 2), y + 64, fadeColor(0x2EEDEAE0, t), 44, glyph);
    const tw: i32 = @intCast(text.measure(e, .semibold, title, 16));
    _ = try str(gpa, dl, e, .semibold, x0 + @divTrunc(w - tw, 2), y + 104, fadeColor(muted, t), 16, title);
    const hw: i32 = @intCast(text.measure(e, .regular, hint, 13));
    _ = try str(gpa, dl, e, .regular, x0 + @divTrunc(w - hw, 2), y + 128, fadeColor(faint, t), 13, hint);
    return y + 168;
}

/// Case-insensitive "does the tag contain the query" — the live search filter.
fn zoneMatches(tag: []const u8, query: []const u8) bool {
    if (query.len == 0) return true;
    return std.ascii.indexOfIgnoreCase(tag, query) != null;
}

/// The Zones HUB (`screen_zones_browse`) — the catalog as a real directory:
/// three LIVE sub-tabs (Browse / Pinned / Trending) under an animated accent
/// underline, a WORKING search-or-jump field (type filters live; Enter jumps
/// straight to the tag), then the tab's body — the activity-sorted card grid,
/// the viewer's pinned shelf, or the velocity-ranked trending list. Every
/// number drawn is real (tag index stats); tab switches settle in (enter_t)
/// and page entry fades in (fade). Returns total content height (scroll
/// clamp). PURE — all state arrives in `zv`.
fn drawZonesBrowse(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, m: Metrics, height: i32, scroll: i32, regions: ?*Regions, accent: u32, zv: ZonesView) error{OutOfMemory}!i32 {
    const x0 = m.lx;
    const w = m.cw;
    var y: i32 = (if (m.wide) @as(i32, 40) else 30) + scroll;

    // Title + subtitle.
    _ = try str(gpa, dl, e, .semibold, x0, y + 30, ink, 30, "Zones");
    y += 46;
    _ = try str(gpa, dl, e, .regular, x0, y, muted, 14, "places that precipitated out of tags — pin the ones you return to");
    y += 24;

    // Sub-tabs — all three LIVE, slotted by the semibold width so the label
    // doesn't shift when its weight changes with focus.
    const tabs = [_][]const u8{ "Browse", "Pinned", "Trending" };
    var slot_x: [tabs.len]i32 = undefined;
    var slot_w: [tabs.len]i32 = undefined;
    var tx: i32 = x0;
    for (tabs, 0..) |tab, ti| {
        const on = zv.tab == ti;
        const tw: i32 = @intCast(text.measure(e, .semibold, tab, 16));
        slot_x[ti] = tx;
        slot_w[ti] = tw;
        _ = try str(gpa, dl, e, if (on) .semibold else .regular, tx, y + 20, if (on) ink else muted, 16, tab);
        try emitRegion(gpa, regions, tx - 8, y - 2, tw + 16, 36, @intCast(ti), .zone_tab);
        tx += tw + 34;
    }
    // The underline GLIDES between slots: interpolate the rect at tab_t.
    {
        const tt = @max(0.0, @min(@as(f32, @floatFromInt(tabs.len - 1)), zv.tab_t));
        const ia: usize = @intFromFloat(@floor(tt));
        const ib: usize = @min(ia + 1, tabs.len - 1);
        const f = tt - @floor(tt);
        const ux: i32 = @intFromFloat(@as(f32, @floatFromInt(slot_x[ia])) * (1 - f) + @as(f32, @floatFromInt(slot_x[ib])) * f);
        const uw: i32 = @intFromFloat(@as(f32, @floatFromInt(slot_w[ia])) * (1 - f) + @as(f32, @floatFromInt(slot_w[ib])) * f);
        try rect(gpa, dl, ux, y + 30, uw, 3, accent, 1);
    }
    y += 42;
    try rect(gpa, dl, x0, y, w, 1, divider, 0);
    y += 22;

    // The search-or-jump field (Browse only — the other tabs are short lists).
    if (zv.tab == 0) {
        const sh: i32 = 48;
        if (zv.q_focus) try rect(gpa, dl, x0 - 2, y - 2, w + 4, sh + 4, (0x55 << 24) | (accent & 0x00FFFFFF), 14); // focus ring
        try rect(gpa, dl, x0, y, w, sh, skinPanel(accent), 12);
        try iconSearch(gpa, dl, x0 + 16, y + 14, 20, if (zv.q_focus) muted else faint);
        if (zv.query.len == 0 and !zv.q_focus) {
            _ = try str(gpa, dl, e, .regular, x0 + 50, y + 30, faint, 15, "Search zones, or jump straight to a tag…");
        } else {
            const qend = try str(gpa, dl, e, .regular, x0 + 50, y + 30, ink, 15, zv.query);
            if (zv.q_focus and zv.caret_on) try rect(gpa, dl, qend + 2, y + 13, 2, 22, accent, 1);
            if (zv.query.len > 0) {
                var jb: [96]u8 = undefined;
                const jump = std.fmt.bufPrint(&jb, "\xE2\x86\xB5 opens #{s}", .{zv.query}) catch "";
                const jw: i32 = @intCast(text.measure(e, .regular, jump, 12));
                _ = try str(gpa, dl, e, .regular, x0 + w - jw - 16, y + 29, faint, 12, jump);
            }
        }
        try emitRegion(gpa, regions, x0, y, w, @intCast(sh), 0, .zone_search);
        y += sh + 24;
    }

    // The tab body settles IN: rises the last few px while fading up.
    const t = @max(0.0, @min(1.0, zv.enter_t));
    y += @intFromFloat((1.0 - t) * 14.0);

    switch (zv.tab) {
        1 => { // ---- PINNED — the viewer's shelf ----
            _ = try str(gpa, dl, e, .semibold, x0, y, fadeColor(faint, t), 11, "PINNED · THE ONES YOU RETURN TO");
            y += 18;
            y = try drawZoneGrid(gpa, dl, e, m, height, regions, accent, zv, y, .pinned, t);
        },
        2 => { // ---- TRENDING — ranked by 24h velocity ----
            try rect(gpa, dl, x0, y - 6, 6, 6, live_green, 3);
            _ = try str(gpa, dl, e, .semibold, x0 + 14, y, fadeColor(faint, t), 11, "LIVE · RANKED BY 24H ACTIVITY");
            y += 24;
            const row_h: i32 = 92;
            var rank: usize = 0;
            for (zv.cards, 0..) |z, zi| {
                if (z.recent == 0) continue;
                rank += 1;
                if (y + row_h > 0 and y < height)
                    try drawTrendRow(gpa, dl, e, regions, x0, y, w, row_h, rank, z, @intCast(zi), zv, accent, t);
                y += row_h;
                if (rank >= 30) break; // the tail isn't "trending"
            }
            if (rank == 0)
                y = try drawZonesEmpty(gpa, dl, e, x0, w, y, "~", "Nothing moving yet", "when a zone stirs in the last 24h, it climbs here", t);
        },
        else => { // ---- BROWSE — the living directory ----
            _ = try str(gpa, dl, e, .semibold, x0, y, fadeColor(faint, t), 11, if (zv.query.len > 0) "ZONES · MATCHING" else "ZONES · MOST ACTIVE FIRST");
            y += 18;
            y = try drawZoneGrid(gpa, dl, e, m, height, regions, accent, zv, y, .browse, t);
        },
    }
    y += 40;
    return y - scroll;
}

/// The card GRID shared by Browse (search-filtered) and Pinned (pin-filtered):
/// two columns wide, one narrow, culled to the window (i16 draw coords), with
/// the tab-appropriate empty state. Returns the y past the grid. PURE.
fn drawZoneGrid(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, m: Metrics, height: i32, regions: ?*Regions, accent: u32, zv: ZonesView, y0: i32, which: enum { browse, pinned }, t: f32) error{OutOfMemory}!i32 {
    const x0 = m.lx;
    const w = m.cw;
    const cols: i32 = if (m.wide and w >= 640) 2 else 1;
    const col_gap: i32 = 18;
    const card_w: i32 = @divTrunc(w - col_gap * (cols - 1), cols);
    const card_h: i32 = 96;
    const row_gap: i32 = 16;
    var shown: i32 = 0;
    for (zv.cards, 0..) |z, zi| {
        const keep = switch (which) {
            .browse => zoneMatches(z.tag, zv.query),
            .pinned => z.pinned,
        };
        if (!keep) continue;
        const col = @mod(shown, cols);
        const row = @divTrunc(shown, cols);
        const cardx = x0 + col * (card_w + col_gap);
        const cardy = y0 + row * (card_h + row_gap);
        // Cull rows scrolled out of the window (i16 draw coords; long catalogs).
        if (cardy + card_h > 0 and cardy < height)
            try drawZoneCard(gpa, dl, e, regions, cardx, cardy, card_w, card_h, z, @intCast(zi), zv, accent, t);
        shown += 1;
    }
    if (shown == 0) {
        return switch (which) {
            .browse => if (zv.query.len > 0)
                try drawZonesEmpty(gpa, dl, e, x0, w, y0, "#", "No zone by that name yet", "press Enter to jump straight to the tag — you might be first", t)
            else
                try drawZonesEmpty(gpa, dl, e, x0, w, y0, "#", "No zones yet", "tag a post with #anything and a zone precipitates here", t),
            .pinned => try drawZonesEmpty(gpa, dl, e, x0, w, y0, "\xE2\x8C\x96", "Nothing pinned yet", "tap the bookmark on any zone to keep it here", t),
        };
    }
    const rows = @divTrunc(shown + cols - 1, cols);
    return y0 + rows * (card_h + row_gap);
}

/// The feed column's sticky TOP BAR: a frosted box over the top strip, then the
/// screen title (+ Following/Discover tabs on Home / mobile), then the hairline
/// divider. Emitted AFTER the posts so they pass behind it (occluded + dimmed),
/// the chrome reading crisply on top. The box spans the feed column width; the
/// rail/sidebar live in their own columns and are untouched.
fn drawTopBar(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, m: Metrics, active_screen: u8, regions: ?*Regions, profile: ?ProfileHeader, accent: u32, socket_tray: ?lens_socket.TrayView, socket_ui: lens_socket.SocketUi, socket_hits: ?*lens_socket.HitList, zone_title: []const u8, zone_count: usize, zv: ZonesView, scroll: i32) error{OutOfMemory}!void {
    if (active_screen == screen_profile) return drawProfileHeader(gpa, dl, e, m, regions, profile orelse .{ .display_name = "", .handle = "", .post_count = 0 }, accent);
    if (active_screen == screen_zones) return drawZoneHeader(gpa, dl, e, m, regions, accent, socket_tray, socket_ui, socket_hits, zone_title, zone_count, zv, scroll);
    const is_thread = active_screen == screen_thread;
    const is_home = active_screen == screen_home;
    const is_zone = active_screen == screen_zones;
    // The zone page titles by its tag ("#water"); thread is "Thread"; rail
    // screens use their nav label.
    var zbuf: [140]u8 = undefined;
    const title: []const u8 = if (is_zone)
        (std.fmt.bufPrint(&zbuf, "#{s}", .{zone_title}) catch "#zone")
    else if (active_screen < nav_labels.len) nav_labels[active_screen] else "Thread";
    // Home AND a zone page seat the lens socket → the taller header; both the
    // thread and a zone page get a Back button on the left.
    const seats_socket = is_home or is_zone;
    const wants_back = is_thread or is_zone;
    if (m.wide) {
        const box_h: i32 = if (seats_socket) home_header_h_wide else 111;
        try rect(gpa, dl, m.col_x, 0, m.col_w, box_h, skinHeaderVeil(accent), 0);
        var tx = m.lx;
        if (wants_back) {
            const bl = "<  Back";
            const blw: i32 = @intCast(text.measure(e, .semibold, bl, 15) + 26);
            try rect(gpa, dl, m.lx, 30, blw, 36, skinPanel(accent), 16);
            _ = try str(gpa, dl, e, .semibold, m.lx + 13, 53, ink, 15, bl);
            try emitRegion(gpa, regions, m.lx, 30, blw, 36, 0, .back);
            tx = m.lx + blw + 22;
        }
        _ = try str(gpa, dl, e, .semibold, tx, 50, ink, 27, title);
        // THE LENS SOCKET seats here (Home + zone page), replacing tab labels.
        if (seats_socket) if (socket_tray) |tray| {
            const geom: lens_socket.Geometry = .{ .x = m.lx, .y = socket_y_wide, .w = m.cw, .scale = 1.0 };
            _ = try lens_socket.build(gpa, e, tray, socket_ui, geom, dl, socket_hits);
        };
        try rect(gpa, dl, m.col_x, box_h - 1, m.col_w, 1, divider, 0);
    } else {
        const box_h: i32 = if (seats_socket) home_header_h_narrow else 97;
        try rect(gpa, dl, m.col_x, 0, m.col_w, box_h, skinHeaderVeil(accent), 0);
        if (wants_back) {
            const bl = "<  Back";
            const blw: i32 = @intCast(text.measure(e, .semibold, bl, 14) + 22);
            try rect(gpa, dl, m.lx, 16, blw, 32, skinPanel(accent), 15);
            _ = try str(gpa, dl, e, .semibold, m.lx + 11, 37, ink, 14, bl);
            try emitRegion(gpa, regions, m.lx, 16, blw, 32, 0, .back);
            _ = try str(gpa, dl, e, .semibold, m.lx + blw + 18, 38, ink, 18, title);
            // A zone page seats its socket below the back row; the thread does not.
            if (is_zone) if (socket_tray) |tray| {
                const geom: lens_socket.Geometry = .{ .x = m.lx, .y = socket_y_narrow, .w = m.cw, .scale = 1.0 };
                _ = try lens_socket.build(gpa, e, tray, socket_ui, geom, dl, socket_hits);
            };
            try rect(gpa, dl, m.col_x, box_h - 1, m.col_w, 1, divider, 0);
            return;
        }
        // Mobile home header: a hamburger (opens the nav drawer — tap OR the
        // swipe-right both work) at the left, the wordmark CENTERED, and a
        // search magnifier at the right.
        const ham_cy: i32 = 21;
        try rect(gpa, dl, m.lx, ham_cy - 7, 22, 2, ink, 1);
        try rect(gpa, dl, m.lx, ham_cy, 22, 2, ink, 1);
        try rect(gpa, dl, m.lx, ham_cy + 7, 22, 2, ink, 1);
        try emitRegion(gpa, regions, m.lx - 6, ham_cy - 15, 40, 38, 0, .drawer_open);
        const ww: i32 = @intCast(text.measure(e, .semibold, "Zat4.", 22));
        const wmx = m.col_x + @divTrunc(m.col_w - ww, 2);
        const wm = try str(gpa, dl, e, .semibold, wmx, 29, accent, 22, "Zat4");
        _ = try str(gpa, dl, e, .semibold, wm, 29, ink, 22, ".");
        const right_margin = m.lx - m.col_x;
        const srch_x = m.col_x + m.col_w - right_margin - 26;
        try iconSearch(gpa, dl, srch_x, 8, 26, ink);
        try emitRegion(gpa, regions, srch_x - 6, 5, 40, 38, 0, .search);
        if (is_home) if (socket_tray) |tray| {
            const geom: lens_socket.Geometry = .{ .x = m.lx, .y = socket_y_narrow, .w = m.cw, .scale = 1.0 };
            _ = try lens_socket.build(gpa, e, tray, socket_ui, geom, dl, socket_hits);
        };
        try rect(gpa, dl, m.col_x, box_h - 1, m.col_w, 1, divider, 0);
    }
}

/// Relative luminance of an RGB colour (0–255), fixed-point ~0.2126/0.7152/0.0722.
fn lumaOf(c: u32) u32 {
    const r = (c >> 16) & 0xFF;
    const g = (c >> 8) & 0xFF;
    const b = c & 0xFF;
    return (54 * r + 182 * g + 19 * b) >> 8;
}
/// Primary text colour readable over `bgcol` — near-black on a light block, the
/// house ink on a dark one — so the zone block reads at ANY hue.
fn readableOn(bgcol: u32) u32 {
    return if (lumaOf(bgcol) > 140) 0xFF1A1710 else 0xFFEDEAE0;
}
/// Secondary (dimmer) text over `bgcol` — the same hue at reduced alpha.
fn readableDim(bgcol: u32) u32 {
    return if (lumaOf(bgcol) > 140) 0xB01A1710 else 0xBFEDEAE0;
}

/// A three-dot "more" affordance — three small filled dots centred on (cx, cy).
fn menuDots(gpa: Allocator, dl: *raster.DrawList, cx: i32, cy: i32, c: u32) error{OutOfMemory}!void {
    const r: i32 = 2;
    var i: i32 = -1;
    while (i <= 1) : (i += 1) {
        try rect(gpa, dl, cx + i * 9 - r, cy - r, r * 2, r * 2, c, @intCast(r));
    }
}

/// The ZONE page MASTHEAD — the band that makes a zone read as a distinct PLACE
/// rather than the home feed with a different title: an icon tile in the zone's
/// hue, the big #name beside a "communal face" chip and a LIVE Pin toggle, a
/// description, the real community stats (posts · people · last activity), then
/// the lens socket and its "the order is yours" caption.
///
/// The masthead COLLAPSES with scroll (the thread chain-header contract):
/// scrolling in shrinks the tall band toward a thin bar — the identity block
/// slides up and fades, the socket tucks under the coloured band and fades,
/// and a compact "tile + #name · count" fades in beside Back. Everything is a
/// pure function of `scroll` (`zoneCollapseT`/`zoneHeaderH`), so returning to
/// the top restores the tall masthead PIXEL-PERFECT. Back returns to wherever
/// the zone was entered from. The face chip stays scaffold (Z4); everything
/// numeric is real. Sticky (posts scroll under it). PURE.
fn drawZoneHeader(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, m: Metrics, regions: ?*Regions, accent: u32, socket_tray: ?lens_socket.TrayView, socket_ui: lens_socket.SocketUi, socket_hits: ?*lens_socket.HitList, zone_title: []const u8, zone_count: usize, zv: ZonesView, scroll: i32) error{OutOfMemory}!void {
    // The stats line, every number real: posts, distinct people (when known),
    // and how recently the place moved.
    var actb: [40]u8 = undefined;
    const act = activityLabel(&actb, zv.now, zv.last_at);
    var statb: [160]u8 = undefined;
    var stats: []const u8 = std.fmt.bufPrint(&statb, "{d} {s}", .{ zone_count, if (zone_count == 1) "post" else "posts" }) catch "";
    if (zv.people > 0) {
        const more = std.fmt.bufPrint(statb[stats.len..], " · {d} {s}", .{ zv.people, if (zv.people == 1) "person" else "people" }) catch "";
        stats = statb[0 .. stats.len + more.len];
    }
    if (act.len > 0) {
        const more = std.fmt.bufPrint(statb[stats.len..], " · {s}", .{act}) catch "";
        stats = statb[0 .. stats.len + more.len];
    }

    // Collapse state: ct 0→1 over the first (tall−thin) px of scroll. The
    // identity block fades OUT early (fi), the thin bar fades IN late (ti) —
    // the crossover keeps the bar readable through the whole travel.
    const ct = zoneCollapseT(scroll, m.wide);
    const box_h = zoneHeaderH(scroll, m.wide);
    // The identity block is gone EARLY (by ~1/3 travel) so it never collides
    // with the fixed Back/more chrome as the band shrinks past it.
    const fi = std.math.clamp(1.0 - ct * 3.2, 0.0, 1.0);
    const ti = std.math.clamp((ct - 0.55) / 0.45, 0.0, 1.0);

    if (m.wide) {
        // The whole top BLOCK takes the zone ALGO (socket) colour; text auto-
        // contrasts (luminance) so it reads at any hue. This is separate from the
        // app accent — the home feed is untouched; the block follows the ZONE
        // socket's seated lens. Switch the zone lens → the block recolours.
        const zc: u32 = if (socket_tray) |t| lens_socket.seatedAccent(t) else accent;
        const on = readableOn(zc);
        const dim = readableDim(zc);
        // The coloured IDENTITY band shrinks 160 → the thin bar; the identity
        // content rides it (dy) while fading.
        const id_h: i32 = 160 - @as(i32, @intFromFloat(@as(f32, @floatFromInt(160 - zone_thin_h_wide)) * ct));
        // A gentle upward drift while it fades — NOT the full band shrink,
        // which would ram the block into the Back pill before it's gone.
        const dy: i32 = -@as(i32, @intFromFloat(30.0 * ct));
        const redge = m.lx + m.cw; // right edge of the CENTRED content column

        // 1) The NEUTRAL strip + the socket + its caption — drawn FIRST so the
        // coloured band covers them as they tuck under it, fading on the way
        // (the socket widget has no alpha input; fadeItems retints its range).
        // Its tap targets go dead once it starts tucking (no phantom hits).
        if (box_h > id_h) try rect(gpa, dl, m.col_x, id_h, m.col_w, box_h - id_h, skinHeaderVeil(accent), 0);
        if (ct < 0.98) if (socket_tray) |tray| {
            const sock_from = dl.len;
            const geom: lens_socket.Geometry = .{ .x = m.lx, .y = box_h - (zone_header_h_wide - zone_socket_y_wide), .w = m.cw, .scale = 1.0 };
            _ = try lens_socket.build(gpa, e, tray, socket_ui, geom, dl, if (ct < 0.35) socket_hits else null);
            _ = try str(gpa, dl, e, .regular, m.lx, box_h - 16, faint, 12, "the face is shared; the order is yours — swap in any algorithm");
            if (ct > 0.001) fadeItems(dl, sock_from, 1.0 - ct);
        };

        // 2) The coloured identity band (covers the tucking socket).
        try rect(gpa, dl, m.col_x, 0, m.col_w, id_h, zc, 0);

        // 3) The fixed chrome: Back (left) + the "more" menu (far right) —
        // both live in the thin bar too, so they never move.
        const bl = "<  Back";
        const blw: i32 = @intCast(text.measure(e, .semibold, bl, 15) + 26);
        try rect(gpa, dl, m.lx, 22, blw, 34, (0x22 << 24) | (on & 0x00FFFFFF), 16);
        _ = try str(gpa, dl, e, .semibold, m.lx + 13, 44, on, 15, bl);
        try emitRegion(gpa, regions, m.lx, 22, blw, 34, 0, .back);
        try menuDots(gpa, dl, redge - 2, 39, dim);
        try emitRegion(gpa, regions, redge - 18, 28, 36, 26, 0, .more);

        // 4) The identity block — slides up with the band and fades out.
        if (fi > 0.001) {
            const tile: i32 = 50;
            const ty: i32 = 68 + dy;
            try rect(gpa, dl, m.lx, ty, tile, tile, fadeColor(tilePalette(zone_title), fi), 13);
            if (zone_title.len > 0) {
                var g0: u8 = zone_title[0];
                if (g0 >= 'a' and g0 <= 'z') g0 -= 32;
                const gadv: i32 = @intCast(text.advance(e, .semibold, g0, 24));
                _ = try glyph1(gpa, dl, e, .semibold, m.lx + @divTrunc(tile - gadv, 2), ty + 34, fadeColor(bg, fi), 24, g0);
            }
            const nx = m.lx + tile + 16;
            const hx = try str(gpa, dl, e, .semibold, nx, ty + 24, fadeColor(on, fi), 28, "#");
            const nend = try str(gpa, dl, e, .semibold, hx, ty + 24, fadeColor(on, fi), 28, zone_title);
            const chip = "communal face";
            const cw: i32 = @intCast(text.measure(e, .regular, chip, 12));
            try rect(gpa, dl, nend + 14, ty + 8, cw + 24, 24, fadeColor((0x26 << 24) | (on & 0x00FFFFFF), fi), 12);
            _ = try str(gpa, dl, e, .regular, nend + 26, ty + 24, fadeColor(on, fi), 12, chip);

            // "+ Post" — compose INTO this zone (the tag arrives locked in the
            // composer's tag bar). Left of Pin, same visual weight.
            const pin = if (zv.pinned) "Pinned" else "Pin";
            const pw: i32 = @intCast(text.measure(e, .semibold, pin, 14) + 50);
            const px = redge - pw;
            {
                const pl = "+ Post";
                const plw: i32 = @intCast(text.measure(e, .semibold, pl, 14) + 32);
                const plx = px - plw - 10;
                try rect(gpa, dl, plx, ty + 4, plw, 40, fadeColor((0x2A << 24) | (on & 0x00FFFFFF), fi), 12);
                _ = try str(gpa, dl, e, .semibold, plx + 16, ty + 29, fadeColor(on, fi), 14, pl);
                if (ct < 0.2) try emitRegion(gpa, regions, plx, ty + 4, plw, 40, 0, .zone_compose);
            }

            // Pin — a LIVE toggle. Unpinned: a quiet translucent pill ("Pin").
            // Pinned: the reverse pill (solid contrast fill) with a filled
            // bookmark ("Pinned") — kept, unmistakably. Its tap target only
            // exists while the block is readable (no invisible toggles).
            if (zv.pinned) {
                try rect(gpa, dl, px, ty + 4, pw, 40, fadeColor(on, fi), 12);
                try iconBookmarkFill(gpa, dl, px + 16, ty + 15, 17, fadeColor(zc, fi));
                _ = try str(gpa, dl, e, .semibold, px + 40, ty + 29, fadeColor(zc, fi), 14, pin);
            } else {
                try rect(gpa, dl, px, ty + 4, pw, 40, fadeColor((0x2A << 24) | (on & 0x00FFFFFF), fi), 12);
                try iconBookmark(gpa, dl, px + 16, ty + 15, 17, fadeColor(on, fi));
                _ = try str(gpa, dl, e, .semibold, px + 40, ty + 29, fadeColor(on, fi), 14, pin);
            }
            if (ct < 0.2) try emitRegion(gpa, regions, px, ty + 4, pw, 40, 0, .zone_pin);

            // Description + the real stats line (posts · people · last activity).
            _ = try str(gpa, dl, e, .regular, m.lx, ty + 64, fadeColor(dim, fi), 14, "a place that precipitated out of the tag — ordered by your own lens");
            _ = try str(gpa, dl, e, .regular, m.lx, ty + 86, fadeColor(dim, fi), 13, stats);
        }

        // 5) The THIN BAR content — a compact tile + #name · count beside
        // Back, fading in as the tall block departs.
        if (ti > 0.001) {
            const bx = m.lx + blw + 14;
            try rect(gpa, dl, bx, 19, 26, 26, fadeColor(tilePalette(zone_title), ti), 8);
            if (zone_title.len > 0) {
                var g0: u8 = zone_title[0];
                if (g0 >= 'a' and g0 <= 'z') g0 -= 32;
                const gadv: i32 = @intCast(text.advance(e, .semibold, g0, 13));
                _ = try glyph1(gpa, dl, e, .semibold, bx + @divTrunc(26 - gadv, 2), 37, fadeColor(bg, ti), 13, g0);
            }
            const thx = try str(gpa, dl, e, .semibold, bx + 26 + 10, 41, fadeColor(on, ti), 17, "#");
            const thend = try str(gpa, dl, e, .semibold, thx, 41, fadeColor(on, ti), 17, zone_title);
            var cb2: [32]u8 = undefined;
            const short = std.fmt.bufPrint(&cb2, "· {d} {s}", .{ zone_count, if (zone_count == 1) "post" else "posts" }) catch "";
            _ = try str(gpa, dl, e, .regular, thend + 10, 40, fadeColor(dim, ti), 12, short);
        }
        try rect(gpa, dl, m.col_x, box_h - 1, m.col_w, 1, divider, 0);
    } else {
        try rect(gpa, dl, m.col_x, 0, m.col_w, box_h, skinHeaderVeil(accent), 0);
        // The socket slides up with the shrinking box and fades out (drawn
        // before the identity content; on narrow there is no covering band,
        // so the fade IS the tuck). Hits die as soon as it starts moving.
        if (ct < 0.85) if (socket_tray) |tray| {
            const sock_from = dl.len;
            const geom: lens_socket.Geometry = .{ .x = m.lx, .y = box_h - (zone_header_h_narrow - zone_socket_y_narrow), .w = m.cw, .scale = 1.0 };
            _ = try lens_socket.build(gpa, e, tray, socket_ui, geom, dl, if (ct < 0.25) socket_hits else null);
            if (ct > 0.001) fadeItems(dl, sock_from, 1.0 - ct * 1.4);
        };
        const bl = "<  Back";
        const blw: i32 = @intCast(text.measure(e, .semibold, bl, 14) + 22);
        try rect(gpa, dl, m.lx, 14, blw, 30, skinPanel(accent), 15);
        _ = try str(gpa, dl, e, .semibold, m.lx + 11, 34, ink, 14, bl);
        try emitRegion(gpa, regions, m.lx, 14, blw, 30, 0, .back);

        if (fi > 0.001) {
            const tile: i32 = 42;
            const ty: i32 = 50 - @as(i32, @intFromFloat(20.0 * ct));
            try rect(gpa, dl, m.lx, ty, tile, tile, fadeColor(tilePalette(zone_title), fi), 11);
            if (zone_title.len > 0) {
                var g0: u8 = zone_title[0];
                if (g0 >= 'a' and g0 <= 'z') g0 -= 32;
                const gadv: i32 = @intCast(text.advance(e, .semibold, g0, 20));
                _ = try glyph1(gpa, dl, e, .semibold, m.lx + @divTrunc(tile - gadv, 2), ty + 29, fadeColor(bg, fi), 20, g0);
            }
            const nx = m.lx + tile + 12;
            const hx = try str(gpa, dl, e, .semibold, nx, ty + 18, fadeColor(ink, fi), 22, "#");
            const nend = try str(gpa, dl, e, .semibold, hx, ty + 18, fadeColor(ink, fi), 22, zone_title);
            _ = try str(gpa, dl, e, .regular, nx, ty + 38, fadeColor(faint, fi), 12, stats);
            // Compact pin toggle: just the bookmark, right of the name. The
            // tap target only exists while visible.
            if (zv.pinned)
                try iconBookmarkFill(gpa, dl, nend + 14, ty + 2, 18, fadeColor(accent, fi))
            else
                try iconBookmark(gpa, dl, nend + 14, ty + 2, 18, fadeColor(faint, fi));
            if (ct < 0.2) try emitRegion(gpa, regions, nend + 6, ty - 6, 34, 34, 0, .zone_pin);
        }
        // The thin bar: #name beside Back.
        if (ti > 0.001) {
            const bx = m.lx + blw + 12;
            try rect(gpa, dl, bx, 15, 22, 22, fadeColor(tilePalette(zone_title), ti), 7);
            if (zone_title.len > 0) {
                var g0: u8 = zone_title[0];
                if (g0 >= 'a' and g0 <= 'z') g0 -= 32;
                const gadv: i32 = @intCast(text.advance(e, .semibold, g0, 11));
                _ = try glyph1(gpa, dl, e, .semibold, bx + @divTrunc(22 - gadv, 2), 31, fadeColor(bg, ti), 11, g0);
            }
            const thx = try str(gpa, dl, e, .semibold, bx + 22 + 8, 34, fadeColor(ink, ti), 16, "#");
            _ = try str(gpa, dl, e, .semibold, thx, 34, fadeColor(ink, ti), 16, zone_title);
        }
        try rect(gpa, dl, m.col_x, box_h - 1, m.col_w, 1, divider, 0);
    }
}

/// The zone page's ABOUT SIDEBAR — the community card beside the reading
/// column (the subreddit-sidebar shape): the zone's identity, its honest
/// description, the real stat rows (posts · people · last activity, with a
/// live pulse), and a full-width Pin toggle. Drawn only when the glass fits
/// reading column + rail; rides the collapsing masthead's bottom edge so it
/// rises as the reader scrolls in. Every number is real. PURE.
fn drawZoneSidebar(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, m: Metrics, regions: ?*Regions, accent: u32, zone_title: []const u8, zone_count: usize, zv: ZonesView, scroll: i32) error{OutOfMemory}!void {
    const sx = m.lx + m.cw + zone_side_gap;
    const sw = zone_side_w;
    const y0 = zoneHeaderH(scroll, true) + 18;
    const card_h: i32 = 372;
    try rect(gpa, dl, sx, y0, sw, card_h, panel, 14);
    try rect(gpa, dl, sx, y0, sw, 1, 0x14EDEAE0, 14);
    const ix = sx + 20;
    var y = y0 + 30;
    _ = try str(gpa, dl, e, .semibold, ix, y, faint, 11, "ABOUT THIS ZONE");
    y += 20;

    // Identity row: tile + #name.
    try rect(gpa, dl, ix, y, 36, 36, tilePalette(zone_title), 10);
    if (zone_title.len > 0) {
        var g0: u8 = zone_title[0];
        if (g0 >= 'a' and g0 <= 'z') g0 -= 32;
        const gadv: i32 = @intCast(text.advance(e, .semibold, g0, 17));
        _ = try glyph1(gpa, dl, e, .semibold, ix + @divTrunc(36 - gadv, 2), y + 25, bg, 17, g0);
    }
    const hx = try str(gpa, dl, e, .semibold, ix + 36 + 12, y + 24, ink, 17, "#");
    _ = try str(gpa, dl, e, .semibold, hx, y + 24, ink, 17, zone_title);
    y += 52;
    _ = try str(gpa, dl, e, .regular, ix, y, muted, 13, "a place that precipitated out of the tag");
    y += 18;
    try rect(gpa, dl, ix, y, sw - 40, 1, divider, 0);
    y += 8;

    // The stat rows — label left, the real number right.
    var vb: [40]u8 = undefined;
    const rows = [_]struct { label: []const u8, live: bool }{
        .{ .label = "posts", .live = false },
        .{ .label = "people", .live = false },
        .{ .label = "activity", .live = true },
    };
    for (rows) |row| {
        y += 26;
        _ = try str(gpa, dl, e, .regular, ix, y, faint, 13, row.label);
        var val: []const u8 = "";
        if (std.mem.eql(u8, row.label, "posts")) {
            val = std.fmt.bufPrint(&vb, "{d}", .{zone_count}) catch "";
        } else if (std.mem.eql(u8, row.label, "people")) {
            val = if (zv.people > 0) std.fmt.bufPrint(&vb, "{d}", .{zv.people}) catch "" else "—";
        } else {
            const act = activityLabel(&vb, zv.now, zv.last_at);
            val = if (act.len > 0) act else "—";
        }
        const vw: i32 = @intCast(text.measure(e, .regular, val, 13));
        var vx = sx + sw - 20 - vw;
        _ = try str(gpa, dl, e, .regular, vx, y, ink, 13, val);
        if (row.live and zv.last_at > 0 and zv.now - zv.last_at < 3600) {
            vx -= 14;
            try rect(gpa, dl, vx, y - 8, 6, 6, live_green, 3);
        }
    }
    y += 22;

    // "Post in #zone" — the community's primary action, full width.
    const bw = sw - 40;
    const bh: i32 = 40;
    {
        var plb: [80]u8 = undefined;
        const pl = std.fmt.bufPrint(&plb, "Post in #{s}", .{zone_title}) catch "Post here";
        const plw: i32 = @intCast(text.measure(e, .semibold, pl, 14));
        try rect(gpa, dl, ix, y, bw, bh, accent, 12);
        _ = try str(gpa, dl, e, .semibold, ix + @divTrunc(bw - plw, 2), y + 26, bg, 14, pl);
        try emitRegion(gpa, regions, ix, y, bw, @intCast(bh), 0, .zone_compose);
        y += bh + 12;
    }

    // The Pin toggle, full width — secondary to Post (one accent button per
    // card); pinned state reads from the FILLED accent bookmark.
    const pin_label = if (zv.pinned) "Pinned" else "Pin this zone";
    const lw: i32 = @intCast(text.measure(e, .semibold, pin_label, 14));
    const label_x = ix + @divTrunc(bw - lw, 2) + 12; // shifted right of the icon
    const icon_x = label_x - 24;
    try rect(gpa, dl, ix, y, bw, bh, skinPanel(accent), 12);
    try rect(gpa, dl, ix, y, bw, 1, 0x22EDEAE0, 12);
    if (zv.pinned) {
        try iconBookmarkFill(gpa, dl, icon_x, y + 11, 17, accent);
        _ = try str(gpa, dl, e, .semibold, label_x, y + 26, ink, 14, pin_label);
    } else {
        try iconBookmark(gpa, dl, icon_x, y + 11, 17, ink);
        _ = try str(gpa, dl, e, .semibold, label_x, y + 26, ink, 14, pin_label);
    }
    try emitRegion(gpa, regions, ix, y, bw, @intCast(bh), 0, .zone_pin);
}

/// The sticky PROFILE identity header: a compact HORIZONTAL band — avatar on the
/// left, the name on line 1 and "@handle · N posts" on line 2 to its right, an
/// Edit-profile pill far right — pinned so identity stays visible as posts scroll
/// under it (the old band was tall, vertical, and scrolled away). The natural
/// anchor for future profile-level nav (Links / Posts·Replies tabs): a row would
/// attach below the identity line, growing `profile_header_h_*`.
fn drawProfileHeader(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, m: Metrics, regions: ?*Regions, ph: ProfileHeader, accent: u32) error{OutOfMemory}!void {
    const name = if (ph.display_name.len > 0) ph.display_name else ph.handle;
    var cb: [24]u8 = undefined;
    const counts = std.fmt.bufPrint(&cb, "{d} posts", .{ph.post_count}) catch "0 posts";

    if (m.wide) {
        const band_h = profile_header_h_wide;
        try rect(gpa, dl, m.col_x, 0, m.col_w, band_h, skinHeaderVeil(accent), 0);
        const av: i32 = 56;
        const ay: i32 = 26;
        try rect(gpa, dl, m.lx, ay, av, av, tintFor(ph.handle), @intCast(av >> 1));
        const iadv: i32 = @intCast(text.advance(e, .semibold, initialOf(name), 28));
        _ = try glyph1(gpa, dl, e, .semibold, m.lx + @divTrunc(av - iadv, 2), ay + 38, bg, 28, initialOf(name));
        const tx = m.lx + av + 16;
        _ = try str(gpa, dl, e, .semibold, tx, 50, ink, 22, name);
        var bx = try str(gpa, dl, e, .regular, tx, 78, faint, 15, ph.handle);
        bx = try str(gpa, dl, e, .regular, bx + 8, 78, faint, 15, "·");
        _ = try str(gpa, dl, e, .regular, bx + 8, 78, muted, 15, counts);
        if (ph.editable) {
            const label = "Edit profile";
            const bw: i32 = @intCast(text.measure(e, .semibold, label, 14) + 28);
            const bx2 = m.lx + m.cw - bw;
            try rect(gpa, dl, bx2, 41, bw, 34, skinPanel(accent), 16);
            _ = try str(gpa, dl, e, .semibold, bx2 + 14, 63, ink, 14, label);
            try emitRegion(gpa, regions, bx2, 41, bw, 34, 0, .edit_profile);
        }
        // Profile-nav tabs row, below the identity line (Posts active).
        try drawProfileTabs(gpa, dl, e, m.lx, 116, 15, regions, accent);
        try rect(gpa, dl, m.col_x, band_h - 1, m.col_w, 1, divider, 0);
        return;
    }

    // Narrow (mobile) profile band — same idea, tighter.
    const band_h = profile_header_h_narrow;
    try rect(gpa, dl, m.col_x, 0, m.col_w, band_h, skinHeaderVeil(accent), 0);
    const av: i32 = 44;
    const ay: i32 = 14;
    try rect(gpa, dl, m.lx, ay, av, av, tintFor(ph.handle), @intCast(av >> 1));
    const iadv: i32 = @intCast(text.advance(e, .semibold, initialOf(name), 22));
    _ = try glyph1(gpa, dl, e, .semibold, m.lx + @divTrunc(av - iadv, 2), ay + 30, bg, 22, initialOf(name));
    const tx = m.lx + av + 12;
    _ = try str(gpa, dl, e, .semibold, tx, 36, ink, 18, name);
    var bx = try str(gpa, dl, e, .regular, tx, 58, faint, 13, ph.handle);
    bx = try str(gpa, dl, e, .regular, bx + 6, 58, faint, 13, "·");
    _ = try str(gpa, dl, e, .regular, bx + 6, 58, muted, 13, counts);
    if (ph.editable) {
        const label = "Edit";
        const bw: i32 = @intCast(text.measure(e, .semibold, label, 13) + 22);
        const bx2 = m.lx + m.cw - bw;
        try rect(gpa, dl, bx2, 30, bw, 30, skinPanel(accent), 14);
        _ = try str(gpa, dl, e, .semibold, bx2 + 11, 50, ink, 13, label);
        try emitRegion(gpa, regions, bx2, 30, bw, 30, 0, .edit_profile);
    }
    try drawProfileTabs(gpa, dl, e, m.lx, 100, 14, regions, accent);
    try rect(gpa, dl, m.col_x, band_h - 1, m.col_w, 1, divider, 0);
}

/// The profile-nav tab row (Posts · Replies · Media · Likes). "Posts" is active
/// (ink + an accent underline); the rest are muted. Each emits a `.profile_tab`
/// region carrying its index — visual for now, wired by a later slice (the Links
/// page attaches here too). `baseline` is the tab-label baseline.
fn drawProfileTabs(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, x0: i32, baseline: i32, px: u16, regions: ?*Regions, accent: u32) error{OutOfMemory}!void {
    var tx = x0;
    for (profile_tabs, 0..) |tab, i| {
        const on = i == 0;
        const tw: i32 = @intCast(text.measure(e, .semibold, tab, px));
        _ = try str(gpa, dl, e, .semibold, tx, baseline, if (on) ink else muted, px, tab);
        if (on) try rect(gpa, dl, tx, baseline + 8, tw, 3, accent, 2);
        try emitRegion(gpa, regions, tx - 6, baseline - @as(i32, px) - 4, tw + 12, 30, @intCast(i), .profile_tab);
        tx += tw + 30;
    }
}

fn emitRegion(gpa: Allocator, regions: ?*Regions, x: i32, y: i32, w: i32, h: u16, post: u16, kind: Action) !void {
    const rg = regions orelse return;
    try rg.append(gpa, .{ .x = @intCast(std.math.clamp(x, -32768, 32767)), .y = @intCast(std.math.clamp(y, -32768, 32767)), .w = @intCast(@max(0, @min(32767, w))), .h = h, .post = post, .kind = kind });
}

// ---------------------------------------------------------------------------
// View-model construction (B2): real timeline items → PostViews. Pure — the
// shell hands plain TimelineItems in, plain PostViews come out (B5). Strings
// are borrowed from the store for the frame; only the derived "@handle" and
// the age string are allocated, into the per-frame arena (C3). Viewer
// like/repost state lives in the store, not the item, so it defaults off
// here — the input slice that wires the buttons will thread it.
// ---------------------------------------------------------------------------

const feed = @import("feed.zig");

// ---------------------------------------------------------------------------
// THE MESSAGES PAGE (screen_messages) — Zat Chat (ZAT_CHAT_ROADMAP U2).
// Master–detail: the conversation list on the left, the open thread + a
// composer strip on the right. The surface draws its own honesty banner —
// this is dev-gated plaintext until milestone M1, and it SAYS so in pixels;
// the banner and the plaintext path come down in the same commit.
// ---------------------------------------------------------------------------

/// Per-frame chat motion (U6a). Plain values the SHELL's springs drive —
/// this layer only draws the frame they describe (one loop, one clock;
/// ANIMATION_SYSTEM_NOTES). At rest every field is its default and the
/// layout is byte-identical to the unanimated one.
pub const ChatMotion = struct {
    /// The typing indicator: 0 closed, 1 fully grown; intermediate values
    /// are the grow-in / melt-away. The thread lifts to make room as it
    /// grows, so the motion is fluid from inception to end.
    typing_t: f32 = 0,
    /// The three-dot pulse clock (seconds); only advances while visible.
    typing_phase: f32 = 0,
    /// Seconds since the last keystroke in the focused input — the caret
    /// stays lit while typing and breathes (smooth blink) once idle.
    caret_phase: f32 = 0,
    /// The thread REFLOW settle (U6b): 0 = a new bubble was just appended (the
    /// older content, bottom-anchored, has jumped UP by the new row's height),
    /// 1 = the older content has slid to rest. Older rows are drawn shifted DOWN
    /// by `slot_last * (1 - reflow_t)`, so they glide up instead of snapping.
    /// Driven by its own shell spring, independent of any one bubble's morph.
    /// Default 1 = at rest (static previews, the software path).
    reflow_t: f32 = 1,

    comptime {
        // A7.1: four f32 knobs, no padding. The per-bubble send/arrive scalars
        // moved OUT to `BubbleXform` (U6b); the thread-reflow settle stayed as
        // its own channel here.
        assert(@sizeOf(ChatMotion) == 16);
    }
};

/// PLAIN DATA (A1). One bubble's live transform for the frame — the shell's
/// per-bubble springs (`core/spring.zig`) composed into values the layout
/// applies. Handed across the core/shell boundary as a slice parallel to
/// `thread` (B5); the shell's spring indexes never cross (A5). Identity
/// (`grow = 1, rise = 0, alpha = 1`) = a seated, resting bubble.
pub const BubbleXform = struct {
    /// Scale multiplier on the bubble rect (its scale spring's position). May
    /// exceed 1 briefly — the overshoot that reads as native.
    grow: f32 = 1,
    /// Pixels BELOW the seat the bubble is drawn (its offset spring's position),
    /// settling to 0 as it rises into place.
    rise: f32 = 0,
    /// Opacity 0..1. NOT a spring (an overshooting opacity flickers): a short
    /// monotonic ramp the shell derives from the scale spring's progress.
    alpha: f32 = 1,

    comptime {
        // Three f32, no padding. One per visible in-flight bubble.
        assert(@sizeOf(BubbleXform) == 12);
    }
};

/// True when a transform is the resting identity — the bubble draws normally.
pub fn xformIsRest(x: BubbleXform) bool {
    return x.grow == 1 and x.rise == 0 and x.alpha == 1;
}

/// The caret's alpha at `phase` seconds after the last keystroke: solid
/// while typing (the first 0.55s), then a smooth ~1.1s breath — the premium
/// blink, not a hard square wave.
fn caretAlpha(phase: f32) f32 {
    if (phase < 0.55) return 1.0;
    const s = 0.5 + 0.5 * @sin((phase - 0.55) * (std.math.tau / 1.1) + std.math.pi / 2.0);
    return 0.15 + 0.85 * s * s;
}

/// `color` with its alpha byte scaled by `a` (0..1) — the fade half of the
/// motion vocabulary.
fn scaleAlpha(color: u32, a: f32) u32 {
    const al: f32 = @floatFromInt(color >> 24);
    const s: u32 = @intFromFloat(std.math.clamp(al * a, 0, 255));
    return (s << 24) | (color & 0x00FFFFFF);
}

// ---------------------------------------------------------------------------
// Payments in the thread (M5 A4): the card and the pay sheet. The card is a
// document, not a text bubble — rail tag, the amount large, the note, and a
// LIVE status line (the six-block confirmation animation when on-chain depth
// is climbing). The sheet composes a request/send: rail toggle, amount chips,
// two small inputs, three verbs. Everything here is a pure transform of the
// frame's values (B2) — the shell owns state, springs, and every side effect.
// ---------------------------------------------------------------------------

/// How the amount is ENTERED and displayed. The stored/sent value is always
/// satoshis; BTC is a decimal-entry convenience for larger numbers.
pub const PayUnit = enum(u8) { sats, btc };

/// The pay sheet's per-frame state — shell values in, pixels out.
/// A7.2: cold struct, size guard waived — one transient parameter carrier.
pub const ChatPaySheet = struct {
    open: bool = false,
    rail: chat_msg.Rail = .lightning,
    /// The amount draft — digits in sats mode, a decimal in BTC mode (the
    /// shell filters keystrokes to the unit).
    amount: []const u8 = "",
    note: []const u8 = "",
    /// 0 = the amount field owns the keyboard, 1 = the note.
    focus: u8 = 0,
    /// One short amber line ("" = none): why the last attempt refused.
    status: []const u8 = "",
    /// True while the send-confirm face is showing — the last money-hasn't-moved
    /// moment before the wallet hand-off (PAYMENT_UX_SPEC §8.2). Requests never
    /// confirm (they move no money); only sends.
    confirm: bool = false,
    /// True until the first-time irreversibility disclosure has been
    /// acknowledged this session — the confirm face shows the full warning
    /// (§8.1) the first time, then the short line after.
    first_send: bool = true,
    /// The entry unit for `amount` (sats or BTC).
    unit: PayUnit = .sats,
    /// Live USD-cents per 1 BTC for the ≈$ readout (0 = unknown → hidden). A
    /// plain price the shell refreshes off-thread; the view only formats it.
    usd_cents_per_btc: u64 = 0,
};

/// Parse the amount draft to SATOSHIS for the entry unit — the ONE place
/// amount-entry becomes a number, so the view's ≈$ and the shell's send can
/// never disagree. Sats mode: a plain integer. BTC mode: a decimal (e.g.
/// "0.0001"), truncated at 8 places. Null = empty / malformed / zero / above
/// the max supply (caught before it can overflow).
pub fn payAmountToSats(draft: []const u8, unit: PayUnit) ?u64 {
    const s = std.mem.trim(u8, draft, " ");
    if (s.len == 0) return null;
    switch (unit) {
        .sats => {
            const v = std.fmt.parseInt(u64, s, 10) catch return null;
            return if (v == 0) null else v;
        },
        .btc => {
            const dot = std.mem.indexOfScalar(u8, s, '.');
            const whole_str = if (dot) |d| s[0..d] else s;
            const frac_str = if (dot) |d| s[d + 1 ..] else "";
            for (whole_str) |c| if (c < '0' or c > '9') return null;
            for (frac_str) |c| if (c < '0' or c > '9') return null;
            const whole = std.fmt.parseInt(u64, if (whole_str.len == 0) "0" else whole_str, 10) catch return null;
            if (whole > 21_000_000) return null; // above max supply → invalid, and keeps the product in u64
            var frac: u64 = 0;
            var scale: u64 = 100_000_000;
            var i: usize = 0;
            while (i < frac_str.len and i < 8) : (i += 1) {
                scale /= 10;
                frac += @as(u64, frac_str[i] - '0') * scale;
            }
            const total = whole * 100_000_000 + frac;
            return if (total == 0) null else total;
        },
    }
}

/// Format the ≈USD value of `amount_sat` at `cents_per_btc` (0 = unknown →
/// ""). Integer math widened to u128 for the multiply — a max-supply amount
/// times a price in cents overflows u64. "$1.23" / "$1,234.50".
fn formatFiat(buf: []u8, amount_sat: u64, cents_per_btc: u64) []const u8 {
    if (cents_per_btc == 0 or amount_sat == 0) return "";
    const cents: u128 = (@as(u128, amount_sat) * cents_per_btc) / 100_000_000;
    const dollars: u64 = @intCast(cents / 100);
    const rem: u64 = @intCast(cents % 100);
    var gb: [27]u8 = undefined;
    const dg = groupSats(&gb, dollars);
    return std.fmt.bufPrint(buf, "\u{2248} ${s}.{d:0>2}", .{ dg, rem }) catch "";
}

/// Which face of the receive-setup flow is showing.
/// - `onboard`: the first-run empty state — "I have a wallet" vs "I don't yet".
/// - `paste`:   the two address fields + Save (for users who have an address).
/// - `wallets`: the "get a wallet" list for users who have none (routes out).
pub const RecvMode = enum(u8) { onboard, paste, wallets };

/// A recommended wallet for the walletless (the "I don't have one yet" path).
/// A7.2: cold const table, size guard waived — three entries, never in a loop
/// beyond the render of this one sheet.
pub const WalletRec = struct {
    name: []const u8,
    tagline: []const u8,
    /// Opened by the shell's OS-handler seam on tap (the address itself is got
    /// on the wallet's own site, then pasted back).
    url: []const u8,
};

/// The curated shortlist. Simplest-first: a custodial one-tap address, a
/// self-custodial-but-easy option, then a web wallet. Honest one-liners.
pub const recv_wallets = [_]WalletRec{
    .{ .name = "Wallet of Satoshi", .tagline = "Simplest \u{2014} you get an address instantly.", .url = "https://www.walletofsatoshi.com" },
    .{ .name = "Phoenix", .tagline = "Your own keys, still easy to use.", .url = "https://phoenix.acinq.co" },
    .{ .name = "Alby", .tagline = "Web wallet with a lightning address.", .url = "https://getalby.com" },
};

/// The "set up your CHAT receive address" sheet (the private-chat wallet — the
/// public-facing wallet is a later, separate field). Three modes (`RecvMode`):
/// the first-run onboarding empty state, the paste form, and the get-a-wallet
/// list. The shell owns the drafts and the publish; this is the plain view (B5).
pub const ChatReceiveSheet = struct {
    open: bool = false,
    /// Which face is showing (the shell picks `onboard` when you're not set up).
    mode: RecvMode = .paste,
    /// The two receive-address drafts. A Lightning address (LUD-16, like
    /// `you@wallet.com`) is the easy path; the on-chain address is optional.
    lightning: []const u8 = "",
    bitcoin: []const u8 = "",
    /// 0 = the lightning field owns the keyboard, 1 = the bitcoin field.
    focus: u8 = 0,
    /// One short line ("" = none): the specific refusal (amber) OR, after a
    /// successful publish, the green confirmation — `saved` picks the colour.
    status: []const u8 = "",
    /// True once a publish succeeded this session: the status reads as the green
    /// "you can receive" confirmation rather than an amber refusal.
    saved: bool = false,

    comptime {
        // Three slices (48) + two bools + a u8, packed into the trailing 8 = 56.
        assert(@sizeOf(ChatReceiveSheet) == 56);
    }
};

/// The sheet's amount chips (sats) — one tap fills the amount field. The
/// tap region's `post` is the index into this table.
pub const pay_chips = [4]u64{ 1_000, 5_000, 10_000, 25_000 };

/// Above this, the send-confirm shows a large-amount step-up (§8.3). Tune later.
pub const pay_large_sat: u64 = 100_000;

/// Digits grouped in thousands ("250,000") — money is read in groups.
/// 20 digits + 6 separators bounds the buffer.
fn groupSats(buf: *[27]u8, v: u64) []const u8 {
    var tmp: [20]u8 = undefined;
    const digits = std.fmt.bufPrint(&tmp, "{d}", .{v}) catch unreachable;
    var n: usize = 0;
    for (digits, 0..) |d, i| {
        if (i > 0 and (digits.len - i) % 3 == 0) {
            buf[n] = ',';
            n += 1;
        }
        buf[n] = d;
        n += 1;
    }
    return buf[0..n];
}

/// The actions a payment card offers in its current state. A card shows a
/// PRIMARY (accent) button and, in the S2 offer states, an optional SECONDARY
/// (muted) one — every action here moves no money until a wallet is opened.
/// A7.2: cold transient, size guard waived — one per card render.
const CardActions = struct { primary: ?Action = null, secondary: ?Action = null };

/// What a card offers now:
///   - counterparty's open REQUEST → **Pay**.
///   - own REQUEST, still open → **Mark received** (the payee's wallet is the
///     only place a lightning receipt shows, so the payee closes that loop
///     until the on-chain watcher (A5) automates its rail).
///   - S2 SEND offer (`pending_setup`) — recipient sees **Set up wallet** +
///     **Decline**; the offering payer sees **Cancel**.
///   - S2 `ready` (recipient set up) — the payer sees **Send** + **Cancel**;
///     the recipient just waits.
///   - own send handed to the wallet (`pending`) → **Cancel**.
fn payCardActions(mine: bool, kind: chat_msg.Kind, status: chat_msg.PayStatus) CardActions {
    if (kind == .payment_request) {
        if (!mine and status == .requested) return .{ .primary = .pay_card_pay };
        if (mine and !chat_msg.isTerminalStatus(status)) return .{ .primary = .pay_card_received };
        return .{};
    }
    // payment_sent (a send / send-offer card).
    switch (status) {
        .pending_setup => return if (mine)
            .{ .primary = .pay_card_cancel }
        else
            .{ .primary = .pay_card_setup, .secondary = .pay_card_decline },
        .ready => return if (mine)
            .{ .primary = .pay_card_send, .secondary = .pay_card_cancel }
        else
            .{}, // recipient waits for the payer to send
        .pending => return if (mine) .{ .primary = .pay_card_cancel } else .{},
        else => return .{},
    }
}

/// The label a card action wears on its button.
fn payActionLabel(act: Action) []const u8 {
    return switch (act) {
        .pay_card_pay => "Pay",
        .pay_card_cancel => "Cancel",
        .pay_card_received => "Mark received",
        .pay_card_setup => "Set up wallet",
        .pay_card_decline => "Decline",
        .pay_card_send => "Send",
        else => unreachable,
    };
}

/// The status line's words ("" = the confirming blocks draw instead).
/// Every word claims exactly what is known — `pending` means "initiated,
/// unobserved", never "sent" (§6 honesty).
const PayTone = enum { neutral, good, warn };

/// A7.2: cold transient, size guard waived — one per card render, never stored.
const PayLine = struct { head: []const u8, sub: []const u8, tone: PayTone };

/// The honest per-side status copy (PAYMENT_UX_SPEC §4). Every string is a
/// static literal — the WHO is already shown by the conversation, so we say
/// "you"/"them" and never interpolate (no per-frame allocation). The `sub` line
/// carries the trust load: whether money has moved. `confirming` has no copy
/// here — the six-block row renders it.
fn payStatusLine(status: chat_msg.PayStatus, kind: chat_msg.Kind, mine: bool) PayLine {
    const send = kind == .payment_sent;
    if (send and mine) {
        // I am paying them.
        return switch (status) {
            .pending_setup => .{ .head = "Waiting to send", .sub = "They need a wallet \u{2014} nothing sent yet", .tone = .warn },
            .ready => .{ .head = "Ready to send", .sub = "Tap Send to pay from your wallet", .tone = .neutral },
            .pending => .{ .head = "Approve in your wallet", .sub = "Nothing is sent until you approve", .tone = .neutral },
            .broadcast => .{ .head = "On its way", .sub = "0 confirmations", .tone = .neutral },
            .confirming => .{ .head = "Confirming", .sub = "", .tone = .neutral },
            .settled => .{ .head = "Sent", .sub = "", .tone = .good },
            .cancelled => .{ .head = "Cancelled", .sub = "No money moved", .tone = .neutral },
            .declined => .{ .head = "Declined", .sub = "They declined \u{2014} no money moved", .tone = .neutral },
            .expired => .{ .head = "Expired", .sub = "Offer lapsed \u{2014} no money moved", .tone = .neutral },
            .failed => .{ .head = "Didn't complete", .sub = "No money moved", .tone = .neutral },
            .requested => .{ .head = "", .sub = "", .tone = .neutral },
        };
    }
    if (send and !mine) {
        // They are paying me.
        return switch (status) {
            .pending_setup => .{ .head = "They want to pay you", .sub = "Set up a wallet to accept it", .tone = .neutral },
            .ready => .{ .head = "Ready to receive", .sub = "", .tone = .neutral },
            .pending => .{ .head = "Incoming", .sub = "They're sending it now", .tone = .neutral },
            .broadcast => .{ .head = "Incoming", .sub = "0 confirmations", .tone = .neutral },
            .confirming => .{ .head = "Confirming", .sub = "", .tone = .neutral },
            .settled => .{ .head = "Received", .sub = "", .tone = .good },
            .cancelled => .{ .head = "Cancelled", .sub = "They cancelled \u{2014} no money moved", .tone = .neutral },
            .declined => .{ .head = "Declined", .sub = "You declined", .tone = .neutral },
            .expired => .{ .head = "Expired", .sub = "This offer lapsed", .tone = .neutral },
            .failed => .{ .head = "Didn't complete", .sub = "", .tone = .neutral },
            .requested => .{ .head = "", .sub = "", .tone = .neutral },
        };
    }
    if (!send and mine) {
        // I requested; I am waiting to be paid.
        return switch (status) {
            .requested => .{ .head = "Requested", .sub = "Waiting for them to pay", .tone = .neutral },
            .pending => .{ .head = "Incoming", .sub = "They're paying now", .tone = .neutral },
            .broadcast => .{ .head = "Incoming", .sub = "0 confirmations", .tone = .neutral },
            .confirming => .{ .head = "Confirming", .sub = "", .tone = .neutral },
            .settled => .{ .head = "Received", .sub = "", .tone = .good },
            .cancelled => .{ .head = "Request cancelled", .sub = "", .tone = .neutral },
            .declined => .{ .head = "Declined", .sub = "They declined", .tone = .neutral },
            .expired => .{ .head = "Request expired", .sub = "", .tone = .neutral },
            .pending_setup, .ready, .failed => .{ .head = "Didn't complete", .sub = "", .tone = .neutral },
        };
    }
    // They requested; I am the one who can pay.
    return switch (status) {
        .requested => .{ .head = "Payment requested", .sub = "Tap Pay to send from your wallet", .tone = .neutral },
        .pending => .{ .head = "Approve in your wallet", .sub = "Nothing is sent until you approve", .tone = .neutral },
        .broadcast => .{ .head = "On its way", .sub = "0 confirmations", .tone = .neutral },
        .confirming => .{ .head = "Confirming", .sub = "", .tone = .neutral },
        .settled => .{ .head = "You paid", .sub = "", .tone = .good },
        .cancelled => .{ .head = "Request cancelled", .sub = "They withdrew it", .tone = .neutral },
        .declined => .{ .head = "Declined", .sub = "You declined", .tone = .neutral },
        .expired => .{ .head = "Request expired", .sub = "", .tone = .neutral },
        .pending_setup, .ready, .failed => .{ .head = "Didn't complete", .sub = "", .tone = .neutral },
    };
}

const pay_card_w_max: i32 = 280;

/// A card's height for the thread's measure pass — the same arithmetic the
/// draw pass walks, so the two can never disagree.
fn payCardHeight(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, b: chat_view.BubbleRow, card: chat_view.PayCard, cw2: i32) !i32 {
    var h: i32 = 12 + 16 + 30 + 38 + 10; // pads + rail tag + amount + status(head+sub)
    if (b.body.len > 0)
        h += try wrapBody(gpa, dl, e, 0, 0, cw2 - 28, 0, 13, b.body, 18, false, null) + 4;
    if (payCardActions(b.mine, b.kind, card.status).primary != null) h += 44;
    return h;
}

/// Draw one payment card at its seat. `ordinal` is the row's index in the
/// thread — what a button tap hands back to the shell (the shell re-derives
/// the payment through its own thread query; no store index crosses, A5).
fn drawPayCard(
    gpa: Allocator,
    dl: *raster.DrawList,
    e: *const text.Engine,
    regions: ?*Regions,
    accent: u32,
    bx: i32,
    by: i32,
    bw: i32,
    bh_card: i32,
    b: chat_view.BubbleRow,
    card: chat_view.PayCard,
    ordinal: u16,
) !void {
    const settled_c: u32 = 0xFF9BCE9B; // soft success green
    const warn_c: u32 = 0xFFE0A868; // amber dot
    const fill: u32 = bubbleFill(accent, b.mine);
    // Every glyph on this card takes its colour FROM the fill (the "colour
    // proof" rule) — the fill is the user's ambient accent and can be any hue
    // or lightness, so nothing is hardcoded against it.
    const bright = fillIsBright(fill);
    const text_c = onFill(fill);
    const sub_c = onFillMuted(fill);
    if (b.tail) try bubbleTail(gpa, dl, b.mine, bx, by, bw, bh_card, fill);
    try rect(gpa, dl, bx, by, bw, bh_card, fill, 14);
    if (!chat_msg.isTerminalStatus(card.status)) {
        // A live card wears a faint ring drawn from the ON-fill ink, so it
        // shows on a bright bubble as well as a dark one.
        const ring_c = (0x50 << 24) | (text_c & 0x00FFFFFF);
        try rect(gpa, dl, bx, by, bw, 1, ring_c, 0);
        try rect(gpa, dl, bx, by + bh_card - 1, bw, 1, ring_c, 0);
        try rect(gpa, dl, bx, by, 1, bh_card, ring_c, 0);
        try rect(gpa, dl, bx + bw - 1, by, 1, bh_card, ring_c, 0);
    }
    var ty = by + 12;
    _ = try str(gpa, dl, e, .semibold, bx + 14, ty + 11, sub_c, 11, if (card.rail == .lightning) "LIGHTNING" else "ON-CHAIN");
    ty += 16;
    var gb: [27]u8 = undefined;
    const amt = groupSats(&gb, card.amount_sat);
    const pen = try str(gpa, dl, e, .semibold, bx + 14, ty + 22, text_c, 22, amt);
    _ = try str(gpa, dl, e, .regular, pen + 6, ty + 22, sub_c, 13, "sats");
    ty += 30;
    if (b.body.len > 0) {
        const note_h = try wrapBody(gpa, dl, e, 0, 0, bw - 28, 0, 13, b.body, 18, false, null);
        _ = try wrapBody(gpa, dl, e, bx + 14, ty + 13, bw - 28, sub_c, 13, b.body, 18, true, null);
        ty += note_h + 4;
    }
    if (card.status == .confirming) {
        // The six-block animation: one block fills per confirmation, live
        // in the conversation — the thread IS the receipt (§4). The filled
        // block is the ON-fill ink; empty blocks a faint wash of it.
        var i: i32 = 0;
        while (i < chat_msg.settle_depth) : (i += 1) {
            const on = i < card.confirmations;
            try rect(gpa, dl, bx + 14 + i * 19, ty + 5, 14, 14, if (on) text_c else (0x28 << 24) | (text_c & 0x00FFFFFF), 4);
        }
        var cb: [8]u8 = undefined;
        const cs = std.fmt.bufPrint(&cb, "{d}/{d}", .{ card.confirmations, chat_msg.settle_depth }) catch "";
        _ = try str(gpa, dl, e, .regular, bx + 14 + 6 * 19 + 6, ty + 16, sub_c, 12, cs);
    } else {
        // The honest per-side status: a legible headline (ON-fill ink) + a
        // muted trust subline. The tone survives as a small saturated DOT
        // (green settled / amber caution) — a coloured dot reads on any fill,
        // where coloured TEXT would not.
        const pl = payStatusLine(card.status, b.kind, b.mine);
        var hx = bx + 14;
        if (pl.tone == .good or pl.tone == .warn) {
            try rect(gpa, dl, bx + 14, ty + 8, 8, 8, if (pl.tone == .good) settled_c else warn_c, 4);
            hx = bx + 28;
        }
        _ = try str(gpa, dl, e, .semibold, hx, ty + 16, text_c, 13, pl.head);
        if (pl.sub.len > 0)
            _ = try str(gpa, dl, e, .regular, bx + 14, ty + 32, sub_c, 11, pl.sub);
    }
    ty += 38;
    const acts = payCardActions(b.mine, b.kind, card.status);
    if (acts.primary) |act| {
        var ax = bx + 14;
        ax = try drawCardButton(gpa, dl, e, regions, fill, bright, ax, ty, act, ordinal);
        if (acts.secondary) |sec|
            _ = try drawCardButton(gpa, dl, e, regions, fill, bright, ax + 10, ty, sec, ordinal);
    }
}

/// One card action button, styled to CONTRAST its card fill (never accent-on-
/// accent, which vanishes on a `mine` card). An affirmative action is a solid
/// contrasting chip; a withdrawal (Cancel/Decline) is a quiet ghost. Returns
/// the x just past the button so a second one can follow.
fn drawCardButton(
    gpa: Allocator,
    dl: *raster.DrawList,
    e: *const text.Engine,
    regions: ?*Regions,
    fill: u32,
    bright: bool,
    x: i32,
    ty: i32,
    act: Action,
    ordinal: u16,
) !i32 {
    const quiet = act == .pay_card_cancel or act == .pay_card_decline;
    const label = payActionLabel(act);
    const lw: i32 = @intCast(text.measure(e, .semibold, label, 13));
    const pw = lw + 32;
    if (quiet) {
        // A ghost chip: a faint wash of the ON-fill ink, with muted text.
        const wash = (0x24 << 24) | (onFill(fill) & 0x00FFFFFF);
        try rect(gpa, dl, x, ty + 4, pw, 34, wash, 12);
        _ = try str(gpa, dl, e, .semibold, x + 16, ty + 26, onFillMuted(fill), 13, label);
    } else {
        // A solid chip that reads on the card: dark on a bright card, light
        // on a dark one, with inverted text either way.
        const chip = if (bright) @as(u32, 0xFF1A1712) else @as(u32, 0xFFF4F1EA);
        const chip_fg = if (bright) @as(u32, 0xFFF4F1EA) else @as(u32, 0xFF1A1712);
        try rect(gpa, dl, x, ty + 4, pw, 34, chip, 12);
        _ = try str(gpa, dl, e, .semibold, x + 16, ty + 26, chip_fg, 13, label);
    }
    try emitRegion(gpa, regions, x, ty + 4, pw, 34, ordinal, act);
    return x + pw;
}

/// Draw `s` truncated to `maxw`, with a trailing ellipsis when it overflows.
fn strEllipsis(gpa: Allocator, dl: *raster.DrawList, e: *const text.Engine, weight: text.Weight, x0: i32, baseline: i32, color: u32, px: u16, s: []const u8, maxw: i32) !void {
    if (@as(i32, @intCast(text.measure(e, weight, s, px))) <= maxw) {
        _ = try str(gpa, dl, e, weight, x0, baseline, color, px, s);
        return;
    }
    const ell: u32 = 0x2026; // …
    const ellw: i32 = @intCast(text.advance(e, weight, ell, px));
    var x = x0;
    var it = (std.unicode.Utf8View.init(s) catch return).iterator();
    while (it.nextCodepoint()) |cp| {
        const adv: i32 = @intCast(text.advance(e, weight, cp, px));
        if (x + adv > x0 + maxw - ellw) break;
        x = try glyph1(gpa, dl, e, weight, x, baseline, color, px, cp);
    }
    _ = try glyph1(gpa, dl, e, weight, x, baseline, color, px, ell);
}

/// The chat surface. Returns `height` plus the thread's history OVERFLOW
/// (content that doesn't fit the pane), so the shell's usual
/// `max_scroll = content_h - viewport` math yields how far back the reader
/// can scroll. The thread bottom-anchors at scroll 0 (newest visible above
/// the composer); scroll > 0 reveals older history. The chrome and the
/// conversation list do not scroll.
/// The chat list's search state (phone): the query, whether the field owns
/// the keyboard, and the caret blink. A view param — the shell filters the
/// SAME way on tap, so ordinals agree with what the user sees.
/// A7.2: cold view-param struct, waived.
pub const ChatListSearch = struct {
    q: []const u8 = "",
    focus: bool = false,
    caret_on: bool = false,
};

/// Chat body type: bubbles + the composer input. 14px read too small on the
/// phone (owner, 2026-07-11) — 16 on a 23px line is the default until the
/// settings text-size control lands.
const chat_px: u16 = 16;
const chat_line_h: i32 = 23;

pub fn layoutChat(
    gpa: Allocator,
    e: *const text.Engine,
    width: i32,
    height: i32,
    dl: *raster.DrawList,
    regions: ?*Regions,
    accent: u32,
    scroll: i32,
    /// GPU path: the rail's SDF-icon pass strikes the nav icons (same as
    /// `layout`'s / `layoutLoadout`'s flag). Software: false.
    skip_nav: bool,
    /// When true the shell renders the rail as its own tile.
    rail_external: bool,
    pane_geom: ?PaneGeom,
    /// The conversation list, in `chat_view.buildList` order. A row's tap
    /// region carries its ORDINAL — the shell maps it back through its own
    /// copy of the ordering query (no store index crosses here, A5).
    list: []const chat_view.ListRow,
    /// The open conversation's bubbles; empty with an empty `peer` = no
    /// conversation selected.
    thread: []const chat_view.BubbleRow,
    /// The thread's payment cards, addressed by `BubbleRow.pay` (M5 A4).
    cards: []const chat_view.PayCard,
    /// Ordinal (into `list`) of the selected conversation; ≥ list.len = none.
    sel: u16,
    /// Display name of the open conversation's counterparty ("" = none).
    peer: []const u8,
    /// The composer strip's draft ("" shows the placeholder). Editing state
    /// (caret, selection) arrives with the U3 wiring.
    draft: []const u8,
    /// Caret + selection + edit-bar state; `.{}` = caret at end, no
    /// selection, no bar.
    edit: ChatEdit,
    /// True while the composer owns the keyboard: the strip shows an accent
    /// ring + caret so "can I type?" is answered by the pixels (the owner's
    /// U5 field note — an input with no focus state reads as dead).
    input_focus: bool,
    /// True while the new-conversation flow is open: a recipient bar renders
    /// between the banner and the list, and it owns the keyboard.
    composing: bool,
    /// The recipient bar's draft (a handle or DID being typed).
    compose_draft: []const u8,
    /// One short line under the recipient bar ("" = none): why the last
    /// attempt didn't start — unresolvable handle, no published keys, relay
    /// down. Static shell strings; this layer just draws them.
    compose_status: []const u8,
    /// The pay sheet's state (M5 A4); `.{}` = closed.
    pay: ChatPaySheet,
    /// The frame's motion values (U6a) — shell springs in, pixels out.
    motion: ChatMotion,
    /// Per-bubble transforms (U6b), parallel to `thread`: `xforms[i]` is row
    /// `i`'s live spring transform. Empty (or shorter than `thread`) = the
    /// missing rows are at rest — the static/software path passes `&.{}`.
    xforms: []const BubbleXform,
    /// The "set up your receive address" sheet; `.{}` = closed.
    recv: ChatReceiveSheet,
    /// Safe-area insets (logical px): the phone shape shifts its headers below
    /// the status bar and lifts the composer above the home pill. Desktop: zero.
    insets: EdgeInsets,
    /// The phone list's search field state (`.{}` = absent/desktop).
    search: ChatListSearch,
) error{OutOfMemory}!i32 {
    const m: Metrics = if (pane_geom) |g|
        .{ .rail_x = g.rail_x, .col_x = g.col_x, .col_w = g.col_w, .lx = g.lx, .cw = g.cw, .side_x = g.side_x, .wide = g.wide }
    else
        metricsPage(width, screen_messages);
    if (regions) |rg| rg.clearRetainingCapacity();

    // Glass column over the field + the rail (the layoutLoadout frame).
    try rect(gpa, dl, m.col_x, 0, m.col_w, height, skinVeil(accent), 0);
    if (m.wide) {
        try rect(gpa, dl, m.col_x, 0, 1, height, 0x24EDEAE0, 0);
        try rect(gpa, dl, m.col_x + m.col_w - 1, 0, 1, height, 0x24EDEAE0, 0);
        if (!rail_external) try drawRail(gpa, dl, e, m.rail_x, height, screen_messages, regions, accent, skip_nav, 1.0);
        try drawAgpl(gpa, dl, e, m.lx, height - 40);
    }

    const x0 = m.lx;
    const w = m.cw;
    // ── THE PHONE SHAPE: single-pane (this surface must carry a standalone
    // app one day — the desktop master–detail squeezed into 430px read as
    // half-broken). No conversation open → the LIST fills the column, a
    // proper front page. A conversation open → the THREAD fills it,
    // immersive: the shell hides the tab bar; the header's back chevron or
    // the system back returns to the list. ──
    const phone = width <= phone_max;
    const phone_thread = phone and peer.len > 0;
    const top: i32 = if (phone) insets.top + 18 else if (m.wide) 40 else 30;
    const list_w: i32 = if (phone) w else std.math.clamp(@divTrunc(w * 34, 100), 220, 320);
    const split_gap: i32 = 28;
    const detail_x = if (phone) x0 else x0 + list_w + split_gap;
    const detail_w = if (phone) w else w - list_w - split_gap;
    // The split divider runs the full pane height: the two columns each own
    // their chrome now (list header left, peer header right), so the seam is
    // the page's one structural line. (Desktop only — the phone is one pane.)
    if (!phone) try rect(gpa, dl, detail_x - @divTrunc(split_gap, 2), top - 10, 1, height - top - 20, divider, 0);

    // ── Left column header: the page title, "+ New" under it, and the E2EE
    // honesty line — all fitted to the LIST column so the thread column keeps
    // its full height for messages (the owner's reorg: the old full-width
    // banner block cost the thread ~130px of chrome). ──
    if (phone_thread) {
        // The open thread owns the whole phone pane — no list chrome at all;
        // jump straight to the thread section below.
    } else if (phone) {
        // The front page: a big title with the new-conversation button as a
        // round accent-ready control at the right — the standalone-app face.
        _ = try str(gpa, dl, e, .semibold, x0, top + 36, ink, 30, "Zat Chat");
        const nb: i32 = 42;
        const nx = x0 + w - nb;
        const ny = top + 4;
        try rect(gpa, dl, nx, ny, nb, nb, if (composing) accent else skinPanel(accent), 21);
        const plw: i32 = @intCast(text.measure(e, .semibold, "+", 24));
        _ = try str(gpa, dl, e, .semibold, nx + @divTrunc(nb - plw, 2), ny + 29, if (composing) 0xFF20201A else body_c, 24, "+");
        try emitRegion(gpa, regions, nx - 6, ny - 6, nb + 12, nb + 12, 0, .chat_new);
    } else {
        _ = try str(gpa, dl, e, .semibold, x0, top + 22, ink, 24, "Zat Chat");
        const label = "+ New";
        const lw: i32 = @intCast(text.measure(e, .semibold, label, 14));
        const pill_w = lw + 28;
        const pill_h: i32 = 30;
        const py0 = top + 34;
        try rect(gpa, dl, x0, py0, pill_w, pill_h, if (composing) accent else skinPanel(accent), 15);
        _ = try str(gpa, dl, e, .semibold, x0 + 14, py0 + 20, if (composing) 0xFF20201A else body_c, 14, label);
        try emitRegion(gpa, regions, x0, py0, pill_w, @intCast(pill_h), 0, .chat_new);
    }
    // The honesty line (ZAT_CHAT_ROADMAP M1), compact: the claim itself in
    // full, the mechanism suffix ellipsized to whatever the column spares.
    // It names only what ships — content secrecy — never metadata privacy
    // against a global observer (vision §8).
    const ban_y = if (phone) top + 62 else top + 74;
    const ban_h: i32 = 22;
    if (phone_thread) {
        // No list chrome in the open thread; fall through to the thread pane.
    } else {
    try rect(gpa, dl, x0, ban_y, list_w, ban_h, skinPanel(accent), 8);
    try rect(gpa, dl, x0, ban_y, 3, ban_h, (0xC0 << 24) | (accent & 0x00FFFFFF), 1);
    const ban_pen = try str(gpa, dl, e, .semibold, x0 + 12, ban_y + 15, ink, 11, "End-to-end encrypted");
    try strEllipsis(gpa, dl, e, .regular, ban_pen + 8, ban_y + 15, muted, 11, "— MLS, post-quantum hybrid, forward secrecy", x0 + list_w - 10 - (ban_pen + 8));
    var body_y = ban_y + ban_h + 14;
    if (phone) {
        // The list SEARCH: filter conversations as you type. The render
        // matches live; the shell's tap mapping applies the same filter, so
        // the row you tap is the row you saw.
        const sh: i32 = 40;
        const ring_c = (0xC0 << 24) | (accent & 0x00FFFFFF);
        if (search.focus) try rect(gpa, dl, x0 - 1, body_y - 1, w + 2, sh + 2, ring_c, 21);
        try rect(gpa, dl, x0, body_y, w, sh, skinPanel(accent), 20);
        var pen_x = x0 + 18;
        if (search.q.len > 0) {
            pen_x = try str(gpa, dl, e, .regular, pen_x, body_y + 26, ink, 14, search.q);
        } else {
            _ = try str(gpa, dl, e, .regular, pen_x, body_y + 26, faint, 14, "Search");
        }
        if (search.focus and search.caret_on)
            try rect(gpa, dl, pen_x + 2, body_y + 11, 2, sh - 22, (0xE0 << 24) | (accent & 0x00FFFFFF), 0);
        try emitRegion(gpa, regions, x0, body_y, w, @intCast(sh), 0, .chat_search);
        body_y += sh + 12;
    }

    // The recipient bar (new-conversation flow), list-width: an input for a
    // handle or DID with the composer strip's focus vocabulary (ring + caret),
    // and a hint / refusal line under it. It pushes the list down, never the
    // thread — the thread column doesn't care.
    if (composing) {
        const bar_h: i32 = 40;
        try rect(gpa, dl, x0, body_y, list_w, bar_h, skinPanel(accent), 12);
        const ring_c = (0xC0 << 24) | (accent & 0x00FFFFFF);
        try rect(gpa, dl, x0, body_y, list_w, 1, ring_c, 0);
        try rect(gpa, dl, x0, body_y + bar_h - 1, list_w, 1, ring_c, 0);
        try rect(gpa, dl, x0, body_y, 1, bar_h, ring_c, 0);
        try rect(gpa, dl, x0 + list_w - 1, body_y, 1, bar_h, ring_c, 0);
        const lab_pen = try str(gpa, dl, e, .semibold, x0 + 12, body_y + 26, muted, 14, "To:");
        if (compose_draft.len > 0) {
            try strEllipsis(gpa, dl, e, .regular, lab_pen + 8, body_y + 26, ink, 14, compose_draft, x0 + list_w - 12 - (lab_pen + 8));
        } else {
            _ = try str(gpa, dl, e, .regular, lab_pen + 8, body_y + 26, faint, 14, "handle or did:…");
        }
        const draft_w: i32 = @intCast(text.measure(e, .regular, compose_draft, 14));
        const bar_caret_x = lab_pen + 8 + @min(draft_w, x0 + list_w - 12 - (lab_pen + 8)) + 1;
        try rect(gpa, dl, bar_caret_x, body_y + 11, 2, bar_h - 22, scaleAlpha((0xE0 << 24) | (accent & 0x00FFFFFF), caretAlpha(motion.caret_phase)), 0);
        try emitRegion(gpa, regions, x0, body_y, list_w, @intCast(bar_h), 0, .chat_compose_input);
        body_y += bar_h + 8;
        if (compose_status.len > 0) {
            try strEllipsis(gpa, dl, e, .regular, x0 + 2, body_y + 10, 0xFFE0A868, 12, compose_status, list_w - 4);
        } else {
            _ = try str(gpa, dl, e, .regular, x0 + 2, body_y + 10, faint, 12, "Enter to start · Esc to cancel");
        }
        body_y += 24;
    }

    // ── Left: the conversation list (avatar + name + preview / age + unread).
    // Phone rows breathe: taller, bigger avatar, a hairline between rows. ──
    const row_h: i32 = if (phone) 78 else 64;
    var ly = body_y;
    if (list.len == 0) {
        _ = try str(gpa, dl, e, .regular, x0, body_y + 24, faint, 14, "No conversations yet");
    }
    for (list, 0..) |row, i| {
        const on = !phone and i == sel; // no persistent selection wash on phone
        if (on) try rect(gpa, dl, x0, ly, list_w, row_h - 6, (0x1F << 24) | (accent & 0x00FFFFFF), 12);
        const av: i32 = if (phone) 50 else 40;
        const av_y = ly + @divTrunc(row_h - 6 - av, 2);
        try rect(gpa, dl, x0 + 10, av_y, av, av, tintFor(row.name), @intCast(@divTrunc(av, 2)));
        const ini = [1]u8{initialOf(row.name)};
        const ini_px: u16 = if (phone) 21 else 18;
        const iw: i32 = @intCast(text.measure(e, .semibold, &ini, ini_px));
        _ = try str(gpa, dl, e, .semibold, x0 + 10 + @divTrunc(av - iw, 2), av_y + @divTrunc(av, 2) + 7, 0xFF20201A, ini_px, &ini);
        const right = x0 + list_w - 12;
        if (row.age.len > 0) {
            const aw: i32 = @intCast(text.measure(e, .regular, row.age, 12));
            _ = try str(gpa, dl, e, .regular, right - aw, ly + @as(i32, if (phone) 30 else 26), faint, 12, row.age);
        }
        if (row.unread > 0) {
            var nbuf: [8]u8 = undefined;
            const ns = std.fmt.bufPrint(&nbuf, "{d}", .{@min(row.unread, 99)}) catch "99";
            const nw: i32 = @intCast(text.measure(e, .semibold, ns, 12));
            const pw = nw + 14;
            try rect(gpa, dl, right - pw, ly + @as(i32, if (phone) 40 else 34), pw, 20, accent, 10);
            _ = try str(gpa, dl, e, .semibold, right - pw + 7, ly + @as(i32, if (phone) 54 else 48), 0xFF20201A, 12, ns);
        }
        const tx = x0 + 10 + av + 14;
        const tw = right - 46 - tx; // clear of the age column
        try strEllipsis(gpa, dl, e, .semibold, tx, ly + @as(i32, if (phone) 30 else 26), if (on) ink else body_c, @as(u16, if (phone) 16 else 15), row.name, tw);
        if (row.preview.len > 0) {
            // Unread conversations keep their preview bright (the classic cue).
            const pw: text.Weight = if (row.unread > 0) .semibold else .regular;
            const pc: u32 = if (row.unread > 0) body_c else muted;
            try strEllipsis(gpa, dl, e, pw, tx, ly + @as(i32, if (phone) 54 else 48), pc, @as(u16, if (phone) 14 else 13), row.preview, tw);
        }
        if (phone and i + 1 < list.len) try rect(gpa, dl, tx, ly + row_h - 7, right - tx, 1, divider, 0);
        try emitRegion(gpa, regions, x0, ly, list_w, @intCast(row_h - 6), @intCast(i), .chat_conv);
        ly += row_h;
    }
    } // (phone_thread skips the whole list block)

    // ── Right: the open thread + the composer strip. The peer header sits at
    // the very TOP of the column and costs ~50px — everything under it is
    // messages (the owner's reorg: this column is only the conversation). ──
    if (peer.len == 0) {
        if (!phone) _ = try str(gpa, dl, e, .regular, detail_x + 20, top + 26, faint, 15, "Select a conversation");
        return height; // phone: the list IS the page
    }
    const thread_top = if (phone) insets.top + 64 else top + 52;
    // The composer GROWS DOWNWARD as the draft wraps (hard word-break
    // included), so a long message builds lines inside the pane instead of
    // running off it; the thread above yields the space. Enter sends,
    // Shift+Enter breaks the line ('\n' in the draft is a real line).
    const send_w: i32 = if (phone) 46 else 84; // phone: a round send button
    // The pay button (M5 A4) sits left of the input; the input yields it room.
    const pay_btn: i32 = if (phone) 46 else 40;
    const input_x = detail_x + pay_btn + 8;
    const input_w = detail_w - send_w - 12 - pay_btn - 8;
    const input_line_h: i32 = chat_line_h;
    const draft_h: i32 = if (draft.len == 0)
        input_line_h
    else
        try wrapBody(gpa, dl, e, 0, input_line_h, input_w - 28, 0, chat_px, draft, input_line_h, false, null) - input_line_h;
    const comp_h: i32 = @max(46, draft_h + 26);
    const comp_y = if (phone) height - comp_h - insets.bottom - 12 else height - comp_h - 24;
    // The typing indicator claims space between the thread and the composer
    // as it grows (typing_t 0→1) — the bubbles above LIFT with it, so the
    // grow-in / melt-away is fluid, not a pop over the thread.
    const typing_open = std.math.clamp(motion.typing_t, 0.0, 1.0);
    const typing_room: i32 = @intFromFloat(@round(46.0 * typing_open));
    const thread_bot = comp_y - 12 - typing_room;

    // Bubble geometry: measure pass (draw_it = false), then a bottom-anchored
    // draw pass. Text is chat_px on a chat_line_h line; a bubble is its
    // wrapped text plus padding; a stamp is a centred relative-time divider.
    const bub_max: i32 = @min(420, detail_w - 90);
    const line_h: i32 = chat_line_h;
    const pad_x: i32 = 14;
    const pad_y: i32 = 10;
    const stamp_h: i32 = 26;
    const gap: i32 = 8;
    const bh = try gpa.alloc(i32, thread.len);
    defer gpa.free(bh);
    var total: i32 = 0;
    for (thread, bh) |b, *hslot| {
        if (b.kind == .system) {
            hslot.* = 24;
        } else if (b.pay != chat_view.no_pay and b.pay < cards.len) {
            hslot.* = try payCardHeight(gpa, dl, e, b, cards[b.pay], @min(pay_card_w_max, bub_max));
        } else {
            const text_h = try wrapBody(gpa, dl, e, 0, 0, bub_max - 2 * pad_x, 0, chat_px, b.body, line_h, false, null);
            hslot.* = text_h + 2 * pad_y - 4;
        }
        total += hslot.* + gap;
        if (b.stamp) total += stamp_h;
    }

    // Bottom-anchor; scroll > 0 walks back into history. Rows fully outside
    // the pane are skipped (the shell clamps scroll to the returned overflow,
    // U3); partially-clipped edge rows are accepted.
    //
    // U6a — the newest bubble may be IN FLIGHT, and the whole thread rides
    // the same spring with it (one motion, one clock — never a one-frame
    // snap): while it flies, every OLDER row is drawn shifted DOWN by the
    // newest slot's height, sliding up to seat as t → 1; the accumulator
    // stays in destination coordinates, so t = 1 is byte-identical to the
    // resting layout. The newest bubble itself: an own message springs up
    // out of the composer (unclamped t — the overshoot carries it a breath
    // past its seat, then it settles), growing from 82% and fading in; a
    // counterparty message rises ~20px, growing from 92% and fading in.
    // U6b — per-bubble springs. Each row may carry its own live transform
    // (`xforms[i]`: grow/rise/alpha), so several bubbles can animate at once
    // with independent momentum — the interruptibility a single scalar could
    // not express. Separately, the whole thread REFLOWS when a new row is
    // appended: bottom-anchored, the older content jumps UP by the new row's
    // height, then slides back down to rest as `reflow_t` 0 → 1. That shift is
    // applied to every RESTING row (the animating ones ride their own `rise`).
    const reflow_t = std.math.clamp(motion.reflow_t, 0.0, 1.0);
    const reflowing = reflow_t < 0.999;
    var shift: i32 = 0;
    if (reflowing and thread.len > 0) {
        var slot_last = bh[thread.len - 1] + gap;
        if (thread[thread.len - 1].stamp) slot_last += stamp_h;
        shift = @intFromFloat(@round(@as(f32, @floatFromInt(slot_last)) * (1.0 - reflow_t)));
    }
    // A row is "in flight" when it carries a non-rest transform.
    const rowXform = struct {
        fn get(xf: []const BubbleXform, i: usize) BubbleXform {
            return if (i < xf.len) xf[i] else .{};
        }
    }.get;
    // Bottom-anchor ALWAYS. Once history outgrows the pane,
    // `thread_bot - total` goes above thread_top and the oldest rows
    // top-clip — that is correct. The old `@max(thread_top, …)` clamp
    // silently TOP-anchored an overflowing thread instead, hiding the
    // NEWEST messages below the composer (the owner's field bug: sends
    // showed in the list preview but not in the thread).
    var y = thread_bot - total + scroll;
    for (thread, bh, 0..) |b, hh, idx| {
        const xf = rowXform(xforms, idx);
        // A row is "in flight" when it carries a non-rest transform (its own
        // scale/rise/alpha springs are still running). Resting rows ride the
        // thread reflow shift; flying rows position by their own `rise`.
        const is_fly = !xformIsRest(xf);
        const row_shift: i32 = if (!is_fly) shift else 0;
        const clip_bot = if (reflowing or is_fly) comp_y else thread_bot;
        if (b.stamp) {
            const sy = y + row_shift;
            if (sy + stamp_h > thread_top and sy < clip_bot) {
                const aw: i32 = @intCast(text.measure(e, .regular, b.age, 11));
                // A flying row's divider fades in with its bubble.
                const sc = if (is_fly) scaleAlpha(faint, xf.alpha) else faint;
                _ = try str(gpa, dl, e, .regular, detail_x + @divTrunc(detail_w - aw, 2), sy + 16, sc, 11, b.age);
            }
            y += stamp_h;
        }
        const by = y + row_shift;
        if (by + hh > thread_top and by < clip_bot) {
            if (b.kind == .system) {
                const sw2: i32 = @intCast(text.measure(e, .regular, b.body, 12));
                _ = try str(gpa, dl, e, .regular, detail_x + @divTrunc(detail_w - sw2, 2), by + 16, faint, 12, b.body);
            } else if (b.pay != chat_view.no_pay and b.pay < cards.len) {
                // A payment card draws at its seat even when it is the
                // newest row mid-flight — the thread still slides as one; a
                // card is a document, not a chat pop (motion polish can
                // revisit under judgment).
                const cw2 = @min(pay_card_w_max, bub_max);
                const cbx = if (b.mine) detail_x + detail_w - cw2 else detail_x;
                try drawPayCard(gpa, dl, e, regions, accent, cbx, by, cw2, hh, b, cards[b.pay], @intCast(@min(idx, std.math.maxInt(u16))));
            } else {
                // Single-line bubbles shrink-wrap; wrapped ones take the max.
                const one_w: i32 = @intCast(text.measure(e, .regular, b.body, chat_px));
                const fits_one = std.mem.indexOfScalar(u8, b.body, '\n') == null and one_w <= bub_max - 2 * pad_x;
                const bw = if (fits_one) one_w + 2 * pad_x else bub_max;
                const bx = if (b.mine) detail_x + detail_w - bw else detail_x;
                const fill: u32 = bubbleFill(accent, b.mine);
                const bub_rad: u8 = if (phone) 17 else 14; // rounder on phone
                if (!is_fly) {
                    if (b.tail) try bubbleTail(gpa, dl, b.mine, bx, by, bw, hh, fill);
                    try rect(gpa, dl, bx, by, bw, hh, fill, bub_rad);
                    _ = try wrapBody(gpa, dl, e, bx + pad_x, by + pad_y + 14, bub_max - 2 * pad_x, ink, chat_px, b.body, line_h, true, null);
                } else {
                    // THE MORPH. Spring physics, not easing: rise and scale
                    // ride the SAME spring (unclamped t — a gentle ~2%
                    // overshoot that settles reads as native). The motion
                    // is VERTICAL only — a rise from just below the seat
                    // (the composer / typing-indicator slot is right
                    // there); a cross-pane sweep read wrong. The rect (and
                    // its tail) does the scaling, TIGHT (86%+), anchored at
                    // the sender-side bottom corner; the text stays at its
                    // final size and position — the renderer rasterizes
                    // text at integer px, so continuous glyph scaling
                    // STEPS between sizes (the chop). Opacity ramps faster
                    // than the transform: the shell already shaped `alpha` so
                    // the bubble is solid while it is still settling.
                    const fade = xf.alpha;
                    const grow = xf.grow;
                    const seat_bot: f32 = @floatFromInt(y + hh);
                    const bot_a = seat_bot + xf.rise;
                    const bw_a: i32 = @intFromFloat(@round(@as(f32, @floatFromInt(bw)) * grow));
                    const hh_a: i32 = @intFromFloat(@round(@as(f32, @floatFromInt(hh)) * grow));
                    const bx_a = if (b.mine) bx + (bw - bw_a) else bx;
                    const by_a = @as(i32, @intFromFloat(@round(bot_a))) - hh_a;
                    const fill_a = scaleAlpha(fill, fade);
                    if (b.tail) try bubbleTail(gpa, dl, b.mine, bx_a, by_a, bw_a, hh_a, fill_a);
                    try rect(gpa, dl, bx_a, by_a, bw_a, hh_a, fill_a, bub_rad);
                    _ = try wrapBody(gpa, dl, e, bx + pad_x, by_a + pad_y + 14, bub_max - 2 * pad_x, scaleAlpha(ink, fade), chat_px, b.body, line_h, true, null);
                }
            }
        }
        y += hh + gap;
    }
    if (thread.len == 0) {
        if (phone) {
            // Centred, calm, and the trust line where a first message begins.
            const l1 = "End-to-end encrypted";
            const w1: i32 = @intCast(text.measure(e, .semibold, l1, 12));
            _ = try str(gpa, dl, e, .semibold, detail_x + @divTrunc(detail_w - w1, 2), thread_top + 34, faint, 12, l1);
            const l2 = "No messages yet \u{2014} say hello";
            const w2: i32 = @intCast(text.measure(e, .regular, l2, 14));
            _ = try str(gpa, dl, e, .regular, detail_x + @divTrunc(detail_w - w2, 2), thread_top + 58, muted, 14, l2);
        } else {
            _ = try str(gpa, dl, e, .regular, detail_x, thread_top + 20, faint, 14, "No messages yet — say hello");
        }
    }

    // The typing indicator (U6a): a counterparty-side bubble that grows in
    // from the composer edge, pulses three dots while open, and melts away —
    // every stage is the same draw at a different typing_t/phase (a pure
    // transform of the frame's values; the SIGNAL is the shell's concern).
    if (typing_open > 0.01) {
        // The bubble's own scale rides the UNCLAMPED spring a little, so the
        // grow-in pops a breath past full size and settles (the thread's
        // lift above stays clamped — layout never overshoots).
        const tt = std.math.clamp(motion.typing_t, 0.0, 1.12);
        const th: i32 = @intFromFloat(@round(34.0 * tt));
        const tw: i32 = @intFromFloat(@round(64.0 * (0.55 + 0.45 * tt)));
        const ty = comp_y - 12 - th;
        // The indicator is a received-side bubble: it wears the tail too —
        // and the arriving message grows out of this same slot, so the
        // handoff reads as the dots becoming the message.
        try bubbleTail(gpa, dl, false, detail_x, ty, tw, th, scaleAlpha(skinPanel(accent), typing_open));
        try rect(gpa, dl, detail_x, ty, tw, th, scaleAlpha(skinPanel(accent), typing_open), 14);
        if (typing_open > 0.55) {
            const dot_a = (typing_open - 0.55) / 0.45; // dots arrive after the bubble
            var di: i32 = 0;
            while (di < 3) : (di += 1) {
                const phase = motion.typing_phase * 5.0 - @as(f32, @floatFromInt(di)) * 0.9;
                const pulse = 0.30 + 0.70 * (0.5 + 0.5 * @sin(phase));
                const dsz: i32 = 7;
                const dx = detail_x + @divTrunc(tw, 2) + (di - 1) * 15 - @divTrunc(dsz, 2);
                const dy = ty + @divTrunc(th, 2) - @divTrunc(dsz, 2) - @as(i32, @intFromFloat(@round(2.0 * (pulse - 0.5))));
                try rect(gpa, dl, dx, dy, dsz, dsz, scaleAlpha(muted, dot_a * pulse), 3);
            }
        }
    }

    // The sticky peer header: a near-opaque strip over the detail column's
    // top, drawn AFTER the thread so a scrolled bubble slides beneath it and
    // ghosts faintly through — the feed's header_veil pattern — then the
    // peer name + divider on top.
    if (phone) {
        // The thread app-bar: OPAQUE under the status bar (nothing ghosts
        // through chrome), a back chevron at the left, the avatar + peer name
        // centred — the standalone-app face.
        try rect(gpa, dl, m.col_x, 0, m.col_w, thread_top, bg, 0);
        try rect(gpa, dl, m.col_x, 0, m.col_w, thread_top, skinHeaderVeil(accent), 0);
        try rect(gpa, dl, m.col_x, thread_top - 1, m.col_w, 1, divider, 0);
        const bar_cy = insets.top + 32;
        _ = try str(gpa, dl, e, .semibold, x0 + 2, bar_cy + 10, ink, 27, "\u{2039}");
        try emitRegion(gpa, regions, x0 - 12, bar_cy - 22, 60, 52, 0, .back);
        const pav: i32 = 30;
        const pnw: i32 = @intCast(text.measure(e, .semibold, peer, 16));
        const block_w = pav + 10 + @min(pnw, w - 140);
        const bx0 = x0 + @divTrunc(w - block_w, 2);
        try rect(gpa, dl, bx0, bar_cy - @divTrunc(pav, 2) - 3, pav, pav, tintFor(peer), @intCast(@divTrunc(pav, 2)));
        const pini = [1]u8{initialOf(peer)};
        const piw: i32 = @intCast(text.measure(e, .semibold, &pini, 14));
        _ = try str(gpa, dl, e, .semibold, bx0 + @divTrunc(pav - piw, 2), bar_cy + 8, 0xFF20201A, 14, &pini);
        try strEllipsis(gpa, dl, e, .semibold, bx0 + pav + 10, bar_cy + 8, ink, 16, peer, w - 140);
    } else {
        const hdr_x = detail_x - @divTrunc(split_gap, 2) + 1;
        try rect(gpa, dl, hdr_x, 0, x0 + w - hdr_x, thread_top, skinHeaderVeil(accent), 0);
        _ = try str(gpa, dl, e, .semibold, detail_x, top + 26, ink, 16, peer);
        try rect(gpa, dl, detail_x, top + 40, detail_w, 1, divider, 0);
    }

    // The composer: a growing multi-line input + Send. The draft renders
    // through the same wrap engine as the bubbles (soft wrap + hard
    // word-break + '\n' from Shift+Enter); the caret sits after the last
    // glyph and BREATHES when idle (caretAlpha — lit while typing).
    // Phone: the input is a PILL (the messenger grammar) — a rounded ring
    // drawn as a slightly larger accent round-rect UNDER the fill, so focus
    // reads as a true rounded outline (edge-line rects overhang a pill's
    // corners). Desktop keeps the squarer field + edge-line ring.
    const in_rad: u8 = if (phone) 23 else 14;
    if (phone and input_focus) {
        const ring_c = (0xC0 << 24) | (accent & 0x00FFFFFF);
        try rect(gpa, dl, input_x - 1, comp_y - 1, input_w + 2, comp_h + 2, ring_c, 24);
    }
    try rect(gpa, dl, input_x, comp_y, input_w, comp_h, skinPanel(accent), in_rad);
    try rect(gpa, dl, input_x, comp_y, input_w, 1, 0x14EDEAE0, in_rad);
    if (!phone and input_focus) {
        // Focus ring: a one-pixel accent outline (the rounded fill draws
        // first, so four thin edge rects read as a ring at this radius).
        const ring_c = (0xC0 << 24) | (accent & 0x00FFFFFF);
        try rect(gpa, dl, input_x, comp_y, input_w, 1, ring_c, 0);
        try rect(gpa, dl, input_x, comp_y + comp_h - 1, input_w, 1, ring_c, 0);
        try rect(gpa, dl, input_x, comp_y, 1, comp_h, ring_c, 0);
        try rect(gpa, dl, input_x + input_w - 1, comp_y, 1, comp_h, ring_c, 0);
    }
    var caret_x: i32 = input_x + 14;
    var caret_base: i32 = comp_y + 31;
    if (draft.len > 0) {
        // The draft wrapper carries a MID-TEXT caret (the composer's
        // machinery): the shell moves `draft_caret` with arrow keys and the
        // keyboard's space-hold slide, and the caret pen lands wherever
        // that byte offset wrapped to.
        const pens = try wrapDraft(gpa, dl, e, input_x + 14, comp_y + 31, input_w - 28, ink, chat_px, draft, input_line_h, @min(edit.caret, draft.len), @min(edit.sel_a, draft.len), @min(edit.sel_b, draft.len));
        caret_x = pens.caret.x;
        caret_base = pens.caret.baseline;
    } else {
        var pbuf: [96]u8 = undefined;
        // Phone: plain "Message" — the peer already heads the app bar.
        const ph = if (phone) "Message" else std.fmt.bufPrint(&pbuf, "Message {s}", .{peer}) catch "Message";
        try strEllipsis(gpa, dl, e, .regular, input_x + 14, comp_y + 31, faint, chat_px, ph, input_w - 28);
    }
    if (input_focus) {
        const ca = caretAlpha(motion.caret_phase);
        try rect(gpa, dl, caret_x + 1, caret_base - 16, 2, 20, scaleAlpha((0xE0 << 24) | (accent & 0x00FFFFFF), ca), 0);
    }
    try emitRegion(gpa, regions, input_x, comp_y, input_w, @intCast(comp_h), 0, .chat_input);
    // The EDIT BAR (long-press summons it): Copy/Cut/Paste/Select all in a
    // strip riding above the input. Copy/Cut only light with a selection.
    if (edit.bar and input_focus) {
        const acts = [_]struct { label: []const u8, act: Action, needs_sel: bool }{
            .{ .label = "Copy", .act = .chat_copy, .needs_sel = true },
            .{ .label = "Cut", .act = .chat_cut, .needs_sel = true },
            .{ .label = "Paste", .act = .chat_paste, .needs_sel = false },
            .{ .label = "Select all", .act = .chat_selall, .needs_sel = false },
        };
        const bar_h: i32 = 44;
        const by0 = comp_y - bar_h - 8;
        var bx = input_x;
        const have_sel = edit.sel_b > edit.sel_a;
        for (acts) |a2| {
            const lw: i32 = @intCast(text.measure(e, .semibold, a2.label, 14));
            const cw = lw + 28;
            const on = have_sel or !a2.needs_sel;
            try rect(gpa, dl, bx - 1, by0 - 1, cw + 2, bar_h + 2, (0x70 << 24) | (accent & 0x00FFFFFF), 11);
            try rect(gpa, dl, bx, by0, cw, bar_h, 0xFF23221B, 10);
            _ = try str(gpa, dl, e, .semibold, bx + 14, by0 + 28, if (on) ink else faint, 14, a2.label);
            if (on) try emitRegion(gpa, regions, bx, by0, cw, @intCast(bar_h), 0, a2.act);
            bx += cw + 8;
        }
    }
    // The pay button: a "B" wearing the two ₿ ticks (the embedded fonts
    // carry no bitcoin glyph; the line-art spelling is ours). Pins to the
    // input's bottom edge like Send; accent-filled while the sheet is open.
    {
        const py = comp_y + comp_h - 46;
        try rect(gpa, dl, detail_x, py, pay_btn, 46, if (pay.open) accent else skinPanel(accent), if (phone) 23 else 14);
        const bc: u32 = if (pay.open) 0xFF20201A else body_c;
        const bw2: i32 = @intCast(text.measure(e, .semibold, "B", 17));
        const bx2 = detail_x + @divTrunc(pay_btn - bw2, 2);
        _ = try str(gpa, dl, e, .semibold, bx2, py + 29, bc, 17, "B");
        try rect(gpa, dl, bx2 + @divTrunc(bw2, 2) - 1, py + 11, 2, 4, bc, 0);
        try rect(gpa, dl, bx2 + @divTrunc(bw2, 2) - 1, py + 31, 2, 4, bc, 0);
        try emitRegion(gpa, regions, detail_x, py, pay_btn, 46, 0, .pay_open);
    }
    // Send pins to the input's bottom edge as the composer grows. Phone: a
    // ROUND accent button with an up-arrow (the messenger grammar) — armed it
    // fills accent, resting it sits as a quiet disc; the tap target stays 46.
    const sx = detail_x + detail_w - send_w;
    const sy = comp_y + comp_h - 46;
    const armed = draft.len > 0;
    if (phone) {
        try rect(gpa, dl, sx, sy, send_w, 46, if (armed) accent else skinPanel(accent), 23);
        const aw3: i32 = @intCast(text.measure(e, .semibold, "\u{2191}", 22));
        _ = try str(gpa, dl, e, .semibold, sx + @divTrunc(send_w - aw3, 2), sy + 31, if (armed) 0xFF20201A else faint, 22, "\u{2191}");
    } else {
        try rect(gpa, dl, sx, sy, send_w, 46, if (armed) accent else skinPanel(accent), 14);
        const sw3: i32 = @intCast(text.measure(e, .semibold, "Send", 14));
        _ = try str(gpa, dl, e, .semibold, sx + @divTrunc(send_w - sw3, 2), sy + 29, if (armed) 0xFF20201A else faint, 14, "Send");
    }
    try emitRegion(gpa, regions, sx, sy, send_w, 46, 0, .chat_send);

    // ── The pay sheet (M5 A4): compose a request or a send. Sits above the
    // composer; drawn (and its regions emitted) LAST, so it shadows anything
    // beneath it (hitTest is last-wins). Near-opaque — the thread must not
    // bleed through a surface that talks about money. ──
    // The send-confirm face (§8.2): the last money-hasn't-moved beat before the
    // wallet hand-off. Who + ✓ verified, the amount, and the irreversibility
    // warning — the full first-time disclosure (§8.1) once, the short line after.
    if (pay.open and pay.confirm) {
        const amt_val = payAmountToSats(pay.amount, pay.unit) orelse 0;
        const large = amt_val >= pay_large_sat;
        const has_note = pay.note.len > 0;
        var sheet_h: i32 = 16 + 30 + 26 + 34; // pad + title + paying + amount
        if (has_note) sheet_h += 20;
        sheet_h += if (pay.first_send) 62 else 22; // disclosure
        if (large) sheet_h += 22;
        sheet_h += 54; // buttons + pad
        const sy0 = comp_y - sheet_h - 12;
        try rect(gpa, dl, detail_x, sy0, detail_w, sheet_h, 0xFF201F18, 16);
        const ring_c = (0x90 << 24) | (accent & 0x00FFFFFF);
        try rect(gpa, dl, detail_x, sy0, detail_w, 1, ring_c, 0);
        try rect(gpa, dl, detail_x, sy0 + sheet_h - 1, detail_w, 1, ring_c, 0);
        try rect(gpa, dl, detail_x, sy0, 1, sheet_h, ring_c, 0);
        try rect(gpa, dl, detail_x + detail_w - 1, sy0, 1, sheet_h, ring_c, 0);

        var py = sy0 + 16;
        _ = try str(gpa, dl, e, .semibold, detail_x + 18, py + 14, ink, 15, "Confirm payment");
        py += 30;
        {
            var hb: [96]u8 = undefined;
            const s = std.fmt.bufPrint(&hb, "Paying {s}", .{peer}) catch "Payment";
            try strEllipsis(gpa, dl, e, .semibold, detail_x + 18, py + 14, ink, 13, s, detail_w - 130);
            const vl = "\u{2713} verified";
            const vw: i32 = @intCast(text.measure(e, .semibold, vl, 11));
            _ = try str(gpa, dl, e, .semibold, detail_x + detail_w - 18 - vw, py + 14, 0xFF9BCE9B, 11, vl);
        }
        py += 26;
        {
            var gb: [27]u8 = undefined;
            const amt = groupSats(&gb, amt_val);
            const pen = try str(gpa, dl, e, .semibold, detail_x + 18, py + 22, ink, 22, amt);
            const pen2 = try str(gpa, dl, e, .regular, pen + 6, py + 22, muted, 13, "sats");
            // The ≈$ value at the confirm moment too — the amount is fixed now.
            if (pay.usd_cents_per_btc > 0) {
                var fbuf: [40]u8 = undefined;
                const fs = formatFiat(&fbuf, amt_val, pay.usd_cents_per_btc);
                if (fs.len > 0) _ = try str(gpa, dl, e, .regular, pen2 + 10, py + 22, faint, 12, fs);
            }
            const rl = if (pay.rail == .lightning) "LIGHTNING" else "ON-CHAIN";
            const rw: i32 = @intCast(text.measure(e, .semibold, rl, 11));
            _ = try str(gpa, dl, e, .semibold, detail_x + detail_w - 18 - rw, py + 18, faint, 11, rl);
        }
        py += 34;
        if (has_note) {
            try strEllipsis(gpa, dl, e, .regular, detail_x + 18, py + 12, muted, 12, pay.note, detail_w - 36);
            py += 20;
        }
        if (pay.first_send) {
            _ = try strEllipsis(gpa, dl, e, .regular, detail_x + 18, py + 12, body_c, 11, "Payments are final \u{2014} they can't be reversed or refunded.", detail_w - 36);
            py += 18;
            _ = try strEllipsis(gpa, dl, e, .regular, detail_x + 18, py + 12, body_c, 11, "Only send to people you know and trust completely.", detail_w - 36);
            py += 18;
            _ = try strEllipsis(gpa, dl, e, .regular, detail_x + 18, py + 12, body_c, 11, "Zat4 never holds your money \u{2014} it goes straight to them.", detail_w - 36);
            py += 26;
        } else {
            _ = try strEllipsis(gpa, dl, e, .regular, detail_x + 18, py + 12, muted, 11, "Payments can't be undone. Only send to people you trust.", detail_w - 36);
            py += 22;
        }
        if (large) {
            _ = try str(gpa, dl, e, .semibold, detail_x + 18, py + 12, 0xFFE0A868, 12, "This is a large amount \u{2014} double-check it.");
            py += 22;
        }
        {
            const back_w: i32 = 92;
            var bx3 = detail_x + 18;
            try rect(gpa, dl, bx3, py, back_w, 42, 0x2AEDEAE0, 14);
            const blw: i32 = @intCast(text.measure(e, .semibold, "Back", 13));
            _ = try str(gpa, dl, e, .semibold, bx3 + @divTrunc(back_w - blw, 2), py + 27, body_c, 13, "Back");
            try emitRegion(gpa, regions, bx3, py, back_w, 42, 0, .pay_confirm_back);
            bx3 += back_w + 8;
            const conf_w = detail_x + detail_w - 18 - bx3;
            try rect(gpa, dl, bx3, py, conf_w, 42, accent, 14);
            const cl = "Confirm \u{2014} open wallet";
            const clw2: i32 = @intCast(text.measure(e, .semibold, cl, 13));
            _ = try str(gpa, dl, e, .semibold, bx3 + @divTrunc(conf_w - clw2, 2), py + 27, 0xFF20201A, 13, cl);
            try emitRegion(gpa, regions, bx3, py, conf_w, 42, 0, .pay_send);
        }
    }

    if (pay.open and !pay.confirm) {
        const status_extra: i32 = if (pay.status.len > 0) 24 else 0;
        // The ≈$ line shows only when a price is known and the amount parses.
        const sheet_sats = payAmountToSats(pay.amount, pay.unit);
        const show_fiat = pay.usd_cents_per_btc > 0 and sheet_sats != null;
        const fiat_extra: i32 = if (show_fiat) 20 else 0;
        // +30 for the "set up how you get paid" link row at the foot.
        const sheet_h: i32 = 254 + 30 + status_extra + fiat_extra;
        const sy0 = comp_y - sheet_h - 12;
        try rect(gpa, dl, detail_x, sy0, detail_w, sheet_h, 0xFF201F18, 16);
        const ring_c = (0x90 << 24) | (accent & 0x00FFFFFF);
        try rect(gpa, dl, detail_x, sy0, detail_w, 1, ring_c, 0);
        try rect(gpa, dl, detail_x, sy0 + sheet_h - 1, detail_w, 1, ring_c, 0);
        try rect(gpa, dl, detail_x, sy0, 1, sheet_h, ring_c, 0);
        try rect(gpa, dl, detail_x + detail_w - 1, sy0, 1, sheet_h, ring_c, 0);

        var py = sy0 + 16;
        // Header: who, and the rail toggle (two pills, selected = accent).
        {
            var hbuf: [96]u8 = undefined;
            const hs = std.fmt.bufPrint(&hbuf, "Pay {s}", .{peer}) catch "Pay";
            try strEllipsis(gpa, dl, e, .semibold, detail_x + 18, py + 14, ink, 14, hs, detail_w - 260);
            var rx = detail_x + detail_w - 18;
            const rails = [2][]const u8{ "On-chain", "Lightning" }; // drawn right-to-left
            for (rails, 0..) |label, ri| {
                const rail_val: chat_msg.Rail = if (ri == 0) .onchain else .lightning;
                const on = pay.rail == rail_val;
                const lw: i32 = @intCast(text.measure(e, .semibold, label, 12));
                const pw = lw + 22;
                rx -= pw;
                try rect(gpa, dl, rx, py - 3, pw, 28, if (on) accent else 0x2AEDEAE0, 14);
                _ = try str(gpa, dl, e, .semibold, rx + 11, py + 15, if (on) 0xFF20201A else body_c, 12, label);
                try emitRegion(gpa, regions, rx, py - 3, pw, 28, @intFromEnum(rail_val), .pay_rail);
                rx -= 8;
            }
        }
        py += 38;
        // Amount chips: one tap fills the amount.
        {
            var cx = detail_x + 18;
            for (pay_chips, 0..) |chip, ci| {
                var gb: [27]u8 = undefined;
                const cs = groupSats(&gb, chip);
                const lw: i32 = @intCast(text.measure(e, .regular, cs, 13));
                const pw = lw + 24;
                try rect(gpa, dl, cx, py, pw, 30, 0x2AEDEAE0, 12);
                _ = try str(gpa, dl, e, .regular, cx + 12, py + 20, body_c, 13, cs);
                try emitRegion(gpa, regions, cx, py, pw, 30, @intCast(ci), .pay_chip);
                cx += pw + 8;
            }
        }
        py += 40;
        // The two inputs: amount (digits) and note. The focused one wears
        // the ring + caret — the composer's focus vocabulary.
        const unit_label = if (pay.unit == .btc) "BTC" else "sats";
        const amount_ph = if (pay.unit == .btc) "amount in BTC" else "amount in sats";
        const fields = [2]struct { draft: []const u8, ph: []const u8, act: Action }{
            .{ .draft = pay.amount, .ph = amount_ph, .act = .pay_amount },
            .{ .draft = pay.note, .ph = "note (optional)", .act = .pay_note },
        };
        for (fields, 0..) |fld, fi| {
            const focused = pay.focus == fi;
            try rect(gpa, dl, detail_x + 18, py, detail_w - 36, 38, 0x22EDEAE0, 12);
            if (focused) {
                const fr = (0xC0 << 24) | (accent & 0x00FFFFFF);
                try rect(gpa, dl, detail_x + 18, py, detail_w - 36, 1, fr, 0);
                try rect(gpa, dl, detail_x + 18, py + 37, detail_w - 36, 1, fr, 0);
                try rect(gpa, dl, detail_x + 18, py, 1, 38, fr, 0);
                try rect(gpa, dl, detail_x + detail_w - 19, py, 1, 38, fr, 0);
            }
            var fpen: i32 = detail_x + 32;
            if (fld.draft.len > 0) {
                fpen = try str(gpa, dl, e, if (fi == 0) .semibold else .regular, detail_x + 32, py + 25, ink, 14, fld.draft);
            } else {
                _ = try str(gpa, dl, e, .regular, detail_x + 32, py + 25, faint, 14, fld.ph);
            }
            if (focused) {
                const ca = caretAlpha(motion.caret_phase);
                try rect(gpa, dl, fpen + 2, py + 10, 2, 18, scaleAlpha((0xE0 << 24) | (accent & 0x00FFFFFF), ca), 0);
            }
            try emitRegion(gpa, regions, detail_x + 18, py, detail_w - 36, 38, 0, fld.act);
            // The amount row carries a tappable UNIT toggle (sats ⇄ BTC),
            // right-aligned inside the field.
            if (fi == 0) {
                const ulw: i32 = @intCast(text.measure(e, .semibold, unit_label, 12));
                const upw = ulw + 22;
                const ux = detail_x + detail_w - 19 - upw - 3;
                try rect(gpa, dl, ux, py + 4, upw, 30, 0x33EDEAE0, 10);
                _ = try str(gpa, dl, e, .semibold, ux + 11, py + 25, body_c, 12, unit_label);
                try emitRegion(gpa, regions, ux, py + 4, upw, 30, 0, .pay_unit);
            }
            py += 46;
            // The ≈$ readout under the amount (a price we know, an amount we can read).
            if (fi == 0 and show_fiat) {
                var fbuf: [40]u8 = undefined;
                const fs = formatFiat(&fbuf, sheet_sats.?, pay.usd_cents_per_btc);
                if (fs.len > 0) {
                    _ = try str(gpa, dl, e, .regular, detail_x + 20, py + 2, muted, 12, fs);
                    py += 20;
                }
            }
        }
        if (pay.status.len > 0) {
            _ = try str(gpa, dl, e, .regular, detail_x + 20, py + 12, 0xFFE0A868, 13, pay.status);
            py += 24;
        }
        // The verbs: Cancel | Request | Send. Request asks the peer for
        // this amount; Send resolves their published address and hands off
        // to YOUR wallet (§0 — approval happens there).
        {
            const armed2 = pay.amount.len > 0;
            const cancel_w: i32 = 92;
            const rest = detail_w - 36 - cancel_w - 16;
            const req_w = @divTrunc(rest, 2);
            const send_w2 = rest - req_w;
            var bx3 = detail_x + 18;
            try rect(gpa, dl, bx3, py, cancel_w, 42, 0x2AEDEAE0, 14);
            const clw: i32 = @intCast(text.measure(e, .semibold, "Cancel", 13));
            _ = try str(gpa, dl, e, .semibold, bx3 + @divTrunc(cancel_w - clw, 2), py + 27, body_c, 13, "Cancel");
            try emitRegion(gpa, regions, bx3, py, cancel_w, 42, 0, .pay_cancel);
            bx3 += cancel_w + 8;
            try rect(gpa, dl, bx3, py, req_w, 42, 0x2AEDEAE0, 14);
            const rlw: i32 = @intCast(text.measure(e, .semibold, "Request", 13));
            _ = try str(gpa, dl, e, .semibold, bx3 + @divTrunc(req_w - rlw, 2), py + 27, if (armed2) ink else faint, 13, "Request");
            try emitRegion(gpa, regions, bx3, py, req_w, 42, 0, .pay_request);
            bx3 += req_w + 8;
            try rect(gpa, dl, bx3, py, send_w2, 42, if (armed2) accent else skinPanel(accent), 14);
            const slw: i32 = @intCast(text.measure(e, .semibold, "Send", 13));
            _ = try str(gpa, dl, e, .semibold, bx3 + @divTrunc(send_w2 - slw, 2), py + 27, if (armed2) 0xFF20201A else faint, 13, "Send");
            // Send ARMS the confirm face (§8.2) — the actual hand-off happens on
            // the confirm's "Confirm & open wallet". Request moves no money, so it
            // fires directly with no confirm.
            try emitRegion(gpa, regions, bx3, py, send_w2, 42, 0, .pay_arm);
        }
        // The way IN to setting up how YOU get paid — the answer to "where do
        // I set my own address?" lives right where money is discussed.
        py += 50;
        {
            const link = "Set up how you get paid \u{203A}";
            const lw: i32 = @intCast(text.measure(e, .semibold, link, 12));
            const lx = detail_x + @divTrunc(detail_w - lw, 2);
            _ = try str(gpa, dl, e, .semibold, lx, py + 6, (0xC0 << 24) | (accent & 0x00FFFFFF), 12, link);
            try emitRegion(gpa, regions, detail_x + 18, py - 8, detail_w - 36, 28, 0, .recv_open);
        }
    }

    // ── The receive-setup sheet: paste YOUR address so people in your chats
    // can pay you. Same chrome as the pay sheet; mutually exclusive with it. ──
    if (recv.open) {
        const status_extra: i32 = if (recv.status.len > 0) 24 else 0;
        // The paste form grows by one line when the Remove link shows (an
        // address is present and we're not on the just-saved confirmation).
        const remove_extra: i32 = if (recv.mode == .paste and !recv.saved and (recv.lightning.len > 0 or recv.bitcoin.len > 0)) 26 else 0;
        const sheet_h: i32 = switch (recv.mode) {
            .onboard => 224,
            .paste => 236 + status_extra + remove_extra,
            .wallets => 24 + 28 + 30 + @as(i32, @intCast(recv_wallets.len)) * 56 + 54,
        };
        const sy0 = comp_y - sheet_h - 12;
        try rect(gpa, dl, detail_x, sy0, detail_w, sheet_h, 0xFF201F18, 16);
        const ring_c = (0x90 << 24) | (accent & 0x00FFFFFF);
        try rect(gpa, dl, detail_x, sy0, detail_w, 1, ring_c, 0);
        try rect(gpa, dl, detail_x, sy0 + sheet_h - 1, detail_w, 1, ring_c, 0);
        try rect(gpa, dl, detail_x, sy0, 1, sheet_h, ring_c, 0);
        try rect(gpa, dl, detail_x + detail_w - 1, sy0, 1, sheet_h, ring_c, 0);

        var py = sy0 + 16;
        switch (recv.mode) {
            // First run: the branch. Don't dump a wallet-less user into a form.
            .onboard => {
                _ = try str(gpa, dl, e, .semibold, detail_x + 18, py + 16, ink, 16, "Get paid in Zat Chat");
                py += 34;
                _ = try strEllipsis(gpa, dl, e, .regular, detail_x + 18, py + 12, muted, 12, "People in your chats can send you bitcoin once you add a wallet address.", detail_w - 36);
                py += 40;
                // Primary: I have a wallet -> the paste form.
                try rect(gpa, dl, detail_x + 18, py, detail_w - 36, 44, accent, 14);
                const l1 = "I have a wallet \u{2014} paste it";
                const w1: i32 = @intCast(text.measure(e, .semibold, l1, 13));
                _ = try str(gpa, dl, e, .semibold, detail_x + @divTrunc(detail_w - w1, 2), py + 28, 0xFF20201A, 13, l1);
                try emitRegion(gpa, regions, detail_x + 18, py, detail_w - 36, 44, 0, .recv_have);
                py += 52;
                // Secondary: I don't have one -> the get-a-wallet list.
                try rect(gpa, dl, detail_x + 18, py, detail_w - 36, 44, 0x2AEDEAE0, 14);
                const l2 = "I don't have one yet";
                const w2: i32 = @intCast(text.measure(e, .semibold, l2, 13));
                _ = try str(gpa, dl, e, .semibold, detail_x + @divTrunc(detail_w - w2, 2), py + 28, body_c, 13, l2);
                try emitRegion(gpa, regions, detail_x + 18, py, detail_w - 36, 44, 0, .recv_need);
                py += 50;
                const later = "Maybe later";
                const wl: i32 = @intCast(text.measure(e, .regular, later, 12));
                _ = try str(gpa, dl, e, .regular, detail_x + @divTrunc(detail_w - wl, 2), py + 6, faint, 12, later);
                try emitRegion(gpa, regions, detail_x + 18, py - 6, detail_w - 36, 24, 0, .recv_cancel);
            },
            // The paste form (for users who have an address).
            .paste => {
                _ = try str(gpa, dl, e, .semibold, detail_x + 18, py + 14, ink, 15, "Receive payments in chat");
                py += 30;
                _ = try strEllipsis(gpa, dl, e, .regular, detail_x + 18, py + 12, muted, 12, "Paste an address so people can pay you. A Lightning address (you@wallet.com) is easiest.", detail_w - 36);
                py += 34;
                const rfields = [2]struct { draft: []const u8, ph: []const u8, act: Action }{
                    .{ .draft = recv.lightning, .ph = "lightning address  \u{2014}  you@wallet.com", .act = .recv_ln },
                    .{ .draft = recv.bitcoin, .ph = "bitcoin address (optional)", .act = .recv_btc },
                };
                for (rfields, 0..) |fld, fi| {
                    const focused = recv.focus == fi;
                    try rect(gpa, dl, detail_x + 18, py, detail_w - 36, 38, 0x22EDEAE0, 12);
                    if (focused) {
                        const fr = (0xC0 << 24) | (accent & 0x00FFFFFF);
                        try rect(gpa, dl, detail_x + 18, py, detail_w - 36, 1, fr, 0);
                        try rect(gpa, dl, detail_x + 18, py + 37, detail_w - 36, 1, fr, 0);
                        try rect(gpa, dl, detail_x + 18, py, 1, 38, fr, 0);
                        try rect(gpa, dl, detail_x + detail_w - 19, py, 1, 38, fr, 0);
                    }
                    const fmaxw = detail_w - 64;
                    var fpen: i32 = detail_x + 32;
                    if (fld.draft.len > 0) {
                        try strEllipsis(gpa, dl, e, .regular, detail_x + 32, py + 25, ink, 14, fld.draft, fmaxw);
                        const tw: i32 = @intCast(text.measure(e, .regular, fld.draft, 14));
                        fpen = detail_x + 32 + @min(tw, fmaxw);
                    } else {
                        try strEllipsis(gpa, dl, e, .regular, detail_x + 32, py + 25, faint, 14, fld.ph, fmaxw);
                    }
                    if (focused) {
                        const ca = caretAlpha(motion.caret_phase);
                        try rect(gpa, dl, fpen + 2, py + 10, 2, 18, scaleAlpha((0xE0 << 24) | (accent & 0x00FFFFFF), ca), 0);
                    }
                    try emitRegion(gpa, regions, detail_x + 18, py, detail_w - 36, 38, 0, fld.act);
                    py += 46;
                }
                // A one-tap Remove when an address is present (was: clear every
                // char, then Cancel — unintuitive). It unpublishes the record so
                // you read as walletless again. Right-aligned, quiet red.
                if (!recv.saved and (recv.lightning.len > 0 or recv.bitcoin.len > 0)) {
                    const rl = "Remove wallet";
                    const rw: i32 = @intCast(text.measure(e, .semibold, rl, 12));
                    _ = try str(gpa, dl, e, .semibold, detail_x + detail_w - 18 - rw, py + 10, 0xFFD98A7A, 12, rl);
                    try emitRegion(gpa, regions, detail_x + detail_w - 26 - rw, py - 2, rw + 16, 26, 0, .recv_remove);
                    py += 26;
                }
                if (recv.status.len > 0) {
                    const sc: u32 = if (recv.saved) 0xFF9BCE9B else 0xFFE0A868;
                    _ = try str(gpa, dl, e, .regular, detail_x + 20, py + 12, sc, 13, recv.status);
                    py += 24;
                }
                if (recv.saved) {
                    // Once saved there is nothing left to do here — the footer
                    // collapses to a single Done that closes the sheet (reusing
                    // recv_cancel, which dismisses). No more lone "Cancel".
                    const done_w = detail_w - 36;
                    const dx = detail_x + 18;
                    try rect(gpa, dl, dx, py, done_w, 42, accent, 14);
                    const dlw: i32 = @intCast(text.measure(e, .semibold, "Done", 13));
                    _ = try str(gpa, dl, e, .semibold, dx + @divTrunc(done_w - dlw, 2), py + 27, 0xFF20201A, 13, "Done");
                    try emitRegion(gpa, regions, dx, py, done_w, 42, 0, .recv_cancel);
                } else {
                    const cancel_w: i32 = 92;
                    var bx3 = detail_x + 18;
                    try rect(gpa, dl, bx3, py, cancel_w, 42, 0x2AEDEAE0, 14);
                    const clw: i32 = @intCast(text.measure(e, .semibold, "Cancel", 13));
                    _ = try str(gpa, dl, e, .semibold, bx3 + @divTrunc(cancel_w - clw, 2), py + 27, body_c, 13, "Cancel");
                    try emitRegion(gpa, regions, bx3, py, cancel_w, 42, 0, .recv_cancel);
                    bx3 += cancel_w + 8;
                    const save_w = detail_x + detail_w - 18 - bx3;
                    const has_addr = recv.lightning.len > 0 or recv.bitcoin.len > 0;
                    try rect(gpa, dl, bx3, py, save_w, 42, if (has_addr) accent else skinPanel(accent), 14);
                    const slw: i32 = @intCast(text.measure(e, .semibold, "Save", 13));
                    _ = try str(gpa, dl, e, .semibold, bx3 + @divTrunc(save_w - slw, 2), py + 27, if (has_addr) 0xFF20201A else faint, 13, "Save");
                    try emitRegion(gpa, regions, bx3, py, save_w, 42, 0, .recv_save);
                }
            },
            // The get-a-wallet list (for users who have none). Each row opens the
            // wallet's site; you grab an address there and come back to paste.
            .wallets => {
                _ = try str(gpa, dl, e, .semibold, detail_x + 18, py + 14, ink, 15, "Get a wallet \u{2014} about a minute");
                py += 28;
                _ = try strEllipsis(gpa, dl, e, .regular, detail_x + 18, py + 12, muted, 12, "Grab one, then come back and paste your address.", detail_w - 36);
                py += 30;
                for (recv_wallets, 0..) |wal, wi| {
                    try rect(gpa, dl, detail_x + 18, py, detail_w - 36, 48, 0x22EDEAE0, 12);
                    _ = try str(gpa, dl, e, .semibold, detail_x + 32, py + 20, ink, 13, wal.name);
                    _ = try strEllipsis(gpa, dl, e, .regular, detail_x + 32, py + 38, muted, 11, wal.tagline, detail_w - 64);
                    // A subtle arrow to read as "opens out".
                    _ = try str(gpa, dl, e, .semibold, detail_x + detail_w - 40, py + 29, faint, 15, "\u{203A}");
                    try emitRegion(gpa, regions, detail_x + 18, py, detail_w - 36, 48, @intCast(wi), .recv_wallet);
                    py += 56;
                }
                const cancel_w: i32 = 92;
                var bx3 = detail_x + 18;
                try rect(gpa, dl, bx3, py, cancel_w, 42, 0x2AEDEAE0, 14);
                const clw: i32 = @intCast(text.measure(e, .semibold, "Cancel", 13));
                _ = try str(gpa, dl, e, .semibold, bx3 + @divTrunc(cancel_w - clw, 2), py + 27, body_c, 13, "Cancel");
                try emitRegion(gpa, regions, bx3, py, cancel_w, 42, 0, .recv_cancel);
                bx3 += cancel_w + 8;
                const paste_w = detail_x + detail_w - 18 - bx3;
                try rect(gpa, dl, bx3, py, paste_w, 42, accent, 14);
                const pl = "I've got one \u{2014} paste";
                const plw: i32 = @intCast(text.measure(e, .semibold, pl, 13));
                _ = try str(gpa, dl, e, .semibold, bx3 + @divTrunc(paste_w - plw, 2), py + 27, 0xFF20201A, 13, pl);
                try emitRegion(gpa, regions, bx3, py, paste_w, 42, 0, .recv_paste);
            },
        }
    }

    return height + @max(0, total - (thread_bot - thread_top));
}

/// True when `cid` is one of the reader's expanded posts (Read-more). Linear
/// over a handful of expanded cids — the set is tiny (what fits on screen).
fn cidIn(cids: []const []const u8, cid: []const u8) bool {
    for (cids) |c| if (std.mem.eql(u8, c, cid)) return true;
    return false;
}

pub fn fromTimeline(arena: Allocator, items: []const feed.TimelineItem, now: i64, expanded: []const []const u8) error{OutOfMemory}![]PostView {
    const out = try arena.alloc(PostView, items.len);
    for (items, out) |it, *pv| {
        const name = if (it.author_display_name.len > 0) it.author_display_name else it.author_handle;
        pv.* = .{
            .name = name,
            .handle = try std.fmt.allocPrint(arena, "@{s}", .{it.author_handle}),
            .age = try ageStr(arena, now, it.created_at),
            .body = it.text,
            .replying_to = if (it.replying_to_handle.len > 0)
                try std.fmt.allocPrint(arena, "@{s}", .{it.replying_to_handle})
            else
                "",
            .tint = tintFor(it.author_handle),
            .reply = it.reply_count,
            .boost = it.repost_count,
            .like = it.like_count,
            .initial = initialOf(name),
            .liked = it.item_flags.viewer_liked,
            .boosted = it.item_flags.viewer_reposted,
            .depth = it.depth,
            .is_focus = it.is_focus,
            .stitched = it.stitched,
            .has_kids = it.has_kids,
            .collapsed = it.collapsed,
            .expanded = cidIn(expanded, it.cid),
            .tags = it.tags,
            .quote_author_name = it.quote_author_display_name,
            .quote_author_handle = it.quote_author_handle,
            .quote_text = it.quote_text,
        };
    }
    return out;
}

/// Arena-owned relative age. Formats via the shared `timefmt` (the single
/// source, also used by the TUI — D6) into a stack buffer, then dupes into the
/// arena. The dedicated one-function module is why this no longer needs a local
/// copy yet still avoids pulling a whole UI module into the view's graph.
fn ageStr(arena: Allocator, now: i64, created: i64) error{OutOfMemory}![]const u8 {
    var buf: [16]u8 = undefined;
    return arena.dupe(u8, timefmt.format(&buf, now, created));
}

const avatar_tints = [_]u32{ 0xFFCAA3A8, 0xFF9FC7A0, 0xFFE0C074, 0xFFA9B6D6, 0xFFD6A87F, 0xFFB5A9CC };

/// Deterministic muted tint from the handle (FNV-1a) — same author, same
/// colour, every frame, with no per-author state to store.
fn tintFor(handle: []const u8) u32 {
    var x: u64 = 1469598103934665603;
    for (handle) |b| {
        x ^= b;
        x *%= 1099511628211;
    }
    return avatar_tints[@intCast(x % avatar_tints.len)];
}

fn initialOf(name: []const u8) u8 {
    for (name) |ch| if (ch > ' ' and ch < 128) return ch;
    return '#';
}

test "fromTimeline: display-name fallback, counts, age, deterministic tint" {
    const gpa = std.testing.allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const items = [_]feed.TimelineItem{
        .{ .uri = "", .cid = "", .author_handle = "mara.zat", .author_display_name = "Mara Vesper", .reposted_by_handle = "", .replying_to_handle = "", .text = "hello field", .created_at = 1000, .like_count = 48, .repost_count = 9, .reply_count = 6, .quote_count = 0, .label_flags = .{}, .item_flags = .{ .viewer_liked = true } },
        .{ .uri = "", .cid = "", .author_handle = "oko.zat", .author_display_name = "", .reposted_by_handle = "", .replying_to_handle = "", .text = "monospace", .created_at = 0, .like_count = 73, .repost_count = 18, .reply_count = 24, .quote_count = 0, .label_flags = .{}, .item_flags = .{} },
    };
    const out = try fromTimeline(arena, &items, 1000 + 120, &.{});

    try std.testing.expectEqualStrings("Mara Vesper", out[0].name);
    try std.testing.expectEqualStrings("@mara.zat", out[0].handle);
    try std.testing.expectEqualStrings("2m", out[0].age);
    try std.testing.expectEqual(@as(u32, 48), out[0].like);
    try std.testing.expectEqual(@as(u8, 'M'), out[0].initial);
    try std.testing.expect(out[0].liked);
    try std.testing.expect(!out[1].liked);
    // empty display name falls back to the handle
    try std.testing.expectEqualStrings("oko.zat", out[1].name);
    try std.testing.expectEqual(@as(u8, 'o'), out[1].initial);
    // tint is a pure function of the handle
    try std.testing.expectEqual(tintFor("mara.zat"), out[0].tint);
}

test "layout emits 4 tap regions per post (avatar + 3 engagement); hitTest resolves each" {
    const gpa = std.testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);
    var regions: Regions = .empty;
    defer regions.deinit(gpa);

    const posts = [_]PostView{
        .{ .name = "A", .handle = "@a.zat", .age = "1m", .body = "hello there field", .tint = 0xFFAAAAAA, .reply = 1, .boost = 2, .like = 3, .initial = 'A', .liked = true, .boosted = false },
    };
    const h = try layout(gpa, &engine, 460, 940, &posts, 0, &dl, &regions, null, false, screen_home, null, 0, accent_house, null, .{}, null, null, null, "", .{}, null, 0, 0, .{}, 0, 255, null, .{}, .{});
    try std.testing.expect(h > 112); // content extends below the top bar
    // 8 post regions (body + avatar + reply/repost/like + bookmark/share/more)
    // + 2 mobile-header regions (the hamburger drawer-opener and the search
    // magnifier) = 10.
    try std.testing.expectEqual(@as(usize, 10), regions.items.len);

    var saw_like = false;
    var saw_author = false;
    var saw_body = false;
    for (regions.items) |r| {
        const cxp = @as(i32, r.x) + @divTrunc(@as(i32, r.w), 2);
        const cyp = @as(i32, r.y) + @divTrunc(@as(i32, r.h), 2);
        const hit = hitTest(regions.items, cxp, cyp) orelse return error.NoHit;
        try std.testing.expectEqual(r.kind, hit.kind);
        try std.testing.expectEqual(@as(u16, 0), hit.post);
        if (r.kind == .like) saw_like = true;
        if (r.kind == .author) saw_author = true;
        if (r.kind == .post_body) saw_body = true;
    }
    try std.testing.expect(saw_like);
    try std.testing.expect(saw_author);
    try std.testing.expect(saw_body);
    // The avatar + engagement regions PUNCH THROUGH the whole-post body region:
    // each self-hit-tests to itself (verified in the loop above) even though the
    // body region covers them, because they are emitted AFTER it (found first in
    // the reverse hit-test). So a tap on the avatar opens the profile, the body
    // opens the thread.
    // a click far outside every region (above the first post) resolves to nothing
    try std.testing.expect(hitTest(regions.items, 5, 5) == null);
}

test "Toy Box depth: transformDlRange scales every variant about the pivot" {
    const gpa = std.testing.allocator;
    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);
    // One of each variant, positioned away from the origin so a 2x scale about
    // (0,0) with no translate simply doubles every coordinate/size.
    try dl.append(gpa, .{ .rect = .{ .x = 10, .y = 20, .w = 30, .h = 40, .color = 0xFF112233, .radius = 4 } });
    try dl.append(gpa, .{ .text = .{ .x = 5, .baseline = 15, .codepoint = 'Z', .color = 0xFFFFFFFF, .px = 16, .weight = 0 } });
    try dl.append(gpa, .{ .line = .{ .x0 = 2, .y0 = 3, .x1 = 6, .y1 = 9, .color = 0xFF000000, .thickness = 2 } });
    try dl.append(gpa, .{ .tri = .{ .x0 = 1, .y0 = 2, .x1 = 3, .y1 = 4, .x2 = 5, .y2 = 6, .color = 0xFF00FF00 } });
    transformDlRange(&dl, 0, dl.len, 2.0, 0, 0, 0, 0);
    const r = dl.get(0).rect;
    try std.testing.expectEqual(@as(i16, 20), r.x);
    try std.testing.expectEqual(@as(i16, 40), r.y);
    try std.testing.expectEqual(@as(u16, 60), r.w);
    try std.testing.expectEqual(@as(u16, 80), r.h);
    try std.testing.expectEqual(@as(u8, 8), r.radius);
    try std.testing.expectEqual(@as(u32, 0xFF112233), r.color); // colour untouched
    const t = dl.get(1).text;
    try std.testing.expectEqual(@as(i16, 10), t.x);
    try std.testing.expectEqual(@as(i16, 30), t.baseline);
    try std.testing.expectEqual(@as(u16, 32), t.px); // font size scales
    const l = dl.get(2).line;
    try std.testing.expectEqual(@as(i16, 4), l.x0);
    try std.testing.expectEqual(@as(i16, 18), l.y1);
    try std.testing.expectEqual(@as(u8, 4), l.thickness);
    const tr = dl.get(3).tri;
    try std.testing.expectEqual(@as(i16, 10), tr.x2);
    try std.testing.expectEqual(@as(i16, 12), tr.y2);

    // A pathological scale saturates at the i16/u16 bounds rather than wrapping.
    var big: raster.DrawList = .{};
    defer big.deinit(gpa);
    try big.append(gpa, .{ .rect = .{ .x = 30000, .y = -30000, .w = 60000, .h = 5, .color = 0, .radius = 200 } });
    transformDlRange(&big, 0, big.len, 100.0, 0, 0, 0, 0);
    const b = big.get(0).rect;
    try std.testing.expectEqual(@as(i16, 32767), b.x);
    try std.testing.expectEqual(@as(i16, -32768), b.y);
    try std.testing.expectEqual(@as(u16, 65535), b.w);
    try std.testing.expectEqual(@as(u8, 255), b.radius);
}

test "Toy Box depth: loomScale is monotonic in engagement with a safe flat case" {
    const quiet: PostView = .{ .name = "q", .handle = "@q", .age = "1m", .body = "", .tint = 0, .reply = 0, .boost = 0, .like = 0, .initial = 'q', .liked = false, .boosted = false };
    const loud: PostView = .{ .name = "l", .handle = "@l", .age = "1m", .body = "", .tint = 0, .reply = 10, .boost = 10, .like = 80, .initial = 'l', .liked = false, .boosted = false };
    // Full range: quiet hits the floor, loud hits the ceiling, monotonic between.
    try std.testing.expectApproxEqAbs(@as(f32, 0.80), loomScale(quiet, 0, 100), 0.001);
    try std.testing.expectApproxEqAbs(@as(f32, 1.12), loomScale(loud, 0, 100), 0.001);
    try std.testing.expect(loomScale(loud, 0, 100) > loomScale(quiet, 0, 100));
    // Flat slice (every post equal): no divide-by-zero, neutral midpoint.
    try std.testing.expectApproxEqAbs(@as(f32, 0.96), loomScale(quiet, 0, 0), 0.001); // 0.8 + 0.5*0.32
}

test "Toy Box depth: the toy decorates pixels but never moves the scroll accounting" {
    const gpa = std.testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);
    var regions: Regions = .empty;
    defer regions.deinit(gpa);

    const posts = [_]PostView{
        .{ .name = "Loud", .handle = "@l.zat", .age = "1m", .body = "a lively post that people engaged with heavily", .tint = 0xFFAAAAAA, .reply = 40, .boost = 30, .like = 200, .initial = 'L', .liked = false, .boosted = false },
        .{ .name = "Quiet", .handle = "@q.zat", .age = "2m", .body = "a quiet post barely anyone noticed at all", .tint = 0xFF888888, .reply = 0, .boost = 0, .like = 0, .initial = 'Q', .liked = false, .boosted = false },
    };

    // Baseline: natural layout. Record the content height and a checksum of every
    // text item's geometry (x + baseline + px) so we can prove pixels changed.
    const h_none = try layout(gpa, &engine, 460, 940, &posts, 0, &dl, &regions, null, false, screen_home, null, 0, accent_house, null, .{}, null, null, null, "", .{}, null, 0, 0, .{}, 0, 255, null, .{}, .{});
    var sum_none: i64 = 0;
    for (0..dl.len) |i| if (dl.get(i) == .text) {
        const t = dl.get(i).text;
        sum_none += @as(i64, t.x) + t.baseline + t.px;
    };

    // Depth on: same posts, same width/scroll. Height MUST be identical (the toy
    // never touches the measure pass or the y cursor), but the emitted geometry
    // MUST differ (posts are scaled by engagement).
    dl.clearRetainingCapacity();
    regions.clearRetainingCapacity();
    const h_depth = try layout(gpa, &engine, 460, 940, &posts, 0, &dl, &regions, null, false, screen_home, null, 0, accent_house, null, .{}, null, null, null, "", .{}, null, 0, 0, .{}, 0, 255, null, .{ .feed_toy = .depth }, .{});
    var sum_depth: i64 = 0;
    for (0..dl.len) |i| if (dl.get(i) == .text) {
        const t = dl.get(i).text;
        sum_depth += @as(i64, t.x) + t.baseline + t.px;
    };

    try std.testing.expectEqual(h_none, h_depth); // scroll/height accounting untouched
    try std.testing.expect(sum_none != sum_depth); // but the pixels moved (the loom)
}

test "Toy Box tectonic: horizontal filmstrip returns strip width and stays tappable" {
    const gpa = std.testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);
    var regions: Regions = .empty;
    defer regions.deinit(gpa);

    const posts = [_]PostView{
        .{ .name = "A", .handle = "@a.zat", .age = "1m", .body = "first card in the strip", .tint = 0xFFAAAAAA, .reply = 1, .boost = 0, .like = 2, .initial = 'A', .liked = false, .boosted = false },
        .{ .name = "B", .handle = "@b.zat", .age = "2m", .body = "second card in the strip", .tint = 0xFF999999, .reply = 0, .boost = 1, .like = 3, .initial = 'B', .liked = false, .boosted = false },
        .{ .name = "C", .handle = "@c.zat", .age = "3m", .body = "third card in the strip", .tint = 0xFF888888, .reply = 2, .boost = 0, .like = 4, .initial = 'C', .liked = false, .boosted = false },
    };

    // A vertical layout of three short posts is only a few hundred px tall; the
    // tectonic strip lays them left-to-right, so the returned extent (the width the
    // shell pans across) is much larger — proof the horizontal model is in effect.
    const extent = try layout(gpa, &engine, 1280, 940, &posts, 0, &dl, &regions, null, false, screen_home, null, 0, accent_house, null, .{}, null, null, null, "", .{}, null, 0, 0, .{}, 0, 255, null, .{ .feed_toy = .tectonic }, .{});
    try std.testing.expect(extent > 900);
    // On-strip cards still emit tap regions (taps + GPU icons track the moved card).
    try std.testing.expect(regions.items.len > 0);
}

test "Toy Box zero-g / liquid: drift moves pixels, leaves scroll accounting exact" {
    const gpa = std.testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);

    const posts = [_]PostView{
        .{ .name = "A", .handle = "@a.zat", .age = "1m", .body = "a post that should float", .tint = 0xFFAAAAAA, .reply = 1, .boost = 0, .like = 2, .initial = 'A', .liked = false, .boosted = false },
        .{ .name = "B", .handle = "@b.zat", .age = "2m", .body = "another post drifting in space", .tint = 0xFF999999, .reply = 0, .boost = 1, .like = 3, .initial = 'B', .liked = false, .boosted = false },
    };

    const sumText = struct {
        fn f(d: *raster.DrawList) i64 {
            var s: i64 = 0;
            for (0..d.len) |i| if (d.get(i) == .text) {
                const t = d.get(i).text;
                s += @as(i64, t.x) + t.baseline;
            };
            return s;
        }
    }.f;

    // Baseline height with no toy.
    const h_none = try layout(gpa, &engine, 460, 940, &posts, 0, &dl, null, null, false, screen_home, null, 0, accent_house, null, .{}, null, null, null, "", .{}, null, 0, 0, .{}, 0, 255, null, .{}, .{});
    const sum_none = sumText(&dl);

    // Zero-G at a non-zero clock: height identical (scroll math untouched), pixels moved.
    dl.clearRetainingCapacity();
    const h_zg = try layout(gpa, &engine, 460, 940, &posts, 0, &dl, null, null, false, screen_home, null, 0, accent_house, null, .{}, null, null, null, "", .{}, null, 0, 0, .{}, 0, 255, null, .{ .feed_toy = .zero_g, .t = 3.0 }, .{});
    try std.testing.expectEqual(h_none, h_zg);
    try std.testing.expect(sum_none != sumText(&dl));

    // Liquid with a live slosh amplitude also moves pixels; zero flow leaves it at rest.
    dl.clearRetainingCapacity();
    _ = try layout(gpa, &engine, 460, 940, &posts, 0, &dl, null, null, false, screen_home, null, 0, accent_house, null, .{}, null, null, null, "", .{}, null, 0, 0, .{}, 0, 255, null, .{ .feed_toy = .liquid, .t = 1.0, .flow = 40.0 }, .{});
    try std.testing.expect(sum_none != sumText(&dl));

    dl.clearRetainingCapacity();
    _ = try layout(gpa, &engine, 460, 940, &posts, 0, &dl, null, null, false, screen_home, null, 0, accent_house, null, .{}, null, null, null, "", .{}, null, 0, 0, .{}, 0, 255, null, .{ .feed_toy = .liquid, .t = 1.0, .flow = 0.0 }, .{});
    try std.testing.expectEqual(sum_none, sumText(&dl)); // flow 0 ⇒ settled, no offset
}

test "Toy Box XP skin: chrome emits from the base vocabulary and spans the frame" {
    const gpa = std.testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);

    const W: i32 = 1280;
    const H: i32 = 800;
    // 11:07 PM — exercises the 12-hour PM path and the zero-padded minute.
    try drawXpSkin(gpa, &dl, &engine, W, H, 23, 7);

    // The overlay draws only rect/line/text — no new primitive slipped in.
    var rects: usize = 0;
    var lines: usize = 0;
    var top_span: i16 = 0; // widest rect touching the top edge (the title bar)
    var bot_hit = false; // a rect sits in the taskbar band along the bottom
    for (0..dl.len) |i| switch (dl.get(i)) {
        .rect => |r| {
            rects += 1;
            if (r.y == 0 and @as(i16, @intCast(r.w)) > top_span) top_span = @intCast(r.w);
            if (@as(i32, r.y) + r.h >= H - 2 and r.w > 40) bot_hit = true;
        },
        .line => lines += 1,
        .text => {},
        else => return error.UnexpectedDrawItem, // no cell/tri in the chrome
    };
    try std.testing.expect(rects > 0);
    try std.testing.expect(lines >= 2); // the close-button X is two strokes
    try std.testing.expectEqual(@as(i16, @intCast(W)), top_span); // title bar spans full width
    try std.testing.expect(bot_hit); // the taskbar reaches the bottom edge
}

test "Toy Box XP skin: rethemeRetro squares corners, blackens text, keeps accent hues" {
    const gpa = std.testing.allocator;
    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);

    // A representative slice of a real frame: dark bg, a rounded card, a warm-ink
    // body glyph, a saturated avatar tint, and the red "liked" heart stroke.
    try rect(gpa, &dl, 0, 0, 460, 900, bg, 0); // dark background slab
    try rect(gpa, &dl, 40, 60, 380, 120, panel, 16); // a rounded card (widget band)
    try dl.append(gpa, .{ .text = .{ .x = 60, .baseline = 90, .codepoint = 'a', .color = ink, .px = 18, .weight = 0 } });
    try rect(gpa, &dl, 50, 70, 40, 40, 0xFFE0A868, 20); // saturated avatar tint
    try dl.append(gpa, .{ .line = .{ .x0 = 60, .y0 = 200, .x1 = 72, .y1 = 212, .color = 0xFFE84D3C, .thickness = 2 } }); // liked heart (red)

    try rethemeRetro(gpa, &dl, 460, 940, true);

    var saw_client_bg = false;
    var saw_kept_accent_fill = false;
    var saw_kept_red_stroke = false;
    var max_radius: u8 = 0;
    for (0..dl.len) |i| switch (dl.get(i)) {
        .rect => |r| {
            max_radius = @max(max_radius, r.radius);
            if (r.color == retro_win and r.w > 300 and r.h > 300) saw_client_bg = true;
            if ((r.color & 0x00FFFFFF) == 0x00E0A868) saw_kept_accent_fill = true;
        },
        .text => |t| try std.testing.expectEqual(retro_text, t.color), // warm ink → black
        .line => |ln| {
            if ((ln.color & 0x00FFFFFF) == 0x00E84D3C) saw_kept_red_stroke = true;
        },
        else => {},
    };
    try std.testing.expectEqual(@as(u8, 0), max_radius); // every corner squared off
    try std.testing.expect(saw_client_bg); // the grey window client was prepended
    try std.testing.expect(saw_kept_accent_fill); // avatar hue survived (meaning intact)
    try std.testing.expect(saw_kept_red_stroke); // the like heart stays red
}

test "layout captures the rooted post's body glyphs for selection (thread screen)" {
    const gpa = std.testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);
    var regions: Regions = .empty;
    defer regions.deinit(gpa);
    var sel: SelGlyphs = .empty;
    defer sel.deinit(gpa);

    const posts = [_]PostView{
        .{ .name = "A", .handle = "@a.zat", .age = "1m", .body = "hello there field", .tint = 0xFFAAAAAA, .reply = 0, .boost = 0, .like = 0, .initial = 'A', .liked = false, .boosted = false, .is_focus = true },
    };
    // A WIDE layout so the focus post is on-screen and the body is drawn.
    _ = try layout(gpa, &engine, 1280, 940, &posts, 0, &dl, &regions, null, true, screen_thread, null, 0, accent_house, null, .{}, null, null, &sel, "", .{}, null, 0, 0, .{}, 0, 255, null, .{}, .{});
    // "hello there field" = 15 visible glyphs (spaces are emitted too): the body
    // captured into the selection map, in reading order.
    try std.testing.expect(sel.items.len > 0);
    try std.testing.expectEqual(@as(u32, 'h'), sel.items[0].cp);

    // A non-thread screen captures nothing (only the rooted post is selectable).
    _ = try layout(gpa, &engine, 1280, 940, &posts, 0, &dl, &regions, null, true, screen_home, null, 0, accent_house, null, .{}, null, null, &sel, "", .{}, null, 0, 0, .{}, 0, 255, null, .{}, .{});
    try std.testing.expectEqual(@as(usize, 0), sel.items.len);
}

test "layoutCompose emits send + cancel regions; multi-line draft + empty draft both render" {
    const gpa = std.testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);
    var regions: Regions = .empty;
    defer regions.deinit(gpa);

    // A reply draft spanning an explicit newline (Enter inserts '\n').
    const draft_ml = "line one\nline two is a bit longer so it wraps";
    try layoutCompose(gpa, &engine, 1300, 900, accent_house, .reply, "@mara.zat", "", draft_ml, 5, 9, 17, true, "", &.{}, .{}, &dl, &regions);
    try std.testing.expect(dl.len > 0);
    var saw_send = false;
    var saw_cancel = false;
    for (regions.items) |r| {
        if (r.kind == .compose_send) saw_send = true;
        if (r.kind == .compose_cancel) saw_cancel = true;
    }
    try std.testing.expect(saw_send);
    try std.testing.expect(saw_cancel);
    // Both buttons must hit-test back to themselves.
    for (regions.items) |r| {
        const cxp = @as(i32, r.x) + @divTrunc(@as(i32, r.w), 2);
        const cyp = @as(i32, r.y) + @divTrunc(@as(i32, r.h), 2);
        const hit = hitTest(regions.items, cxp, cyp) orelse return error.NoHit;
        try std.testing.expectEqual(r.kind, hit.kind);
    }

    // The TAG BAR: a locked zone chip (no ×), one manual chip (its × emits
    // .compose_tag_remove with the chip index), an inline mirror (no ×), and
    // the "+ tag" doorway (.compose_tag_add). The profile editor draws none.
    dl.len = 0;
    try layoutCompose(gpa, &engine, 1300, 900, accent_house, .post, "", "", "", 0, 0, 0, true, "", &.{}, .{ .inline_tags = &.{"water"}, .manual = &.{"rivers"}, .locked = "deep" }, &dl, &regions);
    var n_add: usize = 0;
    var n_remove: usize = 0;
    for (regions.items) |r| {
        if (r.kind == .compose_tag_add) n_add += 1;
        if (r.kind == .compose_tag_remove) {
            try std.testing.expectEqual(@as(u16, 0), r.post); // the chip's index
            n_remove += 1;
        }
    }
    try std.testing.expectEqual(@as(usize, 1), n_add);
    try std.testing.expectEqual(@as(usize, 1), n_remove); // locked + inline emit NO remove

    // An empty profile draft renders the placeholder path without crashing.
    dl.len = 0;
    try layoutCompose(gpa, &engine, 700, 800, accent_house, .profile, "", "", "", 0, 0, 0, true, "saving...", &.{}, .{}, &dl, &regions);
    try std.testing.expect(dl.len > 0);
    for (regions.items) |r| {
        try std.testing.expect(r.kind != .compose_tag_add and r.kind != .compose_tag_remove);
    }

    // The inverse (click → caret offset) replays the same wrap: a click far
    // before the text lands at 0; a click far past it lands at the end.
    try std.testing.expectEqual(@as(u32, 0), composeCaretAtPoint(&engine, 1300, draft_ml, -10000, -10000));
    try std.testing.expectEqual(@as(u32, draft_ml.len), composeCaretAtPoint(&engine, 1300, draft_ml, 1_000_000, 1_000_000));
}

test "long timeline does not overflow draw coordinates (off-screen posts skipped)" {
    const gpa = std.testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);
    var regions: Regions = .empty;
    defer regions.deinit(gpa);
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    // 800 posts would push y well past the 16-bit draw coordinate limit if
    // every post were painted — this is exactly the crash from a real feed.
    const n: usize = 800;
    const posts = try arena.alloc(PostView, n);
    for (posts) |*pv| pv.* = .{ .name = "x", .handle = "@x.zat", .age = "1m", .body = "a body line that wraps a little across the feed column width here", .tint = 0xFF888888, .reply = 1, .boost = 2, .like = 3, .initial = 'x', .liked = false, .boosted = false };

    const h = try layout(gpa, &engine, 460, 940, posts, 0, &dl, &regions, null, false, screen_home, null, 0, accent_house, null, .{}, null, null, null, "", .{}, null, 0, 0, .{}, 0, 255, null, .{}, .{}); // must not panic
    try std.testing.expect(h > 940 * 10); // height accounts for the whole list
    try std.testing.expect(regions.items.len < 4 * 24); // only on-screen posts are tappable

    // The height cache (the scroll-lag fix) must yield IDENTICAL geometry. A
    // first pass with an all-(-1) cache measures + fills it; a second pass that
    // reuses the filled cache (the per-frame scroll path) must return the same
    // total height and the same tappable region set — i.e. the cached advance
    // reconstructs body_end exactly. A regression here means cached scrolling
    // would drift from a fresh layout.
    const heights = try arena.alloc(i32, n);
    @memset(heights, -1);
    dl.len = 0;
    regions.clearRetainingCapacity();
    const h_fill = try layout(gpa, &engine, 460, 940, posts, 0, &dl, &regions, heights, false, screen_home, null, 0, accent_house, null, .{}, null, null, null, "", .{}, null, 0, 0, .{}, 0, 255, null, .{}, .{});
    const fill_regions = regions.items.len;
    dl.len = 0;
    regions.clearRetainingCapacity();
    const h_cached = try layout(gpa, &engine, 460, 940, posts, 0, &dl, &regions, heights, false, screen_home, null, 0, accent_house, null, .{}, null, null, null, "", .{}, null, 0, 0, .{}, 0, 255, null, .{}, .{});
    try std.testing.expectEqual(h, h_fill);
    try std.testing.expectEqual(h, h_cached);
    try std.testing.expectEqual(fill_regions, regions.items.len);
}

test "profile screen renders the author's posts under a header; other screens stay placeholders" {
    const gpa = std.testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);
    var regions: Regions = .empty;
    defer regions.deinit(gpa);

    const posts = [_]PostView{
        .{ .name = "Connor", .handle = "@connor.zat4.com", .age = "2h", .body = "hello world", .tint = 0xFFAAAAAA, .reply = 0, .boost = 0, .like = 1, .initial = 'C', .liked = false, .boosted = false },
    };
    const header: ProfileHeader = .{ .display_name = "connor.zat4.com", .handle = "@connor.zat4.com", .post_count = 1 };

    // Profile screen: 8 post tap regions (body + avatar + reply/repost/like +
    // bookmark/share/more) + 4 profile-nav tab regions in the sticky header
    // (the header here isn't editable, so no edit-profile region).
    const hp = try layout(gpa, &engine, 460, 940, &posts, 0, &dl, &regions, null, false, screen_profile, header, 0, accent_house, null, .{}, null, null, null, "", .{}, null, 0, 0, .{}, 0, 255, null, .{}, .{});
    try std.testing.expect(hp > 112);
    try std.testing.expectEqual(@as(usize, 12), regions.items.len);

    // A non-Home, non-Profile screen is a titled placeholder: no posts render,
    // so no POST regions, and the height clamps to the viewport (no post stack).
    // On the phone header it still carries the 2 chrome regions (hamburger +
    // search), so the total is 2, not 0.
    dl.len = 0;
    regions.clearRetainingCapacity();
    const he = try layout(gpa, &engine, 460, 940, &posts, 0, &dl, &regions, null, false, 2, null, 0, accent_house, null, .{}, null, null, null, "", .{}, null, 0, 0, .{}, 0, 255, null, .{}, .{}); // Activity (a still-bare placeholder)
    try std.testing.expectEqual(@as(i32, 940), he);
    try std.testing.expectEqual(@as(usize, 2), regions.items.len);

    // The Settings screen is now a master–detail surface (driven by the
    // settings_view table): one tap region per SECTION (left list) plus one per
    // INTERACTIVE row of the selected section (info rows aren't tappable).
    // Section 0 (Account) is selected here. Counts are derived from the table so
    // this stays green when the table is rearranged — only the SHAPE is asserted.
    dl.len = 0;
    regions.clearRetainingCapacity();
    // Narrow width (460): `m.wide` is false so the rail emits no regions — the
    // only regions are the settings surface's own, keeping the count exact.
    _ = try layout(gpa, &engine, 460, 940, &posts, 0, &dl, &regions, null, false, screen_settings, null, 0, accent_house, null, .{}, null, null, null, "", .{}, null, settings_view.sec_account, 0, .{}, 0, 255, null, .{}, .{});
    // Rows that emit a tap region: not info, and not WIP-greyed (those are inert).
    var account_interactive: usize = 0;
    for (settings_view.rows) |r| {
        if (r.section == settings_view.sec_account and r.kind != .info and (r.flags & settings_view.flag_wip) == 0) account_interactive += 1;
    }
    var n_sections: usize = 0;
    var n_sign_out: usize = 0;
    for (regions.items) |r| {
        if (r.kind == .settings_section) n_sections += 1;
        if (r.kind == .sign_out) n_sign_out += 1;
    }
    // Every section is listed, and Account's interactive rows are tappable.
    try std.testing.expectEqual(settings_view.sections.len, n_sections);
    try std.testing.expectEqual(settings_view.sections.len + account_interactive, regions.items.len);
    // The one wired control survives the rework: Account's Sign out still routes
    // through the live `.sign_out` handler.
    try std.testing.expectEqual(@as(usize, 1), n_sign_out);
}

test "messages screen: master-detail chat surface (list, thread, composer)" {
    const gpa = std.testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);
    var regions: Regions = .empty;
    defer regions.deinit(gpa);

    const lrows = [_]chat_view.ListRow{
        .{ .name = "maya.zat4.com", .preview = "You: hey", .age = "2h", .unread = 0 },
        .{ .name = "did:plc:xyz", .preview = "hello there", .age = "1m", .unread = 3 },
    };
    const brows = [_]chat_view.BubbleRow{
        .{ .body = "hey", .age = "2h", .mine = true, .stamp = true, .kind = .text, .tail = true },
        .{ .body = "a longer reply that should wrap across the bubble width once it exceeds the maximum line", .age = "2h", .mine = false, .stamp = false, .kind = .text, .tail = true },
    };

    // Narrow DESKTOP width (700 — above phone_max, below the wide rail): no
    // rail regions, so the counts are exactly the surface's own — one region
    // per conversation row + the composer pair + the "+ New" pill. (460 now
    // exercises the PHONE single-pane shape — its own test below.)
    const h = try layoutChat(gpa, &engine, 700, 940, &dl, &regions, accent_house, 0, false, false, null, &lrows, &brows, &.{}, 0, "maya.zat4.com", "", .{}, true, false, "", "", .{}, .{}, &.{}, .{}, .{}, .{});
    var n_conv: usize = 0;
    var n_input: usize = 0;
    var n_send: usize = 0;
    var n_new: usize = 0;
    var n_pay: usize = 0;
    for (regions.items) |r| {
        if (r.kind == .chat_conv) n_conv += 1;
        if (r.kind == .chat_input) n_input += 1;
        if (r.kind == .chat_send) n_send += 1;
        if (r.kind == .chat_new) n_new += 1;
        if (r.kind == .pay_open) n_pay += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), n_conv);
    try std.testing.expectEqual(@as(usize, 1), n_input);
    try std.testing.expectEqual(@as(usize, 1), n_send);
    try std.testing.expectEqual(@as(usize, 1), n_new);
    try std.testing.expectEqual(@as(usize, 1), n_pay); // the pay button (M5 A4)
    try std.testing.expectEqual(regions.items.len, n_conv + n_input + n_send + n_new + n_pay);
    try std.testing.expect(h >= 940); // viewport + any thread overflow
    try std.testing.expect(dl.len > 0);

    // No conversation selected: the list still renders and taps, but there is
    // no thread pane and no composer to arm. The "+ New" pill is always there.
    dl.len = 0;
    regions.clearRetainingCapacity();
    const h2 = try layoutChat(gpa, &engine, 700, 940, &dl, &regions, accent_house, 0, false, false, null, &lrows, &.{}, &.{}, 255, "", "", .{}, false, false, "", "", .{}, .{}, &.{}, .{}, .{}, .{});
    try std.testing.expectEqual(@as(i32, 940), h2);
    var n2_conv: usize = 0;
    var n2_new: usize = 0;
    for (regions.items) |r| {
        if (r.kind == .chat_conv) n2_conv += 1;
        if (r.kind == .chat_new) n2_new += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), n2_conv);
    try std.testing.expectEqual(@as(usize, 1), n2_new);
    try std.testing.expectEqual(regions.items.len, n2_conv + n2_new);

    // Composing: the recipient bar renders with its input region; the status
    // line draws when the shell hands one over.
    dl.len = 0;
    regions.clearRetainingCapacity();
    _ = try layoutChat(gpa, &engine, 700, 940, &dl, &regions, accent_house, 0, false, false, null, &lrows, &.{}, &.{}, 255, "", "", .{}, false, true, "chattest.zat4.com", "Couldn't resolve that handle", .{}, .{}, &.{}, .{}, .{}, .{});
    var n3_compose: usize = 0;
    for (regions.items) |r| {
        if (r.kind == .chat_compose_input) n3_compose += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), n3_compose);

    // Motion (U6a): an at-rest frame and a fully-animating one (mid-send +
    // grown typing indicator) both render clean; the typing bubble and its
    // dots ADD draw items over the at-rest frame; regions are unaffected
    // (motion never moves a tap target).
    dl.len = 0;
    regions.clearRetainingCapacity();
    _ = try layoutChat(gpa, &engine, 700, 940, &dl, &regions, accent_house, 0, false, false, null, &lrows, &brows, &.{}, 0, "maya.zat4.com", "", .{}, true, false, "", "", .{}, .{}, &.{}, .{}, .{}, .{});
    const rest_items = dl.len;
    const rest_regions = regions.items.len;
    dl.len = 0;
    regions.clearRetainingCapacity();
    _ = try layoutChat(gpa, &engine, 700, 940, &dl, &regions, accent_house, 0, false, false, null, &lrows, &brows, &.{}, 0, "maya.zat4.com", "", .{}, true, false, "", "", .{}, .{ .typing_t = 1, .typing_phase = 0.7 }, &.{}, .{}, .{}, .{});
    try std.testing.expect(dl.len > rest_items);
    try std.testing.expectEqual(rest_regions, regions.items.len);
}

test "messages screen: the phone shape — list page, then an immersive thread with back" {
    const gpa = std.testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);
    var regions: Regions = .empty;
    defer regions.deinit(gpa);

    const lrows = [_]chat_view.ListRow{
        .{ .name = "maya.zat4.com", .preview = "You: hey", .age = "2h", .unread = 0 },
        .{ .name = "did:plc:xyz", .preview = "hello there", .age = "1m", .unread = 3 },
    };
    const brows = [_]chat_view.BubbleRow{
        .{ .body = "hey", .age = "2h", .mine = true, .stamp = true, .kind = .text, .tail = true },
    };

    // LIST page (no peer): full-width rows + the new-conversation button; no
    // composer, no thread chrome, no back — the tab bar is the way out.
    _ = try layoutChat(gpa, &engine, 430, 940, &dl, &regions, accent_house, 0, false, false, null, &lrows, &.{}, &.{}, 255, "", "", .{}, false, false, "", "", .{}, .{}, &.{}, .{}, .{ .top = 48 }, .{});
    var l_conv: usize = 0;
    var l_new: usize = 0;
    var l_back: usize = 0;
    for (regions.items) |r| {
        if (r.kind == .chat_conv) l_conv += 1;
        if (r.kind == .chat_new) l_new += 1;
        if (r.kind == .back) l_back += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), l_conv);
    try std.testing.expectEqual(@as(usize, 1), l_new);
    try std.testing.expectEqual(@as(usize, 0), l_back);

    // THREAD page (peer open): immersive — NO list rows, NO new button; the
    // app-bar's back region + the composer trio are the page's controls.
    dl.len = 0;
    regions.clearRetainingCapacity();
    _ = try layoutChat(gpa, &engine, 430, 940, &dl, &regions, accent_house, 0, false, false, null, &lrows, &brows, &.{}, 0, "maya.zat4.com", "", .{}, true, false, "", "", .{}, .{}, &.{}, .{}, .{ .top = 48, .bottom = 34 }, .{});
    var t_conv: usize = 0;
    var t_new: usize = 0;
    var t_back: usize = 0;
    var t_input: usize = 0;
    var t_send: usize = 0;
    for (regions.items) |r| {
        if (r.kind == .chat_conv) t_conv += 1;
        if (r.kind == .chat_new) t_new += 1;
        if (r.kind == .back) t_back += 1;
        if (r.kind == .chat_input) t_input += 1;
        if (r.kind == .chat_send) t_send += 1;
    }
    try std.testing.expectEqual(@as(usize, 0), t_conv);
    try std.testing.expectEqual(@as(usize, 0), t_new);
    try std.testing.expectEqual(@as(usize, 1), t_back);
    try std.testing.expectEqual(@as(usize, 1), t_input);
    try std.testing.expectEqual(@as(usize, 1), t_send);
}

test "messages screen: payment cards and the pay sheet emit their regions (M5 A4)" {
    const gpa = std.testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);
    var regions: Regions = .empty;
    defer regions.deinit(gpa);

    const lrows = [_]chat_view.ListRow{
        .{ .name = "maya.zat4.com", .preview = "Payment request · 5000 sats", .age = "2h", .unread = 0 },
    };
    // A peer's open request (offers Pay), our pending send (offers Cancel),
    // our own request (offers Mark received), and a confirming card (the
    // six-block row, no action).
    const brows = [_]chat_view.BubbleRow{
        .{ .body = "dinner", .age = "2h", .mine = false, .stamp = true, .kind = .payment_request, .tail = true, .pay = 0 },
        .{ .body = "", .age = "1h", .mine = true, .stamp = false, .kind = .payment_sent, .tail = true, .pay = 1 },
        .{ .body = "rent", .age = "1h", .mine = true, .stamp = false, .kind = .payment_request, .tail = true, .pay = 2 },
        .{ .body = "", .age = "1h", .mine = true, .stamp = false, .kind = .payment_sent, .tail = true, .pay = 3 },
    };
    const cards = [_]chat_view.PayCard{
        .{ .payment_id = 1, .amount_sat = 5000, .rail = .lightning, .status = .requested, .confirmations = 0 },
        .{ .payment_id = 2, .amount_sat = 21_000, .rail = .onchain, .status = .pending, .confirmations = 0 },
        .{ .payment_id = 3, .amount_sat = 250_000, .rail = .lightning, .status = .requested, .confirmations = 0 },
        .{ .payment_id = 4, .amount_sat = 9_000, .rail = .onchain, .status = .confirming, .confirmations = 3 },
    };

    // Sheet closed: the card buttons carry their thread ordinals.
    _ = try layoutChat(gpa, &engine, 900, 940, &dl, &regions, accent_house, 0, false, false, null, &lrows, &brows, &cards, 0, "maya.zat4.com", "", .{}, false, false, "", "", .{}, .{}, &.{}, .{}, .{}, .{});
    var pay_at: u16 = 999;
    var cancel_at: u16 = 999;
    var received_at: u16 = 999;
    for (regions.items) |r| {
        if (r.kind == .pay_card_pay) pay_at = r.post;
        if (r.kind == .pay_card_cancel) cancel_at = r.post;
        if (r.kind == .pay_card_received) received_at = r.post;
    }
    try std.testing.expectEqual(@as(u16, 0), pay_at);
    try std.testing.expectEqual(@as(u16, 1), cancel_at);
    try std.testing.expectEqual(@as(u16, 2), received_at);

    // Sheet open: rail toggle ×2, chips ×4, the two inputs, three verbs —
    // and the amber status line renders without disturbing the regions.
    dl.len = 0;
    regions.clearRetainingCapacity();
    _ = try layoutChat(gpa, &engine, 900, 940, &dl, &regions, accent_house, 0, false, false, null, &lrows, &brows, &cards, 0, "maya.zat4.com", "", .{}, false, false, "", "", .{ .open = true, .rail = .onchain, .amount = "5000", .note = "dinner", .status = "They haven't set up payments" }, .{}, &.{}, .{}, .{}, .{});
    var n_rail: usize = 0;
    var n_chip: usize = 0;
    var n_amount: usize = 0;
    var n_note: usize = 0;
    var n_req: usize = 0;
    var n_sendv: usize = 0;
    var n_cancel: usize = 0;
    for (regions.items) |r| {
        switch (r.kind) {
            .pay_rail => n_rail += 1,
            .pay_chip => n_chip += 1,
            .pay_amount => n_amount += 1,
            .pay_note => n_note += 1,
            .pay_request => n_req += 1,
            .pay_arm => n_sendv += 1, // compose "Send" now arms the confirm face
            .pay_cancel => n_cancel += 1,
            else => {},
        }
    }
    try std.testing.expectEqual(@as(usize, 2), n_rail);
    try std.testing.expectEqual(@as(usize, 4), n_chip);
    try std.testing.expectEqual(@as(usize, 1), n_amount);
    try std.testing.expectEqual(@as(usize, 1), n_note);
    try std.testing.expectEqual(@as(usize, 1), n_req);
    try std.testing.expectEqual(@as(usize, 1), n_sendv);
    try std.testing.expectEqual(@as(usize, 1), n_cancel);
}

test "zones browse: each catalog entry emits one .zone_open card region carrying its index" {
    const gpa = std.testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);
    var regions: Regions = .empty;
    defer regions.deinit(gpa);

    const posts = [_]PostView{}; // the browse screen ignores posts entirely
    const zones = [_]ZoneCard{
        .{ .tag = "deep", .count = 2481 },
        .{ .tag = "zig", .count = 913 },
        .{ .tag = "small-net", .count = 1 },
    };
    const h = try layout(gpa, &engine, 1280, 940, &posts, 0, &dl, &regions, null, false, screen_zones_browse, null, 0, accent_house, null, .{}, null, null, null, "", .{ .cards = &zones }, null, 0, 0, .{}, 0, 255, null, .{}, .{});
    try std.testing.expect(h > 0);
    // Each card emits `.zone_open` (whole card) AND `.zone_pin` (its bookmark)
    // carrying the same catalog index; the pin is emitted after so it wins the
    // overlap under `hitTest`'s last-match rule.
    var card_idx: u16 = 0;
    var pin_idx: u16 = 0;
    for (regions.items) |r| {
        if (r.kind == .zone_open) {
            try std.testing.expectEqual(card_idx, r.post);
            card_idx += 1;
        } else if (r.kind == .zone_pin) {
            try std.testing.expectEqual(pin_idx, r.post);
            pin_idx += 1;
        }
    }
    try std.testing.expectEqual(@as(u16, zones.len), card_idx);
    try std.testing.expectEqual(@as(u16, zones.len), pin_idx);
    // The live chrome emits its regions too: three tab targets + the search field.
    var n_tabs: usize = 0;
    var n_search: usize = 0;
    for (regions.items) |r| {
        if (r.kind == .zone_tab) n_tabs += 1;
        if (r.kind == .zone_search) n_search += 1;
    }
    try std.testing.expectEqual(@as(usize, 3), n_tabs);
    try std.testing.expectEqual(@as(usize, 1), n_search);
}

test "zones hub: search filters the browse grid; the pinned tab shows only pins; trending ranks by velocity" {
    const gpa = std.testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);
    var regions: Regions = .empty;
    defer regions.deinit(gpa);

    const posts = [_]PostView{};
    const zones = [_]ZoneCard{
        .{ .tag = "water", .count = 10, .recent = 5, .pinned = true },
        .{ .tag = "zig", .count = 8, .recent = 0 },
        .{ .tag = "waterfowl", .count = 2, .recent = 1 },
    };

    // Search "water" on Browse: only the two matching cards emit regions.
    _ = try layout(gpa, &engine, 1280, 940, &posts, 0, &dl, &regions, null, false, screen_zones_browse, null, 0, accent_house, null, .{}, null, null, null, "", .{ .cards = &zones, .query = "water" }, null, 0, 0, .{}, 0, 255, null, .{}, .{});
    var opens: usize = 0;
    for (regions.items) |r| {
        if (r.kind != .zone_open) continue;
        try std.testing.expect(r.post == 0 or r.post == 2); // water + waterfowl, catalog indices intact
        opens += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), opens);

    // The Pinned tab: only the pinned card.
    _ = try layout(gpa, &engine, 1280, 940, &posts, 0, &dl, &regions, null, false, screen_zones_browse, null, 0, accent_house, null, .{}, null, null, null, "", .{ .cards = &zones, .tab = 1, .tab_t = 1 }, null, 0, 0, .{}, 0, 255, null, .{}, .{});
    opens = 0;
    for (regions.items) |r| {
        if (r.kind != .zone_open) continue;
        try std.testing.expectEqual(@as(u16, 0), r.post);
        opens += 1;
    }
    try std.testing.expectEqual(@as(usize, 1), opens);

    // Trending: only zones that moved in the window (recent > 0) list.
    _ = try layout(gpa, &engine, 1280, 940, &posts, 0, &dl, &regions, null, false, screen_zones_browse, null, 0, accent_house, null, .{}, null, null, null, "", .{ .cards = &zones, .tab = 2, .tab_t = 2 }, null, 0, 0, .{}, 0, 255, null, .{}, .{});
    opens = 0;
    for (regions.items) |r| {
        if (r.kind != .zone_open) continue;
        try std.testing.expect(r.post == 0 or r.post == 2); // zig (recent 0) never trends
        opens += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), opens);
}

test "zones: sortZonesByActivity ranks by 24h velocity, then size, then recency" {
    var cards = [_]ZoneCard{
        .{ .tag = "b-quiet", .count = 100, .recent = 0, .last_at = 50 },
        .{ .tag = "a-alive", .count = 3, .recent = 2, .last_at = 900 },
        .{ .tag = "c-alive", .count = 9, .recent = 2, .last_at = 100 },
        .{ .tag = "d-dead", .count = 1, .recent = 0, .last_at = 0 },
    };
    sortZonesByActivity(&cards);
    try std.testing.expectEqualStrings("c-alive", cards[0].tag); // same velocity → bigger first
    try std.testing.expectEqualStrings("a-alive", cards[1].tag);
    try std.testing.expectEqualStrings("b-quiet", cards[2].tag); // quiet: size beats recency
    try std.testing.expectEqualStrings("d-dead", cards[3].tag);
}

test "zones: the masthead collapse is a pure function of scroll — pixel-perfect return" {
    // At rest: the tall masthead. Fully scrolled: the thin bar. And the same
    // scroll always yields the same height (returning to top restores 250).
    try std.testing.expectEqual(zone_header_h_wide, zoneHeaderH(0, true));
    try std.testing.expectEqual(zone_thin_h_wide, zoneHeaderH(-10_000, true));
    try std.testing.expectEqual(zone_header_h_narrow, zoneHeaderH(0, false));
    try std.testing.expectEqual(zone_thin_h_narrow, zoneHeaderH(-10_000, false));
    // Monotonic through the travel; scrolling back up retraces exactly.
    var prev: i32 = zoneHeaderH(0, true);
    var s: i32 = 0;
    while (s >= -220) : (s -= 20) {
        const h = zoneHeaderH(s, true);
        try std.testing.expect(h <= prev);
        prev = h;
    }
    try std.testing.expectEqual(zone_header_h_wide, zoneHeaderH(0, true)); // the return trip
    try std.testing.expectEqual(@as(f32, 0.0), zoneCollapseT(0, true));
    try std.testing.expectEqual(@as(f32, 1.0), zoneCollapseT(-10_000, true));
}

test "zones: activityLabel buckets — just now, minutes, hours, days, quiet weeks" {
    var buf: [40]u8 = undefined;
    try std.testing.expectEqualStrings("active just now", activityLabel(&buf, 1000, 950));
    try std.testing.expectEqualStrings("active 5m ago", activityLabel(&buf, 1300, 1000));
    try std.testing.expectEqualStrings("active 3h ago", activityLabel(&buf, 100_000, 100_000 - 3 * 3600 - 10));
    try std.testing.expectEqualStrings("active 2d ago", activityLabel(&buf, 1_000_000, 1_000_000 - 2 * 86400 - 60));
    try std.testing.expectEqualStrings("quiet for 3w", activityLabel(&buf, 10_000_000, 10_000_000 - 3 * 7 * 86400 - 60));
    try std.testing.expectEqualStrings("", activityLabel(&buf, 100, 0)); // unknown stays silent
    try std.testing.expectEqualStrings("", activityLabel(&buf, 100, 200)); // future = clock skew, stay silent
}

test "wrapBody honours explicit newlines as hard line breaks" {
    const gpa = std.testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);

    const line_h: i32 = 24;
    const wide: i32 = 4000; // wide enough that nothing soft-wraps
    // The same words on one line vs split across three hard breaks.
    const one = try wrapBody(gpa, &dl, &engine, 0, 0, wide, ink, 16, "alpha beta gamma", line_h, false, null);
    const three = try wrapBody(gpa, &dl, &engine, 0, 0, wide, ink, 16, "alpha\nbeta\ngamma", line_h, false, null);
    try std.testing.expectEqual(line_h, one);
    try std.testing.expectEqual(@as(i32, line_h * 3), three);
    // A blank line (consecutive newlines) is kept as its own line.
    const blank = try wrapBody(gpa, &dl, &engine, 0, 0, wide, ink, 16, "a\n\nb", line_h, false, null);
    try std.testing.expectEqual(@as(i32, line_h * 3), blank);
}

test "inline #tags emit tappable .tag_inline regions, resolved case-insensitively to the post's tags" {
    const gpa = std.testing.allocator;
    var engine = try text.initEngine();
    defer text.deinitEngine(gpa, &engine);
    var dl: raster.DrawList = .{};
    defer dl.deinit(gpa);
    var regions: Regions = .empty;
    defer regions.deinit(gpa);

    const tags = [_][]const u8{ "deep", "smallweb" };
    const style: BodyTags = .{ .color = tag_blue, .regions = &regions, .pi = 7, .tags = &tags };
    // Two inline tags; the second is cased differently than the served tag.
    _ = try wrapBody(gpa, &dl, &engine, 0, 0, 4000, body_c, 16, "go #deep then #SmallWeb ok", 24, true, &style);

    var pads: [4]u8 = .{ 255, 255, 255, 255 };
    var n: usize = 0;
    for (regions.items) |r| {
        if (r.kind != .tag_inline) continue;
        try std.testing.expectEqual(@as(u16, 7), r.post); // the post index rides through
        if (n < pads.len) pads[n] = r._pad;
        n += 1;
    }
    try std.testing.expectEqual(@as(usize, 2), n);
    try std.testing.expectEqual(@as(u8, 0), pads[0]); // #deep → tags[0]
    try std.testing.expectEqual(@as(u8, 1), pads[1]); // #SmallWeb → tags[1] (case-insensitive)
}
