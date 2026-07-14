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

//! B1 classification: SHELL. The **renderer deep module**, file 3 of 3:
//! the terminal session — the ONLY file in the program where a tty, raw
//! mode, the wall clock, and stdin/stdout bytes exist (B3).
//!
//! The loop is the imperative-shell sandwich, once per frame:
//!   shell: read terminal size, read the clock, read input bytes
//!   core:  buildTimeline (feed) -> buildFrame (screen) -> encodeDiff (ANSI)
//!   shell: write the bytes
//! Per-frame work lives in one arena reset every iteration — C3's
//! "per-frame arena" taken literally.
//!
//! POSIX-only by recorded decision: terminal control IS a platform API,
//! and this is the renderer's shell — a Windows console or GPU renderer is
//! a future sibling behind the same view-model boundary (D1 contains the
//! swap to this module). There is no automated test in this file: it is
//! ~150 lines of choreography over a tty the test runner does not have;
//! every decision it choreographs is tested in the two core files. The
//! terminal is ALWAYS restored — raw mode and the alternate screen are
//! released by defers that run on success, error, and quit alike (C5).

const std = @import("std");
const builtin = @import("builtin");
const posix = std.posix;
const Allocator = std.mem.Allocator;
const tui = @import("../core/tui.zig");
const timeline_ui = @import("../core/timeline_ui.zig");
const feed_core = @import("../core/feed.zig");
const chat_core = @import("../core/chat.zig");
const chat_view_core = @import("../core/chat_view.zig");
const spring = @import("../core/spring.zig");
const shatter = @import("../core/shatter.zig");
const pet_core = @import("../core/pet.zig");
const gesture = @import("../core/gesture.zig");
const chat_relay = @import("chat_relay.zig");
const chat_e2ee = @import("chat_e2ee.zig");
const chat_keys = @import("chat_keys.zig"); // multi-device: ask / approve / who is waiting
const enroll_view = @import("../core/enroll_view.zig");
const boot_intro = @import("../core/boot_intro.zig"); // the signed-out boot entrance (§5)
const enroll_run = @import("enroll_run.zig");
const membership_shell = @import("membership.zig");
const membership_record = @import("membership_record.zig");
const pay_addr = @import("pay_addr.zig");
const lnurl = @import("lnurl.zig");
const wallet_caps = @import("../core/wallet_caps.zig");
const http = @import("http.zig");
const payuri = @import("../core/payuri.zig");
const launch = @import("launch.zig");
const chainwatch_core = @import("../core/chainwatch.zig");
const chainwatch_shell = @import("chainwatch.zig");
const anchor_core = @import("../core/anchor.zig");
const feed_shell = @import("feed.zig");
const stream_shell = @import("stream.zig");
const cache_shell = @import("cache.zig");
const xrpc = @import("xrpc.zig");
const window_shell = @import("native.zig");
const mobile_host = @import("mobile_host.zig");
const gpu = @import("gpu.zig");
const glyph_field = @import("../core/glyph_field.zig");
const layout_core = @import("../core/layout.zig");
const raster_core = @import("../core/raster.zig");
const text_core = @import("../core/text.zig");
const field_core = @import("../core/field.zig");
const field_ui = @import("../core/field_ui.zig");
const feed_view = @import("../core/feed_view.zig");
const pin_store = @import("../core/zone_pins.zig");
const compose_core = @import("../core/compose.zig");
const settings_view = @import("../core/settings_view.zig");
const kbd_lm = @import("../core/kbd_lm.zig");
const emoji_atlas = @import("../core/emoji_atlas.zig");
const text_select = @import("../core/text_select.zig");
const textedit = @import("../core/textedit.zig");
const lens_socket = @import("../core/lens_socket.zig");
const lens_catalog = @import("../core/lens_catalog.zig");
const discover = @import("../core/discover.zig");
const create_flow = @import("../core/create_flow.zig");
const dev_flow = @import("../core/dev_flow.zig");
const zal_templates = @import("../core/zal_templates.zig");
const algo_gate = @import("../core/algo_gate.zig");
const algo_docs = @import("../core/algo_docs.zig");
const builder = @import("../core/builder.zig");
const algo_library = @import("../core/algo_library.zig");
const transparency = @import("../core/transparency.zig");
const algorithm_core = @import("../core/algorithm.zig");
const algorithm_shell = @import("algorithm.zig");
// The DID→PDS resolver: a marketplace author's repo lives on THEIR PDS (any
// host in the network), so the inspect fetch must resolve the DID document's
// service endpoint — never assume the session PDS (the cross-PDS install bug).
const identity_shell = @import("identity.zig");
const dist_config = @import("dist_config");
const loadout_store = @import("loadout.zig");
const effect_core = @import("../core/effect.zig");
const clock_shell = @import("clock.zig");
const write = @import("write.zig");
const write_worker = @import("write_worker.zig");
const refresh_worker = @import("refresh_worker.zig");
const view_worker = @import("view_worker.zig");
const auth = @import("auth.zig");
const lexicon = @import("../core/lexicon.zig");
const moderation = @import("../core/moderation.zig");

/// DIAGNOSTIC flag (temporary): when true, `fireEngageEffect` prints one
/// stderr line per effect actually fired, so the fire count of a single click
/// can be read on the real machine (there is no live GUI to watch in the
/// build/test environment). Compile-time, so it is free when false and breaks
/// no rule — it is not a mutable global and not a getenv (which 0.16 lacks).
/// Set to false to silence once the question of "how many effects fire?" is
/// settled.
const debug_effects = true;
// G1/G2: flip to true to print per-phase wall-clock every frame — build
// (compose + content layout) vs present (raster.paint + blit) — so the
// burst cost is MEASURED on the real machine, not guessed, before any
// optimization. Zero cost when false (the branch folds away).
const debug_frame_timing = false;
/// Zat Chat (ZAT_CHAT_ROADMAP): route the Messages rail slot to the chat
/// surface. FEATURE GATE — the transport (relay), E2EE core (MLS), and
/// persistence are all real now (M1); this flag gates a still-maturing
/// feature (no compose-new-conversation UI yet — ZAT4_CHAT_PEER is the
/// entry point — and the iOS-grade motion of U6a is pending). Off ⇒
/// Messages stays the titled placeholder.
const dev_chat = true;

/// Run the timeline screen until the user quits. The store may arrive
/// empty; `r` loads pages. Network calls happen inline between frames —
/// the "loading" frame is painted first, so the wait is visible, not a
/// freeze without explanation. (A streaming/async loop is Phase 7's
/// firehose work.)
/// Open the live stream for the authors the store has met (capped at 64;
/// the follow-graph subscription is the recorded upgrade). Returns null on
/// any non-OOM failure — a stream that won't start is a status line, never
/// a dead screen (E2).
/// The subscription list: the session's OWN did first — your own posts
/// are the one live source you can summon on demand, and they were
/// structurally absent before — then the authors the store has met.
fn composeSubscription(
    arena: Allocator,
    session_did: []const u8,
    store: *feed_core.Store,
    max_authors: usize,
) error{OutOfMemory}![]const []const u8 {
    const authors = try feed_core.authorDids(arena, store, max_authors);
    var dids = try arena.alloc([]const u8, authors.len + 1);
    dids[0] = session_did;
    var count: usize = 1;
    for (authors) |did| {
        if (std.mem.eql(u8, did, session_did)) continue;
        dids[count] = did;
        count += 1;
    }
    return dids[0..count];
}

fn startLiveStream(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session_did: []const u8,
    store: *feed_core.Store,
    mailbox: *stream_shell.Mailbox,
    arena: Allocator,
) error{OutOfMemory}!?*stream_shell.Stream {
    const dids = try composeSubscription(arena, session_did, store, 255);
    const default_host = "jetstream2.us-east.bsky.network";
    const host = if (environ) |env|
        env.get("ZAT_JETSTREAM") orelse default_host
    else
        default_host;
    // Transcript DEFAULT ON (diagnostic phase, recorded): zat-stream.log
    // in the working directory; ZAT_STREAM_LOG overrides; "off" disables.
    const requested = if (environ) |env| env.get("ZAT_STREAM_LOG") else null;
    const chosen = requested orelse "zat-stream.log";
    const log_path: ?[]const u8 = if (std.mem.eql(u8, chosen, "off")) null else chosen;
    return stream_shell.start(gpa, io, mailbox, host, 443, true, dids, log_path) catch |err| switch (err) {
        error.OutOfMemory => error.OutOfMemory,
        else => null,
    };
}

/// The rendering-backend decision (D1), sealed to a two-way switch: the
/// SAME loop, screens, and input decoder serve a tty or an X11 window.
/// The window pretends to be a terminal (cells out, key bytes in); the
/// loop never learns the difference.
/// A7.2: cold union, size guard waived — exactly one per app run.
pub const Backend = union(enum) {
    terminal,
    window: *window_shell.Window,
    /// An OS-owned surface (a phone): the OS runs the loop and calls
    /// stepFrame per vsync; input arrives through the C-ABI seam into the
    /// host's queue (M_CORE_INVERSION MC.4b). GPU-only by design — the
    /// software cell renderer never runs here (the ARGB-blit fallback is
    /// the roadmap's simulator story, not this arm's).
    mobile: *mobile_host.MobileHost,
};

/// Raw terminal mode exists everywhere but Windows (v1 there is window-only:
/// the console needs SetConsoleMode, a recorded follow-up).
const has_termios = builtin.os.tag != .windows;

/// Input-idle gate (a historical note): the auto-refresh used to be a
/// SYNCHRONOUS getTimeline on the render thread, and this gate kept it from
/// freezing active navigation (the old "tap j/k, lag, then it unsticks"
/// symptom). The fetch now runs on the refresh worker's thread, so nothing
/// blocks either way — the gate is kept because it is still the right
/// POLICY: while the user is actively navigating there is no reason to
/// churn the store under them; the poll waits the few hundred ms until
/// they pause. (G4: the network stays exiled off the input path.)
const input_idle_gate_nanos: u64 = 600 * std.time.ns_per_ms;

/// Pull-to-refresh: crossing this much accumulated overscroll (~four wheel
/// notches) while pinned at the top of Home requests a manual refresh.
const pull_refresh_threshold: i32 = 112;

/// One marketplace catalog row (Algorithms → Marketplace tab): the full
/// gpa-owned record, incl. the author DID + rkey the "View details" fetch
/// needs. The display projection handed to the renderer is
/// `feed_view.MarketAlgoCard`.
const MarketRow = struct {
    name: []const u8,
    author_disp: []const u8, // "@handle" or the DID
    author_did: []const u8,
    rkey: []const u8,
    cid: []const u8,
    ranks: []const u8, // author prose (schema rev)
    desc: []const u8,
    tags: []const u8, // joined ", "
    learns: bool,
    uses_behavioral: bool,
    designed: u8, // declared-surface bitmask
    state_budget_bytes: u32,

    comptime {
        // A7.1: budget raised 88 → 136 for the schema rev — three more slices
        // (ranks/desc/tags, 48) + the designed byte (packs into the existing
        // bool/u32 tail padding). Eight slices (128) + 2 bools + u8 + u32 =
        // 135, padded to 136. A small catalog, still a guarded collection row.
        std.debug.assert(@sizeOf(MarketRow) == 136);
    }
};

/// Refill the marketplace catalog + its display projection from a fetched
/// browse page — factored so the view-load drain handles its OOM (the only
/// error) in one place. Owned copies of every string; the cards' strings
/// point into the catalog rows, which are stable until the next refill
/// clears them.
fn refillMarket(
    gpa: Allocator,
    algos: []const lexicon.AlgorithmView,
    catalog: *std.ArrayList(MarketRow),
    cards: *std.ArrayList(feed_view.MarketAlgoCard),
) error{OutOfMemory}!void {
    for (catalog.items) |r| {
        gpa.free(r.name);
        gpa.free(r.author_disp);
        gpa.free(r.author_did);
        gpa.free(r.rkey);
        gpa.free(r.cid);
        gpa.free(r.ranks);
        gpa.free(r.desc);
        gpa.free(r.tags);
    }
    catalog.clearRetainingCapacity();
    for (algos) |a| {
        const author_disp = if (a.handle.len > 0)
            try std.fmt.allocPrint(gpa, "@{s}", .{a.handle})
        else
            try gpa.dupe(u8, a.author);
        // The declared surfaces, back to the compact mask the client renders.
        var designed: u8 = 0;
        for (a.designedFor) |n| {
            if (std.mem.eql(u8, n, "feed")) {
                designed |= 1;
            } else if (std.mem.eql(u8, n, "replies")) {
                designed |= 2;
            } else if (std.mem.eql(u8, n, "zones")) {
                designed |= 4;
            }
        }
        try catalog.append(gpa, .{
            .name = try gpa.dupe(u8, a.name),
            .author_disp = author_disp,
            .author_did = try gpa.dupe(u8, a.author),
            .rkey = try gpa.dupe(u8, a.rkey),
            .cid = try gpa.dupe(u8, a.cid),
            .ranks = try gpa.dupe(u8, a.ranks),
            .desc = try gpa.dupe(u8, a.desc),
            .tags = try gpa.dupe(u8, a.tags),
            .learns = a.learns,
            .uses_behavioral = a.usesBehavioral,
            .designed = designed,
            .state_budget_bytes = a.stateBudgetBytes,
        });
    }
    cards.clearRetainingCapacity();
    for (catalog.items) |r| try cards.append(gpa, .{
        .name = r.name,
        .author = r.author_disp,
        .ranks = r.ranks,
        .designed = r.designed,
        .learns = r.learns,
        .uses_behavioral = r.uses_behavioral,
        .state_budget_bytes = r.state_budget_bytes,
    });
}

/// Case-insensitive substring over the fields the search box promises
/// (name / creator / one-liner / tags). Empty query matches everything.
fn marketRowMatches(r: MarketRow, q: []const u8) bool {
    if (q.len == 0) return true;
    return std.ascii.indexOfIgnoreCase(r.name, q) != null or
        std.ascii.indexOfIgnoreCase(r.author_disp, q) != null or
        std.ascii.indexOfIgnoreCase(r.ranks, q) != null or
        std.ascii.indexOfIgnoreCase(r.tags, q) != null;
}

/// Rebuild the FILTERED browse view (cards + the position->catalog map) from
/// the catalog and the current search draft. Runs on refill and per search
/// keystroke — the catalog is one browse page, the rebuild is trivial.
fn refilterMarket(rs: *RunState) void {
    const gpa = rs.gpa;
    const q = rs.gmarket_q_buf[0..rs.gmarket_q_len];
    rs.market_cards.clearRetainingCapacity();
    rs.gmarket_map.clearRetainingCapacity();
    for (rs.market_catalog.items, 0..) |r, ri| {
        if (!marketRowMatches(r, q)) continue;
        // The capability chip (feed_view.market_filters order).
        const cap_ok = switch (rs.gmarket_filter) {
            1 => !r.uses_behavioral,
            2 => r.learns,
            3 => r.uses_behavioral,
            else => true,
        };
        if (!cap_ok) continue;
        rs.market_cards.append(gpa, .{
            .name = r.name,
            .author = r.author_disp,
            .ranks = r.ranks,
            .designed = r.designed,
            .learns = r.learns,
            .uses_behavioral = r.uses_behavioral,
            .state_budget_bytes = r.state_budget_bytes,
        }) catch break;
        rs.gmarket_map.append(gpa, @intCast(ri)) catch break;
    }
}

/// A filtered browse position back to its catalog row (bounds-safe).
fn marketCatalogRow(rs: *const RunState, filtered: usize) ?usize {
    if (filtered >= rs.gmarket_map.items.len) return null;
    const row = rs.gmarket_map.items[filtered];
    if (row >= rs.market_catalog.items.len) return null;
    return row;
}

/// Install a marketplace algorithm into the local library: the catalog row's
/// prose + the serialized config (already validated by the fetch path), id =
/// the record CID (A5/A8 — the same identity everywhere), a stable
/// cid-derived accent. Dedup rides algo_library.add.
fn installMarketAlgo(rs: *RunState, environ: ?*const std.process.Environ.Map, row: usize, config_bytes: []const u8) void {
    const gpa = rs.gpa;
    if (row >= rs.market_catalog.items.len or config_bytes.len == 0) return;
    const r = rs.market_catalog.items[row];
    const new: algo_library.NewAlgo = .{
        .id = r.cid,
        .name = r.name,
        .ranks = r.ranks,
        .desc = r.desc,
        .creator = r.author_disp,
        .config = config_bytes,
        .color = @intCast(std.hash.Wyhash.hash(0, r.cid) % lens_socket.palette.len),
        .designed = r.designed, // the record's declaration rides into the library
        .visibility = .private, // in MY library; "public" means MY submission
    };
    if (rs.algo_lib.add(gpa, new)) |_| {
        _ = cache_shell.saveLibrary(gpa, environ, &rs.algo_lib);
        rs.status = "Added to your library — it's on your bench.";
    } else |_| rs.status = "Couldn't install — out of memory.";
}

/// Everything run() holds across frames — the state a frame step reads and
/// mutates, hoisted so the loop body can become a callable step
/// (M_CORE_INVERSION MC.1). Fields are in original declaration order; the
/// WHY of each lives with its assignment in initRunState, which is the old
/// setup code verbatim. Initialized IN PLACE (initRunState takes the
/// pointer) and never moved or copied afterwards: workers hold addresses of
/// the mailbox fields, `out` points into `out_writer`, and slice fields
/// (e.g. profile_target_did) point into sibling buffers at runtime.
/// A7.2: cold struct, size guard waived — exactly one per run().
const RunState = struct {
    // The run() arguments, captured for deinit + the coming stepFrame
    // (MC.2). Copies of immutable values — no divergence risk.
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    appview_url: []const u8,
    store: *feed_core.Store,
    backend: Backend,

    user_signed_out: bool,
    stdin_fd: std.Io.File.Handle,
    original_termios: ?(if (has_termios) posix.termios else void),
    out_buffer: [32 * 1024]u8,
    out_writer: std.Io.File.Writer,
    out: *std.Io.Writer,
    prev: tui.Surface,
    next: tui.Surface,
    state: timeline_ui.UiState,
    status_buf: [96]u8,
    status: []const u8,
    frame_arena: std.heap.ArenaAllocator,
    mode: Mode,
    compose_store: [1200]u8,
    compose: textedit.Field,
    caret_anchor_ns: u64,
    compose_drag: bool,
    last_click_ns: u64,
    last_click_x: i32,
    last_click_y: i32,
    click_count: u8,
    armed_kind: ?feed_view.Action,
    armed_post: u16,
    armed_legacy: bool,
    armed_cx: u16,
    armed_cy: u16,
    armed_compose: ?feed_view.Action,
    compose_arena_state: std.heap.ArenaAllocator,
    reply_target: ?write.ReplyTarget,
    reply_handle: []const u8,
    quote_target: ?lexicon.RecordRef,
    quoting_handle: []const u8,
    grepost_menu: ?u16,
    compose_kind: ComposeKind,
    pending_send: ?ChainSend,
    chain_segments: std.ArrayList([]const u8),
    pending_profile_save: ?[]const u8,
    revealed: std.ArrayList([]const u8),
    profile_arena_state: std.heap.ArenaAllocator,
    profile_info: ?timeline_ui.ProfileInfo,
    mailbox: stream_shell.Mailbox,
    live_stream: ?*stream_shell.Stream,
    live_mail: std.ArrayList(stream_shell.Mail),
    subscribed_authors: usize,
    live_start_attempted: bool,
    write_in: write_worker.RequestBox,
    write_out: write_worker.ResultBox,
    writer: ?*write_worker.Worker,
    write_results: std.ArrayList(write_worker.Result),
    refresh_in: refresh_worker.RequestBox,
    refresh_out: refresh_worker.ResultBox,
    refresher: ?*refresh_worker.Worker,
    refresh_results: std.ArrayList(refresh_worker.Result),
    refresh_inflight: u32,
    viewload_in: view_worker.RequestBox,
    viewload_out: view_worker.ResultBox,
    viewloader: ?*view_worker.Worker,
    viewload_results: std.ArrayList(view_worker.Result),
    deferred_unlike: std.AutoHashMapUnmanaged(u64, void),
    deferred_unrepost: std.AutoHashMapUnmanaged(u64, void),
    refresh_interval: i64,
    last_auto_refresh: i64,
    last_input_nanos: u64,
    engine: ?text_core.Engine,
    gfield: field_core.Field,
    gparticles: field_core.ParticleList,
    gactive: effect_core.ActiveList,
    gdraw: raster_core.DrawList,
    ghr: field_ui.HitList,
    ghearts: field_ui.HeartList,
    gview: field_ui.ViewState,
    gspawn: std.ArrayList(field_core.SpawnEvent),
    glast_nanos: u64,
    gzoom: f32,
    gscroll_px: i32,
    gcontent_h: i32,
    overscroll_accum: i32,
    pull_refresh_requested: bool,
    gregions: feed_view.Regions,
    empty_cards: [0]lens_socket.LensCard,
    socket_cards: []lens_socket.LensCard,
    socket_blob: []const u8,
    gseated: u32,
    reply_cards: []lens_socket.LensCard,
    reply_blob: []const u8,
    reply_seated: u32,
    zone_cards: []lens_socket.LensCard,
    zone_blob: []const u8,
    zone_seated: u32,
    loadout_dirty: bool,
    socket_was_open: bool,
    gsocket_ui: lens_socket.SocketUi,
    gsocket_hits: lens_socket.HitList,
    reply_ui: lens_socket.SocketUi,
    reply_hits: lens_socket.HitList,
    zone_ui: lens_socket.SocketUi,
    zone_hits: lens_socket.HitList,
    page_geoms: [3]lens_socket.Geometry,
    // The phone loadout's library band top (screen px; maxInt = wide shelf mode).
    // Written by layoutLoadout each frame; the touch drop test reads it —
    // released over the library = unequip the dragged card.
    page_lib_y: i32,
    page_drag_surface: ?u8,
    prev_screen: u8,
    gloadout_tab: u8,
    gcreate_step: create_flow.Step,
    gcreate_answers: builder.Answers,
    gcreate_config: discover.FeedConfig,
    gcreate_color: u8,
    gcreate_name_buf: [64]u8,
    gcreate_name_len: usize,
    // The developer submission flow (ALGO_SUBMISSION slice 1): the Create tab
    // hosts it while gdev_active. The source rides a textedit.Field over its
    // fixed store (16 KiB holds any sane Zal program — the gate's caps refuse
    // far smaller); the detail fields are short append/backspace buffers (the
    // create-name convention). Check output — diagnostics, disclosures, the
    // serialized config — is gpa-owned, freed on re-check / reset (C5).
    gdev_active: bool,
    gdev_step: dev_flow.Step,
    gdev_src_store: [16384]u8,
    gdev_src: textedit.Field,
    gdev_name_buf: [64]u8,
    gdev_name_len: usize,
    gdev_ranks_buf: [96]u8,
    gdev_ranks_len: usize,
    gdev_desc_buf: [512]u8,
    gdev_desc_len: usize,
    gdev_focus: u8,
    gdev_color: u8,
    gdev_designed: u8,
    gdev_tags_buf: [128]u8,
    gdev_tags_len: usize,
    gdev_checked: bool,
    gdev_check_ok: bool,
    gdev_diags: std.ArrayListUnmanaged([]const u8),
    gdev_discl: std.ArrayListUnmanaged([]const u8),
    gdev_config: []const u8,
    gdev_status_buf: [512]u8,
    gdev_status_len: usize,
    // Marketplace browse/detail: the search draft, the filtered-view map
    // (filtered card position -> catalog row), the open detail row (a
    // CATALOG index), and the install-on-fetch latch (Install tapped before
    // the config arrived — finish in the inspect drain).
    gmarket_q_buf: [64]u8,
    gmarket_q_len: usize,
    gmarket_q_focus: bool,
    gmarket_filter: u8, // active capability chip (0 all · 1 private · 2 learns · 3 attention)
    gmarket_map: std.ArrayListUnmanaged(u16),
    gdetail_row: usize,
    gdetail_install_pending: bool,
    // The bench socket chooser: the tapped shelf/library index and, when a
    // mismatched target was picked, the pending surface awaiting confirm.
    gbench_pick: ?u16,
    gbench_warn: ?u8,
    // A live bench drag: the shelf/library index riding the pointer.
    gbench_drag: ?u16,
    gbench_drag_x: i32,
    gbench_drag_y: i32,
    // The chat list's search field (phone): live filter over conversations.
    gchat_q_buf: [64]u8,
    gchat_q_len: usize,
    gchat_q_focus: bool,
    // The Zat4 keyboard (phone): one-shot shift, letters/symbols page, and
    // the tapped bytes queued for the next frame's input stream. `kbd_caps`
    // is the double-tap shift lock; `kbd_shift_ns` stamps the last shift
    // tap (the double-tap window). `kbd_flash_key`/`kbd_flash_ns` are the
    // press-feedback flash: the pressed key's identity + when it landed —
    // the grid carries a decayed alpha each frame (kbdFlashAlpha).
    kbd_shift: bool,
    kbd_caps: bool,
    kbd_page: u8,
    kbd_shift_ns: u64,
    kbd_flash_key: u16,
    kbd_flash_ns: u64,
    /// The flash's key is still under a finger: the pop and glow HOLD at
    /// full until release starts the decay (kbd_flash_ns is re-stamped
    /// at release).
    kbd_flash_held: bool,
    /// A keystroke changed keyboard/draft state THIS lap: the lap ends with
    /// an extra paint (after a grid re-stamp) so the pixels land the same
    /// tick as the finger — the razor-tap paint. One frame bought back.
    kbd_dirty: bool,
    /// The tap decoder's context: the last few typed classes (kbd_lm), a
    /// ring so backspace can pop. Feeds kbdResolve's trigram prior.
    kbd_hist: [8]u8,
    kbd_hist_n: usize,
    /// The emoji picker (the emoji key toggles it; abc closes). The grid
    /// scrolls vertically; the offset is logical px, clamped to
    /// [0, feed_view.emojiScrollMax()], f32 so drags and flings carry
    /// sub-pixel remainders.
    kbd_emoji_open: bool,
    kbd_emoji_scroll: f32,
    /// The picker's SECTION (0 = emoji, 1 = GIFs) — the LAST choice made
    /// on the nav rollout, disk-persisted so the emoji key reopens where
    /// the user lives. `kbd_prefs_dirty` marks a pending save (the run
    /// loop drains it — kbdAction has no environ).
    kbd_picker_mode: u8,
    kbd_prefs_dirty: bool,
    /// The nav rollout: want (pressed open) + reveal [0,1] eased per lap
    /// by the pump. Continuous motion — rides the ordinary paint (LAW).
    kbd_nav_want: bool,
    kbd_nav_t: f32,
    /// The rollout column's rubber-band give (displayed logical px) + its
    /// return-spring velocity. The strip has nothing real to scroll to —
    /// the give IS the whole scroll feel (owner's ask, 2026-07-12).
    kbd_nav_scroll: f32,
    kbd_nav_scroll_v: f32,
    /// A category-jump target for the picker scroll (logical px; < 0 =
    /// idle). The pump glides scroll toward it; a finger drag cancels it.
    kbd_emoji_jump: f32,
    /// The long-press popup: 0 closed / 1 @-handles / 2 #-zones. Options
    /// are copied into the fixed bufs; `kbd_popup_opts` slices into them
    /// (RunState never moves). The anchor is the pressed key's region.
    kbd_popup_kind: u8,
    kbd_popup_n: usize,
    kbd_popup_bufs: [4][64]u8,
    kbd_popup_opts: [4][]const u8,
    kbd_popup_ax: i32,
    kbd_popup_ay: i32,
    kbd_popup_aw: i32,
    kbd_popup_sel: i32,
    kbd_bytes: std.ArrayList(u8),
    // Double-back-to-exit: the deadline (monotonic ns) until which a second
    // system-back at the root minimizes; the nav tile shows the hint pill.
    back_hint_until: u64,
    // The cartridge DETAIL sheet (item 5): which surface's seated cartridge has its
    // detail/colour overlay open (0 home, 1 reply, 2 zone), or null = closed. Opened
    // by tapping an already-seated cartridge; drawn topmost with its own hit list.
    gcart_detail: ?u8,
    detail_hits: lens_socket.HitList,
    gpub_confirm: ?u16, // Published tab: the library index whose Delete is armed
    gdocs_kind: u8, // the docs page shown (0 = user explainer, 1 = the dev guide)
    docs_return_screen: u8,
    market_loading: bool, // a getAlgorithms fetch is in flight (browse shows a loading state)
    market_prefetched: bool, // the one-shot startup warmup fired
    gchat_store: chat_core.Store,
    gchat_sel: ?chat_core.ConvIndex,
    gchat_draft_buf: [512]u8,
    gchat_draft_len: usize,
    /// Selection over the draft ([a,b) bytes; a == b = none) + the edit
    /// bar's visibility (long-press summons; edits dismiss).
    /// The clipboard seam (phone): copy/cut queue text OUT here (the
    /// activity polls + hands it to the OS clipboard); paste raises `want`
    /// and the activity feeds the OS clipboard back IN next lap.
    clip_out_buf: [1024]u8,
    clip_out_len: usize,
    clip_want: bool,
    clip_in_buf: [1024]u8,
    clip_in_len: usize,
    clip_in_ready: bool,
    gchat_sel_a: usize,
    gchat_sel_b: usize,
    gchat_edit_bar: bool,
    /// Caret byte offset into the draft (always kept <= gchat_draft_len).
    gchat_caret: usize,
    gchat_input_focus: bool,
    gchat_composing: bool,
    gchat_peer_buf: [254]u8,
    gchat_peer_len: usize,
    gchat_compose_status: []const u8,
    gchat_typing_deadline: i64,
    gchat_typing_peer_buf: [256]u8,
    gchat_typing_peer_len: usize,
    gchat_typing_sent_at: i64,
    gchat_key_ns: u64,
    gpay_open: bool,
    gpay_rail: chat_core.Rail,
    gpay_amount_buf: [16]u8,
    gpay_amount_len: usize,
    gpay_note_buf: [256]u8,
    gpay_note_len: usize,
    gpay_focus: u8,
    gpay_status: []const u8,
    gpay_step: feed_view.PayStep,
    gpay_first_send: bool,
    gpay_unit: feed_view.PayUnit,
    gprice_cents: u64,
    gprice_last: i64,
    gprice_job: PriceJob,
    grecv_open: bool,
    grecv_ln_buf: [256]u8,
    grecv_ln_len: usize,
    grecv_btc_buf: [256]u8,
    grecv_btc_len: usize,
    grecv_focus: u8,
    grecv_status: []const u8,
    grecv_saved: bool,
    grecv_mode: feed_view.RecvMode,
    grecv_known: bool,
    grecv_set: bool,
    gchain_job: ChainJob,
    gchain_last: i64,
    gexpire_last: i64,
    greceive_job: ReceiveJob,
    ghandle_job: HandleJob,
    ghandle_last: i64,
    /// The in-flight wallet hand-off (address resolve + LNURL invoice), off the
    /// render thread. One at a time.
    gpay_job: PaySendJob,
    /// The wallet PUBLISH, off the render thread. It is a PDS write — a network
    /// round-trip that can also rotate the session's tokens — and it used to run
    /// on the click, on the render thread, against the standing law that the UI
    /// thread never blocks on I/O. That is most of why the button felt dead even
    /// on the runs where it was working.
    gpublish_job: PublishJob,
    /// True while that worker is out: the button says "Saving…" and disarms, so a
    /// second tap cannot start a second write.
    gpublish_busy: bool,
    /// True while that worker is out: the sheet shows "Preparing…" and its
    /// primary button disarms, so a second tap cannot start a second send.
    gpay_busy: bool,
    /// The Wallet page's two-tap Remove (see `Grid.wallet_remove_armed`).
    gwallet_remove_armed: bool,
    /// The capability probe: what can the wallet the user just typed actually do?
    gcaps_job: WalletProbeJob,
    /// Lightning payments we are watching settle (LUD-21). The payoff moment.
    gverify: [verify_watch_max]VerifyWatch,
    gverify_n: usize,
    gverify_job: VerifyJob,
    /// True while the probe is out — the form shows "Checking with Strike…".
    grecv_probing: bool,
    /// The answer, held so the app can render its unavailable features FROM it —
    /// attributably, naming the wallet — instead of guessing or going quiet.
    gcaps: wallet_caps.Caps,
    /// DIDs whose handle resolution has already been attempted and refused
    /// (no `alsoKnownAs`, or a claim that failed the round-trip check). Kept so
    /// the 60s sweep does not re-ask the network the same unanswerable question
    /// forever. Keys are gpa-owned; freed with the store.
    ghandle_tried: std.StringHashMapUnmanaged(void),
    gchat_arena_state: std.heap.ArenaAllocator,
    gchat_box: chat_relay.Mailbox,
    gchat_link: ?*chat_relay.ChatRelay,
    gchat_e2ee: ?chat_e2ee.State,
    gchat_mail: std.ArrayList(chat_relay.Mail),
    /// Next second at which the unacknowledged-Welcome pump runs (A1). The
    /// pump itself is a walk of a handful of rows against a pure backoff, but
    /// there is no reason to do it 60 times a second.
    gchat_retry_at: i64,
    /// The relay endpoint, kept so chat can be brought up AGAIN from a click —
    /// A3's "set up chat fresh here" (`chatBringUp`).
    gchat_host_buf: [128]u8,
    gchat_host_len: usize,
    gchat_port: u16,
    /// An env/dist slice: lives as long as the process, so it is not copied.
    gchat_token: []const u8,
    gchat_use_tls: bool,
    /// FALSE = the pre-auth app: no session, no feed, no chat, no appview, no
    /// rail — one screen, the front door. Every entry point that touches the
    /// network or the account gates on this (FRONT_DOOR_ROADMAP §3.1).
    signed_in: bool,
    /// The front door's state (FRONT_DOOR_ROADMAP phase 2). The VIEW is the pure
    /// one the desktop has always used (`core/enroll_view.zig`) — it was never the
    /// problem. What was missing is a place to drive it from that a phone can
    /// reach, and this is it: the ONE run loop, which already owns the GPU path,
    /// the input pump, the soft keyboard, the gestures and the insets on BOTH
    /// platforms.
    /// The flow's REAL state — the same `enroll_run.State` the desktop window
    /// loop has always driven. Not a copy of it: the same type, the same
    /// `snapshot`, the same `apply`, the same `handleText`. One implementation,
    /// two callers, and this time the second caller is a phone.
    genroll_state: enroll_run.State,
    genroll_hits: enroll_view.HitList,
    genroll_mstore: membership_shell.Store,
    genroll_memjob: enroll_run.MemJob,
    /// Release-activation: the target a press armed (the front door has its own
    /// hit list, so it arms separately from the feed's regions).
    genroll_armed: ?enroll_view.HitTarget,
    /// The proof-of-work solve, on a worker: it is memory-hard Argon2id, and on
    /// the render thread it would freeze the app for seconds.
    genroll_pow: enroll_run.PowJob,
    /// The account creation, on a worker. `enroll_run` calls createZatAccount
    /// INLINE — survivable in a window with nothing else to do, and NOT survivable
    /// here, where the same thread has to keep drawing (the standing law).
    genroll_create: CreateJob,
    /// THE PHONE ASKS THE SEAM FOR THE BROWSER. A phone cannot use the desktop's
    /// OAuth leg — that one opens a browser and waits on a LOOPBACK LISTENER, and
    /// on Android the redirect comes back as an OS intent to a trampoline, not to
    /// a socket. So the front door does not run the flow itself there: it raises
    /// this, and the seam (which owns the intent plumbing) does the hop.
    glogin_want: bool,
    /// The browser has already been asked for, this visit to the step. Without it
    /// the request fired every frame.
    glogin_asked: bool,
    /// The in-app sign-in worker has been started for the tap that is in flight.
    /// `signin_busy` is what the CARD shows; this is what stops the loop starting a
    /// second `createSession` on the very next frame.
    genroll_signin_started: bool,
    /// THE BOOT ENTRANCE (§5). When the entrance began (0 = it has not), and
    /// whether it is over. It plays when the app comes up with NO SESSION — which
    /// is the honest reading of "on first open": one bit of state (are you signed
    /// in?) instead of a lifetime of remembering whether somebody has seen a
    /// cartoon. A skip rewrites `gboot_start_ns` to land on the settled wordmark.
    gboot_start_ns: u64,
    gboot_done: bool,
    /// The existing-account browser sign-in ("I already have an account"), on a
    /// worker: it resolves a handle, opens a browser, and waits on a loopback
    /// listener — none of which may happen on the thread that draws.
    genroll_oauth: enroll_run.OAuthJob,
    /// WHO HOSTS THIS HANDLE — the lookup that forks the existing-account road:
    /// our own PDS ⇒ an in-app password field; anyone else's ⇒ their browser.
    /// Network, so: a worker.
    genroll_resolve: enroll_run.ResolveJob,
    /// The in-app `createSession` for an account we host — the other side of that
    /// fork, also on a worker.
    genroll_pwlogin: enroll_run.PwLoginJob,
    /// A signed-in DID carried through the membership gate: an existing account
    /// still has to MINT its Zat4 membership before it is a member here.
    genroll_pending: ?auth.Session,
    /// The session enrollment produced. Non-null = we are somebody now, and the
    /// loop asks to be restarted with it: the app cannot hot-swap an identity
    /// mid-frame, because every worker, cache and store was built for "nobody".
    genroll_session: ?auth.Session,
    /// A3: this account's chat identity is published from ANOTHER device and we
    /// refused to overwrite it. Messages says so, plainly, and offers the only
    /// honest way forward — never a silently re-minted identity.
    gchat_identity_elsewhere: bool,
    /// CHAT_MULTIDEVICE slice 2 — the device gate's live state.
    /// `pending`: what this account's repo says is asking to join (refreshed off
    /// the render thread, like every other network fact).
    gdev_state: feed_view.ChatDeviceState,
    gdev_busy: bool,
    gdev_error: []const u8,
    gdev_added_ns: u64, // when an approval landed (drives the confirmation + its fade)
    gdev_added_name: [48]u8,
    gdev_added_len: u8,
    gdev_help: bool,
    /// One pending device at a time, always. A STACK of prompts is how you train
    /// somebody to tap yes without reading, which is the attack.
    gdev_pend_have: bool,
    gdev_pend_name: [48]u8,
    gdev_pend_name_len: u8,
    gdev_pend_fp: [24]u8,
    gdev_pend_fp_len: u8,
    gdev_pend_at: i64,
    /// What an approval actually acts on: the device's KEY (what gets signed) and
    /// the record's rkey (where the signature is written). The record's own bytes
    /// stay in the job, where the poll that read them left them.
    gdev_pend_anchor: [32]u8,
    gdev_pend_rkey: [32]u8,
    gdev_pend_rkey_len: u8,
    gdev_poll_ns: u64, // last time we asked the network who is waiting
    gdev_job: DeviceJob,
    /// THE ROSTER QUEUE (slice 3). People another device of ours says we talk to,
    /// waiting to be opened — ONE PER FRAME. Opening a conversation is a network
    /// round-trip; twenty of them inside one frame is the freeze the UI-thread law
    /// exists to prevent, and a list that fills in visibly is honest besides.
    groster: [32]struct { buf: [128]u8, len: u8 },
    groster_n: usize,
    /// The roster we SEND: only when our own device set or our conversation list has
    /// actually changed, so a quiet app is a silent one.
    groster_sig: u64,
    groster_at: i64,
    /// Slice 4: which conversation the device-set refresh looks at next, and when it
    /// last looked. One at a time, in rotation — checking everybody at once would be
    /// a burst of network on the render thread for no benefit.
    gpeer_refresh_at: i64,
    gpeer_refresh_i: usize,
    /// Slice 5: the backlog, arriving in pieces from our other device. Adopted only
    /// when ALL of it is here — half a history is not a history.
    ghist: std.ArrayListUnmanaged(u8),
    ghist_total: u16,
    ghist_have: u16,
    /// What the "bring my history" button is doing right now.
    gdev_hist_state: feed_view.HistoryState,
    /// CHAT_FEATURES slice 1 — the one-time setup. `asked` is the durable fact that
    /// we have put the screen in front of this account ONCE; the two flags are what
    /// they said. Both start OFF: the private choice must be the lazy one.
    gchat_asked: bool,
    gchat_receipts: bool,
    gchat_typing_on: bool,
    gchat_consent_open: bool,
    /// A URL this frame asked the OS to open. On the phone there is no
    /// `xdg-open` — the seam hands it to the activity, which fires an
    /// ACTION_VIEW intent (the same road the OAuth browser already takes).
    /// Empty = none pending; read-and-cleared by `mobileOpenUrlTake`.
    gopen_url_buf: [1024]u8,
    gopen_url_len: usize,
    gcreate_prepare_frames: u32,
    algo_lib: algo_library.Library,
    algo_uid: u32,
    gscreen: u8,
    on_profile_prev: bool,
    profile_target_buf: [256]u8,
    profile_target_did: []const u8,
    profile_dirty: bool,
    on_thread_prev: bool,
    thread_focus_cid_buf: [256]u8,
    thread_focus_uri_buf: [320]u8,
    thread_focus_cid: []const u8,
    thread_focus_uri: []const u8,
    thread_dirty: bool,
    thread_return_screen: u8,
    on_zone_prev: bool,
    zone_tag_buf: [256]u8,
    zone_tag: []const u8,
    zone_dirty: bool,
    zone_return_screen: u8,
    gsettings_section: u8,
    toggle_bits: u64,
    account_handle_buf: [128]u8,
    choice_sel: [settings_view.choices.len]u8,
    gsettings_picking: u8,
    zone_catalog: std.ArrayList(feed_view.ZoneCard),
    on_browse_prev: bool,
    /// The viewer's pinned zones (persisted in the client cache).
    zone_pins: pin_store.Pins,
    /// The zones hub UI: sub-tab (0 Browse · 1 Pinned · 2 Trending), the live
    /// search buffer/focus, and the motion scalars the render lerps each frame
    /// (tab underline glide, tab-switch settle, page-entry fade).
    gzones_tab: u8,
    gzones_q_buf: [64]u8,
    gzones_q_len: usize,
    gzones_q_focus: bool,
    // Toy Box: the pet's name (an editable settings field).
    pet_name_buf: [24]u8 = undefined,
    pet_name_len: usize = 0,
    pet_name_focus: bool = false,
    gzones_tab_t: f32,
    gzones_enter_t: f32,
    /// The open zone page's community stats (distinct posters + newest post),
    /// recomputed when its view rebuilds — the masthead's real numbers.
    zone_people: usize,
    zone_last_at: i64,
    /// The composer's tag bar: locked zone tag + manual chips + add-tag input.
    gtagbar: ComposeTagBar,
    market_catalog: std.ArrayList(MarketRow),
    market_cards: std.ArrayList(feed_view.MarketAlgoCard),
    on_market_prev: bool,
    inspect_bytes: ?[]const u8,
    inspect_src: ?[]const u8, // the record's Zal source (null -> fall back to the config bytes)
    inspect_name: []const u8,
    inspect_ref: []const u8,
    transp_return_screen: u8,
    gtransp_source: bool,
    inspect_loading: bool,
    inspectjob: InspectJob,
    // The marketplace config PREFETCH: its own job (never shared with the
    // user-tap inspectjob, so a tap can't block on a prefetch join) + the next
    // catalog row to warm. Walks the catalog one fetch at a time whenever idle,
    // filling config_cache/src_cache so Details/install are INSTANT.
    prefetchjob: InspectJob,
    market_prefetch_next: usize,
    config_cache: std.StringHashMapUnmanaged([]u8),
    src_cache: std.StringHashMapUnmanaged([]u8), // CID -> Zal source, beside the config cache (A8)
    thread_rerooted: bool,
    gcollapsed: std.ArrayList([]const u8),
    gexpanded: std.ArrayList([]const u8),
    ghover_x: i32,
    ghover_y: i32,
    gpu_state: ?GpuState,
};

/// The old run() setup, verbatim (MC.1: pure mechanics): every hoisted
/// local is now an in-place field assignment. Errors are possible ONLY in
/// the early terminal section (isTty/termios/alt-screen); everything after
/// is total (catch null / orelse), so on success the caller owns exactly
/// one cleanup: deinitRunState. On error the errdefer restores the
/// terminal, matching the old defer semantics.
fn initRunState(
    rs: *RunState,
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    appview_url: []const u8,
    store: *feed_core.Store,
    backend: Backend,
    /// FALSE = the pre-auth app. Nothing that needs an account may start: no
    /// refresh worker, no view loader, no chat, no keyPackage publish. Every one
    /// of those would otherwise fire with an empty DID and fail in a way that
    /// looks like a network fault rather than what it is.
    signed_in: bool,
) !void {
    rs.* = undefined;
    rs.signed_in = signed_in;
    rs.gpa = gpa;
    rs.io = io;
    rs.environ = environ;
    rs.session = session;
    rs.appview_url = appview_url;
    rs.store = store;
    rs.backend = backend;
    // Returns whether the user SIGNED OUT (vs a normal window close / quit): the
    // caller then clears the cached session instead of re-saving it on exit.
    rs.user_signed_out = false;
    const stdin_file: std.Io.File = .stdin();
    const stdout_file: std.Io.File = .stdout();
    if (backend == .terminal) {
        if (!(try stdin_file.isTty(io)) or !(try stdout_file.isTty(io))) {
            return error.NotATerminal;
        }
    }
    rs.stdin_fd = stdin_file.handle;

    // Raw mode (terminal backend only): no line buffering, no echo, no
    // signal keys (ctrl-c arrives as a byte and quits through the same
    // action path as q). The window backend has no tty to configure.
    rs.original_termios = null;
    if (!has_termios and backend == .terminal) return error.NotATerminal;
    if (comptime has_termios) if (backend == .terminal) {
        const original = try posix.tcgetattr(rs.stdin_fd);
        rs.original_termios = original;
        var raw = original;
        raw.lflag.ICANON = false;
        raw.lflag.ECHO = false;
        raw.lflag.ISIG = false;
        raw.lflag.IEXTEN = false;
        raw.iflag.IXON = false;
        raw.iflag.ICRNL = false;
        raw.iflag.BRKINT = false;
        raw.iflag.ISTRIP = false;
        raw.iflag.INPCK = false;
        raw.oflag.OPOST = false;
        raw.cc[@intFromEnum(posix.V.MIN)] = 1;
        raw.cc[@intFromEnum(posix.V.TIME)] = 0;
        try posix.tcsetattr(rs.stdin_fd, .FLUSH, raw);
    };
    errdefer if (rs.original_termios) |original| {
        if (comptime has_termios) posix.tcsetattr(rs.stdin_fd, .FLUSH, original) catch {}; // C5: always restored
    };

    rs.out_buffer = undefined;
    rs.out_writer = .init(stdout_file, io, &rs.out_buffer);
    rs.out = &rs.out_writer.interface;

    // Alternate screen + hidden cursor; both released on every exit path.
    // (Terminal only — the window has no ANSI to speak.)
    if (backend == .terminal) {
        try rs.out.writeAll("\x1b[?1049h\x1b[?25l");
        try rs.out.flush();
    }

    rs.prev = .{};
    rs.next = .{};

    rs.state = .{};
    rs.status_buf = undefined;
    rs.status = "press r to load your timeline";

    rs.frame_arena = std.heap.ArenaAllocator.init(gpa);

    // Composer session: the draft buffer is gpa-owned (it outlives frames);
    // the reply target's strings are copied into their own arena, reset at
    // each composer open (C3: one composition, one unit of work).
    rs.mode = .timeline;
    // Composer text: a fixed backing buffer (the draft is capped at 300
    // codepoints — ≤1200 UTF-8 bytes) wrapped in the shared editable-text model,
    // so the composer gets caret-aware editing (click-to-place, ←/→, Home/End,
    // mid-text insert/delete) instead of append-only. Caller-owned: no deinit.
    rs.compose_store = undefined;
    rs.compose = .{ .buf = &rs.compose_store };
    // The caret blink anchor: reset on every edit/move so the caret stays solid
    // while the user is active, then blinks when idle (B3: the clock is shell).
    rs.caret_anchor_ns = 0;
    // True between a press and release in the composer text area — a drag extends
    // the selection (textedit anchor stays, caret follows the pointer).
    rs.compose_drag = false;
    // Multi-click tracking (double = word, triple = line): consecutive presses
    // close in time and position step the count.
    rs.last_click_ns = 0;
    rs.last_click_x = -1000;
    rs.last_click_y = -1000;
    rs.click_count = 0;
    // Release-activation (the premium standard): a tap is ARMED on press and
    // FIRES on release only if the release lands on the same target (press then
    // slide off = cancel). The press records the target; the release re-hit-tests
    // and fires the feed switch / legacy cell / composer button if it matches.
    // (Caret placement + socket drag stay on press; the lens socket's own taps
    // are unchanged for now — its drag/drop model is separate.)
    rs.armed_kind = null;
    rs.armed_post = 0;
    rs.armed_legacy = false;
    rs.armed_cx = 0;
    rs.armed_cy = 0;
    rs.armed_compose = null; // composer Send/Cancel armed on press
    rs.compose_arena_state = std.heap.ArenaAllocator.init(gpa);
    rs.reply_target = null;
    rs.reply_handle = "";
    // Quote-post: the quoted post's strong ref (compose-arena-owned, like
    // reply_target) + its @handle for the composer's "Quoting" line. Set when the
    // quote button opens the composer; cleared on send/cancel.
    rs.quote_target = null;
    rs.quoting_handle = "";
    // The VIEW index of the post whose Repost/Quote menu is open, or null. A
    // transient popover: closed by picking a row, tapping elsewhere, or scrolling.
    rs.grepost_menu = null;
    // The compose flow is reused for the profile editor: .post writes a feed
    // post on send; .profile upserts the self profile record with the buffer as
    // the display name. Set when the editor / composer is opened.
    rs.compose_kind = .post;
    // A post/reply optimistically shown, its create write queued for the loop to
    // run after the post is on screen (0ms posting). At most one chain in flight;
    // a lone post is a chain of one.
    rs.pending_send = null;
    // Thread composer: the FINALIZED segments above the active box. Tapping "Add"
    // pushes the active draft here and clears the box for the next post; Send
    // publishes these plus the active box as one self-reply chain. gpa-owned
    // texts, freed on send/cancel/exit (C5).
    rs.chain_segments = .empty;
    // A queued profile-edit save (the display name to putProfile after it's
    // shown optimistically). gpa-owned; at most one in flight.
    rs.pending_profile_save = null;

    // Reveal toggles: cids the user has opened past a moderation collapse.
    // Plain values handed to the core each frame (B5); freed here (C4/C5).
    rs.revealed = .empty;

    // The profile screen's strings live in their own arena, reset per
    // fetch (C3); the info struct is a view over it.
    rs.profile_arena_state = std.heap.ArenaAllocator.init(gpa);
    rs.profile_info = null;

    // Live stream: spawned after the first page teaches us whose posts to
    // want; it speaks only through the mailbox (E1) and is joined before
    // the terminal defers above unwind. A dead stream is a status line,
    // never a dead screen (E2).
    rs.mailbox = .{};
    rs.live_stream = null;
    rs.live_mail = .empty;
    rs.subscribed_authors = 0;
    rs.live_start_attempted = false;

    // The WRITE WORKER (mirror of the firehose): like/unlike/repost network
    // calls run on this worker's own thread so the UI loop never blocks on
    // a write. The UI submits a plain-data request and returns immediately;
    // the worker posts a result back, drained each loop iteration below,
    // and only a server REFUSAL reverts the optimistic state. This is what
    // makes animations smooth — the main loop keeps running every frame
    // while the network call is in flight on another thread.
    rs.write_in = .{};
    rs.write_out = .{};
    rs.writer = write_worker.start(gpa, io, environ, session, &rs.write_in, &rs.write_out) catch null;
    rs.write_results = .empty;
    // The refresh worker — the same actor pattern for the timeline FETCH. The
    // auto-refresh tick and pull-to-refresh used to run getTimeline inline on
    // this thread, freezing the living field for the round trip every interval
    // (the periodic split-second hitch). Now they submit here and drain the
    // page below; only the ingest (pure CPU over the fetched values) runs on
    // this thread. A failed spawn degrades to manual refresh only (E2: the `r`
    // key keeps its synchronous path).
    rs.refresh_in = .{};
    rs.refresh_out = .{};
    rs.refresher = if (signed_in) refresh_worker.start(gpa, io, environ, session, appview_url, &rs.refresh_in, &rs.refresh_out) catch null else null;
    rs.refresh_results = .empty;
    // Auto ticks in flight: the interval clock never stacks a second fetch on
    // an unanswered one (a slow network otherwise queues a burst).
    rs.refresh_inflight = 0;
    // The VIEW-LOAD worker — the same actor pattern for the view-ENTRY
    // fetches (profile/thread/zone/…). Entering a view used to run its fetch
    // inline on this thread — a frozen frame per entry, and a guaranteed ANR
    // once an OS owns the loop (M_CORE_INVERSION MC.3). Now entry submits a
    // request and the drain below ingests the result; the screen shows the
    // store's resident content until the page lands (every view is a query
    // over the shared store). A failed spawn degrades to a status line per
    // view (E2).
    rs.viewload_in = .{};
    rs.viewload_out = .{};
    rs.viewloader = if (signed_in) view_worker.start(gpa, io, environ, session, appview_url, &rs.viewload_in, &rs.viewload_out) catch null else null;
    rs.viewload_results = .empty;
    // Deferred-undo intents: a post the user UN-engaged before its like/repost
    // create had returned a record uri. Keyed by a hash of the post cid; when
    // the create's result lands (with the uri), the drain fires the delete at
    // once — so undo is instant instead of waiting on the create round-trip.
    rs.deferred_unlike = .empty;
    rs.deferred_unrepost = .empty;

    // Auto-refresh: the reliable live path. The Jetstream subsystem stays
    // wired (it proves the firehose engineering), but the VISIBLE feed is
    // kept current by re-running the same getTimeline refresh `r` does, on a
    // wall-clock interval. Polling the timeline endpoint is how most clients
    // actually keep the rendered feed fresh; the firehose shines for
    // notifications/counts, a later slice. Interval is overridable via
    // ZAT_REFRESH_SECS (0 disables auto-refresh, falling back to manual r).
    rs.refresh_interval = blk: {
        const secs = if (environ) |env| env.get("ZAT_REFRESH_SECS") else null;
        if (secs) |s| break :blk std.fmt.parseInt(i64, s, 10) catch 5;
        break :blk 5;
    };
    rs.last_auto_refresh = 0;

    // Last-input clock for the input-idle gate (see input_idle_gate_nanos).
    rs.last_input_nanos = 0;

    // ---- the modern window path (GUI roadmap 5.2/5.5/5.6, §7 amendment) --
    // The proportional engine and pixel view state exist only for the
    // window backend. A failed font init degrades to the cell renderer
    // (E2: a plainer window, never a dead one) — paintFrame() checks.
    rs.engine = null;
    if (backend == .window) rs.engine = text_core.initEngine() catch null;
    // The glyph-field cutover (GLYPH_FIELD_SYSTEM_DESIGN G.0): the
    // window renders the feed as a live simulated mono grid. All of
    // this exists only when the font engine came up (E2: otherwise the
    // cell fallback still runs — a plainer window, never a dead one).
    rs.gfield = .{};
    rs.gparticles = .empty;
    rs.gactive = .empty;
    rs.gdraw = .empty;
    rs.ghr = .empty;
    rs.ghearts = .empty;
    rs.gview = .{};
    rs.gspawn = .empty;
    rs.glast_nanos = 0;
    rs.gzoom = 1.0; // user text-scaling factor (+/- keys)
    // cut 5.6 premium feed: pixel scroll offset (≤0 scrolls the stack up),
    // its clamp bound (total content height), and the per-frame button hit
    // regions the pointer handler tests in pixels.
    rs.gscroll_px = 0;
    rs.gcontent_h = 0;
    // Pull-to-refresh: an upward wheel while already pinned at the top of Home
    // accumulates "overscroll"; crossing `pull_refresh_threshold` requests a
    // manual refresh (handled at the loop top with the auto-refresh). A
    // downward scroll or a fired refresh resets the accumulator.
    rs.overscroll_accum = 0;
    rs.pull_refresh_requested = false;
    rs.gregions = .empty;
    // THE LENS SOCKET loadouts — THREE surfaces (feed / reply / zone),
    // SOCKET_LOADOUT §10. The FEED surface is interactive in the home header;
    // reply/zone are held so a save writes the whole record without clobbering
    // them (the loadout PAGE makes them editable). Cards + blob are gpa-owned
    // so the CID slices the socket emits stay valid across frames (B-split).
    rs.empty_cards = [_]lens_socket.LensCard{};
    rs.socket_cards = &rs.empty_cards;
    rs.socket_blob = "";
    rs.gseated = 0;
    rs.reply_cards = &rs.empty_cards;
    rs.reply_blob = "";
    rs.reply_seated = 0;
    rs.zone_cards = &rs.empty_cards;
    rs.zone_blob = "";
    rs.zone_seated = 0;
    // Load the user's saved library (created/downloaded feeds); empty on first run
    // or a corrupt file (deserialize is total). Saved after each create/adopt.
    rs.algo_lib = cache_shell.loadLibrary(gpa, environ) orelse .{};
    rs.algo_uid = 0;
    // Resume id minting past the highest persisted `user:N`, so a new create can't
    // collide with a saved one (add is idempotent by id → a collision drops the new).
    for (rs.algo_lib.records.items) |rec| {
        const id = rs.algo_lib.slice(rec.id);
        if (std.mem.startsWith(u8, id, "user:")) {
            const n = std.fmt.parseInt(u32, id["user:".len..], 10) catch continue;
            if (n >= rs.algo_uid) rs.algo_uid = n + 1;
        }
    }
    // Restore the persisted loadouts from `app.zat4.socket.loadout`; absent
    // (first run) or a failed read falls back to the catalog defaults, which
    // we then write so the record exists going forward.
    {
        var load_arena = std.heap.ArenaAllocator.init(gpa);
        defer load_arena.deinit();
        const loaded: ?loadout_store.Loaded = loadout_store.load(gpa, load_arena.allocator(), io, environ, session) catch null;
        if (loaded) |ld| {
            buildSurfaceFromEntries(gpa, ld.feed, &rs.algo_lib, &rs.socket_cards, &rs.socket_blob, &rs.gseated);
            buildSurfaceFromEntries(gpa, ld.reply, &rs.algo_lib, &rs.reply_cards, &rs.reply_blob, &rs.reply_seated);
            buildSurfaceFromEntries(gpa, ld.zone, &rs.algo_lib, &rs.zone_cards, &rs.zone_blob, &rs.zone_seated);
        }
        // Any surface that didn't resolve from the record → its catalog default.
        if (rs.socket_cards.len == 0) if (lens_catalog.defaultFeedLoadout(gpa)) |t| {
            rs.socket_cards = t[0];
            rs.socket_blob = t[1];
            rs.gseated = lens_catalog.default_feed_seated;
        } else |_| {};
        if (rs.reply_cards.len == 0) if (lens_catalog.defaultReplyLoadout(gpa)) |t| {
            rs.reply_cards = t[0];
            rs.reply_blob = t[1];
            rs.reply_seated = lens_catalog.default_reply_seated;
        } else |_| {};
        if (rs.zone_cards.len == 0) if (lens_catalog.defaultZoneLoadout(gpa)) |t| {
            rs.zone_cards = t[0];
            rs.zone_blob = t[1];
            rs.zone_seated = lens_catalog.default_zone_seated;
        } else |_| {};
        // First run (no record): persist the defaults once (synchronous here is
        // fine — it's startup, before the loop).
        if (loaded == null) {
            loadout_store.saveAll(
                gpa,
                load_arena.allocator(),
                io,
                environ,
                session,
                surfaceDataOf(load_arena.allocator(), rs.socket_cards, rs.socket_blob, rs.gseated),
                surfaceDataOf(load_arena.allocator(), rs.reply_cards, rs.reply_blob, rs.reply_seated),
                surfaceDataOf(load_arena.allocator(), rs.zone_cards, rs.zone_blob, rs.zone_seated),
                clock_shell.unixSeconds(),
            ) catch {};
        }
    }
    if (rs.socket_cards.len > 0) rs.gseated = @min(rs.gseated, @as(u32, @intCast(rs.socket_cards.len - 1)));
    // Set when the loadout changes (recolor / reorder / seat); flushed to the
    // background worker when the tray closes (so editing never blocks).
    rs.loadout_dirty = false;
    rs.socket_was_open = false;
    rs.gsocket_ui = .{};
    rs.gsocket_hits = .empty;
    // The reply/zone sockets, shown on the loadout PAGE (the feed surface reuses
    // gsocket_ui/gsocket_hits above). Their transient UI + per-frame hit lists.
    rs.reply_ui = .{};
    rs.reply_hits = .empty;
    rs.zone_ui = .{};
    rs.zone_hits = .empty;
    // Drag on the loadout PAGE: each socket's on-page geometry (filled by
    // layoutLoadout), and which surface is mid-drag (0 feed / 1 reply / 2 zone).
    rs.page_geoms = .{ .{ .x = 0, .y = 0, .w = 0 }, .{ .x = 0, .y = 0, .w = 0 }, .{ .x = 0, .y = 0, .w = 0 } };
    rs.page_lib_y = std.math.maxInt(i32);
    rs.page_drag_surface = null;
    // Previous frame's screen — flush the loadout when LEAVING the page (the
    // page's sockets are always open, so there's no tray-close beat there).
    rs.prev_screen = 0;
    // The active sub-tab on the Algorithms page: 0 = Loadout, 1 = Marketplace,
    // 2 = Create (the latter two are placeholders for now).
    rs.gloadout_tab = 0;
    // The simple-Create flow's state (loadout tab 2): the current step, the
    // plain-language answers so far, the live config (rebuilt from the answers, then
    // nudged by the recap knobs), the chosen accent, and the name buffer. The user's
    // OWNED algorithms land in `algo_lib`; `algo_uid` mints their local ids.
    rs.gcreate_step = .landing;
    rs.gcreate_answers = .{};
    rs.gcreate_config = builder.build(.{});
    rs.gcreate_color = 0;
    rs.gcreate_name_buf = undefined;
    rs.gcreate_name_len = 0;
    // The developer submission flow: dormant until the Create landing's
    // "Submit an algorithm you wrote" button wakes it.
    rs.gdev_active = false;
    rs.gdev_step = .source;
    rs.gdev_src_store = undefined;
    rs.gdev_src = .{ .buf = &rs.gdev_src_store };
    rs.gdev_name_buf = undefined;
    rs.gdev_name_len = 0;
    rs.gdev_ranks_buf = undefined;
    rs.gdev_ranks_len = 0;
    rs.gdev_desc_buf = undefined;
    rs.gdev_desc_len = 0;
    rs.gdev_focus = 0;
    rs.gdev_color = 0;
    rs.gdev_designed = 1; // feed pre-checked; the author edits from there
    rs.gdev_tags_buf = undefined;
    rs.gdev_tags_len = 0;
    rs.gdev_checked = false;
    rs.gdev_check_ok = false;
    rs.gdev_diags = .empty;
    rs.gdev_discl = .empty;
    rs.gdev_config = "";
    rs.gdev_status_buf = undefined;
    rs.gdev_status_len = 0;
    rs.gmarket_q_buf = undefined;
    rs.gmarket_q_len = 0;
    rs.gmarket_q_focus = false;
    rs.gmarket_filter = 0;
    rs.gmarket_map = .empty;
    rs.gdetail_row = 0;
    rs.gdetail_install_pending = false;
    rs.gbench_pick = null;
    rs.gbench_warn = null;
    rs.gbench_drag = null;
    rs.gbench_drag_x = 0;
    rs.gbench_drag_y = 0;
    rs.gcart_detail = null;
    rs.detail_hits = .empty;
    rs.back_hint_until = 0;
    rs.gchat_q_buf = undefined;
    rs.gchat_q_len = 0;
    rs.gchat_q_focus = false;
    rs.kbd_shift = false;
    rs.kbd_caps = false;
    rs.kbd_page = 0;
    rs.kbd_shift_ns = 0;
    rs.kbd_flash_key = 0;
    rs.kbd_flash_ns = 0;
    rs.kbd_flash_held = false;
    rs.kbd_dirty = false;
    rs.kbd_hist = .{26} ** 8;
    rs.kbd_hist_n = 0;
    rs.kbd_emoji_open = false;
    rs.kbd_emoji_scroll = 0;
    rs.kbd_picker_mode = cache_shell.loadKbdSection(gpa, environ);
    rs.kbd_prefs_dirty = false;
    rs.kbd_nav_want = false;
    rs.kbd_nav_t = 0;
    rs.kbd_nav_scroll = 0;
    rs.kbd_nav_scroll_v = 0;
    rs.kbd_emoji_jump = -1;
    rs.kbd_popup_kind = 0;
    rs.kbd_popup_n = 0;
    rs.kbd_popup_bufs = undefined;
    rs.kbd_popup_opts = undefined;
    rs.kbd_popup_ax = 0;
    rs.kbd_popup_ay = 0;
    rs.kbd_popup_aw = 0;
    rs.kbd_popup_sel = -1;
    rs.kbd_bytes = .empty;
    rs.gpub_confirm = null;
    rs.gdocs_kind = 0;
    rs.docs_return_screen = feed_view.screen_loadout;
    rs.market_loading = false;
    rs.market_prefetched = false;
    // Zat Chat (M1): the DM view store — a QUERY model over the real E2EE
    // session below (zat-view-model law). Messages are end-to-end encrypted
    // via MLS; this store holds only the plaintext the local user has typed
    // or the crypto core has decrypted for display.
    rs.gchat_store = .{};
    rs.gchat_sel = null;
    rs.gchat_draft_buf = undefined;
    rs.gchat_draft_len = 0;
    rs.gchat_caret = 0;
    rs.gchat_sel_a = 0;
    rs.gchat_sel_b = 0;
    rs.gchat_edit_bar = false;
    rs.clip_out_buf = undefined;
    rs.clip_out_len = 0;
    rs.clip_want = false;
    rs.clip_in_buf = undefined;
    rs.clip_in_len = 0;
    rs.clip_in_ready = false;
    rs.gchat_input_focus = false;
    // The new-conversation flow: the recipient draft (a handle or DID being
    // typed) and why the last attempt refused (static strings, "" = none).
    rs.gchat_composing = false;
    rs.gchat_peer_buf = undefined;
    rs.gchat_peer_len = 0;
    rs.gchat_compose_status = "";
    // The peer-is-typing signal (U6a, real): an ENCRYPTED ping on the
    // reserved wire kind (chat.kind_typing_wire) — the relay sees one more
    // fixed-size bucket; only the peer can read it. Receiving one arms a
    // deadline; the indicator shows in the matching open thread until it
    // lapses (or the message itself arrives). The sender throttles to one
    // ping per 4s of active typing.
    rs.gchat_typing_deadline = 0;
    rs.gchat_typing_peer_buf = undefined;
    rs.gchat_typing_peer_len = 0;
    rs.gchat_typing_sent_at = 0;
    // Last chat keystroke (monotonic ns) — the caret's blink clock: lit
    // while typing, breathing when idle.
    rs.gchat_key_ns = 0;
    // The pay sheet (M5 A4): rail + amount/note drafts + which field owns
    // the keyboard + why the last attempt refused (static strings).
    rs.gpay_open = false;
    rs.gpay_rail = .lightning;
    rs.gpay_amount_buf = undefined;
    rs.gpay_amount_len = 0;
    rs.gpay_note_buf = undefined;
    rs.gpay_note_len = 0;
    rs.gpay_focus = 0;
    rs.gpay_status = "";
    // The send-confirm face (§8.2) + the once-per-session first-time disclosure.
    rs.gpay_step = .compose;
    rs.gpay_first_send = true;
    // The amount entry unit (sats/BTC) + the live USD-cents-per-BTC price for
    // the ≈$ readout (0 = unknown; refreshed off-thread).
    rs.gpay_unit = .sats;
    rs.gprice_cents = 0;
    rs.gprice_last = 0;
    rs.gprice_job = .{};
    // The receive-setup sheet (set up YOUR chat wallet). Addresses can be long
    // (bech32 ~62 chars, lightning addresses too), so give the buffers room.
    rs.grecv_open = false;
    rs.grecv_ln_buf = undefined;
    rs.grecv_ln_len = 0;
    rs.grecv_btc_buf = undefined;
    rs.grecv_btc_len = 0;
    rs.grecv_focus = 0;
    rs.grecv_status = "";
    rs.grecv_saved = false;
    rs.grecv_mode = .paste;
    // Have we checked (once) whether this account already has a receive address
    // published, and what it was? Gates the bitcoin icon: set → pay sheet,
    // unset → the onboarding empty state (never a dead form).
    rs.grecv_known = false;
    rs.grecv_set = false;
    // The confirmation-watcher's cycle (M5 A5). At exit an in-flight cycle
    // is joined (a few HTTP reads at worst) so the worker never outlives
    // the loop's stack.
    rs.gchain_job = .{};
    rs.gchain_last = 0;
    rs.gexpire_last = 0;
    rs.greceive_job = .{};
    rs.ghandle_job = .{};
    rs.ghandle_last = 0;
    rs.ghandle_tried = .empty;
    rs.gpay_job = .{};
    rs.gpublish_job = .{};
    rs.gpublish_busy = false;
    rs.gpay_busy = false;
    rs.gwallet_remove_armed = false;
    rs.gcaps_job = .{};
    rs.gcaps = .{};
    rs.grecv_probing = false;
    rs.gverify = undefined;
    rs.gverify_n = 0;
    rs.gverify_job = .{};

    // The real E2EE session (M1): the crypto state (anchor, keyPackage,
    // per-conversation MLS groups) + the relay link that carries encrypted
    // buckets. Live only when the relay endpoint is configured
    // (ZAT4_RELAY=host:port + ZAT_RELAY_TOKEN); absent it, Messages shows an
    // empty, honest surface (no fake seeds). A dead relay is an empty drain,
    // never a dead screen (E2/E4). A short-lived arena serves the network
    // legs (publish/fetch); the resident state is gpa-owned.
    rs.gchat_arena_state = std.heap.ArenaAllocator.init(gpa);
    rs.gchat_box = .{};
    rs.gchat_link = null;
    rs.gchat_e2ee = null;
    rs.gchat_mail = .empty;
    rs.gchat_retry_at = 0;
    rs.gchat_host_buf = undefined;
    rs.gchat_host_len = 0;
    rs.gchat_port = 0;
    rs.gchat_token = "";
    rs.gchat_use_tls = false;
    rs.gopen_url_buf = undefined;
    rs.gopen_url_len = 0;
    rs.genroll_state = .{};
    rs.genroll_hits = .empty;
    rs.genroll_mstore = membership_shell.init(std.heap.page_allocator);
    rs.genroll_memjob = .{};
    rs.glogin_want = false;
    rs.glogin_asked = false;
    rs.genroll_signin_started = false;
    rs.gdev_state = .ok;
    rs.gdev_busy = false;
    rs.gdev_error = "";
    rs.gdev_added_ns = 0;
    rs.gdev_added_len = 0;
    rs.gdev_help = false;
    rs.gdev_pend_have = false;
    rs.gdev_pend_name_len = 0;
    rs.gdev_pend_fp_len = 0;
    rs.gdev_pend_rkey_len = 0;
    rs.gdev_pend_at = 0;
    rs.gdev_poll_ns = 0;
    rs.gdev_job = .{};
    rs.groster_n = 0;
    rs.groster_sig = 0;
    rs.groster_at = 0;
    rs.gpeer_refresh_at = 0;
    rs.gpeer_refresh_i = 0;
    rs.ghist = .empty;
    rs.ghist_total = 0;
    rs.ghist_have = 0;
    rs.gdev_hist_state = .none;
    rs.gchat_asked = false;
    rs.gchat_receipts = false;
    rs.gchat_typing_on = false;
    rs.gchat_consent_open = false;
    rs.gboot_start_ns = 0;
    // A signed-in app never plays the entrance: it is the front door's overture,
    // not a splash screen, and somebody who is already inside is not arriving.
    rs.gboot_done = rs.signed_in;
    rs.genroll_oauth = .{};
    rs.genroll_resolve = .{};
    rs.genroll_pwlogin = .{};
    rs.genroll_pending = null;
    rs.genroll_pow = .{};
    rs.genroll_create = .{};
    rs.genroll_session = null;
    rs.genroll_armed = null;
    rs.gchat_identity_elsewhere = false;
    // Chat needs an account: an anchor key, a published keyPackage, a relay
    // identity. None of that exists before the front door is walked through.
    if (dev_chat and signed_in) {
        if (environ) |env| {
            // The endpoint + token: env wins; the compiled-in dist values are
            // the fallback (a phone has no env vars — the AppView-token
            // pattern). Two forms: "wss://host[:port]" = TLS via the public
            // Caddy route (default port 443); "host:port" = the plaintext
            // loopback/SSH-tunnel dev posture. No other cleartext path.
            const raw_ep: []const u8 = env.get("ZAT4_RELAY") orelse dist_config.relay_url;
            if (raw_ep.len == 0) chatLog("[chat] no relay endpoint (env or baked) — chat OFF", .{});
            if (raw_ep.len > 0) {
                const token = env.get("ZAT_RELAY_TOKEN") orelse dist_config.relay_token;
                var use_tls = false;
                var hostport = raw_ep;
                if (std.mem.startsWith(u8, raw_ep, "wss://")) {
                    use_tls = true;
                    hostport = raw_ep["wss://".len..];
                } else if (std.mem.startsWith(u8, raw_ep, "ws://")) {
                    hostport = raw_ep["ws://".len..];
                }
                // STRIP THE PATH. The websocket handshake hardcodes `GET /relay`
                // (chat_relay), so the endpoint is a HOST — but the natural thing
                // to configure, and what the phone's APK was baked with, is the
                // full URL `wss://pds.zat4.com/relay`. Without this, `/relay` was
                // glued into the hostname and every dial died with
                // `InvalidHostName`, forever, on a silent 30s-capped retry loop.
                //
                // That is the whole reason cross-device chat never worked: the
                // clients were not "failing to deliver" — they had never once
                // CONNECTED. Deposits queued into an outbox that never drained, and
                // the UI cheerfully reported the message as sent.
                if (std.mem.indexOfScalar(u8, hostport, '/')) |slash|
                    hostport = hostport[0..slash];
                const colon = std.mem.lastIndexOfScalar(u8, hostport, ':');
                const rhost = if (colon) |c| hostport[0..c] else hostport;
                const rport: u16 = if (colon) |c|
                    std.fmt.parseInt(u16, hostport[c + 1 ..], 10) catch 0
                else if (use_tls)
                    443
                else
                    0;
                // A6: NO TOKEN REQUIRED. The client proves who it is (A4 slice 2),
                // and a proof of identity is strictly stronger than a shared secret
                // baked into every build — so the relay takes it in the token's
                // place. A desktop user gets chat with no flags and no secret to
                // fetch, exactly like the phone. A token, when present (the local
                // dev relay, or a relay that hasn't been upgraded), is still sent.
                if (rport != 0 and rhost.len > 0 and rhost.len <= rs.gchat_host_buf.len) {
                    // Remember the endpoint: A3's "set up chat fresh here" has to
                    // be able to bring the whole thing up again later, from a
                    // click, long after this env parse is out of scope.
                    @memcpy(rs.gchat_host_buf[0..rhost.len], rhost);
                    rs.gchat_host_len = rhost.len;
                    rs.gchat_port = rport;
                    rs.gchat_token = token; // an env slice: lives as long as the process
                    rs.gchat_use_tls = use_tls;
                    chatBringUp(rs, gpa, io, env, session, false);
                } else {
                    chatLog("[chat] relay endpoint malformed (need host[:port])", .{});
                }
                // Starting a conversation is a UI verb now — the "+ New"
                // pill on the Messages screen (the ZAT4_CHAT_PEER env
                // stopgap is deleted, not flagged off; same cut-over rule
                // as M1's plaintext path).
            }
        }
    }
    rs.gcreate_prepare_frames = 0; // the .preparing loading beat's progress (frames)
    // The active top-level Screen (index into feed_view.nav_labels); the rail
    // sets it on a click. 0 = Home (the feed). Lives across frames in run().
    rs.gscreen = 0;
    // The premium Profile screen is a VIEW over the ONE shared `store`, not a
    // second store (ZONES invariant 4 — the post is the post). Entering it
    // fetches the viewed author's posts as CONTENT into `store`; the view's
    // ordering is a query (`feed_core.buildAuthorView`). The profile shows ANY
    // author: `profile_target_did` is whose profile (defaults to your own — the
    // rail "Profile"; set to a post author's DID when you tap their avatar).
    // `on_profile_prev` catches re-entry; `profile_dirty` catches a target
    // change (tapping a new author while already on the profile).
    rs.on_profile_prev = false;
    rs.profile_target_buf = undefined;
    rs.profile_target_did = session.did;
    rs.profile_dirty = false;

    // The Thread screen (C4): tapping a post body opens its thread — also a VIEW
    // over the ONE shared store (the reply linkage rides on each post). Entering
    // fetches the thread (`feed_shell.loadThread`) as CONTENT; the ordering is a
    // query (`feed_core.buildThreadView`) keyed by the focused post's cid. The
    // uri is sent to the AppView's getPostThread; `thread_return_screen` is where
    // Back goes.
    rs.on_thread_prev = false;
    rs.thread_focus_cid_buf = undefined;
    rs.thread_focus_uri_buf = undefined;
    rs.thread_focus_cid = "";
    rs.thread_focus_uri = "";
    rs.thread_dirty = false;
    rs.thread_return_screen = 0;
    // ZONE page (a tag-scoped feed): tapping a `#tag` in a post's tray opens it.
    // On entry the shell fetches the zone (`feed_shell.loadZoneFeed`) as CONTENT;
    // the ordering is a query (`feed_core.buildTagView`) keyed by the tag. The
    // tag (display form) is sent to the AppView's getPostsForTag, which normalizes
    // it. `zone_return_screen` is where Back goes.
    rs.on_zone_prev = false;
    rs.zone_tag_buf = undefined;
    rs.zone_tag = "";
    rs.zone_dirty = false;
    rs.zone_return_screen = 0;
    // Settings (`screen_settings`): the selected left-hand section (master–detail
    // state, like the return-screen vars above). A section tap sets it.
    rs.gsettings_section = 0;
    // Runtime on/off of every Settings toggle — a bitset indexed by GLOBAL row
    // index, seeded from each toggle's `flag_on` default. A toggle tap flips its
    // bit (so all Toy Box switches are live, even before their effects are wired).
    rs.toggle_bits = blk: {
        var b: u64 = 0;
        for (settings_view.rows, 0..) |r, i| {
            if (r.kind == .toggle and (r.flags & settings_view.flag_on) != 0) b |= @as(u64, 1) << @intCast(i);
        }
        break :blk b;
    };
    // Holds the "@handle" form for the Settings → Account info row (formatted
    // each frame from the session; the session handle has no leading @).
    rs.account_handle_buf = undefined;
    // CHOICE selections: the live selected-option index per choice, seeded from
    // each choice's default. `gsettings_picking` = the open choice's action
    // (255 = no picker open). A tap on a choice opens its picker; an option tap
    // sets the index + closes.
    rs.choice_sel = blk: {
        var s: [settings_view.choices.len]u8 = undefined;
        for (settings_view.choices, 0..) |c, i| s[i] = c.default;
        break :blk s;
    };
    rs.gsettings_picking = 255;
    // Zones BROWSE catalog (`screen_zones_browse`): gpa-owned zone cards (the
    // display tag duped + post count), (re)fetched from `listTags` on entering
    // the browse screen. Each card taps to its zone feed; freed on exit.
    rs.zone_catalog = .empty;
    rs.on_browse_prev = false;
    // Pinned zones restore from the client cache; absent/torn = none (E4).
    rs.zone_pins = cache_shell.loadPins(gpa, environ) orelse .{};
    rs.gzones_tab = 0;
    rs.gzones_q_buf = undefined;
    rs.gzones_q_len = 0;
    rs.gzones_q_focus = false;
    rs.pet_name_buf = undefined;
    rs.pet_name_len = 0;
    rs.pet_name_focus = false;
    rs.gzones_tab_t = 0;
    rs.gzones_enter_t = 1;
    rs.zone_people = 0;
    rs.zone_last_at = 0;
    rs.gtagbar = .{};
    // MARKETPLACE catalog (Algorithms → Marketplace tab): gpa-owned MarketRow
    // rows from the AppView's `getAlgorithms`, (re)fetched on entering the tab
    // and refilled by the view-load drain via refillMarket; `market_cards` is
    // the display projection handed to the renderer.
    rs.market_catalog = .empty;
    rs.market_cards = .empty;
    rs.on_market_prev = false;
    // The algorithm being inspected on the transparency page (screen_transparency):
    // its fetched config + name + ref (CID), rebuilt into a page each frame. The
    // screen to return to on Back. Config null ⇒ not inspecting.
    // The inspected algorithm is held as its SERIALIZED bytes (gpa-owned, stable),
    // NOT a parsed FeedConfig: a parsed config's `rules`/`vm_program` slices point
    // into the per-frame arena, which is reset every frame — holding the struct
    // across frames dangles those slices (a use-after-free that crashes validated()
    // on any non-empty program). The render re-parses these bytes into the current
    // frame's arena, and the source view IS these bytes.
    rs.inspect_bytes = null;
    rs.inspect_name = "";
    rs.inspect_ref = "";
    rs.transp_return_screen = feed_view.screen_loadout;
    // On the transparency page: false = the summary, true = the byte-exact source
    // (the "View the exact source" tap-through). Reset when a new algorithm opens.
    rs.gtransp_source = false;
    // The config fetch runs on a worker (no UI freeze); true while it's in flight.
    rs.inspect_loading = false;
    rs.inspectjob = .{};
    rs.prefetchjob = .{};
    rs.market_prefetch_next = 0;
    // CID-keyed config cache (A8): an algorithm's config is a content-addressed,
    // immutable record — same CID ⇒ same bytes ⇒ fetch ONCE, never again. Keyed by
    // the record CID (duped), value = the serialized config (owned). A re-view is a
    // local map hit (instant), only a never-seen algorithm pays the network fetch.
    // (A size cap / eviction is a later concern; the marketplace is small for now.)
    rs.config_cache = .empty;
    rs.src_cache = .empty;
    rs.inspect_src = null;
    // RE-ROOT mode: false when a thread is opened from the timeline (show the WHOLE
    // thread, scroll to the focus); true when a reply is tapped INSIDE the thread
    // (re-root on it: condensed ancestors above + the focus + its subtree).
    rs.thread_rerooted = false;
    // Collapsed reply CIDs (Reddit-style) — per-view state (ZONES inv. 4: never
    // on the post). gpa-owned dupes; cleared on exit. Passed to buildThreadView.
    rs.gcollapsed = .empty;
    // Expanded post CIDs (main-feed Read-more) — per-view state, same shape as
    // gcollapsed: gpa-owned dupes, cleared on exit. Passed to fromTimeline so a
    // clamped body lays out in full once the reader taps "Read more".
    rs.gexpanded = .empty;

    // The pointer's last position in LOGICAL coords (for the hover highlight),
    // updated on every motion event; <0 until the first move.
    rs.ghover_x = -1;
    rs.ghover_y = -1;

    // Phase 6.4: the GPU render path, brought up additively when the window is
    // open AND the font engine is live AND `gpu.init` succeeds. On any failure
    // it stays null and the SOFTWARE path renders (E2: a plainer window, never
    // a dead one). Created once here; the window is already open by the time
    // run() is called, so its XID is valid.
    rs.gpu_state = null;
    // Comptime-gated off Android: the window backend never exists in an APK
    // (mobileStart brings the GPU up on the seam's surface instead), and the
    // X11 native handle does not type-check against the Android gpu.init.
    if (comptime !builtin.abi.isAndroid()) if (backend == .window) if (rs.engine) |*e| {
        rs.gpu_state = blk: {
            const win = backend.window;
            const g = gpu.init(window_shell.nativeHandle(win)) catch |err| {
                std.debug.print("[gpu] init failed ({s}) — using the software path.\n", .{@errorName(err)});
                break :blk null;
            };
            break :blk initGpuState(gpa, e, g, win.fb.width, win.fb.height, design_w) catch |err| {
                std.debug.print("[gpu] init failed ({s}) — using the software path.\n", .{@errorName(err)});
                break :blk null;
            };
        };
    };
}

/// The old run() defers, in exact reverse-registration (LIFO) order,
/// evaluated at call time like the defers were (conditions on fields the
/// frame body mutates — live_stream, gpu_state, socket_cards … — read
/// their exit-time values).
fn deinitRunState(rs: *RunState) void {
    // The front door's hit list is gpa-owned (enroll_view.pushHit appends into
    // it every layout). The leak checker caught it on the very first run-through,
    // which is exactly what it is for.
    rs.genroll_hits.deinit(rs.gpa);
    membership_shell.deinit(&rs.genroll_mstore);
    // Its two workers must be off the road before the state they point at dies.
    // The PoW solve is cooperative (it checks `cancel` each attempt); the create
    // worker is a network call we simply wait out — it is seconds at worst, and a
    // detached thread writing into a freed RunState is not a trade worth making.
    enroll_run.stopPow(&rs.genroll_pow);
    enroll_run.joinMem(&rs.genroll_memjob);
    if (rs.genroll_create.thread) |th| {
        th.join();
        rs.genroll_create.thread = null;
    }
    if (rs.genroll_oauth.thread) |th| {
        rs.genroll_oauth.cancel.store(true, .release);
        th.join();
        rs.genroll_oauth.thread = null;
    }
    // Same law for the fork's two workers: waited out, never abandoned. The
    // sign-in one may also be holding a session nobody consumed (it landed in the
    // frame we shut down) — `stopPwLogin` releases it and scrubs the password.
    enroll_run.stopResolve(&rs.genroll_resolve);
    enroll_run.stopPwLogin(&rs.genroll_pwlogin);
    const gpa = rs.gpa;
    const backend = rs.backend;
    if (rs.gpu_state) |*gs| deinitGpuState(gpa, gs);
    {
        for (rs.gexpanded.items) |c| gpa.free(c);
        rs.gexpanded.deinit(gpa);
    }
    {
        for (rs.gcollapsed.items) |c| gpa.free(c);
        rs.gcollapsed.deinit(gpa);
    }
    {
        if (rs.inspect_bytes) |b| gpa.free(b);
        if (rs.inspect_src) |b| gpa.free(b);
        if (rs.inspect_name.len > 0) gpa.free(rs.inspect_name);
        if (rs.inspect_ref.len > 0) gpa.free(rs.inspect_ref);
    }
    {
        var it = rs.config_cache.iterator();
        while (it.next()) |kv| {
            gpa.free(kv.key_ptr.*);
            gpa.free(kv.value_ptr.*);
        }
        rs.config_cache.deinit(gpa);
        var sit = rs.src_cache.iterator();
        while (sit.next()) |kv| {
            gpa.free(kv.key_ptr.*);
            gpa.free(kv.value_ptr.*);
        }
        rs.src_cache.deinit(gpa);
    }
    stopInspect(&rs.inspectjob); // join any in-flight fetch before exit
    stopInspect(&rs.prefetchjob); // and the background prefetch (same shape)
    {
        for (rs.market_catalog.items) |r| {
            gpa.free(r.name);
            gpa.free(r.author_disp);
            gpa.free(r.author_did);
            gpa.free(r.rkey);
            gpa.free(r.cid);
            gpa.free(r.ranks);
            gpa.free(r.desc);
            gpa.free(r.tags);
        }
        rs.market_catalog.deinit(gpa);
        rs.market_cards.deinit(gpa);
        rs.gmarket_map.deinit(gpa);
    }
    {
        for (rs.zone_catalog.items) |zc| gpa.free(zc.tag);
        rs.zone_catalog.deinit(gpa);
    }
    pin_store.deinit(gpa, &rs.zone_pins);
    rs.algo_lib.deinit(gpa);
    {
        devClearCheck(rs); // frees the dev flow's diag/disclosure lines + config
        rs.gdev_diags.deinit(gpa);
        rs.gdev_discl.deinit(gpa);
    }
    {
        for (rs.gchat_mail.items) |m| chat_relay.freeMail(gpa, m);
        rs.gchat_mail.deinit(gpa);
    }
    if (rs.gchat_e2ee) |*st| chat_e2ee.deinit(gpa, st);
    if (rs.gchat_link) |link| chat_relay.shutdown(link);
    rs.gchat_box.deinit(gpa);
    rs.gchat_arena_state.deinit();
    if (rs.ghandle_job.thread) |t| {
        t.join();
        rs.ghandle_job.thread = null;
        handleJobFree(&rs.ghandle_job);
    }
    if (rs.gpay_job.thread) |t| {
        t.join();
        rs.gpay_job.thread = null;
        paySendJobFree(&rs.gpay_job);
    }
    if (rs.gcaps_job.thread) |t| {
        t.join();
        rs.gcaps_job.thread = null;
        walletProbeJobFree(&rs.gcaps_job);
    }
    if (rs.gverify_job.thread) |t| {
        t.join();
        rs.gverify_job.thread = null;
        verifyJobFree(&rs.gverify_job);
    }
    {
        var it = rs.ghandle_tried.keyIterator();
        while (it.next()) |k| gpa.free(k.*);
        rs.ghandle_tried.deinit(gpa);
    }
    if (rs.gchain_job.thread) |t| {
        t.join();
        rs.gchain_job.thread = null;
        chainJobFree(&rs.gchain_job);
    }
    chat_core.deinitStore(gpa, &rs.gchat_store);
    rs.zone_hits.deinit(gpa);
    rs.reply_hits.deinit(gpa);
    rs.gsocket_hits.deinit(gpa);
    rs.detail_hits.deinit(gpa);
    rs.kbd_bytes.deinit(gpa);
    if (rs.zone_blob.len > 0) gpa.free(rs.zone_blob);
    if (rs.zone_cards.len > 0) gpa.free(rs.zone_cards);
    if (rs.reply_blob.len > 0) gpa.free(rs.reply_blob);
    if (rs.reply_cards.len > 0) gpa.free(rs.reply_cards);
    if (rs.socket_blob.len > 0) gpa.free(rs.socket_blob);
    if (rs.socket_cards.len > 0) gpa.free(rs.socket_cards);
    rs.gregions.deinit(gpa);
    rs.gspawn.deinit(gpa);
    rs.ghearts.deinit(gpa);
    rs.ghr.deinit(gpa);
    rs.gdraw.deinit(gpa);
    rs.gactive.deinit(gpa);
    rs.gparticles.deinit(gpa);
    field_core.deinit(gpa, &rs.gfield);
    if (rs.engine) |*e| text_core.deinitEngine(gpa, e);
    rs.deferred_unrepost.deinit(gpa);
    rs.deferred_unlike.deinit(gpa);
    rs.viewload_results.deinit(gpa);
    if (rs.viewloader) |w| view_worker.shutdown(w);
    rs.viewload_out.deinit(gpa);
    rs.viewload_in.deinit(gpa);
    rs.refresh_results.deinit(gpa);
    if (rs.refresher) |w| refresh_worker.shutdown(w);
    rs.refresh_out.deinit(gpa);
    rs.refresh_in.deinit(gpa);
    rs.write_results.deinit(gpa);
    if (rs.writer) |w| write_worker.shutdown(w);
    rs.write_out.deinit(gpa);
    rs.write_in.deinit(gpa);
    rs.live_mail.deinit(gpa);
    if (rs.live_stream) |live| stream_shell.shutdown(live);
    rs.mailbox.deinit(gpa);
    rs.profile_arena_state.deinit();
    {
        for (rs.revealed.items) |cid| gpa.free(cid);
        rs.revealed.deinit(gpa);
    }
    if (rs.pending_profile_save) |n| gpa.free(n);
    {
        for (rs.chain_segments.items) |s| gpa.free(s);
        rs.chain_segments.deinit(gpa);
    }
    if (rs.pending_send) |cs| freeChain(gpa, cs);
    rs.compose_arena_state.deinit();
    rs.frame_arena.deinit();
    tui.deinitSurface(gpa, &rs.next);
    tui.deinitSurface(gpa, &rs.prev);
    if (backend == .terminal) {
        rs.out.writeAll("\x1b[0m\x1b[?25h\x1b[?1049l") catch {};
        rs.out.flush() catch {};
    }
    if (rs.original_termios) |original| {
        if (comptime has_termios) posix.tcsetattr(rs.stdin_fd, .FLUSH, original) catch {}; // C5: always restored
    }
}

/// What one frame step decided: run another frame, or leave the loop.
/// The driver owns the loop — the desktop run() below, a phone's vsync
/// callback later (M_CORE_INVERSION MC.2/MC.4).
const StepOutcome = enum {
    /// The frame completed; call again.
    again,
    /// The user quit (q / window close). The session stays cached.
    quit,
    /// The user signed out (Settings): the caller clears the cached
    /// session instead of re-saving it.
    signed_out,
};

/// ONE frame of the client, cut out of the old main_loop verbatim (MC.2):
/// drain the workers, pump input, advance the sim, lay out, paint. The
/// old `continue :main_loop`-equivalent exits are `return .again`; the
/// old `break :main_loop` sites jump past the frame block and map to the
/// outcome below.
///
/// `wait_budget_ms` is the longest the input pump may block waiting for
/// events — the wait POLICY belongs to the driver (M_CORE_INVERSION MC.4):
/// the desktop loop below passes its 16/500ms cadence; a phone's
/// choreographer does the waiting itself and passes 0, so the step never
/// sleeps on an OS-owned thread.
fn stepFrame(rs: *RunState, wait_budget_ms: i32) !StepOutcome {
    const gpa = rs.gpa;
    const io = rs.io;
    const environ = rs.environ;
    const session = rs.session;
    const appview_url = rs.appview_url;
    const store = rs.store;
    const backend = rs.backend;
    main_loop: {
        _ = rs.frame_arena.reset(.retain_capacity); // C3: one arena per frame
        const arena = rs.frame_arena.allocator();

        const size: WindowSize = switch (backend) {
            .terminal => readWindowSize(rs.stdin_fd),
            .window => |win| .{ .cols = win.cols, .rows = win.rows },
            // The cell Surface is vestigial on the GPU-only mobile arm (the
            // GPU paint never reads it); a notional 8x16 cell keeps the
            // resize accounting total and cheap.
            .mobile => |m| .{
                .cols = @intCast(@max(1, @min(m.width_px / 8, std.math.maxInt(u16)))),
                .rows = @intCast(@max(1, @min(m.height_px / 16, std.math.maxInt(u16)))),
            },
        };
        if (size.cols != rs.next.width or size.rows != rs.next.height) {
            try tui.resizeSurface(gpa, &rs.next, size.cols, size.rows);
            // prev keeps its old dimensions; encodeDiff sees the mismatch
            // and full-repaints — resize handling for free.
        }

        // Wall clock via the cross-OS clock shell (kernel-stable syscalls
        // on Linux, kernel32 on Windows — std.Io's clock API still drifts
        // between 0.16-dev snapshots). The clock stays in the shell (B3);
        // the core receives the epoch as plain data (B4).
        const now: i64 = clock_shell.unixSeconds();

        // Phase 8: a cache-warmed store gets live coverage and an honest
        // status from frame one — no fetch needed to learn whose posts to
        // want. One attempt; the fetch arms below retry on their own.
        if (!rs.live_start_attempted and rs.live_stream == null and store.authors.len > 0) {
            rs.live_start_attempted = true;
            rs.status = std.fmt.bufPrint(&rs.status_buf, "cached: {d} posts (r refreshes)", .{store.feed.len}) catch "cached";
            rs.live_stream = try startLiveStream(gpa, io, environ, session.did, store, &rs.mailbox, arena);
            if (rs.live_stream != null) rs.subscribed_authors = store.authors.len;
        }

        // Drain the stream's mailbox on the UI thread: plain values in,
        // ingested here, so the store stays single-threaded. Post strings
        // are freed the moment they are ingested — and the unprocessed
        // tail is freed before any error bubbles (C5).
        rs.live_mail.clearRetainingCapacity();
        try rs.mailbox.drain(gpa, &rs.live_mail);
        var mail_i: usize = 0;
        while (mail_i < rs.live_mail.items.len) : (mail_i += 1) {
            switch (rs.live_mail.items[mail_i]) {
                .status => |msg| rs.status = msg,
                .failure => |err| rs.status = std.fmt.bufPrint(
                    &rs.status_buf,
                    "stream: {s}; retrying",
                    .{@errorName(err)},
                ) catch "stream: retrying",
                .post => |post| {
                    const ingested = feed_core.ingestLivePost(gpa, store, post);
                    stream_shell.freePost(gpa, post);
                    const outcome = ingested catch |err| {
                        var rest = mail_i + 1;
                        while (rest < rs.live_mail.items.len) : (rest += 1) {
                            switch (rs.live_mail.items[rest]) {
                                .post => |tail| stream_shell.freePost(gpa, tail),
                                .status, .failure => {},
                            }
                        }
                        return err;
                    };
                    if (outcome == .added) {
                        // A live post inserts at feed index 0. The render
                        // window starts at scroll_top and paints downward, so
                        // to SHOW the arrival we anchor the viewport and the
                        // cursor at the top. (The prior code did scroll_top +=1
                        // to "hold position," but that pushed the window one row
                        // BELOW the new post — rendering everything except the
                        // post that just arrived, the exact "live: new post but
                        // nothing appears" bug. For a firehose the right default
                        // is to surface the new post; hold-position can return
                        // later as a configurable behavior.)
                        rs.state.selected = 0;
                        rs.state.scroll_top = 0;
                        rs.gview.scroll_rows = 0;
                        rs.status = "live: new post";
                    }
                },
            }
        }

        // The front door: its motion, its proof-of-work, its account creation —
        // every frame it is up (FRONT_DOOR_ROADMAP §2/§3).
        if (rs.gscreen == feed_view.screen_enroll) {
            const fns = clock_shell.monotonicNanos();
            // The boot entrance plays FIRST, over the door (§5). It owns the frame
            // while it runs — the door's own motion is stepped anyway, so the card
            // it hands over to is already settled rather than mid-animation.
            bootIntroStep(rs, fns);
            enrollStep(rs, fns, @as(f32, @floatFromInt(@mod(fns / 1_000_000, 1_000_000))) / 1000.0);
            enrollConfirm(rs, io);
            enrollRehearse(rs);
            enrollConnect(rs, gpa, io, environ, fns);
            enrollVerify(rs, gpa, io, environ, fns);
            // Enrollment landed a session: end the pre-auth loop and hand it up.
            // The caller restarts the app AS that person (main.zig / the seam).
            if (rs.genroll_session != null) return .quit;
        }

        // THE ROTATED TOKENS REACH DISK THE FRAME THEY ROTATE.
        //
        // An OAuth refresh token is single-use: the grant hands back a new one
        // and burns the old. We persisted only at teardown — and a kill never
        // reaches teardown. So a rotate-then-die left a SPENT refresh token on
        // disk, and from that moment the device could never write again: every
        // refresh 401s, and the app says "check your connection" while the
        // connection is perfectly fine. Reads keep working (public records need
        // no token), which is what made it look alive. This was the owner's
        // phone, and it would have been every user's phone eventually.
        if (session.rotated) {
            session.rotated = false;
            var sp_buf: [512]u8 = undefined;
            if (session.mode == .oauth) {
                if (cache_shell.oauthSessionPath(&sp_buf, environ)) |sp|
                    _ = cache_shell.saveOAuthSessionAt(gpa, sp, session);
            } else if (cache_shell.sessionPath(&sp_buf, environ)) |sp| {
                _ = cache_shell.saveSessionAt(gpa, sp, session);
            }
            chatLog("[auth] rotated tokens persisted", .{});
        }

        // Drain the chat relay's mailbox (M1): each delivered bucket is an
        // MLS message the E2EE session routes — a decrypted application
        // message becomes a counterparty bubble in the one shared store; a
        // Welcome opens a new conversation (verified against the directory).
        // Damaged/foreign buckets are skipped values, never a dead screen
        // (E2/E4). The surface repaints via the chat signature exactly as a
        // local append does.
        if (rs.gchat_link != null) if (rs.gchat_e2ee) |*st| {
            rs.gchat_mail.clearRetainingCapacity();
            try rs.gchat_box.drain(gpa, &rs.gchat_mail);
            var chat_mutated = false;
            var saw_bucket = false;
            for (rs.gchat_mail.items) |m| {
                switch (m) {
                    .blob => |b| {
                        saw_bucket = true;
                        _ = rs.gchat_arena_state.reset(.retain_capacity);
                        const inc = chat_e2ee.onBucket(gpa, rs.gchat_arena_state.allocator(), io, environ, st, b.id, b.data) catch null;
                        if (inc) |ev| {
                            defer chat_e2ee.freeIncoming(gpa, ev);
                            switch (ev) {
                                .message => |msg| {
                                    if (chat_core.openConversation(gpa, &rs.gchat_store, msg.peer_did, "") catch null) |c| {
                                        _ = chat_core.appendMessage(gpa, &rs.gchat_store, c, msg.kind, msg.text, now, false) catch {};
                                        chat_mutated = true;
                                    }
                                    // The message supersedes its typing bubble.
                                    if (std.mem.eql(u8, msg.peer_did, rs.gchat_typing_peer_buf[0..rs.gchat_typing_peer_len]))
                                        rs.gchat_typing_deadline = 0;
                                },
                                .started => |s| {
                                    _ = chat_core.openConversation(gpa, &rs.gchat_store, s.peer_did, "") catch null;
                                    chat_mutated = true;
                                    rs.status = "chat: new conversation";
                                    chatLog("[chat] started <- {s}", .{s.peer_did});
                                    // A1: tell them it landed. Without this their
                                    // client cannot tell a delivered Welcome from a
                                    // lost one, and a lost one is silent forever.
                                    chatAck(rs, gpa, io, environ, st, s.peer_did, s.device, now);
                                },
                                // The peer RE-ESTABLISHED this conversation (their
                                // side had been lost, or never completed). Verified
                                // against their published anchor, same bar as first
                                // contact. Say so — from here messages will actually
                                // arrive, and before now they silently did not.
                                .restarted => |s| {
                                    _ = chat_core.openConversation(gpa, &rs.gchat_store, s.peer_did, "") catch null;
                                    chat_mutated = true;
                                    rs.status = "chat: conversation re-established";
                                    chatLog("[chat] RE-ESTABLISHED <- {s} (their keys verified)", .{s.peer_did});
                                    // The replacement group has a NEW traffic mailbox.
                                    // Subscribe it NOW rather than relying on the
                                    // post-drain re-walk: "we happen to re-walk after
                                    // a bucket" is not a guarantee, and the failure it
                                    // hides — replies landing in an unwatched address —
                                    // is invisible.
                                    if (rs.gchat_link) |lnk| chatEnsureSubs(gpa, st, lnk);
                                    chatAck(rs, gpa, io, environ, st, s.peer_did, s.device, now);
                                },
                                // Their Welcome, again (A1): the one we already
                                // joined. Our ack never reached them, so they are
                                // still retrying. Nothing changes here — answer.
                                .welcome_again => |s| {
                                    chatLog("[chat] welcome re-delivered <- {s} (re-acking)", .{s.peer_did});
                                    chatAck(rs, gpa, io, environ, st, s.peer_did, s.device, now);
                                },
                                // A2 — the two halves DRIFTED. Their message will
                                // not open under our ratchet, and it is neither
                                // tampering nor a redelivery. This used to be a
                                // silent drop: the thread looked healthy and replies
                                // simply stopped, forever. Now the thread says so and
                                // the saying IS the repair (tap the strip).
                                .drifted => |s| {
                                    chat_mutated = true; // the banner is part of the surface
                                    rs.status = "chat: this conversation needs to reconnect";
                                    chatLog("[chat] DRIFT <- {s} (epochs diverged; offering repair)", .{s.peer_did});
                                },
                                // A2 — the ciphertext did not authenticate. Not drift,
                                // and not something a tap can fix. Refuse it loudly and
                                // never dress it up as a routine reconnect.
                                .tampered => |s| {
                                    rs.status = "chat: a message failed verification and was refused";
                                    chatLog("[chat] REFUSED a message that failed verification <- {s}", .{s.peer_did});
                                },
                                // They ACKED our Welcome (A1): the conversation is
                                // real on both sides. The retry retires and the
                                // thread stops saying "waiting".
                                .confirmed => |s| {
                                    // No store write: an ack is not history. The
                                    // thread's delivery line repaints because the
                                    // delivery state folds into the chat signature,
                                    // and chat_e2ee has already persisted the retired
                                    // retry to its own blob.
                                    rs.status = "chat: they're in — messages will reach them";
                                    chatLog("[chat] welcome CONFIRMED <- {s}", .{s.peer_did});
                                },
                                // Ephemeral: arm the indicator's deadline;
                                // nothing enters the store (M2 never sees it).
                                .typing => |t| if (t.peer_did.len <= rs.gchat_typing_peer_buf.len) {
                                    @memcpy(rs.gchat_typing_peer_buf[0..t.peer_did.len], t.peer_did);
                                    rs.gchat_typing_peer_len = t.peer_did.len;
                                    rs.gchat_typing_deadline = now + 6;
                                },
                                // THE ROSTER (slice 3): another device of ours has
                                // handed over the list of people we talk to. We do
                                // NOT open them here — that is one network
                                // round-trip per person, and doing twenty of them
                                // inside a frame is the freeze this codebase has a
                                // standing law against. They go into a queue and are
                                // opened one per frame, visibly, so the list fills in
                                // in front of the person instead of the app dying.
                                // HISTORY (slice 5). Our other device asked for the
                                // backlog: serialize what we have and send it. The
                                // request already proved it came from one of our own
                                // devices (it decrypted under a session with our own
                                // DID), and the person approved that device
                                // themselves — there is nobody else to ask.
                                .history_request => |h| hreq: {
                                    if (rs.gchat_link) |l| {
                                        const blob = chat_core.serializeStore(gpa, &rs.gchat_store) catch break :hreq;
                                        defer gpa.free(blob);
                                        chatLog("[chat] history -> our other device: {d} bytes", .{blob.len});
                                        chat_e2ee.sendHistory(gpa, io, environ, st, l, h.device, blob) catch |err|
                                            chatLog("[chat] history send failed: {s}", .{@errorName(err)});
                                    }
                                },
                                // A piece of it. Held until the whole thing has
                                // arrived — half a history is not a history, and
                                // adopting one would leave a person with a past that
                                // silently stops in the middle.
                                .history_chunk => |h| hchunk: {
                                    if (h.total == 0 or h.total > 4096) break :hchunk;
                                    if (rs.ghist_total != h.total) {
                                        rs.ghist.clearRetainingCapacity();
                                        rs.ghist_total = h.total;
                                        rs.ghist_have = 0;
                                    }
                                    rs.ghist.appendSlice(gpa, h.bytes) catch break :hchunk;
                                    rs.ghist_have += 1;
                                    if (rs.ghist_have < rs.ghist_total) break :hchunk;

                                    // All of it. Adopt ONLY onto an empty store: this
                                    // is a device that has just been let in, and
                                    // merging two histories is a different, harder
                                    // feature that nobody has asked for.
                                    defer {
                                        rs.ghist.clearRetainingCapacity();
                                        rs.ghist_total = 0;
                                        rs.ghist_have = 0;
                                    }
                                    if (rs.gchat_store.convs.len > 0) {
                                        chatLog("[chat] history arrived but this device already has one — ignored", .{});
                                        break :hchunk;
                                    }
                                    var incoming = chat_core.deserializeStore(gpa, rs.ghist.items) catch {
                                        chatLog("[chat] history arrived damaged — ignored", .{});
                                        break :hchunk;
                                    };
                                    chat_core.deinitStore(gpa, &rs.gchat_store);
                                    rs.gchat_store = incoming;
                                    incoming = .{};
                                    chatPersistHistory(gpa, io, environ, st, &rs.gchat_store);
                                    rs.gdev_hist_state = .done;
                                    rs.status = "chat: your history is here";
                                    chatLog("[chat] history ADOPTED: {d} conversation(s)", .{rs.gchat_store.convs.len});
                                },
                                .roster => |r| {
                                    var it = std.mem.tokenizeScalar(u8, r.dids, '\n');
                                    var queued: usize = 0;
                                    while (it.next()) |did| {
                                        if (rs.groster_n >= rs.groster.len) break;
                                        if (did.len == 0 or did.len > 128) continue;
                                        if (chat_e2ee.hasConversation(st, did)) continue; // already ours
                                        rs.groster[rs.groster_n].len = @intCast(did.len);
                                        @memcpy(rs.groster[rs.groster_n].buf[0..did.len], did);
                                        rs.groster_n += 1;
                                        queued += 1;
                                    }
                                    chatLog("[chat] roster <- our other device: {d} conversation(s) to open", .{queued});
                                },
                                // A payment card (M5 A1): a known id advances
                                // the existing card (one card per payment,
                                // morphing in place); a fresh one lands as a
                                // new card + row.
                                .payment => |p| {
                                    if (chat_core.openConversation(gpa, &rs.gchat_store, p.peer_did, "") catch null) |c| blk: {
                                        const ref: ?[32]u8 = if (std.mem.allEqual(u8, &p.ref, 0)) null else p.ref;
                                        if (chat_core.findPayment(&rs.gchat_store, c, p.id)) |pay| {
                                            // An offer we already hold is a
                                            // duplicate — no-op (E4). Otherwise
                                            // only a `sent` card moves forward.
                                            // To `pending` — the payer INITIATED;
                                            // network evidence (broadcast/
                                            // confirming) is A5's.
                                            if (!p.is_offer and p.kind == .payment_sent) {
                                                if (chat_core.advancePayment(gpa, &rs.gchat_store, pay, .pending, ref) catch false)
                                                    chat_mutated = true;
                                            }
                                        } else {
                                            const pay = chat_core.appendPayment(gpa, &rs.gchat_store, c, p.kind, p.id, p.rail, p.amount_sat, p.note, now, false) catch break :blk;
                                            // S2: an offer to a walletless me lands
                                            // BELOW the kind default — "{P} wants to
                                            // send you {amt}", no money in motion.
                                            if (p.is_offer)
                                                chat_core.initPaymentStatus(&rs.gchat_store, pay, .pending_setup)
                                            else if (ref) |r|
                                                chat_core.setSettlementRef(gpa, &rs.gchat_store, pay, r) catch {};
                                            chat_mutated = true;
                                        }
                                    }
                                    // A card supersedes its typing bubble too.
                                    if (std.mem.eql(u8, p.peer_did, rs.gchat_typing_peer_buf[0..rs.gchat_typing_peer_len]))
                                        rs.gchat_typing_deadline = 0;
                                },
                                // A card-flip event (settlement, or S2 ready/
                                // cancel/decline): advances an existing card to
                                // the carried status; an unknown id is a
                                // straggler, dropped (E4).
                                .payment_update => |u| {
                                    if (chat_core.openConversation(gpa, &rs.gchat_store, u.peer_did, "") catch null) |c| {
                                        if (chat_core.findPayment(&rs.gchat_store, c, u.id)) |pay| {
                                            // Trust gate (§0 golden rule): a peer's
                                            // WITHDRAWAL (cancel/decline) may not
                                            // retire a card the chain has already
                                            // witnessed — that would hide a real
                                            // transfer. Settlement/forward events
                                            // are unaffected. Dropped straggler = E4.
                                            const cur = chat_core.paymentRow(&rs.gchat_store, pay).status;
                                            const withdrawal = u.status == .cancelled or u.status == .declined;
                                            if (!(withdrawal and chat_core.hasNetworkEvidence(cur))) {
                                                const ref: ?[32]u8 = if (std.mem.allEqual(u8, &u.ref, 0)) null else u.ref;
                                                if (chat_core.advancePayment(gpa, &rs.gchat_store, pay, u.status, ref) catch false)
                                                    chat_mutated = true;
                                            }
                                        }
                                    }
                                },
                            }
                        }
                    },
                    // NAME the refusal — "refused" alone hides whether it's
                    // retryable. Rate-limited is transient (back off, resend);
                    // full is the relay under pressure. A generic message is how
                    // a lost send looks like nothing.
                    .refused => |r| {
                        rs.status = switch (r) {
                            .rate_limited => "chat: sending too fast — wait a moment and resend",
                            .mailbox_full => "chat: their inbox is full right now — try again shortly",
                            .store_full => "chat: relay is at capacity — try again shortly",
                            // A4 slice 2: the relay requires a proven identity and
                            // this device has none it accepts. Not retryable by
                            // waiting — say what it is, don't imply patience helps.
                            .unauthenticated => "chat: the relay didn't recognize this device",
                            .ok => "chat: sent",
                        };
                        chatLog("[chat] deposit refused: {s}", .{@tagName(r)});
                    },
                    .status => {},
                    .failure => {},
                }
                chat_relay.freeMail(gpa, m);
            }
            rs.gchat_mail.clearRetainingCapacity();
            // M2: one history write per drain that changed the store. This
            // matters more than the send-side write — forward secrecy means a
            // decrypted message can NEVER be recovered from the wire again, so
            // it reaches disk before this frame ends.
            if (chat_mutated) chatPersistHistory(gpa, io, environ, st, &rs.gchat_store);
            // M2.1: a drained bucket may have advanced an epoch or opened a
            // conversation — re-arm the rotated traffic mailboxes.
            if (saw_bucket) chatEnsureSubs(gpa, st, rs.gchat_link.?);

            // A1 — the unacknowledged-Welcome pump. A Welcome is one shot into
            // a relay whose store is in-memory: lose it to a restart, a
            // disconnect, or a recipient who is simply offline, and the sender
            // keeps believing in a conversation the other side has never heard
            // of. Re-send on a backoff until their ack comes back. Once a
            // second at most; the work is a walk of a few rows against a pure
            // policy, and it deposits only what that policy admits.
            if (now >= rs.gchat_retry_at) {
                rs.gchat_retry_at = now + 1;
                chat_e2ee.retryWelcomes(gpa, environ, st, rs.gchat_link.?, now);
            }

            // THE ROSTER, RECEIVING SIDE (slice 3): open ONE queued conversation per
            // pass. Each is a network round-trip, so they are spread out rather than
            // fired in a burst — the list fills in in front of the person, which is
            // both honest and the only thing the render thread can afford.
            if (rs.groster_n > 0 and now >= rs.gchat_retry_at) {
                const e = rs.groster[rs.groster_n - 1];
                rs.groster_n -= 1;
                const did = e.buf[0..e.len];
                if (!chat_e2ee.hasConversation(st, did)) {
                    chatStartWith(rs, gpa, io, environ, st, did);
                }
            }

            // THE ROSTER, SENDING SIDE: hand our other devices the people we talk
            // to. Only when something actually changed (the device set, or the
            // conversation list) — a quiet app must be a silent one, and re-sending
            // an unchanged roster every tick would be a deposit per device per tick
            // for no reason at all.
            if (now - rs.groster_at >= 15) {
                rs.groster_at = now;
                rosterPublish(rs, gpa, io, environ, st, now);
            }

            // SLICE 4 — KEEP UP WITH WHO PEOPLE ARE. One conversation at a time, in
            // rotation: are they still on the devices we think they are? This is what
            // makes a lost phone survivable WITHOUT anybody re-messaging anybody —
            // and it is where a key change becomes visible instead of silent.
            if (now - rs.gpeer_refresh_at >= 60) {
                rs.gpeer_refresh_at = now;
                peerRefreshNext(rs, gpa, io, environ, st, now);
            }
        };


        // Prefetch OUR own receive-setup once, in the background, the first
        // time we're on the messages screen — so the ₿ button opens the pay
        // sheet with no stall (loadOwnReceive is a PDS fetch; on the click it
        // blocked the render thread). If the user taps before this lands,
        // `.pay_open` still falls back to the sync fetch.
        if (dev_chat and (rs.gscreen == feed_view.screen_messages or rs.gscreen == feed_view.screen_wallet) and !rs.grecv_known) {
            if (rs.greceive_job.thread == null) {
                const a = std.heap.page_allocator;
                if (a.dupe(u8, session.did)) |did_copy| {
                    rs.greceive_job.did = did_copy;
                    rs.greceive_job.done.store(false, .monotonic);
                    rs.greceive_job.found = false;
                    rs.greceive_job.ln_len = 0;
                    rs.greceive_job.btc_len = 0;
                    rs.greceive_job.thread = std.Thread.spawn(.{}, receiveWorker, .{ &rs.greceive_job, io, environ }) catch th: {
                        a.free(did_copy);
                        break :th null;
                    };
                    // Spawn failed → don't retry every frame; the sync fallback covers it.
                    if (rs.greceive_job.thread == null) rs.grecv_known = true;
                } else |_| rs.grecv_known = true;
            } else if (rs.greceive_job.done.load(.acquire)) {
                rs.greceive_job.thread.?.join();
                rs.greceive_job.thread = null;
                // Only adopt the result if the sync path hasn't already answered
                // (it sets grecv_known), so a race can't clobber a fresh save.
                if (!rs.grecv_known) {
                    if (rs.greceive_job.found) {
                        @memcpy(rs.grecv_ln_buf[0..rs.greceive_job.ln_len], rs.greceive_job.ln[0..rs.greceive_job.ln_len]);
                        rs.grecv_ln_len = rs.greceive_job.ln_len;
                        @memcpy(rs.grecv_btc_buf[0..rs.greceive_job.btc_len], rs.greceive_job.btc[0..rs.greceive_job.btc_len]);
                        rs.grecv_btc_len = rs.greceive_job.btc_len;
                        rs.grecv_set = rs.greceive_job.ln_len > 0 or rs.greceive_job.btc_len > 0;
                    } else {
                        rs.grecv_set = false;
                    }
                    rs.grecv_known = true;
                }
                std.heap.page_allocator.free(rs.greceive_job.did);
                rs.greceive_job.did = &.{};
            }
        }

        // Refresh the BTC/USD price off-thread for the ≈$ readout: once on
        // arrival, then every ~5 minutes. A dead source just leaves the last
        // known price (or none — the readout stays hidden).
        if (dev_chat and rs.gscreen == feed_view.screen_messages) {
            if (rs.gprice_job.thread == null and (rs.gprice_cents == 0 or now - rs.gprice_last >= 300)) {
                rs.gprice_last = now;
                rs.gprice_job.done.store(false, .monotonic);
                rs.gprice_job.ok = false;
                rs.gprice_job.thread = std.Thread.spawn(.{}, priceWorker, .{ &rs.gprice_job, io, environ }) catch null;
            } else if (rs.gprice_job.thread) |t| {
                if (rs.gprice_job.done.load(.acquire)) {
                    t.join();
                    rs.gprice_job.thread = null;
                    if (rs.gprice_job.ok) rs.gprice_cents = rs.gprice_job.usd_cents;
                }
            }
        }

        // The send worker's result. THIS is where the wallet opens — not on the
        // click, which is what used to freeze the frame. Everything below is
        // local and fast: open the URI, write the card, persist, signal the peer.
        // The wallet publish landed (off-thread; the no-blocking-IO law). Apply the
        // PDS's verdict: saved → the Done face; refused → the reason, on the face
        // the user is actually looking at.
        if (dev_chat) {
            if (rs.gpublish_job.thread) |t| {
                if (rs.gpublish_job.done.load(.acquire)) {
                    t.join();
                    rs.gpublish_job.thread = null;
                    rs.gpublish_busy = false;
                    rs.grecv_saved = rs.gpublish_job.saved;
                    rs.grecv_status = rs.gpublish_job.status;
                    if (rs.grecv_saved) {
                        // The address is live: remember it as OURS (the sheet and the
                        // Wallet page both read this) and show the saved/Done face.
                        rs.grecv_set = rs.gpublish_job.ln_len > 0 or rs.gpublish_job.btc_len > 0;
                        rs.grecv_known = true;
                        rs.grecv_mode = .paste;
                    }
                }
            }
        }
        if (dev_chat) {
            if (rs.gpay_job.thread) |t| {
                if (rs.gpay_job.done.load(.acquire)) {
                    t.join();
                    rs.gpay_job.thread = null;
                    rs.gpay_busy = false;
                    const job = &rs.gpay_job;
                    const conv: chat_core.ConvIndex = @enumFromInt(job.conv);
                    // The user may have walked away from this conversation while
                    // the network was thinking. Apply the result to the card's OWN
                    // conversation regardless — the payment belongs to it, not to
                    // whatever is on screen now — but only speak to the sheet if
                    // the sheet is still theirs.
                    // The sheet may be spoken to ONLY if this job is the sheet's
                    // own, and the user is still in the conversation it belongs to.
                    // A card-originated result must never close, clear or
                    // disclosure-burn a compose the user is in the middle of.
                    const sheet_is_theirs = job.from_sheet and
                        rs.gpay_open and
                        rs.gchat_sel != null and
                        @intFromEnum(rs.gchat_sel.?) == job.conv;
                    const e2ee = if (rs.gchat_e2ee) |*p| p else null;

                    if (job.err.len > 0) {
                        // A8, failure isolation: say what went wrong, and say it
                        // where the user is looking. NOTHING moved.
                        if (sheet_is_theirs) rs.gpay_status = job.err else rs.status = job.err;
                    } else if (!job.resolved) {
                        // They cannot receive yet. A fresh send becomes an in-thread
                        // OFFER — no money moves, and when they set up a wallet they
                        // signal ready and the payer re-confirms (§4.1). Paying an
                        // existing REQUEST with no payee is a stale record, not an
                        // offer: they asked to be paid, so they had an address.
                        if (job.paying != null) {
                            if (sheet_is_theirs) rs.gpay_status = "They haven't set up payments" else rs.status = "They haven't set up payments";
                        } else {
                            const verdict = payOffer(gpa, io, environ, e2ee, rs.gchat_link, &rs.gchat_store, conv, job.rail, job.amount_sat, job.note, now);
                            if (verdict.len > 0) {
                                if (sheet_is_theirs) rs.gpay_status = verdict else rs.status = verdict;
                            } else if (sheet_is_theirs) {
                                closePaySheet(rs);
                                rs.gpay_amount_len = 0;
                                rs.gpay_note_len = 0;
                                rs.gscroll_px = 0;
                            }
                        }
                    } else if (job.stage == .gate) {
                        // They CAN be paid on this rail. Arm the confirm face — the
                        // last money-hasn't-moved beat before the hand-off.
                        if (sheet_is_theirs) {
                            rs.gpay_step = .confirm;
                            rs.gpay_status = "";
                        }
                    } else {
                        // The hand-off. The URI is built and exact.
                        var minted: u64 = 0;
                        const verdict = payCommit(rs, gpa, io, environ, e2ee, rs.gchat_link, &rs.gchat_store, conv, job.rail, job.amount_sat, job.note, job.paying, now, job.uri_buf[0..job.uri_len], &minted);
                        // THE WATCH. The payee's provider handed us a verify URL
                        // with the invoice, so this payment can confirm ITSELF —
                        // no custody, no wallet connection, nobody trusted. Where
                        // it did not (Strike, Wallet of Satoshi), there is nothing
                        // to watch and the card waits for a human, as their
                        // capability table said it would.
                        if (verdict.len == 0 and minted != 0 and job.verify_len > 0) {
                            verifyWatchAdd(rs, minted, job.conv, job.verify_buf[0..job.verify_len], clock_shell.monotonicNanos());
                        }
                        if (verdict.len > 0) {
                            if (sheet_is_theirs) rs.gpay_status = verdict else rs.status = verdict;
                        } else {
                            rs.status = "pay: handed to your wallet";
                            if (sheet_is_theirs) {
                                closePaySheet(rs);
                                rs.gpay_first_send = false; // the disclosure was acknowledged
                                rs.gpay_amount_len = 0;
                                rs.gpay_note_len = 0;
                                rs.gscroll_px = 0;
                            }
                        }
                    }
                    paySendJobFree(&rs.gpay_job);
                }
            }
        }

        // ── THE SETTLEMENT WATCH (LUD-21). Poll the payee's provider and ask the
        // one question that used to have no answer: has it landed? When it has,
        // the card flips ITSELF to Sent ✓ and the peer is signalled — nobody
        // tapped anything, and nobody had to be trusted. ──
        // MULTI-DEVICE (slice 2). Runs whether or not chat is up, because the
        // device that is WAITING to be let in has no chat state by definition — and
        // it is the one that most needs its screen to keep itself current.
        if (dev_chat) chatDevicesStep(rs, gpa, io, environ, session);

        if (dev_chat) if (rs.gchat_e2ee) |*st| {
            const now_ns = clock_shell.monotonicNanos();

            // Retire watches nobody is coming back for. The card does NOT fail —
            // we simply stop knowing, which is honest, and it falls back to the
            // manual confirm. Silence is never read as settlement.
            {
                var i: usize = 0;
                while (i < rs.gverify_n) {
                    if (now_ns -| rs.gverify[i].started_ns > verify_giveup_ns) {
                        rs.gverify[i] = rs.gverify[rs.gverify_n - 1];
                        rs.gverify_n -= 1;
                        continue;
                    }
                    i += 1;
                }
            }

            if (rs.gverify_job.thread == null and rs.gverify_n > 0) spawn_v: {
                const a = std.heap.page_allocator;
                var items: std.ArrayList(VerifyItem) = .empty;
                for (rs.gverify[0..rs.gverify_n]) |*w| {
                    if (now_ns < w.next_ns) continue;
                    // Brisk while the payer is plausibly still looking at their
                    // wallet; lazy once they have plainly wandered off.
                    const age = now_ns -| w.started_ns;
                    w.next_ns = now_ns + (if (age < verify_fast_window_ns) verify_fast_ns else verify_slow_ns);
                    const u = a.dupe(u8, w.url_buf[0..w.url_len]) catch continue;
                    items.append(a, .{ .payment_id = w.payment_id, .conv = w.conv, .url = u }) catch {
                        a.free(u);
                        break;
                    };
                }
                if (items.items.len == 0) {
                    items.deinit(a);
                    break :spawn_v;
                }
                const owned = items.toOwnedSlice(a) catch {
                    for (items.items) |it| a.free(it.url);
                    items.deinit(a);
                    break :spawn_v;
                };
                rs.gverify_job = .{ .items = owned };
                rs.gverify_job.thread = std.Thread.spawn(.{}, verifyWorker, .{ &rs.gverify_job, io, environ }) catch {
                    verifyJobFree(&rs.gverify_job);
                    break :spawn_v;
                };
            }

            if (rs.gverify_job.thread) |t| {
                if (rs.gverify_job.done.load(.acquire)) {
                    t.join();
                    rs.gverify_job.thread = null;
                    var settled_any = false;
                    for (rs.gverify_job.items) |it| {
                        if (!it.settled) continue; // merely unpaid, or unanswered
                        const conv: chat_core.ConvIndex = @enumFromInt(it.conv);
                        const pay = chat_core.findPayment(&rs.gchat_store, conv, it.payment_id) orelse {
                            verifyWatchDrop(rs, it.payment_id);
                            continue;
                        };
                        if (chat_core.advancePayment(gpa, &rs.gchat_store, pay, .settled, null) catch false) {
                            settled_any = true;
                            // Tell the other side, over the wire byte that has
                            // existed all along and never had anything to say.
                            payCardEvent(gpa, io, environ, st, rs.gchat_link, &rs.gchat_store, conv, it.payment_id, true);
                            rs.status = "pay: settled \u{2014} it landed";
                        }
                        verifyWatchDrop(rs, it.payment_id);
                    }
                    if (settled_any) chatPersistHistory(gpa, io, environ, st, &rs.gchat_store);
                    verifyJobFree(&rs.gverify_job);
                }
            }
        };

        // The wallet probe's answer. Nothing is published yet: the user is taken
        // to the capability review to sign off on what this wallet will and will
        // not do — or told, plainly, that the address does not exist.
        if (dev_chat) {
            if (rs.gcaps_job.thread) |t| {
                if (rs.gcaps_job.done.load(.acquire)) {
                    t.join();
                    rs.gcaps_job.thread = null;
                    rs.grecv_probing = false;
                    if (rs.gcaps_job.err.len > 0) {
                        rs.grecv_status = rs.gcaps_job.err;
                        rs.grecv_mode = .paste; // stay on the form, with the reason
                    } else {
                        rs.gcaps = rs.gcaps_job.caps;
                        rs.grecv_status = "";
                        rs.grecv_mode = .caps; // → the review
                        // Re-run the table's stagger from the top: the rows should
                        // tick in as ANSWERS arriving, not appear pre-filled.
                        if (rs.gpu_state) |*gsp| {
                            gsp.sheet_t = 0;
                            gsp.sheet_v = 0;
                        }
                    }
                    walletProbeJobFree(&rs.gcaps_job);
                }
            }
        }

        // Put NAMES on the nameless. A conversation opened by an inbound message
        // carries only the peer's DID, so without this sweep it addresses a
        // person as `did:plc:uelpy…` — in the chat list, in the thread header,
        // and on the payment cards. Two network legs per DID (the round-trip
        // verification), so it runs on a worker, on the 60s cadence, capped.
        // A DID we could not verify goes in `ghandle_tried` and is never asked
        // about again this run — the honest short DID is its final answer.
        if (dev_chat) {
            if (rs.ghandle_job.thread == null and now - rs.ghandle_last >= chain_poll_seconds) {
                rs.ghandle_last = now;
                _ = rs.gchat_arena_state.reset(.retain_capacity);
                const dids = chat_core.unresolvedDids(rs.gchat_arena_state.allocator(), &rs.gchat_store) catch &.{};
                if (dids.len > 0) spawn_h: {
                    const a = std.heap.page_allocator;
                    var items: std.ArrayList(HandleItem) = .empty;
                    for (dids) |d| {
                        if (items.items.len >= handle_sweep_max) break;
                        if (rs.ghandle_tried.contains(d)) continue;
                        const dd = a.dupe(u8, d) catch continue;
                        items.append(a, .{ .did = dd }) catch {
                            a.free(dd);
                            break;
                        };
                    }
                    if (items.items.len == 0) {
                        items.deinit(a);
                        break :spawn_h;
                    }
                    const owned = items.toOwnedSlice(a) catch {
                        for (items.items) |it| a.free(it.did);
                        items.deinit(a);
                        break :spawn_h;
                    };
                    rs.ghandle_job = .{ .items = owned };
                    rs.ghandle_job.thread = std.Thread.spawn(.{}, handleWorker, .{ &rs.ghandle_job, io, environ }) catch {
                        handleJobFree(&rs.ghandle_job);
                        break :spawn_h;
                    };
                }
            }
            if (rs.ghandle_job.thread) |t| {
                if (rs.ghandle_job.done.load(.acquire)) {
                    t.join();
                    rs.ghandle_job.thread = null;
                    var named = false;
                    for (rs.ghandle_job.items) |it| {
                        if (it.handle_len == 0) {
                            // Refused (no claim, or a claim that failed the round
                            // trip). Remember, so we stop asking. `getOrPut`, not
                            // `put`: put keeps the EXISTING key on a duplicate and
                            // would leak the new one.
                            const gop = rs.ghandle_tried.getOrPut(gpa, it.did) catch continue;
                            if (!gop.found_existing) {
                                gop.key_ptr.* = gpa.dupe(u8, it.did) catch {
                                    _ = rs.ghandle_tried.remove(it.did);
                                    continue;
                                };
                            }
                            continue;
                        }
                        // openConversation interns by DID and reconciles the
                        // handle in place — no new conversation is created.
                        _ = chat_core.openConversation(gpa, &rs.gchat_store, it.did, it.handle[0..it.handle_len]) catch {};
                        named = true;
                    }
                    handleJobFree(&rs.ghandle_job);
                    // Handles live in the persisted store, so writing them back
                    // means the next launch opens already knowing who everyone
                    // is — the sweep is a one-time cost per conversation, not a
                    // per-run one.
                    if (named) if (rs.gchat_e2ee) |*st| chatPersistHistory(gpa, io, environ, st, &rs.gchat_store);
                }
            }
        }

        // Expire stale offers/requests (S2, §6): a pure, local sweep to
        // `expired` for any pre-money card older than the 24h TTL — both sides
        // reach the same terminal from the same `created_at`, no wire. Cheap
        // (linear over a handful of payments); riding the 60s chain cadence
        // keeps it off the per-frame path. Persist only on an actual change.
        if (dev_chat) if (rs.gchat_e2ee) |*st| {
            if (now - rs.gexpire_last >= chain_poll_seconds) {
                rs.gexpire_last = now;
                if (chat_core.sweepExpired(&rs.gchat_store, now, chat_core.payment_offer_ttl_s))
                    chatPersistHistory(gpa, io, environ, st, &rs.gchat_store);
            }
        };

        // The confirmation-watcher (M5 A5): spawn a poll cycle when one is
        // due and none is in flight; drain a finished one. Needs no relay —
        // only the E2EE state (for the pinned anchors) and the store.
        if (dev_chat) if (rs.gchat_e2ee) |*st| {
            if (rs.gchain_job.thread == null and now - rs.gchain_last >= chain_poll_seconds) {
                rs.gchain_last = now;
                _ = rs.gchat_arena_state.reset(.retain_capacity);
                const entries = chat_core.watchList(rs.gchat_arena_state.allocator(), &rs.gchat_store) catch &.{};
                if (entries.len > 0) spawn: {
                    const a = std.heap.page_allocator;
                    const my_pub = anchor_core.publicKey(st.anchor_seed) catch break :spawn;
                    var items: std.ArrayList(ChainItem) = .empty;
                    for (entries) |en| {
                        const conv_did = chat_core.conversationDid(&rs.gchat_store, en.conv);
                        const anchor_pub = if (en.mine_address)
                            my_pub
                        else
                            (chat_e2ee.peerAnchor(st, conv_did) orelse continue);
                        const cd = a.dupe(u8, conv_did) catch continue;
                        const od = a.dupe(u8, if (en.mine_address) st.my_did else conv_did) catch {
                            a.free(cd);
                            continue;
                        };
                        items.append(a, .{
                            .conv_did = cd,
                            .owner_did = od,
                            .owner_anchor = anchor_pub,
                            .payment_id = en.payment_id,
                            .amount_sat = en.amount_sat,
                        }) catch {
                            a.free(cd);
                            a.free(od);
                            break;
                        };
                    }
                    if (items.items.len == 0) {
                        items.deinit(a);
                        break :spawn;
                    }
                    const owned = items.toOwnedSlice(a) catch {
                        for (items.items) |it| {
                            a.free(it.conv_did);
                            a.free(it.owner_did);
                        }
                        items.deinit(a);
                        break :spawn;
                    };
                    rs.gchain_job = .{ .items = owned };
                    rs.gchain_job.thread = std.Thread.spawn(.{}, chainWorker, .{ &rs.gchain_job, io, environ }) catch {
                        chainJobFree(&rs.gchain_job);
                        break :spawn;
                    };
                }
            }
            if (rs.gchain_job.thread) |t| {
                if (rs.gchain_job.done.load(.acquire)) {
                    t.join();
                    rs.gchain_job.thread = null;
                    var chain_mutated = false;
                    for (rs.gchain_job.results) |res| {
                        const depth = res.depth orelse continue;
                        const c = chat_core.openConversation(gpa, &rs.gchat_store, res.conv_did, "") catch continue;
                        const pay = chat_core.findPayment(&rs.gchat_store, c, res.payment_id) orelse continue;
                        if (depth == 0) {
                            // Seen in the mempool: network evidence at last —
                            // the card may say `broadcast` now.
                            if (chat_core.advancePayment(gpa, &rs.gchat_store, pay, .broadcast, null) catch false)
                                chain_mutated = true;
                        } else if (chat_core.setConfirmations(&rs.gchat_store, pay, depth)) {
                            chain_mutated = true;
                        }
                    }
                    if (chain_mutated) chatPersistHistory(gpa, io, environ, st, &rs.gchat_store);
                    chainJobFree(&rs.gchain_job);
                }
            }
        };

        // Drain write-worker results (the non-blocking like/unlike/repost
        // replies). On OK, nothing to do — the optimistic state already
        // shows the right thing. On a refusal or network error, REVERT the
        // optimism so the count returns to truth. This runs every loop
        // iteration, off the network thread, so the UI never blocked on the
        // write — the whole point of the worker.
        rs.write_results.clearRetainingCapacity();
        try rs.write_out.drain(gpa, &rs.write_results);
        for (rs.write_results.items) |res| {
            // Deferred-undo: if the user un-engaged this post WHILE its create
            // was in flight, the create's result is the first moment we can
            // delete the record. Fire the delete now (the optimistic hollow is
            // already shown); on a failed create there's nothing to delete.
            const deferred: ?*std.AutoHashMapUnmanaged(u64, void) = switch (res.kind) {
                .like => &rs.deferred_unlike,
                .repost => &rs.deferred_unrepost,
                .unlike, .unrepost => null,
                .loadout => null, // loadout writes post no result; defensive only
                .publish_algo => null, // its result drives the dev flow below
                .delete_algo => null, // its result drives the dashboard below
                .chain => null, // per-segment post results, reconciled below
            };
            if (deferred) |set| {
                if (set.remove(std.hash.Wyhash.hash(0, res.cid))) {
                    if (res.outcome == .ok and res.outcome.ok.len > 0) {
                        if (rs.writer) |w| _ = write_worker.submit(w, if (res.kind == .like) .unlike else .unrepost, res.cid, "", "", res.outcome.ok, now);
                    }
                    write_worker.freeResult(gpa, res);
                    continue;
                }
            }
            switch (res.outcome) {
                .ok => |uri| {
                    // A finished algorithm publish: land it on the bench and
                    // move the dev flow to its done screen (revert_uri carries
                    // the record CID — the library id / transparency anchor).
                    if (res.kind == .publish_algo) {
                        finishDevPublish(rs, environ, uri, res.revert_uri);
                    } else if (res.kind == .delete_algo) {
                        // Retracted on the wire: drop the library record + the
                        // local marketplace row; the AppView reconciles on its
                        // next poll of this author.
                        if (rs.algo_lib.removeById(res.cid)) {
                            _ = cache_shell.saveLibrary(gpa, environ, &rs.algo_lib);
                        }
                        for (rs.market_catalog.items, 0..) |mr, mi| {
                            if (std.mem.eql(u8, mr.cid, res.cid)) {
                                const r2 = rs.market_catalog.orderedRemove(mi);
                                gpa.free(r2.name);
                                gpa.free(r2.author_disp);
                                gpa.free(r2.author_did);
                                gpa.free(r2.rkey);
                                gpa.free(r2.cid);
                                gpa.free(r2.ranks);
                                gpa.free(r2.desc);
                                gpa.free(r2.tags);
                                break;
                            }
                        }
                        refilterMarket(rs);
                        rs.status = "Deleted — retracted from the marketplace.";
                    } else if (res.kind == .chain) {
                        // A chain segment landed: swap its optimistic temp cid
                        // for the server's real ref (`cid` = the temp key,
                        // `revert_uri` = the REAL record cid — the seat-reuse
                        // precedent, `uri` = the real record uri).
                        feed_core.reconcileOptimisticPost(gpa, store, res.cid, res.revert_uri, uri) catch {};
                    } else if (uri.len > 0) switch (res.kind) {
                        // Record OUR created like/repost uri so a later unlike/
                        // unrepost can delete that record — the AppView never sends
                        // viewer.like, so the optimistic path has no uri otherwise.
                        .like => feed_core.setLikeUri(gpa, store, res.cid, uri) catch {},
                        .repost => feed_core.setRepostUri(gpa, store, res.cid, uri) catch {},
                        .unlike, .unrepost, .loadout, .publish_algo, .delete_algo, .chain => {},
                    };
                },
                .refused => |f| if (res.kind == .chain) {
                    // A refused segment: its optimistic post comes down (the
                    // worker already stopped the rest of the chain).
                    feed_core.dropOptimisticPost(store, res.cid);
                    rs.status = std.fmt.bufPrint(&rs.status_buf, "send refused: {d} {s}", .{ f.status, f.code }) catch "send refused";
                } else if (res.kind == .delete_algo) {
                    rs.status = std.fmt.bufPrint(&rs.status_buf, "delete refused: {d} {s}", .{ f.status, f.code }) catch "delete refused";
                } else if (res.kind == .publish_algo) {
                    rs.gdev_step = .review; // nothing was published; the draft stands
                    rs.gdev_status_len = if (std.fmt.bufPrint(&rs.gdev_status_buf, "The server refused the publish ({d} {s}). Nothing went out — fix and retry.", .{ f.status, f.code })) |m| m.len else |_| 0;
                } else {
                    revertWrite(res.kind, gpa, store, res.cid, res.revert_uri) catch {};
                    rs.status = std.fmt.bufPrint(&rs.status_buf, "refused: {d} {s}", .{ f.status, f.code }) catch "refused";
                },
                .net_error => |name| if (res.kind == .chain) {
                    feed_core.dropOptimisticPost(store, res.cid);
                    rs.status = if (std.mem.eql(u8, name, "ChainStopped"))
                        rs.status // keep the first failure's message
                    else
                        std.fmt.bufPrint(&rs.status_buf, "send failed: {s}", .{name}) catch "send failed";
                } else if (res.kind == .delete_algo) {
                    rs.status = std.fmt.bufPrint(&rs.status_buf, "delete failed: {s} — retry", .{name}) catch "delete failed";
                } else if (res.kind == .publish_algo) {
                    rs.gdev_step = .review;
                    rs.gdev_status_len = if (std.fmt.bufPrint(&rs.gdev_status_buf, "Couldn't reach your repo ({s}). Nothing went out — retry when you're online.", .{name})) |m| m.len else |_| 0;
                } else {
                    revertWrite(res.kind, gpa, store, res.cid, res.revert_uri) catch {};
                    rs.status = std.fmt.bufPrint(&rs.status_buf, "network error: {s}", .{name}) catch "network error";
                },
            }
            write_worker.freeResult(gpa, res);
        }

        // Auto-refresh tick: in timeline mode, once the interval has elapsed,
        // SUBMIT the same getTimeline the `r` key runs to the refresh worker —
        // the fetch happens off this thread and its page is drained below, so
        // the living field never hitches on the round trip. This ALSO does the
        // initial load: an empty store (a cleared cache / first run) would
        // otherwise never fetch — the window path has no separate startup
        // fetch, so the first tick is the first load. Failure is contained to
        // the status line (E2). Never fires mid-compose, so it cannot disturb
        // a draft.
        if (rs.refresh_interval > 0 and rs.mode == .timeline and rs.refresh_inflight == 0 and
            now - rs.last_auto_refresh >= rs.refresh_interval and
            clock_shell.monotonicNanos() -| rs.last_input_nanos >= input_idle_gate_nanos)
        {
            rs.last_auto_refresh = now;
            if (rs.refresher) |w| {
                if (refresh_worker.submit(w, .auto, 30)) {
                    rs.refresh_inflight += 1;
                    mobile_host.logcat("refresh: auto tick submitted", .{});
                }
            } else mobile_host.logcat("refresh: NO worker (spawn failed at startup) — auto-refresh is off", .{});
            // No worker (spawn failed at startup): auto-refresh is simply off;
            // the `r` key's synchronous path still loads the feed (E2).
        }

        // Pull-to-refresh: the overscroll gesture asked for a refresh — same
        // worker, marked .pull so the drain below reveals + jumps (an EXPLICIT
        // pull asks to SEE the new, unlike the passive auto tick).
        if (rs.pull_refresh_requested) {
            rs.pull_refresh_requested = false;
            if (rs.refresher) |w| {
                rs.status = "refreshing...";
                if (refresh_worker.submit(w, .pull, 30)) rs.refresh_inflight += 1;
            } else rs.status = "refresh unavailable (r refreshes)";
        }

        // Drain fetched pages. The ingest is the CPU half (pure functions over
        // the fetched values — the store belongs to this thread); the reveal
        // choreography is unchanged from the old inline refresh: an auto tick
        // STAGES new posts behind the "N new posts" pill (revealing only on
        // first load or at the very top of Home, so the reader's place is
        // never yanked — the Twitter/Bluesky pattern); a pull reveals + jumps.
        rs.refresh_results.clearRetainingCapacity();
        try rs.refresh_out.drain(gpa, &rs.refresh_results);
        for (rs.refresh_results.items) |res| {
            rs.refresh_inflight -|= 1;
            switch (res.outcome) {
                .ok => |page| if (res.trigger == .older) {
                    // Load-more: APPEND (ingestPage walks the cursor down);
                    // the refresh prepend below would misfile older rows.
                    const stats = feed_core.ingestPage(gpa, store, page) catch |err| {
                        refresh_worker.freeResult(gpa, res);
                        return err; // OOM only
                    };
                    rs.status = std.fmt.bufPrint(&rs.status_buf, "+{d} older ({d} seen)", .{
                        stats.items_added, stats.posts_deduped,
                    }) catch "loaded";
                    _ = cache_shell.saveStore(gpa, environ, store); // E4
                    if (rs.live_stream == null and store.authors.len > 0) {
                        rs.live_stream = startLiveStream(gpa, io, environ, session.did, store, &rs.mailbox, arena) catch |err| {
                            refresh_worker.freeResult(gpa, res);
                            return err; // OOM only — same posture as the ingest arm
                        };
                        if (rs.live_stream == null) rs.status = "live stream unavailable" else rs.subscribed_authors = store.authors.len;
                    }
                } else {
                    const was_empty = store.feed.len == 0;
                    const stats = feed_core.ingestPageRefresh(gpa, store, page) catch |err| {
                        refresh_worker.freeResult(gpa, res);
                        return err; // OOM only
                    };
                    mobile_host.logcat("refresh: OK +{d} items ({d} posts in store)", .{ stats.items_added, store.posts.len });
                    switch (res.trigger) {
                        .auto => if (feed_core.pendingCount(store) > 0) {
                            const at_top_home = rs.gscreen == feed_view.screen_home and rs.gscroll_px == 0;
                            if (was_empty or at_top_home) {
                                _ = feed_core.revealPending(gpa, store) catch 0;
                                rs.state.selected = 0;
                                rs.state.scroll_top = 0;
                                rs.gview.scroll_rows = 0;
                                rs.gscroll_px = 0;
                            }
                            // else: the pill (feed_core.pendingCount) carries the count.
                        },
                        .older => unreachable, // took the append branch above
                        .pull => {
                            const revealed_n = feed_core.revealPending(gpa, store) catch 0;
                            if (revealed_n > 0) {
                                rs.state.selected = 0;
                                rs.state.scroll_top = 0;
                                rs.gview.scroll_rows = 0;
                                rs.gscroll_px = 0;
                            }
                            rs.status = if (stats.items_added == 0 and revealed_n == 0)
                                "no new posts"
                            else
                                std.fmt.bufPrint(&rs.status_buf, "+{d} new at top", .{revealed_n}) catch "new posts";
                            // Parity with the old inline `r`: an explicit
                            // refresh that finds a populated store may also
                            // bring the live stream up.
                            if (rs.live_stream == null and store.authors.len > 0) {
                                rs.live_stream = startLiveStream(gpa, io, environ, session.did, store, &rs.mailbox, arena) catch |err| {
                                    refresh_worker.freeResult(gpa, res);
                                    return err; // OOM only — same posture as the ingest arm above
                                };
                                if (rs.live_stream == null) rs.status = "live stream unavailable" else rs.subscribed_authors = store.authors.len;
                            }
                        },
                    }
                    _ = cache_shell.saveStore(gpa, environ, store); // E4: a failed save is simply no cache
                },
                .refused => |f| switch (res.trigger) {
                    .auto => mobile_host.logcat("refresh: REFUSED {d} {s}", .{ f.status, f.code }), // silent on desktop; the next tick retries
                    // bufPrint COPIES f.code into status_buf before freeResult
                    // destroys the arena that owns it.
                    .pull, .older => rs.status = std.fmt.bufPrint(&rs.status_buf, "refused: {d} {s}", .{ f.status, f.code }) catch "refused",
                },
                .net_error => |errname| switch (res.trigger) {
                    .auto => {
                        rs.status = "auto-refresh: network error"; // contained
                        mobile_host.logcat("refresh: NET ERROR {s}", .{errname});
                    },
                    .pull, .older => rs.status = "network error", // contained (E2)
                },
            }
            refresh_worker.freeResult(gpa, res);
        }

        // Drain view-entry loads. The network half ran on the view worker;
        // only the ingest (pure functions over the fetched values — the store
        // belongs to this thread) runs here. A late page whose view the user
        // already left ingests harmlessly: content lands in the SHARED store
        // and every screen is a query over it (ZONES inv. 4), so there is no
        // stale-view hazard to guard.
        rs.viewload_results.clearRetainingCapacity();
        try rs.viewload_out.drain(gpa, &rs.viewload_results);
        for (rs.viewload_results.items) |res| {
            switch (res.outcome) {
                .page => |page| {
                    _ = feed_core.ingestPosts(gpa, store, page) catch |err| {
                        view_worker.freeResult(gpa, res);
                        return err; // OOM only
                    };
                    rs.status = ""; // the submit's "loading..." line is done
                },
                .zones => |tags| {
                    // Merge the AppView's catalog over the locally-derived set
                    // the browse entry built: a server count is authoritative
                    // (it spans posts this client hasn't loaded), and a
                    // server-only zone is appended. A skipped dup (OOM) drops
                    // one row, not the screen (E2).
                    for (tags) |t| {
                        var found = false;
                        for (rs.zone_catalog.items) |*zc| {
                            if (std.ascii.eqlIgnoreCase(zc.tag, t.tag)) {
                                zc.count = @max(zc.count, t.count);
                                // A server that predates the community stats
                                // sends zeros (lastAt 0 marks it) — keep the
                                // locally-derived numbers rather than letting
                                // the merge ERASE them a beat after they show
                                // (the "stats blink away" live finding, E4).
                                if (t.lastAt != 0) {
                                    zc.authors = t.authors;
                                    zc.recent = t.recent;
                                    zc.last_at = t.lastAt;
                                }
                                found = true;
                                break;
                            }
                        }
                        if (!found) {
                            const dup = gpa.dupe(u8, t.tag) catch continue;
                            rs.zone_catalog.append(gpa, .{ .tag = dup, .count = t.count, .authors = t.authors, .recent = t.recent, .last_at = t.lastAt, .pinned = pin_store.has(&rs.zone_pins, t.tag) }) catch gpa.free(dup);
                        }
                    }
                    feed_view.sortZonesByActivity(rs.zone_catalog.items);
                    rs.status = "";
                },
                .algorithms => |algos| {
                    refillMarket(gpa, algos, &rs.market_catalog, &rs.market_cards) catch |err| {
                        view_worker.freeResult(gpa, res);
                        return err; // OOM only
                    };
                    refilterMarket(rs); // re-apply the live search over the fresh catalog
                    rs.market_prefetch_next = 0; // fresh catalog → warm every config again
                    rs.market_loading = false;
                    rs.status = "";
                },
                // bufPrint COPIES f.code into status_buf before freeResult
                // destroys the arena that owns it.
                .refused => |f| rs.status = std.fmt.bufPrint(&rs.status_buf, "{s}: refused {d} {s}", .{
                    viewNoun(res.kind), f.status, f.code,
                }) catch "refused",
                .net_error => rs.status = std.fmt.bufPrint(&rs.status_buf, "{s}: network error", .{
                    viewNoun(res.kind),
                }) catch "network error", // contained (E2)
            }
            view_worker.freeResult(gpa, res);
        }

        // Premium Profile screen: on ENTERING it (the rail click flips gscreen),
        // SUBMIT the viewed account's feed to the view worker — a fresh fetch
        // each visit, off the frame thread (M-Core.1 unblocking, 3/7). The
        // drain above ingests the page as CONTENT into the SHARED store when
        // it lands; failure stays a status line (E2). Gated to the timeline
        // mode + window path.
        const on_profile = rs.mode == .timeline and rs.gscreen == feed_view.screen_profile;
        if (on_profile and (!rs.on_profile_prev or rs.profile_dirty)) {
            if (rs.viewloader) |w| {
                // The target lives in a mutable UI buffer the next tap
                // rewrites — the worker owns a gpa copy.
                const actor = try gpa.dupe(u8, rs.profile_target_did);
                if (view_worker.submit(w, .profile, actor, 30)) {
                    rs.status = "loading profile...";
                } else {
                    gpa.free(actor);
                    rs.status = "profile load skipped"; // mailbox OOM; re-entering retries
                }
            } else rs.status = "profile: unavailable"; // worker never started (E2: a status, not a dead screen)
            rs.profile_dirty = false;
        }
        rs.on_profile_prev = on_profile;

        // Thread screen: on ENTERING (a post-body tap flips gscreen) or a target
        // change, SUBMIT the focused post's thread to the view worker (M-Core.1
        // unblocking, 4/7); the drain above ingests it as CONTENT into the
        // SHARED store. The view ordering is then a query (buildThreadView) —
        // the tapped post is already resident, so the screen shows it at once
        // and the ancestors/replies fill in when the page lands. Same E2
        // containment as the profile submit.
        const on_thread = rs.mode == .timeline and rs.gscreen == feed_view.screen_thread;
        if (on_thread and (!rs.on_thread_prev or rs.thread_dirty)) {
            if (rs.viewloader) |w| {
                const uri = try gpa.dupe(u8, rs.thread_focus_uri);
                if (view_worker.submit(w, .thread, uri, 50)) {
                    rs.status = "loading thread...";
                } else {
                    gpa.free(uri);
                    rs.status = "thread load skipped"; // mailbox OOM; re-entering retries
                }
            } else rs.status = "thread: unavailable"; // worker never started (E2)
            rs.thread_dirty = false;
        }
        rs.on_thread_prev = on_thread;

        // Zone page: on ENTERING (a tag-pill tap flips gscreen) or a tag change,
        // SUBMIT the zone's feed to the view worker (M-Core.1 unblocking, 5/7);
        // the drain above ingests it as CONTENT into the SHARED store. The view
        // ordering is then a query (buildTagView) — resident posts wearing the
        // tag show at once; the rest fill in when the page lands. Same E2
        // containment as the other view submits.
        const on_zone = rs.mode == .timeline and rs.gscreen == feed_view.screen_zones;
        if (on_zone and (!rs.on_zone_prev or rs.zone_dirty)) {
            if (rs.viewloader) |w| {
                const tag = try gpa.dupe(u8, rs.zone_tag);
                if (view_worker.submit(w, .zone, tag, 50)) {
                    rs.status = "loading zone...";
                } else {
                    gpa.free(tag);
                    rs.status = "zone load skipped"; // mailbox OOM; re-entering retries
                }
            } else rs.status = "zone: unavailable"; // worker never started (E2)
            rs.zone_dirty = false;
        }
        rs.on_zone_prev = on_zone;

        // Zones BROWSE: on ENTERING the catalog screen, rebuild the local
        // catalog and submit the server's zone set (`listTags`). Metadata, not
        // posts — it doesn't touch the store. Contained failure (E2): the grid
        // just stays as it was.
        const on_browse = rs.mode == .timeline and rs.gscreen == feed_view.screen_zones_browse;
        if (on_browse and !rs.on_browse_prev) {
            // The catalog the client can see NOW: derive it from the resident store
            // so a zone whose posts are loaded lists IMMEDIATELY, independent of the
            // AppView's `listTags` (ZONES inv. 4 — a zone catalog is a query, the
            // same as its feed). This is why a zone reachable by tapping its hashtag
            // must also appear here. The server's wider set merges on top.
            for (rs.zone_catalog.items) |zc| gpa.free(zc.tag);
            rs.zone_catalog.clearRetainingCapacity();
            if (feed_core.listZonesLocal(arena, store, now - 24 * 60 * 60) catch null) |local| {
                for (local) |t| {
                    const dup = gpa.dupe(u8, t.tag) catch continue;
                    rs.zone_catalog.append(gpa, .{ .tag = dup, .count = t.count, .authors = t.authors, .recent = t.recent, .last_at = t.lastAt, .pinned = pin_store.has(&rs.zone_pins, t.tag) }) catch gpa.free(dup);
                }
            }
            // A pinned zone whose posts aren't resident still deserves its
            // shelf spot — append it as a bare card (the server merge fills
            // the stats in when `listTags` lands).
            pins: for (rs.zone_pins.tags.items) |ptag| {
                for (rs.zone_catalog.items) |zc| {
                    if (std.ascii.eqlIgnoreCase(zc.tag, ptag)) continue :pins;
                }
                const dup = gpa.dupe(u8, ptag) catch continue;
                rs.zone_catalog.append(gpa, .{ .tag = dup, .count = 0, .pinned = true }) catch gpa.free(dup);
            }
            feed_view.sortZonesByActivity(rs.zone_catalog.items);
            // The AppView's wider catalog: SUBMIT to the view worker (M-Core.1
            // unblocking, 6/7); the drain above merges it over this local set
            // when it lands (a server count is authoritative). Failure leaves
            // the local set showing — a status line, never a dead grid (E2).
            if (rs.viewloader) |w| {
                if (view_worker.submit(w, .zones, null, 0)) {
                    rs.status = "loading zones...";
                } else rs.status = "zones load skipped"; // mailbox OOM; re-entering retries
            } else rs.status = "zones: unavailable"; // worker never started (E2)
        }
        rs.on_browse_prev = on_browse;

        // MARKETPLACE: on ENTERING the Algorithms → Marketplace tab, SUBMIT the
        // published-algorithms fetch (`getAlgorithms`) to the view worker
        // (M-Core.1 unblocking, 7/7); the drain above refills the owned catalog
        // when the page lands. Metadata, not posts — it doesn't touch the
        // store. Contained failure (E2).
        // Warm the marketplace ONCE at startup: the first fetch rides a cold
        // TLS connection (seconds through the proxy) — prefetching means the
        // tab usually opens populated instead of blank (owner-hit bug; the
        // browse also shows an honest loading state now, never the
        // "nothing published" lie while a fetch is in flight).
        if (!rs.market_prefetched and rs.mode == .timeline) {
            rs.market_prefetched = true;
            if (rs.viewloader) |w| {
                if (view_worker.submit(w, .algorithms, null, 50)) rs.market_loading = true;
            }
        }
        const on_market = rs.mode == .timeline and rs.gscreen == feed_view.screen_loadout and rs.gloadout_tab == 1;
        if (on_market and !rs.on_market_prev) {
            if (rs.viewloader) |w| {
                if (view_worker.submit(w, .algorithms, null, 50)) {
                    rs.status = "loading marketplace...";
                    rs.market_loading = true;
                } else rs.status = "marketplace load skipped"; // mailbox OOM; re-entering retries
            } else rs.status = "marketplace: unavailable"; // worker never started (E2)
        }
        rs.on_market_prev = on_market;

        // Consume a finished background config fetch (View details): after the
        // worker signals done, join it and copy its page_allocator result into the
        // render gpa (no concurrency past the join), then free the worker copy.
        if (rs.inspectjob.active and rs.inspectjob.done.load(.acquire)) {
            joinInspect(&rs.inspectjob);
            if (rs.inspectjob.ok) {
                if (rs.inspectjob.bytes) |b| {
                    if (rs.inspect_bytes) |old| gpa.free(old);
                    rs.inspect_bytes = gpa.dupe(u8, b) catch null;
                    // Cache the config by CID (A8) so a re-view never re-fetches.
                    if (rs.inspect_ref.len > 0 and !rs.config_cache.contains(rs.inspect_ref)) {
                        const k = gpa.dupe(u8, rs.inspect_ref) catch null;
                        const v = gpa.dupe(u8, b) catch null;
                        if (k != null and v != null) {
                            rs.config_cache.put(gpa, k.?, v.?) catch {
                                gpa.free(k.?);
                                gpa.free(v.?);
                            };
                        } else {
                            if (k) |kk| gpa.free(kk);
                            if (v) |vv| gpa.free(vv);
                        }
                    }
                    std.heap.page_allocator.free(b);
                    rs.inspectjob.bytes = null;
                }
                // The record's Zal source, beside the config (schema rev): shown
                // by the source sub-view when present; cached like the config.
                if (rs.inspect_src) |old_src| gpa.free(old_src);
                rs.inspect_src = null;
                if (rs.inspectjob.src) |sb| {
                    rs.inspect_src = gpa.dupe(u8, sb) catch null;
                    if (rs.inspect_ref.len > 0 and !rs.src_cache.contains(rs.inspect_ref)) {
                        const k = gpa.dupe(u8, rs.inspect_ref) catch null;
                        const v = gpa.dupe(u8, sb) catch null;
                        if (k != null and v != null) {
                            rs.src_cache.put(gpa, k.?, v.?) catch {
                                gpa.free(k.?);
                                gpa.free(v.?);
                            };
                        } else {
                            if (k) |kk| gpa.free(kk);
                            if (v) |vv| gpa.free(vv);
                        }
                    }
                    std.heap.page_allocator.free(sb);
                    rs.inspectjob.src = null;
                }
                // Install latched before the config arrived: finish it now —
                // the fetched row is found by CID (the browse may have moved).
                if (rs.gdetail_install_pending) {
                    rs.gdetail_install_pending = false;
                    if (rs.inspect_bytes) |cfg_bytes| {
                        for (rs.market_catalog.items, 0..) |mr, mrow| {
                            if (std.mem.eql(u8, mr.cid, rs.inspect_ref)) {
                                installMarketAlgo(rs, environ, mrow, cfg_bytes);
                                break;
                            }
                        }
                    }
                }
            } else {
                rs.status = "algorithm: unavailable";
                rs.gdetail_install_pending = false;
                mobile_host.logcat("inspect: job failed — the page shows the error state", .{});
            }
            rs.inspect_loading = false;
        }

        // MARKETPLACE PREFETCH (its own job — a user tap never blocks on it):
        // consume a finished background fetch into the CID caches, then kick the
        // next catalog row when idle. The first Details/install used to pay a
        // live DID resolve + a cross-PDS getRecord (seconds); warming every
        // listed config as soon as the catalog lands makes them instant (A8:
        // same CID ⇒ same bytes, cached forever). Failures are silent — the
        // user-tap path still fetches live and shows the honest error page.
        if (rs.prefetchjob.active and rs.prefetchjob.done.load(.acquire)) {
            joinInspect(&rs.prefetchjob);
            if (rs.prefetchjob.ok) {
                const ref = rs.prefetchjob.cid[0..rs.prefetchjob.cid_len];
                if (rs.prefetchjob.bytes) |b| {
                    if (ref.len > 0 and !rs.config_cache.contains(ref)) {
                        const k = gpa.dupe(u8, ref) catch null;
                        const v = gpa.dupe(u8, b) catch null;
                        if (k != null and v != null) {
                            rs.config_cache.put(gpa, k.?, v.?) catch {
                                gpa.free(k.?);
                                gpa.free(v.?);
                            };
                        } else {
                            if (k) |kk| gpa.free(kk);
                            if (v) |vv| gpa.free(vv);
                        }
                    }
                    std.heap.page_allocator.free(b);
                    rs.prefetchjob.bytes = null;
                }
                if (rs.prefetchjob.src) |sb| {
                    if (ref.len > 0 and !rs.src_cache.contains(ref)) {
                        const k = gpa.dupe(u8, ref) catch null;
                        const v = gpa.dupe(u8, sb) catch null;
                        if (k != null and v != null) {
                            rs.src_cache.put(gpa, k.?, v.?) catch {
                                gpa.free(k.?);
                                gpa.free(v.?);
                            };
                        } else {
                            if (k) |kk| gpa.free(kk);
                            if (v) |vv| gpa.free(vv);
                        }
                    }
                    std.heap.page_allocator.free(sb);
                    rs.prefetchjob.src = null;
                }
            }
        }
        // Cap the bulk-warm: at marketplace scale, prefetching EVERY config would
        // be needless bytes + requests — the head of the list (what a browser
        // actually taps) warms; the tail stays lazy via the live fetch path.
        const market_prefetch_cap: usize = 24;
        if (!rs.prefetchjob.active and rs.market_prefetch_next < @min(market_prefetch_cap, rs.market_catalog.items.len)) {
            const pr = rs.market_catalog.items[rs.market_prefetch_next];
            rs.market_prefetch_next += 1;
            if (!rs.config_cache.contains(pr.cid)) {
                startInspect(&rs.prefetchjob, io, environ, session.pds_url, pr.author_did, pr.rkey);
                // The cache key, stamped AFTER the spawn: the worker never reads
                // it — only this drain does, after the join.
                const cl = @min(pr.cid.len, rs.prefetchjob.cid.len);
                @memcpy(rs.prefetchjob.cid[0..cl], pr.cid[0..cl]);
                rs.prefetchjob.cid_len = cl;
            }
        }

        // The ACTIVE view: Home (one ordering over the store), the profile screen
        // (the TARGET author's posts), a post's THREAD, or a ZONE (a tag query) —
        // each a query over the SAME store. One list of view-models the render +
        // input + engagement paths all key off; the post records (and so
        // engagement + identity) are shared (ZONES invariant 4).
        // The seated lens per surface decides ordering: the FEED lens whether
        // Home is scored (and by which algorithm), the REPLY lens how a thread's
        // siblings order (null on either = the no-scoring path: feed order /
        // chronological threading). Resolved once per frame and reused by the
        // engagement repaints so they rebuild through the same algorithm.
        const feed_config = seatedLensConfig(arena, &rs.algo_lib, rs.socket_cards, rs.socket_blob, rs.gseated);
        const reply_config = seatedLensConfig(arena, &rs.algo_lib, rs.reply_cards, rs.reply_blob, rs.reply_seated);
        const view_items: []const feed_core.TimelineItem = if (on_thread)
            try feed_core.buildThreadView(arena, store, rs.thread_focus_cid, rs.thread_rerooted, rs.gcollapsed.items, now, reply_config)
        else if (on_profile)
            try feed_core.buildAuthorView(arena, store, rs.profile_target_did)
        else if (on_zone)
            try feed_core.buildTagView(arena, store, rs.zone_tag)
        else if (feed_config) |cfg|
            try feed_core.buildDiscoverView(arena, store, cfg, now, null)
        else
            try feed_core.buildTimeline(arena, store);
        const profile_header = try profileHeaderFor(arena, session, rs.gscreen, rs.profile_target_did, view_items);
        // Advance the seat animation one step per painted frame, resetting at
        // the end of the swap (the field animates continuously, so frames
        // flow). The widget maps swap_phase→geometry purely (B4).
        // Advance every surface's swap (home / reply / zone) — a swipe can now
        // re-seat any of them, so each needs its clock advanced. swap_dir resets
        // with swap_phase so the next TAP re-seat falls back to the vertical eject.
        for ([_]*lens_socket.SocketUi{ &rs.gsocket_ui, &rs.reply_ui, &rs.zone_ui }) |sui| {
            if (sui.swap_phase > 0) {
                sui.swap_phase +|= 1;
                if (sui.swap_phase > lens_socket.swap_total_frames) {
                    sui.swap_phase = 0;
                    sui.swap_dir = 0;
                }
            }
        }
        // Spring-open: ease each switcher socket's open progress toward its open
        // state. The widget sweeps the tray + reveals cards by this (page sockets
        // force open_t=1 in their render, so this is a no-op there).
        {
            const oe: f32 = 0.34;
            rs.gsocket_ui.open_t += ((if (rs.gsocket_ui.open) @as(f32, 1) else 0) - rs.gsocket_ui.open_t) * oe;
            rs.reply_ui.open_t += ((if (rs.reply_ui.open) @as(f32, 1) else 0) - rs.reply_ui.open_t) * oe;
            rs.zone_ui.open_t += ((if (rs.zone_ui.open) @as(f32, 1) else 0) - rs.zone_ui.open_t) * oe;
            // Zones hub motion: the tab underline GLIDES toward the active tab
            // and the incoming tab body settles in. (Page ENTRY rides the GPU
            // path's screen-switch crossfade — no extra state here.)
            rs.gzones_tab_t += (@as(f32, @floatFromInt(rs.gzones_tab)) - rs.gzones_tab_t) * 0.30;
            rs.gzones_enter_t += (1.0 - rs.gzones_enter_t) * 0.22;
        }
        // The open zone's community stats — distinct posters + newest post over
        // the zone view (≤50 rows; plain compares, no allocation). The masthead
        // draws only real numbers (0 people = the line stays posts-only).
        if (on_zone) {
            var people: usize = 0;
            var last_at: i64 = 0;
            for (view_items, 0..) |it, i| {
                if (it.created_at > last_at) last_at = it.created_at;
                var seen_before = false;
                for (view_items[0..i]) |prev| {
                    if (std.mem.eql(u8, prev.author_handle, it.author_handle)) {
                        seen_before = true;
                        break;
                    }
                }
                if (!seen_before) people += 1;
            }
            rs.zone_people = people;
            rs.zone_last_at = last_at;
        }
        const home_tray: lens_socket.TrayView = .{ .cards = rs.socket_cards, .text = rs.socket_blob, .seated = rs.gseated };
        // Advance the drag's LIVE REFLOW + lift + settle one step per frame (the
        // iOS "pick up and the others fill in" feel). The targets are pure
        // integer slot math; positions are eased here, drawn by the widget.
        const socket_layout_w: i32 = if (rs.gpu_state) |*sgs| @intCast(sgs.design_w) else switch (backend) {
            .window => |w| @intCast(w.fb.width),
            else => @intCast(design_w),
        };
        if (rs.gscreen == feed_view.screen_loadout) {
            // On the page, advance whichever surface is mid-drag, using its
            // on-page geometry (from last frame's layoutLoadout). Clear the
            // drag once its settle finishes (drag_active goes null).
            if (rs.page_drag_surface) |s| {
                switch (s) {
                    0 => advanceSocketDrag(&rs.gsocket_ui, home_tray, rs.page_geoms[0]),
                    1 => advanceSocketDrag(&rs.reply_ui, .{ .cards = rs.reply_cards, .text = rs.reply_blob, .seated = rs.reply_seated }, rs.page_geoms[1]),
                    else => advanceSocketDrag(&rs.zone_ui, .{ .cards = rs.zone_cards, .text = rs.zone_blob, .seated = rs.zone_seated }, rs.page_geoms[2]),
                }
                const ui_done = switch (s) {
                    1 => rs.reply_ui.drag_active == null,
                    2 => rs.zone_ui.drag_active == null,
                    else => rs.gsocket_ui.drag_active == null,
                };
                if (ui_done) rs.page_drag_surface = null;
            }
        } else {
            advanceSocketDrag(&rs.gsocket_ui, home_tray, feed_view.homeSocketGeom(socket_layout_w));
        }
        // Persist the loadout when the tray CLOSES (the "done editing" beat).
        // Hand it to the BACKGROUND write worker (the same thread that does
        // likes/reposts) so the putRecord never blocks the UI loop — this is
        // the fix for the freeze on cartridge-switch (seating closes the tray,
        // which used to do a synchronous network write right here). The ids
        // are slices into socket_blob; submitLoadout dupes them.
        // Flush on the home tray CLOSING, or on LEAVING the loadout page (whose
        // sockets are always open, so there's no tray-close there).
        const left_loadout_page = rs.prev_screen == feed_view.screen_loadout and rs.gscreen != feed_view.screen_loadout;
        const left_thread = rs.prev_screen == feed_view.screen_thread and rs.gscreen != feed_view.screen_thread;
        const left_zone = rs.prev_screen == feed_view.screen_zones and rs.gscreen != feed_view.screen_zones;
        const tray_closed = rs.socket_was_open and !rs.gsocket_ui.open;
        if ((tray_closed or left_loadout_page or left_thread or left_zone) and rs.loadout_dirty) {
            if (rs.writer) |w| {
                // Write the WHOLE record (all three surfaces) so one surface's
                // edit doesn't clobber the others. ids slice into each surface's
                // blob; submitLoadout dupes them onto the worker.
                _ = write_worker.submitLoadout(
                    w,
                    surfaceDataOf(arena, rs.socket_cards, rs.socket_blob, rs.gseated),
                    surfaceDataOf(arena, rs.reply_cards, rs.reply_blob, rs.reply_seated),
                    surfaceDataOf(arena, rs.zone_cards, rs.zone_blob, rs.zone_seated),
                    now,
                );
            }
            rs.loadout_dirty = false;
        }
        rs.socket_was_open = rs.gsocket_ui.open;
        rs.prev_screen = rs.gscreen;
        // The feed-socket hit list is rebuilt every frame by layout()/
        // layoutLoadout() (both clear it at entry). Zat Chat and the transparency
        // reader are the two dispatch branches that render NEITHER, so without this
        // they scan the previous screen's stale seats — the cursor, the GPU hover
        // wash, and the click path all read g.socket_hits, which is why the
        // Algorithms grid stayed lit behind the chat. Clear it on those screens
        // (before the event pump) so they present no phantom socket targets. The
        // reply/zone hit lists are already screen-gated to the loadout page, so
        // only this list can leak across the switch.
        if (rs.gscreen == feed_view.screen_messages or rs.gscreen == feed_view.screen_transparency)
            rs.gsocket_hits.clearRetainingCapacity();
        // pix exists exactly when a window backend has a live engine; the
        // composer and profile screens stay on the cell path this cut
        // (their pixel port is the recorded next slice).
        // On the THREAD screen the socket-of-the-screen is the REPLY socket
        // (drawn inline after the root + author self-thread). Elsewhere (home
        // header, loadout page) it's the FEED socket. Accent stays feed-derived
        // — reply seating never retints (owner rule).
        // The socket-of-the-screen: REPLY socket on a thread, the ZONE socket on a
        // zone page, the FEED socket on Home. Each is a switcher over its own
        // surface's loadout (the three the Algorithms page edits).
        const on_thread_screen = rs.gscreen == feed_view.screen_thread;
        const on_zone_screen = rs.gscreen == feed_view.screen_zones;
        const cur_socket_tray: lens_socket.TrayView = if (on_thread_screen)
            .{ .cards = rs.reply_cards, .text = rs.reply_blob, .seated = rs.reply_seated }
        else if (on_zone_screen)
            .{ .cards = rs.zone_cards, .text = rs.zone_blob, .seated = rs.zone_seated }
        else
            home_tray;
        // Functional Toy Box / Appearance toggles — each reads its runtime bit
        // (the generalized Julia pattern) and gates its behaviour below.
        const julia_on = toggleOn(rs.toggle_bits, settings_view.act_julia);
        const ripples_on = toggleOn(rs.toggle_bits, settings_view.act_ripples);
        const field_on = toggleOn(rs.toggle_bits, settings_view.act_field);
        const crt_on = toggleOn(rs.toggle_bits, settings_view.act_crt);
        const frametiming_on = toggleOn(rs.toggle_bits, settings_view.act_frametiming);
        const depth_on = toggleOn(rs.toggle_bits, settings_view.act_depth);
        const tectonic_on = toggleOn(rs.toggle_bits, settings_view.act_tectonic);
        const gravity_on = toggleOn(rs.toggle_bits, settings_view.act_gravity);
        const pet_on = toggleOn(rs.toggle_bits, settings_view.act_pet);
        const zerog_on = toggleOn(rs.toggle_bits, settings_view.act_zero_g);
        const liquid_on = toggleOn(rs.toggle_bits, settings_view.act_liquid);
        const xp_on = toggleOn(rs.toggle_bits, settings_view.act_xp);
        const light_on = toggleOn(rs.toggle_bits, settings_view.act_light);
        // Toy Box XP skin: the shell reads the wall clock ONCE per frame (B3) and
        // hands the local hour/minute to the pure renderer as plain bytes (B4).
        const xp_hm = clock_shell.localHourMinute();
        const settings_account: feed_view.SettingsAccount = .{
            .handle = std.fmt.bufPrint(&rs.account_handle_buf, "@{s}", .{session.handle}) catch session.handle,
            .did = session.did,
            .pds = session.pds_url,
            .pet_name = rs.pet_name_buf[0..rs.pet_name_len],
            .pet_name_focus = rs.pet_name_focus,
        };
        // Choice selections → the effects (each frame, declarative like the toggles).
        const settings_choices_packed = packChoices(&rs.choice_sel);
        const accent_override: ?u32 = accentChoiceColor(choiceSel(&rs.choice_sel, settings_view.act_accent));
        const field_gain: f32 = fieldGainFor(choiceSel(&rs.choice_sel, settings_view.act_field_intensity));
        switch (backend) { // heart cursor follows the Julia toggle
            .window => |w| window_shell.setJulia(w, julia_on),
            else => {},
        }
        var cur_socket_ui = if (on_thread_screen) rs.reply_ui else if (on_zone_screen) rs.zone_ui else rs.gsocket_ui;
        cur_socket_ui.julia = julia_on;
        const cur_socket_hits = if (on_thread_screen) &rs.reply_hits else if (on_zone_screen) &rs.zone_hits else &rs.gsocket_hits;
        // The Create "preparing" beat: a brief loading pause after the last question,
        // so it reads that the answers calibrated the numbers, then reveal the recap.
        // The living field repaints every frame, so a frame counter advances it.
        const create_prepare_len: u32 = 66; // ~1.1s at 60fps
        if (rs.gscreen == feed_view.screen_loadout and rs.gloadout_tab == 2 and rs.gcreate_step == .preparing) {
            rs.gcreate_prepare_frames += 1;
            if (rs.gcreate_prepare_frames >= create_prepare_len) rs.gcreate_step = .recap;
        }
        const create_prepare_t: f32 = @min(@as(f32, @floatFromInt(rs.gcreate_prepare_frames)) / @as(f32, @floatFromInt(create_prepare_len)), 1.0);
        // The bench: the user's library algorithms as socket cards, built into the
        // frame arena (auto-freed). Only on the Loadout tab; empty otherwise.
        var bench_tray: lens_socket.TrayView = .{ .cards = &.{}, .text = "", .seated = 0 };
        if (rs.gscreen == feed_view.screen_loadout and rs.gloadout_tab == 0) {
            if (lens_catalog.benchCards(arena, arena, &rs.algo_lib)) |res| {
                bench_tray = .{ .cards = res[0], .text = res[1], .seated = 0 };
            } else |_| {}
        }
        var pix: ?Grid = if (rs.engine) |*e| .{ .engine = e, .field = &rs.gfield, .particles = &rs.gparticles, .active = &rs.gactive, .draw = &rs.gdraw, .hr = &rs.ghr, .hearts = &rs.ghearts, .view = &rs.gview, .spawn_buf = &rs.gspawn, .last_nanos = &rs.glast_nanos, .zoom = &rs.gzoom, .scroll = &rs.gscroll_px, .content_h = &rs.gcontent_h, .regions = &rs.gregions, .screen = &rs.gscreen, .gpu = if (rs.gpu_state) |*gs| gs else null, .pending_new = feed_core.pendingCount(store), .hover_x = rs.ghover_x, .hover_y = rs.ghover_y, .socket_tray = cur_socket_tray, .socket_ui = cur_socket_ui, .socket_hits = cur_socket_hits, .accent = if (julia_on) lens_socket.julia_pink else (accent_override orelse lens_socket.seatedAccent(home_tray)), .reply_tray = .{ .cards = rs.reply_cards, .text = rs.reply_blob, .seated = rs.reply_seated }, .reply_ui = rs.reply_ui, .reply_hits = &rs.reply_hits, .zone_tray = .{ .cards = rs.zone_cards, .text = rs.zone_blob, .seated = rs.zone_seated }, .zone_ui = rs.zone_ui, .zone_hits = &rs.zone_hits, .loadout_tab = rs.gloadout_tab, .market = .{ .cards = if (rs.gscreen == feed_view.screen_loadout and rs.gloadout_tab == 1) rs.market_cards.items else &.{}, .q = rs.gmarket_q_buf[0..rs.gmarket_q_len], .q_focus = rs.gmarket_q_focus, .loading = rs.market_loading, .filter = rs.gmarket_filter, .hover_x = rs.ghover_x, .hover_y = rs.ghover_y }, .bench_pick = benchPickViewOf(rs), .bench_drag = benchDragViewOf(rs), .cart_detail = if (detailCardOf(rs)) |dt| dt.card else null, .back_hint = clock_shell.monotonicNanos() < rs.back_hint_until, .cart_detail_blob = if (detailCardOf(rs)) |dt| dt.blob else "", .detail_hits = &rs.detail_hits, .published = publishedRowsOf(arena, rs), .docs_kind = rs.gdocs_kind, .detail = detailViewOf(rs), .create = .{ .step = rs.gcreate_step, .answers = rs.gcreate_answers, .config = rs.gcreate_config, .name = rs.gcreate_name_buf[0..rs.gcreate_name_len], .color = rs.gcreate_color, .naming = rs.gcreate_step == .name, .prepare_t = create_prepare_t }, .dev = devViewOf(rs), .bench = bench_tray, .inspect_bytes = rs.inspect_bytes orelse "", .inspect_src = rs.inspect_src orelse "", .inspect_name = rs.inspect_name, .inspect_ref = rs.inspect_ref, .inspect_source = rs.gtransp_source, .inspect_loading = rs.inspect_loading, .loadout_geoms = &rs.page_geoms, .loadout_lib_y = &rs.page_lib_y, .zone_title = if (on_zone_screen) rs.zone_tag else "", .zones = .{ .cards = if (rs.gscreen == feed_view.screen_zones_browse) rs.zone_catalog.items else &.{}, .tab = rs.gzones_tab, .query = rs.gzones_q_buf[0..rs.gzones_q_len], .q_focus = rs.gzones_q_focus, .caret_on = composeBlinkOn(rs.caret_anchor_ns), .hover_x = rs.ghover_x, .hover_y = rs.ghover_y, .now = now, .tab_t = rs.gzones_tab_t, .enter_t = rs.gzones_enter_t, .people = rs.zone_people, .pinned = if (on_zone_screen) pin_store.has(&rs.zone_pins, rs.zone_tag) else false, .last_at = rs.zone_last_at }, .settings_section = rs.gsettings_section, .settings_toggles = rs.toggle_bits, .settings_account = settings_account, .settings_choices = settings_choices_packed, .settings_picking = rs.gsettings_picking, .chat_store = if (dev_chat) &rs.gchat_store else null, .chat_sel = rs.gchat_sel, .chat_delivery = chatDeliveryOf(rs), .chat_identity_elsewhere = rs.gchat_identity_elsewhere, .chat_link = chatLinkOf(rs), .chat_devices = chatDevicesOf(rs, arena), .enroll = enroll_run.snapshot(&rs.genroll_state, composeBlinkOn(rs.caret_anchor_ns)), .enroll_hits = &rs.genroll_hits, .boot_on = bootIntroOn(rs), .boot_t = bootIntroT(rs), .kbd_visible = softKeyboardWanted(rs), .kbd_shift = rs.kbd_shift, .kbd_page = rs.kbd_page, .kbd_caps = rs.kbd_caps, .kbd_flash_key = rs.kbd_flash_key, .kbd_flash_a = kbdFlashAlpha(rs), .kbd_popup = .{ .opts = rs.kbd_popup_opts[0..rs.kbd_popup_n], .anchor_x = rs.kbd_popup_ax, .anchor_y = rs.kbd_popup_ay, .anchor_w = rs.kbd_popup_aw, .sel = rs.kbd_popup_sel }, .kbd_emoji_open = rs.kbd_emoji_open, .kbd_emoji_scroll = @intFromFloat(rs.kbd_emoji_scroll), .kbd_picker_mode = rs.kbd_picker_mode, .kbd_nav_t = rs.kbd_nav_t, .kbd_nav_scroll = @intFromFloat(rs.kbd_nav_scroll), .chat_q = rs.gchat_q_buf[0..rs.gchat_q_len], .chat_q_focus = rs.gchat_q_focus, .chat_q_caret = composeBlinkOn(rs.caret_anchor_ns), .chat_draft = rs.gchat_draft_buf[0..rs.gchat_draft_len], .chat_edit = .{ .caret = @min(rs.gchat_caret, rs.gchat_draft_len), .sel_a = @min(rs.gchat_sel_a, rs.gchat_draft_len), .sel_b = @min(rs.gchat_sel_b, rs.gchat_draft_len), .bar = rs.gchat_edit_bar }, .chat_input_focus = rs.gchat_input_focus, .chat_composing = rs.gchat_composing, .chat_compose = rs.gchat_peer_buf[0..rs.gchat_peer_len], .chat_compose_status = rs.gchat_compose_status, .chat_typing = rs.gscreen == feed_view.screen_messages and now < rs.gchat_typing_deadline and rs.gchat_sel != null and std.mem.eql(u8, chat_core.conversationDid(&rs.gchat_store, rs.gchat_sel.?), rs.gchat_typing_peer_buf[0..rs.gchat_typing_peer_len]), .chat_key_ns = rs.gchat_key_ns, .chat_pay = .{ .open = rs.gpay_open, .rail = rs.gpay_rail, .amount = rs.gpay_amount_buf[0..rs.gpay_amount_len], .note = rs.gpay_note_buf[0..rs.gpay_note_len], .focus = rs.gpay_focus, .status = rs.gpay_status, .step = rs.gpay_step, .first_send = rs.gpay_first_send, .unit = rs.gpay_unit, .usd_cents_per_btc = rs.gprice_cents, .busy = rs.gpay_busy }, .chat_recv = .{ .open = rs.grecv_open, .mode = rs.grecv_mode, .lightning = rs.grecv_ln_buf[0..rs.grecv_ln_len], .bitcoin = rs.grecv_btc_buf[0..rs.grecv_btc_len], .focus = rs.grecv_focus, .status = rs.grecv_status, .saved = rs.grecv_saved, .rooted = rs.grecv_set, .set = rs.grecv_set, .known = rs.grecv_known, .probing = rs.grecv_probing, .caps = rs.gcaps, .saving = rs.gpublish_busy }, .wallet_remove_armed = rs.gwallet_remove_armed, .verify_ids = verifyIdsOf(arena, rs), .expanded = rs.gexpanded.items, .repost_menu = if (rs.grepost_menu) |m| @as(usize, m) else null, .field_gain = field_gain, .julia = julia_on, .you_handle = session.handle, .ripples_on = ripples_on, .field_on = field_on, .crt_on = crt_on, .frametiming_on = frametiming_on, .pet = pet_on, .xp = xp_on, .light = light_on, .xp_hour = xp_hm.hour, .xp_min = xp_hm.minute, .toys = .{ .feed_toy = if (gravity_on) feed_view.ToyKind.gravity else if (tectonic_on) feed_view.ToyKind.tectonic else if (depth_on) feed_view.ToyKind.depth else if (zerog_on) feed_view.ToyKind.zero_g else if (liquid_on) feed_view.ToyKind.liquid else .none, .t = if (rs.gpu_state) |*gs| gs.t else 0, .flow = if (rs.gpu_state) |*gs| gs.flow else 0 } } else null;
        switch (rs.mode) {
            .timeline => try paintFrame(gpa, rs.out, arena, &rs.prev, &rs.next, backend, pix, view_items, profile_header, &rs.state, rs.revealed.items, now, session.handle, rs.status),
            .compose => {
                if (pix) |g| switch (backend) {
                    .window => |win| {
                        if (g.gpu) |gs| {
                            // Premium composer on the GPU (the living field behind
                            // the card). Reply is distinguished by a non-empty
                            // target handle; the profile editor reuses the same
                            // surface with its own context line + "Save" label.
                            const ctx: feed_view.ComposeContext = if (rs.compose_kind == .profile)
                                .profile
                            else if (rs.reply_handle.len > 0) .reply else .post;
                            var tb_chips: [max_manual_tags][]const u8 = undefined;
                            const tb_view = tagBarViewOf(arena, rs, &tb_chips);
                            paintComposeGpu(gpa, win.fb.width, win.fb.height, g, gs, ctx, rs.reply_handle, rs.quoting_handle, textedit.view(&rs.compose), rs.compose.caret, textedit.selStart(&rs.compose), textedit.selEnd(&rs.compose), composeBlinkOn(rs.caret_anchor_ns), rs.status, rs.chain_segments.items, tb_view) catch {};
                        } else {
                            // Software fallback: the glyph-field cell composer.
                            const cell = cellSize(win.fb.width, rs.gzoom);
                            const fgrid = softFieldGrid(win.fb.width, win.fb.height, cell.w, cell.h);
                            const cols = fgrid.cols;
                            const rows = fgrid.rows;
                            if (rs.gfield.cols != cols or rs.gfield.rows != rows) {
                                field_core.deinit(gpa, &rs.gfield);
                                try field_core.init(gpa, &rs.gfield, cols, rows);
                            }
                            const cc = timeline_ui.countCodepoints(textedit.view(&rs.compose));
                            // Software fallback keeps an end-of-text cursor (the
                            // GPU path owns the caret-aware bar); the model still
                            // edits at the caret either way.
                            const cursor = field_ui.buildCompose(&rs.gfield, textedit.view(&rs.compose), rs.reply_handle, cc, rs.status);
                            try field_core.compose(gpa, &rs.gfield, rs.gparticles.slice(), .{ .x = @floatFromInt(cols / 2), .y = @floatFromInt(rows / 3), .radius = @floatFromInt(cols), .ambient = 0.7 }, cell.w, cell.h, &rs.gdraw);
                            // The cursor: a filled block at the insertion cell,
                            // tinted with the app accent (alpha-blended).
                            try rs.gdraw.append(gpa, .{ .rect = .{ .x = @intCast(@min(cursor.x * cell.w, 32767)), .y = @intCast(@min(cursor.y * cell.h, 32767)), .w = cell.w, .h = cell.h, .color = 0x88000000 | (field_core.palette[field_ui.col_accent] & 0x00FFFFFF), .radius = 0 } });
                            window_shell.presentDrawList(win, gpa, g.engine, rs.gdraw.slice(), field_core.background) catch {};
                        }
                    },
                    // The phone composer: the SAME premium GPU surface as the
                    // desktop (the tab bar's ＋ and every reply button open
                    // it — the old "unreachable v1" no-op FROZE the app the
                    // moment they did, caught live on the Pixel 2026-07-05).
                    // Typing awaits the IME leg (M-And.5 follow-up); until
                    // then the card renders, Cancel works, nothing freezes.
                    .mobile => |m| if (g.gpu) |gs| {
                        const ctx: feed_view.ComposeContext = if (rs.compose_kind == .profile)
                            .profile
                        else if (rs.reply_handle.len > 0) .reply else .post;
                        var tb_chips: [max_manual_tags][]const u8 = undefined;
                        const tb_view = tagBarViewOf(arena, rs, &tb_chips);
                        paintComposeGpu(gpa, m.width_px, m.height_px, g, gs, ctx, rs.reply_handle, rs.quoting_handle, textedit.view(&rs.compose), rs.compose.caret, textedit.selStart(&rs.compose), textedit.selEnd(&rs.compose), composeBlinkOn(rs.caret_anchor_ns), rs.status, rs.chain_segments.items, tb_view) catch {};
                    },
                    .terminal => {
                        timeline_ui.buildComposeFrame(&rs.next, textedit.view(&rs.compose), rs.reply_handle, rs.status);
                        try present(gpa, rs.out, arena, &rs.prev, &rs.next, backend);
                    },
                } else {
                    timeline_ui.buildComposeFrame(&rs.next, textedit.view(&rs.compose), rs.reply_handle, rs.status);
                    try present(gpa, rs.out, arena, &rs.prev, &rs.next, backend);
                }
            },
            .profile => {
                if (pix) |g| switch (backend) {
                    .window => |win| {
                        const cell = cellSize(win.fb.width, rs.gzoom);
                        const fgrid = softFieldGrid(win.fb.width, win.fb.height, cell.w, cell.h);
                        const cols = fgrid.cols;
                        const rows = fgrid.rows;
                        if (rs.gfield.cols != cols or rs.gfield.rows != rows) {
                            field_core.deinit(gpa, &rs.gfield);
                            try field_core.init(gpa, &rs.gfield, cols, rows);
                        }
                        field_ui.buildProfile(&rs.gfield, rs.profile_info orelse .{}, rs.status);
                        try field_core.compose(gpa, &rs.gfield, rs.gparticles.slice(), .{ .x = @floatFromInt(cols / 2), .y = @floatFromInt(rows / 3), .radius = @floatFromInt(cols), .ambient = 0.7 }, cell.w, cell.h, &rs.gdraw);
                        window_shell.presentDrawList(win, gpa, g.engine, rs.gdraw.slice(), field_core.background) catch {};
                    },
                    // The legacy cell-profile mode is desktop-only; mobile's
                    // profile is the premium screen inside .timeline mode.
                    .mobile => {},
                    .terminal => {
                        timeline_ui.buildProfileFrame(&rs.next, rs.profile_info orelse .{}, rs.status);
                        try present(gpa, rs.out, arena, &rs.prev, &rs.next, backend);
                    },
                } else {
                    timeline_ui.buildProfileFrame(&rs.next, rs.profile_info orelse .{}, rs.status);
                    try present(gpa, rs.out, arena, &rs.prev, &rs.next, backend);
                }
            },
        }

        // 0ms posting: a queued send was shown optimistically and PAINTED above
        // this frame; hand the actual create writes to the WRITE WORKER. Each
        // segment pays the volume tax and blocks on its createRecord — done
        // inline this froze the render thread for seconds on a several-segment
        // chain (the owner's live finding), so the whole walk runs off-thread
        // and its per-segment results reconcile in the write drain above
        // (temp cid → the server's real ref, or drop on failure). Ownership
        // MOVES into the request on a successful submit; a refused push (no
        // worker / mailbox OOM) drops the optimistic posts and frees here (E2).
        if (rs.pending_send) |chain| {
            rs.pending_send = null;
            var submitted = false;
            if (rs.writer) |w| {
                submitted = write_worker.submitChain(
                    w,
                    chain.segments,
                    chain.tags,
                    if (chain.base_target) |t| t.root_uri else "",
                    if (chain.base_target) |t| t.root_cid else "",
                    if (chain.base_target) |t| t.parent_uri else "",
                    if (chain.base_target) |t| t.parent_cid else "",
                    if (chain.base_quote) |q| q.uri else "",
                    if (chain.base_quote) |q| q.cid else "",
                    now,
                );
            }
            if (!submitted) {
                for (chain.segments) |seg| feed_core.dropOptimisticPost(store, seg.temp_cid);
                rs.status = "send failed — no write worker";
                freeChain(gpa, chain);
            }
        }

        // 0ms profile-name save: the name is already shown optimistically (and
        // guarded); run the putProfile write now, reverting the guard on failure
        // so the next refresh restores the server name. On success the guard
        // releases when the AppView re-polls + serves the new name.
        if (rs.pending_profile_save) |name| {
            rs.pending_profile_save = null;
            defer gpa.free(name);
            const saved = write.putProfile(gpa, arena, io, environ, session, name, now) catch |err| switch (err) {
                error.OutOfMemory => return err,
                else => blk: {
                    feed_core.clearPendingDisplay(store);
                    rs.status = "name save failed";
                    break :blk null;
                },
            };
            if (saved) |s| switch (s) {
                .ok => {},
                .failed => |f| {
                    feed_core.clearPendingDisplay(store);
                    rs.status = std.fmt.bufPrint(&rs.status_buf, "name refused: {d} {s}", .{ f.status, f.code }) catch "refused";
                },
            };
        }

        // Wait for input up to the driver's budget; the timeout re-renders
        // so relative ages stay honest on an idle screen (the WHY of the
        // budget's size lives with the driver that chose it).
        var in_buf: [256]u8 = undefined;
        var n: usize = 0;
        // The pointer channel + synthesized key bytes, filled per backend
        // (the X11 pump; the mobile host's seam queue) and consumed by the
        // SHARED dispatch below the switch — one input path for every
        // surface (MC.4d: taps on a phone are the same release-activation
        // clicks as the desktop mouse). Drained per lap so a motion flood
        // never accumulates.
        var pointer_events: std.ArrayList(layout_core.InputEvent) = .empty;
        defer pointer_events.deinit(gpa);
        var pumped_bytes: std.ArrayList(u8) = .empty;
        defer pumped_bytes.deinit(gpa);
        // The surface's pixel dims, for the dispatch's cell/scale mapping.
        var fb_w: u32 = 0;
        var fb_h: u32 = 0;
        switch (backend) {
            // On Windows the terminal backend returns NotATerminal at
            // startup (console raw mode is the recorded follow-up), so
            // this arm comptime-vanishes there — this std snapshot's
            // posix.pollfd does not even resolve on that target.
            .terminal => if (comptime builtin.os.tag == .windows) unreachable else {
                var fds = [_]posix.pollfd{.{ .fd = rs.stdin_fd, .events = posix.POLL.IN, .revents = 0 }};
                const ready = posix.poll(&fds, wait_budget_ms) catch 0;
                if (ready == 0) return .again; // poll timeout: frame over (was `continue`)
                n = posix.read(rs.stdin_fd, &in_buf) catch 0;
                if (n == 0) return .again; // nothing read: frame over (was `continue`)
                rs.last_input_nanos = clock_shell.monotonicNanos();
            },
            .mobile => |m| {
                // The OS delivered input through the seam between frames;
                // drain the queue so a motion flood never accumulates. The
                // wait budget is unused here by design: a choreographer-
                // driven host passes 0 and the step never blocks on an
                // OS-owned thread.
                if (m.closed) break :main_loop;
                fb_w = m.width_px;
                fb_h = m.height_px;
                var touch_events: std.ArrayList(layout_core.InputEvent) = .empty;
                defer touch_events.deinit(gpa);
                mobile_host.drain(m, gpa, &touch_events) catch {}; // OOM: dropped taps, contained (E2)
                // Soft-keyboard bytes ride the SAME stream the window pump
                // fills — decodeInput + the compose path work untouched.
                mobile_host.drainBytes(m, gpa, &pumped_bytes) catch {};
                if (touch_events.items.len > 0 or pumped_bytes.items.len > 0) rs.last_input_nanos = clock_shell.monotonicNanos();
                // TOUCH SLOP (MC.4d): a press that stays within ~a finger's
                // wobble and releases is a TAP — forwarded to the shared
                // dispatch below as the same button_down/button_up pair the
                // mouse sends (release-activation and hit-testing then work
                // untouched). A press that travels further is a SCROLL: the
                // feed follows the finger 1:1 with the desktop wheel's pixel
                // clamp, and nothing is forwarded (a scroll is not a click).
                // Momentum/fling is the M-UX pass. Bare moves never forward:
                // a finger casts no hover.
                const touch_slop: i32 = 28; // device px, ~a fingertip's wobble
                const scale: f32 = if (rs.gpu_state) |*gs| gs.scale else 1.0;
                const view_h: i32 = @intFromFloat(@as(f32, @floatFromInt(m.height_px)) / scale);
                const view_h_f: f32 = @floatFromInt(view_h);
                const min_scroll: i32 = @min(0, view_h - rs.gcontent_h - 24);
                const min_scroll_f: f32 = @floatFromInt(min_scroll);
                // The gesture core's sample clock: one shell stamp per drained
                // batch (B4 — the core only subtracts these). Same-frame
                // events share a stamp; the velocity window spans frames, so
                // the estimate's denominator is real time.
                const now_ms: u32 = @truncate(clock_shell.monotonicNanos() / 1_000_000);
                // This frame's finger travel (logical px) — the fling's
                // velocity sample. Zero on drag-free frames, which is what
                // decays the smoothed velocity toward rest during a
                // press-and-hold before release.
                var frame_dy: f32 = 0;
                for (touch_events.items) |tev| switch (tev.kind) {
                    .button_down => {
                        // AUX POINTER (a second thumb — the seam forwards
                        // ACTION_POINTER_DOWN as button 2): it exists only to
                        // TYPE. Press-commit its key and leave the whole
                        // single-pointer gesture machine to the primary
                        // finger — two-thumb typing stops dropping the
                        // second key (the recorded single-pointer limit).
                        if (tev.button == 2) {
                            m.kbd_multi = true; // renumbering ahead: slides stand down
                            if (if (pix) |gv| gv.kbd_visible else false) {
                                if (rs.gpu_state) |*gsd| {
                                    const ax: i32 = @intFromFloat(@as(f32, @floatFromInt(tev.x)) / gsd.scale);
                                    const ay: i32 = @intFromFloat(@as(f32, @floatFromInt(tev.y)) / gsd.scale);
                                    if (feed_view.kbdResolve(rs.gregions.items, ax, ay - kbd_touch_bias_y, kbdCtx(rs))) |kh| switch (kh.kind) {
                                        // A second-thumb space types plainly
                                        // (no caret slide from an aux finger).
                                        .kbd_key, .kbd_shift, .kbd_page, .kbd_backspace => {
                                            kbdAction(rs, gpa, kh.kind, kh.post);
                                            rs.kbd_flash_held = true; // this finger owns the pop until a lift
                                            if (toggleOn(rs.toggle_bits, settings_view.act_kbd_haptic)) m.haptic_pending = 1;
                                        },
                                        else => {},
                                    };
                                }
                            }
                            continue;
                        }
                        m.down_x = tev.x;
                        m.down_y = tev.y;
                        m.down_ms = now_ms; // the long-press clock starts
                        m.hold_fired = false;
                        m.scrolling = false;
                        m.hswipe = false;
                        m.drag_y = tev.y;
                        m.fling_v = 0; // a touch catches the gliding feed (interruptible)
                        m.scroll_carry = 0; // fresh gesture: no stale sub-pixel remainder
                        m.socket_swipe = false;
                        gesture.clear(&m.ring);
                        gesture.push(&m.ring, .{ .x = @as(f32, @floatFromInt(tev.x)) / scale, .y = @as(f32, @floatFromInt(tev.y)) / scale, .t_ms = now_ms });
                        // A touch catches a mid-flight edge bounce too, and
                        // hands the displayed give back to the finger as raw
                        // travel (roadmap §2.4): the drag resumes the same
                        // stretch, no snap. Catching a bounce COMMITS the
                        // press as a scroll (no slop, no tap on release) —
                        // the finger owns moving content the instant it
                        // lands, exactly like catching a glide.
                        // A press that lands ON the Zat4 keyboard types; it must
                        // never commit to a scroll or drawer swipe underneath.
                        // A PRESS RIPPLES THE FIELD: the tactile answer to a tap,
                        // the same one the desktop's press gives.
                        if (rs.gpu_state) |*gsf| {
                            if (gsf.cols > 0 and gsf.rows > 0) {
                                const fx: u32 = @min(@as(u32, @intFromFloat(@max(0.0, @as(f32, @floatFromInt(tev.x)) / @as(f32, @floatFromInt(field_cell_w))))), gsf.cols - 1);
                                const fy: u32 = @min(@as(u32, @intFromFloat(@max(0.0, @as(f32, @floatFromInt(tev.y)) / @as(f32, @floatFromInt(field_cell_h))))), gsf.rows - 1);
                                gsf.splashes.append(gpa, .{ .x = fx, .y = fy, .radius = 3, .amp = 0.9 }) catch {};
                            }
                        }
                        m.press_in_kbd = false;
                        m.kbd_bs_repeats = 0;
                        m.kbd_press_cp = 0;
                        m.kbd_multi = false;
                        m.input_press = false;
                        m.input_lp = false;
                        m.chat_hnd = 0;
                        m.kbd_emoji_cand = 0;
                        m.kbd_emoji_drag = false;
                        m.kbd_emoji_v = 0; // a touch catches a gliding picker
                        m.kbd_nav_cand = 0;
                        m.kbd_nav_drag = false;
                        m.kbd_nav_raw = 0;
                        rs.kbd_nav_scroll_v = 0; // a touch catches the banded column
                        if (if (pix) |gv| gv.kbd_visible else false) {
                            if (rs.gpu_state) |*gsd| {
                                const klx: i32 = @intFromFloat(@as(f32, @floatFromInt(tev.x)) / gsd.scale);
                                const kly: i32 = @intFromFloat(@as(f32, @floatFromInt(tev.y)) / gsd.scale);
                                const klh: i32 = @intFromFloat(@as(f32, @floatFromInt(m.height_px)) / gsd.scale);
                                if (kly >= klh - feed_view.keyboard_h - @as(i32, @intCast(gsd.inset_bottom_l))) {
                                    m.press_in_kbd = true;
                                    // PRESS-COMMIT: the key fires the instant
                                    // the finger lands (flash + bytes) — real
                                    // keyboard latency, not tap-on-release.
                                    // The release tap is suppressed below so
                                    // a key never fires twice.
                                    // Thumbs land LOW: resolve the key a few
                                    // logical px above the touch centroid.
                                    if (feed_view.kbdResolve(rs.gregions.items, klx, kly - kbd_touch_bias_y, kbdCtx(rs))) |kh| switch (kh.kind) {
                                        .kbd_key => if (kh.post == ' ') {
                                            // Space commits at DOWN like every
                                            // key — commit-on-release made it
                                            // land AFTER the next letter in
                                            // overlapped typing ("ab " for
                                            // "a b", the wrong-order report,
                                            // 2026-07-11). A caret slide that
                                            // engages UNDOES it (.move).
                                            kbdAction(rs, gpa, .kbd_key, ' ');
                                            if (toggleOn(rs.toggle_bits, settings_view.act_kbd_haptic)) m.haptic_pending = 1;
                                            m.kbd_space_down = true;
                                            m.kbd_nav = false;
                                            m.kbd_nav_x = @as(f32, @floatFromInt(tev.x)) / gsd.scale;
                                            m.kbd_nav_fx = m.kbd_nav_x;
                                            ktLogDown(m, kh, klx, kly);
                                        } else {
                                            kbdAction(rs, gpa, kh.kind, kh.post);
                                            // Arm slide-off cancel + the long-
                                            // press anchor: the popup rides
                                            // this key's region.
                                            m.kbd_press_cp = kh.post;
                                            m.kbd_press_x = kh.x;
                                            m.kbd_press_y = kh.y;
                                            m.kbd_press_w = kh.w;
                                            rs.kbd_flash_held = true;
                                            if (toggleOn(rs.toggle_bits, settings_view.act_kbd_haptic)) m.haptic_pending = 1;
                                            ktLogDown(m, kh, klx, kly);
                                        },
                                        .kbd_shift, .kbd_page, .kbd_backspace, .kbd_nav => {
                                            kbdAction(rs, gpa, kh.kind, kh.post);
                                            if (toggleOn(rs.toggle_bits, settings_view.act_kbd_haptic)) m.haptic_pending = 1;
                                            // TEMPORARY typo-gap keylog: backspaces
                                            // mark corrections for offline pairing.
                                            if (kh.kind == .kbd_backspace) std.debug.print("[kt] bs\n", .{});
                                        },
                                        // A NAV ROLLOUT entry arms a release-
                                        // commit like the emoji cells — the
                                        // column rubber-bands under a slide.
                                        .kbd_cat => {
                                            m.kbd_nav_cand = kh.post +% 1;
                                            m.kbd_nav_raw = 0;
                                        },
                                        // An emoji CELL is the one keyboard press
                                        // that is NOT press-commit: the grid
                                        // scrolls, so the press must stay
                                        // convertible into a drag — a clean
                                        // release commits it in the up arm.
                                        .kbd_emoji => {
                                            m.kbd_emoji_cand = kh.post + 1;
                                            m.kbd_emoji_scroll0 = rs.kbd_emoji_scroll;
                                        },
                                        else => {},
                                    };
                                }
                            }
                        }
                        if (!m.press_in_kbd) if (rs.gpu_state) |*gsi| {
                            const iix: i32 = @intFromFloat(@as(f32, @floatFromInt(tev.x)) / gsi.scale);
                            const iiy: i32 = @intFromFloat(@as(f32, @floatFromInt(tev.y)) / gsi.scale);
                            if (feed_view.hitTest(rs.gregions.items, iix, iiy)) |ih| {
                                if (ih.kind == .chat_input) m.input_press = true;
                                if (ih.kind == .chat_handle) {
                                    // The whole press belongs to the handle:
                                    // no long-press, no scroll, no tap.
                                    m.chat_hnd = @intCast(ih.post + 1);
                                    m.input_press = false;
                                }
                            }
                        };
                        if (m.bounce_px != 0) {
                            m.over_px = gesture.rubberBandInv(std.math.clamp(m.bounce_px, -(view_h_f - 1), view_h_f - 1), view_h_f);
                            m.bounce_px = 0;
                            m.bounce_v = 0;
                            m.scrolling = true;
                        }
                    },
                    .move => if (m.down_x >= 0) {
                        // THE FINGER LIGHTS THE FIELD. On the desktop the pointer
                        // does this on every mouse-move; a phone emits no move
                        // events into that path, so the field has never once felt a
                        // touch. It should — it is a MEDIUM, and on the front door
                        // (the one phone screen where the field is the whole
                        // backdrop) it is the difference between a picture and a
                        // place.
                        if (rs.gpu_state) |*gsf| {
                            gsf.mcx = @as(f32, @floatFromInt(tev.x)) / @as(f32, @floatFromInt(field_cell_w));
                            gsf.mcy = @as(f32, @floatFromInt(tev.y)) / @as(f32, @floatFromInt(field_cell_h));
                            if (gsf.cols > 0 and gsf.rows > 0) {
                                const fx: u32 = @min(@as(u32, @intFromFloat(@max(0.0, gsf.mcx))), gsf.cols - 1);
                                const fy: u32 = @min(@as(u32, @intFromFloat(@max(0.0, gsf.mcy))), gsf.rows - 1);
                                gsf.splashes.append(gpa, .{ .x = fx, .y = fy, .radius = 3, .amp = 0.5 }) catch {};
                            }
                        }
                        // A live press-and-hold drag owns the finger: the picked-up
                        // card's ghost tracks it (logical px), and nothing scrolls or
                        // swipes underneath (the edge auto-scroll below is the one
                        // exception). Release drops it — benchDrop / pageDragDrop.
                        if (m.hold_fired) {
                            const dlx2: i32 = @intFromFloat(@as(f32, @floatFromInt(tev.x)) / scale);
                            const dly2: i32 = @intFromFloat(@as(f32, @floatFromInt(tev.y)) / scale);
                            if (rs.page_drag_surface) |ps| {
                                const dui: *lens_socket.SocketUi = switch (ps) {
                                    1 => &rs.reply_ui,
                                    2 => &rs.zone_ui,
                                    else => &rs.gsocket_ui,
                                };
                                dui.drag_x = dlx2;
                                dui.drag_y = dly2;
                            } else {
                                rs.gbench_drag_x = dlx2;
                                rs.gbench_drag_y = dly2;
                            }
                            continue;
                        }
                        gesture.push(&m.ring, .{ .x = @as(f32, @floatFromInt(tev.x)) / scale, .y = @as(f32, @floatFromInt(tev.y)) / scale, .t_ms = now_ms });
                        // SELECTION HANDLE DRAG: the finger owns its end of
                        // the selection — the point maps through the same
                        // wrap walk the long-press select uses, and the ends
                        // SWAP when dragged across each other (the messenger
                        // grammar). Renders via chat_sig (no kbd_dirty —
                        // continuous motion, the razor law).
                        if (m.chat_hnd != 0) if (rs.engine) |*heng| {
                            for (rs.gregions.items) |r2| {
                                if (r2.kind != .chat_input) continue;
                                const hlx: i32 = @intFromFloat(@as(f32, @floatFromInt(tev.x)) / scale);
                                const hly: i32 = @intFromFloat(@as(f32, @floatFromInt(tev.y)) / scale);
                                const off = feed_view.chatDraftOffsetAt(heng, rs.gchat_draft_buf[0..rs.gchat_draft_len], r2.w, hlx - r2.x, hly - r2.y);
                                if (m.chat_hnd == 1) rs.gchat_sel_a = off else rs.gchat_sel_b = off;
                                if (rs.gchat_sel_a > rs.gchat_sel_b) {
                                    const t2 = rs.gchat_sel_a;
                                    rs.gchat_sel_a = rs.gchat_sel_b;
                                    rs.gchat_sel_b = t2;
                                    m.chat_hnd = if (m.chat_hnd == 1) 2 else 1;
                                }
                                rs.gchat_caret = if (m.chat_hnd == 1) rs.gchat_sel_a else rs.gchat_sel_b;
                                break;
                            }
                        };
                        // NAV COLUMN DRAG: a press armed on a rollout entry
                        // follows the finger as pure rubber-band give — the
                        // column fits, so the band IS the scroll feel; the
                        // release spring brings it home.
                        if (m.press_in_kbd and rs.kbd_emoji_open and (m.kbd_nav_cand != 0 or m.kbd_nav_drag)) {
                            const ndy = @as(f32, @floatFromInt(@as(i32, tev.y) - m.down_y)) / scale;
                            if (!m.kbd_nav_drag and @abs(ndy) > 8) {
                                m.kbd_nav_drag = true;
                                m.kbd_nav_cand = 0; // a slide never picks
                            }
                            if (m.kbd_nav_drag) {
                                m.kbd_nav_raw = ndy;
                                rs.kbd_nav_scroll = gesture.rubberBand(ndy, @floatFromInt(feed_view.emoji_view_h));
                            }
                        }
                        // EMOJI PICKER DRAG: a press armed on a cell (or one
                        // already dragging) follows the finger vertically —
                        // past the slop the press stops being a tap and the
                        // grid scrolls 1:1 under it, clamped to the content.
                        if (m.press_in_kbd and rs.kbd_emoji_open and (m.kbd_emoji_cand != 0 or m.kbd_emoji_drag)) {
                            const edy = @as(f32, @floatFromInt(@as(i32, tev.y) - m.down_y)) / scale;
                            if (!m.kbd_emoji_drag and @abs(edy) > 8) {
                                m.kbd_emoji_drag = true;
                                m.kbd_emoji_cand = 0; // a scroll never types
                                rs.kbd_emoji_jump = -1; // the finger owns the grid
                            }
                            if (m.kbd_emoji_drag) {
                                const max_sc: f32 = @floatFromInt(feed_view.emojiScrollMax());
                                // NO kbd_dirty here: continuous motion rides the
                                // normal top-of-loop paint (the scroll folds into
                                // feed_sig; the composer rebuilds every lap).
                                // Marking dirty per move added a SECOND full
                                // paint+swap every lap of the drag — a sustained
                                // half frame rate (the scroll lag, 2026-07-12).
                                // kbd_dirty is for discrete keystroke feedback.
                                rs.kbd_emoji_scroll = std.math.clamp(m.kbd_emoji_scroll0 - edy, 0, max_sc);
                            }
                        }
                        // SLIDE-OFF CANCEL: the finger leaves the key it
                        // committed before lifting — undo the char (one
                        // backspace), kill its flash. The standard escape
                        // hatch press-commit otherwise loses.
                        if (m.press_in_kbd and m.kbd_press_cp != 0 and rs.kbd_popup_kind == 0 and
                            !m.kbd_multi and (now_ms -% m.down_ms) > 120)
                        {
                            const cdx = @abs(@as(f32, @floatFromInt(@as(i32, tev.x) - m.down_x))) / scale;
                            const cdy = @abs(@as(f32, @floatFromInt(@as(i32, tev.y) - m.down_y))) / scale;
                            if (cdx > 30 or cdy > 34) {
                                rs.kbd_bytes.append(gpa, 8) catch {};
                                rs.kbd_flash_key = 0;
                                rs.kbd_flash_held = false;
                                rs.kbd_dirty = true;
                                m.kbd_press_cp = 0;
                                if (m.kt_cp != 0) std.debug.print("[kt] x cp={d}\n", .{m.kt_cp});
                                m.kt_cp = 0;
                            }
                        }
                        // The open popup tracks the finger: the cell under it
                        // highlights (same math the draw uses — no drift).
                        if (rs.kbd_popup_kind != 0) if (rs.engine) |*peng| {
                            const pfx: i32 = @intFromFloat(@as(f32, @floatFromInt(tev.x)) / scale);
                            const psel = feed_view.kbdPopupCellAt(peng, if (rs.gpu_state) |*pgs| @intCast(pgs.design_w) else design_w, .{ .opts = rs.kbd_popup_opts[0..rs.kbd_popup_n], .anchor_x = rs.kbd_popup_ax, .anchor_y = rs.kbd_popup_ay, .anchor_w = rs.kbd_popup_aw }, pfx);
                            if (psel != rs.kbd_popup_sel) {
                                rs.kbd_popup_sel = psel;
                                rs.kbd_dirty = true;
                            }
                        };
                        // SPACE-HOLD CARET SLIDE (Zat4 keyboard): with the
                        // press parked on the space bar, horizontal travel
                        // walks the caret — arrow escapes ride the same byte
                        // stream typed keys do (~14 logical px per step).
                        // Engaging eats the pending space.
                        if (m.kbd_space_down and !m.kbd_multi) {
                            const fx = @as(f32, @floatFromInt(tev.x)) / scale;
                            if (!m.kbd_nav and @abs(fx - m.kbd_nav_x) > 10) {
                                m.kbd_nav = true;
                                m.kbd_nav_x = fx;
                                // The slide eats the space it pre-committed.
                                rs.kbd_bytes.append(gpa, 8) catch {};
                            }
                            if (m.kbd_nav) {
                                // Velocity-tuned: a slow slide steps every
                                // ~15 px (precision); a fast one every ~6
                                // (reach) — the Gboard glide's feel.
                                const spd = @abs(fx - m.kbd_nav_fx);
                                const nav_step: f32 = std.math.clamp(15.0 - spd * 0.45, 6.0, 15.0);
                                const nav_x0 = m.kbd_nav_x;
                                while (fx - m.kbd_nav_x >= nav_step) : (m.kbd_nav_x += nav_step)
                                    rs.kbd_bytes.appendSlice(gpa, "\x1b[C") catch break;
                                while (m.kbd_nav_x - fx >= nav_step) : (m.kbd_nav_x -= nav_step)
                                    rs.kbd_bytes.appendSlice(gpa, "\x1b[D") catch break;
                                // The caret RATCHETS under the finger: one
                                // soft tick per step (the drag-threshold
                                // haptic channel; lands mid-gesture, §3).
                                if (m.kbd_nav_x != nav_x0) m.haptic_pending = 1;
                            }
                            m.kbd_nav_fx = fx;
                        }
                        // The dominant axis at the slop threshold commits the
                        // gesture: vertical -> scroll (as ever), horizontal ->
                        // the nav-drawer swipe (resolved on release). One
                        // commitment per press; a committed swipe never
                        // scrolls the feed under the moving finger.
                        if (!m.scrolling and !m.hswipe and !m.socket_swipe and !m.press_in_kbd and m.chat_hnd == 0) {
                            const adx = @abs(@as(i32, tev.x) - m.down_x);
                            const ady = @abs(@as(i32, tev.y) - m.down_y);
                            if (ady > touch_slop and ady >= adx) {
                                m.scrolling = true;
                            } else if (adx > touch_slop and adx > ady) blk: {
                                // A horizontal swipe that STARTED on the active
                                // surface's CLOSED socket swaps the seated cartridge
                                // and takes PRECEDENCE over the nav-drawer swipe — the
                                // drawer never comes out from a socket swipe. Works on
                                // ALL THREE sockets (home / reply / zone): the active
                                // socket's hit list carries its on-screen rects (in
                                // logical px, rebuilt each frame — the previous frame's
                                // are valid here), so hitBounds gives the bar box no
                                // matter where that socket sits (fixed / inline / masthead).
                                {
                                    const dlx: i32 = @intFromFloat(@as(f32, @floatFromInt(m.down_x)) / scale);
                                    const dly: i32 = @intFromFloat(@as(f32, @floatFromInt(m.down_y)) / scale);
                                    const surf: u8 = if (rs.gscreen == feed_view.screen_thread)
                                        1
                                    else if (rs.gscreen == feed_view.screen_zones)
                                        2
                                    else if (rs.gscreen == feed_view.screen_home)
                                        0
                                    else
                                        255; // no socket surface on this screen
                                    if (surf != 255) {
                                        const sock_ui = switch (surf) {
                                            1 => rs.reply_ui,
                                            2 => rs.zone_ui,
                                            else => rs.gsocket_ui,
                                        };
                                        const sock_hits = switch (surf) {
                                            1 => rs.reply_hits,
                                            2 => rs.zone_hits,
                                            else => rs.gsocket_hits,
                                        };
                                        if (!sock_ui.open) {
                                            if (lens_socket.hitBounds(sock_hits.items)) |b| {
                                                if (dlx >= b.x0 and dlx <= b.x1 and dly >= b.y0 and dly <= b.y1) {
                                                    m.socket_swipe = true;
                                                    m.socket_swipe_surface = surf;
                                                    break :blk;
                                                }
                                            }
                                        }
                                    }
                                }
                                m.hswipe = true;
                                if (rs.gpu_state) |*gsd| {
                                    // Re-grab (§2.4): a settling drawer hands its
                                    // CURRENT position back to the finger — there
                                    // is no locked-while-animating state; the 1:1
                                    // tether below owns motion from here.
                                    m.hswipe_base = gsd.drawer_t;
                                    gsd.drawer_drag = true;
                                }
                            }
                        }
                        if (m.hswipe) {
                            // TETHERED: the drawer follows the finger 1:1
                            // (owner's spec — it comes out WITH the swipe),
                            // panel-widths of travel mapping to t. The
                            // spring stands down while the finger owns it.
                            if (rs.gpu_state) |*gsd| {
                                const dxl = @as(f32, @floatFromInt(@as(i32, tev.x) - m.down_x)) / scale;
                                const t_old = gsd.drawer_t;
                                gsd.drawer_t = std.math.clamp(m.hswipe_base + dxl / @as(f32, @floatFromInt(feed_view.drawer_w)), 0.0, 1.0);
                                gsd.drawer_v = 0;
                                // Haptic latch edge (§3): a tick the instant
                                // the tethered drawer crosses its commit
                                // point, either direction, mid-drag.
                                if ((t_old < 0.5) != (gsd.drawer_t < 0.5)) m.haptic_pending = 2;
                            }
                        }
                        if (m.scrolling) {
                            const dy_phys: i32 = @as(i32, tev.y) - m.drag_y;
                            m.drag_y = tev.y;
                            var dy: f32 = @as(f32, @floatFromInt(dy_phys)) / scale;
                            // The open chat thread is BOTTOM-anchored (its
                            // scroll measures up from the newest message), so
                            // the finger-to-content mapping FLIPS: dragging
                            // down walks back into history, like every
                            // messenger (on-device it read backwards,
                            // 2026-07-10). Flipped at the source so the
                            // carry, fling, and edge accounting follow.
                            if (rs.gscreen == feed_view.screen_messages and rs.gchat_sel != null) dy = -dy;
                            frame_dy += dy;
                            // Pull-to-refresh (the desktop overscroll gesture,
                            // by touch): dragging DOWN while already pinned at
                            // the top of Home builds overscroll; past the
                            // threshold it asks for a refresh. Any upward drag
                            // cancels the pull.
                            if (rs.gscreen == feed_view.screen_home and rs.gscroll_px >= 0 and dy > 0) {
                                rs.overscroll_accum += @intFromFloat(dy);
                                if (rs.overscroll_accum >= pull_refresh_threshold) {
                                    rs.pull_refresh_requested = true;
                                    rs.overscroll_accum = 0;
                                    m.haptic_pending = 1; // the arming ticks under the finger (§3)
                                } else {
                                    rs.status = "↓ keep pulling to refresh";
                                }
                            } else if (dy < 0) {
                                rs.overscroll_accum = 0;
                            }
                            // RUBBER-BAND (roadmap §3): travel past an edge
                            // accumulates RAW overscroll instead of dying in a
                            // clamp; the curve maps it to displayed give at
                            // the frame's end. While banded, the LOGICAL
                            // scroll is pinned exactly at the edge, so the
                            // accounting below never reads the banded value.
                            // Include any sub-pixel fraction carried from the
                            // previous event so slow drags track the finger 1:1
                            // (the integer gscroll_px would otherwise truncate it).
                            var d = dy + m.scroll_carry;
                            m.scroll_carry = 0;
                            if (m.over_px != 0) {
                                const was_top = m.over_px > 0;
                                m.over_px += d;
                                if (m.over_px == 0 or (m.over_px > 0) != was_top) {
                                    // The finger came back through the edge:
                                    // the remainder re-enters real scrolling.
                                    d = m.over_px;
                                    m.over_px = 0;
                                    rs.gscroll_px = if (was_top) 0 else min_scroll;
                                } else {
                                    d = 0;
                                }
                            }
                            if (d != 0) {
                                const tent = @as(f32, @floatFromInt(rs.gscroll_px)) + d;
                                if (tent > 0) {
                                    rs.gscroll_px = 0;
                                    m.over_px = tent;
                                } else if (tent < min_scroll_f) {
                                    rs.gscroll_px = min_scroll;
                                    m.over_px = tent - min_scroll_f;
                                } else {
                                    const npx: i32 = @intFromFloat(tent);
                                    m.scroll_carry = tent - @as(f32, @floatFromInt(npx)); // keep the lost fraction
                                    rs.gscroll_px = npx;
                                }
                            }
                        }
                    },
                    .button_up => {
                        // An aux finger lifting: its key committed at its
                        // down, but SOME finger left the glass — the pop
                        // fades NOW. Per-pointer previews need ids we don't
                        // track; any-lift-fades + any-press-rearms reads
                        // right (alternating-finger spam pinned the pop
                        // solid for a measured 7.2 s, 2026-07-12).
                        if (tev.button == 2) {
                            if (rs.kbd_flash_held) {
                                rs.kbd_flash_held = false;
                                rs.kbd_flash_ns = clock_shell.monotonicNanos() -| 25_000_000;
                                rs.kbd_dirty = true;
                            }
                            continue;
                        }
                        // The long-press popup commits on release: the cell
                        // under the finger types its remainder (the sigil is
                        // already in the draft); off every cell = cancel.
                        if (rs.kbd_popup_kind != 0) {
                            if (rs.kbd_popup_sel >= 0 and rs.kbd_popup_sel < rs.kbd_popup_n) {
                                rs.kbd_bytes.appendSlice(gpa, rs.kbd_popup_opts[@intCast(rs.kbd_popup_sel)]) catch {};
                                if (toggleOn(rs.toggle_bits, settings_view.act_kbd_haptic)) m.haptic_pending = 1;
                            }
                            rs.kbd_popup_kind = 0;
                            rs.kbd_popup_n = 0;
                            rs.kbd_popup_sel = -1;
                            rs.kbd_dirty = true;
                        }
                        // Release lets a HELD pop VANISH — backdated past the
                        // attack window so the fade starts falling now, and
                        // dirty so the off-edge paints THIS tick (it was one
                        // frame late; under spam the pop never visibly fell).
                        if (rs.kbd_flash_held) {
                            rs.kbd_flash_held = false;
                            rs.kbd_flash_ns = clock_shell.monotonicNanos() -| 25_000_000;
                            rs.kbd_dirty = true;
                        }
                        // EMOJI PICKER RELEASE: a clean press (no drag)
                        // commits its cell NOW — tap-on-release is correct
                        // here because a picker press may become a scroll;
                        // a drag hands its speed to the glide instead (the
                        // feed's momentum idiom).
                        if (m.kbd_emoji_drag) {
                            m.kbd_emoji_v = -gesture.velocity(&m.ring).y / 60.0; // logical px/s → scroll px/frame
                            m.kbd_emoji_drag = false;
                        } else if (m.kbd_emoji_cand != 0) {
                            kbdAction(rs, gpa, .kbd_emoji, m.kbd_emoji_cand - 1);
                            if (toggleOn(rs.toggle_bits, settings_view.act_kbd_haptic)) m.haptic_pending = 1;
                        }
                        m.kbd_emoji_cand = 0;
                        // NAV COLUMN RELEASE: a clean press picks its entry;
                        // a banded slide hands the give to the return spring
                        // at the finger's displayed speed (§2.3 handoff).
                        if (m.kbd_nav_drag) {
                            rs.kbd_nav_scroll_v = gesture.velocity(&m.ring).y * gesture.rubberBandSlope(m.kbd_nav_raw, @floatFromInt(feed_view.emoji_view_h));
                            m.kbd_nav_drag = false;
                        } else if (m.kbd_nav_cand != 0) {
                            kbdAction(rs, gpa, .kbd_cat, m.kbd_nav_cand -% 1);
                            if (toggleOn(rs.toggle_bits, settings_view.act_kbd_haptic)) m.haptic_pending = 1;
                        }
                        m.kbd_nav_cand = 0;
                        // TEMPORARY typo-gap keylog: the release closes the
                        // press's roll vector (same raw space as its `d`).
                        if (m.kt_cp != 0) {
                            if (rs.gpu_state) |*gsu| {
                                const uxl: i32 = @intFromFloat(@as(f32, @floatFromInt(tev.x)) / gsu.scale);
                                const uyl: i32 = @intFromFloat(@as(f32, @floatFromInt(tev.y)) / gsu.scale);
                                std.debug.print("[kt] u cp={d} rx={d} ry={d} dt={d}\n", .{ m.kt_cp, uxl - (m.kt_kx + @divTrunc(m.kt_kw, 2)), uyl - (m.kt_ky + @divTrunc(m.kt_kh, 2)), now_ms -% m.down_ms });
                            }
                            m.kt_cp = 0;
                        }
                        m.kbd_press_cp = 0;
                        // Space already committed at down; release just ends
                        // the slide state.
                        m.kbd_space_down = false;
                        m.kbd_nav = false;
                        m.kbd_multi = false; // the gesture fully ended
                        if (m.hold_fired) {
                            // A press-and-hold drag ends. A LIBRARY card drops onto the
                            // socket under the finger (benchDrop hit-tests all three;
                            // off any of them it fizzles). A SOCKETED card released over
                            // the library band UNEQUIPS (back to the library); anywhere
                            // else it reorders in place — the desktop drop semantics,
                            // by touch. A drag never fires a tap.
                            const dpx: i32 = @intFromFloat(@as(f32, @floatFromInt(tev.x)) / scale);
                            const dpy: i32 = @intFromFloat(@as(f32, @floatFromInt(tev.y)) / scale);
                            if (rs.page_drag_surface) |ps| {
                                if (dpy >= rs.page_lib_y) {
                                    removeDraggedFromSurface(rs, ps);
                                } else switch (ps) {
                                    0 => pageDragDrop(rs.socket_cards, rs.socket_blob, &rs.gseated, &rs.gsocket_ui, rs.page_geoms[0], &rs.loadout_dirty),
                                    1 => pageDragDrop(rs.reply_cards, rs.reply_blob, &rs.reply_seated, &rs.reply_ui, rs.page_geoms[1], &rs.loadout_dirty),
                                    else => pageDragDrop(rs.zone_cards, rs.zone_blob, &rs.zone_seated, &rs.zone_ui, rs.page_geoms[2], &rs.loadout_dirty),
                                }
                                // page_drag_surface stays set — the settle advance
                                // (advanceSocketDrag) eases the ghost home and clears it.
                            } else if (rs.gbench_drag) |bdi| {
                                benchDrop(rs, bdi, dpx, dpy);
                                rs.gbench_drag = null;
                            }
                            m.hold_fired = false;
                        } else if (m.socket_swipe) {
                            // A socket swipe cycles the seated cartridge on release
                            // if it travelled past the threshold: swipe LEFT → next,
                            // RIGHT → previous, wrapping. Same re-seat the tap path
                            // does, but the swap slides HORIZONTALLY along the swipe
                            // (swap_dir). Cycles the surface the swipe started on.
                            const dx = @as(i32, tev.x) - m.down_x;
                            const surf = m.socket_swipe_surface;
                            const seated_ptr: *u32 = switch (surf) {
                                1 => &rs.reply_seated,
                                2 => &rs.zone_seated,
                                else => &rs.gseated,
                            };
                            const sock_ui: *lens_socket.SocketUi = switch (surf) {
                                1 => &rs.reply_ui,
                                2 => &rs.zone_ui,
                                else => &rs.gsocket_ui,
                            };
                            const count: i32 = switch (surf) {
                                1 => @intCast(rs.reply_cards.len),
                                2 => @intCast(rs.zone_cards.len),
                                else => @intCast(rs.socket_cards.len),
                            };
                            if (count > 1 and @abs(dx) > 55) {
                                const delta: i32 = if (dx < 0) 1 else -1;
                                const ni: u32 = @intCast(@mod(@as(i32, @intCast(seated_ptr.*)) + delta + count, count));
                                if (ni != seated_ptr.*) {
                                    sock_ui.swap_from = seated_ptr.*;
                                    sock_ui.swap_to = ni;
                                    sock_ui.swap_phase = 1;
                                    sock_ui.swap_dir = if (dx < 0) -1 else 1; // slide the cartridge along the swipe
                                    seated_ptr.* = ni;
                                    // The home feed re-ranks + scrolls to top on re-seat;
                                    // the inline reply/zone sockets keep the scroll position
                                    // (they re-rank in place, no jump).
                                    if (surf == 0) rs.gscroll_px = 0;
                                    rs.loadout_dirty = true;
                                    m.haptic_pending = 2; // the swap latches under the finger
                                }
                            }
                            m.socket_swipe = false;
                            m.socket_swipe_surface = 0;
                        } else if (m.hswipe) {
                            // Release: the settle DECISION comes from where
                            // momentum would land (projection, roadmap §2.2),
                            // not from where the finger stopped — a small
                            // flick still sends the drawer all the way. The
                            // settle spring STARTS with the finger's release
                            // velocity (§2.3), so the motion picks up exactly
                            // where the gesture ended.
                            if (rs.gpu_state) |*gsd| {
                                gsd.drawer_drag = false;
                                const v_t = gesture.velocity(&m.ring).x / @as(f32, @floatFromInt(feed_view.drawer_w));
                                gsd.drawer_want = gesture.settleOpen(gsd.drawer_t, v_t);
                                gsd.drawer_v = v_t;
                            }
                        } else if (m.down_x >= 0 and !m.scrolling) {
                            // A clean tap: the press point, then the release —
                            // unless the press landed on the Zat4 keyboard
                            // (its keys already fired at touch-down; the
                            // panel swallows the rest by design) or on a
                            // selection handle (the drag was the action).
                            if (!m.press_in_kbd and !m.input_lp and m.chat_hnd == 0) {
                                pointer_events.append(gpa, .{ .x = @intCast(m.down_x), .y = @intCast(m.down_y), .kind = .button_down, .button = 1, .mods = 0, ._pad = 0 }) catch {};
                                pointer_events.append(gpa, .{ .x = tev.x, .y = tev.y, .kind = .button_up, .button = 1, .mods = 0, ._pad = 0 }) catch {};
                            }
                            m.input_lp = false;
                        }
                        if (m.over_px != 0) {
                            // A banded release hands the stretch to the bounce
                            // spring at the speed the give was visibly moving:
                            // finger velocity through the band's local slope
                            // (§2.3 velocity handoff, in displayed units).
                            // The chat thread's finger-to-content mapping is
                            // FLIPPED (bottom-anchor) — the band accumulated
                            // in flipped space, so the release velocity must
                            // flip too or the spring launches AGAINST the
                            // stretch and dies at the rest clamp: the missing
                            // messages bounce (owner, 2026-07-12).
                            var band_vy = gesture.velocity(&m.ring).y;
                            if (rs.gscreen == feed_view.screen_messages and rs.gchat_sel != null) band_vy = -band_vy;
                            m.bounce_px = gesture.rubberBand(m.over_px, view_h_f);
                            m.bounce_v = band_vy * gesture.rubberBandSlope(m.over_px, view_h_f);
                            m.over_px = 0;
                            m.fling_v = 0; // the spring owns the return; no glide underneath
                        }
                        // A scroll release KEEPS m.fling_v — the glide below
                        // takes over from the sampled velocity. FLICK LAUNCH: a
                        // release throws the glide FASTER than the finger's last
                        // speed so a quick flick ramps up and carries. The boost
                        // is multiplicative (a slow release is barely affected)
                        // and clamped so a hard flick stays controllable.
                        if (m.over_px == 0 and @abs(m.fling_v) > 0.5) {
                            const flick_boost: f32 = 2.1;
                            const flick_v_max: f32 = 240.0; // logical px/frame ceiling
                            m.fling_v = std.math.clamp(m.fling_v * flick_boost, -flick_v_max, flick_v_max);
                        }
                        m.down_x = -1;
                        m.down_y = -1;
                        m.scrolling = false;
                        m.drag_y = -1;
                        m.chat_hnd = 0;
                    },
                    else => {},
                };
                // ACTION_CANCEL: the OS claimed the in-flight gesture (the back
                // edge, the notification shade). Reset the whole machine — no tap
                // fires, a held card is dropped in place, the drawer settles from
                // wherever the finger left it. Before this, the cancel was simply
                // DROPPED and the pump kept a phantom finger.
                if (m.touch_cancel) {
                    m.touch_cancel = false;
                    m.chat_hnd = 0;
                    m.kbd_space_down = false;
                    m.kbd_nav = false;
                    m.kbd_multi = false;
                    m.kbd_press_cp = 0;
                    rs.kbd_popup_kind = 0;
                    rs.kbd_popup_n = 0;
                    rs.kbd_popup_sel = -1;
                    rs.kbd_flash_held = false;
                    m.down_x = -1;
                    m.down_y = -1;
                    m.scrolling = false;
                    m.drag_y = -1;
                    m.socket_swipe = false;
                    m.over_px = 0;
                    m.fling_v = 0;
                    if (m.hswipe) {
                        m.hswipe = false;
                        if (rs.gpu_state) |*gsd| {
                            gsd.drawer_drag = false;
                            gsd.drawer_want = gesture.settleOpen(gsd.drawer_t, 0);
                        }
                    }
                    if (m.hold_fired) {
                        m.hold_fired = false;
                        rs.gbench_drag = null;
                        if (rs.page_drag_surface) |cps| {
                            switch (cps) {
                                1 => rs.reply_ui.drag_active = null,
                                2 => rs.zone_ui.drag_active = null,
                                else => rs.gsocket_ui.drag_active = null,
                            }
                            rs.page_drag_surface = null;
                        }
                    }
                }
                // SYSTEM BACK (the Pixel edge swipe / back button, ferried by the
                // activity's key drain): pop one level of in-app navigation; with
                // nothing left to pop, flag the activity to step the task back to
                // the launcher — back-at-root minimizes, never exits the process.
                if (m.back_pending) {
                    m.back_pending = false;
                    if (!backNavigate(rs)) m.minimize_pending = true;
                }
                // PRESS-AND-HOLD backspace (Zat4 keyboard): a finger resting
                // on the backspace key repeats the delete — first at 350 ms,
                // then ~18/s — the way every phone keyboard behaves. The
                // continuous render loop ticks on a motionless finger, so
                // this per-frame timer fires; the burst cap keeps a hitched
                // frame from dumping deletes. Once a repeat lands, the
                // release tap is spent (swallowed at button_up).
                if (m.down_x >= 0 and m.press_in_kbd and !m.scrolling and
                    (now_ms -% m.down_ms) >= 350) bs_rep:
                {
                    const bx: i32 = @intFromFloat(@as(f32, @floatFromInt(m.down_x)) / scale);
                    const by: i32 = @intFromFloat(@as(f32, @floatFromInt(m.down_y)) / scale);
                    const bhit = feed_view.hitTest(rs.gregions.items, bx, by) orelse break :bs_rep;
                    if (bhit.kind != .kbd_backspace) break :bs_rep;
                    const due: u32 = 1 + ((now_ms -% m.down_ms) - 350) / 55;
                    var burst: u32 = 0;
                    while (m.kbd_bs_repeats < due and burst < 2) : (burst += 1) {
                        rs.kbd_bytes.append(gpa, 8) catch break;
                        m.kbd_bs_repeats += 1;
                    }
                    if (burst > 0) {
                        rs.kbd_flash_key = 0xE002;
                        rs.kbd_flash_ns = clock_shell.monotonicNanos();
                        rs.kbd_dirty = true;
                    }
                }
                // LONG-PRESS (Zat4 keyboard): ₿ held opens the pay sheet —
                // the money key; @ / # held open APP-AWARE alternates
                // (recent conversation handles / pinned zones). The keyboard
                // IS the app, so these cost no privacy — the very reason it
                // exists. The sigil itself was press-committed; a selection
                // types only the remainder.
                if (m.down_x >= 0 and m.press_in_kbd and rs.kbd_popup_kind == 0 and
                    m.kbd_press_cp != 0 and (now_ms -% m.down_ms) >= 380)
                {
                    switch (m.kbd_press_cp) {
                        0x20BF => {
                            m.kbd_press_cp = 0;
                            rs.kbd_bytes.append(gpa, 8) catch {}; // un-type the ₿
                            rs.kbd_flash_held = false;
                            if (dev_chat and rs.gscreen == feed_view.screen_messages and rs.gchat_sel != null) {
                                rs.gpay_open = true;
                                m.haptic_pending = 2;
                            }
                        },
                        '@', '#' => {
                            rs.kbd_popup_n = 0;
                            if (m.kbd_press_cp == '#') {
                                for (rs.zone_pins.tags.items) |tag| {
                                    if (rs.kbd_popup_n >= 4) break;
                                    const tn = @min(tag.len, 63);
                                    @memcpy(rs.kbd_popup_bufs[rs.kbd_popup_n][0..tn], tag[0..tn]);
                                    rs.kbd_popup_opts[rs.kbd_popup_n] = rs.kbd_popup_bufs[rs.kbd_popup_n][0..tn];
                                    rs.kbd_popup_n += 1;
                                }
                            } else if (dev_chat) {
                                const rows = chat_view_core.buildList(arena, &rs.gchat_store, now) catch &[_]chat_view_core.ListRow{};
                                for (rows) |row| {
                                    if (rs.kbd_popup_n >= 4) break;
                                    if (row.name.len == 0) continue;
                                    const hn = @min(row.name.len, 63);
                                    @memcpy(rs.kbd_popup_bufs[rs.kbd_popup_n][0..hn], row.name[0..hn]);
                                    rs.kbd_popup_opts[rs.kbd_popup_n] = rs.kbd_popup_bufs[rs.kbd_popup_n][0..hn];
                                    rs.kbd_popup_n += 1;
                                }
                            }
                            if (rs.kbd_popup_n > 0) {
                                rs.kbd_popup_kind = if (m.kbd_press_cp == '#') 2 else 1;
                                rs.kbd_popup_ax = m.kbd_press_x;
                                rs.kbd_popup_ay = m.kbd_press_y;
                                rs.kbd_popup_aw = m.kbd_press_w;
                                rs.kbd_popup_sel = -1;
                                m.haptic_pending = 2;
                                rs.kbd_dirty = true;
                            }
                            m.kbd_press_cp = 0; // one popup per press
                        },
                        else => {},
                    }
                }
                // LONG-PRESS on the chat INPUT: select the word under the
                // finger + summon the Copy/Cut/Paste bar (the standard
                // text-editing entry the strip was missing).
                if (m.down_x >= 0 and m.input_press and !m.scrolling and (now_ms -% m.down_ms) >= 420) {
                    m.input_press = false;
                    m.input_lp = true; // the release tap is spent
                    if (rs.engine) |*ieng| {
                        for (rs.gregions.items) |r2| {
                            if (r2.kind != .chat_input) continue;
                            const lx: i32 = @intFromFloat(@as(f32, @floatFromInt(m.down_x)) / scale);
                            const ly: i32 = @intFromFloat(@as(f32, @floatFromInt(m.down_y)) / scale);
                            const off = feed_view.chatDraftOffsetAt(ieng, rs.gchat_draft_buf[0..rs.gchat_draft_len], r2.w, lx - r2.x, ly - r2.y);
                            const wd = feed_view.wordAround(rs.gchat_draft_buf[0..rs.gchat_draft_len], off);
                            rs.gchat_sel_a = wd.a;
                            rs.gchat_sel_b = wd.b;
                            rs.gchat_caret = wd.b;
                            rs.gchat_edit_bar = true;
                            rs.gchat_input_focus = true;
                            rs.kbd_dirty = true;
                            m.haptic_pending = 2;
                            break;
                        }
                    }
                }
                // PRESS-AND-HOLD to pick up a draggable (phone loadout): a finger
                // that rests on a library card past the hold threshold — WITHOUT
                // committing to a scroll or swipe — lifts it into a drag, the way you
                // hold a home-screen icon to move it. The continuous render loop ticks
                // even on a motionless finger, so this per-frame timer fires. Once
                // lifted, the move/up arms above own the ghost + the drop.
                const hold_ms: u32 = 300;
                if (m.down_x >= 0 and !m.hold_fired and !m.scrolling and !m.hswipe and !m.socket_swipe and
                    rs.gbench_drag == null and rs.gbench_pick == null and
                    rs.gscreen == feed_view.screen_loadout and (now_ms -% m.down_ms) >= hold_ms)
                {
                    const hx: i32 = @intFromFloat(@as(f32, @floatFromInt(m.down_x)) / scale);
                    const hy: i32 = @intFromFloat(@as(f32, @floatFromInt(m.down_y)) / scale);
                    if (feed_view.hitTest(rs.gregions.items, hx, hy)) |hit| {
                        if (hit.kind == .bench_seat) {
                            rs.gbench_drag = @intCast(hit.post);
                            rs.gbench_drag_x = hx;
                            rs.gbench_drag_y = hy;
                            m.hold_fired = true;
                            m.haptic_pending = 2; // the pick-up ticks under the finger
                        }
                    }
                    // Not a library card: a hold on a SOCKETED tray card lifts it
                    // into the page drag — reorder within its socket, or carry it
                    // down to the library to unequip. The SEATED lens stays put
                    // (§7.3: seat another first), same as the desktop handle rule.
                    if (!m.hold_fired) socket_pick: {
                        const Surf = struct { hits: *lens_socket.HitList, ui: *lens_socket.SocketUi, cards: []lens_socket.LensCard, blob: []const u8, seated: u32 };
                        const surfs = [3]Surf{
                            .{ .hits = &rs.gsocket_hits, .ui = &rs.gsocket_ui, .cards = rs.socket_cards, .blob = rs.socket_blob, .seated = rs.gseated },
                            .{ .hits = &rs.reply_hits, .ui = &rs.reply_ui, .cards = rs.reply_cards, .blob = rs.reply_blob, .seated = rs.reply_seated },
                            .{ .hits = &rs.zone_hits, .ui = &rs.zone_ui, .cards = rs.zone_cards, .blob = rs.zone_blob, .seated = rs.zone_seated },
                        };
                        for (surfs, 0..) |sf, si| {
                            const act = lens_socket.hitTest(sf.hits.items, hx, hy) orelse continue;
                            switch (act) {
                                .seat => |cid| {
                                    const idx = trayIndexOfCid(sf.cards, sf.blob, cid) orelse continue;
                                    if (idx == sf.seated) continue; // the seated lens isn't draggable
                                    rs.page_drag_surface = @intCast(si);
                                    sf.ui.picking = null;
                                    sf.ui.drag_active = idx;
                                    sf.ui.drag_x = hx;
                                    sf.ui.drag_y = hy;
                                    m.hold_fired = true;
                                    m.haptic_pending = 2;
                                    break :socket_pick;
                                },
                                else => {},
                            }
                        }
                    }
                }
                // EDGE-DRAG AUTO-SCROLL: while a held card rides near the top or
                // bottom of the viewport, scroll the page under the finger — from
                // the library below the three sockets, only the BOTTOM socket was
                // reachable (owner, 2026-07-09). Speed ramps with edge proximity;
                // the clamp keeps it inside the page.
                if (m.hold_fired) {
                    const fy: i32 = if (rs.page_drag_surface) |ps| (switch (ps) {
                        1 => rs.reply_ui.drag_y,
                        2 => rs.zone_ui.drag_y,
                        else => rs.gsocket_ui.drag_y,
                    }) else rs.gbench_drag_y;
                    const ins_top: i32 = if (rs.gpu_state) |*gsd| @intCast(gsd.inset_top_l) else 0;
                    const ins_bot: i32 = if (rs.gpu_state) |*gsd| @intCast(gsd.inset_bottom_l) else 0;
                    const band: i32 = 110; // trigger band at each edge (logical px)
                    const top_zone = ins_top + 140 + band; // below the sticky header
                    const bot_zone = view_h - feed_view.tab_bar_h - ins_bot - band;
                    var dscroll: i32 = 0;
                    if (fy < top_zone) {
                        dscroll = @min(14, @divTrunc(top_zone - fy, 8) + 4);
                    } else if (fy > bot_zone) {
                        dscroll = -@min(14, @divTrunc(fy - bot_zone, 8) + 4);
                    }
                    if (dscroll != 0) rs.gscroll_px = @max(min_scroll, @min(0, rs.gscroll_px + dscroll));
                }
                // MOMENTUM (M-UX, first slice): while dragging, smooth the
                // per-frame travel into a velocity; with the finger up, the
                // feed glides on it — exponential friction. Constants are
                // per-60Hz-frame: friction 0.955 halves the glide roughly
                // every quarter second; rest below half a pixel. A glide that
                // reaches an edge no longer dies there — it hands its speed
                // to the bounce spring (roadmap §2.3/§3: no hard walls).
                // EMOJI PICKER MOMENTUM: the same exponential-friction glide,
                // clamped hard at the content edges (the picker is chrome,
                // not a page — no bounce).
                if (m.kbd_emoji_v != 0 and !m.kbd_emoji_drag) {
                    const max_sc: f32 = @floatFromInt(feed_view.emojiScrollMax());
                    // No kbd_dirty (same reason as the drag): the glide renders
                    // through the ordinary per-lap paint, not a razor repaint.
                    const ns = std.math.clamp(rs.kbd_emoji_scroll + m.kbd_emoji_v, 0, max_sc);
                    rs.kbd_emoji_scroll = ns;
                    m.kbd_emoji_v *= 0.955;
                    if (@abs(m.kbd_emoji_v) < 0.5 or ns == 0 or ns == max_sc) m.kbd_emoji_v = 0;
                }
                // The nav column's rubber band springs home after a slide —
                // the same edge-bounce constants the feed uses, so the two
                // gives read as one material.
                if (!m.kbd_nav_drag and (rs.kbd_nav_scroll != 0 or @abs(rs.kbd_nav_scroll_v) > 1.0)) {
                    const nav_return = comptime spring.springConstants(0.0, 0.35);
                    spring.stepScalar(&rs.kbd_nav_scroll, &rs.kbd_nav_scroll_v, 0.0, nav_return, 1.0 / 60.0);
                    if (@abs(rs.kbd_nav_scroll) < 0.5 and @abs(rs.kbd_nav_scroll_v) < 5.0) {
                        rs.kbd_nav_scroll = 0;
                        rs.kbd_nav_scroll_v = 0;
                    }
                }
                const fling_friction: f32 = 0.966; // softer decay → the flick carries further
                const fling_rest: f32 = 0.5;
                if (m.scrolling or m.down_x >= 0) {
                    m.fling_v = m.fling_v * 0.6 + frame_dy * 0.4;
                } else if (@abs(m.fling_v) > fling_rest) {
                    const pos = @as(f32, @floatFromInt(rs.gscroll_px)) + m.fling_v;
                    if (pos > 0 or pos < min_scroll_f) {
                        const edge: f32 = if (pos > 0) 0 else min_scroll_f;
                        rs.gscroll_px = @intFromFloat(edge);
                        m.bounce_px = pos - edge; // the overshoot step, displayed px
                        m.bounce_v = m.fling_v * 60.0; // px/frame -> px/s
                        m.fling_v = 0;
                    } else {
                        rs.gscroll_px = @intFromFloat(pos);
                        m.fling_v *= fling_friction;
                    }
                } else m.fling_v = 0;
                // THE EDGE EPISODE writes the frame's scroll: while the finger
                // holds a stretch, edge + band(raw); while the spring returns
                // it, edge + bounce. Both offsets are in displayed logical px
                // and their SIGN names the edge (positive = top). drawDrawer-
                // style consumers see an ordinary scroll value throughout.
                if (m.over_px != 0) {
                    const edge_i: i32 = if (m.over_px > 0) 0 else min_scroll;
                    rs.gscroll_px = edge_i + @as(i32, @intFromFloat(gesture.rubberBand(m.over_px, view_h_f)));
                } else if (m.bounce_px != 0 or @abs(m.bounce_v) > 1.0) {
                    const scroll_bounce = comptime spring.springConstants(0.0, 0.35);
                    spring.stepScalar(&m.bounce_px, &m.bounce_v, 0.0, scroll_bounce, 1.0 / 60.0);
                    const edge_i: i32 = if (m.bounce_px > 0 or (m.bounce_px == 0 and m.bounce_v > 0)) 0 else min_scroll;
                    if (@abs(m.bounce_px) < 0.5 and @abs(m.bounce_v) < 5.0) {
                        m.bounce_px = 0;
                        m.bounce_v = 0;
                        rs.gscroll_px = edge_i;
                    } else {
                        rs.gscroll_px = edge_i + @as(i32, @intFromFloat(m.bounce_px));
                    }
                }
            },
            .window => |win| {
                // The pump translates X keys into the same bytes a tty
                // would deliver (into the hoisted lists above); close/resize
                // fold into the loop's own re-render lap (E2: a window
                // hiccup is not a crash).
                fb_w = win.fb.width;
                fb_h = win.fb.height;
                // Block up to the driver's wait budget — the 16ms-vs-500ms
                // cadence policy lives with the desktop driver now (MC.4).
                const pumped = window_shell.pump(win, wait_budget_ms, gpa, &pumped_bytes, &pointer_events) catch {
                    rs.status = "window error";
                    return .again; // frame over (was `continue`)
                };
                if (pumped.closed) break :main_loop;
                if (pumped.dropped > 0) rs.status = "input dropped (low memory)";
                if (pumped.x_error != 0) {
                    // The server refused a request (almost always a blit).
                    // Show the code so a black window names its own cause
                    // instead of staying mute. Codes: 1=Request 2=Value
                    // 3=Window 4=Pixmap 8=Match 9=Drawable 13=GContext
                    // 16=Length. (E3: no silent failure.)
                    rs.status = std.fmt.bufPrint(&rs.status_buf, "X error code {d}", .{pumped.x_error}) catch "X error";
                }
                // The window's FIRST valid drawable arrives with Expose, not
                // with map: a PutImage sent before the server has exposed the
                // window is discarded, which is exactly the "window opens
                // black and never paints" failure. The pump reports Expose
                // (and geometry changes) precisely so the loop can paint the
                // moment the surface becomes valid — honor it by re-presenting
                // the current frame at once instead of idling 500 ms with a
                // blit the server already threw away. (E2: a repaint request
                // is folded into the loop's own re-render lap.)
                if (pumped.exposed or pumped.resized) {
                    if (rs.mode == .timeline) {
                        try paintFrame(gpa, rs.out, arena, &rs.prev, &rs.next, backend, pix, view_items, profile_header, &rs.state, rs.revealed.items, now, session.handle, rs.status);
                    } else {
                        try present(gpa, rs.out, arena, &rs.prev, &rs.next, backend);
                    }
                }
            },
        }
        // ---- the mouse becomes the app (5.2): consume the channel.
        // Wheel scrolls the pixel viewport; motion drives hover;
        // a click selects its card, and an action zone injects the
        // SAME byte the bound key sends, so the dispatch below is
        // the one and only path (timeline_ui.keyFor — round-trip
        // tested against actionFor). Hit rects are last frame's:
        // immediate-mode's standard one-frame contract.
        if (rs.mode == .timeline) if (pix) |g| {
            // Pointer coords are PIXELS; the grid thinks in cells.
            // Use the SAME zoom-derived cell size the renderer
            // used, so clicks land on the cell under the cursor at
            // any zoom. Convert once, then everything is cell-space.
            const pcell = cellSize(fb_w, g.zoom.*);
            // The GPU feed lays out in LOGICAL pixels (design_w, scaled
            // to fill); the software feed in physical pixels. So the
            // region hit-test and the scroll clamp work in whichever
            // space the layout used — map the physical pointer back to
            // logical for GPU (÷scale), pass it through for software.
            const gpu_scale: f32 = if (g.gpu) |gs| gs.scale else 1.0;
            for (pointer_events.items) |pev| {
                const cx: u16 = pev.x / pcell.w;
                const cy: u16 = pev.y / pcell.h;
                const rx: i32 = if (g.gpu != null) @intFromFloat(@as(f32, @floatFromInt(pev.x)) / gpu_scale) else @intCast(pev.x);
                const ry: i32 = if (g.gpu != null) @intFromFloat(@as(f32, @floatFromInt(pev.y)) / gpu_scale) else @intCast(pev.y);
                // The cartridge DETAIL sheet (item 5) owns the pointer while open: its
                // hit list is topmost, so resolve it here and CONSUME every event so the
                // screen beneath never reacts. A swatch recolours (live, incl. the whole-
                // UI accent when it's the seated lens); the X / scrim / a stray tap close;
                // a tap on the panel body is swallowed.
                if (rs.gcart_detail != null) {
                    if (pev.kind == .button_down and pev.button == 1) {
                        if (lens_socket.hitTest(rs.detail_hits.items, rx, ry)) |dact| switch (dact) {
                            .close_detail => rs.gcart_detail = null,
                            .set_color => |sc| applyDetailColor(rs, sc.color),
                            else => {}, // noop_detail: a tap on the panel body, swallowed
                        } else rs.gcart_detail = null;
                    }
                    continue;
                }
                // Toy Box: Gravity SHATTER owns the pointer while the page is broken —
                // grab/fling tiles, tap the highlighted OFF toggle to stop, and NOTHING
                // else is clickable (nav + settings are locked out). Consume the event.
                if (rs.gpu_state) |*gs| if (gs.shatter_active) {
                    // The fixed EXIT box (top-right) ends it instantly, wherever the
                    // debris is — checked before any grab.
                    const ex = feed_view.shatterExitX(@intCast(gs.design_w));
                    const in_exit = rx >= ex and rx < ex + feed_view.shatter_exit_w and ry >= feed_view.shatter_exit_margin and ry < feed_view.shatter_exit_margin + feed_view.shatter_exit_h;
                    if (pev.kind == .button_down and pev.button == 1 and in_exit) {
                        if (settings_view.rowOf(settings_view.act_gravity)) |grow|
                            rs.toggle_bits &= ~(@as(u64, 1) << grow);
                        continue;
                    }
                    switch (pev.kind) {
                        .button_down => if (pev.button == 1) {
                            gs.shatter_down_x = rx;
                            gs.shatter_down_y = ry;
                            if (shatter.pick(gs.shatter_x.items, gs.shatter_y.items, gs.shatter_bw.items, gs.shatter_bh.items, @floatFromInt(rx), @floatFromInt(ry))) |p| {
                                // Grab a group (word / the Gravity control) by its
                                // leader so the whole block drags together.
                                const target: usize = if (p < gs.shatter_leader_of.items.len) gs.shatter_leader_of.items[p] else p;
                                gs.shatter_held = target;
                                gs.shatter_grab_dx = @as(f32, @floatFromInt(rx)) - gs.shatter_x.items[target];
                                gs.shatter_grab_dy = @as(f32, @floatFromInt(ry)) - gs.shatter_y.items[target];
                            }
                        },
                        .move => {
                            rs.ghover_x = rx; // the render pins the held body to this
                            rs.ghover_y = ry;
                        },
                        .button_up => if (pev.button == 1) {
                            gs.shatter_held = null; // release → the drag velocity flings it
                            // A TAP (barely moved) on the Gravity block stops it.
                            const moved = @abs(rx - gs.shatter_down_x) + @abs(ry - gs.shatter_down_y);
                            if (moved < 10) {
                                if (shatter.pick(gs.shatter_x.items, gs.shatter_y.items, gs.shatter_bw.items, gs.shatter_bh.items, @floatFromInt(rx), @floatFromInt(ry))) |hit| {
                                    if (hit < gs.shatter_group.items.len and gs.shatter_group.items[hit]) {
                                        if (settings_view.rowOf(settings_view.act_gravity)) |grow|
                                            rs.toggle_bits &= ~(@as(u64, 1) << grow); // gravity OFF
                                    }
                                }
                            }
                        },
                        else => {},
                    }
                    continue; // shatter consumes the pointer — no normal dispatch
                };
                // Toy Box: Pet — any input keeps it awake; scrolling feeds the
                // doom-scroll signal; grab it to toss it (a tap pets it); and while
                // it's out you can drag a profile picture from the feed to feed it.
                if (rs.gpu_state) |*gs| if (toggleOn(rs.toggle_bits, settings_view.act_pet)) {
                    gs.pet_interacted = true;
                    if (pev.kind == .wheel) gs.pet_scroll_ms +|= 120;
                    if (pev.kind == .move and gs.avatar_drag) {
                        gs.avatar_x = @floatFromInt(rx);
                        gs.avatar_y = @floatFromInt(ry);
                    }
                    const in_pet = rx >= gs.pet_x and rx < gs.pet_x + gs.pet_bw and ry >= gs.pet_y and ry < gs.pet_y + gs.pet_bh;
                    if (pev.kind == .button_down and pev.button == 1 and in_pet) {
                        gs.pet_grabbed = true;
                        gs.pet_grab_dx = @as(f32, @floatFromInt(rx)) - gs.pet_px;
                        gs.pet_grab_dy = @as(f32, @floatFromInt(ry)) - gs.pet_py;
                        gs.pet_down_x = rx;
                        gs.pet_down_y = ry;
                        continue;
                    }
                    // Start dragging a profile picture out of the feed toward the pet.
                    if (pev.kind == .button_down and pev.button == 1 and !in_pet and !gs.avatar_drag) {
                        if (feed_view.hitTest(g.regions.items, rx, ry)) |h2| {
                            if (h2.kind == .author) {
                                gs.avatar_drag = true;
                                gs.avatar_post = h2.post;
                                gs.avatar_x = @floatFromInt(rx);
                                gs.avatar_y = @floatFromInt(ry);
                                continue; // dragging the avatar, not opening the profile
                            }
                        }
                    }
                    if (pev.kind == .button_up and pev.button == 1 and gs.pet_grabbed) {
                        gs.pet_grabbed = false; // release → the drag velocity tosses it
                        if (@abs(rx - gs.pet_down_x) + @abs(ry - gs.pet_down_y) < 14) { // a tap (not a fling) pets it
                            gs.pet_petted = true;
                            gs.pet_happy = 42; // a brief reaction, then back to neutral
                            gs.pet_vx = 0; // don't also toss it
                            gs.pet_vy = 0;
                        } else {
                            gs.pet_tossed = true; // a real fling → fun in moderation
                        }
                        continue;
                    }
                    if (pev.kind == .button_up and pev.button == 1 and gs.avatar_drag) {
                        if (in_pet) { // dropped on the pet → feed it
                            gs.pet_petted = true;
                            gs.pet_happy = 55; // a brief, clear smile
                        }
                        gs.avatar_drag = false;
                        continue;
                    }
                };
                switch (pev.kind) {
                    .wheel => {
                        if (g.gpu) |gs| gs.menu_open = false; // scrolling dismisses the menu
                        rs.grepost_menu = null; // …and the Repost/Quote popover
                        // Wheel-down (5) / wheel-right (7) advance; wheel-up (4) /
                        // wheel-left (6) retreat. Horizontal wheel feeds the same
                        // scroll so the Tectonic filmstrip pans sideways too.
                        const delta: i32 = if (pev.button == 5 or pev.button == 7) 3 else -3;
                        g.view.scroll_rows += delta;
                        // The premium feed scrolls in PIXELS. Wheel down
                        // (button 5) moves content up, so the offset goes
                        // more negative; clamp so you cannot scroll past
                        // the ends (top = 0, bottom exposes the last post
                        // + a little breathing room). content_h is in the
                        // layout's space, so the viewport height matches.
                        if (dev_chat and g.screen.* == feed_view.screen_messages) {
                            // The chat thread is BOTTOM-anchored: wheel UP walks
                            // back into history. The shared clamp keeps scroll in
                            // [min_scroll, 0]; the dispatch passes -scroll to
                            // layoutChat as its positive history offset.
                            g.scroll.* += delta * 28;
                        } else {
                            g.scroll.* -= delta * 28;
                        }
                        const view_h: i32 = if (g.gpu != null)
                            @intFromFloat(@as(f32, @floatFromInt(fb_h)) / gpu_scale)
                        else
                            @intCast(fb_h);
                        const min_scroll: i32 = @min(0, view_h - g.content_h.* - 24);
                        g.scroll.* = @max(min_scroll, @min(0, g.scroll.*));
                        effect_core.shiftY(g.active, -delta);
                        // Pull-to-refresh: a wheel-up (button 4 → delta < 0)
                        // that lands while already pinned at the top of Home
                        // builds overscroll; past the threshold it asks for a
                        // refresh. A wheel-down cancels the pull.
                        if (g.screen.* == feed_view.screen_home and pev.button == 4 and g.scroll.* == 0) {
                            rs.overscroll_accum += 28;
                            if (rs.overscroll_accum >= pull_refresh_threshold) {
                                rs.pull_refresh_requested = true;
                                rs.overscroll_accum = 0;
                            } else {
                                // Visible proof the pull is registering (the
                                // animated indicator is the deferred polish).
                                rs.status = "↑ keep pulling to refresh";
                            }
                        } else if (pev.button == 5) {
                            rs.overscroll_accum = 0;
                        }
                    },
                    .move => {
                        // Track the pointer in LOGICAL coords for the hover
                        // highlight (rx/ry are already mapped through scale).
                        rs.ghover_x = rx;
                        rs.ghover_y = ry;
                        // A live drag: the ghost card follows the pointer. On the
                        // loadout page the dragged surface may be reply/zone.
                        if (rs.page_drag_surface) |s| {
                            const ui = switch (s) {
                                1 => &rs.reply_ui,
                                2 => &rs.zone_ui,
                                else => &rs.gsocket_ui,
                            };
                            ui.drag_x = rx;
                            ui.drag_y = ry;
                        } else if (rs.gsocket_ui.drag_active != null) {
                            rs.gsocket_ui.drag_x = rx;
                            rs.gsocket_ui.drag_y = ry;
                        }
                        if (rs.gbench_drag != null) {
                            rs.gbench_drag_x = rx;
                            rs.gbench_drag_y = ry;
                        }
                        const field_hit = field_ui.hitTest(cx, cy, g.hr.slice());
                        g.view.hover = if (field_hit) |hit| hit.target else field_ui.no_target;
                        // Pointer affordance: the hand cursor over anything
                        // clickable, the arrow otherwise. The SAME hit-tests
                        // the click path below consults — feed regions, the
                        // lens socket, on the Algorithms page the reply/zone
                        // sockets too, and the legacy cell rects — so the
                        // cursor and the click always agree on what is tappable.
                        const over_clickable =
                            feed_view.hitTest(g.regions.items, rx, ry) != null or
                            (rs.gbench_pick == null and lens_socket.hitTest(g.socket_hits.items, rx, ry) != null) or
                            (rs.gscreen == feed_view.screen_loadout and rs.gbench_pick == null and
                                (lens_socket.hitTest(rs.reply_hits.items, rx, ry) != null or
                                    lens_socket.hitTest(rs.zone_hits.items, rx, ry) != null)) or
                            field_hit != null;
                        // A live text-selection drag over the rooted post:
                        // extend the selection to the caret under the pointer.
                        if (g.gpu) |gs| if (gs.sel_dragging) {
                            gs.sel_focus = text_select.caretAtPoint(gs.sel_glyphs.items, rx, ry);
                        };
                        // Cursor shape, by priority: grab while dragging a lens
                        // card; the I-beam over the rooted post's selectable body
                        // (or mid text-drag); the hand over anything else
                        // clickable; the arrow otherwise.
                        const dragging_card = rs.page_drag_surface != null or rs.gsocket_ui.drag_active != null or rs.gbench_drag != null;
                        const over_focus_text = rs.gscreen == feed_view.screen_thread and blk: {
                            const h = feed_view.hitTest(g.regions.items, rx, ry) orelse break :blk false;
                            break :blk h.kind == .post_body and h.post < view_items.len and view_items[h.post].is_focus;
                        };
                        const sel_dragging = if (g.gpu) |gs| gs.sel_dragging else false;
                        const cursor_shape: layout_core.Cursor = if (dragging_card)
                            .grab
                        else if (over_focus_text or sel_dragging)
                            .text
                        else if (over_clickable)
                            .pointer
                        else
                            .default;
                        switch (backend) {
                            .window => |w| window_shell.setCursor(w, cursor_shape),
                            else => {}, // a finger casts no cursor
                        }
                        // GPU: the cursor lights the field (drawFieldGrid
                        // halo) and leaves a gentle colourless wake.
                        if (g.gpu) |gs| {
                            gs.mcx = @as(f32, @floatFromInt(pev.x)) / @as(f32, @floatFromInt(field_cell_w));
                            gs.mcy = @as(f32, @floatFromInt(pev.y)) / @as(f32, @floatFromInt(field_cell_h));
                            if (gs.cols > 0 and gs.rows > 0) {
                                const sx: u32 = @min(@as(u32, @intFromFloat(@max(0.0, gs.mcx))), gs.cols - 1);
                                const sy: u32 = @min(@as(u32, @intFromFloat(@max(0.0, gs.mcy))), gs.rows - 1);
                                // hover wake: a gentle, colourless ripple at the pointer.
                                gs.splashes.append(gpa, .{ .x = sx, .y = sy, .radius = 3, .amp = 0.4 }) catch {};
                            }
                        }
                    },
                    .button_down => {
                        // Right-click → the context menu over the rooted
                        // post body. Left-click while the menu is open hits
                        // an item or dismisses it (never the feed beneath).
                        if (pev.button == 3) {
                            if (g.gpu) |gs| openContextMenu(gs, rs.gscreen, view_items, g.regions.items, rx, ry);
                        } else if (pev.button == 1) {
                            if (g.gpu) |gs| if (gs.menu_open) {
                                menuClick(gpa, gs, backend, rx, ry);
                                continue;
                            };
                            // Premium buttons are hit-tested against the
                            // regions the feed emitted this frame. A like/
                            // repost tap blooms the burst right at the icon:
                            // on the GPU it stamps the living field (a real
                            // dye splash); on the software path it triggers
                            // the legacy burst effect. (Persisting a MOUSE
                            // tap is still the deferred slice; the keyboard
                            // like persists and bursts via fireEngageEffect.)
                            // If nothing premium is hit, fall through to the
                            // legacy cell hit rects.
                            //
                            // THE LENS SOCKET is tested FIRST — it sits in the
                            // sticky header, on top of the feed (its hits live
                            // in their own space). Seating re-tints + animates
                            // the swap; re-ranking the feed awaits the discover
                            // engine (only Following exists today).
                            var socket_handled = false;
                            // PHONE: a tap in the bottom TAB-BAR band never reaches the
                            // socket hit lists — page-socket card rects scroll BEHIND the
                            // bar and were eating nav taps ("home takes a ton of taps"
                            // from Algorithms, owner 2026-07-09). The bar's own regions
                            // (nav buttons + blocker) own that band via the regions path.
                            const in_bar_band = blk: {
                                if (rs.gpu_state) |*gsb| {
                                    if (gsb.design_w <= feed_view.phone_max) {
                                        const lvh: i32 = @intFromFloat(@as(f32, @floatFromInt(fb_h)) / gpu_scale);
                                        break :blk ry >= lvh - feed_view.tab_bar_h - @as(i32, @intCast(gsb.inset_bottom_l));
                                    }
                                }
                                break :blk false;
                            };
                            // The bench socket-chooser overlay owns input while open:
                            // socket hit-lists are tested BEFORE page regions, so
                            // without this gate the trays under the dim eat every
                            // click and the overlay soft-locks (owner-hit bug).
                            if (in_bar_band) {
                                // fall through to the regions dispatch (nav/blocker win)
                            } else if (rs.gscreen == feed_view.screen_loadout and rs.gbench_pick == null) {
                                // Loadout page: edit the surface under the cursor (feed /
                                // reply / zone). A handle press (.reorder) starts a drag for
                                // that surface; everything else is a click edit.
                                if (lens_socket.hitTest(g.socket_hits.items, rx, ry)) |sact| {
                                    switch (sact) {
                                        .reorder => |r| {
                                            rs.page_drag_surface = 0;
                                            rs.gsocket_ui.drag_active = trayIndexOfCid(rs.socket_cards, rs.socket_blob, r.lens);
                                            rs.gsocket_ui.drag_x = rx;
                                            rs.gsocket_ui.drag_y = ry;
                                        },
                                        // Tapping the ALREADY-seated cartridge opens its
                                        // detail/colour sheet here too (item 5) — the owner
                                        // expected this door on the Algorithms page as well.
                                        .seat => |scid| {
                                            if (trayIndexOfCid(rs.socket_cards, rs.socket_blob, scid)) |six| {
                                                if (six == rs.gseated) {
                                                    rs.gcart_detail = 0;
                                                } else applyLoadoutAction(sact, rs.socket_cards, rs.socket_blob, &rs.gseated, &rs.gsocket_ui, &rs.loadout_dirty);
                                            }
                                        },
                                        else => applyLoadoutAction(sact, rs.socket_cards, rs.socket_blob, &rs.gseated, &rs.gsocket_ui, &rs.loadout_dirty),
                                    }
                                    socket_handled = true;
                                } else if (lens_socket.hitTest(rs.reply_hits.items, rx, ry)) |sact| {
                                    switch (sact) {
                                        .reorder => |r| {
                                            rs.page_drag_surface = 1;
                                            rs.reply_ui.drag_active = trayIndexOfCid(rs.reply_cards, rs.reply_blob, r.lens);
                                            rs.reply_ui.drag_x = rx;
                                            rs.reply_ui.drag_y = ry;
                                        },
                                        // Tapping the ALREADY-seated cartridge opens its
                                        // detail/colour sheet here too (item 5) — the owner
                                        // expected this door on the Algorithms page as well.
                                        .seat => |scid| {
                                            if (trayIndexOfCid(rs.reply_cards, rs.reply_blob, scid)) |six| {
                                                if (six == rs.reply_seated) {
                                                    rs.gcart_detail = 1;
                                                } else applyLoadoutAction(sact, rs.reply_cards, rs.reply_blob, &rs.reply_seated, &rs.reply_ui, &rs.loadout_dirty);
                                            }
                                        },
                                        else => applyLoadoutAction(sact, rs.reply_cards, rs.reply_blob, &rs.reply_seated, &rs.reply_ui, &rs.loadout_dirty),
                                    }
                                    socket_handled = true;
                                } else if (lens_socket.hitTest(rs.zone_hits.items, rx, ry)) |sact| {
                                    switch (sact) {
                                        .reorder => |r| {
                                            rs.page_drag_surface = 2;
                                            rs.zone_ui.drag_active = trayIndexOfCid(rs.zone_cards, rs.zone_blob, r.lens);
                                            rs.zone_ui.drag_x = rx;
                                            rs.zone_ui.drag_y = ry;
                                        },
                                        // Tapping the ALREADY-seated cartridge opens its
                                        // detail/colour sheet here too (item 5) — the owner
                                        // expected this door on the Algorithms page as well.
                                        .seat => |scid| {
                                            if (trayIndexOfCid(rs.zone_cards, rs.zone_blob, scid)) |six| {
                                                if (six == rs.zone_seated) {
                                                    rs.gcart_detail = 2;
                                                } else applyLoadoutAction(sact, rs.zone_cards, rs.zone_blob, &rs.zone_seated, &rs.zone_ui, &rs.loadout_dirty);
                                            }
                                        },
                                        else => applyLoadoutAction(sact, rs.zone_cards, rs.zone_blob, &rs.zone_seated, &rs.zone_ui, &rs.loadout_dirty),
                                    }
                                    socket_handled = true;
                                }
                            } else if (rs.gscreen == feed_view.screen_thread) {
                                // The inline REPLY socket on a thread: a switcher over the
                                // reply loadout (shared with the Algorithms page). Order-only,
                                // no view retint. Reorder lives on the Algorithms page.
                                if (lens_socket.hitTest(g.socket_hits.items, rx, ry)) |sact| {
                                    socket_handled = true;
                                    switch (sact) {
                                        .toggle_tray => rs.reply_ui.open = !rs.reply_ui.open,
                                        .seat => |cid| {
                                            if (trayIndexOfCid(rs.reply_cards, rs.reply_blob, cid)) |idx| {
                                                if (idx == rs.reply_seated) {
                                                    rs.gcart_detail = 1; // tap the seated cartridge again → detail sheet
                                                } else {
                                                    rs.reply_seated = idx;
                                                    rs.loadout_dirty = true;
                                                }
                                            }
                                            rs.reply_ui.open = false;
                                            rs.reply_ui.expanded = null;
                                            rs.reply_ui.picking = null;
                                        },
                                        .get_more => {
                                            rs.reply_ui.open = false;
                                            rs.gscreen = feed_view.screen_loadout;
                                            rs.gscroll_px = 0;
                                        },
                                        else => applyLoadoutAction(sact, rs.reply_cards, rs.reply_blob, &rs.reply_seated, &rs.reply_ui, &rs.loadout_dirty),
                                    }
                                }
                            } else if (rs.gscreen == feed_view.screen_zones) {
                                // The zone page's socket: a switcher over the ZONE
                                // loadout (shared with the Algorithms page). Order-only;
                                // no real ranking power yet (the discover engine is
                                // unbuilt). Reorder lives on the Algorithms page.
                                if (lens_socket.hitTest(g.socket_hits.items, rx, ry)) |sact| {
                                    socket_handled = true;
                                    switch (sact) {
                                        .toggle_tray => rs.zone_ui.open = !rs.zone_ui.open,
                                        .seat => |cid| {
                                            if (trayIndexOfCid(rs.zone_cards, rs.zone_blob, cid)) |idx| {
                                                if (idx == rs.zone_seated) {
                                                    rs.gcart_detail = 2; // tap the seated cartridge again → detail sheet
                                                } else {
                                                    rs.zone_seated = idx;
                                                    rs.loadout_dirty = true;
                                                }
                                            }
                                            rs.zone_ui.open = false;
                                            rs.zone_ui.expanded = null;
                                            rs.zone_ui.picking = null;
                                        },
                                        .get_more => {
                                            rs.zone_ui.open = false;
                                            rs.gscreen = feed_view.screen_loadout;
                                            rs.gscroll_px = 0;
                                        },
                                        else => applyLoadoutAction(sact, rs.zone_cards, rs.zone_blob, &rs.zone_seated, &rs.zone_ui, &rs.loadout_dirty),
                                    }
                                }
                            } else if (lens_socket.hitTest(g.socket_hits.items, rx, ry)) |sact| {
                                socket_handled = true;
                                // Any socket action other than opening/using the picker
                                // closes it (the open/set arms re-open or keep as needed).
                                switch (sact) {
                                    .open_swatch, .set_color => {},
                                    else => rs.gsocket_ui.picking = null,
                                }
                                switch (sact) {
                                    .toggle_tray => rs.gsocket_ui.open = !rs.gsocket_ui.open,
                                    .seat => |cid| {
                                        if (trayIndexOfCid(rs.socket_cards, rs.socket_blob, cid)) |ni| {
                                            if (ni != rs.gseated) {
                                                rs.gsocket_ui.swap_from = rs.gseated;
                                                rs.gsocket_ui.swap_to = ni;
                                                rs.gsocket_ui.swap_phase = 1;
                                                rs.gsocket_ui.swap_dir = 0; // a tap ejects vertically (not a swipe)
                                                rs.gseated = ni;
                                                // Seat = re-rank now, scroll to top (owner decision
                                                // 2026-06-22). The visible gesture today; the actual
                                                // lens re-ordering is the discover-engine track —
                                                // THIS is the seam it plugs into (re-rank the feed by
                                                // the seated lens here, then reset scroll).
                                                rs.gscroll_px = 0;
                                            } else {
                                                // Tapping the ALREADY-seated cartridge opens its detail
                                                // + colour sheet (item 5) instead of a no-op re-seat.
                                                rs.gcart_detail = 0;
                                            }
                                        }
                                        rs.gsocket_ui.expanded = null;
                                        rs.gsocket_ui.open = false; // watch it plug in, then the tray retracts
                                        rs.loadout_dirty = true;
                                    },
                                    // ⓘ → expand inline detail; tapping the open one collapses it.
                                    .expand => |cid| {
                                        if (trayIndexOfCid(rs.socket_cards, rs.socket_blob, cid)) |idx| {
                                            rs.gsocket_ui.expanded = if (rs.gsocket_ui.expanded == idx) null else idx;
                                        }
                                    },
                                    .collapse => rs.gsocket_ui.expanded = null,
                                    // Press on a drag handle → start dragging that lens (the
                                    // seated one has no handle, §7.3). The ghost follows the
                                    // pointer; the drop lands on button_up.
                                    .reorder => |r| {
                                        rs.gsocket_ui.picking = null;
                                        rs.gsocket_ui.drag_active = trayIndexOfCid(rs.socket_cards, rs.socket_blob, r.lens);
                                        rs.gsocket_ui.drag_x = rx;
                                        rs.gsocket_ui.drag_y = ry;
                                    },
                                    // Tap a card's swatch → open/close its color picker (§11.5).
                                    .open_swatch => |cid| {
                                        const idx = trayIndexOfCid(rs.socket_cards, rs.socket_blob, cid);
                                        rs.gsocket_ui.picking = if (rs.gsocket_ui.picking == idx) null else idx;
                                    },
                                    // Pick a color → recolor that lens (totally the user's
                                    // call; duplicates allowed). If it's the seated lens, the
                                    // whole-UI accent follows next frame (seatedAccent).
                                    .set_color => |sc2| {
                                        if (trayIndexOfCid(rs.socket_cards, rs.socket_blob, sc2.lens)) |idx| {
                                            if (idx < rs.socket_cards.len) rs.socket_cards[idx].color = sc2.color;
                                            rs.loadout_dirty = true;
                                        }
                                        rs.gsocket_ui.picking = null;
                                    },
                                    // "get more" → the Algorithms (loadout) page.
                                    .get_more => {
                                        rs.gsocket_ui.picking = null;
                                        rs.gsocket_ui.open = false;
                                        rs.gscreen = feed_view.screen_loadout;
                                    },
                                    // The detail-sheet actions only arise from its own hit
                                    // list (dispatched topmost), never the socket — no-op here.
                                    .close_detail, .noop_detail => {},
                                }
                            }
                            // THE FRONT DOOR owns the pointer when it is up: it has
                            // its own hit list (enroll_view.HitList), so it arms and
                            // fires on its own, and nothing behind it is reachable.
                            if (rs.gscreen == feed_view.screen_enroll) {
                                // …unless the ENTRANCE is still playing, in which
                                // case the press means one thing only: get me past
                                // this. It never also arms a button on the card
                                // underneath — nobody aimed at a card they cannot
                                // see yet.
                                if (bootIntroSkip(rs)) continue;
                                rs.genroll_armed = enroll_view.hitTest(rs.genroll_hits.items, rx, ry);
                                continue;
                            }
                            if (!socket_handled) {
                                // Release-activation: ARM the tap (don't fire). It
                                // fires on button_up only if the release lands on
                                // the same target — press-then-slide-off cancels.
                                if (feed_view.hitTest(g.regions.items, rx, ry)) |hit| {
                                    rs.gsocket_ui.picking = null; // a click off the socket closes the picker
                                    // The ROOTED post's body is selectable, not a
                                    // re-root target: a press there places the caret
                                    // and begins a text selection (web-style — a
                                    // release without a drag clears it). Don't arm a tap.
                                    const is_focus_body = rs.gscreen == feed_view.screen_thread and hit.kind == .post_body and
                                        hit.post < view_items.len and view_items[hit.post].is_focus;
                                    if (hit.kind == .bench_seat and rs.gbench_pick == null) {
                                        // A press on a shelf card BEGINS the bench drag
                                        // (direct equip — owner call 2026-07-06); no tap
                                        // arms, the drop decides on release.
                                        rs.gbench_drag = @intCast(hit.post);
                                        rs.gbench_drag_x = rx;
                                        rs.gbench_drag_y = ry;
                                    } else if (is_focus_body) {
                                        if (g.gpu) |gs| selectPress(gs, rx, ry, &rs.last_click_ns, &rs.last_click_x, &rs.last_click_y, &rs.click_count, clock_shell.monotonicNanos());
                                    } else {
                                        rs.armed_kind = hit.kind;
                                        rs.armed_post = hit.post;
                                    }
                                } else if (field_ui.hitTest(cx, cy, g.hr.slice())) |_| {
                                    rs.armed_legacy = true;
                                    rs.armed_cx = cx;
                                    rs.armed_cy = cy;
                                }
                            }
                        }
                    },
                    // Release-activation: the armed tap fires here (see the
                    // button_down arm). Placed after the drag-drop handling so
                    // a drag never also triggers a tap.
                    .button_up => if (pev.button == 1) {
                        // The front door commits on release over the SAME target —
                        // the same release-activation the feed uses, so a press that
                        // slides off cancels rather than firing something else.
                        if (rs.gscreen == feed_view.screen_enroll) {
                            if (rs.genroll_armed) |at| {
                                if (enroll_view.hitTest(rs.genroll_hits.items, rx, ry)) |rel| if (rel == at) {
                                    if (at == .copy) enrollCopy(rs);
                                    enroll_run.apply(&rs.genroll_state, at, io, clock_shell.monotonicNanos(), &rs.genroll_mstore, &rs.genroll_memjob);
                                    // A STEP DOES NOT SUMMON THE KEYBOARD. `apply`
                                    // auto-focuses the first field when a step opens
                                    // — which is right with a mouse (the caret is
                                    // simply ready) and wrong with a thumb, where it
                                    // throws a keyboard over half the screen that
                                    // nobody asked for and cannot easily dismiss.
                                    // On a phone the keyboard comes up when, and only
                                    // when, a FIELD is tapped.
                                    if (rs.backend == .mobile and !isEnrollField(at)) rs.genroll_state.focus = .none;
                                    rs.caret_anchor_ns = clock_shell.monotonicNanos();
                                };
                            }
                            rs.genroll_armed = null;
                            continue;
                        }
                        // End a text-selection drag (the selection itself
                        // persists until the next press; a no-drag press left
                        // anchor==focus, i.e. an empty selection = cleared).
                        if (g.gpu) |gs| gs.sel_dragging = false;
                        // Finish any drag with a drop first (the press began it).
                        // A dragged BENCH card seats into the socket under the
                        // pointer (full sockets refuse; a mismatched declaration
                        // gets the heads-up); released elsewhere it fizzles.
                        if (rs.gbench_drag) |bdi| {
                            rs.gbench_drag = null;
                            benchDrop(rs, bdi, rx, ry);
                        }
                        if (rs.gscreen == feed_view.screen_loadout) {
                            if (rs.page_drag_surface) |s| {
                                // A tray card dropped on the LIBRARY column is
                                // removed from that surface (drag out = unequip;
                                // it stays in the library / the catalog).
                                const shelf_x = rs.page_geoms[0].x + rs.page_geoms[0].w + 40;
                                if (rs.page_geoms[0].w != 0 and rx >= shelf_x) {
                                    removeDraggedFromSurface(rs, s);
                                } else switch (s) {
                                    0 => pageDragDrop(rs.socket_cards, rs.socket_blob, &rs.gseated, &rs.gsocket_ui, rs.page_geoms[0], &rs.loadout_dirty),
                                    1 => pageDragDrop(rs.reply_cards, rs.reply_blob, &rs.reply_seated, &rs.reply_ui, rs.page_geoms[1], &rs.loadout_dirty),
                                    else => pageDragDrop(rs.zone_cards, rs.zone_blob, &rs.zone_seated, &rs.zone_ui, rs.page_geoms[2], &rs.loadout_dirty),
                                }
                            }
                        } else if (rs.gsocket_ui.drag_active) |d| {
                            const geom = feed_view.homeSocketGeom(if (rs.gpu_state) |*sgs| @as(i32, @intCast(sgs.design_w)) else @as(i32, @intCast(fb_w)));
                            const to: u32 = lens_socket.dropIndex(home_tray, rs.gsocket_ui, geom) orelse d;
                            const seated_off = if (rs.gseated < rs.socket_cards.len) rs.socket_cards[rs.gseated].cid.off else 0;
                            reorderTray(rs.socket_cards, d, to);
                            for (rs.socket_cards, 0..) |c, ix| {
                                if (c.cid.off == seated_off) {
                                    rs.gseated = @intCast(ix);
                                    break;
                                }
                            }
                            rs.gsocket_ui.drag_active = to; // the card now lives at `to`
                            rs.gsocket_ui.settle_phase = 1; // ghost eases from release point into its slot
                            rs.loadout_dirty = true;
                        }
                        // The zones search blurs when a tap lands anywhere but
                        // the field itself (the universal input-blur norm).
                        if (rs.gzones_q_focus and rs.gscreen == feed_view.screen_zones_browse) {
                            const over_search = if (feed_view.hitTest(g.regions.items, rx, ry)) |sh| (sh.kind == .zone_search or kbdRegion(sh.kind)) else false;
                            if (!over_search) rs.gzones_q_focus = false;
                        }
                        // The chat input blurs the same way: a tap anywhere off the
                        // composer strip (input / send / pay) drops focus — and with
                        // it the phone keyboard ("not being able to tap off the
                        // keyboard is driving me nuts", owner 2026-07-09).
                        if (rs.gchat_input_focus and rs.gscreen == feed_view.screen_messages) {
                            // The EDIT BAR's buttons keep focus: Copy/Cut/
                            // Paste/Select-all act ON the focused draft —
                            // blurring them closed the keyboard and made
                            // select-all → delete impossible (owner,
                            // 2026-07-12).
                            const over_composer = if (feed_view.hitTest(g.regions.items, rx, ry)) |sh|
                                (sh.kind == .chat_input or sh.kind == .chat_send or sh.kind == .pay_open or
                                    sh.kind == .chat_copy or sh.kind == .chat_cut or sh.kind == .chat_paste or
                                    sh.kind == .chat_selall or sh.kind == .chat_handle or kbdRegion(sh.kind))
                            else
                                false;
                            if (!over_composer) rs.gchat_input_focus = false;
                        }
                        if (rs.gchat_q_focus and rs.gscreen == feed_view.screen_messages) {
                            const over_q = if (feed_view.hitTest(g.regions.items, rx, ry)) |sh|
                                (sh.kind == .chat_search or kbdRegion(sh.kind))
                            else
                                false;
                            if (!over_q) rs.gchat_q_focus = false;
                        }
                        // Release-activation: fire the armed feed tap ONLY if the
                        // release lands on the same target the press armed. A press
                        // that began a drag never armed a tap, so a drag never also
                        // fires one.
                        if (rs.armed_kind) |ak| {
                            if (feed_view.hitTest(g.regions.items, rx, ry)) |hit| {
                                if (hit.kind == ak and hit.post == rs.armed_post) {
                                    // An open Repost/Quote menu is dismissed by any tap
                                    // outside its rows (and the repost button that toggles
                                    // it), and the tap is swallowed — the popover norm.
                                    if (rs.grepost_menu != null and hit.kind != .repost_do and hit.kind != .quote_new and hit.kind != .repost) {
                                        rs.grepost_menu = null;
                                    } else switch (hit.kind) {
                                        // Left-rail destination: switch the active screen
                                        // (post carries the Screen index). Selecting Profile
                                        // targets YOUR own profile; the next frame re-renders.
                                        .nav => {
                                            rs.gscreen = @intCast(hit.post);
                                            if (rs.gscreen == feed_view.screen_profile) {
                                                rs.profile_target_did = session.did;
                                                rs.profile_dirty = true;
                                            }
                                            if (rs.gscreen == feed_view.screen_wallet) {
                                                // Arrive at the page's RESTING face, never
                                                // mid-edit: the receive state is shared with
                                                // the chat modal, so a form left open there
                                                // would otherwise greet you here.
                                                rs.grecv_open = false;
                                                rs.grecv_mode = .onboard;
                                                rs.grecv_status = "";
                                                rs.grecv_saved = false;
                                                rs.grecv_focus = 0;
                                                rs.gwallet_remove_armed = false;
                                            }
                                            // Each screen starts at the top (scroll is shared).
                                            rs.gscroll_px = 0;
                                            // Navigating dismisses the phone drawer (it is a
                                            // nav surface; arriving somewhere closes it).
                                            if (rs.gpu_state) |*gsd| gsd.drawer_want = false;
                                        },
                                        // The phone drawer's scrim: tap-outside closes.
                                        .drawer_close => {
                                            if (rs.gpu_state) |*gsd| gsd.drawer_want = false;
                                        },
                                        // The mobile header hamburger: tap opens the nav
                                        // drawer (the swipe-right is the other way in).
                                        .drawer_open => {
                                            if (rs.gpu_state) |*gsd| gsd.drawer_want = true;
                                        },
                                        // The mobile header search magnifier. Interim: the
                                        // Zones hub IS the search surface (its "search or jump
                                        // to a tag" field) until a global search exists — land
                                        // there with the field focused.
                                        .search => {
                                            rs.gscreen = feed_view.screen_zones_browse;
                                            rs.gscroll_px = 0;
                                            rs.gzones_q_focus = true;
                                            if (rs.gpu_state) |*gsd| gsd.drawer_want = false;
                                        },
                                        // The bottom bar's tap-swallow: consume the tap so it
                                        // never falls through to a post behind the bar.
                                        .blocker => {},
                                        // Avatar tap → open THAT author's profile (any author;
                                        // the DID comes from the post's at-uri). A query over
                                        // the shared store — same engagement/identity truth.
                                        .author => if (hit.post < view_items.len) {
                                            const did = authorDidFromUri(view_items[hit.post].uri);
                                            if (did.len > 0 and did.len <= rs.profile_target_buf.len) {
                                                @memcpy(rs.profile_target_buf[0..did.len], did);
                                                rs.profile_target_did = rs.profile_target_buf[0..did.len];
                                                rs.gscreen = feed_view.screen_profile;
                                                rs.profile_dirty = true;
                                            }
                                        },
                                        // New-post button → the composer (cell path for now).
                                        // Fresh post: no reply target, no quote attached.
                                        .compose => {
                                            rs.reply_target = null;
                                            rs.reply_handle = "";
                                            rs.quote_target = null;
                                            rs.quoting_handle = "";
                                            rs.compose_kind = .post;
                                            tagBarReset(&rs.gtagbar);
                                            rs.mode = .compose;
                                        },
                                        // "Edit profile" → reuse the composer to set your
                                        // display name; prefill the current one (when it's a
                                        // real name, not the handle fallback). Saved via
                                        // putProfile on send (handleComposeInput).
                                        .edit_profile => {
                                            rs.compose_kind = .profile;
                                            textedit.clear(&rs.compose);
                                            if (profile_header) |ph| {
                                                const bare = if (ph.handle.len > 1) ph.handle[1..] else "";
                                                if (ph.display_name.len > 0 and !std.mem.eql(u8, ph.display_name, bare))
                                                    textedit.set(&rs.compose, ph.display_name);
                                            }
                                            tagBarReset(&rs.gtagbar);
                                            rs.mode = .compose;
                                            rs.status = "edit display name · Enter saves";
                                        },
                                        // Like / boost: the SAME path the keyboard uses —
                                        // optimistic toggle (heart fills red), persist via
                                        // the worker, and fire the splash + heart-pop.
                                        // Works in ANY view: engageSelected is CID-keyed on
                                        // the one shared store, so a like from the profile
                                        // updates the same record Home shows (ZONES inv. 4).
                                        .like => if (hit.post < view_items.len) {
                                            rs.state.selected = hit.post;
                                            const r = try engageSelected(.like, gpa, arena, session, store, view_items[hit.post], hit.post, rs.gscreen, rs.profile_target_did, rs.thread_focus_cid, rs.zone_tag, rs.thread_rerooted, rs.gcollapsed.items, feed_config, reply_config, &rs.state, rs.revealed.items, now, rs.out, &rs.prev, &rs.next, backend, pix, rs.writer, &rs.deferred_unlike, &rs.deferred_unrepost);
                                            if (r.status.len > 0) rs.status = r.status;
                                        },
                                        // Repost button → OPEN the Repost/Quote menu for
                                        // this post (a second tap closes it). The middle
                                        // action doubles as repost + quote (the universal
                                        // pattern); the choice is made in the menu below.
                                        .repost => if (hit.post < view_items.len) {
                                            rs.grepost_menu = if (rs.grepost_menu == @as(u16, @intCast(hit.post))) null else @intCast(hit.post);
                                        },
                                        // Menu "Repost" row → the optimistic repost toggle.
                                        .repost_do => if (hit.post < view_items.len) {
                                            rs.grepost_menu = null;
                                            rs.state.selected = hit.post;
                                            const r = try engageSelected(.repost, gpa, arena, session, store, view_items[hit.post], hit.post, rs.gscreen, rs.profile_target_did, rs.thread_focus_cid, rs.zone_tag, rs.thread_rerooted, rs.gcollapsed.items, feed_config, reply_config, &rs.state, rs.revealed.items, now, rs.out, &rs.prev, &rs.next, backend, pix, rs.writer, &rs.deferred_unlike, &rs.deferred_unrepost);
                                            if (r.status.len > 0) rs.status = r.status;
                                        },
                                        // Reply → open the premium composer in reply
                                        // mode for the TAPPED post (C2). Same sequence
                                        // the cell-path keyboard reply proved: resolve
                                        // the root/parent refs, copy them out of the
                                        // store (the composer outlives this frame), set
                                        // the target + handle, open compose.
                                        .reply => if (hit.post < view_items.len) {
                                            const item = view_items[hit.post];
                                            if (feed_core.replyRefsForCid(store, item.cid)) |refs| {
                                                _ = rs.compose_arena_state.reset(.retain_capacity);
                                                const compose_arena = rs.compose_arena_state.allocator();
                                                rs.reply_target = .{
                                                    .root_uri = try compose_arena.dupe(u8, refs.root_uri),
                                                    .root_cid = try compose_arena.dupe(u8, refs.root_cid),
                                                    .parent_uri = try compose_arena.dupe(u8, refs.parent_uri),
                                                    .parent_cid = try compose_arena.dupe(u8, refs.parent_cid),
                                                };
                                                rs.reply_handle = try compose_arena.dupe(u8, item.author_handle);
                                                // The arena reset above freed any prior quote
                                                // strings — drop the references with them.
                                                rs.quote_target = null;
                                                rs.quoting_handle = "";
                                                rs.compose_kind = .post;
                                                textedit.clear(&rs.compose);
                                                rs.status = "";
                                                tagBarReset(&rs.gtagbar);
                                                rs.mode = .compose;
                                            }
                                        },
                                        // Quote → open the composer with the tapped post
                                        // attached as the quote embed (attaches to the
                                        // first segment on send). Refs copied into the
                                        // compose arena (they outlive this frame).
                                        .quote_new => if (hit.post < view_items.len) {
                                            rs.grepost_menu = null;
                                            const item = view_items[hit.post];
                                            if (item.uri.len > 0 and item.cid.len > 0) {
                                                _ = rs.compose_arena_state.reset(.retain_capacity);
                                                const compose_arena = rs.compose_arena_state.allocator();
                                                rs.quote_target = .{
                                                    .uri = try compose_arena.dupe(u8, item.uri),
                                                    .cid = try compose_arena.dupe(u8, item.cid),
                                                };
                                                rs.quoting_handle = try compose_arena.dupe(u8, item.author_handle);
                                                rs.reply_target = null;
                                                rs.reply_handle = "";
                                                rs.compose_kind = .post;
                                                textedit.clear(&rs.compose);
                                                rs.status = "";
                                                tagBarReset(&rs.gtagbar);
                                                rs.mode = .compose;
                                            }
                                        },
                                        // Quote card tap → open the QUOTED post's thread
                                        // (its uri/cid ride the quoting item, resolved from
                                        // the store's quote_of edge). Mirrors .post_body.
                                        .quote_open => if (hit.post < view_items.len) {
                                            const item = view_items[hit.post];
                                            if (item.quote_cid.len > 0 and item.quote_cid.len <= rs.thread_focus_cid_buf.len and item.quote_uri.len <= rs.thread_focus_uri_buf.len) {
                                                @memcpy(rs.thread_focus_cid_buf[0..item.quote_cid.len], item.quote_cid);
                                                rs.thread_focus_cid = rs.thread_focus_cid_buf[0..item.quote_cid.len];
                                                @memcpy(rs.thread_focus_uri_buf[0..item.quote_uri.len], item.quote_uri);
                                                rs.thread_focus_uri = rs.thread_focus_uri_buf[0..item.quote_uri.len];
                                                const was_in_thread = rs.gscreen == feed_view.screen_thread;
                                                if (!was_in_thread) rs.thread_return_screen = rs.gscreen;
                                                rs.gscreen = feed_view.screen_thread;
                                                rs.thread_dirty = true;
                                                rs.thread_rerooted = was_in_thread;
                                                g.scroll.* = 0;
                                                if (g.gpu) |gs| {
                                                    gs.scroll_to_focus = true;
                                                    gs.sel_anchor = 0;
                                                    gs.sel_focus = 0;
                                                    gs.sel_dragging = false;
                                                }
                                            }
                                        },
                                        // Post body tap → open this post's THREAD
                                        // (whole post minus the avatar/engagement
                                        // carve-outs). Remember the focus cid (for
                                        // the buildThreadView query) + the uri (for
                                        // the getPostThread fetch) and where Back
                                        // returns. Copy them out — the view list is
                                        // rebuilt next frame.
                                        .post_body => if (hit.post < view_items.len) {
                                            const item = view_items[hit.post];
                                            if (item.cid.len > 0 and item.cid.len <= rs.thread_focus_cid_buf.len and item.uri.len <= rs.thread_focus_uri_buf.len) {
                                                @memcpy(rs.thread_focus_cid_buf[0..item.cid.len], item.cid);
                                                rs.thread_focus_cid = rs.thread_focus_cid_buf[0..item.cid.len];
                                                @memcpy(rs.thread_focus_uri_buf[0..item.uri.len], item.uri);
                                                rs.thread_focus_uri = rs.thread_focus_uri_buf[0..item.uri.len];
                                                const was_in_thread = rs.gscreen == feed_view.screen_thread;
                                                if (!was_in_thread) rs.thread_return_screen = rs.gscreen;
                                                rs.gscreen = feed_view.screen_thread;
                                                rs.thread_dirty = true;
                                                // First tap from the timeline = WHOLE thread; a tap
                                                // INSIDE the thread = RE-ROOT (condensed ancestors
                                                // above the focus). EITHER way, land ON the tapped
                                                // post (it's the new root) — ancestors sit above,
                                                // scrollable up — so a deep-chain tap doesn't dump
                                                // you at the top to scroll back down.
                                                rs.thread_rerooted = was_in_thread;
                                                g.scroll.* = 0;
                                                if (g.gpu) |gs| {
                                                    gs.scroll_to_focus = true;
                                                    // The rooted post (and so the
                                                    // selectable body) changed — drop any
                                                    // stale selection.
                                                    gs.sel_anchor = 0;
                                                    gs.sel_focus = 0;
                                                    gs.sel_dragging = false;
                                                }
                                            }
                                        },
                                        // Back (thread top bar) → the prior screen.
                                        .back => {
                                            // A money modal owns "back" while it is up.
                                            // This arm used to skip that check entirely:
                                            // it popped the conversation out from under
                                            // an open pay sheet, nulling `gchat_sel` —
                                            // and since every pay verb is guarded on
                                            // `gchat_sel`, the sheet stayed on screen
                                            // with every button silently dead. That is
                                            // the "back buttons don't work" bug.
                                            const modal_took_it = payModalOpen(rs);
                                            if (modal_took_it) {
                                                _ = payModalBack(rs);
                                            } else if (rs.gscreen == feed_view.screen_messages) {
                                                rs.gchat_sel = null; // phone chat thread → the list
                                            } else if (rs.gscreen == feed_view.screen_algo_docs) {
                                                rs.gscreen = rs.docs_return_screen;
                                                rs.gscroll_px = 0;
                                            } else if (rs.gscreen == feed_view.screen_algo_detail) {
                                                rs.gscreen = feed_view.screen_loadout; // back to the browse tab
                                                rs.gscroll_px = 0;
                                            } else if (rs.gscreen == feed_view.screen_transparency) {
                                                if (rs.gtransp_source) {
                                                    // On the source sub-view → back to the summary.
                                                    rs.gtransp_source = false;
                                                } else {
                                                    rs.gscreen = rs.transp_return_screen;
                                                    if (rs.inspect_bytes) |b| gpa.free(b);
                                                    rs.inspect_bytes = null;
                                                    if (rs.inspect_src) |b| gpa.free(b);
                                                    rs.inspect_src = null;
                                                }
                                            } else {
                                                rs.gscreen = if (rs.gscreen == feed_view.screen_zones) rs.zone_return_screen else rs.thread_return_screen;
                                            }
                                            // Only a real navigation resets the scroll —
                                            // stepping back inside a modal must leave the
                                            // conversation behind it exactly where it was.
                                            if (!modal_took_it) g.scroll.* = 0;
                                        },
                                        // "N new posts" pill → reveal the staged
                                        // posts + jump to the top (the reader opted
                                        // in, so displacing them now is wanted).
                                        .reveal_new => {
                                            _ = feed_core.revealPending(gpa, store) catch 0;
                                            g.scroll.* = 0;
                                            rs.gview.scroll_rows = 0;
                                            rs.state.selected = 0;
                                            rs.status = "";
                                        },
                                        // The composer's footer buttons never appear
                                        // on the timeline; they are handled in compose
                                        // mode below.
                                        .compose_send, .compose_cancel, .compose_add, .compose_remove => {},
                                        // Not wired yet — drawn for the fuller row /
                                        // profile tabs; their regions exist so hover
                                        // can highlight them and a later slice wires
                                        // them. A tap is a no-op for now.
                                        // Algorithms-page sub-tab (Loadout / Marketplace / Create).
                                        .loadout_tab => {
                                            rs.gloadout_tab = @intCast(hit.post);
                                            rs.gmarket_q_focus = false;
                                            rs.gpub_confirm = null;
                                            if (hit.post == 2) rs.gcreate_step = .landing; // Create opens on its landing page
                                            rs.gscroll_px = 0; // top of the newly-selected tab
                                        },
                                        // ---- The simple-Create flow (loadout tab 2) ----
                                        // Pick a question option → record the answer and rebuild
                                        // the config; the step's Continue button advances (so a
                                        // choice reads back before it commits).
                                        .create_pick => {
                                            create_flow.applyAnswer(&rs.gcreate_answers, rs.gcreate_step, hit.post);
                                            rs.gcreate_config = builder.build(rs.gcreate_answers);
                                        },
                                        .create_back => {
                                            rs.gcreate_step = create_flow.prevStep(rs.gcreate_step);
                                            if (rs.gcreate_step == .preparing) rs.gcreate_step = .privacy; // skip the beat going back
                                            rs.gscroll_px = 0;
                                        },
                                        .create_next => { // landing → questions → … (privacy → the preparing beat)
                                            rs.gcreate_step = create_flow.nextStep(rs.gcreate_step);
                                            if (rs.gcreate_step == .preparing) rs.gcreate_prepare_frames = 0; // start the beat
                                            rs.gscroll_px = 0;
                                        },
                                        .create_dev => { // the landing's second button → the dev flow
                                            rs.gdev_active = true;
                                            rs.gdev_step = .source;
                                            rs.gscroll_px = 0;
                                        },
                                        // ---- The developer submission flow (ALGO_SUBMISSION slice 1) ----
                                        .dev_template => {
                                            const ti: usize = hit.post;
                                            if (ti < zal_templates.all.len) {
                                                textedit.set(&rs.gdev_src, zal_templates.all[ti].source);
                                                devClearCheck(rs);
                                            }
                                        },
                                        .dev_src => { // click into the editor → place the caret
                                            const wdt: i32 = @intCast(if (rs.gpu_state) |*sgs| sgs.design_w else design_w);
                                            const off = feed_view.devSrcCaretAtPoint(g.engine, wdt, textedit.view(&rs.gdev_src), rs.gscroll_px, rx, ry);
                                            textedit.setCaret(&rs.gdev_src, off);
                                        },
                                        .dev_check => runDevCheck(rs),
                                        .dev_next => switch (rs.gdev_step) {
                                            .source => if (rs.gdev_check_ok) {
                                                rs.gdev_step = .details;
                                                rs.gscroll_px = 0;
                                            } else {
                                                rs.status = "Check must pass first — every refusal is named, fix what it says.";
                                            },
                                            .details => if (rs.gdev_name_len > 0) {
                                                rs.gdev_step = .review;
                                                rs.gscroll_px = 0;
                                            } else {
                                                rs.status = "Give it a name first.";
                                            },
                                            .review, .publishing => {},
                                            .done => { // "Done" → leave the flow, land on the loadout bench
                                                devReset(rs);
                                                rs.gloadout_tab = 0;
                                                rs.gscroll_px = 0;
                                            },
                                        },
                                        .dev_back => switch (rs.gdev_step) {
                                            .source => { // back to the Create landing
                                                devReset(rs);
                                                rs.gscroll_px = 0;
                                            },
                                            .details => {
                                                rs.gdev_step = .source;
                                                rs.gscroll_px = 0;
                                            },
                                            .review => {
                                                rs.gdev_step = .details;
                                                rs.gscroll_px = 0;
                                            },
                                            .publishing, .done => {},
                                        },
                                        .dev_field => rs.gdev_focus = @intCast(hit.post),
                                        .dev_surface => rs.gdev_designed ^= @as(u8, 1) << @intCast(hit.post),
                                        // ---- The bench drag + heads-up (slice 3, drag rework) ----
                                        .bench_seat => {}, // the PRESS starts the drag; a bare tap is a no-op
                                        .bench_confirm => if (rs.gbench_pick) |bi| {
                                            seatBenchAlgo(rs, @intCast(hit.post), bi);
                                            rs.gbench_pick = null;
                                            rs.gbench_warn = null;
                                        },
                                        .bench_cancel => {
                                            rs.gbench_pick = null;
                                            rs.gbench_warn = null;
                                        },
                                        // ---- The documentation pages (slice 5) ----
                                        .docs_user, .docs_dev => {
                                            rs.gdocs_kind = if (hit.kind == .docs_dev) 1 else 0;
                                            rs.docs_return_screen = rs.gscreen;
                                            rs.gscreen = feed_view.screen_algo_docs;
                                            rs.gscroll_px = 0;
                                        },
                                        // ---- The creator dashboard's retraction (two-tap) ----
                                        // The Published row's View → the algorithm's
                                        // marketplace page (the same destination a browse
                                        // card opens; payload is the LIBRARY index).
                                        .pub_view => {
                                            if (hit.post < rs.algo_lib.records.items.len) {
                                                const rec = rs.algo_lib.records.items[hit.post];
                                                const id = rs.algo_lib.slice(rec.id);
                                                var found: ?usize = null;
                                                for (rs.market_catalog.items, 0..) |mr, mi| {
                                                    if (std.mem.eql(u8, mr.cid, id)) {
                                                        found = mi;
                                                        break;
                                                    }
                                                }
                                                if (found) |mi| {
                                                    rs.gdetail_row = mi;
                                                    rs.gmarket_q_focus = false;
                                                    rs.gscreen = feed_view.screen_algo_detail;
                                                    rs.gscroll_px = 0;
                                                } else rs.status = "Still syncing — it opens once the marketplace lists it.";
                                            }
                                        },
                                        .pub_delete => {
                                            if (rs.gpub_confirm == null or rs.gpub_confirm.? != hit.post) {
                                                rs.gpub_confirm = @intCast(hit.post); // arm; the next tap fires
                                            } else if (hit.post < rs.algo_lib.records.items.len) {
                                                rs.gpub_confirm = null;
                                                const rec = rs.algo_lib.records.items[hit.post];
                                                const id = rs.algo_lib.slice(rec.id);
                                                // The record uri needs the rkey — carried by the
                                                // fetched marketplace row (mine included). Not yet
                                                // indexed ⇒ can't address it; be honest.
                                                var found: ?usize = null;
                                                for (rs.market_catalog.items, 0..) |mr, mi| {
                                                    if (std.mem.eql(u8, mr.cid, id)) {
                                                        found = mi;
                                                        break;
                                                    }
                                                }
                                                if (found) |mi| {
                                                    const mr = rs.market_catalog.items[mi];
                                                    var ub: [420]u8 = undefined;
                                                    const uri = std.fmt.bufPrint(&ub, "at://{s}/{s}/{s}", .{ mr.author_did, lexicon.collection.algorithm, mr.rkey }) catch "";
                                                    if (uri.len > 0) {
                                                        if (rs.writer) |w| {
                                                            if (write_worker.submit(w, .delete_algo, id, "", "", uri, now)) {
                                                                rs.status = "deleting...";
                                                            } else rs.status = "Couldn't queue the delete — try again.";
                                                        } else rs.status = "Deleting needs the online session.";
                                                    }
                                                } else rs.status = "Still syncing — the record isn't addressable yet; try shortly.";
                                            } else rs.gpub_confirm = null;
                                        },
                                        .dev_color => rs.gdev_color = @intCast(hit.post),
                                        .dev_publish => {
                                            if (rs.gdev_config.len == 0 or !rs.gdev_check_ok) {
                                                rs.status = "Run Check first.";
                                            } else if (rs.writer) |w| {
                                                // rkey: a name slug + the local uid — readable in the
                                                // repo, unique per publish (an edited resubmit gets a
                                                // fresh record, never a silent overwrite).
                                                var slug: [32]u8 = undefined;
                                                var sn: usize = 0;
                                                for (rs.gdev_name_buf[0..rs.gdev_name_len]) |ch| {
                                                    if (sn >= 24) break;
                                                    const lc = std.ascii.toLower(ch);
                                                    if (std.ascii.isAlphanumeric(lc)) {
                                                        slug[sn] = lc;
                                                        sn += 1;
                                                    } else if (sn > 0 and slug[sn - 1] != '-') {
                                                        slug[sn] = '-';
                                                        sn += 1;
                                                    }
                                                }
                                                if (sn == 0) {
                                                    slug[0] = 'a';
                                                    sn = 1;
                                                }
                                                var rkb: [48]u8 = undefined;
                                                const rkey = std.fmt.bufPrint(&rkb, "{s}-{d}", .{ slug[0..sn], rs.algo_uid }) catch "algo";
                                                var idb: [24]u8 = undefined;
                                                const local_id = std.fmt.bufPrint(&idb, "user:{d}", .{rs.algo_uid}) catch "user:x";
                                                if (write_worker.submitPublishAlgo(w, .{
                                                    .local_id = local_id,
                                                    .name = rs.gdev_name_buf[0..rs.gdev_name_len],
                                                    .config = rs.gdev_config,
                                                    .rkey = rkey,
                                                    .ranks = rs.gdev_ranks_buf[0..rs.gdev_ranks_len],
                                                    .desc = rs.gdev_desc_buf[0..rs.gdev_desc_len],
                                                    .source = textedit.view(&rs.gdev_src),
                                                    .tags_csv = rs.gdev_tags_buf[0..rs.gdev_tags_len],
                                                    .designed = rs.gdev_designed,
                                                }, now)) {
                                                    rs.gdev_step = .publishing;
                                                    rs.gscroll_px = 0;
                                                } else rs.status = "Couldn't queue the publish — out of memory.";
                                            } else rs.status = "Publishing needs the online session.";
                                        },
                                        .create_knob_dec, .create_knob_inc => {
                                            const k: create_flow.Knob = @enumFromInt(@as(u8, @intCast(hit.post)));
                                            const step = create_flow.knobMeta(k).step;
                                            const cur = create_flow.knobValue(rs.gcreate_config, k);
                                            create_flow.knobSet(&rs.gcreate_config, k, if (hit.kind == .create_knob_inc) cur + step else cur - step);
                                        },
                                        .create_color => rs.gcreate_color = @intCast(hit.post),
                                        // Finalize: serialize the config into a PRIVATE library
                                        // record (a minted local id), reset the flow, and drop
                                        // the user back on their loadout with it saved.
                                        .create_save => {
                                            var idbuf: [24]u8 = undefined;
                                            const id = std.fmt.bufPrint(&idbuf, "user:{d}", .{rs.algo_uid}) catch "user:x";
                                            const nm = if (rs.gcreate_name_len > 0) rs.gcreate_name_buf[0..rs.gcreate_name_len] else "My feed";
                                            if (create_flow.finalize(arena, rs.gcreate_config, id, nm, rs.gcreate_color)) |new| {
                                                if (rs.algo_lib.add(gpa, new)) |_| {
                                                    rs.algo_uid += 1;
                                                    _ = cache_shell.saveLibrary(gpa, environ, &rs.algo_lib); // persist across launches
                                                    rs.status = "Saved to your library.";
                                                    rs.gcreate_step = .pace;
                                                    rs.gcreate_answers = .{};
                                                    rs.gcreate_config = builder.build(.{});
                                                    rs.gcreate_name_len = 0;
                                                    rs.gcreate_color = 0;
                                                    rs.gloadout_tab = 0;
                                                    rs.gscroll_px = 0;
                                                } else |_| rs.status = "Couldn't save — out of memory.";
                                            } else |_| rs.status = "Couldn't build that feed.";
                                        },
                                        // Reddit-style collapse: toggle this reply's CID in the
                                        // per-view collapsed set (no network — buildThreadView
                                        // re-derives the view next frame; ZONES inv. 4).
                                        .collapse => if (hit.post < view_items.len) {
                                            const cid = view_items[hit.post].cid;
                                            var found: ?usize = null;
                                            for (rs.gcollapsed.items, 0..) |c, ix| if (std.mem.eql(u8, c, cid)) {
                                                found = ix;
                                                break;
                                            };
                                            if (found) |ix| {
                                                gpa.free(rs.gcollapsed.items[ix]);
                                                _ = rs.gcollapsed.swapRemove(ix);
                                            } else if (gpa.dupe(u8, cid)) |d| {
                                                rs.gcollapsed.append(gpa, d) catch gpa.free(d);
                                            } else |_| {}
                                        },
                                        // Main-feed Read-more: toggle this post's CID in the
                                        // per-view expanded set (no network — fromTimeline stamps
                                        // PostView.expanded next frame, and the height cache is
                                        // invalidated because the expanded set feeds the content
                                        // signature; ZONES inv. 4).
                                        .expand => if (hit.post < view_items.len) {
                                            const cid = view_items[hit.post].cid;
                                            var found: ?usize = null;
                                            for (rs.gexpanded.items, 0..) |c, ix| if (std.mem.eql(u8, c, cid)) {
                                                found = ix;
                                                break;
                                            };
                                            if (found) |ix| {
                                                gpa.free(rs.gexpanded.items[ix]);
                                                _ = rs.gexpanded.swapRemove(ix);
                                            } else if (gpa.dupe(u8, cid)) |d| {
                                                rs.gexpanded.append(gpa, d) catch gpa.free(d);
                                            } else |_| {}
                                        },
                                        .bookmark, .share, .more, .profile_tab => {},
                                        // Composer-only regions never exist on the timeline.
                                        .compose_tag_add, .compose_tag_remove => {},
                                        // Zat Chat (U3): open the tapped conversation. The
                                        // region carries the LIST ORDINAL; map it back through
                                        // the same ordering query the list was built from (no
                                        // store index rides a region, A5).
                                        .chat_conv => if (dev_chat) {
                                            // The ordinal is in FILTERED space when a list
                                            // search is live — map it through the same
                                            // predicate the render used (chatConvAt).
                                            const cq = rs.gchat_q_buf[0..rs.gchat_q_len];
                                            if (chatConvAt(arena, &rs.gchat_store, now, cq, hit.post)) |conv| {
                                                rs.gchat_sel = conv;
                                                chat_core.markRead(&rs.gchat_store, conv);
                                                // M2: read-state survives a relaunch too.
                                                chatPersistHistory(gpa, io, environ, if (rs.gchat_e2ee) |*p| p else null, &rs.gchat_store);
                                                rs.gchat_input_focus = true;
                                                rs.gchat_q_focus = false; // opening a thread leaves the search
                                                rs.gchat_composing = false; // a row tap leaves the compose flow
                                                rs.gpay_open = false; // the sheet belongs to one conversation
                                                rs.gscroll_px = 0; // newest, bottom-anchored
                                            }
                                        },
                                        // The chat list search field: tap → it owns the keyboard.
                                        .chat_search => if (dev_chat) {
                                            rs.gchat_q_focus = true;
                                        },
                                        // The Zat4 keyboard: a key tap queues its UTF-8 bytes
                                        // for the next frame's input stream — the SAME stream
                                        // the system IME feeds, so every consumer (drafts,
                                        // searches, the composer) works unchanged. Shift is
                                        // one-shot, like a phone.
                                        // The Zat4 keyboard (desktop mouse path;
                                        // phone keys commit at touch-DOWN in the
                                        // pump and never reach this tap).
                                        .kbd_key, .kbd_shift, .kbd_page, .kbd_backspace, .kbd_emoji, .kbd_nav, .kbd_cat => kbdAction(rs, gpa, hit.kind, hit.post),
                                        .chat_input => if (dev_chat) {
                                            rs.gchat_input_focus = true;
                                            rs.gchat_composing = false;
                                            rs.gchat_caret = rs.gchat_draft_len;
                                            chatCollapseSel(rs);
                                        },
                                        // The edit bar (long-press summons it).
                                        .chat_copy, .chat_cut => if (dev_chat) {
                                            const ca = @min(rs.gchat_sel_a, rs.gchat_draft_len);
                                            const cb = @min(rs.gchat_sel_b, rs.gchat_draft_len);
                                            if (cb > ca) {
                                                const t = rs.gchat_draft_buf[ca..cb];
                                                switch (backend) {
                                                    .window => |w| window_shell.setClipboard(w, t),
                                                    else => {},
                                                }
                                                const cn = @min(t.len, rs.clip_out_buf.len);
                                                @memcpy(rs.clip_out_buf[0..cn], t[0..cn]);
                                                rs.clip_out_len = cn;
                                                if (hit.kind == .chat_cut) _ = chatDeleteSelection(rs);
                                                rs.gchat_edit_bar = false;
                                                rs.kbd_dirty = true;
                                                rs.status = if (hit.kind == .chat_cut) "cut" else "copied";
                                            }
                                        },
                                        .chat_paste => if (dev_chat) {
                                            // The OS clipboard arrives via the
                                            // seam next lap (clip_in drain).
                                            rs.clip_want = true;
                                            rs.gchat_edit_bar = false;
                                        },
                                        .chat_selall => if (dev_chat) {
                                            rs.gchat_sel_a = 0;
                                            rs.gchat_sel_b = rs.gchat_draft_len;
                                            rs.gchat_caret = rs.gchat_draft_len;
                                            rs.kbd_dirty = true;
                                        },
                                        // "+ New": open (or close) the recipient bar; it owns
                                        // the keyboard while open. Tapping the bar itself is
                                        // inert — being open IS its focus state.
                                        .chat_new => if (dev_chat) {
                                            rs.gchat_composing = !rs.gchat_composing;
                                            rs.gchat_peer_len = 0;
                                            rs.gchat_compose_status = "";
                                            rs.gchat_input_focus = false;
                                        },
                                        .chat_compose_input => {},
                                        // Handles act by DRAG (the pump owns
                                        // them); a stationary tap is inert.
                                        .chat_handle => {},
                                        // Repair a conversation whose two halves have
                                        // drifted apart (see chatRestart).
                                        .chat_restart => if (dev_chat) {
                                            if (rs.gchat_sel) |sc| chatRestart(rs, gpa, io, environ, sc);
                                        },
                                        // A3: the user has read what it costs and
                                        // chosen to make THIS device the one that owns
                                        // chat for the account. Only now do we replace
                                        // the published key — never on our own.
                                        .chat_identity_reset => if (dev_chat) {
                                            chatLog("[chat] A3: user chose to set chat up fresh on this device (replacing the published key)", .{});
                                            chatBringUp(rs, gpa, io, environ, session, true);
                                            rs.status = if (rs.gchat_identity_elsewhere)
                                                "chat: couldn't set up on this device — try again"
                                            else
                                                "chat: set up on this device";
                                        },
                                        // ── MULTI-DEVICE: the two taps, and the two
                                        // ways out of them. Every one of these is a
                                        // network round-trip, so every one of them
                                        // goes to a worker and the UI says so.
                                        .chat_device_add => if (dev_chat) {
                                            rs.gdev_error = "";
                                            startDeviceJob(rs, gpa, io, environ, session, .ask);
                                        },
                                        .chat_device_approve => if (dev_chat) {
                                            rs.gdev_error = "";
                                            startDeviceJob(rs, gpa, io, environ, session, .approve);
                                        },
                                        .chat_device_refuse => if (dev_chat) {
                                            rs.gdev_error = "";
                                            startDeviceJob(rs, gpa, io, environ, session, .refuse);
                                        },
                                        .chat_history_get => if (dev_chat) {
                                            if (rs.gchat_e2ee) |*st| if (rs.gchat_link) |l| {
                                                rs.gdev_hist_state = .asking;
                                                chat_e2ee.requestHistory(gpa, io, environ, st, l) catch |err| {
                                                    chatLog("[chat] history request failed: {s}", .{@errorName(err)});
                                                    rs.gdev_hist_state = .none;
                                                };
                                            };
                                        },
                                        // The one-time setup (slice 1). The switches
                                        // are local until Start chatting — nothing is
                                        // persisted, and nothing is emitted, until the
                                        // person has actually said so.
                                        .chat_consent_receipts => rs.gchat_receipts = !rs.gchat_receipts,
                                        .chat_consent_typing => rs.gchat_typing_on = !rs.gchat_typing_on,
                                        .chat_consent_done => {
                                            rs.gchat_asked = true;
                                            rs.gchat_consent_open = false;
                                            chatPrefsSave(rs, environ, session.did);
                                            chatLog("[chat] privacy setup: receipts={} typing={}", .{ rs.gchat_receipts, rs.gchat_typing_on });
                                        },
                                        .chat_device_help => rs.gdev_help = true,
                                        .chat_help_close => rs.gdev_help = false,
                                        .chat_send => if (dev_chat) {
                                            const body = std.mem.trimEnd(u8, rs.gchat_draft_buf[0..rs.gchat_draft_len], " \n");
                                            if (body.len > 0) if (rs.gchat_sel) |sc| {
                                                _ = chat_core.appendMessage(gpa, &rs.gchat_store, sc, .text, body, now, true) catch {};
                                                chatSend(gpa, io, environ, if (rs.gchat_e2ee) |*st| st else null, rs.gchat_link, &rs.gchat_store, sc, body);
                                                chatPersistHistory(gpa, io, environ, if (rs.gchat_e2ee) |*p| p else null, &rs.gchat_store);
                                                rs.gchat_draft_len = 0;
                            rs.gchat_caret = 0;
                            chatCollapseSel(rs);
                                                rs.gchat_caret = 0;
                                                rs.gchat_input_focus = true;
                                                rs.gscroll_px = 0;
                                            };
                                        },
                                        // The pay sheet (M5 A4): the button toggles it;
                                        // it owns the keyboard while open.
                                        .pay_open => if (dev_chat) {
                                            // Learn (once) whether payments are set up.
                                            if (!rs.grecv_known) {
                                                rs.grecv_known = true;
                                                _ = rs.gchat_arena_state.reset(.retain_capacity);
                                                rs.grecv_set = loadOwnReceive(gpa, rs.gchat_arena_state.allocator(), io, environ, session, &rs.grecv_ln_buf, &rs.grecv_ln_len, &rs.grecv_btc_buf, &rs.grecv_btc_len);
                                            }
                                            rs.gchat_input_focus = false;
                                            rs.gchat_composing = false;
                                            if (rs.grecv_set) {
                                                // Set up → the pay sheet (request/send).
                                                rs.gpay_open = !rs.gpay_open;
                                                rs.gpay_status = "";
                                                rs.gpay_focus = 0;
                                                rs.gpay_step = .compose;
                                                rs.grecv_open = false;
                                            } else {
                                                // Not set up → onboard, never a dead form.
                                                rs.grecv_open = true;
                                                rs.grecv_mode = .onboard;
                                                rs.grecv_status = "";
                                                rs.gpay_open = false;
                                            }
                                        },
                                        .pay_rail => if (dev_chat) {
                                            rs.gpay_rail = if (hit.post == 1) .onchain else .lightning;
                                        },
                                        .pay_chip => if (dev_chat) {
                                            if (hit.post < feed_view.pay_chips.len) {
                                                var ab: [16]u8 = undefined;
                                                const s = std.fmt.bufPrint(&ab, "{d}", .{feed_view.pay_chips[hit.post]}) catch "";
                                                if (s.len <= rs.gpay_amount_buf.len) {
                                                    @memcpy(rs.gpay_amount_buf[0..s.len], s);
                                                    rs.gpay_amount_len = s.len;
                                                }
                                                rs.gpay_unit = .sats; // the chips are sats amounts
                                                rs.gpay_focus = 0;
                                            }
                                        },
                                        .pay_amount => if (dev_chat) {
                                            rs.gpay_focus = 0;
                                        },
                                        .pay_note => if (dev_chat) {
                                            rs.gpay_focus = 1;
                                        },
                                        // Toggle the entry unit; clear the draft (a
                                        // sats integer isn't a BTC decimal) so nothing
                                        // is silently reinterpreted by 1e8.
                                        .pay_unit => if (dev_chat) {
                                            rs.gpay_unit = if (rs.gpay_unit == .sats) .btc else .sats;
                                            rs.gpay_amount_len = 0;
                                            rs.gpay_focus = 0;
                                            rs.gpay_status = "";
                                        },
                                        .pay_cancel => if (dev_chat) closePaySheet(rs),
                                        // The pay sheet's "Set up how you get
                                        // paid" link AND an incoming offer card's
                                        // "Set up wallet to accept" both open the
                                        // receive onboarding (S2, PAYMENT_UX_SPEC
                                        // §4.1). On save, `announceReceiveReady`
                                        // flips the offer to ready + signals the
                                        // payer — so the tap just opens the sheet.
                                        .recv_open, .pay_card_setup => if (dev_chat) {
                                            if (!rs.grecv_known) {
                                                rs.grecv_known = true;
                                                _ = rs.gchat_arena_state.reset(.retain_capacity);
                                                rs.grecv_set = loadOwnReceive(gpa, rs.gchat_arena_state.allocator(), io, environ, session, &rs.grecv_ln_buf, &rs.grecv_ln_len, &rs.grecv_btc_buf, &rs.grecv_btc_len);
                                            }
                                            rs.grecv_open = true;
                                            rs.gpay_open = false;
                                            rs.grecv_status = "";
                                            rs.grecv_saved = false;
                                            rs.grecv_focus = 0;
                                            rs.grecv_mode = if (rs.grecv_set) .paste else .onboard;
                                            rs.gchat_input_focus = false;
                                            rs.gchat_composing = false;
                                        },
                                        .recv_have => if (dev_chat) {
                                            rs.grecv_mode = .paste;
                                            rs.grecv_focus = 0;
                                            rs.grecv_status = "";
                                        },
                                        .recv_need => if (dev_chat) {
                                            rs.grecv_mode = .wallets;
                                            rs.grecv_status = "";
                                        },
                                        .recv_wallet => if (dev_chat) {
                                            // Open the wallet's own site; you get an address there,
                                            // then come back and paste it. No return channel needed.
                                            if (hit.post < feed_view.recv_wallets.len) {
                                                // The phone has no xdg-open: this takes
                                                // the seam's ACTION_VIEW road instead.
                                                if (!openUri(rs, io, feed_view.recv_wallets[hit.post].url))
                                                    rs.grecv_status = "Couldn't open that wallet's page";
                                            }
                                        },
                                        .recv_paste => if (dev_chat) {
                                            rs.grecv_mode = .paste;
                                            rs.grecv_focus = 0;
                                            rs.grecv_status = "";
                                        },
                                        // A wallet address is a string nobody types by
                                        // hand — you copy it out of your wallet's app.
                                        // The phone has no Ctrl+V, so without this the
                                        // only way in was to retype it off another
                                        // screen. The clipboard arrives next lap.
                                        .recv_clip => if (dev_chat) {
                                            rs.clip_want = true;
                                            rs.grecv_focus = 0; // the lightning field is what it fills
                                        },
                                        // ONE step back. `recvBackEdge` is the only
                                        // place that answers "what is behind this
                                        // face?", so the Back button, Escape, the
                                        // chevron and a scrim tap can never disagree
                                        // — they used to, and Cancel on the wallet
                                        // picker dismissed the whole flow instead of
                                        // returning to the branch it came from.
                                        .recv_back => if (dev_chat) {
                                            if (rs.gscreen == feed_view.screen_wallet) {
                                                // The page's own root is the resting
                                                // face; back never leaves the page.
                                                rs.grecv_mode = .onboard;
                                                rs.grecv_focus = 0;
                                                rs.grecv_status = "";
                                            } else if (feed_view.recvBackEdge(rs.grecv_mode, rs.grecv_set)) |prev| {
                                                rs.grecv_mode = prev;
                                                rs.grecv_focus = 0;
                                                rs.grecv_status = "";
                                            } else {
                                                closeRecvSheet(rs);
                                            }
                                        },
                                        .recv_ln => if (dev_chat) {
                                            rs.grecv_focus = 0;
                                        },
                                        .recv_btc => if (dev_chat) {
                                            rs.grecv_focus = 1;
                                        },
                                        // On the Wallet PAGE there is no modal to
                                        // close — "Cancel"/"Done" returns to the
                                        // page's resting face instead of trying to
                                        // dismiss a sheet that isn't there.
                                        .recv_cancel => if (dev_chat) {
                                            if (rs.gscreen == feed_view.screen_wallet) {
                                                rs.grecv_mode = .onboard;
                                                rs.grecv_status = "";
                                                rs.gwallet_remove_armed = false;
                                            } else closeRecvSheet(rs);
                                        },
                                        // SAVE no longer publishes. It ASKS the wallet
                                        // what it can do, off-thread, and routes to the
                                        // capability review. The old path published a
                                        // string it had never once tried to use and told
                                        // the user their wallet was good — which is how
                                        // `connor@strike.me` (an address belonging to
                                        // nobody) sailed through.
                                        .recv_save => if (dev_chat) {
                                            const ln = std.mem.trim(u8, rs.grecv_ln_buf[0..rs.grecv_ln_len], " ");
                                            if (ln.len == 0) {
                                                // No Lightning address to interrogate: an
                                                // on-chain-only setup publishes directly.
                                                // (On-chain needs no probe — the chain
                                                // watcher already confirms it, always.)
                                                rs.grecv_status = spawnPublish(rs, io, environ, session);
                                            } else {
                                                rs.grecv_status = spawnWalletProbe(rs, io, environ, ln);
                                                if (rs.grecv_status.len == 0) rs.grecv_probing = true;
                                            }
                                        },
                                        // The sign-off: the user has SEEN what this wallet
                                        // will and won't do, and accepts it. Only now do we
                                        // publish.
                                        .recv_use => if (dev_chat) {
                                            // Off the render thread. The drain below flips
                                            // the face when the PDS answers.
                                            rs.grecv_status = spawnPublish(rs, io, environ, session);
                                        },
                                        // Remove wallet: unpublish the record (walletless
                                        // again) and clear the fields — one tap, not
                                        // delete-every-char-then-Cancel.
                                        .recv_remove => if (dev_chat) {
                                            // On the Wallet page Remove is a TWO-TAP:
                                            // unpublishing makes you unpayable and
                                            // would strand anyone mid-send to you, so
                                            // the first tap only arms it. (The sheet's
                                            // quiet "Remove wallet" link keeps its
                                            // single tap — it is already a deliberate
                                            // reach.)
                                            if (rs.gscreen == feed_view.screen_wallet and !rs.gwallet_remove_armed) {
                                                rs.gwallet_remove_armed = true;
                                                rs.grecv_status = "";
                                            } else {
                                                rs.gwallet_remove_armed = false;
                                                _ = rs.gchat_arena_state.reset(.retain_capacity);
                                                if (pay_addr.unpublish(gpa, rs.gchat_arena_state.allocator(), io, environ, session)) |_| {
                                                    rs.grecv_ln_len = 0;
                                                    rs.grecv_btc_len = 0;
                                                    rs.grecv_set = false;
                                                    rs.grecv_saved = false;
                                                    rs.grecv_focus = 0;
                                                    rs.grecv_status = "Removed \u{2014} you no longer receive payments here";
                                                } else |_| {
                                                    rs.grecv_status = "Couldn't remove it \u{2014} try again";
                                                }
                                            }
                                        },
                                        // Compose "Send": run the per-action gate
                                        // (§5). A walletless recipient → an OFFER
                                        // straight away (no wallet to approve, so no
                                        // "open wallet" confirm — the old lie). A
                                        // set-up recipient → ARM the confirm face,
                                        // whose Confirm is the real hand-off
                                        // (.pay_send). A refusal lands on the sheet.
                                        // Send: resolve the peer OFF-THREAD, then either
                                        // arm the confirm face or make a walletless
                                        // OFFER. The resolve used to run inline on this
                                        // click — a PDS round-trip on the render thread.
                                        .pay_arm => if (dev_chat) {
                                            if (rs.gchat_sel) |sc| {
                                                const amount = feed_view.payAmountToSats(rs.gpay_amount_buf[0..rs.gpay_amount_len], rs.gpay_unit) orelse 0;
                                                if (amount == 0 or amount > chat_core.max_amount_sat) {
                                                    rs.gpay_status = "Enter an amount in sats";
                                                } else {
                                                    const note = std.mem.trim(u8, rs.gpay_note_buf[0..rs.gpay_note_len], " ");
                                                    rs.gpay_status = paySpawn(rs, io, environ, sc, .gate, rs.gpay_rail, amount, note, true, null);
                                                    if (rs.gpay_status.len == 0) rs.gpay_busy = true;
                                                }
                                            }
                                        },
                                        .pay_confirm_back => if (dev_chat) {
                                            rs.gpay_step = .compose;
                                        },
                                        .pay_request, .pay_send => if (dev_chat) {
                                            if (rs.gchat_sel) |sc| {
                                                const amount = feed_view.payAmountToSats(rs.gpay_amount_buf[0..rs.gpay_amount_len], rs.gpay_unit) orelse 0;
                                                if (amount == 0 or amount > chat_core.max_amount_sat) {
                                                    rs.gpay_status = "Enter an amount in sats";
                                                } else {
                                                    const note = std.mem.trim(u8, rs.gpay_note_buf[0..rs.gpay_note_len], " ");
                                                    if (hit.kind == .pay_request) {
                                                        // Request gate (§5): you can only ASK to be
                                                        // paid on a rail you can actually RECEIVE on
                                                        // — otherwise the money would have nowhere to
                                                        // land. Your own published addresses are
                                                        // already loaded (grecv_*).
                                                        const have_rail = switch (rs.gpay_rail) {
                                                            .lightning => rs.grecv_ln_len > 0,
                                                            .onchain => rs.grecv_btc_len > 0,
                                                        };
                                                        if (!have_rail) {
                                                            rs.gpay_status = switch (rs.gpay_rail) {
                                                                .lightning => "Add your Lightning address first \u{2014} tap \u{201C}Set up how you get paid\u{201D}",
                                                                .onchain => "Add your Bitcoin address first \u{2014} tap \u{201C}Set up how you get paid\u{201D}",
                                                            };
                                                        } else {
                                                            rs.gpay_status = payRequest(gpa, io, environ, if (rs.gchat_e2ee) |*p| p else null, rs.gchat_link, &rs.gchat_store, sc, rs.gpay_rail, amount, note, now);
                                                        }
                                                    } else {
                                                        // The real hand-off. The address resolve and the
                                                        // LNURL invoice fetch go to the worker; the sheet
                                                        // stays up showing "Preparing…" and the wallet
                                                        // opens from the DRAIN. The alternative — what
                                                        // this used to do — was to freeze the app mid-tap
                                                        // on a slow network, at the exact moment a user
                                                        // is deciding whether to trust it with money.
                                                        rs.gpay_status = paySpawn(rs, io, environ, sc, .hand_off, rs.gpay_rail, amount, note, true, null);
                                                        if (rs.gpay_status.len == 0) rs.gpay_busy = true;
                                                    }
                                                    // A REQUEST moves no money and needs no network
                                                    // resolution, so it still completes on the spot.
                                                    // A SEND is now in flight — the drain closes the
                                                    // sheet when the wallet actually opens.
                                                    if (hit.kind == .pay_request and rs.gpay_status.len == 0) {
                                                        rs.gpay_open = false;
                                                        rs.gpay_step = .compose;
                                                        rs.gpay_amount_len = 0;
                                                        rs.gpay_note_len = 0;
                                                        rs.gscroll_px = 0;
                                                    }
                                                }
                                            }
                                        },
                                        // A request card's Pay: the card's own rail,
                                        // amount, and id drive the same send leg the
                                        // sheet uses. Refusals land on the app status
                                        // line (the sheet may be closed).
                                        .pay_card_pay => if (dev_chat) {
                                            if (rs.gchat_sel) |sc| {
                                                if (payRowByOrdinal(gpa, &rs.gchat_store, sc, hit.post)) |row| {
                                                    const verdict = paySpawn(rs, io, environ, sc, .hand_off, row.rail, row.amount_sat, "", false, row.payment_id);
                                                    rs.status = if (verdict.len == 0) "pay: preparing the hand-off\u{2026}" else verdict;
                                                    if (verdict.len == 0) rs.gpay_busy = true;
                                                }
                                            }
                                        },
                                        .pay_card_received => if (dev_chat) {
                                            if (rs.gchat_sel) |sc| {
                                                if (payRowByOrdinal(gpa, &rs.gchat_store, sc, hit.post)) |row| {
                                                    payCardEvent(gpa, io, environ, if (rs.gchat_e2ee) |*p| p else null, rs.gchat_link, &rs.gchat_store, sc, row.payment_id, true);
                                                }
                                            }
                                        },
                                        // Withdraw an offer/send (→ cancelled) or
                                        // turn down an incoming offer (→ declined):
                                        // both flip BOTH sides and move no money
                                        // (S2). Each terminal names itself (§8.5).
                                        .pay_card_cancel, .pay_card_decline => if (dev_chat) {
                                            if (rs.gchat_sel) |sc| {
                                                if (payRowByOrdinal(gpa, &rs.gchat_store, sc, hit.post)) |row| {
                                                    const decline = hit.kind == .pay_card_decline;
                                                    payCardSignal(
                                                        gpa,
                                                        io,
                                                        environ,
                                                        if (rs.gchat_e2ee) |*p| p else null,
                                                        rs.gchat_link,
                                                        &rs.gchat_store,
                                                        sc,
                                                        row.payment_id,
                                                        if (decline) .declined else .cancelled,
                                                        if (decline) chat_core.kind_pay_decline_wire else chat_core.kind_pay_cancel_wire,
                                                    );
                                                }
                                            }
                                        },
                                        // A `ready` offer card's Send: the peer
                                        // set up a wallet, so the standard send leg
                                        // now resolves — re-confirm has already
                                        // happened at the card (money-critical, so
                                        // the hand-off is a deliberate tap).
                                        .pay_card_send => if (dev_chat) {
                                            if (rs.gchat_sel) |sc| {
                                                if (payRowByOrdinal(gpa, &rs.gchat_store, sc, hit.post)) |row| {
                                                    const verdict = paySpawn(rs, io, environ, sc, .hand_off, row.rail, row.amount_sat, "", false, row.payment_id);
                                                    rs.status = if (verdict.len == 0) "pay: preparing the hand-off\u{2026}" else verdict;
                                                    if (verdict.len == 0) rs.gpay_busy = true;
                                                }
                                            }
                                        },
                                        // Tag pill (tray) OR an inline `#tag` in the prose →
                                        // ENTER its zone. Both regions carry the post index in
                                        // `post` and the tag's index in `_pad`; resolve the
                                        // display tag, open the zone page, and let the
                                        // fetch-on-enter pull the zone feed (buildTagView).
                                        .zone_jump, .tag_inline => if (hit.post < view_items.len) {
                                            const tags = view_items[hit.post].tags;
                                            if (hit._pad < tags.len) {
                                                const t = tags[hit._pad];
                                                if (t.len > 0 and t.len <= rs.zone_tag_buf.len) {
                                                    // Zones are canonical lowercase (invariant 1):
                                                    // fold the tapped tag so #Foo opens zone "foo".
                                                    for (t, 0..) |c, i| rs.zone_tag_buf[i] = std.ascii.toLower(c);
                                                    // Back returns to where we came FROM (don't
                                                    // overwrite it on a zone→zone hop).
                                                    if (rs.gscreen != feed_view.screen_zones) rs.zone_return_screen = rs.gscreen;
                                                    rs.zone_tag = rs.zone_tag_buf[0..t.len];
                                                    rs.gscreen = feed_view.screen_zones;
                                                    rs.zone_dirty = true;
                                                    rs.gscroll_px = 0;
                                                    rs.gsocket_ui.open = false; // tuck the home socket
                                                }
                                            }
                                        },
                                        // Zone card (browse grid) → ENTER its zone. The
                                        // region carries the catalog index in `post`; resolve
                                        // its display tag and open the zone page (the
                                        // fetch-on-enter pulls the feed, like a tag pill).
                                        .zone_open => if (hit.post < rs.zone_catalog.items.len) {
                                            const t = rs.zone_catalog.items[hit.post].tag;
                                            if (t.len > 0 and t.len <= rs.zone_tag_buf.len) {
                                                // Canonical lowercase zone name (invariant 1).
                                                for (t, 0..) |c, i| rs.zone_tag_buf[i] = std.ascii.toLower(c);
                                                if (rs.gscreen != feed_view.screen_zones) rs.zone_return_screen = rs.gscreen;
                                                rs.zone_tag = rs.zone_tag_buf[0..t.len];
                                                rs.gscreen = feed_view.screen_zones;
                                                rs.zone_dirty = true;
                                                rs.gscroll_px = 0;
                                                rs.gsocket_ui.open = false;
                                                rs.gzones_q_focus = false;
                                            }
                                        },
                                        // Hub sub-tab: flip + restart the settle so the
                                        // incoming list slides in; the underline glides on
                                        // its own (tab_t lerps toward tab each frame).
                                        .zone_tab => if (hit.post <= 2) {
                                            const t: u8 = @intCast(hit.post);
                                            if (t != rs.gzones_tab) {
                                                rs.gzones_tab = t;
                                                rs.gzones_enter_t = 0;
                                                rs.gscroll_px = 0;
                                            }
                                            rs.gzones_q_focus = false;
                                        },
                                        .zone_search => {
                                            rs.gzones_q_focus = true;
                                            rs.caret_anchor_ns = clock_shell.monotonicNanos();
                                        },
                                        // Compose INTO this zone: open the composer with
                                        // the zone's tag LOCKED in the tag bar — it rides
                                        // the post as a record-level tag and can't be
                                        // removed from this view.
                                        .zone_compose => if (rs.zone_tag.len > 0) {
                                            rs.reply_target = null;
                                            rs.reply_handle = "";
                                            rs.quote_target = null;
                                            rs.quoting_handle = "";
                                            rs.compose_kind = .post;
                                            textedit.clear(&rs.compose);
                                            tagBarReset(&rs.gtagbar);
                                            const zt = rs.zone_tag;
                                            if (zt.len <= rs.gtagbar.locked_buf.len) {
                                                @memcpy(rs.gtagbar.locked_buf[0..zt.len], zt);
                                                rs.gtagbar.locked_len = @intCast(zt.len);
                                            }
                                            rs.status = "";
                                            rs.mode = .compose;
                                        },
                                        // Pin toggle — from a hub card (idx = catalog row)
                                        // or the zone masthead (screen_zones → the open
                                        // zone's tag). Persisted immediately; the catalog
                                        // card mirrors the new state.
                                        .zone_pin => {
                                            const tag: []const u8 = if (rs.gscreen == feed_view.screen_zones)
                                                rs.zone_tag
                                            else if (hit.post < rs.zone_catalog.items.len)
                                                rs.zone_catalog.items[hit.post].tag
                                            else
                                                "";
                                            if (tag.len > 0) {
                                                if (try pin_store.toggle(gpa, &rs.zone_pins, tag)) |now_pinned| {
                                                    for (rs.zone_catalog.items) |*zc| {
                                                        if (std.ascii.eqlIgnoreCase(zc.tag, tag)) zc.pinned = now_pinned;
                                                    }
                                                    _ = cache_shell.savePins(gpa, environ, &rs.zone_pins);
                                                    rs.status = if (now_pinned) "pinned — it keeps a place under Zones · Pinned" else "unpinned";
                                                }
                                            }
                                        },
                                        // Marketplace "View details": fetch this
                                        // algorithm's full config by (author, rkey) and
                                        // open its transparency page. The fetched config
                                        // is validated in the shell leg (never trust the
                                        // wire); what the page shows is what would run.
                                        // A browse card (or the detail page's button) → the
                                        // algorithm's full page. Payload is a FILTERED index.
                                        .algo_open => if (marketCatalogRow(rs, hit.post)) |row| {
                                            rs.gdetail_row = row;
                                            rs.gmarket_q_focus = false;
                                            rs.gscreen = feed_view.screen_algo_detail;
                                            rs.gscroll_px = 0;
                                        },
                                        .market_search => {
                                            rs.gmarket_q_focus = true;
                                        },
                                        // A capability chip: remember it + refilter the
                                        // browse list (the same shell-side path as search).
                                        .market_filter => {
                                            rs.gmarket_filter = @intCast(@min(hit.post, 3));
                                            refilterMarket(rs);
                                            rs.gscroll_px = 0;
                                        },
                                        .algo_install => if (marketCatalogRow(rs, hit.post)) |row| {
                                            const r = rs.market_catalog.items[row];
                                            if (rs.algo_lib.indexOf(r.cid) != null) {
                                                rs.status = "Already in your library.";
                                            } else if (rs.config_cache.get(r.cid)) |cached| {
                                                // Seen before (A8): install straight from the cache.
                                                installMarketAlgo(rs, environ, row, cached);
                                            } else if (!rs.inspectjob.active) {
                                                // Fetch the config off-thread, then finish the
                                                // install in the drain (the latch below).
                                                if (rs.inspect_ref.len > 0) gpa.free(rs.inspect_ref);
                                                rs.inspect_ref = try gpa.dupe(u8, r.cid);
                                                rs.gdetail_install_pending = true;
                                                startInspect(&rs.inspectjob, io, environ, session.pds_url, r.author_did, r.rkey);
                                                rs.status = "installing...";
                                            } else rs.status = "One moment — a fetch is already running.";
                                        },
                                        .algo_view => if (marketCatalogRow(rs, hit.post)) |algo_row| {
                                            const r = rs.market_catalog.items[algo_row];
                                            // Join any still-running fetch (rapid re-tap) before reusing
                                            // the job, so its thread can't outlive the reused fields.
                                            if (rs.inspectjob.active) {
                                                joinInspect(&rs.inspectjob);
                                                if (rs.inspectjob.ok) {
                                                    if (rs.inspectjob.bytes) |b| std.heap.page_allocator.free(b);
                                                    if (rs.inspectjob.src) |b| std.heap.page_allocator.free(b);
                                                }
                                                rs.inspectjob.bytes = null;
                                                rs.inspectjob.src = null;
                                            }
                                            if (rs.inspect_name.len > 0) gpa.free(rs.inspect_name);
                                            if (rs.inspect_ref.len > 0) gpa.free(rs.inspect_ref);
                                            if (rs.inspect_bytes) |b| gpa.free(b);
                                            rs.inspect_bytes = null;
                                            if (rs.inspect_src) |b| gpa.free(b);
                                            rs.inspect_src = null;
                                            rs.inspect_name = try gpa.dupe(u8, r.name);
                                            rs.inspect_ref = try gpa.dupe(u8, r.cid);
                                            rs.transp_return_screen = rs.gscreen;
                                            rs.gscreen = feed_view.screen_transparency;
                                            rs.gtransp_source = false; // open on the summary
                                            rs.gscroll_px = 0;
                                            // A8: a config we've already retrieved is immutable (same
                                            // CID) — serve it from the cache, INSTANT, no network.
                                            if (rs.config_cache.get(r.cid)) |cached| {
                                                rs.inspect_bytes = gpa.dupe(u8, cached) catch null;
                                                if (rs.src_cache.get(r.cid)) |sc| rs.inspect_src = gpa.dupe(u8, sc) catch null;
                                                rs.inspect_loading = false;
                                            } else {
                                                // Never seen: fetch on a worker (public read, no shared
                                                // session), page opens in a loading state meanwhile.
                                                startInspect(&rs.inspectjob, io, environ, session.pds_url, r.author_did, r.rkey);
                                                rs.inspect_loading = true;
                                            }
                                        },
                                        // "View the exact source" on the transparency
                                        // page → the byte-exact serialized artifact.
                                        .algo_source => {
                                            rs.gtransp_source = true;
                                            rs.gscroll_px = 0;
                                        },
                                        // "Add to loadout" (adopt + score) is the next
                                        // slice — it needs the fetched config wired into
                                        // the scoring resolver. Honest until then.
                                        .algo_add => {
                                            rs.status = "Add to loadout is coming next — view its details for now.";
                                        },
                                        // Settings → Sign out: flag it and leave the
                                        // run loop. The caller (main) clears the cached
                                        // session instead of re-saving it, so the next
                                        // launch shows the Join/login flow.
                                        .sign_out => {
                                            rs.user_signed_out = true;
                                            break :main_loop;
                                        },
                                        // Settings master–detail: pick the section.
                                        .settings_section => {
                                            rs.gsettings_section = @intCast(hit.post);
                                            rs.gscroll_px = 0;
                                            rs.gsettings_picking = 255; // close any open picker
                                        },
                                        // A detail-pane row. Toggles flip their
                                        // runtime bit (live — Julia mode reads its
                                        // bit; other toggles flip but do nothing
                                        // until wired). Non-toggle rows: inert.
                                        .settings_row => {
                                            // The pet-name field: tapping it focuses the text box;
                                            // tapping any other row gives the keyboard back.
                                            if (hit.post < settings_view.rows.len and settings_view.rows[hit.post].action == settings_view.act_pet_name) {
                                                rs.pet_name_focus = true;
                                            } else rs.pet_name_focus = false;
                                            if (hit.post < settings_view.rows.len and settings_view.rows[hit.post].kind == .toggle) {
                                                rs.toggle_bits ^= @as(u64, 1) << @intCast(hit.post);
                                                // Layout-owning toys are mutually exclusive (they all
                                                // resolve a post's on-screen position). Flipping one ON
                                                // clears the others. F4: fold into a real radio control
                                                // if this list keeps growing.
                                                const layout_toys = [_]u8{ settings_view.act_depth, settings_view.act_tectonic, settings_view.act_gravity, settings_view.act_zero_g, settings_view.act_liquid };
                                                const fa = settings_view.rows[hit.post].action;
                                                const now_on = (rs.toggle_bits >> @intCast(hit.post)) & 1 != 0;
                                                var is_layout_toy = false;
                                                for (layout_toys) |a| {
                                                    if (a == fa) is_layout_toy = true;
                                                }
                                                if (now_on and is_layout_toy) {
                                                    for (layout_toys) |a| {
                                                        if (a != fa) if (settings_view.rowOf(a)) |orow| {
                                                            rs.toggle_bits &= ~(@as(u64, 1) << orow);
                                                        };
                                                    }
                                                }
                                                // Julia mode flipped ON → sparks fly from the
                                                // SWITCH: a heart-shaped bloom of ripples out of
                                                // the toggle's spot in the field. Convert the
                                                // toggle pill (logical px, right end of the row)
                                                // to a field cell (window px / cell, via scale).
                                                if (settings_view.rows[hit.post].action == settings_view.act_julia and (rs.toggle_bits >> @intCast(hit.post)) & 1 != 0) {
                                                    if (rs.gpu_state) |*gs| {
                                                        const tx = (@as(f32, @floatFromInt(hit.x)) + @as(f32, @floatFromInt(hit.w)) - 36.0) * gs.scale;
                                                        const ty = (@as(f32, @floatFromInt(hit.y)) + @as(f32, @floatFromInt(hit.h)) * 0.5) * gs.scale;
                                                        pushJuliaBurst(gpa, gs, @intFromFloat(tx / @as(f32, @floatFromInt(field_cell_w))), @intFromFloat(ty / @as(f32, @floatFromInt(field_cell_h))));
                                                        // The visible spark: hearts fly from the switch, on top of everything.
                                                        gs.julia_burst_x = tx;
                                                        gs.julia_burst_y = ty;
                                                        gs.julia_burst_t = 1.0;
                                                    }
                                                }
                                            }
                                            rs.gsettings_picking = 255; // a row tap closes the picker
                                        },
                                        // A wired CHOICE row: open (or re-close) its
                                        // picker popover.
                                        .settings_choice => {
                                            const act = settings_view.rows[hit.post].action;
                                            rs.gsettings_picking = if (rs.gsettings_picking == act) 255 else act;
                                        },
                                        // A picker option: post = choiceIndex*8 + optionIndex.
                                        .settings_choice_opt => {
                                            const ci = hit.post / 8;
                                            const oi: u8 = @intCast(hit.post % 8);
                                            if (ci < rs.choice_sel.len) rs.choice_sel[ci] = oi;
                                            rs.gsettings_picking = 255; // selection closes the picker
                                        },
                                    }
                                }
                            }
                        } else if (rs.armed_legacy and cx == rs.armed_cx and cy == rs.armed_cy) {
                            // Legacy (software cell) tap: same target on release.
                            if (field_ui.hitTest(cx, cy, g.hr.slice())) |hit| {
                                if (hit.target != field_ui.no_target and hit.target < view_items.len) rs.state.selected = hit.target;
                                if (hit.action != .none) if (timeline_ui.keyFor(hit.action)) |byte| {
                                    try pumped_bytes.append(gpa, byte);
                                };
                            }
                        }
                        rs.armed_kind = null;
                        rs.armed_legacy = false;
                    },
                    else => {},
                }
            }
            if (pointer_events.items.len > 0) rs.last_input_nanos = clock_shell.monotonicNanos();
        };
        // Compose mode: the premium composer's footer buttons. A tap is
        // turned into the SAME control byte the keyboard sends — Ctrl-D
        // (send) / Ctrl-C (cancel) — so handleComposeInput stays the one
        // dispatch path (the timeline does the same trick for its rows).
        if (rs.mode == .compose) if (pix) |g| {
            const gpu_scale: f32 = if (g.gpu) |gs| gs.scale else 1.0;
            for (pointer_events.items) |pev| {
                const rx: i32 = if (g.gpu != null) @intFromFloat(@as(f32, @floatFromInt(pev.x)) / gpu_scale) else @intCast(pev.x);
                const ry: i32 = if (g.gpu != null) @intFromFloat(@as(f32, @floatFromInt(pev.y)) / gpu_scale) else @intCast(pev.y);
                switch (pev.kind) {
                    .button_down => {
                        if (pev.button != 1) continue;
                        if (feed_view.hitTest(g.regions.items, rx, ry)) |hit| switch (hit.kind) {
                            // Release-activation: arm the footer button; it fires
                            // on button_up if the release is still on it. A
                            // segment's ✕ / a tag chip's × carries its index in
                            // `post`.
                            .compose_send, .compose_cancel, .compose_add, .compose_remove, .compose_tag_add, .compose_tag_remove => {
                                rs.armed_compose = hit.kind;
                                rs.armed_post = hit.post;
                            },
                            else => {},
                        } else {
                            // Press in the text area: typing returns to the
                            // draft — the tag input lets go.
                            rs.gtagbar.input_focus = false;
                            // Count consecutive presses close in time + place:
                            // 1 = caret + drag, 2 = select word, 3 = select line.
                            const now_ns = clock_shell.monotonicNanos();
                            const near = @abs(rx - rs.last_click_x) <= 3 and @abs(ry - rs.last_click_y) <= 3;
                            rs.click_count = if (now_ns -| rs.last_click_ns < 400_000_000 and near) rs.click_count + 1 else 1;
                            rs.last_click_ns = now_ns;
                            rs.last_click_x = rx;
                            rs.last_click_y = ry;
                            const off = feed_view.composeCaretAtPoint(g.engine, @intCast(if (rs.gpu_state) |*sgs| sgs.design_w else design_w), textedit.view(&rs.compose), rx, ry);
                            switch (@min(rs.click_count, @as(u8, 3))) {
                                1 => {
                                    textedit.setCaret(&rs.compose, off);
                                    rs.compose_drag = true; // single press → drag-select
                                },
                                2 => textedit.selectWord(&rs.compose, off),
                                else => textedit.selectLine(&rs.compose, off),
                            }
                            rs.caret_anchor_ns = now_ns;
                        }
                    },
                    .move => {
                        // Affordance: the hand over the composer's footer
                        // buttons (the only regions it emits), the I-beam over
                        // the editable text area otherwise — so a tap into the
                        // composer doesn't leave the hand from the button that
                        // opened it, and editable text reads as selectable.
                        switch (backend) {
                            .window => |w| window_shell.setCursor(w, if (feed_view.hitTest(g.regions.items, rx, ry) != null) .pointer else .text),
                            else => {}, // a finger casts no cursor
                        }
                        if (rs.compose_drag) {
                            // Drag extends the selection to the pointer.
                            const off = feed_view.composeCaretAtPoint(g.engine, @intCast(if (rs.gpu_state) |*sgs| sgs.design_w else design_w), textedit.view(&rs.compose), rx, ry);
                            textedit.extendTo(&rs.compose, off);
                            rs.caret_anchor_ns = clock_shell.monotonicNanos();
                        }
                    },
                    .button_up => if (pev.button == 1) {
                        rs.compose_drag = false;
                        // Fire the armed footer button only if the release is
                        // still over the same button (slide-off cancels).
                        if (rs.armed_compose) |ac| {
                            if (feed_view.hitTest(g.regions.items, rx, ry)) |hit| {
                                if (hit.kind == ac) switch (ac) {
                                    .compose_send => try pumped_bytes.append(gpa, 4), // ctrl-D
                                    .compose_cancel => try pumped_bytes.append(gpa, 3), // ctrl-C
                                    // "Add": finalize the active draft as a thread
                                    // segment and clear the box for the next post.
                                    .compose_add => {
                                        const active = textedit.view(&rs.compose);
                                        if (active.len > 0 and rs.chain_segments.items.len < max_chain_segments - 1) {
                                            if (gpa.dupe(u8, active)) |d| {
                                                rs.chain_segments.append(gpa, d) catch gpa.free(d);
                                                textedit.clear(&rs.compose);
                                                rs.caret_anchor_ns = clock_shell.monotonicNanos();
                                            } else |_| {}
                                        }
                                    },
                                    // A segment's ✕: drop it, preserving order.
                                    .compose_remove => if (rs.armed_post < rs.chain_segments.items.len) {
                                        gpa.free(rs.chain_segments.items[rs.armed_post]);
                                        _ = rs.chain_segments.orderedRemove(rs.armed_post);
                                    },
                                    // The tag bar: focus the add-tag input / drop a chip.
                                    .compose_tag_add => {
                                        rs.gtagbar.input_focus = true;
                                        rs.caret_anchor_ns = clock_shell.monotonicNanos();
                                    },
                                    .compose_tag_remove => if (rs.armed_post < rs.gtagbar.chips_n) {
                                        // Shift the fixed-buffer chips down over the hole.
                                        var ci: usize = rs.armed_post;
                                        while (ci + 1 < rs.gtagbar.chips_n) : (ci += 1) {
                                            rs.gtagbar.chips_buf[ci] = rs.gtagbar.chips_buf[ci + 1];
                                            rs.gtagbar.chip_lens[ci] = rs.gtagbar.chip_lens[ci + 1];
                                        }
                                        rs.gtagbar.chips_n -= 1;
                                    },
                                    else => {},
                                };
                            }
                        }
                        rs.armed_compose = null;
                    },
                    else => {},
                }
            }
            if (pointer_events.items.len > 0) rs.last_input_nanos = clock_shell.monotonicNanos();
        };
        // The OS clipboard arrived (the activity fed it after a paste tap):
        // it replaces the selection / lands at the caret, like typing does.
        if (rs.clip_in_ready) {
            rs.clip_in_ready = false;
            // The RECEIVE fields take it first when they are the thing on screen
            // asking for it (the wallet page, or the sheet's paste face). An
            // address is pasted whole — it replaces the field rather than
            // inserting at a caret, because that is what "paste your address"
            // means and a half-merged address is worse than none.
            const recv_asking = rs.grecv_open or rs.gscreen == feed_view.screen_wallet;
            if (recv_asking) {
                const raw = rs.clip_in_buf[0..rs.clip_in_len];
                const addr = std.mem.trim(u8, raw, " \t\r\n");
                const dst_len = if (rs.grecv_focus == 1) &rs.grecv_btc_len else &rs.grecv_ln_len;
                const dst: []u8 = if (rs.grecv_focus == 1) &rs.grecv_btc_buf else &rs.grecv_ln_buf;
                if (addr.len > 0 and addr.len <= dst.len) {
                    @memcpy(dst[0..addr.len], addr);
                    dst_len.* = addr.len;
                    rs.grecv_status = "";
                    rs.gchat_key_ns = clock_shell.monotonicNanos();
                } else if (addr.len > dst.len) {
                    rs.grecv_status = "That doesn't look like an address";
                }
            } else if (rs.gchat_input_focus and rs.gscreen == feed_view.screen_messages) {
                _ = chatDeleteSelection(rs);
                const room = rs.gchat_draft_buf.len - rs.gchat_draft_len;
                const pn = @min(rs.clip_in_len, room);
                if (pn > 0) {
                    const at = @min(rs.gchat_caret, rs.gchat_draft_len);
                    std.mem.copyBackwards(u8, rs.gchat_draft_buf[at + pn .. rs.gchat_draft_len + pn], rs.gchat_draft_buf[at..rs.gchat_draft_len]);
                    @memcpy(rs.gchat_draft_buf[at..][0..pn], rs.clip_in_buf[0..pn]);
                    rs.gchat_draft_len += pn;
                    rs.gchat_caret = at + pn;
                    rs.gchat_key_ns = clock_shell.monotonicNanos();
                    rs.kbd_dirty = true;
                }
            }
        }
        // A nav-rollout choice marked the picker prefs dirty: persist the
        // one byte here (environ is in scope; kbdAction has none).
        if (rs.kbd_prefs_dirty) {
            rs.kbd_prefs_dirty = false;
            _ = cache_shell.saveKbdSection(environ, rs.kbd_picker_mode);
        }
        // The picker NAV rollout eases toward its want, and a category
        // jump glides the grid to its block — per lap for EVERY backend
        // (the desktop mouse flips the same wants), rendered through the
        // ordinary paint (feed_sig carries them; kbd_dirty stays out —
        // continuous motion, the razor law). A mobile drag cancels the
        // jump at engage, so the glide never fights a finger.
        const nav_goal: f32 = if (rs.kbd_nav_want) 1.0 else 0.0;
        if (rs.kbd_nav_t != nav_goal) {
            rs.kbd_nav_t += (nav_goal - rs.kbd_nav_t) * 0.24;
            if (@abs(rs.kbd_nav_t - nav_goal) < 0.004) rs.kbd_nav_t = nav_goal;
        }
        if (rs.kbd_emoji_jump >= 0) {
            const jt = rs.kbd_emoji_jump;
            rs.kbd_emoji_scroll += (jt - rs.kbd_emoji_scroll) * 0.3;
            if (@abs(jt - rs.kbd_emoji_scroll) < 1.0) {
                rs.kbd_emoji_scroll = jt;
                rs.kbd_emoji_jump = -1;
            }
        }
        if (backend != .terminal) {
            // The Zat4 keyboard's taps from LAST frame join the stream first —
            // one input path; every downstream consumer is IME-agnostic.
            if (rs.kbd_bytes.items.len > 0) {
                pumped_bytes.insertSlice(gpa, 0, rs.kbd_bytes.items) catch {};
                rs.kbd_bytes.clearRetainingCapacity();
            }
            n = @min(pumped_bytes.items.len, in_buf.len);
            @memcpy(in_buf[0..n], pumped_bytes.items[0..n]);
        }
        // No input this lap: idle back to the top. The top-of-loop
        // paintFrame is the ONE place the sim advances — it runs every
        // lap, and the dynamic pump above already set this lap's length
        // to the frame cadence while animating, so looping back yields
        // exactly one animation frame. (A second paint here was
        // redundant: it re-ran the whole pipeline with ~0 dt, doing the
        // CPU work of a frame the top-of-loop paint repeats next lap —
        // pure waste on the render thread. One paint per lap.)
        if (backend != .terminal) {
            if (n == 0) {
                // THE RAZOR-TAP PAINT: a byteless keystroke (shift, a popup
                // slide, a held pop) still gets its pixels THIS tick. Paint
                // the CURRENT mode's surface — the timeline funnel here in
                // compose mode flashed the feed under every keystroke.
                if (rs.kbd_dirty) {
                    kbdRestamp(rs, &pix);
                    if (rs.mode == .compose)
                        paintComposeRazor(gpa, arena, rs, pix, backend)
                    else
                        try paintFrame(gpa, rs.out, arena, &rs.prev, &rs.next, backend, pix, view_items, profile_header, &rs.state, rs.revealed.items, now, session.handle, rs.status);
                }
                return .again; // no input this lap: frame over (was `continue`)
            }
            rs.last_input_nanos = clock_shell.monotonicNanos();
        }

        // THE FRONT DOOR owns the keyboard while it is up. It takes the RAW byte
        // stream — the same stream the Zat4 soft keyboard feeds on the phone, so
        // enrollment gets phone typing for free, with no second input path and no
        // second text model (`enroll_run.handleText` runs the shared `textedit`).
        // This is the entire dividend of hosting the front door in this loop.
        if (rs.gscreen == feed_view.screen_enroll and n > 0) {
            // A key during the ENTRANCE skips it and is spent doing so — it must not
            // also land in a field on a card that is not on screen yet.
            if (bootIntroSkip(rs)) {
                n = 0;
            } else {
                if (enroll_run.handleTextFor(&rs.genroll_state, in_buf[0..n], rs.backend == .mobile)) return .quit; // bare Esc
                rs.caret_anchor_ns = clock_shell.monotonicNanos();
                n = 0; // consumed: nothing behind the front door may see these keys
            }
        }

        var offset: usize = 0;
        while (offset < n) {
            const decoded = tui.decodeInput(in_buf[offset..n]);
            if (decoded.consumed == 0) break;
            offset += decoded.consumed;

            if (rs.mode == .profile) {
                try handleProfileInput(gpa, arena, io, environ, session, rs.out, backend, &rs.prev, &rs.next, &rs.status, &rs.status_buf, &rs.mode, &rs.profile_info, decoded.event, now);
                continue;
            }

            // Timeline: Escape dismisses an open context menu; Ctrl+C copies the
            // rooted post's text selection. Both need the shell (menu state /
            // clipboard). Ctrl+C only CONSUMES the key when a selection exists, so
            // with none it still falls through to its normal handling.
            if (rs.mode == .timeline) if (pix) |g| if (g.gpu) |gs| {
                if (decoded.event == .escape and gs.menu_open) {
                    gs.menu_open = false;
                    continue;
                }
                const ch: ?u21 = switch (decoded.event) {
                    .char => |c| c,
                    else => null,
                };
                if (ch == 3) {
                    const r = text_select.range(gs.sel_glyphs.items.len, gs.sel_anchor, gs.sel_focus);
                    if (r.hi > r.lo) {
                        copySelection(gpa, gs, backend);
                        rs.status = "Copied";
                        continue;
                    }
                }
                // Tiling foundation: '/' toggles the content-driven SEARCH tile —
                // it grows + pushes the trending/follow tiles down (a cheap
                // reposition, no relayout). The shell springs `search_open`.
                // Dead while a text input owns the keyboard ('/' is text there).
                if (ch == '/' and !typingOwnsKeyboard(rs)) {
                    gs.search_want = !gs.search_want;
                    continue;
                }
            };

            if (rs.mode == .compose) {
                // The tag bar's add-tag input owns the keyboard while focused:
                // Enter/space/comma commit the chip (focus stays for the next
                // tag), Esc gives the keyboard back to the draft, Backspace on
                // an empty input removes the newest chip. Tag bytes only —
                // the same rule the inline detector uses, so a chip can never
                // hold what a facet couldn't.
                if (rs.gtagbar.input_focus) {
                    const bar = &rs.gtagbar;
                    switch (decoded.event) {
                        .escape => bar.input_focus = false,
                        .enter, .shift_enter => tagBarCommitInput(bar),
                        .char => |c| switch (c) {
                            3 => bar.input_focus = false, // ctrl-C: back out, don't cancel the post
                            ' ', ',' => tagBarCommitInput(bar),
                            127, 8 => if (bar.input_len > 0) {
                                bar.input_len -= 1;
                            } else if (bar.chips_n > 0) {
                                bar.chips_n -= 1;
                            },
                            '#' => {}, // the chip supplies its own '#'
                            else => if (c >= 0x20 and c < 0x7f and bar.input_len < bar.input_buf.len) {
                                const b: u8 = @intCast(c);
                                if (std.ascii.isAlphanumeric(b) or b == '_') {
                                    bar.input_buf[bar.input_len] = b;
                                    bar.input_len += 1;
                                }
                            },
                        },
                        else => {},
                    }
                    rs.caret_anchor_ns = clock_shell.monotonicNanos();
                    continue;
                }
                // Copy (Ctrl+C) / Cut (Ctrl+X) on a selection — handled here
                // because the clipboard write needs the window. With a selection,
                // Ctrl+C copies (not cancel); Ctrl+X copies then deletes.
                const ctrl_char: ?u21 = switch (decoded.event) {
                    .char => |c| c,
                    else => null,
                };
                if (ctrl_char) |c| if ((c == 3 or c == 24) and textedit.hasSelection(&rs.compose)) {
                    switch (backend) {
                        .window => |w| window_shell.setClipboard(w, textedit.selView(&rs.compose)),
                        .terminal, .mobile => {}, // no clipboard surface (mobile: a later UX pass)
                    }
                    if (c == 24) textedit.deleteSelection(&rs.compose);
                    rs.caret_anchor_ns = clock_shell.monotonicNanos();
                    continue;
                };
                try handleComposeInput(gpa, session, &rs.status, &rs.mode, store, &rs.compose, &rs.chain_segments, &rs.reply_target, &rs.reply_handle, &rs.quote_target, &rs.quoting_handle, rs.compose_kind, &rs.gtagbar, pix, &rs.pending_send, &rs.pending_profile_save, decoded.event, now);
                if (rs.mode != .compose) rs.compose_drag = false; // composer closed → end any drag
                rs.caret_anchor_ns = clock_shell.monotonicNanos(); // keystroke/move → solid caret
                continue;
            }

            // Zoom (text scaling) is a window-render concern, so it is
            // handled here in the shell, before the core action dispatch
            // — the pure timeline_ui need not learn about pixel cells
            // (B2/D3), the same way wheel-scroll lives in the pointer
            // block, not the core Action enum. '+'/'=' grow the text,
            // '-'/'_' shrink it; only meaningful in the window (the
            // terminal has no pixel cells), so gated on an engine.
            // Zat Chat's structural keys arrive as decoded EVENTS, not chars
            // (the terminal decoder owns that mapping — checking for '\r' in
            // a .char is dead code). Enter SENDS the draft (trailing
            // whitespace trimmed; all-whitespace sends nothing) or submits
            // the recipient bar; Shift+Enter breaks the line in the draft;
            // Escape leaves the focused input. Consumes the key.
            // The pay sheet owns the keyboard while open (M5 A4): Enter =
            // Send, Escape closes, Tab hops fields; characters route by
            // focus — digits only in the amount, anything printable in the
            // note. Consumes the key.
            // The receive-setup sheet owns the keyboard while open: Enter saves,
            // Escape closes, Tab hops the two address fields, any printable
            // character types into the focused one (addresses are alphanumeric +
            // punctuation, so no digit filter). Consumes the key.
            // The receive form owns the keyboard on BOTH surfaces it appears on:
            // the chat modal, and the Wallet page (where it is a page section, so
            // `grecv_open` is false — the mode is what says it is showing).
            const recv_typing = (rs.gscreen == feed_view.screen_messages and rs.grecv_open) or
                (rs.gscreen == feed_view.screen_wallet and rs.grecv_mode == .paste);
            if (rs.engine != null and dev_chat and recv_typing) {
                var recv_key = true;
                switch (decoded.event) {
                    // One step back per press (wallet picker → the branch →
                    // closed), not an instant dismissal of the whole flow.
                    .escape => _ = payModalBack(rs),
                    .enter => if (rs.grecv_mode == .paste) {
                        const ln = std.mem.trim(u8, rs.grecv_ln_buf[0..rs.grecv_ln_len], " ");
                        const btc = std.mem.trim(u8, rs.grecv_btc_buf[0..rs.grecv_btc_len], " ");
                        _ = rs.gchat_arena_state.reset(.retain_capacity);
                        rs.grecv_status = saveReceiveAddress(gpa, rs.gchat_arena_state.allocator(), io, environ, session, ln, btc, &rs.grecv_saved);
                        if (rs.grecv_saved) {
                            rs.grecv_set = true;
                            announceReceiveReady(gpa, io, environ, if (rs.gchat_e2ee) |*p| p else null, rs.gchat_link, &rs.gchat_store);
                        }
                    },
                    .char => |zc| if (rs.grecv_mode == .paste) {
                        if (zc == 8 or zc == 127) {
                            if (rs.grecv_focus == 0) {
                                if (rs.grecv_ln_len > 0) rs.grecv_ln_len -= 1;
                            } else if (rs.grecv_btc_len > 0) rs.grecv_btc_len -= 1;
                            rs.gchat_key_ns = clock_shell.monotonicNanos();
                        } else if (zc == 9) {
                            rs.grecv_focus = 1 - rs.grecv_focus;
                        } else if (zc >= 0x20 and zc < 0x7f) {
                            if (rs.grecv_focus == 0) {
                                if (rs.grecv_ln_len < rs.grecv_ln_buf.len) {
                                    rs.grecv_ln_buf[rs.grecv_ln_len] = @intCast(zc);
                                    rs.grecv_ln_len += 1;
                                    rs.gchat_key_ns = clock_shell.monotonicNanos();
                                }
                            } else if (rs.grecv_btc_len < rs.grecv_btc_buf.len) {
                                rs.grecv_btc_buf[rs.grecv_btc_len] = @intCast(zc);
                                rs.grecv_btc_len += 1;
                                rs.gchat_key_ns = clock_shell.monotonicNanos();
                            }
                        }
                    },
                    else => recv_key = false,
                }
                if (recv_key) {
                    try paintFrame(gpa, rs.out, arena, &rs.prev, &rs.next, backend, pix, view_items, profile_header, &rs.state, rs.revealed.items, now, session.handle, rs.status);
                    continue;
                }
            }

            if (rs.engine != null and dev_chat and rs.gscreen == feed_view.screen_messages and rs.gpay_open) {
                var pay_key = true;
                switch (decoded.event) {
                    // Escape takes ONE step back through the same edge the ×, the
                    // scrim, the chevron and the system back all use.
                    .escape => _ = payModalBack(rs),
                    // Enter does exactly what the button under the caret does —
                    // compose ARMS, confirm HANDS OFF — and both go through the
                    // worker, so the keyboard path cannot block the frame either.
                    .enter => if (rs.gchat_sel) |sc| {
                        const amount = feed_view.payAmountToSats(rs.gpay_amount_buf[0..rs.gpay_amount_len], rs.gpay_unit) orelse 0;
                        if (amount == 0 or amount > chat_core.max_amount_sat) {
                            rs.gpay_status = "Enter an amount in sats";
                        } else if (!rs.gpay_busy) {
                            const note = std.mem.trim(u8, rs.gpay_note_buf[0..rs.gpay_note_len], " ");
                            const stage: PayStage = if (rs.gpay_step == .compose) .gate else .hand_off;
                            rs.gpay_status = paySpawn(rs, io, environ, sc, stage, rs.gpay_rail, amount, note, true, null);
                            if (rs.gpay_status.len == 0) rs.gpay_busy = true;
                        }
                    },
                    .char => |zc| {
                        if (zc == 8 or zc == 127) {
                            if (rs.gpay_focus == 0) {
                                if (rs.gpay_amount_len > 0) rs.gpay_amount_len -= 1;
                            } else if (rs.gpay_note_len > 0) rs.gpay_note_len -= 1;
                            rs.gchat_key_ns = clock_shell.monotonicNanos();
                        } else if (zc == 9) {
                            rs.gpay_focus = 1 - rs.gpay_focus;
                        } else if (rs.gpay_focus == 0) {
                            // BTC mode accepts one decimal point; sats mode is
                            // digits only.
                            const is_digit = zc >= '0' and zc <= '9';
                            const is_dot = zc == '.' and rs.gpay_unit == .btc and
                                std.mem.indexOfScalar(u8, rs.gpay_amount_buf[0..rs.gpay_amount_len], '.') == null;
                            if ((is_digit or is_dot) and rs.gpay_amount_len < rs.gpay_amount_buf.len) {
                                rs.gpay_amount_buf[rs.gpay_amount_len] = @intCast(zc);
                                rs.gpay_amount_len += 1;
                                rs.gchat_key_ns = clock_shell.monotonicNanos();
                            }
                        } else if (zc >= 0x20 and zc < 0x7f and rs.gpay_note_len < rs.gpay_note_buf.len) {
                            rs.gpay_note_buf[rs.gpay_note_len] = @intCast(zc);
                            rs.gpay_note_len += 1;
                            rs.gchat_key_ns = clock_shell.monotonicNanos();
                        }
                    },
                    else => pay_key = false,
                }
                if (pay_key) {
                    try paintFrame(gpa, rs.out, arena, &rs.prev, &rs.next, backend, pix, view_items, profile_header, &rs.state, rs.revealed.items, now, session.handle, rs.status);
                    continue;
                }
            }

            if (rs.engine != null and dev_chat and rs.gscreen == feed_view.screen_messages and (rs.gchat_composing or rs.gchat_input_focus)) {
                var chat_key = true;
                switch (decoded.event) {
                    .enter => if (rs.gchat_composing) {
                        if (rs.gchat_peer_len > 0) {
                            _ = rs.gchat_arena_state.reset(.retain_capacity);
                            var new_sel: ?chat_core.ConvIndex = null;
                            rs.gchat_compose_status = chatStartCompose(gpa, rs.gchat_arena_state.allocator(), io, environ, if (rs.gchat_e2ee) |*p| p else null, rs.gchat_link, &rs.gchat_store, rs.gchat_peer_buf[0..rs.gchat_peer_len], &new_sel);
                            if (new_sel) |nc| {
                                rs.gchat_sel = nc;
                                rs.gchat_composing = false;
                                rs.gchat_peer_len = 0;
                                rs.gchat_compose_status = "";
                                rs.gchat_input_focus = true; // straight into typing the first message
                                rs.gscroll_px = 0;
                            }
                        }
                    } else {
                        const body = std.mem.trimEnd(u8, rs.gchat_draft_buf[0..rs.gchat_draft_len], " \n");
                        if (body.len > 0) if (rs.gchat_sel) |sc| {
                            _ = chat_core.appendMessage(gpa, &rs.gchat_store, sc, .text, body, now, true) catch {};
                            chatSend(gpa, io, environ, if (rs.gchat_e2ee) |*st| st else null, rs.gchat_link, &rs.gchat_store, sc, body);
                            chatPersistHistory(gpa, io, environ, if (rs.gchat_e2ee) |*p| p else null, &rs.gchat_store);
                            rs.gchat_draft_len = 0;
                            rs.gscroll_px = 0; // re-anchor to the newest message
                        };
                    },
                    .shift_enter => if (!rs.gchat_composing and insertUtf8At(&rs.gchat_draft_buf, &rs.gchat_draft_len, &rs.gchat_caret, '\n')) {
                        rs.gchat_key_ns = clock_shell.monotonicNanos();
                    },
                    // Caret navigation (arrow keys; the phone keyboard's
                    // space-hold slide arrives as the same escapes).
                    .left => if (!rs.gchat_composing and rs.gchat_input_focus) {
                        chatCollapseSel(rs);
                        rs.gchat_caret = @min(rs.gchat_caret, rs.gchat_draft_len);
                        caretLeftUtf8(&rs.gchat_draft_buf, &rs.gchat_caret);
                        rs.gchat_key_ns = clock_shell.monotonicNanos();
                    } else {
                        chat_key = false;
                    },
                    .right => if (!rs.gchat_composing and rs.gchat_input_focus) {
                        chatCollapseSel(rs);
                        caretRightUtf8(&rs.gchat_draft_buf, rs.gchat_draft_len, &rs.gchat_caret);
                        rs.gchat_key_ns = clock_shell.monotonicNanos();
                    } else {
                        chat_key = false;
                    },
                    .escape => if (rs.gchat_composing) {
                        rs.gchat_composing = false;
                        rs.gchat_compose_status = "";
                    } else {
                        rs.gchat_input_focus = false;
                    },
                    else => chat_key = false,
                }
                if (chat_key) {
                    kbdRestamp(rs, &pix);
                    try paintFrame(gpa, rs.out, arena, &rs.prev, &rs.next, backend, pix, view_items, profile_header, &rs.state, rs.revealed.items, now, session.handle, rs.status);
                    continue;
                }
            }

            if (rs.engine != null) if (decoded.event == .char) {
                const zc = decoded.event.char;
                // The Zat Chat composer strip: typing lands in the chat draft
                // while the field has focus (tap the input to focus). ASCII
                // for now, same as the Create name field; the full textedit
                // (caret, selection, UTF-8) is the recorded upgrade.
                // Consumes the key. The recipient bar (compose-new-
                // conversation) owns the keyboard while open. Every chat
                // keystroke stamps `gchat_key_ns` — the caret stays lit
                // while typing and breathes when idle.
                if (dev_chat and rs.gscreen == feed_view.screen_messages and rs.gchat_composing) {
                    if (zc == 8 or zc == 127) {
                        popUtf8(&rs.gchat_peer_buf, &rs.gchat_peer_len);
                        rs.gchat_key_ns = clock_shell.monotonicNanos();
                    } else if (zc >= 0x20 and pushUtf8(&rs.gchat_peer_buf, &rs.gchat_peer_len, zc)) {
                        rs.gchat_key_ns = clock_shell.monotonicNanos();
                    }
                    // Consume the key while the bar owns the keyboard — without
                    // this it falls through to the feed shortcuts, so typing a
                    // handle with an 'n' in it opened the new-post composer.
                    kbdRestamp(rs, &pix);
                    try paintFrame(gpa, rs.out, arena, &rs.prev, &rs.next, backend, pix, view_items, profile_header, &rs.state, rs.revealed.items, now, session.handle, rs.status);
                    continue;
                } else if (dev_chat and rs.gscreen == feed_view.screen_messages and rs.gchat_input_focus) {
                    if (zc == 8 or zc == 127) {
                        // Backspace eats the SELECTION when one exists.
                        if (!chatDeleteSelection(rs)) deleteUtf8Before(&rs.gchat_draft_buf, &rs.gchat_draft_len, &rs.gchat_caret);
                        rs.gchat_edit_bar = false;
                        rs.gchat_key_ns = clock_shell.monotonicNanos();
                    } else if (zc >= 0x20 and blk: {
                        _ = chatDeleteSelection(rs); // typing over a selection replaces it
                        rs.gchat_edit_bar = false;
                        break :blk insertUtf8At(&rs.gchat_draft_buf, &rs.gchat_draft_len, &rs.gchat_caret, zc);
                    }) {
                        rs.gchat_key_ns = clock_shell.monotonicNanos();
                        // One encrypted typing ping per 4s of active typing.
                        // deposit is worker-queued (never blocks the frame);
                        // the ping's persist is the same nonce rule a send
                        // pays — one keystore write per ping, throttled.
                        // AND ONLY IF THEY SAID YES (slice 1). A typing ping is a
                        // deposit into their mailbox every few seconds — the relay
                        // cannot read it, but it says "this person is at their
                        // keyboard right now", and that is a thing to be asked about
                        // rather than assumed. Off unless they turned it on.
                        if (rs.gchat_typing_on and now - rs.gchat_typing_sent_at >= 4) if (rs.gchat_sel) |sc| {
                            if (rs.gchat_e2ee) |*st| if (rs.gchat_link) |l| {
                                chat_e2ee.sendTyping(gpa, io, environ, st, l, chat_core.conversationDid(&rs.gchat_store, sc)) catch {};
                                rs.gchat_typing_sent_at = now;
                            };
                        };
                    }
                    kbdRestamp(rs, &pix);
                    try paintFrame(gpa, rs.out, arena, &rs.prev, &rs.next, backend, pix, view_items, profile_header, &rs.state, rs.revealed.items, now, session.handle, rs.status);
                    continue;
                }
                // Esc dismisses the designed-for heads-up.
                if (rs.gbench_pick != null and zc == 27) {
                    rs.gbench_pick = null;
                    rs.gbench_warn = null;
                    continue;
                }
                // The zones search-or-jump field: live filter per keystroke
                // (the render matches as it draws); Enter JUMPS straight to the
                // typed tag's zone (it may not exist yet — a zone is a query,
                // ZONES inv. 4); Esc gives the keyboard back. ASCII (tags are).
                if (rs.gscreen == feed_view.screen_zones_browse and rs.gzones_q_focus) {
                    if (zc == '\r' or zc == '\n') {
                        rs.gzones_q_focus = false;
                        const q = std.mem.trim(u8, rs.gzones_q_buf[0..rs.gzones_q_len], " #");
                        if (q.len > 0 and q.len <= rs.zone_tag_buf.len) {
                            for (q, 0..) |c, i| rs.zone_tag_buf[i] = std.ascii.toLower(c); // canonical (inv. 1)
                            rs.zone_return_screen = rs.gscreen;
                            rs.zone_tag = rs.zone_tag_buf[0..q.len];
                            rs.gscreen = feed_view.screen_zones;
                            rs.zone_dirty = true;
                            rs.gscroll_px = 0;
                            rs.gzones_q_len = 0; // the jump consumed the query
                        }
                    } else if (zc == 27) {
                        rs.gzones_q_focus = false;
                    } else if (zc == 8 or zc == 127) {
                        if (rs.gzones_q_len > 0) rs.gzones_q_len -= 1;
                    } else if (zc >= 0x20 and zc < 0x7f and rs.gzones_q_len < rs.gzones_q_buf.len) {
                        rs.gzones_q_buf[rs.gzones_q_len] = @intCast(zc);
                        rs.gzones_q_len += 1;
                    }
                    try paintFrame(gpa, rs.out, arena, &rs.prev, &rs.next, backend, pix, view_items, profile_header, &rs.state, rs.revealed.items, now, session.handle, rs.status);
                    continue;
                }
                // The chat list search: live filter per keystroke; Enter/Esc give
                // the keyboard back. ASCII (handles + previews match on ASCII).
                if (rs.gscreen == feed_view.screen_messages and rs.gchat_q_focus) {
                    if (zc == '\r' or zc == '\n' or zc == 27) {
                        rs.gchat_q_focus = false;
                    } else if (zc == 8 or zc == 127) {
                        if (rs.gchat_q_len > 0) rs.gchat_q_len -= 1;
                    } else if (zc >= 0x20 and zc < 0x7f and rs.gchat_q_len < rs.gchat_q_buf.len) {
                        rs.gchat_q_buf[rs.gchat_q_len] = @intCast(zc);
                        rs.gchat_q_len += 1;
                    }
                    try paintFrame(gpa, rs.out, arena, &rs.prev, &rs.next, backend, pix, view_items, profile_header, &rs.state, rs.revealed.items, now, session.handle, rs.status);
                    continue;
                }
                // The Toy Box pet-name field: type a name (ASCII), Enter/Esc give
                // the keyboard back, Backspace deletes. The name floats over the pet.
                if (rs.gscreen == feed_view.screen_settings and rs.pet_name_focus) {
                    if (zc == '\r' or zc == '\n' or zc == 27) {
                        rs.pet_name_focus = false;
                    } else if (zc == 8 or zc == 127) {
                        if (rs.pet_name_len > 0) rs.pet_name_len -= 1;
                    } else if (zc >= 0x20 and zc < 0x7f and rs.pet_name_len < rs.pet_name_buf.len) {
                        rs.pet_name_buf[rs.pet_name_len] = @intCast(zc);
                        rs.pet_name_len += 1;
                    }
                    try paintFrame(gpa, rs.out, arena, &rs.prev, &rs.next, backend, pix, view_items, profile_header, &rs.state, rs.revealed.items, now, session.handle, rs.status);
                    continue;
                }
                // The marketplace search box: live filter per keystroke; Enter or
                // Esc gives the keyboard back. ASCII (names/tags are).
                if (rs.gscreen == feed_view.screen_loadout and rs.gloadout_tab == 1 and rs.gmarket_q_focus) {
                    if (zc == '\r' or zc == '\n' or zc == 27) {
                        rs.gmarket_q_focus = false;
                    } else if (zc == 8 or zc == 127) {
                        if (rs.gmarket_q_len > 0) {
                            rs.gmarket_q_len -= 1;
                            refilterMarket(rs);
                        }
                    } else if (zc >= 0x20 and zc < 0x7f and rs.gmarket_q_len < rs.gmarket_q_buf.len) {
                        rs.gmarket_q_buf[rs.gmarket_q_len] = @intCast(zc);
                        rs.gmarket_q_len += 1;
                        refilterMarket(rs);
                    }
                    try paintFrame(gpa, rs.out, arena, &rs.prev, &rs.next, backend, pix, view_items, profile_header, &rs.state, rs.revealed.items, now, session.handle, rs.status);
                    continue;
                }
                // The dev submission flow's inputs. SOURCE: the Zal editor — a
                // textedit.Field, so paste (Ctrl+V arrives as the byte stream),
                // mid-text edits, and Enter-as-newline behave like a code
                // editor, not a form. Any edit drops the last check (the gate
                // verdict binds to exact bytes). DETAILS: name/ranks are short
                // single-line buffers; Enter or Tab hops fields; the
                // description takes real newlines. ASCII only (Zal is ASCII).
                if (rs.gscreen == feed_view.screen_loadout and rs.gloadout_tab == 2 and rs.gdev_active and rs.gdev_step == .source) {
                    if (zc == 8 or zc == 127) {
                        textedit.backspace(&rs.gdev_src);
                        devClearCheck(rs);
                    } else if (zc == '\r' or zc == '\n') {
                        textedit.insert(&rs.gdev_src, "\n");
                        devClearCheck(rs);
                    } else if (zc == 9) {
                        textedit.insert(&rs.gdev_src, "    ");
                        devClearCheck(rs);
                    } else if (zc >= 0x20 and zc < 0x7f) {
                        const b: [1]u8 = .{@intCast(zc)};
                        textedit.insert(&rs.gdev_src, &b);
                        devClearCheck(rs);
                    }
                    try paintFrame(gpa, rs.out, arena, &rs.prev, &rs.next, backend, pix, view_items, profile_header, &rs.state, rs.revealed.items, now, session.handle, rs.status);
                    continue;
                }
                if (rs.gscreen == feed_view.screen_loadout and rs.gloadout_tab == 2 and rs.gdev_active and rs.gdev_step == .details) {
                    if (zc == 9 or ((zc == '\r' or zc == '\n') and rs.gdev_focus != 2)) {
                        rs.gdev_focus = (rs.gdev_focus + 1) % 4;
                    } else if (zc == 8 or zc == 127) {
                        switch (rs.gdev_focus) {
                            0 => {
                                if (rs.gdev_name_len > 0) rs.gdev_name_len -= 1;
                            },
                            1 => {
                                if (rs.gdev_ranks_len > 0) rs.gdev_ranks_len -= 1;
                            },
                            3 => {
                                if (rs.gdev_tags_len > 0) rs.gdev_tags_len -= 1;
                            },
                            else => {
                                if (rs.gdev_desc_len > 0) rs.gdev_desc_len -= 1;
                            },
                        }
                    } else if ((zc == '\r' or zc == '\n') and rs.gdev_focus == 2) {
                        if (rs.gdev_desc_len < rs.gdev_desc_buf.len) {
                            rs.gdev_desc_buf[rs.gdev_desc_len] = '\n';
                            rs.gdev_desc_len += 1;
                        }
                    } else if (zc >= 0x20 and zc < 0x7f) {
                        switch (rs.gdev_focus) {
                            0 => if (rs.gdev_name_len < rs.gdev_name_buf.len) {
                                rs.gdev_name_buf[rs.gdev_name_len] = @intCast(zc);
                                rs.gdev_name_len += 1;
                            },
                            1 => if (rs.gdev_ranks_len < rs.gdev_ranks_buf.len) {
                                rs.gdev_ranks_buf[rs.gdev_ranks_len] = @intCast(zc);
                                rs.gdev_ranks_len += 1;
                            },
                            3 => if (rs.gdev_tags_len < rs.gdev_tags_buf.len) {
                                rs.gdev_tags_buf[rs.gdev_tags_len] = @intCast(zc);
                                rs.gdev_tags_len += 1;
                            },
                            else => if (rs.gdev_desc_len < rs.gdev_desc_buf.len) {
                                rs.gdev_desc_buf[rs.gdev_desc_len] = @intCast(zc);
                                rs.gdev_desc_len += 1;
                            },
                        }
                    }
                    try paintFrame(gpa, rs.out, arena, &rs.prev, &rs.next, backend, pix, view_items, profile_header, &rs.state, rs.revealed.items, now, session.handle, rs.status);
                    continue;
                }
                // The Create name field: route typing into the feed-name buffer (ASCII
                // for now — a zone/feed name is short). Backspace via BS/DEL. Consumes
                // the key so it never falls through to zoom or the feed shortcuts.
                if (rs.gscreen == feed_view.screen_loadout and rs.gloadout_tab == 2 and rs.gcreate_step == .name) {
                    if ((zc == 8 or zc == 127)) {
                        if (rs.gcreate_name_len > 0) rs.gcreate_name_len -= 1;
                    } else if (zc >= 0x20 and zc < 0x7f and rs.gcreate_name_len < rs.gcreate_name_buf.len) {
                        rs.gcreate_name_buf[rs.gcreate_name_len] = @intCast(zc);
                        rs.gcreate_name_len += 1;
                    }
                    try paintFrame(gpa, rs.out, arena, &rs.prev, &rs.next, backend, pix, view_items, profile_header, &rs.state, rs.revealed.items, now, session.handle, rs.status);
                    continue;
                }
                // SHORTCUT FENCE — the across-the-board guard over the branch-
                // level consumes above: while ANY text input owns the keyboard,
                // a printable key that reaches this point is swallowed — never
                // zoom, never a feed shortcut (actionFor below). An input is
                // protected even if its own branch forgets to consume a key —
                // the bug class where 'n' typed into the chat recipient bar
                // fell through and opened the new-post composer.
                if (typingOwnsKeyboard(rs)) continue;
                if (zc == '+' or zc == '=') {
                    rs.gzoom = std.math.clamp(rs.gzoom + 0.15, zoom_min, zoom_max);
                    rs.status = "zoom in";
                    try paintFrame(gpa, rs.out, arena, &rs.prev, &rs.next, backend, pix, view_items, profile_header, &rs.state, rs.revealed.items, now, session.handle, rs.status);
                    continue;
                } else if (zc == '-' or zc == '_') {
                    rs.gzoom = std.math.clamp(rs.gzoom - 0.15, zoom_min, zoom_max);
                    rs.status = "zoom out";
                    try paintFrame(gpa, rs.out, arena, &rs.prev, &rs.next, backend, pix, view_items, profile_header, &rs.state, rs.revealed.items, now, session.handle, rs.status);
                    continue;
                }
            };

            const kbd_action = timeline_ui.actionFor(decoded.event);
            // Mouse-only in the window app: the keyboard SELECTION CURSOR
            // (j/k/g/G/PgUp/PgDn) and the ENGAGE-THROUGH-SELECTED verbs
            // (l/b/R/f/p/x) are obsolete here. They drove `state.selected`, an
            // invisible cursor the mouse never tracks — feed_view draws no gutter,
            // only the terminal card renderer does — so a keystroke engaged a
            // possibly off-screen post: the stale-cursor glitch. The pure-terminal
            // TUI keeps every key; the window swallows just these. Mouse taps
            // engage via the pointer dispatch above (hit.post), untouched.
            if (backend == .window) switch (kbd_action) {
                .move_up, .move_down, .page_up, .page_down, .go_top, .go_bottom, .like, .repost, .reply, .follow, .profile, .toggle_reveal => continue,
                else => {},
            };
            switch (kbd_action) {
                .quit => break :main_loop,
                .refresh => {
                    // Off the frame thread, like the pull gesture: submit
                    // .pull and let the drain above reveal + jump when the
                    // page lands (M-Core.1: the frame body must not block —
                    // this was one of its seven synchronous fetches). The
                    // live-stream start the old inline path did now rides
                    // the drain's .pull success arm.
                    if (rs.refresher) |w| {
                        if (refresh_worker.submit(w, .pull, 30)) {
                            rs.refresh_inflight += 1;
                            rs.status = "refreshing...";
                        } else rs.status = "refresh already running";
                    } else rs.status = "refresh unavailable"; // worker never started (E2: a status, not a dead key)
                },
                .load_more => {
                    if (store.feed.len > 0 and feed_core.nextCursor(store).len == 0) {
                        rs.status = "end of feed";
                        continue;
                    }
                    // Off the frame thread (M-Core.1 unblocking, 2/7): copy
                    // the cursor out of the store — the worker never reads
                    // the store — and let the drain ingest the older page
                    // (ingestPage, append) when it lands.
                    if (rs.refresher) |w| {
                        if (gpa.dupe(u8, feed_core.nextCursor(store))) |cur| {
                            if (refresh_worker.submitOlder(w, cur, 30)) {
                                rs.refresh_inflight += 1;
                                rs.status = "loading...";
                            } else {
                                gpa.free(cur);
                                rs.status = "load already queued";
                            }
                        } else |err| return err; // OOM
                    } else rs.status = "load unavailable"; // worker never started (E2)
                },
                .like => if (view_items.len > 0) {
                    const r = try engageSelected(.like, gpa, arena, session, store, view_items[rs.state.selected], rs.state.selected, rs.gscreen, rs.profile_target_did, rs.thread_focus_cid, rs.zone_tag, rs.thread_rerooted, rs.gcollapsed.items, feed_config, reply_config, &rs.state, rs.revealed.items, now, rs.out, &rs.prev, &rs.next, backend, pix, rs.writer, &rs.deferred_unlike, &rs.deferred_unrepost);
                    if (r.status.len > 0) rs.status = r.status;
                    if (r.skip_rest) continue;
                },
                .repost => if (view_items.len > 0) {
                    const r = try engageSelected(.repost, gpa, arena, session, store, view_items[rs.state.selected], rs.state.selected, rs.gscreen, rs.profile_target_did, rs.thread_focus_cid, rs.zone_tag, rs.thread_rerooted, rs.gcollapsed.items, feed_config, reply_config, &rs.state, rs.revealed.items, now, rs.out, &rs.prev, &rs.next, backend, pix, rs.writer, &rs.deferred_unlike, &rs.deferred_unrepost);
                    if (r.status.len > 0) rs.status = r.status;
                    if (r.skip_rest) continue;
                },
                .profile => if (view_items.len > 0) {
                    const item = view_items[rs.state.selected];
                    rs.status = "loading profile...";
                    try paintFrame(gpa, rs.out, arena, &rs.prev, &rs.next, backend, pix, view_items, profile_header, &rs.state, rs.revealed.items, now, session.handle, rs.status);
                    const outcome = auth.queryHost(gpa, arena, io, environ, session, appview_url, lexicon.method.get_profile, &.{
                        .{ .name = "actor", .value = item.author_handle },
                    }, lexicon.ProfileViewDetailed) catch |err| switch (err) {
                        error.OutOfMemory => return err,
                        else => {
                            rs.status = "network error"; // contained (E2)
                            continue;
                        },
                    };
                    switch (outcome) {
                        .ok => |wire| {
                            _ = rs.profile_arena_state.reset(.retain_capacity);
                            const parena = rs.profile_arena_state.allocator();
                            rs.profile_info = .{
                                .did = try parena.dupe(u8, wire.did),
                                .handle = try parena.dupe(u8, wire.handle),
                                .display_name = try parena.dupe(u8, wire.displayName orelse ""),
                                .description = try parena.dupe(u8, wire.description orelse ""),
                                .followers = @intCast(@min(wire.followersCount, std.math.maxInt(u32))),
                                .follows = @intCast(@min(wire.followsCount, std.math.maxInt(u32))),
                                .posts = @intCast(@min(wire.postsCount, std.math.maxInt(u32))),
                                .following = wire.viewer != null and wire.viewer.?.following != null,
                            };
                            rs.mode = .profile;
                            rs.status = "";
                        },
                        .failed => |failure| rs.status = std.fmt.bufPrint(&rs.status_buf, "refused: {d} {s}", .{
                            failure.status, failure.code,
                        }) catch "refused",
                    }
                },
                .toggle_reveal => if (view_items.len > 0) {
                    const item = view_items[rs.state.selected];
                    var found: ?usize = null;
                    for (rs.revealed.items, 0..) |cid, i| {
                        if (std.mem.eql(u8, cid, item.cid)) {
                            found = i;
                            break;
                        }
                    }
                    if (found) |i| {
                        gpa.free(rs.revealed.items[i]);
                        _ = rs.revealed.swapRemove(i);
                        rs.status = "hidden again";
                    } else if (moderation.verdictFor(item.label_flags) == .hide) {
                        try rs.revealed.append(gpa, try gpa.dupe(u8, item.cid));
                        rs.status = "shown (x re-hides)";
                    }
                },
                .follow => if (view_items.len > 0) {
                    const item = view_items[rs.state.selected];
                    const did = feed_core.authorDidForCid(store, item.cid);
                    if (did.len > 0) {
                        rs.status = "following...";
                        try paintFrame(gpa, rs.out, arena, &rs.prev, &rs.next, backend, pix, view_items, profile_header, &rs.state, rs.revealed.items, now, session.handle, rs.status);
                        const outcome = write.followAccount(gpa, arena, io, environ, session, did, now) catch |err| switch (err) {
                            error.OutOfMemory => return err,
                            else => {
                                rs.status = "network error";
                                continue;
                            },
                        };
                        rs.status = switch (outcome) {
                            .ok => std.fmt.bufPrint(&rs.status_buf, "followed @{s}", .{item.author_handle}) catch "followed",
                            .failed => |failure| std.fmt.bufPrint(&rs.status_buf, "refused: {d} {s}", .{
                                failure.status, failure.code,
                            }) catch "refused",
                        };
                    }
                },
                .reply => if (view_items.len > 0) {
                    const item = view_items[rs.state.selected];
                    if (feed_core.replyRefsForCid(store, item.cid)) |refs| {
                        // Copy the refs out of the store before composing:
                        // the composer outlives this frame and the store may
                        // grow under it (the lifetime contract, honored).
                        _ = rs.compose_arena_state.reset(.retain_capacity);
                        const compose_arena = rs.compose_arena_state.allocator();
                        rs.reply_target = .{
                            .root_uri = try compose_arena.dupe(u8, refs.root_uri),
                            .root_cid = try compose_arena.dupe(u8, refs.root_cid),
                            .parent_uri = try compose_arena.dupe(u8, refs.parent_uri),
                            .parent_cid = try compose_arena.dupe(u8, refs.parent_cid),
                        };
                        rs.reply_handle = try compose_arena.dupe(u8, item.author_handle);
                        // The arena reset above freed any prior quote strings —
                        // drop the references with them.
                        rs.quote_target = null;
                        rs.quoting_handle = "";
                        textedit.clear(&rs.compose);
                        rs.status = "";
                        tagBarReset(&rs.gtagbar);
                        rs.mode = .compose;
                    }
                },
                .new_post => {
                    rs.reply_target = null;
                    rs.reply_handle = "";
                    rs.quote_target = null;
                    rs.quoting_handle = "";
                    textedit.clear(&rs.compose);
                    rs.status = "";
                    tagBarReset(&rs.gtagbar);
                    rs.mode = .compose;
                },
                else => |action| {
                    timeline_ui.applyAction(&rs.state, action, view_items.len);
                    switch (action) {
                        // Key navigation scrolls the pixel viewport to the
                        // cursor; wheel reading never does (one-shot flag,
                        // consumed by buildTimeline).
                        .move_up, .move_down, .page_up, .page_down, .go_top, .go_bottom => rs.gview.ensure_selected = true,
                        else => {},
                    }
                },
            }
        }
        // THE RAZOR-TAP PAINT (lap end): a keystroke consumed above renders
        // NOW — with the grid re-stamped — not at the next tick's top paint.
        // Mode-aware for the same reason as the mid-lap site above.
        if (rs.kbd_dirty) {
            kbdRestamp(rs, &pix);
            if (rs.mode == .compose)
                paintComposeRazor(gpa, arena, rs, pix, backend)
            else
                try paintFrame(gpa, rs.out, arena, &rs.prev, &rs.next, backend, pix, view_items, profile_header, &rs.state, rs.revealed.items, now, session.handle, rs.status);
        }
        return .again;
    }
    return if (rs.user_signed_out) .signed_out else .quit;
}

/// The MOBILE driver's handle (M_CORE_INVERSION MC.4c): the same RunState
/// the desktop loop drives, plus the host surface the seam writes into —
/// heap-owned because the OS keeps it alive across vsync callbacks, not a
/// stack frame. Created by mobileStart, stepped by mobileStep, torn down
/// by mobileEnd. A7.2: cold struct, size guard waived — one per app process.
pub const MobileRun = struct {
    rs: RunState,
    host: mobile_host.MobileHost,
    /// The empty session the pre-auth app runs against (FRONT_DOOR_ROADMAP). It
    /// holds no tokens and names no account; `rs.signed_in` is false and every
    /// entry point that would touch the network is gated on it. It lives HERE
    /// because the RunState points at it for the life of the process.
    pre_auth: auth.Session,
};

/// Driver #2 of the one funnel: bring the feed up on an OS-owned surface.
/// The caller (the C-ABI seam) owns session/store/appview_url and made the
/// GL context against its own surface; this builds the RunState exactly as
/// run() does, then hands the context to the same feed renderer the desktop
/// uses. `g` is owned from the first line (deinit on failure). GPU-only by
/// design: a failed feed-renderer bring-up fails the start (the mobile arm
/// has no software fallback), so the seam can report false honestly.
pub fn mobileStart(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    /// NULL = the pre-auth app (FRONT_DOOR_ROADMAP). The phone is the entire
    /// reason this is optional: enrollment used to live in a run loop that owns
    /// a WINDOW, and a phone has none — so a phone could not create an account.
    session_opt: ?*auth.Session,
    appview_url: []const u8,
    store: *feed_core.Store,
    g: gpu.Gpu,
    width_px: u32,
    height_px: u32,
) !*MobileRun {
    // Ownership of the context is TRANSFERRED to initGpuState the moment it
    // is called (it deinits on its own failure) — the optional disarms this
    // errdefer at that hand-off so no path deinits twice (C5).
    var g_owned: ?gpu.Gpu = g;
    errdefer if (g_owned) |*go| gpu.deinit(go);
    const mr = try gpa.create(MobileRun);
    errdefer gpa.destroy(mr);
    mr.host = .{ .width_px = width_px, .height_px = height_px };
    // The empty session must outlive the call, so it lives in MobileRun — not on
    // this stack frame, which is gone by the first frame.
    mr.pre_auth = .{ .did = "", .handle = "", .pds_url = "", .access_jwt = "", .refresh_jwt = "" };
    const session: *auth.Session = session_opt orelse &mr.pre_auth;
    mobile_host.logcat("driver: building RunState (workers, arenas)", .{});
    try initRunState(&mr.rs, gpa, io, environ, session, appview_url, store, .{ .mobile = &mr.host }, session_opt != null);
    errdefer deinitRunState(&mr.rs);
    if (!mr.rs.signed_in) mr.rs.gscreen = feed_view.screen_enroll;
    mobile_host.logcat("driver: RunState up — font engine next", .{});
    // The engine + feed GPU state the window path builds in initRunState's
    // window-gated tail — built here against the seam's context instead.
    mr.rs.engine = text_core.initEngine() catch null;
    if (mr.rs.engine) |*e| {
        mobile_host.logcat("driver: font engine up — GPU feed state next", .{});
        const gg = g_owned.?;
        g_owned = null;
        mr.rs.gpu_state = try initGpuState(gpa, e, gg, width_px, height_px, design_w_phone);
        mobile_host.logcat("driver: GPU feed state up", .{});
    } else return error.FontEngineUnavailable; // GPU-only arm: no engine → no renderer → honest failure
    return mr;
}

/// One frame on the OS's clock. Wait budget 0: the choreographer already
/// waited — the step must never sleep on an OS-owned thread (MC.4a).
pub fn mobileStep(mr: *MobileRun) !StepOutcome {
    return stepFrame(&mr.rs, 0);
}

/// Queue one input event from the seam (same ownership rule as the host:
/// dropped on OOM, contained). Returns false on the drop.
pub fn mobilePush(mr: *MobileRun, ev: layout_core.InputEvent) bool {
    return mobile_host.push(&mr.host, mr.rs.gpa, ev);
}

/// Queue one soft-keyboard byte from the seam (the terminal vocabulary the
/// pump already speaks: UTF-8 text, 0x08 backspace, '\r' enter).
pub fn mobilePushByte(mr: *MobileRun, b: u8) bool {
    return mobile_host.pushByte(&mr.host, mr.rs.gpa, b);
}

/// One pending haptic tick, taken (read-and-clear). 0 = none; 1 = the
/// pull-to-refresh arm; 2 = the drawer latch crossing. The pump detects the
/// edge the frame it happens; the activity performs the actual taptic
/// (GESTURE_SYSTEM_ROADMAP §3 — the shell fires, the detection is data).
/// Hand a URL to the OS. On the desktop this is `xdg-open`/`open`/ShellExecute
/// straight away. ON THE PHONE THERE IS NO SUCH BINARY — `launch.openUri` was
/// spawning `xdg-open` on Android, which does not exist there, so EVERY link
/// died in silence: the wallet suggestions did nothing, and, far worse, so did
/// the PAYMENT HAND-OFF — `payOpenWallet` reported "no wallet answered" when in
/// truth nothing had ever been asked. The phone route is the one the OAuth
/// browser already takes: park the URL, let the activity fire an ACTION_VIEW
/// intent. False only when the URL is too long to carry.
fn openUri(rs: *RunState, io: std.Io, uri: []const u8) bool {
    if (comptime builtin.abi.isAndroid()) {
        if (uri.len == 0 or uri.len > rs.gopen_url_buf.len) return false;
        @memcpy(rs.gopen_url_buf[0..uri.len], uri);
        rs.gopen_url_len = uri.len;
        return true;
    }
    launch.openUri(io, uri) catch return false;
    return true;
}

/// The URL the app wants opened, handed to the activity ONCE (read-and-clear —
/// a URL re-offered every frame would relaunch the browser every frame).
/// NUL-terminated into the caller's buffer; null = nothing pending.
pub fn mobileOpenUrlTake(mr: *MobileRun, out: []u8) ?[:0]const u8 {
    const n = mr.rs.gopen_url_len;
    if (n == 0 or n + 1 > out.len) return null;
    mr.rs.gopen_url_len = 0;
    @memcpy(out[0..n], mr.rs.gopen_url_buf[0..n]);
    out[n] = 0;
    return out[0..n :0];
}

/// The front door wants the OS browser (the "I already have an account" branch on
/// a phone). Read-and-clear: the seam opens it once, not every frame.
pub fn mobileLoginWant(mr: *MobileRun) bool {
    const w = mr.rs.glogin_want;
    mr.rs.glogin_want = false;
    return w;
}

/// The handle the person TYPED. The phone's sign-in used to ignore it entirely and
/// authorize against our own PDS unconditionally — which works only for accounts
/// that live there. `connor.zat4.com` wears a zat4.com handle but is HOSTED on
/// Bluesky's PDS, so the phone was asking the wrong server to sign him in, and the
/// redirect never came back. A handle must be resolved to ITS OWN server, exactly
/// as the desktop has always done.
pub fn mobileLoginHandle(mr: *MobileRun) []const u8 {
    const s = &mr.rs.genroll_state;
    return s.handle.buf[0..s.handle.len];
}

/// Enrollment produced a session. The seam persists it and restarts the app AS
/// that person — the loop cannot hot-swap an identity mid-frame. Ownership passes
/// to the caller.
pub fn mobileEnrolledTake(mr: *MobileRun) ?auth.Session {
    const s = mr.rs.genroll_session;
    mr.rs.genroll_session = null;
    return s;
}

pub fn mobileHapticTake(mr: *MobileRun) u8 {
    const tag = mr.host.haptic_pending;
    mr.host.haptic_pending = 0;
    return tag;
}

/// Copy/cut queued clipboard text OUT (read-and-clear); the activity hands
/// it to the OS clipboard. The pointer stays valid until the next frame.
pub fn mobileClipTake(mr: *MobileRun, len_out: *u32) ?[*]const u8 {
    if (mr.rs.clip_out_len == 0) return null;
    len_out.* = @intCast(mr.rs.clip_out_len);
    mr.rs.clip_out_len = 0;
    return &mr.rs.clip_out_buf;
}

/// Paste wants the OS clipboard (read-and-clear, one-shot per tap).
pub fn mobileClipWant(mr: *MobileRun) bool {
    const w = mr.rs.clip_want;
    mr.rs.clip_want = false;
    return w;
}

/// The activity feeds the OS clipboard's text back in; the next frame's
/// drain lands it in the focused draft.
pub fn mobileClipFeed(mr: *MobileRun, bytes: []const u8) void {
    const n = @min(bytes.len, mr.rs.clip_in_buf.len);
    @memcpy(mr.rs.clip_in_buf[0..n], bytes[0..n]);
    mr.rs.clip_in_len = n;
    mr.rs.clip_in_ready = true;
}

/// Does the frame WANT the soft keyboard? Keyed off the SAME predicate the
/// desktop keyboard fence uses (typingOwnsKeyboard — every text input registers
/// there), so the IME rises for chat, the searches, create/dev fields, and the
/// pet name — not just the composer (the "none of the keyboard stuff works"
/// on-device finding: only compose mode ever summoned it). The activity polls
/// this per lap and shows/hides the IME on the transition.
pub fn mobileImeWanted(mr: *MobileRun) bool {
    // The Zat4 keyboard replaces the system IME entirely while enabled — the
    // settings toggle (Appearance → "Zat4 keyboard") swaps back.
    if (toggleOn(mr.rs.toggle_bits, settings_view.act_zat_kbd)) return false;
    return typingOwnsKeyboard(&mr.rs);
}

/// The system BACK arrived (edge swipe / back button): queue it for the pump,
/// which pops one level of in-app navigation on the next frame.
pub fn mobileBack(mr: *MobileRun) void {
    mr.host.back_pending = true;
}

/// ACTION_CANCEL: the OS claimed the in-flight gesture — the pump resets its
/// touch machine (no tap, no drop, the drawer settles from where it is).
pub fn mobileTouchCancel(mr: *MobileRun) void {
    mr.host.touch_cancel = true;
}

/// Did the last back-pop find NOTHING to pop (read-and-clear)? True tells the
/// activity to step the task back to the launcher (moveTaskToBack) — the
/// Android back-at-root convention; the process and feed stay hot.
pub fn mobileMinimizeTake(mr: *MobileRun) bool {
    const v = mr.host.minimize_pending;
    mr.host.minimize_pending = false;
    return v;
}

/// The surface changed size (rotation / fold): the next frame lays out to
/// the new dims. The GL viewport is set per frame by the paint.
pub fn mobileResize(mr: *MobileRun, width_px: u32, height_px: u32) void {
    mr.host.width_px = width_px;
    mr.host.height_px = height_px;
}

/// The OS safe-area insets (physical px) → stored on GpuState in LOGICAL px by
/// dividing by the current ui scale (scale = physical_w / design_w, so logical =
/// physical / scale). Called from the mobile seam on surface/inset changes.
/// The soft keyboard's CURRENT bottom inset (device px; 0 = hidden), polled
/// by the activity while the IME is up: the chat composer lifts above it (it
/// used to be covered — the owner typed blind). Stored in logical px; the
/// layout call folds it into the chat insets and the rebuild signature.
pub fn mobileSetImeInset(mr: *MobileRun, bottom_px: i32) void {
    if (mr.rs.gpu_state) |*gs| {
        const s: f32 = if (gs.scale > 0) gs.scale else 1.0;
        gs.ime_bottom_l = @intFromFloat(@round(@as(f32, @floatFromInt(bottom_px)) / s));
    }
}

pub fn mobileSetInsets(mr: *MobileRun, top: i32, bottom: i32, left: i32, right: i32) void {
    if (mr.rs.gpu_state) |*gs| {
        const s: f32 = if (gs.scale > 0) gs.scale else 1.0;
        gs.inset_top_l = @intFromFloat(@round(@as(f32, @floatFromInt(top)) / s));
        gs.inset_bottom_l = @intFromFloat(@round(@as(f32, @floatFromInt(bottom)) / s));
        gs.inset_left_l = @intFromFloat(@round(@as(f32, @floatFromInt(left)) / s));
        gs.inset_right_l = @intFromFloat(@round(@as(f32, @floatFromInt(right)) / s));
        gs.feed_sig = 0; // force a rebuild — insets change the layout (see paintFrameGpu sig)
    }
}

/// M-And.4: the surface is dying but the app lives on — release ONLY the
/// GPU leg. The GL context dies with the surface anyway, and every GpuState
/// object dies with the context; the RunState — store, session, workers,
/// scroll, view state — stays hot for the next surface. Idempotent.
pub fn mobileSuspend(mr: *MobileRun) void {
    if (mr.rs.gpu_state) |*gs| {
        deinitGpuState(mr.rs.gpa, gs);
        mr.rs.gpu_state = null;
    }
}

/// M-And.4: a new surface arrived for a suspended feed — rebuild the GPU
/// leg against the seam's fresh context (owned from the call, the
/// mobileStart contract) and adopt the new geometry (rotation lands here as
/// a recreated surface). False = bring-up failed, context released; the
/// caller falls back to a full restart.
pub fn mobileResume(mr: *MobileRun, g_in: gpu.Gpu, width_px: u32, height_px: u32) bool {
    var g = g_in;
    if (mr.rs.gpu_state != null) {
        gpu.deinit(&g); // already rendering — refuse the spare context
        return true;
    }
    const eng = if (mr.rs.engine) |*e| e else {
        gpu.deinit(&g); // no font engine → mobileStart never succeeded
        return false;
    };
    mr.host.width_px = width_px;
    mr.host.height_px = height_px;
    // initGpuState owns g from the call (deinits on its own failure, C5).
    mr.rs.gpu_state = initGpuState(mr.rs.gpa, eng, g, width_px, height_px, design_w_phone) catch return false;
    return true;
}

/// Tear the feed down: the RunState's deinit (workers joined, arenas freed —
/// the GPU state inside it owns the GL context) plus the host queue.
pub fn mobileEnd(mr: *MobileRun) void {
    const gpa = mr.rs.gpa;
    deinitRunState(&mr.rs);
    mobile_host.deinit(&mr.host, gpa);
    gpa.destroy(mr);
}

pub fn run(
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    /// NULL = NOBODY YET. The app must be able to represent "not signed in",
    /// because a client that cannot represent it cannot sign anybody in — which
    /// is precisely why a phone could not create an account: enrollment lived in
    /// a run loop of its own, in a window a phone does not have
    /// (FRONT_DOOR_ROADMAP §0). With no session there is no feed, no chat, no
    /// appview and no rail: there is one screen, and it is the front door.
    session_opt: ?*auth.Session,
    appview_url: []const u8,
    store: *feed_core.Store,
    backend: Backend,
    /// OUT: the session enrollment produced, when the pre-auth app completed a
    /// sign-up. The caller restarts the app AS that person — the loop cannot
    /// hot-swap an identity mid-flight, because every worker, cache and store in
    /// it was built for "nobody". Ownership passes to the caller.
    enrolled_out: ?*?auth.Session,
) !bool {
    // MC.1 (M_CORE_INVERSION): all cross-frame state lives in RunState,
    // built in place (workers capture field addresses) and torn down by
    // deinitRunState — the setup and defers moved there verbatim. The
    // frame body below is unchanged except for the rs. prefix; MC.2 will
    // cut it out as stepFrame(&rs).
    // NOBODY YET. The loop below reads `session` freely, but every path that
    // does is reachable only when there IS one — the pre-auth app has exactly
    // one screen (the front door) and no feed, no chat, no appview, no rail.
    //
    // The empty session is not a fake credential: it holds no tokens and names
    // no account, and `signed_in` is the single gate every entry point checks.
    // The alternative — threading `?*Session` through 48 call sites, most of them
    // inside screens that cannot render pre-auth — would touch far more code to
    // say the same thing, and every one of those touches is a chance to break the
    // signed-in path that works today.
    var pre_auth: auth.Session = .{
        .did = "",
        .handle = "",
        .pds_url = "",
        .access_jwt = "",
        .refresh_jwt = "",
    };
    const session: *auth.Session = session_opt orelse &pre_auth;

    var rs: RunState = undefined;
    try initRunState(&rs, gpa, io, environ, session, appview_url, store, backend, session_opt != null);
    defer deinitRunState(&rs);
    if (!rs.signed_in) rs.gscreen = feed_view.screen_enroll;
    // The enrolled session outlives this loop (the caller runs the app as that
    // person); hand it over before the RunState is torn down.
    defer if (enrolled_out) |out| {
        out.* = rs.genroll_session;
        rs.genroll_session = null;
    };

    while (true) {
        // The inter-frame wait is the DRIVER's business (MC.4) — the step
        // itself never chooses how long to sleep. Desktop policy, verbatim
        // from the old pump site: the field animates only while it has live
        // work — the GPU field is ALIVE AT REST (ambient forcing drives
        // it), so when the GPU path is live we always pump at frame cadence
        // (~16 ms) to keep the simulation ticking; otherwise only when a
        // software effect/particles are in flight. A static screen blocks
        // the full idle interval so a still timeline costs ZERO CPU (the
        // no-wasted-cycles ethos, and the laptop's battery); 500 ms keeps
        // relative ages honest at human latency — two wakeups a second is
        // beneath measurement (G3). The next lap's paintFrame is what
        // advances the sim — a short pump returning no input still yields
        // one animation frame.
        const animating = rs.gpu_state != null or (rs.engine != null and (rs.gactive.len > 0 or rs.gparticles.len > 0));
        const wait_ms: i32 = if (backend == .window and animating) 16 else 500;
        switch (try stepFrame(&rs, wait_ms)) {
            .again => {},
            // Both exits leave the loop; the sign-out distinction rides in
            // rs.user_signed_out (set before the break), same as before the
            // cut. The mobile driver (MC.4) is what consumes the enum.
            .quit, .signed_out => break,
        }
    }
    return rs.user_signed_out;
}

/// The caret blink phase: solid for the ~530 ms after the last edit/move
/// (anchor), then a 530 ms on/off cycle while idle. B3: the clock is the shell's.
/// True while any TEXT INPUT owns the keyboard: the premium composer, the
/// chat recipient bar / message draft, the pay + receive sheets, the Create
/// name field. Printable keys are TEXT there, never shortcuts. The shortcut
/// layer checks this ONE predicate (the '/' search toggle + the char fence
/// in the run loop), so every input — present and future — is shielded even
/// when its own branch forgets to consume a key. Grow this list with every
/// new text input; that one line is the whole protection.
/// Should the in-app soft keyboard be on screen?
///
/// It is a PHONE affordance — the setting even says so ("Zat4 keyboard (phone)")
/// — but nothing enforced it, so on a laptop it drew a full soft keyboard over
/// half the window while a perfectly good physical one sat under the user's
/// hands. Gate it on the PHONE layout, not on the toggle alone.
fn softKeyboardWanted(rs: *const RunState) bool {
    if (!toggleOn(rs.toggle_bits, settings_view.act_zat_kbd)) return false;
    if (!typingOwnsKeyboard(rs)) return false;
    const gs = if (rs.gpu_state) |*g| g else return false; // software path is desktop-only
    return gs.design_w <= feed_view.phone_max;
}

/// The caret's blink phase: solid for a beat after the last keystroke, then a
/// smooth 1.1s breath. One implementation, so the chat composer, the pay modal
/// and the Wallet page's address fields all blink in step.
fn caretPhaseOf(clock_ns: u64, key_ns: u64) f32 {
    const raw: u64 = if (key_ns == 0) clock_ns else clock_ns -| key_ns;
    var ph: f64 = @as(f64, @floatFromInt(raw)) / 1_000_000_000.0;
    if (ph > 0.55) ph = 0.55 + @mod(ph - 0.55, 1.1);
    return @floatCast(ph);
}

fn typingOwnsKeyboard(rs: *const RunState) bool {
    if (rs.mode == .compose) return true;
    if (rs.engine == null) return false; // terminal: none of the GUI inputs exist
    // THE FRONT DOOR (the standing fence law: every new text input adds itself
    // here, or the keys fire app shortcuts instead of typing). It has five
    // fields — handle, username, email, the spot-checks, the full confirm — and
    // one of them is a PASSWORD being typed back. Nothing else on this screen
    // exists to be shortcut TO.
    if (rs.gscreen == feed_view.screen_enroll) return rs.genroll_state.focus != .none;
    if (rs.gscreen == feed_view.screen_messages and
        (rs.gchat_composing or rs.gchat_input_focus or rs.gchat_q_focus or rs.gpay_open or
            // The receive flow only TYPES on its paste face (the address
            // field). Its other faces — the branch, the wallet list, the
            // capability review — have no text input at all, and raising the
            // keyboard over them shoved the sheet up the screen and made the
            // phone look broken. The keyboard belongs where the caret is.
            (rs.grecv_open and rs.grecv_mode == .paste))) return true;
    // The Wallet page's address fields (the standing fence law: every new text
    // input adds itself here, or typing an address fires app shortcuts).
    if (rs.gscreen == feed_view.screen_wallet and rs.grecv_mode == .paste) return true;
    if (rs.gscreen == feed_view.screen_loadout and rs.gloadout_tab == 2 and rs.gcreate_step == .name) return true;
    // The dev submission flow: the Zal source editor and the details fields.
    if (rs.gscreen == feed_view.screen_loadout and rs.gloadout_tab == 2 and rs.gdev_active and
        (rs.gdev_step == .source or rs.gdev_step == .details)) return true;
    // The marketplace search box.
    if (rs.gscreen == feed_view.screen_loadout and rs.gloadout_tab == 1 and rs.gmarket_q_focus) return true;
    // The zones hub search-or-jump field.
    if (rs.gscreen == feed_view.screen_zones_browse and rs.gzones_q_focus) return true;
    // The Toy Box pet-name field.
    if (rs.gscreen == feed_view.screen_settings and rs.pet_name_focus) return true;
    return false;
}

// ---------------------------------------------------------------------------
// The developer submission flow's shell machinery (ALGO_SUBMISSION slice 1):
// check output ownership, the check runner, and the flow reset. The pure
// compile/gate/disclosure logic lives in core (dev_flow, algo_gate,
// transparency); this is only state hygiene + formatting.
// ---------------------------------------------------------------------------

/// Free the last check's gpa-owned output (diagnostics, disclosures, the
/// serialized config) and mark the source unchecked. Runs before every
/// re-check, on any source edit, on reset, and at teardown (C5).
fn devClearCheck(rs: *RunState) void {
    const gpa = rs.gpa;
    for (rs.gdev_diags.items) |s| gpa.free(s);
    rs.gdev_diags.clearRetainingCapacity();
    for (rs.gdev_discl.items) |s| gpa.free(s);
    rs.gdev_discl.clearRetainingCapacity();
    if (rs.gdev_config.len > 0) gpa.free(rs.gdev_config);
    rs.gdev_config = "";
    rs.gdev_checked = false;
    rs.gdev_check_ok = false;
}

/// Leave the dev flow entirely: drop the check output and every draft field.
fn devReset(rs: *RunState) void {
    devClearCheck(rs);
    textedit.clear(&rs.gdev_src);
    rs.gdev_name_len = 0;
    rs.gdev_ranks_len = 0;
    rs.gdev_desc_len = 0;
    rs.gdev_focus = 0;
    rs.gdev_color = 0;
    rs.gdev_designed = 1;
    rs.gdev_tags_len = 0;
    rs.gdev_status_len = 0;
    rs.gdev_step = .source;
    rs.gdev_active = false;
}

/// Append a gpa-owned copy of `s` to a dev line list. OOM drops the line —
/// a missing sentence, never a crash (E4).
fn devPush(rs: *RunState, list: *std.ArrayListUnmanaged([]const u8), s: []const u8) void {
    const gpa = rs.gpa;
    const copy = gpa.dupe(u8, s) catch return;
    list.append(gpa, copy) catch gpa.free(copy);
}

/// Run the compile + publish-gate check over the editor's source and turn the
/// outcome into display state: named diagnostics on refusal, or the serialized
/// config (kept byte-exact for the publish) + the code-DERIVED disclosure
/// sentences the review page shows (invariant 6: facts come from the compiled
/// code, never the author's claim).
fn runDevCheck(rs: *RunState) void {
    const gpa = rs.gpa;
    devClearCheck(rs);
    rs.gdev_checked = true;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const src = textedit.view(&rs.gdev_src);
    const c = dev_flow.check(arena, src) catch {
        devPush(rs, &rs.gdev_diags, "Out of memory while checking.");
        return;
    };
    if (c.errors.len > 0) {
        for (c.errors) |err| {
            var b: [256]u8 = undefined;
            const line = std.fmt.bufPrint(&b, "line {d}: {s}", .{ dev_flow.lineOf(src, err.start), err.msg }) catch err.msg;
            devPush(rs, &rs.gdev_diags, line);
        }
        return;
    }
    if (!c.verdict.pass()) {
        for (c.verdict.list()) |r| devPush(rs, &rs.gdev_diags, algo_gate.label(r));
        return;
    }
    const bytes = algorithm_core.serialize(arena, discover.validated(c.config)) catch {
        devPush(rs, &rs.gdev_diags, "Out of memory while checking.");
        return;
    };
    rs.gdev_config = gpa.dupe(u8, bytes) catch "";
    rs.gdev_check_ok = rs.gdev_config.len > 0;
    if (transparency.guestSection(c.config)) |gs| {
        var b: [192]u8 = undefined;
        devPush(rs, &rs.gdev_discl, if (gs.uses_attention)
            "Reads your attention signals — on your device only, never sent anywhere."
        else
            "Never reads your attention.");
        devPush(rs, &rs.gdev_discl, if (gs.keeps_state)
            "Keeps an on-device memory between sessions."
        else
            "Keeps nothing between sessions.");
        devPush(rs, &rs.gdev_discl, if (gs.composes_retrieval)
            "Composes its own candidate pool (retrieve())."
        else
            "Uses the standard candidate pool.");
        if (gs.reads_tags and gs.zones.len > 0) {
            var zb: [128]u8 = undefined;
            var zw: usize = 0;
            for (gs.zones, 0..) |z, i| {
                const sep: []const u8 = if (i == 0) "" else ", ";
                if (zw + sep.len + z.len > zb.len) break;
                @memcpy(zb[zw..][0..sep.len], sep);
                zw += sep.len;
                @memcpy(zb[zw..][0..z.len], z);
                zw += z.len;
            }
            const zl = std.fmt.bufPrint(&b, "Reads zone tags: {s}.", .{zb[0..zw]}) catch "Reads zone tags.";
            devPush(rs, &rs.gdev_discl, zl);
        }
        const fl = std.fmt.bufPrint(&b, "Compute ceiling: {d} instructions per post.", .{gs.fuel}) catch "";
        if (fl.len > 0) devPush(rs, &rs.gdev_discl, fl);
        const sl = if (gs.retrieve_len > 0)
            std.fmt.bufPrint(&b, "Code size: {d} score + {d} retrieve instructions.", .{ gs.score_len, gs.retrieve_len }) catch ""
        else
            std.fmt.bufPrint(&b, "Code size: {d} instructions.", .{gs.score_len}) catch "";
        if (sl.len > 0) devPush(rs, &rs.gdev_discl, sl);
    }
}

/// A publish landed OK: put the algorithm on the bench (visibility PUBLIC —
/// the record shape the marketplace serves), persist the library, and move
/// the flow to its done screen with the record uri shown. `record_cid` (the
/// result's revert_uri seat) becomes the library id — the same identity a
/// DOWNLOADED copy of this record would carry (A5/A8).
fn finishDevPublish(rs: *RunState, environ: ?*const std.process.Environ.Map, uri: []const u8, record_cid: []const u8) void {
    const gpa = rs.gpa;
    var idb: [24]u8 = undefined;
    const local_id = std.fmt.bufPrint(&idb, "user:{d}", .{rs.algo_uid}) catch "user:x";
    const id: []const u8 = if (record_cid.len > 0) record_cid else local_id;
    const nm: []const u8 = if (rs.gdev_name_len > 0) rs.gdev_name_buf[0..rs.gdev_name_len] else "Untitled algorithm";
    const new: algo_library.NewAlgo = .{
        .id = id,
        .name = nm,
        .ranks = rs.gdev_ranks_buf[0..rs.gdev_ranks_len],
        .desc = rs.gdev_desc_buf[0..rs.gdev_desc_len],
        .creator = "you",
        .config = rs.gdev_config,
        .color = rs.gdev_color,
        .designed = rs.gdev_designed,
        .visibility = .public,
    };
    if (rs.algo_lib.add(gpa, new)) |_| {
        rs.algo_uid += 1;
        _ = cache_shell.saveLibrary(gpa, environ, &rs.algo_lib);
    } else |_| {} // the record is live regardless; the bench copy just missed
    rs.gdev_step = .done;
    rs.gdev_status_len = if (std.fmt.bufPrint(&rs.gdev_status_buf, "{s}", .{uri})) |m| m.len else |_| 0;
    rs.gscroll_px = 0;
}

/// The dev flow's render view from the run state — one place, so the grid
/// literal stays a plain field list.
fn devViewOf(rs: *RunState) feed_view.DevView {
    return .{
        .active = rs.gdev_active,
        .step = rs.gdev_step,
        .src = textedit.view(&rs.gdev_src),
        .caret = rs.gdev_src.caret,
        .checked = rs.gdev_checked,
        .check_ok = rs.gdev_check_ok,
        .diags = rs.gdev_diags.items,
        .disclosures = rs.gdev_discl.items,
        .name = rs.gdev_name_buf[0..rs.gdev_name_len],
        .ranks = rs.gdev_ranks_buf[0..rs.gdev_ranks_len],
        .desc = rs.gdev_desc_buf[0..rs.gdev_desc_len],
        .focus = rs.gdev_focus,
        .color = rs.gdev_color,
        .designed = rs.gdev_designed,
        .tags = rs.gdev_tags_buf[0..rs.gdev_tags_len],
        .status = rs.gdev_status_buf[0..rs.gdev_status_len],
    };
}

/// The open detail page's render view from its catalog row (empty view when
/// the row went stale — the page renders its placeholder, never garbage).
fn detailViewOf(rs: *RunState) feed_view.AlgoDetailView {
    if (rs.gscreen != feed_view.screen_algo_detail) return .{};
    if (rs.gdetail_row >= rs.market_catalog.items.len) return .{};
    const r = rs.market_catalog.items[rs.gdetail_row];
    // The filtered position, so install/transparency payloads survive a live
    // search narrowing while the page is open.
    var idx: u16 = 0;
    for (rs.gmarket_map.items, 0..) |row, fi| {
        if (row == rs.gdetail_row) {
            idx = @intCast(fi);
            break;
        }
    }
    return .{
        .name = r.name,
        .author = r.author_disp,
        .ranks = r.ranks,
        .desc = r.desc,
        .tags = r.tags,
        .designed = r.designed,
        .learns = r.learns,
        .uses_behavioral = r.uses_behavioral,
        .state_budget_bytes = r.state_budget_bytes,
        .installed = rs.algo_lib.indexOf(r.cid) != null,
        .idx = idx,
    };
}

/// The bench chooser's render view (null = closed / a stale index).
fn benchPickViewOf(rs: *RunState) ?feed_view.BenchPickView {
    const bi = rs.gbench_pick orelse return null;
    if (bi >= rs.algo_lib.records.items.len) return null;
    const rec = rs.algo_lib.records.items[bi];
    return .{ .name = rs.algo_lib.slice(rec.name), .designed = rec.designed, .warn = rs.gbench_warn };
}

/// Seat a bench (library) algorithm into a surface socket: already present ⇒
/// just seat it; otherwise append it to the surface's entries and rebuild the
/// tray library-aware. The loadout-dirty flag persists it on leave (the same
/// flush every socket edit rides).
fn seatBenchAlgo(rs: *RunState, target: u8, lib_idx: usize) void {
    const gpa = rs.gpa;
    if (lib_idx >= rs.algo_lib.records.items.len) return;
    const rec = rs.algo_lib.records.items[lib_idx];
    const id = rs.algo_lib.slice(rec.id);
    const cards, const blob, const seated = switch (target) {
        0 => .{ &rs.socket_cards, &rs.socket_blob, &rs.gseated },
        1 => .{ &rs.reply_cards, &rs.reply_blob, &rs.reply_seated },
        else => .{ &rs.zone_cards, &rs.zone_blob, &rs.zone_seated },
    };
    for (cards.*, 0..) |c, ci| {
        const cid = blob.*[c.cid.off..][0..c.cid.len];
        if (std.mem.eql(u8, cid, id)) {
            seated.* = @intCast(ci);
            rs.loadout_dirty = true;
            rs.status = "Seated.";
            return;
        }
    }
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const scratch = arena_state.allocator();
    const entries = scratch.alloc(lens_catalog.Entry, cards.*.len + 1) catch return;
    for (cards.*, 0..) |c, ci| {
        const end = @min(blob.*.len, @as(usize, c.cid.off) + c.cid.len);
        entries[ci] = .{ .id = blob.*[@min(c.cid.off, blob.*.len)..end], .color = c.color };
    }
    entries[cards.*.len] = .{ .id = id, .color = rec.color };
    if (lens_catalog.loadoutFromEntriesLib(gpa, entries, &rs.algo_lib, scratch)) |t2| {
        if (cards.*.len > 0) gpa.free(cards.*);
        if (blob.*.len > 0) gpa.free(blob.*);
        cards.* = t2[0];
        blob.* = t2[1];
        seated.* = @intCast(cards.*.len - 1);
        rs.loadout_dirty = true;
        rs.status = "Socketed — it's driving that surface now.";
    } else |_| rs.status = "Couldn't socket it — out of memory.";
}

/// Drop a dragged bench card: seat it into the socket band under the pointer.
/// A full socket refuses honestly; a mismatched declaration opens the heads-up
/// modal (never a block); a release off every socket just fizzles.
fn benchDrop(rs: *RunState, lib_idx: u16, rx: i32, ry: i32) void {
    if (lib_idx >= rs.algo_lib.records.items.len) return;
    // The three sockets stack vertically: band i runs from its geometry's top
    // to the next one's (the last band gets generous tail room for its tray).
    var target: ?u8 = null;
    const geoms = rs.page_geoms;
    for (0..3) |i| {
        const gm = geoms[i];
        if (gm.w == 0) continue; // that surface wasn't laid out this frame
        const y1: i32 = if (i < 2 and geoms[i + 1].w != 0) geoms[i + 1].y else gm.y + 900;
        if (ry >= gm.y and ry < y1 and rx >= gm.x and rx < gm.x + gm.w) {
            target = @intCast(i);
            break;
        }
    }
    const t = target orelse return;
    const cards_len = switch (t) {
        0 => rs.socket_cards.len,
        1 => rs.reply_cards.len,
        else => rs.zone_cards.len,
    };
    if (cards_len >= lens_socket.max_lenses) {
        rs.status = "That socket is full — drag a lens out to the library first.";
        return;
    }
    const rec = rs.algo_lib.records.items[lib_idx];
    const bit = @as(u8, 1) << @intCast(t);
    if (rec.designed != 0 and (rec.designed & bit) == 0) {
        rs.gbench_pick = lib_idx; // the heads-up modal takes it from here
        rs.gbench_warn = t;
        return;
    }
    seatBenchAlgo(rs, t, lib_idx);
}

/// A tray card dragged out to the library column: remove it from that surface
/// (it stays in the library/catalog — unequip, never delete). Rebuilds the
/// tray from the remaining entries, library-aware.
fn removeDraggedFromSurface(rs: *RunState, s: u8) void {
    const gpa = rs.gpa;
    const cards, const blob, const seated, const ui = switch (s) {
        1 => .{ &rs.reply_cards, &rs.reply_blob, &rs.reply_seated, &rs.reply_ui },
        2 => .{ &rs.zone_cards, &rs.zone_blob, &rs.zone_seated, &rs.zone_ui },
        else => .{ &rs.socket_cards, &rs.socket_blob, &rs.gseated, &rs.gsocket_ui },
    };
    const di = ui.drag_active orelse return;
    ui.drag_active = null;
    if (di >= cards.*.len) return;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    const scratch = arena_state.allocator();
    const entries = scratch.alloc(lens_catalog.Entry, cards.*.len - 1) catch return;
    var n: usize = 0;
    for (cards.*, 0..) |c, ci| {
        if (ci == di) continue;
        const end = @min(blob.*.len, @as(usize, c.cid.off) + c.cid.len);
        entries[n] = .{ .id = blob.*[@min(c.cid.off, blob.*.len)..end], .color = c.color };
        n += 1;
    }
    if (lens_catalog.loadoutFromEntriesLib(gpa, entries[0..n], &rs.algo_lib, scratch)) |t2| {
        if (cards.*.len > 0) gpa.free(cards.*);
        if (blob.*.len > 0) gpa.free(blob.*);
        cards.* = t2[0];
        blob.* = t2[1];
        if (seated.* >= cards.*.len) seated.* = 0;
        rs.loadout_dirty = true;
        rs.status = "Removed from the socket — it stays in your library.";
    } else |_| {}
}

/// The Published tab's rows, built into the frame arena: MY marketplace
/// submissions (library visibility == public), each crossed with the fetched
/// marketplace catalog for its honest live status.
fn publishedRowsOf(arena: Allocator, rs: *RunState) []const feed_view.PublishedRow {
    if (rs.gscreen != feed_view.screen_loadout or rs.gloadout_tab != 3) return &.{};
    var out: std.ArrayList(feed_view.PublishedRow) = .empty;
    for (rs.algo_lib.records.items, 0..) |rec, li| {
        if (rec.visibility != .public) continue;
        const id = rs.algo_lib.slice(rec.id);
        // The matched marketplace row carries the capability facts (the
        // library doesn't store them); unmatched ⇒ syncing, facts unknown.
        var live_row: ?MarketRow = null;
        for (rs.market_catalog.items) |mr| {
            if (std.mem.eql(u8, mr.cid, id)) {
                live_row = mr;
                break;
            }
        }
        out.append(arena, .{
            .name = rs.algo_lib.slice(rec.name),
            .ranks = rs.algo_lib.slice(rec.ranks),
            .designed = rec.designed,
            .color = rec.color,
            .live = live_row != null,
            .confirm = rs.gpub_confirm != null and rs.gpub_confirm.? == li,
            .lib_idx = @intCast(li),
            .caps_known = live_row != null,
            .learns = if (live_row) |mr| mr.learns else false,
            .uses_behavioral = if (live_row) |mr| mr.uses_behavioral else false,
        }) catch break;
    }
    return out.items;
}

/// The bench drag ghost's render view (null = no drag).
fn benchDragViewOf(rs: *RunState) ?feed_view.BenchDragView {
    const bi = rs.gbench_drag orelse return null;
    if (bi >= rs.algo_lib.records.items.len) return null;
    const rec = rs.algo_lib.records.items[bi];
    return .{ .name = rs.algo_lib.slice(rec.name), .color = rec.color, .x = rs.gbench_drag_x, .y = rs.gbench_drag_y };
}


/// Is this region one of the Zat4 keyboard's? A key tap must never read as a
/// tap-off (it would blur the very input being typed into).
fn kbdRegion(k: feed_view.Action) bool {
    return k == .kbd_key or k == .kbd_shift or k == .kbd_page or k == .kbd_backspace or k == .blocker;
}

fn composeBlinkOn(anchor_ns: u64) bool {
    return ((clock_shell.monotonicNanos() -| anchor_ns) / 530_000_000) % 2 == 0;
}

/// The seated lens card + its blob for whichever surface has its detail sheet
/// open (item 5) — home / reply / zone. Null when closed or the seat is out of
/// range. The overlay renders from this; `set_color` writes back to the surface.
/// One system-BACK step (the Pixel edge swipe / back button): close the topmost
/// transient first — nav drawer, cartridge detail sheet, repost menu, composer —
/// else pop the screen stack the same way the on-screen ‹ Back buttons do (the
/// `.back` region arm mirrors the screen-specific returns), else report false:
/// the caller minimizes the task (back-at-root never kills the process).
fn backNavigate(rs: *RunState) bool {
    const gpa = rs.gpa;
    // THE FRONT DOOR answers the system back button. On a phone, back is how a
    // person expects to undo a wrong tap — and on the pre-auth screen there is no
    // nav rail to escape through, so if back does nothing there, nothing does.
    // At the first step it falls through: back-at-root minimizes, as everywhere.
    if (rs.gscreen == feed_view.screen_enroll) {
        // BACK PUTS THE KEYBOARD AWAY FIRST. That is what back MEANS on a phone
        // when a keyboard is up, and anything else is a trap: the owner swiped
        // back to dismiss it and got thrown to the previous step instead, over and
        // over, which is why the flow "kept resetting". Only with no keyboard up
        // does back mean "the step before this one".
        if (rs.genroll_state.focus != .none) {
            rs.genroll_state.focus = .none;
            return true;
        }
        if (rs.genroll_state.step != .provenance) {
            enroll_run.apply(&rs.genroll_state, .back, rs.io, clock_shell.monotonicNanos(), &rs.genroll_mstore, &rs.genroll_memjob);
            return true;
        }
        return false;
    }
    if (rs.gpu_state) |*gsd| {
        if (gsd.drawer_want or gsd.drawer_t > 0.3) {
            gsd.drawer_want = false;
            return true;
        }
    }
    if (rs.gcart_detail != null) {
        rs.gcart_detail = null;
        return true;
    }
    if (rs.grepost_menu != null) {
        rs.grepost_menu = null;
        return true;
    }
    // A money modal owns "back" while it is up — BEFORE the keyboard-blur step
    // below, not after.
    //
    // The old order was the bug: blur ran first, cleared a focus bit the modal
    // did not even own (the conversation-search field keeps `gchat_q_focus` set
    // behind an open sheet), returned "consumed" — and back appeared to do
    // nothing at all. One press, swallowed, no visible change. `payModalBack`
    // walks the same edge as Escape, the ×, the scrim and the chevron.
    if (rs.gscreen == feed_view.screen_messages and payModalOpen(rs)) {
        return payModalBack(rs);
    }
    // The Zat4 keyboard: back DISMISSES the panel first when a plain text
    // field raised it (blur the field; the next back navigates) — the
    // Android IME convention; without this the panel stuck to the screen
    // across pops (on-device, 2026-07-10). Overlays that own their keys
    // (the composer, the create/dev editors) keep their own pop below.
    if (rs.engine != null and toggleOn(rs.toggle_bits, settings_view.act_zat_kbd)) {
        var blurred = false;
        if (rs.gscreen == feed_view.screen_messages) {
            if (rs.gchat_input_focus) {
                rs.gchat_input_focus = false;
                blurred = true;
            }
            if (rs.gchat_q_focus) {
                rs.gchat_q_focus = false;
                blurred = true;
            }
            if (rs.gchat_composing) {
                rs.gchat_composing = false;
                blurred = true;
            }
        }
        if (rs.gscreen == feed_view.screen_loadout and rs.gloadout_tab == 1 and rs.gmarket_q_focus) {
            rs.gmarket_q_focus = false;
            blurred = true;
        }
        if (rs.gscreen == feed_view.screen_zones_browse and rs.gzones_q_focus) {
            rs.gzones_q_focus = false;
            blurred = true;
        }
        if (rs.gscreen == feed_view.screen_settings and rs.pet_name_focus) {
            rs.pet_name_focus = false;
            blurred = true;
        }
        if (blurred) return true;
    }
    if (rs.mode == .compose) {
        rs.mode = .timeline; // the draft is kept; ＋ reopens where you left off
        return true;
    }
    if (rs.gscreen == feed_view.screen_messages and rs.gchat_sel != null) {
        rs.gchat_sel = null; // the phone chat thread pops to the conversation list
        return true;
    }
    switch (rs.gscreen) {
        feed_view.screen_home => {
            // The double-back convention (owner asked for the TikTok pattern):
            // the FIRST back at the root shows a heads-up pill and arms a short
            // window; a second back inside it minimizes. Clock is shell-side.
            const now_ns = clock_shell.monotonicNanos();
            if (now_ns < rs.back_hint_until) return false; // second swipe → minimize
            rs.back_hint_until = now_ns + 2_000_000_000;
            return true; // consumed — the hint pill shows while armed
        },
        feed_view.screen_algo_docs => rs.gscreen = rs.docs_return_screen,
        feed_view.screen_algo_detail => rs.gscreen = feed_view.screen_loadout,
        feed_view.screen_transparency => {
            if (rs.gtransp_source) {
                rs.gtransp_source = false; // source sub-view → back to the summary
            } else {
                rs.gscreen = rs.transp_return_screen;
                if (rs.inspect_bytes) |b| gpa.free(b);
                rs.inspect_bytes = null;
                if (rs.inspect_src) |b| gpa.free(b);
                rs.inspect_src = null;
            }
        },
        feed_view.screen_thread => rs.gscreen = rs.thread_return_screen,
        feed_view.screen_zones => rs.gscreen = rs.zone_return_screen,
        // Every other top-level page (zones hub, loadout, settings, chat,
        // profile, activity) steps back to Home — the tab bar's own root.
        else => rs.gscreen = feed_view.screen_home,
    }
    rs.gscroll_px = 0;
    return true;
}

/// Recolour the seated lens of whichever surface has its detail sheet open
/// (item 5). Writes the palette index back to the tray card; flags the loadout
/// dirty so it persists. A no-op if the seat is out of range.
fn applyDetailColor(rs: *RunState, color: u8) void {
    const surf = rs.gcart_detail orelse return;
    const cards: []lens_socket.LensCard, const seated: u32 = switch (surf) {
        1 => .{ rs.reply_cards, rs.reply_seated },
        2 => .{ rs.zone_cards, rs.zone_seated },
        else => .{ rs.socket_cards, rs.gseated },
    };
    if (seated < cards.len) {
        cards[seated].color = color;
        rs.loadout_dirty = true;
    }
}

const DetailTarget = struct { card: lens_socket.LensCard, blob: []const u8 };
fn detailCardOf(rs: *RunState) ?DetailTarget {
    const surf = rs.gcart_detail orelse return null;
    const cards: []const lens_socket.LensCard, const blob: []const u8, const seated: u32 = switch (surf) {
        1 => .{ rs.reply_cards, rs.reply_blob, rs.reply_seated },
        2 => .{ rs.zone_cards, rs.zone_blob, rs.zone_seated },
        else => .{ rs.socket_cards, rs.socket_blob, rs.gseated },
    };
    if (seated >= cards.len) return null;
    return .{ .card = cards[seated], .blob = blob };
}

/// Diff, write, flush, and bring `prev` up to date with what is on screen.
const Mode = enum { timeline, compose, profile };

// ---------------------------------------------------------------------------
// Mode input handlers — the per-mode split that completes the recorded
// B3 thinning (deviation #1): run() keeps only dispatch; each mode's
// choreography lives in its own named function. Same parameter-passing
// house style as engageSelected: explicit values and pointers, no
// hidden context (D4: the coupling is loud and stays inside this file).
// ---------------------------------------------------------------------------

fn handleProfileInput(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
    out: *std.Io.Writer,
    backend: Backend,
    prev: *tui.Surface,
    next: *tui.Surface,
    status: *[]const u8,
    status_buf: []u8,
    mode: *Mode,
    profile_info: *?timeline_ui.ProfileInfo,
    ev: tui.InputEvent,
    now: i64,
) !void {
    switch (timeline_ui.actionForProfile(ev)) {
        .close => {
            mode.* = .timeline;
            status.* = "";
        },
        .follow => if (profile_info.*) |info| {
            if (info.did.len > 0 and !info.following) {
                status.* = "following...";
                timeline_ui.buildProfileFrame(next, info, status.*);
                try present(gpa, out, arena, prev, next, backend);
                const outcome = write.followAccount(gpa, arena, io, environ, session, info.did, now) catch |err| switch (err) {
                    error.OutOfMemory => return err,
                    else => {
                        status.* = "network error"; // contained (E2)
                        return;
                    },
                };
                switch (outcome) {
                    .ok => {
                        profile_info.*.?.following = true;
                        status.* = "followed";
                    },
                    .failed => |failure| status.* = std.fmt.bufPrint(status_buf, "refused: {d} {s}", .{
                        failure.status, failure.code,
                    }) catch "refused",
                }
            }
        },
        .none => {},
    }
}

/// A queued create-write for a post/reply that was already shown OPTIMISTICALLY
/// (seated in the store under `temp_cid`). The loop performs the write AFTER the
/// optimistic post is on screen, then reconciles the temp cid to the server's
/// real one (or drops the post on failure). Owns its strings (gpa) — they
/// outlive the cleared compose draft. One in flight at a time.
/// A7.2: cold struct, size guard waived — at most one in flight, transient.
// One post in a queued chain: its optimistic temp cid and its text. The
// inter-segment reply refs are NOT stored — they depend on each createPost's
// real result, so the drain threads them as it goes (seg i replies to seg i-1).
/// One queued post of a chain send — the worker's own segment shape (the
/// chain is handed to the write worker whole, no re-boxing at the seam).
const SendJob = write_worker.ChainSegment;

// The most posts one thread composer can queue at once (active box + finalized
// segments). A soft ceiling — a chain longer than this is almost never intended.
const max_chain_segments: usize = 25;

// A queued publish: one or more segments in thread order. `base_target` is what
// segment 0 replies to (a reply-chain), or null for a fresh thread. A single
// post is a one-segment chain with the whole feature collapsing to the old path.
// A7.2: cold struct, size guard waived — at most one in flight per compose.
const ChainSend = struct {
    segments: []SendJob,
    base_target: ?write.ReplyTarget,
    /// The quoted post's strong ref when segment 0 is a quote-post; null else.
    /// gpa-owned (dupe'd on send), freed in freeChain.
    base_quote: ?lexicon.RecordRef = null,
    /// The tag bar's record-level tags (locked + manual chips), riding EVERY
    /// segment — a thread posted into a zone lives in the zone whole. Each
    /// string gpa-owned (dupe'd on send), freed in freeChain.
    tags: [][]const u8 = &.{},
};

/// The composer TAG BAR's shell state: the LOCKED zone tag (composing from a
/// zone page — not removable), the manual "+ tag" chips, and the add-tag
/// input. Fixed buffers, nothing owned; reset with the composer.
/// A7.2: cold struct, size guard waived — one per session, never hot.
const ComposeTagBar = struct {
    locked_buf: [64]u8 = undefined,
    locked_len: u8 = 0,
    chips_buf: [max_manual_tags][32]u8 = undefined,
    chip_lens: [max_manual_tags]u8 = [_]u8{0} ** max_manual_tags,
    chips_n: u8 = 0,
    input_buf: [32]u8 = undefined,
    input_len: u8 = 0,
    input_focus: bool = false,
};
const max_manual_tags = 6;

fn tagBarLocked(bar: *const ComposeTagBar) []const u8 {
    return bar.locked_buf[0..bar.locked_len];
}
fn tagBarChip(bar: *const ComposeTagBar, i: usize) []const u8 {
    return bar.chips_buf[i][0..bar.chip_lens[i]];
}
fn tagBarReset(bar: *ComposeTagBar) void {
    bar.locked_len = 0;
    bar.chips_n = 0;
    bar.input_len = 0;
    bar.input_focus = false;
}
/// Commit the add-tag input as a manual chip: trim '#'/spaces, refuse empties
/// and duplicates (against the locked tag and the other chips), cap at
/// max_manual_tags. The input clears either way; focus stays for the next tag.
fn tagBarCommitInput(bar: *ComposeTagBar) void {
    const raw = std.mem.trim(u8, bar.input_buf[0..bar.input_len], " #\t");
    defer bar.input_len = 0;
    if (raw.len == 0 or bar.chips_n >= max_manual_tags) return;
    if (std.ascii.eqlIgnoreCase(raw, tagBarLocked(bar))) return;
    for (0..bar.chips_n) |i| if (std.ascii.eqlIgnoreCase(raw, tagBarChip(bar, i))) return;
    const n = bar.chips_n;
    @memcpy(bar.chips_buf[n][0..raw.len], raw);
    bar.chip_lens[n] = @intCast(raw.len);
    bar.chips_n = n + 1;
}
/// The bar's record-level tags for a send: locked first, then the chips —
/// filled into `out` (locked + max_manual_tags wide), returns the slice.
fn tagBarTags(bar: *const ComposeTagBar, out: *[1 + max_manual_tags][]const u8) []const []const u8 {
    var n: usize = 0;
    if (bar.locked_len > 0) {
        out[n] = tagBarLocked(bar);
        n += 1;
    }
    for (0..bar.chips_n) |i| {
        out[n] = tagBarChip(bar, i);
        n += 1;
    }
    return out[0..n];
}

fn dupeTarget(gpa: Allocator, t: ?write.ReplyTarget) !?write.ReplyTarget {
    const tt = t orelse return null;
    return .{
        .root_uri = try gpa.dupe(u8, tt.root_uri),
        .root_cid = try gpa.dupe(u8, tt.root_cid),
        .parent_uri = try gpa.dupe(u8, tt.parent_uri),
        .parent_cid = try gpa.dupe(u8, tt.parent_cid),
    };
}

fn freeTarget(gpa: Allocator, t: ?write.ReplyTarget) void {
    const tt = t orelse return;
    gpa.free(tt.root_uri);
    gpa.free(tt.root_cid);
    gpa.free(tt.parent_uri);
    gpa.free(tt.parent_cid);
}

fn freeChain(gpa: Allocator, cs: ChainSend) void {
    for (cs.segments) |seg| {
        gpa.free(seg.temp_cid);
        if (seg.text.len > 0) gpa.free(seg.text);
    }
    gpa.free(cs.segments);
    for (cs.tags) |t| gpa.free(t);
    if (cs.tags.len > 0) gpa.free(cs.tags);
    freeTarget(gpa, cs.base_target);
    if (cs.base_quote) |q| {
        gpa.free(q.uri);
        gpa.free(q.cid);
    }
}

// Input handling only mutates draft/compose state and QUEUES network writes
// (pending_send / pending_profile_save) for the loop to run after the
// optimistic UI is on screen — so it takes no I/O args of its own.
fn handleComposeInput(
    gpa: Allocator,
    session: *auth.Session,
    status: *[]const u8,
    mode: *Mode,
    /// The shared store — a send is optimistically ingested into it so it shows
    /// INSTANTLY (the 5s refresh would otherwise gate it).
    store: *feed_core.Store,
    compose: *textedit.Field,
    /// The finalized thread segments above the active box (empty for a lone post).
    /// On send they publish before the active box, all as one self-reply chain.
    chain_segments: *std.ArrayList([]const u8),
    reply_target: *?write.ReplyTarget,
    reply_handle: *[]const u8,
    /// The quoted post's strong ref when composing a quote-post; null otherwise.
    /// Cleared on send/cancel like reply_target. Attaches to the first segment.
    quote_target: *?lexicon.RecordRef,
    /// The quoted author's handle (the composer's "Quoting @x" line). Lives in
    /// the compose arena; cleared with quote_target so no reference survives the
    /// next arena reset.
    quoting_handle: *[]const u8,
    compose_kind: ComposeKind,
    /// The composer's TAG BAR (locked zone tag + manual chips): its tags ride
    /// the send as record-level tags; reset with the composer on send/cancel.
    tagbar: *ComposeTagBar,
    /// The live render grid (for the post-send scroll-to-top).
    pix: ?Grid,
    /// Set by a post/reply send: the queued create-write(s) the loop performs
    /// AFTER the optimistic posts are on screen (0ms). Null when nothing queued.
    pending_send: *?ChainSend,
    /// Set by a profile-edit save: the display name to putProfile, run by the
    /// loop after the name is optimistically shown. gpa-owned; null when idle.
    pending_profile_save: *?[]const u8,
    ev: tui.InputEvent,
    now: i64,
) !void {
    switch (timeline_ui.actionForCompose(ev)) {
        .cancel => {
            // Drop any finalized thread segments so they don't leak or bleed into
            // the next compose session (C5).
            for (chain_segments.items) |s| gpa.free(s);
            chain_segments.clearRetainingCapacity();
            quote_target.* = null;
            quoting_handle.* = "";
            tagBarReset(tagbar);
            mode.* = .timeline;
            status.* = "cancelled";
        },
        .backspace => textedit.backspace(compose),
        .delete_fwd => textedit.deleteForward(compose),
        .left => textedit.left(compose),
        .right => textedit.right(compose),
        .home => textedit.home(compose),
        .end => textedit.end(compose),
        .insert => |cp| {
            if (timeline_ui.countCodepoints(textedit.view(compose)) >= 300) {
                status.* = "300 character limit";
            } else {
                var utf8_buf: [4]u8 = undefined;
                const len = std.unicode.utf8Encode(cp, &utf8_buf) catch 0;
                if (len > 0) textedit.insert(compose, utf8_buf[0..len]);
            }
        },
        .send => {
            // A half-typed tag in the bar's input still counts — commit it
            // rather than silently dropping it with the send.
            if (tagbar.input_len > 0) tagBarCommitInput(tagbar);
            const active = textedit.view(compose);
            // Profile editor: upsert the self profile record, then return to the
            // profile screen (mode→timeline re-enters it and re-fetches, so the
            // new name shows once the AppView re-polls the record).
            if (compose_kind == .profile) {
                if (active.len == 0) {
                    status.* = "name can't be empty";
                    return;
                }
                // 0ms: set the display name locally NOW (guarded against a stale
                // refresh), close to the profile, and queue the putProfile write
                // for the loop to run after — the new name shows instantly.
                feed_core.setOwnDisplayName(gpa, store, session.did, active) catch {};
                pending_profile_save.* = gpa.dupe(u8, active) catch null;
                textedit.clear(compose);
                mode.* = .timeline;
                status.* = "name updated";
                return;
            }
            // The ordered segment texts: the finalized chain, then the active box
            // if it still holds anything. A lone post is a chain of one.
            const total = chain_segments.items.len + @as(usize, if (active.len > 0) 1 else 0);
            if (total == 0) {
                status.* = "nothing to post";
                return;
            }
            const base = reply_target.*;
            const quote = quote_target.*; // attaches to segment 0 only
            // The tag bar's record-level tags (the locked zone tag + the
            // manual chips) — they ride EVERY segment; inline #tags keep
            // riding the text as facets, resolved at write time.
            var bar_buf: [1 + max_manual_tags][]const u8 = undefined;
            const bar_tags = tagBarTags(tagbar, &bar_buf);
            // TRULY 0ms: seat every segment in the store under TEMPORARY cids,
            // threaded to each other so they render as a stitched self-thread THIS
            // frame; the create writes are queued (`pending_send`) and run by the
            // loop after, reconciling each temp cid to the server's real one. The
            // temp cids are unique: `posts.len` only grows as we ingest.
            var segs = try gpa.alloc(SendJob, total);
            var filled: usize = 0;
            errdefer {
                for (segs[0..filled]) |s| {
                    gpa.free(s.temp_cid);
                    if (s.text.len > 0) gpa.free(s.text);
                }
                gpa.free(segs);
            }
            var prev_temp: []const u8 = ""; // previous segment's temp cid → next parent
            var root_temp: []const u8 = ""; // first segment's temp cid → the thread root
            var i: usize = 0;
            while (i < total) : (i += 1) {
                const seg_text = if (i < chain_segments.items.len)
                    chain_segments.items[i]
                else
                    active;
                const temp_cid = try std.fmt.allocPrint(gpa, "pending:{d}", .{store.posts.len});
                // Segment 0 replies to the external base (or nothing); later
                // segments reply to the previous segment, rooted at the base's
                // root when replying, else at segment 0.
                const parent_cid = if (i == 0) (if (base) |b| b.parent_cid else "") else prev_temp;
                const root_cid = if (i == 0)
                    (if (base) |b| b.root_cid else "")
                else
                    (if (base) |b| b.root_cid else root_temp);
                // The optimistic seat carries its zone tags so the tray shows
                // THIS frame: the segment's inline #tags + the bar's tags.
                var seat_tags: std.ArrayList([]const u8) = .empty;
                defer seat_tags.deinit(gpa);
                if (compose_core.inlineTags(gpa, seg_text)) |il| {
                    defer gpa.free(il);
                    seat_tags.appendSlice(gpa, il) catch {};
                } else |_| {}
                seat_tags.appendSlice(gpa, bar_tags) catch {};
                _ = feed_core.ingestLivePost(gpa, store, .{
                    .did = session.did,
                    .handle = session.handle,
                    .uri = "",
                    .cid = temp_cid,
                    .text = seg_text,
                    .reply_parent_cid = parent_cid,
                    .reply_root_cid = root_cid,
                    .quote_of_cid = if (i == 0) (if (quote) |q| q.cid else "") else "",
                    .created_at = now + @as(i64, @intCast(i)), // keep chain order stable
                    .tags = seat_tags.items,
                }) catch {};
                segs[i] = .{ .temp_cid = temp_cid, .text = try gpa.dupe(u8, seg_text) };
                filled = i + 1;
                if (i == 0) root_temp = temp_cid;
                prev_temp = temp_cid;
            }
            if (base) |t| feed_core.bumpReplyCount(store, t.parent_cid); // only seg 0 replies out
            const base_quote: ?lexicon.RecordRef = if (quote) |q|
                .{ .uri = try gpa.dupe(u8, q.uri), .cid = try gpa.dupe(u8, q.cid) }
            else
                null;
            // The bar tags outlive the composer (the drain sends them) —
            // gpa-owned dupes, freed with the chain.
            var send_tags: [][]const u8 = &.{};
            if (bar_tags.len > 0) {
                send_tags = try gpa.alloc([]const u8, bar_tags.len);
                var tn: usize = 0;
                errdefer {
                    for (send_tags[0..tn]) |t| gpa.free(t);
                    gpa.free(send_tags);
                }
                for (bar_tags) |t| {
                    send_tags[tn] = try gpa.dupe(u8, t);
                    tn += 1;
                }
            }
            pending_send.* = .{ .segments = segs, .base_target = try dupeTarget(gpa, base), .base_quote = base_quote, .tags = send_tags };
            // Ownership of the queued texts now rides `segs`; release the finalized
            // drafts and reset the composer.
            for (chain_segments.items) |s| gpa.free(s);
            chain_segments.clearRetainingCapacity();
            textedit.clear(compose);
            reply_target.* = null;
            reply_handle.* = "";
            quote_target.* = null;
            quoting_handle.* = "";
            tagBarReset(tagbar);
            mode.* = .timeline;
            if (pix) |g| g.scroll.* = 0; // jump to top so you see your posts land
            status.* = "";
        },
        .none => {},
    }
}

// ---------------------------------------------------------------------------
// Engagement — the like/boost twins, unified (the first cut of the
// recorded B3 thinning: one body, two verbs; the run loop keeps only
// control flow). Optimistic apply paints first; any refusal reverts.
// ---------------------------------------------------------------------------

const Engagement = enum { like, repost };

/// What the reused compose flow writes on send — a feed post, or the self
/// profile record (the in-app profile editor reuses the composer's input).
const ComposeKind = enum { post, profile };

/// The discover-engine config a surface's seated lens resolves to, or null when
/// that lens is the no-scoring path (Following / Most Recent) — then the surface
/// stays its plain builder (feed order, or chronological threading). Surface-
/// agnostic: the SAME resolver serves the feed tray and the reply tray, because
/// the tray is the user's and identical on every surface (DISCOVER invariant 12).
/// Empty tray ⇒ null (E4).
fn seatedLensConfig(arena: Allocator, lib: *const algo_library.Library, cards: []const lens_socket.LensCard, blob: []const u8, seated: u32) ?discover.FeedConfig {
    if (cards.len == 0) return null;
    const idx = @min(seated, @as(u32, @intCast(cards.len - 1)));
    const span = cards[idx].cid;
    const cid = blob[span.off..][0..span.len];
    // Library-aware: a seated created/installed algorithm scores through the
    // same one engine as a built-in (invariant 1). Parsed slices live in the
    // frame arena (C3) — scoring happens within this frame.
    return lens_catalog.scoringConfig(arena, cid, lib) catch null;
}

/// Build the ACTIVE view's posts over the SHARED store — Home (scored by the
/// seated feed lens, or chronological), a post's thread (sibling order composed
/// onto threading by the seated reply lens), the profile author query, or a
/// zone. The single place "which view is showing" is decided, for both the main
/// loop and engageSelected's optimistic repaint. `now` is the shell's clock
/// reading, handed to the pure scorer (invariant 9).
/// Zat Chat (U3): the per-frame view bundle for the Messages surface. A7.2:
/// cold struct, size guard waived — one transient per frame, never collected.
const ChatFrame = struct {
    list: []const chat_view_core.ListRow = &.{},
    thread: []const chat_view_core.BubbleRow = &.{},
    /// The thread's payment cards, addressed by `BubbleRow.pay` (M5 A4).
    cards: []chat_view_core.PayCard = &.{},
    sel: u16 = std.math.maxInt(u16),
    peer: []const u8 = "",
    /// The open thread's stable message keys, parallel to `thread` (U6b): the
    /// shell maps its per-bubble springs onto rows by matching these. Empty
    /// when no conversation is selected.
    order: []const chat_core.MsgIndex = &.{},
};

/// Resolve the Messages surface's view-models from the one chat store: the
/// conversation list, the open thread, the selected ordinal, and the peer
/// label. Pure queries into the frame arena (C3); the ordinal is the value
/// the surface's tap regions carry.
/// M1 send: encrypt the just-typed draft to the conversation's peer and
/// deposit it on the relay (chat_e2ee owns the crypto + persistence). A null
/// session/link (no ZAT4_RELAY) keeps the send local-only — the bubble still
/// shows, it just doesn't transmit. A crypto/relay error is a status line,
/// never a crash (E2). `env` feeds the persist-after-send.
fn chatSend(gpa: Allocator, io: std.Io, env: ?*const std.process.Environ.Map, st: ?*chat_e2ee.State, link: ?*chat_relay.ChatRelay, cs: *const chat_core.Store, conv: chat_core.ConvIndex, text: []const u8) void {
    const state = st orelse return;
    const l = link orelse return;
    chatLog("[chat] send -> {s} ({d} bytes)", .{ chat_core.conversationDid(cs, conv), text.len });
    const peer_did = chat_core.conversationDid(cs, conv);
    // A swallowed send error is how a message "disappears": the bubble appears,
    // nothing leaves, and nobody is told. Say it.
    chat_e2ee.send(gpa, io, env, state, l, peer_did, .text, text) catch |err|
        chatLog("[chat] SEND FAILED -> {s}: {s}", .{ peer_did, @errorName(err) });
}

/// Bring the whole chat stack up: the E2EE session (anchor + keyPackage +
/// restored MLS groups), the relay link, the restored transcript. Called once
/// at startup, and AGAIN if the user chooses "set up chat fresh here" (A3) —
/// which is the entire reason it is a function rather than an inline block.
///
/// `adopt` (A3) is the user's explicit answer to "your chat identity lives on
/// another device": true means replace the published key and start over here.
/// It is never true unless a human clicked it.
fn chatBringUp(
    rs: *RunState,
    gpa: Allocator,
    io: std.Io,
    env: ?*const std.process.Environ.Map,
    session: *auth.Session,
    adopt: bool,
) void {
    const rhost = rs.gchat_host_buf[0..rs.gchat_host_len];
    _ = rs.gchat_arena_state.reset(.retain_capacity);
    var st = chat_e2ee.init(gpa, rs.gchat_arena_state.allocator(), io, env, session, adopt) catch |err| {
        chatLog("[chat] E2EE init failed: {s}", .{@errorName(err)});
        // A3 — the one failure that is not a failure but a FACT the user has to
        // be told. Chat was set up on another device, and the key that owns it
        // cannot be copied here; that is exactly what makes it worth having.
        // The Messages screen says so, and offers the only honest way forward.
        rs.gchat_identity_elsewhere = (err == error.IdentityElsewhere);
        // MULTI-DEVICE: the wall is now a question with two answers. "We asked and
        // are waiting" is not the same screen as "chat lives elsewhere and you have
        // not asked" — one waits, the other offers a button, and a person can tell
        // instantly which of the two they are in.
        rs.gdev_state = switch (err) {
            error.DeviceApprovalPending => .pending,
            error.IdentityElsewhere => .elsewhere,
            else => rs.gdev_state,
        };
        return;
    };
    rs.gchat_identity_elsewhere = false;
    rs.gdev_state = .ok; // we are part of the account: no gate, and we can approve others
    rs.gchat_e2ee = st;
    // What did this account say the one time we asked? (Never asked ⇒ the setup is
    // due, and it goes in front of everything else on this screen.)
    chatPrefsLoad(rs, gpa, env, session.did);

    // M2.1: bootstrap inbox (Welcomes) + every restored conversation's
    // current-epoch traffic mailbox.
    if (chat_e2ee.subscriptions(gpa, &st)) |subs| {
        defer gpa.free(subs);
        // A4 slice 2: the link carries THIS DEVICE'S identity — the DID and the
        // anchor seed that proves it. The relay challenges us and we sign; a
        // relay that has flipped to require_auth admits nothing else. The seed
        // is the same key the directory already publishes for us.
        rs.gchat_link = chat_relay.start(gpa, io, &rs.gchat_box, rhost, rs.gchat_port, rs.gchat_token, rs.gchat_use_tls, subs, st.my_did, st.anchor_seed) catch null;
    } else |_| {}

    // Restore the displayed history (M2) first. A missing or corrupt blob is a
    // cold start, never a half-restore (the codec is strict) — the mirror below
    // still recovers the conversation LIST from the MLS groups; only the
    // transcript would be gone.
    var hist_path_buf: [512]u8 = undefined;
    if (cache_shell.chatHistoryPath(&hist_path_buf, env, st.my_did)) |hist_path| {
        if (cache_shell.loadChatHistoryAt(gpa, hist_path, st.my_did)) |blob| {
            defer {
                std.crypto.secureZero(u8, blob);
                gpa.free(blob);
            }
            if (chat_core.deserializeStore(gpa, blob)) |restored| {
                chat_core.deinitStore(gpa, &rs.gchat_store);
                rs.gchat_store = restored;
            } else |_| {}
        }
    }
    // Mirror restored conversations into the view store so they show on launch
    // (openConversation dedupes by DID, so ones already in the history blob are
    // found, not doubled), then persist once to heal any divergence.
    for (st.peer_dids.items) |did| {
        _ = chat_core.openConversation(gpa, &rs.gchat_store, did, "") catch {};
    }
    // HEAL-GUARD (final-product law: chats are never lost by machinery, only by
    // the user): persist at init ONLY when something was actually restored — a
    // failed restore writing the empty store would DESTROY the very blob it
    // failed to read.
    if (st.peer_dids.items.len > 0 or rs.gchat_store.convs.len > 0)
        chatPersistHistory(gpa, io, env, &st, &rs.gchat_store);

    if (rs.gchat_link != null) {
        chatLog("[chat] E2EE up -> {s} ({d} conversation(s) restored)", .{ rhost, st.peer_dids.items.len });
        // THE mailboxes. A Welcome deposited into an address the peer is not
        // draining is delivered nowhere, forever, and says nothing. Print both ends.
        var hb: [16]u8 = undefined;
        chatLog("[chat]   my inbox  = {s}  (Welcomes to me land here)", .{chat_e2ee.mailboxHex(&hb, chat_e2ee.inbox(&st))});
        for (st.peer_dids.items) |pd| {
            if (chat_e2ee.peerBootstrap(&st, pd)) |pb| {
                var hb2: [16]u8 = undefined;
                chatLog("[chat]   peer {s} bootstrap = {s}", .{ pd, chat_e2ee.mailboxHex(&hb2, pb) });
            }
        }
    } else {
        chatLog("[chat] keys ready but the relay link did NOT start", .{});
    }
}

/// Account creation, off the render thread. `enroll_run` runs this INLINE on its
/// loop — which is fine in a window whose only job is the card, and is not fine
/// here, where the same thread is drawing the app. A createAccount is a PDS
/// round-trip plus a membership-record write; on a phone that is seconds.
/// A7.2: cold struct, size guard waived — one in flight, ever.
// ─────────────── multi-device: the network legs, on a worker ───────────────
//
// Asking to join, approving, refusing, and polling for who is waiting are all
// network round-trips, and NONE of them may run on the thread that draws (the
// standing law — a chain-send once froze the app for five seconds and that was
// strike three). The UI states the intent; the worker does the trip; the loop
// drains the result.

const DeviceJob = struct {
    // A7.2: cold struct (one live instance, holds a thread), size guard waived.
    thread: ?std.Thread = null,
    done: std.atomic.Value(bool) = .init(false),
    kind: enum { none, ask, approve, refuse, poll, status } = .none,
    /// `status`: where this device now stands with the account.
    status: chat_keys.DeviceStatus = .not_asked,
    ok: bool = false,
    /// `poll`: what the repo says is waiting. Copied out as bytes — the worker's
    /// arena dies with it, so nothing it allocated escapes.
    found: bool = false,
    name: [48]u8 = undefined,
    name_len: u8 = 0,
    fp: [24]u8 = undefined,
    fp_len: u8 = 0,
    at: i64 = 0,
    anchor_pub: [32]u8 = undefined,
    rkey: [32]u8 = undefined,
    rkey_len: u8 = 0,
    /// The device we are approving/refusing (copied in by the main thread).
    target_anchor: [32]u8 = undefined,
    target_rkey: [32]u8 = undefined,
    target_rkey_len: u8 = 0,
    target_kp: [4096]u8 = undefined,
    target_kp_len: u16 = 0,
    target_sig: [128]u8 = undefined,
    target_sig_len: u8 = 0,
    target_na: [32]u8 = undefined,
    target_na_len: u8 = 0,
    io: std.Io = undefined,
    env: ?*const std.process.Environ.Map = null,
    session: ?*auth.Session = null,
};

const CreateJob = struct {
    // A7.2: cold struct (one live instance, holds a thread), size guard waived.
    thread: ?std.Thread = null,
    done: std.atomic.Value(bool) = .init(false),
    active: bool = false,
    /// The result. Null = it failed, and the card says so rather than hanging.
    session: ?auth.Session = null,
};

/// Open a conversation with one person from the roster our other device sent. The
/// store row first (so the person appears in the list immediately, even if the
/// network leg is slow), then the crypto.
fn chatStartWith(
    rs: *RunState,
    gpa: Allocator,
    io: std.Io,
    env: ?*const std.process.Environ.Map,
    st: *chat_e2ee.State,
    did: []const u8,
) void {
    const link = rs.gchat_link orelse return;
    _ = chat_core.openConversation(gpa, &rs.gchat_store, did, "") catch null;
    _ = rs.gchat_arena_state.reset(.retain_capacity);
    chat_e2ee.startConversation(gpa, rs.gchat_arena_state.allocator(), io, env, st, link, did) catch |err| {
        // Not fatal, and not silent. The person is in the list; the channel will be
        // built by the next attempt, or by them messaging us.
        chatLog("[chat] roster: couldn't open {s}: {s}", .{ did, @errorName(err) });
        return;
    };
    chatLog("[chat] roster: opened {s}", .{did});
    // The new session has its own traffic mailbox — drain it, or the conversation
    // we just opened would be one we could never hear from.
    chatEnsureSubs(gpa, st, link);
}

/// Check ONE conversation's device set (slice 4), in rotation. When somebody has
/// started chat on a new device, SAY SO in the thread — a line of grey text, and
/// the difference between an encrypted app and an app that IS encrypted.
fn peerRefreshNext(
    rs: *RunState,
    gpa: Allocator,
    io: std.Io,
    env: ?*const std.process.Environ.Map,
    st: *chat_e2ee.State,
    now: i64,
) void {
    const link = rs.gchat_link orelse return;
    const n = rs.gchat_store.convs.len;
    if (n == 0) return;
    if (rs.gpeer_refresh_i >= n) rs.gpeer_refresh_i = 0;
    const conv: chat_core.ConvIndex = @enumFromInt(rs.gpeer_refresh_i);
    rs.gpeer_refresh_i += 1;

    const did = chat_core.conversationDid(&rs.gchat_store, conv);
    if (did.len == 0 or std.mem.eql(u8, did, st.my_did)) return; // never ourselves
    _ = rs.gchat_arena_state.reset(.retain_capacity);
    const what = chat_e2ee.refreshPeer(gpa, rs.gchat_arena_state.allocator(), io, env, st, link, did);
    switch (what) {
        .unchanged => {},
        .updated => {
            // They added or retired a device. Housekeeping, not news — we now reach
            // every device they have, and nobody needs to be interrupted about it.
            chatLog("[chat] devices changed for {s} — sessions updated", .{did});
            chatEnsureSubs(gpa, st, link);
        },
        .reset => {
            // EVERY device we knew of theirs is gone. Their messages will reach us
            // again — and the person MUST be told, because "their keys changed and
            // everything carried on quietly" is precisely what a successful
            // impersonation looks like. It costs one line of grey text, and it is the
            // whole difference between an encrypted app and an app that IS encrypted.
            chatLog("[chat] {s} STARTED CHAT ON A NEW DEVICE — sessions rebuilt", .{did});
            chatEnsureSubs(gpa, st, link);
            const handle = chat_core.conversationHandle(&rs.gchat_store, conv);
            const who = if (handle.len > 0) handle else did;
            var buf: [160]u8 = undefined;
            const line = std.fmt.bufPrint(&buf, "{s} started chat on a new device. If that wasn't them, ask them.", .{who}) catch
                "They started chat on a new device. If that wasn't them, ask them.";
            _ = chat_core.appendMessage(gpa, &rs.gchat_store, conv, .system, line, now, false) catch {};
            chatPersistHistory(gpa, io, env, st, &rs.gchat_store);
            rs.status = "chat: they started chat on a new device";
        },
    }
}

/// Hand our other devices the list of people we talk to (slice 3) — but only when
/// there is something new to say. The signature folds in BOTH the conversation list
/// and how many self-sessions we hold, so a device joining is itself a change.
fn rosterPublish(
    rs: *RunState,
    gpa: Allocator,
    io: std.Io,
    env: ?*const std.process.Environ.Map,
    st: *chat_e2ee.State,
    now: i64,
) void {
    _ = now;
    const link = rs.gchat_link orelse return;
    _ = rs.gchat_arena_state.reset(.retain_capacity);
    const arena = rs.gchat_arena_state.allocator();

    // Our other devices, and a session with each. A device that was approved while
    // this one was asleep is picked up right here.
    const selves = chat_e2ee.ensureSelfSessions(gpa, arena, io, env, st, link);
    if (selves == 0) return; // no other device: nobody to tell

    // The list, newline-joined. The people — not the history, and not their names.
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(gpa);
    var sig: u64 = @intCast(selves);
    const n = rs.gchat_store.convs.len;
    var i: usize = 0;
    while (i < n) : (i += 1) {
        const did = chat_core.conversationDid(&rs.gchat_store, @enumFromInt(i));
        if (did.len == 0 or std.mem.eql(u8, did, st.my_did)) continue; // never ourselves
        buf.appendSlice(gpa, did) catch return;
        buf.append(gpa, '\n') catch return;
        for (did) |c| {
            sig ^= c;
            sig *%= 1099511628211;
        }
    }
    if (buf.items.len == 0) return;
    if (sig == rs.groster_sig) return; // nothing has changed; say nothing
    chat_e2ee.sendRoster(gpa, io, env, st, link, buf.items) catch |err| {
        chatLog("[chat] roster: send failed: {s}", .{@errorName(err)});
        return; // do NOT bank the signature: an unsent roster must be retried
    };
    rs.groster_sig = sig;
    chatLog("[chat] roster -> our other device(s): {d} people", .{n});
}

/// The multi-device surfaces' snapshot: plain values in, pixels out.
fn chatDevicesOf(rs: *RunState, arena: Allocator) feed_view.ChatDevices {
    var pend: []const feed_view.PendingDeviceView = &.{};
    if (rs.gdev_pend_have) {
        const rows = arena.alloc(feed_view.PendingDeviceView, 1) catch return .{};
        rows[0] = .{
            .name = if (rs.gdev_pend_name_len > 0) rs.gdev_pend_name[0..rs.gdev_pend_name_len] else "A new device",
            .fingerprint = rs.gdev_pend_fp[0..rs.gdev_pend_fp_len],
            .age = deviceAge(arena, rs.gdev_pend_at),
        };
        pend = rows;
    }
    const now = clock_shell.monotonicNanos();
    // The confirmation holds for a beat, then fades. An approval that vanished the
    // instant it landed would leave a person wondering whether they tapped it.
    var added_t: f32 = 0;
    if (rs.gdev_added_ns != 0) {
        const el: f32 = @floatFromInt(now -| rs.gdev_added_ns);
        added_t = el / 2_600_000_000.0;
        if (added_t >= 1.0) added_t = 0; // retired
    }
    return .{
        .state = rs.gdev_state,
        .pending = pend,
        .busy = rs.gdev_busy,
        .error_line = rs.gdev_error,
        .added_t = added_t,
        .added_name = rs.gdev_added_name[0..rs.gdev_added_len],
        .t = @as(f32, @floatFromInt(@mod(now / 1_000_000, 100_000))) / 1000.0,
        // The offer belongs on exactly one screen: a device that is IN the account
        // and has no history of its own. Anywhere else it would be an invitation to
        // do something that makes no sense.
        .history = if (rs.gdev_hist_state != .none)
            rs.gdev_hist_state
        else if (rs.gchat_e2ee != null and rs.gchat_store.convs.len == 0 and rs.gdev_state == .ok)
            .offered
        else
            .none,
        .help_open = rs.gdev_help,
        .consent_open = rs.gchat_consent_open,
        .consent_receipts = rs.gchat_receipts,
        .consent_typing = rs.gchat_typing_on,
    };
}

/// Load what this account said the one time we asked (slice 1). Never asked = the
/// screen is due; and "never asked" is NOT the same as "said no", which is exactly
/// why the fact is stored rather than inferred from the two flags.
fn chatPrefsLoad(rs: *RunState, gpa: Allocator, env: ?*const std.process.Environ.Map, did: []const u8) void {
    var buf: [512]u8 = undefined;
    const path = cache_shell.chatPrefsPath(&buf, env, did) orelse return;
    const bits = cache_shell.loadChatPrefsAt(gpa, path) orelse {
        rs.gchat_asked = false;
        rs.gchat_consent_open = true; // first time in: ask, once
        return;
    };
    rs.gchat_asked = (bits & cache_shell.chat_prefs_asked) != 0;
    rs.gchat_receipts = (bits & cache_shell.chat_prefs_receipts) != 0;
    rs.gchat_typing_on = (bits & cache_shell.chat_prefs_typing) != 0;
    rs.gchat_consent_open = !rs.gchat_asked;
}

fn chatPrefsSave(rs: *RunState, env: ?*const std.process.Environ.Map, did: []const u8) void {
    var buf: [512]u8 = undefined;
    const path = cache_shell.chatPrefsPath(&buf, env, did) orelse return;
    var bits: u8 = cache_shell.chat_prefs_asked;
    if (rs.gchat_receipts) bits |= cache_shell.chat_prefs_receipts;
    if (rs.gchat_typing_on) bits |= cache_shell.chat_prefs_typing;
    _ = cache_shell.saveChatPrefsAt(path, bits);
}

/// "just now" / "4 minutes ago". A request that appeared while you were asleep
/// deserves more suspicion than one you just triggered, and the surface should let
/// a person notice that for themselves.
fn deviceAge(arena: Allocator, at: i64) []const u8 {
    if (at == 0) return "just now";
    const secs = clock_shell.unixSeconds() - at;
    if (secs < 90) return "just now";
    const mins = @divTrunc(secs, 60);
    if (mins < 60) return std.fmt.allocPrint(arena, "{d} minutes ago", .{mins}) catch "recently";
    const hours = @divTrunc(mins, 60);
    if (hours < 24) return std.fmt.allocPrint(arena, "{d} hours ago", .{hours}) catch "recently";
    return std.fmt.allocPrint(arena, "{d} days ago", .{@divTrunc(hours, 24)}) catch "a while ago";
}

/// Every frame Messages is up: keep the device gate's facts current, and drain any
/// worker that has landed. All of the network is on the worker; none of it is here.
fn chatDevicesStep(rs: *RunState, gpa: Allocator, io: std.Io, env: ?*const std.process.Environ.Map, session: *auth.Session) void {
    const job = &rs.gdev_job;

    // Drain a finished leg.
    if (job.thread != null and job.done.load(.acquire)) {
        job.thread.?.join();
        job.thread = null;
        rs.gdev_busy = false;
        switch (job.kind) {
            .ask => {
                if (job.ok) {
                    rs.gdev_state = .pending; // now we wait, and the screen says so
                    rs.gdev_error = "";
                } else rs.gdev_error = "Couldn't ask right now. Check your connection.";
            },
            .approve => {
                if (job.ok) {
                    // Say it landed, by name, for a beat.
                    const n = @min(rs.gdev_pend_name_len, rs.gdev_added_name.len);
                    @memcpy(rs.gdev_added_name[0..n], rs.gdev_pend_name[0..n]);
                    rs.gdev_added_len = @intCast(n);
                    rs.gdev_added_ns = clock_shell.monotonicNanos();
                    rs.gdev_pend_have = false;
                    rs.gdev_error = "";
                } else rs.gdev_error = "Couldn't approve it. Try again.";
            },
            .refuse => {
                if (job.ok) {
                    rs.gdev_pend_have = false;
                    // NOT a dismiss. Somebody signed in as this account, and the
                    // person deserves to be told what that means.
                    rs.gdev_error = "Refused. Someone signed in as you \u{2014} change your password.";
                } else rs.gdev_error = "Couldn't refuse it. Try again.";
            },
            .status => {
                // Approved. Bring chat up right here: the person is looking at the
                // waiting screen, and the next thing they should see is their
                // conversations — not a prompt to restart the app.
                if (job.ok and (job.status == .approved or job.status == .root)) {
                    rs.gdev_state = .ok;
                    rs.gdev_error = "";
                    chatBringUp(rs, gpa, io, env, session, false);
                }
            },
            .poll => {
                if (job.ok) {
                    if (job.found) {
                        rs.gdev_pend_have = true;
                        rs.gdev_pend_anchor = job.anchor_pub;
                        rs.gdev_pend_rkey_len = job.rkey_len;
                        @memcpy(rs.gdev_pend_rkey[0..job.rkey_len], job.rkey[0..job.rkey_len]);
                        rs.gdev_pend_name_len = job.name_len;
                        @memcpy(rs.gdev_pend_name[0..job.name_len], job.name[0..job.name_len]);
                        rs.gdev_pend_fp_len = job.fp_len;
                        @memcpy(rs.gdev_pend_fp[0..job.fp_len], job.fp[0..job.fp_len]);
                        rs.gdev_pend_at = job.at;
                    } else if (rs.gdev_added_ns == 0) {
                        rs.gdev_pend_have = false;
                    }
                }
            },
            .none => {},
        }
        job.kind = .none;
    }

    if (job.thread != null) return;
    const now = clock_shell.monotonicNanos();

    // WAITING: ask, quietly and repeatedly, whether we have been let in. This is
    // what makes "this page updates itself" true — and it is why the waiting screen
    // needs no refresh button, which would only be a way for a person to feel that
    // nothing is happening.
    if (rs.gdev_state == .pending) {
        if (rs.gdev_poll_ns != 0 and now -| rs.gdev_poll_ns < 8_000_000_000) return; // every 8s
        rs.gdev_poll_ns = now;
        startDeviceJob(rs, gpa, io, env, session, .status);
        return;
    }

    // IN THE ACCOUNT: is anybody asking to join? Only a device that is actually in
    // has anybody to approve — a device at the gate has nothing to answer.
    if (rs.gchat_e2ee == null or rs.gdev_state != .ok) return;
    if (rs.gdev_poll_ns != 0 and now -| rs.gdev_poll_ns < 20_000_000_000) return; // every 20s
    rs.gdev_poll_ns = now;
    startDeviceJob(rs, gpa, io, env, session, .poll);
}

fn startDeviceJob(rs: *RunState, gpa: Allocator, io: std.Io, env: ?*const std.process.Environ.Map, session: *auth.Session, kind: @TypeOf(@as(DeviceJob, undefined).kind)) void {
    const job = &rs.gdev_job;
    if (job.thread != null) return;
    job.kind = kind;
    job.io = io;
    job.env = env;
    job.session = session;
    job.ok = false;
    job.found = false;
    job.done.store(false, .monotonic);
    // Approve/refuse act on the pending device we are SHOWING — copied in, so the
    // worker never reads state the render thread is mutating.
    if (kind == .approve or kind == .refuse) {
        job.target_anchor = rs.gdev_pend_anchor;
        job.target_rkey_len = rs.gdev_pend_rkey_len;
        @memcpy(job.target_rkey[0..job.target_rkey_len], rs.gdev_pend_rkey[0..rs.gdev_pend_rkey_len]);
    }
    job.thread = std.Thread.spawn(.{}, deviceWorker, .{ job, gpa }) catch null;
    if (job.thread == null) {
        job.done.store(true, .release);
        return;
    }
    if (kind != .poll) rs.gdev_busy = true; // the button says so; the poll is silent
}

fn deviceWorker(job: *DeviceJob, gpa: Allocator) void {
    const a = std.heap.page_allocator;
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();
    const session = job.session orelse {
        job.done.store(true, .release);
        return;
    };

    switch (job.kind) {
        .ask => {
            chat_keys.requestJoin(gpa, arena, job.io, job.env, session, deviceLabel(job.env)) catch {
                job.done.store(true, .release);
                return;
            };
            job.ok = true;
        },
        .approve, .refuse => {
            if (job.kind == .refuse) {
                chat_keys.refuseDevice(gpa, arena, job.io, job.env, session, job.target_rkey[0..job.target_rkey_len]) catch {
                    job.done.store(true, .release);
                    return;
                };
            } else {
                chat_keys.approveDevice(gpa, arena, job.io, job.env, session, .{
                    .anchor_pub = job.target_anchor,
                    .name = "",
                    .created_at = 0,
                    .rkey = job.target_rkey[0..job.target_rkey_len],
                    .key_package_b64 = job.target_kp[0..job.target_kp_len],
                    .anchor_sig_b64 = job.target_sig[0..job.target_sig_len],
                    .not_after = job.target_na[0..job.target_na_len],
                }) catch {
                    job.done.store(true, .release);
                    return;
                };
            }
            job.ok = true;
        },
        .status => {
            // HAS ANYBODY SAID YES YET? The waiting screen asks this on a worker,
            // never on the thread that draws — a screen that freezes while it waits
            // is worse than one that says nothing.
            job.status = chat_keys.ensureDevice(gpa, arena, job.io, job.env, session, deviceLabel(job.env)) catch {
                job.done.store(true, .release);
                return;
            };
            job.ok = true;
        },
        .poll => {
            // Who is asking? Only devices our OWN trusted set does not already
            // contain, and only records that actually validate — junk must never be
            // able to put a prompt in front of a person.
            const set = chat_keys.fetchPeerDevices(gpa, arena, job.io, job.env, session.did) catch null;
            var trusted_buf: [16][32]u8 = undefined;
            var trusted: []const [32]u8 = &.{};
            if (set) |s| {
                var n: usize = 0;
                for (s.devices) |d| {
                    if (n == trusted_buf.len) break;
                    trusted_buf[n] = d.anchor_pub;
                    n += 1;
                }
                trusted = trusted_buf[0..n];
            }
            const pending = chat_keys.fetchPending(gpa, arena, job.io, job.env, session.did, trusted) catch &.{};
            if (pending.len > 0) {
                const p = pending[0];
                job.found = true;
                job.anchor_pub = p.anchor_pub;
                const nn = @min(p.name.len, job.name.len);
                @memcpy(job.name[0..nn], p.name[0..nn]);
                job.name_len = @intCast(nn);
                const rn = @min(p.rkey.len, job.rkey.len);
                @memcpy(job.rkey[0..rn], p.rkey[0..rn]);
                job.rkey_len = @intCast(rn);
                job.at = p.created_at;
                // The record's own bytes, kept so an approval can be written back
                // into it without inventing any field it already carries.
                const kn = @min(p.key_package_b64.len, job.target_kp.len);
                @memcpy(job.target_kp[0..kn], p.key_package_b64[0..kn]);
                job.target_kp_len = @intCast(kn);
                const sn = @min(p.anchor_sig_b64.len, job.target_sig.len);
                @memcpy(job.target_sig[0..sn], p.anchor_sig_b64[0..sn]);
                job.target_sig_len = @intCast(sn);
                const an = @min(p.not_after.len, job.target_na.len);
                @memcpy(job.target_na[0..an], p.not_after[0..an]);
                job.target_na_len = @intCast(an);
                job.fp_len = @intCast(deviceFingerprint(&job.fp, p.anchor_pub).len);
            }
            job.ok = true;
        },
        .none => {},
    }
    job.done.store(true, .release);
}

/// A short, readable check of a device's key: four groups of four. It answers "is
/// this the phone in my hand?" — a MIX-UP check, not a security control (an
/// attacker's device would show a matching one, because it IS the device asking).
/// Shown quietly; no ritual is built around it.
fn deviceFingerprint(out: *[24]u8, key: [32]u8) []const u8 {
    const hex = "0123456789abcdef";
    var n: usize = 0;
    for (0..8) |i| {
        if (i > 0 and i % 2 == 0 and n < out.len) {
            out[n] = ' ';
            n += 1;
        }
        if (n + 2 > out.len) break;
        out[n] = hex[key[i] >> 4];
        out[n + 1] = hex[key[i] & 0xF];
        n += 2;
    }
    return out[0..n];
}

fn deviceLabel(env: ?*const std.process.Environ.Map) []const u8 {
    if (env) |e| {
        if (e.get("ZAT_DEVICE_NAME")) |n| {
            if (n.len > 0) return n;
        }
    }
    return if (builtin.os.tag == .linux and builtin.abi.isAndroid()) "Phone" else "Desktop";
}

fn createWorker(job: *CreateJob, gpa: Allocator, io: std.Io, env: ?*const std.process.Environ.Map, st: *enroll_run.State) void {
    job.session = enroll_run.createZatAccount(gpa, io, env, st);
    job.done.store(true, .release);
}

/// The EXISTING branch's other half: an imported DID mints its Zat4 membership
/// record. It already has a session; what it does not yet have is membership
/// here, and that is a network write like any other — off the render thread.
fn memberWorker(job: *CreateJob, gpa: Allocator, io: std.Io, env: ?*const std.process.Environ.Map, sess: *auth.Session, age_ok: bool) void {
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    _ = membership_record.put(gpa, arena_state.allocator(), io, env, sess, lexicon.membership_via.imported, enroll_run.tos_version_placeholder, age_ok, clock_shell.unixSeconds()) catch |err| {
        // A failed membership write must not cost the person their session — they
        // ARE signed in; they simply are not a member yet, and can retry.
        std.debug.print("[enroll] membership write failed: {s}\n", .{@errorName(err)});
    };
    job.session = sess.*;
    job.done.store(true, .release);
}

/// The verifying step: the proof-of-work ring, then the account. Both on workers;
/// the ring's motion is a pure function of elapsed time, so the UI stays honest
/// about an unknowable duration (it creeps, decelerating, and only completes when
/// the real solution lands — never a fast fill and a dead stall).
fn enrollVerify(rs: *RunState, gpa: Allocator, io: std.Io, env: ?*const std.process.Environ.Map, frame_ns: u64) void {
    const s = &rs.genroll_state;
    if (s.step != .verifying) {
        // Left the step: cancel the solve and re-arm, so a Back-then-forward does
        // not inherit a half-finished proof.
        if (rs.genroll_pow.active) {
            enroll_run.stopPow(&rs.genroll_pow);
            rs.genroll_pow.active = false;
        }
        s.pow_t = 0.0;
        s.seal_t = 0.0;
        s.seal_start_ns = 0;
        return;
    }

    if (!rs.genroll_pow.active) {
        enroll_run.startPow(&rs.genroll_pow, s, io);
        s.pow_start_ns = frame_ns;
    }
    const el: f32 = @floatFromInt(frame_ns -| s.pow_start_ns);
    const floor_ns: f32 = 3_200_000_000.0; // a minimum, so the proof never flickers past
    const solved = rs.genroll_pow.done.load(.acquire);
    if (solved and el >= floor_ns) {
        s.pow_t += (1.0 - s.pow_t) * 0.16;
        if (s.pow_t > 0.999) s.pow_t = 1.0;
    } else {
        // A DECELERATING CREEP across the whole unknown solve: always moving,
        // slowing as it climbs, never reaching the top until the real solution
        // lands. The motion IS the work.
        const creep = 1.0 - @exp(-el / 2_800_000_000.0);
        s.pow_t = @min(0.97, creep);
    }
    if (s.pow_t >= 0.999) {
        if (s.seal_start_ns == 0) s.seal_start_ns = frame_ns;
        const sel: f32 = @floatFromInt(frame_ns -| s.seal_start_ns);
        s.seal_t = @min(1.0, sel / 800_000_000.0);
    } else {
        s.seal_t = 0.0;
        s.seal_start_ns = 0;
    }

    // Sealed, EXISTING branch: the DID is already on the network but is not a
    // member HERE yet. Write the Zat4 membership record (via=imported, no
    // password) and become that person. The write is a PDS round-trip — the same
    // no-blocking-IO law applies, so it rides the CreateJob worker too.
    if (s.seal_t >= 1.0 and s.branch == .existing and rs.genroll_pending != null and
        !rs.genroll_create.active and rs.genroll_create.thread == null)
    {
        rs.genroll_create.done.store(false, .monotonic);
        rs.genroll_create.session = null;
        rs.genroll_create.thread = std.Thread.spawn(.{}, memberWorker, .{ &rs.genroll_create, gpa, io, env, &rs.genroll_pending.?, s.age_ok }) catch null;
        rs.genroll_create.active = rs.genroll_create.thread != null;
        if (!rs.genroll_create.active) s.step = .done;
    }

    // REHEARSAL: the proof is real, the screens are real, and the account is NOT.
    // Stop at the finish line and say so, rather than minting something on a
    // production PDS that somebody then has to go and delete.
    if (comptime dist_config.enroll_rehearsal) {
        if (s.seal_t >= 1.0 and s.step == .verifying) {
            s.step = .done;
            enroll_run.stopPow(&rs.genroll_pow);
            rs.genroll_pow.active = false;
        }
        return;
    }

    // Sealed → make the account. ON A WORKER (see CreateJob).
    if (s.seal_t >= 1.0 and !rs.genroll_create.active and rs.genroll_create.thread == null and s.branch == .new) {
        rs.genroll_create.done.store(false, .monotonic);
        rs.genroll_create.session = null;
        rs.genroll_create.thread = std.Thread.spawn(.{}, createWorker, .{ &rs.genroll_create, gpa, io, env, s }) catch null;
        rs.genroll_create.active = rs.genroll_create.thread != null;
        if (!rs.genroll_create.active) s.step = .done; // could not even start: say so
    }
    if (rs.genroll_create.thread) |th| {
        if (rs.genroll_create.done.load(.acquire)) {
            th.join();
            rs.genroll_create.thread = null;
            rs.genroll_create.active = false;
            rs.genroll_pending = null; // its ownership moved into the job's result
            if (rs.genroll_create.session) |sess| {
                // WE ARE SOMEBODY NOW. The loop asks to be restarted with this
                // session — it cannot hot-swap an identity mid-frame, because
                // every worker, cache and store in it was built for "nobody".
                rs.genroll_session = sess;
                enroll_run.stopPow(&rs.genroll_pow);
                rs.genroll_pow.active = false;
            } else {
                // It failed. SAY SO — do not sit on a sealed ring forever.
                s.step = .done;
                s.pow_t = 0;
                s.seal_t = 0;
                enroll_run.stopPow(&rs.genroll_pow);
                rs.genroll_pow.active = false;
            }
        }
    }
}

/// "I already have an account" — THE FORK. Who hosts the handle decides the road:
/// an account on OUR PDS signs in with a password, in the app, no browser (we run
/// that server and hold the hash — there is no third party to protect them from);
/// an account anywhere else goes to its own provider's website, because collecting
/// somebody else's provider password in our app is the thing OAuth exists to
/// prevent. Both legs are network, so both are workers.
///
/// Downstream both roads converge: a returning MEMBER drops straight into the
/// feed; a DID that is on the network but holds no Zat4 membership record carries
/// its session through the proof-of-work gate and mints one.
fn enrollConnect(rs: *RunState, gpa: Allocator, io: std.Io, env: ?*const std.process.Environ.Map, frame_ns: u64) void {
    const s = &rs.genroll_state;
    if (s.step != .connecting and s.step != .signin) {
        // They left. Cancel the browser leg — a sign-in that lands after somebody
        // has walked away from the screen that asked for it is not a gift.
        s.connect_failed = false;
        rs.glogin_want = false;
        rs.glogin_asked = false;
        // Reap whatever the fork left running, once it lands: a lookup nobody is
        // waiting for, or a session nobody asked for any more (freed, not leaked).
        // Only when it is DONE — the render thread does not wait on the network.
        if (rs.genroll_resolve.thread != null and rs.genroll_resolve.done.load(.acquire))
            enroll_run.stopResolve(&rs.genroll_resolve);
        if (rs.genroll_pwlogin.thread != null and rs.genroll_pwlogin.done.load(.acquire)) {
            enroll_run.stopPwLogin(&rs.genroll_pwlogin);
            rs.genroll_signin_started = false;
        }
        return;
    }

    if (s.step == .signin) {
        enrollSignin(rs, gpa, io, env, frame_ns);
        return;
    }

    // ── who hosts it? (before any browser is opened, and before any password is
    // asked for) ──
    if (!s.resolved) {
        // A lookup left over from an earlier visit to this step answers about a
        // handle that may since have been retyped: joined and DROPPED, and only
        // once it is done. Until then we do not start a second one.
        if (!s.resolving and rs.genroll_resolve.thread != null and rs.genroll_resolve.done.load(.acquire))
            enroll_run.stopResolve(&rs.genroll_resolve);
        if (!s.resolving and rs.genroll_resolve.thread == null) {
            s.resolving = true;
            enroll_run.startResolve(&rs.genroll_resolve, s, io, env);
        }
        if (!s.resolving or !rs.genroll_resolve.done.load(.acquire)) return;
        if (!enroll_run.takeResolve(&rs.genroll_resolve, s)) return; // → "we couldn't find that handle"
        if (s.host_ours) {
            // OUR account. No browser: a password field, right here.
            s.step = .signin;
            s.sign_error = .none;
            // A STEP DOES NOT SUMMON THE KEYBOARD (the standing phone rule): with a
            // mouse the caret is simply ready; with a thumb an auto-focus throws a
            // keyboard over half the screen nobody asked for.
            if (rs.backend != .mobile) s.focus = .pw;
            return;
        }
        // Hosted elsewhere → the browser road below, and the card now NAMES the host.
    }

    // A HANDLE THAT RESOLVED TO NOTHING GETS NO BROWSER. The lookup has answered
    // (`resolved`), so the block above is skipped from here on — without this the
    // very next frame would sail into the OAuth leg and open a browser to sign in
    // to an account we just established does not exist. The card is showing "we
    // couldn't find that handle"; the only way forward is the one it offers.
    if (s.sign_error == .not_found) return;

    // THE PHONE TAKES A DIFFERENT ROAD. The desktop leg opens a browser and waits
    // on a loopback listener; Android delivers the redirect as an OS intent to a
    // trampoline instead, and the seam owns that plumbing. So on mobile we ASK,
    // and the seam does the hop — the app then restarts as the person it signed
    // in (the same "hand the session up" shape the new-account branch uses).
    if (rs.backend == .mobile) {
        // ONCE. The seam's request is read-and-clear, so raising it every frame
        // asked for a browser a hundred times a second — harmless only because
        // `loginStart` refuses to start a second flow, which is not a thing to
        // rely on. A latch: cleared when the step is left (above).
        if (!s.connect_failed and !rs.glogin_asked) {
            rs.glogin_want = true;
            rs.glogin_asked = true;
        }
        return;
    }

    if (!rs.genroll_oauth.active and !s.connect_failed)
        enroll_run.startOAuth(&rs.genroll_oauth, s, io, env);
    if (!rs.genroll_oauth.active or !rs.genroll_oauth.done.load(.acquire)) return;

    enroll_run.joinOAuth(&rs.genroll_oauth);
    if (!rs.genroll_oauth.ok) {
        // It failed. The spinner becomes a retry card — never an endless spinner,
        // which is the same lie as a dead button.
        s.connect_failed = true;
        return;
    }
    // Re-home the worker's session into the render allocator (the worker is
    // joined, so there is no concurrency here).
    const sess = auth.reownSession(gpa, std.heap.page_allocator, rs.genroll_oauth.session) catch {
        auth.freeSession(std.heap.page_allocator, rs.genroll_oauth.session);
        s.connect_failed = true;
        return;
    };
    if (rs.genroll_oauth.is_member) {
        rs.genroll_session = sess; // returning member → straight to the feed
        return;
    }
    // First-time imported DID: it is on the network, but it is not a member HERE
    // yet. Through the proof-of-work gate, carrying its session.
    rs.genroll_pending = sess;
    s.step = .verifying;
    s.pow_start_ns = frame_ns;
}

/// THE IN-APP SIGN-IN (the fork's other road): `createSession` against our own
/// PDS, on a worker. The tap raised `signin_busy`; this starts the work, drains
/// the result, and lands in exactly the same two places the browser road lands —
/// straight to the feed for a member, the proof-of-work gate for a DID that has
/// no Zat4 membership record yet.
fn enrollSignin(rs: *RunState, gpa: Allocator, io: std.Io, env: ?*const std.process.Environ.Map, frame_ns: u64) void {
    const s = &rs.genroll_state;
    const job = &rs.genroll_pwlogin;

    // A sign-in abandoned on an earlier visit: reaped (its session freed) the
    // moment it lands, so it can never be mistaken for the answer to THIS tap.
    if (!rs.genroll_signin_started and job.thread != null and job.done.load(.acquire))
        enroll_run.stopPwLogin(job);

    if (s.signin_busy and !rs.genroll_signin_started and job.thread == null) {
        rs.genroll_signin_started = true;
        enroll_run.startPwLogin(job, s, io, env);
    }
    if (!rs.genroll_signin_started or !job.done.load(.acquire)) return;

    rs.genroll_signin_started = false;
    enroll_run.joinPwLogin(job); // joins + scrubs the job's copy of the password
    s.signin_busy = false;
    if (!job.ok) {
        // Say WHICH failure it was. "Wrong password" when the truth is "we couldn't
        // reach the server" is how you get someone to change a password that was
        // never wrong.
        s.sign_error = if (job.refused) .refused else .network;
        return;
    }
    const sess = auth.reownSession(gpa, std.heap.page_allocator, job.session) catch {
        auth.freeSession(std.heap.page_allocator, job.session);
        s.sign_error = .network;
        return;
    };
    enroll_run.wipePw(s); // it did its job; it does not linger on the screen or in RAM
    if (job.is_member) {
        rs.genroll_session = sess; // returning member → straight to the feed
        return;
    }
    // On our PDS but holding no membership record (an account minted before the
    // record existed, or by hand): the same gate everyone else walks.
    rs.genroll_pending = sess;
    s.step = .verifying;
    s.pow_start_ns = frame_ns;
}

/// REHEARSAL (dev builds, `-Denroll-rehearsal`). The password gates exist to make
/// a person prove they SAVED their password — which is exactly right for a real
/// sign-up and pure friction when the same person is walking the flow for the
/// tenth time to look at the screens. So here they arrive pre-filled: every
/// screen still renders, the real proof-of-work still runs, and the only thing
/// that does not happen is the one thing you cannot undo — minting an account.
fn enrollRehearse(rs: *RunState) void {
    if (comptime !dist_config.enroll_rehearsal) return;
    const s = &rs.genroll_state;
    if (s.step != .confirm or !s.has_pw) return;
    const pw = s.cred.bytes[0..s.cred.len];
    // The spot-checks want the word at each challenged position; the full entry
    // wants the whole thing. Fill what is empty, and leave anything the tester
    // has typed alone (so it can still be exercised deliberately).
    for (0..3) |i| {
        if (s.spot[i].len != 0) continue;
        const want = enroll_view.wordAt(pw, s.spot_positions[i]);
        const n = @min(want.len, s.spot[i].buf.len);
        @memcpy(s.spot[i].buf[0..n], want[0..n]);
        s.spot[i].len = @intCast(n);
        s.spot[i].caret = @intCast(n);
    }
    if (s.full.len == 0) {
        const n = @min(pw.len, s.full.buf.len);
        @memcpy(s.full.buf[0..n], pw[0..n]);
        s.full.len = @intCast(n);
        s.full.caret = @intCast(n);
    }
}

/// The CONFIRM step's off-thread membership verify (Argon2id — memory-hard, so it
/// cannot run on the thread that draws). `enroll_run`'s own loop drained this;
/// nothing in THIS loop did, so the worker finished, nobody joined it, and the
/// button said "Checking…" for ever. A job with no drain is a hang with a
/// friendly label on it.
fn enrollConfirm(rs: *RunState, io: std.Io) void {
    const s = &rs.genroll_state;
    if (s.step != .confirm or !s.mem_verifying) return;
    if (!rs.genroll_memjob.done.load(.acquire)) return;
    enroll_run.joinMem(&rs.genroll_memjob);
    s.mem_verifying = false;
    if (rs.genroll_memjob.verify_ok) {
        enroll_run.confirmSucceed(s, io, &rs.genroll_mstore);
    } else {
        s.confirm_error = true; // say so; never sit on a spinner
    }
}

/// The front door's per-frame motion. The window loop in `enroll_run` interleaves
/// these with its own field splashes; the eased values themselves are plain
/// arithmetic over the state, so they live here and the two callers agree on what
/// the card is DOING without agreeing on what the field is doing.
///
/// The verifying step's proof-of-work ring is deliberately NOT here: it is a
/// worker + a network leg, and it lands in phase 3 with the rest of them.
fn enrollStep(rs: *RunState, frame_ns: u64, t: f32) void {
    const s = &rs.genroll_state;

    // Hover (desktop pointer; the phone simply never sets it).
    const hovered = enroll_view.hitTest(rs.genroll_hits.items, rs.ghover_x, rs.ghover_y);
    s.hover_on = hovered != null;
    if (hovered) |hv| s.hover = hv;
    s.hover_t += ((if (s.hover_on) @as(f32, 1.0) else 0.0) - s.hover_t) * 0.28;

    // The password's "crafting" decode: eased 0→1, then it sits at 1.
    if (s.step == .password and s.has_pw and s.craft_start_ns != 0) {
        const el: f32 = @floatFromInt(frame_ns -| s.craft_start_ns);
        const lin = @min(1.0, el / 1_900_000_000.0);
        const inv = 1.0 - lin;
        s.craft_t = 1.0 - inv * inv * inv; // easeOutCubic
    } else s.craft_t = 1.0;

    // The strength bar fills in after a tier is picked; the phase free-runs.
    if (s.tier_chosen) {
        const el: f32 = @floatFromInt(frame_ns -| s.bar_sel_ns);
        s.bar_t = @min(1.0, el / 600_000_000.0);
    } else s.bar_t = 0.0;
    s.bar_phase = t;

    // The step transition: the content slides in from the side you came from while
    // the card grows under it. One routine, shared with the dev harness.
    enroll_run.stepMotion(s, frame_ns);

    // The "Copied" toast decays on its own clock.
    if (s.copied_ns != 0) {
        const el: f32 = @floatFromInt(frame_ns -| s.copied_ns);
        s.copied_t = @max(0.0, 1.0 - el / 1_400_000_000.0);
        if (s.copied_t <= 0.001) s.copied_ns = 0;
    } else s.copied_t = 0.0;
}

/// THE BOOT ENTRANCE (§5) — the clock, and the end of it. Pure state: the drawing
/// is `boot_intro.layout`, a function of elapsed seconds alone.
fn bootIntroStep(rs: *RunState, frame_ns: u64) void {
    if (rs.gboot_done) return;
    if (rs.gboot_start_ns == 0) rs.gboot_start_ns = frame_ns;
    if (bootIntroT(rs) >= boot_intro.duration()) rs.gboot_done = true;
}

/// Seconds into the entrance.
fn bootIntroT(rs: *const RunState) f32 {
    if (rs.gboot_start_ns == 0) return 0;
    const el = clock_shell.monotonicNanos() -| rs.gboot_start_ns;
    return @as(f32, @floatFromInt(el)) / 1_000_000_000.0;
}

/// Is the entrance on screen right now? (It only ever is at the front door.)
fn bootIntroOn(rs: *const RunState) bool {
    return !rs.gboot_done and rs.gscreen == feed_view.screen_enroll;
}

/// ANY input skips — and skipping lands you ON the settled wordmark, not on
/// nothing. An animation you cannot skip is a toll booth, and this one plays when
/// a person is at their least patient: they are trying to get IN. Returns true if
/// the input was consumed by the skip (so it does not also press whatever it
/// happened to land on).
fn bootIntroSkip(rs: *RunState) bool {
    if (!bootIntroOn(rs)) return false;
    const to_ns: u64 = @intFromFloat(boot_intro.skipTo() * 1_000_000_000.0);
    const now = clock_shell.monotonicNanos();
    // Only ever jump FORWARD: a second tap during the closing beat must not rewind
    // the entrance it is trying to get past.
    if (bootIntroT(rs) < boot_intro.skipTo()) rs.gboot_start_ns = now -| to_ns;
    return true;
}

/// True for the hit targets that ARE a text field — the only things that may
/// raise a keyboard on a phone.
fn isEnrollField(t: enroll_view.HitTarget) bool {
    return switch (t) {
        .field_handle, .field_username, .field_email, .field_spot0, .field_spot1, .field_spot2, .field_full, .field_pw => true,
        else => false,
    };
}

/// The front door's Copy button: the password (password step) or the recovery
/// key (recovery step) onto the system clipboard. On the phone that is the seam's
/// ClipboardManager bridge, on desktop the X11 selection — the SAME clipboard the
/// composer uses, which is the point of hosting the front door in this loop: it
/// inherits everything instead of reimplementing it.
fn enrollCopy(rs: *RunState) void {
    const s = &rs.genroll_state;
    const clip: []const u8 = if (s.step == .recovery)
        s.recovery_key[0..s.recovery_len]
    else if (s.has_pw)
        s.cred.bytes[0..s.cred.len]
    else
        "";
    if (clip.len == 0) return;
    // Desktop: the X11 selection. Phone: the seam's clip_out buffer, which the
    // activity drains into ClipboardManager (the same road the chat composer's
    // Copy takes — inherited, not reimplemented).
    switch (rs.backend) {
        .window => |w| window_shell.setClipboard(w, clip),
        else => {},
    }
    const n = @min(clip.len, rs.clip_out_buf.len);
    @memcpy(rs.clip_out_buf[0..n], clip[0..n]);
    rs.clip_out_len = n;
    s.copied_ns = clock_shell.monotonicNanos();
}

/// The relay link's live state (A5) — what the connection dot renders from.
/// No link at all reads as `.off`: chat is not configured, and the surface says
/// that in its own words rather than showing a dot that claims nothing.
fn chatLinkOf(rs: *RunState) feed_view.ChatLink {
    const l = rs.gchat_link orelse return .off;
    return switch (chat_relay.linkState(l)) {
        .connecting => .connecting,
        .connected => .connected,
        .authenticated => .authenticated,
    };
}

/// What the open conversation's peer knows about it (A1) — the fact the
/// thread's delivery line renders. No conversation open, or chat offline:
/// nothing to say.
fn chatDeliveryOf(rs: *RunState) chat_core.Delivery {
    const st = if (rs.gchat_e2ee) |*p| p else return .confirmed;
    const sel = rs.gchat_sel orelse return .confirmed;
    return chat_e2ee.deliveryState(st, chat_core.conversationDid(&rs.gchat_store, sel));
}

/// Acknowledge a Welcome we just accepted (A1): one encrypted byte back over
/// the group we joined, so the starter learns their Welcome LANDED. Failure is
/// logged, not surfaced — the peer's own retry brings us back here, and this
/// path is invisible to the user by design.
/// `device` is the peer DEVICE whose Welcome we just accepted. An ack answers ONE
/// Welcome, so it is encrypted over that one session — never fanned out across
/// their other devices, which would retire retries for channels that do not exist.
fn chatAck(rs: *RunState, gpa: Allocator, io: std.Io, env: ?*const std.process.Environ.Map, st: *chat_e2ee.State, peer_did: []const u8, device: [32]u8, now: i64) void {
    const l = rs.gchat_link orelse return;
    chat_e2ee.sendGroupAck(gpa, io, env, st, l, peer_did, device, now) catch |err|
        chatLog("[chat] ACK FAILED -> {s}: {s}", .{ peer_did, @errorName(err) });
}

/// Re-establish a conversation whose two halves have drifted apart: fetch the
/// peer's CURRENT keys, build a new group, send them a Welcome, replace ours.
///
/// A conversation can be alive on one side and absent on the other — the Welcome
/// that opened it may never have arrived (a relay outage, or a client pointed at
/// the wrong relay), or the peer reinstalled. Until now that state was terminal
/// AND invisible: the sender's bubbles appeared and went nowhere, and the peer's
/// client silently discarded every attempt to start over.
///
/// Costs nothing to use: history is local (the Signal model), and a group the
/// peer never joined cannot decrypt anything anyway.
fn chatRestart(rs: *RunState, gpa: Allocator, io: std.Io, env: ?*const std.process.Environ.Map, conv: chat_core.ConvIndex) void {
    const state = if (rs.gchat_e2ee) |*p| p else {
        rs.status = "chat: offline";
        return;
    };
    const l = rs.gchat_link orelse {
        rs.status = "chat: offline";
        return;
    };
    const peer_did = chat_core.conversationDid(&rs.gchat_store, conv);
    _ = rs.gchat_arena_state.reset(.retain_capacity);
    chat_e2ee.restartConversation(gpa, rs.gchat_arena_state.allocator(), io, env, state, l, peer_did) catch |err| {
        chatLog("[chat] re-establish FAILED -> {s}: {s}", .{ peer_did, @errorName(err) });
        rs.status = switch (err) {
            error.NoKeyPackage => "They haven't set up chat on this account yet",
            error.RelayDown => "Chat relay unreachable — try again",
            else => "Couldn't re-establish — try again",
        };
        return;
    };
    // RE-SUBSCRIBE. The new group has a NEW traffic mailbox, and traffic mailboxes
    // are only walked at startup and after a drained batch. Without this the peer's
    // replies land in an address we are not listening on — which is precisely the
    // shape of the bug we just spent the evening on, one layer up: everything looks
    // sent, nothing arrives, and nothing says why.
    chatEnsureSubs(gpa, state, l);
    chatLog("[chat] re-established -> {s} (new Welcome sent, re-subscribed)", .{peer_did});
    rs.status = "chat: re-established — they'll get your next message";
}

// ---------------------------------------------------------------------------
// Payments in the thread (M5 A4): the sheet's verbs and the card's taps.
// Every flow is: mutate the store (pure core), persist (M2 — a payment card
// is history), then tell the peer over the E2EE channel. The wallet leg
// (fetch the published address, validate it against the PINNED anchor,
// build the standard URI, open the wallet) runs on the caller's thread —
// the recorded first-contact posture: rare, user-initiated events.
// ---------------------------------------------------------------------------

/// Ask the wallet what it can do. Returns a static refusal ("" = launched).
fn spawnWalletProbe(
    rs: *RunState,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    lnaddr: []const u8,
) []const u8 {
    if (rs.gcaps_job.thread != null) return "Still checking that wallet\u{2026}";
    const a = std.heap.page_allocator;
    const copy = a.dupe(u8, lnaddr) catch return "Out of memory";
    rs.gcaps_job = .{ .addr = copy };
    rs.gcaps_job.thread = std.Thread.spawn(.{}, walletProbeWorker, .{ &rs.gcaps_job, io, environ }) catch {
        walletProbeJobFree(&rs.gcaps_job);
        return "Couldn't check that wallet \u{2014} try again";
    };
    return "";
}

/// Publish the receive record. Reached ONLY after the user has seen the wallet's
/// capability table and accepted it (or for an on-chain-only address, which needs
/// no interrogation — the chain watcher confirms those unconditionally).
fn publishReceive(
    rs: *RunState,
    gpa: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    /// By POINTER: publishing may refresh the session's tokens, and the refreshed
    /// ones must survive the call.
    session: *auth.Session,
) []const u8 {
    const ln = std.mem.trim(u8, rs.grecv_ln_buf[0..rs.grecv_ln_len], " ");
    const btc = std.mem.trim(u8, rs.grecv_btc_buf[0..rs.grecv_btc_len], " ");
    _ = rs.gchat_arena_state.reset(.retain_capacity);
    const status = saveReceiveAddress(gpa, rs.gchat_arena_state.allocator(), io, environ, session, ln, btc, &rs.grecv_saved);
    if (rs.grecv_saved) {
        rs.grecv_set = true;
        // Now that I can receive, every offer waiting on me can proceed (S2).
        announceReceiveReady(gpa, io, environ, if (rs.gchat_e2ee) |*p| p else null, rs.gchat_link, &rs.gchat_store);
    }
    return status;
}

/// Close the pay modal. ONE routine, so every dismissal path — the × , the
/// scrim, Escape, the back chevron, the system back gesture, and leaving the
/// conversation — leaves exactly the same state behind. They did not before:
/// the back chevron closed nothing, popped the conversation out from under the
/// open sheet, and left it on screen with every button inert (`gchat_sel` was
/// null, and all the pay verbs are guarded on it).
fn closePaySheet(rs: *RunState) void {
    rs.gpay_open = false;
    rs.gpay_step = .compose;
    rs.gpay_status = "";
}

/// Close the receive modal. Same contract as `closePaySheet`.
fn closeRecvSheet(rs: *RunState) void {
    rs.grecv_open = false;
    rs.grecv_status = "";
}

/// True while a money modal owns the screen. The back edge consults this FIRST
/// — before blurring a focus bit, before popping the thread — because a modal
/// about money must be the thing that "back" acts on while it is up.
fn payModalOpen(rs: *const RunState) bool {
    return rs.gpay_open or rs.grecv_open;
}

/// Take one step back inside whichever money modal is open. Returns true when
/// the press was consumed. This is the single implementation that Escape, the
/// on-screen chevron and the system back gesture all call, so they can no longer
/// drift apart (they had drifted into four different behaviours).
fn payModalBack(rs: *RunState) bool {
    if (rs.grecv_open) {
        if (feed_view.recvBackEdge(rs.grecv_mode, rs.grecv_set)) |prev| {
            rs.grecv_mode = prev;
            rs.grecv_focus = 0;
            rs.grecv_status = "";
        } else {
            closeRecvSheet(rs);
        }
        return true;
    }
    if (rs.gpay_open) {
        if (feed_view.payBackEdge(rs.gpay_step)) |prev| {
            rs.gpay_step = prev;
            rs.gpay_status = "";
        } else {
            closePaySheet(rs);
        }
        return true;
    }
    return false;
}

/// Kick off the send worker. Returns a static refusal ("" = launched).
///
/// Everything cheap and local is checked HERE, on the render thread, where a
/// refusal can be shown instantly. Only the two network legs go to the worker.
fn paySpawn(
    rs: *RunState,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    conv: chat_core.ConvIndex,
    stage: PayStage,
    rail: chat_core.Rail,
    amount_sat: u64,
    note: []const u8,
    from_sheet: bool,
    paying: ?u64,
) []const u8 {
    // A second money action while one is in flight is REFUSED, out loud. Returning
    // "" here would be catastrophic: "" is the success sentinel, so a dropped tap
    // would look launched. Tap Pay on a 500,000-sat request card, then Send 1,000
    // from the sheet before it lands, and the sheet would say "Checking…" while the
    // FIRST job's result opened your wallet for 500,000 — the app attributing one
    // payment's outcome to a different action. Never.
    if (rs.gpay_job.thread != null) return "Another payment is already being prepared";
    const state = if (rs.gchat_e2ee) |*p| p else return "Chat is offline — no relay configured";
    if (rs.gchat_link == null) return "Chat is offline — no relay configured";
    const peer_did = chat_core.conversationDid(&rs.gchat_store, conv);
    const anchor_pub = chat_e2ee.peerAnchor(state, peer_did) orelse
        return "No secure conversation with them yet";

    const a = std.heap.page_allocator;
    const did_copy = a.dupe(u8, peer_did) catch return "Out of memory";
    const note_copy = a.dupe(u8, note) catch {
        a.free(did_copy);
        return "Out of memory";
    };
    const label_copy = a.dupe(u8, chat_core.conversationHandle(&rs.gchat_store, conv)) catch {
        a.free(did_copy);
        a.free(note_copy);
        return "Out of memory";
    };
    rs.gpay_job = .{
        .stage = stage,
        .peer_did = did_copy,
        .note = note_copy,
        .label = label_copy,
        .anchor = anchor_pub,
        .rail = rail,
        .amount_sat = amount_sat,
        .paying = paying,
        .conv = @intFromEnum(conv),
        .from_sheet = from_sheet,
    };
    rs.gpay_job.thread = std.Thread.spawn(.{}, paySendWorker, .{ &rs.gpay_job, io, environ }) catch {
        paySendJobFree(&rs.gpay_job);
        return "Couldn't start the payment";
    };
    return "";
}

/// A nonzero payment id — the wire correlation key. Entropy is the shell's
/// job (B3); null = the CSPRNG refused (the caller shows a status line).
fn payMintId(io: std.Io) ?u64 {
    var b: [8]u8 = undefined;
    io.randomSecure(&b) catch return null;
    const v = std.mem.readInt(u64, &b, .little);
    return if (v == 0) 1 else v; // zero is the one reserved value
}

/// The sheet's Request verb: a payment_request card in the store + the
/// encrypted frame to the peer. Returns the sheet's status line ("" =
/// success; the caller closes the sheet).
/// Publish YOUR chat receive address (the receive-setup sheet's Save/Enter).
/// Runs the same validate-first + anchor-sign + put-record path as
/// `--pay-publish`. Returns the status line to show; sets `saved` so the sheet
/// colours it green (success) vs amber (refusal). One place, two call sites.
fn saveReceiveAddress(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    env: ?*const std.process.Environ.Map,
    session: *auth.Session,
    ln: []const u8,
    btc: []const u8,
    saved: *bool,
) []const u8 {
    if (pay_addr.publish(gpa, arena, io, env, session, ln, btc)) |_| {
        saved.* = true;
        return "Saved \u{2014} you can now receive payments in chats";
    } else |err| {
        saved.* = false;
        // NAME IT. "Check your connection" is what this said for every failure it
        // did not have a case for — including failures that have nothing to do
        // with the connection — which sent the owner looking at his wifi while
        // the real fault sat in the log, unlogged.
        chatLog("[wallet] publish FAILED: {s}", .{@errorName(err)});
        return switch (err) {
            error.NoAddresses => "Add a Lightning or Bitcoin address first",
            error.BadLightning => "That Lightning address isn't valid",
            error.BadBitcoin => "That Bitcoin address isn't valid",
            error.NoAnchor => "Couldn't sign \u{2014} chat identity missing",
            error.SignFailed => "Couldn't sign the address record",
            else => "Couldn't save \u{2014} check your connection",
        };
    }
}

/// Read this account's already-published receive address ONCE, to gate the
/// bitcoin icon and prefill the sheet. Returns true if set up, copying the
/// current addresses into the drafts. A network read on the UI thread the first
/// time payments are opened (the first-contact posture); failure = "not set up"
/// (E4) — the user just sees onboarding, never an error.
fn loadOwnReceive(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    env: ?*const std.process.Environ.Map,
    session: *auth.Session,
    ln_buf: []u8,
    ln_len: *usize,
    btc_buf: []u8,
    btc_len: *usize,
) bool {
    const own = (pay_addr.fetchOwn(gpa, arena, io, env, session.did) catch null) orelse return false;
    if (own.lightning.len <= ln_buf.len) {
        @memcpy(ln_buf[0..own.lightning.len], own.lightning);
        ln_len.* = own.lightning.len;
    }
    if (own.bitcoin.len <= btc_buf.len) {
        @memcpy(btc_buf[0..own.bitcoin.len], own.bitcoin);
        btc_len.* = own.bitcoin.len;
    }
    return true;
}

fn payRequest(
    gpa: Allocator,
    io: std.Io,
    env: ?*const std.process.Environ.Map,
    st: ?*chat_e2ee.State,
    link: ?*chat_relay.ChatRelay,
    cs: *chat_core.Store,
    conv: chat_core.ConvIndex,
    rail: chat_core.Rail,
    amount_sat: u64,
    note: []const u8,
    now: i64,
) []const u8 {
    const state = st orelse return "Chat is offline — no relay configured";
    const l = link orelse return "Chat is offline — no relay configured";
    const id = payMintId(io) orelse return "No entropy — try again";
    if (chat_core.findPayment(cs, conv, id) != null) return "Try again"; // 2^-64 event
    _ = chat_core.appendPayment(gpa, cs, conv, .payment_request, id, rail, amount_sat, note, now, true) catch
        return "Out of memory";
    chatPersistHistory(gpa, io, env, state, cs);
    chat_e2ee.sendPayment(gpa, io, env, state, l, chat_core.conversationDid(cs, conv), .payment_request, .{
        .payment_id = id,
        .amount_sat = amount_sat,
        .note = note,
        .ref = chat_core.zero_ref,
        .rail = rail,
    }) catch return "Couldn't reach them — the request shows here only";
    return "";
}
/// The LOCAL half of a send: open the wallet, write the card, persist, signal
/// the peer. Everything slow already happened on `paySendWorker`, so nothing
/// here touches the network except the relay publish.
///
/// Split out of the old `paySend`, which resolved the peer's address and (for
/// Lightning) fetched an invoice INLINE, on the click, on the render thread.
fn payCommit(
    rs: *RunState,
    gpa: Allocator,
    io: std.Io,
    env: ?*const std.process.Environ.Map,
    st: ?*chat_e2ee.State,
    link: ?*chat_relay.ChatRelay,
    cs: *chat_core.Store,
    conv: chat_core.ConvIndex,
    rail: chat_core.Rail,
    amount_sat: u64,
    note: []const u8,
    paying: ?u64,
    now: i64,
    uri: []const u8,
    /// Out: the payment id this send is carried by, so the caller can start
    /// WATCHING it settle. Zero when nothing was written.
    id_out: *u64,
) []const u8 {
    const state = st orelse return "Chat is offline \u{2014} no relay configured";
    const l = link orelse return "Chat is offline \u{2014} no relay configured";
    const peer_did = chat_core.conversationDid(cs, conv);

    // THE HAND-OFF. On Android this used to spawn `xdg-open` — a binary that
    // does not exist on a phone — so the send died here every single time, and
    // said "No wallet answered", which was not true: no wallet had ever been
    // asked. Paying from the phone could not work, and the message blamed the
    // wallet for it.
    if (!openUri(rs, io, uri)) return "No wallet answered the hand-off";
    // The card: a fresh sent-card, or the paid request advancing — both to
    // `pending` (initiated, unobserved; §6 honesty).
    var id: u64 = undefined;
    if (paying) |pid| {
        id = pid;
        if (chat_core.findPayment(cs, conv, pid)) |pay| {
            _ = chat_core.advancePayment(gpa, cs, pay, .pending, null) catch {};
        }
    } else {
        id = payMintId(io) orelse return "No entropy — try again";
        if (chat_core.findPayment(cs, conv, id) != null) return "Try again";
        _ = chat_core.appendPayment(gpa, cs, conv, .payment_sent, id, rail, amount_sat, note, now, true) catch
            return "Out of memory";
    }
    id_out.* = id;
    chatPersistHistory(gpa, io, env, state, cs);
    chat_e2ee.sendPayment(gpa, io, env, state, l, peer_did, .payment_sent, .{
        .payment_id = id,
        .amount_sat = amount_sat,
        .note = note,
        .ref = chat_core.zero_ref,
        .rail = rail,
    }) catch return "Wallet opened, but the card couldn't reach them";
    return "";
}

// The per-action gate (§5) — "can this peer actually be paid on this rail?" —
// used to live here as `peerSendGate`, a synchronous fetch on the click. It is
// now the `.gate` stage of `paySendWorker`: the same question, asked off the
// render thread, answered in the drain. The refusal strings moved with it.

/// A FRESH send to a walletless recipient (S2): mint the card at
/// `pending_setup` (no money moves — "Waiting to send"), persist, and send
/// the offer wire byte (20) so the peer sees "{P} wants to send you {amt}".
/// No `launch.openUri` — there is no address to hand a wallet yet. Returns
/// the status line ("" = the offer stands).
fn payOffer(
    gpa: Allocator,
    io: std.Io,
    env: ?*const std.process.Environ.Map,
    st: ?*chat_e2ee.State,
    link: ?*chat_relay.ChatRelay,
    cs: *chat_core.Store,
    conv: chat_core.ConvIndex,
    rail: chat_core.Rail,
    amount_sat: u64,
    note: []const u8,
    now: i64,
) []const u8 {
    const state = st orelse return "Chat is offline — no relay configured";
    const l = link orelse return "Chat is offline — no relay configured";
    const id = payMintId(io) orelse return "No entropy — try again";
    if (chat_core.findPayment(cs, conv, id) != null) return "Try again"; // 2^-64 event
    const pay = chat_core.appendPayment(gpa, cs, conv, .payment_sent, id, rail, amount_sat, note, now, true) catch
        return "Out of memory";
    chat_core.initPaymentStatus(cs, pay, .pending_setup);
    chatPersistHistory(gpa, io, env, state, cs);
    chat_e2ee.sendPaymentSignal(gpa, io, env, state, l, chat_core.conversationDid(cs, conv), chat_core.kind_pay_offer_wire, .{
        .payment_id = id,
        .amount_sat = amount_sat,
        .note = note,
        .ref = chat_core.zero_ref,
        .rail = rail,
    }) catch return "Offer saved here — couldn't reach them";
    return "";
}

/// An S2 lifecycle event on a card (Cancel an offer → `cancelled`, Decline
/// an offer → `declined`): advance the local card, persist, and signal the
/// peer with the matching wire byte. A no-op on a terminal card (E4).
fn payCardSignal(
    gpa: Allocator,
    io: std.Io,
    env: ?*const std.process.Environ.Map,
    st: ?*chat_e2ee.State,
    link: ?*chat_relay.ChatRelay,
    cs: *chat_core.Store,
    conv: chat_core.ConvIndex,
    payment_id: u64,
    to: chat_core.PayStatus,
    wire_byte: u8,
) void {
    const pay = chat_core.findPayment(cs, conv, payment_id) orelse return;
    const row = chat_core.paymentRow(cs, pay);
    if (!(chat_core.advancePayment(gpa, cs, pay, to, null) catch false)) return;
    const state = st orelse return;
    chatPersistHistory(gpa, io, env, state, cs);
    if (link) |l| {
        chat_e2ee.sendPaymentSignal(gpa, io, env, state, l, chat_core.conversationDid(cs, conv), wire_byte, .{
            .payment_id = payment_id,
            .amount_sat = row.amount_sat,
            .note = "",
            .ref = chat_core.zero_ref,
            .rail = row.rail,
        }) catch {};
    }
}

/// I just published a receive address — every offer sitting in
/// `pending_setup` (someone waiting to send me money, on any conversation)
/// can now proceed: advance it to `ready` locally and signal that payer with
/// the ready wire byte (21) so their card reads "Ready — Send now?". Scans
/// all payments; the offers are the counterparty's (`!paymentMine`).
fn announceReceiveReady(
    gpa: Allocator,
    io: std.Io,
    env: ?*const std.process.Environ.Map,
    st: ?*chat_e2ee.State,
    link: ?*chat_relay.ChatRelay,
    cs: *chat_core.Store,
) void {
    const state = st orelse return;
    var changed = false;
    const n = chat_core.paymentCount(cs);
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        const pay: chat_core.PayIndex = @enumFromInt(i);
        const row = chat_core.paymentRow(cs, pay);
        if (row.status != .pending_setup) continue;
        if (chat_core.paymentMine(cs, pay)) continue; // my OWN offers aren't mine to ready
        const conv = chat_core.paymentConv(cs, pay);
        if (!(chat_core.advancePayment(gpa, cs, pay, .ready, null) catch false)) continue;
        changed = true;
        if (link) |l| {
            chat_e2ee.sendPaymentSignal(gpa, io, env, state, l, chat_core.conversationDid(cs, conv), chat_core.kind_pay_ready_wire, .{
                .payment_id = row.payment_id,
                .amount_sat = row.amount_sat,
                .note = "",
                .ref = chat_core.zero_ref,
                .rail = row.rail,
            }) catch {};
        }
    }
    if (changed) chatPersistHistory(gpa, io, env, state, cs);
}

/// A card's Cancel (own unobserved send) / Mark received (own request —
/// the payee's wallet is where a lightning receipt shows, so the payee
/// closes the loop): flip the local card, persist, tell the peer (the
/// settlement wire bytes). A no-op on a terminal card (E4).
fn payCardEvent(
    gpa: Allocator,
    io: std.Io,
    env: ?*const std.process.Environ.Map,
    st: ?*chat_e2ee.State,
    link: ?*chat_relay.ChatRelay,
    cs: *chat_core.Store,
    conv: chat_core.ConvIndex,
    payment_id: u64,
    settled: bool,
) void {
    const pay = chat_core.findPayment(cs, conv, payment_id) orelse return;
    const row = chat_core.paymentRow(cs, pay);
    const to: chat_core.PayStatus = if (settled) .settled else .failed;
    if (!(chat_core.advancePayment(gpa, cs, pay, to, null) catch false)) return;
    const state = st orelse return;
    chatPersistHistory(gpa, io, env, state, cs);
    if (link) |l| {
        chat_e2ee.sendPaymentEvent(gpa, io, env, state, l, chat_core.conversationDid(cs, conv), settled, .{
            .payment_id = payment_id,
            .amount_sat = row.amount_sat,
            .note = "",
            .ref = chat_core.zero_ref,
            .rail = row.rail,
        }) catch {};
    }
}

/// The payment row a card tap addresses: the region carries the THREAD
/// ordinal (no store index rides a region, A5); re-derive through the same
/// thread query the view was built from.
fn payRowByOrdinal(gpa: Allocator, cs: *const chat_core.Store, conv: chat_core.ConvIndex, ordinal: u16) ?chat_core.PaymentRow {
    const order = chat_core.threadSlice(gpa, cs, conv) catch return null;
    defer gpa.free(order);
    if (ordinal >= order.len) return null;
    const pay = chat_core.paymentByMsg(cs, order[ordinal]) orelse return null;
    return chat_core.paymentRow(cs, pay);
}

// ---------------------------------------------------------------------------
// The confirmation-watcher's poll cycle (M5 A5): a ONE-SHOT worker (the
// OAuthJob pattern — page_allocator inside, atomic done, join before
// reading) the run loop spawns every `chain_poll_seconds` while any
// on-chain card is live. Plain values cross the thread seam both ways
// (E1); a dead chain source is a skipped cycle — stale cards, never a
// blocked frame or a broken thread (E2/E4). The six-block animation is
// this cycle's output arriving through the store's monotonic transitions.
// ---------------------------------------------------------------------------

/// How often the watcher asks the chain. On-chain blocks land ~10 min
/// apart; a minute keeps the card honest without hammering the source.
const chain_poll_seconds: i64 = 60;

/// How many DIDs one handle sweep will resolve. Each costs two network legs
/// (fetch the document, then verify its claim by resolving back), so a large
/// backlog is spread across sweeps rather than fired at the network at once.
/// Names land a few per minute; the store persists them, so the backlog is
/// paid down once and never again.
const handle_sweep_max: usize = 8;

/// A7.2: cold struct, size guard waived — a few per poll cycle, worker-owned
/// page_allocator copies (the worker never touches render memory).
const ChainItem = struct {
    conv_did: []u8,
    owner_did: []u8,
    owner_anchor: [32]u8,
    payment_id: u64,
    amount_sat: u64,
};

/// A7.2: cold struct, size guard waived. `conv_did` borrows its item's copy.
const ChainResult = struct {
    conv_did: []const u8,
    payment_id: u64,
    /// null = not seen; 0 = mempool; n ≥ 1 = confirmations.
    depth: ?u8,
};

/// A7.2: cold struct, size guard waived — one per run loop.
const ChainJob = struct {
    thread: ?std.Thread = null,
    done: std.atomic.Value(bool) = .init(false),
    items: []ChainItem = &.{},
    /// Written by the worker BEFORE `done` flips (release/acquire pairs).
    results: []ChainResult = &.{},
};

fn chainJobFree(job: *ChainJob) void {
    const a = std.heap.page_allocator;
    for (job.items) |it| {
        a.free(it.conv_did);
        a.free(it.owner_did);
    }
    if (job.items.len > 0) a.free(job.items);
    if (job.results.len > 0) a.free(job.results);
    job.* = .{};
}

fn chainWorker(job: *ChainJob, io: std.Io, environ: ?*const std.process.Environ.Map) void {
    const a = std.heap.page_allocator;
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const src = chainwatch_shell.source(environ);
    var results: std.ArrayList(ChainResult) = .empty;
    const tip = chainwatch_shell.tipHeight(arena_state.allocator(), io, environ, src) catch {
        job.done.store(true, .release);
        return; // source down: nothing observed this cycle (E4)
    };
    for (job.items) |item| {
        _ = arena_state.reset(.retain_capacity);
        const arena = arena_state.allocator();
        // DID → published address, validated against the PINNED anchor
        // (A2's redirect defense holds on the watch path too).
        const payee = (pay_addr.fetchPayee(a, arena, io, environ, item.owner_did, item.owner_anchor) catch continue) orelse continue;
        if (payee.bitcoin.len == 0) continue;
        const ob = chainwatch_shell.observe(arena, io, environ, src, payee.bitcoin, item.amount_sat) catch continue;
        results.append(a, .{
            .conv_did = item.conv_did,
            .payment_id = item.payment_id,
            .depth = chainwatch_core.depthOf(ob, tip),
        }) catch break;
    }
    job.results = results.toOwnedSlice(a) catch &.{};
    job.done.store(true, .release);
}

/// A7.2: cold struct, size guard waived — a singleton, one prefetch per app run.
/// Worker-owned; plain values cross the seam (E1). Buffers written BEFORE
/// `done` flips (release/acquire pair on the join).
const ReceiveJob = struct {
    thread: ?std.Thread = null,
    done: std.atomic.Value(bool) = .init(false),
    /// The account DID to resolve (page-alloc'd copy, freed on join).
    did: []u8 = &.{},
    found: bool = false,
    ln: [160]u8 = undefined,
    ln_len: usize = 0,
    btc: [160]u8 = undefined,
    btc_len: usize = 0,
};

/// Resolve OUR OWN published receive record off the render thread — the ₿
/// button opens the pay sheet instantly instead of stalling on this fetch.
/// A public getRecord (no auth), so only the DID crosses the seam.
fn receiveWorker(job: *ReceiveJob, io: std.Io, environ: ?*const std.process.Environ.Map) void {
    const a = std.heap.page_allocator;
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    if (pay_addr.fetchOwn(a, arena_state.allocator(), io, environ, job.did) catch null) |own| {
        job.found = true;
        if (own.lightning.len <= job.ln.len) {
            @memcpy(job.ln[0..own.lightning.len], own.lightning);
            job.ln_len = own.lightning.len;
        }
        if (own.bitcoin.len <= job.btc.len) {
            @memcpy(job.btc[0..own.bitcoin.len], own.bitcoin);
            job.btc_len = own.bitcoin.len;
        }
    }
    job.done.store(true, .release);
}

/// One DID awaiting a verified handle, and the answer. `handle_len == 0` on
/// return means "no handle we are willing to show" — either the document
/// claimed none, or the claim failed the round-trip check.
/// A7.2: cold struct, size guard waived — a handful per sweep, never hot.
const HandleItem = struct {
    /// page-alloc'd copy — the worker must not borrow store text across the
    /// thread seam (the store keeps mutating on the render thread).
    did: []u8,
    handle: [253]u8 = undefined, // a handle's max length under atproto
    handle_len: usize = 0,
};

/// A7.2: cold struct, size guard waived — a singleton sweep.
const HandleJob = struct {
    thread: ?std.Thread = null,
    done: std.atomic.Value(bool) = .init(false),
    items: []HandleItem = &.{},
};

fn handleJobFree(job: *HandleJob) void {
    const a = std.heap.page_allocator;
    for (job.items) |it| a.free(it.did);
    if (job.items.len > 0) a.free(job.items);
    job.items = &.{};
}

/// Resolve counterparty DIDs to VERIFIED handles off the render thread.
///
/// A conversation opened by an inbound message knows only the peer's DID, so
/// without this every such chat — and every payment card in it — addresses a
/// human being as `did:plc:uelpy3ug6lkvisqcxt5ovva2`. Nobody sends money to a
/// hex string.
///
/// `identity.handleForDid` does the bidirectional check (the DID's claimed
/// handle must resolve back to that DID), so a name that arrives here is one we
/// can stand behind next to a Pay button. A refusal is an ordinary outcome, not
/// an error: the item comes back empty and the UI keeps showing the short DID.
/// Two network legs per DID, so this is emphatically not frame work (B3).
fn handleWorker(job: *HandleJob, io: std.Io, environ: ?*const std.process.Environ.Map) void {
    const a = std.heap.page_allocator;
    for (job.items) |*it| {
        const h = identity_shell.handleForDid(a, io, environ, .{}, it.did) catch continue;
        defer a.free(h);
        if (h.len > 0 and h.len <= it.handle.len) {
            @memcpy(it.handle[0..h.len], h);
            it.handle_len = h.len;
        }
    }
    job.done.store(true, .release);
}

/// What the send worker was asked to do.
///  - `gate`: resolve the peer's published record only — enough to decide
///    whether a Send becomes a confirm face or a walletless OFFER (§5).
///  - `hand_off`: resolve it AND build the exact-amount URI, so the wallet can
///    be opened the moment the result lands.
const PayStage = enum(u8) { gate, hand_off };
/// The wallet publish, off the render thread (the no-blocking-IO law). A PDS
/// write is a network round-trip; on a phone with a slow link it is seconds, and
/// every one of those seconds was a frozen UI that looked like a dead button.
/// A7.2: cold struct, size guard waived — one in flight at a time.
const PublishJob = struct {
    thread: ?std.Thread = null,
    done: std.atomic.Value(bool) = .init(false),

    // ── Inputs, copied in (the render thread's buffers keep moving) ──
    ln_buf: [256]u8 = undefined,
    ln_len: usize = 0,
    btc_buf: [256]u8 = undefined,
    btc_len: usize = 0,

    // ── Outputs, read on join ──
    saved: bool = false,
    /// A static string (the same vocabulary `saveReceiveAddress` returns), so it
    /// crosses the thread seam without an allocation to own.
    status: []const u8 = "",
};

/// The worker: one PDS write, then done. `session` is shared with the render
/// thread and mutated here (a write can rotate tokens) — which is exactly what
/// `Session.cred_lock` exists for; `auth.procedure` takes it.
fn publishWorker(
    job: *PublishJob,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    session: *auth.Session,
) void {
    const gpa = std.heap.page_allocator;
    var arena_state = std.heap.ArenaAllocator.init(gpa);
    defer arena_state.deinit();
    job.status = saveReceiveAddress(
        gpa,
        arena_state.allocator(),
        io,
        environ,
        session,
        job.ln_buf[0..job.ln_len],
        job.btc_buf[0..job.btc_len],
        &job.saved,
    );
    job.done.store(true, .release);
}

/// Start the publish. Returns a refusal to show immediately, or "" when the
/// worker is away (the button then says "Saving…" until the drain lands).
fn spawnPublish(rs: *RunState, io: std.Io, environ: ?*const std.process.Environ.Map, session: *auth.Session) []const u8 {
    if (rs.gpublish_busy) return ""; // already out; the button is disarmed anyway
    const ln = std.mem.trim(u8, rs.grecv_ln_buf[0..rs.grecv_ln_len], " ");
    const btc = std.mem.trim(u8, rs.grecv_btc_buf[0..rs.grecv_btc_len], " ");
    if (ln.len == 0 and btc.len == 0) return "Add a Lightning or Bitcoin address first";
    if (ln.len > rs.gpublish_job.ln_buf.len or btc.len > rs.gpublish_job.btc_buf.len)
        return "That address is too long";

    const job = &rs.gpublish_job;
    @memcpy(job.ln_buf[0..ln.len], ln);
    job.ln_len = ln.len;
    @memcpy(job.btc_buf[0..btc.len], btc);
    job.btc_len = btc.len;
    job.saved = false;
    job.status = "";
    job.done.store(false, .monotonic);
    job.thread = std.Thread.spawn(.{}, publishWorker, .{ job, io, environ, session }) catch
        return "Couldn't start the save — try again";
    rs.gpublish_busy = true;
    return "";
}


/// The wallet hand-off, done OFF the render thread.
///
/// This is the money path, and until now it ran inline on the click: a PDS
/// `getRecord` for the peer's address, and — for Lightning — two more HTTP legs
/// to turn their address into a BOLT11 invoice for the exact amount. On a slow
/// network the app simply stopped painting, at the precise moment a user is
/// deciding whether to trust it with money. `PAYMENTS_TEST_WALKTHROUGH.md` even
/// admitted it ("a slow PDS/LNURL fetch can hold a frame"). The standing law is
/// that network never runs on the render thread; this is that law applied where
/// it matters most.
///
/// Plain values cross the seam (E1). Inputs are page-alloc'd copies — the store
/// keeps mutating on the render thread and the worker must not borrow from it.
/// A7.2: cold struct, size guard waived — one in flight at a time.
const PaySendJob = struct {
    thread: ?std.Thread = null,
    done: std.atomic.Value(bool) = .init(false),

    // ── Inputs (owned; freed on join) ──
    stage: PayStage = .gate,
    peer_did: []u8 = &.{},
    note: []u8 = &.{},
    /// The BIP-21 label — the payee's handle, so the payer's wallet shows a name
    /// and not a bare address. Meaningful now that handles actually resolve.
    label: []u8 = &.{},
    /// The anchor this conversation PINS. The peer's address record must carry a
    /// signature under it, which is what stops a compromised PDS from rerouting
    /// the money — so it crosses the seam and is re-checked inside the worker.
    anchor: [32]u8 = undefined,
    rail: chat_core.Rail = .lightning,
    amount_sat: u64 = 0,
    /// The id of the REQUEST being paid, if this send answers one.
    paying: ?u64 = null,
    /// The conversation the caller was on, so the drain can refuse to apply a
    /// result to a conversation the user has since navigated away from.
    conv: u32 = 0,
    /// True when this job was started FROM the pay sheet, false when it came from
    /// a payment card's own Pay/Send button.
    ///
    /// The drain must know: a card-originated result that closed the sheet would
    /// tear down a compose the user is in the middle of, wipe their amount, and
    /// burn the once-per-session irreversibility disclosure for a payment they
    /// never made from that sheet. Only a sheet's own job may touch the sheet.
    from_sheet: bool = false,

    // ── Outputs ──
    /// They have a published, anchor-verified receive record.
    resolved: bool = false,
    uri_buf: [payuri.max_uri_len]u8 = undefined,
    uri_len: usize = 0,
    /// LUD-21: where THIS invoice can be watched. Empty when the payee's provider
    /// does not offer it — Strike and Wallet of Satoshi do not; Alby and Coinos
    /// do. Its presence is what decides whether this payment confirms itself or
    /// waits for someone to tap "Mark received".
    verify_buf: [512]u8 = undefined,
    verify_len: usize = 0,
    /// "" = no failure. Always a static literal, so it crosses the seam freely.
    err: []const u8 = "",
};

fn paySendJobFree(job: *PaySendJob) void {
    const a = std.heap.page_allocator;
    if (job.peer_did.len > 0) a.free(job.peer_did);
    if (job.note.len > 0) a.free(job.note);
    if (job.label.len > 0) a.free(job.label);
    job.peer_did = &.{};
    job.note = &.{};
    job.label = &.{};
}

/// The two slow legs, on a worker thread. Pure network + parse; it touches no
/// store and no UI state — the drain applies the outcome.
fn paySendWorker(job: *PaySendJob, io: std.Io, environ: ?*const std.process.Environ.Map) void {
    const a = std.heap.page_allocator;
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const arena = arena_state.allocator();

    const rails = (pay_addr.fetchPayee(a, arena, io, environ, job.peer_did, job.anchor) catch {
        job.err = "Couldn't verify their payment record";
        job.done.store(true, .release);
        return;
    }) orelse {
        // No published record. Not an error: a fresh send to someone who cannot
        // yet receive becomes an in-thread OFFER, and no money moves (§4.1).
        job.resolved = false;
        job.done.store(true, .release);
        return;
    };
    job.resolved = true;

    const addr = switch (job.rail) {
        .lightning => rails.lightning,
        .onchain => rails.bitcoin,
    };
    if (addr.len == 0) {
        job.err = switch (job.rail) {
            .lightning => "They don't take lightning \u{2014} try on-chain",
            .onchain => "They don't take on-chain \u{2014} try lightning",
        };
        job.done.store(true, .release);
        return;
    }
    if (job.stage == .gate) {
        // The gate only needed to know they can be paid on this rail.
        job.done.store(true, .release);
        return;
    }

    const uri: []const u8 = switch (job.rail) {
        .onchain => payuri.buildBitcoinUri(&job.uri_buf, addr, job.amount_sat, job.label, job.note) catch {
            job.err = "Their published address didn't validate";
            job.done.store(true, .release);
            return;
        },
        // Lightning EXACTNESS (LNURL-pay): resolve their address to a BOLT11
        // invoice for THIS amount, so the wallet cannot send a different number
        // than the card shows. This is the leg that could hang a frame.
        .lightning => ln: {
            const res = lnurl.resolveInvoice(arena, io, environ, addr, job.amount_sat) catch |err| {
                job.err = switch (err) {
                    error.AmountOutOfRange => "That amount is outside their wallet's limits",
                    error.NotPayEndpoint, error.BadAddress => "Their Lightning address didn't resolve",
                    error.OutOfMemory => "Out of memory",
                    else => "Couldn't reach their Lightning wallet \u{2014} try again",
                };
                job.done.store(true, .release);
                return;
            };
            if (res.verify.len > 0 and res.verify.len <= job.verify_buf.len) {
                @memcpy(job.verify_buf[0..res.verify.len], res.verify);
                job.verify_len = res.verify.len;
            }
            break :ln payuri.buildLightningInvoiceUri(&job.uri_buf, res.bolt11) catch {
                job.err = "Their wallet returned a bad invoice";
                job.done.store(true, .release);
                return;
            };
        },
    };
    // `buildBitcoinUri` / `buildLightningInvoiceUri` wrote into `uri_buf`; record
    // how much of it is real.
    job.uri_len = uri.len;
    job.done.store(true, .release);
}

// ---------------------------------------------------------------------------
// THE LIGHTNING SETTLEMENT WATCHER (LUD-21)
//
// The moment this whole subsystem was missing. A Lightning payment is approved
// inside the payer's own wallet — an app we hand off to and cannot see into —
// and settles on a rail we do not touch. So nobody outside the payee's wallet
// observed it, and the card sat at "Approve in your wallet" forever until a
// human tapped "Mark received". That button was a confession.
//
// LUD-21 closes it WITHOUT custody and without connecting a wallet: the invoice
// the payer fetched comes with a `verify` URL, and polling it answers exactly one
// question — has this landed? When it has, the card flips itself to Sent ✓ and
// the peer is signalled over the existing wire byte. Nobody had to be trusted and
// nobody had to be asked.
//
// It is not universal, and we never pretend it is: Alby and Coinos offer `verify`,
// Strike and Wallet of Satoshi do not (live-probed 2026-07-12). Which one you get
// is a property of the PAYEE's provider — precisely what their capability table
// told them when they set the wallet up. Where it is absent, "Mark received"
// stays, and it now says whose wallet made that necessary.
// ---------------------------------------------------------------------------

/// How many payments we watch at once. More than a couple in flight is already
/// unusual; the cap keeps this an inline array with no allocation churn.
const verify_watch_max: usize = 4;

/// A payment settles in seconds, so the first minute is polled BRISKLY — this is
/// the payoff moment and a lazy cadence would squander it. After that the payer
/// has plainly wandered off, and we back away.
const verify_fast_ns: u64 = 2 * std.time.ns_per_s;
const verify_slow_ns: u64 = 10 * std.time.ns_per_s;
const verify_fast_window_ns: u64 = 90 * std.time.ns_per_s;
/// Give up watching after this long. The card does NOT become "failed" — we
/// simply stop knowing, which is the honest outcome, and it falls back to the
/// manual confirm. We never infer a settlement from silence.
const verify_giveup_ns: u64 = 10 * std.time.ns_per_min;

/// One Lightning payment we are watching settle.
/// A7.2: cold struct, size guard waived — at most `verify_watch_max` exist.
const VerifyWatch = struct {
    payment_id: u64 = 0,
    conv: u32 = 0,
    url_buf: [512]u8 = undefined,
    url_len: usize = 0,
    started_ns: u64 = 0,
    /// Monotonic ns of the next due poll.
    next_ns: u64 = 0,
};

/// One watch handed to the worker, and its answer.
/// A7.2: cold struct, size guard waived.
const VerifyItem = struct {
    payment_id: u64,
    conv: u32,
    /// page-alloc'd copy — the render thread's watch array must not be borrowed
    /// across the seam.
    url: []u8,
    settled: bool = false,
};

/// A7.2: cold struct, size guard waived — a singleton.
const VerifyJob = struct {
    thread: ?std.Thread = null,
    done: std.atomic.Value(bool) = .init(false),
    items: []VerifyItem = &.{},
};

fn verifyJobFree(job: *VerifyJob) void {
    const a = std.heap.page_allocator;
    for (job.items) |it| a.free(it.url);
    if (job.items.len > 0) a.free(job.items);
    job.items = &.{};
}

/// Poll each due verify URL. Pure network; the drain applies the outcome.
fn verifyWorker(job: *VerifyJob, io: std.Io, environ: ?*const std.process.Environ.Map) void {
    const a = std.heap.page_allocator;
    for (job.items) |*it| {
        var arena_state = std.heap.ArenaAllocator.init(a);
        defer arena_state.deinit();
        it.settled = lnurl.verifySettled(arena_state.allocator(), io, environ, it.url);
    }
    job.done.store(true, .release);
}

/// Begin watching a payment we just handed to a wallet. A no-op when the payee's
/// provider offers no `verify` URL — in which case nothing can be watched, and
/// the card will wait for a human.
fn verifyWatchAdd(rs: *RunState, payment_id: u64, conv: u32, url: []const u8, now_ns: u64) void {
    if (url.len == 0 or url.len > 512) return;
    if (rs.gverify_n >= verify_watch_max) return;
    var w: VerifyWatch = .{
        .payment_id = payment_id,
        .conv = conv,
        .url_len = url.len,
        .started_ns = now_ns,
        // Poll almost immediately: a Lightning payment can land before the user
        // has finished putting their phone down.
        .next_ns = now_ns + std.time.ns_per_s,
    };
    @memcpy(w.url_buf[0..url.len], url);
    rs.gverify[rs.gverify_n] = w;
    rs.gverify_n += 1;
}

/// Drop the watch on `payment_id` (it settled, or it was withdrawn).
fn verifyWatchDrop(rs: *RunState, payment_id: u64) void {
    var i: usize = 0;
    while (i < rs.gverify_n) {
        if (rs.gverify[i].payment_id == payment_id) {
            rs.gverify[i] = rs.gverify[rs.gverify_n - 1];
            rs.gverify_n -= 1;
            continue;
        }
        i += 1;
    }
}

/// The watched payment ids, for the frame. Frame-arena owned.
fn verifyIdsOf(arena: Allocator, rs: *const RunState) []const u64 {
    if (rs.gverify_n == 0) return &.{};
    const out = arena.alloc(u64, rs.gverify_n) catch return &.{};
    for (out, 0..) |*o, i| o.* = rs.gverify[i].payment_id;
    return out;
}

/// True while any payment is being watched — the card shows it, and the shell
/// keeps animating.
fn verifyWatching(rs: *const RunState, payment_id: u64) bool {
    var i: usize = 0;
    while (i < rs.gverify_n) : (i += 1) {
        if (rs.gverify[i].payment_id == payment_id) return true;
    }
    return false;
}

/// Asking a wallet what it can do, off the render thread.
///
/// Two network legs (the provider's well-known document, then its invoice
/// callback), so this is emphatically not click work. It runs when an address is
/// SAVED — the moment the old code published a string it had never once tried to
/// use, and cheerfully reported "your wallet is good."
/// A7.2: cold struct, size guard waived — one at a time.
const WalletProbeJob = struct {
    thread: ?std.Thread = null,
    done: std.atomic.Value(bool) = .init(false),
    /// The address being interrogated (page-alloc'd copy; freed on join).
    addr: []u8 = &.{},
    /// What it answered. `receivable == false` ⇒ do not publish.
    caps: wallet_caps.Caps = .{},
    /// "" = the wallet answered. Otherwise the honest refusal to show.
    err: []const u8 = "",
};

fn walletProbeJobFree(job: *WalletProbeJob) void {
    const a = std.heap.page_allocator;
    if (job.addr.len > 0) a.free(job.addr);
    job.addr = &.{};
}

fn walletProbeWorker(job: *WalletProbeJob, io: std.Io, environ: ?*const std.process.Environ.Map) void {
    const a = std.heap.page_allocator;
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    job.caps = lnurl.probe(arena_state.allocator(), io, environ, job.addr) catch |err| {
        job.err = switch (err) {
            // The headline case: a well-formed address that belongs to nobody.
            error.NotPayEndpoint => "That address doesn't exist \u{2014} check it and try again",
            error.BadAddress => "That's not a Lightning address (it should look like you@wallet.com)",
            error.ProviderDown => "Couldn't reach that wallet \u{2014} try again",
            else => "Couldn't check that wallet \u{2014} try again",
        };
        job.done.store(true, .release);
        return;
    };
    job.done.store(true, .release);
}

/// A7.2: cold struct, size guard waived — a singleton, refreshed a few times an
/// hour. Worker-owned; the price crosses the seam as a plain integer (E1).
const PriceJob = struct {
    thread: ?std.Thread = null,
    done: std.atomic.Value(bool) = .init(false),
    usd_cents: u64 = 0,
    ok: bool = false,
};

/// The one field we read from the mempool.space prices document.
/// A7.2: cold struct, size guard waived — one per fetch, JSON-parse target only.
const PriceDoc = struct { USD: f64 = 0 };

/// The BTC/USD price source. mempool.space's `/api/v1/prices` (the same host
/// family as the chain watcher), overridable to a self-host with ZAT_PRICE_API.
fn priceSource(environ: ?*const std.process.Environ.Map) []const u8 {
    if (environ) |env| if (env.get("ZAT_PRICE_API")) |u| if (u.len > 0) return u;
    return "https://mempool.space/api/v1/prices";
}

/// Fetch BTC/USD off the render thread so the pay sheet's ≈$ readout never
/// costs a frame. USD is dollars per BTC in the response; we keep cents.
fn priceWorker(job: *PriceJob, io: std.Io, environ: ?*const std.process.Environ.Map) void {
    const a = std.heap.page_allocator;
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const resp = http.request(arena_state.allocator(), io, environ, priceSource(environ), .{
        .guard = .untrusted,
        .max_response_bytes = 8 * 1024,
    }) catch {
        job.done.store(true, .release);
        return;
    };
    if (resp.status == 200) {
        if (std.json.parseFromSliceLeaky(PriceDoc, arena_state.allocator(), resp.body, .{ .ignore_unknown_fields = true })) |p| {
            if (p.USD > 0) {
                job.usd_cents = @intFromFloat(@round(p.USD * 100));
                job.ok = true;
            }
        } else |_| {}
    }
    job.done.store(true, .release);
}

/// The compose flow's one verb: resolve what the user typed (a handle via
/// the PDS, or a literal `did:`), start the E2EE conversation, and open it
/// in the view store — the typed handle becomes the list label. Returns a
/// static status line ("" = success) and reports the opened conversation
/// through `sel_out`. Runs on the caller's thread — the recorded v1
/// first-contact posture (chat_e2ee module header): rare events, a worker
/// is the recorded upgrade if they ever jank.
fn chatStartCompose(
    gpa: Allocator,
    arena: Allocator,
    io: std.Io,
    env: ?*const std.process.Environ.Map,
    st: ?*chat_e2ee.State,
    link: ?*chat_relay.ChatRelay,
    cs: *chat_core.Store,
    typed_raw: []const u8,
    sel_out: *?chat_core.ConvIndex,
) []const u8 {
    const state = st orelse return "Chat is offline — no relay configured";
    const l = link orelse return "Chat is offline — no relay configured";
    var typed = std.mem.trim(u8, typed_raw, " ");
    if (typed.len > 0 and typed[0] == '@') typed = typed[1..]; // "@handle" reads naturally; accept it
    if (typed.len == 0) return "";

    var did: []const u8 = undefined;
    var handle: []const u8 = "";
    if (std.mem.startsWith(u8, typed, "did:")) {
        did = typed;
    } else {
        // The peer can live on ANY PDS: resolve the handle through the identity
        // module (DNS TXT / HTTPS well-known → verified DID document — the
        // bidirectional check, SSRF-guarded), never the viewer's own PDS
        // resolveHandle, which only knows its own accounts. That was the
        // cross-PDS bug, same class as the marketplace record fetch: chat with
        // any account hosted elsewhere failed "Couldn't resolve that handle"
        // (found on-device 2026-07-09). Arena-owned result, frame lifetime —
        // the same lifetime the old xrpc parse had.
        const identity = identity_shell.resolve(arena, io, env, .{}, typed) catch
            return "Couldn't resolve that handle";
        did = identity.did;
        handle = typed;
    }
    if (std.mem.eql(u8, did, state.my_did)) return "That's you — pick someone else";

    if (!chat_e2ee.hasConversation(state, did)) {
        chat_e2ee.startConversation(gpa, arena, io, env, state, l, did) catch |err| switch (err) {
            error.AlreadyOpen => {}, // raced ourselves; the view opens below
            error.NoConversation => {}, // unreachable on the start path
            error.NoKeyPackage => return "No chat keys published for that account",
            error.RelayDown => return "Relay unreachable — try again",
            error.CryptoFailed, error.OutOfMemory => return "Couldn't start the conversation",
        };
        // M2.1: subscribe the fresh conversation's traffic mailbox now —
        // the peer's first reply rides it, not the bootstrap inbox.
        chatEnsureSubs(gpa, state, l);
    }
    const conv = chat_core.openConversation(gpa, cs, did, handle) catch return "Couldn't start the conversation";
    sel_out.* = conv;
    chatPersistHistory(gpa, io, env, state, cs);
    return "";
}

/// One Zat4-keyboard key firing — shared by the desktop mouse dispatch and
/// the touch pump's PRESS-COMMIT (phone keys type at touch-DOWN, real
/// keyboard latency; the pump then suppresses the release tap so a key
/// never fires twice). Queues bytes for the next frame's input stream and
/// stamps the press flash.
fn kbdAction(rs: *RunState, gpa: Allocator, kind: feed_view.Action, post: u16) void {
    // TEMPORARY keylog for the fast-typing investigation (owner reads it
    // via `adb logcat -s zat4`): every commit, in byte-stream order, with
    // a monotonic stamp. Flip off after the verdict.
    rs.kbd_dirty = true;
    switch (kind) {
        .kbd_key => {
            if (post == 0) { // the emoji key: toggle the picker
                rs.kbd_emoji_open = !rs.kbd_emoji_open;
                rs.kbd_emoji_scroll = 0; // reopen at the top (the faces)
                rs.kbd_emoji_jump = -1;
                rs.kbd_nav_want = false; // the rollout never survives a toggle
                rs.kbd_nav_t = 0;
                rs.kbd_nav_scroll = 0;
                rs.kbd_nav_scroll_v = 0;
                rs.kbd_flash_key = 0xE005;
                rs.kbd_flash_ns = clock_shell.monotonicNanos();
                return;
            }
            var kb: [4]u8 = undefined;
            const kn = std.unicode.utf8Encode(@intCast(post), &kb) catch 0;
            if (kn > 0) rs.kbd_bytes.appendSlice(gpa, kb[0..kn]) catch {};
            // The decoder context: letters push their class; boundaries
            // collapse. (kbd_lm.classOf maps anything non-letter to 26.)
            if (post < 256) {
                const c = kbd_lm.classOf(@intCast(post));
                if (!(c == 26 and rs.kbd_hist_n > 0 and rs.kbd_hist[(rs.kbd_hist_n - 1) % 8] == 26)) {
                    rs.kbd_hist[rs.kbd_hist_n % 8] = c;
                    rs.kbd_hist_n += 1;
                }
            }
            if (!rs.kbd_caps) rs.kbd_shift = false; // one-shot unless locked
            rs.kbd_flash_key = post;
            rs.kbd_flash_ns = clock_shell.monotonicNanos();
        },
        // One-shot shift; a second tap inside the double-tap window LOCKS
        // caps; any tap while locked clears both.
        .kbd_shift => {
            const tns = clock_shell.monotonicNanos();
            if (rs.kbd_caps) {
                rs.kbd_caps = false;
                rs.kbd_shift = false;
            } else if (rs.kbd_shift and tns -| rs.kbd_shift_ns < 400_000_000) {
                rs.kbd_caps = true;
            } else {
                rs.kbd_shift = !rs.kbd_shift;
            }
            rs.kbd_shift_ns = tns;
            rs.kbd_flash_key = 0xE001;
            rs.kbd_flash_ns = tns;
        },
        // The layer key carries its TARGET page (0 letters / 1 symbols / 2
        // the "=\\<" layer) in the region payload. (The picker's old </>
        // paging posts are gone — it scrolls now.)
        .kbd_page => {
            rs.kbd_page = @intCast(@min(post, 2));
            rs.kbd_emoji_open = false; // abc closes the picker
            rs.kbd_emoji_jump = -1;
            rs.kbd_nav_want = false;
            rs.kbd_nav_t = 0;
            rs.kbd_nav_scroll = 0;
            rs.kbd_nav_scroll_v = 0;
            rs.kbd_flash_key = 0xE003;
            rs.kbd_flash_ns = clock_shell.monotonicNanos();
        },
        // The picker's bottom-left NAV square: toggle the rollout (the
        // pump eases kbd_nav_t toward the want).
        .kbd_nav => {
            rs.kbd_nav_want = !rs.kbd_nav_want;
            rs.kbd_flash_key = 0xE006;
            rs.kbd_flash_ns = clock_shell.monotonicNanos();
        },
        // A rollout entry: a category tab jumps the grid to its block; the
        // GIF entry swaps the section. EITHER WAY the choice is the
        // picker's new persistent home (saved by the loop's prefs drain —
        // the emoji key reopens here).
        .kbd_cat => {
            rs.kbd_nav_want = false;
            if (post == feed_view.emoji_nav_gif) {
                rs.kbd_picker_mode = 1;
            } else {
                rs.kbd_picker_mode = 0;
                rs.kbd_emoji_jump = @floatFromInt(feed_view.emojiCategoryScroll(post));
            }
            rs.kbd_prefs_dirty = true;
            rs.kbd_flash_key = 0xE006;
            rs.kbd_flash_ns = clock_shell.monotonicNanos();
        },
        // A picker cell: the atlas maps the CELL back to its codepoint.
        .kbd_emoji => {
            const cp: u21 = emoji_atlas.cps[@min(post, emoji_atlas.count - 1)];
            var eb: [4]u8 = undefined;
            const en = std.unicode.utf8Encode(cp, &eb) catch 0;
            if (en > 0) rs.kbd_bytes.appendSlice(gpa, eb[0..en]) catch {};
            if (!(rs.kbd_hist_n > 0 and rs.kbd_hist[(rs.kbd_hist_n - 1) % 8] == 26)) {
                rs.kbd_hist[rs.kbd_hist_n % 8] = 26;
                rs.kbd_hist_n += 1;
            }
            rs.kbd_flash_key = 0xE005;
            rs.kbd_flash_ns = clock_shell.monotonicNanos();
        },
        // One delete per press; a HELD press repeats via the pump's timer.
        .kbd_backspace => {
            rs.kbd_bytes.append(gpa, 8) catch {};
            if (rs.kbd_hist_n > 0) rs.kbd_hist_n -= 1; // the context pops too
            rs.kbd_flash_key = 0xE002;
            rs.kbd_flash_ns = clock_shell.monotonicNanos();
        },
        else => {},
    }
}

/// Append one codepoint to a fixed byte buffer as UTF-8 — the chat draft
/// and recipient bar take real glyphs, not just ASCII (₿ was silently
/// dropped on-device, 2026-07-10). False = no room / unencodable.
fn pushUtf8(buf: []u8, len: *usize, cp: u21) bool {
    var eb: [4]u8 = undefined;
    const en = std.unicode.utf8Encode(cp, &eb) catch return false;
    if (len.* + en > buf.len) return false;
    @memcpy(buf[len.*..][0..en], eb[0..en]);
    len.* += en;
    return true;
}

/// Insert one codepoint at the caret (UTF-8), shifting the tail right.
fn insertUtf8At(buf: []u8, len: *usize, at: *usize, cp: u21) bool {
    var eb: [4]u8 = undefined;
    const en = std.unicode.utf8Encode(cp, &eb) catch return false;
    if (len.* + en > buf.len) return false;
    const a = @min(at.*, len.*);
    std.mem.copyBackwards(u8, buf[a + en .. len.* + en], buf[a..len.*]);
    @memcpy(buf[a..][0..en], eb[0..en]);
    len.* += en;
    at.* = a + en;
    return true;
}

/// Backspace one full UTF-8 sequence BEFORE the caret, closing the gap.
fn deleteUtf8Before(buf: []u8, len: *usize, at: *usize) void {
    const a = @min(at.*, len.*);
    if (a == 0) {
        at.* = 0;
        return;
    }
    var st = a - 1;
    while (st > 0 and buf[st] >= 0x80 and buf[st] < 0xC0) st -= 1;
    std.mem.copyForwards(u8, buf[st .. st + (len.* - a)], buf[a..len.*]);
    len.* -= a - st;
    at.* = st;
}

/// One caret step left/right over UTF-8 sequence boundaries.
fn caretLeftUtf8(buf: []const u8, at: *usize) void {
    if (at.* == 0) return;
    at.* -= 1;
    while (at.* > 0 and buf[at.*] >= 0x80 and buf[at.*] < 0xC0) at.* -= 1;
}
fn caretRightUtf8(buf: []const u8, len: usize, at: *usize) void {
    if (at.* >= len) return;
    at.* += 1;
    while (at.* < len and buf[at.*] >= 0x80 and buf[at.*] < 0xC0) at.* += 1;
}

/// Backspace one full UTF-8 sequence (never strand continuation bytes).
fn popUtf8(buf: []const u8, len: *usize) void {
    while (len.* > 0) {
        len.* -= 1;
        const b = buf[len.*];
        if (b < 0x80 or b >= 0xC0) return; // consumed through the lead byte
    }
}

/// Delete the draft's selection (if any), closing the gap and parking the
/// caret at the wound. False = there was no selection.
fn chatDeleteSelection(rs: *RunState) bool {
    const a = @min(rs.gchat_sel_a, rs.gchat_draft_len);
    const b = @min(rs.gchat_sel_b, rs.gchat_draft_len);
    if (b <= a) return false;
    std.mem.copyForwards(u8, rs.gchat_draft_buf[a .. rs.gchat_draft_len - (b - a)], rs.gchat_draft_buf[b..rs.gchat_draft_len]);
    rs.gchat_draft_len -= b - a;
    rs.gchat_caret = a;
    rs.gchat_sel_a = 0;
    rs.gchat_sel_b = 0;
    return true;
}

/// Collapse the selection + drop the edit bar (any ordinary edit does).
fn chatCollapseSel(rs: *RunState) void {
    rs.gchat_sel_a = 0;
    rs.gchat_sel_b = 0;
    rs.gchat_edit_bar = false;
}

/// The tap decoder's two-class context (the last two typed), or the
/// disabled sentinel when the smart-targeting toggle is off.
fn kbdCtx(rs: *const RunState) [2]u8 {
    if (!toggleOn(rs.toggle_bits, settings_view.act_kbd_lm)) return .{ 255, 255 };
    const n = rs.kbd_hist_n;
    const c2: u8 = if (n > 0) rs.kbd_hist[(n - 1) % 8] else 26;
    const c1: u8 = if (n > 1) rs.kbd_hist[(n - 2) % 8] else 26;
    return .{ c1, c2 };
}

/// The razor-tap re-stamp: the frame's Grid was snapshotted BEFORE input
/// ran, so a keystroke's flash/pop/draft rendered one frame late. Refresh
/// the volatile keyboard + chat-draft view fields from live state right
/// before a mid-lap or lap-end paint, and the press's pixels land the same
/// tick as the finger.
fn kbdRestamp(rs: *RunState, pix: *?Grid) void {
    rs.kbd_dirty = false;
    if (pix.*) |*g| {
        g.kbd_shift = rs.kbd_shift;
        g.kbd_caps = rs.kbd_caps;
        g.kbd_page = rs.kbd_page;
        g.kbd_flash_key = rs.kbd_flash_key;
        g.kbd_flash_a = kbdFlashAlpha(rs);
        g.kbd_popup = .{ .opts = rs.kbd_popup_opts[0..rs.kbd_popup_n], .anchor_x = rs.kbd_popup_ax, .anchor_y = rs.kbd_popup_ay, .anchor_w = rs.kbd_popup_aw, .sel = rs.kbd_popup_sel };
        g.kbd_emoji_open = rs.kbd_emoji_open;
        g.kbd_emoji_scroll = @intFromFloat(rs.kbd_emoji_scroll);
        g.kbd_picker_mode = rs.kbd_picker_mode;
        g.kbd_nav_t = rs.kbd_nav_t;
        g.kbd_nav_scroll = @intFromFloat(rs.kbd_nav_scroll);
        g.chat_draft = rs.gchat_draft_buf[0..rs.gchat_draft_len];
        g.chat_edit = .{ .caret = @min(rs.gchat_caret, rs.gchat_draft_len), .sel_a = @min(rs.gchat_sel_a, rs.gchat_draft_len), .sel_b = @min(rs.gchat_sel_b, rs.gchat_draft_len), .bar = rs.gchat_edit_bar };
        g.chat_key_ns = rs.gchat_key_ns;
        g.chat_compose = rs.gchat_peer_buf[0..rs.gchat_peer_len];
    }
}

/// The razor-tap paint for COMPOSE mode. The two razor sites below used to
/// call paintFrame — the TIMELINE funnel — regardless of mode, so every
/// keystroke in the post composer swapped one FEED frame before the next
/// lap's top paint swapped the composer back: typing flickered feed/composer
/// on the phone (on-device, 2026-07-12). Compose mode re-renders its own
/// surface instead, keeping the same-tick key latency.
fn paintComposeRazor(gpa: Allocator, arena: Allocator, rs: *RunState, pix: ?Grid, backend: Backend) void {
    const g = pix orelse return;
    // Software/terminal composers have no Zat4 keyboard; the next lap's top
    // paint covers them.
    const gs = g.gpu orelse return;
    const dims: struct { w: u32, h: u32 } = switch (backend) {
        .window => |win| .{ .w = win.fb.width, .h = win.fb.height },
        .mobile => |m| .{ .w = m.width_px, .h = m.height_px },
        .terminal => return,
    };
    const ctx: feed_view.ComposeContext = if (rs.compose_kind == .profile)
        .profile
    else if (rs.reply_handle.len > 0) .reply else .post;
    var tb_chips: [max_manual_tags][]const u8 = undefined;
    const tb_view = tagBarViewOf(arena, rs, &tb_chips);
    paintComposeGpu(gpa, dims.w, dims.h, g, gs, ctx, rs.reply_handle, rs.quoting_handle, textedit.view(&rs.compose), rs.compose.caret, textedit.selStart(&rs.compose), textedit.selEnd(&rs.compose), composeBlinkOn(rs.caret_anchor_ns), rs.status, rs.chain_segments.items, tb_view) catch {};
}

/// TEMPORARY typo-gap keylog (2026-07-12, owner investigation): one `d`
/// line per typed key at touch-DOWN — the offset from the resolved key's
/// center in RAW logical space (the resolver's 5px lift is NOT applied
/// here; subtract it offline) — and one `u` line at the release with the
/// same-space offset (u − d = the finger-roll vector) + the hold time.
/// Backspaces log `bs` for correction pairing; a slide-off cancel logs
/// `x`. Read via `adb logcat -s zat4`; strip after the verdict.
/// Chat bring-up narration reaches BOTH surfaces: stderr (desktop) and
/// logcat (phone). The 2026-07-12 disappeared-conversations incident was
/// undiagnosable from the device because these lines printed only to
/// stderr, which Android drops.
fn chatLog(comptime fmt: []const u8, args: anytype) void {
    std.debug.print(fmt ++ "\n", args);
    mobile_host.logcat(fmt, args);
}

fn ktLogDown(m: anytype, kh: feed_view.Region, klx: i32, kly: i32) void {
    m.kt_cp = kh.post;
    m.kt_kx = kh.x;
    m.kt_ky = kh.y;
    m.kt_kw = kh.w;
    m.kt_kh = kh.h;
    std.debug.print("[kt] d cp={d} rx={d} ry={d} multi={d}\n", .{ kh.post, klx - (@as(i32, kh.x) + @divTrunc(@as(i32, kh.w), 2)), kly - (@as(i32, kh.y) + @divTrunc(@as(i32, kh.h), 2)), @as(u1, @intFromBool(m.kbd_multi)) });
}

/// Thumbs consistently strike BELOW the key they aim at — resolve keyboard
/// presses this many logical px above the touch centroid (the correction
/// every serious keyboard applies; per-user learning is the follow-up).
const kbd_touch_bias_y: i32 = 5;

/// The Zat4 keyboard's press-flash alpha this frame: full at the press,
/// gone 220 ms later. Nonzero alpha folds into feed_sig, so the fade
/// rebuilds the keyboard tile frame-by-frame only while it runs.
fn kbdFlashAlpha(rs: *const RunState) u8 {
    if (rs.kbd_flash_key == 0) return 0;
    const age = clock_shell.monotonicNanos() -| rs.kbd_flash_ns;
    // A full-bright ATTACK (~2 frames) then a fast fall — the snap is what
    // reads as crispness; a slow even fade read as lag.
    // Held = full; release = a ~2-frame vanish. The platform keyboards'
    // spam test (owner, 2026-07-12): spamming a key must BLINK the pop per
    // press — a slow fade reads as a frozen pop, i.e. wasted frames.
    const attack: u64 = 25_000_000;
    const dur: u64 = 60_000_000;
    if (rs.kbd_flash_held) return 190; // held: the pop stays until release
    if (age < attack) return 190;
    if (age >= dur) return 0;
    // Quantized: each level is one vert rebuild, not each frame.
    const a: u8 = @intCast(190 - (age - attack) * 190 / (dur - attack));
    return a & 0xE0;
}

/// M2.1: keep the relay subscribed to every mailbox we currently drain —
/// the bootstrap inbox + each conversation's current-epoch traffic mailbox.
/// An idempotent walk (chat_relay.subscribe dedupes), run after any drained
/// batch (a Welcome or an epoch advance may have minted a fresh ID) and
/// after starting a conversation. Old-epoch subscriptions linger for the
/// session — that lingering IS the look-behind window.
fn chatEnsureSubs(gpa: Allocator, st: *const chat_e2ee.State, link: *chat_relay.ChatRelay) void {
    const subs = chat_e2ee.subscriptions(gpa, st) catch return;
    defer gpa.free(subs);
    for (subs) |id| chat_relay.subscribe(link, id) catch {};
}

/// M2 persist: the displayed history survives a relaunch. Serialize the view
/// store (pure core codec) and hand cache the blob — sealed at rest under a
/// keystore-held key, per account. A quiet no-op without a live E2EE session
/// (no DID to key the file by, and nothing durable to show); a failed write
/// drops this snapshot, never the frame — the next mutation rewrites the
/// whole blob anyway.
fn chatPersistHistory(gpa: Allocator, io: std.Io, env: ?*const std.process.Environ.Map, st: ?*const chat_e2ee.State, cs: *const chat_core.Store) void {
    const state = st orelse return;
    const blob = chat_core.serializeStore(gpa, cs) catch return;
    defer {
        std.crypto.secureZero(u8, blob); // the transcript passes through
        gpa.free(blob);
    }
    var path_buf: [512]u8 = undefined;
    const path = cache_shell.chatHistoryPath(&path_buf, env, state.my_did) orelse return;
    _ = cache_shell.saveChatHistoryAt(gpa, io, path, state.my_did, blob);
}

/// Does a conversation row match the list-search query? Name or preview,
/// case-insensitive — the ONE predicate the render and the tap mapping share.
fn chatRowMatches(row: chat_view_core.ListRow, query: []const u8) bool {
    return std.ascii.indexOfIgnoreCase(row.name, query) != null or
        std.ascii.indexOfIgnoreCase(row.preview, query) != null;
}

/// The conversation at FILTERED ordinal `row` — the tap mapping. Applies the
/// same activity order + search predicate the render used, so the row tapped
/// is the row seen. Empty query = the plain activity order.
fn chatConvAt(arena: Allocator, cs: *const chat_core.Store, now: i64, query: []const u8, row: usize) ?chat_core.ConvIndex {
    const order = chat_core.conversationsByActivity(arena, cs) catch return null;
    if (query.len == 0) return if (row < order.len) order[row] else null;
    const list = chat_view_core.buildList(arena, cs, now) catch return null;
    var seen: usize = 0;
    for (order, 0..) |c, i| {
        if (i >= list.len) break;
        if (!chatRowMatches(list[i], query)) continue;
        if (seen == row) return c;
        seen += 1;
    }
    return null;
}

/// `watching` carries the payment ids the settlement watcher currently has an
/// eye on (LUD-21) — a NETWORK fact the store cannot know, so the shell folds it
/// onto the cards here rather than teaching the pure view about providers.
fn buildChatFrame(arena: Allocator, cs: *const chat_core.Store, sel: ?chat_core.ConvIndex, now: i64, query: []const u8, watching: []const u64) ChatFrame {
    const full = chat_view_core.buildList(arena, cs, now) catch return .{};
    // The list-search filter (phone): rows and the selected ordinal both live
    // in FILTERED space, in lockstep with chatConvAt's tap mapping.
    var list = full;
    if (query.len > 0) {
        var kept: std.ArrayList(chat_view_core.ListRow) = .empty;
        for (full) |row| {
            if (chatRowMatches(row, query)) kept.append(arena, row) catch return .{ .list = full };
        }
        list = kept.items;
    }
    var out: ChatFrame = .{ .list = list };
    const sc = sel orelse return out;
    const order = chat_core.conversationsByActivity(arena, cs) catch return out;
    var seen: u16 = 0;
    for (order, 0..) |c, i| {
        if (query.len > 0) {
            if (i >= full.len or !chatRowMatches(full[i], query)) continue;
        }
        if (c == sc) {
            out.sel = seen;
            break;
        }
        seen += 1;
    }
    if (out.sel != std.math.maxInt(u16) and out.sel < list.len) {
        out.peer = list[out.sel].name;
        const th = chat_view_core.buildThread(arena, cs, sc, now) catch chat_view_core.Thread{};
        out.thread = th.rows;
        out.cards = th.cards;
        // Fold on what the settlement watcher knows. `th.cards` is arena-owned
        // and ours to mark.
        if (watching.len > 0) {
            for (out.cards) |*c| {
                for (watching) |wid| {
                    if (c.payment_id == wid) {
                        c.watching = true;
                        break;
                    }
                }
            }
        }
        // The same message order `buildThread` iterated, exposed so the shell can
        // bind its per-bubble springs to rows by key (U6b). 1:1 with `th.rows`.
        out.order = chat_core.threadSlice(arena, cs, sc) catch &.{};
    }
    return out;
}

fn buildActiveView(arena: Allocator, store: *feed_core.Store, screen: u8, profile_did: []const u8, thread_cid: []const u8, zone_tag: []const u8, rerooted: bool, collapsed: []const []const u8, feed_config: ?discover.FeedConfig, reply_config: ?discover.FeedConfig, now: i64) error{OutOfMemory}![]feed_core.TimelineItem {
    if (screen == feed_view.screen_thread) return feed_core.buildThreadView(arena, store, thread_cid, rerooted, collapsed, now, reply_config);
    if (screen == feed_view.screen_profile) return feed_core.buildAuthorView(arena, store, profile_did);
    if (screen == feed_view.screen_zones) return feed_core.buildTagView(arena, store, zone_tag);
    if (feed_config) |cfg| return feed_core.buildDiscoverView(arena, store, cfg, now, null);
    return feed_core.buildTimeline(arena, store);
}

/// The profile header on the profile screen, else null. Derives the viewed
/// account's identity from its posts (the handle/display name the AppView
/// serves), falling back to your own session handle for an empty OWN profile,
/// else the target DID. Works for any author (tap-to-profile).
fn profileHeaderFor(arena: Allocator, session: *const auth.Session, screen: u8, target_did: []const u8, view_items: []const feed_core.TimelineItem) error{OutOfMemory}!?feed_view.ProfileHeader {
    if (screen != feed_view.screen_profile) return null;
    const first_handle = if (view_items.len > 0) view_items[0].author_handle else "";
    const first_name = if (view_items.len > 0) view_items[0].author_display_name else "";
    const is_self = std.mem.eql(u8, target_did, session.did);
    const handle_src = if (first_handle.len > 0) first_handle else if (is_self) session.handle else target_did;
    const name = if (first_name.len > 0) first_name else handle_src;
    return .{
        .display_name = name,
        .handle = try std.fmt.allocPrint(arena, "@{s}", .{handle_src}),
        .post_count = @intCast(view_items.len),
        .editable = is_self, // your own profile gets the "Edit profile" button
    };
}

/// Pull the author DID out of an at-uri (`at://{did}/{collection}/{rkey}`),
/// so a tap on a post's avatar can open that author's profile. "" if malformed.
fn authorDidFromUri(uri: []const u8) []const u8 {
    if (!std.mem.startsWith(u8, uri, "at://")) return "";
    const rest = uri["at://".len..];
    const slash = std.mem.indexOfScalar(u8, rest, '/') orelse return rest;
    return rest[0..slash];
}

const EngageResult = struct {
    // A7.2: cold struct, size guard waived — one per action, returned by value.

    /// Status to show ("" = leave the current status alone).
    status: []const u8,
    /// True on the network-error path: the caller skips the rest of this
    /// input batch, exactly as the inline arms did.
    skip_rest: bool = false,
};

fn engageSelected(
    kind: Engagement,
    gpa: Allocator,
    arena: Allocator,
    session: *auth.Session,
    store: *feed_core.Store,
    item: feed_core.TimelineItem,
    target: u32,
    /// The active Screen + the profile's author DID + the thread's focus cid, so
    /// the optimistic repaint rebuilds the SAME view the tap came from (Home,
    /// a profile, or a thread).
    screen: u8,
    profile_did: []const u8,
    thread_cid: []const u8,
    /// The open zone's tag, so a like on the zone page repaints the zone view.
    zone_tag: []const u8,
    thread_rerooted: bool,
    collapsed_cids: []const []const u8,
    /// The seated FEED and REPLY lens configs (null = the no-scoring path), so
    /// the optimistic repaint rebuilds the active surface through the SAME
    /// algorithm it's showing (Home scored / a thread's siblings ordered).
    feed_config: ?discover.FeedConfig,
    reply_config: ?discover.FeedConfig,
    state: *timeline_ui.UiState,
    revealed_cids: []const []const u8,
    now: i64,
    out: *std.Io.Writer,
    prev: *tui.Surface,
    next: *tui.Surface,
    backend: Backend,
    pix: ?Grid,
    writer: ?*write_worker.Worker,
    /// Deferred-undo intent sets (by post-cid hash) for the case where the user
    /// un-engages before the create's record uri is known — see the drain.
    def_unlike: *std.AutoHashMapUnmanaged(u64, void),
    def_unrepost: *std.AutoHashMapUnmanaged(u64, void),
) !EngageResult {
    const applied = switch (kind) {
        .like => feed_core.applyLike(store, item.cid),
        .repost => feed_core.applyRepost(store, item.cid),
    };
    switch (applied) {
        .already => {
            // Toggle: already engaged, so this press DISENGAGES. The
            // verdict's uri borrows the store's bytes — copy it out
            // before anything can append (the revert path appends).
            const dis = switch (kind) {
                .like => feed_core.applyUnlike(store, item.cid),
                .repost => feed_core.applyUnrepost(store, item.cid),
            };
            const borrowed = switch (dis) {
                .applied => |uri| uri,
                .not_engaged, .unknown => return .{ .status = "" },
                // The record uri isn't known yet (the create is still in
                // flight). Don't make the user wait: hollow the heart NOW and
                // remember to delete the record the instant the create returns
                // its uri (handled in the write-result drain). Undo is instant.
                .no_record_uri => {
                    const acted = switch (kind) {
                        .like => feed_core.applyUnlikeDeferred(store, item.cid),
                        .repost => feed_core.applyUnrepostDeferred(store, item.cid),
                    };
                    if (!acted) return .{ .status = "" };
                    const set = if (kind == .like) def_unlike else def_unrepost;
                    set.put(gpa, std.hash.Wyhash.hash(0, item.cid), {}) catch {};
                    const fresh = try buildActiveView(arena, store, screen, profile_did, thread_cid, zone_tag, thread_rerooted, collapsed_cids, feed_config, reply_config, now);
                    const fresh_header = try profileHeaderFor(arena, session, screen, profile_did, fresh);
                    try paintFrame(gpa, out, arena, prev, next, backend, pix, fresh, fresh_header, state, revealed_cids, now, session.handle, if (kind == .like) "unliking..." else "unboosting...");
                    if (pix) |g| fireEngageEffect(gpa, g, kind, target, false);
                    return .{ .status = if (kind == .like) "unliking..." else "unboosting..." };
                },
            };
            var uri_buf: [512]u8 = undefined;
            if (borrowed.len > uri_buf.len) {
                // Absurd uri: undo the optimistic state while the borrow
                // is still valid (nothing has appended yet) and refuse.
                try revertDisengage(kind, gpa, store, item.cid, borrowed);
                return .{ .status = "refused: bad record uri" };
            }
            const record_uri = uri_buf[0..borrowed.len];
            @memcpy(record_uri, borrowed);

            const fresh = try buildActiveView(arena, store, screen, profile_did, thread_cid, zone_tag, thread_rerooted, collapsed_cids, feed_config, reply_config, now);
            const fresh_header = try profileHeaderFor(arena, session, screen, profile_did, fresh);
            try paintFrame(gpa, out, arena, prev, next, backend, pix, fresh, fresh_header, state, revealed_cids, now, session.handle, if (kind == .like) "unliking..." else "unboosting...");
            // Fire the drain effect at the post's heart cell (state is now
            // DISENGAGED → the cooler recipe). One trigger, derived from the
            // actual transition — no click-path race.
            if (pix) |g| fireEngageEffect(gpa, g, kind, target, false);
            // SUBMIT the delete to the write worker and RETURN — the UI loop
            // keeps running, the drain animation plays smoothly every frame,
            // and the worker's result (drained later) reverts only on a
            // refusal. If the worker is unavailable (start failed) or its
            // queue is full, fall back to reverting now so state stays true.
            if (writer) |w| {
                if (!write_worker.submit(w, if (kind == .like) .unlike else .unrepost, item.cid, "", "", record_uri, now)) {
                    try revertDisengage(kind, gpa, store, item.cid, record_uri);
                    return .{ .status = "busy, try again" };
                }
                return .{ .status = if (kind == .like) "unliking..." else "unboosting..." };
            } else {
                try revertDisengage(kind, gpa, store, item.cid, record_uri);
                return .{ .status = "write unavailable" };
            }
        },
        .unknown => return .{ .status = "" },
        .applied => {},
    }

    // Optimistic first: the bumped count paints now; the worker call
    // follows on its own thread; a refusal reverts (drained in the loop).
    const fresh = try buildActiveView(arena, store, screen, profile_did, thread_cid, zone_tag, thread_rerooted, collapsed_cids, feed_config, reply_config, now);
    const fresh_header = try profileHeaderFor(arena, session, screen, profile_did, fresh);
    try paintFrame(gpa, out, arena, prev, next, backend, pix, fresh, fresh_header, state, revealed_cids, now, session.handle, if (kind == .like) "liking..." else "boosting...");
    // Fire the like/boost burst at the post's heart cell (state is now
    // ENGAGED). One trigger derived from the transition.
    if (pix) |g| fireEngageEffect(gpa, g, kind, target, true);
    // SUBMIT the create to the worker and RETURN immediately — no blocking
    // network call on the render thread, so the burst animation plays
    // smoothly in the main loop. The worker posts its result back; only a
    // refusal reverts the optimistic count.
    if (writer) |w| {
        if (!write_worker.submit(w, if (kind == .like) .like else .repost, item.cid, item.uri, item.cid, "", now)) {
            revertEngagement(kind, store, item.cid);
            return .{ .status = "busy, try again" };
        }
        return .{ .status = if (kind == .like) "liking..." else "boosting..." };
    } else {
        revertEngagement(kind, store, item.cid);
        return .{ .status = "write unavailable" };
    }
}

// (legacy synchronous engage path removed — the worker handles writes now)
fn revertDisengage(kind: Engagement, gpa: Allocator, store: *feed_core.Store, cid: []const u8, uri: []const u8) error{OutOfMemory}!void {
    switch (kind) {
        .like => try feed_core.revertUnlike(gpa, store, cid, uri),
        .repost => try feed_core.revertUnrepost(gpa, store, cid, uri),
    }
}

/// The status-line noun for a view-load failure — which screen's fetch it
/// was, so "network error" says whose.
fn viewNoun(kind: view_worker.Kind) []const u8 {
    return switch (kind) {
        .profile => "profile",
        .thread => "thread",
        .zone => "zone",
        .zones => "zones",
        .algorithms => "marketplace",
    };
}

/// Undo the optimistic state for a write the worker reported as refused
/// or failed. A refused CREATE (like/repost) is undone by removing the
/// optimistic engagement (cid only). A refused DELETE (unlike/unrepost)
/// is undone by RESTORING the engagement, which needs the original record
/// uri the request carried back (revert_uri). Matches by CID; if the post
/// has scrolled out of the store, the revert is a no-op (the lookup
/// misses) — benign, the next refresh reconciles.
fn revertWrite(kind: write_worker.Request.Kind, gpa: Allocator, store: *feed_core.Store, cid: []const u8, revert_uri: []const u8) error{OutOfMemory}!void {
    switch (kind) {
        .like => feed_core.revertLike(store, cid),
        .repost => feed_core.revertRepost(store, cid),
        .unlike => try feed_core.revertUnlike(gpa, store, cid, revert_uri),
        .unrepost => try feed_core.revertUnrepost(gpa, store, cid, revert_uri),
        .loadout => {}, // loadout writes are not optimistic; nothing to revert
        .publish_algo => {}, // the dev flow reconciles its own state (no store optimism)
        .delete_algo => {}, // the dashboard reconciles its own state
        .chain => {}, // the chain drain drops its optimistic post explicitly
    }
}

/// Undo an optimistic like/repost (the CREATE direction) — used on the
/// submit-failure fallback in engageSelected when the worker queue is
/// full or unavailable. Removing the engagement needs only the CID.
fn revertEngagement(kind: Engagement, store: *feed_core.Store, cid: []const u8) void {
    switch (kind) {
        .like => feed_core.revertLike(store, cid),
        .repost => feed_core.revertRepost(store, cid),
    }
}

/// The pixel path's working set, threaded as one explicit handle
/// (house style: plain pointers, no hidden state). A7.2: cold struct,
/// size guard waived — one per run(), stack-only.
/// The live glyph-field state for the window — the cutover's working
/// set (GLYPH_FIELD_SYSTEM_DESIGN G.0), threaded as one handle (house
/// style: plain pointers, no hidden state). A7.2: cold struct, waived —
/// one per run(). The font engine renders the mono cells; the field IS
/// the UI (every glyph a physics cell); active are the playing effects;
/// particles the transient agents; hr the click map; view the
/// scroll/selection; spawn_buf scratch for the events effects emit.
/// Resolve a persisted surface (id/color entries → gpa-owned cards + blob) via
/// the catalog. No-op when the surface has no entries (caller then uses the
/// default). Sets `cards`/`blob`/`seated` on success.
fn buildSurfaceFromEntries(gpa: Allocator, se: loadout_store.SurfaceEntries, lib: *const algo_library.Library, cards: *[]lens_socket.LensCard, blob: *[]const u8, seated: *u32) void {
    if (se.entries.len == 0) return;
    // Library-aware: a persisted entry may be a created/installed algorithm,
    // not a built-in (ALGO_SUBMISSION slice 3). Scratch feeds the derived-flag
    // config parse and dies here (C3).
    var scratch_state = std.heap.ArenaAllocator.init(gpa);
    defer scratch_state.deinit();
    if (lens_catalog.loadoutFromEntriesLib(gpa, se.entries, lib, scratch_state.allocator())) |t| {
        cards.* = t[0];
        blob.* = t[1];
        seated.* = se.seated;
    } else |_| {}
}

/// Extract a surface's persist form (parallel id/color arrays + seated) from
/// its live cards + blob, into `arena`. The ids are slices into `blob`; the
/// caller (worker submit / saveAll) copies them as needed.
fn surfaceDataOf(arena: Allocator, cards: []const lens_socket.LensCard, blob: []const u8, seated: u32) loadout_store.SurfaceData {
    const ids = arena.alloc([]const u8, cards.len) catch return .{};
    const colors = arena.alloc(u8, cards.len) catch return .{};
    for (cards, 0..) |c, i| {
        const end = @min(blob.len, @as(usize, c.cid.off) + c.cid.len);
        ids[i] = if (c.cid.off <= blob.len) blob[@min(c.cid.off, blob.len)..end] else "";
        colors[i] = c.color;
    }
    return .{ .ids = ids, .colors = colors, .seated = seated };
}

/// Apply a socket action to a surface on the LOADOUT PAGE (click-only: seat,
/// recolor, expand — drag-reorder on the page is a later slice). Mutates the
/// surface's seated/color/ui and flags it dirty. Unlike the home feed handler
/// there is no scroll/close/plug-in animation — the page socket is always open.
fn applyLoadoutAction(sact: lens_socket.SocketAction, cards: []lens_socket.LensCard, blob: []const u8, seated: *u32, ui: *lens_socket.SocketUi, dirty: *bool) void {
    switch (sact) {
        .seat => |cid| {
            if (trayIndexOfCid(cards, blob, cid)) |idx| {
                seated.* = idx;
                dirty.* = true;
            }
            ui.expanded = null;
            ui.picking = null;
        },
        .expand => |cid| {
            if (trayIndexOfCid(cards, blob, cid)) |idx| {
                ui.expanded = if (ui.expanded == idx) null else idx;
            }
        },
        .collapse => ui.expanded = null,
        .open_swatch => |cid| {
            const idx = trayIndexOfCid(cards, blob, cid);
            ui.picking = if (ui.picking == idx) null else idx;
        },
        .set_color => |sc2| {
            if (trayIndexOfCid(cards, blob, sc2.lens)) |idx| {
                if (idx < cards.len) cards[idx].color = sc2.color;
                dirty.* = true;
            }
            ui.picking = null;
        },
        else => {}, // toggle_tray / reorder / get_more: not used on the page
    }
}

/// Drop a dragged page socket: reorder the surface's cards to the slot under
/// the pointer (using that socket's on-page geometry), keep the seated lens by
/// CID, and start the settle. Flags dirty. Mirrors the home-feed drop.
fn pageDragDrop(cards: []lens_socket.LensCard, blob: []const u8, seated: *u32, ui: *lens_socket.SocketUi, geom: lens_socket.Geometry, dirty: *bool) void {
    if (ui.drag_active) |d| {
        const tray: lens_socket.TrayView = .{ .cards = cards, .text = blob, .seated = seated.* };
        // Force open for the insertion math — the page socket renders open but
        // its stored `open` is false (which dropIndex would reject).
        var oui = ui.*;
        oui.open = true;
        const to: u32 = lens_socket.dropIndex(tray, oui, geom) orelse d;
        const seated_off = if (seated.* < cards.len) cards[seated.*].cid.off else 0;
        reorderTray(cards, d, to);
        for (cards, 0..) |c, ix| {
            if (c.cid.off == seated_off) {
                seated.* = @intCast(ix);
                break;
            }
        }
        ui.drag_active = to;
        ui.settle_phase = 1;
        dirty.* = true;
    }
}

/// Index of the card whose CID equals `cid` (a slice into `blob`), or null.
fn trayIndexOfCid(cards: []const lens_socket.LensCard, blob: []const u8, cid: []const u8) ?u32 {
    for (cards, 0..) |c, i| {
        const s = blob[c.cid.off..][0..c.cid.len];
        if (std.mem.eql(u8, s, cid)) return @intCast(i);
    }
    return null;
}

/// Advance the socket's drag animation one frame: lift, the per-card reflow
/// (others slide to open a gap at the insertion slot), and the drop-settle.
/// Pure easing over the persistent SocketUi state; the widget draws the result.
fn advanceSocketDrag(ui: *lens_socket.SocketUi, tray: lens_socket.TrayView, geom: lens_socket.Geometry) void {
    const ease = 0.30; // per-frame approach factor (~150ms feel at 60fps)
    const n: i32 = @intCast(tray.cards.len);
    if (ui.drag_active) |d| {
        if (ui.settle_phase == 0) {
            // Active drag: lift the ghost; reflow neighbours toward the gap.
            ui.lift += (1.0 - ui.lift) * ease;
            // dropIndex early-returns null unless the socket is open; the page
            // sockets are rendered open but their stored `open` is false, so
            // force it for the insertion math (home is already open here).
            var oui = ui.*;
            oui.open = true;
            const ins: i32 = if (lens_socket.dropIndex(tray, oui, geom)) |x| @intCast(x) else @as(i32, @intCast(d));
            var a: i32 = 0;
            while (a < n and a < @as(i32, @intCast(ui.slide.len))) : (a += 1) {
                if (a == d) continue;
                // target slot of card a when d is pulled out and re-inserted at ins
                const r = if (a < @as(i32, @intCast(d))) a else a - 1;
                const target = if (r < ins) r else r + 1;
                const desired: f32 = @floatFromInt(target - a); // -1, 0, or +1
                ui.slide[@intCast(a)] += (desired - ui.slide[@intCast(a)]) * ease;
            }
        } else {
            // Settling: drop the lift, glide the reflow back to home, finish.
            ui.lift += (0.0 - ui.lift) * ease;
            for (&ui.slide) |*s| s.* += (0.0 - s.*) * ease;
            ui.settle_phase +|= 1;
            if (ui.settle_phase > lens_socket.settle_total_frames) {
                ui.drag_active = null;
                ui.settle_phase = 0;
                ui.lift = 0;
                ui.slide = [_]f32{0} ** lens_socket.max_lenses;
            }
        }
    } else {
        // Not dragging: relax any residual offsets back to rest.
        ui.lift += (0.0 - ui.lift) * ease;
        for (&ui.slide) |*s| s.* += (0.0 - s.*) * ease;
    }
}

/// Move the card at `from` to rank `to`, sliding the rest — the L.4 reorder.
/// The CID spans travel with the moved structs (the blob is unchanged), so a
/// caller can re-find the seated card by its CID offset afterward.
fn reorderTray(cards: []lens_socket.LensCard, from: u32, to: u32) void {
    if (from == to or from >= cards.len or to >= cards.len) return;
    const moved = cards[from];
    if (from < to) {
        var k = from;
        while (k < to) : (k += 1) cards[k] = cards[k + 1];
    } else {
        var k = from;
        while (k > to) : (k -= 1) cards[k] = cards[k - 1];
    }
    cards[to] = moved;
}

/// The background config-fetch for the marketplace "View details" page. Fetching
/// an algorithm's config is a network round-trip; done on the UI thread it FREEZES
/// the app for the fetch (the "extreme lag going to the info page"). So it runs on
/// this worker — a public, unauthenticated `getRecord`, so the worker never touches
/// the shared mutable session. The run loop polls `done`, then copies the
/// page_allocator result into the render `gpa` after join (no concurrency).
/// A7.2: cold struct (one live instance, holds a thread), size guard waived.
const InspectJob = struct {
    thread: ?std.Thread = null,
    done: std.atomic.Value(bool) = .init(false),
    active: bool = false, // a fetch is running (or finished, not yet consumed)
    ok: bool = false, // a config was produced (read after done-acquire / join)
    bytes: ?[]u8 = null, // page_allocator-owned serialized config on success
    src: ?[]u8 = null, // page_allocator-owned Zal source (null on old records)
    // Inputs, COPIED in so the worker never reads run-loop state (which the UI
    // thread mutates). io/env are shared but read-only / thread-safe.
    io: std.Io = undefined,
    env: ?*const std.process.Environ.Map = null,
    pds: [256]u8 = undefined,
    pds_len: usize = 0,
    repo: [128]u8 = undefined,
    repo_len: usize = 0,
    rkey: [128]u8 = undefined,
    rkey_len: usize = 0,
    /// The record CID this fetch is FOR — the prefetch drain's cache key (the
    /// user-tap path keys off rs.inspect_ref instead). Set by the kicker AFTER
    /// startInspect (the worker never reads it; only the post-join drain does).
    cid: [128]u8 = undefined,
    cid_len: usize = 0,
};

/// Worker body: a public getRecord + serialize, all off the `page_allocator` (a
/// private arena for the fetch, page_allocator for the surviving result), so the
/// render allocator is never touched. Publishes via `done` (release).
fn inspectWorker(job: *InspectJob) void {
    const a = std.heap.page_allocator;
    var arena_state = std.heap.ArenaAllocator.init(a);
    defer arena_state.deinit();
    const scratch = arena_state.allocator();
    // Narrate to logcat (a no-op off Android): the on-device failure was silent —
    // a black transparency page / a dead install with nothing in the log.
    mobile_host.logcat("inspect: fetch repo={s} rkey={s}", .{ job.repo[0..job.repo_len], job.rkey[0..job.rkey_len] });
    // The author's repo lives on THEIR PDS — resolve the DID document's service
    // endpoint and fetch THERE. The old code fetched from the SESSION PDS, which
    // only worked when author and viewer shared a PDS: a cross-PDS marketplace
    // author (the owner's own bsky-hosted test account) always got RecordNotFound
    // (found on-device 2026-07-09). Resolution failing (plc unreachable) falls
    // back to the session PDS, which preserves the old same-PDS behaviour.
    const author_pds: []const u8 = identity_shell.pdsForDid(scratch, job.io, job.env, .{}, job.repo[0..job.repo_len]) catch |err| blk: {
        mobile_host.logcat("inspect: DID resolve failed ({s}) — trying the session PDS", .{@errorName(err)});
        break :blk job.pds[0..job.pds_len];
    };
    mobile_host.logcat("inspect: author pds={s}", .{author_pds});
    const pub_algo = algorithm_shell.fetchPublic(scratch, job.io, job.env, author_pds, job.repo[0..job.repo_len], job.rkey[0..job.rkey_len]) catch |err| blk: {
        mobile_host.logcat("inspect: fetch ERROR {s}", .{@errorName(err)});
        break :blk null;
    };
    if (pub_algo == null) mobile_host.logcat("inspect: fetch returned nothing (refused or not found)", .{});
    if (pub_algo) |pa| {
        // Serialize into page_allocator (survives the arena deinit); the main
        // thread copies both into gpa and frees these after join.
        if (algorithm_core.serialize(a, pa.config)) |b| {
            job.bytes = b;
            job.src = if (pa.source.len > 0) a.dupe(u8, pa.source) catch null else null;
            job.ok = true;
        } else |_| job.ok = false;
    } else job.ok = false;
    job.done.store(true, .release);
}

/// Spawn a config fetch for (pds, repo, rkey). The strings are COPIED into the job
/// so the worker never reads run-loop state. A spawn failure completes the job as
/// a clean failure (done, ok=false) rather than hanging the loading state forever.
fn startInspect(job: *InspectJob, io: std.Io, env: ?*const std.process.Environ.Map, pds: []const u8, repo: []const u8, rkey: []const u8) void {
    const pn = @min(pds.len, job.pds.len);
    @memcpy(job.pds[0..pn], pds[0..pn]);
    job.pds_len = pn;
    const rn = @min(repo.len, job.repo.len);
    @memcpy(job.repo[0..rn], repo[0..rn]);
    job.repo_len = rn;
    const kn = @min(rkey.len, job.rkey.len);
    @memcpy(job.rkey[0..kn], rkey[0..kn]);
    job.rkey_len = kn;
    job.io = io;
    job.env = env;
    job.done.store(false, .monotonic);
    job.ok = false;
    job.bytes = null;
    job.active = true;
    job.thread = std.Thread.spawn(.{}, inspectWorker, .{job}) catch null;
    if (job.thread == null) job.done.store(true, .release); // spawn failed → done, ok=false
}

/// Join a finished fetch WITHOUT freeing its result — the caller is about to
/// CONSUME `bytes` (copy into gpa). Leaves `thread == null` so shutdown skips it.
fn joinInspect(job: *InspectJob) void {
    if (job.thread) |th| {
        th.join();
        job.thread = null;
    }
    job.active = false;
}

/// Shutdown cleanup (the defer): join any in-flight fetch and free a result the
/// loop never consumed (landed in the frame the app exits). A no-op if the loop
/// already took it (`thread == null`), so never a double-free.
fn stopInspect(job: *InspectJob) void {
    if (job.thread) |th| {
        th.join();
        job.thread = null;
        if (job.ok) {
            if (job.bytes) |b| std.heap.page_allocator.free(b);
            if (job.src) |b| std.heap.page_allocator.free(b);
        }
    }
    job.active = false;
}

/// A7.2: cold struct, waived — one per run(), the per-frame bundle of
/// shared pointers the paint path and input handler both read.
const Grid = struct {
    engine: *text_core.Engine,
    field: *field_core.Field,
    particles: *field_core.ParticleList,
    active: *effect_core.ActiveList,
    draw: *raster_core.DrawList,
    hr: *field_ui.HitList,
    hearts: *field_ui.HeartList,
    view: *field_ui.ViewState,
    spawn_buf: *std.ArrayList(field_core.SpawnEvent),
    /// Monotonic clock of the previous frame, for dt injection (B4 —
    /// the one time source). 0 until the first frame.
    last_nanos: *u64,
    /// User zoom factor for the glyph cell size (text scaling). 1.0 is
    /// the base size; '+'/'-' adjust it, clamped to [zoom_min, zoom_max].
    /// Shared so paintFrame and the pointer hit-test derive the SAME cell
    /// size from it.
    zoom: *f32,
    /// cut 5.6: premium feed pixel scroll, its content-height clamp bound,
    /// and the latest frame's button hit regions (pixel-space).
    scroll: *i32,
    content_h: *i32,
    regions: *feed_view.Regions,
    /// The active top-level Screen (index into feed_view.nav_labels): 0 = Home
    /// (the feed); the rail switches it on a click. Shared (a pointer to a run()
    /// local) so paint and the click handler agree on the same value.
    screen: *u8,
    /// THE LENS SOCKET (Home). The tray is the user's carried lens set
    /// (invariant 12); `socket_ui` is the transient open/swap state; the
    /// socket's tap targets land in `socket_hits` (its own space, tested
    /// before the feed regions). `accent` is the seated lens's palette
    /// color (§11.5), the app accent token this frame.
    socket_tray: ?lens_socket.TrayView = null,
    socket_ui: lens_socket.SocketUi = .{},
    socket_hits: *lens_socket.HitList,
    accent: u32 = feed_view.accent_house,
    /// The reply/zone sockets — only drawn on the loadout page (screen_loadout).
    reply_tray: lens_socket.TrayView = .{ .cards = &.{}, .text = "", .seated = 0 },
    reply_ui: lens_socket.SocketUi = .{},
    reply_hits: *lens_socket.HitList = undefined,
    zone_tray: lens_socket.TrayView = .{ .cards = &.{}, .text = "", .seated = 0 },
    zone_ui: lens_socket.SocketUi = .{},
    zone_hits: *lens_socket.HitList = undefined,
    /// The active Algorithms-page sub-tab (0 Loadout / 1 Marketplace / 2 Create).
    loadout_tab: u8 = 0,
    /// The Marketplace tab's render state (cards mapped from the AppView's rows +
    /// search/filter/hover). Cards empty on every other tab/screen; set per frame.
    market: feed_view.MarketView = .{},
    bench_pick: ?feed_view.BenchPickView = null,
    bench_drag: ?feed_view.BenchDragView = null,
    /// The cartridge DETAIL sheet (item 5): the seated lens card whose detail +
    /// colour overlay is open (null = closed), its text blob, and the hit list the
    /// overlay writes for the shell to dispatch. Set per frame from `gcart_detail`.
    cart_detail: ?lens_socket.LensCard = null,
    /// The double-back hint pill is armed this frame (folded into feed_sig).
    back_hint: bool = false,
    cart_detail_blob: []const u8 = "",
    detail_hits: ?*lens_socket.HitList = null,
    published: []const feed_view.PublishedRow = &.{},
    docs_kind: u8 = 0,
    detail: feed_view.AlgoDetailView = .{},
    /// The simple-Create flow's state (loadout tab 2). A value set per frame.
    create: feed_view.CreateView = .{ .step = .landing, .answers = .{}, .config = discover.DEFAULT_CONFIG, .name = "", .color = 0 },
    dev: feed_view.DevView = .{},
    /// The user's bench — library algorithms not in a socket (Loadout tab). A value
    /// set per frame (built from the library into the frame arena).
    bench: lens_socket.TrayView = .{ .cards = &.{}, .text = "", .seated = 0 },
    /// The transparency page's inspected algorithm (screen_transparency): its
    /// fetched config + name + ref (CID), rebuilt into a page each frame. Null
    /// config ⇒ not inspecting. Set per frame.
    /// The inspected algorithm's SERIALIZED bytes (stable; the render re-parses
    /// them into the frame arena — see the run-loop note). Empty = not inspecting.
    inspect_bytes: []const u8 = "",
    inspect_src: []const u8 = "", // Zal source when the record carries it; "" -> config bytes
    inspect_name: []const u8 = "",
    inspect_ref: []const u8 = "",
    /// On the transparency page: false = the summary, true = the byte-exact source.
    inspect_source: bool = false,
    /// True while the background config fetch is in flight (show a loading state).
    inspect_loading: bool = false,
    /// Out: the phone loadout's library band top (unequip drop test); maxInt
    /// in wide-shelf mode. Written by layoutLoadout each frame.
    loadout_lib_y: ?*i32 = null,
    /// Out: layoutLoadout writes each page socket's geometry here for the
    /// shell's drag math (feed / reply / zone).
    loadout_geoms: *[3]lens_socket.Geometry = undefined,
    /// The GPU render path, present only when `gpu.init` succeeded on this
    /// window (else null → the software path renders, the rule's fallback).
    /// A pointer into run()'s `gpu_state` local; one-frame contract like the
    /// rest of Grid.
    gpu: ?*GpuState,
    /// Count of staged-but-unrevealed new posts this frame — drives the Home
    /// "N new posts" pill. A value (set per frame), not a pointer.
    pending_new: usize = 0,
    /// The pointer's position in LOGICAL layout coords (the space regions live
    /// in), or <0 when off-window — drives the hover highlight. Set per frame.
    hover_x: i32 = -1,
    hover_y: i32 = -1,
    /// The open zone's display tag (e.g. "water") when on the zone page — the
    /// "#name" title in its header. "" on every other screen.
    zone_title: []const u8 = "",
    /// The zone CATALOG for the browse screen (`screen_zones_browse`): the known
    /// zones with post counts. Empty on every other screen.
    zones: feed_view.ZonesView = .{},
    /// The selected SECTION on the Settings screen (master–detail state). Index
    /// into `settings_view.sections`; ignored off `screen_settings`.
    settings_section: u8 = 0,
    /// Runtime on/off of every Settings toggle (bitset by global row index).
    settings_toggles: u64 = 0,
    /// The viewer's real identity for the Settings → Account info rows.
    settings_account: feed_view.SettingsAccount = .{},
    /// Packed selected-option index per CHOICE (3 bits each); drives the choice
    /// values + picker checkmark. `settings_picking` = the open choice's action
    /// (255 = none). `field_gain` is the brightness the Field-intensity choice
    /// resolves to (applied to the GPU field each frame).
    settings_choices: u64 = 0,
    settings_picking: u8 = 255,
    /// Zat Chat (U3, dev-gated): the DM store (null = gate off), the selected
    /// conversation, and the composer strip's live draft. The view-models are
    /// built per frame in paintFrame from these (queries over the one store).
    chat_store: ?*const chat_core.Store = null,
    chat_sel: ?chat_core.ConvIndex = null,
    /// The Zat4 keyboard (phone): wants-to-show + one-shot shift + page.
    kbd_visible: bool = false,
    kbd_shift: bool = false,
    kbd_page: u8 = 0,
    /// Double-tap shift lock: letters stay shifted, the key wears a bar.
    kbd_caps: bool = false,
    /// Press feedback: the pressed key's identity (its codepoint; 0xE001
    /// shift / 0xE002 backspace / 0xE003 page / '\r' enter) + the flash's
    /// current alpha, decayed per frame by the shell (kbdFlashAlpha). Both
    /// fold into feed_sig, so the fade rebuilds the verts while it runs.
    kbd_flash_key: u16 = 0,
    kbd_flash_a: u8 = 0,
    kbd_emoji_open: bool = false,
    /// Picker scroll offset, logical px (folded into feed_sig — a drag
    /// or fling must rebuild the verts every frame it moves).
    kbd_emoji_scroll: i32 = 0,
    /// The picker's persisted section (0 emoji / 1 GIFs) + the nav
    /// rollout's reveal — both fold into feed_sig.
    kbd_picker_mode: u8 = 0,
    kbd_nav_t: f32 = 0,
    /// The rollout column's rubber-band give, displayed logical px.
    kbd_nav_scroll: i32 = 0,
    /// The open long-press popup (empty = closed).
    kbd_popup: feed_view.KbdPopup = .{},
    /// The chat list-search state (phone): query + focus + caret blink.
    chat_q: []const u8 = "",
    chat_q_focus: bool = false,
    chat_q_caret: bool = false,

    chat_draft: []const u8 = "",
    /// Caret + selection + edit-bar state for the draft.
    chat_edit: feed_view.ChatEdit = .{},
    chat_input_focus: bool = false,
    chat_composing: bool = false,
    chat_compose: []const u8 = "",
    chat_compose_status: []const u8 = "",
    /// The typing-indicator SIGNAL (U6a): true = the counterparty is typing
    /// (an encrypted ping armed the deadline).
    chat_typing: bool = false,
    /// Last chat keystroke (monotonic ns) for the caret blink clock.
    chat_key_ns: u64 = 0,
    /// The pay sheet's frame state (M5 A4) — closed by default.
    chat_pay: feed_view.ChatPaySheet = .{},
    chat_recv: feed_view.ChatReceiveSheet = .{},
    /// What the OPEN conversation's peer knows about it (A1): confirmed once
    /// they ack our Welcome, `waiting` while it is still going out,
    /// `undelivered` once the retries are spent. The thread says so.
    chat_delivery: chat_core.Delivery = .confirmed,
    /// A3: chat is published from another device and this one refused to
    /// overwrite it. The Messages surface says so instead of showing a list
    /// that cannot work.
    chat_identity_elsewhere: bool = false,
    /// CHAT_MULTIDEVICE slice 2: the device gate, the wait, the approval card and
    /// the explainer — everything the multi-device surfaces render from.
    chat_devices: feed_view.ChatDevices = .{},
    /// A5: what the relay link is doing right now — the connection dot.
    chat_link: feed_view.ChatLink = .off,
    /// The front door (FRONT_DOOR_ROADMAP): the enrollment view (a pure snapshot
    /// of the flow state) + its hit list.
    enroll: enroll_view.EnrollView = .{},
    enroll_hits: ?*enroll_view.HitList = null,
    /// THE BOOT ENTRANCE (§5): whether it is playing over the door, and how many
    /// seconds in. The animation is a pure function of that one number.
    boot_on: bool = false,
    boot_t: f32 = 0,
    /// The payment ids the LUD-21 settlement watcher currently has an eye on.
    /// A network fact, folded onto the cards so they can say "watching for it".
    verify_ids: []const u64 = &.{},
    /// The Wallet page's Remove button is a two-tap: the first arms it, the
    /// second unpublishes. Removing your address makes you unpayable, and would
    /// strand anyone mid-send to you — it does not get a one-tap.
    wallet_remove_armed: bool = false,
    /// The reader's expanded posts (main-feed Read-more): CIDs stamped onto
    /// PostView.expanded by fromTimeline so a clamped body lays out in full.
    expanded: []const []const u8 = &.{},
    /// The VIEW index of the post whose Repost/Quote menu is open, or null.
    repost_menu: ?usize = null,
    field_gain: f32 = 0.9,
    /// Toy Box "Julia mode" active — the field renderer pinks its glyph ink.
    julia: bool = false,
    /// The signed-in handle for the phone drawer's profile card.
    you_handle: []const u8 = "",
    /// "Ripples on like" — the like fires the field ripple + red dye.
    ripples_on: bool = true,
    /// "Living glyph field" — the field renders (off ⇒ flat background).
    field_on: bool = true,
    /// Toy Box "CRT scanlines" — a scanline overlay over the whole frame.
    crt_on: bool = false,
    /// Toy Box "Show frame timing" — an fps/ms overlay.
    frametiming_on: bool = false,
    /// Toy Box "Pet" — the corner companion is active (forces a per-frame rebuild
    /// so it animates).
    pet: bool = false,
    /// Toy Box "XP skin" — the retro-desktop chrome overlay (title bar + taskbar).
    xp: bool = false,
    /// Appearance "Light mode" — re-themes the whole draw list light (rethemeLight)
    /// and flips the field to dark glyphs on a light canvas.
    light: bool = false,
    /// Local wall-clock hour (0–23) / minute (0–59) for the XP taskbar clock —
    /// read by the shell (B3), consumed as plain data by the pure renderer (B4).
    xp_hour: u8 = 0,
    xp_min: u8 = 0,
    /// Toy Box layout toy (`.depth` = the engagement loom); `.none` = natural.
    toys: feed_view.ToyView = .{},
};

// ===========================================================================
// The GPU render path (Phase 6.4): the living glyph field (a pure CPU wave
// simulation, core/glyph_field.zig) rendered grid-intensity + the premium feed,
// both on the GPU via shell/gpu.zig. Brought up additively when the window
// opens and `gpu.init` succeeds; the SOFTWARE path stays the automatic fallback
// (E2: degrade to a plainer window, never a dead one). The reference pipeline is
// src/gpu_preview.zig; this is that pipeline, driven by the live app's input.
// ===========================================================================

/// Field glyph cell — big enough to read the symbols, still many of them
/// (matches the preview). The field grid is win/cell in physical pixels.
const field_cell_w: u16 = 15;
const field_cell_h: u16 = 20;
/// The feed is authored for a fixed LOGICAL width and scaled to FILL the
/// window (DPI): scale = window_width / design_w. So the three-pane keeps its
/// cohesion at any window size and the type lands at design size, crisp.
const design_w: u32 = 1340;
/// The PHONE logical width (the locked mobile shape: portrait single column).
/// Small enough that feed_view's narrow path drops the rail + sidebar, and it
/// makes the scale ~2.5× on a 1080-wide phone — real thumb-sized type and
/// targets, glyphs still rasterized at physical resolution (crisp). The live
/// design width rides GpuState.design_w; this is what the mobile driver seeds.
pub const design_w_phone: u32 = 430;
/// Ambient-forcing knobs: a slow drifting swell so the still field breathes.
const amb_amp: f32 = 0.010;
const amb_scale: f32 = 0.060;
const amb_drift: f32 = 0.10;
/// 0xFF181812 — the same background the software path clears to.
// The app canvas: PURE BLACK. It is the living field's true backdrop (the field
// renders glyphs with per-glyph alpha, so the space between them is exactly this
// colour — black), and it sits well below the #1b1b1b cards so panels clearly
// float above it (the elevation model, now actually visible).
const gpu_clear_r: f32 = 0.0;
const gpu_clear_g: f32 = 0.0;
const gpu_clear_b: f32 = 0.0;
// Julia mode is a LIGHT theme: the field backdrop is a soft pink-white (not the
// dark room), so the field reads as pink symbols on white paper.
const julia_clear_r: f32 = @as(f32, 0xF7) / 255.0;
const julia_clear_g: f32 = @as(f32, 0xE9) / 255.0;
const julia_clear_b: f32 = @as(f32, 0xF1) / 255.0;
// XP skin: the classic teal desktop the retro grey window floats on.
const retro_clear_r: f32 = @as(f32, 0x0E) / 255.0;
const retro_clear_g: f32 = @as(f32, 0x7C) / 255.0;
const retro_clear_b: f32 = @as(f32, 0x74) / 255.0;
// Light mode: the soft warm-grey canvas the whole app + field ride on. Kept a
// touch grey (not near-white) so the pure-white cards lift off it (elevation).
const light_clear_r: f32 = @as(f32, 0xEC) / 255.0;
const light_clear_g: f32 = @as(f32, 0xEB) / 255.0;
const light_clear_b: f32 = @as(f32, 0xE4) / 255.0;

fn uiScaleFor(physical_w: u32, dw: u32) f32 {
    return @as(f32, @floatFromInt(physical_w)) / @as(f32, @floatFromInt(dw));
}
fn logicalHFor(physical_w: u32, physical_h: u32, dw: u32) u32 {
    return @max(1, @as(u32, @intFromFloat(@as(f32, @floatFromInt(physical_h)) / uiScaleFor(physical_w, dw))));
}

/// The GPU path's working set, one per run(). A7.2: cold struct, size guard
/// waived — stack-only, exactly one. The CPU sim (`field`) + shell-side
/// ambient `bias` + queued `splashes` feed the pure `glyph_field.step`; the
/// renderers (`grid`, `ramp`, `feed`) draw it. `t`/`mcx`/`mcy` are the animation
/// clock and the cursor-light cell (top-down; <0 = no cursor).
const GpuState = struct {
    g: gpu.Gpu,
    field: glyph_field.Field,
    grid: gpu.FieldGrid,
    ramp: gpu.FieldRenderer,
    feed: gpu.Feed,
    /// The PREVIOUS screen's feed verts, kept for the screen-switch CROSSFADE:
    /// The chat pane the fade last saw (0 list / 1 thread) — the in-screen swap.
    fade_chat_pane: u16 = 0,
    /// on a screen change `feed`↔`feed_prev` swap, then `feed` rebuilds with the
    /// new content while `feed_prev` holds the old; we draw old at (1-fade) + new
    /// at fade. The nav rail is in BOTH so it stays solid; only content dissolves.
    feed_prev: gpu.Feed,
    fade_t: f32 = 1, // 1 = settled (no fade); 0 just after a screen switch
    fade_screen: u8 = 0, // the screen `feed` currently holds (edge-detects switches)
    /// The nav rail as its OWN tile (decomposition) — a separate vert buffer so
    /// it can slide/compress independently of the content. Built each rebuild.
    rail: gpu.Feed,
    /// A small overlay vert buffer for the HOVER highlight (post wash + button
    /// highlight), rebuilt each frame and drawn between the field and the feed so
    /// the highlights sit BEHIND the post content. Separate from `feed` so a
    /// pointer move never rebuilds the cached feed verts.
    hover: gpu.Feed,
    /// Eased hover opacity (0→1) so the highlight FADES in/out instead of
    /// snapping — the "hover animation" feel.
    hover_alpha: f32 = 0,
    /// Read-only text selection of the ROOTED post's body (thread screen). `sel`
    /// is its own overlay vert buffer (the highlight rects, drawn BEHIND the feed
    /// text like the hover wash); `sel_glyphs` is the rooted body's glyph geometry
    /// captured on each feed rebuild (feed_view.SelGlyphs — the one selectable
    /// post, ZONES inv. 4). `sel_anchor`/`sel_focus` are caret indices into it
    /// (0..len), equal = no selection; `sel_dragging` while the button is held.
    sel: gpu.Feed,
    sel_glyphs: feed_view.SelGlyphs = .empty,
    sel_anchor: u32 = 0,
    sel_focus: u32 = 0,
    sel_dragging: bool = false,
    /// The right-click context menu (Copy / Select all) over the rooted post.
    /// `menu` is its own overlay vert buffer (drawn last, on top of everything);
    /// `menu_x`/`menu_y` are its top-left in logical pixels. Closed by an item
    /// click, a click outside, Escape, or a scroll.
    menu: gpu.Feed,
    menu_open: bool = false,
    menu_x: i32 = 0,
    menu_y: i32 = 0,
    /// A like's red dye REVEALED gradually (synced to the spark animation) rather
    /// than blipping in: while frames>0, advanceField injects a fraction of the
    /// dye ring at (cx,cy) each step. Defaults so they ride the struct literal.
    dye_reveal_cx: u32 = 0,
    dye_reveal_cy: u32 = 0,
    dye_reveal_frames: u32 = 0,
    /// The animated like-heart pass (SDF fill + pop + star burst), drawn over
    /// the feed for each active like effect this frame.
    heart: gpu.HeartRenderer,
    /// Toy Box "CRT scanlines" — a full-screen post-process drawn last.
    scanlines: gpu.Scanlines,
    /// "Show frame timing" — smoothed frame period (ms) + the last frame's clock,
    /// for the fps/ms overlay. 0 until the first frame pair.
    frame_ms: f32 = 0,
    last_frame_nanos: u64 = 0,
    /// Toy Box: Gravity SHATTER — the retained physics state (struct-of-arrays, A3)
    /// for the Settings-page collapse: one body PER DRAW ITEM (each word/glyph, icon
    /// stroke, toggle, panel is its own falling piece). Position + velocity + the
    /// seed home anchor + size. Shell-owned (Rule 4); pure `shatter.step` reads it.
    /// `shatter_group`/`shatter_leader` bind the Gravity row rigid (label + switch
    /// fall together — find that block and tap it to stop).
    shatter_x: std.ArrayListUnmanaged(f32) = .empty,
    shatter_y: std.ArrayListUnmanaged(f32) = .empty,
    shatter_vx: std.ArrayListUnmanaged(f32) = .empty,
    shatter_vy: std.ArrayListUnmanaged(f32) = .empty,
    shatter_hx: std.ArrayListUnmanaged(f32) = .empty,
    shatter_hy: std.ArrayListUnmanaged(f32) = .empty,
    shatter_bw: std.ArrayListUnmanaged(f32) = .empty,
    shatter_bh: std.ArrayListUnmanaged(f32) = .empty,
    shatter_gid: std.ArrayListUnmanaged(u32) = .empty, // group id (words, gravity); 0 = alone
    shatter_leader_of: std.ArrayListUnmanaged(u32) = .empty, // each item's group leader index
    shatter_group: std.ArrayListUnmanaged(bool) = .empty, // true = a Gravity-toggle item (tap to stop)
    shatter_active: bool = false,
    shatter_n: usize = 0,
    shatter_held: ?usize = null,
    shatter_grab_dx: f32 = 0,
    shatter_grab_dy: f32 = 0,
    shatter_down_x: i32 = 0, // pointer-down position, to tell a tap from a drag
    shatter_down_y: i32 = 0,
    /// Toy Box: Pet — the companion's state + the activity accumulated since the
    /// last step (reset each frame), plus its on-screen box for tap hit-testing.
    pet: pet_core.State = .{},
    pet_scroll_ms: u16 = 0,
    pet_petted: bool = false,
    pet_tossed: bool = false,
    pet_interacted: bool = false,
    // The pet is a little free physics body: position/velocity/roll, whether it's
    // held, and its on-screen box (scaled) for the tap/grab hit-test.
    pet_px: f32 = 0,
    pet_py: f32 = 0,
    pet_vx: f32 = 0,
    pet_vy: f32 = 0,
    pet_roll: f32 = 0,
    pet_grabbed: bool = false,
    pet_grab_dx: f32 = 0,
    pet_grab_dy: f32 = 0,
    pet_down_x: i32 = 0,
    pet_down_y: i32 = 0,
    pet_seeded: bool = false,
    pet_x: i32 = 0,
    pet_y: i32 = 0,
    pet_bw: i32 = 0,
    pet_bh: i32 = 0,
    // Feeding: a profile picture dragged out of the feed toward the pet.
    avatar_drag: bool = false,
    avatar_post: usize = 0,
    avatar_x: f32 = 0,
    avatar_y: f32 = 0,
    pet_happy: u16 = 0, // frames of a guaranteed HAPPY reaction after a pet/feed
    /// The SDF-icon pass (the heart's technique generalised) — crisp engagement /
    /// nav icons, one draw call each, replacing the aliased line-art.
    icon: gpu.IconRenderer,
    bias: []f32,
    splashes: std.ArrayList(glyph_field.Splash),
    cols: u32,
    rows: u32,
    t: f32,
    mcx: f32,
    mcy: f32,
    /// Toy Box "Liquid": a scroll-velocity-kicked spring (px). Stepped each frame,
    /// settles to 0 when the reader stops scrolling; handed to the pure renderer as
    /// the slosh amplitude. `flow_scroll_prev` remembers last frame's scroll offset.
    flow: f32 = 0,
    flow_v: f32 = 0,
    flow_scroll_prev: f32 = 0,
    /// Toy Box "Julia mode" toggle-ON spark: a one-shot burst of SDF hearts that
    /// fly out from the switch, drawn ON TOP (so it isn't hidden behind a panel
    /// like the field ripple is). `t` runs 1→0 over the burst; x,y = origin in
    /// framebuffer px.
    julia_burst_t: f32 = 0,
    julia_burst_x: f32 = 0,
    julia_burst_y: f32 = 0,
    /// Last frame's DPI scale (physical_w / design_w) — the feed lays out in
    /// LOGICAL pixels, so the input handlers read this to map a click/region
    /// back to physical pixels and thence to a field cell. Refreshed each
    /// frame by paintFrameGpu.
    scale: f32,
    /// The LOGICAL layout width this surface designs to: `design_w` (1340,
    /// the desktop three-pane) or `design_w_phone` (430 — the single-column
    /// phone shape; feed_view goes narrow + phone chrome below its
    /// thresholds). Fixed at initGpuState; `scale` and every layout call
    /// derive from it, so shape is one number the driver chooses.
    design_w: u32,
    /// Safe-area insets in LOGICAL (design) px — set by mobileSetInsets from the
    /// OS physical insets / ui scale. Reserve status bar (top) + home pill
    /// (bottom); zero on desktop. Folded into feed_sig so a change rebuilds.
    inset_top_l: i32 = 0,
    /// The soft keyboard's LIVE bottom inset (logical px; 0 = hidden) — polled
    /// per lap by the activity while the IME is up. The chat composer rides
    /// above it; folded into feed_sig so the lift tracks the keyboard.
    ime_bottom_l: i32 = 0,
    inset_bottom_l: i32 = 0,
    inset_left_l: i32 = 0,
    inset_right_l: i32 = 0,
    /// Dirty signature of the last-built feed (scroll + window size + each
    /// post's identity/counts/flags). The field animates every frame, but the
    /// feed — transform + per-post text measurement + vertex build — is rebuilt
    /// ONLY when this changes, so a large feed does not pay that cost 60×/sec.
    feed_sig: u64,
    /// Content-only signature (excludes scroll + window height): when it
    /// changes, the per-post `heights` cache is reset. So a pure SCROLL (which
    /// changes feed_sig but not this) keeps the cache and skips re-measuring
    /// every post — the scroll-lag fix.
    feed_content_sig: u64,
    /// Per-post measured-height cache handed to feed_view.layout. Scroll-
    /// invariant; sized to the post count, reset to -1 on content/width change.
    heights: []i32,
    /// Monotonic clock of the last simulation STEP. The field advances on a
    /// fixed wall-clock timestep (≈60 Hz) so it evolves at a constant real-time
    /// rate no matter how fast the loop spins — without this, a fast input
    /// stream (mouse motion floods events → the loop runs far above 60 fps)
    /// stepped the sim every lap and the WHOLE field's motion sped up while the
    /// pointer moved. 0 until the first frame.
    last_step_nanos: u64,
    /// Set when a thread is opened / re-focused: paintFrameGpu scrolls the
    /// focused post to the top (ancestors remain above, scrollable up) once the
    /// per-post heights are valid, then clears it. (Thread view only.)
    scroll_to_focus: bool = false,
    /// Sticky CHAIN header (thread "chain"): the extent + identity are captured on
    /// the feed rebuild (content-space offsets, scroll-independent); the per-frame
    /// overlay uses them + the live scroll to pin / catch-up / push-out. Identity
    /// is OWNED (copied) so it survives across non-rebuild frames.
    chain_present: bool = false,
    chain_top_off: i32 = 0,
    chain_bottom_off: i32 = 0,
    chain_pin_y: i32 = 0,
    chain_tint: u32 = 0,
    chain_initial: u21 = ' ',
    chain_name: [64]u8 = undefined,
    chain_name_len: u8 = 0,
    chain_handle: [80]u8 = undefined,
    chain_handle_len: u8 = 0,
    chain_catchup_t: f32 = 0, // 0 = above/hidden, 1 = settled at the pin
    chain_was_pinned: bool = false, // edge-detect the scroll-down pin to fire the catch-up
    /// Tiling foundation (S.2): the pane geometry as ANIMATED state. The live
    /// sub-pixel pane boundaries (`geom_*`) spring toward the current screen's
    /// target (feed_view.paneGeomFor), so switching screens GLIDES the panes
    /// instead of snapping. `gv_*` are the velocities; seeded on the first frame.
    /// Geometry is a SOLVED partition each frame — a blend of two valid layouts
    /// is itself valid, so the morph never overlaps.
    geom_init: bool = false,
    geom_rail_x: f32 = 0,
    geom_col_x: f32 = 0,
    geom_col_w: f32 = 0,
    geom_lx: f32 = 0,
    geom_cw: f32 = 0,
    geom_side_x: f32 = 0,
    gv_rail_x: f32 = 0,
    gv_col_x: f32 = 0,
    gv_col_w: f32 = 0,
    gv_lx: f32 = 0,
    gv_cw: f32 = 0,
    gv_side_x: f32 = 0,
    /// Content-driven SEARCH tile (sidebar): `search_open` springs 0..1 toward
    /// `search_want`; while it moves it pushes the trending/follow tiles down
    /// (a cheap reposition — no relayout). Toggled by '/'.
    search_open: f32 = 0,
    search_v: f32 = 0,
    search_want: bool = false,
    /// ZONES test: the nav rail relocates to the right on the Zones tab. Springs
    /// 0 (rail at home/left) → 1 (rail slid to the right). A revertable demo.
    zones_t: f32 = 0,
    /// The PHONE nav drawer (Bluesky-pattern): 0 closed → 1 open. `want` is
    /// flipped by the swipe gesture / nav taps; the spring animates t.
    drawer_t: f32 = 0,
    drawer_v: f32 = 0,
    drawer_want: bool = false,
    /// The finger owns drawer_t right now (tethered drag) — the spring
    /// stands down and the chrome rebuilds every frame.
    drawer_drag: bool = false,
    zones_v: f32 = 0,
    /// Hover-expand of the condensed right rail: 0 = icons-only strip, 1 = full
    /// labelled rail. Springs toward 1 while the cursor is over the right strip.
    rail_hover_t: f32 = 0,
    rail_hover_v: f32 = 0,
    /// The LIVE content column (logical px) — set each rebuild from the animated
    /// geometry. The field's panel-softening ("distortion") reads THIS so it
    /// tracks the content as it widens/shifts, instead of the static metricsPage.
    content_x: i32 = 0,
    content_w: i32 = 0,
    /// ALGORITHMS test: the LEFT rail condenses in place (stays left) and the
    /// content expands. `algo_t` springs on the loadout screen; `left_hover_t`
    /// springs while the cursor is over the (left) rail, re-expanding it.
    algo_t: f32 = 0,
    algo_v: f32 = 0,
    left_hover_t: f32 = 0,
    left_hover_v: f32 = 0,
    /// Zat Chat motion (U6b): PER-BUBBLE springs. Each in-flight bubble owns a
    /// scale + offset spring in `chat_world` (core/spring.zig), bound by its
    /// message key in `chat_anims` — so several bubbles animate at once with
    /// independent momentum (the interruptibility one shared scalar could not
    /// give). `chat_reflow` is the thread's settle after an append; the typing
    /// indicator keeps its own small spring. ONE trigger site — the observed
    /// state transition (the open conversation's newest message advanced).
    chat_world: spring.World = .empty,
    chat_anims: std.ArrayListUnmanaged(ChatAnim) = .empty,
    chat_reflow: ?spring.Handle = null,
    chat_typing_t: f32 = 0,
    chat_typing_v: f32 = 0,
    chat_typing_phase: f32 = 0,
    /// Watermark: the open conversation and its newest MsgIndex, so only a genuine
    /// new arrival/send animates (switching convs or restoring history must not).
    chat_seen_conv: u32 = 0,
    chat_seen_key: u32 = 0,
    /// False until a conversation has been observed once — a first paint (history
    /// restore, pre-visit arrivals) must NOT animate.
    chat_seen_valid: bool = false,
    /// The chat springs' frame-clock watermark (monotonic ns): motion advances by
    /// MEASURED time, not a fixed per-frame tick.
    chat_clock_ns: u64 = 0,
    /// The money modal's entrance (0 = out, 1 = seated) and its velocity. The
    /// scrim fades and the panel rises on this one scalar. It MUST also be folded
    /// into `chat_sig` (below) or the GPU path caches the first frame of the
    /// animation and the modal freezes half-risen — the standing rebuild law.
    sheet_t: f32 = 0,
    sheet_v: f32 = 0,
};

/// One in-flight bubble's spring binding (U6b). A7.2: cold-ish — a handful live
/// at once, held in a small list, never scanned in a hot inner loop; guard waived.
const ChatAnim = struct {
    /// The bubble's stable message key (`@intFromEnum(MsgIndex)`), matched
    /// against the thread's order to place the transform on the right row.
    key: u32,
    scale: spring.Handle, // grows the bubble into place (0.86/0.92 → 1.0, bouncy)
    off: spring.Handle, // rises it from below the seat (px → 0)
    /// Spawn time (monotonic ns) — drives the short, monotonic opacity ramp,
    /// which is deliberately NOT a spring (an overshooting alpha flickers).
    born_ns: u64,
};

/// Spring one geometry boundary toward its target (S.2). Stiff + just over
/// critical damping → fast settle, no overshoot (overshoot would let a pane
/// boundary cross past its target mid-morph).
fn springGeom(cur: *f32, vel: *f32, target: f32, dt: f32) void {
    const k: f32 = 150.0;
    const c: f32 = 25.0;
    vel.* += (-k * (cur.* - target) - c * vel.*) * dt;
    cur.* += vel.* * dt;
}

/// The phone drawer's spring: much stiffer than the pane morphs — a nav
/// surface should ARRIVE (~0.2 s, critically damped, no overshoot). Tuned
/// from the owner's first drawer feel pass ("quicker, snappier").
fn springDrawer(cur: *f32, vel: *f32, target: f32, dt: f32) void {
    const k: f32 = 600.0;
    const c: f32 = 49.0;
    vel.* += (-k * (cur.* - target) - c * vel.*) * dt;
    cur.* += vel.* * dt;
}

/// The message-motion spring (U6a): stiffness 230, damping 24, mass 1 —
/// damping ratio ≈ 0.79, one gentle ~2% overshoot that settles (the
/// native-messenger response: springs, not easing curves). Geometry
/// morphs keep springGeom (no overshoot — a pane boundary must not cross
/// its target); a bubble should breathe past its seat and settle.
fn springPop(cur: *f32, vel: *f32, target: f32, dt: f32) void {
    const k: f32 = 230.0;
    const c: f32 = 24.0;
    vel.* += (-k * (cur.* - target) - c * vel.*) * dt;
    cur.* += vel.* * dt;
}

/// Step the WHOLE geometry toward the screen's target — content column AND
/// glass move together (no "finished content waiting for the glass"). A convex
/// blend of two valid layouts is itself valid, so it never overlaps. The text
/// width (cw) is folded into the height-cache key by the caller, so a morph that
/// changes cw re-measures — but those are the wide NON-post pages (nothing heavy
/// to measure), while the post pages share one reading width (cache stays warm).
fn stepGeomAnim(gs: *GpuState, target: feed_view.PaneGeom, dt: f32) bool {
    const tr: f32 = @floatFromInt(target.rail_x);
    const tcx: f32 = @floatFromInt(target.col_x);
    const tcw: f32 = @floatFromInt(target.col_w);
    const tlx: f32 = @floatFromInt(target.lx);
    const tcwd: f32 = @floatFromInt(target.cw);
    const tsx: f32 = @floatFromInt(target.side_x);
    if (!gs.geom_init) {
        gs.geom_init = true;
        gs.geom_rail_x = tr;
        gs.geom_col_x = tcx;
        gs.geom_col_w = tcw;
        gs.geom_lx = tlx;
        gs.geom_cw = tcwd;
        gs.geom_side_x = tsx;
        return false;
    }
    springGeom(&gs.geom_rail_x, &gs.gv_rail_x, tr, dt);
    springGeom(&gs.geom_col_x, &gs.gv_col_x, tcx, dt);
    springGeom(&gs.geom_col_w, &gs.gv_col_w, tcw, dt);
    springGeom(&gs.geom_lx, &gs.gv_lx, tlx, dt);
    springGeom(&gs.geom_cw, &gs.gv_cw, tcwd, dt);
    springGeom(&gs.geom_side_x, &gs.gv_side_x, tsx, dt);
    const far = @abs(gs.geom_rail_x - tr) + @abs(gs.geom_col_x - tcx) + @abs(gs.geom_col_w - tcw) +
        @abs(gs.geom_lx - tlx) + @abs(gs.geom_cw - tcwd) + @abs(gs.geom_side_x - tsx);
    return far > 0.75;
}

/// The live (animated) geometry as a PaneGeom to hand `layout()`. The glass
/// width is clamped to never be narrower than the text column, so the text
/// never overflows the panel mid-widen. `wide` snaps to the target's value.
fn liveGeom(gs: *const GpuState, target: feed_view.PaneGeom) feed_view.PaneGeom {
    const col_w: i32 = @intFromFloat(@round(@max(gs.geom_col_w, gs.geom_cw)));
    return .{
        .rail_x = @intFromFloat(@round(gs.geom_rail_x)),
        .col_x = @intFromFloat(@round(gs.geom_col_x)),
        .col_w = col_w,
        .lx = @intFromFloat(@round(gs.geom_lx)),
        .cw = @intFromFloat(@round(gs.geom_cw)),
        .side_x = @intFromFloat(@round(gs.geom_side_x)),
        .wide = target.wide,
    };
}

/// Bring up the GPU FEED path on an already-current GL context (`g` — the
/// caller made it against its own surface: the X11 window here, the seam's
/// ANativeWindow on mobile; this fn OWNS it from the first line, failure
/// included). Any failure (shader/pack error, OOM) propagates so the caller
/// falls back to software (E2). Each acquired resource has an errdefer so a
/// mid-init failure frees cleanly (C5).
fn initGpuState(gpa: Allocator, engine: *text_core.Engine, g_in: gpu.Gpu, w: u32, h: u32, logical_w: u32) !GpuState {
    var g = g_in;
    errdefer gpu.deinit(&g);
    gpu.setViewport(@intCast(w), @intCast(h));

    var feed = try gpu.initFeed(gpa);
    errdefer gpu.feedDeinit(&feed, gpa);
    var feed_prev = try gpu.initFeed(gpa);
    errdefer gpu.feedDeinit(&feed_prev, gpa);
    var rail = try gpu.initFeed(gpa);
    errdefer gpu.feedDeinit(&rail, gpa);
    var hover = try gpu.initFeed(gpa);
    errdefer gpu.feedDeinit(&hover, gpa);
    var sel = try gpu.initFeed(gpa);
    errdefer gpu.feedDeinit(&sel, gpa);
    var menu = try gpu.initFeed(gpa);
    errdefer gpu.feedDeinit(&menu, gpa);
    const ramp = try gpu.initFieldRenderer(gpa, engine, field_cell_w, field_cell_h);
    const grid = try gpu.initFieldGrid();
    const heart = try gpu.initHeartRenderer();
    const scanlines = try gpu.initScanlines();
    const icon_r = try gpu.initIconRenderer();

    const fgrid = gpuFieldGrid(w, h);
    const cols = fgrid.cols;
    const rows = fgrid.rows;
    var field: glyph_field.Field = undefined;
    try glyph_field.init(gpa, &field, cols, rows);
    errdefer glyph_field.deinit(gpa, &field);
    const bias = try gpa.alloc(f32, cols * rows);
    errdefer gpa.free(bias);

    return .{
        .g = g,
        .field = field,
        .grid = grid,
        .ramp = ramp,
        .feed = feed,
        .feed_prev = feed_prev,
        .rail = rail,
        .hover = hover,
        .sel = sel,
        .menu = menu,
        .heart = heart,
        .scanlines = scanlines,
        .icon = icon_r,
        .bias = bias,
        .splashes = .empty,
        .cols = cols,
        .rows = rows,
        .t = 0,
        .mcx = -1,
        .mcy = -1,
        .scale = uiScaleFor(w, logical_w),
        .design_w = logical_w,
        .feed_sig = 0,
        .feed_content_sig = 0,
        .heights = &.{},
        .last_step_nanos = 0,
    };
}

/// A cheap dirty signature of the rendered feed: the scroll offset, the window
/// size, and each post's identity (cid) + the fields that affect its render
/// (engagement counts + viewer flags). Hashing the whole feed is far cheaper
/// (a few µs) than the layout it gates (per-post text measurement). Relative
/// age is intentionally excluded — it would force a rebuild every second; ages
/// refresh on the next scroll / new post / engagement instead.
fn feedSignature(items: []const feed_core.TimelineItem, scroll: i32, w: u32, h: u32) u64 {
    var hh = std.hash.Wyhash.init(0x7A74_F1E1);
    hh.update(std.mem.asBytes(&scroll));
    hh.update(std.mem.asBytes(&w));
    hh.update(std.mem.asBytes(&h));
    const n: u64 = items.len;
    hh.update(std.mem.asBytes(&n));
    for (items) |it| {
        hh.update(it.cid);
        hh.update(std.mem.asBytes(&it.like_count));
        hh.update(std.mem.asBytes(&it.repost_count));
        hh.update(std.mem.asBytes(&it.reply_count));
        hh.update(std.mem.asBytes(&it.item_flags));
        // Thread view-state: focus moving / collapse / stitch all change the
        // render, so fold them in (else tapping a different post in the same
        // thread wouldn't rebuild the cached feed verts).
        hh.update(std.mem.asBytes(&it.is_focus));
        hh.update(std.mem.asBytes(&it.depth));
        hh.update(std.mem.asBytes(&it.stitched));
        hh.update(std.mem.asBytes(&it.collapsed));
    }
    return hh.final();
}

fn deinitGpuState(gpa: Allocator, gs: *GpuState) void {
    gs.splashes.deinit(gpa);
    if (gs.heights.len > 0) gpa.free(gs.heights);
    gpa.free(gs.bias);
    glyph_field.deinit(gpa, &gs.field);
    gpu.feedDeinit(&gs.feed, gpa);
    gpu.feedDeinit(&gs.feed_prev, gpa);
    gpu.feedDeinit(&gs.rail, gpa);
    gpu.feedDeinit(&gs.hover, gpa);
    gpu.feedDeinit(&gs.sel, gpa);
    gpu.feedDeinit(&gs.menu, gpa);
    gs.sel_glyphs.deinit(gpa);
    gs.chat_anims.deinit(gpa);
    gs.chat_world.deinit(gpa);
    gs.shatter_x.deinit(gpa);
    gs.shatter_y.deinit(gpa);
    gs.shatter_vx.deinit(gpa);
    gs.shatter_vy.deinit(gpa);
    gs.shatter_hx.deinit(gpa);
    gs.shatter_hy.deinit(gpa);
    gs.shatter_bw.deinit(gpa);
    gs.shatter_bh.deinit(gpa);
    gs.shatter_gid.deinit(gpa);
    gs.shatter_leader_of.deinit(gpa);
    gs.shatter_group.deinit(gpa);
    gpu.deinit(&gs.g);
}

// ── Zat Chat per-bubble motion (U6b) ─────────────────────────────────────────
// The presets are the roadmap's tuning seeds (duration/bounce, §8 step 7). An
// OWN send pops a touch harder than a counterparty ARRIVAL (0.28 vs 0.20 bounce)
// and starts smaller/lower — it springs up out of the composer; an arrival
// settles more gently. Tune these live (this is the ONE place hand-taste belongs).
const chat_scale_mine = spring.springConstants(0.28, 0.35);
const chat_scale_them = spring.springConstants(0.20, 0.35);
const chat_off_c = spring.springConstants(0.15, 0.40);
const chat_reflow_c = spring.springConstants(0.0, 0.40); // critical: a reflow must not overshoot
const chat_fade_ns: f32 = 0.18 * 1_000_000_000.0; // opacity ramp duration

/// The money modal's entrance. A little bounce (it should feel like the sheet
/// SEATS, not merely arrives) but brisk — this sits in front of a task, and a
/// slow modal is a modal you resent by the third time you open it.
const sheet_spring_c = spring.springConstants(0.18, 0.30);

/// Spawn a bubble's scale + offset springs and bind them to its message key.
/// Idempotent per key; silently no-ops on OOM (a missed animation is cosmetic,
/// never a crash — E4).
fn spawnBubbleAnim(gpa: Allocator, gs: *GpuState, key: u32, mine: bool, born_ns: u64) void {
    for (gs.chat_anims.items) |a| if (a.key == key) return;
    const c_scale = if (mine) chat_scale_mine else chat_scale_them;
    const start_scale: f32 = if (mine) 0.86 else 0.92;
    const start_rise: f32 = if (mine) 26.0 else 20.0;
    const sh = gs.chat_world.spawn(gpa, start_scale, 1.0, c_scale) catch return;
    const oh = gs.chat_world.spawn(gpa, start_rise, 0.0, chat_off_c) catch {
        gs.chat_world.release(sh);
        return;
    };
    gs.chat_anims.append(gpa, .{ .key = key, .scale = sh, .off = oh, .born_ns = born_ns }) catch {
        gs.chat_world.release(sh);
        gs.chat_world.release(oh);
    };
}

/// Restart the thread-reflow spring (0 → 1) on an append: the older content just
/// jumped up by the new row's height and now slides back to rest.
fn startChatReflow(gpa: Allocator, gs: *GpuState) void {
    if (gs.chat_reflow) |h| gs.chat_world.release(h);
    gs.chat_reflow = gs.chat_world.spawn(gpa, 0.0, 1.0, chat_reflow_c) catch null;
}

/// Release the springs of any bubble (and the reflow) that has reached rest, so
/// the world's active set shrinks back toward empty.
fn reapChatAnims(gs: *GpuState) void {
    var i: usize = 0;
    while (i < gs.chat_anims.items.len) {
        const a = gs.chat_anims.items[i];
        if (!gs.chat_world.isActive(a.scale) and !gs.chat_world.isActive(a.off)) {
            gs.chat_world.release(a.scale);
            gs.chat_world.release(a.off);
            _ = gs.chat_anims.swapRemove(i);
        } else i += 1;
    }
    if (gs.chat_reflow) |h| if (!gs.chat_world.isActive(h)) {
        gs.chat_world.release(h);
        gs.chat_reflow = null;
    };
}

/// Refit the CPU field grid + ambient-bias buffer to a new window size. New
/// buffers allocated BEFORE the old are freed, so a failed alloc leaves the
/// existing state (and its deinit) valid (C5). The dye/height reset on resize
/// is accepted for v1 (the field re-seeds calm); reproject later if wanted.
fn resizeGpuField(gpa: Allocator, gs: *GpuState, w: u32, h: u32) !void {
    const fgrid = gpuFieldGrid(w, h);
    const cols = fgrid.cols;
    const rows = fgrid.rows;
    var newfield: glyph_field.Field = undefined;
    try glyph_field.init(gpa, &newfield, cols, rows);
    errdefer glyph_field.deinit(gpa, &newfield);
    const new_bias = try gpa.alloc(f32, cols * rows);
    glyph_field.deinit(gpa, &gs.field);
    gs.field = newfield;
    gpa.free(gs.bias);
    gs.bias = new_bias;
    gs.cols = cols;
    gs.rows = rows;
}

/// Append the LIKE burst — a splash RECIPE: a strong central kick plus a ring
/// of six satellites, all staining the medium red — at field cell (gx,gy).
/// This is the heart-burst as energy injected into the field (design §1). A
/// queue-full append is dropped silently (E4: a missed effect must never break
/// the action). Mirrors the preview's recipe + the spec's tuning.
/// Read a functional settings TOGGLE's runtime bit by its action — maps the
/// action → its global row index (`settings_view.rowOf`) → the `toggle_bits`
/// bit. False if the action isn't a toggle in the table. The generalized form
/// of the Julia-mode wiring: each functional toggle reads its bit this way.
fn toggleOn(bits: u64, action: u8) bool {
    return if (settings_view.rowOf(action)) |i| (bits >> i) & 1 != 0 else false;
}

/// Pack the per-choice selected indices into the 3-bits-each word `layout` reads.
fn packChoices(sel: []const u8) u64 {
    var p: u64 = 0;
    for (sel, 0..) |s, i| p |= @as(u64, s & 7) << @intCast(i * 3);
    return p;
}

/// The live selected option index for a choice action (0 if it isn't a choice).
fn choiceSel(sel: []const u8, action: u8) u8 {
    return if (settings_view.choiceIndex(action)) |i| sel[i] else 0;
}

/// "Accent" choice → an accent override, or null for "Auto" (follow the lens).
/// Option order matches settings_view.choices: Auto, Amber, Blue, Green, Violet,
/// Rose, Teal (the lens-socket palette colours).
fn accentChoiceColor(opt: u8) ?u32 {
    return switch (opt) {
        1 => feed_view.accent_house, // Amber (house)
        2 => 0xFF4A9EFF, // Blue
        3 => 0xFF3FC97E, // Green
        4 => 0xFF9B7BFF, // Violet
        5 => 0xFFFF5C8A, // Rose
        6 => 0xFF33C2C2, // Teal
        else => null, // 0 = Auto
    };
}

/// "Field intensity" choice → the field's uGain. Subtle / Normal / Vivid.
fn fieldGainFor(opt: u8) f32 {
    return switch (opt) {
        0 => 0.5, // Subtle
        2 => 1.5, // Vivid
        else => 0.9, // Normal (the default)
    };
}

fn pushLikeSplash(gpa: Allocator, gs: *GpuState, gx: u32, gy: u32, with_dye: bool) void {
    if (gs.cols == 0 or gs.rows == 0) return;
    const sx = @min(gx, gs.cols - 1);
    const sy = @min(gy, gs.rows - 1);
    // A strong central splash THROWS the wave; two concentric rings carry it
    // OUTWARD, so a like visibly shoots out and ripples. The WAVE fires once here
    // (dye = 0); the RED is faded in separately over the next ~18 steps (armed
    // below), synced to the spark — so the colour grows in instead of blipping.
    gs.splashes.append(gpa, .{ .x = sx, .y = sy, .radius = 6, .amp = 3.6, .dye = 0 }) catch {};
    const ring_dist = [_]f32{ 5.0, 9.0 };
    const ring_amp = [_]f32{ 1.8, 1.1 };
    for (ring_dist, ring_amp) |dist, amp| {
        var k: u32 = 0;
        while (k < 8) : (k += 1) {
            const ang = @as(f32, @floatFromInt(k)) * (6.2831853 / 8.0);
            const ox: i32 = @intFromFloat(@cos(ang) * dist);
            const oy: i32 = @intFromFloat(@sin(ang) * dist);
            const rx = std.math.clamp(@as(i32, @intCast(sx)) + ox, 0, @as(i32, @intCast(gs.cols - 1)));
            const ry = std.math.clamp(@as(i32, @intCast(sy)) + oy, 0, @as(i32, @intCast(gs.rows - 1)));
            gs.splashes.append(gpa, .{ .x = @intCast(rx), .y = @intCast(ry), .radius = 3, .amp = amp, .dye = 0 }) catch {};
        }
    }
    // Arm the gradual dye reveal at the centre — but ONLY for a like. The red
    // dye is the heart's alone (repost gets the colourless ripple above, no
    // stain; a boost-green dye is future per-effect work, GLYPH_FIELD spec).
    if (with_dye) {
        gs.dye_reveal_cx = sx;
        gs.dye_reveal_cy = sy;
        gs.dye_reveal_frames = dye_reveal_frames_total;
    }
}

/// Toy Box "Julia mode" — the over-the-top toggle-ON celebration: sparks fly out
/// of the SWITCH as a bloom of wave splashes, traced along a HEART curve so the
/// living field pulses a heart of ripples outward then relaxes. WAVE only
/// (dye = 0), so nothing accumulates across toggles. One call per ON-flip; ~17
/// one-shot splashes (the like burst is the same mechanism), negligible — the
/// splash buffer is cleared every field step. `(cx, cy)` is a field cell.
fn pushJuliaBurst(gpa: Allocator, gs: *GpuState, cx: i32, cy: i32) void {
    if (gs.cols == 0 or gs.rows == 0) return;
    const cols_i: i32 = @intCast(gs.cols);
    const rows_i: i32 = @intCast(gs.rows);
    const cl = struct {
        fn f(v: i32, hi: i32) u16 {
            return @intCast(std.math.clamp(v, 0, hi - 1));
        }
    }.f;
    // A bright central pulse at the switch.
    gs.splashes.append(gpa, .{ .x = cl(cx, cols_i), .y = cl(cy, rows_i), .radius = 7, .amp = 4.5, .dye = 0 }) catch {};
    // Splashes traced along the classic heart parametric curve (scaled to cells,
    // screen-y flipped so the point sits at the bottom): the ripples bloom a heart.
    const n: u32 = 16;
    const sscale: f32 = 0.9;
    var k: u32 = 0;
    while (k < n) : (k += 1) {
        const t = @as(f32, @floatFromInt(k)) * (6.2831853 / @as(f32, @floatFromInt(n)));
        const s = @sin(t);
        const hx = 16.0 * s * s * s;
        const hy = 13.0 * @cos(t) - 5.0 * @cos(2.0 * t) - 2.0 * @cos(3.0 * t) - @cos(4.0 * t);
        const ox: i32 = @intFromFloat(hx * sscale);
        const oy: i32 = @intFromFloat(-hy * sscale); // screen y is down
        gs.splashes.append(gpa, .{ .x = cl(cx + ox, cols_i), .y = cl(cy + oy, rows_i), .radius = 3, .amp = 1.8, .dye = 0 }) catch {};
    }
}

/// THE single source of truth for the glyph cell size for the CELL-PATH
/// fallback. Two facts drive it: (1) the cell HEIGHT is the pixel size the
/// font rasterizes at, and (2) the cell WIDTH is sized to a font advance at
/// that height. The UI face is now PROPORTIONAL (Inter), which has no single
/// advance; we size the cell to 'M' (~0.765× px, the wide reference) so the
/// widest glyph never overflows its cell on this fallback — proportional text
/// reads a little loose here, the accepted cost of the fallback (the premium
/// GPU path uses real per-glyph advances and is unaffected). A bigger window →
/// taller glyphs → larger text, at a roughly constant column count.
///
/// The ratio is a stable font constant, so the pure cellSize can hold it
/// without calling the engine (B2 preserved). It is asserted against the real
/// 'M' metric in a core test (text.zig) so it cannot silently drift.
const glyph_advance_ratio: f32 = 0.765; // measured: advance(M)/px for Inter
/// Target columns the window aims to show at zoom 1.0 — cells scale so
/// roughly this many fit, so widening the window scales text UP rather
/// than packing in more small cells. [TUNE].
const target_cols: f32 = 70;
/// Glyph-height bounds (px): legible when small, dense enough for the
/// physics when large. [TUNE].
const glyph_h_min: f32 = 14;
const glyph_h_max: f32 = 40;
/// Zoom multiplies the window-derived size. [TUNE].
const zoom_min: f32 = 0.6;
const zoom_max: f32 = 2.2;

/// The field grid never shrinks below this many cells, so even a tiny window
/// shows a coherent glyph field rather than a sparse smear. ONE floor for every
/// surface and both render paths (D6): the home/compose/profile software sites
/// had drifted to 24/8 vs 16/6 and the GPU path to 8/8 — same window, so that
/// was change-amplification drift, not intent. The floor binds only at
/// degenerate sizes; the field is a transient background (wiped on resize, §7).
const field_grid_min_cols: u32 = 24;
const field_grid_min_rows: u32 = 8;

/// SOFTWARE-path field grid: how many `cellSize` cells tile the framebuffer
/// (u16, as `field_core.init` wants). The single source for the home, compose,
/// and profile software paths — derive the grid here, never inline (D6).
fn softFieldGrid(fb_w: u32, fb_h: u32, cell_w: u16, cell_h: u16) struct { cols: u16, rows: u16 } {
    return .{
        .cols = @intCast(@max(field_grid_min_cols, fb_w / cell_w)),
        .rows = @intCast(@max(field_grid_min_rows, fb_h / cell_h)),
    };
}

/// GPU-path field grid: the fixed `field_cell_*` cells tile the window (u32, as
/// `glyph_field.init` wants). The single source for GPU init AND resize so the
/// two can never derive the grid differently (the CLAUDE.md §6 unify item).
fn gpuFieldGrid(w: u32, h: u32) struct { cols: u32, rows: u32 } {
    return .{
        .cols = @max(field_grid_min_cols, w / field_cell_w),
        .rows = @max(field_grid_min_rows, h / field_cell_h),
    };
}

/// Derive the integer cell size from the WINDOW width and the user zoom.
/// Pure; the single place the (window,zoom)→pixels mapping lives, so the
/// render path, the pointer hit-test, and the grid-dimension math can
/// never disagree (all call it with the same window width).
fn cellSize(win_w: u32, zoom: f32) struct { w: u16, h: u16 } {
    const z = std.math.clamp(zoom, zoom_min, zoom_max);
    // Width that fits target_cols across the window, zoomed. That width is
    // a glyph ADVANCE; convert it to the glyph HEIGHT the font needs, clamp
    // the height to legible bounds, then set width back to the true advance
    // at that height — so the cell and the glyph are exactly the same width.
    const fitted_w = (@as(f32, @floatFromInt(@max(1, win_w))) / target_cols) * z;
    const h = std.math.clamp(fitted_w / glyph_advance_ratio, glyph_h_min, glyph_h_max);
    const w = h * glyph_advance_ratio;
    return .{
        .w = @max(1, @as(u16, @intFromFloat(@round(w)))),
        .h = @max(1, @as(u16, @intFromFloat(@round(h)))),
    };
}

/// The simulation's injected RNG. Seeded once; the field's evolution is
/// deterministic given the seed + the dt sequence (B2). A process-
/// lifetime source is fine here — it is the SHELL's injected randomness,
/// not core state; the core never reaches for it, the shell hands it in
/// at the one call site below (B4).
var sim_rng = std.Random.DefaultPrng.init(0x7A74_2026);

/// Render the timeline. The window earns the LIVING GLYPH FIELD (G.0):
/// the feed is laid out into a mono grid, effects advance, particles
/// integrate, and compose maps the whole simulation to pixels — every
/// frame a pure transform with dt injected from the monotonic clock
/// (B4). Everything else (terminal, or a window whose font engine
/// failed) keeps the cell frame + diff/present pair. ONE funnel, so
/// interim status flashes render through the same path (D6).
fn paintFrame(
    gpa: Allocator,
    out: *std.Io.Writer,
    arena: Allocator,
    prev: *tui.Surface,
    next: *tui.Surface,
    backend: Backend,
    pix: ?Grid,
    /// The ACTIVE view's posts — Home's timeline, or a profile/zone query. ONE
    /// list of view-models over the shared store, chosen by the caller; the
    /// renderer and input paths key off it uniformly (ZONES invariant 4).
    view_items: []const feed_core.TimelineItem,
    /// The profile header band, non-null only on the profile screen.
    profile_header: ?feed_view.ProfileHeader,
    state: *timeline_ui.UiState,
    revealed: []const []const u8,
    now: i64,
    account_handle: []const u8,
    status: []const u8,
) !void {
    if (pix) |g| switch (backend) {
        // The mobile arm is GPU-only by design (Backend doc): no GPU state
        // → no paint, an honest blank until MC.4c wires the attach. The
        // software cell path below needs an X11 window to blit to.
        .mobile => |m| {
            if (view_items.len > 0 and state.selected >= view_items.len) state.selected = @intCast(view_items.len - 1);
            if (g.gpu) |gs| try paintFrameGpu(gpa, arena, m.width_px, m.height_px, g, gs, view_items, profile_header, now);
            return;
        },
        .window => |win| {
            if (view_items.len > 0 and state.selected >= view_items.len) state.selected = @intCast(view_items.len - 1);
            // Phase 6.4: when the GPU path is live, render the field + feed on
            // the GPU and return; the software path below is the fallback.
            if (g.gpu) |gs| {
                try paintFrameGpu(gpa, arena, win.fb.width, win.fb.height, g, gs, view_items, profile_header, now);
                return;
            }
            // Cell size scales with the user zoom; the grid reflows to
            // fill the window at whatever size results. The font engine
            // rasterizes at the derived pixel height (cached per-size).
            const cell = cellSize(win.fb.width, g.zoom.*);
            const fgrid = softFieldGrid(win.fb.width, win.fb.height, cell.w, cell.h);
            const cols = fgrid.cols;
            const rows = fgrid.rows;
            // (Re)size the field to the window. Cheap; the perturb grid
            // is wiped on resize (transient by design, §7).
            if (g.field.cols != cols or g.field.rows != rows) {
                field_core.deinit(gpa, g.field);
                try field_core.init(gpa, g.field, cols, rows);
            }
            // dt from the monotonic clock — the one time source (B4).
            const t = clock_shell.monotonicNanos();
            var dt: f32 = if (g.last_nanos.* == 0) 1.0 / 60.0 else @as(f32, @floatFromInt(t -| g.last_nanos.*)) / 1_000_000_000.0;
            g.last_nanos.* = t;
            if (dt > 0.1) dt = 0.1; // a long stall integrates one capped step, not a leap
            if (dt <= 0) dt = 1.0 / 60.0;

            // The pipeline, in order: 1. layout writes the content grid
            // + hit rects (perturb persists). 2. effects paint their
            // current stage and emit any spawns. 3. physics integrates
            // particles + cells. 4. compose maps it all to pixels.
            //
            // Step 1 is now the three-column shell carve (nav · feed ·
            // sidebar), which delegates the centre band to the same feed
            // builder and collapses to the full-width feed when the window
            // is too narrow (SHELL_LAYOUT_ROADMAP). Pane widths are a cold
            // config value (A7.2) held here, the one seat a settings screen
            // will later write — no config plumbing built before it is used
            // (F4).
            const t_start = if (debug_frame_timing) clock_shell.monotonicNanos() else 0;
            const pane_cfg: field_ui.PaneConfig = .{};
            _ = try field_ui.layoutShell(g.field, pane_cfg, g.hr, g.hearts, view_items, state.selected, g.view, revealed, now, account_handle, status, gpa);
            // cut 5.6: replace the old cell-grid feed text with the static
            // ambient glyph texture — the premium feed_view layer draws the
            // real content on top. layoutShell still runs so the hit rects and
            // heart slots are ready for the input slice (buttons), but its
            // content is overwritten here.
            field_core.fillAmbient(g.field);
            try effect_core.advance(gpa, g.active, g.field, dt, g.spawn_buf);
            try field_core.step(gpa, g.field, g.particles, g.spawn_buf.items, dt, sim_rng.random());
            const light: field_core.Light = .{
                .x = @floatFromInt(cols / 2),
                .y = @floatFromInt(rows / 4),
                .radius = @floatFromInt(cols),
                .ambient = 0.30, // dim so the field recedes and pools at the light — dark cells
                // starve so the light pools through the material (mockup look)
            };
            // Same rule as the GPU path: the hit-region list starts each frame
            // clean, or it accumulates forever and every pass that walks it sees
            // the ghosts of screens gone by.
            g.regions.clearRetainingCapacity();
            try field_core.compose(gpa, g.field, g.particles.slice(), light, cell.w, cell.h, g.draw);
            // The animating heart burst still composes (when an effect is
            // live); the OLD resting heart sprites are gone — the premium
            // layer owns the heart icons now.
            try effect_core.composeEffects(gpa, g.active.slice(), cell.w, cell.h, g.draw);
            const t_built = if (debug_frame_timing) clock_shell.monotonicNanos() else 0;
            // The premium content layer (avatars, type hierarchy, engagement
            // row, dividers) painted OVER the field as proportional items, fed
            // by the REAL timeline via a pure transform (B5). An empty timeline
            // renders the chrome with no posts — no placeholder content.
            const feed_posts = feed_view.fromTimeline(arena, view_items, now, g.expanded) catch &[_]feed_view.PostView{};
            if (g.screen.* == feed_view.screen_wallet) {
                // The Wallet page: how you get paid, as a durable place. Owns its
                // whole surface and its own scroll (the layoutChat precedent).
                g.content_h.* = feed_view.layoutWallet(gpa, g.engine, @intCast(win.fb.width), @intCast(win.fb.height), g.draw, g.regions, g.accent, g.scroll.*, g.chat_recv, 0, g.wallet_remove_armed, .{}, false, false) catch g.content_h.*;
            } else if (g.chat_store != null and g.screen.* == feed_view.screen_messages) {
                // Zat Chat (U3, dev-gated): the Messages surface. -scroll maps the
                // shared ≤0 scroll state onto layoutChat's positive history offset.
                const cf = buildChatFrame(arena, g.chat_store.?, g.chat_sel, now, g.chat_q, g.verify_ids);
                g.content_h.* = feed_view.layoutChat(gpa, g.engine, @intCast(win.fb.width), @intCast(win.fb.height), g.draw, g.regions, g.accent, -g.scroll.*, false, false, null, cf.list, cf.thread, cf.cards, cf.sel, cf.peer, g.chat_draft, g.chat_edit, g.chat_input_focus, g.chat_composing, g.chat_compose, g.chat_compose_status, g.chat_pay, .{}, &.{}, g.chat_recv, .{}, .{}, g.chat_delivery, g.chat_link, g.chat_devices) catch g.content_h.*;
            } else if (g.screen.* == feed_view.screen_loadout) {
                const ft = g.socket_tray orelse lens_socket.TrayView{ .cards = &.{}, .text = "", .seated = 0 };
                g.content_h.* = feed_view.layoutLoadout(gpa, g.engine, @intCast(win.fb.width), @intCast(win.fb.height), g.draw, g.regions, g.accent, g.scroll.*, g.loadout_tab, g.loadout_geoms, ft, g.socket_ui, g.socket_hits, g.reply_tray, g.reply_ui, g.reply_hits, g.zone_tray, g.zone_ui, g.zone_hits, false, false, null, g.market, g.bench_pick, g.bench_drag, g.published, g.create, g.dev, g.bench, .{}, g.loadout_lib_y) catch g.content_h.*; // software: draw line-art nav
            } else if (g.screen.* == feed_view.screen_enroll) {
                // THE FRONT DOOR (software path). The same pure surface the
                // desktop has always drawn — now on the one loop a phone reaches.
                if (g.boot_on) {
                    if (g.enroll_hits) |hl| hl.clearRetainingCapacity();
                    boot_intro.layout(gpa, g.engine, @intCast(win.fb.width), @intCast(win.fb.height), g.boot_t, g.draw) catch {};
                } else {
                    enroll_view.layout(gpa, g.engine, @intCast(win.fb.width), @intCast(win.fb.height), g.enroll, g.draw, g.enroll_hits) catch {};
                }
                g.content_h.* = @intCast(win.fb.height);
            } else if (g.screen.* == feed_view.screen_algo_docs) {
                g.content_h.* = feed_view.layoutAlgoDocs(gpa, g.engine, @intCast(win.fb.width), @intCast(win.fb.height), g.draw, g.regions, g.accent, g.scroll.*, if (g.docs_kind == 1) algo_docs.dev_doc else algo_docs.user_doc) catch g.content_h.*;
            } else if (g.screen.* == feed_view.screen_algo_detail) {
                g.content_h.* = feed_view.layoutAlgoDetail(gpa, g.engine, @intCast(win.fb.width), @intCast(win.fb.height), g.draw, g.regions, g.accent, g.scroll.*, g.detail) catch g.content_h.*;
            } else if (g.screen.* == feed_view.screen_transparency) {
                if (g.inspect_loading) {
                    g.content_h.* = feed_view.layoutAlgorithmLoading(gpa, g.engine, @intCast(win.fb.width), g.draw, g.regions, g.accent, g.inspect_name, false) catch g.content_h.*;
                } else if (g.inspect_bytes.len > 0) {
                    if (g.inspect_source) {
                        // The byte-exact source IS the stored serialized config.
                        g.content_h.* = feed_view.layoutAlgorithmSource(gpa, g.engine, @intCast(win.fb.width), @intCast(win.fb.height), g.draw, g.regions, g.accent, g.scroll.*, g.inspect_name, g.inspect_ref, if (g.inspect_src.len > 0) g.inspect_src else g.inspect_bytes) catch g.content_h.*;
                    } else {
                        // Re-parse into THIS frame's arena (stable bytes → valid slices).
                        const cfg = algorithm_core.parse(arena, g.inspect_bytes) catch discover.DEFAULT_CONFIG;
                        if (transparency.buildPage(arena, g.inspect_name, g.inspect_ref, cfg) catch null) |pg|
                            g.content_h.* = feed_view.layoutTransparency(gpa, g.engine, @intCast(win.fb.width), @intCast(win.fb.height), g.draw, g.regions, g.accent, g.scroll.*, pg) catch g.content_h.*;
                    }
                } else {
                    // The fetch FAILED: an honest error page, never a black screen.
                    g.content_h.* = feed_view.layoutAlgorithmLoading(gpa, g.engine, @intCast(win.fb.width), g.draw, g.regions, g.accent, g.inspect_name, true) catch g.content_h.*;
                }
            } else {
                // Tiling foundation (S.1): geometry comes through the partition
                // seam. Slice 1 hands back the screen's own geometry (identical
                // render); the animated morph springs this between screens.
                const sw_geom = feed_view.paneGeomFor(@intCast(win.fb.width), g.screen.*);
                g.content_h.* = feed_view.layout(gpa, g.engine, @intCast(win.fb.width), @intCast(win.fb.height), feed_posts, g.scroll.*, g.draw, g.regions, null, false, g.screen.*, profile_header, g.pending_new, g.accent, g.socket_tray, g.socket_ui, g.socket_hits, null, null, g.zone_title, g.zones, sw_geom, g.settings_section, g.settings_toggles, g.settings_account, g.settings_choices, g.settings_picking, g.repost_menu, g.toys, .{}) catch g.content_h.*;
            }
            // A narrow (phone-width) window renders the tab-bar shape here too, so
            // reserve the bar's height so the last row clears it — the same
            // clearance the GPU phone path adds. The software backend is desktop, so
            // there are no safe-area insets: just the bar.
            if (win.fb.width <= feed_view.phone_max)
                g.content_h.* += feed_view.tab_bar_h;
            // The cartridge DETAIL sheet (item 5): topmost overlay when open.
            if (g.cart_detail) |cd| if (g.detail_hits) |dh| {
                dh.clearRetainingCapacity();
                lens_socket.drawDetail(gpa, g.draw, g.engine, cd, g.cart_detail_blob, @intCast(win.fb.width), @intCast(win.fb.height), 0, dh) catch {};
            };
            const t_layout = if (debug_frame_timing) clock_shell.monotonicNanos() else 0;
            window_shell.presentDrawList(win, gpa, g.engine, g.draw.slice(), field_core.background) catch {}; // E2: a lost blit is the next frame's problem
            if (debug_frame_timing) {
                const t_end = clock_shell.monotonicNanos();
                const us = struct {
                    fn d(a: i128, b: i128) i64 {
                        return @intCast(@divTrunc(b - a, 1000));
                    }
                };
                std.debug.print("[zat frame] field+effects {d}us · content {d}us · present(paint+blit) {d}us · items {d} · effects {d}\n", .{ us.d(t_start, t_built), us.d(t_built, t_layout), us.d(t_layout, t_end), g.draw.len, g.active.len });
            }
            return;
        },
        .terminal => {},
    };
    timeline_ui.buildFrame(next, view_items, state, revealed, now, account_handle, status);
    try present(gpa, out, arena, prev, next, backend);
}

/// The GPU render route (Phase 6.4), one frame: step the living field, render
/// Advance the glyph-field medium one fixed-timestep (≈60 Hz) tick, at most once
/// per frame, so it evolves at a constant real-time rate regardless of how fast
/// the loop spins. Stepping per loop-iteration coupled the sim to the INPUT rate
/// (a mouse-motion flood drove the loop far above 60 fps → the whole field sped
/// up while the pointer moved). With the clock gate, idle and active evolve
/// identically; only the pointer's local splash is injected. Shared by the feed
/// and composer paint paths so the field animates the same behind both.
/// How many sim steps the like's red dye fades in over — ~0.3s at 60 Hz, timed
/// to land with the heart's spark burst.
const dye_reveal_frames_total: u32 = 18;
/// Inject one increment (`frac` of the full charge) of a like's dye ring —
/// centre + two concentric rings — as DYE-ONLY splashes (amp 0), so the red
/// FADES in across the splat instead of blipping. Mirrors pushLikeSplash's
/// spatial pattern. A queue-full append is dropped (E4).
fn injectLikeDye(gpa: Allocator, gs: *GpuState, cx: u32, cy: u32, frac: f32) void {
    if (gs.cols == 0 or gs.rows == 0) return;
    gs.splashes.append(gpa, .{ .x = cx, .y = cy, .radius = 6, .amp = 0, .dye = 1.0 * frac }) catch {};
    const ring_dist = [_]f32{ 5.0, 9.0 };
    const ring_dye = [_]f32{ 0.9, 0.6 };
    for (ring_dist, ring_dye) |dist, dye| {
        var k: u32 = 0;
        while (k < 8) : (k += 1) {
            const ang = @as(f32, @floatFromInt(k)) * (6.2831853 / 8.0);
            const ox: i32 = @intFromFloat(@cos(ang) * dist);
            const oy: i32 = @intFromFloat(@sin(ang) * dist);
            const rx = std.math.clamp(@as(i32, @intCast(cx)) + ox, 0, @as(i32, @intCast(gs.cols - 1)));
            const ry = std.math.clamp(@as(i32, @intCast(cy)) + oy, 0, @as(i32, @intCast(gs.rows - 1)));
            gs.splashes.append(gpa, .{ .x = @intCast(rx), .y = @intCast(ry), .radius = 3, .amp = 0, .dye = dye * frac }) catch {};
        }
    }
}

fn advanceField(gpa: Allocator, gs: *GpuState, active: *effect_core.ActiveList) void {
    const dt_ns: u64 = 16_666_667; // 1/60 s
    const now_ns = clock_shell.monotonicNanos();
    const due = gs.last_step_nanos == 0 or (now_ns -| gs.last_step_nanos) >= dt_ns;
    if (!due) return;
    // Fill the time-driven ambient bias (shell side → the core stays pure, B3):
    // a slow drifting two-sine swell plus a finer term so the dense interior is
    // an ASSORTMENT of glyphs, not a wall of one symbol.
    //
    // Both terms are SEPARABLE products — sin(of x,t)·sin(of y,t) — so the value
    // factors into a per-COLUMN part and a per-ROW part. Precompute those 1D
    // tables once (≈2·(cols+rows) sins) and the inner loop is pure multiplies,
    // instead of 4 sins PER CELL (≈4·cols·rows). The arithmetic is the same
    // operands in the same order, so `bias` is bit-identical to the naive form;
    // this is a cost change only. Falls back to per-cell sins if the grid ever
    // exceeds the table cap (no realistic monitor does at a 13×17 px cell).
    const amb_cap = 2048;
    if (gs.cols <= amb_cap and gs.rows <= amb_cap) {
        var ax: [amb_cap]f32 = undefined; // base x-factor:  sin(fx·s + t·d)
        var cx: [amb_cap]f32 = undefined; // fine x-factor:  sin(fx·0.21 − t·0.07)
        var by: [amb_cap]f32 = undefined; // base y-factor:  sin(fy·s·1.3 − t·d·0.8)
        var dy: [amb_cap]f32 = undefined; // fine y-factor:  sin(fy·0.18 + t·0.06)
        var xx: u32 = 0;
        while (xx < gs.cols) : (xx += 1) {
            const fx: f32 = @floatFromInt(xx);
            ax[xx] = std.math.sin(fx * amb_scale + gs.t * amb_drift);
            cx[xx] = std.math.sin(fx * 0.21 - gs.t * 0.07);
        }
        var yy: u32 = 0;
        while (yy < gs.rows) : (yy += 1) {
            const fy: f32 = @floatFromInt(yy);
            by[yy] = std.math.sin(fy * amb_scale * 1.3 - gs.t * amb_drift * 0.8);
            dy[yy] = std.math.sin(fy * 0.18 + gs.t * 0.06);
        }
        yy = 0;
        while (yy < gs.rows) : (yy += 1) {
            const row = yy * gs.cols;
            const byy = by[yy];
            const dyy = dy[yy];
            xx = 0;
            while (xx < gs.cols) : (xx += 1) {
                const base = ax[xx] * byy;
                const fine = cx[xx] * dyy;
                gs.bias[row + xx] = amb_amp * (base + 0.5 * fine);
            }
        }
    } else {
        var yy: u32 = 0;
        while (yy < gs.rows) : (yy += 1) {
            const fy: f32 = @floatFromInt(yy);
            var xx: u32 = 0;
            while (xx < gs.cols) : (xx += 1) {
                const fx: f32 = @floatFromInt(xx);
                const base = std.math.sin(fx * amb_scale + gs.t * amb_drift) *
                    std.math.sin(fy * amb_scale * 1.3 - gs.t * amb_drift * 0.8);
                const fine = std.math.sin(fx * 0.21 - gs.t * 0.07) *
                    std.math.sin(fy * 0.18 + gs.t * 0.06);
                gs.bias[yy * gs.cols + xx] = amb_amp * (base + 0.5 * fine);
            }
        }
    }
    // A like's red DYE is revealed gradually (synced to the spark animation)
    // rather than blipping in: inject a fraction of the dye ring each step until
    // the window closes. The wave (the ripple) already fired once in
    // pushLikeSplash; this only fades the colour in.
    if (gs.dye_reveal_frames > 0) {
        injectLikeDye(gpa, gs, gs.dye_reveal_cx, gs.dye_reveal_cy, 1.0 / @as(f32, @floatFromInt(dye_reveal_frames_total)));
        gs.dye_reveal_frames -= 1;
    }
    // Advance the medium one step; queued splashes injected once.
    glyph_field.step(&gs.field, .{}, gs.splashes.items, gs.bias);
    gs.splashes.clearRetainingCapacity();
    // Tick the like-heart animation clocks on the same 60 Hz step.
    effect_core.advanceClocks(active, 1.0 / 60.0);
    gs.t += 1.0 / 60.0;
    // Advance the step clock by one tick; if we fell far behind (a stall), snap
    // to now and DROP the backlog rather than fast-forward the field.
    gs.last_step_nanos = if (gs.last_step_nanos == 0 or (now_ns -| gs.last_step_nanos) > dt_ns * 4)
        now_ns
    else
        gs.last_step_nanos + dt_ns;
}

/// Render the premium composer (PHASE C1) on the GPU: the living field behind,
/// the composer card on top, then swap — the same field-behind-content pipeline
/// the feed uses, so New-post / reply / profile-edit share the feed's look and
/// the field stays alive behind them. The composer verts are rebuilt every frame
/// (the draft changes per keystroke) into the SAME `gs.feed` buffer; `feed_sig`
/// is zeroed so the timeline rebuilds cleanly on return.
/// The composer tag bar's per-frame VIEW: the draft's live inline #tags
/// (arena-cut by the same rule the facets use) + the shell's chips/locked/
/// input state, as plain values for the pure renderer (B5).
fn tagBarViewOf(arena: Allocator, rs: *RunState, chips_out: *[max_manual_tags][]const u8) feed_view.ComposeTagBarView {
    const bar = &rs.gtagbar;
    for (0..bar.chips_n) |i| chips_out[i] = tagBarChip(bar, i);
    return .{
        .inline_tags = compose_core.inlineTags(arena, textedit.view(&rs.compose)) catch &.{},
        .manual = chips_out[0..bar.chips_n],
        .locked = tagBarLocked(bar),
        .input = bar.input_buf[0..bar.input_len],
        .input_focus = bar.input_focus,
        .caret_on = composeBlinkOn(rs.caret_anchor_ns),
    };
}

fn paintComposeGpu(
    gpa: Allocator,
    // Surface dims, not the Window — the composer renders on any GPU
    // surface (the mobile arm passes the host's; MC.4b's same seam).
    w: u32,
    h: u32,
    g: Grid,
    gs: *GpuState,
    ctx: feed_view.ComposeContext,
    reply_handle: []const u8,
    quoting: []const u8,
    draft: []const u8,
    caret: usize,
    sel_start: usize,
    sel_end: usize,
    blink_on: bool,
    status: []const u8,
    /// Finalized thread segments above the active box (empty for a lone post).
    segments: []const []const u8,
    /// The tag bar's state for this frame (inline + manual + locked chips).
    tag_bar: feed_view.ComposeTagBarView,
) !void {
    gpu.setViewport(@intCast(w), @intCast(h));
    const want = gpuFieldGrid(w, h);
    if (want.cols != gs.cols or want.rows != gs.rows) {
        resizeGpuField(gpa, gs, w, h) catch {};
    }
    const scale = uiScaleFor(w, gs.design_w);
    gs.scale = scale;

    // Build the composer at the LOGICAL design width (scaled to fill), exactly as
    // the feed lays out — so the emitted button regions map back through gs.scale.
    const lh = logicalHFor(w, h, gs.design_w);
    g.draw.len = 0;
    // The Zat4 keyboard shares the composer surface (it was simply never
    // drawn in this pass — no keys on the post composer, on-device
    // 2026-07-10): the composer lays out ABOVE the panel (its footer lifts
    // clear), the keys draw over the bottom band + inset, and their regions
    // land last so they win the taps.
    const kbd_lift: u32 = if (g.kbd_visible) @intCast(feed_view.keyboard_h + @as(i32, @intCast(gs.inset_bottom_l))) else 0;
    feed_view.layoutCompose(gpa, g.engine, @intCast(gs.design_w), @intCast(lh - kbd_lift), g.accent, ctx, reply_handle, quoting, draft, caret, sel_start, sel_end, blink_on, status, segments, tag_bar, g.draw, g.regions) catch {};
    if (g.kbd_visible)
        feed_view.drawKeyboard(gpa, g.draw, g.engine, g.regions, @intCast(gs.design_w), @intCast(lh), @intCast(gs.inset_bottom_l), g.accent, g.kbd_shift, g.kbd_page, g.kbd_caps, g.kbd_flash_key, g.kbd_flash_a, gs.t, toggleOn(g.settings_toggles, settings_view.act_kbd_pulses), toggleOn(g.settings_toggles, settings_view.act_kbd_pop), g.kbd_popup, g.kbd_emoji_open, g.kbd_emoji_scroll, g.kbd_picker_mode, g.kbd_nav_t, g.kbd_nav_scroll) catch {};
    if (g.julia) feed_view.juliaRemapText(g.draw); // light theme: dark text
    if (g.light) feed_view.rethemeLight(gpa, g.draw) catch {};
    gpu.feedBuild(&gs.feed, gpa, g.engine, g.draw.slice(), scale) catch {};
    gs.feed_sig = 0; // force a timeline rebuild when the composer closes

    advanceField(gpa, gs, g.active);

    // The field is OFF on a phone — it costs battery and the feed covers most of
    // it anyway. THE FRONT DOOR IS THE EXCEPTION: it is one card on an otherwise
    // empty screen, so the field is the entire backdrop there, and it is the first
    // thing a new person ever sees of this app. That is worth the milliamps.
    const field_mobile_off = gs.design_w <= feed_view.phone_max and g.screen.* != feed_view.screen_enroll;
    if (!field_mobile_off) gpu.uploadField(&gs.grid, gs.field.height, gs.field.dye, gs.field.cols, gs.field.rows);
    if (g.xp) gpu.clear(retro_clear_r, retro_clear_g, retro_clear_b) else if (g.julia) gpu.clear(julia_clear_r, julia_clear_g, julia_clear_b) else if (g.light) gpu.clear(light_clear_r, light_clear_g, light_clear_b) else gpu.clear(gpu_clear_r, gpu_clear_g, gpu_clear_b);
    // Field glyph ink: cool grey-white normally; pink under Julia mode (the glow
    // rides the ink, so it pinks too). 0xA6ACBA = the shader's original bright endpoint.
    const field_ink: u32 = if (g.julia) lens_socket.julia_field_ink else if (g.light) feed_view.light_field_ink else 0xFFFFFFFF;
    if (g.field_on and !g.xp and !field_mobile_off) gpu.drawFieldGrid(&gs.grid, &gs.ramp, gs.mcx, gs.mcy, gs.t, @intCast(w), @intCast(h), 0, 0, field_ink, g.julia, g.light); // composer: no panel softening (mobile ⇒ field off for battery)
    gpu.feedDraw(&gs.feed, @intCast(w), @intCast(h));
    gpu.swap(&gs.g);
}

/// it grid-intensity, then the premium feed on top, and swap. The feed is laid
/// out at the fixed LOGICAL design width and scaled to FILL the window (DPI),
/// exactly as the preview does. No per-frame pixel blit — render + swap.
fn paintFrameGpu(
    gpa: Allocator,
    arena: Allocator,
    // Surface pixel dims — all this pass ever needed from the window, so
    // the OS-agnostic value crosses instead (the mobile arm has no Window).
    w: u32,
    h: u32,
    g: Grid,
    gs: *GpuState,
    items: []const feed_core.TimelineItem, // the ACTIVE view's posts
    /// The profile header band, non-null only on the profile screen.
    profile_header: ?feed_view.ProfileHeader,
    now: i64,
) !void {
    // Frame-period measurement for the "Show frame timing" overlay — a smoothed
    // ms between successive frames (cheap; the clock read is the only cost).
    {
        const now_ns = clock_shell.monotonicNanos();
        if (gs.last_frame_nanos != 0) {
            const ms = @as(f32, @floatFromInt(now_ns -| gs.last_frame_nanos)) / 1_000_000.0;
            gs.frame_ms = if (gs.frame_ms == 0) ms else gs.frame_ms * 0.9 + ms * 0.1;
        }
        gs.last_frame_nanos = now_ns;
    }
    gpu.setViewport(@intCast(w), @intCast(h));
    // Refit the field grid to the window when the cell count changes (cheap;
    // a few KB R32F). On a failed realloc keep the prior grid (E2).
    const want = gpuFieldGrid(w, h);
    if (want.cols != gs.cols or want.rows != gs.rows) {
        resizeGpuField(gpa, gs, w, h) catch {};
    }

    const scale = uiScaleFor(w, gs.design_w);
    gs.scale = scale;

    // Auto-scroll a freshly-opened/re-focused THREAD so the focused post lands at
    // the top (ancestors above, scrollable up — Bluesky parity). Uses the per-post
    // height cache from the prior layout (valid when its length matches this
    // view); done BEFORE the rebuild so the new scroll takes effect THIS frame.
    if (gs.scroll_to_focus and g.screen.* == feed_view.screen_thread and gs.heights.len == items.len) {
        var off: i32 = 0;
        var measured = true; // only apply once the preceding posts' heights exist
        for (items, 0..) |it, ix| {
            if (it.is_focus) break;
            if (gs.heights[ix] > 0) off += gs.heights[ix] else {
                measured = false;
                break;
            }
        }
        if (measured) {
            const lh_view = logicalHFor(w, h, gs.design_w);
            const min_scroll: i32 = @min(0, @as(i32, @intCast(lh_view)) - g.content_h.* - 24);
            g.scroll.* = @max(min_scroll, @min(0, -off));
            gs.scroll_to_focus = false; // applied; wait for heights next frame otherwise
        }
    }

    // Rebuild the feed ONLY when it changed (scroll / window size / any post's
    // identity, counts, or flags). The field below animates every frame, but
    // this pipeline — fromTimeline + feed_view.layout (which MEASURES every
    // post, including off-screen ones) + buildVertices — is the one per-frame
    // cost worth avoiding (§5 gotcha): at 60 fps over a large feed it stutters.
    // A content hash is the dirty signal, far cheaper than the layout it gates.
    // The feed verts persist in gs.feed across frames; feedDraw below reuses
    // them. (G1/G3: this is the measured-cause fix for the live lag.)
    // Fold the active screen into the dirty signature: switching screens
    // changes the rendered body, so the cached feed verts must rebuild.
    // Fold the socket's live state into the dirty signature: opening the
    // tray, the seat animation advancing, or a re-seat all change what the
    // header draws, so the cached feed verts must rebuild those frames.
    var socket_sig: u64 = (@as(u64, @intFromBool(g.socket_ui.open)) << 40) |
        (@as(u64, g.socket_ui.swap_phase) << 32) | (@as(u64, g.socket_ui.swap_to) << 16) |
        (@as(u64, (g.socket_ui.expanded orelse 0xFFF) + 1) << 48) |
        (if (g.socket_tray) |t| @as(u64, t.seated) else 0);
    socket_sig ^= (@as(u64, (g.socket_ui.picking orelse 0xFF)) +% 1) *% 0xA24B_AED4_963E_E407;
    // While the tray springs open/closed, open_t changes each frame — quantize
    // it into the signature so the feed verts rebuild through the animation.
    socket_sig ^= (@as(u64, @intFromFloat(@max(0, @min(1.0, g.socket_ui.open_t)) * 64)) +% 1) *% 0xCA6B_9576_3F1D_2E11;
    // While dragging, the ghost follows the pointer — fold the drag pointer in
    // so each move rebuilds the socket (the one time a per-move rebuild is wanted).
    if (g.socket_ui.drag_active) |d| {
        socket_sig ^= (@as(u64, d) +% 1) *% 0x2545_F491_4F6C_DD1D;
        socket_sig ^= @as(u64, @bitCast(@as(i64, g.socket_ui.drag_x))) *% 0x9E37_79B1;
        socket_sig ^= @as(u64, @bitCast(@as(i64, g.socket_ui.drag_y))) *% 0x85EB_CA77;
    }
    // Screen-switch CROSSFADE: on a screen change, swap the feed buffers so the
    // OLD screen's verts survive in `feed_prev` (it fades OUT) while `feed`
    // rebuilds with the new content (it fades IN). The nav rail is identical in
    // both, so it stays solid; only the differing content dissolves. Cheap — no
    // relayout during the fade, just two cached draws at a uniform alpha.
    // The chat list↔thread swap is a pane change on ONE screen — treat it
    // like a screen switch so the same crossfade covers it (the pop read raw).
    const chat_pane: u16 = if (g.screen.* == feed_view.screen_messages and g.chat_sel != null) 1 else 0;
    if (gs.fade_screen != g.screen.* or gs.fade_chat_pane != chat_pane) {
        const tmp = gs.feed;
        gs.feed = gs.feed_prev;
        gs.feed_prev = tmp;
        gs.fade_t = 0;
        gs.fade_screen = g.screen.*;
        gs.fade_chat_pane = chat_pane;
        gs.feed_sig = 0; // the swapped-in buffer is stale → force a rebuild below
    }
    gs.fade_t += (1.0 - gs.fade_t) * 0.16; // ease in (~0.25 s)

    // Content-driven SEARCH tile: spring it toward open/closed. While it moves
    // the sidebar repositions, so the feed rebuilds — but the feed's width is
    // unchanged, so its height cache stays warm (cheap, like a scroll).
    springGeom(&gs.search_open, &gs.search_v, if (gs.search_want) 1.0 else 0.0, 1.0 / 60.0);
    const search_animating = @abs(gs.search_open - (if (gs.search_want) @as(f32, 1.0) else 0.0)) > 0.004 or @abs(gs.search_v) > 0.004;

    // ZONES TEST: on the Zones tab the nav rail relocates to the RIGHT — a
    // custom per-page tile-move. `zones_t` springs 0→1 when on a zones screen;
    // while it animates the rail (and its regions/icons) follow, so we rebuild.
    // DESKTOP choreography only: on the phone there is no rail to relocate and
    // no width to shift into — zones_t pinned 0 keeps the page in the plain
    // narrow column (its overflow at 430 was the first on-device finding).
    const on_zones = gs.design_w > feed_view.phone_max and
        (g.screen.* == feed_view.screen_zones_browse or g.screen.* == feed_view.screen_zones);
    springGeom(&gs.zones_t, &gs.zones_v, if (on_zones) 1.0 else 0.0, 1.0 / 60.0);
    const zones_animating = @abs(gs.zones_t - (if (on_zones) @as(f32, 1.0) else 0.0)) > 0.003 or @abs(gs.zones_v) > 0.003;

    // The PHONE drawer springs open/shut; while it moves the chrome tile
    // (scrim + panel + regions) must rebuild each frame.
    if (!gs.drawer_drag) springDrawer(&gs.drawer_t, &gs.drawer_v, if (gs.drawer_want) 1.0 else 0.0, 1.0 / 60.0);
    const drawer_animating = gs.drawer_drag or @abs(gs.drawer_t - (if (gs.drawer_want) @as(f32, 1.0) else 0.0)) > 0.003 or @abs(gs.drawer_v) > 0.003;

    // Hover the RIGHT rail → it expands. The hit-band must track the rail's
    // CURRENT (animated) left edge — when expanded it reaches ~188px further
    // left, so a fixed collapsed-strip band would drop the hover as you move
    // onto the open panel and snap it shut. Use last frame's rail_hover_t.
    const dwf: f32 = @floatFromInt(gs.design_w);
    const rail_left_now: f32 = (dwf - 76.0) - gs.rail_hover_t * 188.0;
    const over_right_rail = gs.zones_t > 0.5 and @as(f32, @floatFromInt(g.hover_x)) >= rail_left_now - 8.0 and g.hover_x < @as(i32, @intCast(gs.design_w)) and g.hover_y >= 0;
    springGeom(&gs.rail_hover_t, &gs.rail_hover_v, if (over_right_rail) 1.0 else 0.0, 1.0 / 60.0);
    const rail_hover_animating = @abs(gs.rail_hover_t - (if (over_right_rail) @as(f32, 1.0) else 0.0)) > 0.004 or @abs(gs.rail_hover_v) > 0.004;

    // ALGORITHMS + ZAT CHAT: the LEFT rail condenses in place (stays left).
    // algo_t springs on the loadout AND messages screens (both master–detail
    // surfaces that want the width); hovering the left rail (its current
    // right edge tracks the expand) re-opens it.
    // DESKTOP choreography only (like zones_t): no rail to condense on phone,
    // and the shift pushed the loadout off the 430 column (on-device finding).
    const on_algo = gs.design_w > feed_view.phone_max and
        (g.screen.* == feed_view.screen_loadout or g.screen.* == feed_view.screen_messages);
    springGeom(&gs.algo_t, &gs.algo_v, if (on_algo) 1.0 else 0.0, 1.0 / 60.0);
    const home_rail_left: f32 = @floatFromInt(feed_view.paneGeomFor(@intCast(gs.design_w), feed_view.screen_loadout).rail_x);
    // The condensed rail hugs the left edge (shifted left by 60); the hover band
    // tracks that shifted position + the current expand width.
    const left_rail_right: f32 = (home_rail_left - 60.0) + 64.0 + gs.left_hover_t * 188.0;
    const over_left_rail = gs.algo_t > 0.5 and g.hover_x >= 0 and @as(f32, @floatFromInt(g.hover_x)) < left_rail_right + 8.0 and g.hover_y >= 0;
    springGeom(&gs.left_hover_t, &gs.left_hover_v, if (over_left_rail) 1.0 else 0.0, 1.0 / 60.0);
    const algo_animating = @abs(gs.algo_t - (if (on_algo) @as(f32, 1.0) else 0.0)) > 0.003 or @abs(gs.algo_v) > 0.003 or @abs(gs.left_hover_t - (if (over_left_rail) @as(f32, 1.0) else 0.0)) > 0.004 or @abs(gs.left_hover_v) > 0.004;
    // Zat Chat (U3): the Messages surface renders from the chat store +
    // selection + draft, none of which the feed signature below can see — a
    // conversation tap or a local send must invalidate the cached content
    // vertices or the screen only updates on re-entry (the caching bug the
    // first live test caught). Fold the chat state in when on the screen.
    var chat_sig: u64 = 0;
    // The WALLET page renders from the same receive state, on a different screen.
    // It needs its OWN fold: `chat_sig` below is gated on screen_messages, so
    // without this the page would build its verts once and then freeze — every
    // button hit-testing against a stale frame's regions. That is the standing
    // rebuild law, and it has bitten three times; this is the fourth surface it
    // would have bitten.
    // THE FRONT DOOR must join the signature or its verts cache on the first
    // frame and every button on it goes dead — the standing rebuild law, which
    // has bitten four surfaces now. Everything the surface RENDERS FROM goes in.
    if (g.screen.* == feed_view.screen_enroll) {
        const en = g.enroll;
        chat_sig = (@as(u64, @intFromEnum(en.step)) +% 1) *% 0x9E37_79B9_7F4A_7C15;
        chat_sig ^= (@as(u64, @intFromEnum(en.branch)) +% 1) *% 0xC2B2_AE3D_27D4_EB4F;
        chat_sig ^= (@as(u64, @intFromEnum(en.focus)) +% 1) *% 0xD6E8_FEB8_6659_FD93;
        chat_sig ^= (@as(u64, @intFromEnum(en.info)) +% 1) *% 0x2545_F491_4F6C_DD1D;
        chat_sig ^= (@as(u64, @intFromEnum(en.tier)) +% 1) *% 0x1656_67B1_9E37_79F9;
        chat_sig ^= (@as(u64, @intFromEnum(en.confirm_stage)) +% 1) *% 0x8EBC_6AF0_9C88_C6E3;
        chat_sig ^= std.hash.Wyhash.hash(0x5A72_C4A7, en.handle);
        chat_sig ^= std.hash.Wyhash.hash(0x3C6E_F372, en.username);
        chat_sig ^= std.hash.Wyhash.hash(0x77E1_A2C9, en.email);
        chat_sig ^= std.hash.Wyhash.hash(0x3B8F_55D1, en.password);
        chat_sig ^= std.hash.Wyhash.hash(0x1F83_D9AB, en.recovery_key);
        chat_sig ^= @as(u64, @intFromBool(en.age_ok)) *% 0xF29C_511C_8E3D_45A7;
        chat_sig ^= @as(u64, @intFromBool(en.tos_ok)) *% 0xBF58_476D_1CE4_E5B9;
        chat_sig ^= @as(u64, @intFromBool(en.saved)) *% 0x94D0_49BB_1331_11EB;
        chat_sig ^= @as(u64, @intFromBool(en.rec_saved)) *% 0x6C8E_9CF5_7703_11A5;
        // The copied-toast FADES, so it must keep rebuilding while it runs.
        chat_sig ^= @as(u64, @intFromFloat(en.copied_t * 64.0)) *% 0xACB5_4B6E_3C2F_1D77;
    }
    if (g.screen.* == feed_view.screen_wallet) {
        chat_sig = (@as(u64, @intFromEnum(g.chat_recv.mode)) +% 1) *% 0x632B_E5A3_11D9_6F07;
        chat_sig ^= (@as(u64, g.chat_recv.focus) +% 1) *% 0xC2B2_AE3D_27D4_EB4F;
        chat_sig ^= @as(u64, @intFromBool(g.chat_recv.saved)) *% 0x1656_67B1_9E37_79F9;
        chat_sig ^= @as(u64, @intFromBool(g.chat_recv.set)) *% 0x2545_F491_4F6C_DD1D;
        chat_sig ^= @as(u64, @intFromBool(g.chat_recv.saving)) *% 0x9E37_79B9_0C1F_2A53;
        chat_sig ^= @as(u64, @intFromBool(g.chat_recv.known)) *% 0xACB5_4B6E_3C2F_1D77;
        chat_sig ^= @as(u64, @intFromBool(g.wallet_remove_armed)) *% 0x8EBC_6AF0_9C88_C6E3;
        chat_sig ^= std.hash.Wyhash.hash(0x2C1B_3C6D, g.chat_recv.lightning);
        chat_sig ^= std.hash.Wyhash.hash(0x9E37_79B1, g.chat_recv.bitcoin);
        chat_sig ^= std.hash.Wyhash.hash(0x7F4A_7C15, g.chat_recv.status);
        // The caret's blink rides `chat_key_ns` (the same channel the chat inputs
        // use), so a focused address field breathes instead of sitting frozen.
        chat_sig ^= g.chat_key_ns *% 0x94D0_49BB_1331_11EB;
    }
    if (g.screen.* == feed_view.screen_messages) if (g.chat_store) |cs| {
        chat_sig = (@as(u64, cs.msgs.len) *% 0x9E37_79B9_7F4A_7C15) ^
            ((if (g.chat_sel) |sc| @as(u64, @intFromEnum(sc)) +% 1 else 0) *% 0xC2B2_AE3D_27D4_EB4F) ^
            std.hash.Wyhash.hash(0x5A72_C4A7, g.chat_draft) ^
            // The list search: each keystroke refilters; focus + blink redraw.
            std.hash.Wyhash.hash(0x3C6E_F372, g.chat_q) ^
            (@as(u64, @intFromBool(g.chat_q_focus)) *% 0x9E6C_63D0_676A_9A99) ^
            (@as(u64, @intFromBool(g.chat_q_focus and g.chat_q_caret)) *% 0xD6E8_FEB8_6659_FD93);
        var unread_sum: u64 = 0;
        for (cs.convs.items(.unread)) |u| unread_sum +%= u;
        chat_sig ^= unread_sum *% 0x2545_F491_4F6C_DD1D;
        // The delivery line (A1): "waiting for them to receive this" has to
        // appear the frame the conversation opens and VANISH the frame their
        // ack lands — a stale line here is the exact dishonesty the ack exists
        // to end (the rebuild law).
        chat_sig ^= (@as(u64, @intFromEnum(g.chat_delivery)) +% 1) *% 0xB4F6_1E27_9D3A_5C81;
        // A3: the identity panel replaces the whole surface — it must appear the
        // frame chat init refuses, and vanish the frame the user adopts (and its
        // one button must be hit-testable against THIS frame's regions).
        chat_sig ^= @as(u64, @intFromBool(g.chat_identity_elsewhere)) *% 0x6C8E_9CF5_7703_11A5;
        // A5: the dot must change colour the frame the link does — a stale dot
        // is worse than no dot, because it is a confident lie about the channel.
        chat_sig ^= (@as(u64, @intFromEnum(g.chat_link)) +% 1) *% 0x1D8E_4E27_F4B3_9A07;
        // The composer focus ring must appear the frame the input is tapped.
        chat_sig ^= @as(u64, @intFromBool(g.chat_input_focus)) *% 0x8A91_7F2B_4D3E_61C7;
        // Caret/selection/bar changes rebuild the strip (the rebuild law).
        chat_sig ^= (@as(u64, g.chat_edit.caret) +% 1) *% 0xD1B5_4A32_D192_ED03;
        chat_sig ^= ((@as(u64, g.chat_edit.sel_a) << 20 ^ @as(u64, g.chat_edit.sel_b) << 1 ^ @as(u64, @intFromBool(g.chat_edit.bar))) +% 1) *% 0x94D0_49BB_1331_11EB;
        // The recipient bar: open/close, every keystroke, and the status
        // line must each repaint the frame they change.
        chat_sig ^= @as(u64, @intFromBool(g.chat_composing)) *% 0xF29C_511C_8E3D_45A7;
        chat_sig ^= std.hash.Wyhash.hash(0x77E1_A2C9, g.chat_compose);
        chat_sig ^= std.hash.Wyhash.hash(0x3B8F_55D1, g.chat_compose_status);
        // The pay sheet (M5 A4): open/close, the rail toggle, every chip
        // tap and keystroke, the focus hop, and the refusal line — each
        // must repaint (and re-emit the TAP REGIONS) the frame it changes.
        // The first live test caught exactly this: a sheet drawn from a
        // lucky rebuild whose buttons hit-tested against the previous
        // frame's regions — dead buttons.
        chat_sig ^= @as(u64, @intFromBool(g.chat_pay.open)) *% 0xBF58_476D_1CE4_E5B9;
        chat_sig ^= (@as(u64, @intFromEnum(g.chat_pay.rail)) +% 1) *% 0x94D0_49BB_1331_11EB;
        chat_sig ^= (@as(u64, g.chat_pay.focus) +% 1) *% 0xD6E8_FEB8_6659_FD93;
        chat_sig ^= (@as(u64, @intFromEnum(g.chat_pay.step)) +% 1) *% 0x7C3A_1B59_E64D_8811;
        chat_sig ^= @as(u64, @intFromBool(g.chat_pay.first_send)) *% 0x3F9A_2E17_5C08_BD43;
        // The worker's in-flight flag changes the button's LABEL and whether it
        // is armed — render-affecting state, so it joins the signature.
        chat_sig ^= @as(u64, @intFromBool(g.chat_pay.busy)) *% 0x5851_F42D_4C95_7F2D;
        // The unit toggle + the live price change what the sheet draws (unit
        // label, ≈$ line) — they MUST join the signature or the readout won't
        // repaint on the GPU path (the A5 lesson).
        chat_sig ^= (@as(u64, @intFromEnum(g.chat_pay.unit)) +% 1) *% 0x2C1B_3C6D_820F_FA8D;
        chat_sig ^= g.chat_pay.usd_cents_per_btc *% 0xEB44_ACCA_B455_D165;
        chat_sig ^= std.hash.Wyhash.hash(0x1F83_D9AB, g.chat_pay.amount);
        chat_sig ^= std.hash.Wyhash.hash(0x9B05_688C, g.chat_pay.note);
        chat_sig ^= std.hash.Wyhash.hash(0x510E_527F, g.chat_pay.status);
        // The receive-setup sheet is render-affecting state too — it MUST join
        // the signature or its content + tap regions won't rebuild on the GPU
        // path (the A5 lesson: a stale frame = dead buttons).
        chat_sig ^= @as(u64, @intFromBool(g.chat_recv.open)) *% 0xA3C5_9AC0_1FEE_D1B7;
        chat_sig ^= (@as(u64, @intFromEnum(g.chat_recv.mode)) +% 1) *% 0x632B_E5A3_11D9_6F07;
        chat_sig ^= (@as(u64, g.chat_recv.focus) +% 1) *% 0xC2B2_AE3D_27D4_EB4F;
        chat_sig ^= @as(u64, @intFromBool(g.chat_recv.saved)) *% 0x1656_67B1_9E37_79F9;
        chat_sig ^= std.hash.Wyhash.hash(0x2C1B_3C6D, g.chat_recv.lightning);
        chat_sig ^= std.hash.Wyhash.hash(0x9E37_79B1, g.chat_recv.bitcoin);
        chat_sig ^= std.hash.Wyhash.hash(0x7F4A_7C15, g.chat_recv.status);
        chat_sig ^= @as(u64, @intFromBool(g.chat_recv.rooted)) *% 0x8A5C_D789_635D_2DFF;
        // The modal's entrance spring. Quantised, because a raw f32 would rebuild
        // every frame forever on floating-point noise; 1/256ths are finer than a
        // pixel of rise. WITHOUT this fold the GPU path caches frame one and the
        // modal freezes half-risen — the rebuild law, which has bitten three times.
        chat_sig ^= @as(u64, @intFromFloat(std.math.clamp(gs.sheet_t, 0, 1) * 256)) *% 0xD1B5_4A32_D192_ED03;
        // Payment CARDS advance without the message count moving (a wire
        // event or the watcher flips status/confirmations on an existing
        // row) — fold every row's live state in so the card repaints the
        // frame it changes (M5 A5's six blocks arrive through here).
        var pay_sum: u64 = 0;
        const pay_status = cs.payments.items(.status);
        const pay_conf = cs.payments.items(.confirmations);
        for (pay_status, pay_conf, 0..) |s, c, i| {
            pay_sum +%= ((@as(u64, @intFromEnum(s)) << 8) +% @as(u64, c) +% 1) *% (i + 2);
        }
        chat_sig ^= (@as(u64, cs.payments.len) << 32) ^ (pay_sum *% 0x2545_F491_4F6C_DD1D);
        // A WATCHED card breathes while we poll for its settlement, so it must
        // rebuild as it breathes — otherwise the GPU path caches the first frame
        // and the "waiting for it to land" dot sits frozen, which is the exact
        // opposite of the reassurance it exists to give. (The rebuild law: fifth
        // surface it would have bitten.) Quantised to ~30 steps a second, so it
        // is a pulse and not a busy-loop.
        for (g.verify_ids) |vid| chat_sig ^= vid *% 0xC2B2_AE3D_27D4_EB4F;
        if (g.verify_ids.len > 0) {
            const tick: u64 = gs.chat_clock_ns / (33 * std.time.ns_per_ms);
            chat_sig ^= tick *% 0x9E37_79B9_7F4A_7C15;
        }
    };

    // Zat Chat motion (U6b). The trigger is DERIVED, in this one place, from the
    // observed state transition — the OPEN conversation's newest message key
    // advanced — and the newest message's direction picks the preset (own send
    // vs counterparty arrival). Each new bubble gets its OWN scale + offset
    // springs; they then run in the one loop on the one clock, and the surface
    // draws whatever the springs say (ANIMATION_SYSTEM_NOTES).
    var chat_animating = false;
    if (g.screen.* == feed_view.screen_messages) if (g.chat_store) |cs| {
        // MEASURED frame time (the one clock): motion is identical at 60/144Hz
        // or across a dropped frame — smoothness comes from real elapsed time.
        const spring_now = clock_shell.monotonicNanos();
        var dt: f32 = if (gs.chat_clock_ns == 0) 1.0 / 60.0 else @as(f32, @floatFromInt(spring_now -| gs.chat_clock_ns)) / 1_000_000_000.0;
        gs.chat_clock_ns = spring_now;
        dt = std.math.clamp(dt, 0.0, 0.05);

        // The money modal's entrance. One scalar, driven off the same measured
        // clock as the bubbles: the scrim fades and the panel rises together.
        // A touch of overshoot so it SEATS rather than merely arriving — the
        // payments flow used to pop into existence, which is most of what made
        // it feel cheap.
        {
            const modal_open = g.chat_pay.open or g.chat_recv.open;
            const target: f32 = if (modal_open) 1 else 0;
            spring.stepScalar(&gs.sheet_t, &gs.sheet_v, target, sheet_spring_c, dt);
            if (@abs(gs.sheet_t - target) > 0.001 or @abs(gs.sheet_v) > 0.001) chat_animating = true;
        }

        // Detect a new bubble in the SELECTED conversation and spawn its springs.
        if (g.chat_sel) |conv| {
            const order = chat_core.threadSlice(arena, cs, conv) catch &[_]chat_core.MsgIndex{};
            const newest: u32 = if (order.len > 0) @intFromEnum(order[order.len - 1]) else 0;
            const conv_key: u32 = @intFromEnum(conv);
            if (!gs.chat_seen_valid or gs.chat_seen_conv != conv_key) {
                // First sight of this conversation (or a switch): sync the
                // watermark WITHOUT animating the thread that was already there.
                gs.chat_seen_conv = conv_key;
                gs.chat_seen_key = newest;
                gs.chat_seen_valid = true;
            } else if (order.len > 0 and newest > gs.chat_seen_key) {
                const msg = order[order.len - 1];
                spawnBubbleAnim(gpa, gs, newest, chat_core.isMine(cs, msg), spring_now);
                startChatReflow(gpa, gs);
                gs.chat_seen_key = newest;
            }
        } else {
            gs.chat_seen_valid = false; // no conversation open
        }

        // Advance every bubble spring + the reflow (the world does its own fixed
        // sub-stepping), and the typing indicator's small spring alongside.
        gs.chat_world.step(dt);
        var rem = dt;
        while (rem > 1e-6) {
            const step = @min(rem, 1.0 / 240.0);
            springPop(&gs.chat_typing_t, &gs.chat_typing_v, if (g.chat_typing) 1.0 else 0.0, step);
            rem -= step;
        }
        if (gs.chat_typing_t > 0.01) gs.chat_typing_phase += dt;
        reapChatAnims(gs);
        // Keep frames coming while anything is in motion (a focused input keeps
        // them for the caret's breath; the pay sheet always holds focus, M5 A4).
        chat_animating = gs.chat_anims.items.len > 0 or gs.chat_reflow != null or
            gs.chat_typing_t > 0.01 or g.chat_typing or
            g.chat_input_focus or g.chat_composing or g.chat_pay.open or g.chat_recv.open;
    };
    // ZONES: the hub + zone page render from state the feed signature can't
    // see — the sub-tab, the search text/focus/caret, the catalog's pins and
    // live stats, the motion scalars, and (hub only) the hover position. Fold
    // it in when on a zones screen, or the cached verts go stale — the chat
    // A5 lesson exactly: dead tabs, dead pins, a frozen frame (the first
    // zones live test caught all three).
    var zones_sig: u64 = 0;
    if (g.screen.* == feed_view.screen_zones_browse or g.screen.* == feed_view.screen_zones) {
        zones_sig = (@as(u64, g.zones.tab) +% 1) *% 0x9E37_79B9_7F4A_7C15;
        zones_sig ^= @as(u64, @intFromBool(g.zones.q_focus)) *% 0x8A91_7F2B_4D3E_61C7;
        zones_sig ^= @as(u64, @intFromBool(g.zones.caret_on)) *% 0xF29C_511C_8E3D_45A7;
        zones_sig ^= @as(u64, @intFromBool(g.zones.pinned)) *% 0xBF58_476D_1CE4_E5B9;
        zones_sig ^= std.hash.Wyhash.hash(0x5A72_C4A7, g.zones.query);
        // Quantized motion: the underline glide + tab-body settle rebuild
        // through their animation frames, then go quiet.
        zones_sig ^= (@as(u64, @intFromFloat(std.math.clamp(g.zones.tab_t, 0.0, 2.0) * 64.0)) +% 1) *% 0xCA6B_9576_3F1D_2E11;
        zones_sig ^= (@as(u64, @intFromFloat(std.math.clamp(g.zones.enter_t, 0.0, 1.0) * 64.0)) +% 1) *% 0xD6E8_FEB8_6659_FD93;
        // The catalog: a pin toggles in place and the server merge updates
        // stats without the length moving — hash the drawn fields.
        var zh: u64 = g.zones.cards.len;
        for (g.zones.cards, 0..) |zc, zi| {
            zh ^= (std.hash.Wyhash.hash(0x2C1B_3C6D, zc.tag) ^
                ((@as(u64, zc.count) << 20) +% (@as(u64, zc.recent) << 8) +% @as(u64, zc.authors) +% (@as(u64, @intFromBool(zc.pinned)) << 40)) ^
                @as(u64, @bitCast(zc.last_at))) *% (@as(u64, zi) *% 2 +% 0x9E37_79B1);
        }
        zones_sig ^= zh;
        // Hover lifts hub cards/rows — track the pointer on the HUB only
        // (it has no posts; its relayout is cheap, G3-measured class).
        if (g.screen.* == feed_view.screen_zones_browse) {
            zones_sig ^= @as(u64, @bitCast(@as(i64, g.hover_x))) *% 0x9E37_79B1;
            zones_sig ^= @as(u64, @bitCast(@as(i64, g.hover_y))) *% 0x85EB_CA77;
        }
    }
    // Read-more expanded set → a set hash (XOR of each CID's FNV, order-free). It
    // rides BOTH the frame signature (so a Read-more tap forces a rebuild — the
    // tap changes PostView.expanded, not `items`, so nothing else would) and the
    // content signature below (so the height cache re-measures clamped/full).
    var exp_sig: u64 = 0;
    for (g.expanded) |c| {
        var eh: u64 = 1469598103934665603;
        for (c) |b| {
            eh ^= b;
            eh *%= 1099511628211;
        }
        exp_sig ^= eh;
    }
    // On the settings screen the hover tooltip is a function of pointer position,
    // so fold hover into the signature THERE (only) — the frame rebuilds as the
    // cursor crosses a help row, and stays cached everywhere else.
    var settings_hover_sig: u64 = 0;
    if (g.screen.* == feed_view.screen_settings) {
        settings_hover_sig ^= @as(u64, @bitCast(@as(i64, g.hover_x))) *% 0x9E37_79B1;
        settings_hover_sig ^= @as(u64, @bitCast(@as(i64, g.hover_y))) *% 0x85EB_CA77;
        // The pet-name field is a live-editing input — fold its text + focus in so
        // the settings frame rebuilds as you type.
        settings_hover_sig ^= @as(u64, @intFromBool(g.settings_account.pet_name_focus)) *% 0x2545_F491_4F6C_DD1D;
        for (g.settings_account.pet_name) |c| settings_hover_sig = settings_hover_sig *% 131 +% c;
    }
    const sig = feedSignature(items, g.scroll.*, w, h) ^ (@as(u64, g.screen.*) *% 0x9E37_79B9_7F4A_7C15) ^ (socket_sig *% 0xD1B5_4A32_D192_ED03) ^ (@as(u64, g.settings_section) *% 0xC2B2_AE3D_27D4_EB4F) ^ (g.settings_toggles *% 0x9E6C_63D0_676A_9A99) ^ (g.settings_choices *% 0x2545_F491_4F6C_DD1D) ^ (@as(u64, g.settings_picking) *% 0x8A91_7F2B_4D3E_61C7) ^ (@as(u64, @intFromBool(g.inspect_source)) *% 0xF29C_511C_8E3D_45A7) ^ (@as(u64, @intFromBool(g.inspect_loading)) *% 0xBF58_476D_1CE4_E5B9) ^ chat_sig ^ zones_sig ^ (exp_sig *% 0x2545_F491_4F6C_DD1D) ^ (@as(u64, if (g.repost_menu) |m| m + 1 else 0) *% 0xA0761D6478BD642F) ^ settings_hover_sig ^ (if (g.xp) (@as(u64, g.xp_hour) *% 60 +% g.xp_min +% 1) *% 0xF1357AEA2E62A9C5 else 0) ^ (@as(u64, @intFromBool(g.light)) *% 0xD6E8_FEB8_6659_FD93) ^ (@as(u64, @bitCast(@as(i64, gs.inset_top_l) *% 73856093 ^ @as(i64, gs.inset_bottom_l) *% 19349663 ^ @as(i64, gs.inset_left_l) *% 83492791 ^ @as(i64, gs.inset_right_l) *% 49979687)) *% 0x9E37_79B9_7F4A_7C15)
        // Item 5: the cartridge detail sheet. Open (vs closed) AND its target colour
        // fold in, so opening, recolouring (the ring + the whole-UI accent), and
        // closing each rebuild the verts even though the overlay keeps input.
        ^ (if (g.cart_detail) |cd| (@as(u64, cd.color) +% 1) *% 0x94D0_49BB_1331_11EB else 0)
        // The double-back hint pill: arming/expiry rebuilds the nav tile.
        ^ (@as(u64, @intFromBool(g.back_hint)) *% 0x517C_C1B7_2722_0A95)
        // Phone chat: opening/closing a thread swaps the tab bar in/out.
        ^ (@as(u64, @intFromBool(g.chat_sel != null)) *% 0x6C62_2726_93D2_35B1)
        // The live keyboard inset: the chat composer rides above it.
        ^ (@as(u64, @intCast(@max(0, gs.ime_bottom_l))) *% 0xE703_7ED1_A0B4_28DB)
        // The Zat4 keyboard: visibility, shift, caps, and page redraw the
        // tile; the press-flash key + its decaying alpha rebuild it each
        // frame of the fade (the rebuild-signature law).
        ^ ((@as(u64, @intFromBool(g.kbd_visible)) << 9 | @as(u64, @intFromBool(g.kbd_emoji_open)) << 8 | @as(u64, @as(u32, @bitCast(g.kbd_emoji_scroll))) << 10 | @as(u64, g.kbd_picker_mode) << 43 | @as(u64, @intFromFloat(std.math.clamp(g.kbd_nav_t, 0.0, 1.0) * 255.0)) << 44 | @as(u64, @as(u32, @bitCast(g.kbd_nav_scroll))) << 21 | @as(u64, @intFromBool(g.kbd_shift)) << 5 | @as(u64, @intFromBool(g.kbd_caps)) << 4 | @as(u64, g.kbd_page)) *% 0xA3B1_95E7_4C29_D6F1) ^ ((@as(u64, g.kbd_flash_key) << 8 | @as(u64, g.kbd_flash_a)) *% 0xC4CE_B9FE_1A85_EC53) ^ (if (g.kbd_visible and toggleOn(g.settings_toggles, settings_view.act_kbd_pulses)) (@as(u64, @intFromFloat(@max(0, (if (g.gpu) |gsp| gsp.t else 0)) * 20.0)) +% 1) *% 0x94D0_49BB_1331_11EB else 0) ^ ((@as(u64, @intCast(g.kbd_popup.sel + 2)) << 4 | @as(u64, g.kbd_popup.opts.len)) *% 0xA0761D6478BD642F);
    // A drag/settle animates the socket every frame (lift, reflow, ghost), so
    // bypass the feed cache while it runs — a brief interaction, and the field
    // already rebuilds every frame anyway.
    const feed_animating = g.toys.feed_toy == .zero_g or g.toys.feed_toy == .liquid;
    // The Zat4 keyboard animates by SIGNATURE, not by bypass: a full
    // per-frame rebuild re-shaped every chat bubble at the display rate and
    // made TYPING mushy (the owner's "something isn't right", 2026-07-11).
    // The pulse clock folds in at 50 ms buckets (~20 fps motion) and the
    // flash alpha is quantized — rebuilds now track change, not refresh.
    // THE FRONT DOOR IS ALWAYS ANIMATING. Its card height, its step slide, its
    // hover, the password's decode, the strength bar and the Copied toast are all
    // EASED — and an eased value cannot live in a signature (it changes every
    // frame by definition, which is the same as having no signature at all).
    //
    // Without this the tile rebuilt on the step CHANGE, while `card_h` was still
    // easing up from the previous step's smaller height, and then never rebuilt
    // again: the panel froze mid-animation, short, while the content was laid out
    // at its true size — so "Create & continue" and "Back" were drawn OUTSIDE the
    // card, on the field. Fifth surface the rebuild law has bitten, and I wrote
    // the warning about it two commits ago.
    const enroll_animating = g.screen.* == feed_view.screen_enroll;
    if (sig != gs.feed_sig or gs.feed.verts.items.len == 0 or g.socket_ui.drag_active != null or search_animating or zones_animating or drawer_animating or rail_hover_animating or algo_animating or chat_animating or enroll_animating or g.screen.* == feed_view.screen_loadout or g.frametiming_on or gs.shatter_active or g.pet or feed_animating) {
        gs.feed_sig = sig;
        // An empty timeline renders the chrome with no posts (no placeholders).
        const feed_posts = feed_view.fromTimeline(arena, items, now, g.expanded) catch &[_]feed_view.PostView{};
        // Per-post height cache: post heights are scroll-invariant, so only
        // reset the cache when the CONTENT or WIDTH changed (scroll/height
        // zeroed in this signature). A pure scroll then reuses every post's
        // measured height and skips the text-shaping pass — the scroll-lag fix.
        // The expanded set also rides the content signature (exp_sig computed
        // above), so toggling a post's expansion re-measures it clamped/full.
        const content_sig = feedSignature(items, 0, w, 0) ^ (exp_sig *% 0x100000001b3);
        if (content_sig != gs.feed_content_sig or gs.heights.len != feed_posts.len) {
            gs.feed_content_sig = content_sig;
            if (gs.heights.len != feed_posts.len) {
                if (gpa.alloc(i32, feed_posts.len)) |buf| {
                    if (gs.heights.len > 0) gpa.free(gs.heights);
                    gs.heights = buf;
                } else |_| {} // keep the old buffer; layout guards on length
            }
            @memset(gs.heights, -1);
        }
        const lh = logicalHFor(w, h, gs.design_w);
        g.draw.len = 0;
        // START THE HIT-REGION LIST CLEAN. It never was.
        //
        // Regions were appended for the life of the process and truncated nowhere,
        // so the list carried every region from every frame of every screen the
        // user had ever visited. Taps still worked — `hitTest` is last-wins, so
        // the newest region won — which is why this survived so long. But the GPU
        // SDF icon pass walks the WHOLE list, and so it cheerfully drew the feed's
        // hearts and reposts on top of the Wallet page, and redrew the rail's nav
        // icons once per rebuild at drifting positions while the rail animated
        // (the "smear"). It was also an unbounded leak.
        //
        // Every emitter — the content layouts AND the chrome (rail, tab bar,
        // drawer, keyboard) — runs inside this rebuild block, so one clear here
        // covers all of them.
        g.regions.clearRetainingCapacity();
        var chain_info: feed_view.ChainSticky = .{};
        if (g.screen.* == feed_view.screen_loadout) {
            // The loadout page: three stacked sockets, its own render path.
            const ft = g.socket_tray orelse lens_socket.TrayView{ .cards = &.{}, .text = "", .seated = 0 };
            // ALGORITHMS: expand the loadout content into the space the condensed
            // left rail frees — shift the glass a bit LEFT toward the rail + widen
            // RIGHT, by algo_t. (The rail itself condenses in the rail-tile pass.)
            var lg = feed_view.paneGeomFor(@intCast(gs.design_w), feed_view.screen_loadout);
            if (gs.algo_t > 0.01) {
                const at = gs.algo_t * gs.algo_t * (3.0 - 2.0 * gs.algo_t);
                const tcx: f32 = home_rail_left + 92.0;
                const tcw: f32 = @as(f32, @floatFromInt(gs.design_w)) - tcx - 40.0;
                const lp2 = struct {
                    fn f(a: i32, b: f32, t: f32) i32 {
                        return @intFromFloat(@as(f32, @floatFromInt(a)) + (b - @as(f32, @floatFromInt(a))) * t);
                    }
                }.f;
                lg.col_x = lp2(lg.col_x, tcx, at);
                lg.col_w = lp2(lg.col_w, tcw, at);
                lg.lx = lp2(lg.lx, tcx + 22.0, at);
            }
            gs.content_x = lg.col_x;
            gs.content_w = lg.col_w;
            g.content_h.* = feed_view.layoutLoadout(gpa, g.engine, @intCast(design_w), @intCast(lh), g.draw, g.regions, g.accent, g.scroll.*, g.loadout_tab, g.loadout_geoms, ft, g.socket_ui, g.socket_hits, g.reply_tray, g.reply_ui, g.reply_hits, g.zone_tray, g.zone_ui, g.zone_hits, true, true, lg, g.market, g.bench_pick, g.bench_drag, g.published, g.create, g.dev, g.bench, .{ .top = @intCast(gs.inset_top_l), .bottom = @intCast(gs.inset_bottom_l), .left = @intCast(gs.inset_left_l), .right = @intCast(gs.inset_right_l) }, g.loadout_lib_y) catch g.content_h.*; // GPU: SDF pass strikes the nav icons crisp
        } else if (g.screen.* == feed_view.screen_enroll) {
            // THE FRONT DOOR, on the GPU path — which is the path the PHONE takes.
            // This one branch is the whole difference between "you can install
            // Zat4" and "you can join Zat4" on a phone.
            if (g.boot_on) {
                // The ENTRANCE, over the door. The hit list is CLEARED, not merely
                // ignored: a tap must not fire a button that is behind an animation.
                if (g.enroll_hits) |hl| hl.clearRetainingCapacity();
                boot_intro.layout(gpa, g.engine, @intCast(gs.design_w), @intCast(lh), g.boot_t, g.draw) catch {};
            } else {
                enroll_view.layout(gpa, g.engine, @intCast(gs.design_w), @intCast(lh), g.enroll, g.draw, g.enroll_hits) catch {};
            }
            g.content_h.* = @intCast(lh);
        } else if (g.screen.* == feed_view.screen_wallet) {
            g.content_h.* = feed_view.layoutWallet(gpa, g.engine, @intCast(gs.design_w), @intCast(lh), g.draw, g.regions, g.accent, g.scroll.*, g.chat_recv, caretPhaseOf(gs.chat_clock_ns, g.chat_key_ns), g.wallet_remove_armed, .{ .top = @intCast(gs.inset_top_l), .bottom = @intCast(gs.inset_bottom_l), .left = @intCast(gs.inset_left_l), .right = @intCast(gs.inset_right_l) }, true, true) catch g.content_h.*;
        } else if (g.chat_store != null and g.screen.* == feed_view.screen_messages) {
            // Zat Chat (U3, dev-gated): the Messages surface in the GPU's logical
            // design space; the rail is the shell's own tile (rail_external), and
            // -scroll maps the shared ≤0 scroll onto the positive history offset.
            // ZAT CHAT: expand the chat glass into the space the condensed
            // left rail frees — shift LEFT toward the rail + widen RIGHT, by
            // algo_t (the same reflow the Algorithms page runs; the rail
            // itself condenses in the rail-tile pass).
            var lg = feed_view.paneGeomFor(@intCast(gs.design_w), feed_view.screen_messages);
            if (gs.algo_t > 0.01) {
                const at = gs.algo_t * gs.algo_t * (3.0 - 2.0 * gs.algo_t);
                const tcx: f32 = home_rail_left + 92.0;
                const tcw: f32 = @as(f32, @floatFromInt(gs.design_w)) - tcx - 40.0;
                const lp2 = struct {
                    fn f(a: i32, b: f32, t: f32) i32 {
                        return @intFromFloat(@as(f32, @floatFromInt(a)) + (b - @as(f32, @floatFromInt(a))) * t);
                    }
                }.f;
                lg.col_x = lp2(lg.col_x, tcx, at);
                lg.col_w = lp2(lg.col_w, tcw, at);
                lg.lx = lp2(lg.lx, tcx + 22.0, at);
                lg.cw = lp2(lg.cw, tcw - 44.0, at);
            }
            gs.content_x = lg.col_x;
            gs.content_w = lg.col_w;
            const cf = buildChatFrame(arena, g.chat_store.?, g.chat_sel, now, g.chat_q, g.verify_ids);
            // Seconds since the last chat keystroke, wrapped onto one blink
            // period past the solid window — f32-precise forever, and a
            // never-touched input still breathes (clock-since-launch).
            const caret_raw_ns: u64 = if (g.chat_key_ns == 0) gs.chat_clock_ns else gs.chat_clock_ns -| g.chat_key_ns;
            var caret_ph: f64 = @as(f64, @floatFromInt(caret_raw_ns)) / 1_000_000_000.0;
            if (caret_ph > 0.55) caret_ph = 0.55 + @mod(caret_ph - 0.55, 1.1);
            const caret_phase: f32 = @floatCast(caret_ph);
            // Compose the per-bubble springs into row transforms (U6b): identity
            // for resting rows, live scale/rise/alpha for the ones still flying.
            // The shell reads its own spring world here and hands the layout plain
            // values — no spring index crosses the boundary (A5/B5).
            var xforms: []feed_view.BubbleXform = &.{};
            if (arena.alloc(feed_view.BubbleXform, cf.thread.len)) |xs| {
                xforms = xs;
                for (xforms) |*x| x.* = .{};
                for (gs.chat_anims.items) |a| {
                    for (cf.order, 0..) |m, ri| {
                        if (@intFromEnum(m) == a.key and ri < xforms.len) {
                            const grow = gs.chat_world.position(a.scale) orelse 1.0;
                            const rise = gs.chat_world.position(a.off) orelse 0.0;
                            // Opacity: a short monotonic ramp off the spawn clock,
                            // NOT a spring — opaque well before the transform settles.
                            const age_ns: f32 = @floatFromInt(gs.chat_clock_ns -| a.born_ns);
                            const alpha = std.math.clamp(age_ns / chat_fade_ns, 0.0, 1.0);
                            xforms[ri] = .{ .grow = grow, .rise = rise, .alpha = alpha };
                            break;
                        }
                    }
                }
            } else |_| {}
            const reflow_t: f32 = if (gs.chat_reflow) |rh| (gs.chat_world.position(rh) orelse 1.0) else 1.0;
            g.content_h.* = feed_view.layoutChat(gpa, g.engine, @intCast(gs.design_w), @intCast(lh), g.draw, g.regions, g.accent, -g.scroll.*, true, true, lg, cf.list, cf.thread, cf.cards, cf.sel, cf.peer, g.chat_draft, g.chat_edit, g.chat_input_focus, g.chat_composing, g.chat_compose, g.chat_compose_status, g.chat_pay, .{ .typing_t = gs.chat_typing_t, .typing_phase = gs.chat_typing_phase, .caret_phase = caret_phase, .reflow_t = reflow_t, .sheet_t = gs.sheet_t }, xforms, g.chat_recv, .{ .top = @intCast(gs.inset_top_l), .bottom = @intCast(@max(gs.inset_bottom_l, @max(gs.ime_bottom_l, if (g.kbd_visible) feed_view.keyboard_h + gs.inset_bottom_l else 0))), .left = @intCast(gs.inset_left_l), .right = @intCast(gs.inset_right_l) }, .{ .q = g.chat_q, .focus = g.chat_q_focus, .caret_on = g.chat_q_caret }, g.chat_delivery, g.chat_link, g.chat_devices) catch g.content_h.*;
        } else if (g.screen.* == feed_view.screen_algo_docs) {
            g.content_h.* = feed_view.layoutAlgoDocs(gpa, g.engine, @intCast(gs.design_w), @intCast(lh), g.draw, g.regions, g.accent, g.scroll.*, if (g.docs_kind == 1) algo_docs.dev_doc else algo_docs.user_doc) catch g.content_h.*;
        } else if (g.screen.* == feed_view.screen_algo_detail) {
            g.content_h.* = feed_view.layoutAlgoDetail(gpa, g.engine, @intCast(gs.design_w), @intCast(lh), g.draw, g.regions, g.accent, g.scroll.*, g.detail) catch g.content_h.*;
        } else if (g.screen.* == feed_view.screen_transparency) {
            // The algorithm transparency page: a plain scrolling document (no rail),
            // rebuilt from the inspected config each entry (what you see = what runs).
            // Summary by default; the byte-exact serialized source on the tap-through.
            if (g.inspect_loading) {
                g.content_h.* = feed_view.layoutAlgorithmLoading(gpa, g.engine, @intCast(gs.design_w), g.draw, g.regions, g.accent, g.inspect_name, false) catch g.content_h.*;
            } else if (g.inspect_bytes.len > 0) {
                if (g.inspect_source) {
                    g.content_h.* = feed_view.layoutAlgorithmSource(gpa, g.engine, @intCast(gs.design_w), @intCast(lh), g.draw, g.regions, g.accent, g.scroll.*, g.inspect_name, g.inspect_ref, if (g.inspect_src.len > 0) g.inspect_src else g.inspect_bytes) catch g.content_h.*;
                } else {
                    const cfg = algorithm_core.parse(arena, g.inspect_bytes) catch discover.DEFAULT_CONFIG;
                    if (transparency.buildPage(arena, g.inspect_name, g.inspect_ref, cfg) catch null) |pg|
                        g.content_h.* = feed_view.layoutTransparency(gpa, g.engine, @intCast(gs.design_w), @intCast(lh), g.draw, g.regions, g.accent, g.scroll.*, pg) catch g.content_h.*;
                }
            } else {
                // The fetch FAILED (not loading, no bytes): an honest error page —
                // before this the arm drew NOTHING and the screen was pure black.
                g.content_h.* = feed_view.layoutAlgorithmLoading(gpa, g.engine, @intCast(gs.design_w), g.draw, g.regions, g.accent, g.inspect_name, true) catch g.content_h.*;
            }
        } else {
            // skip_heart=true on every screen: the SDF heart pass (drawEngagementHearts,
            // below) draws the heart in place for each visible like button of the
            // ACTIVE view, so layout never draws its own — one heart, one pipeline.
            // Tiling foundation (S.1): geometry through the partition seam. The
            // GPU path lays out at the logical design width, so the geom is
            // solved at design_w. Slice 1 = the screen's own geometry (identical).
            // Tiling foundation (S.1): geometry through the partition seam. The
            // GPU path lays out at the logical design width, so the geom is
            // solved at design_w. Geometry SNAPS to the screen's layout (smooth,
            // no per-frame relayout); a cross-screen MORPH is a separate, cheaper
            // mechanism (see the dormant geom_* spring state) — not a relayout.
            var gp_geom = feed_view.paneGeomFor(@intCast(gs.design_w), g.screen.*);
            gp_geom.search_open = gs.search_open; // the content-driven sidebar push
            gp_geom.rail_external = true; // the rail is its own tile (decomposition)
            // ZONES: the rail moved to the right, so the content fills the freed
            // LEFT space — shift the glass left + widen as zones_t grows. (Zones
            // has no posts, so the per-frame relayout during the slide is cheap.)
            if (gs.zones_t > 0.01) {
                const zt2 = gs.zones_t * gs.zones_t * (3.0 - 2.0 * gs.zones_t);
                const tcx: f32 = 90.0;
                const tcw: f32 = @as(f32, @floatFromInt(gs.design_w)) - 90.0 - 104.0; // stop before the right rail
                const lp = struct {
                    fn f(a: i32, b: f32, t: f32) i32 {
                        return @intFromFloat(@as(f32, @floatFromInt(a)) + (b - @as(f32, @floatFromInt(a))) * t);
                    }
                }.f;
                gp_geom.col_x = lp(gp_geom.col_x, tcx, zt2);
                gp_geom.col_w = lp(gp_geom.col_w, tcw, zt2);
                gp_geom.lx = lp(gp_geom.lx, tcx + 22.0, zt2);
            }
            gs.content_x = gp_geom.col_x; // for the field panel-softening (tracks the live content)
            gs.content_w = gp_geom.col_w;
            // Toy Box Liquid: step the scroll-kicked slosh spring so `flow` handed
            // to layout is THIS frame's value. Scrolling kicks it; an underdamped
            // pull to rest makes it sway and settle. Zero-G needs only the clock.
            {
                const cur_scroll: f32 = @floatFromInt(g.scroll.*);
                const dscroll = cur_scroll - gs.flow_scroll_prev;
                gs.flow_scroll_prev = cur_scroll;
                const fdt = std.math.clamp(gs.frame_ms / 1000.0, 0.0, 0.05);
                if (g.toys.feed_toy == .liquid) gs.flow_v += dscroll * 0.5;
                gs.flow_v += (-70.0 * gs.flow - 5.0 * gs.flow_v) * fdt; // spring toward rest
                gs.flow += gs.flow_v * fdt;
                gs.flow = std.math.clamp(gs.flow, -48.0, 48.0);
            }
            var toys_frame = g.toys;
            toys_frame.t = gs.t;
            toys_frame.flow = gs.flow;
            g.content_h.* = feed_view.layout(gpa, g.engine, @intCast(gs.design_w), @intCast(lh), feed_posts, g.scroll.*, g.draw, g.regions, gs.heights, true, g.screen.*, profile_header, g.pending_new, g.accent, g.socket_tray, g.socket_ui, g.socket_hits, &chain_info, &gs.sel_glyphs, g.zone_title, g.zones, gp_geom, g.settings_section, g.settings_toggles, g.settings_account, g.settings_choices, g.settings_picking, g.repost_menu, toys_frame, .{ .top = @intCast(gs.inset_top_l), .bottom = @intCast(gs.inset_bottom_l), .left = @intCast(gs.inset_left_l), .right = @intCast(gs.inset_right_l) }) catch g.content_h.*;
        }
        // Phone: EVERY scrollable body reserves the bottom chrome (tab bar +
        // home-pill inset) so its last row lifts clear of the tab bar — the scroll
        // clamp reads content_h. Done once here for ALL screens (feed, settings,
        // zones, loadout, chat, algo pages), so the pure layout functions stay
        // device-agnostic. Desktop (design_w > phone_max): the nav is a side rail,
        // no bottom bar, nothing reserved.
        if (gs.design_w <= feed_view.phone_max)
            g.content_h.* += feed_view.tab_bar_h + @as(i32, @intCast(gs.inset_bottom_l));
        if (g.julia) feed_view.juliaRemapText(g.draw); // light theme: dark text
        // "Show frame timing": ride the fps/ms badge on the feed buffer. The gate
        // above forces a per-frame rebuild while this is on, so the number is live
        // (a debug mode — the rebuild cost is the thing you're measuring anyway).
        if (g.frametiming_on) {
            var fbuf: [48]u8 = undefined;
            const fps: f32 = if (gs.frame_ms > 0.05) 1000.0 / gs.frame_ms else 0;
            const fs = std.fmt.bufPrint(&fbuf, "{d:.1} ms   {d:.0} fps", .{ gs.frame_ms, fps }) catch "";
            if (fs.len > 0) feed_view.overlayBadge(gpa, g.draw, g.engine, 16, 26, fs) catch {};
        }
        // Toy Box: Gravity SHATTER — on the Settings screen with Gravity on, EVERY
        // individual element (word/glyph, icon stroke, toggle, panel) becomes a
        // falling, grabbable body. Fold the rail in, seed one body per draw item on
        // entry (home + a strong launch so it drops instantly), bind the Gravity row
        // rigid, then step and carry each item by its body. Input owns grab/fling/
        // tap-to-stop + nav lock.
        if (g.toys.feed_toy == .gravity and g.screen.* == feed_view.screen_settings) {
            // Fold the nav rail + logo into the same draw list so they shatter too
            // (the rail is normally its own tile). skip_nav=false → line-art icons
            // fall as pieces; regions=null since nav is locked while shattered.
            if (gs.design_w > feed_view.phone_max) {
                const rail_home_x = feed_view.paneGeomFor(@intCast(gs.design_w), g.screen.*).rail_x;
                feed_view.renderRail(gpa, g.draw, g.engine, rail_home_x, @intCast(lh), g.screen.*, null, g.accent, false, 1.0) catch {};
            }
            // Thin out the big dark panels: drop the huge backgrounds, cut mid ones
            // into small squares — so the pile isn't a wall of black boxes.
            feed_view.shatterCullBig(gpa, g.draw, 88, 240) catch {};
            const sn = g.draw.len;
            gs.shatter_x.resize(gpa, sn) catch {};
            gs.shatter_y.resize(gpa, sn) catch {};
            gs.shatter_vx.resize(gpa, sn) catch {};
            gs.shatter_vy.resize(gpa, sn) catch {};
            gs.shatter_hx.resize(gpa, sn) catch {};
            gs.shatter_hy.resize(gpa, sn) catch {};
            gs.shatter_bw.resize(gpa, sn) catch {};
            gs.shatter_bh.resize(gpa, sn) catch {};
            gs.shatter_gid.resize(gpa, sn) catch {};
            gs.shatter_leader_of.resize(gpa, sn) catch {};
            gs.shatter_group.resize(gpa, sn) catch {};
            if (gs.shatter_x.items.len == sn and sn > 0) {
                if (!gs.shatter_active or gs.shatter_n != sn) {
                    feed_view.shatterCaptureHomes(g.draw, gs.shatter_hx.items, gs.shatter_hy.items, gs.shatter_bw.items, gs.shatter_bh.items);
                    @memset(gs.shatter_group.items, false);
                    // Group runs of adjacent glyphs into words (fall together, stay
                    // readable), and give the Gravity row (label + switch) its own
                    // group so it stays as one recognizable, tappable control.
                    const grav_gid = feed_view.shatterWordGroups(g.draw, gs.shatter_gid.items);
                    for (g.regions.items) |rgn| {
                        if (rgn.kind == .settings_row and rgn.post < settings_view.rows.len and settings_view.rows[rgn.post].action == settings_view.act_gravity) {
                            const rl: f32 = @floatFromInt(rgn.x);
                            const rt: f32 = @floatFromInt(rgn.y);
                            const rr: f32 = @floatFromInt(@as(i32, rgn.x) + rgn.w);
                            const rb: f32 = @floatFromInt(@as(i32, rgn.y) + rgn.h);
                            for (0..sn) |c| {
                                const px = gs.shatter_hx.items[c] + gs.shatter_bw.items[c] * 0.5;
                                const py = gs.shatter_hy.items[c] + gs.shatter_bh.items[c] * 0.5;
                                if (px >= rl and px < rr and py >= rt and py < rb) {
                                    gs.shatter_gid.items[c] = grav_gid;
                                    gs.shatter_group.items[c] = true;
                                }
                            }
                        }
                    }
                    // Each group's leader = the first item carrying its id (else self).
                    for (0..sn) |c| gs.shatter_leader_of.items[c] = @intCast(c);
                    for (0..sn) |c| {
                        const gid = gs.shatter_gid.items[c];
                        if (gid == 0) continue;
                        var f: usize = 0;
                        while (f < c) : (f += 1) {
                            if (gs.shatter_gid.items[f] == gid) {
                                gs.shatter_leader_of.items[c] = @intCast(f);
                                break;
                            }
                        }
                    }
                    for (0..sn) |c| {
                        gs.shatter_x.items[c] = gs.shatter_hx.items[c];
                        gs.shatter_y.items[c] = gs.shatter_hy.items[c];
                        // Strong launch kick → an instant, heavy, chaotic drop.
                        const rxh: u32 = @as(u32, @intCast(c)) *% 2654435761;
                        const ryh: u32 = @as(u32, @intCast(c)) *% 40503 +% 1013904223;
                        gs.shatter_vx.items[c] = @floatFromInt(@as(i32, @intCast(rxh % 1200)) - 600);
                        gs.shatter_vy.items[c] = @floatFromInt(@as(i32, @intCast(ryh % 700)) + 250);
                    }
                    gs.shatter_active = true;
                    gs.shatter_n = sn;
                }
                if (gs.shatter_held) |hidx| if (hidx < sn) {
                    const tx = @as(f32, @floatFromInt(g.hover_x)) - gs.shatter_grab_dx;
                    const ty = @as(f32, @floatFromInt(g.hover_y)) - gs.shatter_grab_dy;
                    const dtc = std.math.clamp(gs.frame_ms / 1000.0, 0.004, 0.05);
                    gs.shatter_vx.items[hidx] = (tx - gs.shatter_x.items[hidx]) / dtc;
                    gs.shatter_vy.items[hidx] = (ty - gs.shatter_y.items[hidx]) / dtc;
                    gs.shatter_x.items[hidx] = tx;
                    gs.shatter_y.items[hidx] = ty;
                };
                const sdt: f32 = std.math.clamp(gs.frame_ms / 1000.0, 0.0, 0.05);
                shatter.step(gs.shatter_x.items, gs.shatter_y.items, gs.shatter_vx.items, gs.shatter_vy.items, gs.shatter_bw.items, gs.shatter_bh.items, gs.shatter_held, @floatFromInt(lh), @floatFromInt(gs.design_w), sdt);
                // Bind each group member rigidly to its leader, COMPACTED horizontally
                // so a wide row (the Gravity label + far-right switch) collapses into
                // one tight block instead of a stretched, dismembered-looking strip.
                for (0..sn) |c| {
                    const ld = gs.shatter_leader_of.items[c];
                    if (ld == @as(u32, @intCast(c))) continue;
                    const l: usize = ld;
                    const dx = std.math.clamp(gs.shatter_hx.items[c] - gs.shatter_hx.items[l], -120.0, 120.0);
                    gs.shatter_x.items[c] = gs.shatter_x.items[l] + dx;
                    gs.shatter_y.items[c] = gs.shatter_y.items[l] + (gs.shatter_hy.items[c] - gs.shatter_hy.items[l]);
                    gs.shatter_vx.items[c] = gs.shatter_vx.items[l];
                    gs.shatter_vy.items[c] = gs.shatter_vy.items[l];
                }
                feed_view.applyShatterItems(g.draw, gs.shatter_x.items, gs.shatter_y.items, gs.shatter_hx.items, gs.shatter_hy.items);
                // A fixed EXIT box, top-right, always on top — the easy way out.
                feed_view.shatterExitBox(gpa, g.draw, g.engine, @intCast(gs.design_w), g.accent) catch {};
            }
        } else {
            gs.shatter_active = false;
            gs.shatter_held = null;
        }
        // Settings: a hover tooltip for rows that opted into a help string. The
        // pointer over a `.settings_row` region → look up the row's help → draw
        // it last so it overlays the rows. Suppressed while the page is shattered.
        if (g.screen.* == feed_view.screen_settings and !gs.shatter_active) {
            if (feed_view.hitTest(g.regions.items, g.hover_x, g.hover_y)) |hit| {
                if (hit.kind == .settings_row and hit.post < settings_view.rows.len) {
                    const help = settings_view.helpText(settings_view.rows[hit.post].action);
                    feed_view.drawTooltip(gpa, g.draw, g.engine, g.hover_x, g.hover_y, 0, @intCast(gs.design_w), help) catch {};
                }
            }
        }
        // Toy Box: Pet — step the pure state machine on this frame's activity, then
        // draw the companion in the bottom-right, on top of everything. Its box is
        // stored for the tap hit-test (clicking it "pets" it).
        if (g.pet) {
            const act: pet_core.Activity = .{ .petted = gs.pet_petted, .tossed = gs.pet_tossed, .scroll_ms = gs.pet_scroll_ms, .interacted = gs.pet_interacted };
            const dt_ms: u32 = @intFromFloat(std.math.clamp(gs.frame_ms, 0.0, 100.0));
            gs.pet = pet_core.step(gs.pet, dt_ms, act);
            gs.pet_petted = false;
            gs.pet_tossed = false;
            gs.pet_scroll_ms = 0;
            gs.pet_interacted = false;

            const size_ci: u6 = @intCast((settings_view.choiceIndex(settings_view.act_pet_size) orelse 0) * 3);
            const color_ci: u6 = @intCast((settings_view.choiceIndex(settings_view.act_pet_color) orelse 0) * 3);
            const pscale = feed_view.petScale(@intCast((g.settings_choices >> size_ci) & 7));
            const pcolor = feed_view.petColor(@intCast((g.settings_choices >> color_ci) & 7));
            const pw_s = @as(f32, @floatFromInt(feed_view.pet_w)) * pscale;
            const ph_s = @as(f32, @floatFromInt(feed_view.pet_h)) * pscale;
            const wf: f32 = @floatFromInt(gs.design_w);
            const floor_y: f32 = @as(f32, @floatFromInt(lh)) - 30.0; // the cushion from the bottom
            if (!gs.pet_seeded) {
                gs.pet_px = wf - pw_s - 26.0;
                gs.pet_py = floor_y - ph_s;
                gs.pet_vx = 0;
                gs.pet_vy = 0;
                gs.pet_roll = 0;
                gs.pet_seeded = true;
            }
            const dt: f32 = std.math.clamp(gs.frame_ms / 1000.0, 0.0, 0.05);
            if (gs.pet_grabbed) {
                // Follow the cursor; track velocity so releasing TOSSES it.
                const tx = @as(f32, @floatFromInt(g.hover_x)) - gs.pet_grab_dx;
                const ty = @as(f32, @floatFromInt(g.hover_y)) - gs.pet_grab_dy;
                const dtc = @max(dt, 0.004);
                gs.pet_vx = (tx - gs.pet_px) / dtc;
                gs.pet_vy = (ty - gs.pet_py) / dtc;
                gs.pet_px = tx;
                gs.pet_py = ty;
            } else {
                gs.pet_vy += 2600.0 * dt; // gravity
                gs.pet_px += gs.pet_vx * dt;
                gs.pet_py += gs.pet_vy * dt;
                if (gs.pet_px < 0) {
                    gs.pet_px = 0;
                    gs.pet_vx = -gs.pet_vx * 0.5;
                } else if (gs.pet_px + pw_s > wf) {
                    gs.pet_px = wf - pw_s;
                    gs.pet_vx = -gs.pet_vx * 0.5;
                }
                if (gs.pet_py + ph_s > floor_y) {
                    gs.pet_py = floor_y - ph_s;
                    if (gs.pet_vy > 220.0) gs.pet_vy = -gs.pet_vy * 0.45 else gs.pet_vy = 0;
                    gs.pet_vx *= 0.90; // ground friction
                }
                // Roll from horizontal motion (ω = v / radius); settle upright when slow.
                gs.pet_roll += (gs.pet_vx / (pw_s * 0.5)) * dt;
                if (@abs(gs.pet_vx) < 12.0) gs.pet_roll -= gs.pet_roll * @min(1.0, 8.0 * dt);
            }
            gs.pet_x = @intFromFloat(gs.pet_px);
            gs.pet_y = @intFromFloat(gs.pet_py);
            gs.pet_bw = @intFromFloat(pw_s);
            gs.pet_bh = @intFromFloat(ph_s);
            // Feeding: a profile picture dragged from the feed — dim the original
            // in its post, and float the token toward the pet.
            if (gs.avatar_drag and gs.avatar_post < feed_posts.len) {
                for (g.regions.items) |rgn| {
                    if (rgn.kind == .author and rgn.post == gs.avatar_post) {
                        feed_view.dimAvatar(gpa, g.draw, rgn.x, rgn.y, rgn.w, rgn.h) catch {};
                    }
                }
                const ap = feed_posts[gs.avatar_post];
                feed_view.drawAvatarToken(gpa, g.draw, g.engine, @intFromFloat(gs.avatar_x), @intFromFloat(gs.avatar_y), 44, ap.tint, ap.initial) catch {};
            }
            // Held or airborne → the wide-eyed EXCITED "whee" face; a recent pet/
            // feed → a guaranteed HAPPY smile for a beat (so the reaction always
            // reads, independent of the slow mood machine); otherwise its mood.
            const airborne = gs.pet_py + ph_s < floor_y - 4.0;
            if (gs.pet_happy > 0) gs.pet_happy -= 1;
            const anim_draw: u8 = if (gs.pet_grabbed or airborne) 4 else if (gs.pet_happy > 0) 1 else @intFromEnum(gs.pet.anim);
            feed_view.drawPet(gpa, g.draw, g.engine, gs.pet_x, gs.pet_y, anim_draw, gs.t * 2.4, gs.pet_roll, pscale, pcolor, g.accent, g.settings_account.pet_name) catch {};
        } else {
            gs.pet_seeded = false; // re-toggling drops it back in the corner
            gs.avatar_drag = false;
        }
        // Toy Box: XP skin — first RE-THEME the whole content tile into the
        // old-software look (grey window, black text, beveled widgets), THEN draw
        // the desktop chrome on top so the chrome keeps its own Luna palette.
        // Logical coords (design_w × logical height); feedBuild scales it.
        if (g.xp) {
            feed_view.rethemeRetro(gpa, g.draw, @intCast(gs.design_w), @intCast(lh), true) catch {};
            feed_view.drawXpSkin(gpa, g.draw, g.engine, @intCast(gs.design_w), @intCast(lh), g.xp_hour, g.xp_min) catch {};
        } else if (g.light) feed_view.rethemeLight(gpa, g.draw) catch {};
        gpu.feedBuild(&gs.feed, gpa, g.engine, g.draw.slice(), scale) catch {};

        // The nav rail as its OWN tile (the decomposition): render it into a
        // separate vertex buffer so it can slide/compress independently of the
        // content. It emits the nav hit regions (clicks + the SDF nav icons
        // follow). Because the rail is no longer in `gs.feed`, the screen-switch
        // crossfade no longer dissolves it — it stays solid, which is correct.
        // Built for EVERY screen (incl. the loadout/Algorithms page, which now
        // skips its own rail via rail_external) with the active nav = the screen.
        if (g.screen.* == feed_view.screen_enroll) {
            // THE FRONT DOOR WEARS NO CHROME — but it DOES need the keyboard.
            //
            // A person who is not signed in must not see a nav rail, a tab bar, a
            // composer or a profile chip, let alone be able to USE them to walk
            // into an app they have no account for. So this tile is emptied.
            //
            // But the Zat4 KEYBOARD lives in this same tile (chrome above content),
            // and emptying it took the keyboard with it — so the front door had
            // five text fields and no way on earth to type into any of them. The
            // person was shown a form they could not fill in. Draw the keyboard,
            // and nothing else.
            g.draw.len = 0;
            if (g.kbd_visible)
                feed_view.drawKeyboard(gpa, g.draw, g.engine, g.regions, @intCast(gs.design_w), @intCast(lh), @intCast(gs.inset_bottom_l), g.accent, g.kbd_shift, g.kbd_page, g.kbd_caps, g.kbd_flash_key, g.kbd_flash_a, gs.t, toggleOn(g.settings_toggles, settings_view.act_kbd_pulses), toggleOn(g.settings_toggles, settings_view.act_kbd_pop), g.kbd_popup, g.kbd_emoji_open, g.kbd_emoji_scroll, g.kbd_picker_mode, g.kbd_nav_t, g.kbd_nav_scroll) catch {};
            gpu.feedBuild(&gs.rail, gpa, g.engine, g.draw.slice(), scale) catch {};
        } else if (gs.shatter_active and gs.design_w > feed_view.phone_max) {
            // The desktop rail was folded INTO the shattered feed buffer above, so
            // clear its separate tile — otherwise an intact rail would draw on top
            // of the debris.
            gs.rail.verts.items.len = 0;
        } else if (gs.design_w <= feed_view.phone_max) {
            // PHONE: the nav-chrome tile IS the bottom tab bar (the rail is
            // desktop furniture). Same buffer, same un-crossfaded draw, same
            // region kinds — the dispatch and the SDF icon pass are unchanged.
            g.draw.len = 0;
            // Zat Chat's open THREAD is immersive on the phone: no tab bar — the
            // header's back chevron / the system back leave it, and the composer
            // owns the bottom edge (the future standalone app's shape).
            const chat_thread_open = g.screen.* == feed_view.screen_messages and g.chat_sel != null;
            if (!chat_thread_open)
                feed_view.drawTabBar(gpa, g.draw, g.engine, @intCast(gs.design_w), @intCast(lh), @intCast(gs.inset_bottom_l), g.screen.*, g.regions, g.accent, true) catch {};
            // The nav DRAWER slides over everything (scrim + panel); its
            // regions land last, so while open it owns the taps.
            feed_view.drawDrawer(gpa, g.draw, g.engine, @intCast(gs.design_w), @intCast(lh), gs.drawer_t, g.screen.*, g.regions, g.accent, g.you_handle, true) catch {};
            // THE ZAT4 KEYBOARD: drawn in this tile (chrome above content, under
            // the modal sheets), covering the tab bar + inset while a text
            // input wants keys. Its taps feed the same byte stream the system
            // IME's fallback feeds — one input path (MC.4d).
            if (g.kbd_visible)
                feed_view.drawKeyboard(gpa, g.draw, g.engine, g.regions, @intCast(gs.design_w), @intCast(lh), @intCast(gs.inset_bottom_l), g.accent, g.kbd_shift, g.kbd_page, g.kbd_caps, g.kbd_flash_key, g.kbd_flash_a, gs.t, toggleOn(g.settings_toggles, settings_view.act_kbd_pulses), toggleOn(g.settings_toggles, settings_view.act_kbd_pop), g.kbd_popup, g.kbd_emoji_open, g.kbd_emoji_scroll, g.kbd_picker_mode, g.kbd_nav_t, g.kbd_nav_scroll) catch {};
            // The cartridge DETAIL sheet (item 5) is chrome-topmost: it lives in
            // THIS tile (drawn after the feed buffer), not the feed buffer, or the
            // tab bar + FAB paint over its scrim (the on-device bleed, 2026-07-09).
            // Input is consumed by the sheet's own hit list while open.
            if (g.cart_detail) |cd| if (g.detail_hits) |dh| {
                dh.clearRetainingCapacity();
                lens_socket.drawDetail(gpa, g.draw, g.engine, cd, g.cart_detail_blob, @intCast(gs.design_w), @intCast(lh), @intCast(gs.inset_top_l), dh) catch {};
            };
            // The double-back heads-up: a centred pill above the bar while armed.
            if (g.back_hint) feed_view.drawBackHint(gpa, g.draw, g.engine, @intCast(gs.design_w), @intCast(lh), @intCast(gs.inset_bottom_l)) catch {};
            if (g.julia) feed_view.juliaRemapText(g.draw);
            if (g.xp) feed_view.rethemeRetro(gpa, g.draw, @intCast(gs.design_w), @intCast(lh), false) catch {};
            if (g.light) feed_view.rethemeLight(gpa, g.draw) catch {};
            gpu.feedBuild(&gs.rail, gpa, g.engine, g.draw.slice(), scale) catch {};
        } else {
            const dw: f32 = @floatFromInt(gs.design_w);
            const home_rail_x: f32 = @floatFromInt(feed_view.paneGeomFor(@intCast(gs.design_w), g.screen.*).rail_x);
            const zt = gs.zones_t * gs.zones_t * (3.0 - 2.0 * gs.zones_t); // smoothstep
            g.draw.len = 0;
            // LEFT rail: slides off the left as zt→1 (Zones). On the Algorithms
            // page it CONDENSES and hugs the LEFT EDGE (shift left by algo_t);
            // hover re-expands it in place.
            const algo_shift: f32 = gs.algo_t * 60.0;
            const left_home: f32 = home_rail_x - algo_shift;
            const exit_x: i32 = @intFromFloat(left_home + (-260.0 - left_home) * zt);
            const left_expand: f32 = 1.0 - gs.algo_t * (1.0 - gs.left_hover_t);
            feed_view.renderRail(gpa, g.draw, g.engine, exit_x, @intCast(lh), g.screen.*, g.regions, g.accent, true, left_expand) catch {};
            // RIGHT rail (CONDENSED): slides IN from beyond the right edge as
            // zt→1, simultaneously. Hover expands it (rail_hover_t) and shifts it
            // LEFT so the full width fits on-screen (a flyout over the content).
            if (gs.zones_t > 0.01) {
                const compressed_x = dw - 76.0;
                const settled_x = compressed_x - gs.rail_hover_t * 188.0; // shift left when expanded
                const enter_x: i32 = @intFromFloat((dw + 20.0) + (settled_x - (dw + 20.0)) * zt);
                feed_view.renderRail(gpa, g.draw, g.engine, enter_x, @intCast(lh), g.screen.*, g.regions, g.accent, true, gs.rail_hover_t) catch {};
            }
            // The cartridge DETAIL sheet (item 5): same chrome-topmost placement as
            // the phone arm, so the desktop rail can't paint over its scrim.
            if (g.cart_detail) |cd| if (g.detail_hits) |dh| {
                dh.clearRetainingCapacity();
                lens_socket.drawDetail(gpa, g.draw, g.engine, cd, g.cart_detail_blob, @intCast(gs.design_w), @intCast(lh), @intCast(gs.inset_top_l), dh) catch {};
            };
            if (g.julia) feed_view.juliaRemapText(g.draw); // light theme: dark text
            if (g.xp) feed_view.rethemeRetro(gpa, g.draw, @intCast(gs.design_w), @intCast(lh), false) catch {};
            if (g.light) feed_view.rethemeLight(gpa, g.draw) catch {};
            gpu.feedBuild(&gs.rail, gpa, g.engine, g.draw.slice(), scale) catch {};
        }

        // Capture the chain extent + identity (OWNED copies) for the sticky chain
        // header overlay — valid across the non-rebuild frames until the next
        // content change (offsets are scroll-independent).
        gs.chain_present = chain_info.present and chain_info.head_index < feed_posts.len;
        if (gs.chain_present) {
            const head = feed_posts[chain_info.head_index];
            gs.chain_top_off = chain_info.top_off;
            gs.chain_bottom_off = chain_info.bottom_off;
            gs.chain_pin_y = chain_info.pin_y;
            gs.chain_tint = head.tint;
            gs.chain_initial = head.initial;
            const nl = @min(head.name.len, gs.chain_name.len);
            @memcpy(gs.chain_name[0..nl], head.name[0..nl]);
            gs.chain_name_len = @intCast(nl);
            const hl = @min(head.handle.len, gs.chain_handle.len);
            @memcpy(gs.chain_handle[0..hl], head.handle[0..hl]);
            gs.chain_handle_len = @intCast(hl);
        }
    }

    advanceField(gpa, gs, g.active);

    // The living field is OFF on the phone (mobile): it is barely visible under
    // the full-bleed feed and the per-frame R32F upload + full-screen field
    // shader is real battery/GPU cost for ~no payoff on a handheld. The CPU sim
    // (advanceField, tens of µs) stays so effects/dye accounting are intact; only
    // the GPU upload + draw are skipped. Desktop is unchanged.
    // The field is OFF on a phone — it costs battery and the feed covers most of
    // it anyway. THE FRONT DOOR IS THE EXCEPTION: it is one card on an otherwise
    // empty screen, so the field is the entire backdrop there, and it is the first
    // thing a new person ever sees of this app. That is worth the milliamps.
    const field_mobile_off = gs.design_w <= feed_view.phone_max and g.screen.* != feed_view.screen_enroll;

    // Render: the living field behind, the feed on top, then swap.
    if (!field_mobile_off) gpu.uploadField(&gs.grid, gs.field.height, gs.field.dye, gs.field.cols, gs.field.rows);
    if (g.xp) gpu.clear(retro_clear_r, retro_clear_g, retro_clear_b) else if (g.julia) gpu.clear(julia_clear_r, julia_clear_g, julia_clear_b) else if (g.light) gpu.clear(light_clear_r, light_clear_g, light_clear_b) else gpu.clear(gpu_clear_r, gpu_clear_g, gpu_clear_b);
    // Soften the field UNDER the content column (glass backdrop). The feed lays
    // out at the logical design width; map the column's x-range to physical px.
    // Panel softening tracks the LIVE (animated) content column, not the static
    // metricsPage one — so the "distortion" panel follows the widened Zones glass.
    // While the page is shattered there is no content column to soften — the glass
    // itself has broken into falling debris, so the field must render flat under it.
    const panel_l = if (gs.shatter_active) 0 else @as(f32, @floatFromInt(gs.content_x)) * scale;
    const panel_r = if (gs.shatter_active) 0 else @as(f32, @floatFromInt(gs.content_x + gs.content_w)) * scale;
    const field_ink: u32 = if (g.julia) lens_socket.julia_field_ink else if (g.light) feed_view.light_field_ink else 0xFFFFFFFF;
    gs.grid.gain = g.field_gain; // Appearance → "Field intensity" choice
    if (g.field_on and !g.xp and !field_mobile_off) gpu.drawFieldGrid(&gs.grid, &gs.ramp, gs.mcx, gs.mcy, gs.t, @intCast(w), @intCast(h), panel_l, panel_r, field_ink, g.julia, g.light); // "Living glyph field" off ⇒ flat background (XP ⇒ teal desktop; mobile ⇒ off for battery)
    // Hover highlight (post wash + button highlight), BEHIND the feed so the
    // content draws on top — the app feels alive under the cursor. DESKTOP only:
    // on touch there is no persistent cursor, so a tap would leave a stray wash
    // rectangle lingering at the last tap point (the "random rectangle").
    if (!field_mobile_off) drawHoverOverlay(gpa, g, gs, scale, @intCast(w), @intCast(h));
    // The feed verts persist across frames (rebuilt above only when the feed
    // changed); just draw them. During a screen-switch CROSSFADE, draw the old
    // screen (fading out) under the new (fading in) — the rail, in both, stays.
    if (gs.fade_t < 0.995) {
        gpu.feedDrawAlpha(&gs.feed_prev, @intCast(w), @intCast(h), 1.0 - gs.fade_t);
        gpu.feedDrawAlpha(&gs.feed, @intCast(w), @intCast(h), gs.fade_t);
    } else {
        gpu.feedDraw(&gs.feed, @intCast(w), @intCast(h));
    }
    // The nav rail tile draws ON TOP of the content and SOLID (no crossfade) —
    // it's constant across screens, so it stays put while content dissolves.
    gpu.feedDraw(&gs.rail, @intCast(w), @intCast(h));
    // The rooted post's read-only text selection — a translucent band drawn ON TOP
    // of the feed text (a highlighter, not an occluder). It must sit above the
    // post's glass fill, so it draws AFTER the feed, not behind it (behind, the
    // glass swallowed it — the "selection does nothing" report).
    drawSelectionOverlay(gpa, g, gs, scale, @intCast(w), @intCast(h));
    // The socket hover highlight rides ON TOP of the feed (its panels are
    // opaque, so it can't sit behind like the post wash does). Gated off while
    // the detail sheet is open (modal chrome — nothing may paint over it).
    if (g.cart_detail == null) drawSocketHoverTop(gpa, g, gs, scale, @intCast(w), @intCast(h));
    // The engagement hearts: one SDF heart per visible like button, drawn IN
    // PLACE (feed_view skips its own), so a like fills + pops the ACTUAL heart.
    drawEngagementHearts(g, gs, items, @intCast(w), @intCast(h));
    drawJuliaBurst(gs, @intCast(w), @intCast(h));
    // The SDF icons (repost, gear) — crisp, drawn in place of the line-art.
    drawSdfIcons(g, gs, items, @intCast(w), @intCast(h));
    // The sticky CHAIN header: pins while scrolling the chain, catches up on
    // scroll-down, pushed out at the chain's end. Drawn LAST (on top), per-frame.
    // Gated off while the detail sheet is open (it can open from the reply socket
    // on the thread screen, right where the chain header pins).
    if (g.cart_detail == null) drawChainSticky(gpa, g, gs, scale, @intCast(w), @intCast(h));
    // The right-click context menu sits ABOVE everything else.
    drawContextMenu(gpa, g, gs, scale, @intCast(w), @intCast(h));
    // Toy Box: CRT scanlines — a post-process over the whole frame.
    if (g.crt_on) gpu.drawScanlines(&gs.scanlines);
    gpu.swap(&gs.g);
}

/// The sticky chain header overlay (thread "chain"). Pure-sticky base
/// (`y = min(max(inlineY, pinY), chainBottom − h)`) so the scroll-UP handoff to
/// the inline header is seamless by construction; a scroll-DOWN-only catch-up
/// (brief fade + slide-down) is layered on top and never affects the up seam.
fn drawChainSticky(gpa: Allocator, g: Grid, gs: *GpuState, scale: f32, vw: i32, vh: i32) void {
    if (!gs.chain_present or g.screen.* != feed_view.screen_thread) {
        gs.chain_catchup_t = 0;
        gs.chain_was_pinned = false;
        return;
    }
    const scroll = g.scroll.*;
    const header_h: i32 = 46;
    const is_phone = gs.design_w <= feed_view.phone_max;
    const top_edge: i32 = @intCast(gs.inset_top_l); // visible top (status-bar bottom; 0 on desktop)
    // PHONE: the desktop pin (feed_y0 ≈ 112 + the inset shift) read as a fat dead
    // band ~40% down the screen, and the bar appeared while the head post's
    // name/avatar were STILL VISIBLE inline — a doubled header (owner, 2026-07-09).
    // Owner's rule: appear only once the inline header is ENTIRELY out of view,
    // and sit snug under the Back/Thread bar. `chain_pin_phone` is the tuck-under
    // offset — an eyes-on-device [TUNE].
    const chain_pin_phone: i32 = 48;
    const pin_y = if (is_phone) top_edge + chain_pin_phone else gs.chain_pin_y;
    const inline_y = gs.chain_top_off + scroll; // screen y of the inline header
    const bottom_y = gs.chain_bottom_off + scroll; // screen y of the chain end
    // Desktop keeps the seamless slide-under handoff (pin the moment the inline
    // header crosses the pin line); phone waits for it to fully leave the screen.
    const pinned = if (is_phone) inline_y + header_h < top_edge else inline_y < pin_y;
    // Catch-up edge: newly pinned (scrolled down past) → restart the entrance.
    if (pinned and !gs.chain_was_pinned) gs.chain_catchup_t = 0;
    gs.chain_was_pinned = pinned;
    if (!pinned) {
        gs.chain_catchup_t = 0; // inline header is in view; the feed draws it
        return;
    }
    gs.chain_catchup_t += (1.0 - gs.chain_catchup_t) * 0.16;
    const t = gs.chain_catchup_t;
    // Pure-sticky base, pushed up by the chain's end (continuous → seamless).
    var base_y = pin_y;
    const pushed = bottom_y - header_h;
    if (pushed < base_y) base_y = pushed;
    // Catch-up: a small downward slide settling to base_y + a fade.
    const slide: i32 = @intFromFloat((1.0 - t) * 16.0);
    const draw_y = base_y - slide;
    // Fully pushed out above the pin → nothing to show.
    if (base_y + header_h <= pin_y) return;
    const alpha: f32 = t * std.math.clamp(@as(f32, @floatFromInt(base_y + header_h - pin_y)) / @as(f32, @floatFromInt(header_h)), 0.0, 1.0);
    if (alpha <= 0.02) return;

    var hd: raster_core.DrawList = .{};
    defer hd.deinit(gpa);
    feed_view.buildChainHeaderBar(gpa, &hd, g.engine, @intCast(gs.design_w), draw_y, header_h, pin_y, gs.chain_tint, gs.chain_initial, gs.chain_name[0..gs.chain_name_len], gs.chain_handle[0..gs.chain_handle_len], g.accent, alpha, if (is_phone) 0 else null) catch return;
    if (hd.len == 0) return;
    gpu.feedBuild(&gs.hover, gpa, g.engine, hd.slice(), scale) catch return;
    gpu.feedDraw(&gs.hover, vw, vh);
}

/// Scan one socket HitList for the rect under the pointer, splitting it the
/// same way the feed does: a `.seat` (the whole lens card) is the wash; every
/// other control (toggle/expand/reorder/swatch/get_more…) is the brighter
/// button. Forward iteration means the last (topmost-drawn) match wins, so a
/// sub-control over its card highlights the control AND washes the card.
fn scanSocketHits(hits: []const lens_socket.HitRect, hx: i32, hy: i32, wash: *?lens_socket.HitRect, button: *?lens_socket.HitRect) void {
    for (hits) |r| {
        if (hx < r.x or hx >= @as(i32, r.x) + r.w or hy < r.y or hy >= @as(i32, r.y) + r.h) continue;
        switch (r.target) {
            .seat => wash.* = r, // the whole lens card
            // The whole-bar toggle is clickable but should NOT wash on hover —
            // only its chevron (the .caret sub-hit) lights up.
            .toggle => {},
            else => button.* = r, // caret, expand, reorder, swatch_open, get_more…
        }
    }
}

/// Build + draw the hover highlight: a subtle wash over the post under the
/// cursor and a brighter highlight behind the specific button under it. Driven
/// by g.hover_x/y (logical coords) hit-tested against THIS frame's regions, into
/// a small overlay vert buffer — so a pointer move never rebuilds the feed.
fn drawHoverOverlay(gpa: Allocator, g: Grid, gs: *GpuState, scale: f32, vw: i32, vh: i32) void {
    var wash: ?feed_view.Region = null; // the post under the cursor
    var button: ?feed_view.Region = null; // a button/control under the cursor
    // Socket tap targets live in their own HitLists (not g.regions), so scan
    // them too: a `.seat` (whole card) reads as the wash, sub-controls as the
    // brighter button — the same wash/button split the feed uses.
    var sock_wash: ?lens_socket.HitRect = null;
    var sock_button: ?lens_socket.HitRect = null;
    if (g.hover_x >= 0) {
        for (g.regions.items) |r| {
            if (g.hover_x < r.x or g.hover_x >= @as(i32, r.x) + r.w or g.hover_y < r.y or g.hover_y >= @as(i32, r.y) + r.h) continue;
            switch (r.kind) {
                .post_body => wash = r,
                .tag_inline => {}, // an inline hashtag underlines in drawSocketHoverTop (on TOP of the feed); the post wash here still fires via .post_body
                .compose_send, .compose_cancel, .compose_add, .compose_remove => {},
                else => button = r, // engagement, avatar, nav, tabs, edit, pill, back…
            }
        }
        // The active socket (feed on home, reply on the thread, feed on the
        // loadout page) is always live; the reply/zone sockets are only laid
        // out by layoutLoadout, so scan them only on that screen.
        if (g.bench_pick == null) { // the chooser overlay outranks socket hover
            scanSocketHits(g.socket_hits.items, g.hover_x, g.hover_y, &sock_wash, &sock_button);
            if (g.screen.* == feed_view.screen_loadout) {
                scanSocketHits(g.reply_hits.items, g.hover_x, g.hover_y, &sock_wash, &sock_button);
                scanSocketHits(g.zone_hits.items, g.hover_x, g.hover_y, &sock_wash, &sock_button);
            }
        }
    }
    // Ease toward present/absent so the highlight fades rather than snaps.
    const target: f32 = if (wash != null or button != null or sock_wash != null or sock_button != null) 1.0 else 0.0;
    gs.hover_alpha += (target - gs.hover_alpha) * 0.30;
    if (gs.hover_alpha < 0.02) return;

    // Scale each highlight's alpha byte by the eased opacity.
    // Post wash bumped 0x0E → 0x16 (~1.6×): the large post area read too faint at
    // 5.5% while the smaller icon/nav highlights (0x1C) looked right.
    const wash_a: u32 = @intFromFloat(@as(f32, 0x16) * gs.hover_alpha);
    const btn_a: u32 = @intFromFloat(@as(f32, 0x1C) * gs.hover_alpha);
    var hd: raster_core.DrawList = .{};
    defer hd.deinit(gpa);
    // The feed wash/button sit BEHIND the feed: posts are translucent glass over
    // the field, so the highlight shows through. The socket is NOT drawn here —
    // its panels are opaque, so a highlight behind them is occluded. It draws in
    // drawSocketHoverTop (after the feed) instead; the sock_* detection above
    // only feeds the easing target so the alpha rises while over the socket.
    if (wash) |r| hd.append(gpa, .{ .rect = .{ .x = r.x, .y = r.y, .w = r.w, .h = r.h, .color = (wash_a << 24) | 0x00FFFFFF, .radius = 0 } }) catch {};
    if (button) |r| hd.append(gpa, .{ .rect = .{ .x = @intCast(@as(i32, r.x) - 4), .y = r.y, .w = r.w + 8, .h = r.h, .color = (btn_a << 24) | 0x00FFFFFF, .radius = 12 } }) catch {};
    if (hd.len == 0) return;
    gpu.feedBuild(&gs.hover, gpa, g.engine, hd.slice(), scale) catch return;
    gpu.feedDraw(&gs.hover, vw, vh);
}

/// A press on the rooted post's body: place the caret + begin a drag (single
/// click), or select the word (double) / line (triple) under it — the standard
/// text affordances, counted by the same time+proximity rule the composer uses.
fn selectPress(gs: *GpuState, rx: i32, ry: i32, last_ns: *u64, last_x: *i32, last_y: *i32, count: *u8, now_ns: u64) void {
    const near = @abs(rx - last_x.*) <= 3 and @abs(ry - last_y.*) <= 3;
    count.* = if (now_ns -| last_ns.* < 400_000_000 and near) count.* + 1 else 1;
    last_ns.* = now_ns;
    last_x.* = rx;
    last_y.* = ry;
    const caret = text_select.caretAtPoint(gs.sel_glyphs.items, rx, ry);
    switch (@min(count.*, @as(u8, 3))) {
        1 => {
            gs.sel_anchor = caret;
            gs.sel_focus = caret;
            gs.sel_dragging = true; // single click → drag-extend
        },
        2 => {
            const s = text_select.wordAt(gs.sel_glyphs.items, caret);
            gs.sel_anchor = s.lo;
            gs.sel_focus = s.hi;
            gs.sel_dragging = false;
        },
        else => {
            // Triple click → the WHOLE post. A wrapped "line" is just a layout
            // break here, not a meaningful unit, so word → post is the ladder.
            gs.sel_anchor = 0;
            gs.sel_focus = @intCast(gs.sel_glyphs.items.len);
            gs.sel_dragging = false;
        },
    }
}

// The right-click context menu over a rooted post's selectable text.
const menu_w: i32 = 184;
const menu_row_h: i32 = 30;
const menu_pad_y: i32 = 6;
const menu_items = [_][]const u8{ "Copy", "Select all" };

fn clampI16(v: i32) i16 {
    return @intCast(std.math.clamp(v, -32768, 32767));
}
fn clampU16(v: i32) u16 {
    return @intCast(std.math.clamp(v, 0, 65535));
}

/// Right-click on the rooted post body opens the menu at the cursor. With no
/// selection yet, it first selects the word under the cursor so Copy has a
/// target (browser behaviour). A miss (not the rooted body) does nothing.
fn openContextMenu(gs: *GpuState, screen: u8, view_items: []const feed_core.TimelineItem, regions: []const feed_view.Region, rx: i32, ry: i32) void {
    if (screen != feed_view.screen_thread) return;
    const hit = feed_view.hitTest(regions, rx, ry) orelse return;
    if (hit.kind != .post_body or hit.post >= view_items.len or !view_items[hit.post].is_focus) return;
    const r = text_select.range(gs.sel_glyphs.items.len, gs.sel_anchor, gs.sel_focus);
    if (r.hi <= r.lo) {
        const caret = text_select.caretAtPoint(gs.sel_glyphs.items, rx, ry);
        const w = text_select.wordAt(gs.sel_glyphs.items, caret);
        gs.sel_anchor = w.lo;
        gs.sel_focus = w.hi;
    }
    gs.menu_open = true;
    gs.menu_x = std.math.clamp(rx, 0, @as(i32, @intCast(gs.design_w)) - menu_w);
    gs.menu_y = @max(0, ry);
}

/// The menu item (0=Copy, 1=Select all) under the pointer, or null.
fn menuItemAt(gs: *const GpuState, rx: i32, ry: i32) ?u8 {
    if (rx < gs.menu_x or rx >= gs.menu_x + menu_w) return null;
    var i: u8 = 0;
    while (i < menu_items.len) : (i += 1) {
        const iy = gs.menu_y + menu_pad_y + @as(i32, i) * menu_row_h;
        if (ry >= iy and ry < iy + menu_row_h) return i;
    }
    return null;
}

/// A click while the menu is open: run the item under the pointer (or just close
/// on a click outside). Always closes the menu.
fn menuClick(gpa: Allocator, gs: *GpuState, backend: Backend, rx: i32, ry: i32) void {
    defer gs.menu_open = false;
    const item = menuItemAt(gs, rx, ry) orelse return;
    switch (item) {
        0 => copySelection(gpa, gs, backend),
        1 => {
            gs.sel_anchor = 0;
            gs.sel_focus = @intCast(gs.sel_glyphs.items.len);
        },
        else => {},
    }
}

/// Copy the current selection to the clipboard (no-op if empty). Shared by the
/// menu's Copy and the Ctrl+C key path.
fn copySelection(gpa: Allocator, gs: *GpuState, backend: Backend) void {
    const r = text_select.range(gs.sel_glyphs.items.len, gs.sel_anchor, gs.sel_focus);
    if (r.hi <= r.lo) return;
    var buf: std.ArrayListUnmanaged(u8) = .empty;
    defer buf.deinit(gpa);
    text_select.copyInto(gpa, &buf, gs.sel_glyphs.items, gs.sel_anchor, gs.sel_focus) catch return;
    if (buf.items.len == 0) return;
    switch (backend) {
        .window => |w| window_shell.setClipboard(w, buf.items),
        .terminal, .mobile => {}, // no clipboard surface (mobile: a later UX pass)
    }
}

/// Append a UTF-8 run as proportional glyph items (the shell's own little text
/// emitter for the menu — feed_view owns the feed's text; this is just chrome).
fn menuText(dl: *raster_core.DrawList, gpa: Allocator, engine: *const text_core.Engine, x: i32, baseline: i32, color: u32, px: u16, s: []const u8) void {
    var pen = x;
    var it = (std.unicode.Utf8View.init(s) catch return).iterator();
    while (it.nextCodepoint()) |cp| {
        dl.append(gpa, .{ .text = .{ .x = clampI16(pen), .baseline = clampI16(baseline), .codepoint = cp, .color = color, .px = px, .weight = 0 } }) catch return;
        pen += @intCast(text_core.advance(engine, .regular, cp, px));
    }
}

/// Draw the context menu on top of everything: a rounded slab, a row hover
/// highlight, and the item labels (Copy dim when there's nothing selected).
fn drawContextMenu(gpa: Allocator, g: Grid, gs: *GpuState, scale: f32, vw: i32, vh: i32) void {
    if (!gs.menu_open) return;
    const x = gs.menu_x;
    const y = gs.menu_y;
    const h: i32 = menu_pad_y * 2 + menu_row_h * @as(i32, menu_items.len);
    var dl: raster_core.DrawList = .{};
    defer dl.deinit(gpa);
    dl.append(gpa, .{ .rect = .{ .x = clampI16(x), .y = clampI16(y), .w = clampU16(menu_w), .h = clampU16(h), .color = 0xF21C1E26, .radius = 10 } }) catch {};
    const has_sel = blk: {
        const r = text_select.range(gs.sel_glyphs.items.len, gs.sel_anchor, gs.sel_focus);
        break :blk r.hi > r.lo;
    };
    for (menu_items, 0..) |label, i| {
        const iy = y + menu_pad_y + @as(i32, @intCast(i)) * menu_row_h;
        const hovered = g.hover_x >= x and g.hover_x < x + menu_w and g.hover_y >= iy and g.hover_y < iy + menu_row_h;
        if (hovered) dl.append(gpa, .{ .rect = .{ .x = clampI16(x + 4), .y = clampI16(iy + 2), .w = clampU16(menu_w - 8), .h = clampU16(menu_row_h - 4), .color = 0x24FFFFFF, .radius = 6 } }) catch {};
        const dim = i == 0 and !has_sel; // Copy is dim with no selection
        const color: u32 = if (dim) 0x66E8EAED else 0xFFE8EAED;
        menuText(&dl, gpa, g.engine, x + 14, iy + 20, color, 15, label);
    }
    gpu.feedBuild(&gs.menu, gpa, g.engine, dl.slice(), scale) catch return;
    gpu.feedDraw(&gs.menu, vw, vh);
}

/// The rooted post's read-only text selection: one translucent accent band per
/// selected line, drawn BEHIND the feed text (the glyphs land on top, so it
/// reads as a highlight). The bands come from the pure `text_select` core over
/// the body glyphs captured this rebuild; the indices are clamped there, so a
/// just-shrunk glyph run can't read out of bounds. Thread screen only.
fn drawSelectionOverlay(gpa: Allocator, g: Grid, gs: *GpuState, scale: f32, vw: i32, vh: i32) void {
    if (g.screen.* != feed_view.screen_thread) return;
    const r = text_select.range(gs.sel_glyphs.items.len, gs.sel_anchor, gs.sel_focus);
    if (r.hi <= r.lo) return;
    var rects: std.ArrayListUnmanaged(text_select.Rect) = .empty;
    defer rects.deinit(gpa);
    // Body text is 16px: ~14px above the baseline, ~4px below, covers the band.
    text_select.highlightRects(gpa, &rects, gs.sel_glyphs.items, gs.sel_anchor, gs.sel_focus, 14, 4) catch return;
    if (rects.items.len == 0) return;
    var hd: raster_core.DrawList = .{};
    defer hd.deinit(gpa);
    const accent = g.accent & 0x00FFFFFF;
    // One CONTINUOUS selection: each wrapped line's band is extended down to the
    // next line's top so they abut (no gaps, no per-line pills), with only a
    // gentle uniform softening. A whole-selection breath on the fill keeps a bit
    // of life without the busy per-line glow that read as disjointed blobs.
    const pulse: f32 = 0.5 + 0.5 * @sin(gs.t * 1.8);
    const fill_a: u32 = @intFromFloat(@as(f32, 0x44) + pulse * @as(f32, 0x12)); // ~68..86
    for (rects.items, 0..) |rc, i| {
        // Abut: a non-last line fills the leading down to the next line's top.
        const h: i32 = if (i + 1 < rects.items.len) rects.items[i + 1].y - rc.y else rc.h;
        hd.append(gpa, .{ .rect = .{
            .x = clampI16(rc.x),
            .y = clampI16(rc.y),
            .w = clampU16(rc.w),
            .h = clampU16(h),
            .color = (fill_a << 24) | accent,
            .radius = 2,
        } }) catch {};
    }
    // Bracket beams: a crisp bright accent bar at the selection's exact start and
    // end (the | | the owner pictured) — drawn ON TOP of the fill so they read as
    // clean range markers. They sit at the first/last glyphs' edges and span the
    // text line height (not the abutted leading).
    if (rects.items.len > 0) {
        const first = rects.items[0];
        const last = rects.items[rects.items.len - 1];
        const beam: u32 = (@as(u32, 0xCC) << 24) | accent;
        hd.append(gpa, .{ .rect = .{ .x = clampI16(first.x - 1), .y = clampI16(first.y), .w = 2, .h = clampU16(first.h), .color = beam, .radius = 1 } }) catch {};
        hd.append(gpa, .{ .rect = .{ .x = clampI16(last.x + last.w - 1), .y = clampI16(last.y), .w = 2, .h = clampU16(last.h), .color = beam, .radius = 1 } }) catch {};
    }
    if (hd.len == 0) return;
    gpu.feedBuild(&gs.sel, gpa, g.engine, hd.slice(), scale) catch return;
    gpu.feedDraw(&gs.sel, vw, vh);
}

/// The socket half of the hover highlight, drawn AFTER the feed (on top): the
/// socket panels are opaque, so its wash/button can't go behind the feed like
/// the post highlight does. Reuses the eased `gs.hover_alpha` set this frame by
/// drawHoverOverlay (which already folded the socket into its target), and the
/// same gs.hover vert buffer — built+drawn after the feed so it lands on top.
fn drawSocketHoverTop(gpa: Allocator, g: Grid, gs: *GpuState, scale: f32, vw: i32, vh: i32) void {
    if (g.hover_x < 0 or gs.hover_alpha < 0.02) return;
    if (g.bench_pick != null) return; // the chooser overlay outranks socket hover
    var sock_wash: ?lens_socket.HitRect = null;
    var sock_button: ?lens_socket.HitRect = null;
    scanSocketHits(g.socket_hits.items, g.hover_x, g.hover_y, &sock_wash, &sock_button);
    if (g.screen.* == feed_view.screen_loadout) {
        scanSocketHits(g.reply_hits.items, g.hover_x, g.hover_y, &sock_wash, &sock_button);
        scanSocketHits(g.zone_hits.items, g.hover_x, g.hover_y, &sock_wash, &sock_button);
    }
    // An inline `#tag` under the cursor gets an UNDERLINE — drawn HERE (after the
    // feed) so it lands on TOP of the prose, not behind the translucent post like
    // the wash. The "this is a link" affordance the user asked for.
    var tag_ul: ?feed_view.Region = null;
    for (g.regions.items) |r| {
        if (r.kind != .tag_inline) continue;
        if (g.hover_x < r.x or g.hover_x >= @as(i32, r.x) + r.w or g.hover_y < r.y or g.hover_y >= @as(i32, r.y) + r.h) continue;
        tag_ul = r;
    }
    if (sock_wash == null and sock_button == null and tag_ul == null) return;

    const wash_a: u32 = @intFromFloat(@as(f32, 0x0E) * gs.hover_alpha);
    const btn_a: u32 = @intFromFloat(@as(f32, 0x1C) * gs.hover_alpha);
    var hd: raster_core.DrawList = .{};
    defer hd.deinit(gpa);
    // Card wash is rounded to match the cards; the sub-control highlight is the
    // feed's pill. Both translucent white on top — a lift, not a veil.
    if (sock_wash) |r| hd.append(gpa, .{ .rect = .{ .x = r.x, .y = r.y, .w = r.w, .h = r.h, .color = (wash_a << 24) | 0x00FFFFFF, .radius = 10 } }) catch {};
    if (sock_button) |r| hd.append(gpa, .{ .rect = .{ .x = @intCast(@as(i32, r.x) - 4), .y = r.y, .w = r.w + 8, .h = r.h, .color = (btn_a << 24) | 0x00FFFFFF, .radius = 12 } }) catch {};
    if (tag_ul) |r| {
        const ul_a: u32 = @intFromFloat(@as(f32, 0xFF) * gs.hover_alpha);
        const uy: i32 = @as(i32, r.y) + @as(i32, r.h) - 1;
        hd.append(gpa, .{ .rect = .{ .x = r.x, .y = @intCast(uy), .w = r.w, .h = 2, .color = (ul_a << 24) | 0x004DA3FF, .radius = 0 } }) catch {}; // 0x4DA3FF = feed_view tag_blue
    }
    if (hd.len == 0) return;
    gpu.feedBuild(&gs.hover, gpa, g.engine, hd.slice(), scale) catch return;
    gpu.feedDraw(&gs.hover, vw, vh);
}

/// Draw the engagement heart for EVERY visible like button as an SDF heart, at
/// the heart's real place in the feed — the like region's LEFT edge (the region
/// also spans the count, so its CENTRE sits too far right; that mismatch was the
/// "offset overlay" bug). `fill` is the post's liked state; if a like effect is
/// live for that post it ANIMATES (bottom-up fill + scale pop + star burst) from
/// the pure, tested `effect.heartVisual`. This is the ONE heart on the GPU path
/// (feed_view skips its own), so the fill happens IN PLACE. No allocation.
/// The SDF-icon pass: crisp engagement / nav icons drawn in place (feed_view
/// skips the line-art for these on the GPU path). Prototype set — the repost
/// (per .repost region, green when the viewer reposted) and the gear (the
/// Settings rail slot). Positions mirror feed_view's icon offsets; the full
/// rollout will have feed_view emit exact placements.
fn drawSdfIcons(g: Grid, gs: *GpuState, items: []const feed_core.TimelineItem, vw: i32, vh: i32) void {
    // The cartridge detail sheet is modal chrome drawn after every buffer but
    // BEFORE this pass — with it open, any icon would paint over its scrim/panel
    // (the on-device bleed, 2026-07-09). It needs no icons of its own: skip all.
    if (g.cart_detail != null) return;
    const scale = gs.scale;
    // The phone drawer is OPAQUE chrome, but this pass paints after every
    // buffer — while it's open, only ITS rows get icons (they're the only
    // wide .nav regions; everything else would bleed through the panel).
    const drawer_open = gs.drawer_t > 0.5;
    const header_bottom: i32 = if (g.screen.* == feed_view.screen_home)
        feed_view.homeSocketBottom(g.socket_tray, g.socket_ui)
    else if (g.screen.* == feed_view.screen_zones)
        // The zone masthead COLLAPSES with scroll — clip to its CURRENT
        // height or icons vanish behind where the tall band used to be.
        feed_view.zoneSocketBottom(g.socket_tray, g.socket_ui, g.scroll.*, feed_view.paneGeomFor(@intCast(gs.design_w), feed_view.screen_zones).wide)
    else
        feed_view.headerBottom(g.screen.*);
    const grey: u32 = 0xFFB4B1A8; // feed_view.icon_grey (soft white)
    const muted: u32 = 0xFF9A968A; // feed_view.muted (inactive nav)
    const green: u32 = 0xFF8FD18F; // feed_view.boost_c (reposted)
    const eng: f32 = 9.5 * scale; // engagement icon half-extent
    const nav: f32 = 11.0 * scale; // rail icon half-extent (line-art was 22 box)
    // Engagement icons scroll under the sticky header (shifted by the safe-area
    // top inset on mobile) AND under the bottom tab bar — clip both bands. The
    // nav tab icons live IN the bar and never call clipped(), so they stay.
    const hb_eff = header_bottom + gs.inset_top_l;
    const is_phone = gs.design_w <= feed_view.phone_max;
    const logical_h: i32 = @intFromFloat(@as(f32, @floatFromInt(vh)) / scale);
    const bottom_clip: i32 = if (is_phone) logical_h - feed_view.tab_bar_h - gs.inset_bottom_l else std.math.maxInt(i32);
    // The Zat4 keyboard is opaque bottom chrome drawn AFTER the bars — any
    // icon whose centre lands under it would bleed through onto the keys
    // (the on-device space-bar bleed, 2026-07-10). The cartridge-sheet rule
    // at panel scale: skip them, tab-bar nav icons included.
    const kbd_top: i32 = if (g.kbd_visible) logical_h - feed_view.keyboard_h - gs.inset_bottom_l else std.math.maxInt(i32);
    const clipped = struct {
        fn f(r: feed_view.Region, top: i32, bot: i32) bool {
            const c = @as(i32, r.y) + @divTrunc(@as(i32, r.h), 2);
            return c < top or c > bot;
        }
    }.f;
    // The compose FAB floats ABOVE the tab bar, so bottom_clip doesn't catch a
    // post's rightmost engagement icons as they scroll behind it — skip any icon
    // whose LOGICAL centre lands in the FAB box (phone only; the FAB is phone-only).
    const fab = feed_view.composeFabBox(@intCast(gs.design_w), logical_h, gs.inset_bottom_l);
    const inFab = struct {
        fn f(b: @TypeOf(fab), on: bool, px: i32, py: i32) bool {
            return on and px >= b.x0 and px <= b.x1 and py >= b.y0 and py <= b.y1;
        }
    }.f;
    for (g.regions.items) |r| {
        if (drawer_open and !(r.kind == .nav and r.w > 100)) continue;
        const cy = (@as(f32, @floatFromInt(r.y)) + @as(f32, @floatFromInt(r.h)) * 0.5) * scale;
        const cyl = @as(i32, r.y) + @divTrunc(@as(i32, r.h), 2); // logical centre y
        if (cyl >= kbd_top) continue; // under the Zat4 keyboard panel
        switch (r.kind) {
            // LEFT engagement group — the icon sits at region.x + is/2 (8.5).
            .reply => {
                if (clipped(r, hb_eff, bottom_clip)) continue;
                if (inFab(fab, is_phone, @as(i32, r.x) + 8, cyl)) continue;
                gpu.drawIcon(&gs.icon, gpu.icon_reply, (@as(f32, @floatFromInt(r.x)) + 8.5) * scale, cy, eng, grey, vw, vh);
            },
            .repost => {
                if (clipped(r, hb_eff, bottom_clip) or r.post >= items.len) continue;
                if (inFab(fab, is_phone, @as(i32, r.x) + 8, cyl)) continue;
                const col = if (items[r.post].item_flags.viewer_reposted) green else grey;
                gpu.drawIcon(&gs.icon, gpu.icon_repost, (@as(f32, @floatFromInt(r.x)) + 8.5) * scale, cy, eng, col, vw, vh);
            },
            // RIGHT engagement group — the icon centres in its (narrower) region.
            .bookmark, .share, .more => {
                if (clipped(r, hb_eff, bottom_clip)) continue;
                if (inFab(fab, is_phone, @as(i32, r.x) + @divTrunc(@as(i32, r.w), 2), cyl)) continue;
                const cx = (@as(f32, @floatFromInt(r.x)) + @as(f32, @floatFromInt(r.w)) * 0.5) * scale;
                const id: i32 = switch (r.kind) {
                    .bookmark => gpu.icon_bookmark,
                    .share => gpu.icon_share,
                    else => gpu.icon_more,
                };
                gpu.drawIcon(&gs.icon, id, cx, cy, eng, grey, vw, vh);
            },
            // The nav rail (mirrors drawRail's icon at region.x+10, size 22 →
            // centre +21 / +19). Drawn on EVERY screen incl. the loadout page, so
            // the Algorithms tab gets the same crisp SDF icons as the rest (it used
            // to be excluded here + line-art in layoutLoadout — which looked worse).
            .nav => {
                const id: i32 = switch (r.post) {
                    0 => gpu.icon_home,
                    1 => gpu.icon_hash, // Zones
                    2 => gpu.icon_heart, // Activity
                    3 => gpu.icon_reply, // Messages
                    4 => gpu.icon_sliders, // Algorithms
                    5 => gpu.icon_gear, // Settings
                    else => continue, // the "you" card (post 7) is an avatar, not an icon
                };
                // The phone TAB BAR emits full-slot nav regions (drawTabBar —
                // bar-top to screen-bottom, ≥76 tall): its 28px icon centres at
                // (r.x + r.w/2, r.y + 36). The rail/drawer keep the 42px region
                // with the 22px icon centred at (r.x+21, r.y+19).
                const tabbar = r.h >= 50;
                const half: f32 = if (tabbar) 14.0 * scale else nav;
                const cx = if (tabbar)
                    (@as(f32, @floatFromInt(r.x)) + @as(f32, @floatFromInt(r.w)) * 0.5) * scale
                else
                    (@as(f32, @floatFromInt(r.x)) + 21.0) * scale;
                const ncy = (@as(f32, @floatFromInt(r.y)) + if (tabbar) @as(f32, 36.0) else @as(f32, 19.0)) * scale;
                const col: u32 = if (@as(u16, g.screen.*) == r.post) g.accent else muted;
                gpu.drawIcon(&gs.icon, id, cx, ncy, half, col, vw, vh);
            },
            else => {},
        }
    }
}

/// The Julia toggle-ON spark: a ring of SDF hearts flying out of the switch,
/// drawn over everything so it can't hide behind a panel. Procedural (no
/// per-heart storage) — positions derive from the burst clock + index; each
/// heart flies outward, arcs up a touch, and shrinks as it fades. ~14 hearts for
/// ~0.5s, one draw call each — negligible. Decrements the clock each frame.
fn drawJuliaBurst(gs: *GpuState, vw: i32, vh: i32) void {
    if (gs.julia_burst_t <= 0) return;
    const t = gs.julia_burst_t; // 1 → 0
    const prog = 1.0 - t; // 0 → 1
    const n: u32 = 10;
    const maxdist: f32 = 150.0 * gs.scale;
    var i: u32 = 0;
    while (i < n) : (i += 1) {
        const ang = @as(f32, @floatFromInt(i)) * (6.2831853 / @as(f32, @floatFromInt(n))) + 0.3;
        const dist = prog * maxdist;
        const px = gs.julia_burst_x + @cos(ang) * dist;
        const py = gs.julia_burst_y + @sin(ang) * dist - prog * prog * 50.0 * gs.scale; // arc up
        const size = (9.0 + 7.0 * t) * gs.scale; // shrink as they fade
        // Each heart's SDF runs over a full-screen triangle — without a scissor,
        // N hearts = N full-screen fragment passes (the lag spike). Clip each to
        // its own small box so it only shades ~(box²) px. GL origin is bottom-left.
        const box = size * 3.0;
        gpu.pushScissor(@intFromFloat(px - box), @intFromFloat(@as(f32, @floatFromInt(vh)) - py - box), @intFromFloat(box * 2.0), @intFromFloat(box * 2.0));
        gpu.drawHeart(&gs.heart, px, py, size, 1.0, 1.0 + 0.4 * t, t, 0.0, vw, vh);
    }
    gpu.popScissor();
    gs.julia_burst_t = @max(0.0, t - 0.03); // ~33 frames ≈ 0.55s
}

fn drawEngagementHearts(g: Grid, gs: *GpuState, items: []const feed_core.TimelineItem, vw: i32, vh: i32) void {
    if (gs.drawer_t > 0.5) return; // the drawer is opaque chrome; hearts are content
    if (g.cart_detail != null) return; // the detail sheet is modal chrome — same rule
    const scale = gs.scale;
    const s = g.active.slice();
    const recipes = s.items(.recipe);
    const axs = s.items(.x);
    const ays = s.items(.y);
    const stages = s.items(.stage);
    const stage_ts = s.items(.stage_t);
    // The sticky header occludes the post text (it's painted over it in the feed
    // draw list), but the heart is a SEPARATE pass on top — so it would bleed
    // over the frosted header as a post scrolls up. Clip it: skip any heart whose
    // row has crossed under the header band. feed_view owns the exact height so
    // this can't drift from it (the profile-tabs growth broke the old hardcode).
    // On Home, the OPEN lens-socket tray drops over the posts; clip hearts to
    // its bottom too, or they bleed over it (the socket only draws once, on
    // top, but the heart pass is separate).
    const header_bottom: i32 = if (g.screen.* == feed_view.screen_home)
        feed_view.homeSocketBottom(g.socket_tray, g.socket_ui)
    else if (g.screen.* == feed_view.screen_zones)
        // The zone masthead collapses with scroll — clip to its CURRENT height.
        feed_view.zoneSocketBottom(g.socket_tray, g.socket_ui, g.scroll.*, feed_view.paneGeomFor(@intCast(gs.design_w), feed_view.screen_zones).wide)
    else
        feed_view.headerBottom(g.screen.*);
    // The header (and the post regions) are shifted DOWN by the safe-area top
    // inset on mobile, so the clip band shifts with them. And the bottom tab bar
    // now occludes too — clip engagement hearts that scroll under it (the nav
    // icons live IN the bar and are a separate pass, unaffected).
    const hb_eff = header_bottom + gs.inset_top_l;
    const is_phone = gs.design_w <= feed_view.phone_max;
    const logical_h: i32 = @intFromFloat(@as(f32, @floatFromInt(vh)) / scale);
    const bottom_clip: i32 = if (is_phone) logical_h - feed_view.tab_bar_h - gs.inset_bottom_l else std.math.maxInt(i32);
    // Skip a heart that scrolls behind the floating compose FAB (above the bar,
    // so bottom_clip misses it). Phone only. Same box source as drawSdfIcons.
    const fab = feed_view.composeFabBox(@intCast(gs.design_w), logical_h, gs.inset_bottom_l);
    // And the Zat4 keyboard band — the same bleed rule as drawSdfIcons.
    const kbd_top: i32 = if (g.kbd_visible) logical_h - feed_view.keyboard_h - gs.inset_bottom_l else std.math.maxInt(i32);
    for (g.regions.items) |r| {
        if (r.kind != .like or r.post >= items.len) continue;
        const row_c = @as(i32, r.y) + @divTrunc(@as(i32, r.h), 2);
        if (row_c < hb_eff or row_c > bottom_clip or row_c >= kbd_top) continue;
        const heart_cx = @as(i32, r.x) + 8; // logical heart centre
        if (is_phone and heart_cx >= fab.x0 and heart_cx <= fab.x1 and row_c >= fab.y0 and row_c <= fab.y1) continue;
        const liked = items[r.post].item_flags.viewer_liked;
        // Heart centre: the region starts at the heart's left edge; the icon box
        // is 16 logical wide, so the heart centres 8 in. Vertical centre of the
        // region row. [TUNE] 8 = is/2; size 9 = half the icon box.
        const cx: f32 = (@as(f32, @floatFromInt(r.x)) + 8.5) * scale; // icon box is 17 wide
        const cy: f32 = (@as(f32, @floatFromInt(r.y)) + @as(f32, @floatFromInt(r.h)) * 0.5) * scale;
        const size: f32 = 11.0 * scale; // was 9 — the heart read small next to the line icons
        // Static fill from the liked state; overridden by the live animation if
        // a like effect for this post is playing (matched by its heart cell).
        var vis = effect_core.HeartVisual{ .fill = if (liked) 1.0 else 0.0, .scale = 1.0, .glow = 0.0, .burst = 0.0 };
        if (heartFieldCell(g, gs, r.post)) |cell| {
            const hx: u16 = @intCast(@min(cell.x, std.math.maxInt(u16)));
            const hy: u16 = @intCast(@min(cell.y, std.math.maxInt(u16)));
            var i: usize = 0;
            while (i < g.active.len) : (i += 1) {
                if (recipes[i] != &effect_core.like_heart and recipes[i] != &effect_core.unlike_heart) continue;
                if (axs[i] == hx and ays[i] == hy) {
                    vis = effect_core.heartVisual(recipes[i], stages[i], stage_ts[i]);
                    break;
                }
            }
        }
        gpu.drawHeart(&gs.heart, cx, cy, size, vis.fill, vis.scale, vis.glow, vis.burst, vw, vh);
    }
}

/// Fire the field effect for an engagement transition at the post's heart
/// cell — the ONE place an engagement maps to a recipe, derived from the
/// transition itself (liking vs unliking), not from a separate click
/// handler that could race the toggle. `now_liked` is the state AFTER the
/// toggle: true ⇒ a like burst, false ⇒ the unlike drain. The heart cell
/// is found from the frame's heart slots by the post's index. Errors are
/// swallowed: a missed effect must never break the action (E4).
fn fireEngageEffect(gpa: Allocator, g: Grid, kind: Engagement, target: u32, now_liked: bool) void {
    // GPU path: the living field IS the effect. Inject the like/boost burst as
    // a SPLASH (energy + red dye) into the medium at the post's heart cell;
    // the medium carries and keeps it. The software effect list is NOT advanced
    // on the GPU path, so firing it here would only accumulate — so we don't.
    // An unlike has no dye-removal in v1 (the stain persists by design).
    if (g.gpu) |gs| {
        if (heartFieldCell(g, gs, target)) |cell| {
            const hx: u16 = @intCast(@min(cell.x, std.math.maxInt(u16)));
            const hy: u16 = @intCast(@min(cell.y, std.math.maxInt(u16)));
            if (now_liked or kind == .repost) {
                // Like / boost: splash the field, and (for a like) pop the heart.
                // The RED dye is the like's alone — a repost gets only the
                // colourless ripple (no dye stain). The field ripple + dye are
                // gated by the "Ripples on like" toggle; the heart pop is not.
                if (g.ripples_on) pushLikeSplash(gpa, gs, cell.x, cell.y, now_liked and kind == .like);
                if (now_liked and kind == .like) {
                    effect_core.trigger(gpa, g.active, &effect_core.like_heart, hx, hy, 1.0) catch {};
                }
            } else if (kind == .like) {
                // Unlike: DRAIN the heart back to hollow (no field splash — the
                // dye is permanent ink in the medium by design).
                effect_core.trigger(gpa, g.active, &effect_core.unlike_heart, hx, hy, 1.0) catch {};
            }
        }
        if (debug_effects) {
            const name = switch (kind) {
                .like => if (now_liked) "like(fill)" else "unlike(drain)",
                .repost => "boost",
            };
            std.debug.print("[zat] gpu splash {s} for post {d}\n", .{ name, target });
        }
        return;
    }
    const recipe: *const effect_core.Recipe = switch (kind) {
        .like => if (now_liked) &effect_core.like_heart else &effect_core.unlike_heart,
        .repost => &effect_core.boost,
    };
    // Locate the heart cell for this post in the current frame's slots.
    const txs = g.hearts.slice().items(.target);
    const hxs = g.hearts.slice().items(.x);
    const hys = g.hearts.slice().items(.y);
    for (txs, hxs, hys) |tg, hx, hy| {
        if (tg == target) {
            effect_core.trigger(gpa, g.active, recipe, hx, hy, 1.0) catch {};
            // DIAGNOSTIC (temporary, shell-side I/O is allowed): when
            // `debug_effects` is true, every effect actually fired prints one
            // stderr line, so a single click that should fire ONE effect can
            // be checked against what really happens on the real machine —
            // there is no live GUI here to watch (G2: profile the affected
            // hardware, don't guess). A compile-time const, not a global var
            // and not a 0.16-absent getenv: zero cost when false, and it
            // obeys the project's no-globals/capability rules. One unlike
            // click should print exactly one `unlike(drain)`. Two lines — or
            // an `unlike` then a `like` — means the toggle is firing more than
            // once (a click-path bug); exactly one means the trigger is fine
            // and any visual doubling is in the renderer.
            if (debug_effects) {
                const name = switch (kind) {
                    .like => if (now_liked) "like(fill)" else "unlike(drain)",
                    .repost => "boost",
                };
                std.debug.print("[zat] fired {s} at cell ({d},{d}); active effects now = {d}\n", .{ name, hx, hy, g.active.len });
            }
            return;
        }
    }
}

/// Find the field grid cell under post `target`'s like button, for the GPU
/// burst. The feed regions are in LOGICAL pixels (the feed lays out at
/// design_w); map a region's centre through the frame's DPI scale to physical
/// pixels, then to a field cell. Returns null if the post has no like region
/// this frame (scrolled out) — the caller then fires nothing (E4).
fn heartFieldCell(g: Grid, gs: *GpuState, target: u32) ?struct { x: u32, y: u32 } {
    for (g.regions.items) |r| {
        if (r.post == target and r.kind == .like) {
            const cx_logical: f32 = @as(f32, @floatFromInt(r.x)) + @as(f32, @floatFromInt(r.w)) / 2.0;
            const cy_logical: f32 = @as(f32, @floatFromInt(r.y)) + @as(f32, @floatFromInt(r.h)) / 2.0;
            const px: f32 = cx_logical * gs.scale;
            const py: f32 = cy_logical * gs.scale;
            const gx: u32 = @intFromFloat(@max(0.0, px / @as(f32, field_cell_w)));
            const gy: u32 = @intFromFloat(@max(0.0, py / @as(f32, field_cell_h)));
            return .{ .x = gx, .y = gy };
        }
    }
    return null;
}

fn present(
    gpa: Allocator,
    out: *std.Io.Writer,
    arena: Allocator,
    prev: *tui.Surface,
    next: *const tui.Surface,
    backend: Backend,
) !void {
    switch (backend) {
        .window => |win| return window_shell.present(win, next) catch {}, // E2: a lost blit is the next frame's problem
        .mobile => return, // GPU-only: the GPU pass swapped already; no cell blit exists here
        .terminal => {},
    }
    const bytes = try tui.encodeDiff(arena, prev, next);
    if (bytes.len > 0) {
        try out.writeAll(bytes);
        try out.flush();
    }
    if (prev.width != next.width or prev.height != next.height) {
        try tui.resizeSurface(gpa, prev, next.width, next.height);
    }
    @memcpy(prev.chars.items, next.chars.items);
    @memcpy(prev.styles.items, next.styles.items);
}

const WindowSize = struct {
    // A7.2: cold struct, size guard waived — one per frame, returned by value.
    cols: u16,
    rows: u16,
};

/// Ask the kernel for the terminal size; polled each frame, which also
/// handles resize without signal machinery. Off Linux (or on failure) the
/// classic 80×24 stands in — same fallback std.Progress uses.
fn readWindowSize(fd: posix.fd_t) WindowSize {
    if (builtin.os.tag == .linux) {
        var ws: posix.winsize = undefined;
        const rc = std.os.linux.ioctl(fd, std.os.linux.T.IOCGWINSZ, @intFromPtr(&ws));
        if (posix.errno(rc) == .SUCCESS and ws.col > 0 and ws.row > 0) {
            return .{ .cols = ws.col, .rows = ws.row };
        }
    }
    return .{ .cols = 80, .rows = 24 };
}
