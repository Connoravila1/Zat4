//! Rover · composition proof — the spine, exercised together on a real screen.
//!
//! This is NOT a Rover module (it imports several siblings); it is the host-side
//! INTEGRATION test that proves the primitives compose. It builds a realistic post
//! card entirely out of `layout` + `tokens` + `typeset` + `input` — no hand-computed
//! pixel offsets — and asserts the composed geometry is correct and that the buttons
//! it laid out hit-test back to the right controls. It is the API/geometry half of
//! the spine proof; the pixel half is judged live in the app.
//!
//! Text sizes here are plain numbers standing in for what the host's font engine
//! would measure — the point is the composition, not the glyphs.

const std = @import("std");
const layout = @import("layout.zig");
const input = @import("input.zig");
const tokens = @import("tokens.zig");
const typeset = @import("typeset.zig");

const expect = std.testing.expect;
fn approx(a: f32, b: f32) bool {
    return @abs(a - b) < 0.01;
}

test "compose: a post card lays out from primitives with no pixel math" {
    var t = layout.Tree.init(std.testing.allocator);
    defer t.deinit();

    // Design constants come from tokens, not magic numbers.
    const card_w: f32 = 400;
    const pad = @as(f32, @floatFromInt(tokens.space(.lg))); // 16
    const gap = @as(f32, @floatFromInt(tokens.space(.md))); // 12

    // Card: a hugging column, padded, children stretched to its width.
    const card = try t.add(.{
        .axis = .col,
        .cross = .stretch,
        .w_fit = .fixed,
        .h_fit = .hug,
        .w = card_w,
        .gap = gap,
        .pad_l = pad,
        .pad_t = pad,
        .pad_r = pad,
        .pad_b = pad,
    });

    // Header row: avatar | (name / handle) that grows | timestamp.
    const header = try t.add(.{ .axis = .row, .cross = .center, .h_fit = .hug, .gap = gap });
    const avatar = try t.add(.{ .w_fit = .fixed, .h_fit = .fixed, .w = 40, .h = 40 });
    const namecol = try t.add(.{ .axis = .col, .w_fit = .grow, .h_fit = .hug, .gap = 2 });
    const name = try t.add(.{ .w_fit = .fixed, .h_fit = .fixed, .w = 120, .h = 18 }); // "measured" name
    const handle = try t.add(.{ .w_fit = .fixed, .h_fit = .fixed, .w = 90, .h = 14 });
    const time = try t.add(.{ .w_fit = .fixed, .h_fit = .fixed, .w = 40, .h = 14 });
    t.child(card, header);
    t.child(header, avatar);
    t.child(header, namecol);
    t.child(namecol, name);
    t.child(namecol, handle);
    t.child(header, time);

    // Body: full-width text block of a known wrapped height.
    const body = try t.add(.{ .w_fit = .grow, .h_fit = .fixed, .h = 60 });
    t.child(card, body);

    // Actions row: three buttons spread across the width. Each button HUGS its
    // label + padding (intrinsic sizing) — the thing you cannot do with fixed px.
    const actions = try t.add(.{ .axis = .row, .justify = .between, .h_fit = .hug });
    t.child(card, actions);
    const btn_ids = [_]input.Id{ 101, 102, 103 };
    var btns: [3]layout.Node = undefined;
    for (0..3) |i| {
        const btn = try t.add(.{ .axis = .row, .cross = .center, .pad_l = 12, .pad_r = 12, .pad_t = 6, .pad_b = 6 });
        const label = try t.add(.{ .w_fit = .fixed, .h_fit = .fixed, .w = 40, .h = 16 }); // "measured" label
        t.child(btn, label);
        t.child(actions, btn);
        btns[i] = btn;
    }

    t.solve(card, 1000, 1000);

    // --- assert the COMPOSED geometry (all derived, none hand-placed) ---

    const cr = t.rectOf(card);
    // Card hugged its content height: pad + header(40) + gap + body(60) + gap + button(28) + pad.
    try expect(approx(cr.w, 400));
    try expect(approx(cr.h, pad + 40 + gap + 60 + gap + 28 + pad)); // 184

    // Header: avatar pinned top-left inside the padding; the name column grew and
    // pushed the timestamp flush to the right content edge.
    try expect(approx(t.rectOf(avatar).x, 16) and approx(t.rectOf(avatar).y, 16));
    const tr = t.rectOf(time);
    try expect(approx(tr.x + tr.w, card_w - pad)); // 384 — right content edge
    try expect(approx(t.rectOf(namecol).w, 264)); // 368 content - 40 - 40 - 2*gap

    // Body spans the full content width just below the header.
    const br = t.rectOf(body);
    try expect(approx(br.w, card_w - 2 * pad)); // 368
    try expect(approx(br.y, pad + 40 + gap)); // 68

    // Buttons: intrinsic sizing gave each label(40) + horizontal pad(24) = 64 wide,
    // label(16) + vertical pad(12) = 28 tall; justify-between pinned the ends.
    const b0 = t.rectOf(btns[0]);
    const b2 = t.rectOf(btns[2]);
    try expect(approx(b0.w, 64) and approx(b0.h, 28));
    try expect(approx(b0.x, pad)); // first flush left
    try expect(approx(b2.x + b2.w, card_w - pad)); // last flush right

    // --- prove INPUT maps the laid-out buttons back to their controls ---
    var regions: [3]input.Region = undefined;
    for (0..3) |i| {
        const r = t.rectOf(btns[i]);
        regions[i] = .{ .id = btn_ids[i], .x = r.x, .y = r.y, .w = r.w, .h = r.h, .flags = .{ .focusable = true } };
    }
    // A press at the center of the middle button resolves to it.
    const mid = t.rectOf(btns[1]);
    try std.testing.expectEqual(btn_ids[1], input.hitTest(&regions, mid.x + mid.w / 2, mid.y + mid.h / 2));
    // A press in the card's empty header area hits no button.
    try std.testing.expectEqual(input.none, input.hitTest(&regions, 200, 20));

    // --- typeset places a label's baseline centered inside its button box ---
    const m: typeset.Metrics = .{ .ascent = 13, .descent = 3, .cap_height = 11 };
    const bl = typeset.baselineCapCentered(b0.y, b0.h, m);
    try expect(bl > b0.y and bl < b0.y + b0.h); // baseline sits inside the button
}
