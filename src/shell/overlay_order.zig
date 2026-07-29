//! Zat4 binding from live overlay flags to Rover's declared stack order.
//!
//! This module owns only Zat's layer precedence. Rover owns stack mechanics;
//! `tui` owns the effects of dismissing the returned value-level kind.

const std = @import("std");
const assert = std.debug.assert;
const overlay = @import("../ui/overlay.zig");

pub const Kind = enum(u32) {
    none = 0,
    consent,
    help,
    receive,
    settings_picker,
    money,
    pending_game,
    chat_menu,
    game,
    repost,
    detail,
    call,
    drawer,
};

/// Plain snapshot of overlay visibility. Declaration order below is the one
/// source of truth for which visible layer Back dismisses first.
pub const State = packed struct(u16) {
    consent: bool = false,
    help: bool = false,
    receive: bool = false,
    settings_picker: bool = false,
    money: bool = false,
    pending_game: bool = false,
    chat_menu: bool = false,
    game: bool = false,
    repost: bool = false,
    detail: bool = false,
    call: bool = false,
    drawer: bool = false,
    _pad: u4 = 0,

    comptime {
        // A7: rebuilt and scanned on every Back edge.
        assert(@sizeOf(State) == 2);
    }
};

pub fn top(state: State) Kind {
    var stack: overlay.Stack = .{};
    pushIf(&stack, .consent, state.consent);
    pushIf(&stack, .help, state.help);
    pushIf(&stack, .receive, state.receive);
    pushIf(&stack, .settings_picker, state.settings_picker);
    pushIf(&stack, .money, state.money);
    pushIf(&stack, .pending_game, state.pending_game);
    pushIf(&stack, .chat_menu, state.chat_menu);
    pushIf(&stack, .game, state.game);
    pushIf(&stack, .repost, state.repost);
    pushIf(&stack, .detail, state.detail);
    pushIf(&stack, .call, state.call);
    pushIf(&stack, .drawer, state.drawer);
    return @enumFromInt(overlay.activeId(&stack));
}

fn pushIf(stack: *overlay.Stack, kind: Kind, visible: bool) void {
    if (!visible) return;
    // The declaration set is statically smaller than Rover's fixed capacity.
    assert(overlay.push(stack, @intFromEnum(kind), 0, 0, 0, 0, .{ .modal = true }));
}

test "overlay order: topmost visible layer wins" {
    try std.testing.expectEqual(Kind.none, top(.{}));
    try std.testing.expectEqual(Kind.money, top(.{ .consent = true, .money = true }));
    try std.testing.expectEqual(Kind.game, top(.{ .money = true, .game = true }));
    try std.testing.expectEqual(Kind.drawer, top(.{ .game = true, .drawer = true }));
}

test "overlay order: removing top exposes exactly the next layer" {
    var state: State = .{ .help = true, .chat_menu = true, .detail = true };
    try std.testing.expectEqual(Kind.detail, top(state));
    state.detail = false;
    try std.testing.expectEqual(Kind.chat_menu, top(state));
    state.chat_menu = false;
    try std.testing.expectEqual(Kind.help, top(state));
}

test "overlay order: all declared layers fit Rover's fixed stack" {
    const state: State = .{
        .consent = true,
        .help = true,
        .receive = true,
        .settings_picker = true,
        .money = true,
        .pending_game = true,
        .chat_menu = true,
        .game = true,
        .repost = true,
        .detail = true,
        .call = true,
        .drawer = true,
    };
    try std.testing.expectEqual(Kind.drawer, top(state));
}
