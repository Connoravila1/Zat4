// SPDX-License-Identifier: AGPL-3.0-or-later
//
// Zat4 — a social-media client built on the AT Protocol.
// Copyright (C) 2026  Connor Avila

//! B1 classification: SHELL. Dev entry for the "Join Zat4" flow (`zig build
//! enroll`).
//!
//! The enrollment surface, crypto, and run loop all live in
//! `shell/enroll_run.zig` — ONE implementation shared with the live app's
//! pre-auth front door (D6, no change amplification). This file is just the
//! standalone entry point so the flow can be iterated on without a session or
//! network; it opens nothing and owns nothing itself.

const std = @import("std");
const enroll_run = @import("shell/enroll_run.zig");
const auth = @import("shell/auth.zig");

pub fn main(init: std.process.Init) !void {
    // The dev harness drives the surface only; it discards any session the flow
    // returns (sign-up needs an invite + network, which the live app supplies).
    if (try enroll_run.run(init.gpa, init.io, init.environ_map)) |session| {
        auth.freeSession(init.gpa, session);
    }
}
