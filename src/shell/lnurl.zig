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

//! B1 classification: SHELL (network + JSON of network responses). LNURL-pay
//! (LUD-06 + LUD-16): turn a recipient's Lightning ADDRESS into a BOLT11
//! invoice for an EXACT amount, so the wallet hand-off carries a locked amount
//! the payer cannot change. This is the honesty fix for "the number both
//! parties see must equal what is actually sent": on-chain already carries its
//! amount in the URI, but a bare `lightning:<address>` does not — the payer's
//! wallet prompts for the amount, unenforced. Resolving an invoice for the
//! card's amount closes that gap.
//!
//! Two fetches to the recipient's OWN LN provider — a host derived from a
//! network value (the address, and then the provider's callback URL), so both
//! go out `.untrusted`: the SSRF guard refuses a Lightning address pointed at
//! a private/loopback host (`connoravila@127.0.0.1` must not reach an internal
//! service). The BOLT11 is re-gated in `core/payuri` before it is ever spliced
//! into a URI. F1: no dependency — `std.json` + the house `http` client.

const std = @import("std");
const Allocator = std.mem.Allocator;

const http = @import("http.zig");
const wallet_caps = @import("../core/wallet_caps.zig");

/// The LN provider's replies are small JSON documents; a tight ceiling keeps a
/// hostile or broken provider from ballooning memory (E2 at the process edge).
const max_lnurl_bytes: usize = 16 * 1024;

/// LUD-06 payRequest parameters (only the fields we consume; the rest are
/// ignored). Millisatoshis for the sendable bounds, per the spec.
/// A7.2: cold struct, size guard waived — one per resolve, never held.
const PayParams = struct {
    callback: []const u8 = "",
    minSendable: u64 = 0,
    maxSendable: u64 = 0,
    tag: []const u8 = "",
};

/// LUD-06 callback response: `pr` is the BOLT11 invoice.
/// A7.2: cold struct, size guard waived — one per resolve.
const InvoiceResponse = struct {
    pr: []const u8 = "",
};

pub const Error = error{
    /// The address is not `local@domain`.
    BadAddress,
    /// The provider didn't answer, or answered non-2xx / unparseable.
    ProviderDown,
    /// The well-known document is not a payRequest endpoint.
    NotPayEndpoint,
    /// The card amount is below minSendable or above maxSendable.
    AmountOutOfRange,
    /// The callback returned no usable invoice.
    NoInvoice,
    OutOfMemory,
};

/// Resolve `lnaddr` (a LUD-16 `local@domain`, already format-validated by the
/// caller's address gate) to a BOLT11 invoice for exactly `amount_sat`. The
/// returned invoice is arena-owned. Every failure is an explicit, honest error
/// the caller turns into a user-facing line (E3) — never a silent fallback to
/// an amount-less hand-off, which would reopen the very gap this closes.
pub fn resolveInvoice(
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    lnaddr: []const u8,
    amount_sat: u64,
) Error![]const u8 {
    const at = std.mem.indexOfScalar(u8, lnaddr, '@') orelse return error.BadAddress;
    const user = lnaddr[0..at];
    const domain = lnaddr[at + 1 ..];
    if (user.len == 0 or domain.len == 0) return error.BadAddress;
    // Defensively reject a domain that itself carries a slash or scheme — the
    // address gate already forbids it, but this string is about to become a URL.
    for (domain) |c| if (c == '/' or c == ':' or c == '?' or c == '#' or c == '@') return error.BadAddress;

    // LUD-16: local@domain → https://domain/.well-known/lnurlp/local
    var url_buf: [512]u8 = undefined;
    const well_known = std.fmt.bufPrint(&url_buf, "https://{s}/.well-known/lnurlp/{s}", .{ domain, user }) catch
        return error.BadAddress;
    const params = try fetchJson(PayParams, arena, io, environ, well_known);
    if (!std.mem.eql(u8, params.tag, "payRequest") or params.callback.len == 0)
        return error.NotPayEndpoint;

    const msat: u64 = amount_sat *| 1000; // saturating: never wraps into range
    if (msat < params.minSendable or msat > params.maxSendable) return error.AmountOutOfRange;

    // The callback is the provider's own URL and may already carry a query.
    const sep: u8 = if (std.mem.indexOfScalar(u8, params.callback, '?') != null) '&' else '?';
    var cb_buf: [2048]u8 = undefined;
    const cb_url = std.fmt.bufPrint(&cb_buf, "{s}{c}amount={d}", .{ params.callback, sep, msat }) catch
        return error.ProviderDown; // an absurdly long callback: treat as unusable
    const inv = try fetchJson(InvoiceResponse, arena, io, environ, cb_url);
    if (inv.pr.len == 0) return error.NoInvoice;
    // The caller (`payuri.buildLightningInvoiceUri`) re-gates the charset and
    // the mainnet prefix before the invoice touches a URI — here we only need
    // an owned copy that outlives the parse arena's inner frees.
    return arena.dupe(u8, inv.pr) catch return error.OutOfMemory;
}

/// Build the LUD-16 well-known URL for `lnaddr`. Shared by the invoice leg and
/// the capability probe, so the two can never disagree about where a wallet
/// lives. `buf` must outlive the returned slice.
fn wellKnownUrl(buf: []u8, lnaddr: []const u8) Error![]const u8 {
    const at = std.mem.indexOfScalar(u8, lnaddr, '@') orelse return error.BadAddress;
    const user = lnaddr[0..at];
    const domain = lnaddr[at + 1 ..];
    if (user.len == 0 or domain.len == 0) return error.BadAddress;
    // This string is about to become a URL; the address gate already forbids
    // these, but never trust that twice.
    for (domain) |c| if (c == '/' or c == ':' or c == '?' or c == '#' or c == '@') return error.BadAddress;
    return std.fmt.bufPrint(buf, "https://{s}/.well-known/lnurlp/{s}", .{ domain, user }) catch
        error.BadAddress;
}

/// ASK THE WALLET WHAT IT CAN DO — the probe behind the capability table.
///
/// Zat4 keeps wallets open: any provider, no allow-list, no blessed few. The
/// price of that openness is that the app's behaviour quietly changes with a
/// choice the user made once and forgot. So instead of guessing, we interrogate
/// the provider at the moment its address is added, and hand the answer back as
/// plain facts the user signs off on.
///
/// Two legs, both `.untrusted` (the host came from a user-typed value):
///   1. the well-known payRequest document → can it receive, what limits, notes?
///   2. its invoice callback at the MINIMUM amount → does it return a LUD-21
///      `verify` URL, i.e. can a payment to it be observed settling?
///
/// Leg 2 mints an invoice that is never paid. That is harmless and normal — an
/// unpaid Lightning invoice simply expires — and it is the only way to learn
/// whether `verify` is offered, because `verify` rides with the invoice and not
/// with the parameters.
///
/// `error.NotPayEndpoint` here is the case that matters most: a well-formed
/// address that belongs to nobody (`connor@strike.me`). It is returned as an
/// ERROR inside an HTTP **200**, which is why the shape check we used to do was
/// worthless.
pub fn probe(
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    lnaddr: []const u8,
) Error!wallet_caps.Caps {
    var url_buf: [512]u8 = undefined;
    const well_known = try wellKnownUrl(&url_buf, lnaddr);

    const params_body = try fetchBody(arena, io, environ, well_known);
    var callback: []const u8 = "";
    var caps = wallet_caps.readPayDoc(arena, params_body, &callback) catch |err| return switch (err) {
        error.CannotReceive => error.NotPayEndpoint, // "this address can't be paid"
        error.NotPayEndpoint => error.NotPayEndpoint,
        error.Malformed => error.ProviderDown,
        error.OutOfMemory => error.OutOfMemory,
    };

    // Leg 2: the smallest invoice the provider will mint, purely to read the
    // envelope it comes in. If this leg fails we do NOT fail the probe — the
    // address demonstrably resolves and can receive, which is the part that
    // gates publishing. We simply cannot claim auto-confirmation, and the
    // capability table says so rather than pretending.
    const msat: u64 = caps.min_sat *| 1000;
    const sep: u8 = if (std.mem.indexOfScalar(u8, callback, '?') != null) '&' else '?';
    var cb_buf: [2048]u8 = undefined;
    const cb_url = std.fmt.bufPrint(&cb_buf, "{s}{c}amount={d}", .{ callback, sep, msat }) catch return caps;
    const inv_body = fetchBody(arena, io, environ, cb_url) catch return caps;
    wallet_caps.readInvoice(arena, inv_body, &caps) catch return caps;
    return caps;
}

/// One guarded GET returning the raw body — the capability probe parses it with
/// the pure core rather than through a typed fetch, because the ERROR case is
/// carried in the body and must be READ, not inferred from the status.
fn fetchBody(
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    url: []const u8,
) Error![]const u8 {
    const resp = http.request(arena, io, environ, url, .{
        .guard = .untrusted,
        .max_response_bytes = max_lnurl_bytes,
    }) catch return error.ProviderDown;
    // NOTE the asymmetry with `fetchJson` below: we accept a 200 here and let the
    // core decide, because a refusal IS a 200 with the error in the body.
    if (resp.status != 200) return error.ProviderDown;
    return resp.body;
}

/// One guarded GET + leaky JSON parse into `T`. `.untrusted` so the SSRF guard
/// applies (the host came from a network value). A non-2xx or unparseable body
/// is `ProviderDown` — an ordinary, contained failure (E4).
fn fetchJson(
    comptime T: type,
    arena: Allocator,
    io: std.Io,
    environ: ?*const std.process.Environ.Map,
    url: []const u8,
) Error!T {
    const resp = http.request(arena, io, environ, url, .{
        .guard = .untrusted,
        .max_response_bytes = max_lnurl_bytes,
    }) catch return error.ProviderDown;
    if (resp.status != 200) return error.ProviderDown;
    return std.json.parseFromSliceLeaky(T, arena, resp.body, .{ .ignore_unknown_fields = true }) catch
        error.ProviderDown;
}

test {
    // Pure decisions only — the two-fetch leg is typed through the exe build
    // and live-proven by the `--pay-invoice` harness (main.zig), the same
    // posture as chainwatch's network legs.
    std.testing.refAllDecls(@This());
}
