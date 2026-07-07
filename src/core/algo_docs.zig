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

//! B1 classification: CORE (pure data). **The algorithm documentation pages**
//! (ALGO_SUBMISSION slice 5): the in-app explainer a USER reads before trying
//! algorithms, and the writing guide a DEVELOPER reads before submitting one.
//! Every sentence lives here — one reviewable module, no prose scattered
//! through renderers. The renderer (`feed_view.layoutAlgoDocs`) draws any
//! `Doc` generically; adding a section is adding a row.
//!
//! The developer guide is the DISTILLED in-app companion of
//! `ZAL_DEVELOPER_GUIDE.md` (the full reference stays a document); the user
//! explainer states the system's promises in plain language — and only
//! promises the engine actually enforces (labels derived, source carried,
//! sandbox capability-gated). If a claim here stops being enforced, fixing
//! the ENGINE — not this text — is the move (H4 in spirit).

/// One section: a heading and its body. Rendered as a titled block; a body
/// renders as wrapped paragraphs split on blank lines. A7.2: cold — a
/// comptime catalog, never held in quantity. Waived.
pub const Section = struct {
    heading: []const u8,
    body: []const u8,
};

/// A whole page: its title, a one-line deck, and the sections.
/// A7.2: cold comptime catalog. Waived.
pub const Doc = struct {
    title: []const u8,
    deck: []const u8,
    sections: []const Section,
};

/// The USER explainer — "How algorithms work here." Plain language, no
/// jargon a reader has to already know, and nothing the engine can't prove.
pub const user_doc: Doc = .{
    .title = "How algorithms work here",
    .deck = "Your feed is yours to shape — and everything an algorithm can do is provable, never a promise.",
    .sections = &.{
        .{
            .heading = "What an algorithm is",
            .body =
            \\An algorithm decides which posts you see and in what order. On most
            \\platforms there is exactly one, it runs on someone else's servers, and
            \\nobody outside can see what it does. On Zat4 an algorithm is a small
            \\program that runs on YOUR device, you can hold several, and you choose
            \\which one drives each surface — your feed, your reply threads, your
            \\zones. Swapping one is one drag.
            ,
        },
        .{
            .heading = "What it can and cannot touch",
            .body =
            \\Every algorithm runs inside a sandbox with a short, fixed list of
            \\doors. It can read a post's public facts — likes, reposts, replies,
            \\age, zone tags. If it declares so, it can also read your attention
            \\signals (what you linger on), but those never leave your device: the
            \\sandbox has no door to the network, no door to your keys, no door to
            \\anything it didn't declare. There is a hard ceiling on how much
            \\computation it may spend per post and how much it may remember
            \\between sessions.
            \\
            \\The labels you see — "no behavioral data", "learns on-device" — are
            \\computed by the engine from the algorithm's compiled code. A creator
            \\cannot claim them; the code proves them.
            ,
        },
        .{
            .heading = "Open source, by construction",
            .body =
            \\Every published algorithm carries its own source code in the record.
            \\Open any algorithm's page and tap "Full transparency" to read exactly
            \\what it does — the code shown is the code that runs, anchored by a
            \\content hash that cannot be quietly swapped.
            ,
        },
        .{
            .heading = "Installing and equipping",
            .body =
            \\Installing an algorithm copies it into your library — your bench on
            \\the Algorithms page. From there, drag it onto a socket (Feed, Replies,
            \\or Zones) to put it in charge of that surface; drag it back out to the
            \\library to remove it. A socket holds up to six; the seated one does
            \\the ranking.
            ,
        },
        .{
            .heading = "Designed-for, and the heads-up",
            .body =
            \\Creators declare which surfaces they built an algorithm for. You can
            \\socket anything anywhere — the declaration never blocks you — but if
            \\you socket one somewhere its creator didn't design for, you get a
            \\one-time heads-up first. It protects your expectations and the
            \\creator's reputation at the same time.
            ,
        },
        .{
            .heading = "Making your own",
            .body =
            \\The Create tab has two doors: a five-minute guided builder that asks a
            \\few plain questions and produces a private feed just for you, and a
            \\real code path where you write an algorithm in Zal and publish it to
            \\the marketplace for everyone. Both produce the same kind of algorithm,
            \\ranked by the same engine — there is no privileged path, not even for
            \\the ones Zat4 ships with.
            ,
        },
    },
};

/// The DEVELOPER guide — "Write an algorithm." The distilled in-app companion
/// of ZAL_DEVELOPER_GUIDE.md: enough to write, check, and publish a real one
/// from a standing start.
pub const dev_doc: Doc = .{
    .title = "Write an algorithm",
    .deck = "Real code, checked by a fail-closed gate, published open — the whole pipeline in one page.",
    .sections = &.{
        .{
            .heading = "The shape of a feed",
            .body =
            \\A feed runs in three stages, each an optional function in your Zal
            \\source: retrieve() composes the candidate POOL (which posts even
            \\enter), score() ranks each candidate, and arrange() reorders the
            \\scored pool as a whole. Omit retrieve() and the standard pool is
            \\used; omit arrange() and the score order stands. score() is the one
            \\required function. This is where the fundamentals live: a timeline,
            \\a search index, and a storefront differ in retrieve() and arrange(),
            \\not in their weights — see the Search Tiers and Catalog templates.
            ,
        },
        .{
            .heading = "The facts score() can read",
            .body =
            \\Per candidate: like_count, repost_count, reply_count, age_hrs,
            \\author_rep (a public reputation prior in 0..1), in_network (whether
            \\you follow the author), tag_count, reply_chain, viewer_engaged, and
            \\base_score. There is deliberately no author identity, no post text,
            \\and no other user's data — an algorithm ranks on public shape, not
            \\on who somebody is.
            ,
        },
        .{
            .heading = "Capabilities — the declared doors",
            .body =
            \\In retrieve(): follows(w), discovery(w), trending(threshold, w), and
            \\tag_scope("zone", w) each add a source to the pool query. In score():
            \\attention_dwell() and attention_clicked() read the reader's on-device
            \\attention (this marks your algorithm as behavioral — derived from the
            \\bytecode, not from anything you claim); has_tag("zone") reads public
            \\zone membership; state_read()/state_write() keep a small on-device
            \\model between sessions. In arrange(): pool_len(), pool_read(i, fact),
            \\and emit(i) walk and reorder the visible pool. Each capability
            \\belongs to its stage — the entry wall refuses a source call inside
            \\score() and an attention call inside retrieve(), at compile time, at
            \\publish time, and at load time.
            ,
        },
        .{
            .heading = "The language, in one breath",
            .body =
            \\Zal is small and C-like: fn, var, while, if, numbers (one type:
            \\num), booleans, and the operators you expect. No strings beyond tag
            \\literals, no arrays, no recursion, no imports. Every program is
            \\fuel-metered — a per-candidate instruction budget the gate proves
            \\you fit inside — so an infinite loop is a compile-shaped problem,
            \\never a reader's frozen feed.
            ,
        },
        .{
            .heading = "Check, then publish",
            .body =
            \\Check compiles your source and runs the same fail-closed publish
            \\gate the network enforces: malformed programs, wrong-stage
            \\capability calls, over-budget fuel or state, and load-instability
            \\are each refused BY NAME while you can still fix them. Publishing
            \\writes a signed record to your own repo carrying your name for it,
            \\your description, your declared surfaces, your tags — and your
            \\SOURCE. Every marketplace algorithm is open by construction; the
            \\engine still trusts only the compiled form it re-proves itself.
            ,
        },
        .{
            .heading = "What users will see",
            .body =
            \\Your words (name, one-liner, description) render beside what the
            \\code PROVES (behavioral or not, state kept, pool composed, compute
            \\ceiling, size). The two never mix: you cannot claim what the code
            \\doesn't show, and nothing the code shows can be hidden. Ratings
            \\come from readers; the designed-for declaration steers them to the
            \\surfaces you built for. Deleting a published algorithm from your
            \\dashboard retracts the record; installed copies keep working.
            ,
        },
    },
};

// ---------------------------------------------------------------------------
// Tests — the catalog stays renderable (no empty sections, sane lengths).
// ---------------------------------------------------------------------------

const std = @import("std");
const t = std.testing;

test "docs: every section has a heading and a body, and bodies fit the wrap budget" {
    for ([_]Doc{ user_doc, dev_doc }) |doc| {
        try t.expect(doc.title.len > 0);
        try t.expect(doc.sections.len >= 4);
        for (doc.sections) |sec| {
            try t.expect(sec.heading.len > 0);
            try t.expect(sec.body.len > 40);
            try t.expect(sec.body.len < 4096);
        }
    }
}
