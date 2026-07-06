# The Zat4 Algorithm Developer Guide

**Everything you need to write, test, and publish a feed algorithm for Zat4 —
from adjusting a few weights to shipping a real program in Zal.**

> Status legend, used throughout:
> **LIVE** — works end-to-end in the app today.
> **WIRED** — compiles and validates today; its runtime data source is still
> being connected, so calls behave as documented but return placeholder values.
> **PLANNED** — designed and deliberately deferred; the docs say so rather than
> pretend.
>
> This is the single-document edition. It is written to be split into a
> searchable site later: every `##` section stands alone.

---

## 1. What an algorithm is here

On every large social network, the feed is ordered by one algorithm the
platform owns and keeps closed. Zat4 is built the other way around: **a feed is
a scoring function over a pool of candidate posts, and an algorithm is simply
the data that function reads.** The house feed and your feed run through the
identical engine, by the identical path, with nothing marking one as
privileged.

Four properties follow, and they are the ground rules for everything you build:

1. **One engine, no special path.** Your published algorithm is evaluated
   exactly the way the default is. There is no platform-only capability, no
   hidden re-rank after yours runs (moderation and diversity passes are public,
   fixed, and documented below).
2. **Published under its own hash.** An algorithm serializes to a canonical
   record and is identified by the hash (CID) of those exact bytes. The version
   a user inspects is provably the version that runs — re-serializing a parsed
   record reproduces the same bytes.
3. **Safe by absent capability.** Your code runs on a machine that has no
   instruction for the network, the filesystem, the clock, randomness, another
   person's identity, or the user's private attention stream (unless the user
   opts in). You cannot reach those things because the reach does not exist —
   not because a reviewer checks.
4. **On the reader's device.** Scoring runs locally. Nothing about how a user
   ranks their feed leaves their machine.

Everything is ordered by the same primitive: the home feed, a topic zone's
page, replies under a post, search results. One algorithm, carried by the
user, seated onto whatever surface they view.

---

## 2. The four authoring tiers

An algorithm is one configuration record with four levels of authorship. Each
level is the same record, progressively enriched, handed to the same scorer.
Start at the lowest tier that expresses your idea — every tier above weights
costs you more to write and your readers more to audit.

| Tier | You write | Good for | Effort |
|---|---|---|---|
| **1. Weights** | Numbers (like/reply/repost weights, freshness half-life, …) | Rebalancing the default feel: calmer, fresher, more conversational | Minutes |
| **2. Rules** | A short list of `{if condition, then action}` rows | Boost/dampen/exclude by simple public conditions | Minutes |
| **3. Formula** | An arithmetic expression over the public facts | A custom scoring formula with no loops | An hour |
| **4. Developer (Zal)** | A real program: branches, loops, memory, the whole pool | New *kinds* of ranking — cross-item, staged, structural | Real work |

**LIVE** — all four tiers evaluate in the engine today. The in-app creation UI
is being built out; this guide focuses on what you author and what it means.

### Tier 1: weights

The default score is multiplicative:

```
score = max(0, Σ countₖ × wₖ + floor)      // positive engagement signals only
      × recency_decay(age, half_life)      // 0.5 ^ (age/half_life)
      × velocity_factor                    // up to 2× in the first ~30 min
      × (1 + author_rep × author_rep_weight)
      × (1 + relevance × relevance_weight)
      × (1 + behavioral × behavioral_weight)   // 0 by default: opt-in, on-device
      × negative_damping                   // blocks/mutes/reports pull toward 0
```

The weights you tune, with their defaults (calibrated to a published industry
ranker's ratios — a reply is worth far more than a like):

| Weight | Default | Signal |
|---|---|---|
| `w_like` | 1.0 | passive approval |
| `w_repost` | 2.0 | amplification |
| `w_reply` | 27.0 | conversation — the dominant public signal |
| `w_reply_chain` | 150.0 | the author replied back — strongest positive |
| `w_bookmark` | 10.0 | high-intent private save |
| `w_profile_click` | 24.0 | interest in the author |
| `w_link_click` | 22.0 | followed the content out |
| `w_negative` | 148.0 (magnitude) | blocks / mutes / reports — see below |
| `engagement_floor` | 0 | cold-start baseline so new posts can surface |
| `recency_half_life_hrs` | 6.0 | freshness half-life |
| `velocity_boost` | on | early-engagement multiplier |
| `author_rep_weight` | 0.5 | public author-reputation prior |
| `relevance_weight` | 1.0 | topic-match prior |
| `behavioral_weight` | 0.0 | on-device personalization (opt-in) |

**Negative feedback is damping, not a weight you can flip.** Blocks, mutes, and
reports multiply the score by `d = base / (base + |w_negative| × n)`, which is
always in `(0, 1]`: it can only pull a score toward zero. The sign of
`w_negative` is ignored — no published algorithm can turn safety signals into a
booster — and a mass-block brigade has diminishing effect per additional block
rather than burying a post arbitrarily deep.

### Tier 2: rules

A rule is `{predicate, action}`, applied to each candidate's score in order.
The vocabulary is fixed and public, so a shared rule list needs no interpreter:

**Predicates:** `always` · `in_network` · `out_of_network` · `min_likes(p)` ·
`min_reposts(p)` · `min_replies(p)` · `min_engagement(p)` · `newer_than_hrs(p)`
· `older_than_hrs(p)`

**Actions:** `boost(factor)` · `dampen(factor)` · `exclude`

Up to 64 rules per algorithm. A rule can exclude a candidate from your pool; it
can never resurface what moderation hides (that pass runs after you, always).

### Tier 3: formula

An arbitrary arithmetic expression over the same public facts, evaluated per
candidate with the rule-adjusted score available as `base_score`. No loops —
it is a straight-line formula, so it always terminates by construction. If you
find yourself wanting a loop or memory, you want Tier 4.

### Tier 4: the developer tier — Zal

A real language, compiled to a sandboxed virtual machine. The rest of this
guide is about this tier.

---

## 3. Quickstart: your first Zal algorithm

A feed **is** a scoring function. The smallest valid algorithm is one function:

```
fn score() num { return like_count; }
```

That is "Most Liked." Rank by conversation instead, with a freshness fade:

```
fn score() num {
  var eng = like_count + reply_count * 27.0 + repost_count * 2.0;
  eng = eng + 1.0;                          // cold-start floor
  return eng * (6.0 / (age_hrs + 6.0));     // soft ~6h decay
}
```

What happens to this text:

1. **Compile.** The Zal compiler turns it into bytecode for the guest VM. Any
   error — unknown name, wrong-side capability call, a string outside a tag
   argument — is reported with a message and the program is rejected whole.
2. **Gate.** At publish time the program passes the publish gate: structural
   validation, the capability walls, and a battery that actually runs your
   program against edge-case candidates inside your declared fuel budget. Every
   refusal is a named sentence (see §11).
3. **Publish.** The program travels inside the algorithm record, serialized to
   canonical JSON, identified by its CID. What a user inspects is what runs.
4. **Run.** On each reader's device, per refresh: your `retrieve()` (if any)
   shapes the candidate query, your `score()` runs once per candidate, your
   `arrange()` (if any) runs once over the ranked pool, and the engine's
   moderation + diversity passes run after. Their feed is the result.

---

## 4. The Zal language

Zal is deliberately small. If you know C or JavaScript you already know the
shape; what's missing is missing on purpose (see §9 for why).

### 4.1 The one type

- **`num`** — a 64-bit float. The only type. No integers-vs-floats, no
  booleans, no strings, no arrays, no structs, no null.
- Booleans are numbers: comparisons evaluate to `1`/`0`; in `if`/`while`, any
  non-zero value is true.
- Literals are plain decimals: `1`, `42`, `3.14`, `0.5`. **No** exponent
  notation (`1e5`), hex, underscores, or suffixes.
- Text appears in exactly one place: a quoted tag name passed to `has_tag` /
  `tag_scope`. A string is never a value — it is interned into the artifact's
  read-only tag pool at compile time and referenced by index.

### 4.2 Statements

```
var x = <expr>;          // declare (required before use)
x = <expr>;              // assign
if (<expr>) { ... } else if (<expr>) { ... } else { ... }
while (<expr>) { ... }   // the only loop
return <expr>;           // the function's value
<expr>;                  // expression statement (e.g. emit(i);)
```

No `for`, `break`, `continue`, `switch`, ternary, `++`/`--`, `+=`. Comments are
`//` to end of line.

### 4.3 Operators, lowest to highest binding

`||` · `&&` · `==` `!=` · `<` `>` `<=` `>=` · `+` `-` · `*` `/` · unary `-` `!`
· grouping/calls/literals.

Division by zero yields 0 — never a crash. There is no math library (`exp`,
`pow`, `sqrt`, `log`, `min`, `max`, `random` do not exist); build curves from
arithmetic (§8.4) and choices from `if`.

### 4.4 The facts

Inside `score()` (and `learn()`), the current post's public features are plain
names:

| Fact | Meaning |
|---|---|
| `like_count` `repost_count` `reply_count` | the public counters |
| `reply_chain` | times the author replied back into this thread |
| `quote_count` | quote-reposts |
| `tag_count` | how many topic tags (zones) the post carries |
| `age_hrs` | hours since the post was created (the host computes it — your code never sees a clock) |
| `author_rep` | public author-reputation prior, 0…1 |
| `in_network` | 1 if from an account the viewer follows |
| `viewer_engaged` | 1 if the viewer already liked/reposted it |
| `base_score` | the engine's own score for the post — layer on it or ignore it |

There are **no other facts**. No author identity, no post text, no viewer
identity. That absence is a guarantee, not a gap — see §9.

### 4.5 Functions you can call

Every callable is a *capability* — a numbered door in a fixed, audited table.
The full table with permissions is in §6. There are no user-defined function
calls yet: only `score`/`retrieve`/`arrange`/`learn` are compiled, and they
cannot call each other or your other `fn` declarations — keep logic inline.

---

## 5. Entry points: the staged pipeline

A program implements whichever stages it needs; an absent stage falls back to
the engine default. All stages compile from one source file and share one tag
pool.

```
retrieve()  →  score()  →  [sort]  →  arrange()  →  moderation/diversity
 shape the     rank each              order the      the engine's fixed
 pool query    candidate              ranked pool    passes — always run
```

### `fn score() num` — required — **LIVE**

Runs once per candidate. Return a larger number to rank the post higher.
Reads the facts (§4.4), may read the whole pool (§7), may call `has_tag`.

### `fn retrieve() num` — optional — **LIVE**

Runs once per refresh, *before* scoring, to compose the candidate query. Call
source functions to add pools; a post enters your pool if it matches at least
one source:

```
fn retrieve() num {
  follows(1.0);              // accounts the viewer follows, weight 1
  trending(50.0, 0.8);       // engagement ≥ 50, weight 0.8
  tag_scope("zig", 1.5);     // the zig zone, weighted up
  return 0.0;                // the return value is ignored
}
```

You name and weight sources; the host runs the query over its own indexes. You
cannot traverse the network, follow graphs by hand, or query anything the
source vocabulary doesn't name — that is the retrieval boundary (§14).

### `fn arrange() num` — optional — **LIVE**

Runs once per refresh, *after* scoring, over the ranked pool (index 0 = the
top-scored post). This is where cross-item structure lives: interleaving,
variety, slotting. Read any pool post with `pool_read(i, fact)`; build the
final order with `emit(i)`.

- `emit(i)` appends pool post `i` to the final order, once: a duplicate or
  out-of-range emit is ignored (returns 0; a successful emit returns 1).
- Posts you never emit are appended after your emits, in score order. **You
  cannot lose a post, only re-place it.**
- There is no "current post" inside `arrange()` — bare facts read as zero.
  Read the pool instead.

### `fn learn(…)` — **PLANNED**

The contract defines a `learn` entry (per attention event, for adaptive
algorithms that maintain an on-device model). It is not yet compiled from Zal
source and its runtime host is not yet wired. Adaptive behavior today is
limited to reading attention inside `score()` — see the status column in §6.

---

## 6. Capabilities: the full table

A capability is granted, audited, and walled per entry point. Calling one from
the wrong entry is a **compile error** in Zal, a **named refusal** at the
publish gate for raw bytecode, and an **emptied program** at load — the same
rule enforced three times, so hand-crafted bytecode gets no path around the
compiler.

| Call | Does | Allowed in | Status |
|---|---|---|---|
| `follows(w)` | add the follows source to your pool query | `retrieve` | **LIVE** |
| `discovery(w)` | add the beyond-your-follows source | `retrieve` | **LIVE** |
| `trending(threshold, w)` | add the engagement-threshold source | `retrieve` | **LIVE** |
| `tag_scope("tag", w)` | add a zone-scoped source | `retrieve` | **LIVE** |
| `has_tag("tag")` | 1 if the current post carries the zone tag | `score`, `learn` | **LIVE** |
| `pool_len()` | how many posts are visible in the pool | `score`, `learn`, `arrange` | **LIVE** |
| `pool_read(i, fact)` | the named fact of pool post `i` | `score`, `learn`, `arrange` | **LIVE** |
| `emit(i)` | append pool post `i` to the final order | `arrange` only | **LIVE** |
| `attention_dwell()` | the viewer's dwell on the current post, 0…1 | `score`, `learn`; behavioral | **WIRED** — compiles + labels; the on-device attention host is not connected yet, so it returns 0 |
| `attention_clicked()` | 1 if the viewer clicked into the post | `score`, `learn`; behavioral | **WIRED** — same |
| `state_read(i)` | read a word of your persistent on-device state | `score`, `learn`, `arrange` | **WIRED** — returns 0 until the state host lands |
| `state_write(i, v)` | write a word of persistent state | `score`, `learn`, `arrange` | **WIRED** — no-op until the state host lands |

Notes:

- **Tag arguments are quoted literals only.** `has_tag("zig")`, never a
  variable. The literal is interned at compile time; your program passes an
  index the host resolves. Tags are public, moderated zone names — never an
  author handle, never post text.
- **`pool_read`'s second argument is a bare fact name**, not a value:
  `pool_read(i, like_count)`. A number or variable there is a compile error.
- **Behavioral capabilities are labeled.** Calling either `attention_*`
  function marks your algorithm "uses your attention data" — derived from the
  bytecode, not from your description. See §10.
- Writing code against **WIRED** capabilities is safe: it compiles, gates, and
  publishes today, and gains real data when the hosts land, with no source
  change.

---

## 7. Cross-item ranking: the pool

`score()` classically sees one post at a time. Zat4 also hands your program the
**whole candidate pool** as a read-only, indexed array of the same public
facts — which unlocks the ranking families a pointwise scorer structurally
cannot express: "don't clump similar posts," relational ranking, arranging
under constraints.

**What the pool is:**
- During `score()`: the retrieval-passing candidates, in feed order, up to the
  system cap. `pool_read(j, base_score)` answers the *engine's* base score for
  post `j` (your scores don't all exist yet — no paradox).
- During `arrange()`: the same posts sorted by final score, index 0 = top.
  `pool_read(i, base_score)` answers post `i`'s final score.
- The visible window is capped by the system (currently 256 posts). `pool_len()`
  tells you the real size; reads past it return 0; `arrange` re-orders only the
  window (ranks past it keep score order behind it).

**Cost model:** every `pool_read` costs fuel like any other call. Comparing
every post against every other post is *legal* — it just spends your budget as
`n²`, and when fuel runs out your program stops where it is (a partial arrange
still yields a valid feed; unemitted posts follow in score order). Efficient
shapes win:

- **Compare against a fixed anchor** (the top post, the pool average you
  compute once into locals): `n` reads, not `n²`.
- **The two-pass arrange skeleton** — walk the pool and place what matters,
  then place the rest (already-placed posts are skipped for free):

```
fn score() num { return like_count + repost_count * 2.0; }

fn arrange() num {
  var n = pool_len();
  var i = 0.0;
  while (i < n) {
    if (pool_read(i, age_hrs) < 1.0) { emit(i); }   // sub-hour posts first
    i = i + 1.0;
  }
  i = 0.0;
  while (i < n) { emit(i); i = i + 1.0; }           // then everyone else
  return 0.0;
}
```

- **Interleave two passes** (fresh/popular, in/out-of-network) the same way:
  two selective passes and a sweep.

**What the pool does not contain:** author identity, in any form. You can read
each post's counters, age, tags-count, reputation — you cannot ask whether two
posts share an author. "No three posts in a row from one author" is therefore
not yet expressible in a program; the engine's own `max_per_author` diversity
cap (a config field) covers that need today, and an anonymous author-equivalence
signal is a **PLANNED** addition (§14).

---

## 8. The execution model

### 8.1 The machine

Your program compiles to bytecode for a small stack VM: an operand stack (64
slots), 1024 words of per-run scratch memory (your `var`s live there; zeroed
every run, discarded after), and a fixed opcode set. There is no opcode for
I/O of any kind. Programs are capped at 4096 instructions, artifacts at 64 tag
constants of 128 bytes each.

### 8.2 Fuel: why your program cannot hang a phone

Zal has real loops, so termination cannot be structural — it is metered.
Every executed instruction spends one unit of **fuel**; when the budget is
exhausted the machine simply stops and the engine uses what it has (your
score's current stack top; your partial arrange plus the score-order fallback).

- Default budget: **100,000 instructions per run** (one run = one candidate
  scored, or one retrieve/arrange pass).
- You may declare a higher budget, up to the hard ceiling of **5,000,000** —
  but the publish gate then *runs your program* against edge-case candidates
  (and a full-size pool, for `arrange`) and refuses it if it cannot finish
  inside its own declared budget. An algorithm that cannot finish does not
  ship; fuel exhaustion in the wild is a malformed-input safety net, not a
  normal mode.
- The engine's total work per refresh is therefore hard-bounded by
  `(pool + 1) × fuel` — the property that makes running strangers' code on a
  reader's device sane at all.

Evaluation is **total**: bounded stack (underflow reads 0, overflow drops),
every value forced finite (no NaN/Inf can propagate), division by zero yields
0, a bad jump ends the run. Any bytes, however hostile, produce a defined,
finite number. Your bugs can make your feed rank badly; they cannot crash the
app or hang the device.

### 8.3 Real numbers

Measured on a desktop dev machine (release build): the VM executes a
call-heavy loop at ~**7 ns per instruction**. The worst refresh the default
budget admits — 256 candidates each burning all 100k fuel on pool reads, plus
an all-burn arrange — costs ~**165 ms**, once per refresh, off the render
thread. A typical scoring program (a few hundred instructions per candidate)
is far below one millisecond per refresh. Efficiency still matters at the
margin — snappier algorithms feel better and the marketplace will notice — but
you have real room.

### 8.4 Idioms (no math library needed)

```
var freshness = 6.0 / (age_hrs + 6.0);          // rational decay, ~6h half-feel
var velocity  = 1.0 + (repost_count + reply_count) / (age_hrs + 2.0);
eng = eng + 1.0;                                 // cold-start floor
if (!in_network && eng > 150.0) { s = s * 1.4; } // conditional boost
if (age_hrs > 48.0) { s = s * 0.4; }             // stale dampener
```

---

## 9. What you cannot do, and why it's structural

The sandbox is not a reviewer or a filter — the dangerous reaches are *absent
from the instruction set*. These are theorems of the capability table, not
policies:

- **No network, no filesystem, no clock, no randomness.** There is no opcode
  or capability for any of them. `age_hrs` arrives precomputed; two users with
  the same algorithm and posts see the same order (determinism is what makes
  the published-hash promise meaningful).
- **No targeting.** No fact or pool read exposes an author handle, DID, post
  text, or "is this me." An algorithm cannot single out an account — yours,
  a rival's, anyone's — because the identifying input does not exist.
- **No exfiltration.** The attention signals (when live) and your persistent
  state stay on the device. Reading attention is possible *because* leaving
  with it is not expressible — there is no capability that moves data off the
  device.
- **No safety-signal inversion.** Blocks/mutes/reports enter scoring only as
  damping toward zero; no weight or program can make them boost a post.
- **No pool escape.** `retrieve()` names sources from a fixed vocabulary;
  moderation and diversity run after your code, non-bypassably. Freedom over
  *ranking* is total; freedom over *what enters the pool* and *what safety
  removes* is not granted.
- **Entry walls.** Sources only in `retrieve()`; per-post reads only where a
  current post exists; `emit` only in `arrange()`. Enforced at compile,
  publish, and load.

If your idea genuinely needs off-device computation — a heavy model, an image
classifier — Zat4's on-device trade is the wrong tool, on purpose. The design
buys privacy, determinism, and auditability with that ceiling.

---

## 10. Transparency: what users see about your algorithm

Every published algorithm gets a transparency page derived **from the record
and bytecode themselves**, never from your marketing copy:

- Every config field renders with its label, value, and meaning, in plain
  language.
- Rules render as readable "if … then …" lines; programs are inspectable.
- The privacy labels are *proven*, not claimed: "uses your attention data" is
  true iff your bytecode calls a behavioral capability; "keeps an on-device
  model" is true iff it calls `state_write`. You cannot get a clean label by
  describing your algorithm modestly, and you cannot be smeared by a false
  one — the label is a scan of what the code can reach.
- Your on-device state, if you keep any, is bounded by a declared budget
  (hard cap 10 MiB) that is shown to the user and never leaves their device.

Write with the assumption that everything about your algorithm's behavior is
legible. That is the marketplace's trust model: competition on quality, under
inspection.

---

## 11. Publishing and the gate

Publishing serializes your whole algorithm record (weights, rules, formula,
programs, tag pool, declared budgets) to canonical JSON, addressed by CID.
Before anything ships, the **publish gate** runs — pure, local, and total.
Every refusal is a named sentence you can act on:

| Refusal | Meaning |
|---|---|
| `guest_score_malformed` / `guest_retrieve_malformed` / `guest_arrange_malformed` | the bytecode is structurally invalid (bad jump target or capability id, or over the length cap) |
| `entry_wall_score` | `score()` calls a retrieval source |
| `entry_wall_retrieve` | `retrieve()` calls a candidate/state/attention capability |
| `entry_wall_arrange` | `arrange()` calls outside the pool/state set |
| `fuel_over_ceiling` | declared fuel budget above the 5M ceiling |
| `state_budget_over_ceiling` | declared state budget above 10 MiB |
| `strings_over_cap` / `string_too_long` | tag pool over 64 entries / a tag over 128 bytes |
| `rules_over_cap` / `sources_over_cap` / `candidates_over_cap` | over 64 rules / 32 sources / 5000 candidates |
| `battery_score_exhausted` | `score()` could not finish its declared fuel on an edge-case candidate (empty, saturated counts, hostile floats) |
| `battery_retrieve_exhausted` | same, for `retrieve()` |
| `battery_arrange_exhausted` | `arrange()` could not finish against a full-size pool |
| `not_load_stable` | the record contains a value the loader would silently repair — what you publish must be exactly what runs |

The battery deserves emphasis: the gate does not trust your program's shape,
it **executes it** against the calm case, the empty case, saturated counters,
and hostile float values — and for `arrange`, against a pool reporting the
full 256-entry window. A loop bounded by an assumption the battery violates is
caught before any reader runs it.

At load time on each device, the same validations run again as a backstop, and
anything invalid degrades to a safe no-op (your program empties; the engine
default takes over) — never a crash on the reader's end.

---

## 12. Worked examples

All of these compile and run today; the first four ship as in-app starters.

**Most Liked** — the minimum viable algorithm:
```
fn score() num { return like_count; }
```

**Most Recent** — reverse-chronological:
```
fn score() num { return 0.0 - age_hrs; }
```

**Calm** — temper pile-ons:
```
fn score() num {
  var eng = like_count + reply_count * 4.0;
  return eng / (1.0 + (repost_count + reply_count) / 20.0);
}
```

**Fresh First** — the arrange skeleton (see §7 for the walkthrough):
```
fn score() num { return like_count + repost_count * 2.0; }
fn arrange() num {
  var n = pool_len();
  var i = 0.0;
  while (i < n) {
    if (pool_read(i, age_hrs) < 1.0) { emit(i); }
    i = i + 1.0;
  }
  i = 0.0;
  while (i < n) { emit(i); i = i + 1.0; }
  return 0.0;
}
```

**A zone-first feed** — retrieval + content capability together:
```
fn retrieve() num {
  tag_scope("zig", 1.5);      // the zig zone, weighted up
  follows(1.0);               // plus your follows
  return 0.0;
}
fn score() num {
  var s = like_count + reply_count * 27.0;
  if (has_tag("zig")) { s = s * 2.0; }
  return s * (6.0 / (age_hrs + 6.0));
}
```

**Conversation Discover** — the full flagship shape (public signals only):
```
fn score() num {
  var eng = like_count + repost_count * 2.0 + reply_count * 40.0;
  eng = eng + 1.0;
  var s = eng * (4.0 / (age_hrs + 4.0));
  s = s * (1.0 + (repost_count + reply_count) / (age_hrs + 2.0));
  s = s * (1.0 + author_rep * 0.5);
  if (!in_network && eng > 150.0) { s = s * 1.4; }
  if (age_hrs > 48.0) { s = s * 0.4; }
  return s;
}
```

**Pool-relative cap** — cross-item scoring (note: during `score()` the pool is
in feed order, not ranked; compute your own aggregate):
```
fn score() num {
  // Cap runaway posts relative to the POOL, not a constant: average the
  // pool's engine base once (a few hundred reads — cheap against the
  // fuel budget), then cap anything 10x above it.
  var n = pool_len();
  var sum = 0.0;
  var i = 0.0;
  while (i < n) {
    sum = sum + pool_read(i, base_score);
    i = i + 1.0;
  }
  var avg = 1.0;
  if (n > 0.0) { avg = sum / n; }
  var s = like_count + reply_count * 27.0;
  if (s > avg * 10.0) { s = avg * 10.0; }
  return s;
}
```

---

## 13. FAQ

**Why can't I read the post's text?**
Text exposes identity (names, handles, quoted content) and would make ranking
non-auditable. The fact vocabulary is public *signals about* posts, which keeps
"no targeting" provable. Topic access goes through zone tags (`has_tag`),
which are public and moderated.

**Why is there only one number type?**
Every fact and score is a magnitude; one type removes an entire class of
authoring errors and keeps the VM's value model auditable. Booleans are 0/1 by
convention, and it works fine in practice.

**My loop condition is `i < pool_len()` — is calling it every iteration wasteful?**
It costs a few instructions per iteration. Idiomatic: hoist it once into a
local (`var n = pool_len();`). At 100k fuel you're unlikely to notice either
way; see the numbers in §8.3.

**What happens if my program runs out of fuel?**
It stops; the engine uses what exists. In `score()` that's the current stack
top (or the engine base if none); in `arrange()` your emits so far, with
everything unemitted following in score order. No error reaches the reader —
but note the publish gate refuses programs that exhaust fuel on its battery,
so ship programs that finish.

**Can I make my algorithm adapt to the individual reader?**
The design supports it — that's the behavioral tier: `attention_dwell()` /
`attention_clicked()` as inputs, `state_read`/`state_write` as your on-device
model, everything on-device with no exfiltration path, and an honest "uses
your attention data" label. **Status:** those capabilities compile and label
correctly today but return placeholder values until their runtime hosts land
(§6). Write against them now; they light up without source changes.

**Can I exclude posts I consider spam?**
You can rank them to the bottom (score 0), and a Tier-2 rule can `exclude`
from your pool. You cannot *add* posts moderation removed, ever.

**Why can't my `arrange()` call `has_tag`?**
`has_tag` answers about the *current post*, and inside `arrange()` there is no
current post — you're operating on the whole pool. Read per-post facts with
`pool_read`. (A per-pool-row tag test is a plausible future capability; see
§14.)

**Can two algorithms compose — run one, then another?**
Not as a first-class operation today. The stages of one program compose
(`retrieve` → `score` → `arrange`), and your `score()` can layer on the
engine's `base_score`. Copying and modifying a published algorithm is the
intended borrowing path — records are open by design.

**How do I test before publishing?**
The publish gate runs locally and names every problem, and its battery
executes your program. The in-app create flow (in progress) is where
compile-run-inspect lives; today the gate is the contract.

**Is my source code published, or the bytecode?**
The record carries the compiled program (with its tag pool). The transparency
page derives capability labels from the bytecode, so the privacy claims hold
even when source isn't attached — the label is about what the code can reach,
not what anyone says about it.

---

## 14. Current limits, and what's coming

Deliberate boundaries, stated plainly:

- **Retrieval stays host-run.** Your `retrieve()` names and weights sources
  from a fixed vocabulary; it cannot express new queries or traverse the
  graph. Widening retrieval (graph-walk, similar-to) is designed but gated on
  network scale, and it is a genuinely different safety question — which posts
  are *fetched* can touch what is queried about a user. **PLANNED.**
- **No author identity in the pool** — so cross-item *author* diversity is not
  yet expressible in a program (the engine's `max_per_author` cap covers it).
  The designed fix is an anonymous per-refresh author-bucket fact: same author
  ⇒ same opaque number, reshuffled every refresh, so equivalence is readable
  but identity never is. **PLANNED.**
- **Adaptive runtime** — attention and persistent state hosts: **WIRED**,
  landing with the on-device learner milestone. `learn()` compilation lands
  with them.
- **Pool window = 256, fuel default = 100k, ceiling = 5M** — calibration
  values, re-measured on phone hardware before launch; the walls' existence is
  permanent, the numbers are tuned.
- **No heavy models on-device.** A fuel-bounded local program cannot run an
  image classifier. That is the privacy trade, and it is the right one for a
  feed; ideas that need server-scale compute need a different tool.

---

*Companion documents: `ZAL_LLM_REFERENCE.md` (the terse, machine-oriented
language reference), `THE_RULESET.md` (the engineering law this codebase obeys),
and the Zat4 whitepaper (the system's design rationale).*
