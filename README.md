# zat — a Zig + atproto client

Built under **THE_RULESET.md** and **DESIGN_PHILOSOPHY.md**; build order follows
**TECHNICAL_ROADMAP.md**. Where this code and those documents disagree, the
code is wrong (H4).

## Status

**All roadmap phases (0–8) complete.** Phase 5 finished with the profile
view (`p`), the moderation reveal toggle (`x`), and the test-scaffold
consolidation. Phase 8: persistence — the whole feed store snapshots to a sealed, versioned on-disk format and the session persists behind 0600; a second launch renders your cached timeline instantly, starts live coverage immediately, and skips login. Deleting `session.zat` from the cache directory is the logout. The window milestone: `--window` opens the same client in a native X11 window — hand-rolled over the Unix socket, zero dependencies, same keys. Phase 7: a live timeline — the stream subsystem subscribes to Jetstream over a hand-rolled, golden-byte-tested WebSocket layer, delivers posts through a plain-data mailbox, and reconnects with cursor resume; a dropped stream is a status line, never a dead screen. Phase 0: raw HTTPS GET parsed into typed flat
structs under a leak-detecting allocator. Phase 1: the identity deep module —
handle → verified DID → PDS URL + signing key, with bidirectional handle
verification (the DID document must claim the handle back, or resolution
fails). Phase 2: the XRPC deep module — typed `query`/`procedure` calls over
the transport, lexicon records decoded by comptime reflection, server
refusals carried as plain `Failure` values, bounded 429 retry on a pure
schedule. Phase 3: the auth deep module — app-password sessions with
reactive token refresh (`ExpiredToken` → refresh → retry once, tokens
rotating in place); demo with `ZAT_APP_PASSWORD=… zig build run -- you.bsky.social`.
Phase 4: the feed module — the timeline lands in a struct-of-arrays store
(posts/authors/feed-items in `MultiArrayList`, all text in one span-addressed
buffer, typed u32 indexes, CID-deduplicated), every resident record under a
compile-time exact-size guard, with a pure core producing render-ready
view-models and cursor pagination. Phase 5's recorded decision: a hand-built,
immediate-mode terminal renderer, zero dependencies — each frame is a pure
transform of view-models into a SoA cell grid, presented as a minimal ANSI
diff, golden-byte tested. Run it:

    ZAT_APP_PASSWORD=xxxx-xxxx-xxxx-xxxx zig build run -- your.handle --tui

(j/k move, g/G ends, r loads pages; l like, b boost, R reply, n new post,
f follow author; in the composer ctrl-d sends and esc cancels; q quits.)
Phase 6's write path: five createRecord verbs through the auth module,
rich-text facets detected as byte-range spans with mentions resolved to
DIDs, and optimistic updates that revert on refusal and reconcile against
server truth at dedup time. Labeled posts collapse behind the sealed
moderation module's notices. Remaining in Phase 5: a profile view and the
hidden-post reveal toggle.

Note on `test-live`: the identity tests need unrestricted egress
(plc.directory, dns.google, the handle's own domain). Sandboxes with outbound
allowlists fail them at the proxy — environment, not defect. The offline
suite proves the same logic via a fixture corpus plus a loopback round trip
over real sockets.

## Toolchain

Zig **0.16.0** (pinned in `build.zig.zon` as `minimum_zig_version`).
Install from ziglang.org/download, or via the official PyPI wheel:
`pip install ziglang` (binary lands inside the package; symlink it onto PATH).

## Commands

```
zig build run -- alice.bsky.social   # resolve a handle (default: bsky.app)
zig build run -- your.handle --tui      # the client, in the terminal
zig build run -- your.handle --window   # the client, in its own X11 window
zig build test       # offline unit tests — leak-checked (C6), deterministic
zig build test-live  # network smoke tests — hits the real network on purpose
zig build bench      # the G1 performance ledger (core transforms, measured)
zig build guards     # A7: every struct guarded or waived — also runs inside `zig build test`
zig build clean      # wipe the local build cache (.zig-cache) + zig-out
```

> **On the build cache growing:** `.zig-cache/` ballooning during heavy
> testing is expected, not a bug. Zig keeps content-hashed compiled
> artifacts so incremental rebuilds are fast, and it cannot auto-delete
> old variants (it has no way to know you won't switch back to a target
> or mode). Across a session that cross-compiles several targets — and
> with the fonts embedded into every binary variant — it accumulates.
> `zig build clean` clears it in one command. The cache never enters git
> (`.gitignore` covers it), so this is purely local disk.

`l` and `b` are toggles: pressing on an already-liked/boosted post
unlikes/unboosts it — optimistic, reverted if the server refuses. Items
restored from the offline cache ask for one refresh first: the
like-record id travels on the wire, not in the snapshot.

## Layout

```
src/
  main.zig           shell — entry point; per-request arena (C3); current demo: zat [handle]
  guard.zig          core (comptime-only) — the A7 size-guard harness every hot struct uses
  core/
    feed.zig         core — the SoA store: size-guarded records, CID interning, ingest, view-models (A3/A4/A7/A8)
    compose.zig      core — write module: rich-text facet detection as byte-range spans
    moderation.zig   core — the sealed moderation module (D1): labels in, verdicts out
    tui.zig          core — renderer substrate: SoA cell surface, pure ANSI diff encoder, input decoding
    timeline_ui.zig  core — the timeline screen: pure frame building, scroll, wrap, ages
    identity.zig     core — pure: handle/DID validation, payload parsing, DID-doc verification
    lexicon.zig      core — plain-data wire shapes: the lexicon subset we consume (A1)
    xrpc.zig         core — pure: the sealed wire-format decision — URLs, escaping, codec, error bodies (D1)
  shell/
    http.zig         shell — the transport deep module; the ONLY file where HTTP/TLS exists (B3, D1)
    identity.zig     shell — public face of the identity deep module (D1): Identity, resolve()
    xrpc.zig         shell — public face of the XRPC deep module (D1): query(), procedure(), Outcome
    auth.zig         shell — public face of the auth deep module (D1): Session, login(), refresh-and-retry
    feed.zig         shell — timeline fetch + cursor pagination feeding the core store
    tui.zig          shell — the terminal session: raw mode, clock, frame loop (the only tty code)
    write.zig        shell — write module: createRecord verbs, mention resolution
  live_tests.zig     shell — live network tests, isolated behind `test-live`
```

Standing notes:

- Zero third-party dependencies (F1). TLS comes from Zig std; the written
  justification lives at the site, in `src/shell/http.zig`.
- Every file's first line classifies it core or shell (B1).
- Every hot struct carries a `comptime` exact-size assertion (A7); cold
  structs carry an explicit `// A7.2` waiver. No silent exemptions.
- `core/` holds only pure, deterministic transforms (B2/B4): no I/O, no
  clocks, no globals. The shell hands it bytes; it hands back plain values.

## Window (`--window`)

`zig build run -- your.handle --window` opens zat in its own X11 window
instead of the terminal: same screens, same keys (j/k/arrows, r, space,
l, b, f, n to compose, p profile, x show, q or the close button to quit). It speaks the X11
wire protocol directly over the Unix socket — no Xlib, no SDL, no
dependencies — renders through an embedded Spleen 8x16 bitmap font, and
resizes live. Requirements: a `DISPLAY` (any X11 or XWayland session);
`XAUTHORITY`/`~/.Xauthority` is honored when present. The terminal
remains the default; `--window` is the same client behind a different
backend. Cross-platform (Route A, in progress): the backend is selected
per-OS by `shell/native.zig` — X11 on Linux, a hand-rolled Win32 backend
on Windows, and a runtime-bound AppKit backend on macOS — the FULL app
cross-compiles for all three from one container:
`zig build -Dtarget=x86_64-windows` emits `zat.exe`, and
`zig build -Dtarget=aarch64-macos` / `-Dtarget=x86_64-macos` emit Mach-O
binaries with zero framework link-time symbols (everything is dlopen'd
at run time). Window-only on Windows v1; fixed-size window on macOS v1;
runtime verification pending on real hardware for both. Zero third-party
dependencies throughout.

## Live timeline (Phase 7)

`r` refreshes: it fetches the newest page, slides previously-unseen posts
in at the top, and jumps you to them (`+N new at top`). Posts arriving on
the live stream instead preserve your reading position. `space` or `enter` loads OLDER posts below, walking
the cursor down. After the first successful load, zat opens a Jetstream subscription for
YOU plus the authors it has seen (up to 256, growing as the feed teaches
it more) — the status corner says `live: connected` the moment the
handshake lands. Your own posts are in the filter by design: post from
your phone and it should appear at the top within a couple of seconds —
that is the canonical live self-test. New posts from those accounts slide
in at the top of the feed in real time — your cursor stays on the post
you were reading, and the status line announces `live: new post`.

The stream is its own subsystem: it fails alone. A drop becomes a
named status (`stream: <Error>; retrying`) while the feed keeps working; reconnects
back off politely (1s → 30s cap) and resume from a cursor, so nothing is
missed. Quiet stretches are probed, not presumed dead: after 30 s of silence zat
pings; a ping unanswered for 30 s more is declared dead and the
connection rebuilt (NATs kill idle flows without a goodbye). Quitting joins the stream cleanly.

Live posts arrive without moderation labels (labelers are a separate
channel); a timeline refresh reconciles them. Posts from accounts the
store hasn't met yet render by DID until a refresh teaches their handle.

| Variable | Meaning |
|---|---|
| `ZAT_JETSTREAM` | Override the Jetstream host (default `jetstream2.us-east.bsky.network`). |
| `ZAT_STREAM_LOG` | Stream transcript path. DEFAULT ON: `zat-stream.log` in the working directory (connects, the subscribe URL, cursor, every frame and verdict, heartbeat). Set to `off` to disable. |
| `ZAT_REFRESH_SECS` | Auto-refresh interval for the visible feed (default 5; `0` disables, reverting to manual `r`). |
| `ZAT_CACHE_DIR` | Cache directory (default `$XDG_CACHE_HOME/zat`, else `~/.cache/zat`). Holds `store.zat` (the feed snapshot) and `session.zat` (0600 credentials — delete it to log out). |
