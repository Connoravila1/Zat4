# zat

A social-media client **and** a self-contained social network, written from
scratch in **Zig** on the **AT Protocol** — with zero third-party dependencies.

zat speaks atproto, but it is its own environment: it reads and writes its own
`app.zat4.*` record namespace and is served by its own indexer, so it inherits
the protocol's portable identities while remaining a distinct network. Nearly
everything is hand-built — the GUI renderer, the X11 / Win32 / AppKit window
backends, the WebSocket and HTTP layers, font rasterization, the GPU path, and
the server-side indexer — linking only libc (TLS comes from the Zig standard
library; GL/EGL is loaded at runtime via `dlopen`).

## What's inside

- **A hand-rolled immediate-mode GUI** with a distinctive aesthetic: a living
  "glyph field" — ASCII characters lit like a material by a real neighbour-
  coupled wave simulation — behind a premium, proportionally-typeset feed. There
  is no UI toolkit; the renderer is the project's own, with both a software
  rasterizer and an EGL/GLES GPU backend.
- **Native window backends spoken as raw protocol:** X11 over a Unix socket on
  Linux, a Win32 backend on Windows, a runtime-bound AppKit backend on macOS —
  selected per-OS at comptime and cross-compiled from one toolchain.
- **A full atproto stack from scratch:** identity resolution (handle → DID → PDS,
  bidirectionally verified), XRPC, app-password sessions with reactive token
  refresh, a struct-of-arrays feed store, rich-text facets, and a live firehose
  subscription over a hand-built WebSocket layer.
- **Its own network layer:** a standalone **AppView** (indexer) that ingests
  `app.zat4.*` records from the firehose, indexes them, and serves timelines —
  with a durable append-only event log, a bearer-auth gate, and idempotent
  replay. New accounts are minted on a project-run PDS with `*.zat4.com` handles;
  existing atproto users bring their own identity.

## Design

zat is built data-first: plain records in struct-of-arrays, `u32` indexes rather
than pointers, an exact compile-time size assertion on every hot struct (the
build fails the instant a layout regresses), a strict pure-core / thin-shell
split with all I/O at the edges, explicit allocators everywhere, and a hard line
against casual dependencies. The result is a large, fast, fully-owned codebase.

## Build & run

Requires **Zig 0.16.0** (pinned in `build.zig.zon`).

```
zig build run -- your.handle --window         # the client, in a native window
zig build run -- your.handle --tui            # the client, in the terminal
zig build run -- your.handle                  # just resolve a handle and print it
zig build run -- you.zat4.com --post "…"        # headless: publish one post
zig build run -- you.zat4.com --follow h.zat4.com   # headless: publish one follow
zig build appview                             # run the AppView (ingest → serve timelines)
zig build test                                # offline unit tests, leak-checked
zig build test-appview                        # the AppView's offline tests
zig build bench                               # the performance ledger
```

Running the live client needs an app password in the environment:

```
ZAT_APP_PASSWORD=xxxx-xxxx-xxxx-xxxx zig build run -- your.handle --window
```

`--window` opens the client in a native window with the same keys as the
terminal: `j`/`k` or arrows to move, `g`/`G` to ends, `r` to refresh, `space`/
`enter` for older posts, `l` like, `b` boost, `n` compose, `p` profile, `q` to
quit. It speaks the X11 wire protocol directly over the socket — no Xlib, no SDL.

### Environment

| Variable | Meaning |
|---|---|
| `ZAT_APP_PASSWORD` | App password for login. |
| `ZAT4_APPVIEW` | AppView base URL the client reads timelines/profiles from (default `http://127.0.0.1:2584`). |
| `ZAT_APPVIEW_TOKEN` | Bearer token the client sends to the AppView (scoped to AppView calls; PDS login/writes use the session). |
| `ZAT_CACHE_DIR` | Cache directory (default `$XDG_CACHE_HOME/zat`, else `~/.cache/zat`). Holds the feed snapshot and the `0600` session — delete the session file to log out. |

> A note on the build cache: `.zig-cache/` grows during heavy testing because Zig
> keeps content-hashed artifacts for fast incremental rebuilds (and the embedded
> fonts ride into every binary variant). `zig build clean` clears it. It never
> enters git.

## Status

Active development. The client — identity, auth, feed, live timeline, composer,
native windows on three platforms, and the GPU glyph-field renderer — and the
standalone server side — an AppView with firehose ingestion, durable persistence,
and bearer auth, plus a project-run PDS minting `*.zat4.com` handles — are all
working. The codebase carries zero third-party dependencies.
