# Zat4

Zat4 is a social client built from scratch in Zig on the AT Protocol, with zero third-party dependencies.

It speaks atproto and runs as its own environment. It reads and writes its own `app.zat4.*` record namespace and is served by its own indexer, so it carries the protocol's portable identities while standing as a distinct network. Nearly all of it is hand-built: the GUI renderer, the X11, Win32, and AppKit window backends, the WebSocket and HTTP layers, font rasterization, the GPU path, and the server-side indexer. The only linked library is libc. TLS comes from the Zig standard library, and GL/EGL loads at runtime through `dlopen`.

## What's inside

- **A hand-rolled immediate-mode GUI** with a distinctive look: a living "glyph field," ASCII characters lit like a material by a real neighbour-coupled wave simulation, sitting behind a premium, proportionally typeset feed. The renderer is purpose-built, with both a software rasterizer and an EGL/GLES GPU backend.
- **Native window backends spoken as raw protocol.** X11 over a Unix socket on Linux, a Win32 backend on Windows, and a runtime-bound AppKit backend on macOS, each selected per OS at comptime and cross-compiled from one toolchain.
- **A full atproto stack written from scratch:** identity resolution (handle to DID to PDS, verified both ways), XRPC, app-password sessions with reactive token refresh, a struct-of-arrays feed store, rich-text facets, and a live firehose subscription over a hand-built WebSocket layer.
- **Caret-aware text and threads.** A shared editable-text core gives every input (the composer, the profile editor, the sign-up fields) click-to-place caret, motion and Home/End/Delete keys, double-click word and triple-click line selection, and drag-to-highlight with copy, cut, and paste. The thread view stitches an author's run of self-replies into one continuous "chain," nests everyone else's replies Reddit-style with collapse, and pins a catch-up author header as you scroll the chain.
- **Its own network layer.** A standalone AppView (indexer) ingests `app.zat4.*` records from the firehose, indexes them, and serves timelines, backed by a durable append-only event log, a bearer-auth gate, and idempotent replay. New accounts are minted on a project-run PDS with `*.zat4.com` handles, and existing atproto users can bring their own identity.

## Design

Zat4 is built data-first. Records are plain data held in struct-of-arrays, cross-record references are `u32` indexes rather than pointers, and every hot struct carries an exact compile-time size assertion, so the build fails the moment a layout regresses. The core is pure and the shell is thin, with all I/O kept at the edges. Allocators are explicit everywhere, and the project holds a firm line on adding dependencies. The result is a large, fast, fully owned codebase.

## Build and run

Zat4 needs Zig 0.16.0 (pinned in `build.zig.zon`).

```
zig build run -- your.handle --window               # the client, in a native window
zig build run -- your.handle --tui                  # the client, in the terminal
zig build run -- your.handle                        # resolve a handle and print it
zig build run -- you.zat4.com --post "…"            # headless: publish one post
zig build run -- you.zat4.com --follow h.zat4.com   # headless: publish one follow
zig build run -- --create-account name --email a@b.c # headless: mint name.zat4.com (invite via ZAT_INVITE_CODE)
zig build appview                                   # run the AppView (ingest → serve timelines)
zig build test                                      # offline unit tests, leak-checked
zig build test-appview                              # the AppView's offline tests
zig build bench                                     # the performance ledger
```

Running the live client needs an app password in the environment:

```
ZAT_APP_PASSWORD=xxxx-xxxx-xxxx-xxxx zig build run -- your.handle --window
```

`--window` opens the client in a native window with the same keys as the terminal: `j`/`k` or arrows to move, `g`/`G` to the ends, `r` to refresh, `space`/`enter` for older posts, `l` to like, `b` to boost, `n` to compose, `p` for the profile, `q` to quit. It talks the X11 wire protocol directly over the socket.

### Environment

| Variable | Meaning |
|---|---|
| `ZAT_APP_PASSWORD` | App password for login. |
| `ZAT4_APPVIEW` | AppView base URL the client reads timelines and profiles from (default `http://127.0.0.1:2584`). |
| `ZAT_APPVIEW_TOKEN` | Bearer token the client sends to the AppView (scoped to AppView calls; PDS login and writes use the session). |
| `ZAT_CACHE_DIR` | Cache directory (default `$XDG_CACHE_HOME/zat`, else `~/.cache/zat`). Holds the feed snapshot and the `0600` session. Delete the session file to log out. |

> A note on the build cache: `.zig-cache/` grows during heavy testing because Zig keeps content-hashed artifacts for fast incremental rebuilds, and the embedded fonts ride into every binary variant. `zig build clean` clears it. It stays out of git.

## Status

Active development. The client side is working: identity, auth, feed, live timeline, the composer with caret-aware editing and selection, the thread view, native windows on three platforms, and the GPU glyph-field renderer. The server side is working too: an AppView with firehose ingestion, durable persistence, and bearer auth, alongside a project-run PDS that mints `*.zat4.com` handles. The codebase carries zero third-party dependencies.

## License

Zat4 is free software, licensed under the GNU Affero General Public License, version 3 or (at your option) any later version (AGPL-3.0-or-later). The full text lives in [`LICENSE`](LICENSE), and every source file carries the licence header.

Because Zat4 runs over a network, the AGPL's section 13 applies: anyone who interacts with a running instance is offered its Corresponding Source. Zat4 honors this with a persistent, visible source link in the UI (the sidebar footer) that points back to this repository at `codeberg.org/connoravila/Zat4`. A deployed modification should keep that link pointing at its own modified source.

Bundled components keep their own licences, retained in their files: the `stb_truetype` rasterizer (`vendor/`, public domain) and the embedded UI font (BSD-2-Clause, notice in `src/core/font.zig`). Both are compatible with the AGPL and leave the licensing of the project's own code unchanged.
