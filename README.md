# Zat4

Zat4 is a social network written from scratch in Zig — a native client, its own
indexer, and its own account host, all speaking the AT Protocol, with zero
third-party dependencies. The only linked library is libc. TLS comes from the
Zig standard library; GL/EGL and the OS keystore load at runtime through
`dlopen`.

It carries the protocol's portable identities but stands as its own network: it
reads and writes only its own `app.zat4.*` record namespace, is served by its
own AppView, and mints new accounts on its own PDS as `*.zat4.com` handles.
Existing atproto users can bring their identity with them.

## The client

The GUI is hand-rolled and immediate-mode. Behind a proportionally typeset feed
sits a living "glyph field" — ASCII characters lit like a material by a real
neighbour-coupled wave simulation, where interactions splash energy and dye
into the medium. The renderer is the project's own, twice: a software
rasterizer, and an EGL/GLES GPU backend with a glyph atlas and one batched-quad
shader. Window backends are spoken as raw protocol — X11 over a Unix socket on
Linux, Win32 on Windows, runtime-bound AppKit on macOS — selected at comptime
and cross-compiled from one toolchain.

On top of that: a shared caret-aware text core (click-to-place caret,
word/line selection, drag-highlight, copy/cut/paste) used by every input; a
thread view that stitches an author's self-reply chain into one continuous
post and nests everyone else with collapse; a lens socket for switching feed
algorithms in place; and schema-driven settings.

## Open algorithms

The feed ranker is not a privileged black box. Every feed — including the
defaults — is a published configuration over one scoring engine, so "the
algorithm" is something you can read, edit, build with a guided flow, or
install from a marketplace. Serious creators write real code in **Zal**, a
small C-like language compiled to an in-house bytecode VM that is
fuel-metered and capability-sandboxed: guest code sees facts, never I/O, and
a feed's privacy label is *derived from the capabilities it actually uses*,
so the label cannot lie.

## The protocol stack

Everything atproto is written from scratch: identity resolution (handle → DID
→ PDS, verified both directions), XRPC, a live firehose subscription over a
hand-built WebSocket layer, and a struct-of-arrays feed store. Auth speaks
both app passwords and full OAuth — PAR, PKCE, and DPoP-bound tokens with
ES256/JWS built in-house — with secrets kept in the OS keystore where one
exists. The trust boundary is enforced, not assumed: strict DAG-CBOR and CID
verification run live at ingest, repo commit signatures verify end to end
(ECDSA with low-S canonicalization), and outbound requests pass an SSRF
guard.

## Zat Chat (in progress)

Private 1:1 messaging is being built on MLS (RFC 9420), restricted to the
two-member case, over HPKE (RFC 9180) with the X-Wing hybrid post-quantum
KEM. The whole crypto core is written in-house and pinned byte-for-byte to
the published interop and spec test vectors — wire codec, key schedule,
secret tree, and the full create → welcome → exchange → rotate state
machine. It is not yet wired to the network: the current Messages surface is
a development sandbox, runs in plaintext, and says so on screen. The
encrypted path replaces it wholesale — there will be no "encrypted" label in
the UI until the plaintext path is deleted.

## Design

Zat4 is built data-first, under a written ruleset the build enforces. Records
are plain data in struct-of-arrays; cross-record references are `u32`
indexes, never pointers; every hot struct carries an exact compile-time size
assertion, so the build fails the moment a layout regresses. The core is
pure — no I/O, no clock, no RNG — and the shell is thin, with entropy and
network passed in at the edges; that split is what lets the crypto ship with
its test vectors. Allocators are explicit everywhere, tests run
leak-checked, and the answer to "should we add a dependency?" is no.

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
zig build test                                      # offline unit tests, leak-checked + size-guard gate
zig build test-appview                              # the AppView's offline tests
zig build bench                                     # the performance ledger
```

Running the live client needs an app password in the environment:

```
ZAT_APP_PASSWORD=xxxx-xxxx-xxxx-xxxx zig build run -- your.handle --window
```

`--window` opens the client in a native window with the same keys as the
terminal: `j`/`k` or arrows to move, `g`/`G` to the ends, `r` to refresh,
`space`/`enter` for older posts, `l` to like, `b` to boost, `n` to compose,
`p` for the profile, `q` to quit.

### Environment

| Variable | Meaning |
|---|---|
| `ZAT_APP_PASSWORD` | App password for login. |
| `ZAT4_APPVIEW` | AppView base URL the client reads timelines and profiles from (default `http://127.0.0.1:2584`). |
| `ZAT_APPVIEW_TOKEN` | Bearer token the client sends to the AppView (scoped to AppView calls; PDS login and writes use the session). |
| `ZAT_CACHE_DIR` | Cache directory (default `$XDG_CACHE_HOME/zat`, else `~/.cache/zat`). Holds the feed snapshot and session state. |

> A note on the build cache: `.zig-cache/` grows during heavy testing because
> Zig keeps content-hashed artifacts for fast incremental rebuilds.
> `zig build clean` clears it. It stays out of git.

## License

Zat4 is free software, licensed under the GNU Affero General Public License,
version 3 or (at your option) any later version (AGPL-3.0-or-later). The full
text lives in [`LICENSE`](LICENSE), and every source file carries the licence
header.

Because Zat4 runs over a network, the AGPL's section 13 applies: anyone who
interacts with a running instance is offered its Corresponding Source. Zat4
honors this with a persistent, visible source link in the UI (the sidebar
footer) that points back to this repository at
`codeberg.org/connoravila/Zat4`. A deployed modification should keep that
link pointing at its own modified source.

Bundled components keep their own licences, retained in their files: the
`stb_truetype` rasterizer (`vendor/`, public domain) and the embedded UI font
(BSD-2-Clause, notice in `src/core/font.zig`). Both are compatible with the
AGPL and leave the licensing of the project's own code unchanged.
