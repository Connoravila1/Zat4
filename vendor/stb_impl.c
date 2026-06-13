/*
 * F1 note (the one third-party import in this project, per the GUI
 * roadmap §4's pre-written justification):
 *
 *   stb_truetype.h v1.26 — single-file, public-domain TrueType
 *   rasterizer (Sean Barrett / RAD Game Tools).
 *
 *   What it does: turns a .ttf outline + a pixel size into an
 *   antialiased coverage bitmap + metrics.
 *
 *   Why we do not write it ourselves (yet): a correct vector glyph
 *   rasterizer is a multi-week numeric sub-project (roadmap Option B);
 *   stb is one vetted file with zero transitive dependencies — the
 *   same "single vetted file" bar we hold our own code to.
 *
 *   Cost to remove: swap text.zig's engine body for Option B behind
 *   the unchanged coverage interface; nothing else in the app learns.
 *
 *   Caveat (from stb's own docs): no bounds-checking on untrusted font
 *   files. zat ships its OWN embedded fonts (assets/IBMPlexSans-*.ttf,
 *   OFL-licensed, license reproduced beside them) and NEVER loads user
 *   font files — which removes that attack surface entirely.
 *
 * Build notes: compiled with -fno-sanitize=undefined (stb performs
 * intentional unaligned/sign tricks that trip UBSan in debug builds);
 * this is the upstream-recommended posture for stb headers.
 */
#define STB_TRUETYPE_IMPLEMENTATION
#include "stb_truetype.h"
