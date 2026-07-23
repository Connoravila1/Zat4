# Sound assets — attribution

The user-interface sounds in this directory are derived from the **Material
Design Sound Resources** by **Google**, used under the
**Creative Commons Attribution 4.0 International (CC-BY 4.0)** license.

- Source: https://github.com/material-foundation/material-design-sound-resources
- License: https://creativecommons.org/licenses/by/4.0/

**Modifications:** the original 48 kHz / 24-bit stereo WAVs were folded to mono,
anti-alias low-pass filtered and downsampled to 24 kHz / 16-bit PCM, and trimmed
of leading/trailing silence. A subset was selected and renamed to the app's
event names (see `core/sfx.zig`). No other alteration was made.

CC-BY 4.0 requires that this attribution ship with the application. It is
surfaced in-app under Settings → About / Licenses.

## File → original source

| File            | Original |
|-----------------|----------|
| `tap.wav`         | `ui_tap-variant-01` |
| `key.wav`         | `ui_tap-variant-04` |
| `hover.wav`       | `navigation_hover-tap` |
| `nav_forward.wav` | `navigation_forward-selection-minimal` |
| `nav_back.wav`    | `navigation_backward-selection-minimal` |
| `like.wav`        | `ui_tap-variant-03` |
| `unlike.wav`      | `ui_tap-variant-02` |
| `send.wav`        | `navigation_selection-complete-celebration` |
| `msg_receive.wav` | `notification_simple-01` |
| `notify.wav`      | `notification_decorative-01` |
| `error.wav`       | `alert_error-01` |
| `refresh.wav`     | `ui_refresh-feed` |
| `unavailable.wav` | `navigation_unavailable-selection` |
| `success.wav`     | `hero_simple-celebration-01` |
| `ringtone.wav`    | `ringtone_minimal` |
