# screencast reference

Deeper detail for `SKILL.md`'s summaries. Read that first.

File names such as `screencast/timeline.py` are relative to the installed package; in the
repository they are under `src/`.

## Timeline schema v2, field by field

`screencast/schema/timeline.schema.json` is the source of truth;
`screencast/timeline.py`'s `Timeline` class validates against it on
every load/construction. A document:

```json
{
  "version": 2,
  "observer": {"name": "cockpit", "video": "page@abc123.webm"},
  "actors": [
    {"actor": "author", "video": "page@def456.webm", "offset": 12.34, "duration": 45.6}
  ],
  "events": [
    {"type": "turn_start", "time": 12.34, "actor": "author"},
    {"type": "chapter", "time": 12.34, "eyebrow": "Story · 1/5", "title": "Author",
     "subtitle": "Drafting", "duration": 8.0},
    {"type": "focus", "time": 20.0, "view": "observer", "scale": 0.4, "margin": 24, "border": 3},
    {"type": "turn_end", "time": 58.0, "actor": "author"},
    {"type": "hold", "time": 58.0, "duration": 12.0, "view": "observer"},
    {"type": "caption", "time": 30.0, "text": "Alice submits the form", "duration": 4.0},
    {"type": "wait", "time": 40.0, "duration": 2.5, "keyword": "Wait For Order"}
  ]
}
```

- **`version`** — the composer/verifier refuse anything but `2`, loudly.
- **`observer.video`** — the one recording spanning the whole take. All
  other times (`actors[].offset`, every event's `time`) are seconds on
  *this* clip's own clock.
- **`actors[]`** — one entry per recorded turn. `offset` is when the actor's
  context was *created* (`time.monotonic() - started`, captured by `Start
  Actor Turn`), not when the turn's first click happened. `duration` is
  written by `End Actor Turn` from the real elapsed time; the composer
  re-measures it with `ffprobe` anyway and does not trust a stale value.
- **`events[].time`** — always on the observer's clock, same units as
  `actors[].offset`.
- **`chapter`** — a title card. `duration` is how long the composer holds
  it; no browser time is spent waiting for it.
- **`focus`** — which recording (`"actor"` or `"observer"`) is main from
  this point on. `scale`/`margin`/`border` (defaults 0.4/24/3) describe the
  *other* one's inset.
- **`hold`** — freeze the current frame(s) for `duration` extra seconds.
  `view` (default `"observer"`) is which side is "current" for freezing
  purposes when a hold coincides with a turn boundary. A hold with
  `"recorded": true` is real elapsed recording time the library itself
  noted (the wait after a turn ends, while the observer is brought back to
  the front): the composer inserts no synthetic freeze for it.
- **`caption`** — a subtitle cue. The composer maps `time` (observer clock) to
  the composed output's clock, adding every title card and hold inserted at
  or before it, and writes `output.vtt` next to `output.webm`.
- **`wait`** — recorded by the library's listener around the outermost
  waiting keyword (`Sleep`, `Wait Until Keyword Succeeds`, the engine's own
  waits, or a keyword tagged `screencast:wait`), for waits of 0.25 s or more.
  The composer ignores it; `verify`'s `dead_air` check judges it.

`screencast.timeline.OVERLAP_TOLERANCE` (1.5s) is not a schema field — it's
the composer's tolerance for encoder-startup jitter between a
`time.monotonic()` offset and ffprobe's measured duration, so two
back-to-back turns with near-zero real gap don't spuriously fail the
overlap check. An overlap *larger* than that is a real bug: two actor
contexts were open at once, which `Start Actor Turn`/`End Actor Turn`
should never allow.

## The composer's segment algorithm

`screencast/compose.py`'s module docstring has the policy; this is
the mechanism.

1. Collect every turn's `(actor, start, end)` window from `turn_start`/
   `turn_end` events, and every `focus`/`chapter`/`hold` event's time.
2. Build a sorted list of **boundaries**: `0`, the observer's total
   duration, every turn start/end, every event time (all clamped to
   `[0, observer_duration]` — a `time.monotonic()` timestamp can land a few
   milliseconds past ffprobe's measured length from encoder flush latency;
   clamping instead of dropping is what stops a trailing hold from silently
   never rendering).
3. Walk consecutive boundary pairs `(start, end)`. For each: emit any
   chapter/hold whose event time equals `start` (a title card or freeze
   inserted *before* this segment — pure insertion, consumes no recorded
   time from either source), then resolve `(view, inset_actor, scale,
   margin, border)` at the segment's midpoint via `_view_at()` (the default
   policy from `SKILL.md`), and build the segment: a `trim`+`scale` of the
   main source, an inset built from the other source (live footage if that
   actor's turn is still technically open, otherwise their last frame
   frozen with `tpad=stop_mode=clone`), composited with `overlay`.
4. A **trailing** chapter/hold whose time equals the very last boundary
   never becomes any segment's `start` (nothing follows it) — emitted once
   more, explicitly, after the loop.
5. Every source slice is normalized to `scale=1920:1080` before concat:
   nothing guarantees a source clip was recorded at exactly that size (a
   differently configured viewport, or in `tests/test_compose.py`, a
   synthetic stand-in clip), and `concat` requires uniform frame size.
6. All segments concatenate, in order, into `[out]`.

Title cards are rendered once per distinct `(eyebrow, title, subtitle,
duration)` and cached in `<take_dir>/titles/`; composing the same timeline
twice does not re-render them.

## Writing a new `verify` check

`screencast/verify.py`'s `verify()` returns
`{"ok": bool, "findings": [...], ...}`; each finding is
`{"check": str, "severity": "error", "message": str}`. To add one:

1. Write the detection as its own function, real ffmpeg/ffprobe underneath
   (see `detect_black_intervals()`/`frame_luma_range()`
   for the existing patterns — a filter run with `-f null -`, parsed from
   stderr, or a raw-pixel pipe for a single-frame sample).
2. Call it from `verify()`, append a finding dict on a problem.
3. Test it in `tests/test_verify.py` against a real synthetic clip
   (`make_clip`/`make_animated_clip`) that should and shouldn't trigger it —
   see `test_detect_black_intervals_ignores_a_dark_but_not_black_theme` for
   why a "should not trigger" case matters as much as a "should".

Calibrate new checks against real footage, not generic defaults —
`blackdetect`'s default `pix_th` (10% luma) flags the dark-navy title cards
(`#0f172a`) as black, which is exactly why `verify.py` tightens it to `0.02`.
A check is only worth having if it can tell a healthy take from a broken one
on real recordings: a whole-frame freeze check could not (a healthy take's
longest frozen stretch was longer than that of a take with a deliberate 12 s
sleep), and was removed in favour of judging dead air from the timeline.

## What CI covers

The engine's own tests (schema, the library against a fake Playwright, the
driver, the composer and verifier against real ffmpeg on synthetic clips) run
on Python 3.10 and 3.13 with the oldest supported and the latest Robot
Framework. They never run a real story's content: that needs the application
it records. After any change that could affect a story's selectors or flow,
run the story (`screencast run`, or with `--no-record` while iterating) against
your application by hand, then `compose` and `verify` it.

## Recording by hand, without the engine

The engine covers a scripted, multi-actor take. For a one-off recording that does
not need it — a single page, a terminal, a quick edit — these are the raw pieces.
The `browser` skill has the basic 25 fps `record_video_dir` setup they build on.
The engine already does the cursor, human pacing, offset-aware composition,
picture-in-picture focus and verification, so do not re-implement those by hand.

### Chapter transitions and HTML overlays (`page.screencast`)

For recorded demos or verification walkthroughs, `page.screencast` provides
chapter title cards and live annotations overlaid onto the page:

```python
import os
from playwright.sync_api import sync_playwright

OUTPUT_DIR = "/tmp/playwright-output"
os.makedirs(OUTPUT_DIR, exist_ok=True)
video_path = os.path.join(OUTPUT_DIR, "screencast.webm")

with sync_playwright() as p:
    browser = p.chromium.launch(
        headless=True,
        args=["--no-sandbox", "--disable-dev-shm-usage"],
    )
    page = browser.new_page(viewport={"width": 1280, "height": 720})

    # Start 25 fps recording to file
    page.screencast.start(path=video_path, size={"width": 1280, "height": 720})
    page.goto("https://example.com")

    # Full-screen chapter card (blurs background, auto-dismisses after duration)
    page.screencast.show_chapter("Introduction", description="Opening demo page", duration=2000)
    page.wait_for_timeout(1000)

    # Sticky HTML overlay annotation (pointer-events: none)
    page.screencast.show_overlay(
        """
        <div style="position: absolute; top: 16px; right: 16px;
                    padding: 8px 16px; background: rgba(0,0,0,0.75);
                    border-radius: 8px; font-family: sans-serif;
                    font-size: 14px; color: white;">
            ⚡ Navigated successfully
        </div>
        """,
        duration=2000,
    )
    page.wait_for_timeout(2500)

    # Finalize recording
    page.screencast.stop()
    browser.close()
```

### Simulated cursor and click annotations (`show_actions`)

Headless recordings have no OS mouse pointer, which can make a recorded demo
hard to follow. `page.screencast.show_actions()` draws a simulated cursor and a
caption for each interacted element:

```python
page.screencast.start(path="demo.webm")

with page.screencast.show_actions(cursor="pointer", position="bottom-left"):
    page.get_by_label("Event Title").fill("Wrobocon Demo Day")
    page.get_by_role("button", name="Complete").click()

page.screencast.stop()
```

`show_actions(duration=500, position="bottom|bottom-left|bottom-right|top|top-left|top-right", font_size=None, cursor="pointer"|"none")`
returns a disposable that can be used as a context manager, or hidden with
`hide_actions()`. Wrap it around the whole driven sequence rather than each
action individually.

There is no parameter to resize the cursor or click-point dot, or to suppress
the caption text; `font_size` only scales the caption. These elements live in
an `x-pw-glass` element with a closed shadow root and are redrawn internally,
so treat the cursor, dot, and caption as fixed-size and always-captioned. Raw
CDP attribute overrides are clobbered by the redraw loop; an event-driven
override requires the async API, so it is not a practical workaround for a
sync-API script.

### Multiple concurrent recordings

Each `Page` owns its own screencast, so unrelated pages can record
independently in the same script:

```python
page_a.screencast.start(path="a.webm")
page_b.screencast.start(path="b.webm")
# Drive page_a while page_b records untouched in the background.
page_a.screencast.stop()
page_b.screencast.stop()
```

This is useful for recording multiple sources separately and combining them
later with `ffmpeg`.

### Transcoding to MP4 or GIF

WebM is the native capture format. If downstream tools or presentation viewers
require MP4 (H.264) or animated GIF, transcode on demand using Nix:

```sh
# Convert 25 fps WebM to 25 fps MP4 (H.264, universally compatible)
nix shell --impure --expr \
  'with (builtins.getFlake "nixpkgs").legacyPackages.${builtins.currentSystem}; ffmpeg-headless' \
  --command ffmpeg -i /tmp/playwright-output/screencast.webm -c:v libx264 -pix_fmt yuv420p -r 25 /tmp/playwright-output/screencast.mp4

# Convert 25 fps WebM to optimized 25 fps animated GIF
nix shell --impure --expr \
  'with (builtins.getFlake "nixpkgs").legacyPackages.${builtins.currentSystem}; ffmpeg-headless' \
  --command ffmpeg -i /tmp/playwright-output/screencast.webm -vf "fps=25,scale=800:-1:flags=lanczos,split[s0][s1];[s0]palettegen[p];[s1][p]paletteuse" /tmp/playwright-output/screencast.gif
```

### Recording a headless terminal and compositing with browser

A terminal session running headlessly inside the sandbox can be recorded the
same way as any other page: run `ttyd` on loopback and drive/record it with
Playwright. The loopback binding below is intentional for sandbox-local
Playwright. If a host browser must reach ttyd, publish the port and bind ttyd
to `0.0.0.0` instead; `0.0.0.0` is not required for an in-sandbox recording.

```sh
nix shell --impure --expr \
  'with (builtins.getFlake "nixpkgs").legacyPackages.${builtins.currentSystem}; ttyd' \
  --command ttyd -p 7681 -i 127.0.0.1 -W bash &
```

Navigate to it, click the terminal to focus the xterm.js instance, then type
like a human:

```python
page.goto("http://127.0.0.1:7681", wait_until="networkidle")
page.screencast.start(path="/tmp/playwright-output/terminal.webm")
page.click(".xterm")
page.keyboard.type("some-command --here", delay=40)
page.keyboard.press("Enter")
page.wait_for_timeout(5000)
page.screencast.stop()
```

To show it alongside a browser recording, the simplest zero-desync option is
a single wrapper HTML page with two `<iframe>`s — one for the web app, one for
`http://127.0.0.1:7681` — recorded as one tab. Compositing two already-recorded
videos afterward (side-by-side, picture-in-picture) is also possible with
`ffmpeg`'s `hstack`/`overlay` filters if the wrapper-page approach doesn't fit.

### Compositing recordings with ffmpeg: PiP overlay and concat

Scale an inset recording and overlay it in a corner:

```sh
ffmpeg -y -i main.webm -i inset.webm -filter_complex "\
  [1:v]scale=380:-2,pad=iw+6:ih+6:3:3:color=0x1f2937[pip]; \
  [0:v][pip]overlay=x=W-w-24:y=H-h-24,format=yuv420p[outv]" \
  -map "[outv]" -c:v libx264 -pix_fmt yuv420p -r 25 composited.mp4
```

Two details in that filter earn their place. `scale=380:-2` (not `-1`) keeps
**both** dimensions even, which `yuv420p` requires — `-1` can produce an odd
height and fail the encode. The `pad` draws a 3 px border: a light page inset
on a light main view has no edge at all without one, and simply looks like part
of the page.

> **Do not add `overlay=...:shortest=1` by reflex.** It ends the output at the
> *shorter* input. If the inset outlasts the main video, the tail of the
> composite is silently cut — and since the source clips still contain
> everything, the loss is invisible unless you watch the composite itself.
> Reach for it only when you have checked which input is shorter and you
> actually want the output truncated there. Otherwise build both tracks to the
> same length.

Join already-encoded, same-resolution and same-fps parts with the concat
demuxer. Use a plain file list when stream copying is sufficient:

```sh
printf "file '%s'\nfile '%s'\n" "$(pwd)/part1.mp4" "$(pwd)/part2.mp4" > list.txt
ffmpeg -y -f concat -safe 0 -i list.txt -c copy final.mp4
```

### Making a final cut with fades

For a two-clip edit with a one-second dissolve, trim the first clip to six
seconds and start the transition at five seconds. `acrossfade` keeps the audio
transition aligned with the video transition:

```sh
ffmpeg -y -i part1.mp4 -i part2.mp4 -filter_complex "\
  [0:v]trim=duration=6,setpts=PTS-STARTPTS[v0]; \
  [1:v]setpts=PTS-STARTPTS[v1]; \
  [v0][v1]xfade=transition=fade:duration=1:offset=5[v]; \
  [0:a]atrim=duration=6,asetpts=PTS-STARTPTS[a0]; \
  [1:a]asetpts=PTS-STARTPTS[a1]; \
  [a0][a1]acrossfade=d=1:c1=tri[a]" \
  -map "[v]" -map "[a]" -c:v libx264 -pix_fmt yuv420p -r 25 \
  -c:a aac -b:a 192k final.mp4
```

The general rule is `xfade`'s `offset = first-clip-duration - transition-duration`.
For more clips, chain another `xfade` and `acrossfade`, using the accumulated
output duration for the next offset. Add a fade at the beginning or end when
there is no neighboring clip:

```sh
ffmpeg -y -i final.mp4 -vf \
  "fade=t=in:st=0:d=0.5,fade=t=out:st=11.5:d=0.5" \
  -af "afade=t=in:st=0:d=0.5,afade=t=out:st=11.5:d=0.5" \
  -c:v libx264 -pix_fmt yuv420p -c:a aac faded.mp4
```

Adjust the final fade's `st` to the actual duration of the edited file. When
the clips have no audio stream, omit the audio filters and `-map "[a]"`.
