# Browser — advanced patterns

Read `SKILL.md` first. The headless sections assume `playwright-python` is
what you reach for; this file covers what it wraps and when to bypass it.

## The raw `nix build`/`nix shell` invocation

`playwright-python script.py` (see `SKILL.md`) is this, wrapped into one
command:

```sh
export PLAYWRIGHT_BROWSERS_PATH=$(nix build --impure --expr \
  'with (builtins.getFlake "nixpkgs").legacyPackages.${builtins.currentSystem}; playwright-driver.browsers' \
  --no-link --print-out-paths) && \
nix shell --impure --expr \
  'with (builtins.getFlake "nixpkgs").legacyPackages.${builtins.currentSystem}; python3.withPackages (ps: [ ps.playwright ])' \
  --command python3 script.py
```

Reach for this instead of the wrapper when the shell needs more than
`python3` + Playwright — extra fonts (below), other packages — or when
running outside this image, where `playwright-python` isn't on `PATH`.
**Don't rely on the `export` surviving into a later tool call** — if your
next command is a separate shell invocation, this variable is gone. Keep it
and whatever uses it in one invocation, or write it into the script/session
you're about to run rather than a throwaway shell line.

## Fonts, in full

The image ships `dejavu_fonts` and `liberation_ttf` and sets `FONTCONFIG_FILE`,
which covers Latin text. It does not ship a full desktop font set: CJK,
Arabic, Devanagari and emoji all render as boxes or nothing.

`pkgs.makeFontsConf` is nixpkgs' own helper for this (it's what NixOS's
headless-browser tests use) — it builds a `fonts.conf` pointing at the font
packages you give it, with no need for a real `/etc/fonts` to exist:

```sh
nix build --impure --expr \
  'with (builtins.getFlake "nixpkgs").legacyPackages.${builtins.currentSystem};
   makeFontsConf { fontDirectories = [ dejavu_fonts liberation_ttf noto-fonts-color-emoji ]; }' \
  --no-link --print-out-paths
```

Add `noto-fonts-color-emoji` (or other script-specific font packages) if the
pages you're rendering need non-Latin scripts or emoji.

Note that a `nix shell --command` inherits `FONTCONFIG_FILE` from the
environment, so the image's value applies unless something overrides it. To
debug font resolution directly, add `fontconfig` to a `nix shell` and run
`fc-list` — it lists every font the active config wired in.

## Filling forms, waiting, multiple tabs

```python
page.fill("#email", "user@example.com")
page.select_option("#country", label="Finland")
page.check("#agree-to-terms")

page.wait_for_selector("text=Loading…", state="hidden")
page.wait_for_url("**/dashboard")

# a second tab/popup opened by the page
with page.expect_popup() as popup_info:
    page.click("a[target=_blank]")
popup = popup_info.value
popup.wait_for_load_state()
```

`page.goto(url, wait_until=...)` accepts `"load"`, `"domcontentloaded"`, or
`"networkidle"` — prefer `"load"` for typical pages; `"networkidle"` is slower
and unnecessary unless the page keeps polling in the background.

### Downloading a file and displaying it

A download is not a popup. Capture it with `expect_download`, save the file,
then open it in a fresh page to show its content:

```python
with page.expect_download() as dl_info:
    page.get_by_text("Download").click()
download = dl_info.value
download.save_as("/tmp/playwright-output/report.html")

viewer = context.new_page()
viewer.goto("file:///tmp/playwright-output/report.html")
```

## PDF export

Only Chromium supports it (`p.chromium`, not `p.firefox`/`p.webkit`), and only
in headless mode:

```python
page.pdf(path="page.pdf", format="A4")
```

## Output directory

Write screenshots, traces, and PDFs to a fixed scratch directory rather than
scattering them wherever a script happens to run — `/tmp/playwright-output`
is a reasonable default. Create it fresh at the top of a script:

```python
import os
import shutil
OUTPUT_DIR = "/tmp/playwright-output"
shutil.rmtree(OUTPUT_DIR, ignore_errors=True)
os.makedirs(OUTPUT_DIR)
```

This is container-local, not a host mount — it disappears with the session.
Read results back with the agent's own tools (e.g. Claude Code's `Read` for a
screenshot) before the session ends rather than expecting the directory to
persist.

## Video and screencasts

See `SKILL.md` for the base recording setup (25 fps, WebM/VP8 via the bundled
`ffmpeg`). The rest of this section builds on that: chapter titles and HTML
overlays, transcoding, and compositing in a terminal recording.

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

### Human-paced cursor and clicks

`show_actions` above is page-scoped and rides on `page.screencast`. When you
record at **context** level with `record_video_dir` — which is what you need to
record several actors as separate clips (see *Composing several recordings*
below) — inject your own cursor with `context.add_init_script()`. That also
gives you a cursor with no caption text and a size you control, which
`show_actions` does not.

Init scripts run on **every new document** in the context, so this survives
navigation automatically:

```python
CURSOR_SCRIPT = """
(() => {
  const install = () => {
    const style = document.createElement('style');
    style.textContent = `
      #pw-cursor {
        position: fixed; left: 50%; top: 50%; z-index: 2147483647;
        width: 24px; height: 24px; border: 2px solid #ff3b30;
        border-radius: 50%; pointer-events: none;
        transform: translate(-50%, -50%); box-shadow: 0 0 0 2px white;
      }
      .pw-click {
        position: fixed; z-index: 2147483646; width: 56px; height: 56px;
        border: 4px solid #ff3b30; border-radius: 50%; pointer-events: none;
        transform: translate(-50%, -50%); animation: pw-click .8s ease-out;
      }
      @keyframes pw-click {
        from { opacity: .95; transform: translate(-50%, -50%) scale(.35); }
        to   { opacity: 0;   transform: translate(-50%, -50%) scale(1.25); }
      }
    `;
    document.documentElement.appendChild(style);
    const cursor = document.createElement('div');
    cursor.id = 'pw-cursor';
    document.documentElement.appendChild(cursor);
    document.addEventListener('mousemove', event => {
      cursor.style.left = `${event.clientX}px`;
      cursor.style.top = `${event.clientY}px`;
    }, true);
    document.addEventListener('click', event => {
      const ring = document.createElement('div');
      ring.className = 'pw-click';
      ring.style.left = `${event.clientX}px`;
      ring.style.top = `${event.clientY}px`;
      document.documentElement.appendChild(ring);
      ring.addEventListener('animationend', () => ring.remove());
    }, true);
  };
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', install, {once: true});
  } else {
    install();
  }
})();
"""

context = browser.new_context(
    viewport={"width": 1920, "height": 1080},
    record_video_dir="/tmp/playwright-output",
    record_video_size={"width": 1920, "height": 1080},
)
context.add_init_script(CURSOR_SCRIPT)
```

Three details that are easy to get wrong:

- **Guard on `DOMContentLoaded`.** An init script can run before
  `document.documentElement` exists; appending to it unguarded throws and you
  get no cursor at all, silently.
- **Use capturing listeners** (`true` as the third argument). A page that stops
  propagation on its own handlers would otherwise swallow the events your
  cursor needs.
- **Remove each click ring on `animationend`**, or they accumulate in the DOM
  for the length of the recording.

### Pacing it for human eyes

Playwright's own `click()` and `fill()` are instantaneous — correct for tests,
unwatchable in a demo. Wrap them so the pointer travels, hovers, clicks, and
rests:

```python
def human_move(page, locator):
    locator.scroll_into_view_if_needed()
    box = locator.bounding_box()
    assert box
    page.mouse.move(
        box["x"] + box["width"] / 2,
        box["y"] + box["height"] / 2,
        steps=18,                       # interpolated => a visible glide
    )
    page.wait_for_timeout(450)          # hover beat, so the target registers

def human_click(page, locator):
    human_move(page, locator)
    locator.click()
    page.wait_for_timeout(850)          # let the click ring play out

def human_fill(page, locator, value):
    human_click(page, locator)
    locator.fill("")
    locator.press_sequentially(value, delay=75)   # ~13 chars/sec
    page.wait_for_timeout(650)
```

`steps=18` is what turns a teleport into a glide — `mouse.move()` without it
jumps in one frame and the cursor simply appears elsewhere. These defaults
(450 ms hover, 850 ms after a click, 75 ms per keystroke) read as unhurried but
not sleepy at 25 fps; scale them together if you want a different tempo.

**After every navigation, move the pointer again before clicking.** The new
document re-runs the init script, which recreates the cursor at its CSS default
(centred) — so the first `human_click` on a fresh page starts its glide from the
middle of the viewport regardless of where the pointer "was". Ending a page's
sequence with a `human_move` onto the next thing also gives the viewer
somewhere to look while the next page loads.

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
> same length, as below.

Join already-encoded, same-resolution and same-fps parts with the concat
demuxer. Use a plain file list when stream copying is sufficient:

```sh
printf "file '%s'\nfile '%s'\n" "$(pwd)/part1.mp4" "$(pwd)/part2.mp4" > list.txt
ffmpeg -y -f concat -safe 0 -i list.txt -c copy final.mp4
```

### Composing several recordings onto one timeline

Recording one actor per context (a visitor, an admin, an observer) gives clips
that all ran against the same wall clock but start at different moments and
have different lengths. Concatenating them throws that timing away: the inset
then shows the wrong actor at the wrong moment, and the composite is whatever
length the concat happened to produce.

Keep the timing instead. Note when each recorded page is created, relative to
whichever clip is the main view:

```python
main_page = main_ctx.new_page()          # the observer / main view
started = time.monotonic()
...
actor_page = actor_ctx.new_page()
offset = time.monotonic() - started      # where this clip belongs
```

Then place each clip at its offset with `tpad`, holding the adjacent frame
across the gaps so the inset is continuous:

```
[1:v]trim=start=0.8,setpts=PTS-STARTPTS,
     tpad=start_duration=<offset>:start_mode=clone
         :stop_duration=<gap>:stop_mode=clone,fps=25[a];
[2:v]trim=start=0.8,setpts=PTS-STARTPTS,
     tpad=stop_duration=<tail>:stop_mode=clone,fps=25[b];
[a][b]concat=n=2:v=1:a=0[inset];
[0:v]trim=start=0.8,setpts=PTS-STARTPTS[main];
[main][inset]overlay=W-w-24:H-h-24,format=yuv420p[out]
```

- `start_mode`/`stop_mode` must be **`clone`**; the default `add` pads with
  black.
- Trim the same settle (≈0.8 s) off **every** clip, main included. Each one
  opens blank while its first document paints — on an inset clip those frames
  are what `clone` would hold, and on the main clip they are what the composite
  opens on. Trimming the main track by the same amount also makes each inset
  clip's lead-in exactly its recorded offset, with no correction term.
- Size the pads from the measured durations so the inset track comes out
  exactly as long as the trimmed main track. Then no `shortest` is needed and
  nothing is dropped. Compute the holds in the script and assert they are
  non-negative — a negative hold means the contexts overlapped, i.e. you opened
  the next actor before closing the previous one.
- Pass `-v error -nostats` to the encode. FFmpeg's banner and per-frame
  progress otherwise bury your own script's output.

### Animating PiP focus during page activity

For a demonstration with a main observer view and an active actor view, the
inset can take focus while the actor is being driven instead of remaining
small in the corner. Record action intervals for each actor, merge intervals
whose gaps are short enough to be one interaction, and use those windows as
the animation timeline:

```python
FOCUS_SCALE = 0.8       # active inset: 80% of the frame, centered
FOCUS_FADE = 0.6        # seconds to ease in and out
FOCUS_MERGE_GAP = 1.5   # coalesce typing/click bursts
```

Keep the normal inset at 40% in the bottom-right corner. During an activity
window, interpolate its scale from 40% to 80% and its position from the corner
to the centered position; interpolate back after the window ends. A cosine
ease such as `0.5 - 0.5*cos(PI*u)` avoids abrupt starts and stops. Evaluate
both `scale` and `overlay` per frame so the position follows the changing
inset dimensions:

```text
focus = eased_activity_window_factor(t)
factor = 0.4 + (0.8 - 0.4) * focus
inset_w = even(1920 * factor)
inset_h = even(1080 * factor)
x = corner_x + ((W - w) / 2 - corner_x) * focus
y = corner_y + ((H - h) / 2 - corner_y) * focus
```

Use the recorded action timestamps after subtracting the same head trim used
by the composition. Keep the focus windows independent of the clip padding:
`tpad` still establishes the actor's wall-clock position, while the activity
windows only control the visual transition. This keeps Cockpit visible when
nothing is happening and makes form filling, navigation, and approval readable
when they are happening.

### Verifying a recording

Every interesting way a recording goes wrong — truncated tail, blank lead-in,
a frozen page for half the clip, an inset that never appears — exits 0 and
produces a file that plays. Check the artifact, not the exit status.

**Duration and geometry**, against what you expected:

```sh
ffprobe -v error -show_entries format=duration \
  -show_entries stream=width,height,r_frame_rate,codec_name \
  -of default=noprint_wrappers=1 out.webm
```

A composite should equal the length of its main track. Anything shorter means
something was cut.

**Look at the whole thing at once.** A contact sheet turns dead air, a missing
inset and a wrong ordering into one image you can read in a glance:

```sh
ffmpeg -y -i out.webm -vf 'fps=0.5,scale=520:-1,tile=6x4' -frames:v 1 sheet.png
```

`fps=0.5` samples every 2 s; `tile=RxC` must cover the clip (`6x4` = 24 tiles =
48 s here) or the tail is not shown. Then read `sheet.png` with your own image
tool. Repeated identical tiles are dead air; white tiles are an unpainted page.

**Scan for blank frames** rather than trusting your eye on a thumbnail grid. A
blank region compresses to almost nothing, which makes file size a reliable
detector:

```sh
for t in $(seq 0 0.5 48); do
  ffmpeg -v error -y -ss "$t" -i out.webm -frames:v 1 -vf 'crop=1100:900:0:100' /tmp/f.png
  s=$(stat -c%s /tmp/f.png)
  [ "$s" -lt 30000 ] && echo "BLANK at t=$t (${s}B)"
done
```

Crop to the region you care about (here, excluding a corner inset) so an inset
that is legitimately light does not mask a blank main view. Tune the threshold
to the content: a sparse page is small too, so compare against a known-good
frame from the same recording before trusting a number.

Two blank sources worth knowing, both fixable in the script rather than the
edit: a clip's own first frames before the document paints (trim them), and a
full-page `reload()` of a single-page app, which re-bootstraps the framework
and can blank the view for about a second in the middle of the recording.
Prefer an in-app navigation — click through the UI to the same route — when you
need a view to re-query its data on camera.

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

## Raw CDP fallback

If Playwright itself is undesirable (want the browser process directly, or the
Python/driver combo is broken), Chromium can be driven over the Chrome
DevTools Protocol without Playwright:

```sh
nix shell --impure --expr \
  'with (builtins.getFlake "nixpkgs").legacyPackages.${builtins.currentSystem};
   [ chromium fontconfig dejavu_fonts liberation_ttf ]' \
  --command chromium --headless=new --no-sandbox --disable-dev-shm-usage \
  --remote-debugging-port=9222 --remote-debugging-address=127.0.0.1
```

This exposes a WebSocket CDP endpoint (`http://127.0.0.1:9222/json/version`
lists it) — but you still need a CDP client to do anything with it (e.g.
Playwright's own `chromium.connect_over_cdp(...)`, or a raw websocket library
sending `Page.navigate` / `Page.captureScreenshot` calls by hand). This is
materially more work than launching through Playwright directly and is a last
resort, not a default.

## Version skew between playwright and playwright-driver

On nixpkgs-unstable these can drift by a patch release — observed live:
`python3Packages.playwright` at `1.61.0` while `playwright-driver` (and hence
`playwright-driver.browsers`) was already at `1.61.1`. This is expected, not a
bug to chase: the Python package always symlinks its driver to whatever
`playwright-driver` currently resolves to in the same nixpkgs snapshot
(`pkgs/development/python-modules/playwright/default.nix`), and both carry a
`skipBulkUpdate` marker specifically so they get bumped together by the
project's own update script. A one-patch gap between snapshots doesn't break
anything in practice. If exact reproducibility ever matters (e.g. pinned CI),
pin the whole expression to one nixpkgs revision instead of trying to pin the
two packages independently:

```sh
nix build --impure --expr \
  'with (builtins.getFlake "nixpkgs/nixos-25.05").legacyPackages.${builtins.currentSystem}; ...'
```

## A browser the user already had open

`agent-sandbox browser` is the path to prefer: it is disposable, it carries an
allow list, and it prints the relaunch line. But the user may have their own
Chrome open already — with their logins, their extensions, a session they do
not want to recreate — and want *that* driven.

That browser is not policed by anything. What it fetches is on their account,
and `--host-loopback-port` is a channel the sandbox's proxy never sees. Say so
when suggesting it, and treat it as the exception.

They need two things, in one message:

```sh
google-chrome --user-data-dir=/tmp/cdp-profile \
              --remote-debugging-port=9222 \
              --remote-debugging-address=127.0.0.1
# or chromium, same flags
```

```sh
agent-sandbox --host-loopback-port 9222 -- <their usual command>
```

The separate `--user-data-dir` is **required**, not optional: Chrome 136+
refuses `--remote-debugging-port` on the default profile outright, and an
already-running Chrome silently ignores the flag. Keep
`--remote-debugging-address` on `127.0.0.1`, never `0.0.0.0` — CDP has no
authentication, so reachability is the only thing standing between "the sandbox
can drive this tab" and "anything on the network can read every cookie and run
arbitrary JS in it."

If the sandbox already has something on 9222, the user can move the inside
number: `--host-loopback-port 9222:19222` puts the host's 9222 on the sandbox's
19222, and `$AGENT_SANDBOX_HOST_PORTS` then lists `19222`.

Attach with `connect_over_cdp` exactly as in `SKILL.md`.

## Debugging checklist

| Symptom | Cause | Fix |
| --- | --- | --- |
| Screenshot is a flat, uniform color | no usable fonts | check `$FONTCONFIG_FILE` and `fc-list`; rebuild it with the scripts the page needs (see above) |
| `page.goto()` hangs or times out | proxied sandbox denying the host | check `$HTTPS_PROXY`, pass it explicitly, ask for `ctl policy allow` |
| "Failed to move to new namespace" / renderer crash | container can't create Chromium's own sandbox | add `--no-sandbox` to `launch(args=[...])` |
| Renderer crashes under load, blank/partial screenshot | `/dev/shm` too small (often 64 MB in containers) | add `--disable-dev-shm-usage` |
| `browserType.launch` complains about a missing executable | `PLAYWRIGHT_BROWSERS_PATH` unset — running raw `python3` instead of `playwright-python`, or `export`ed in a separate tool call that didn't carry into this one | use `playwright-python`, or re-derive it in the *same* command as the failing one, see `SKILL.md` |
| `$AGENT_SANDBOX_HOST_PORTS` is unset, or missing the port | launched without `--browser`, so nothing reaches the host's `127.0.0.1:9222` | ask the user to run `agent-sandbox browser`, then relaunch with `--browser`, see `SKILL.md` |
| `connect_over_cdp` refuses/times out with the port listed | the channel exists, so nothing is listening on the host's `127.0.0.1:9222` | the browser was closed, or a hand-started Chrome had no separate `--user-data-dir` |
| `$AGENT_SANDBOX_BROWSER_CDP_PORT` is unset even though the port is reachable | relaunched with a bare `--host-loopback-port` instead of `--browser` | use `--browser`, or add the variable with `-e` |
| Only one browser reachable when two were started | the second was started after the sandbox, so `--browser` never saw it | start every browser before the sandbox; the channel is set at launch |
| `ctl policy … --browser` says several browsers are running | more than one session, so the target is ambiguous | name one: `--browser alice` |
| A page in the host browser fails to load, `curl` from here reaches it | the browser's allow list is separate from the sandbox's | `agent-sandbox ctl policy allow <host>:443 --browser` |
| `socat` reports it could not bind, or the port answers the wrong service | something in the sandbox already listens on that number | relaunch with `--host-loopback-port 9222:19222` and dial 19222 inside |
| `connect_over_cdp` times out on an enforcing SELinux host, and the port is listed | SELinux denied the container's `connectto` to the host-loopback socket | inspect `sudo ausearch -m avc -ts recent | grep connectto`, then decide whether `sudo setsebool -P container_connect_any 1` is acceptable on the host |
| `host.containers.internal` refuses even though the host's service is up | that name is podman's `--map-guest-addr`, which resolves to the host's *LAN* address, not its loopback | bind the host service to `0.0.0.0` to use that name, or map it with `--host-loopback-port` for a loopback-bound one |
| Video file is 0 bytes or missing | context or screencast was not closed before exit | call `context.close()` or `page.screencast.stop()` to flush ffmpeg to disk |
| Video does not play in target tool/player | target environment lacks WebM (VP8) decoder | transcode to MP4 (H.264) using the Nix ffmpeg recipe above |
| Recording opens with seconds of blank white | context created before the flow it records; it records in real time from `new_page()` | create it immediately before the flow, and trim the paint-in settle when compositing |
| Recording ends with a frozen page for ages | context left open while other work ran | close it as soon as its flow is done |
| Composite is shorter than its main input, tail missing | `overlay=…:shortest=1` with a longer inset track | drop `shortest`, build both tracks to the same length |
| Inset invisible or looks like part of the page | light inset on a light main view, no edge | `pad` a border around the scaled inset |
| Encode fails on odd dimensions / `yuv420p` | `scale=W:-1` produced an odd height | use `scale=W:-2` |
| Inset shows the wrong actor at the wrong moment | clips concatenated, discarding when each happened | place each at its recorded offset with `tpad`, holding frames across gaps |
| No cursor in the video; clicks are invisible | Playwright records no pointer | inject a cursor via `context.add_init_script()`, or use `page.screencast.show_actions()` |
| Injected cursor missing on some pages | init script ran before `document.documentElement` existed | guard `install()` behind `DOMContentLoaded` |
| Cursor jumps instead of gliding | `page.mouse.move()` without interpolation | pass `steps=18` (or similar) |
| Cursor starts mid-screen after a navigation | the new document re-ran the init script, recreating it centred | `human_move` onto the target again after each navigation |
| Blank view for ~1 s mid-recording of an SPA | `page.reload()` re-bootstrapped the framework | navigate in-app to the same route instead |
