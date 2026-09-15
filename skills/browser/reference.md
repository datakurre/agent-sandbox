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

Scale an inset recording, overlay it in a corner, and stop when the shorter
input ends:

```sh
ffmpeg -y -i main.webm -i inset.webm -filter_complex "\
  [1:v]scale=380:-1[pip]; \
  [0:v][pip]overlay=x=W-w-24:y=H-h-24:shortest=1[outv]" \
  -map "[outv]" -c:v libx264 -pix_fmt yuv420p -r 25 composited.mp4
```

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
