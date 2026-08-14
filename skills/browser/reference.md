# Headless browser — advanced patterns

Read `SKILL.md` first. This assumes `PLAYWRIGHT_BROWSERS_PATH` and
`FONTCONFIG_FILE` are already exported as shown there.

## Why fonts are missing, in full

`agent-sandbox` images are built for CLI/dev tooling, not desktop rendering —
`/etc/fonts` doesn't exist and no font packages are installed anywhere. That is
a gap in the base image, not something specific to Chromium: any tool that
shells out to fontconfig would hit the same wall. `pkgs.makeFontsConf` is
nixpkgs' own helper for exactly this case (it's what NixOS's headless-browser
tests use) — it builds a `fonts.conf` pointing at the font packages you give
it, with no need for a real `/etc/fonts` to exist:

```sh
nix build --impure --expr \
  'with (builtins.getFlake "nixpkgs").legacyPackages.${builtins.currentSystem};
   makeFontsConf { fontDirectories = [ dejavu_fonts liberation_ttf noto-fonts-color-emoji ]; }' \
  --no-link --print-out-paths
```

Add `noto-fonts-color-emoji` (or other script-specific font packages) if the
pages you're rendering need non-Latin scripts or emoji — `dejavu_fonts` and
`liberation_ttf` alone only cover Latin text well.

To debug font resolution directly, add `fontconfig` to a `nix shell` and run
`fc-list` — with `FONTCONFIG_FILE` unset it prints nothing; with it set, it
lists every font `makeFontsConf` wired in.

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

## PDF export

Only Chromium supports it (`p.chromium`, not `p.firefox`/`p.webkit`), and only
in headless mode:

```python
page.pdf(path="page.pdf", format="A4")
```

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

## playwright-mcp flags

From `nix run nixpkgs#playwright-mcp -- --help`:

| Flag | What it does |
| --- | --- |
| `--headless` | run without a visible browser (default is headed — always pass this here) |
| `--isolated` | keep the profile in memory, don't persist it to disk |
| `--browser <name>` | defaults to chromium (`PLAYWRIGHT_MCP_BROWSER`) |
| `--viewport-size <WxH>` | e.g. `1280x720` |
| `--user-agent <ua>` | override the UA string |
| `--proxy-server <url>` / `--proxy-bypass <domains>` | explicit proxy, same reasoning as the scripted path |
| `--output-dir <path>` | where screenshots/snapshots get written |
| `--storage-state <path>` | reuse cookies/local storage across runs |
| `--no-sandbox` | disable Chromium's own sandbox (container default) |
| `--port <port>` | serve over SSE instead of stdio |

## Registering with other agent CLIs

The same `nix run nixpkgs#playwright-mcp -- --headless --isolated` command
works as the server command for any MCP-aware CLI; only the registration verb
differs, e.g. for codex:

```sh
codex mcp add playwright-nix --env DISPLAY=:0 -- nix run nixpkgs#playwright-mcp -- --headless --isolated
```

## Debugging checklist

| Symptom | Cause | Fix |
| --- | --- | --- |
| Screenshot is a flat, uniform color | no fonts | export `FONTCONFIG_FILE` (see `SKILL.md`) |
| `page.goto()` hangs or times out | proxied sandbox denying the host | check `$HTTPS_PROXY`, pass it explicitly, ask for `ctl proxy allow` |
| "Failed to move to new namespace" / renderer crash | container can't create Chromium's own sandbox | add `--no-sandbox` to `launch(args=[...])` |
| Renderer crashes under load, blank/partial screenshot | `/dev/shm` too small (often 64 MB in containers) | add `--disable-dev-shm-usage` |
| `browserType.launch` complains about a missing executable | `PLAYWRIGHT_BROWSERS_PATH` unset or wrong | re-export it, see `SKILL.md` |
| `$AGENT_SANDBOX_HOST_LOOPBACK` is unset | launched without `--host-loopback`, so nothing routes to the host's `127.0.0.1` — or under `--proxy`/`--shared-network`, which refuse it | ask the user to relaunch with `agent-sandbox --host-loopback`, see `SKILL.md` |
| `connect_over_cdp` refuses/times out with that variable set | the route exists, so Chrome is not listening on the host's `127.0.0.1:9222` | an already-running Chrome ignores `--remote-debugging-port`; the user needs a separate `--user-data-dir` |
| `host.containers.internal` refuses even though the host's service is up | that name is podman's `--map-guest-addr`, which resolves to the host's *LAN* address, not its loopback | bind the host service to `0.0.0.0` to use that name, or use `$AGENT_SANDBOX_HOST_LOOPBACK` for a loopback-bound one |
