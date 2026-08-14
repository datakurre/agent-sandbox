---
name: browser
description: Drive a headless browser sourced entirely from nixpkgs to screenshot a page for visual/image analysis or to interact with it (navigate, click, fill, wait). Trigger when asked to look at a rendered web page, verify what a UI looks like, screenshot a site, or automate clicks/form-fills against a page, and no host browser or Chrome extension is available.
compatibility: opencode
metadata:
  workflow: headless-browser-automation
  audience: developers-and-agents
---

# Headless browser, from nixpkgs

No host install, same philosophy as the `nix` skill: pull a browser and its
driver from nixpkgs for the duration of one script or session. Two ingredients
cover both screenshotting and interactive control — `python3Packages.playwright`
(the scripting API) and `playwright-driver.browsers` (the actual chromium /
firefox / webkit binaries). The Python package's driver is symlinked to
nixpkgs' own `playwright-driver` at build time, so the two are always
protocol-compatible — never run `playwright install`, it tries to hit a CDN and
isn't needed.

## Get the browser, once per session

```sh
export PLAYWRIGHT_BROWSERS_PATH=$(nix build --impure --expr \
  'with (builtins.getFlake "nixpkgs").legacyPackages.${builtins.currentSystem}; playwright-driver.browsers' \
  --no-link --print-out-paths)
```

Everything below inherits this from the environment — no need to repeat it.

## Fix fonts first, or screenshots come back blank

This image ships no fonts at all (no `/etc/fonts`, no `fc-list`). Headless
Chromium under these conditions fails **silently**: `page.goto()` succeeds,
`page.title()` and `page.content()` return correct data, and `page.screenshot()`
comes back a flat, uniform color — no error, no crash, just a blank image that
looks like nothing loaded. Confirmed by inspecting the actual pixels: without
this fix a screenshot of a real page was a single solid color end to end.

Fix once per session, same way:

```sh
export FONTCONFIG_FILE=$(nix build --impure --expr \
  'with (builtins.getFlake "nixpkgs").legacyPackages.${builtins.currentSystem};
   makeFontsConf { fontDirectories = [ dejavu_fonts liberation_ttf ]; }' \
  --no-link --print-out-paths)
```

Do this before taking any screenshot meant for visual inspection. It is not
needed if you only read `page.content()` or `aria_snapshot()` (text stays
correct either way), but skip it and every screenshot is a trap.

## Script it: navigate, screenshot, click

```sh
nix shell --impure --expr \
  'with (builtins.getFlake "nixpkgs").legacyPackages.${builtins.currentSystem};
   [ (python3.withPackages (ps: [ ps.playwright ])) fontconfig dejavu_fonts liberation_ttf ]' \
  --command python3 script.py
```

```python
# script.py
from playwright.sync_api import sync_playwright

with sync_playwright() as p:
    browser = p.chromium.launch(
        headless=True,
        args=["--no-sandbox", "--disable-dev-shm-usage"],  # container defaults
    )
    page = browser.new_page(viewport={"width": 1280, "height": 800})
    page.goto("https://example.com", wait_until="load")

    page.screenshot(path="page.png")              # for visual/image analysis
    print(page.locator("body").aria_snapshot())    # text-only accessibility tree

    page.click("text=Learn more")
    page.wait_for_load_state("load")

    browser.close()
```

Then read `page.png` with your own image-viewing tool (e.g. Claude Code's
`Read`) to actually look at it — this skill gets the pixels on disk, not in
front of the model. Prefer `aria_snapshot()` or `page.content()` over a
screenshot when the task is pure text/structure, not appearance — it's cheaper
and immune to the fonts gotcha.

## JavaScript console and errors

Attach listeners before navigating — messages logged during `page.goto()`
itself are otherwise missed:

```python
page.on("console", lambda msg: print(f"[{msg.type}] {msg.text}"))
page.on("pageerror", lambda exc: print(f"pageerror: {exc}"))
page.on("requestfailed", lambda req: print(f"failed: {req.url} {req.failure}"))

page.goto("https://example.com", wait_until="load")

print(page.evaluate("window.location.href"))     # run arbitrary JS, get the result back
```

`msg.type` is `"log"` / `"warning"` / `"error"` / etc.; `msg.text` is the
formatted message. This is the way to see what a page's own script is doing —
network failures, thrown exceptions, `console.log` debugging output — the
same signal DevTools' console gives a human.

## Sandbox network

This is `agent-sandbox`: a proxied session firewalls all egress
deny-by-default (see the `agent-sandbox` skill and its `network.md`). A
headless browser makes requests to whatever host the page needs, and those are
blocked the same as any other request. Check first:

```sh
env | grep -i '^https\?_proxy'
```

If set, pass it to Playwright explicitly rather than relying on it being
picked up automatically:

```python
import os
proxy = {"server": os.environ["HTTPS_PROXY"]} if os.environ.get("HTTPS_PROXY") else None
browser = p.chromium.launch(headless=True, proxy=proxy, args=[...])
```

A denied host is policy working as configured — ask the user to run
`agent-sandbox ctl proxy allow <host>:443` on the host, the same escalation the
`agent-sandbox` skill teaches. Don't unset the proxy or add `--no-proxy-server`
to route around it.

## Skip the script: playwright-mcp

nixpkgs also packages Microsoft's official Playwright MCP server
(`playwright-mcp`), pre-wired with `PLAYWRIGHT_BROWSERS_PATH` already set. It
gives an agent native `browser_navigate` / `browser_click` /
`browser_take_screenshot` / `browser_snapshot` tools instead of hand-written
scripts — better for many small interactive steps driven turn by turn; a
script is better for a fixed sequence run once.

```sh
nix run nixpkgs#playwright-mcp -- --headless --isolated
```

Register it (Claude Code):

```sh
claude mcp add playwright-nix -- nix run nixpkgs#playwright-mcp -- --headless --isolated
```

`FONTCONFIG_FILE` must already be exported in the shell that runs this command
— the package's wrapper only force-sets `PLAYWRIGHT_BROWSERS_PATH`, so the
fonts fix above still applies. It captures console messages and network logs
too (`--output-mode`/`--output-dir` control where those land), so console
access doesn't need the scripted path either.

## More

`reference.md` covers form filling and waiting, multiple tabs, PDF export, the
raw CDP fallback for when Playwright itself isn't wanted, a version-skew note
between `python3Packages.playwright` and `playwright-driver` on
nixpkgs-unstable, the full `playwright-mcp` flag list, and a debugging
checklist.
