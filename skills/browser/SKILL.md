---
name: browser
description: Drive a browser to screenshot a page for visual/image analysis or to interact with it (navigate, click, fill, wait) — either headless from nixpkgs, or the user's own visible Chrome on the host over CDP. Trigger when asked to look at a rendered web page, verify what a UI looks like, screenshot a site, automate clicks/form-fills against a page, or work in the user's real browser so they can watch and click along.
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

## A visible browser: attach to Chrome on the host

Headless-in-container is the default because there's no X server here (see
above), but a headed browser is still reachable — as a *client*, over CDP, to a
browser the user launches on the **host**. This is what to use when the task
needs a real browser with the user watching: their own profile and logins, a
visible window, and the user clicking things themselves between your calls.

### Ask the user for two things, in one message

The sandbox flag below can only be set at launch, so a half-answer costs another
round trip. Give them both halves at once.

**First, start Chrome on the host** with a debugging port bound to loopback. The
separate `--user-data-dir` is **required**, not optional — an already-running
Chrome silently ignores `--remote-debugging-port`:

```sh
google-chrome --user-data-dir=/tmp/cdp-profile \
              --remote-debugging-port=9222 \
              --remote-debugging-address=127.0.0.1
# or chromium, same flags
```

Keep `--remote-debugging-address` on `127.0.0.1`, never `0.0.0.0` — CDP has no
authentication, so reachability is the only thing standing between "the sandbox
can drive this tab" and "anything on the network can read every cookie and run
arbitrary JS in it."

**Second, relaunch the sandbox** with that port named. Tell them to keep whatever
flags they were already using and add one:

```sh
agent-sandbox --host-loopback-port 9222 -- <their usual command>
```

It composes with everything, `--proxy` included:

```sh
agent-sandbox --proxy --ports --host-loopback-port 9222 -- claude
```

By default the sandbox has **no route to the host's loopback at all**, and
neither `host.containers.internal` nor the gateway reaches one — podman points
the first at the host's *LAN* address and passes pasta `--no-map-gw`. The flag is
the only way in, and it opens exactly the ports named.

### Check the channel before dialing

The launcher sets `$AGENT_SANDBOX_HOST_PORTS` to the ports it mapped, and only
those:

```sh
case ",$AGENT_SANDBOX_HOST_PORTS," in
  *,9222,*) ;;
  *) echo "relaunch with: agent-sandbox --host-loopback-port 9222"; exit 1 ;;
esac
curl -s http://127.0.0.1:9222/json/version
```

Port missing from the list means this session has no channel to it — say so and
ask for the relaunch, rather than guessing at other ports. Listed but refused
means Chrome isn't listening on the host's `127.0.0.1:9222`, which is almost
always the missing `--user-data-dir`.

### Attach

A remote connection, not a local launch, so `PLAYWRIGHT_BROWSERS_PATH` and
`FONTCONFIG_FILE` aren't needed:

```python
from playwright.sync_api import sync_playwright

p = sync_playwright().start()
browser = p.chromium.connect_over_cdp("http://127.0.0.1:9222")
page = browser.contexts[0].pages[0]     # the host's already-open tab
page.goto("https://example.com")
```

Dialing `127.0.0.1` also sidesteps Chrome's DevTools host check, which rejects a
`Host:` header that is not an IP or `localhost`.

If the sandbox already has something on 9222, the user can move the inside
number: `--host-loopback-port 9222:19222` puts the host's 9222 on the sandbox's
19222, and `$AGENT_SANDBOX_HOST_PORTS` then lists `19222`.

### Both directions at once

To point that browser at a server running *in* the sandbox, publish a port as
well — the two compose:

```sh
agent-sandbox --proxy --ports --host-loopback-port 9222 -- bash
```

The host's Chrome then reaches it over the host's own loopback, e.g.
`http://127.0.0.1:8000` for a `[ports]` entry publishing 8000. Bind that server
to `0.0.0.0` inside the sandbox: publishing forwards to the sandbox's interface
address, so a loopback-bound one is reachable from inside and dead from the host.

### Under `--proxy`, this channel is not policed

The egress policy governs what the *sandbox* connects to. It cannot govern what
the host's Chrome fetches on its own account, so a `page.goto()` reaches hosts a
`curl` from here would be denied.

That is not a workaround to reach for. If a host is denied, the fix is still to
ask the user to run `agent-sandbox ctl proxy allow <host>:443` — the same
escalation as everywhere else. Don't route ordinary fetching through the host's
browser to get around a policy.

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
