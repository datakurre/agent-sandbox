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

## A visible browser: attach to Chrome on the host

Headless-in-container is the default because there's no X server here (see
above), but a headed browser is still reachable — as a *client*, over CDP, to
a browser the user launches on the **host**. Ask them to start it with a
fixed debugging port bound to loopback:

```sh
google-chrome --remote-debugging-port=9222 --remote-debugging-address=127.0.0.1
# or
chromium --remote-debugging-port=9222 --remote-debugging-address=127.0.0.1
```

Keep `--remote-debugging-address` on `127.0.0.1`, never `0.0.0.0` — CDP has no
authentication, so reachability is the only thing standing between "the
sandbox can drive this tab" and "anything on the network can read every
cookie and run arbitrary JS in it."

By default the sandbox has **no route to the host's loopback at all**, so this
needs `--host-loopback` at launch. Podman's rootless pasta setup passes
`--no-map-gw`, which disables the gateway-to-loopback translation, and wires
`host.containers.internal` with `--map-guest-addr` — that lands on the host's
*LAN* address, not `127.0.0.1`. Neither one reaches a loopback-bound Chrome.
The flag asks pasta for the mapping:

```sh
agent-sandbox --host-loopback -- bash
```

Anything the sandbox then sends to `169.254.1.3` arrives on the host as
`127.0.0.1 → 127.0.0.1`. Chrome stays bound to loopback, one address reaches
it, and nothing else on the network can.

**Check `$AGENT_SANDBOX_HOST_LOOPBACK` first.** The launcher sets it to the
mapped address, and only when the route exists:

```sh
echo "${AGENT_SANDBOX_HOST_LOOPBACK:?relaunch with: agent-sandbox --host-loopback}"
curl -s "http://$AGENT_SANDBOX_HOST_LOOPBACK:9222/json/version"
```

Unset means this session cannot reach the host at all — say so and ask the user
to relaunch, rather than guessing at ports. Set but refused means Chrome isn't
listening on the host's `127.0.0.1:9222`: an already-running Chrome ignores
`--remote-debugging-port`, so the user needs a separate `--user-data-dir` for
the flag to take effect. Use the variable rather than the literal below; the
user may have picked another address with `--host-loopback=ADDR`.

Then attach as a CDP client — this is a remote connection, not a local launch,
so `PLAYWRIGHT_BROWSERS_PATH` and `FONTCONFIG_FILE` aren't needed:

```python
import os
from playwright.sync_api import sync_playwright

host = os.environ["AGENT_SANDBOX_HOST_LOOPBACK"]   # KeyError = no route, relaunch
p = sync_playwright().start()
browser = p.chromium.connect_over_cdp(f"http://{host}:9222")
page = browser.contexts[0].pages[0]     # the host's already-open tab
page.goto("https://example.com")
```

Dialing the literal address also sidesteps Chrome's DevTools host check, which
rejects a `Host:` header that is not an IP or `localhost`.

To point that browser at a server running *in* the sandbox, publish a port as
well — the two compose, since publishing no longer changes the network mode:

```sh
agent-sandbox --ports --host-loopback -- bash
```

The host's Chrome then reaches it over the host's own loopback, e.g.
`http://127.0.0.1:8000` for a `[ports]` entry publishing 8000. Bind that server
to `0.0.0.0` inside the sandbox: publishing forwards to the sandbox's interface
address, so a loopback-bound one is reachable from inside and dead from the
host.

Two modes have no route to the host and cannot do any of this: `--proxy`
(deliberately — the sandbox is on an `--internal` network) and
`--shared-network` (a bridge, where pasta options do not apply). A proxied
sandbox can still *publish* to the host's loopback, so the user can open your
server in their own browser; it is only the outbound CDP connection that has
nowhere to go. The last-resort
fallback remains `agent-sandbox --no-proxy --podman-args --network=host --
bash`, which shares the host's entire network stack to obtain the one port.

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
