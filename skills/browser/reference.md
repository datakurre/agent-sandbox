# Browser — advanced patterns

Read `SKILL.md` first. The headless sections assume `PLAYWRIGHT_BROWSERS_PATH`
is exported as shown there.

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

## playwright-mcp flags

`playwright-mcp` is on the image PATH — no `nix run`, and it works under
`--proxy` without reaching `cache.nixos.org`. From `playwright-mcp --help`:

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
| `--cdp-endpoint <url>` | drive a browser already running, instead of launching one |

`--allowed-origins` / `--blocked-origins` exist too, but its own documentation
says they are not a security boundary — the proxy is what bounds a host
browser, and the sandbox's `--proxy` policy is what bounds a headless one.

## Registering it yourself

The entrypoint writes an MCP config at `~/.config/agent-sandbox/mcp.json` when
`AGENT_SANDBOX_BROWSER_CDP_PORT` is set (host browser) or
`AGENT_SANDBOX_BROWSER_MCP=headless` is set (a headless one in here) — one
entry per server, in the shape `{"mcpServers": {"<name>": {"command": ...,
"args": [...]}}}`. `AGENT_SANDBOX_BROWSER_MCP=off` turns the whole thing off.

Claude Code picks it up automatically (`--mcp-config`, appended for you).
Every other agent has to register it with its own mechanism — there are only
two shapes that mechanism takes:

| Agent | Mechanism | Config it writes |
| --- | --- | --- |
| `codex` | CLI subcommand | `~/.codex/config.toml` |
| `copilot` | CLI subcommand (identical syntax to `codex`) | `~/.copilot/mcp-config.json` |
| `antigravity` (`agy`) | config-file merge, same `mcpServers` shape as `mcp.json` — no reshaping | `~/.gemini/config/mcp_config.json` (global) or `./.agents/mcp_config.json` (workspace) |
| `opencode` | config-file merge, different shape (`mcp` key, `type`/`command` array/`enabled`) | `~/.config/opencode/opencode.json` (global) or project `opencode.json` |

**`codex` / `copilot`** — both take `<name> -- <command> <args...>`, so the
same loop registers every server in the file with either:

```sh
agent_mcp_cli=codex   # or: copilot
jq -r '.mcpServers | to_entries[] | "\(.key)\t\(.value.command)\t\(.value.args | join(" "))"' \
  ~/.config/agent-sandbox/mcp.json |
while IFS=$'\t' read -r name command args; do
  "$agent_mcp_cli" mcp add "$name" -- "$command" $args
done
```

**`antigravity`** — its config already uses the same `mcpServers` shape, so
this is a plain merge, not a reshape:

```sh
CONFIG=~/.gemini/config/mcp_config.json   # or ./.agents/mcp_config.json, workspace-local
mkdir -p "$(dirname "$CONFIG")"
if [ -f "$CONFIG" ]; then
  jq -s '.[0] * {mcpServers: .[1].mcpServers}' "$CONFIG" ~/.config/agent-sandbox/mcp.json \
    > "$CONFIG.tmp" && mv "$CONFIG.tmp" "$CONFIG"
else
  jq '{mcpServers: .mcpServers}' ~/.config/agent-sandbox/mcp.json > "$CONFIG"
fi
```

**`opencode`** — its `mcp` key wants a different per-server shape
(`type`/`command` as one array/`enabled`), so reshape while merging:

```sh
CONFIG=~/.config/opencode/opencode.json   # or a project-local opencode.json
NEW=$(jq '{mcp: (.mcpServers | map_values({type: "local", command: ([.command] + .args), enabled: true}))}' \
  ~/.config/agent-sandbox/mcp.json)
mkdir -p "$(dirname "$CONFIG")"
if [ -f "$CONFIG" ]; then
  jq --argjson new "$NEW" '. * $new' "$CONFIG" > "$CONFIG.tmp" && mv "$CONFIG.tmp" "$CONFIG"
else
  jq -n --argjson new "$NEW" '{"$schema": "https://opencode.ai/config.json"} * $new' > "$CONFIG"
fi
```

Every snippet above merges rather than overwrites, since these are host-mounted
state files that may already carry the operator's own servers. Running
something else, or one of these has drifted? The ingredients are always the
server name/command/args in `~/.config/agent-sandbox/mcp.json` — check your
own CLI's docs or `--help` for how it takes MCP servers.

## Debugging checklist

| Symptom | Cause | Fix |
| --- | --- | --- |
| Screenshot is a flat, uniform color | no usable fonts | check `$FONTCONFIG_FILE` and `fc-list`; rebuild it with the scripts the page needs (see above) |
| `page.goto()` hangs or times out | proxied sandbox denying the host | check `$HTTPS_PROXY`, pass it explicitly, ask for `ctl proxy allow` |
| "Failed to move to new namespace" / renderer crash | container can't create Chromium's own sandbox | add `--no-sandbox` to `launch(args=[...])` |
| Renderer crashes under load, blank/partial screenshot | `/dev/shm` too small (often 64 MB in containers) | add `--disable-dev-shm-usage` |
| `browserType.launch` complains about a missing executable | `PLAYWRIGHT_BROWSERS_PATH` unset — likely `export`ed in a separate tool call that didn't carry into this one | re-derive it in the *same* command as the failing one, see `SKILL.md` |
| `$AGENT_SANDBOX_HOST_PORTS` is unset, or missing the port | launched without `--browser`, so nothing reaches the host's `127.0.0.1:9222` | ask the user to run `agent-sandbox browser`, then relaunch with `--browser`, see `SKILL.md` |
| `connect_over_cdp` refuses/times out with the port listed | the channel exists, so nothing is listening on the host's `127.0.0.1:9222` | the browser was closed, or a hand-started Chrome had no separate `--user-data-dir` |
| No `browser_*` MCP tools, but CDP works from a script | relaunched with a bare `--host-loopback-port` instead of `--browser`, so nothing set `AGENT_SANDBOX_BROWSER_CDP_PORT` | use `--browser`, or add the variable with `-e` |
| Only one browser reachable when two were started | the second was started after the sandbox, so `--browser` never saw it | start every browser before the sandbox; the channel is set at launch |
| `ctl proxy … --browser` says several browsers are running | more than one session, so the target is ambiguous | name one: `--browser alice` |
| A page in the host browser fails to load, `curl` from here reaches it | the browser's allow list is separate from the sandbox's | `agent-sandbox ctl proxy allow <host>:443 --browser` |
| `socat` reports it could not bind, or the port answers the wrong service | something in the sandbox already listens on that number | relaunch with `--host-loopback-port 9222:19222` and dial 19222 inside |
| `host.containers.internal` refuses even though the host's service is up | that name is podman's `--map-guest-addr`, which resolves to the host's *LAN* address, not its loopback | bind the host service to `0.0.0.0` to use that name, or map it with `--host-loopback-port` for a loopback-bound one |
