---
name: screencast
description: Record, compose, and verify a multi-actor screencast of a Robot Framework-driven browser scenario with the robotframework-screencast Python library (https://github.com/datakurre/robotframework-screencast, documentation https://datakurre.github.io/robotframework-screencast/) — several personas taking turns, an observer recording the whole run, title cards, and a picture-in-picture composite. The library is NOT on PyPI: install it from GitHub, as the skill's first section says. Trigger when asked to record a scenario/demo video or product walkthrough of a web application, add a persona turn to an existing recording, re-cut a take without re-recording, debug a broken story or take, or fix dead air, a blank frame or a truncated composite.
compatibility: Needs Python 3.10+, ffmpeg and ffprobe on the PATH, a Chromium that Playwright can launch, and network access to install the library from GitHub. The application being recorded must be running and reachable from the machine.
metadata:
  workflow: screencast-recording
  audience: developers-and-agents
  library: https://github.com/datakurre/robotframework-screencast
---

## Installing the library

This skill drives the **`robotframework-screencast`** Python package. It is
**not published to PyPI**, so install it from GitHub — and never
`pip install robotframework-screencast`, which is not this project and could
resolve to an unrelated package:

```sh
pip install "git+https://github.com/datakurre/robotframework-screencast"
# pinned to a tag or commit:
pip install "git+https://github.com/datakurre/robotframework-screencast@<tag-or-commit>"
# with uv:
uv pip install "git+https://github.com/datakurre/robotframework-screencast"
```

**With Nix** (if your environment has the `nix` skill, prefer this: nothing is
installed, and ffmpeg, a matching Chromium and fonts come with the package). The
repository is a flake, so run the command straight from GitHub:

```sh
nix run github:datakurre/robotframework-screencast -- --version
nix run github:datakurre/robotframework-screencast -- run story.robot --take <dir>
nix shell github:datakurre/robotframework-screencast --command screencast verify <dir>
```

Pin a tag or commit (`github:datakurre/robotframework-screencast/<rev>`) when
the version matters: a remote flake runs code from that repository, and the
default branch moves. A story that imports Python packages of its own needs an
environment with them: use the pip install above in a virtualenv instead, since
the Nix package carries only the engine's dependencies. In a project flake, add
this one as an input and use `overlays.default` (it provides
`pkgs.robotframework-screencast`), or `nix develop` in a clone for the
development shell.

Check it with `screencast --version` (or `python -m screencast --version`): it
prints the resolved versions of Robot Framework, Playwright, jsonschema and
ffmpeg. If the command is missing, the package is not installed in the
environment you are running in — install it there, not somewhere else.

Where to look things up:

- **Documentation:** <https://datakurre.github.io/robotframework-screencast/>
  (these same pages, plus the timeline schema).
- **Source and issues:** <https://github.com/datakurre/robotframework-screencast>.
- **A complete worked example** — three stories with several personas each,
  the shared keyword layer, and a walkthrough of each scenario — on the
  repository's `legacy-playground` branch:
  <https://github.com/datakurre/robotframework-screencast/tree/legacy-playground/scripts/screencasts>.
- **The installed package itself:**
  `python -c "import screencast, pathlib; print(pathlib.Path(screencast.__file__).parent)"`.
  File names below such as `screencast/library.py` are relative to it; in the
  repository they live under `src/`.

## Before you start

- You need `ffmpeg` and `ffprobe` on the `PATH`, Robot Framework 7.4 or newer
  (installed with the package), a **Chromium that Playwright can launch**, and
  **the application you are recording running** — the engine drives a browser
  against it and knows nothing about it.
- **Provide the browser the way your environment does.** In an ordinary
  environment that is `playwright install chromium`; a sandbox or Nix setup
  usually supplies one already (follow its own rules — some forbid
  `playwright install`). `SCREENCAST_CHROMIUM_PATH` points the engine at a
  specific Chromium build.
- If your environment has a `browser` skill, read it for getting a Chromium
  running (headless or over CDP), fonts and the sandbox's network policy; it
  also has the basic `record_video_dir` setup. Without it, the recording
  essentials are these.
  Playwright records a context in real time from `new_page()` to `close()`, so
  any time a context is open but not driven is dead air in its video; Playwright
  draws no mouse cursor. The engine handles both — it opens each recorded context
  just before its flow and closes it right after, and injects a visible cursor —
  which is why a story must use `Start Actor Turn`/`End Actor Turn` and
  `Start Observer`/`End Observer` and not open browsers itself. When composing
  video by hand, never use `overlay=...:shortest=1` (it truncates), and freeze a
  frame with `tpad=stop_mode=clone`.
- **Never run a story against an environment you do not own.** Stories
  usually start by resetting some state; that is what makes a take
  repeatable, and it is destructive.

# Three layers, one engine

```
screencast/                    the installed package — generic, no application knowledge
  library.py                     Screencast: the Robot Framework keyword library
  timeline.py                    Timeline (EDL) schema v2: load/validate/save
  schema/timeline.schema.json    the JSON Schema timeline.py validates against
  compose.py                     timeline.json -> one ffmpeg filter_complex
  verify.py                      ffprobe, blank frames, wait events, contact sheet
  driver.py, __main__.py         the `screencast` command (`python -m screencast`)
  tests/                         against a fake Playwright and real ffmpeg

your project                   the two upper layers, yours
  resources/<app>.resource       keywords in your app's vocabulary
  <name>.robot                   one story per scenario, *** Tasks *** suites

<output>/<story>/<take>/       everything a take writes
  page@*.webm                    observer + each actor turn's own clip
  timeline.json                  schema v2 — see *The timeline*, below
  output.webm                    `screencast compose`'s output
  report.json, contact-sheet.png `screencast verify`'s output
```

Who writes what:

- **The engine** is generic. Extend it only for something a *different*
  project's screencast would also need (a new selector convention, a new
  verify check) — see *Extending the engine*, below.
- **The project resource** is your app's vocabulary: `Log In`, `Add Item`,
  `Wait For Order`, all built from the engine's primitives. Add a keyword
  here when two or more stories would otherwise repeat the same sequence.
  `screencast keywords resources/app.resource` lists what already exists
  before you write a new one.
- **A story** reads like a screenplay: one `*** Tasks ***` suite, one task
  per actor turn (plus a few unrecorded setup/observation tasks), built from
  the resource file's keywords and, for anything genuinely one-off, the
  engine's own primitives directly (`Human Click role=button[name="..."]`,
  `Paste Text`, ...).

A complete worked example of the two upper layers — three stories with
several personas each and an observer, and the shared keyword layer they use —
is the `scripts/screencasts/` of the library repository's
[`legacy-playground`](https://github.com/datakurre/robotframework-screencast/tree/legacy-playground/scripts/screencasts)
branch, the project (collective.bpmproxy) the engine was written for.

# Scaffolding a new story

```robotframework
*** Settings ***
Documentation     One or two sentences: who does what, and why it's worth recording.
Library           screencast.Screencast    take_dir=${TAKE_DIR}    record=${RECORD}
Resource          resources/app.resource

*** Variables ***
${SHOTS_DIR}      ${TAKE_DIR}/screenshots

*** Tasks ***
Prepare The Take
    # Unrecorded: reset state. Nothing here may become blank seconds at the
    # head of a recording.
    Start Scratch Context    ${BASE_URL}    http_credentials=${{ {'username': 'admin', 'password': 'admin'} }}
    Reset Demo Data
    End Scratch Context

Start Observing
    # Log in unrecorded, then hand the session to the recorded observer. A
    # variable assigned in a task is local to it, so this stays in one task.
    Start Scratch Context    ${BASE_URL}/login
    Log In As    admin    admin
    ${state}=    Get Storage State
    End Scratch Context
    Start Observer    dashboard    ${BASE_URL}/dashboard    storage_state=${state}

Alice Does A Thing
    [Setup]    Start Actor Turn    alice    eyebrow=My scenario · 1 / 2
    ...    title=Alice    subtitle=What she's doing
    Go To    ${BASE_URL}
    Human Click    role=link[name="Add new…"]
    Human Type    \#title    A page title
    Human Click    role=button[name="Save"]
    Take Screenshot    ${SHOTS_DIR}/page-added.png
    [Teardown]    End Actor Turn

Wrap Up
    Observe    ${BASE_URL}/dashboard
    Hold    3
    End Observer
```

`${TAKE_DIR}` and `${RECORD}` are supplied by the driver (`screencast run`),
never hard-coded in the story. Keywords, by what they are for:

| Group | Keywords |
|---|---|
| Observer | `Start Observer`, `Observe` (bring it to the front; `reload=` only as a deliberate exception), `End Observer` |
| Actor turns | `Start Actor Turn`, `End Actor Turn` |
| Unrecorded setup | `Start Scratch Context`, `End Scratch Context`, `Get Storage State` |
| Human-paced input | `Human Move`, `Human Click`, `Human Type`, `Paste Text` (for long text), `Press Key`, `Select Option`, `Check`, `Uncheck` |
| Waiting and reading | `Wait Until Visible`, `Wait For Navigation Away`, `Count Matches`, `Get Attribute`, `Get Url`, `Get Current Page` (the raw Playwright page) |
| Navigation and shots | `Go To`, `Take Screenshot` |
| Data shared between tasks and runs | `Save State`, `Load State`, `Clear State` |
| Edit events (no browser time) | `Chapter`, `Focus`, `Hold`, `Caption` |

`Start Actor Turn` logs the persona in with HTTP Basic auth as `actor` /
`password` (the password defaults to the actor's name; pass `anonymous=${True}`
for a visitor with no login). For anything else, do the login in a scratch
context and hand the resulting storage state on.

Rules that are easy to get backwards:

- **`Start Observer` first, `End Observer` last, always as the very last
  keyword of the very last task.** Playwright only flushes a context's video
  on `close()` — skip `End Observer` and `ffprobe` sees a near-empty file no
  matter how long the take actually ran.
- **Every `Start Actor Turn` needs a matching `End Actor Turn`**, as
  `[Setup]`/`[Teardown]` on the same Task. This is what makes "one recorded
  context per turn, opened immediately before, closed immediately after"
  automatic — see the `browser` skill for why that matters.
- **Never sleep to make a video longer.** A wait is dead air on screen (see
  *Take verification*). Use `Hold` to freeze a frame in the edit, `Chapter`
  for a title card; neither spends browser time.
- **Submit through `Wait For Navigation Away`** (or a keyword built on it)
  when a form must go through: a rejected submit leaves the page where it
  was and nothing else says so.

## Selector conventions the input keywords understand

Beyond a plain CSS selector or Playwright's own `role=`/`text=` engines:

| Prefix | Resolves via | For |
|---|---|---|
| `label=<text>` | `page.get_by_label()` | A form field's own label |
| `<frame> >>> <inner>` | `page.frame_locator(frame).locator(inner)` | Content inside a real `<iframe>` (a rich-text body) — **`>>>` alone in `.locator()` does not cross an iframe boundary**: it parses as a plain child combinator and times out |
| `role=X[name="Y"s]` | Playwright's own role engine | Exact-match a name — the attribute is **not** `[exact=true]`, which errors; `s` is a suffix on the value |

`index=` on the same keywords: `0` (default) is `.first`, `-1` is `.last` —
e.g. the most recently created row in a table that only grows.

# The timeline

`timeline.json` (schema v2, `screencast/schema/timeline.schema.json`) is
the *only* input the composer and verifier need: the observer clip, each
actor clip with its measured offset on the observer's own clock, and a
chronological event list (`turn_start`/`turn_end`, `chapter`, `focus`, `hold`,
`caption`, `wait`). The library writes it automatically from real keyword
start/end times — a story never constructs it by hand.

**Re-cutting a take needs no re-recording.** Edit `focus`/`hold` events
directly in `<take>/timeline.json`, then:

```sh
screencast compose <take dir>
```

Composer defaults, if you're wondering why a take looks a certain way with no
`Focus` calls in the story at all: before any turn, the observer is the only
view (nothing to inset yet); during a turn its actor is main and the
observer is the inset; between turns the main view follows the most recent
`focus` event, default observer. A story only calls `Focus` to override one
of these defaults for a specific stretch.

# Sharing data between tasks, and re-running one task

A variable assigned in a Robot task is local to it, and `Set Suite Variable`
lives only in the running process. A story that carries something from one
task to the next (a created item's URL) therefore cannot re-run a single later
task: it would start without what the earlier tasks learned. Keep such data in
the take directory's `state.json`:

```robotframework
Alice Adds A Page
    ...
    ${page_url}=    Get Url
    Set Suite Variable    ${PAGE_URL}    ${page_url}
    Save State    page_url    ${page_url}
```

`Save State    key    value` writes the file at once (atomically; the value
must be JSON: a string, number, boolean, list or dict, e.g. `${{ {...} }}`).
`Load State    key    default=` reads it back; without a `default` a missing key
fails and names the keys that do exist. `Clear State` forgets everything. A
story restores what its tasks need in a `Suite Setup`, which runs even when only
one task is selected:

```robotframework
Suite Setup       Restore The Story State

*** Keywords ***
Restore The Story State
    ${page_url}=    Load State    page_url    default=${EMPTY}
    Set Suite Variable    ${PAGE_URL}    ${page_url}
```

The driver ties this together: **a full `run` starts from empty state** (the take
directory may be reused, and the previous take's data must not leak in), and
**`run --take <same dir> --task "Task name"` continues from the state the
previous run saved**. After a failure, fix the cause and re-run just the
failing task; no earlier task is replayed:

```sh
screencast run story.robot --no-record --take <dir> --task "Bob Approves The Page"
```

What this does *not* do: only data is restored, never a browser session, so a
**recorded** take must still run start to finish. With `--no-record` an actor
turn works on its own (there is no observer clip to time it against), but a
task that drives the observer (`Observe`, ...) fails without the observer task
that starts it. And the application must still be in the state the earlier tasks
left it in, so do not re-run past a task that resets it. `state.json` may hold
credentials (a Playwright storage state, say); keep the take directory out of
version control.

# The agent debug loop

`screencast` (or `python -m screencast`) is a thin CLI over
`screencast/driver.py`, whose functions are also plain Python if you want
to call them directly:

1. **`check story.robot`** — Robot Framework's own `--dryrun`: every keyword
   call resolves and validates its arguments against what's actually
   imported, with no browser opened. Cheapest first move on anything that
   might be a typo or a missing argument.
2. **`run story.robot [--task NAME] [--no-record] [--take DIR] [--repl-on-failure]`**
   — executes in-process. On a failure, prints a compact summary instead of
   Robot Framework's normal per-keyword trace:
   ```
   FAIL: Story.Broken Turn
     Broken Turn > Human Click[label=Approve]
       TimeoutError: Locator.get_by_label: Timeout 30000ms exceeded.
       Traceback (most recent call last):
         File ".../library.py", line 487, in human_click
       ...
       Failure artifacts: <take>/failure-143022-0.png, .txt
   ```
   The path is the keyword call chain (`Task > Setup[args] > Keyword[args]`,
   collapsed to the innermost failure), then the message, then the DEBUG-level
   Python traceback, then any failure-artifact paths the library's own
   listener wrote — a screenshot, `aria_snapshot()`, console log, and URL for
   every page still open when it failed. Read those before touching the
   story again; the answer is usually right there. The run stops at the first
   failed task: every later task depends on the state it should have left.

   **`--repl-on-failure` is the primary way to debug a broken story.** On
   the first keyword that fails outside any recovery boundary (a `Wait
   Until Keyword Succeeds`/`Run Keyword And ...`/`TRY` block whose retries
   or `EXCEPT` might still swallow it), the run pauses *before* the task's
   own `[Teardown]` runs — so `End Actor Turn` has not yet closed the page
   that failed — prints the same failure summary, and drops into a
   keyword-per-line REPL against that exact live session:
   ```
   FAIL: Story.Broken Turn > Human Click[label=Approve]
     TimeoutError: Locator.get_by_label: Timeout 30000ms exceeded.
   repl-on-failure: one keyword per line against the live session
   (Keyword Name<tab or 4 spaces>arg1<tab or 4 spaces>arg2), Ctrl-D/EOF to
   stop and let teardown run.
   Get Current Page
   OK
   ```
   Try the fix directly against the failing page, Ctrl-D/EOF when done, and
   teardown (and the process) proceeds normally. This is a single `run`
   invocation, one Python process throughout — no separate `probe` call and
   no risk of a dead browser.
3. **`probe KEYWORD args... [--resource FILE]`** — runs one keyword against
   the *live* session a previous `run`/`probe` call left open, **as long as
   it happened in this same Python process**: the session is module-level
   state in `screencast.library`, not per-instance, and it does **not**
   survive a process exit. Two separate `screencast run` / `screencast probe`
   shell commands do *not* share a browser — each is its own process, so
   `probe` there always starts a fresh one. `--repl` reads one keyword call
   per line from stdin against the same session for as long as the process
   stays up; to share one browser between a `run` and later `probe` calls
   without `--repl-on-failure`, call `driver.run(...)` then
   `driver.probe(...)`/`driver.repl(...)` from one Python script.
4. **`keywords resources/app.resource`** — lists a resource's keywords
   with their arguments and doc, so you know what already exists before
   writing a new one or guessing an argument name.

Loop: `run --repl-on-failure` → read the summary → try the fix at the paused
REPL against the still-open page → Ctrl-D/EOF → `run --no-record` again once
it's clean → record for real. `--repl-on-failure` runs its probes via
`BuiltIn().run_keyword()` in the same process and execution context as the
run itself — deliberately not a nested `TestSuite.run()` (as `probe` uses):
Robot Framework's `TestSuite.run()` wraps its execution in `with LOGGER:`,
and `LOGGER` is a process-wide singleton whose `__exit__` unconditionally
resets it, discarding every listener the *outer*, still-running suite
registered — a nested run from inside a listener callback returns normally
with no exception, but every listener notification for the rest of the outer
run silently stops arriving (verified against Robot Framework 7.5).

# Take verification

`run` exiting 0 does not mean the *recording* is good — dead air, a blank
frame, and a truncated composite all still exit 0. Always:

```sh
screencast compose <take dir>
screencast verify <take dir>
```

`verify` writes `report.json` (`{"ok": bool, "findings": [...]}`) and
`contact-sheet.png`, sampled at a rate derived from the take's own measured
duration — never a stale hand-tuned value. Read the contact sheet: the checks
catch what they were written for. Findings, by `check`:

| `check` | Means |
|---|---|
| `stream` | Not exactly one 1920x1080 25fps video stream |
| `duration` | Composed duration doesn't match the timeline's own prediction (observer length + every chapter/hold duration) |
| `dead_air` | Judged from the timeline's `wait` events (recorded around `Sleep`, `Wait Until Keyword Succeeds`, the engine's own waits, and any keyword tagged `screencast:wait`): **error** for one wait over 10 s, warning when all waits together pass 30 s |
| `blank_frame` | A near-pure-black interval (`blackdetect`, tuned so a dark-navy title card does not count), or an actor's page still one flat colour where the composer enters its clip — also what missing fonts look like |
| `empty_inset` | A sampled observer frame at some turn's midpoint is a near-uniform colour — that turn's inset would be blank |

**Tag your own polling keywords** so their waiting counts as dead air:
`[Tags]    screencast:wait` on a user keyword, or
`@keyword(tags=[WAIT_TAG])` (from `screencast.library`) on a Python one.
Only the outermost wait counts, and waits under 0.25 s are not recorded.
Pixels cannot judge dead air — a whole-frame freeze check cannot see cursor
motion at 1080p and could not tell a healthy take from one with a deliberate
12 s sleep — which is why the timeline does.

# Extending the engine

The engine lives at <https://github.com/datakurre/robotframework-screencast>. To
change it — not just your stories — work in a clone of that repository
(`pip install -e ".[test]"`, then `pytest`) and open a pull request; an
installed copy is not the place to edit. The paths below are the repository's.

Add to `src/screencast/library.py` only when the need is generic — not "this
app's form has a field named X" but "Robot keywords can't express
`get_by_label()`/`frame_locator()`/`.last` in plain selector syntax", the
kind of gap that produced the `label=`/`>>>`/`index=` conventions above.
Mirror an addition with:

- a unit test in `src/screencast/tests/test_library.py` against the fake
  Playwright in `tests/fakes.py` (extend the fake if the new keyword touches
  a Playwright API it doesn't cover yet) — no real browser needed;
- if it changes what the composer/verifier read or produce, a
  `tests/test_compose.py`/`test_verify.py` case, which runs against real
  ffmpeg on tiny synthetic clips.

See `reference.md` for the timeline schema's full field reference, the
composer's segment-boundary algorithm in more depth, and writing a new
`verify` check. It also covers recording without the engine — the raw
`page.screencast` API, a headless terminal (`ttyd`), transcoding to MP4/GIF and
hand-written `ffmpeg` edits — for a one-off that does not need a story.
