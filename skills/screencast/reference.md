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
  "tracks": [
    {"name": "terminal", "video": "page@ghi789.webm", "offset": -5.0,
     "focusable": false, "fade": true}
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
- **`tracks[]`** (optional, absent on a timeline written before it existed)
  — one entry per `Start Track`/`End Track` pair (see "Engine-recorded
  tracks", below, for the full mechanism). `name` must be unique across
  the whole take; `offset` uses the same clock as `actors[].offset`
  (`Start Track` needs a running observer, so it is never negative in
  practice; unlike an external `--track`'s, which often is).
  `focusable`/`fade`/`scale`/`margin`/`border`/`corner` (defaults
  `true`/`false`/`0.4`/`24`/`3`/`"bottom-left"`) are all omitted at their
  default, same convention `actors[].duration` already follows.
- **`events[].time`** — always on the observer's clock, same units as
  `actors[].offset`.
- **`chapter`** — a title card. `duration` is how long the composer holds
  it; no browser time is spent waiting for it.
- **`focus`** — which recording is main from this point on: `"actor"`,
  `"observer"`, or the `name` of a track recorded in `tracks[]` (resolved
  at compose time against `tracks[]`, not validated when `Focus` itself is
  called — see "Engine-recorded tracks", below, for why). `scale`/`margin`/
  `border` (defaults 0.4/24/3) describe the *other* view(s)' inset(s).
  `solo` (default `false`) turns every inset off entirely from this point
  on — not just the usual actor/observer cross-inset, but every track's
  own always-present inset too — until the next `focus` event says
  otherwise; there is no other way to turn an inset back off once one has
  become available.
- **`hold`** — freeze the current frame(s) for `duration` extra seconds.
  `view` (default `"observer"`; the `Hold` keyword always writes one) is
  which side is "current" for freezing purposes when a hold coincides with
  a turn boundary — only `"actor"`/`"observer"` are valid here (`Hold`
  refuses anything else at record time). A hold
  event with no `view` key at all (not something `Hold` itself ever
  writes, but a legal, pre-existing document the schema still accepts)
  falls back to whatever `_view_at()` resolves at that instant instead —
  including a focused track, frozen on its own last frame, if that is what
  was on screen. A hold with
  `"recorded": true` is real elapsed recording time the library itself
  noted (the wait after a turn ends, while the observer is brought back to
  the front): the composer inserts no synthetic freeze for it.
- **`caption`** — a subtitle cue. The composer maps `time` (observer clock) to
  the composed output's clock — less the dropped lead-in, if any (see step 3
  of the segment algorithm, below), plus every title card and hold inserted
  at or before it — and writes `output.vtt` next to the composed output.
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
   never rendering), and every track's own start and end, so no segment
   straddles a track appearing, running out, or being promoted to main.
3. **Drop the lead-in.** A turn's chapter is timestamped at its first `Go
   To`'s load, so a titled first turn leaves raw footage ahead of the card
   (`Start Observer`'s load, the turn's context creation and navigation).
   When the take's first chapter fires at or before its first turn starts
   (`compose._leading_shift()`), every boundary before it is dropped —
   along with any hold in that stretch — and the output opens on the card.
   `_output_time()` (captions), `chapter_windows()` and `verify`'s
   `predicted_duration()` subtract the same shift.
4. Walk consecutive boundary pairs `(start, end)`. For each: emit any
   chapter/hold whose event time equals `start` (a title card or freeze
   inserted *before* this segment — pure insertion, consumes no recorded
   time from either source), then resolve `(view, inset_turn, scale,
   margin, border, solo)` at the segment's midpoint via `_view_at()` (the
   default policy from `SKILL.md`; `view` may also be `track:<name>`), and
   build the segment: a `trim`+`scale` of the main source, an inset built
   from the other source (live footage if that actor's turn is still
   technically open, otherwise their last frame frozen with
   `tpad=stop_mode=clone`), composited with `overlay`, then each track's
   own inset on top — none of them when `solo`.
5. A **trailing** chapter/hold whose time equals the very last boundary
   never becomes any segment's `start` (nothing follows it) — emitted once
   more, explicitly, after the loop.
6. Every source slice is normalized to `scale=1920:1080` before concat:
   nothing guarantees a source clip was recorded at exactly that size (a
   differently configured viewport, or in `tests/test_compose.py`, a
   synthetic stand-in clip), and `concat` requires uniform frame size.
7. All segments concatenate, in order, into `[out]`.

Title cards are rendered once per distinct `(eyebrow, title, subtitle,
duration)` and cached in `<take_dir>/titles/`; composing the same timeline
twice does not re-render them.

**The main view needs the same live/frozen clamp the inset already had.**
A gap `focus` event can bring an actor back as the *main* view after their
own `turn_end` (see `test_gap_focus_event_can_bring_back_the_actor` and
the "Between turns" bullet of `compose.py`'s docstring) -- e.g. a story that sets `Focus
actor` and deliberately never flips it back before `End Actor Turn`, to
close a take on that actor's own last frame. Past `turn_end` there is no
more live footage for them either way, same as the inset case step 4
already describes -- but the main-view branch (`if view == "actor":`)
used to call the live-trim helper unconditionally, with no `turn_end`
clamp. The clip's own `rel_start` (already clamped to its real duration)
could then land at or past `rel_end`, handing ffmpeg's trim filter a
backwards/empty range, which silently produced a near-zero-length segment
instead of an error -- chopping real seconds off the composed output. Fixed
by giving the main-view branch the exact same `if end <= turn_end: <live>
else: <frozen>` clamp the inset branch already had; see
`test_compose_with_actor_focus_lingering_past_turn_end_freezes_instead_of_breaking`.

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

## The injected cursor

`screencast/cursor.py`'s `CURSOR_SCRIPT` is injected into every recorded
context (observer and actor) via `context.add_init_script()` — plain CSS and
JS, not Playwright's own cursor (which lives in a closed shadow root and
cannot be resized or restyled, see the `browser` skill). It re-creates itself
on every new document, so a caller moving the mouse after a navigation
(`human_click()`/`human_move()` already do this) is what keeps it visible.
It fades to `opacity: 0` via a CSS transition after ~3s with no `mousemove`
(a `setTimeout`, cleared and rescheduled on every move, also armed once at
install so a cursor that never moves still fades), and back to `1`
immediately on the next one — so it doesn't sit motionless on screen through
a long wait. The click-ripple animation is separate and unaffected by the
fade. `Hide Cursor` hides both outright instead, for a turn with no mouse
interaction at all where the cursor looks out of place even appearing once
(see "Using a ttyd terminal as the observer", below). It hides them on the
current page at once *and* adds an init script to that page's context, so
they stay hidden on every later document — the cursor itself is re-injected
on each navigation, and a style tag alone would not survive one.
Beyond that, change the color, size, timing, or fade behavior directly in
`CURSOR_SCRIPT`'s CSS/JS; there is no configuration surface for those today.

## Using a ttyd terminal as the observer

A terminal is a web page like any other, so `Start Observer` can point
straight at one (the `browser` skill's "Recording a headless terminal"
material covers getting ttyd running) -- no `tracks=` needed; this is the
engine recording the terminal *as* the observer, not compositing an
externally-recorded one after the fact (see "Compositing a secondary PiP
source", below, for that case instead). Three gotchas specific to a
terminal observer, none of them about the engine being wrong so much as a
terminal looking nothing like the web pages the rest of this engine was
built against:

- **The injected cursor is still pointless on a terminal.** The 3s idle
  fade above (described in "The injected cursor") was built for a page
  with real pointer interactions and long waits between them -- it still
  means the cursor *appears* at least once, which looks out of place on
  something purely keyboard-driven. Call `Hide Cursor` right after `Start
  Observer` instead of relying on the fade; it also hides the click-ripple,
  for the one deliberate click a terminal turn usually still does (to focus
  it) before going keyboard-only.
- **ttyd's own xterm.js resize overlay needs hiding separately, and
  earlier.** ttyd bundles its own xterm.js "OverlayAddon", which briefly
  flashes e.g. `135x41` over the terminal the first time it resizes --
  reliably once, early, as soon as the real font metrics settle (the
  container's first layout pass can use a fallback font's cell size). The
  overlay is a plain `<div>` with no class or id, just a distinctive
  inline style (`font-size: xx-large`) -- no CSS selector can hide a
  classless element pre-emptively, and the resize fires early enough
  (within the first second) that a `MutationObserver` installed via
  `page.evaluate()` *after* `Start Observer` returns is usually already
  too late: the node was created and the flash already recorded before the
  observer call ever runs. Two ways out, and only the second is reliable:
  running the real recording later than the flash (e.g. behind a leading
  title card -- see step 3 of "The composer's segment algorithm" above,
  which drops the raw preamble before it entirely) hides it as a
  side effect, but only if that preamble is already short enough; the
  robust fix is a `MutationObserver` that's in place *before* ttyd's own
  bundle runs at all, which for an already-loaded document only `Start
  Observer` itself can arrange (it calls `context.add_init_script()`
  before its own `page.goto()`) -- a page-level fix has no equivalent hook
  for a navigation that already happened.
- **There is no DOM text layer.** ttyd's xterm.js renders to a `<canvas>`,
  so `page.inner_text()`/`page.content()` see nothing of what's on screen
  -- reading the terminal's apparent state (did a command finish, what did
  it print) needs a side channel instead: the application's own API if it
  has one, or `docker exec`/a file-existence check against whatever the
  terminal's own shell is running inside, polled rather than scraped.

**Sequencing two typed commands where the second depends on the first
finishing needs the same side channel, not a longer `Sleep`.** A fixed
`Sleep` between `Type Command`-style keystrokes is a guess at how long the
first command takes; under load the guess runs out while the first
command is still printing, and the second command's keystrokes land
interleaved mid-line with its still-printing output -- garbling both,
including the *next* shell prompt, which can look like the prompt
"disappeared" entirely rather than merely being interleaved with other
text. Poll the same side channel the no-DOM-text-layer bullet above
already needs (a file the first command is known to write last, an API
response) instead of guessing a duration.

## Engine-recorded tracks (Start Track/End Track, Focus(view=name))

Unlike the externally recorded `tracks=`/`--track` path below (a secondary
source the engine never drove itself, composited after the fact), `Start
Track`/`End Track` open and close a context the engine *does* drive and
record for the whole take, the same way `Start Observer`/`End Observer`
does for the observer:

```robotframework
Start Observing
    Start Observer    cockpit    ${BASE_URL}/cockpit
    ${terminal_url}=    Start Purjo Terminal    # project-specific: launch ttyd, return its URL
    Start Track    terminal    ${terminal_url}    focusable=False    fade=True
    Hide Cursor    # a terminal has no pointer interactions worth drawing

...

Wrap Up
    End Track    terminal      # before End Observer -- the observer closes last
    Stop Purjo Terminal
    Observe    ${BASE_URL}/cockpit
    End Observer
```

`compose()` always composites a recorded track as a corner inset
(`bottom-left` by default, override with `corner` -- see below) on every
segment from its own `offset` onward, regardless of focus — this is what
makes it "always on screen" rather than something a story has to remember
to keep showing. A track's `name` must be unique for the whole take:
`Start Track` raises if it was already used for an earlier track, even one
that already closed, since `Focus(view=name)` and `compose()`'s own
`track_defs_by_name` both resolve a track by name alone and could not tell
two same-named clips apart. A track still open at `End Observer` is closed
and recorded there, with a warning (otherwise its video would never be
flushed); an explicit `End Track` keeps the story's intent readable.
`scale`/`margin`/`border` given from Robot Framework as strings are
converted to numbers, and an unknown `corner` fails at `Start Track`.

**`focusable` (default `True`).** With the default, `Focus view=name`
promotes the track to the composer's main (full-frame) view for whichever
segments follow, with the observer and the active actor turn demoted to
its two PiPs — see `test_focus_on_a_track_makes_it_main_with_observer_and_
actor_as_pips` in `tests/test_compose.py`. Pass `focusable=False` when a
track should *never* be main by policy (a shell that must always stay a
PiP, say): this is enforced structurally — the track's name is left out of
`compose()`'s own `track_names` set entirely, so even a `Focus view=name`
event naming it (a leftover from editing the story, or from re-cutting
`timeline.json` by hand) falls back to ordinary actor/observer resolution,
exactly like naming a track that was never recorded at all. Prefer this
over the discipline of "just never write that `Focus` call" — a re-cut
(see "Re-cutting a take needs no re-recording" in `SKILL.md`) only has to
edit `timeline.json`'s events, and `focusable=False` survives that untouched.

A `focusable` track still falls back the same way when `Focus view=name`
is in effect *before* its own `offset` or *after* it has already run out
(`offset <= t < offset + duration`, checked at the point `_view_at()`
resolves, the same window `track_slice()` trims against) — "not yet
available"/"already finished" is a real third case alongside "never
recorded" and "opted out with `focusable=False`" above, and the schema's
own `focusEvent.view` description names it explicitly. A take-wide `Focus
view=name` set once near the start, say, still shows the observer for the
stretch before the track actually starts, and again once the track's own
footage has run out (see "The shorter-source trap", below) — it only
takes over while genuinely live.

`Focus(view=...)` no longer validates `view` against `'actor'`/`'observer'`
at record time (it only rejects an empty string) — any other value is
assumed to be a track name, since one may not exist yet when `Focus` is
called (see `library.py`'s own `focus()` docstring). This means a typo no
longer fails loudly at record time; `compose()` instead issues a
`UserWarning` for a `view` that matches neither `'actor'`/`'observer'` nor
any track actually recorded on the timeline (`focusable=False` tracks
still count as "recorded" here, so opting a track out never warns) —
check `compose()`'s own stderr output if a take's cuts look wrong and
nothing else explains it.

**`fade` (default `False`).** `fade=True` fades the track's own inset
image past its left third: fully opaque there, then a logarithmic falloff
(`1 - log(1+9t)/log(10)`, the standard audio fade-out curve — steep at
first, easing towards zero) across the remaining two-thirds, reaching
fully transparent at its right edge. Built via `format=yuva420p` +
`geq=lum=...:cb=...:cr=...:a=...` in `compose.pad_inset_faded()` — the
`lum`/`cb`/`cr` expressions are pure self-reference passthroughs
(`lum(X,Y)` while evaluating the luma plane *is* the luma plane), only
`a` actually computes a new value per pixel. Useful for an inset whose
most legible content is left-aligned (a left-to-right terminal prompt) and
is always on screen regardless of focus: the fade lets more of the main
view show through the rest of the box instead of permanently occluding a
fixed rectangle of it. Independent of `focusable` — it only ever changes
how the track's *inset* renders; a segment where the track is main (an
eligible, focused track) still renders it full-frame, unfaded.

**`scale`/`margin`/`border` (schema defaults `0.4`/`24`/`3`, the same as a
focus event's own inset).** Override this track's own inset's size and
spacing — e.g. `Start Track terminal ${url} scale=0.6` for a PiP 1.5x the
default size, with no re-recording: these are read fresh from
`timeline.json` by every `compose()` call, so re-cutting a take only means
editing its track clip's `scale` (directly, or via `Timeline.load()` +
`add_track_clip()`'s same kwargs) and recomposing. Exactly mirrors what
the external `tracks=`/`--track` path already accepted per-track (see
below) — before this existed, an engine-recorded track's inset size was a
fixed `DEFAULT_SCALE`/`DEFAULT_MARGIN`/`DEFAULT_BORDER`, not overridable at
all. Like `fade`, only ever affects the inset rendering, never a segment
where the track is main (main always fills the whole frame, regardless).

**`corner` (schema default `bottom-left`).** Which corner this track's own
inset is pinned to — one of `bottom-left`/`bottom-right`/`top-left`/
`top-right`, the same four values the external `tracks=`/`--track` path's
`CORNER` already accepts. Before this existed, an engine-recorded track's
inset corner was hardcoded to `bottom-left` with no override at all, so two
simultaneous engine tracks (or a track and a `Focus`-demoted actor/
observer inset) could never avoid landing in the same corner at once — see
`test_compose_with_two_simultaneous_engine_tracks_in_different_corners` in
`tests/test_compose.py`. Set a second/third track's `corner` to one no
other always-present inset is using for that stretch of the take.

**Dead air.** A `Sleep`/`Wait Until Keyword Succeeds`/etc. during which
nothing is being driven is not automatically dead air if a track has real,
independently changing content on screen for that whole stretch — judged
by `verify.py`'s `_covered_by_a_track()`, two ways:

- the track is the *main* view at the wait's start (a `Focus view=name`
  still in effect) — resolved the same way `compose()` itself decides what
  is on screen, so this can never disagree with the composed output; or
- the track is "only" a corner inset, but has not yet run out — checked at
  both the wait's start *and* end (`offset <= t < offset + duration`,
  track footage is contiguous and only ever runs forward, so true at both
  ends means true throughout). This is what lets a `focusable=False` track
  still exempt a wait: "never main" and "not live" are independent —
  `focusable` says nothing about whether the inset itself still has real
  footage at a given instant. Not under a `solo` focus, though: that hides
  every inset, so the wait is dead air on screen again.

A track that has already frozen on its last frame by the time a wait
starts (see "The shorter-source trap", below) does *not* cover that wait
either way — a frozen frame is exactly the "nothing changing" dead_air is
meant to catch, track or not.

## Compositing a secondary PiP source onto the engine's own output

The engine never records a secondary source itself (a terminal via `ttyd`,
say; see the `browser` skill's "Recording a headless terminal" material) —
that recording always happens "outside the engine". But *compositing* it as
a corner inset on top of the engine's own output is a native, first-class
part of `compose()`: pass `tracks=` (or repeat `--track` on the CLI), no
second `ffmpeg` pass required.

```sh
screencast compose take/ \
  --track terminal:take/raw_terminal.webm:23.703:bottom-left:0.4167 \
  --output take/final.webm
```

`--track NAME:VIDEO:OFFSET[:CORNER[:SCALE]]` (repeatable). `OFFSET` is
seconds on the *observer's own clock* — the same convention `actors[].offset`
already uses in `timeline.json` — i.e. when the track's own t=0 falls
relative to `Start Observer`. `CORNER` is one of `bottom-left` (the
default — the engine's own actor/observer inset keeps `bottom-right`, so the
two never collide unless you ask them to), `bottom-right`, `top-left`,
`top-right`. `SCALE` defaults to `DEFAULT_SCALE` (0.4); margin/border aren't
exposed on the CLI (they default to the engine's own `DEFAULT_MARGIN`/
`DEFAULT_BORDER`) — pass `tracks=[{"margin": ..., "border": ...}]` directly
to `compose()` from Python if you need to override them. `compose()`
`ffprobe_duration()`s each track's video the same way it already does for
actor clips.

**Why a title card automatically stays on top, with no `enable=` needed.**
A track is only ever composited onto the main per-boundary segment loop's
own segment label (see *The composer's segment algorithm*, above) — the
same `label` the `if view == "actor": ... else: ...` block builds. A
chapter card (or a synthetic hold freeze) is a wholly separate clip, emitted
by `emit_chapters_at()`/`emit_holds_at()` straight into `segment_labels`;
it never passes through that `label` at all. So a track is structurally
absent behind a title card — compositing it never has to know where the
cards are, there is no `chapter_windows()`/`enable()` expression to build,
and the two code paths can never drift apart because they are, by
construction, disjoint.

**The shorter-source trap this still has to handle.** A track's own
recording is usually shorter than the composed output, not longer — every
chapter card adds real on-screen time with no corresponding external
footage, so a 5-chapter take can easily run 30-40s longer than a track that
only spans the live portions. `compose()`'s own `track_slice()` helper
handles this the same way `frozen_turn_slice()` already does for an actor
whose turn has ended: trim whatever real footage is available for a given
segment, then `tpad=stop_mode=clone:stop_duration=<n>` to freeze its last
frame for the remainder, so no segment ever comes up short for `concat`.
Visibility is resolved per segment, and is still exact: a track's own start
and end are segment boundaries themselves. A track whose `offset` is still ahead of a segment's own start
composites nothing for that segment at all (not a frozen first frame) —
chosen deliberately, since "not recorded yet" is a more honest picture than
a frame that looks like something is already there.

### Fallback: the older hand-rolled second pass

Before `tracks=`/`--track` existed, the same effect required a second,
separate `ffmpeg overlay` pass *after* `screencast compose`, using
`screencast.compose.chapter_windows(timeline)` (each chapter's own
`(start, end)` span **in the composed output's own clock**) fed into the
overlay filter's `enable` option, combined with the same `tpad` trick by
hand:

```python
from screencast.compose import chapter_windows
from screencast.timeline import Timeline

timeline = Timeline.load(take_dir / "timeline.json")
windows = chapter_windows(timeline)  # [(0.0, 8.0), (47.65, 55.65), ...]
hide = "+".join(f"between(t,{s:.3f},{e:.3f})" for s, e in windows)
enable = f"not({hide})" if windows else "1"
```

```sh
ffmpeg -y -ss <offset> -t <generous> -i secondary.webm -i output.webm \
  -filter_complex "\
    [0:v]scale=800:-2,pad=iw+6:ih+6:3:3:color=0x1f2937,\
    tpad=stop_mode=clone:stop_duration=<pad-seconds>[pip]; \
    [1:v][pip]overlay=x=24:y=H-h-24:shortest=1:enable='<enable>',\
    format=yuv420p[outv]" \
  -map "[outv]" -r 25 -c:v libvpx-vp9 -deadline good -b:v 0 -crf 32 -an final.webm
```

Keep this only for an older engine version without `tracks=`, or a case
where extending `compose()` genuinely isn't an option — `chapter_windows()`
is still exported for it. Either way, verify the result's duration actually
matches `output.webm`'s own (`ffprobe`) — `screencast verify` only inspects
the engine's own `output.webm`, it has no idea a second pass (hand-rolled or
otherwise) happened to produce a different final file.

## What CI covers

The engine's own tests (schema, the library against a fake Playwright, the
driver, the composer and verifier against real ffmpeg on synthetic clips) run
on Python 3.10 and 3.13 with the oldest supported and the latest Robot
Framework. They never run a real story's content: that needs the application
it records. After any change that could affect a story's selectors or flow,
run the story (`screencast run`, or with `--no-record` while iterating) against
your application by hand, then `compose` and `verify` it.
