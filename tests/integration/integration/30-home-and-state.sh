#!/usr/bin/env bash
# The writable home, and what persists across sessions.
#
# ~/.config, ~/.cache and ~/.local are tmpfs so each session starts clean; the
# selected agent's own state is bind-mounted over them so its login survives.
# The interaction of those two is what this checks -- a tmpfs mounted after the
# bind would silently discard everything the agent saved.
source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"
require_image

for dir in .config .cache .local .local/share; do
  out="$(sandbox_run -- bash -c "touch ~/$dir/probe && echo written")"
  assert_contains "$out" "written" "~/$dir is writable"
done

# A tmpfs home does not carry anything between sessions.
sandbox_run -- bash -c 'echo marker > ~/.cache/leak' >/dev/null
out="$(sandbox_run -- bash -c 'cat ~/.cache/leak 2>&1 || true')"
assert_not_contains "$out" "marker" "a second session's ~/.cache"

# The selected agent's state directory does persist, because it is a bind.
marker="persisted-$$"
sandbox_run opencode -- bash -c "mkdir -p ~/.config/opencode && echo $marker > ~/.config/opencode/probe" >/dev/null
out="$(sandbox_run opencode -- bash -c 'cat ~/.config/opencode/probe 2>&1 || true')"
assert_contains "$out" "$marker" "the agent's own state in a later session"
rm -f "$HOME/.config/opencode/probe"

# ...and only for the agent that was selected.
out="$(sandbox_run claude -- bash -c 'ls ~/.config/opencode 2>&1 || true')"
assert_not_contains "$out" "probe" "another agent's state directory"

# --devenv persists only its own subdirectory, while the parent remains a
# writable per-session tmpfs.
probe="probe-$$"
marker="devenv-persisted-$$"
trap 'rm -f "$HOME/.local/share/devenv/$probe"' EXIT
out="$(sandbox_run --devenv -- bash -c \
  "touch ~/.local/share/parent-$probe && echo $marker > ~/.local/share/devenv/$probe && echo written")"
assert_contains "$out" "written" "--devenv writable parent"
out="$(sandbox_run --devenv -- bash -c \
  "cat ~/.local/share/devenv/$probe && test ! -e ~/.local/share/parent-$probe && echo parent-absent")"
assert_contains "$out" "$marker" "--devenv data in a later session"
assert_not_contains "$out" "parent-$probe" "--devenv parent does not persist"
assert_contains "$out" "parent-absent" "--devenv parent does not persist"
