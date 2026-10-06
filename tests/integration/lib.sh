# Shared harness for the tests that need a real podman.
#
# Sourced by every case under integration/ and acceptance/.  A case is a plain
# shell script: it calls the assertions below, and the runner decides pass,
# fail or skip from its exit status.
#
#   0    pass
#   77   skip (the case said so, with a reason)
#   else fail
#
# Cases must clean up after themselves.  `stop_bg` stops a backgrounded
# launcher and everything under it, and `cleanup_sandboxes` removes the
# sandboxes and sidecars that appeared after the case started -- never one
# that was already running, such as the operator's own session -- so a case
# that dies half way does not poison the next one.

set -u

SKIP_EXIT=77

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
export ROOT

# ── locating the binary under test ──────────────────────────────────────────
# In order: an explicit override, this checkout's `nix build` result, then
# whatever is on PATH.  The point of preferring the result symlink is that a
# case then tests the tree it is sitting in rather than an older install.

if [ -n "${AGENT_SANDBOX_BIN:-}" ]; then
  AS="$AGENT_SANDBOX_BIN"
elif [ -x "$ROOT/result/bin/agent-sandbox" ]; then
  AS="$ROOT/result/bin/agent-sandbox"
elif command -v agent-sandbox >/dev/null 2>&1; then
  AS="$(command -v agent-sandbox)"
else
  echo "no agent-sandbox binary: run 'nix build' in $ROOT, or set AGENT_SANDBOX_BIN" >&2
  exit 1
fi
export AS

CASE_NAME="$(basename "${BASH_SOURCE[1]:-case}" .sh)"
CASE_TAG="astest-$CASE_NAME-$$"

# ── assertions ──────────────────────────────────────────────────────────────

_fail() {
  echo "  FAIL: $*" >&2
  exit 1
}

pass_note() {
  echo "  ok: $*"
}

skip() {
  echo "  SKIP: $*"
  exit "$SKIP_EXIT"
}

assert_eq() {
  local want="$1" got="$2" what="${3:-value}"
  [ "$want" = "$got" ] || _fail "$what: want [$want], got [$got]"
  pass_note "$what is [$got]"
}

assert_contains() {
  local haystack="$1" needle="$2" what="${3:-output}"
  case "$haystack" in
    *"$needle"*) pass_note "$what contains [$needle]" ;;
    *) _fail "$what does not contain [$needle]; got: $haystack" ;;
  esac
}

assert_not_contains() {
  local haystack="$1" needle="$2" what="${3:-output}"
  case "$haystack" in
    *"$needle"*) _fail "$what must not contain [$needle]; got: $haystack" ;;
    *) pass_note "$what does not contain [$needle]" ;;
  esac
}

assert_status() {
  local want="$1" got="$2" what="${3:-command}"
  [ "$want" = "$got" ] || _fail "$what: want exit $want, got $got"
  pass_note "$what exited $got"
}

# Succeeds when the command fails, which is most of what the acceptance tier
# asserts: a firewall is only doing its job when something does not happen.
assert_fails() {
  local what="$1"; shift
  if "$@" >/dev/null 2>&1; then
    _fail "$what: expected failure, but the command succeeded"
  fi
  pass_note "$what failed, as it must"
}

require_command() {
  command -v "$1" >/dev/null 2>&1 || skip "$1 is not installed"
}

require_env() {
  local name="$1" why="$2"
  [ -n "${!name:-}" ] || skip "$name is unset ($why)"
}

# An `allowed_hosts` entry on port 22 refuses the launch unless the host has
# authorized a key for that host, and this suite cannot authorize itself: the
# file is the operator's, and forging it is the one thing these cases must not
# do.  So skip, with the block to add -- the same shape as the secret cases.
require_trusted_host_key() {
  local host="$1"
  local config="${XDG_CONFIG_HOME:-$HOME/.config}/agent-sandbox/trusted.toml"
  if ! grep -qs -- "\"$host:22\"\\|\"$host\"" "$config"; then
    skip "no host key for $host is authorized on this host. Add to
         $config:
           [[network.known_hosts]]
           host = \"$host:22\"
           key = \"<from: ssh-keyscan $host, verified out of band>\"
         Launching with a :22 rule and no key is refused by design."
  fi
}

# The session word for a running sandbox, from `ctl list`.
#
# The listing is two lines of preamble ("Agent-sandbox containers for <pwd>:"
# and a tab-separated header) followed by one row per sandbox, and the row's
# second field is the word.  Splitting on tabs matters: STATUS holds "Up 3
# seconds", so whitespace splitting silently shifts every later column.
sandbox_word_from_list() {
  "$AS" ctl list 2>/dev/null | awk -F'\t' 'NR>2 && NF>=2 {print $2; exit}'
}

# Wait for a sandbox to appear in `ctl list`, and print its word.
wait_for_sandbox() {
  local tries="${1:-60}" word
  for _ in $(seq 1 "$tries"); do
    word="$(sandbox_word_from_list)"
    [ -n "$word" ] && { echo "$word"; return 0; }
    sleep 1
  done
  return 1
}

# A denial can take either of two shapes, and both are correct: the proxy
# refuses a CONNECT tunnel, so curl fails outright, or it answers a plain HTTP
# request with 403.  A test that accepts only one of them is asserting an
# implementation detail rather than the policy.
assert_denied() {
  local out="$1" what="${2:-the request}"
  case "$out" in
    *BLOCKED*|*403*) pass_note "$what was denied ($(echo "$out" | tr -d '\n'))" ;;
    *) _fail "$what was not denied; got: $out" ;;
  esac
}

# Start a static HTTP server on the host, in the background, and echo its PID.
# The host of a Nix project always has nix, so that is the last resort rather
# than a skip.
start_host_http_server() {
  local port="$1" bind="${2:-127.0.0.1}"
  if command -v python3 >/dev/null 2>&1; then
    python3 -m http.server "$port" --bind "$bind" >/dev/null 2>&1 &
    echo $!
  elif command -v nix >/dev/null 2>&1; then
    nix shell nixpkgs#python3 --command \
      python3 -m http.server "$port" --bind "$bind" >/dev/null 2>&1 &
    echo $!
  else
    return 1
  fi
}

require_network() {
  # A single cheap reachability check, so a case that needs egress fails as a
  # skip on an offline machine rather than as a firewall regression.
  curl --silent --show-error --max-time 10 -o /dev/null https://example.com 2>/dev/null \
    || skip "no outbound network from the host"
}

# ── driving the sandbox ─────────────────────────────────────────────────────

# Run a command inside a sandbox and print its output. Every flag before `--`
# goes to the launcher.
#
#   sandbox_run --workspace -- bash -c 'echo hi'
#
# On an enforcing SELinux host every launch gets `--selinux`, the way a user
# there has to launch: without it the sandbox can use none of its binds and
# every case fails for that one reason.  Prepended, so a case can still pass
# `--no-selinux` to test the unlabeled path.
if [ "$(cat /sys/fs/selinux/enforce 2>/dev/null)" = 1 ]; then
  SANDBOX_SELINUX=(--selinux)
else
  SANDBOX_SELINUX=()
fi

sandbox_run() {
  # The `+` form: an empty array under `set -u` is "unbound" before bash 4.4.
  "$AS" ${SANDBOX_SELINUX[@]+"${SANDBOX_SELINUX[@]}"} "$@" 2>&1
}

# Stop a background `sandbox_run ... &` (or any `cmd &`) by its $!.  That PID
# is the subshell, not the launcher in it: killing only the subshell leaves the
# launcher running, and a launcher that is still starting goes on to create a
# container after the case has cleaned up -- one that keeps its published port
# and fails the next run.  So its children go first.
stop_bg() {
  [ -n "${1:-}" ] || return 0
  local pids
  pids="$(_descendants "$1") $1"
  kill -TERM $pids 2>/dev/null
  # Long enough for the launcher's own cleanup -- stopping a sidecar and
  # reclaiming its network takes seconds -- before anything is KILLed.
  for _ in $(seq 1 300); do
    kill -0 "$1" 2>/dev/null || break
    sleep 0.1
  done
  kill -KILL $pids 2>/dev/null
  wait "$1" 2>/dev/null
  return 0
}

# Every process below PID, deepest last.  The launcher cleans up after a
# SIGTERM, but a case's background job is not always the launcher itself, and
# a launcher wedged before its handler is installed would leave `podman run`
# behind -- so the whole tree is stopped, and KILLed if it has not gone.
_descendants() {
  local child
  for child in $(pgrep -P "$1" 2>/dev/null); do
    echo "$child"
    _descendants "$child"
  done
}

# Fail if something already answers on a host loopback port the case is about
# to publish, so a leftover from an earlier run is named rather than tested.
require_free_port() {
  local port="$1"
  if curl --silent --max-time 2 -o /dev/null "http://127.0.0.1:$port/"; then
    _fail "127.0.0.1:$port already answers before the case starts (a leftover sandbox? see: podman ps; ss -ltnp | grep :$port)"
  fi
}

# A scratch workspace with an AGENTS.md, for the cases that need one.
make_workspace() {
  local dir
  dir="$(mktemp -d "${TMPDIR:-/tmp}/$CASE_TAG-ws.XXXXXX")"
  echo "$dir"
}

# Remove anything this case left running. Registered as a trap by the runner,
# but safe to call directly.
## The sidecar networks currently defined, one per line. A session's network,
## its sidecar container and its /tmp directory all carry the same name, so
## this doubles as the list of session ids.
sidecar_networks() {
  podman network ls --format '{{.Name}}' 2>/dev/null \
    | grep '^agent-sandbox-sidecar-' | sort
}

# Containers that existed before this case started: the operator's own
# sessions, which a case must never remove.  Taken when lib.sh is sourced.
CASE_PREEXISTING="$(podman ps -aq --no-trunc 2>/dev/null || true)"

#
# A subshell from /, because a case's cleanup usually removes its workspace
# while still standing in it, and podman then refuses every command with
# "error getting current working directory" -- which left every container in
# place for as long as this was run from the case's own cwd.
cleanup_sandboxes() (
  cd / || exit 0
  local id role
  # One query per role: podman ANDs repeated label filters.
  for id in $(for role in sandbox proxy; do
      podman ps -aq --no-trunc --filter "label=agent-sandbox.role=$role" 2>/dev/null
    done); do
    case "$CASE_PREEXISTING" in
      *"$id"*) continue ;;
    esac
    podman rm -f "$id" >/dev/null 2>&1 \
      || echo "  note: could not remove container $id" >&2
  done
  exit 0
)

# The image every case needs. Built once by the Makefile's `image` target;
# checked here so a case says what is missing rather than timing out.
require_image() {
  local ref="${AGENT_SANDBOX_IMAGE:-localhost/agent-sandbox:latest}"
  podman image exists "$ref" \
    || skip "image $ref is not loaded (run: make -C tests/integration image)"
}
