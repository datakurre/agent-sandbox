#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
agent-sandbox-attach [ID] [-- CMD...]

Executes an interactive command inside a running sandbox.
If no command is provided, starts an interactive bash shell.

  ID      The short name or full container name of the sandbox.
          If omitted, acts on the current workspace's sandbox.
  CMD     The command to execute (default: bash).
USAGE
}

explicit=""
cmd=()

while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--help) usage; exit 0 ;;
    --) shift; cmd=("$@"); break ;;
    -*) echo "${0##*/}: unknown option: $1" >&2; usage >&2; exit 1 ;;
    *) 
       if [[ -z "$explicit" ]]; then
         explicit="$1"
       else
         echo "${0##*/}: unexpected argument: $1" >&2; usage >&2; exit 1
       fi
       ;;
  esac
  shift
done

sandbox="$(resolve_sandbox "$explicit" --running)"

if [[ ${#cmd[@]} -eq 0 ]]; then
  cmd=(bash)
fi

exec podman exec -it "$sandbox" "${cmd[@]}"
