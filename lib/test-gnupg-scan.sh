#!/usr/bin/env bash
# Fixture tests for agent-sandbox-gnupg-scan.
#
# The smart-card case is the one that matters most: a card-backed ~/.gnupg is
# full of .key files, and a naive "any key file present" check would lock out
# precisely the setup this tool is built around.
#
# Usage: test-gnupg-scan.sh [path-to-scanner]

set -euo pipefail

scanner="${1:-$(dirname "$0")/gnupg-scan.sh}"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

failures=0

# Build a GnuPG home from a list of "filename:header" specs.
make_home() {
  local name="$1"
  shift
  local home="$tmp/$name"
  mkdir -p "$home/private-keys-v1.d"
  printf 'public keyring\n' > "$home/pubring.kbx"
  local spec file header
  for spec in "$@"; do
    file="${spec%%:*}"
    header="${spec#*:}"
    printf '%s(rsa(n #00AB#)(e #010001#)))\n' "$header" \
      > "$home/private-keys-v1.d/$file"
  done
  printf '%s' "$home"
}

expect() {
  local label="$1" home="$2" want="$3"
  local got=0
  bash "$scanner" "$home" > "$tmp/out" 2>&1 || got=$?
  if [[ "$got" == "$want" ]]; then
    printf 'ok       %s\n' "$label"
  else
    printf 'FAIL     %s (exit %s, wanted %s)\n' "$label" "$got" "$want"
    sed 's/^/           /' "$tmp/out"
    failures=$((failures + 1))
  fi
}

# --- safe cases ------------------------------------------------------------

expect "missing gnupg home" "$tmp/nonexistent" 0

empty=$(make_home empty)
expect "empty private-keys-v1.d" "$empty" 0

# The smart-card setup: stubs only.
card=$(make_home card \
  "AB12.key:(shadowed-private-key" \
  "CD34.key:(shadowed-private-key" \
  "9999.key:Token: foo Key: (shadowed-private-key")
expect "smart-card stubs only" "$card" 0

# --- unsafe cases ----------------------------------------------------------

protected=$(make_home protected "EF56.key:(protected-private-key")
expect "passphrase-protected key on disk" "$protected" 2

unprotected=$(make_home unprotected "7890.key:(private-key")
expect "unprotected key on disk" "$unprotected" 2

# Fails closed on anything it does not recognise.
unknown=$(make_home unknown "AAAA.key:(future-key-format")
expect "unrecognised key format" "$unknown" 2

# One real key among stubs must still trip the wire.
mixed=$(make_home mixed \
  "AB12.key:(shadowed-private-key" \
  "EF56.key:(protected-private-key" \
  "CD34.key:(shadowed-private-key")
expect "one real key among card stubs" "$mixed" 2

legacy=$(make_home legacy "AB12.key:(shadowed-private-key")
printf 'secret keyring data\n' > "$legacy/secring.gpg"
expect "legacy secring.gpg" "$legacy" 2

empty_legacy=$(make_home empty-legacy "AB12.key:(shadowed-private-key")
: > "$empty_legacy/secring.gpg"
expect "empty legacy secring.gpg is ignored" "$empty_legacy" 0

# A file whose S-expression starts with (protected-private-key but also
# mentions (shadowed-private-key in a comment must still be flagged as unsafe.
spoofed=$(make_home spoofed \
  "SPOOF.key:(protected-private-key (comment (shadowed-private-key)")
expect "protected key with shadowed-key in comment" "$spoofed" 2

# --- output shape ----------------------------------------------------------

# pipefail would otherwise see the scanner's deliberate exit 2 as a failure.
report=$(bash "$scanner" "$mixed" || true)

if grep -q 'EF56.key' <<< "$report"; then
  printf 'ok       names the offending file\n'
else
  printf 'FAIL     names the offending file\n'
  failures=$((failures + 1))
fi

if grep -q 'AB12.key' <<< "$report"; then
  printf 'FAIL     must not report card stubs as offenders\n'
  failures=$((failures + 1))
else
  printf 'ok       card stubs are not reported\n'
fi

if [[ "$failures" -gt 0 ]]; then
  printf '\n%s test(s) failed\n' "$failures" >&2
  exit 1
fi

printf '\nall gnupg-scan tests passed\n'
