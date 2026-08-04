#!/usr/bin/env bash
# Decide whether a GnuPG home is safe to expose to the sandbox.
#
# "Safe" means: it holds no usable private key material on disk.  The
# reference setup is a smart card, where the secret keys live on the card and
# ~/.gnupg holds only public keys plus *stubs* pointing at the card.
#
# The distinction matters because a card-backed home is NOT empty:
# private-keys-v1.d/ is full of .key files.  Telling the two apart requires
# reading the S-expression each file opens with:
#
#   (shadowed-private-key ...   stub; the secret is on the card      -> safe
#   (protected-private-key ...  passphrase-encrypted secret on disk  -> unsafe
#   (private-key ...            unencrypted secret on disk           -> unsafe
#
# Anything unrecognised counts as unsafe: this is a security gate, so it fails
# closed rather than guessing.
#
# Usage:  agent-sandbox-gnupg-scan [GNUPGHOME]
# Exit:   0  safe -- no on-disk secrets
#         2  unsafe -- offending paths listed on stdout, one per line
#         1  usage error

gnupg_home="${1:-$HOME/.gnupg}"

if [[ ! -d "$gnupg_home" ]]; then
  # Nothing to expose is trivially safe.
  exit 0
fi

offenders=()

# GnuPG 2.1+ keeps secrets here, one S-expression file per key.
private_dir="$gnupg_home/private-keys-v1.d"
if [[ -d "$private_dir" ]]; then
  while IFS= read -r -d '' key; do
    # The header is ASCII at byte 0.  Strip NULs so command substitution
    # cannot swallow the value, and collapse whitespace for the match.
    header=$(head -c 64 -- "$key" 2>/dev/null | tr -d '\0' | tr -s ' \t\n' ' ' || true)
    case "$header" in
      "(shadowed-private-key"*) continue ;;
      *) offenders+=("$key") ;;
    esac
  done < <(find "$private_dir" -maxdepth 1 -type f -print0 2>/dev/null | sort -z)
fi

# GnuPG 1.x / 2.0 kept secrets in a single keyring file.  An empty one is
# what `gpg --list-secret-keys` leaves behind on a fresh home; ignore that.
legacy_secring="$gnupg_home/secring.gpg"
if [[ -s "$legacy_secring" ]]; then
  offenders+=("$legacy_secring")
fi

if [[ ${#offenders[@]} -gt 0 ]]; then
  printf '%s\n' "${offenders[@]}"
  exit 2
fi

exit 0
