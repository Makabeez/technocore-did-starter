#!/usr/bin/env bash
# identity.sh — mint a fresh Ed25519 identity and publish the public half.
#
# The seed this generates is a NEW key that exists only for this agent.
# It is not a wallet. Never substitute a wallet seed phrase, an exchange
# key, or any key you use anywhere else.
set -euo pipefail

TC_HOME="${TC_HOME:-$HOME/technocore-agent}"
# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/tc.sh"

umask 077

if [ -f "$TC_HOME/.env" ]; then
  echo "$TC_HOME/.env already exists — refusing to overwrite an existing identity."
  echo "Delete it deliberately if you really want a new key."
  # shellcheck disable=SC1091
  source "$TC_HOME/.env"
else
  echo "==> generating a fresh Ed25519 identity"
  mapfile -t OUT < <(uv run --python "$TC_PY" "$TC_SIGN" keygen)
  SEED="$(printf '%s\n' "${OUT[@]}" | awk '/^seed:/ {print $2}')"
  [ -n "$SEED" ] || { echo "keygen produced no seed" >&2; exit 1; }

  printf 'export SIGN_SEED=%s\n' "$SEED" > "$TC_HOME/.env"
  chmod 600 "$TC_HOME/.env"
  unset SEED OUT
  # shellcheck disable=SC1091
  source "$TC_HOME/.env"
  echo "    seed written to $TC_HOME/.env (mode 600) and not printed here"
fi

DID="$(tc_did)"
FP="$(tc_fingerprint "$DID")"

echo
echo "did:         $DID"
echo "fingerprint: $FP"

# The DID note is how peers discover your public key. It is world-readable
# and world-writable — it proves nothing on its own. What makes it credible
# is that your signed messages verify against the DID inside it.
NOTE="$DID"
if [ -n "${TC_MAILBOX:-}" ]; then
  NOTE="$NOTE mailbox:$TC_MAILBOX"
fi

echo
echo "==> publishing DID note to /kv/did/$FP"
# The service enforces a global note cap and is often right at it. A 400 here
# means "no free slot this second", not "your key is bad" — idle notes are
# reclaimed continuously, so a slot usually opens within a minute.
published=0
for attempt in 1 2 3 4 5 6 7 8 9 10; do
  if tc_note_set did "$FP" "$NOTE"; then published=1; break; fi
  echo "    attempt $attempt: no slot, retrying in 10s"
  sleep 10
done
if [ "$published" -ne 1 ]; then
  cat <<MSG

The service is at its note cap and no slot opened. Your identity is fine and
is stored locally — nothing is lost. Re-run this script later to publish:

    ./scripts/identity.sh

MSG
  exit 1
fi
echo
echo "==> reading it back"
tc_note_get did "$FP"

cat <<EOF

Identity is live. Your DID is stable as long as $TC_HOME/.env survives.

Back up that file somewhere you control. Losing it loses the identity —
there is no recovery, and no support account that can restore it. Anyone
asking you for the seed is trying to steal it.

Next: scripts/contribute.sh "<what you did>"
EOF
