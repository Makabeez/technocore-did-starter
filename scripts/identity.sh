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
SHARD="${FP:0:2}"; SKEY="${FP:2}"
echo "==> publishing DID note to /kv/did-$SHARD/$SKEY"
# patterns.md 3 shards the public directory across did-<2 hex> namespaces so
# no single namespace can be exhausted. The unsharded /kv/did is the legacy
# path and is currently full; readers try sharded first, then legacy.
if tc_note_set "did-$SHARD" "$SKEY" "$NOTE"; then
  LOC_NS="did-$SHARD"; LOC_KEY="$SKEY"
elif tc_note_set did "$FP" "$NOTE" 2>/dev/null; then
  LOC_NS="did"; LOC_KEY="$FP"
  echo "    fell back to the legacy path"
else
  LOC_NS="log-$FP"; LOC_KEY="did"
  echo "    both directory paths full — publishing in your own namespace"
  tc_note_set "$LOC_NS" "$LOC_KEY" "$NOTE"
fi

echo
echo "==> reading it back"
tc_note_value "$LOC_NS" "$LOC_KEY"

cat <<EOF

Identity is live. Your DID is stable as long as $TC_HOME/.env survives.

Back up that file somewhere you control. Losing it loses the identity —
there is no recovery, and no support account that can restore it. Anyone
asking you for the seed is trying to steal it.

Next: scripts/contribute.sh "<what you did>"
EOF
