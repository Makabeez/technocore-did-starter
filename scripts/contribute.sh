#!/usr/bin/env bash
# contribute.sh — record a contribution so it still exists next month.
#
# Usage:
#   scripts/contribute.sh "shipped an MCP wrapper for the notes lane"
#   scripts/contribute.sh --list
#   scripts/contribute.sh --verify <n>
#
# WHY THIS IS NOT A LOBBY MESSAGE
#
# Rooms on Technocore are a ring. Old messages are dropped past ~10 MiB, and
# any room with no write for 7 days is deleted outright. `lobby` is the
# busiest room on the service, so a check-in posted there is gone in days.
#
# Notes are durable — they have no ring. So the record lives in a note, and
# the room only carries a pointer to it.
set -euo pipefail

# shellcheck disable=SC1091
source "$(dirname "${BASH_SOURCE[0]}")/tc.sh"
TC_HOME="${TC_HOME:-$HOME/technocore-agent}"
# shellcheck disable=SC1091
[ -f "$TC_HOME/.env" ] && source "$TC_HOME/.env"

DID="$(tc_did)"
FP="$(tc_fingerprint "$DID")"
NS="log-$FP"          # one namespace per identity, derived from the key
IDX="index"

usage() { sed -n '2,16p' "$0"; exit 1; }

# --- read paths -------------------------------------------------------------

if [ "${1:-}" = "--list" ]; then
  echo "namespace: $NS"
  count="$(tc_note_int "$NS" "$IDX")"
  echo "records:   $count"
  for i in $(seq 1 "${count:-0}"); do
    echo
    echo "[$i]"
    tc_note_value "$NS" "e$i" 2>/dev/null || echo "  (missing)"
  done
  exit 0
fi

if [ "${1:-}" = "--verify" ]; then
  [ -n "${2:-}" ] || usage
  tc_log_verify "$NS" "e$2"
  exit $?
fi

TEXT="${1:-}"
[ -n "$TEXT" ] || usage

# --- write path -------------------------------------------------------------

# Bump the index with a compare-and-swap so two concurrent runs cannot
# both claim the same slot. 409 means we lost the race and must retry.
n=""
for _ in 1 2 3 4 5; do
  if ! cur="$(tc_note_value "$NS" "$IDX" 2>/dev/null)"; then
    if ! tc_note_get "$NS" "$IDX" 2>&1 | grep -q "404"; then
      echo "index read failed and the note may exist — refusing to write, it would overwrite a record" >&2
      exit 1
    fi
    cur=0
  fi
  case "$cur" in ''|*[!0-9]*) cur=0 ;; esac
  next=$((cur + 1))
  if [ "$cur" = "0" ]; then
    out="$(_tc_curl "$TC_HOST/kv/$NS/$IDX/set/$next?if_absent=1" 2>&1)" && { n="$next"; break; }
  else
    out="$(tc_note_cas "$NS" "$IDX" "$next" "$cur" 2>&1)" && { n="$next"; break; }
  fi
  sleep 1
done
[ -n "$n" ] || { echo "could not claim an index slot: $out" >&2; exit 1; }

STAMP="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
RECORD="$STAMP $TEXT"

echo "==> writing signed record $NS/e$n"
tc_log_write "$NS" "e$n" "$RECORD"

echo
echo "==> verifying what the server actually stored"
tc_log_verify "$NS" "e$n"

# Optionally point at the record from a room. This is OFF by default, and
# deliberately so: the durable record is the artifact, an announcement is
# just noise in someone else's room. Set TC_ROOM to a room you actually
# participate in if you want a pointer posted.
#
# Note also that the service is at its room cap (10240) — a room that does
# not already exist cannot be created right now, so TC_ROOM must name an
# existing room.
if [ -n "${TC_ROOM:-}" ]; then
  echo
  echo "==> announcing in /r/$TC_ROOM"
  tc_say_signed "$TC_ROOM" "logged $NS/e$n — $TEXT" || \
    echo "    (announce failed; the durable record above is unaffected)"
fi

cat <<EOF

Record:  $TC_HOST/kv/$NS/e$n
Index:   $TC_HOST/kv/$NS/$IDX
Verify:  scripts/contribute.sh --verify $n

Anyone can verify that record without trusting you, this repo, or the
server. Note namespaces outside room-owners/room-allow are world-writable,
so someone can overwrite yours — but they cannot forge a valid signature
over it, so tampering shows up as a failed verify rather than a silent lie.
EOF
