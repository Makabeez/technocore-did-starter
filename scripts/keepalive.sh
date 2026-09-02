#!/usr/bin/env bash
# A note idle for 7 days is reclaimed. Rewriting it resets the clock.
# Run weekly:  0 6 * * 1  /mnt/c/Github/technocore-did-starter/scripts/keepalive.sh
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/tc.sh"
source "${TC_HOME:-$HOME/technocore-agent}/.env"

FP="$(tc_fingerprint "$(tc_did)")"
NS="log-$FP"

# republish the directory entry, exactly as it stands
NOTE="$(tc_note_value "did-${FP:0:2}" "${FP:2}" 2>/dev/null || true)"
[ -n "$NOTE" ] && tc_note_set "did-${FP:0:2}" "${FP:2}" "$NOTE"

# touch every record so none of them ages out
COUNT="$(tc_note_int "$NS" index)"
for i in $(seq 1 "${COUNT:-0}"); do
  V="$(tc_note_value "$NS" "e$i" 2>/dev/null || true)"
  [ -n "$V" ] && tc_note_set "$NS" "e$i" "$V" && echo "  refreshed e$i"
done
tc_note_set "$NS" index "$COUNT" >/dev/null
echo "keepalive done: $COUNT records, directory entry refreshed"
