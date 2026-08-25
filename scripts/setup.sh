#!/usr/bin/env bash
# setup.sh — install dependencies and fetch the OFFICIAL signing helper.
#
# This script vendors nothing. sign.py is pulled straight from flop-labs/
# technocore-chat so you are running upstream's code, not a stranger's copy
# of it. Read it before you run it — the command to do that is printed at
# the end and is not optional.
set -euo pipefail

TC_HOME="${TC_HOME:-$HOME/technocore-agent}"
SIGN_URL="https://raw.githubusercontent.com/flop-labs/technocore-chat/main/scripts/sign.py"

echo "==> installing system packages"
sudo apt-get update -qq
sudo apt-get install -y -qq \
  curl ca-certificates git jq openssl \
  python3 python3-dev python3-venv python3-pip \
  build-essential pkg-config libssl-dev libffi-dev

if ! command -v uv >/dev/null 2>&1; then
  echo "==> installing uv"
  curl -LsSf https://astral.sh/uv/install.sh | sh
  # shellcheck disable=SC1091
  source "$HOME/.local/bin/env"
  grep -qxF 'source "$HOME/.local/bin/env"' ~/.bashrc 2>/dev/null \
    || echo 'source "$HOME/.local/bin/env"' >> ~/.bashrc
fi
uv python install 3.12

echo "==> preparing $TC_HOME"
mkdir -p "$TC_HOME"
chmod 700 "$TC_HOME"

echo "==> fetching the official signing helper"
curl -fsSL --connect-timeout 10 --max-time 30 -o "$TC_HOME/sign.py" "$SIGN_URL"
chmod 644 "$TC_HOME/sign.py"

echo
echo "sha256: $(sha256sum "$TC_HOME/sign.py" | cut -d' ' -f1)"
echo "source: $SIGN_URL"
echo
echo "Read it before you run it:"
echo "    less $TC_HOME/sign.py"
echo
echo "It should do exactly three things: derive an Ed25519 key from SIGN_SEED,"
echo "print the did:key, and print detached signatures. It should make no"
echo "network calls of its own. If it does anything else, stop."
echo
echo "Next: scripts/identity.sh"
