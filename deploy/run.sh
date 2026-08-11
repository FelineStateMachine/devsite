#!/usr/bin/env bash
# Run the control plane and the tunnel in front of it.
set -euo pipefail

DEVSITE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
export DEVSITE_ROOT
# shellcheck source=./env
source "$DEVSITE_ROOT/deploy/env"

config="$DEVSITE_ROOT/deploy/cloudflared.yml"
[[ -f "$config" ]] || { echo "error: run ./deploy/setup-tunnel.sh first" >&2; exit 1; }

mkdir -p "$DEVSITE_ROOT/data"

# Build the browser bundle if it is missing, so a fresh checkout serves a working page
# rather than a blank one.
if [[ ! -f "$DEVSITE_ROOT/web/pkg/manifest.json" ]]; then
  echo "building the browser bundle…"
  "$DEVSITE_ROOT/scripts/build-wasm.sh" --release
fi

cargo build --release -p devsite-server
server="$DEVSITE_ROOT/target/release/devsite-server"

"$server" &
server_pid=$!

cloudflared tunnel --config "$config" run &
tunnel_pid=$!

# Either process dying should take the other with it, rather than leaving a tunnel
# pointing at nothing or a server nobody can reach.
cleanup() {
  trap - EXIT INT TERM
  kill "$server_pid" "$tunnel_pid" 2>/dev/null || true
  wait "$server_pid" "$tunnel_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

echo
echo "  control plane  http://$DEVSITE_BIND"
echo "  public         $DEVSITE_PUBLIC_ORIGIN"
echo

# Poll rather than `wait -n`: macOS ships bash 3.2, which does not have it.
while kill -0 "$server_pid" 2>/dev/null && kill -0 "$tunnel_pid" 2>/dev/null; do
  sleep 2
done
