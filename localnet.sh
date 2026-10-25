#!/usr/bin/env bash
# Persistent local 3-of-5 network for real Kaspa/Hoosat transactions.
#
#   ./localnet.sh up                       create keys on first run (DKG), start the 5 nodes
#   ./localnet.sh address <network>        deposit address of the "main" key
#   ./localnet.sh balance <network>        UTXOs and balance from the public API
#   ./localnet.sh send <network> --to ADDR (--amount SOMPI | --all) [--dry-run]
#   ./localnet.sh serve [args]             run tsn-coordinator (HTTP API for apps) on 127.0.0.1:7100
#   ./localnet.sh passkey                  coordinator + passkey test page (Touch ID) on localhost:8080
#   ./localnet.sh down                     stop the nodes
#
# Networks: kaspa-testnet, kaspa-mainnet, hoosat-mainnet (hoosat-testnet needs --api URL).
#
# Keys live in ./localnet (gitignored) and are never recreated. Deleting that folder, or losing
# 3 of the 5 node folders, loses every coin sent to its addresses. Unlike demo.sh, this script
# never deletes anything.
set -euo pipefail
cd "$(dirname "$0")"
export RUST_BACKTRACE=0

DIR=localnet
BIN=target/release
PORT_BASE=710
NAME=main

build() { cargo build -q --release; }

alive() { [ -f "$DIR/node$1.pid" ] && kill -0 "$(cat "$DIR/node$1.pid")" 2>/dev/null; }

start() {
  for i in 1 2 3 4 5; do
    if alive "$i"; then continue; fi
    nohup "$BIN/tsn-node" run --dir "$DIR/node$i" --registry "$DIR/registry.json" --port "$PORT_BASE$i" \
      >> "$DIR/node$i.log" 2>&1 &
    echo $! > "$DIR/node$i.pid"
  done
  for i in 1 2 3 4 5; do
    for _ in $(seq 1 50); do curl -sf "http://127.0.0.1:$PORT_BASE$i/info" >/dev/null && break; sleep 0.2; done
    curl -sf "http://127.0.0.1:$PORT_BASE$i/info" >/dev/null || { echo "node $i failed to start; see $DIR/node$i.log"; exit 1; }
  done
}

init() {
  if [ -f "$DIR/master.pub.json" ]; then return; fi
  if [ -d "$DIR" ] && [ -n "$(ls -A "$DIR" 2>/dev/null)" ]; then
    echo "$DIR exists but has no master.pub.json (interrupted setup?). Inspect it; this script will not overwrite keys."
    exit 1
  fi
  mkdir -p "$DIR"
  local args=()
  for i in 1 2 3 4 5; do
    "$BIN/tsn-node" keygen --dir "$DIR/node$i" --id "$i" >/dev/null
    args+=(--node "$DIR/node$i=http://127.0.0.1:$PORT_BASE$i")
  done
  "$BIN/tsn" registry --threshold 3 "${args[@]}" --out "$DIR/registry.json"
  start
  "$BIN/tsn" dkg --registry "$DIR/registry.json" --key-id master --out "$DIR/master.pub.json"
  "$BIN/tsn" owner-new --out "$DIR/owner.json"
  echo "keys created in $DIR - back this folder up before sending real funds"
}

need_network() { [ $# -ge 1 ] || { echo "usage: $0 $CMD <network> ..."; exit 2; }; }

CMD="${1:-}"; shift || true
case "$CMD" in
  up)
    build; init; start
    echo "5 nodes running on ports ${PORT_BASE}1-${PORT_BASE}5 (3-of-5)"
    ;;
  down)
    for i in 1 2 3 4 5; do
      if alive "$i"; then kill "$(cat "$DIR/node$i.pid")"; fi
      rm -f "$DIR/node$i.pid"
    done
    echo "nodes stopped (keys kept in $DIR)"
    ;;
  serve)
    start
    echo "master public key (pin this in SDK clients): $(python3 -c 'import json,sys;print(json.load(sys.stdin)["verifying_key"])' < "$DIR/master.pub.json" 2>/dev/null || echo "see $DIR/master.pub.json")"
    exec "$BIN/tsn-coordinator" --registry "$DIR/registry.json" --public "$DIR/master.pub.json" "$@"
    ;;
  passkey)
    build
    start
    (cd sdk/ts && { [ -d node_modules ] || npm ci --silent; } && npm run --silent build)
    master=$(python3 -c 'import json,sys;print(json.load(sys.stdin)["verifying_key"])' < "$DIR/master.pub.json")
    recovery=$(python3 -c 'import json,sys;print(json.load(sys.stdin)["ed25519_public"])' < "$DIR/owner.json")
    "$BIN/tsn-coordinator" --registry "$DIR/registry.json" --public "$DIR/master.pub.json" \
      --cors-origin http://localhost:8080 "$@" >> "$DIR/coordinator.log" 2>&1 &
    coord=$!
    trap 'kill $coord 2>/dev/null' EXIT
    echo "coordinator on 127.0.0.1:7100 (log: $DIR/coordinator.log)"
    echo
    echo "open http://localhost:8080/examples/passkey.html?master=$master&recovery=$recovery"
    echo "(use localhost, not 127.0.0.1: the passkey is bound to the page's domain)"
    echo
    python3 -m http.server 8080 --bind 127.0.0.1 --directory sdk/ts
    ;;
  status)
    for i in 1 2 3 4 5; do if alive "$i"; then echo "node $i up"; else echo "node $i down"; fi; done
    ;;
  address)
    need_network "$@"; net="$1"; shift
    "$BIN/tsn" address --public "$DIR/master.pub.json" --owner "$DIR/owner.json" --name "$NAME" --network "$net"
    ;;
  balance)
    need_network "$@"; net="$1"; shift
    "$BIN/tsn" balance --public "$DIR/master.pub.json" --owner "$DIR/owner.json" --name "$NAME" --network "$net" "$@"
    ;;
  send)
    need_network "$@"; net="$1"; shift
    start
    "$BIN/tsn" send --registry "$DIR/registry.json" --public "$DIR/master.pub.json" --owner "$DIR/owner.json" \
      --name "$NAME" --network "$net" "$@"
    ;;
  *)
    sed -n '2,16p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
