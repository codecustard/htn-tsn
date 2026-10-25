#!/usr/bin/env bash
# Browser test of the passkey wallet page (sdk/ts/examples/passkey.html) with Chrome's virtual
# authenticator: create a wallet on device A, sign in on fresh devices B and C with the synced
# passkey, pay through a local 3-of-5 network, and check what the nodes refuse.
#
# Needs Node with Playwright and Chromium (npm i -g playwright && npx playwright install chromium).
# Uses ports 7211-7215 (nodes), 7190 (coordinator), 7299 (mock API) and 8080 (page).
set -euo pipefail
cd "$(dirname "$0")/.."
cargo build -q --release
(cd sdk/ts && { [ -d node_modules ] || npm ci --silent; } && npm run --silent build)
BIN=$PWD/target/release
D=$(mktemp -d)
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; rm -rf "$D"; }
trap cleanup EXIT
ARGS=()
for i in 1 2 3 4 5; do $BIN/tsn-node keygen --dir "$D/node$i" --id "$i" >/dev/null; ARGS+=(--node "$D/node$i=http://127.0.0.1:721$i"); done
$BIN/tsn registry --threshold 3 "${ARGS[@]}" --out "$D/registry.json" >/dev/null
for i in 1 2 3 4 5; do
  $BIN/tsn-node run --dir "$D/node$i" --registry "$D/registry.json" --port "721$i" > "$D/node$i.log" 2>&1 &
  PIDS+=($!)
done
for i in 1 2 3 4 5; do until curl -sf "http://127.0.0.1:721$i/info" >/dev/null; do sleep 0.2; done; done
$BIN/tsn dkg --registry "$D/registry.json" --key-id master --out "$D/master.pub.json" >/dev/null
$BIN/tsn owner-new --out "$D/recovery.json" >/dev/null
$BIN/tsn owner-new --out "$D/bob.json" >/dev/null
$BIN/tsn-coordinator --registry "$D/registry.json" --public "$D/master.pub.json" --listen 127.0.0.1:7190 \
  --api kaspa-testnet=http://127.0.0.1:7299 --cors-origin http://localhost:8080 > "$D/coordinator.log" 2>&1 &
PIDS+=($!)
python3 -m http.server 8080 --bind 127.0.0.1 --directory sdk/ts > "$D/http.log" 2>&1 &
PIDS+=($!)
until curl -sf http://127.0.0.1:7190/healthz >/dev/null && curl -sf http://127.0.0.1:8080/examples/passkey.html >/dev/null; do sleep 0.2; done
NODE_PATH="${NODE_PATH:-$(npm root -g)}" RUN_DIR="$D" BIN="$BIN" node tools/passkey-browser-test.mjs
