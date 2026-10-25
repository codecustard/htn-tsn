#!/usr/bin/env bash
# End-to-end demo: 5 nodes, 3-of-5 threshold, one byzantine node, Kaspa + Hoosat signing.
set -euo pipefail
cd "$(dirname "$0")"
export RUST_BACKTRACE=0

cargo build -q --release
BIN=target/release
DEMO=demo-run
rm -rf "$DEMO" && mkdir -p "$DEMO"
PIDS=()
cleanup() { for p in "${PIDS[@]}"; do kill "$p" 2>/dev/null || true; done; }
trap cleanup EXIT

step() { printf '\n\033[1m== %s\033[0m\n' "$*"; }
expect_fail() { if "$@" > "$DEMO/last.log" 2>&1; then echo "UNEXPECTED SUCCESS"; exit 1; else echo "refused as expected -> $(grep -m1 -E "^Error|error:" "$DEMO/last.log" | sed -E "s/^Error: //")"; fi; }

step "1. Five operators create node identities"
NODE_ARGS=()
for i in 1 2 3 4 5; do
  $BIN/tsn-node keygen --dir "$DEMO/node$i" --id "$i"
  NODE_ARGS+=(--node "$DEMO/node$i=http://127.0.0.1:700$i")
done
$BIN/tsn registry --threshold 3 "${NODE_ARGS[@]}" --out "$DEMO/registry.json"

step "2. Start nodes (node 2 is byzantine: it returns corrupted shares)"
for i in 1 2 3 4 5; do
  extra=(); [ "$i" = 2 ] && extra=(--byzantine)
  $BIN/tsn-node run --dir "$DEMO/node$i" --registry "$DEMO/registry.json" --port "700$i" \
    --max-external-spend 10000000000 "${extra[@]}" > "$DEMO/node$i.log" 2>&1 &
  PIDS+=($!)
done
for i in 1 2 3 4 5; do until curl -sf "http://127.0.0.1:700$i/info" >/dev/null; do sleep 0.2; done; done
echo "all 5 nodes up"

step "3. Distributed key generation (no dealer, no one sees the key)"
$BIN/tsn dkg --registry "$DEMO/registry.json" --key-id master --out "$DEMO/master.pub.json"

step "4. Owners: alice (key holder), bob (recipient), mallory (attacker)"
for o in alice bob mallory; do printf '%-8s' "$o"; $BIN/tsn owner-new --out "$DEMO/$o.json"; done

step "5. Derived addresses, computed offline from the master public key"
ALICE_KAS=$($BIN/tsn address --public "$DEMO/master.pub.json" --owner "$DEMO/alice.json" --name treasury --network kaspa-testnet)
ALICE_HTN=$($BIN/tsn address --public "$DEMO/master.pub.json" --owner "$DEMO/alice.json" --name treasury --network hoosat-testnet)
BOB_KAS=$($BIN/tsn address --public "$DEMO/master.pub.json" --owner "$DEMO/bob.json" --name main --network kaspa-testnet)
BOB_HTN=$($BIN/tsn address --public "$DEMO/master.pub.json" --owner "$DEMO/bob.json" --name main --network hoosat-testnet)
echo "alice/treasury  kaspa:  $ALICE_KAS"
echo "alice/treasury  hoosat: $ALICE_HTN"
echo "bob/main        kaspa:  $BOB_KAS"

SIGN=($BIN/tsn sign --registry "$DEMO/registry.json" --public "$DEMO/master.pub.json")

step "6. Kaspa payment, 10 KAS. First pick [1,2,3] hits byzantine node 2 -> identified, excluded, retried"
"${SIGN[@]}" --owner "$DEMO/alice.json" --name treasury --network kaspa-testnet \
  --to "$BOB_KAS" --amount 1000000000 --out "$DEMO/signed-kaspa.json"

step "7. Hoosat payment with an explicit signer set [1,3,5]"
"${SIGN[@]}" --owner "$DEMO/alice.json" --name treasury --network hoosat-testnet \
  --to "$BOB_HTN" --amount 1000000000 --signers 1,3,5 --out "$DEMO/signed-hoosat.json"

step "8. Node 5 goes offline; the network still signs"
kill "${PIDS[4]}"; sleep 0.3
"${SIGN[@]}" --owner "$DEMO/alice.json" --name treasury --network kaspa-testnet \
  --to "$BOB_KAS" --amount 500000000

step "9. Policy: 200 KAS exceeds every node's 100 KAS limit"
expect_fail "${SIGN[@]}" --owner "$DEMO/alice.json" --name treasury --network kaspa-testnet \
  --to "$BOB_KAS" --amount 20000000000 --utxo-amount 30000000000 --signers 1,3,4

step "10. Mallory tries to spend alice's key"
expect_fail "${SIGN[@]}" --owner "$DEMO/mallory.json" --path-owner "$DEMO/alice.json" --name treasury \
  --network kaspa-testnet --to "$BOB_KAS" --amount 100000000 --signers 1,3,4

step "11. Two nodes are not enough"
expect_fail "${SIGN[@]}" --owner "$DEMO/alice.json" --name treasury --network kaspa-testnet \
  --to "$BOB_KAS" --amount 100000000 --signers 1,3

if command -v python3 >/dev/null; then
  step "12. Real-payment path (tsn send) against a mock API: 2 UTXOs, coin selection, fee, broadcast"
  for net in kaspa-testnet hoosat-mainnet; do
    ADDR=$($BIN/tsn address --public "$DEMO/master.pub.json" --owner "$DEMO/alice.json" --name treasury --network $net)
    SCRIPT=$($BIN/tsn address --public "$DEMO/master.pub.json" --owner "$DEMO/alice.json" --name treasury --network $net --script)
    python3 tools/mock_api.py --port 7099 --address "$ADDR" --script "$SCRIPT" \
      --utxos 2000000000,1500000000 --save "$DEMO/submitted-$net.json" &
    MOCK=$!; PIDS+=($MOCK)
    until curl -sf "http://127.0.0.1:7099/info/blockdag" >/dev/null; do sleep 0.2; done
    TO=$($BIN/tsn address --public "$DEMO/master.pub.json" --owner "$DEMO/bob.json" --name main --network $net)
    $BIN/tsn send --registry "$DEMO/registry.json" --public "$DEMO/master.pub.json" --owner "$DEMO/alice.json" --name treasury --network $net --api http://127.0.0.1:7099 \
      --to "$TO" --amount 2500000000 --out "$DEMO/sent-$net.json"
    kill $MOCK; wait $MOCK 2>/dev/null || true
  done
fi

if command -v python3 >/dev/null && command -v npm >/dev/null; then
  step "13. App path: TypeScript SDK -> tsn-coordinator -> nodes (mock API)"
  if [ ! -d sdk/ts/node_modules ]; then (cd sdk/ts && npm ci --silent); fi
  (cd sdk/ts && npm run --silent build)
  ADDR=$($BIN/tsn address --public "$DEMO/master.pub.json" --owner "$DEMO/alice.json" --name treasury --network kaspa-testnet)
  SCRIPT=$($BIN/tsn address --public "$DEMO/master.pub.json" --owner "$DEMO/alice.json" --name treasury --network kaspa-testnet --script)
  python3 tools/mock_api.py --port 7099 --address "$ADDR" --script "$SCRIPT" \
    --utxos 3000000000 --save "$DEMO/submitted-sdk.json" &
  PIDS+=($!)
  $BIN/tsn-coordinator --registry "$DEMO/registry.json" --public "$DEMO/master.pub.json" --listen 127.0.0.1:7098 \
    --api kaspa-testnet=http://127.0.0.1:7099 > "$DEMO/coordinator.log" 2>&1 &
  PIDS+=($!)
  until curl -sf http://127.0.0.1:7098/healthz >/dev/null && curl -sf http://127.0.0.1:7099/info/blockdag >/dev/null; do sleep 0.2; done
  MASTER=$(python3 -c 'import json,sys;print(json.load(sys.stdin)["verifying_key"])' < "$DEMO/master.pub.json")
  SECRET=$(python3 -c 'import json,sys;print(json.load(sys.stdin)["ed25519_secret"])' < "$DEMO/alice.json")
  TSN_URL=http://127.0.0.1:7098 TSN_MASTER=$MASTER OWNER_SECRET=$SECRET NETWORK=kaspa-testnet NAME=treasury \
    TO="$BOB_KAS" AMOUNT=1000000000 OUT="$DEMO/sent-sdk.json" node sdk/ts/examples/pay.mjs
fi

step "14. Independent re-verification of the saved transactions"
$BIN/tsn verify --tx "$DEMO/signed-kaspa.json"
$BIN/tsn verify --tx "$DEMO/signed-hoosat.json"
for f in "$DEMO"/sent-*.json; do [ -f "$f" ] && $BIN/tsn verify --tx "$f"; done
if command -v go >/dev/null; then
  (cd tools/hoosat-verify && go build -o hoosat-verify .)
  tools/hoosat-verify/hoosat-verify "$DEMO/signed-hoosat.json"
  [ -f "$DEMO/sent-hoosat-mainnet.json" ] && tools/hoosat-verify/hoosat-verify "$DEMO/sent-hoosat-mainnet.json"
fi

step "Node logs (what each node decided)"
grep -h -E "signed|REFUSED|BYZANTINE" "$DEMO"/node*.log | sort -t']' -k1,1 -s
