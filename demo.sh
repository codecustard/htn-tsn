#!/usr/bin/env bash
# End-to-end demo: 5 nodes, 3-of-5 threshold, one byzantine node, Kaspa + Hoosat signing.
# Runs in production mode: signed registry, pinned mutual TLS, encrypted key shares.
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
expect_fail() { if "$@" > "$DEMO/last.log" 2>&1; then echo "UNEXPECTED SUCCESS"; exit 1; else echo "refused as expected -> $(grep -m1 -E "^Error|error:|DOWN" "$DEMO/last.log" | sed -E "s/^Error: //")"; fi; }

step "1. Admin, five operators and a coordinator create their identities"
# Production setup, all on one machine for the demo: each operator's identity and key shares are
# encrypted with their own passphrase; the admin signs the registry; nodes accept only TLS
# connections from the registered coordinator.
$BIN/tsn owner-new --out "$DEMO/admin.json" >/dev/null
export TSN_ADMIN=$(grep -o '"ed25519_public": *"[0-9a-f]*"' "$DEMO/admin.json" | grep -o '[0-9a-f]\{64\}')
echo "admin key $TSN_ADMIN"
pass() { echo "demo passphrase for node $1"; }
NODE_ARGS=()
for i in 1 2 3 4 5; do
  TSN_NODE_PASSPHRASE=$(pass $i) $BIN/tsn-node keygen --dir "$DEMO/node$i" --id "$i"
  NODE_ARGS+=(--node "$DEMO/node$i/identity.pub.json=https://127.0.0.1:700$i")
done
$BIN/tsn coordinator-new --name demo-coordinator --out "$DEMO/coordinator.json"
export TSN_CLIENT_CERT="$DEMO/coordinator.json"
$BIN/tsn registry --threshold 3 "${NODE_ARGS[@]}" --coordinator "$DEMO/coordinator.pub.json" \
  --sign-with "$DEMO/admin.json" --out "$DEMO/registry.json"

step "2. Start nodes (node 2 is byzantine: it returns corrupted shares)"
for i in 1 2 3 4 5; do
  extra=(); [ "$i" = 2 ] && extra=(--byzantine)
  TSN_NODE_PASSPHRASE=$(pass $i) $BIN/tsn-node run --dir "$DEMO/node$i" --registry "$DEMO/registry.json" --port "700$i" \
    --max-external-spend 10000000000 "${extra[@]}" > "$DEMO/node$i.log" 2>&1 &
  PIDS+=($!)
done
until $BIN/tsn status --registry "$DEMO/registry.json" > "$DEMO/status.log" 2>&1; do sleep 0.3; done
cat "$DEMO/status.log"
echo "-- strangers can't reach the nodes: no certificate, or one the registry doesn't list"
expect_fail env -u TSN_CLIENT_CERT $BIN/tsn status --registry "$DEMO/registry.json"
$BIN/tsn coordinator-new --name stranger --out "$DEMO/stranger.json" >/dev/null
expect_fail env TSN_CLIENT_CERT="$DEMO/stranger.json" $BIN/tsn status --registry "$DEMO/registry.json"
echo "-- a registry not signed by the admin is refused"
sed 's/700[1]/7666/' "$DEMO/registry.json" > "$DEMO/tampered-registry.json"
expect_fail $BIN/tsn registry-info --registry "$DEMO/tampered-registry.json"

step "3. Distributed key generation (no dealer, no one sees the key)"
$BIN/tsn dkg --registry "$DEMO/registry.json" --key-id master --out "$DEMO/master.pub.json"

echo "-- key shares on disk are encrypted:"
head -c 160 "$DEMO/node1/keys/master.json"; echo " ..."
if grep -q signing_share "$DEMO"/node*/keys/master.json; then echo "PLAINTEXT SHARE ON DISK"; exit 1; fi

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

step "9. Node spend cap: 200 KAS exceeds every node's 100 KAS limit"
expect_fail "${SIGN[@]}" --owner "$DEMO/alice.json" --name treasury --network kaspa-testnet \
  --to "$BOB_KAS" --amount 20000000000 --utxo-amount 30000000000 --signers 1,3,4

step "10. Mallory tries to spend alice's key"
expect_fail "${SIGN[@]}" --owner "$DEMO/mallory.json" --path-owner "$DEMO/alice.json" --name treasury \
  --network kaspa-testnet --to "$BOB_KAS" --amount 100000000 --signers 1,3,4

step "11. Two nodes are not enough"
expect_fail "${SIGN[@]}" --owner "$DEMO/alice.json" --name treasury --network kaspa-testnet \
  --to "$BOB_KAS" --amount 100000000 --signers 1,3

step "12. Policy keys: rules control the key, every node enforces them"
pub() { grep -o '"ed25519_public": *"[0-9a-f]*"' "$1" | grep -o '[0-9a-f]\{64\}'; }
for o in server ops buyer seller arbiter carol; do $BIN/tsn owner-new --out "$DEMO/$o.json" >/dev/null; done
CAROL_KAS=$($BIN/tsn address --public "$DEMO/master.pub.json" --owner "$DEMO/carol.json" --name main --network kaspa-testnet)
cat > "$DEMO/hot-wallet.policy.json" <<JSON
{"version": 1, "clauses": [
  {"signers": {"k": 1, "of": ["ed25519:$(pub "$DEMO/server.json")"]},
   "only_to": ["$BOB_KAS"], "max_per_tx": "5000000000"},
  {"signers": {"k": 2, "of": ["ed25519:$(pub "$DEMO/server.json")", "ed25519:$(pub "$DEMO/ops.json")"]}}
]}
JSON
$BIN/tsn policy-info --public "$DEMO/master.pub.json" --policy "$DEMO/hot-wallet.policy.json" --name hot
POL=($BIN/tsn sign --registry "$DEMO/registry.json" --public "$DEMO/master.pub.json" --network kaspa-testnet --amount 1000000000)
echo "-- protected hot wallet: server alone may pay only bob (the 'exchange'), up to 50 KAS"
"${POL[@]}" --policy "$DEMO/hot-wallet.policy.json" --name hot --approver "$DEMO/server.json" --to "$BOB_KAS" | tail -1
expect_fail "${POL[@]}" --policy "$DEMO/hot-wallet.policy.json" --name hot --approver "$DEMO/server.json" --to "$CAROL_KAS"
"${POL[@]}" --policy "$DEMO/hot-wallet.policy.json" --name hot --approver "$DEMO/server.json" --approver "$DEMO/ops.json" --to "$CAROL_KAS" | tail -1
expect_fail "${POL[@]}" --policy "$DEMO/hot-wallet.policy.json" --name hot --approver "$DEMO/ops.json" --to "$BOB_KAS"
DEADLINE=$(( $(date +%s) + 86400 ))
cat > "$DEMO/escrow.policy.json" <<JSON
{"version": 1, "clauses": [
  {"signers": {"k": 2, "of": ["ed25519:$(pub "$DEMO/buyer.json")", "ed25519:$(pub "$DEMO/seller.json")", "ed25519:$(pub "$DEMO/arbiter.json")"]}},
  {"signers": {"k": 1, "of": ["ed25519:$(pub "$DEMO/buyer.json")"]}, "after": $DEADLINE}
]}
JSON
echo "-- escrow: any 2 of buyer/seller/arbiter, or the buyer alone after the deadline (tomorrow)"
expect_fail "${POL[@]}" --policy "$DEMO/escrow.policy.json" --name deal-42 --approver "$DEMO/seller.json" --to "$CAROL_KAS"
expect_fail "${POL[@]}" --policy "$DEMO/escrow.policy.json" --name deal-42 --approver "$DEMO/buyer.json" --to "$CAROL_KAS"
"${POL[@]}" --policy "$DEMO/escrow.policy.json" --name deal-42 --approver "$DEMO/seller.json" --approver "$DEMO/arbiter.json" --to "$CAROL_KAS" | tail -1

if command -v python3 >/dev/null; then
  step "13. Real-payment path (tsn send) against a mock API: 2 UTXOs, coin selection, fee, broadcast"
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
  step "14. App path: TypeScript SDK -> tsn-coordinator -> nodes (mock API)"
  if [ ! -d sdk/ts/node_modules ]; then (cd sdk/ts && npm ci --silent); fi
  (cd sdk/ts && npm run --silent build)
  ADDR=$($BIN/tsn address --public "$DEMO/master.pub.json" --owner "$DEMO/alice.json" --name treasury --network kaspa-testnet)
  SCRIPT=$($BIN/tsn address --public "$DEMO/master.pub.json" --owner "$DEMO/alice.json" --name treasury --network kaspa-testnet --script)
  # Phone wallet: the user's passkey alone pays up to 20 KAS; more needs the passkey plus a recovery key.
  export PASSKEY_SECRET=$(python3 -c 'import secrets;print(secrets.token_hex(32))')
  PASSKEY=$(node sdk/ts/examples/passkey-pay.mjs signer)
  $BIN/tsn owner-new --out "$DEMO/recovery.json" >/dev/null
  cat > "$DEMO/phone.policy.json" <<JSON
{"version": 1, "clauses": [
  {"signers": {"k": 1, "of": ["$PASSKEY"]}, "max_per_tx": "2000000000"},
  {"signers": {"k": 2, "of": ["$PASSKEY", "ed25519:$(pub "$DEMO/recovery.json")"]}}
]}
JSON
  PADDR=$($BIN/tsn address --public "$DEMO/master.pub.json" --policy "$DEMO/phone.policy.json" --name phone --network kaspa-testnet)
  PSCRIPT=$($BIN/tsn address --public "$DEMO/master.pub.json" --policy "$DEMO/phone.policy.json" --name phone --network kaspa-testnet --script)
  python3 tools/mock_api.py --port 7099 --address "$ADDR" --script "$SCRIPT" --utxos 3000000000 \
    --address "$PADDR" --script "$PSCRIPT" --utxos 5000000000 --save "$DEMO/submitted-sdk.json" &
  PIDS+=($!)
  $BIN/tsn-coordinator --registry "$DEMO/registry.json" --public "$DEMO/master.pub.json" --listen 127.0.0.1:7098 \
    --api kaspa-testnet=http://127.0.0.1:7099 > "$DEMO/coordinator.log" 2>&1 &
  PIDS+=($!)
  until curl -sf http://127.0.0.1:7098/healthz >/dev/null && curl -sf http://127.0.0.1:7099/info/blockdag >/dev/null; do sleep 0.2; done
  MASTER=$(python3 -c 'import json,sys;print(json.load(sys.stdin)["verifying_key"])' < "$DEMO/master.pub.json")
  SECRET=$(python3 -c 'import json,sys;print(json.load(sys.stdin)["ed25519_secret"])' < "$DEMO/alice.json")
  TSN_URL=http://127.0.0.1:7098 TSN_MASTER=$MASTER OWNER_SECRET=$SECRET NETWORK=kaspa-testnet NAME=treasury \
    TO="$BOB_KAS" AMOUNT=1000000000 OUT="$DEMO/sent-sdk.json" node sdk/ts/examples/pay.mjs
  echo "-- passkey policy: $PASSKEY"
  PK=(env TSN_URL=http://127.0.0.1:7098 TSN_MASTER=$MASTER POLICY="$DEMO/phone.policy.json" NAME=phone NETWORK=kaspa-testnet TO="$CAROL_KAS")
  echo "-- the passkey alone can't move 25 KAS (over its 20 KAS limit)"
  expect_fail "${PK[@]}" AMOUNT=2500000000 node sdk/ts/examples/passkey-pay.mjs
  echo "-- a phishing site's assertion is refused (origin is not localhost)"
  expect_fail "${PK[@]}" AMOUNT=1000000000 ORIGIN=http://wallet-login.example node sdk/ts/examples/passkey-pay.mjs
  echo "-- the passkey alone pays 10 KAS"
  "${PK[@]}" AMOUNT=1000000000 OUT="$DEMO/sent-passkey.json" node sdk/ts/examples/passkey-pay.mjs
fi

step "15. Independent re-verification of the saved transactions"
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
