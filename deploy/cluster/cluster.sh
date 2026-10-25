#!/usr/bin/env bash
# Local production-mode cluster in Docker: 5 nodes (3-of-5) and a coordinator.
#
#   ./cluster.sh init       admin key, node identities (encrypted), coordinator identity, signed registry
#   ./cluster.sh up         start the nodes, run the DKG once, start the coordinator on 127.0.0.1:7100
#   ./cluster.sh status     check every node over its pinned TLS
#   ./cluster.sh selftest   sign test payments; check that strangers and a forged registry are refused
#   ./cluster.sh tsn ARGS   run the tsn CLI inside the cluster network (as the registered coordinator)
#   ./cluster.sh logs [-f]  node and coordinator logs
#   ./cluster.sh down       stop everything (keys stay in ./data)
#
# Build the image first: docker build -t htn-tsn ../..   (or set TSN_IMAGE)
# Everything lives in ./data. Its passphrases sit next to the keys, which is fine for a local test
# and wrong for real funds: real operators keep their node and passphrase on their own machine.
set -euo pipefail
cd "$(dirname "$0")"
export TSN_IMAGE=${TSN_IMAGE:-htn-tsn} TSN_UID=$(id -u) TSN_GID=$(id -g)
D=$PWD/data
[ -f "$D/admin.pub" ] && export TSN_ADMIN=$(cat "$D/admin.pub")
compose() { docker compose -f compose.yml "$@"; }
run() { docker run --rm --user "$TSN_UID:$TSN_GID" "$@"; }
tsn() { compose --profile tools run --rm -T cli "$@"; }

case "${1:-}" in
  init)
    [ -e "$D/registry.json" ] && { echo "already initialized ($D); remove it to start over"; exit 1; }
    mkdir -p "$D/secrets" && chmod 700 "$D/secrets"
    run -v "$D:/cluster" --entrypoint tsn "$TSN_IMAGE" owner-new --out /cluster/admin.json >/dev/null
    grep -o '"ed25519_public": *"[0-9a-f]*"' "$D/admin.json" | grep -o '[0-9a-f]\{64\}' > "$D/admin.pub"
    nodes=()
    for i in 1 2 3 4 5; do
      (umask 077; head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n' > "$D/secrets/node$i.pass")
      mkdir -p "$D/node$i"
      run -v "$D/node$i:/data" -v "$D/secrets/node$i.pass:/run/secrets/passphrase:ro" \
        -e TSN_NODE_PASSPHRASE_FILE=/run/secrets/passphrase "$TSN_IMAGE" keygen --dir /data --id "$i"
      nodes+=(--node "/cluster/node$i/identity.pub.json=https://node$i:7001")
    done
    run -v "$D:/cluster" --entrypoint tsn "$TSN_IMAGE" coordinator-new --name cluster-coordinator --out /cluster/coordinator.json
    run -v "$D:/cluster" --entrypoint tsn "$TSN_IMAGE" registry --threshold 3 "${nodes[@]}" \
      --coordinator /cluster/coordinator.pub.json --sign-with /cluster/admin.json --out /cluster/registry.json
    echo "admin key: $(cat "$D/admin.pub")"
    ;;
  up)
    [ -n "${TSN_ADMIN:-}" ] || { echo "run ./cluster.sh init first"; exit 1; }
    compose up -d node1 node2 node3 node4 node5
    for _ in $(seq 1 60); do tsn status --registry registry.json >/dev/null 2>&1 && break; sleep 1; done
    tsn status --registry registry.json
    [ -f "$D/master.pub.json" ] || tsn dkg --registry registry.json --key-id master --out master.pub.json
    compose --profile app up -d coordinator
    for _ in $(seq 1 30); do curl -sf http://127.0.0.1:7100/healthz >/dev/null && break; sleep 1; done
    curl -sf http://127.0.0.1:7100/v1/info; echo
    ;;
  status)
    tsn status --registry registry.json
    ;;
  selftest)
    # A throwaway owner signs mock payments through the cluster.
    tsn owner-new --out selftest-owner.json >/dev/null
    tsn owner-new --out selftest-bob.json >/dev/null
    to=$(tsn address --public master.pub.json --owner selftest-bob.json --name main --network kaspa-testnet | tr -d '\r')
    tsn sign --registry registry.json --public master.pub.json --owner selftest-owner.json --name main \
      --network kaspa-testnet --to "$to" --amount 100000000
    to=$(tsn address --public master.pub.json --owner selftest-bob.json --name main --network hoosat-mainnet | tr -d '\r')
    tsn sign --registry registry.json --public master.pub.json --owner selftest-owner.json --name main \
      --network hoosat-mainnet --to "$to" --amount 100000000 --signers 2,4,5
    expect_refused() { # what, expected error, command...
      local what=$1 want=$2; shift 2
      if out=$(compose --profile tools run --rm -T --entrypoint sh cli -c "$*" 2>&1); then
        echo "UNEXPECTED: $what was accepted"; exit 1
      fi
      grep -q "$want" <<<"$out" || { echo "UNEXPECTED: $what failed for another reason:"; echo "$out"; exit 1; }
      echo "-- $what: refused ($(grep -m1 -o "$want" <<<"$out"))"
    }
    expect_refused "client without a certificate" "CertificateRequired" \
      env -u TSN_CLIENT_CERT tsn status --registry registry.json
    expect_refused "client with an unregistered certificate" "HandshakeFailure" \
      "tsn coordinator-new --name stranger --out /tmp/stranger.json >/dev/null && tsn status --registry registry.json --client-cert /tmp/stranger.json"
    sed 's/node1:7001/evil:7001/' "$D/registry.json" > "$D/forged-registry.json"
    expect_refused "registry not signed by the admin" "registry signature is invalid" \
      tsn status --registry forged-registry.json
    rm -f "$D/selftest-owner.json" "$D/selftest-bob.json" "$D/forged-registry.json"
    echo "selftest passed"
    ;;
  tsn)
    shift; tsn "$@"
    ;;
  logs)
    shift; compose --profile app logs "$@"
    ;;
  down)
    compose --profile app --profile tools down
    ;;
  *)
    sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
    exit 2
    ;;
esac
