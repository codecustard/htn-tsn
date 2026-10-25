# Running htn-tsn with separate operators

A network is one **admin** (who signs the operator list and runs the DKG), **operators** (one
node each, on their own machines) and one or more **coordinators** (the untrusted HTTP service
apps use). With a 3-of-5 network, any 3 nodes can sign and no 2 operators together can.

What protects what:

| Protection | Against |
| --- | --- |
| Registry signed by the admin key; nodes pin that key (`--admin`) | A swapped peer key or address in an operator's registry file |
| TLS pinned to each node's certificate fingerprint (in the registry) | Someone impersonating a node, or reading traffic |
| Nodes accept only coordinators listed in the registry (mutual TLS) | Strangers reaching the signing API, e.g. to exhaust its nonce pool |
| Identity and key shares encrypted with the operator's passphrase (Argon2id + ChaCha20-Poly1305) | A stolen disk, backup or copied node folder |
| Every node checks the owner or policy approval, input ownership, its own spend cap and the sighash | A malicious coordinator, or a compromised app |

The passphrase file sits on the node machine so the node can restart unattended. That protects
copies of the node folder, not a node machine whose root account is compromised: that is what the
threshold is for.

## Build

Docker (no Rust needed):

```bash
docker build -t htn-tsn https://github.com/codecustard/htn-tsn.git
tsn() { docker run --rm -it --user "$(id -u):$(id -g)" -v "$PWD:/w" -w /w --entrypoint tsn htn-tsn "$@"; }
```

Or from source: `cargo build --release` gives `target/release/{tsn-node,tsn,tsn-coordinator}`.

## 1. Admin: keys

```bash
tsn owner-new --out admin.json                          # admin key: keep it offline; share only its public key
tsn coordinator-new --name main --out coordinator.json  # one per coordinator; keep coordinator.json private
```

Send every operator the admin public key (`ed25519_public` in admin.json).

## 2. Operator: create the node

On the node machine, in an empty folder:

```bash
openssl rand -hex 32 > passphrase.txt && chmod 600 passphrase.txt   # also store a copy in your password manager
mkdir node && chmod 700 node
docker run --rm --user "$(id -u):$(id -g)" -v "$PWD/node:/data" \
  -v "$PWD/passphrase.txt:/run/secrets/passphrase:ro" -e TSN_NODE_PASSPHRASE_FILE=/run/secrets/passphrase \
  htn-tsn keygen --dir /data --id <your node number>
```

Send the admin `node/identity.pub.json` (public keys only) and the address the coordinator will
reach you at, e.g. `https://node3.example.org:7001` or `https://203.0.113.7:7001`. No domain or
certificate authority is needed: the registry pins your certificate's fingerprint.

## 3. Admin: sign the registry

```bash
tsn registry --threshold 3 \
  --node op1.identity.pub.json=https://203.0.113.1:7001 \
  --node op2.identity.pub.json=https://node2.example.org:7001 \
  ... \
  --coordinator coordinator.pub.json \
  --sign-with admin.json --out registry.json
tsn registry-info --registry registry.json --admin <admin public key>
```

Send `registry.json` to every operator. Operators can check it themselves with
`tsn registry-info --admin <admin public key>`: their entry, the threshold, the other nodes.

## 4. Operator: run the node

Copy [`deploy/node/compose.yml`](deploy/node/compose.yml) next to `node/`, `passphrase.txt` and
`registry.json`, then:

```bash
printf 'TSN_ADMIN=%s\nTSN_UID=%s\nTSN_GID=%s\n' <admin public key> "$(id -u)" "$(id -g)" > .env
docker compose up -d && docker compose logs -f
```

The log should say `listening on 0.0.0.0:7001 (TLS, 1 registered coordinator(s))`. Open port 7001
to the coordinator's address only (mutual TLS refuses everyone else anyway). `TSN_MAX_SPEND` in
`.env` sets this node's cap per transaction in sompi (default 100 coins); every node enforces its
own.

## 5. Admin: key generation

From a machine that can reach every node:

```bash
export TSN_ADMIN=<admin public key> TSN_CLIENT_CERT=coordinator.json
tsn status --registry registry.json        # every node up, same registry
tsn dkg --registry registry.json --key-id master --out master.pub.json
```

All nodes must be up for the DKG. Each node stores its share, encrypted. Publish the master public
key from `master.pub.json`: apps pin it.

## 6. Admin: coordinator

```bash
tsn-coordinator --registry registry.json --public master.pub.json --admin <admin public key> \
  --client-cert coordinator.json --listen 0.0.0.0:7100 --api-key <random secret>
```

Put it behind a TLS reverse proxy before exposing it. It never holds a secret that can move
coins; losing `coordinator.json` only means issuing a new one in the next registry.

## Operating

- **Backups:** the `node/` folder (already encrypted) and the passphrase, stored separately. Never
  give a copy to another operator.
- **Losing nodes:** a 3-of-5 network keeps signing with up to 2 nodes gone. Replacing an operator
  currently means a new registry, a new DKG and moving funds to the new keys (resharing, which
  keeps the same key, is on the roadmap).
- **Upgrades:** rebuild the image and `docker compose up -d`. Keys persist in `node/`.
- **Existing node folders** (made before TLS or encryption): `tsn-node upgrade --dir node` adds a
  TLS certificate and encrypts the identity and shares, keeping the same keys and addresses. Then
  re-send `identity.pub.json` for the new registry.
- **Local testing:** [`deploy/cluster`](deploy/cluster) runs all five nodes and a coordinator in
  Docker in this same production mode (`./cluster.sh init && ./cluster.sh up && ./cluster.sh selftest`).
  `localnet.sh` stays in dev mode: plain HTTP, unsigned registry, unencrypted files.
