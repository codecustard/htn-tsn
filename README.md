# htn-tsn — threshold signing network prototype for Hoosat and Kaspa

[![CI](https://github.com/codecustard/htn-tsn/actions/workflows/ci.yml/badge.svg)](https://github.com/codecustard/htn-tsn/actions/workflows/ci.yml)

A threshold signing network for Hoosat and Kaspa. Independent nodes jointly hold one master key
that no single node ever has. From it they derive a separate key for each owner and name, and they
sign transactions only when the owner requests it and every node's policy allows it.

- **Protocol:** FROST, 3-of-5, secp256k1 BIP340 (Zcash Foundation `frost-secp256k1-tr` 3.0)
- **Key setup:** dealerless DKG; round-2 shares sealed node-to-node (X25519 + ChaCha20-Poly1305)
- **Keys:** path-derived child keys (`owner/<ed25519 pubkey>/<name>`), addresses computable offline
- **Checks per node:** owner signature or policy rules, input ownership, spend cap, own sighash, single-use nonces
- **Robustness:** identifiable abort — a node sending a bad share is named and routed around

## Run the demo

```bash
./demo.sh          # needs Rust 1.80+; Go 1.22+ optional for the HTND cross-check
```

The demo starts 5 nodes (node 2 is deliberately byzantine), runs DKG, derives addresses, then:

| Step | Result |
| --- | --- |
| Kaspa payment | First subset includes node 2 → bad share identified → retried with [1,3,4] → valid |
| Hoosat payment, signers [1,3,5] | Valid |
| Node 5 killed | Still signs |
| 200 KAS (limit 100) | Nodes refuse (policy) |
| Attacker signs for alice's path | Nodes refuse (owner signature) |
| Only 2 signers | Nodes refuse (threshold) |
| `tsn send` against a mock API (needs python3) | Picks 2 UTXOs, computes the fee, signs each input, "broadcasts" |
| Policy keys: protected hot wallet, escrow | Allowed spends sign; wrong destination, missing approver or early refund are refused by the nodes |
| SDK → `tsn-coordinator` → nodes (needs npm) | Pays via the HTTP service; SDK checks the transaction before the owner signs |

## What "valid" means here

- **Kaspa:** every input executed by the real rusty-kaspa consensus script engine (`kaspa-txscript` 2.1).
- **Hoosat:** BIP340 over Hoosat's BLAKE3 sighash, then re-checked by `tools/hoosat-verify`, which
  feeds the transaction to HTND v2's own Go consensus code (address decoding, sighash, script engine).
- Tampering with any output makes both checks fail.

The demo spends mock UTXOs and broadcasts nothing.

## Real transactions

No Kaspa or Hoosat node is needed. `tsn send` reads UTXOs from a public REST API and submits the
signed transaction there. A lying API can't redirect funds: each input's signature commits to the
UTXO's amount and script, so bad data only makes the transaction fail. A bad fee estimate could
overpay miners, so `send` refuses fees above `--max-fee` (default 0.1 KAS/HTN).

```bash
./localnet.sh up                          # first run: 5 node keys + DKG in ./localnet, then starts the nodes
./localnet.sh address kaspa-testnet       # fund this address (testnet-10 faucet)
./localnet.sh balance kaspa-testnet
./localnet.sh send kaspa-testnet --to kaspatest:... --amount 100000000 --dry-run   # sign + verify only
./localnet.sh send kaspa-testnet --to kaspatest:... --amount 100000000             # broadcast
./localnet.sh down
```

| Network | Default API | Notes |
| --- | --- | --- |
| `kaspa-testnet` (testnet-10) | `api-tn10.kaspa.org` | Fee rate from the API's estimate |
| `kaspa-mainnet` | `api.kaspa.org` | Same |
| `hoosat-mainnet` | `api.explorer-eu.hoosat.network` | No fee estimate; uses 2 sompi/gram (relay minimum is 1). Inputs must be 1000 DAA old before HTND relays a spend |
| `hoosat-testnet` | none | Pass `--api <url>` |

Amounts are in sompi (1 KAS or HTN = 100,000,000). `--all` sweeps the balance. Each node refuses
to send more than 100 coins outside the key's own address per request (`--max-external-spend`).

**`./localnet` holds the only copies of the key shares.** Deleting it, or losing 3 of the 5 node
folders, loses every coin sent to its addresses. `demo.sh` uses a separate folder that it wipes on
every run, so never send real funds to demo addresses.

## Policy keys

A policy key is controlled by published rules instead of one owner key. Its path is
`policy/<hash of the rules>/<name>`, so the rules are fixed when the address is created, and every
node checks them before signing. A spend is allowed if any clause passes; a clause can require
k-of-m approvals (`signers`), a not-before time (`after`, Unix seconds), allowed destinations
(`only_to`; change back to the key is always allowed) and a per-transaction cap (`max_per_tx`).

```json
{"version": 1, "clauses": [
  {"signers": {"k": 1, "of": ["ed25519:<server>"]}, "only_to": ["kaspa:<exchange>"], "max_per_tx": "5000000000"},
  {"signers": {"k": 2, "of": ["ed25519:<server>", "ed25519:<ops>"]}}
]}
```

A hacked server holding the `server` key can then only pay the exchange, 50 KAS at a time.

```bash
tsn policy-info --public P --policy hot.json --name hot           # id, path, addresses
tsn send ... --policy hot.json --name hot --approver server.json --to ... --amount ...
```

Templates: team treasury (`k` of the team's keys), escrow (2 of buyer/seller/arbiter, or the buyer
alone `after` a deadline), vesting (beneficiary `after` a date), recovery (owner, or a recovery key
`after` a date). Not yet: daily limits and announce-then-wait delays, which need state shared
across nodes. In the SDK: `client.payWithPolicy({ policy, name, approvers, ... })`, or
`newPolicyRequest` + `approve` when approvers are on different machines.

## Signing service for apps

`tsn-coordinator` is an HTTP API in front of the nodes; `sdk/ts` is the TypeScript client.
Apps keep their owner key and call the service to get addresses and send payments.

```bash
./localnet.sh up
./localnet.sh serve            # http://127.0.0.1:7100; prints the master public key to pin in clients
```

```ts
const client = new TsnClient({ baseUrl: "http://127.0.0.1:7100", masterPublicKey: "03…" });
const { txid } = await client.pay({ owner, name: "main", network: "kaspa-testnet", to, amount: 100_000_000n });
```

| Endpoint | Does |
| --- | --- |
| `GET /v1/info` | Threshold, master public key, networks, fee cap |
| `GET /v1/address`, `GET /v1/balance` | Address and UTXOs of `owner`+`name` (or any key `path`) on `network` |
| `POST /v1/policy` | Validates a policy; returns its id, path and address |
| `POST /v1/tx/prepare` | Coin selection and fee; returns the unsigned transaction |
| `POST /v1/tx/send` | With the owner's authorization: FROST across the nodes, verify, broadcast |
| `GET /healthz` | Live nodes vs threshold |

The service is untrusted. The SDK derives addresses from the pinned master key and checks every
prepared transaction against what the app asked for before the owner signs; the owner's signature
covers the exact transaction and expires (default 10 minutes); every node verifies it again.
Options: `--api-key` (or `TSN_API_KEY`), `--cors-origin`, `--rate-limit` (per IP per minute),
`--max-fee`, `--api NETWORK=URL`. See [sdk/ts/README.md](sdk/ts/README.md).

## Layout

```
crates/tsn-core   addresses, sighash and mass (Kaspa + Hoosat), coin selection, derivation, sealing, owner auth
crates/tsn-node   signer node (axum HTTP): DKG rounds, commit, share
crates/tsn-coord  coordinator library (nodes, chain API, payments) + `tsn-coordinator` HTTP service
crates/tsn-cli    `tsn`: registry, dkg, owner-new, address, balance, sign, send, verify
sdk/ts            `@htn-tsn/sdk` TypeScript client
testdata/         vectors shared by Rust and the SDK
tools/hoosat-verify  Go program that validates a signed Hoosat tx with HTND's consensus engine
tools/mock_api.py    offline stand-in for the REST API, used by demo.sh
demo.sh           end-to-end scenario (throwaway keys)
localnet.sh       persistent local network for real transactions
```

## Prototype shortcuts (not production)

- Plain HTTP on localhost; production needs mTLS/Noise between all parties.
- `tsn-coordinator` speaks plain HTTP; put it behind a TLS reverse proxy with `--api-key` before exposing it
  (its rate limit then sees the proxy's IP).
- Shares are stored unencrypted in each node's directory; production encrypts at rest or uses a TEE/HSM.
- Registry is a local JSON file; production signs it (Phase 1) or puts it on-chain (Phase 3).
- No nonce preprocessing pools, share refresh, or resharing yet (see design doc roadmap).
- Only version-0, native-subnetwork, pay-to-pubkey (Schnorr) transactions with SIGHASH_ALL.
- All 5 nodes run on one machine in `localnet.sh`, so it has no real threshold security yet.
- Not audited. Use only testnet funds or amounts you can afford to lose.

## Tests

```bash
cargo test                       # address vectors, coin selection and fees, auth, DKG + signing on both chains
(cd sdk/ts && npm ci && npm test) # SDK, including vectors generated by Rust
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
