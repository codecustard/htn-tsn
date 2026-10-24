# htn-tsn — threshold signing network prototype for Hoosat and Kaspa

A threshold signing network for Hoosat and Kaspa. Independent nodes jointly hold one master key
that no single node ever has. From it they derive a separate key for each owner and name, and they
sign transactions only when the owner requests it and every node's policy allows it.

- **Protocol:** FROST, 3-of-5, secp256k1 BIP340 (Zcash Foundation `frost-secp256k1-tr` 3.0)
- **Key setup:** dealerless DKG; round-2 shares sealed node-to-node (X25519 + ChaCha20-Poly1305)
- **Keys:** path-derived child keys (`owner/<ed25519 pubkey>/<name>`), addresses computable offline
- **Checks per node:** owner signature, input ownership, spend cap, own sighash, single-use nonces
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

## What "valid" means here

- **Kaspa:** every input executed by the real rusty-kaspa consensus script engine (`kaspa-txscript` 2.1).
- **Hoosat:** BIP340 over Hoosat's BLAKE3 sighash, then re-checked by `tools/hoosat-verify`, which
  feeds the transaction to HTND v2's own Go consensus code (address decoding, sighash, script engine).
- Tampering with any output makes both checks fail.

Transactions spend mock UTXOs, so nothing is broadcast. To go live, replace the mock input with a
real UTXO of the derived address and submit the signed transaction to a node.

## Layout

```
crates/tsn-core   address encoding, sighash (Kaspa + Hoosat), derivation, sealing, owner auth, wire types
crates/tsn-node   signer node (axum HTTP): DKG rounds, commit, share
crates/tsn-cli    `tsn`: registry, dkg, owner-new, address, sign, verify (coordinator is untrusted)
tools/hoosat-verify  Go program that validates a signed Hoosat tx with HTND's consensus engine
demo.sh           end-to-end scenario
```

## Prototype shortcuts (not production)

- Plain HTTP on localhost; production needs mTLS/Noise between all parties.
- Shares are stored unencrypted in each node's directory; production encrypts at rest or uses a TEE/HSM.
- Registry is a local JSON file; production signs it (Phase 1) or puts it on-chain (Phase 3).
- No nonce preprocessing pools, share refresh, or resharing yet (see design doc roadmap).
- Only version-0, native-subnetwork, pay-to-pubkey (Schnorr) transactions with SIGHASH_ALL.
- Not audited. Do not use with real funds.

## Tests

```bash
cargo test   # address vectors (vs kaspa-addresses and HTND), in-process DKG + signing on both chains
```

## License

Licensed under either of [Apache License, Version 2.0](LICENSE-APACHE) or [MIT license](LICENSE-MIT) at your option.
