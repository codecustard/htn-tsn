# @htn-tsn/sdk

TypeScript client for the htn-tsn threshold signing network. An app holds an **owner key**
(ed25519); the network's nodes jointly hold every derived Kaspa/Hoosat key and sign only what the
owner authorizes.

```ts
import { TsnClient, generateOwnerKey } from "@htn-tsn/sdk";

const client = new TsnClient({
  baseUrl: "http://127.0.0.1:7100",                      // tsn-coordinator
  masterPublicKey: "03…",                                // from the operators (printed by `tsn dkg`)
  apiKey: process.env.TSN_API_KEY,                       // if the coordinator requires one
});

const owner = generateOwnerKey();                        // store owner.secret like a wallet seed

// Deposit address: computed locally, no request.
const { address } = client.address(owner.public, "main", "kaspa-testnet");

// Pay: prepare -> check -> authorize -> threshold-sign -> broadcast.
const result = await client.pay({
  owner,
  name: "main",
  network: "kaspa-testnet",
  to: "kaspatest:…",
  amount: 100_000_000n,                                  // sompi; or "all"
});
console.log(result.txid);
```

## Policy keys

```ts
import { signerId, type Policy } from "@htn-tsn/sdk";

const policy: Policy = {
  version: 1,
  clauses: [
    { signers: { k: 1, of: [signerId(server.public)] }, only_to: [exchange], max_per_tx: "5000000000" },
    { signers: { k: 2, of: [signerId(server.public), signerId(ops.public)] } },
  ],
};

const { address } = client.policyAddress(policy, "hot", "kaspa-mainnet");   // deposit here
await client.payWithPolicy({ policy, name: "hot", network: "kaspa-mainnet", to: exchange, amount: 100_000_000n, approvers: [server] });
```

When approvers are on different machines: one party prepares (`client.prepare({ path, ... })`),
creates `newPolicyRequest(...)`, and sends it to each approver, who runs `checkIntent` and returns
`approve(theirKey, request)`; then `client.send(path, prepared, policyAuthorization(request, approvals))`.

## Passkeys

Passkeys (Face ID, Touch ID, Windows Hello, security keys) can be policy signers. The simplest use
is a passkey wallet, which needs no storage: settings live in the passkey and its public key is
recovered from its signatures.

```ts
import { createWallet, signInWallet, confirmWallet, approveWithWallet, walletPolicy, WALLET_KEY_NAME } from "@htn-tsn/sdk";

// New user: one prompt. Limit and recovery key are optional.
let wallet = await createWallet({ rpId: "wallet.example.com", rpName: "My Wallet", userName: "alice",
                                  settings: { limit: "2000000000", recovery: backupKeyHex } });

// Any other device: one prompt; the device lists the user's passkeys for this site.
wallet = await signInWallet({ rpId: "wallet.example.com" });
// wallet.keys has two candidates until the next signature. The one whose address holds coins is
// the wallet; confirmWallet(wallet) settles it with one more prompt (do that before showing a
// deposit address).

const key = wallet.keys[0];   // or the funded candidate
const policy = walletPolicy(wallet.rpId, key, wallet.settings);
await client.payWithPolicy({ policy, name: WALLET_KEY_NAME, network, to, amount,
  approve: async (req) => { const r = await approveWithWallet(req, wallet, key); wallet = r.wallet; return r.approval; } });
```

For other policies, `createPasskey` returns `{ credentialId, rpId, signer }`; put `signer` in any
clause and approve with `approveWithPasskey(request, passkey)`. Keep such policies: unlike a wallet,
they can't be rebuilt from the passkey.

`rpId` must be the page's domain (or a parent of it); the nodes reject assertions from any other
origin. `softPasskey(rpId, origin)` makes the same assertions in software, for tests.
`examples/passkey.html` is a working wallet page (`./localnet.sh passkey` at the repo root), and
`examples/passkey-pay.mjs` pays with a software passkey from Node.

## What the SDK checks

The coordinator is untrusted, so the SDK never takes its word for anything that matters:

- **Addresses** are derived locally from the pinned `masterPublicKey`. `info()` and `pay()` refuse
  a coordinator that serves a different key.
- **Prepared transactions** go through `checkIntent` before signing: right network and key, every
  input owned by the paying key, first output is the recipient with the exact amount, any other
  output is change back to the paying key, fee within `maxFee` (default 0.1 coin).
- **Authorizations** cover the exact transaction (every input and output), a random request id and
  an expiry (default 10 minutes, max 1 hour). Nodes verify them independently.

## API

| Function | Purpose |
| --- | --- |
| `generateOwnerKey()`, `ownerFromSecret(hex)` | Owner keys |
| `keyAddress(master, ownerPub, name, network)` | Address, path and script of a key, offline |
| `TsnClient.info()` | Coordinator info (verifies the pinned master key) |
| `TsnClient.balance(ownerPub, name, network)` | UTXOs and balance |
| `TsnClient.prepare(...)`, `checkIntent(...)`, `authorize(...)`, `TsnClient.send(...)` | The steps of `pay`, for custom flows |
| `requestDigest(...)` | The bytes an owner signs (matches Rust; see `testdata/sdk-vectors.json`) |
| `policyId`, `policyPath`, `policyAddress`, `normalizePolicy` | Policy keys, offline |
| `TsnClient.payWithPolicy`, `newPolicyRequest`, `approve`, `policyAuthorization` | Spending from policy keys |
| `createPasskey`, `approveWithPasskey`, `passkeySigner`, `softPasskey` | Passkey signers (browser WebAuthn; software for tests) |
| `createWallet`, `signInWallet`, `confirmWallet`, `approveWithWallet`, `walletPolicy` | Passkey wallets: sign in anywhere, nothing stored |

Amounts are `bigint` in arguments and decimal strings in transactions, because JSON numbers lose
precision above 2^53.

## Develop

```bash
npm ci && npm run build && npm test     # tests include vectors generated by the Rust implementation
TSN_MASTER=… OWNER_SECRET=… TO=… AMOUNT=100000000 node examples/pay.mjs
```
