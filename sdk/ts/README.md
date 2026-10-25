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

Passkeys (Face ID, Touch ID, Windows Hello, security keys) can be policy signers. In the browser:

```ts
import { createPasskey, approveWithPasskey } from "@htn-tsn/sdk";

// Once: create it and store { credentialId, rpId, signer } with the user's account.
const passkey = await createPasskey({ rpId: "wallet.example.com", rpName: "My Wallet", userName: "alice" });
const policy: Policy = { version: 1, clauses: [{ signers: { k: 1, of: [passkey.signer] }, max_per_tx: "2000000000" }] };

// Each payment: the approve callback gets the checked request; the prompt signs that exact transaction.
await client.payWithPolicy({ policy, name: "phone", network, to, amount, approve: (req) => approveWithPasskey(req, passkey) });
```

`rpId` must be the page's domain (or a parent of it); the nodes reject assertions from any other
origin. The public key is only available when the passkey is created, so keep the policy (it holds
the signer id); without it the address can't be spent from. `softPasskey(rpId, origin)` makes the
same assertions in software, for tests. `examples/passkey.html` is a working test page
(`./localnet.sh passkey` at the repo root), and `examples/passkey-pay.mjs` pays with a software
passkey from Node.

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

Amounts are `bigint` in arguments and decimal strings in transactions, because JSON numbers lose
precision above 2^53.

## Develop

```bash
npm ci && npm run build && npm test     # tests include vectors generated by the Rust implementation
TSN_MASTER=… OWNER_SECRET=… TO=… AMOUNT=100000000 node examples/pay.mjs
```
