// Pay from a policy key approved by a passkey, through tsn-coordinator (build first: npm run build).
//
// This uses a software passkey: the same WebAuthn assertion format a browser produces, signed with
// a P-256 key held here. It exercises the node-side checks (challenge, origin, rpId, user
// verification, signature) without a browser. For Face ID / Touch ID, see examples/passkey.html.
//
//   node examples/passkey-pay.mjs signer                        # print the passkey's signer id
//   TSN_URL=http://127.0.0.1:7100 TSN_MASTER=<hex> POLICY=policy.json NAME=phone \
//   NETWORK=kaspa-testnet TO=kaspatest:... AMOUNT=100000000 node examples/passkey-pay.mjs
//
// PASSKEY_SECRET (P-256 secret, hex) fixes the key; RP_ID / ORIGIN default to localhost.

import { readFileSync, writeFileSync } from "node:fs";
import { TsnClient, hexToBytes, softPasskey } from "../dist/index.js";

const env = (k, d) => {
  const v = process.env[k] ?? d;
  if (v === undefined) throw new Error(`set ${k}`);
  return v;
};

const passkey = softPasskey(env("RP_ID", "localhost"), env("ORIGIN", "http://localhost:8080"), hexToBytes(env("PASSKEY_SECRET")));
if (process.argv[2] === "signer") {
  console.log(passkey.signer);
  process.exit(0);
}

const client = new TsnClient({ baseUrl: env("TSN_URL", "http://127.0.0.1:7100"), masterPublicKey: env("TSN_MASTER"), apiKey: process.env.TSN_API_KEY });
const policy = JSON.parse(readFileSync(env("POLICY"), "utf8"));
const name = env("NAME", "main");
const network = env("NETWORK", "kaspa-testnet");
const amount = env("AMOUNT") === "all" ? "all" : BigInt(env("AMOUNT"));

console.log(`from   ${client.policyAddress(policy, name, network).address}  (derived locally)`);
const result = await client.payWithPolicy({
  policy,
  name,
  network,
  to: env("TO"),
  amount,
  broadcast: env("BROADCAST", "1") !== "0",
  approve: (request) => passkey.approve(request),
});
for (const line of result.log) console.log(`       ${line}`);
console.log(`fee    ${result.fee} sompi (checked against intent before signing)`);
console.log(result.txid ? `txid   ${result.txid}` : "signed, not broadcast");
if (process.env.OUT) writeFileSync(process.env.OUT, JSON.stringify(result.tx, null, 2));
