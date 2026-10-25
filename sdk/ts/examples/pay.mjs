// Pay through tsn-coordinator with the SDK (build first: npm run build).
//
//   TSN_URL=http://127.0.0.1:7100 TSN_MASTER=<master public key hex> OWNER_SECRET=<hex> \
//   NETWORK=kaspa-testnet NAME=main TO=kaspatest:... AMOUNT=100000000 node examples/pay.mjs
//
// AMOUNT=all sweeps the balance. BROADCAST=0 signs without broadcasting. OUT=file saves the signed tx.

import { writeFileSync } from "node:fs";
import { TsnClient, ownerFromSecret } from "../dist/index.js";

const env = (k, d) => {
  const v = process.env[k] ?? d;
  if (v === undefined) throw new Error(`set ${k}`);
  return v;
};

const client = new TsnClient({ baseUrl: env("TSN_URL", "http://127.0.0.1:7100"), masterPublicKey: env("TSN_MASTER"), apiKey: process.env.TSN_API_KEY });
const owner = ownerFromSecret(env("OWNER_SECRET"));
const network = env("NETWORK", "kaspa-testnet");
const name = env("NAME", "main");
const amount = env("AMOUNT") === "all" ? "all" : BigInt(env("AMOUNT"));

const me = client.address(owner.public, name, network);
console.log(`from   ${me.address}  (derived locally)`);
const result = await client.pay({ owner, name, network, to: env("TO"), amount, broadcast: env("BROADCAST", "1") !== "0" });
for (const line of result.log) console.log(`       ${line}`);
console.log(`fee    ${result.fee} sompi (checked against intent before signing)`);
console.log(result.txid ? `txid   ${result.txid}` : "signed, not broadcast");
if (result.explorer) console.log(result.explorer);
if (process.env.OUT) writeFileSync(process.env.OUT, JSON.stringify(result.tx, null, 2));
