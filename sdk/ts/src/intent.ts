// Checks that a transaction prepared by the (untrusted) coordinator does exactly what the app
// asked before the owner signs it. Run this on every prepared transaction.

import type { Network, Prepared } from "./types.js";

export interface Intent {
  network: Network;
  keyId: string;
  /** Derivation path of the paying key (from `keyAddress`). */
  path: string;
  /** Address of the paying key, computed locally (from `keyAddress`). */
  from: string;
  /** P2PK script of the paying key, hex (from `keyAddress`). */
  script: string;
  to: string;
  /** Exact amount in sompi, or "all" to sweep. */
  amount: bigint | "all";
  maxFee: bigint;
}

/** Throws if `p` deviates from `intent`; returns the fee in sompi. */
export function checkIntent(p: Prepared, intent: Intent): bigint {
  const fail = (why: string): never => {
    throw new Error(`prepared transaction rejected: ${why}`);
  };
  const tx = p.tx;
  if (tx.network !== intent.network) fail(`network is ${tx.network}, expected ${intent.network}`);
  if (p.key_id !== intent.keyId) fail(`key id is ${p.key_id}, expected ${intent.keyId}`);
  if (p.path !== intent.path) fail("derivation path differs");
  if (p.from !== intent.from) fail("source address differs");
  if (tx.inputs.length === 0) fail("no inputs");
  for (const i of tx.inputs) if (i.script_pubkey !== intent.script) fail("an input does not belong to the paying key");
  const [first, ...rest] = tx.outputs;
  if (!first || first.address !== intent.to) fail("first output is not the recipient");
  if (intent.amount === "all") {
    if (rest.length !== 0) fail("a sweep must have exactly one output");
  } else if (BigInt(first!.amount) !== intent.amount) {
    fail(`recipient amount is ${first!.amount}, expected ${intent.amount}`);
  }
  for (const o of rest) if (o.address !== intent.from) fail("an extra output pays someone other than the paying key");
  if (BigInt(tx.lock_time) !== 0n) fail("lock time must be 0");
  const ins = tx.inputs.reduce((s, i) => s + BigInt(i.amount), 0n);
  const outs = tx.outputs.reduce((s, o) => s + BigInt(o.amount), 0n);
  const fee = ins - outs;
  if (fee < 0n) fail("outputs exceed inputs");
  if (fee > intent.maxFee) fail(`fee ${fee} exceeds the maximum ${intent.maxFee}`);
  return fee;
}
