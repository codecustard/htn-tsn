import { describe, expect, it } from "vitest";
import { checkIntent, type Intent } from "../src/intent.js";
import { keyAddress } from "../src/derive.js";
import type { Prepared } from "../src/types.js";

const MASTER = "02c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5"; // 2·G
const OWNER = "11".repeat(32);
const me = keyAddress(MASTER, OWNER, "main", "kaspa-testnet");
const them = keyAddress(MASTER, OWNER, "other", "kaspa-testnet");

function prepared(): Prepared {
  return {
    key_id: "master",
    path: me.path,
    from: me.address,
    tx: {
      network: "kaspa-testnet",
      inputs: [{ prev_txid: "aa".repeat(32), index: 0, amount: "500000000", script_pubkey: me.script, sequence: "0", sig_op_count: 1 }],
      outputs: [
        { address: them.address, amount: "100000000" },
        { address: me.address, amount: "399990000" },
      ],
      lock_time: "0",
    },
    fee: "10000",
    mass: "2036",
    change: "399990000",
    feerate: 1,
    skipped_young_utxos: 0,
  };
}

const intent: Intent = {
  network: "kaspa-testnet",
  keyId: "master",
  path: me.path,
  from: me.address,
  script: me.script,
  to: them.address,
  amount: 100_000_000n,
  maxFee: 1_000_000n,
};

describe("checkIntent", () => {
  it("accepts the expected payment and returns the fee", () => {
    expect(checkIntent(prepared(), intent)).toBe(10_000n);
  });

  const cases: [string, (p: Prepared) => void, RegExp][] = [
    ["wrong recipient", (p) => void (p.tx.outputs[0]!.address = me.address), /recipient/],
    ["wrong amount", (p) => void (p.tx.outputs[0]!.amount = "100000001"), /amount/],
    ["change to a stranger", (p) => void (p.tx.outputs[1]!.address = them.address), /someone other/],
    ["extra output", (p) => void p.tx.outputs.push({ address: them.address, amount: "1" }), /someone other|exceed/],
    ["foreign input", (p) => void (p.tx.inputs[0]!.script_pubkey = them.script), /does not belong/],
    ["fee too high", (p) => void (p.tx.outputs[1]!.amount = "390000000"), /fee/],
    ["other network", (p) => void (p.tx.network = "kaspa-mainnet"), /network/],
    ["other key id", (p) => void (p.key_id = "evil"), /key id/],
    ["lock time", (p) => void (p.tx.lock_time = "5"), /lock time/],
  ];
  for (const [name, mutate, why] of cases) {
    it(`rejects ${name}`, () => {
      const p = prepared();
      mutate(p);
      expect(() => checkIntent(p, intent)).toThrow(why);
    });
  }

  it("accepts a sweep with one output", () => {
    const p = prepared();
    p.tx.outputs = [{ address: them.address, amount: "499990000" }];
    expect(checkIntent(p, { ...intent, amount: "all" })).toBe(10_000n);
  });
});
