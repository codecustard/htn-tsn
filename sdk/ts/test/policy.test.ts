import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { ed25519 } from "@noble/curves/ed25519.js";
import { hexToBytes } from "../src/bytes.js";
import { requestDigest } from "../src/digest.js";
import { ownerFromSecret } from "../src/owner.js";
import {
  approve,
  canonicalJson,
  newPolicyRequest,
  normalizePolicy,
  policyAddress,
  policyAuthorization,
  policyId,
  policyPath,
  signerId,
} from "../src/policy.js";
import type { Policy, Tx } from "../src/types.js";

const v = JSON.parse(readFileSync(new URL("../../../testdata/sdk-vectors.json", import.meta.url), "utf8"));

describe("policy vectors (Rust)", () => {
  for (const p of v.policies) {
    it(p.id.slice(0, 12), () => {
      expect(canonicalJson(normalizePolicy(p.policy))).toBe(p.canonical);
      expect(policyId(p.policy)).toBe(p.id);
      expect(policyPath(p.policy, p.name)).toBe(p.path);
      expect(policyAddress(p.master_public_key, p.policy, p.name, "kaspa-testnet").address).toBe(p.kaspa_testnet_address);
    });
  }

  it("id ignores key order and numeric vs string max_per_tx", () => {
    const p = v.policies[0].policy as Policy;
    const reordered = JSON.parse(JSON.stringify({ clauses: p.clauses, version: p.version }));
    expect(policyId(reordered)).toBe(v.policies[0].id);
    const asNumber = structuredClone(p) as any;
    asNumber.clauses[0].max_per_tx = 5000000000;
    const asString = structuredClone(p);
    asString.clauses[0]!.max_per_tx = "5000000000";
    expect(policyId(asNumber)).toBe(policyId(asString));
  });
});

describe("policy validation", () => {
  const ok: Policy = v.policies[1].policy;
  const bad = (mutate: (p: any) => void) => {
    const p = structuredClone(ok) as any;
    mutate(p);
    return () => policyId(p);
  };
  it("rejects k above the signer count", () => expect(bad((p) => (p.clauses[0].signers.k = 4))).toThrow(/k must/));
  it("rejects duplicate signers", () => expect(bad((p) => (p.clauses[0].signers.of[1] = p.clauses[0].signers.of[0]))).toThrow(/duplicate/));
  it("rejects malformed signers", () => expect(bad((p) => (p.clauses[0].signers.of[0] = "ed25519:XYZ"))).toThrow(/signer/));
  it("rejects bad addresses", () => expect(bad((p) => (p.clauses[0].only_to = ["kaspatest:qqqq"]))).toThrow());
  it("rejects other versions", () => expect(bad((p) => (p.version = 2))).toThrow(/version/));
});

describe("approvals", () => {
  it("each approver signs the same request digest", () => {
    const a = ownerFromSecret("01".repeat(32));
    const b = ownerFromSecret("02".repeat(32));
    const policy: Policy = { version: 1, clauses: [{ signers: { k: 2, of: [signerId(a.public), signerId(b.public)] } }] };
    const tx: Tx = v.authorization.tx;
    const req = newPolicyRequest("master", policyPath(policy, "team"), policy, tx, 600, 1_700_000_000_000);
    const auth = policyAuthorization(req, [approve(a, req), approve(b, req)]);
    const digest = requestDigest("master", req.path, auth.request_id, auth.expires_at, tx);
    for (const [owner, ap] of [[a, auth.approvals![0]!], [b, auth.approvals![1]!]] as const) {
      expect(ap.signer).toBe(signerId(owner.public));
      expect(ed25519.verify(hexToBytes(ap.sig), digest, hexToBytes(owner.public))).toBe(true);
    }
    expect(auth.policy).toEqual(normalizePolicy(policy));
    expect(auth.owner_sig).toBeUndefined();
  });
});
