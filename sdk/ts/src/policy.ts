// Policy keys: keys controlled by published rules, matching tsn-core/src/policy.rs.
// The policy id (a hash of the canonical policy document) is part of the key's path, so the
// rules are fixed when the address is created.

import { ed25519 } from "@noble/curves/ed25519.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, hexToBytes, lp, randomHex, utf8ToBytes } from "./bytes.js";
import { childXOnly, p2pkScript, type KeyAddress } from "./derive.js";
import { decodeAddress, encodeAddress, VERSION_PUBKEY } from "./bech32.js";
import { requestDigest } from "./digest.js";
import { MAX_TTL_SECS, type OwnerKey } from "./owner.js";
import { PREFIX, type Approval, type Authorization, type Network, type Policy, type Tx } from "./types.js";

const ID_DOMAIN = utf8ToBytes("HTN-TSN/policy/v1");

/** `ed25519:<hex>` signer id for an owner key's public key. */
export function signerId(publicKeyHex: string): string {
  if (!/^[0-9a-f]{64}$/.test(publicKeyHex)) throw new Error("public key must be 32 bytes of lowercase hex");
  return `ed25519:${publicKeyHex}`;
}

/** JSON with object keys sorted and no whitespace (undefined fields dropped). */
export function canonicalJson(v: unknown): string {
  if (Array.isArray(v)) return `[${v.map(canonicalJson).join(",")}]`;
  if (v !== null && typeof v === "object") {
    const entries = Object.entries(v as Record<string, unknown>)
      .filter(([, x]) => x !== undefined)
      .sort(([a], [b]) => (a < b ? -1 : a > b ? 1 : 0));
    return `{${entries.map(([k, x]) => `${JSON.stringify(k)}:${canonicalJson(x)}`).join(",")}}`;
  }
  if (typeof v === "bigint") throw new Error("bigint in policy: use decimal strings for max_per_tx");
  return JSON.stringify(v);
}

/** Validates a policy and returns it in normal form (max_per_tx as a decimal string). */
export function normalizePolicy(p: Policy): Policy {
  if (p.version !== 1) throw new Error(`unsupported policy version ${p.version}`);
  if (!Array.isArray(p.clauses) || p.clauses.length < 1 || p.clauses.length > 16) throw new Error("a policy needs 1..=16 clauses");
  return {
    version: 1,
    clauses: p.clauses.map((c, i) => {
      const of = c.signers?.of ?? [];
      if (of.length < 1 || of.length > 16) throw new Error(`clause ${i}: needs 1..=16 signers`);
      if (!Number.isInteger(c.signers.k) || c.signers.k < 1 || c.signers.k > of.length) throw new Error(`clause ${i}: k must be between 1 and ${of.length}`);
      const seen = new Set<string>();
      for (const s of of) {
        if (!/^ed25519:[0-9a-f]{64}$/.test(s)) throw new Error(`clause ${i}: signer ${s} must be ed25519:<64 lowercase hex>`);
        if (seen.has(s)) throw new Error(`clause ${i}: duplicate signer ${s}`);
        seen.add(s);
      }
      const out: Policy["clauses"][number] = { signers: { k: c.signers.k, of: [...of] } };
      if (c.after !== undefined) {
        if (!Number.isSafeInteger(c.after) || c.after < 0) throw new Error(`clause ${i}: after must be a Unix time in seconds`);
        out.after = c.after;
      }
      if (c.only_to !== undefined) {
        if (c.only_to.length < 1 || c.only_to.length > 32) throw new Error(`clause ${i}: only_to needs 1..=32 addresses`);
        for (const a of c.only_to) decodeAddress(a);
        out.only_to = [...c.only_to];
      }
      if (c.max_per_tx !== undefined) {
        const m = BigInt(c.max_per_tx);
        if (m <= 0n) throw new Error(`clause ${i}: max_per_tx must be positive`);
        out.max_per_tx = m.toString();
      }
      return out;
    }),
  };
}

/** 32-byte policy id (hex) that goes into the key's path. */
export function policyId(p: Policy): string {
  const c = utf8ToBytes(canonicalJson(normalizePolicy(p)));
  return bytesToHex(sha256(concatBytes(lp(ID_DOMAIN), lp(c))));
}

export function policyPath(p: Policy, name: string): string {
  if (!name) throw new Error("name must not be empty");
  return `policy/${policyId(p)}/${name}`;
}

/** Address of the policy key POLICY/NAME on `network`, computed offline. */
export function policyAddress(masterPublicKeyHex: string, p: Policy, name: string, network: Network): KeyAddress {
  const path = policyPath(p, name);
  const xonly = childXOnly(masterPublicKeyHex, path);
  return { path, address: encodeAddress(PREFIX[network], VERSION_PUBKEY, xonly), script: bytesToHex(p2pkScript(xonly)) };
}

/** A request every approver signs: same id, expiry and transaction for all of them. */
export interface PolicyRequest {
  keyId: string;
  path: string;
  policy: Policy;
  tx: Tx;
  request_id: string;
  expires_at: number;
}

export function newPolicyRequest(keyId: string, path: string, policy: Policy, tx: Tx, ttlSecs = 600, now = Date.now()): PolicyRequest {
  return {
    keyId,
    path,
    policy: normalizePolicy(policy),
    tx,
    request_id: randomHex(16),
    expires_at: Math.floor(now / 1000) + Math.min(ttlSecs, MAX_TTL_SECS),
  };
}

/** One approver's signature. Each approver should check the transaction first (checkIntent). */
export function approve(owner: OwnerKey, r: PolicyRequest): Approval {
  const digest = requestDigest(r.keyId, r.path, r.request_id, r.expires_at, r.tx);
  return { signer: signerId(owner.public), sig: bytesToHex(ed25519.sign(digest, hexToBytes(owner.secret))) };
}

export function policyAuthorization(r: PolicyRequest, approvals: Approval[]): Authorization {
  return { request_id: r.request_id, expires_at: r.expires_at, approvals, policy: r.policy };
}
