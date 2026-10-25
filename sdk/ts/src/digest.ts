// Owner authorization digest, matching tsn-core/src/auth.rs `request_digest`.

import { sha256 } from "@noble/hashes/sha2.js";
import { concatBytes, hexToBytes, lp, u32le, u64le, utf8ToBytes } from "./bytes.js";
import { PREFIX, type Tx } from "./types.js";

const DOMAIN = utf8ToBytes("HTN-TSN/sign-request/v2");

export function validateRequestId(id: string): void {
  if (!/^[0-9a-f]{32}$/.test(id)) throw new Error("request_id must be 16 bytes of lowercase hex");
}

/**
 * SHA-256 over a fixed binary encoding of (key id, path, request id, expiry, transaction).
 * Signature scripts are excluded, so it is the same before and after signing.
 */
export function requestDigest(keyId: string, path: string, requestId: string, expiresAt: number, tx: Tx): Uint8Array {
  validateRequestId(requestId);
  const parts: Uint8Array[] = [
    lp(DOMAIN),
    lp(utf8ToBytes(keyId)),
    lp(utf8ToBytes(path)),
    lp(utf8ToBytes(requestId)),
    u64le(expiresAt),
    lp(utf8ToBytes(PREFIX[tx.network])),
    u64le(tx.inputs.length),
  ];
  for (const i of tx.inputs) {
    const txid = hexToBytes(i.prev_txid);
    if (txid.length !== 32) throw new Error("txid must be 32 bytes");
    parts.push(txid, u32le(i.index), u64le(BigInt(i.amount)), lp(hexToBytes(i.script_pubkey)), u64le(BigInt(i.sequence)));
    parts.push(Uint8Array.of(i.sig_op_count));
  }
  parts.push(u64le(tx.outputs.length));
  for (const o of tx.outputs) parts.push(lp(utf8ToBytes(o.address)), u64le(BigInt(o.amount)));
  parts.push(u64le(BigInt(tx.lock_time)));
  return sha256(concatBytes(...parts));
}
