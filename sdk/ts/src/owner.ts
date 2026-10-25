// Owner keys (ed25519). The owner key never leaves the app; it only signs authorizations.

import { ed25519 } from "@noble/curves/ed25519.js";
import { bytesToHex, hexToBytes, randomHex } from "./bytes.js";
import { requestDigest } from "./digest.js";
import type { Authorization, Tx } from "./types.js";

/** Longest validity nodes accept for an authorization (seconds). */
export const MAX_TTL_SECS = 3600;

export interface OwnerKey {
  /** 32-byte ed25519 secret, hex. Store it like a wallet seed. */
  secret: string;
  /** 32-byte ed25519 public key, hex. Part of every derivation path. */
  public: string;
}

export function generateOwnerKey(): OwnerKey {
  const { secretKey, publicKey } = ed25519.keygen();
  return { secret: bytesToHex(secretKey), public: bytesToHex(publicKey) };
}

export function ownerFromSecret(secretHex: string): OwnerKey {
  const secret = hexToBytes(secretHex);
  if (secret.length !== 32) throw new Error("owner secret must be 32 bytes");
  return { secret: secretHex, public: bytesToHex(ed25519.getPublicKey(secret)) };
}

/** Signs an authorization for `tx`, valid for `ttlSecs` (capped at MAX_TTL_SECS). */
export function authorize(owner: OwnerKey, keyId: string, path: string, tx: Tx, ttlSecs = 600, now = Date.now()): Authorization {
  const request_id = randomHex(16);
  const expires_at = Math.floor(now / 1000) + Math.min(ttlSecs, MAX_TTL_SECS);
  const digest = requestDigest(keyId, path, request_id, expires_at, tx);
  return { request_id, expires_at, owner_sig: bytesToHex(ed25519.sign(digest, hexToBytes(owner.secret))) };
}
