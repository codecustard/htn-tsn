// Passkey signers (WebAuthn, P-256): approve policy-key spends with Face ID, Touch ID or a
// security key. Matches tsn-core/src/policy.rs `verify_passkey`: the assertion's challenge is the
// request digest, the passkey's domain (rpId) is part of the signer id, and user verification
// (biometric or PIN) is required.

import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from "./bytes.js";
import { requestDigest } from "./digest.js";
import type { PolicyRequest } from "./policy.js";
import type { Approval } from "./types.js";

const SPKI_P256_PREFIX = hexToBytes("3059301306072a8648ce3d020106082a8648ce3d030107034200");

export function base64url(b: Uint8Array): string {
  let s = "";
  for (const x of b) s += String.fromCharCode(x);
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64url(s: string): Uint8Array<ArrayBuffer> {
  const b = atob(s.replace(/-/g, "+").replace(/_/g, "/") + "===".slice((s.length + 3) % 4));
  return Uint8Array.from(b, (c) => c.charCodeAt(0));
}

/** Copy into a plain ArrayBuffer-backed array, as WebAuthn's BufferSource requires. */
function buffer(b: Uint8Array): Uint8Array<ArrayBuffer> {
  return new Uint8Array(b);
}

/** `passkey:<rpId>:<compressed P-256 key hex>` */
export function passkeySigner(rpId: string, compressedPublicKeyHex: string): string {
  if (!/^[a-z0-9-]+(\.[a-z0-9-]+)*$/.test(rpId)) throw new Error("rpId must be a lowercase domain (or localhost)");
  if (!/^0[23][0-9a-f]{64}$/.test(compressedPublicKeyHex)) throw new Error("passkey public key must be 33-byte compressed hex");
  return `passkey:${rpId}:${compressedPublicKeyHex}`;
}

/** Compressed point from the SPKI DER that `AuthenticatorAttestationResponse.getPublicKey()` returns. */
export function spkiToCompressed(spki: Uint8Array): string {
  const prefixOk = spki.length === 91 && SPKI_P256_PREFIX.every((b, i) => spki[i] === b);
  if (!prefixOk || spki[26] !== 0x04) throw new Error("not an uncompressed P-256 SPKI key (passkey must use ES256)");
  const x = spki.slice(27, 59);
  const y = spki.slice(59, 91);
  return bytesToHex(concatBytes(Uint8Array.of(y[31]! & 1 ? 0x03 : 0x02), x));
}

export interface Passkey {
  /** Credential id (base64url): pass it back when approving so the right passkey is used. */
  credentialId: string;
  rpId: string;
  /** Signer id to put in a policy. */
  signer: string;
}

/**
 * Browser: create a passkey on `rpId` (the page's domain, or "localhost" in development).
 * `userId` (at most 64 bytes, default random) comes back at every sign-in with a discoverable passkey.
 */
export async function createPasskey(opts: {
  rpId: string;
  rpName: string;
  userName: string;
  userId?: Uint8Array;
  /** Require a discoverable passkey (sign-in without knowing its id). */
  discoverable?: boolean;
}): Promise<Passkey> {
  const userId = buffer(opts.userId ?? crypto.getRandomValues(new Uint8Array(16)));
  if (userId.length > 64) throw new Error("passkey user id is limited to 64 bytes");
  const cred = (await navigator.credentials.create({
    publicKey: {
      rp: { id: opts.rpId, name: opts.rpName },
      user: { id: userId, name: opts.userName, displayName: opts.userName },
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      pubKeyCredParams: [{ type: "public-key", alg: -7 }], // ES256 (P-256)
      authenticatorSelection: { residentKey: opts.discoverable ? "required" : "preferred", userVerification: "required" },
      timeout: 120_000,
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("passkey creation was cancelled");
  const res = cred.response as AuthenticatorAttestationResponse;
  const spki = res.getPublicKey?.();
  if (!spki) throw new Error("this browser can't export the passkey's public key; use a current Chrome, Safari or Firefox");
  return {
    credentialId: base64url(new Uint8Array(cred.rawId)),
    rpId: opts.rpId,
    signer: passkeySigner(opts.rpId, spkiToCompressed(new Uint8Array(spki))),
  };
}

/** Browser: approve `request` with a passkey (shows the Face ID / Touch ID / PIN prompt). */
export async function approveWithPasskey(request: PolicyRequest, passkey: Passkey): Promise<Approval> {
  const digest = requestDigest(request.keyId, request.path, request.request_id, request.expires_at, request.tx);
  const cred = (await navigator.credentials.get({
    publicKey: {
      challenge: buffer(digest),
      rpId: passkey.rpId,
      userVerification: "required",
      allowCredentials: [{ type: "public-key", id: fromBase64url(passkey.credentialId) }],
      timeout: 120_000,
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("passkey approval was cancelled");
  const res = cred.response as AuthenticatorAssertionResponse;
  return {
    signer: passkey.signer,
    sig: bytesToHex(new Uint8Array(res.signature)),
    authenticator_data: bytesToHex(new Uint8Array(res.authenticatorData)),
    client_data_json: bytesToHex(new Uint8Array(res.clientDataJSON)),
  };
}

/**
 * Software passkey for tests and CI: produces the same assertion format a browser would.
 * Never use it for real funds; a real passkey keeps its key in secure hardware.
 */
export function softPasskey(rpId: string, origin: string, secretKey: Uint8Array = p256.utils.randomSecretKey()) {
  const publicKey = bytesToHex(p256.getPublicKey(secretKey, true));
  const signer = passkeySigner(rpId, publicKey);
  /** A WebAuthn assertion over `challenge`, as `navigator.credentials.get` returns it. */
  function assert(challenge: Uint8Array, flags = 0x05) {
    const authenticatorData = concatBytes(sha256(utf8ToBytes(rpId)), Uint8Array.of(flags), new Uint8Array(4));
    const clientDataJSON = utf8ToBytes(
      JSON.stringify({ type: "webauthn.get", challenge: base64url(challenge), origin, crossOrigin: false }),
    );
    const signature = p256.sign(concatBytes(authenticatorData, sha256(clientDataJSON)), secretKey, { format: "der" });
    return { authenticatorData, clientDataJSON, signature };
  }
  return {
    signer,
    publicKey,
    assert,
    approve(request: PolicyRequest, flags = 0x05): Approval {
      const digest = requestDigest(request.keyId, request.path, request.request_id, request.expires_at, request.tx);
      const a = assert(digest, flags);
      return {
        signer,
        sig: bytesToHex(a.signature),
        authenticator_data: bytesToHex(a.authenticatorData),
        client_data_json: bytesToHex(a.clientDataJSON),
      };
    },
  };
}
