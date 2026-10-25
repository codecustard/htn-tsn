// Passkey wallets: a policy key determined entirely by one passkey, so a user signs in on any
// device with Face ID / Touch ID and finds their wallet. Nothing to download or store.
//
// - Settings (limit, recovery key) live in the passkey's user handle, which the device returns at
//   every sign-in.
// - The passkey's public key is recovered from its signatures (ECDSA public key recovery): one
//   signature leaves two candidate keys, a second signature settles it.
// - The policy is a fixed template of (public key, settings), so nodes see an ordinary policy.

import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, hexToBytes } from "./bytes.js";
import { approveWithPasskey, backupState, base64url, fromBase64url, createPasskey, passkeySigner, type Passkey } from "./passkey.js";
import { signerId, type PolicyRequest } from "./policy.js";
import type { Approval, Clause, Policy } from "./types.js";

/** Name of the wallet key under its policy (`policy/<id>/wallet`). */
export const WALLET_KEY_NAME = "wallet";
const VERSION = 1;
const FLAG_LIMIT = 1;
const FLAG_RECOVERY = 2;
const SETTINGS_LEN = 58;

export interface WalletSettings {
  /** Most sompi the passkey alone may send per transaction (decimal string); none if absent. */
  limit?: string;
  /** ed25519 public key (hex) that may also spend, e.g. to move coins if the passkey is lost. */
  recovery?: string;
}

export interface PasskeyWallet {
  rpId: string;
  /** Passkey credential id (base64url). */
  credentialId: string;
  settings: WalletSettings;
  /** Candidate public keys (compressed hex): two right after sign-in, one once resolved. */
  keys: string[];
  /**
   * Whether the passkey is synced to a provider (iCloud Keychain, Google, …), as of its last
   * signature. If false, losing this device loses the passkey; only the recovery key remains.
   */
  backedUp?: boolean;
}

/**
 * The 58 bytes stored as the passkey's user id:
 * version u8 | flags u8 | limit u64le | recovery key [32] | random [16].
 * The random part keeps two wallets with equal settings from replacing each other's passkey.
 */
export function encodeSettings(s: WalletSettings, nonce: Uint8Array = crypto.getRandomValues(new Uint8Array(16))): Uint8Array {
  checkSettings(s);
  if (nonce.length !== 16) throw new Error("nonce must be 16 bytes");
  const out = new Uint8Array(SETTINGS_LEN);
  const view = new DataView(out.buffer);
  out[0] = VERSION;
  out[1] = (s.limit !== undefined ? FLAG_LIMIT : 0) | (s.recovery !== undefined ? FLAG_RECOVERY : 0);
  if (s.limit !== undefined) view.setBigUint64(2, BigInt(s.limit), true);
  if (s.recovery !== undefined) out.set(hexToBytes(s.recovery), 10);
  out.set(nonce, 42);
  return out;
}

export function decodeSettings(b: Uint8Array): WalletSettings {
  if (b.length !== SETTINGS_LEN || b[0] !== VERSION || (b[1]! & ~(FLAG_LIMIT | FLAG_RECOVERY)) !== 0) {
    throw new Error("this passkey was not created as an htn-tsn wallet");
  }
  const view = new DataView(b.buffer, b.byteOffset, b.byteLength);
  const s: WalletSettings = {};
  if (b[1]! & FLAG_LIMIT) s.limit = view.getBigUint64(2, true).toString();
  if (b[1]! & FLAG_RECOVERY) s.recovery = bytesToHex(b.slice(10, 42));
  checkSettings(s);
  return s;
}

function checkSettings(s: WalletSettings) {
  if (s.limit !== undefined && (!/^[0-9]+$/.test(s.limit) || BigInt(s.limit) === 0n || BigInt(s.limit) >= 1n << 64n)) {
    throw new Error("limit must be a positive whole number of sompi");
  }
  if (s.recovery !== undefined) signerId(s.recovery);
}

/** The wallet's policy for one candidate key: the passkey alone (up to the limit), or the recovery key. */
export function walletPolicy(rpId: string, publicKey: string, s: WalletSettings): Policy {
  const passkey: Clause = { signers: { k: 1, of: [passkeySigner(rpId, publicKey)] } };
  if (s.limit !== undefined) passkey.max_per_tx = s.limit;
  const clauses = [passkey];
  if (s.recovery !== undefined) clauses.push({ signers: { k: 1, of: [signerId(s.recovery)] } });
  return { version: 1, clauses };
}

/** Policies of the wallet's candidate keys (one entry once resolved). */
export function walletPolicies(w: PasskeyWallet): { key: string; policy: Policy }[] {
  return w.keys.map((key) => ({ key, policy: walletPolicy(w.rpId, key, w.settings) }));
}

/** P-256 public keys (compressed hex) that verify this WebAuthn assertion: usually two. */
export function recoverPasskeyKeys(authenticatorData: Uint8Array, clientDataJSON: Uint8Array, derSignature: Uint8Array): string[] {
  const hash = sha256(concatBytes(authenticatorData, sha256(clientDataJSON)));
  const sig = p256.Signature.fromBytes(derSignature, "der");
  const keys = new Set<string>();
  for (const bit of [0, 1, 2, 3]) {
    try {
      keys.add(bytesToHex(sig.addRecoveryBit(bit).recoverPublicKey(hash).toBytes(true)));
    } catch {
      // no point for this recovery bit
    }
  }
  return [...keys];
}

/** Keeps the wallet's candidate keys that also made another assertion. */
export function narrowWallet(w: PasskeyWallet, keys: string[]): PasskeyWallet {
  const left = w.keys.filter((k) => keys.includes(k));
  if (left.length === 0) throw new Error("that passkey doesn't belong to this wallet");
  return { ...w, keys: left };
}

/** The resolved wallet as a `Passkey` (for `approveWithPasskey`). */
export function walletPasskey(w: PasskeyWallet): Passkey {
  if (w.keys.length !== 1) throw new Error("wallet key not settled yet; call confirmWallet");
  return { credentialId: w.credentialId, rpId: w.rpId, signer: passkeySigner(w.rpId, w.keys[0]!) };
}

interface Assertion {
  credentialId: string;
  userHandle: Uint8Array | null;
  authenticatorData: Uint8Array;
  clientDataJSON: Uint8Array;
  signature: Uint8Array;
}

async function assertion(rpId: string, credentialId?: string): Promise<Assertion> {
  const cred = (await navigator.credentials.get({
    publicKey: {
      challenge: crypto.getRandomValues(new Uint8Array(32)),
      rpId,
      userVerification: "required",
      allowCredentials: credentialId ? [{ type: "public-key", id: fromBase64url(credentialId) }] : [],
      timeout: 120_000,
    },
  })) as PublicKeyCredential | null;
  if (!cred) throw new Error("passkey sign-in was cancelled");
  const res = cred.response as AuthenticatorAssertionResponse;
  return {
    credentialId: base64url(new Uint8Array(cred.rawId)),
    userHandle: res.userHandle ? new Uint8Array(res.userHandle) : null,
    authenticatorData: new Uint8Array(res.authenticatorData),
    clientDataJSON: new Uint8Array(res.clientDataJSON),
    signature: new Uint8Array(res.signature),
  };
}

/** Browser: create a wallet passkey (one Face ID / Touch ID prompt). The key is known right away. */
export async function createWallet(opts: { rpId: string; rpName: string; userName: string; settings: WalletSettings }): Promise<PasskeyWallet> {
  const userId = encodeSettings(opts.settings);
  const pk = await createPasskey({ rpId: opts.rpId, rpName: opts.rpName, userName: opts.userName, userId, discoverable: true });
  return {
    rpId: opts.rpId,
    credentialId: pk.credentialId,
    settings: opts.settings,
    keys: [pk.signer.split(":")[2]!],
    ...(pk.backedUp !== undefined ? { backedUp: pk.backedUp } : {}),
  };
}

/**
 * Browser: sign in with any wallet passkey for `rpId` (one prompt; the device lists its passkeys).
 * Leaves two candidate keys; the next signature (a payment, or `confirmWallet`) settles it.
 */
export async function signInWallet(opts: { rpId: string }): Promise<PasskeyWallet> {
  const a = await assertion(opts.rpId);
  if (!a.userHandle) throw new Error("this passkey has no wallet settings (not created as an htn-tsn wallet)");
  const settings = decodeSettings(a.userHandle);
  return {
    rpId: opts.rpId,
    credentialId: a.credentialId,
    settings,
    keys: recoverPasskeyKeys(a.authenticatorData, a.clientDataJSON, a.signature),
    backedUp: backupState(a.authenticatorData).backedUp,
  };
}

/** Browser: settle the wallet's key with one more signature (needed before showing a deposit address). */
export async function confirmWallet(w: PasskeyWallet): Promise<PasskeyWallet> {
  if (w.keys.length === 1) return w;
  const a = await assertion(w.rpId, w.credentialId);
  return {
    ...narrowWallet(w, recoverPasskeyKeys(a.authenticatorData, a.clientDataJSON, a.signature)),
    backedUp: backupState(a.authenticatorData).backedUp,
  };
}

/**
 * Browser: approve a payment from the wallet key `key` (default: the settled key). Returns the
 * approval and the wallet, now settled. Throws if the passkey's real key isn't `key`.
 */
export async function approveWithWallet(
  request: PolicyRequest,
  w: PasskeyWallet,
  key: string | undefined = w.keys.length === 1 ? w.keys[0] : undefined,
): Promise<{ approval: Approval; wallet: PasskeyWallet }> {
  if (!key || !w.keys.includes(key)) throw new Error("choose which of the wallet's keys pays (or call confirmWallet)");
  const approval = await approveWithPasskey(request, { credentialId: w.credentialId, rpId: w.rpId, signer: passkeySigner(w.rpId, key) });
  const recovered = recoverPasskeyKeys(
    hexToBytes(approval.authenticator_data!),
    hexToBytes(approval.client_data_json!),
    hexToBytes(approval.sig),
  );
  const wallet = { ...narrowWallet(w, recovered), backedUp: backupState(hexToBytes(approval.authenticator_data!)).backedUp };
  if (wallet.keys.length !== 1 || wallet.keys[0] !== key) throw new Error("this passkey doesn't control that address");
  return { approval, wallet };
}
