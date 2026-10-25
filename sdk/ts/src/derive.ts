// Path-based key derivation, matching tsn-core/src/derive.rs:
//   child_pub = master_pub + t·G,  t = H("HTN-TSN/derive/v1", master_pub || path) mod n
// Anyone with the master public key can compute every child address offline.

import { secp256k1 } from "@noble/curves/secp256k1.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, hexToBytes, u32le, utf8ToBytes } from "./bytes.js";
import { encodeAddress, VERSION_PUBKEY } from "./bech32.js";
import { PREFIX, type Network } from "./types.js";

const Point = secp256k1.Point;
const TAG = sha256(utf8ToBytes("HTN-TSN/derive/v1"));

/** Tweak scalar for `path` under the 33-byte compressed master public key. */
export function tweak(masterPublicKey: Uint8Array, path: string): bigint {
  const p = utf8ToBytes(path);
  const h = sha256(concatBytes(TAG, TAG, masterPublicKey, u32le(p.length), p));
  return Point.Fn.create(BigInt("0x" + bytesToHex(h)));
}

/** 32-byte BIP340 x-only public key of the child key at `path`. */
export function childXOnly(masterPublicKeyHex: string, path: string): Uint8Array {
  const master = hexToBytes(masterPublicKeyHex);
  if (master.length !== 33) throw new Error("master public key must be 33 bytes (compressed)");
  const child = Point.fromBytes(master).add(Point.BASE.multiply(tweak(master, path)));
  return child.toBytes(true).slice(1);
}

/** `OP_DATA_32 <x-only key> OP_CHECKSIG`, the standard Schnorr pay-to-pubkey script. */
export function p2pkScript(xonly: Uint8Array): Uint8Array {
  return concatBytes(Uint8Array.of(0x20), xonly, Uint8Array.of(0xac));
}

export function ownerPath(ownerPublicKeyHex: string, name: string): string {
  if (!/^[0-9a-f]{64}$/.test(ownerPublicKeyHex)) throw new Error("owner public key must be 32 bytes of lowercase hex");
  if (!name) throw new Error("name must not be empty");
  return `owner/${ownerPublicKeyHex}/${name}`;
}

export interface KeyAddress {
  path: string;
  address: string;
  script: string;
}

/** Address of OWNER/NAME on `network`, computed offline from the master public key. */
export function keyAddress(masterPublicKeyHex: string, ownerPublicKeyHex: string, name: string, network: Network): KeyAddress {
  const path = ownerPath(ownerPublicKeyHex, name);
  const xonly = childXOnly(masterPublicKeyHex, path);
  return { path, address: encodeAddress(PREFIX[network], VERSION_PUBKEY, xonly), script: bytesToHex(p2pkScript(xonly)) };
}
