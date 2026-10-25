import { bytesToHex, concatBytes, hexToBytes, utf8ToBytes } from "@noble/hashes/utils.js";

export { bytesToHex, concatBytes, hexToBytes, utf8ToBytes };

export function u32le(n: number): Uint8Array {
  const b = new Uint8Array(4);
  new DataView(b.buffer).setUint32(0, n, true);
  return b;
}

export function u64le(n: bigint | number): Uint8Array {
  const v = BigInt(n);
  if (v < 0n || v >= 1n << 64n) throw new Error(`value out of u64 range: ${v}`);
  const b = new Uint8Array(8);
  new DataView(b.buffer).setBigUint64(0, v, true);
  return b;
}

/** u64 little-endian length prefix followed by the bytes. */
export function lp(b: Uint8Array): Uint8Array {
  return concatBytes(u64le(b.length), b);
}

export function randomHex(nBytes: number): string {
  const b = new Uint8Array(nBytes);
  globalThis.crypto.getRandomValues(b);
  return bytesToHex(b);
}
