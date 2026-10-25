// Kaspa-family bech32 (CashAddr-style 40-bit checksum), matching tsn-core/src/address.rs.

const CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l";
const GEN = [0x98f2bc8e61n, 0x79b76d99e2n, 0xf33e5fb3c4n, 0xae2eabe2a8n, 0x1e4f43e470n];

export const VERSION_PUBKEY = 0;
export const VERSION_PUBKEY_ECDSA = 1;
export const VERSION_SCRIPT_HASH = 8;

function polymod(values: number[]): bigint {
  let c = 1n;
  for (const d of values) {
    const c0 = c >> 35n;
    c = ((c & 0x07ffffffffn) << 5n) ^ BigInt(d);
    for (let i = 0; i < 5; i++) if ((c0 >> BigInt(i)) & 1n) c ^= GEN[i]!;
  }
  return c ^ 1n;
}

function conv8to5(data: Uint8Array): number[] {
  const out: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const b of data) {
    acc = ((acc << 8) | b) & 0xffff;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out.push((acc >> bits) & 31);
    }
  }
  if (bits > 0) out.push((acc << (5 - bits)) & 31);
  return out;
}

function conv5to8(data: number[]): Uint8Array {
  const out: number[] = [];
  let acc = 0;
  let bits = 0;
  for (const b of data) {
    acc = ((acc << 5) | b) & 0xffff;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((acc >> bits) & 0xff);
    }
  }
  if (bits >= 5 || ((acc << (8 - bits)) & 0xff) !== 0) throw new Error("invalid padding in address payload");
  return Uint8Array.from(out);
}

function checksum(prefix: string, payload5: number[]): bigint {
  const values = [...Array.from(prefix, (ch) => ch.charCodeAt(0) & 0x1f), 0, ...payload5, 0, 0, 0, 0, 0, 0, 0, 0];
  return polymod(values);
}

/** Encodes `prefix:payload` where payload = version byte ‖ data. */
export function encodeAddress(prefix: string, version: number, data: Uint8Array): string {
  const payload5 = conv8to5(Uint8Array.from([version, ...data]));
  const cs = checksum(prefix, payload5);
  const cs5 = Array.from({ length: 8 }, (_, i) => Number((cs >> BigInt(5 * (7 - i))) & 31n));
  return `${prefix}:${[...payload5, ...cs5].map((v) => CHARSET[v]).join("")}`;
}

/** Decodes and checksum-validates an address. */
export function decodeAddress(address: string): { prefix: string; version: number; data: Uint8Array } {
  const sep = address.indexOf(":");
  if (sep < 0) throw new Error("address missing prefix");
  const prefix = address.slice(0, sep);
  const body = address.slice(sep + 1);
  if (body.length < 9) throw new Error("address too short");
  const values = Array.from(body, (ch) => {
    const v = CHARSET.indexOf(ch);
    if (v < 0) throw new Error(`invalid character ${ch}`);
    return v;
  });
  const payload5 = values.slice(0, -8);
  const cs = values.slice(-8).reduce((acc, v) => (acc << 5n) | BigInt(v), 0n);
  if (checksum(prefix, payload5) !== cs) throw new Error("bad address checksum");
  const raw = conv5to8(payload5);
  return { prefix, version: raw[0]!, data: raw.slice(1) };
}
