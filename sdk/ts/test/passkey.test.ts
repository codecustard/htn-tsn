import { describe, expect, it } from "vitest";
import { p256 } from "@noble/curves/nist.js";
import { sha256 } from "@noble/hashes/sha2.js";
import { bytesToHex, concatBytes, hexToBytes } from "../src/bytes.js";
import { requestDigest } from "../src/digest.js";
import { base64url, fromBase64url, passkeySigner, softPasskey, spkiToCompressed } from "../src/passkey.js";
import { newPolicyRequest, normalizePolicy, policyPath } from "../src/policy.js";
import type { Policy, Tx } from "../src/types.js";
import { readFileSync } from "node:fs";

const v = JSON.parse(readFileSync(new URL("../../../testdata/sdk-vectors.json", import.meta.url), "utf8"));

describe("passkeys", () => {
  it("converts a P-256 SPKI public key to the compressed signer form", () => {
    const sk = p256.utils.randomSecretKey();
    const uncompressed = p256.getPublicKey(sk, false);
    const spki = concatBytes(hexToBytes("3059301306072a8648ce3d020106082a8648ce3d030107034200"), uncompressed);
    expect(spkiToCompressed(spki)).toBe(bytesToHex(p256.getPublicKey(sk, true)));
  });

  it("base64url round-trips", () => {
    const b = Uint8Array.from({ length: 33 }, (_, i) => i * 7);
    expect(base64url(b)).not.toMatch(/[+/=]/);
    expect(fromBase64url(base64url(b))).toEqual(b);
  });

  it("validates signer ids", () => {
    expect(() => passkeySigner("Wallet.com", "02" + "aa".repeat(32))).toThrow();
    expect(() => passkeySigner("wallet.com", "04" + "aa".repeat(32))).toThrow();
    expect(passkeySigner("localhost", "02" + "aa".repeat(32))).toMatch(/^passkey:localhost:02/);
  });

  it("soft passkey produces a WebAuthn assertion over the request digest", () => {
    const pk = softPasskey("wallet.example.com", "https://wallet.example.com");
    const policy: Policy = { version: 1, clauses: [{ signers: { k: 1, of: [pk.signer] } }] };
    expect(normalizePolicy(policy).clauses[0]!.signers.of[0]).toBe(pk.signer);
    const tx: Tx = v.authorization.tx;
    const req = newPolicyRequest("master", policyPath(policy, "w"), policy, tx);
    const a = pk.approve(req);
    const ad = hexToBytes(a.authenticator_data!);
    const cd = hexToBytes(a.client_data_json!);
    const client = JSON.parse(new TextDecoder().decode(cd));
    const digest = requestDigest("master", req.path, req.request_id, req.expires_at, tx);
    expect(client.challenge).toBe(base64url(digest));
    expect(bytesToHex(ad.slice(0, 32))).toBe(bytesToHex(sha256(new TextEncoder().encode("wallet.example.com"))));
    expect(ad[32]! & 0x05).toBe(0x05);
    const pub = hexToBytes(pk.signer.split(":")[2]!);
    expect(p256.verify(hexToBytes(a.sig), concatBytes(ad, sha256(cd)), pub, { format: "der" })).toBe(true);
  });
});
