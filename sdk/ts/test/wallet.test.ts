import { describe, expect, it } from "vitest";
import { readFileSync } from "node:fs";
import { hexToBytes } from "../src/bytes.js";
import { softPasskey } from "../src/passkey.js";
import { newPolicyRequest, normalizePolicy, policyPath } from "../src/policy.js";
import type { Tx } from "../src/types.js";
import {
  WALLET_KEY_NAME,
  decodeSettings,
  encodeSettings,
  narrowWallet,
  recoverPasskeyKeys,
  walletPasskey,
  walletPolicies,
  walletPolicy,
  type PasskeyWallet,
} from "../src/wallet.js";

const v = JSON.parse(readFileSync(new URL("../../../testdata/sdk-vectors.json", import.meta.url), "utf8"));
const recovery = "ab".repeat(32);
const RP = "wallet.example.com";
const ORIGIN = "https://wallet.example.com";

describe("passkey wallet settings", () => {
  it("round-trips through the 58-byte user handle", () => {
    for (const s of [{}, { limit: "100000000" }, { recovery }, { limit: "18446744073709551615", recovery }]) {
      const b = encodeSettings(s);
      expect(b.length).toBe(58);
      expect(b.length).toBeLessThanOrEqual(64);
      expect(decodeSettings(b)).toEqual(s);
    }
  });

  it("random part differs between wallets with equal settings", () => {
    const a = encodeSettings({ limit: "1" });
    const b = encodeSettings({ limit: "1" });
    expect(a.slice(0, 42)).toEqual(b.slice(0, 42));
    expect(a.slice(42)).not.toEqual(b.slice(42));
  });

  it("rejects bad settings and foreign user handles", () => {
    expect(() => encodeSettings({ limit: "0" })).toThrow();
    expect(() => encodeSettings({ limit: "-1" })).toThrow();
    expect(() => encodeSettings({ limit: (1n << 64n).toString() })).toThrow();
    expect(() => encodeSettings({ recovery: "xyz" })).toThrow();
    expect(() => decodeSettings(new Uint8Array(16))).toThrow(/not created as an htn-tsn wallet/);
    const b = encodeSettings({});
    b[0] = 2;
    expect(() => decodeSettings(b)).toThrow();
  });

  it("builds a valid policy: passkey up to the limit, or the recovery key", () => {
    const pk = softPasskey(RP, ORIGIN);
    const p = walletPolicy(RP, pk.publicKey, { limit: "100000000", recovery });
    expect(normalizePolicy(p)).toEqual({
      version: 1,
      clauses: [
        { signers: { k: 1, of: [pk.signer] }, max_per_tx: "100000000" },
        { signers: { k: 1, of: [`ed25519:${recovery}`] } },
      ],
    });
    expect(walletPolicy(RP, pk.publicKey, {})).toEqual({ version: 1, clauses: [{ signers: { k: 1, of: [pk.signer] } }] });
  });
});

describe("passkey key recovery", () => {
  it("one assertion leaves the real key among two candidates; a second settles it", () => {
    const pk = softPasskey(RP, ORIGIN);
    const a = pk.assert(crypto.getRandomValues(new Uint8Array(32)));
    const keys = recoverPasskeyKeys(a.authenticatorData, a.clientDataJSON, a.signature);
    expect(keys).toContain(pk.publicKey);
    expect(keys.length).toBe(2);
    let w: PasskeyWallet = { rpId: RP, credentialId: "id", settings: { recovery }, keys };
    expect(() => walletPasskey(w)).toThrow(/not settled/);
    expect(walletPolicies(w)).toHaveLength(2);
    const b = pk.assert(crypto.getRandomValues(new Uint8Array(32)));
    w = narrowWallet(w, recoverPasskeyKeys(b.authenticatorData, b.clientDataJSON, b.signature));
    expect(w.keys).toEqual([pk.publicKey]);
    expect(walletPasskey(w).signer).toBe(pk.signer);
  });

  it("a payment approval settles it too, and another passkey doesn't", () => {
    const pk = softPasskey(RP, ORIGIN);
    const a = pk.assert(crypto.getRandomValues(new Uint8Array(32)));
    const w: PasskeyWallet = { rpId: RP, credentialId: "id", settings: {}, keys: recoverPasskeyKeys(a.authenticatorData, a.clientDataJSON, a.signature) };
    const policy = walletPolicy(RP, pk.publicKey, w.settings);
    const tx: Tx = v.authorization.tx;
    const req = newPolicyRequest("master", policyPath(policy, WALLET_KEY_NAME), policy, tx);
    const approval = pk.approve(req);
    const keys = recoverPasskeyKeys(hexToBytes(approval.authenticator_data!), hexToBytes(approval.client_data_json!), hexToBytes(approval.sig));
    expect(narrowWallet(w, keys).keys).toEqual([pk.publicKey]);
    const other = softPasskey(RP, ORIGIN).assert(new Uint8Array(32));
    expect(() => narrowWallet(w, recoverPasskeyKeys(other.authenticatorData, other.clientDataJSON, other.signature))).toThrow(/doesn't belong/);
  });
});
