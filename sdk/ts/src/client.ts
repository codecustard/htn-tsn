// Client for tsn-coordinator. The coordinator is untrusted: addresses are derived locally from a
// pinned master public key, and every prepared transaction is checked before the owner signs it.

import { keyAddress, type KeyAddress } from "./derive.js";
import { checkIntent } from "./intent.js";
import { authorize, type OwnerKey } from "./owner.js";
import type { Authorization, Balance, Info, Network, Prepared, SendResult } from "./types.js";

export interface ClientOptions {
  /** Coordinator base URL, e.g. http://127.0.0.1:7100 */
  baseUrl: string;
  /**
   * The network's master public key (33-byte compressed, hex), obtained out of band from the
   * operators (it is printed by `tsn dkg`). Pinned so a coordinator can't substitute its own key.
   */
  masterPublicKey: string;
  /** Master key id; defaults to "master". */
  keyId?: string;
  /** Sent as `x-api-key` when the coordinator requires one. */
  apiKey?: string;
  fetch?: typeof fetch;
}

export interface PayRequest {
  owner: OwnerKey;
  /** Key name under the owner; one owner can have any number of keys. */
  name: string;
  network: Network;
  to: string;
  /** Sompi (1 KAS/HTN = 100,000,000), or "all" to sweep the balance. */
  amount: bigint | "all";
  /** Refuse fees above this (sompi). Default 0.1 coin. */
  maxFee?: bigint;
  /** Sompi per gram; default is the coordinator's choice (API estimate or chain minimum). */
  feerate?: number;
  /** Authorization lifetime in seconds (max 3600). Default 600. */
  ttlSecs?: number;
  /** Set false to sign without broadcasting. Default true. */
  broadcast?: boolean;
}

export class TsnClient {
  readonly baseUrl: string;
  readonly masterPublicKey: string;
  readonly keyId: string;
  private readonly apiKey?: string;
  private readonly fetchFn: typeof fetch;

  constructor(opts: ClientOptions) {
    if (!/^0[23][0-9a-f]{64}$/.test(opts.masterPublicKey)) {
      throw new Error("masterPublicKey must be a 33-byte compressed secp256k1 key in lowercase hex");
    }
    this.baseUrl = opts.baseUrl.replace(/\/+$/, "");
    this.masterPublicKey = opts.masterPublicKey;
    this.keyId = opts.keyId ?? "master";
    this.apiKey = opts.apiKey;
    this.fetchFn = opts.fetch ?? globalThis.fetch.bind(globalThis);
  }

  private async call<T>(method: "GET" | "POST", path: string, body?: unknown): Promise<T> {
    const headers: Record<string, string> = {};
    if (body !== undefined) headers["content-type"] = "application/json";
    if (this.apiKey) headers["x-api-key"] = this.apiKey;
    const res = await this.fetchFn(this.baseUrl + path, {
      method,
      headers,
      body: body === undefined ? undefined : JSON.stringify(body),
    });
    const text = await res.text();
    let json: unknown;
    try {
      json = JSON.parse(text);
    } catch {
      throw new Error(`${method} ${path}: HTTP ${res.status}: ${text.slice(0, 200)}`);
    }
    if (!res.ok) {
      const msg = (json as { error?: string }).error ?? text;
      throw new Error(`${method} ${path}: ${msg}`);
    }
    return json as T;
  }

  /** Coordinator info; throws if it serves a different master key than the pinned one. */
  async info(): Promise<Info> {
    const info = await this.call<Info>("GET", "/v1/info");
    if (info.master_public_key !== this.masterPublicKey) {
      throw new Error("coordinator's master public key differs from the pinned one; refusing to use it");
    }
    if (info.key_id !== this.keyId) throw new Error(`coordinator serves key ${info.key_id}, expected ${this.keyId}`);
    return info;
  }

  /** Address of OWNER/NAME, computed locally (no request). */
  address(ownerPublicKey: string, name: string, network: Network): KeyAddress {
    return keyAddress(this.masterPublicKey, ownerPublicKey, name, network);
  }

  async balance(ownerPublicKey: string, name: string, network: Network): Promise<Balance> {
    const q = new URLSearchParams({ owner: ownerPublicKey, name, network });
    const b = await this.call<Balance>("GET", `/v1/balance?${q}`);
    if (b.address !== this.address(ownerPublicKey, name, network).address) {
      throw new Error("coordinator returned a balance for a different address");
    }
    return b;
  }

  async prepare(r: Omit<PayRequest, "owner" | "ttlSecs" | "broadcast"> & { ownerPublicKey: string }): Promise<Prepared> {
    return this.call<Prepared>("POST", "/v1/tx/prepare", {
      owner: r.ownerPublicKey,
      name: r.name,
      network: r.network,
      to: r.to,
      ...(r.amount === "all" ? { all: true } : { amount: r.amount.toString() }),
      ...(r.feerate !== undefined ? { feerate: r.feerate } : {}),
      ...(r.maxFee !== undefined ? { max_fee: r.maxFee.toString() } : {}),
    });
  }

  async send(path: string, prepared: Prepared, auth: Authorization, broadcast = true): Promise<SendResult> {
    return this.call<SendResult>("POST", "/v1/tx/send", { path, tx: prepared.tx, auth, broadcast });
  }

  /** Prepare → check → authorize → threshold-sign (→ broadcast). */
  async pay(r: PayRequest): Promise<SendResult & { prepared: Prepared; fee: bigint }> {
    await this.info();
    const key = this.address(r.owner.public, r.name, r.network);
    const maxFee = r.maxFee ?? 10_000_000n;
    const prepared = await this.prepare({ ...r, ownerPublicKey: r.owner.public, maxFee });
    const fee = checkIntent(prepared, {
      network: r.network,
      keyId: this.keyId,
      path: key.path,
      from: key.address,
      script: key.script,
      to: r.to,
      amount: r.amount,
      maxFee,
    });
    const auth = authorize(r.owner, this.keyId, key.path, prepared.tx, r.ttlSecs ?? 600);
    const result = await this.send(key.path, prepared, auth, r.broadcast ?? true);
    const sameOutputs = JSON.stringify(result.tx.outputs) === JSON.stringify(prepared.tx.outputs);
    if (!sameOutputs) throw new Error("coordinator returned a transaction with different outputs");
    return { ...result, prepared, fee };
  }
}
