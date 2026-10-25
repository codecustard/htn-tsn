/** Networks supported by the signing network. */
export type Network = "kaspa-mainnet" | "kaspa-testnet" | "hoosat-mainnet" | "hoosat-testnet";

/** Bech32 address prefix for each network. */
export const PREFIX: Record<Network, string> = {
  "kaspa-mainnet": "kaspa",
  "kaspa-testnet": "kaspatest",
  "hoosat-mainnet": "hoosat",
  "hoosat-testnet": "hoosattest",
};

/**
 * Transaction as exchanged with the coordinator. 64-bit values are decimal strings so they
 * survive JSON in JavaScript; use `BigInt(...)` to do arithmetic on them.
 */
export interface TxInput {
  prev_txid: string;
  index: number;
  amount: string;
  script_pubkey: string;
  sequence: string;
  sig_op_count: number;
  signature_script?: string;
}

export interface TxOutput {
  address: string;
  amount: string;
}

export interface Tx {
  network: Network;
  inputs: TxInput[];
  outputs: TxOutput[];
  lock_time: string;
}

/** The owner's approval of one transaction (all inputs, all retries) until it expires. */
export interface Authorization {
  request_id: string;
  expires_at: number;
  owner_sig: string;
}

export interface Prepared {
  key_id: string;
  path: string;
  from: string;
  tx: Tx;
  fee: string;
  mass: string;
  change: string;
  feerate: number;
  skipped_young_utxos: number;
}

export interface SendResult {
  txid: string | null;
  explorer: string | null;
  tx: Tx;
  log: string[];
}

export interface Info {
  key_id: string;
  master_public_key: string;
  threshold: number;
  nodes: number;
  networks: { network: Network; prefix: string; api: string }[];
  max_fee: string;
  max_authorization_ttl_secs: number;
}

export interface Balance {
  address: string;
  balance: string;
  utxos: { txid: string; index: number; amount: string; block_daa_score: string }[];
}
