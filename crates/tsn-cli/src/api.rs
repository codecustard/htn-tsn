//! Client for the public REST API that Kaspa and Hoosat both run (kaspa-rest-server and its
//! Hoosat fork share endpoints and JSON shapes). No full node is needed: UTXOs are read and
//! signed transactions submitted over HTTPS. A lying API cannot redirect funds: each input's
//! sighash commits to the UTXO's amount and script, so bad data only makes the transaction fail.

use anyhow::{anyhow, bail, Context, Result};
use serde::Deserialize;
use serde_json::{json, Value};
use std::time::Duration;
use tsn_core::chain::{self, Network, Tx};

pub fn default_api(network: Network) -> Option<&'static str> {
    match network {
        Network::KaspaMainnet => Some("https://api.kaspa.org"),
        Network::KaspaTestnet => Some("https://api-tn10.kaspa.org"),
        Network::HoosatMainnet => Some("https://api.explorer-eu.hoosat.network"),
        Network::HoosatTestnet => None,
    }
}

pub fn explorer_tx_url(network: Network, txid: &str) -> Option<String> {
    let base = match network {
        Network::KaspaMainnet => "https://explorer.kaspa.org",
        Network::KaspaTestnet => "https://explorer-tn10.kaspa.org",
        Network::HoosatMainnet => "https://explorer-eu.hoosat.network",
        Network::HoosatTestnet => return None,
    };
    Some(format!("{base}/txs/{txid}"))
}

/// Minimum fee rates, sompi per gram, used when the API has no fee estimate.
/// Hoosat's default relay minimum is 1 sompi/gram; 2 leaves headroom at negligible cost.
pub fn fallback_feerate(network: Network) -> f64 {
    if network.is_hoosat() {
        2.0
    } else {
        1.0
    }
}

#[derive(Debug, Clone, Deserialize)]
pub struct Utxo {
    pub outpoint: Outpoint,
    #[serde(rename = "utxoEntry")]
    pub entry: UtxoEntry,
}

#[derive(Debug, Clone, Deserialize)]
pub struct Outpoint {
    #[serde(rename = "transactionId")]
    pub transaction_id: String,
    pub index: u32,
}

#[derive(Debug, Clone, Deserialize)]
pub struct UtxoEntry {
    #[serde(deserialize_with = "u64_from_str_or_num")]
    pub amount: u64,
    #[serde(rename = "scriptPublicKey")]
    pub script_public_key: ScriptPublicKey,
    #[serde(rename = "blockDaaScore", deserialize_with = "u64_from_str_or_num")]
    pub block_daa_score: u64,
    #[serde(rename = "isCoinbase", default)]
    pub is_coinbase: bool,
}

#[derive(Debug, Clone, Deserialize)]
pub struct ScriptPublicKey {
    #[serde(rename = "scriptPublicKey")]
    pub script: String,
    #[serde(default)]
    pub version: u16,
}

fn u64_from_str_or_num<'de, D: serde::Deserializer<'de>>(d: D) -> std::result::Result<u64, D::Error> {
    match Value::deserialize(d)? {
        Value::String(s) => s.parse().map_err(serde::de::Error::custom),
        Value::Number(n) => n.as_u64().ok_or_else(|| serde::de::Error::custom("not a u64")),
        other => Err(serde::de::Error::custom(format!("expected number, got {other}"))),
    }
}

pub fn parse_utxos(body: &str) -> Result<Vec<Utxo>> {
    Ok(serde_json::from_str(body)?)
}

/// Request body for `POST /transactions` (same on Kaspa and Hoosat).
pub fn submit_body(tx: &Tx) -> Result<Value> {
    let inputs: Vec<Value> = tx
        .inputs
        .iter()
        .map(|i| {
            json!({
                "previousOutpoint": { "transactionId": i.prev_txid, "index": i.index },
                "signatureScript": i.signature_script,
                "sequence": i.sequence,
                "sigOpCount": i.sig_op_count,
            })
        })
        .collect();
    let mut outputs = Vec::new();
    for o in &tx.outputs {
        let spk = chain::script_for_address(tx.network, &o.address)?;
        outputs.push(json!({ "amount": o.amount, "scriptPublicKey": { "version": 0, "scriptPublicKey": hex::encode(spk) } }));
    }
    Ok(json!({
        "transaction": {
            "version": 0,
            "inputs": inputs,
            "outputs": outputs,
            "lockTime": tx.lock_time,
            "subnetworkId": "0000000000000000000000000000000000000000",
        },
        "allowOrphan": false,
    }))
}

pub struct Api {
    base: String,
    http: reqwest::Client,
    /// True when using the network's default public API (so explorer links apply).
    pub is_default: bool,
}

impl Api {
    pub fn new(network: Network, base: Option<String>) -> Result<Self> {
        let is_default = base.is_none();
        let base = base
            .or_else(|| default_api(network).map(str::to_string))
            .ok_or_else(|| anyhow!("no public API known for {network:?}; pass --api <url>"))?;
        let http = reqwest::Client::builder().timeout(Duration::from_secs(30)).build()?;
        Ok(Self { base: base.trim_end_matches('/').to_string(), http, is_default })
    }

    async fn get(&self, path: &str) -> Result<String> {
        let url = format!("{}{}", self.base, path);
        let r = self.http.get(&url).send().await.with_context(|| format!("GET {url}"))?;
        let status = r.status();
        let body = r.text().await?;
        if !status.is_success() {
            bail!("GET {url}: HTTP {status}: {}", body.chars().take(300).collect::<String>());
        }
        Ok(body)
    }

    pub async fn utxos(&self, address: &str) -> Result<Vec<Utxo>> {
        parse_utxos(&self.get(&format!("/addresses/{address}/utxos")).await?)
            .with_context(|| format!("parsing UTXOs from {}", self.base))
    }

    /// Normal-priority fee rate from `/info/fee-estimate`, if the API offers one.
    pub async fn feerate(&self) -> Option<f64> {
        let body = self.get("/info/fee-estimate").await.ok()?;
        let v: Value = serde_json::from_str(&body).ok()?;
        v["normalBuckets"][0]["feerate"].as_f64().or_else(|| v["priorityBucket"]["feerate"].as_f64())
    }

    /// Current virtual DAA score (used to warn about Hoosat's minimum input age).
    pub async fn virtual_daa_score(&self) -> Option<u64> {
        let body = self.get("/info/blockdag").await.ok()?;
        let v: Value = serde_json::from_str(&body).ok()?;
        v["virtualDaaScore"].as_str().and_then(|s| s.parse().ok()).or_else(|| v["virtualDaaScore"].as_u64())
    }

    /// Server-side mass check (Kaspa only exposes this).
    pub async fn server_mass(&self, tx: &Tx) -> Result<Value> {
        let url = format!("{}/transactions/mass", self.base);
        let body = submit_body(tx)?["transaction"].clone();
        let r = self.http.post(&url).json(&body).send().await?;
        let status = r.status();
        let v: Value = r.json().await.unwrap_or(Value::Null);
        if !status.is_success() {
            bail!("POST {url}: HTTP {status}: {v}");
        }
        Ok(v)
    }

    pub async fn submit(&self, tx: &Tx) -> Result<String> {
        let url = format!("{}/transactions", self.base);
        let r = self.http.post(&url).json(&submit_body(tx)?).send().await.with_context(|| format!("POST {url}"))?;
        let status = r.status();
        let text = r.text().await?;
        let v: Value = serde_json::from_str(&text).unwrap_or(Value::String(text.clone()));
        if let Some(id) = v["transactionId"].as_str() {
            return Ok(id.to_string());
        }
        let err = v["error"].as_str().or(v["detail"].as_str()).map(str::to_string).unwrap_or_else(|| v.to_string());
        bail!("node rejected transaction (HTTP {status}): {err}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_kaspa_rest_utxos() {
        // Shape returned by api-tn10.kaspa.org (no script version field, amounts as strings).
        let body = r#"[{"address":"kaspatest:qpqz2vxj23kvh0m73ta2jjn2u4cv4tlufqns2eap8mxyyt0rvrxy6ejkful67",
            "outpoint":{"transactionId":"23bd1658e1b0fdbe6c2193b1331a0e364f35e6fb26806e865e75bb7e4356d221","index":0},
            "utxoEntry":{"amount":"1000000000","scriptPublicKey":{"scriptPublicKey":"20402530d2546ccbbf7e8afaa94a6ae570caaffc48270567a13ecc422de360cc4dac"},
            "blockDaaScore":"307038561","isCoinbase":false}}]"#;
        let u = parse_utxos(body).unwrap();
        assert_eq!(u.len(), 1);
        assert_eq!(u[0].entry.amount, 1_000_000_000);
        assert_eq!(u[0].entry.block_daa_score, 307_038_561);
        assert_eq!(u[0].entry.script_public_key.version, 0);
    }

    #[test]
    fn parses_numeric_amounts_and_versions() {
        let body = r#"[{"outpoint":{"transactionId":"aa","index":3},
            "utxoEntry":{"amount":5,"scriptPublicKey":{"version":0,"scriptPublicKey":"ab"},"blockDaaScore":7}}]"#;
        let u = parse_utxos(body).unwrap();
        assert_eq!((u[0].entry.amount, u[0].outpoint.index, u[0].entry.is_coinbase), (5, 3, false));
    }
}
