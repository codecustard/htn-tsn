//! Turning "send AMOUNT from OWNER/NAME to ADDRESS" into an unsigned transaction.

use crate::{
    chain_api::{self, ChainApi},
    spent::RecentSpends,
};
use anyhow::{bail, Result};
use ed25519_dalek::VerifyingKey as OwnerKey;
use serde::Serialize;
use tsn_core::{
    address, auth,
    build::{self, Amount},
    chain::{self, Network, Tx, TxInput},
    derive,
    frost::VerifyingKey,
};

/// HTND relays a spend only once its inputs are this many DAA old.
pub const HOOSAT_MIN_INPUT_AGE_DAA: u64 = 1000;

pub struct Request {
    pub network: Network,
    /// Key path: `owner/<pubkey>/<name>` or `policy/<id>/<name>`.
    pub path: String,
    pub to: String,
    pub amount: Amount,
    /// Sompi per gram; `None` = the API's estimate, else the chain's minimum.
    pub feerate: Option<f64>,
    pub max_fee: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct Prepared {
    pub path: String,
    pub from: String,
    pub tx: Tx,
    #[serde(with = "chain::u64_string")]
    pub fee: u64,
    #[serde(with = "chain::u64_string")]
    pub mass: u64,
    #[serde(with = "chain::u64_string")]
    pub change: u64,
    pub feerate: f64,
    /// UTXOs left out because they are too new to spend (Hoosat).
    pub skipped_young_utxos: usize,
    /// UTXOs left out because a recent payment from this coordinator already spent them.
    pub skipped_spent_utxos: usize,
}

/// Checks a key path: `owner/<ed25519 hex>/<name>` or `policy/<id>/<name>`.
pub fn validate_path(path: &str) -> Result<()> {
    if path.starts_with("policy/") {
        tsn_core::policy::parse_path(path).map(|_| ())
    } else {
        auth::path_owner(path).map(|_| ())
    }
}

/// Address and P2PK script of the key at `path` under `master`, computed offline.
pub fn path_address(master: &VerifyingKey, network: Network, path: &str) -> Result<(String, Vec<u8>)> {
    validate_path(path)?;
    let xonly = derive::child_xonly(master, path)?;
    Ok((address::encode(network.prefix(), address::VERSION_PUBKEY, &xonly), chain::p2pk_script(&xonly)))
}

/// Address and P2PK script of `owner/name` under `master`, computed offline.
pub fn key_address(
    master: &VerifyingKey,
    network: Network,
    owner: &OwnerKey,
    name: &str,
) -> Result<(String, String, Vec<u8>)> {
    let path = auth::owner_path(owner, name);
    let (addr, script) = path_address(master, network, &path)?;
    Ok((path, addr, script))
}

/// Fetches the key's UTXOs, selects coins, prices the fee and returns the unsigned transaction.
pub async fn prepare(api: &ChainApi, master: &VerifyingKey, req: &Request, spent: &RecentSpends) -> Result<Prepared> {
    let path = req.path.clone();
    let (from, own_script) = path_address(master, req.network, &path)?;
    let mut utxos = api.utxos(&from).await?;
    utxos.retain(|u| {
        u.entry.script_public_key.version == 0
            && hex::decode(&u.entry.script_public_key.script).map(|s| s == own_script).unwrap_or(false)
    });
    let listed = utxos.len();
    utxos.retain(|u| !spent.contains(&u.outpoint.transaction_id, u.outpoint.index));
    let skipped_spent = listed - utxos.len();
    if utxos.is_empty() && skipped_spent > 0 {
        bail!(
            "the {skipped_spent} coin(s) the API lists at {from} were just spent by a recent payment; \
             retry in a few seconds, once the API shows its change"
        );
    }
    let mut skipped = 0;
    if req.network.is_hoosat() {
        if let Some(daa) = api.virtual_daa_score().await {
            let before = utxos.len();
            utxos.retain(|u| u.entry.block_daa_score + HOOSAT_MIN_INPUT_AGE_DAA <= daa);
            skipped = before - utxos.len();
        }
    }
    let inputs: Vec<TxInput> = utxos
        .iter()
        .map(|u| TxInput {
            prev_txid: u.outpoint.transaction_id.clone(),
            index: u.outpoint.index,
            amount: u.entry.amount,
            script_pubkey: u.entry.script_public_key.script.clone(),
            sequence: 0,
            sig_op_count: 1,
            signature_script: String::new(),
        })
        .collect();
    if inputs.is_empty() && skipped > 0 {
        bail!("{skipped} UTXO(s) at {from} are younger than Hoosat's {HOOSAT_MIN_INPUT_AGE_DAA}-DAA minimum input age (about 3 minutes); retry shortly");
    }
    let feerate = match req.feerate {
        Some(f) => f,
        None => api.feerate().await.unwrap_or_else(|| chain_api::fallback_feerate(req.network)),
    };
    let template = Tx { network: req.network, inputs: vec![], outputs: vec![], lock_time: 0 };
    let plan = build::build_payment(&template, inputs, &req.to, req.amount, &from, feerate)?;
    if plan.fee > req.max_fee {
        bail!(
            "fee {} sompi exceeds the maximum {} (fee rate {feerate} sompi/gram, mass {}); raise the maximum or set a fee rate",
            plan.fee,
            req.max_fee,
            plan.mass
        );
    }
    Ok(Prepared {
        path,
        from,
        tx: plan.tx,
        fee: plan.fee,
        mass: plan.mass,
        change: plan.change,
        feerate,
        skipped_young_utxos: skipped,
        skipped_spent_utxos: skipped_spent,
    })
}

/// Fee implied by a transaction: inputs minus outputs.
pub fn implied_fee(tx: &Tx) -> Result<u64> {
    let ins: u64 = tx.inputs.iter().map(|i| i.amount).sum();
    let outs: u64 = tx.outputs.iter().map(|o| o.amount).sum();
    match ins.checked_sub(outs) {
        Some(f) => Ok(f),
        None => bail!("outputs exceed inputs"),
    }
}
