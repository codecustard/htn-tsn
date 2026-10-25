//! Transaction model shared by Kaspa and Hoosat, plus per-chain sighash and verification.
//!
//! Both chains sign the same fields in the same order and verify BIP340 Schnorr signatures.
//! The only difference that matters for signing is the hash: Kaspa uses BLAKE2b keyed with
//! "TransactionSigningHash"; Hoosat uses BLAKE3 keyed with the same string zero-padded to 32 bytes.
//! The prototype supports native-subnetwork, version-0 transactions with SIGHASH_ALL.

use crate::address::{self, VERSION_PUBKEY, VERSION_PUBKEY_ECDSA};
use anyhow::{anyhow, bail, ensure, Context, Result};
use serde::{Deserialize, Serialize};

pub const SIGHASH_ALL: u8 = 0x01;
const OP_DATA_32: u8 = 0x20;
const OP_DATA_33: u8 = 0x21;
const OP_DATA_65: u8 = 0x41;
const OP_CHECKSIG: u8 = 0xac;
const OP_CHECKSIG_ECDSA: u8 = 0xab;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Network {
    KaspaMainnet,
    KaspaTestnet,
    HoosatMainnet,
    HoosatTestnet,
}

impl Network {
    pub fn prefix(self) -> &'static str {
        match self {
            Network::KaspaMainnet => "kaspa",
            Network::KaspaTestnet => "kaspatest",
            Network::HoosatMainnet => "hoosat",
            Network::HoosatTestnet => "hoosattest",
        }
    }
    pub fn is_hoosat(self) -> bool {
        matches!(self, Network::HoosatMainnet | Network::HoosatTestnet)
    }
    pub fn parse(s: &str) -> Result<Self> {
        serde_json::from_value(serde_json::Value::String(s.to_string())).map_err(|_| {
            anyhow!("unknown network {s}; use kaspa-mainnet, kaspa-testnet, hoosat-mainnet, hoosat-testnet")
        })
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TxInput {
    /// Previous transaction id, hex (raw byte order).
    pub prev_txid: String,
    pub index: u32,
    /// Amount of the UTXO being spent, in sompi.
    #[serde(with = "u64_string")]
    pub amount: u64,
    /// Script public key of the UTXO being spent, hex.
    pub script_pubkey: String,
    #[serde(with = "u64_string")]
    pub sequence: u64,
    pub sig_op_count: u8,
    /// Filled in after signing.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub signature_script: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct TxOutput {
    pub address: String,
    #[serde(with = "u64_string")]
    pub amount: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Tx {
    pub network: Network,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    #[serde(with = "u64_string")]
    pub lock_time: u64,
}

/// 64-bit values travel as decimal strings: JSON numbers above 2^53 lose precision in JavaScript,
/// and a wrong amount would mean a wrong signature. Plain numbers are still accepted on input.
pub mod u64_string {
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&v.to_string())
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
        match serde_json::Value::deserialize(d)? {
            serde_json::Value::String(s) => s.parse().map_err(D::Error::custom),
            serde_json::Value::Number(n) => n.as_u64().ok_or_else(|| D::Error::custom("not a u64")),
            other => Err(D::Error::custom(format!("expected u64, got {other}"))),
        }
    }
}

/// `OP_DATA_32 <x-only key> OP_CHECKSIG` — standard Schnorr pay-to-pubkey.
pub fn p2pk_script(xonly: &[u8; 32]) -> Vec<u8> {
    let mut s = Vec::with_capacity(34);
    s.push(OP_DATA_32);
    s.extend_from_slice(xonly);
    s.push(OP_CHECKSIG);
    s
}

/// Script public key (version 0) for an address on `network`.
pub fn script_for_address(network: Network, addr: &str) -> Result<Vec<u8>> {
    let (prefix, version, data) = address::decode(addr)?;
    ensure!(prefix == network.prefix(), "address {addr} is not a {} address", network.prefix());
    match version {
        VERSION_PUBKEY if data.len() == 32 => Ok(p2pk_script(data.as_slice().try_into()?)),
        VERSION_PUBKEY_ECDSA if data.len() == 33 => {
            let mut s = vec![OP_DATA_33];
            s.extend_from_slice(&data);
            s.push(OP_CHECKSIG_ECDSA);
            Ok(s)
        }
        _ => bail!("prototype supports only pay-to-pubkey addresses (got version {version})"),
    }
}

/// Signature script: `OP_DATA_65 <64-byte sig || sighash type>`.
pub fn signature_script(sig64: &[u8; 64]) -> Vec<u8> {
    let mut s = Vec::with_capacity(66);
    s.push(OP_DATA_65);
    s.extend_from_slice(sig64);
    s.push(SIGHASH_ALL);
    s
}

fn txid_bytes(hex_id: &str) -> Result<[u8; 32]> {
    hex::decode(hex_id)?.try_into().map_err(|_| anyhow!("txid must be 32 bytes"))
}

/// Sighash for input `idx` (SIGHASH_ALL).
pub fn sighash(tx: &Tx, idx: usize) -> Result<[u8; 32]> {
    ensure!(idx < tx.inputs.len(), "input index out of range");
    if tx.network.is_hoosat() {
        hoosat::sighash(tx, idx)
    } else {
        kaspa::sighash(tx, idx)
    }
}

/// Mempools on both chains reject transactions heavier than this.
pub const MAX_STANDARD_MASS: u64 = 100_000;

/// Length of a P2PK Schnorr signature script (OP_DATA_65 + 64-byte sig + sighash type).
const SIG_SCRIPT_LEN: usize = 66;

/// Mass the mempool will charge for `tx` once signed (unsigned inputs are sized as if signed).
/// Kaspa: max(compute, transient, storage) mass from rusty-kaspa's own calculator (KIP-9 included).
/// Hoosat: HTND's v0 formula: size·1 + script-pubkey bytes·10 + sigops·1000.
pub fn estimate_mass(tx: &Tx) -> Result<u64> {
    if tx.network.is_hoosat() {
        hoosat::mass(tx)
    } else {
        kaspa::mass(tx)
    }
}

/// Total sent to scripts other than `own_script` (i.e. excluding change).
pub fn external_spend(tx: &Tx, own_script: &[u8]) -> Result<u64> {
    let mut total = 0u64;
    for o in &tx.outputs {
        if script_for_address(tx.network, &o.address)? != own_script {
            total = total.checked_add(o.amount).ok_or_else(|| anyhow!("overflow"))?;
        }
    }
    Ok(total)
}

/// Full verification of a signed transaction.
/// Kaspa: runs every input through the real Kaspa consensus script engine (rusty-kaspa).
/// Hoosat: recomputes the BLAKE3 sighash and checks BIP340 against the P2PK key
/// (cross-checked against HTND's own engine by tools/hoosat-verify).
pub fn verify_signed(tx: &Tx) -> Result<()> {
    ensure!(tx.inputs.iter().all(|i| !i.signature_script.is_empty()), "unsigned input");
    let out_sum: u64 = tx.outputs.iter().map(|o| o.amount).sum();
    let in_sum: u64 = tx.inputs.iter().map(|i| i.amount).sum();
    ensure!(out_sum <= in_sum, "outputs exceed inputs");
    if tx.network.is_hoosat() {
        hoosat::verify(tx)
    } else {
        kaspa::verify(tx)
    }
}

mod kaspa {
    use super::*;
    use kaspa_consensus_core::{
        hashing::{
            sighash::{calc_schnorr_signature_hash, SigHashReusedValuesUnsync},
            sighash_type::SIG_HASH_ALL,
        },
        subnets::SUBNETWORK_ID_NATIVE,
        tx::{
            PopulatedTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint,
            TransactionOutput, UtxoEntry,
        },
    };

    fn build(tx: &Tx) -> Result<(Transaction, Vec<UtxoEntry>)> {
        build_with(tx, false)
    }

    /// `size_as_signed`: give unsigned inputs a placeholder signature script of the final length.
    fn build_with(tx: &Tx, size_as_signed: bool) -> Result<(Transaction, Vec<UtxoEntry>)> {
        let mut inputs = Vec::new();
        let mut entries = Vec::new();
        for i in &tx.inputs {
            let outpoint = TransactionOutpoint::new(TransactionId::from_bytes(txid_bytes(&i.prev_txid)?), i.index);
            let sig_script = match (i.signature_script.is_empty(), size_as_signed) {
                (false, _) => hex::decode(&i.signature_script)?,
                (true, true) => vec![0u8; SIG_SCRIPT_LEN],
                (true, false) => vec![],
            };
            inputs.push(TransactionInput::new(outpoint, sig_script, i.sequence, i.sig_op_count));
            let spk = ScriptPublicKey::new(0, hex::decode(&i.script_pubkey)?.into());
            entries.push(UtxoEntry::new(i.amount, spk, 0, false, None));
        }
        let mut outputs = Vec::new();
        for o in &tx.outputs {
            let spk = ScriptPublicKey::new(0, script_for_address(tx.network, &o.address)?.into());
            outputs.push(TransactionOutput::new(o.amount, spk));
        }
        Ok((Transaction::new(0, inputs, outputs, tx.lock_time, SUBNETWORK_ID_NATIVE, 0, vec![]), entries))
    }

    pub fn mass(tx: &Tx) -> Result<u64> {
        use kaspa_consensus_core::{config::params::MAINNET_PARAMS, mass::MassCalculator};
        ensure!(tx.outputs.iter().all(|o| o.amount > 0), "zero-value output");
        let (ktx, entries) = build_with(tx, true)?;
        let calc = MassCalculator::new_with_consensus_params(&MAINNET_PARAMS);
        let nc = calc.calc_non_contextual_masses(&ktx);
        let storage = calc
            .calc_contextual_masses(&PopulatedTransaction::new(&ktx, entries))
            .map(|c| c.storage_mass)
            .unwrap_or(u64::MAX);
        Ok(nc.compute_mass.max(nc.transient_mass).max(storage))
    }

    pub fn sighash(tx: &Tx, idx: usize) -> Result<[u8; 32]> {
        let (ktx, entries) = build(tx)?;
        let ptx = PopulatedTransaction::new(&ktx, entries);
        let reused = SigHashReusedValuesUnsync::new();
        Ok(calc_schnorr_signature_hash(&ptx, idx, SIG_HASH_ALL, &reused).as_bytes())
    }

    pub fn verify(tx: &Tx) -> Result<()> {
        use kaspa_txscript::{caches::Cache, EngineCtx, TxScriptEngine};
        let (ktx, entries) = build(tx)?;
        let ptx = PopulatedTransaction::new(&ktx, entries.clone());
        let cache = Cache::new(1_000);
        let reused = SigHashReusedValuesUnsync::new();
        for (idx, (input, entry)) in ktx.inputs.iter().zip(entries.iter()).enumerate() {
            let mut vm = TxScriptEngine::from_transaction_input(
                &ptx,
                input,
                idx,
                entry,
                EngineCtx::new(&cache).with_reused(&reused),
                Default::default(),
            );
            vm.execute().map_err(|e| anyhow!("Kaspa script engine rejected input {idx}: {e}"))?;
        }
        Ok(())
    }
}

mod hoosat {
    use super::*;
    use k256::schnorr::{Signature, VerifyingKey};

    fn hasher() -> blake3::Hasher {
        let mut key = [0u8; 32];
        let domain = b"TransactionSigningHash";
        key[..domain.len()].copy_from_slice(domain);
        blake3::Hasher::new_keyed(&key)
    }

    fn var_bytes(h: &mut blake3::Hasher, b: &[u8]) {
        h.update(&(b.len() as u64).to_le_bytes());
        h.update(b);
    }

    pub fn sighash(tx: &Tx, idx: usize) -> Result<[u8; 32]> {
        let mut prev = hasher();
        let mut seqs = hasher();
        let mut sigops = hasher();
        for i in &tx.inputs {
            prev.update(&txid_bytes(&i.prev_txid)?);
            prev.update(&i.index.to_le_bytes());
            seqs.update(&i.sequence.to_le_bytes());
            sigops.update(&[i.sig_op_count]);
        }
        let mut outs = hasher();
        for o in &tx.outputs {
            outs.update(&o.amount.to_le_bytes());
            outs.update(&0u16.to_le_bytes());
            var_bytes(&mut outs, &script_for_address(tx.network, &o.address)?);
        }
        let input = &tx.inputs[idx];
        let mut h = hasher();
        h.update(&0u16.to_le_bytes()); // tx version
        h.update(prev.finalize().as_bytes());
        h.update(seqs.finalize().as_bytes());
        h.update(sigops.finalize().as_bytes());
        h.update(&txid_bytes(&input.prev_txid)?);
        h.update(&input.index.to_le_bytes());
        h.update(&0u16.to_le_bytes()); // prev script version
        var_bytes(&mut h, &hex::decode(&input.script_pubkey)?);
        h.update(&input.amount.to_le_bytes());
        h.update(&input.sequence.to_le_bytes());
        h.update(&[input.sig_op_count]);
        h.update(outs.finalize().as_bytes());
        h.update(&tx.lock_time.to_le_bytes());
        h.update(&[0u8; 20]); // native subnetwork id
        h.update(&0u64.to_le_bytes()); // gas
        h.update(&[0u8; 32]); // payload hash (native subnetwork)
        h.update(&[SIGHASH_ALL]);
        Ok(*h.finalize().as_bytes())
    }

    /// Mirrors HTND util/txmass for version-0 transactions with an empty payload.
    pub fn mass(tx: &Tx) -> Result<u64> {
        let mut size: u64 = 2 + 8; // version, input count
        for i in &tx.inputs {
            let sig_len = if i.signature_script.is_empty() { SIG_SCRIPT_LEN } else { i.signature_script.len() / 2 };
            size += 32 + 4 + 8 + sig_len as u64 + 8; // outpoint, script length, script, sequence
        }
        size += 8; // output count
        let mut spk_bytes = 0u64;
        for o in &tx.outputs {
            let script_len = script_for_address(tx.network, &o.address)?.len() as u64;
            size += 8 + 2 + 8 + script_len; // value, script version, script length, script
            spk_bytes += 2 + script_len;
        }
        size += 8 + 20 + 8 + 32 + 8; // lock time, subnetwork, gas, payload hash, payload length
        let sigops: u64 = tx.inputs.iter().map(|i| i.sig_op_count as u64).sum();
        Ok(size + spk_bytes * 10 + sigops * 1000)
    }

    pub fn verify(tx: &Tx) -> Result<()> {
        for (idx, input) in tx.inputs.iter().enumerate() {
            let spk = hex::decode(&input.script_pubkey)?;
            ensure!(spk.len() == 34 && spk[0] == OP_DATA_32 && spk[33] == OP_CHECKSIG, "input {idx}: not P2PK Schnorr");
            let ss = hex::decode(&input.signature_script)?;
            ensure!(
                ss.len() == 66 && ss[0] == OP_DATA_65 && ss[65] == SIGHASH_ALL,
                "input {idx}: bad signature script"
            );
            let vk = VerifyingKey::from_bytes(&spk[1..33]).context("bad x-only key")?;
            let sig = Signature::try_from(&ss[1..65]).context("bad signature encoding")?;
            vk.verify_raw(&sighash(tx, idx)?, &sig).map_err(|_| anyhow!("input {idx}: BIP340 verification failed"))?;
        }
        Ok(())
    }
}
