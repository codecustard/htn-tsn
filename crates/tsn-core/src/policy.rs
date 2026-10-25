//! Policy keys: keys controlled by published rules instead of a single owner.
//!
//! A policy key's path is `policy/<policy id>/<name>`, where the id is a hash of the policy
//! document. The address derives from the path, so the rules are fixed when the address is
//! created; anyone can check which rules control an address by hashing the published policy.
//!
//! A policy is a list of clauses. A spend is allowed if **any** clause passes. A clause passes
//! when every condition it sets holds:
//!
//! - `signers`: at least `k` of the listed keys approved (signed the request digest);
//! - `after`: the node's clock is at or past this Unix time;
//! - `only_to`: every output pays one of these addresses, or is change back to the key;
//! - `max_per_tx`: the amount sent outside the key is at most this many sompi.
//!
//! Every condition can be checked by a node alone; nothing here needs state shared across
//! nodes. The id covers a canonical JSON encoding (sorted keys, no whitespace), which the
//! TypeScript SDK reproduces byte for byte (testdata/sdk-vectors.json).

use crate::{address, chain::Tx};
use anyhow::{anyhow, bail, ensure, Result};
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;

pub const VERSION: u32 = 1;
const ID_DOMAIN: &[u8] = b"HTN-TSN/policy/v1";
const MAX_CLAUSES: usize = 16;
const MAX_SIGNERS: usize = 16;
const MAX_ADDRESSES: usize = 32;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub version: u32,
    pub clauses: Vec<Clause>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Clause {
    pub signers: Signers,
    /// Unix time (seconds) from which this clause can pass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub after: Option<u64>,
    /// Allowed destinations (change back to the key is always allowed).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub only_to: Option<Vec<String>>,
    /// Most sompi that may leave the key per transaction (decimal string).
    #[serde(default, skip_serializing_if = "Option::is_none", with = "opt_u64_string")]
    pub max_per_tx: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Signers {
    pub k: u32,
    /// Signer ids: `ed25519:<64 hex>` (passkeys will add `p256:`).
    pub of: Vec<String>,
}

/// One signer's approval: an ed25519 signature over the request digest.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Approval {
    pub signer: String,
    pub sig: String,
}

mod opt_u64_string {
    use serde::{Deserialize, Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &Option<u64>, s: S) -> Result<S::Ok, S::Error> {
        match v {
            Some(v) => crate::chain::u64_string::serialize(v, s),
            None => s.serialize_none(),
        }
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<u64>, D::Error> {
        #[derive(Deserialize)]
        struct W(#[serde(with = "crate::chain::u64_string")] u64);
        Ok(Some(W::deserialize(d)?.0))
    }
}

/// `ed25519:<hex>` for an ed25519 public key.
pub fn ed25519_signer(key: &VerifyingKey) -> String {
    format!("ed25519:{}", hex::encode(key.as_bytes()))
}

fn parse_signer(id: &str) -> Result<VerifyingKey> {
    let hex_key = id.strip_prefix("ed25519:").ok_or_else(|| anyhow!("unsupported signer type in {id}"))?;
    ensure!(
        hex_key.len() == 64 && hex_key.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "signer {id} must be ed25519:<64 lowercase hex>"
    );
    let bytes: [u8; 32] = hex::decode(hex_key)?.try_into().map_err(|_| anyhow!("bad signer key"))?;
    Ok(VerifyingKey::from_bytes(&bytes)?)
}

/// Serializes a JSON value with object keys sorted and no whitespace.
pub fn canonical_json(v: &Value) -> String {
    match v {
        Value::Object(map) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.sort();
            let fields: Vec<String> = keys
                .into_iter()
                .map(|k| format!("{}:{}", serde_json::to_string(k).expect("string"), canonical_json(&map[k])))
                .collect();
            format!("{{{}}}", fields.join(","))
        }
        Value::Array(items) => format!("[{}]", items.iter().map(canonical_json).collect::<Vec<_>>().join(",")),
        other => serde_json::to_string(other).expect("scalar"),
    }
}

impl Policy {
    /// Structural checks; a policy that fails them can never control a key.
    pub fn validate(&self) -> Result<()> {
        ensure!(self.version == VERSION, "unsupported policy version {}", self.version);
        ensure!(
            !self.clauses.is_empty() && self.clauses.len() <= MAX_CLAUSES,
            "a policy needs 1..={MAX_CLAUSES} clauses"
        );
        for (i, c) in self.clauses.iter().enumerate() {
            let n = c.signers.of.len();
            ensure!((1..=MAX_SIGNERS).contains(&n), "clause {i}: needs 1..={MAX_SIGNERS} signers");
            ensure!(c.signers.k >= 1 && c.signers.k as usize <= n, "clause {i}: k must be between 1 and {n}");
            let mut seen = BTreeSet::new();
            for s in &c.signers.of {
                parse_signer(s).map_err(|e| anyhow!("clause {i}: {e}"))?;
                ensure!(seen.insert(s), "clause {i}: duplicate signer {s}");
            }
            if let Some(list) = &c.only_to {
                ensure!(
                    (1..=MAX_ADDRESSES).contains(&list.len()),
                    "clause {i}: only_to needs 1..={MAX_ADDRESSES} addresses"
                );
                for a in list {
                    address::decode(a).map_err(|e| anyhow!("clause {i}: bad address {a}: {e}"))?;
                }
            }
            if let Some(m) = c.max_per_tx {
                ensure!(m > 0, "clause {i}: max_per_tx must be positive");
            }
        }
        Ok(())
    }

    pub fn canonical(&self) -> String {
        canonical_json(&serde_json::to_value(self).expect("policy serializes"))
    }

    /// 32-byte id (hex) that goes into the key's path.
    pub fn id(&self) -> String {
        let c = self.canonical();
        let mut h = Sha256::new();
        h.update((ID_DOMAIN.len() as u64).to_le_bytes());
        h.update(ID_DOMAIN);
        h.update((c.len() as u64).to_le_bytes());
        h.update(c.as_bytes());
        hex::encode(h.finalize())
    }

    pub fn path(&self, name: &str) -> Result<String> {
        self.validate()?;
        ensure!(!name.is_empty(), "name must not be empty");
        Ok(format!("policy/{}/{name}", self.id()))
    }

    /// Index of the first clause that allows this spend, or an error saying why each failed.
    pub fn evaluate(
        &self,
        tx: &Tx,
        own_script: &[u8],
        approvals: &[Approval],
        digest: &[u8; 32],
        now: u64,
    ) -> Result<usize> {
        self.validate()?;
        // Signers whose approval verifies; invalid approvals are an error, not silently ignored.
        let mut approved = BTreeSet::new();
        for a in approvals {
            let key = parse_signer(&a.signer)?;
            let sig: [u8; 64] =
                hex::decode(&a.sig)?.try_into().map_err(|_| anyhow!("approval signature must be 64 bytes"))?;
            key.verify(digest, &Signature::from_bytes(&sig))
                .map_err(|_| anyhow!("approval from {} does not verify", a.signer))?;
            approved.insert(a.signer.as_str());
        }
        let external = crate::chain::external_spend(tx, own_script)?;
        let mut reasons = vec![];
        for (i, c) in self.clauses.iter().enumerate() {
            match check_clause(c, tx, own_script, &approved, external, now) {
                Ok(()) => return Ok(i),
                Err(e) => reasons.push(format!("clause {i}: {e}")),
            }
        }
        bail!("policy: no clause allows this spend ({})", reasons.join("; "))
    }
}

fn check_clause(
    c: &Clause,
    tx: &Tx,
    own_script: &[u8],
    approved: &BTreeSet<&str>,
    external: u64,
    now: u64,
) -> Result<()> {
    let have = c.signers.of.iter().filter(|s| approved.contains(s.as_str())).count();
    ensure!(have >= c.signers.k as usize, "{have} of {} required approvals", c.signers.k);
    if let Some(after) = c.after {
        ensure!(now >= after, "locked until {after}");
    }
    if let Some(list) = &c.only_to {
        for o in &tx.outputs {
            let is_change = crate::chain::script_for_address(tx.network, &o.address)? == own_script;
            ensure!(is_change || list.contains(&o.address), "{} is not an allowed destination", o.address);
        }
    }
    if let Some(max) = c.max_per_tx {
        ensure!(external <= max, "sends {external} sompi, limit {max}");
    }
    Ok(())
}

/// Splits `policy/<id>/<name>` into (id, name).
pub fn parse_path(path: &str) -> Result<(&str, &str)> {
    let mut parts = path.splitn(3, '/');
    match (parts.next(), parts.next(), parts.next()) {
        (Some("policy"), Some(id), Some(name))
            if id.len() == 64
                && id.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
                && !name.is_empty() =>
        {
            Ok((id, name))
        }
        _ => bail!("path must look like policy/<64 hex>/<name>"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{self, Network, TxInput, TxOutput};
    use ed25519_dalek::{Signer, SigningKey};

    fn key(b: u8) -> SigningKey {
        SigningKey::from_bytes(&[b; 32])
    }

    fn approve(k: &SigningKey, digest: &[u8; 32]) -> Approval {
        Approval { signer: ed25519_signer(&k.verifying_key()), sig: hex::encode(k.sign(digest).to_bytes()) }
    }

    fn setup() -> (Policy, Tx, Vec<u8>, String, String) {
        let me = [3u8; 32];
        let own = chain::p2pk_script(&me);
        let my_addr = address::encode("kaspatest", 0, &me);
        let exchange = address::encode("kaspatest", 0, &[4u8; 32]);
        let stranger = address::encode("kaspatest", 0, &[5u8; 32]);
        let (server, ops) = (key(1), key(2));
        let policy = Policy {
            version: 1,
            clauses: vec![
                Clause {
                    signers: Signers { k: 1, of: vec![ed25519_signer(&server.verifying_key())] },
                    after: None,
                    only_to: Some(vec![exchange.clone()]),
                    max_per_tx: Some(5_000_000_000),
                },
                Clause {
                    signers: Signers {
                        k: 2,
                        of: vec![ed25519_signer(&server.verifying_key()), ed25519_signer(&ops.verifying_key())],
                    },
                    after: None,
                    only_to: None,
                    max_per_tx: None,
                },
            ],
        };
        let tx = Tx {
            network: Network::KaspaTestnet,
            inputs: vec![TxInput {
                prev_txid: "11".repeat(32),
                index: 0,
                amount: 10_000_000_000,
                script_pubkey: hex::encode(&own),
                sequence: 0,
                sig_op_count: 1,
                signature_script: String::new(),
            }],
            outputs: vec![
                TxOutput { address: exchange.clone(), amount: 1_000_000_000 },
                TxOutput { address: my_addr.clone(), amount: 8_999_990_000 },
            ],
            lock_time: 0,
        };
        (policy, tx, own, exchange, stranger)
    }

    #[test]
    fn protected_hot_wallet() {
        let (policy, tx, own, _exchange, stranger) = setup();
        let d = [9u8; 32];
        let (server, ops, mallory) = (key(1), key(2), key(7));
        // Server alone may pay the exchange.
        assert_eq!(policy.evaluate(&tx, &own, &[approve(&server, &d)], &d, 0).unwrap(), 0);
        // Server alone may not pay a stranger...
        let mut to_stranger = tx.clone();
        to_stranger.outputs[0].address = stranger;
        let err = policy.evaluate(&to_stranger, &own, &[approve(&server, &d)], &d, 0).unwrap_err();
        assert!(err.to_string().contains("not an allowed destination"), "{err}");
        // ...but server + ops may.
        assert_eq!(policy.evaluate(&to_stranger, &own, &[approve(&server, &d), approve(&ops, &d)], &d, 0).unwrap(), 1);
        // Over the cap needs both too.
        let mut big = tx.clone();
        big.outputs[0].amount = 6_000_000_000;
        big.outputs[1].amount = 3_999_990_000;
        assert!(policy.evaluate(&big, &own, &[approve(&server, &d)], &d, 0).is_err());
        // An outsider's approval doesn't count; a bad signature is an error.
        assert!(policy.evaluate(&to_stranger, &own, &[approve(&server, &d), approve(&mallory, &d)], &d, 0).is_err());
        let forged = Approval { signer: ed25519_signer(&ops.verifying_key()), sig: approve(&mallory, &d).sig };
        assert!(policy.evaluate(&to_stranger, &own, &[approve(&server, &d), forged], &d, 0).is_err());
        // Approvals over a different digest don't count.
        let other = [8u8; 32];
        assert!(policy.evaluate(&tx, &own, &[approve(&server, &other)], &d, 0).is_err());
    }

    #[test]
    fn escrow_with_deadline() {
        let (buyer, seller, arbiter) = (key(11), key(12), key(13));
        let s = |k: &SigningKey| ed25519_signer(&k.verifying_key());
        let policy = Policy {
            version: 1,
            clauses: vec![
                Clause {
                    signers: Signers { k: 2, of: vec![s(&buyer), s(&seller), s(&arbiter)] },
                    after: None,
                    only_to: None,
                    max_per_tx: None,
                },
                Clause {
                    signers: Signers { k: 1, of: vec![s(&buyer)] },
                    after: Some(1_000),
                    only_to: None,
                    max_per_tx: None,
                },
            ],
        };
        let (_, tx, own, _, _) = setup();
        let d = [1u8; 32];
        assert!(policy.evaluate(&tx, &own, &[approve(&seller, &d)], &d, 0).is_err());
        assert!(policy.evaluate(&tx, &own, &[approve(&buyer, &d)], &d, 999).is_err());
        assert_eq!(policy.evaluate(&tx, &own, &[approve(&buyer, &d)], &d, 1_000).unwrap(), 1);
        assert_eq!(policy.evaluate(&tx, &own, &[approve(&seller, &d), approve(&arbiter, &d)], &d, 0).unwrap(), 0);
    }

    #[test]
    fn id_is_canonical_and_validation_rejects_bad_policies() {
        let (policy, ..) = setup();
        // Key order in the input doesn't change the id.
        let shuffled: Policy = serde_json::from_str(&format!(
            r#"{{"clauses":{},"version":1}}"#,
            serde_json::to_string(&policy.clauses).unwrap()
        ))
        .unwrap();
        assert_eq!(shuffled.id(), policy.id());
        assert!(policy.canonical().starts_with(r#"{"clauses":[{"max_per_tx":"5000000000","only_to":["#));
        let mut bad = policy.clone();
        bad.clauses[1].signers.k = 3;
        assert!(bad.validate().is_err());
        let mut dup = policy.clone();
        dup.clauses[1].signers.of[1] = dup.clauses[1].signers.of[0].clone();
        assert!(dup.validate().is_err());
        assert!(serde_json::from_str::<Policy>(r#"{"version":1,"clauses":[],"extra":1}"#).is_err());
        assert!(parse_path(&policy.path("vault").unwrap()).is_ok());
    }
}
