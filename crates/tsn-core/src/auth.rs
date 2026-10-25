//! Owner-bound keys: each derived key belongs to the identity named in its path.
//!
//! A derivation path of the form `owner/<ed25519 pubkey hex>/<name>` belongs to that owner.
//! Nodes contribute a signature share only when the request carries the owner's signature over
//! [`request_digest`]. Phase 3 replaces owner keys with programmable policy modules (see design doc).
//!
//! One owner signature authorizes one transaction, for every input and every retry, until it
//! expires. It binds the key, the path, a random request id, the expiry and the exact
//! transaction (every input and output), so it can't be reused for anything else. Replaying it
//! can only produce more signatures over the same transaction, which spends the same UTXOs.

use crate::{
    chain::Tx,
    policy::{self, Approval, Policy},
};
use anyhow::{anyhow, bail, ensure, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::RngCore;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Longest validity a node accepts for an authorization.
pub const MAX_REQUEST_TTL_SECS: u64 = 3600;
const DOMAIN: &[u8] = b"HTN-TSN/sign-request/v2";

/// Approval of one transaction, sent with every signing request.
///
/// For `owner/...` keys: `owner_sig` is the owner's signature over [`request_digest`].
/// For `policy/...` keys: `policy` is the full policy document and `approvals` holds one
/// signature over the same digest from each approving signer.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Authorization {
    /// 16 random bytes, lowercase hex.
    pub request_id: String,
    /// Unix time (seconds) after which nodes refuse it.
    pub expires_at: u64,
    /// Owner's ed25519 signature over [`request_digest`], hex (owner keys).
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub owner_sig: String,
    /// Signer approvals (policy keys).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub approvals: Vec<Approval>,
    /// The policy document whose id is in the path (policy keys).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub policy: Option<Policy>,
}

pub fn owner_path(owner: &VerifyingKey, name: &str) -> String {
    format!("owner/{}/{}", hex::encode(owner.as_bytes()), name)
}

/// Extracts the owner key from an `owner/<hex>/<name>` path.
pub fn path_owner(path: &str) -> Result<VerifyingKey> {
    let mut parts = path.splitn(3, '/');
    match (parts.next(), parts.next(), parts.next()) {
        (Some("owner"), Some(hex_pk), Some(name)) if !name.is_empty() => {
            let bytes: [u8; 32] = hex::decode(hex_pk)?.try_into().map_err(|_| anyhow!("owner key must be 32 bytes"))?;
            Ok(VerifyingKey::from_bytes(&bytes)?)
        }
        _ => bail!("path must look like owner/<ed25519-pubkey-hex>/<name>"),
    }
}

pub fn new_request_id() -> String {
    let mut b = [0u8; 16];
    rand::thread_rng().fill_bytes(&mut b);
    hex::encode(b)
}

pub fn now_secs() -> u64 {
    std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn lp(h: &mut Sha256, b: &[u8]) {
    h.update((b.len() as u64).to_le_bytes());
    h.update(b);
}

/// SHA-256 over a fixed binary encoding (all integers little-endian, `lp` = u64 length prefix):
///
/// ```text
/// lp(DOMAIN) lp(key_id) lp(path) lp(request_id) u64(expires_at) lp(network prefix)
/// u64(#inputs)  { txid[32] u32(index) u64(amount) lp(script) u64(sequence) u8(sig_op_count) }
/// u64(#outputs) { lp(address utf-8) u64(amount) }
/// u64(lock_time)
/// ```
///
/// Signature scripts are excluded, so the digest is the same before and after signing.
/// The TypeScript SDK implements the same encoding (sdk/ts/src/digest.ts, shared vectors).
pub fn request_digest(key_id: &str, path: &str, request_id: &str, expires_at: u64, tx: &Tx) -> Result<[u8; 32]> {
    validate_request_id(request_id)?;
    let mut h = Sha256::new();
    lp(&mut h, DOMAIN);
    lp(&mut h, key_id.as_bytes());
    lp(&mut h, path.as_bytes());
    lp(&mut h, request_id.as_bytes());
    h.update(expires_at.to_le_bytes());
    lp(&mut h, tx.network.prefix().as_bytes());
    h.update((tx.inputs.len() as u64).to_le_bytes());
    for i in &tx.inputs {
        let txid: [u8; 32] = hex::decode(&i.prev_txid)?.try_into().map_err(|_| anyhow!("txid must be 32 bytes"))?;
        h.update(txid);
        h.update(i.index.to_le_bytes());
        h.update(i.amount.to_le_bytes());
        lp(&mut h, &hex::decode(&i.script_pubkey)?);
        h.update(i.sequence.to_le_bytes());
        h.update([i.sig_op_count]);
    }
    h.update((tx.outputs.len() as u64).to_le_bytes());
    for o in &tx.outputs {
        lp(&mut h, o.address.as_bytes());
        h.update(o.amount.to_le_bytes());
    }
    h.update(tx.lock_time.to_le_bytes());
    Ok(h.finalize().into())
}

pub fn validate_request_id(id: &str) -> Result<()> {
    ensure!(
        id.len() == 32 && id.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c)),
        "request_id must be 16 bytes of lowercase hex"
    );
    Ok(())
}

/// Builds an owner-key authorization valid for `ttl_secs`.
pub fn authorize(owner: &SigningKey, key_id: &str, path: &str, tx: &Tx, ttl_secs: u64) -> Result<Authorization> {
    let request_id = new_request_id();
    let expires_at = now_secs() + ttl_secs.min(MAX_REQUEST_TTL_SECS);
    let digest = request_digest(key_id, path, &request_id, expires_at, tx)?;
    Ok(Authorization {
        request_id,
        expires_at,
        owner_sig: hex::encode(owner.sign(&digest).to_bytes()),
        approvals: vec![],
        policy: None,
    })
}

/// Builds a policy-key authorization with approvals from `signers`, valid for `ttl_secs`.
pub fn authorize_policy(
    signers: &[SigningKey],
    key_id: &str,
    path: &str,
    policy: &Policy,
    tx: &Tx,
    ttl_secs: u64,
) -> Result<Authorization> {
    let request_id = new_request_id();
    let expires_at = now_secs() + ttl_secs.min(MAX_REQUEST_TTL_SECS);
    let digest = request_digest(key_id, path, &request_id, expires_at, tx)?;
    let approvals = signers
        .iter()
        .map(|k| Approval::ed25519(policy::ed25519_signer(&k.verifying_key()), hex::encode(k.sign(&digest).to_bytes())))
        .collect();
    Ok(Authorization { request_id, expires_at, owner_sig: String::new(), approvals, policy: Some(policy.clone()) })
}

/// Node-side check: well-formed, unexpired, not valid for too long, and approved as the key's
/// path requires (its owner for `owner/...`, a passing clause for `policy/...`).
/// `own_script` is the P2PK script of the key at `path`.
pub fn verify(key_id: &str, path: &str, tx: &Tx, auth: &Authorization, own_script: &[u8], now: u64) -> Result<()> {
    ensure!(auth.expires_at >= now, "authorization expired");
    ensure!(auth.expires_at <= now + MAX_REQUEST_TTL_SECS + 60, "authorization valid for too long");
    let digest = request_digest(key_id, path, &auth.request_id, auth.expires_at, tx)?;
    if path.starts_with("policy/") {
        let (id, _) = policy::parse_path(path)?;
        let p = auth.policy.as_ref().ok_or_else(|| anyhow!("policy key: request must include the policy"))?;
        p.validate()?;
        ensure!(p.id() == id, "policy does not match the key's path");
        ensure!(auth.owner_sig.is_empty(), "policy keys take approvals, not an owner signature");
        p.evaluate(tx, own_script, &auth.approvals, &digest, now)?;
        return Ok(());
    }
    ensure!(auth.approvals.is_empty() && auth.policy.is_none(), "owner keys take an owner signature only");
    let owner = path_owner(path)?;
    let sig: [u8; 64] =
        hex::decode(&auth.owner_sig)?.try_into().map_err(|_| anyhow!("owner signature must be 64 bytes"))?;
    owner.verify(&digest, &Signature::from_bytes(&sig)).map_err(|_| anyhow!("owner signature invalid for {path}"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chain::{Network, TxInput, TxOutput};

    pub(crate) fn sample_tx() -> Tx {
        Tx {
            network: Network::KaspaTestnet,
            inputs: vec![TxInput {
                prev_txid: "11".repeat(32),
                index: 1,
                amount: 5_000_000_000,
                script_pubkey: format!("20{}ac", "22".repeat(32)),
                sequence: 0,
                sig_op_count: 1,
                signature_script: String::new(),
            }],
            outputs: vec![TxOutput {
                address: "kaspatest:qpqz2vxj23kvh0m73ta2jjn2u4cv4tlufqns2eap8mxyyt0rvrxy6ejkful67".into(),
                amount: 1_000_000_000,
            }],
            lock_time: 0,
        }
    }

    #[test]
    fn authorization_round_trip_and_binding() {
        let owner = SigningKey::from_bytes(&[7u8; 32]);
        let path = owner_path(&owner.verifying_key(), "main");
        let tx = sample_tx();
        let a = authorize(&owner, "master", &path, &tx, 600).unwrap();
        let now = now_secs();
        verify("master", &path, &tx, &a, &[], now).unwrap();
        // Signature scripts don't affect the digest.
        let mut signed = tx.clone();
        signed.inputs[0].signature_script = "41".into();
        verify("master", &path, &signed, &a, &[], now).unwrap();
        // Anything else does.
        let mut other = tx.clone();
        other.outputs[0].amount += 1;
        assert!(verify("master", &path, &other, &a, &[], now).is_err());
        assert!(verify("other-key", &path, &tx, &a, &[], now).is_err());
        assert!(verify("master", &path, &tx, &a, &[], a.expires_at + 1).is_err());
        let mallory = SigningKey::from_bytes(&[9u8; 32]);
        let forged = authorize(&mallory, "master", &path, &tx, 600).unwrap();
        assert!(verify("master", &path, &tx, &forged, &[], now).is_err());
    }
}
