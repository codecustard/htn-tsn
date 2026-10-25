//! Owner-bound keys: each derived key belongs to the identity named in its path.
//!
//! A derivation path of the form `owner/<ed25519 pubkey hex>/<name>` belongs to that owner.
//! Nodes contribute a signature share only when the request is signed by the owner key embedded
//! in the path. Phase 3 replaces owner keys with programmable policy modules (see design doc).

use anyhow::{anyhow, bail, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use sha2::{Digest, Sha256};

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

/// Digest the owner signs: binds key, path, session and the exact transaction.
pub fn request_digest(key_id: &str, path: &str, session_id: &str, tx_json: &str, input_index: usize) -> [u8; 32] {
    let mut h = Sha256::new();
    for part in [b"HTN-TSN/sign-request/v1".as_slice(), key_id.as_bytes(), path.as_bytes(), session_id.as_bytes(), tx_json.as_bytes()] {
        h.update((part.len() as u64).to_le_bytes());
        h.update(part);
    }
    h.update((input_index as u64).to_le_bytes());
    h.finalize().into()
}

pub fn sign_request(owner: &SigningKey, digest: &[u8; 32]) -> String {
    hex::encode(owner.sign(digest).to_bytes())
}

pub fn verify_request(path: &str, digest: &[u8; 32], sig_hex: &str) -> Result<()> {
    let owner = path_owner(path)?;
    let sig: [u8; 64] = hex::decode(sig_hex)?.try_into().map_err(|_| anyhow!("signature must be 64 bytes"))?;
    owner.verify(digest, &Signature::from_bytes(&sig)).map_err(|_| anyhow!("owner signature invalid for {path}"))
}
