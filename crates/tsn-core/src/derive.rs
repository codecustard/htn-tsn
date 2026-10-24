//! ICP-style key derivation: one master key from DKG, unlimited child keys addressed by a path.
//!
//! child_secret = master_secret + t,  child_pub = master_pub + t·G,
//! t = H("HTN-TSN/derive/v1", master_pub || path).
//!
//! Every node adds the same public `t` to its share. Because Lagrange coefficients sum to 1 for any
//! signing subset, the shares still interpolate to child_secret — no new DKG per key, and no
//! party ever holds the child key. This is non-hardened derivation: anyone with the master public
//! key can compute every child public key (needed so clients can derive addresses offline).

use crate::frost::{
    keys::{KeyPackage, PublicKeyPackage, SigningShare, VerifyingShare},
    VerifyingKey,
};
use anyhow::{anyhow, Result};
use k256::{elliptic_curve::ops::Reduce, ProjectivePoint, Scalar, U256};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;

const TAG: &[u8] = b"HTN-TSN/derive/v1";

/// Derivation tweak for `path` under `master`.
pub fn tweak(master: &VerifyingKey, path: &str) -> Result<Scalar> {
    let tag = Sha256::digest(TAG);
    let mut h = Sha256::new();
    h.update(tag);
    h.update(tag);
    h.update(master.serialize().map_err(|e| anyhow!("{e}"))?);
    h.update((path.len() as u32).to_le_bytes());
    h.update(path.as_bytes());
    let bytes: [u8; 32] = h.finalize().into();
    Ok(<Scalar as Reduce<U256>>::reduce_bytes(&bytes.into()))
}

/// A node's share of the child key at `path`.
pub fn key_package(kp: &KeyPackage, path: &str) -> Result<KeyPackage> {
    let t = tweak(kp.verifying_key(), path)?;
    let tp = ProjectivePoint::GENERATOR * t;
    Ok(KeyPackage::new(
        *kp.identifier(),
        SigningShare::new(kp.signing_share().to_scalar() + t),
        VerifyingShare::new(kp.verifying_share().to_element() + tp),
        VerifyingKey::new(kp.verifying_key().to_element() + tp),
        *kp.min_signers(),
    ))
}

/// The public package of the child key at `path` (used by the coordinator to aggregate/verify).
pub fn public_key_package(pkp: &PublicKeyPackage, path: &str) -> Result<PublicKeyPackage> {
    let t = tweak(pkp.verifying_key(), path)?;
    let tp = ProjectivePoint::GENERATOR * t;
    let shares: BTreeMap<_, _> = pkp
        .verifying_shares()
        .iter()
        .map(|(id, vs)| (*id, VerifyingShare::new(vs.to_element() + tp)))
        .collect();
    Ok(PublicKeyPackage::new(shares, VerifyingKey::new(pkp.verifying_key().to_element() + tp), pkp.min_signers()))
}

/// BIP340 x-only public key (what Kaspa/Hoosat P2PK addresses commit to).
pub fn xonly(vk: &VerifyingKey) -> Result<[u8; 32]> {
    let sec1 = vk.serialize().map_err(|e| anyhow!("{e}"))?;
    sec1[1..33].try_into().map_err(|_| anyhow!("unexpected key encoding"))
}

/// Child x-only key at `path`, computed from public data only.
pub fn child_xonly(master: &VerifyingKey, path: &str) -> Result<[u8; 32]> {
    let t = tweak(master, path)?;
    xonly(&VerifyingKey::new(master.to_element() + ProjectivePoint::GENERATOR * t))
}
