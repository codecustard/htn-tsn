//! Wire types and the operator registry.

use crate::frost::{
    self,
    keys::{dkg::round1, PublicKeyPackage},
};
use crate::{auth::Authorization, chain::Tx};
use anyhow::{anyhow, bail, ensure, Context, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::path::Path;

/// The operator set: threshold, nodes and the coordinators they accept. In Phase 1 it is a file
/// signed by the network admin that every node and coordinator holds; in Phase 3 it moves
/// on-chain. Nodes trust peer identities from here, never from the coordinator.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Registry {
    pub threshold: u16,
    pub nodes: Vec<NodeEntry>,
    /// Coordinators (TLS client certificates) the nodes accept. Empty = any client (dev only).
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub coordinators: Vec<CoordinatorEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct NodeEntry {
    pub id: u16,
    /// `https://host:port` (TLS, pinned to `tls_cert_sha256`), or `http://` for local development.
    pub url: String,
    pub x25519_pub: String,
    /// SHA-256 of the node's TLS certificate (DER), hex. Required for https URLs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_cert_sha256: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct CoordinatorEntry {
    pub name: String,
    /// SHA-256 of the coordinator's TLS client certificate (DER), hex.
    pub tls_cert_sha256: String,
}

/// A registry signed by the network admin's ed25519 key.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedRegistry {
    pub registry: Registry,
    /// Admin public key (hex). Nodes pin it with `--admin`.
    pub admin: String,
    /// ed25519 signature over [`Registry::digest`] (hex).
    pub signature: String,
}

const REGISTRY_DOMAIN: &[u8] = b"HTN-TSN/registry/v1";

fn parse_admin(hex_key: &str) -> Result<VerifyingKey> {
    let b: [u8; 32] = hex::decode(hex_key)?.try_into().map_err(|_| anyhow!("admin key must be 32 bytes of hex"))?;
    Ok(VerifyingKey::from_bytes(&b)?)
}

fn valid_fingerprint(f: &str) -> bool {
    f.len() == 64 && f.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

impl Registry {
    /// Reads a registry file, signed or not. A signed file's signature is checked, but nothing
    /// pins who signed it; nodes use [`Registry::load_pinned`].
    pub fn load(path: &Path) -> Result<Self> {
        Ok(Self::load_any(path)?.0)
    }

    /// Reads a registry that must be signed by `admin` (hex ed25519 public key).
    pub fn load_pinned(path: &Path, admin: &str) -> Result<Self> {
        let (r, signer) = Self::load_any(path)?;
        match signer {
            None => bail!("{} is not signed; nodes need a registry signed by the admin", path.display()),
            Some(k) if k == parse_admin(admin)? => Ok(r),
            Some(k) => {
                bail!("{} is signed by {}, not the pinned admin {admin}", path.display(), hex::encode(k.as_bytes()))
            }
        }
    }

    /// `load_pinned` when an admin key is given, else `load`.
    pub fn load_checked(path: &Path, admin: Option<&str>) -> Result<Self> {
        match admin {
            Some(a) => Self::load_pinned(path, a),
            None => Self::load(path),
        }
    }

    fn load_any(path: &Path) -> Result<(Self, Option<VerifyingKey>)> {
        let s = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let v: serde_json::Value = serde_json::from_str(&s).with_context(|| format!("parsing {}", path.display()))?;
        if v.get("signature").is_some() {
            let signed: SignedRegistry = serde_json::from_value(v)?;
            let admin = parse_admin(&signed.admin)?;
            let sig: [u8; 64] = hex::decode(&signed.signature)?
                .try_into()
                .map_err(|_| anyhow!("registry signature must be 64 bytes"))?;
            admin
                .verify(&signed.registry.digest()?, &Signature::from_bytes(&sig))
                .map_err(|_| anyhow!("{}: registry signature is invalid (file altered?)", path.display()))?;
            signed.registry.validate()?;
            Ok((signed.registry, Some(admin)))
        } else {
            let r: Registry = serde_json::from_value(v)?;
            r.validate()?;
            Ok((r, None))
        }
    }

    pub fn validate(&self) -> Result<()> {
        let n = self.nodes.len() as u16;
        ensure!(self.threshold >= 2 && self.threshold <= n, "threshold must be in 2..={n}");
        let mut ids: Vec<u16> = self.nodes.iter().map(|e| e.id).collect();
        ids.sort();
        ids.dedup();
        ensure!(ids.len() == self.nodes.len() && ids.first() != Some(&0), "node ids must be unique and nonzero");
        for e in &self.nodes {
            if e.url.starts_with("https://") {
                ensure!(
                    e.tls_cert_sha256.as_deref().is_some_and(valid_fingerprint),
                    "node {}: https needs tls_cert_sha256",
                    e.id
                );
            } else {
                ensure!(e.url.starts_with("http://"), "node {}: url must be http:// or https://", e.id);
            }
        }
        for c in &self.coordinators {
            ensure!(valid_fingerprint(&c.tls_cert_sha256), "coordinator {}: bad tls_cert_sha256", c.name);
        }
        Ok(())
    }

    /// Hash nodes and coordinators compare to be sure they all use the same registry.
    pub fn digest(&self) -> Result<[u8; 32]> {
        Ok(Sha256::new().chain_update(REGISTRY_DOMAIN).chain_update(serde_json::to_vec(self)?).finalize().into())
    }

    pub fn digest_hex(&self) -> Result<String> {
        Ok(hex::encode(self.digest()?))
    }

    /// Signs this registry with the admin key.
    pub fn sign(&self, admin: &SigningKey) -> Result<SignedRegistry> {
        self.validate()?;
        Ok(SignedRegistry {
            registry: self.clone(),
            admin: hex::encode(admin.verifying_key().as_bytes()),
            signature: hex::encode(admin.sign(&self.digest()?).to_bytes()),
        })
    }

    pub fn n(&self) -> u16 {
        self.nodes.len() as u16
    }
    pub fn node(&self, id: u16) -> Result<&NodeEntry> {
        self.nodes.iter().find(|n| n.id == id).ok_or_else(|| anyhow!("node {id} not in registry"))
    }
    pub fn x25519(&self, id: u16) -> Result<[u8; 32]> {
        hex::decode(&self.node(id)?.x25519_pub)?.try_into().map_err(|_| anyhow!("bad x25519 key for node {id}"))
    }
}

/// What an operator sends the admin to be added to the registry (`identity.pub.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdentity {
    pub id: u16,
    pub x25519_pub: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls_cert_sha256: Option<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InfoResp {
    pub id: u16,
    pub x25519_pub: String,
    pub keys: Vec<String>,
    /// [`Registry::digest`] of the registry this node runs with (hex).
    #[serde(default)]
    pub registry: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DkgPart1Req {
    pub key_id: String,
    /// The coordinator's [`Registry::digest`]; a node refuses DKG under a different registry.
    #[serde(default)]
    pub registry: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct DkgPart1Resp {
    pub package: round1::Package,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DkgPart2Req {
    pub key_id: String,
    /// Round-1 broadcasts from every other node, keyed by node id.
    pub round1_packages: BTreeMap<u16, round1::Package>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct DkgPart2Resp {
    /// Sealed round-2 packages, keyed by recipient node id (hex ciphertext).
    pub sealed: BTreeMap<u16, String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DkgPart3Req {
    pub key_id: String,
    pub round1_packages: BTreeMap<u16, round1::Package>,
    /// Sealed round-2 packages addressed to this node, keyed by sender node id.
    pub sealed_for_me: BTreeMap<u16, String>,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct DkgPart3Resp {
    pub public_key_package: PublicKeyPackage,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct CommitReq {
    pub key_id: String,
    pub session_id: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct CommitResp {
    pub commitments: frost::round1::SigningCommitments,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ShareReq {
    pub key_id: String,
    pub session_id: String,
    pub path: String,
    /// The full transaction, so each node recomputes the sighash and applies policy itself
    /// instead of blindly signing a 32-byte hash.
    pub tx: Tx,
    pub input_index: usize,
    pub signing_package: frost::SigningPackage,
    /// The owner's approval of this transaction (covers every input and retry).
    pub auth: Authorization,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct ShareResp {
    pub share: frost::round2::SignatureShare,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ErrorResp {
    pub error: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn registry() -> Registry {
        Registry {
            threshold: 2,
            nodes: (1..=3)
                .map(|id| NodeEntry {
                    id,
                    url: format!("https://node{id}.example:7001"),
                    x25519_pub: hex::encode([id as u8; 32]),
                    tls_cert_sha256: Some(hex::encode([id as u8 + 10; 32])),
                })
                .collect(),
            coordinators: vec![CoordinatorEntry { name: "main".into(), tls_cert_sha256: hex::encode([7u8; 32]) }],
        }
    }

    fn write(dir: &std::path::Path, name: &str, v: &impl Serialize) -> std::path::PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, serde_json::to_vec_pretty(v).unwrap()).unwrap();
        p
    }

    #[test]
    fn signed_registry_is_pinned_and_tamper_evident() {
        let dir = std::env::temp_dir().join(format!("tsn-registry-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let admin = SigningKey::from_bytes(&[1u8; 32]);
        let admin_hex = hex::encode(admin.verifying_key().as_bytes());
        let signed = registry().sign(&admin).unwrap();
        let p = write(&dir, "signed.json", &signed);
        assert_eq!(Registry::load_pinned(&p, &admin_hex).unwrap(), registry());
        assert_eq!(Registry::load(&p).unwrap().digest().unwrap(), registry().digest().unwrap());

        // Signed by someone else.
        let other = hex::encode(SigningKey::from_bytes(&[2u8; 32]).verifying_key().as_bytes());
        assert!(Registry::load_pinned(&p, &other).unwrap_err().to_string().contains("not the pinned admin"));
        // Any edit breaks the signature, even through the unpinned loader.
        let mut forged = signed.clone();
        forged.registry.nodes[0].url = "https://evil.example:7001".into();
        let f = write(&dir, "forged.json", &forged);
        assert!(Registry::load(&f).unwrap_err().to_string().contains("signature is invalid"));
        // A forger re-signing with their own key is caught by the pin.
        let resigned = forged.registry.sign(&SigningKey::from_bytes(&[3u8; 32])).unwrap();
        assert!(Registry::load_pinned(&write(&dir, "resigned.json", &resigned), &admin_hex).is_err());
        // Unsigned registries load only unpinned.
        let u = write(&dir, "unsigned.json", &registry());
        assert!(Registry::load(&u).is_ok());
        assert!(Registry::load_pinned(&u, &admin_hex).unwrap_err().to_string().contains("not signed"));
        assert_ne!(registry().digest().unwrap(), forged.registry.digest().unwrap());
        std::fs::remove_dir_all(dir).ok();
    }

    #[test]
    fn registry_validation() {
        let mut r = registry();
        r.nodes[1].tls_cert_sha256 = None;
        assert!(r.validate().unwrap_err().to_string().contains("https needs tls_cert_sha256"));
        let mut r = registry();
        r.nodes[1].id = 1;
        assert!(r.validate().is_err());
        let mut r = registry();
        r.threshold = 4;
        assert!(r.validate().is_err());
        let mut r = registry();
        r.nodes[0].url = "ftp://x".into();
        assert!(r.validate().is_err());
        // Old dev registries (http, no TLS, no coordinators) still load.
        let old: Registry = serde_json::from_str(
            r#"{"threshold":2,"nodes":[{"id":1,"url":"http://127.0.0.1:7001","x25519_pub":"00"},{"id":2,"url":"http://127.0.0.1:7002","x25519_pub":"00"}]}"#,
        )
        .unwrap();
        old.validate().unwrap();
        assert!(!serde_json::to_string(&old).unwrap().contains("coordinators"), "digest of old registries unchanged");
    }
}
