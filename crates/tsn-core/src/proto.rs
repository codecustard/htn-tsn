//! Wire types and the operator registry.

use crate::frost::{
    self,
    keys::{dkg::round1, PublicKeyPackage},
};
use crate::{auth::Authorization, chain::Tx};
use anyhow::{anyhow, Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

/// The operator set. In Phase 1 this is a signed config file every node and coordinator holds;
/// in Phase 3 it moves on-chain. Nodes trust peer identities from here, never from the coordinator.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Registry {
    pub threshold: u16,
    pub nodes: Vec<NodeEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeEntry {
    pub id: u16,
    pub url: String,
    pub x25519_pub: String,
}

impl Registry {
    pub fn load(path: &Path) -> Result<Self> {
        let s = std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        Ok(serde_json::from_str(&s)?)
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeIdentity {
    pub id: u16,
    pub x25519_pub: String,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct InfoResp {
    pub id: u16,
    pub x25519_pub: String,
    pub keys: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct DkgPart1Req {
    pub key_id: String,
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
