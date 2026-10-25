//! Core library for the Hoosat/Kaspa threshold signing network (TSN) prototype.
//!
//! - [`address`]: Kaspa/Hoosat bech32 address encoding.
//! - [`chain`]: transaction model, per-chain sighash, mass, and signature verification.
//! - [`build`]: coin selection, change and fees for real payments.
//! - [`derive`]: ICP-style path-based key derivation on top of a FROST master key.
//! - [`seal`]: node-to-node encryption for DKG round-2 packages (coordinator cannot read them).
//! - [`auth`]: owner request signing — binds a derived key to the identity allowed to use it.
//! - [`proto`]: wire types shared by nodes and the coordinator.

pub mod address;
pub mod auth;
pub mod build;
pub mod chain;
pub mod derive;
pub mod proto;
pub mod seal;

pub use frost_secp256k1_tr as frost;

/// Converts a 1-based node id into a FROST identifier.
pub fn identifier(id: u16) -> anyhow::Result<frost::Identifier> {
    frost::Identifier::try_from(id).map_err(|e| anyhow::anyhow!("invalid node id {id}: {e}"))
}
