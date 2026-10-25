//! Coordinator side of the htn-tsn threshold signing network.
//!
//! - [`chain_api`]: the public Kaspa/Hoosat REST API (UTXOs, fee estimates, broadcast).
//! - [`nodes`]: the signer nodes (DKG, FROST sessions, identifiable-abort retries).
//! - [`payment`]: coin selection and fees for a payment from an owner's derived key.
//!
//! Used by the `tsn` CLI and by the `tsn-coordinator` HTTP service.

pub mod chain_api;
pub mod nodes;
pub mod payment;
