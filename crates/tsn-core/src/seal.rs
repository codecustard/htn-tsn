//! Node-to-node sealing for DKG round-2 packages.
//!
//! Round-2 packages carry secret shares, so they must reach only their recipient. Each node has a
//! static X25519 identity listed in the registry; a package is encrypted under
//! ECDH(sender, recipient) with ChaCha20-Poly1305 and bound to (key_id, sender, recipient).
//! The coordinator relays ciphertext it cannot read, and cannot forge because it holds neither key.
//! Production would use a forward-secret channel (Noise/mTLS); this keeps the prototype small.

use anyhow::{anyhow, ensure, Result};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

fn context(key_id: &str, from: u16, to: u16) -> Vec<u8> {
    let mut c = b"HTN-TSN/seal/v1|".to_vec();
    c.extend_from_slice(key_id.as_bytes());
    c.extend_from_slice(&from.to_le_bytes());
    c.extend_from_slice(&to.to_le_bytes());
    c
}

fn cipher(me: &StaticSecret, peer: &[u8; 32], ctx: &[u8]) -> ChaCha20Poly1305 {
    let shared = me.diffie_hellman(&PublicKey::from(*peer));
    let key = Sha256::new().chain_update(shared.as_bytes()).chain_update(ctx).finalize();
    ChaCha20Poly1305::new(&key)
}

pub fn seal(me: &StaticSecret, peer: &[u8; 32], key_id: &str, from: u16, to: u16, plaintext: &[u8]) -> Result<Vec<u8>> {
    let ctx = context(key_id, from, to);
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut nonce);
    let ct = cipher(me, peer, &ctx)
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: &ctx })
        .map_err(|_| anyhow!("seal failed"))?;
    Ok([nonce.as_slice(), &ct].concat())
}

pub fn open(me: &StaticSecret, peer: &[u8; 32], key_id: &str, from: u16, to: u16, sealed: &[u8]) -> Result<Vec<u8>> {
    ensure!(sealed.len() > 12, "sealed package too short");
    let ctx = context(key_id, from, to);
    let (nonce, ct) = sealed.split_at(12);
    cipher(me, peer, &ctx)
        .decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad: &ctx })
        .map_err(|_| anyhow!("package from node {from} failed authentication"))
}
