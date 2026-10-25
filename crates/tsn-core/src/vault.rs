//! Passphrase-encrypted files for node secrets (identity keys, key shares).
//!
//! The key comes from the passphrase with Argon2id; the file is sealed with ChaCha20-Poly1305 and
//! bound to a label (e.g. "identity", "key:master"), so files can't be swapped for one another.
//! A stolen node directory is useless without the passphrase.

use anyhow::{anyhow, ensure, Context, Result};
use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    ChaCha20Poly1305, Nonce,
};
use rand::RngCore;
use serde::{Deserialize, Serialize};

const AAD_PREFIX: &[u8] = b"HTN-TSN/vault/v1|";

/// Argon2id cost. The default takes about a second and 64 MiB per open.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub struct KdfParams {
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl Default for KdfParams {
    fn default() -> Self {
        KdfParams { m_kib: 64 * 1024, t: 3, p: 1 }
    }
}

#[derive(Serialize, Deserialize)]
struct VaultFile {
    tsn_vault: u32,
    kdf: String,
    #[serde(flatten)]
    params: KdfParams,
    salt: String,
    nonce: String,
    ciphertext: String,
}

fn derive_key(passphrase: &str, salt: &[u8], p: KdfParams) -> Result<[u8; 32]> {
    let params = Params::new(p.m_kib, p.t, p.p, Some(32)).map_err(|e| anyhow!("argon2 params: {e}"))?;
    let mut key = [0u8; 32];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|e| anyhow!("argon2: {e}"))?;
    Ok(key)
}

fn aad(label: &str) -> Vec<u8> {
    [AAD_PREFIX, label.as_bytes()].concat()
}

/// Encrypts `plaintext` under `passphrase`; returns the file contents (JSON).
pub fn seal(plaintext: &[u8], passphrase: &str, label: &str, params: KdfParams) -> Result<Vec<u8>> {
    ensure!(!passphrase.is_empty(), "empty passphrase");
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    rand::thread_rng().fill_bytes(&mut salt);
    rand::thread_rng().fill_bytes(&mut nonce);
    let key = derive_key(passphrase, &salt, params)?;
    let ct = ChaCha20Poly1305::new(&key.into())
        .encrypt(Nonce::from_slice(&nonce), Payload { msg: plaintext, aad: &aad(label) })
        .map_err(|_| anyhow!("encryption failed"))?;
    let f = VaultFile {
        tsn_vault: 1,
        kdf: "argon2id".into(),
        params,
        salt: hex::encode(salt),
        nonce: hex::encode(nonce),
        ciphertext: hex::encode(ct),
    };
    Ok(serde_json::to_vec_pretty(&f)?)
}

/// Decrypts a file made by [`seal`] with the same label.
pub fn open(file: &[u8], passphrase: &str, label: &str) -> Result<Vec<u8>> {
    let f: VaultFile = serde_json::from_slice(file).context("not an encrypted node file")?;
    ensure!(f.tsn_vault == 1 && f.kdf == "argon2id", "unsupported encrypted file version");
    ensure!(f.params.m_kib <= 4 * 1024 * 1024 && f.params.t <= 64, "unreasonable key-derivation cost in file");
    let key = derive_key(passphrase, &hex::decode(&f.salt)?, f.params)?;
    let nonce: [u8; 12] = hex::decode(&f.nonce)?.try_into().map_err(|_| anyhow!("bad nonce"))?;
    ChaCha20Poly1305::new(&key.into())
        .decrypt(Nonce::from_slice(&nonce), Payload { msg: &hex::decode(&f.ciphertext)?, aad: &aad(label) })
        .map_err(|_| anyhow!("wrong passphrase (or the file was altered or renamed)"))
}

/// Whether `file` is an encrypted node file (as opposed to plaintext JSON).
pub fn is_sealed(file: &[u8]) -> bool {
    serde_json::from_slice::<serde_json::Value>(file).map(|v| v.get("tsn_vault").is_some()).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: KdfParams = KdfParams { m_kib: 64, t: 1, p: 1 };

    #[test]
    fn round_trip_and_failures() {
        let f = seal(b"share bytes", "correct horse", "key:master", FAST).unwrap();
        assert!(is_sealed(&f));
        assert!(!is_sealed(b"{\"x25519_secret\":\"00\"}"));
        assert!(!String::from_utf8_lossy(&f).contains("share bytes"));
        assert_eq!(open(&f, "correct horse", "key:master").unwrap(), b"share bytes");
        assert!(open(&f, "wrong", "key:master").unwrap_err().to_string().contains("wrong passphrase"));
        assert!(open(&f, "correct horse", "identity").is_err(), "label binds the file");
        let mut v: serde_json::Value = serde_json::from_slice(&f).unwrap();
        let ct = v["ciphertext"].as_str().unwrap().to_string();
        v["ciphertext"] = format!("{}{}", &ct[..ct.len() - 2], if ct.ends_with('0') { "1" } else { "0" }).into();
        assert!(open(&serde_json::to_vec(&v).unwrap(), "correct horse", "key:master").is_err());
        assert!(seal(b"x", "", "l", FAST).is_err());
    }
}
