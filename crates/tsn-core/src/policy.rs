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
//! Signers are `ed25519:<public key>` or `passkey:<domain>:<P-256 public key>`. A passkey
//! approval is a WebAuthn assertion whose challenge is the request digest (see
//! [`verify_passkey`]), so users approve with Face ID, Touch ID or a security key.
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

/// One signer's approval of the request digest.
///
/// ed25519 signers: `sig` is the 64-byte signature over the digest (hex).
/// Passkey signers: a WebAuthn assertion — `sig` is the DER ECDSA signature, plus the exact
/// `authenticator_data` and `client_data_json` bytes the authenticator signed (all hex).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Approval {
    pub signer: String,
    pub sig: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub authenticator_data: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub client_data_json: String,
}

impl Approval {
    pub fn ed25519(signer: String, sig: String) -> Self {
        Self { signer, sig, authenticator_data: String::new(), client_data_json: String::new() }
    }
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

enum Signer {
    Ed25519(VerifyingKey),
    Passkey { rp_id: String, key: p256::ecdsa::VerifyingKey },
}

fn is_lower_hex(s: &str) -> bool {
    s.bytes().all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
}

/// A WebAuthn relying-party id: a lowercase domain name (or `localhost`).
fn valid_rp_id(rp: &str) -> bool {
    !rp.is_empty()
        && rp.len() <= 253
        && !rp.starts_with('.')
        && !rp.ends_with('.')
        && !rp.contains("..")
        && rp.bytes().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == b'.' || c == b'-')
}

fn parse_signer(id: &str) -> Result<Signer> {
    if let Some(hex_key) = id.strip_prefix("ed25519:") {
        ensure!(hex_key.len() == 64 && is_lower_hex(hex_key), "signer {id} must be ed25519:<64 lowercase hex>");
        let bytes: [u8; 32] = hex::decode(hex_key)?.try_into().map_err(|_| anyhow!("bad signer key"))?;
        return Ok(Signer::Ed25519(VerifyingKey::from_bytes(&bytes)?));
    }
    if let Some(rest) = id.strip_prefix("passkey:") {
        let (rp_id, hex_key) =
            rest.rsplit_once(':').ok_or_else(|| anyhow!("signer {id} must be passkey:<domain>:<key>"))?;
        ensure!(valid_rp_id(rp_id), "signer {id}: bad passkey domain");
        ensure!(
            hex_key.len() == 66 && is_lower_hex(hex_key),
            "signer {id}: passkey key must be a 33-byte compressed P-256 point (66 lowercase hex)"
        );
        let key = p256::ecdsa::VerifyingKey::from_sec1_bytes(&hex::decode(hex_key)?)
            .map_err(|_| anyhow!("signer {id}: not a P-256 point"))?;
        return Ok(Signer::Passkey { rp_id: rp_id.to_string(), key });
    }
    bail!("unsupported signer type in {id}")
}

/// `passkey:<rp id>:<compressed P-256 key hex>` for a passkey registered on `rp_id`.
pub fn passkey_signer(rp_id: &str, key: &p256::ecdsa::VerifyingKey) -> String {
    format!("passkey:{rp_id}:{}", hex::encode(key.to_encoded_point(true).as_bytes()))
}

/// WebAuthn flags: user present and user verified (biometric or PIN).
const FLAG_UP: u8 = 0x01;
const FLAG_UV: u8 = 0x04;

/// Verifies a WebAuthn assertion as an approval of `digest`:
/// - `clientDataJSON` is a `webauthn.get` whose challenge is base64url(digest), from an origin on
///   `rp_id` (https, or http on localhost for development);
/// - `authenticatorData` is for `rp_id` (SHA-256 of it) with user-present and user-verified set;
/// - the P-256 signature covers `authenticatorData || SHA-256(clientDataJSON)`.
pub fn verify_passkey(
    rp_id: &str,
    key: &p256::ecdsa::VerifyingKey,
    digest: &[u8; 32],
    authenticator_data: &[u8],
    client_data_json: &[u8],
    der_sig: &[u8],
) -> Result<()> {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
    use p256::ecdsa::signature::Verifier as _;

    let cd: Value = serde_json::from_slice(client_data_json).map_err(|_| anyhow!("clientDataJSON is not JSON"))?;
    ensure!(cd["type"] == "webauthn.get", "not a WebAuthn assertion");
    ensure!(cd["challenge"].as_str() == Some(&URL_SAFE_NO_PAD.encode(digest)), "passkey signed a different request");
    let origin = cd["origin"].as_str().ok_or_else(|| anyhow!("clientDataJSON has no origin"))?;
    let (scheme, rest) = origin.split_once("://").ok_or_else(|| anyhow!("bad origin {origin}"))?;
    let host = rest.split([':', '/']).next().unwrap_or_default();
    let on_rp = host == rp_id || host.ends_with(&format!(".{rp_id}"));
    let secure = scheme == "https" || (scheme == "http" && host == "localhost");
    ensure!(on_rp && secure, "passkey used from origin {origin}, not {rp_id}");

    ensure!(authenticator_data.len() >= 37, "authenticatorData too short");
    ensure!(authenticator_data[..32] == Sha256::digest(rp_id.as_bytes())[..], "passkey was for a different domain");
    let flags = authenticator_data[32];
    ensure!(flags & FLAG_UP != 0, "passkey: user not present");
    ensure!(flags & FLAG_UV != 0, "passkey: user not verified (biometric or PIN required)");

    let sig = p256::ecdsa::Signature::from_der(der_sig).map_err(|_| anyhow!("passkey signature is not DER ECDSA"))?;
    let sig = sig.normalize_s().unwrap_or(sig);
    let mut msg = authenticator_data.to_vec();
    msg.extend_from_slice(&Sha256::digest(client_data_json));
    key.verify(&msg, &sig).map_err(|_| anyhow!("passkey signature does not verify"))
}

fn verify_approval(a: &Approval, digest: &[u8; 32]) -> Result<()> {
    match parse_signer(&a.signer)? {
        Signer::Ed25519(key) => {
            let sig: [u8; 64] =
                hex::decode(&a.sig)?.try_into().map_err(|_| anyhow!("approval signature must be 64 bytes"))?;
            key.verify(digest, &Signature::from_bytes(&sig))
                .map_err(|_| anyhow!("approval from {} does not verify", a.signer))
        }
        Signer::Passkey { rp_id, key } => verify_passkey(
            &rp_id,
            &key,
            digest,
            &hex::decode(&a.authenticator_data)?,
            &hex::decode(&a.client_data_json)?,
            &hex::decode(&a.sig)?,
        )
        .map_err(|e| anyhow!("approval from {}: {e}", a.signer)),
    }
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
            verify_approval(a, digest)?;
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
        Approval::ed25519(ed25519_signer(&k.verifying_key()), hex::encode(k.sign(digest).to_bytes()))
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
        let forged = Approval::ed25519(ed25519_signer(&ops.verifying_key()), approve(&mallory, &d).sig);
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

    /// Software authenticator: builds what a browser + passkey would return for `digest`.
    pub(crate) fn passkey_assertion(
        key: &p256::ecdsa::SigningKey,
        rp_id: &str,
        origin: &str,
        flags: u8,
        challenge: &[u8; 32],
    ) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
        use p256::ecdsa::signature::Signer as _;
        let mut ad = Sha256::digest(rp_id.as_bytes()).to_vec();
        ad.push(flags);
        ad.extend_from_slice(&[0, 0, 0, 0]);
        let cd = format!(
            r#"{{"type":"webauthn.get","challenge":"{}","origin":"{origin}","crossOrigin":false}}"#,
            URL_SAFE_NO_PAD.encode(challenge)
        )
        .into_bytes();
        let mut msg = ad.clone();
        msg.extend_from_slice(&Sha256::digest(&cd));
        let sig: p256::ecdsa::Signature = key.sign(&msg);
        (ad, cd, sig.to_der().as_bytes().to_vec())
    }

    #[test]
    fn passkey_approvals() {
        let pk = p256::ecdsa::SigningKey::from_bytes(&[5u8; 32].into()).unwrap();
        let signer = passkey_signer("wallet.example.com", pk.verifying_key());
        let policy = Policy {
            version: 1,
            clauses: vec![Clause {
                signers: Signers { k: 1, of: vec![signer.clone()] },
                after: None,
                only_to: None,
                max_per_tx: None,
            }],
        };
        policy.validate().unwrap();
        let (_, tx, own, _, _) = setup();
        let d = [3u8; 32];
        let approval = |rp: &str, origin: &str, flags: u8, challenge: &[u8; 32]| {
            let (ad, cd, sig) = passkey_assertion(&pk, rp, origin, flags, challenge);
            Approval {
                signer: signer.clone(),
                sig: hex::encode(sig),
                authenticator_data: hex::encode(ad),
                client_data_json: hex::encode(cd),
            }
        };
        let ok = approval("wallet.example.com", "https://wallet.example.com", FLAG_UP | FLAG_UV, &d);
        assert_eq!(policy.evaluate(&tx, &own, std::slice::from_ref(&ok), &d, 0).unwrap(), 0);
        let sub = approval("wallet.example.com", "https://app.wallet.example.com", FLAG_UP | FLAG_UV, &d);
        assert!(policy.evaluate(&tx, &own, &[sub], &d, 0).is_ok());

        let fails = [
            (
                "other request",
                approval("wallet.example.com", "https://wallet.example.com", FLAG_UP | FLAG_UV, &[4u8; 32]),
            ),
            ("phishing origin", approval("wallet.example.com", "https://wallet-example.com", FLAG_UP | FLAG_UV, &d)),
            ("plain http", approval("wallet.example.com", "http://wallet.example.com", FLAG_UP | FLAG_UV, &d)),
            ("other domain", approval("evil.com", "https://wallet.example.com", FLAG_UP | FLAG_UV, &d)),
            ("no user verification", approval("wallet.example.com", "https://wallet.example.com", FLAG_UP, &d)),
        ];
        for (why, a) in fails {
            assert!(policy.evaluate(&tx, &own, &[a], &d, 0).is_err(), "{why} should fail");
        }
        let mut tampered = ok.clone();
        tampered.authenticator_data.replace_range(64..66, "01"); // flags byte -> user present only
        assert!(policy.evaluate(&tx, &own, &[tampered], &d, 0).is_err());
        let other = p256::ecdsa::SigningKey::from_bytes(&[6u8; 32].into()).unwrap();
        let (ad, cd, sig) =
            passkey_assertion(&other, "wallet.example.com", "https://wallet.example.com", FLAG_UP | FLAG_UV, &d);
        let wrong_key = Approval {
            signer,
            sig: hex::encode(sig),
            authenticator_data: hex::encode(ad),
            client_data_json: hex::encode(cd),
        };
        assert!(policy.evaluate(&tx, &own, &[wrong_key], &d, 0).is_err());

        // localhost over http is allowed for development.
        let dev_pk = p256::ecdsa::SigningKey::from_bytes(&[7u8; 32].into()).unwrap();
        let dev_signer = passkey_signer("localhost", dev_pk.verifying_key());
        let dev = Policy {
            version: 1,
            clauses: vec![Clause {
                signers: Signers { k: 1, of: vec![dev_signer.clone()] },
                after: None,
                only_to: None,
                max_per_tx: None,
            }],
        };
        let (ad, cd, sig) = passkey_assertion(&dev_pk, "localhost", "http://localhost:8080", FLAG_UP | FLAG_UV, &d);
        let a = Approval {
            signer: dev_signer,
            sig: hex::encode(sig),
            authenticator_data: hex::encode(ad),
            client_data_json: hex::encode(cd),
        };
        assert!(dev.evaluate(&tx, &own, &[a], &d, 0).is_ok());
    }

    #[test]
    fn rejects_bad_passkey_signers() {
        for bad in [
            "passkey:Wallet.com:02aa",
            "passkey::02",
            "passkey:a..b:0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798",
            "passkey:wallet.com:zz",
        ] {
            assert!(parse_signer(bad).is_err(), "{bad}");
        }
    }
}
