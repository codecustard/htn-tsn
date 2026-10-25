//! Test vectors shared with the TypeScript SDK (testdata/sdk-vectors.json).
//!
//! The SDK re-implements address encoding, key derivation and the owner authorization digest;
//! these vectors keep the two byte-for-byte identical. Regenerate after an intentional change:
//!   UPDATE_VECTORS=1 cargo test -p tsn-core --test sdk_vectors

use ed25519_dalek::{Signer, SigningKey};
use k256::{elliptic_curve::sec1::ToEncodedPoint, ProjectivePoint, Scalar};
use serde_json::{json, Value};
use tsn_core::{
    address, auth,
    chain::{Network, Tx, TxInput, TxOutput},
    derive,
    frost::VerifyingKey,
};

fn master_hex(seed: u64) -> String {
    let p = ProjectivePoint::GENERATOR * Scalar::from(seed);
    hex::encode(p.to_affine().to_encoded_point(true).as_bytes())
}

fn vectors() -> Value {
    let addresses: Vec<Value> = [
        ("kaspa", address::VERSION_PUBKEY, vec![0u8; 32]),
        ("kaspatest", address::VERSION_PUBKEY, (0..32u8).collect::<Vec<_>>()),
        ("hoosat", address::VERSION_PUBKEY, vec![0xffu8; 32]),
        ("hoosattest", address::VERSION_PUBKEY_ECDSA, (0..33u8).map(|i| i.wrapping_mul(7)).collect()),
        ("kaspa", address::VERSION_SCRIPT_HASH, vec![0x5au8; 32]),
    ]
    .into_iter()
    .map(|(prefix, version, data)| {
        json!({ "prefix": prefix, "version": version, "data": hex::encode(&data), "address": address::encode(prefix, version, &data) })
    })
    .collect();

    let owner = SigningKey::from_bytes(&[42u8; 32]);
    let owner_pub = hex::encode(owner.verifying_key().as_bytes());
    let mut derivations = vec![];
    for (seed, name) in [(7u64, "main"), (123_456_789, "treasury"), (u64::MAX, "a/b c")] {
        let master = master_hex(seed);
        let vk = VerifyingKey::deserialize(&hex::decode(&master).unwrap()).unwrap();
        let path = auth::owner_path(&owner.verifying_key(), name);
        let xonly = derive::child_xonly(&vk, &path).unwrap();
        derivations.push(json!({
            "master_public_key": master,
            "owner_public_key": owner_pub,
            "name": name,
            "path": path,
            "tweak": hex::encode(derive::tweak(&vk, &path).unwrap().to_bytes()),
            "xonly": hex::encode(xonly),
            "kaspa_testnet_address": address::encode("kaspatest", address::VERSION_PUBKEY, &xonly),
            "hoosat_mainnet_address": address::encode("hoosat", address::VERSION_PUBKEY, &xonly),
        }));
    }

    let tx = Tx {
        network: Network::HoosatMainnet,
        inputs: vec![
            TxInput {
                prev_txid: "ab".repeat(32),
                index: 3,
                // Above 2^53: must survive JSON in JavaScript (sent as a string).
                amount: 9_007_199_254_740_993,
                script_pubkey: format!("20{}ac", "cd".repeat(32)),
                sequence: u64::MAX,
                sig_op_count: 1,
                signature_script: String::new(),
            },
            TxInput {
                prev_txid: "01".repeat(32),
                index: 0,
                amount: 1,
                script_pubkey: format!("20{}ac", "cd".repeat(32)),
                sequence: 0,
                sig_op_count: 1,
                signature_script: String::new(),
            },
        ],
        outputs: vec![
            TxOutput {
                address: "hoosat:qr35ennsep3hxfe7lnz5ee7j5jgmkjswsn35ennsep3hxfe7ln35cta93d2lg".into(),
                amount: 100_000_000,
            },
            TxOutput {
                address: "hoosat:qyp0r5mcq4rd5grj3652ra09u5dcgwqq9ntuswp247nama5quyj40eq0f28wqsx".into(),
                amount: 9_007_199_154_740_000,
            },
        ],
        lock_time: 0,
    };
    let request_id = "00112233445566778899aabbccddeeff";
    let expires_at = 1_800_000_000u64;
    let path = auth::owner_path(&owner.verifying_key(), "main");
    let digest = auth::request_digest("master", &path, request_id, expires_at, &tx).unwrap();
    let signature = owner.sign(&digest);

    json!({
        "addresses": addresses,
        "derivations": derivations,
        "authorization": {
            "owner_secret": hex::encode(owner.to_bytes()),
            "owner_public_key": owner_pub,
            "key_id": "master",
            "path": path,
            "request_id": request_id,
            "expires_at": expires_at,
            "tx": tx,
            "digest": hex::encode(digest),
            "owner_sig": hex::encode(signature.to_bytes()),
        },
    })
}

#[test]
fn sdk_vectors_are_current() {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../testdata/sdk-vectors.json");
    let fresh = serde_json::to_string_pretty(&vectors()).unwrap() + "\n";
    if std::env::var("UPDATE_VECTORS").is_ok() {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, &fresh).unwrap();
    }
    let on_disk = std::fs::read_to_string(&path).expect("testdata/sdk-vectors.json missing; run with UPDATE_VECTORS=1");
    assert_eq!(on_disk, fresh, "SDK vectors are stale; rerun with UPDATE_VECTORS=1 and update the SDK if needed");
}
