//! In-process end-to-end: real DKG (no dealer), derived child key, FROST signing, chain verification.

use rand::rngs::OsRng;
use std::collections::BTreeMap;
use tsn_core::chain::{self, Network, Tx, TxInput, TxOutput};
use tsn_core::frost::{self, keys::dkg, keys::KeyPackage, keys::PublicKeyPackage};
use tsn_core::{address, derive, identifier};

fn run_dkg(n: u16, t: u16) -> (BTreeMap<frost::Identifier, KeyPackage>, PublicKeyPackage) {
    let ids: Vec<_> = (1..=n).map(|i| identifier(i).unwrap()).collect();
    let mut r1_secret = BTreeMap::new();
    let mut r1_pkg = BTreeMap::new();
    for id in &ids {
        let (s, p) = dkg::part1(*id, n, t, OsRng).unwrap();
        r1_secret.insert(*id, s);
        r1_pkg.insert(*id, p);
    }
    let mut r2_secret = BTreeMap::new();
    let mut r2_inbox: BTreeMap<_, BTreeMap<_, _>> = BTreeMap::new();
    for id in &ids {
        let others: BTreeMap<_, _> = r1_pkg.iter().filter(|(k, _)| *k != id).map(|(k, v)| (*k, v.clone())).collect();
        let (s, out) = dkg::part2(r1_secret.remove(id).unwrap(), &others).unwrap();
        r2_secret.insert(*id, s);
        for (to, pkg) in out {
            r2_inbox.entry(to).or_default().insert(*id, pkg);
        }
    }
    let mut kps = BTreeMap::new();
    let mut pkp = None;
    for id in &ids {
        let others: BTreeMap<_, _> = r1_pkg.iter().filter(|(k, _)| *k != id).map(|(k, v)| (*k, v.clone())).collect();
        let (kp, p) = dkg::part3(&r2_secret[id], &others, &r2_inbox[id]).unwrap();
        if let Some(prev) = &pkp {
            assert_eq!(prev, &p, "all nodes must agree on the group key");
        }
        pkp = Some(p);
        kps.insert(*id, kp);
    }
    (kps, pkp.unwrap())
}

fn sign(
    kps: &BTreeMap<frost::Identifier, KeyPackage>,
    pkp: &PublicKeyPackage,
    signers: &[u16],
    path: &str,
    msg: &[u8; 32],
) -> Result<frost::Signature, frost::Error> {
    let mut nonces = BTreeMap::new();
    let mut commits = BTreeMap::new();
    for s in signers {
        let id = identifier(*s).unwrap();
        let (n, c) = frost::round1::commit(kps[&id].signing_share(), &mut OsRng);
        nonces.insert(id, n);
        commits.insert(id, c);
    }
    let pkg = frost::SigningPackage::new(commits, msg);
    let mut shares = BTreeMap::new();
    for s in signers {
        let id = identifier(*s).unwrap();
        let child = derive::key_package(&kps[&id], path).unwrap();
        shares.insert(id, frost::round2::sign(&pkg, &nonces[&id], &child)?);
    }
    frost::aggregate(&pkg, &shares, &derive::public_key_package(pkp, path).unwrap())
}

fn demo_tx(network: Network, xonly: &[u8; 32]) -> Tx {
    let to = address::encode(network.prefix(), address::VERSION_PUBKEY, &[9u8; 32]);
    let change = address::encode(network.prefix(), address::VERSION_PUBKEY, xonly);
    Tx {
        network,
        inputs: vec![TxInput {
            prev_txid: hex::encode([0x11u8; 32]),
            index: 0,
            amount: 5_000_000_000,
            script_pubkey: hex::encode(chain::p2pk_script(xonly)),
            sequence: 0,
            sig_op_count: 1,
            signature_script: String::new(),
        }],
        outputs: vec![
            TxOutput { address: to, amount: 1_000_000_000 },
            TxOutput { address: change, amount: 3_999_990_000 },
        ],
        lock_time: 0,
    }
}

#[test]
fn three_of_five_signs_kaspa_and_hoosat() {
    let (kps, pkp) = run_dkg(5, 3);
    let path = "owner/abc/treasury";
    let xonly = derive::child_xonly(pkp.verifying_key(), path).unwrap();
    assert_ne!(xonly, derive::xonly(pkp.verifying_key()).unwrap(), "child differs from master");

    for network in [Network::KaspaTestnet, Network::HoosatTestnet] {
        for signers in [[1u16, 2, 3], [1, 3, 5], [2, 4, 5]] {
            let mut tx = demo_tx(network, &xonly);
            let msg = chain::sighash(&tx, 0).unwrap();
            let sig = sign(&kps, &pkp, &signers, path, &msg).unwrap();
            let sig64: [u8; 64] = sig.serialize().unwrap().try_into().unwrap();
            tx.inputs[0].signature_script = hex::encode(chain::signature_script(&sig64));
            chain::verify_signed(&tx).unwrap_or_else(|e| panic!("{network:?} {signers:?}: {e}"));

            // Tampering with an output must break verification.
            let mut bad = tx.clone();
            bad.outputs[0].amount += 1;
            assert!(chain::verify_signed(&bad).is_err());
        }
    }
}

#[test]
fn two_signers_cannot_sign() {
    let (kps, pkp) = run_dkg(5, 3);
    let msg = [7u8; 32];
    assert!(sign(&kps, &pkp, &[1, 2], "owner/abc/x", &msg).is_err());
}

#[test]
fn kaspa_and_hoosat_sighash_differ_only_by_hash() {
    let xonly = [5u8; 32];
    let k = chain::sighash(&demo_tx(Network::KaspaTestnet, &xonly), 0).unwrap();
    let h = chain::sighash(&demo_tx(Network::HoosatTestnet, &xonly), 0).unwrap();
    assert_ne!(k, h);
}
