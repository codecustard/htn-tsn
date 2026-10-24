//! `tsn`: operator + client CLI. The coordinator role is untrusted: it relays messages,
//! picks signers and aggregates, but never sees a secret share and cannot make nodes sign
//! anything the owner and node policy don't allow.

use anyhow::{anyhow, bail, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand::{rngs::OsRng, RngCore};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::{collections::BTreeMap, path::PathBuf, time::Duration};
use tsn_core::{
    address, auth,
    chain::{self, Network, Tx, TxInput, TxOutput},
    derive,
    frost::{self, keys::PublicKeyPackage},
    identifier,
    proto::*,
};

#[derive(Parser)]
#[command(name = "tsn", about = "Hoosat/Kaspa threshold signing network — operator and client CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Build registry.json from node identities. Each --node is DIR=URL.
    Registry {
        #[arg(long)]
        threshold: u16,
        #[arg(long = "node", required = true)]
        nodes: Vec<String>,
        #[arg(long, default_value = "registry.json")]
        out: PathBuf,
    },
    /// Run distributed key generation across all registry nodes.
    Dkg {
        #[arg(long, default_value = "registry.json")]
        registry: PathBuf,
        #[arg(long, default_value = "master")]
        key_id: String,
        #[arg(long)]
        out: PathBuf,
    },
    /// Create an owner (ed25519) key — the identity allowed to use its derived keys.
    OwnerNew {
        #[arg(long)]
        out: PathBuf,
    },
    /// Print the address of OWNER's key NAME. Computed offline from the master public key.
    Address {
        #[arg(long)]
        public: PathBuf,
        #[arg(long)]
        owner: PathBuf,
        #[arg(long)]
        name: String,
        #[arg(long)]
        network: String,
    },
    /// Build and threshold-sign a payment from OWNER's key NAME (spends a mock UTXO).
    Sign {
        #[arg(long, default_value = "registry.json")]
        registry: PathBuf,
        #[arg(long)]
        public: PathBuf,
        #[arg(long, default_value = "master")]
        key_id: String,
        /// Key that signs the request.
        #[arg(long)]
        owner: PathBuf,
        /// Owner named in the derivation path (defaults to --owner). Set differently to test impersonation.
        #[arg(long)]
        path_owner: Option<PathBuf>,
        #[arg(long)]
        name: String,
        #[arg(long)]
        network: String,
        #[arg(long)]
        to: String,
        #[arg(long)]
        amount: u64,
        #[arg(long, default_value_t = 5_000_000_000)]
        utxo_amount: u64,
        /// Comma-separated node ids to use; default = any live nodes, retrying around bad ones.
        #[arg(long)]
        signers: Option<String>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Verify a signed transaction file against chain rules.
    Verify {
        #[arg(long)]
        tx: PathBuf,
    },
}

#[derive(Serialize, Deserialize)]
struct OwnerFile {
    ed25519_secret: String,
    ed25519_public: String,
}

fn load_owner(p: &PathBuf) -> Result<SigningKey> {
    let f: OwnerFile = serde_json::from_slice(&std::fs::read(p).with_context(|| format!("reading {}", p.display()))?)?;
    let bytes: [u8; 32] = hex::decode(f.ed25519_secret)?.try_into().map_err(|_| anyhow!("bad owner key"))?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn load_public(p: &PathBuf) -> Result<PublicKeyPackage> {
    Ok(serde_json::from_slice(&std::fs::read(p).with_context(|| format!("reading {}", p.display()))?)?)
}

fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

struct Client {
    http: reqwest::Client,
    registry: Registry,
}

impl Client {
    fn new(registry: Registry) -> Self {
        Self { http: reqwest::Client::builder().timeout(Duration::from_secs(10)).build().unwrap(), registry }
    }

    async fn post<Req: Serialize, Resp: DeserializeOwned>(&self, id: u16, route: &str, body: &Req) -> Result<Resp> {
        let url = format!("{}{}", self.registry.node(id)?.url, route);
        let r = self.http.post(&url).json(body).send().await.with_context(|| format!("node {id} unreachable"))?;
        if r.status().is_success() {
            Ok(r.json().await?)
        } else {
            let e: ErrorResp = r.json().await.unwrap_or(ErrorResp { error: "unknown error".into() });
            bail!("node {id}: {}", e.error)
        }
    }

    async fn live_nodes(&self) -> Vec<u16> {
        let mut live = vec![];
        for n in &self.registry.nodes {
            if self.http.get(format!("{}/info", n.url)).send().await.map(|r| r.status().is_success()).unwrap_or(false) {
                live.push(n.id);
            }
        }
        live
    }

    async fn dkg(&self, key_id: &str) -> Result<PublicKeyPackage> {
        let ids: Vec<u16> = self.registry.nodes.iter().map(|n| n.id).collect();
        let mut r1 = BTreeMap::new();
        for id in &ids {
            let resp: DkgPart1Resp = self.post(*id, "/dkg/part1", &DkgPart1Req { key_id: key_id.into() }).await?;
            r1.insert(*id, resp.package);
        }
        let others = |me: u16| r1.iter().filter(|(k, _)| **k != me).map(|(k, v)| (*k, v.clone())).collect::<BTreeMap<_, _>>();
        let mut inbox: BTreeMap<u16, BTreeMap<u16, String>> = BTreeMap::new();
        for id in &ids {
            let resp: DkgPart2Resp =
                self.post(*id, "/dkg/part2", &DkgPart2Req { key_id: key_id.into(), round1_packages: others(*id) }).await?;
            for (to, ct) in resp.sealed {
                inbox.entry(to).or_default().insert(*id, ct);
            }
        }
        let mut result: Option<PublicKeyPackage> = None;
        for id in &ids {
            let req = DkgPart3Req {
                key_id: key_id.into(),
                round1_packages: others(*id),
                sealed_for_me: inbox.remove(id).unwrap_or_default(),
            };
            let resp: DkgPart3Resp = self.post(*id, "/dkg/part3", &req).await?;
            match &result {
                Some(p) if p != &resp.public_key_package => bail!("node {id} disagrees on the group key"),
                _ => result = Some(resp.public_key_package),
            }
        }
        result.ok_or_else(|| anyhow!("no nodes"))
    }

    /// One FROST session for one input. Returns the signature or the culprits of an invalid share.
    async fn sign_once(
        &self,
        key_id: &str,
        path: &str,
        owner: &SigningKey,
        public: &PublicKeyPackage,
        tx: &Tx,
        idx: usize,
        signers: &[u16],
    ) -> Result<std::result::Result<[u8; 64], Vec<u16>>> {
        let session_id = random_hex(16);
        let mut commitments = BTreeMap::new();
        for id in signers {
            let r: CommitResp = self.post(*id, "/sign/commit", &CommitReq { key_id: key_id.into(), session_id: session_id.clone() }).await?;
            commitments.insert(identifier(*id)?, r.commitments);
        }
        let sighash = chain::sighash(tx, idx)?;
        let signing_package = frost::SigningPackage::new(commitments, &sighash);
        let tx_json = serde_json::to_string(tx)?;
        let owner_sig = auth::sign_request(owner, &auth::request_digest(key_id, path, &session_id, &tx_json, idx));
        let mut shares = BTreeMap::new();
        for id in signers {
            let req = ShareReq {
                key_id: key_id.into(),
                session_id: session_id.clone(),
                path: path.into(),
                tx: tx.clone(),
                input_index: idx,
                signing_package: signing_package.clone(),
                owner_sig: owner_sig.clone(),
            };
            let r: ShareResp = self.post(*id, "/sign/share", &req).await?;
            shares.insert(identifier(*id)?, r.share);
        }
        let child_public = derive::public_key_package(public, path)?;
        match frost::aggregate(&signing_package, &shares, &child_public) {
            Ok(sig) => Ok(Ok(sig.serialize()?.try_into().map_err(|_| anyhow!("bad signature length"))?)),
            Err(e) if !e.culprits().is_empty() => {
                let ids: BTreeMap<frost::Identifier, u16> =
                    self.registry.nodes.iter().map(|n| Ok((identifier(n.id)?, n.id))).collect::<Result<_>>()?;
                Ok(Err(e.culprits().iter().map(|c| ids[c]).collect()))
            }
            Err(e) => bail!("aggregation failed: {e}"),
        }
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Registry { threshold, nodes, out } => {
            let mut entries = vec![];
            for spec in nodes {
                let (dir, url) = spec.split_once('=').ok_or_else(|| anyhow!("--node must be DIR=URL"))?;
                let ident: NodeIdentity = serde_json::from_slice(&std::fs::read(PathBuf::from(dir).join("identity.pub.json"))?)?;
                entries.push(NodeEntry { id: ident.id, url: url.to_string(), x25519_pub: ident.x25519_pub });
            }
            entries.sort_by_key(|e| e.id);
            let n = entries.len() as u16;
            if threshold < 2 || threshold > n {
                bail!("threshold must be in 2..={n}");
            }
            std::fs::write(&out, serde_json::to_vec_pretty(&Registry { threshold, nodes: entries })?)?;
            println!("registry: {threshold}-of-{n} -> {}", out.display());
        }
        Cmd::Dkg { registry, key_id, out } => {
            let client = Client::new(Registry::load(&registry)?);
            let pkp = client.dkg(&key_id).await?;
            std::fs::write(&out, serde_json::to_vec_pretty(&pkp)?)?;
            println!("DKG complete: master key {}", hex::encode(pkp.verifying_key().serialize()?));
            println!("no node and no coordinator ever held the private key; public package -> {}", out.display());
        }
        Cmd::OwnerNew { out } => {
            let sk = SigningKey::generate(&mut OsRng);
            let f = OwnerFile { ed25519_secret: hex::encode(sk.to_bytes()), ed25519_public: hex::encode(sk.verifying_key().as_bytes()) };
            std::fs::write(&out, serde_json::to_vec_pretty(&f)?)?;
            println!("owner {}", f.ed25519_public);
        }
        Cmd::Address { public, owner, name, network } => {
            let network = Network::parse(&network)?;
            let path = auth::owner_path(&load_owner(&owner)?.verifying_key(), &name);
            let xonly = derive::child_xonly(load_public(&public)?.verifying_key(), &path)?;
            println!("{}", address::encode(network.prefix(), address::VERSION_PUBKEY, &xonly));
        }
        Cmd::Sign { registry, public, key_id, owner, path_owner, name, network, to, amount, utxo_amount, signers, out } => {
            let network = Network::parse(&network)?;
            let client = Client::new(Registry::load(&registry)?);
            let public = load_public(&public)?;
            let owner = load_owner(&owner)?;
            let path_owner_key = match &path_owner {
                Some(p) => load_owner(p)?.verifying_key(),
                None => owner.verifying_key(),
            };
            let path = auth::owner_path(&path_owner_key, &name);
            let xonly = derive::child_xonly(public.verifying_key(), &path)?;
            let from = address::encode(network.prefix(), address::VERSION_PUBKEY, &xonly);
            let fee = 10_000;
            let change = utxo_amount.checked_sub(amount + fee).ok_or_else(|| anyhow!("amount + fee exceeds UTXO"))?;
            let mut tx = Tx {
                network,
                inputs: vec![TxInput {
                    prev_txid: random_hex(32), // mock UTXO owned by `from`
                    index: 0,
                    amount: utxo_amount,
                    script_pubkey: hex::encode(chain::p2pk_script(&xonly)),
                    sequence: 0,
                    sig_op_count: 1,
                    signature_script: String::new(),
                }],
                outputs: vec![TxOutput { address: to.clone(), amount }, TxOutput { address: from.clone(), amount: change }],
                lock_time: 0,
            };
            let t = client.registry.threshold as usize;
            println!("from   {from}\nto     {to}\namount {amount} sompi (change {change}, fee {fee})");

            for idx in 0..tx.inputs.len() {
                let mut pool: Vec<u16> = match &signers {
                    Some(s) => s.split(',').map(|x| x.trim().parse()).collect::<std::result::Result<_, _>>()?,
                    None => client.live_nodes().await,
                };
                let fixed = signers.is_some();
                let sig = loop {
                    // With an explicit signer set the request goes to the nodes as-is, so a
                    // too-small set is refused by the nodes themselves rather than by this client.
                    if !fixed && pool.len() < t {
                        bail!("only {} usable signers ({pool:?}); threshold is {t}", pool.len());
                    }
                    let chosen: Vec<u16> = if fixed { pool.clone() } else { pool[..t].to_vec() };
                    println!("input {idx}: signing with nodes {chosen:?}");
                    match client.sign_once(&key_id, &path, &owner, &public, &tx, idx, &chosen).await? {
                        Ok(sig) => break sig,
                        Err(culprits) => {
                            println!("input {idx}: invalid shares from {culprits:?} (identifiable abort) - excluding and retrying");
                            if fixed {
                                bail!("fixed signer set contains bad nodes {culprits:?}");
                            }
                            pool.retain(|id| !culprits.contains(id));
                        }
                    }
                };
                tx.inputs[idx].signature_script = hex::encode(chain::signature_script(&sig));
            }
            chain::verify_signed(&tx)?;
            println!(
                "signature valid: {}",
                if network.is_hoosat() { "BIP340 over Hoosat BLAKE3 sighash" } else { "accepted by the Kaspa consensus script engine" }
            );
            if let Some(out) = out {
                std::fs::write(&out, serde_json::to_vec_pretty(&tx)?)?;
                println!("signed tx -> {}", out.display());
            }
        }
        Cmd::Verify { tx } => {
            let tx: Tx = serde_json::from_slice(&std::fs::read(&tx)?)?;
            chain::verify_signed(&tx)?;
            println!("valid");
        }
    }
    Ok(())
}
