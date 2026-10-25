//! `tsn`: operator + client CLI. The coordinator role is untrusted: it relays messages,
//! picks signers and aggregates, but never sees a secret share and cannot make nodes sign
//! anything the owner and node policy don't allow.

use anyhow::{anyhow, bail, ensure, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::SigningKey;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tsn_coord::{
    chain_api::{self, ChainApi},
    nodes::NodeClient,
    payment,
    spent::RecentSpends,
};
use tsn_core::{
    address, auth,
    build::Amount,
    chain::{self, Network, Tx, TxInput, TxOutput},
    derive,
    frost::keys::PublicKeyPackage,
    policy::Policy,
    proto::*,
};

/// How long an owner authorization made by this CLI stays valid.
const AUTH_TTL_SECS: u64 = 600;

#[derive(Parser)]
#[command(name = "tsn", about = "Hoosat/Kaspa threshold signing network — operator and client CLI")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
    /// Admin public key (hex) that must have signed the registry (commands that talk to nodes).
    #[arg(long, global = true, env = "TSN_ADMIN")]
    admin: Option<String>,
    /// This coordinator's TLS identity (`tsn coordinator-new`), required by production nodes.
    #[arg(long, global = true, env = "TSN_CLIENT_CERT")]
    client_cert: Option<PathBuf>,
}

#[derive(Subcommand)]
enum Cmd {
    /// Build the registry from node identities. Each --node is IDENTITY=URL, where IDENTITY is
    /// a node's identity.pub.json (or its directory) and URL is https://host:port.
    Registry {
        #[arg(long)]
        threshold: u16,
        #[arg(long = "node", required = true)]
        nodes: Vec<String>,
        /// A coordinator the nodes accept: its coordinator.pub.json (repeatable).
        #[arg(long = "coordinator")]
        coordinators: Vec<PathBuf>,
        /// Sign the registry with this admin key file (`tsn owner-new`).
        #[arg(long)]
        sign_with: Option<PathBuf>,
        #[arg(long, default_value = "registry.json")]
        out: PathBuf,
    },
    /// Check every node in the registry: reachable over its pinned TLS, same registry, keys held.
    /// Fails if any node is down or disagrees.
    Status {
        #[arg(long, default_value = "registry.json")]
        registry: PathBuf,
    },
    /// Show a registry: digest, signer, nodes and coordinators.
    RegistryInfo {
        #[arg(long, default_value = "registry.json")]
        registry: PathBuf,
    },
    /// Create a coordinator TLS identity; nodes accept it once its .pub.json is in the registry.
    CoordinatorNew {
        #[arg(long)]
        name: String,
        #[arg(long)]
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
    /// Validate a policy file and print its id, key path and addresses.
    PolicyInfo {
        #[arg(long)]
        public: PathBuf,
        #[arg(long)]
        policy: PathBuf,
        #[arg(long)]
        name: String,
    },
    /// Print the address of OWNER's key NAME. Computed offline from the master public key.
    Address {
        #[arg(long)]
        public: PathBuf,
        /// Owner key file (for owner/<pubkey>/<name> keys).
        #[arg(long, required_unless_present = "policy")]
        owner: Option<PathBuf>,
        /// Policy file (for policy/<id>/<name> keys) instead of --owner.
        #[arg(long, conflicts_with = "owner")]
        policy: Option<PathBuf>,
        #[arg(long)]
        name: String,
        #[arg(long)]
        network: String,
        /// Print the address's scriptPublicKey (hex) instead of the address.
        #[arg(long)]
        script: bool,
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
        /// Owner key file (for owner/<pubkey>/<name> keys).
        #[arg(long, required_unless_present = "policy")]
        owner: Option<PathBuf>,
        /// Policy file (for policy/<id>/<name> keys) instead of --owner.
        #[arg(long, conflicts_with = "owner")]
        policy: Option<PathBuf>,
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
        /// Owner key file of an approving signer (repeatable; policy keys).
        #[arg(long = "approver")]
        approvers: Vec<PathBuf>,
        #[arg(long)]
        out: Option<PathBuf>,
    },
    /// Show the UTXOs and balance of OWNER's key NAME, read from a public API.
    Balance {
        #[arg(long)]
        public: PathBuf,
        /// Owner key file (for owner/<pubkey>/<name> keys).
        #[arg(long, required_unless_present = "policy")]
        owner: Option<PathBuf>,
        /// Policy file (for policy/<id>/<name> keys) instead of --owner.
        #[arg(long, conflicts_with = "owner")]
        policy: Option<PathBuf>,
        #[arg(long)]
        name: String,
        #[arg(long)]
        network: String,
        /// REST API base URL (defaults: api.kaspa.org, api-tn10.kaspa.org, api.explorer-eu.hoosat.network).
        #[arg(long)]
        api: Option<String>,
    },
    /// Spend real UTXOs of OWNER's key NAME: select coins, threshold-sign, verify, broadcast.
    Send {
        #[arg(long, default_value = "registry.json")]
        registry: PathBuf,
        #[arg(long)]
        public: PathBuf,
        #[arg(long, default_value = "master")]
        key_id: String,
        /// Owner key file (for owner/<pubkey>/<name> keys).
        #[arg(long, required_unless_present = "policy")]
        owner: Option<PathBuf>,
        /// Policy file (for policy/<id>/<name> keys) instead of --owner.
        #[arg(long, conflicts_with = "owner")]
        policy: Option<PathBuf>,
        #[arg(long)]
        name: String,
        #[arg(long)]
        network: String,
        #[arg(long)]
        to: String,
        /// Amount in sompi (1 KAS/HTN = 100,000,000 sompi).
        #[arg(long, required_unless_present = "all", conflicts_with = "all")]
        amount: Option<u64>,
        /// Send the whole balance minus the fee.
        #[arg(long)]
        all: bool,
        #[arg(long)]
        api: Option<String>,
        /// Owner key file of an approving signer (repeatable; policy keys).
        #[arg(long = "approver")]
        approvers: Vec<PathBuf>,
        /// Fee rate in sompi per gram of mass (default: API estimate, else chain minimum).
        #[arg(long)]
        feerate: Option<f64>,
        /// Refuse to pay more than this fee, in sompi. Guards against a bad fee estimate from the API.
        #[arg(long, default_value_t = 10_000_000)]
        max_fee: u64,
        #[arg(long)]
        signers: Option<String>,
        /// Build, sign and verify, but don't broadcast.
        #[arg(long)]
        dry_run: bool,
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

/// Writes a file readable only by its owner (Unix).
fn write_private(path: &std::path::Path, data: &[u8]) -> Result<()> {
    #[cfg(unix)]
    {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new().write(true).create(true).truncate(true).mode(0o600).open(path)?;
        f.write_all(data)?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        Ok(std::fs::write(path, data)?)
    }
}

fn load_public(p: &PathBuf) -> Result<PublicKeyPackage> {
    Ok(serde_json::from_slice(&std::fs::read(p).with_context(|| format!("reading {}", p.display()))?)?)
}

fn load_policy(p: &PathBuf) -> Result<Policy> {
    let policy: Policy =
        serde_json::from_slice(&std::fs::read(p).with_context(|| format!("reading {}", p.display()))?)?;
    policy.validate()?;
    Ok(policy)
}

/// Key path for `--owner` or `--policy` plus `--name`.
fn key_path(owner: Option<&PathBuf>, policy: Option<&PathBuf>, name: &str) -> Result<(String, Option<Policy>)> {
    match (owner, policy) {
        (Some(o), None) => Ok((auth::owner_path(&load_owner(o)?.verifying_key(), name), None)),
        (None, Some(p)) => {
            let policy = load_policy(p)?;
            Ok((policy.path(name)?, Some(policy)))
        }
        _ => bail!("give --owner or --policy"),
    }
}

/// Owner signature for owner keys; approvals from `approvers` for policy keys.
fn authorization(
    owner: Option<&PathBuf>,
    policy: Option<&Policy>,
    approvers: &[PathBuf],
    key_id: &str,
    path: &str,
    tx: &Tx,
) -> Result<auth::Authorization> {
    match policy {
        Some(policy) => {
            let keys = approvers.iter().map(load_owner).collect::<Result<Vec<_>>>()?;
            ensure!(!keys.is_empty(), "policy keys need at least one --approver");
            auth::authorize_policy(&keys, key_id, path, policy, tx, AUTH_TTL_SECS)
        }
        None => {
            let owner = load_owner(owner.ok_or_else(|| anyhow!("--owner required"))?)?;
            auth::authorize(&owner, key_id, path, tx, AUTH_TTL_SECS)
        }
    }
}

fn coins(sompi: u64) -> String {
    format!("{}.{:08}", sompi / 100_000_000, sompi % 100_000_000)
}

fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

fn parse_signers(s: Option<&str>) -> Result<Option<Vec<u16>>> {
    s.map(|s| s.split(',').map(|x| x.trim().parse().map_err(|_| anyhow!("bad node id {x}"))).collect()).transpose()
}

fn print_line(line: String) {
    println!("{line}");
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    let cli_admin = cli.admin.clone();
    let node_client = |registry: &PathBuf| -> Result<NodeClient> {
        let reg = Registry::load_checked(registry, cli.admin.as_deref())?;
        let tls = cli.client_cert.as_deref().map(tsn_net::load_identity).transpose()?.map(|(_, t)| t);
        NodeClient::new(reg, tls.as_ref())
    };
    match cli.cmd {
        Cmd::Registry { threshold, nodes, coordinators, sign_with, out } => {
            let mut entries = vec![];
            for spec in nodes {
                let (path, url) = spec.split_once('=').ok_or_else(|| anyhow!("--node must be IDENTITY=URL"))?;
                let path = PathBuf::from(path);
                let file = if path.is_dir() { path.join("identity.pub.json") } else { path };
                let ident: NodeIdentity = serde_json::from_slice(
                    &std::fs::read(&file).with_context(|| format!("reading {}", file.display()))?,
                )?;
                let tls =
                    if url.starts_with("https://") {
                        Some(ident.tls_cert_sha256.clone().ok_or_else(|| {
                            anyhow!("{} has no TLS certificate; upgrade the node first", file.display())
                        })?)
                    } else {
                        None
                    };
                entries.push(NodeEntry {
                    id: ident.id,
                    url: url.trim_end_matches('/').to_string(),
                    x25519_pub: ident.x25519_pub,
                    tls_cert_sha256: tls,
                });
            }
            entries.sort_by_key(|e| e.id);
            let mut coords = vec![];
            for f in coordinators {
                coords.push(serde_json::from_slice::<CoordinatorEntry>(
                    &std::fs::read(&f).with_context(|| format!("reading {}", f.display()))?,
                )?);
            }
            let reg = Registry { threshold, nodes: entries, coordinators: coords };
            reg.validate()?;
            let n = reg.n();
            match sign_with {
                Some(k) => {
                    let signed = reg.sign(&load_owner(&k)?)?;
                    std::fs::write(&out, serde_json::to_vec_pretty(&signed)?)?;
                    println!("registry: {threshold}-of-{n}, signed by admin {} -> {}", signed.admin, out.display());
                }
                None => {
                    std::fs::write(&out, serde_json::to_vec_pretty(&reg)?)?;
                    println!("registry: {threshold}-of-{n}, unsigned (dev) -> {}", out.display());
                }
            }
            println!("digest {}", reg.digest_hex()?);
        }
        Cmd::Status { registry } => {
            let client = node_client(&registry)?;
            let digest = client.registry.digest_hex()?;
            let mut problems = 0;
            for n in &client.registry.nodes {
                match client.info(n.id).await {
                    Ok(i) if i.registry == digest => println!("node {:<3} up    keys {:?}", n.id, i.keys),
                    Ok(_) => {
                        problems += 1;
                        println!("node {:<3} up    but runs with a DIFFERENT registry", n.id)
                    }
                    Err(e) => {
                        problems += 1;
                        println!("node {:<3} DOWN  {e:#}", n.id)
                    }
                }
            }
            ensure!(problems == 0, "{problems} node(s) down or misconfigured");
        }
        Cmd::RegistryInfo { registry } => {
            let reg = Registry::load_checked(&registry, cli_admin.as_deref())?;
            let v: serde_json::Value = serde_json::from_slice(&std::fs::read(&registry)?)?;
            println!("digest     {}", reg.digest_hex()?);
            match v.get("admin").and_then(|a| a.as_str()) {
                Some(a) if cli_admin.is_some() => println!("signed by  {a} (matches --admin)"),
                Some(a) => println!("signed by  {a} (pass --admin to require this key)"),
                None => println!("signed by  nobody (dev registry)"),
            }
            println!("threshold  {}-of-{}", reg.threshold, reg.n());
            for e in &reg.nodes {
                println!("node {:<5} {}  tls {}", e.id, e.url, e.tls_cert_sha256.as_deref().unwrap_or("-"));
            }
            for c in &reg.coordinators {
                println!("coordinator {}  tls {}", c.name, c.tls_cert_sha256);
            }
        }
        Cmd::CoordinatorNew { name, out } => {
            ensure!(!out.exists(), "{} exists", out.display());
            let tls = tsn_net::TlsIdentity::generate(&name)?;
            let entry = CoordinatorEntry { name: name.clone(), tls_cert_sha256: tls.fingerprint() };
            write_private(&out, &serde_json::to_vec_pretty(&serde_json::json!({ "name": name, "tls": tls }))?)?;
            let public = out.with_extension("pub.json");
            std::fs::write(&public, serde_json::to_vec_pretty(&entry)?)?;
            println!("coordinator {name}: tls {}; add {} to the registry", entry.tls_cert_sha256, public.display());
        }
        Cmd::Dkg { registry, key_id, out } => {
            let client = node_client(&registry)?;
            let pkp = client.dkg(&key_id).await?;
            std::fs::write(&out, serde_json::to_vec_pretty(&pkp)?)?;
            println!("DKG complete: master key {}", hex::encode(pkp.verifying_key().serialize()?));
            println!("no node and no coordinator ever held the private key; public package -> {}", out.display());
        }
        Cmd::OwnerNew { out } => {
            let sk = SigningKey::generate(&mut OsRng);
            let f = OwnerFile {
                ed25519_secret: hex::encode(sk.to_bytes()),
                ed25519_public: hex::encode(sk.verifying_key().as_bytes()),
            };
            std::fs::write(&out, serde_json::to_vec_pretty(&f)?)?;
            println!("owner {}", f.ed25519_public);
        }
        Cmd::PolicyInfo { public, policy, name } => {
            let master = load_public(&public)?;
            let policy = load_policy(&policy)?;
            let path = policy.path(&name)?;
            println!("policy id  {}", policy.id());
            println!("path       {path}");
            println!("canonical  {}", policy.canonical());
            for network in
                [Network::KaspaMainnet, Network::KaspaTestnet, Network::HoosatMainnet, Network::HoosatTestnet]
            {
                let (addr, _) = payment::path_address(master.verifying_key(), network, &path)?;
                println!("{:<11}{addr}", network.prefix());
            }
        }
        Cmd::Address { public, owner, policy, name, network, script } => {
            let network = Network::parse(&network)?;
            let master = load_public(&public)?;
            let (path, _) = key_path(owner.as_ref(), policy.as_ref(), &name)?;
            let (addr, spk) = payment::path_address(master.verifying_key(), network, &path)?;
            println!("{}", if script { hex::encode(spk) } else { addr });
        }
        Cmd::Sign {
            registry,
            public,
            key_id,
            owner,
            policy,
            approvers,
            path_owner,
            name,
            network,
            to,
            amount,
            utxo_amount,
            signers,
            out,
        } => {
            let network = Network::parse(&network)?;
            let client = node_client(&registry)?;
            let public = load_public(&public)?;
            let (path, policy) = match &path_owner {
                // Impersonation test: the path names one owner, the request is signed by another.
                Some(p) => (auth::owner_path(&load_owner(p)?.verifying_key(), &name), None),
                None => key_path(owner.as_ref(), policy.as_ref(), &name)?,
            };
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
                outputs: vec![
                    TxOutput { address: to.clone(), amount },
                    TxOutput { address: from.clone(), amount: change },
                ],
                lock_time: 0,
            };
            println!("from   {from}\nto     {to}\namount {amount} sompi (change {change}, fee {fee})");
            let authz = authorization(owner.as_ref(), policy.as_ref(), &approvers, &key_id, &path, &tx)?;
            let signers = parse_signers(signers.as_deref())?;
            client.sign_inputs(&key_id, &path, &authz, &public, &mut tx, signers.as_deref(), &print_line).await?;
            chain::verify_signed(&tx)?;
            println!(
                "signature valid: {}",
                if network.is_hoosat() {
                    "BIP340 over Hoosat BLAKE3 sighash"
                } else {
                    "accepted by the Kaspa consensus script engine"
                }
            );
            if let Some(out) = out {
                std::fs::write(&out, serde_json::to_vec_pretty(&tx)?)?;
                println!("signed tx -> {}", out.display());
            }
        }
        Cmd::Balance { public, owner, policy, name, network, api } => {
            let network = Network::parse(&network)?;
            let master = load_public(&public)?;
            let (path, _) = key_path(owner.as_ref(), policy.as_ref(), &name)?;
            let (addr, _) = payment::path_address(master.verifying_key(), network, &path)?;
            let api = ChainApi::new(network, api)?;
            let utxos = api.utxos(&addr).await?;
            let total: u64 = utxos.iter().map(|u| u.entry.amount).sum();
            println!("address {addr}");
            for u in &utxos {
                let kind = if u.entry.is_coinbase { ", coinbase" } else { "" };
                println!(
                    "  {}:{}  {} sompi  (DAA {}{kind})",
                    u.outpoint.transaction_id, u.outpoint.index, u.entry.amount, u.entry.block_daa_score
                );
            }
            println!("balance {total} sompi ({} UTXOs) = {}", utxos.len(), coins(total));
        }
        Cmd::Send {
            registry,
            public,
            key_id,
            owner,
            policy,
            approvers,
            name,
            network,
            to,
            amount,
            all,
            api,
            feerate,
            max_fee,
            signers,
            dry_run,
            out,
        } => {
            let network = Network::parse(&network)?;
            let client = node_client(&registry)?;
            let public = load_public(&public)?;
            let (path, policy) = key_path(owner.as_ref(), policy.as_ref(), &name)?;
            let api = ChainApi::new(network, api)?;
            let amount = if all { Amount::All } else { Amount::Exact(amount.expect("clap enforces amount or --all")) };
            let req = payment::Request { network, path, to: to.clone(), amount, feerate, max_fee };
            // Shared by CLI runs against the same network folder: skips coins spent seconds ago.
            let spent =
                RecentSpends::file(registry.parent().unwrap_or(std::path::Path::new(".")).join(".recent-spends.json"));
            let p = payment::prepare(&api, public.verifying_key(), &req, &spent).await?;
            if p.skipped_spent_utxos > 0 {
                println!(
                    "skipping {} coin(s) spent by a recent payment (the API hasn't caught up)",
                    p.skipped_spent_utxos
                );
            }
            if p.skipped_young_utxos > 0 {
                println!(
                    "skipping {} UTXO(s) younger than Hoosat's minimum input age; retry shortly to include them",
                    p.skipped_young_utxos
                );
            }
            let mut tx = p.tx;
            println!("from   {}\nto     {to}", p.from);
            println!(
                "amount {} sompi, change {}, fee {} ({} grams at {} sompi/gram), {} input(s)",
                tx.outputs[0].amount,
                p.change,
                p.fee,
                p.mass,
                p.feerate,
                tx.inputs.len()
            );

            let authz = authorization(owner.as_ref(), policy.as_ref(), &approvers, &key_id, &p.path, &tx)?;
            let signers = parse_signers(signers.as_deref())?;
            client.sign_inputs(&key_id, &p.path, &authz, &public, &mut tx, signers.as_deref(), &print_line).await?;
            chain::verify_signed(&tx)?;
            println!(
                "signatures valid ({})",
                if network.is_hoosat() { "BIP340 over Hoosat sighash" } else { "Kaspa consensus script engine" }
            );
            if !network.is_hoosat() {
                match api.server_mass(&tx).await {
                    Ok(m) => println!("API mass check: {m} (local estimate {})", p.mass),
                    Err(e) => println!("API mass check unavailable: {e:#}"),
                }
            }
            if let Some(out) = &out {
                std::fs::write(out, serde_json::to_vec_pretty(&tx)?)?;
                println!("signed tx -> {}", out.display());
            }
            if dry_run {
                println!("dry run: not broadcast");
            } else {
                let txid = api.submit(&tx).await?;
                spent.record(&tx);
                println!("broadcast: {txid}");
                if let Some(url) = chain_api::explorer_tx_url(network, &txid).filter(|_| api.is_default) {
                    println!("{url}");
                }
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
