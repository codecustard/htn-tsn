//! tsn-node: one signer in the threshold network. Holds one share per master key, never the key.
//!
//! Before contributing a signature share, every node independently:
//!   1. verifies the owner's signature on the request (the path names its owner),
//!   2. checks the input being signed belongs to that path's derived key,
//!   3. enforces its spend policy on the full transaction,
//!   4. recomputes the sighash itself and refuses if the coordinator's message differs,
//!   5. burns the nonce for the session (single use), success or not.

use anyhow::{anyhow, bail, ensure, Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use clap::{Parser, Subcommand};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};
use tsn_core::{
    auth, chain, derive,
    frost::{
        self,
        keys::{dkg, KeyPackage, PublicKeyPackage},
    },
    identifier,
    proto::*,
    seal,
};
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Parser)]
#[command(about = "Threshold signing node for Hoosat/Kaspa")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Create this node's identity (X25519 key) in DIR.
    Keygen {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        id: u16,
    },
    /// Serve the signing API.
    Run {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        registry: PathBuf,
        #[arg(long)]
        port: u16,
        /// Max sompi a single request may send to addresses other than the key's own (change).
        #[arg(long, default_value_t = 10_000_000_000)]
        max_external_spend: u64,
        /// Demo only: return corrupted signature shares to exercise identifiable abort.
        #[arg(long)]
        byzantine: bool,
    },
}

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    id: u16,
    x25519_secret: String,
}

#[derive(Serialize, Deserialize, Clone)]
struct StoredKey {
    key_package: KeyPackage,
    public_key_package: PublicKeyPackage,
}

struct Node {
    id: u16,
    secret: StaticSecret,
    registry: Registry,
    dir: PathBuf,
    max_external_spend: u64,
    byzantine: bool,
    keys: Mutex<HashMap<String, StoredKey>>,
    dkg_r1: Mutex<HashMap<String, dkg::round1::SecretPackage>>,
    dkg_r2: Mutex<HashMap<String, dkg::round2::SecretPackage>>,
    nonces: Mutex<HashMap<String, (String, frost::round1::SigningNonces)>>,
}

type Shared = Arc<Node>;

struct AppError(anyhow::Error);
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        (StatusCode::BAD_REQUEST, Json(ErrorResp { error: format!("{:#}", self.0) })).into_response()
    }
}
impl<E: Into<anyhow::Error>> From<E> for AppError {
    fn from(e: E) -> Self {
        AppError(e.into())
    }
}
type ApiResult<T> = Result<Json<T>, AppError>;

impl Node {
    fn log(&self, msg: impl AsRef<str>) {
        println!("[node {}] {}", self.id, msg.as_ref());
    }

    fn id_map(&self) -> Result<BTreeMap<frost::Identifier, u16>> {
        self.registry.nodes.iter().map(|n| Ok((identifier(n.id)?, n.id))).collect()
    }

    fn to_frost_map<T: Clone>(&self, m: &BTreeMap<u16, T>) -> Result<BTreeMap<frost::Identifier, T>> {
        let expected: Vec<u16> = self.registry.nodes.iter().map(|n| n.id).filter(|i| *i != self.id).collect();
        let got: Vec<u16> = m.keys().copied().collect();
        ensure!(got == expected, "expected packages from nodes {expected:?}, got {got:?}");
        m.iter().map(|(k, v)| Ok((identifier(*k)?, v.clone()))).collect()
    }

    fn key(&self, key_id: &str) -> Result<StoredKey> {
        self.keys.lock().unwrap().get(key_id).cloned().ok_or_else(|| anyhow!("unknown key {key_id}"))
    }

    fn persist(&self, key_id: &str, k: &StoredKey) -> Result<()> {
        let dir = self.dir.join("keys");
        std::fs::create_dir_all(&dir)?;
        std::fs::write(dir.join(format!("{key_id}.json")), serde_json::to_vec_pretty(k)?)?;
        Ok(())
    }
}

fn require(cond: bool, msg: impl std::fmt::Display) -> Result<()> {
    if cond { Ok(()) } else { Err(anyhow!("{msg}")) }
}

fn valid_key_id(k: &str) -> Result<()> {
    ensure!(!k.is_empty() && k.len() <= 64 && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'), "bad key id");
    Ok(())
}

async fn info(State(n): State<Shared>) -> ApiResult<InfoResp> {
    let keys = n.keys.lock().unwrap().keys().cloned().collect();
    Ok(Json(InfoResp { id: n.id, x25519_pub: hex::encode(PublicKey::from(&n.secret).as_bytes()), keys }))
}

async fn dkg_part1(State(n): State<Shared>, Json(req): Json<DkgPart1Req>) -> ApiResult<DkgPart1Resp> {
    valid_key_id(&req.key_id)?;
    require(n.key(&req.key_id).is_err(), format!("key {} already exists", req.key_id))?;
    let (secret, package) = dkg::part1(identifier(n.id)?, n.registry.n(), n.registry.threshold, OsRng)?;
    n.dkg_r1.lock().unwrap().insert(req.key_id.clone(), secret);
    n.log(format!("DKG {}: round 1 (n={}, t={})", req.key_id, n.registry.n(), n.registry.threshold));
    Ok(Json(DkgPart1Resp { package }))
}

async fn dkg_part2(State(n): State<Shared>, Json(req): Json<DkgPart2Req>) -> ApiResult<DkgPart2Resp> {
    let secret = n.dkg_r1.lock().unwrap().remove(&req.key_id).ok_or_else(|| anyhow!("no round 1 for {}", req.key_id))?;
    let r1 = n.to_frost_map(&req.round1_packages)?;
    let (r2_secret, outgoing) = dkg::part2(secret, &r1)?;
    let ids = n.id_map()?;
    let mut sealed = BTreeMap::new();
    for (to, pkg) in outgoing {
        let to = ids[&to];
        let ct = seal::seal(&n.secret, &n.registry.x25519(to)?, &req.key_id, n.id, to, &pkg.serialize()?)?;
        sealed.insert(to, hex::encode(ct));
    }
    n.dkg_r2.lock().unwrap().insert(req.key_id.clone(), r2_secret);
    n.log(format!("DKG {}: round 2, sealed {} share packages to peers", req.key_id, sealed.len()));
    Ok(Json(DkgPart2Resp { sealed }))
}

async fn dkg_part3(State(n): State<Shared>, Json(req): Json<DkgPart3Req>) -> ApiResult<DkgPart3Resp> {
    let r2_secret = n.dkg_r2.lock().unwrap().remove(&req.key_id).ok_or_else(|| anyhow!("no round 2 for {}", req.key_id))?;
    let r1 = n.to_frost_map(&req.round1_packages)?;
    let mut r2 = BTreeMap::new();
    for (from, hex_ct) in &req.sealed_for_me {
        let pt = seal::open(&n.secret, &n.registry.x25519(*from)?, &req.key_id, *from, n.id, &hex::decode(hex_ct)?)?;
        r2.insert(*from, dkg::round2::Package::deserialize(&pt)?);
    }
    let r2 = n.to_frost_map(&r2)?;
    let (key_package, public_key_package) = dkg::part3(&r2_secret, &r1, &r2)?;
    let stored = StoredKey { key_package, public_key_package: public_key_package.clone() };
    n.persist(&req.key_id, &stored)?;
    n.keys.lock().unwrap().insert(req.key_id.clone(), stored);
    let vk = hex::encode(public_key_package.verifying_key().serialize()?);
    n.log(format!("DKG {}: done, group key {vk}", req.key_id));
    Ok(Json(DkgPart3Resp { public_key_package }))
}

async fn sign_commit(State(n): State<Shared>, Json(req): Json<CommitReq>) -> ApiResult<CommitResp> {
    let key = n.key(&req.key_id)?;
    let mut nonces = n.nonces.lock().unwrap();
    require(!nonces.contains_key(&req.session_id), "session already used")?;
    let (secret_nonces, commitments) = frost::round1::commit(key.key_package.signing_share(), &mut OsRng);
    nonces.insert(req.session_id, (req.key_id, secret_nonces));
    Ok(Json(CommitResp { commitments }))
}

fn check_request(n: &Node, req: &ShareReq, key: &StoredKey) -> Result<[u8; 32]> {
    // 1. Owner authorization.
    let tx_json = serde_json::to_string(&req.tx)?;
    let digest = auth::request_digest(&req.key_id, &req.path, &req.session_id, &tx_json, req.input_index);
    auth::verify_request(&req.path, &digest, &req.owner_sig)?;
    // 2. The input must be owned by this path's derived key.
    let own_script = chain::p2pk_script(&derive::child_xonly(key.public_key_package.verifying_key(), &req.path)?);
    let input = req.tx.inputs.get(req.input_index).ok_or_else(|| anyhow!("input index out of range"))?;
    ensure!(hex::decode(&input.script_pubkey)? == own_script, "input {} is not owned by {}", req.input_index, req.path);
    // 3. Policy.
    let external = chain::external_spend(&req.tx, &own_script)?;
    if external > n.max_external_spend {
        bail!("policy: sends {external} sompi externally, limit is {}", n.max_external_spend);
    }
    // 4. Sign only what we computed ourselves.
    let sighash = chain::sighash(&req.tx, req.input_index)?;
    ensure!(req.signing_package.message().as_slice() == sighash, "coordinator message does not match transaction sighash");
    Ok(sighash)
}

async fn sign_share(State(n): State<Shared>, Json(req): Json<ShareReq>) -> ApiResult<ShareResp> {
    // 5. Nonces are single-use: remove before anything can fail.
    let (key_id, nonces) = n.nonces.lock().unwrap().remove(&req.session_id).ok_or_else(|| anyhow!("unknown or used session"))?;
    require(key_id == req.key_id, "session belongs to another key")?;
    let key = n.key(&req.key_id)?;
    if let Err(e) = check_request(&n, &req, &key) {
        n.log(format!("REFUSED {} on {}: {e:#}", req.path, req.tx.network.prefix()));
        return Err(e.into());
    }
    let child = derive::key_package(&key.key_package, &req.path)?;
    let mut share = frost::round2::sign(&req.signing_package, &nonces, &child)?;
    if n.byzantine {
        let mut bytes = share.serialize();
        let last = bytes.len() - 1;
        bytes[last] ^= 1;
        share = frost::round2::SignatureShare::deserialize(&bytes)?;
        n.log(format!("signed {} (BYZANTINE: share corrupted)", req.path));
    } else {
        n.log(format!("signed input {} for {} on {}", req.input_index, req.path, req.tx.network.prefix()));
    }
    Ok(Json(ShareResp { share }))
}

fn load_identity(dir: &Path) -> Result<IdentityFile> {
    let s = std::fs::read_to_string(dir.join("identity.json")).context("missing identity.json; run keygen first")?;
    Ok(serde_json::from_str(&s)?)
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Keygen { dir, id } => {
            std::fs::create_dir_all(&dir)?;
            ensure!(!dir.join("identity.json").exists(), "identity already exists in {}", dir.display());
            let secret = StaticSecret::random_from_rng(OsRng);
            let public = hex::encode(PublicKey::from(&secret).as_bytes());
            std::fs::write(dir.join("identity.json"), serde_json::to_vec_pretty(&IdentityFile { id, x25519_secret: hex::encode(secret.to_bytes()) })?)?;
            std::fs::write(dir.join("identity.pub.json"), serde_json::to_vec_pretty(&NodeIdentity { id, x25519_pub: public.clone() })?)?;
            println!("node {id} identity: {public}");
        }
        Cmd::Run { dir, registry, port, max_external_spend, byzantine } => {
            let ident = load_identity(&dir)?;
            let bytes: [u8; 32] = hex::decode(&ident.x25519_secret)?.try_into().map_err(|_| anyhow!("bad secret"))?;
            let registry = Registry::load(&registry)?;
            let secret = StaticSecret::from(bytes);
            ensure!(registry.x25519(ident.id)? == *PublicKey::from(&secret).as_bytes(), "registry entry does not match this node's identity");
            let mut keys = HashMap::new();
            if let Ok(rd) = std::fs::read_dir(dir.join("keys")) {
                for e in rd.flatten() {
                    let name = e.file_name().to_string_lossy().trim_end_matches(".json").to_string();
                    keys.insert(name, serde_json::from_slice(&std::fs::read(e.path())?)?);
                }
            }
            let node = Arc::new(Node {
                id: ident.id,
                secret,
                registry,
                dir,
                max_external_spend,
                byzantine,
                keys: Mutex::new(keys),
                dkg_r1: Default::default(),
                dkg_r2: Default::default(),
                nonces: Default::default(),
            });
            let app = Router::new()
                .route("/info", get(info))
                .route("/dkg/part1", post(dkg_part1))
                .route("/dkg/part2", post(dkg_part2))
                .route("/dkg/part3", post(dkg_part3))
                .route("/sign/commit", post(sign_commit))
                .route("/sign/share", post(sign_share))
                .with_state(node.clone());
            let listener = tokio::net::TcpListener::bind(("127.0.0.1", port)).await?;
            node.log(format!("listening on 127.0.0.1:{port}{}", if byzantine { " (byzantine)" } else { "" }));
            axum::serve(listener, app).await?;
        }
    }
    Ok(())
}
