//! tsn-node: one signer in the threshold network. Holds one share per master key, never the key.
//!
//! Before contributing a signature share, every node independently:
//!   1. verifies the owner's signature on the request (the path names its owner),
//!   2. checks the input being signed belongs to that path's derived key,
//!   3. enforces its spend policy on the full transaction,
//!   4. recomputes the sighash itself and refuses if the coordinator's message differs,
//!   5. burns the nonce for the session (single use), success or not.
//!
//! In production mode (the default) the node also requires: a registry signed by the pinned admin
//! key, TLS with its registered certificate, a registered coordinator on every connection, and a
//! passphrase that encrypts its identity and key shares on disk. `--dev` relaxes these for local
//! testing.

use anyhow::{anyhow, bail, ensure, Context, Result};
use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use clap::{Args, Parser, Subcommand};
use rand::rngs::OsRng;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    net::SocketAddr,
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
    vault::{self, KdfParams},
};
use tsn_net::TlsIdentity;
use x25519_dalek::{PublicKey, StaticSecret};

#[derive(Parser)]
#[command(about = "Threshold signing node for Hoosat/Kaspa")]
struct Cli {
    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Args, Clone)]
struct Secrets {
    /// Passphrase that encrypts this node's identity and key shares on disk.
    #[arg(long, env = "TSN_NODE_PASSPHRASE", hide_env_values = true)]
    passphrase: Option<String>,
    /// Read the passphrase from this file instead (e.g. a Docker secret).
    #[arg(long, env = "TSN_NODE_PASSPHRASE_FILE", conflicts_with = "passphrase")]
    passphrase_file: Option<PathBuf>,
    /// Local testing: allow unencrypted files, plain HTTP and an unsigned registry.
    #[arg(long)]
    dev: bool,
}

impl Secrets {
    fn passphrase(&self) -> Result<Option<String>> {
        let p = match (&self.passphrase, &self.passphrase_file) {
            (Some(p), _) => Some(p.clone()),
            (None, Some(f)) => Some(
                std::fs::read_to_string(f)
                    .with_context(|| format!("reading {}", f.display()))?
                    .trim_end_matches(['\n', '\r'])
                    .to_string(),
            ),
            (None, None) => None,
        };
        match p {
            Some(p) if p.len() < 12 => bail!("passphrase must be at least 12 characters"),
            None if !self.dev => bail!(
                "set TSN_NODE_PASSPHRASE or --passphrase-file (it encrypts this node's secrets), or use --dev for local testing"
            ),
            p => Ok(p),
        }
    }
}

#[derive(Subcommand)]
enum Cmd {
    /// Create this node's identity in DIR: an X25519 key (DKG) and a TLS certificate.
    Keygen {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        id: u16,
        #[command(flatten)]
        secrets: Secrets,
    },
    /// Serve the signing API.
    Run {
        #[arg(long)]
        dir: PathBuf,
        #[arg(long)]
        registry: PathBuf,
        /// Admin public key (hex) that must have signed the registry.
        #[arg(long, env = "TSN_ADMIN")]
        admin: Option<String>,
        /// Address to listen on, e.g. 0.0.0.0:7001.
        #[arg(long, required_unless_present = "port")]
        listen: Option<SocketAddr>,
        /// Shorthand for --listen 127.0.0.1:PORT.
        #[arg(long)]
        port: Option<u16>,
        /// Max sompi a single request may send to addresses other than the key's own (change).
        #[arg(long, default_value_t = 10_000_000_000)]
        max_external_spend: u64,
        /// Demo only: return corrupted signature shares to exercise identifiable abort.
        #[arg(long)]
        byzantine: bool,
        #[command(flatten)]
        secrets: Secrets,
    },
    /// Upgrade an existing node directory: add a TLS certificate if missing and encrypt the
    /// identity and key shares with the passphrase. Keys and addresses stay the same.
    Upgrade {
        #[arg(long)]
        dir: PathBuf,
        #[command(flatten)]
        secrets: Secrets,
    },
}

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    id: u16,
    x25519_secret: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tls: Option<TlsIdentity>,
}

/// Reads and writes this node's secret files, encrypted when a passphrase is set.
#[derive(Clone)]
struct Store {
    dir: PathBuf,
    passphrase: Option<String>,
}

impl Store {
    fn read(&self, file: &Path, label: &str) -> Result<Vec<u8>> {
        let bytes = std::fs::read(file).with_context(|| format!("reading {}", file.display()))?;
        if vault::is_sealed(&bytes) {
            let p = self
                .passphrase
                .as_ref()
                .ok_or_else(|| anyhow!("{} is encrypted; set the passphrase", file.display()))?;
            vault::open(&bytes, p, label).map_err(|e| anyhow!("{}: {e}", file.display()))
        } else {
            ensure!(
                self.passphrase.is_none(),
                "{} is not encrypted; run `tsn-node upgrade --dir {}` to encrypt it",
                file.display(),
                self.dir.display()
            );
            Ok(bytes)
        }
    }

    fn write(&self, file: &Path, label: &str, plaintext: &[u8]) -> Result<()> {
        let data = match &self.passphrase {
            Some(p) => vault::seal(plaintext, p, label, KdfParams::default())?,
            None => plaintext.to_vec(),
        };
        let tmp = file.with_extension("tmp");
        write_private(&tmp, &data)?;
        std::fs::rename(&tmp, file)?;
        Ok(())
    }

    fn identity(&self) -> Result<IdentityFile> {
        let f = self.dir.join("identity.json");
        ensure!(f.exists(), "missing {}; run keygen first", f.display());
        Ok(serde_json::from_slice(&self.read(&f, "identity")?)?)
    }

    fn key_file(&self, key_id: &str) -> PathBuf {
        self.dir.join("keys").join(format!("{key_id}.json"))
    }
}

/// Writes a file readable only by its owner (Unix).
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
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

#[derive(Serialize, Deserialize, Clone)]
struct StoredKey {
    key_package: KeyPackage,
    public_key_package: PublicKeyPackage,
}

struct Node {
    id: u16,
    secret: StaticSecret,
    registry: Registry,
    registry_digest: String,
    store: Store,
    max_external_spend: u64,
    byzantine: bool,
    keys: Mutex<HashMap<String, StoredKey>>,
    dkg_r1: Mutex<HashMap<String, dkg::round1::SecretPackage>>,
    dkg_r2: Mutex<HashMap<String, dkg::round2::SecretPackage>>,
    nonces: Mutex<HashMap<String, PendingNonce>>,
    /// Signing sessions served per authorization (request_id -> (count, expires_at)).
    requests: Mutex<HashMap<String, (u32, u64)>>,
}

type Shared = Arc<Node>;

/// Secret nonces waiting for round 2. Never written to disk; evicted after `NONCE_TTL_SECS`.
struct PendingNonce {
    key_id: String,
    nonces: frost::round1::SigningNonces,
    created: u64,
}

/// Unanswered commitments older than this are discarded.
const NONCE_TTL_SECS: u64 = 300;
/// Most outstanding commitments a node holds (bounds memory under request floods).
const MAX_PENDING_NONCES: usize = 10_000;
/// Most signing sessions one authorization may open (retries around bad nodes, per input).
const MAX_SESSIONS_PER_REQUEST: u32 = 64;

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
        std::fs::create_dir_all(self.store.dir.join("keys"))?;
        self.store.write(&self.store.key_file(key_id), &format!("key:{key_id}"), &serde_json::to_vec_pretty(k)?)
    }
}

fn require(cond: bool, msg: impl std::fmt::Display) -> Result<()> {
    if cond {
        Ok(())
    } else {
        Err(anyhow!("{msg}"))
    }
}

fn short(h: &str) -> String {
    if h.is_empty() {
        "(none)".into()
    } else {
        format!("{}…", &h[..h.len().min(12)])
    }
}

fn valid_key_id(k: &str) -> Result<()> {
    ensure!(
        !k.is_empty() && k.len() <= 64 && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_'),
        "bad key id"
    );
    Ok(())
}

async fn info(State(n): State<Shared>) -> ApiResult<InfoResp> {
    let keys = n.keys.lock().unwrap().keys().cloned().collect();
    Ok(Json(InfoResp {
        id: n.id,
        x25519_pub: hex::encode(PublicKey::from(&n.secret).as_bytes()),
        keys,
        registry: n.registry_digest.clone(),
    }))
}

async fn dkg_part1(State(n): State<Shared>, Json(req): Json<DkgPart1Req>) -> ApiResult<DkgPart1Resp> {
    valid_key_id(&req.key_id)?;
    require(n.key(&req.key_id).is_err(), format!("key {} already exists", req.key_id))?;
    require(
        req.registry == n.registry_digest,
        format!(
            "coordinator's registry {} differs from this node's {}",
            short(&req.registry),
            short(&n.registry_digest)
        ),
    )?;
    let (secret, package) = dkg::part1(identifier(n.id)?, n.registry.n(), n.registry.threshold, OsRng)?;
    n.dkg_r1.lock().unwrap().insert(req.key_id.clone(), secret);
    n.log(format!("DKG {}: round 1 (n={}, t={})", req.key_id, n.registry.n(), n.registry.threshold));
    Ok(Json(DkgPart1Resp { package }))
}

async fn dkg_part2(State(n): State<Shared>, Json(req): Json<DkgPart2Req>) -> ApiResult<DkgPart2Resp> {
    let secret =
        n.dkg_r1.lock().unwrap().remove(&req.key_id).ok_or_else(|| anyhow!("no round 1 for {}", req.key_id))?;
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
    let r2_secret =
        n.dkg_r2.lock().unwrap().remove(&req.key_id).ok_or_else(|| anyhow!("no round 2 for {}", req.key_id))?;
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
    let now = auth::now_secs();
    let mut nonces = n.nonces.lock().unwrap();
    nonces.retain(|_, p| p.created + NONCE_TTL_SECS > now);
    require(nonces.len() < MAX_PENDING_NONCES, "too many pending signing sessions; retry later")?;
    require(!nonces.contains_key(&req.session_id), "session already used")?;
    let (secret_nonces, commitments) = frost::round1::commit(key.key_package.signing_share(), &mut OsRng);
    nonces.insert(req.session_id, PendingNonce { key_id: req.key_id, nonces: secret_nonces, created: now });
    Ok(Json(CommitResp { commitments }))
}

fn check_request(n: &Node, req: &ShareReq, key: &StoredKey) -> Result<[u8; 32]> {
    // 1. Authorization: the path's owner, or a passing clause of the path's policy; unexpired
    //    and not overused.
    let now = auth::now_secs();
    let own_script = chain::p2pk_script(&derive::child_xonly(key.public_key_package.verifying_key(), &req.path)?);
    auth::verify(&req.key_id, &req.path, &req.tx, &req.auth, &own_script, now)?;
    {
        let mut requests = n.requests.lock().unwrap();
        requests.retain(|_, (_, exp)| *exp >= now);
        let entry = requests.entry(req.auth.request_id.clone()).or_insert((0, req.auth.expires_at));
        ensure!(entry.0 < MAX_SESSIONS_PER_REQUEST, "authorization used for too many signing sessions");
        entry.0 += 1;
    }
    // 2. The input must be owned by this path's derived key.
    let input = req.tx.inputs.get(req.input_index).ok_or_else(|| anyhow!("input index out of range"))?;
    ensure!(hex::decode(&input.script_pubkey)? == own_script, "input {} is not owned by {}", req.input_index, req.path);
    // 3. This node's own spend cap, on top of anything the key's policy allows.
    let external = chain::external_spend(&req.tx, &own_script)?;
    if external > n.max_external_spend {
        bail!("node spend cap: sends {external} sompi externally, limit is {}", n.max_external_spend);
    }
    // 4. Sign only what we computed ourselves.
    let sighash = chain::sighash(&req.tx, req.input_index)?;
    ensure!(
        req.signing_package.message().as_slice() == sighash,
        "coordinator message does not match transaction sighash"
    );
    Ok(sighash)
}

async fn sign_share(State(n): State<Shared>, Json(req): Json<ShareReq>) -> ApiResult<ShareResp> {
    // 5. Nonces are single-use: remove before anything can fail.
    let pending = n.nonces.lock().unwrap().remove(&req.session_id).ok_or_else(|| anyhow!("unknown or used session"))?;
    require(pending.key_id == req.key_id, "session belongs to another key")?;
    let nonces = pending.nonces;
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

fn load_keys(store: &Store) -> Result<HashMap<String, StoredKey>> {
    let mut keys = HashMap::new();
    if let Ok(rd) = std::fs::read_dir(store.dir.join("keys")) {
        for e in rd.flatten() {
            let name = e.file_name().to_string_lossy().to_string();
            let Some(key_id) = name.strip_suffix(".json") else { continue };
            let k = store.read(&e.path(), &format!("key:{key_id}"))?;
            keys.insert(key_id.to_string(), serde_json::from_slice(&k)?);
        }
    }
    Ok(keys)
}

fn write_public_identity(dir: &Path, id: &IdentityFile) -> Result<NodeIdentity> {
    let secret = StaticSecret::from(x25519_bytes(&id.x25519_secret)?);
    let public = NodeIdentity {
        id: id.id,
        x25519_pub: hex::encode(PublicKey::from(&secret).as_bytes()),
        tls_cert_sha256: id.tls.as_ref().map(|t| t.fingerprint()),
    };
    std::fs::write(dir.join("identity.pub.json"), serde_json::to_vec_pretty(&public)?)?;
    Ok(public)
}

fn x25519_bytes(h: &str) -> Result<[u8; 32]> {
    hex::decode(h)?.try_into().map_err(|_| anyhow!("bad x25519 secret"))
}

#[tokio::main]
async fn main() -> Result<()> {
    match Cli::parse().cmd {
        Cmd::Keygen { dir, id, secrets } => {
            let passphrase = secrets.passphrase()?;
            std::fs::create_dir_all(&dir)?;
            ensure!(!dir.join("identity.json").exists(), "identity already exists in {}", dir.display());
            let secret = StaticSecret::random_from_rng(OsRng);
            let ident = IdentityFile {
                id,
                x25519_secret: hex::encode(secret.to_bytes()),
                tls: Some(TlsIdentity::generate(&format!("tsn-node-{id}"))?),
            };
            let store = Store { dir: dir.clone(), passphrase };
            store.write(&dir.join("identity.json"), "identity", &serde_json::to_vec_pretty(&ident)?)?;
            let public = write_public_identity(&dir, &ident)?;
            println!(
                "node {id}: x25519 {} tls {} ({}); send {} to the admin",
                public.x25519_pub,
                public.tls_cert_sha256.unwrap_or_default(),
                if store.passphrase.is_some() { "encrypted" } else { "UNENCRYPTED, dev only" },
                dir.join("identity.pub.json").display()
            );
        }
        Cmd::Upgrade { dir, secrets } => {
            let passphrase = secrets.passphrase()?;
            let old = Store { dir: dir.clone(), passphrase: passphrase.clone() };
            let read_any = |f: &Path, label: &str| -> Result<Vec<u8>> {
                let b = std::fs::read(f)?;
                if vault::is_sealed(&b) {
                    old.read(f, label)
                } else {
                    Ok(b)
                }
            };
            let mut ident: IdentityFile = serde_json::from_slice(&read_any(&dir.join("identity.json"), "identity")?)?;
            if ident.tls.is_none() {
                ident.tls = Some(TlsIdentity::generate(&format!("tsn-node-{}", ident.id))?);
                println!("added a TLS certificate");
            }
            let mut keys = vec![];
            if let Ok(rd) = std::fs::read_dir(dir.join("keys")) {
                for e in rd.flatten() {
                    let name = e.file_name().to_string_lossy().to_string();
                    if let Some(key_id) = name.strip_suffix(".json") {
                        keys.push((e.path(), key_id.to_string(), read_any(&e.path(), &format!("key:{key_id}"))?));
                    }
                }
            }
            let store = Store { dir: dir.clone(), passphrase };
            store.write(&dir.join("identity.json"), "identity", &serde_json::to_vec_pretty(&ident)?)?;
            for (path, key_id, data) in &keys {
                store.write(path, &format!("key:{key_id}"), data)?;
            }
            let public = write_public_identity(&dir, &ident)?;
            println!(
                "node {}: {} key share(s) {}; tls {}. Update its registry entry from {}",
                public.id,
                keys.len(),
                if store.passphrase.is_some() { "encrypted" } else { "left unencrypted (dev)" },
                public.tls_cert_sha256.unwrap_or_default(),
                dir.join("identity.pub.json").display()
            );
        }
        Cmd::Run { dir, registry, admin, listen, port, max_external_spend, byzantine, secrets } => {
            let store = Store { dir: dir.clone(), passphrase: secrets.passphrase()? };
            let dev = secrets.dev;
            let ident = store.identity()?;
            let registry = match (&admin, dev) {
                (Some(a), _) => Registry::load_pinned(&registry, a)?,
                (None, true) => Registry::load(&registry)?,
                (None, false) => {
                    bail!("pass --admin <hex> (the admin's public key) so only a registry it signed is accepted")
                }
            };
            let secret = StaticSecret::from(x25519_bytes(&ident.x25519_secret)?);
            ensure!(
                registry.x25519(ident.id)? == *PublicKey::from(&secret).as_bytes(),
                "registry entry does not match this node's identity"
            );
            let entry = registry.node(ident.id)?.clone();
            let tls = if entry.url.starts_with("https://") {
                let t = ident
                    .tls
                    .clone()
                    .ok_or_else(|| anyhow!("registry says https but this node has no TLS certificate; run upgrade"))?;
                ensure!(
                    entry.tls_cert_sha256.as_deref() == Some(t.fingerprint().as_str()),
                    "registry's TLS fingerprint for node {} is not this node's certificate",
                    ident.id
                );
                ensure!(
                    dev || !registry.coordinators.is_empty(),
                    "registry lists no coordinators, so anyone could reach this node"
                );
                Some(tsn_net::server_config(
                    &t,
                    &registry.coordinators.iter().map(|c| c.tls_cert_sha256.clone()).collect::<Vec<_>>(),
                )?)
            } else {
                ensure!(dev, "node {} has a plain-http URL in the registry; production nodes use https", ident.id);
                None
            };
            let keys = load_keys(&store)?;
            let addr = listen.unwrap_or_else(|| SocketAddr::from(([127, 0, 0, 1], port.unwrap_or(7001))));
            let node = Arc::new(Node {
                id: ident.id,
                secret,
                registry_digest: registry.digest_hex()?,
                registry,
                store,
                max_external_spend,
                byzantine,
                keys: Mutex::new(keys),
                dkg_r1: Default::default(),
                dkg_r2: Default::default(),
                nonces: Default::default(),
                requests: Default::default(),
            });
            let app = Router::new()
                .route("/info", get(info))
                .route("/dkg/part1", post(dkg_part1))
                .route("/dkg/part2", post(dkg_part2))
                .route("/dkg/part3", post(dkg_part3))
                .route("/sign/commit", post(sign_commit))
                .route("/sign/share", post(sign_share))
                .with_state(node.clone());
            let listener = tokio::net::TcpListener::bind(addr).await.with_context(|| format!("binding {addr}"))?;
            node.log(format!(
                "listening on {addr} ({}{}), registry {}, {} key(s){}",
                if tls.is_some() { "TLS" } else { "plain HTTP, dev" },
                match (&tls, node.registry.coordinators.len()) {
                    (Some(_), 0) => ", any client".to_string(),
                    (Some(_), c) => format!(", {c} registered coordinator(s)"),
                    _ => String::new(),
                },
                short(&node.registry_digest),
                node.keys.lock().unwrap().len(),
                if byzantine { " (byzantine)" } else { "" }
            ));
            match tls {
                Some(cfg) => tsn_net::serve_tls(listener, cfg, app).await?,
                None => axum::serve(listener, app).await?,
            }
        }
    }
    Ok(())
}
