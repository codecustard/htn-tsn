//! `tsn-coordinator`: HTTP signing service in front of the signer nodes.
//!
//! Apps hold their owner key and call this service to get addresses, prepare payments and have
//! them threshold-signed and broadcast. The service is untrusted: it never holds a secret, every
//! node re-checks the owner's signature and its own policy, and the owner signs the exact
//! transaction, so a compromised coordinator can at worst refuse service.
//!
//! Endpoints (JSON; 64-bit amounts are decimal strings):
//!   GET  /healthz
//!   GET  /v1/info
//!   GET  /v1/address?owner=<ed25519 hex>&name=<name>&network=<network>
//!   GET  /v1/balance?owner=..&name=..&network=..
//!   POST /v1/tx/prepare  {owner, name, network, to, amount | all, feerate?, max_fee?}
//!   POST /v1/tx/send     {path, tx, auth, broadcast?, signers?}

use anyhow::{anyhow, bail, ensure, Result};
use axum::{
    extract::{ConnectInfo, Query, Request, State},
    http::{HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use clap::Parser;
use ed25519_dalek::VerifyingKey as OwnerKey;
use serde::Deserialize;
use serde_json::{json, Value};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::{Arc, Mutex},
};
use tower_http::cors::{AllowOrigin, CorsLayer};
use tsn_coord::{
    chain_api::{self, ChainApi},
    nodes::NodeClient,
    payment,
};
use tsn_core::{
    auth::{self, Authorization},
    build::Amount,
    chain::{self, Network, Tx},
    frost::keys::PublicKeyPackage,
    proto::Registry,
};

#[derive(Parser)]
#[command(about = "HTTP signing service for the htn-tsn threshold signing network")]
struct Args {
    #[arg(long, default_value = "registry.json")]
    registry: PathBuf,
    /// Master public key package written by `tsn dkg`.
    #[arg(long)]
    public: PathBuf,
    #[arg(long, default_value = "master")]
    key_id: String,
    #[arg(long, default_value = "127.0.0.1:7100")]
    listen: SocketAddr,
    /// Override a network's REST API: NETWORK=URL (repeatable). hoosat-testnet needs one.
    #[arg(long = "api")]
    apis: Vec<String>,
    /// Refuse to sign transactions paying more than this fee (sompi).
    #[arg(long, default_value_t = 10_000_000)]
    max_fee: u64,
    /// Require this value in the `x-api-key` header. Strongly recommended outside localhost.
    #[arg(long, env = "TSN_API_KEY")]
    api_key: Option<String>,
    /// Allow browser requests from this origin (repeatable). Default: none (backend clients).
    #[arg(long = "cors-origin")]
    cors_origins: Vec<String>,
    /// Requests per minute per client IP; 0 disables.
    #[arg(long, default_value_t = 120)]
    rate_limit: u32,
}

struct App {
    nodes: NodeClient,
    public: PublicKeyPackage,
    key_id: String,
    apis: HashMap<Network, ChainApi>,
    max_fee: u64,
    api_key: Option<String>,
    rate_limit: u32,
    rate: Mutex<HashMap<IpAddr, (u64, u32)>>,
}

type Shared = Arc<App>;

struct ApiError(StatusCode, String);

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.0, Json(json!({ "error": self.1 }))).into_response()
    }
}

impl<E: Into<anyhow::Error>> From<E> for ApiError {
    fn from(e: E) -> Self {
        ApiError(StatusCode::BAD_REQUEST, format!("{:#}", e.into()))
    }
}

type ApiResult = Result<Json<Value>, ApiError>;

const NETWORKS: [Network; 4] =
    [Network::KaspaMainnet, Network::KaspaTestnet, Network::HoosatMainnet, Network::HoosatTestnet];

fn network_name(n: Network) -> String {
    serde_json::to_value(n).ok().and_then(|v| v.as_str().map(str::to_string)).unwrap_or_default()
}

fn parse_owner(hex_key: &str) -> Result<OwnerKey> {
    let bytes: [u8; 32] =
        hex::decode(hex_key)?.try_into().map_err(|_| anyhow!("owner must be a 32-byte ed25519 public key (hex)"))?;
    Ok(OwnerKey::from_bytes(&bytes)?)
}

fn parse_u64(v: &Value, what: &str) -> Result<u64> {
    match v {
        Value::String(s) => s.parse().map_err(|_| anyhow!("{what} must be an integer")),
        Value::Number(n) => n.as_u64().ok_or_else(|| anyhow!("{what} must be a non-negative integer")),
        _ => bail!("{what} must be an integer or decimal string"),
    }
}

impl App {
    fn api(&self, network: Network) -> Result<&ChainApi> {
        self.apis
            .get(&network)
            .ok_or_else(|| anyhow!("no API configured for {}; start with --api", network_name(network)))
    }
}

/// Compares without leaking where the first difference is.
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

async fn guard(
    State(app): State<Shared>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    if req.uri().path() != "/healthz" {
        if let Some(key) = &app.api_key {
            let ok =
                req.headers().get("x-api-key").map(|v| constant_time_eq(v.as_bytes(), key.as_bytes())).unwrap_or(false);
            if !ok {
                return ApiError(StatusCode::UNAUTHORIZED, "missing or wrong x-api-key".into()).into_response();
            }
        }
        if app.rate_limit > 0 {
            let minute = auth::now_secs() / 60;
            let mut rate = app.rate.lock().unwrap();
            rate.retain(|_, (m, _)| *m == minute);
            let entry = rate.entry(peer.ip()).or_insert((minute, 0));
            entry.1 += 1;
            if entry.1 > app.rate_limit {
                return ApiError(StatusCode::TOO_MANY_REQUESTS, "rate limit exceeded".into()).into_response();
            }
        }
    }
    next.run(req).await
}

async fn healthz(State(app): State<Shared>) -> Json<Value> {
    let live = app.nodes.live_nodes().await;
    let t = app.nodes.registry.threshold as usize;
    Json(json!({ "ok": live.len() >= t, "live_nodes": live, "threshold": t }))
}

async fn info(State(app): State<Shared>) -> ApiResult {
    let networks: Vec<Value> = NETWORKS
        .iter()
        .filter_map(|n| {
            app.apis.get(n).map(|a| json!({ "network": network_name(*n), "prefix": n.prefix(), "api": a.base() }))
        })
        .collect();
    Ok(Json(json!({
        "key_id": app.key_id,
        "master_public_key": hex::encode(app.public.verifying_key().serialize()?),
        "threshold": app.nodes.registry.threshold,
        "nodes": app.nodes.registry.n(),
        "networks": networks,
        "max_fee": app.max_fee.to_string(),
        "max_authorization_ttl_secs": auth::MAX_REQUEST_TTL_SECS,
    })))
}

#[derive(Deserialize)]
struct KeyQuery {
    owner: String,
    name: String,
    network: String,
}

async fn address(State(app): State<Shared>, Query(q): Query<KeyQuery>) -> ApiResult {
    let network = Network::parse(&q.network)?;
    let (path, address, script) =
        payment::key_address(app.public.verifying_key(), network, &parse_owner(&q.owner)?, &q.name)?;
    Ok(Json(json!({ "network": q.network, "path": path, "address": address, "script": hex::encode(script) })))
}

async fn balance(State(app): State<Shared>, Query(q): Query<KeyQuery>) -> ApiResult {
    let network = Network::parse(&q.network)?;
    let (_, address, _) = payment::key_address(app.public.verifying_key(), network, &parse_owner(&q.owner)?, &q.name)?;
    let utxos = app.api(network)?.utxos(&address).await?;
    let total: u64 = utxos.iter().map(|u| u.entry.amount).sum();
    let list: Vec<Value> = utxos
        .iter()
        .map(|u| {
            json!({
                "txid": u.outpoint.transaction_id,
                "index": u.outpoint.index,
                "amount": u.entry.amount.to_string(),
                "block_daa_score": u.entry.block_daa_score.to_string(),
            })
        })
        .collect();
    Ok(Json(json!({ "address": address, "balance": total.to_string(), "utxos": list })))
}

#[derive(Deserialize)]
struct PrepareReq {
    owner: String,
    name: String,
    network: String,
    to: String,
    amount: Option<Value>,
    #[serde(default)]
    all: bool,
    feerate: Option<f64>,
    max_fee: Option<Value>,
}

async fn prepare(State(app): State<Shared>, Json(r): Json<PrepareReq>) -> ApiResult {
    let network = Network::parse(&r.network)?;
    let amount = match (&r.amount, r.all) {
        (Some(v), false) => Amount::Exact(parse_u64(v, "amount")?),
        (None, true) => Amount::All,
        _ => return Err(anyhow!("give exactly one of amount or all=true").into()),
    };
    let max_fee = match &r.max_fee {
        Some(v) => parse_u64(v, "max_fee")?.min(app.max_fee),
        None => app.max_fee,
    };
    let req = payment::Request {
        network,
        owner: parse_owner(&r.owner)?,
        name: r.name,
        to: r.to,
        amount,
        feerate: r.feerate,
        max_fee,
    };
    let prepared = payment::prepare(app.api(network)?, app.public.verifying_key(), &req).await?;
    let mut out = serde_json::to_value(&prepared)?;
    out["key_id"] = json!(app.key_id);
    Ok(Json(out))
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
struct SendReq {
    path: String,
    tx: Tx,
    auth: Authorization,
    #[serde(default = "default_true")]
    broadcast: bool,
    signers: Option<Vec<u16>>,
}

async fn send(State(app): State<Shared>, Json(r): Json<SendReq>) -> ApiResult {
    Ok(Json(send_inner(&app, r).await?))
}

async fn send_inner(app: &App, r: SendReq) -> Result<Value> {
    let mut tx = r.tx;
    // Fail fast on what the nodes would refuse anyway.
    auth::verify(&app.key_id, &r.path, &tx, &r.auth, auth::now_secs())?;
    let xonly = tsn_core::derive::child_xonly(app.public.verifying_key(), &r.path)?;
    let own_script = hex::encode(chain::p2pk_script(&xonly));
    ensure!(!tx.inputs.is_empty(), "transaction has no inputs");
    ensure!(tx.inputs.iter().all(|i| i.script_pubkey == own_script), "every input must belong to {}", r.path);
    let fee = payment::implied_fee(&tx)?;
    ensure!(fee <= app.max_fee, "fee {fee} sompi exceeds this coordinator's maximum {}", app.max_fee);
    let api = app.api(tx.network)?;

    let log_lines = Mutex::new(Vec::<String>::new());
    let log = |line: String| {
        println!("[{}] {line}", &r.auth.request_id[..8]);
        log_lines.lock().unwrap().push(line);
    };
    app.nodes.sign_inputs(&app.key_id, &r.path, &r.auth, &app.public, &mut tx, r.signers.as_deref(), &log).await?;
    chain::verify_signed(&tx)?;
    let (txid, explorer) = if r.broadcast {
        let txid = api.submit(&tx).await?;
        println!("[{}] broadcast {txid}", &r.auth.request_id[..8]);
        let url = chain_api::explorer_tx_url(tx.network, &txid).filter(|_| api.is_default);
        (Some(txid), url)
    } else {
        (None, None)
    };
    Ok(json!({ "txid": txid, "explorer": explorer, "tx": tx, "log": log_lines.into_inner().unwrap() }))
}

#[tokio::main]
async fn main() -> Result<()> {
    let a = Args::parse();
    let registry = Registry::load(&a.registry)?;
    let public: PublicKeyPackage = serde_json::from_slice(&std::fs::read(&a.public)?)?;

    let mut overrides: HashMap<Network, String> = HashMap::new();
    for spec in &a.apis {
        let (net, url) = spec.split_once('=').ok_or_else(|| anyhow!("--api must be NETWORK=URL"))?;
        overrides.insert(Network::parse(net)?, url.to_string());
    }
    let mut apis = HashMap::new();
    for n in NETWORKS {
        if let Ok(api) = ChainApi::new(n, overrides.remove(&n)) {
            apis.insert(n, api);
        }
    }

    let app = Arc::new(App {
        nodes: NodeClient::new(registry),
        public,
        key_id: a.key_id,
        apis,
        max_fee: a.max_fee,
        api_key: a.api_key.filter(|k| !k.is_empty()),
        rate_limit: a.rate_limit,
        rate: Mutex::new(HashMap::new()),
    });

    let mut router = Router::new()
        .route("/healthz", get(healthz))
        .route("/v1/info", get(info))
        .route("/v1/address", get(address))
        .route("/v1/balance", get(balance))
        .route("/v1/tx/prepare", post(prepare))
        .route("/v1/tx/send", post(send))
        .layer(middleware::from_fn_with_state(app.clone(), guard))
        .with_state(app.clone());
    if !a.cors_origins.is_empty() {
        let origins: Vec<HeaderValue> = a.cors_origins.iter().map(|o| o.parse()).collect::<Result<_, _>>()?;
        router = router.layer(
            CorsLayer::new()
                .allow_origin(AllowOrigin::list(origins))
                .allow_methods([axum::http::Method::GET, axum::http::Method::POST])
                .allow_headers([axum::http::header::CONTENT_TYPE, "x-api-key".parse()?]),
        );
    }
    if app.api_key.is_none() && !a.listen.ip().is_loopback() {
        println!("warning: listening on {} without --api-key", a.listen);
    }
    let listener = tokio::net::TcpListener::bind(a.listen).await?;
    println!(
        "tsn-coordinator on http://{} ({}-of-{}, key {}, master public key {})",
        a.listen,
        app.nodes.registry.threshold,
        app.nodes.registry.n(),
        app.key_id,
        hex::encode(app.public.verifying_key().serialize()?)
    );
    axum::serve(listener, router.into_make_service_with_connect_info::<SocketAddr>()).await?;
    Ok(())
}
