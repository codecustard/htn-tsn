//! Client for the signer nodes: DKG orchestration and FROST signing sessions.
//!
//! The coordinator is untrusted. It relays messages, picks signers and aggregates shares, but it
//! never holds a secret and can't make a node sign anything the owner and node policy don't allow.

use anyhow::{anyhow, bail, Context, Result};
use futures::future::{join_all, try_join_all};
use serde::{de::DeserializeOwned, Serialize};
use std::{collections::BTreeMap, time::Duration};
use tsn_core::{
    auth::Authorization,
    chain::{self, Tx},
    derive,
    frost::{self, keys::PublicKeyPackage},
    identifier,
    proto::*,
};

/// Progress messages ("input 0: signing with nodes [1, 3, 4]").
pub type Log<'a> = &'a (dyn Fn(String) + Sync);

pub struct NodeClient {
    http: reqwest::Client,
    pub registry: Registry,
}

/// Outcome of one FROST session: a signature, or the nodes whose shares were invalid.
enum Session {
    Signed([u8; 64]),
    BadShares(Vec<u16>),
}

fn random_session_id() -> String {
    tsn_core::auth::new_request_id()
}

impl NodeClient {
    pub fn new(registry: Registry) -> Self {
        Self { http: reqwest::Client::builder().timeout(Duration::from_secs(10)).build().unwrap(), registry }
    }

    async fn post<Req: Serialize, Resp: DeserializeOwned>(&self, id: u16, route: &str, body: &Req) -> Result<Resp> {
        let url = format!("{}{}", self.registry.node(id)?.url, route);
        let r = self.http.post(&url).json(body).send().await.with_context(|| format!("node {id} unreachable"))?;
        let status = r.status();
        let text = r.text().await?;
        if status.is_success() {
            return serde_json::from_str(&text).with_context(|| format!("node {id}: unexpected response"));
        }
        let msg = serde_json::from_str::<ErrorResp>(&text)
            .map(|e| e.error)
            .unwrap_or_else(|_| format!("HTTP {status}: {}", text.chars().take(200).collect::<String>()));
        bail!("node {id}: {msg}")
    }

    /// Node ids answering `/info`, in registry order.
    pub async fn live_nodes(&self) -> Vec<u16> {
        let checks = self.registry.nodes.iter().map(|n| async move {
            let ok = self.http.get(format!("{}/info", n.url)).send().await.map(|r| r.status().is_success());
            (n.id, ok.unwrap_or(false))
        });
        join_all(checks).await.into_iter().filter(|(_, ok)| *ok).map(|(id, _)| id).collect()
    }

    /// Runs the three DKG rounds across every registry node; returns the agreed public package.
    pub async fn dkg(&self, key_id: &str) -> Result<PublicKeyPackage> {
        let ids: Vec<u16> = self.registry.nodes.iter().map(|n| n.id).collect();
        let mut r1 = BTreeMap::new();
        for id in &ids {
            let resp: DkgPart1Resp = self.post(*id, "/dkg/part1", &DkgPart1Req { key_id: key_id.into() }).await?;
            r1.insert(*id, resp.package);
        }
        let others =
            |me: u16| r1.iter().filter(|(k, _)| **k != me).map(|(k, v)| (*k, v.clone())).collect::<BTreeMap<_, _>>();
        let mut inbox: BTreeMap<u16, BTreeMap<u16, String>> = BTreeMap::new();
        for id in &ids {
            let resp: DkgPart2Resp = self
                .post(*id, "/dkg/part2", &DkgPart2Req { key_id: key_id.into(), round1_packages: others(*id) })
                .await?;
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

    /// Threshold-signs every input of `tx` (inputs in parallel), routing around nodes that send
    /// invalid shares. `signers` pins the signer set; otherwise any `t` live nodes are used.
    #[allow(clippy::too_many_arguments)]
    pub async fn sign_inputs(
        &self,
        key_id: &str,
        path: &str,
        auth: &Authorization,
        public: &PublicKeyPackage,
        tx: &mut Tx,
        signers: Option<&[u16]>,
        log: Log<'_>,
    ) -> Result<()> {
        let pool: Vec<u16> = match signers {
            Some(s) => s.to_vec(),
            None => self.live_nodes().await,
        };
        let frozen = tx.clone();
        let jobs = (0..tx.inputs.len())
            .map(|idx| self.sign_input(key_id, path, auth, public, &frozen, idx, pool.clone(), signers.is_some(), log));
        let sigs = try_join_all(jobs).await?;
        for (idx, sig) in sigs.into_iter().enumerate() {
            tx.inputs[idx].signature_script = hex::encode(chain::signature_script(&sig));
        }
        Ok(())
    }

    #[allow(clippy::too_many_arguments)]
    async fn sign_input(
        &self,
        key_id: &str,
        path: &str,
        auth: &Authorization,
        public: &PublicKeyPackage,
        tx: &Tx,
        idx: usize,
        mut pool: Vec<u16>,
        fixed: bool,
        log: Log<'_>,
    ) -> Result<[u8; 64]> {
        let t = self.registry.threshold as usize;
        loop {
            // With a pinned signer set the request goes to the nodes as-is, so a too-small set is
            // refused by the nodes themselves rather than by this client.
            if !fixed && pool.len() < t {
                bail!("only {} usable signers ({pool:?}); threshold is {t}", pool.len());
            }
            let chosen: Vec<u16> = if fixed { pool.clone() } else { pool[..t].to_vec() };
            log(format!("input {idx}: signing with nodes {chosen:?}"));
            match self.sign_once(key_id, path, auth, public, tx, idx, &chosen).await? {
                Session::Signed(sig) => return Ok(sig),
                Session::BadShares(culprits) => {
                    log(format!(
                        "input {idx}: invalid shares from {culprits:?} (identifiable abort) - excluding and retrying"
                    ));
                    if fixed {
                        bail!("pinned signer set contains bad nodes {culprits:?}");
                    }
                    pool.retain(|id| !culprits.contains(id));
                }
            }
        }
    }

    /// One FROST session for one input; both rounds go to all chosen nodes concurrently.
    #[allow(clippy::too_many_arguments)]
    async fn sign_once(
        &self,
        key_id: &str,
        path: &str,
        auth: &Authorization,
        public: &PublicKeyPackage,
        tx: &Tx,
        idx: usize,
        signers: &[u16],
    ) -> Result<Session> {
        let session_id = random_session_id();
        let commit_req = CommitReq { key_id: key_id.into(), session_id: session_id.clone() };
        let commits = try_join_all(signers.iter().map(|id| async {
            let r: CommitResp = self.post(*id, "/sign/commit", &commit_req).await?;
            Ok::<_, anyhow::Error>((identifier(*id)?, r.commitments))
        }))
        .await?;
        let sighash = chain::sighash(tx, idx)?;
        let signing_package = frost::SigningPackage::new(commits.into_iter().collect(), &sighash);
        let req = ShareReq {
            key_id: key_id.into(),
            session_id,
            path: path.into(),
            tx: tx.clone(),
            input_index: idx,
            signing_package: signing_package.clone(),
            auth: auth.clone(),
        };
        let shares = try_join_all(signers.iter().map(|id| async {
            let r: ShareResp = self.post(*id, "/sign/share", &req).await?;
            Ok::<_, anyhow::Error>((identifier(*id)?, r.share))
        }))
        .await?;
        let child_public = derive::public_key_package(public, path)?;
        match frost::aggregate(&signing_package, &shares.into_iter().collect(), &child_public) {
            Ok(sig) => Ok(Session::Signed(sig.serialize()?.try_into().map_err(|_| anyhow!("bad signature length"))?)),
            Err(e) if !e.culprits().is_empty() => {
                let ids: BTreeMap<frost::Identifier, u16> =
                    self.registry.nodes.iter().map(|n| Ok((identifier(n.id)?, n.id))).collect::<Result<_>>()?;
                Ok(Session::BadShares(e.culprits().iter().map(|c| ids[c]).collect()))
            }
            Err(e) => bail!("aggregation failed: {e}"),
        }
    }
}
