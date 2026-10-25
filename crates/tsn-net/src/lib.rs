//! TLS between coordinators and nodes, pinned to certificate fingerprints.
//!
//! Each node and coordinator has a self-signed certificate. The signed registry lists the SHA-256
//! of every node's certificate and of every coordinator's certificate, so no certificate authority
//! or domain name is involved:
//! - a coordinator connects to a node only if it presents the registered certificate;
//! - a node accepts a connection only from a registered coordinator (mutual TLS), so strangers
//!   can't reach the signing API at all.

use anyhow::{anyhow, Context, Result};
use rustls::{
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::{verify_tls12_signature, verify_tls13_signature, CryptoProvider, WebPkiSupportedAlgorithms},
    pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime},
    server::danger::{ClientCertVerified, ClientCertVerifier},
    DigitallySignedStruct, DistinguishedName, SignatureScheme,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{sync::Arc, time::Duration};

/// A self-signed TLS certificate and its private key (both DER, stored as hex).
#[derive(Clone, Serialize, Deserialize)]
pub struct TlsIdentity {
    pub cert: String,
    pub key: String,
}

impl std::fmt::Debug for TlsIdentity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TlsIdentity").field("fingerprint", &self.fingerprint()).finish_non_exhaustive()
    }
}

impl TlsIdentity {
    /// New ECDSA P-256 self-signed certificate. `name` is informational; peers pin the fingerprint.
    pub fn generate(name: &str) -> Result<Self> {
        let c = rcgen::generate_simple_self_signed(vec![name.to_string()])?;
        Ok(TlsIdentity { cert: hex::encode(c.cert.der()), key: hex::encode(c.key_pair.serialize_der()) })
    }

    /// SHA-256 of the certificate (DER), hex: what the registry lists.
    pub fn fingerprint(&self) -> String {
        hex::decode(&self.cert).map(|d| fingerprint(&d)).unwrap_or_default()
    }

    fn cert_der(&self) -> Result<CertificateDer<'static>> {
        Ok(CertificateDer::from(hex::decode(&self.cert)?))
    }

    fn key_der(&self) -> Result<PrivateKeyDer<'static>> {
        Ok(PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(hex::decode(&self.key)?)))
    }
}

pub fn fingerprint(der: &[u8]) -> String {
    hex::encode(Sha256::digest(der))
}

fn provider() -> Arc<CryptoProvider> {
    Arc::new(rustls::crypto::ring::default_provider())
}

fn algs() -> WebPkiSupportedAlgorithms {
    rustls::crypto::ring::default_provider().signature_verification_algorithms
}

/// Accepts exactly one server certificate.
#[derive(Debug)]
struct PinnedServer {
    fingerprint: String,
}

impl ServerCertVerifier for PinnedServer {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        let got = fingerprint(end_entity);
        if got == self.fingerprint {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::General(format!(
                "node certificate {got} is not the one in the registry ({})",
                self.fingerprint
            )))
        }
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &algs())
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &algs())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        algs().supported_schemes()
    }
}

/// Accepts client certificates whose fingerprint is listed.
#[derive(Debug)]
struct PinnedClients {
    allowed: Vec<String>,
}

impl ClientCertVerifier for PinnedClients {
    fn root_hint_subjects(&self) -> &[DistinguishedName] {
        &[]
    }
    fn verify_client_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        if self.allowed.contains(&fingerprint(end_entity)) {
            Ok(ClientCertVerified::assertion())
        } else {
            Err(rustls::Error::General("client certificate is not a registered coordinator".into()))
        }
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls12_signature(message, cert, dss, &algs())
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        verify_tls13_signature(message, cert, dss, &algs())
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        algs().supported_schemes()
    }
}

/// Node side: serve `identity`; if `allowed_clients` is non-empty, require one of those client
/// certificates (registered coordinators).
pub fn server_config(identity: &TlsIdentity, allowed_clients: &[String]) -> Result<rustls::ServerConfig> {
    let builder = rustls::ServerConfig::builder_with_provider(provider()).with_safe_default_protocol_versions()?;
    let builder = if allowed_clients.is_empty() {
        builder.with_no_client_auth()
    } else {
        builder.with_client_cert_verifier(Arc::new(PinnedClients { allowed: allowed_clients.to_vec() }))
    };
    let mut cfg = builder.with_single_cert(vec![identity.cert_der()?], identity.key_der()?)?;
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(cfg)
}

/// Coordinator side: an HTTP client that only talks to the server with `server_fingerprint`,
/// presenting `client` (if given) as its own certificate.
pub fn pinned_client(
    server_fingerprint: &str,
    client: Option<&TlsIdentity>,
    timeout: Duration,
) -> Result<reqwest::Client> {
    let builder = rustls::ClientConfig::builder_with_provider(provider())
        .with_safe_default_protocol_versions()?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(PinnedServer { fingerprint: server_fingerprint.to_string() }));
    let mut cfg = match client {
        Some(id) => builder.with_client_auth_cert(vec![id.cert_der()?], id.key_der()?)?,
        None => builder.with_no_client_auth(),
    };
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(reqwest::Client::builder().use_preconfigured_tls(cfg).timeout(timeout).build()?)
}

/// Serves `app` over TLS on `listener` until the process exits.
pub async fn serve_tls(
    listener: tokio::net::TcpListener,
    config: rustls::ServerConfig,
    app: axum::Router,
) -> Result<()> {
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(config));
    loop {
        let (tcp, _) = listener.accept().await.context("accept")?;
        let (acceptor, app) = (acceptor.clone(), app.clone());
        tokio::spawn(async move {
            // Unregistered clients fail here, before any request reaches the API.
            let Ok(Ok(tls)) = tokio::time::timeout(Duration::from_secs(10), acceptor.accept(tcp)).await else {
                return;
            };
            let svc = hyper_util::service::TowerToHyperService::new(app);
            let _ = hyper::server::conn::http1::Builder::new()
                .serve_connection(hyper_util::rt::TokioIo::new(tls), svc)
                .await;
        });
    }
}

/// Loads a coordinator identity file (`tsn coordinator-new`).
pub fn load_identity(path: &std::path::Path) -> Result<(String, TlsIdentity)> {
    #[derive(Deserialize)]
    struct File {
        name: String,
        tls: TlsIdentity,
    }
    let f: File = serde_json::from_slice(&std::fs::read(path).with_context(|| format!("reading {}", path.display()))?)
        .map_err(|e| anyhow!("{}: not a coordinator identity file: {e}", path.display()))?;
    Ok((f.name, f.tls))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::routing::get;

    async fn start(id: &TlsIdentity, allowed: &[String]) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let app = axum::Router::new().route("/info", get(|| async { "ok" }));
        tokio::spawn(serve_tls(listener, server_config(id, allowed).unwrap(), app));
        format!("https://{addr}/info")
    }

    #[tokio::test]
    async fn pinning_both_ways() {
        let node = TlsIdentity::generate("tsn-node-1").unwrap();
        let other_node = TlsIdentity::generate("tsn-node-2").unwrap();
        let coord = TlsIdentity::generate("coordinator").unwrap();
        let stranger = TlsIdentity::generate("stranger").unwrap();
        let t = Duration::from_secs(5);
        let url = start(&node, &[coord.fingerprint()]).await;

        let ok = pinned_client(&node.fingerprint(), Some(&coord), t).unwrap().get(&url).send().await.unwrap();
        assert_eq!(ok.text().await.unwrap(), "ok");
        // Wrong node certificate (impersonation or a swapped node): refused by the coordinator.
        let err = pinned_client(&other_node.fingerprint(), Some(&coord), t).unwrap().get(&url).send().await;
        assert!(err.is_err());
        // Unregistered or missing client certificate: refused by the node.
        assert!(pinned_client(&node.fingerprint(), Some(&stranger), t).unwrap().get(&url).send().await.is_err());
        assert!(pinned_client(&node.fingerprint(), None, t).unwrap().get(&url).send().await.is_err());

        // Without a coordinator list, any client that pins the node gets through (dev).
        let open = start(&node, &[]).await;
        assert!(pinned_client(&node.fingerprint(), None, t).unwrap().get(&open).send().await.is_ok());
        let s = serde_json::to_string(&node).unwrap();
        assert_eq!(serde_json::from_str::<TlsIdentity>(&s).unwrap().fingerprint(), node.fingerprint());
    }
}
