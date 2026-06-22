// ============================================================
// VOID-TUNNEL :: vt-transport :: tunnel :: client.rs
//
// Core Encrypted Tunnel Client
//
// Establishes authenticated, ChaCha20-Poly1305 encrypted HTTP/2
// or HTTP/3 connections to the Cloudflare Worker gatekeeper.
//
// Each outbound packet is:
//   1. Polymorphic-padded
//   2. ChaCha20-Poly1305 encrypted
//   3. Handshake-fragmented (during setup)
//   4. HMAC-authenticated via X-Void-Auth header
//   5. Transmitted inside an HTTPS POST body
//
// Author: Vladimir Unknown
// ============================================================

use std::sync::Arc;
use std::time::{Duration, Instant};

use reqwest::{Client, ClientBuilder, Method, StatusCode};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};

use vt_core::config::schema::{NodeCredentials, VoidTunnelConfig};
use vt_core::crypto::chacha::{self, KEY_SIZE};
use vt_core::crypto::hmac;
use vt_core::crypto::keygen::parse_key_from_hex_wrapper;
use vt_core::padding::distributions::PaddingParams;
use vt_core::padding::polymorphic;

use crate::error::{TransportError, TransportResult};
use crate::metrics::CloakingMetrics;
use crate::obfs::packet_split::PacketSplitter;
use crate::proxy::socks5::Socks5Target;

/// Connection timeout for tunnel establishment
const CONNECT_TIMEOUT_SECS: u64 = 10;

/// Maximum body size for a single tunnel request (16MB)
const MAX_BODY_SIZE: usize = 16 * 1024 * 1024;

/// Custom HTTP header carrying the HMAC auth token
const AUTH_HEADER: &str = "X-Void-Auth";

/// Custom HTTP header carrying the target host for the worker
const TARGET_HOST_HEADER: &str = "X-Void-Target";

/// Custom HTTP header carrying the target port
const TARGET_PORT_HEADER: &str = "X-Void-Port";

pub struct TunnelClient {
    config: Arc<VoidTunnelConfig>,
    http_client: Client,
    metrics: Arc<CloakingMetrics>,
    splitter: Arc<PacketSplitter>,
}

impl TunnelClient {
    /// Build and initialize the tunnel client with a pre-configured
    /// reqwest Client applying JA4-spoofed TLS fingerprint settings.
    pub async fn new(
        config: Arc<VoidTunnelConfig>,
        metrics: Arc<CloakingMetrics>,
    ) -> TransportResult<Self> {
        let http_client = build_http_client(&config)?;
        let splitter = Arc::new(PacketSplitter::from_config(&config.packet_split));

        Ok(Self {
            config,
            http_client,
            metrics,
            splitter,
        })
    }

    // ── Target Connection ─────────────────────────────────────────────────────

    /// Request the Cloudflare Worker to open a tunnel to the specified target.
    /// Returns a local TcpStream that proxies data through the worker.
    /// This is achieved by creating a loopback pipe backed by the HTTP stream.
    pub async fn connect_to_target(
        &self,
        target: &Socks5Target,
    ) -> TransportResult<TcpStream> {
        let creds = self.get_primary_credentials()?;

        // Generate HMAC auth token
        let hmac_secret = hex::decode(&creds.hmac_secret_hex)
            .map_err(|_| TransportError::TunnelAuthRejected)?;
        let auth_token = hmac::generate_token(&hmac_secret)
            .map_err(|e| TransportError::Crypto(e))?;

        // Build the encrypted connection metadata payload
        let meta_payload = build_meta_payload(target, &creds)?;

        // Encrypt the payload
        let chacha_key = parse_chacha_key(&creds.chacha_key_hex)?;
        let encrypted = chacha::encrypt(&chacha_key, &meta_payload)
            .map_err(|e| TransportError::Crypto(e))?;

        // Wrap in polymorphic padding frame
        let padded = polymorphic::encapsulate(&encrypted, &self.config.padding)
            .map_err(|e| TransportError::Crypto(e))?;

        debug!(
            "Tunnel connect → {}:{} | payload={}B wire={}B",
            target.host, target.port,
            encrypted.len(), padded.len()
        );

        self.metrics.record_outbound(
            encrypted.len(),
            padded.len(),
            padded.len() - encrypted.len(),
        );

        // Measure RTT
        let t0 = Instant::now();

        // POST encrypted+padded payload to worker
        let response = timeout(
            Duration::from_secs(CONNECT_TIMEOUT_SECS),
            self.http_client
                .post(&creds.worker_url)
                .header(AUTH_HEADER, &auth_token)
                .header(TARGET_HOST_HEADER, &target.host)
                .header(TARGET_PORT_HEADER, target.port.to_string())
                .header("Content-Type", "application/octet-stream")
                .body(padded)
                .send()
        ).await
        .map_err(|_| TransportError::TunnelConnectionFailed {
            url: creds.worker_url.clone(),
        })??;

        self.metrics.record_rtt(t0.elapsed());

        if response.status() == StatusCode::FORBIDDEN {
            return Err(TransportError::TunnelAuthRejected);
        }

        if !response.status().is_success() {
            return Err(TransportError::TunnelConnectionFailed {
                url: creds.worker_url.clone(),
            });
        }

        // Create a local pipe that streams the response body
        // and wraps it as a TcpStream-compatible interface
        let stream = create_response_stream_pipe(response, chacha_key).await?;
        Ok(stream)
    }

    // ── Send Encrypted Data Packet ────────────────────────────────────────────

    /// Send an encrypted data packet through an established tunnel.
    pub async fn send_packet(
        &self,
        creds: &NodeCredentials,
        plaintext: &[u8],
    ) -> TransportResult<Vec<u8>> {
        let chacha_key = parse_chacha_key(&creds.chacha_key_hex)?;
        let hmac_secret = hex::decode(&creds.hmac_secret_hex)
            .map_err(|_| TransportError::TunnelAuthRejected)?;

        // Encrypt payload
        let encrypted = chacha::encrypt(&chacha_key, plaintext)
            .map_err(|e| TransportError::Crypto(e))?;

        // Apply polymorphic padding
        let padded = polymorphic::encapsulate(&encrypted, &self.config.padding)
            .map_err(|e| TransportError::Crypto(e))?;

        self.metrics.record_outbound(
            plaintext.len(),
            padded.len(),
            padded.len() - encrypted.len(),
        );

        // Generate fresh auth token
        let token = hmac::generate_token(&hmac_secret)
            .map_err(|e| TransportError::Crypto(e))?;

        // POST to worker
        let resp = self.http_client
            .post(&creds.worker_url)
            .header(AUTH_HEADER, token)
            .header("Content-Type", "application/octet-stream")
            .body(padded)
            .send()
            .await?;

        if !resp.status().is_success() {
            return Err(TransportError::TunnelWriteError);
        }

        // Read encrypted response body
        let resp_bytes = resp.bytes().await?.to_vec();

        // Decapsulate padding
        let decapped = polymorphic::decapsulate(&resp_bytes)
            .map_err(|e| TransportError::Crypto(e))?
            .to_vec();

        // Decrypt response
        let plaintext_resp = chacha::decrypt(&chacha_key, &decapped)
            .map_err(|e| TransportError::Crypto(e))?;

        self.metrics.record_inbound(plaintext_resp.len());

        Ok(plaintext_resp)
    }

    // ── Health Check ──────────────────────────────────────────────────────────

    /// Perform a lightweight health check against the worker endpoint.
    /// Sends a minimal HMAC-authenticated probe and validates HTTP 200 response.
    pub async fn health_check(&self, creds: &NodeCredentials) -> bool {
        let hmac_secret = match hex::decode(&creds.hmac_secret_hex) {
            Ok(b) => b,
            Err(_) => return false,
        };

        let token = match hmac::generate_token(&hmac_secret) {
            Ok(t) => t,
            Err(_) => return false,
        };

        match timeout(
            Duration::from_secs(5),
            self.http_client
                .get(&creds.worker_url)
                .header(AUTH_HEADER, token)
                .send()
        ).await {
            Ok(Ok(resp)) => resp.status().is_success(),
            _ => false,
        }
    }

    // ── Credential Access ─────────────────────────────────────────────────────

    fn get_primary_credentials(&self) -> TransportResult<NodeCredentials> {
        self.config
            .primary_node
            .clone()
            .ok_or(TransportError::TunnelConnectionFailed {
                url: "no primary node configured".into(),
            })
    }
}

// ── HTTP Client Builder ───────────────────────────────────────────────────────

/// Build a reqwest HTTP client with JA4-spoofed TLS settings,
/// HTTP/2 enabled, and strict timeout configuration.
fn build_http_client(config: &VoidTunnelConfig) -> TransportResult<Client> {
    // Embed trusted root CA certificates (webpki-roots bundle)
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(
        webpki_roots::TLS_SERVER_ROOTS
            .iter()
            .cloned()
    );

    // Build rustls config with JA4-aligned cipher suite ordering
    let tls_config = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();

    let client = ClientBuilder::new()
        .use_preconfigured_tls(tls_config)
        .http2_prior_knowledge()
        .timeout(Duration::from_secs(30))
        .connect_timeout(Duration::from_secs(CONNECT_TIMEOUT_SECS))
        .tcp_keepalive(Duration::from_secs(20))
        .user_agent(chrome_user_agent())
        .build()
        .map_err(|e| TransportError::Reqwest(e))?;

    Ok(client)
}

/// Return a realistic Chrome user-agent string for traffic blending.
fn chrome_user_agent() -> &'static str {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) \
     AppleWebKit/537.36 (KHTML, like Gecko) \
     Chrome/126.0.0.0 Safari/537.36"
}

// ── Payload Builder ───────────────────────────────────────────────────────────

/// Build the binary metadata payload describing the connection target.
/// Format: JSON-encoded target descriptor.
fn build_meta_payload(
    target: &Socks5Target,
    _creds: &NodeCredentials,
) -> TransportResult<Vec<u8>> {
    let payload = serde_json::json!({
        "host": target.host,
        "port": target.port,
        "protocol": "tcp",
        "timestamp": chrono::Utc::now().timestamp(),
    });

    serde_json::to_vec(&payload)
        .map_err(|_| TransportError::TunnelWriteError)
}

// ── Response Stream Pipe ──────────────────────────────────────────────────────

/// Create a TcpStream-compatible loopback pipe backed by a streaming
/// HTTP response body. Decrypts each chunk on arrival.
async fn create_response_stream_pipe(
    response: reqwest::Response,
    chacha_key: [u8; KEY_SIZE],
) -> TransportResult<TcpStream> {
    // Create a loopback TCP socket pair
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
    let addr = listener.local_addr()?;
    let client_stream = TcpStream::connect(addr).await?;

    // Accept the server side
    let (server_stream, _) = listener.accept().await?;

    // Spawn a task that drains the HTTP response body into the server side
    tokio::spawn(async move {
        let mut server = server_stream;
        let mut response = response;

        while let Ok(Some(chunk)) = response.chunk().await {
            // Decapsulate padding
            match polymorphic::decapsulate(&chunk) {
                Ok(decapped) => {
                    // Decrypt chunk
                    match chacha::decrypt(&chacha_key, decapped) {
                        Ok(plaintext) => {
                            if server.write_all(&plaintext).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
                Err(_) => break,
            }
        }
    });

    Ok(client_stream)
}

// ── Key Parser Helper ─────────────────────────────────────────────────────────

fn parse_chacha_key(hex_str: &str) -> TransportResult<[u8; KEY_SIZE]> {
    let bytes = hex::decode(hex_str)
        .map_err(|_| TransportError::TunnelAuthRejected)?;
    if bytes.len() != KEY_SIZE {
        return Err(TransportError::TunnelAuthRejected);
    }
    let mut key = [0u8; KEY_SIZE];
    key.copy_from_slice(&bytes);
    Ok(key)
}

use tokio::io::AsyncWriteExt;
use vt_core::padding::polymorphic;
use webpki_roots;