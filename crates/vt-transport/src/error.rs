// ============================================================
// VOID-TUNNEL :: vt-transport :: error.rs
// Author: Vladimir Unknown
// ============================================================

use thiserror::Error;
use vt_core::VtError;

#[derive(Debug, Error)]
pub enum TransportError {
    // ── Proxy Errors ─────────────────────────────────────────
    #[error("SOCKS5 handshake failed: {reason}")]
    Socks5HandshakeFailed { reason: String },

    #[error("SOCKS5 auth method unsupported: {method}")]
    Socks5AuthUnsupported { method: u8 },

    #[error("SOCKS5 command unsupported: {cmd}")]
    Socks5CommandUnsupported { cmd: u8 },

    #[error("HTTP CONNECT tunnel failed: {reason}")]
    HttpConnectFailed { reason: String },

    #[error("Proxy bind failed on port {port}")]
    ProxyBindFailed { port: u16 },

    // ── Tunnel Errors ─────────────────────────────────────────
    #[error("Tunnel connection failed to worker: {url}")]
    TunnelConnectionFailed { url: String },

    #[error("Tunnel stream write error")]
    TunnelWriteError,

    #[error("Tunnel stream read error")]
    TunnelReadError,

    #[error("Tunnel authentication rejected by worker")]
    TunnelAuthRejected,

    #[error("All tunnel providers exhausted — failover failed")]
    AllProvidersExhausted,

    // ── Obfuscation Errors ────────────────────────────────────
    #[error("Packet split transmission error")]
    PacketSplitError,

    #[error("QUIC stream initialization failed")]
    QuicStreamFailed,

    #[error("JA4 profile compilation failed")]
    Ja4CompilationFailed,

    // ── DNS Errors ────────────────────────────────────────────
    #[error("DoH resolution failed: {domain}")]
    DohFailed { domain: String },

    #[error("All DNS resolvers exhausted")]
    DnsExhausted,

    // ── Bootstrap Errors ──────────────────────────────────────
    #[error("All bootstrap nodes unreachable")]
    BootstrapExhausted,

    #[error("DHT lookup failed for info-hash")]
    DhtLookupFailed,

    #[error("Bootstrap node signature invalid")]
    BootstrapSignatureInvalid,

    // ── Kill Switch Errors ────────────────────────────────────
    #[error("Kill switch activation failed: {reason}")]
    KillSwitchFailed { reason: String },

    // ── Core Crypto Forwarded ─────────────────────────────────
    #[error("Cryptographic error: {0}")]
    Crypto(#[from] VtError),

    // ── I/O ───────────────────────────────────────────────────
    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Hyper HTTP error: {0}")]
    Hyper(#[from] hyper::Error),

    #[error("Reqwest error: {0}")]
    Reqwest(#[from] reqwest::Error),
}

pub type TransportResult<T> = Result<T, TransportError>;