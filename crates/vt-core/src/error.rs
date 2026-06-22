// ============================================================
// VOID-TUNNEL :: vt-core :: error.rs
// Unified Error Taxonomy for the Entire Core Engine
// Author: Vladimir Unknown
// ============================================================

use thiserror::Error;

/// Master error enum for all vt-core subsystems.
/// Every error variant is designed to produce zero sensitive
/// information leakage in its Display representation.
#[derive(Debug, Error)]
pub enum VtError {
    // ── Cryptographic Errors ─────────────────────────────────
    #[error("HMAC token validation failed")]
    HmacValidationFailed,

    #[error("HMAC token timestamp drift exceeded maximum window")]
    HmacReplayDetected,

    #[error("ChaCha20-Poly1305 decryption authentication failed")]
    AeadDecryptionFailed,

    #[error("ChaCha20-Poly1305 encryption error")]
    AeadEncryptionFailed,

    #[error("Ed25519 signature verification failed")]
    SignatureInvalid,

    #[error("Ed25519 public key malformed")]
    PublicKeyMalformed,

    #[error("Key generation entropy failure")]
    KeyGenerationFailed,

    #[error("KDF derivation error: insufficient input material")]
    KdfError,

    // ── Padding / Obfuscation Errors ─────────────────────────
    #[error("Polymorphic padding frame header truncated")]
    PaddingHeaderTruncated,

    #[error("Polymorphic padding declared length exceeds buffer")]
    PaddingLengthOverflow,

    #[error("Padding distribution parameter out of valid range")]
    PaddingDistributionInvalid,

    // ── TLS / Fingerprinting Errors ──────────────────────────
    #[error("JA4 profile unknown or unsupported: {profile}")]
    Ja4ProfileUnknown { profile: String },

    #[error("TLS handshake fragmentation error")]
    HandshakeFragmentationFailed,

    #[error("Rustls TLS error: {0}")]
    TlsError(#[from] rustls::Error),

    // ── DNS Errors ───────────────────────────────────────────
    #[error("DNS-over-HTTPS resolution failed for: {domain}")]
    DohResolutionFailed { domain: String },

    #[error("DNS-over-TLS resolution failed for: {domain}")]
    DotResolutionFailed { domain: String },

    #[error("DNS bootstrap IP pool exhausted")]
    DnsBootstrapExhausted,

    // ── Configuration Errors ─────────────────────────────────
    #[error("Configuration schema deserialization failed")]
    ConfigDeserializationFailed,

    #[error("Configuration patch signature invalid — rejecting")]
    ConfigPatchSignatureInvalid,

    #[error("Geographic profile not found: {jurisdiction}")]
    GeoProfileNotFound { jurisdiction: String },

    #[error("Profile community string parse error")]
    ProfileParseError,

    // ── I/O and Runtime Errors ───────────────────────────────
    #[error("I/O operation failed: {context}")]
    IoError {
        context: String,
        #[source]
        source: std::io::Error,
    },

    #[error("Tokio task join error")]
    TaskJoinError(#[from] tokio::task::JoinError),

    // ── Generic / Catch-all ──────────────────────────────────
    #[error("Internal engine error: {0}")]
    Internal(#[from] anyhow::Error),
}

/// Type alias used uniformly across all vt-core modules.
pub type VtResult<T> = Result<T, VtError>;