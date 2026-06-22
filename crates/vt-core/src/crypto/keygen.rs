// ============================================================
// VOID-TUNNEL :: vt-core :: crypto :: keygen.rs
//
// Cryptographically Secure Key Generation
//
// Generates all Void-Tunnel cryptographic key material using
// OS-level entropy sources via `rand::thread_rng` / `OsRng`.
// All keys are wrapped in `Zeroizing` to guarantee RAM cleanup.
//
// Author: Vladimir Unknown
// ============================================================

use ed25519_dalek::SigningKey;
use rand::{thread_rng, RngCore};
use zeroize::Zeroizing;

use crate::crypto::chacha::KEY_SIZE;
use crate::error::{VtError, VtResult};

/// Minimum HMAC secret size in bytes (256-bit)
pub const HMAC_SECRET_SIZE: usize = 32;

// ── Key Generation Functions ──────────────────────────────────────────────────

/// Generate a cryptographically secure 256-bit ChaCha20-Poly1305 symmetric key.
/// Uses `thread_rng` which is seeded by the OS entropy source (urandom/getrandom).
pub fn generate_chacha_key() -> VtResult<Zeroizing<[u8; KEY_SIZE]>> {
    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    thread_rng().fill_bytes(key.as_mut());

    // Sanity check: key must not be all-zeros (catastrophic entropy failure)
    if key.iter().all(|&b| b == 0) {
        return Err(VtError::KeyGenerationFailed);
    }

    Ok(key)
}

/// Generate a cryptographically secure 256-bit HMAC-SHA256 secret key.
pub fn generate_hmac_secret() -> VtResult<Zeroizing<[u8; HMAC_SECRET_SIZE]>> {
    let mut secret = Zeroizing::new([0u8; HMAC_SECRET_SIZE]);
    thread_rng().fill_bytes(secret.as_mut());

    if secret.iter().all(|&b| b == 0) {
        return Err(VtError::KeyGenerationFailed);
    }

    Ok(secret)
}

/// Generate a fresh Ed25519 signing keypair for config patch verification.
/// Returns (signing_key_hex, verifying_key_hex).
/// The signing key should NEVER leave the maintainer's secure environment.
pub fn generate_ed25519_keypair() -> VtResult<(String, String)> {
    let mut csprng = rand::rngs::OsRng;
    let signing_key = SigningKey::generate(&mut csprng);
    let verifying_key = signing_key.verifying_key();

    let signing_hex = hex::encode(signing_key.to_bytes());
    let verifying_hex = hex::encode(verifying_key.to_bytes());

    Ok((signing_hex, verifying_hex))
}

/// Generate a complete Void-Tunnel cryptographic keypair bundle
/// for a new user deployment. Returns a `KeyBundle` struct.
pub fn generate_deployment_keybundle() -> VtResult<KeyBundle> {
    let chacha_key = generate_chacha_key()?;
    let hmac_secret = generate_hmac_secret()?;

    Ok(KeyBundle {
        chacha_key_hex: hex::encode(chacha_key.as_slice()),
        hmac_secret_hex: hex::encode(hmac_secret.as_slice()),
    })
}

// ── Key Bundle ────────────────────────────────────────────────────────────────

/// A complete set of cryptographic credentials for one Void-Tunnel deployment.
/// Serialized to JSON and injected as environment variables into the
/// Cloudflare Worker during automated 1-Click deployment.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct KeyBundle {
    /// Hex-encoded 32-byte ChaCha20-Poly1305 symmetric key
    pub chacha_key_hex: String,

    /// Hex-encoded 32-byte HMAC-SHA256 shared secret
    pub hmac_secret_hex: String,
}

impl Drop for KeyBundle {
    fn drop(&mut self) {
        // Overwrite heap-allocated key strings before deallocation
        // Note: This is best-effort; Zeroizing<String> not used here
        // to keep the struct serializable. Treat as short-lived.
        unsafe {
            let bytes = self.chacha_key_hex.as_bytes_mut();
            for b in bytes.iter_mut() {
                std::ptr::write_volatile(b, 0);
            }
            let bytes = self.hmac_secret_hex.as_bytes_mut();
            for b in bytes.iter_mut() {
                std::ptr::write_volatile(b, 0);
            }
        }
    }
}

// ── Unit Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chacha_key_is_32_bytes() {
        let key = generate_chacha_key().unwrap();
        assert_eq!(key.len(), 32);
    }

    #[test]
    fn test_chacha_keys_are_unique() {
        let a = generate_chacha_key().unwrap();
        let b = generate_chacha_key().unwrap();
        assert_ne!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn test_hmac_secret_is_32_bytes() {
        let s = generate_hmac_secret().unwrap();
        assert_eq!(s.len(), 32);
    }

    #[test]
    fn test_hmac_secrets_are_unique() {
        let a = generate_hmac_secret().unwrap();
        let b = generate_hmac_secret().unwrap();
        assert_ne!(a.as_slice(), b.as_slice());
    }

    #[test]
    fn test_ed25519_keypair_lengths() {
        let (sign, verify) = generate_ed25519_keypair().unwrap();
        // Ed25519 keys are 32 bytes = 64 hex chars
        assert_eq!(sign.len(), 64);
        assert_eq!(verify.len(), 64);
    }

    #[test]
    fn test_deployment_keybundle_all_fields_populated() {
        let bundle = generate_deployment_keybundle().unwrap();
        assert_eq!(bundle.chacha_key_hex.len(), 64);
        assert_eq!(bundle.hmac_secret_hex.len(), 64);
    }
}