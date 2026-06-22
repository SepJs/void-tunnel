// ============================================================
// VOID-TUNNEL :: vt-core :: crypto :: ed25519.rs
//
// Ed25519 Signature Verification for Config Patch Updates
//
// All JSON configuration patches downloaded by the Dual-Stream
// Update Pipeline must be signed by Vladimir Unknown's Ed25519
// private key and verified client-side before any parameter
// is applied to the live engine. This prevents adversary-injected
// false configuration updates from altering evasion parameters.
//
// Author: Vladimir Unknown
// ============================================================

use ed25519_dalek::{Signature, Verifier, VerifyingKey};

use crate::error::{VtError, VtResult};

/// Hardcoded Ed25519 public key for Vladimir Unknown's release channel.
/// This must be replaced with the actual generated public key at project init.
/// Format: 32-byte key as lowercase hex string (64 characters).
///
/// MAINTAINER NOTE: Generate with `generate_ed25519_keypair()` in keygen.rs.
/// Embed the verifying key here. NEVER embed the signing key in client code.
pub const VU_ED25519_VERIFYING_KEY_HEX: &str =
    "0000000000000000000000000000000000000000000000000000000000000000";
//   ^^^ REPLACE WITH REAL KEY BEFORE PRODUCTION BUILD ^^^

/// Verify an Ed25519 signature over a raw byte payload.
///
/// # Arguments
/// * `payload`   — The raw bytes of the signed data (e.g., JSON patch body)
/// * `signature_hex` — Hex-encoded 64-byte Ed25519 signature
///
/// # Returns
/// `Ok(())` if signature is valid. `Err(SignatureInvalid)` otherwise.
pub fn verify_patch_signature(payload: &[u8], signature_hex: &str) -> VtResult<()> {
    // Load the hardcoded maintainer public key
    let verifying_key = load_verifying_key(VU_ED25519_VERIFYING_KEY_HEX)?;
    verify_with_key(payload, signature_hex, &verifying_key)
}

/// Verify an Ed25519 signature using an explicit verifying key.
/// Used for community mirror key verification (non-primary channels).
pub fn verify_with_key(
    payload: &[u8],
    signature_hex: &str,
    verifying_key: &VerifyingKey,
) -> VtResult<()> {
    // Decode 64-byte signature from hex
    let sig_bytes = hex::decode(signature_hex.trim())
        .map_err(|_| VtError::SignatureInvalid)?;

    if sig_bytes.len() != 64 {
        return Err(VtError::SignatureInvalid);
    }

    let signature = Signature::from_bytes(
        sig_bytes
            .as_slice()
            .try_into()
            .map_err(|_| VtError::SignatureInvalid)?,
    );

    verifying_key
        .verify(payload, &signature)
        .map_err(|_| VtError::SignatureInvalid)
}

/// Parse an Ed25519 verifying key from a hex string.
pub fn load_verifying_key(hex_str: &str) -> VtResult<VerifyingKey> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|_| VtError::PublicKeyMalformed)?;

    if bytes.len() != 32 {
        return Err(VtError::PublicKeyMalformed);
    }

    let key_bytes: [u8; 32] = bytes.try_into().map_err(|_| VtError::PublicKeyMalformed)?;

    VerifyingKey::from_bytes(&key_bytes).map_err(|_| VtError::PublicKeyMalformed)
}

// ── Unit Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::Signer;

    fn test_keypair() -> (ed25519_dalek::SigningKey, VerifyingKey) {
        let signing_key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let verifying_key = signing_key.verifying_key();
        (signing_key, verifying_key)
    }

    #[test]
    fn test_valid_signature_accepted() {
        let (signing_key, verifying_key) = test_keypair();
        let payload = b"void-tunnel config patch v1.2.3";
        let signature = signing_key.sign(payload);
        let sig_hex = hex::encode(signature.to_bytes());

        assert!(verify_with_key(payload, &sig_hex, &verifying_key).is_ok());
    }

    #[test]
    fn test_tampered_payload_rejected() {
        let (signing_key, verifying_key) = test_keypair();
        let payload = b"original payload";
        let signature = signing_key.sign(payload);
        let sig_hex = hex::encode(signature.to_bytes());

        // Tamper with payload after signing
        let tampered = b"modified payload";
        assert!(verify_with_key(tampered, &sig_hex, &verifying_key).is_err());
    }

    #[test]
    fn test_wrong_key_rejected() {
        let (signing_key, _) = test_keypair();
        let (_, wrong_key) = test_keypair();
        let payload = b"authentic";
        let signature = signing_key.sign(payload);
        let sig_hex = hex::encode(signature.to_bytes());

        assert!(verify_with_key(payload, &sig_hex, &wrong_key).is_err());
    }

    #[test]
    fn test_malformed_hex_signature_rejected() {
        let (_, verifying_key) = test_keypair();
        let payload = b"data";
        assert!(verify_with_key(payload, "not-valid-hex", &verifying_key).is_err());
    }

    #[test]
    fn test_wrong_length_signature_rejected() {
        let (_, verifying_key) = test_keypair();
        let payload = b"data";
        let short_sig = "ab".repeat(30); // 30 bytes, not 64
        assert!(verify_with_key(payload, &short_sig, &verifying_key).is_err());
    }

    #[test]
    fn test_load_verifying_key_valid() {
        let (_, verifying_key) = test_keypair();
        let hex_str = hex::encode(verifying_key.to_bytes());
        let loaded = load_verifying_key(&hex_str).unwrap();
        assert_eq!(loaded.to_bytes(), verifying_key.to_bytes());
    }

    #[test]
    fn test_load_verifying_key_wrong_length() {
        let short_hex = "deadbeef00112233";
        assert!(load_verifying_key(short_hex).is_err());
    }
}