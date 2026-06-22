// ============================================================
// VOID-TUNNEL :: vt-core :: crypto :: chacha.rs
//
// ChaCha20-Poly1305 AEAD Symmetric Encryption Engine
//
// Security Properties:
//   - Unique cryptographic nonce per packet (96-bit, random)
//   - Authenticated encryption: any tampering invalidates MAC
//   - Keys zeroized from RAM immediately after use
//   - Nonce prepended to ciphertext for transmission
//
// Wire Format (encrypted packet):
//   [ 12-byte random nonce | ciphertext | 16-byte Poly1305 tag ]
//
// Author: Vladimir Unknown
// ============================================================

use chacha20poly1305::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    ChaCha20Poly1305, Key, Nonce,
};
use rand::RngCore;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{VtError, VtResult};

/// Size of a ChaCha20-Poly1305 key in bytes (256-bit)
pub const KEY_SIZE: usize = 32;

/// Size of a ChaCha20-Poly1305 nonce in bytes (96-bit)
pub const NONCE_SIZE: usize = 12;

/// Poly1305 authentication tag size in bytes
pub const TAG_SIZE: usize = 16;

/// Minimum encrypted packet size:
/// nonce (12) + empty plaintext (0) + tag (16) = 28 bytes
pub const MIN_ENCRYPTED_SIZE: usize = NONCE_SIZE + TAG_SIZE;

// ── Core Encrypt/Decrypt ──────────────────────────────────────────────────────

/// Encrypt plaintext using ChaCha20-Poly1305 with a unique random nonce.
///
/// The nonce is generated via OS CSPRNG (via `OsRng`) and prepended
/// to the ciphertext for transmission. The key is not stored after use.
///
/// # Wire output format:
/// `[ 12 nonce bytes | encrypted_bytes | 16 poly1305 tag bytes ]`
pub fn encrypt(key_bytes: &[u8; KEY_SIZE], plaintext: &[u8]) -> VtResult<Vec<u8>> {
    // Initialize cipher with the provided key
    let key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    // Generate unique 96-bit nonce from OS entropy source
    let nonce = ChaCha20Poly1305::generate_nonce(&mut OsRng);

    // Encrypt + authenticate (AEAD)
    let ciphertext = cipher
        .encrypt(&nonce, plaintext)
        .map_err(|_| VtError::AeadEncryptionFailed)?;

    // Prepend nonce: [ nonce (12) | ciphertext | tag (16) ]
    let mut output = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    output.extend_from_slice(nonce.as_slice());
    output.extend_from_slice(&ciphertext);

    Ok(output)
}

/// Decrypt a ChaCha20-Poly1305 encrypted packet received from the wire.
///
/// Extracts the nonce from the first 12 bytes, then decrypts and
/// verifies the Poly1305 authentication tag. Any tampering with
/// the ciphertext or tag causes authentication failure.
pub fn decrypt(key_bytes: &[u8; KEY_SIZE], packet: &[u8]) -> VtResult<Vec<u8>> {
    // Reject packets too small to contain nonce + tag
    if packet.len() < MIN_ENCRYPTED_SIZE {
        return Err(VtError::AeadDecryptionFailed);
    }

    // Extract nonce from wire packet prefix
    let (nonce_bytes, ciphertext_with_tag) = packet.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    // Initialize cipher
    let key = Key::from_slice(key_bytes);
    let cipher = ChaCha20Poly1305::new(key);

    // Decrypt and verify authentication tag atomically
    let plaintext = cipher
        .decrypt(nonce, ciphertext_with_tag)
        .map_err(|_| VtError::AeadDecryptionFailed)?;

    Ok(plaintext)
}

// ── Key Validation Helper ─────────────────────────────────────────────────────

/// Parse and validate a hex-encoded 32-byte ChaCha20 key string.
/// Returns the key bytes zeroized in a `Zeroizing` wrapper.
pub fn parse_key_from_hex(hex_str: &str) -> VtResult<Zeroizing<[u8; KEY_SIZE]>> {
    let bytes = hex::decode(hex_str.trim())
        .map_err(|_| VtError::AeadDecryptionFailed)?;

    if bytes.len() != KEY_SIZE {
        return Err(VtError::AeadDecryptionFailed);
    }

    let mut key = Zeroizing::new([0u8; KEY_SIZE]);
    key.copy_from_slice(&bytes);
    Ok(key)
}

// ── Unit Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::keygen::generate_chacha_key;

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let key = generate_chacha_key().unwrap();
        let plaintext = b"void-tunnel :: test payload :: hello darkness";

        let encrypted = encrypt(&key, plaintext).unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();

        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_encrypted_size_is_nonce_plus_ciphertext_plus_tag() {
        let key = generate_chacha_key().unwrap();
        let plaintext = b"16 bytes exactly";

        let encrypted = encrypt(&key, plaintext).unwrap();

        // Expected: 12 (nonce) + 16 (plaintext) + 16 (tag) = 44
        assert_eq!(encrypted.len(), NONCE_SIZE + plaintext.len() + TAG_SIZE);
    }

    #[test]
    fn test_unique_nonce_per_encryption() {
        let key = generate_chacha_key().unwrap();
        let plaintext = b"same plaintext, same key";

        let enc_a = encrypt(&key, plaintext).unwrap();
        let enc_b = encrypt(&key, plaintext).unwrap();

        // Nonces must differ due to OsRng
        assert_ne!(&enc_a[..NONCE_SIZE], &enc_b[..NONCE_SIZE]);
        // Full ciphertexts must differ (nonce uniqueness guarantees this)
        assert_ne!(enc_a, enc_b);
    }

    #[test]
    fn test_tampered_ciphertext_rejected() {
        let key = generate_chacha_key().unwrap();
        let mut encrypted = encrypt(&key, b"authentic payload").unwrap();

        // Flip one bit in the ciphertext body (after nonce)
        encrypted[NONCE_SIZE + 2] ^= 0xFF;

        assert!(decrypt(&key, &encrypted).is_err());
    }

    #[test]
    fn test_tampered_tag_rejected() {
        let key = generate_chacha_key().unwrap();
        let mut encrypted = encrypt(&key, b"authentic payload").unwrap();

        // Corrupt the last byte of the Poly1305 tag
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;

        assert!(decrypt(&key, &encrypted).is_err());
    }

    #[test]
    fn test_wrong_key_rejected() {
        let key_a = generate_chacha_key().unwrap();
        let key_b = generate_chacha_key().unwrap();

        let encrypted = encrypt(&key_a, b"secret message").unwrap();
        assert!(decrypt(&key_b, &encrypted).is_err());
    }

    #[test]
    fn test_truncated_packet_rejected() {
        let key = generate_chacha_key().unwrap();
        // Packet shorter than minimum (28 bytes)
        let short_packet = vec![0u8; 10];
        assert!(decrypt(&key, &short_packet).is_err());
    }

    #[test]
    fn test_empty_plaintext_roundtrip() {
        let key = generate_chacha_key().unwrap();
        let encrypted = encrypt(&key, b"").unwrap();
        let decrypted = decrypt(&key, &encrypted).unwrap();
        assert_eq!(decrypted, b"");
    }

    #[test]
    fn test_parse_key_from_valid_hex() {
        let key = generate_chacha_key().unwrap();
        let hex_str = hex::encode(key.as_slice());
        let parsed = parse_key_from_hex(&hex_str).unwrap();
        assert_eq!(parsed.as_slice(), key.as_slice());
    }

    #[test]
    fn test_parse_key_wrong_length_rejected() {
        let short_hex = "deadbeef";
        assert!(parse_key_from_hex(short_hex).is_err());
    }
}