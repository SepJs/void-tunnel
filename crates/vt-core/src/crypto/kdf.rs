// ============================================================
// VOID-TUNNEL :: vt-core :: crypto :: kdf.rs
//
// Key Derivation Function for DHT Info-Hash Mapping
//
// Maps Void-Link bridge addresses into cryptographic info-hashes
// that blend with BitTorrent Mainline DHT lookup traffic.
//
// Uses HKDF-SHA256 with a domain-separation context string.
//
// Author: Vladimir Unknown
// ============================================================

use hkdf::Hkdf;
use sha2::Sha256;

use crate::error::{VtError, VtResult};

/// Domain separation label for DHT hash derivation
const DHT_CONTEXT: &[u8] = b"void-tunnel-dht-v1";

/// Size of a BitTorrent DHT info-hash in bytes (SHA-1 compatible = 20 bytes)
pub const DHT_INFOHASH_SIZE: usize = 20;

/// Derive a 20-byte DHT info-hash from a Void-Link bridge address.
///
/// Uses HKDF-SHA256 with a fixed domain separation context to ensure
/// that the derived hash is uniquely bound to the Void-Tunnel namespace
/// while appearing as a valid BitTorrent torrent lookup to censors.
///
/// # Arguments
/// * `bridge_address` — The cleartext bridge address string
///                      (e.g., "void-link://abc123@workers.dev:443")
/// * `salt`           — Random per-session salt for output diversity
pub fn derive_dht_infohash(
    bridge_address: &str,
    salt: &[u8],
) -> VtResult<[u8; DHT_INFOHASH_SIZE]> {
    let hk = Hkdf::<Sha256>::new(Some(salt), bridge_address.as_bytes());

    let mut output = [0u8; DHT_INFOHASH_SIZE];
    hk.expand(DHT_CONTEXT, &mut output)
        .map_err(|_| VtError::KdfError)?;

    Ok(output)
}

// ── Unit Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_infohash_is_correct_length() {
        let hash = derive_dht_infohash("void-link://test@example.com:443", b"salt")
            .unwrap();
        assert_eq!(hash.len(), DHT_INFOHASH_SIZE);
    }

    #[test]
    fn test_same_input_same_output() {
        let a = derive_dht_infohash("void-link://node@cf.com:443", b"salt1").unwrap();
        let b = derive_dht_infohash("void-link://node@cf.com:443", b"salt1").unwrap();
        assert_eq!(a, b);
    }

    #[test]
    fn test_different_address_different_hash() {
        let a = derive_dht_infohash("void-link://node-a@cf.com:443", b"s").unwrap();
        let b = derive_dht_infohash("void-link://node-b@cf.com:443", b"s").unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn test_different_salt_different_hash() {
        let a = derive_dht_infohash("void-link://node@cf.com:443", b"salt-1").unwrap();
        let b = derive_dht_infohash("void-link://node@cf.com:443", b"salt-2").unwrap();
        assert_ne!(a, b);
    }
}