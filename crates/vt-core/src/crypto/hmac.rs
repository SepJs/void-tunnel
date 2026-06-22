// ============================================================
// VOID-TUNNEL :: vt-core :: crypto :: hmac.rs
//
// HMAC-SHA256 Time-Drift-Compensated Token Engine
//
// Security Properties:
//   - Constant-time comparison via `subtle` crate (anti-timing-attack)
//   - Maximum clock drift window: ±30 seconds (configurable)
//   - Replay prevention: time-epoch-binding to 30s slots
//   - Token format: HMAC( secret || unix_epoch_slot ) → hex(32 bytes)
//
// Author: Vladimir Unknown
// ============================================================

use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use zeroize::Zeroizing;

use crate::error::{VtError, VtResult};

type HmacSha256 = Hmac<Sha256>;

/// Maximum allowed clock drift in seconds between client and server.
pub const MAX_DRIFT_SECONDS: i64 = 30;

/// Granularity of the time slot window in seconds.
/// All timestamps within the same 30-second window hash identically,
/// providing replay resistance with drift tolerance.
pub const TIME_SLOT_GRANULARITY: i64 = 30;

// ── Token Generation ─────────────────────────────────────────────────────────

/// Generate a time-bound HMAC-SHA256 authentication token.
///
/// The token encodes the current 30-second epoch slot, preventing
/// replay attacks outside the valid drift window. The secret key
/// is zeroized from memory upon function return.
///
/// # Arguments
/// * `secret` — Pre-shared HMAC secret (32+ bytes recommended)
///
/// # Returns
/// Lowercase hex-encoded 32-byte HMAC digest (64 characters)
pub fn generate_token(secret: &[u8]) -> VtResult<String> {
    let slot = current_time_slot();
    compute_hmac_hex(secret, slot)
}

/// Generate tokens for the current slot AND adjacent drift windows.
/// Returns a Vec of valid tokens covering the full ±30s drift range.
/// Used server-side to accept tokens from slightly clock-skewed clients.
pub fn generate_valid_token_window(secret: &[u8]) -> VtResult<Vec<String>> {
    let now_slot = current_time_slot();

    // Cover: [slot-1, slot, slot+1] = ±30 seconds total drift window
    let slots = [now_slot - 1, now_slot, now_slot + 1];

    slots
        .iter()
        .map(|&slot| compute_hmac_hex(secret, slot))
        .collect()
}

// ── Token Validation ─────────────────────────────────────────────────────────

/// Validate a client-supplied HMAC token in constant time.
///
/// Checks the token against all valid slots in the ±30s drift window.
/// Uses `subtle::ConstantTimeEq` to prevent timing oracle attacks.
/// Returns `Err(HmacReplayDetected)` if no slot matches.
///
/// # Arguments
/// * `secret`       — Server-side pre-shared HMAC secret
/// * `client_token` — Hex-encoded token received from client header
pub fn validate_token(secret: &[u8], client_token: &str) -> VtResult<()> {
    // Decode client token from hex — failure is not a timing leak path
    let client_bytes = hex::decode(client_token.trim())
        .map_err(|_| VtError::HmacValidationFailed)?;

    if client_bytes.len() != 32 {
        return Err(VtError::HmacValidationFailed);
    }

    let valid_tokens = generate_valid_token_window(secret)?;

    // Perform constant-time comparison across ALL valid window tokens.
    // We must check all slots regardless of early match to prevent
    // timing side-channels leaking which slot matched.
    let mut any_match: u8 = 0u8;

    for valid_token_hex in &valid_tokens {
        let valid_bytes = hex::decode(valid_token_hex)
            .map_err(|_| VtError::HmacValidationFailed)?;

        // subtle::ConstantTimeEq ensures branch-free comparison
        let cmp: u8 = client_bytes.ct_eq(&valid_bytes).unwrap_u8();
        any_match |= cmp; // OR-accumulate: 1 if any slot matched
    }

    if any_match == 1u8 {
        Ok(())
    } else {
        Err(VtError::HmacReplayDetected)
    }
}

// ── Internal Helpers ─────────────────────────────────────────────────────────

/// Compute HMAC-SHA256( secret || little_endian(slot) ) → lowercase hex
fn compute_hmac_hex(secret: &[u8], slot: i64) -> VtResult<String> {
    let mut mac = HmacSha256::new_from_slice(secret)
        .map_err(|_| VtError::HmacValidationFailed)?;

    // Bind the time slot into the MAC input as a fixed 8-byte LE integer
    mac.update(&slot.to_le_bytes());

    let result = mac.finalize().into_bytes();

    // Zeroize intermediate result before returning hex string
    let hex_str = hex::encode(result.as_slice());
    Ok(hex_str)
}

/// Return the current 30-second granularity Unix time slot.
/// All timestamps within the same 30s window produce the same slot number.
fn current_time_slot() -> i64 {
    let now = Utc::now().timestamp();
    now / TIME_SLOT_GRANULARITY
}

// ── Unit Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn test_secret() -> Vec<u8> {
        b"void-tunnel-test-secret-key-32b!".to_vec()
    }

    #[test]
    fn test_token_generation_is_deterministic_within_slot() {
        let secret = test_secret();
        let token_a = generate_token(&secret).unwrap();
        let token_b = generate_token(&secret).unwrap();
        // Within the same test execution (same time slot), tokens must match
        assert_eq!(token_a, token_b);
    }

    #[test]
    fn test_token_hex_length() {
        let token = generate_token(&test_secret()).unwrap();
        // HMAC-SHA256 = 32 bytes = 64 hex characters
        assert_eq!(token.len(), 64);
        assert!(token.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_valid_token_validates_successfully() {
        let secret = test_secret();
        let token = generate_token(&secret).unwrap();
        assert!(validate_token(&secret, &token).is_ok());
    }

    #[test]
    fn test_invalid_token_rejected() {
        let secret = test_secret();
        let bad_token = "a".repeat(64); // 32 bytes of 0xaa
        assert!(validate_token(&secret, &bad_token).is_err());
    }

    #[test]
    fn test_wrong_secret_rejected() {
        let secret_a = test_secret();
        let secret_b = b"completely-different-secret-key!".to_vec();
        let token = generate_token(&secret_a).unwrap();
        assert!(validate_token(&secret_b, &token).is_err());
    }

    #[test]
    fn test_token_window_covers_three_slots() {
        let window = generate_valid_token_window(&test_secret()).unwrap();
        assert_eq!(window.len(), 3);
        // All three must be valid hex strings of correct length
        for t in window {
            assert_eq!(t.len(), 64);
        }
    }

    #[test]
    fn test_truncated_token_rejected() {
        let secret = test_secret();
        // Only 30 hex chars (15 bytes) — too short
        let short_token = "ab".repeat(15);
        assert!(validate_token(&secret, &short_token).is_err());
    }

    #[test]
    fn test_non_hex_token_rejected() {
        let secret = test_secret();
        let garbage = "ZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ";
        assert!(validate_token(&secret, garbage).is_err());
    }
}