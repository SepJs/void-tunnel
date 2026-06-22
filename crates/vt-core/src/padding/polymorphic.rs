// ============================================================
// VOID-TUNNEL :: vt-core :: padding :: polymorphic.rs
//
// Polymorphic Padding Protocol — Anti-ML-DPI Shield
//
// Wire Frame Format:
//   [ 2 bytes: payload_len (Big-Endian u16)
//   | payload_len bytes: encrypted payload
//   | N bytes: cryptographically random noise padding ]
//
// N is sampled from a dynamically shifting distribution matrix.
// This renders packet-length frequency analysis ineffective.
//
// Author: Vladimir Unknown
// ============================================================

use rand::{thread_rng, Rng, RngCore};

use crate::error::{VtError, VtResult};
use crate::padding::distributions::{PaddingDistribution, PaddingParams};

/// Minimum allowed padding bytes per packet
pub const MIN_PADDING: usize = 32;

/// Maximum allowed padding bytes per packet (MTU-aware ceiling)
pub const MAX_PADDING: usize = 1500;

/// Size of the payload length header in bytes (Big-Endian u16)
pub const PAYLOAD_LEN_HEADER_SIZE: usize = 2;

// ── Encapsulation ─────────────────────────────────────────────────────────────

/// Encapsulate an encrypted payload inside a Polymorphic Padding frame.
///
/// The output wire frame consists of:
///   1. A 2-byte Big-Endian u16 declaring the exact payload length
///   2. The encrypted payload bytes
///   3. N random noise bytes (N chosen from the active distribution)
///
/// # Arguments
/// * `payload` — Already-encrypted bytes to encapsulate
/// * `params`  — Active padding distribution parameters
pub fn encapsulate(payload: &[u8], params: &PaddingParams) -> VtResult<Vec<u8>> {
    let payload_len = payload.len();

    // Enforce payload fits in a u16 (65535 byte maximum)
    if payload_len > u16::MAX as usize {
        return Err(VtError::PaddingLengthOverflow);
    }

    // Sample padding size from the active statistical distribution
    let padding_len = params.distribution.sample(params)?;

    // Allocate output: 2 (header) + payload + padding
    let total_len = PAYLOAD_LEN_HEADER_SIZE + payload_len + padding_len;
    let mut frame = Vec::with_capacity(total_len);

    // 1. Write 2-byte Big-Endian payload length header
    let len_header = (payload_len as u16).to_be_bytes();
    frame.extend_from_slice(&len_header);

    // 2. Append the encrypted payload
    frame.extend_from_slice(payload);

    // 3. Append cryptographically secure random noise padding
    let mut noise = vec![0u8; padding_len];
    thread_rng().fill_bytes(&mut noise);
    frame.extend_from_slice(&noise);

    Ok(frame)
}

/// Decapsulate a Polymorphic Padding frame on the receiving end.
///
/// Reads the 2-byte header to determine payload boundary,
/// extracts exactly that many bytes, and discards all trailing noise.
///
/// # Arguments
/// * `frame` — Complete wire frame bytes received from the network
///
/// # Returns
/// The inner encrypted payload (noise discarded)
pub fn decapsulate(frame: &[u8]) -> VtResult<&[u8]> {
    // Must have at least the 2-byte header
    if frame.len() < PAYLOAD_LEN_HEADER_SIZE {
        return Err(VtError::PaddingHeaderTruncated);
    }

    // Parse 2-byte Big-Endian payload length
    let payload_len = u16::from_be_bytes([frame[0], frame[1]]) as usize;

    // Validate that the declared length fits within the received frame
    let payload_end = PAYLOAD_LEN_HEADER_SIZE + payload_len;
    if frame.len() < payload_end {
        return Err(VtError::PaddingLengthOverflow);
    }

    // Slice out the payload, discarding trailing noise in-place
    Ok(&frame[PAYLOAD_LEN_HEADER_SIZE..payload_end])
}

// ── Handshake Fragmentation ───────────────────────────────────────────────────

/// Fragment a byte stream into micro-fragments for handshake obfuscation.
///
/// Splits the input bytes into non-uniform fragments of size 1..=16 bytes.
/// Each fragment should be sent with an artificial inter-fragment delay
/// applied by the caller (see `vt-transport::obfs::packet_split`).
///
/// # Returns
/// A vector of non-overlapping byte slices covering the full input.
pub fn fragment_handshake(data: &[u8]) -> Vec<Vec<u8>> {
    let mut rng = thread_rng();
    let mut fragments = Vec::new();
    let mut offset = 0usize;

    while offset < data.len() {
        // Random fragment size: 1 to 16 bytes
        let remaining = data.len() - offset;
        let frag_size = rng.gen_range(1..=remaining.min(16));

        fragments.push(data[offset..offset + frag_size].to_vec());
        offset += frag_size;
    }

    fragments
}

// ── Unit Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use crate::padding::distributions::{PaddingDistribution, PaddingParams};

    fn test_params() -> PaddingParams {
        PaddingParams {
            distribution: PaddingDistribution::Uniform,
            min_bytes: 32,
            max_bytes: 256,
            mean: None,
            std_dev: None,
        }
    }

    #[test]
    fn test_encapsulate_decapsulate_roundtrip() {
        let payload = b"test encrypted payload for void-tunnel";
        let params = test_params();

        let frame = encapsulate(payload, &params).unwrap();
        let recovered = decapsulate(&frame).unwrap();

        assert_eq!(recovered, payload);
    }

    #[test]
    fn test_frame_contains_header_plus_payload_plus_padding() {
        let payload = b"hello";
        let params = test_params();
        let frame = encapsulate(payload, &params).unwrap();

        // Frame must be at least: 2 (header) + 5 (payload) + 32 (min padding)
        assert!(frame.len() >= PAYLOAD_LEN_HEADER_SIZE + payload.len() + MIN_PADDING);
    }

    #[test]
    fn test_two_encapsulations_differ_due_to_random_padding() {
        let payload = b"same payload";
        let params = test_params();

        let frame_a = encapsulate(payload, &params).unwrap();
        let frame_b = encapsulate(payload, &params).unwrap();

        // Frames may differ in either padding content or padding length
        // (they must differ statistically — this test catches consistent failures)
        // We check at least one differs from the other
        let noise_a = &frame_a[PAYLOAD_LEN_HEADER_SIZE + payload.len()..];
        let noise_b = &frame_b[PAYLOAD_LEN_HEADER_SIZE + payload.len()..];

        // It's statistically near-impossible for 32+ random bytes to match
        // (probability: 2^-256 for equal-length noise)
        if noise_a.len() == noise_b.len() {
            assert_ne!(noise_a, noise_b);
        }
    }

    #[test]
    fn test_truncated_frame_rejected_by_decapsulate() {
        let frame = vec![0u8; 1]; // Only 1 byte — header requires 2
        assert!(decapsulate(&frame).is_err());
    }

    #[test]
    fn test_declared_length_overflow_rejected() {
        // Header says payload is 1000 bytes but frame is only 10 bytes total
        let mut frame = vec![0u8; 10];
        let overflow_len: u16 = 1000;
        frame[0] = (overflow_len >> 8) as u8;
        frame[1] = (overflow_len & 0xFF) as u8;

        assert!(decapsulate(&frame).is_err());
    }

    #[test]
    fn test_empty_payload_roundtrip() {
        let params = test_params();
        let frame = encapsulate(b"", &params).unwrap();
        let recovered = decapsulate(&frame).unwrap();
        assert_eq!(recovered, b"");
    }

    #[test]
    fn test_handshake_fragmentation_covers_all_bytes() {
        let data: Vec<u8> = (0u8..=255u8).collect();
        let fragments = fragment_handshake(&data);

        // Reassemble fragments
        let reassembled: Vec<u8> = fragments.into_iter().flatten().collect();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_handshake_fragments_are_max_16_bytes() {
        let data = vec![0u8; 1000];
        let fragments = fragment_handshake(&data);

        for frag in &fragments {
            assert!(frag.len() >= 1 && frag.len() <= 16);
        }
    }
}