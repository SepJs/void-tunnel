// ============================================================
// VOID-TUNNEL :: vt-transport :: obfs :: packet_split.rs
//
// Dynamic Packet Splitting Engine
//
// Fragments the TLS Client Hello and early handshake bytes into
// micro-fragments of randomized size (1..=16 bytes) transmitted
// with artificial non-deterministic inter-fragment delays.
//
// This permanently scrambles protocol signatures, preventing
// hardware-accelerated DPI firewalls from pattern-matching
// the connection as a proxy tunnel.
//
// Author: Vladimir Unknown
// ============================================================

use std::time::Duration;

use rand::{thread_rng, Rng};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::time::sleep;
use tracing::debug;

use vt_core::config::schema::PacketSplitConfig;
use vt_core::padding::polymorphic::fragment_handshake;

use crate::error::{TransportError, TransportResult};
use crate::metrics::CloakingMetrics;

/// The Dynamic Packet Splitting engine configured from active profile.
pub struct PacketSplitter {
    config: PacketSplitConfig,
}

impl PacketSplitter {
    pub fn from_config(config: &PacketSplitConfig) -> Self {
        Self {
            config: config.clone(),
        }
    }

    /// Transmit handshake bytes as micro-fragments with jitter delays.
    ///
    /// Each fragment is written to the socket individually, followed
    /// by a randomized microsecond/millisecond sleep delay.
    /// This disrupts stateful DPI reassembly engines.
    pub async fn transmit_fragmented(
        &self,
        stream: &mut TcpStream,
        data: &[u8],
        metrics: &CloakingMetrics,
    ) -> TransportResult<()> {
        let fragments = self.fragment(data);
        let mut rng = thread_rng();

        debug!(
            "Transmitting {} bytes as {} fragments",
            data.len(), fragments.len()
        );

        for fragment in &fragments {
            // Write fragment to socket
            stream.write_all(fragment).await
                .map_err(|_| TransportError::PacketSplitError)?;

            // Apply randomized inter-fragment jitter delay
            let delay_ms = rng.gen_range(
                self.config.min_delay_ms..=self.config.max_delay_ms
            );
            let delay_us = delay_ms * 1000;

            metrics.record_jitter(delay_us);

            debug!(
                "Fragment {}B sent | jitter {}ms",
                fragment.len(), delay_ms
            );

            sleep(Duration::from_millis(delay_ms)).await;
        }

        Ok(())
    }

    /// Fragment data into randomized-size chunks.
    pub fn fragment(&self, data: &[u8]) -> Vec<Vec<u8>> {
        let mut rng = thread_rng();
        let mut fragments = Vec::new();
        let mut offset = 0;

        while offset < data.len() {
            let remaining = data.len() - offset;
            let frag_size = rng.gen_range(
                self.config.min_fragment_bytes..=
                    remaining.min(self.config.max_fragment_bytes)
            );

            fragments.push(data[offset..offset + frag_size].to_vec());
            offset += frag_size;
        }

        fragments
    }

    /// Transmit data without fragmentation (for non-handshake packets).
    pub async fn transmit_normal(
        stream: &mut TcpStream,
        data: &[u8],
    ) -> TransportResult<()> {
        stream.write_all(data).await
            .map_err(|_| TransportError::PacketSplitError)
    }
}

// ── Unit Tests ────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use vt_core::config::schema::PacketSplitConfig;

    fn default_splitter() -> PacketSplitter {
        PacketSplitter::from_config(&PacketSplitConfig {
            min_fragment_bytes: 1,
            max_fragment_bytes: 16,
            min_delay_ms: 1,
            max_delay_ms: 5,
        })
    }

    #[test]
    fn test_fragments_cover_all_bytes() {
        let splitter = default_splitter();
        let data: Vec<u8> = (0u8..200u8).collect();
        let frags = splitter.fragment(&data);

        let reassembled: Vec<u8> = frags.into_iter().flatten().collect();
        assert_eq!(reassembled, data);
    }

    #[test]
    fn test_fragment_sizes_within_bounds() {
        let splitter = default_splitter();
        let data = vec![0u8; 500];
        let frags = splitter.fragment(&data);

        for f in &frags {
            assert!(f.len() >= 1 && f.len() <= 16);
        }
    }

    #[test]
    fn test_empty_data_produces_no_fragments() {
        let splitter = default_splitter();
        let frags = splitter.fragment(&[]);
        assert!(frags.is_empty());
    }

    #[test]
    fn test_single_byte_data() {
        let splitter = default_splitter();
        let frags = splitter.fragment(&[0xAB]);
        assert_eq!(frags.len(), 1);
        assert_eq!(frags[0], vec![0xAB]);
    }
}