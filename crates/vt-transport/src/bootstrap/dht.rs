// ============================================================
// VOID-TUNNEL :: vt-transport :: bootstrap :: dht.rs
//
// BitTorrent Mainline DHT Peer Discovery Client
//
// Publishes and queries ephemeral Void-Link bridge addresses
// mapped to cryptographic info-hashes via HKDF-SHA256 KDF.
//
// These hashes blend seamlessly with legitimate BitTorrent
// DHT lookup traffic, providing censorship-resistant
// rendezvous without centralized servers.
//
// Author: Vladimir Unknown
// ============================================================

use std::net::SocketAddr;
use std::time::Duration;

use rand::{thread_rng, Rng};
use tokio::net::UdpSocket;
use tokio::time::timeout;
use tracing::{debug, info, warn};

use vt_core::crypto::kdf::derive_dht_infohash;
use crate::error::{TransportError, TransportResult};

/// Well-known BitTorrent DHT bootstrap nodes (public infrastructure)
const DHT_BOOTSTRAP_NODES: &[&str] = &[
    "router.bittorrent.com:6881",
    "dht.transmissionbt.com:6881",
    "router.utorrent.com:6881",
    "dht.libtorrent.org:25401",
];

/// DHT session state for Void-Link peer discovery
pub struct DhtClient {
    socket: UdpSocket,
    /// Our ephemeral DHT node ID (20 random bytes)
    node_id: [u8; 20],
}

impl DhtClient {
    /// Initialize a new DHT client with a random ephemeral node ID.
    pub async fn new() -> TransportResult<Self> {
        let socket = UdpSocket::bind("0.0.0.0:0").await?;
        let mut node_id = [0u8; 20];
        thread_rng().fill_bytes(&mut node_id);

        Ok(Self { socket, node_id })
    }

    /// Derive the DHT info-hash for a Void-Link bridge address.
    /// Uses HKDF-SHA256 with a session-specific salt.
    pub fn derive_infohash(
        &self,
        bridge_address: &str,
    ) -> TransportResult<[u8; 20]> {
        // Use the first 8 bytes of our node_id as session salt
        // for output diversity across different Void-Tunnel instances
        derive_dht_infohash(bridge_address, &self.node_id[..8])
            .map_err(|e| TransportError::Crypto(e))
    }

    /// Announce our Void-Link bridge to the DHT network.
    /// This makes our bridge discoverable by other isolated clients.
    pub async fn announce_bridge(
        &self,
        bridge_address: &str,
        port: u16,
    ) -> TransportResult<()> {
        let infohash = self.derive_infohash(bridge_address)?;

        info!(
            "DHT: announcing bridge on infohash {:?}",
            hex::encode(&infohash)
        );

        // Send get_peers and announce_peer messages to bootstrap nodes
        for bootstrap in DHT_BOOTSTRAP_NODES {
            if let Ok(addr) = bootstrap.parse::<SocketAddr>() {
                let msg = build_announce_msg(&self.node_id, &infohash, port);
                let _ = self.socket.send_to(&msg, addr).await;
                debug!("DHT announce sent to {}", bootstrap);
            }
        }

        Ok(())
    }

    /// Query the DHT for peers sharing our Void-Link bridge info-hash.
    /// Returns a list of discovered peer socket addresses.
    pub async fn find_peers(
        &self,
        bridge_address: &str,
    ) -> TransportResult<Vec<SocketAddr>> {
        let infohash = self.derive_infohash(bridge_address)?;

        info!(
            "DHT: looking up peers for infohash {}",
            hex::encode(&infohash)
        );

        let mut discovered_peers: Vec<SocketAddr> = Vec::new();

        // Query all bootstrap nodes
        for bootstrap in DHT_BOOTSTRAP_NODES {
            if let Ok(addr) = bootstrap.parse::<SocketAddr>() {
                let query = build_get_peers_msg(&self.node_id, &infohash);

                if let Err(e) = self.socket.send_to(&query, addr).await {
                    warn!("DHT query send failed to {}: {}", bootstrap, e);
                    continue;
                }

                // Wait for response (up to 3 seconds per node)
                let mut recv_buf = [0u8; 4096];
                match timeout(
                    Duration::from_secs(3),
                    self.socket.recv_from(&mut recv_buf)
                ).await {
                    Ok(Ok((n, _from))) => {
                        let peers = parse_peers_response(&recv_buf[..n]);
                        debug!("DHT: got {} peers from {}", peers.len(), bootstrap);
                        discovered_peers.extend(peers);
                    }
                    _ => {
                        warn!("DHT: timeout/error from {}", bootstrap);
                    }
                }
            }
        }

        if discovered_peers.is_empty() {
            return Err(TransportError::DhtLookupFailed);
        }

        info!("DHT: discovered {} peers", discovered_peers.len());
        Ok(discovered_peers)
    }
}

// ── BEP-5 Message Builders ────────────────────────────────────────────────────

/// Build a BEP-5 get_peers query message (bencode format).
fn build_get_peers_msg(node_id: &[u8; 20], infohash: &[u8; 20]) -> Vec<u8> {
    // Minimal BEP-5 get_peers in bencode:
    // d1:ad2:id20:<node_id>9:info_hash20:<infohash>e1:q9:get_peers1:t2:aa1:y1:qe
    let mut msg = b"d1:ad2:id20:".to_vec();
    msg.extend_from_slice(node_id);
    msg.extend_from_slice(b"9:info_hash20:");
    msg.extend_from_slice(infohash);
    msg.extend_from_slice(b"e1:q9:get_peers1:t2:vt1:y1:qe");
    msg
}

/// Build a BEP-5 announce_peer message.
fn build_announce_msg(node_id: &[u8; 20], infohash: &[u8; 20], port: u16) -> Vec<u8> {
    let port_str = port.to_string();
    let mut msg = b"d1:ad2:id20:".to_vec();
    msg.extend_from_slice(node_id);
    msg.extend_from_slice(b"12:implied_porti1e9:info_hash20:");
    msg.extend_from_slice(infohash);
    msg.extend_from_slice(b"4:porti");
    msg.extend_from_slice(port_str.as_bytes());
    msg.extend_from_slice(b"e5:token4:vt00e1:q13:announce_peer1:t2:vt1:y1:qe");
    msg
}

/// Parse compact peer addresses from a DHT response.
/// Compact format: 6 bytes per peer (4 IP + 2 port).
fn parse_peers_response(data: &[u8]) -> Vec<SocketAddr> {
    let mut peers = Vec::new();

    // Find "6:" compact peer list marker and extract 6-byte peer records
    let marker = b"6:";
    if let Some(pos) = find_subsequence(data, marker) {
        let compact = &data[pos + 2..];
        let mut i = 0;
        while i + 6 <= compact.len() {
            let ip = std::net::Ipv4Addr::new(
                compact[i], compact[i+1], compact[i+2], compact[i+3]
            );
            let port = u16::from_be_bytes([compact[i+4], compact[i+5]]);
            if port > 0 {
                peers.push(SocketAddr::new(
                    std::net::IpAddr::V4(ip), port
                ));
            }
            i += 6;
        }
    }

    peers
}

fn find_subsequence(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack.windows(needle.len()).position(|w| w == needle)
}