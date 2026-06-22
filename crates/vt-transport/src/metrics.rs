// ============================================================
// VOID-TUNNEL :: vt-transport :: metrics.rs
//
// Real-Time Cloaking Metrics Collector
// Feeds live data to the Tauri GUI and CLI TUI dashboards.
// Vladimir Unknown Cloaking Framework — operational telemetry.
//
// Author: Vladimir Unknown
// ============================================================

use parking_lot::RwLock;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// Snapshot of current cloaking and tunnel performance metrics.
/// Serialized to JSON and sent to the Tauri frontend via IPC events.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct MetricsSnapshot {
    /// Total bytes sent through tunnel (raw payload, before padding)
    pub bytes_sent_raw: u64,

    /// Total bytes sent on wire (with padding overhead)
    pub bytes_sent_wire: u64,

    /// Total bytes received (after decapsulation)
    pub bytes_received: u64,

    /// Current padding overhead percentage
    pub padding_overhead_pct: f64,

    /// Last observed random padding size (bytes)
    pub last_padding_bytes: usize,

    /// Last observed inter-fragment jitter delay (microseconds)
    pub last_jitter_us: u64,

    /// Active tunnel provider name
    pub active_provider: String,

    /// Number of successful failovers in this session
    pub failover_count: u32,

    /// Current tunnel latency (RTT) in milliseconds
    pub rtt_ms: f64,

    /// Packets sent this session
    pub packets_sent: u64,

    /// Packets received this session
    pub packets_received: u64,

    /// Current connection state
    pub state: ConnectionState,

    /// Active jurisdiction profile
    pub active_profile: String,

    /// JA4 fingerprint currently active
    pub ja4_profile: String,

    /// Timestamp of last metric update (Unix ms)
    pub updated_at_ms: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    #[default]
    Disconnected,
    Bootstrapping,
    Connecting,
    Connected,
    Failover,   // Amber UI indicator
    KillSwitch, // Red UI indicator — all traffic halted
}

/// Thread-safe shared metrics store.
/// Wrapped in Arc<RwLock<>> for multi-threaded Tokio access.
#[derive(Debug, Clone)]
pub struct CloakingMetrics {
    inner: Arc<RwLock<MetricsSnapshot>>,
    session_start: Instant,
}

impl CloakingMetrics {
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(MetricsSnapshot::default())),
            session_start: Instant::now(),
        }
    }

    /// Record an outbound packet transmission.
    pub fn record_outbound(&self, raw_bytes: usize, wire_bytes: usize, padding_bytes: usize) {
        let mut m = self.inner.write();
        m.bytes_sent_raw = m.bytes_sent_raw.saturating_add(raw_bytes as u64);
        m.bytes_sent_wire = m.bytes_sent_wire.saturating_add(wire_bytes as u64);
        m.packets_sent = m.packets_sent.saturating_add(1);
        m.last_padding_bytes = padding_bytes;

        // Recalculate live padding overhead percentage
        if m.bytes_sent_wire > 0 {
            let overhead = (m.bytes_sent_wire - m.bytes_sent_raw) as f64;
            m.padding_overhead_pct = (overhead / m.bytes_sent_wire as f64) * 100.0;
        }

        m.updated_at_ms = current_unix_ms();
    }

    /// Record an inbound packet receipt.
    pub fn record_inbound(&self, bytes: usize) {
        let mut m = self.inner.write();
        m.bytes_received = m.bytes_received.saturating_add(bytes as u64);
        m.packets_received = m.packets_received.saturating_add(1);
        m.updated_at_ms = current_unix_ms();
    }

    /// Record a jitter delay applied during handshake fragmentation.
    pub fn record_jitter(&self, delay_us: u64) {
        let mut m = self.inner.write();
        m.last_jitter_us = delay_us;
        m.updated_at_ms = current_unix_ms();
    }

    /// Record a tunnel RTT measurement.
    pub fn record_rtt(&self, rtt: Duration) {
        let mut m = self.inner.write();
        m.rtt_ms = rtt.as_secs_f64() * 1000.0;
        m.updated_at_ms = current_unix_ms();
    }

    /// Update connection state (drives UI color changes).
    pub fn set_state(&self, state: ConnectionState) {
        let mut m = self.inner.write();
        m.state = state;
        m.updated_at_ms = current_unix_ms();
    }

    /// Record a failover event.
    pub fn record_failover(&self, new_provider: &str) {
        let mut m = self.inner.write();
        m.failover_count = m.failover_count.saturating_add(1);
        m.active_provider = new_provider.to_string();
        m.state = ConnectionState::Failover;
        m.updated_at_ms = current_unix_ms();
    }

    /// Update the active provider label.
    pub fn set_provider(&self, provider: &str) {
        let mut m = self.inner.write();
        m.active_provider = provider.to_string();
    }

    /// Update active geo-profile label.
    pub fn set_profile(&self, profile: &str) {
        let mut m = self.inner.write();
        m.active_profile = profile.to_string();
    }

    /// Update JA4 fingerprint label.
    pub fn set_ja4(&self, ja4: &str) {
        let mut m = self.inner.write();
        m.ja4_profile = ja4.to_string();
    }

    /// Get a snapshot clone for UI serialization.
    pub fn snapshot(&self) -> MetricsSnapshot {
        self.inner.read().clone()
    }

    /// Reset all metrics for a new session.
    pub fn reset(&self) {
        let mut m = self.inner.write();
        *m = MetricsSnapshot::default();
        m.updated_at_ms = current_unix_ms();
    }
}

fn current_unix_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}