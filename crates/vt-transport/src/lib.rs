// ============================================================
// VOID-TUNNEL :: vt-transport :: lib.rs
// Public API surface for the entire transport layer
// Author: Vladimir Unknown
// ============================================================

pub mod proxy {
    pub mod socks5;
    pub mod http_proxy;
}

pub mod tunnel {
    pub mod client;
    pub mod stream;
    pub mod failover;
}

pub mod obfs {
    pub mod packet_split;
    pub mod quic_cloak;
    pub mod ja4;
}

pub mod dns {
    pub mod resolver;
}

pub mod bootstrap {
    pub mod nodes;
    pub mod dht;
    pub mod discovery;
}

pub mod kill_switch;
pub mod metrics;
pub mod error;

// ── Re-exports ────────────────────────────────────────────────
pub use error::{TransportError, TransportResult};
pub use proxy::socks5::Socks5Server;
pub use proxy::http_proxy::HttpProxyServer;
pub use tunnel::client::TunnelClient;
pub use tunnel::failover::FailoverOrchestrator;
pub use kill_switch::KillSwitch;
pub use metrics::CloakingMetrics;