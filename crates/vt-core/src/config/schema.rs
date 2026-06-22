// ============================================================
// VOID-TUNNEL :: vt-core :: config :: schema.rs
//
// Unified Configuration Schema — All User Profiles
//
// Serializes to/from TOML for file storage and JSON for
// hot-patch updates and API communication.
//
// Author: Vladimir Unknown
// ============================================================

use serde::{Deserialize, Serialize};

use crate::padding::distributions::PaddingParams;

/// Operational mode selected by the user.
/// Controls UI complexity and automatic vs. manual failover behavior.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
#[serde(rename_all = "snake_case")]
pub enum OperationalMode {
    /// Non-technical users — fully automated, minimal UI
    #[default]
    GeneralPrivacy,

    /// Security researchers — full controls exposed, auto-switch allowed
    AdvancedResearcher,

    /// Journalists/activists — maximum hardening, manual failover only
    HighRiskStrict,
}

/// Target jurisdiction for out-of-the-box evasion preset selection.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Jurisdiction {
    Iran,
    China,
    Russia,
    Custom,
}

/// Supported application interface languages.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub enum Language {
    #[default]
    English,
    Russian,
    Chinese,
    Persian,
}

/// Complete cryptographic credential set for a single deployment node.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NodeCredentials {
    /// Hex-encoded ChaCha20-Poly1305 symmetric key (32 bytes)
    pub chacha_key_hex: String,

    /// Hex-encoded HMAC-SHA256 shared secret (32 bytes)
    pub hmac_secret_hex: String,

    /// Worker subdomain URL (e.g. "void-tunnel-edge.username.workers.dev")
    pub worker_url: String,

    /// Cloudflare Account ID (used for multi-account failover)
    pub account_id: String,
}

/// Serverless provider target for outbound tunnel connections.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ServerlessProvider {
    CloudflareWorkers,
    VercelEdge,
    SupabaseEdge,
    AwsLambda,
    CommunityMirror { url: String },
}

/// TLS JA4 fingerprint spoofing profile.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum Ja4Profile {
    /// Mimic latest stable Chrome on desktop (Windows/Linux/macOS)
    ChromeDesktopLatest,

    /// Mimic native Safari on iOS
    SafariIosLatest,

    /// Custom cipher suite ordering (Advanced Researcher Mode)
    Custom {
        cipher_suites: Vec<u16>,
        extensions: Vec<u16>,
        elliptic_curves: Vec<u16>,
    },
}

/// Packet splitting configuration for handshake fragmentation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PacketSplitConfig {
    /// Minimum fragment size in bytes (1..=16 recommended for handshake)
    pub min_fragment_bytes: usize,

    /// Maximum fragment size in bytes
    pub max_fragment_bytes: usize,

    /// Minimum inter-fragment delay in milliseconds
    pub min_delay_ms: u64,

    /// Maximum inter-fragment delay in milliseconds
    pub max_delay_ms: u64,
}

impl Default for PacketSplitConfig {
    fn default() -> Self {
        Self {
            min_fragment_bytes: 1,
            max_fragment_bytes: 16,
            min_delay_ms: 1,
            max_delay_ms: 5,
        }
    }
}

/// Iran-optimized packet split defaults:
/// Aggressive fragmentation (1-8 bytes) + exponential jitter (2-7ms)
pub fn iran_packet_split_config() -> PacketSplitConfig {
    PacketSplitConfig {
        min_fragment_bytes: 1,
        max_fragment_bytes: 8,
        min_delay_ms: 2,
        max_delay_ms: 7,
    }
}

/// Complete Void-Tunnel runtime configuration.
/// Stored locally at: `~/.config/void-tunnel/config.toml` (Linux/macOS)
///                    `%APPDATA%\void-tunnel\config.toml` (Windows)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VoidTunnelConfig {
    /// Schema version for forward compatibility
    pub schema_version: u32,

    /// Current operational mode
    pub mode: OperationalMode,

    /// Active UI language
    pub language: Language,

    /// Target jurisdiction for embedded preset selection
    pub jurisdiction: Option<Jurisdiction>,

    /// Primary deployment node credentials
    pub primary_node: Option<NodeCredentials>,

    /// Optional secondary/backup node credentials (multi-account)
    pub secondary_nodes: Vec<NodeCredentials>,

    /// Active serverless provider chain (in failover priority order)
    pub provider_chain: Vec<ServerlessProvider>,

    /// Local SOCKS5 proxy port (default: 1080)
    pub local_socks5_port: u16,

    /// Local HTTP proxy port (default: 8080)
    pub local_http_port: u16,

    /// Active polymorphic padding parameters
    pub padding: PaddingParams,

    /// Active packet splitting configuration
    pub packet_split: PacketSplitConfig,

    /// JA4 TLS fingerprint spoofing profile
    pub ja4_profile: Ja4Profile,

    /// Kill switch enabled (always true in HighRiskStrict mode)
    pub kill_switch_enabled: bool,

    /// DoH resolver URLs (bootstrapped with Cloudflare Anycast IPs)
    pub doh_resolvers: Vec<String>,

    /// Config patch channel Ed25519 verifying key override (optional)
    pub patch_verifying_key_override: Option<String>,
}

impl Default for VoidTunnelConfig {
    fn default() -> Self {
        Self {
            schema_version: 1,
            mode: OperationalMode::GeneralPrivacy,
            language: Language::English,
            jurisdiction: None,
            primary_node: None,
            secondary_nodes: Vec::new(),
            provider_chain: vec![ServerlessProvider::CloudflareWorkers],
            local_socks5_port: 1080,
            local_http_port: 8080,
            padding: crate::padding::distributions::iran_default_params(),
            packet_split: PacketSplitConfig::default(),
            ja4_profile: Ja4Profile::ChromeDesktopLatest,
            kill_switch_enabled: false,
            doh_resolvers: vec![
                "https://cloudflare-dns.com/dns-query".to_string(),
                "https://dns.google/dns-query".to_string(),
            ],
            patch_verifying_key_override: None,
        }
    }
}