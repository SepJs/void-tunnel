// ============================================================
// VOID-TUNNEL :: vt-transport :: bootstrap :: nodes.rs
//
// Pre-Deployed Public Bootstrap Node Matrix
//
// Embedded bootstrap entry points for zero-internet first launch.
// Primary tier: signed by Vladimir Unknown (Ed25519).
// Community tier: verified against hardcoded public key matrix.
//
// Author: Vladimir Unknown
// ============================================================

use serde::{Deserialize, Serialize};
use vt_core::crypto::ed25519::{load_verifying_key, verify_with_key};
use vt_core::error::VtResult;

/// A single bootstrap node entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BootstrapNode {
    /// Unique node identifier
    pub id: String,

    /// Worker endpoint URL (Cloudflare workers.dev or custom domain)
    pub url: String,

    /// Hex-encoded HMAC secret for this node
    pub hmac_secret_hex: String,

    /// Whether this is a primary (Vladimir Unknown) or community node
    pub tier: NodeTier,

    /// Geographic region tag
    pub region: String,

    /// Ed25519 signature over (id + url + hmac_secret_hex) bytes
    pub signature: String,

    /// Hex-encoded Ed25519 verifying key for community nodes
    /// (None for primary nodes — uses hardcoded VU key)
    pub community_verifying_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum NodeTier {
    /// Maintained and signed by Vladimir Unknown
    Primary,
    /// Community-contributed, independently verified
    Community,
}

/// The static embedded bootstrap node matrix.
/// These are pre-deployed public workers maintained for zero-internet bootstrap.
/// Replace URL and signature values with real deployed worker data.
pub fn embedded_bootstrap_nodes() -> Vec<BootstrapNode> {
    vec![
        BootstrapNode {
            id: "vt-bootstrap-primary-01".into(),
            url: "https://vt-bootstrap-01.void-tunnel.workers.dev".into(),
            hmac_secret_hex: "0000000000000000000000000000000000000000000000000000000000000000".into(),
            tier: NodeTier::Primary,
            region: "global".into(),
            signature: "0000000000000000000000000000000000000000000000000000000000000000\
                        0000000000000000000000000000000000000000000000000000000000000000".into(),
            community_verifying_key: None,
        },
        // Additional primary and community nodes added here at release time
    ]
}

/// Verify and return only nodes that pass Ed25519 signature validation.
pub fn get_verified_nodes() -> Vec<BootstrapNode> {
    embedded_bootstrap_nodes()
        .into_iter()
        .filter(|node| verify_node_signature(node).is_ok())
        .collect()
}

/// Verify a node's Ed25519 signature over its identity fields.
pub fn verify_node_signature(node: &BootstrapNode) -> VtResult<()> {
    // Construct the signed payload: id + url + hmac_secret_hex
    let payload = format!("{}{}{}", node.id, node.url, node.hmac_secret_hex);

    match node.tier {
        NodeTier::Primary => {
            // Use hardcoded Vladimir Unknown verifying key
            vt_core::crypto::ed25519::verify_patch_signature(
                payload.as_bytes(),
                &node.signature,
            )
        }
        NodeTier::Community => {
            // Use the node's own community key
            let key_hex = node.community_verifying_key.as_deref()
                .ok_or(vt_core::VtError::SignatureInvalid)?;
            let key = load_verifying_key(key_hex)?;
            verify_with_key(payload.as_bytes(), &node.signature, &key)
        }
    }
}