// ============================================================
// VOID-TUNNEL :: vt-transport :: tunnel :: failover.rs
//
// Multi-Tier Failover Orchestrator
//
// Tier 1: Primary Cloudflare Worker → Secondary CF account
// Tier 2: Alternative serverless provider (Vercel/Supabase/AWS)
// Tier 3: Community mirrors / bootstrap nodes
// Tier 4: DHT peer relay chain
//
// Behavior is profile-dependent:
//   GeneralPrivacy    → Fully automatic silent failover
//   AdvancedResearcher → Auto-switch + alert
//   HighRiskStrict    → Kill switch + manual confirm required
//
// Author: Vladimir Unknown
// ============================================================

use std::sync::Arc;
use std::time::Duration;

use tokio::sync::{Mutex, watch};
use tokio::time::{sleep, timeout};
use tracing::{error, info, warn};

use vt_core::config::schema::{NodeCredentials, OperationalMode, VoidTunnelConfig};

use crate::error::{TransportError, TransportResult};
use crate::kill_switch::KillSwitch;
use crate::metrics::{CloakingMetrics, ConnectionState};
use crate::tunnel::client::TunnelClient;

/// Duration of consecutive failures before failover is triggered (5 seconds)
const FAILURE_WINDOW_SECS: u64 = 5;

/// Number of consecutive health check failures before failover
const MAX_FAILURES_BEFORE_FAILOVER: u32 = 3;

/// Health check polling interval during active session
const HEALTH_CHECK_INTERVAL_MS: u64 = 2000;

/// Represents a failover event notification sent to the UI.
#[derive(Debug, Clone, serde::Serialize)]
pub struct FailoverEvent {
    pub reason: String,
    pub from_provider: String,
    pub to_provider: String,
    pub tier: u8,
    pub requires_user_action: bool,
}

/// Orchestrates the multi-tier failover decision engine.
pub struct FailoverOrchestrator {
    config: Arc<VoidTunnelConfig>,
    tunnel: Arc<TunnelClient>,
    metrics: Arc<CloakingMetrics>,
    kill_switch: Arc<KillSwitch>,

    /// Current active node index in the provider chain
    active_node_idx: Arc<Mutex<usize>>,

    /// Channel to broadcast failover events to the UI layer
    event_tx: watch::Sender<Option<FailoverEvent>>,
    pub event_rx: watch::Receiver<Option<FailoverEvent>>,
}

impl FailoverOrchestrator {
    pub fn new(
        config: Arc<VoidTunnelConfig>,
        tunnel: Arc<TunnelClient>,
        metrics: Arc<CloakingMetrics>,
        kill_switch: Arc<KillSwitch>,
    ) -> Self {
        let (event_tx, event_rx) = watch::channel(None);

        Self {
            config,
            tunnel,
            metrics,
            kill_switch,
            active_node_idx: Arc::new(Mutex::new(0)),
            event_tx,
            event_rx,
        }
    }

    /// Start the continuous health monitoring loop.
    /// Runs forever in a background Tokio task.
    pub async fn run_monitor(self: Arc<Self>) {
        info!("Failover monitor started");

        let mut consecutive_failures: u32 = 0;

        loop {
            sleep(Duration::from_millis(HEALTH_CHECK_INTERVAL_MS)).await;

            let creds = match self.get_active_credentials().await {
                Some(c) => c,
                None => {
                    warn!("No active credentials for health check");
                    continue;
                }
            };

            let healthy = self.tunnel.health_check(&creds).await;

            if healthy {
                consecutive_failures = 0;

                // Restore connected state if previously in failover amber
                let snap = self.metrics.snapshot();
                if snap.state == ConnectionState::Failover {
                    self.metrics.set_state(ConnectionState::Connected);
                }
            } else {
                consecutive_failures += 1;
                warn!(
                    "Health check failed ({}/{})",
                    consecutive_failures, MAX_FAILURES_BEFORE_FAILOVER
                );

                if consecutive_failures >= MAX_FAILURES_BEFORE_FAILOVER {
                    consecutive_failures = 0;
                    self.trigger_failover().await;
                }
            }
        }
    }

    // ── Failover Trigger ──────────────────────────────────────────────────────

    async fn trigger_failover(&self) {
        let mode = &self.config.mode;

        match mode {
            OperationalMode::GeneralPrivacy => {
                self.automatic_failover().await;
            }

            OperationalMode::AdvancedResearcher => {
                // Auto-switch but notify user
                self.automatic_failover().await;
                // Event already sent in automatic_failover
            }

            OperationalMode::HighRiskStrict => {
                // HARD LOCKDOWN — activate kill switch immediately
                warn!("HighRiskStrict: primary node failed → Kill Switch ACTIVATED");
                self.metrics.set_state(ConnectionState::KillSwitch);

                if let Err(e) = self.kill_switch.activate().await {
                    error!("Kill switch activation failed: {}", e);
                }

                // Broadcast alert requiring manual user action
                let event = FailoverEvent {
                    reason: "Primary node unreachable — manual failover required".into(),
                    from_provider: self.get_active_provider_name().await,
                    to_provider: "PENDING USER AUTHORIZATION".into(),
                    tier: 0,
                    requires_user_action: true,
                };

                let _ = self.event_tx.send(Some(event));
            }
        }
    }

    async fn automatic_failover(&self) {
        self.metrics.set_state(ConnectionState::Failover);

        // Tier 1: Try secondary Cloudflare accounts
        if let Some(next) = self.next_node().await {
            let provider_name = next.worker_url.clone();
            info!("Failover Tier 1: switching to secondary node {}", provider_name);

            let event = FailoverEvent {
                reason: "Primary node unreachable".into(),
                from_provider: self.get_active_provider_name().await,
                to_provider: provider_name.clone(),
                tier: 1,
                requires_user_action: false,
            };

            self.metrics.record_failover(&provider_name);
            let _ = self.event_tx.send(Some(event));
            return;
        }

        // Tier 2: Alternative serverless providers
        warn!("Failover Tier 2: all CF nodes exhausted, switching provider");
        let event = FailoverEvent {
            reason: "All Cloudflare nodes exhausted".into(),
            from_provider: "Cloudflare".into(),
            to_provider: "Alternative Provider".into(),
            tier: 2,
            requires_user_action: false,
        };
        let _ = self.event_tx.send(Some(event));

        // Tier 3/4: Community mirrors / DHT peer relay
        // (handled by bootstrap::discovery module)
        warn!("Failover Tier 3/4: initiating DHT peer discovery");
    }

    // ── Node Rotation ─────────────────────────────────────────────────────────

    /// Advance to the next available node in the provider chain.
    /// Returns the new credentials, or None if all nodes exhausted.
    async fn next_node(&self) -> Option<NodeCredentials> {
        let mut idx = self.active_node_idx.lock().await;

        let all_nodes: Vec<NodeCredentials> = {
            let mut nodes = Vec::new();
            if let Some(primary) = &self.config.primary_node {
                nodes.push(primary.clone());
            }
            nodes.extend(self.config.secondary_nodes.clone());
            nodes
        };

        if *idx + 1 < all_nodes.len() {
            *idx += 1;
            Some(all_nodes[*idx].clone())
        } else {
            None
        }
    }

    async fn get_active_credentials(&self) -> Option<NodeCredentials> {
        let idx = *self.active_node_idx.lock().await;

        let mut nodes: Vec<NodeCredentials> = Vec::new();
        if let Some(primary) = &self.config.primary_node {
            nodes.push(primary.clone());
        }
        nodes.extend(self.config.secondary_nodes.clone());

        nodes.get(idx).cloned()
    }

    async fn get_active_provider_name(&self) -> String {
        self.get_active_credentials()
            .await
            .map(|c| c.worker_url)
            .unwrap_or_else(|| "Unknown".into())
    }

    /// Manual failover trigger — called by UI in HighRiskStrict mode
    /// after user explicitly authorizes the infrastructure swap.
    pub async fn manual_authorize_failover(&self) -> TransportResult<()> {
        if self.config.mode != OperationalMode::HighRiskStrict {
            return Ok(());
        }

        // Deactivate kill switch
        self.kill_switch.deactivate().await
            .map_err(|e| TransportError::KillSwitchFailed {
                reason: e.to_string(),
            })?;

        // Execute failover
        self.automatic_failover().await;
        self.metrics.set_state(ConnectionState::Connected);

        Ok(())
    }
}