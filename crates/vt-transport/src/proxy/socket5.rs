// ============================================================
// VOID-TUNNEL :: vt-transport :: proxy :: socks5.rs
//
// SOCKS5 Proxy Server — RFC 1928 Compliant
//
// Listens on loopback (127.0.0.1:1080 by default).
// Intercepts all TCP connection requests from browsers,
// applications, and system-wide proxy hooks.
// Routes all traffic through the encrypted Void-Tunnel pipeline.
//
// Supports:
//   - SOCKS5 CONNECT (TCP proxy)
//   - No-auth and username/password auth methods
//   - IPv4, IPv6, and domain name address types
//   - Tokio async I/O with zero blocking
//
// Author: Vladimir Unknown
// ============================================================

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

use crate::error::{TransportError, TransportResult};
use crate::metrics::{CloakingMetrics, ConnectionState};
use crate::tunnel::client::TunnelClient;

// ── SOCKS5 Protocol Constants ─────────────────────────────────────────────────

const SOCKS5_VERSION: u8     = 0x05;
const SOCKS5_AUTH_NONE: u8   = 0x00;
const SOCKS5_AUTH_PASSWD: u8 = 0x02;
const SOCKS5_AUTH_NO_ACCEPTABLE: u8 = 0xFF;
const SOCKS5_CMD_CONNECT: u8 = 0x01;
const SOCKS5_ATYP_IPV4: u8   = 0x01;
const SOCKS5_ATYP_DOMAIN: u8 = 0x03;
const SOCKS5_ATYP_IPV6: u8   = 0x04;
const SOCKS5_REP_SUCCESS: u8 = 0x00;
const SOCKS5_REP_FAILURE: u8 = 0x01;
const SOCKS5_REP_CMD_UNSUPPORTED: u8 = 0x07;

/// Represents a parsed SOCKS5 connection request target.
#[derive(Debug, Clone)]
pub struct Socks5Target {
    pub host: String,
    pub port: u16,
}

/// SOCKS5 proxy server handle.
pub struct Socks5Server {
    bind_addr: SocketAddr,
    tunnel: Arc<TunnelClient>,
    metrics: Arc<CloakingMetrics>,
    /// Optional username/password for SOCKS5 auth (None = no auth)
    credentials: Option<(String, String)>,
}

impl Socks5Server {
    pub fn new(
        port: u16,
        tunnel: Arc<TunnelClient>,
        metrics: Arc<CloakingMetrics>,
        credentials: Option<(String, String)>,
    ) -> Self {
        Self {
            bind_addr: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOOPBACK), port
            ),
            tunnel,
            metrics,
            credentials,
        }
    }

    /// Start the SOCKS5 listener loop.
    /// Spawns a Tokio task per incoming connection.
    pub async fn run(self: Arc<Self>) -> TransportResult<()> {
        let listener = TcpListener::bind(self.bind_addr)
            .await
            .map_err(|_| TransportError::ProxyBindFailed {
                port: self.bind_addr.port(),
            })?;

        info!(
            "SOCKS5 proxy listening on {}",
            self.bind_addr
        );

        self.metrics.set_state(ConnectionState::Connected);

        loop {
            match listener.accept().await {
                Ok((stream, peer)) => {
                    debug!("SOCKS5: new connection from {}", peer);
                    let server = Arc::clone(&self);

                    tokio::spawn(async move {
                        if let Err(e) = server.handle_connection(stream).await {
                            warn!("SOCKS5 connection error: {}", e);
                        }
                    });
                }
                Err(e) => {
                    error!("SOCKS5 accept error: {}", e);
                }
            }
        }
    }

    // ── Connection Handler ────────────────────────────────────────────────────

    async fn handle_connection(&self, mut stream: TcpStream) -> TransportResult<()> {
        // Phase 1: Negotiate authentication method
        self.negotiate_auth(&mut stream).await?;

        // Phase 2: Parse the CONNECT request
        let target = self.parse_request(&mut stream).await?;

        debug!("SOCKS5 CONNECT → {}:{}", target.host, target.port);

        // Phase 3: Establish tunnel to target via Void-Tunnel pipeline
        match self.tunnel.connect_to_target(&target).await {
            Ok(tunnel_stream) => {
                // Send SOCKS5 success reply
                self.send_reply(&mut stream, SOCKS5_REP_SUCCESS).await?;

                // Relay data bidirectionally between local client and tunnel
                self.relay_bidirectional(stream, tunnel_stream).await?;
            }
            Err(e) => {
                warn!("Tunnel connect failed for {}:{} — {}", target.host, target.port, e);
                self.send_reply(&mut stream, SOCKS5_REP_FAILURE).await?;
            }
        }

        Ok(())
    }

    // ── Auth Negotiation ──────────────────────────────────────────────────────

    async fn negotiate_auth(&self, stream: &mut TcpStream) -> TransportResult<()> {
        // Read: VER(1) + NMETHODS(1) + METHODS(N)
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).await
            .map_err(|_| TransportError::Socks5HandshakeFailed {
                reason: "failed to read version/nmethods".into(),
            })?;

        if header[0] != SOCKS5_VERSION {
            return Err(TransportError::Socks5HandshakeFailed {
                reason: format!("invalid SOCKS version: {}", header[0]),
            });
        }

        let n_methods = header[1] as usize;
        let mut methods = vec![0u8; n_methods];
        stream.read_exact(&mut methods).await
            .map_err(|_| TransportError::Socks5HandshakeFailed {
                reason: "failed to read auth methods".into(),
            })?;

        // Select auth method
        let chosen = if self.credentials.is_some() {
            if methods.contains(&SOCKS5_AUTH_PASSWD) {
                SOCKS5_AUTH_PASSWD
            } else {
                SOCKS5_AUTH_NO_ACCEPTABLE
            }
        } else {
            if methods.contains(&SOCKS5_AUTH_NONE) {
                SOCKS5_AUTH_NONE
            } else {
                SOCKS5_AUTH_NO_ACCEPTABLE
            }
        };

        // Send method selection: VER(1) + METHOD(1)
        stream.write_all(&[SOCKS5_VERSION, chosen]).await
            .map_err(|_| TransportError::Socks5HandshakeFailed {
                reason: "failed to send method selection".into(),
            })?;

        if chosen == SOCKS5_AUTH_NO_ACCEPTABLE {
            return Err(TransportError::Socks5HandshakeFailed {
                reason: "no acceptable auth method".into(),
            });
        }

        // If password auth, verify credentials
        if chosen == SOCKS5_AUTH_PASSWD {
            self.verify_password_auth(stream).await?;
        }

        Ok(())
    }

    async fn verify_password_auth(&self, stream: &mut TcpStream) -> TransportResult<()> {
        // Sub-negotiation: VER(1) + ULEN(1) + UNAME + PLEN(1) + PASSWD
        let mut ver = [0u8; 1];
        stream.read_exact(&mut ver).await
            .map_err(|_| TransportError::Socks5HandshakeFailed {
                reason: "auth sub-negotiation read failed".into(),
            })?;

        let mut ulen_buf = [0u8; 1];
        stream.read_exact(&mut ulen_buf).await
            .map_err(|_| TransportError::Socks5HandshakeFailed {
                reason: "username length read failed".into(),
            })?;
        let ulen = ulen_buf[0] as usize;

        let mut username = vec![0u8; ulen];
        stream.read_exact(&mut username).await
            .map_err(|_| TransportError::Socks5HandshakeFailed {
                reason: "username read failed".into(),
            })?;

        let mut plen_buf = [0u8; 1];
        stream.read_exact(&mut plen_buf).await
            .map_err(|_| TransportError::Socks5HandshakeFailed {
                reason: "password length read failed".into(),
            })?;
        let plen = plen_buf[0] as usize;

        let mut password = vec![0u8; plen];
        stream.read_exact(&mut password).await
            .map_err(|_| TransportError::Socks5HandshakeFailed {
                reason: "password read failed".into(),
            })?;

        let username_str = String::from_utf8_lossy(&username);
        let password_str = String::from_utf8_lossy(&password);

        let valid = if let Some((ref u, ref p)) = self.credentials {
            u.as_str() == username_str && p.as_str() == password_str
        } else {
            false
        };

        // Always send reply — 0x00 success, 0x01 failure
        let status = if valid { 0x00u8 } else { 0x01u8 };
        stream.write_all(&[0x01, status]).await
            .map_err(|_| TransportError::Socks5HandshakeFailed {
                reason: "failed to send auth reply".into(),
            })?;

        if !valid {
            return Err(TransportError::Socks5HandshakeFailed {
                reason: "authentication failed".into(),
            });
        }

        Ok(())
    }

    // ── Request Parsing ───────────────────────────────────────────────────────

    async fn parse_request(&self, stream: &mut TcpStream) -> TransportResult<Socks5Target> {
        // VER(1) + CMD(1) + RSV(1) + ATYP(1)
        let mut header = [0u8; 4];
        stream.read_exact(&mut header).await
            .map_err(|_| TransportError::Socks5HandshakeFailed {
                reason: "request header read failed".into(),
            })?;

        if header[0] != SOCKS5_VERSION {
            return Err(TransportError::Socks5HandshakeFailed {
                reason: "invalid version in request".into(),
            });
        }

        if header[1] != SOCKS5_CMD_CONNECT {
            // Send CMD_UNSUPPORTED and close
            let _ = self.send_reply(stream, SOCKS5_REP_CMD_UNSUPPORTED).await;
            return Err(TransportError::Socks5CommandUnsupported { cmd: header[1] });
        }

        // Parse address based on ATYP
        let (host, port) = match header[3] {
            SOCKS5_ATYP_IPV4 => {
                let mut addr = [0u8; 4];
                stream.read_exact(&mut addr).await
                    .map_err(|_| TransportError::Socks5HandshakeFailed {
                        reason: "IPv4 addr read failed".into(),
                    })?;
                let ip = Ipv4Addr::from(addr);
                let port = read_u16(stream).await?;
                (ip.to_string(), port)
            }

            SOCKS5_ATYP_IPV6 => {
                let mut addr = [0u8; 16];
                stream.read_exact(&mut addr).await
                    .map_err(|_| TransportError::Socks5HandshakeFailed {
                        reason: "IPv6 addr read failed".into(),
                    })?;
                let ip = Ipv6Addr::from(addr);
                let port = read_u16(stream).await?;
                (format!("[{}]", ip), port)
            }

            SOCKS5_ATYP_DOMAIN => {
                let mut len_buf = [0u8; 1];
                stream.read_exact(&mut len_buf).await
                    .map_err(|_| TransportError::Socks5HandshakeFailed {
                        reason: "domain length read failed".into(),
                    })?;
                let len = len_buf[0] as usize;

                let mut domain = vec![0u8; len];
                stream.read_exact(&mut domain).await
                    .map_err(|_| TransportError::Socks5HandshakeFailed {
                        reason: "domain read failed".into(),
                    })?;

                let port = read_u16(stream).await?;
                let host = String::from_utf8_lossy(&domain).to_string();
                (host, port)
            }

            other => {
                return Err(TransportError::Socks5AuthUnsupported { method: other });
            }
        };

        Ok(Socks5Target { host, port })
    }

    // ── Reply Builder ─────────────────────────────────────────────────────────

    async fn send_reply(
        &self,
        stream: &mut TcpStream,
        rep: u8,
    ) -> TransportResult<()> {
        // VER(1) REP(1) RSV(1) ATYP(1) BND.ADDR(4) BND.PORT(2)
        // We always return 0.0.0.0:0 as bound address
        let reply = [
            SOCKS5_VERSION, rep, 0x00,
            SOCKS5_ATYP_IPV4,
            0x00, 0x00, 0x00, 0x00, // 0.0.0.0
            0x00, 0x00,              // port 0
        ];
        stream.write_all(&reply).await
            .map_err(|_| TransportError::Socks5HandshakeFailed {
                reason: "failed to send reply".into(),
            })?;
        Ok(())
    }

    // ── Bidirectional Relay ───────────────────────────────────────────────────

    /// Relay data between the local SOCKS5 client stream and the
    /// encrypted Void-Tunnel stream. Uses Tokio's copy_bidirectional
    /// for zero-copy async data transfer.
    async fn relay_bidirectional(
        &self,
        local: TcpStream,
        tunnel: TcpStream,
    ) -> TransportResult<()> {
        let (mut local_r, mut local_w) = tokio::io::split(local);
        let (mut tunnel_r, mut tunnel_w) = tokio::io::split(tunnel);

        let metrics_up = Arc::clone(&self.metrics);
        let metrics_down = Arc::clone(&self.metrics);

        // Upload: local → tunnel (with metric tracking)
        let upload = tokio::spawn(async move {
            let mut buf = [0u8; 65536];
            loop {
                match local_r.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        metrics_up.record_outbound(n, n, 0);
                        if tunnel_w.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        // Download: tunnel → local (with metric tracking)
        let download = tokio::spawn(async move {
            let mut buf = [0u8; 65536];
            loop {
                match tunnel_r.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => {
                        metrics_down.record_inbound(n);
                        if local_w.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                    }
                    Err(_) => break,
                }
            }
        });

        let _ = tokio::join!(upload, download);
        Ok(())
    }
}

// ── Helpers ───────────────────────────────────────────────────────────────────

async fn read_u16(stream: &mut TcpStream) -> TransportResult<u16> {
    let mut buf = [0u8; 2];
    stream.read_exact(&mut buf).await
        .map_err(|_| TransportError::Socks5HandshakeFailed {
            reason: "port read failed".into(),
        })?;
    Ok(u16::from_be_bytes(buf))
}