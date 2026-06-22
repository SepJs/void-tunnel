// ============================================================
// VOID-TUNNEL :: vt-transport :: proxy :: http_proxy.rs
//
// HTTP CONNECT Proxy Server
//
// Handles HTTP CONNECT tunneling for browsers and tools
// that prefer HTTP proxy over SOCKS5.
// Routes all CONNECT tunnels through the encrypted pipeline.
//
// Author: Vladimir Unknown
// ============================================================

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;

use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, warn};

use crate::error::{TransportError, TransportResult};
use crate::metrics::CloakingMetrics;
use crate::proxy::socks5::Socks5Target;
use crate::tunnel::client::TunnelClient;

pub struct HttpProxyServer {
    bind_addr: SocketAddr,
    tunnel: Arc<TunnelClient>,
    metrics: Arc<CloakingMetrics>,
}

impl HttpProxyServer {
    pub fn new(
        port: u16,
        tunnel: Arc<TunnelClient>,
        metrics: Arc<CloakingMetrics>,
    ) -> Self {
        Self {
            bind_addr: SocketAddr::new(
                IpAddr::V4(Ipv4Addr::LOOPBACK), port
            ),
            tunnel,
            metrics,
        }
    }

    pub async fn run(self: Arc<Self>) -> TransportResult<()> {
        let listener = TcpListener::bind(self.bind_addr)
            .await
            .map_err(|_| TransportError::ProxyBindFailed {
                port: self.bind_addr.port(),
            })?;

        loop {
            match listener.accept().await {
                Ok((stream, _peer)) => {
                    let server = Arc::clone(&self);
                    tokio::spawn(async move {
                        if let Err(e) = server.handle(stream).await {
                            warn!("HTTP proxy error: {}", e);
                        }
                    });
                }
                Err(e) => error!("HTTP proxy accept error: {}", e),
            }
        }
    }

    async fn handle(&self, mut stream: TcpStream) -> TransportResult<()> {
        let mut reader = BufReader::new(&mut stream);
        let mut request_line = String::new();

        // Read the first line: "CONNECT host:port HTTP/1.1"
        reader.read_line(&mut request_line).await
            .map_err(|e| TransportError::HttpConnectFailed {
                reason: e.to_string(),
            })?;

        let request_line = request_line.trim();
        debug!("HTTP proxy request: {}", request_line);

        // Drain remaining headers until blank line
        loop {
            let mut line = String::new();
            reader.read_line(&mut line).await
                .map_err(|e| TransportError::HttpConnectFailed {
                    reason: e.to_string(),
                })?;
            if line.trim().is_empty() {
                break;
            }
        }

        // Parse CONNECT target
        let target = parse_connect_target(request_line)?;

        // Establish tunnel
        match self.tunnel.connect_to_target(&target).await {
            Ok(tunnel_stream) => {
                // Send 200 Connection Established
                stream.write_all(
                    b"HTTP/1.1 200 Connection Established\r\n\r\n"
                ).await
                .map_err(|e| TransportError::HttpConnectFailed {
                    reason: e.to_string(),
                })?;

                // Relay bidirectionally
                relay(stream, tunnel_stream, Arc::clone(&self.metrics)).await;
            }
            Err(e) => {
                let _ = stream.write_all(
                    b"HTTP/1.1 502 Bad Gateway\r\n\r\n"
                ).await;
                return Err(TransportError::HttpConnectFailed {
                    reason: e.to_string(),
                });
            }
        }

        Ok(())
    }
}

fn parse_connect_target(request_line: &str) -> TransportResult<Socks5Target> {
    // Format: "CONNECT host:port HTTP/1.x"
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 || parts[0].to_uppercase() != "CONNECT" {
        return Err(TransportError::HttpConnectFailed {
            reason: "invalid CONNECT request line".into(),
        });
    }

    let host_port = parts[1];
    if let Some(colon_pos) = host_port.rfind(':') {
        let host = host_port[..colon_pos].to_string();
        let port: u16 = host_port[colon_pos + 1..]
            .parse()
            .map_err(|_| TransportError::HttpConnectFailed {
                reason: "invalid port in CONNECT".into(),
            })?;
        Ok(Socks5Target { host, port })
    } else {
        Err(TransportError::HttpConnectFailed {
            reason: "no port in CONNECT target".into(),
        })
    }
}

async fn relay(
    local: TcpStream,
    tunnel: TcpStream,
    metrics: Arc<CloakingMetrics>,
) {
    let (mut lr, mut lw) = tokio::io::split(local);
    let (mut tr, mut tw) = tokio::io::split(tunnel);

    let m_up = Arc::clone(&metrics);
    let m_dn = Arc::clone(&metrics);

    let up = tokio::spawn(async move {
        let mut buf = [0u8; 65536];
        while let Ok(n) = lr.read(&mut buf).await {
            if n == 0 { break; }
            m_up.record_outbound(n, n, 0);
            if tw.write_all(&buf[..n]).await.is_err() { break; }
        }
    });

    let dn = tokio::spawn(async move {
        let mut buf = [0u8; 65536];
        while let Ok(n) = tr.read(&mut buf).await {
            if n == 0 { break; }
            m_dn.record_inbound(n);
            if lw.write_all(&buf[..n]).await.is_err() { break; }
        }
    });

    let _ = tokio::join!(up, dn);
}

use tokio::io::AsyncReadExt;