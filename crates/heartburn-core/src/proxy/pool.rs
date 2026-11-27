//! Multi-connection upstream session pool with client-IP hashing (`proxy/pool.go`).

use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use crate::config::TransportKind;
use crate::error::ProxyError;
use crate::proxy::{UdpTunnel, UpstreamSession};
use crate::tls::BoxStream;

/// Distributes client tunnels across 1..N upstream [`UpstreamSession`] instances,
/// pinning flows from the same client IP to the same upstream session when healthy
/// (and maintaining an optional auxiliary H2 session for `CONNECT-UDP` when the main
/// transport is HTTP/3 or HTTP/1.1).
#[derive(Debug)]
pub struct SessionPool {
    transport: TransportKind,
    sessions: Vec<Arc<dyn UpstreamSession>>,
    udp_h2_fallback: Option<Arc<dyn UpstreamSession>>,
    rr_cursor: AtomicUsize,
}

impl SessionPool {
    pub fn new(
        transport: TransportKind,
        sessions: Vec<Arc<dyn UpstreamSession>>,
        udp_h2_fallback: Option<Arc<dyn UpstreamSession>>,
    ) -> Self {
        Self {
            transport,
            sessions,
            udp_h2_fallback,
            rr_cursor: AtomicUsize::new(0),
        }
    }

    /// Returns the actual upstream transport active for primary sessions in this pool.
    pub const fn transport(&self) -> TransportKind {
        self.transport
    }

    pub fn len(&self) -> usize {
        self.sessions.len()
    }

    pub fn is_empty(&self) -> bool {
        self.sessions.is_empty()
    }

    /// Returns `true` if every primary upstream session is closed.
    pub fn all_closed(&self) -> bool {
        self.sessions.iter().all(|s| s.is_closed())
    }

    /// Selects a live upstream session using consistent client-IP hashing when available.
    pub fn pick_session(&self, client_ip: Option<IpAddr>) -> Result<Arc<dyn UpstreamSession>, ProxyError> {
        if self.sessions.is_empty() {
            return Err(ProxyError::Transport("no upstream proxy sessions active".into()));
        }

        let start = if let Some(ip) = client_ip {
            let mut h = DefaultHasher::new();
            ip.hash(&mut h);
            (h.finish() as usize) % self.sessions.len()
        } else {
            self.rr_cursor.fetch_add(1, Ordering::Relaxed) % self.sessions.len()
        };

        for offset in 0..self.sessions.len() {
            let idx = (start + offset) % self.sessions.len();
            let sess = &self.sessions[idx];
            if !sess.is_closed() {
                return Ok(Arc::clone(sess));
            }
        }
        Err(ProxyError::Transport("all upstream proxy sessions are closed".into()))
    }

    /// Opens a proxied TCP tunnel via the pool.
    pub async fn open_tcp(
        &self,
        client_ip: Option<IpAddr>,
        target_host: &str,
        target_port: u16,
    ) -> Result<BoxStream, ProxyError> {
        let sess = self.pick_session(client_ip)?;
        sess.open_tcp(target_host, target_port).await
    }

    /// Opens a proxied UDP tunnel via primary H2 session or auxiliary H2 UDP session.
    pub async fn open_udp(
        &self,
        client_ip: Option<IpAddr>,
        target_host: &str,
        target_port: u16,
    ) -> Result<UdpTunnel, ProxyError> {
        if let Some(ref aux) = self.udp_h2_fallback
            && !aux.is_closed()
        {
            return aux.open_udp(target_host, target_port).await;
        }
        let sess = self.pick_session(client_ip)?;
        sess.open_udp(target_host, target_port).await
    }

    /// Propagates a renewed ProxyPass JWT to every live session in the pool.
    pub fn update_proxy_pass(&self, pass: &str) {
        for sess in &self.sessions {
            sess.update_proxy_pass(pass);
        }
        if let Some(ref aux) = self.udp_h2_fallback {
            aux.update_proxy_pass(pass);
        }
    }

    /// Gracefully closes all pooled sessions.
    pub async fn close_all(&self) {
        for sess in &self.sessions {
            sess.close().await;
        }
        if let Some(ref aux) = self.udp_h2_fallback {
            aux.close().await;
        }
    }
}
