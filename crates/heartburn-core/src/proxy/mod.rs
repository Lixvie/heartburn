//! Upstream Mozilla Fastly proxy transports (`h2`, `h3`, `h1`), `CONNECT-UDP`,
//! multi-session pooling, failover, and lifecycle controller.

pub mod controller;
pub mod failover;
pub mod pool;
pub mod status;
pub mod tunnel;
pub mod udp_h2;
pub mod upstream_h1;
pub mod upstream_h2;
pub mod upstream_h3;
pub mod watched;

use std::future::Future;
use std::pin::Pin;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use tokio::sync::mpsc;

use crate::error::ProxyError;
use crate::tls::BoxStream;

/// UDP datagram stream opened over Fastly `CONNECT-UDP` (`RFC 9298`).
pub struct UdpTunnel {
    pub tx: mpsc::Sender<Vec<u8>>,
    pub rx: mpsc::Receiver<Vec<u8>>,
    pub closed: Arc<AtomicBool>,
}

/// Boxed future helper for [`UpstreamSession`].
pub type SessionFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, ProxyError>> + Send + 'a>>;

/// Abstract upstream Fastly proxy transport (`h2`, `h3`, or `h1`).
pub trait UpstreamSession: Send + Sync + std::fmt::Debug {
    /// Opens a proxied TCP byte stream to `target_host:target_port`.
    fn open_tcp<'a>(&'a self, target_host: &'a str, target_port: u16) -> SessionFuture<'a, BoxStream>;

    /// Opens a proxied UDP datagram association to `target_host:target_port` (`CONNECT-UDP`).
    fn open_udp<'a>(&'a self, target_host: &'a str, target_port: u16) -> SessionFuture<'a, UdpTunnel>;

    /// Hot-swaps the ProxyPass bearer token used for subsequent stream opens.
    fn update_proxy_pass(&self, pass: &str);

    /// Returns whether this session has closed or failed.
    fn is_closed(&self) -> bool;

    /// Gracefully shuts down the upstream session and background tasks.
    fn close<'a>(&'a self) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>>;
}

/// Port/host remappings applied identically to Go `proxy/relay.go` (`throughMozilla`).
///
/// - `github.com:22` -> `ssh.github.com:443`
/// - `mtalk.google.com` / `alt*-mtalk.google.com` `{443, 5228, 5229, 5230}` -> `host:443`
pub fn through_mozilla(host: &str, port: u16) -> (String, u16) {
    let lower = host.trim().to_ascii_lowercase();
    if lower == "github.com" && port == 22 {
        return ("ssh.github.com".to_owned(), 443);
    }
    if is_mtalk_host(&lower) && matches!(port, 443 | 5228 | 5229 | 5230) {
        return (host.trim().to_owned(), 443);
    }
    (host.trim().to_owned(), port)
}

fn is_mtalk_host(lower: &str) -> bool {
    if lower == "mtalk.google.com" {
        return true;
    }
    if let Some(rest) = lower.strip_prefix("alt")
        && let Some((num, tail)) = rest.split_once("-mtalk.google.com")
    {
        return tail.is_empty() && !num.is_empty() && num.bytes().all(|b| b.is_ascii_digit());
    }
    false
}

/// Fastly/Mozilla allowed outbound UDP ports (`proxy/udp.go`).
pub const fn is_allowed_udp_port(port: u16) -> bool {
    matches!(port, 80 | 443 | 3478 | 8080 | 8443) || (port >= 49152 && port <= 65534)
}

/// Fastly's documented standard allowed TCP ports (`proxy/failure.go`),
/// used when classifying upstream HTTP 403/502 `portRefused` responses.
pub const fn is_standard_mozilla_tcp_port(port: u16) -> bool {
    matches!(port, 80 | 443 | 8080 | 8443)
}

/// Formats `host:port` bracketing literal IPv6 addresses.
pub fn format_authority(host: &str, port: u16) -> String {
    let clean = host.trim_matches(['[', ']']);
    if clean.contains(':') {
        format!("[{clean}]:{port}")
    } else {
        format!("{clean}:{port}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rewrites_through_mozilla_ports() {
        assert_eq!(
            through_mozilla("github.com", 22),
            ("ssh.github.com".into(), 443)
        );
        assert_eq!(
            through_mozilla("mtalk.google.com", 5228),
            ("mtalk.google.com".into(), 443)
        );
        assert_eq!(
            through_mozilla("alt4-mtalk.google.com", 5228),
            ("alt4-mtalk.google.com".into(), 443)
        );
        assert_eq!(through_mozilla("example.com", 8443), ("example.com".into(), 8443));
    }

    #[test]
    fn enforces_fastly_udp_port_allowlist() {
        assert!(is_allowed_udp_port(443));
        assert!(is_allowed_udp_port(3478));
        assert!(is_allowed_udp_port(49152));
        assert!(is_allowed_udp_port(65534));
        assert!(!is_allowed_udp_port(53));
        assert!(!is_allowed_udp_port(65535));
    }
}
