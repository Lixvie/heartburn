//! Upstream server failover tracker (`proxy/failover.go`) & error classification (`proxy/failure.go`).

use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use crate::error::ProxyError;
use crate::proxy::is_standard_mozilla_tcp_port;
use crate::serverlist::{ProxyCandidate, build_standin_candidates};

const CONSECUTIVE_STRIKE_LIMIT: usize = 3;
const WINDOW_STRIKE_LIMIT: usize = 4;
const STRIKE_WINDOW: Duration = Duration::from_secs(5 * 60);
const SERVER_AVOID_DURATION: Duration = Duration::from_secs(15 * 60);

/// Distinguishes per-destination rejections (`portRefused` on non-80/443/8080/8443)
/// from session/edge-level upstream failures that merit failover.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FailureKind {
    DestinationPortRefused,
    AuthExpired,
    RateLimited,
    UpstreamSessionBroken,
    ClientDisconnected,
}

/// Classifies an upstream tunnel failure relative to the requested destination port.
pub fn classify_upstream_error(err: &ProxyError, target_port: u16) -> FailureKind {
    match err {
        ProxyError::AuthFailed => FailureKind::AuthExpired,
        ProxyError::PortRejected(_) => FailureKind::DestinationPortRefused,
        ProxyError::UpstreamStatus { status, .. } => match *status {
            401 | 402 | 407 => FailureKind::AuthExpired,
            429 => FailureKind::RateLimited,
            403 | 502 if !is_standard_mozilla_tcp_port(target_port) => {
                FailureKind::DestinationPortRefused
            }
            _ => FailureKind::UpstreamSessionBroken,
        },
        ProxyError::Transport(_) => FailureKind::UpstreamSessionBroken,
        ProxyError::Io(io_err) => match io_err.kind() {
            std::io::ErrorKind::BrokenPipe
            | std::io::ErrorKind::ConnectionReset
            | std::io::ErrorKind::ConnectionAborted
            | std::io::ErrorKind::TimedOut
            | std::io::ErrorKind::UnexpectedEof => FailureKind::UpstreamSessionBroken,
            _ => FailureKind::ClientDisconnected,
        },
        _ => FailureKind::UpstreamSessionBroken,
    }
}

#[derive(Debug, Default)]
struct ServerHealth {
    consecutive_strikes: usize,
    recent_failures: VecDeque<Instant>,
    avoid_until: Option<Instant>,
}

/// Tracks per-edge failure strikes (3 consecutive or 4 in 5m -> 15m avoidance)
/// and selects standby proxy locations.
#[derive(Debug, Default)]
pub struct ServerFailover {
    servers: Mutex<HashMap<String, ServerHealth>>,
}

impl ServerFailover {
    pub fn new() -> Self {
        Self::default()
    }

    /// Clears consecutive strike count when a stream or session succeeds on `server_addr`.
    pub fn record_success(&self, server_addr: &str) {
        if let Ok(mut map) = self.servers.lock()
            && let Some(h) = map.get_mut(server_addr)
        {
            h.consecutive_strikes = 0;
            h.avoid_until = None;
        }
    }

    /// Records a session failure on `server_addr`. Returns `true` if the server has crossed
    /// the avoidance threshold (`3 consecutive` or `4 in 5m`) and should be avoided for 15m.
    pub fn record_failure(&self, server_addr: &str) -> bool {
        let now = Instant::now();
        let Ok(mut map) = self.servers.lock() else {
            return false;
        };
        let entry = map.entry(server_addr.to_owned()).or_default();
        entry.consecutive_strikes += 1;
        entry.recent_failures.push_back(now);
        while entry
            .recent_failures
            .front()
            .is_some_and(|&t| now.saturating_duration_since(t) > STRIKE_WINDOW)
        {
            entry.recent_failures.pop_front();
        }

        if entry.consecutive_strikes >= CONSECUTIVE_STRIKE_LIMIT
            || entry.recent_failures.len() >= WINDOW_STRIKE_LIMIT
        {
            entry.avoid_until = Some(now + SERVER_AVOID_DURATION);
            return true;
        }
        false
    }

    /// Returns `true` when `server_addr` is currently inside a 15-minute cooldown window.
    pub fn is_avoided(&self, server_addr: &str) -> bool {
        let now = Instant::now();
        self.servers
            .lock()
            .ok()
            .and_then(|map| map.get(server_addr).and_then(|h| h.avoid_until))
            .map(|until| now < until)
            .unwrap_or(false)
    }

    /// Returns the set of all currently avoided `host:port` addresses.
    pub fn avoided_set(&self) -> HashSet<String> {
        let now = Instant::now();
        let Ok(mut map) = self.servers.lock() else {
            return HashSet::new();
        };
        let mut out = HashSet::new();
        for (addr, h) in map.iter_mut() {
            if let Some(until) = h.avoid_until {
                if now < until {
                    out.insert(addr.clone());
                } else {
                    h.avoid_until = None;
                }
            }
        }
        out
    }

    /// Picks standby replacement candidates excluding currently avoided edges.
    pub fn standin_candidates(
        &self,
        all: &[ProxyCandidate],
        current_country: &str,
    ) -> Vec<ProxyCandidate> {
        let avoid = self.avoided_set();
        build_standin_candidates(all, current_country, &avoid)
    }

    /// Clears all failure and avoidance state (e.g., on explicit user reconnect or network swap).
    pub fn clear(&self) {
        if let Ok(mut map) = self.servers.lock() {
            map.clear();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn triggers_avoidance_after_three_consecutive_strikes() {
        let f = ServerFailover::new();
        assert!(!f.record_failure("de1.example:443"));
        assert!(!f.record_failure("de1.example:443"));
        assert!(f.record_failure("de1.example:443"));
        assert!(f.is_avoided("de1.example:443"));

        f.record_success("de1.example:443");
        assert!(!f.is_avoided("de1.example:443"));
    }

    #[test]
    fn distinguishes_port_refused_from_session_error() {
        let err_nonstd = ProxyError::UpstreamStatus {
            status: 403,
            message: "forbidden".into(),
        };
        assert_eq!(
            classify_upstream_error(&err_nonstd, 25),
            FailureKind::DestinationPortRefused
        );
        assert_eq!(
            classify_upstream_error(&err_nonstd, 443),
            FailureKind::UpstreamSessionBroken
        );
    }
}
