//! HTTP/2 over TLS upstream session (`proxy/upstream_h2.go`) with `1 MiB` flow-control
//! window, adaptive 5s PING keepalive (4s timeout, 1s retry, 2 misses), and `CONNECT-UDP`.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bytes::Bytes;
use h2::Ping;
use h2::client::SendRequest;
use http::{HeaderValue, Method, Request};
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::config::{CONNECT_TIMEOUT, IpVersionMode};
use crate::dns::BootstrapResolver;
use crate::error::ProxyError;
use crate::hellosplit::{HelloSplitMode, SplitStream};
use crate::proxy::tunnel::H2TunnelStream;
use crate::proxy::udp_h2::open_h2_connect_udp;
use crate::proxy::watched::{ActivityTracker, WatchedStream};
use crate::proxy::{SessionFuture, UdpTunnel, UpstreamSession, format_authority, through_mozilla};
use crate::tls::{BoxStream, TlsConfig, TlsConnector, TlsFingerprint};

const H2_STREAM_WINDOW: u32 = 1024 * 1024;
const PING_INTERVAL: Duration = Duration::from_secs(5);
const PING_TIMEOUT: Duration = Duration::from_secs(4);
const PING_RETRY_DELAY: Duration = Duration::from_secs(1);
const MAX_PING_MISSES: usize = 2;

/// Upstream HTTP/2 CONNECT + `CONNECT-UDP` session to a Mozilla Fastly edge server.
pub struct H2Session {
    server_host: String,
    server_port: u16,
    user_agent: String,
    proxy_pass: RwLock<String>,
    sender: SendRequest<Bytes>,
    tracker: Arc<ActivityTracker>,
    closed: Arc<AtomicBool>,
    cancel: CancellationToken,
    tasks: Mutex<Vec<JoinHandle<()>>>,
}

impl std::fmt::Debug for H2Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H2Session")
            .field("server_host", &self.server_host)
            .field("server_port", &self.server_port)
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .finish()
    }
}

impl H2Session {
    /// Dials the Fastly proxy edge, performs TLS + H2 handshake, and starts adaptive keepalive.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        server_host: String,
        server_port: u16,
        user_agent: String,
        proxy_pass: String,
        split_mode: HelloSplitMode,
        ip_version: IpVersionMode,
        resolver: Arc<BootstrapResolver>,
        tls: Arc<dyn TlsConnector>,
    ) -> Result<Arc<Self>, ProxyError> {
        let (tcp, _) = resolver
            .dial_tcp(&server_host, server_port, ip_version, CONNECT_TIMEOUT)
            .await
            .map_err(|e| ProxyError::Transport(e.to_string()))?;

        let boxed: BoxStream = if split_mode.is_active() {
            Box::new(SplitStream::new(tcp, split_mode))
        } else {
            Box::new(tcp)
        };

        let tls_cfg = TlsConfig {
            server_name: server_host.clone(),
            alpn: vec![b"h2".to_vec()],
            ech_config_list: None,
            tls12_only: false,
            fingerprint: TlsFingerprint::Firefox158,
        };
        let tls_stream = tokio::time::timeout(CONNECT_TIMEOUT, tls.connect(boxed, &tls_cfg))
            .await
            .map_err(|_| ProxyError::Transport("H2 TLS handshake timed out".into()))?
            .map_err(|e| ProxyError::Transport(e.to_string()))?;

        let tracker = Arc::new(ActivityTracker::new());
        let watched = WatchedStream::new(tls_stream, Arc::clone(&tracker));

        let mut builder = h2::client::Builder::new();
        builder
            .initial_window_size(H2_STREAM_WINDOW)
            .max_frame_size(32 * 1024)
            .enable_push(false);

        let (sender, mut conn) = tokio::time::timeout(CONNECT_TIMEOUT, builder.handshake(watched))
            .await
            .map_err(|_| ProxyError::Transport("H2 preface handshake timed out".into()))?
            .map_err(|e| ProxyError::Transport(format!("H2 handshake failed: {e}")))?;

        let ping_pong = conn.ping_pong();
        let closed = Arc::new(AtomicBool::new(false));
        let cancel = CancellationToken::new();

        let closed_drv = Arc::clone(&closed);
        let cancel_drv = cancel.clone();
        let drv_handle = tokio::spawn(async move {
            tokio::select! {
                res = &mut conn => {
                    if let Err(err) = res {
                        tracing::debug!(error = %err, "H2 upstream connection closed");
                    }
                }
                _ = cancel_drv.cancelled() => {}
            }
            closed_drv.store(true, Ordering::Relaxed);
        });

        let mut handles = vec![drv_handle];

        if let Some(mut pp) = ping_pong {
            let closed_ka = Arc::clone(&closed);
            let cancel_ka = cancel.clone();
            let tracker_ka = Arc::clone(&tracker);
            let ka_handle = tokio::spawn(async move {
                let mut misses = 0usize;
                loop {
                    tokio::select! {
                        _ = cancel_ka.cancelled() => break,
                        _ = tokio::time::sleep(PING_INTERVAL) => {}
                    }
                    if closed_ka.load(Ordering::Relaxed) {
                        break;
                    }
                    if tracker_ka.should_suppress_ping() {
                        misses = 0;
                        continue;
                    }
                    match tokio::time::timeout(PING_TIMEOUT, pp.ping(Ping::opaque())).await {
                        Ok(Ok(_pong)) => {
                            misses = 0;
                        }
                        _ => {
                            misses += 1;
                            if misses >= MAX_PING_MISSES {
                                tracing::warn!("H2 keepalive missed {misses} pings; closing session");
                                closed_ka.store(true, Ordering::Relaxed);
                                cancel_ka.cancel();
                                break;
                            }
                            tokio::select! {
                                _ = cancel_ka.cancelled() => break,
                                _ = tokio::time::sleep(PING_RETRY_DELAY) => {}
                            }
                        }
                    }
                }
            });
            handles.push(ka_handle);
        }

        Ok(Arc::new(Self {
            server_host,
            server_port,
            user_agent,
            proxy_pass: RwLock::new(proxy_pass),
            sender,
            tracker,
            closed,
            cancel,
            tasks: Mutex::new(handles),
        }))
    }

    /// Exposes shared byte/read/write activity tracker for controller telemetry.
    pub fn activity(&self) -> &Arc<ActivityTracker> {
        &self.tracker
    }

    /// Clones the underlying `SendRequest` (e.g., to check extended CONNECT capability).
    pub fn is_extended_connect_enabled(&self) -> bool {
        self.sender.is_extended_connect_protocol_enabled()
    }
}

impl UpstreamSession for H2Session {
    fn open_tcp<'a>(&'a self, target_host: &'a str, target_port: u16) -> SessionFuture<'a, BoxStream> {
        Box::pin(async move {
            if self.is_closed() {
                return Err(ProxyError::Transport("H2 session closed".into()));
            }
            let (eff_host, eff_port) = through_mozilla(target_host, target_port);
            let authority = format_authority(&eff_host, eff_port);
            let pass = self
                .proxy_pass
                .read()
                .map(|g| g.clone())
                .unwrap_or_default();

            let mut ready = self
                .sender
                .clone()
                .ready()
                .await
                .map_err(|e| ProxyError::Transport(format!("H2 session not ready: {e}")))?;

            let req = Request::builder()
                .method(Method::CONNECT)
                .uri(&authority)
                .header(
                    http::header::PROXY_AUTHORIZATION,
                    HeaderValue::from_str(&format!("Bearer {pass}"))
                        .map_err(|_| ProxyError::Protocol("invalid ProxyPass header".into()))?,
                )
                .header(
                    http::header::USER_AGENT,
                    HeaderValue::from_str(&self.user_agent)
                        .map_err(|_| ProxyError::Protocol("invalid User-Agent header".into()))?,
                )
                .body(())
                .map_err(|e| ProxyError::Protocol(format!("build H2 CONNECT request: {e}")))?;

            let (resp_fut, h2_send) = ready
                .send_request(req, false)
                .map_err(|e| ProxyError::Transport(format!("H2 send CONNECT failed: {e}")))?;

            let resp = tokio::time::timeout(CONNECT_TIMEOUT, resp_fut)
                .await
                .map_err(|_| ProxyError::Transport("H2 CONNECT response timed out".into()))?
                .map_err(|e| ProxyError::Transport(format!("H2 CONNECT error: {e}")))?;

            let status = resp.status();
            if !status.is_success() {
                if matches!(status.as_u16(), 401 | 402 | 407) {
                    return Err(ProxyError::AuthFailed);
                }
                return Err(ProxyError::UpstreamStatus {
                    status: status.as_u16(),
                    message: format!("H2 CONNECT {authority} rejected with {status}"),
                });
            }

            let h2_recv = resp.into_body();
            let stream = H2TunnelStream::new(h2_send, h2_recv, Some(Arc::clone(&self.tracker)));
            Ok(Box::new(stream) as BoxStream)
        })
    }

    fn open_udp<'a>(&'a self, target_host: &'a str, target_port: u16) -> SessionFuture<'a, UdpTunnel> {
        Box::pin(async move {
            if self.is_closed() {
                return Err(ProxyError::Transport("H2 session closed".into()));
            }
            let pass = self
                .proxy_pass
                .read()
                .map(|g| g.clone())
                .unwrap_or_default();
            let proxy_auth = format_authority(&self.server_host, self.server_port);
            open_h2_connect_udp(
                self.sender.clone(),
                &proxy_auth,
                &self.user_agent,
                &pass,
                target_host,
                target_port,
            )
            .await
        })
    }

    fn update_proxy_pass(&self, pass: &str) {
        if let Ok(mut g) = self.proxy_pass.write() {
            *g = pass.to_owned();
        }
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Relaxed)
    }

    fn close<'a>(&'a self) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send + 'a>> {
        Box::pin(async move {
            self.closed.store(true, Ordering::Relaxed);
            self.cancel.cancel();
            let mut handles = self.tasks.lock().await;
            for h in handles.drain(..) {
                h.abort();
            }
        })
    }
}
