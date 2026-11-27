//! HTTP/1.1 TLS `CONNECT` upstream session with a single pre-warmed spare connection
//! (`proxy/upstream_h1.go`).

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;

use crate::config::{CONNECT_TIMEOUT, IpVersionMode};
use crate::dns::BootstrapResolver;
use crate::error::ProxyError;
use crate::hellosplit::{HelloSplitMode, SplitStream};
use crate::proxy::tunnel::PrefixedStream;
use crate::proxy::{SessionFuture, UpstreamSession, format_authority, through_mozilla};
use crate::tls::{BoxStream, BoxedTlsStream, TlsConfig, TlsConnector, TlsFingerprint};

const SPARE_MAX_AGE: Duration = Duration::from_secs(20);

#[derive(Debug)]
struct SpareConn {
    stream: BoxedTlsStream,
    created_at: Instant,
}

/// Upstream HTTP/1.1 CONNECT-over-TLS transport (`proxy.transport = "h1"`).
pub struct H1Session {
    server_host: String,
    server_port: u16,
    user_agent: String,
    proxy_pass: RwLock<String>,
    split_mode: HelloSplitMode,
    ip_version: IpVersionMode,
    resolver: Arc<BootstrapResolver>,
    tls: Arc<dyn TlsConnector>,
    spare: Mutex<Option<SpareConn>>,
    closed: AtomicBool,
}

impl std::fmt::Debug for H1Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H1Session")
            .field("server_host", &self.server_host)
            .field("server_port", &self.server_port)
            .finish()
    }
}

impl H1Session {
    /// Connects and validates credentials via a warmup TLS connection stored as spare.
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
        let sess = Arc::new(Self {
            server_host,
            server_port,
            user_agent,
            proxy_pass: RwLock::new(proxy_pass),
            split_mode,
            ip_version,
            resolver,
            tls,
            spare: Mutex::new(None),
            closed: AtomicBool::new(false),
        });
        let warm = sess.dial_tls().await?;
        *sess.spare.lock().await = Some(SpareConn {
            stream: warm,
            created_at: Instant::now(),
        });
        Ok(sess)
    }

    async fn dial_tls(&self) -> Result<BoxedTlsStream, ProxyError> {
        let (tcp, _) = self
            .resolver
            .dial_tcp(&self.server_host, self.server_port, self.ip_version, CONNECT_TIMEOUT)
            .await
            .map_err(|e| ProxyError::Transport(e.to_string()))?;

        let boxed: BoxStream = if self.split_mode.is_active() {
            Box::new(SplitStream::new(tcp, self.split_mode))
        } else {
            Box::new(tcp)
        };

        let tls_cfg = TlsConfig {
            server_name: self.server_host.clone(),
            alpn: vec![b"http/1.1".to_vec()],
            ech_config_list: None,
            tls12_only: false,
            fingerprint: TlsFingerprint::Firefox158,
        };
        tokio::time::timeout(CONNECT_TIMEOUT, self.tls.connect(boxed, &tls_cfg))
            .await
            .map_err(|_| ProxyError::Transport("H1 TLS handshake timed out".into()))?
            .map_err(|e| ProxyError::Transport(e.to_string()))
    }

    async fn take_or_dial(&self) -> Result<BoxedTlsStream, ProxyError> {
        if let Some(spare) = self.spare.lock().await.take()
            && spare.created_at.elapsed() <= SPARE_MAX_AGE
        {
            return Ok(spare.stream);
        }
        self.dial_tls().await
    }

    fn spawn_warm_spare(self: &Arc<Self>) {
        if self.closed.load(Ordering::Relaxed) {
            return;
        }
        let me = Arc::clone(self);
        tokio::spawn(async move {
            let needs_warm = me
                .spare
                .lock()
                .await
                .as_ref()
                .map(|s| s.created_at.elapsed() > SPARE_MAX_AGE)
                .unwrap_or(true);
            if !needs_warm || me.closed.load(Ordering::Relaxed) {
                return;
            }
            if let Ok(conn) = me.dial_tls().await {
                if me.closed.load(Ordering::Relaxed) {
                    return;
                }
                let mut guard = me.spare.lock().await;
                if guard.is_none() {
                    *guard = Some(SpareConn {
                        stream: conn,
                        created_at: Instant::now(),
                    });
                }
            }
        });
    }
}

impl UpstreamSession for H1Session {
    fn open_tcp<'a>(&'a self, target_host: &'a str, target_port: u16) -> SessionFuture<'a, BoxStream> {
        Box::pin(async move {
            if self.closed.load(Ordering::Relaxed) {
                return Err(ProxyError::Transport("H1 session closed".into()));
            }
            let (eff_host, eff_port) = through_mozilla(target_host, target_port);
            let authority = format_authority(&eff_host, eff_port);
            let mut stream = self.take_or_dial().await?;

            let pass = self
                .proxy_pass
                .read()
                .map(|g| g.clone())
                .unwrap_or_default();
            let req = format!(
                "CONNECT {authority} HTTP/1.1\r\n\
                 Host: {authority}\r\n\
                 User-Agent: {}\r\n\
                 Proxy-Authorization: Bearer {pass}\r\n\
                 Proxy-Connection: keep-alive\r\n\r\n",
                self.user_agent
            );

            tokio::time::timeout(CONNECT_TIMEOUT, stream.write_all(req.as_bytes()))
                .await
                .map_err(|_| ProxyError::Transport("H1 CONNECT write timed out".into()))??;
            stream.flush().await?;

            let mut buf = Vec::with_capacity(1024);
            let mut tmp = [0u8; 512];
            let header_end = loop {
                if let Some(pos) = find_double_crlf(&buf) {
                    break pos;
                }
                if buf.len() >= 16 * 1024 {
                    return Err(ProxyError::Transport("H1 CONNECT response headers too large".into()));
                }
                let n = tokio::time::timeout(CONNECT_TIMEOUT, stream.read(&mut tmp))
                    .await
                    .map_err(|_| ProxyError::Transport("H1 CONNECT response timed out".into()))??;
                if n == 0 {
                    return Err(ProxyError::Transport("H1 CONNECT EOF before headers".into()));
                }
                buf.extend_from_slice(&tmp[..n]);
            };

            let status = parse_http_status_line(&buf[..header_end])?;
            if !(200..300).contains(&status) {
                let msg = String::from_utf8_lossy(&buf[..header_end]).into_owned();
                if matches!(status, 401 | 402 | 407) {
                    return Err(ProxyError::AuthFailed);
                }
                return Err(ProxyError::UpstreamStatus { status, message: msg });
            }

            let leftover = Bytes::copy_from_slice(&buf[header_end..]);
            if leftover.is_empty() {
                Ok(Box::new(stream) as BoxStream)
            } else {
                Ok(Box::new(PrefixedStream::new(leftover, stream)) as BoxStream)
            }
        })
    }

    fn open_udp<'a>(&'a self, _target_host: &'a str, _target_port: u16) -> SessionFuture<'a, crate::proxy::UdpTunnel> {
        Box::pin(async move {
            Err(ProxyError::Transport(
                "UDP requires HTTP/2 CONNECT-UDP session".into(),
            ))
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
            *self.spare.lock().await = None;
        })
    }
}

/// Convenience helper for warming spare socket asynchronously via `Arc<H1Session>`.
pub fn warm_h1_spare(sess: &Arc<H1Session>) {
    sess.spawn_warm_spare();
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|idx| idx + 4)
}

fn parse_http_status_line(head: &[u8]) -> Result<u16, ProxyError> {
    let text = String::from_utf8_lossy(head);
    let first_line = text.lines().next().unwrap_or_default();
    let code_str = first_line
        .split_ascii_whitespace()
        .nth(1)
        .ok_or_else(|| ProxyError::Transport(format!("malformed H1 response line: {first_line:?}")))?;
    code_str
        .parse::<u16>()
        .map_err(|e| ProxyError::Transport(format!("invalid H1 status code {code_str:?}: {e}")))
}
