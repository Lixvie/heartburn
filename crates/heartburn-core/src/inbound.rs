//! Local loopback SOCKS5 + HTTP CONNECT inbound listener for `sing-box`.
//!
//! Intentionally handles only client TCP forwarding (`SOCKS5 CONNECT`, `HTTP CONNECT`,
//! absolute-form HTTP) and Fastly-allowed UDP associations (`SOCKS5 UDP ASSOCIATE` over
//! `CONNECT-UDP`). Port 53 DNS interception is NOT performed here (`sing-box` handles DNS).

use std::collections::HashMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use base64::Engine as _;
use bytes::Bytes;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::{Mutex, Semaphore};
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::config::HANDSHAKE_TIMEOUT;
use crate::error::ProxyError;
use crate::proxy::failover::{FailureKind, classify_upstream_error};
use crate::proxy::tunnel::PrefixedStream;
use crate::proxy::{UdpTunnel, format_authority, is_allowed_udp_port};
use crate::tls::BoxStream;

const UDP_ASSOC_IDLE_TIMEOUT: Duration = Duration::from_secs(120);

/// Abstract outbound tunnel opener implemented by the engine controller.
pub trait TunnelOpener: Send + Sync + std::fmt::Debug {
    fn open_tcp<'a>(
        &'a self,
        client_ip: IpAddr,
        target_host: &'a str,
        target_port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<BoxStream, ProxyError>> + Send + 'a>>;

    fn open_udp<'a>(
        &'a self,
        client_ip: IpAddr,
        target_host: &'a str,
        target_port: u16,
    ) -> Pin<Box<dyn Future<Output = Result<UdpTunnel, ProxyError>> + Send + 'a>>;

    fn on_tunnel_opened(&self) {}
    fn on_tunnel_closed(&self) {}
}

/// Optional username/password credential pair guarding the local inbound listener.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InboundAuth {
    pub username: String,
    pub password: String,
}

impl InboundAuth {
    pub fn is_enabled(&self) -> bool {
        !self.username.is_empty() && !self.password.is_empty()
    }
}

/// Starts serving the local SOCKS5 + HTTP proxy listener until `cancel` triggers.
pub async fn serve_inbound(
    listener: TcpListener,
    opener: Arc<dyn TunnelOpener>,
    auth: Arc<InboundAuth>,
    max_connections: usize,
    verbose_log: bool,
    active_count: Arc<AtomicUsize>,
    cancel: CancellationToken,
) {
    let limit = if max_connections == 0 {
        None
    } else {
        Some(Arc::new(Semaphore::new(max_connections)))
    };
    let tasks = TaskTracker::new();

    loop {
        let accepted = tokio::select! {
            _ = cancel.cancelled() => break,
            res = listener.accept() => res,
        };

        let (stream, peer_addr) = match accepted {
            Ok(pair) => pair,
            Err(err) => {
                tracing::debug!(error = %err, "inbound accept failed");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let _ = stream.set_nodelay(true);

        let permit = if let Some(ref sem) = limit {
            match sem.clone().try_acquire_owned() {
                Ok(p) => Some(p),
                Err(_) => {
                    drop(stream);
                    continue;
                }
            }
        } else {
            None
        };

        let opener = Arc::clone(&opener);
        let auth = Arc::clone(&auth);
        let active_count = Arc::clone(&active_count);
        let child_cancel = cancel.clone();

        tasks.spawn(async move {
            let _permit = permit;
            if let Err(err) = handle_client(
                stream,
                peer_addr,
                opener,
                auth,
                verbose_log,
                active_count,
                child_cancel,
            )
            .await
            {
                tracing::debug!(peer = %peer_addr, error = %err, "inbound connection closed");
            }
        });
    }

    tasks.close();
    tasks.wait().await;
}

async fn handle_client(
    mut stream: TcpStream,
    peer_addr: SocketAddr,
    opener: Arc<dyn TunnelOpener>,
    auth: Arc<InboundAuth>,
    verbose_log: bool,
    active_count: Arc<AtomicUsize>,
    cancel: CancellationToken,
) -> Result<(), ProxyError> {
    let mut first = [0u8; 1];
    tokio::time::timeout(HANDSHAKE_TIMEOUT, stream.read_exact(&mut first))
        .await
        .map_err(|_| ProxyError::Protocol("inbound handshake timed out".into()))??;

    if first[0] == 0x05 {
        handle_socks5(
            stream,
            peer_addr.ip(),
            opener,
            &auth,
            verbose_log,
            active_count,
            cancel,
        )
        .await
    } else {
        handle_http(
            first[0],
            stream,
            peer_addr.ip(),
            opener,
            &auth,
            verbose_log,
            active_count,
            cancel,
        )
        .await
    }
}

async fn handle_socks5(
    mut stream: TcpStream,
    client_ip: IpAddr,
    opener: Arc<dyn TunnelOpener>,
    auth: &InboundAuth,
    verbose_log: bool,
    active_count: Arc<AtomicUsize>,
    cancel: CancellationToken,
) -> Result<(), ProxyError> {
    tokio::time::timeout(HANDSHAKE_TIMEOUT, socks5_negotiate_auth(&mut stream, auth))
        .await
        .map_err(|_| ProxyError::Protocol("SOCKS5 auth handshake timed out".into()))??;

    let (cmd, host, port) =
        tokio::time::timeout(HANDSHAKE_TIMEOUT, socks5_read_request(&mut stream))
            .await
            .map_err(|_| ProxyError::Protocol("SOCKS5 request timed out".into()))??;

    match cmd {
        0x01 => {
            if verbose_log {
                tracing::info!(target = %format_authority(&host, port), "SOCKS5 CONNECT");
            }
            let upstream = match opener.open_tcp(client_ip, &host, port).await {
                Ok(u) => u,
                Err(err) => {
                    let rep = socks5_reply_code(&err, port);
                    let _ = stream
                        .write_all(&[0x05, rep, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                        .await;
                    return Err(err);
                }
            };

            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await?;
            stream.flush().await?;

            bridge_tcp_stream(stream, upstream, opener.as_ref(), active_count, cancel).await
        }
        0x03 => {
            // SOCKS5 UDP ASSOCIATE
            handle_socks5_udp_associate(stream, client_ip, opener, verbose_log, cancel).await
        }
        other => {
            let _ = stream
                .write_all(&[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            Err(ProxyError::Protocol(format!(
                "unsupported SOCKS5 command {other:#x}"
            )))
        }
    }
}

async fn socks5_negotiate_auth(stream: &mut TcpStream, auth: &InboundAuth) -> Result<(), ProxyError> {
    let mut nmethods_buf = [0u8; 1];
    stream.read_exact(&mut nmethods_buf).await?;
    let nmethods = usize::from(nmethods_buf[0]);
    if nmethods == 0 {
        let _ = stream.write_all(&[0x05, 0xff]).await;
        return Err(ProxyError::Protocol("SOCKS5 0 methods".into()));
    }
    let mut methods = vec![0u8; nmethods];
    stream.read_exact(&mut methods).await?;

    if auth.is_enabled() {
        if !methods.contains(&0x02) {
            let _ = stream.write_all(&[0x05, 0xff]).await;
            return Err(ProxyError::AuthFailed);
        }
        stream.write_all(&[0x05, 0x02]).await?;

        let mut hdr = [0u8; 2];
        stream.read_exact(&mut hdr).await?;
        let ulen = usize::from(hdr[1]);
        let mut ubytes = vec![0u8; ulen];
        stream.read_exact(&mut ubytes).await?;

        let mut plen_buf = [0u8; 1];
        stream.read_exact(&mut plen_buf).await?;
        let mut pbytes = vec![0u8; usize::from(plen_buf[0])];
        stream.read_exact(&mut pbytes).await?;

        let ok = ubytes == auth.username.as_bytes() && pbytes == auth.password.as_bytes();
        if !ok {
            let _ = stream.write_all(&[0x01, 0x01]).await;
            return Err(ProxyError::AuthFailed);
        }
        stream.write_all(&[0x01, 0x00]).await?;
    } else {
        if !methods.contains(&0x00) {
            let _ = stream.write_all(&[0x05, 0xff]).await;
            return Err(ProxyError::Protocol("client rejected no-auth".into()));
        }
        stream.write_all(&[0x05, 0x00]).await?;
    }
    Ok(())
}

async fn socks5_read_request(stream: &mut TcpStream) -> Result<(u8, String, u16), ProxyError> {
    let mut hdr = [0u8; 4];
    stream.read_exact(&mut hdr).await?;
    if hdr[0] != 0x05 {
        return Err(ProxyError::Protocol("invalid SOCKS5 request version".into()));
    }
    let cmd = hdr[1];
    let atyp = hdr[3];
    let host = match atyp {
        0x01 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            IpAddr::V4(Ipv4Addr::from(ip)).to_string()
        }
        0x03 => {
            let mut len = [0u8; 1];
            stream.read_exact(&mut len).await?;
            let mut dom = vec![0u8; usize::from(len[0])];
            stream.read_exact(&mut dom).await?;
            String::from_utf8(dom)
                .map_err(|_| ProxyError::Protocol("non-UTF8 SOCKS5 domain".into()))?
        }
        0x04 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            IpAddr::V6(Ipv6Addr::from(ip)).to_string()
        }
        other => {
            let _ = stream
                .write_all(&[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await;
            return Err(ProxyError::Protocol(format!("unsupported ATYP {other:#x}")));
        }
    };

    let mut port_bytes = [0u8; 2];
    stream.read_exact(&mut port_bytes).await?;
    Ok((cmd, host, u16::from_be_bytes(port_bytes)))
}

async fn handle_socks5_udp_associate(
    mut ctrl_tcp: TcpStream,
    client_ip: IpAddr,
    opener: Arc<dyn TunnelOpener>,
    verbose_log: bool,
    cancel: CancellationToken,
) -> Result<(), ProxyError> {
    let local_ip = ctrl_tcp
        .local_addr()
        .map(|a| a.ip())
        .unwrap_or(IpAddr::V4(Ipv4Addr::LOCALHOST));
    let udp = Arc::new(UdpSocket::bind(SocketAddr::new(local_ip, 0)).await?);
    let udp_addr = udp.local_addr()?;

    let mut rep = Vec::with_capacity(22);
    rep.extend_from_slice(&[0x05, 0x00, 0x00]);
    match udp_addr.ip() {
        IpAddr::V4(v4) => {
            rep.push(0x01);
            rep.extend_from_slice(&v4.octets());
        }
        IpAddr::V6(v6) => {
            rep.push(0x04);
            rep.extend_from_slice(&v6.octets());
        }
    }
    rep.extend_from_slice(&udp_addr.port().to_be_bytes());
    ctrl_tcp.write_all(&rep).await?;
    ctrl_tcp.flush().await?;

    struct AssocEntry {
        tx: tokio::sync::mpsc::Sender<Vec<u8>>,
        last_used: Arc<std::sync::atomic::AtomicU64>,
    }

    let assoc_map: Arc<Mutex<HashMap<(String, u16), AssocEntry>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let epoch = Instant::now();
    let client_udp_addr: Arc<Mutex<Option<SocketAddr>>> = Arc::new(Mutex::new(None));
    let assoc_cancel = cancel.child_token();

    let mut udp_buf = vec![0u8; 65536];
    let mut ctrl_buf = [0u8; 16];

    loop {
        tokio::select! {
            _ = assoc_cancel.cancelled() => break,
            ctrl_res = ctrl_tcp.read(&mut ctrl_buf) => {
                // RFC 1928: UDP association terminates when the TCP control connection closes.
                match ctrl_res {
                    Ok(0) | Err(_) => break,
                    Ok(_) => continue,
                }
            }
            recv_res = udp.recv_from(&mut udp_buf) => {
                let (n, src_addr) = match recv_res {
                    Ok(v) => v,
                    Err(_) => break,
                };
                if src_addr.ip() != client_ip && !src_addr.ip().is_loopback() {
                    continue;
                }
                *client_udp_addr.lock().await = Some(src_addr);

                let Ok((host, port, payload)) = parse_socks5_udp_datagram(&udp_buf[..n]) else {
                    continue;
                };
                if !is_allowed_udp_port(port) {
                    if verbose_log {
                        tracing::debug!(host = %host, port, "refused disallowed SOCKS5 UDP port");
                    }
                    continue;
                }

                let key = (host.clone(), port);
                let tx_opt = {
                    let mut map = assoc_map.lock().await;
                    map.retain(|_, e| {
                        let last = e.last_used.load(Ordering::Relaxed);
                        (epoch.elapsed().as_millis() as u64).saturating_sub(last)
                            < UDP_ASSOC_IDLE_TIMEOUT.as_millis() as u64
                    });
                    map.get(&key).map(|e| (e.tx.clone(), Arc::clone(&e.last_used)))
                };

                let (tx, last_used) = match tx_opt {
                    Some(existing) => existing,
                    None => {
                        if verbose_log {
                            tracing::info!(target = %format_authority(&host, port), "SOCKS5 UDP ASSOCIATE");
                        }
                        let mut tunnel = match opener.open_udp(client_ip, &host, port).await {
                            Ok(t) => t,
                            Err(err) => {
                                tracing::debug!(error = %err, "CONNECT-UDP open failed");
                                continue;
                            }
                        };
                        let last = Arc::new(std::sync::atomic::AtomicU64::new(
                            epoch.elapsed().as_millis() as u64,
                        ));
                        let entry = AssocEntry {
                            tx: tunnel.tx.clone(),
                            last_used: Arc::clone(&last),
                        };
                        assoc_map.lock().await.insert(key.clone(), entry);

                        let udp_down = Arc::clone(&udp);
                        let client_down = Arc::clone(&client_udp_addr);
                        let assoc_map_down = Arc::clone(&assoc_map);
                        let last_down = Arc::clone(&last);
                        let child = assoc_cancel.clone();
                        let down_host = host.clone();

                        tokio::spawn(async move {
                            loop {
                                let pkt = tokio::select! {
                                    _ = child.cancelled() => break,
                                    p = tunnel.rx.recv() => match p {
                                        Some(p) => p,
                                        None => break,
                                    }
                                };
                                last_down.store(epoch.elapsed().as_millis() as u64, Ordering::Relaxed);
                                if let Some(dest) = *client_down.lock().await
                                    && let Ok(framed) = encode_socks5_udp_datagram(&down_host, port, &pkt)
                                {
                                    let _ = udp_down.send_to(&framed, dest).await;
                                }
                            }
                            assoc_map_down.lock().await.remove(&(down_host, port));
                        });

                        (tunnel.tx, last)
                    }
                };

                last_used.store(epoch.elapsed().as_millis() as u64, Ordering::Relaxed);
                if tx.send(payload.to_vec()).await.is_err() {
                    assoc_map.lock().await.remove(&key);
                }
            }
        }
    }

    assoc_cancel.cancel();
    Ok(())
}

/// Parses RFC 1928 SOCKS5 UDP request datagram (`RSV(2), FRAG(1), ATYP, DST.ADDR, DST.PORT, DATA`).
pub fn parse_socks5_udp_datagram(pkt: &[u8]) -> Result<(String, u16, &[u8]), ProxyError> {
    if pkt.len() < 8 {
        return Err(ProxyError::Protocol("UDP datagram too short".into()));
    }
    if pkt[2] != 0x00 {
        // RFC 1928: drop fragmented UDP datagrams when fragmentation isn't supported.
        return Err(ProxyError::Protocol("fragmented SOCKS5 UDP unsupported".into()));
    }
    let (host, pos) = match pkt[3] {
        0x01 => {
            if pkt.len() < 10 {
                return Err(ProxyError::Protocol("truncated IPv4 UDP datagram".into()));
            }
            let ip = Ipv4Addr::new(pkt[4], pkt[5], pkt[6], pkt[7]);
            (IpAddr::V4(ip).to_string(), 8)
        }
        0x03 => {
            let dlen = usize::from(pkt[4]);
            if pkt.len() < 5 + dlen + 2 {
                return Err(ProxyError::Protocol("truncated domain UDP datagram".into()));
            }
            let host = String::from_utf8(pkt[5..5 + dlen].to_vec())
                .map_err(|_| ProxyError::Protocol("non-UTF8 UDP host".into()))?;
            (host, 5 + dlen)
        }
        0x04 => {
            if pkt.len() < 22 {
                return Err(ProxyError::Protocol("truncated IPv6 UDP datagram".into()));
            }
            let mut octets = [0u8; 16];
            octets.copy_from_slice(&pkt[4..20]);
            (IpAddr::V6(Ipv6Addr::from(octets)).to_string(), 20)
        }
        other => return Err(ProxyError::Protocol(format!("unknown UDP ATYP {other:#x}"))),
    };
    let port = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
    Ok((host, port, &pkt[pos + 2..]))
}

/// Encodes a SOCKS5 UDP datagram response header around `payload`.
pub fn encode_socks5_udp_datagram(
    host: &str,
    port: u16,
    payload: &[u8],
) -> Result<Vec<u8>, ProxyError> {
    let mut out = Vec::with_capacity(24 + payload.len());
    out.extend_from_slice(&[0x00, 0x00, 0x00]); // RSV=0, FRAG=0
    if let Ok(ip) = host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(v4) => {
                out.push(0x01);
                out.extend_from_slice(&v4.octets());
            }
            IpAddr::V6(v6) => {
                out.push(0x04);
                out.extend_from_slice(&v6.octets());
            }
        }
    } else {
        if host.len() > 255 {
            return Err(ProxyError::Protocol("UDP host exceeds 255 bytes".into()));
        }
        out.push(0x03);
        out.push(host.len() as u8);
        out.extend_from_slice(host.as_bytes());
    }
    out.extend_from_slice(&port.to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

#[allow(clippy::too_many_arguments)]
async fn handle_http(
    first_byte: u8,
    mut stream: TcpStream,
    client_ip: IpAddr,
    opener: Arc<dyn TunnelOpener>,
    auth: &InboundAuth,
    verbose_log: bool,
    active_count: Arc<AtomicUsize>,
    cancel: CancellationToken,
) -> Result<(), ProxyError> {
    let mut buf = vec![first_byte];
    let mut tmp = [0u8; 1024];
    let header_end = tokio::time::timeout(HANDSHAKE_TIMEOUT, async {
        loop {
            if let Some(pos) = find_double_crlf(&buf) {
                return Ok::<usize, ProxyError>(pos);
            }
            if buf.len() >= 32 * 1024 {
                return Err(ProxyError::Protocol("HTTP proxy header exceeds 32 KiB".into()));
            }
            let n = stream.read(&mut tmp).await?;
            if n == 0 {
                return Err(ProxyError::Protocol("HTTP proxy EOF before headers".into()));
            }
            buf.extend_from_slice(&tmp[..n]);
        }
    })
    .await
    .map_err(|_| ProxyError::Protocol("HTTP header read timed out".into()))??;

    let head = String::from_utf8_lossy(&buf[..header_end]);
    let mut lines = head.split("\r\n");
    let req_line = lines
        .next()
        .ok_or_else(|| ProxyError::Protocol("empty HTTP request line".into()))?;
    let mut parts = req_line.split_ascii_whitespace();
    let method = parts
        .next()
        .ok_or_else(|| ProxyError::Protocol("missing HTTP method".into()))?;
    let target = parts
        .next()
        .ok_or_else(|| ProxyError::Protocol("missing HTTP target".into()))?;
    let version = parts.next().unwrap_or("HTTP/1.1");

    let mut proxy_auth_header: Option<&str> = None;
    let mut raw_headers: Vec<(&str, &str)> = Vec::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let kt = k.trim();
            let vt = v.trim();
            if kt.eq_ignore_ascii_case("proxy-authorization") {
                proxy_auth_header = Some(vt);
            } else if !kt.eq_ignore_ascii_case("proxy-connection") {
                raw_headers.push((kt, vt));
            }
        }
    }

    if auth.is_enabled() && !verify_basic_proxy_auth(proxy_auth_header, auth) {
        let _ = stream
            .write_all(
                b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"heartburn\"\r\nConnection: close\r\n\r\n",
            )
            .await;
        return Err(ProxyError::AuthFailed);
    }

    let leftover = Bytes::copy_from_slice(&buf[header_end..]);

    if method.eq_ignore_ascii_case("CONNECT") {
        let (host, port) = crate::config::split_host_port(target)
            .ok_or_else(|| ProxyError::Protocol(format!("invalid CONNECT target {target:?}")))?;
        if verbose_log {
            tracing::info!(target = %format_authority(host, port), "HTTP CONNECT");
        }
        let upstream = match opener.open_tcp(client_ip, host, port).await {
            Ok(u) => u,
            Err(err) => {
                let status = if matches!(
                    classify_upstream_error(&err, port),
                    FailureKind::DestinationPortRefused
                ) {
                    "403 Forbidden"
                } else {
                    "502 Bad Gateway"
                };
                let msg = format!("HTTP/1.1 {status}\r\nConnection: close\r\n\r\n");
                let _ = stream.write_all(msg.as_bytes()).await;
                return Err(err);
            }
        };

        stream
            .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
            .await?;
        stream.flush().await?;

        let client_io = PrefixedStream::new(leftover, stream);
        return bridge_tcp_stream(client_io, upstream, opener.as_ref(), active_count, cancel).await;
    }

    // Plain absolute-form HTTP proxy request (`GET http://example.com/path HTTP/1.1`).
    let parsed = url::Url::parse(target)
        .map_err(|e| ProxyError::Protocol(format!("invalid HTTP proxy URL {target:?}: {e}")))?;
    let host = parsed
        .host_str()
        .filter(|h| !h.is_empty())
        .ok_or_else(|| ProxyError::Protocol("HTTP proxy URL missing host".into()))?
        .trim_matches(['[', ']'])
        .to_owned();
    let port = parsed.port_or_known_default().unwrap_or(80);
    if verbose_log {
        tracing::info!(target = %format_authority(&host, port), "HTTP PROXY");
    }

    let mut upstream = opener.open_tcp(client_ip, &host, port).await?;
    let mut path_q = parsed.path().to_owned();
    if path_q.is_empty() {
        path_q = "/".to_owned();
    }
    if let Some(q) = parsed.query() {
        path_q.push('?');
        path_q.push_str(q);
    }

    let mut forward = format!("{method} {path_q} {version}\r\n");
    let mut has_host = false;
    for (k, v) in raw_headers {
        if k.eq_ignore_ascii_case("host") {
            has_host = true;
        }
        forward.push_str(k);
        forward.push_str(": ");
        forward.push_str(v);
        forward.push_str("\r\n");
    }
    if !has_host {
        forward.push_str(&format!("Host: {}\r\n", format_authority(&host, port)));
    }
    forward.push_str("\r\n");
    upstream.write_all(forward.as_bytes()).await?;
    if !leftover.is_empty() {
        upstream.write_all(&leftover).await?;
    }
    upstream.flush().await?;

    bridge_tcp_stream(stream, upstream, opener.as_ref(), active_count, cancel).await
}

fn verify_basic_proxy_auth(header_val: Option<&str>, auth: &InboundAuth) -> bool {
    let Some(raw) = header_val else {
        return false;
    };
    let Some(b64) = raw
        .trim()
        .strip_prefix("Basic ")
        .or_else(|| raw.trim().strip_prefix("basic "))
    else {
        return false;
    };
    let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(b64.trim()) else {
        return false;
    };
    let Ok(text) = std::str::from_utf8(&decoded) else {
        return false;
    };
    text.split_once(':')
        .map(|(u, p)| u == auth.username && p == auth.password)
        .unwrap_or(false)
}

async fn bridge_tcp_stream<C>(
    mut client: C,
    mut upstream: BoxStream,
    opener: &dyn TunnelOpener,
    active_count: Arc<AtomicUsize>,
    cancel: CancellationToken,
) -> Result<(), ProxyError>
where
    C: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    active_count.fetch_add(1, Ordering::Relaxed);
    opener.on_tunnel_opened();

    let res = tokio::select! {
        _ = cancel.cancelled() => Ok(()),
        r = copy_bidirectional(&mut client, &mut upstream) => {
            r.map(|_| ()).map_err(ProxyError::Io)
        }
    };

    active_count.fetch_sub(1, Ordering::Relaxed);
    opener.on_tunnel_closed();
    res
}

fn socks5_reply_code(err: &ProxyError, port: u16) -> u8 {
    match classify_upstream_error(err, port) {
        FailureKind::DestinationPortRefused => 0x02,
        FailureKind::AuthExpired | FailureKind::RateLimited => 0x01,
        FailureKind::UpstreamSessionBroken | FailureKind::ClientDisconnected => 0x05,
    }
}

fn find_double_crlf(buf: &[u8]) -> Option<usize> {
    buf.windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map(|idx| idx + 4)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_socks5_udp_datagram_framing() {
        let framed = encode_socks5_udp_datagram("one.one.one.one", 443, b"quic-pkt").unwrap();
        let (host, port, payload) = parse_socks5_udp_datagram(&framed).unwrap();
        assert_eq!(host, "one.one.one.one");
        assert_eq!(port, 443);
        assert_eq!(payload, b"quic-pkt");

        let v6 = encode_socks5_udp_datagram("2606:4700::1111", 8443, b"hi").unwrap();
        let (h6, p6, d6) = parse_socks5_udp_datagram(&v6).unwrap();
        assert_eq!(h6, "2606:4700::1111");
        assert_eq!(p6, 8443);
        assert_eq!(d6, b"hi");
    }

    #[test]
    fn verifies_http_basic_proxy_auth() {
        let auth = InboundAuth {
            username: "u1".into(),
            password: "p1".into(),
        };
        let hdr = format!(
            "Basic {}",
            base64::engine::general_purpose::STANDARD.encode("u1:p1")
        );
        assert!(verify_basic_proxy_auth(Some(&hdr), &auth));
        assert!(!verify_basic_proxy_auth(Some("Basic bad=="), &auth));
        assert!(!verify_basic_proxy_auth(None, &auth));
    }

    #[derive(Debug)]
    struct EchoOpener {
        echo_tcp_target: SocketAddr,
    }

    impl TunnelOpener for EchoOpener {
        fn open_tcp<'a>(
            &'a self,
            _client_ip: IpAddr,
            _target_host: &'a str,
            _target_port: u16,
        ) -> Pin<Box<dyn Future<Output = Result<BoxStream, ProxyError>> + Send + 'a>> {
            let target = self.echo_tcp_target;
            Box::pin(async move {
                let tcp = TcpStream::connect(target).await?;
                Ok(Box::new(tcp) as BoxStream)
            })
        }

        fn open_udp<'a>(
            &'a self,
            _client_ip: IpAddr,
            _target_host: &'a str,
            target_port: u16,
        ) -> Pin<Box<dyn Future<Output = Result<UdpTunnel, ProxyError>> + Send + 'a>> {
            Box::pin(async move {
                if !is_allowed_udp_port(target_port) {
                    return Err(ProxyError::PortRejected(target_port));
                }
                let (up_tx, mut up_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
                let (down_tx, down_rx) = tokio::sync::mpsc::channel::<Vec<u8>>(8);
                let closed = Arc::new(std::sync::atomic::AtomicBool::new(false));
                tokio::spawn(async move {
                    while let Some(mut pkt) = up_rx.recv().await {
                        pkt.extend_from_slice(b"-echo");
                        if down_tx.send(pkt).await.is_err() {
                            break;
                        }
                    }
                });
                Ok(UdpTunnel {
                    tx: up_tx,
                    rx: down_rx,
                    closed,
                })
            })
        }
    }

    #[tokio::test]
    async fn socks5_and_http_connect_startup_forward_and_clean_shutdown() {
        // Upstream echo server
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo_listener.local_addr().unwrap();
        let echo_cancel = CancellationToken::new();
        let ec = echo_cancel.clone();
        let echo_task = tokio::spawn(async move {
            loop {
                tokio::select! {
                    _ = ec.cancelled() => break,
                    Ok((mut s, _)) = echo_listener.accept() => {
                        tokio::spawn(async move {
                            let (mut r, mut w) = s.split();
                            let _ = tokio::io::copy(&mut r, &mut w).await;
                        });
                    }
                }
            }
        });

        let inbound_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_addr = inbound_listener.local_addr().unwrap();
        let cancel = CancellationToken::new();
        let active = Arc::new(AtomicUsize::new(0));
        let opener: Arc<dyn TunnelOpener> = Arc::new(EchoOpener {
            echo_tcp_target: echo_addr,
        });
        let auth = Arc::new(InboundAuth {
            username: "alice".into(),
            password: "secret".into(),
        });

        let server_handle = tokio::spawn(serve_inbound(
            inbound_listener,
            opener,
            auth,
            16,
            false,
            Arc::clone(&active),
            cancel.clone(),
        ));

        // 1. Test SOCKS5 CONNECT with RFC 1929 auth
        {
            let mut c = TcpStream::connect(proxy_addr).await.unwrap();
            c.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
            let mut m = [0u8; 2];
            c.read_exact(&mut m).await.unwrap();
            assert_eq!(&m, &[0x05, 0x02]);

            c.write_all(&[0x01, 5, b'a', b'l', b'i', b'c', b'e', 6, b's', b'e', b'c', b'r', b'e', b't'])
                .await
                .unwrap();
            let mut ar = [0u8; 2];
            c.read_exact(&mut ar).await.unwrap();
            assert_eq!(&ar, &[0x01, 0x00]);

            c.write_all(&[0x05, 0x01, 0x00, 0x03, 9, b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't', 0x01, 0xbb])
                .await
                .unwrap();
            let mut rep = [0u8; 10];
            c.read_exact(&mut rep).await.unwrap();
            assert_eq!(rep[1], 0x00);

            c.write_all(b"hello-socks").await.unwrap();
            let mut buf = [0u8; 11];
            c.read_exact(&mut buf).await.unwrap();
            assert_eq!(&buf, b"hello-socks");
        }

        // 2. Test HTTP CONNECT with Basic auth
        {
            let mut c = TcpStream::connect(proxy_addr).await.unwrap();
            let creds = base64::engine::general_purpose::STANDARD.encode("alice:secret");
            let req = format!(
                "CONNECT example.org:443 HTTP/1.1\r\nHost: example.org:443\r\nProxy-Authorization: Basic {creds}\r\n\r\n"
            );
            c.write_all(req.as_bytes()).await.unwrap();
            let mut hdr = vec![0u8; 128];
            let n = c.read(&mut hdr).await.unwrap();
            let resp_txt = String::from_utf8_lossy(&hdr[..n]);
            assert!(resp_txt.starts_with("HTTP/1.1 200"));

            c.write_all(b"http-tun").await.unwrap();
            let mut out = [0u8; 8];
            c.read_exact(&mut out).await.unwrap();
            assert_eq!(&out, b"http-tun");
        }

        // 3. Test SOCKS5 UDP ASSOCIATE (port 443 allowed; port 53 dropped)
        {
            let mut ctrl = TcpStream::connect(proxy_addr).await.unwrap();
            ctrl.write_all(&[0x05, 0x01, 0x02]).await.unwrap();
            let mut m = [0u8; 2];
            ctrl.read_exact(&mut m).await.unwrap();
            ctrl.write_all(&[0x01, 5, b'a', b'l', b'i', b'c', b'e', 6, b's', b'e', b'c', b'r', b'e', b't'])
                .await
                .unwrap();
            let mut ar = [0u8; 2];
            ctrl.read_exact(&mut ar).await.unwrap();
            ctrl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut rep = [0u8; 10];
            ctrl.read_exact(&mut rep).await.unwrap();
            assert_eq!(rep[1], 0x00);
            let udp_ip = Ipv4Addr::new(rep[4], rep[5], rep[6], rep[7]);
            let udp_port = u16::from_be_bytes([rep[8], rep[9]]);
            let relay_addr = SocketAddr::new(IpAddr::V4(udp_ip), udp_port);

            let client_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            // Send allowed port 443 packet
            let pkt = encode_socks5_udp_datagram("1.1.1.1", 443, b"quic").unwrap();
            client_udp.send_to(&pkt, relay_addr).await.unwrap();
            let mut rbuf = [0u8; 256];
            let (rn, _) = tokio::time::timeout(Duration::from_secs(2), client_udp.recv_from(&mut rbuf))
                .await
                .unwrap()
                .unwrap();
            let (rh, rp, rdata) = parse_socks5_udp_datagram(&rbuf[..rn]).unwrap();
            assert_eq!(rh, "1.1.1.1");
            assert_eq!(rp, 443);
            assert_eq!(rdata, b"quic-echo");

            // Port 53 must NOT be proxied/intercepted.
            let dns_pkt = encode_socks5_udp_datagram("1.1.1.1", 53, b"dns").unwrap();
            client_udp.send_to(&dns_pkt, relay_addr).await.unwrap();
            assert!(
                tokio::time::timeout(Duration::from_millis(120), client_udp.recv_from(&mut rbuf))
                    .await
                    .is_err()
            );
        }

        // 4. Graceful shutdown leaves zero lingering tasks
        cancel.cancel();
        tokio::time::timeout(Duration::from_secs(2), server_handle)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(active.load(Ordering::Relaxed), 0);

        echo_cancel.cancel();
        let _ = echo_task.await;
    }
}
