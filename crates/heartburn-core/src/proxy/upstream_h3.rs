//! HTTP/3 over QUIC (`quinn` + `h3`) upstream session (`proxy/upstream_h3.go`).
//!
//! Uses [`ProtectedDialer::bind_std_udp`] before constructing `quinn::Endpoint` so Android's
//! `VpnService.protect` hook runs on every QUIC UDP socket prior to sending packets.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, RwLock};
use std::time::Duration;

use bytes::{Buf, Bytes};
use h3::client::SendRequest;
use h3::error::Code;
use http::{HeaderValue, Method, Request};
use quinn::crypto::rustls::QuicClientConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::Mutex;
use tokio::task::{JoinHandle, JoinSet};
use tokio_util::sync::CancellationToken;

use crate::config::{CONNECT_TIMEOUT, IpVersionMode};
use crate::dialer::ProtectedDialer;
use crate::dns::{BootstrapResolver, HAPPY_EYEBALLS_STAGGER};
use crate::error::ProxyError;
use crate::proxy::tunnel::duplex_bridge;
use crate::proxy::{SessionFuture, UdpTunnel, UpstreamSession, format_authority, through_mozilla};
use crate::tls::{BoxStream, RustlsConnector, TlsConfig};

/// Faster HTTP/3 QUIC handshake timeout used on initial primary dial before falling back to HTTP/2.
pub const H3_FALLBACK_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(3);

const H3_INITIAL_MTU: u16 = 1200;
const H3_KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const H3_MAX_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const H3_DUPLEX_BUF_SIZE: usize = 256 * 1024;

struct EndpointGuard(Option<quinn::Endpoint>);

impl EndpointGuard {
    fn disarm(&mut self) -> Option<quinn::Endpoint> {
        self.0.take()
    }
}

impl Drop for EndpointGuard {
    fn drop(&mut self) {
        if let Some(ep) = self.0.take() {
            ep.close(0u32.into(), b"aborted");
        }
    }
}

/// Upstream HTTP/3 CONNECT session to a Mozilla Fastly edge node.
pub struct H3Session {
    server_host: String,
    server_port: u16,
    user_agent: String,
    proxy_pass: RwLock<String>,
    send_request: Mutex<SendRequest<h3_quinn::OpenStreams, Bytes>>,
    endpoint: quinn::Endpoint,
    closed: Arc<AtomicBool>,
    cancel: CancellationToken,
    driver_handle: Mutex<Option<JoinHandle<()>>>,
}

impl std::fmt::Debug for H3Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("H3Session")
            .field("server_host", &self.server_host)
            .field("server_port", &self.server_port)
            .field("closed", &self.closed.load(Ordering::Relaxed))
            .finish()
    }
}

type QuicAttemptResult =
    Result<(SocketAddr, quinn::Endpoint, quinn::Connection), (SocketAddr, ProxyError)>;

fn spawn_quic_attempt(
    set: &mut JoinSet<QuicAttemptResult>,
    peer_addr: SocketAddr,
    server_host: String,
    client_cfg: quinn::ClientConfig,
    dialer: ProtectedDialer,
) {
    set.spawn(async move {
        let bind_ip = if peer_addr.is_ipv6() {
            IpAddr::V6(Ipv6Addr::UNSPECIFIED)
        } else {
            IpAddr::V4(Ipv4Addr::UNSPECIFIED)
        };
        let std_udp = dialer
            .bind_std_udp(SocketAddr::new(bind_ip, 0))
            .map_err(|e| {
                (
                    peer_addr,
                    ProxyError::Transport(format!("H3 UDP socket protect/bind: {e}")),
                )
            })?;

        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            None,
            std_udp,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|e| {
            (
                peer_addr,
                ProxyError::Transport(format!("QUIC endpoint init: {e}")),
            )
        })?;

        let mut ep_guard = EndpointGuard(Some(endpoint));
        let connecting = ep_guard
            .0
            .as_ref()
            .expect("endpoint initialized")
            .connect_with(client_cfg, peer_addr, &server_host)
            .map_err(|e| {
                (
                    peer_addr,
                    ProxyError::Transport(format!("QUIC connect setup: {e}")),
                )
            })?;

        let quic_conn = connecting.await.map_err(|e| {
            (
                peer_addr,
                ProxyError::Transport(format!("QUIC handshake failed: {e}")),
            )
        })?;

        let endpoint = ep_guard.disarm().expect("endpoint still present");
        Ok((peer_addr, endpoint, quic_conn))
    });
}

async fn dial_quic_race(
    server_host: &str,
    client_cfg: &quinn::ClientConfig,
    dialer: &ProtectedDialer,
    resolver: &BootstrapResolver,
    candidates: &[SocketAddr],
) -> Result<(quinn::Endpoint, quinn::Connection), ProxyError> {
    let mut set = JoinSet::new();
    let mut next_idx = 0;
    let mut last_err: Option<ProxyError> = None;

    if let Some(&first) = candidates.first() {
        spawn_quic_attempt(
            &mut set,
            first,
            server_host.to_owned(),
            client_cfg.clone(),
            dialer.clone(),
        );
        next_idx = 1;
    }

    let stagger = tokio::time::sleep(HAPPY_EYEBALLS_STAGGER);
    tokio::pin!(stagger);

    while !set.is_empty() || next_idx < candidates.len() {
        tokio::select! {
            joined = set.join_next(), if !set.is_empty() => {
                match joined {
                    Some(Ok(Ok((addr, endpoint, quic_conn)))) => {
                        set.abort_all();
                        resolver.record_dial_success(addr);
                        return Ok((endpoint, quic_conn));
                    }
                    Some(Ok(Err((addr, err)))) => {
                        tracing::debug!(peer = %addr, error = %err, "H3 candidate attempt failed");
                        resolver.record_dial_failure(addr);
                        last_err = Some(err);
                    }
                    Some(Err(join_err)) => {
                        last_err = Some(ProxyError::Transport(format!("QUIC task join error: {join_err}")));
                    }
                    None => break,
                }
                if next_idx < candidates.len() {
                    let cand = candidates[next_idx];
                    next_idx += 1;
                    spawn_quic_attempt(
                        &mut set,
                        cand,
                        server_host.to_owned(),
                        client_cfg.clone(),
                        dialer.clone(),
                    );
                    stagger
                        .as_mut()
                        .reset(tokio::time::Instant::now() + HAPPY_EYEBALLS_STAGGER);
                }
            }
            () = &mut stagger, if next_idx < candidates.len() => {
                let cand = candidates[next_idx];
                next_idx += 1;
                spawn_quic_attempt(
                    &mut set,
                    cand,
                    server_host.to_owned(),
                    client_cfg.clone(),
                    dialer.clone(),
                );
                stagger
                    .as_mut()
                    .reset(tokio::time::Instant::now() + HAPPY_EYEBALLS_STAGGER);
            }
        }
    }

    Err(last_err
        .unwrap_or_else(|| ProxyError::Transport(format!("no IPs resolved for {server_host}"))))
}

impl H3Session {
    /// Resolves `server_host`, binds protected UDP sockets via `dialer`, opens a QUIC + HTTP/3
    /// session (`InitialMTU = 1200`, `KeepAlive = 15s`, `MaxIdleTimeout = 60s`), and starts the
    /// connection driver task.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect(
        server_host: String,
        server_port: u16,
        user_agent: String,
        proxy_pass: String,
        ip_version: IpVersionMode,
        resolver: Arc<BootstrapResolver>,
        dialer: ProtectedDialer,
        rustls: RustlsConnector,
    ) -> Result<Arc<Self>, ProxyError> {
        Self::connect_with_timeout(
            server_host,
            server_port,
            user_agent,
            proxy_pass,
            ip_version,
            resolver,
            dialer,
            rustls,
            CONNECT_TIMEOUT,
        )
        .await
    }

    /// Opens an HTTP/3 session with an explicit total QUIC + H3 handshake timeout.
    #[allow(clippy::too_many_arguments)]
    pub async fn connect_with_timeout(
        server_host: String,
        server_port: u16,
        user_agent: String,
        proxy_pass: String,
        ip_version: IpVersionMode,
        resolver: Arc<BootstrapResolver>,
        dialer: ProtectedDialer,
        rustls: RustlsConnector,
        handshake_timeout: Duration,
    ) -> Result<Arc<Self>, ProxyError> {
        let ips = resolver
            .lookup_ip(&server_host)
            .await
            .map_err(|e| ProxyError::Transport(e.to_string()))?;
        let candidates = resolver.order_addrs(&ips, server_port, ip_version);
        if candidates.is_empty() {
            return Err(ProxyError::Transport(format!(
                "no IPs resolved for {server_host}"
            )));
        }

        Self::connect_addrs(
            server_host,
            server_port,
            user_agent,
            proxy_pass,
            resolver,
            dialer,
            rustls,
            &candidates,
            handshake_timeout,
        )
        .await
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) async fn connect_addrs(
        server_host: String,
        server_port: u16,
        user_agent: String,
        proxy_pass: String,
        resolver: Arc<BootstrapResolver>,
        dialer: ProtectedDialer,
        rustls: RustlsConnector,
        candidates: &[SocketAddr],
        handshake_timeout: Duration,
    ) -> Result<Arc<Self>, ProxyError> {
        if candidates.is_empty() {
            return Err(ProxyError::Transport(format!(
                "no IPs resolved for {server_host}"
            )));
        }

        let tls_cfg = TlsConfig {
            server_name: server_host.clone(),
            alpn: vec![b"h3".to_vec()],
            ech_config_list: None,
            tls12_only: false,
            ..Default::default()
        };
        let rustls_cfg = rustls
            .build_client_config(&tls_cfg)
            .map_err(|e| ProxyError::Transport(e.to_string()))?;
        let quic_crypto = QuicClientConfig::try_from(rustls_cfg)
            .map_err(|e| ProxyError::Transport(format!("QUIC TLS config error: {e}")))?;

        let mut transport = quinn::TransportConfig::default();
        transport.initial_mtu(H3_INITIAL_MTU);
        transport.keep_alive_interval(Some(H3_KEEPALIVE_INTERVAL));
        transport.max_idle_timeout(Some(
            quinn::IdleTimeout::try_from(H3_MAX_IDLE_TIMEOUT)
                .expect("60s idle timeout fits QUIC VarInt"),
        ));

        let mut client_cfg = quinn::ClientConfig::new(Arc::new(quic_crypto));
        client_cfg.transport_config(Arc::new(transport));

        let (endpoint, mut h3_conn, send_request) =
            tokio::time::timeout(handshake_timeout, async {
                let (endpoint, quic_conn) = dial_quic_race(
                    &server_host,
                    &client_cfg,
                    &dialer,
                    &resolver,
                    candidates,
                )
                .await?;
                let mut ep_guard = EndpointGuard(Some(endpoint));
                let (h3_conn, send_request) = h3::client::builder()
                    .build(h3_quinn::Connection::new(quic_conn))
                    .await
                    .map_err(|e| ProxyError::Transport(format!("H3 session build failed: {e}")))?;
                let endpoint = ep_guard.disarm().expect("endpoint still present");
                Ok::<_, ProxyError>((endpoint, h3_conn, send_request))
            })
            .await
            .map_err(|_| ProxyError::Transport("HTTP/3 QUIC handshake timed out".into()))??;

        let closed = Arc::new(AtomicBool::new(false));
        let cancel = CancellationToken::new();
        let closed_drv = Arc::clone(&closed);
        let cancel_drv = cancel.clone();

        let drv_handle = tokio::spawn(async move {
            tokio::select! {
                _ = cancel_drv.cancelled() => {
                    let _ = h3_conn.shutdown(0).await;
                }
                err = h3_conn.wait_idle() => {
                    tracing::debug!(error = %err, "H3 upstream connection went idle/closed");
                }
            }
            closed_drv.store(true, Ordering::Relaxed);
        });

        Ok(Arc::new(Self {
            server_host,
            server_port,
            user_agent,
            proxy_pass: RwLock::new(proxy_pass),
            send_request: Mutex::new(send_request),
            endpoint,
            closed,
            cancel,
            driver_handle: Mutex::new(Some(drv_handle)),
        }))
    }
}

impl UpstreamSession for H3Session {
    fn open_tcp<'a>(&'a self, target_host: &'a str, target_port: u16) -> SessionFuture<'a, BoxStream> {
        Box::pin(async move {
            if self.is_closed() {
                return Err(ProxyError::Transport("H3 session closed".into()));
            }
            let (eff_host, eff_port) = through_mozilla(target_host, target_port);
            let authority = format_authority(&eff_host, eff_port);
            let pass = self
                .proxy_pass
                .read()
                .map(|g| g.clone())
                .unwrap_or_default();

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
                .map_err(|e| ProxyError::Protocol(format!("build H3 CONNECT request: {e}")))?;

            let mut sender = self.send_request.lock().await;
            let mut req_stream = tokio::time::timeout(CONNECT_TIMEOUT, sender.send_request(req))
                .await
                .map_err(|_| ProxyError::Transport("H3 CONNECT request timed out".into()))?
                .map_err(|e| ProxyError::Transport(format!("H3 CONNECT error: {e}")))?;
            drop(sender);

            let resp = tokio::time::timeout(CONNECT_TIMEOUT, req_stream.recv_response())
                .await
                .map_err(|_| ProxyError::Transport("H3 CONNECT response timed out".into()))?
                .map_err(|e| ProxyError::Transport(format!("H3 CONNECT response error: {e}")))?;

            let status = resp.status();
            if !status.is_success() {
                if matches!(status.as_u16(), 401 | 402 | 407) {
                    return Err(ProxyError::AuthFailed);
                }
                return Err(ProxyError::UpstreamStatus {
                    status: status.as_u16(),
                    message: format!("H3 CONNECT {authority} rejected with {status}"),
                });
            }

            let (mut h3_send, mut h3_recv) = req_stream.split();
            let (client_end, bridge_end) = duplex_bridge(H3_DUPLEX_BUF_SIZE);
            let (mut bridge_r, mut bridge_w) = tokio::io::split(bridge_end);
            let cancel_tx = self.cancel.clone();
            let cancel_rx = self.cancel.clone();

            tokio::spawn(async move {
                let mut buf = vec![0u8; 32 * 1024];
                loop {
                    let read_res = tokio::select! {
                        _ = cancel_tx.cancelled() => break,
                        r = bridge_r.read(&mut buf) => r,
                    };
                    match read_res {
                        Ok(0) | Err(_) => break,
                        Ok(n) => {
                            if h3_send.send_data(Bytes::copy_from_slice(&buf[..n])).await.is_err() {
                                break;
                            }
                        }
                    }
                }
                let _ = h3_send.finish().await;
            });

            tokio::spawn(async move {
                loop {
                    let data_res = tokio::select! {
                        _ = cancel_rx.cancelled() => break,
                        d = h3_recv.recv_data() => d,
                    };
                    match data_res {
                        Ok(Some(mut chunk)) => {
                            let bytes = chunk.copy_to_bytes(chunk.remaining());
                            if bridge_w.write_all(&bytes).await.is_err() {
                                h3_recv.stop_sending(Code::H3_NO_ERROR);
                                break;
                            }
                        }
                        Ok(None) | Err(_) => break,
                    }
                }
                let _ = bridge_w.shutdown().await;
            });

            Ok(Box::new(client_end) as BoxStream)
        })
    }

    fn open_udp<'a>(&'a self, _target_host: &'a str, _target_port: u16) -> SessionFuture<'a, UdpTunnel> {
        Box::pin(async move {
            Err(ProxyError::Transport(
                "UDP uses HTTP/2 CONNECT-UDP auxiliary session".into(),
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
            self.cancel.cancel();
            self.endpoint.close(0u32.into(), b"shutdown");
            if let Some(h) = self.driver_handle.lock().await.take() {
                h.abort();
            }
        })
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::sync::atomic::AtomicUsize;

    use super::*;
    #[cfg(unix)]
    use crate::dialer::{SocketFd, SocketProtector};
    use crate::dialer::UpstreamSocks5;
    use crate::tls::TlsConnector;

    #[cfg(unix)]
    #[derive(Debug, Default)]
    struct CountingProtector {
        calls: AtomicUsize,
    }

    #[cfg(unix)]
    impl SocketProtector for CountingProtector {
        fn protect_fd(&self, _fd: SocketFd) -> std::io::Result<()> {
            self.calls.fetch_add(1, Ordering::Relaxed);
            Ok(())
        }
    }

    fn test_resolver_and_tls() -> (Arc<BootstrapResolver>, RustlsConnector) {
        let rustls = RustlsConnector::new().unwrap();
        let tls_dyn: Arc<dyn TlsConnector> = Arc::new(crate::tls::AdaptiveTlsConnector::new().unwrap());
        let resolver = Arc::new(
            BootstrapResolver::new(
                &[],
                false,
                ProtectedDialer::with_protector(None),
                tls_dyn,
                None::<UpstreamSocks5>,
            )
            .unwrap(),
        );
        (resolver, rustls)
    }

    #[tokio::test]
    async fn h3_handshake_timeout_respects_short_deadline_and_protects_udp_socket() {
        assert_eq!(H3_FALLBACK_HANDSHAKE_TIMEOUT, Duration::from_secs(3));

        let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let blackhole_addr = blackhole.local_addr().unwrap();

        #[cfg(unix)]
        let (protector, dialer) = {
            let p = Arc::new(CountingProtector::default());
            let d = ProtectedDialer::with_protector(Some(p.clone()));
            (p, d)
        };
        #[cfg(not(unix))]
        let dialer = ProtectedDialer::with_protector(None);
        let (resolver, rustls) = test_resolver_and_tls();

        let started = tokio::time::Instant::now();
        let res = H3Session::connect_addrs(
            "test.edge.example".into(),
            blackhole_addr.port(),
            "HeartburnTest/1.0".into(),
            "test-pass".into(),
            resolver,
            dialer,
            rustls,
            &[blackhole_addr],
            Duration::from_millis(250),
        )
        .await;
        let elapsed = started.elapsed();

        let err = res.expect_err("blackholed UDP peer must time out");
        assert!(
            err.to_string().contains("timed out"),
            "expected timeout error, got: {err}"
        );
        assert!(
            elapsed < Duration::from_secs(2),
            "H3 short handshake timeout took too long: {elapsed:?}"
        );
        #[cfg(unix)]
        assert!(
            protector.calls.load(Ordering::Relaxed) >= 1,
            "SocketProtector must be invoked on QUIC UDP bind"
        );
    }

    #[cfg(feature = "firefox-tls")]
    #[tokio::test]
    async fn h3_connect_addrs_fails_over_past_blackholed_candidate_and_tunnels_tcp() {
        use boring2::asn1::Asn1Time;
        use boring2::bn::{BigNum, MsbOption};
        use boring2::hash::MessageDigest;
        use boring2::pkey::PKey;
        use boring2::rsa::Rsa;
        use boring2::x509::extension::{
            AuthorityKeyIdentifier, BasicConstraints, KeyUsage, SubjectAlternativeName,
            SubjectKeyIdentifier,
        };
        use boring2::x509::{X509, X509NameBuilder, X509Ref};
        use rustls::RootCertStore;
        use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};

        let ca_rsa = Rsa::generate(2048).unwrap();
        let ca_key = PKey::from_rsa(ca_rsa).unwrap();
        let mut ca_name = X509NameBuilder::new().unwrap();
        ca_name.append_entry_by_text("CN", "Heartburn H3 Test CA").unwrap();
        let ca_name = ca_name.build();

        let mut ca_builder = X509::builder().unwrap();
        ca_builder.set_version(2).unwrap();
        let mut ca_serial = BigNum::new().unwrap();
        ca_serial.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
        ca_builder
            .set_serial_number(&ca_serial.to_asn1_integer().unwrap())
            .unwrap();
        ca_builder.set_subject_name(&ca_name).unwrap();
        ca_builder.set_issuer_name(&ca_name).unwrap();
        ca_builder.set_pubkey(&ca_key).unwrap();
        let not_before = Asn1Time::days_from_now(0).unwrap();
        let not_after = Asn1Time::days_from_now(365).unwrap();
        ca_builder.set_not_before(&not_before).unwrap();
        ca_builder.set_not_after(&not_after).unwrap();
        ca_builder
            .append_extension(BasicConstraints::new().critical().ca().build().unwrap())
            .unwrap();
        ca_builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .key_cert_sign()
                    .crl_sign()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        let ca_ski = SubjectKeyIdentifier::new()
            .build(&ca_builder.x509v3_context(None, None))
            .unwrap();
        ca_builder.append_extension(ca_ski).unwrap();
        ca_builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
        let ca_cert = ca_builder.build();

        let leaf_rsa = Rsa::generate(2048).unwrap();
        let leaf_key = PKey::from_rsa(leaf_rsa).unwrap();
        let mut leaf_name = X509NameBuilder::new().unwrap();
        leaf_name.append_entry_by_text("CN", "test.edge.example").unwrap();
        let leaf_name = leaf_name.build();

        let mut leaf_builder = X509::builder().unwrap();
        leaf_builder.set_version(2).unwrap();
        let mut leaf_serial = BigNum::new().unwrap();
        leaf_serial.rand(159, MsbOption::MAYBE_ZERO, false).unwrap();
        leaf_builder
            .set_serial_number(&leaf_serial.to_asn1_integer().unwrap())
            .unwrap();
        leaf_builder.set_subject_name(&leaf_name).unwrap();
        leaf_builder.set_issuer_name(ca_cert.subject_name()).unwrap();
        leaf_builder.set_pubkey(&leaf_key).unwrap();
        leaf_builder.set_not_before(&not_before).unwrap();
        leaf_builder.set_not_after(&not_after).unwrap();
        leaf_builder
            .append_extension(BasicConstraints::new().build().unwrap())
            .unwrap();
        leaf_builder
            .append_extension(
                KeyUsage::new()
                    .critical()
                    .digital_signature()
                    .key_encipherment()
                    .build()
                    .unwrap(),
            )
            .unwrap();
        let ctx_ref: Option<&X509Ref> = Some(&ca_cert);
        let leaf_ski = SubjectKeyIdentifier::new()
            .build(&leaf_builder.x509v3_context(ctx_ref, None))
            .unwrap();
        leaf_builder.append_extension(leaf_ski).unwrap();
        let leaf_aki = AuthorityKeyIdentifier::new()
            .keyid(false)
            .issuer(false)
            .build(&leaf_builder.x509v3_context(ctx_ref, None))
            .unwrap();
        leaf_builder.append_extension(leaf_aki).unwrap();
        let san = SubjectAlternativeName::new()
            .dns("test.edge.example")
            .build(&leaf_builder.x509v3_context(ctx_ref, None))
            .unwrap();
        leaf_builder.append_extension(san).unwrap();
        leaf_builder.sign(&ca_key, MessageDigest::sha256()).unwrap();
        let leaf_cert = leaf_builder.build();

        let mut roots = RootCertStore::empty();
        let (added, _) = roots.add_parsable_certificates([CertificateDer::from(ca_cert.to_der().unwrap())]);
        assert_eq!(added, 1);

        let mut tls_server_cfg = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![CertificateDer::from(leaf_cert.to_der().unwrap())],
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(
                leaf_key.private_key_to_der_pkcs8().unwrap(),
            )),
        )
        .unwrap();
        tls_server_cfg.alpn_protocols = vec![b"h3".to_vec()];
        let quic_server_cfg =
            quinn::crypto::rustls::QuicServerConfig::try_from(tls_server_cfg).unwrap();
        let server_ep = quinn::Endpoint::server(
            quinn::ServerConfig::with_crypto(Arc::new(quic_server_cfg)),
            SocketAddr::from(([127, 0, 0, 1], 0)),
        )
        .unwrap();
        let live_addr = server_ep.local_addr().unwrap();

        let server_task = tokio::spawn(async move {
            let Some(incoming) = server_ep.accept().await else {
                return;
            };
            let quic_conn = incoming.await.unwrap();
            let mut h3_conn = h3::server::builder()
                .build(h3_quinn::Connection::new(quic_conn))
                .await
                .unwrap();
            if let Ok(Some(resolver)) = h3_conn.accept().await {
                let (req, mut stream) = resolver.resolve_request().await.unwrap();
                assert_eq!(req.method(), Method::CONNECT);
                assert_eq!(
                    req.headers()
                        .get(http::header::PROXY_AUTHORIZATION)
                        .and_then(|v| v.to_str().ok()),
                    Some("Bearer test-pass")
                );
                let resp = http::Response::builder()
                    .status(http::StatusCode::OK)
                    .body(())
                    .unwrap();
                stream.send_response(resp).await.unwrap();
                while let Ok(Some(mut chunk)) = stream.recv_data().await {
                    let data = chunk.copy_to_bytes(chunk.remaining());
                    if stream.send_data(data).await.is_err() {
                        break;
                    }
                }
                let _ = stream.finish().await;
            }
            server_ep.close(0u32.into(), b"done");
        });

        let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let blackhole_addr = blackhole.local_addr().unwrap();

        let (resolver, _) = test_resolver_and_tls();
        let rustls = RustlsConnector::with_roots(Arc::new(roots));
        let dialer = ProtectedDialer::with_protector(None);

        let started = tokio::time::Instant::now();
        let sess = H3Session::connect_addrs(
            "test.edge.example".into(),
            live_addr.port(),
            "HeartburnTest/1.0".into(),
            "test-pass".into(),
            resolver,
            dialer,
            rustls,
            &[blackhole_addr, live_addr],
            H3_FALLBACK_HANDSHAKE_TIMEOUT,
        )
        .await
        .unwrap();
        let elapsed = started.elapsed();
        assert!(
            elapsed < Duration::from_secs(2),
            "expected fast stagger failover to live H3 peer, took {elapsed:?}"
        );

        let mut stream = sess.open_tcp("example.com", 443).await.unwrap();
        stream.write_all(b"ping-h3").await.unwrap();
        stream.flush().await.unwrap();
        let mut echoed = [0u8; 7];
        stream.read_exact(&mut echoed).await.unwrap();
        assert_eq!(&echoed, b"ping-h3");

        drop(stream);
        sess.close().await;
        assert!(sess.is_closed());
        let _ = server_task.await;
    }
}
