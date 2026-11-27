//! Bootstrap DNS/DoH/DoT + ECH (`HTTPS` record) resolver and Happy Eyeballs dialer.
//!
//! Used exclusively for `heartburn`'s own control-plane and Fastly edge lookups.
//! Client traffic DNS is intentionally NOT intercepted here (`sing-box` handles it externally).

use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Method;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use url::Url;

use crate::config::IpVersionMode;
use crate::dialer::{ProtectedDialer, UpstreamSocks5};
use crate::error::{DialError, DnsError};
use crate::tls::{TlsConfig, TlsConnector};

const MIN_CACHE_TTL: Duration = Duration::from_secs(30);
const MAX_CACHE_TTL: Duration = Duration::from_secs(600);
const DNS_QUERY_TIMEOUT: Duration = Duration::from_secs(4);
const SYSTEM_FALLBACK_DELAY: Duration = Duration::from_secs(1);
pub(crate) const HAPPY_EYEBALLS_STAGGER: Duration = Duration::from_millis(300);
const FAILED_ADDR_PENALTY: Duration = Duration::from_secs(600);

/// DNS record types encoded by the bootstrap wire codec.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u16)]
pub enum RecordType {
    A = 1,
    Aaaa = 28,
    Https = 65,
}

/// Decoded DNS answer records and minimum TTL.
#[derive(Debug, Clone)]
pub struct DnsAnswer {
    pub ips: Vec<IpAddr>,
    pub ech_configs: Vec<Vec<u8>>,
    pub ttl: Duration,
}

#[derive(Debug, Clone)]
struct CacheEntry {
    answer: DnsAnswer,
    expires_at: Instant,
}

/// Configured bootstrap DNS upstream endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DnsServer {
    Doh { url: String, host: String, port: u16, path_and_query: String },
    Dot { host: String, port: u16 },
    Plain(SocketAddr),
}

impl DnsServer {
    /// Parses `"https://..."`, `"tls://host[:port]"`, or `"IP[:port]"`.
    pub fn parse(raw: &str) -> Result<Self, DnsError> {
        let s = raw.trim();
        if s.starts_with("https://") {
            let url = Url::parse(s).map_err(|e| DnsError::InvalidServer(s.into(), e.to_string()))?;
            let host = url
                .host_str()
                .filter(|h| !h.is_empty())
                .ok_or_else(|| DnsError::InvalidServer(s.into(), "missing host".into()))?
                .trim_matches(['[', ']'])
                .to_owned();
            let port = url.port_or_known_default().unwrap_or(443);
            let mut pq = url.path().to_owned();
            if pq.is_empty() {
                pq = "/dns-query".to_owned();
            }
            if let Some(q) = url.query() {
                pq.push('?');
                pq.push_str(q);
            }
            Ok(Self::Doh {
                url: s.to_owned(),
                host,
                port,
                path_and_query: pq,
            })
        } else if let Some(rest) = s.strip_prefix("tls://") {
            let (host, port) = if let Some((h, p)) = crate::config::split_host_port(rest) {
                (h.to_owned(), p)
            } else {
                (rest.trim_matches(['[', ']']).to_owned(), 853)
            };
            if host.is_empty() {
                return Err(DnsError::InvalidServer(s.into(), "missing DoT host".into()));
            }
            Ok(Self::Dot { host, port })
        } else if let Ok(ip) = s.parse::<IpAddr>() {
            Ok(Self::Plain(SocketAddr::new(ip, 53)))
        } else if let Ok(sa) = s.parse::<SocketAddr>() {
            Ok(Self::Plain(sa))
        } else {
            Err(DnsError::InvalidServer(
                s.into(),
                "expected https://, tls://, or IP[:port]".into(),
            ))
        }
    }
}

/// Returns `true` for known censorship sinkholes or non-public block-page IPs.
pub fn is_block_page_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_unspecified()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.octets()[0] == 10 && v4.octets()[1] == 10
        }
        IpAddr::V6(v6) => {
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() {
                return true;
            }
            let segs = v6.segments();
            // Unique local fc00::/7 or link-local fe80::/10
            if (segs[0] & 0xfe00) == 0xfc00 || (segs[0] & 0xffc0) == 0xfe80 {
                return true;
            }
            // Known Iranian ISP DPI block-page prefix: 2001:4188:2:600:10:10:34:0/112
            segs[0] == 0x2001
                && segs[1] == 0x4188
                && segs[2] == 0x0002
                && segs[3] == 0x0600
                && segs[4] == 0x0010
                && segs[5] == 0x0010
                && segs[6] == 0x0034
        }
    }
}

/// Bootstrap DNS/DoH/DoT/ECH resolver and Happy Eyeballs dialer.
#[derive(Clone)]
pub struct BootstrapResolver {
    servers: Vec<DnsServer>,
    fallback_to_system: bool,
    dialer: ProtectedDialer,
    tls: Arc<dyn TlsConnector>,
    upstream_proxy: Option<UpstreamSocks5>,
    cache: Arc<RwLock<HashMap<(String, RecordType), CacheEntry>>>,
    failed_addrs: Arc<Mutex<HashMap<SocketAddr, Instant>>>,
}

impl std::fmt::Debug for BootstrapResolver {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BootstrapResolver")
            .field("servers", &self.servers.len())
            .field("fallback_to_system", &self.fallback_to_system)
            .finish()
    }
}

impl BootstrapResolver {
    /// Constructs a new resolver from config server strings.
    pub fn new(
        server_strs: &[String],
        fallback_to_system: bool,
        dialer: ProtectedDialer,
        tls: Arc<dyn TlsConnector>,
        upstream_proxy: Option<UpstreamSocks5>,
    ) -> Result<Self, DnsError> {
        let servers = server_strs
            .iter()
            .map(|s| DnsServer::parse(s))
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self {
            servers,
            fallback_to_system,
            dialer,
            tls,
            upstream_proxy,
            cache: Arc::new(RwLock::new(HashMap::new())),
            failed_addrs: Arc::new(Mutex::new(HashMap::new())),
        })
    }

    /// Resolves `host` into deduplicated public IP addresses using DoH/DoT/plain servers
    /// in parallel, falling back to system DNS after 1s if configured.
    pub async fn lookup_ip(&self, host: &str) -> Result<Vec<IpAddr>, DnsError> {
        Box::pin(async move {
            let host = host.trim().trim_end_matches('.');
            if host.is_empty() {
                return Err(DnsError::InvalidName(host.to_owned()));
            }
            if let Ok(ip) = host.parse::<IpAddr>() {
                return Ok(vec![ip]);
            }

            let name = host.to_ascii_lowercase();
            let (res_v4, res_v6) = tokio::join!(
                Box::pin(self.lookup_record_with_fallback(&name, RecordType::A)),
                Box::pin(self.lookup_record_with_fallback(&name, RecordType::Aaaa))
            );

            let mut ips = Vec::new();
            if let Ok(a) = &res_v4 {
                for ip in &a.ips {
                    if !is_block_page_ip(*ip) && !ips.contains(ip) {
                        ips.push(*ip);
                    }
                }
            }
            if let Ok(aaaa) = &res_v6 {
                for ip in &aaaa.ips {
                    if !is_block_page_ip(*ip) && !ips.contains(ip) {
                        ips.push(*ip);
                    }
                }
            }

            if ips.is_empty() {
                let e1 = res_v4.err().map(|e| e.to_string()).unwrap_or_default();
                let e2 = res_v6.err().map(|e| e.to_string()).unwrap_or_default();
                return Err(DnsError::AllFailed(format!("{name}: v4=[{e1}] v6=[{e2}]")));
            }
            Ok(ips)
        })
        .await
    }

    /// Looks up TLS ECHConfigList payloads advertised via `HTTPS` (type 65) DNS records.
    pub async fn lookup_ech(&self, host: &str) -> Result<Vec<Vec<u8>>, DnsError> {
        Box::pin(async move {
            let name = host.trim().trim_end_matches('.').to_ascii_lowercase();
            if name.is_empty() {
                return Err(DnsError::InvalidName(host.to_owned()));
            }
            let ans = self.lookup_record(&name, RecordType::Https).await?;
            Ok(ans.ech_configs)
        })
        .await
    }

    /// Clears cached DNS and Happy Eyeballs penalty state (e.g., on network change).
    pub fn reset_cache(&self) {
        if let Ok(mut c) = self.cache.write() {
            c.clear();
        }
        if let Ok(mut f) = self.failed_addrs.lock() {
            f.clear();
        }
    }

    /// Records a dial failure so subsequent Happy Eyeballs attempts deprioritize `addr` for 10m.
    pub fn record_dial_failure(&self, addr: SocketAddr) {
        if let Ok(mut map) = self.failed_addrs.lock() {
            map.insert(addr, Instant::now() + FAILED_ADDR_PENALTY);
        }
    }

    /// Clears penalty status when a dial succeeds.
    pub fn record_dial_success(&self, addr: SocketAddr) {
        if let Ok(mut map) = self.failed_addrs.lock() {
            map.remove(&addr);
        }
    }

    /// Orders candidate IPs according to `mode` and deprioritizes recently penalized addresses.
    pub fn order_addrs(&self, ips: &[IpAddr], port: u16, mode: IpVersionMode) -> Vec<SocketAddr> {
        let v4: Vec<SocketAddr> = ips
            .iter()
            .filter(|ip| ip.is_ipv4())
            .map(|&ip| SocketAddr::new(ip, port))
            .collect();
        let v6: Vec<SocketAddr> = ips
            .iter()
            .filter(|ip| ip.is_ipv6())
            .map(|&ip| SocketAddr::new(ip, port))
            .collect();

        let mut ordered = match mode {
            IpVersionMode::Ipv4 => v4,
            IpVersionMode::Ipv6 => v6,
            IpVersionMode::Auto => {
                let mut out = v4;
                out.extend(v6);
                out
            }
            IpVersionMode::Ipv6First => {
                let mut out = v6;
                out.extend(v4);
                out
            }
            IpVersionMode::Dual => interleave(&v4, &v6),
        };

        let now = Instant::now();
        if let Ok(mut map) = self.failed_addrs.lock() {
            map.retain(|_, exp| *exp > now);
            let penalized: HashSet<SocketAddr> = map.keys().copied().collect();
            let mut healthy = Vec::with_capacity(ordered.len());
            let mut bad = Vec::new();
            for addr in ordered {
                if penalized.contains(&addr) {
                    bad.push(addr);
                } else {
                    healthy.push(addr);
                }
            }
            healthy.extend(bad);
            ordered = healthy;
        }

        ordered
    }

    /// Dials `host:port` honoring `upstream_proxy` (delegating remote resolution via
    /// SOCKS5 ATYP 0x03) or racing resolved IPs via Happy Eyeballs (`300ms` stagger).
    pub async fn dial_tcp(
        &self,
        host: &str,
        port: u16,
        mode: IpVersionMode,
        timeout: Duration,
    ) -> Result<(TcpStream, SocketAddr), DialError> {
        self.dial_tcp_pinned(host, port, mode, timeout, None).await
    }

    /// Dials `host:port`, optionally dialing `pinned_peer` directly so multi-request
    /// sessions (such as Fastly challenges) never switch between IPv4/IPv6 or CDN edge IPs.
    pub async fn dial_tcp_pinned(
        &self,
        host: &str,
        port: u16,
        mode: IpVersionMode,
        timeout: Duration,
        pinned_peer: Option<SocketAddr>,
    ) -> Result<(TcpStream, SocketAddr), DialError> {
        Box::pin(async move {
            if let Some(ref upstream) = self.upstream_proxy {
                let (proxy_host, proxy_port) = crate::config::split_host_port(&upstream.addr)
                    .ok_or_else(|| DialError::InvalidAddress(upstream.addr.clone(), "expected host:port".into()))?;
                let proxy_ips = self.resolve_literal_or_dns(proxy_host).await?;
                let proxy_addr = *proxy_ips
                    .first()
                    .ok_or_else(|| DialError::NoAddresses(upstream.addr.clone()))?;
                let proxy_sock = SocketAddr::new(proxy_addr, proxy_port);
                let stream = self
                    .dialer
                    .connect_via_socks5(upstream, proxy_sock, host, port, timeout)
                    .await?;
                return Ok((stream, proxy_sock));
            }

            if let Some(peer) = pinned_peer {
                let stream = self.dialer.connect_tcp(peer, timeout).await?;
                self.record_dial_success(peer);
                return Ok((stream, peer));
            }

            let ips = self.lookup_ip(host).await?;
            let addrs = self.order_addrs(&ips, port, mode);
            if addrs.is_empty() {
                return Err(DialError::NoAddresses(format!("{host}:{port}")));
            }

            self.race_tcp_addrs(&addrs, timeout).await
        })
        .await
    }

    async fn resolve_literal_or_dns(&self, host: &str) -> Result<Vec<IpAddr>, DialError> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return Ok(vec![ip]);
        }
        Ok(self.lookup_ip(host).await?)
    }

    async fn race_tcp_addrs(
        &self,
        addrs: &[SocketAddr],
        total_timeout: Duration,
    ) -> Result<(TcpStream, SocketAddr), DialError> {
        Box::pin(async move {
            tokio::time::timeout(total_timeout, self.race_tcp_addrs_inner(addrs, total_timeout))
                .await
                .map_err(|_| DialError::Timeout)?
        })
        .await
    }

    async fn race_tcp_addrs_inner(
        &self,
        addrs: &[SocketAddr],
        attempt_timeout: Duration,
    ) -> Result<(TcpStream, SocketAddr), DialError> {
        Box::pin(async move {
            type AttemptFut<'a> =
                Pin<Box<dyn Future<Output = (SocketAddr, Result<TcpStream, DialError>)> + Send + 'a>>;

            let mut pending: futures::stream::FuturesUnordered<AttemptFut<'_>> =
                futures::stream::FuturesUnordered::new();

            let dialer = self.dialer.clone();
            let mut iter = addrs.iter().copied().enumerate();

            if let Some((_, first)) = iter.next() {
                let d = dialer.clone();
                pending.push(Box::pin(async move {
                    (first, d.connect_tcp(first, attempt_timeout).await)
                }));
            }

            let stagger = tokio::time::sleep(HAPPY_EYEBALLS_STAGGER);
            tokio::pin!(stagger);
            let mut more_to_launch = true;
            let mut last_err: Option<DialError> = None;

            use futures::StreamExt;
            loop {
                tokio::select! {
                    _ = &mut stagger, if more_to_launch => {
                        if let Some((_, next_addr)) = iter.next() {
                            let d = dialer.clone();
                            pending.push(Box::pin(async move {
                                (next_addr, d.connect_tcp(next_addr, attempt_timeout).await)
                            }));
                            stagger.as_mut().reset(tokio::time::Instant::now() + HAPPY_EYEBALLS_STAGGER);
                        } else {
                            more_to_launch = false;
                        }
                    }
                    res = pending.next() => {
                        match res {
                            Some((addr, Ok(stream))) => {
                                self.record_dial_success(addr);
                                return Ok((stream, addr));
                            }
                            Some((addr, Err(err))) => {
                                self.record_dial_failure(addr);
                                last_err = Some(err);
                                if more_to_launch {
                                    if let Some((_, next_addr)) = iter.next() {
                                        let d = dialer.clone();
                                        pending.push(Box::pin(async move {
                                            (next_addr, d.connect_tcp(next_addr, attempt_timeout).await)
                                        }));
                                        stagger.as_mut().reset(tokio::time::Instant::now() + HAPPY_EYEBALLS_STAGGER);
                                    } else {
                                        more_to_launch = false;
                                    }
                                }
                            }
                            None => {
                                if !more_to_launch {
                                    return Err(last_err.unwrap_or(DialError::NoAddresses("empty target list".into())));
                                }
                            }
                        }
                    }
                }
            }
        })
        .await
    }

    async fn lookup_record_with_fallback(
        &self,
        name: &str,
        rtype: RecordType,
    ) -> Result<DnsAnswer, DnsError> {
        Box::pin(async move {
            if self.servers.is_empty() {
                if self.fallback_to_system {
                    return system_lookup(name, rtype).await;
                }
                return Err(DnsError::AllFailed("no DNS servers configured".into()));
            }

            if !self.fallback_to_system || rtype == RecordType::Https {
                return self.lookup_record(name, rtype).await;
            }

            // Race custom bootstrap DNS against 1s-delayed system fallback matching Go's resolver.
            let mut custom = Box::pin(self.lookup_record(name, rtype));
            let fallback_timer = tokio::time::sleep(SYSTEM_FALLBACK_DELAY);
            tokio::pin!(fallback_timer);

            tokio::select! {
                res = &mut custom => {
                    if res.is_ok() {
                        return res;
                    }
                    match system_lookup(name, rtype).await {
                        Ok(sys) => Ok(sys),
                        Err(_) => res,
                    }
                }
                _ = &mut fallback_timer => {
                    let mut sys = Box::pin(system_lookup(name, rtype));
                    tokio::select! {
                        res = &mut custom => match res {
                            Ok(ans) => Ok(ans),
                            Err(e) => match sys.await {
                                Ok(ans) => Ok(ans),
                                Err(_) => Err(e),
                            }
                        },
                        res = &mut sys => match res {
                            Ok(ans) => Ok(ans),
                            Err(_) => custom.await,
                        }
                    }
                }
            }
        })
        .await
    }

    async fn lookup_record(&self, name: &str, rtype: RecordType) -> Result<DnsAnswer, DnsError> {
        Box::pin(async move {
            if let Ok(cache) = self.cache.read()
                && let Some(entry) = cache.get(&(name.to_owned(), rtype))
                && entry.expires_at > Instant::now()
            {
                return Ok(entry.answer.clone());
            }

            let query = encode_dns_query(name, rtype)?;
            let mut futs = futures::stream::FuturesUnordered::new();
            for server in &self.servers {
                let srv = server.clone();
                let q = query.clone();
                futs.push(Box::pin(async move {
                    tokio::time::timeout(DNS_QUERY_TIMEOUT, self.query_single_server(&srv, &q))
                        .await
                        .map_err(|_| DnsError::Timeout)?
                }));
            }

            use futures::StreamExt;
            let mut errs = Vec::new();
            while let Some(res) = futs.next().await {
                match res {
                    Ok(raw) => match decode_dns_response(&raw, rtype) {
                        Ok(ans) if !ans.ips.is_empty() || !ans.ech_configs.is_empty() => {
                            let ttl = ans.ttl.clamp(MIN_CACHE_TTL, MAX_CACHE_TTL);
                            if let Ok(mut cache) = self.cache.write() {
                                cache.insert(
                                    (name.to_owned(), rtype),
                                    CacheEntry {
                                        answer: ans.clone(),
                                        expires_at: Instant::now() + ttl,
                                    },
                                );
                            }
                            return Ok(ans);
                        }
                        Ok(_) => errs.push("empty answer".to_owned()),
                        Err(e) => errs.push(e.to_string()),
                    },
                    Err(e) => errs.push(e.to_string()),
                }
            }

            Err(DnsError::AllFailed(errs.join("; ")))
        })
        .await
    }

    async fn query_single_server(&self, server: &DnsServer, wire_query: &[u8]) -> Result<Vec<u8>, DnsError> {
        Box::pin(async move {
            match server {
                DnsServer::Plain(addr) => self.query_plain(*addr, wire_query).await,
                DnsServer::Dot { host, port } => self.query_dot(host, *port, wire_query).await,
                DnsServer::Doh {
                    host,
                    port,
                    path_and_query,
                    ..
                } => self.query_doh(host, *port, path_and_query, wire_query).await,
            }
        })
        .await
    }

    async fn query_plain(&self, addr: SocketAddr, wire_query: &[u8]) -> Result<Vec<u8>, DnsError> {
        Box::pin(async move {
            let udp = self
                .dialer
                .connect_udp(addr)
                .await
                .map_err(|e| DnsError::AllFailed(e.to_string()))?;
            udp.send(wire_query).await?;
            let mut buf = vec![0u8; 4096];
            let n = udp.recv(&mut buf).await?;
            buf.truncate(n);

            // Retry over TCP if TC (truncated) bit is set in DNS header flags.
            if buf.len() >= 4 && (buf[2] & 0x02) != 0 {
                let mut tcp = self
                    .dialer
                    .connect_tcp(addr, DNS_QUERY_TIMEOUT)
                    .await
                    .map_err(|e| DnsError::AllFailed(e.to_string()))?;
                return exchange_tcp_dns(&mut tcp, wire_query).await;
            }
            Ok(buf)
        })
        .await
    }

    async fn query_dot(&self, host: &str, port: u16, wire_query: &[u8]) -> Result<Vec<u8>, DnsError> {
        Box::pin(async move {
            let tcp = self.connect_dns_host_tcp(host, port).await?;
            let cfg = TlsConfig {
                server_name: host.to_owned(),
                alpn: vec![b"dot".to_vec()],
                ..Default::default()
            };
            let mut tls_stream = self
                .tls
                .connect(Box::new(tcp), &cfg)
                .await
                .map_err(|e| DnsError::AllFailed(e.to_string()))?;
            exchange_tcp_dns(&mut tls_stream, wire_query).await
        })
        .await
    }

    async fn query_doh(
        &self,
        host: &str,
        port: u16,
        path_and_query: &str,
        wire_query: &[u8],
    ) -> Result<Vec<u8>, DnsError> {
        Box::pin(async move {
            let tcp = self.connect_dns_host_tcp(host, port).await?;
            let cfg = TlsConfig {
                server_name: host.to_owned(),
                alpn: vec![b"http/1.1".to_vec()],
                ..Default::default()
            };
            let tls_stream = self
                .tls
                .connect(Box::new(tcp), &cfg)
                .await
                .map_err(|e| DnsError::AllFailed(e.to_string()))?;

            let (mut sender, conn) =
                hyper::client::conn::http1::handshake(TokioIo::new(tls_stream))
                    .await
                    .map_err(|e| DnsError::AllFailed(format!("DoH handshake failed: {e}")))?;

            let driver = tokio::spawn(async move {
                let _ = conn.await;
            });

            let authority = if port == 443 {
                host.to_owned()
            } else {
                format!("{host}:{port}")
            };
            let req = hyper::Request::builder()
                .method(Method::POST)
                .uri(path_and_query)
                .header(hyper::header::HOST, authority)
                .header(hyper::header::CONTENT_TYPE, "application/dns-message")
                .header(hyper::header::ACCEPT, "application/dns-message")
                .body(Full::new(Bytes::copy_from_slice(wire_query)))
                .map_err(|e| DnsError::AllFailed(e.to_string()))?;

            let resp = sender
                .send_request(req)
                .await
                .map_err(|e| DnsError::AllFailed(format!("DoH request failed: {e}")))?;

            if !resp.status().is_success() {
                driver.abort();
                return Err(DnsError::AllFailed(format!(
                    "DoH server returned HTTP {}",
                    resp.status()
                )));
            }
            let body = resp
                .into_body()
                .collect()
                .await
                .map_err(|e| DnsError::AllFailed(e.to_string()))?
                .to_bytes()
                .to_vec();
            driver.abort();
            Ok(body)
        })
        .await
    }

    async fn connect_dns_host_tcp(&self, host: &str, port: u16) -> Result<TcpStream, DnsError> {
        Box::pin(async move {
            if let Ok(ip) = host.parse::<IpAddr>() {
                return self
                    .dialer
                    .connect_tcp(SocketAddr::new(ip, port), DNS_QUERY_TIMEOUT)
                    .await
                    .map_err(|e| DnsError::AllFailed(e.to_string()));
            }
            let mut addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, port))
                .await?
                .collect();
            if addrs.is_empty() {
                return Err(DnsError::AllFailed(format!("system DNS returned no address for {host}")));
            }
            // Prefer IPv4 first on DNS host bootstrap unless none exist.
            addrs.sort_by_key(|a| a.is_ipv6());
            let (stream, _) = self
                .race_tcp_addrs(&addrs, DNS_QUERY_TIMEOUT)
                .await
                .map_err(|e| DnsError::AllFailed(e.to_string()))?;
            Ok(stream)
        })
        .await
    }
}

async fn exchange_tcp_dns<S: AsyncReadExt + AsyncWriteExt + Unpin>(
    stream: &mut S,
    wire_query: &[u8],
) -> Result<Vec<u8>, DnsError> {
    let len = u16::try_from(wire_query.len())
        .map_err(|_| DnsError::Wire("DNS query exceeds u16 length".into()))?;
    stream.write_all(&len.to_be_bytes()).await?;
    stream.write_all(wire_query).await?;
    stream.flush().await?;

    let mut len_buf = [0u8; 2];
    stream.read_exact(&mut len_buf).await?;
    let resp_len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; resp_len];
    stream.read_exact(&mut resp).await?;
    Ok(resp)
}

async fn system_lookup(name: &str, rtype: RecordType) -> Result<DnsAnswer, DnsError> {
    Box::pin(async move {
        let want_v6 = matches!(rtype, RecordType::Aaaa);
        let mut ips = Vec::new();
        for addr in tokio::net::lookup_host((name, 0)).await? {
            let ip = addr.ip();
            if ip.is_ipv6() == want_v6 && !is_block_page_ip(ip) && !ips.contains(&ip) {
                ips.push(ip);
            }
        }
        if ips.is_empty() {
            return Err(DnsError::AllFailed(format!(
                "system DNS found no usable addresses for {name}"
            )));
        }
        Ok(DnsAnswer {
            ips,
            ech_configs: Vec::new(),
            ttl: Duration::from_secs(60),
        })
    })
    .await
}

fn interleave(a: &[SocketAddr], b: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut out = Vec::with_capacity(a.len() + b.len());
    let max_len = a.len().max(b.len());
    for i in 0..max_len {
        if let Some(&x) = a.get(i) {
            out.push(x);
        }
        if let Some(&y) = b.get(i) {
            out.push(y);
        }
    }
    out
}

/// Encodes a standard RFC 1035 DNS wire query (`RD=1`, EDNS0 4096 bytes for large HTTPS/ECH answers).
pub fn encode_dns_query(name: &str, rtype: RecordType) -> Result<Vec<u8>, DnsError> {
    let trimmed = name.trim().trim_end_matches('.');
    if trimmed.is_empty() || trimmed.len() > 253 {
        return Err(DnsError::InvalidName(name.to_owned()));
    }

    let mut pkt = Vec::with_capacity(64 + trimmed.len());
    // Header: ID=0 (recommended by RFC 8484 for cacheability), Flags=0x0100 (RD=1),
    // QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=1 (EDNS0 OPT).
    pkt.extend_from_slice(&[0x00, 0x00, 0x01, 0x00]);
    pkt.extend_from_slice(&1u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes());

    for label in trimmed.split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(DnsError::InvalidName(name.to_owned()));
        }
        pkt.push(label.len() as u8);
        pkt.extend_from_slice(label.as_bytes());
    }
    pkt.push(0); // Root label
    pkt.extend_from_slice(&(rtype as u16).to_be_bytes());
    pkt.extend_from_slice(&1u16.to_be_bytes()); // QCLASS = IN

    // EDNS0 OPT pseudo-RR (RFC 6891): NAME=0, TYPE=41, CLASS=4096, TTL=0, RDLEN=0
    pkt.push(0);
    pkt.extend_from_slice(&41u16.to_be_bytes());
    pkt.extend_from_slice(&4096u16.to_be_bytes());
    pkt.extend_from_slice(&0u32.to_be_bytes());
    pkt.extend_from_slice(&0u16.to_be_bytes());
    Ok(pkt)
}

/// Decodes a wire DNS response extracting `A`, `AAAA`, and `HTTPS` (`ECH`) records.
pub fn decode_dns_response(pkt: &[u8], wanted: RecordType) -> Result<DnsAnswer, DnsError> {
    if pkt.len() < 12 {
        return Err(DnsError::Wire("DNS response shorter than 12 bytes".into()));
    }
    let flags = u16::from_be_bytes([pkt[2], pkt[3]]);
    let rcode = flags & 0x000f;
    if rcode != 0 {
        return Err(DnsError::Wire(format!("DNS server returned RCODE {rcode}")));
    }

    let qdcount = u16::from_be_bytes([pkt[4], pkt[5]]) as usize;
    let ancount = u16::from_be_bytes([pkt[6], pkt[7]]) as usize;

    let mut pos = 12usize;
    for _ in 0..qdcount {
        pos = skip_dns_name(pkt, pos)?;
        if pos + 4 > pkt.len() {
            return Err(DnsError::Wire("truncated question section".into()));
        }
        pos += 4;
    }

    let mut ips = Vec::new();
    let mut ech_configs = Vec::new();
    let mut min_ttl_secs: Option<u32> = None;

    for _ in 0..ancount {
        pos = skip_dns_name(pkt, pos)?;
        if pos + 10 > pkt.len() {
            return Err(DnsError::Wire("truncated answer RR header".into()));
        }
        let rr_type = u16::from_be_bytes([pkt[pos], pkt[pos + 1]]);
        let rr_class = u16::from_be_bytes([pkt[pos + 2], pkt[pos + 3]]);
        let ttl = u32::from_be_bytes([pkt[pos + 4], pkt[pos + 5], pkt[pos + 6], pkt[pos + 7]]);
        let rdlen = u16::from_be_bytes([pkt[pos + 8], pkt[pos + 9]]) as usize;
        pos += 10;
        if pos + rdlen > pkt.len() {
            return Err(DnsError::Wire("truncated answer RDATA".into()));
        }
        let rdata = &pkt[pos..pos + rdlen];
        pos += rdlen;

        if rr_class != 1 {
            continue;
        }
        if rr_type == wanted as u16 {
            min_ttl_secs = Some(min_ttl_secs.map_or(ttl, |cur| cur.min(ttl)));
        }

        match rr_type {
            1 if rdata.len() == 4 => {
                let ip = IpAddr::V4(Ipv4Addr::new(rdata[0], rdata[1], rdata[2], rdata[3]));
                ips.push(ip);
            }
            28 if rdata.len() == 16 => {
                let mut octets = [0u8; 16];
                octets.copy_from_slice(rdata);
                ips.push(IpAddr::V6(Ipv6Addr::from(octets)));
            }
            65 => {
                parse_https_ech_params(rdata, &mut ech_configs);
            }
            _ => {}
        }
    }

    Ok(DnsAnswer {
        ips,
        ech_configs,
        ttl: Duration::from_secs(u64::from(min_ttl_secs.unwrap_or(60))),
    })
}

fn skip_dns_name(pkt: &[u8], mut pos: usize) -> Result<usize, DnsError> {
    let mut jumps = 0u8;
    loop {
        if pos >= pkt.len() {
            return Err(DnsError::Wire("unexpected EOF inside DNS name".into()));
        }
        let len = pkt[pos];
        if len == 0 {
            return Ok(pos + 1);
        }
        if (len & 0xc0) == 0xc0 {
            if pos + 2 > pkt.len() {
                return Err(DnsError::Wire("truncated DNS compression pointer".into()));
            }
            return Ok(pos + 2);
        }
        if (len & 0xc0) != 0 {
            return Err(DnsError::Wire("invalid DNS label header".into()));
        }
        pos += 1 + usize::from(len);
        jumps += 1;
        if jumps > 128 {
            return Err(DnsError::Wire("DNS name exceeded max label count".into()));
        }
    }
}

/// Parses RFC 9460 SVCB/HTTPS RDATA (`SvcPriority`, uncompressed `TargetName`, `SvcParams`),
/// appending every raw `ech` (`key == 5`) SvcParamValue to `out`.
fn parse_https_ech_params(rdata: &[u8], out: &mut Vec<Vec<u8>>) {
    // SvcPriority (2 bytes)
    if rdata.len() < 3 {
        return;
    }
    let priority = u16::from_be_bytes([rdata[0], rdata[1]]);
    if priority == 0 {
        // AliasMode carries no SvcParams.
        return;
    }
    let mut pos = 2usize;
    // TargetName is uncompressed wire-format labels terminated by 0x00.
    while pos < rdata.len() {
        let l = rdata[pos] as usize;
        pos += 1;
        if l == 0 {
            break;
        }
        pos = pos.saturating_add(l);
        if pos > rdata.len() {
            return;
        }
    }

    while pos + 4 <= rdata.len() {
        let key = u16::from_be_bytes([rdata[pos], rdata[pos + 1]]);
        let val_len = u16::from_be_bytes([rdata[pos + 2], rdata[pos + 3]]) as usize;
        pos += 4;
        if pos + val_len > rdata.len() {
            return;
        }
        if key == 5 && val_len >= 2 {
            out.push(rdata[pos..pos + val_len].to_vec());
        }
        pos += val_len;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encodes_and_decodes_a_and_https_ech_records() {
        let query = encode_dns_query("vpn.mozilla.org", RecordType::A).unwrap();
        assert!(query.len() > 20);

        // Synthetic wire response with 1 A record (1.2.3.4) and 1 HTTPS record with ECH param key=5.
        let mut resp = Vec::new();
        resp.extend_from_slice(&[0x00, 0x00, 0x81, 0x80]); // QR=1, RD=1, RA=1, RCODE=0
        resp.extend_from_slice(&0u16.to_be_bytes()); // QDCOUNT=0
        resp.extend_from_slice(&2u16.to_be_bytes()); // ANCOUNT=2
        resp.extend_from_slice(&[0, 0, 0, 0]);

        // Answer 1: root name, TYPE A, IN, TTL=120, 1.2.3.4
        resp.push(0x00);
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&120u32.to_be_bytes());
        resp.extend_from_slice(&4u16.to_be_bytes());
        resp.extend_from_slice(&[1, 2, 3, 4]);

        // Answer 2: root name, TYPE HTTPS (65), IN, TTL=300
        let mut rdata = Vec::new();
        rdata.extend_from_slice(&1u16.to_be_bytes()); // priority=1
        rdata.push(0x00); // target=.
        rdata.extend_from_slice(&5u16.to_be_bytes()); // key=ech (5)
        let ech_payload = vec![0x00, 0x04, 0xde, 0xad, 0xbe, 0xef];
        rdata.extend_from_slice(&(ech_payload.len() as u16).to_be_bytes());
        rdata.extend_from_slice(&ech_payload);

        resp.push(0x00);
        resp.extend_from_slice(&65u16.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes());
        resp.extend_from_slice(&300u32.to_be_bytes());
        resp.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
        resp.extend_from_slice(&rdata);

        let decoded = decode_dns_response(&resp, RecordType::A).unwrap();
        assert_eq!(decoded.ips, vec![IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4))]);
        assert_eq!(decoded.ech_configs, vec![ech_payload]);
        assert_eq!(decoded.ttl, Duration::from_secs(120));
    }

    #[test]
    fn detects_block_page_and_private_ips() {
        assert!(is_block_page_ip("10.10.34.35".parse().unwrap()));
        assert!(is_block_page_ip("127.0.0.1".parse().unwrap()));
        assert!(is_block_page_ip("2001:4188:2:600:10:10:34:35".parse().unwrap()));
        assert!(!is_block_page_ip("151.101.1.194".parse().unwrap()));
        assert!(!is_block_page_ip("2606:4700::6810:85e5".parse().unwrap()));
    }

    #[test]
    fn parses_dns_server_variants() {
        assert!(matches!(
            DnsServer::parse("https://1.1.1.1/dns-query").unwrap(),
            DnsServer::Doh { .. }
        ));
        assert!(matches!(
            DnsServer::parse("tls://dns.quad9.net").unwrap(),
            DnsServer::Dot { port: 853, .. }
        ));
        assert!(matches!(
            DnsServer::parse("8.8.8.8").unwrap(),
            DnsServer::Plain(_)
        ));
        assert!(DnsServer::parse("ftp://bad").is_err());
    }
}
