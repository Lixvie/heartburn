//! Control-plane HTTP client for FxA, Guardian, and Mozilla Remote Settings.
//!
//! Built directly on `hyper`, [`BootstrapResolver`], [`ProtectedDialer`],
//! [`SplitStream`], and [`TlsConnector`] so every outbound socket honors Android
//! `VpnService.protect`, TLS fragmentation (`hellosplit`), TLS 1.3 ECH,
//! Cloudflare `.workers.dev` TLS 1.2 edge fallback, and personal `api_relay` rewriting.

use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderMap, HeaderName, HeaderValue, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper_util::rt::{TokioExecutor, TokioIo};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use url::Url;

use crate::config::{
    EchSource, IpVersionMode, NetworkConfig, RELAY_ECH_OFF, RELAY_ECH_ON, RELAY_ECH_REQUIRE,
    parse_ech_source,
};
use crate::dialer::ProtectedDialer;
use crate::dns::BootstrapResolver;
use crate::error::TlsError;
use crate::hellosplit::{HelloSplitMode, SplitStream};
use crate::tls::{BoxStream, BoxedTlsStream, TlsConfig, TlsConnector, TlsFingerprint};

/// Default API request timeout (`controlplane/client.go`).
pub const API_REQUEST_TIMEOUT: Duration = Duration::from_secs(15);

/// Control-plane client timeout (`30s`).
pub const CLIENT_TIMEOUT: Duration = Duration::from_secs(30);

/// Direct connection failure threshold before preferring relay for 10 minutes.
const RELAY_PREFER_DURATION: Duration = Duration::from_secs(10 * 60);
const RELAY_DIRECT_RACE_HEADSTART: Duration = Duration::from_secs(4);
const RENEWAL_TUNNEL_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_GET_REDIRECTS: usize = 5;

const QUERY_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Platform-matched Firefox User-Agent string (`controlplane/headers.go`).
pub fn firefox_user_agent(major_version: &str) -> String {
    let major = if major_version.trim().is_empty() {
        "158"
    } else {
        major_version.trim()
    };
    let os_token = if cfg!(target_os = "macos") {
        "Macintosh; Intel Mac OS X 10.15"
    } else if cfg!(target_os = "linux") && !cfg!(target_os = "android") {
        if cfg!(target_arch = "aarch64") {
            "X11; Linux aarch64"
        } else {
            "X11; Linux x86_64"
        }
    } else {
        // Windows and Android control-plane clients mimic Firefox Desktop on Windows.
        "Windows NT 10.0; Win64; x64"
    };
    format!("Mozilla/5.0 ({os_token}; rv:{major}.0) Gecko/20100101 Firefox/{major}.0")
}

/// Applies Go `controlplane.ApplyFirefoxHeaders` for general FxA/Mozilla endpoints.
pub fn apply_firefox_headers(headers: &mut HeaderMap, user_agent: &str) {
    set_header_if_absent(headers, "user-agent", user_agent);
    set_header_if_absent(headers, "accept", "*/*");
    set_header_if_absent(headers, "accept-encoding", "identity");
}

/// Applies OAuth XHR/fetch headers matching `fxa/oauth_code.go` (`newOAuthJSONRequest`).
pub fn apply_oauth_headers(headers: &mut HeaderMap, user_agent: &str) {
    set_header_if_absent(headers, "user-agent", user_agent);
    set_header_if_absent(headers, "accept", "application/json;q=0.9,*/*;q=0.2");
    set_header_if_absent(headers, "accept-language", "en-US, en");
    set_header_if_absent(headers, "accept-encoding", "identity");
    set_header_if_absent(headers, "content-type", "application/json; charset=utf-8");
    set_header_if_absent(headers, "cache-control", "no-cache");
    set_header_if_absent(headers, "pragma", "no-cache");
    set_header_if_absent(headers, "sec-fetch-dest", "empty");
    set_header_if_absent(headers, "sec-fetch-mode", "no-cors");
    set_header_if_absent(headers, "sec-fetch-site", "none");
    set_header_if_absent(headers, "priority", "u=4");
}

/// Compatibility alias for [`apply_firefox_headers`] used by FxA/Remote Settings helpers.
pub fn apply_fxa_headers(headers: &mut HeaderMap, user_agent: &str) {
    apply_firefox_headers(headers, user_agent);
}

/// Applies Guardian REST API headers (`guardian/guardian.go`:`applyGuardianHeaders`).
pub fn apply_guardian_headers(headers: &mut HeaderMap, user_agent: &str) {
    set_header_if_absent(headers, "user-agent", user_agent);
    set_header_if_absent(headers, "accept", "*/*");
    set_header_if_absent(headers, "accept-encoding", "identity");
    set_header_if_absent(headers, "content-type", "application/json");
    set_header_if_absent(headers, "cache-control", "max-age=0");
}

fn set_header_if_absent(headers: &mut HeaderMap, name: &'static str, value: &str) {
    if let (Ok(n), Ok(v)) = (
        HeaderName::from_bytes(name.as_bytes()),
        HeaderValue::from_str(value),
    ) && !headers.contains_key(&n)
    {
        headers.insert(n, v);
    }
}

/// Optional dialer callback routed through an already-established Mozilla tunnel
/// for background ProxyPass / quota renewal when direct Guardian access is blocked.
pub type TunnelDialFn = Arc<
    dyn Fn(String, u16) -> Pin<Box<dyn Future<Output = std::io::Result<BoxStream>> + Send>>
        + Send
        + Sync,
>;

/// Per-request route/evasion options.
#[derive(Debug, Clone)]
pub struct RequestOptions {
    pub split_mode: HelloSplitMode,
    pub force_h2: bool,
    pub prefer_h1: bool,
    pub follow_redirects: bool,
    pub use_cookies: bool,
    pub allow_relay: bool,
    pub reuse_connection: bool,
    pub pinned_peer: Option<SocketAddr>,
    pub timeout: Duration,
    pub ip_version: IpVersionMode,
}

impl Default for RequestOptions {
    fn default() -> Self {
        Self {
            split_mode: HelloSplitMode::Off,
            force_h2: false,
            prefer_h1: false,
            follow_redirects: false,
            use_cookies: false,
            allow_relay: true,
            reuse_connection: false,
            pinned_peer: None,
            timeout: API_REQUEST_TIMEOUT,
            ip_version: IpVersionMode::Auto,
        }
    }
}

/// Complete buffered HTTP response from the control plane.
#[derive(Debug, Clone)]
pub struct ControlResponse {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl ControlResponse {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }
}

/// Single HTTP cookie stored in [`CookieJar`] with domain/path scoping (RFC 6265 subset).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoredCookie {
    pub name: String,
    pub value: String,
    pub domain: String,
    pub host_only: bool,
    pub path: String,
}

impl StoredCookie {
    fn matches(&self, host_lower: &str, req_path: &str) -> bool {
        let domain_ok = if self.host_only {
            host_lower == self.domain
        } else {
            host_lower == self.domain
                || (host_lower.len() > self.domain.len()
                    && host_lower.ends_with(&self.domain)
                    && host_lower.as_bytes()[host_lower.len() - self.domain.len() - 1] == b'.')
        };
        if !domain_ok {
            return false;
        }
        if self.path == "/" {
            return true;
        }
        req_path == self.path
            || (req_path.starts_with(&self.path)
                && (self.path.ends_with('/') || req_path.as_bytes()[self.path.len()] == b'/'))
    }
}

/// Domain- and path-aware in-memory cookie jar scoped to FxA/Firefox origins.
#[derive(Debug, Default)]
pub struct CookieJar {
    cookies: Mutex<Vec<StoredCookie>>,
}

impl CookieJar {
    fn allowed_host(host: &str) -> bool {
        let lower = host.to_ascii_lowercase();
        lower == "firefox.com" || lower.ends_with(".firefox.com")
    }

    /// Parses `Set-Cookie` headers from a response for `url`.
    pub fn record_from_headers(&self, url: &Url, headers: &HeaderMap) {
        let Some(host) = url.host_str().map(str::to_ascii_lowercase) else {
            return;
        };
        if !Self::allowed_host(&host) {
            return;
        }
        let default_path = default_cookie_path(url.path());

        let Ok(mut jar) = self.cookies.lock() else {
            return;
        };

        let set_cookie_count = headers.get_all(http::header::SET_COOKIE).iter().count();
        if set_cookie_count > 0 {
            tracing::debug!(url = %url, set_cookie_count, "processing Set-Cookie headers");
        }

        for val in headers.get_all(http::header::SET_COOKIE) {
            let Ok(raw) = val.to_str() else {
                continue;
            };
            let mut parts = raw.split(';');
            let Some(nv) = parts.next() else {
                continue;
            };
            let Some((name_raw, value_raw)) = nv.split_once('=') else {
                continue;
            };
            let name = name_raw.trim();
            if name.is_empty() {
                continue;
            }
            let value = value_raw.trim();

            let mut domain = host.clone();
            let mut host_only = true;
            let mut path = default_path.clone();
            let mut deleted = false;
            let mut rejected = false;
            let now_unix = unix_timestamp_now();

            for attr in parts {
                let attr = attr.trim();
                if let Some((k, v)) = attr.split_once('=') {
                    let kl = k.trim().to_ascii_lowercase();
                    let vt = v.trim();
                    match kl.as_str() {
                        "domain" => {
                            let d = vt.trim_start_matches('.').to_ascii_lowercase();
                            if !d.is_empty() && domain_suffix_matches(&host, &d) && Self::allowed_host(&d) {
                                domain = d;
                                host_only = false;
                            } else {
                                // RFC 6265 §5.3 step 6: reject cookie on invalid Domain attribute.
                                rejected = true;
                                break;
                            }
                        }
                        "path" if vt.starts_with('/') => {
                            path = vt.to_owned();
                        }
                        "max-age" if vt.parse::<i64>().is_ok_and(|s| s <= 0) => {
                            deleted = true;
                        }
                        "expires" => {
                            if let Some(exp) = parse_cookie_expires_unix(vt)
                                && exp <= now_unix
                            {
                                deleted = true;
                            }
                        }
                        _ => {}
                    }
                }
            }
            if rejected {
                continue;
            }

            tracing::debug!(
                cookie_name = %name,
                value_len = value.len(),
                domain = %domain,
                host_only,
                path = %path,
                deleted,
                "recorded Set-Cookie in cookie jar"
            );

            // Replace matching (name, domain, path) entry.
            jar.retain(|c| !(c.name == name && c.domain == domain && c.path == path));
            if !deleted {
                jar.push(StoredCookie {
                    name: name.to_owned(),
                    value: value.to_owned(),
                    domain,
                    host_only,
                    path,
                });
            }
        }
    }

    /// Formats the `Cookie` request header matching `url`.
    pub fn cookie_header_for(&self, url: &Url) -> Option<String> {
        let host = url.host_str()?.to_ascii_lowercase();
        if !Self::allowed_host(&host) {
            return None;
        }
        let req_path = if url.path().is_empty() { "/" } else { url.path() };
        let jar = self.cookies.lock().ok()?;
        let mut matched: Vec<&StoredCookie> = jar
            .iter()
            .filter(|c| c.matches(&host, req_path))
            .collect();
        if matched.is_empty() {
            return None;
        }
        // RFC 6265 §5.4: cookies with longer Path precede shorter ones.
        matched.sort_by_key(|a| std::cmp::Reverse(a.path.len()));
        let pairs: Vec<String> = matched
            .into_iter()
            .map(|c| format!("{}={}", c.name, c.value))
            .collect();
        Some(pairs.join("; "))
    }

    /// Returns all cookies matching `url`.
    pub fn cookies_for(&self, url: &Url) -> Vec<StoredCookie> {
        let Some(host) = url.host_str().map(str::to_ascii_lowercase) else {
            return Vec::new();
        };
        if !Self::allowed_host(&host) {
            return Vec::new();
        }
        let req_path = if url.path().is_empty() { "/" } else { url.path() };
        self.cookies
            .lock()
            .ok()
            .map(|jar| {
                jar.iter()
                    .filter(|c| c.matches(&host, req_path))
                    .cloned()
                    .collect()
            })
            .unwrap_or_default()
    }

    /// Installs explicit cookies onto a specific target URL origin (mirroring Go `SetCookies`).
    pub fn set_cookies_for(&self, url: &Url, cookies: &[StoredCookie]) {
        let Some(host) = url.host_str().map(str::to_ascii_lowercase) else {
            return;
        };
        if !Self::allowed_host(&host) {
            return;
        }
        let Ok(mut jar) = self.cookies.lock() else {
            return;
        };
        for c in cookies {
            let (domain, host_only) = if !c.host_only && domain_suffix_matches(&host, &c.domain) {
                (c.domain.clone(), false)
            } else {
                (host.clone(), true)
            };
            let path = if c.path.is_empty() {
                "/".to_owned()
            } else {
                c.path.clone()
            };
            jar.retain(|ex| !(ex.name == c.name && ex.domain == domain && ex.path == path));
            jar.push(StoredCookie {
                name: c.name.clone(),
                value: c.value.clone(),
                domain,
                host_only,
                path,
            });
        }
    }

    /// Clears all stored cookies.
    pub fn clear(&self) {
        if let Ok(mut g) = self.cookies.lock() {
            g.clear();
        }
    }
}

fn domain_suffix_matches(host_lower: &str, domain_lower: &str) -> bool {
    host_lower == domain_lower
        || (host_lower.len() > domain_lower.len()
            && host_lower.ends_with(domain_lower)
            && host_lower.as_bytes()[host_lower.len() - domain_lower.len() - 1] == b'.')
}

fn unix_timestamp_now() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

fn parse_cookie_expires_unix(raw: &str) -> Option<i64> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }

    // Normalize optional trailing "GMT"/"UTC" to numeric "+0000" for RFC 2822 / dashed HTTP-date formats.
    let normalized = if trimmed.ends_with(" GMT") || trimmed.ends_with(" UTC") {
        format!("{} +0000", &trimmed[..trimmed.len() - 4])
    } else {
        trimmed.to_owned()
    };

    if let Ok(dt) =
        time::OffsetDateTime::parse(&normalized, &time::format_description::well_known::Rfc2822)
    {
        return Some(dt.unix_timestamp());
    }

    const DASHED_HTTP_DATE: &[time::format_description::FormatItem<'static>] = time::macros::format_description!(
        "[weekday repr:short], [day]-[month repr:short]-[year] [hour]:[minute]:[second] [offset_hour sign:mandatory][offset_minute]"
    );
    if let Ok(dt) = time::OffsetDateTime::parse(&normalized, DASHED_HTTP_DATE) {
        return Some(dt.unix_timestamp());
    }

    const SPACE_HTTP_DATE: &[time::format_description::FormatItem<'static>] = time::macros::format_description!(
        "[weekday repr:short], [day] [month repr:short] [year] [hour]:[minute]:[second] [offset_hour sign:mandatory][offset_minute]"
    );
    time::OffsetDateTime::parse(&normalized, SPACE_HTTP_DATE)
        .ok()
        .map(|dt| dt.unix_timestamp())
}

fn default_cookie_path(req_path: &str) -> String {
    if !req_path.starts_with('/') {
        return "/".to_owned();
    }
    match req_path.rfind('/') {
        Some(0) | None => "/".to_owned(),
        Some(idx) => req_path[..idx].to_owned(),
    }
}

struct CachedH1Conn {
    sender: hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    driver: JoinHandle<()>,
    peer_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
}

impl Drop for CachedH1Conn {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

#[derive(Default)]
struct PinnedSessionState {
    pinned_peers: tokio::sync::Mutex<HashMap<(String, u16), SocketAddr>>,
    h1_conns: tokio::sync::Mutex<HashMap<(String, u16), CachedH1Conn>>,
}

/// Control-plane HTTP engine supporting bootstrap DoH, `hellosplit`, ECH, personal
/// `api_relay`, `.workers.dev` TLS 1.2 edge fallback, and tunnel-backed renewals.
#[derive(Clone)]
pub struct ControlPlaneClient {
    resolver: Arc<BootstrapResolver>,
    dialer: ProtectedDialer,
    tls: Arc<dyn TlsConnector>,
    user_agent: Arc<RwLock<String>>,
    network: Arc<RwLock<NetworkConfig>>,
    cookies: Arc<CookieJar>,
    session: Arc<PinnedSessionState>,
    relay_preferred_until: Arc<Mutex<Option<Instant>>>,
    tunnel_dial: Arc<RwLock<Option<TunnelDialFn>>>,
}

impl std::fmt::Debug for ControlPlaneClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ControlPlaneClient").finish()
    }
}

impl ControlPlaneClient {
    /// Creates a new control-plane client sharing the core resolver and TLS connector.
    pub fn new(
        resolver: Arc<BootstrapResolver>,
        dialer: ProtectedDialer,
        tls: Arc<dyn TlsConnector>,
        network: NetworkConfig,
    ) -> Self {
        Self {
            resolver,
            dialer,
            tls,
            user_agent: Arc::new(RwLock::new(firefox_user_agent("158"))),
            network: Arc::new(RwLock::new(network)),
            cookies: Arc::new(CookieJar::default()),
            session: Arc::new(PinnedSessionState::default()),
            relay_preferred_until: Arc::new(Mutex::new(None)),
            tunnel_dial: Arc::new(RwLock::new(None)),
        }
    }

    /// Creates a clone sharing transport/DNS/network/UA settings with an isolated empty
    /// [`CookieJar`] and isolated pinned keep-alive connection pool (used by Fastly challenge solvers).
    pub fn with_isolated_cookie_jar(&self) -> Self {
        Self {
            resolver: Arc::clone(&self.resolver),
            dialer: self.dialer.clone(),
            tls: Arc::clone(&self.tls),
            user_agent: Arc::clone(&self.user_agent),
            network: Arc::clone(&self.network),
            cookies: Arc::new(CookieJar::default()),
            session: Arc::new(PinnedSessionState::default()),
            relay_preferred_until: Arc::clone(&self.relay_preferred_until),
            tunnel_dial: Arc::clone(&self.tunnel_dial),
        }
    }

    /// Reads stored cookies valid for `url` in this client's cookie jar.
    pub fn cookies_for(&self, url: &Url) -> Vec<StoredCookie> {
        self.cookies.cookies_for(url)
    }

    /// Installs cookies for `url` into this client's shared cookie jar.
    pub fn set_cookies_for(&self, url: &Url, cookies: &[StoredCookie]) {
        self.cookies.set_cookies_for(url, cookies);
    }

    /// Updates Firefox User-Agent major version (e.g. from Product Details sync).
    pub async fn set_firefox_major_version(&self, major: &str) {
        let mut ua = self.user_agent.write().await;
        *ua = firefox_user_agent(major);
    }

    /// Returns the active Firefox User-Agent string.
    pub async fn user_agent(&self) -> String {
        self.user_agent.read().await.clone()
    }

    /// Updates live network settings (relay, ECH, hello_split, upstream proxy).
    pub async fn set_network_config(&self, net: NetworkConfig) {
        let mut guard = self.network.write().await;
        *guard = net;
        drop(guard);
        if let Ok(mut pref) = self.relay_preferred_until.lock() {
            *pref = None;
        }
    }

    /// Returns a snapshot of current network configuration.
    pub async fn network_config(&self) -> NetworkConfig {
        self.network.read().await.clone()
    }

    /// Attaches or clears an active tunnel dialer for renewal-tunnel calls.
    pub async fn set_tunnel_dialer(&self, dial: Option<TunnelDialFn>) {
        let mut guard = self.tunnel_dial.write().await;
        *guard = dial;
    }

    /// Clears stored FxA challenge cookies.
    pub fn clear_cookies(&self) {
        self.cookies.clear();
    }

    /// Executes an HTTP request with full control-plane fallback semantics.
    pub async fn execute(
        &self,
        method: Method,
        url: &str,
        headers: HeaderMap,
        body: Bytes,
        opts: RequestOptions,
    ) -> Result<ControlResponse, String> {
        Box::pin(async move {
            let mut current_url =
                Url::parse(url).map_err(|e| format!("invalid URL {url:?}: {e}"))?;
            let max_hops =
                if opts.follow_redirects && (method == Method::GET || method == Method::HEAD) {
                    MAX_GET_REDIRECTS
                } else {
                    0
                };

            for hop in 0..=max_hops {
                let mut req_headers = headers.clone();
                if opts.use_cookies
                    && let Some(cookie) = self.cookies.cookie_header_for(&current_url)
                {
                    set_header_if_absent(&mut req_headers, "cookie", &cookie);
                }

                let resp = self
                    .execute_single_hop(
                        method.clone(),
                        &current_url,
                        req_headers,
                        body.clone(),
                        &opts,
                    )
                    .await?;

                if opts.use_cookies {
                    self.cookies.record_from_headers(&current_url, &resp.headers);
                }

                if hop < max_hops
                    && matches!(
                        resp.status,
                        StatusCode::MOVED_PERMANENTLY
                            | StatusCode::FOUND
                            | StatusCode::SEE_OTHER
                            | StatusCode::TEMPORARY_REDIRECT
                            | StatusCode::PERMANENT_REDIRECT
                    )
                    && let Some(loc) = resp.header("location")
                    && let Ok(next_url) = current_url.join(loc.trim())
                {
                    tracing::debug!(
                        from = %current_url,
                        to = %next_url,
                        status = %resp.status,
                        "following control-plane redirect"
                    );
                    current_url = next_url;
                    continue;
                }

                return Ok(resp);
            }

            Err("control-plane exceeded maximum redirect hops".into())
        })
        .await
    }

    async fn execute_single_hop(
        &self,
        method: Method,
        parsed: &Url,
        headers: HeaderMap,
        body: Bytes,
        opts: &RequestOptions,
    ) -> Result<ControlResponse, String> {
        Box::pin(async move {
            let net = self.network.read().await.clone();
            let personal_relay = net.api_relay_in_use().to_owned();

            let has_cookie = headers.contains_key(http::header::COOKIE);
            tracing::debug!(
                %method,
                url = %parsed,
                prefer_h1 = opts.prefer_h1,
                force_h2 = opts.force_h2,
                has_cookie,
                via_relay = opts.allow_relay && !personal_relay.is_empty(),
                "sending control-plane request"
            );

            let resp = if opts.allow_relay && !personal_relay.is_empty() {
                self.execute_with_relay_race(
                    method.clone(),
                    parsed,
                    headers.clone(),
                    body.clone(),
                    &net,
                    opts,
                )
                .await
            } else {
                self.send_direct_internal(method.clone(), parsed, headers.clone(), body.clone(), opts, false)
                    .await
            };

            if let Ok(ref ok) = resp {
                log_control_response(&method, parsed, ok);
                return Ok(ok.clone());
            }

            // Fallback to active Mozilla VPN renewal tunnel if configured and direct failed.
            if let Some(tunnel_dial) = self.tunnel_dial.read().await.clone() {
                match self
                    .send_via_tunnel(
                        tunnel_dial,
                        method.clone(),
                        parsed,
                        headers,
                        body,
                        opts.timeout.min(RENEWAL_TUNNEL_TIMEOUT),
                        opts.prefer_h1,
                    )
                    .await
                {
                    Ok(tun_resp) => {
                        log_control_response(&method, parsed, &tun_resp);
                        return Ok(tun_resp);
                    }
                    Err(tun_err) => {
                        tracing::debug!(error = %tun_err, url = %parsed, "renewal tunnel attempt also failed");
                    }
                }
            }

            resp
        })
        .await
    }

    /// Direct-only execution (bypassing relay auto-racing), useful for probing or H2 retry.
    pub async fn send_direct(
        &self,
        method: Method,
        url: &Url,
        headers: HeaderMap,
        body: Bytes,
        opts: &RequestOptions,
    ) -> Result<ControlResponse, String> {
        self.send_direct_internal(method, url, headers, body, opts, true)
            .await
    }

    async fn send_direct_internal(
        &self,
        method: Method,
        url: &Url,
        mut headers: HeaderMap,
        body: Bytes,
        opts: &RequestOptions,
        record_cookies: bool,
    ) -> Result<ControlResponse, String> {
        Box::pin(async move {
            if opts.use_cookies
                && let Some(cookie) = self.cookies.cookie_header_for(url)
            {
                set_header_if_absent(&mut headers, "cookie", &cookie);
            }

            let host = url
                .host_str()
                .filter(|h| !h.is_empty())
                .ok_or_else(|| format!("URL {url} missing host"))?
                .trim_matches(['[', ']'])
                .to_owned();
            let port = url.port_or_known_default().unwrap_or(443);
            let session_key = (host.to_ascii_lowercase(), port);

            let host_hdr = match url.port() {
                Some(p) => format!("{host}:{p}"),
                None => host.clone(),
            };
            let pq = url_path_and_query(url);

            // Reuse existing keep-alive HTTP/1.1 connection when requested (e.g. Fastly challenges).
            if opts.reuse_connection && opts.prefer_h1 && !opts.force_h2 {
                let maybe_cached = {
                    let mut map = self.session.h1_conns.lock().await;
                    map.remove(&session_key)
                };
                if let Some(mut cached) = maybe_cached
                    && !cached.sender.is_closed()
                    && cached.sender.ready().await.is_ok()
                {
                    let mut reuse_hdrs = headers.clone();
                    set_header_if_absent(&mut reuse_hdrs, "host", &host_hdr);
                    tracing::debug!(
                        host = %host,
                        peer_addr = %cached.peer_addr,
                        local_addr = ?cached.local_addr,
                        reused_conn = true,
                        "reusing HTTP/1.1 keep-alive connection"
                    );
                    match send_over_h1_sender(
                        &mut cached.sender,
                        method.clone(),
                        pq.clone(),
                        reuse_hdrs,
                        body.clone(),
                        opts.timeout,
                    )
                    .await
                    {
                        Ok((resp, server_closing)) => {
                            if !server_closing && !cached.sender.is_closed() {
                                let mut map = self.session.h1_conns.lock().await;
                                map.insert(session_key.clone(), cached);
                            }
                            if record_cookies && opts.use_cookies {
                                self.cookies.record_from_headers(url, &resp.headers);
                            }
                            return Ok(resp);
                        }
                        Err(e) if method == Method::GET || method == Method::HEAD => {
                            tracing::debug!(
                                host = %host,
                                peer_addr = %cached.peer_addr,
                                error = %e,
                                "reused HTTP/1.1 connection failed; redialing pinned peer"
                            );
                        }
                        Err(e) => return Err(e),
                    }
                }
            }

            let pinned_peer = if opts.pinned_peer.is_some() {
                opts.pinned_peer
            } else if opts.reuse_connection {
                let peers = self.session.pinned_peers.lock().await;
                peers.get(&session_key).copied()
            } else {
                None
            };

            let (tcp, peer_addr) = self
                .resolver
                .dial_tcp_pinned(&host, port, opts.ip_version, opts.timeout, pinned_peer)
                .await
                .map_err(|e| format!("dial {host}:{port}: {e}"))?;
            let local_addr = tcp.local_addr().ok();
            tracing::debug!(
                host = %host,
                port,
                %peer_addr,
                local_addr = ?local_addr,
                pinned = pinned_peer.is_some(),
                "control-plane TCP connected"
            );

            if opts.reuse_connection {
                let mut peers = self.session.pinned_peers.lock().await;
                peers.insert(session_key.clone(), peer_addr);
            }

            let stream: BoxStream = if opts.split_mode.is_active() {
                Box::new(SplitStream::new(tcp, opts.split_mode))
            } else {
                Box::new(tcp)
            };

            let alpn = if opts.force_h2 {
                vec![b"h2".to_vec()]
            } else if opts.prefer_h1 {
                vec![b"http/1.1".to_vec()]
            } else {
                vec![b"h2".to_vec(), b"http/1.1".to_vec()]
            };

            let tls_cfg = TlsConfig {
                server_name: host.clone(),
                alpn,
                ech_config_list: None,
                tls12_only: false,
                fingerprint: TlsFingerprint::Firefox158,
            };
            let tls_stream = tokio::time::timeout(opts.timeout, self.tls.connect(stream, &tls_cfg))
                .await
                .map_err(|_| format!("TLS handshake to {host}:{port} timed out"))?
                .map_err(|e| format!("TLS handshake to {host}:{port}: {e}"))?;

            tracing::debug!(
                host = %host,
                %peer_addr,
                alpn = ?tls_stream.alpn_protocol().map(String::from_utf8_lossy),
                "control-plane TLS handshake complete"
            );

            let resp = if tls_stream.alpn_protocol() != Some(b"h2") && opts.reuse_connection {
                set_header_if_absent(&mut headers, "host", &host_hdr);
                let io = TokioIo::new(tls_stream);
                let mut h1_builder = hyper::client::conn::http1::Builder::new();
                h1_builder.title_case_headers(true);
                let (mut sender, conn) = h1_builder
                    .handshake(io)
                    .await
                    .map_err(|e| format!("H1 handshake failed: {e}"))?;
                let driver = tokio::spawn(async move {
                    let _ = conn.await;
                });

                let (resp, server_closing) = send_over_h1_sender(
                    &mut sender,
                    method,
                    pq,
                    headers,
                    body,
                    opts.timeout,
                )
                .await
                .inspect_err(|_| {
                    driver.abort();
                })?;

                if !server_closing && !sender.is_closed() {
                    let mut map = self.session.h1_conns.lock().await;
                    map.insert(
                        session_key,
                        CachedH1Conn {
                            sender,
                            driver,
                            peer_addr,
                            local_addr,
                        },
                    );
                } else {
                    driver.abort();
                }
                resp
            } else {
                self.send_over_tls_stream(tls_stream, method, url, headers, body, opts.timeout)
                    .await?
            };

            if record_cookies && opts.use_cookies {
                self.cookies.record_from_headers(url, &resp.headers);
            }
            Ok(resp)
        })
        .await
    }

    async fn execute_with_relay_race(
        &self,
        method: Method,
        target: &Url,
        headers: HeaderMap,
        body: Bytes,
        net: &NetworkConfig,
        opts: &RequestOptions,
    ) -> Result<ControlResponse, String> {
        Box::pin(async move {
            let prefer_relay = self
                .relay_preferred_until
                .lock()
                .ok()
                .and_then(|g| *g)
                .map(|until| Instant::now() < until)
                .unwrap_or(false);

            if prefer_relay
                && let Ok(resp) = self
                    .send_via_personal_relay(method.clone(), target, headers.clone(), body.clone(), net, opts)
                    .await
            {
                return Ok(resp);
            }

            // Direct headstart (4s) matching Go `relayTransport`, then race personal relay.
            let mut direct_fut = Box::pin(self.send_direct_internal(
                method.clone(),
                target,
                headers.clone(),
                body.clone(),
                opts,
                false,
            ));

            match tokio::time::timeout(RELAY_DIRECT_RACE_HEADSTART, &mut direct_fut).await {
                Ok(Ok(resp)) => return Ok(resp),
                Ok(Err(direct_err)) => {
                    if let Ok(mut pref) = self.relay_preferred_until.lock() {
                        *pref = Some(Instant::now() + RELAY_PREFER_DURATION);
                    }
                    return self
                        .send_via_personal_relay(method, target, headers, body, net, opts)
                        .await
                        .map_err(|relay_err| format!("direct ({direct_err}) and relay ({relay_err}) failed"));
                }
                Err(_elapsed) => {}
            }

            let mut relay_fut = Box::pin(self.send_via_personal_relay(
                method, target, headers, body, net, opts,
            ));

            tokio::select! {
                res = &mut direct_fut => {
                    if let Ok(resp) = res {
                        return Ok(resp);
                    }
                    match relay_fut.await {
                        Ok(resp) => {
                            if let Ok(mut pref) = self.relay_preferred_until.lock() {
                                *pref = Some(Instant::now() + RELAY_PREFER_DURATION);
                            }
                            Ok(resp)
                        }
                        Err(relay_err) => Err(format!("direct and relay ({relay_err}) timed out/failed")),
                    }
                }
                res = &mut relay_fut => {
                    match res {
                        Ok(resp) => {
                            if let Ok(mut pref) = self.relay_preferred_until.lock() {
                                *pref = Some(Instant::now() + RELAY_PREFER_DURATION);
                            }
                            Ok(resp)
                        }
                        Err(relay_err) => {
                            direct_fut.await.map_err(|d| format!("relay ({relay_err}); direct ({d})"))
                        }
                    }
                }
            }
        })
        .await
    }

    /// Routes `target` through a personal HTTPS relay (`?url=<encoded>`) with ECH and
    /// `.workers.dev` TLS 1.2 + `chatgpt.com` edge SNI fallback for GET/HEAD requests.
    #[allow(clippy::too_many_arguments)]
    pub async fn send_via_relay_url(
        &self,
        relay_base: &str,
        method: Method,
        target: &Url,
        headers: HeaderMap,
        body: Bytes,
        net: &NetworkConfig,
        opts: &RequestOptions,
    ) -> Result<ControlResponse, String> {
        Box::pin(async move {
            let mut relay_url =
                Url::parse(relay_base).map_err(|e| format!("invalid relay URL {relay_base:?}: {e}"))?;
            let encoded_target = utf8_percent_encode(target.as_str(), QUERY_ENCODE_SET).to_string();
            let existing_q = relay_url.query().unwrap_or("").to_owned();
            if existing_q.is_empty() {
                relay_url.set_query(Some(&format!("url={encoded_target}")));
            } else {
                relay_url.set_query(Some(&format!("{existing_q}&url={encoded_target}")));
            }

            let relay_host = relay_url
                .host_str()
                .filter(|h| !h.is_empty())
                .ok_or_else(|| "relay URL missing host".to_owned())?
                .trim_matches(['[', ']'])
                .to_owned();
            let relay_port = relay_url.port_or_known_default().unwrap_or(443);

            let ech_mode = if net.api_relay_ech.trim().is_empty() {
                RELAY_ECH_ON
            } else {
                net.api_relay_ech.trim()
            };

            let ech_configs = self.resolve_relay_ech_configs(&relay_host, ech_mode, net).await?;

            let tls_attempt = self
                .dial_relay_and_send(
                    &relay_host,
                    relay_port,
                    &relay_host,
                    ech_configs,
                    false,
                    method.clone(),
                    &relay_url,
                    headers.clone(),
                    body.clone(),
                    opts,
                )
                .await;

            let resp = match tls_attempt {
                Ok(ok) => ok,
                Err(primary_err) => {
                    let idempotent = method == Method::GET || method == Method::HEAD;
                    if idempotent && relay_host.to_ascii_lowercase().ends_with(".workers.dev") {
                        self.dial_relay_and_send(
                            "chatgpt.com",
                            443,
                            "chatgpt.com",
                            None,
                            true,
                            method,
                            &relay_url,
                            headers,
                            body,
                            opts,
                        )
                        .await
                        .map_err(|fallback_err| {
                            format!("{primary_err}; workers.dev TLS1.2 fallback: {fallback_err}")
                        })?
                    } else {
                        return Err(primary_err);
                    }
                }
            };

            if let Some(relay_err) = resp.header("x-relay-error") {
                return Err(format!("relay upstream error: {relay_err}"));
            }
            Ok(resp)
        })
        .await
    }

    async fn send_via_personal_relay(
        &self,
        method: Method,
        target: &Url,
        headers: HeaderMap,
        body: Bytes,
        net: &NetworkConfig,
        opts: &RequestOptions,
    ) -> Result<ControlResponse, String> {
        let base = net.api_relay_in_use();
        if base.is_empty() {
            return Err("personal relay is not configured".into());
        }
        self.send_via_relay_url(base, method, target, headers, body, net, opts)
            .await
    }

    async fn resolve_relay_ech_configs(
        &self,
        relay_host: &str,
        ech_mode: &str,
        net: &NetworkConfig,
    ) -> Result<Option<Vec<u8>>, String> {
        Box::pin(async move {
            if ech_mode == RELAY_ECH_OFF {
                return Ok(None);
            }

            let source = parse_ech_source(&net.api_relay_ech_config)
                .map_err(|e| format!("invalid ECH source: {e}"))?;

            let found = match source {
                EchSource::RawConfigList(bytes) => Some(bytes),
                EchSource::DnsName(name) => self
                    .resolver
                    .lookup_ech(&name)
                    .await
                    .ok()
                    .and_then(|v| v.into_iter().next()),
                EchSource::RelayHost => self
                    .resolver
                    .lookup_ech(relay_host)
                    .await
                    .ok()
                    .and_then(|v| v.into_iter().next()),
            };

            if found.is_none() && ech_mode == RELAY_ECH_REQUIRE {
                return Err(format!(
                    "ECH required for relay {relay_host} but no ECHConfigList record was found"
                ));
            }
            Ok(found)
        })
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn dial_relay_and_send(
        &self,
        dial_host: &str,
        dial_port: u16,
        tls_sni: &str,
        mut ech_config_list: Option<Vec<u8>>,
        tls12_only: bool,
        method: Method,
        relay_url: &Url,
        headers: HeaderMap,
        body: Bytes,
        opts: &RequestOptions,
    ) -> Result<ControlResponse, String> {
        Box::pin(async move {
            for attempt in 0..2 {
                let tcp = self
                    .resolver
                    .dial_tcp(dial_host, dial_port, opts.ip_version, opts.timeout)
                    .await
                    .map_err(|e| format!("dial relay {dial_host}:{dial_port}: {e}"))?
                    .0;

                let stream: BoxStream =
                    if !tls12_only && opts.split_mode.is_active() && ech_config_list.is_none() {
                        Box::new(SplitStream::new(tcp, opts.split_mode))
                    } else {
                        Box::new(tcp)
                    };

                let tls_cfg = TlsConfig {
                    server_name: tls_sni.to_owned(),
                    alpn: if opts.prefer_h1 {
                        vec![b"http/1.1".to_vec()]
                    } else {
                        vec![b"h2".to_vec(), b"http/1.1".to_vec()]
                    },
                    ech_config_list: ech_config_list.clone(),
                    tls12_only,
                    fingerprint: TlsFingerprint::Firefox158,
                };

                match tokio::time::timeout(opts.timeout, self.tls.connect(stream, &tls_cfg)).await {
                    Ok(Ok(tls_stream)) => {
                        return self
                            .send_over_tls_stream(
                                tls_stream,
                                method,
                                relay_url,
                                headers,
                                body,
                                opts.timeout,
                            )
                            .await;
                    }
                    Ok(Err(TlsError::EchRejected {
                        retry_configs: Some(retry),
                    })) if attempt == 0 => {
                        ech_config_list = Some(retry);
                        continue;
                    }
                    Ok(Err(err)) => {
                        return Err(format!("relay TLS {tls_sni}: {err}"));
                    }
                    Err(_) => {
                        return Err(format!("relay TLS {tls_sni} timed out"));
                    }
                }
            }
            Err("relay ECH retry exhausted".into())
        })
        .await
    }

    #[allow(clippy::too_many_arguments)]
    async fn send_via_tunnel(
        &self,
        tunnel_dial: TunnelDialFn,
        method: Method,
        url: &Url,
        headers: HeaderMap,
        body: Bytes,
        timeout: Duration,
        prefer_h1: bool,
    ) -> Result<ControlResponse, String> {
        Box::pin(async move {
            let host = url
                .host_str()
                .filter(|h| !h.is_empty())
                .ok_or_else(|| "URL missing host".to_owned())?
                .trim_matches(['[', ']'])
                .to_owned();
            let port = url.port_or_known_default().unwrap_or(443);

            let stream = tokio::time::timeout(Duration::from_secs(5), tunnel_dial(host.clone(), port))
                .await
                .map_err(|_| "tunnel dial timed out".to_owned())?
                .map_err(|e| format!("tunnel dial failed: {e}"))?;

            let tls_cfg = TlsConfig {
                server_name: host,
                alpn: if prefer_h1 {
                    vec![b"http/1.1".to_vec()]
                } else {
                    vec![b"h2".to_vec(), b"http/1.1".to_vec()]
                },
                ech_config_list: None,
                tls12_only: false,
                fingerprint: TlsFingerprint::Firefox158,
            };
            let tls_stream = tokio::time::timeout(timeout, self.tls.connect(stream, &tls_cfg))
                .await
                .map_err(|_| "tunnel TLS handshake timed out".to_owned())?
                .map_err(|e| format!("tunnel TLS failed: {e}"))?;

            self.send_over_tls_stream(tls_stream, method, url, headers, body, timeout)
                .await
        })
        .await
    }

    async fn send_over_tls_stream(
        &self,
        tls_stream: BoxedTlsStream,
        method: Method,
        url: &Url,
        mut headers: HeaderMap,
        body: Bytes,
        timeout: Duration,
    ) -> Result<ControlResponse, String> {
        let is_h2 = tls_stream.alpn_protocol() == Some(b"h2");
        if is_h2 {
            self.send_over_h2_stream(tls_stream, method, url, headers, body, timeout)
                .await
        } else {
            let host_hdr = match url.port() {
                Some(p) => format!("{}:{p}", url.host_str().unwrap_or_default()),
                None => url.host_str().unwrap_or_default().to_owned(),
            };
            let pq = url_path_and_query(url);
            set_header_if_absent(&mut headers, "host", &host_hdr);
            self.send_over_h1_stream(tls_stream, method, pq, headers, body, timeout)
                .await
        }
    }

    async fn send_over_h2_stream(
        &self,
        tls_stream: BoxedTlsStream,
        method: Method,
        url: &Url,
        mut headers: HeaderMap,
        body: Bytes,
        timeout: Duration,
    ) -> Result<ControlResponse, String> {
        Box::pin(async move {
            let uri = url.as_str();
            log_outgoing_wire_request(&method, uri, "HTTP/2", &headers);
            let io = TokioIo::new(tls_stream);
            let (mut sender, conn) =
                hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
                    .await
                    .map_err(|e| format!("H2 handshake failed: {e}"))?;
            let driver = tokio::spawn(async move {
                let _ = conn.await;
            });

            headers.remove(http::header::CONNECTION);
            let mut builder = Request::builder().method(method).uri(uri);
            if let Some(map) = builder.headers_mut() {
                *map = headers;
            }
            let req = builder
                .body(Full::new(body))
                .map_err(|e| format!("build H2 request: {e}"))?;

            let res = tokio::time::timeout(timeout, sender.send_request(req))
                .await
                .map_err(|_| "HTTP/2 request timed out".to_owned())?
                .map_err(|e| format!("HTTP/2 request error: {e}"))?;

            let status = res.status();
            let resp_headers = res.headers().clone();
            let resp_body = tokio::time::timeout(timeout, res.into_body().collect())
                .await
                .map_err(|_| "HTTP/2 response body timed out".to_owned())?
                .map_err(|e| format!("HTTP/2 body read error: {e}"))?
                .to_bytes();
            driver.abort();
            Ok(ControlResponse {
                status,
                headers: resp_headers,
                body: resp_body,
            })
        })
        .await
    }

    async fn send_over_h1_stream(
        &self,
        tls_stream: BoxedTlsStream,
        method: Method,
        pq: String,
        headers: HeaderMap,
        body: Bytes,
        timeout: Duration,
    ) -> Result<ControlResponse, String> {
        Box::pin(async move {
            let io = TokioIo::new(tls_stream);
            let mut h1_builder = hyper::client::conn::http1::Builder::new();
            h1_builder.title_case_headers(true);
            let (mut sender, conn) = h1_builder
                .handshake(io)
                .await
                .map_err(|e| format!("H1 handshake failed: {e}"))?;
            let driver = tokio::spawn(async move {
                let _ = conn.await;
            });

            let res = send_over_h1_sender(&mut sender, method, pq, headers, body, timeout).await;
            driver.abort();
            res.map(|(resp, _closing)| resp)
        })
        .await
    }
}

fn url_path_and_query(url: &Url) -> String {
    let mut pq = url.path().to_owned();
    if pq.is_empty() {
        pq = "/".to_owned();
    }
    if let Some(q) = url.query() {
        pq.push('?');
        pq.push_str(q);
    }
    pq
}

async fn send_over_h1_sender(
    sender: &mut hyper::client::conn::http1::SendRequest<Full<Bytes>>,
    method: Method,
    pq: String,
    headers: HeaderMap,
    body: Bytes,
    timeout: Duration,
) -> Result<(ControlResponse, bool), String> {
    Box::pin(async move {
        log_outgoing_wire_request(&method, &pq, "HTTP/1.1", &headers);
        let mut builder = Request::builder().method(method).uri(pq);
        if let Some(map) = builder.headers_mut() {
            *map = headers;
        }
        let req = builder
            .body(Full::new(body))
            .map_err(|e| format!("build H1 request: {e}"))?;

        let res = tokio::time::timeout(timeout, sender.send_request(req))
            .await
            .map_err(|_| "HTTP/1.1 request timed out".to_owned())?
            .map_err(|e| format!("HTTP/1.1 request error: {e}"))?;

        let status = res.status();
        let resp_headers = res.headers().clone();
        let server_closing = resp_headers
            .get_all(http::header::CONNECTION)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .any(|s| s.split(',').any(|t| t.trim().eq_ignore_ascii_case("close")));

        let resp_body = tokio::time::timeout(timeout, res.into_body().collect())
            .await
            .map_err(|_| "HTTP/1.1 response body timed out".to_owned())?
            .map_err(|e| format!("HTTP/1.1 body read error: {e}"))?
            .to_bytes();
        Ok((
            ControlResponse {
                status,
                headers: resp_headers,
                body: resp_body,
            },
            server_closing,
        ))
    })
    .await
}

fn log_outgoing_wire_request(
    method: &Method,
    target: &str,
    protocol: &str,
    headers: &HeaderMap,
) {
    let mut header_names: Vec<&str> = headers.keys().map(|k| k.as_str()).collect();
    header_names.sort_unstable();
    let cookie_info = sanitize_cookie_summary(headers);
    tracing::debug!(
        %method,
        target = %target,
        protocol,
        title_case = (protocol == "HTTP/1.1"),
        header_names = ?header_names,
        cookies = ?cookie_info,
        "sending outgoing wire HTTP request"
    );
}

fn sanitize_cookie_summary(headers: &HeaderMap) -> Vec<String> {
    let mut summary = Vec::new();
    for val in headers.get_all(http::header::COOKIE) {
        if let Ok(raw) = val.to_str() {
            for pair in raw.split(';') {
                if let Some((n, v)) = pair.trim().split_once('=') {
                    let clean = n.trim();
                    if !clean.is_empty() {
                        summary.push(format!("{clean}(len={})", v.len()));
                    }
                }
            }
        }
    }
    summary
}

fn log_control_response(method: &Method, url: &Url, resp: &ControlResponse) {
    let ct = resp.header("content-type").unwrap_or("-");
    let body_len = resp.body.len();
    if resp.status.is_client_error() || resp.status.is_server_error() {
        let preview = truncate_lossy(&resp.body, 512);
        let hdrs = format_diag_headers(&resp.headers);
        tracing::debug!(
            %method,
            url = %url,
            status = %resp.status,
            content_type = %ct,
            body_len,
            headers = %hdrs,
            body_snippet = %preview,
            "control-plane HTTP error response"
        );
    } else {
        tracing::debug!(
            %method,
            url = %url,
            status = %resp.status,
            content_type = %ct,
            body_len,
            "control-plane HTTP response"
        );
    }
}

fn format_diag_headers(headers: &HeaderMap) -> String {
    let mut parts = Vec::new();
    for (k, v) in headers {
        let name = k.as_str();
        // Omit full Set-Cookie secrets; summarize cookie names only.
        if name.eq_ignore_ascii_case("set-cookie") {
            let cname = v
                .to_str()
                .ok()
                .and_then(|s| s.split('=').next())
                .unwrap_or("?");
            parts.push(format!("set-cookie:<{}>", cname.trim()));
        } else if let Ok(vs) = v.to_str() {
            parts.push(format!("{name}:{vs}"));
        }
    }
    parts.join(", ")
}

fn truncate_lossy(bytes: &[u8], max_chars: usize) -> String {
    let s = String::from_utf8_lossy(bytes);
    let mut out: String = s.chars().take(max_chars).collect();
    if s.chars().count() > max_chars {
        out.push_str("...");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_firefox_user_agent_and_headers() {
        let ua = firefox_user_agent("160");
        assert!(ua.contains("Firefox/160.0"));
        let mut h = HeaderMap::new();
        apply_firefox_headers(&mut h, &ua);
        assert_eq!(h.get("accept").unwrap(), "*/*");
        assert_eq!(h.get("accept-encoding").unwrap(), "identity");

        let mut oh = HeaderMap::new();
        apply_oauth_headers(&mut oh, &ua);
        assert_eq!(oh.get("sec-fetch-dest").unwrap(), "empty");

        let mut gh = HeaderMap::new();
        apply_guardian_headers(&mut gh, &ua);
        assert_eq!(gh.get("accept").unwrap(), "*/*");
        assert_eq!(gh.get("content-type").unwrap(), "application/json");
        assert_eq!(gh.get("cache-control").unwrap(), "max-age=0");
    }

    #[test]
    fn cookie_jar_supports_domain_cookies_across_firefox_subdomains() {
        let jar = CookieJar::default();
        let site = Url::parse("https://accounts.firefox.com/").unwrap();
        let fxa = Url::parse("https://api.accounts.firefox.com/v1/account/login").unwrap();
        let oauth = Url::parse("https://oauth.accounts.firefox.com/v1/token").unwrap();
        let other = Url::parse("https://vpn.mozilla.org/api/v1/fpn/token").unwrap();

        let mut headers = HeaderMap::new();
        headers.append(
            http::header::SET_COOKIE,
            HeaderValue::from_static("fs_ch=tok123; Domain=.firefox.com; Path=/; HttpOnly"),
        );
        headers.append(
            http::header::SET_COOKIE,
            HeaderValue::from_static("host_only=xyz; Path=/"),
        );
        jar.record_from_headers(&site, &headers);
        jar.record_from_headers(&other, &headers);

        let api_hdr = jar.cookie_header_for(&fxa).unwrap();
        assert_eq!(api_hdr, "fs_ch=tok123");
        let oauth_hdr = jar.cookie_header_for(&oauth).unwrap();
        assert_eq!(oauth_hdr, "fs_ch=tok123");

        let site_hdr = jar.cookie_header_for(&site).unwrap();
        assert!(site_hdr.contains("fs_ch=tok123"));
        assert!(site_hdr.contains("host_only=xyz"));
        assert_eq!(jar.cookie_header_for(&other), None);
    }

    #[test]
    fn cookie_jar_respects_expires_domain_validation_and_path_order() {
        let jar = CookieJar::default();
        let site = Url::parse("https://accounts.firefox.com/_fs-ch-abc/script.js?reload=true").unwrap();

        let mut hdrs = HeaderMap::new();
        // Valid host-only cookie + longer path cookie
        hdrs.append(
            http::header::SET_COOKIE,
            HeaderValue::from_static("a=one; Path=/; HttpOnly; Secure"),
        );
        hdrs.append(
            http::header::SET_COOKIE,
            HeaderValue::from_static("b=two; Path=/_fs-ch-abc; Max-Age=300"),
        );
        // Invalid domain must be rejected rather than converted to host-only
        hdrs.append(
            http::header::SET_COOKIE,
            HeaderValue::from_static("evil=bad; Domain=example.com; Path=/"),
        );
        // Expired cookie must be deleted/ignored rather than sent as "dead="
        hdrs.append(
            http::header::SET_COOKIE,
            HeaderValue::from_static("dead=; Path=/; Expires=Thu, 01 Jan 1970 00:00:00 GMT"),
        );
        hdrs.append(
            http::header::SET_COOKIE,
            HeaderValue::from_static("dead2=; Path=/; Expires=Thu, 01-Jan-1970 00:00:00 GMT"),
        );
        jar.record_from_headers(&site, &hdrs);

        let cookie_hdr = jar.cookie_header_for(&site).unwrap();
        // Longer path cookie precedes shorter path; no attributes leak
        assert_eq!(cookie_hdr, "b=two; a=one");
    }

    #[tokio::test]
    async fn http1_wire_preserves_query_title_case_and_clean_cookies() {
        use crate::tls::RustlsConnector;
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let dialer = ProtectedDialer::new();
        let tls_real = Arc::new(RustlsConnector::new().unwrap());
        let resolver = Arc::new(BootstrapResolver::new(&[], false, dialer.clone(), tls_real, None).unwrap());
        let client = ControlPlaneClient::new(
            resolver,
            dialer,
            Arc::new(RustlsConnector::new().unwrap()),
            NetworkConfig::default(),
        );

        let page_url = Url::parse("https://accounts.firefox.com/").unwrap();
        let mut resp_hdrs = HeaderMap::new();
        resp_hdrs.append(
            http::header::SET_COOKIE,
            HeaderValue::from_static("__fs_c=tok=123; Domain=.firefox.com; Path=/; HttpOnly; Secure"),
        );
        client.cookies.record_from_headers(&page_url, &resp_hdrs);

        let target = Url::parse("https://accounts.firefox.com/_fs-ch-1T1wmsGaOgGaSxcX/script.js?reload=true").unwrap();
        let mut req_hdrs = HeaderMap::new();
        apply_firefox_headers(&mut req_hdrs, "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:158.0) Gecko/20100101 Firefox/158.0");
        req_hdrs.insert(
            http::header::ACCEPT,
            HeaderValue::from_static("text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"),
        );
        let cookie = client.cookies.cookie_header_for(&target).unwrap();
        req_hdrs.insert(http::header::COOKIE, HeaderValue::from_str(&cookie).unwrap());

        let (client_io, mut server_io) = tokio::io::duplex(8192);
        let srv = tokio::spawn(async move {
            let mut buf = Vec::new();
            let mut tmp = [0u8; 2048];
            loop {
                let n = server_io.read(&mut tmp).await.unwrap();
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                    break;
                }
            }
            let _ = server_io
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                .await;
            String::from_utf8_lossy(&buf).into_owned()
        });

        let tls_stream = BoxedTlsStream::new(Box::new(client_io), Some(b"http/1.1".to_vec()));
        let resp = client
            .send_over_tls_stream(
                tls_stream,
                Method::GET,
                &target,
                req_hdrs,
                Bytes::new(),
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(resp.status, StatusCode::OK);

        let wire = srv.await.unwrap();
        assert!(wire.starts_with("GET /_fs-ch-1T1wmsGaOgGaSxcX/script.js?reload=true HTTP/1.1\r\n"), "wire was:\n{wire}");
        assert!(wire.contains("\r\nHost: accounts.firefox.com\r\n"), "wire was:\n{wire}");
        assert!(wire.contains("\r\nCookie: __fs_c=tok=123\r\n"), "wire was:\n{wire}");
        assert!(!wire.contains("Content-Length: 0"), "GET must not emit Content-Length: 0:\n{wire}");
        assert!(!wire.contains("Domain=") && !wire.contains("Path="), "cookie attrs leaked:\n{wire}");
    }

    #[tokio::test]
    async fn challenge_session_pins_peer_reuses_keepalive_and_preserves_multi_cookies() {
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;
        use crate::tls::{BoxStream, BoxedTlsStream, TlsConfig, TlsConnectFuture, TlsConnector};

        #[derive(Debug)]
        struct PlainTls;
        impl TlsConnector for PlainTls {
            fn connect<'a>(
                &'a self,
                stream: BoxStream,
                _config: &'a TlsConfig,
            ) -> TlsConnectFuture<'a> {
                Box::pin(async move { Ok(BoxedTlsStream::new(stream, Some(b"http/1.1".to_vec()))) })
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let accept_count = Arc::new(AtomicUsize::new(0));
        let accept_clone = Arc::clone(&accept_count);

        let srv = tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            accept_clone.fetch_add(1, Ordering::SeqCst);

            // Handle TWO sequential HTTP/1.1 keep-alive requests on the single accepted TCP socket
            for req_idx in 0..2 {
                let mut buf = Vec::new();
                let mut tmp = [0u8; 1024];
                loop {
                    let n = s.read(&mut tmp).await.unwrap();
                    if n == 0 {
                        break;
                    }
                    buf.extend_from_slice(&tmp[..n]);
                    if buf.windows(4).any(|w| w == b"\r\n\r\n") {
                        break;
                    }
                }
                let raw = String::from_utf8_lossy(&buf);
                if req_idx == 0 {
                    assert!(raw.starts_with("GET / HTTP/1.1\r\n"));
                    let resp = concat!(
                        "HTTP/1.1 200 OK\r\n",
                        "Set-Cookie: _fs_ch_st_ABC=\"val+with=eq/and\\\"quote\"; Path=/; HttpOnly; Secure\r\n",
                        "Set-Cookie: extra=second~val; Domain=.firefox.com; Path=/\r\n",
                        "Content-Length: 2\r\n",
                        "Connection: keep-alive\r\n\r\nok"
                    );
                    s.write_all(resp.as_bytes()).await.unwrap();
                } else {
                    assert!(raw.starts_with("GET /_fs-ch-123/script.js?reload=true HTTP/1.1\r\n"));
                    assert!(
                        raw.contains("_fs_ch_st_ABC=\"val+with=eq/and\\\"quote\""),
                        "cookie value mutated:\n{raw}"
                    );
                    assert!(raw.contains("extra=second~val"), "second Set-Cookie dropped:\n{raw}");
                    s.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\njs")
                        .await
                        .unwrap();
                }
            }
        });

        let dialer = ProtectedDialer::new();
        let tls_dyn: Arc<dyn TlsConnector> = Arc::new(PlainTls);
        let resolver = Arc::new(
            BootstrapResolver::new(&[], false, dialer.clone(), Arc::clone(&tls_dyn), None).unwrap(),
        );
        let base_client =
            ControlPlaneClient::new(resolver, dialer, tls_dyn, NetworkConfig::default());
        let solver_client = base_client.with_isolated_cookie_jar();

        let opts = RequestOptions {
            use_cookies: true,
            allow_relay: false,
            prefer_h1: true,
            reuse_connection: true,
            pinned_peer: Some(addr),
            split_mode: HelloSplitMode::Off,
            ..Default::default()
        };

        let r1 = solver_client
            .execute(
                Method::GET,
                "https://accounts.firefox.com/",
                HeaderMap::new(),
                Bytes::new(),
                opts.clone(),
            )
            .await
            .unwrap();
        assert_eq!(r1.body.as_ref(), b"ok");
        assert_eq!(r1.headers.get_all(http::header::SET_COOKIE).iter().count(), 2);

        let r2 = solver_client
            .execute(
                Method::GET,
                "https://accounts.firefox.com/_fs-ch-123/script.js?reload=true",
                HeaderMap::new(),
                Bytes::new(),
                opts,
            )
            .await
            .unwrap();
        assert_eq!(r2.body.as_ref(), b"js");
        assert_eq!(
            accept_count.load(Ordering::SeqCst),
            1,
            "second request should reuse the single keep-alive TCP connection"
        );
        srv.await.unwrap();
    }
}
