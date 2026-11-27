//! Mozilla Guardian client: ProxyPass JWT acquisition, quota polling, 451 bypass,
//! and cached evasion route waterfall (`direct` -> `sni` -> `first-byte` -> `record` -> `relay`).

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use serde::{Deserialize, Serialize};
use url::Url;

use crate::config::{DEFAULT_GUARDIAN_ENDPOINT, NetworkConfig};
use crate::controlplane::{ControlPlaneClient, ControlResponse, RequestOptions, apply_guardian_headers};
use crate::error::GuardianError;
use crate::hellosplit::HelloSplitMode;
use crate::storage::Storage;

const ROUTE_CACHE_FILE: &str = "guardian-route.json";
const ROUTE_CACHE_TTL: Duration = Duration::from_secs(30 * 60);
const TOKEN_REQUEST_BUDGET: Duration = Duration::from_secs(25);
const CLOCK_SKEW_ANCHOR_THRESHOLD: Duration = Duration::from_secs(60);

/// Decoded Guardian ProxyPass JWT metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyPassInfo {
    /// Raw JWT bearer string sent in `Proxy-Authorization: Bearer <token>`.
    pub token: String,
    /// Anchored UNIX expiration timestamp (seconds).
    pub expires_at: u64,
    /// Original JWT `iat` claim if present.
    pub issued_at: Option<u64>,
    /// Subject (`sub`) claim if present.
    pub subject: Option<String>,
}

impl ProxyPassInfo {
    /// Returns remaining lifetime before expiration relative to current wall clock.
    pub fn remaining(&self) -> Duration {
        let now = unix_now();
        Duration::from_secs(self.expires_at.saturating_sub(now))
    }
}

/// Bandwidth quota state parsed from Guardian `X-Quota-*` response headers.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProxyUsage {
    pub limit_bytes: u64,
    pub remaining_bytes: u64,
    pub used_bytes: u64,
    pub reset_at: Option<String>,
    pub checked_at: u64,
}

impl ProxyUsage {
    /// Usage fraction from `0.0` to `100.0`, or `0.0` if `limit_bytes == 0`.
    pub fn used_percent(&self) -> f64 {
        if self.limit_bytes == 0 {
            return 0.0;
        }
        (self.used_bytes as f64 / self.limit_bytes as f64) * 100.0
    }

    /// Returns `true` when remaining quota has hit 0 on a bounded quota plan.
    pub fn is_exhausted(&self) -> bool {
        self.limit_bytes > 0 && self.remaining_bytes == 0
    }
}

/// Cached working route variant for Guardian API requests (`guardian/route_cache.go`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum GuardianRouteKind {
    Direct,
    SplitSni,
    SplitFirstByte,
    SplitRecord,
    PersonalRelay,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct CachedGuardianRoute {
    route: GuardianRouteKind,
    cached_at_unix: u64,
}

/// Guardian API client (`https://vpn.mozilla.org`).
#[derive(Clone)]
pub struct GuardianClient {
    endpoint: String,
    http: ControlPlaneClient,
    network: NetworkConfig,
    storage: std::sync::Arc<dyn Storage>,
}

impl std::fmt::Debug for GuardianClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("GuardianClient")
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

impl GuardianClient {
    pub fn new(
        endpoint: impl Into<String>,
        http: ControlPlaneClient,
        network: NetworkConfig,
        storage: std::sync::Arc<dyn Storage>,
    ) -> Self {
        let ep = endpoint.into();
        let clean = if ep.trim().is_empty() {
            DEFAULT_GUARDIAN_ENDPOINT.to_owned()
        } else {
            ep.trim().trim_end_matches('/').to_owned()
        };
        Self {
            endpoint: clean,
            http,
            network,
            storage,
        }
    }

    /// Calls `POST /api/v1/fpn/activate` to ensure Mozilla VPN entitlement is provisioned.
    pub async fn activate(&self, access_token: &str) -> Result<(), GuardianError> {
        let url = format!("{}/api/v1/fpn/activate", self.endpoint);
        let resp = self
            .request_with_cascade(Method::POST, &url, access_token, Bytes::new())
            .await?;
        if resp.status.is_success() {
            Ok(())
        } else {
            Err(map_guardian_status(resp.status, &resp.headers, &resp.body))
        }
    }

    /// Acquires a fresh Guardian ProxyPass JWT (`GET /api/v1/fpn/token`) using
    /// the cached working route or cascading fallback across DPI workarounds within 25s.
    pub async fn fetch_proxy_pass(&self, access_token: &str) -> Result<ProxyPassInfo, GuardianError> {
        let url = format!("{}/api/v1/fpn/token", self.endpoint);
        let resp = tokio::time::timeout(
            TOKEN_REQUEST_BUDGET,
            self.request_with_cascade(Method::GET, &url, access_token, Bytes::new()),
        )
        .await
        .map_err(|_| GuardianError::Transport("Guardian ProxyPass request exceeded 25s budget".into()))??;

        if !resp.status.is_success() {
            return Err(map_guardian_status(resp.status, &resp.headers, &resp.body));
        }

        let json: serde_json::Value = serde_json::from_slice(&resp.body)
            .map_err(|e| GuardianError::Protocol(format!("invalid /api/v1/fpn/token JSON: {e}")))?;
        let token = json
            .get("token")
            .and_then(|v| v.as_str())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| GuardianError::Protocol("missing \"token\" field in Guardian response".into()))?
            .to_owned();

        let server_now = parse_http_date(resp.header("date"));
        parse_proxy_pass_jwt(&token, server_now)
    }

    /// Queries account quota usage via `HEAD /api/v1/fpn/token` (`X-Quota-*` headers),
    /// falling back once to `GET /api/v1/fpn/token` on HTTP 403 (`guardian/guardian.go`).
    pub async fn fetch_proxy_usage(&self, access_token: &str) -> Result<ProxyUsage, GuardianError> {
        let url = format!("{}/api/v1/fpn/token", self.endpoint);
        let mut resp = self
            .request_with_cascade(Method::HEAD, &url, access_token, Bytes::new())
            .await?;
        if resp.status == StatusCode::FORBIDDEN {
            resp = self
                .request_with_cascade(Method::GET, &url, access_token, Bytes::new())
                .await?;
        }
        if resp.status == StatusCode::TOO_MANY_REQUESTS && has_quota_headers(&resp.headers) {
            return parse_proxy_usage_headers(&resp.headers, unix_now());
        }
        if !resp.status.is_success() {
            return Err(map_guardian_status(resp.status, &resp.headers, &resp.body));
        }
        parse_proxy_usage_headers(&resp.headers, unix_now())
    }

    /// Clears cached Guardian route preference so the next call re-probes routes.
    pub async fn invalidate_route_cache(&self) {
        let _ = self.storage.remove(ROUTE_CACHE_FILE).await;
    }

    async fn request_with_cascade(
        &self,
        method: Method,
        url: &str,
        access_token: &str,
        body: Bytes,
    ) -> Result<ControlResponse, GuardianError> {
        Box::pin(async move {
            let route_order = self.build_route_order().await;
            let idempotent = method == Method::GET || method == Method::HEAD;
            let mut last_resp: Option<ControlResponse> = None;
            let mut last_err: Option<GuardianError> = None;

            for route in route_order {
                let res = self
                    .execute_on_route(route, method.clone(), url, access_token, body.clone())
                    .await;

                match res {
                    Ok(resp) if resp.status == StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS => {
                        // HTTP 451: Mozilla geo-fence workaround retries directly with doubled slash `//api/...`
                        // before considering relays (`guardian/region_recovery.go`).
                        if let Some(doubled) = double_api_slash(url)
                            && let Ok(r2) = self
                                .execute_on_route(route, method.clone(), &doubled, access_token, body.clone())
                                .await
                            && r2.status != StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS
                        {
                            if r2.status.is_success() {
                                self.save_cached_route(route).await;
                            } else if r2.status == StatusCode::UNAUTHORIZED {
                                log_guardian_unauthorized(&method, &doubled, route, access_token);
                            }
                            return Ok(r2);
                        }
                        last_err = Some(GuardianError::RegionBlocked);
                        continue;
                    }
                    Ok(resp) if resp.status == StatusCode::UNAUTHORIZED => {
                        log_guardian_unauthorized(&method, url, route, access_token);
                        return Ok(resp);
                    }
                    Ok(resp)
                        if idempotent
                            && (resp.status == StatusCode::NOT_ACCEPTABLE
                                || resp.status.is_server_error()) =>
                    {
                        last_resp = Some(resp);
                        continue;
                    }
                    Ok(resp) => {
                        if resp.status.is_success() {
                            self.save_cached_route(route).await;
                        }
                        return Ok(resp);
                    }
                    Err(e) => {
                        last_err = Some(e);
                        continue;
                    }
                }
            }

            if let Some(resp) = last_resp {
                return Ok(resp);
            }
            Err(last_err.unwrap_or_else(|| {
                GuardianError::Transport("all Guardian request routes failed".into())
            }))
        })
        .await
    }

    async fn execute_on_route(
        &self,
        route: GuardianRouteKind,
        method: Method,
        url: &str,
        access_token: &str,
        body: Bytes,
    ) -> Result<ControlResponse, GuardianError> {
        Box::pin(async move {
            let ua = self.http.user_agent().await;
            let mut hdrs = HeaderMap::new();
            apply_guardian_headers(&mut hdrs, &ua);
            let bearer = format!("Bearer {}", access_token.trim());
            let auth_val = HeaderValue::from_str(&bearer)
                .map_err(|_| GuardianError::Protocol("invalid access token characters".into()))?;
            hdrs.insert(http::header::AUTHORIZATION, auth_val);

            if route == GuardianRouteKind::PersonalRelay {
                let relay_base = self.network.api_relay_in_use();
                if relay_base.is_empty() {
                    return Err(GuardianError::Transport("personal relay not enabled".into()));
                }
                let target = Url::parse(url)
                    .map_err(|e| GuardianError::Protocol(format!("invalid Guardian URL: {e}")))?;
                let opts = RequestOptions {
                    split_mode: HelloSplitMode::Off,
                    allow_relay: false,
                    ..Default::default()
                };
                return self
                    .http
                    .send_via_relay_url(relay_base, method, &target, hdrs, body, &self.network, &opts)
                    .await
                    .map_err(GuardianError::Transport);
            }

            let split_mode = match route {
                GuardianRouteKind::Direct => HelloSplitMode::Off,
                GuardianRouteKind::SplitSni => HelloSplitMode::Sni,
                GuardianRouteKind::SplitFirstByte => HelloSplitMode::FirstByte,
                GuardianRouteKind::SplitRecord => HelloSplitMode::Record,
                GuardianRouteKind::PersonalRelay => HelloSplitMode::Off,
            };
            let opts = RequestOptions {
                split_mode,
                allow_relay: false,
                ..Default::default()
            };
            self.http
                .execute(method, url, hdrs, body, opts)
                .await
                .map_err(GuardianError::Transport)
        })
        .await
    }

    async fn build_route_order(&self) -> Vec<GuardianRouteKind> {
        let mut base = vec![
            GuardianRouteKind::Direct,
            GuardianRouteKind::SplitSni,
            GuardianRouteKind::SplitFirstByte,
            GuardianRouteKind::SplitRecord,
        ];
        if !self.network.api_relay_in_use().is_empty() {
            base.push(GuardianRouteKind::PersonalRelay);
        }

        if let Some(cached) = self.load_cached_route().await
            && let Some(pos) = base.iter().position(|&r| r == cached)
        {
            base.remove(pos);
            base.insert(0, cached);
        }
        base
    }

    async fn load_cached_route(&self) -> Option<GuardianRouteKind> {
        let bytes = self.storage.read(ROUTE_CACHE_FILE).await.ok().flatten()?;
        let parsed: CachedGuardianRoute = serde_json::from_slice(&bytes).ok()?;
        let age = unix_now().saturating_sub(parsed.cached_at_unix);
        if age <= ROUTE_CACHE_TTL.as_secs() {
            Some(parsed.route)
        } else {
            None
        }
    }

    async fn save_cached_route(&self, route: GuardianRouteKind) {
        let rec = CachedGuardianRoute {
            route,
            cached_at_unix: unix_now(),
        };
        if let Ok(json) = serde_json::to_vec(&rec) {
            let _ = self.storage.write(ROUTE_CACHE_FILE, &json).await;
        }
    }
}

/// Summarizes non-secret bearer token format metadata for HTTP 401 diagnostics.
///
/// Never emits the raw token string, signature, or JWT claims payload.
pub fn summarize_bearer_token_metadata(token: &str) -> String {
    let trimmed = token.trim();
    let has_whitespace = trimmed.len() != token.len();
    let len = trimmed.len();
    let parts: Vec<&str> = if trimmed.is_empty() {
        Vec::new()
    } else {
        trimmed.split('.').collect()
    };

    if parts.len() == 3 {
        let hdr_info = decode_jwt_header_meta(parts[0]);
        return format!(
            "kind=jwt parts=3 len={len} whitespace={has_whitespace} {hdr_info}"
        );
    }

    let is_hex = !trimmed.is_empty() && trimmed.bytes().all(|b| b.is_ascii_hexdigit());
    format!(
        "kind=opaque parts={} len={len} hex={is_hex} whitespace={has_whitespace}",
        parts.len()
    )
}

fn decode_jwt_header_meta(header_b64: &str) -> String {
    let trimmed = header_b64.trim_end_matches('=');
    let Ok(bytes) = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(trimmed)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(header_b64))
    else {
        return "hdr=invalid_base64".to_owned();
    };
    let Ok(val) = serde_json::from_slice::<serde_json::Value>(&bytes) else {
        return "hdr=invalid_json".to_owned();
    };
    let alg = val.get("alg").and_then(|v| v.as_str()).unwrap_or("-");
    let typ = val.get("typ").and_then(|v| v.as_str()).unwrap_or("-");
    let has_kid = val.get("kid").and_then(|v| v.as_str()).is_some_and(|s| !s.is_empty());
    format!("alg={alg} typ={typ} has_kid={has_kid}")
}

fn log_guardian_unauthorized(
    method: &Method,
    url: &str,
    route: GuardianRouteKind,
    access_token: &str,
) {
    let token_meta = summarize_bearer_token_metadata(access_token);
    tracing::debug!(
        %method,
        url = %url,
        route = ?route,
        %token_meta,
        "Guardian returned HTTP 401 Unauthorized"
    );
}

/// Parses JWT payload claims without verifying the HMAC/RSA signature (server-issued opaque token)
/// and anchors expiration against `server_now` when local clock drift exceeds 60 seconds.
pub fn parse_proxy_pass_jwt(token: &str, server_now: Option<u64>) -> Result<ProxyPassInfo, GuardianError> {
    let mut parts = token.split('.');
    let _hdr = parts.next();
    let payload_b64 = parts
        .next()
        .ok_or_else(|| GuardianError::Protocol("ProxyPass JWT missing payload segment".into()))?;
    let payload_bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(payload_b64)
        .or_else(|_| base64::engine::general_purpose::URL_SAFE.decode(payload_b64))
        .map_err(|e| GuardianError::Protocol(format!("decode JWT payload: {e}")))?;

    #[derive(Deserialize)]
    struct Claims {
        exp: Option<u64>,
        iat: Option<u64>,
        nbf: Option<u64>,
        sub: Option<String>,
    }
    let claims: Claims = serde_json::from_slice(&payload_bytes)
        .map_err(|e| GuardianError::Protocol(format!("parse JWT claims: {e}")))?;

    let mut exp = claims
        .exp
        .ok_or_else(|| GuardianError::Protocol("ProxyPass JWT missing \"exp\" claim".into()))?;

    // Anchor claims against server Date header if local clock is skewed > 1 minute (`guardian/pass.go`).
    let local_now = unix_now();
    let start_claim = claims.nbf.filter(|&v| v > 0).or(claims.iat.filter(|&v| v > 0));
    if let Some(srv) = server_now {
        let drift = srv.abs_diff(local_now);
        if drift > CLOCK_SKEW_ANCHOR_THRESHOLD.as_secs() {
            if let Some(start) = start_claim {
                let ttl = exp.saturating_sub(start);
                exp = local_now.saturating_add(ttl);
            } else {
                let remaining = exp.saturating_sub(srv);
                exp = local_now.saturating_add(remaining);
            }
        }
    }

    Ok(ProxyPassInfo {
        token: token.to_owned(),
        expires_at: exp,
        issued_at: claims.iat,
        subject: claims.sub,
    })
}

fn has_quota_headers(headers: &HeaderMap) -> bool {
    headers
        .get("x-quota-unlimited")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.trim().eq_ignore_ascii_case("true"))
        || (parse_u64_header(headers, "x-quota-limit").is_some()
            && parse_u64_header(headers, "x-quota-remaining").is_some())
}

/// Extracts bandwidth quota fields from Guardian `X-Quota-*` HTTP response headers.
pub fn parse_proxy_usage_headers(headers: &HeaderMap, checked_at: u64) -> Result<ProxyUsage, GuardianError> {
    let unlimited = headers
        .get("x-quota-unlimited")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s.trim().eq_ignore_ascii_case("true"));
    if unlimited {
        return Ok(ProxyUsage {
            limit_bytes: 0,
            remaining_bytes: 0,
            used_bytes: 0,
            reset_at: None,
            checked_at,
        });
    }

    let limit = parse_u64_header(headers, "x-quota-limit").unwrap_or(0);
    let remaining = parse_u64_header(headers, "x-quota-remaining").unwrap_or(limit);
    let used = parse_u64_header(headers, "x-quota-used")
        .unwrap_or_else(|| limit.saturating_sub(remaining));
    let reset_at = headers
        .get("x-quota-reset")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_owned());

    Ok(ProxyUsage {
        limit_bytes: limit,
        remaining_bytes: remaining,
        used_bytes: used,
        reset_at,
        checked_at,
    })
}

fn parse_u64_header(headers: &HeaderMap, name: &str) -> Option<u64> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok())
}

fn map_guardian_status(status: StatusCode, headers: &HeaderMap, body: &[u8]) -> GuardianError {
    match status {
        StatusCode::UNAUTHORIZED => GuardianError::Unauthorized,
        StatusCode::FORBIDDEN => GuardianError::NoSubscription,
        StatusCode::TOO_MANY_REQUESTS => {
            let retry_after = headers
                .get(http::header::RETRY_AFTER)
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.trim().parse::<u64>().ok())
                .map(Duration::from_secs);
            GuardianError::RateLimited { retry_after }
        }
        StatusCode::UNAVAILABLE_FOR_LEGAL_REASONS => GuardianError::RegionBlocked,
        _ => GuardianError::Http {
            status: status.as_u16(),
            message: String::from_utf8_lossy(body).into_owned(),
        },
    }
}

fn double_api_slash(url: &str) -> Option<String> {
    url.find("/api/").map(|idx| {
        let mut out = String::with_capacity(url.len() + 1);
        out.push_str(&url[..idx]);
        out.push('/');
        out.push_str(&url[idx..]);
        out
    })
}

fn parse_http_date(raw: Option<&str>) -> Option<u64> {
    let s = raw?.trim();
    // Standard IMF-fixdate: "Sun, 06 Nov 1994 08:49:37 GMT"
    let fmt = time::format_description::well_known::Rfc2822;
    time::OffsetDateTime::parse(s, &fmt)
        .ok()
        .and_then(|dt| u64::try_from(dt.unix_timestamp()).ok())
}

pub(crate) fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proxy_pass_jwt_and_anchors_clock_skew() {
        let hdr = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256"}"#);
        let now = unix_now();
        // Pretend server clock is 2 hours ahead of local clock with a 300s token TTL.
        let server_iat = now + 7200;
        let server_exp = server_iat + 300;
        let payload = format!(r#"{{"iat":{server_iat},"exp":{server_exp},"sub":"user-1"}}"#);
        let payload_b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(payload.as_bytes());
        let jwt = format!("{hdr}.{payload_b64}.sig");

        let info = parse_proxy_pass_jwt(&jwt, Some(server_iat)).unwrap();
        let rem = info.remaining().as_secs();
        assert!((295..=305).contains(&rem), "anchored remaining was {rem}");
        assert_eq!(info.subject.as_deref(), Some("user-1"));
    }

    #[test]
    fn parses_quota_headers_and_percent() {
        let mut h = HeaderMap::new();
        h.insert("x-quota-limit", HeaderValue::from_static("53687091200")); // 50 GiB
        h.insert("x-quota-remaining", HeaderValue::from_static("2684354560")); // 2.5 GiB left -> 95% used

        let usage = parse_proxy_usage_headers(&h, 12345).unwrap();
        assert_eq!(usage.limit_bytes, 53_687_091_200);
        assert_eq!(usage.remaining_bytes, 2_684_354_560);
        assert_eq!(usage.used_bytes, 51_002_736_640);
        assert!((usage.used_percent() - 95.0).abs() < 0.001);
        assert!(!usage.is_exhausted());
    }

    #[test]
    fn doubles_api_slash_for_451_retry() {
        assert_eq!(
            double_api_slash("https://vpn.mozilla.org/api/v1/fpn/token").as_deref(),
            Some("https://vpn.mozilla.org//api/v1/fpn/token")
        );
    }

    #[test]
    fn summarizes_bearer_token_metadata_without_leaking_secrets() {
        let hdr = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"alg":"RS256","typ":"at+JWT","kid":"20190730-54ff956e"}"#);
        let payload = base64::engine::general_purpose::URL_SAFE_NO_PAD
            .encode(br#"{"sub":"secret-user-id","scope":"vpn"}"#);
        let jwt = format!("{hdr}.{payload}.secret-sig-value");

        let meta = summarize_bearer_token_metadata(&jwt);
        assert!(meta.contains("kind=jwt"));
        assert!(meta.contains("parts=3"));
        assert!(meta.contains("alg=RS256"));
        assert!(meta.contains("typ=at+JWT"));
        assert!(meta.contains("has_kid=true"));
        assert!(!meta.contains("secret-user-id"));
        assert!(!meta.contains("secret-sig-value"));
        assert!(!meta.contains("20190730-54ff956e"));

        let opaque = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let opaque_meta = summarize_bearer_token_metadata(opaque);
        assert!(opaque_meta.contains("kind=opaque"));
        assert!(opaque_meta.contains("len=64"));
        assert!(opaque_meta.contains("hex=true"));
        assert!(!opaque_meta.contains("0123456789abcdef"));
    }

    #[tokio::test]
    async fn fetches_proxy_pass_via_get_and_quota_via_head_with_403_fallback() {
        use std::sync::Arc;
        use std::sync::atomic::{AtomicUsize, Ordering};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        use crate::dialer::{ProtectedDialer, UpstreamSocks5};
        use crate::dns::BootstrapResolver;
        use crate::storage::MemoryStorage;
        use crate::tls::{BoxStream, BoxedTlsStream, TlsConfig, TlsConnectFuture, TlsConnector};

        #[derive(Debug)]
        struct PassthroughTls;
        impl TlsConnector for PassthroughTls {
            fn connect<'a>(
                &'a self,
                stream: BoxStream,
                _config: &'a TlsConfig,
            ) -> TlsConnectFuture<'a> {
                Box::pin(async move { Ok(BoxedTlsStream::new(stream, Some(b"http/1.1".to_vec()))) })
            }
        }

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = listener.local_addr().unwrap();

        let pass_hdr =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(br#"{"alg":"HS256"}"#);
        let exp = unix_now() + 600;
        let pass_claims =
            base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(format!(r#"{{"exp":{exp}}}"#));
        let pass_jwt = format!("{pass_hdr}.{pass_claims}.sig");

        let head_calls = Arc::new(AtomicUsize::new(0));
        let head_calls_srv = Arc::clone(&head_calls);
        let pass_jwt_srv = pass_jwt.clone();

        let srv = tokio::spawn(async move {
            let mut handles = Vec::with_capacity(3);
            for _ in 0..3 {
                let (mut s, _) = listener.accept().await.unwrap();
                let head_calls_srv = Arc::clone(&head_calls_srv);
                let pass_jwt_srv = pass_jwt_srv.clone();
                handles.push(tokio::spawn(async move {
                    let mut greet = [0u8; 3];
                    s.read_exact(&mut greet).await.unwrap();
                    s.write_all(&[0x05, 0x00]).await.unwrap();
                    let mut hdr = [0u8; 4];
                    s.read_exact(&mut hdr).await.unwrap();
                    let mut dlen = [0u8; 1];
                    s.read_exact(&mut dlen).await.unwrap();
                    let mut host_buf = vec![0u8; usize::from(dlen[0])];
                    s.read_exact(&mut host_buf).await.unwrap();
                    let mut pbuf = [0u8; 2];
                    s.read_exact(&mut pbuf).await.unwrap();
                    s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                        .await
                        .unwrap();

                    let mut req_buf = Vec::new();
                    let mut tmp = [0u8; 2048];
                    loop {
                        let n = s.read(&mut tmp).await.unwrap();
                        if n == 0 {
                            break;
                        }
                        req_buf.extend_from_slice(&tmp[..n]);
                        if req_buf.windows(4).any(|w| w == b"\r\n\r\n") {
                            break;
                        }
                    }
                    let raw = String::from_utf8_lossy(&req_buf);
                    let first = raw.lines().next().unwrap_or("");
                    assert!(
                        raw.to_ascii_lowercase().contains("authorization: bearer tok-123"),
                        "missing bearer auth:\n{raw}"
                    );
                    assert!(
                        raw.to_ascii_lowercase().contains("content-type: application/json"),
                        "missing Guardian Content-Type:\n{raw}"
                    );
                    assert!(
                        raw.to_ascii_lowercase().contains("cache-control: max-age=0"),
                        "missing Cache-Control:\n{raw}"
                    );

                    if first.starts_with("HEAD /api/v1/fpn/token ") {
                        head_calls_srv.fetch_add(1, Ordering::SeqCst);
                        s.write_all(
                            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                        )
                        .await
                        .unwrap();
                    } else if first.starts_with("GET /api/v1/fpn/token ") {
                        let body = format!(r#"{{"token":"{pass_jwt_srv}"}}"#);
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nX-Quota-Limit: 1000\r\nX-Quota-Remaining: 750\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        s.write_all(resp.as_bytes()).await.unwrap();
                    } else {
                        panic!("unexpected Guardian wire request line: {first:?}");
                    }
                }));
            }
            for h in handles {
                h.await.unwrap();
            }
        });

        let dialer = ProtectedDialer::new();
        let tls_dyn: Arc<dyn TlsConnector> = Arc::new(PassthroughTls);
        let resolver = Arc::new(
            BootstrapResolver::new(
                &[],
                false,
                dialer.clone(),
                Arc::clone(&tls_dyn),
                Some(UpstreamSocks5 {
                    addr: socks_addr.to_string(),
                    username: String::new(),
                    password: String::new(),
                }),
            )
            .unwrap(),
        );
        let http = ControlPlaneClient::new(resolver, dialer, tls_dyn, NetworkConfig::default());
        let storage = Arc::new(MemoryStorage::new());
        let guardian =
            GuardianClient::new("https://guardian.invalid", http, NetworkConfig::default(), storage);

        let pass = guardian.fetch_proxy_pass("tok-123").await.unwrap();
        assert_eq!(pass.token, pass_jwt);

        let usage = guardian.fetch_proxy_usage("tok-123").await.unwrap();
        assert_eq!(head_calls.load(Ordering::SeqCst), 1);
        assert_eq!(usage.limit_bytes, 1000);
        assert_eq!(usage.remaining_bytes, 750);

        srv.await.unwrap();
    }
}
