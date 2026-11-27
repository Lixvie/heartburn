//! Firefox Accounts (FxA) authentication, HAWK signing, OAuth/PKCE, refresh, and device registration.
//!
//! Every FxA HTTP call routes through `fxa_do_with_406_fallback`, solving Fastly
//! anti-bot challenges (`406 Not Acceptable` with empty or non-JSON body) and
//! replaying with domain-scoped FxA cookies (`fxa/fxa.go`, `signin.go`, `oauth_code.go`).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use bytes::Bytes;
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use pbkdf2::pbkdf2_hmac;
use rand::Rng;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::challenge::{
    CaptchaSolver, FXA_API_ORIGIN, FXA_CHALLENGE_BUDGET, MAX_CHALLENGE_ATTEMPTS,
    solve_fastly_challenge,
};
use crate::controlplane::{
    ControlPlaneClient, ControlResponse, RequestOptions, apply_firefox_headers, apply_oauth_headers,
};
use crate::error::FxaError;
use crate::hellosplit::HelloSplitMode;

pub const FXA_AUTH_SERVER: &str = "https://api.accounts.firefox.com/v1";
pub const FXA_OAUTH_TOKEN_URL: &str = "https://oauth.accounts.firefox.com/v1/token";
pub const FXA_SITE_URL: &str = "https://accounts.firefox.com/";
pub const FIREFOX_CLIENT_ID: &str = "5882386c6d801776";
pub const OAUTH_SCOPE: &str = "profile https://identity.mozilla.com/apps/vpn";
pub const DEVICE_NAME: &str = "Firefox's built-in VPN";
pub const DEVICE_TYPE: &str = "desktop";

const PROTOCOL_VERSION: &str = "identity.mozilla.com/picl/v1/";
const PBKDF2_ROUNDS: u32 = 1000;
const STRETCHED_PW_LEN: usize = 32;
const HKDF_LEN: usize = 32;

const VERIFICATION_METHOD_EMAIL_2FA: &str = "email-2fa";
const FXA_ERRNO_INVALID_PARAMETER: u32 = 107;
const FXA_ERRNO_INVALID_TOKEN: u32 = 108;
const FXA_ERRNO_INCORRECT_EMAIL_CASE: u32 = 120;
pub const FXA_ERRNO_REQUEST_BLOCKED: u32 = 125;

/// Trims and normalizes verification/OTP/unblock codes (stripping spaces and hyphens).
pub fn normalize_code(raw: &str) -> String {
    raw.trim()
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .collect()
}

/// Normalizes an email address (trimmed + ASCII lowercase).
pub fn normalize_email(raw: &str) -> String {
    raw.trim().to_ascii_lowercase()
}

/// Derives the 32-byte (64-hex) FxA `authPW` via PBKDF2-HMAC-SHA256 (1000 rounds)
/// followed by HKDF-SHA256 (`identity.mozilla.com/picl/v1/authPW`).
///
/// Letter case matters because FxA hashes the exact account email string.
pub fn derive_auth_pw(email: &str, password: &str) -> Result<String, FxaError> {
    let trimmed_email = email.trim();
    if trimmed_email.is_empty() || password.is_empty() {
        return Err(FxaError::InvalidInput(
            "email and password must not be empty".into(),
        ));
    }

    let salt = format!("{PROTOCOL_VERSION}quickStretch:{trimmed_email}");
    let mut quick_stretched = [0u8; STRETCHED_PW_LEN];
    pbkdf2_hmac::<Sha256>(
        password.as_bytes(),
        salt.as_bytes(),
        PBKDF2_ROUNDS,
        &mut quick_stretched,
    );

    let hk = Hkdf::<Sha256>::new(None, &quick_stretched);
    let mut auth_pw = [0u8; HKDF_LEN];
    hk.expand(format!("{PROTOCOL_VERSION}authPW").as_bytes(), &mut auth_pw)
        .map_err(|e| FxaError::Crypto(e.to_string()))?;

    Ok(hex::encode(auth_pw))
}

/// Derived HAWK credentials (`id` as 64-char hex + 32-byte HMAC key).
#[derive(Debug, Clone)]
pub struct HawkCredentials {
    pub id: String,
    pub key: [u8; 32],
}

/// Derives HAWK credentials from a hex token using FxA's HKDF context (`"sessionToken"`).
pub fn derive_hawk_credentials(token_hex: &str, context: &str) -> Result<HawkCredentials, FxaError> {
    let raw = hex::decode(token_hex.trim())
        .map_err(|e| FxaError::Crypto(format!("invalid token hex: {e}")))?;
    let hk = Hkdf::<Sha256>::new(None, &raw);
    let mut out = [0u8; 96];
    let info = format!("{PROTOCOL_VERSION}{context}");
    hk.expand(info.as_bytes(), &mut out)
        .map_err(|e| FxaError::Crypto(e.to_string()))?;

    let id = hex::encode(&out[..32]);
    let mut key = [0u8; 32];
    key.copy_from_slice(&out[32..64]);
    Ok(HawkCredentials { id, key })
}

/// Computes an RFC-compliant `Hawk` `Authorization` header for FxA requests.
pub fn build_hawk_header(
    creds: &HawkCredentials,
    method: &str,
    url: &str,
    payload_content_type: Option<&str>,
    body: &[u8],
) -> Result<String, FxaError> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| FxaError::Crypto(e.to_string()))?
        .as_secs();
    let nonce = random_nonce(6);
    build_hawk_header_with_params(creds, method, url, ts, &nonce, payload_content_type, body)
}

/// Deterministic helper exposed for HAWK MAC verification in tests.
pub fn build_hawk_header_with_params(
    creds: &HawkCredentials,
    method: &str,
    url: &str,
    ts: u64,
    nonce: &str,
    payload_content_type: Option<&str>,
    body: &[u8],
) -> Result<String, FxaError> {
    let parsed = url::Url::parse(url)
        .map_err(|e| FxaError::InvalidInput(format!("invalid HAWK URL {url:?}: {e}")))?;
    let host = parsed
        .host_str()
        .ok_or_else(|| FxaError::InvalidInput("HAWK URL missing host".into()))?
        .to_ascii_lowercase();
    let port = parsed.port_or_known_default().unwrap_or(443);

    let mut path_and_query = parsed.path().to_owned();
    if path_and_query.is_empty() {
        path_and_query = "/".to_owned();
    }
    if let Some(q) = parsed.query() {
        path_and_query.push('?');
        path_and_query.push_str(q);
    }

    let hash_b64 = if !body.is_empty() {
        let ct_mime = payload_content_type
            .unwrap_or("application/json")
            .split(';')
            .next()
            .unwrap_or("application/json")
            .trim()
            .to_ascii_lowercase();
        let mut p = Vec::with_capacity(32 + ct_mime.len() + body.len());
        p.extend_from_slice(b"hawk.1.payload\n");
        p.extend_from_slice(ct_mime.as_bytes());
        p.push(b'\n');
        p.extend_from_slice(body);
        p.push(b'\n');
        Some(base64::engine::general_purpose::STANDARD.encode(Sha256::digest(&p)))
    } else {
        None
    };

    let hash_str = hash_b64.as_deref().unwrap_or("");
    let normalized = format!(
        "hawk.1.header\n{ts}\n{nonce}\n{}\n{path_and_query}\n{host}\n{port}\n{hash_str}\n\n",
        method.to_ascii_uppercase()
    );

    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(&creds.key)
        .map_err(|e| FxaError::Crypto(e.to_string()))?;
    mac.update(normalized.as_bytes());
    let mac_b64 = base64::engine::general_purpose::STANDARD.encode(mac.finalize().into_bytes());

    if let Some(h) = hash_b64 {
        Ok(format!(
            "Hawk id=\"{}\", ts=\"{ts}\", nonce=\"{nonce}\", hash=\"{h}\", mac=\"{mac_b64}\"",
            creds.id
        ))
    } else {
        Ok(format!(
            "Hawk id=\"{}\", ts=\"{ts}\", nonce=\"{nonce}\", mac=\"{mac_b64}\"",
            creds.id
        ))
    }
}

fn random_nonce(len: usize) -> String {
    const CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-";
    let mut rng = rand::thread_rng();
    (0..len)
        .map(|_| CHARS[rng.gen_range(0..CHARS.len())] as char)
        .collect()
}

/// FxA session returned by `/account/login`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LoginResponse {
    pub uid: String,
    pub session_token: String,
    #[serde(default)]
    pub verified: bool,
    #[serde(default)]
    pub verification_method: Option<String>,
    #[serde(default)]
    pub verification_reason: Option<String>,
    #[serde(default)]
    pub auth_at: u64,
    #[serde(default)]
    pub email: Option<String>,
}

/// OAuth token pair returned by FxA OAuth endpoints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OAuthTokenResponse {
    pub access_token: String,
    #[serde(default)]
    pub refresh_token: Option<String>,
    #[serde(default)]
    pub expires_in: u64,
    #[serde(default)]
    pub scope: String,
    #[serde(default)]
    pub token_type: String,
}

/// Outcome of `login`, representing either a verified session or pending 2FA/email verification.
#[derive(Debug, Clone)]
pub enum SignInStep {
    Verified(LoginResponse),
    NeedsVerification {
        session: LoginResponse,
        method: String,
    },
}

/// Raw JSON error body returned by FxA endpoints.
#[derive(Debug, Deserialize)]
struct FxaErrorBody {
    #[serde(default)]
    errno: u32,
    #[serde(default)]
    message: String,
    #[serde(default)]
    error: String,
    #[serde(default)]
    email: String,
}

struct BuiltRequest {
    method: Method,
    url: String,
    headers: HeaderMap,
    body: Bytes,
    force_h2: bool,
    prefer_h1: bool,
}

type Fallback406Fn<'a> = &'a mut (dyn FnMut(usize) -> Pin<
    Box<dyn Future<Output = Result<Option<ControlResponse>, FxaError>> + Send + 'a>,
> + Send);

const FXA_INTERACTIVE_CHALLENGE_BUDGET: std::time::Duration = std::time::Duration::from_secs(240);

/// High-level client for Firefox Accounts authentication & OAuth token lifecycle.
#[derive(Clone)]
pub struct FxaClient {
    auth_server: String,
    oauth_token_url: String,
    challenge_hosts: Vec<String>,
    http: ControlPlaneClient,
    captcha: Arc<std::sync::RwLock<Option<Arc<dyn CaptchaSolver>>>>,
}

impl std::fmt::Debug for FxaClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("FxaClient")
            .field("auth_server", &self.auth_server)
            .finish()
    }
}

impl FxaClient {
    /// Creates an [`FxaClient`] using the canonical Mozilla FxA endpoints.
    pub fn new(http: ControlPlaneClient) -> Self {
        Self {
            auth_server: FXA_AUTH_SERVER.to_owned(),
            oauth_token_url: FXA_OAUTH_TOKEN_URL.to_owned(),
            challenge_hosts: vec![
                FXA_API_ORIGIN.to_owned(),
                FXA_SITE_URL.trim_end_matches('/').to_owned(),
            ],
            http,
            captcha: Arc::new(std::sync::RwLock::new(None)),
        }
    }

    /// Creates an [`FxaClient`] with custom endpoints (primarily for mock testing).
    pub fn with_endpoints(
        http: ControlPlaneClient,
        auth_server: impl Into<String>,
        oauth_token_url: impl Into<String>,
    ) -> Self {
        Self {
            auth_server: auth_server.into().trim_end_matches('/').to_owned(),
            oauth_token_url: oauth_token_url.into(),
            challenge_hosts: vec![
                FXA_API_ORIGIN.to_owned(),
                FXA_SITE_URL.trim_end_matches('/').to_owned(),
            ],
            http,
            captcha: Arc::new(std::sync::RwLock::new(None)),
        }
    }

    /// Overrides the ordered host list probed when solving Fastly 406 challenges.
    pub fn with_challenge_hosts(mut self, hosts: Vec<String>) -> Self {
        self.challenge_hosts = hosts;
        self
    }

    /// Installs an optional interactive CAPTCHA solver hook (builder style).
    pub fn with_captcha_solver(self, solver: Arc<dyn CaptchaSolver>) -> Self {
        self.set_captcha_solver(Some(solver));
        self
    }

    /// Installs or clears the interactive CAPTCHA solver hook on this client.
    pub fn set_captcha_solver(&self, solver: Option<Arc<dyn CaptchaSolver>>) {
        if let Ok(mut guard) = self.captcha.write() {
            *guard = solver;
        }
    }

    fn captcha_solver(&self) -> Option<Arc<dyn CaptchaSolver>> {
        self.captcha.read().ok().and_then(|g| g.clone())
    }

    /// Signs into FxA with email + password, transparently solving Fastly 406 challenges,
    /// handling errno `120` canonical email-case correction (`originalLoginEmail`), and
    /// falling back from `"email-2fa"` if a deployment rejects `verificationMethod` (`107`).
    pub async fn login(
        &self,
        email: &str,
        password: &str,
        unblock_code: Option<&str>,
    ) -> Result<SignInStep, FxaError> {
        Box::pin(async move {
            let typed = email.trim();
            match self.login_as(typed, None, password, unblock_code).await {
                Ok(step) => Ok(step),
                Err(FxaError::Api {
                    errno: FXA_ERRNO_INCORRECT_EMAIL_CASE,
                    ..
                }) => {
                    self.login_with_case_recovery(typed, password, unblock_code)
                        .await
                }
                Err(e) => Err(e),
            }
        })
        .await
    }

    async fn login_with_case_recovery(
        &self,
        typed: &str,
        password: &str,
        unblock_code: Option<&str>,
    ) -> Result<SignInStep, FxaError> {
        Box::pin(async move {
            let lower = normalize_email(typed);
            if lower != typed {
                self.login_as(&lower, Some(typed), password, unblock_code)
                    .await
            } else {
                self.login_as(typed, None, password, unblock_code).await
            }
        })
        .await
    }

    async fn login_as(
        &self,
        email: &str,
        original_email: Option<&str>,
        password: &str,
        unblock_code: Option<&str>,
    ) -> Result<SignInStep, FxaError> {
        Box::pin(async move {
            let mut resp = match self
                .login_attempt(
                    email,
                    original_email,
                    password,
                    Some(VERIFICATION_METHOD_EMAIL_2FA),
                    unblock_code,
                )
                .await
            {
                Ok(r) => r,
                Err((
                    FxaError::Api {
                        errno: FXA_ERRNO_INVALID_PARAMETER,
                        ..
                    },
                    _,
                )) => {
                    tracing::debug!(
                        "FxA rejected verificationMethod=email-2fa (errno 107); retrying plain login"
                    );
                    self.login_attempt(email, original_email, password, None, unblock_code)
                        .await
                        .map_err(|(e, _)| e)?
                }
                Err((
                    FxaError::Api {
                        errno: FXA_ERRNO_INCORRECT_EMAIL_CASE,
                        ..
                    },
                    Some(canon),
                )) if canon != email => {
                    tracing::debug!("retrying FxA login with account's canonical email letter case");
                    self.login_attempt(
                        &canon,
                        Some(email),
                        password,
                        Some(VERIFICATION_METHOD_EMAIL_2FA),
                        unblock_code,
                    )
                    .await
                    .map_err(|(e, _)| e)?
                }
                Err((err, _)) => return Err(err),
            };

            if resp.email.is_none() {
                resp.email = Some(email.to_owned());
            }
            if resp.verified {
                Ok(SignInStep::Verified(resp))
            } else {
                let method = resp
                    .verification_method
                    .clone()
                    .filter(|m| !m.is_empty())
                    .unwrap_or_else(|| VERIFICATION_METHOD_EMAIL_2FA.to_owned());
                Ok(SignInStep::NeedsVerification {
                    session: resp,
                    method,
                })
            }
        })
        .await
    }

    async fn login_attempt(
        &self,
        email: &str,
        original_email: Option<&str>,
        password: &str,
        verification_method: Option<&str>,
        unblock_code: Option<&str>,
    ) -> Result<LoginResponse, (FxaError, Option<String>)> {
        Box::pin(async move {
            let auth_pw = derive_auth_pw(email, password).map_err(|e| (e, None))?;

            let mut payload = serde_json::json!({
                "email": email,
                "authPW": auth_pw,
            });
            if let Some(orig) = original_email.filter(|s| !s.is_empty()) {
                payload["originalLoginEmail"] = Value::String(orig.to_owned());
            }
            if let Some(vm) = verification_method.filter(|s| !s.is_empty()) {
                payload["verificationMethod"] = Value::String(vm.to_owned());
            }
            if let Some(code) = unblock_code.map(normalize_code).filter(|c| !c.is_empty()) {
                payload["unblockCode"] = Value::String(code.to_ascii_uppercase());
            }

            let body_bytes =
                Bytes::from(serde_json::to_vec(&payload).map_err(|e| (FxaError::Protocol(e.to_string()), None))?);
            let url = format!("{}/account/login", self.auth_server);
            tracing::debug!(url = %url, has_unblock = unblock_code.is_some(), "attempting FxA /account/login");

            let ua = self.http.user_agent().await;
            let resp = self
                .fxa_do(None, || {
                    let mut hdrs = HeaderMap::new();
                    apply_firefox_headers(&mut hdrs, &ua);
                    hdrs.insert(
                        http::header::CONTENT_TYPE,
                        HeaderValue::from_static("application/json"),
                    );
                    Ok(BuiltRequest {
                        method: Method::POST,
                        url: url.clone(),
                        headers: hdrs,
                        body: body_bytes.clone(),
                        force_h2: false,
                        prefer_h1: true,
                    })
                })
                .await
                .map_err(|e| (e, None))?;

            if resp.status == StatusCode::OK {
                let login: LoginResponse = serde_json::from_slice(&resp.body)
                    .map_err(|e| (FxaError::Protocol(format!("decode /account/login: {e}")), None))?;
                return Ok(login);
            }

            Err(parse_fxa_error_with_email(resp.status, &resp.body))
        })
        .await
    }

    /// Triggers sending a login unblock code email (`errno 125`).
    pub async fn send_unblock_code(&self, email: &str) -> Result<(), FxaError> {
        let payload = serde_json::json!({ "email": email.trim() });
        let resp = self
            .post_json(&format!("{}/account/login/send_unblock_code", self.auth_server), &payload, None)
            .await?;
        expect_success(resp)
    }

    /// Verifies an email OTP / confirmation code on the current `sessionToken`.
    pub async fn verify_email_code(&self, session_token: &str, code: &str) -> Result<(), FxaError> {
        let creds = derive_hawk_credentials(session_token, "sessionToken")?;
        let clean = normalize_code(code);
        let payload = serde_json::json!({
            "code": clean,
        });
        let resp = self
            .post_json(
                &format!("{}/session/verify_code", self.auth_server),
                &payload,
                Some(&creds),
            )
            .await?;
        expect_success(resp)
    }

    /// Re-sends the email verification code for a session.
    pub async fn resend_email_code(&self, session_token: &str) -> Result<(), FxaError> {
        let creds = derive_hawk_credentials(session_token, "sessionToken")?;
        let resp = self
            .post_json(
                &format!("{}/session/resend_code", self.auth_server),
                &serde_json::json!({}),
                Some(&creds),
            )
            .await?;
        expect_success(resp)
    }

    /// Verifies a TOTP authenticator 6-digit code.
    pub async fn verify_totp(&self, session_token: &str, code: &str) -> Result<bool, FxaError> {
        let creds = derive_hawk_credentials(session_token, "sessionToken")?;
        let clean = normalize_code(code);
        let payload = serde_json::json!({ "code": clean });
        let resp = self
            .post_json(
                &format!("{}/session/verify/totp", self.auth_server),
                &payload,
                Some(&creds),
            )
            .await?;
        if resp.status.is_success() {
            let v: Value = serde_json::from_slice(&resp.body)
                .map_err(|e| FxaError::Protocol(format!("decode totp verify: {e}")))?;
            return Ok(v.get("success").and_then(|s| s.as_bool()).unwrap_or(true));
        }
        Err(parse_fxa_error(resp.status, &resp.body))
    }

    /// Polls `/recovery_email/status` until the user verifies a link or OTP.
    pub async fn session_status(&self, session_token: &str) -> Result<bool, FxaError> {
        let creds = derive_hawk_credentials(session_token, "sessionToken")?;
        let url = format!("{}/recovery_email/status", self.auth_server);
        let resp = self.get_hawk(&url, &creds).await?;
        if resp.status.is_success() {
            let v: Value = serde_json::from_slice(&resp.body)
                .map_err(|e| FxaError::Protocol(format!("decode status: {e}")))?;
            let verified = v.get("verified").and_then(|b| b.as_bool()).unwrap_or(false)
                && v.get("sessionVerified")
                    .and_then(|b| b.as_bool())
                    .unwrap_or(true);
            return Ok(verified);
        }
        Err(parse_fxa_error(resp.status, &resp.body))
    }

    /// Registers a desktop VPN device record under the authenticated FxA session.
    pub async fn register_device(&self, session_token: &str) -> Result<String, FxaError> {
        let creds = derive_hawk_credentials(session_token, "sessionToken")?;
        let payload = serde_json::json!({
            "name": DEVICE_NAME,
            "type": DEVICE_TYPE,
        });
        let resp = self
            .post_json(
                &format!("{}/account/device", self.auth_server),
                &payload,
                Some(&creds),
            )
            .await?;
        if resp.status.is_success() {
            let v: Value = serde_json::from_slice(&resp.body).unwrap_or(Value::Null);
            return Ok(v
                .get("id")
                .and_then(|s| s.as_str())
                .unwrap_or_default()
                .to_owned());
        }
        Err(parse_fxa_error(resp.status, &resp.body))
    }

    /// Exchanges a verified `sessionToken` for an offline Mozilla VPN OAuth token pair,
    /// trying direct `fxa-credentials` grant first (with HTTP/2 + PKCE `406` fallbacks
    /// as well as the Fastly challenge solver).
    pub async fn exchange_session_for_oauth(
        &self,
        session_token: &str,
    ) -> Result<OAuthTokenResponse, FxaError> {
        Box::pin(async move {
            let creds = derive_hawk_credentials(session_token, "sessionToken")?;
            let direct_payload = serde_json::json!({
                "client_id": FIREFOX_CLIENT_ID,
                "scope": OAUTH_SCOPE,
                "grant_type": "fxa-credentials",
                "access_type": "offline",
            });
            let body = serde_json::to_vec(&direct_payload)
                .map_err(|e| FxaError::Protocol(e.to_string()))?;
            let token_url = format!("{}/oauth/token", self.auth_server);
            let ua = self.http.user_agent().await;

            let mut on_406 = |solved: usize| -> Pin<Box<dyn Future<Output = Result<Option<ControlResponse>, FxaError>> + Send + '_>> {
                let body = body.clone();
                let token_url = token_url.clone();
                let ua = ua.clone();
                let creds = creds.clone();
                Box::pin(async move {
                    if solved <= 1
                        && let Ok(h2_resp) = self.try_direct_h2_oauth(&token_url, &body, &creds, &ua).await
                        && h2_resp.status != StatusCode::NOT_ACCEPTABLE
                    {
                        return Ok(Some(h2_resp));
                    }
                    match self.try_pkce_oauth(&creds).await {
                        Ok(Some(pkce_resp)) => Ok(Some(pkce_resp)),
                        Ok(None) => Ok(None),
                        Err(e) => Err(e),
                    }
                })
            };

            let resp = self
                .fxa_do(Some(&mut on_406), || {
                    let mut hdrs = HeaderMap::new();
                    apply_oauth_headers(&mut hdrs, &ua);
                    let hawk = build_hawk_header(&creds, "POST", &token_url, Some("application/json"), &body)?;
                    if let Ok(val) = HeaderValue::from_str(&hawk) {
                        hdrs.insert(http::header::AUTHORIZATION, val);
                    }
                    Ok(BuiltRequest {
                        method: Method::POST,
                        url: token_url.clone(),
                        headers: hdrs,
                        body: Bytes::from(body.clone()),
                        force_h2: false,
                        prefer_h1: true,
                    })
                })
                .await?;

            if resp.status.is_success() {
                return serde_json::from_slice(&resp.body)
                    .map_err(|e| FxaError::Protocol(format!("decode oauth token: {e}")));
            }
            Err(parse_fxa_error(resp.status, &resp.body))
        })
        .await
    }

    async fn try_direct_h2_oauth(
        &self,
        url: &str,
        body: &[u8],
        creds: &HawkCredentials,
        ua: &str,
    ) -> Result<ControlResponse, FxaError> {
        Box::pin(async move {
            let mut hdrs = HeaderMap::new();
            apply_oauth_headers(&mut hdrs, ua);
            let hawk = build_hawk_header(creds, "POST", url, Some("application/json"), body)?;
            if let Ok(val) = HeaderValue::from_str(&hawk) {
                hdrs.insert(http::header::AUTHORIZATION, val);
            }
            let parsed = url::Url::parse(url).map_err(|e| FxaError::InvalidInput(e.to_string()))?;
            let opts = RequestOptions {
                force_h2: true,
                use_cookies: true,
                split_mode: HelloSplitMode::Off,
                ..Default::default()
            };
            let resp = self
                .http
                .send_direct(Method::POST, &parsed, hdrs, Bytes::copy_from_slice(body), &opts)
                .await
                .map_err(FxaError::Transport)?;
            tracing::info!(status = %resp.status, "direct OAuth HTTP/2 retry response");
            Ok(resp)
        })
        .await
    }

    async fn try_pkce_oauth(
        &self,
        creds: &HawkCredentials,
    ) -> Result<Option<ControlResponse>, FxaError> {
        Box::pin(async move {
            let verifier = random_nonce(43);
            let challenge = base64::engine::general_purpose::URL_SAFE_NO_PAD
                .encode(Sha256::digest(verifier.as_bytes()));
            let state = random_nonce(16);
            let ua = self.http.user_agent().await;

            let auth_url = format!("{}/oauth/authorization", self.auth_server);
            let auth_body = serde_json::to_vec(&serde_json::json!({
                "client_id": FIREFOX_CLIENT_ID,
                "scope": OAUTH_SCOPE,
                "state": state,
                "access_type": "offline",
                "code_challenge": challenge,
                "code_challenge_method": "S256",
                "response_type": "code",
            }))
            .map_err(|e| FxaError::Protocol(e.to_string()))?;

            let mut auth_hdrs = HeaderMap::new();
            apply_oauth_headers(&mut auth_hdrs, &ua);
            let hawk = build_hawk_header(creds, "POST", &auth_url, Some("application/json"), &auth_body)?;
            if let Ok(val) = HeaderValue::from_str(&hawk) {
                auth_hdrs.insert(http::header::AUTHORIZATION, val);
            }

            let opts = RequestOptions {
                use_cookies: true,
                prefer_h1: true,
                ..Default::default()
            };
            let auth_resp = self
                .http
                .execute(Method::POST, &auth_url, auth_hdrs, Bytes::from(auth_body), opts.clone())
                .await
                .map_err(FxaError::Transport)?;

            if auth_resp.status == StatusCode::NOT_ACCEPTABLE {
                tracing::info!("OAuth /oauth/authorization returned HTTP 406; delegating to challenge solver");
                return Ok(None);
            }
            if !auth_resp.status.is_success() {
                return Err(parse_fxa_error(auth_resp.status, &auth_resp.body));
            }

            let v: Value = serde_json::from_slice(&auth_resp.body)
                .map_err(|e| FxaError::Protocol(format!("decode /oauth/authorization: {e}")))?;
            let code = v
                .get("code")
                .and_then(|c| c.as_str())
                .ok_or_else(|| FxaError::Protocol("missing authorization code".into()))?;

            let tok_body = serde_json::to_vec(&serde_json::json!({
                "client_id": FIREFOX_CLIENT_ID,
                "code": code,
                "code_verifier": verifier,
                "grant_type": "authorization_code",
            }))
            .map_err(|e| FxaError::Protocol(e.to_string()))?;

            let mut tok_hdrs = HeaderMap::new();
            apply_oauth_headers(&mut tok_hdrs, &ua);
            let tok_resp = self
                .http
                .execute(
                    Method::POST,
                    &self.oauth_token_url,
                    tok_hdrs,
                    Bytes::from(tok_body),
                    opts,
                )
                .await
                .map_err(FxaError::Transport)?;

            if tok_resp.status == StatusCode::NOT_ACCEPTABLE {
                return Ok(None);
            }
            if !tok_resp.status.is_success() {
                return Err(parse_fxa_error(tok_resp.status, &tok_resp.body));
            }
            Ok(Some(tok_resp))
        })
        .await
    }

    /// Refreshes an expired `access_token` using `refresh_token`, trying `/v1/oauth/token`
    /// first, falling back to `oauth.accounts.firefox.com/v1/token` and Fastly 406 solving.
    pub async fn refresh_oauth_token(&self, refresh_token: &str) -> Result<OAuthTokenResponse, FxaError> {
        Box::pin(async move {
            let body = serde_json::to_vec(&serde_json::json!({
                "client_id": FIREFOX_CLIENT_ID,
                "grant_type": "refresh_token",
                "refresh_token": refresh_token,
                "scope": OAUTH_SCOPE,
            }))
            .map_err(|e| FxaError::Protocol(e.to_string()))?;

            let primary_url = format!("{}/oauth/token", self.auth_server);
            let ua = self.http.user_agent().await;

            let mut on_406 = |solved: usize| -> Pin<Box<dyn Future<Output = Result<Option<ControlResponse>, FxaError>> + Send + '_>> {
                let body = body.clone();
                let ua = ua.clone();
                Box::pin(async move {
                    if solved != 0 {
                        return Ok(None);
                    }
                    let mut hdrs = HeaderMap::new();
                    apply_oauth_headers(&mut hdrs, &ua);
                    let opts = RequestOptions {
                        use_cookies: true,
                        prefer_h1: true,
                        ..Default::default()
                    };
                    match self
                        .http
                        .execute(Method::POST, &self.oauth_token_url, hdrs, Bytes::from(body), opts)
                        .await
                    {
                        Ok(r) if r.status == StatusCode::OK => {
                            tracing::info!("OAuth refresh accepted by oauth.accounts.firefox.com after 406");
                            Ok(Some(r))
                        }
                        Ok(r) if r.status == StatusCode::NOT_ACCEPTABLE => Ok(None),
                        Ok(r) if r.status == StatusCode::BAD_REQUEST => {
                            let err = parse_fxa_error(r.status, &r.body);
                            if matches!(err, FxaError::Api { errno: FXA_ERRNO_INVALID_TOKEN, .. }) {
                                Err(err)
                            } else {
                                Ok(None)
                            }
                        }
                        _ => Ok(None),
                    }
                })
            };

            let resp = self
                .fxa_do(Some(&mut on_406), || {
                    let mut hdrs = HeaderMap::new();
                    apply_oauth_headers(&mut hdrs, &ua);
                    Ok(BuiltRequest {
                        method: Method::POST,
                        url: primary_url.clone(),
                        headers: hdrs,
                        body: Bytes::from(body.clone()),
                        force_h2: false,
                        prefer_h1: true,
                    })
                })
                .await?;

            if resp.status.is_success() {
                let mut tok: OAuthTokenResponse = serde_json::from_slice(&resp.body)
                    .map_err(|e| FxaError::Protocol(format!("decode refreshed token: {e}")))?;
                if tok.refresh_token.as_deref().unwrap_or("").is_empty() {
                    tok.refresh_token = Some(refresh_token.to_owned());
                }
                return Ok(tok);
            }
            Err(parse_fxa_error(resp.status, &resp.body))
        })
        .await
    }

    /// Invalidates the server-side FxA `sessionToken` (`POST /session/destroy`).
    pub async fn destroy_session(&self, session_token: &str) -> Result<(), FxaError> {
        let creds = derive_hawk_credentials(session_token, "sessionToken")?;
        let resp = self
            .post_json(
                &format!("{}/session/destroy", self.auth_server),
                &serde_json::json!({}),
                Some(&creds),
            )
            .await?;
        expect_success(resp)
    }

    async fn get_hawk(&self, url: &str, creds: &HawkCredentials) -> Result<ControlResponse, FxaError> {
        let ua = self.http.user_agent().await;
        let url_owned = url.to_owned();
        self.fxa_do(None, || {
            let mut hdrs = HeaderMap::new();
            apply_firefox_headers(&mut hdrs, &ua);
            let hawk = build_hawk_header(creds, "GET", &url_owned, None, &[])?;
            if let Ok(val) = HeaderValue::from_str(&hawk) {
                hdrs.insert(http::header::AUTHORIZATION, val);
            }
            Ok(BuiltRequest {
                method: Method::GET,
                url: url_owned.clone(),
                headers: hdrs,
                body: Bytes::new(),
                force_h2: false,
                prefer_h1: true,
            })
        })
        .await
    }

    async fn post_json(
        &self,
        url: &str,
        payload: &Value,
        creds: Option<&HawkCredentials>,
    ) -> Result<ControlResponse, FxaError> {
        let body = serde_json::to_vec(payload).map_err(|e| FxaError::Protocol(e.to_string()))?;
        let ua = self.http.user_agent().await;
        let url_owned = url.to_owned();
        let bytes = Bytes::from(body);

        self.fxa_do(None, || {
            let mut hdrs = HeaderMap::new();
            apply_firefox_headers(&mut hdrs, &ua);
            hdrs.insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            if let Some(c) = creds {
                let hawk = build_hawk_header(c, "POST", &url_owned, Some("application/json"), &bytes)?;
                if let Ok(val) = HeaderValue::from_str(&hawk) {
                    hdrs.insert(http::header::AUTHORIZATION, val);
                }
            }
            Ok(BuiltRequest {
                method: Method::POST,
                url: url_owned.clone(),
                headers: hdrs,
                body: bytes.clone(),
                force_h2: false,
                prefer_h1: true,
            })
        })
        .await
    }

    /// Core FxA executor (`fxaDoWith406Fallback`): sends any FxA request, invokes
    /// optional `on_406` fallback on HTTP `406`, then transparently solves Fastly
    /// anti-bot challenges (up to 5 attempts / 90s budget) and replays with cookies.
    async fn fxa_do<F>(
        &self,
        mut on_406: Option<Fallback406Fn<'_>>,
        build_req: F,
    ) -> Result<ControlResponse, FxaError>
    where
        F: Fn() -> Result<BuiltRequest, FxaError>,
    {
        Box::pin(async move {
            let net = self.http.network_config().await;
            let split_mode: HelloSplitMode = net.hello_split.parse().unwrap_or(HelloSplitMode::Off);
            let mut budget_deadline: Option<Instant> = None;

            for solved in 0..=MAX_CHALLENGE_ATTEMPTS {
                let req = build_req()?;
                let method_str = req.method.as_str().to_owned();
                let path = url::Url::parse(&req.url)
                    .map(|u| u.path().to_owned())
                    .unwrap_or_else(|_| req.url.clone());

                let timeout = match budget_deadline {
                    Some(dl) => dl.saturating_duration_since(Instant::now()),
                    None => RequestOptions::default().timeout,
                };
                if timeout.is_zero() {
                    return Err(FxaError::ChallengeBlocked(
                        "FxA 406 recovery exceeded 90s time budget".into(),
                    ));
                }

                let opts = RequestOptions {
                    split_mode,
                    force_h2: req.force_h2,
                    prefer_h1: req.prefer_h1,
                    follow_redirects: false,
                    use_cookies: true,
                    allow_relay: true,
                    timeout,
                    ..Default::default()
                };

                let resp = self
                    .http
                    .execute(req.method, &req.url, req.headers, req.body, opts)
                    .await
                    .map_err(|e| {
                        if solved > 0 {
                            tracing::warn!(method = %method_str, path = %path, solves = solved, error = %e, "FxA retry ended without HTTP response");
                        }
                        FxaError::Transport(e)
                    })?;

                if solved > 0 {
                    tracing::info!(
                        method = %method_str,
                        path = %path,
                        status = %resp.status,
                        solves = solved,
                        "FxA request replay after Fastly challenge completed"
                    );
                }

                if resp.status != StatusCode::NOT_ACCEPTABLE {
                    return Ok(resp);
                }

                let snippet = String::from_utf8_lossy(&resp.body[..resp.body.len().min(256)]);
                tracing::warn!(
                    method = %method_str,
                    url = %req.url,
                    body_len = resp.body.len(),
                    body_snippet = %snippet,
                    attempt = solved + 1,
                    "FxA server returned HTTP 406 (Fastly anti-bot challenge); starting recovery"
                );

                let captcha_solver = self.captcha_solver();
                let budget = if captcha_solver.is_some() {
                    FXA_INTERACTIVE_CHALLENGE_BUDGET
                } else {
                    FXA_CHALLENGE_BUDGET
                };
                let deadline = *budget_deadline.get_or_insert_with(|| Instant::now() + budget);

                if let Some(ref mut fallback) = on_406
                    && let Some(alt_resp) = fallback(solved).await?
                {
                    return Ok(alt_resp);
                }

                if solved == MAX_CHALLENGE_ATTEMPTS {
                    return Err(FxaError::ChallengeBlocked(format!(
                        "still HTTP 406 after {solved} solved Fastly challenges"
                    )));
                }

                let host_refs: Vec<&str> = self.challenge_hosts.iter().map(String::as_str).collect();
                solve_fastly_challenge(
                    &self.http,
                    &host_refs,
                    captcha_solver.as_deref(),
                    deadline,
                )
                .await
                .inspect_err(|e| {
                    tracing::warn!(attempt = solved + 1, error = %e, "Fastly challenge solve failed");
                })?;
            }

            Err(FxaError::ChallengeBlocked(
                "Fastly challenge retry loop exhausted".into(),
            ))
        })
        .await
    }
}

fn expect_success(resp: ControlResponse) -> Result<(), FxaError> {
    if resp.status.is_success() {
        Ok(())
    } else {
        Err(parse_fxa_error(resp.status, &resp.body))
    }
}

fn parse_fxa_error(status: StatusCode, body: &[u8]) -> FxaError {
    parse_fxa_error_with_email(status, body).0
}

fn parse_fxa_error_with_email(status: StatusCode, body: &[u8]) -> (FxaError, Option<String>) {
    if let Ok(parsed) = serde_json::from_slice::<FxaErrorBody>(body) {
        let msg = if !parsed.message.is_empty() {
            parsed.message
        } else if !parsed.error.is_empty() {
            parsed.error.clone()
        } else {
            "(empty message)".to_owned()
        };
        let email = (!parsed.email.is_empty()).then_some(parsed.email);
        return (
            FxaError::Api {
                status: status.as_u16(),
                errno: parsed.errno,
                code: parsed.error,
                message: msg,
            },
            email,
        );
    }
    let text = String::from_utf8_lossy(body).trim().to_owned();
    let message = if text.is_empty() {
        "(empty response body)".to_owned()
    } else {
        text
    };
    (
        FxaError::Api {
            status: status.as_u16(),
            errno: 0,
            code: status.as_str().to_owned(),
            message,
        },
        None,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{NetworkConfig, IpVersionMode};
    use crate::dialer::{ProtectedDialer, UpstreamSocks5};
    use crate::dns::BootstrapResolver;
    use crate::tls::{BoxStream, BoxedTlsStream, RustlsConnector, TlsConfig, TlsConnector, TlsConnectFuture};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    #[test]
    fn normalizes_codes_and_emails() {
        assert_eq!(normalize_email("  User@Example.COM "), "user@example.com");
        assert_eq!(normalize_code("123 - 456\t78"), "12345678");
    }

    #[test]
    fn derives_auth_pw_and_hawk_credentials_deterministically() {
        let pw1 = derive_auth_pw("User@Example.com", "correct horse").unwrap();
        let pw2 = derive_auth_pw("User@Example.com", "correct horse").unwrap();
        assert_eq!(pw1, pw2);
        assert_eq!(pw1.len(), 64);

        let token = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let creds = derive_hawk_credentials(token, "sessionToken").unwrap();
        assert_eq!(creds.id.len(), 64);

        let hdr = build_hawk_header_with_params(
            &creds,
            "POST",
            "https://api.accounts.firefox.com/v1/oauth/token",
            1700000000,
            "abc123",
            Some("application/json; charset=utf-8"),
            br#"{"grant_type":"fxa-credentials"}"#,
        )
        .unwrap();
        assert!(hdr.starts_with("Hawk id=\""));
        assert!(hdr.contains("hash=\""));
        assert!(hdr.contains("mac=\""));
    }

    #[derive(Debug)]
    struct PassthroughTls;

    impl TlsConnector for PassthroughTls {
        fn connect<'a>(&'a self, stream: BoxStream, _config: &'a TlsConfig) -> TlsConnectFuture<'a> {
            Box::pin(async move { Ok(BoxedTlsStream::new(stream, Some(b"http/1.1".to_vec()))) })
        }
    }

    #[tokio::test]
    async fn solves_empty_body_406_on_login_and_replays_with_cookie() {
        // Local mock SOCKS5 -> HTTP mux handling both api.accounts.firefox.com and accounts.firefox.com.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let socks_addr = listener.local_addr().unwrap();

        let base = "pow-seed-99:";
        let expected_hash = hex::encode(Sha256::digest(b"pow-seed-99:A7"));

        let srv = tokio::spawn(async move {
            let challenged = Arc::new(std::sync::atomic::AtomicBool::new(false));
            let login_attempts = Arc::new(std::sync::atomic::AtomicUsize::new(0));

            loop {
                let Ok((mut s, _)) = listener.accept().await else {
                    break;
                };
                let challenged = Arc::clone(&challenged);
                let login_attempts = Arc::clone(&login_attempts);
                let expected_hash = expected_hash.clone();

                tokio::spawn(async move {
                    // Mock minimal SOCKS5 handshake
                    let mut greet = [0u8; 3];
                    if s.read_exact(&mut greet).await.is_err() {
                        return;
                    }
                    let _ = s.write_all(&[0x05, 0x00]).await;
                    let mut hdr = [0u8; 4];
                    if s.read_exact(&mut hdr).await.is_err() {
                        return;
                    }
                    let mut dlen = [0u8; 1];
                    let _ = s.read_exact(&mut dlen).await;
                    let mut host_buf = vec![0u8; usize::from(dlen[0])];
                    let _ = s.read_exact(&mut host_buf).await;
                    let host = String::from_utf8_lossy(&host_buf).into_owned();
                    let mut pbuf = [0u8; 2];
                    let _ = s.read_exact(&mut pbuf).await;
                    let _ = s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0]).await;

                    // Read single HTTP/1.1 request
                    let mut req_buf = vec![0u8; 8192];
                    let n = match s.read(&mut req_buf).await {
                        Ok(n) if n > 0 => n,
                        _ => return,
                    };
                    let raw = String::from_utf8_lossy(&req_buf[..n]).into_owned();
                    let first_line = raw.lines().next().unwrap_or("");
                    let path = first_line.split_ascii_whitespace().nth(1).unwrap_or("/");
                    let has_solved_cookie = raw.contains("__fs_solved=yes");

                    if host == "api.accounts.firefox.com" && path == "/v1/account/login" {
                        login_attempts.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                        if !has_solved_cookie {
                            // Empty-body HTTP 406 matching live Fastly behavior!
                            let _ = s
                                .write_all(b"HTTP/1.1 406 Not Acceptable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                                .await;
                        } else {
                            let body = r#"{"uid":"u123","sessionToken":"abcd","verified":true,"authAt":1700000000}"#;
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            );
                            let _ = s.write_all(resp.as_bytes()).await;
                        }
                    } else if host == "api.accounts.firefox.com" && path == "/" {
                        let body = "<html>OK API</html>";
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = s.write_all(resp.as_bytes()).await;
                    } else if host == "accounts.firefox.com" && path == "/" {
                        if challenged.load(std::sync::atomic::Ordering::SeqCst) && has_solved_cookie {
                            let body = "<html><body>Signed in</body></html>";
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            );
                            let _ = s.write_all(resp.as_bytes()).await;
                        } else {
                            let body = r#"<html><title>Client Challenge</title><script src="/_fs-ch-test123/script.js?reload=true"></script></html>"#;
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nSet-Cookie: __fs_pre=1; Domain=.firefox.com; Path=/\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            );
                            let _ = s.write_all(resp.as_bytes()).await;
                        }
                    } else if host == "accounts.firefox.com" && path == "/_fs-ch-test123/script.js?reload=true" {
                        let body = format!(
                            r#"init([{{"ty":"pat","data":{{}}}},{{"ty":"pow","data":{{"base":"{base}","expires":"99999","hmac":"hm1","hash":"{expected_hash}"}}}}],"tok-1","/_fs-ch-test123");"#
                        );
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = s.write_all(resp.as_bytes()).await;
                    } else if host == "accounts.firefox.com" && path.starts_with("/_fs-ch-test123/pat") {
                        let _ = s
                            .write_all(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                            .await;
                    } else if host == "accounts.firefox.com" && path == "/_fs-ch-test123/fst-post-back" {
                        // Validate PoW answer in body before issuing cookie
                        if raw.contains("\"answer\":\"A7\"") && raw.contains("\"ty\":\"pat\"") {
                            challenged.store(true, std::sync::atomic::Ordering::SeqCst);
                            let body = r#"{"status":"success"}"#;
                            let resp = format!(
                                "HTTP/1.1 200 OK\r\nSet-Cookie: __fs_solved=yes; Domain=.firefox.com; Path=/\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                body.len()
                            );
                            let _ = s.write_all(resp.as_bytes()).await;
                        } else {
                            let _ = s.write_all(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\n\r\n").await;
                        }
                    }
                });
            }
        });

        let dialer = ProtectedDialer::new();
        let tls_real = Arc::new(RustlsConnector::new().unwrap());
        let resolver = Arc::new(
            BootstrapResolver::new(
                &[],
                false,
                dialer.clone(),
                tls_real,
                Some(UpstreamSocks5 {
                    addr: socks_addr.to_string(),
                    username: String::new(),
                    password: String::new(),
                }),
            )
            .unwrap(),
        );
        let passthrough: Arc<dyn TlsConnector> = Arc::new(PassthroughTls);
        let net = NetworkConfig {
            hello_split: "off".into(),
            ..Default::default()
        };
        let http = ControlPlaneClient::new(resolver, dialer, passthrough, net);
        let fxa = FxaClient::new(http);

        let step = fxa
            .login("user@example.com", "secret-pw", None)
            .await
            .unwrap();
        match step {
            SignInStep::Verified(login) => {
                assert_eq!(login.uid, "u123");
                assert_eq!(login.session_token, "abcd");
            }
            other => panic!("expected verified login after 406 solve, got {other:?}"),
        }

        srv.abort();
        let _ = IpVersionMode::Auto;
    }

    fn build_minimal_client_hello(sni: &str) -> Vec<u8> {
        let mut ext_sni = Vec::new();
        let name = sni.as_bytes();
        let list_len = (3 + name.len()) as u16;
        ext_sni.extend_from_slice(&0x0000u16.to_be_bytes());
        ext_sni.extend_from_slice(&(list_len + 2).to_be_bytes());
        ext_sni.extend_from_slice(&list_len.to_be_bytes());
        ext_sni.push(0x00);
        ext_sni.extend_from_slice(&(name.len() as u16).to_be_bytes());
        ext_sni.extend_from_slice(name);

        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]);
        body.extend_from_slice(&[0xaa; 32]);
        body.push(0x00);
        body.extend_from_slice(&2u16.to_be_bytes());
        body.extend_from_slice(&[0x13, 0x01]);
        body.push(0x01);
        body.push(0x00);
        body.extend_from_slice(&(ext_sni.len() as u16).to_be_bytes());
        body.extend_from_slice(&ext_sni);

        let mut rec = Vec::new();
        rec.push(0x16);
        rec.extend_from_slice(&[0x03, 0x01]);
        rec.extend_from_slice(&((4 + body.len()) as u16).to_be_bytes());
        rec.push(0x01);
        let bl = body.len() as u32;
        rec.extend_from_slice(&bl.to_be_bytes()[1..4]);
        rec.extend_from_slice(&body);
        rec
    }

    fn encode_dns_a_or_aaaa_reply(query: &[u8]) -> Vec<u8> {
        if query.len() < 12 {
            return Vec::new();
        }
        // Extract QTYPE right after QNAME in first question section
        let mut pos = 12usize;
        while pos < query.len() && query[pos] != 0 {
            let l = usize::from(query[pos]);
            pos += 1 + l;
        }
        let q_end = (pos + 5).min(query.len());
        let qtype = if pos + 3 < query.len() {
            u16::from_be_bytes([query[pos + 1], query[pos + 2]])
        } else {
            1
        };

        let mut resp = Vec::new();
        resp.extend_from_slice(&query[..2]); // ID
        resp.extend_from_slice(&[0x81, 0x80]); // QR=1, RD=1, RA=1, RCODE=0
        resp.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
        resp.extend_from_slice(&1u16.to_be_bytes()); // ANCOUNT
        resp.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
        resp.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
        resp.extend_from_slice(&query[12..q_end]); // Question

        // Answer pointing to QNAME at offset 12 (0xc00c)
        resp.extend_from_slice(&[0xc0, 0x0c]);
        resp.extend_from_slice(&qtype.to_be_bytes());
        resp.extend_from_slice(&1u16.to_be_bytes()); // IN
        resp.extend_from_slice(&60u32.to_be_bytes()); // TTL
        if qtype == 28 {
            resp.extend_from_slice(&16u16.to_be_bytes());
            resp.extend_from_slice(&[
                0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01,
                0x02, 0x48, 0x18, 0x93, 0x25, 0xc8, 0x19, 0x46,
            ]);
        } else {
            resp.extend_from_slice(&4u16.to_be_bytes());
            resp.extend_from_slice(&[93, 184, 216, 34]);
        }
        resp
    }

    #[derive(Debug)]
    struct ClientHelloPassthroughTls;

    impl TlsConnector for ClientHelloPassthroughTls {
        fn connect<'a>(
            &'a self,
            mut stream: BoxStream,
            config: &'a TlsConfig,
        ) -> TlsConnectFuture<'a> {
            let sni = config.server_name.clone();
            Box::pin(async move {
                // Trigger SplitStream's ClientHello SNI splitter during connect()
                let hello = build_minimal_client_hello(&sni);
                stream
                    .write_all(&hello)
                    .await
                    .map_err(crate::error::TlsError::Handshake)?;
                stream
                    .flush()
                    .await
                    .map_err(crate::error::TlsError::Handshake)?;
                Ok(BoxedTlsStream::new(stream, Some(b"http/1.1".to_vec())))
            })
        }
    }

    #[test]
    fn cold_doh_and_challenge_flow_survives_one_mib_debug_stack() {
        let handle = std::thread::Builder::new()
            .name("heartburn-1mib-stack-test".into())
            .stack_size(1024 * 1024)
            .spawn(|| {
                let rt = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .unwrap();

                rt.block_on(async {
                    // 1. Mock local DoH server (exercises cold lookup_ip -> query_doh -> hyper -> tls)
                    let doh_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let doh_addr = doh_listener.local_addr().unwrap();
                    let doh_task = tokio::spawn(async move {
                        loop {
                            let Ok((mut s, _)) = doh_listener.accept().await else {
                                break;
                            };
                            tokio::spawn(async move {
                                // Consume ClientHello written by ClientHelloPassthroughTls before HTTP/1.1 DoH POST
                                let mut tls_hdr = [0u8; 5];
                                if s.read_exact(&mut tls_hdr).await.is_err() {
                                    return;
                                }
                                if tls_hdr[0] == 0x16 {
                                    let rec_len = u16::from_be_bytes([tls_hdr[3], tls_hdr[4]]) as usize;
                                    let mut skip = vec![0u8; rec_len];
                                    if s.read_exact(&mut skip).await.is_err() {
                                        return;
                                    }
                                }

                                let mut buf = vec![0u8; 4096];
                                let mut total = 0usize;
                                let header_end;
                                loop {
                                    let n = match s.read(&mut buf[total..]).await {
                                        Ok(n) if n > 0 => n,
                                        _ => return,
                                    };
                                    total += n;
                                    if let Some(pos) = buf[..total].windows(4).position(|w| w == b"\r\n\r\n") {
                                        header_end = pos + 4;
                                        break;
                                    }
                                    if total == buf.len() {
                                        return;
                                    }
                                }
                                let hdr_str = String::from_utf8_lossy(&buf[..header_end]);
                                let content_len = hdr_str
                                    .lines()
                                    .find_map(|l| {
                                        let (k, v) = l.split_once(':')?;
                                        if k.trim().eq_ignore_ascii_case("content-length") {
                                            v.trim().parse::<usize>().ok()
                                        } else {
                                            None
                                        }
                                    })
                                    .unwrap_or(0);
                                while total < header_end + content_len {
                                    let n = match s.read(&mut buf[total..]).await {
                                        Ok(n) if n > 0 => n,
                                        _ => return,
                                    };
                                    total += n;
                                }
                                let dns_req = &buf[header_end..header_end + content_len];
                                let dns_rep = encode_dns_a_or_aaaa_reply(dns_req);
                                let resp_hdr = format!(
                                    "HTTP/1.1 200 OK\r\nContent-Type: application/dns-message\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                                    dns_rep.len()
                                );
                                let _ = s.write_all(resp_hdr.as_bytes()).await;
                                let _ = s.write_all(&dns_rep).await;
                            });
                        }
                    });

                    // 2. Mock SOCKS5 + HTTP mux for FxA + Fastly challenge with synthetic ClientHello consumption
                    let socks_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
                    let socks_addr = socks_listener.local_addr().unwrap();
                    let base = "pow-1mib:";
                    let expected_hash = hex::encode(Sha256::digest(b"pow-1mib:Q2"));

                    let srv_task = tokio::spawn(async move {
                        let challenged = Arc::new(std::sync::atomic::AtomicBool::new(false));
                        loop {
                            let Ok((mut s, _)) = socks_listener.accept().await else {
                                break;
                            };
                            let challenged = Arc::clone(&challenged);
                            let expected_hash = expected_hash.clone();
                            tokio::spawn(async move {
                                let mut greet = [0u8; 3];
                                if s.read_exact(&mut greet).await.is_err() {
                                    return;
                                }
                                let _ = s.write_all(&[0x05, 0x00]).await;
                                let mut hdr = [0u8; 4];
                                if s.read_exact(&mut hdr).await.is_err() {
                                    return;
                                }
                                let mut dlen = [0u8; 1];
                                let _ = s.read_exact(&mut dlen).await;
                                let mut host_buf = vec![0u8; usize::from(dlen[0])];
                                let _ = s.read_exact(&mut host_buf).await;
                                let host = String::from_utf8_lossy(&host_buf).into_owned();
                                let mut pbuf = [0u8; 2];
                                let _ = s.read_exact(&mut pbuf).await;
                                let _ = s.write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0]).await;

                                // Consume SplitStream-fragmented ClientHello TLS record before reading HTTP/1.1
                                let mut tls_hdr = [0u8; 5];
                                if s.read_exact(&mut tls_hdr).await.is_err() {
                                    return;
                                }
                                if tls_hdr[0] == 0x16 {
                                    let rec_len = u16::from_be_bytes([tls_hdr[3], tls_hdr[4]]) as usize;
                                    let mut skip = vec![0u8; rec_len];
                                    if s.read_exact(&mut skip).await.is_err() {
                                        return;
                                    }
                                }

                                let mut req_buf = vec![0u8; 8192];
                                let n = match s.read(&mut req_buf).await {
                                    Ok(n) if n > 0 => n,
                                    _ => return,
                                };
                                let raw = String::from_utf8_lossy(&req_buf[..n]).into_owned();
                                let first_line = raw.lines().next().unwrap_or("");
                                let path = first_line.split_ascii_whitespace().nth(1).unwrap_or("/");
                                let has_solved_cookie = raw.contains("__fs_1mib=ok");

                                if host == "api.accounts.firefox.com" && path == "/v1/account/login" {
                                    if !has_solved_cookie {
                                        let _ = s
                                            .write_all(b"HTTP/1.1 406 Not Acceptable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                                            .await;
                                    } else {
                                        let body = r#"{"uid":"u1mib","sessionToken":"tok1mib","verified":true,"authAt":1700000001}"#;
                                        let resp = format!(
                                            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                            body.len()
                                        );
                                        let _ = s.write_all(resp.as_bytes()).await;
                                    }
                                } else if host == "api.accounts.firefox.com" && path == "/" {
                                    let _ = s
                                        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                                        .await;
                                } else if host == "accounts.firefox.com" && path == "/" {
                                    if challenged.load(std::sync::atomic::Ordering::SeqCst) && has_solved_cookie {
                                        let _ = s
                                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
                                            .await;
                                    } else {
                                        let body = r#"<html><title>Client Challenge</title><script src="/_fs-ch-stackTest1/script.js?reload=true"></script></html>"#;
                                        let resp = format!(
                                            "HTTP/1.1 200 OK\r\nSet-Cookie: __fs_pre=1; Domain=.firefox.com; Path=/\r\nContent-Type: text/html\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                            body.len()
                                        );
                                        let _ = s.write_all(resp.as_bytes()).await;
                                    }
                                } else if host == "accounts.firefox.com"
                                    && path == "/_fs-ch-stackTest1/script.js?reload=true"
                                {
                                    let body = format!(
                                        r#"init([{{"ty":"pow","data":{{"base":"{base}","expires":"99999","hmac":"h1","hash":"{expected_hash}"}}}}],"tok-1mib","/_fs-ch-stackTest1");"#
                                    );
                                    let resp = format!(
                                        "HTTP/1.1 200 OK\r\nContent-Type: application/javascript\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                        body.len()
                                    );
                                    let _ = s.write_all(resp.as_bytes()).await;
                                } else if host == "accounts.firefox.com" && path == "/_fs-ch-stackTest1/fst-post-back" {
                                    challenged.store(true, std::sync::atomic::Ordering::SeqCst);
                                    let body = r#"{"status":"success"}"#;
                                    let resp = format!(
                                        "HTTP/1.1 200 OK\r\nSet-Cookie: __fs_1mib=ok; Domain=.firefox.com; Path=/\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                                        body.len()
                                    );
                                    let _ = s.write_all(resp.as_bytes()).await;
                                }
                            });
                        }
                    });

                    let dialer = ProtectedDialer::new();
                    let hello_tls: Arc<dyn TlsConnector> = Arc::new(ClientHelloPassthroughTls);
                    let cold_resolver = BootstrapResolver::new(
                        &[format!("https://{doh_addr}/dns-query")],
                        false,
                        dialer.clone(),
                        Arc::clone(&hello_tls),
                        None,
                    )
                    .unwrap();

                    // Assert outer future sizes stay compact in debug builds (never inline multi-KB trees)
                    let lookup_fut = cold_resolver.lookup_ip("accounts.firefox.com");
                    assert!(
                        std::mem::size_of_val(&lookup_fut) <= 1024,
                        "lookup_ip future bloated to {} bytes",
                        std::mem::size_of_val(&lookup_fut)
                    );
                    let resolved = lookup_fut.await.unwrap();
                    assert_eq!(resolved[0], "93.184.216.34".parse::<std::net::IpAddr>().unwrap());

                    // Exercise real RustlsConnector construction on the same 1 MiB stack
                    let real_rustls = RustlsConnector::new().unwrap();
                    let (duplex_a, _duplex_b) = tokio::io::duplex(512);
                    drop(_duplex_b);
                    let tls_cfg = TlsConfig {
                        server_name: "accounts.firefox.com".into(),
                        alpn: vec![b"http/1.1".to_vec()],
                        ..Default::default()
                    };
                    let rustls_fut = real_rustls.connect(Box::new(duplex_a), &tls_cfg);
                    assert!(
                        std::mem::size_of_val(&rustls_fut) <= 1024,
                        "TlsConnector::connect future bloated to {} bytes",
                        std::mem::size_of_val(&rustls_fut)
                    );
                    let _ = rustls_fut.await;

                    // Exercise full fxa.login -> 406 -> solve_fastly_challenge -> HelloSplitMode::Auto -> replay on 1 MiB stack
                    let proxy_resolver = Arc::new(
                        BootstrapResolver::new(
                            &[],
                            false,
                            dialer.clone(),
                            Arc::clone(&hello_tls),
                            Some(UpstreamSocks5 {
                                addr: socks_addr.to_string(),
                                username: String::new(),
                                password: String::new(),
                            }),
                        )
                        .unwrap(),
                    );
                    let http = ControlPlaneClient::new(
                        Arc::clone(&proxy_resolver),
                        dialer,
                        hello_tls,
                        NetworkConfig::default(), // hello_split = "auto"
                    );
                    let fxa = FxaClient::new(http.clone());

                    let exec_fut = http.execute(
                        Method::GET,
                        "https://accounts.firefox.com/",
                        HeaderMap::new(),
                        Bytes::new(),
                        RequestOptions::default(),
                    );
                    assert!(
                        std::mem::size_of_val(&exec_fut) <= 2048,
                        "ControlPlaneClient::execute future bloated to {} bytes",
                        std::mem::size_of_val(&exec_fut)
                    );
                    drop(exec_fut);

                    let chal_fut = solve_fastly_challenge(
                        &http,
                        &[],
                        None,
                        Instant::now() + std::time::Duration::from_secs(10),
                    );
                    assert!(
                        std::mem::size_of_val(&chal_fut) <= 1024,
                        "solve_fastly_challenge future bloated to {} bytes",
                        std::mem::size_of_val(&chal_fut)
                    );
                    drop(chal_fut);

                    let login_fut = fxa.login("user@example.com", "secret-pw", None);
                    assert!(
                        std::mem::size_of_val(&login_fut) <= 2048,
                        "FxaClient::login future bloated to {} bytes",
                        std::mem::size_of_val(&login_fut)
                    );

                    match login_fut.await.unwrap() {
                        SignInStep::Verified(s) => assert_eq!(s.uid, "u1mib"),
                        other => panic!("expected Verified login on 1 MiB stack, got {other:?}"),
                    }

                    doh_task.abort();
                    srv_task.abort();
                });
            })
            .expect("spawn 1 MiB stack thread");

        handle
            .join()
            .expect("1 MiB stack thread panicked or overflowed its stack");
    }
}
