//! Fastly client-challenge solver for Firefox Accounts (`fxa/challenge.go`).
//!
//! When any FxA endpoint answers HTTP `406 Not Acceptable` (usually with an empty
//! body), Fastly requires solving the JavaScript anti-bot challenge served at
//! `https://api.accounts.firefox.com/` or `https://accounts.firefox.com/`:
//!
//! 1. Probe host root with an isolated fresh cookie jar to detect `"/_fs-ch-..."` +
//!    `"Client Challenge"`.
//! 2. Fetch `{base}{prefix}/script.js?reload=true` and parse the `init([...], token, prefix)` call.
//! 3. Answer `pow` (brute-forcing the 2-char alphanumeric suffix), `pat` (`POST /pat`, treating
//!    400/401 as abort so Fastly falls back cleanly to PoW), `clientmetrics`, and optional
//!    user-supplied `captcha` (delegated via [`CaptchaSolver`], never bypassed).
//! 4. Post answers to `POST {base}{prefix}/fst-post-back` up to 8 rounds until `"status": "success"`.
//! 5. Re-probe `{base}/` to verify clearance, then install issued cookies across
//!    `api.accounts.firefox.com`, `oauth.accounts.firefox.com`, and `accounts.firefox.com`.

use std::future::Future;
use std::pin::Pin;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::{HeaderMap, HeaderValue, Method, StatusCode};
use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::Mutex;
use url::Url;

use crate::controlplane::{ControlPlaneClient, RequestOptions, apply_firefox_headers};
use crate::error::FxaError;
use crate::hellosplit::HelloSplitMode;

pub const FXA_API_ORIGIN: &str = "https://api.accounts.firefox.com";
pub const FXA_SITE_ORIGIN: &str = "https://accounts.firefox.com";
pub const FXA_OAUTH_ORIGIN: &str = "https://oauth.accounts.firefox.com";

const POW_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// Maximum number of Fastly challenge solves within a single FxA request attempt.
pub const MAX_CHALLENGE_ATTEMPTS: usize = 5;

/// Total recovery budget after the first HTTP 406 (`fxa.go`).
pub const FXA_CHALLENGE_BUDGET: Duration = Duration::from_secs(90);

/// Timeout per full Fastly challenge solve (`challenge.go`).
pub const FASTLY_SOLVE_TIMEOUT: Duration = Duration::from_secs(60);

/// Extended timeout when an interactive user CAPTCHA solver is attached.
pub const INTERACTIVE_SOLVE_TIMEOUT: Duration = Duration::from_secs(180);

const HTTP_HOP_TIMEOUT_CAP: Duration = Duration::from_secs(30);

const MAX_POSTBACK_ROUNDS: usize = 8;

const QUERY_ENCODE_SET: &AsciiSet = &NON_ALPHANUMERIC
    .remove(b'-')
    .remove(b'_')
    .remove(b'.')
    .remove(b'~');

/// Global lock serializing Fastly challenge solves across concurrent FxA tasks
/// (equivalent to Go's `challengeSolveSlot`).
static CHALLENGE_SOLVE_LOCK: std::sync::OnceLock<Mutex<()>> = std::sync::OnceLock::new();

fn challenge_lock() -> &'static Mutex<()> {
    CHALLENGE_SOLVE_LOCK.get_or_init(|| Mutex::new(()))
}

/// Optional callback hook invoked only when Fastly requires solving a visual image CAPTCHA.
pub trait CaptchaSolver: Send + Sync + std::fmt::Debug {
    /// Displays `image_data_url` (`data:image/...`) to the user and returns their answer.
    fn solve_captcha<'a>(
        &'a self,
        image_data_url: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, FxaError>> + Send + 'a>>;
}

#[derive(Debug, Clone, Deserialize)]
pub struct FastlyChallengeTask {
    #[serde(default)]
    pub ty: String,
    #[serde(default)]
    pub data: serde_json::Value,
}

#[derive(Debug, Deserialize)]
struct FastlyPowData {
    #[serde(default)]
    base: String,
    #[serde(default)]
    expires: String,
    #[serde(default)]
    hmac: String,
    #[serde(default)]
    hash: String,
}

#[derive(Debug, Serialize)]
struct FastlyPostBackReq {
    token: String,
    data: Vec<serde_json::Value>,
}

#[derive(Debug, Deserialize)]
struct FastlyPostBackResp {
    #[serde(default)]
    status: String,
    #[serde(default)]
    ch: Vec<FastlyChallengeTask>,
    #[serde(default)]
    tok: String,
}

/// Brute-forces the 2-character alphanumeric suffix such that lowercase hex
/// `SHA-256(base + suffix) == target_hash_hex` (`62 * 62 = 3844` checks).
pub fn solve_pow(base: &str, target_hash_hex: &str) -> Option<String> {
    let want = target_hash_hex.trim().to_ascii_lowercase();
    if want.len() != 64 || !want.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let prefix = base.as_bytes();
    let mut buf = Vec::with_capacity(prefix.len() + 2);
    buf.extend_from_slice(prefix);
    buf.push(0);
    buf.push(0);

    for &a in POW_ALPHABET {
        buf[prefix.len()] = a;
        for &b in POW_ALPHABET {
            buf[prefix.len() + 1] = b;
            let digest = Sha256::digest(&buf);
            if hex::encode(digest) == want {
                return String::from_utf8(vec![a, b]).ok();
            }
        }
    }
    None
}

/// Extracts `<script ...>...</script>` (or opening `<script ...>` tag) snippets from challenge HTML
/// for diagnostics under verbose logging.
pub fn extract_script_tags(page: &str) -> Vec<String> {
    let lower = page.to_ascii_lowercase();
    let mut tags = Vec::new();
    let mut pos = 0usize;
    while let Some(rel) = lower[pos..].find("<script") {
        let start = pos + rel;
        let rest_orig = &page[start..];
        let rest_lower = &lower[start..];
        if let Some(close_rel) = rest_lower.find("</script>") {
            let end = close_rel + "</script>".len();
            tags.push(rest_orig[..end.min(256)].to_owned());
            pos = start + end;
        } else if let Some(gt_rel) = rest_lower.find('>') {
            let end = gt_rel + 1;
            tags.push(rest_orig[..end.min(256)].to_owned());
            pos = start + end;
        } else {
            break;
        }
    }
    tags
}

/// Extracts the Fastly asset prefix (`/_fs-ch-[A-Za-z0-9]+`) from a challenge HTML page.
pub fn find_challenge_prefix(page: &str) -> Option<String> {
    let needle = "/_fs-ch-";
    let start = page.find(needle)?;
    let rest = &page[start + needle.len()..];
    let suffix_len = rest
        .bytes()
        .take_while(|b| b.is_ascii_alphanumeric())
        .count();
    if suffix_len == 0 {
        return None;
    }
    Some(page[start..start + needle.len() + suffix_len].to_owned())
}

/// Reports whether an HTML body is Fastly's Client Challenge interstitial.
pub fn is_challenge_page_body(body: &str) -> bool {
    body.contains("/_fs-ch-") && body.contains("Client Challenge")
}

/// Extracts `(challenges, token)` from the last valid `init([challenges], "token", "prefix", ...)`
/// call inside Fastly's `/script.js` matching `prefix` (`challenge.go:parseChallengeInit`).
pub fn parse_challenge_init(
    script: &str,
    prefix: &str,
) -> Result<(Vec<FastlyChallengeTask>, String), FxaError> {
    let call_positions = find_init_call_starts(script);
    let mut legacy_match: Option<(Vec<FastlyChallengeTask>, String)> = None;

    for &(fn_start, bracket_idx) in call_positions.iter().rev() {
        let slice = &script[bracket_idx..];
        let Some((challenges, token, script_prefix, rest)) = decode_challenge_init_args(slice)
        else {
            continue;
        };

        if script_prefix != prefix
            || token.is_empty()
            || challenges.is_empty()
            || challenges.iter().any(|c| c.ty.is_empty())
        {
            continue;
        }

        if has_challenge_init_delimiter(rest) {
            return Ok((challenges, token));
        }

        let consumed = &script[fn_start..script.len() - rest.len()];
        if legacy_match.is_none()
            && consumed.starts_with("init([")
            && has_legacy_challenge_init_delimiter(rest)
        {
            legacy_match = Some((challenges, token));
        }
    }

    legacy_match.ok_or_else(|| {
        FxaError::ChallengeBlocked("valid Fastly challenge init() call not found in script.js".into())
    })
}

fn find_init_call_starts(script: &str) -> Vec<(usize, usize)> {
    let bytes = script.as_bytes();
    let mut results = Vec::new();
    let mut i = 0usize;

    while let Some(rel) = script[i..].find("init") {
        let pos = i + rel;
        let prev_ok = pos == 0
            || (!bytes[pos - 1].is_ascii_alphanumeric() && bytes[pos - 1] != b'_');
        if prev_ok {
            let mut j = pos + 4;
            while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                j += 1;
            }
            if bytes.get(j) == Some(&b'(') {
                j += 1;
                while j < bytes.len() && bytes[j].is_ascii_whitespace() {
                    j += 1;
                }
                if bytes.get(j) == Some(&b'[') {
                    results.push((pos, j));
                }
            }
        }
        i = pos + 4;
    }
    results
}

fn decode_challenge_init_args(
    rest_with_bracket: &str,
) -> Option<(Vec<FastlyChallengeTask>, String, String, &str)> {
    let (challenges, after1) = decode_one_json::<Vec<FastlyChallengeTask>>(rest_with_bracket)?;
    let after1 = after1.trim_start().strip_prefix(',')?;
    let (token, after2) = decode_one_json::<String>(after1.trim_start())?;
    let after2 = after2.trim_start().strip_prefix(',')?;
    let (script_prefix, after3) = decode_one_json::<String>(after2.trim_start())?;
    Some((challenges, token, script_prefix, after3.trim_start()))
}

fn decode_one_json<'a, T: for<'de> Deserialize<'de>>(src: &'a str) -> Option<(T, &'a str)> {
    let mut stream = serde_json::Deserializer::from_str(src).into_iter::<T>();
    let val = stream.next()?.ok()?;
    let end = stream.byte_offset();
    Some((val, &src[end..]))
}

fn has_challenge_init_delimiter(rest: &str) -> bool {
    if rest.starts_with(')') {
        return true;
    }
    rest.strip_prefix(',')
        .is_some_and(|after| !after.trim().is_empty())
}

fn has_legacy_challenge_init_delimiter(mut rest: &str) -> bool {
    while let Some(after_open) = rest.strip_prefix("/*") {
        let Some((_, after_close)) = after_open.split_once("*/") else {
            return false;
        };
        rest = after_close.trim_start();
    }
    has_challenge_init_delimiter(rest)
}

fn client_metrics_answer() -> serde_json::Value {
    serde_json::json!({
        "ty": "clientmetrics",
        "webdriver": false,
        "bot_detection_result": { "bot_detected": false, "bot_kind": null },
        "browser_metrics": { "client_data": "{}", "error_trace": null },
        "detector_results": {},
        "v": 2
    })
}

/// Performs the complete Fastly anti-bot challenge handshake against `api.accounts.firefox.com`
/// (falling back to `accounts.firefox.com`) and installs earned cookies onto `main_client`.
pub async fn solve_fastly_challenge(
    main_client: &ControlPlaneClient,
    hosts: &[&str],
    captcha_solver: Option<&dyn CaptchaSolver>,
    budget_deadline: Instant,
) -> Result<(), FxaError> {
    Box::pin(async move {
        let _slot = tokio::time::timeout(
            budget_deadline.saturating_duration_since(Instant::now()),
            challenge_lock().lock(),
        )
        .await
        .map_err(|_| FxaError::ChallengeBlocked("timed out waiting for challenge solver lock".into()))?;

        let solve_cap = if captcha_solver.is_some() {
            INTERACTIVE_SOLVE_TIMEOUT
        } else {
            FASTLY_SOLVE_TIMEOUT
        };
        let deadline =
            Instant::now() + solve_cap.min(budget_deadline.saturating_duration_since(Instant::now()));
        let effective_hosts = if hosts.is_empty() {
            &[FXA_API_ORIGIN, FXA_SITE_ORIGIN][..]
        } else {
            hosts
        };

        let mut last_err: Option<FxaError> = None;
        for &base in effective_hosts {
            let rem = deadline.saturating_duration_since(Instant::now());
            if rem.is_zero() {
                return Err(FxaError::ChallengeBlocked("Fastly challenge solve timed out".into()));
            }
            let clean_base = base.trim_end_matches('/');
            tracing::debug!(host = %clean_base, "probing host for Fastly Client Challenge");

            match solve_challenge_on_host(main_client, clean_base, captcha_solver, deadline).await {
                Ok(()) => return Ok(()),
                Err(ChallengeHostError::NoChallengePage) => {
                    tracing::debug!(host = %clean_base, "host served normal page instead of Fastly challenge");
                    last_err = Some(FxaError::ChallengeBlocked(format!(
                        "{clean_base} did not serve a Fastly challenge page"
                    )));
                    continue;
                }
                Err(ChallengeHostError::Other(err)) => {
                    tracing::warn!(host = %clean_base, error = %err, "Fastly challenge attempt failed on host");
                    last_err = Some(err);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| {
            FxaError::ChallengeBlocked("no host served a solvable Fastly challenge page".into())
        }))
    })
    .await
}

enum ChallengeHostError {
    NoChallengePage,
    Other(FxaError),
}

async fn solve_challenge_on_host(
    main_client: &ControlPlaneClient,
    base: &str,
    captcha_solver: Option<&dyn CaptchaSolver>,
    deadline: Instant,
) -> Result<(), ChallengeHostError> {
    Box::pin(async move {
        let started = Instant::now();
        let solver_client = main_client.with_isolated_cookie_jar();
        let ua = solver_client.user_agent().await;
        let net = solver_client.network_config().await;
        let split_mode: HelloSplitMode = net.hello_split.parse().unwrap_or(HelloSplitMode::Off);
        let page_url = format!("{base}/");

        let (page, is_chal) =
            fetch_challenge_page(&solver_client, &ua, &page_url, split_mode, deadline).await?;
        if !is_chal {
            return Err(ChallengeHostError::NoChallengePage);
        }

        let prefix = find_challenge_prefix(&page).ok_or_else(|| {
            ChallengeHostError::Other(FxaError::ChallengeBlocked(format!(
                "challenge asset prefix /_fs-ch-... not found on {base}"
            )))
        })?;
        let script_tags = extract_script_tags(&page);
        tracing::debug!(
            host = %base,
            prefix = %prefix,
            page_len = page.len(),
            user_agent = %ua,
            script_tags = ?script_tags,
            "detected Fastly challenge page"
        );

        let script_url = format!("{base}{prefix}/script.js?reload=true");
        let script = fetch_text(
            &solver_client,
            &ua,
            &script_url,
            "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            split_mode,
            deadline,
        )
        .await
        .map_err(|e| {
            tracing::warn!(
                host = %base,
                script_url = %script_url,
                user_agent = %ua,
                script_tags = ?script_tags,
                error = %e,
                "Fastly challenge script fetch failed"
            );
            ChallengeHostError::Other(FxaError::ChallengeBlocked(format!(
                "fetching challenge script {script_url}: {e}"
            )))
        })?;

        let (mut challenges, mut token) =
            parse_challenge_init(&script, &prefix).map_err(ChallengeHostError::Other)?;
        let initial_types: Vec<&str> = challenges.iter().map(|c| c.ty.as_str()).collect();
        tracing::debug!(
            host = %base,
            prefix = %prefix,
            script_len = script.len(),
            challenges = ?initial_types,
            "parsed Fastly script.js initial challenges"
        );

        let mut solved_kinds = Vec::new();
        let prefix_url = format!("{base}{prefix}");

        for round in 0..MAX_POSTBACK_ROUNDS {
            let round_types: Vec<&str> = challenges.iter().map(|c| c.ty.as_str()).collect();
            tracing::debug!(
                host = %base,
                round = round + 1,
                challenges = ?round_types,
                "answering Fastly challenge round"
            );

            let mut answers = Vec::with_capacity(challenges.len());
            for ch in &challenges {
                solved_kinds.push(ch.ty.clone());
                let ans = answer_challenge(
                    &solver_client,
                    &ua,
                    base,
                    &prefix_url,
                    &token,
                    ch,
                    captcha_solver,
                    split_mode,
                    deadline,
                )
                .await
                .map_err(ChallengeHostError::Other)?;
                answers.push(ans);
            }

            let postback_url = format!("{prefix_url}/fst-post-back");
            let payload = serde_json::to_vec(&FastlyPostBackReq {
                token: token.clone(),
                data: answers,
            })
            .map_err(|e| ChallengeHostError::Other(FxaError::Protocol(e.to_string())))?;

            let mut hdrs = HeaderMap::new();
            apply_firefox_headers(&mut hdrs, &ua);
            hdrs.insert(
                http::header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            hdrs.insert(
                http::header::ACCEPT,
                HeaderValue::from_static("application/json"),
            );
            if let Ok(orig) = HeaderValue::from_str(base) {
                hdrs.insert(http::header::ORIGIN, orig);
            }

            let opts = RequestOptions {
                use_cookies: true,
                allow_relay: false,
                prefer_h1: true,
                reuse_connection: true,
                split_mode,
                timeout: remaining_timeout(deadline)?.min(HTTP_HOP_TIMEOUT_CAP),
                ..Default::default()
            };

            let resp = solver_client
                .execute(Method::POST, &postback_url, hdrs, Bytes::from(payload), opts)
                .await
                .map_err(|e| {
                    ChallengeHostError::Other(FxaError::ChallengeBlocked(format!(
                        "challenge post-back error: {e}"
                    )))
                })?;

            let pb_snippet = String::from_utf8_lossy(&resp.body[..resp.body.len().min(512)]);
            tracing::debug!(
                host = %base,
                round = round + 1,
                status = %resp.status,
                body_len = resp.body.len(),
                body_snippet = %pb_snippet,
                "Fastly /fst-post-back HTTP response"
            );

            if resp.status != StatusCode::OK {
                return Err(ChallengeHostError::Other(FxaError::ChallengeBlocked(format!(
                    "challenge post-back returned HTTP {}",
                    resp.status
                ))));
            }

            let pb_resp: FastlyPostBackResp = serde_json::from_slice(&resp.body).map_err(|e| {
                ChallengeHostError::Other(FxaError::ChallengeBlocked(format!(
                    "parsing post-back JSON: {e}"
                )))
            })?;

            let next_types: Vec<&str> = pb_resp.ch.iter().map(|c| c.ty.as_str()).collect();
            tracing::debug!(
                host = %base,
                round = round + 1,
                status = %pb_resp.status,
                next_challenges = ?next_types,
                "parsed Fastly challenge post-back JSON"
            );

            if pb_resp.status == "success" {
                let (_, still_challenged) =
                    fetch_challenge_page(&solver_client, &ua, &page_url, split_mode, deadline)
                        .await?;
                if still_challenged {
                    return Err(ChallengeHostError::Other(FxaError::ChallengeBlocked(
                        "challenge cookie was not accepted on probe request".into(),
                    )));
                }

                install_challenge_cookies(&solver_client, main_client, &page_url)
                    .map_err(ChallengeHostError::Other)?;

                tracing::info!(
                    host = %base.trim_start_matches("https://"),
                    challenges = %solved_kinds.join(","),
                    rounds = round + 1,
                    took_ms = started.elapsed().as_millis(),
                    "Fastly challenge solved and cookies installed"
                );
                return Ok(());
            }

            if pb_resp.ch.is_empty() || pb_resp.tok.is_empty() {
                return Err(ChallengeHostError::Other(FxaError::ChallengeBlocked(
                    "challenge post-back missing follow-up round data".into(),
                )));
            }
            challenges = pb_resp.ch;
            token = pb_resp.tok;
        }

        Err(ChallengeHostError::Other(FxaError::ChallengeBlocked(format!(
            "Fastly challenge did not finish within {MAX_POSTBACK_ROUNDS} rounds"
        ))))
    })
    .await
}

async fn fetch_challenge_page(
    client: &ControlPlaneClient,
    ua: &str,
    page_url: &str,
    split_mode: HelloSplitMode,
    deadline: Instant,
) -> Result<(String, bool), ChallengeHostError> {
    Box::pin(async move {
        let accept = "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8";
        let body = fetch_text(client, ua, page_url, accept, split_mode, deadline)
            .await
            .map_err(|e| ChallengeHostError::Other(FxaError::Transport(e)))?;
        let is_chal = is_challenge_page_body(&body);
        Ok((body, is_chal))
    })
    .await
}

async fn fetch_text(
    client: &ControlPlaneClient,
    ua: &str,
    url: &str,
    accept: &str,
    split_mode: HelloSplitMode,
    deadline: Instant,
) -> Result<String, String> {
    Box::pin(async move {
        let mut hdrs = HeaderMap::new();
        apply_firefox_headers(&mut hdrs, ua);
        if let Ok(v) = HeaderValue::from_str(accept) {
            hdrs.insert(http::header::ACCEPT, v);
        }

        let rem = deadline
            .saturating_duration_since(Instant::now())
            .min(HTTP_HOP_TIMEOUT_CAP)
            .max(Duration::from_secs(1));
        let opts = RequestOptions {
            use_cookies: true,
            allow_relay: false,
            prefer_h1: true,
            follow_redirects: true,
            reuse_connection: true,
            split_mode,
            timeout: rem,
            ..Default::default()
        };

        let resp = client
            .execute(Method::GET, url, hdrs, Bytes::new(), opts)
            .await?;
        if resp.status != StatusCode::OK {
            return Err(format!("GET {url} returned HTTP {}", resp.status));
        }
        Ok(String::from_utf8_lossy(&resp.body).into_owned())
    })
    .await
}

#[allow(clippy::too_many_arguments)]
async fn answer_challenge(
    client: &ControlPlaneClient,
    ua: &str,
    base: &str,
    prefix_url: &str,
    token: &str,
    ch: &FastlyChallengeTask,
    captcha_solver: Option<&dyn CaptchaSolver>,
    split_mode: HelloSplitMode,
    deadline: Instant,
) -> Result<serde_json::Value, FxaError> {
    Box::pin(async move {
        match ch.ty.as_str() {
            "pow" => {
                let d: FastlyPowData = serde_json::from_value(ch.data.clone())
                    .map_err(|e| FxaError::ChallengeBlocked(format!("parsing pow challenge: {e}")))?;
                let base_str = d.base.clone();
                let hash_str = d.hash.clone();
                let answer = tokio::task::spawn_blocking(move || solve_pow(&base_str, &hash_str))
                    .await
                    .map_err(|e| FxaError::ChallengeBlocked(e.to_string()))?
                    .ok_or_else(|| {
                        FxaError::ChallengeBlocked(format!(
                            "no proof-of-work solution found for base {:?}",
                            d.base
                        ))
                    })?;
                tracing::debug!(expires = %d.expires, "solved Fastly PoW challenge");
                Ok(serde_json::json!({
                    "ty": "pow",
                    "base": d.base,
                    "answer": answer,
                    "hmac": d.hmac,
                    "expires": d.expires,
                }))
            }
            "pat" => {
                let auth = fetch_pat(client, ua, base, prefix_url, token, split_mode, deadline).await?;
                tracing::debug!(auth_len = auth.len(), "completed Fastly PAT step");
                Ok(serde_json::json!({ "ty": "pat", "auth": auth }))
            }
            "clientmetrics" => {
                tracing::debug!("answering Fastly clientmetrics challenge");
                Ok(client_metrics_answer())
            }
            "captcha" => {
                let solver = captcha_solver.ok_or_else(|| {
                    FxaError::ChallengeBlocked(
                        "Fastly requires an interactive image CAPTCHA challenge".into(),
                    )
                })?;
                let img = ch
                    .data
                    .get("image_b64")
                    .and_then(|v| v.as_str())
                    .filter(|s| s.starts_with("data:image/"))
                    .ok_or_else(|| {
                        FxaError::ChallengeBlocked("unrecognized CAPTCHA challenge data".into())
                    })?;
                tracing::debug!(image_len = img.len(), "invoking interactive CAPTCHA solver");
                let answer = solver.solve_captcha(img).await?;
                Ok(serde_json::json!({ "ty": "captcha", "answer": answer.trim() }))
            }
            other => Err(FxaError::ChallengeBlocked(format!(
                "unsupported Fastly challenge type {other:?}"
            ))),
        }
    })
    .await
}

#[allow(clippy::too_many_arguments)]
async fn fetch_pat(
    client: &ControlPlaneClient,
    ua: &str,
    base: &str,
    prefix_url: &str,
    token: &str,
    split_mode: HelloSplitMode,
    deadline: Instant,
) -> Result<String, FxaError> {
    Box::pin(async move {
        let encoded_tok = utf8_percent_encode(token, QUERY_ENCODE_SET);
        let pat_url = format!("{prefix_url}/pat?token={encoded_tok}");

        let mut hdrs = HeaderMap::new();
        apply_firefox_headers(&mut hdrs, ua);
        hdrs.insert(http::header::ACCEPT, HeaderValue::from_static("text/plain"));
        hdrs.insert(
            http::header::CONTENT_TYPE,
            HeaderValue::from_static("application/json"),
        );
        if let Ok(orig) = HeaderValue::from_str(base) {
            hdrs.insert(http::header::ORIGIN, orig);
        }

        let rem = deadline
            .saturating_duration_since(Instant::now())
            .min(HTTP_HOP_TIMEOUT_CAP)
            .max(Duration::from_secs(1));
        let opts = RequestOptions {
            use_cookies: true,
            allow_relay: false,
            prefer_h1: true,
            reuse_connection: true,
            split_mode,
            timeout: rem,
            ..Default::default()
        };

        let resp = client
            .execute(Method::POST, &pat_url, hdrs, Bytes::new(), opts)
            .await
            .map_err(|e| FxaError::ChallengeBlocked(format!("PAT request error: {e}")))?;

        if matches!(resp.status, StatusCode::UNAUTHORIZED | StatusCode::BAD_REQUEST) {
            // Returning empty auth tells Fastly server to fall back to solvable PoW challenge.
            tracing::debug!(status = %resp.status, "PAT aborted cleanly (expected PoW fallback)");
            return Ok(String::new());
        }
        if resp.status != StatusCode::OK {
            return Err(FxaError::ChallengeBlocked(format!(
                "PAT request returned HTTP {}",
                resp.status
            )));
        }
        #[derive(Deserialize)]
        struct PatOut {
            #[serde(default)]
            auth: String,
        }
        let parsed: PatOut = serde_json::from_slice(&resp.body)
            .map_err(|e| FxaError::ChallengeBlocked(format!("parsing PAT response: {e}")))?;
        if parsed.auth.is_empty() {
            return Err(FxaError::ChallengeBlocked("empty PAT auth token".into()));
        }
        Ok(parsed.auth)
    })
    .await
}

fn install_challenge_cookies(
    solver_client: &ControlPlaneClient,
    main_client: &ControlPlaneClient,
    page_url: &str,
) -> Result<(), FxaError> {
    let parsed = Url::parse(page_url)
        .map_err(|e| FxaError::ChallengeBlocked(format!("invalid challenge URL: {e}")))?;
    let cookies = solver_client.cookies_for(&parsed);
    if cookies.is_empty() {
        return Err(FxaError::ChallengeBlocked(
            "Fastly challenge completed but no cookies were issued".into(),
        ));
    }

    let names: Vec<&str> = cookies.iter().map(|c| c.name.as_str()).collect();
    tracing::debug!(cookie_names = ?names, "installing Fastly challenge cookies onto FxA origins");

    // Mirror Go's cookiejar.Jar.Cookies() -> SetCookies(): install origin-scoped copies with path "/".
    let root_scoped: Vec<_> = cookies
        .into_iter()
        .map(|mut c| {
            c.path = "/".to_owned();
            c
        })
        .collect();

    for origin in [
        "https://api.accounts.firefox.com/v1/",
        "https://api.accounts.firefox.com/",
        "https://oauth.accounts.firefox.com/",
        "https://accounts.firefox.com/",
    ] {
        let u = Url::parse(origin)
            .map_err(|e| FxaError::ChallengeBlocked(format!("invalid FxA origin {origin}: {e}")))?;
        main_client.set_cookies_for(&u, &root_scoped);
    }
    Ok(())
}

fn remaining_timeout(deadline: Instant) -> Result<Duration, ChallengeHostError> {
    let rem = deadline.saturating_duration_since(Instant::now());
    if rem.is_zero() {
        Err(ChallengeHostError::Other(FxaError::ChallengeBlocked(
            "Fastly challenge solve exceeded budget".into(),
        )))
    } else {
        Ok(rem)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn solves_fastly_pow_two_char_suffix() {
        let base = "fastly-nonce-42:";
        let expected_hash = hex::encode(Sha256::digest(b"fastly-nonce-42:Z9"));
        assert_eq!(solve_pow(base, &expected_hash).as_deref(), Some("Z9"));
    }

    #[test]
    fn extracts_fastly_prefix_and_parses_init_script() {
        let html = r#"<!doctype html><html><title>Client Challenge</title><script src="/_fs-ch-abc123XYZ/script.js?reload=true"></script></html>"#;
        assert!(is_challenge_page_body(html));
        let prefix = find_challenge_prefix(html).unwrap();
        assert_eq!(prefix, "/_fs-ch-abc123XYZ");
        assert_eq!(
            extract_script_tags(html),
            vec![r#"<script src="/_fs-ch-abc123XYZ/script.js?reload=true"></script>"#]
        );

        let expected_hash = hex::encode(Sha256::digest(b"b1:k7"));
        let script = format!(
            r#"
            function helper() {{ init([], "wrong", "/_fs-ch-other"); }}
            init([
              {{"ty":"pat","data":{{}}}},
              {{"ty":"pow","data":{{"base":"b1:","expires":"99999","hmac":"h1","hash":"{expected_hash}"}}}}
            ], "tok-xyz", "/_fs-ch-abc123XYZ");
            "#
        );

        let (tasks, tok) = parse_challenge_init(&script, &prefix).unwrap();
        assert_eq!(tok, "tok-xyz");
        assert_eq!(tasks.len(), 2);
        assert_eq!(tasks[0].ty, "pat");
        assert_eq!(tasks[1].ty, "pow");
    }
}
